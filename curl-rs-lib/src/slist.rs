// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
// Rust rewrite of lib/slist.c — Vec-based string list replacing the C
// `struct curl_slist` linked list.  Used throughout the crate for custom
// headers (`CURLOPT_HTTPHEADER`), mail recipients (`CURLOPT_MAIL_RCPT`),
// resolve lists (`CURLOPT_RESOLVE`), FTP commands (`CURLOPT_QUOTE`), and
// any other option that accepts a string list.
//
// Design notes:
//   * A `Vec<String>` replaces the C linked-list; append is O(1) amortized,
//     iteration is cache-friendly, and Rust's ownership model eliminates
//     the manual `curl_slist_free_all` that callers had to remember in C.
//   * `append` clones the incoming `&str` (mirrors `curl_slist_append`).
//   * `append_nodup` takes ownership of a `String` without copying
//     (mirrors `Curl_slist_append_nodup`).
//   * `duplicate` performs a deep copy (mirrors `Curl_slist_duplicate`).
//   * Drop is automatic — Rust drops the `Vec<String>` when the `SList`
//     goes out of scope, matching `curl_slist_free_all` semantics.

use std::fmt;
use std::ops::Index;
use std::slice;

// ---------------------------------------------------------------------------
// SList — the core type
// ---------------------------------------------------------------------------

/// A list of strings used throughout the curl library.
///
/// `SList` wraps a `Vec<String>` and provides a purpose-built API that maps
/// one-to-one to the C `curl_slist` operations (`curl_slist_append`,
/// `Curl_slist_append_nodup`, `Curl_slist_duplicate`, `curl_slist_free_all`).
///
/// # Examples
///
/// ```
/// use curl_rs_lib::slist::SList;
///
/// let mut list = SList::new();
/// list.append("Content-Type: application/json")
///     .append("Accept: */*");
///
/// assert_eq!(list.len(), 2);
/// for header in list.iter() {
///     println!("{header}");
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SList {
    /// Internal storage — each element is an owned `String`.
    entries: Vec<String>,
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

impl SList {
    /// Creates a new, empty `SList`.
    ///
    /// This is the Rust equivalent of initialising a `struct curl_slist *`
    /// to `NULL` in C and then calling `curl_slist_append` for the first item.
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::slist::SList;
    /// let list = SList::new();
    /// assert!(list.is_empty());
    /// ```
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Creates a new `SList` with the given pre-allocated capacity.
    ///
    /// This avoids repeated re-allocations when the caller knows roughly
    /// how many entries the list will contain.
    #[inline]
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
        }
    }
}

// ---------------------------------------------------------------------------
// Append operations
// ---------------------------------------------------------------------------

impl SList {
    /// Appends a **copy** of `data` to the end of the list.
    ///
    /// This mirrors the semantics of `curl_slist_append` in C, which calls
    /// `strdup` to duplicate the input string before storing it.
    ///
    /// Returns `&mut Self` to allow method chaining.
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::slist::SList;
    /// let mut list = SList::new();
    /// list.append("Host: example.com")
    ///     .append("X-Custom: value");
    /// assert_eq!(list.len(), 2);
    /// ```
    #[inline]
    pub fn append(&mut self, data: &str) -> &mut Self {
        self.entries.push(data.to_owned());
        self
    }

    /// Appends a `String` to the list **without copying**.
    ///
    /// This mirrors `Curl_slist_append_nodup` in C, which takes ownership
    /// of a `malloc`-allocated string.  In Rust the transfer of ownership
    /// is explicit and safe.
    ///
    /// Returns `&mut Self` to allow method chaining.
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::slist::SList;
    /// let mut list = SList::new();
    /// let owned = String::from("Transfer-Encoding: chunked");
    /// list.append_nodup(owned);
    /// assert_eq!(list.len(), 1);
    /// ```
    #[inline]
    pub fn append_nodup(&mut self, data: String) -> &mut Self {
        self.entries.push(data);
        self
    }
}

// ---------------------------------------------------------------------------
// Query operations
// ---------------------------------------------------------------------------

impl SList {
    /// Returns an iterator over the string entries as `&str` slices.
    ///
    /// This is the idiomatic Rust replacement for walking a C
    /// `struct curl_slist *` linked list via `item = item->next`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::slist::SList;
    /// let mut list = SList::new();
    /// list.append("a").append("b").append("c");
    /// let collected: Vec<&str> = list.iter().collect();
    /// assert_eq!(collected, vec!["a", "b", "c"]);
    /// ```
    #[inline]
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            inner: self.entries.iter(),
        }
    }

    /// Returns the number of entries in the list.
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::slist::SList;
    /// let mut list = SList::new();
    /// assert_eq!(list.len(), 0);
    /// list.append("item");
    /// assert_eq!(list.len(), 1);
    /// ```
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the list contains no entries.
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::slist::SList;
    /// let list = SList::new();
    /// assert!(list.is_empty());
    /// ```
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Creates a **deep copy** of this list.
    ///
    /// Every string is cloned into a fresh allocation, producing a fully
    /// independent `SList`.  This mirrors `Curl_slist_duplicate` in C.
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::slist::SList;
    /// let mut original = SList::new();
    /// original.append("x");
    /// let copy = original.duplicate();
    /// assert_eq!(original, copy);
    /// ```
    #[inline]
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self {
            entries: self.entries.clone(),
        }
    }

    /// Returns a reference to the entry at position `index`, or `None` if
    /// `index` is out of bounds.
    #[inline]
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&str> {
        self.entries.get(index).map(String::as_str)
    }

    /// Returns `true` if the list contains an entry equal to `value`.
    #[inline]
    #[must_use]
    pub fn contains(&self, value: &str) -> bool {
        self.entries.iter().any(|e| e == value)
    }

    /// Returns the internal entries as a slice of `String`s.
    ///
    /// Primarily intended for the FFI crate which needs direct access to
    /// convert entries into C-compatible structures.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.entries
    }

    /// Consumes the `SList` and returns the underlying `Vec<String>`.
    ///
    /// Useful when handing data off to an API that expects a `Vec<String>`
    /// or when the caller wants to take ownership of the individual entries.
    #[inline]
    #[must_use]
    pub fn into_vec(self) -> Vec<String> {
        self.entries
    }
}

// ---------------------------------------------------------------------------
// Mutation helpers
// ---------------------------------------------------------------------------

impl SList {
    /// Removes all entries from the list, leaving it empty.
    ///
    /// This is equivalent to calling `curl_slist_free_all` and then
    /// initialising a fresh list, but reuses the existing allocation.
    #[inline]
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Removes and returns the last entry, or `None` if the list is empty.
    #[inline]
    pub fn pop(&mut self) -> Option<String> {
        self.entries.pop()
    }

    /// Removes the entry at `index`, shifting all subsequent entries left.
    ///
    /// # Panics
    ///
    /// Panics if `index >= self.len()`.
    #[inline]
    pub fn remove(&mut self, index: usize) -> String {
        self.entries.remove(index)
    }

    /// Retains only the entries for which the predicate returns `true`.
    #[inline]
    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&String) -> bool,
    {
        self.entries.retain(f);
    }
}

// ---------------------------------------------------------------------------
// Custom iterator type
// ---------------------------------------------------------------------------

/// An iterator over the entries of an [`SList`] yielding `&str` references.
///
/// Created by [`SList::iter`].
#[derive(Clone, Debug)]
pub struct Iter<'a> {
    inner: slice::Iter<'a, String>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a str;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(String::as_str)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<'a> ExactSizeIterator for Iter<'a> {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<'a> DoubleEndedIterator for Iter<'a> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back().map(String::as_str)
    }
}

// ---------------------------------------------------------------------------
// Standard trait implementations
// ---------------------------------------------------------------------------

impl Default for SList {
    /// Returns an empty `SList` (identical to [`SList::new`]).
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SList {
    /// Formats the list as a newline-separated sequence of entries.
    ///
    /// This matches the natural rendering of header lists.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, entry) in self.entries.iter().enumerate() {
            if i > 0 {
                f.write_str("\n")?;
            }
            f.write_str(entry)?;
        }
        Ok(())
    }
}

impl<'a> IntoIterator for &'a SList {
    type Item = &'a str;
    type IntoIter = Iter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Owning iterator — consumes the `SList`.
impl IntoIterator for SList {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl FromIterator<String> for SList {
    /// Collects an iterator of `String`s into an `SList`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::slist::SList;
    /// let list: SList = vec!["a".to_owned(), "b".to_owned()].into_iter().collect();
    /// assert_eq!(list.len(), 2);
    /// ```
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        Self {
            entries: iter.into_iter().collect(),
        }
    }
}

impl<'a> FromIterator<&'a str> for SList {
    /// Collects an iterator of `&str` slices into an `SList` (cloning each).
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::slist::SList;
    /// let list: SList = ["x", "y", "z"].iter().copied().collect();
    /// assert_eq!(list.len(), 3);
    /// ```
    fn from_iter<I: IntoIterator<Item = &'a str>>(iter: I) -> Self {
        Self {
            entries: iter.into_iter().map(str::to_owned).collect(),
        }
    }
}

impl Extend<String> for SList {
    /// Extends the list with the contents of an iterator of `String`s.
    fn extend<I: IntoIterator<Item = String>>(&mut self, iter: I) {
        self.entries.extend(iter);
    }
}

impl<'a> Extend<&'a str> for SList {
    /// Extends the list with the contents of an iterator of `&str` slices.
    fn extend<I: IntoIterator<Item = &'a str>>(&mut self, iter: I) {
        self.entries.extend(iter.into_iter().map(str::to_owned));
    }
}

impl Index<usize> for SList {
    type Output = str;

    /// Returns a reference to the entry at position `index`.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds.
    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.entries[index]
    }
}

impl From<Vec<String>> for SList {
    /// Creates an `SList` from an existing `Vec<String>` without copying.
    #[inline]
    fn from(entries: Vec<String>) -> Self {
        Self { entries }
    }
}

impl From<SList> for Vec<String> {
    /// Consumes the `SList` and returns the underlying `Vec<String>`.
    #[inline]
    fn from(list: SList) -> Self {
        list.entries
    }
}

impl From<&[&str]> for SList {
    /// Creates an `SList` from a slice of `&str`, cloning each entry.
    fn from(slice: &[&str]) -> Self {
        Self {
            entries: slice.iter().map(|s| (*s).to_owned()).collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_is_empty() {
        let list = SList::new();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn test_append_copies() {
        let mut list = SList::new();
        let data = String::from("hello");
        list.append(&data);
        // The original string is still valid — append cloned it.
        assert_eq!(data, "hello");
        assert_eq!(list.len(), 1);
        assert_eq!(list.get(0), Some("hello"));
    }

    #[test]
    fn test_append_nodup_takes_ownership() {
        let mut list = SList::new();
        let owned = String::from("world");
        list.append_nodup(owned);
        // `owned` has been moved — cannot be used.
        assert_eq!(list.len(), 1);
        assert_eq!(list.get(0), Some("world"));
    }

    #[test]
    fn test_chained_append() {
        let mut list = SList::new();
        list.append("a").append("b").append("c");
        assert_eq!(list.len(), 3);
        let items: Vec<&str> = list.iter().collect();
        assert_eq!(items, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_iter() {
        let mut list = SList::new();
        list.append("x").append("y");
        let mut it = list.iter();
        assert_eq!(it.next(), Some("x"));
        assert_eq!(it.next(), Some("y"));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn test_iter_exact_size() {
        let mut list = SList::new();
        list.append("1").append("2").append("3");
        let it = list.iter();
        assert_eq!(it.len(), 3);
    }

    #[test]
    fn test_iter_double_ended() {
        let mut list = SList::new();
        list.append("a").append("b").append("c");
        let mut it = list.iter();
        assert_eq!(it.next_back(), Some("c"));
        assert_eq!(it.next(), Some("a"));
        assert_eq!(it.next_back(), Some("b"));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn test_duplicate_is_deep_copy() {
        let mut original = SList::new();
        original.append("first").append("second");

        let copy = original.duplicate();
        assert_eq!(original, copy);

        // Mutating the original does not affect the copy.
        original.append("third");
        assert_eq!(original.len(), 3);
        assert_eq!(copy.len(), 2);
    }

    #[test]
    fn test_duplicate_empty() {
        let empty = SList::new();
        let copy = empty.duplicate();
        assert!(copy.is_empty());
        assert_eq!(empty, copy);
    }

    #[test]
    fn test_contains() {
        let mut list = SList::new();
        list.append("Host: example.com");
        assert!(list.contains("Host: example.com"));
        assert!(!list.contains("Host: other.com"));
    }

    #[test]
    fn test_clear() {
        let mut list = SList::new();
        list.append("a").append("b");
        assert_eq!(list.len(), 2);
        list.clear();
        assert!(list.is_empty());
    }

    #[test]
    fn test_pop() {
        let mut list = SList::new();
        list.append("x").append("y");
        assert_eq!(list.pop(), Some(String::from("y")));
        assert_eq!(list.len(), 1);
        assert_eq!(list.pop(), Some(String::from("x")));
        assert!(list.is_empty());
        assert_eq!(list.pop(), None);
    }

    #[test]
    fn test_remove() {
        let mut list = SList::new();
        list.append("a").append("b").append("c");
        let removed = list.remove(1);
        assert_eq!(removed, "b");
        assert_eq!(list.len(), 2);
        let items: Vec<&str> = list.iter().collect();
        assert_eq!(items, vec!["a", "c"]);
    }

    #[test]
    fn test_retain() {
        let mut list = SList::new();
        list.append("keep-a").append("drop-b").append("keep-c");
        list.retain(|s| s.starts_with("keep"));
        assert_eq!(list.len(), 2);
        let items: Vec<&str> = list.iter().collect();
        assert_eq!(items, vec!["keep-a", "keep-c"]);
    }

    #[test]
    fn test_index() {
        let mut list = SList::new();
        list.append("zero").append("one").append("two");
        assert_eq!(&list[0], "zero");
        assert_eq!(&list[1], "one");
        assert_eq!(&list[2], "two");
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn test_index_out_of_bounds() {
        let list = SList::new();
        let _ = &list[0];
    }

    #[test]
    fn test_default() {
        let list: SList = Default::default();
        assert!(list.is_empty());
    }

    #[test]
    fn test_display() {
        let mut list = SList::new();
        list.append("Host: h").append("Accept: */*");
        let s = list.to_string();
        assert_eq!(s, "Host: h\nAccept: */*");
    }

    #[test]
    fn test_display_empty() {
        let list = SList::new();
        assert_eq!(list.to_string(), "");
    }

    #[test]
    fn test_into_iterator_ref() {
        let mut list = SList::new();
        list.append("a").append("b");
        let mut collected = Vec::new();
        for item in &list {
            collected.push(item);
        }
        assert_eq!(collected, vec!["a", "b"]);
    }

    #[test]
    fn test_into_iterator_owned() {
        let mut list = SList::new();
        list.append("a").append("b");
        let collected: Vec<String> = list.into_iter().collect();
        assert_eq!(collected, vec!["a", "b"]);
    }

    #[test]
    fn test_from_iter_string() {
        let list: SList = vec!["x".to_owned(), "y".to_owned()]
            .into_iter()
            .collect();
        assert_eq!(list.len(), 2);
        assert_eq!(list.get(0), Some("x"));
        assert_eq!(list.get(1), Some("y"));
    }

    #[test]
    fn test_from_iter_str() {
        let list: SList = ["p", "q", "r"].iter().copied().collect();
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn test_extend_string() {
        let mut list = SList::new();
        list.append("existing");
        list.extend(vec!["new1".to_owned(), "new2".to_owned()]);
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn test_extend_str() {
        let mut list = SList::new();
        list.extend(["a", "b", "c"].iter().copied());
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn test_from_vec() {
        let v = vec!["alpha".to_owned(), "beta".to_owned()];
        let list = SList::from(v);
        assert_eq!(list.len(), 2);
        assert_eq!(list.get(0), Some("alpha"));
    }

    #[test]
    fn test_into_vec() {
        let mut list = SList::new();
        list.append("one").append("two");
        let v: Vec<String> = list.into_vec();
        assert_eq!(v, vec!["one", "two"]);
    }

    #[test]
    fn test_from_slice() {
        let slice: &[&str] = &["a", "b", "c"];
        let list = SList::from(slice);
        assert_eq!(list.len(), 3);
        assert_eq!(list.get(2), Some("c"));
    }

    #[test]
    fn test_as_slice() {
        let mut list = SList::new();
        list.append("hello");
        let s = list.as_slice();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0], "hello");
    }

    #[test]
    fn test_with_capacity() {
        let list = SList::with_capacity(100);
        assert!(list.is_empty());
        // Capacity is at least what was requested (may be more).
    }

    #[test]
    fn test_clone_and_eq() {
        let mut list = SList::new();
        list.append("item1").append("item2");
        let cloned = list.clone();
        assert_eq!(list, cloned);
    }

    #[test]
    fn test_ne() {
        let mut a = SList::new();
        a.append("x");
        let mut b = SList::new();
        b.append("y");
        assert_ne!(a, b);
    }

    #[test]
    fn test_large_list() {
        let mut list = SList::new();
        for i in 0..10_000 {
            list.append(&format!("entry-{i}"));
        }
        assert_eq!(list.len(), 10_000);
        assert_eq!(list.get(0), Some("entry-0"));
        assert_eq!(list.get(9_999), Some("entry-9999"));

        let dup = list.duplicate();
        assert_eq!(dup.len(), 10_000);
        assert_eq!(list, dup);
    }

    #[test]
    fn test_empty_string_entries() {
        let mut list = SList::new();
        list.append("").append("non-empty").append("");
        assert_eq!(list.len(), 3);
        assert_eq!(list.get(0), Some(""));
        assert_eq!(list.get(1), Some("non-empty"));
        assert_eq!(list.get(2), Some(""));
    }

    #[test]
    fn test_unicode_entries() {
        let mut list = SList::new();
        list.append("日本語ヘッダー: 値")
            .append("Ñoño: café");
        assert_eq!(list.len(), 2);
        assert!(list.contains("日本語ヘッダー: 値"));
        assert!(list.contains("Ñoño: café"));
    }

    #[test]
    fn test_duplicate_matches_c_semantics() {
        // In C, Curl_slist_duplicate walks the linked list and calls
        // curl_slist_append for each entry (which strdup's).
        // Our duplicate() must produce an independent deep copy.
        let mut original = SList::new();
        original
            .append("Header-A: 1")
            .append("Header-B: 2")
            .append("Header-C: 3");

        let mut copy = original.duplicate();

        // They start equal.
        assert_eq!(original, copy);

        // Mutating one does not affect the other.
        copy.append("Header-D: 4");
        assert_ne!(original, copy);
        assert_eq!(original.len(), 3);
        assert_eq!(copy.len(), 4);
    }
}
