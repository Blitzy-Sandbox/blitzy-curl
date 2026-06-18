// Singly-linked string list container (`curl_slist`) for the curl-rs workspace.
//
// SPDX-License-Identifier: curl
//
// This file is a memory-safe Rust reimplementation of curl's `curl_slist`
// string list (`lib/slist.c` plus the public `struct curl_slist` declared in
// `include/curl/curl.h`). The original C sources are
//   Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// and are licensed under the curl license (https://curl.se/docs/copyright.html).
// This Rust port preserves the observable behavior and the public API *names*
// of that container; it is a behavioral translation, not a line-by-line one.

//! Owning, insertion-ordered list of C strings — the safe replacement for
//! libcurl's `curl_slist` (`lib/slist.c`).
//!
//! `curl_slist` is the singly-linked list of NUL-terminated strings that
//! libcurl uses pervasively: custom request headers (`CURLOPT_HTTPHEADER`),
//! FTP/SFTP quote commands (`CURLOPT_QUOTE` / `CURLOPT_POSTQUOTE` /
//! `CURLOPT_PREQUOTE`), name-resolution overrides (`CURLOPT_RESOLVE`,
//! `CURLOPT_CONNECT_TO`), `CURLOPT_TELNETOPTIONS`, `CURLOPT_MAIL_RCPT`, the
//! `CURLINFO_COOKIELIST` and `CURLINFO_SSL_ENGINES` info results, and the
//! MIME/header machinery, among others. Internal consumers store an [`SList`]
//! on the easy/multi handle and iterate it; the FFI crate marshals it to and
//! from the C linked form (see below).
//!
//! # Why this is a `Vec<CString>`, not a pointer list
//!
//! The C type is an intrusive singly-linked list:
//!
//! ```c
//! struct curl_slist {
//!   char *data;              /* a strdup'd, NUL-terminated string */
//!   struct curl_slist *next; /* next node, or NULL at the tail   */
//! };
//! ```
//!
//! Each `curl_slist_append` `malloc`s a node and `strdup`s the string onto it,
//! threading nodes together by raw `next` pointers; `curl_slist_free_all`
//! walks the chain freeing every node and its `data`. That design is built on
//! raw-pointer manipulation and manual `malloc`/`free`, which the
//! workspace-wide `#![forbid(unsafe_code)]` rule (AAP §0.7.1) prohibits in the
//! core crate.
//!
//! The faithful *safe* translation collapses the linked list onto an owning
//! [`Vec<CString>`]:
//!
//! * A [`CString`] is precisely curl's per-node payload — an owned, heap
//!   allocated, NUL-terminated byte string with no interior NUL — so it is a
//!   zero-overhead, C-ready model of a single node's `data`.
//! * A [`Vec`] preserves the **insertion order** curl guarantees (every
//!   `curl_slist_append` adds at the tail and iteration runs head-to-tail) and
//!   gives O(1) amortized append.
//! * Ownership plus a deterministic [`Drop`] replaces `curl_slist_free_all`:
//!   when an `SList` goes out of scope every `CString` is freed automatically,
//!   with no leak and no double-free possible.
//! * The derived [`Clone`] is curl's `Curl_slist_duplicate` — a deep copy of
//!   every string into a fresh, independent list.
//!
//! The raw `curl_slist*` linked-node form lives **only** at the FFI edge
//! (`curl-rs-ffi`, which defines the `#[repr(C)] struct curl_slist` and the
//! `extern "C"` `curl_slist_append` / `curl_slist_free_all` symbols). That
//! layer marshals to and from this safe type with the conversion helpers below
//! — [`SList::to_vec`] / [`SList::iter_cstring`] on the outbound path, and
//! [`SList::from_cstrings`] plus the [`FromIterator<CString>`] impl on the
//! inbound path. This module itself never touches a raw pointer.
//!
//! # API mapping
//!
//! | libcurl C function        | Safe Rust equivalent on [`SList`]                       |
//! |---------------------------|---------------------------------------------------------|
//! | `curl_slist_append`       | [`append`](SList::append) / [`append_cstr`](SList::append_cstr) (copies) |
//! | `Curl_slist_append_nodup` | [`append_cstring`](SList::append_cstring) (takes ownership, no copy)     |
//! | `Curl_slist_duplicate`    | [`Clone`] (derived)                                     |
//! | `curl_slist_free_all`     | [`Drop`] (automatic) / [`clear`](SList::clear)          |
//!
//! # Interior NUL bytes
//!
//! A C string ends at its first NUL, so a `curl_slist` node can never *contain*
//! a NUL byte. The `&str`/byte-taking constructors here therefore reject an
//! argument with an interior NUL — it cannot be represented as a single C
//! string — by returning [`CurlError::BadFunctionArgument`] (the same `CURLE_*`
//! class curl uses for a bad argument) rather than silently truncating at the
//! NUL. The [`CStr`]/[`CString`]-taking entry points are infallible because
//! their inputs are NUL-free by construction.
//!
//! # Memory safety
//!
//! This module contains **zero** `unsafe` and compiles under the module-level
//! `#![forbid(unsafe_code)]` declared below (reinforcing the crate-root
//! attribute). All allocation and freeing is handled by [`Vec`]/[`CString`].
#![forbid(unsafe_code)]

use crate::error::{CurlError, Result};
use std::ffi::{CStr, CString};

/// A safe, owning, insertion-ordered list of C strings — the core-crate
/// representation of libcurl's `curl_slist`.
///
/// Internally an ordered [`Vec<CString>`]; see the [module documentation](self)
/// for the rationale and the full C-API mapping. An `SList` is cheaply
/// [`Clone`]able (a deep copy, matching `Curl_slist_duplicate`) and is stored
/// directly on easy/multi handles by the option setters that accept a string
/// list (`CURLOPT_HTTPHEADER`, `CURLOPT_QUOTE`, `CURLOPT_RESOLVE`, …).
///
/// # Examples
///
/// ```ignore
/// let mut list = SList::new();
/// list.append("Host: example.com")?;
/// list.append("X-Trace: 1")?;
/// assert_eq!(list.len(), 2);
/// assert_eq!(list.first().unwrap().to_bytes(), b"Host: example.com");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SList {
    /// The entries, in insertion order. Each entry is an owned, NUL-terminated
    /// string with no interior NUL — exactly one C node's `data`.
    items: Vec<CString>,
}

impl SList {
    // -- Construction -------------------------------------------------------

    /// Creates a new, empty list.
    ///
    /// Equivalent to a `NULL` `curl_slist*` in C: the first [`append`](Self::append)
    /// produces what would be the head node. No allocation is performed until
    /// the first push.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        SList { items: Vec::new() }
    }

    /// Creates an empty list preallocated to hold at least `capacity` entries.
    ///
    /// A non-semantic optimization for call sites that know the entry count up
    /// front (for example the FFI inbound path that has already counted the C
    /// nodes).
    #[inline]
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        SList {
            items: Vec::with_capacity(capacity),
        }
    }

    /// Builds a list directly from owned [`CString`] entries, preserving order.
    ///
    /// This is the primary **inbound** FFI helper: after walking a C
    /// `curl_slist*` and copying each node's `data` into an owned [`CString`],
    /// the FFI layer hands the resulting vector here. Because every [`CString`]
    /// is already NUL-free and owned, the conversion is total and infallible.
    #[inline]
    #[must_use]
    pub fn from_cstrings(items: Vec<CString>) -> Self {
        SList { items }
    }

    /// Builds a list by copying each string of an iterator, in order.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::BadFunctionArgument`] if any item contains an
    /// interior NUL byte (it cannot be represented as a C string). On error the
    /// partially built list is discarded.
    pub fn try_from_strs<I, S>(iter: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let iter = iter.into_iter();
        let (lower, _) = iter.size_hint();
        let mut list = SList::with_capacity(lower);
        for item in iter {
            list.append(item.as_ref())?;
        }
        Ok(list)
    }

    // -- Mutation -----------------------------------------------------------

    /// Appends a string to the tail, copying it — the safe analog of
    /// `curl_slist_append`.
    ///
    /// curl `strdup`s the argument; this likewise stores an owned copy, leaving
    /// the caller's `&str` untouched. Insertion order is preserved (the new
    /// entry becomes the last).
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::BadFunctionArgument`] if `s` contains an interior
    /// NUL byte (see the [module docs](self#interior-nul-bytes)).
    pub fn append(&mut self, s: &str) -> Result<()> {
        let entry = CString::new(s).map_err(|_| CurlError::BadFunctionArgument)?;
        self.items.push(entry);
        Ok(())
    }

    /// Appends a string built from raw bytes, copying them.
    ///
    /// The terminating NUL is added automatically, so `bytes` must **not**
    /// contain a NUL (whether interior or trailing).
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::BadFunctionArgument`] if `bytes` contains any NUL
    /// byte.
    pub fn append_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let entry = CString::new(bytes).map_err(|_| CurlError::BadFunctionArgument)?;
        self.items.push(entry);
        Ok(())
    }

    /// Appends a copy of an existing C string.
    ///
    /// Infallible: a [`CStr`] is, by construction, already free of interior
    /// NULs, so no validation is required.
    pub fn append_cstr(&mut self, s: &CStr) {
        self.items.push(s.to_owned());
    }

    /// Appends an owned [`CString`] by moving it onto the tail — the safe analog
    /// of `Curl_slist_append_nodup`, which takes ownership of an
    /// already-allocated string instead of copying it.
    ///
    /// Use this on hot paths where the caller already holds an owned [`CString`]
    /// and a copy would be wasteful.
    pub fn append_cstring(&mut self, s: CString) {
        self.items.push(s);
    }

    /// Removes every entry, freeing the owned strings.
    ///
    /// The in-place analog of `curl_slist_free_all` (which in C also frees the
    /// list head; here the `SList` itself remains, now empty). The allocated
    /// capacity is retained for reuse.
    pub fn clear(&mut self) {
        self.items.clear();
    }

    // -- Queries ------------------------------------------------------------

    /// Returns `true` if the list has no entries.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns the number of entries in the list.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns the entry at `index` as a [`CStr`], or `None` if out of bounds.
    #[inline]
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&CStr> {
        self.items.get(index).map(CString::as_c_str)
    }

    /// Returns the first entry as a [`CStr`], or `None` if the list is empty.
    #[inline]
    #[must_use]
    pub fn first(&self) -> Option<&CStr> {
        self.items.first().map(CString::as_c_str)
    }

    /// Returns the last entry as a [`CStr`], or `None` if the list is empty.
    #[inline]
    #[must_use]
    pub fn last(&self) -> Option<&CStr> {
        self.items.last().map(CString::as_c_str)
    }

    // -- Iteration & conversion --------------------------------------------

    /// Returns an iterator over the entries as [`CStr`] slices, in insertion
    /// order — the safe analog of walking `node = node->next` from the head.
    #[inline]
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            inner: self.items.iter(),
        }
    }

    /// Returns an iterator over the entries as borrowed [`CString`] references.
    ///
    /// Useful for the FFI outbound path, which clones each entry into a freshly
    /// allocated C node.
    #[inline]
    pub fn iter_cstring(&self) -> std::slice::Iter<'_, CString> {
        self.items.iter()
    }

    /// Borrows the entries as a contiguous `&[CString]`, in insertion order.
    ///
    /// The primary **outbound** FFI helper: the FFI layer walks this slice and
    /// builds one `#[repr(C)] curl_slist` node per [`CString`]. Despite the
    /// `to_` name (kept to match the planned FFI contract), this is a zero-copy
    /// borrow, not a clone; use [`Clone`] or [`into_cstrings`](Self::into_cstrings)
    /// when an owned copy is needed.
    #[inline]
    #[must_use]
    pub fn to_vec(&self) -> &[CString] {
        &self.items
    }

    /// Borrows the entries as a contiguous `&[CString]`, in insertion order.
    ///
    /// The idiomatic Rust spelling of [`to_vec`](Self::to_vec).
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[CString] {
        &self.items
    }

    /// Consumes the list, returning the owned `Vec<CString>` of entries in
    /// insertion order.
    #[inline]
    #[must_use]
    pub fn into_cstrings(self) -> Vec<CString> {
        self.items
    }
}

/// Borrowing iterator over the entries of an [`SList`], yielding each as a
/// [`CStr`] in insertion order.
///
/// Created by [`SList::iter`] and by iterating a `&SList`. Implements
/// [`DoubleEndedIterator`], [`ExactSizeIterator`], and [`FusedIterator`], so it
/// supports reverse traversal, exact `len`, and the usual adapter chains.
///
/// [`FusedIterator`]: std::iter::FusedIterator
#[derive(Debug, Clone)]
pub struct Iter<'a> {
    inner: std::slice::Iter<'a, CString>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a CStr;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(CString::as_c_str)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl DoubleEndedIterator for Iter<'_> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back().map(CString::as_c_str)
    }
}

impl ExactSizeIterator for Iter<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl std::iter::FusedIterator for Iter<'_> {}

impl FromIterator<CString> for SList {
    /// Collects owned [`CString`] entries into a list, preserving order — the
    /// inbound FFI collection point and the natural target of
    /// `vec_of_cstrings.into_iter().collect()`.
    #[inline]
    fn from_iter<I: IntoIterator<Item = CString>>(iter: I) -> Self {
        SList {
            items: iter.into_iter().collect(),
        }
    }
}

impl Extend<CString> for SList {
    /// Appends every [`CString`] of the iterator to the tail, in order.
    #[inline]
    fn extend<I: IntoIterator<Item = CString>>(&mut self, iter: I) {
        self.items.extend(iter);
    }
}

impl IntoIterator for SList {
    type Item = CString;
    type IntoIter = std::vec::IntoIter<CString>;

    /// Consumes the list, yielding each owned [`CString`] in insertion order.
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

impl<'a> IntoIterator for &'a SList {
    type Item = &'a CStr;
    type IntoIter = Iter<'a>;

    /// Borrows the list, yielding each entry as a [`CStr`] in insertion order.
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl From<Vec<CString>> for SList {
    /// Wraps an owned `Vec<CString>` as an [`SList`]; see
    /// [`from_cstrings`](SList::from_cstrings).
    #[inline]
    fn from(items: Vec<CString>) -> Self {
        SList::from_cstrings(items)
    }
}

impl From<SList> for Vec<CString> {
    /// Unwraps an [`SList`] into its owned `Vec<CString>`; see
    /// [`into_cstrings`](SList::into_cstrings).
    #[inline]
    fn from(list: SList) -> Self {
        list.into_cstrings()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Convenience: build a `CString` from a `&str` that is known NUL-free.
    fn cs(s: &str) -> CString {
        CString::new(s).expect("test string must be NUL-free")
    }

    #[test]
    fn new_and_default_are_empty() {
        let a = SList::new();
        let b = SList::default();
        assert!(a.is_empty());
        assert_eq!(a.len(), 0);
        assert_eq!(a, b);
        assert!(a.first().is_none());
        assert!(a.last().is_none());
        assert!(a.get(0).is_none());
        assert_eq!(a.to_vec(), &[] as &[CString]);
    }

    #[test]
    fn append_preserves_insertion_order() {
        // Mirrors curl_slist_append: each append adds at the tail.
        let mut list = SList::new();
        list.append("first").unwrap();
        list.append("second").unwrap();
        list.append("third").unwrap();

        assert_eq!(list.len(), 3);
        assert!(!list.is_empty());
        assert_eq!(list.first().unwrap(), cs("first").as_c_str());
        assert_eq!(list.last().unwrap(), cs("third").as_c_str());
        assert_eq!(list.get(1).unwrap(), cs("second").as_c_str());

        let collected: Vec<&CStr> = list.iter().collect();
        let expected = [cs("first"), cs("second"), cs("third")];
        let expected: Vec<&CStr> = expected.iter().map(CString::as_c_str).collect();
        assert_eq!(collected, expected);
    }

    #[test]
    fn append_rejects_interior_nul() {
        let mut list = SList::new();
        let err = list.append("bad\0string").unwrap_err();
        assert_eq!(err, CurlError::BadFunctionArgument);
        // The failed append must not have added an entry.
        assert!(list.is_empty());
    }

    #[test]
    fn append_empty_string_is_allowed() {
        // An empty C string ("") is a legitimate entry; curl strdup("") works.
        let mut list = SList::new();
        list.append("").unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list.first().unwrap(), cs("").as_c_str());
        assert_eq!(list.first().unwrap().to_bytes(), b"");
    }

    #[test]
    fn append_bytes_ok_and_rejects_nul() {
        let mut list = SList::new();
        list.append_bytes(b"raw bytes").unwrap();
        assert_eq!(list.last().unwrap().to_bytes(), b"raw bytes");

        // Interior NUL is rejected.
        assert_eq!(
            list.append_bytes(b"x\0y").unwrap_err(),
            CurlError::BadFunctionArgument
        );
        // A trailing NUL is also rejected (the terminator is added implicitly).
        assert_eq!(
            list.append_bytes(b"trailing\0").unwrap_err(),
            CurlError::BadFunctionArgument
        );
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn append_cstr_copies() {
        let mut list = SList::new();
        let owned = cs("borrowed");
        list.append_cstr(owned.as_c_str());
        // The source CString is untouched (still usable) — a copy was stored.
        assert_eq!(owned.to_bytes(), b"borrowed");
        assert_eq!(list.first().unwrap(), owned.as_c_str());
    }

    #[test]
    fn append_cstring_takes_ownership() {
        // The nodup analog: moves the CString in, no copy.
        let mut list = SList::new();
        list.append_cstring(cs("owned-one"));
        list.append_cstring(cs("owned-two"));
        assert_eq!(list.len(), 2);
        assert_eq!(list.first().unwrap(), cs("owned-one").as_c_str());
        assert_eq!(list.last().unwrap(), cs("owned-two").as_c_str());
    }

    #[test]
    fn clear_empties_the_list() {
        let mut list = SList::new();
        list.append("a").unwrap();
        list.append("b").unwrap();
        assert_eq!(list.len(), 2);
        list.clear();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
        // Reusable after clearing.
        list.append("c").unwrap();
        assert_eq!(list.first().unwrap(), cs("c").as_c_str());
    }

    #[test]
    fn clone_is_a_deep_independent_copy() {
        // Models Curl_slist_duplicate: a fully independent clone.
        let mut original = SList::new();
        original.append("one").unwrap();
        original.append("two").unwrap();

        let clone = original.clone();
        assert_eq!(original, clone);

        // Mutating the original must not affect the clone.
        original.append("three").unwrap();
        assert_eq!(original.len(), 3);
        assert_eq!(clone.len(), 2);
        assert_ne!(original, clone);
        assert_eq!(clone.last().unwrap(), cs("two").as_c_str());
    }

    #[test]
    fn iter_is_double_ended_and_exact_sized() {
        let mut list = SList::new();
        for s in ["a", "b", "c", "d"] {
            list.append(s).unwrap();
        }

        // ExactSizeIterator.
        assert_eq!(list.iter().len(), 4);

        // size_hint is exact.
        assert_eq!(list.iter().size_hint(), (4, Some(4)));

        // Forward order.
        let fwd: Vec<&[u8]> = list.iter().map(CStr::to_bytes).collect();
        assert_eq!(fwd, vec![&b"a"[..], &b"b"[..], &b"c"[..], &b"d"[..]]);

        // Reverse order via DoubleEndedIterator.
        let rev: Vec<&[u8]> = list.iter().rev().map(CStr::to_bytes).collect();
        assert_eq!(rev, vec![&b"d"[..], &b"c"[..], &b"b"[..], &b"a"[..]]);
    }

    #[test]
    fn iter_cstring_yields_cstrings() {
        let mut list = SList::new();
        list.append("x").unwrap();
        list.append("y").unwrap();
        let v: Vec<CString> = list.iter_cstring().cloned().collect();
        assert_eq!(v, vec![cs("x"), cs("y")]);
    }

    #[test]
    fn into_iter_owned_and_borrowed() {
        let mut list = SList::new();
        list.append("p").unwrap();
        list.append("q").unwrap();

        // Borrowed &SList -> &CStr.
        let borrowed: Vec<&[u8]> = (&list).into_iter().map(CStr::to_bytes).collect();
        assert_eq!(borrowed, vec![&b"p"[..], &b"q"[..]]);

        // Owned SList -> CString (consumes the list).
        let owned: Vec<CString> = list.into_iter().collect();
        assert_eq!(owned, vec![cs("p"), cs("q")]);
    }

    #[test]
    fn from_iterator_and_extend() {
        // FromIterator<CString>.
        let list: SList = vec![cs("h1"), cs("h2"), cs("h3")].into_iter().collect();
        assert_eq!(list.len(), 3);
        assert_eq!(list.get(2).unwrap(), cs("h3").as_c_str());

        // Extend appends, preserving order.
        let mut list = SList::new();
        list.append("base").unwrap();
        list.extend(vec![cs("e1"), cs("e2")]);
        assert_eq!(list.len(), 3);
        assert_eq!(list.first().unwrap(), cs("base").as_c_str());
        assert_eq!(list.last().unwrap(), cs("e2").as_c_str());
    }

    #[test]
    fn try_from_strs_ok_and_err() {
        let ok = SList::try_from_strs(["a", "b", "c"]).unwrap();
        assert_eq!(ok.len(), 3);
        assert_eq!(ok.last().unwrap(), cs("c").as_c_str());

        let err = SList::try_from_strs(["ok", "no\0pe"]).unwrap_err();
        assert_eq!(err, CurlError::BadFunctionArgument);
    }

    #[test]
    fn vec_conversions_round_trip() {
        let source = vec![cs("a"), cs("b")];
        let list: SList = source.clone().into(); // From<Vec<CString>>
        assert_eq!(list.as_slice(), source.as_slice());

        let back: Vec<CString> = list.into(); // From<SList>
        assert_eq!(back, source);
    }

    /// Simulates the `curl-rs-ffi` marshaling round-trip without touching a raw
    /// pointer: build an `SList`, export it as the FFI would (`to_vec`), then
    /// reconstruct it as the FFI would on the inbound path (`from_cstrings`),
    /// and assert the contents are identical.
    #[test]
    fn ffi_round_trip_preserves_contents() {
        let mut original = SList::new();
        original.append("Accept: */*").unwrap();
        original.append("X-Empty:").unwrap();
        original.append("").unwrap();
        original.append_bytes(b"Binary-ish: \xff\xfe").unwrap();

        // Outbound: the FFI clones each entry into a fresh C node. We model the
        // C side as the owned vector of node payloads.
        let exported: Vec<CString> = original.to_vec().to_vec();
        assert_eq!(exported.len(), original.len());

        // Inbound: the FFI walks the C nodes, copies each `data` into a CString,
        // and rebuilds the SList.
        let rebuilt = SList::from_cstrings(exported);

        assert_eq!(rebuilt, original);
        assert_eq!(rebuilt.len(), 4);
        assert_eq!(rebuilt.get(0).unwrap().to_bytes(), b"Accept: */*");
        assert_eq!(rebuilt.get(1).unwrap().to_bytes(), b"X-Empty:");
        assert_eq!(rebuilt.get(2).unwrap().to_bytes(), b"");
        assert_eq!(rebuilt.get(3).unwrap().to_bytes(), b"Binary-ish: \xff\xfe");
    }

    #[test]
    fn with_capacity_constructs_empty() {
        let list = SList::with_capacity(8);
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn drop_of_large_list_is_clean() {
        // Exercised under Miri to prove no leak / double-free in the Drop path
        // (the safe analog of curl_slist_free_all).
        let mut list = SList::new();
        for i in 0..1024 {
            list.append(&format!("entry-{i}")).unwrap();
        }
        assert_eq!(list.len(), 1024);
        let clone = list.clone();
        drop(list);
        // The clone remains valid and independent after the original is dropped.
        assert_eq!(clone.len(), 1024);
        assert_eq!(clone.last().unwrap(), cs("entry-1023").as_c_str());
    }
}
