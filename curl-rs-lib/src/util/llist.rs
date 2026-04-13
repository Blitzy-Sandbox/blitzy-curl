//! Linked list utility replacing C `lib/llist.c` (268 lines).
//!
//! The original C implementation is an intrusive doubly-linked list
//! (`struct Curl_llist`) with sentinel-based debug assertions
//! (`CURL_LLI_VALID = 0x163ABD47`), `Curl_llist_insert_next`,
//! `Curl_llist_append`, `Curl_llist_remove`, and manual node pointer
//! management via `Curl_llist_node` structs.
//!
//! In Rust this is replaced by a thin generic wrapper around
//! [`VecDeque<T>`] which provides:
//! - O(1) push/pop at both ends (replacing C head/tail operations)
//! - O(n) indexed access and removal (replacing C node-walking removal)
//! - Predicate-based filtering via `retain` (replacing C walk-and-remove loops)
//! - Safe ownership semantics replacing C manual node allocation/deallocation
//!
//! No sentinel values or debug magic numbers are needed — Rust's type
//! system provides compile-time safety guarantees that the C sentinels
//! only caught at runtime in debug builds.
//!
//! # MSRV
//!
//! This module requires Rust 1.75 or later.

use std::collections::VecDeque;

/// A generic doubly-ended list backed by [`VecDeque<T>`].
///
/// `CurlList<T>` is the idiomatic Rust replacement for the C
/// `struct Curl_llist` / `struct Curl_llist_node` pair.  It exposes an
/// API surface that mirrors the original C functions while leveraging
/// Rust's ownership, borrowing, and `Drop` semantics to eliminate all
/// manual memory management.
///
/// # C API mapping
///
/// | C function / macro            | Rust equivalent            |
/// |-------------------------------|----------------------------|
/// | `Curl_llist_init`             | [`CurlList::new()`]        |
/// | `Curl_llist_append`           | [`CurlList::push_back()`]  |
/// | `Curl_llist_insert_next(NULL)`| [`CurlList::push_front()`] |
/// | `Curl_llist_insert_next(node)`| [`CurlList::insert()`]     |
/// | `Curl_llist_remove`           | [`CurlList::remove()`]     |
/// | `Curl_llist_destroy`          | `Drop` (automatic)         |
/// | `Curl_llist_head`             | [`CurlList::front()`]      |
/// | `Curl_llist_tail`             | [`CurlList::back()`]       |
/// | `Curl_llist_count`            | [`CurlList::len()`]        |
/// | `Curl_node_next` iteration    | [`CurlList::iter()`]       |
///
/// # Examples
///
/// ```
/// use curl_rs_lib::util::llist::CurlList;
///
/// let mut list = CurlList::new();
/// list.push_back(1);
/// list.push_back(2);
/// list.push_front(0);
///
/// assert_eq!(list.len(), 3);
/// assert_eq!(list.front(), Some(&0));
/// assert_eq!(list.back(), Some(&2));
///
/// let items: Vec<&i32> = list.iter().collect();
/// assert_eq!(items, vec![&0, &1, &2]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurlList<T> {
    /// The underlying double-ended queue that stores elements.
    ///
    /// `VecDeque` is chosen over `LinkedList` because:
    /// - Most callers use the list as a simple stack or queue (push/pop
    ///   at front/back), which is O(1) for `VecDeque`.
    /// - `VecDeque` has better cache locality and lower per-element overhead.
    /// - Middle insertion/removal (rare in curl) is O(n) for both data
    ///   structures when accessed by index.
    inner: VecDeque<T>,
}

// ---------------------------------------------------------------------------
// Construction / Destruction
// ---------------------------------------------------------------------------

impl<T> CurlList<T> {
    /// Creates a new, empty `CurlList`.
    ///
    /// No memory is allocated until elements are inserted (lazy
    /// allocation), matching the behavior of `Curl_llist_init` which
    /// sets head/tail to `NULL` and size to 0.
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::util::llist::CurlList;
    /// let list: CurlList<i32> = CurlList::new();
    /// assert!(list.is_empty());
    /// ```
    #[inline]
    pub fn new() -> Self {
        CurlList {
            inner: VecDeque::new(),
        }
    }

    /// Creates a new, empty `CurlList` with at least the specified
    /// capacity.
    ///
    /// The list will be able to hold `cap` elements without
    /// reallocating.  There is no direct C equivalent — this is a
    /// Rust convenience for callers that know the expected size.
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::util::llist::CurlList;
    /// let list: CurlList<String> = CurlList::with_capacity(64);
    /// assert!(list.is_empty());
    /// ```
    #[inline]
    pub fn with_capacity(cap: usize) -> Self {
        CurlList {
            inner: VecDeque::with_capacity(cap),
        }
    }

    // -----------------------------------------------------------------------
    // Insertion
    // -----------------------------------------------------------------------

    /// Inserts an element at the front of the list.
    ///
    /// Matches the C pattern `Curl_llist_insert_next(list, NULL, p, ne)`
    /// which inserts before the current head when the reference node is
    /// `NULL`.
    ///
    /// # Complexity
    ///
    /// Amortized O(1).
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::util::llist::CurlList;
    /// let mut list = CurlList::new();
    /// list.push_front(2);
    /// list.push_front(1);
    /// assert_eq!(list.front(), Some(&1));
    /// ```
    #[inline]
    pub fn push_front(&mut self, item: T) {
        self.inner.push_front(item);
    }

    /// Appends an element at the back of the list.
    ///
    /// Matches the C `Curl_llist_append(list, p, ne)` which calls
    /// `Curl_llist_insert_next(list, list->_tail, p, ne)`.
    ///
    /// # Complexity
    ///
    /// Amortized O(1).
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::util::llist::CurlList;
    /// let mut list = CurlList::new();
    /// list.push_back(1);
    /// list.push_back(2);
    /// assert_eq!(list.back(), Some(&2));
    /// ```
    #[inline]
    pub fn push_back(&mut self, item: T) {
        self.inner.push_back(item);
    }

    /// Inserts an element at the given `index`, shifting all elements
    /// at that index and beyond towards the back.
    ///
    /// Matches the C `Curl_llist_insert_next(list, node, p, ne)` where
    /// `node` points to the element *after which* insertion occurs.
    /// Note: in the Rust API `index` is the position *at which* the new
    /// element will reside after insertion.  An `index` of 0 is
    /// equivalent to [`push_front`](Self::push_front), and an `index`
    /// equal to [`len`](Self::len) is equivalent to
    /// [`push_back`](Self::push_back).
    ///
    /// # Panics
    ///
    /// Panics if `index > self.len()`.
    ///
    /// # Complexity
    ///
    /// O(min(index, len − index)).
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::util::llist::CurlList;
    /// let mut list = CurlList::new();
    /// list.push_back(1);
    /// list.push_back(3);
    /// list.insert(1, 2); // [1, 2, 3]
    /// assert_eq!(list.len(), 3);
    /// let v: Vec<_> = list.iter().copied().collect();
    /// assert_eq!(v, vec![1, 2, 3]);
    /// ```
    #[inline]
    pub fn insert(&mut self, index: usize, item: T) {
        self.inner.insert(index, item);
    }

    // -----------------------------------------------------------------------
    // Removal
    // -----------------------------------------------------------------------

    /// Removes and returns the element at the front of the list, or
    /// `None` if the list is empty.
    ///
    /// This is the inverse of [`push_front`](Self::push_front) and is
    /// the primary dequeue operation when the list is used as a FIFO
    /// queue.
    ///
    /// # Complexity
    ///
    /// O(1).
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::util::llist::CurlList;
    /// let mut list = CurlList::new();
    /// list.push_back(1);
    /// list.push_back(2);
    /// assert_eq!(list.pop_front(), Some(1));
    /// assert_eq!(list.pop_front(), Some(2));
    /// assert_eq!(list.pop_front(), None);
    /// ```
    #[inline]
    pub fn pop_front(&mut self) -> Option<T> {
        self.inner.pop_front()
    }

    /// Removes and returns the element at the back of the list, or
    /// `None` if the list is empty.
    ///
    /// This is the inverse of [`push_back`](Self::push_back) and is
    /// the primary pop operation when the list is used as a LIFO stack.
    ///
    /// # Complexity
    ///
    /// O(1).
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::util::llist::CurlList;
    /// let mut list = CurlList::new();
    /// list.push_back(1);
    /// list.push_back(2);
    /// assert_eq!(list.pop_back(), Some(2));
    /// assert_eq!(list.pop_back(), Some(1));
    /// assert_eq!(list.pop_back(), None);
    /// ```
    #[inline]
    pub fn pop_back(&mut self) -> Option<T> {
        self.inner.pop_back()
    }

    /// Removes and returns the element at the given `index`, or `None`
    /// if the index is out of bounds.
    ///
    /// Matches the C `Curl_node_remove` / `Curl_node_take_elem` pattern
    /// where a specific node is detached from the list and its payload
    /// returned.  Elements after `index` are shifted towards the front.
    ///
    /// # Complexity
    ///
    /// O(min(index, len − index)).
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::util::llist::CurlList;
    /// let mut list = CurlList::new();
    /// list.push_back(10);
    /// list.push_back(20);
    /// list.push_back(30);
    /// assert_eq!(list.remove(1), Some(20));
    /// assert_eq!(list.len(), 2);
    /// ```
    #[inline]
    pub fn remove(&mut self, index: usize) -> Option<T> {
        self.inner.remove(index)
    }

    /// Retains only the elements for which the predicate returns `true`.
    ///
    /// Removes all elements where `f(&element)` returns `false`,
    /// preserving the relative order of the retained elements.  This
    /// replaces C patterns where code walks the list with
    /// `Curl_node_next` and calls `Curl_node_remove` on matching nodes.
    ///
    /// # Complexity
    ///
    /// O(n).
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::util::llist::CurlList;
    /// let mut list = CurlList::new();
    /// for i in 0..10 {
    ///     list.push_back(i);
    /// }
    /// list.retain(|&x| x % 2 == 0);
    /// let v: Vec<_> = list.iter().copied().collect();
    /// assert_eq!(v, vec![0, 2, 4, 6, 8]);
    /// ```
    #[inline]
    pub fn retain<F: FnMut(&T) -> bool>(&mut self, f: F) {
        self.inner.retain(f);
    }

    /// Removes all elements from the list.
    ///
    /// Matches the C `Curl_llist_destroy` which walks the list and
    /// calls the destructor on every node.  In Rust, `Drop` handles
    /// element cleanup automatically.
    ///
    /// # Complexity
    ///
    /// O(n).
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::util::llist::CurlList;
    /// let mut list = CurlList::new();
    /// list.push_back(1);
    /// list.push_back(2);
    /// list.clear();
    /// assert!(list.is_empty());
    /// ```
    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    // -----------------------------------------------------------------------
    // Access
    // -----------------------------------------------------------------------

    /// Returns a reference to the first element, or `None` if the list
    /// is empty.
    ///
    /// Matches the C `Curl_llist_head` which returns the head node
    /// pointer (may be `NULL`).
    ///
    /// # Complexity
    ///
    /// O(1).
    #[inline]
    pub fn front(&self) -> Option<&T> {
        self.inner.front()
    }

    /// Returns a reference to the last element, or `None` if the list
    /// is empty.
    ///
    /// Matches the C `Curl_llist_tail` which returns the tail node
    /// pointer (may be `NULL`).
    ///
    /// # Complexity
    ///
    /// O(1).
    #[inline]
    pub fn back(&self) -> Option<&T> {
        self.inner.back()
    }

    /// Returns the number of elements in the list.
    ///
    /// Matches the C `Curl_llist_count` which returns `list->_size`.
    ///
    /// # Complexity
    ///
    /// O(1).
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the list contains no elements.
    ///
    /// # Complexity
    ///
    /// O(1).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    // -----------------------------------------------------------------------
    // Iteration
    // -----------------------------------------------------------------------

    /// Returns an iterator over immutable references to the elements
    /// in order from front to back.
    ///
    /// Replaces the C pattern of walking from `Curl_llist_head` via
    /// `Curl_node_next` and accessing payloads with `Curl_node_elem`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::util::llist::CurlList;
    /// let mut list = CurlList::new();
    /// list.push_back("a");
    /// list.push_back("b");
    /// let joined: String = list.iter().copied().collect();
    /// assert_eq!(joined, "ab");
    /// ```
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.inner.iter()
    }

    /// Returns an iterator over mutable references to the elements
    /// in order from front to back.
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::util::llist::CurlList;
    /// let mut list = CurlList::new();
    /// list.push_back(1);
    /// list.push_back(2);
    /// for val in list.iter_mut() {
    ///     *val *= 10;
    /// }
    /// assert_eq!(list.front(), Some(&10));
    /// ```
    #[inline]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.inner.iter_mut()
    }

    // -----------------------------------------------------------------------
    // Advanced: drain_filter
    // -----------------------------------------------------------------------

    /// Removes all elements for which `pred` returns `true`, collecting
    /// them into a `Vec<T>`.
    ///
    /// This replaces the C pattern where code iterates over the linked
    /// list with `Curl_node_next`, evaluates a condition, and calls
    /// `Curl_node_remove` on matching nodes mid-iteration.  In Rust,
    /// modifying a collection during iteration requires a separate pass
    /// — `drain_filter` encapsulates that pattern safely.
    ///
    /// Elements that are *not* matched by `pred` remain in the list in
    /// their original order.  Matched elements are returned in a `Vec`
    /// in order of occurrence.
    ///
    /// # Complexity
    ///
    /// O(n).
    ///
    /// # Examples
    ///
    /// ```
    /// # use curl_rs_lib::util::llist::CurlList;
    /// let mut list = CurlList::new();
    /// for i in 0..6 {
    ///     list.push_back(i);
    /// }
    /// let evens = list.drain_filter(|x| *x % 2 == 0);
    /// assert_eq!(evens, vec![0, 2, 4]);
    /// assert_eq!(list.len(), 3);
    /// let remaining: Vec<_> = list.iter().copied().collect();
    /// assert_eq!(remaining, vec![1, 3, 5]);
    /// ```
    pub fn drain_filter<F>(&mut self, mut pred: F) -> Vec<T>
    where
        F: FnMut(&mut T) -> bool,
    {
        let mut drained = Vec::new();
        // We iterate once, partitioning into "keep" and "drain" sets.
        // VecDeque doesn't have a built-in drain_filter on stable Rust
        // 1.75, so we perform a manual retain-with-extraction.
        let mut kept = VecDeque::with_capacity(self.inner.len());
        while let Some(mut item) = self.inner.pop_front() {
            if pred(&mut item) {
                drained.push(item);
            } else {
                kept.push_back(item);
            }
        }
        self.inner = kept;
        drained
    }
}

// ---------------------------------------------------------------------------
// Default — produces an empty list
// ---------------------------------------------------------------------------

impl<T> Default for CurlList<T> {
    /// Creates an empty `CurlList`, equivalent to [`CurlList::new()`].
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// IntoIterator implementations
// ---------------------------------------------------------------------------

impl<T> IntoIterator for CurlList<T> {
    type Item = T;
    type IntoIter = std::collections::vec_deque::IntoIter<T>;

    /// Consumes the `CurlList` and returns an iterator over owned
    /// elements from front to back.
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a CurlList<T> {
    type Item = &'a T;
    type IntoIter = std::collections::vec_deque::Iter<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut CurlList<T> {
    type Item = &'a mut T;
    type IntoIter = std::collections::vec_deque::IterMut<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter_mut()
    }
}

// ---------------------------------------------------------------------------
// FromIterator — enables .collect::<CurlList<T>>()
// ---------------------------------------------------------------------------

impl<T> std::iter::FromIterator<T> for CurlList<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        CurlList {
            inner: VecDeque::from_iter(iter),
        }
    }
}

// ---------------------------------------------------------------------------
// Extend — enables list.extend(other_iter)
// ---------------------------------------------------------------------------

impl<T> Extend<T> for CurlList<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.inner.extend(iter);
    }
}

// ---------------------------------------------------------------------------
// Index access (read-only)
// ---------------------------------------------------------------------------

impl<T> std::ops::Index<usize> for CurlList<T> {
    type Output = T;

    /// Returns a reference to the element at the given index.
    ///
    /// # Panics
    ///
    /// Panics if `index >= self.len()`.
    #[inline]
    fn index(&self, index: usize) -> &T {
        &self.inner[index]
    }
}

impl<T> std::ops::IndexMut<usize> for CurlList<T> {
    /// Returns a mutable reference to the element at the given index.
    ///
    /// # Panics
    ///
    /// Panics if `index >= self.len()`.
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut T {
        &mut self.inner[index]
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
        let list: CurlList<i32> = CurlList::new();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
        assert_eq!(list.front(), None);
        assert_eq!(list.back(), None);
    }

    #[test]
    fn test_with_capacity() {
        let list: CurlList<i32> = CurlList::with_capacity(16);
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn test_default() {
        let list: CurlList<i32> = CurlList::default();
        assert!(list.is_empty());
    }

    #[test]
    fn test_push_front() {
        let mut list = CurlList::new();
        list.push_front(3);
        list.push_front(2);
        list.push_front(1);
        assert_eq!(list.len(), 3);
        assert_eq!(list.front(), Some(&1));
        assert_eq!(list.back(), Some(&3));
    }

    #[test]
    fn test_push_back() {
        let mut list = CurlList::new();
        list.push_back(1);
        list.push_back(2);
        list.push_back(3);
        assert_eq!(list.len(), 3);
        assert_eq!(list.front(), Some(&1));
        assert_eq!(list.back(), Some(&3));
    }

    #[test]
    fn test_insert_at_front() {
        let mut list = CurlList::new();
        list.push_back(2);
        list.push_back(3);
        list.insert(0, 1);
        let v: Vec<_> = list.iter().copied().collect();
        assert_eq!(v, vec![1, 2, 3]);
    }

    #[test]
    fn test_insert_at_back() {
        let mut list = CurlList::new();
        list.push_back(1);
        list.push_back(2);
        list.insert(2, 3);
        let v: Vec<_> = list.iter().copied().collect();
        assert_eq!(v, vec![1, 2, 3]);
    }

    #[test]
    fn test_insert_in_middle() {
        let mut list = CurlList::new();
        list.push_back(1);
        list.push_back(3);
        list.insert(1, 2);
        let v: Vec<_> = list.iter().copied().collect();
        assert_eq!(v, vec![1, 2, 3]);
    }

    #[test]
    fn test_pop_front() {
        let mut list = CurlList::new();
        list.push_back(1);
        list.push_back(2);
        assert_eq!(list.pop_front(), Some(1));
        assert_eq!(list.pop_front(), Some(2));
        assert_eq!(list.pop_front(), None);
    }

    #[test]
    fn test_pop_back() {
        let mut list = CurlList::new();
        list.push_back(1);
        list.push_back(2);
        assert_eq!(list.pop_back(), Some(2));
        assert_eq!(list.pop_back(), Some(1));
        assert_eq!(list.pop_back(), None);
    }

    #[test]
    fn test_remove_valid_index() {
        let mut list = CurlList::new();
        list.push_back(10);
        list.push_back(20);
        list.push_back(30);
        assert_eq!(list.remove(1), Some(20));
        assert_eq!(list.len(), 2);
        let v: Vec<_> = list.iter().copied().collect();
        assert_eq!(v, vec![10, 30]);
    }

    #[test]
    fn test_remove_out_of_bounds() {
        let mut list = CurlList::new();
        list.push_back(1);
        assert_eq!(list.remove(5), None);
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn test_remove_first_element() {
        let mut list = CurlList::new();
        list.push_back(10);
        list.push_back(20);
        assert_eq!(list.remove(0), Some(10));
        assert_eq!(list.front(), Some(&20));
    }

    #[test]
    fn test_remove_last_element() {
        let mut list = CurlList::new();
        list.push_back(10);
        list.push_back(20);
        assert_eq!(list.remove(1), Some(20));
        assert_eq!(list.back(), Some(&10));
    }

    #[test]
    fn test_retain() {
        let mut list = CurlList::new();
        for i in 0..10 {
            list.push_back(i);
        }
        list.retain(|&x| x % 2 == 0);
        let v: Vec<_> = list.iter().copied().collect();
        assert_eq!(v, vec![0, 2, 4, 6, 8]);
    }

    #[test]
    fn test_retain_all() {
        let mut list = CurlList::new();
        list.push_back(1);
        list.push_back(2);
        list.retain(|_| true);
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_retain_none() {
        let mut list = CurlList::new();
        list.push_back(1);
        list.push_back(2);
        list.retain(|_| false);
        assert!(list.is_empty());
    }

    #[test]
    fn test_clear() {
        let mut list = CurlList::new();
        list.push_back(1);
        list.push_back(2);
        list.push_back(3);
        list.clear();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
        assert_eq!(list.front(), None);
        assert_eq!(list.back(), None);
    }

    #[test]
    fn test_front_back_single() {
        let mut list = CurlList::new();
        list.push_back(42);
        assert_eq!(list.front(), Some(&42));
        assert_eq!(list.back(), Some(&42));
    }

    #[test]
    fn test_iter_order() {
        let mut list = CurlList::new();
        list.push_back(1);
        list.push_back(2);
        list.push_back(3);
        let v: Vec<_> = list.iter().copied().collect();
        assert_eq!(v, vec![1, 2, 3]);
    }

    #[test]
    fn test_iter_mut() {
        let mut list = CurlList::new();
        list.push_back(1);
        list.push_back(2);
        list.push_back(3);
        for val in list.iter_mut() {
            *val *= 10;
        }
        let v: Vec<_> = list.iter().copied().collect();
        assert_eq!(v, vec![10, 20, 30]);
    }

    #[test]
    fn test_into_iter() {
        let mut list = CurlList::new();
        list.push_back(String::from("hello"));
        list.push_back(String::from("world"));
        let collected: Vec<String> = list.into_iter().collect();
        assert_eq!(collected, vec!["hello", "world"]);
    }

    #[test]
    fn test_into_iter_ref() {
        let mut list = CurlList::new();
        list.push_back(1);
        list.push_back(2);
        let sum: i32 = (&list).into_iter().sum();
        assert_eq!(sum, 3);
    }

    #[test]
    fn test_into_iter_mut_ref() {
        let mut list = CurlList::new();
        list.push_back(1);
        list.push_back(2);
        for val in &mut list {
            *val += 100;
        }
        assert_eq!(list.front(), Some(&101));
        assert_eq!(list.back(), Some(&102));
    }

    #[test]
    fn test_drain_filter_evens() {
        let mut list = CurlList::new();
        for i in 0..6 {
            list.push_back(i);
        }
        let evens = list.drain_filter(|x| *x % 2 == 0);
        assert_eq!(evens, vec![0, 2, 4]);
        let remaining: Vec<_> = list.iter().copied().collect();
        assert_eq!(remaining, vec![1, 3, 5]);
    }

    #[test]
    fn test_drain_filter_none() {
        let mut list = CurlList::new();
        list.push_back(1);
        list.push_back(2);
        let drained = list.drain_filter(|_| false);
        assert!(drained.is_empty());
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_drain_filter_all() {
        let mut list = CurlList::new();
        list.push_back(1);
        list.push_back(2);
        let drained = list.drain_filter(|_| true);
        assert_eq!(drained, vec![1, 2]);
        assert!(list.is_empty());
    }

    #[test]
    fn test_drain_filter_empty_list() {
        let mut list: CurlList<i32> = CurlList::new();
        let drained = list.drain_filter(|_| true);
        assert!(drained.is_empty());
        assert!(list.is_empty());
    }

    #[test]
    fn test_from_iterator() {
        let list: CurlList<i32> = vec![1, 2, 3].into_iter().collect();
        assert_eq!(list.len(), 3);
        assert_eq!(list.front(), Some(&1));
        assert_eq!(list.back(), Some(&3));
    }

    #[test]
    fn test_extend() {
        let mut list = CurlList::new();
        list.push_back(1);
        list.extend(vec![2, 3, 4]);
        assert_eq!(list.len(), 4);
        let v: Vec<_> = list.iter().copied().collect();
        assert_eq!(v, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_index() {
        let mut list = CurlList::new();
        list.push_back(10);
        list.push_back(20);
        list.push_back(30);
        assert_eq!(list[0], 10);
        assert_eq!(list[1], 20);
        assert_eq!(list[2], 30);
    }

    #[test]
    fn test_index_mut() {
        let mut list = CurlList::new();
        list.push_back(10);
        list.push_back(20);
        list[0] = 100;
        assert_eq!(list[0], 100);
    }

    #[test]
    fn test_clone() {
        let mut list = CurlList::new();
        list.push_back(1);
        list.push_back(2);
        let cloned = list.clone();
        assert_eq!(list, cloned);
    }

    #[test]
    fn test_eq() {
        let mut a = CurlList::new();
        a.push_back(1);
        a.push_back(2);
        let mut b = CurlList::new();
        b.push_back(1);
        b.push_back(2);
        assert_eq!(a, b);
        b.push_back(3);
        assert_ne!(a, b);
    }

    #[test]
    fn test_empty_list_operations_dont_panic() {
        let mut list: CurlList<i32> = CurlList::new();
        assert_eq!(list.front(), None);
        assert_eq!(list.back(), None);
        assert_eq!(list.pop_front(), None);
        assert_eq!(list.pop_back(), None);
        assert_eq!(list.remove(0), None);
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
        list.retain(|_| true);
        list.clear();
        let drained = list.drain_filter(|_| true);
        assert!(drained.is_empty());
    }

    #[test]
    fn test_mixed_push_pop() {
        let mut list = CurlList::new();
        // Simulate stack usage (LIFO from back)
        list.push_back(1);
        list.push_back(2);
        list.push_back(3);
        assert_eq!(list.pop_back(), Some(3));
        list.push_back(4);
        assert_eq!(list.pop_back(), Some(4));
        assert_eq!(list.pop_back(), Some(2));
        assert_eq!(list.pop_back(), Some(1));
        assert!(list.is_empty());
    }

    #[test]
    fn test_queue_fifo() {
        // Simulate FIFO queue: push_back, pop_front
        let mut list = CurlList::new();
        list.push_back(1);
        list.push_back(2);
        list.push_back(3);
        assert_eq!(list.pop_front(), Some(1));
        assert_eq!(list.pop_front(), Some(2));
        list.push_back(4);
        assert_eq!(list.pop_front(), Some(3));
        assert_eq!(list.pop_front(), Some(4));
        assert!(list.is_empty());
    }

    #[test]
    fn test_large_list() {
        let mut list = CurlList::new();
        for i in 0..10_000 {
            list.push_back(i);
        }
        assert_eq!(list.len(), 10_000);
        assert_eq!(list.front(), Some(&0));
        assert_eq!(list.back(), Some(&9999));
        // Remove all odds
        list.retain(|&x| x % 2 == 0);
        assert_eq!(list.len(), 5_000);
    }

    #[test]
    fn test_string_elements() {
        let mut list = CurlList::new();
        list.push_back(String::from("alpha"));
        list.push_back(String::from("beta"));
        list.push_back(String::from("gamma"));
        assert_eq!(list.front().map(|s| s.as_str()), Some("alpha"));
        assert_eq!(list.back().map(|s| s.as_str()), Some("gamma"));
        let removed = list.remove(1);
        assert_eq!(removed.as_deref(), Some("beta"));
    }
}
