// Doubly-linked list container for the curl-rs workspace.
//
// SPDX-License-Identifier: curl
//
// This file is a memory-safe Rust reimplementation of curl's intrusive linked
// list (`lib/llist.c` / `lib/llist.h`). The original C sources are
//   Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// and are licensed under the curl license (https://curl.se/docs/copyright.html).
// This Rust port preserves the observable behavior and the public API *names*
// of that container; it is a behavioral translation, not a line-by-line one.

//! Owning, FIFO-ordered list container — the safe replacement for curl's
//! intrusive doubly-linked list (`lib/llist.c` / `lib/llist.h`).
//!
//! # Why this is a `VecDeque`, not a pointer list
//!
//! curl's C implementation is an *intrusive* doubly-linked list: each stored
//! object embeds a `struct Curl_llist_node` carrying raw `_next`/`_prev`
//! pointers, and the list threads those nodes together by hand. That design
//! depends on raw pointer manipulation, which is exactly what the
//! workspace-wide `#![forbid(unsafe_code)]` rule (AAP §0.7.1) prohibits.
//!
//! A faithful *safe* translation collapses the intrusive list onto an owning
//! `std::collections::VecDeque<T>`. The `VecDeque` provides O(1) push/pop at
//! both ends and preserves the **FIFO ordering** that curl's queues rely on:
//! pending transfers, message lists, and send queues are all order-sensitive,
//! so the head is always the oldest element and `append` always adds at the
//! tail. Ownership plus deterministic `Drop` replace curl's manual
//! `malloc`/`free` and `_dtor` lifecycle.
//!
//! # API shape
//!
//! Two complementary surfaces are exposed on [`CurlLList`]:
//!
//! * **Idiomatic Rust** — `push_back`/`push_front`, `pop_front`/`pop_back`,
//!   `front`/`back`, `get`/`get_mut`, `len`/`is_empty`, `iter`/`iter_mut`,
//!   `insert`, `remove`, `take_elem`, `destroy`. Prefer these in new Rust code.
//! * **curl-named wrappers** — `Curl_llist_append`, `Curl_llist_insert_next`,
//!   `Curl_llist_head`, `Curl_llist_tail`, `Curl_llist_count`,
//!   `Curl_node_remove`, `Curl_node_take_elem`, `Curl_node_elem`,
//!   `Curl_llist_destroy`. These keep curl's original names and semantics to
//!   ease porting of C call sites, operating by **index** rather than by node
//!   pointer.
//!
//! # Porting curl's node-pointer API
//!
//! curl's node-walking primitives have no safe pointer-based analog. They are
//! replaced by Rust iterators and indexed access:
//!
//! | curl C API (pointer walk) | Safe Rust replacement                          |
//! |---------------------------|------------------------------------------------|
//! | `Curl_node_next(n)`       | `iter()` / `iter_mut()` / index `get(i + 1)`   |
//! | `Curl_node_prev(n)`       | `iter().rev()` / index `get(i - 1)`            |
//! | `Curl_node_elem(n)`       | `get(i)` / `Curl_node_elem(i)`                 |
//! | `Curl_node_llist(n)`      | the owning `CurlLList` is the receiver `self`  |
//!
//! A C loop such as `for(n = Curl_llist_head(l); n; n = Curl_node_next(n))`
//! becomes the iterator loop `for elem in list.iter() { /* ... */ }`.
//!
//! # The destructor hook
//!
//! curl registers a `Curl_llist_dtor` that is invoked once per element when the
//! element leaves the list via `Curl_node_remove` / `Curl_llist_destroy` (in C
//! that callback frees the element). In Rust, value `Drop` is the real
//! reclamation mechanism, so an explicit hook is normally unnecessary — prefer
//! `Drop`. For behavioral parity an **optional** hook of type `fn(&mut T)` may
//! be registered with [`CurlLList::with_dtor`]. It is a *supplement* to `Drop`,
//! not a replacement, and because it only borrows the element (`&mut T`) it can
//! never free or double-free it.
//!
//! The hook runs when an element is *disposed of by the list*: in `remove`,
//! `destroy`, and on `Drop` of the list. Operations that *extract* an element
//! and transfer ownership to the caller — `take_elem`, `pop_front`,
//! `pop_back`, and owned iteration (`for x in list { .. }`) — deliberately do
//! **not** run the hook, mirroring curl's `Curl_node_take_elem`. When no hook
//! is registered (the common case) `remove` and `take_elem` behave identically.
//!
//! # Example
//!
//! ```text
//! let mut list = CurlLList::new();
//! list.Curl_llist_append("first");   // tail
//! list.Curl_llist_append("second");  // tail
//! assert_eq!(list.Curl_llist_count(), 2);
//! assert_eq!(list.Curl_llist_head(), Some(&"first"));  // oldest
//! assert_eq!(list.Curl_llist_tail(), Some(&"second")); // newest
//! for item in list.iter() { /* head-to-tail (FIFO) */ }
//! ```

use std::collections::vec_deque::{IntoIter, Iter, IterMut};
use std::collections::VecDeque;
use std::fmt;

/// Optional per-element destructor hook.
///
/// Mirrors curl's `Curl_llist_dtor` (`void (*)(void *user, void *elem)`),
/// reduced to `fn(&mut T)` because the Rust container owns its elements and the
/// C `user` context pointer is unnecessary in the ownership model. The hook
/// borrows the element mutably, so it may perform cleanup or notification but
/// can never deallocate the element — that remains `Drop`'s responsibility.
pub type Dtor<T> = fn(&mut T);

/// An owning, FIFO-ordered list container — the safe replacement for curl's
/// intrusive `struct Curl_llist`.
///
/// The front of the list is the **head** (oldest element); the back is the
/// **tail** (newest element). See the [module documentation](self) for the
/// design rationale and the full mapping from curl's C API.
pub struct CurlLList<T> {
    /// Backing store. Front == head (oldest), back == tail (newest).
    items: VecDeque<T>,
    /// Optional parity destructor hook (see the module-level documentation).
    dtor: Option<Dtor<T>>,
}

impl<T> CurlLList<T> {
    // ------------------------------------------------------------------
    // Construction (curl: `Curl_llist_init`)
    // ------------------------------------------------------------------

    /// Creates an empty list with no destructor hook.
    ///
    /// Equivalent to curl's `Curl_llist_init(list, NULL)`.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: VecDeque::new(),
            dtor: None,
        }
    }

    /// Creates an empty list with the given destructor hook registered.
    ///
    /// Equivalent to curl's `Curl_llist_init(list, dtor)`. The hook is run on
    /// each element disposed of via `remove`, `destroy`, or `Drop` (see the
    /// module-level documentation for the precise rules).
    #[inline]
    #[must_use]
    pub fn with_dtor(dtor: Dtor<T>) -> Self {
        Self {
            items: VecDeque::new(),
            dtor: Some(dtor),
        }
    }

    /// Creates an empty list (with no destructor hook) preallocated for at
    /// least `capacity` elements.
    #[inline]
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            items: VecDeque::with_capacity(capacity),
            dtor: None,
        }
    }

    /// Registers (or replaces) the destructor hook. Pass `None` to clear it.
    #[inline]
    pub fn set_dtor(&mut self, dtor: Option<Dtor<T>>) {
        self.dtor = dtor;
    }

    /// Returns `true` if a destructor hook is currently registered.
    #[inline]
    #[must_use]
    pub fn has_dtor(&self) -> bool {
        self.dtor.is_some()
    }

    // ------------------------------------------------------------------
    // Inspection (curl: `Curl_llist_count`, head/tail accessors)
    // ------------------------------------------------------------------

    /// Returns the number of elements in the list.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns `true` when the list holds no elements.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Borrows the head (oldest) element, or `None` when the list is empty.
    #[inline]
    #[must_use]
    pub fn front(&self) -> Option<&T> {
        self.items.front()
    }

    /// Mutably borrows the head (oldest) element, or `None` when empty.
    #[inline]
    pub fn front_mut(&mut self) -> Option<&mut T> {
        self.items.front_mut()
    }

    /// Borrows the tail (newest) element, or `None` when the list is empty.
    #[inline]
    #[must_use]
    pub fn back(&self) -> Option<&T> {
        self.items.back()
    }

    /// Mutably borrows the tail (newest) element, or `None` when empty.
    #[inline]
    pub fn back_mut(&mut self) -> Option<&mut T> {
        self.items.back_mut()
    }

    /// Borrows the element at `index` (0 == head), or `None` if out of range.
    #[inline]
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&T> {
        self.items.get(index)
    }

    /// Mutably borrows the element at `index`, or `None` if out of range.
    #[inline]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.items.get_mut(index)
    }

    // ------------------------------------------------------------------
    // Insertion (curl: `Curl_llist_append`, `Curl_llist_insert_next`)
    // ------------------------------------------------------------------

    /// Appends `value` at the tail (newest position). Runs in O(1).
    #[inline]
    pub fn push_back(&mut self, value: T) {
        self.items.push_back(value);
    }

    /// Pushes `value` at the head (oldest position). Runs in O(1).
    #[inline]
    pub fn push_front(&mut self, value: T) {
        self.items.push_front(value);
    }

    /// Inserts `value` so that it ends up at `index`, shifting later elements
    /// toward the tail.
    ///
    /// Unlike [`VecDeque::insert`], an out-of-range `index` is **clamped** to
    /// the tail (the value is appended) rather than panicking, matching the
    /// tolerant behavior of curl's pointer-based `Curl_llist_insert_next`.
    pub fn insert(&mut self, index: usize, value: T) {
        let pos = index.min(self.items.len());
        self.items.insert(pos, value);
    }

    // ------------------------------------------------------------------
    // Removal (curl: `Curl_node_remove`, `Curl_node_take_elem`,
    //          `Curl_llist_destroy`)
    // ------------------------------------------------------------------

    /// Removes and returns the head (oldest) element, or `None` when empty.
    ///
    /// This is an *extraction*: ownership transfers to the caller and the
    /// destructor hook is **not** run.
    #[inline]
    pub fn pop_front(&mut self) -> Option<T> {
        self.items.pop_front()
    }

    /// Removes and returns the tail (newest) element, or `None` when empty.
    ///
    /// Like [`Self::pop_front`], this is an extraction and the destructor hook
    /// is **not** run.
    #[inline]
    pub fn pop_back(&mut self) -> Option<T> {
        self.items.pop_back()
    }

    /// Removes the element at `index`, runs the destructor hook on it (if a
    /// hook is registered), and returns it. Returns `None` when `index` is out
    /// of range.
    ///
    /// Mirrors curl's `Curl_node_remove`, which invokes the registered `_dtor`.
    /// When no hook is registered this is equivalent to [`Self::take_elem`].
    /// Because the hook only borrows the element, the returned value remains
    /// fully valid; its real reclamation happens when the caller drops it.
    pub fn remove(&mut self, index: usize) -> Option<T> {
        let mut elem = self.items.remove(index)?;
        if let Some(dtor) = self.dtor {
            dtor(&mut elem);
        }
        Some(elem)
    }

    /// Removes the element at `index` and returns it **without** running the
    /// destructor hook. Returns `None` when `index` is out of range.
    ///
    /// Mirrors curl's `Curl_node_take_elem` (detach and return ownership; the
    /// `_dtor` is intentionally skipped).
    #[inline]
    pub fn take_elem(&mut self, index: usize) -> Option<T> {
        self.items.remove(index)
    }

    /// Empties the list, running the destructor hook on every element (if a
    /// hook is registered) before the elements are dropped.
    ///
    /// Mirrors curl's `Curl_llist_destroy`. Dropping the list value has the
    /// same effect (see the [`Drop`] implementation), so calling this
    /// explicitly is only necessary when the list value is to be reused
    /// afterwards.
    pub fn destroy(&mut self) {
        if let Some(dtor) = self.dtor {
            for elem in &mut self.items {
                dtor(elem);
            }
        }
        self.items.clear();
    }

    // ------------------------------------------------------------------
    // Iteration (curl: `Curl_node_next` / `Curl_node_prev` walking)
    // ------------------------------------------------------------------

    /// Returns a front-to-back (head-to-tail, i.e. oldest-to-newest) iterator
    /// over shared references to the elements.
    #[inline]
    pub fn iter(&self) -> Iter<'_, T> {
        self.items.iter()
    }

    /// Returns a front-to-back iterator over mutable references to the
    /// elements.
    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_, T> {
        self.items.iter_mut()
    }
}

/// curl-named compatibility surface.
///
/// These methods preserve the names and semantics of curl's `Curl_llist_*` /
/// `Curl_node_*` C API to ease porting of existing call sites. The node-pointer
/// primitives are re-expressed in terms of an **index** (or, for traversal, the
/// idiomatic iterators — see the [module documentation](self)).
///
/// The block is annotated `#[allow(non_snake_case)]` because it intentionally
/// uses curl's C identifiers, which are not `snake_case`.
#[allow(non_snake_case)]
impl<T> CurlLList<T> {
    /// Adds `data` to the end (tail) of the list.
    ///
    /// Equivalent to curl's `Curl_llist_append`.
    #[inline]
    pub fn Curl_llist_append(&mut self, data: T) {
        self.push_back(data);
    }

    /// Inserts `data` after the element at `after_index`.
    ///
    /// `after_index == None` inserts the element at the **head**, mirroring
    /// curl's `Curl_llist_insert_next` invoked with a `NULL` node (which means
    /// "insert first"). `Some(i)` inserts immediately after index `i`; an
    /// out-of-range `i` is clamped so the element is appended at the tail.
    pub fn Curl_llist_insert_next(&mut self, after_index: Option<usize>, data: T) {
        let pos = match after_index {
            None => 0,
            Some(i) => i.saturating_add(1).min(self.items.len()),
        };
        self.items.insert(pos, data);
    }

    /// Borrows the head (oldest) element, or `None` when empty.
    ///
    /// Equivalent to curl's `Curl_llist_head` (which returns the head *node*;
    /// here the stored element is returned directly).
    #[inline]
    #[must_use]
    pub fn Curl_llist_head(&self) -> Option<&T> {
        self.front()
    }

    /// Borrows the tail (newest) element, or `None` when empty.
    ///
    /// Equivalent to curl's `Curl_llist_tail`.
    #[inline]
    #[must_use]
    pub fn Curl_llist_tail(&self) -> Option<&T> {
        self.back()
    }

    /// Returns the number of elements. Equivalent to curl's `Curl_llist_count`.
    #[inline]
    #[must_use]
    pub fn Curl_llist_count(&self) -> usize {
        self.len()
    }

    /// Borrows the element stored at `index`, or `None` if out of range.
    ///
    /// Index-based replacement for curl's `Curl_node_elem` (which read the
    /// stored pointer out of a node).
    #[inline]
    #[must_use]
    pub fn Curl_node_elem(&self, index: usize) -> Option<&T> {
        self.get(index)
    }

    /// Removes the element at `index` and returns it **without** running the
    /// destructor hook.
    ///
    /// Index-based replacement for curl's `Curl_node_take_elem`.
    #[inline]
    pub fn Curl_node_take_elem(&mut self, index: usize) -> Option<T> {
        self.take_elem(index)
    }

    /// Removes the element at `index`, runs the destructor hook on it, and
    /// returns it.
    ///
    /// Index-based replacement for curl's `Curl_node_remove`. Note that the C
    /// function returns `void`; this returns the removed element for
    /// convenience (it may be ignored, in which case it is dropped
    /// immediately).
    #[inline]
    pub fn Curl_node_remove(&mut self, index: usize) -> Option<T> {
        self.remove(index)
    }

    /// Empties the list, running the destructor hook on each element.
    ///
    /// Equivalent to curl's `Curl_llist_destroy`.
    #[inline]
    pub fn Curl_llist_destroy(&mut self) {
        self.destroy();
    }
}

impl<T> Default for CurlLList<T> {
    /// Creates an empty list with no destructor hook.
    ///
    /// Implemented manually (rather than via `#[derive(Default)]`) so that it
    /// does **not** impose a `T: Default` bound — a container must be
    /// default-constructible regardless of its element type, exactly like
    /// `VecDeque`.
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T> fmt::Debug for CurlLList<T> {
    /// Structural debug output that does not require `T: Debug`, so the
    /// container can hold non-`Debug` payloads (handles, callbacks, etc.).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CurlLList")
            .field("len", &self.items.len())
            .field("has_dtor", &self.dtor.is_some())
            .finish()
    }
}

impl<T> Drop for CurlLList<T> {
    /// Runs the destructor hook (if any) on every remaining element, for parity
    /// with curl's `Curl_llist_destroy`. The elements themselves are then
    /// dropped by `VecDeque`'s own `Drop`, which is the real reclamation step.
    fn drop(&mut self) {
        if let Some(dtor) = self.dtor {
            for elem in &mut self.items {
                dtor(elem);
            }
        }
    }
}

impl<T> Extend<T> for CurlLList<T> {
    /// Appends every item from `iter` at the tail, preserving their order.
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.items.extend(iter);
    }
}

impl<T> FromIterator<T> for CurlLList<T> {
    /// Builds a list (with no destructor hook) from an iterator, preserving
    /// iteration order — the first item becomes the head.
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self {
            items: iter.into_iter().collect(),
            dtor: None,
        }
    }
}

impl<T> IntoIterator for CurlLList<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    /// Consumes the list, yielding its elements head-to-tail.
    ///
    /// This is an *extraction*: the destructor hook is **not** run on the
    /// yielded elements (ownership transfers to the caller), mirroring a
    /// sequence of `Curl_node_take_elem` calls.
    fn into_iter(mut self) -> Self::IntoIter {
        // Move the backing store out so the elements are handed to the caller
        // untouched. `self` (now holding an empty deque) is dropped when this
        // function returns; its `Drop` then runs the hook over zero elements.
        std::mem::take(&mut self.items).into_iter()
    }
}

impl<'a, T> IntoIterator for &'a CurlLList<T> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut CurlLList<T> {
    type Item = &'a mut T;
    type IntoIter = IterMut<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.items.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A test payload whose `cleaned` counter is bumped by `marking_dtor`, so a
    /// test can observe whether the destructor hook ran on a given element.
    #[derive(Debug, Clone)]
    struct Item {
        id: u32,
        cleaned: u32,
    }

    impl Item {
        fn new(id: u32) -> Self {
            Self { id, cleaned: 0 }
        }
    }

    /// Element-mutating destructor hook (no shared state) used to verify that
    /// `remove`/`destroy` run the hook while `take_elem`/extraction do not.
    fn marking_dtor(it: &mut Item) {
        it.cleaned = it.cleaned.saturating_add(1);
    }

    /// Shared counter touched by exactly one test
    /// (`dtor_runs_on_destroy_and_on_drop`); keeping it to a single test means
    /// it is free of cross-test data races even under parallel execution.
    static DTOR_CALLS: AtomicUsize = AtomicUsize::new(0);

    /// Counting destructor hook, paired with `DTOR_CALLS`.
    fn counting_dtor(_it: &mut Item) {
        DTOR_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn new_and_default_are_empty() {
        let a: CurlLList<Item> = CurlLList::new();
        let b: CurlLList<Item> = CurlLList::default();
        for l in [&a, &b] {
            assert_eq!(l.len(), 0);
            assert!(l.is_empty());
            assert!(l.front().is_none());
            assert!(l.back().is_none());
            assert!(l.get(0).is_none());
        }
        assert!(!a.has_dtor());
    }

    #[test]
    fn append_sets_head_tail_count() {
        let mut l = CurlLList::new();
        l.push_back(Item::new(1));
        l.push_back(Item::new(2));
        l.push_back(Item::new(3));
        assert_eq!(l.len(), 3);
        assert!(!l.is_empty());
        assert_eq!(l.front().unwrap().id, 1); // oldest
        assert_eq!(l.back().unwrap().id, 3); // newest
        assert_eq!(l.get(1).unwrap().id, 2);
    }

    #[test]
    fn curl_named_append_and_accessors() {
        let mut l = CurlLList::new();
        l.Curl_llist_append(Item::new(10));
        l.Curl_llist_append(Item::new(20));
        assert_eq!(l.Curl_llist_count(), 2);
        assert_eq!(l.Curl_llist_head().unwrap().id, 10);
        assert_eq!(l.Curl_llist_tail().unwrap().id, 20);
        assert_eq!(l.Curl_node_elem(1).unwrap().id, 20);
        assert!(l.Curl_node_elem(99).is_none());
    }

    #[test]
    fn insert_next_at_head_when_none() {
        let mut l = CurlLList::new();
        l.Curl_llist_append(Item::new(1));
        l.Curl_llist_append(Item::new(2));
        // None => insert first (at the head), mirroring a NULL node in C.
        l.Curl_llist_insert_next(None, Item::new(99));
        assert_eq!(l.Curl_llist_count(), 3);
        assert_eq!(l.front().unwrap().id, 99);
        let ids: Vec<u32> = l.iter().map(|i| i.id).collect();
        assert_eq!(ids, [99u32, 1, 2]);
    }

    #[test]
    fn insert_next_in_middle() {
        let mut l: CurlLList<Item> = (1u32..=3).map(Item::new).collect();
        // After index 0 => position 1.
        l.Curl_llist_insert_next(Some(0), Item::new(50));
        let ids: Vec<u32> = l.iter().map(|i| i.id).collect();
        assert_eq!(ids, [1u32, 50, 2, 3]);
    }

    #[test]
    fn insert_next_after_tail_appends_and_clamps() {
        let mut l: CurlLList<Item> = (1u32..=3).map(Item::new).collect();
        // After the last index => append.
        l.Curl_llist_insert_next(Some(2), Item::new(77));
        assert_eq!(l.back().unwrap().id, 77);
        // An out-of-range index is clamped so the element is appended.
        l.Curl_llist_insert_next(Some(999), Item::new(88));
        assert_eq!(l.back().unwrap().id, 88);
        assert_eq!(l.len(), 5);
    }

    #[test]
    fn remove_returns_element_and_decrements() {
        let mut l: CurlLList<Item> = (1u32..=3).map(Item::new).collect();
        let removed = l.remove(1).unwrap();
        assert_eq!(removed.id, 2);
        assert_eq!(l.len(), 2);
        let ids: Vec<u32> = l.iter().map(|i| i.id).collect();
        assert_eq!(ids, [1u32, 3]);
        // Out-of-range removal yields None and does not change the length.
        assert!(l.remove(99).is_none());
        assert_eq!(l.len(), 2);
    }

    #[test]
    fn remove_runs_dtor_take_elem_does_not() {
        let mut l = CurlLList::with_dtor(marking_dtor);
        l.push_back(Item::new(1));
        l.push_back(Item::new(2));
        // `remove` runs the dtor hook -> cleaned incremented.
        let r = l.remove(0).unwrap();
        assert_eq!(r.id, 1);
        assert_eq!(r.cleaned, 1, "remove must run the dtor hook");
        // `take_elem` skips the dtor hook -> cleaned stays 0.
        let t = l.take_elem(0).unwrap();
        assert_eq!(t.id, 2);
        assert_eq!(t.cleaned, 0, "take_elem must NOT run the dtor hook");
        assert!(l.is_empty());
    }

    #[test]
    fn curl_node_remove_matches_remove() {
        let mut l = CurlLList::with_dtor(marking_dtor);
        l.Curl_llist_append(Item::new(7));
        let r = l.Curl_node_remove(0).unwrap();
        assert_eq!(r.id, 7);
        assert_eq!(r.cleaned, 1);
        assert!(l.is_empty());
    }

    #[test]
    fn destroy_empties_the_list() {
        let mut l: CurlLList<Item> = (1u32..=4).map(Item::new).collect();
        assert_eq!(l.len(), 4);
        l.destroy();
        assert!(l.is_empty());
        assert_eq!(l.len(), 0);
        // curl-named alias behaves the same.
        l.push_back(Item::new(9));
        l.Curl_llist_destroy();
        assert!(l.is_empty());
    }

    // This is the ONLY test that touches `DTOR_CALLS` / `counting_dtor`, so the
    // static counter is race-free even under parallel test execution.
    #[test]
    fn dtor_runs_on_destroy_and_on_drop() {
        // `destroy()` runs the hook once per element.
        DTOR_CALLS.store(0, Ordering::SeqCst);
        let mut l = CurlLList::with_dtor(counting_dtor);
        l.push_back(Item::new(1));
        l.push_back(Item::new(2));
        l.push_back(Item::new(3));
        l.destroy();
        assert_eq!(DTOR_CALLS.load(Ordering::SeqCst), 3);

        // `Drop` runs the hook on whatever remains in the list.
        DTOR_CALLS.store(0, Ordering::SeqCst);
        {
            let mut l2 = CurlLList::with_dtor(counting_dtor);
            l2.push_back(Item::new(1));
            l2.push_back(Item::new(2));
            // dropped here at end of scope
        }
        assert_eq!(DTOR_CALLS.load(Ordering::SeqCst), 2);

        // Extracted elements (take_elem) are NOT counted; only the remaining
        // element is finalized on drop.
        DTOR_CALLS.store(0, Ordering::SeqCst);
        {
            let mut l3 = CurlLList::with_dtor(counting_dtor);
            l3.push_back(Item::new(1));
            l3.push_back(Item::new(2));
            let _taken = l3.take_elem(0); // not counted
                                          // one element remains -> counted on drop
        }
        assert_eq!(DTOR_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn fifo_ordering_is_preserved() {
        let mut l = CurlLList::new();
        for i in 1..=5 {
            l.push_back(i);
        }
        // `iter` yields oldest-to-newest.
        let order: Vec<i32> = l.iter().copied().collect();
        assert_eq!(order, [1, 2, 3, 4, 5]);
        // `pop_front` yields the oldest first (FIFO).
        assert_eq!(l.pop_front(), Some(1));
        assert_eq!(l.pop_front(), Some(2));
        // `pop_back` yields the newest.
        assert_eq!(l.back().copied(), Some(5));
        assert_eq!(l.pop_back(), Some(5));
    }

    #[test]
    fn push_front_orders_before_head() {
        let mut l = CurlLList::new();
        l.push_back(2);
        l.push_front(1);
        l.push_back(3);
        let order: Vec<i32> = l.iter().copied().collect();
        assert_eq!(order, [1, 2, 3]);
    }

    #[test]
    fn iter_mut_allows_mutation() {
        let mut l: CurlLList<i32> = (1..=3).collect();
        l.iter_mut().for_each(|v| *v *= 10);
        let order: Vec<i32> = l.iter().copied().collect();
        assert_eq!(order, [10, 20, 30]);
        if let Some(f) = l.front_mut() {
            *f += 1;
        }
        assert_eq!(l.front().copied(), Some(11));
        if let Some(b) = l.back_mut() {
            *b += 1;
        }
        assert_eq!(l.back().copied(), Some(31));
    }

    #[test]
    fn into_iter_consumes_in_order_without_dtor() {
        // Owned `IntoIterator` extracts elements; the dtor hook must NOT run.
        let mut l = CurlLList::with_dtor(marking_dtor);
        l.push_back(Item::new(1));
        l.push_back(Item::new(2));
        let collected: Vec<Item> = l.into_iter().collect();
        assert_eq!(
            collected.iter().map(|i| i.id).collect::<Vec<u32>>(),
            [1u32, 2]
        );
        assert!(
            collected.iter().all(|i| i.cleaned == 0),
            "owned into_iter must not run the dtor hook"
        );
    }

    #[test]
    fn ref_into_iter_borrows() {
        let l: CurlLList<i32> = (1..=3).collect();
        let mut sum = 0;
        for v in &l {
            sum += *v;
        }
        assert_eq!(sum, 6);
        assert_eq!(l.len(), 3); // not consumed
    }

    #[test]
    fn ref_mut_into_iter_mutates() {
        let mut l: CurlLList<i32> = (1..=3).collect();
        for v in &mut l {
            *v += 1;
        }
        assert_eq!(l.iter().copied().collect::<Vec<i32>>(), [2, 3, 4]);
    }

    #[test]
    fn extend_and_from_iter_preserve_order() {
        let mut l: CurlLList<i32> = [1, 2].into_iter().collect();
        l.extend([3, 4]);
        assert_eq!(l.iter().copied().collect::<Vec<i32>>(), [1, 2, 3, 4]);
        assert_eq!(l.Curl_llist_count(), 4);
    }

    #[test]
    fn insert_clamps_out_of_range() {
        let mut l: CurlLList<i32> = (1..=3).collect();
        l.insert(99, 100); // clamps to the tail
        assert_eq!(l.back().copied(), Some(100));
        l.insert(0, 0); // head
        assert_eq!(l.front().copied(), Some(0));
        assert_eq!(l.iter().copied().collect::<Vec<i32>>(), [0, 1, 2, 3, 100]);
    }

    #[test]
    fn with_capacity_and_set_dtor() {
        let mut l: CurlLList<Item> = CurlLList::with_capacity(8);
        assert!(l.is_empty());
        assert!(!l.has_dtor());
        l.set_dtor(Some(marking_dtor));
        assert!(l.has_dtor());
        l.push_back(Item::new(1));
        let r = l.remove(0).unwrap();
        assert_eq!(r.cleaned, 1);
        l.set_dtor(None);
        assert!(!l.has_dtor());
    }

    #[test]
    fn debug_is_structural() {
        let l: CurlLList<i32> = (1..=2).collect();
        let s = format!("{l:?}");
        assert!(s.contains("CurlLList"));
        assert!(s.contains("len"));
        assert!(s.contains("has_dtor"));
        assert!(s.contains('2'));
    }
}
