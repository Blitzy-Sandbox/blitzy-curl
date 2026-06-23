// SPDX-License-Identifier: curl
//
// Rust rewrite of libcurl's `lib/hash.c` / `lib/hash.h` for the curl-rs project
// (C -> Rust migration of curl 8.19.0-DEV). Behavioral parity, NOT a line-by-line
// transliteration: the C oracle is `lib/hash.c` and `lib/hash.h`.

//! Hash-map container — a memory-safe Rust replacement for curl's hand-rolled
//! open-chaining hash table (`struct Curl_hash`).
//!
//! # Why this collapses onto [`std::collections::HashMap`]
//!
//! libcurl's `Curl_hash` is a classic separate-chaining hash table: a `table`
//! of `slots` buckets, a `hash_func` mapping a key to a bucket, a `comp_func`
//! comparing two keys for equality, and a `dtor` destructor invoked on a stored
//! value when an element is removed. Every one of those responsibilities is
//! provided natively and more safely by the standard library:
//!
//! | C concept (`Curl_hash`)            | Rust equivalent                         |
//! |------------------------------------|-----------------------------------------|
//! | `table` / `slots` (buckets)        | [`HashMap`] internal storage            |
//! | `hash_func` (`Curl_hash_str`)      | [`HashMap`]'s `Hash` on the byte key    |
//! | `comp_func` (`curlx_str_key_compare`) | [`HashMap`]'s `Eq` on the byte key   |
//! | `Curl_hash_element` chain          | [`HashMap`] entries                     |
//! | `dtor` per-element / general       | value [`Drop`] (+ optional hook, below) |
//!
//! Because of this, the `slots`, `hash_func`, and `comp_func` arguments of
//! `Curl_hash_init` are intentionally **dropped** in the Rust API — the
//! `HashMap` owns hashing and comparison. The original key helpers
//! [`curl_hash_str`] and [`curlx_str_key_compare`] are still provided as free
//! functions for API parity, but they are *not* used internally.
//!
//! # Keys are arbitrary byte buffers
//!
//! curl keys are `void *key` + explicit `size_t key_len`; they are **not**
//! guaranteed to be valid UTF-8 (e.g. binary connection-cache keys). The keys
//! here are therefore [`Vec<u8>`] / `&[u8]`, never `String` / `&str`.
//!
//! # Destructor (`dtor`) semantics
//!
//! In C, the `dtor` frees the stored `void *` value when an element is removed.
//! In Rust the value `V` owns its resources and is freed deterministically by
//! [`Drop`] when it is removed from the map — so **the idiomatic and preferred
//! mechanism is simply to store an owning `V` and let `Drop` run**.
//!
//! For parity with callers that pass an explicit destructor (the DNS cache and
//! the connection cache install one via `Curl_hash_init`), an optional
//! `dtor: Option<fn(&mut V)>` hook is retained. It is a **pre-drop
//! notification**: it borrows the value (`&mut V`) — it does *not* take
//! ownership and must *not* free anything — and is then followed by the normal
//! `Drop` of `V`. This makes double-free impossible by construction (memory
//! safety, AAP §0.7.1). The hook fires on:
//! [`curl_hash_delete`](CurlHash::curl_hash_delete),
//! [`curl_hash_clean`](CurlHash::curl_hash_clean),
//! [`curl_hash_clean_with_criterium`](CurlHash::curl_hash_clean_with_criterium),
//! [`curl_hash_destroy`](CurlHash::curl_hash_destroy), and on the displaced old
//! value when [`curl_hash_add`](CurlHash::curl_hash_add) replaces a key.
//!
//! libcurl additionally supports a *per-element* destructor via
//! `Curl_hash_add2`. That exists because C stores heterogeneous `void *` values
//! that need distinct cleanup. In Rust each `V` already cleans itself via
//! `Drop`, so heterogeneous cleanup needs no special support; the per-element
//! destructor of `Curl_hash_add2` therefore collapses onto the same single
//! hash-level hook (see [`curl_hash_add2`](CurlHash::curl_hash_add2)).
//!
//! Note: dropping the whole `CurlHash` (scope end) frees every value via `V`'s
//! own `Drop` — that is always memory-safe — but does **not** invoke the
//! optional hook (mirroring C, where teardown requires an explicit
//! `Curl_hash_destroy`). Call [`curl_hash_destroy`](CurlHash::curl_hash_destroy)
//! or [`curl_hash_clean`](CurlHash::curl_hash_clean) when hook parity matters.
//!
//! # Iteration order
//!
//! [`HashMap`] iteration order is unspecified. curl's bucket-walk order is also
//! effectively unspecified (it depends on the hash function and insertion
//! history), so unordered iteration is acceptable parity. No in-tree caller
//! relies on a deterministic order.
//!
//! # Memory safety
//!
//! This module forbids `unsafe` entirely (`#![forbid(unsafe_code)]`) and is a
//! pure wrapper over [`HashMap`] — there are no raw buckets or pointers.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt;

/// An optional per-value destructor hook.
///
/// Invoked with a mutable borrow of a value immediately *before* the value is
/// dropped when it is removed from a [`CurlHash`]. It is a notification only:
/// it must not attempt to free the value (Rust's [`Drop`] does that). This is
/// the Rust analogue of curl's `Curl_hash_dtor` / `Curl_hash_elem_dtor`.
pub type CurlHashDtor<V> = fn(&mut V);

/// A memory-safe hash map keyed by arbitrary byte sequences.
///
/// This is the Rust replacement for libcurl's `struct Curl_hash`. Values of
/// type `V` are owned by the map; keys are owned [`Vec<u8>`] byte buffers and
/// are looked up by `&[u8]` slices.
///
/// See the [module documentation](self) for the mapping from the C API and the
/// destructor (`dtor`) semantics.
///
/// # Examples
///
/// ```ignore
/// let mut h: CurlHash<u32> = CurlHash::new();
/// h.curl_hash_add(b"answer", 42);
/// assert_eq!(h.curl_hash_pick(b"answer"), Some(&42));
/// assert_eq!(h.curl_hash_count(), 1);
/// assert!(h.curl_hash_delete(b"answer"));
/// assert!(h.is_empty());
/// ```
pub struct CurlHash<V> {
    /// Backing storage. Keys are arbitrary byte buffers; `HashMap` owns the
    /// hashing (`Curl_hash_str` analogue) and key comparison
    /// (`curlx_str_key_compare` analogue).
    map: HashMap<Vec<u8>, V>,
    /// Optional pre-drop destructor hook applied to a value when it is removed.
    /// `None` means "rely solely on `V`'s `Drop`" (the common, preferred case).
    dtor: Option<CurlHashDtor<V>>,
}

impl<V> CurlHash<V> {
    /// Creates an empty hash with no destructor hook (values are cleaned up via
    /// their own [`Drop`]).
    ///
    /// This is the idiomatic constructor. See [`curl_hash_init`] for the
    /// C-parity constructor that accepts an explicit destructor.
    ///
    /// [`curl_hash_init`]: CurlHash::curl_hash_init
    #[must_use]
    pub fn new() -> Self {
        CurlHash {
            map: HashMap::new(),
            dtor: None,
        }
    }

    /// Creates an empty hash, pre-allocating room for at least `capacity`
    /// entries. Parity convenience for curl's `slots` sizing hint — purely an
    /// optimization; behavior is identical to [`new`](CurlHash::new).
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        CurlHash {
            map: HashMap::with_capacity(capacity),
            dtor: None,
        }
    }

    /// Creates an empty hash with an explicit destructor hook installed.
    ///
    /// Convenience equivalent to `curl_hash_init(Some(dtor))`.
    #[must_use]
    pub fn with_dtor(dtor: CurlHashDtor<V>) -> Self {
        CurlHash {
            map: HashMap::new(),
            dtor: Some(dtor),
        }
    }

    /// Initializes a hash — the Rust analogue of `Curl_hash_init`.
    ///
    /// The C signature is
    /// `Curl_hash_init(h, slots, hash_func, comp_func, dtor)`. The `slots`,
    /// `hash_func`, and `comp_func` parameters are **intentionally omitted**:
    /// the backing [`HashMap`] provides bucketing, hashing, and key comparison.
    /// Only the optional destructor survives (see the [module docs](self)).
    #[must_use]
    pub fn curl_hash_init(dtor: Option<CurlHashDtor<V>>) -> Self {
        CurlHash {
            map: HashMap::new(),
            dtor,
        }
    }

    /// Replaces the hash-level destructor hook. Subsequent removals use the new
    /// hook. Pass `None` to rely solely on value [`Drop`].
    pub fn set_dtor(&mut self, dtor: Option<CurlHashDtor<V>>) {
        self.dtor = dtor;
    }
}

// ---------------------------------------------------------------------------
// Core operations
// ---------------------------------------------------------------------------

impl<V> CurlHash<V> {
    /// Inserts `value` under `key`, replacing any existing value for that key.
    ///
    /// The Rust analogue of `Curl_hash_add`. Returns a mutable reference to the
    /// freshly stored value.
    ///
    /// If an entry already existed for `key`, the displaced old value has the
    /// destructor hook applied (if one is set) and is then dropped — matching
    /// curl, where adding an existing key clears the previous pointer via its
    /// destructor before overwriting it.
    ///
    /// # Return value
    ///
    /// C returns the stored pointer, or `NULL` only on out-of-memory. Rust has
    /// no equivalent fallible-allocation path here, so this always returns
    /// `Some(&mut value)`. The [`Option`] is retained for signature parity with
    /// the C "pointer or NULL" contract.
    pub fn curl_hash_add(&mut self, key: &[u8], value: V) -> Option<&mut V> {
        self.insert_with_dtor(key, value, None)
    }

    /// Inserts `value` under `key` with an explicit per-call destructor —
    /// the Rust analogue of `Curl_hash_add2`.
    ///
    /// In libcurl, `Curl_hash_add2` attaches a *per-element* destructor that
    /// overrides the hash-level one. In this idiomatic collapse, real cleanup
    /// is performed by each value's [`Drop`], so the distinct per-element
    /// destructor is unnecessary; the supplied `dtor` is installed as the
    /// hash's active hook (subsequent removals use it). When `dtor` is `None`
    /// the existing hook is left unchanged, exactly as `Curl_hash_add`
    /// (`= Curl_hash_add2(..., NULL)`) leaves the general destructor in place.
    ///
    /// See [`curl_hash_add`](CurlHash::curl_hash_add) for the return semantics.
    pub fn curl_hash_add2(
        &mut self,
        key: &[u8],
        value: V,
        dtor: Option<CurlHashDtor<V>>,
    ) -> Option<&mut V> {
        if dtor.is_some() {
            self.dtor = dtor;
        }
        self.insert_with_dtor(key, value, dtor)
    }

    /// Shared insert path for [`curl_hash_add`] and [`curl_hash_add2`].
    ///
    /// `old_dtor` is the destructor to apply to a displaced value: for
    /// `add2` it is the freshly supplied per-call hook, otherwise it falls back
    /// to the hash-level hook. This mirrors C's `hash_elem_clear_ptr`, which
    /// prefers the element destructor and falls back to the general one.
    ///
    /// [`curl_hash_add`]: CurlHash::curl_hash_add
    /// [`curl_hash_add2`]: CurlHash::curl_hash_add2
    fn insert_with_dtor(
        &mut self,
        key: &[u8],
        value: V,
        old_dtor: Option<CurlHashDtor<V>>,
    ) -> Option<&mut V> {
        // `HashMap::insert` returns the previous value for the key, if any.
        if let Some(mut old) = self.map.insert(key.to_vec(), value) {
            if let Some(d) = old_dtor.or(self.dtor) {
                d(&mut old);
            }
            // `old` is dropped here, after the hook has run.
        }
        self.map.get_mut(key)
    }

    /// Looks up the value stored under `key` — the Rust analogue of
    /// `Curl_hash_pick`. Returns `None` if the key is absent (C returns `NULL`).
    #[must_use]
    pub fn curl_hash_pick(&self, key: &[u8]) -> Option<&V> {
        self.map.get(key)
    }

    /// Idiomatic alias for [`curl_hash_pick`](CurlHash::curl_hash_pick).
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<&V> {
        self.map.get(key)
    }

    /// Returns a mutable reference to the value stored under `key`, if present.
    pub fn get_mut(&mut self, key: &[u8]) -> Option<&mut V> {
        self.map.get_mut(key)
    }

    /// Returns `true` if a value is stored under `key`.
    #[must_use]
    pub fn contains_key(&self, key: &[u8]) -> bool {
        self.map.contains_key(key)
    }

    /// Removes the entry identified by `key` — the Rust analogue of
    /// `Curl_hash_delete`.
    ///
    /// The destructor hook (if set) is applied to the removed value before it
    /// is dropped. Returns `true` if an entry was removed, `false` if `key` was
    /// not present.
    ///
    /// Note the boolean convention is inverted relative to C, which returns `0`
    /// on success and non-zero on failure.
    pub fn curl_hash_delete(&mut self, key: &[u8]) -> bool {
        match self.map.remove(key) {
            Some(mut value) => {
                if let Some(d) = self.dtor {
                    d(&mut value);
                }
                // `value` dropped here, after the hook.
                true
            }
            None => false,
        }
    }

    /// Returns the number of entries — the Rust analogue of `Curl_hash_count`.
    #[must_use]
    pub fn curl_hash_count(&self) -> usize {
        self.map.len()
    }

    /// Returns the number of entries. Idiomatic alias for
    /// [`curl_hash_count`](CurlHash::curl_hash_count).
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns `true` if the hash holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Removes every entry — the Rust analogue of `Curl_hash_clean`.
    ///
    /// The destructor hook (if set) is applied to each value before it is
    /// dropped.
    pub fn curl_hash_clean(&mut self) {
        // Copy the `fn` pointer out so the closure below does not borrow
        // `self` while `self.map` is borrowed mutably by `drain`.
        let dtor = self.dtor;
        if let Some(d) = dtor {
            for (_key, mut value) in self.map.drain() {
                d(&mut value);
                // `value` dropped at end of iteration, after the hook.
            }
        } else {
            self.map.clear();
        }
    }

    /// Idiomatic alias for [`curl_hash_clean`](CurlHash::curl_hash_clean).
    pub fn clear(&mut self) {
        self.curl_hash_clean();
    }

    /// Removes every entry for which `criterium` returns `true` — the Rust
    /// analogue of `Curl_hash_clean_with_criterium`.
    ///
    /// This preserves curl's predicate-prune contract used by the connection
    /// cache and DNS cache: the predicate inspects a stored value and returns
    /// `true` to **remove** it (matching curl's "returning non-zero means
    /// remove the entry, return 0 to keep it") or `false` to keep it. The
    /// destructor hook (if set) is applied to each removed value before it is
    /// dropped.
    ///
    /// `criterium` is [`FnMut`] so it may carry and update state across the
    /// scan (curl's DNS-cache pruner, for example, tracks the oldest surviving
    /// entry). To remove every entry, pass `|_| true`.
    pub fn curl_hash_clean_with_criterium<F>(&mut self, mut criterium: F)
    where
        F: FnMut(&V) -> bool,
    {
        let dtor = self.dtor;
        self.map.retain(|_key, value| {
            if criterium(value) {
                if let Some(d) = dtor {
                    d(value);
                }
                false // remove
            } else {
                true // keep
            }
        });
    }

    /// Destroys the hash, removing and dropping every entry — the Rust analogue
    /// of `Curl_hash_destroy`.
    ///
    /// Consumes `self`. The destructor hook (if set) is applied to every value
    /// (via [`curl_hash_clean`](CurlHash::curl_hash_clean)) before the hash is
    /// dropped, matching curl, where `Curl_hash_destroy` cleans every element
    /// before releasing the table.
    pub fn curl_hash_destroy(mut self) {
        self.curl_hash_clean();
        // `self` (now empty) is dropped at end of scope.
    }
}

// ---------------------------------------------------------------------------
// Iteration
// ---------------------------------------------------------------------------

impl<V> CurlHash<V> {
    /// Returns an iterator over `(key, &value)` pairs in unspecified order.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &V)> + '_ {
        self.map.iter().map(|(k, v)| (k.as_slice(), v))
    }

    /// Returns an iterator over `(key, &mut value)` pairs in unspecified order.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&[u8], &mut V)> + '_ {
        self.map.iter_mut().map(|(k, v)| (k.as_slice(), v))
    }

    /// Returns an iterator over the keys (byte slices) in unspecified order.
    pub fn keys(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.map.keys().map(Vec::as_slice)
    }

    /// Returns an iterator over the stored values in unspecified order.
    pub fn values(&self) -> impl Iterator<Item = &V> + '_ {
        self.map.values()
    }

    /// Returns a mutable iterator over the stored values in unspecified order.
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut V> + '_ {
        self.map.values_mut()
    }

    /// Begins an iteration — the Rust analogue of `Curl_hash_start_iterate`.
    ///
    /// Returns a [`CurlHashIterator`] whose
    /// [`curl_hash_next_element`](CurlHashIterator::curl_hash_next_element)
    /// method mirrors `Curl_hash_next_element`. The returned iterator also
    /// implements [`Iterator`], so it can be used directly in a `for` loop.
    #[must_use]
    pub fn curl_hash_start_iterate(&self) -> CurlHashIterator<'_, V> {
        CurlHashIterator {
            inner: self.map.iter(),
        }
    }
}

/// An element yielded while iterating a [`CurlHash`] — the Rust analogue of
/// `struct Curl_hash_element` as observed by iterators.
///
/// Exposes the entry's byte `key` (curl's `key` + `key_len`) and a shared
/// reference to its `value` (curl's `ptr`).
pub struct CurlHashElement<'a, V> {
    /// The entry key as a byte slice.
    pub key: &'a [u8],
    /// A shared reference to the entry's value.
    pub value: &'a V,
}

/// An iterator over the entries of a [`CurlHash`] — the Rust analogue of
/// `struct Curl_hash_iterator`.
///
/// Created by [`curl_hash_start_iterate`](CurlHash::curl_hash_start_iterate).
/// Implements [`Iterator`], and additionally exposes the curl-named
/// [`curl_hash_next_element`](CurlHashIterator::curl_hash_next_element).
pub struct CurlHashIterator<'a, V> {
    inner: std::collections::hash_map::Iter<'a, Vec<u8>, V>,
}

impl<'a, V> CurlHashIterator<'a, V> {
    /// Returns the next element, or `None` at the end — the Rust analogue of
    /// `Curl_hash_next_element`. Equivalent to [`Iterator::next`].
    pub fn curl_hash_next_element(&mut self) -> Option<CurlHashElement<'a, V>> {
        self.next()
    }
}

impl<'a, V> Iterator for CurlHashIterator<'a, V> {
    type Item = CurlHashElement<'a, V>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(k, v)| CurlHashElement {
            key: k.as_slice(),
            value: v,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<'a, V> ExactSizeIterator for CurlHashIterator<'a, V> {}

impl<V> IntoIterator for CurlHash<V> {
    type Item = (Vec<u8>, V);
    type IntoIter = std::collections::hash_map::IntoIter<Vec<u8>, V>;

    /// Consumes the hash, yielding owned `(key, value)` pairs.
    ///
    /// This transfers ownership of the values to the caller; it is *not* a
    /// "removal with cleanup", so the destructor hook is intentionally **not**
    /// invoked (the caller now owns each value and is responsible for it).
    fn into_iter(mut self) -> Self::IntoIter {
        // `std::mem::take` swaps in an empty map, letting us move the populated
        // map out by value even though the borrow checker would otherwise
        // object. (`self` is then dropped with an empty map.)
        std::mem::take(&mut self.map).into_iter()
    }
}

impl<'a, V> IntoIterator for &'a CurlHash<V> {
    type Item = (&'a [u8], &'a V);
    type IntoIter = std::iter::Map<
        std::collections::hash_map::Iter<'a, Vec<u8>, V>,
        fn((&'a Vec<u8>, &'a V)) -> (&'a [u8], &'a V),
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.map.iter().map(|(k, v)| (k.as_slice(), v))
    }
}

// ---------------------------------------------------------------------------
// Trait impls
// ---------------------------------------------------------------------------

impl<V> Default for CurlHash<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> Extend<(Vec<u8>, V)> for CurlHash<V> {
    fn extend<T: IntoIterator<Item = (Vec<u8>, V)>>(&mut self, iter: T) {
        for (key, value) in iter {
            self.curl_hash_add(&key, value);
        }
    }
}

impl<V> FromIterator<(Vec<u8>, V)> for CurlHash<V> {
    fn from_iter<T: IntoIterator<Item = (Vec<u8>, V)>>(iter: T) -> Self {
        let mut hash = CurlHash::new();
        hash.extend(iter);
        hash
    }
}

impl<V: fmt::Debug> fmt::Debug for CurlHash<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Render byte keys as lossy UTF-8 for readability while keeping the raw
        // value debug output.
        f.debug_map()
            .entries(
                self.map
                    .iter()
                    .map(|(k, v)| (String::from_utf8_lossy(k), v)),
            )
            .finish()
    }
}

impl<V: fmt::Debug> CurlHash<V> {
    /// Dumps the hash contents to stderr — the Rust analogue of
    /// `Curl_hash_print` (a debugging aid; the C version is compiled out by
    /// default behind `#if 0`).
    ///
    /// Keys are rendered as lossy UTF-8. Available when `V: Debug`.
    pub fn curl_hash_print(&self) {
        eprintln!("=Hash dump= ({} entries)", self.map.len());
        for (key, value) in &self.map {
            eprintln!(" [key={}, value={:?}]", String::from_utf8_lossy(key), value);
        }
    }
}

// ---------------------------------------------------------------------------
// Free functions — curl key helpers (provided for API parity; NOT used
// internally, since `HashMap` owns hashing and key comparison).
// ---------------------------------------------------------------------------

/// Computes curl's string hash for `key` over `slots_num` buckets — the Rust
/// analogue of `Curl_hash_str`.
///
/// This reproduces curl's DJB2-xor variant (`h = h*33 ^ byte`, seeded at
/// `5381`) using wrapping arithmetic to mirror C `size_t` modular overflow, and
/// reduces the result modulo `slots_num`.
///
/// It is provided only for parity/compatibility — [`CurlHash`] uses the
/// standard library's hasher internally and never calls this. If `slots_num`
/// is `0` the result is `0` (curl requires a non-zero slot count; this guard
/// simply avoids a divide-by-zero panic).
#[must_use]
pub fn curl_hash_str(key: &[u8], slots_num: usize) -> usize {
    let mut h: usize = 5381;
    for &byte in key {
        h = h.wrapping_add(h << 5); // h += h * 32  =>  h *= 33
        h ^= byte as usize;
    }
    if slots_num == 0 {
        0
    } else {
        h % slots_num
    }
}

/// Compares two byte keys for equality — the Rust analogue of
/// `curlx_str_key_compare`.
///
/// Returns `true` if the keys have the same length and identical bytes. curl
/// returns `1`/`0`; Rust returns `bool`. Provided for parity; [`CurlHash`] uses
/// `Eq` on the byte key internally.
#[must_use]
pub fn curlx_str_key_compare(k1: &[u8], k2: &[u8]) -> bool {
    k1 == k2
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn add_pick_count_round_trip() {
        let mut h: CurlHash<i32> = CurlHash::new();
        assert!(h.is_empty());
        assert_eq!(h.curl_hash_count(), 0);

        assert_eq!(h.curl_hash_add(b"one", 1).copied(), Some(1));
        assert_eq!(h.curl_hash_add(b"two", 2).copied(), Some(2));
        assert_eq!(h.curl_hash_add(b"three", 3).copied(), Some(3));

        assert_eq!(h.curl_hash_count(), 3);
        assert_eq!(h.len(), 3);
        assert!(!h.is_empty());

        assert_eq!(h.curl_hash_pick(b"one"), Some(&1));
        assert_eq!(h.curl_hash_pick(b"two"), Some(&2));
        assert_eq!(h.curl_hash_pick(b"three"), Some(&3));
        assert_eq!(h.curl_hash_pick(b"missing"), None);

        assert!(h.contains_key(b"one"));
        assert!(!h.contains_key(b"missing"));
        // `get` is an alias for `curl_hash_pick`.
        assert_eq!(h.get(b"two"), Some(&2));
    }

    #[test]
    fn add_returns_mutable_reference() {
        let mut h: CurlHash<i32> = CurlHash::new();
        {
            let r = h.curl_hash_add(b"k", 10).expect("always Some in Rust");
            *r += 5;
        }
        assert_eq!(h.curl_hash_pick(b"k"), Some(&15));

        if let Some(r) = h.get_mut(b"k") {
            *r = 99;
        }
        assert_eq!(h.curl_hash_pick(b"k"), Some(&99));
    }

    #[test]
    fn add_replaces_existing_key() {
        // curl: adding an existing key replaces (overwrites) the value and does
        // not grow the table.
        let mut h: CurlHash<String> = CurlHash::new();
        h.curl_hash_add(b"key", "first".to_string());
        assert_eq!(h.curl_hash_count(), 1);

        h.curl_hash_add(b"key", "second".to_string());
        assert_eq!(h.curl_hash_count(), 1, "replace must not grow the hash");
        assert_eq!(h.curl_hash_pick(b"key"), Some(&"second".to_string()));
    }

    #[test]
    fn delete_round_trip() {
        let mut h: CurlHash<i32> = CurlHash::new();
        h.curl_hash_add(b"a", 1);
        h.curl_hash_add(b"b", 2);
        assert_eq!(h.curl_hash_count(), 2);

        // Removing a present key returns true and shrinks the hash.
        assert!(h.curl_hash_delete(b"a"));
        assert_eq!(h.curl_hash_count(), 1);
        assert_eq!(h.curl_hash_pick(b"a"), None);

        // Removing an absent key returns false and leaves the hash unchanged.
        assert!(!h.curl_hash_delete(b"a"));
        assert!(!h.curl_hash_delete(b"missing"));
        assert_eq!(h.curl_hash_count(), 1);
    }

    #[test]
    fn clean_empties_the_hash() {
        let mut h: CurlHash<i32> = CurlHash::new();
        for i in 0..16 {
            h.curl_hash_add(format!("k{i}").as_bytes(), i);
        }
        assert_eq!(h.curl_hash_count(), 16);

        h.curl_hash_clean();
        assert_eq!(h.curl_hash_count(), 0);
        assert!(h.is_empty());

        // Idiomatic alias behaves identically.
        h.curl_hash_add(b"x", 1);
        h.clear();
        assert!(h.is_empty());
    }

    #[test]
    fn clean_with_criterium_prunes_only_matching() {
        // Remove only the even values; keep the odd ones (mirrors the DNS-cache
        // "remove if stale" prune).
        let mut h: CurlHash<i32> = CurlHash::new();
        for i in 0..10 {
            h.curl_hash_add(format!("k{i}").as_bytes(), i);
        }
        assert_eq!(h.curl_hash_count(), 10);

        h.curl_hash_clean_with_criterium(|v| v % 2 == 0); // true => remove

        assert_eq!(h.curl_hash_count(), 5);
        for i in 0..10 {
            let present = h.curl_hash_pick(format!("k{i}").as_bytes()).is_some();
            assert_eq!(present, i % 2 == 1, "only odd values should remain");
        }
    }

    #[test]
    fn clean_with_criterium_can_track_state() {
        // The predicate is FnMut, so it may accumulate state across the scan
        // (curl's pruner records the oldest surviving entry this way).
        let mut h: CurlHash<i32> = CurlHash::new();
        for i in 0..6 {
            h.curl_hash_add(format!("k{i}").as_bytes(), i);
        }

        let mut max_kept = i32::MIN;
        h.curl_hash_clean_with_criterium(|v| {
            if *v >= 3 {
                true // remove values >= 3
            } else {
                max_kept = max_kept.max(*v);
                false
            }
        });

        assert_eq!(h.curl_hash_count(), 3);
        assert_eq!(max_kept, 2);
    }

    #[test]
    fn clean_with_criterium_remove_all() {
        let mut h: CurlHash<i32> = CurlHash::new();
        h.curl_hash_add(b"a", 1);
        h.curl_hash_add(b"b", 2);
        h.curl_hash_clean_with_criterium(|_| true);
        assert!(h.is_empty());
    }

    // A module-local counter used by the destructor-hook tests below. Because
    // `counting_dtor` is a plain `fn` pointer stored inside the hash, it cannot
    // capture a per-test local; all hook-counting tests must therefore share
    // this single global counter. Several tests each reset it to zero and then
    // assert exact invocation counts, so they MUST NOT run concurrently with one
    // another — otherwise one test's `store(0)`/`fetch_add` races another's
    // assertions. `DTOR_TEST_LOCK` serializes exactly those tests. The lock is
    // poison-tolerant (`unwrap_or_else(PoisonError::into_inner)`) so that a
    // genuine assertion failure in one test is reported as that test's own
    // failure instead of cascading into the others as spurious poison panics.
    static DTOR_CALLS: AtomicUsize = AtomicUsize::new(0);
    static DTOR_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn counting_dtor(_v: &mut i32) {
        DTOR_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn dtor_hook_invoked_on_removal_paths() {
        // Serialize with the other DTOR_CALLS-sharing tests; held for the body.
        let _guard = DTOR_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        DTOR_CALLS.store(0, Ordering::SeqCst);

        let mut h: CurlHash<i32> = CurlHash::with_dtor(counting_dtor);
        h.curl_hash_add(b"a", 1);
        h.curl_hash_add(b"b", 2);
        h.curl_hash_add(b"c", 3);
        h.curl_hash_add(b"d", 4);

        // delete -> one hook call
        assert!(h.curl_hash_delete(b"a"));
        assert_eq!(DTOR_CALLS.load(Ordering::SeqCst), 1);

        // replacing an existing key -> hook runs on the displaced old value
        h.curl_hash_add(b"b", 20);
        assert_eq!(DTOR_CALLS.load(Ordering::SeqCst), 2);
        assert_eq!(h.curl_hash_pick(b"b"), Some(&20));

        // clean_with_criterium -> hook runs per removed value (remove "b"=20)
        h.curl_hash_clean_with_criterium(|v| *v == 20);
        assert_eq!(DTOR_CALLS.load(Ordering::SeqCst), 3);

        // clean -> hook runs on each remaining value (c, d)
        h.curl_hash_clean();
        assert_eq!(DTOR_CALLS.load(Ordering::SeqCst), 5);

        // No entries left -> destroy invokes the hook zero more times.
        h.curl_hash_destroy();
        assert_eq!(DTOR_CALLS.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn destroy_runs_hook_on_remaining_entries() {
        // Serialize with the other DTOR_CALLS-sharing tests; held for the body.
        let _guard = DTOR_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        DTOR_CALLS.store(0, Ordering::SeqCst);

        let mut h: CurlHash<i32> = CurlHash::curl_hash_init(Some(counting_dtor));
        h.curl_hash_add(b"x", 1);
        h.curl_hash_add(b"y", 2);
        h.curl_hash_destroy(); // cleans both -> two hook calls
        assert_eq!(DTOR_CALLS.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn add2_installs_and_uses_dtor() {
        // Serialize with the other DTOR_CALLS-sharing tests; held for the body.
        let _guard = DTOR_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        DTOR_CALLS.store(0, Ordering::SeqCst);

        // Start with no hook; add2 installs one.
        let mut h: CurlHash<i32> = CurlHash::new();
        h.curl_hash_add2(b"k", 1, Some(counting_dtor));
        assert_eq!(h.curl_hash_pick(b"k"), Some(&1));

        // The installed hook fires on subsequent removal.
        assert!(h.curl_hash_delete(b"k"));
        assert_eq!(DTOR_CALLS.load(Ordering::SeqCst), 1);

        // add2 with None leaves the existing hook in place (parity with
        // Curl_hash_add == Curl_hash_add2(..., NULL)).
        h.curl_hash_add2(b"k2", 2, None);
        assert!(h.curl_hash_delete(b"k2"));
        assert_eq!(DTOR_CALLS.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn no_dtor_relies_on_value_drop() {
        // With no hook installed, removal must still work and simply rely on
        // the value's own Drop. We assert behavior, not hook calls.
        let mut h: CurlHash<String> = CurlHash::new();
        h.curl_hash_add(b"k", "value".to_string());
        assert!(h.curl_hash_delete(b"k"));
        assert!(h.is_empty());
    }

    #[test]
    fn iteration_covers_all_entries() {
        let mut h: CurlHash<i32> = CurlHash::new();
        let expected: HashSet<(Vec<u8>, i32)> =
            (0..8).map(|i| (format!("k{i}").into_bytes(), i)).collect();
        for (k, v) in &expected {
            h.curl_hash_add(k, *v);
        }

        // Idiomatic `iter`.
        let via_iter: HashSet<(Vec<u8>, i32)> = h.iter().map(|(k, v)| (k.to_vec(), *v)).collect();
        assert_eq!(via_iter, expected);

        // curl-named iterator wrapper.
        let mut via_curl: HashSet<(Vec<u8>, i32)> = HashSet::new();
        let mut it = h.curl_hash_start_iterate();
        while let Some(elem) = it.curl_hash_next_element() {
            via_curl.insert((elem.key.to_vec(), *elem.value));
        }
        assert_eq!(via_curl, expected);

        // The curl iterator is also a std Iterator.
        let via_for: HashSet<(Vec<u8>, i32)> = h
            .curl_hash_start_iterate()
            .map(|e| (e.key.to_vec(), *e.value))
            .collect();
        assert_eq!(via_for, expected);

        // keys / values cover the same data.
        let keys: HashSet<Vec<u8>> = h.keys().map(<[u8]>::to_vec).collect();
        assert_eq!(keys, expected.iter().map(|(k, _)| k.clone()).collect());
        let values: HashSet<i32> = h.values().copied().collect();
        assert_eq!(values, expected.iter().map(|(_, v)| *v).collect());
    }

    #[test]
    fn iter_mut_and_values_mut_allow_mutation() {
        let mut h: CurlHash<i32> = CurlHash::new();
        h.curl_hash_add(b"a", 1);
        h.curl_hash_add(b"b", 2);

        for (_k, v) in h.iter_mut() {
            *v *= 10;
        }
        let mut got: Vec<i32> = h.values().copied().collect();
        got.sort_unstable();
        assert_eq!(got, vec![10, 20]);

        for v in h.values_mut() {
            *v += 1;
        }
        let mut got: Vec<i32> = h.values().copied().collect();
        got.sort_unstable();
        assert_eq!(got, vec![11, 21]);
    }

    #[test]
    fn into_iter_yields_owned_entries() {
        let mut h: CurlHash<i32> = CurlHash::new();
        h.curl_hash_add(b"a", 1);
        h.curl_hash_add(b"b", 2);

        let collected: HashSet<(Vec<u8>, i32)> = h.into_iter().collect();
        let expected: HashSet<(Vec<u8>, i32)> = [(b"a".to_vec(), 1), (b"b".to_vec(), 2)]
            .into_iter()
            .collect();
        assert_eq!(collected, expected);
    }

    #[test]
    fn ref_into_iter_borrows_entries() {
        let mut h: CurlHash<i32> = CurlHash::new();
        h.curl_hash_add(b"a", 1);
        h.curl_hash_add(b"b", 2);

        let mut sum = 0;
        for (_k, v) in &h {
            sum += *v;
        }
        assert_eq!(sum, 3);
        // `h` is still usable after borrowing iteration.
        assert_eq!(h.curl_hash_count(), 2);
    }

    #[test]
    fn from_iter_and_extend() {
        let mut h: CurlHash<i32> = [(b"a".to_vec(), 1), (b"b".to_vec(), 2)]
            .into_iter()
            .collect();
        assert_eq!(h.curl_hash_count(), 2);

        h.extend([(b"c".to_vec(), 3)]);
        assert_eq!(h.curl_hash_count(), 3);
        assert_eq!(h.curl_hash_pick(b"c"), Some(&3));
    }

    #[test]
    fn default_constructs_empty() {
        let h: CurlHash<i32> = CurlHash::default();
        assert!(h.is_empty());
    }

    #[test]
    fn binary_non_utf8_keys() {
        // Keys are arbitrary byte buffers, not necessarily valid UTF-8.
        let mut h: CurlHash<u8> = CurlHash::new();
        let key = [0xFF_u8, 0x00, 0xFE, 0x80];
        h.curl_hash_add(&key, 7);
        assert_eq!(h.curl_hash_pick(&key), Some(&7));
        assert!(h.curl_hash_delete(&key));
    }

    #[test]
    fn capacity_constructor_behaves_like_new() {
        let mut h: CurlHash<i32> = CurlHash::with_capacity(64);
        assert!(h.is_empty());
        h.curl_hash_add(b"k", 1);
        assert_eq!(h.curl_hash_pick(b"k"), Some(&1));
    }

    #[test]
    fn curl_hash_str_matches_c_algorithm() {
        // Reference values computed from curl's djb2-xor (h=5381; h+=h<<5; h^=b)
        // reduced modulo slots. Verify determinism and range.
        let slots = 256;
        let a = curl_hash_str(b"example.com", slots);
        let b = curl_hash_str(b"example.com", slots);
        assert_eq!(a, b, "hash must be deterministic");
        assert!(a < slots, "hash must be reduced into [0, slots)");

        // Different keys generally land in different buckets here.
        assert_ne!(
            curl_hash_str(b"example.com", slots),
            curl_hash_str(b"example.org", slots)
        );

        // Explicit known value: empty key seeds 5381 -> 5381 % 256.
        assert_eq!(curl_hash_str(b"", slots), 5381 % slots);

        // Single byte 'A' (0x41): h = 5381 + (5381<<5) = 5381*33 = 177573;
        // 177573 ^ 0x41 = 177636; 177636 % 256 == 228.
        assert_eq!(curl_hash_str(b"A", 256), 228);

        // Guard: zero slots must not panic.
        assert_eq!(curl_hash_str(b"anything", 0), 0);
    }

    #[test]
    fn curlx_str_key_compare_is_byte_equality() {
        assert!(curlx_str_key_compare(b"abc", b"abc"));
        assert!(!curlx_str_key_compare(b"abc", b"abd"));
        assert!(!curlx_str_key_compare(b"abc", b"ab")); // length differs
        assert!(curlx_str_key_compare(b"", b""));
        assert!(curlx_str_key_compare(&[0u8, 1, 2], &[0u8, 1, 2]));
    }

    #[test]
    fn debug_format_renders_entries() {
        let mut h: CurlHash<i32> = CurlHash::new();
        h.curl_hash_add(b"k", 1);
        let rendered = format!("{h:?}");
        assert!(rendered.contains('k'));
        assert!(rendered.contains('1'));
    }
}
