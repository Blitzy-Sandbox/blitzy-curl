//! Hash table utility module — idiomatic Rust replacement for `lib/hash.c`.
//!
//! The original C implementation uses a DJB2 hash function with bucket chains
//! (linked lists), lazy table allocation, sentinel debug assertions
//! (`CURL_HI_VALID`), explicit destructor callbacks, and a manual iterator
//! protocol (`Curl_hash_start_iterate` / `Curl_hash_next_element`).
//!
//! In Rust, all of that machinery is replaced by a thin wrapper around
//! [`std::collections::HashMap`] which provides:
//!
//! - **SipHash** (DoS-resistant) instead of DJB2 — superior for general use.
//! - **Lazy allocation** by default — `HashMap::new()` allocates nothing until
//!   the first insertion, matching the C lazy-init behaviour.
//! - **Ownership semantics** replacing C destructor callbacks — when a value is
//!   removed or overwritten the Rust `Drop` trait runs automatically.
//! - **Standard iterators** (`iter`, `iter_mut`, `into_iter`, `keys`, `values`,
//!   `drain`) replacing the C `Curl_hash_start_iterate`/`Curl_hash_next_element`
//!   manual iteration protocol.
//! - **Type-safe hashing** via the `Hash` trait bound instead of a C function
//!   pointer (`hash_function`).
//!
//! # Exported types
//!
//! | Rust type | Replaces C type / function | Purpose |
//! |-----------|---------------------------|---------|
//! | [`CurlHash<K, V>`] | `struct Curl_hash` | Generic hash map wrapper |
//! | [`CurlStringHash<V>`] | `Curl_hash` with `Curl_hash_str` | String-keyed variant |
//! | [`CurlIntHash<V>`] | `uint_hash` patterns | Integer-keyed variant |
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks. All operations delegate to
//! the safe `HashMap` API.

use std::collections::hash_map;
use std::collections::HashMap;
use std::hash::Hash;

// ---------------------------------------------------------------------------
// CurlHash<K, V> — generic hash map wrapper
// ---------------------------------------------------------------------------

/// A generic hash map replacing the C `struct Curl_hash`.
///
/// `CurlHash` wraps [`HashMap<K, V>`] and exposes an API surface that maps
/// one-to-one with the C curl hash functions:
///
/// | Rust method | C function |
/// |-------------|------------|
/// | [`new`](Self::new) | `Curl_hash_init` (with default slots) |
/// | [`with_capacity`](Self::with_capacity) | `Curl_hash_init` (with explicit slots hint) |
/// | [`insert`](Self::insert) | `Curl_hash_add` / `Curl_hash_add2` |
/// | [`get`](Self::get) | `Curl_hash_pick` |
/// | [`remove`](Self::remove) | `Curl_hash_delete` |
/// | [`clear`](Self::clear) | `Curl_hash_clean` / `Curl_hash_destroy` |
/// | [`len`](Self::len) | `Curl_hash_count` |
/// | [`iter`](Self::iter) | `Curl_hash_start_iterate` + `Curl_hash_next_element` |
/// | [`drain`](Self::drain) | `Curl_hash_clean_with_criterium` (take-all variant) |
///
/// # Type parameters
///
/// - `K` — Key type. Must implement [`Eq`] + [`Hash`].
/// - `V` — Value type. Dropped automatically when entries are removed or
///   overwritten, replacing C destructor callbacks (`Curl_hash_dtor`).
#[derive(Debug, Clone)]
pub struct CurlHash<K: Eq + Hash, V> {
    /// Inner standard library hash map providing the actual storage.
    inner: HashMap<K, V>,
}

// --- Construction -----------------------------------------------------------

impl<K: Eq + Hash, V> CurlHash<K, V> {
    /// Creates an empty `CurlHash` with no pre-allocated capacity.
    ///
    /// Matches `Curl_hash_init` — the underlying `HashMap` performs lazy
    /// allocation on the first insertion, identical to the C implementation
    /// which defers `calloc` of the bucket table until the first `Curl_hash_add`.
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::util::hash::CurlHash;
    /// let map: CurlHash<String, i32> = CurlHash::new();
    /// assert!(map.is_empty());
    /// ```
    #[inline]
    pub fn new() -> Self {
        CurlHash {
            inner: HashMap::new(),
        }
    }

    /// Creates an empty `CurlHash` pre-allocated for at least `capacity`
    /// entries.
    ///
    /// This mirrors the `slots` parameter of `Curl_hash_init` — the C code
    /// used it as a fixed bucket count, while Rust's `HashMap` uses it as a
    /// capacity hint and will rehash dynamically.
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::util::hash::CurlHash;
    /// let map: CurlHash<String, i32> = CurlHash::with_capacity(64);
    /// assert!(map.is_empty());
    /// ```
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        CurlHash {
            inner: HashMap::with_capacity(capacity),
        }
    }
}

// --- Insertion / Update -----------------------------------------------------

impl<K: Eq + Hash, V> CurlHash<K, V> {
    /// Inserts a key-value pair, returning the previous value for that key if
    /// one existed.
    ///
    /// Matches `Curl_hash_add` / `Curl_hash_add2`:
    /// - If the key is **new**, the entry is created and `None` is returned.
    /// - If the key **already exists**, the old value is replaced and returned
    ///   as `Some(old_value)`. In C this triggered the destructor callback on
    ///   the old pointer; in Rust the returned `Option<V>` is dropped by the
    ///   caller (or used).
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::util::hash::CurlHash;
    /// let mut map = CurlHash::new();
    /// assert_eq!(map.insert("key".to_string(), 1), None);
    /// assert_eq!(map.insert("key".to_string(), 2), Some(1));
    /// ```
    #[inline]
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.inner.insert(key, value)
    }

    /// Returns a mutable reference to the value for `key`, inserting a new
    /// value computed by `f` if the key is not present.
    ///
    /// This is a Rust-idiomatic convenience that has no direct C equivalent but
    /// maps to the common curl pattern:
    ///
    /// ```c
    /// ptr = Curl_hash_pick(h, key, key_len);
    /// if(!ptr) {
    ///     ptr = create_new_value();
    ///     Curl_hash_add(h, key, key_len, ptr);
    /// }
    /// ```
    ///
    /// Uses [`HashMap::entry`] internally for an efficient single lookup.
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::util::hash::CurlHash;
    /// let mut map = CurlHash::new();
    /// let val = map.get_or_insert_with("host".to_string(), || vec![]);
    /// val.push(42);
    /// assert_eq!(map.get(&"host".to_string()), Some(&vec![42]));
    /// ```
    #[inline]
    pub fn get_or_insert_with<F: FnOnce() -> V>(&mut self, key: K, f: F) -> &mut V {
        self.inner.entry(key).or_insert_with(f)
    }
}

// --- Lookup -----------------------------------------------------------------

impl<K: Eq + Hash, V> CurlHash<K, V> {
    /// Returns an immutable reference to the value associated with `key`, or
    /// `None` if the key is not present.
    ///
    /// Matches `Curl_hash_pick`.
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::util::hash::CurlHash;
    /// let mut map = CurlHash::new();
    /// map.insert(1u64, "one");
    /// assert_eq!(map.get(&1), Some(&"one"));
    /// assert_eq!(map.get(&2), None);
    /// ```
    #[inline]
    pub fn get(&self, key: &K) -> Option<&V> {
        self.inner.get(key)
    }

    /// Returns a mutable reference to the value associated with `key`, or
    /// `None` if the key is not present.
    #[inline]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.inner.get_mut(key)
    }

    /// Returns `true` if the hash map contains a value for the specified key.
    #[inline]
    pub fn contains_key(&self, key: &K) -> bool {
        self.inner.contains_key(key)
    }
}

// --- Removal ----------------------------------------------------------------

impl<K: Eq + Hash, V> CurlHash<K, V> {
    /// Removes the entry for `key` and returns its value, or `None` if the key
    /// was not present.
    ///
    /// Matches `Curl_hash_delete`. The C function returned `0` on success and
    /// `1` on not-found; in Rust the result is communicated via `Option<V>`.
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::util::hash::CurlHash;
    /// let mut map = CurlHash::new();
    /// map.insert("a".to_string(), 10);
    /// assert_eq!(map.remove(&"a".to_string()), Some(10));
    /// assert_eq!(map.remove(&"a".to_string()), None);
    /// ```
    #[inline]
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.inner.remove(key)
    }

    /// Removes **all** entries from the hash map.
    ///
    /// Matches both `Curl_hash_clean` (remove entries, keep structure) and
    /// `Curl_hash_destroy` (remove entries and free table). In Rust the
    /// allocated capacity is retained so subsequent inserts avoid reallocating.
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::util::hash::CurlHash;
    /// let mut map = CurlHash::new();
    /// map.insert(1u64, "a");
    /// map.insert(2u64, "b");
    /// map.clear();
    /// assert!(map.is_empty());
    /// ```
    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

// --- Iteration & Queries ----------------------------------------------------

impl<K: Eq + Hash, V> CurlHash<K, V> {
    /// Returns an iterator over immutable `(&K, &V)` pairs.
    ///
    /// Replaces the C `Curl_hash_start_iterate` / `Curl_hash_next_element`
    /// manual iteration protocol entirely.
    #[inline]
    pub fn iter(&self) -> hash_map::Iter<'_, K, V> {
        self.inner.iter()
    }

    /// Returns an iterator over mutable `(&K, &mut V)` pairs.
    #[inline]
    pub fn iter_mut(&mut self) -> hash_map::IterMut<'_, K, V> {
        self.inner.iter_mut()
    }

    /// Returns an iterator over the keys of the hash map.
    #[inline]
    pub fn keys(&self) -> hash_map::Keys<'_, K, V> {
        self.inner.keys()
    }

    /// Returns an iterator over the values of the hash map.
    #[inline]
    pub fn values(&self) -> hash_map::Values<'_, K, V> {
        self.inner.values()
    }

    /// Returns the number of entries in the hash map.
    ///
    /// Matches `Curl_hash_count`.
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the hash map contains no entries.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Removes and returns all entries as an iterator of `(K, V)` pairs.
    ///
    /// After `drain()` the hash map is empty. This is the Rust equivalent of
    /// the C `Curl_hash_clean_with_criterium` take-all pattern (where the
    /// comparator always returns true).
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::util::hash::CurlHash;
    /// let mut map = CurlHash::new();
    /// map.insert(1u64, "a");
    /// map.insert(2u64, "b");
    /// let drained: Vec<_> = map.drain().collect();
    /// assert!(map.is_empty());
    /// assert_eq!(drained.len(), 2);
    /// ```
    #[inline]
    pub fn drain(&mut self) -> hash_map::Drain<'_, K, V> {
        self.inner.drain()
    }

    /// Retains only the entries for which the predicate returns `true`.
    ///
    /// This is the Rust equivalent of `Curl_hash_clean_with_criterium` — the C
    /// function iterates all entries and removes those for which the comparator
    /// callback returns a truthy value. In Rust the sense is inverted: entries
    /// where `f` returns `true` are **kept**.
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::util::hash::CurlHash;
    /// let mut map = CurlHash::new();
    /// map.insert(1u64, 10);
    /// map.insert(2u64, 20);
    /// map.insert(3u64, 30);
    /// map.retain(|_k, v| *v > 15);
    /// assert_eq!(map.len(), 2);
    /// ```
    #[inline]
    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        self.inner.retain(f);
    }
}

// --- Default ----------------------------------------------------------------

impl<K: Eq + Hash, V> Default for CurlHash<K, V> {
    /// Returns an empty `CurlHash`, identical to [`CurlHash::new`].
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// --- IntoIterator -----------------------------------------------------------

impl<K: Eq + Hash, V> IntoIterator for CurlHash<K, V> {
    type Item = (K, V);
    type IntoIter = hash_map::IntoIter<K, V>;

    /// Consumes the `CurlHash` and returns an owning iterator over `(K, V)`
    /// pairs.
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a, K: Eq + Hash, V> IntoIterator for &'a CurlHash<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = hash_map::Iter<'a, K, V>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

impl<'a, K: Eq + Hash, V> IntoIterator for &'a mut CurlHash<K, V> {
    type Item = (&'a K, &'a mut V);
    type IntoIter = hash_map::IterMut<'a, K, V>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter_mut()
    }
}

// --- FromIterator -----------------------------------------------------------

impl<K: Eq + Hash, V> FromIterator<(K, V)> for CurlHash<K, V> {
    /// Creates a `CurlHash` from an iterator of `(K, V)` pairs.
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        CurlHash {
            inner: HashMap::from_iter(iter),
        }
    }
}

// --- Extend -----------------------------------------------------------------

impl<K: Eq + Hash, V> Extend<(K, V)> for CurlHash<K, V> {
    /// Extends the `CurlHash` with the contents of an iterator.
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        self.inner.extend(iter);
    }
}

// --- PartialEq --------------------------------------------------------------

impl<K: Eq + Hash, V: PartialEq> PartialEq for CurlHash<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<K: Eq + Hash, V: Eq> Eq for CurlHash<K, V> {}

// ---------------------------------------------------------------------------
// Specialised type aliases
// ---------------------------------------------------------------------------

/// A string-keyed hash map — the most common hash usage in curl.
///
/// Used by the connection cache (keyed by host string), cookie jar (keyed by
/// domain), DNS cache (keyed by hostname), and header storage.
///
/// Replaces C `Curl_hash` instances initialised with `Curl_hash_str` as the
/// hash function and `curlx_str_key_compare` as the comparator.
pub type CurlStringHash<V> = CurlHash<String, V>;

/// An integer-keyed hash map.
///
/// Replaces the C `uint-hash.c` patterns where entries are keyed by unsigned
/// integer identifiers (socket file descriptors, transfer IDs, etc.).
pub type CurlIntHash<V> = CurlHash<u64, V>;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_is_empty() {
        let map: CurlHash<String, i32> = CurlHash::new();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn test_with_capacity() {
        let map: CurlHash<String, i32> = CurlHash::with_capacity(128);
        assert!(map.is_empty());
    }

    #[test]
    fn test_insert_and_get() {
        let mut map = CurlHash::new();
        assert_eq!(map.insert("hello".to_string(), 42), None);
        assert_eq!(map.get(&"hello".to_string()), Some(&42));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_insert_replaces_value() {
        let mut map = CurlHash::new();
        map.insert("key".to_string(), 1);
        let old = map.insert("key".to_string(), 2);
        assert_eq!(old, Some(1));
        assert_eq!(map.get(&"key".to_string()), Some(&2));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_get_or_insert_with_existing() {
        let mut map = CurlHash::new();
        map.insert("k".to_string(), 10);
        let val = map.get_or_insert_with("k".to_string(), || 99);
        assert_eq!(*val, 10);
    }

    #[test]
    fn test_get_or_insert_with_missing() {
        let mut map: CurlHash<String, i32> = CurlHash::new();
        let val = map.get_or_insert_with("k".to_string(), || 99);
        assert_eq!(*val, 99);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_get_mut() {
        let mut map = CurlHash::new();
        map.insert("a".to_string(), 1);
        if let Some(v) = map.get_mut(&"a".to_string()) {
            *v = 100;
        }
        assert_eq!(map.get(&"a".to_string()), Some(&100));
    }

    #[test]
    fn test_contains_key() {
        let mut map = CurlHash::new();
        map.insert(1u64, "one");
        assert!(map.contains_key(&1));
        assert!(!map.contains_key(&2));
    }

    #[test]
    fn test_remove() {
        let mut map = CurlHash::new();
        map.insert("key".to_string(), 42);
        assert_eq!(map.remove(&"key".to_string()), Some(42));
        assert!(map.is_empty());
        assert_eq!(map.remove(&"key".to_string()), None);
    }

    #[test]
    fn test_clear() {
        let mut map = CurlHash::new();
        map.insert(1u64, "a");
        map.insert(2u64, "b");
        map.insert(3u64, "c");
        assert_eq!(map.len(), 3);
        map.clear();
        assert!(map.is_empty());
    }

    #[test]
    fn test_iter() {
        let mut map = CurlHash::new();
        map.insert("a".to_string(), 1);
        map.insert("b".to_string(), 2);
        let collected: HashMap<&String, &i32> = map.iter().collect();
        assert_eq!(collected.len(), 2);
        assert_eq!(*collected[&"a".to_string()], 1);
        assert_eq!(*collected[&"b".to_string()], 2);
    }

    #[test]
    fn test_iter_mut() {
        let mut map = CurlHash::new();
        map.insert("x".to_string(), 10);
        map.insert("y".to_string(), 20);
        for (_k, v) in map.iter_mut() {
            *v += 1;
        }
        assert_eq!(map.get(&"x".to_string()), Some(&11));
        assert_eq!(map.get(&"y".to_string()), Some(&21));
    }

    #[test]
    fn test_keys_and_values() {
        let mut map = CurlHash::new();
        map.insert(1u64, "one");
        map.insert(2u64, "two");
        let mut keys: Vec<&u64> = map.keys().collect();
        keys.sort();
        assert_eq!(keys, vec![&1, &2]);
        let mut values: Vec<&&str> = map.values().collect();
        values.sort();
        assert_eq!(values, vec![&"one", &"two"]);
    }

    #[test]
    fn test_drain() {
        let mut map = CurlHash::new();
        map.insert(1u64, "a");
        map.insert(2u64, "b");
        let drained: Vec<(u64, &str)> = map.drain().collect();
        assert!(map.is_empty());
        assert_eq!(drained.len(), 2);
    }

    #[test]
    fn test_retain() {
        let mut map = CurlHash::new();
        map.insert(1u64, 10);
        map.insert(2u64, 20);
        map.insert(3u64, 30);
        map.retain(|_k, v| *v >= 20);
        assert_eq!(map.len(), 2);
        assert!(!map.contains_key(&1));
        assert!(map.contains_key(&2));
        assert!(map.contains_key(&3));
    }

    #[test]
    fn test_into_iter() {
        let mut map = CurlHash::new();
        map.insert("a".to_string(), 1);
        map.insert("b".to_string(), 2);
        let mut entries: Vec<(String, i32)> = map.into_iter().collect();
        entries.sort_by_key(|(k, _)| k.clone());
        assert_eq!(entries, vec![("a".to_string(), 1), ("b".to_string(), 2)]);
    }

    #[test]
    fn test_from_iterator() {
        let map: CurlHash<u64, &str> =
            vec![(1u64, "one"), (2, "two"), (3, "three")].into_iter().collect();
        assert_eq!(map.len(), 3);
        assert_eq!(map.get(&2), Some(&"two"));
    }

    #[test]
    fn test_extend() {
        let mut map = CurlHash::new();
        map.insert(1u64, "a");
        map.extend(vec![(2u64, "b"), (3, "c")]);
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn test_default() {
        let map: CurlHash<String, i32> = CurlHash::default();
        assert!(map.is_empty());
    }

    #[test]
    fn test_equality() {
        let mut a = CurlHash::new();
        a.insert(1u64, "x");
        let mut b = CurlHash::new();
        b.insert(1u64, "x");
        assert_eq!(a, b);
    }

    #[test]
    fn test_clone() {
        let mut original = CurlHash::new();
        original.insert("key".to_string(), 42);
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_string_hash_alias() {
        let mut map: CurlStringHash<i32> = CurlStringHash::new();
        map.insert("host.example.com".to_string(), 443);
        assert_eq!(map.get(&"host.example.com".to_string()), Some(&443));
    }

    #[test]
    fn test_int_hash_alias() {
        let mut map: CurlIntHash<String> = CurlIntHash::new();
        map.insert(42u64, "socket_42".to_string());
        assert_eq!(map.get(&42), Some(&"socket_42".to_string()));
    }

    #[test]
    fn test_empty_operations_no_panic() {
        let mut map: CurlHash<String, i32> = CurlHash::new();
        assert_eq!(map.get(&"nope".to_string()), None);
        assert_eq!(map.get_mut(&"nope".to_string()), None);
        assert!(!map.contains_key(&"nope".to_string()));
        assert_eq!(map.remove(&"nope".to_string()), None);
        assert_eq!(map.len(), 0);
        assert!(map.is_empty());
        map.clear(); // should not panic
        assert_eq!(map.iter().count(), 0);
        assert_eq!(map.iter_mut().count(), 0);
        assert_eq!(map.keys().count(), 0);
        assert_eq!(map.values().count(), 0);
        assert_eq!(map.drain().count(), 0);
    }

    #[test]
    fn test_ref_into_iter() {
        let mut map = CurlHash::new();
        map.insert(1u64, "a");
        let mut count = 0;
        for (_k, _v) in &map {
            count += 1;
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn test_mut_ref_into_iter() {
        let mut map = CurlHash::new();
        map.insert(1u64, 10);
        for (_k, v) in &mut map {
            *v += 5;
        }
        assert_eq!(map.get(&1), Some(&15));
    }
}
