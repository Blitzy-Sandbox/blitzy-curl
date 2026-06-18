// Timer / expiry tree for the curl-rs workspace.
//
// SPDX-License-Identifier: curl
//
// This file is a memory-safe Rust reimplementation of curl's splay tree
// (`lib/splay.c` / `lib/splay.h`). The original C sources are
//   Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// and are licensed under the curl license (https://curl.se/docs/copyright.html).
// This Rust port preserves the *observable* behavior and the public API *names*
// of that data structure; it is a behavioral translation, not a line-by-line
// one.

//! Ordered timer / expiry tree — the safe replacement for curl's splay tree
//! (`lib/splay.c` / `lib/splay.h`).
//!
//! # What curl uses this for
//!
//! curl's splay tree is keyed by `struct curltime` and is used by the multi
//! handle as the **timeout / expiry tree**: it answers "which transfer expires
//! next?" and "give me every transfer whose deadline has already passed". On
//! each iteration the multi loop pops the smallest-keyed node that is due
//! (`key <= now`) and re-arms that handle's next timer. The splay tree's
//! defining trick — splaying a recently accessed node to the root for
//! amortised-`O(log n)` access — is purely a performance optimisation; it has
//! **no observable effect** on *which* node is returned, only on how fast the
//! lookup is.
//!
//! # Why this is a `BTreeMap`, not a hand-rolled tree
//!
//! curl's C implementation threads raw `struct Curl_tree` nodes together with
//! `smaller`/`larger` child pointers plus a `samen`/`samep` circular list for
//! duplicate keys. That design is built entirely on raw-pointer manipulation,
//! which the workspace-wide `#![forbid(unsafe_code)]` rule (AAP §0.7.1)
//! prohibits.
//!
//! The only behavior the rest of curl relies on is:
//!
//! 1. **Ordering** — find the node with the smallest key, and the smallest key
//!    that is `<= now`.
//! 2. **Duplicate keys** — several transfers may share the *exact* same expiry
//!    instant; curl keeps them in a per-key list and drains them one at a time.
//!
//! Both fall straight out of [`std::collections::BTreeMap`]:
//!
//! * `BTreeMap<CurlTime, _>` keeps keys in ascending order, so the smallest key
//!   is `keys().next()` and "smallest key `<= now`" is `range(..=now).next()` —
//!   each `O(log n)`, which subsumes the splay tree's amortised guarantee.
//! * The duplicate-key list (`samen`/`samep`) becomes the `Vec<T>` value:
//!   pushes append at the back and pops take the front, giving **FIFO** drain
//!   order — the same order curl's same-key list produces, since
//!   `Curl_splaygetbest` removes the original (oldest) node of a same-key group
//!   first.
//!
//! Ownership plus deterministic [`Drop`] replace curl's manual `malloc`/`free`,
//! and the payload (`void *ptr` in C) is stored *directly* as the generic value
//! `T`, so the C accessors `Curl_splayset` / `Curl_splayget` have nothing left
//! to do — see [the API mapping](#api-mapping).
//!
//! # API mapping
//!
//! | curl C function          | Safe Rust replacement                              |
//! |--------------------------|----------------------------------------------------|
//! | `Curl_splayinsert`       | [`Splay::insert`] / [`Splay::Curl_splayinsert`]    |
//! | `Curl_splaygetbest`      | [`Splay::getbest`] / [`Splay::Curl_splaygetbest`]  |
//! | `Curl_splayremove`       | [`Splay::remove`] / [`Splay::Curl_splayremove`]    |
//! | `Curl_splay` (rebalance) | *subsumed* — a `BTreeMap` is always ordered        |
//! | `Curl_splayset(node, p)` | *subsumed* — the payload `T` is the map value      |
//! | `Curl_splayget(node)`    | *subsumed* — [`Splay::getbest`] returns the `T`    |
//!
//! Two complementary surfaces are exposed, exactly like the sibling
//! [`crate::util::llist`] port: idiomatic Rust names for new code, plus
//! `Curl_`-prefixed wrappers that keep curl's original names to ease porting the
//! multi handle (`lib/multi.c` → `multi.rs`) call sites.
//!
//! # Memory safety
//!
//! This module contains no `unsafe` code and compiles under the module-level
//! and crate-wide `#![forbid(unsafe_code)]` mandated for the core crate
//! (AAP §0.7.1). It also never panics on caller input: every removal is guarded
//! so no index can ever be out of bounds, matching curl's "never trap"
//! contract.

// The full timer-tree surface is authored here even though its only consumer,
// the multi handle (`multi.rs`, a sibling port of `lib/multi.c`), has not yet
// landed in the crate. As in the sibling `util` modules (`timeval.rs`,
// `llist.rs`), `dead_code` is allowed for this foundational container so the
// complete, documented API can exist ahead of its call sites.
#![allow(dead_code)]
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use crate::util::timeval::CurlTime;

/// An ordered timer / expiry tree keyed by [`CurlTime`].
///
/// `Splay<T>` is the memory-safe replacement for curl's `struct Curl_tree`
/// splay tree (`lib/splay.c`). It maps each expiry instant ([`CurlTime`]) to a
/// FIFO list of payloads (`T`) scheduled for that instant. The payload is
/// whatever the caller associates with a timer — in the multi handle that is a
/// per-transfer identifier or handle (curl's `void *ptr`).
///
/// # Why a `Vec<T>` value
///
/// Multiple transfers can legitimately share the *exact* same expiry instant
/// (down to the microsecond). curl models this with a circular `samen`/`samep`
/// list hanging off the keyed node; here it is simply the `Vec<T>` stored at
/// that key. New entries are pushed at the back and drained from the front, so
/// payloads sharing a key come out in **insertion order (FIFO)** — matching
/// curl, whose `Curl_splaygetbest` removes the original (oldest) node of a
/// same-key group first.
///
/// # Invariant
///
/// A key is present in the map **iff** its `Vec<T>` is non-empty. Every method
/// that can empty a bucket (e.g. [`getbest`](Splay::getbest),
/// [`remove`](Splay::remove)) removes the key entry as soon as its list becomes
/// empty. This keeps [`is_empty`](Splay::is_empty) `O(1)` and
/// [`earliest`](Splay::earliest) exact, and means the map never holds an empty
/// bucket.
///
/// # Ordering source
///
/// The chronological ordering comes entirely from [`CurlTime`]'s derived
/// [`Ord`] (which compares `tv_sec` then `tv_usec`); `Splay` adds no comparison
/// logic of its own.
///
/// # Examples
///
/// ```ignore
/// use curl_rs_lib::util::splay::Splay;
/// use curl_rs_lib::util::timeval::CurlTime;
///
/// let mut timers: Splay<u64> = Splay::new();
/// timers.insert(CurlTime::new(3, 0), 30); // transfer 30 expires at t=3s
/// timers.insert(CurlTime::new(1, 0), 10); // transfer 10 expires at t=1s
///
/// // Drain everything due at "now == 5s", smallest deadline first.
/// let now = CurlTime::new(5, 0);
/// assert_eq!(timers.getbest(now), Some(10));
/// assert_eq!(timers.getbest(now), Some(30));
/// assert_eq!(timers.getbest(now), None);
/// ```
#[derive(Debug, Clone)]
pub struct Splay<T> {
    /// Expiry instant → FIFO list of payloads due at that instant.
    ///
    /// Ordered by key ascending (smallest expiry first). Per the type
    /// invariant, no value is ever an empty `Vec`.
    map: BTreeMap<CurlTime, Vec<T>>,
}

impl<T> Splay<T> {
    /// Create a new, empty timer tree.
    ///
    /// This is a `const fn` (so a `Splay` can initialise a `static`/`const`
    /// item), mirroring the C "an empty tree is just a `NULL` root" starting
    /// state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    /// Insert `payload`, scheduled to expire at `key`.
    ///
    /// This is the safe analogue of `Curl_splayinsert`. If one or more payloads
    /// are already scheduled for `key`, `payload` is appended after them, so a
    /// later [`getbest`](Splay::getbest) drains them **FIFO** (oldest first) —
    /// the exact order curl's same-key (`samen`/`samep`) list produces.
    ///
    /// Inserting is idempotent with respect to the key set: a brand-new key
    /// creates its bucket, an existing key extends its bucket.
    pub fn insert(&mut self, key: CurlTime, payload: T) {
        // `or_default()` materialises an empty `Vec` for a new key; `push`
        // appends at the back, establishing FIFO order within the key.
        self.map.entry(key).or_default().push(payload);
    }

    /// Remove and return the single payload with the **smallest key that is
    /// `<= now`**, or [`None`] if no scheduled key is due yet.
    ///
    /// This is the safe analogue of `Curl_splaygetbest` and is the timeout-pop
    /// the multi loop calls repeatedly to drain expired timers. Each call
    /// returns **exactly one** payload (matching curl, which removes one node
    /// per call); callers loop until it yields [`None`]:
    ///
    /// ```ignore
    /// while let Some(payload) = timers.getbest(now) {
    ///     // handle the expired timer for `payload`
    /// }
    /// ```
    ///
    /// # Semantics
    ///
    /// * The boundary is **inclusive**: a key exactly equal to `now` *is*
    ///   returned (it is `<= now`), while any key strictly greater than `now`
    ///   (not yet due) is never returned — identical to curl's `getbest`, which
    ///   returns nothing only when even the smallest key exceeds the probe time.
    /// * Within a group of payloads sharing the due key, the **oldest**
    ///   (first-inserted) one is returned, i.e. FIFO.
    #[must_use = "getbest removes a payload from the tree; dropping the return value loses that timer"]
    pub fn getbest(&mut self, now: CurlTime) -> Option<T> {
        // The earliest key that is actually due: the smallest key `<= now`.
        // `range(..=now)` is the inclusive range `[min ..= now]`, so a deadline
        // equal to `now` is in range while a later (not-yet-due) deadline is
        // skipped. `.next()` yields that smallest in-range key in `O(log n)`.
        let key = *self.map.range(..=now).next()?.0;

        // `key` was just produced by `range`, so the bucket exists; by the type
        // invariant it is non-empty. The guard keeps the method panic-free
        // (curl's "never trap" contract) even if that invariant were violated:
        // it returns without indexing, never reaching `remove(0)` on an empty
        // bucket and never mutating the map while `bucket` is borrowed.
        let bucket = self.map.get_mut(&key)?;
        if bucket.is_empty() {
            return None;
        }

        // Front-pop = FIFO: the oldest payload queued at this instant leaves
        // first, exactly as curl drains the original node of a same-key list
        // first. The group size is tiny (transfers sharing one microsecond), so
        // the `O(group)` shift is negligible.
        let payload = bucket.remove(0);
        // `bucket`'s borrow ends at this last use; the map may then be mutated.
        let became_empty = bucket.is_empty();
        if became_empty {
            // Uphold the invariant: a key never maps to an empty bucket.
            self.map.remove(&key);
        }
        Some(payload)
    }

    /// Remove and return the first payload at `key` for which `predicate`
    /// returns `true`, or [`None`] if `key` is absent or no payload matches.
    ///
    /// This is the safe analogue of `Curl_splayremove`, which deletes one
    /// specific node from the tree. Because several payloads can share a key
    /// (see [`insert`](Splay::insert)), the caller identifies *which* one to
    /// drop via `predicate` (typically an equality check against a transfer
    /// id/handle). If removing the matched payload empties the key's bucket,
    /// the key entry is pruned, upholding the type invariant.
    ///
    /// Only the **first** matching payload (in FIFO order) is removed, mirroring
    /// curl's removal of a single targeted node.
    pub fn remove<F>(&mut self, key: CurlTime, predicate: F) -> Option<T>
    where
        F: FnMut(&T) -> bool,
    {
        // Absent key → nothing to remove.
        let bucket = self.map.get_mut(&key)?;
        // First payload (FIFO) satisfying the predicate, if any. `position`
        // takes the `FnMut` by value and feeds it each `&T`, so the predicate
        // is forwarded directly (no wrapping closure).
        let pos = bucket.iter().position(predicate)?;
        let payload = bucket.remove(pos);
        if bucket.is_empty() {
            // Uphold the invariant: prune the now-empty key.
            self.map.remove(&key);
        }
        Some(payload)
    }

    /// Peek at the smallest key (the **next** expiry instant) without removing
    /// anything, or [`None`] when the tree is empty.
    ///
    /// The multi handle uses the soonest deadline to compute how long it may
    /// block in `poll`/`select` before it must run again. This is the safe,
    /// non-destructive analogue of curl splaying the lowest node to the root and
    /// reading `timetree->key`.
    #[must_use]
    pub fn earliest(&self) -> Option<CurlTime> {
        // Keys iterate in ascending order, so the first is the minimum.
        // `CurlTime: Copy`, so `copied()` is a cheap by-value return.
        self.map.keys().next().copied()
    }

    /// Total number of payloads currently scheduled across **all** keys.
    ///
    /// This counts every timer in the tree (summing the per-key FIFO lists), so
    /// it is the closest analogue of "how many nodes does curl's tree hold".
    /// Contrast with [`count`](Splay::count), which counts *distinct* expiry
    /// instants.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.values().map(|bucket| bucket.len()).sum()
    }

    /// Returns `true` when no payloads are scheduled.
    ///
    /// Equivalent to `self.len() == 0`, but `O(1)`: by the type invariant the
    /// map holds no empty buckets, so "the map is empty" is exactly "no
    /// payloads are scheduled".
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Number of **distinct** expiry instants currently scheduled.
    ///
    /// This is the number of unique keys (buckets), which differs from
    /// [`len`](Splay::len) whenever several payloads share an instant: e.g. two
    /// timers at `t = 5s` contribute `2` to [`len`](Splay::len) but `1` to
    /// `count`.
    #[must_use]
    pub fn count(&self) -> usize {
        self.map.len()
    }
}

impl<T> Default for Splay<T> {
    /// Returns an empty tree, identical to [`Splay::new`].
    ///
    /// Implemented by hand (rather than `#[derive(Default)]`) so that `T` is
    /// **not** required to be [`Default`]: an empty tree holds no `T`, so there
    /// is no reason to constrain the payload type.
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// curl-named API surface
//
// These wrappers keep curl's original function names so that the multi-handle
// port (`lib/multi.c` → `multi.rs`) can translate its call sites with minimal
// churn — the same dual-surface convention used by the sibling `llist.rs`
// (`Curl_llist_append`, `Curl_node_remove`, …). Each is a thin delegation to
// the idiomatic method above; prefer the idiomatic names in new Rust code.
//
// The block is annotated `#[allow(non_snake_case)]` because it intentionally
// reproduces curl's `Curl_*` casing, which the default `non_snake_case` lint
// (denied via the `-D warnings` gate) would otherwise reject.
//
// Note on the C functions with no wrapper here:
//   * `Curl_splay`    — the pure rebalancing primitive. A `BTreeMap` is always
//                       ordered, so there is no separate "splay to root" step;
//                       its effect is subsumed by every ordered lookup.
//   * `Curl_splayset` / `Curl_splayget` — in C these write/read a node's opaque
//                       `void *ptr` payload. Here the payload is the generic
//                       value `T` stored directly in the map, so there is no
//                       distinct node to set/get: `insert` stores the `T` and
//                       `getbest` returns it. (In `lib/multi.c` the call
//                       `Curl_splayget(t)` always immediately follows the
//                       `Curl_splaygetbest` that produced `t`; `getbest`
//                       returning the `T` directly collapses both into one
//                       step.)
// =============================================================================
#[allow(non_snake_case)]
impl<T> Splay<T> {
    /// curl-named alias of [`insert`](Splay::insert).
    ///
    /// Schedules `payload` to expire at `key`, appending after any payloads
    /// already queued for that key (FIFO). Equivalent to C's `Curl_splayinsert`
    /// adding a node (or a same-key subnode) to the tree.
    pub fn Curl_splayinsert(&mut self, key: CurlTime, payload: T) {
        self.insert(key, payload);
    }

    /// curl-named alias of [`getbest`](Splay::getbest).
    ///
    /// Removes and returns the single payload with the smallest key `<= now`,
    /// or [`None`] if none is due. Equivalent to C's `Curl_splaygetbest`
    /// (followed by the `Curl_splayget` that reads the removed node's payload).
    #[must_use = "Curl_splaygetbest removes a payload from the tree; dropping the return value loses that timer"]
    pub fn Curl_splaygetbest(&mut self, now: CurlTime) -> Option<T> {
        self.getbest(now)
    }

    /// curl-named alias of [`remove`](Splay::remove).
    ///
    /// Removes and returns the first payload at `key` matching `predicate`, or
    /// [`None`] if `key` is absent or nothing matches. Equivalent to C's
    /// `Curl_splayremove` deleting one specific node from the tree.
    pub fn Curl_splayremove<F>(&mut self, key: CurlTime, predicate: F) -> Option<T>
    where
        F: FnMut(&T) -> bool,
    {
        self.remove(key, predicate)
    }
}

// =============================================================================
// Unit tests
//
// These exercise the *observable* contract curl's multi handle depends on:
// ascending best-pop order, an inclusive `<= now` boundary, sub-second
// (microsecond) ordering, FIFO draining of duplicate keys, the non-destructive
// `earliest` peek, predicate-based removal with empty-bucket pruning, and the
// `do { … } while(t)` drain loop shape used in `lib/multi.c`.
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::timeval::CurlTime;

    /// Terse helper to build a [`CurlTime`] from seconds + microseconds.
    fn ct(sec: i64, usec: i32) -> CurlTime {
        CurlTime::new(sec, usec)
    }

    #[test]
    fn new_and_default_are_empty() {
        let a: Splay<u32> = Splay::new();
        let b: Splay<u32> = Splay::default();

        assert!(a.is_empty());
        assert!(b.is_empty());
        assert_eq!(a.len(), 0);
        assert_eq!(a.count(), 0);
        assert_eq!(a.earliest(), None);
        assert_eq!(b.earliest(), None);
    }

    #[test]
    fn getbest_on_empty_returns_none() {
        let mut s: Splay<u32> = Splay::new();
        assert_eq!(s.getbest(ct(100, 0)), None);
        // Still empty / unchanged after a miss.
        assert!(s.is_empty());
    }

    #[test]
    fn getbest_returns_ascending_key_order() {
        let mut s = Splay::new();
        // Insert deliberately out of order.
        s.insert(ct(3, 0), "c");
        s.insert(ct(1, 0), "a");
        s.insert(ct(2, 0), "b");

        // `now` large enough that every timer is due.
        let now = ct(10, 0);
        assert_eq!(s.getbest(now), Some("a"));
        assert_eq!(s.getbest(now), Some("b"));
        assert_eq!(s.getbest(now), Some("c"));
        assert_eq!(s.getbest(now), None);
        assert!(s.is_empty());
    }

    #[test]
    fn getbest_excludes_keys_greater_than_now() {
        let mut s = Splay::new();
        s.insert(ct(5, 0), 50);
        s.insert(ct(10, 0), 100);

        // now == 7s: only the 5s timer is due.
        assert_eq!(s.getbest(ct(7, 0)), Some(50));
        // The 10s timer is not due yet, so nothing more comes back.
        assert_eq!(s.getbest(ct(7, 0)), None);
        // The not-yet-due timer is still present.
        assert_eq!(s.len(), 1);
        assert_eq!(s.earliest(), Some(ct(10, 0)));
    }

    #[test]
    fn equal_key_boundary_is_inclusive() {
        let mut s = Splay::new();
        s.insert(ct(4, 500), 1);
        // `now` exactly equals the key → returned, because the bound is `<= now`.
        assert_eq!(s.getbest(ct(4, 500)), Some(1));
        assert!(s.is_empty());
    }

    #[test]
    fn microsecond_ordering_within_same_second() {
        let mut s = Splay::new();
        // Same second, different microseconds, inserted out of order.
        s.insert(ct(1, 900), "late");
        s.insert(ct(1, 100), "early");

        let now = ct(2, 0);
        // tv_usec breaks the tie: 100us sorts before 900us.
        assert_eq!(s.getbest(now), Some("early"));
        assert_eq!(s.getbest(now), Some("late"));
        assert_eq!(s.getbest(now), None);
    }

    #[test]
    fn duplicate_keys_drain_fifo() {
        let mut s = Splay::new();
        let k = ct(5, 0);
        s.insert(k, 1);
        s.insert(k, 2);
        s.insert(k, 3);

        // One distinct deadline, three payloads.
        assert_eq!(s.count(), 1);
        assert_eq!(s.len(), 3);

        // Drained oldest-first (FIFO), one per call.
        let now = ct(5, 0);
        assert_eq!(s.getbest(now), Some(1));
        assert_eq!(s.getbest(now), Some(2));
        assert_eq!(s.getbest(now), Some(3));
        assert_eq!(s.getbest(now), None);
        assert!(s.is_empty());
    }

    #[test]
    fn earliest_returns_min_key_without_removing() {
        let mut s = Splay::new();
        s.insert(ct(8, 0), 1);
        s.insert(ct(2, 0), 2);
        s.insert(ct(5, 0), 3);

        assert_eq!(s.earliest(), Some(ct(2, 0)));
        // `earliest` is a non-destructive peek.
        assert_eq!(s.len(), 3);
        assert_eq!(s.earliest(), Some(ct(2, 0)));
    }

    #[test]
    fn len_count_is_empty_track_state() {
        let mut s = Splay::new();
        assert!(s.is_empty());

        s.insert(ct(1, 0), 10);
        s.insert(ct(1, 0), 11); // duplicate key
        s.insert(ct(2, 0), 20);

        assert!(!s.is_empty());
        assert_eq!(s.len(), 3); // total payloads: 10, 11, 20
        assert_eq!(s.count(), 2); // distinct keys: t=1s, t=2s

        // Pop 10 (FIFO front of key 1s) → key 1s still holds 11.
        assert_eq!(s.getbest(ct(100, 0)), Some(10));
        assert_eq!(s.len(), 2);
        assert_eq!(s.count(), 2);

        // Pop 11 → key 1s now empty and pruned.
        assert_eq!(s.getbest(ct(100, 0)), Some(11));
        assert_eq!(s.len(), 1);
        assert_eq!(s.count(), 1);
        assert_eq!(s.earliest(), Some(ct(2, 0)));
    }

    #[test]
    fn remove_deletes_matching_payload_and_prunes() {
        let mut s = Splay::new();
        let k = ct(7, 0);
        s.insert(k, 1);
        s.insert(k, 2);
        s.insert(ct(9, 0), 3);

        // Remove the payload equal to 2 at key 7s; key 7s still holds 1.
        assert_eq!(s.remove(k, |p| *p == 2), Some(2));
        assert_eq!(s.len(), 2);
        assert_eq!(s.count(), 2); // key 7s (→1) and key 9s (→3)

        // Remove the remaining payload at key 7s → that key entry is pruned.
        assert_eq!(s.remove(k, |p| *p == 1), Some(1));
        assert_eq!(s.count(), 1); // only key 9s remains
        assert_eq!(s.earliest(), Some(ct(9, 0)));
    }

    #[test]
    fn remove_first_match_only_in_fifo_order() {
        let mut s = Splay::new();
        let k = ct(1, 0);
        // Two payloads sharing a value at the same key.
        s.insert(k, 7);
        s.insert(k, 7);
        s.insert(k, 8);

        // Only the FIRST matching payload (FIFO) is removed.
        assert_eq!(s.remove(k, |p| *p == 7), Some(7));
        assert_eq!(s.len(), 2); // one 7 and one 8 remain

        // Drain to confirm the surviving order is [7, 8].
        let now = ct(1, 0);
        assert_eq!(s.getbest(now), Some(7));
        assert_eq!(s.getbest(now), Some(8));
        assert_eq!(s.getbest(now), None);
    }

    #[test]
    fn remove_absent_key_or_no_match_returns_none() {
        let mut s = Splay::new();
        s.insert(ct(1, 0), 1);

        // Absent key.
        assert_eq!(s.remove(ct(2, 0), |_| true), None);
        // Present key, but no payload matches.
        assert_eq!(s.remove(ct(1, 0), |p| *p == 999), None);
        // Unchanged.
        assert_eq!(s.len(), 1);
        assert_eq!(s.count(), 1);
    }

    #[test]
    fn drain_loop_matches_multi_usage() {
        // Mirror lib/multi.c: `do { t = getbest(now); … } while(t);`
        let mut s = Splay::new();
        s.insert(ct(1, 0), 1);
        s.insert(ct(2, 0), 2);
        s.insert(ct(3, 0), 3); // all three due at now=5s
        s.insert(ct(20, 0), 20); // not due

        let now = ct(5, 0);
        let mut drained = Vec::new();
        while let Some(p) = s.getbest(now) {
            drained.push(p);
        }

        assert_eq!(drained, vec![1, 2, 3]);
        // The not-yet-due timer survives the drain.
        assert_eq!(s.len(), 1);
        assert_eq!(s.earliest(), Some(ct(20, 0)));
    }

    #[test]
    fn curl_named_wrappers_match_idiomatic() {
        let mut s = Splay::new();
        s.Curl_splayinsert(ct(2, 0), 2);
        s.Curl_splayinsert(ct(1, 0), 1);

        // Smallest due key first.
        assert_eq!(s.Curl_splaygetbest(ct(10, 0)), Some(1));

        // Add a duplicate at a key and remove it by predicate.
        s.Curl_splayinsert(ct(1, 0), 11);
        assert_eq!(s.Curl_splayremove(ct(1, 0), |p| *p == 11), Some(11));

        // Then the original key-2 payload drains.
        assert_eq!(s.Curl_splaygetbest(ct(10, 0)), Some(2));
        assert_eq!(s.Curl_splaygetbest(ct(10, 0)), None);
    }

    #[test]
    fn zero_key_is_valid_and_orders_first() {
        // curl uses the all-zero curltime as a sentinel; it must order first.
        let mut s = Splay::new();
        s.insert(CurlTime::zero(), "zero");
        s.insert(ct(0, 1), "one_usec");

        assert_eq!(s.earliest(), Some(CurlTime::zero()));
        // Both are due at any now >= 0.
        assert_eq!(s.getbest(ct(0, 1)), Some("zero"));
        assert_eq!(s.getbest(ct(0, 1)), Some("one_usec"));
        assert_eq!(s.getbest(ct(0, 1)), None);
    }
}
