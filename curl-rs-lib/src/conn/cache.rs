// curl-rs — a memory-safe Rust rewrite of curl / libcurl.
//
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// Copyright (C) Linus Nielsen Feltzing, <linus@haxx.se>
//
// This software is licensed as described in the file COPYING, which you should
// have received as part of this distribution. The terms are also available at
// https://curl.se/docs/copyright.html.
//
// You may opt to use, copy, modify, merge, publish, distribute and/or sell
// copies of the Software, and permit persons to whom the Software is furnished
// to do so, under the terms of the COPYING file.
//
// This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
// KIND, either express or implied.
//
// SPDX-License-Identifier: curl

//! The connection pool / cache — libcurl's connection-reuse machinery.
//!
//! This module is the Rust rewrite of libcurl's `lib/conncache.c` /
//! `lib/conncache.h`. It owns the data structure that lets a finished transfer
//! leave its TCP/TLS/SSH connection *open* so that the next transfer to the
//! same destination can reuse it instead of paying the connect/handshake cost
//! again.
//!
//! # What this module owns (and what it deliberately does not)
//!
//! Pooled connections are grouped into **bundles**, one per destination — the
//! `scheme://host:port` (plus proxy / zone) key that curl stores in
//! `conn->destination`. The pool is a map from that destination string to a
//! [`CpoolBundle`], and each bundle holds the connections to that endpoint in
//! insertion/age order. This file owns **only**:
//!
//! * the pool *structure* — the per-destination bundles keyed by destination;
//! * the connection *limits* — the per-host (`CURLMOPT_MAX_HOST_CONNECTIONS`)
//!   and total (`CURLMOPT_MAX_TOTAL_CONNECTIONS`) caps, plus the
//!   `CURLMOPT_MAXCONNECTS` idle ceiling;
//! * connection *age / expiry / pruning* — oldest-idle eviction, dead-connection
//!   reaping, and network-change invalidation;
//! * the *find-iteration scaffolding* — locking the pool, locating the right
//!   bundle, and invoking a caller-supplied match callback over its members.
//!
//! ## Boundary: the reuse-eligibility predicate lives in `crate::url`
//!
//! The deep *"is this connection reusable for **this** transfer?"* decision —
//! matching proxy, credentials, TLS parameters, NTLM state, HTTP version, and
//! the rest — is curl's `ConnectionExists` / `url_match_conn` in `lib/url.c`,
//! and it is [`crate::url`]'s responsibility, **not** this module's. [`ConnectionPool::find`]
//! takes that predicate as a callback: this file merely locks the pool, selects
//! the bundle whose key equals the requested destination, and invokes the
//! callback on each connection in it. The cache never inspects credentials or
//! TLS state.
//!
//! # Sharing model: `Arc<Mutex<ConnectionPool>>`
//!
//! curl's C pool carries an explicit `locked` bit plus `Curl_share_lock` /
//! `Curl_share_unlock` calls so that several easy handles attached to one
//! `CURLSH` share can serialize access. In the Rust rewrite that bit disappears:
//! the pool is wrapped in an [`Arc<Mutex<ConnectionPool>>`] ([`SharedPool`]) and
//! "locked" is simply *holding the [`std::sync::MutexGuard`]*. A pool owned by a
//! `CURLSH` share lives in [`crate::share`] as a [`SharedPool`] and is cloned
//! (the `Arc`) into every easy handle that joins the share; a non-shared pool is
//! owned by the [`crate::multi`] handle. The borrow checker plus the mutex make
//! a missing-lock data race impossible by construction.
//!
//! # The async-shutdown seam
//!
//! When the cache evicts or terminates a connection it does **not** close it
//! inline: curl hands the connection to the per-multi graceful-shutdown registry
//! ([`crate::conn::shutdown::Cshutdn`]) so the protocol/TLS close handshake can
//! finish in the background. That registry is asynchronous, whereas the pool's
//! limit/expiry methods are synchronous (so they can run while the
//! [`std::sync::Mutex`] is held — you must never `await` while holding a `std`
//! mutex). The two are bridged without coupling the cache to the async runtime:
//!
//! * Terminated connections are moved out of the pool and collected in an
//!   internal discard queue as [`DiscardedConn`] values; the owning multi handle
//!   drains them with [`ConnectionPool::take_discards`] and feeds each to its
//!   `Cshutdn` on the async side.
//! * The shutting-down connection *counts* that the limit math needs
//!   (`Curl_cshutdn_count` / `Curl_cshutdn_dest_count`) and the
//!   close-one-right-away action (`Curl_cshutdn_close_oldest`) are reached
//!   through the small synchronous [`ShutdownCounts`] view, which the multi
//!   handle implements over its `Cshutdn`.
//!
//! # Memory safety (AAP §0.7.1)
//!
//! The whole module is safe Rust: the C ref-counted, hash-of-flexible-array
//! cache becomes safe [`HashMap`] / [`VecDeque`] containers plus [`Arc`], with
//! deterministic [`Drop`] replacing the manual `Curl_conn_free` walk. There are
//! no raw pointers and no `unsafe`; the crate-root `#![forbid(unsafe_code)]`
//! (declared in `lib.rs`) applies here and is intentionally **not** repeated.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use crate::conn::shutdown::{ConnShutdown, SocketIndex};
use crate::error::Result;
use crate::util::timeval::{curlx_ptimediff_ms, CurlTime};

// =============================================================================
// Limit-check result codes (oracle `lib/conncache.h` L90-92).
//
// These mirror the C `#define CPOOL_LIMIT_*` integers exactly. They are the
// return values of [`ConnectionPool::check_limits`] and are kept as a plain
// `i32` (curl's `int`) so the values match the C contract byte-for-byte.
// =============================================================================

/// The pool can accept another connection to the requested destination
/// (the C `CPOOL_LIMIT_OK`, value `0`).
pub const CPOOL_LIMIT_OK: i32 = 0;

/// The per-destination connection limit (`CURLMOPT_MAX_HOST_CONNECTIONS`) is
/// reached and no idle connection could be freed (the C `CPOOL_LIMIT_DEST`,
/// value `1`).
pub const CPOOL_LIMIT_DEST: i32 = 1;

/// The total connection limit (`CURLMOPT_MAX_TOTAL_CONNECTIONS`) is reached and
/// no idle connection could be freed (the C `CPOOL_LIMIT_TOTAL`, value `2`).
pub const CPOOL_LIMIT_TOTAL: i32 = 2;

// =============================================================================
// The connection's view as the cache sees it — the `PoolConn` trait.
// =============================================================================

/// The behaviour the connection pool requires of a connection.
///
/// This trait is the cache's view of curl's `struct connectdata`. Rather than
/// depend on the full connection god-object (which lives above the connection
/// layer and pulls in the protocol engines), the pool stores connections behind
/// this minimal contract — exactly the fields `lib/conncache.c` reads or writes:
/// the destination key, the stable connection id, the last-used timestamp, the
/// in-use / `connect_only` / `close` / `no_reuse` flags, a liveness probe, and
/// per-connection upkeep.
///
/// It is a **supertrait of [`ConnShutdown`]**: every pooled connection is also a
/// shutdownable connection, so the pool can read its id / destination /
/// `connect_only` / aborted state and close its sockets through the same object,
/// and — when a connection is evicted — hand it to the graceful-shutdown
/// registry via [`PoolConn::into_shutdown`] without any trait up-casting (which
/// is unavailable at the crate's MSRV).
///
/// The concrete connection type (authored in the connection layer) implements
/// this; unit tests implement it with a mock. Because `ConnShutdown: Send`, a
/// `Box<dyn PoolConn>` is [`Send`], which is what makes [`ConnectionPool`]
/// shareable across threads behind a [`SharedPool`].
pub trait PoolConn: ConnShutdown {
    /// Assign the connection's stable id (the C `conn->connection_id`).
    ///
    /// Called once by [`ConnectionPool::add`] with the pool's monotonically
    /// increasing counter, mirroring the C `conn->connection_id =
    /// cpool->next_connection_id++`.
    fn set_connection_id(&mut self, id: i64);

    /// When the connection was last used (the C `conn->lastused`).
    ///
    /// Idle age is measured as the elapsed time from this instant to "now"; the
    /// oldest-idle eviction in [`ConnectionPool::check_limits`] /
    /// [`ConnectionPool::conn_now_idle`] picks the connection with the largest
    /// such age.
    fn lastused(&self) -> CurlTime;

    /// Record that the connection was used up until `when` (the C
    /// `conn->lastused = *Curl_pgrs_now(data)`).
    fn set_lastused(&mut self, when: CurlTime);

    /// Whether the connection is currently carrying one or more transfers — the
    /// C `CONN_INUSE(conn)` (`conn->attached_xfers > 0`). An in-use connection
    /// is never eligible for idle eviction.
    fn is_in_use(&self) -> bool;

    /// Whether the connection is marked to be closed and not reused (the C
    /// `conn->bits.close`). Such connections are skipped by the pool-wide
    /// oldest-idle selection.
    fn marked_close(&self) -> bool;

    /// Whether the connection has been flagged as not reusable (the C
    /// `conn->bits.no_reuse`), e.g. after a network change. Reaped once it is no
    /// longer in use.
    fn no_reuse(&self) -> bool;

    /// Set the not-reusable flag (the C `conn->bits.no_reuse = TRUE`), used by
    /// [`ConnectionPool::nw_changed`] to stale every pooled connection.
    fn set_no_reuse(&mut self, value: bool);

    /// Record that the owning transfer was aborted (the C
    /// `conn->bits.aborted`), so the graceful-shutdown path tears the connection
    /// down quickly instead of exchanging a clean protocol goodbye.
    fn set_aborted(&mut self, value: bool);

    /// Probe whether the connection looks dead / half-open (the C
    /// `Curl_conn_seems_dead`). Implementations return `false` for an in-use
    /// connection, matching curl, so that a live transfer is never reaped.
    fn seems_dead(&self) -> bool;

    /// Perform connection upkeep (the C `Curl_conn_upkeep`), e.g. an HTTP/2
    /// keep-alive `PING`. Invoked for every pooled connection by
    /// [`ConnectionPool::upkeep`].
    fn upkeep(&mut self);

    /// Convert this owned pooled connection into a [`ConnShutdown`] for handoff
    /// to the graceful-shutdown registry.
    ///
    /// The `self: Box<Self>` receiver makes the method object-safe *and*
    /// dispatchable on a `Box<dyn PoolConn>`; the concrete implementation simply
    /// returns `self` (an unsizing coercion `Box<Concrete> -> Box<dyn
    /// ConnShutdown>`, **not** a trait up-cast), so it compiles at the project's
    /// MSRV where `dyn`-to-`dyn` up-casting is not yet stable.
    fn into_shutdown(self: Box<Self>) -> Box<dyn ConnShutdown>;

    /// Convert this owned pooled connection into a `Box<dyn Any>` so the caller
    /// can downcast it back to the concrete connection type for **by-value
    /// checkout** ([`ConnectionPool::checkout`]).
    ///
    /// The cache stores connections type-erased as `Box<dyn PoolConn>`; reuse
    /// requires recovering the concrete `Connection` to drive a fresh transfer
    /// over it. As with [`into_shutdown`](PoolConn::into_shutdown), the
    /// `self: Box<Self>` receiver keeps the method object-safe and the concrete
    /// impl simply returns `self` (an unsizing coercion to `Box<dyn Any>`, not a
    /// `dyn`-to-`dyn` up-cast), so it compiles at the project's MSRV.
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any>;
}

/// `true` when the connection is carrying at least one transfer — the C
/// `CONN_INUSE(conn)` macro, expressed once here so the pool's many call sites
/// read exactly like the oracle.
#[inline]
fn conn_in_use(conn: &dyn PoolConn) -> bool {
    conn.is_in_use()
}

/// The effective idle-connection ceiling (the C `Curl_cpool_conn_now_idle`
/// `maxconnects` computation, L564-570).
///
/// When the multi handle sets no explicit `maxconnects` (`maxconnects == 0`),
/// curl derives the ceiling from the number of `running` transfers as
/// `running * 4`, saturating at `UINT_MAX` (the C `if(maxconnects > UINT_MAX/4)
/// maxconnects = UINT_MAX; else maxconnects = closes * 4;` guard, where `closes`
/// is the running count). An explicit `maxconnects` is used verbatim. Factored
/// out as a pure function so the parity of this arithmetic — including the
/// `UINT_MAX` cap — can be unit-tested directly.
#[inline]
const fn idle_ceiling(maxconnects: u32, running: u32) -> u32 {
    if maxconnects == 0 {
        if running <= u32::MAX / 4 {
            running * 4
        } else {
            u32::MAX
        }
    } else {
        maxconnects
    }
}

// =============================================================================
// The cache's synchronous view of the multi handle's shutdown registry.
// =============================================================================

/// The slice of the graceful-shutdown registry (`Cshutdn`) that the limit math
/// needs, exposed synchronously.
///
/// curl's `Curl_cpool_check_limits` counts connections that are *already*
/// shutting down toward the per-destination and total limits (via
/// `Curl_cshutdn_dest_count` / `Curl_cshutdn_count`) and, under pressure, closes
/// the oldest such connection right away (`Curl_cshutdn_close_oldest`). The Rust
/// `Cshutdn` performs the actual close asynchronously, but [`ConnectionPool`]'s
/// methods are synchronous (they run while the pool [`Mutex`] is held). This
/// trait is the bridge: the owning multi handle implements it over its
/// `Cshutdn`, providing the counts directly and a synchronous
/// [`close_oldest`](ShutdownCounts::close_oldest) that force-closes one
/// shutting-down connection.
///
/// A [`NoShutdowns`] no-op implementation is provided for callers (and tests)
/// that have no shutdown registry — equivalent to the C path where
/// `data->multi` is absent, so the counts are always zero.
pub trait ShutdownCounts {
    /// Total number of connections currently being shut down (the C
    /// `Curl_cshutdn_count`).
    fn count(&self) -> usize;

    /// Number of connections to `destination` currently being shut down (the C
    /// `Curl_cshutdn_dest_count`).
    fn dest_count(&self, destination: &str) -> usize;

    /// Force-close the oldest connection being shut down — to `destination` when
    /// `Some`, or to any destination when `None` (the C
    /// `Curl_cshutdn_close_oldest`). Returns `true` if one was closed, `false`
    /// if there was none to close.
    fn close_oldest(&mut self, destination: Option<&str>) -> bool;
}

/// A [`ShutdownCounts`] that reports no connections in shutdown and can close
/// none.
///
/// This is the analogue of the C code path where `data->multi` is `NULL`, so
/// `Curl_cshutdn_*count` are effectively zero. It lets a [`ConnectionPool`] that
/// is not owned by a multi handle (and unit tests) run the limit logic without a
/// real registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoShutdowns;

impl ShutdownCounts for NoShutdowns {
    #[inline]
    fn count(&self) -> usize {
        0
    }

    #[inline]
    fn dest_count(&self, _destination: &str) -> usize {
        0
    }

    #[inline]
    fn close_oldest(&mut self, _destination: Option<&str>) -> bool {
        false
    }
}

// =============================================================================
// A connection removed from the pool and awaiting graceful shutdown.
// =============================================================================

/// A connection that has been evicted/terminated and is queued for the
/// graceful-shutdown registry.
///
/// When [`ConnectionPool`] terminates a connection (to honour a limit, reap a
/// dead connection, invalidate after a network change, or tear the pool down) it
/// removes the owned connection from its bundle and wraps it here together with
/// the C `aborted` flag. The owning multi handle drains these with
/// [`ConnectionPool::take_discards`] and hands each to its
/// [`crate::conn::shutdown::Cshutdn`] (`Curl_cshutdn_add`) on the async side.
/// This is the cache's half of the synchronous→asynchronous shutdown bridge
/// described in the module docs.
pub struct DiscardedConn {
    /// The connection, already in [`ConnShutdown`] form, ready to be registered
    /// for shutdown or force-closed.
    conn: Box<dyn ConnShutdown>,
    /// The C `aborted` flag: `true` means "tear down quickly, no clean goodbye".
    aborted: bool,
}

impl DiscardedConn {
    /// The id of the discarded connection (the C `conn->connection_id`), for
    /// tracing/correlation.
    #[must_use]
    pub fn connection_id(&self) -> i64 {
        self.conn.connection_id()
    }

    /// Whether the connection was aborted (so its shutdown should be a fast
    /// teardown rather than a graceful close).
    #[must_use]
    pub fn aborted(&self) -> bool {
        self.aborted
    }

    /// Consume the discard, yielding the owned connection and its `aborted`
    /// flag so the caller can register it with the shutdown registry.
    #[must_use]
    pub fn into_parts(self) -> (Box<dyn ConnShutdown>, bool) {
        (self.conn, self.aborted)
    }
}

// =============================================================================
// A bundle — the connections to one destination (oracle `cpool_bundle` L63-67).
// =============================================================================

/// A list of connections to the same destination (the C `struct cpool_bundle`).
///
/// In C the bundle is a flexible-array struct holding a `Curl_llist` of
/// connections plus the destination string (`dest[1]` over-allocated to
/// `dest_len`). Here the destination is an owned [`String`] and the connections
/// are owned `Box<dyn PoolConn>` in a [`VecDeque`], which preserves
/// insertion/age order (oldest at the front) so that oldest-idle eviction is
/// deterministic. The bundle is the sole owner of its connections; an empty
/// bundle is removed from the pool map (see [`ConnectionPool::remove_conn`]).
struct CpoolBundle {
    /// The destination key these connections share (the C `bundle->dest`),
    /// equal to each member's `conn.destination()`.
    dest: String,
    /// The connections in the bundle, oldest first (the C `bundle->conns`).
    conns: VecDeque<Box<dyn PoolConn>>,
}

impl CpoolBundle {
    /// Create an empty bundle for `dest` (the C `cpool_bundle_create`, L69-81).
    fn new(dest: &str) -> Self {
        Self {
            dest: dest.to_string(),
            conns: VecDeque::new(),
        }
    }

    /// Append a connection to the bundle (the C `cpool_bundle_add`, L90-96).
    fn add(&mut self, conn: Box<dyn PoolConn>) {
        self.conns.push_back(conn);
    }

    /// Number of connections in the bundle (the C
    /// `Curl_llist_count(&bundle->conns)`).
    fn count(&self) -> usize {
        self.conns.len()
    }

    /// Remove and return the connection with the given id, if present (the C
    /// `cpool_bundle_remove` for a specific connection). The connection's
    /// position is found by id since `Box<dyn PoolConn>` has no pointer
    /// identity exposed to the cache.
    fn remove(&mut self, conn_id: i64) -> Option<Box<dyn PoolConn>> {
        let idx = self
            .conns
            .iter()
            .position(|c| c.connection_id() == conn_id)?;
        self.conns.remove(idx)
    }

    /// The oldest **idle** connection in this bundle (the C
    /// `cpool_bundle_get_oldest_idle`, L308-334), as a connection id.
    ///
    /// "Idle" here is *only* "not in use" — matching the C bundle-scoped
    /// selector, which (unlike the pool-wide one) does **not** also skip
    /// `bits.close` / `connect_only` connections. The score is the elapsed
    /// milliseconds since `lastused`; the highest score (oldest) wins, with the
    /// C initial `highscore = -1` so any idle connection beats "none".
    fn oldest_idle(&self, now: CurlTime) -> Option<i64> {
        let mut highscore: i64 = -1;
        let mut oldest: Option<i64> = None;
        for conn in &self.conns {
            if conn_in_use(conn.as_ref()) {
                continue;
            }
            let last = conn.lastused();
            let score = curlx_ptimediff_ms(&now, &last);
            if score > highscore {
                highscore = score;
                oldest = Some(conn.connection_id());
            }
        }
        oldest
    }
}

// =============================================================================
// The connection pool (oracle `struct cpool` L49-60).
// =============================================================================

/// The connection pool — bundles of reusable connections keyed by destination
/// (the C `struct cpool`).
///
/// # Field mapping to the C `struct cpool`
///
/// | C field | Rust field | Notes |
/// |---------|-----------|-------|
/// | `Curl_hash dest2bundle` | `dest2bundle: HashMap<String, CpoolBundle>` | per-destination bundles |
/// | `size_t num_conn` | `num_conn: usize` | live connection count |
/// | `curl_off_t next_connection_id` | `next_connection_id: i64` | monotonic id source |
/// | `curl_off_t next_easy_id` | `next_easy_id: i64` | monotonic easy-handle id |
/// | `struct curltime last_cleanup` | `last_cleanup: CurlTime` | last dead-prune time |
/// | `struct Curl_share *share` | `owned_by_share: bool` | "belongs to a share" |
/// | `BIT(locked)` | — | implicit in holding the [`Mutex`] guard |
/// | `BIT(initialised)` | — | guaranteed by Rust construction |
/// | `struct Curl_easy *idata` | — | the admin handle is not needed here |
///
/// The C `idata` (internal maintenance handle) and `share` back-pointer exist in
/// C to reach `Curl_share_lock`/trace and to drive shutdown through an admin
/// handle; in the Rust model locking is the [`Mutex`] and shutdown is handled by
/// the discard queue, so only a `bool` "is this a share pool" remains (kept for
/// tracing/observability parity).
///
/// All counters start at zero exactly like the C `calloc`-ed struct, so the
/// derived [`Default`] reproduces `Curl_cpool_init`'s initial state; [`new`](ConnectionPool::new)
/// / [`init`](ConnectionPool::init) additionally size the map.
#[derive(Default)]
pub struct ConnectionPool {
    /// Per-destination connection bundles (the C `cpool->dest2bundle`).
    dest2bundle: HashMap<String, CpoolBundle>,
    /// Number of live connections held across all bundles (the C
    /// `cpool->num_conn`).
    num_conn: usize,
    /// Monotonic source of `conn->connection_id` (the C
    /// `cpool->next_connection_id`).
    next_connection_id: i64,
    /// Monotonic source of `data->id` (the C `cpool->next_easy_id`).
    next_easy_id: i64,
    /// When dead connections were last pruned (the C `cpool->last_cleanup`);
    /// pruning runs at most once per second.
    last_cleanup: CurlTime,
    /// Whether this pool belongs to a `CURLSH` share (the C `cpool->share !=
    /// NULL`). Advisory in the Rust model — locking is the [`Mutex`].
    owned_by_share: bool,
    /// Connections evicted/terminated and awaiting graceful shutdown; drained by
    /// the owning multi handle via [`ConnectionPool::take_discards`].
    discards: Vec<DiscardedConn>,
}

/// A connection pool shared across easy handles and stored by a `CURLSH` share.
///
/// This is the type [`crate::share`] holds for `CURL_LOCK_DATA_CONNECT` and that
/// every easy handle attached to the share clones. A pool *not* owned by a share
/// is owned directly by the [`crate::multi`] handle (which can keep it in the
/// same [`Arc<Mutex<…>>`] form for a uniform API). Holding the
/// [`std::sync::MutexGuard`] is the Rust equivalent of curl's `cpool->locked`
/// bit.
pub type SharedPool = Arc<Mutex<ConnectionPool>>;

// =============================================================================
// Construction, accessors, and the bundle/connection structural helpers.
// =============================================================================

impl ConnectionPool {
    /// Create an empty pool sized for roughly `size` destinations (the C
    /// `Curl_cpool_init`, L113-126, with its `size` hint mapped to
    /// [`HashMap::with_capacity`]).
    ///
    /// All counters start at zero, exactly like the C `calloc`-ed `struct
    /// cpool`. The pool is not associated with a share; use [`init`](Self::init)
    /// to mark a share-owned pool.
    #[must_use]
    pub fn new(size: usize) -> Self {
        Self::init(size, false)
    }

    /// Create an empty pool, recording whether it belongs to a `CURLSH` share
    /// (the C `Curl_cpool_init`'s `share` argument, L113-126).
    ///
    /// `size` is the same capacity hint as [`new`](Self::new); `owned_by_share`
    /// records the C `cpool->share != NULL` for tracing/observability (locking
    /// itself is the [`Mutex`], so the C `Curl_share_lock` calls have no analog).
    ///
    /// All counters start at zero, exactly like the C `calloc`-ed `struct
    /// cpool`. The fields are written explicitly rather than via
    /// `..Default::default()` because [`ConnectionPool`] implements [`Drop`]
    /// (which forbids the partial-move struct-update form).
    #[must_use]
    pub fn init(size: usize, owned_by_share: bool) -> Self {
        Self {
            dest2bundle: HashMap::with_capacity(size),
            num_conn: 0,
            next_connection_id: 0,
            next_easy_id: 0,
            last_cleanup: CurlTime::zero(),
            owned_by_share,
            discards: Vec::new(),
        }
    }

    /// Whether this pool belongs to a `CURLSH` share (the C `cpool->share !=
    /// NULL`).
    #[must_use]
    pub fn is_share_pool(&self) -> bool {
        self.owned_by_share
    }

    /// The number of live connections held in the pool (the C
    /// `cpool->num_conn`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.num_conn
    }

    /// Whether the pool currently holds no live connections.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.num_conn == 0
    }

    /// The number of distinct destinations (bundles) currently in the pool.
    #[must_use]
    pub fn bundle_count(&self) -> usize {
        self.dest2bundle.len()
    }

    /// Initialise a transfer within the pool, returning the id to assign to it
    /// (the C `Curl_cpool_xfer_init`, L269-283, which sets `data->id =
    /// cpool->next_easy_id++`).
    ///
    /// The returned value is the pre-increment counter (so ids start at `0`),
    /// after which the counter advances. As in C, if advancing would make the
    /// counter non-positive (wrap-around), it resets to `0`; [`i64::wrapping_add`]
    /// reproduces the C `curl_off_t` wrap without a debug-mode overflow panic.
    pub fn xfer_init(&mut self) -> i64 {
        let id = self.next_easy_id;
        self.next_easy_id = self.next_easy_id.wrapping_add(1);
        if self.next_easy_id <= 0 {
            self.next_easy_id = 0;
        }
        id
    }

    /// The id of the "first" connection in the pool, or `None` when empty (the C
    /// `cpool_get_first`, L129-145): the head connection of the first non-empty
    /// bundle encountered while iterating the map.
    fn get_first(&self) -> Option<i64> {
        for bundle in self.dest2bundle.values() {
            if let Some(conn) = bundle.conns.front() {
                return Some(conn.connection_id());
            }
        }
        None
    }

    /// Look up the bundle for `destination`, if any (the C `cpool_find_bundle`,
    /// L147-152, which keys on `conn->destination`).
    fn find_bundle(&self, destination: &str) -> Option<&CpoolBundle> {
        self.dest2bundle.get(destination)
    }

    /// Create (and insert) an empty bundle for `destination`, returning a
    /// mutable reference to it (the C `cpool_add_bundle`, L291-307).
    fn add_bundle(&mut self, destination: &str) -> &mut CpoolBundle {
        self.dest2bundle
            .entry(destination.to_string())
            .or_insert_with(|| CpoolBundle::new(destination))
    }

    /// Remove a bundle from the map (the C `cpool_remove_bundle`, L154-160).
    fn remove_bundle(&mut self, destination: &str) {
        self.dest2bundle.remove(destination);
    }

    /// Remove the connection with `conn_id` from whichever bundle holds it,
    /// returning the owned connection (the C `cpool_remove_conn`, L162-182).
    ///
    /// If the bundle becomes empty it is removed from the map (the key parity
    /// invariant "empty bundles removed from the map"), and `num_conn` is
    /// decremented. The connection is located by id because, unlike the C
    /// `Curl_node_llist` pointer walk, a `Box<dyn PoolConn>` exposes no pointer
    /// identity to the cache.
    fn remove_conn(&mut self, conn_id: i64) -> Option<Box<dyn PoolConn>> {
        // Find which destination's bundle currently holds this connection. The
        // bundle is the authority on its own destination (the C `bundle->dest`),
        // which equals the map key by construction (see `add_bundle`); reading
        // it here mirrors the C `cpool_remove_conn`, which reaches the bundle
        // from the connection and uses `bundle->dest` as the key.
        let dest = self.dest2bundle.values().find_map(|bundle| {
            if bundle.conns.iter().any(|c| c.connection_id() == conn_id) {
                Some(bundle.dest.clone())
            } else {
                None
            }
        })?;

        let bundle = self.dest2bundle.get_mut(&dest)?;
        let conn = bundle.remove(conn_id)?;
        if bundle.count() == 0 {
            self.remove_bundle(&dest);
        }
        self.num_conn = self.num_conn.saturating_sub(1);
        Some(conn)
    }

    /// Queue an already-removed connection for graceful shutdown (the discard
    /// half of the C `cpool_discard_conn`, L184-229).
    ///
    /// Mirrors the C decisions that *configure* the discard: a `connect_only`
    /// connection is always treated as `aborted` (curl does not know what the
    /// application did with the socket, L209-210), and the chosen `aborted`
    /// state is recorded on the connection (L211). The connection is then moved
    /// into the discard queue in [`ConnShutdown`] form; the owning multi handle
    /// drains it and decides between a graceful shutdown and an immediate close
    /// when it registers the connection with its `Cshutdn`.
    fn push_discard(&mut self, mut conn: Box<dyn PoolConn>, aborted: bool) {
        let aborted = aborted || conn.connect_only();
        conn.set_aborted(aborted);
        self.discards.push(DiscardedConn {
            conn: conn.into_shutdown(),
            aborted,
        });
    }

    /// Remove the connection with `conn_id` from the pool and queue it for
    /// shutdown — the internal "terminate a pooled connection" used by the
    /// limit, idle, prune, and network-change paths (the structural core of the
    /// C `Curl_conn_terminate`, L635-685).
    ///
    /// Returns `true` if a connection was found and terminated.
    fn terminate_pooled(&mut self, conn_id: i64, aborted: bool) -> bool {
        match self.remove_conn(conn_id) {
            Some(conn) => {
                self.push_discard(conn, aborted);
                true
            }
            None => false,
        }
    }

    /// Drain the connections that have been evicted/terminated and are awaiting
    /// graceful shutdown.
    ///
    /// The owning multi handle calls this (typically right after a pool
    /// operation) and registers each returned [`DiscardedConn`] with its
    /// asynchronous [`crate::conn::shutdown::Cshutdn`]. Draining leaves the
    /// pool's discard queue empty.
    #[must_use]
    pub fn take_discards(&mut self) -> Vec<DiscardedConn> {
        std::mem::take(&mut self.discards)
    }

    /// The number of connections currently queued for shutdown but not yet
    /// drained (mainly for tests/observability).
    #[must_use]
    pub fn pending_discards(&self) -> usize {
        self.discards.len()
    }
}

// =============================================================================
// Limits, add, idle management, find, and termination (oracle L308-685).
// =============================================================================

impl ConnectionPool {
    /// The id of the oldest **idle** connection across the whole pool, or `None`
    /// (the C `cpool_get_oldest_idle`, L336-368).
    ///
    /// Unlike the bundle-scoped [`CpoolBundle::oldest_idle`], the pool-wide
    /// selector additionally skips connections marked to close
    /// (`conn->bits.close`) and `connect_only` connections — exactly the C
    /// `if(CONN_INUSE(conn) || conn->bits.close || conn->connect_only) continue;`
    /// guard. The highest idle-age score wins (initial `highscore = -1`).
    fn get_oldest_idle(&self, now: CurlTime) -> Option<i64> {
        let mut highscore: i64 = -1;
        let mut oldest: Option<i64> = None;
        for bundle in self.dest2bundle.values() {
            for conn in &bundle.conns {
                if conn_in_use(conn.as_ref()) || conn.marked_close() || conn.connect_only() {
                    continue;
                }
                let score = curlx_ptimediff_ms(&now, &conn.lastused());
                if score > highscore {
                    highscore = score;
                    oldest = Some(conn.connection_id());
                }
            }
        }
        oldest
    }

    /// Whether the pool can accept another connection to `cand_dest`, trying to
    /// free space if it is at a limit (the C `Curl_cpool_check_limits`,
    /// L370-464). Returns [`CPOOL_LIMIT_OK`], [`CPOOL_LIMIT_DEST`], or
    /// [`CPOOL_LIMIT_TOTAL`].
    ///
    /// The C `data`/`conn`-derived inputs are passed explicitly: `dest_limit` is
    /// `multi->max_host_connections`, `total_limit` is
    /// `multi->max_total_connections` (each `0` = unlimited), `cand_dest` is the
    /// candidate connection's `destination`, and `now` is `Curl_pgrs_now(data)`.
    /// `shutdowns` is the cache's synchronous view of the shutdown registry
    /// ([`ShutdownCounts`]), supplying `Curl_cshutdn_count` /
    /// `Curl_cshutdn_dest_count` and the close-oldest action.
    ///
    /// Connections shutting down count toward the limits, matching curl: a slot
    /// is reclaimed either by force-closing an oldest shutting-down connection
    /// (when any exist) or by evicting an oldest *idle* pooled connection. The
    /// destination loop uses the bundle-scoped oldest-idle (skips only in-use);
    /// the total loop uses the pool-wide oldest-idle (also skips close /
    /// connect-only) — preserving the C asymmetry exactly.
    ///
    /// This runs entirely under the caller's [`Mutex`] guard (curl's
    /// `CPOOL_LOCK` … `CPOOL_UNLOCK`).
    pub fn check_limits(
        &mut self,
        shutdowns: &mut dyn ShutdownCounts,
        dest_limit: usize,
        total_limit: usize,
        cand_dest: &str,
        now: CurlTime,
    ) -> i32 {
        // Both unlimited ⇒ nothing to enforce (C L388-389).
        if dest_limit == 0 && total_limit == 0 {
            return CPOOL_LIMIT_OK;
        }

        // --- per-destination limit (C L392-431) ---
        if dest_limit != 0 {
            let mut live = self.find_bundle(cand_dest).map_or(0, CpoolBundle::count);
            let mut in_shutdown = shutdowns.dest_count(cand_dest);
            while live + in_shutdown >= dest_limit {
                if in_shutdown > 0 {
                    // Close one shutting-down connection right away, if we can.
                    if !shutdowns.close_oldest(Some(cand_dest)) {
                        break;
                    }
                } else {
                    // The bundle is full of live connections: extract the oldest
                    // one that may be removed now, if any.
                    let oldest = match self.find_bundle(cand_dest) {
                        None => break,
                        Some(bundle) => match bundle.oldest_idle(now) {
                            None => break,
                            Some(id) => id,
                        },
                    };
                    self.terminate_pooled(oldest, false);
                    // The bundle may have been removed in the process; re-count.
                    live = self.find_bundle(cand_dest).map_or(0, CpoolBundle::count);
                }
                in_shutdown = shutdowns.dest_count(cand_dest);
            }
            if live + in_shutdown >= dest_limit {
                return CPOOL_LIMIT_DEST;
            }
        }

        // --- total limit (C L433-459) ---
        if total_limit != 0 {
            let mut in_shutdown = shutdowns.count();
            while self.num_conn + in_shutdown >= total_limit {
                if in_shutdown > 0 {
                    if !shutdowns.close_oldest(None) {
                        break;
                    }
                } else {
                    let oldest = match self.get_oldest_idle(now) {
                        None => break,
                        Some(id) => id,
                    };
                    self.terminate_pooled(oldest, false);
                }
                in_shutdown = shutdowns.count();
            }
            if self.num_conn + in_shutdown >= total_limit {
                return CPOOL_LIMIT_TOTAL;
            }
        }

        CPOOL_LIMIT_OK
    }

    /// Add a connection to the pool (the C `Curl_cpool_add`, L466-498).
    ///
    /// Finds or creates the bundle for the connection's `destination`, appends
    /// the connection, assigns its stable id from `next_connection_id`
    /// (post-increment, exactly the C `conn->connection_id =
    /// cpool->next_connection_id++`), and increments `num_conn`.
    ///
    /// The [`Result`] mirrors the C `CURLcode` return for ABI symmetry; in safe
    /// Rust there is no allocation-failure path (the C `CURLE_OUT_OF_MEMORY`
    /// case) and the pool is always initialised by construction (the C
    /// `CURLE_FAILED_INIT` case cannot occur), so it returns `Ok(())`.
    pub fn add(&mut self, mut conn: Box<dyn PoolConn>) -> Result<()> {
        let dest = conn.destination().to_string();
        // Assign the id before moving the connection into its bundle (C L489).
        conn.set_connection_id(self.next_connection_id);
        self.next_connection_id = self.next_connection_id.wrapping_add(1);
        self.add_bundle(&dest).add(conn);
        self.num_conn += 1;
        Ok(())
    }

    /// A pooled connection has become idle: record the time and, if the pool is
    /// over its idle ceiling, evict the oldest idle connection (the C
    /// `Curl_cpool_conn_now_idle`, L553-593).
    ///
    /// `conn_id` is the connection that just went idle; its `lastused` is set to
    /// `now`. `maxconnects` is `multi->maxconnects` and `running` is
    /// `Curl_multi_xfers_running(multi)`. When `maxconnects == 0`, curl derives
    /// the ceiling as `running * 4` (capped at `u32::MAX` — the C
    /// `UINT_MAX`), otherwise it uses `maxconnects` verbatim. If the pool then
    /// exceeds the ceiling, the oldest idle connection is evicted. Returns
    /// whether the just-idle connection was *kept* (`true`) rather than itself
    /// being the one evicted (`false`).
    pub fn conn_now_idle(
        &mut self,
        conn_id: i64,
        maxconnects: u32,
        running: u32,
        now: CurlTime,
    ) -> bool {
        // The connection was used up until now (C L572).
        if let Some(conn) = self.conn_mut(conn_id) {
            conn.set_lastused(now);
        }

        // Effective idle ceiling (C L564-570): the `running * 4` default capped
        // at `UINT_MAX`, or the explicit `maxconnects`.
        let maxconnects = idle_ceiling(maxconnects, running);

        let mut kept = true;
        if maxconnects != 0 && self.num_conn > maxconnects as usize {
            // Pool is full: close the oldest idle connection (C L578-586).
            if let Some(oldest) = self.get_oldest_idle(now) {
                kept = oldest != conn_id;
                self.terminate_pooled(oldest, false);
            }
        }
        kept
    }

    /// Find a connection in the bundle for `destination`, delegating the
    /// reuse-eligibility decision to the caller's callbacks (the C
    /// `Curl_cpool_find`, L595-633).
    ///
    /// This is the [boundary](self#boundary-the-reuse-eligibility-predicate-lives-in-crateurl):
    /// the cache locates the bundle whose key equals `destination` and invokes
    /// `conn_cb` on each connection in it until `conn_cb` returns `true` (a
    /// match found); it never inspects the connection itself. The optional
    /// `done_cb` then post-processes the boolean result (the C `done_cb`, which
    /// may override it). Returns the final result (`false` if the bundle was
    /// absent and no `done_cb` overrode it). `conn_cb` is curl's
    /// `Curl_cpool_conn_match_cb` and `done_cb` its `Curl_cpool_done_match_cb`,
    /// both supplied by [`crate::url`]'s connection-matching logic.
    ///
    /// Runs under the caller's [`Mutex`] guard (curl invokes both callbacks
    /// while the pool lock is held).
    pub fn find<M, D>(&self, destination: &str, mut conn_cb: M, done_cb: Option<D>) -> bool
    where
        M: FnMut(&dyn PoolConn) -> bool,
        D: FnOnce(bool) -> bool,
    {
        let mut result = false;
        if let Some(bundle) = self.find_bundle(destination) {
            for conn in &bundle.conns {
                if conn_cb(conn.as_ref()) {
                    result = true;
                    break;
                }
            }
        }
        if let Some(done) = done_cb {
            result = done(result);
        }
        result
    }

    /// Check out a reusable idle connection for `destination`, removing it from
    /// the pool and returning it **by value** for a fresh transfer.
    ///
    /// This is the production reuse entry point (curl's `Curl_cpool_get_conn` /
    /// the reuse half of `ConnectionExists`): the cache locates the bundle whose
    /// key equals `destination` and returns the first connection that is
    /// reusable — not currently carrying a transfer ([`conn_in_use`] is false),
    /// not marked to close ([`PoolConn::marked_close`]), not flagged no-reuse
    /// ([`PoolConn::no_reuse`]) — and for which the caller's `matcher` predicate
    /// (curl's `Curl_cpool_conn_match_cb`, comparing option-level reuse
    /// eligibility) returns `true`. The match is removed via [`remove_conn`]
    /// (decrementing `num_conn`, dropping an emptied bundle) and handed back as a
    /// `Box<dyn PoolConn>` the caller downcasts via [`PoolConn::into_any`].
    /// Returns `None` when no eligible connection exists.
    ///
    /// Runs under the caller's [`Mutex`] guard, exactly like [`find`](Self::find).
    pub fn checkout(
        &mut self,
        destination: &str,
        mut matcher: impl FnMut(&dyn PoolConn) -> bool,
    ) -> Option<Box<dyn PoolConn>> {
        let mut found: Option<i64> = None;
        if let Some(bundle) = self.find_bundle(destination) {
            for conn in &bundle.conns {
                if conn_in_use(conn.as_ref()) || conn.marked_close() || conn.no_reuse() {
                    continue;
                }
                if matcher(conn.as_ref()) {
                    found = Some(conn.connection_id());
                    break;
                }
            }
        }
        self.remove_conn(found?)
    }

    /// Return a keep-alive-eligible connection to the pool after a transfer
    /// completes, so the next transfer to the same `destination` can reuse it
    /// (curl's `Curl_cpool_add` + `Curl_cpool_conn_now_idle`).
    ///
    /// The connection is added under its own `destination` key (assigning its
    /// stable id via [`add`](Self::add)), then [`conn_now_idle`](Self::conn_now_idle)
    /// stamps its `lastused` and enforces the idle ceiling: with `maxconnects`
    /// the explicit `CURLOPT_MAXCONNECTS` cap, the oldest idle connection is
    /// evicted (queued for shutdown, drainable via [`take_discards`](Self::take_discards))
    /// when the pool would exceed it. `running` is passed as `0` here because the
    /// synchronous easy/CLI reuse path has no concurrently running transfers to
    /// derive the `running * 4` default from; an explicit `maxconnects` (curl's
    /// default 5, propagated from the handle) governs the cap.
    pub fn checkin(&mut self, conn: Box<dyn PoolConn>, maxconnects: u32, now: CurlTime) {
        // Preserve an already-assigned stable id: curl assigns `connection_id`
        // ONCE, when the connection is first cached, and reuse keeps it (the
        // "Reusing existing" path never re-ids). A connection returning to the
        // pool after a transfer (id >= 0) is re-inserted without reassignment; a
        // never-pooled connection (id < 0) is given the next id by `add`.
        let existing = conn.connection_id();
        let id = if existing >= 0 {
            self.insert_keep_id(conn);
            existing
        } else {
            // `add` assigns `self.next_connection_id` then post-increments, so
            // the id just assigned is the pre-increment value.
            let new_id = self.next_connection_id;
            let _ = self.add(conn);
            new_id
        };
        self.conn_now_idle(id, maxconnects, 0, now);
    }

    /// Re-insert a connection that already carries a pool-assigned id (a reused
    /// connection being checked back in) WITHOUT reassigning it, preserving
    /// curl's "assign `connection_id` once" semantics. This is the id-preserving
    /// counterpart of [`add`](Self::add): same bundle insert and `num_conn`
    /// increment, but no id mutation.
    fn insert_keep_id(&mut self, conn: Box<dyn PoolConn>) {
        let dest = conn.destination().to_string();
        self.add_bundle(&dest).add(conn);
        self.num_conn += 1;
    }

    /// Terminate a connection: remove it from the pool and queue it for graceful
    /// shutdown (the C `Curl_conn_terminate`, L635-685).
    ///
    /// As in C, an in-use connection is **not** terminated unless `aborted` is
    /// set (the C `if(CONN_INUSE(conn) && !aborted) return;` guard, L649-653);
    /// otherwise the connection is removed (decrementing `num_conn`, dropping an
    /// emptied bundle) and discarded via the shutdown path — gracefully unless
    /// `aborted`. A `conn_id` not present in this pool is a no-op.
    pub fn conn_terminate(&mut self, conn_id: i64, aborted: bool) {
        let terminable = match self.get_conn(conn_id) {
            Some(conn) => aborted || !conn_in_use(conn),
            None => return,
        };
        if terminable {
            self.terminate_pooled(conn_id, aborted);
        }
    }

    /// Return a mutable reference to the pooled connection with `conn_id`, if
    /// present. Used internally to update a connection's `lastused`.
    fn conn_mut(&mut self, conn_id: i64) -> Option<&mut (dyn PoolConn + 'static)> {
        for bundle in self.dest2bundle.values_mut() {
            for conn in &mut bundle.conns {
                if conn.connection_id() == conn_id {
                    return Some(conn.as_mut());
                }
            }
        }
        None
    }

    /// Return a shared reference to the pooled connection with `conn_id`, if
    /// present (the lookup behind [`ConnectionPool::get_conn`]).
    #[must_use]
    pub fn get_conn(&self, conn_id: i64) -> Option<&dyn PoolConn> {
        for bundle in self.dest2bundle.values() {
            for conn in &bundle.conns {
                if conn.connection_id() == conn_id {
                    return Some(conn.as_ref());
                }
            }
        }
        None
    }
}

// =============================================================================
// Reaping, upkeep, network-change, teardown (oracle L687-end).
// =============================================================================

impl ConnectionPool {
    /// Collect the ids of every pooled connection for which `pred` holds.
    ///
    /// This is the read-only half of the C `cpool_foreach` (L512-552): it walks
    /// every bundle and connection, gathering matches. The callers below then
    /// act on the collected ids in a second pass, because terminating a
    /// connection mutates the pool and cannot run while an iteration borrow is
    /// live (curl's C loop sidesteps this by advancing the list cursor *before*
    /// invoking the callback; collecting ids first is the safe-Rust equivalent).
    fn collect_ids<F>(&self, pred: F) -> Vec<i64>
    where
        F: Fn(&dyn PoolConn) -> bool,
    {
        let mut ids = Vec::new();
        for bundle in self.dest2bundle.values() {
            for conn in &bundle.conns {
                if pred(conn.as_ref()) {
                    ids.push(conn.connection_id());
                }
            }
        }
        ids
    }

    /// Scan the pool for half-open / dead connections, terminating them — at
    /// most **once per second** (the C `Curl_cpool_prune_dead`, L718-737).
    ///
    /// `now` is `Curl_pgrs_now(data)`. If fewer than `1000` ms have elapsed
    /// since the last prune (`curlx_ptimediff_ms(now, last_cleanup) < 1000`),
    /// this is a no-op (the C L729-734 cadence guard). Otherwise every
    /// connection that is not in use and either explicitly not reusable
    /// (`conn->bits.no_reuse`) or that [`PoolConn::seems_dead`] reports dead (the
    /// C `cpool_reap_dead_cb`) is terminated, and `last_cleanup` is advanced to
    /// `now`.
    pub fn prune_dead(&mut self, now: CurlTime) {
        let elapsed = curlx_ptimediff_ms(&now, &self.last_cleanup);
        if elapsed < 1000 {
            return;
        }

        // C `cpool_reap_dead_cb`: terminate = (!in_use && no_reuse) || seems_dead
        // (and `seems_dead` itself yields false for an in-use connection).
        let dead = self.collect_ids(|conn| {
            if !conn_in_use(conn) && conn.no_reuse() {
                true
            } else {
                conn.seems_dead()
            }
        });
        for id in dead {
            self.terminate_pooled(id, false);
        }

        self.last_cleanup = now;
    }

    /// Perform upkeep on every pooled connection (the C `Curl_cpool_upkeep`,
    /// L748-759, driving `conn_upkeep` / `Curl_conn_upkeep` over the pool).
    ///
    /// Each connection's [`PoolConn::upkeep`] is invoked (e.g. an HTTP/2
    /// keep-alive `PING`). Returns `Ok(())`; the [`Result`] mirrors the C
    /// `CURLcode` return for ABI symmetry.
    pub fn upkeep(&mut self) -> Result<()> {
        for bundle in self.dest2bundle.values_mut() {
            for conn in &mut bundle.conns {
                conn.upkeep();
            }
        }
        Ok(())
    }

    /// Invalidate the pool after a network change: stale every connection and
    /// close the unused ones (the C `Curl_cpool_nw_changed`, L862-873).
    ///
    /// First every connection is flagged not-reusable (the C `cpool_mark_stale`,
    /// so even connections currently in use will not be reused once idle); then
    /// every connection that is not in use is terminated (the C
    /// `cpool_reap_no_reuse`). This prevents reuse of connections that may have
    /// been routed over a now-defunct network path.
    pub fn nw_changed(&mut self) {
        // Mark every connection stale (C `cpool_mark_stale`).
        for bundle in self.dest2bundle.values_mut() {
            for conn in &mut bundle.conns {
                conn.set_no_reuse(true);
            }
        }
        // Reap every idle (now not-reusable) connection (C `cpool_reap_no_reuse`).
        let stale = self.collect_ids(|conn| !conn_in_use(conn) && conn.no_reuse());
        for id in stale {
            self.terminate_pooled(id, false);
        }
    }

    /// Tear the pool down: move every connection to the discard queue for
    /// graceful shutdown (the C `Curl_cpool_destroy`, L231-251).
    ///
    /// Mirrors the C loop that repeatedly takes the first connection, removes
    /// it, and hands it to the shutdown machinery, until the pool is empty.
    /// After this returns, the pool holds no live connections and the
    /// terminated connections are available via
    /// [`ConnectionPool::take_discards`]; any that are never drained are
    /// force-closed when the pool is dropped (see the [`Drop`] impl).
    pub fn destroy(&mut self) {
        while let Some(id) = self.get_first() {
            if !self.terminate_pooled(id, false) {
                break;
            }
        }
    }
}

impl Drop for ConnectionPool {
    /// Deterministic teardown (the safety-net half of the C `Curl_cpool_destroy`
    /// / `Curl_conn_free`).
    ///
    /// A destructor cannot `await`, so it cannot run the graceful protocol/TLS
    /// close (that is [`ConnectionPool::destroy`] + the multi handle draining
    /// [`ConnectionPool::take_discards`] on the async side). Instead it
    /// force-closes the sockets of every connection still held — both those
    /// still pooled and those queued for shutdown but not yet drained — closing
    /// `SECONDARYSOCKET` before `FIRSTSOCKET` (the order the shutdown subsystem
    /// uses). Dropping the boxes afterwards frees the connections, deregistering
    /// their sockets from the async reactor structurally.
    fn drop(&mut self) {
        for bundle in self.dest2bundle.values_mut() {
            for conn in &mut bundle.conns {
                conn.close_socket(SocketIndex::Secondary);
                conn.close_socket(SocketIndex::First);
            }
        }
        for discarded in &mut self.discards {
            discarded.conn.close_socket(SocketIndex::Secondary);
            discarded.conn.close_socket(SocketIndex::First);
        }
    }
}

// =============================================================================
// Shared-pool helpers.
// =============================================================================

/// Create a new [`SharedPool`] (an `Arc<Mutex<ConnectionPool>>`) sized for
/// roughly `size` destinations.
///
/// This is the form [`crate::share`] stores for `CURL_LOCK_DATA_CONNECT` and
/// that the [`crate::multi`] handle can use for its own (non-shared) pool, so
/// both reach the pool through the same locked handle.
#[must_use]
pub fn new_shared_pool(size: usize) -> SharedPool {
    Arc::new(Mutex::new(ConnectionPool::new(size)))
}

/// Run `f` with the pool locked (the C `Curl_cpool_do_locked`, L828-840).
///
/// Acquires the pool's [`Mutex`] — the Rust equivalent of curl's `CPOOL_LOCK` —
/// and invokes `f` with exclusive access to the [`ConnectionPool`], returning
/// whatever `f` returns. The C `(data, conn, cb, cbdata)` arguments are captured
/// by the closure. A poisoned mutex (a thread panicked while holding it) is
/// recovered rather than propagated, so a callback panic cannot wedge the pool
/// for every later caller.
pub fn do_locked<R>(pool: &SharedPool, f: impl FnOnce(&mut ConnectionPool) -> R) -> R {
    let mut guard = pool
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(&mut guard)
}

// =============================================================================
// Tests.
//
// The tests exercise the *parity-critical* behaviour of the cache against the C
// oracle (`lib/conncache.c`): the exact limit/eviction rules of
// `Curl_cpool_check_limits`, the `maxconnects` default of
// `Curl_cpool_conn_now_idle`, the once-per-second cadence of
// `Curl_cpool_prune_dead`, monotonic `connection_id` assignment, empty-bundle
// removal, the find-iteration BOUNDARY (no reuse-eligibility logic here), and
// shareability across threads via `Arc<Mutex<…>>`.
//
// A `MockConn` implements both [`ConnShutdown`] and [`PoolConn`] with builder
// methods to script each connection's idle/in-use/close/no-reuse/dead state, and
// two `ShutdownCounts` doubles model the multi handle's shutdown registry: one
// that can reclaim slots (`MockShutdowns`) and one that cannot (`StuckShutdowns`).
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::BoxFuture;
    use crate::conn::shutdown::DisconnectHook;
    use std::cell::RefCell;
    use std::collections::HashMap as StdHashMap;

    // -------------------------------------------------------------------------
    // Test doubles.
    // -------------------------------------------------------------------------

    /// Observable side effects recorded by a [`MockConn`], shared with the test
    /// via a clone of the `Arc` so they can be inspected after the connection has
    /// been moved into (and possibly out of) the pool.
    #[derive(Default)]
    struct ConnState {
        /// How many times [`PoolConn::upkeep`] was invoked.
        upkeep_calls: usize,
        /// The order in which sockets were closed (the [`Drop`] / terminate path).
        closed: Vec<SocketIndex>,
    }

    /// A scriptable [`PoolConn`] / [`ConnShutdown`] test double.
    struct MockConn {
        id: i64,
        destination: String,
        connect_only: bool,
        aborted: bool,
        in_use: bool,
        marked_close: bool,
        no_reuse: bool,
        dead: bool,
        lastused: CurlTime,
        state: Arc<Mutex<ConnState>>,
    }

    impl MockConn {
        /// A fresh idle connection for `dest` (id unassigned until `add`).
        fn new(dest: &str) -> Self {
            Self {
                id: -1,
                destination: dest.to_string(),
                connect_only: false,
                aborted: false,
                in_use: false,
                marked_close: false,
                no_reuse: false,
                dead: false,
                lastused: CurlTime::zero(),
                state: Arc::new(Mutex::new(ConnState::default())),
            }
        }

        /// A handle to this connection's shared side-effect record.
        fn state_handle(&self) -> Arc<Mutex<ConnState>> {
            Arc::clone(&self.state)
        }

        /// Box this connection as a `dyn PoolConn` ready for [`ConnectionPool::add`].
        fn boxed(self) -> Box<dyn PoolConn> {
            Box::new(self)
        }

        // -- builders (named to avoid colliding with the trait getters) --

        /// Record the connection's `lastused` instant (older ⇒ evicted first).
        fn idle_at(mut self, when: CurlTime) -> Self {
            self.lastused = when;
            self
        }

        /// Mark the connection as carrying a transfer (the C `CONN_INUSE`).
        fn mark_in_use(mut self) -> Self {
            self.in_use = true;
            self
        }

        /// Mark the connection `CURLOPT_CONNECT_ONLY` (the C `conn->connect_only`).
        fn mark_connect_only(mut self) -> Self {
            self.connect_only = true;
            self
        }

        /// Mark the connection to-be-closed (the C `conn->bits.close`).
        fn mark_close(mut self) -> Self {
            self.marked_close = true;
            self
        }

        /// Mark the connection not-reusable (the C `conn->bits.no_reuse`).
        fn mark_no_reuse(mut self) -> Self {
            self.no_reuse = true;
            self
        }

        /// Make the connection report itself dead when idle (the C
        /// `Curl_conn_seems_dead`).
        fn mark_dead(mut self) -> Self {
            self.dead = true;
            self
        }
    }

    impl ConnShutdown for MockConn {
        fn connection_id(&self) -> i64 {
            self.id
        }
        fn destination(&self) -> &str {
            &self.destination
        }
        fn connect_only(&self) -> bool {
            self.connect_only
        }
        fn is_aborted(&self) -> bool {
            self.aborted
        }
        fn is_connected(&self, _socket: SocketIndex) -> bool {
            true
        }
        fn take_disconnect_hook(&mut self) -> Option<DisconnectHook> {
            None
        }
        fn shutdown_socket<'a>(&'a mut self, _socket: SocketIndex) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async { Ok(true) })
        }
        fn close_socket(&mut self, socket: SocketIndex) {
            self.state
                .lock()
                .expect("mock conn state poisoned")
                .closed
                .push(socket);
        }
    }

    impl PoolConn for MockConn {
        fn set_connection_id(&mut self, id: i64) {
            self.id = id;
        }
        fn lastused(&self) -> CurlTime {
            self.lastused
        }
        fn set_lastused(&mut self, when: CurlTime) {
            self.lastused = when;
        }
        fn is_in_use(&self) -> bool {
            self.in_use
        }
        fn marked_close(&self) -> bool {
            self.marked_close
        }
        fn no_reuse(&self) -> bool {
            self.no_reuse
        }
        fn set_no_reuse(&mut self, value: bool) {
            self.no_reuse = value;
        }
        fn set_aborted(&mut self, value: bool) {
            self.aborted = value;
        }
        fn seems_dead(&self) -> bool {
            // Faithful to curl: an in-use connection is never "dead".
            if self.in_use {
                false
            } else {
                self.dead
            }
        }
        fn upkeep(&mut self) {
            self.state
                .lock()
                .expect("mock conn state poisoned")
                .upkeep_calls += 1;
        }
        fn into_shutdown(self: Box<Self>) -> Box<dyn ConnShutdown> {
            self
        }
        fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
            self
        }
    }

    /// A [`ShutdownCounts`] double whose `close_oldest` reclaims a slot
    /// (decrementing the relevant per-destination count), modelling a shutdown
    /// registry that can make room.
    #[derive(Default)]
    struct MockShutdowns {
        per_dest: StdHashMap<String, usize>,
    }

    impl MockShutdowns {
        /// `n` connections to `dest` currently shutting down.
        fn with(dest: &str, n: usize) -> Self {
            let mut per_dest = StdHashMap::new();
            per_dest.insert(dest.to_string(), n);
            Self { per_dest }
        }
    }

    impl ShutdownCounts for MockShutdowns {
        fn count(&self) -> usize {
            self.per_dest.values().copied().sum()
        }
        fn dest_count(&self, destination: &str) -> usize {
            self.per_dest.get(destination).copied().unwrap_or(0)
        }
        fn close_oldest(&mut self, destination: Option<&str>) -> bool {
            match destination {
                Some(d) => match self.per_dest.get_mut(d) {
                    Some(c) if *c > 0 => {
                        *c -= 1;
                        true
                    }
                    _ => false,
                },
                None => {
                    for c in self.per_dest.values_mut() {
                        if *c > 0 {
                            *c -= 1;
                            return true;
                        }
                    }
                    false
                }
            }
        }
    }

    /// A [`ShutdownCounts`] double that reports connections shutting down but can
    /// never reclaim a slot (`close_oldest` always fails) — models a registry
    /// whose connections are all mid-shutdown and not yet closable.
    struct StuckShutdowns {
        total: usize,
        per_dest: usize,
    }

    impl ShutdownCounts for StuckShutdowns {
        fn count(&self) -> usize {
            self.total
        }
        fn dest_count(&self, _destination: &str) -> usize {
            self.per_dest
        }
        fn close_oldest(&mut self, _destination: Option<&str>) -> bool {
            false
        }
    }

    /// Convenience: add a connection and return the pool's resulting length.
    fn add(pool: &mut ConnectionPool, conn: MockConn) {
        pool.add(conn.boxed())
            .expect("add never fails in safe Rust");
    }

    // -------------------------------------------------------------------------
    // Constants & basic structure.
    // -------------------------------------------------------------------------

    #[test]
    fn limit_constants_match_oracle() {
        // conncache.h L90-92.
        assert_eq!(CPOOL_LIMIT_OK, 0);
        assert_eq!(CPOOL_LIMIT_DEST, 1);
        assert_eq!(CPOOL_LIMIT_TOTAL, 2);
    }

    #[test]
    fn add_assigns_monotonic_ids_and_tracks_num_conn() {
        let mut pool = ConnectionPool::new(0);
        add(&mut pool, MockConn::new("a")); // id 0
        add(&mut pool, MockConn::new("a")); // id 1
        add(&mut pool, MockConn::new("b")); // id 2
        add(&mut pool, MockConn::new("a")); // id 3

        assert_eq!(pool.len(), 4, "num_conn tracks pool size");
        assert_eq!(pool.bundle_count(), 2, "two destinations ⇒ two bundles");
        // Each id 0..=3 was assigned exactly once, strictly increasing.
        for id in 0..4 {
            assert!(pool.get_conn(id).is_some(), "id {id} present");
        }
        assert!(pool.get_conn(4).is_none(), "no id beyond the last assigned");
    }

    #[test]
    fn connection_id_is_never_reused() {
        // Terminating a connection must not cause its id to be handed out again:
        // `next_connection_id` only ever moves forward.
        let mut pool = ConnectionPool::new(0);
        add(&mut pool, MockConn::new("a")); // id 0
        add(&mut pool, MockConn::new("a")); // id 1
        pool.conn_terminate(0, true);
        add(&mut pool, MockConn::new("a")); // id 2, NOT 0
        assert!(pool.get_conn(0).is_none(), "terminated id stays gone");
        assert!(
            pool.get_conn(2).is_some(),
            "new id continues from the counter"
        );
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn empty_bundle_is_removed_from_map() {
        let mut pool = ConnectionPool::new(0);
        add(&mut pool, MockConn::new("a")); // id 0
        add(&mut pool, MockConn::new("a")); // id 1
        assert_eq!(pool.bundle_count(), 1);

        pool.conn_terminate(0, true); // bundle still holds id 1
        assert_eq!(pool.bundle_count(), 1, "non-empty bundle stays");
        assert_eq!(pool.len(), 1);

        pool.conn_terminate(1, true); // bundle now empty ⇒ removed
        assert_eq!(pool.bundle_count(), 0, "empty bundle removed from the map");
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn xfer_init_returns_monotonic_easy_ids() {
        let mut pool = ConnectionPool::new(0);
        assert_eq!(pool.xfer_init(), 0);
        assert_eq!(pool.xfer_init(), 1);
        assert_eq!(pool.xfer_init(), 2);
    }

    // -------------------------------------------------------------------------
    // check_limits parity (the critical limit/eviction rules, C L370-464).
    // -------------------------------------------------------------------------

    #[test]
    fn check_limits_both_zero_is_always_ok() {
        let mut pool = ConnectionPool::new(0);
        add(&mut pool, MockConn::new("a").mark_in_use());
        add(&mut pool, MockConn::new("a").mark_in_use());
        let mut sd = MockShutdowns::default();
        // Both unlimited ⇒ OK regardless of how full the pool is (C L388-389).
        assert_eq!(
            pool.check_limits(&mut sd, 0, 0, "a", CurlTime::new(10, 0)),
            CPOOL_LIMIT_OK
        );
        assert_eq!(pool.len(), 2, "nothing evicted when unlimited");
    }

    #[test]
    fn check_limits_dest_evicts_oldest_idle_then_ok() {
        let mut pool = ConnectionPool::new(0);
        add(&mut pool, MockConn::new("a").idle_at(CurlTime::new(0, 0))); // idle, evictable
        let mut sd = MockShutdowns::default();
        // dest_limit reached, an idle conn exists ⇒ evict it, return OK.
        assert_eq!(
            pool.check_limits(&mut sd, 1, 0, "a", CurlTime::new(10, 0)),
            CPOOL_LIMIT_OK
        );
        assert_eq!(pool.len(), 0, "oldest idle evicted to make room");
        assert_eq!(
            pool.pending_discards(),
            1,
            "evicted conn queued for shutdown"
        );
    }

    #[test]
    fn check_limits_dest_no_idle_returns_dest() {
        let mut pool = ConnectionPool::new(0);
        add(&mut pool, MockConn::new("a").mark_in_use()); // in use ⇒ not evictable
        let mut sd = MockShutdowns::default();
        assert_eq!(
            pool.check_limits(&mut sd, 1, 0, "a", CurlTime::new(10, 0)),
            CPOOL_LIMIT_DEST
        );
        assert_eq!(pool.len(), 1, "in-use conn is never evicted");
    }

    #[test]
    fn check_limits_total_evicts_oldest_idle_then_ok() {
        let mut pool = ConnectionPool::new(0);
        add(&mut pool, MockConn::new("a").idle_at(CurlTime::new(0, 0)));
        let mut sd = MockShutdowns::default();
        assert_eq!(
            pool.check_limits(&mut sd, 0, 1, "a", CurlTime::new(10, 0)),
            CPOOL_LIMIT_OK
        );
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.pending_discards(), 1);
    }

    #[test]
    fn check_limits_total_no_idle_returns_total() {
        let mut pool = ConnectionPool::new(0);
        add(&mut pool, MockConn::new("a").mark_in_use());
        let mut sd = MockShutdowns::default();
        assert_eq!(
            pool.check_limits(&mut sd, 0, 1, "a", CurlTime::new(10, 0)),
            CPOOL_LIMIT_TOTAL
        );
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn check_limits_counts_shutdowns_and_prefers_closing_them() {
        // dest_limit = 2; one live idle conn + one shutting-down conn ⇒ at limit.
        // curl closes the shutting-down one (counted toward the limit) rather
        // than evicting the live idle connection.
        let mut pool = ConnectionPool::new(0);
        add(&mut pool, MockConn::new("a").idle_at(CurlTime::new(0, 0)));
        let mut sd = MockShutdowns::with("a", 1);
        assert_eq!(
            pool.check_limits(&mut sd, 2, 0, "a", CurlTime::new(10, 0)),
            CPOOL_LIMIT_OK
        );
        assert_eq!(
            pool.len(),
            1,
            "live idle conn kept; shutdown slot reclaimed"
        );
        assert_eq!(pool.pending_discards(), 0, "no pool eviction occurred");
        assert_eq!(sd.dest_count("a"), 0, "the shutting-down conn was closed");
    }

    #[test]
    fn check_limits_dest_unreclaimable_shutdowns_returns_dest() {
        // The destination is at its limit purely due to shutting-down conns that
        // cannot be closed yet ⇒ DEST (they are counted, none can be reclaimed).
        let mut pool = ConnectionPool::new(0);
        let mut sd = StuckShutdowns {
            total: 1,
            per_dest: 1,
        };
        assert_eq!(
            pool.check_limits(&mut sd, 1, 0, "a", CurlTime::new(10, 0)),
            CPOOL_LIMIT_DEST
        );
    }

    #[test]
    fn check_limits_total_unreclaimable_shutdowns_returns_total() {
        let mut pool = ConnectionPool::new(0);
        let mut sd = StuckShutdowns {
            total: 1,
            per_dest: 0,
        };
        assert_eq!(
            pool.check_limits(&mut sd, 0, 1, "a", CurlTime::new(10, 0)),
            CPOOL_LIMIT_TOTAL
        );
    }

    #[test]
    fn check_limits_dest_bundle_selector_evicts_close_marked_idle() {
        // ASYMMETRY (oracle L308 vs L336): the *bundle-scoped* oldest-idle
        // selector used by the destination loop skips ONLY in-use conns, so a
        // close-marked idle conn IS evictable here.
        let mut pool = ConnectionPool::new(0);
        add(
            &mut pool,
            MockConn::new("a").idle_at(CurlTime::new(0, 0)).mark_close(),
        );
        let mut sd = MockShutdowns::default();
        assert_eq!(
            pool.check_limits(&mut sd, 1, 0, "a", CurlTime::new(10, 0)),
            CPOOL_LIMIT_OK
        );
        assert_eq!(
            pool.len(),
            0,
            "close-marked idle conn evicted by dest selector"
        );
    }

    #[test]
    fn check_limits_total_pool_selector_skips_close_marked_idle() {
        // ASYMMETRY: the *pool-wide* oldest-idle selector used by the total loop
        // additionally skips close-marked conns, so the same conn is NOT
        // evictable here ⇒ TOTAL.
        let mut pool = ConnectionPool::new(0);
        add(
            &mut pool,
            MockConn::new("a").idle_at(CurlTime::new(0, 0)).mark_close(),
        );
        let mut sd = MockShutdowns::default();
        assert_eq!(
            pool.check_limits(&mut sd, 0, 1, "a", CurlTime::new(10, 0)),
            CPOOL_LIMIT_TOTAL
        );
        assert_eq!(pool.len(), 1, "pool selector skips close-marked conn");
    }

    #[test]
    fn check_limits_total_pool_selector_skips_connect_only_idle() {
        // The pool-wide selector also skips connect_only conns (C L336 guard).
        let mut pool = ConnectionPool::new(0);
        add(
            &mut pool,
            MockConn::new("a")
                .idle_at(CurlTime::new(0, 0))
                .mark_connect_only(),
        );
        let mut sd = MockShutdowns::default();
        assert_eq!(
            pool.check_limits(&mut sd, 0, 1, "a", CurlTime::new(10, 0)),
            CPOOL_LIMIT_TOTAL
        );
        assert_eq!(pool.len(), 1);
    }

    // -------------------------------------------------------------------------
    // maxconnects default parity (C `Curl_cpool_conn_now_idle`, L564-570).
    // -------------------------------------------------------------------------

    #[test]
    fn idle_ceiling_default_is_running_times_four_capped() {
        // maxconnects == 0 ⇒ running * 4, saturating at u32::MAX (UINT_MAX).
        assert_eq!(idle_ceiling(0, 0), 0);
        assert_eq!(idle_ceiling(0, 1), 4);
        assert_eq!(idle_ceiling(0, 3), 12);
        // Exactly at the multiplication boundary: no overflow, no cap.
        assert_eq!(idle_ceiling(0, u32::MAX / 4), (u32::MAX / 4) * 4);
        // One past the boundary: cap to UINT_MAX rather than overflow.
        assert_eq!(idle_ceiling(0, u32::MAX / 4 + 1), u32::MAX);
    }

    #[test]
    fn idle_ceiling_explicit_value_wins() {
        // A non-zero maxconnects is used verbatim, ignoring `running`.
        assert_eq!(idle_ceiling(10, 0), 10);
        assert_eq!(idle_ceiling(10, 5), 10);
        assert_eq!(idle_ceiling(1, u32::MAX), 1);
    }

    #[test]
    fn conn_now_idle_evicts_oldest_when_over_default_ceiling() {
        // maxconnects == 0, running == 1 ⇒ ceiling 4. Five idle conns ⇒ over.
        let mut pool = ConnectionPool::new(0);
        for sec in 1..=5 {
            add(&mut pool, MockConn::new("a").idle_at(CurlTime::new(sec, 0)));
        }
        assert_eq!(pool.len(), 5);
        // Conn id 4 (lastused sec 5) just went idle; its lastused is bumped to
        // `now`, so the oldest (id 0, lastused sec 1) is evicted.
        let kept = pool.conn_now_idle(4, 0, 1, CurlTime::new(100, 0));
        assert!(kept, "the just-idled conn was kept; another was evicted");
        assert_eq!(pool.len(), 4);
        assert!(pool.get_conn(0).is_none(), "oldest idle (id 0) evicted");
        assert!(pool.get_conn(4).is_some(), "just-idled conn retained");
    }

    #[test]
    fn conn_now_idle_reports_not_kept_when_self_is_evicted() {
        // maxconnects 1 explicit. id 0 is in use (not evictable); id 1 is the
        // only idle conn ⇒ it is itself the one evicted ⇒ kept == false.
        let mut pool = ConnectionPool::new(0);
        add(&mut pool, MockConn::new("a").mark_in_use()); // id 0
        add(&mut pool, MockConn::new("a").idle_at(CurlTime::new(0, 0))); // id 1
        let kept = pool.conn_now_idle(1, 1, 0, CurlTime::new(10, 0));
        assert!(!kept, "the just-idled conn was the one evicted");
        assert_eq!(pool.len(), 1);
        assert!(pool.get_conn(0).is_some(), "in-use conn kept");
        assert!(pool.get_conn(1).is_none(), "idle conn id 1 evicted");
    }

    #[test]
    fn conn_now_idle_keeps_all_when_under_ceiling() {
        let mut pool = ConnectionPool::new(0);
        for _ in 0..3 {
            add(&mut pool, MockConn::new("a"));
        }
        // Explicit ceiling 10 ≫ 3 ⇒ nothing evicted.
        assert!(pool.conn_now_idle(0, 10, 0, CurlTime::new(10, 0)));
        assert_eq!(pool.len(), 3);
        // Default ceiling with running 0 ⇒ ceiling 0 ⇒ the `maxconnects != 0`
        // guard means no eviction even though num_conn > 0.
        assert!(pool.conn_now_idle(0, 0, 0, CurlTime::new(20, 0)));
        assert_eq!(pool.len(), 3);
    }

    // -------------------------------------------------------------------------
    // prune_dead cadence parity (C `Curl_cpool_prune_dead`, L718-737).
    // -------------------------------------------------------------------------

    #[test]
    fn prune_dead_runs_at_most_once_per_second() {
        let mut pool = ConnectionPool::new(0);
        add(&mut pool, MockConn::new("a").mark_dead()); // id 0, idle+dead
        add(&mut pool, MockConn::new("b").mark_dead()); // id 1, idle+dead

        // First prune at t = 10s (≥ 1s since last_cleanup == 0) ⇒ runs.
        pool.prune_dead(CurlTime::new(10, 0));
        assert_eq!(pool.len(), 0, "dead conns reaped on first prune");
        assert_eq!(pool.pending_discards(), 2);

        // A new dead conn, then a prune only 500 ms later ⇒ no-op (cadence).
        add(&mut pool, MockConn::new("c").mark_dead()); // id 2
        pool.prune_dead(CurlTime::new(10, 500_000));
        assert_eq!(pool.len(), 1, "within 1s ⇒ prune is a no-op");
        assert_eq!(
            pool.pending_discards(),
            2,
            "no new discards within the second"
        );

        // 2s after the last successful prune ⇒ runs again.
        pool.prune_dead(CurlTime::new(12, 0));
        assert_eq!(pool.len(), 0, "after ≥1s ⇒ prune runs");
        assert_eq!(pool.pending_discards(), 3);
    }

    #[test]
    fn prune_dead_skips_in_use_and_reaps_no_reuse() {
        let mut pool = ConnectionPool::new(0);
        // In-use + "dead": never reaped (seems_dead is false while in use).
        add(&mut pool, MockConn::new("a").mark_in_use().mark_dead()); // id 0
        pool.prune_dead(CurlTime::new(10, 0)); // runs (last_cleanup 0)
        assert_eq!(pool.len(), 1, "in-use conn never reaped");

        // Idle + no_reuse: reaped on the next (≥1s later) prune.
        add(&mut pool, MockConn::new("b").mark_no_reuse()); // id 1
        pool.prune_dead(CurlTime::new(11, 0));
        assert_eq!(pool.len(), 1, "only the no_reuse idle conn reaped");
        assert!(pool.get_conn(0).is_some(), "in-use conn still present");
        assert!(pool.get_conn(1).is_none(), "no_reuse idle conn reaped");
    }

    // -------------------------------------------------------------------------
    // find(): the BOUNDARY — cache only iterates + invokes callbacks; it never
    // implements the reuse-eligibility predicate (that is crate::url's job).
    // -------------------------------------------------------------------------

    #[test]
    fn find_iterates_in_order_and_stops_at_first_match() {
        let mut pool = ConnectionPool::new(0);
        add(&mut pool, MockConn::new("a")); // id 0
        add(&mut pool, MockConn::new("a")); // id 1
        add(&mut pool, MockConn::new("a")); // id 2

        let visited = RefCell::new(Vec::new());
        let matched = pool.find(
            "a",
            |c| {
                visited.borrow_mut().push(c.connection_id());
                c.connection_id() == 1 // the caller's predicate (BOUNDARY)
            },
            None::<fn(bool) -> bool>,
        );
        assert!(matched, "a match was found");
        assert_eq!(
            *visited.borrow(),
            vec![0, 1],
            "iterates in insertion order, stops right after the match"
        );
    }

    #[test]
    fn find_visits_all_when_no_match() {
        let mut pool = ConnectionPool::new(0);
        add(&mut pool, MockConn::new("a")); // id 0
        add(&mut pool, MockConn::new("a")); // id 1

        let visited = RefCell::new(Vec::new());
        let matched = pool.find(
            "a",
            |c| {
                visited.borrow_mut().push(c.connection_id());
                false // never matches
            },
            None::<fn(bool) -> bool>,
        );
        assert!(!matched);
        assert_eq!(
            *visited.borrow(),
            vec![0, 1],
            "every conn in the bundle visited"
        );
    }

    #[test]
    fn find_absent_bundle_returns_false_without_invoking_cb() {
        let pool = ConnectionPool::new(0);
        let mut calls = 0;
        let matched = pool.find(
            "nonexistent",
            |_c| {
                calls += 1;
                true
            },
            None::<fn(bool) -> bool>,
        );
        assert!(!matched);
        assert_eq!(calls, 0, "no bundle ⇒ the match callback is never called");
    }

    #[test]
    fn find_done_cb_post_processes_the_result() {
        let mut pool = ConnectionPool::new(0);
        add(&mut pool, MockConn::new("a"));
        // conn_cb never matches (result == false), but done_cb inverts it.
        let matched = pool.find("a", |_c| false, Some(|r: bool| !r));
        assert!(
            matched,
            "done_cb overrides the match result (the C done_cb)"
        );
    }

    // -------------------------------------------------------------------------
    // conn_terminate / nw_changed / upkeep / destroy / Drop.
    // -------------------------------------------------------------------------

    #[test]
    fn conn_terminate_respects_in_use_guard() {
        let mut pool = ConnectionPool::new(0);
        add(&mut pool, MockConn::new("a").mark_in_use()); // id 0
                                                          // In use and not aborted ⇒ not terminated (C L649-653).
        pool.conn_terminate(0, false);
        assert_eq!(pool.len(), 1, "in-use, non-aborted conn is retained");
        // Aborted ⇒ terminated even though in use.
        pool.conn_terminate(0, true);
        assert_eq!(pool.len(), 0, "aborted in-use conn is terminated");
        assert_eq!(pool.pending_discards(), 1);
    }

    #[test]
    fn nw_changed_marks_stale_and_reaps_idle() {
        let mut pool = ConnectionPool::new(0);
        add(&mut pool, MockConn::new("a").idle_at(CurlTime::new(0, 0))); // id 0, idle
        add(&mut pool, MockConn::new("a").mark_in_use()); // id 1, in use

        pool.nw_changed();
        // Idle conn reaped; in-use conn kept but flagged not-reusable.
        assert_eq!(pool.len(), 1);
        assert!(
            pool.get_conn(0).is_none(),
            "idle conn reaped on network change"
        );
        let kept = pool.get_conn(1).expect("in-use conn retained");
        assert!(kept.no_reuse(), "retained conn marked not-reusable");
        assert_eq!(pool.pending_discards(), 1);
    }

    #[test]
    fn upkeep_invokes_every_pooled_connection() {
        let mut pool = ConnectionPool::new(0);
        let c0 = MockConn::new("a");
        let c1 = MockConn::new("b");
        let h0 = c0.state_handle();
        let h1 = c1.state_handle();
        add(&mut pool, c0);
        add(&mut pool, c1);

        pool.upkeep().expect("upkeep is infallible here");
        assert_eq!(h0.lock().unwrap().upkeep_calls, 1);
        assert_eq!(h1.lock().unwrap().upkeep_calls, 1);
    }

    #[test]
    fn destroy_moves_every_connection_to_the_discard_queue() {
        let mut pool = ConnectionPool::new(0);
        add(&mut pool, MockConn::new("a"));
        add(&mut pool, MockConn::new("a"));
        add(&mut pool, MockConn::new("b"));

        pool.destroy();
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.bundle_count(), 0);
        assert_eq!(pool.pending_discards(), 3, "all conns queued for shutdown");
    }

    #[test]
    fn drop_force_closes_sockets_secondary_before_first() {
        let handle;
        {
            let mut pool = ConnectionPool::new(0);
            let conn = MockConn::new("a");
            handle = conn.state_handle();
            add(&mut pool, conn);
            // pool dropped here ⇒ Drop closes the pooled conn's sockets.
        }
        let closed = &handle.lock().unwrap().closed;
        assert_eq!(
            *closed,
            vec![SocketIndex::Secondary, SocketIndex::First],
            "Drop closes SECONDARYSOCKET before FIRSTSOCKET"
        );
    }

    // -------------------------------------------------------------------------
    // Shareability: Arc<Mutex<ConnectionPool>> usable across threads.
    // -------------------------------------------------------------------------

    #[test]
    fn shared_pool_is_usable_concurrently() {
        let pool = new_shared_pool(4);
        do_locked(&pool, |p| add(p, MockConn::new("a")));

        let pool2 = Arc::clone(&pool);
        let handle = std::thread::spawn(move || {
            do_locked(&pool2, |p| add(p, MockConn::new("b")));
        });
        handle.join().expect("worker thread panicked");

        let (len, bundles) = do_locked(&pool, |p| (p.len(), p.bundle_count()));
        assert_eq!(len, 2, "both threads' connections are present");
        assert_eq!(bundles, 2);
    }

    #[test]
    fn do_locked_returns_the_closure_value() {
        let pool = new_shared_pool(0);
        let id = do_locked(&pool, ConnectionPool::xfer_init);
        assert_eq!(id, 0);
        let id = do_locked(&pool, ConnectionPool::xfer_init);
        assert_eq!(id, 1);
    }
}
