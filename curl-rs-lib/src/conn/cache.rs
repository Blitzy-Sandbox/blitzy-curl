//! Connection pool with async-aware locking.
//!
//! Rust rewrite of `lib/conncache.c` (910 lines) — implements the connection
//! pool (`ConnectionPool`) that caches and reuses TCP/TLS connections across
//! transfers. Connections are grouped by destination (scheme://host:port) in
//! [`PoolBundle`] entries stored inside a [`HashMap`] for O(1) average lookup.
//!
//! # Architecture
//!
//! ```text
//! ConnectionPool
//!   ├── bundles: HashMap<String, PoolBundle>
//!   │     ├── "https://example.com:443" → PoolBundle { connections: [C1, C2] }
//!   │     └── "ftp://files.example.com:21" → PoolBundle { connections: [C3] }
//!   ├── shutdown: ShutdownManager   (graceful connection termination)
//!   └── limits: max_total, max_per_host
//! ```
//!
//! # Thread Safety
//!
//! When a connection pool is shared across multiple easy handles (via
//! `curl_share`), it is wrapped in [`SharedPool`] (`Arc<Mutex<ConnectionPool>>`)
//! matching the C `CPOOL_LOCK`/`CPOOL_UNLOCK` semantics.
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use tracing::{debug, info, trace, warn};

use crate::conn::connect::ConnectionData;
use crate::conn::shutdown::ShutdownManager;
use crate::error::{CurlError, CurlResult};

// ===========================================================================
// Constants
// ===========================================================================

/// Minimum interval between dead-connection pruning passes (1 second).
///
/// Matches the C constant: `if(elapsed >= 1000L)` in `Curl_cpool_prune_dead`.
const PRUNE_INTERVAL: Duration = Duration::from_secs(1);

// ===========================================================================
// Helper — destination key construction
// ===========================================================================

/// Builds the destination key used as the [`HashMap`] key for connection
/// bundles. The format is `scheme://host:port`, matching the C
/// `conn->destination` string used for bundle lookups.
fn make_dest_key(scheme: &str, host: &str, port: u16) -> String {
    format!("{}://{}:{}", scheme, host, port)
}

// ===========================================================================
// PoolLimitResult — connection limit check outcome
// ===========================================================================

/// Result of checking connection pool limits before adding a new connection.
///
/// Integer values match the C constants exactly:
/// - `CPOOL_LIMIT_OK = 0`
/// - `CPOOL_LIMIT_DEST = 1`
/// - `CPOOL_LIMIT_TOTAL = 2`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum PoolLimitResult {
    /// Connection allowed — pool has capacity.
    Ok = 0,
    /// Per-destination (per-host) limit has been reached.
    DestinationLimit = 1,
    /// Total pool-wide connection limit has been reached.
    TotalLimit = 2,
}

impl std::fmt::Display for PoolLimitResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "OK"),
            Self::DestinationLimit => write!(f, "destination limit reached"),
            Self::TotalLimit => write!(f, "total limit reached"),
        }
    }
}

// ===========================================================================
// PoolBundle — connections grouped by destination
// ===========================================================================

/// A group of connections to the same destination (scheme://host:port).
///
/// Replaces the C `struct cpool_bundle` which uses a linked list
/// (`Curl_llist`). The Rust version uses a `Vec<ConnectionData>` for
/// cache-friendly iteration and O(1) indexed access.
///
/// Bundles are created automatically when the first connection to a new
/// destination is added, and removed when the last connection in the bundle
/// is removed.
pub struct PoolBundle {
    /// Connections to this destination, ordered by insertion time.
    pub connections: Vec<ConnectionData>,
    /// Destination key: `scheme://host:port`.
    pub dest: String,
}

impl PoolBundle {
    /// Creates a new empty bundle for the given destination.
    fn new(dest: String) -> Self {
        Self {
            connections: Vec::new(),
            dest,
        }
    }

    /// Returns the number of connections in this bundle.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Returns `true` if this bundle has no connections.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Find the index and `conn_id` of the oldest idle connection in this
    /// bundle, measured by `last_used()` timestamp.
    ///
    /// Returns `None` if the bundle is empty.
    fn oldest_idle(&self) -> Option<(usize, u64)> {
        let mut oldest_idx: Option<usize> = None;
        let mut oldest_time: Option<Instant> = None;

        for (idx, conn) in self.connections.iter().enumerate() {
            let t = conn.last_used();
            if oldest_time.map_or(true, |prev| t < prev) {
                oldest_time = Some(t);
                oldest_idx = Some(idx);
            }
        }

        oldest_idx.map(|idx| (idx, self.connections[idx].conn_id()))
    }
}

impl std::fmt::Debug for PoolBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolBundle")
            .field("dest", &self.dest)
            .field("connections", &self.connections.len())
            .finish()
    }
}

// ===========================================================================
// ConnectionPool — the core connection cache
// ===========================================================================

/// Connection pool that caches and reuses TCP/TLS connections across
/// transfers.
///
/// Replaces the C `struct cpool` from `lib/conncache.c`. Connections are
/// grouped by destination in [`PoolBundle`] entries stored in a [`HashMap`]
/// for O(1) average lookup by destination key.
///
/// # Limits
///
/// Two configurable limits control pool size:
/// - `max_total` — maximum total connections across all destinations
///   (maps to `CURLMOPT_MAX_TOTAL_CONNECTIONS`). Zero means unlimited.
/// - `max_per_host` — maximum connections per destination host
///   (maps to `CURLMOPT_MAX_HOST_CONNECTIONS`). Zero means unlimited.
///
/// When limits are hit, the pool evicts the oldest idle connections to make
/// room for new ones.
///
/// # Shutdown Integration
///
/// The pool owns a [`ShutdownManager`] that handles graceful connection
/// teardown. When connections are removed from the pool (due to limits,
/// idle timeout, or network changes), they are transferred to the shutdown
/// manager for orderly close.
pub struct ConnectionPool {
    /// Connection bundles keyed by destination string (scheme://host:port).
    bundles: HashMap<String, PoolBundle>,

    /// Total number of pooled connections across all bundles.
    num_connections: usize,

    /// Monotonically increasing connection ID counter.
    next_connection_id: u64,

    /// Monotonically increasing easy handle / transfer ID counter.
    next_easy_id: u64,

    /// Monotonic timestamp of the last dead-connection pruning pass.
    last_cleanup: Instant,

    /// Maximum total connections across all destinations. Zero = no limit.
    max_total: usize,

    /// Maximum connections per destination host. Zero = no limit.
    max_per_host: usize,

    /// Whether the pool has been initialized and is ready for use.
    initialized: bool,

    /// Shutdown manager for graceful connection termination.
    shutdown: ShutdownManager,
}

impl ConnectionPool {
    // ====================================================================
    // Construction and Initialization
    // ====================================================================

    /// Creates a new connection pool with the specified limits.
    ///
    /// Both limits may be zero to indicate no limit. The pool is immediately
    /// ready for use after construction.
    ///
    /// Matches `Curl_cpool_init` from `lib/conncache.c`.
    pub fn new(max_total: usize, max_per_host: usize) -> Self {
        debug!(
            max_total = max_total,
            max_per_host = max_per_host,
            "[CPOOL] creating new connection pool"
        );
        Self {
            bundles: HashMap::new(),
            num_connections: 0,
            next_connection_id: 0,
            next_easy_id: 0,
            last_cleanup: Instant::now(),
            max_total,
            max_per_host,
            initialized: true,
            shutdown: ShutdownManager::new(),
        }
    }

    /// Re-initializes or reconfigures the pool with a new total limit.
    ///
    /// Preserves existing connections but updates the maximum total
    /// connections. This is called when the multi handle's
    /// `CURLMOPT_MAX_TOTAL_CONNECTIONS` is changed.
    pub fn init(&mut self, max_total: usize) {
        debug!(
            old_max = self.max_total,
            new_max = max_total,
            "[CPOOL] re-initializing pool limits"
        );
        self.max_total = max_total;
        if !self.initialized {
            self.bundles = HashMap::new();
            self.num_connections = 0;
            self.next_connection_id = 0;
            self.next_easy_id = 0;
            self.last_cleanup = Instant::now();
            self.shutdown = ShutdownManager::new();
            self.initialized = true;
        }
    }

    // ====================================================================
    // Destruction
    // ====================================================================

    /// Destroys the connection pool, closing all pooled connections.
    ///
    /// All connections are transferred to the internal [`ShutdownManager`]
    /// for orderly teardown, then the shutdown manager is destroyed
    /// (force-closing any remaining connections).
    ///
    /// After this call the pool is marked as uninitialized and must not be
    /// used for further operations.
    ///
    /// Matches `Curl_cpool_destroy` from `lib/conncache.c`.
    pub fn destroy(&mut self) {
        if !self.initialized {
            return;
        }

        info!(
            num_connections = self.num_connections,
            num_bundles = self.bundles.len(),
            "[CPOOL] destroying pool with {} connections",
            self.num_connections
        );

        // Drain all connections from every bundle and queue them for shutdown.
        let mut all_conns: Vec<ConnectionData> = Vec::with_capacity(self.num_connections);
        for bundle in self.bundles.values_mut() {
            all_conns.append(&mut bundle.connections);
        }
        self.bundles.clear();
        self.num_connections = 0;

        // Transfer ownership of each connection to the shutdown manager.
        for conn in all_conns {
            debug!(
                conn_id = conn.conn_id(),
                host = %conn.host(),
                "[CPOOL] queueing connection for shutdown"
            );
            let _ = self.shutdown.add(conn, false);
        }

        // Force-close everything remaining in the shutdown queue.
        self.shutdown.destroy();

        self.initialized = false;
        debug!("[CPOOL] pool destroyed");
    }

    // ====================================================================
    // Connection Addition
    // ====================================================================

    /// Adds a connection to the pool.
    ///
    /// The connection is placed into the bundle matching its destination
    /// key (`scheme://host:port`). If no bundle exists for that destination,
    /// one is created automatically. The pool's connection counter is
    /// incremented and the internal ID counter is updated.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::FailedInit`] if the pool is not initialized.
    ///
    /// Matches `Curl_cpool_add` from `lib/conncache.c`.
    pub fn add(&mut self, conn: ConnectionData) -> CurlResult<()> {
        if !self.initialized {
            warn!("[CPOOL] add called on uninitialized pool");
            return Err(CurlError::FailedInit);
        }

        let conn_id = conn.conn_id();
        let dest = make_dest_key(conn.scheme(), conn.host(), conn.port());

        // Update the ID counter to stay ahead of any externally assigned IDs.
        if conn_id >= self.next_connection_id {
            self.next_connection_id = conn_id.saturating_add(1);
        }

        // Find or create the destination bundle.
        let bundle = self.bundles.entry(dest.clone()).or_insert_with(|| {
            trace!(dest = %dest, "[CPOOL] creating new bundle");
            PoolBundle::new(dest.clone())
        });

        bundle.connections.push(conn);
        self.num_connections += 1;

        debug!(
            conn_id = conn_id,
            dest = %dest,
            pool_size = self.num_connections,
            "[CPOOL] added connection. Pool now contains {} members",
            self.num_connections
        );

        Ok(())
    }

    // ====================================================================
    // Limit Checking
    // ====================================================================

    /// Checks whether adding a connection to the pool would exceed limits.
    ///
    /// If limits are reached, the pool attempts to evict the oldest idle
    /// connection(s) to make room. If eviction does not free sufficient
    /// space, a limit result is returned indicating which limit was hit.
    ///
    /// # Returns
    ///
    /// - [`PoolLimitResult::Ok`] — capacity available
    /// - [`PoolLimitResult::DestinationLimit`] — per-host limit exceeded
    /// - [`PoolLimitResult::TotalLimit`] — total pool limit exceeded
    ///
    /// Matches `Curl_cpool_check_limits` from `lib/conncache.c`.
    pub fn check_limits(&mut self, conn: &ConnectionData) -> PoolLimitResult {
        if !self.initialized {
            return PoolLimitResult::Ok;
        }

        let dest_limit = self.max_per_host;
        let total_limit = self.max_total;

        // No limits configured — always OK.
        if dest_limit == 0 && total_limit == 0 {
            return PoolLimitResult::Ok;
        }

        let dest = make_dest_key(conn.scheme(), conn.host(), conn.port());

        // --- Per-destination limit ---
        if dest_limit > 0 {
            let live = self.bundles.get(&dest).map_or(0, |b| b.len());
            let shutdowns = self.shutdown.dest_count(&dest);

            if live + shutdowns >= dest_limit {
                let mut cur_live = live;
                let mut cur_shut = shutdowns;

                while cur_live + cur_shut >= dest_limit {
                    if cur_shut > 0 {
                        if !self.shutdown.close_oldest(Some(&dest)) {
                            break;
                        }
                    } else if let Some(evicted) = self.evict_from_dest(&dest) {
                        info!(
                            conn_id = evicted.conn_id(),
                            dest = %dest,
                            "[CPOOL] evicted connection for destination limit {}",
                            dest_limit
                        );
                        let _ = self.shutdown.add(evicted, false);
                    } else {
                        break;
                    }

                    cur_live = self.bundles.get(&dest).map_or(0, |b| b.len());
                    cur_shut = self.shutdown.dest_count(&dest);
                }

                if cur_live + cur_shut >= dest_limit {
                    debug!(
                        dest = %dest,
                        live = cur_live,
                        shutdowns = cur_shut,
                        limit = dest_limit,
                        "[CPOOL] destination limit reached"
                    );
                    return PoolLimitResult::DestinationLimit;
                }
            }
        }

        // --- Total pool limit ---
        if total_limit > 0 {
            let shutdowns = self.shutdown.len();

            if self.num_connections + shutdowns >= total_limit {
                let mut cur_total = self.num_connections;
                let mut cur_shut = shutdowns;

                while cur_total + cur_shut >= total_limit {
                    if cur_shut > 0 {
                        if !self.shutdown.close_oldest(None) {
                            break;
                        }
                    } else if let Some(evicted) = self.evict_oldest_idle(None) {
                        info!(
                            conn_id = evicted.conn_id(),
                            pool_size = self.num_connections,
                            "[CPOOL] evicted connection for total limit {}",
                            total_limit
                        );
                        let _ = self.shutdown.add(evicted, false);
                    } else {
                        break;
                    }

                    cur_total = self.num_connections;
                    cur_shut = self.shutdown.len();
                }

                if cur_total + cur_shut >= total_limit {
                    debug!(
                        total = cur_total,
                        shutdowns = cur_shut,
                        limit = total_limit,
                        "[CPOOL] total pool limit reached"
                    );
                    return PoolLimitResult::TotalLimit;
                }
            }
        }

        PoolLimitResult::Ok
    }

    // ====================================================================
    // Connection Lookup
    // ====================================================================

    /// Finds a connection by its unique connection ID.
    ///
    /// Searches across all bundles. Returns an immutable reference if found.
    ///
    /// Matches `Curl_cpool_get_conn` from `lib/conncache.c`.
    pub fn get_conn(&self, conn_id: u64) -> Option<&ConnectionData> {
        for bundle in self.bundles.values() {
            for conn in &bundle.connections {
                if conn.conn_id() == conn_id {
                    return Some(conn);
                }
            }
        }
        None
    }

    /// Searches for a connection in the bundle matching `dest` using the
    /// provided matcher closure.
    ///
    /// The `matcher` is called for each connection in the destination bundle
    /// until it returns `true` (indicating a match) or all connections have
    /// been checked. Returns `true` if a matching connection was found.
    ///
    /// Matches `Curl_cpool_find` from `lib/conncache.c`.
    pub fn find<F>(&self, dest: &str, mut matcher: F) -> bool
    where
        F: FnMut(&ConnectionData) -> bool,
    {
        if !self.initialized {
            return false;
        }

        if let Some(bundle) = self.bundles.get(dest) {
            trace!(
                dest = %dest,
                bundle_size = bundle.len(),
                "[CPOOL] searching bundle for match"
            );
            for conn in &bundle.connections {
                if matcher(conn) {
                    return true;
                }
            }
        }
        false
    }

    /// Finds a reusable connection for the given destination.
    ///
    /// A connection is reusable if `is_alive()` returns `true`. Among alive
    /// connections, the most recently used one is preferred (to promote
    /// temporal locality and warm TLS sessions).
    ///
    /// Returns an immutable reference to the best reusable connection, or
    /// `None` if no suitable connection exists.
    pub fn find_reusable(&self, dest: &str) -> Option<&ConnectionData> {
        if !self.initialized {
            return None;
        }

        let bundle = self.bundles.get(dest)?;

        let mut best: Option<&ConnectionData> = None;
        let mut best_time: Option<Instant> = None;

        for conn in &bundle.connections {
            if !conn.is_alive() {
                continue;
            }
            let t = conn.last_used();
            // Prefer the most recently used (latest last_used).
            if best_time.map_or(true, |prev| t > prev) {
                best_time = Some(t);
                best = Some(conn);
            }
        }

        if let Some(found) = best {
            trace!(
                conn_id = found.conn_id(),
                dest = %dest,
                "[CPOOL] found reusable connection"
            );
        }

        best
    }

    // ====================================================================
    // Connection Removal
    // ====================================================================

    /// Removes a connection from the pool by its connection ID.
    ///
    /// If the connection is found, it is removed from its bundle and
    /// returned with full ownership. If the bundle becomes empty after
    /// removal, it is also cleaned up from the map.
    ///
    /// Returns `None` if no connection with the given ID exists in the pool.
    pub fn remove(&mut self, conn_id: u64) -> Option<ConnectionData> {
        // Locate the bundle and index of the target connection.
        let mut target_dest: Option<String> = None;
        let mut target_idx: Option<usize> = None;

        for (dest, bundle) in self.bundles.iter() {
            for (idx, conn) in bundle.connections.iter().enumerate() {
                if conn.conn_id() == conn_id {
                    target_dest = Some(dest.clone());
                    target_idx = Some(idx);
                    break;
                }
            }
            if target_dest.is_some() {
                break;
            }
        }

        if let (Some(dest), Some(idx)) = (target_dest, target_idx) {
            let bundle = self.bundles.get_mut(&dest)?;
            let conn = bundle.connections.remove(idx);
            self.num_connections -= 1;

            debug!(
                conn_id = conn_id,
                dest = %dest,
                pool_size = self.num_connections,
                "[CPOOL] removed connection"
            );

            // Remove empty bundle.
            if bundle.is_empty() {
                self.bundles.remove(&dest);
                trace!(dest = %dest, "[CPOOL] removed empty bundle");
            }

            return Some(conn);
        }

        None
    }

    // ====================================================================
    // Idle Connection Management
    // ====================================================================

    /// Cleans up connections that have been idle longer than the specified
    /// timeout.
    ///
    /// Iterates all bundles and removes connections whose idle duration
    /// exceeds `idle_timeout`. Removed connections are transferred to the
    /// shutdown manager for graceful close.
    ///
    /// Returns the number of connections cleaned up.
    pub fn cleanup_idle(&mut self, now: Instant, idle_timeout: Duration) -> usize {
        if !self.initialized || self.num_connections == 0 {
            return 0;
        }

        // Collect IDs of idle connections that exceed the timeout.
        let mut expired_ids: Vec<u64> = Vec::new();

        for bundle in self.bundles.values() {
            for conn in &bundle.connections {
                let idle_duration = now.duration_since(conn.last_used());
                if idle_duration >= idle_timeout {
                    expired_ids.push(conn.conn_id());
                }
            }
        }

        if expired_ids.is_empty() {
            return 0;
        }

        let count = expired_ids.len();
        info!(
            count = count,
            idle_timeout_ms = idle_timeout.as_millis() as u64,
            "[CPOOL] cleaning up {} idle connections",
            count
        );

        for id in &expired_ids {
            if let Some(conn) = self.remove(*id) {
                debug!(conn_id = conn.conn_id(), "[CPOOL] idle connection cleaned");
                let _ = self.shutdown.add(conn, false);
            }
        }

        self.last_cleanup = now;
        count
    }

    /// Evicts and returns the oldest idle connection from the pool.
    ///
    /// If `dest` is provided, only connections from that destination bundle
    /// are considered. Otherwise, the oldest connection across all bundles
    /// is selected.
    ///
    /// The "oldest" connection is the one with the earliest `last_used()`
    /// timestamp. This is used when the pool is full and a new connection
    /// needs space.
    pub fn evict_oldest_idle(&mut self, dest: Option<&str>) -> Option<ConnectionData> {
        let oldest_id = self.find_oldest_idle_id(dest)?;
        self.remove(oldest_id)
    }

    // ====================================================================
    // Dead Connection Pruning
    // ====================================================================

    /// Scans for half-open or dead connections, removes and shuts them down.
    ///
    /// The scan is rate-limited to at most once per second (matching the C
    /// implementation's `if(elapsed >= 1000L)` check). A connection is
    /// considered dead if `is_alive()` returns `false`.
    ///
    /// Matches `Curl_cpool_prune_dead` from `lib/conncache.c`.
    pub fn prune_dead(&mut self) {
        if !self.initialized || self.num_connections == 0 {
            return;
        }

        // Rate-limit pruning to once per second.
        if self.last_cleanup.elapsed() < PRUNE_INTERVAL {
            return;
        }

        let mut dead_ids: Vec<u64> = Vec::new();
        let mut checked: usize = 0;

        for bundle in self.bundles.values() {
            for conn in &bundle.connections {
                checked += 1;
                if !conn.is_alive() {
                    dead_ids.push(conn.conn_id());
                }
            }
        }

        if !dead_ids.is_empty() {
            debug!(
                checked = checked,
                dead = dead_ids.len(),
                "[CPOOL] pruning {} dead connections out of {} checked",
                dead_ids.len(),
                checked
            );
        }

        for id in &dead_ids {
            if let Some(conn) = self.remove(*id) {
                let _ = self.shutdown.add(conn, false);
            }
        }

        self.last_cleanup = Instant::now();
    }

    // ====================================================================
    // Upkeep
    // ====================================================================

    /// Performs upkeep actions on all pooled connections.
    ///
    /// Sends keepalive probes to all connections via their filter chains.
    /// This helps detect dead connections early and maintain firewall/NAT
    /// state.
    ///
    /// Matches `Curl_cpool_upkeep` from `lib/conncache.c`.
    pub fn upkeep(&self) -> CurlResult<()> {
        if !self.initialized {
            return Ok(());
        }

        trace!(
            num_connections = self.num_connections,
            "[CPOOL] performing upkeep on all connections"
        );

        for bundle in self.bundles.values() {
            for conn in &bundle.connections {
                if let Err(e) = conn.keep_alive() {
                    warn!(
                        conn_id = conn.conn_id(),
                        error = %e,
                        "[CPOOL] keepalive failed"
                    );
                }
            }
        }

        Ok(())
    }

    // ====================================================================
    // Connection Idle Notification
    // ====================================================================

    /// Handles a connection (already in the pool) becoming idle.
    ///
    /// Updates the connection's `last_used` timestamp and enforces pool
    /// capacity limits. If the pool is over capacity, the oldest idle
    /// connection is evicted.
    ///
    /// Returns `true` if the specified connection was kept in the pool,
    /// `false` if it was evicted (i.e., it was the oldest idle connection).
    ///
    /// Matches `Curl_cpool_conn_now_idle` from `lib/conncache.c`.
    pub fn conn_now_idle(&mut self, conn_id: u64) -> bool {
        // Touch the connection to update its last_used timestamp.
        if let Some(conn) = self.get_conn_mut(conn_id) {
            conn.touch();
        }

        // Determine effective max connections for the cache.
        let maxconnects = if self.max_total > 0 {
            self.max_total
        } else {
            // No limit configured — connection is always kept.
            return true;
        };

        if self.num_connections <= maxconnects {
            return true;
        }

        // Pool is over capacity — evict the oldest idle connection.
        info!(
            pool_size = self.num_connections,
            limit = maxconnects,
            "[CPOOL] pool is full, closing the oldest of {}/{}",
            self.num_connections,
            maxconnects
        );

        if let Some(oldest_id) = self.find_oldest_idle_id(None) {
            let kept = oldest_id != conn_id;
            if let Some(evicted) = self.remove(oldest_id) {
                let _ = self.shutdown.add(evicted, false);
            }
            return kept;
        }

        // Could not evict anything — keep the connection.
        true
    }

    // ====================================================================
    // Network Change Handling
    // ====================================================================

    /// Handles a network change by closing all pooled connections.
    ///
    /// When the network changes (e.g., IP address change, VPN toggle),
    /// all existing connections become potentially stale. This method closes
    /// all connections and transfers them to the shutdown manager.
    ///
    /// Matches `Curl_cpool_nw_changed` from `lib/conncache.c`.
    pub fn network_changed(&mut self) {
        if !self.initialized || self.num_connections == 0 {
            return;
        }

        info!(
            pool_size = self.num_connections,
            "[CPOOL] network changed, closing all {} pooled connections",
            self.num_connections
        );

        // Collect all connection IDs — close all of them.
        let all_ids: Vec<u64> = self
            .bundles
            .values()
            .flat_map(|b| b.connections.iter())
            .map(|c| c.conn_id())
            .collect();

        for id in &all_ids {
            if let Some(conn) = self.remove(*id) {
                let _ = self.shutdown.add(conn, false);
            }
        }
    }

    // ====================================================================
    // Transfer ID Assignment
    // ====================================================================

    /// Assigns a unique transfer (easy handle) ID from the pool's counter.
    ///
    /// The returned ID is monotonically increasing and unique within the
    /// lifetime of this pool. Called during `curl_multi_add_handle` to
    /// assign `data->id`.
    ///
    /// Matches `Curl_cpool_xfer_init` from `lib/conncache.c`.
    pub fn assign_transfer_id(&mut self) -> u64 {
        let id = self.next_easy_id;
        self.next_easy_id = self.next_easy_id.wrapping_add(1);
        debug!(transfer_id = id, "[CPOOL] assigned transfer ID");
        id
    }

    // ====================================================================
    // Pool Statistics
    // ====================================================================

    /// Returns the total number of connections in the pool.
    pub fn len(&self) -> usize {
        self.num_connections
    }

    /// Returns `true` if the pool contains no connections.
    pub fn is_empty(&self) -> bool {
        self.num_connections == 0
    }

    // ====================================================================
    // Shutdown Manager Access
    // ====================================================================

    /// Returns a mutable reference to the pool's shutdown manager.
    ///
    /// The shutdown manager can be used by the owning multi handle to:
    /// - Run `perform()` to advance graceful shutdowns on each event-loop
    ///   iteration
    /// - Call `terminate_all().await` for graceful pool teardown before
    ///   `destroy()`
    pub fn shutdown_manager(&mut self) -> &mut ShutdownManager {
        &mut self.shutdown
    }

    // ====================================================================
    // Private Helpers
    // ====================================================================

    /// Returns a mutable reference to a connection by its ID.
    fn get_conn_mut(&mut self, conn_id: u64) -> Option<&mut ConnectionData> {
        for bundle in self.bundles.values_mut() {
            for conn in &mut bundle.connections {
                if conn.conn_id() == conn_id {
                    return Some(conn);
                }
            }
        }
        None
    }

    /// Finds the `conn_id` of the oldest idle connection.
    ///
    /// If `dest` is `Some`, restricts search to that destination's bundle.
    /// If `None`, searches across all bundles.
    fn find_oldest_idle_id(&self, dest: Option<&str>) -> Option<u64> {
        let mut oldest_id: Option<u64> = None;
        let mut oldest_time: Option<Instant> = None;

        match dest {
            Some(d) => {
                if let Some(bundle) = self.bundles.get(d) {
                    for conn in &bundle.connections {
                        let t = conn.last_used();
                        if oldest_time.map_or(true, |prev| t < prev) {
                            oldest_time = Some(t);
                            oldest_id = Some(conn.conn_id());
                        }
                    }
                }
            }
            None => {
                for bundle in self.bundles.values() {
                    for conn in &bundle.connections {
                        let t = conn.last_used();
                        if oldest_time.map_or(true, |prev| t < prev) {
                            oldest_time = Some(t);
                            oldest_id = Some(conn.conn_id());
                        }
                    }
                }
            }
        }

        oldest_id
    }

    /// Evicts the oldest idle connection from a specific destination bundle.
    fn evict_from_dest(&mut self, dest: &str) -> Option<ConnectionData> {
        let oldest = {
            let bundle = self.bundles.get(dest)?;
            bundle.oldest_idle()
        };

        if let Some((_idx, conn_id)) = oldest {
            return self.remove(conn_id);
        }

        None
    }
}

impl Drop for ConnectionPool {
    fn drop(&mut self) {
        if self.initialized && self.num_connections > 0 {
            debug!(
                num_connections = self.num_connections,
                "[CPOOL] dropping pool with {} remaining connections",
                self.num_connections
            );
            self.destroy();
        }
    }
}

impl std::fmt::Debug for ConnectionPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionPool")
            .field("num_connections", &self.num_connections)
            .field("num_bundles", &self.bundles.len())
            .field("max_total", &self.max_total)
            .field("max_per_host", &self.max_per_host)
            .field("next_connection_id", &self.next_connection_id)
            .field("next_easy_id", &self.next_easy_id)
            .field("initialized", &self.initialized)
            .finish()
    }
}

// ===========================================================================
// SharedPool — thread-safe shared connection pool
// ===========================================================================

/// Thread-safe wrapper for sharing a [`ConnectionPool`] across multiple
/// easy handles.
///
/// Uses `Arc<Mutex<ConnectionPool>>` to match the C `CPOOL_LOCK` /
/// `CPOOL_UNLOCK` semantics. When a pool is shared via `curl_share`, all
/// operations on the pool go through this wrapper for mutual exclusion.
///
/// # Poisoned Mutex Recovery
///
/// If a thread panics while holding the pool lock, the mutex becomes
/// "poisoned". `SharedPool` recovers from poisoning by extracting the
/// inner pool data, matching the resilient behavior expected of a
/// network library.
#[derive(Clone)]
pub struct SharedPool {
    inner: Arc<Mutex<ConnectionPool>>,
}

impl SharedPool {
    /// Creates a new [`SharedPool`] wrapping the given connection pool.
    ///
    /// The pool is moved into an `Arc<Mutex<>>` for shared, thread-safe
    /// access.
    pub fn new(pool: ConnectionPool) -> Self {
        Self {
            inner: Arc::new(Mutex::new(pool)),
        }
    }

    /// Acquires an exclusive lock on the connection pool.
    ///
    /// Returns a [`MutexGuard`] providing mutable access to the underlying
    /// [`ConnectionPool`]. The lock is released when the guard is dropped.
    ///
    /// If the mutex has been poisoned (a thread panicked while holding the
    /// lock), the pool data is recovered and a warning is logged.
    pub fn lock(&self) -> MutexGuard<'_, ConnectionPool> {
        self.inner.lock().unwrap_or_else(|poisoned| {
            warn!("[CPOOL] shared pool mutex was poisoned, recovering");
            poisoned.into_inner()
        })
    }
}

impl std::fmt::Debug for SharedPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedPool")
            .field("arc_strong_count", &Arc::strong_count(&self.inner))
            .finish()
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test ConnectionData with the given parameters.
    fn test_conn(id: u64, scheme: &str, host: &str, port: u16) -> ConnectionData {
        ConnectionData::new(id, host.to_owned(), port, scheme.to_owned())
    }

    #[test]
    fn test_make_dest_key() {
        assert_eq!(
            make_dest_key("https", "example.com", 443),
            "https://example.com:443"
        );
        assert_eq!(
            make_dest_key("ftp", "files.host.org", 21),
            "ftp://files.host.org:21"
        );
        assert_eq!(
            make_dest_key("http", "localhost", 8080),
            "http://localhost:8080"
        );
    }

    #[test]
    fn test_pool_limit_result_values() {
        assert_eq!(PoolLimitResult::Ok as i32, 0);
        assert_eq!(PoolLimitResult::DestinationLimit as i32, 1);
        assert_eq!(PoolLimitResult::TotalLimit as i32, 2);
    }

    #[test]
    fn test_new_pool_is_empty() {
        let pool = ConnectionPool::new(10, 5);
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_add_and_get_conn() {
        let mut pool = ConnectionPool::new(10, 5);
        let conn = test_conn(1, "https", "example.com", 443);

        pool.add(conn).unwrap();
        assert_eq!(pool.len(), 1);
        assert!(!pool.is_empty());

        let found = pool.get_conn(1);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.conn_id(), 1);
        assert_eq!(found.host(), "example.com");
    }

    #[test]
    fn test_add_multiple_same_dest() {
        let mut pool = ConnectionPool::new(10, 5);

        pool.add(test_conn(1, "https", "example.com", 443)).unwrap();
        pool.add(test_conn(2, "https", "example.com", 443)).unwrap();
        pool.add(test_conn(3, "https", "example.com", 443)).unwrap();

        assert_eq!(pool.len(), 3);
        let dest = make_dest_key("https", "example.com", 443);
        assert!(pool.bundles.contains_key(&dest));
        assert_eq!(pool.bundles.get(&dest).unwrap().len(), 3);
    }

    #[test]
    fn test_add_different_destinations() {
        let mut pool = ConnectionPool::new(10, 5);

        pool.add(test_conn(1, "https", "example.com", 443)).unwrap();
        pool.add(test_conn(2, "ftp", "files.example.com", 21)).unwrap();

        assert_eq!(pool.len(), 2);
        assert_eq!(pool.bundles.len(), 2);
    }

    #[test]
    fn test_remove_connection() {
        let mut pool = ConnectionPool::new(10, 5);

        pool.add(test_conn(1, "https", "example.com", 443)).unwrap();
        pool.add(test_conn(2, "https", "example.com", 443)).unwrap();

        let removed = pool.remove(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().conn_id(), 1);
        assert_eq!(pool.len(), 1);

        assert!(pool.get_conn(1).is_none());
        assert!(pool.get_conn(2).is_some());
    }

    #[test]
    fn test_remove_last_in_bundle_removes_bundle() {
        let mut pool = ConnectionPool::new(10, 5);
        let dest = make_dest_key("https", "example.com", 443);

        pool.add(test_conn(1, "https", "example.com", 443)).unwrap();
        assert!(pool.bundles.contains_key(&dest));

        pool.remove(1);
        assert!(!pool.bundles.contains_key(&dest));
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut pool = ConnectionPool::new(10, 5);
        assert!(pool.remove(999).is_none());
    }

    #[test]
    fn test_find_matcher() {
        let mut pool = ConnectionPool::new(10, 5);
        let dest = make_dest_key("https", "example.com", 443);

        pool.add(test_conn(1, "https", "example.com", 443)).unwrap();
        pool.add(test_conn(2, "https", "example.com", 443)).unwrap();

        let found = pool.find(&dest, |c| c.conn_id() == 2);
        assert!(found);

        let found = pool.find(&dest, |c| c.conn_id() == 999);
        assert!(!found);
    }

    #[test]
    fn test_check_limits_ok() {
        let mut pool = ConnectionPool::new(10, 5);
        let conn = test_conn(1, "https", "example.com", 443);
        assert_eq!(pool.check_limits(&conn), PoolLimitResult::Ok);
    }

    #[test]
    fn test_check_limits_no_limits() {
        let mut pool = ConnectionPool::new(0, 0);
        let conn = test_conn(1, "https", "example.com", 443);
        pool.add(test_conn(0, "https", "example.com", 443)).unwrap();
        assert_eq!(pool.check_limits(&conn), PoolLimitResult::Ok);
    }

    #[test]
    fn test_assign_transfer_id() {
        let mut pool = ConnectionPool::new(10, 5);
        assert_eq!(pool.assign_transfer_id(), 0);
        assert_eq!(pool.assign_transfer_id(), 1);
        assert_eq!(pool.assign_transfer_id(), 2);
    }

    #[test]
    fn test_destroy_clears_pool() {
        let mut pool = ConnectionPool::new(10, 5);

        pool.add(test_conn(1, "https", "example.com", 443)).unwrap();
        pool.add(test_conn(2, "ftp", "files.example.com", 21)).unwrap();
        assert_eq!(pool.len(), 2);

        pool.destroy();
        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());
    }

    #[test]
    fn test_conn_now_idle_keeps_under_limit() {
        let mut pool = ConnectionPool::new(10, 5);
        pool.add(test_conn(1, "https", "example.com", 443)).unwrap();
        assert!(pool.conn_now_idle(1));
    }

    #[test]
    fn test_init_reinitializes() {
        let mut pool = ConnectionPool::new(5, 2);
        pool.add(test_conn(1, "https", "example.com", 443)).unwrap();

        pool.init(20);
        assert_eq!(pool.max_total, 20);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_pool_bundle_len_is_empty() {
        let bundle = PoolBundle::new("https://example.com:443".to_owned());
        assert!(bundle.is_empty());
        assert_eq!(bundle.len(), 0);
    }

    #[test]
    fn test_shared_pool_lock() {
        let pool = ConnectionPool::new(10, 5);
        let shared = SharedPool::new(pool);

        {
            let mut guard = shared.lock();
            guard
                .add(test_conn(1, "https", "example.com", 443))
                .unwrap();
            assert_eq!(guard.len(), 1);
        }

        let shared2 = shared.clone();
        let guard2 = shared2.lock();
        assert_eq!(guard2.len(), 1);
    }

    #[test]
    fn test_cleanup_idle_removes_old_connections() {
        let mut pool = ConnectionPool::new(10, 5);
        pool.add(test_conn(1, "https", "example.com", 443)).unwrap();
        pool.add(test_conn(2, "https", "example.com", 443)).unwrap();

        // With zero timeout, all connections should be cleaned up.
        let removed = pool.cleanup_idle(Instant::now(), Duration::from_millis(0));
        assert_eq!(removed, 2);
        assert!(pool.is_empty());
    }

    #[test]
    fn test_cleanup_idle_preserves_fresh_connections() {
        let mut pool = ConnectionPool::new(10, 5);
        pool.add(test_conn(1, "https", "example.com", 443)).unwrap();

        // With a long timeout, no connections should be cleaned up.
        let removed = pool.cleanup_idle(Instant::now(), Duration::from_secs(3600));
        assert_eq!(removed, 0);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_evict_oldest_idle_all_bundles() {
        let mut pool = ConnectionPool::new(10, 5);

        pool.add(test_conn(1, "https", "example.com", 443)).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        pool.add(test_conn(2, "https", "other.com", 443)).unwrap();

        let evicted = pool.evict_oldest_idle(None);
        assert!(evicted.is_some());
        assert_eq!(evicted.unwrap().conn_id(), 1);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_evict_oldest_idle_specific_dest() {
        let mut pool = ConnectionPool::new(10, 5);
        let dest = make_dest_key("https", "example.com", 443);

        pool.add(test_conn(1, "https", "example.com", 443)).unwrap();
        pool.add(test_conn(2, "https", "other.com", 443)).unwrap();

        let evicted = pool.evict_oldest_idle(Some(&dest));
        assert!(evicted.is_some());
        assert_eq!(evicted.unwrap().conn_id(), 1);
        assert!(pool.get_conn(2).is_some());
    }

    #[test]
    fn test_network_changed_closes_all() {
        let mut pool = ConnectionPool::new(10, 5);

        pool.add(test_conn(1, "https", "example.com", 443)).unwrap();
        pool.add(test_conn(2, "ftp", "files.example.com", 21)).unwrap();
        pool.add(test_conn(3, "https", "other.com", 443)).unwrap();
        assert_eq!(pool.len(), 3);

        pool.network_changed();
        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());
    }

    #[test]
    fn test_add_to_uninitialized_pool_fails() {
        let mut pool = ConnectionPool::new(10, 5);
        pool.destroy();

        let conn = test_conn(1, "https", "example.com", 443);
        let result = pool.add(conn);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::FailedInit);
    }

    #[test]
    fn test_debug_format() {
        let pool = ConnectionPool::new(10, 5);
        let debug_str = format!("{:?}", pool);
        assert!(debug_str.contains("ConnectionPool"));
        assert!(debug_str.contains("max_total"));

        let bundle = PoolBundle::new("test".to_owned());
        let debug_str = format!("{:?}", bundle);
        assert!(debug_str.contains("PoolBundle"));

        let shared = SharedPool::new(ConnectionPool::new(1, 1));
        let debug_str = format!("{:?}", shared);
        assert!(debug_str.contains("SharedPool"));
    }

    #[test]
    fn test_find_reusable_empty_bundle() {
        let pool = ConnectionPool::new(10, 5);
        assert!(pool.find_reusable("https://example.com:443").is_none());
    }

    #[test]
    fn test_upkeep_empty_pool() {
        let pool = ConnectionPool::new(10, 5);
        assert!(pool.upkeep().is_ok());
    }

    #[test]
    fn test_prune_dead_rate_limited() {
        let mut pool = ConnectionPool::new(10, 5);
        pool.add(test_conn(1, "https", "example.com", 443)).unwrap();

        // First call should update last_cleanup.
        pool.last_cleanup = Instant::now() - Duration::from_secs(2);
        pool.prune_dead();

        // Second immediate call should be rate-limited (no-op).
        let before = pool.len();
        pool.prune_dead();
        assert_eq!(pool.len(), before);
    }

    #[test]
    fn test_conn_now_idle_no_limit() {
        let mut pool = ConnectionPool::new(0, 0);
        pool.add(test_conn(1, "https", "example.com", 443)).unwrap();
        // With no limit, connection is always kept.
        assert!(pool.conn_now_idle(1));
    }

    #[test]
    fn test_multiple_operations_sequence() {
        let mut pool = ConnectionPool::new(5, 3);

        // Add connections.
        pool.add(test_conn(10, "https", "a.com", 443)).unwrap();
        pool.add(test_conn(11, "https", "a.com", 443)).unwrap();
        pool.add(test_conn(12, "https", "b.com", 443)).unwrap();
        assert_eq!(pool.len(), 3);
        assert_eq!(pool.bundles.len(), 2);

        // Find by matcher.
        let dest_a = make_dest_key("https", "a.com", 443);
        assert!(pool.find(&dest_a, |c| c.conn_id() == 11));

        // Remove one.
        let removed = pool.remove(10);
        assert!(removed.is_some());
        assert_eq!(pool.len(), 2);

        // Add more.
        pool.add(test_conn(13, "https", "c.com", 443)).unwrap();
        assert_eq!(pool.len(), 3);
        assert_eq!(pool.bundles.len(), 3);

        // Network change clears all.
        pool.network_changed();
        assert!(pool.is_empty());
        assert_eq!(pool.bundles.len(), 0);
    }

    #[test]
    fn test_next_connection_id_tracks_max() {
        let mut pool = ConnectionPool::new(10, 5);

        pool.add(test_conn(100, "https", "a.com", 443)).unwrap();
        assert!(pool.next_connection_id > 100);

        pool.add(test_conn(50, "https", "b.com", 443)).unwrap();
        // next_connection_id should still be > 100.
        assert!(pool.next_connection_id > 100);
    }

    #[test]
    fn test_shared_pool_across_threads() {
        use std::thread;

        let pool = ConnectionPool::new(100, 10);
        let shared = SharedPool::new(pool);

        let shared_clone = shared.clone();
        let handle = thread::spawn(move || {
            let mut guard = shared_clone.lock();
            guard
                .add(test_conn(42, "https", "thread.com", 443))
                .unwrap();
        });

        handle.join().unwrap();

        let guard = shared.lock();
        assert_eq!(guard.len(), 1);
        assert!(guard.get_conn(42).is_some());
    }
}
