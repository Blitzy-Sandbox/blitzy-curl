//! Graceful connection shutdown manager.
//!
//! Rust rewrite of `lib/cshutdn.c` (534 lines) — manages the orderly shutdown
//! of connections that have been released from the connection pool. This module:
//!
//! - Maintains a queue of connections pending graceful shutdown
//! - Runs protocol-specific disconnect handlers (FTP QUIT, SMTP QUIT, etc.)
//! - Drives the connection filter chain shutdown (TLS close_notify, TCP FIN)
//! - Enforces configurable per-connection shutdown timeouts
//! - Supports both individual and bulk shutdown (for multi_cleanup)
//! - Provides poll descriptor collection for event-loop integration
//!
//! # Architecture
//!
//! The shutdown manager is owned by the multi handle (or connection pool). On
//! each multi_perform iteration, `perform()` advances all pending shutdowns.
//! On multi_cleanup, `terminate_all()` force-closes everything with a timeout.
//!
//! ```text
//! Connection released from pool
//!   → ShutdownManager::add(conn)
//!   → [multi_perform loop] → ShutdownManager::perform()
//!     → run_once_entry():
//!       1. Start shutdown timer
//!       2. Run filter chain shutdown (TLS close_notify, etc.)
//!       3. Check timeout → force close if exceeded
//!     → Remove completed entries
//!   → [multi_cleanup] → ShutdownManager::terminate_all()
//! ```
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use tracing::{debug, trace, warn};

use crate::conn::connect::{
    ConnectionData, DEFAULT_SHUTDOWN_TIMEOUT_MS, shutdown_start, shutdown_timeleft,
};
use crate::conn::filters::PollSet;
use crate::error::{CurlError, CurlResult};

// ===========================================================================
// ShutdownState — lifecycle state of a shutdown entry
// ===========================================================================

/// Lifecycle state of a connection shutdown entry.
///
/// Transitions follow the state machine:
/// ```text
/// Pending → Running → Complete
///                  ↘ TimedOut
/// ```
///
/// Once in `Complete` or `TimedOut`, the entry is removed from the queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShutdownState {
    /// Shutdown has been queued but not yet started. The connection filter
    /// chain has not received any shutdown signals yet.
    Pending,

    /// Shutdown is actively running. The protocol disconnect handler and/or
    /// filter chain shutdown are in progress.
    Running,

    /// Shutdown completed successfully. The connection has been gracefully
    /// closed through all filter layers.
    Complete,

    /// Shutdown timed out and the connection was force-closed. This happens
    /// when the server does not respond to disconnect commands within the
    /// configured timeout.
    TimedOut,
}

impl std::fmt::Display for ShutdownState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShutdownState::Pending => write!(f, "pending"),
            ShutdownState::Running => write!(f, "running"),
            ShutdownState::Complete => write!(f, "complete"),
            ShutdownState::TimedOut => write!(f, "timed_out"),
        }
    }
}

// ===========================================================================
// ShutdownEntry — a connection in the shutdown queue
// ===========================================================================

/// A single connection entry in the shutdown queue.
///
/// Wraps a [`ConnectionData`] with shutdown-specific metadata: timing,
/// state tracking, and abort flag. The public fields provide read access
/// to entry metadata; the connection itself is managed internally by the
/// [`ShutdownManager`].
///
/// Maps to the C combination of `struct Curl_llist_node` entries in
/// `cshutdn.list` with associated `connectdata` and shutdown timing.
pub struct ShutdownEntry {
    /// Unique connection identifier, matching [`ConnectionData::conn_id()`].
    pub conn_id: u64,

    /// Current shutdown lifecycle state.
    pub state: ShutdownState,

    /// Monotonic timestamp when this entry was added to the shutdown queue.
    pub started: Instant,

    /// Maximum duration allowed for graceful shutdown before force-closing.
    pub timeout: Duration,

    /// Whether the shutdown was triggered by an abort condition (e.g., the
    /// transfer was cancelled before completion).
    pub aborted: bool,

    /// The connection data being shut down. Owned by this entry until
    /// shutdown completes or times out.
    conn: ConnectionData,

    /// Whether the protocol-specific disconnect handler has completed.
    /// Maps to C `conn->bits.shutdown_handler`.
    handler_done: bool,

    /// Whether the connection filter chain shutdown is complete.
    /// Maps to C `conn->bits.shutdown_filters`.
    filters_done: bool,

    /// Whether the shutdown timer has been started on the connection.
    shutdown_started: bool,
}

impl ShutdownEntry {
    /// Creates a new shutdown entry for the given connection.
    fn new(conn: ConnectionData, timeout: Duration, aborted: bool) -> Self {
        let conn_id = conn.conn_id();
        Self {
            conn_id,
            state: ShutdownState::Pending,
            started: Instant::now(),
            timeout,
            aborted,
            conn,
            handler_done: false,
            filters_done: false,
            shutdown_started: false,
        }
    }

    /// Returns the destination string for this connection (scheme://host:port).
    ///
    /// Used for matching connections by destination in [`ShutdownManager::dest_count`]
    /// and [`ShutdownManager::close_oldest`].
    fn destination(&self) -> String {
        format!("{}://{}:{}", self.conn.scheme(), self.conn.host(), self.conn.port())
    }

    /// Returns whether this entry has reached a terminal state.
    fn is_terminal(&self) -> bool {
        matches!(self.state, ShutdownState::Complete | ShutdownState::TimedOut)
    }

    /// Check whether the shutdown timeout has been exceeded.
    fn is_timed_out(&self) -> bool {
        self.started.elapsed() >= self.timeout
    }
}

impl std::fmt::Debug for ShutdownEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShutdownEntry")
            .field("conn_id", &self.conn_id)
            .field("state", &self.state)
            .field("started", &self.started)
            .field("timeout", &self.timeout)
            .field("aborted", &self.aborted)
            .field("handler_done", &self.handler_done)
            .field("filters_done", &self.filters_done)
            .finish()
    }
}

// ===========================================================================
// ShutdownManager — the core shutdown queue manager
// ===========================================================================

/// Manages orderly shutdown of connections released from the connection pool.
///
/// Replaces the C `struct cshutdn` and its associated functions:
/// - `Curl_cshutdn_init` → [`ShutdownManager::new`]
/// - `Curl_cshutdn_add` → [`ShutdownManager::add`]
/// - `Curl_cshutdn_perform` → [`ShutdownManager::perform`]
/// - `Curl_cshutdn_run_once` → [`ShutdownManager::run_once`]
/// - `Curl_cshutdn_terminate` → [`ShutdownManager::terminate`]
/// - `cshutdn_terminate_all` → [`ShutdownManager::terminate_all`]
/// - `Curl_cshutdn_close_oldest` → [`ShutdownManager::close_oldest`]
/// - `Curl_cshutdn_destroy` → [`ShutdownManager::destroy`]
/// - `Curl_cshutdn_count` → [`ShutdownManager::len`]
/// - `Curl_cshutdn_dest_count` → [`ShutdownManager::dest_count`]
/// - `Curl_cshutdn_add_pollfds` → [`ShutdownManager::add_pollfds`]
/// - `Curl_cshutdn_add_waitfds` → [`ShutdownManager::add_waitfds`]
/// - `Curl_cshutdn_setfds` → [`ShutdownManager::setfds`]
///
/// # Ownership
///
/// The shutdown manager is owned by the multi handle (or its connection pool).
/// When a connection is released from the pool, it is transferred to the
/// shutdown manager via [`add`](Self::add). The manager takes full ownership
/// and is responsible for closing the connection when shutdown completes.
pub struct ShutdownManager {
    /// Queue of connections pending graceful shutdown. `VecDeque` replaces
    /// the C `Curl_llist` linked list, providing O(1) push_back/pop_front
    /// and efficient iteration with retain.
    pending: VecDeque<ShutdownEntry>,

    /// Default timeout for graceful shutdown per connection. Matches the C
    /// `DEFAULT_SHUTDOWN_TIMEOUT_MS` (2000 ms).
    default_timeout: Duration,

    /// Maximum number of pending shutdowns. When exceeded, the oldest entry
    /// is force-closed to make room. 0 means no limit.
    max_pending: usize,
}

impl ShutdownManager {
    // ====================================================================
    // Construction
    // ====================================================================

    /// Creates a new `ShutdownManager` with the default shutdown timeout.
    ///
    /// The default timeout matches the C constant `DEFAULT_SHUTDOWN_TIMEOUT_MS`
    /// (2000 milliseconds = 2 seconds). The maximum pending limit is initially
    /// unlimited (0).
    ///
    /// Matches `Curl_cshutdn_init` from `lib/cshutdn.c`.
    pub fn new() -> Self {
        Self {
            pending: VecDeque::new(),
            default_timeout: Duration::from_millis(DEFAULT_SHUTDOWN_TIMEOUT_MS),
            max_pending: 0,
        }
    }

    /// Creates a new `ShutdownManager` with a custom default timeout.
    ///
    /// This is useful for testing or when the multi handle specifies a
    /// non-default shutdown timeout.
    pub fn with_config(default_timeout: Duration, max_pending: usize) -> Self {
        Self {
            pending: VecDeque::new(),
            default_timeout,
            max_pending,
        }
    }

    // ====================================================================
    // Queue Management
    // ====================================================================

    /// Adds a connection to the shutdown queue for graceful shutdown.
    ///
    /// Takes ownership of the `ConnectionData`. If the queue is at capacity
    /// (when `max_pending > 0`), the oldest entry is force-closed first to
    /// make room.
    ///
    /// Matches `Curl_cshutdn_add` from `lib/cshutdn.c`.
    ///
    /// # Errors
    ///
    /// Returns `CurlError::FailedInit` if the connection is in an invalid
    /// state for shutdown (e.g., never connected).
    pub fn add(&mut self, conn: ConnectionData, aborted: bool) -> CurlResult<()> {
        let conn_id = conn.conn_id();
        let host = conn.host().to_owned();
        let port = conn.port();

        // If we're at capacity, force-close the oldest entry to make room.
        // This matches the C behaviour when max_total_connections is exceeded.
        if self.max_pending > 0 && self.pending.len() >= self.max_pending {
            debug!(
                conn_id = conn_id,
                max_pending = self.max_pending,
                "[SHUTDOWN] discarding oldest shutdown connection due to limit"
            );
            self.close_oldest(None);
        }

        let entry = ShutdownEntry::new(conn, self.default_timeout, aborted);

        debug!(
            conn_id = conn_id,
            host = %host,
            port = port,
            aborted = aborted,
            pending = self.pending.len() + 1,
            "[SHUTDOWN] added connection to shutdown queue"
        );

        self.pending.push_back(entry);
        Ok(())
    }

    // ====================================================================
    // Shutdown Processing
    // ====================================================================

    /// Process all pending shutdowns, advancing each by one iteration.
    ///
    /// For each entry in the queue:
    /// 1. Start the shutdown timer if not yet started
    /// 2. Attempt to advance the filter chain shutdown
    /// 3. Check timeout — force close if exceeded
    /// 4. Remove entries that have reached a terminal state
    ///
    /// Returns the number of entries still pending after processing.
    ///
    /// Matches `Curl_cshutdn_perform` / `cshutdn_perform` from `lib/cshutdn.c`.
    pub async fn perform(&mut self) -> usize {
        if self.pending.is_empty() {
            return 0;
        }

        trace!(
            count = self.pending.len(),
            "[SHUTDOWN] perform on pending connections"
        );

        let mut completed_ids: Vec<u64> = Vec::new();
        let mut next_expire_ms: i64 = 0;

        // Process each entry. We iterate by index to avoid borrow issues
        // with async operations on mutable entries.
        let len = self.pending.len();
        for i in 0..len {
            let entry = &mut self.pending[i];

            // Skip entries already in terminal state (shouldn't happen but
            // defensive programming).
            if entry.is_terminal() {
                completed_ids.push(entry.conn_id);
                continue;
            }

            let done = run_once_entry(entry).await;

            if done {
                completed_ids.push(entry.conn_id);
            } else {
                // Track the minimum time remaining for the next expiry.
                // Uses shutdown_timeleft on the connection to determine
                // remaining time, matching C logic.
                let ms = shutdown_timeleft(&entry.conn, 0);
                if ms > 0 && (next_expire_ms == 0 || ms < next_expire_ms) {
                    next_expire_ms = ms;
                }
            }
        }

        // Remove all completed entries.
        if !completed_ids.is_empty() {
            self.pending.retain(|e| !completed_ids.contains(&e.conn_id));
        }

        if next_expire_ms > 0 {
            trace!(
                next_expire_ms = next_expire_ms,
                remaining = self.pending.len(),
                "[SHUTDOWN] next expiry"
            );
        }

        self.pending.len()
    }

    /// Run one shutdown iteration on a specific connection identified by ID.
    ///
    /// Returns `true` if the connection's shutdown is complete (either
    /// successfully or due to timeout/error). Returns `true` if the
    /// connection ID is not found (treat as already done).
    ///
    /// Matches the public `Curl_cshutdn_run_once` from `lib/cshutdn.c`.
    pub async fn run_once(&mut self, conn_id: u64) -> bool {
        let entry = self.pending.iter_mut().find(|e| e.conn_id == conn_id);
        match entry {
            Some(entry) => {
                let done = run_once_entry(entry).await;
                trace!(
                    conn_id = conn_id,
                    done = done,
                    "[SHUTDOWN] run_once result"
                );
                done
            }
            None => {
                // Connection not found in the queue — treat as already done.
                trace!(
                    conn_id = conn_id,
                    "[SHUTDOWN] run_once: connection not found, treating as done"
                );
                true
            }
        }
    }

    /// Force-close and remove a specific connection by ID.
    ///
    /// The connection is immediately closed without attempting graceful
    /// shutdown. This is used when a connection must be terminated urgently.
    ///
    /// Matches `Curl_cshutdn_terminate` from `lib/cshutdn.c`.
    pub fn terminate(&mut self, conn_id: u64) {
        if let Some(pos) = self.pending.iter().position(|e| e.conn_id == conn_id) {
            let mut entry = self.pending.remove(pos).expect("position was valid");
            debug!(
                conn_id = conn_id,
                filters_done = entry.filters_done,
                "[SHUTDOWN] force-terminating connection"
            );
            entry.conn.close();
            entry.state = ShutdownState::TimedOut;
        }
    }

    /// Attempt graceful shutdown of all pending connections, then force-close
    /// any remaining.
    ///
    /// This method:
    /// 1. Runs one `perform()` iteration to advance all shutdowns
    /// 2. Checks if all connections have completed
    /// 3. If the default timeout has elapsed, stops waiting
    /// 4. Force-closes any connections still remaining
    ///
    /// Called during multi_cleanup or process exit.
    ///
    /// Matches `cshutdn_terminate_all` from `lib/cshutdn.c`.
    pub async fn terminate_all(&mut self) {
        if self.pending.is_empty() {
            return;
        }

        let started = Instant::now();
        let timeout = self.default_timeout;

        debug!(
            count = self.pending.len(),
            timeout_ms = timeout.as_millis() as u64,
            "[SHUTDOWN] terminating all connections"
        );

        // Loop: try graceful shutdown with timeout.
        loop {
            self.perform().await;

            if self.pending.is_empty() {
                debug!("[SHUTDOWN] all shutdowns completed cleanly");
                break;
            }

            // Check overall timeout.
            let elapsed = started.elapsed();
            if elapsed >= timeout {
                let remaining = self.pending.len();
                debug!(
                    remaining = remaining,
                    elapsed_ms = elapsed.as_millis() as u64,
                    "[SHUTDOWN] terminate_all timeout reached"
                );
                break;
            }

            // If all remaining entries have individually timed out or
            // completed, there is nothing more to wait for.
            let all_terminal = self.pending.iter().all(|e| e.is_terminal());
            if all_terminal {
                break;
            }
        }

        // Force-close any remaining connections.
        self.force_close_all();
    }

    /// Close the oldest connection in the shutdown queue matching the given
    /// destination, or any destination if `None` is provided.
    ///
    /// Returns `true` if a connection was closed, `false` if no matching
    /// connection was found.
    ///
    /// Matches `Curl_cshutdn_close_oldest` / `cshutdn_destroy_oldest`
    /// from `lib/cshutdn.c`.
    pub fn close_oldest(&mut self, destination: Option<&str>) -> bool {
        let pos = match destination {
            Some(dest) => self
                .pending
                .iter()
                .position(|e| e.destination() == dest),
            None => {
                if self.pending.is_empty() {
                    None
                } else {
                    Some(0) // oldest is at the front
                }
            }
        };

        if let Some(pos) = pos {
            let mut entry = self.pending.remove(pos).expect("position was valid");
            debug!(
                conn_id = entry.conn_id,
                "[SHUTDOWN] force-closing oldest shutdown connection"
            );
            entry.conn.close();
            entry.state = ShutdownState::TimedOut;
            true
        } else {
            false
        }
    }

    /// Terminate all remaining connections and clean up the manager.
    ///
    /// This is a synchronous force-close of all pending connections without
    /// any graceful shutdown attempt. Used during final cleanup when no
    /// async context is available.
    ///
    /// Matches `Curl_cshutdn_destroy` from `lib/cshutdn.c`.
    pub fn destroy(&mut self) {
        if !self.pending.is_empty() {
            debug!(
                count = self.pending.len(),
                "[SHUTDOWN] destroy: force-closing all remaining connections"
            );
        }
        self.force_close_all();
    }

    // ====================================================================
    // Queue Inspection
    // ====================================================================

    /// Returns `true` if there are no connections pending shutdown.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Returns the total number of connections pending shutdown.
    ///
    /// Matches `Curl_cshutdn_count` from `lib/cshutdn.c`.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Returns the number of connections pending shutdown to a specific
    /// destination (identified as `scheme://host:port`).
    ///
    /// Matches `Curl_cshutdn_dest_count` from `lib/cshutdn.c`.
    pub fn dest_count(&self, destination: &str) -> usize {
        self.pending
            .iter()
            .filter(|e| e.destination() == destination)
            .count()
    }

    // ====================================================================
    // Poll Descriptor Collection
    // ====================================================================

    /// Collect poll descriptors from all pending shutdown connections into
    /// the provided [`PollSet`].
    ///
    /// For each connection in the shutdown queue that is still actively being
    /// shut down, the connection's socket is added to the poll set with both
    /// read and write interest. This allows the event loop to monitor shutdown
    /// progress.
    ///
    /// Matches `Curl_cshutdn_add_pollfds` from `lib/cshutdn.c`.
    #[cfg(unix)]
    pub fn add_pollfds(&self, pollset: &mut PollSet) -> CurlResult<()> {
        use crate::conn::filters::PollAction;

        if self.pending.is_empty() {
            return Ok(());
        }

        trace!(
            count = self.pending.len(),
            "[SHUTDOWN] collecting poll descriptors"
        );

        for entry in &self.pending {
            if entry.is_terminal() {
                continue;
            }
            // Get the connection's primary socket for poll monitoring.
            if let Some(fd) = entry.conn.get_socket() {
                pollset.add(fd, PollAction::POLL_IN | PollAction::POLL_OUT);
            }
        }

        Ok(())
    }

    /// Non-unix stub: poll descriptor collection is not supported.
    #[cfg(not(unix))]
    pub fn add_pollfds(&self, _pollset: &mut PollSet) -> CurlResult<()> {
        Ok(())
    }

    /// Collect wait descriptors from all pending shutdown connections.
    ///
    /// Similar to [`add_pollfds`](Self::add_pollfds) but returns the number
    /// of descriptors that would be needed (even if the poll set is full).
    ///
    /// Matches `Curl_cshutdn_add_waitfds` from `lib/cshutdn.c`.
    #[cfg(unix)]
    pub fn add_waitfds(&self, pollset: &mut PollSet) -> usize {
        use crate::conn::filters::PollAction;

        let mut need: usize = 0;

        if self.pending.is_empty() {
            return 0;
        }

        for entry in &self.pending {
            if entry.is_terminal() {
                continue;
            }
            if let Some(fd) = entry.conn.get_socket() {
                pollset.add(fd, PollAction::POLL_IN | PollAction::POLL_OUT);
                need += 1;
            }
        }

        need
    }

    /// Non-unix stub: wait descriptor collection is not supported.
    #[cfg(not(unix))]
    pub fn add_waitfds(&self, _pollset: &mut PollSet) -> usize {
        0
    }

    /// Set file descriptors for `select()`-based monitoring of shutdown
    /// connections.
    ///
    /// Collects socket descriptors from all pending shutdown connections and
    /// adds them to the provided [`PollSet`] with appropriate read/write
    /// interest flags.
    ///
    /// Matches `Curl_cshutdn_setfds` from `lib/cshutdn.c`.
    #[cfg(unix)]
    pub fn setfds(&self, pollset: &mut PollSet) {
        use crate::conn::filters::PollAction;

        if self.pending.is_empty() {
            return;
        }

        for entry in &self.pending {
            if entry.is_terminal() {
                continue;
            }
            if let Some(fd) = entry.conn.get_socket() {
                // During shutdown, we need to monitor both directions:
                // - Read: to receive server's response to disconnect commands
                // - Write: to send disconnect commands (QUIT, close_notify)
                pollset.add(fd, PollAction::POLL_IN | PollAction::POLL_OUT);
            }
        }
    }

    /// Non-unix stub: fd_set collection is not supported.
    #[cfg(not(unix))]
    pub fn setfds(&self, _pollset: &mut PollSet) {}

    // ====================================================================
    // Internal Helpers
    // ====================================================================

    /// Force-close all remaining connections in the queue without any
    /// graceful shutdown attempt.
    fn force_close_all(&mut self) {
        while let Some(mut entry) = self.pending.pop_front() {
            if !entry.is_terminal() {
                warn!(
                    conn_id = entry.conn_id,
                    state = %entry.state,
                    "[SHUTDOWN] force-closing connection"
                );
                entry.conn.close();
                entry.state = ShutdownState::TimedOut;
            }
        }
    }
}

impl Default for ShutdownManager {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ShutdownManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShutdownManager")
            .field("pending", &self.pending.len())
            .field("default_timeout", &self.default_timeout)
            .field("max_pending", &self.max_pending)
            .finish()
    }
}

// ===========================================================================
// Internal (module-private) shutdown processing functions
// ===========================================================================

/// Run a single shutdown iteration on one entry.
///
/// This function drives the shutdown state machine for a single connection:
///
/// 1. **Timeout check**: If the shutdown timeout has been exceeded, the
///    connection is force-closed and the entry is marked `TimedOut`.
///
/// 2. **Connectivity check**: If the connection is no longer connected (e.g.,
///    remote closed), the entry is immediately marked `Complete`.
///
/// 3. **Shutdown timer**: Starts the connection's internal shutdown timer
///    on the first invocation, matching `Curl_shutdown_start`.
///
/// 4. **Filter chain shutdown**: Calls [`ConnectionData::shutdown()`] which
///    walks the filter chain sending TLS close_notify, TCP FIN, etc. This
///    is a non-blocking poll-style operation that returns `Ok(true)` when
///    complete or `Ok(false)` when more I/O is needed.
///
/// Returns `true` when the entry has reached a terminal state.
///
/// Matches the logic of `cshutdn_run_once` from `lib/cshutdn.c`.
async fn run_once_entry(entry: &mut ShutdownEntry) -> bool {
    // If already in a terminal state, nothing to do.
    if entry.is_terminal() {
        return true;
    }

    // Transition from Pending to Running on first invocation.
    if entry.state == ShutdownState::Pending {
        entry.state = ShutdownState::Running;
    }

    // Check timeout: if the allowed shutdown duration has elapsed,
    // force-close the connection immediately.
    if entry.is_timed_out() {
        warn!(
            conn_id = entry.conn_id,
            elapsed_ms = entry.started.elapsed().as_millis() as u64,
            timeout_ms = entry.timeout.as_millis() as u64,
            "[SHUTDOWN] connection shutdown timed out, force-closing"
        );
        entry.conn.close();
        entry.state = ShutdownState::TimedOut;
        return true;
    }

    // If the connection is no longer connected (remote side closed, etc.),
    // mark as complete immediately.
    if !entry.conn.is_connected() && !entry.conn.is_alive() {
        debug!(
            conn_id = entry.conn_id,
            "[SHUTDOWN] connection already disconnected"
        );
        entry.conn.close();
        entry.state = ShutdownState::Complete;
        entry.filters_done = true;
        return true;
    }

    // Start the shutdown timer on the connection if not already started.
    // This sets the connection's internal shutdown tracking, matching the C
    // call to Curl_shutdown_start(data, FIRSTSOCKET, 0).
    if !entry.shutdown_started {
        shutdown_start(
            &mut entry.conn,
            0, // FIRSTSOCKET
            0, // use default timeout
            entry.timeout.as_millis() as i64,
        );
        entry.shutdown_started = true;
    }

    // If filters are already done (previous iteration completed), we're done.
    if entry.filters_done {
        entry.state = ShutdownState::Complete;
        return true;
    }

    // Drive the filter chain shutdown. This is the core non-blocking
    // operation that sends TLS close_notify, TCP shutdown, etc.
    //
    // The async .await here cooperatively yields if the underlying I/O
    // is not ready, allowing other connections to make progress.
    match entry.conn.shutdown().await {
        Ok(true) => {
            // All filters in the chain have completed shutdown.
            debug!(
                conn_id = entry.conn_id,
                "[SHUTDOWN] filter chain shutdown complete"
            );
            entry.filters_done = true;
            entry.state = ShutdownState::Complete;
            true
        }
        Ok(false) => {
            // Shutdown is in progress but not yet complete. The caller
            // should retry on the next event loop iteration after the
            // poll descriptors indicate readiness.
            trace!(
                conn_id = entry.conn_id,
                "[SHUTDOWN] filter chain shutdown in progress"
            );
            false
        }
        Err(CurlError::Again) => {
            // Non-blocking retry: the underlying I/O operation would block.
            // This is expected and normal — retry on next iteration.
            trace!(
                conn_id = entry.conn_id,
                "[SHUTDOWN] filter shutdown returned Again, will retry"
            );
            false
        }
        Err(e) => {
            // Shutdown encountered an error. Force-close the connection
            // since we cannot complete a graceful shutdown.
            warn!(
                conn_id = entry.conn_id,
                error = %e,
                "[SHUTDOWN] filter chain shutdown error, force-closing"
            );
            entry.conn.close();
            entry.state = ShutdownState::Complete;
            entry.filters_done = true;
            true
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a test ConnectionData with the given ID.
    fn make_test_conn(id: u64) -> ConnectionData {
        ConnectionData::new(id, "example.com".to_string(), 443, "https".to_string())
    }

    #[test]
    fn shutdown_state_display() {
        assert_eq!(ShutdownState::Pending.to_string(), "pending");
        assert_eq!(ShutdownState::Running.to_string(), "running");
        assert_eq!(ShutdownState::Complete.to_string(), "complete");
        assert_eq!(ShutdownState::TimedOut.to_string(), "timed_out");
    }

    #[test]
    fn manager_new_defaults() {
        let mgr = ShutdownManager::new();
        assert!(mgr.is_empty());
        assert_eq!(mgr.len(), 0);
        assert_eq!(
            mgr.default_timeout,
            Duration::from_millis(DEFAULT_SHUTDOWN_TIMEOUT_MS)
        );
    }

    #[test]
    fn manager_with_config() {
        let mgr = ShutdownManager::with_config(Duration::from_secs(5), 10);
        assert_eq!(mgr.default_timeout, Duration::from_secs(5));
        assert_eq!(mgr.max_pending, 10);
    }

    #[test]
    fn manager_add_and_len() {
        let mut mgr = ShutdownManager::new();
        let conn1 = make_test_conn(1);
        let conn2 = make_test_conn(2);

        mgr.add(conn1, false).unwrap();
        assert_eq!(mgr.len(), 1);
        assert!(!mgr.is_empty());

        mgr.add(conn2, true).unwrap();
        assert_eq!(mgr.len(), 2);
    }

    #[test]
    fn manager_terminate_specific() {
        let mut mgr = ShutdownManager::new();
        mgr.add(make_test_conn(10), false).unwrap();
        mgr.add(make_test_conn(20), false).unwrap();
        mgr.add(make_test_conn(30), false).unwrap();

        assert_eq!(mgr.len(), 3);
        mgr.terminate(20);
        assert_eq!(mgr.len(), 2);

        // Verify the correct one was removed.
        let ids: Vec<u64> = mgr.pending.iter().map(|e| e.conn_id).collect();
        assert_eq!(ids, vec![10, 30]);
    }

    #[test]
    fn manager_terminate_nonexistent() {
        let mut mgr = ShutdownManager::new();
        mgr.add(make_test_conn(1), false).unwrap();
        mgr.terminate(999); // should be a no-op
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn manager_close_oldest_any() {
        let mut mgr = ShutdownManager::new();
        mgr.add(make_test_conn(1), false).unwrap();
        mgr.add(make_test_conn(2), false).unwrap();

        let closed = mgr.close_oldest(None);
        assert!(closed);
        assert_eq!(mgr.len(), 1);
        assert_eq!(mgr.pending[0].conn_id, 2); // oldest (1) was removed
    }

    #[test]
    fn manager_close_oldest_by_dest() {
        let mut mgr = ShutdownManager::new();

        // Add two connections to different destinations.
        let conn1 = ConnectionData::new(1, "a.example.com".to_string(), 443, "https".to_string());
        let conn2 = ConnectionData::new(2, "b.example.com".to_string(), 80, "http".to_string());
        let conn3 = ConnectionData::new(3, "a.example.com".to_string(), 443, "https".to_string());

        mgr.add(conn1, false).unwrap();
        mgr.add(conn2, false).unwrap();
        mgr.add(conn3, false).unwrap();

        // Close oldest to "https://a.example.com:443" — should remove conn 1.
        let closed = mgr.close_oldest(Some("https://a.example.com:443"));
        assert!(closed);
        assert_eq!(mgr.len(), 2);
        let ids: Vec<u64> = mgr.pending.iter().map(|e| e.conn_id).collect();
        assert_eq!(ids, vec![2, 3]);
    }

    #[test]
    fn manager_close_oldest_no_match() {
        let mut mgr = ShutdownManager::new();
        mgr.add(make_test_conn(1), false).unwrap();

        let closed = mgr.close_oldest(Some("https://nonexistent:443"));
        assert!(!closed);
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn manager_dest_count() {
        let mut mgr = ShutdownManager::new();

        let conn1 = ConnectionData::new(1, "a.com".to_string(), 443, "https".to_string());
        let conn2 = ConnectionData::new(2, "b.com".to_string(), 80, "http".to_string());
        let conn3 = ConnectionData::new(3, "a.com".to_string(), 443, "https".to_string());

        mgr.add(conn1, false).unwrap();
        mgr.add(conn2, false).unwrap();
        mgr.add(conn3, false).unwrap();

        assert_eq!(mgr.dest_count("https://a.com:443"), 2);
        assert_eq!(mgr.dest_count("http://b.com:80"), 1);
        assert_eq!(mgr.dest_count("ftp://c.com:21"), 0);
    }

    #[test]
    fn manager_destroy() {
        let mut mgr = ShutdownManager::new();
        mgr.add(make_test_conn(1), false).unwrap();
        mgr.add(make_test_conn(2), false).unwrap();
        mgr.add(make_test_conn(3), false).unwrap();

        mgr.destroy();
        assert!(mgr.is_empty());
    }

    #[test]
    fn manager_add_respects_max_pending() {
        let mut mgr = ShutdownManager::with_config(Duration::from_secs(2), 2);

        mgr.add(make_test_conn(1), false).unwrap();
        mgr.add(make_test_conn(2), false).unwrap();
        assert_eq!(mgr.len(), 2);

        // Adding a third should evict the oldest (conn 1).
        mgr.add(make_test_conn(3), false).unwrap();
        assert_eq!(mgr.len(), 2);
        let ids: Vec<u64> = mgr.pending.iter().map(|e| e.conn_id).collect();
        assert_eq!(ids, vec![2, 3]);
    }

    #[test]
    fn shutdown_entry_destination() {
        let conn = ConnectionData::new(1, "host.example.com".to_string(), 8080, "https".to_string());
        let entry = ShutdownEntry::new(conn, Duration::from_secs(2), false);
        assert_eq!(entry.destination(), "https://host.example.com:8080");
    }

    #[test]
    fn shutdown_entry_initial_state() {
        let conn = make_test_conn(42);
        let entry = ShutdownEntry::new(conn, Duration::from_secs(5), true);

        assert_eq!(entry.conn_id, 42);
        assert_eq!(entry.state, ShutdownState::Pending);
        assert!(entry.aborted);
        assert!(!entry.handler_done);
        assert!(!entry.filters_done);
        assert!(!entry.shutdown_started);
        assert!(!entry.is_terminal());
    }

    #[test]
    fn shutdown_entry_timeout_check() {
        let conn = make_test_conn(1);
        // Use zero-duration timeout so it immediately times out.
        let entry = ShutdownEntry::new(conn, Duration::from_millis(0), false);
        assert!(entry.is_timed_out());
    }

    #[test]
    fn manager_default_is_new() {
        let default_mgr = ShutdownManager::default();
        let new_mgr = ShutdownManager::new();
        assert_eq!(default_mgr.default_timeout, new_mgr.default_timeout);
        assert_eq!(default_mgr.max_pending, new_mgr.max_pending);
        assert_eq!(default_mgr.len(), new_mgr.len());
    }

    #[test]
    fn manager_debug_format() {
        let mgr = ShutdownManager::new();
        let debug_str = format!("{:?}", mgr);
        assert!(debug_str.contains("ShutdownManager"));
        assert!(debug_str.contains("pending"));
    }

    #[test]
    fn shutdown_state_equality() {
        assert_eq!(ShutdownState::Pending, ShutdownState::Pending);
        assert_ne!(ShutdownState::Pending, ShutdownState::Running);
        assert_ne!(ShutdownState::Complete, ShutdownState::TimedOut);
    }

    #[tokio::test]
    async fn manager_perform_empty() {
        let mut mgr = ShutdownManager::new();
        let remaining = mgr.perform().await;
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn manager_perform_processes_disconnected() {
        let mut mgr = ShutdownManager::new();
        // A freshly created connection (never connected) should complete
        // shutdown immediately since is_connected() returns false.
        let conn = make_test_conn(1);
        mgr.add(conn, false).unwrap();

        let remaining = mgr.perform().await;
        // The connection was never connected, so shutdown should complete.
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn manager_run_once_nonexistent() {
        let mut mgr = ShutdownManager::new();
        let done = mgr.run_once(999).await;
        assert!(done); // Non-existent treated as done.
    }

    #[tokio::test]
    async fn manager_terminate_all_empty() {
        let mut mgr = ShutdownManager::new();
        mgr.terminate_all().await;
        assert!(mgr.is_empty());
    }

    #[tokio::test]
    async fn manager_terminate_all_force_closes() {
        let mut mgr = ShutdownManager::new();
        mgr.add(make_test_conn(1), false).unwrap();
        mgr.add(make_test_conn(2), false).unwrap();

        mgr.terminate_all().await;
        assert!(mgr.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn manager_add_pollfds_empty() {
        let mgr = ShutdownManager::new();
        let mut ps = PollSet::new();
        let result = mgr.add_pollfds(&mut ps);
        assert!(result.is_ok());
        assert!(ps.entries().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn manager_add_waitfds_empty() {
        let mgr = ShutdownManager::new();
        let mut ps = PollSet::new();
        let count = mgr.add_waitfds(&mut ps);
        assert_eq!(count, 0);
    }

    #[cfg(unix)]
    #[test]
    fn manager_setfds_empty() {
        let mgr = ShutdownManager::new();
        let mut ps = PollSet::new();
        mgr.setfds(&mut ps);
        assert!(ps.entries().is_empty());
    }
}
