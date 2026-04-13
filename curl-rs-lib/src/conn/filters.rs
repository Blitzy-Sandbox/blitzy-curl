//! Connection filter framework — core trait, chain management, and constants.
//!
//! This module is the Rust rewrite of `lib/cfilters.c` (1,104 lines) and
//! `lib/cfilters.h` (687 lines) from the curl C codebase. It defines:
//!
//! - [`ConnectionFilter`] — the core trait that every connection filter
//!   implements (socket, TLS, proxy, HTTP/2, QUIC, etc.), replacing the C
//!   `Curl_cftype` vtable of 15 function pointers.
//! - [`FilterChain`] — a managed ordered collection of boxed
//!   `ConnectionFilter` instances, replacing the C linked-list chain
//!   (`cf->next` pointer chain) with a `Vec<Box<dyn ConnectionFilter>>`.
//! - Constants for filter type flags (`CF_TYPE_*`), control events
//!   (`CF_CTRL_*`), and query identifiers (`CF_QUERY_*`), all with integer
//!   values matching the C definitions exactly.
//! - [`PollSet`], [`PollEntry`], [`PollAction`] — types for socket I/O
//!   readiness monitoring in the filter chain.
//! - [`QueryResult`] — typed return values for filter property queries.
//! - [`TransferData`] — opaque per-transfer state passed to filter methods.
//! - Convenience helper functions for common filter-chain queries.
//!
//! # Architecture
//!
//! The filter chain follows a Tower-like middleware pattern:
//!
//! ```text
//! ┌───────────┐   ┌──────────┐   ┌──────────┐   ┌────────┐
//! │ HTTP/2    │──▶│   TLS    │──▶│  Proxy   │──▶│ Socket │
//! │ (index 0) │   │(index 1) │   │(index 2) │   │(last)  │
//! └───────────┘   └──────────┘   └──────────┘   └────────┘
//!   "top"                                          "bottom"
//! ```
//!
//! Index 0 is the outermost ("top") filter; the last index is the innermost
//! ("bottom", typically the raw socket). Data flows top-to-bottom for sends
//! and bottom-to-top for receives.

use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::time::Instant;

use async_trait::async_trait;

use crate::error::CurlError;

// ===========================================================================
// Filter Type Flags (bitfield constants — matching C values exactly)
// ===========================================================================

/// Type alias for filter type flag bitfields.
///
/// Filters declare their capabilities by combining these flags via bitwise OR
/// in their [`ConnectionFilter::type_flags`] implementation.
pub type FilterTypeFlags = u32;

/// Filter provides an IP-level connection or equivalent (TCP, UNIX domain
/// socket, QUIC connection, CONNECT tunnel, etc.).
///
/// C: `#define CF_TYPE_IP_CONNECT  (1 << 0)`
pub const CF_TYPE_IP_CONNECT: u32 = 1 << 0;

/// Filter provides SSL/TLS encryption.
///
/// C: `#define CF_TYPE_SSL  (1 << 1)`
pub const CF_TYPE_SSL: u32 = 1 << 1;

/// Filter provides multiplexing of easy handles (e.g., HTTP/2 streams).
///
/// C: `#define CF_TYPE_MULTIPLEX  (1 << 2)`
pub const CF_TYPE_MULTIPLEX: u32 = 1 << 2;

/// Filter provides proxying functionality.
///
/// C: `#define CF_TYPE_PROXY  (1 << 3)`
pub const CF_TYPE_PROXY: u32 = 1 << 3;

/// Filter implements an HTTP protocol version.
///
/// C: `#define CF_TYPE_HTTP  (1 << 4)`
pub const CF_TYPE_HTTP: u32 = 1 << 4;

// ===========================================================================
// Control Event Constants (matching C values exactly)
// ===========================================================================
//
// Events/controls distributed to connection filters via the `control` method.
// Filters handle events top-down through the chain. Return-code handling is
// either "first fail" (abort on first error) or "ignored" (distribute to all).

/// Notify filters that a transfer's data setup phase begins.
/// Return handling: first fail.
///
/// C: `#define CF_CTRL_DATA_SETUP  4`
pub const CF_CTRL_DATA_SETUP: i32 = 4;

/// Notify filters that data transfer is being paused or unpaused.
/// `arg1`: 1 to pause, 0 to unpause. Return handling: first fail.
///
/// C: `#define CF_CTRL_DATA_PAUSE  6`
pub const CF_CTRL_DATA_PAUSE: i32 = 6;

/// Notify filters that the transfer is done (possibly premature).
/// `arg1`: 1 if premature. Return handling: ignored.
///
/// C: `#define CF_CTRL_DATA_DONE  7`
pub const CF_CTRL_DATA_DONE: i32 = 7;

/// Notify filters that the transfer is done sending data.
/// Return handling: ignored.
///
/// C: `#define CF_CTRL_DATA_DONE_SEND  8`
pub const CF_CTRL_DATA_DONE_SEND: i32 = 8;

/// Update connection info at connection and data level.
/// Return handling: ignored.
///
/// C: `#define CF_CTRL_CONN_INFO_UPDATE  (256 + 0)`
pub const CF_CTRL_CONN_INFO_UPDATE: i32 = 256;

/// Tell filters to forget about their socket.
/// Return handling: ignored.
///
/// C: `#define CF_CTRL_FORGET_SOCKET  (256 + 1)`
pub const CF_CTRL_FORGET_SOCKET: i32 = 257;

/// Flush any pending data in the filter chain.
/// Return handling: first fail.
///
/// C: `#define CF_CTRL_FLUSH  (256 + 2)`
pub const CF_CTRL_FLUSH: i32 = 258;

// ===========================================================================
// Query Constants (matching C values exactly)
// ===========================================================================
//
// Query identifiers passed to [`ConnectionFilter::query`]. Filters that
// recognise a query return a typed [`QueryResult`]; unrecognised queries
// are passed down the chain.

/// Maximum number of parallel transfers the filter chain can handle.
/// Default: 1 (non-multiplexed). Returns `QueryResult::Int`.
///
/// C: `#define CF_QUERY_MAX_CONCURRENT  1`
pub const CF_QUERY_MAX_CONCURRENT: i32 = 1;

/// Milliseconds until the first server response indication on connect.
/// −1 if not determined. Returns `QueryResult::Int`.
///
/// C: `#define CF_QUERY_CONNECT_REPLY_MS  2`
pub const CF_QUERY_CONNECT_REPLY_MS: i32 = 2;

/// The underlying socket file descriptor. Returns `QueryResult::Socket`.
///
/// C: `#define CF_QUERY_SOCKET  3`
pub const CF_QUERY_SOCKET: i32 = 3;

/// Timestamp when TCP/QUIC connection was established.
/// Returns `QueryResult::Time`.
///
/// C: `#define CF_QUERY_TIMER_CONNECT  4`
pub const CF_QUERY_TIMER_CONNECT: i32 = 4;

/// Timestamp when application-level connection (e.g., TLS handshake)
/// completed. Returns `QueryResult::Time`.
///
/// C: `#define CF_QUERY_TIMER_APPCONNECT  5`
pub const CF_QUERY_TIMER_APPCONNECT: i32 = 5;

/// Underlying stream-level error code, or 0 if none.
/// Returns `QueryResult::Int`.
///
/// C: `#define CF_QUERY_STREAM_ERROR  6`
pub const CF_QUERY_STREAM_ERROR: i32 = 6;

/// Whether any filter has unsent data. Returns `QueryResult::Bool`.
///
/// C: `#define CF_QUERY_NEED_FLUSH  7`
pub const CF_QUERY_NEED_FLUSH: i32 = 7;

/// IP information: whether IPv6, and the address quadruple.
/// Returns `QueryResult::Addr` (with `QueryResult::Bool` for IPv6 flag
/// via the filter's implementation).
///
/// C: `#define CF_QUERY_IP_INFO  8`
pub const CF_QUERY_IP_INFO: i32 = 8;

/// HTTP version in use (09, 10, 11, 20, 30). Returns `QueryResult::Int`.
///
/// C: `#define CF_QUERY_HTTP_VERSION  9`
pub const CF_QUERY_HTTP_VERSION: i32 = 9;

/// Remote address the connection is talking to.
/// Returns `QueryResult::Addr`.
///
/// C: `#define CF_QUERY_REMOTE_ADDR  10`
pub const CF_QUERY_REMOTE_ADDR: i32 = 10;

/// Host and port the filter is currently talking to.
/// Returns `QueryResult::String` (hostname) or `QueryResult::Int` (port).
///
/// C: `#define CF_QUERY_HOST_PORT  11`
pub const CF_QUERY_HOST_PORT: i32 = 11;

/// SSL/TLS session info. Returns `QueryResult::String` with session details.
///
/// C: `#define CF_QUERY_SSL_INFO  12`
pub const CF_QUERY_SSL_INFO: i32 = 12;

/// SSL/TLS context info. Returns `QueryResult::String`.
///
/// C: `#define CF_QUERY_SSL_CTX_INFO  13`
pub const CF_QUERY_SSL_CTX_INFO: i32 = 13;

/// Transport type in use (TCP, UDP, UNIX). Returns `QueryResult::Int`.
///
/// C: `#define CF_QUERY_TRANSPORT  14`
pub const CF_QUERY_TRANSPORT: i32 = 14;

/// ALPN protocol negotiated by the server, or `None` if not available.
/// Returns `QueryResult::String`.
///
/// C: `#define CF_QUERY_ALPN_NEGOTIATED  15`
pub const CF_QUERY_ALPN_NEGOTIATED: i32 = 15;

// ===========================================================================
// SSL Configuration Constants
// ===========================================================================

/// Use default SSL behaviour for the connection.
///
/// C: `#define CURL_CF_SSL_DEFAULT  (-1)`
pub const CURL_CF_SSL_DEFAULT: i32 = -1;

/// Disable SSL on the connection.
///
/// C: `#define CURL_CF_SSL_DISABLE  0`
pub const CURL_CF_SSL_DISABLE: i32 = 0;

/// Enable SSL on the connection.
///
/// C: `#define CURL_CF_SSL_ENABLE  1`
pub const CURL_CF_SSL_ENABLE: i32 = 1;

// ===========================================================================
// Poll Types
// ===========================================================================

/// Bit-flags for socket poll actions. These mirror the C `CURL_POLL_IN` and
/// `CURL_POLL_OUT` semantics.
pub struct PollAction;

impl PollAction {
    /// Socket is ready for reading / has incoming data.
    pub const POLL_IN: u8 = 1;
    /// Socket is ready for writing / can accept outgoing data.
    pub const POLL_OUT: u8 = 2;
}

/// An entry in a [`PollSet`] describing a socket and the I/O actions
/// that should be monitored on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollEntry {
    /// The file descriptor of the socket to monitor.
    #[cfg(unix)]
    pub socket: RawFd,

    /// Bitmask of [`PollAction`] flags indicating which directions to poll.
    pub actions: u8,
}

/// A set of sockets and their associated poll actions.
///
/// Filters use [`ConnectionFilter::adjust_pollset`] to add or remove sockets
/// from the poll set. Lower (inner) filters can override actions set by upper
/// (outer) filters, matching the C `easy_pollset` semantics.
#[derive(Debug, Clone)]
pub struct PollSet {
    /// Socket entries to poll.
    entries: Vec<PollEntry>,
}

impl PollSet {
    /// Creates an empty poll set.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Adds a socket with the given actions to the poll set.
    ///
    /// If the socket already exists in the set, the actions are merged
    /// (bitwise OR) with the existing actions. If after merging the actions
    /// are non-zero, the entry is kept; otherwise it is removed.
    #[cfg(unix)]
    pub fn add(&mut self, socket: RawFd, actions: u8) {
        if actions == 0 {
            // Zero actions means remove.
            self.entries.retain(|e| e.socket != socket);
            return;
        }
        for entry in &mut self.entries {
            if entry.socket == socket {
                entry.actions |= actions;
                return;
            }
        }
        self.entries.push(PollEntry { socket, actions });
    }

    /// Removes a specific action from a socket. If no actions remain, the
    /// socket entry is removed entirely.
    #[cfg(unix)]
    pub fn remove(&mut self, socket: RawFd, actions: u8) {
        self.entries.retain_mut(|e| {
            if e.socket == socket {
                e.actions &= !actions;
                e.actions != 0
            } else {
                true
            }
        });
    }

    /// Clears all entries from the poll set.
    pub fn reset(&mut self) {
        self.entries.clear();
    }

    /// Returns a slice of all current poll entries.
    pub fn entries(&self) -> &[PollEntry] {
        &self.entries
    }
}

impl Default for PollSet {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// QueryResult
// ===========================================================================

/// Typed result returned by [`ConnectionFilter::query`].
///
/// Each variant carries a payload appropriate for the query type.
/// `NotHandled` indicates that the filter does not recognise the query and
/// the caller should try the next filter in the chain.
#[derive(Debug, Clone)]
pub enum QueryResult {
    /// The query was not handled by this filter — try the next one in the
    /// chain.
    NotHandled,

    /// An integer result. Used for `CF_QUERY_MAX_CONCURRENT`,
    /// `CF_QUERY_CONNECT_REPLY_MS`, `CF_QUERY_STREAM_ERROR`,
    /// `CF_QUERY_HTTP_VERSION`, `CF_QUERY_TRANSPORT`, etc.
    Int(i32),

    /// A boolean result. Used for `CF_QUERY_NEED_FLUSH`,
    /// `CF_QUERY_IP_INFO` (IPv6 flag), etc.
    Bool(bool),

    /// A socket file descriptor. Used for `CF_QUERY_SOCKET`.
    #[cfg(unix)]
    Socket(RawFd),

    /// A string result. Used for `CF_QUERY_ALPN_NEGOTIATED`,
    /// `CF_QUERY_HOST_PORT`, `CF_QUERY_SSL_INFO`, etc.
    String(String),

    /// A socket address. Used for `CF_QUERY_REMOTE_ADDR`,
    /// `CF_QUERY_IP_INFO` (address quadruple).
    Addr(SocketAddr),

    /// A timestamp. Used for `CF_QUERY_TIMER_CONNECT`,
    /// `CF_QUERY_TIMER_APPCONNECT`.
    Time(Instant),
}

// ===========================================================================
// TransferData
// ===========================================================================

/// Per-transfer state passed to filter methods.
///
/// This is the Rust equivalent of `struct Curl_easy *data` in the C codebase.
/// It carries the transfer-specific configuration and state that filters need
/// to make decisions (e.g., timeouts, verbose mode, authentication state).
///
/// The struct is intentionally kept as a simple container here; the full
/// implementation is provided by the easy-handle module and wired up at the
/// transfer layer.
#[derive(Debug, Default)]
pub struct TransferData {
    /// Whether verbose logging is enabled for this transfer.
    pub verbose: bool,
    /// Transfer timeout in milliseconds (0 = no timeout).
    pub timeout_ms: u64,
    /// Whether the connection should be marked for closure after this transfer.
    pub close_connection: bool,
}

// ===========================================================================
// ConnectionFilter Trait — THE CORE ABSTRACTION
// ===========================================================================
//
// Replaces the C `Curl_cftype` vtable. Each concrete filter (socket, TLS,
// proxy, HTTP/2, QUIC, etc.) implements this trait. The `async_trait` macro
// is required because Rust 1.75 native async-fn-in-trait does not support
// dynamic dispatch (`dyn ConnectionFilter`).

/// The core connection filter trait.
///
/// Every connection filter in the chain implements this trait. Filters compose
/// in a layered stack: the outermost (index 0 in [`FilterChain`]) handles
/// protocol-level concerns (HTTP/2 framing, multiplexing); the innermost
/// (last index) manages the raw transport (TCP socket, QUIC endpoint).
///
/// # Default Implementations
///
/// Methods with default implementations match the C `Curl_cf_def_*`
/// pass-through behaviour — they either no-op or return sensible defaults.
/// Concrete filters override only the methods relevant to their layer.
///
/// # Object Safety
///
/// This trait is object-safe: it can be used as `dyn ConnectionFilter`. The
/// `async_trait` macro desugars async methods into
/// `Pin<Box<dyn Future + Send>>` returns.
#[async_trait]
pub trait ConnectionFilter: Send + Sync {
    /// Human-readable name of this filter type, used in logging and debugging
    /// output. Examples: `"socket"`, `"tls-rustls"`, `"h2-proxy"`.
    fn name(&self) -> &str;

    /// Bitfield of [`FilterTypeFlags`] indicating the capabilities that this
    /// filter provides (e.g., `CF_TYPE_SSL | CF_TYPE_IP_CONNECT`).
    fn type_flags(&self) -> u32;

    /// Log verbosity level for this filter. A higher value means the filter
    /// produces more detailed trace output.
    ///
    /// Default: `0` (minimal logging).
    fn log_level(&self) -> i32 {
        0
    }

    /// Attempt to establish the connection through this filter.
    ///
    /// This is a non-blocking operation. Returns:
    /// - `Ok(true)` — this filter is now fully connected.
    /// - `Ok(false)` — more I/O is needed; call again after the poll set
    ///   indicates readiness.
    /// - `Err(e)` — a fatal error occurred.
    ///
    /// The `data` parameter carries per-transfer state (timeouts, auth, etc.).
    async fn connect(&mut self, data: &mut TransferData) -> Result<bool, CurlError>;

    /// Immediately close the connection through this filter.
    ///
    /// After this call, [`is_connected`](ConnectionFilter::is_connected)
    /// returns `false`. Unlike [`shutdown`](ConnectionFilter::shutdown), this
    /// is not graceful — data in flight may be lost.
    fn close(&mut self);

    /// Gracefully shut down the connection through this filter (non-blocking).
    ///
    /// Returns:
    /// - `Ok(true)` — shutdown is complete.
    /// - `Ok(false)` — more I/O is needed; call again.
    /// - `Err(e)` — shutdown failed.
    ///
    /// Default: immediate completion (`Ok(true)`), matching
    /// `Curl_cf_def_shutdown`.
    async fn shutdown(&mut self) -> Result<bool, CurlError> {
        Ok(true)
    }

    /// Adjust the poll set for socket I/O monitoring.
    ///
    /// Filters add or remove sockets and their poll directions to/from `ps`.
    /// Lower filters are called after upper filters, so they can override
    /// upper-layer decisions (e.g., a TLS handshake may temporarily need
    /// the opposite poll direction).
    ///
    /// Default: no-op (the poll set is unchanged), matching
    /// `Curl_cf_def_adjust_pollset`.
    fn adjust_pollset(
        &self,
        _data: &TransferData,
        _ps: &mut PollSet,
    ) -> Result<(), CurlError> {
        Ok(())
    }

    /// Returns `true` if this filter has data buffered that is ready to be
    /// read without further I/O.
    ///
    /// Default: `false`, matching `Curl_cf_def_data_pending`.
    fn data_pending(&self) -> bool {
        false
    }

    /// Send data through this filter.
    ///
    /// Writes up to `buf.len()` bytes from `buf`. When `eos` is `true`, this
    /// is the last chunk of data for the current transfer direction.
    ///
    /// Returns the number of bytes actually written. A return of `0` with
    /// `Err(CurlError::Again)` indicates the filter is temporarily unable
    /// to accept data.
    async fn send(&mut self, buf: &[u8], eos: bool) -> Result<usize, CurlError>;

    /// Receive data through this filter.
    ///
    /// Reads up to `buf.len()` bytes into `buf`.
    ///
    /// Returns the number of bytes actually read. A return of `0` with
    /// `Ok(0)` indicates end-of-stream. `Err(CurlError::Again)` indicates
    /// the filter is temporarily unable to provide data.
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, CurlError>;

    /// Handle a control event.
    ///
    /// `event` is one of the `CF_CTRL_*` constants. `arg1` carries
    /// event-specific data (e.g., pause flag for `CF_CTRL_DATA_PAUSE`).
    ///
    /// Default: ignore the event and return success, matching
    /// `Curl_cf_def_cntrl`.
    fn control(&mut self, _event: i32, _arg1: i32) -> Result<(), CurlError> {
        Ok(())
    }

    /// Check whether the underlying connection is still alive.
    ///
    /// Default: `true` (optimistic), matching `Curl_cf_def_conn_is_alive`
    /// in the absence of a chain delegate.
    fn is_alive(&self) -> bool {
        true
    }

    /// Send keepalive probes through this filter to prevent connection
    /// timeout at the remote end.
    ///
    /// Default: no-op, matching `Curl_cf_def_conn_keep_alive`.
    fn keep_alive(&mut self) -> Result<(), CurlError> {
        Ok(())
    }

    /// Query this filter for properties identified by `query`
    /// (one of the `CF_QUERY_*` constants).
    ///
    /// Returns a typed [`QueryResult`]. If this filter does not handle the
    /// query, return [`QueryResult::NotHandled`] so the chain can delegate
    /// to the next filter.
    ///
    /// Default: `QueryResult::NotHandled`, matching `Curl_cf_def_query`.
    fn query(&self, _query: i32) -> QueryResult {
        QueryResult::NotHandled
    }

    /// Whether this filter is in the connected state.
    ///
    /// A filter is connected after a successful [`connect`](Self::connect)
    /// call returns `Ok(true)` and before [`close`](Self::close) or a
    /// completed [`shutdown`](Self::shutdown).
    fn is_connected(&self) -> bool;

    /// Whether this filter has been gracefully shut down (via
    /// [`shutdown`](Self::shutdown) returning `Ok(true)`).
    fn is_shutdown(&self) -> bool;
}

// ===========================================================================
// FilterChain — managed collection of connection filters
// ===========================================================================

/// An ordered chain of connection filters.
///
/// Replaces the C `struct Curl_cfilter` linked-list (`cf->next` pointer
/// chain) with a `Vec<Box<dyn ConnectionFilter>>`. Index 0 is the
/// outermost ("top") filter; the last index is the innermost ("bottom",
/// typically the raw socket).
///
/// # Chain Operations
///
/// The chain exposes both management methods (add, insert, remove) and
/// operational methods (connect, send, recv, shutdown, control, query) that
/// delegate to the appropriate filter(s) in the chain.
pub struct FilterChain {
    filters: Vec<Box<dyn ConnectionFilter>>,
}

impl FilterChain {
    // -----------------------------------------------------------------------
    // Construction and management
    // -----------------------------------------------------------------------

    /// Creates a new empty filter chain.
    pub fn new() -> Self {
        Self {
            filters: Vec::new(),
        }
    }

    /// Adds a filter at the front (top / outermost position) of the chain.
    ///
    /// This matches the C `Curl_conn_cf_add` behaviour which inserts at the
    /// start of the linked list.
    pub fn push_front(&mut self, filter: Box<dyn ConnectionFilter>) {
        self.filters.insert(0, filter);
    }

    /// Inserts a filter immediately after position `index`.
    ///
    /// # Panics
    ///
    /// Panics if `index >= self.len()`.
    pub fn insert_after(&mut self, index: usize, filter: Box<dyn ConnectionFilter>) {
        assert!(
            index < self.filters.len(),
            "insert_after: index {} out of bounds (len = {})",
            index,
            self.filters.len()
        );
        self.filters.insert(index + 1, filter);
    }

    /// Removes and returns the filter at `index`.
    ///
    /// # Panics
    ///
    /// Panics if `index >= self.len()`.
    pub fn remove(&mut self, index: usize) -> Box<dyn ConnectionFilter> {
        assert!(
            index < self.filters.len(),
            "remove: index {} out of bounds (len = {})",
            index,
            self.filters.len()
        );
        self.filters.remove(index)
    }

    /// Removes and drops all filters in the chain, matching
    /// `Curl_conn_cf_discard_all` / `Curl_conn_cf_discard_chain`.
    pub fn discard_all(&mut self) {
        self.filters.clear();
    }

    /// Returns the number of filters in the chain.
    pub fn len(&self) -> usize {
        self.filters.len()
    }

    /// Returns `true` if the chain contains no filters.
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }

    /// Returns a reference to the filter at `index`, or `None` if out of
    /// bounds.
    pub fn get(&self, index: usize) -> Option<&dyn ConnectionFilter> {
        self.filters.get(index).map(|f| f.as_ref())
    }

    /// Returns a mutable reference to the boxed filter at `index`, or `None`
    /// if out of bounds.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Box<dyn ConnectionFilter>> {
        self.filters.get_mut(index)
    }

    // -----------------------------------------------------------------------
    // Chain operations — delegating to the appropriate filter(s)
    // -----------------------------------------------------------------------

    /// Drive the connection process through the entire filter chain.
    ///
    /// Iterates from the bottom (innermost) to the top (outermost). A filter
    /// is only asked to connect once all filters below it are connected.
    /// Returns `Ok(true)` when the entire chain is connected.
    ///
    /// This matches the logic of `Curl_conn_connect` in the C codebase.
    pub async fn connect(&mut self, data: &mut TransferData) -> Result<bool, CurlError> {
        if self.filters.is_empty() {
            return Err(CurlError::FailedInit);
        }

        // Walk from the bottom (last) to the top (first). Each filter should
        // only be asked to connect when all filters below it are already
        // connected.
        let len = self.filters.len();
        for i in (0..len).rev() {
            if self.filters[i].is_connected() {
                continue;
            }
            // Ensure all filters below this one are connected.
            let below_connected = (i + 1..len).all(|j| self.filters[j].is_connected());
            if !below_connected {
                // Need to connect lower filters first — they haven't finished
                // yet, so the whole chain is not ready.
                return Ok(false);
            }
            let done = self.filters[i].connect(data).await?;
            if !done {
                return Ok(false);
            }
        }

        // All filters connected.
        Ok(self.filters[0].is_connected())
    }

    /// Send data through the top (outermost) connected filter.
    ///
    /// The top filter is responsible for delegating down the chain as needed
    /// (e.g., a TLS filter encrypts and then writes to the socket filter
    /// below it).
    ///
    /// Matches `Curl_cf_send` — finds the first connected filter and sends.
    pub async fn send(&mut self, buf: &[u8], eos: bool) -> Result<usize, CurlError> {
        for filter in &mut self.filters {
            if filter.is_connected() {
                return filter.send(buf, eos).await;
            }
        }
        Err(CurlError::FailedInit)
    }

    /// Receive data from the top (outermost) connected filter.
    ///
    /// Matches `Curl_cf_recv` — finds the first connected filter and receives.
    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, CurlError> {
        for filter in &mut self.filters {
            if filter.is_connected() {
                return filter.recv(buf).await;
            }
        }
        Err(CurlError::FailedInit)
    }

    /// Close the connection through the top filter.
    ///
    /// Matches `Curl_conn_close` — closes the top filter, which is
    /// responsible for closing the chain below it.
    pub fn close(&mut self) {
        if let Some(filter) = self.filters.first_mut() {
            filter.close();
        }
    }

    /// Gracefully shut down the filter chain (non-blocking).
    ///
    /// Walks the chain to find the first connected, non-shutdown filter and
    /// calls shutdown on it. Once that filter completes shutdown, subsequent
    /// calls will proceed to the next filter down. Returns `Ok(true)` when
    /// the entire chain has been shut down.
    ///
    /// Matches the `Curl_conn_shutdown` logic in `lib/cfilters.c`.
    pub async fn shutdown(&mut self) -> Result<bool, CurlError> {
        for filter in &mut self.filters {
            if !filter.is_connected() || filter.is_shutdown() {
                continue;
            }
            let done = filter.shutdown().await?;
            if !done {
                // This filter is still shutting down; return false to indicate
                // the caller should retry.
                return Ok(false);
            }
            // This filter completed shutdown; continue to the next one.
        }
        // All filters are shut down (or were already).
        Ok(true)
    }

    /// Distribute a control event to all filters in the chain.
    ///
    /// If `ignore_result` is `true`, errors from individual filters are
    /// ignored and the event is sent to every filter. If `false`, the first
    /// filter error stops propagation ("first fail" semantics).
    ///
    /// Matches `Curl_conn_cf_cntrl` in `lib/cfilters.c`.
    pub fn control(
        &mut self,
        event: i32,
        arg1: i32,
        ignore_result: bool,
    ) -> Result<(), CurlError> {
        for filter in &mut self.filters {
            match filter.control(event, arg1) {
                Ok(()) => {}
                Err(e) => {
                    if !ignore_result {
                        return Err(e);
                    }
                    // When ignoring results, continue distributing to all filters.
                }
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // State queries
    // -----------------------------------------------------------------------

    /// Returns `true` if the top (outermost) filter is connected.
    ///
    /// Matches `Curl_conn_is_connected`.
    pub fn is_connected(&self) -> bool {
        self.filters
            .first()
            .is_some_and(|f| f.is_connected())
    }

    /// Returns `true` if any filter with the `CF_TYPE_IP_CONNECT` flag is
    /// connected. This indicates that the IP-level transport is established
    /// even if upper layers (e.g., TLS handshake) are still in progress.
    ///
    /// Matches `Curl_conn_is_ip_connected`.
    pub fn is_ip_connected(&self) -> bool {
        for filter in &self.filters {
            if filter.is_connected() {
                return true;
            }
            if filter.type_flags() & CF_TYPE_IP_CONNECT != 0 {
                return false;
            }
        }
        false
    }

    /// Returns `true` if any filter in the chain (above the IP-connect layer)
    /// has the `CF_TYPE_SSL` flag, indicating that the connection will use or
    /// is using SSL/TLS.
    ///
    /// Matches `Curl_conn_is_ssl` / `cf_is_ssl`.
    pub fn is_ssl(&self) -> bool {
        for filter in &self.filters {
            if filter.type_flags() & CF_TYPE_SSL != 0 {
                return true;
            }
            if filter.type_flags() & CF_TYPE_IP_CONNECT != 0 {
                return false;
            }
        }
        false
    }

    /// Returns `true` if the top filter considers the connection alive.
    ///
    /// Matches `Curl_conn_is_alive`.
    pub fn is_alive(&self) -> bool {
        self.filters
            .first()
            .is_some_and(|f| f.is_alive())
    }

    // -----------------------------------------------------------------------
    // Query chain — walk top-down, first non-NotHandled wins
    // -----------------------------------------------------------------------

    /// Query the filter chain for a property.
    ///
    /// Walks the chain from top to bottom. The first filter returning a
    /// [`QueryResult`] other than [`QueryResult::NotHandled`] provides the
    /// answer. If all filters return `NotHandled`, appropriate defaults are
    /// returned:
    /// - `CF_QUERY_MAX_CONCURRENT` → `Int(1)` (single-stream default).
    /// - `CF_QUERY_CONNECT_REPLY_MS` → `Int(-1)` (not determined).
    /// - All others → `NotHandled`.
    ///
    /// Matches the C `Curl_cf_def_query` chain-delegation pattern.
    pub fn query(&self, query: i32) -> QueryResult {
        for filter in &self.filters {
            let result = filter.query(query);
            if !matches!(result, QueryResult::NotHandled) {
                return result;
            }
        }
        // Default values when no filter handles the query.
        match query {
            CF_QUERY_MAX_CONCURRENT => QueryResult::Int(1),
            CF_QUERY_CONNECT_REPLY_MS => QueryResult::Int(-1),
            _ => QueryResult::NotHandled,
        }
    }
}

impl Default for FilterChain {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for FilterChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilterChain")
            .field("len", &self.filters.len())
            .field(
                "filters",
                &self
                    .filters
                    .iter()
                    .map(|flt| flt.name())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

// ===========================================================================
// Convenience Helper Functions
// ===========================================================================

/// Query the filter chain for the underlying socket file descriptor.
///
/// Returns `Some(fd)` if any filter in the chain handles `CF_QUERY_SOCKET`,
/// or `None` if no socket is available.
///
/// Matches `Curl_conn_cf_get_socket`.
#[cfg(unix)]
pub fn get_socket(chain: &FilterChain) -> Option<RawFd> {
    match chain.query(CF_QUERY_SOCKET) {
        QueryResult::Socket(fd) => Some(fd),
        _ => None,
    }
}

/// Query the filter chain for IP information.
///
/// Returns `Some((is_ipv6, addr))` if a filter handles `CF_QUERY_IP_INFO`.
///
/// Matches `Curl_conn_cf_get_ip_info`.
pub fn get_ip_info(chain: &FilterChain) -> Option<(bool, SocketAddr)> {
    match chain.query(CF_QUERY_IP_INFO) {
        QueryResult::Addr(addr) => {
            let is_ipv6 = addr.is_ipv6();
            Some((is_ipv6, addr))
        }
        _ => None,
    }
}

/// Query whether any filter in the chain has data pending to be flushed.
///
/// Matches `Curl_conn_cf_needs_flush`.
pub fn needs_flush(chain: &FilterChain) -> bool {
    match chain.query(CF_QUERY_NEED_FLUSH) {
        QueryResult::Bool(val) => val,
        QueryResult::Int(val) => val != 0,
        _ => false,
    }
}

/// Query the filter chain for the transport type.
///
/// Matches `Curl_conn_cf_get_transport`.
pub fn get_transport(chain: &FilterChain) -> Option<i32> {
    match chain.query(CF_QUERY_TRANSPORT) {
        QueryResult::Int(val) => Some(val),
        _ => None,
    }
}

/// Query the filter chain for the ALPN protocol negotiated during TLS.
///
/// Matches `Curl_conn_cf_get_alpn_negotiated`.
pub fn get_alpn_negotiated(chain: &FilterChain) -> Option<String> {
    match chain.query(CF_QUERY_ALPN_NEGOTIATED) {
        QueryResult::String(s) if !s.is_empty() => Some(s),
        _ => None,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal no-op filter used exclusively in tests to validate trait
    /// object safety and chain management operations.
    struct NoopFilter {
        filter_name: &'static str,
        flags: u32,
        connected: bool,
        shut_down: bool,
    }

    impl NoopFilter {
        fn new(name: &'static str, flags: u32) -> Self {
            Self {
                filter_name: name,
                flags,
                connected: false,
                shut_down: false,
            }
        }

        fn new_connected(name: &'static str, flags: u32) -> Self {
            Self {
                filter_name: name,
                flags,
                connected: true,
                shut_down: false,
            }
        }
    }

    #[async_trait]
    impl ConnectionFilter for NoopFilter {
        fn name(&self) -> &str {
            self.filter_name
        }

        fn type_flags(&self) -> u32 {
            self.flags
        }

        async fn connect(&mut self, _data: &mut TransferData) -> Result<bool, CurlError> {
            self.connected = true;
            Ok(true)
        }

        fn close(&mut self) {
            self.connected = false;
            self.shut_down = false;
        }

        async fn send(&mut self, buf: &[u8], _eos: bool) -> Result<usize, CurlError> {
            Ok(buf.len())
        }

        async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, CurlError> {
            let n = buf.len().min(64);
            buf[..n].fill(0);
            Ok(n)
        }

        fn is_connected(&self) -> bool {
            self.connected
        }

        fn is_shutdown(&self) -> bool {
            self.shut_down
        }
    }

    /// A filter that always returns an error on control, used for testing
    /// error propagation in `FilterChain::control`.
    struct FailingControlFilter {
        connected: bool,
    }

    #[async_trait]
    impl ConnectionFilter for FailingControlFilter {
        fn name(&self) -> &str {
            "failing-control"
        }
        fn type_flags(&self) -> u32 {
            0
        }
        async fn connect(&mut self, _data: &mut TransferData) -> Result<bool, CurlError> {
            self.connected = true;
            Ok(true)
        }
        fn close(&mut self) {
            self.connected = false;
        }
        async fn send(&mut self, _buf: &[u8], _eos: bool) -> Result<usize, CurlError> {
            Err(CurlError::SendError)
        }
        async fn recv(&mut self, _buf: &mut [u8]) -> Result<usize, CurlError> {
            Err(CurlError::RecvError)
        }
        fn control(&mut self, _event: i32, _arg1: i32) -> Result<(), CurlError> {
            Err(CurlError::BadFunctionArgument)
        }
        fn is_connected(&self) -> bool {
            self.connected
        }
        fn is_shutdown(&self) -> bool {
            false
        }
    }

    /// A filter that answers specific queries, used for testing query
    /// propagation.
    struct QueryableFilter {
        connected: bool,
    }

    #[async_trait]
    impl ConnectionFilter for QueryableFilter {
        fn name(&self) -> &str {
            "queryable"
        }
        fn type_flags(&self) -> u32 {
            CF_TYPE_IP_CONNECT
        }
        async fn connect(&mut self, _data: &mut TransferData) -> Result<bool, CurlError> {
            self.connected = true;
            Ok(true)
        }
        fn close(&mut self) {
            self.connected = false;
        }
        async fn send(&mut self, buf: &[u8], _eos: bool) -> Result<usize, CurlError> {
            Ok(buf.len())
        }
        async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, CurlError> {
            let n = buf.len().min(8);
            buf[..n].fill(0);
            Ok(n)
        }
        fn query(&self, query: i32) -> QueryResult {
            match query {
                CF_QUERY_MAX_CONCURRENT => QueryResult::Int(100),
                CF_QUERY_NEED_FLUSH => QueryResult::Bool(true),
                CF_QUERY_TRANSPORT => QueryResult::Int(1), // TCP
                CF_QUERY_ALPN_NEGOTIATED => QueryResult::String("h2".to_string()),
                CF_QUERY_IP_INFO | CF_QUERY_REMOTE_ADDR => {
                    QueryResult::Addr("127.0.0.1:8080".parse().unwrap())
                }
                _ => QueryResult::NotHandled,
            }
        }
        fn is_connected(&self) -> bool {
            self.connected
        }
        fn is_shutdown(&self) -> bool {
            false
        }
    }

    // -- Constant value tests -----------------------------------------------

    #[test]
    fn test_filter_type_flags_values() {
        assert_eq!(CF_TYPE_IP_CONNECT, 1);
        assert_eq!(CF_TYPE_SSL, 2);
        assert_eq!(CF_TYPE_MULTIPLEX, 4);
        assert_eq!(CF_TYPE_PROXY, 8);
        assert_eq!(CF_TYPE_HTTP, 16);
    }

    #[test]
    fn test_control_event_values() {
        assert_eq!(CF_CTRL_DATA_SETUP, 4);
        assert_eq!(CF_CTRL_DATA_PAUSE, 6);
        assert_eq!(CF_CTRL_DATA_DONE, 7);
        assert_eq!(CF_CTRL_DATA_DONE_SEND, 8);
        assert_eq!(CF_CTRL_CONN_INFO_UPDATE, 256);
        assert_eq!(CF_CTRL_FORGET_SOCKET, 257);
        assert_eq!(CF_CTRL_FLUSH, 258);
    }

    #[test]
    fn test_query_constant_values() {
        assert_eq!(CF_QUERY_MAX_CONCURRENT, 1);
        assert_eq!(CF_QUERY_CONNECT_REPLY_MS, 2);
        assert_eq!(CF_QUERY_SOCKET, 3);
        assert_eq!(CF_QUERY_TIMER_CONNECT, 4);
        assert_eq!(CF_QUERY_TIMER_APPCONNECT, 5);
        assert_eq!(CF_QUERY_STREAM_ERROR, 6);
        assert_eq!(CF_QUERY_NEED_FLUSH, 7);
        assert_eq!(CF_QUERY_IP_INFO, 8);
        assert_eq!(CF_QUERY_HTTP_VERSION, 9);
        assert_eq!(CF_QUERY_REMOTE_ADDR, 10);
        assert_eq!(CF_QUERY_HOST_PORT, 11);
        assert_eq!(CF_QUERY_SSL_INFO, 12);
        assert_eq!(CF_QUERY_SSL_CTX_INFO, 13);
        assert_eq!(CF_QUERY_TRANSPORT, 14);
        assert_eq!(CF_QUERY_ALPN_NEGOTIATED, 15);
    }

    #[test]
    fn test_ssl_constant_values() {
        assert_eq!(CURL_CF_SSL_DEFAULT, -1);
        assert_eq!(CURL_CF_SSL_DISABLE, 0);
        assert_eq!(CURL_CF_SSL_ENABLE, 1);
    }

    #[test]
    fn test_poll_action_values() {
        assert_eq!(PollAction::POLL_IN, 1);
        assert_eq!(PollAction::POLL_OUT, 2);
    }

    // -- PollSet tests ------------------------------------------------------

    #[test]
    #[cfg(unix)]
    fn test_pollset_add_and_entries() {
        let mut ps = PollSet::new();
        assert!(ps.entries().is_empty());

        ps.add(5, PollAction::POLL_IN);
        assert_eq!(ps.entries().len(), 1);
        assert_eq!(ps.entries()[0].socket, 5);
        assert_eq!(ps.entries()[0].actions, PollAction::POLL_IN);

        // Merge actions on same socket.
        ps.add(5, PollAction::POLL_OUT);
        assert_eq!(ps.entries().len(), 1);
        assert_eq!(
            ps.entries()[0].actions,
            PollAction::POLL_IN | PollAction::POLL_OUT
        );

        // Different socket.
        ps.add(10, PollAction::POLL_OUT);
        assert_eq!(ps.entries().len(), 2);
    }

    #[test]
    #[cfg(unix)]
    fn test_pollset_remove() {
        let mut ps = PollSet::new();
        ps.add(5, PollAction::POLL_IN | PollAction::POLL_OUT);
        ps.remove(5, PollAction::POLL_OUT);
        assert_eq!(ps.entries().len(), 1);
        assert_eq!(ps.entries()[0].actions, PollAction::POLL_IN);

        // Remove remaining action — entry removed entirely.
        ps.remove(5, PollAction::POLL_IN);
        assert!(ps.entries().is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn test_pollset_add_zero_removes() {
        let mut ps = PollSet::new();
        ps.add(5, PollAction::POLL_IN);
        ps.add(5, 0); // zero actions removes entry
        assert!(ps.entries().is_empty());
    }

    #[test]
    fn test_pollset_reset() {
        let mut ps = PollSet::new();
        #[cfg(unix)]
        {
            ps.add(1, PollAction::POLL_IN);
            ps.add(2, PollAction::POLL_OUT);
        }
        ps.reset();
        assert!(ps.entries().is_empty());
    }

    // -- FilterChain management tests ---------------------------------------

    #[test]
    fn test_chain_new_is_empty() {
        let chain = FilterChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
    }

    #[test]
    fn test_chain_default_is_empty() {
        let chain = FilterChain::default();
        assert!(chain.is_empty());
    }

    #[test]
    fn test_chain_push_front() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(NoopFilter::new("socket", CF_TYPE_IP_CONNECT)));
        chain.push_front(Box::new(NoopFilter::new("tls", CF_TYPE_SSL)));

        assert_eq!(chain.len(), 2);
        assert_eq!(chain.get(0).unwrap().name(), "tls");
        assert_eq!(chain.get(1).unwrap().name(), "socket");
    }

    #[test]
    fn test_chain_insert_after() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(NoopFilter::new("socket", CF_TYPE_IP_CONNECT)));
        chain.push_front(Box::new(NoopFilter::new("tls", CF_TYPE_SSL)));
        chain.insert_after(0, Box::new(NoopFilter::new("proxy", CF_TYPE_PROXY)));

        assert_eq!(chain.len(), 3);
        assert_eq!(chain.get(0).unwrap().name(), "tls");
        assert_eq!(chain.get(1).unwrap().name(), "proxy");
        assert_eq!(chain.get(2).unwrap().name(), "socket");
    }

    #[test]
    fn test_chain_remove() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(NoopFilter::new("socket", CF_TYPE_IP_CONNECT)));
        chain.push_front(Box::new(NoopFilter::new("tls", CF_TYPE_SSL)));

        let removed = chain.remove(0);
        assert_eq!(removed.name(), "tls");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.get(0).unwrap().name(), "socket");
    }

    #[test]
    fn test_chain_discard_all() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(NoopFilter::new("socket", CF_TYPE_IP_CONNECT)));
        chain.push_front(Box::new(NoopFilter::new("tls", CF_TYPE_SSL)));
        chain.discard_all();
        assert!(chain.is_empty());
    }

    #[test]
    fn test_chain_get_mut() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(NoopFilter::new("socket", CF_TYPE_IP_CONNECT)));
        assert!(chain.get_mut(0).is_some());
        assert!(chain.get_mut(1).is_none());
    }

    #[test]
    fn test_chain_get_out_of_bounds() {
        let chain = FilterChain::new();
        assert!(chain.get(0).is_none());
    }

    // -- FilterChain operation tests ----------------------------------------

    #[tokio::test]
    async fn test_chain_connect_empty_returns_error() {
        let mut chain = FilterChain::new();
        let mut data = TransferData::default();
        let result = chain.connect(&mut data).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::FailedInit);
    }

    #[tokio::test]
    async fn test_chain_connect_single_filter() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(NoopFilter::new("socket", CF_TYPE_IP_CONNECT)));
        let mut data = TransferData::default();
        let done = chain.connect(&mut data).await.unwrap();
        assert!(done);
        assert!(chain.is_connected());
    }

    #[tokio::test]
    async fn test_chain_connect_multi_filter() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(NoopFilter::new("socket", CF_TYPE_IP_CONNECT)));
        chain.push_front(Box::new(NoopFilter::new("tls", CF_TYPE_SSL)));
        let mut data = TransferData::default();
        let done = chain.connect(&mut data).await.unwrap();
        assert!(done);
        assert!(chain.is_connected());
    }

    #[tokio::test]
    async fn test_chain_send_recv() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(NoopFilter::new_connected(
            "socket",
            CF_TYPE_IP_CONNECT,
        )));
        let sent = chain.send(b"hello", false).await.unwrap();
        assert_eq!(sent, 5);

        let mut buf = [0u8; 32];
        let received = chain.recv(&mut buf).await.unwrap();
        assert!(received > 0);
    }

    #[tokio::test]
    async fn test_chain_send_no_connected_filter() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(NoopFilter::new("socket", CF_TYPE_IP_CONNECT)));
        let result = chain.send(b"data", false).await;
        assert_eq!(result.unwrap_err(), CurlError::FailedInit);
    }

    #[tokio::test]
    async fn test_chain_recv_no_connected_filter() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(NoopFilter::new("socket", CF_TYPE_IP_CONNECT)));
        let mut buf = [0u8; 32];
        let result = chain.recv(&mut buf).await;
        assert_eq!(result.unwrap_err(), CurlError::FailedInit);
    }

    #[tokio::test]
    async fn test_chain_shutdown() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(NoopFilter::new_connected(
            "socket",
            CF_TYPE_IP_CONNECT,
        )));
        let done = chain.shutdown().await.unwrap();
        assert!(done);
    }

    #[tokio::test]
    async fn test_chain_shutdown_empty() {
        let mut chain = FilterChain::new();
        let done = chain.shutdown().await.unwrap();
        assert!(done);
    }

    #[test]
    fn test_chain_close() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(NoopFilter::new_connected(
            "socket",
            CF_TYPE_IP_CONNECT,
        )));
        assert!(chain.is_connected());
        chain.close();
        assert!(!chain.is_connected());
    }

    #[test]
    fn test_chain_close_empty() {
        let mut chain = FilterChain::new();
        chain.close(); // should not panic
    }

    #[test]
    fn test_chain_control_first_fail() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(NoopFilter::new("socket", CF_TYPE_IP_CONNECT)));
        let result = chain.control(CF_CTRL_DATA_SETUP, 0, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_chain_control_first_fail_propagates_error() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(FailingControlFilter { connected: true }));
        chain.push_front(Box::new(NoopFilter::new("tls", CF_TYPE_SSL)));
        // The second filter (FailingControlFilter) should error, but it's
        // after the NoopFilter which succeeds. If the NoopFilter is first,
        // it succeeds and then the second filter fails.
        // Order: tls (index 0, succeeds), failing-control (index 1, fails)
        let result = chain.control(CF_CTRL_FLUSH, 0, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_chain_control_ignore_result() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(FailingControlFilter { connected: true }));
        let result = chain.control(CF_CTRL_DATA_DONE, 1, true);
        assert!(result.is_ok());
    }

    // -- State query tests --------------------------------------------------

    #[test]
    fn test_chain_is_ip_connected() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(NoopFilter::new_connected(
            "socket",
            CF_TYPE_IP_CONNECT,
        )));
        chain.push_front(Box::new(NoopFilter::new("tls", CF_TYPE_SSL)));
        // TLS is not connected but socket (IP) is — first filter checked is
        // tls (not connected), but it doesn't have IP_CONNECT flag, so we
        // continue. Socket has IP_CONNECT flag and is connected.
        assert!(chain.is_ip_connected());
    }

    #[test]
    fn test_chain_is_ip_connected_none_connected() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(NoopFilter::new("socket", CF_TYPE_IP_CONNECT)));
        // Socket has IP_CONNECT flag but is not connected.
        assert!(!chain.is_ip_connected());
    }

    #[test]
    fn test_chain_is_ssl() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(NoopFilter::new("socket", CF_TYPE_IP_CONNECT)));
        assert!(!chain.is_ssl());

        chain.push_front(Box::new(NoopFilter::new("tls", CF_TYPE_SSL)));
        assert!(chain.is_ssl());
    }

    #[test]
    fn test_chain_is_alive_empty() {
        let chain = FilterChain::new();
        assert!(!chain.is_alive());
    }

    #[test]
    fn test_chain_is_alive_with_filter() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(NoopFilter::new_connected(
            "socket",
            CF_TYPE_IP_CONNECT,
        )));
        assert!(chain.is_alive());
    }

    // -- Query chain tests --------------------------------------------------

    #[test]
    fn test_query_default_max_concurrent() {
        let chain = FilterChain::new();
        match chain.query(CF_QUERY_MAX_CONCURRENT) {
            QueryResult::Int(1) => {}
            other => panic!("expected Int(1), got {:?}", other),
        }
    }

    #[test]
    fn test_query_default_connect_reply_ms() {
        let chain = FilterChain::new();
        match chain.query(CF_QUERY_CONNECT_REPLY_MS) {
            QueryResult::Int(-1) => {}
            other => panic!("expected Int(-1), got {:?}", other),
        }
    }

    #[test]
    fn test_query_unhandled() {
        let chain = FilterChain::new();
        assert!(matches!(
            chain.query(CF_QUERY_SOCKET),
            QueryResult::NotHandled
        ));
    }

    #[test]
    fn test_query_from_queryable_filter() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(QueryableFilter { connected: true }));

        match chain.query(CF_QUERY_MAX_CONCURRENT) {
            QueryResult::Int(100) => {}
            other => panic!("expected Int(100), got {:?}", other),
        }

        match chain.query(CF_QUERY_NEED_FLUSH) {
            QueryResult::Bool(true) => {}
            other => panic!("expected Bool(true), got {:?}", other),
        }

        match chain.query(CF_QUERY_TRANSPORT) {
            QueryResult::Int(1) => {}
            other => panic!("expected Int(1), got {:?}", other),
        }

        match chain.query(CF_QUERY_ALPN_NEGOTIATED) {
            QueryResult::String(ref s) if s == "h2" => {}
            other => panic!("expected String(\"h2\"), got {:?}", other),
        }
    }

    // -- Convenience helper tests -------------------------------------------

    #[test]
    fn test_needs_flush_empty_chain() {
        let chain = FilterChain::new();
        assert!(!needs_flush(&chain));
    }

    #[test]
    fn test_needs_flush_with_queryable() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(QueryableFilter { connected: true }));
        assert!(needs_flush(&chain));
    }

    #[test]
    fn test_get_transport_empty_chain() {
        let chain = FilterChain::new();
        assert!(get_transport(&chain).is_none());
    }

    #[test]
    fn test_get_transport_with_queryable() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(QueryableFilter { connected: true }));
        assert_eq!(get_transport(&chain), Some(1));
    }

    #[test]
    fn test_get_alpn_negotiated_empty_chain() {
        let chain = FilterChain::new();
        assert!(get_alpn_negotiated(&chain).is_none());
    }

    #[test]
    fn test_get_alpn_negotiated_with_queryable() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(QueryableFilter { connected: true }));
        assert_eq!(get_alpn_negotiated(&chain), Some("h2".to_string()));
    }

    #[test]
    fn test_get_ip_info_empty_chain() {
        let chain = FilterChain::new();
        assert!(get_ip_info(&chain).is_none());
    }

    #[test]
    fn test_get_ip_info_with_queryable() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(QueryableFilter { connected: true }));
        let info = get_ip_info(&chain).unwrap();
        assert!(!info.0); // IPv4
        assert_eq!(info.1, "127.0.0.1:8080".parse().unwrap());
    }

    // -- Debug formatting ---------------------------------------------------

    #[test]
    fn test_filter_chain_debug() {
        let mut chain = FilterChain::new();
        chain.push_front(Box::new(NoopFilter::new("socket", CF_TYPE_IP_CONNECT)));
        chain.push_front(Box::new(NoopFilter::new("tls", CF_TYPE_SSL)));
        let debug_str = format!("{:?}", chain);
        assert!(debug_str.contains("FilterChain"));
        assert!(debug_str.contains("tls"));
        assert!(debug_str.contains("socket"));
    }

    #[test]
    fn test_transfer_data_default() {
        let data = TransferData::default();
        assert!(!data.verbose);
        assert_eq!(data.timeout_ms, 0);
        assert!(!data.close_connection);
    }

    // -- Object safety verification -----------------------------------------

    #[test]
    fn test_trait_object_safety() {
        // Verify that ConnectionFilter is object-safe by creating a
        // Box<dyn ConnectionFilter>.
        let _boxed: Box<dyn ConnectionFilter> =
            Box::new(NoopFilter::new("test", 0));
    }

    #[test]
    fn test_query_result_clone() {
        let q1 = QueryResult::Int(42);
        let q2 = q1.clone();
        assert!(matches!(q2, QueryResult::Int(42)));

        let q3 = QueryResult::String("h2".to_string());
        let q4 = q3.clone();
        assert!(matches!(q4, QueryResult::String(ref s) if s == "h2"));
    }
}
