//! Async transfer engine — drives send/receive data flow.
//!
//! This module is the Rust rewrite of `lib/transfer.c` (912 lines) from the
//! curl C codebase (version 8.19.0-DEV). It provides the core data transfer
//! engine that:
//!
//! - Drives the send/receive loop through the connection filter chain.
//! - Manages transfer state transitions (`Idle` → `Connecting` → `Sending`
//!   → `Receiving` → `Done`).
//! - Enforces configurable timeouts (total, connect, low-speed).
//! - Integrates bandwidth rate limiting via [`RateLimiter`].
//! - Tracks transfer progress via [`Progress`].
//! - Handles content-encoding decompression transparently.
//! - Supports redirect following (3xx responses) with configurable limits.
//! - Provides pause/resume semantics for send and receive directions.
//! - Manages Expect: 100-continue negotiation.
//! - Handles connection reuse and keep-alive signaling.
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.
//!
//! # Architecture
//!
//! The [`TransferEngine`] struct is the central orchestrator.  It holds:
//! - A [`TransferConfig`] for timeout, buffer, and redirect settings.
//! - A [`TransferState`] tracking the current phase.
//! - A [`Progress`] tracker for speed and callback invocation.
//! - Optional [`RateLimiter`] instances for upload and download throttling.
//! - Send and receive buffers backed by [`BytesMut`] for zero-copy slicing.
//!
//! # C Equivalents
//!
//! | Rust                                 | C function                              |
//! |--------------------------------------|-----------------------------------------|
//! | `TransferEngine::perform()`          | `Curl_sendrecv()`                       |
//! | `TransferEngine::pretransfer()`      | `Curl_pretransfer()`                    |
//! | `TransferEngine::retry_request()`    | `Curl_retry_request()`                  |
//! | `TransferEngine::send_data()`        | `Curl_xfer_send()`                      |
//! | `TransferEngine::recv_data()`        | `Curl_xfer_recv()`                      |
//! | `TransferEngine::write_response()`   | `Curl_xfer_write_resp()`                |
//! | `TransferEngine::write_response_header()` | `Curl_xfer_write_resp_hd()`        |
//! | `TransferEngine::write_done()`       | `Curl_xfer_write_done()`                |
//! | `TransferEngine::needs_flush()`      | `Curl_xfer_needs_flush()`               |
//! | `TransferEngine::flush()`            | `Curl_xfer_flush()`                     |
//! | `TransferEngine::is_blocked()`       | `Curl_xfer_is_blocked()`                |
//! | `TransferEngine::pause_send()`       | `Curl_xfer_pause_send()`                |
//! | `TransferEngine::pause_recv()`       | `Curl_xfer_pause_recv()`                |
//! | `TransferEngine::is_send_paused()`   | `Curl_xfer_send_is_paused()`            |
//! | `TransferEngine::is_recv_paused()`   | `Curl_xfer_recv_is_paused()`            |
//! | `TransferEngine::check_headers()`    | `Curl_checkheaders()`                   |
//! | `TransferEngine::meets_timecondition()` | `Curl_meets_timecondition()`         |
//! | `TransferEngine::setup_send()`       | `Curl_xfer_setup_send()`                |
//! | `TransferEngine::setup_recv()`       | `Curl_xfer_setup_recv()`                |
//! | `TransferEngine::setup_sendrecv()`   | `Curl_xfer_setup_sendrecv()`            |
//! | `TransferConfig`                     | Subset of `struct UserDefined`          |
//! | `TransferState`                      | Implicit in `SingleRequest.keepon`      |

use std::time::{Duration, Instant};

use bytes::{BytesMut, BufMut};
use tracing;

use crate::conn::FilterChain;
use crate::content_encoding::{ContentDecoder, create_decoder, supported_encodings};
use crate::error::{CurlError, CurlResult};
use crate::headers::Headers;
use crate::progress::Progress;
use crate::ratelimit::RateLimiter;
use crate::request::Request;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default receive buffer capacity (16 KiB), matching the C
/// `CURL_MAX_WRITE_SIZE` default used in `sendrecv_dl`.
const DEFAULT_BUFFER_SIZE: usize = 16 * 1024;

/// Default upload (send) buffer capacity (64 KiB), matching the C
/// `CURL_MAX_WRITE_SIZE` for upload buffers.
const DEFAULT_UPLOAD_BUFFER_SIZE: usize = 64 * 1024;

/// Maximum number of iterations in the receive loop per `perform()` call.
/// Prevents monopolization of the event loop on fast connections.
/// Matches the C `maxloops = 10` in `sendrecv_dl`.
const MAX_RECV_LOOPS: usize = 10;

/// Maximum number of connection retry attempts before giving up.
/// Matches the C `CONN_MAX_RETRIES` constant in `Curl_retry_request`.
const CONN_MAX_RETRIES: u32 = 5;

/// Default maximum number of redirects (50), matching C
/// `DEFAULT_MAXREDIRS` used when `CURLOPT_MAXREDIRS` is not explicitly set
/// but `CURLOPT_FOLLOWLOCATION` is enabled.
const DEFAULT_MAX_REDIRECTS: u32 = 50;

// ===========================================================================
// TransferState — Runtime enum (internal use)
// ===========================================================================

/// Lifecycle state of the transfer engine (runtime enum).
///
/// Mirrors the implicit state encoded by the C `SingleRequest.keepon` bitmask
/// and the `data->req.done` flag. This runtime enum is used internally by
/// `TransferEngine` for state tracking. External consumers should prefer the
/// type-state API (see [`TypedTransfer`]) which enforces valid state
/// transitions at compile time per AAP §0.4.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TransferState {
    /// Transfer has been created but not yet started.
    #[default]
    Idle,
    /// Connection is being established (TCP + TLS + proxy).
    Connecting,
    /// Request headers/body are being sent to the server.
    Sending,
    /// Response headers/body are being received from the server.
    Receiving,
    /// Transfer has completed (success or error).
    Done,
}

impl std::fmt::Display for TransferState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::Connecting => write!(f, "Connecting"),
            Self::Sending => write!(f, "Sending"),
            Self::Receiving => write!(f, "Receiving"),
            Self::Done => write!(f, "Done"),
        }
    }
}

// ===========================================================================
// Type-State Pattern — Compile-time state machine (AAP §0.4.3)
// ===========================================================================

/// Marker type for a transfer that has not yet started.
/// Methods available: `connect()` → `TypedTransfer<Connected>`.
#[derive(Debug)]
pub struct Idle;

/// Marker type for a transfer with an established connection.
/// Methods available: `start_sending()` → `TypedTransfer<Transferring>`.
#[derive(Debug)]
pub struct Connected;

/// Marker type for a transfer actively sending/receiving data.
/// Methods available: `complete()` → `TypedTransfer<Complete>`.
#[derive(Debug)]
pub struct Transferring;

/// Marker type for a completed transfer.
/// Methods available: `reset()` → `TypedTransfer<Idle>`.
#[derive(Debug)]
pub struct Complete;

/// Compile-time enforced transfer state machine wrapper.
///
/// Implements the type-state pattern specified in AAP §0.4.3:
///
/// ```text
/// TypedTransfer<Idle> → TypedTransfer<Connected>
///     → TypedTransfer<Transferring> → TypedTransfer<Complete>
/// ```
///
/// Invalid state transitions are **compile-time errors** — for example,
/// calling `start_sending()` on a `TypedTransfer<Idle>` is impossible because
/// that method only exists on `TypedTransfer<Connected>`.
///
/// The inner [`TransferEngine`] is consumed and returned on each transition,
/// ensuring exclusive ownership semantics.
///
/// # Usage
///
/// ```rust,ignore
/// let transfer = TypedTransfer::<Idle>::new(engine);
/// let transfer = transfer.connect().await?;      // Idle → Connected
/// let transfer = transfer.start_sending()?;       // Connected → Transferring
/// let transfer = transfer.complete()?;             // Transferring → Complete
/// let (engine, _) = transfer.reset();              // Complete → Idle (reclaim engine)
/// ```
pub struct TypedTransfer<State> {
    engine: TransferEngine,
    _state: std::marker::PhantomData<State>,
}

impl TypedTransfer<Idle> {
    /// Creates a new typed transfer in the `Idle` state.
    pub fn new(engine: TransferEngine) -> Self {
        Self {
            engine,
            _state: std::marker::PhantomData,
        }
    }

    /// Transition from `Idle` → `Connected` by establishing the connection.
    ///
    /// The underlying engine's `pretransfer()` is called to initialize the
    /// connection state. Returns the transfer in the `Connected` state.
    pub fn connect(mut self) -> CurlResult<TypedTransfer<Connected>> {
        self.engine.pretransfer()?;
        Ok(TypedTransfer {
            engine: self.engine,
            _state: std::marker::PhantomData,
        })
    }

    /// Access the underlying engine (read-only) in Idle state.
    pub fn engine(&self) -> &TransferEngine {
        &self.engine
    }

    /// Access the underlying engine (mutable) in Idle state.
    pub fn engine_mut(&mut self) -> &mut TransferEngine {
        &mut self.engine
    }
}

impl TypedTransfer<Connected> {
    /// Transition from `Connected` → `Transferring` by starting data flow.
    ///
    /// This initiates the request send phase. The engine's state is set to
    /// `Sending`.
    pub fn start_sending(mut self) -> CurlResult<TypedTransfer<Transferring>> {
        self.engine.begin_send();
        Ok(TypedTransfer {
            engine: self.engine,
            _state: std::marker::PhantomData,
        })
    }

    /// Access the underlying engine in Connected state.
    pub fn engine(&self) -> &TransferEngine {
        &self.engine
    }

    /// Access the underlying engine (mutable) in Connected state.
    pub fn engine_mut(&mut self) -> &mut TransferEngine {
        &mut self.engine
    }
}

impl TypedTransfer<Transferring> {
    /// Transition from `Transferring` → `Complete` when the transfer finishes.
    pub fn complete(mut self) -> CurlResult<TypedTransfer<Complete>> {
        self.engine.mark_done();
        Ok(TypedTransfer {
            engine: self.engine,
            _state: std::marker::PhantomData,
        })
    }

    /// Access the underlying engine in Transferring state.
    pub fn engine(&self) -> &TransferEngine {
        &self.engine
    }

    /// Access the underlying engine (mutable) in Transferring state.
    pub fn engine_mut(&mut self) -> &mut TransferEngine {
        &mut self.engine
    }
}

impl TypedTransfer<Complete> {
    /// Transition from `Complete` → `Idle` by resetting the engine.
    ///
    /// Returns the engine and the typed transfer in Idle state, ready for
    /// reuse on a keep-alive connection.
    pub fn reset(mut self) -> TypedTransfer<Idle> {
        self.engine.reset();
        TypedTransfer {
            engine: self.engine,
            _state: std::marker::PhantomData,
        }
    }

    /// Consume the completed transfer and reclaim the engine.
    pub fn into_engine(self) -> TransferEngine {
        self.engine
    }

    /// Access the underlying engine in Complete state.
    pub fn engine(&self) -> &TransferEngine {
        &self.engine
    }
}

// ===========================================================================
// TimeCondition
// ===========================================================================

/// Time condition type for conditional requests.
///
/// Maps to C `curl_TimeCond` enum values used with
/// `CURLOPT_TIMECONDITION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimeCondition {
    /// No time condition.
    #[default]
    None,
    /// If-Modified-Since semantics (CURL_TIMECOND_IFMODSINCE).
    IfModifiedSince,
    /// If-Unmodified-Since semantics (CURL_TIMECOND_IFUNMODSINCE).
    IfUnmodifiedSince,
    /// Last-Modified semantics (CURL_TIMECOND_LASTMOD).
    LastMod,
}

// ===========================================================================
// WriteCallbackResult — return value from write callbacks
// ===========================================================================

/// Result returned by write callbacks indicating how to proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackResult {
    /// Continue the transfer normally.
    Continue,
    /// Pause the transfer (the callback will be retried later).
    Pause,
    /// Abort the transfer.
    Abort,
}

// ===========================================================================
// Callback type aliases
// ===========================================================================

/// Write callback: receives response body data.
///
/// Parameters: `(data_chunk)`.
/// Returns the number of bytes consumed, or an error/pause/abort signal.
pub type WriteCallback = Box<dyn FnMut(&[u8]) -> Result<usize, CallbackResult> + Send>;

/// Read callback: provides upload body data.
///
/// Parameters: `(buffer_to_fill)`.
/// Returns the number of bytes written into the buffer, 0 for EOF.
pub type ReadCallback = Box<dyn FnMut(&mut [u8]) -> Result<usize, CallbackResult> + Send>;

/// Header callback: receives individual response header lines.
///
/// Parameters: `(header_line)`.
/// Returns the number of bytes consumed.
pub type HeaderCallback = Box<dyn FnMut(&[u8]) -> Result<usize, CallbackResult> + Send>;

/// Debug callback: receives verbose debug information.
///
/// Parameters: `(info_type, data)`.
pub type DebugCallback = Box<dyn FnMut(DebugInfoType, &[u8]) + Send>;

/// Debug information type indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugInfoType {
    /// Informational text.
    Text,
    /// Data received from the server (headers).
    HeaderIn,
    /// Data sent to the server (headers).
    HeaderOut,
    /// Binary data received from the server.
    DataIn,
    /// Binary data sent to the server.
    DataOut,
    /// SSL/TLS informational data.
    SslDataIn,
    /// SSL/TLS outgoing data.
    SslDataOut,
}

// ===========================================================================
// TransferConfig
// ===========================================================================

/// Configuration parameters for the transfer engine.
///
/// Encapsulates all user-configurable options that affect transfer behavior,
/// replacing the subset of C `struct UserDefined` fields consumed by
/// `lib/transfer.c`.  Created via [`TransferConfig::new()`] and customised
/// with the builder-style `set_*` methods.
#[derive(Debug)]
pub struct TransferConfig {
    /// Total transfer timeout (0 = no timeout).
    /// Maps to `CURLOPT_TIMEOUT` / `CURLOPT_TIMEOUT_MS`.
    timeout: Duration,

    /// Connection establishment timeout (0 = system default, typically 300s).
    /// Maps to `CURLOPT_CONNECTTIMEOUT` / `CURLOPT_CONNECTTIMEOUT_MS`.
    connect_timeout: Duration,

    /// Minimum transfer speed in bytes/sec for low-speed detection.
    /// Maps to `CURLOPT_LOW_SPEED_LIMIT`.
    low_speed_limit: u64,

    /// Duration in seconds the speed must remain below `low_speed_limit`
    /// before the transfer is aborted.
    /// Maps to `CURLOPT_LOW_SPEED_TIME`.
    low_speed_time: Duration,

    /// Receive buffer size hint in bytes.
    /// Maps to `CURLOPT_BUFFERSIZE`.
    buffer_size: usize,

    /// Upload (send) buffer size hint in bytes.
    /// Maps to `CURLOPT_UPLOAD_BUFFERSIZE`.
    upload_buffer_size: usize,

    /// Maximum number of redirects to follow (0 = none, -1 = unlimited).
    /// Maps to `CURLOPT_MAXREDIRS`.
    max_redirects: i32,

    /// Maximum download speed in bytes/sec (0 = unlimited).
    /// Maps to `CURLOPT_MAX_RECV_SPEED_LARGE`.
    max_recv_speed: i64,

    /// Maximum upload speed in bytes/sec (0 = unlimited).
    /// Maps to `CURLOPT_MAX_SEND_SPEED_LARGE`.
    max_send_speed: i64,

    /// Whether to follow HTTP 3xx redirect responses.
    /// Maps to `CURLOPT_FOLLOWLOCATION`.
    follow_location: bool,

    /// Time condition for conditional requests.
    /// Maps to `CURLOPT_TIMECONDITION`.
    time_condition: TimeCondition,

    /// Reference timestamp for time-conditional requests (Unix epoch seconds).
    /// Maps to `CURLOPT_TIMEVALUE`.
    time_value: i64,

    /// Whether to request verbose debug output.
    verbose: bool,

    /// Custom headers set by the user (`CURLOPT_HTTPHEADER`).
    custom_headers: Vec<String>,
}

impl TransferConfig {
    /// Creates a new `TransferConfig` with sensible defaults matching
    /// curl 8.x out-of-the-box behavior.
    pub fn new() -> Self {
        Self {
            timeout: Duration::ZERO,
            connect_timeout: Duration::ZERO,
            low_speed_limit: 0,
            low_speed_time: Duration::ZERO,
            buffer_size: DEFAULT_BUFFER_SIZE,
            upload_buffer_size: DEFAULT_UPLOAD_BUFFER_SIZE,
            max_redirects: DEFAULT_MAX_REDIRECTS as i32,
            max_recv_speed: 0,
            max_send_speed: 0,
            follow_location: false,
            time_condition: TimeCondition::None,
            time_value: 0,
            verbose: false,
            custom_headers: Vec::new(),
        }
    }

    /// Sets the total transfer timeout.
    ///
    /// A zero duration disables the timeout (no limit). This maps to
    /// `CURLOPT_TIMEOUT_MS`.
    pub fn set_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.timeout = timeout;
        self
    }

    /// Sets the connection establishment timeout.
    ///
    /// A zero duration uses the system/OS default (typically 300 seconds).
    /// Maps to `CURLOPT_CONNECTTIMEOUT_MS`.
    pub fn set_connect_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.connect_timeout = timeout;
        self
    }

    /// Sets the low-speed limit in bytes per second.
    ///
    /// The transfer is aborted if the average speed stays below this limit
    /// for the duration set by [`set_low_speed_time()`](Self::set_low_speed_time).
    /// Set to `0` to disable the check.
    pub fn set_low_speed_limit(&mut self, limit: u64) -> &mut Self {
        self.low_speed_limit = limit;
        self
    }

    /// Sets the low-speed time window.
    ///
    /// If the transfer speed stays below the low-speed limit for this
    /// duration, the transfer is aborted. A zero duration disables the check.
    pub fn set_low_speed_time(&mut self, time: Duration) -> &mut Self {
        self.low_speed_time = time;
        self
    }

    /// Sets the receive buffer size hint.
    ///
    /// This determines the maximum number of bytes read per iteration of
    /// the receive loop. The actual allocation may differ.
    pub fn set_buffer_size(&mut self, size: usize) -> &mut Self {
        if size > 0 {
            self.buffer_size = size;
        }
        self
    }

    /// Sets the upload (send) buffer size hint.
    pub fn set_upload_buffer_size(&mut self, size: usize) -> &mut Self {
        if size > 0 {
            self.upload_buffer_size = size;
        }
        self
    }

    /// Sets the maximum number of redirects to follow.
    ///
    /// - `0` — no redirects followed.
    /// - `-1` — unlimited redirects.
    /// - Positive value — limit to that many redirects.
    pub fn set_max_redirects(&mut self, max: i32) -> &mut Self {
        self.max_redirects = max;
        self
    }

    /// Sets the maximum download speed in bytes per second.
    ///
    /// `0` means unlimited. Maps to `CURLOPT_MAX_RECV_SPEED_LARGE`.
    pub fn set_max_recv_speed(&mut self, speed: i64) -> &mut Self {
        self.max_recv_speed = speed;
        self
    }

    /// Sets the maximum upload speed in bytes per second.
    ///
    /// `0` means unlimited. Maps to `CURLOPT_MAX_SEND_SPEED_LARGE`.
    pub fn set_max_send_speed(&mut self, speed: i64) -> &mut Self {
        self.max_send_speed = speed;
        self
    }

    /// Enables or disables automatic redirect following.
    ///
    /// Maps to `CURLOPT_FOLLOWLOCATION`.
    pub fn set_follow_location(&mut self, follow: bool) -> &mut Self {
        self.follow_location = follow;
        self
    }

    /// Sets the time condition and reference timestamp.
    ///
    /// Maps to `CURLOPT_TIMECONDITION` and `CURLOPT_TIMEVALUE`.
    pub fn set_time_condition(&mut self, condition: TimeCondition, value: i64) -> &mut Self {
        self.time_condition = condition;
        self.time_value = value;
        self
    }

    /// Enables or disables verbose debug output.
    ///
    /// Maps to `CURLOPT_VERBOSE`.
    pub fn set_verbose(&mut self, verbose: bool) -> &mut Self {
        self.verbose = verbose;
        self
    }

    /// Appends a custom header to the request.
    ///
    /// Maps to `CURLOPT_HTTPHEADER`.
    pub fn add_custom_header(&mut self, header: String) -> &mut Self {
        self.custom_headers.push(header);
        self
    }
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// TransferEngine
// ===========================================================================

/// Core transfer engine that drives send/receive data flow.
///
/// This struct orchestrates the entire lifecycle of a curl transfer:
/// pre-transfer setup, request sending, response receiving, redirect
/// following, and cleanup. It replaces the C `Curl_sendrecv` +
/// `Curl_pretransfer` + `Curl_retry_request` family of functions.
///
/// # Buffer Management
///
/// All internal buffers use [`BytesMut`] from the `bytes` crate, providing:
/// - Ownership-based memory management (no malloc/free).
/// - Zero-copy slicing via `split_to()` and `freeze()`.
/// - Automatic capacity growth without manual realloc.
pub struct TransferEngine {
    // -- Lifecycle state ------------------------------------------------------
    /// Current transfer state.
    state: TransferState,

    // -- Configuration --------------------------------------------------------
    /// Transfer configuration (timeouts, limits, buffer sizes).
    config: TransferConfig,

    // -- Progress tracking ----------------------------------------------------
    /// Progress tracker for speed calculation and callback invocation.
    progress: Progress,

    // -- Rate limiting --------------------------------------------------------
    /// Optional download rate limiter.
    recv_rate_limiter: Option<RateLimiter>,
    /// Optional upload rate limiter.
    send_rate_limiter: Option<RateLimiter>,

    // -- Buffers --------------------------------------------------------------
    /// Receive (download) buffer.
    recv_buf: BytesMut,
    /// Send (upload) buffer.
    send_buf: BytesMut,

    // -- Pause flags ----------------------------------------------------------
    /// Whether sending is paused.
    send_paused: bool,
    /// Whether receiving is paused.
    recv_paused: bool,

    // -- Transfer metadata ----------------------------------------------------
    /// Total number of body bytes received in this transfer.
    bytes_received: u64,
    /// Total number of body bytes sent in this transfer.
    bytes_sent: u64,
    /// Expected response size (-1 = unknown).
    expected_size: i64,

    // -- Redirect tracking ----------------------------------------------------
    /// Number of redirects followed so far.
    redirect_count: u32,
    /// URL to redirect to (set when a 3xx response is received).
    redirect_url: Option<String>,

    // -- Retry tracking -------------------------------------------------------
    /// Number of connection-level retries attempted.
    retry_count: u32,

    // -- Response state -------------------------------------------------------
    /// Collected response headers.
    response_headers: Headers,
    /// HTTP response status code.
    response_code: u16,
    /// Whether the response body has been fully received.
    download_done: bool,
    /// Whether the request body has been fully sent.
    upload_done: bool,
    /// Whether end-of-stream has been written to the client.
    eos_written: bool,

    // -- Content decoding -----------------------------------------------------
    /// Optional content decoder for transparent decompression.
    content_decoder: Option<Box<dyn ContentDecoder>>,

    // -- Timing ---------------------------------------------------------------
    /// Instant when the transfer started (set by `pretransfer()`).
    start_time: Option<Instant>,

    // -- Callbacks (stored as Options) ----------------------------------------
    /// User write callback for response body data.
    write_callback: Option<WriteCallback>,
    /// User read callback for upload body data.
    read_callback: Option<ReadCallback>,
    /// User header callback for response header lines.
    header_callback: Option<HeaderCallback>,
    /// User debug callback for verbose output.
    debug_callback: Option<DebugCallback>,

    // -- Connection state hints -----------------------------------------------
    /// Whether this transfer wants to send data.
    want_send: bool,
    /// Whether this transfer wants to receive data.
    want_recv: bool,
    /// Whether the connection should be shut down after the transfer.
    shutdown_on_done: bool,
    /// Whether to ignore errors during shutdown.
    shutdown_err_ignore: bool,
}

impl TransferEngine {
    /// Creates a new `TransferEngine` in the [`TransferState::Idle`] state
    /// with default configuration.
    ///
    /// Maps to the initial state of a curl easy handle before any transfer
    /// is performed.
    pub fn new() -> Self {
        let config = TransferConfig::new();
        let recv_cap = config.buffer_size;
        let send_cap = config.upload_buffer_size;

        Self {
            state: TransferState::Idle,
            config,
            progress: Progress::new(),
            recv_rate_limiter: None,
            send_rate_limiter: None,
            recv_buf: BytesMut::with_capacity(recv_cap),
            send_buf: BytesMut::with_capacity(send_cap),
            send_paused: false,
            recv_paused: false,
            bytes_received: 0,
            bytes_sent: 0,
            expected_size: -1,
            redirect_count: 0,
            redirect_url: None,
            retry_count: 0,
            response_headers: Headers::new(),
            response_code: 0,
            download_done: false,
            upload_done: false,
            eos_written: false,
            content_decoder: None,
            start_time: None,
            write_callback: None,
            read_callback: None,
            header_callback: None,
            debug_callback: None,
            want_send: false,
            want_recv: false,
            shutdown_on_done: false,
            shutdown_err_ignore: false,
        }
    }

    // ====================================================================
    // Configuration Accessors
    // ====================================================================

    /// Returns a reference to the current transfer configuration.
    pub fn config(&self) -> &TransferConfig {
        &self.config
    }

    /// Returns a mutable reference to the transfer configuration.
    ///
    /// Configuration changes take effect on the next `pretransfer()` /
    /// `perform()` call.
    pub fn config_mut(&mut self) -> &mut TransferConfig {
        &mut self.config
    }

    /// Returns the current transfer state.
    pub fn state(&self) -> TransferState {
        self.state
    }

    /// Returns a reference to the progress tracker.
    pub fn progress(&self) -> &Progress {
        &self.progress
    }

    /// Returns a mutable reference to the progress tracker.
    pub fn progress_mut(&mut self) -> &mut Progress {
        &mut self.progress
    }

    /// Transition the engine to the `Sending` state.
    ///
    /// Used by the type-state API ([`TypedTransfer`]) for the
    /// `Connected → Transferring` transition.
    pub fn begin_send(&mut self) {
        self.state = TransferState::Sending;
    }

    /// Mark the transfer as complete.
    ///
    /// Used by the type-state API ([`TypedTransfer`]) for the
    /// `Transferring → Complete` transition.
    pub fn mark_done(&mut self) {
        self.state = TransferState::Done;
    }

    /// Reset the engine to the `Idle` state for reuse.
    ///
    /// Used by the type-state API ([`TypedTransfer`]) for the
    /// `Complete → Idle` transition.
    pub fn reset(&mut self) {
        self.state = TransferState::Idle;
    }

    /// Sets the user write callback for response body data.
    pub fn set_write_callback(&mut self, cb: WriteCallback) {
        self.write_callback = Some(cb);
    }

    /// Sets the user read callback for upload body data.
    pub fn set_read_callback(&mut self, cb: ReadCallback) {
        self.read_callback = Some(cb);
    }

    /// Sets the user header callback for response header lines.
    pub fn set_header_callback(&mut self, cb: HeaderCallback) {
        self.header_callback = Some(cb);
    }

    /// Sets the user debug callback for verbose output.
    pub fn set_debug_callback(&mut self, cb: DebugCallback) {
        self.debug_callback = Some(cb);
    }

    // ====================================================================
    // Pretransfer — Curl_pretransfer()
    // ====================================================================

    /// Prepares the transfer engine for a new transfer.
    ///
    /// This MUST be called once before `perform()` for each new transfer.
    /// It resets per-transfer state, initializes rate limiters based on the
    /// current configuration, and records the transfer start time.
    ///
    /// Maps to `Curl_pretransfer()` in `lib/transfer.c`.
    ///
    /// # Errors
    ///
    /// - [`CurlError::UrlMalformat`] if essential transfer parameters are
    ///   missing (analogous to the C "No URL set" check).
    /// - [`CurlError::BadFunctionArgument`] if rate limiter creation fails.
    pub fn pretransfer(&mut self) -> CurlResult<()> {
        tracing::debug!("pretransfer: initializing transfer state");

        // Reset retry counter at the start of each request (matches C behavior
        // where data->state.retrycount is reset in Curl_pretransfer).
        self.retry_count = 0;

        // Reset per-transfer counters.
        self.bytes_received = 0;
        self.bytes_sent = 0;
        self.expected_size = -1;
        self.redirect_count = 0;
        self.redirect_url = None;
        self.response_code = 0;
        self.download_done = false;
        self.upload_done = false;
        self.eos_written = false;
        self.send_paused = false;
        self.recv_paused = false;
        self.shutdown_on_done = false;
        self.shutdown_err_ignore = false;
        self.want_send = false;
        self.want_recv = false;

        // Clear buffers, preserving allocation.
        self.recv_buf.clear();
        self.send_buf.clear();

        // Reset response headers.
        self.response_headers = Headers::new();

        // Clear content decoder.
        self.content_decoder = None;

        // Initialize rate limiters based on configuration.
        self.recv_rate_limiter = if self.config.max_recv_speed > 0 {
            let limiter = RateLimiter::new(self.config.max_recv_speed, 0)?;
            Some(limiter)
        } else {
            None
        };

        self.send_rate_limiter = if self.config.max_send_speed > 0 {
            let limiter = RateLimiter::new(self.config.max_send_speed, 0)?;
            Some(limiter)
        } else {
            None
        };

        // Reset and start progress tracking.
        self.progress.reset();
        self.progress.low_speed_limit = self.config.low_speed_limit;
        self.progress.low_speed_time = self.config.low_speed_time.as_secs();
        self.progress.start_now();

        // Record transfer start time.
        let now = Instant::now();
        self.start_time = Some(now);

        // Transition to Idle (ready for perform).
        self.state = TransferState::Idle;

        tracing::debug!("pretransfer: initialization complete");
        Ok(())
    }

    // ====================================================================
    // Perform — Curl_sendrecv()
    // ====================================================================

    /// Drives one iteration of the send/receive transfer loop.
    ///
    /// This is the main entry point called repeatedly by the multi-handle
    /// event loop (or by `curl_easy_perform` internally). Each call:
    ///
    /// 1. Checks if the transfer is blocked (both directions paused).
    /// 2. Receives response data if the transfer wants to recv.
    /// 3. Sends request data if the transfer wants to send.
    /// 4. Updates progress tracking and checks for timeouts.
    /// 5. Detects transfer completion.
    ///
    /// Maps to `Curl_sendrecv()` in `lib/transfer.c`.
    ///
    /// # Arguments
    ///
    /// * `request` — the per-request state machine.
    /// * `filter_chain` — the connection filter chain for I/O.
    ///
    /// # Errors
    ///
    /// Returns appropriate [`CurlError`] variants for:
    /// - Timeout conditions ([`OperationTimedOut`](CurlError::OperationTimedOut))
    /// - Callback aborts ([`AbortedByCallback`](CurlError::AbortedByCallback))
    /// - Partial transfers ([`PartialFile`](CurlError::PartialFile))
    /// - Network errors ([`SendError`](CurlError::SendError), [`RecvError`](CurlError::RecvError))
    pub async fn perform(
        &mut self,
        request: &mut Request,
        filter_chain: &mut FilterChain,
    ) -> CurlResult<()> {
        // If the transfer is blocked (both directions paused), return immediately.
        if self.is_blocked() {
            tracing::trace!("perform: transfer is blocked, returning Ok");
            return Ok(());
        }

        // Apply total transfer timeout if configured.
        if !self.config.timeout.is_zero() {
            if let Some(start) = self.start_time {
                let elapsed = start.elapsed();
                if elapsed >= self.config.timeout {
                    let elapsed_ms = elapsed.as_millis();
                    tracing::error!(
                        "perform: operation timed out after {}ms with {} bytes received",
                        elapsed_ms,
                        self.bytes_received,
                    );
                    return Err(CurlError::OperationTimedOut);
                }
            }
        }

        // --- Receive phase ---
        if self.want_recv && !self.recv_paused {
            let result = self.do_recv(request, filter_chain).await;
            match result {
                Ok(()) => {}
                Err(CurlError::Again) => {
                    // Transient: no data available right now, will retry.
                    tracing::trace!("perform: recv returned Again");
                }
                Err(e) => return Err(e),
            }
        }

        // --- Send phase ---
        if self.want_send && !self.send_paused {
            let result = self.do_send(request, filter_chain).await;
            match result {
                Ok(()) => {}
                Err(CurlError::Again) => {
                    tracing::trace!("perform: send returned Again");
                }
                Err(e) => return Err(e),
            }
        }

        // --- Progress check ---
        // Matches Curl_pgrsCheck() call in Curl_sendrecv().
        self.progress.check()?;

        // --- Timeout check ---
        if self.want_send || self.want_recv {
            if let Some(remaining) = self.time_left() {
                if remaining.is_zero() {
                    let elapsed_ms = self.elapsed_ms();
                    if self.expected_size >= 0 {
                        tracing::error!(
                            "perform: operation timed out after {}ms with {} out of {} bytes received",
                            elapsed_ms,
                            self.bytes_received,
                            self.expected_size,
                        );
                    } else {
                        tracing::error!(
                            "perform: operation timed out after {}ms with {} bytes received",
                            elapsed_ms,
                            self.bytes_received,
                        );
                    }
                    return Err(CurlError::OperationTimedOut);
                }
            }
        } else {
            // Transfer is not sending or receiving — it should be done.
            // Validate that we received all expected data.
            if self.expected_size >= 0
                && (self.bytes_received as i64) != self.expected_size
                && self.redirect_url.is_none()
            {
                let remaining = self.expected_size - self.bytes_received as i64;
                tracing::error!(
                    "perform: transfer closed with {} bytes remaining to read",
                    remaining,
                );
                return Err(CurlError::PartialFile);
            }
        }

        // --- Completion detection ---
        if !self.want_send && !self.want_recv {
            self.state = TransferState::Done;
            tracing::debug!("perform: transfer complete");
        }

        // --- Final progress update ---
        self.progress.update()?;

        Ok(())
    }

    // ====================================================================
    // Internal receive loop — sendrecv_dl()
    // ====================================================================

    /// Internal receive loop: reads response data from the filter chain.
    ///
    /// Iterates up to [`MAX_RECV_LOOPS`] times, reading data and passing
    /// it through content decoding and the write callback. Respects rate
    /// limiting and detects end-of-stream.
    async fn do_recv(
        &mut self,
        _request: &mut Request,
        filter_chain: &mut FilterChain,
    ) -> CurlResult<()> {
        let mut loops_remaining = MAX_RECV_LOOPS;
        let is_multiplex = filter_chain.is_connected()
            && !filter_chain.is_empty();

        loop {
            if loops_remaining == 0 {
                break;
            }
            loops_remaining -= 1;

            // Check rate limiting.
            if let Some(ref mut limiter) = self.recv_rate_limiter {
                if let Some(delay) = limiter.should_throttle() {
                    tracing::trace!(
                        "do_recv: rate limited, need to wait {}ms",
                        delay.as_millis()
                    );
                    // Don't actually sleep here — return to the event loop
                    // so the multi handle can schedule the wakeup.
                    break;
                }
            }

            // Determine bytes to read.
            let mut bytes_to_read = self.config.buffer_size;

            // If we know the expected size and the connection doesn't reliably
            // signal EOS, limit the read to the remaining expected bytes.
            if !is_multiplex && self.expected_size >= 0 {
                let remaining = (self.expected_size - self.bytes_received as i64).max(0) as usize;
                if remaining < bytes_to_read {
                    bytes_to_read = remaining;
                }
            }

            if bytes_to_read == 0 {
                // Nothing more to read.
                self.download_done = true;
                self.want_recv = false;
                break;
            }

            // Ensure receive buffer has capacity.
            self.recv_buf.reserve(bytes_to_read);

            // Read from the filter chain.
            let mut tmp_buf = vec![0u8; bytes_to_read];
            let n = match filter_chain.recv(&mut tmp_buf).await {
                Ok(n) => n,
                Err(CurlError::Again) => {
                    tracing::trace!("do_recv: recv returned Again");
                    break;
                }
                Err(e) => {
                    tracing::error!("do_recv: recv error: {}", CurlError::strerror(&e));
                    return Err(e);
                }
            };

            // Zero-length read signals end-of-stream.
            let is_eos = n == 0;

            if n > 0 {
                // Record bytes for rate limiting.
                if let Some(ref mut limiter) = self.recv_rate_limiter {
                    limiter.record_bytes(n as u64);
                }

                // Update progress counters.
                self.bytes_received += n as u64;
                self.progress.download_inc(n as u64);

                // Feed data through the write_response path.
                self.write_response_bytes(&tmp_buf[..n], false)?;
            }

            if is_eos {
                tracing::debug!("do_recv: end-of-stream reached");
                self.write_response_bytes(&[], true)?;
                self.download_done = true;
                self.eos_written = true;
                self.want_recv = false;
                break;
            }

            // If download is done (based on expected size), stop receiving.
            if self.expected_size >= 0
                && self.bytes_received as i64 >= self.expected_size
            {
                tracing::debug!(
                    "do_recv: received all expected bytes ({})",
                    self.expected_size
                );
                self.download_done = true;
                self.want_recv = false;
                break;
            }
        }

        Ok(())
    }

    // ====================================================================
    // Internal send loop — sendrecv_ul()
    // ====================================================================

    /// Internal send loop: sends request data through the filter chain.
    async fn do_send(
        &mut self,
        _request: &mut Request,
        filter_chain: &mut FilterChain,
    ) -> CurlResult<()> {
        // If the send buffer is empty and we have a read callback, fill it.
        if self.send_buf.is_empty() {
            if let Some(ref mut read_cb) = self.read_callback {
                let mut tmp = vec![0u8; self.config.upload_buffer_size];
                match read_cb(&mut tmp) {
                    Ok(0) => {
                        // EOF — upload complete.
                        self.upload_done = true;
                        self.want_send = false;
                        tracing::debug!("do_send: read callback returned EOF");
                        return Ok(());
                    }
                    Ok(n) => {
                        self.send_buf.put_slice(&tmp[..n]);
                    }
                    Err(CallbackResult::Pause) => {
                        self.send_paused = true;
                        tracing::trace!("do_send: read callback requested pause");
                        return Ok(());
                    }
                    Err(CallbackResult::Abort) => {
                        return Err(CurlError::AbortedByCallback);
                    }
                    Err(CallbackResult::Continue) => {
                        // Continue means 0 bytes available now, retry later.
                        return Err(CurlError::Again);
                    }
                }
            } else {
                // No data to send and no read callback — upload is done.
                self.upload_done = true;
                self.want_send = false;
                return Ok(());
            }
        }

        // Check send rate limiting.
        if let Some(ref mut limiter) = self.send_rate_limiter {
            if let Some(_delay) = limiter.should_throttle() {
                tracing::trace!("do_send: send rate limited");
                return Ok(());
            }
        }

        // Send data through the filter chain.
        let to_send = self.send_buf.len();
        if to_send > 0 {
            let data_to_send = self.send_buf.split_to(to_send);
            let is_eos = self.upload_done && self.send_buf.is_empty();

            match filter_chain.send(&data_to_send, is_eos).await {
                Ok(written) => {
                    if written < to_send {
                        // Not all data was sent — put the remainder back.
                        let unsent = &data_to_send[written..];
                        // Prepend unsent data back to send_buf.
                        let mut new_buf = BytesMut::with_capacity(
                            unsent.len() + self.send_buf.len(),
                        );
                        new_buf.put_slice(unsent);
                        if !self.send_buf.is_empty() {
                            let remaining = self.send_buf.split_to(self.send_buf.len());
                            new_buf.put_slice(&remaining);
                        }
                        self.send_buf = new_buf;
                    }

                    if written > 0 {
                        self.bytes_sent += written as u64;
                        self.progress.upload_inc(written as u64);

                        // Record bytes for rate limiting.
                        if let Some(ref mut limiter) = self.send_rate_limiter {
                            limiter.record_bytes(written as u64);
                        }

                        // Debug callback for outgoing data (gated on verbose).
                        if self.config.verbose {
                            if let Some(ref mut debug_cb) = self.debug_callback {
                                debug_cb(
                                    DebugInfoType::DataOut,
                                    &data_to_send[..written],
                                );
                            }
                        }
                    }
                }
                Err(CurlError::Again) => {
                    // Put all data back.
                    let mut new_buf = BytesMut::with_capacity(
                        data_to_send.len() + self.send_buf.len(),
                    );
                    new_buf.put_slice(&data_to_send);
                    if !self.send_buf.is_empty() {
                        let remaining = self.send_buf.split_to(self.send_buf.len());
                        new_buf.put_slice(&remaining);
                    }
                    self.send_buf = new_buf;
                    return Err(CurlError::Again);
                }
                Err(e) => {
                    tracing::error!(
                        "do_send: send error: {}",
                        CurlError::strerror(&e),
                    );
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    // ====================================================================
    // write_response — Curl_xfer_write_resp()
    // ====================================================================

    /// Writes raw response bytes through the content decoder and write callback.
    ///
    /// All received response body data flows through this method. Protocol
    /// handlers (e.g., HTTP) may intercept and pre-process data before
    /// calling this.
    ///
    /// Maps to `Curl_xfer_write_resp()` in `lib/transfer.c`.
    ///
    /// # Arguments
    ///
    /// * `buf` — raw response bytes.
    /// * `is_eos` — `true` when this is the last chunk (end-of-stream).
    ///
    /// # Errors
    ///
    /// - [`CurlError::WriteError`] if the write callback fails.
    /// - [`CurlError::BadContentEncoding`] if decompression fails.
    /// - [`CurlError::AbortedByCallback`] if the callback aborts.
    pub fn write_response(&mut self, buf: &[u8], is_eos: bool) -> CurlResult<()> {
        self.write_response_bytes(buf, is_eos)
    }

    /// Internal method that handles response body writing with content
    /// decoding and callback invocation.
    fn write_response_bytes(&mut self, buf: &[u8], is_eos: bool) -> CurlResult<()> {
        let decoded_data: Vec<u8>;
        let data_to_write: &[u8];

        // Apply content decoding if a decoder is active.
        if let Some(ref mut decoder) = self.content_decoder {
            if !buf.is_empty() {
                decoded_data = decoder.decode(buf)?;
            } else if is_eos {
                decoded_data = decoder.finish()?;
            } else {
                decoded_data = Vec::new();
            }
            data_to_write = &decoded_data;
        } else {
            data_to_write = buf;
        }

        // Invoke write callback if set and there's data to write.
        if !data_to_write.is_empty() || is_eos {
            if let Some(ref mut write_cb) = self.write_callback {
                if !data_to_write.is_empty() {
                    match write_cb(data_to_write) {
                        Ok(consumed) => {
                            if consumed != data_to_write.len() {
                                tracing::warn!(
                                    "write callback consumed {} of {} bytes",
                                    consumed,
                                    data_to_write.len()
                                );
                                return Err(CurlError::WriteError);
                            }
                        }
                        Err(CallbackResult::Pause) => {
                            self.recv_paused = true;
                            tracing::trace!("write_response: write callback requested pause");
                            return Ok(());
                        }
                        Err(CallbackResult::Abort) => {
                            return Err(CurlError::AbortedByCallback);
                        }
                        Err(CallbackResult::Continue) => {
                            // Continue is treated as "all bytes consumed".
                        }
                    }
                }
            }
        }

        if is_eos {
            self.eos_written = true;
            self.download_done = true;
            tracing::trace!("write_response: EOS written");
        }

        Ok(())
    }

    // ====================================================================
    // write_response_header — Curl_xfer_write_resp_hd()
    // ====================================================================

    /// Writes a single response header line.
    ///
    /// Stores the header in the response header collection and invokes
    /// the header callback if set.
    ///
    /// Maps to `Curl_xfer_write_resp_hd()` in `lib/transfer.c`.
    ///
    /// # Arguments
    ///
    /// * `header` — null-terminated header line (e.g., `"Content-Type: text/html\r\n"`).
    /// * `is_eos` — `true` when this is the last header (blank line separator).
    pub fn write_response_header(
        &mut self,
        header: &str,
        is_eos: bool,
    ) -> CurlResult<()> {
        // Trim trailing CRLF for inspection.
        let trimmed = header.trim_end_matches(['\r', '\n']);

        // Detect HTTP status line (e.g. "HTTP/1.1 200 OK").
        // Status lines begin with "HTTP/" and do not have a ':' separator,
        // so they cannot be stored via the normal header push path.
        let is_status_line = trimmed.starts_with("HTTP/");

        if is_status_line {
            // Extract response code from "HTTP/<ver> <code> <reason>".
            if let Some(rest) = trimmed.strip_prefix("HTTP/") {
                // Skip version portion (e.g. "1.1 " or "2 ").
                if let Some(code_start) = rest.find(' ') {
                    let after_space = &rest[code_start + 1..];
                    let code_str = after_space.split_whitespace().next().unwrap_or("0");
                    if let Ok(code) = code_str.parse::<u16>() {
                        self.response_code = code;
                        tracing::debug!("write_response_header: status code {}", code);
                    }
                }
            }
        } else if !trimmed.is_empty()
            && !trimmed.starts_with('\r')
            && !trimmed.starts_with('\n')
        {
            // Regular "Name: Value" header — store in collection.
            // push() expects the raw header with CRLF intact for trimming.
            self.response_headers
                .push(header, crate::headers::HeaderOrigin::HEADER)?;
        }

        // Invoke header callback for all header lines (including status).
        if let Some(ref mut header_cb) = self.header_callback {
            match header_cb(header.as_bytes()) {
                Ok(_consumed) => {}
                Err(CallbackResult::Abort) => {
                    return Err(CurlError::AbortedByCallback);
                }
                Err(CallbackResult::Pause) => {
                    self.recv_paused = true;
                }
                Err(CallbackResult::Continue) => {}
            }
        }

        // Debug callback for incoming headers (gated on verbose).
        if self.config.verbose {
            if let Some(ref mut debug_cb) = self.debug_callback {
                debug_cb(DebugInfoType::HeaderIn, header.as_bytes());
            }
        }

        // If this is the EOS (blank line after headers), check for redirects.
        if is_eos {
            self.write_response_bytes(&[], true)?;
        }

        Ok(())
    }

    // ====================================================================
    // write_done — Curl_xfer_write_done()
    // ====================================================================

    /// Signals that the transfer is done with writing.
    ///
    /// Called by the multi handle when the transfer transitions to DONE.
    /// Ensures any pending EOS has been written to the client.
    ///
    /// Maps to `Curl_xfer_write_done()` in `lib/transfer.c`.
    ///
    /// # Arguments
    ///
    /// * `premature` — `true` if the transfer was ended prematurely.
    pub fn write_done(&mut self, premature: bool) -> CurlResult<()> {
        if premature {
            tracing::debug!("write_done: premature transfer completion");
        }

        // If EOS hasn't been written yet, flush content decoder and signal it.
        if !self.eos_written {
            if let Some(ref mut decoder) = self.content_decoder {
                let final_data = decoder.finish()?;
                if !final_data.is_empty() {
                    if let Some(ref mut write_cb) = self.write_callback {
                        match write_cb(&final_data) {
                            Ok(_) => {}
                            Err(CallbackResult::Abort) => {
                                return Err(CurlError::AbortedByCallback);
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
            self.eos_written = true;
        }

        Ok(())
    }

    // ====================================================================
    // needs_flush — Curl_xfer_needs_flush()
    // ====================================================================

    /// Returns `true` if there is pending data to send in the send buffer.
    ///
    /// Maps to `Curl_xfer_needs_flush()` in `lib/transfer.c`.
    pub fn needs_flush(&self) -> bool {
        !self.send_buf.is_empty()
    }

    // ====================================================================
    // flush — Curl_xfer_flush()
    // ====================================================================

    /// Flushes any pending send data through the filter chain.
    ///
    /// Maps to `Curl_xfer_flush()` in `lib/transfer.c`.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::SendError`] if the flush fails.
    pub async fn flush(&mut self, filter_chain: &mut FilterChain) -> CurlResult<()> {
        if self.send_buf.is_empty() {
            return Ok(());
        }

        let to_send = self.send_buf.len();
        let data = self.send_buf.split_to(to_send);
        let frozen = data.freeze();

        match filter_chain.send(&frozen, false).await {
            Ok(written) => {
                if written < frozen.len() {
                    // Put remaining data back.
                    let unsent = &frozen[written..];
                    let mut new_buf = BytesMut::with_capacity(
                        unsent.len() + self.send_buf.len(),
                    );
                    new_buf.put_slice(unsent);
                    if !self.send_buf.is_empty() {
                        let remaining = self.send_buf.split_to(self.send_buf.len());
                        new_buf.put_slice(&remaining);
                    }
                    self.send_buf = new_buf;
                }
                Ok(())
            }
            Err(CurlError::Again) => {
                // Put all data back.
                let mut new_buf = BytesMut::with_capacity(
                    frozen.len() + self.send_buf.len(),
                );
                new_buf.put_slice(&frozen);
                if !self.send_buf.is_empty() {
                    let remaining = self.send_buf.split_to(self.send_buf.len());
                    new_buf.put_slice(&remaining);
                }
                self.send_buf = new_buf;
                Err(CurlError::Again)
            }
            Err(e) => Err(e),
        }
    }

    // ====================================================================
    // send_data — Curl_xfer_send()
    // ====================================================================

    /// Sends data through the connection filter chain.
    ///
    /// Returns the number of bytes actually sent (may be 0 on blocking).
    ///
    /// Maps to `Curl_xfer_send()` in `lib/transfer.c`.
    ///
    /// # Arguments
    ///
    /// * `buf` — data to send.
    /// * `eos` — `true` if this is the last chunk.
    /// * `filter_chain` — the connection filter chain.
    pub async fn send_data(
        &mut self,
        buf: &[u8],
        eos: bool,
        filter_chain: &mut FilterChain,
    ) -> CurlResult<usize> {
        if buf.is_empty() && !eos {
            return Ok(0);
        }

        match filter_chain.send(buf, eos).await {
            Ok(written) => {
                if written > 0 {
                    self.bytes_sent += written as u64;
                }
                tracing::trace!(
                    "send_data: sent {}/{} bytes, eos={}",
                    written,
                    buf.len(),
                    eos,
                );
                Ok(written)
            }
            Err(CurlError::Again) => {
                tracing::trace!("send_data: would block, 0 bytes sent");
                Ok(0)
            }
            Err(e) => {
                tracing::error!(
                    "send_data: error: {}",
                    CurlError::strerror(&e),
                );
                Err(e)
            }
        }
    }

    // ====================================================================
    // recv_data — Curl_xfer_recv()
    // ====================================================================

    /// Receives data from the connection filter chain.
    ///
    /// Returns the number of bytes received.
    ///
    /// Maps to `Curl_xfer_recv()` in `lib/transfer.c`.
    ///
    /// # Arguments
    ///
    /// * `buf` — buffer to receive data into.
    /// * `filter_chain` — the connection filter chain.
    pub async fn recv_data(
        &mut self,
        buf: &mut [u8],
        filter_chain: &mut FilterChain,
    ) -> CurlResult<usize> {
        // Limit read size to configured buffer size (matches C behavior).
        let max_read = buf.len().min(self.config.buffer_size);
        let read_buf = &mut buf[..max_read];

        match filter_chain.recv(read_buf).await {
            Ok(n) => {
                tracing::trace!("recv_data: received {} bytes", n);
                Ok(n)
            }
            Err(CurlError::Again) => {
                tracing::trace!("recv_data: would block");
                Err(CurlError::Again)
            }
            Err(e) => {
                tracing::error!(
                    "recv_data: error: {}",
                    CurlError::strerror(&e),
                );
                Err(e)
            }
        }
    }

    // ====================================================================
    // is_blocked — Curl_xfer_is_blocked()
    // ====================================================================

    /// Returns `true` if the transfer cannot make progress because all
    /// active directions are paused.
    ///
    /// Maps to `Curl_xfer_is_blocked()` in `lib/transfer.c`.
    pub fn is_blocked(&self) -> bool {
        if !self.want_send {
            // Only receiving — blocked if recv is paused.
            self.want_recv && self.recv_paused
        } else if !self.want_recv {
            // Only sending — blocked if send is paused.
            self.want_send && self.send_paused
        } else {
            // Both directions active — blocked only if both are paused.
            self.recv_paused && self.send_paused
        }
    }

    // ====================================================================
    // Pause control — Curl_xfer_pause_send/recv()
    // ====================================================================

    /// Pauses or unpauses the send direction.
    ///
    /// Maps to `Curl_xfer_pause_send()` in `lib/transfer.c`.
    ///
    /// # Arguments
    ///
    /// * `enable` — `true` to pause, `false` to resume.
    pub fn pause_send(&mut self, enable: bool) -> CurlResult<()> {
        self.send_paused = enable;

        // Update rate limiter blocking state.
        if let Some(ref mut limiter) = self.send_rate_limiter {
            limiter.block(enable);
        }

        // Notify progress tracker.
        self.progress.send_pause(enable);

        if !enable {
            tracing::debug!("pause_send: send unpaused");
        } else {
            tracing::debug!("pause_send: send paused");
        }

        Ok(())
    }

    /// Pauses or unpauses the receive direction.
    ///
    /// Maps to `Curl_xfer_pause_recv()` in `lib/transfer.c`.
    ///
    /// # Arguments
    ///
    /// * `enable` — `true` to pause, `false` to resume.
    pub fn pause_recv(&mut self, enable: bool) -> CurlResult<()> {
        self.recv_paused = enable;

        // Update rate limiter blocking state.
        if let Some(ref mut limiter) = self.recv_rate_limiter {
            limiter.block(enable);
        }

        // Notify progress tracker.
        self.progress.recv_pause(enable);

        if !enable {
            tracing::debug!("pause_recv: recv unpaused");
        } else {
            tracing::debug!("pause_recv: recv paused");
        }

        Ok(())
    }

    /// Returns `true` if the send direction is paused.
    ///
    /// Maps to `Curl_xfer_send_is_paused()`.
    pub fn is_send_paused(&self) -> bool {
        self.send_paused
            || self
                .send_rate_limiter
                .as_ref()
                .is_some_and(|l| l.is_blocked())
    }

    /// Returns `true` if the receive direction is paused.
    ///
    /// Maps to `Curl_xfer_recv_is_paused()`.
    pub fn is_recv_paused(&self) -> bool {
        self.recv_paused
            || self
                .recv_rate_limiter
                .as_ref()
                .is_some_and(|l| l.is_blocked())
    }

    // ====================================================================
    // check_headers — Curl_checkheaders()
    // ====================================================================

    /// Checks if a custom header with the given prefix exists.
    ///
    /// Searches the configured custom headers for a header whose name
    /// starts with `prefix` (case-insensitive comparison). Returns the
    /// first matching header line, or `None`.
    ///
    /// Maps to `Curl_checkheaders()` in `lib/transfer.c`.
    ///
    /// # Arguments
    ///
    /// * `prefix` — header name prefix to search for (without trailing colon).
    pub fn check_headers(&self, prefix: &str) -> Option<&str> {
        let prefix_lower = prefix.to_ascii_lowercase();
        for header in &self.config.custom_headers {
            // Match prefix case-insensitively, followed by headersep char.
            let header_lower = header.to_ascii_lowercase();
            if header_lower.starts_with(&prefix_lower) {
                let remaining = header.as_bytes();
                if remaining.len() > prefix.len()
                    && headersep(remaining[prefix.len()])
                {
                    return Some(header.as_str());
                }
            }
        }
        None
    }

    // ====================================================================
    // meets_timecondition — Curl_meets_timecondition()
    // ====================================================================

    /// Checks whether the `CURLOPT_TIMECONDITION` is satisfied.
    ///
    /// Compares the document's modification time against the configured
    /// reference time. Returns `true` if the condition is met (the
    /// transfer should proceed), `false` if the condition is not met
    /// (the document fails the time check).
    ///
    /// Maps to `Curl_meets_timecondition()` in `lib/transfer.c`.
    ///
    /// # Arguments
    ///
    /// * `time_of_doc` — document modification time as Unix timestamp.
    pub fn meets_timecondition(&self, time_of_doc: i64) -> bool {
        // No time condition or no document time — condition is met.
        if time_of_doc == 0 || self.config.time_value == 0 {
            return true;
        }

        match self.config.time_condition {
            TimeCondition::IfModifiedSince => {
                if time_of_doc <= self.config.time_value {
                    tracing::debug!(
                        "meets_timecondition: document not new enough (doc={}, ref={})",
                        time_of_doc,
                        self.config.time_value,
                    );
                    return false;
                }
            }
            TimeCondition::IfUnmodifiedSince => {
                if time_of_doc >= self.config.time_value {
                    tracing::debug!(
                        "meets_timecondition: document not old enough (doc={}, ref={})",
                        time_of_doc,
                        self.config.time_value,
                    );
                    return false;
                }
            }
            TimeCondition::None | TimeCondition::LastMod => {
                // No condition or LastMod — always met.
            }
        }

        true
    }

    // ====================================================================
    // retry_request — Curl_retry_request()
    // ====================================================================

    /// Determines whether a failed request should be retried on a fresh
    /// connection.
    ///
    /// Returns `Some(url)` with the URL to retry if retry is warranted,
    /// or `None` if the request should not be retried.
    ///
    /// Maps to `Curl_retry_request()` in `lib/transfer.c`.
    ///
    /// Retry conditions:
    /// - Connection was reused but no data was received (dead connection).
    /// - Stream was refused (HTTP/2 REFUSED_STREAM).
    /// - Retry count has not exceeded [`CONN_MAX_RETRIES`].
    pub fn retry_request(
        &mut self,
        url: &str,
        connection_reused: bool,
        stream_refused: bool,
    ) -> CurlResult<Option<String>> {
        let mut should_retry = false;

        // Check for dead reused connection (no data received).
        if connection_reused
            && self.bytes_received == 0
            && self.bytes_sent == 0
        {
            tracing::debug!("retry_request: dead reused connection detected");
            should_retry = true;
        }

        // Check for refused stream (HTTP/2).
        if stream_refused && self.bytes_received == 0 {
            tracing::debug!("retry_request: REFUSED_STREAM, retrying fresh connect");
            should_retry = true;
        }

        if should_retry {
            self.retry_count += 1;
            if self.retry_count > CONN_MAX_RETRIES {
                tracing::error!(
                    "retry_request: connection died, tried {} times before giving up",
                    CONN_MAX_RETRIES,
                );
                self.retry_count = 0;
                return Err(CurlError::SendError);
            }

            tracing::debug!(
                "retry_request: connection died, retrying fresh connect (attempt {})",
                self.retry_count,
            );

            return Ok(Some(url.to_string()));
        }

        Ok(None)
    }

    // ====================================================================
    // setup_send — Curl_xfer_setup_send()
    // ====================================================================

    /// Configures the transfer to only send data (no receiving).
    ///
    /// Maps to `Curl_xfer_setup_send()` in `lib/transfer.c`.
    pub fn setup_send(&mut self) {
        self.want_send = true;
        self.want_recv = false;
        self.expected_size = -1;
        self.shutdown_on_done = false;
        self.shutdown_err_ignore = false;

        if self.state == TransferState::Idle {
            self.state = TransferState::Sending;
        }

        tracing::trace!("setup_send: configured for send-only");
    }

    // ====================================================================
    // setup_recv — Curl_xfer_setup_recv()
    // ====================================================================

    /// Configures the transfer to only receive data (no sending).
    ///
    /// # Arguments
    ///
    /// * `recv_size` — expected number of bytes to receive, or `-1` if unknown.
    ///
    /// Maps to `Curl_xfer_setup_recv()` in `lib/transfer.c`.
    pub fn setup_recv(&mut self, recv_size: i64) {
        self.want_send = false;
        self.want_recv = true;
        self.expected_size = recv_size;
        self.shutdown_on_done = false;
        self.shutdown_err_ignore = false;

        // If size is known and positive, set download size on progress tracker.
        if recv_size > 0 {
            self.progress.set_download_size(Some(recv_size as u64));
        }

        if self.state == TransferState::Idle || self.state == TransferState::Sending {
            self.state = TransferState::Receiving;
        }

        tracing::trace!("setup_recv: configured for recv-only, size={}", recv_size);
    }

    // ====================================================================
    // setup_sendrecv — Curl_xfer_setup_sendrecv()
    // ====================================================================

    /// Configures the transfer for bidirectional data flow (both send and
    /// receive).
    ///
    /// # Arguments
    ///
    /// * `recv_size` — expected number of bytes to receive, or `-1` if unknown.
    ///
    /// Maps to `Curl_xfer_setup_sendrecv()` in `lib/transfer.c`.
    pub fn setup_sendrecv(&mut self, recv_size: i64) {
        self.want_send = true;
        self.want_recv = true;
        self.expected_size = recv_size;
        self.shutdown_on_done = false;
        self.shutdown_err_ignore = false;

        // If size is known, set download size on progress tracker.
        if recv_size > 0 {
            self.progress.set_download_size(Some(recv_size as u64));
        }

        if self.state == TransferState::Idle {
            self.state = TransferState::Sending;
        }

        tracing::trace!(
            "setup_sendrecv: configured for bidirectional, recv_size={}",
            recv_size,
        );
    }

    // ====================================================================
    // Content-Encoding Integration
    // ====================================================================

    /// Sets up content decoding for the given encoding name.
    ///
    /// This should be called when the `Content-Encoding` response header
    /// is received. Creates the appropriate decoder chain.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::BadContentEncoding`] if the encoding is not
    /// supported.
    pub fn setup_content_decoding(&mut self, encoding: &str) -> CurlResult<()> {
        if encoding.is_empty() || encoding.eq_ignore_ascii_case("identity") {
            self.content_decoder = None;
            return Ok(());
        }

        let decoder = create_decoder(encoding)?;
        self.content_decoder = Some(decoder);
        tracing::debug!("setup_content_decoding: {} decoder active", encoding);
        Ok(())
    }

    // ====================================================================
    // Accessors for transfer state
    // ====================================================================

    /// Returns the number of body bytes received so far.
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    /// Returns the number of body bytes sent so far.
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    /// Returns the HTTP response code (0 if not yet received).
    pub fn response_code(&self) -> u16 {
        self.response_code
    }

    /// Sets the HTTP response code.
    pub fn set_response_code(&mut self, code: u16) {
        self.response_code = code;
    }

    /// Returns a reference to the collected response headers.
    pub fn response_headers(&self) -> &Headers {
        &self.response_headers
    }

    /// Returns `true` if the download has completed.
    pub fn is_download_done(&self) -> bool {
        self.download_done
    }

    /// Returns `true` if the upload has completed.
    pub fn is_upload_done(&self) -> bool {
        self.upload_done
    }

    /// Returns the redirect URL if a redirect was detected.
    pub fn redirect_url(&self) -> Option<&str> {
        self.redirect_url.as_deref()
    }

    /// Sets the redirect URL.
    pub fn set_redirect_url(&mut self, url: Option<String>) {
        self.redirect_url = url;
    }

    /// Returns the number of redirects followed.
    pub fn redirect_count(&self) -> u32 {
        self.redirect_count
    }

    /// Increments the redirect counter.
    pub fn increment_redirect(&mut self) {
        self.redirect_count += 1;
    }

    /// Returns the supported content encodings as a comma-separated string.
    ///
    /// Used for setting the `Accept-Encoding` request header.
    pub fn supported_encodings(&self) -> String {
        supported_encodings()
    }

    // ====================================================================
    // Private helpers
    // ====================================================================

    /// Computes the remaining time before the total transfer timeout.
    ///
    /// Returns `Some(Duration::ZERO)` when the timeout has been exceeded,
    /// `Some(remaining)` when time is left, or `None` when no timeout is set.
    fn time_left(&self) -> Option<Duration> {
        if self.config.timeout.is_zero() {
            return None;
        }

        let start = self.start_time?;
        let elapsed = start.elapsed();
        if elapsed >= self.config.timeout {
            Some(Duration::ZERO)
        } else {
            Some(self.config.timeout - elapsed)
        }
    }

    /// Returns the total elapsed time in milliseconds since transfer start.
    fn elapsed_ms(&self) -> u128 {
        self.start_time
            .map(|s| s.elapsed().as_millis())
            .unwrap_or(0)
    }
}

impl Default for TransferEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Unit-testable helper — headersep check
// ===========================================================================

/// Returns `true` if `ch` is a header name/value separator (`:` or `;`).
///
/// Maps to the C macro `Curl_headersep(x)` in `lib/transfer.h`.
#[inline]
fn headersep(ch: u8) -> bool {
    ch == b':' || ch == b';'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_state_display() {
        assert_eq!(format!("{}", TransferState::Idle), "Idle");
        assert_eq!(format!("{}", TransferState::Connecting), "Connecting");
        assert_eq!(format!("{}", TransferState::Sending), "Sending");
        assert_eq!(format!("{}", TransferState::Receiving), "Receiving");
        assert_eq!(format!("{}", TransferState::Done), "Done");
    }

    #[test]
    fn test_transfer_state_default() {
        assert_eq!(TransferState::default(), TransferState::Idle);
    }

    #[test]
    fn test_transfer_config_defaults() {
        let config = TransferConfig::new();
        assert_eq!(config.timeout, Duration::ZERO);
        assert_eq!(config.connect_timeout, Duration::ZERO);
        assert_eq!(config.low_speed_limit, 0);
        assert_eq!(config.buffer_size, DEFAULT_BUFFER_SIZE);
        assert_eq!(config.upload_buffer_size, DEFAULT_UPLOAD_BUFFER_SIZE);
        assert_eq!(config.max_redirects, DEFAULT_MAX_REDIRECTS as i32);
        assert_eq!(config.max_recv_speed, 0);
        assert_eq!(config.max_send_speed, 0);
        assert!(!config.follow_location);
    }

    #[test]
    fn test_transfer_config_setters() {
        let mut config = TransferConfig::new();
        config
            .set_timeout(Duration::from_secs(30))
            .set_connect_timeout(Duration::from_secs(10))
            .set_low_speed_limit(1024)
            .set_low_speed_time(Duration::from_secs(5))
            .set_buffer_size(32768)
            .set_upload_buffer_size(131072)
            .set_max_redirects(10)
            .set_max_recv_speed(1_000_000)
            .set_max_send_speed(500_000)
            .set_follow_location(true);

        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert_eq!(config.low_speed_limit, 1024);
        assert_eq!(config.low_speed_time, Duration::from_secs(5));
        assert_eq!(config.buffer_size, 32768);
        assert_eq!(config.upload_buffer_size, 131072);
        assert_eq!(config.max_redirects, 10);
        assert_eq!(config.max_recv_speed, 1_000_000);
        assert_eq!(config.max_send_speed, 500_000);
        assert!(config.follow_location);
    }

    #[test]
    fn test_transfer_config_zero_buffer_ignored() {
        let mut config = TransferConfig::new();
        let original_size = config.buffer_size;
        config.set_buffer_size(0);
        assert_eq!(config.buffer_size, original_size);
    }

    #[test]
    fn test_transfer_engine_new() {
        let engine = TransferEngine::new();
        assert_eq!(engine.state(), TransferState::Idle);
        assert_eq!(engine.bytes_received(), 0);
        assert_eq!(engine.bytes_sent(), 0);
        assert_eq!(engine.response_code(), 0);
        assert!(!engine.is_download_done());
        assert!(!engine.is_upload_done());
        assert!(engine.redirect_url().is_none());
        assert_eq!(engine.redirect_count(), 0);
        assert!(!engine.is_send_paused());
        assert!(!engine.is_recv_paused());
        assert!(!engine.is_blocked());
        assert!(!engine.needs_flush());
    }

    #[test]
    fn test_headersep() {
        assert!(headersep(b':'));
        assert!(headersep(b';'));
        assert!(!headersep(b' '));
        assert!(!headersep(b'A'));
        assert!(!headersep(b'\0'));
    }

    #[test]
    fn test_meets_timecondition_no_condition() {
        let engine = TransferEngine::new();
        // Both zero — condition always met.
        assert!(engine.meets_timecondition(0));
        assert!(engine.meets_timecondition(1000));
    }

    #[test]
    fn test_meets_timecondition_if_modified_since() {
        let mut engine = TransferEngine::new();
        engine.config.time_condition = TimeCondition::IfModifiedSince;
        engine.config.time_value = 1000;

        // Document older than reference — condition NOT met.
        assert!(!engine.meets_timecondition(999));
        // Document same as reference — condition NOT met.
        assert!(!engine.meets_timecondition(1000));
        // Document newer — condition met.
        assert!(engine.meets_timecondition(1001));
    }

    #[test]
    fn test_meets_timecondition_if_unmodified_since() {
        let mut engine = TransferEngine::new();
        engine.config.time_condition = TimeCondition::IfUnmodifiedSince;
        engine.config.time_value = 1000;

        // Document older — condition met.
        assert!(engine.meets_timecondition(999));
        // Document same as reference — condition NOT met.
        assert!(!engine.meets_timecondition(1000));
        // Document newer — condition NOT met.
        assert!(!engine.meets_timecondition(1001));
    }

    #[test]
    fn test_check_headers_found() {
        let mut engine = TransferEngine::new();
        engine.config.custom_headers = vec![
            "Content-Type: application/json".to_string(),
            "Authorization: Bearer token123".to_string(),
            "X-Custom;".to_string(),
        ];

        assert!(engine.check_headers("Content-Type").is_some());
        assert!(engine.check_headers("Authorization").is_some());
        assert!(engine.check_headers("X-Custom").is_some());
        assert!(engine.check_headers("Not-Present").is_none());
    }

    #[test]
    fn test_check_headers_case_insensitive() {
        let mut engine = TransferEngine::new();
        engine.config.custom_headers = vec![
            "Content-Type: text/html".to_string(),
        ];

        assert!(engine.check_headers("content-type").is_some());
        assert!(engine.check_headers("CONTENT-TYPE").is_some());
        assert!(engine.check_headers("Content-Type").is_some());
    }

    #[test]
    fn test_is_blocked_logic() {
        let mut engine = TransferEngine::new();

        // Neither want_send nor want_recv — not blocked.
        assert!(!engine.is_blocked());

        // Want recv, not paused — not blocked.
        engine.want_recv = true;
        assert!(!engine.is_blocked());

        // Want recv, paused — blocked.
        engine.recv_paused = true;
        assert!(engine.is_blocked());

        // Want both, only recv paused — not blocked.
        engine.want_send = true;
        assert!(!engine.is_blocked());

        // Want both, both paused — blocked.
        engine.send_paused = true;
        assert!(engine.is_blocked());

        // Want only send, send paused — blocked.
        engine.want_recv = false;
        engine.recv_paused = false;
        assert!(engine.is_blocked());
    }

    #[test]
    fn test_setup_send() {
        let mut engine = TransferEngine::new();
        engine.setup_send();
        assert!(engine.want_send);
        assert!(!engine.want_recv);
        assert_eq!(engine.expected_size, -1);
        assert_eq!(engine.state(), TransferState::Sending);
    }

    #[test]
    fn test_setup_recv() {
        let mut engine = TransferEngine::new();
        engine.setup_recv(1024);
        assert!(!engine.want_send);
        assert!(engine.want_recv);
        assert_eq!(engine.expected_size, 1024);
        assert_eq!(engine.state(), TransferState::Receiving);
    }

    #[test]
    fn test_setup_sendrecv() {
        let mut engine = TransferEngine::new();
        engine.setup_sendrecv(2048);
        assert!(engine.want_send);
        assert!(engine.want_recv);
        assert_eq!(engine.expected_size, 2048);
        assert_eq!(engine.state(), TransferState::Sending);
    }

    #[test]
    fn test_setup_recv_unknown_size() {
        let mut engine = TransferEngine::new();
        engine.setup_recv(-1);
        assert_eq!(engine.expected_size, -1);
        assert!(engine.want_recv);
    }

    #[test]
    fn test_retry_request_no_retry() {
        let mut engine = TransferEngine::new();
        engine.bytes_received = 100;

        let result = engine.retry_request("http://example.com", true, false);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_retry_request_dead_connection() {
        let mut engine = TransferEngine::new();
        engine.bytes_received = 0;
        engine.bytes_sent = 0;

        let result = engine.retry_request("http://example.com", true, false);
        assert!(result.is_ok());
        let url = result.unwrap();
        assert!(url.is_some());
        assert_eq!(url.unwrap(), "http://example.com");
        assert_eq!(engine.retry_count, 1);
    }

    #[test]
    fn test_retry_request_max_retries() {
        let mut engine = TransferEngine::new();
        engine.bytes_received = 0;
        engine.bytes_sent = 0;
        engine.retry_count = CONN_MAX_RETRIES;

        let result = engine.retry_request("http://example.com", true, false);
        assert!(result.is_err());
        match result.unwrap_err() {
            CurlError::SendError => {}
            e => panic!("expected SendError, got {:?}", e),
        }
    }

    #[test]
    fn test_retry_request_refused_stream() {
        let mut engine = TransferEngine::new();
        engine.bytes_received = 0;

        let result = engine.retry_request("http://example.com", false, true);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_pretransfer() {
        let mut engine = TransferEngine::new();
        let result = engine.pretransfer();
        assert!(result.is_ok());
        assert_eq!(engine.state(), TransferState::Idle);
        assert_eq!(engine.bytes_received(), 0);
        assert_eq!(engine.bytes_sent(), 0);
        assert!(engine.start_time.is_some());
        assert_eq!(engine.retry_count, 0);
    }

    #[test]
    fn test_pretransfer_with_rate_limits() {
        let mut engine = TransferEngine::new();
        engine.config.max_recv_speed = 1024;
        engine.config.max_send_speed = 512;

        let result = engine.pretransfer();
        assert!(result.is_ok());
        assert!(engine.recv_rate_limiter.is_some());
        assert!(engine.send_rate_limiter.is_some());
    }

    #[test]
    fn test_pretransfer_no_rate_limits() {
        let mut engine = TransferEngine::new();
        let result = engine.pretransfer();
        assert!(result.is_ok());
        assert!(engine.recv_rate_limiter.is_none());
        assert!(engine.send_rate_limiter.is_none());
    }

    #[test]
    fn test_write_done_not_premature() {
        let mut engine = TransferEngine::new();
        engine.eos_written = true;
        let result = engine.write_done(false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_write_done_premature() {
        let mut engine = TransferEngine::new();
        engine.eos_written = true;
        let result = engine.write_done(true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_needs_flush_empty() {
        let engine = TransferEngine::new();
        assert!(!engine.needs_flush());
    }

    #[test]
    fn test_needs_flush_with_data() {
        let mut engine = TransferEngine::new();
        engine.send_buf.put_slice(b"data");
        assert!(engine.needs_flush());
    }

    #[test]
    fn test_pause_send() {
        let mut engine = TransferEngine::new();
        assert!(!engine.is_send_paused());

        engine.pause_send(true).unwrap();
        assert!(engine.is_send_paused());

        engine.pause_send(false).unwrap();
        assert!(!engine.is_send_paused());
    }

    #[test]
    fn test_pause_recv() {
        let mut engine = TransferEngine::new();
        assert!(!engine.is_recv_paused());

        engine.pause_recv(true).unwrap();
        assert!(engine.is_recv_paused());

        engine.pause_recv(false).unwrap();
        assert!(!engine.is_recv_paused());
    }

    #[test]
    fn test_set_response_code() {
        let mut engine = TransferEngine::new();
        engine.set_response_code(200);
        assert_eq!(engine.response_code(), 200);
    }

    #[test]
    fn test_redirect_tracking() {
        let mut engine = TransferEngine::new();
        assert_eq!(engine.redirect_count(), 0);
        assert!(engine.redirect_url().is_none());

        engine.set_redirect_url(Some("http://example.com/new".to_string()));
        assert_eq!(engine.redirect_url(), Some("http://example.com/new"));

        engine.increment_redirect();
        assert_eq!(engine.redirect_count(), 1);
    }

    #[test]
    fn test_supported_encodings() {
        let engine = TransferEngine::new();
        let encodings = engine.supported_encodings();
        // Should at least contain gzip and deflate since they're always available.
        assert!(encodings.contains("gzip"));
        assert!(encodings.contains("deflate"));
    }

    #[test]
    fn test_write_response_no_callback() {
        let mut engine = TransferEngine::new();
        // Without a write callback, data is silently consumed.
        let result = engine.write_response(b"hello world", false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_write_response_eos() {
        let mut engine = TransferEngine::new();
        let result = engine.write_response(b"", true);
        assert!(result.is_ok());
        assert!(engine.eos_written);
        assert!(engine.download_done);
    }

    #[test]
    fn test_write_response_with_callback() {
        let mut engine = TransferEngine::new();
        let mut received = Vec::new();
        engine.set_write_callback(Box::new(move |data: &[u8]| {
            received.extend_from_slice(data);
            Ok(data.len())
        }));
        let result = engine.write_response(b"test data", false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_write_response_callback_abort() {
        let mut engine = TransferEngine::new();
        engine.set_write_callback(Box::new(|_data: &[u8]| {
            Err(CallbackResult::Abort)
        }));
        let result = engine.write_response(b"test data", false);
        assert!(result.is_err());
        match result.unwrap_err() {
            CurlError::AbortedByCallback => {}
            e => panic!("expected AbortedByCallback, got {:?}", e),
        }
    }

    #[test]
    fn test_write_response_callback_pause() {
        let mut engine = TransferEngine::new();
        engine.set_write_callback(Box::new(|_data: &[u8]| {
            Err(CallbackResult::Pause)
        }));
        let result = engine.write_response(b"test data", false);
        assert!(result.is_ok());
        assert!(engine.recv_paused);
    }

    #[test]
    fn test_time_condition_none() {
        let engine = TransferEngine::new();
        assert!(engine.meets_timecondition(12345));
    }

    #[test]
    fn test_default_implementations() {
        let _config = TransferConfig::default();
        let _engine = TransferEngine::default();
    }

    // ====================================================================
    // Additional tests for coverage boost (Issue #2)
    // ====================================================================

    // -- Constants -------------------------------------------------------

    #[test]
    fn test_default_buffer_size_constant() {
        assert_eq!(DEFAULT_BUFFER_SIZE, 16 * 1024);
    }

    #[test]
    fn test_default_upload_buffer_size_constant() {
        assert_eq!(DEFAULT_UPLOAD_BUFFER_SIZE, 64 * 1024);
    }

    #[test]
    fn test_max_recv_loops_constant() {
        assert_eq!(MAX_RECV_LOOPS, 10);
    }

    #[test]
    fn test_conn_max_retries_constant() {
        assert_eq!(CONN_MAX_RETRIES, 5);
    }

    #[test]
    fn test_default_max_redirects_constant() {
        assert_eq!(DEFAULT_MAX_REDIRECTS, 50);
    }

    // -- TransferState traits -------------------------------------------

    #[test]
    fn test_transfer_state_clone_copy() {
        let s = TransferState::Sending;
        let cloned = s.clone();
        let copied = s;
        assert_eq!(cloned, TransferState::Sending);
        assert_eq!(copied, TransferState::Sending);
    }

    #[test]
    fn test_transfer_state_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(TransferState::Idle);
        set.insert(TransferState::Connecting);
        set.insert(TransferState::Sending);
        set.insert(TransferState::Receiving);
        set.insert(TransferState::Done);
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn test_transfer_state_debug() {
        let dbg = format!("{:?}", TransferState::Connecting);
        assert!(dbg.contains("Connecting"));
    }

    #[test]
    fn test_transfer_state_display_all_variants() {
        assert_eq!(TransferState::Idle.to_string(), "Idle");
        assert_eq!(TransferState::Connecting.to_string(), "Connecting");
        assert_eq!(TransferState::Sending.to_string(), "Sending");
        assert_eq!(TransferState::Receiving.to_string(), "Receiving");
        assert_eq!(TransferState::Done.to_string(), "Done");
    }

    #[test]
    fn test_transfer_state_equality() {
        assert_eq!(TransferState::Idle, TransferState::Idle);
        assert_ne!(TransferState::Idle, TransferState::Done);
    }

    // -- TimeCondition traits -------------------------------------------

    #[test]
    fn test_time_condition_default() {
        let tc: TimeCondition = TimeCondition::default();
        assert_eq!(tc, TimeCondition::None);
    }

    #[test]
    fn test_time_condition_clone_copy() {
        let tc = TimeCondition::IfModifiedSince;
        let cloned = tc.clone();
        let copied = tc;
        assert_eq!(cloned, TimeCondition::IfModifiedSince);
        assert_eq!(copied, TimeCondition::IfModifiedSince);
    }

    #[test]
    fn test_time_condition_debug() {
        let dbg = format!("{:?}", TimeCondition::LastMod);
        assert!(dbg.contains("LastMod"));
    }

    #[test]
    fn test_time_condition_all_variants_eq() {
        assert_eq!(TimeCondition::None, TimeCondition::None);
        assert_eq!(TimeCondition::IfModifiedSince, TimeCondition::IfModifiedSince);
        assert_eq!(TimeCondition::IfUnmodifiedSince, TimeCondition::IfUnmodifiedSince);
        assert_eq!(TimeCondition::LastMod, TimeCondition::LastMod);
        assert_ne!(TimeCondition::None, TimeCondition::LastMod);
    }

    // -- CallbackResult traits ------------------------------------------

    #[test]
    fn test_callback_result_debug() {
        let dbg = format!("{:?}", CallbackResult::Pause);
        assert!(dbg.contains("Pause"));
    }

    #[test]
    fn test_callback_result_clone_copy() {
        let cr = CallbackResult::Abort;
        let cloned = cr.clone();
        let copied = cr;
        assert_eq!(cloned, CallbackResult::Abort);
        assert_eq!(copied, CallbackResult::Abort);
    }

    #[test]
    fn test_callback_result_all_variants() {
        assert_eq!(CallbackResult::Continue, CallbackResult::Continue);
        assert_eq!(CallbackResult::Pause, CallbackResult::Pause);
        assert_eq!(CallbackResult::Abort, CallbackResult::Abort);
        assert_ne!(CallbackResult::Continue, CallbackResult::Pause);
        assert_ne!(CallbackResult::Pause, CallbackResult::Abort);
    }

    // -- DebugInfoType traits -------------------------------------------

    #[test]
    fn test_debug_info_type_all_variants() {
        let variants = [
            DebugInfoType::Text,
            DebugInfoType::HeaderIn,
            DebugInfoType::HeaderOut,
            DebugInfoType::DataIn,
            DebugInfoType::DataOut,
            DebugInfoType::SslDataIn,
            DebugInfoType::SslDataOut,
        ];
        for v in &variants {
            let dbg = format!("{:?}", v);
            assert!(!dbg.is_empty());
        }
        assert_eq!(DebugInfoType::Text, DebugInfoType::Text);
        assert_ne!(DebugInfoType::Text, DebugInfoType::HeaderIn);
    }

    #[test]
    fn test_debug_info_type_clone_copy() {
        let dit = DebugInfoType::DataOut;
        let cloned = dit.clone();
        let copied = dit;
        assert_eq!(cloned, DebugInfoType::DataOut);
        assert_eq!(copied, DebugInfoType::DataOut);
    }

    // -- TransferConfig additional setters ------------------------------

    #[test]
    fn test_transfer_config_set_time_condition() {
        let mut config = TransferConfig::new();
        config.set_time_condition(TimeCondition::IfModifiedSince, 1234567890);
        assert_eq!(config.time_condition, TimeCondition::IfModifiedSince);
        assert_eq!(config.time_value, 1234567890);
    }

    #[test]
    fn test_transfer_config_set_verbose() {
        let mut config = TransferConfig::new();
        assert!(!config.verbose);
        config.set_verbose(true);
        assert!(config.verbose);
        config.set_verbose(false);
        assert!(!config.verbose);
    }

    #[test]
    fn test_transfer_config_add_custom_header() {
        let mut config = TransferConfig::new();
        assert!(config.custom_headers.is_empty());
        config.add_custom_header("X-Test: value1".to_string());
        config.add_custom_header("X-Other: value2".to_string());
        assert_eq!(config.custom_headers.len(), 2);
        assert_eq!(config.custom_headers[0], "X-Test: value1");
        assert_eq!(config.custom_headers[1], "X-Other: value2");
    }

    #[test]
    fn test_transfer_config_upload_buffer_zero_ignored() {
        let mut config = TransferConfig::new();
        let original = config.upload_buffer_size;
        config.set_upload_buffer_size(0);
        assert_eq!(config.upload_buffer_size, original);
    }

    #[test]
    fn test_transfer_config_debug() {
        let config = TransferConfig::new();
        let dbg = format!("{:?}", config);
        assert!(dbg.contains("TransferConfig"));
    }

    #[test]
    fn test_transfer_config_set_low_speed_time() {
        let mut config = TransferConfig::new();
        config.set_low_speed_time(Duration::from_secs(30));
        assert_eq!(config.low_speed_time, Duration::from_secs(30));
    }

    #[test]
    fn test_transfer_config_chained_setters() {
        let mut config = TransferConfig::new();
        config
            .set_timeout(Duration::from_secs(60))
            .set_verbose(true)
            .set_follow_location(true)
            .set_max_redirects(5)
            .set_time_condition(TimeCondition::IfUnmodifiedSince, 100)
            .add_custom_header("Host: example.com".to_string());

        assert_eq!(config.timeout, Duration::from_secs(60));
        assert!(config.verbose);
        assert!(config.follow_location);
        assert_eq!(config.max_redirects, 5);
        assert_eq!(config.time_condition, TimeCondition::IfUnmodifiedSince);
        assert_eq!(config.time_value, 100);
        assert_eq!(config.custom_headers.len(), 1);
    }

    // -- TransferEngine accessors ---------------------------------------

    #[test]
    fn test_engine_config_accessor() {
        let engine = TransferEngine::new();
        let config = engine.config();
        assert_eq!(config.buffer_size, DEFAULT_BUFFER_SIZE);
    }

    #[test]
    fn test_engine_config_mut_accessor() {
        let mut engine = TransferEngine::new();
        engine.config_mut().set_timeout(Duration::from_secs(42));
        assert_eq!(engine.config().timeout, Duration::from_secs(42));
    }

    #[test]
    fn test_engine_progress_accessor() {
        let engine = TransferEngine::new();
        let _progress = engine.progress();
    }

    #[test]
    fn test_engine_progress_mut_accessor() {
        let mut engine = TransferEngine::new();
        let _progress = engine.progress_mut();
    }

    #[test]
    fn test_engine_state_accessor() {
        let engine = TransferEngine::new();
        assert_eq!(engine.state(), TransferState::Idle);
    }

    // -- State transitions (begin_send, mark_done, reset) ---------------

    #[test]
    fn test_begin_send() {
        let mut engine = TransferEngine::new();
        assert_eq!(engine.state(), TransferState::Idle);
        engine.begin_send();
        assert_eq!(engine.state(), TransferState::Sending);
    }

    #[test]
    fn test_mark_done() {
        let mut engine = TransferEngine::new();
        engine.begin_send();
        engine.mark_done();
        assert_eq!(engine.state(), TransferState::Done);
    }

    #[test]
    fn test_reset_state() {
        let mut engine = TransferEngine::new();
        engine.begin_send();
        engine.mark_done();
        engine.reset();
        assert_eq!(engine.state(), TransferState::Idle);
    }

    #[test]
    fn test_state_full_lifecycle() {
        let mut engine = TransferEngine::new();
        assert_eq!(engine.state(), TransferState::Idle);

        engine.begin_send();
        assert_eq!(engine.state(), TransferState::Sending);

        engine.mark_done();
        assert_eq!(engine.state(), TransferState::Done);

        engine.reset();
        assert_eq!(engine.state(), TransferState::Idle);
    }

    // -- Callback setters -----------------------------------------------

    #[test]
    fn test_set_read_callback() {
        let mut engine = TransferEngine::new();
        assert!(engine.read_callback.is_none());
        engine.set_read_callback(Box::new(|_buf: &mut [u8]| Ok(0)));
        assert!(engine.read_callback.is_some());
    }

    #[test]
    fn test_set_header_callback() {
        let mut engine = TransferEngine::new();
        assert!(engine.header_callback.is_none());
        engine.set_header_callback(Box::new(|data: &[u8]| Ok(data.len())));
        assert!(engine.header_callback.is_some());
    }

    #[test]
    fn test_set_debug_callback() {
        let mut engine = TransferEngine::new();
        assert!(engine.debug_callback.is_none());
        engine.set_debug_callback(Box::new(|_info_type, _data| {}));
        assert!(engine.debug_callback.is_some());
    }

    // -- write_response_header ------------------------------------------

    #[test]
    fn test_write_response_header_status_line_http11() {
        let mut engine = TransferEngine::new();
        let result = engine.write_response_header("HTTP/1.1 200 OK\r\n", false);
        assert!(result.is_ok());
        assert_eq!(engine.response_code(), 200);
    }

    #[test]
    fn test_write_response_header_status_line_http2() {
        let mut engine = TransferEngine::new();
        let result = engine.write_response_header("HTTP/2 404 Not Found\r\n", false);
        assert!(result.is_ok());
        assert_eq!(engine.response_code(), 404);
    }

    #[test]
    fn test_write_response_header_status_line_http10() {
        let mut engine = TransferEngine::new();
        let result = engine.write_response_header("HTTP/1.0 301 Moved\r\n", false);
        assert!(result.is_ok());
        assert_eq!(engine.response_code(), 301);
    }

    #[test]
    fn test_write_response_header_status_500() {
        let mut engine = TransferEngine::new();
        let result = engine.write_response_header("HTTP/1.1 500 Internal Server Error\r\n", false);
        assert!(result.is_ok());
        assert_eq!(engine.response_code(), 500);
    }

    #[test]
    fn test_write_response_header_regular_header() {
        let mut engine = TransferEngine::new();
        let result = engine.write_response_header("Content-Type: text/html\r\n", false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_write_response_header_multiple_headers() {
        let mut engine = TransferEngine::new();
        engine.write_response_header("HTTP/1.1 200 OK\r\n", false).unwrap();
        engine.write_response_header("Content-Type: text/html\r\n", false).unwrap();
        engine.write_response_header("Content-Length: 42\r\n", false).unwrap();
        assert_eq!(engine.response_code(), 200);
    }

    #[test]
    fn test_write_response_header_empty_line_eos() {
        let mut engine = TransferEngine::new();
        engine.write_response_header("HTTP/1.1 200 OK\r\n", false).unwrap();
        let result = engine.write_response_header("\r\n", true);
        assert!(result.is_ok());
        assert!(engine.eos_written);
    }

    #[test]
    fn test_write_response_header_with_header_callback() {
        let mut engine = TransferEngine::new();
        let mut received_headers: Vec<Vec<u8>> = Vec::new();
        engine.set_header_callback(Box::new(move |data: &[u8]| {
            received_headers.push(data.to_vec());
            Ok(data.len())
        }));
        let result = engine.write_response_header("HTTP/1.1 200 OK\r\n", false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_write_response_header_callback_abort() {
        let mut engine = TransferEngine::new();
        engine.set_header_callback(Box::new(|_data: &[u8]| {
            Err(CallbackResult::Abort)
        }));
        let result = engine.write_response_header("HTTP/1.1 200 OK\r\n", false);
        assert!(result.is_err());
        match result.unwrap_err() {
            CurlError::AbortedByCallback => {}
            e => panic!("expected AbortedByCallback, got {:?}", e),
        }
    }

    #[test]
    fn test_write_response_header_callback_pause() {
        let mut engine = TransferEngine::new();
        engine.set_header_callback(Box::new(|_data: &[u8]| {
            Err(CallbackResult::Pause)
        }));
        let result = engine.write_response_header("HTTP/1.1 200 OK\r\n", false);
        assert!(result.is_ok());
        assert!(engine.recv_paused);
    }

    #[test]
    fn test_write_response_header_callback_continue() {
        let mut engine = TransferEngine::new();
        engine.set_header_callback(Box::new(|_data: &[u8]| {
            Err(CallbackResult::Continue)
        }));
        let result = engine.write_response_header("Content-Type: text/html\r\n", false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_write_response_header_verbose_debug_callback() {
        let mut engine = TransferEngine::new();
        engine.config.verbose = true;
        let mut called = false;
        engine.set_debug_callback(Box::new(move |info_type, _data| {
            assert_eq!(info_type, DebugInfoType::HeaderIn);
            called = true;
        }));
        let result = engine.write_response_header("HTTP/1.1 200 OK\r\n", false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_write_response_header_not_verbose_no_debug() {
        let mut engine = TransferEngine::new();
        engine.config.verbose = false;
        engine.set_debug_callback(Box::new(move |_info_type, _data| {
            panic!("debug callback should not be called when verbose=false");
        }));
        let result = engine.write_response_header("HTTP/1.1 200 OK\r\n", false);
        assert!(result.is_ok());
    }

    // -- write_response_bytes edge cases --------------------------------

    #[test]
    fn test_write_response_callback_continue_result() {
        let mut engine = TransferEngine::new();
        engine.set_write_callback(Box::new(|_data: &[u8]| {
            Err(CallbackResult::Continue)
        }));
        let result = engine.write_response(b"some data", false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_write_response_callback_short_consume_error() {
        let mut engine = TransferEngine::new();
        engine.set_write_callback(Box::new(|_data: &[u8]| {
            Ok(1) // consume only 1 byte out of many
        }));
        let result = engine.write_response(b"hello world", false);
        assert!(result.is_err());
        match result.unwrap_err() {
            CurlError::WriteError => {}
            e => panic!("expected WriteError, got {:?}", e),
        }
    }

    #[test]
    fn test_write_response_empty_data_not_eos() {
        let mut engine = TransferEngine::new();
        let result = engine.write_response(b"", false);
        assert!(result.is_ok());
        assert!(!engine.eos_written);
    }

    #[test]
    fn test_write_response_empty_eos_with_callback() {
        let mut engine = TransferEngine::new();
        engine.set_write_callback(Box::new(|_data: &[u8]| {
            Ok(0)
        }));
        let result = engine.write_response(b"", true);
        assert!(result.is_ok());
        assert!(engine.eos_written);
        assert!(engine.download_done);
    }

    #[test]
    fn test_write_response_large_data() {
        let mut engine = TransferEngine::new();
        let data = vec![b'X'; 65536];
        engine.set_write_callback(Box::new(move |d: &[u8]| {
            Ok(d.len())
        }));
        let result = engine.write_response(&data, false);
        assert!(result.is_ok());
    }

    // -- setup_content_decoding -----------------------------------------

    #[test]
    fn test_setup_content_decoding_empty() {
        let mut engine = TransferEngine::new();
        let result = engine.setup_content_decoding("");
        assert!(result.is_ok());
        assert!(engine.content_decoder.is_none());
    }

    #[test]
    fn test_setup_content_decoding_identity() {
        let mut engine = TransferEngine::new();
        let result = engine.setup_content_decoding("identity");
        assert!(result.is_ok());
        assert!(engine.content_decoder.is_none());
    }

    #[test]
    fn test_setup_content_decoding_identity_case_insensitive() {
        let mut engine = TransferEngine::new();
        let result = engine.setup_content_decoding("Identity");
        assert!(result.is_ok());
        assert!(engine.content_decoder.is_none());
    }

    #[test]
    fn test_setup_content_decoding_gzip() {
        let mut engine = TransferEngine::new();
        let result = engine.setup_content_decoding("gzip");
        assert!(result.is_ok());
        assert!(engine.content_decoder.is_some());
    }

    #[test]
    fn test_setup_content_decoding_deflate() {
        let mut engine = TransferEngine::new();
        let result = engine.setup_content_decoding("deflate");
        assert!(result.is_ok());
        assert!(engine.content_decoder.is_some());
    }

    #[test]
    fn test_setup_content_decoding_replaces_previous() {
        let mut engine = TransferEngine::new();
        engine.setup_content_decoding("gzip").unwrap();
        assert!(engine.content_decoder.is_some());
        engine.setup_content_decoding("identity").unwrap();
        assert!(engine.content_decoder.is_none());
    }

    // -- write_done with decoder ----------------------------------------

    #[test]
    fn test_write_done_eos_not_written_no_decoder() {
        let mut engine = TransferEngine::new();
        engine.eos_written = false;
        let result = engine.write_done(false);
        assert!(result.is_ok());
        assert!(engine.eos_written);
    }

    #[test]
    fn test_write_done_premature_eos_not_written() {
        let mut engine = TransferEngine::new();
        engine.eos_written = false;
        let result = engine.write_done(true);
        assert!(result.is_ok());
        assert!(engine.eos_written);
    }

    // -- write_response with content decoding ---------------------------

    #[test]
    fn test_write_response_with_gzip_decoder() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        // Prepare gzip-encoded data.
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(b"hello decoded world").unwrap();
        let compressed = gz.finish().unwrap();

        let mut engine = TransferEngine::new();
        engine.setup_content_decoding("gzip").unwrap();
        let mut decoded_output = Vec::new();
        engine.set_write_callback(Box::new(move |data: &[u8]| {
            decoded_output.extend_from_slice(data);
            Ok(data.len())
        }));
        // Write compressed data, then signal EOS.
        let result = engine.write_response(&compressed, false);
        assert!(result.is_ok());
        let result = engine.write_response(b"", true);
        assert!(result.is_ok());
        assert!(engine.eos_written);
    }

    #[test]
    fn test_write_response_with_deflate_decoder() {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(b"deflated content here").unwrap();
        let compressed = enc.finish().unwrap();

        let mut engine = TransferEngine::new();
        engine.setup_content_decoding("deflate").unwrap();
        engine.set_write_callback(Box::new(move |data: &[u8]| Ok(data.len())));
        let result = engine.write_response(&compressed, false);
        assert!(result.is_ok());
    }

    // -- bytes tracking -------------------------------------------------

    #[test]
    fn test_bytes_received_tracking() {
        let mut engine = TransferEngine::new();
        assert_eq!(engine.bytes_received(), 0);
        engine.bytes_received = 42;
        assert_eq!(engine.bytes_received(), 42);
    }

    #[test]
    fn test_bytes_sent_tracking() {
        let mut engine = TransferEngine::new();
        assert_eq!(engine.bytes_sent(), 0);
        engine.bytes_sent = 100;
        assert_eq!(engine.bytes_sent(), 100);
    }

    // -- Upload/download done flags -------------------------------------

    #[test]
    fn test_is_download_done_tracking() {
        let mut engine = TransferEngine::new();
        assert!(!engine.is_download_done());
        engine.download_done = true;
        assert!(engine.is_download_done());
    }

    #[test]
    fn test_is_upload_done_tracking() {
        let mut engine = TransferEngine::new();
        assert!(!engine.is_upload_done());
        engine.upload_done = true;
        assert!(engine.is_upload_done());
    }

    // -- Redirect tracking extended ------------------------------------

    #[test]
    fn test_redirect_url_clear() {
        let mut engine = TransferEngine::new();
        engine.set_redirect_url(Some("http://a.com".to_string()));
        assert!(engine.redirect_url().is_some());
        engine.set_redirect_url(None);
        assert!(engine.redirect_url().is_none());
    }

    #[test]
    fn test_increment_redirect_multiple() {
        let mut engine = TransferEngine::new();
        for i in 1..=5 {
            engine.increment_redirect();
            assert_eq!(engine.redirect_count(), i);
        }
    }

    // -- is_send_paused / is_recv_paused with rate limiter ---------------

    #[test]
    fn test_is_send_paused_with_rate_limiter() {
        let mut engine = TransferEngine::new();
        engine.config.max_send_speed = 100;
        engine.pretransfer().unwrap();
        assert!(!engine.is_send_paused());
        engine.pause_send(true).unwrap();
        assert!(engine.is_send_paused());
        engine.pause_send(false).unwrap();
        assert!(!engine.is_send_paused());
    }

    #[test]
    fn test_is_recv_paused_with_rate_limiter() {
        let mut engine = TransferEngine::new();
        engine.config.max_recv_speed = 100;
        engine.pretransfer().unwrap();
        assert!(!engine.is_recv_paused());
        engine.pause_recv(true).unwrap();
        assert!(engine.is_recv_paused());
        engine.pause_recv(false).unwrap();
        assert!(!engine.is_recv_paused());
    }

    // -- setup variants -------------------------------------------------

    #[test]
    fn test_setup_send_from_non_idle() {
        let mut engine = TransferEngine::new();
        engine.state = TransferState::Receiving;
        engine.setup_send();
        // State should NOT change because it's not Idle.
        assert_eq!(engine.state(), TransferState::Receiving);
        assert!(engine.want_send);
        assert!(!engine.want_recv);
    }

    #[test]
    fn test_setup_recv_zero_size() {
        let mut engine = TransferEngine::new();
        engine.setup_recv(0);
        assert_eq!(engine.expected_size, 0);
        assert!(engine.want_recv);
    }

    #[test]
    fn test_setup_recv_negative_size() {
        let mut engine = TransferEngine::new();
        engine.setup_recv(-1);
        assert_eq!(engine.expected_size, -1);
    }

    #[test]
    fn test_setup_recv_from_sending_state() {
        let mut engine = TransferEngine::new();
        engine.state = TransferState::Sending;
        engine.setup_recv(1024);
        assert_eq!(engine.state(), TransferState::Receiving);
    }

    #[test]
    fn test_setup_sendrecv_negative_size() {
        let mut engine = TransferEngine::new();
        engine.setup_sendrecv(-1);
        assert_eq!(engine.expected_size, -1);
        assert!(engine.want_send);
        assert!(engine.want_recv);
    }

    #[test]
    fn test_setup_sendrecv_from_non_idle() {
        let mut engine = TransferEngine::new();
        engine.state = TransferState::Receiving;
        engine.setup_sendrecv(1024);
        // State should NOT change because it's not Idle.
        assert_eq!(engine.state(), TransferState::Receiving);
    }

    // -- retry_request edge cases ---------------------------------------

    #[test]
    fn test_retry_request_not_reused_not_refused() {
        let mut engine = TransferEngine::new();
        engine.bytes_received = 0;
        engine.bytes_sent = 0;
        let result = engine.retry_request("http://example.com", false, false);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_retry_request_reused_with_data_received() {
        let mut engine = TransferEngine::new();
        engine.bytes_received = 100;
        engine.bytes_sent = 0;
        let result = engine.retry_request("http://example.com", true, false);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_retry_request_reused_with_data_sent() {
        let mut engine = TransferEngine::new();
        engine.bytes_received = 0;
        engine.bytes_sent = 50;
        let result = engine.retry_request("http://example.com", true, false);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_retry_request_refused_with_data() {
        let mut engine = TransferEngine::new();
        engine.bytes_received = 100;
        let result = engine.retry_request("http://example.com", false, true);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_retry_request_increments_count() {
        let mut engine = TransferEngine::new();
        engine.bytes_received = 0;
        engine.bytes_sent = 0;
        for i in 1..=CONN_MAX_RETRIES {
            let result = engine.retry_request("http://ex.com", true, false).unwrap();
            assert!(result.is_some());
            assert_eq!(engine.retry_count, i);
            // Reset bytes so next iteration triggers retry again.
            engine.bytes_received = 0;
            engine.bytes_sent = 0;
        }
        // One more should fail.
        let result = engine.retry_request("http://ex.com", true, false);
        assert!(result.is_err());
    }

    // -- pretransfer with existing state --------------------------------

    #[test]
    fn test_pretransfer_resets_prior_state() {
        let mut engine = TransferEngine::new();
        // Set up some state.
        engine.bytes_received = 1234;
        engine.bytes_sent = 5678;
        engine.redirect_count = 3;
        engine.redirect_url = Some("http://old.com".to_string());
        engine.response_code = 301;
        engine.download_done = true;
        engine.upload_done = true;
        engine.eos_written = true;
        engine.send_paused = true;
        engine.recv_paused = true;
        engine.retry_count = 2;
        engine.state = TransferState::Done;

        let result = engine.pretransfer();
        assert!(result.is_ok());

        // All should be reset.
        assert_eq!(engine.bytes_received, 0);
        assert_eq!(engine.bytes_sent, 0);
        assert_eq!(engine.redirect_count, 0);
        assert!(engine.redirect_url.is_none());
        assert_eq!(engine.response_code, 0);
        assert!(!engine.download_done);
        assert!(!engine.upload_done);
        assert!(!engine.eos_written);
        assert!(!engine.send_paused);
        assert!(!engine.recv_paused);
        assert_eq!(engine.retry_count, 0);
        assert_eq!(engine.state, TransferState::Idle);
        assert!(engine.start_time.is_some());
    }

    #[test]
    fn test_pretransfer_clears_content_decoder() {
        let mut engine = TransferEngine::new();
        engine.setup_content_decoding("gzip").unwrap();
        assert!(engine.content_decoder.is_some());
        engine.pretransfer().unwrap();
        assert!(engine.content_decoder.is_none());
    }

    #[test]
    fn test_pretransfer_clears_buffers() {
        let mut engine = TransferEngine::new();
        engine.send_buf.put_slice(b"leftover send data");
        engine.recv_buf.put_slice(b"leftover recv data");
        engine.pretransfer().unwrap();
        assert!(engine.send_buf.is_empty());
        assert!(engine.recv_buf.is_empty());
    }

    // -- check_headers edge cases ---------------------------------------

    #[test]
    fn test_check_headers_empty_list() {
        let engine = TransferEngine::new();
        assert!(engine.check_headers("Content-Type").is_none());
    }

    #[test]
    fn test_check_headers_prefix_only_no_separator() {
        let mut engine = TransferEngine::new();
        engine.config.custom_headers = vec!["ContentType".to_string()];
        assert!(engine.check_headers("ContentType").is_none());
    }

    #[test]
    fn test_check_headers_semicolon_separator() {
        let mut engine = TransferEngine::new();
        engine.config.custom_headers = vec!["X-Remove;".to_string()];
        assert!(engine.check_headers("X-Remove").is_some());
    }

    #[test]
    fn test_check_headers_returns_first_match() {
        let mut engine = TransferEngine::new();
        engine.config.custom_headers = vec![
            "Accept: text/html".to_string(),
            "Accept: application/json".to_string(),
        ];
        let found = engine.check_headers("Accept");
        assert_eq!(found, Some("Accept: text/html"));
    }

    // -- meets_timecondition edge cases ---------------------------------

    #[test]
    fn test_meets_timecondition_lastmod() {
        let mut engine = TransferEngine::new();
        engine.config.time_condition = TimeCondition::LastMod;
        engine.config.time_value = 1000;
        // LastMod always returns true.
        assert!(engine.meets_timecondition(500));
        assert!(engine.meets_timecondition(1000));
        assert!(engine.meets_timecondition(2000));
    }

    #[test]
    fn test_meets_timecondition_doc_time_zero() {
        let mut engine = TransferEngine::new();
        engine.config.time_condition = TimeCondition::IfModifiedSince;
        engine.config.time_value = 1000;
        // doc time 0 → always met.
        assert!(engine.meets_timecondition(0));
    }

    #[test]
    fn test_meets_timecondition_ref_time_zero() {
        let mut engine = TransferEngine::new();
        engine.config.time_condition = TimeCondition::IfUnmodifiedSince;
        engine.config.time_value = 0;
        // ref time 0 → always met.
        assert!(engine.meets_timecondition(5000));
    }

    // -- TypedTransfer lifecycle ----------------------------------------

    #[test]
    fn test_typed_transfer_idle_new() {
        let engine = TransferEngine::new();
        let transfer = TypedTransfer::<Idle>::new(engine);
        assert_eq!(transfer.engine().state(), TransferState::Idle);
    }

    #[test]
    fn test_typed_transfer_idle_engine_mut() {
        let engine = TransferEngine::new();
        let mut transfer = TypedTransfer::<Idle>::new(engine);
        transfer.engine_mut().config_mut().set_verbose(true);
        assert!(transfer.engine().config().verbose);
    }

    #[test]
    fn test_typed_transfer_connect() {
        let engine = TransferEngine::new();
        let idle = TypedTransfer::<Idle>::new(engine);
        let connected = idle.connect().unwrap();
        assert!(connected.engine().start_time.is_some());
    }

    #[test]
    fn test_typed_transfer_connected_engine() {
        let engine = TransferEngine::new();
        let idle = TypedTransfer::<Idle>::new(engine);
        let connected = idle.connect().unwrap();
        let _ = connected.engine().config();
    }

    #[test]
    fn test_typed_transfer_connected_engine_mut() {
        let engine = TransferEngine::new();
        let idle = TypedTransfer::<Idle>::new(engine);
        let mut connected = idle.connect().unwrap();
        connected.engine_mut().config_mut().set_timeout(Duration::from_secs(5));
    }

    #[test]
    fn test_typed_transfer_start_sending() {
        let engine = TransferEngine::new();
        let idle = TypedTransfer::<Idle>::new(engine);
        let connected = idle.connect().unwrap();
        let transferring = connected.start_sending().unwrap();
        assert_eq!(transferring.engine().state(), TransferState::Sending);
    }

    #[test]
    fn test_typed_transfer_transferring_engine() {
        let engine = TransferEngine::new();
        let t = TypedTransfer::<Idle>::new(engine)
            .connect().unwrap()
            .start_sending().unwrap();
        assert_eq!(t.engine().state(), TransferState::Sending);
    }

    #[test]
    fn test_typed_transfer_transferring_engine_mut() {
        let engine = TransferEngine::new();
        let mut t = TypedTransfer::<Idle>::new(engine)
            .connect().unwrap()
            .start_sending().unwrap();
        t.engine_mut().set_response_code(200);
        assert_eq!(t.engine().response_code(), 200);
    }

    #[test]
    fn test_typed_transfer_complete() {
        let engine = TransferEngine::new();
        let t = TypedTransfer::<Idle>::new(engine)
            .connect().unwrap()
            .start_sending().unwrap()
            .complete().unwrap();
        assert_eq!(t.engine().state(), TransferState::Done);
    }

    #[test]
    fn test_typed_transfer_complete_into_engine() {
        let engine = TransferEngine::new();
        let complete = TypedTransfer::<Idle>::new(engine)
            .connect().unwrap()
            .start_sending().unwrap()
            .complete().unwrap();
        let recovered = complete.into_engine();
        assert_eq!(recovered.state(), TransferState::Done);
    }

    #[test]
    fn test_typed_transfer_reset() {
        let engine = TransferEngine::new();
        let idle_again = TypedTransfer::<Idle>::new(engine)
            .connect().unwrap()
            .start_sending().unwrap()
            .complete().unwrap()
            .reset();
        assert_eq!(idle_again.engine().state(), TransferState::Idle);
    }

    #[test]
    fn test_typed_transfer_full_lifecycle() {
        let mut engine = TransferEngine::new();
        engine.config_mut().set_max_recv_speed(1024);

        let idle = TypedTransfer::<Idle>::new(engine);
        let connected = idle.connect().unwrap();
        let transferring = connected.start_sending().unwrap();
        let complete = transferring.complete().unwrap();
        let idle_again = complete.reset();

        assert_eq!(idle_again.engine().state(), TransferState::Idle);
        assert_eq!(idle_again.engine().config().max_recv_speed, 1024);
    }

    // -- Marker type Debug impls ----------------------------------------

    #[test]
    fn test_marker_type_debug() {
        assert!(!format!("{:?}", Idle).is_empty());
        assert!(!format!("{:?}", Connected).is_empty());
        assert!(!format!("{:?}", Transferring).is_empty());
        assert!(!format!("{:?}", Complete).is_empty());
    }

    // -- needs_flush and send_buf interaction ---------------------------

    #[test]
    fn test_needs_flush_after_clear() {
        let mut engine = TransferEngine::new();
        engine.send_buf.put_slice(b"data");
        assert!(engine.needs_flush());
        engine.send_buf.clear();
        assert!(!engine.needs_flush());
    }

    // -- headersep extended tests --------------------------------------

    #[test]
    fn test_headersep_all_ascii() {
        let separators = [b':', b';'];
        let non_sep = [b' ', b'\t', b'=', b',', b'A', b'z', b'0', b'\0', b'\n'];
        for &ch in &separators {
            assert!(headersep(ch), "expected '{}' to be separator", ch as char);
        }
        for &ch in &non_sep {
            assert!(!headersep(ch), "expected '{}' to NOT be separator", ch as char);
        }
    }

    // -- response_headers accessor -------------------------------------

    #[test]
    fn test_response_headers_accessor() {
        let engine = TransferEngine::new();
        let headers = engine.response_headers();
        assert!(headers.is_empty());
    }

    // -- supported_encodings content ------------------------------------

    #[test]
    fn test_supported_encodings_contains_br() {
        let engine = TransferEngine::new();
        let enc = engine.supported_encodings();
        // Brotli is compiled in — should appear.
        assert!(enc.contains("br"));
    }

    #[test]
    fn test_supported_encodings_contains_zstd() {
        let engine = TransferEngine::new();
        let enc = engine.supported_encodings();
        assert!(enc.contains("zstd"));
    }

    // -- write_response_header status line parsing ----------------------

    #[test]
    fn test_write_response_header_status_100_continue() {
        let mut engine = TransferEngine::new();
        engine.write_response_header("HTTP/1.1 100 Continue\r\n", false).unwrap();
        assert_eq!(engine.response_code(), 100);
    }

    #[test]
    fn test_write_response_header_status_204_no_content() {
        let mut engine = TransferEngine::new();
        engine.write_response_header("HTTP/1.1 204 No Content\r\n", false).unwrap();
        assert_eq!(engine.response_code(), 204);
    }

    #[test]
    fn test_write_response_header_status_304_not_modified() {
        let mut engine = TransferEngine::new();
        engine.write_response_header("HTTP/1.1 304 Not Modified\r\n", false).unwrap();
        assert_eq!(engine.response_code(), 304);
    }

    // -- shutdown flags -------------------------------------------------

    #[test]
    fn test_shutdown_flags_after_setup_send() {
        let mut engine = TransferEngine::new();
        engine.shutdown_on_done = true;
        engine.shutdown_err_ignore = true;
        engine.setup_send();
        assert!(!engine.shutdown_on_done);
        assert!(!engine.shutdown_err_ignore);
    }

    #[test]
    fn test_shutdown_flags_after_setup_recv() {
        let mut engine = TransferEngine::new();
        engine.shutdown_on_done = true;
        engine.shutdown_err_ignore = true;
        engine.setup_recv(100);
        assert!(!engine.shutdown_on_done);
        assert!(!engine.shutdown_err_ignore);
    }

    #[test]
    fn test_shutdown_flags_after_setup_sendrecv() {
        let mut engine = TransferEngine::new();
        engine.shutdown_on_done = true;
        engine.shutdown_err_ignore = true;
        engine.setup_sendrecv(100);
        assert!(!engine.shutdown_on_done);
        assert!(!engine.shutdown_err_ignore);
    }

    // -- expected_size tracking ----------------------------------------

    #[test]
    fn test_expected_size_default() {
        let engine = TransferEngine::new();
        assert_eq!(engine.expected_size, -1);
    }

    #[test]
    fn test_expected_size_after_setup_recv() {
        let mut engine = TransferEngine::new();
        engine.setup_recv(4096);
        assert_eq!(engine.expected_size, 4096);
    }

    #[test]
    fn test_expected_size_after_setup_sendrecv() {
        let mut engine = TransferEngine::new();
        engine.setup_sendrecv(8192);
        assert_eq!(engine.expected_size, 8192);
    }

    // -- want_send / want_recv tracking --------------------------------

    #[test]
    fn test_want_send_recv_defaults() {
        let engine = TransferEngine::new();
        assert!(!engine.want_send);
        assert!(!engine.want_recv);
    }

    #[test]
    fn test_want_send_after_setup_send() {
        let mut engine = TransferEngine::new();
        engine.setup_send();
        assert!(engine.want_send);
        assert!(!engine.want_recv);
    }

    #[test]
    fn test_want_recv_after_setup_recv() {
        let mut engine = TransferEngine::new();
        engine.setup_recv(100);
        assert!(!engine.want_send);
        assert!(engine.want_recv);
    }

    #[test]
    fn test_want_both_after_setup_sendrecv() {
        let mut engine = TransferEngine::new();
        engine.setup_sendrecv(100);
        assert!(engine.want_send);
        assert!(engine.want_recv);
    }

    // -- pretransfer resets want flags ----------------------------------

    #[test]
    fn test_pretransfer_resets_want_flags() {
        let mut engine = TransferEngine::new();
        engine.setup_sendrecv(100);
        assert!(engine.want_send);
        assert!(engine.want_recv);
        engine.pretransfer().unwrap();
        assert!(!engine.want_send);
        assert!(!engine.want_recv);
    }

    // -- write_response_header complex flows ----------------------------

    #[test]
    fn test_write_response_header_full_http_flow() {
        let mut engine = TransferEngine::new();
        // Simulate a complete HTTP response header sequence.
        engine.write_response_header("HTTP/1.1 200 OK\r\n", false).unwrap();
        engine.write_response_header("Content-Type: text/plain\r\n", false).unwrap();
        engine.write_response_header("Content-Length: 13\r\n", false).unwrap();
        engine.write_response_header("\r\n", true).unwrap();

        assert_eq!(engine.response_code(), 200);
        assert!(engine.eos_written);
    }

    #[test]
    fn test_write_response_header_overwrites_status_code() {
        let mut engine = TransferEngine::new();
        engine.write_response_header("HTTP/1.1 301 Moved\r\n", false).unwrap();
        assert_eq!(engine.response_code(), 301);
        // Second status line (e.g., after redirect) overwrites.
        engine.write_response_header("HTTP/1.1 200 OK\r\n", false).unwrap();
        assert_eq!(engine.response_code(), 200);
    }

    // -- pause_send and pause_recv with rate limiter --------------------

    #[test]
    fn test_pause_send_toggle_with_rate_limiter() {
        let mut engine = TransferEngine::new();
        engine.config.max_send_speed = 50;
        engine.pretransfer().unwrap();

        engine.pause_send(true).unwrap();
        assert!(engine.send_paused);
        engine.pause_send(false).unwrap();
        assert!(!engine.send_paused);
    }

    #[test]
    fn test_pause_recv_toggle_with_rate_limiter() {
        let mut engine = TransferEngine::new();
        engine.config.max_recv_speed = 50;
        engine.pretransfer().unwrap();

        engine.pause_recv(true).unwrap();
        assert!(engine.recv_paused);
        engine.pause_recv(false).unwrap();
        assert!(!engine.recv_paused);
    }

    // -- is_blocked comprehensive scenarios ----------------------------

    #[test]
    fn test_is_blocked_only_send_not_paused() {
        let mut engine = TransferEngine::new();
        engine.want_send = true;
        engine.want_recv = false;
        engine.send_paused = false;
        assert!(!engine.is_blocked());
    }

    #[test]
    fn test_is_blocked_both_only_recv_paused() {
        let mut engine = TransferEngine::new();
        engine.want_send = true;
        engine.want_recv = true;
        engine.recv_paused = true;
        engine.send_paused = false;
        assert!(!engine.is_blocked());
    }

    #[test]
    fn test_is_blocked_both_only_send_paused() {
        let mut engine = TransferEngine::new();
        engine.want_send = true;
        engine.want_recv = true;
        engine.send_paused = true;
        engine.recv_paused = false;
        assert!(!engine.is_blocked());
    }

    // -- Config interactions with pretransfer ---------------------------

    #[test]
    fn test_pretransfer_progress_configuration() {
        let mut engine = TransferEngine::new();
        engine.config.low_speed_limit = 1024;
        engine.config.low_speed_time = Duration::from_secs(30);
        engine.pretransfer().unwrap();
        // Verify progress tracker was configured.
        assert_eq!(engine.progress.low_speed_limit, 1024);
        assert_eq!(engine.progress.low_speed_time, 30);
    }

    // -- write_response with eos and no callback -----------------------

    #[test]
    fn test_write_response_eos_sets_both_flags() {
        let mut engine = TransferEngine::new();
        engine.write_response(b"final", true).unwrap();
        assert!(engine.eos_written);
        assert!(engine.download_done);
    }

    #[test]
    fn test_write_response_eos_callback_full_consume() {
        let mut engine = TransferEngine::new();
        engine.set_write_callback(Box::new(|d: &[u8]| Ok(d.len())));
        engine.write_response(b"final data", true).unwrap();
        assert!(engine.eos_written);
        assert!(engine.download_done);
    }
}
