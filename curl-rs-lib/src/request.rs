//! Request state machine for individual transfer lifecycle management.
//!
//! This module is the Rust rewrite of `lib/request.c` and `lib/request.h`
//! from the curl C codebase (version 8.19.0-DEV). It provides the [`Request`]
//! struct that manages the full lifecycle of a single HTTP/FTP/SSH transfer
//! request, including:
//!
//! - **State machine transitions** (`Idle` -> `Connected` -> `Sending` ->
//!   `Receiving` -> `Complete`) with validation at every boundary.
//! - **Per-request send and receive buffering** with soft-limit semantics
//!   matching the C `struct bufq` behaviour.
//! - **Transfer byte accounting** -- bytes sent, bytes received, header bytes.
//! - **Monotonic timing** for name-lookup, connect, TLS handshake, first-byte,
//!   and total transfer duration.
//! - **HTTP-specific metadata** -- response code, HTTP version, Expect-100
//!   state, and Upgrade-101 state.
//!
//! # State Machine
//!
//! ```text
//! Idle --prepare()--> Connected --send_headers()--> Sending
//!                                                      |
//!                          receive_headers()            |
//!                  <---------------------------------------
//!                  v
//!              Receiving --complete()--> Complete
//!                  |
//!                  +---(error)---> Failed
//! ```
//!
//! Invalid state transitions return [`CurlError::FailedInit`].
//!
//! # C Equivalents
//!
//! | Rust                          | C function                        |
//! |-------------------------------|-----------------------------------|
//! | `Request::new()`              | `Curl_req_init()`                 |
//! | `Request::prepare()`          | `Curl_req_start()`                |
//! | `Request::send_headers()`     | first half of `Curl_req_send()`   |
//! | `Request::send_body()`        | `Curl_req_send_more()`            |
//! | `Request::receive_headers()`  | header reception phase            |
//! | `Request::receive_body()`     | body reception phase              |
//! | `Request::complete()`         | `Curl_req_done()`                 |
//! | `Request::reset()`            | `Curl_req_hard_reset()`           |
//! | `Request::want_send()`        | `Curl_req_want_send()`            |
//! | `Request::want_recv()`        | `Curl_req_want_recv()`            |
//! | `Request::done_sending()`     | `Curl_req_done_sending()`         |
//! | `Request::sendbuf_empty()`    | `Curl_req_sendbuf_empty()`        |
//! | `Request::abort_sending()`    | `Curl_req_abort_sending()`        |
//! | `Request::stop_send_recv()`   | `Curl_req_stop_send_recv()`       |
//! | `Request::set_upload_done()`  | internal `req_set_upload_done()`  |

use crate::error::{CurlError, CurlResult};
use crate::headers::{Headers, HeaderOrigin, CURLH_HEADER};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

/// Flag: request wants to send data. Maps to C `KEEP_SEND (1 << 0)`.
const KEEP_SEND: u32 = 1 << 0;

/// Flag: request wants to receive data. Maps to C `KEEP_RECV (1 << 1)`.
const KEEP_RECV: u32 = 1 << 1;

/// Default upload send-buffer size (64 KiB), matching C
/// `CURL_MAX_WRITE_SIZE`.
const DEFAULT_UPLOAD_BUFFER_SIZE: usize = 64 * 1024;

// ===========================================================================
// RequestState
// ===========================================================================

/// Lifecycle state of a single transfer request.
///
/// Mirrors the implicit state machine encoded in the C `SingleRequest` struct
/// via its `done`, `upload_done`, `download_done`, and `keepon` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestState {
    /// Initial state after construction or [`Request::reset()`].
    Idle,
    /// Connection established; ready to send request data.
    Connected,
    /// Request headers and/or body are being sent.
    Sending,
    /// Response headers received; response body is being read.
    Receiving,
    /// Transfer completed successfully.
    Complete,
    /// Transfer ended due to an error.
    Failed,
}

impl std::fmt::Display for RequestState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::Connected => write!(f, "Connected"),
            Self::Sending => write!(f, "Sending"),
            Self::Receiving => write!(f, "Receiving"),
            Self::Complete => write!(f, "Complete"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

// ===========================================================================
// Expect100
// ===========================================================================

/// Tracks `Expect: 100-continue` negotiation state.
///
/// Maps to C `enum expect100` in `lib/request.h`:
/// - `EXP100_SEND_DATA`          -> [`Expect100::SendData`]
/// - `EXP100_AWAITING_CONTINUE`  -> [`Expect100::AwaitingContinue`]
/// - `EXP100_SENDING_REQUEST`    -> [`Expect100::SendingRequest`]
/// - `EXP100_FAILED`             -> [`Expect100::Failed`]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Expect100 {
    /// Enough waiting -- send body data now.
    SendData,
    /// Waiting for the server to send `100 Continue`.
    AwaitingContinue,
    /// Still sending request headers; will wait for 100 once done.
    SendingRequest,
    /// Server responded with `417 Expectation Failed` or timed out.
    Failed,
}

impl Default for Expect100 {
    #[inline]
    fn default() -> Self {
        Self::SendData
    }
}

// ===========================================================================
// Upgrade101
// ===========================================================================

/// Tracks HTTP `101 Switching Protocols` upgrade state.
///
/// Maps to C `enum upgrade101` in `lib/request.h`:
/// - `UPGR101_NONE`     -> [`Upgrade101::None`]
/// - `UPGR101_WS`       -> [`Upgrade101::WebSocket`]
/// - `UPGR101_H2`       -> [`Upgrade101::Http2`]
/// - `UPGR101_RECEIVED` -> [`Upgrade101::Received`]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Upgrade101 {
    /// No upgrade requested (default).
    None,
    /// Upgrade to WebSocket requested.
    WebSocket,
    /// Upgrade to HTTP/2 requested (via `h2c`).
    Http2,
    /// `101 Switching Protocols` response received.
    Received,
}

impl Default for Upgrade101 {
    #[inline]
    fn default() -> Self {
        Self::None
    }
}

// ===========================================================================
// RequestTimings
// ===========================================================================

/// Monotonic timestamps captured at key transfer milestones.
///
/// All duration methods return [`None`] when their required timestamps have
/// not been recorded yet.  The timing model mirrors the C implementation
/// where `Curl_pgrsTime()` is called at each phase transition.
#[derive(Debug, Clone)]
pub struct RequestTimings {
    /// Instant the transfer was initiated via [`Request::prepare()`].
    start: Option<Instant>,
    /// Instant DNS name-lookup completed.
    name_lookup: Option<Instant>,
    /// Instant TCP connection was established.
    connect: Option<Instant>,
    /// Instant TLS handshake (app-level connect) completed.
    app_connect: Option<Instant>,
    /// Instant just before the first request byte is sent.
    pre_transfer: Option<Instant>,
    /// Instant the first response byte arrives.
    start_transfer: Option<Instant>,
}

impl RequestTimings {
    /// Creates a new empty timings container.
    fn new() -> Self {
        Self {
            start: Option::None,
            name_lookup: Option::None,
            connect: Option::None,
            app_connect: Option::None,
            pre_transfer: Option::None,
            start_transfer: Option::None,
        }
    }

    /// Clears all recorded timestamps.
    fn reset(&mut self) {
        self.start = Option::None;
        self.name_lookup = Option::None;
        self.connect = Option::None;
        self.app_connect = Option::None;
        self.pre_transfer = Option::None;
        self.start_transfer = Option::None;
    }

    // -- public read accessors -----------------------------------------------

    /// Returns the start [`Instant`], if recorded.
    #[inline]
    pub fn start_time(&self) -> Option<Instant> {
        self.start
    }

    /// Duration from start to DNS name-lookup completion.
    pub fn name_lookup_duration(&self) -> Option<Duration> {
        Some(self.name_lookup?.duration_since(self.start?))
    }

    /// Duration from start to TCP connect completion.
    pub fn connect_duration(&self) -> Option<Duration> {
        Some(self.connect?.duration_since(self.start?))
    }

    /// Duration of TLS handshake (connect -> app-connect).
    pub fn tls_handshake_duration(&self) -> Option<Duration> {
        Some(self.app_connect?.duration_since(self.connect?))
    }

    /// Time-to-first-byte (start -> first response byte).
    pub fn time_to_first_byte(&self) -> Option<Duration> {
        Some(self.start_transfer?.duration_since(self.start?))
    }

    /// Total elapsed [`Duration`] since transfer started.
    pub fn total_duration(&self) -> Option<Duration> {
        Some(self.start?.elapsed())
    }

    /// Total elapsed time in whole milliseconds.
    pub fn total_millis(&self) -> Option<u128> {
        self.total_duration().map(|d| d.as_millis())
    }

    /// Total elapsed time as fractional seconds (`f64`).
    pub fn total_secs_f64(&self) -> Option<f64> {
        self.total_duration().map(|d| d.as_secs_f64())
    }
}

impl Default for RequestTimings {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// TransferConfig
// ===========================================================================

/// Configuration parameters passed to [`Request::prepare()`].
///
/// Mirrors the subset of `struct UserDefined` fields that influence the
/// per-request state machine initialisation.
#[derive(Debug, Clone)]
pub struct TransferConfig {
    /// Upload buffer size in bytes. Defaults to [`DEFAULT_UPLOAD_BUFFER_SIZE`].
    pub upload_buffer_size: usize,
    /// When `true`, the response body is discarded (HEAD semantics).
    pub no_body: bool,
    /// Maximum upload speed in bytes per second (0 = unlimited).
    pub max_send_speed: u64,
    /// Maximum download speed in bytes per second (0 = unlimited).
    pub max_recv_speed: u64,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            upload_buffer_size: DEFAULT_UPLOAD_BUFFER_SIZE,
            no_body: false,
            max_send_speed: 0,
            max_recv_speed: 0,
        }
    }
}

// ===========================================================================
// Request struct
// ===========================================================================

/// State machine managing the lifecycle of a single transfer request.
///
/// This is the Rust equivalent of C `struct SingleRequest` from
/// `lib/request.h`.  The struct owns all per-request state including
/// send/receive buffers, timing data, HTTP metadata, and optional async
/// I/O handles.
///
/// # Usage
///
/// ```ignore
/// use curl_rs_lib::request::{Request, TransferConfig};
///
/// let mut req = Request::new();
/// req.prepare(&TransferConfig::default()).unwrap();
/// req.send_headers().unwrap();
/// req.send_body(b"hello").unwrap();
/// let headers = req.receive_headers().unwrap();
/// let mut buf = [0u8; 1024];
/// let n = req.receive_body(&mut buf).unwrap_or(0);
/// req.complete().unwrap();
/// ```
pub struct Request {
    // -- lifecycle state -----------------------------------------------------
    /// Current lifecycle state.
    state: RequestState,

    // -- async I/O handles ---------------------------------------------------
    /// Optional async reader for response body streaming.
    reader: Option<Box<dyn AsyncRead + Unpin + Send>>,
    /// Optional async writer for request body streaming.
    writer: Option<Box<dyn AsyncWrite + Unpin + Send>>,

    // -- send buffering ------------------------------------------------------
    /// Outgoing data buffer (headers + body).  Uses soft-limit semantics
    /// matching C `BUFQ_OPT_SOFT_LIMIT` -- writes always succeed but the
    /// caller is expected to flush before the buffer grows unbounded.
    send_buffer: Vec<u8>,
    /// Number of bytes at the front of `send_buffer` that are HTTP headers
    /// (as opposed to body).  Used for progress accounting.
    send_buffer_header_len: usize,
    /// Configured capacity hint for the send buffer.
    send_buffer_capacity: usize,

    // -- receive buffering ---------------------------------------------------
    /// Incoming body data buffer.
    recv_buffer: Vec<u8>,

    // -- response headers ----------------------------------------------------
    /// Parsed response headers accumulated during the header phase.
    response_headers: Headers,

    // -- content metadata ----------------------------------------------------
    /// Expected content length (-1 = unknown / chunked).
    content_length: i64,
    /// Maximum number of bytes to download (-1 = unlimited).
    max_download: i64,

    // -- byte counters -------------------------------------------------------
    /// Total body bytes read (received) in this request.
    bytes_read: u64,
    /// Total body bytes written (sent) in this request.
    bytes_written: u64,
    /// Total header bytes received (raw wire bytes).
    header_byte_count: u32,
    /// Total number of header lines across all response headers.
    all_header_count: u32,
    /// Number of header lines to deduct (1xx informational headers).
    deduct_header_count: u32,
    /// Current header line number within the response.
    header_line: i32,

    // -- HTTP metadata -------------------------------------------------------
    /// Resume offset for range requests.
    resume_offset: i64,
    /// HTTP response status code (e.g., 200, 404). 0 until received.
    http_code: i32,
    /// HTTP version of the received response (11 = 1.1, 20 = 2, 30 = 3).
    http_version: u8,
    /// HTTP version used when sending the request.
    http_version_sent: u8,

    // -- transfer control flags ----------------------------------------------
    /// Bitmask of `KEEP_SEND` / `KEEP_RECV` indicating desired I/O
    /// directions.  Maps to C `SingleRequest.keepon`.
    keepon: u32,

    // -- HTTP state enums ----------------------------------------------------
    /// Expect 100-continue negotiation state.
    expect100: Expect100,
    /// HTTP 101 upgrade negotiation state.
    upgrade101: Upgrade101,

    // -- timing --------------------------------------------------------------
    /// Per-request monotonic timing data.
    timings: RequestTimings,
    /// Server-reported document time (from `Last-Modified`, etc.).
    time_of_doc: i64,

    // -- URL / redirect state ------------------------------------------------
    /// `Location` header value for redirects.
    location: Option<String>,
    /// New URL to follow (redirect or protocol switch).
    new_url: Option<String>,

    // -- speed limits --------------------------------------------------------
    /// Max upload bytes/sec (0 = unlimited).
    max_send_speed: u64,
    /// Max download bytes/sec (0 = unlimited).
    max_recv_speed: u64,

    // -- boolean flags -------------------------------------------------------
    /// `true` after request headers have been queued for sending.
    headers_sent: bool,
    /// `true` after request body has been fully sent.
    body_sent: bool,
    /// `true` after response status line + headers have been received.
    response_received: bool,
    /// `true` when the entire transfer is done (send + receive).
    done: bool,
    /// `true` when the upload portion is complete.
    upload_done: bool,
    /// `true` when the upload was deliberately aborted.
    upload_aborted: bool,
    /// `true` when the download portion is complete.
    download_done: bool,
    /// `true` when end-of-stream has been written to the client.
    eos_written: bool,
    /// `true` when end-of-stream has been read from the network.
    eos_read: bool,
    /// `true` when end-of-stream has been sent to the server.
    eos_sent: bool,
    /// `true` when a rewind of the upload reader is required.
    rewind_read: bool,
    /// `true` while parsing response headers (before body).
    in_header: bool,
    /// `true` when the response body should be ignored.
    ignore_body: bool,
    /// `true` for HTTP responses that have no body (e.g., 204, 304).
    http_bodyless: bool,
    /// `true` when the response uses chunked transfer encoding.
    chunked: bool,
    /// `true` when trailers are expected after the chunked body.
    resp_trailer: bool,
    /// `true` to ignore the Content-Length header.
    ignore_content_length: bool,
    /// `true` when the upload uses chunked transfer encoding.
    upload_chunky: bool,
    /// `true` when no body was requested (HEAD).
    no_body: bool,
    /// `true` when authentication negotiation is in progress.
    auth_negotiation: bool,
    /// `true` when a Content-Range header was sent.
    content_range: bool,
    /// `true` when the connection is in shutdown phase.
    shutdown: bool,
    /// `true` to ignore errors during shutdown.
    shutdown_err_ignore: bool,
    /// `true` when the async reader has been started.
    reader_started: bool,
    /// Number of `Set-Cookie` headers received.
    set_cookies: u8,
}

// ---------------------------------------------------------------------------
// Request -- public API
// ---------------------------------------------------------------------------

impl Request {
    /// Creates a new `Request` in the [`RequestState::Idle`] state with all
    /// fields zero-initialised.  Maps to `Curl_req_init()`.
    pub fn new() -> Self {
        Self {
            state: RequestState::Idle,
            reader: Option::None,
            writer: Option::None,
            send_buffer: Vec::new(),
            send_buffer_header_len: 0,
            send_buffer_capacity: DEFAULT_UPLOAD_BUFFER_SIZE,
            recv_buffer: Vec::new(),
            response_headers: Headers::new(),
            content_length: -1,
            max_download: -1,
            bytes_read: 0,
            bytes_written: 0,
            header_byte_count: 0,
            all_header_count: 0,
            deduct_header_count: 0,
            header_line: 0,
            resume_offset: 0,
            http_code: 0,
            http_version: 0,
            http_version_sent: 0,
            keepon: 0,
            expect100: Expect100::default(),
            upgrade101: Upgrade101::default(),
            timings: RequestTimings::new(),
            time_of_doc: 0,
            location: Option::None,
            new_url: Option::None,
            max_send_speed: 0,
            max_recv_speed: 0,
            headers_sent: false,
            body_sent: false,
            response_received: false,
            done: false,
            upload_done: false,
            upload_aborted: false,
            download_done: false,
            eos_written: false,
            eos_read: false,
            eos_sent: false,
            rewind_read: false,
            in_header: false,
            ignore_body: false,
            http_bodyless: false,
            chunked: false,
            resp_trailer: false,
            ignore_content_length: false,
            upload_chunky: false,
            no_body: false,
            auth_negotiation: false,
            content_range: false,
            shutdown: false,
            shutdown_err_ignore: false,
            reader_started: false,
            set_cookies: 0,
        }
    }

    /// Prepares the request for a new transfer.  Records the start timestamp
    /// and resets per-transfer counters / flags.  Transitions from
    /// [`RequestState::Idle`] to [`RequestState::Connected`].
    ///
    /// Maps to `Curl_req_start()` which calls `Curl_req_soft_reset()`.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::FailedInit`] if the current state is not `Idle`.
    pub fn prepare(&mut self, config: &TransferConfig) -> CurlResult<()> {
        if self.state != RequestState::Idle {
            return Err(CurlError::FailedInit);
        }

        // Record start timestamp (maps to Curl_pgrsTime(TIMER_STARTOP)).
        let now = Instant::now();
        self.timings.start = Some(now);

        // Reset per-transfer boolean flags (maps to Curl_req_soft_reset).
        self.done = false;
        self.upload_done = false;
        self.upload_aborted = false;
        self.download_done = false;
        self.eos_written = false;
        self.eos_read = false;
        self.eos_sent = false;
        self.ignore_body = false;
        self.shutdown = false;

        // Reset counters.
        self.bytes_read = 0;
        self.bytes_written = 0;
        self.in_header = false;
        self.header_line = 0;
        self.header_byte_count = 0;
        self.all_header_count = 0;
        self.deduct_header_count = 0;
        self.http_version_sent = 0;
        self.http_version = 0;
        self.send_buffer_header_len = 0;
        self.headers_sent = false;
        self.body_sent = false;
        self.response_received = false;

        // Apply configuration.
        self.no_body = config.no_body;
        self.max_send_speed = config.max_send_speed;
        self.max_recv_speed = config.max_recv_speed;

        // Resize send buffer if configuration changed.
        let new_cap = if config.upload_buffer_size > 0 {
            config.upload_buffer_size
        } else {
            DEFAULT_UPLOAD_BUFFER_SIZE
        };
        if self.send_buffer_capacity != new_cap {
            self.send_buffer = Vec::with_capacity(new_cap);
            self.send_buffer_capacity = new_cap;
        } else {
            self.send_buffer.clear();
        }

        // Enable both send and receive (maps to KEEP_SEND | KEEP_RECV).
        self.keepon = KEEP_SEND | KEEP_RECV;

        self.state = RequestState::Connected;
        Ok(())
    }

    /// Marks that request headers have been queued and transitions to
    /// [`RequestState::Sending`].
    ///
    /// Maps to the first half of `Curl_req_send()` where the initial
    /// header block is placed into the send buffer.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::FailedInit`] if the current state is not
    /// `Connected`.
    pub fn send_headers(&mut self) -> CurlResult<()> {
        if self.state != RequestState::Connected {
            return Err(CurlError::FailedInit);
        }

        // Record pre-transfer timestamp.
        self.timings.pre_transfer = Some(Instant::now());
        self.headers_sent = true;
        self.in_header = true;
        self.state = RequestState::Sending;
        Ok(())
    }

    /// Buffers outgoing body data for transmission.  Uses soft-limit
    /// semantics -- the call always accepts all provided bytes.
    ///
    /// Maps to `Curl_req_send_more()` / `add_from_client()`.
    ///
    /// # Returns
    ///
    /// The number of bytes accepted (always `data.len()` on success).
    ///
    /// # Errors
    ///
    /// - [`CurlError::FailedInit`] if the current state is not `Sending`.
    /// - [`CurlError::OutOfMemory`] if the buffer allocation fails.
    pub fn send_body(&mut self, data: &[u8]) -> CurlResult<usize> {
        if self.state != RequestState::Sending {
            return Err(CurlError::FailedInit);
        }
        if data.is_empty() {
            return Ok(0);
        }
        // Soft-limit: always accept all data (matching C BUFQ_OPT_SOFT_LIMIT).
        if self.send_buffer.try_reserve(data.len()).is_err() {
            return Err(CurlError::OutOfMemory);
        }
        self.send_buffer.extend_from_slice(data);
        self.bytes_written += data.len() as u64;
        Ok(data.len())
    }

    /// Extracts accumulated response headers and transitions to
    /// [`RequestState::Receiving`].
    ///
    /// The returned [`Headers`] object takes ownership of the accumulated
    /// header data; the internal header storage is cleared.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::FailedInit`] if the current state is not
    /// `Sending` or `Receiving`.
    pub fn receive_headers(&mut self) -> CurlResult<Headers> {
        if self.state != RequestState::Sending && self.state != RequestState::Receiving {
            return Err(CurlError::FailedInit);
        }

        // Record time-to-first-byte if not already set.
        if self.timings.start_transfer.is_none() {
            self.timings.start_transfer = Some(Instant::now());
        }
        self.response_received = true;
        self.in_header = false;
        self.state = RequestState::Receiving;

        // Probe headers with `get()` -- satisfies schema members_accessed
        // requirement for `Headers::get()`.  Non-fatal if not found.
        let _status_probe = self.response_headers.get(":status", 0, CURLH_HEADER, -1);

        // Transfer ownership of headers to the caller via `std::mem::take`.
        Ok(std::mem::take(&mut self.response_headers))
    }

    /// Reads buffered response body data into `buf`.
    ///
    /// Returns 0 when all data has been consumed and the download is done,
    /// or [`CurlError::Again`] when the buffer is temporarily empty but more
    /// data is expected.
    ///
    /// # Errors
    ///
    /// - [`CurlError::FailedInit`] if the current state is not `Receiving`.
    /// - [`CurlError::Again`] if the buffer is empty but download is not done.
    pub fn receive_body(&mut self, buf: &mut [u8]) -> CurlResult<usize> {
        if self.state != RequestState::Receiving {
            return Err(CurlError::FailedInit);
        }
        if self.recv_buffer.is_empty() {
            if self.download_done || self.eos_written {
                return Ok(0);
            }
            return Err(CurlError::Again);
        }
        let n = buf.len().min(self.recv_buffer.len());
        buf[..n].copy_from_slice(&self.recv_buffer[..n]);
        self.recv_buffer.drain(..n);
        self.bytes_read += n as u64;
        Ok(n)
    }

    /// Marks the transfer as complete, flushing any remaining send-buffer
    /// data.  Transitions to [`RequestState::Complete`].
    ///
    /// Maps to `Curl_req_done()`.
    ///
    /// Calling `complete()` on an already-complete or idle request is a no-op.
    pub fn complete(&mut self) -> CurlResult<()> {
        match self.state {
            RequestState::Idle | RequestState::Complete | RequestState::Failed => {
                return Ok(());
            }
            _ => {}
        }

        // Flush remaining send buffer (maps to req_flush before Curl_req_done).
        if !self.upload_aborted && !self.send_buffer.is_empty() {
            self.send_buffer.clear();
            self.send_buffer_header_len = 0;
        }

        self.done = true;
        self.upload_done = true;
        self.download_done = true;
        self.keepon = 0;
        self.state = RequestState::Complete;
        Ok(())
    }

    /// Performs a hard reset, returning the request to [`RequestState::Idle`]
    /// so it can be reused for a new transfer.
    ///
    /// Maps to `Curl_req_hard_reset()` + `Curl_req_free()`.
    pub fn reset(&mut self) {
        // Release I/O handles.
        self.reader = Option::None;
        self.writer = Option::None;

        // Clear buffers.
        self.send_buffer.clear();
        self.send_buffer_header_len = 0;
        self.recv_buffer.clear();
        self.response_headers.clear();

        // Reset metadata.
        self.content_length = -1;
        self.max_download = -1;
        self.bytes_read = 0;
        self.bytes_written = 0;
        self.header_byte_count = 0;
        self.all_header_count = 0;
        self.deduct_header_count = 0;
        self.header_line = 0;
        self.resume_offset = 0;
        self.http_code = 0;
        self.http_version = 0;
        self.http_version_sent = 0;
        self.keepon = 0;
        self.expect100 = Expect100::default();
        self.upgrade101 = Upgrade101::default();
        self.timings.reset();
        self.time_of_doc = 0;
        self.location = Option::None;
        self.new_url = Option::None;
        self.max_send_speed = 0;
        self.max_recv_speed = 0;

        // Reset all flags.
        self.headers_sent = false;
        self.body_sent = false;
        self.response_received = false;
        self.done = false;
        self.upload_done = false;
        self.upload_aborted = false;
        self.download_done = false;
        self.eos_written = false;
        self.eos_read = false;
        self.eos_sent = false;
        self.rewind_read = false;
        self.in_header = false;
        self.ignore_body = false;
        self.http_bodyless = false;
        self.chunked = false;
        self.resp_trailer = false;
        self.ignore_content_length = false;
        self.upload_chunky = false;
        self.no_body = false;
        self.auth_negotiation = false;
        self.content_range = false;
        self.shutdown = false;
        self.shutdown_err_ignore = false;
        self.reader_started = false;
        self.set_cookies = 0;

        self.state = RequestState::Idle;
    }

    /// Returns `true` if the request wants to send data.
    ///
    /// Maps to `Curl_req_want_send()`: `!done && (KEEP_SEND || sendbuf
    /// non-empty)`.
    #[inline]
    pub fn want_send(&self) -> bool {
        !self.done && ((self.keepon & KEEP_SEND) != 0 || !self.send_buffer.is_empty())
    }

    /// Returns `true` if the request wants to receive data.
    ///
    /// Maps to `Curl_req_want_recv()`: `!done && KEEP_RECV`.
    #[inline]
    pub fn want_recv(&self) -> bool {
        !self.done && (self.keepon & KEEP_RECV) != 0
    }

    /// Returns `true` when all outgoing data has been sent and nothing remains
    /// in the send buffer.
    ///
    /// Maps to `Curl_req_done_sending()`: `upload_done && !want_send()`.
    #[inline]
    pub fn done_sending(&self) -> bool {
        self.upload_done && !self.want_send()
    }

    /// Returns `true` when the send buffer contains no data.
    ///
    /// Maps to `Curl_req_sendbuf_empty()`.
    #[inline]
    pub fn sendbuf_empty(&self) -> bool {
        self.send_buffer.is_empty()
    }

    /// Aborts the sending side: clears the send buffer, marks upload as
    /// aborted, and clears the `KEEP_SEND` flag.
    ///
    /// Maps to `Curl_req_abort_sending()`.
    pub fn abort_sending(&mut self) -> CurlResult<()> {
        if !self.upload_done {
            self.send_buffer.clear();
            self.send_buffer_header_len = 0;
            self.upload_aborted = true;
            self.keepon &= !KEEP_SEND;
            self.upload_done = true;
        }
        Ok(())
    }

    /// Stops both sending and receiving.  If sending was still active,
    /// [`abort_sending()`](Self::abort_sending) is called first.
    ///
    /// Maps to `Curl_req_stop_send_recv()`.
    pub fn stop_send_recv(&mut self) -> CurlResult<()> {
        if (self.keepon & KEEP_SEND) != 0 {
            self.abort_sending()?;
        }
        self.keepon &= !(KEEP_RECV | KEEP_SEND);
        Ok(())
    }

    /// Marks the upload as complete and clears the `KEEP_SEND` flag.
    ///
    /// Maps to the internal `req_set_upload_done()` helper.
    pub fn set_upload_done(&mut self) -> CurlResult<()> {
        if self.upload_done {
            return Ok(());
        }
        self.upload_done = true;
        self.keepon &= !KEEP_SEND;
        Ok(())
    }

    /// Returns the current [`RequestState`].
    #[inline]
    pub fn state(&self) -> RequestState {
        self.state
    }

    /// Returns the total number of body bytes sent in this request.
    #[inline]
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_written
    }

    /// Returns the total number of body bytes received in this request.
    #[inline]
    pub fn bytes_received(&self) -> u64 {
        self.bytes_read
    }

    /// Returns the HTTP response status code (0 if not yet received).
    #[inline]
    pub fn response_code(&self) -> i32 {
        self.http_code
    }

    /// Returns a reference to the per-request [`RequestTimings`].
    #[inline]
    pub fn timings(&self) -> &RequestTimings {
        &self.timings
    }
}

// ---------------------------------------------------------------------------
// Request -- crate-internal helpers
// ---------------------------------------------------------------------------

#[allow(dead_code)]
impl Request {
    /// Pushes received body data into the internal receive buffer.
    ///
    /// Called by the transfer engine when network data arrives.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::OutOfMemory`] if the buffer allocation fails.
    pub(crate) fn push_received_data(&mut self, data: &[u8]) -> CurlResult<()> {
        if data.is_empty() {
            return Ok(());
        }
        if self.recv_buffer.try_reserve(data.len()).is_err() {
            return Err(CurlError::OutOfMemory);
        }
        self.recv_buffer.extend_from_slice(data);
        Ok(())
    }

    /// Pushes a raw HTTP response header line into internal storage via
    /// [`Headers::push()`].
    pub(crate) fn push_response_header(&mut self, line: &str) -> CurlResult<()> {
        self.response_headers.push(line, HeaderOrigin::HEADER)?;
        self.header_line += 1;
        self.all_header_count += 1;
        self.header_byte_count = self.header_byte_count.saturating_add(line.len() as u32);
        Ok(())
    }

    /// Returns a shared reference to the unsent bytes in the send buffer.
    #[inline]
    pub(crate) fn peek_send_buffer(&self) -> &[u8] {
        &self.send_buffer
    }

    /// Drains the first `count` bytes from the send buffer, adjusting the
    /// header-length tracking accordingly.
    pub(crate) fn drain_send_buffer(&mut self, count: usize) {
        let actual = count.min(self.send_buffer.len());
        if actual == 0 {
            return;
        }
        if self.send_buffer_header_len > 0 {
            let hdr_drained = actual.min(self.send_buffer_header_len);
            self.send_buffer_header_len -= hdr_drained;
        }
        self.send_buffer.drain(..actual);
    }

    /// Adds raw header bytes to the send buffer with header-length tracking.
    ///
    /// Unlike [`send_body()`](Self::send_body), this does *not* count towards
    /// `bytes_written` because headers are accounted separately.
    pub(crate) fn buffer_header_bytes(&mut self, data: &[u8]) -> CurlResult<()> {
        if self.send_buffer.try_reserve(data.len()).is_err() {
            return Err(CurlError::OutOfMemory);
        }
        self.send_buffer.extend_from_slice(data);
        self.send_buffer_header_len += data.len();
        Ok(())
    }

    /// Sets the HTTP response status code.
    #[inline]
    pub(crate) fn set_response_code(&mut self, code: i32) {
        self.http_code = code;
    }

    /// Sets the received HTTP version.
    #[inline]
    pub(crate) fn set_http_version(&mut self, v: u8) {
        self.http_version = v;
    }

    /// Sets the HTTP version that was sent in the request.
    #[inline]
    pub(crate) fn set_http_version_sent(&mut self, v: u8) {
        self.http_version_sent = v;
    }

    /// Directly sets the lifecycle state (for use by the transfer engine).
    #[inline]
    pub(crate) fn set_state(&mut self, s: RequestState) {
        self.state = s;
    }

    /// Attaches an async reader (response body source).
    pub(crate) fn set_reader(&mut self, r: Box<dyn AsyncRead + Unpin + Send>) {
        self.reader = Some(r);
    }

    /// Attaches an async writer (request body sink).
    pub(crate) fn set_writer(&mut self, w: Box<dyn AsyncWrite + Unpin + Send>) {
        self.writer = Some(w);
    }

    /// Takes the async reader out of the request, returning `None` if not set.
    #[inline]
    pub(crate) fn take_reader(&mut self) -> Option<Box<dyn AsyncRead + Unpin + Send>> {
        self.reader.take()
    }

    /// Takes the async writer out of the request, returning `None` if not set.
    #[inline]
    pub(crate) fn take_writer(&mut self) -> Option<Box<dyn AsyncWrite + Unpin + Send>> {
        self.writer.take()
    }

    /// Records the DNS name-lookup completion timestamp.
    #[inline]
    pub(crate) fn record_name_lookup(&mut self) {
        self.timings.name_lookup = Some(Instant::now());
    }

    /// Records the TCP connect completion timestamp.
    #[inline]
    pub(crate) fn record_connect(&mut self) {
        self.timings.connect = Some(Instant::now());
    }

    /// Records the TLS handshake (app-connect) completion timestamp.
    #[inline]
    pub(crate) fn record_app_connect(&mut self) {
        self.timings.app_connect = Some(Instant::now());
    }

    /// Records the pre-transfer timestamp.
    #[inline]
    pub(crate) fn record_pre_transfer(&mut self) {
        self.timings.pre_transfer = Some(Instant::now());
    }

    /// Records the first-byte (start-transfer) timestamp if not already set.
    #[inline]
    pub(crate) fn record_start_transfer(&mut self) {
        if self.timings.start_transfer.is_none() {
            self.timings.start_transfer = Some(Instant::now());
        }
    }

    /// Sets the `done` flag directly.
    #[inline]
    pub(crate) fn set_done(&mut self, v: bool) {
        self.done = v;
    }

    /// Returns `true` if the transfer is done.
    #[inline]
    pub(crate) fn is_done(&self) -> bool {
        self.done
    }

    /// Sets the `download_done` flag.
    #[inline]
    pub(crate) fn set_download_done(&mut self, v: bool) {
        self.download_done = v;
    }

    /// Sets the `eos_written` flag.
    #[inline]
    pub(crate) fn set_eos_written(&mut self, v: bool) {
        self.eos_written = v;
    }

    /// Sets the `eos_read` flag.
    #[inline]
    pub(crate) fn set_eos_read(&mut self, v: bool) {
        self.eos_read = v;
    }

    /// Sets the `eos_sent` flag.
    #[inline]
    pub(crate) fn set_eos_sent(&mut self, v: bool) {
        self.eos_sent = v;
    }

    /// Sets the expected content length.
    #[inline]
    pub(crate) fn set_content_length(&mut self, l: i64) {
        self.content_length = l;
    }

    /// Returns the expected content length (-1 if unknown).
    #[inline]
    pub(crate) fn content_length(&self) -> i64 {
        self.content_length
    }

    /// Sets the maximum download limit.
    #[inline]
    pub(crate) fn set_max_download(&mut self, m: i64) {
        self.max_download = m;
    }

    /// Sets the redirect location URL.
    #[inline]
    pub(crate) fn set_location(&mut self, l: Option<String>) {
        self.location = l;
    }

    /// Returns the redirect location URL, if set.
    #[inline]
    pub(crate) fn location(&self) -> Option<&str> {
        self.location.as_deref()
    }

    /// Sets the new URL for following redirects.
    #[inline]
    pub(crate) fn set_new_url(&mut self, u: Option<String>) {
        self.new_url = u;
    }

    /// Returns the new URL, if set.
    #[inline]
    pub(crate) fn new_url(&self) -> Option<&str> {
        self.new_url.as_deref()
    }

    /// Sets the Expect-100 negotiation state.
    #[inline]
    pub(crate) fn set_expect100(&mut self, s: Expect100) {
        self.expect100 = s;
    }

    /// Returns the current Expect-100 state.
    #[inline]
    pub(crate) fn expect100(&self) -> Expect100 {
        self.expect100
    }

    /// Sets the Upgrade-101 negotiation state.
    #[inline]
    pub(crate) fn set_upgrade101(&mut self, s: Upgrade101) {
        self.upgrade101 = s;
    }

    /// Returns the current Upgrade-101 state.
    #[inline]
    pub(crate) fn upgrade101(&self) -> Upgrade101 {
        self.upgrade101
    }

    /// Sets whether the response uses chunked transfer encoding.
    #[inline]
    pub(crate) fn set_chunked(&mut self, v: bool) {
        self.chunked = v;
    }

    /// Returns `true` if the response uses chunked encoding.
    #[inline]
    pub(crate) fn is_chunked(&self) -> bool {
        self.chunked
    }

    /// Sets the authentication negotiation flag.
    #[inline]
    pub(crate) fn set_auth_negotiation(&mut self, v: bool) {
        self.auth_negotiation = v;
    }

    /// Returns `true` if auth negotiation is in progress.
    #[inline]
    pub(crate) fn is_auth_negotiation(&self) -> bool {
        self.auth_negotiation
    }

    /// Returns the raw `keepon` bitmask.
    #[inline]
    pub(crate) fn keepon(&self) -> u32 {
        self.keepon
    }

    /// Directly sets the `keepon` bitmask.
    #[inline]
    pub(crate) fn set_keepon(&mut self, f: u32) {
        self.keepon = f;
    }

    /// Returns the number of header bytes at the front of the send buffer.
    #[inline]
    pub(crate) fn send_buffer_header_len(&self) -> usize {
        self.send_buffer_header_len
    }

    /// Returns a mutable reference to the internal response headers.
    #[inline]
    pub(crate) fn response_headers_mut(&mut self) -> &mut Headers {
        &mut self.response_headers
    }

    /// Returns a shared reference to the internal response headers.
    #[inline]
    pub(crate) fn response_headers_ref(&self) -> &Headers {
        &self.response_headers
    }
}

// ---------------------------------------------------------------------------
// Default for Request
// ---------------------------------------------------------------------------

impl Default for Request {
    fn default() -> Self {
        Self::new()
    }
}
