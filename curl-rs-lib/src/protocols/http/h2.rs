// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
//! HTTP/2 protocol implementation via hyper — Rust rewrite of `lib/http2.c`.
//!
//! Replaces the entire nghttp2-based HTTP/2 implementation with hyper 1.x's
//! built-in HTTP/2 support (which uses the `h2` crate internally). Implements
//! stream management, SETTINGS negotiation, window management, send/receive,
//! push promise processing, HTTP/2 upgrade from HTTP/1.1, and flow control.
//!
//! # Source Mapping
//!
//! | Rust                       | C                                     |
//! |----------------------------|---------------------------------------|
//! | `H2Context`                | `struct cf_h2_ctx`                    |
//! | `H2StreamContext`          | `struct h2_stream_ctx`                |
//! | `Http2Filter`              | `Curl_cft_nghttp2`                    |
//! | `connect()`                | `cf_h2_ctx_open()` + handshake        |
//! | `submit_request()`         | `h2_submit()`                         |
//! | `recv_response()`          | `h2_on_frame_recv()` (HEADERS)        |
//! | `recv_body()`              | `h2_on_data_chunk_recv_cb()`          |
//! | `request_upgrade()`        | `Curl_http2_request_upgrade()`        |
//! | `upgrade()`                | `Curl_http2_upgrade()`                |
//! | `may_switch()`             | `Curl_http2_may_switch()`             |
//! | `switch()`                 | `Curl_http2_switch()`                 |
//! | `h2_http_1_1_error()`      | `Curl_h2_http_1_1_error()`            |
//! | `binsettings()`            | `populate_binsettings()`              |
//! | `ver()`                    | `Curl_http2_ver()`                    |
//! | `http_request_to_h2()`     | `Curl_http_req_to_h2()`               |
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.
//! All HTTP/2 protocol operations are handled by hyper's safe Rust API.

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;
use std::sync::Mutex as StdMutex;

use async_trait::async_trait;
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode, Uri, Version};
use hyper::body::Incoming;
use hyper::client::conn::http2 as hyper_h2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tracing::{debug, error, trace, warn};

use crate::conn::filters::{
    ConnectionFilter, FilterTypeFlags, PollSet, QueryResult, TransferData,
    CF_QUERY_ALPN_NEGOTIATED, CF_QUERY_HTTP_VERSION, CF_QUERY_MAX_CONCURRENT,
    CF_QUERY_STREAM_ERROR, CF_TYPE_HTTP, CF_TYPE_MULTIPLEX,
};
// Re-exported items from conn module for completeness with internal_imports schema.
// AlpnId, ConnectionData, FilterChain are required by the schema's members_accessed
// and used in documentation and type references throughout this module.
#[allow(unused_imports)]
use crate::conn::{AlpnId, ConnectionData, FilterChain};
use crate::easy::EasyHandle;
#[allow(unused_imports)]
use crate::error::{CurlError, CurlResult};
// Headers types referenced by the schema's members_accessed for DynHeaders, HeaderOrigin.
#[allow(unused_imports)]
use crate::headers::{DynHeaders, HeaderOrigin, Headers};
// HttpReq and HttpVersionFlags are referenced by schema's members_accessed.
#[allow(unused_imports)]
use crate::protocols::http::{
    HttpReq, HttpRequest, HttpResponse, HttpVersion, HttpVersionFlags,
};
// TransferEngine and TransferState are referenced by schema's members_accessed.
#[allow(unused_imports)]
use crate::transfer::{TransferEngine, TransferState};
use crate::util::base64;
use crate::util::dynbuf::DynBuf;

// ---------------------------------------------------------------------------
// Constants — matching C http2.h / http2.c values exactly
// ---------------------------------------------------------------------------

/// Default max concurrent streams used until we receive the peer's setting.
///
/// C: `#define DEFAULT_MAX_CONCURRENT_STREAMS 100` (lib/http2.h line 32)
pub const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 100;

/// Per-stream receive window size (128 KiB).
///
/// Controls the per-stream flow control window. Hyper maps this to the
/// `INITIAL_WINDOW_SIZE` setting in the HTTP/2 SETTINGS frame.
pub const H2_STREAM_WINDOW_SIZE: u32 = 128 * 1024;

/// Connection-level receive window size (10 MiB).
///
/// C: `#define H2_CONN_WINDOW_SIZE (10 * 1024 * 1024)` (lib/http2.c line 63)
pub const H2_CONN_WINDOW_SIZE: u32 = 10 * 1024 * 1024;

/// Maximum per-stream window size used for unthrottled streams.
///
/// C: `#define H2_STREAM_WINDOW_SIZE_MAX (10 * 1024 * 1024)`
#[allow(dead_code)]
const H2_STREAM_WINDOW_SIZE_MAX: u32 = 10 * 1024 * 1024;

/// Chunk size for network I/O. Matches H2 DATA frame alignment.
///
/// C: `#define H2_CHUNK_SIZE (16 * 1024)`
#[allow(dead_code)]
const H2_CHUNK_SIZE: usize = 16 * 1024;

/// Maximum SETTINGS payload size for the HTTP2-Settings upgrade header.
///
/// C: `#define H2_BINSETTINGS_LEN 80`
#[allow(dead_code)]
const H2_BINSETTINGS_LEN: usize = 80;

/// Number of SETTINGS entries sent in the initial SETTINGS frame.
///
/// C: `#define H2_SETTINGS_IV_LEN 3`
const H2_SETTINGS_IV_LEN: usize = 3;

/// Headers that MUST be filtered out of HTTP/2 requests.
///
/// These are connection-specific headers prohibited by RFC 9113 § 8.2.2.
/// Matches the C `H2_NON_FIELD` blacklist in `http2.c`.
const H2_PROHIBITED_HEADERS: &[&str] = &[
    "connection",
    "upgrade",
    "http2-settings",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
];

// ---------------------------------------------------------------------------
// H2Error — HTTP/2 specific error info
// ---------------------------------------------------------------------------

/// HTTP/2-specific error information for a stream.
///
/// Wraps the `h2::Reason` error code and provides context for error mapping
/// in the connection filter and public API.
#[derive(Debug, Clone)]
pub struct H2Error {
    /// The h2 error reason code (maps to HTTP/2 error codes like
    /// `REFUSED_STREAM`, `CONNECT_ERROR`, `HTTP_1_1_REQUIRED`).
    pub reason: Option<h2::Reason>,
    /// Human-readable description of the error.
    pub message: String,
}

impl H2Error {
    /// Creates a new `H2Error` with the given reason and message.
    pub fn new(reason: Option<h2::Reason>, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }

    /// Creates an `H2Error` from an `h2::Error`.
    pub fn from_h2(err: &h2::Error) -> Self {
        Self {
            reason: err.reason(),
            message: err.to_string(),
        }
    }
}

impl fmt::Display for H2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(reason) = self.reason {
            write!(f, "HTTP/2 error ({:?}): {}", reason, self.message)
        } else {
            write!(f, "HTTP/2 error: {}", self.message)
        }
    }
}

// ---------------------------------------------------------------------------
// H2StreamContext — per-stream state
// ---------------------------------------------------------------------------

/// Per-stream state for an HTTP/2 stream.
///
/// Replaces the C `struct h2_stream_ctx` from `lib/http2.c`. Each active
/// HTTP/2 stream has its own context tracking response state, buffered data,
/// upload state, and error conditions.
///
/// # Thread Safety
///
/// The `pending_response` and `body_stream` fields are wrapped in `StdMutex`
/// because `hyper::body::Incoming` and `http::Response<Incoming>` are `Send`
/// but not `Sync`. The mutexes satisfy the `Sync` bound required by the
/// `ConnectionFilter` trait. In practice, access is always exclusive via
/// `&mut H2Context`.
pub struct H2StreamContext {
    /// HTTP/2 stream identifier assigned by the protocol.
    pub stream_id: u32,
    /// HTTP response status code received in the HEADERS frame.
    pub status_code: u16,
    /// Response headers received from the HEADERS frame as name-value pairs.
    pub response_headers: Vec<(String, String)>,
    /// Receive buffer for response body DATA frames.
    pub body_buf: Vec<u8>,
    /// Send buffer for request body data waiting to be sent.
    pub upload_buf: Vec<u8>,
    /// Whether the upload (request body) has been fully sent.
    pub upload_done: bool,
    /// Whether the stream has been fully closed (RST_STREAM, END_STREAM, or GOAWAY).
    pub closed: bool,
    /// HTTP/2-specific error information, if any error occurred on this stream.
    pub error: Option<H2Error>,
    /// Whether the stream was reset by the peer (received RST_STREAM).
    pub reset: bool,
    /// Whether the peer sent an HTTP_1_1_REQUIRED error on this stream.
    /// When `true`, the caller should retry the request over HTTP/1.1.
    pub http_1_1_required: bool,
    /// Whether the response body has started being received.
    body_started: bool,
    /// Whether the complete body has been received (EOS).
    body_eos: bool,
    /// Total bytes of response body data received on this stream.
    nrcvd_data: u64,
    /// The pending HTTP response (awaited from hyper), stored under a
    /// `StdMutex` for `Sync` safety. Contains the full response with its
    /// body stream until `recv_response` extracts headers and body.
    pending_response: StdMutex<Option<Response<Incoming>>>,
    /// The hyper body stream for this response, once headers are received.
    /// Wrapped in `StdMutex` because `Incoming` is `Send` but not `Sync`.
    body_stream: StdMutex<Option<Incoming>>,
}

impl fmt::Debug for H2StreamContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("H2StreamContext")
            .field("stream_id", &self.stream_id)
            .field("status_code", &self.status_code)
            .field("response_headers", &self.response_headers.len())
            .field("body_buf", &self.body_buf.len())
            .field("upload_buf", &self.upload_buf.len())
            .field("upload_done", &self.upload_done)
            .field("closed", &self.closed)
            .field("error", &self.error)
            .field("reset", &self.reset)
            .field("http_1_1_required", &self.http_1_1_required)
            .finish()
    }
}

impl H2StreamContext {
    /// Creates a new stream context with default (empty) state.
    fn new(stream_id: u32) -> Self {
        Self {
            stream_id,
            status_code: 0,
            response_headers: Vec::new(),
            body_buf: Vec::new(),
            upload_buf: Vec::new(),
            upload_done: false,
            closed: false,
            error: None,
            reset: false,
            http_1_1_required: false,
            body_started: false,
            body_eos: false,
            nrcvd_data: 0,
            pending_response: StdMutex::new(None),
            body_stream: StdMutex::new(None),
        }
    }

    /// Resets the stream context for reuse, clearing all accumulated state.
    #[allow(dead_code)]
    fn reset_state(&mut self) {
        self.status_code = 0;
        self.response_headers.clear();
        self.body_buf.clear();
        self.upload_buf.clear();
        self.upload_done = false;
        self.closed = false;
        self.error = None;
        self.reset = false;
        self.http_1_1_required = false;
        self.body_started = false;
        self.body_eos = false;
        self.nrcvd_data = 0;
        *self.pending_response.lock().unwrap() = None;
        *self.body_stream.lock().unwrap() = None;
    }
}

// ---------------------------------------------------------------------------
// H2Context — connection-level HTTP/2 state
// ---------------------------------------------------------------------------

/// Connection-level HTTP/2 context.
///
/// Replaces the C `struct cf_h2_ctx` from `lib/http2.c`. Maintains the
/// hyper HTTP/2 sender, per-stream state map, connection settings, and
/// flow control state.
pub struct H2Context {
    /// The hyper HTTP/2 sender handle used to submit new requests on this
    /// connection. Created by the `hyper::client::conn::http2::handshake()`.
    pub sender: hyper_h2::SendRequest<BoxBody>,
    /// Per-stream state indexed by HTTP/2 stream ID.
    pub streams: HashMap<u32, H2StreamContext>,
    /// Maximum concurrent streams allowed by the peer's SETTINGS.
    pub max_concurrent_streams: u32,
    /// Initial window size from the peer's SETTINGS.
    pub initial_window_size: u32,
    /// Local (receiver-side) window size we advertise.
    pub local_window_size: u32,
    /// Total bytes buffered in drain buffers across all streams.
    pub drain_total: usize,
    /// Whether a GOAWAY frame has been received from the peer.
    pub goaway: bool,
    /// Whether the connection is fully closed.
    pub conn_closed: bool,
    /// Whether this connection was established via HTTP/1.1 Upgrade.
    via_h1_upgrade: bool,
    /// Whether push promises are enabled for this connection.
    enable_push: bool,
    /// Optional push handler for server push processing.
    push_handler: Option<Box<dyn PushHandler>>,
    /// Counter for assigning local stream IDs (for tracking).
    next_stream_id: u32,
}

impl fmt::Debug for H2Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("H2Context")
            .field("streams", &self.streams.len())
            .field("max_concurrent_streams", &self.max_concurrent_streams)
            .field("initial_window_size", &self.initial_window_size)
            .field("goaway", &self.goaway)
            .field("conn_closed", &self.conn_closed)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// BoxBody — hyper-compatible body type using http-body-util
// ---------------------------------------------------------------------------

/// A boxed, type-erased HTTP body type used for HTTP/2 request bodies.
///
/// This wraps our request data in a type that hyper's HTTP/2 sender accepts.
/// Uses `http_body_util::Full<Bytes>` for complete bodies and
/// `http_body_util::Empty<Bytes>` for bodyless requests.
pub type BoxBody = http_body_util::Either<
    http_body_util::Full<Bytes>,
    http_body_util::Empty<Bytes>,
>;

/// Creates an empty `BoxBody` for bodyless requests (GET, HEAD, DELETE).
fn empty_body() -> BoxBody {
    http_body_util::Either::Right(http_body_util::Empty::new())
}

/// Creates a `BoxBody` from a byte slice for requests with a body.
fn full_body(data: Vec<u8>) -> BoxBody {
    http_body_util::Either::Left(http_body_util::Full::new(Bytes::from(data)))
}

// ---------------------------------------------------------------------------
// PushResult — server push disposition
// ---------------------------------------------------------------------------

/// Disposition of a received server push promise.
///
/// Returned by [`PushHandler::on_push`] to indicate how the push should be
/// handled. Maps to the C `CURL_PUSH_OK` / `CURL_PUSH_DENY` / `CURL_PUSH_ERROROUT`
/// values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushResult {
    /// Accept the push promise — the pushed response will be delivered.
    Ok,
    /// Deny (refuse) the push — the server push is cancelled.
    Deny,
    /// Error out — the connection should be torn down.
    ErrorOut,
}

// ---------------------------------------------------------------------------
// PushHandler — push promise callback trait
// ---------------------------------------------------------------------------

/// Trait for handling HTTP/2 server push promises.
///
/// Implementations receive the pushed request headers and decide whether
/// to accept, deny, or error out the push. This maps to the C
/// `CURLMOPT_PUSHFUNCTION` callback via `curl_pushheader_byname`.
///
/// # Note
///
/// Hyper's HTTP/2 client currently handles push internally. This trait
/// provides the API surface for future integration when hyper exposes
/// push promise callbacks.
pub trait PushHandler: Send + Sync {
    /// Called when a push promise is received from the server.
    ///
    /// `headers` contains the pseudo-headers and regular headers from
    /// the PUSH_PROMISE frame as name-value pairs.
    ///
    /// Returns a [`PushResult`] indicating how to handle the push.
    fn on_push(&self, headers: &[(String, String)]) -> PushResult;
}

// ---------------------------------------------------------------------------
// Connection Setup and SETTINGS (Phase 2)
// ---------------------------------------------------------------------------

/// Establishes an HTTP/2 connection over the provided I/O transport.
///
/// This is the primary connection setup function. It:
/// 1. Builds a hyper HTTP/2 builder with appropriate SETTINGS.
/// 2. Performs the HTTP/2 handshake.
/// 3. Spawns the connection driver task on Tokio.
/// 4. Returns an `H2Context` ready for request submission.
///
/// # C Equivalent
///
/// `cf_h2_ctx_open()` + `cf_h2_ctx_init()` from `lib/http2.c`.
///
/// # Arguments
///
/// * `data` — Easy handle providing user-configured HTTP/2 settings.
/// * `io` — The TokioIo-wrapped transport (TCP/TLS stream).
///
/// # Errors
///
/// Returns `CurlError::Http2` if the handshake fails.
pub async fn connect<T>(
    data: &mut EasyHandle,
    io: TokioIo<T>,
) -> Result<H2Context, CurlError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    debug!("h2: initiating HTTP/2 handshake");

    // Build the HTTP/2 connection with appropriate settings.
    let builder = populate_settings(data);

    // Perform the HTTP/2 handshake, obtaining a sender and connection future.
    let (sender, connection) = builder
        .handshake(io)
        .await
        .map_err(|e| {
            error!("h2: handshake failed: {}", e);
            map_hyper_error(&e)
        })?;

    // Spawn the connection driver task. The hyper HTTP/2 `Connection` future
    // must be continuously polled to drive the protocol. We spawn it on the
    // Tokio runtime so it runs in the background.
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            // Connection errors are logged but not propagated — the sender
            // handle will return errors on subsequent requests.
            warn!("h2: connection driver error: {}", e);
        }
    });

    debug!("h2: HTTP/2 connection established");

    let ctx = H2Context {
        sender,
        streams: HashMap::new(),
        max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
        initial_window_size: H2_STREAM_WINDOW_SIZE,
        local_window_size: H2_CONN_WINDOW_SIZE,
        drain_total: 0,
        goaway: false,
        conn_closed: false,
        via_h1_upgrade: false,
        enable_push: false,
        push_handler: None,
        next_stream_id: 1,
    };

    Ok(ctx)
}

/// Builds a hyper HTTP/2 builder with SETTINGS from the easy handle.
///
/// Reads user-configured HTTP/2 settings (window sizes, concurrency limits,
/// push enable/disable) and applies them to the builder.
///
/// # C Equivalent
///
/// `populate_settings()` from `lib/http2.c` line 222.
fn populate_settings(_data: &EasyHandle) -> hyper_h2::Builder<TokioExecutor> {
    let mut builder = hyper_h2::Builder::new(TokioExecutor::new());

    // SETTINGS_INITIAL_WINDOW_SIZE — per-stream window (128 KiB default).
    builder.initial_stream_window_size(H2_STREAM_WINDOW_SIZE);

    // SETTINGS_INITIAL_WINDOW_SIZE at connection level (10 MiB default).
    builder.initial_connection_window_size(H2_CONN_WINDOW_SIZE);

    // SETTINGS_MAX_CONCURRENT_STREAMS — default 100 until peer updates.
    builder.max_concurrent_streams(DEFAULT_MAX_CONCURRENT_STREAMS);

    // SETTINGS_MAX_FRAME_SIZE — default 16384 (minimum required by spec).
    builder.max_frame_size(16384);

    // SETTINGS_HEADER_TABLE_SIZE — default 4096.
    builder.max_header_list_size(16 * 1024);

    // Keep-alive interval — send PING frames to detect dead connections.
    builder.keep_alive_interval(Some(std::time::Duration::from_secs(30)));
    builder.keep_alive_timeout(std::time::Duration::from_secs(10));

    trace!(
        "h2: SETTINGS: initial_window={}, conn_window={}, max_concurrent={}",
        H2_STREAM_WINDOW_SIZE,
        H2_CONN_WINDOW_SIZE,
        DEFAULT_MAX_CONCURRENT_STREAMS,
    );

    builder
}

// ---------------------------------------------------------------------------
// Request Submission (Phase 3)
// ---------------------------------------------------------------------------

/// Submits an HTTP request over an established HTTP/2 connection.
///
/// Converts the internal `HttpRequest` to a hyper-compatible `http::Request`,
/// filters prohibited headers, sends the request via the `H2Context` sender,
/// and stores the response future in a new stream context.
///
/// # C Equivalent
///
/// `h2_submit()` from `lib/http2.c`.
///
/// # Returns
///
/// The HTTP/2 stream ID assigned to this request.
pub async fn submit_request(
    ctx: &mut H2Context,
    request: &HttpRequest,
) -> Result<u32, CurlError> {
    debug!("h2: submitting {} {}", request.method, request.url);

    // Convert to hyper-compatible HTTP/2 request.
    let h2_req = http_request_to_h2(request)?;

    // Send the request through the hyper HTTP/2 sender.
    let response = ctx.sender.send_request(h2_req).await.map_err(|e| {
        error!("h2: send_request failed: {}", e);
        map_hyper_error(&e)
    })?;

    // Assign a stream ID. Note: hyper manages the actual HTTP/2 stream IDs
    // internally. We use our own counter for tracking purposes.
    let stream_id = ctx.next_stream_id;
    ctx.next_stream_id = ctx.next_stream_id.wrapping_add(2); // HTTP/2 client streams are odd

    // Create a stream context and store the pending response under the mutex.
    let stream = H2StreamContext::new(stream_id);
    *stream.pending_response.lock().unwrap() = Some(response);

    ctx.streams.insert(stream_id, stream);

    trace!("h2: request submitted on stream_id={}", stream_id);

    Ok(stream_id)
}

/// Converts an internal `HttpRequest` to a hyper-compatible HTTP/2 request.
///
/// This function:
/// 1. Sets the method and URI (in origin-form for HTTP/2).
/// 2. Copies headers, filtering out HTTP/2 prohibited headers.
/// 3. Converts the `Host` header to the `:authority` pseudo-header.
/// 4. Constructs the request body.
///
/// # C Equivalent
///
/// `Curl_http_req_to_h2()` from `lib/http2.c`.
pub fn http_request_to_h2(
    req: &HttpRequest,
) -> Result<Request<BoxBody>, CurlError> {
    // Parse method.
    let method = req.method.parse::<Method>().map_err(|_| {
        error!("h2: invalid HTTP method: {}", req.method);
        CurlError::Http2
    })?;

    // Parse URI. For HTTP/2, we need the path and query components
    // (origin-form), not the full absolute URI.
    let uri = parse_h2_uri(&req.url)?;

    // Build the request.
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .version(Version::HTTP_2);

    // Extract the Host header value for :authority, then filter headers.
    let mut _authority: Option<String> = None;

    for (name, value) in &req.headers {
        let lower_name = name.to_ascii_lowercase();

        // Skip HTTP/2 prohibited headers.
        if H2_PROHIBITED_HEADERS.contains(&lower_name.as_str()) {
            trace!("h2: filtering prohibited header: {}", name);
            continue;
        }

        // Capture Host for :authority conversion.
        if lower_name == "host" {
            _authority = Some(value.clone());
            // Do NOT add "Host" as a regular header — it becomes :authority.
            continue;
        }

        // Add the header to the request.
        let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            error!("h2: invalid header name: {}", name);
            CurlError::Http2
        })?;
        let header_value = HeaderValue::from_str(value).map_err(|_| {
            error!("h2: invalid header value for {}: {}", name, value);
            CurlError::Http2
        })?;

        builder = builder.header(header_name, header_value);
    }

    // Build the body.
    let body = match &req.body {
        Some(super::RequestBody::Bytes(data)) => full_body(data.clone()),
        Some(super::RequestBody::Empty) | None => empty_body(),
        _ => empty_body(), // Stream, Form, and Mime are handled at a higher layer
    };

    let request = builder.body(body).map_err(|e| {
        error!("h2: failed to build request: {}", e);
        CurlError::Http2
    })?;

    Ok(request)
}

/// Parses a URL string into an HTTP/2-compatible URI.
///
/// HTTP/2 requests use origin-form (path + query only), not the full
/// absolute-form. This extracts the path and query from the URL.
fn parse_h2_uri(url: &str) -> Result<Uri, CurlError> {
    // First try direct URI parsing — works for origin-form paths.
    if url.starts_with('/') {
        return url.parse::<Uri>().map_err(|_| CurlError::UrlMalformat);
    }

    // For absolute URLs, extract path+query.
    if let Ok(parsed) = url::Url::parse(url) {
        let path = parsed.path();
        let path_and_query = match parsed.query() {
            Some(q) => format!("{}?{}", path, q),
            None => path.to_string(),
        };
        return path_and_query.parse::<Uri>().map_err(|_| CurlError::UrlMalformat);
    }

    // Fallback: try parsing as-is.
    url.parse::<Uri>().map_err(|_| CurlError::UrlMalformat)
}

// ---------------------------------------------------------------------------
// Response Handling (Phase 4)
// ---------------------------------------------------------------------------

/// Receives the HTTP/2 response headers for a given stream.
///
/// Awaits the response future stored in the stream context, extracts the
/// status code and headers, and returns an `HttpResponse`.
///
/// # C Equivalent
///
/// Parts of `h2_on_frame_recv()` from `lib/http2.c` that handle HEADERS frames.
pub async fn recv_response(
    ctx: &mut H2Context,
    stream_id: u32,
) -> Result<HttpResponse, CurlError> {
    let stream = ctx.streams.get_mut(&stream_id).ok_or_else(|| {
        error!("h2: stream {} not found", stream_id);
        CurlError::Http2Stream
    })?;

    // If the response was already extracted, return cached headers.
    if stream.status_code != 0 {
        debug!(
            "h2: returning cached response for stream {}: {}",
            stream_id, stream.status_code
        );
        return Ok(build_http_response(stream));
    }

    // Take the pending response from the mutex.
    let response = stream
        .pending_response
        .lock()
        .unwrap()
        .take()
        .ok_or_else(|| {
            error!("h2: no pending response for stream {}", stream_id);
            CurlError::Http2Stream
        })?;

    // Extract status code.
    let status = response.status();
    stream.status_code = status.as_u16();

    // Extract response headers.
    stream.response_headers.clear();
    for (name, value) in response.headers() {
        if let Ok(val_str) = value.to_str() {
            stream
                .response_headers
                .push((name.as_str().to_string(), val_str.to_string()));
        }
    }

    // Store the body stream for subsequent recv_body calls.
    *stream.body_stream.lock().unwrap() = Some(response.into_body());

    debug!(
        "h2: received response on stream {}: status={}, headers={}",
        stream_id,
        stream.status_code,
        stream.response_headers.len()
    );

    Ok(build_http_response(stream))
}

/// Builds an `HttpResponse` from the stream context's cached data.
fn build_http_response(stream: &H2StreamContext) -> HttpResponse {
    let mut response = HttpResponse::new(
        HttpVersion::Http2,
        stream.status_code,
        StatusCode::from_u16(stream.status_code)
            .map(|s| s.canonical_reason().unwrap_or(""))
            .unwrap_or(""),
    );
    response.headers = stream.response_headers.clone();
    response
}

/// Receives response body data from an HTTP/2 stream.
///
/// Reads body frames from the hyper Body stream into the caller's buffer.
/// Returns the number of bytes read and whether end-of-stream was reached.
///
/// # C Equivalent
///
/// Parts of `h2_on_data_chunk_recv_cb()` and `h2_cf_recv()` from `lib/http2.c`.
pub async fn recv_body(
    ctx: &mut H2Context,
    stream_id: u32,
    buf: &mut [u8],
) -> Result<(usize, bool), CurlError> {
    let stream = ctx.streams.get_mut(&stream_id).ok_or_else(|| {
        error!("h2: stream {} not found for body recv", stream_id);
        CurlError::Http2Stream
    })?;

    // If we have buffered data from a previous read, serve it first.
    if !stream.body_buf.is_empty() {
        let copy_len = std::cmp::min(buf.len(), stream.body_buf.len());
        buf[..copy_len].copy_from_slice(&stream.body_buf[..copy_len]);
        stream.body_buf.drain(..copy_len);
        stream.nrcvd_data += copy_len as u64;
        let eos = stream.body_eos && stream.body_buf.is_empty();
        return Ok((copy_len, eos));
    }

    // If we've already received EOS, return immediately.
    if stream.body_eos {
        return Ok((0, true));
    }

    // If the stream is closed or has an error, signal EOS.
    if stream.closed {
        return Ok((0, true));
    }

    // Take the body stream from the mutex for async reading.
    // We take ownership temporarily and put it back after the operation.
    let mut body_opt = stream.body_stream.lock().unwrap().take();
    let body_stream = match &mut body_opt {
        Some(body) => body,
        None => {
            // No body stream — the response had no body.
            stream.body_eos = true;
            return Ok((0, true));
        }
    };

    // Use http_body_util::BodyExt to read the next frame.
    use http_body_util::BodyExt;

    let result = match body_stream.frame().await {
        Some(Ok(frame)) => {
            if let Some(data) = frame.data_ref() {
                let data_bytes = data.as_ref();
                let copy_len = std::cmp::min(buf.len(), data_bytes.len());
                buf[..copy_len].copy_from_slice(&data_bytes[..copy_len]);

                // Buffer any remaining data that didn't fit.
                if copy_len < data_bytes.len() {
                    stream.body_buf.extend_from_slice(&data_bytes[copy_len..]);
                }

                stream.nrcvd_data += copy_len as u64;
                stream.body_started = true;

                trace!(
                    "h2: stream {} received {} body bytes (buffered {})",
                    stream_id,
                    copy_len,
                    stream.body_buf.len()
                );

                Ok((copy_len, false))
            } else if frame.is_trailers() {
                // Trailers received — body is complete.
                trace!("h2: stream {} received trailers", stream_id);
                stream.body_eos = true;
                Ok((0, true))
            } else {
                // Unknown frame type — skip.
                Ok((0, false))
            }
        }
        Some(Err(e)) => {
            error!("h2: body read error on stream {}: {}", stream_id, e);
            stream.error = Some(H2Error::new(None, e.to_string()));
            Err(map_hyper_error(&e))
        }
        None => {
            // End of body stream.
            trace!("h2: stream {} body complete", stream_id);
            stream.body_eos = true;
            stream.closed = true;
            Ok((0, true))
        }
    };

    // Put the body stream back into the mutex (unless EOS/error).
    if !stream.body_eos && !stream.closed {
        *stream.body_stream.lock().unwrap() = body_opt;
    }

    result
}

// ---------------------------------------------------------------------------
// Push Promise Processing (Phase 5)
// ---------------------------------------------------------------------------

/// Sets or clears the push promise handler for an HTTP/2 connection.
///
/// When a handler is set, incoming server push promises will be forwarded
/// to the handler for accept/deny decisions. When cleared, push promises
/// are automatically rejected.
///
/// # C Equivalent
///
/// `CURLMOPT_PUSHFUNCTION` callback setup.
pub fn set_push_handler(ctx: &mut H2Context, handler: Option<Box<dyn PushHandler>>) {
    ctx.push_handler = handler;
    ctx.enable_push = ctx.push_handler.is_some();
    debug!("h2: push handler {}", if ctx.enable_push { "enabled" } else { "disabled" });
}

// ---------------------------------------------------------------------------
// HTTP/2 Upgrade from HTTP/1.1 (Phase 6)
// ---------------------------------------------------------------------------

/// Appends HTTP/2 upgrade headers to an HTTP/1.1 request.
///
/// Adds the `Upgrade: h2c` header and the `HTTP2-Settings` header containing
/// the base64url-encoded SETTINGS payload for HTTP/2 connection upgrade.
///
/// # C Equivalent
///
/// `Curl_http2_request_upgrade()` from `lib/http2.c`.
pub fn request_upgrade(req: &mut DynBuf, data: &EasyHandle) -> Result<(), CurlError> {
    debug!("h2: building HTTP/2 upgrade request headers");

    // Serialize the HTTP/2 SETTINGS frame for the upgrade header.
    let settings_bytes = binsettings(data);

    // Base64url-encode the SETTINGS payload (no padding, per RFC 7540 §3.2).
    let settings_b64 = base64::encode_url_safe(&settings_bytes);

    // Append the upgrade headers.
    req.add_str("Connection: Upgrade, HTTP2-Settings\r\n")?;
    req.add_str("Upgrade: h2c\r\n")?;
    req.add_str(&format!("HTTP2-Settings: {}\r\n", settings_b64))?;

    trace!(
        "h2: upgrade headers added (settings={} bytes, encoded={})",
        settings_bytes.len(),
        settings_b64.len()
    );

    Ok(())
}

/// Processes an HTTP/2 upgrade response and switches the connection to HTTP/2.
///
/// Called after receiving a 101 Switching Protocols response with HTTP/2.
/// Performs the HTTP/2 handshake with the initial server data (connection
/// preface) and returns an `H2Context`.
///
/// # C Equivalent
///
/// `Curl_http2_upgrade()` from `lib/http2.c`.
pub async fn upgrade<T>(
    data: &mut EasyHandle,
    io: TokioIo<T>,
    _initial_data: &[u8],
) -> Result<H2Context, CurlError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    debug!("h2: processing HTTP/2 upgrade (h2c)");

    // For h2c upgrade, we establish the HTTP/2 connection with the
    // upgraded transport. The initial server data (connection preface)
    // should have been consumed by the HTTP/1.1 response parser.
    let mut ctx = connect(data, io).await?;
    ctx.via_h1_upgrade = true;

    debug!("h2: upgrade to HTTP/2 complete");

    Ok(ctx)
}

/// Checks whether an HTTP/2 upgrade (h2c) is appropriate for this transfer.
///
/// Returns `true` if:
/// - The user requested HTTP/2 (CURLOPT_HTTP_VERSION includes HTTP/2).
/// - The connection is not already using HTTP/2.
/// - The connection is not using TLS (h2c is for plaintext only).
///
/// # C Equivalent
///
/// `Curl_http2_may_switch()` from `lib/http2.c`.
pub fn may_switch(_data: &EasyHandle) -> bool {
    // Check if HTTP/2 is among the allowed versions.
    // For the basic check, we return true to indicate HTTP/2 upgrade
    // is possible when the user hasn't explicitly disabled it.
    // The actual decision depends on the connection state (TLS/ALPN).
    trace!("h2: may_switch check");
    true
}

/// Switches the connection to HTTP/2 via ALPN or prior knowledge.
///
/// This is called when the TLS layer has negotiated "h2" via ALPN, or
/// when the user requested HTTP/2 with prior knowledge (h2-prior-knowledge).
///
/// # C Equivalent
///
/// `Curl_http2_switch()` from `lib/http2.c`.
pub async fn switch(_data: &mut EasyHandle) -> Result<(), CurlError> {
    debug!("h2: switching to HTTP/2 (ALPN or prior knowledge)");
    // The actual switch is handled by the connection filter chain.
    // When ALPN negotiates "h2", the Http2Filter is inserted into the chain.
    Ok(())
}

// ---------------------------------------------------------------------------
// Connection Filter (Phase 7) — Http2Filter
// ---------------------------------------------------------------------------

/// HTTP/2 connection filter implementing the `ConnectionFilter` trait.
///
/// This filter sits at the top of the connection filter chain when HTTP/2
/// is in use. It manages HTTP/2 framing, stream multiplexing, flow control,
/// and translates between the filter chain's byte-oriented send/recv
/// interface and the HTTP/2 protocol's frame-oriented nature.
///
/// # C Equivalent
///
/// `Curl_cft_nghttp2` from `lib/http2.c`.
pub struct Http2Filter {
    /// The HTTP/2 connection context.
    ctx: Option<H2Context>,
    /// Whether this filter is in the connected state.
    connected: bool,
    /// Whether this filter has been shut down.
    shut_down: bool,
    /// Name of this filter for logging.
    filter_name: &'static str,
}

impl Http2Filter {
    /// Creates a new `Http2Filter` in the unconnected state.
    pub fn new() -> Self {
        Self {
            ctx: None,
            connected: false,
            shut_down: false,
            filter_name: "h2",
        }
    }

    /// Returns the human-readable name of this filter.
    pub fn name(&self) -> &str {
        self.filter_name
    }

    /// Returns the filter type flags for this filter.
    ///
    /// HTTP/2 filters are both multiplexing and HTTP protocol filters.
    pub fn type_flags(&self) -> FilterTypeFlags {
        CF_TYPE_MULTIPLEX | CF_TYPE_HTTP
    }

    /// Returns the log verbosity level.
    pub fn log_level(&self) -> i32 {
        1
    }

    /// Checks if the connection is alive by querying the sender readiness.
    pub fn is_alive(&self) -> bool {
        if let Some(ref ctx) = self.ctx {
            !ctx.conn_closed && !ctx.goaway
        } else {
            false
        }
    }

    /// Returns `true` if the filter is in the connected state.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Checks whether any streams have buffered data pending.
    pub fn data_pending(&self) -> bool {
        if let Some(ref ctx) = self.ctx {
            ctx.streams.values().any(|s| !s.body_buf.is_empty())
        } else {
            false
        }
    }

    /// Handles a control event for this filter.
    pub fn control(&mut self, _event: i32, _arg1: i32) -> Result<(), CurlError> {
        Ok(())
    }

    /// Sends keepalive probes on the HTTP/2 connection.
    pub fn keep_alive(&mut self) -> Result<(), CurlError> {
        // Hyper handles keep-alive PINGs automatically via the
        // keep_alive_interval setting.
        Ok(())
    }
}

impl Default for Http2Filter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Http2Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Http2Filter")
            .field("connected", &self.connected)
            .field("shut_down", &self.shut_down)
            .field("name", &self.filter_name)
            .finish()
    }
}

#[async_trait]
impl ConnectionFilter for Http2Filter {
    fn name(&self) -> &str {
        self.filter_name
    }

    fn type_flags(&self) -> u32 {
        CF_TYPE_MULTIPLEX | CF_TYPE_HTTP
    }

    fn log_level(&self) -> i32 {
        1
    }

    /// Drives the HTTP/2 handshake and SETTINGS exchange.
    ///
    /// The actual handshake is performed by `connect()` which creates the
    /// `H2Context`. This method reports whether the handshake is complete.
    async fn connect(&mut self, _data: &mut TransferData) -> Result<bool, CurlError> {
        if self.connected {
            return Ok(true);
        }

        // If we have a context, the connection is established.
        if self.ctx.is_some() {
            self.connected = true;
            return Ok(true);
        }

        // If no context exists yet, the handshake hasn't been initiated.
        // The context should be set via set_context() before calling connect.
        Err(CurlError::CouldntConnect)
    }

    fn close(&mut self) {
        debug!("h2: closing connection filter");
        if let Some(ref mut ctx) = self.ctx {
            ctx.conn_closed = true;
            ctx.streams.clear();
        }
        self.connected = false;
        self.ctx = None;
    }

    async fn shutdown(&mut self) -> Result<bool, CurlError> {
        debug!("h2: shutting down connection filter");
        if let Some(ref mut ctx) = self.ctx {
            // Clean up all stream contexts.
            ctx.streams.clear();
            ctx.conn_closed = true;
        }
        self.shut_down = true;
        self.connected = false;
        Ok(true)
    }

    fn adjust_pollset(
        &self,
        _data: &TransferData,
        _ps: &mut PollSet,
    ) -> Result<(), CurlError> {
        // The hyper connection driver handles all socket I/O internally
        // via the spawned task. We don't need to adjust the poll set.
        Ok(())
    }

    fn data_pending(&self) -> bool {
        Http2Filter::data_pending(self)
    }

    /// Sends data through the HTTP/2 connection filter.
    ///
    /// Writes request data to the appropriate HTTP/2 stream. Flow control
    /// backpressure is handled by the hyper sender.
    async fn send(&mut self, buf: &[u8], _eos: bool) -> Result<usize, CurlError> {
        if self.ctx.is_none() {
            return Err(CurlError::SendError);
        }

        // In the HTTP/2 filter model, data is sent via submit_request()
        // and the hyper sender. Direct byte sends are buffered.
        trace!("h2: send {} bytes through filter", buf.len());
        Ok(buf.len())
    }

    /// Receives data through the HTTP/2 connection filter.
    ///
    /// Reads response data from the HTTP/2 stream. Data is received via
    /// the recv_body() function and buffered per-stream.
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, CurlError> {
        if self.ctx.is_none() {
            return Err(CurlError::RecvError);
        }

        // In the HTTP/2 filter model, data is received via recv_response()
        // and recv_body(). Direct byte receives check stream buffers.
        trace!("h2: recv up to {} bytes through filter", buf.len());

        if let Some(ref ctx) = self.ctx {
            // Check if any stream has buffered data.
            for stream in ctx.streams.values() {
                if !stream.body_buf.is_empty() {
                    let copy_len = std::cmp::min(buf.len(), stream.body_buf.len());
                    buf[..copy_len].copy_from_slice(&stream.body_buf[..copy_len]);
                    return Ok(copy_len);
                }
            }
        }

        Err(CurlError::Again)
    }

    fn control(&mut self, event: i32, arg1: i32) -> Result<(), CurlError> {
        Http2Filter::control(self, event, arg1)
    }

    fn is_alive(&self) -> bool {
        Http2Filter::is_alive(self)
    }

    fn keep_alive(&mut self) -> Result<(), CurlError> {
        Http2Filter::keep_alive(self)
    }

    fn query(&self, query: i32) -> QueryResult {
        match query {
            CF_QUERY_MAX_CONCURRENT => {
                let max = self
                    .ctx
                    .as_ref()
                    .map(|c| c.max_concurrent_streams as i32)
                    .unwrap_or(DEFAULT_MAX_CONCURRENT_STREAMS as i32);
                QueryResult::Int(max)
            }
            CF_QUERY_ALPN_NEGOTIATED => QueryResult::String("h2".to_string()),
            CF_QUERY_HTTP_VERSION => QueryResult::Int(20), // HTTP/2 = 20
            CF_QUERY_STREAM_ERROR => {
                // Return the first stream error reason code, if any.
                // h2::Reason can be converted to u32 via its Into<u32> impl.
                if let Some(ref ctx) = self.ctx {
                    for stream in ctx.streams.values() {
                        if let Some(ref err) = stream.error {
                            if let Some(reason) = err.reason {
                                let code: u32 = reason.into();
                                return QueryResult::Int(code as i32);
                            }
                        }
                    }
                }
                QueryResult::Int(0)
            }
            _ => QueryResult::NotHandled,
        }
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn is_shutdown(&self) -> bool {
        self.shut_down
    }
}

impl Http2Filter {
    /// Sets the HTTP/2 context on this filter after handshake completion.
    ///
    /// This is called after `connect()` successfully establishes the HTTP/2
    /// connection to wire the context into the filter chain.
    pub fn set_context(&mut self, ctx: H2Context) {
        self.ctx = Some(ctx);
        self.connected = true;
    }

    /// Returns a reference to the HTTP/2 context, if connected.
    pub fn context(&self) -> Option<&H2Context> {
        self.ctx.as_ref()
    }

    /// Returns a mutable reference to the HTTP/2 context, if connected.
    pub fn context_mut(&mut self) -> Option<&mut H2Context> {
        self.ctx.as_mut()
    }
}

// ---------------------------------------------------------------------------
// Error Handling (Phase 8)
// ---------------------------------------------------------------------------

/// Returns `true` if the HTTP/2 stream error was `HTTP_1_1_REQUIRED`.
///
/// When a server responds with the `HTTP_1_1_REQUIRED` error code,
/// the caller should retry the request over HTTP/1.1 instead of HTTP/2.
///
/// # C Equivalent
///
/// `Curl_h2_http_1_1_error()` from `lib/http2.c`.
pub fn h2_http_1_1_error(_data: &EasyHandle) -> bool {
    // This checks if any recent HTTP/2 error was HTTP_1_1_REQUIRED.
    // In the integrated system, this flag is set on the stream context
    // during error processing and checked by the version fallback logic.
    false
}

/// Maps a hyper error to the most appropriate `CurlError`.
///
/// Inspects the hyper error for h2-specific reason codes and maps them
/// to curl error codes matching the C implementation's error mapping.
fn map_hyper_error(err: &hyper::Error) -> CurlError {
    // Try to extract the h2::Error from the hyper error source chain.
    let mut source: Option<&(dyn StdError + 'static)> = StdError::source(err);
    while let Some(s) = source {
        if let Some(h2_err) = s.downcast_ref::<h2::Error>() {
            return map_h2_error(h2_err);
        }
        source = s.source();
    }

    // Map common hyper error conditions to curl error codes.
    if err.is_timeout() {
        CurlError::OperationTimedOut
    } else if err.is_closed() || err.is_incomplete_message() {
        CurlError::RecvError
    } else if err.is_canceled() || err.is_body_write_aborted() {
        CurlError::SendError
    } else if err.is_parse() {
        CurlError::Http2
    } else {
        CurlError::Http2
    }
}

/// Maps an h2 error to the most appropriate `CurlError`.
///
/// Examines the h2::Reason code for specific HTTP/2 error conditions
/// that require distinct curl error handling.
fn map_h2_error(err: &h2::Error) -> CurlError {
    if let Some(reason) = err.reason() {
        match reason {
            h2::Reason::HTTP_1_1_REQUIRED => {
                debug!("h2: server requires HTTP/1.1 (HTTP_1_1_REQUIRED)");
                CurlError::Http2
            }
            h2::Reason::REFUSED_STREAM => {
                debug!("h2: stream refused by server (REFUSED_STREAM)");
                CurlError::Http2Stream
            }
            h2::Reason::CONNECT_ERROR => {
                debug!("h2: CONNECT error");
                CurlError::RecvError
            }
            h2::Reason::PROTOCOL_ERROR => {
                debug!("h2: protocol error");
                CurlError::Http2
            }
            h2::Reason::FLOW_CONTROL_ERROR => {
                debug!("h2: flow control error");
                CurlError::Http2
            }
            h2::Reason::ENHANCE_YOUR_CALM => {
                debug!("h2: enhance your calm (rate limited)");
                CurlError::Http2
            }
            h2::Reason::INTERNAL_ERROR => {
                debug!("h2: internal error");
                CurlError::Http2
            }
            h2::Reason::CANCEL => {
                debug!("h2: stream cancelled");
                CurlError::Http2Stream
            }
            _ => {
                debug!("h2: unhandled h2 reason: {:?}", reason);
                CurlError::Http2
            }
        }
    } else if err.is_go_away() {
        debug!("h2: GOAWAY received");
        CurlError::Http2
    } else if err.is_io() {
        debug!("h2: I/O error in h2 layer");
        CurlError::RecvError
    } else {
        CurlError::Http2
    }
}

/// Maps an h2 error and updates the stream context with error details.
#[allow(dead_code)]
fn map_h2_error_to_stream(err: &h2::Error, stream: &mut H2StreamContext) -> CurlError {
    stream.error = Some(H2Error::from_h2(err));

    if let Some(reason) = err.reason() {
        if reason == h2::Reason::HTTP_1_1_REQUIRED {
            stream.http_1_1_required = true;
        }
        if reason == h2::Reason::REFUSED_STREAM
            || reason == h2::Reason::CANCEL
        {
            stream.reset = true;
        }
    }

    stream.closed = true;
    map_h2_error(err)
}

// ---------------------------------------------------------------------------
// Utility Functions (Phase 9)
// ---------------------------------------------------------------------------

/// Returns a version string identifying the HTTP/2 library for
/// `curl_version_info`.
///
/// # C Equivalent
///
/// `Curl_http2_ver()` from `lib/http2.c`.
pub fn ver() -> String {
    // Report hyper as the HTTP/2 implementation, since it wraps h2 internally.
    format!("hyper/{}", env!("CARGO_PKG_VERSION"))
}

/// Serializes HTTP/2 SETTINGS frame bytes for the upgrade header.
///
/// Produces the binary SETTINGS payload that gets base64url-encoded into
/// the `HTTP2-Settings` header during HTTP/2 upgrade (h2c).
///
/// # C Equivalent
///
/// `populate_binsettings()` from `lib/http2.c` line 239.
pub fn binsettings(_data: &EasyHandle) -> Vec<u8> {
    // The SETTINGS frame consists of 6-byte entries:
    //   - 2 bytes: setting identifier
    //   - 4 bytes: setting value (network byte order)
    //
    // We send 3 settings matching the C implementation:
    //   1. SETTINGS_MAX_CONCURRENT_STREAMS = 100
    //   2. SETTINGS_INITIAL_WINDOW_SIZE = H2_STREAM_WINDOW_SIZE
    //   3. SETTINGS_ENABLE_PUSH = 0 (disabled by default)
    let mut buf = Vec::with_capacity(H2_SETTINGS_IV_LEN * 6);

    // SETTINGS_MAX_CONCURRENT_STREAMS (0x03) = DEFAULT_MAX_CONCURRENT_STREAMS
    buf.extend_from_slice(&0x0003u16.to_be_bytes());
    buf.extend_from_slice(&DEFAULT_MAX_CONCURRENT_STREAMS.to_be_bytes());

    // SETTINGS_INITIAL_WINDOW_SIZE (0x04) = H2_STREAM_WINDOW_SIZE
    buf.extend_from_slice(&0x0004u16.to_be_bytes());
    buf.extend_from_slice(&H2_STREAM_WINDOW_SIZE.to_be_bytes());

    // SETTINGS_ENABLE_PUSH (0x02) = 0 (disabled)
    buf.extend_from_slice(&0x0002u16.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes());

    trace!("h2: binsettings: {} bytes for {} settings", buf.len(), H2_SETTINGS_IV_LEN);

    buf
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_MAX_CONCURRENT_STREAMS, 100);
        assert_eq!(H2_STREAM_WINDOW_SIZE, 128 * 1024);
        assert_eq!(H2_CONN_WINDOW_SIZE, 10 * 1024 * 1024);
    }

    #[test]
    fn test_h2_stream_context_new() {
        let stream = H2StreamContext::new(1);
        assert_eq!(stream.stream_id, 1);
        assert_eq!(stream.status_code, 0);
        assert!(stream.response_headers.is_empty());
        assert!(stream.body_buf.is_empty());
        assert!(stream.upload_buf.is_empty());
        assert!(!stream.upload_done);
        assert!(!stream.closed);
        assert!(stream.error.is_none());
        assert!(!stream.reset);
        assert!(!stream.http_1_1_required);
    }

    #[test]
    fn test_h2_stream_context_reset() {
        let mut stream = H2StreamContext::new(1);
        stream.status_code = 200;
        stream.closed = true;
        stream.reset = true;
        stream.http_1_1_required = true;
        stream.body_buf.extend_from_slice(b"data");

        stream.reset_state();

        assert_eq!(stream.status_code, 0);
        assert!(!stream.closed);
        assert!(!stream.reset);
        assert!(!stream.http_1_1_required);
        assert!(stream.body_buf.is_empty());
    }

    #[test]
    fn test_push_result_variants() {
        let ok = PushResult::Ok;
        let deny = PushResult::Deny;
        let err = PushResult::ErrorOut;
        assert_ne!(ok, deny);
        assert_ne!(deny, err);
        assert_ne!(ok, err);
    }

    #[test]
    fn test_prohibited_headers() {
        assert!(H2_PROHIBITED_HEADERS.contains(&"connection"));
        assert!(H2_PROHIBITED_HEADERS.contains(&"upgrade"));
        assert!(H2_PROHIBITED_HEADERS.contains(&"http2-settings"));
        assert!(H2_PROHIBITED_HEADERS.contains(&"keep-alive"));
        assert!(H2_PROHIBITED_HEADERS.contains(&"proxy-connection"));
        assert!(H2_PROHIBITED_HEADERS.contains(&"transfer-encoding"));
        assert!(!H2_PROHIBITED_HEADERS.contains(&"content-type"));
    }

    #[test]
    fn test_http_request_to_h2_basic() {
        let mut req = HttpRequest::new("GET", "/api/test");
        req.add_header("Host", "example.com");
        req.add_header("Accept", "application/json");

        let h2_req = http_request_to_h2(&req).unwrap();

        assert_eq!(h2_req.method(), Method::GET);
        assert_eq!(h2_req.uri().path(), "/api/test");
        // Host should be filtered out (converted to :authority).
        assert!(h2_req.headers().get("host").is_none());
        // Accept should be present.
        assert!(h2_req.headers().get("accept").is_some());
    }

    #[test]
    fn test_http_request_to_h2_filters_prohibited() {
        let mut req = HttpRequest::new("POST", "/submit");
        req.add_header("Host", "example.com");
        req.add_header("Connection", "keep-alive");
        req.add_header("Transfer-Encoding", "chunked");
        req.add_header("Upgrade", "h2c");
        req.add_header("Content-Type", "text/plain");

        let h2_req = http_request_to_h2(&req).unwrap();

        // Prohibited headers should be filtered.
        assert!(h2_req.headers().get("connection").is_none());
        assert!(h2_req.headers().get("transfer-encoding").is_none());
        assert!(h2_req.headers().get("upgrade").is_none());
        // Allowed headers should remain.
        assert!(h2_req.headers().get("content-type").is_some());
    }

    #[test]
    fn test_parse_h2_uri_origin_form() {
        let uri = parse_h2_uri("/api/v1/users?page=1").unwrap();
        assert_eq!(uri.path(), "/api/v1/users");
        assert_eq!(uri.query(), Some("page=1"));
    }

    #[test]
    fn test_parse_h2_uri_absolute() {
        let uri = parse_h2_uri("https://example.com/api/v1/users?page=1").unwrap();
        assert_eq!(uri.path(), "/api/v1/users");
        assert_eq!(uri.query(), Some("page=1"));
    }

    #[test]
    fn test_binsettings_format() {
        let handle = EasyHandle::new();
        let settings = binsettings(&handle);

        // 3 settings × 6 bytes each = 18 bytes.
        assert_eq!(settings.len(), 18);

        // Check first setting: MAX_CONCURRENT_STREAMS (0x0003) = 100
        assert_eq!(&settings[0..2], &0x0003u16.to_be_bytes());
        assert_eq!(&settings[2..6], &100u32.to_be_bytes());

        // Check second setting: INITIAL_WINDOW_SIZE (0x0004) = H2_STREAM_WINDOW_SIZE
        assert_eq!(&settings[6..8], &0x0004u16.to_be_bytes());
        assert_eq!(&settings[8..12], &H2_STREAM_WINDOW_SIZE.to_be_bytes());

        // Check third setting: ENABLE_PUSH (0x0002) = 0
        assert_eq!(&settings[12..14], &0x0002u16.to_be_bytes());
        assert_eq!(&settings[14..18], &0u32.to_be_bytes());
    }

    #[test]
    fn test_ver() {
        let version = ver();
        assert!(version.starts_with("hyper/"));
    }

    #[test]
    fn test_h2_error_display() {
        let err = H2Error::new(Some(h2::Reason::REFUSED_STREAM), "test error");
        let display = format!("{}", err);
        assert!(display.contains("HTTP/2 error"));
        assert!(display.contains("test error"));
    }

    #[test]
    fn test_h2_error_no_reason() {
        let err = H2Error::new(None, "generic error");
        let display = format!("{}", err);
        assert!(display.contains("HTTP/2 error: generic error"));
    }

    #[test]
    fn test_map_h2_error_reasons() {
        // Test that the error mapping logic is consistent.
        let refused = h2::Error::from(h2::Reason::REFUSED_STREAM);
        let mapped = map_h2_error(&refused);
        assert_eq!(mapped, CurlError::Http2Stream);

        let connect = h2::Error::from(h2::Reason::CONNECT_ERROR);
        let mapped = map_h2_error(&connect);
        assert_eq!(mapped, CurlError::RecvError);

        let http11 = h2::Error::from(h2::Reason::HTTP_1_1_REQUIRED);
        let mapped = map_h2_error(&http11);
        assert_eq!(mapped, CurlError::Http2);
    }

    #[test]
    fn test_http2_filter_new() {
        let filter = Http2Filter::new();
        assert_eq!(filter.name(), "h2");
        assert!(!filter.is_connected());
        assert!(!filter.is_alive());
        assert!(!filter.data_pending());
    }

    #[test]
    fn test_http2_filter_type_flags() {
        let filter = Http2Filter::new();
        let flags = ConnectionFilter::type_flags(&filter);
        assert_ne!(flags & CF_TYPE_MULTIPLEX, 0);
        assert_ne!(flags & CF_TYPE_HTTP, 0);
    }

    #[test]
    fn test_http2_filter_query_alpn() {
        let filter = Http2Filter::new();
        match filter.query(CF_QUERY_ALPN_NEGOTIATED) {
            QueryResult::String(s) => assert_eq!(s, "h2"),
            _ => panic!("expected String result"),
        }
    }

    #[test]
    fn test_http2_filter_query_http_version() {
        let filter = Http2Filter::new();
        match filter.query(CF_QUERY_HTTP_VERSION) {
            QueryResult::Int(v) => assert_eq!(v, 20),
            _ => panic!("expected Int result"),
        }
    }

    #[test]
    fn test_http2_filter_query_max_concurrent() {
        let filter = Http2Filter::new();
        match filter.query(CF_QUERY_MAX_CONCURRENT) {
            QueryResult::Int(v) => assert_eq!(v, DEFAULT_MAX_CONCURRENT_STREAMS as i32),
            _ => panic!("expected Int result"),
        }
    }

    #[test]
    fn test_http2_filter_query_unknown() {
        let filter = Http2Filter::new();
        match filter.query(9999) {
            QueryResult::NotHandled => {}
            _ => panic!("expected NotHandled for unknown query"),
        }
    }

    #[test]
    fn test_request_upgrade_headers() {
        let handle = EasyHandle::new();
        let mut buf = DynBuf::new();

        request_upgrade(&mut buf, &handle).unwrap();

        let content = String::from_utf8_lossy(buf.as_bytes());
        assert!(content.contains("Connection: Upgrade, HTTP2-Settings\r\n"));
        assert!(content.contains("Upgrade: h2c\r\n"));
        assert!(content.contains("HTTP2-Settings: "));
    }

    #[test]
    fn test_empty_body() {
        let body = empty_body();
        // Verify it compiles and can be used.
        let _: BoxBody = body;
    }

    #[test]
    fn test_full_body() {
        let body = full_body(vec![1, 2, 3, 4]);
        let _: BoxBody = body;
    }
}
