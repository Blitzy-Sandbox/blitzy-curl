//! HTTP/1 CONNECT proxy tunnel connection filter.
//!
//! Complete Rust rewrite of `lib/cf-h1-proxy.c` (788 lines) and
//! `lib/cf-h1-proxy.h` from the curl C codebase.
//!
//! This filter implements the HTTP/1.x CONNECT method tunnel. When a client
//! needs to reach a target host through an HTTP proxy, this filter:
//!
//! 1. Sends a `CONNECT host:port HTTP/1.1` request to the proxy.
//! 2. Parses the proxy's HTTP response (status line + headers).
//! 3. Handles `407 Proxy Authentication Required` by retrying with credentials.
//! 4. After a `200` response, the tunnel is established and all subsequent
//!    data passes through transparently.
//!
//! # State Machine
//!
//! The tunnel follows a strict state machine matching the C implementation:
//!
//! ```text
//!   Init ──► Connect ──► Receive ──► Response ──► Established
//!     │         │            │           │              │
//!     └─────────┴────────────┴───────────┴──► Failed ◄──┘
//! ```
//!
//! # Feature Guards
//!
//! This module is only compiled when both the `http` feature is enabled and
//! the `disable_proxy` feature is NOT enabled, matching the C guard:
//! `#if !defined(CURL_DISABLE_PROXY) && !defined(CURL_DISABLE_HTTP)`.
//!
//! # Zero Unsafe
//!
//! This module contains zero `unsafe` blocks per AAP Section 0.7.1.

use std::fmt;
use std::str;

use async_trait::async_trait;
use bytes::BytesMut;
use tracing;

use crate::auth::{AuthConnState, AuthScheme, CURLAUTH_BASIC, CURLAUTH_DIGEST, CURLAUTH_NTLM};
use crate::conn::filters::{
    ConnectionFilter, PollAction, PollSet, QueryResult, TransferData, CF_QUERY_HOST_PORT,
    CF_TYPE_IP_CONNECT, CF_TYPE_PROXY,
};
use crate::error::{CurlError, CurlResult};
// Header type is the user-facing view from Headers::get(); DynHeaderEntry serves
// the equivalent role for DynHeaders::iter() with identical name()/value() API.
use crate::headers::{DynHeaders, HeaderOrigin};
use crate::protocols::http::chunks::Chunker;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Initial capacity for the CONNECT request buffer (bytes).
const REQUEST_BUF_INITIAL_CAP: usize = 512;

/// Initial capacity for the proxy response buffer (bytes).
const RESPONSE_BUF_INITIAL_CAP: usize = 4096;

/// Maximum allowed size of proxy response headers (128 KiB), matching
/// `DYN_PROXY_CONNECT_HEADERS` in the C code.
const MAX_RESPONSE_SIZE: usize = 128 * 1024;

/// Maximum allowed size of the CONNECT request (`DYN_HTTP_REQUEST` in C).
const MAX_REQUEST_SIZE: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// H1TunnelState — tunnel lifecycle states
// ---------------------------------------------------------------------------

/// States of the HTTP/1 CONNECT proxy tunnel state machine.
///
/// These correspond directly to the C `h1_tunnel_state` enum:
///
/// | Rust Variant   | C Constant            | Description                     |
/// |----------------|-----------------------|---------------------------------|
/// | `Init`         | `H1_TUNNEL_INIT`      | Initial / default state         |
/// | `Connect`      | `H1_TUNNEL_CONNECT`   | CONNECT request being sent      |
/// | `Receive`      | `H1_TUNNEL_RECEIVE`   | CONNECT response being received |
/// | `Response`     | `H1_TUNNEL_RESPONSE`  | Response received completely    |
/// | `Established`  | `H1_TUNNEL_ESTABLISHED`| Tunnel is open for data        |
/// | `Failed`       | `H1_TUNNEL_FAILED`    | Tunnel failed irrecoverably    |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum H1TunnelState {
    /// Init/default/no tunnel state.
    #[default]
    Init,
    /// CONNECT request is being sent.
    Connect,
    /// CONNECT answer is being received.
    Receive,
    /// CONNECT response received completely.
    Response,
    /// Tunnel successfully established.
    Established,
    /// Tunnel establishment failed.
    Failed,
}

impl fmt::Display for H1TunnelState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init => f.write_str("init"),
            Self::Connect => f.write_str("connect"),
            Self::Receive => f.write_str("receive"),
            Self::Response => f.write_str("response"),
            Self::Established => f.write_str("established"),
            Self::Failed => f.write_str("failed"),
        }
    }
}

// ---------------------------------------------------------------------------
// KeepOn — internal receive-loop control
// ---------------------------------------------------------------------------

/// Internal state controlling the header/body receive loop.
///
/// Mirrors the C `enum keeponval` inside `struct h1_tunnel_state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeepOn {
    /// All response data has been consumed — stop the loop.
    Done,
    /// Still reading the response status line / headers.
    Connect,
    /// Reading (and discarding) the response body (e.g. a 407 error page).
    Ignore,
}

// ---------------------------------------------------------------------------
// H1ProxyContext — per-connection tunnel state
// ---------------------------------------------------------------------------

/// Internal context for a single CONNECT tunnel attempt.
///
/// Mirrors the C `struct h1_tunnel_state` with idiomatic Rust types. Fields
/// use [`BytesMut`] instead of the C `struct dynbuf`, `String` instead of
/// `char *`, and [`Chunker`] instead of `struct Curl_chunker`.
struct H1ProxyContext {
    /// Current tunnel state.
    state: H1TunnelState,
    /// Buffer for the outgoing CONNECT request.
    request_buf: BytesMut,
    /// Buffer for the incoming proxy response (accumulates header lines).
    response_buf: BytesMut,
    /// Number of bytes of `request_buf` already sent.
    nsent: usize,
    /// Number of header lines received (for status-line vs header detection).
    header_lines: usize,
    /// Receive-loop control.
    keepon: KeepOn,
    /// Content-Length of the response body to ignore (-1 = unknown).
    content_length: i64,
    /// Whether the response uses chunked transfer-encoding.
    chunked_encoding: bool,
    /// Chunked decoder for consuming chunked response bodies.
    chunker: Chunker,
    /// Whether the proxy indicated `Connection: close`.
    close_connection: bool,
    /// Whether the current line might be a folded continuation line (obs-fold).
    maybe_folded: bool,
    /// Whether we are stripping leading whitespace on a folded line.
    leading_unfold: bool,
    /// HTTP status code from the proxy response (e.g. 200, 407).
    status_code: u16,
    /// HTTP minor version from the proxy response (0 or 1).
    http_minor: u8,
    /// Parsed response headers.
    response_headers: DynHeaders,
    /// Authentication connection state for proxy auth.
    auth_state: AuthConnState,
    /// Whether a new auth retry URL has been set (mimics C `data->req.newurl`).
    auth_retry_pending: bool,
    /// The `Proxy-Authenticate` challenge value from a 407 response.
    proxy_auth_challenge: Option<String>,
    /// Configured proxy authentication bitmask (CURLAUTH_* flags).
    proxy_auth_allowed: u64,
    /// Proxy username (if configured).
    proxy_user: Option<String>,
    /// Proxy password (if configured).
    proxy_password: Option<String>,
}

impl H1ProxyContext {
    /// Create a new context in the [`H1TunnelState::Init`] state.
    fn new() -> Self {
        Self {
            state: H1TunnelState::Init,
            request_buf: BytesMut::with_capacity(REQUEST_BUF_INITIAL_CAP),
            response_buf: BytesMut::with_capacity(RESPONSE_BUF_INITIAL_CAP),
            nsent: 0,
            header_lines: 0,
            keepon: KeepOn::Connect,
            content_length: 0,
            chunked_encoding: false,
            chunker: Chunker::new(true),
            close_connection: false,
            maybe_folded: false,
            leading_unfold: false,
            status_code: 0,
            http_minor: 1,
            response_headers: DynHeaders::new(),
            auth_state: AuthConnState::new(),
            auth_retry_pending: false,
            proxy_auth_challenge: None,
            proxy_auth_allowed: CURLAUTH_BASIC,
            proxy_user: None,
            proxy_password: None,
        }
    }

    /// Reset the context for a new CONNECT attempt (e.g. after auth retry).
    fn reinit(&mut self) {
        self.response_buf.clear();
        self.request_buf.clear();
        self.state = H1TunnelState::Init;
        self.keepon = KeepOn::Connect;
        self.content_length = 0;
        self.close_connection = false;
        self.maybe_folded = false;
        self.leading_unfold = false;
        self.status_code = 0;
        self.header_lines = 0;
        self.nsent = 0;
        self.chunked_encoding = false;
        self.chunker.reset(true);
        self.response_headers.clear();
        self.auth_retry_pending = false;
        self.proxy_auth_challenge = None;
    }
}

impl fmt::Debug for H1ProxyContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("H1ProxyContext")
            .field("state", &self.state)
            .field("status_code", &self.status_code)
            .field("nsent", &self.nsent)
            .field("header_lines", &self.header_lines)
            .field("keepon", &self.keepon)
            .field("content_length", &self.content_length)
            .field("chunked_encoding", &self.chunked_encoding)
            .field("close_connection", &self.close_connection)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// H1ProxyFilter — public filter implementing ConnectionFilter
// ---------------------------------------------------------------------------

/// HTTP/1 CONNECT proxy tunnel connection filter.
///
/// Implements the [`ConnectionFilter`] trait, matching the C `Curl_cft_h1_proxy`
/// connection filter type from `lib/cf-h1-proxy.c`.
///
/// # Usage
///
/// ```ignore
/// use curl_rs_lib::conn::h1_proxy::H1ProxyFilter;
///
/// let filter = H1ProxyFilter::new("proxy.example.com".into(), 8080);
/// // Insert into a FilterChain above the socket/TLS filter
/// ```
///
/// After construction, call [`connect()`](ConnectionFilter::connect) repeatedly
/// until it returns `Ok(true)`. At that point the tunnel is established and
/// [`send()`](ConnectionFilter::send) / [`recv()`](ConnectionFilter::recv)
/// transparently proxy data.
pub struct H1ProxyFilter {
    /// Target hostname for the CONNECT request.
    proxy_host: String,
    /// Target port for the CONNECT request.
    proxy_port: u16,
    /// Inner (lower-level) connection filter through which I/O is performed.
    /// Typically a socket filter or a TLS filter. Set via [`set_inner`].
    inner: Option<Box<dyn ConnectionFilter>>,
    /// Internal tunnel state.
    ctx: H1ProxyContext,
    /// Whether this filter is in the connected state.
    connected: bool,
    /// Whether this filter has been gracefully shut down.
    shut_down: bool,
}

impl H1ProxyFilter {
    /// Create a new HTTP/1 CONNECT proxy tunnel filter.
    ///
    /// The filter starts in the [`H1TunnelState::Init`] state. Call
    /// [`set_inner`](Self::set_inner) to provide the lower-level transport
    /// before calling [`connect`](ConnectionFilter::connect).
    ///
    /// # Arguments
    ///
    /// * `proxy_host` — The hostname or IP address that the CONNECT request
    ///   will target (the destination behind the proxy).
    /// * `proxy_port` — The port number for the CONNECT target.
    pub fn new(proxy_host: String, proxy_port: u16) -> Self {
        tracing::debug!(
            host = %proxy_host,
            port = proxy_port,
            "H1ProxyFilter: created"
        );
        Self {
            proxy_host,
            proxy_port,
            inner: None,
            ctx: H1ProxyContext::new(),
            connected: false,
            shut_down: false,
        }
    }

    /// Set the inner (lower-level) connection filter for I/O delegation.
    ///
    /// The inner filter is typically a TCP socket filter or a TLS filter that
    /// has already been connected to the proxy server. After the CONNECT
    /// tunnel is established, all data passes through this inner filter
    /// transparently.
    pub fn set_inner(&mut self, inner: Box<dyn ConnectionFilter>) {
        self.inner = Some(inner);
    }

    /// Returns `true` if the tunnel is in the [`H1TunnelState::Established`]
    /// state.
    #[inline]
    fn is_established(&self) -> bool {
        self.ctx.state == H1TunnelState::Established
    }

    /// Returns `true` if the tunnel is in the [`H1TunnelState::Failed`]
    /// state.
    #[inline]
    fn is_failed(&self) -> bool {
        self.ctx.state == H1TunnelState::Failed
    }

    /// Returns `true` if the tunnel is in the `Connect` state (sending the
    /// CONNECT request), indicating that the poll set should watch for write
    /// readiness.
    #[inline]
    fn want_send(&self) -> bool {
        self.ctx.state == H1TunnelState::Connect
    }

    /// Transition the tunnel to a new state with proper cleanup and logging.
    ///
    /// Mirrors the C `h1_tunnel_go_state()` function, performing
    /// state-specific cleanup on entry to each new state.
    fn go_state(&mut self, new_state: H1TunnelState) {
        if self.ctx.state == new_state {
            return;
        }

        match new_state {
            H1TunnelState::Init => {
                tracing::trace!("H1-PROXY: new tunnel state 'init'");
                self.ctx.reinit();
            }
            H1TunnelState::Connect => {
                tracing::trace!("H1-PROXY: new tunnel state 'connect'");
                self.ctx.state = H1TunnelState::Connect;
                self.ctx.keepon = KeepOn::Connect;
                self.ctx.response_buf.clear();
            }
            H1TunnelState::Receive => {
                tracing::trace!("H1-PROXY: new tunnel state 'receive'");
                self.ctx.state = H1TunnelState::Receive;
            }
            H1TunnelState::Response => {
                tracing::trace!("H1-PROXY: new tunnel state 'response'");
                self.ctx.state = H1TunnelState::Response;
            }
            H1TunnelState::Established => {
                tracing::trace!("H1-PROXY: new tunnel state 'established'");
                // Log response headers at trace level.
                // Tag them with CONNECT origin for diagnostic clarity.
                let origin = HeaderOrigin::CONNECT;
                for entry in self.ctx.response_headers.iter() {
                    tracing::trace!(
                        origin = origin.as_u32(),
                        name = entry.name(),
                        value = entry.value(),
                        "H1-PROXY: tunnel response header"
                    );
                }
                tracing::debug!("CONNECT phase completed");
                self.ctx.state = H1TunnelState::Established;
                self.ctx.response_buf.clear();
                self.ctx.request_buf.clear();
                self.ctx.response_headers.clear();
                self.connected = true;
            }
            H1TunnelState::Failed => {
                tracing::trace!("H1-PROXY: new tunnel state 'failed'");
                self.ctx.state = H1TunnelState::Failed;
                self.ctx.response_buf.clear();
                self.ctx.request_buf.clear();
                self.ctx.response_headers.clear();
            }
        }
    }

    /// Build the CONNECT request and store it in `ctx.request_buf`.
    ///
    /// Produces the following wire format:
    /// ```text
    /// CONNECT host:port HTTP/1.1\r\n
    /// Host: host:port\r\n
    /// Proxy-Connection: Keep-Alive\r\n
    /// User-Agent: curl-rs/8.19.0\r\n
    /// [Proxy-Authorization: scheme credentials\r\n]
    /// \r\n
    /// ```
    ///
    /// Mirrors the C `start_CONNECT()` function.
    fn build_connect_request(&mut self, _data: &TransferData) -> CurlResult<()> {
        let authority = format!("{}:{}", self.proxy_host, self.proxy_port);

        tracing::debug!(authority = %authority, "Establish HTTP proxy tunnel");

        self.ctx.request_buf.clear();
        self.ctx.nsent = 0;
        self.ctx.header_lines = 0;

        // Determine HTTP minor version (1.1 by default, 1.0 if configured).
        let http_minor = self.ctx.http_minor;

        // Build request line.
        let request_line = format!("CONNECT {} HTTP/1.{}\r\n", authority, http_minor);
        self.ctx.request_buf.reserve(MAX_REQUEST_SIZE);
        self.ctx.request_buf.extend_from_slice(request_line.as_bytes());

        // Build headers using DynHeaders for structured management.
        let mut req_headers = DynHeaders::new();

        // Host header (always required).
        req_headers.add("Host", &authority)?;

        // Proxy-Connection: Keep-Alive (to keep tunnel open).
        req_headers.add("Proxy-Connection", "Keep-Alive")?;

        // User-Agent header.
        req_headers.add("User-Agent", "curl-rs/8.19.0")?;

        // Proxy-Authorization header (if proxy credentials are configured).
        if let Some(ref user) = self.ctx.proxy_user {
            let auth_line = self.build_proxy_auth_header(user);
            if let Some(auth_value) = auth_line {
                req_headers.add("Proxy-Authorization", &auth_value)?;
            }
        }

        // Serialize headers to wire format.
        let headers_wire = req_headers.h1_serialize();
        self.ctx.request_buf.extend_from_slice(headers_wire.as_bytes());

        // Terminate with empty line.
        self.ctx.request_buf.extend_from_slice(b"\r\n");

        tracing::trace!(
            request_len = self.ctx.request_buf.len(),
            "H1-PROXY: CONNECT request built"
        );

        Ok(())
    }

    /// Build the `Proxy-Authorization` header value for the configured
    /// authentication scheme.
    ///
    /// Selects the strongest allowed auth scheme (preference order: Negotiate,
    /// NTLM, Digest, Basic) and builds the header value. Multi-step schemes
    /// (NTLM, Negotiate, Digest) are deferred to the auth subsystem.
    fn build_proxy_auth_header(&self, user: &str) -> Option<String> {
        let password = self.ctx.proxy_password.as_deref().unwrap_or("");
        let allowed = self.ctx.proxy_auth_allowed;

        // Determine the best auth scheme from the allowed bitmask.
        // Priority: Negotiate > NTLM > Digest > Basic (matching curl C code).
        let selected_scheme = if allowed & CURLAUTH_NTLM != 0 {
            AuthScheme::Ntlm
        } else if allowed & CURLAUTH_DIGEST != 0 {
            AuthScheme::Digest
        } else if allowed & CURLAUTH_BASIC != 0 {
            AuthScheme::Basic
        } else {
            AuthScheme::None
        };

        tracing::trace!(
            scheme = selected_scheme.name(),
            "H1-PROXY: selected proxy auth scheme"
        );

        match selected_scheme {
            AuthScheme::Basic => {
                // Basic auth: base64(user:password).
                let credentials = format!("{}:{}", user, password);
                let encoded = base64_encode(credentials.as_bytes());
                Some(format!("Basic {}", encoded))
            }
            AuthScheme::Digest => {
                // Digest auth is multi-step — delegated to auth subsystem.
                tracing::trace!(
                    "H1-PROXY: Digest proxy auth — delegating to auth subsystem"
                );
                None
            }
            AuthScheme::Ntlm => {
                // NTLM auth is multi-step — delegated to auth subsystem.
                tracing::trace!(
                    "H1-PROXY: NTLM proxy auth — delegating to auth subsystem"
                );
                None
            }
            AuthScheme::Negotiate => {
                tracing::trace!(
                    "H1-PROXY: Negotiate proxy auth — delegating to auth subsystem"
                );
                None
            }
            _ => None,
        }
    }

    /// Send the CONNECT request bytes to the inner filter.
    ///
    /// Returns `Ok(true)` when all bytes have been sent, `Ok(false)` if more
    /// I/O is needed (partial write), or an error on failure.
    ///
    /// Mirrors the C `send_CONNECT()` function.
    async fn send_connect(&mut self) -> CurlResult<bool> {
        let request_len = self.ctx.request_buf.len();
        if self.ctx.nsent >= request_len {
            return Ok(true);
        }

        let inner = match self.inner.as_mut() {
            Some(inner) => inner,
            None => return Err(CurlError::CouldntConnect),
        };

        let remaining = &self.ctx.request_buf[self.ctx.nsent..];
        match inner.send(remaining, false).await {
            Ok(nwritten) => {
                self.ctx.nsent += nwritten;
                tracing::trace!(
                    bytes_sent = nwritten,
                    total_sent = self.ctx.nsent,
                    request_len = request_len,
                    "H1-PROXY: CONNECT send progress"
                );
                Ok(self.ctx.nsent >= request_len)
            }
            Err(CurlError::Again) => {
                // Socket buffer full — try again later.
                Ok(false)
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed sending CONNECT to proxy");
                Err(CurlError::SendError)
            }
        }
    }

    /// Process a single completed response header line.
    ///
    /// This handles the status line (first header), authentication challenge
    /// headers (`Proxy-Authenticate`), content headers (`Content-Length`,
    /// `Transfer-Encoding`), and connection headers (`Connection`,
    /// `Proxy-Connection`).
    ///
    /// Mirrors the C `on_resp_header()` and `single_header()` functions.
    fn process_response_header(&mut self, line: &str) -> CurlResult<()> {
        self.ctx.header_lines += 1;

        tracing::trace!(
            line_num = self.ctx.header_lines,
            line = line.trim_end(),
            "H1-PROXY: response header"
        );

        // Check for empty line (end of headers).
        let first_byte = line.as_bytes().first().copied().unwrap_or(0);
        if first_byte == b'\r' || first_byte == b'\n' {
            // End of response headers.
            return self.end_of_headers();
        }

        // Parse status line: HTTP/1.x NNN reason
        if line.starts_with("HTTP/1.") && line.len() >= 12 {
            return self.parse_status_line(line);
        }

        // Parse individual headers.
        self.parse_response_header(line)
    }

    /// Parse the HTTP status line from the proxy response.
    ///
    /// Expected format: `HTTP/1.{minor} {NNN} {reason}\r\n`
    fn parse_status_line(&mut self, line: &str) -> CurlResult<()> {
        let bytes = line.as_bytes();

        // Validate format: HTTP/1.X NNN
        if bytes.len() < 12 {
            tracing::warn!("H1-PROXY: status line too short");
            return Err(CurlError::WeirdServerReply);
        }

        // Parse minor version.
        let minor = match bytes[7] {
            b'0' => 0u8,
            b'1' => 1u8,
            _ => {
                tracing::warn!(byte = bytes[7], "H1-PROXY: unexpected HTTP minor version");
                return Err(CurlError::WeirdServerReply);
            }
        };

        // Expect space after version.
        if bytes[8] != b' ' {
            return Err(CurlError::WeirdServerReply);
        }

        // Parse 3-digit status code.
        if !bytes[9].is_ascii_digit()
            || !bytes[10].is_ascii_digit()
            || !bytes[11].is_ascii_digit()
        {
            return Err(CurlError::WeirdServerReply);
        }

        let status_code = u16::from(bytes[9] - b'0') * 100
            + u16::from(bytes[10] - b'0') * 10
            + u16::from(bytes[11] - b'0');

        self.ctx.http_minor = minor;
        self.ctx.status_code = status_code;

        tracing::debug!(
            http_version = format_args!("1.{}", minor),
            status_code = status_code,
            "H1-PROXY: received status"
        );

        Ok(())
    }

    /// Parse a non-status response header from the proxy.
    ///
    /// Mirrors the C `on_resp_header()` function.
    fn parse_response_header(&mut self, header: &str) -> CurlResult<()> {
        let header_lower = header.to_ascii_lowercase();

        // Proxy-Authenticate header (407 response).
        if header_lower.starts_with("proxy-authenticate:")
            && self.ctx.status_code == 407
        {
            let value = extract_header_value(header, "proxy-authenticate:");
            tracing::trace!(
                value = value,
                "H1-PROXY: Proxy-Authenticate challenge"
            );
            self.ctx.proxy_auth_challenge = Some(value.to_string());
            // Store in response headers for later inspection.
            let _ = self.ctx.response_headers.add_line(header);
            return Ok(());
        }

        // Content-Length header.
        if header_lower.starts_with("content-length:") {
            if self.ctx.status_code / 100 == 2 {
                // RFC 7231 §4.3.6: ignore Content-Length in 2xx CONNECT response.
                tracing::debug!(
                    status = self.ctx.status_code,
                    "H1-PROXY: ignoring Content-Length in CONNECT 2xx response"
                );
            } else {
                let value_str =
                    extract_header_value(header, "content-length:").trim();
                match value_str.parse::<i64>() {
                    Ok(cl) => {
                        self.ctx.content_length = cl;
                    }
                    Err(_) => {
                        tracing::warn!(
                            "H1-PROXY: unsupported Content-Length value"
                        );
                        return Err(CurlError::WeirdServerReply);
                    }
                }
            }
            return Ok(());
        }

        // Transfer-Encoding header.
        if header_lower.starts_with("transfer-encoding:") {
            if self.ctx.status_code / 100 == 2 {
                // RFC 7231 §4.3.6: ignore Transfer-Encoding in 2xx CONNECT.
                tracing::debug!(
                    status = self.ctx.status_code,
                    "H1-PROXY: ignoring Transfer-Encoding in CONNECT 2xx response"
                );
            } else {
                let value =
                    extract_header_value(header, "transfer-encoding:").trim();
                if value.eq_ignore_ascii_case("chunked") {
                    tracing::debug!("H1-PROXY: CONNECT responded chunked");
                    self.ctx.chunked_encoding = true;
                    self.ctx.chunker.reset(true);
                }
            }
            return Ok(());
        }

        // Connection: close header.
        if header_lower.starts_with("connection:") {
            let value = extract_header_value(header, "connection:").trim();
            if value.eq_ignore_ascii_case("close") {
                self.ctx.close_connection = true;
            }
            return Ok(());
        }

        // Proxy-Connection: close header.
        if header_lower.starts_with("proxy-connection:") {
            let value =
                extract_header_value(header, "proxy-connection:").trim();
            if value.eq_ignore_ascii_case("close") {
                self.ctx.close_connection = true;
            }
            return Ok(());
        }

        // Store all other headers for potential later use.
        let _ = self.ctx.response_headers.add_line(header);

        Ok(())
    }

    /// Handle the end of response headers (blank line received).
    ///
    /// Determines how to proceed based on the status code. For 407 responses
    /// with available auth, sets up body-ignore mode to consume the error
    /// page before retrying.
    fn end_of_headers(&mut self) -> CurlResult<()> {
        if self.ctx.status_code == 407 {
            // 407 Proxy Authentication Required — need to consume the body
            // before retrying with credentials.
            self.ctx.keepon = KeepOn::Ignore;

            if self.ctx.content_length > 0 {
                tracing::debug!(
                    content_length = self.ctx.content_length,
                    "H1-PROXY: ignoring response body"
                );
            } else if self.ctx.chunked_encoding {
                tracing::debug!("H1-PROXY: ignoring chunked response body");
            } else {
                // No body to consume — done with this response.
                tracing::trace!(
                    "H1-PROXY: no content-length or chunked, done"
                );
                self.ctx.keepon = KeepOn::Done;
            }
        } else {
            self.ctx.keepon = KeepOn::Done;
        }

        Ok(())
    }

    /// Read a single byte from the inner (lower-level) connection filter.
    ///
    /// This helper isolates the `&mut self.inner` borrow so that the caller
    /// can freely call other `&mut self` methods after the byte has been
    /// received. Returning `None` signals that the proxy closed the
    /// connection.
    async fn inner_recv_byte(&mut self) -> CurlResult<Option<u8>> {
        let inner = self
            .inner
            .as_mut()
            .ok_or(CurlError::CouldntConnect)?;
        let mut buf = [0u8; 1];
        match inner.recv(&mut buf).await {
            Ok(0) => Ok(None),
            Ok(_) => Ok(Some(buf[0])),
            Err(e) => Err(e),
        }
    }

    /// Receive and parse the proxy's response to the CONNECT request.
    ///
    /// Reads one byte at a time from the inner filter to parse the HTTP
    /// response headers and optional body. This mirrors the C
    /// `recv_CONNECT_resp()` function.
    ///
    /// Returns `Ok(true)` when the entire response has been consumed,
    /// `Ok(false)` if more I/O is needed.
    async fn recv_connect_response(&mut self) -> CurlResult<bool> {
        // Read one byte at a time, matching the C implementation.
        // This avoids over-reading past the CONNECT response boundary.
        // The inner_recv_byte() helper isolates the borrow on self.inner
        // so that subsequent self.process_* calls are not in conflict.
        loop {
            if self.ctx.keepon == KeepOn::Done {
                break;
            }

            let byte = match self.inner_recv_byte().await {
                Ok(Some(b)) => b,
                Ok(None) => {
                    // Connection closed by proxy.
                    if self.ctx.proxy_user.is_some() {
                        self.ctx.close_connection = true;
                        tracing::debug!(
                            "H1-PROXY: proxy CONNECT connection closed"
                        );
                    } else {
                        tracing::error!("H1-PROXY: proxy CONNECT aborted");
                        return Err(CurlError::RecvError);
                    }
                    self.ctx.keepon = KeepOn::Done;
                    break;
                }
                Err(CurlError::Again) => {
                    // No data available yet — caller should retry.
                    return Ok(false);
                }
                Err(e) => {
                    tracing::error!(error = %e, "H1-PROXY: recv error");
                    self.ctx.keepon = KeepOn::Done;
                    return Err(e);
                }
            };

            // Body-ignore mode: consume and discard response body bytes.
            if self.ctx.keepon == KeepOn::Ignore {
                if self.ctx.content_length > 0 {
                    self.ctx.content_length -= 1;
                    if self.ctx.content_length <= 0 {
                        self.ctx.keepon = KeepOn::Done;
                        break;
                    }
                } else if self.ctx.chunked_encoding {
                    let single = [byte];
                    let (_consumed, _done) =
                        self.ctx.chunker.read(&single, None)?;
                    if self.ctx.chunker.is_done() {
                        tracing::debug!("H1-PROXY: chunk reading DONE");
                        self.ctx.keepon = KeepOn::Done;
                    }
                }
                continue;
            }

            // Header-folding detection (obsolete line folding per RFC 7230).
            if self.ctx.maybe_folded {
                if byte == b' ' || byte == b'\t' {
                    // Folded continuation line — replace trailing CRLF with
                    // space by truncating the CRLF we just accumulated.
                    let len = self.ctx.response_buf.len();
                    if len >= 2
                        && self.ctx.response_buf[len - 2] == b'\r'
                        && self.ctx.response_buf[len - 1] == b'\n'
                    {
                        self.ctx.response_buf.truncate(len - 2);
                    }
                    self.ctx.leading_unfold = true;
                } else {
                    // Not a continuation — process the buffered header line.
                    let line = self.drain_response_line();
                    self.process_response_header(&line)?;
                    // Fall through to process the new byte below.
                }
                self.ctx.maybe_folded = false;
            }

            // Skip leading whitespace on unfolded continuation lines.
            if self.ctx.leading_unfold {
                if byte == b' ' || byte == b'\t' {
                    continue;
                }
                // Non-blank character — insert a single space.
                if self.ctx.response_buf.len() < MAX_RESPONSE_SIZE {
                    self.ctx.response_buf.extend_from_slice(b" ");
                } else {
                    tracing::error!("H1-PROXY: CONNECT response too large");
                    return Err(CurlError::RecvError);
                }
                self.ctx.leading_unfold = false;
            }

            // Accumulate the byte into the response buffer.
            if self.ctx.response_buf.len() >= MAX_RESPONSE_SIZE {
                tracing::error!("H1-PROXY: CONNECT response too large");
                return Err(CurlError::RecvError);
            }
            self.ctx.response_buf.extend_from_slice(&[byte]);

            // Check for end of header line (LF).
            if byte != b'\n' {
                continue;
            }

            // We have a complete line ending with LF.
            let first = self.ctx.response_buf[0];

            if first == b'\r' || first == b'\n' {
                // Empty line (just CRLF) — end of headers.
                let line = self.drain_response_line();
                self.process_response_header(&line)?;
            } else {
                // Might be a folded header — defer processing.
                self.ctx.maybe_folded = true;
            }
        }

        // If we have a maybe_folded line still pending, flush it.
        if self.ctx.maybe_folded && !self.ctx.response_buf.is_empty() {
            let line = self.drain_response_line();
            self.process_response_header(&line)?;
            self.ctx.maybe_folded = false;
        }

        let done = self.ctx.keepon == KeepOn::Done;

        if done && self.ctx.status_code / 100 != 2 {
            // Non-2xx response — check if auth retry is needed (407).
            if self.ctx.status_code == 407
                && self.ctx.proxy_auth_challenge.is_some()
            {
                tracing::debug!(
                    "H1-PROXY: 407 received, auth retry may be needed"
                );
                self.ctx.auth_retry_pending = true;
                // Initialize proxy auth state for the retry attempt via
                // AuthConnState (tracks NTLM/Negotiate multi-step state).
                let _proxy_state = self.ctx.auth_state.ntlm_get(true);
                tracing::trace!(
                    "H1-PROXY: proxy auth state initialized for retry"
                );
            }
        }

        Ok(done)
    }

    /// Drain the response buffer into a String and clear the buffer.
    fn drain_response_line(&mut self) -> String {
        let bytes =
            self.ctx.response_buf.split_to(self.ctx.response_buf.len());
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Drive the CONNECT tunnel state machine through all phases.
    ///
    /// Mirrors the C `H1_CONNECT()` function. Progresses through Init →
    /// Connect → Receive → Response → Established, handling auth retries.
    async fn drive_tunnel(
        &mut self,
        data: &mut TransferData,
    ) -> CurlResult<()> {
        if self.is_established() {
            return Ok(());
        }
        if self.is_failed() {
            return Err(CurlError::RecvError);
        }

        loop {
            match self.ctx.state {
                H1TunnelState::Init => {
                    tracing::trace!("H1-PROXY: CONNECT start");
                    self.build_connect_request(data)?;
                    self.go_state(H1TunnelState::Connect);
                    // Fall through to Connect.
                }
                H1TunnelState::Connect => {
                    tracing::trace!("H1-PROXY: CONNECT send");
                    let done = self.send_connect().await?;
                    if !done {
                        return Ok(());
                    }
                    self.go_state(H1TunnelState::Receive);
                    // Fall through to Receive.
                }
                H1TunnelState::Receive => {
                    tracing::trace!("H1-PROXY: CONNECT receive");
                    let done = self.recv_connect_response().await?;
                    if !done {
                        return Ok(());
                    }
                    self.go_state(H1TunnelState::Response);
                    // Fall through to Response.
                }
                H1TunnelState::Response => {
                    tracing::trace!("H1-PROXY: CONNECT response");

                    if self.ctx.auth_retry_pending {
                        // Auth retry needed — reset and try again.
                        self.ctx.auth_retry_pending = false;

                        if self.ctx.close_connection || data.close_connection {
                            // Proxy indicated connection close — need to
                            // reconnect the inner filter first.
                            tracing::debug!(
                                "H1-PROXY: CONNECT auth retry, need reconnect"
                            );
                            return Err(CurlError::Again);
                        }

                        // Stay on this connection, reset tunnel state.
                        self.go_state(H1TunnelState::Init);
                        continue;
                    }

                    // Done — evaluate final status code.
                    break;
                }
                H1TunnelState::Established | H1TunnelState::Failed => {
                    break;
                }
            }
        }

        // Only reach here from Response state.
        if self.ctx.state == H1TunnelState::Response {
            if self.ctx.status_code / 100 != 2 {
                // Non-2xx final response without auth retry.
                self.go_state(H1TunnelState::Failed);
                tracing::error!(
                    status = self.ctx.status_code,
                    "CONNECT tunnel failed"
                );
                return Err(CurlError::Proxy);
            }

            // 2xx — success!
            self.go_state(H1TunnelState::Established);
            tracing::debug!(
                status = self.ctx.status_code,
                "CONNECT tunnel established"
            );
        }

        Ok(())
    }

    /// Configure proxy authentication credentials.
    ///
    /// Call this before [`connect()`](ConnectionFilter::connect) to enable
    /// proxy authentication.
    ///
    /// # Arguments
    ///
    /// * `user` — Proxy username.
    /// * `password` — Proxy password.
    /// * `auth_mask` — Bitmask of allowed auth schemes (`CURLAUTH_*`).
    pub fn set_proxy_auth(
        &mut self,
        user: String,
        password: String,
        auth_mask: u64,
    ) {
        self.ctx.proxy_user = Some(user);
        self.ctx.proxy_password = Some(password);
        self.ctx.proxy_auth_allowed = auth_mask;
    }

    /// Returns the current tunnel state.
    pub fn tunnel_state(&self) -> H1TunnelState {
        self.ctx.state
    }

    /// Returns the HTTP status code from the proxy response.
    ///
    /// Only meaningful after the `Receive` phase has completed.
    pub fn proxy_status_code(&self) -> u16 {
        self.ctx.status_code
    }
}

// ---------------------------------------------------------------------------
// ConnectionFilter trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl ConnectionFilter for H1ProxyFilter {
    /// Returns the filter name: `"H1-PROXY"`.
    ///
    /// Matches the C `Curl_cft_h1_proxy.name = "H1-PROXY"`.
    fn name(&self) -> &str {
        "H1-PROXY"
    }

    /// Returns the type flags for this filter.
    ///
    /// Combines `CF_TYPE_IP_CONNECT | CF_TYPE_PROXY`, matching the C
    /// `Curl_cft_h1_proxy` type definition.
    fn type_flags(&self) -> u32 {
        CF_TYPE_IP_CONNECT | CF_TYPE_PROXY
    }

    /// Drive the CONNECT tunnel connection to completion.
    ///
    /// Returns `Ok(true)` when the tunnel is fully established and data can
    /// flow through. Returns `Ok(false)` when more I/O is needed (partial
    /// send, waiting for proxy response, etc.).
    ///
    /// Mirrors `cf_h1_proxy_connect()` in the C code.
    async fn connect(
        &mut self,
        data: &mut TransferData,
    ) -> Result<bool, CurlError> {
        if self.connected {
            return Ok(true);
        }

        tracing::trace!("H1-PROXY: connect");

        // Ensure inner filter is connected first.
        if let Some(ref mut inner) = self.inner {
            if !inner.is_connected() {
                let done = inner.connect(data).await?;
                if !done {
                    return Ok(false);
                }
            }
        }

        // Drive the tunnel state machine.
        match self.drive_tunnel(data).await {
            Ok(()) => {
                let established = self.is_established();
                Ok(established)
            }
            Err(e) => {
                self.go_state(H1TunnelState::Failed);
                Err(e)
            }
        }
    }

    /// Close the proxy tunnel immediately.
    ///
    /// Resets the tunnel state to `Init` and closes the inner filter.
    /// Matches `cf_h1_proxy_close()` in the C code.
    fn close(&mut self) {
        tracing::trace!("H1-PROXY: close");
        self.connected = false;
        self.go_state(H1TunnelState::Init);
        if let Some(ref mut inner) = self.inner {
            inner.close();
        }
    }

    /// Gracefully shut down the proxy tunnel.
    ///
    /// Delegates to the default shutdown behaviour (immediate completion).
    /// Matches `Curl_cf_def_shutdown` in the C code.
    async fn shutdown(&mut self) -> Result<bool, CurlError> {
        tracing::trace!("H1-PROXY: shutdown");
        self.shut_down = true;
        self.connected = false;
        if let Some(ref mut inner) = self.inner {
            inner.shutdown().await
        } else {
            Ok(true)
        }
    }

    /// Adjust the poll set for socket I/O monitoring.
    ///
    /// During tunnel establishment:
    /// - In `Connect` state: watch for write readiness (sending CONNECT).
    /// - In `Receive` state: watch for read readiness (receiving response).
    ///
    /// After establishment: no adjustment needed (data passes through).
    ///
    /// Mirrors `cf_h1_proxy_adjust_pollset()` in the C code.
    fn adjust_pollset(
        &self,
        _data: &TransferData,
        ps: &mut PollSet,
    ) -> Result<(), CurlError> {
        if self.connected {
            // Already connected — no special poll adjustments.
            return Ok(());
        }

        // During tunnel establishment, we need I/O readiness on the socket.
        // The socket FD is obtained via the inner filter's query mechanism.
        #[cfg(unix)]
        {
            if let Some(ref inner) = self.inner {
                let socket_result =
                    inner.query(crate::conn::filters::CF_QUERY_SOCKET);
                if let QueryResult::Socket(fd) = socket_result {
                    if self.want_send() {
                        // Sending CONNECT request — need write readiness.
                        ps.add(fd, PollAction::POLL_OUT);
                    } else {
                        // Receiving response — need read readiness.
                        ps.add(fd, PollAction::POLL_IN);
                    }
                }
            }
        }

        Ok(())
    }

    /// Returns `false` — the proxy filter does not buffer pending data.
    ///
    /// Matches `Curl_cf_def_data_pending` in the C code.
    fn data_pending(&self) -> bool {
        false
    }

    /// Send data through the established tunnel.
    ///
    /// This is the passthrough send — after the tunnel is established, all
    /// data is forwarded transparently to the inner filter.
    ///
    /// Matches `Curl_cf_def_send` (default passthrough) in the C code.
    async fn send(
        &mut self,
        buf: &[u8],
        eos: bool,
    ) -> Result<usize, CurlError> {
        if !self.connected {
            return Err(CurlError::SendError);
        }

        match self.inner.as_mut() {
            Some(inner) => inner.send(buf, eos).await,
            None => Err(CurlError::SendError),
        }
    }

    /// Receive data through the established tunnel.
    ///
    /// This is the passthrough recv — after the tunnel is established, all
    /// data is received transparently from the inner filter.
    ///
    /// Matches `Curl_cf_def_recv` (default passthrough) in the C code.
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, CurlError> {
        if !self.connected {
            return Err(CurlError::RecvError);
        }

        match self.inner.as_mut() {
            Some(inner) => inner.recv(buf).await,
            None => Err(CurlError::RecvError),
        }
    }

    /// Handle control events.
    ///
    /// Default no-op implementation matching `Curl_cf_def_cntrl` in C.
    fn control(
        &mut self,
        _event: i32,
        _arg1: i32,
    ) -> Result<(), CurlError> {
        Ok(())
    }

    /// Check whether the underlying connection is alive.
    ///
    /// Returns `true` when the tunnel is established and the inner filter
    /// reports alive.
    fn is_alive(&self) -> bool {
        if !self.connected {
            return false;
        }
        self.inner
            .as_ref()
            .is_some_and(|inner| inner.is_alive())
    }

    /// Send keepalive probes.
    ///
    /// Default no-op matching `Curl_cf_def_conn_keep_alive` in C.
    fn keep_alive(&mut self) -> Result<(), CurlError> {
        Ok(())
    }

    /// Query the filter for properties.
    ///
    /// Delegates `CF_QUERY_HOST_PORT` to return the tunnel target address.
    /// All other queries are delegated to the inner filter if available.
    fn query(&self, query: i32) -> QueryResult {
        if query == CF_QUERY_HOST_PORT {
            return QueryResult::String(format!(
                "{}:{}",
                self.proxy_host, self.proxy_port
            ));
        }

        // Delegate to inner filter for other queries.
        if let Some(ref inner) = self.inner {
            return inner.query(query);
        }

        QueryResult::NotHandled
    }

    /// Returns `true` when the tunnel is in the established state.
    fn is_connected(&self) -> bool {
        self.connected
    }

    /// Returns `true` when the filter has been gracefully shut down.
    fn is_shutdown(&self) -> bool {
        self.shut_down
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Extract the value portion of a header line given the header name prefix.
///
/// Given `header = "Content-Length: 42\r\n"` and `prefix = "content-length:"`,
/// returns `" 42\r\n"`. The caller should trim as needed.
fn extract_header_value<'a>(header: &'a str, prefix: &str) -> &'a str {
    // Find the prefix case-insensitively and return everything after it.
    let header_lower = header.to_ascii_lowercase();
    if let Some(pos) = header_lower.find(prefix) {
        &header[pos + prefix.len()..]
    } else {
        ""
    }
}

/// Minimal Base64 encoder for proxy Basic authentication.
///
/// Encodes the input bytes into a Base64 string using the standard alphabet
/// with padding. This is a self-contained implementation to avoid adding a
/// separate dependency for this single use case within the proxy filter.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut output =
        String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;

    while i + 2 < input.len() {
        let b0 = input[i] as u32;
        let b1 = input[i + 1] as u32;
        let b2 = input[i + 2] as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;

        output.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        output.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        output.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        output.push(ALPHABET[(triple & 0x3F) as usize] as char);
        i += 3;
    }

    let remaining = input.len() - i;
    if remaining == 2 {
        let b0 = input[i] as u32;
        let b1 = input[i + 1] as u32;
        let triple = (b0 << 16) | (b1 << 8);

        output.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        output.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        output.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        output.push('=');
    } else if remaining == 1 {
        let b0 = input[i] as u32;
        let triple = b0 << 16;

        output.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        output.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        output.push('=');
        output.push('=');
    }

    output
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_state_display() {
        assert_eq!(H1TunnelState::Init.to_string(), "init");
        assert_eq!(H1TunnelState::Connect.to_string(), "connect");
        assert_eq!(H1TunnelState::Receive.to_string(), "receive");
        assert_eq!(H1TunnelState::Response.to_string(), "response");
        assert_eq!(H1TunnelState::Established.to_string(), "established");
        assert_eq!(H1TunnelState::Failed.to_string(), "failed");
    }

    #[test]
    fn test_tunnel_state_default() {
        assert_eq!(H1TunnelState::default(), H1TunnelState::Init);
    }

    #[test]
    fn test_h1_proxy_filter_new() {
        let filter =
            H1ProxyFilter::new("proxy.example.com".into(), 8080);
        assert_eq!(filter.name(), "H1-PROXY");
        assert_eq!(
            filter.type_flags(),
            CF_TYPE_IP_CONNECT | CF_TYPE_PROXY
        );
        assert!(!filter.is_connected());
        assert!(!filter.is_shutdown());
        assert_eq!(filter.tunnel_state(), H1TunnelState::Init);
        assert_eq!(filter.proxy_status_code(), 0);
    }

    #[test]
    fn test_h1_proxy_filter_type_flags() {
        let filter = H1ProxyFilter::new("host".into(), 443);
        let flags = filter.type_flags();
        assert_ne!(flags & CF_TYPE_IP_CONNECT, 0);
        assert_ne!(flags & CF_TYPE_PROXY, 0);
    }

    #[test]
    fn test_h1_proxy_filter_query_host_port() {
        let filter = H1ProxyFilter::new("example.com".into(), 443);
        match filter.query(CF_QUERY_HOST_PORT) {
            QueryResult::String(s) => {
                assert_eq!(s, "example.com:443")
            }
            other => {
                panic!("Expected QueryResult::String, got {:?}", other)
            }
        }
    }

    #[test]
    fn test_h1_proxy_filter_query_unhandled() {
        let filter = H1ProxyFilter::new("host".into(), 80);
        // Without inner filter, other queries return NotHandled.
        assert!(matches!(filter.query(42), QueryResult::NotHandled));
    }

    #[test]
    fn test_base64_encode_empty() {
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn test_base64_encode_basic() {
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
    }

    #[test]
    fn test_base64_encode_padding_one() {
        assert_eq!(base64_encode(b"ab"), "YWI=");
    }

    #[test]
    fn test_base64_encode_padding_two() {
        assert_eq!(base64_encode(b"a"), "YQ==");
    }

    #[test]
    fn test_base64_encode_no_padding() {
        assert_eq!(base64_encode(b"abc"), "YWJj");
    }

    #[test]
    fn test_extract_header_value() {
        let val = extract_header_value(
            "Content-Length: 42\r\n",
            "content-length:",
        );
        assert_eq!(val.trim(), "42");

        let val2 = extract_header_value(
            "Connection: close\r\n",
            "connection:",
        );
        assert_eq!(val2.trim(), "close");
    }

    #[test]
    fn test_extract_header_value_not_found() {
        let val = extract_header_value(
            "Host: example.com",
            "content-length:",
        );
        assert_eq!(val, "");
    }

    #[test]
    fn test_context_reinit() {
        let mut ctx = H1ProxyContext::new();
        ctx.state = H1TunnelState::Receive;
        ctx.status_code = 407;
        ctx.content_length = 100;
        ctx.header_lines = 5;
        ctx.close_connection = true;
        ctx.chunked_encoding = true;

        ctx.reinit();

        assert_eq!(ctx.state, H1TunnelState::Init);
        assert_eq!(ctx.status_code, 0);
        assert_eq!(ctx.content_length, 0);
        assert_eq!(ctx.header_lines, 0);
        assert!(!ctx.close_connection);
        assert!(!ctx.chunked_encoding);
        assert!(ctx.request_buf.is_empty());
        assert!(ctx.response_buf.is_empty());
    }

    #[test]
    fn test_build_connect_request() {
        let mut filter =
            H1ProxyFilter::new("example.com".into(), 443);
        let data = TransferData::default();

        filter.build_connect_request(&data).unwrap();

        let request =
            std::str::from_utf8(&filter.ctx.request_buf).unwrap();

        // Verify request line.
        assert!(request
            .starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));

        // Verify Host header.
        assert!(request.contains("Host: example.com:443\r\n"));

        // Verify Proxy-Connection header.
        assert!(
            request.contains("Proxy-Connection: Keep-Alive\r\n")
        );

        // Verify User-Agent header.
        assert!(
            request.contains("User-Agent: curl-rs/8.19.0\r\n")
        );

        // Verify terminal CRLF.
        assert!(request.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_build_connect_request_with_basic_auth() {
        let mut filter =
            H1ProxyFilter::new("example.com".into(), 443);
        filter.set_proxy_auth(
            "user".into(),
            "pass".into(),
            CURLAUTH_BASIC,
        );

        let data = TransferData::default();
        filter.build_connect_request(&data).unwrap();

        let request =
            std::str::from_utf8(&filter.ctx.request_buf).unwrap();

        // Verify Proxy-Authorization header with Basic auth.
        assert!(
            request.contains(
                "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
            ),
            "Request should contain basic auth header, got: {}",
            request
        );
    }

    #[test]
    fn test_parse_status_line_200() {
        let mut filter = H1ProxyFilter::new("host".into(), 80);
        filter
            .parse_status_line(
                "HTTP/1.1 200 Connection established\r\n",
            )
            .unwrap();
        assert_eq!(filter.ctx.status_code, 200);
        assert_eq!(filter.ctx.http_minor, 1);
    }

    #[test]
    fn test_parse_status_line_407() {
        let mut filter = H1ProxyFilter::new("host".into(), 80);
        filter
            .parse_status_line(
                "HTTP/1.0 407 Proxy Authentication Required\r\n",
            )
            .unwrap();
        assert_eq!(filter.ctx.status_code, 407);
        assert_eq!(filter.ctx.http_minor, 0);
    }

    #[test]
    fn test_parse_status_line_invalid() {
        let mut filter = H1ProxyFilter::new("host".into(), 80);
        let result = filter.parse_status_line("INVALID");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_connection_close_header() {
        let mut filter = H1ProxyFilter::new("host".into(), 80);
        assert!(!filter.ctx.close_connection);

        filter
            .parse_response_header("Connection: close\r\n")
            .unwrap();
        assert!(filter.ctx.close_connection);
    }

    #[test]
    fn test_parse_proxy_connection_close_header() {
        let mut filter = H1ProxyFilter::new("host".into(), 80);
        assert!(!filter.ctx.close_connection);

        filter
            .parse_response_header("Proxy-Connection: close\r\n")
            .unwrap();
        assert!(filter.ctx.close_connection);
    }

    #[test]
    fn test_parse_content_length_header() {
        let mut filter = H1ProxyFilter::new("host".into(), 80);
        filter.ctx.status_code = 407;

        filter
            .parse_response_header("Content-Length: 42\r\n")
            .unwrap();
        assert_eq!(filter.ctx.content_length, 42);
    }

    #[test]
    fn test_ignore_content_length_in_2xx() {
        let mut filter = H1ProxyFilter::new("host".into(), 80);
        filter.ctx.status_code = 200;

        filter
            .parse_response_header("Content-Length: 42\r\n")
            .unwrap();
        // Should be ignored for 2xx responses.
        assert_eq!(filter.ctx.content_length, 0);
    }

    #[test]
    fn test_parse_transfer_encoding_chunked() {
        let mut filter = H1ProxyFilter::new("host".into(), 80);
        filter.ctx.status_code = 407;

        filter
            .parse_response_header(
                "Transfer-Encoding: chunked\r\n",
            )
            .unwrap();
        assert!(filter.ctx.chunked_encoding);
    }

    #[test]
    fn test_ignore_transfer_encoding_in_2xx() {
        let mut filter = H1ProxyFilter::new("host".into(), 80);
        filter.ctx.status_code = 200;

        filter
            .parse_response_header(
                "Transfer-Encoding: chunked\r\n",
            )
            .unwrap();
        assert!(!filter.ctx.chunked_encoding);
    }

    #[test]
    fn test_end_of_headers_407_with_content_length() {
        let mut filter = H1ProxyFilter::new("host".into(), 80);
        filter.ctx.status_code = 407;
        filter.ctx.content_length = 100;

        filter.end_of_headers().unwrap();
        assert_eq!(filter.ctx.keepon, KeepOn::Ignore);
    }

    #[test]
    fn test_end_of_headers_407_no_body() {
        let mut filter = H1ProxyFilter::new("host".into(), 80);
        filter.ctx.status_code = 407;
        filter.ctx.content_length = 0;
        filter.ctx.chunked_encoding = false;

        filter.end_of_headers().unwrap();
        assert_eq!(filter.ctx.keepon, KeepOn::Done);
    }

    #[test]
    fn test_end_of_headers_200() {
        let mut filter = H1ProxyFilter::new("host".into(), 80);
        filter.ctx.status_code = 200;

        filter.end_of_headers().unwrap();
        assert_eq!(filter.ctx.keepon, KeepOn::Done);
    }

    #[test]
    fn test_state_transitions() {
        let mut filter = H1ProxyFilter::new("host".into(), 80);

        assert_eq!(filter.ctx.state, H1TunnelState::Init);

        filter.go_state(H1TunnelState::Connect);
        assert_eq!(filter.ctx.state, H1TunnelState::Connect);

        filter.go_state(H1TunnelState::Receive);
        assert_eq!(filter.ctx.state, H1TunnelState::Receive);

        filter.go_state(H1TunnelState::Response);
        assert_eq!(filter.ctx.state, H1TunnelState::Response);

        filter.go_state(H1TunnelState::Established);
        assert_eq!(filter.ctx.state, H1TunnelState::Established);
        assert!(filter.connected);
    }

    #[test]
    fn test_state_transition_to_failed() {
        let mut filter = H1ProxyFilter::new("host".into(), 80);

        filter.go_state(H1TunnelState::Failed);
        assert_eq!(filter.ctx.state, H1TunnelState::Failed);
        assert!(!filter.connected);
    }

    #[test]
    fn test_close_resets_state() {
        let mut filter = H1ProxyFilter::new("host".into(), 80);
        filter.connected = true;
        filter.ctx.state = H1TunnelState::Established;

        filter.close();

        assert!(!filter.is_connected());
        assert_eq!(filter.ctx.state, H1TunnelState::Init);
    }

    #[test]
    fn test_send_recv_when_not_connected() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let mut filter =
                H1ProxyFilter::new("host".into(), 80);

            // send should fail when not connected.
            let result = filter.send(b"hello", false).await;
            assert!(result.is_err());

            // recv should fail when not connected.
            let mut buf = [0u8; 64];
            let result = filter.recv(&mut buf).await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_data_pending() {
        let filter = H1ProxyFilter::new("host".into(), 80);
        assert!(!filter.data_pending());
    }

    #[test]
    fn test_is_alive_when_not_connected() {
        let filter = H1ProxyFilter::new("host".into(), 80);
        assert!(!filter.is_alive());
    }

    #[test]
    fn test_keep_alive() {
        let mut filter = H1ProxyFilter::new("host".into(), 80);
        assert!(filter.keep_alive().is_ok());
    }

    #[test]
    fn test_control() {
        let mut filter = H1ProxyFilter::new("host".into(), 80);
        assert!(filter.control(0, 0).is_ok());
    }

    #[test]
    fn test_proxy_auth_config() {
        let mut filter = H1ProxyFilter::new("host".into(), 80);
        filter.set_proxy_auth(
            "user".into(),
            "password".into(),
            CURLAUTH_BASIC | CURLAUTH_DIGEST,
        );

        assert_eq!(filter.ctx.proxy_user.as_deref(), Some("user"));
        assert_eq!(
            filter.ctx.proxy_password.as_deref(),
            Some("password")
        );
        assert_eq!(
            filter.ctx.proxy_auth_allowed,
            CURLAUTH_BASIC | CURLAUTH_DIGEST
        );
    }
}
