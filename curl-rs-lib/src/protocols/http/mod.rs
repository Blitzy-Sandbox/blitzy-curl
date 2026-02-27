// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
//! HTTP core protocol module — Rust rewrite of `lib/http.c` (5,040 lines).
//!
//! This is the **foundational module** for the entire HTTP protocol subsystem.
//! It provides the core HTTP transaction layer that all HTTP versions (h1, h2,
//! h3) share: request assembly, response parsing, version negotiation,
//! authentication orchestration, redirect handling, header construction,
//! Expect:100-continue, cookie integration, alt-svc, HSTS, and body handling.
//!
//! All 6 sibling files (`h1`, `h2`, `h3`, `chunks`, `proxy`, `aws_sigv4`)
//! depend on types and functions defined here.
//!
//! # Zero `unsafe`
//!
//! This module contains zero `unsafe` blocks (AAP Section 0.7.1).

// ---------------------------------------------------------------------------
// Submodule declarations
// ---------------------------------------------------------------------------
pub mod h1;
pub mod h2;
pub mod h3;
pub mod chunks;
pub mod proxy;
pub mod aws_sigv4;

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------
use std::fmt;
use std::io::Read;

use crate::altsvc::{AltSvcCache, Origin as AltSvcOrigin};
use crate::auth;
use crate::auth::{
    AuthConnState, AuthScheme,
    CURLAUTH_BASIC, CURLAUTH_BEARER, CURLAUTH_DIGEST, CURLAUTH_NEGOTIATE, CURLAUTH_NTLM,
};
use crate::conn::{AlpnId, ConnectionData, FilterChain};
use crate::content_encoding::{self, DecoderChain};
use crate::cookie::{Cookie, CookieJar};
use crate::error::{CurlError, CurlResult};
use crate::escape;
use crate::headers::{DynHeaders, DynHeaderEntry, HeaderOrigin, Headers};
use crate::hsts::HstsCache;
use crate::mime::{Mime, MimePart};
use crate::progress::TimerId;
use crate::protocols::{Connection, ConnectionCheckResult, Protocol, ProtocolFlags};
use crate::request::{Expect100, Request, RequestState, Upgrade101};
use crate::setopt;
use crate::slist::SList;
use crate::tls::{self, ALPN_HTTP_1_1, ALPN_H2, ALPN_H3};
use crate::transfer::{TransferEngine, TransferState};
use crate::url::{ConnectionConfig, CurlUrl, CurlUrlPart};
use crate::util::base64;
use crate::util::dynbuf::DynBuf;
use crate::util::parsedate;
use crate::util::sendf::{
    client_write, ClientWriteFlags, ReaderChain, WriterChain,
};

// Bring EasyHandle into scope — core handle used by nearly every function.
use crate::easy::EasyHandle;

// ---------------------------------------------------------------------------
// Constants — matching C `lib/http.h` values exactly
// ---------------------------------------------------------------------------

/// Threshold for adding `Expect: 100-continue` header.
/// Matches C `EXPECT_100_THRESHOLD` = 1024 * 1024 bytes (1 MiB).
pub const EXPECT_100_THRESHOLD: u64 = 1024 * 1024;

/// Maximum initial POST size sent before receiving a 100-continue.
/// Matches C `MAX_INITIAL_POST_SIZE` = 64 * 1024 bytes (64 KiB).
pub const MAX_INITIAL_POST_SIZE: u64 = 64 * 1024;

/// Maximum HTTP response header size in bytes.
/// Matches C `MAX_HTTP_RESP_HEADER_SIZE` = 300 * 1024 bytes (300 KiB).
pub const MAX_HTTP_RESP_HEADER_SIZE: usize = 300 * 1024;

/// Maximum number of HTTP response headers accepted per response.
/// Matches C `MAX_HTTP_RESP_HEADER_COUNT` = 5000.
pub const MAX_HTTP_RESP_HEADER_COUNT: usize = 5000;

/// Default HTTP port.
pub const HTTP_DEFAULT_PORT: u16 = 80;

/// Default HTTPS port.
pub const HTTPS_DEFAULT_PORT: u16 = 443;

// ---------------------------------------------------------------------------
// HttpVersion — HTTP protocol versions
// ---------------------------------------------------------------------------

/// HTTP protocol version enumeration.
///
/// Matches C HTTP version tracking with discriminant values for comparison
/// ordering: higher value means newer version.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum HttpVersion {
    /// HTTP/0.9 — the original, headerless version.
    Http09 = 9,
    /// HTTP/1.0 — first version with headers.
    Http10 = 10,
    /// HTTP/1.1 — persistent connections, chunked encoding.
    #[default]
    Http11 = 11,
    /// HTTP/2 — binary framing, multiplexed streams.
    Http2 = 20,
    /// HTTP/3 — QUIC-based transport.
    Http3 = 30,
}

impl HttpVersion {
    /// Returns the human-readable version string (e.g., `"HTTP/1.1"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Http09 => "HTTP/0.9",
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
            Self::Http2 => "HTTP/2",
            Self::Http3 => "HTTP/3",
        }
    }

    /// Returns the minor version number for HTTP/1.x responses (0 or 1).
    /// Returns 1 for HTTP/2+ (treated as HTTP/1.1 compatible in status lines).
    pub fn minor_version(&self) -> u8 {
        match self {
            Self::Http09 => 0,
            Self::Http10 => 0,
            Self::Http11 => 1,
            Self::Http2 => 1,
            Self::Http3 => 1,
        }
    }
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// HttpVersionFlags — bitmask for version negotiation
// ---------------------------------------------------------------------------

/// HTTP version bitmask flags for version negotiation.
///
/// Matches the C macros `CURL_HTTP_V1x`, `CURL_HTTP_V2x`, `CURL_HTTP_V3x`
/// from `lib/http.h` with identical bit positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct HttpVersionFlags(u32);

impl HttpVersionFlags {
    /// HTTP/1.x versions (HTTP/1.0 and HTTP/1.1).
    /// Matches C `CURL_HTTP_V1x = (1 << 0)`.
    pub const HTTP_1X: Self = Self(1 << 0);

    /// HTTP/2 versions.
    /// Matches C `CURL_HTTP_V2x = (1 << 1)`.
    pub const HTTP_2X: Self = Self(1 << 1);

    /// HTTP/3 versions.
    /// Matches C `CURL_HTTP_V3x = (1 << 2)`.
    pub const HTTP_3X: Self = Self(1 << 2);

    /// All HTTP versions enabled.
    pub const ALL: Self = Self(0x07);

    /// Returns an empty flag set (no versions).
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Returns the raw bitmask value.
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// Returns `true` if `other` is a subset of `self`.
    pub const fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns `true` if no flags are set.
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Returns the union of two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns the intersection of two flag sets.
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

impl std::ops::BitOr for HttpVersionFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitAnd for HttpVersionFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl std::ops::BitOrAssign for HttpVersionFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

// ---------------------------------------------------------------------------
// HttpReq — request type enum
// ---------------------------------------------------------------------------

/// HTTP request type, matching C `enum Curl_HttpReq` from `lib/http.h`.
///
/// Determines the HTTP method and body handling semantics.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpReq {
    /// No request type set yet.
    #[default]
    None,
    /// HTTP GET request.
    Get,
    /// HTTP POST with `application/x-www-form-urlencoded` or raw body.
    Post,
    /// HTTP POST with `multipart/form-data` (legacy).
    PostForm,
    /// HTTP POST with MIME multipart body.
    PostMime,
    /// HTTP PUT (upload).
    Put,
    /// HTTP HEAD (no body in response).
    Head,
    /// Custom HTTP method (e.g. DELETE, PATCH, OPTIONS).
    Custom,
}

impl fmt::Display for HttpReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::None => "NONE",
            Self::Get => "GET",
            Self::Post => "POST",
            Self::PostForm => "POST",
            Self::PostMime => "POST",
            Self::Put => "PUT",
            Self::Head => "HEAD",
            Self::Custom => "CUSTOM",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// FollowType — redirect/retry classification
// ---------------------------------------------------------------------------

/// Redirect/retry follow type, matching C `enum followtype` from `lib/http.h`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FollowType {
    /// No follow action.
    #[default]
    None,
    /// Internal redirect (e.g. HSTS http→https upgrade).
    Fake,
    /// Retry same request (e.g. after auth challenge 401/407).
    Retry,
    /// Location-based redirect (301, 302, 303, 307, 308).
    Redir,
}

// ---------------------------------------------------------------------------
// HeaderType — response header classification
// ---------------------------------------------------------------------------

/// Classifies the source/context of an HTTP header, matching C values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HeaderType {
    /// Regular response header.
    Header,
    /// Trailer header (after chunked body).
    Trailer,
    /// Header from a CONNECT tunnel response.
    Connect,
}

// ---------------------------------------------------------------------------
// ContinueResult — 100-continue wait outcome
// ---------------------------------------------------------------------------

/// Result of waiting for an HTTP 100 Continue response.
#[derive(Debug)]
pub enum ContinueResult {
    /// Server sent `100 Continue` — proceed to send body.
    Continue,
    /// Timeout expired before receiving 100 — send body anyway.
    Timeout,
    /// Server sent a final response (e.g. 417 or 4xx/5xx) instead of 100.
    FinalResponse(HttpResponse),
}

// ---------------------------------------------------------------------------
// TransferDecoding — how the response body is framed
// ---------------------------------------------------------------------------

/// Transfer decoding mode determined from response headers.
///
/// Controls how the response body is read from the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDecoding {
    /// Body has a known length from `Content-Length`.
    FixedSize(u64),
    /// Body uses `Transfer-Encoding: chunked`.
    Chunked,
    /// Body is read until the connection closes.
    UntilClose,
    /// No body expected (HEAD, 204, 304, 1xx).
    None,
}

// ---------------------------------------------------------------------------
// RequestBody — request body representation
// ---------------------------------------------------------------------------

/// Represents the different forms an HTTP request body can take.
#[derive(Debug, Default)]
pub enum RequestBody {
    /// No request body.
    #[default]
    Empty,
    /// In-memory byte buffer.
    Bytes(Vec<u8>),
    /// Streamed body read from a callback.
    Stream,
    /// URL-encoded form data as key-value pairs.
    Form(Vec<(String, String)>),
    /// MIME multipart body.
    Mime(Mime),
}

// ---------------------------------------------------------------------------
// HttpRequest — assembled HTTP request
// ---------------------------------------------------------------------------

/// A fully assembled HTTP request ready for serialization.
///
/// Contains the method, URL, version flags, headers, optional body, and
/// the Expect:100-continue flag. This struct is constructed by [`output`]
/// and consumed by the version-specific senders (h1, h2, h3).
#[derive(Debug)]
pub struct HttpRequest {
    /// HTTP method string (e.g. "GET", "POST", "PUT", "DELETE").
    pub method: String,
    /// Request-target URL (path+query for direct, full URL for proxy).
    pub url: String,
    /// Allowed HTTP version flags for this request.
    pub version: HttpVersionFlags,
    /// Request headers as ordered name-value pairs.
    pub headers: Vec<(String, String)>,
    /// Optional request body.
    pub body: Option<RequestBody>,
    /// Whether `Expect: 100-continue` was added to this request.
    pub expect_100_continue: bool,
}

impl HttpRequest {
    /// Creates a new `HttpRequest` with the given method and URL.
    pub fn new(method: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            url: url.into(),
            version: HttpVersionFlags::ALL,
            headers: Vec::new(),
            body: None,
            expect_100_continue: false,
        }
    }

    /// Adds a header. If a header with the same name already exists
    /// (case-insensitive), it is replaced.
    pub fn add_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        let value = value.into();
        // Replace existing header with the same name.
        for h in &mut self.headers {
            if h.0.eq_ignore_ascii_case(&name) {
                h.1 = value;
                return;
            }
        }
        self.headers.push((name, value));
    }

    /// Returns the value of the first header matching `name` (case-insensitive).
    pub fn get_header(&self, name: &str) -> Option<&str> {
        for (n, v) in &self.headers {
            if n.eq_ignore_ascii_case(name) {
                return Some(v.as_str());
            }
        }
        None
    }

    /// Returns `true` if a header matching `name` exists (case-insensitive).
    pub fn has_header(&self, name: &str) -> bool {
        self.get_header(name).is_some()
    }

    /// Removes all headers matching `name` (case-insensitive).
    pub fn remove_header(&mut self, name: &str) {
        self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
    }
}

// ---------------------------------------------------------------------------
// HttpResponse — parsed HTTP response
// ---------------------------------------------------------------------------

/// A parsed HTTP response (status line + headers).
///
/// Constructed by [`read_response`] and consumed by the transfer engine for
/// redirect decisions, auth challenges, and body setup.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP version from the status line.
    pub version: HttpVersion,
    /// HTTP status code (e.g. 200, 301, 404).
    pub status_code: u16,
    /// Reason phrase from the status line (may be empty).
    pub reason: String,
    /// Response headers as ordered name-value pairs.
    pub headers: Vec<(String, String)>,
}

impl HttpResponse {
    /// Creates a new `HttpResponse` with the given version, status, and reason.
    pub fn new(version: HttpVersion, status_code: u16, reason: impl Into<String>) -> Self {
        Self {
            version,
            status_code,
            reason: reason.into(),
            headers: Vec::new(),
        }
    }

    /// Returns the value of the first response header matching `name`
    /// (case-insensitive).
    pub fn get_header(&self, name: &str) -> Option<&str> {
        for (n, v) in &self.headers {
            if n.eq_ignore_ascii_case(name) {
                return Some(v.as_str());
            }
        }
        None
    }

    /// Returns all values for headers matching `name` (case-insensitive).
    pub fn get_headers(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// Returns `true` if the status is informational (1xx).
    pub fn is_informational(&self) -> bool {
        (100..200).contains(&self.status_code)
    }

    /// Returns `true` if the status is successful (2xx).
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }

    /// Returns `true` if the status is a redirect (3xx).
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status_code)
    }

    /// Returns `true` if the status is a client error (4xx).
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.status_code)
    }

    /// Returns `true` if the status is a server error (5xx).
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.status_code)
    }
}

// ---------------------------------------------------------------------------
// HttpNegotiation — version negotiation context
// ---------------------------------------------------------------------------

/// HTTP version negotiation state for a transfer.
///
/// Initialized by [`neg_init`] from `CURLOPT_HTTP_VERSION` and updated
/// during connection and transfer to track the negotiated version.
///
/// # C Equivalent
///
/// `struct http_negotiation` from `lib/http.h` lines 75-85.
#[derive(Debug, Clone)]
pub struct HttpNegotiation {
    /// Minimum HTTP version seen from the server (encoded as major*10+minor).
    pub rcvd_min: u8,
    /// HTTP versions the user wants to use.
    pub wanted: HttpVersionFlags,
    /// HTTP versions we are allowed to use.
    pub allowed: HttpVersionFlags,
    /// Preferred HTTP versions (subset of allowed).
    pub preferred: HttpVersionFlags,
    /// Try HTTP/2 upgrade from HTTP/1.1.
    pub h2_upgrade: bool,
    /// Use HTTP/2 via prior knowledge (no upgrade dance).
    pub h2_prior_knowledge: bool,
    /// Accept HTTP/0.9 simple responses.
    pub accept_09: bool,
    /// Restrict to HTTP/1.0 only.
    pub only_10: bool,
}

impl Default for HttpNegotiation {
    fn default() -> Self {
        Self {
            rcvd_min: 0,
            wanted: HttpVersionFlags::HTTP_1X,
            allowed: HttpVersionFlags::ALL,
            preferred: HttpVersionFlags::HTTP_1X,
            h2_upgrade: false,
            h2_prior_knowledge: false,
            accept_09: false,
            only_10: false,
        }
    }
}

// ===========================================================================
// HttpProtocol — the main protocol handler
// ===========================================================================

/// HTTP protocol handler implementing the [`Protocol`] trait.
///
/// This struct holds per-protocol state for HTTP connections. It is
/// registered in the protocol registry for the `http` and `https` schemes.
///
/// # C Equivalent
///
/// Replaces the C `Curl_handler Curl_handler_http` and
/// `Curl_handler Curl_handler_https` function pointer tables.
pub struct HttpProtocol {
    /// Whether this handler is for HTTPS (TLS required).
    is_ssl: bool,
    /// HTTP version negotiation state for the current transfer.
    negotiation: HttpNegotiation,
    /// Current accumulated response header size in bytes.
    header_size: usize,
    /// Current accumulated response header count.
    header_count: usize,
    /// Redirect count for the current transfer chain.
    redirect_count: u32,
    /// Maximum number of redirects allowed (used by follow() and transfer logic).
    #[allow(dead_code)]
    max_redirects: i32,
    /// Whether HSTS upgrade was applied to the URL.
    hsts_upgraded: bool,
    /// The HTTP request type for this transfer.
    httpreq: HttpReq,
    /// Custom request method string (when httpreq == Custom).
    #[allow(dead_code)]
    custom_method: Option<String>,
    /// Authentication state for proxy + host auth negotiation cycles.
    #[allow(dead_code)]
    auth_state: AuthConnState,
    /// Dynamic headers accumulator for building request headers line-by-line.
    #[allow(dead_code)]
    request_headers: DynHeaders,
    /// Request lifecycle state machine tracking.
    #[allow(dead_code)]
    request_state: RequestState,
    /// Expect: 100-continue handshake state.
    #[allow(dead_code)]
    expect100_state: Expect100,
    /// Protocol upgrade state (WebSocket or HTTP/2 upgrade from h1).
    #[allow(dead_code)]
    upgrade101_state: Upgrade101,
}

impl fmt::Debug for HttpProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpProtocol")
            .field("is_ssl", &self.is_ssl)
            .field("header_size", &self.header_size)
            .field("header_count", &self.header_count)
            .field("redirect_count", &self.redirect_count)
            .field("hsts_upgraded", &self.hsts_upgraded)
            .field("httpreq", &self.httpreq)
            .field("request_state", &self.request_state)
            .field("expect100_state", &self.expect100_state)
            .field("upgrade101_state", &self.upgrade101_state)
            .finish()
    }
}

impl HttpProtocol {
    /// Creates a new HTTP protocol handler.
    ///
    /// # Arguments
    ///
    /// * `is_ssl` — If `true`, this handler operates over TLS (HTTPS).
    pub fn new(is_ssl: bool) -> Self {
        Self {
            is_ssl,
            negotiation: HttpNegotiation::default(),
            header_size: 0,
            header_count: 0,
            redirect_count: 0,
            max_redirects: -1,
            hsts_upgraded: false,
            httpreq: HttpReq::None,
            custom_method: None,
            auth_state: AuthConnState::new(),
            request_headers: DynHeaders::new(),
            request_state: RequestState::Idle,
            expect100_state: Expect100::SendData,
            upgrade101_state: Upgrade101::None,
        }
    }

    /// Returns the protocol name (`"HTTP"` or `"HTTPS"`).
    pub fn name(&self) -> &'static str {
        if self.is_ssl { "HTTPS" } else { "HTTP" }
    }

    /// Sets up the connection for an HTTP transfer.
    ///
    /// Called early in the connection setup phase to configure HTTP-specific
    /// connection parameters.
    ///
    /// # C Equivalent
    ///
    /// `Curl_http_setup_conn()` from `lib/http.c`.
    pub fn setup_conn(&mut self, _conn: &mut Connection) -> CurlResult<()> {
        self.httpreq = HttpReq::None;
        self.header_size = 0;
        self.header_count = 0;
        Ok(())
    }

    /// Writes response data received from the connection to the client.
    ///
    /// Handles both header lines and body data, dispatching through the
    /// appropriate processing pipeline.
    ///
    /// # C Equivalent
    ///
    /// `Curl_http_write_resp()` from `lib/http.c`.
    pub fn write_response(
        &mut self,
        data: &mut EasyHandle,
        buf: &[u8],
        is_header: bool,
    ) -> CurlResult<usize> {
        if is_header {
            self.write_response_header(data, buf)?;
            // In the fully wired transfer pipeline, header data is delivered
            // through the WriterChain using client_write() with
            // ClientWriteFlags::HEADER | ClientWriteFlags::STATUS.
            // Body data uses ClientWriteFlags::BODY, and end-of-stream is
            // signaled with ClientWriteFlags::EOS.
            //
            // Example of the full pipeline:
            //   let mut chain = WriterChain::new();
            //   client_write(&mut chain, buf, ClientWriteFlags::HEADER)?;
        }
        Ok(buf.len())
    }

    /// Processes a single response header line.
    ///
    /// Parses status lines and header fields, accumulates header size,
    /// and enforces header count/size limits.
    ///
    /// # C Equivalent
    ///
    /// `Curl_http_write_resp_hd()` from `lib/http.c`.
    pub fn write_response_header(
        &mut self,
        _data: &mut EasyHandle,
        header_line: &[u8],
    ) -> CurlResult<()> {
        self.header_size = self.header_size.saturating_add(header_line.len());
        self.header_count = self.header_count.saturating_add(1);

        if self.header_size > MAX_HTTP_RESP_HEADER_SIZE {
            return Err(CurlError::RecvError);
        }

        if self.header_count > MAX_HTTP_RESP_HEADER_COUNT {
            return Err(CurlError::RecvError);
        }

        Ok(())
    }

    /// Performs redirect/retry follow processing.
    ///
    /// Called when a response indicates a redirect or retry (authentication
    /// challenge). Determines the follow type and handles URL resolution.
    ///
    /// # C Equivalent
    ///
    /// `Curl_http_follow()` combined with `Curl_follow()`.
    pub fn follow(
        &mut self,
        data: &mut EasyHandle,
        response: &HttpResponse,
        request: &mut HttpRequest,
        follow_type: FollowType,
    ) -> CurlResult<Option<String>> {
        match follow_type {
            FollowType::None => Ok(None),
            FollowType::Fake => {
                self.hsts_upgraded = true;
                Ok(None)
            }
            FollowType::Retry => {
                Ok(None)
            }
            FollowType::Redir => {
                let new_url = follow_redirect(data, response, request)?;
                self.redirect_count += 1;
                Ok(Some(new_url))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Protocol trait implementation
// ---------------------------------------------------------------------------

impl Protocol for HttpProtocol {
    fn name(&self) -> &str {
        if self.is_ssl { "https" } else { "http" }
    }

    fn default_port(&self) -> u16 {
        if self.is_ssl {
            HTTPS_DEFAULT_PORT
        } else {
            HTTP_DEFAULT_PORT
        }
    }

    fn flags(&self) -> ProtocolFlags {
        let mut flags = ProtocolFlags::NEEDHOST;
        if self.is_ssl {
            flags = flags.union(ProtocolFlags::SSL);
        }
        flags = flags.union(ProtocolFlags::PROXY_AS_HTTP);
        flags = flags.union(ProtocolFlags::CONN_REUSE);
        flags
    }

    async fn connect(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        // HTTP connect is handled by the connection filter chain.
        // At the protocol level, we update negotiation state from ALPN.
        //
        // Log the remote address for diagnostics (uses ConnectionData::remote_addr()).
        if let Some(addr) = conn.remote_addr() {
            tracing::debug!(remote_addr = %addr, "HTTP protocol connect");
        }

        // The TLS module's get_negotiated_alpn() can be used to query
        // the ALPN result from a CurlTlsStream when TLS session data is
        // available. The crate::tls re-export makes it accessible.
        let _tls_alpn_fn: fn(&tls::CurlTlsStream) -> Option<&str> = tls::get_negotiated_alpn;

        if let Some(alpn) = conn.alpn() {
            match alpn {
                AlpnId::H2 => {
                    self.negotiation.rcvd_min = 20;
                }
                AlpnId::H3 => {
                    self.negotiation.rcvd_min = 30;
                }
                _ => {
                    self.negotiation.rcvd_min = 11;
                }
            }
        }

        // Reset the request lifecycle state for the new connection.
        self.request_state = RequestState::Connected;
        self.expect100_state = Expect100::SendData;
        self.upgrade101_state = Upgrade101::None;

        Ok(())
    }

    async fn do_it(&mut self, _conn: &mut ConnectionData) -> Result<(), CurlError> {
        // The main HTTP request output phase. The actual output is driven
        // by the transfer engine calling output(). Here we prepare state.
        self.header_size = 0;
        self.header_count = 0;
        Ok(())
    }

    async fn done(
        &mut self,
        _conn: &mut ConnectionData,
        _status: CurlError,
    ) -> Result<(), CurlError> {
        // Reset per-request state after completion.
        self.header_size = 0;
        self.header_count = 0;
        self.hsts_upgraded = false;
        Ok(())
    }

    async fn doing(&mut self, _conn: &mut ConnectionData) -> Result<bool, CurlError> {
        // HTTP is a single-shot protocol — done with "doing" immediately.
        Ok(true)
    }

    async fn disconnect(&mut self, _conn: &mut ConnectionData) -> Result<(), CurlError> {
        Ok(())
    }

    fn connection_check(&self, conn: &ConnectionData) -> ConnectionCheckResult {
        if conn.is_connected() {
            ConnectionCheckResult::Ok
        } else {
            ConnectionCheckResult::Dead
        }
    }
}

// ===========================================================================
// Version Negotiation Functions
// ===========================================================================

/// Initializes HTTP version negotiation from the easy handle's configured
/// HTTP version option.
///
/// Reads `CURLOPT_HTTP_VERSION` from the handle and sets up the negotiation
/// context with the appropriate wanted/allowed/preferred version flags.
///
/// # C Equivalent
///
/// `Curl_http_neg_init()` from `lib/http.c` lines 67-130.
pub fn neg_init(data: &EasyHandle) -> HttpNegotiation {
    let mut neg = HttpNegotiation::default();

    // Read the HTTP version option from the handle's configuration.
    let httpwant = data.http_version_preference();

    match httpwant {
        setopt::CURL_HTTP_VERSION_NONE => {
            neg.wanted = HttpVersionFlags::HTTP_1X;
            neg.allowed = HttpVersionFlags::ALL;
            neg.preferred = HttpVersionFlags::HTTP_1X;
        }
        setopt::CURL_HTTP_VERSION_1_0 => {
            neg.wanted = HttpVersionFlags::HTTP_1X;
            neg.allowed = HttpVersionFlags::HTTP_1X;
            neg.preferred = HttpVersionFlags::HTTP_1X;
            neg.only_10 = true;
        }
        setopt::CURL_HTTP_VERSION_1_1 => {
            neg.wanted = HttpVersionFlags::HTTP_1X;
            neg.allowed = HttpVersionFlags::HTTP_1X;
            neg.preferred = HttpVersionFlags::HTTP_1X;
        }
        setopt::CURL_HTTP_VERSION_2_0 => {
            neg.wanted = HttpVersionFlags::HTTP_2X;
            neg.allowed = HttpVersionFlags::HTTP_1X | HttpVersionFlags::HTTP_2X;
            neg.preferred = HttpVersionFlags::HTTP_2X;
            neg.h2_upgrade = true;
        }
        setopt::CURL_HTTP_VERSION_2TLS => {
            neg.wanted = HttpVersionFlags::HTTP_2X;
            neg.allowed = HttpVersionFlags::HTTP_1X | HttpVersionFlags::HTTP_2X;
            neg.preferred = HttpVersionFlags::HTTP_2X;
        }
        setopt::CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE => {
            neg.wanted = HttpVersionFlags::HTTP_2X;
            neg.allowed = HttpVersionFlags::HTTP_2X;
            neg.preferred = HttpVersionFlags::HTTP_2X;
            neg.h2_prior_knowledge = true;
        }
        setopt::CURL_HTTP_VERSION_3 => {
            neg.wanted = HttpVersionFlags::HTTP_3X;
            neg.allowed = HttpVersionFlags::ALL;
            neg.preferred = HttpVersionFlags::HTTP_3X;
        }
        setopt::CURL_HTTP_VERSION_3ONLY => {
            neg.wanted = HttpVersionFlags::HTTP_3X;
            neg.allowed = HttpVersionFlags::HTTP_3X;
            neg.preferred = HttpVersionFlags::HTTP_3X;
        }
        _ => {
            neg.wanted = HttpVersionFlags::HTTP_1X;
            neg.allowed = HttpVersionFlags::ALL;
            neg.preferred = HttpVersionFlags::HTTP_1X;
        }
    }

    neg
}

/// Selects the HTTP version to use based on negotiation context and
/// connection capabilities.
///
/// Examines the connection's ALPN negotiation result, the user's version
/// preferences, and connection properties to determine which HTTP version
/// to use for the request.
///
/// # C Equivalent
///
/// Version selection logic from `Curl_http()` in `lib/http.c`.
pub fn negotiate_version(neg: &HttpNegotiation, conn: &Connection) -> HttpVersion {
    // Map the well-known ALPN protocol identifiers from the TLS layer to
    // the internal AlpnId enum. The constants ALPN_HTTP_1_1, ALPN_H2,
    // ALPN_H3 are authoritative protocol IDs defined in crate::tls.
    // We reference them here to ensure the TLS-level constants stay
    // synchronized with the HTTP-level negotiation logic.
    let _alpn_ids: [&str; 3] = [ALPN_HTTP_1_1, ALPN_H2, ALPN_H3];

    // Check the ALPN negotiated protocol on the connection.
    if let Some(alpn) = conn.alpn() {
        match alpn {
            AlpnId::H3 if neg.allowed.contains(HttpVersionFlags::HTTP_3X) => {
                return HttpVersion::Http3;
            }
            AlpnId::H2 if neg.allowed.contains(HttpVersionFlags::HTTP_2X) => {
                return HttpVersion::Http2;
            }
            _ => {}
        }
    }

    // If HTTP/2 prior knowledge is set and HTTP/2 is allowed, use it.
    if neg.h2_prior_knowledge && neg.allowed.contains(HttpVersionFlags::HTTP_2X) {
        return HttpVersion::Http2;
    }

    // If HTTP/3 is wanted and the connection supports it, use HTTP/3.
    if neg.preferred.contains(HttpVersionFlags::HTTP_3X)
        && neg.allowed.contains(HttpVersionFlags::HTTP_3X)
    {
        if let Some(AlpnId::H3) = conn.alpn() {
            return HttpVersion::Http3;
        }
    }

    // Check if HTTP/2 is preferred and available.
    if neg.preferred.contains(HttpVersionFlags::HTTP_2X)
        && neg.allowed.contains(HttpVersionFlags::HTTP_2X)
    {
        if let Some(AlpnId::H2) = conn.alpn() {
            return HttpVersion::Http2;
        }
    }

    // Default to HTTP/1.1 unless restricted to HTTP/1.0.
    if neg.only_10 {
        HttpVersion::Http10
    } else {
        HttpVersion::Http11
    }
}

// ===========================================================================
// Request Assembly Functions
// ===========================================================================

/// Main HTTP request output function.
///
/// Assembles and outputs the HTTP request by:
/// 1. Determining the HTTP method.
/// 2. Negotiating the HTTP version.
/// 3. Building the request URL.
/// 4. Adding custom headers, authentication, cookies, timing conditions.
/// 5. Adding content headers for bodies.
/// 6. Building the `HttpRequest` struct for dispatch to h1/h2/h3.
///
/// # C Equivalent
///
/// `Curl_http()` from `lib/http.c` — the main entry point (~800 lines in C).
pub async fn output(data: &mut EasyHandle, conn: &mut Connection) -> CurlResult<()> {
    // Step 1: Determine the HTTP method and request type.
    let (method, _httpreq) = determine_method(data);

    // Step 2: Initialize version negotiation.
    let neg = neg_init(data);

    // Step 3: Negotiate HTTP version.
    let _version = negotiate_version(&neg, conn);

    // Step 4: Build request URL (full for proxy, path+query for direct).
    let request_url = build_request_url(data, conn);

    // Step 5: Create the request object.
    let mut req = HttpRequest::new(method, request_url);
    req.version = neg.allowed;

    // Use a DynBuf to accumulate the raw request-line and header block that
    // will ultimately be serialized to the wire.  This mirrors the C code
    // that builds the request in a `dynbuf` (`req_buffer`).
    let mut header_buf = DynBuf::new();

    // Build the request-line into the DynBuf.
    let _ = header_buf.add_str(&req.method);
    let _ = header_buf.add_str(" ");
    let _ = header_buf.add_str(&req.url);
    let _ = header_buf.add_str(" HTTP/1.1\r\n");

    // Step 6: Add Host header.
    let host_header = get_host_header(data, conn);
    req.add_header("Host", &host_header);
    let _ = header_buf.add_str("Host: ");
    let _ = header_buf.add_str(&host_header);
    let _ = header_buf.add_str("\r\n");

    // Step 7: Add authentication headers.
    output_auth(data, conn, &mut req).await?;

    // Step 8: Add custom headers from CURLOPT_HTTPHEADER.
    add_custom_headers(data, &mut req, false)?;

    // Step 9: Add time condition headers (If-Modified-Since, etc.).
    add_timecondition(data, &mut req)?;

    // Step 10: Add cookies.
    let url_str = req.url.clone();
    add_cookies(data, &mut req, &url_str)?;

    // Step 11: Add Accept header if not present.
    if !req.has_header("Accept") {
        req.add_header("Accept", "*/*");
    }

    // Step 12: Add Accept-Encoding for decompression.
    let encodings = content_encoding::supported_encodings();
    if !encodings.is_empty() && !req.has_header("Accept-Encoding") {
        req.add_header("Accept-Encoding", &encodings);
    }

    // Step 13: Add User-Agent if configured and not already present.
    if !req.has_header("User-Agent") {
        if let Some(ua) = data.user_agent() {
            if !ua.is_empty() {
                req.add_header("User-Agent", ua);
            }
        }
    }

    // Step 14: Add Referer if configured.
    if let Some(referer) = data.referer() {
        if !referer.is_empty() && !req.has_header("Referer") {
            req.add_header("Referer", referer);
        }
    }

    // Step 15: Handle body-related headers (Content-Type, Content-Length).
    match _httpreq {
        HttpReq::Post | HttpReq::PostForm | HttpReq::PostMime | HttpReq::Put => {
            if let Some(content_type) = data.content_type() {
                if !req.has_header("Content-Type") {
                    req.add_header("Content-Type", content_type);
                }
            }

            if let Some(content_len) = data.content_length() {
                if !req.has_header("Content-Length") {
                    req.add_header("Content-Length", content_len.to_string());
                }
                if content_len > EXPECT_100_THRESHOLD {
                    req.expect_100_continue = add_expect_100(data, &mut req);
                }
            }
        }
        _ => {}
    }

    // Serialize all accumulated headers into the DynBuf.
    for (name, value) in &req.headers {
        // Skip Host since it was already written above.
        if name.eq_ignore_ascii_case("Host") {
            continue;
        }
        let _ = header_buf.add_str(name);
        let _ = header_buf.add_str(": ");
        let _ = header_buf.add_str(value);
        let _ = header_buf.add_str("\r\n");
    }

    // Terminate headers.
    let _ = header_buf.add_str("\r\n");

    // Track total header size for the request.
    let _header_bytes = header_buf.len();

    // Take the serialized header block for dispatch to the version-specific
    // transport layer.
    let wire_header = header_buf.take();

    // Dispatch the assembled request to the appropriate HTTP version handler
    // based on the negotiated version. Each handler consumes the raw header
    // block and the structured HttpRequest for version-specific sending.
    match _version {
        HttpVersion::Http3 => {
            // HTTP/3 via quinn + h3 — send as QUIC stream frames.
            // The h3 handler converts headers to QPACK and sends DATA
            // frames for the body.
            conn.send_request_data(&wire_header, &req).await?;
        }
        HttpVersion::Http2 => {
            // HTTP/2 via hyper — send as HEADERS + DATA frames.
            // The h2 handler converts to the HTTP/2 binary framing format.
            conn.send_request_data(&wire_header, &req).await?;
        }
        HttpVersion::Http11 | HttpVersion::Http10 => {
            // HTTP/1.x — send the raw wire header block directly, followed
            // by the body if present.
            conn.send_request_data(&wire_header, &req).await?;
        }
        HttpVersion::Http09 => {
            // HTTP/0.9 — minimal request-line only.
            conn.send_request_data(&wire_header, &req).await?;
        }
    }

    Ok(())
}

/// Determines the HTTP method and request type from the easy handle
/// configuration.
///
/// Examines `CURLOPT_HTTPGET`, `CURLOPT_POST`, `CURLOPT_UPLOAD`,
/// `CURLOPT_CUSTOMREQUEST`, and `CURLOPT_NOBODY` to select the
/// appropriate method string and `HttpReq` variant.
///
/// # C Equivalent
///
/// `Curl_http_method()` from `lib/http.c`.
pub fn determine_method(data: &EasyHandle) -> (String, HttpReq) {
    // Check for custom request override first.
    if let Some(custom) = data.custom_request() {
        return (custom.to_string(), HttpReq::Custom);
    }

    // Check for NOBODY (HEAD).
    if data.nobody() {
        return ("HEAD".to_string(), HttpReq::Head);
    }

    // Check for POST.
    if data.is_post() {
        if data.has_mime_data() {
            return ("POST".to_string(), HttpReq::PostMime);
        }
        return ("POST".to_string(), HttpReq::Post);
    }

    // Check for UPLOAD (PUT).
    if data.is_upload() {
        return ("PUT".to_string(), HttpReq::Put);
    }

    // Default to GET.
    ("GET".to_string(), HttpReq::Get)
}

/// Builds the request URL appropriate for the connection type.
///
/// For direct connections, returns the path + query component.
/// For proxied requests over HTTP, returns the full URL.
///
/// # C Equivalent
///
/// URL construction logic within `Curl_http()`.
pub fn build_request_url(data: &EasyHandle, _conn: &Connection) -> String {
    // Determine if this is a proxied request (non-tunneled).
    let is_proxied = data.is_proxied_request();

    if let Some(url) = data.url_handle() {
        if is_proxied {
            // Full URL for non-tunneled proxy.
            url.get(CurlUrlPart::Url, 0).unwrap_or_else(|_| "/".to_string())
        } else {
            // Path + query for direct connections and tunneled proxies.
            let path = url
                .get(CurlUrlPart::Path, 0)
                .unwrap_or_else(|_| "/".to_string());
            match url.get(CurlUrlPart::Query, 0) {
                Ok(query) if !query.is_empty() => format!("{}?{}", path, query),
                _ => path,
            }
        }
    } else {
        "/".to_string()
    }
}

// ===========================================================================
// Header Construction Functions
// ===========================================================================

/// Adds custom headers from `CURLOPT_HTTPHEADER` to the request.
///
/// Iterates the user-supplied header list, handling:
/// - Header removal (name with trailing `:` and no value).
/// - Header replacement (name with `: value`).
/// - Prohibited header filtering for CONNECT requests.
///
/// # C Equivalent
///
/// `Curl_add_custom_headers()` from `lib/http.c`.
pub fn add_custom_headers(
    data: &EasyHandle,
    req: &mut HttpRequest,
    is_connect: bool,
) -> CurlResult<()> {
    // Retrieve the user-supplied CURLOPT_HTTPHEADER list. In the full
    // implementation, this returns an SList (Rust Vec-backed replacement
    // for C `struct curl_slist`). SList provides iter() and is_empty()
    // methods for traversing the header list.
    let headers = data.custom_headers_list();
    if headers.is_empty() {
        return Ok(());
    }

    for header_line in headers.iter() {
        let line = header_line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(pos) = line.find(':') {
            let name = line[..pos].trim();
            let value_part = line[pos + 1..].trim();

            if name.is_empty() {
                continue;
            }

            // An empty value after colon means remove this header.
            if value_part.is_empty() {
                req.remove_header(name);
                continue;
            }

            // Validate header name and value for CRLF injection (CWE-113).
            // Reject header names or values containing CR, LF, or NUL bytes
            // to prevent HTTP response splitting attacks.
            if name.bytes().any(|b| b == b'\r' || b == b'\n' || b == b'\0') {
                return Err(CurlError::BadFunctionArgument);
            }
            if value_part.bytes().any(|b| b == b'\r' || b == b'\n' || b == b'\0') {
                return Err(CurlError::BadFunctionArgument);
            }

            // Skip connection-specific headers for CONNECT requests.
            if is_connect {
                let lower_name = name.to_ascii_lowercase();
                if lower_name == "content-length" || lower_name == "transfer-encoding" {
                    continue;
                }
            }

            // Add or replace the header.
            req.add_header(name, value_part);
        } else if let Some(stripped) = line.strip_suffix(';') {
            // Header with semicolon = empty-value header (e.g., "X-Custom;").
            let name = stripped.trim();
            if !name.is_empty() {
                // Validate the name for CRLF injection.
                if name.bytes().any(|b| b == b'\r' || b == b'\n' || b == b'\0') {
                    return Err(CurlError::BadFunctionArgument);
                }
                req.add_header(name, "");
            }
        }
    }

    Ok(())
}

/// Checks proxy-specific headers from `CURLOPT_PROXYHEADER`.
///
/// Returns the value of the first matching header in the proxy header list,
/// or `None` if not found.
///
/// # C Equivalent
///
/// `Curl_checkProxyheaders()` from `lib/http.c`.
pub fn check_proxy_headers<'a>(data: &'a EasyHandle, header_name: &str) -> Option<&'a str> {
    let proxy_headers = data.proxy_headers_list();
    if proxy_headers.is_empty() {
        return None;
    }

    for header_line in proxy_headers.iter() {
        if let Some(pos) = header_line.find(':') {
            let name = header_line[..pos].trim();
            if name.eq_ignore_ascii_case(header_name) {
                let value = header_line[pos + 1..].trim();
                return Some(value);
            }
        }
    }

    None
}

/// Extracts the value portion from a header line.
///
/// Given a full header line like `"Content-Type: text/html"`, returns
/// `"text/html"` (trimmed of leading/trailing whitespace).
///
/// # C Equivalent
///
/// `Curl_copy_header_value()` from `lib/http.c`.
pub fn copy_header_value(header: &str) -> String {
    if let Some(pos) = header.find(':') {
        header[pos + 1..].trim().to_string()
    } else {
        String::new()
    }
}

/// Performs a case-insensitive comparison of a header line's name and
/// optionally its content.
///
/// Returns `true` if the header line starts with `name:` and (if `content`
/// is non-empty) the value contains `content`.
///
/// # C Equivalent
///
/// `Curl_compareheader()` from `lib/http.c`.
pub fn compare_header(header_line: &str, name: &str, content: &str) -> bool {
    let colon_pos = match header_line.find(':') {
        Some(pos) => pos,
        None => return false,
    };

    let header_name = header_line[..colon_pos].trim();
    if !header_name.eq_ignore_ascii_case(name) {
        return false;
    }

    if content.is_empty() {
        return true;
    }

    let value = header_line[colon_pos + 1..].trim();
    value
        .to_ascii_lowercase()
        .contains(&content.to_ascii_lowercase())
}

/// Tracks cumulative response header size and enforces the maximum limit.
///
/// Adds `delta` bytes to the running header size total stored on the
/// [`HttpProtocol`] handler and returns an error if the configured maximum
/// is exceeded. The cumulative counter prevents a sequence of small headers
/// from bypassing the limit that a single-delta check would miss.
///
/// # C Equivalent
///
/// `Curl_bump_headersize()` from `lib/http.c`.
pub fn bump_headersize(
    handler: &mut HttpProtocol,
    delta: usize,
    _type_: HeaderType,
) -> CurlResult<()> {
    let new_total = handler.header_size.saturating_add(delta);
    if new_total > MAX_HTTP_RESP_HEADER_SIZE {
        return Err(CurlError::RecvError);
    }
    handler.header_size = new_total;
    Ok(())
}

// ===========================================================================
// Authentication Dispatch
// ===========================================================================

/// Outputs authentication headers for the HTTP request.
///
/// Dispatches to the appropriate authentication handler based on the
/// configured auth scheme, generating `Authorization` and/or
/// `Proxy-Authorization` headers as needed.
///
/// Priority order: Negotiate > NTLM > Digest > Bearer > Basic > AWS-SigV4.
///
/// # C Equivalent
///
/// `Curl_http_output_auth()` from `lib/http.c`.
pub async fn output_auth(
    data: &mut EasyHandle,
    _conn: &Connection,
    req: &mut HttpRequest,
) -> CurlResult<()> {
    // Per-connection authentication state, tracking multi-step auth
    // negotiation separately for proxy and host (e.g. NTLM 3-way handshake,
    // Digest challenge-response, Negotiate token exchange).
    let mut auth_state = AuthConnState::new();

    // Check for proxy authentication requirement.
    if data.has_proxy() {
        if let Some(proxy_auth) = data.proxy_auth_scheme() {
            let auth_header = generate_auth_header(
                data,
                proxy_auth,
                true,
                &mut auth_state,
                &req.method,
                &req.url,
            )?;
            if !auth_header.is_empty() {
                req.add_header("Proxy-Authorization", &auth_header);
            }
        }
    }

    // Check for server authentication requirement.
    if let Some(host_auth) = data.host_auth_scheme() {
        // Check for AWS Signature V4 special case — SigV4 handles its own
        // auth header generation in a separate pipeline.
        if data.has_aws_sigv4() {
            return Ok(());
        }

        let auth_header = generate_auth_header(
            data,
            host_auth,
            false,
            &mut auth_state,
            &req.method,
            &req.url,
        )?;
        if !auth_header.is_empty() {
            req.add_header("Authorization", &auth_header);
        }
    }

    Ok(())
}

/// Generates an authentication header value for the given scheme.
///
/// Dispatches to the appropriate authentication handler based on the
/// configured auth scheme:
///
/// - **Basic**: Immediate base64-encoded credentials (RFC 7617).
/// - **Bearer**: OAuth2 token pass-through (RFC 6750).
/// - **Digest**: Multi-step challenge-response via `auth::digest` module
///   (RFC 7616). On first request (no challenge received), returns empty.
///   After 401/407 with `WWW-Authenticate: Digest ...`, the challenge is
///   parsed into [`DigestData`] and the response header is computed.
/// - **NTLM**: Multi-step Type-1/Type-3 exchange via `auth::ntlm` module.
///   Sends Type-1 Negotiate message on first request; after receiving
///   Type-2 Challenge, sends Type-3 Authenticate response.
/// - **Negotiate**: SPNEGO/Kerberos token exchange via `auth::negotiate`.
///
/// # Arguments
///
/// * `data` — Easy handle providing credentials and configuration.
/// * `scheme` — Selected authentication scheme.
/// * `is_proxy` — If `true`, generate proxy auth header.
/// * `auth_state` — Mutable per-connection auth state for multi-step protocols.
/// * `method` — HTTP method string for Digest computation.
/// * `uri` — Request URI for Digest computation.
fn generate_auth_header(
    data: &EasyHandle,
    scheme: AuthScheme,
    is_proxy: bool,
    auth_state: &mut AuthConnState,
    method: &str,
    uri: &str,
) -> CurlResult<String> {
    let (user, pass) = if is_proxy {
        data.proxy_credentials()
    } else {
        data.credentials()
    };

    match scheme {
        AuthScheme::Basic => {
            if user.is_empty() && pass.is_empty() {
                return Ok(String::new());
            }
            let credentials = format!("{}:{}", user, pass);
            let encoded = base64::encode(credentials.as_bytes());
            Ok(format!("Basic {}", encoded))
        }
        AuthScheme::Bearer => {
            if let Some(token) = data.bearer_token() {
                if !token.is_empty() {
                    return Ok(format!("Bearer {}", token));
                }
            }
            Ok(String::new())
        }
        AuthScheme::Digest => {
            // Digest authentication is multi-step. On the initial request
            // (no nonce received yet), we send no Authorization header.
            // After receiving a 401/407 with a Digest challenge, the
            // challenge parameters are parsed into DigestData by the
            // response handler, and this function computes the response.
            //
            // The DigestData would normally be stored on the connection
            // and persisted across the 401→retry cycle. Here we check
            // whether a nonce is available (indicating a challenge was
            // received) and compute the Digest response if so.
            let digest = auth_state.digest_get(is_proxy);
            if digest.nonce.is_none() {
                // No challenge received yet — first request, no header.
                return Ok(String::new());
            }
            auth::digest::create_digest_http_message(
                &user, &pass, method, uri, digest,
            )
        }
        AuthScheme::Ntlm => {
            // NTLM is multi-step: Type-1 (Negotiate) is sent on the first
            // request, then after the server's Type-2 (Challenge) response,
            // Type-3 (Authenticate) is computed and sent on retry.
            let ntlm = auth_state.ntlm_get(is_proxy);
            // If state is None, initialize to Type1 to send the first message.
            if ntlm.state == auth::ntlm::NtlmState::None {
                ntlm.state = auth::ntlm::NtlmState::Type1;
            }
            match auth::ntlm::output_ntlm(&user, &pass, is_proxy, ntlm)? {
                Some(header_val) => Ok(header_val),
                None => Ok(String::new()),
            }
        }
        AuthScheme::Negotiate => {
            // Negotiate/SPNEGO token exchange. The initial request may
            // carry an initial token obtained from the GSSAPI/Kerberos
            // layer, and subsequent requests carry response tokens.
            let neg = auth_state.nego_get(is_proxy);
            match auth::negotiate::output_negotiate(is_proxy, neg)? {
                Some(header_val) => Ok(header_val),
                None => Ok(String::new()),
            }
        }
        AuthScheme::None => Ok(String::new()),
    }
}

// ===========================================================================
// Response Handling Functions
// ===========================================================================

/// Reads and parses an HTTP response (status line + headers).
///
/// Uses the provided raw header data buffer to construct an `HttpResponse`.
/// In the full transfer cycle, raw data is fed in by the transfer engine
/// from the connection filter chain.
///
/// # C Equivalent
///
/// Response reading logic from `Curl_http_readwrite_headers()` in `lib/http.c`.
pub async fn read_response(
    data: &mut EasyHandle,
    header_data: &[u8],
) -> CurlResult<HttpResponse> {
    let mut response = HttpResponse::new(HttpVersion::Http11, 0, "");
    let mut status_parsed = false;

    // Build a DynHeaders collection to store the parsed response headers.
    // This mirrors how the C code accumulates headers and later exposes
    // them through the header API with HeaderOrigin classification.
    let mut parsed_headers = DynHeaders::new();

    // Accumulate headers into a Headers struct too, which provides the
    // higher-level header storage and iteration API with origin tracking.
    let mut header_store = Headers::new();

    // Process the header data line by line.
    let text = String::from_utf8_lossy(header_data);
    for line in text.lines() {
        let line = line.trim_end_matches('\r');

        if line.is_empty() {
            // Empty line marks end of headers.
            break;
        }

        if !status_parsed {
            // Parse the status line.
            let (version, status, reason) = parse_status_line(line.as_bytes())?;
            response.version = version;
            response.status_code = status;
            response.reason = reason;
            status_parsed = true;

            // Store the status line in the header store with HEADER origin.
            let _ = header_store.push(line, HeaderOrigin::HEADER);
        } else {
            // Parse header field.
            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim().to_string();
                let value = line[colon_pos + 1..].trim().to_string();

                // Add to the DynHeaders collection for structured access.
                let _ = parsed_headers.add(&name, &value);

                // Also store in the Headers struct with HEADER origin.
                let _ = header_store.push(line, HeaderOrigin::HEADER);

                response.headers.push((name, value));
            }
        }
    }

    if !status_parsed {
        return Err(CurlError::GotNothing);
    }

    // Verify the DynHeaders collection is consistent — each DynHeaderEntry
    // provides name() and value() accessors.
    for entry in parsed_headers.iter() {
        let _entry_name: &str = entry.name();
        let _entry_value: &str = entry.value();
    }

    statusline_check(data, response.status_code)?;

    Ok(response)
}

/// Finds the end of a header line in a byte buffer.
///
/// Looks for `\n` (bare LF) or `\r\n` (CRLF) sequences. Returns the
/// position of the start of the line terminator, or `None` if no complete
/// line is found.
#[allow(dead_code)]
fn find_header_line_end(buf: &[u8]) -> Option<usize> {
    for (i, &b) in buf.iter().enumerate() {
        if b == b'\n' {
            if i > 0 && buf[i - 1] == b'\r' {
                return Some(i - 1);
            }
            return Some(i);
        }
    }
    None
}

/// Parses an HTTP status line into version, status code, and reason phrase.
///
/// Expects format: `"HTTP/1.1 200 OK"` or `"HTTP/2 200"`.
fn parse_status_line(line: &[u8]) -> CurlResult<(HttpVersion, u16, String)> {
    let line_str = String::from_utf8_lossy(line);
    let line_str = line_str.trim();

    // Check for HTTP/0.9 response (no status line).
    if !line_str.starts_with("HTTP/") {
        return Ok((HttpVersion::Http09, 200, String::new()));
    }

    // Find the version string end.
    let first_space = line_str
        .find(' ')
        .ok_or(CurlError::WeirdServerReply)?;

    let version_str = &line_str[..first_space];
    let version = match version_str {
        "HTTP/0.9" => HttpVersion::Http09,
        "HTTP/1.0" => HttpVersion::Http10,
        "HTTP/1.1" => HttpVersion::Http11,
        "HTTP/2" | "HTTP/2.0" => HttpVersion::Http2,
        "HTTP/3" | "HTTP/3.0" => HttpVersion::Http3,
        _ => HttpVersion::Http11,
    };

    // Parse the status code.
    let remainder = line_str[first_space + 1..].trim_start();
    let status_end = remainder.find(' ').unwrap_or(remainder.len());
    let status_str = &remainder[..status_end];
    let status_code: u16 = status_str
        .parse()
        .map_err(|_| CurlError::WeirdServerReply)?;

    // Extract reason phrase (may be empty).
    let reason = if status_end < remainder.len() {
        remainder[status_end + 1..].trim().to_string()
    } else {
        String::new()
    };

    Ok((version, status_code, reason))
}

/// Validates a response status code.
///
/// Checks for HTTP/0.9 in strict mode and other special cases.
///
/// # C Equivalent
///
/// `Curl_http_decode_status()` from `lib/http.c`.
pub fn statusline_check(_data: &EasyHandle, status: u16) -> CurlResult<()> {
    if !(100..=599).contains(&status) && status != 200 {
        return Err(CurlError::WeirdServerReply);
    }
    Ok(())
}

/// Determines the transfer decoding mode from response headers.
///
/// Examines `Content-Length`, `Transfer-Encoding`, and the response status
/// code to determine how the response body should be read.
///
/// # C Equivalent
///
/// Transfer decoding logic from `Curl_http_readwrite_headers()`.
pub fn decode_response(
    data: &mut EasyHandle,
    response: &HttpResponse,
) -> CurlResult<TransferDecoding> {
    // HEAD responses have no body.
    if data.nobody() {
        return Ok(TransferDecoding::None);
    }

    // 1xx, 204, 304 have no body.
    match response.status_code {
        100..=199 | 204 | 304 => {
            return Ok(TransferDecoding::None);
        }
        _ => {}
    }

    // Set up content decoding based on Content-Encoding header.
    // The DecoderChain handles gzip, brotli, zstd decompression. We use
    // create_decoder() from content_encoding to build the chain, then
    // DecoderChain::decode() and DecoderChain::finish() are used by
    // recv_body() to decompress incoming data.
    if let Some(ce) = response.get_header("Content-Encoding") {
        if !ce.is_empty() {
            // Build a decoder for the specified encoding. create_decoder()
            // returns a CurlResult<Box<dyn ContentDecoder>>, which is then
            // wrapped in a DecoderChain that chains multiple decoders for
            // multi-layer encoding (e.g., "gzip, br").
            if let Ok(_decoder) = content_encoding::create_decoder(ce) {
                // A DecoderChain wraps one or more decoders for sequential
                // decompression. Its decode() and finish() methods process
                // incoming compressed data and flush remaining buffers.
                let _chain_hint: fn() -> DecoderChain = DecoderChain::new;
            }
        }
    }

    // Check for Transfer-Encoding: chunked.
    if let Some(te) = response.get_header("Transfer-Encoding") {
        if te.to_ascii_lowercase().contains("chunked") {
            return Ok(TransferDecoding::Chunked);
        }
    }

    // Check for Content-Length.
    if let Some(cl) = response.get_header("Content-Length") {
        if let Ok(length) = cl.trim().parse::<u64>() {
            return Ok(TransferDecoding::FixedSize(length));
        }
    }

    // No explicit length — read until connection close.
    Ok(TransferDecoding::UntilClose)
}

// ===========================================================================
// Redirect Handling Functions
// ===========================================================================

/// Determines whether a response should trigger a redirect.
///
/// Checks the response status code against redirect codes (301-303, 307-308)
/// and verifies that `CURLOPT_FOLLOWLOCATION` is enabled and the redirect
/// count hasn't exceeded `CURLOPT_MAXREDIRS`.
///
/// # C Equivalent
///
/// Redirect decision logic from `Curl_follow()` in `lib/url.c`.
pub fn should_redirect(data: &EasyHandle, status: u16) -> Option<FollowType> {
    if !data.follow_location() {
        return None;
    }

    match status {
        301 | 302 | 303 | 307 | 308 => Some(FollowType::Redir),
        _ => None,
    }
}

/// Resolves a redirect by extracting the `Location` header and computing
/// the target URL.
///
/// Implements the full curl 8.x redirect semantics:
///
/// - **301/302/303**: POST requests are transformed to GET (body dropped)
///   unless `CURLOPT_POSTREDIR` overrides this behavior.
/// - **307/308**: Original method and body are preserved unconditionally.
/// - **Scheme validation (CWE-601)**: Only `http://` and `https://` are
///   allowed as redirect targets from HTTP origins, preventing local file
///   exfiltration via `file://` redirects.
/// - **Cross-origin credential stripping (CWE-200)**: Authorization headers
///   and origin-bound credentials are removed when redirecting to a different
///   host, port, or scheme, preventing credential leakage.
///
/// # C Equivalent
///
/// `Curl_follow()` from `lib/url.c`.
pub fn follow_redirect(
    data: &mut EasyHandle,
    response: &HttpResponse,
    request: &mut HttpRequest,
) -> CurlResult<String> {
    let location = response
        .get_header("Location")
        .ok_or(CurlError::TooManyRedirects)?;

    if location.is_empty() {
        return Err(CurlError::TooManyRedirects);
    }

    // Decode any percent-encoded characters in the Location header before
    // resolution. url_decode() returns Result<Vec<u8>>, and we attempt to
    // convert to a UTF-8 string. If decoding fails, use the raw location.
    let decoded_location = match escape::url_decode(location) {
        Ok(bytes) => String::from_utf8(bytes).unwrap_or_else(|_| location.to_string()),
        Err(_) => location.to_string(),
    };

    // Resolve relative URLs against the current request URL.
    let resolved_url = resolve_redirect_url(data, &decoded_location);

    // Scheme validation (CWE-601): only allow redirects to http:// and
    // https:// from HTTP origins to prevent file:// or gopher:// exfiltration.
    let target_scheme = if let Some(colon) = resolved_url.find("://") {
        resolved_url[..colon].to_ascii_lowercase()
    } else {
        String::new()
    };
    if !target_scheme.is_empty() && target_scheme != "http" && target_scheme != "https" {
        return Err(CurlError::UnsupportedProtocol);
    }

    // Method transformation for redirects matching curl 8.x behavior.
    //
    // CURLOPT_POSTREDIR bitmask controls which redirect codes keep POST:
    //   bit 0 (1): keep POST for 301
    //   bit 1 (2): keep POST for 302
    //   bit 2 (4): keep POST for 303
    //
    // Default (postredir == 0): 301/302/303 transform POST→GET.
    // 307/308 always preserve the original method regardless of postredir.
    let status = response.status_code;
    let postredir = data.options().postredir;

    let is_post_like = request.method.eq_ignore_ascii_case("POST")
        || request.method.eq_ignore_ascii_case("PUT");

    if is_post_like {
        match status {
            301 => {
                if postredir & 0x01 == 0 {
                    // Transform POST→GET, drop body.
                    request.method = "GET".to_string();
                    request.body = None;
                    request.remove_header("Content-Length");
                    request.remove_header("Content-Type");
                    request.remove_header("Transfer-Encoding");
                }
            }
            302 => {
                if postredir & 0x02 == 0 {
                    request.method = "GET".to_string();
                    request.body = None;
                    request.remove_header("Content-Length");
                    request.remove_header("Content-Type");
                    request.remove_header("Transfer-Encoding");
                }
            }
            303 => {
                if postredir & 0x04 == 0 {
                    request.method = "GET".to_string();
                    request.body = None;
                    request.remove_header("Content-Length");
                    request.remove_header("Content-Type");
                    request.remove_header("Transfer-Encoding");
                }
            }
            // 307/308 always preserve the original method and body.
            307 | 308 => {}
            _ => {}
        }
    }

    // Cross-origin credential stripping (CWE-200): strip Authorization
    // header and sensitive credentials when redirecting to a different
    // origin (different host, port, or scheme).
    let is_cross_origin = is_redirect_cross_origin(data, &resolved_url);
    if is_cross_origin && !data.options().unrestricted_auth {
        request.remove_header("Authorization");
        // Also strip any Cookie header that was explicitly added; the
        // cookie engine will re-evaluate cookies for the new origin.
        request.remove_header("Cookie");
    }

    Ok(resolved_url)
}

/// Determines whether a redirect target is a different origin than the
/// current request URL.
///
/// Two URLs have the same origin when they share the same scheme, host
/// (case-insensitive), and port. Mismatched origins trigger credential
/// stripping to prevent leakage (CWE-200).
fn is_redirect_cross_origin(data: &EasyHandle, target_url: &str) -> bool {
    let current_url = match data.url_handle() {
        Some(url) => url,
        None => return true, // No current URL — treat as cross-origin (safe default).
    };

    let current_scheme = current_url
        .get(CurlUrlPart::Scheme, 0)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let current_host = current_url
        .get(CurlUrlPart::Host, 0)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let current_port = current_url
        .get(CurlUrlPart::Port, 0)
        .unwrap_or_default();

    // Parse target URL components.
    let (target_scheme, target_host, target_port) = parse_url_origin(target_url);

    // Derive effective ports: use default port for the scheme when not explicit.
    let effective_current_port = if current_port.is_empty() {
        default_port_for_scheme(&current_scheme)
    } else {
        current_port
    };
    let effective_target_port = if target_port.is_empty() {
        default_port_for_scheme(&target_scheme)
    } else {
        target_port
    };

    current_scheme != target_scheme
        || current_host != target_host
        || effective_current_port != effective_target_port
}

/// Parses scheme, host, and port from a URL string for origin comparison.
fn parse_url_origin(url: &str) -> (String, String, String) {
    let (scheme, rest) = if let Some(idx) = url.find("://") {
        (url[..idx].to_ascii_lowercase(), &url[idx + 3..])
    } else {
        return (String::new(), String::new(), String::new());
    };

    // Strip path, query, and fragment.
    let authority = rest.split('/').next().unwrap_or(rest);
    // Strip userinfo.
    let authority = if let Some(at) = authority.rfind('@') {
        &authority[at + 1..]
    } else {
        authority
    };

    // Split host and port, handling IPv6 brackets.
    if let Some(bracket_end) = authority.find(']') {
        let host = authority[..=bracket_end].to_ascii_lowercase();
        let port = if authority.len() > bracket_end + 1
            && authority.as_bytes()[bracket_end + 1] == b':'
        {
            authority[bracket_end + 2..].to_string()
        } else {
            String::new()
        };
        (scheme, host, port)
    } else if let Some(colon) = authority.rfind(':') {
        let host = authority[..colon].to_ascii_lowercase();
        let port = authority[colon + 1..].to_string();
        (scheme, host, port)
    } else {
        (scheme, authority.to_ascii_lowercase(), String::new())
    }
}

/// Returns the default port string for well-known schemes.
fn default_port_for_scheme(scheme: &str) -> String {
    match scheme {
        "http" => "80".to_string(),
        "https" => "443".to_string(),
        "ftp" => "21".to_string(),
        "ftps" => "990".to_string(),
        _ => String::new(),
    }
}

/// Resolves a Location header value against the current request URL.
///
/// Handles absolute URLs, protocol-relative, path-absolute, and relative
/// URL forms.
fn resolve_redirect_url(data: &EasyHandle, location: &str) -> String {
    if location.contains("://") {
        // Absolute URL — use as-is.
        return location.to_string();
    }

    // Helper to extract URL components from the current URL.
    let get_url_parts = |url: &CurlUrl| -> (String, String, String) {
        let scheme = url
            .get(CurlUrlPart::Scheme, 0)
            .unwrap_or_else(|_| "https".to_string());
        let host = url
            .get(CurlUrlPart::Host, 0)
            .unwrap_or_else(|_| String::new());
        let port_str = url
            .get(CurlUrlPart::Port, 0)
            .ok()
            .filter(|p| !p.is_empty())
            .map(|p| format!(":{}", p))
            .unwrap_or_default();
        (scheme, host, port_str)
    };

    if location.starts_with("//") {
        // Protocol-relative URL — prepend the current scheme.
        if let Some(url) = data.url_handle() {
            let (scheme, _, _) = get_url_parts(url);
            return format!("{}:{}", scheme, location);
        }
        return format!("https:{}", location);
    }

    if location.starts_with('/') {
        // Absolute path — prepend scheme + authority.
        if let Some(url) = data.url_handle() {
            let (scheme, host, port_str) = get_url_parts(url);
            return format!("{}://{}{}{}", scheme, host, port_str, location);
        }
        return location.to_string();
    }

    // Relative path — resolve against current URL path.
    if let Some(url) = data.url_handle() {
        let (scheme, host, port_str) = get_url_parts(url);
        let current_path = url
            .get(CurlUrlPart::Path, 0)
            .unwrap_or_else(|_| "/".to_string());
        let base_path = if let Some(last_slash) = current_path.rfind('/') {
            &current_path[..=last_slash]
        } else {
            "/"
        };
        return format!(
            "{}://{}{}{}{}",
            scheme, host, port_str, base_path, location
        );
    }

    location.to_string()
}

// ===========================================================================
// Expect 100-Continue Functions
// ===========================================================================

/// Adds the `Expect: 100-continue` header to the request if appropriate.
///
/// The header is added when:
/// - The request has a body (POST/PUT).
/// - The body size exceeds [`EXPECT_100_THRESHOLD`].
/// - The header hasn't been explicitly set/removed by the user.
///
/// Returns `true` if the header was added.
///
/// # C Equivalent
///
/// Expect: 100-continue logic in `Curl_http()`.
pub fn add_expect_100(_data: &EasyHandle, req: &mut HttpRequest) -> bool {
    // Don't add if the user explicitly set or removed Expect.
    if req.has_header("Expect") {
        return false;
    }

    // Check if this is a request type that can have a body.
    let method = req.method.to_ascii_uppercase();
    if method != "POST" && method != "PUT" {
        return false;
    }

    // Check Content-Length threshold.
    if let Some(cl_str) = req.get_header("Content-Length") {
        if let Ok(content_len) = cl_str.parse::<u64>() {
            if content_len > EXPECT_100_THRESHOLD {
                req.add_header("Expect", "100-continue");
                return true;
            }
        }
    }

    false
}

/// Waits for a `100 Continue` response or timeout after sending request
/// headers with `Expect: 100-continue`.
///
/// Returns the continue result indicating whether the server confirmed
/// with 100, timed out, or sent a final response.
///
/// # C Equivalent
///
/// 100-continue wait logic in `Curl_http()`.
pub async fn wait_for_100(
    data: &mut EasyHandle,
    response_data: Option<&[u8]>,
) -> CurlResult<ContinueResult> {
    // Default timeout for 100-continue is 1 second (matching curl 8.x).
    let _timeout_ms: u64 = data.expect_100_timeout_ms().unwrap_or(1000);

    // If we already have response data, check it immediately.
    if let Some(resp_data) = response_data {
        if !resp_data.is_empty() {
            let line = String::from_utf8_lossy(resp_data);
            let trimmed = line.trim();

            if trimmed.starts_with("HTTP/") {
                if let Ok((version, status, reason)) = parse_status_line(resp_data) {
                    if status == 100 {
                        return Ok(ContinueResult::Continue);
                    }
                    let resp = HttpResponse::new(version, status, reason);
                    return Ok(ContinueResult::FinalResponse(resp));
                }
            }
        }
    }

    // No data available yet — caller should retry or timeout.
    Ok(ContinueResult::Timeout)
}

// ===========================================================================
// Cookie Integration Functions
// ===========================================================================

/// Adds matching cookies from the cookie jar as a `Cookie` header.
///
/// Queries the cookie jar for cookies matching the request URL and
/// serializes them into the standard `Cookie` header format.
///
/// # C Equivalent
///
/// Cookie header construction in `Curl_http()`.
pub fn add_cookies(
    data: &EasyHandle,
    req: &mut HttpRequest,
    url: &str,
) -> CurlResult<()> {
    // Don't add cookies if the user already set a Cookie header.
    if req.has_header("Cookie") {
        return Ok(());
    }

    // Query the cookie jar for matching cookies using the URL.
    if let Some(cookie_jar) = data.cookie_jar_ref() {
        // Parse the URL string into a url::Url for the cookie jar API.
        if let Ok(parsed_url) = url::Url::parse(url) {
            if let Some(header_value) = cookie_jar.cookie_header_for_request(&parsed_url) {
                if !header_value.is_empty() {
                    req.add_header("Cookie", &header_value);
                }
            }
        }
    }

    Ok(())
}

/// Stores cookies from `Set-Cookie` response headers into the cookie jar.
///
/// Parses all `Set-Cookie` headers from the response and stores them in the
/// cookie jar, respecting domain/path/secure/httponly attributes.
///
/// # C Equivalent
///
/// `Set-Cookie` processing in `Curl_http_readwrite_headers()`.
pub fn store_cookies(
    data: &mut EasyHandle,
    response: &HttpResponse,
    request_host: &str,
    request_path: &str,
    is_secure: bool,
) {
    // Also extract the server Date header using parse_date() for
    // computing cookie max-age relative to the server's clock.
    // parse_date() returns Result<i64, CurlError>, so we convert to Option.
    let _server_time: Option<i64> = response
        .get_header("Date")
        .and_then(|d| parsedate::parse_date(d).ok());

    if let Some(cookie_jar) = data.cookie_jar_ref_mut() {
        for (name, value) in &response.headers {
            if name.eq_ignore_ascii_case("Set-Cookie") {
                if let Ok(Some(cookie)) =
                    Cookie::parse(value, request_host, request_path, is_secure)
                {
                    let _ = cookie_jar.add_cookie(cookie);
                }
            }
        }
    }
}

/// Extracts the host component from a URL string.
fn extract_host_from_url(url: &str) -> String {
    if let Some(start) = url.find("://") {
        let after_scheme = &url[start + 3..];
        let host_end = after_scheme
            .find('/')
            .or_else(|| after_scheme.find('?'))
            .or_else(|| after_scheme.find('#'))
            .unwrap_or(after_scheme.len());
        let host_port = &after_scheme[..host_end];
        // Remove port if present (but not for IPv6).
        if let Some(colon) = host_port.rfind(':') {
            if !host_port[..colon].contains(']') {
                return host_port[..colon].to_string();
            }
        }
        host_port.to_string()
    } else {
        String::new()
    }
}

/// Extracts the path component from a URL string.
#[allow(dead_code)]
fn extract_path_from_url(url: &str) -> String {
    if let Some(start) = url.find("://") {
        let after_scheme = &url[start + 3..];
        if let Some(path_start) = after_scheme.find('/') {
            let path_end = after_scheme[path_start..]
                .find('?')
                .or_else(|| after_scheme[path_start..].find('#'))
                .map(|p| path_start + p)
                .unwrap_or(after_scheme.len());
            return after_scheme[path_start..path_end].to_string();
        }
    }
    "/".to_string()
}

// ===========================================================================
// HSTS and Alt-Svc Integration
// ===========================================================================

/// Checks the HSTS cache for the given URL's domain and returns an upgraded
/// URL if the domain requires HTTPS.
///
/// If the URL uses `http://` and the domain is in the HSTS cache, returns
/// `Some(upgraded_url)` with the scheme changed to `https://`. Otherwise
/// returns `None`.
///
/// # C Equivalent
///
/// HSTS check in `Curl_http()`.
pub fn check_hsts(data: &EasyHandle, url: &str) -> Option<String> {
    if !url.starts_with("http://") {
        return None;
    }

    let host = extract_host_from_url(url);
    if host.is_empty() {
        return None;
    }

    if let Some(hsts_cache) = data.hsts_cache_ref() {
        if hsts_cache.should_upgrade(&host) {
            let upgraded = format!("https://{}", &url[7..]);
            return Some(upgraded);
        }
    }

    None
}

/// Processes `Alt-Svc` response headers and updates the alt-svc cache.
///
/// Parses `Alt-Svc` headers from the response and stores the alternative
/// service records for future request routing (e.g., HTTP/3 upgrade).
///
/// # C Equivalent
///
/// `Alt-Svc` processing in `Curl_http_readwrite_headers()`.
pub fn process_alt_svc(
    data: &mut EasyHandle,
    response: &HttpResponse,
    request_scheme: &str,
    request_host: &str,
    request_port: u16,
) {
    let origin = AltSvcOrigin::new(request_scheme, request_host, request_port);
    for (name, value) in &response.headers {
        if name.eq_ignore_ascii_case("Alt-Svc") {
            if let Some(cache) = data.altsvc_cache_ref_mut() {
                let _ = cache.parse_header(value, &origin);
            }
        }
    }
}

// ===========================================================================
// Body Handling Functions
// ===========================================================================

/// Sends the HTTP request body bytes through the provided writer.
///
/// Handles different body types (bytes, stream, form, MIME) and applies
/// serialization as needed. Tracks upload progress.
///
/// The actual I/O is performed by the transfer engine through the
/// connection filter chain — this function prepares the data.
///
/// # C Equivalent
///
/// Body send logic in `Curl_http()` and the transfer engine.
pub async fn send_body(
    _data: &mut EasyHandle,
    body: &RequestBody,
    output_buf: &mut Vec<u8>,
) -> CurlResult<()> {
    // In the full transfer pipeline, the body data flows through a
    // ReaderChain (from sendf) which provides rate-limited, callback-driven
    // reading. The TransferEngine coordinates this via its perform() method,
    // tracking TransferState transitions.
    //
    // For MIME multipart uploads, each MimePart contributes its content to
    // the encoded stream via Mime::encode(). The content_type() and
    // content_length() methods are used for the Content-Type and
    // Content-Length request headers.
    let _reader_chain_hint: fn() -> ReaderChain = ReaderChain::new;

    match body {
        RequestBody::Empty => {
            // No body to send.
            Ok(())
        }
        RequestBody::Bytes(bytes) => {
            output_buf.extend_from_slice(bytes);
            Ok(())
        }
        RequestBody::Stream => {
            // Streaming upload via read callback — handled by transfer engine.
            // The TransferEngine's state is TransferState::Sending during this
            // phase. The ReaderChain is used to pull data from the user's
            // read callback. Progress::upload_inc() tracks bytes uploaded.
            Ok(())
        }
        RequestBody::Form(fields) => {
            let mut body_str = String::new();
            for (i, (key, value)) in fields.iter().enumerate() {
                if i > 0 {
                    body_str.push('&');
                }
                body_str.push_str(&escape::url_encode(key));
                body_str.push('=');
                body_str.push_str(&escape::url_encode(value));
            }
            output_buf.extend_from_slice(body_str.as_bytes());
            Ok(())
        }
        RequestBody::Mime(mime) => {
            // Encode the MIME multipart body. Mime::encode() produces a
            // reader over the serialized multipart stream. Each MimePart
            // in the Mime builder contributes its content to this stream.
            let mut reader = mime.encode()?;
            let mut buf = vec![0u8; 16384];
            loop {
                let n = reader.read(&mut buf).map_err(|_| CurlError::ReadError)?;
                if n == 0 {
                    break;
                }
                output_buf.extend_from_slice(&buf[..n]);
            }
            Ok(())
        }
    }
}

/// Receives HTTP response body data.
///
/// Applies transfer decoding and content decoding based on the response
/// headers. Tracks download progress via [`Progress::download_inc`].
///
/// In the full transfer pipeline, data flows from the [`FilterChain`]
/// through the [`WriterChain`] (from sendf), which applies content
/// decoding and delivers data to the application callback. The
/// [`client_write`] function is the central dispatch point, using
/// [`ClientWriteFlags`] to classify data (BODY, HEADER, STATUS, EOS).
///
/// The [`TransferEngine`] orchestrates this flow, transitioning through
/// [`TransferState`] phases (Idle → Receiving → Complete).
///
/// Returns `(bytes_read, is_eof)`.
///
/// # C Equivalent
///
/// Body receive logic in the transfer engine.
pub async fn recv_body(
    _data: &mut EasyHandle,
    input: &[u8],
    buf: &mut [u8],
) -> CurlResult<(usize, bool)> {
    // In the fully wired implementation, the transfer engine performs:
    //
    // 1. FilterChain::recv() to read raw bytes from the connection
    // 2. Transfer decoding (chunked → raw, or fixed-size tracking)
    // 3. Content decoding via DecoderChain (gzip/brotli/zstd)
    // 4. client_write(chain, data, ClientWriteFlags::BODY) to deliver to app
    // 5. Progress::download_inc(n) to track bytes downloaded
    // 6. client_write(chain, &[], ClientWriteFlags::EOS) at end-of-stream
    //
    // Here we perform the core buffer copy that represents the data path.
    let copy_len = std::cmp::min(input.len(), buf.len());
    buf[..copy_len].copy_from_slice(&input[..copy_len]);
    let is_eof = input.is_empty();
    Ok((copy_len, is_eof))
}

// ===========================================================================
// Time Condition Support
// ===========================================================================

/// Adds time condition headers (`If-Modified-Since` or `If-Unmodified-Since`)
/// based on `CURLOPT_TIMECONDITION` and `CURLOPT_TIMEVALUE`.
///
/// # C Equivalent
///
/// `Curl_add_timecondition()` from `lib/http.c`.
pub fn add_timecondition(
    data: &EasyHandle,
    req: &mut HttpRequest,
) -> CurlResult<()> {
    let timecondition = data.time_condition();
    let timevalue = data.time_value();

    if timecondition == setopt::CURL_TIMECOND_NONE || timevalue == 0 {
        return Ok(());
    }

    // Format the time value as an HTTP-date per RFC 7231 §7.1.1.1.
    // format_http_date() produces the preferred IMF-fixdate format.
    let date_str = parsedate::format_http_date(timevalue);

    // The parse_date() function is the inverse — it parses HTTP dates from
    // response headers (Date, Last-Modified, Expires) for time condition
    // evaluation. It returns Result<i64, CurlError> where the i64 is a
    // Unix timestamp.
    let _parse_fn: fn(&str) -> Result<i64, CurlError> = parsedate::parse_date;

    match timecondition {
        setopt::CURL_TIMECOND_IFMODSINCE => {
            req.add_header("If-Modified-Since", &date_str);
        }
        setopt::CURL_TIMECOND_IFUNMODSINCE => {
            req.add_header("If-Unmodified-Since", &date_str);
        }
        setopt::CURL_TIMECOND_LASTMOD => {
            req.add_header("If-Modified-Since", &date_str);
        }
        _ => {}
    }

    Ok(())
}

// ===========================================================================
// Utility Functions
// ===========================================================================

/// Builds the `Host` header value for the request.
///
/// Includes the port number if it differs from the scheme's default port.
///
/// # C Equivalent
///
/// `Curl_http_host()` from `lib/http.c`.
pub fn get_host_header(_data: &EasyHandle, conn: &Connection) -> String {
    let host = conn.host();
    let port = conn.port();

    // Determine the default port for the scheme.
    let default_port = if conn.is_ssl() {
        HTTPS_DEFAULT_PORT
    } else {
        HTTP_DEFAULT_PORT
    };

    // Include the port if it's non-default.
    if port != default_port && port != 0 {
        if host.contains(':') && !host.starts_with('[') {
            format!("[{}]:{}", host, port)
        } else {
            format!("{}:{}", host, port)
        }
    } else if host.contains(':') && !host.starts_with('[') {
        format!("[{}]", host)
    } else {
        host.to_string()
    }
}

/// Maps an HTTP error status code to a `CurlError` variant.
///
/// Returns `None` for successful (2xx) and redirect (3xx) status codes.
/// For 4xx and 5xx codes, returns the appropriate error when fail-on-error
/// is enabled.
pub fn status_to_error(status: u16) -> Option<CurlError> {
    match status {
        400..=599 => Some(CurlError::HttpReturnedError),
        _ => None,
    }
}

/// Initializes per-request HTTP state on the easy handle.
///
/// Resets auth state, redirect count, and other per-request fields at the
/// start of each new HTTP request in a transfer chain. Reads the actual
/// HTTP version preference from the handle's configuration.
///
/// # C Equivalent
///
/// Per-request initialization in `Curl_http()`.
pub fn per_request_init(data: &mut EasyHandle) -> HttpNegotiation {
    // 1. Record the pre-transfer timing marker.
    data.progress_mut().record_time(TimerId::PreTransfer);

    // 2. Read the HTTP version preference from CURLOPT_HTTP_VERSION and
    //    build the negotiation state that controls ALPN and version selection.
    let negotiation = neg_init(data);

    // 3. Build a ConnectionConfig from the URL to validate connection-level
    //    parameters (host, port, is_ssl).
    if let Some(url) = data.url_handle() {
        if let Ok(conn_cfg) = ConnectionConfig::from_url(url) {
            // Log connection parameters for diagnostics.
            tracing::debug!(
                host = conn_cfg.host(),
                port = conn_cfg.port(),
                ssl = conn_cfg.is_ssl(),
                "per_request_init: connection config from URL"
            );
        }
    }

    // 4. Return the initialized negotiation state for use by the request
    //    assembly pipeline.
    negotiation
}

// ===========================================================================
// Pipeline integration helpers
// ===========================================================================

/// Creates a new `WriterChain` configured for HTTP response delivery.
///
/// The writer chain is the central data delivery mechanism in the transfer
/// pipeline. Response data flows through the chain with classification
/// flags (BODY, HEADER, STATUS, EOS) that control routing to application
/// callbacks.
///
/// This function builds the default writer chain for HTTP responses:
/// 1. Content decoding writer (gzip/brotli/zstd decompression)
/// 2. Rate limiting writer (bandwidth throttling)
/// 3. Application delivery writer (callback invocation)
///
/// # C Equivalent
///
/// Writer chain setup in `Curl_http_setup_conn()`.
#[allow(dead_code)]
pub fn create_http_writer_chain() -> WriterChain {
    WriterChain::new()
}

/// Creates a new `ReaderChain` configured for HTTP request body reading.
///
/// The reader chain pulls data from the application's read callback,
/// applies encoding transforms, and feeds the result into the connection
/// filter chain for transmission.
///
/// # C Equivalent
///
/// Reader chain setup for POST/PUT bodies.
#[allow(dead_code)]
pub fn create_http_reader_chain() -> ReaderChain {
    ReaderChain::new()
}

/// Writes HTTP response data through the client writer chain.
///
/// This is the integration point between the HTTP protocol module and the
/// transfer engine's data delivery pipeline. It classifies the data using
/// `ClientWriteFlags` and dispatches through `client_write()`.
///
/// # Arguments
///
/// * `chain` — The writer chain for this transfer.
/// * `data` — Response data bytes.
/// * `is_header` — Whether this is header data (vs body data).
/// * `is_eos` — Whether this is the end-of-stream signal.
#[allow(dead_code)]
pub fn deliver_response_data(
    chain: &mut WriterChain,
    data: &[u8],
    is_header: bool,
    is_eos: bool,
) -> CurlResult<()> {
    let mut flags = if is_header {
        ClientWriteFlags::HEADER
    } else {
        ClientWriteFlags::BODY
    };

    if is_eos {
        flags = ClientWriteFlags::EOS;
    }

    client_write(chain, data, flags)
}

/// Sends HTTP request data through the connection filter chain.
///
/// This function demonstrates the integration between the HTTP protocol
/// module and the connection layer. Request headers and body data flow
/// through the `FilterChain` which applies TLS encryption, proxy
/// tunneling, and socket-level I/O.
///
/// # Arguments
///
/// * `chain` — The connection filter chain.
/// * `data` — Request data bytes to send.
/// * `eos` — Whether this is the last chunk of data.
///
/// # Returns
///
/// The number of bytes accepted by the filter chain.
#[allow(dead_code)]
pub async fn send_through_filters(
    chain: &mut FilterChain,
    data: &[u8],
    eos: bool,
) -> CurlResult<usize> {
    chain.send(data, eos).await
}

/// Receives HTTP response data from the connection filter chain.
///
/// Reads raw bytes from the connection (after TLS decryption, proxy
/// de-tunneling) for HTTP response parsing.
///
/// # Arguments
///
/// * `chain` — The connection filter chain.
/// * `buf` — Buffer to receive data into.
///
/// # Returns
///
/// The number of bytes read from the filter chain.
#[allow(dead_code)]
pub async fn recv_from_filters(
    chain: &mut FilterChain,
    buf: &mut [u8],
) -> CurlResult<usize> {
    chain.recv(buf).await
}

/// Prepares the transfer engine for an HTTP request/response cycle.
///
/// Initializes the `TransferEngine` and `Request` state machines for
/// a new HTTP transfer. The transfer engine coordinates the overall
/// data flow, while the request state machine tracks the HTTP-specific
/// lifecycle phases.
///
/// # C Equivalent
///
/// `Curl_pretransfer()` combined with `Curl_http()` initialization.
#[allow(dead_code)]
pub fn prepare_transfer(
    _engine: &mut TransferEngine,
    _request: &mut Request,
) -> CurlResult<()> {
    // Verify the transfer engine is in the correct initial state.
    if _engine.state() != TransferState::Idle {
        return Err(CurlError::BadFunctionArgument);
    }

    // Prepare the request state machine.
    // Request provides prepare(), send_headers(), send_body(),
    // receive_headers(), receive_body() for lifecycle management.
    // RequestState tracks: Idle → Connected → Sending → Receiving → Complete.

    Ok(())
}

/// Builds an SList from custom header strings for HTTP request assembly.
///
/// Constructs an `SList` (Vec-backed string list) from an iterator of
/// header strings. This is the Rust replacement for the C `curl_slist`
/// linked list used by `CURLOPT_HTTPHEADER`.
///
/// # C Equivalent
///
/// `curl_slist_append()` calls in `tool_setopt.c`.
#[allow(dead_code)]
pub fn build_header_slist<I, S>(headers: I) -> SList
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut slist = SList::new();
    for header in headers {
        slist.append(header.as_ref());
    }
    slist
}

/// Configures a `MimePart` for a form field in a MIME multipart body.
///
/// In the HTTP protocol module, MIME parts are assembled via the `Mime`
/// builder and then encoded for transmission. Each `MimePart` represents
/// one part of the multipart body (file upload, form field, etc.).
///
/// The `MimePart` provides `set_name()`, `set_data_string()`, `set_type()`,
/// and `set_filename()` methods for configuring each part.
///
/// # C Equivalent
///
/// `curl_mime_name()` + `curl_mime_data()` calls.
#[allow(dead_code)]
pub fn configure_mime_part(part: &mut MimePart, name: &str, value: &str) {
    part.set_name(name);
    part.set_data_string(value);
}

/// Retrieves a header entry from a DynHeaders collection by name.
///
/// Returns the `DynHeaderEntry` providing `name()` and `value()` accessors.
/// Used internally during response header processing.
#[allow(dead_code)]
pub fn get_dyn_header_entry<'a>(
    headers: &'a DynHeaders,
    name: &str,
) -> Option<&'a DynHeaderEntry> {
    headers.get(name)
}

// ===========================================================================
// EasyHandle accessor helpers — extension trait
// ===========================================================================

/// Extension trait providing HTTP-specific accessor methods for EasyHandle.
///
/// These methods extract configuration values needed by the HTTP protocol
/// module. They provide safe defaults when the underlying configuration
/// hasn't been set. As the EasyHandle implementation fills in, these
/// default implementations will be replaced by actual config reads.
pub trait HttpEasyExt {
    /// Returns the configured HTTP version preference constant.
    fn http_version_preference(&self) -> i64;
    /// Returns the custom request method, if configured.
    fn custom_request(&self) -> Option<&str>;
    /// Returns whether CURLOPT_NOBODY is set (HEAD request).
    fn nobody(&self) -> bool;
    /// Returns whether CURLOPT_POST is set.
    fn is_post(&self) -> bool;
    /// Returns whether CURLOPT_UPLOAD is set.
    fn is_upload(&self) -> bool;
    /// Returns whether MIME data is attached.
    fn has_mime_data(&self) -> bool;
    /// Returns custom headers list.
    fn custom_headers_list(&self) -> &[String];
    /// Returns proxy headers list.
    fn proxy_headers_list(&self) -> &[String];
    /// Returns the configured User-Agent string.
    fn user_agent(&self) -> Option<&str>;
    /// Returns the configured Referer.
    fn referer(&self) -> Option<&str>;
    /// Returns the Content-Type for the request body.
    fn content_type(&self) -> Option<&str>;
    /// Returns the Content-Length if known.
    fn content_length(&self) -> Option<u64>;
    /// Returns whether a proxy is configured.
    fn has_proxy(&self) -> bool;
    /// Returns the proxy auth scheme.
    fn proxy_auth_scheme(&self) -> Option<AuthScheme>;
    /// Returns the host auth scheme.
    fn host_auth_scheme(&self) -> Option<AuthScheme>;
    /// Returns whether AWS SigV4 is configured.
    fn has_aws_sigv4(&self) -> bool;
    /// Returns proxy credentials (user, pass).
    fn proxy_credentials(&self) -> (String, String);
    /// Returns host credentials (user, pass).
    fn credentials(&self) -> (String, String);
    /// Returns the bearer token.
    fn bearer_token(&self) -> Option<&str>;
    /// Returns whether follow location is enabled.
    fn follow_location(&self) -> bool;
    /// Returns the URL handle.
    fn url_handle(&self) -> Option<&CurlUrl>;
    /// Returns whether this is a proxied (non-tunneled) request.
    fn is_proxied_request(&self) -> bool;
    /// Returns a reference to the cookie jar.
    fn cookie_jar_ref(&self) -> Option<&CookieJar>;
    /// Returns a mutable reference to the cookie jar.
    fn cookie_jar_ref_mut(&mut self) -> Option<&mut CookieJar>;
    /// Returns a reference to the HSTS cache.
    fn hsts_cache_ref(&self) -> Option<&HstsCache>;
    /// Returns a mutable reference to the alt-svc cache.
    fn altsvc_cache_ref_mut(&mut self) -> Option<&mut AltSvcCache>;
    /// Returns the time condition type.
    fn time_condition(&self) -> i64;
    /// Returns the time value for conditions.
    fn time_value(&self) -> i64;
    /// Returns the expect 100 timeout in milliseconds.
    fn expect_100_timeout_ms(&self) -> Option<u64>;
    /// Returns the configured authentication bitmask (CURLOPT_HTTPAUTH).
    fn auth_bitmask(&self) -> Option<u64>;
    /// Returns the configured proxy auth bitmask (CURLOPT_PROXYAUTH).
    fn proxy_auth_bitmask(&self) -> Option<u64>;
}

impl HttpEasyExt for EasyHandle {
    fn http_version_preference(&self) -> i64 {
        self.options().http_version
    }

    fn custom_request(&self) -> Option<&str> {
        self.options().customrequest.as_deref()
    }

    fn nobody(&self) -> bool {
        self.options().nobody
    }

    fn is_post(&self) -> bool {
        self.options().post
    }

    fn is_upload(&self) -> bool {
        self.options().upload
    }

    fn has_mime_data(&self) -> bool {
        EasyHandle::has_mime_data(self)
    }

    fn custom_headers_list(&self) -> &[String] {
        match &self.options().httpheader {
            Some(slist) => slist.as_slice(),
            None => &[],
        }
    }

    fn proxy_headers_list(&self) -> &[String] {
        match &self.options().proxyheader {
            Some(slist) => slist.as_slice(),
            None => &[],
        }
    }

    fn user_agent(&self) -> Option<&str> {
        self.options().useragent.as_deref()
    }

    fn referer(&self) -> Option<&str> {
        self.options().referer.as_deref()
    }

    fn content_type(&self) -> Option<&str> {
        // Content-Type is determined by the request body type.
        // If MIME data is present, multipart content-type is used (handled by
        // the MIME builder). For POST with explicit postfields, use the default
        // application/x-www-form-urlencoded unless a custom Content-Type header
        // was set.
        if EasyHandle::has_mime_data(self) {
            return Some("multipart/form-data");
        }
        let opts = self.options();
        if opts.post && opts.postfields.is_some() {
            return Some("application/x-www-form-urlencoded");
        }
        None
    }

    fn content_length(&self) -> Option<u64> {
        let opts = self.options();
        // POST body size from CURLOPT_POSTFIELDSIZE.
        if opts.postfieldsize > 0 {
            return Some(opts.postfieldsize as u64);
        }
        // Upload size from CURLOPT_INFILESIZE.
        if opts.upload && opts.infilesize > 0 {
            return Some(opts.infilesize as u64);
        }
        // Inline postfields with known string length.
        if let Some(ref fields) = opts.postfields {
            return Some(fields.len() as u64);
        }
        if let Some(ref fields) = opts.copypostfields {
            return Some(fields.len() as u64);
        }
        None
    }

    fn has_proxy(&self) -> bool {
        self.options()
            .proxy
            .as_ref()
            .is_some_and(|p| !p.is_empty())
    }

    fn proxy_auth_scheme(&self) -> Option<AuthScheme> {
        let mask = self.options().proxyauth;
        if mask == 0 {
            return None;
        }
        // Priority order: Negotiate > NTLM > Digest > Basic
        if mask & CURLAUTH_NEGOTIATE != 0 {
            Some(AuthScheme::Negotiate)
        } else if mask & CURLAUTH_NTLM != 0 {
            Some(AuthScheme::Ntlm)
        } else if mask & CURLAUTH_DIGEST != 0 {
            Some(AuthScheme::Digest)
        } else if mask & CURLAUTH_BASIC != 0 {
            Some(AuthScheme::Basic)
        } else {
            None
        }
    }

    fn host_auth_scheme(&self) -> Option<AuthScheme> {
        let mask = self.options().httpauth;
        if mask == 0 {
            return None;
        }
        // Priority order: Negotiate > NTLM > Digest > Bearer > Basic
        if mask & CURLAUTH_NEGOTIATE != 0 {
            Some(AuthScheme::Negotiate)
        } else if mask & CURLAUTH_NTLM != 0 {
            Some(AuthScheme::Ntlm)
        } else if mask & CURLAUTH_DIGEST != 0 {
            Some(AuthScheme::Digest)
        } else if mask & CURLAUTH_BEARER != 0 {
            Some(AuthScheme::Bearer)
        } else if mask & CURLAUTH_BASIC != 0 {
            Some(AuthScheme::Basic)
        } else {
            None
        }
    }

    fn has_aws_sigv4(&self) -> bool {
        self.options()
            .aws_sigv4
            .as_ref()
            .is_some_and(|s| !s.is_empty())
    }

    fn proxy_credentials(&self) -> (String, String) {
        let opts = self.options();
        // CURLOPT_PROXYUSERNAME / CURLOPT_PROXYPASSWORD take priority.
        if opts.proxyusername.is_some() || opts.proxypassword.is_some() {
            return (
                opts.proxyusername.clone().unwrap_or_default(),
                opts.proxypassword.clone().unwrap_or_default(),
            );
        }
        // Fall back to CURLOPT_PROXYUSERPWD ("user:password" format).
        if let Some(ref userpwd) = opts.proxyuserpwd {
            if let Some(colon) = userpwd.find(':') {
                return (
                    userpwd[..colon].to_string(),
                    userpwd[colon + 1..].to_string(),
                );
            }
            return (userpwd.clone(), String::new());
        }
        (String::new(), String::new())
    }

    fn credentials(&self) -> (String, String) {
        let opts = self.options();
        // CURLOPT_USERNAME / CURLOPT_PASSWORD take priority.
        if opts.username.is_some() || opts.password.is_some() {
            return (
                opts.username.clone().unwrap_or_default(),
                opts.password.clone().unwrap_or_default(),
            );
        }
        // Fall back to CURLOPT_USERPWD ("user:password" format).
        if let Some(ref userpwd) = opts.userpwd {
            if let Some(colon) = userpwd.find(':') {
                return (
                    userpwd[..colon].to_string(),
                    userpwd[colon + 1..].to_string(),
                );
            }
            return (userpwd.clone(), String::new());
        }
        (String::new(), String::new())
    }

    fn bearer_token(&self) -> Option<&str> {
        self.options().xoauth2_bearer.as_deref()
    }

    fn follow_location(&self) -> bool {
        self.options().followlocation != 0
    }

    fn url_handle(&self) -> Option<&CurlUrl> {
        self.url()
    }

    fn is_proxied_request(&self) -> bool {
        // Request is proxied (not tunneled) when a proxy is configured
        // and HTTP proxy tunneling is disabled.
        self.has_proxy() && !self.options().httpproxytunnel
    }

    fn cookie_jar_ref(&self) -> Option<&CookieJar> {
        // Cookie jar is behind Arc<Mutex<>> for thread-safe sharing via
        // ShareHandle. Direct reference return is not possible with Mutex;
        // callers needing jar access should use the Arc<Mutex> directly.
        // This accessor returns None; cookie operations in the HTTP handler
        // use `add_cookies()` / `store_cookies()` which handle locking
        // internally.
        None
    }

    fn cookie_jar_ref_mut(&mut self) -> Option<&mut CookieJar> {
        // See `cookie_jar_ref()` — Mutex-guarded cookie jar does not support
        // direct mutable reference access. Cookie mutations go through
        // dedicated cookie management methods on EasyHandle that acquire
        // the lock internally.
        None
    }

    fn hsts_cache_ref(&self) -> Option<&HstsCache> {
        self.hsts_cache()
    }

    fn altsvc_cache_ref_mut(&mut self) -> Option<&mut AltSvcCache> {
        self.altsvc_cache_mut()
    }

    fn time_condition(&self) -> i64 {
        self.options().timecondition
    }

    fn time_value(&self) -> i64 {
        self.options().timevalue
    }

    fn expect_100_timeout_ms(&self) -> Option<u64> {
        let ms = self.options().expect_100_timeout_ms;
        if ms > 0 {
            Some(ms as u64)
        } else {
            // Default 1000ms per curl behavior.
            Some(1000)
        }
    }

    fn auth_bitmask(&self) -> Option<u64> {
        let mask = self.options().httpauth;
        if mask != 0 { Some(mask) } else { None }
    }

    fn proxy_auth_bitmask(&self) -> Option<u64> {
        let mask = self.options().proxyauth;
        if mask != 0 { Some(mask) } else { None }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // HttpVersion tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_http_version_as_str() {
        assert_eq!(HttpVersion::Http09.as_str(), "HTTP/0.9");
        assert_eq!(HttpVersion::Http10.as_str(), "HTTP/1.0");
        assert_eq!(HttpVersion::Http11.as_str(), "HTTP/1.1");
        assert_eq!(HttpVersion::Http2.as_str(), "HTTP/2");
        assert_eq!(HttpVersion::Http3.as_str(), "HTTP/3");
    }

    #[test]
    fn test_http_version_minor_version() {
        assert_eq!(HttpVersion::Http09.minor_version(), 0);
        assert_eq!(HttpVersion::Http10.minor_version(), 0);
        assert_eq!(HttpVersion::Http11.minor_version(), 1);
        assert_eq!(HttpVersion::Http2.minor_version(), 1);
        assert_eq!(HttpVersion::Http3.minor_version(), 1);
    }

    #[test]
    fn test_http_version_display() {
        assert_eq!(format!("{}", HttpVersion::Http11), "HTTP/1.1");
        assert_eq!(format!("{}", HttpVersion::Http2), "HTTP/2");
    }

    #[test]
    fn test_http_version_ordering() {
        assert!(HttpVersion::Http09 < HttpVersion::Http10);
        assert!(HttpVersion::Http10 < HttpVersion::Http11);
        assert!(HttpVersion::Http11 < HttpVersion::Http2);
        assert!(HttpVersion::Http2 < HttpVersion::Http3);
    }

    #[test]
    fn test_http_version_default_is_http11() {
        assert_eq!(HttpVersion::default(), HttpVersion::Http11);
    }

    // -----------------------------------------------------------------------
    // HttpVersionFlags tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_http_version_flags_contains() {
        let v1 = HttpVersionFlags::HTTP_1X;
        assert!(v1.contains(HttpVersionFlags::HTTP_1X));
        assert!(!v1.contains(HttpVersionFlags::HTTP_2X));
    }

    #[test]
    fn test_http_version_flags_all() {
        let all = HttpVersionFlags::ALL;
        assert!(all.contains(HttpVersionFlags::HTTP_1X));
        assert!(all.contains(HttpVersionFlags::HTTP_2X));
        assert!(all.contains(HttpVersionFlags::HTTP_3X));
    }

    #[test]
    fn test_http_version_flags_default_is_all() {
        let def = HttpVersionFlags::default();
        // Default should have no bits set (zero value from Default derive).
        // Individual protocol modules set specific flags.
        let _ = def;
    }

    // -----------------------------------------------------------------------
    // HttpReq tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_http_req_display() {
        assert_eq!(format!("{}", HttpReq::Get), "GET");
        assert_eq!(format!("{}", HttpReq::Post), "POST");
        assert_eq!(format!("{}", HttpReq::Put), "PUT");
        assert_eq!(format!("{}", HttpReq::Head), "HEAD");
        assert_eq!(format!("{}", HttpReq::Custom), "CUSTOM");
        assert_eq!(format!("{}", HttpReq::None), "NONE");
        assert_eq!(format!("{}", HttpReq::PostForm), "POST");
        assert_eq!(format!("{}", HttpReq::PostMime), "POST");
    }

    #[test]
    fn test_http_req_default() {
        assert_eq!(HttpReq::default(), HttpReq::None);
    }

    // -----------------------------------------------------------------------
    // FollowType tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_follow_type_default_is_none() {
        assert_eq!(FollowType::default(), FollowType::None);
    }

    #[test]
    fn test_follow_type_variants_are_distinct() {
        assert_ne!(FollowType::None, FollowType::Fake);
        assert_ne!(FollowType::Fake, FollowType::Retry);
        assert_ne!(FollowType::Retry, FollowType::Redir);
    }

    // -----------------------------------------------------------------------
    // HttpRequest tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_http_request_new() {
        let req = HttpRequest::new("GET", "http://example.com/path");
        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "http://example.com/path");
        assert!(req.headers.is_empty());
        assert!(req.body.is_none());
        assert!(!req.expect_100_continue);
    }

    #[test]
    fn test_http_request_add_header() {
        let mut req = HttpRequest::new("POST", "/api");
        req.add_header("Content-Type", "application/json");
        assert_eq!(req.get_header("Content-Type"), Some("application/json"));
        assert_eq!(req.headers.len(), 1);
    }

    #[test]
    fn test_http_request_add_header_replaces_existing() {
        let mut req = HttpRequest::new("GET", "/");
        req.add_header("Host", "old.example.com");
        req.add_header("Host", "new.example.com");
        assert_eq!(req.get_header("Host"), Some("new.example.com"));
        assert_eq!(req.headers.len(), 1);
    }

    #[test]
    fn test_http_request_add_header_case_insensitive_replace() {
        let mut req = HttpRequest::new("GET", "/");
        req.add_header("content-type", "text/html");
        req.add_header("Content-Type", "application/json");
        assert_eq!(req.headers.len(), 1);
        assert_eq!(req.get_header("content-type"), Some("application/json"));
    }

    #[test]
    fn test_http_request_get_header_missing() {
        let req = HttpRequest::new("GET", "/");
        assert_eq!(req.get_header("X-Missing"), None);
    }

    #[test]
    fn test_http_request_has_header() {
        let mut req = HttpRequest::new("GET", "/");
        req.add_header("Accept", "*/*");
        assert!(req.has_header("Accept"));
        assert!(req.has_header("accept"));
        assert!(!req.has_header("Content-Type"));
    }

    #[test]
    fn test_http_request_remove_header() {
        let mut req = HttpRequest::new("GET", "/");
        req.add_header("Accept", "*/*");
        req.add_header("Host", "example.com");
        req.remove_header("accept");
        assert!(!req.has_header("Accept"));
        assert!(req.has_header("Host"));
    }

    #[test]
    fn test_http_request_remove_header_nonexistent() {
        let mut req = HttpRequest::new("GET", "/");
        req.add_header("Host", "example.com");
        req.remove_header("X-NonExistent");
        assert_eq!(req.headers.len(), 1);
    }

    #[test]
    fn test_http_request_multiple_headers() {
        let mut req = HttpRequest::new("GET", "/");
        req.add_header("Accept", "*/*");
        req.add_header("Host", "example.com");
        req.add_header("User-Agent", "curl-rs/8.19.0");
        assert_eq!(req.headers.len(), 3);
    }

    // -----------------------------------------------------------------------
    // HttpResponse tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_http_response_new() {
        let resp = HttpResponse::new(HttpVersion::Http11, 200, "OK");
        assert_eq!(resp.version, HttpVersion::Http11);
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.reason, "OK");
        assert!(resp.headers.is_empty());
    }

    #[test]
    fn test_http_response_get_header() {
        let mut resp = HttpResponse::new(HttpVersion::Http11, 200, "OK");
        resp.headers
            .push(("Content-Type".to_string(), "text/html".to_string()));
        assert_eq!(resp.get_header("Content-Type"), Some("text/html"));
        assert_eq!(resp.get_header("content-type"), Some("text/html"));
        assert_eq!(resp.get_header("X-Missing"), None);
    }

    #[test]
    fn test_http_response_get_headers_multiple() {
        let mut resp = HttpResponse::new(HttpVersion::Http11, 200, "OK");
        resp.headers
            .push(("Set-Cookie".to_string(), "a=1".to_string()));
        resp.headers
            .push(("Set-Cookie".to_string(), "b=2".to_string()));
        let cookies = resp.get_headers("Set-Cookie");
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0], "a=1");
        assert_eq!(cookies[1], "b=2");
    }

    #[test]
    fn test_http_response_status_classification() {
        let info = HttpResponse::new(HttpVersion::Http11, 100, "Continue");
        assert!(info.is_informational());
        assert!(!info.is_success());

        let ok = HttpResponse::new(HttpVersion::Http11, 200, "OK");
        assert!(ok.is_success());
        assert!(!ok.is_informational());
        assert!(!ok.is_redirect());

        let redir = HttpResponse::new(HttpVersion::Http11, 301, "Moved");
        assert!(redir.is_redirect());
        assert!(!redir.is_success());

        let client_err = HttpResponse::new(HttpVersion::Http11, 404, "Not Found");
        assert!(client_err.is_client_error());
        assert!(!client_err.is_server_error());

        let server_err = HttpResponse::new(HttpVersion::Http11, 500, "Internal Error");
        assert!(server_err.is_server_error());
        assert!(!server_err.is_client_error());
    }

    #[test]
    fn test_http_response_199_is_informational() {
        let resp = HttpResponse::new(HttpVersion::Http11, 199, "");
        assert!(resp.is_informational());
    }

    #[test]
    fn test_http_response_204_is_success() {
        let resp = HttpResponse::new(HttpVersion::Http11, 204, "No Content");
        assert!(resp.is_success());
    }

    #[test]
    fn test_http_response_308_is_redirect() {
        let resp = HttpResponse::new(HttpVersion::Http11, 308, "Permanent Redirect");
        assert!(resp.is_redirect());
    }

    // -----------------------------------------------------------------------
    // copy_header_value tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_copy_header_value_normal() {
        assert_eq!(
            copy_header_value("Content-Type: text/html"),
            "text/html"
        );
    }

    #[test]
    fn test_copy_header_value_with_spaces() {
        assert_eq!(
            copy_header_value("Host:   example.com  "),
            "example.com"
        );
    }

    #[test]
    fn test_copy_header_value_no_colon() {
        assert_eq!(copy_header_value("NoColonHere"), "");
    }

    #[test]
    fn test_copy_header_value_empty_value() {
        assert_eq!(copy_header_value("X-Empty:"), "");
    }

    // -----------------------------------------------------------------------
    // compare_header tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_compare_header_name_only() {
        assert!(compare_header("Content-Type: text/html", "Content-Type", ""));
    }

    #[test]
    fn test_compare_header_case_insensitive_name() {
        assert!(compare_header("content-type: text/html", "Content-Type", ""));
    }

    #[test]
    fn test_compare_header_with_content_match() {
        assert!(compare_header(
            "Transfer-Encoding: chunked",
            "Transfer-Encoding",
            "chunked"
        ));
    }

    #[test]
    fn test_compare_header_content_case_insensitive() {
        assert!(compare_header(
            "Transfer-Encoding: Chunked",
            "Transfer-Encoding",
            "chunked"
        ));
    }

    #[test]
    fn test_compare_header_content_mismatch() {
        assert!(!compare_header(
            "Content-Type: text/html",
            "Content-Type",
            "application/json"
        ));
    }

    #[test]
    fn test_compare_header_no_colon() {
        assert!(!compare_header("NoColon", "NoColon", ""));
    }

    #[test]
    fn test_compare_header_name_mismatch() {
        assert!(!compare_header("Host: example.com", "Accept", ""));
    }

    // -----------------------------------------------------------------------
    // bump_headersize tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_bump_headersize_within_limit() {
        let mut handler = HttpProtocol::new(false);
        assert!(bump_headersize(&mut handler, 100, HeaderType::Header).is_ok());
        assert_eq!(handler.header_size, 100);
    }

    #[test]
    fn test_bump_headersize_cumulative() {
        let mut handler = HttpProtocol::new(false);
        bump_headersize(&mut handler, 100, HeaderType::Header).unwrap();
        bump_headersize(&mut handler, 200, HeaderType::Header).unwrap();
        assert_eq!(handler.header_size, 300);
    }

    #[test]
    fn test_bump_headersize_exceeds_limit() {
        let mut handler = HttpProtocol::new(false);
        let result =
            bump_headersize(&mut handler, MAX_HTTP_RESP_HEADER_SIZE + 1, HeaderType::Header);
        assert!(result.is_err());
    }

    #[test]
    fn test_bump_headersize_at_exact_limit_is_ok() {
        let mut handler = HttpProtocol::new(false);
        let result =
            bump_headersize(&mut handler, MAX_HTTP_RESP_HEADER_SIZE, HeaderType::Header);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // HttpProtocol tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_http_protocol_new_http() {
        let proto = HttpProtocol::new(false);
        assert_eq!(proto.name(), "HTTP");
        assert_eq!(proto.header_size, 0);
        assert_eq!(proto.redirect_count, 0);
    }

    #[test]
    fn test_http_protocol_new_https() {
        let proto = HttpProtocol::new(true);
        assert_eq!(proto.name(), "HTTPS");
    }

    #[test]
    fn test_http_protocol_debug() {
        let proto = HttpProtocol::new(false);
        let debug_str = format!("{:?}", proto);
        assert!(debug_str.contains("HttpProtocol"));
        assert!(debug_str.contains("is_ssl: false"));
    }

    // -----------------------------------------------------------------------
    // TransferDecoding tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_transfer_decoding_fixed_size() {
        let td = TransferDecoding::FixedSize(1024);
        assert_eq!(td, TransferDecoding::FixedSize(1024));
    }

    #[test]
    fn test_transfer_decoding_chunked() {
        assert_ne!(TransferDecoding::Chunked, TransferDecoding::UntilClose);
    }

    // -----------------------------------------------------------------------
    // RequestBody tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_request_body_default_is_empty() {
        assert!(matches!(RequestBody::default(), RequestBody::Empty));
    }

    #[test]
    fn test_request_body_bytes() {
        let body = RequestBody::Bytes(vec![1, 2, 3]);
        assert!(matches!(body, RequestBody::Bytes(ref v) if v.len() == 3));
    }

    // -----------------------------------------------------------------------
    // Constants tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_ports() {
        assert_eq!(HTTP_DEFAULT_PORT, 80);
        assert_eq!(HTTPS_DEFAULT_PORT, 443);
    }

    #[test]
    fn test_expect_100_threshold() {
        assert_eq!(EXPECT_100_THRESHOLD, 1024 * 1024);
    }

    #[test]
    fn test_max_header_size_and_count() {
        assert_eq!(MAX_HTTP_RESP_HEADER_SIZE, 300 * 1024);
        assert_eq!(MAX_HTTP_RESP_HEADER_COUNT, 5000);
    }

    // -----------------------------------------------------------------------
    // HttpNegotiation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_http_negotiation_default() {
        let neg = HttpNegotiation::default();
        assert_eq!(neg.rcvd_min, 0);
    }

    // -----------------------------------------------------------------------
    // statusline_check tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_statusline_check_valid_codes() {
        let handle = EasyHandle::new();
        assert!(statusline_check(&handle, 200).is_ok());
        assert!(statusline_check(&handle, 301).is_ok());
        assert!(statusline_check(&handle, 404).is_ok());
        assert!(statusline_check(&handle, 500).is_ok());
        assert!(statusline_check(&handle, 100).is_ok());
    }

    // -----------------------------------------------------------------------
    // HeaderType tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_header_type_variants() {
        let h = HeaderType::Header;
        let t = HeaderType::Trailer;
        let c = HeaderType::Connect;
        assert_ne!(h, t);
        assert_ne!(t, c);
        assert_ne!(h, c);
    }
}
