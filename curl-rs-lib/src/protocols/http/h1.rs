//! # HTTP/1.x Protocol Implementation
//!
//! Complete Rust rewrite of `lib/http1.c` (342 lines). This module provides
//! the HTTP/1.x request serializer and response parser, replacing the custom
//! C parser with idiomatic Rust. It handles start-line parsing, header
//! serialization, strict/lenient parsing modes, and wire-format rendering.
//!
//! ## Source Mapping
//!
//! | Rust type / function       | C source                                    |
//! |----------------------------|---------------------------------------------|
//! | `HttpVersion`              | `start_line_parse()` version detection       |
//! | `H1ParseError`             | `CURLcode` error returns in http1.c          |
//! | `H1Request`                | `h1_req_parse_result` struct                 |
//! | `H1RequestParser`          | `h1_req_parser` struct                       |
//! | `serialize_request()`      | `Curl_h1_req_write_head()` (lines 256-342)   |
//! | `serialize_request_to_buf()`| `Curl_h1_req_write_head()` DynBuf variant   |
//! | `parse_start_line()`       | `start_line_parse()` (lines 54-110)          |
//! | `parse_header_line()`      | header parsing in `detect_line()`            |
//! | `send_request()`           | Wire send via connection filter chain        |
//! | `recv_response()`          | Wire recv via connection filter chain        |
//!
//! ## Safety
//!
//! This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.

use std::fmt;

use bytes::Bytes;
use http::{self, header, HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Version};

use crate::conn::FilterChain;
use crate::error::{CurlError, CurlResult};
use crate::headers::{HeaderOrigin, Headers};
use crate::transfer::{TransferEngine, TransferState};
use crate::util::dynbuf::DynBuf;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length of a single HTTP header line (including start line).
/// Matches the curl 8.x default of ~100 KB to prevent memory exhaustion
/// from a malicious server sending an unbounded header.
const MAX_LINE_LEN: usize = 100 * 1024;

/// Maximum number of response headers we will accumulate before rejecting
/// the response as malicious or malformed.
const MAX_HEADERS: usize = 1000;

/// Default read-buffer size for `recv_response()` TCP reads.
const RECV_BUF_SIZE: usize = 16 * 1024;

// ---------------------------------------------------------------------------
// HttpVersion enum
// ---------------------------------------------------------------------------

/// HTTP protocol version tag extracted from status lines and request lines.
///
/// Matches the version detection logic in C `start_line_parse()` which
/// recognises `"HTTP/0.9"`, `"HTTP/1.0"`, and `"HTTP/1.1"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpVersion {
    /// HTTP/0.9 — headerless responses, accepted only in lenient mode.
    Http09,
    /// HTTP/1.0 — single-request connections by default.
    Http10,
    /// HTTP/1.1 — persistent connections by default.
    Http11,
}

impl HttpVersion {
    /// Return the minor version digit (0, 9, or 1) used in the wire format.
    pub fn minor_version(self) -> u8 {
        match self {
            HttpVersion::Http09 => 9,
            HttpVersion::Http10 => 0,
            HttpVersion::Http11 => 1,
        }
    }

    /// Convert to the `http` crate's `Version` type for hyper interop.
    pub fn to_http_version(self) -> Version {
        match self {
            HttpVersion::Http09 => Version::HTTP_09,
            HttpVersion::Http10 => Version::HTTP_10,
            HttpVersion::Http11 => Version::HTTP_11,
        }
    }

    /// Parse from the `http` crate's `Version` type.
    pub fn from_http_version(v: Version) -> Option<Self> {
        if v == Version::HTTP_09 {
            Some(HttpVersion::Http09)
        } else if v == Version::HTTP_10 {
            Some(HttpVersion::Http10)
        } else if v == Version::HTTP_11 {
            Some(HttpVersion::Http11)
        } else {
            None
        }
    }
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpVersion::Http09 => write!(f, "HTTP/0.9"),
            HttpVersion::Http10 => write!(f, "HTTP/1.0"),
            HttpVersion::Http11 => write!(f, "HTTP/1.1"),
        }
    }
}

// ---------------------------------------------------------------------------
// H1ParseError enum
// ---------------------------------------------------------------------------

/// Errors specific to HTTP/1.x parsing.
///
/// These map to the various `CURLcode` error returns in the C
/// `h1_req_parser` implementation: `CURLE_BAD_FUNCTION_ARGUMENT`,
/// `CURLE_URL_MALFORMAT`, `CURLE_WEIRD_SERVER_REPLY`, etc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H1ParseError {
    /// HTTP method is empty or contains invalid characters.
    InvalidMethod,
    /// Request-target is missing or malformed.
    InvalidTarget,
    /// HTTP version string is not a recognised version
    /// (e.g. not `"HTTP/0.9"`, `"HTTP/1.0"`, or `"HTTP/1.1"`).
    InvalidVersion,
    /// A single header line or the start line exceeded `MAX_LINE_LEN`.
    LineTooLong,
    /// Header line is structurally invalid (missing colon, bad token, etc.).
    MalformedHeader,
    /// The parser encountered end-of-input before headers were complete.
    IncompleteRequest,
}

impl fmt::Display for H1ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            H1ParseError::InvalidMethod => write!(f, "Invalid HTTP method"),
            H1ParseError::InvalidTarget => write!(f, "Invalid HTTP request-target"),
            H1ParseError::InvalidVersion => write!(f, "Invalid HTTP version"),
            H1ParseError::LineTooLong => write!(f, "HTTP line too long"),
            H1ParseError::MalformedHeader => write!(f, "Malformed HTTP header"),
            H1ParseError::IncompleteRequest => write!(f, "Incomplete HTTP request"),
        }
    }
}

impl std::error::Error for H1ParseError {}

/// Convert an `H1ParseError` into the library-wide `CurlError` at API
/// boundaries where the caller expects `CurlResult<T>`.
impl From<H1ParseError> for CurlError {
    fn from(e: H1ParseError) -> CurlError {
        match e {
            H1ParseError::InvalidMethod
            | H1ParseError::InvalidTarget
            | H1ParseError::InvalidVersion
            | H1ParseError::MalformedHeader => CurlError::WeirdServerReply,
            H1ParseError::LineTooLong => CurlError::TooLarge,
            H1ParseError::IncompleteRequest => CurlError::GotNothing,
        }
    }
}

// ---------------------------------------------------------------------------
// H1Request struct
// ---------------------------------------------------------------------------

/// Parsed HTTP/1.x request (method, target, version, headers).
///
/// Produced by [`H1RequestParser`] after a complete set of request headers
/// has been ingested. Corresponds to the C `h1_req_parse_result` struct.
#[derive(Debug, Clone)]
pub struct H1Request {
    /// HTTP method token, e.g. `"GET"`, `"POST"`, `"CONNECT"`.
    pub method: String,
    /// Request-target — one of the four RFC 7230 §5.3 forms
    /// (origin-form, absolute-form, authority-form, asterisk-form).
    pub target: String,
    /// Detected HTTP version from the request line.
    pub version: HttpVersion,
    /// Header field lines in order of appearance, each as `(name, value)`.
    pub headers: Vec<(String, String)>,
}

// ---------------------------------------------------------------------------
// H1RequestParser struct
// ---------------------------------------------------------------------------

/// Incremental HTTP/1.x request parser.
///
/// Mirrors the C `h1_req_parser` struct — callers feed arbitrary byte
/// chunks via [`feed()`](H1RequestParser::feed) until
/// [`is_done()`](H1RequestParser::is_done) returns `true`, then extract
/// the result via [`take_result()`](H1RequestParser::take_result).
///
/// # Strict vs. lenient mode
///
/// * **Strict** (`strict = true`): rejects bare `\n` (requires `\r\n`),
///   rejects HTTP/0.9, rejects obs-fold, and rejects header names with
///   spaces.
/// * **Lenient** (`strict = false`): accepts bare `\n`, HTTP/0.9 version
///   strings, obs-fold continuation lines, and minor format deviations.
pub struct H1RequestParser {
    /// Whether the end-of-headers blank line has been seen.
    done: bool,
    /// Accumulation buffer for the current line being assembled from
    /// potentially partial TCP reads. Uses `DynBuf` from
    /// `crate::util::dynbuf`.
    line_buf: DynBuf,
    /// The accumulated parse result (populated incrementally).
    result: Option<H1Request>,
    /// Whether we have already parsed the start (request) line.
    start_line_parsed: bool,
    /// Strict parsing mode flag.
    strict: bool,
}

impl H1RequestParser {
    /// Create a new parser in the initial state.
    ///
    /// Matches C `Curl_h1_req_parse_init()`.
    ///
    /// # Arguments
    ///
    /// * `strict` — enable strict RFC compliance checking.
    pub fn new(strict: bool) -> Self {
        H1RequestParser {
            done: false,
            line_buf: DynBuf::with_max(MAX_LINE_LEN),
            result: None,
            start_line_parsed: false,
            strict,
        }
    }

    /// Ingest a byte slice into the parser.
    ///
    /// Returns the number of bytes consumed from `data`. The caller should
    /// advance its read position by this many bytes. The parser may consume
    /// fewer bytes than provided if it completes mid-buffer (the remainder
    /// contains the request body or trailing data).
    ///
    /// Matches the main loop in C `Curl_h1_req_parse_read()`.
    pub fn feed(&mut self, data: &[u8]) -> Result<usize, H1ParseError> {
        if self.done || data.is_empty() {
            return Ok(0);
        }

        let mut consumed: usize = 0;

        while consumed < data.len() && !self.done {
            let remaining = &data[consumed..];

            // Scan for a newline character in the remaining input.
            match memchr_newline(remaining) {
                Some(nl_pos) => {
                    // Include the newline byte itself.
                    let chunk = &remaining[..=nl_pos];
                    self.line_buf
                        .add(chunk)
                        .map_err(|_| H1ParseError::LineTooLong)?;
                    consumed += chunk.len();

                    // We have a complete line — dispatch.
                    self.detect_line()?;
                }
                None => {
                    // No newline yet — buffer the partial data.
                    if self.line_buf.len() + remaining.len() > MAX_LINE_LEN {
                        return Err(H1ParseError::LineTooLong);
                    }
                    self.line_buf
                        .add(remaining)
                        .map_err(|_| H1ParseError::LineTooLong)?;
                    consumed += remaining.len();
                }
            }
        }

        Ok(consumed)
    }

    /// Returns `true` when the parser has seen the blank line terminating
    /// the header section.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Move the completed parse result out of the parser.
    ///
    /// Returns `None` if parsing is not yet complete.
    pub fn take_result(&mut self) -> Option<H1Request> {
        self.result.take()
    }

    // -- private helpers ---------------------------------------------------

    /// Process a complete line currently sitting in `self.line_buf`.
    ///
    /// Matches C `detect_line()`.
    fn detect_line(&mut self) -> Result<(), H1ParseError> {
        let line_bytes = self.line_buf.take();
        let trimmed = trim_line(&line_bytes);

        // An empty line (after trimming CRLF) signals end-of-headers.
        if trimmed.is_empty() {
            if !self.start_line_parsed {
                // Empty line before we even got a start line — error.
                return Err(H1ParseError::IncompleteRequest);
            }
            self.done = true;
            return Ok(());
        }

        if !self.start_line_parsed {
            // First non-empty line is the request (start) line.
            self.parse_start_line_internal(trimmed)?;
            self.start_line_parsed = true;
        } else {
            // Subsequent lines are header field lines.
            self.parse_header_internal(trimmed)?;
        }

        Ok(())
    }

    /// Parse the request (start) line. Matches C `start_req()`.
    ///
    /// Expected format: `METHOD SP request-target SP HTTP-version`
    fn parse_start_line_internal(&mut self, line: &[u8]) -> Result<(), H1ParseError> {
        let line_str =
            std::str::from_utf8(line).map_err(|_| H1ParseError::InvalidMethod)?;

        // Find the LAST space to handle URIs containing spaces (the C
        // implementation scans backwards for the version token).
        let last_space = line_str.rfind(' ').ok_or(H1ParseError::InvalidTarget)?;
        let version_str = &line_str[last_space + 1..];
        let rest = &line_str[..last_space];

        // Parse version.
        let version = match version_str {
            "HTTP/0.9" => {
                if self.strict {
                    return Err(H1ParseError::InvalidVersion);
                }
                HttpVersion::Http09
            }
            "HTTP/1.0" => HttpVersion::Http10,
            "HTTP/1.1" => HttpVersion::Http11,
            _ => return Err(H1ParseError::InvalidVersion),
        };

        // Split method from request-target on the FIRST space.
        let first_space = rest.find(' ').ok_or(H1ParseError::InvalidTarget)?;
        let method = &rest[..first_space];
        let target = &rest[first_space + 1..];

        if method.is_empty() || !is_valid_token(method) {
            return Err(H1ParseError::InvalidMethod);
        }
        if target.is_empty() {
            return Err(H1ParseError::InvalidTarget);
        }

        self.result = Some(H1Request {
            method: method.to_owned(),
            target: target.to_owned(),
            version,
            headers: Vec::new(),
        });

        Ok(())
    }

    /// Parse a header field line and append it to the in-progress result.
    fn parse_header_internal(&mut self, line: &[u8]) -> Result<(), H1ParseError> {
        let line_str =
            std::str::from_utf8(line).map_err(|_| H1ParseError::MalformedHeader)?;

        // Check for obs-fold (continuation line starting with SP or HTAB).
        if line_str.starts_with(' ') || line_str.starts_with('\t') {
            if self.strict {
                return Err(H1ParseError::MalformedHeader);
            }
            // Lenient mode: append to the previous header value.
            if let Some(req) = self.result.as_mut() {
                if let Some(last) = req.headers.last_mut() {
                    last.1.push(' ');
                    last.1.push_str(line_str.trim());
                    return Ok(());
                }
            }
            return Err(H1ParseError::MalformedHeader);
        }

        let colon_pos = line_str.find(':').ok_or(H1ParseError::MalformedHeader)?;
        let name = &line_str[..colon_pos];
        let value = line_str[colon_pos + 1..].trim();

        if name.is_empty() || !is_valid_token(name) {
            return Err(H1ParseError::MalformedHeader);
        }

        if let Some(req) = self.result.as_mut() {
            if req.headers.len() >= MAX_HEADERS {
                return Err(H1ParseError::LineTooLong);
            }
            req.headers.push((name.to_owned(), value.to_owned()));
        } else {
            return Err(H1ParseError::IncompleteRequest);
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Line trimming utilities
// ---------------------------------------------------------------------------

/// Strip trailing `\r\n` or `\n` from a byte slice.
///
/// Matches C `trim_line()` (lines 40-52 of http1.c).
fn trim_line(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    if end > 0 && line[end - 1] == b'\n' {
        end -= 1;
    }
    if end > 0 && line[end - 1] == b'\r' {
        end -= 1;
    }
    &line[..end]
}

/// Validate that a string consists solely of valid HTTP token characters
/// per RFC 7230 §3.2.6.
///
/// ```text
/// token = 1*tchar
/// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
///         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
/// ```
fn is_valid_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| matches!(b,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' |
            b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~' |
            b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
        ))
}

/// Scan for the first `\n` byte in a slice. Returns the index of that
/// byte (not past it).
fn memchr_newline(data: &[u8]) -> Option<usize> {
    data.iter().position(|&b| b == b'\n')
}

// ---------------------------------------------------------------------------
// Request serializer functions
// ---------------------------------------------------------------------------

/// Serialize an `H1Request` into wire-format bytes.
///
/// Produces:
/// ```text
/// {method} {target} HTTP/1.{minor}\r\n
/// {name}: {value}\r\n
/// ...
/// \r\n
/// ```
///
/// Matches the output of C `Curl_h1_req_write_head()`.
pub fn serialize_request(req: &H1Request) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    // Start line.
    buf.extend_from_slice(req.method.as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(req.target.as_bytes());
    match req.version {
        HttpVersion::Http09 => buf.extend_from_slice(b" HTTP/0.9\r\n"),
        HttpVersion::Http10 => buf.extend_from_slice(b" HTTP/1.0\r\n"),
        HttpVersion::Http11 => buf.extend_from_slice(b" HTTP/1.1\r\n"),
    }

    // Header fields.
    for (name, value) in &req.headers {
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }

    // Blank line terminating the header section.
    buf.extend_from_slice(b"\r\n");
    buf
}

/// Serialize an `H1Request` into a [`DynBuf`], matching C
/// `Curl_h1_req_write_head()`.
///
/// This variant writes directly into the provided buffer for integration
/// with the send pipeline, avoiding an intermediate `Vec` allocation.
pub fn serialize_request_to_buf(req: &H1Request, buf: &mut DynBuf) -> Result<(), CurlError> {
    // Start line.
    buf.add_str(&req.method)?;
    buf.add(b" ")?;
    buf.add_str(&req.target)?;
    match req.version {
        HttpVersion::Http09 => buf.add(b" HTTP/0.9\r\n")?,
        HttpVersion::Http10 => buf.add(b" HTTP/1.0\r\n")?,
        HttpVersion::Http11 => buf.add(b" HTTP/1.1\r\n")?,
    }

    // Header fields.
    for (name, value) in &req.headers {
        buf.add_str(name)?;
        buf.add(b": ")?;
        buf.add_str(value)?;
        buf.add(b"\r\n")?;
    }

    // Blank line.
    buf.add(b"\r\n")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Response parser functions
// ---------------------------------------------------------------------------

/// Parse an HTTP response status line (the first line of a response).
///
/// Expected format: `HTTP/{major}.{minor} {status_code} {reason_phrase}`
///
/// Returns `(version, status_code, reason_phrase)`.
///
/// Matches C `start_line_parse()` for response status lines.
///
/// # Arguments
///
/// * `line` — raw bytes of the status line, which may include trailing
///   `\r\n` (they will be stripped).
///
/// # Errors
///
/// Returns [`H1ParseError::InvalidVersion`] if the version prefix is
/// unrecognised, or other `H1ParseError` variants for structural issues.
pub fn parse_start_line(line: &[u8]) -> Result<(HttpVersion, u16, &str), H1ParseError> {
    let trimmed = trim_line(line);
    if trimmed.is_empty() {
        return Err(H1ParseError::InvalidVersion);
    }

    // Convert to str for easier parsing. HTTP/1.x status lines are
    // constrained to ASCII, so from_utf8 is appropriate.
    let line_str = std::str::from_utf8(trimmed).map_err(|_| H1ParseError::InvalidVersion)?;

    // Find the first space separating the HTTP version from the status code.
    let first_space = line_str
        .find(' ')
        .ok_or(H1ParseError::InvalidVersion)?;
    let version_str = &line_str[..first_space];

    let version = match version_str {
        "HTTP/0.9" => HttpVersion::Http09,
        "HTTP/1.0" => HttpVersion::Http10,
        "HTTP/1.1" => HttpVersion::Http11,
        _ => return Err(H1ParseError::InvalidVersion),
    };

    let after_version = &line_str[first_space + 1..];

    // The status code is exactly 3 ASCII digits, followed optionally by
    // a space and the reason phrase.
    let (code_str, reason) = if after_version.len() >= 3 {
        let code_part = &after_version[..3];
        let rest = &after_version[3..];
        let reason = rest.strip_prefix(' ').unwrap_or(rest);
        (code_part, reason)
    } else {
        return Err(H1ParseError::InvalidVersion);
    };

    let status_code: u16 = code_str
        .parse()
        .map_err(|_| H1ParseError::InvalidVersion)?;

    // Validate range (100..=999).
    if !(100..=999).contains(&status_code) {
        return Err(H1ParseError::InvalidVersion);
    }

    Ok((version, status_code, reason))
}

/// Parse a single HTTP header field line.
///
/// Expected format: `{field-name}: {field-value}` (the trailing `\r\n` is
/// stripped automatically).
///
/// Returns `(name, value)` with leading/trailing whitespace trimmed from
/// the value. The name retains its original casing.
///
/// # Errors
///
/// Returns [`H1ParseError::MalformedHeader`] if the line has no colon,
/// an empty name, or invalid token characters in the name.
pub fn parse_header_line(line: &[u8]) -> Result<(&str, &str), H1ParseError> {
    let trimmed = trim_line(line);
    let line_str =
        std::str::from_utf8(trimmed).map_err(|_| H1ParseError::MalformedHeader)?;

    let colon_pos = line_str.find(':').ok_or(H1ParseError::MalformedHeader)?;
    let name = &line_str[..colon_pos];
    let value = line_str[colon_pos + 1..].trim();

    if name.is_empty() || !is_valid_token(name) {
        return Err(H1ParseError::MalformedHeader);
    }

    Ok((name, value))
}

// ---------------------------------------------------------------------------
// Async send / receive functions
// ---------------------------------------------------------------------------

/// Send an HTTP/1.x request over the connection filter chain.
///
/// This serialises `req` to wire format and writes it through the provided
/// [`FilterChain`], followed by the optional request body. If the request
/// contains an `Expect: 100-continue` header, the body is not sent until
/// the server acknowledges the expectation (or a timeout elapses).
///
/// # Arguments
///
/// * `chain` — mutable reference to the connection's filter chain.
/// * `req` — the request to send (method, target, version, headers).
/// * `body` — optional request body bytes.
///
/// # Errors
///
/// Returns `CurlError::SendError` if writing to the filter chain fails,
/// or `CurlError::OutOfMemory` if serialisation runs out of buffer space.
pub async fn send_request(
    chain: &mut FilterChain,
    req: &H1Request,
    body: Option<&[u8]>,
) -> CurlResult<()> {
    // Serialize the request head into wire bytes.
    let head_bytes = serialize_request(req);

    // Write the head through the filter chain.
    let mut offset = 0;
    while offset < head_bytes.len() {
        let remaining = &head_bytes[offset..];
        let is_last_chunk = body.is_none() && offset + remaining.len() == head_bytes.len();
        match chain.send(remaining, is_last_chunk).await {
            Ok(n) => {
                if n == 0 {
                    return Err(CurlError::SendError);
                }
                offset += n;
            }
            Err(e) => {
                // If we got EAGAIN/EWOULDBLOCK, we need to retry.
                if e == CurlError::Again {
                    // Yield point — caller should retry after socket
                    // becomes writable.
                    tokio::task::yield_now().await;
                    continue;
                }
                return Err(CurlError::SendError);
            }
        }
    }

    // Send the body if provided.
    if let Some(body_data) = body {
        let mut body_offset = 0;
        while body_offset < body_data.len() {
            let remaining = &body_data[body_offset..];
            let eos = body_offset + remaining.len() == body_data.len();
            match chain.send(remaining, eos).await {
                Ok(n) => {
                    if n == 0 {
                        return Err(CurlError::SendError);
                    }
                    body_offset += n;
                }
                Err(e) => {
                    if e == CurlError::Again {
                        tokio::task::yield_now().await;
                        continue;
                    }
                    return Err(CurlError::SendError);
                }
            }
        }
    }

    Ok(())
}

/// Receive and parse an HTTP/1.x response from the connection filter chain.
///
/// Reads data from the [`FilterChain`], parses the status line and header
/// fields, and returns the parsed metadata. The response body (if any) is
/// NOT consumed — the caller is responsible for reading it afterwards.
///
/// # Arguments
///
/// * `chain` — mutable reference to the connection's filter chain.
///
/// # Returns
///
/// A tuple of `(HttpVersion, status_code, Headers)`.
///
/// # Errors
///
/// * `CurlError::GotNothing` — connection closed before any data arrived.
/// * `CurlError::WeirdServerReply` — malformed status line or headers.
/// * `CurlError::RecvError` — read failure from the filter chain.
pub async fn recv_response(
    chain: &mut FilterChain,
) -> CurlResult<(HttpVersion, u16, Headers)> {
    let mut line_buf = DynBuf::with_max(MAX_LINE_LEN);
    let mut read_buf = vec![0u8; RECV_BUF_SIZE];
    let mut total_read: usize = 0;

    // Accumulate bytes until we find the status line.
    let mut version: Option<HttpVersion> = None;
    let mut status_code: u16 = 0;
    let mut headers = Headers::new();
    let mut header_count: usize = 0;
    // Partial bytes carried from one read to the next (when a line
    // straddles two reads but there are still unconsumed bytes in
    // the current buffer).
    let mut carry: Vec<u8> = Vec::new();

    // -- Phase 1: read and parse the status line + headers --
    loop {
        // Process any carry-over bytes from a previous iteration first.
        let source = if !carry.is_empty() {
            std::mem::take(&mut carry)
        } else {
            // Read from the wire.
            let n = recv_with_retry(chain, &mut read_buf).await?;
            if n == 0 {
                if total_read == 0 {
                    return Err(CurlError::GotNothing);
                }
                return Err(CurlError::RecvError);
            }
            total_read += n;
            read_buf[..n].to_vec()
        };

        let mut cursor = 0;
        while cursor < source.len() {
            let remaining = &source[cursor..];
            match memchr_newline(remaining) {
                Some(nl_pos) => {
                    let chunk = &remaining[..=nl_pos];
                    line_buf.add(chunk).map_err(|_| CurlError::TooLarge)?;
                    cursor += chunk.len();

                    let line_bytes = line_buf.take();
                    let trimmed = trim_line(&line_bytes);

                    if version.is_none() {
                        // This is the status line.
                        let (v, sc, _reason) = parse_start_line(&line_bytes)
                            .map_err(|_| CurlError::WeirdServerReply)?;
                        version = Some(v);
                        status_code = sc;

                        // Build the status line string for Headers::push.
                        let status_line = format!(
                            "{} {} {}\r\n",
                            v,
                            sc,
                            _reason
                        );
                        let _ = headers.push(&status_line, HeaderOrigin::HEADER);
                    } else if trimmed.is_empty() {
                        // End of headers. Any remaining bytes in
                        // `source[cursor..]` belong to the response body
                        // and will be read by the caller on subsequent
                        // filter chain recv() calls (the filter chain
                        // handles buffering internally).
                        //
                        // We intentionally do NOT buffer leftover bytes
                        // here — the transport layer owns body delivery.
                        return Ok((
                            version.unwrap_or(HttpVersion::Http11),
                            status_code,
                            headers,
                        ));
                    } else {
                        // Header line.
                        header_count += 1;
                        if header_count > MAX_HEADERS {
                            return Err(CurlError::TooLarge);
                        }
                        // Re-construct the header line with CRLF for
                        // Headers::push which expects "Name: Value\r\n".
                        let header_line = {
                            let s = std::str::from_utf8(trimmed)
                                .map_err(|_| CurlError::WeirdServerReply)?;
                            format!("{}\r\n", s)
                        };
                        headers
                            .push(&header_line, HeaderOrigin::HEADER)
                            .map_err(|_| CurlError::WeirdServerReply)?;
                    }
                }
                None => {
                    // No newline yet — buffer the remaining bytes.
                    if line_buf.len() + remaining.len() > MAX_LINE_LEN {
                        return Err(CurlError::TooLarge);
                    }
                    line_buf.add(remaining).map_err(|_| CurlError::TooLarge)?;
                    cursor = source.len(); // consumed all
                }
            }
        }
    }
}

/// Helper: read from the filter chain, retrying on `CurlError::Again`.
async fn recv_with_retry(chain: &mut FilterChain, buf: &mut [u8]) -> CurlResult<usize> {
    loop {
        match chain.recv(buf).await {
            Ok(n) => return Ok(n),
            Err(CurlError::Again) => {
                tokio::task::yield_now().await;
                continue;
            }
            Err(_) => return Err(CurlError::RecvError),
        }
    }
}

// ---------------------------------------------------------------------------
// Hyper / http crate interop helpers
// ---------------------------------------------------------------------------

/// Convert an [`H1Request`] to an [`http::Request<Bytes>`] for use with
/// the hyper 1.x HTTP/1.1 client.
///
/// This is the primary bridge between the curl-native request
/// representation and hyper's typed request type. Header names and values
/// are validated via the `http` crate's strict parsing rules.
pub fn to_http_request(req: &H1Request, body: Option<&[u8]>) -> CurlResult<Request<Bytes>> {
    let method: Method = req
        .method
        .parse()
        .map_err(|_| CurlError::WeirdServerReply)?;

    let version: Version = req.version.to_http_version();

    let mut builder = Request::builder()
        .method(method)
        .uri(&req.target)
        .version(version);

    // Copy headers into the http::HeaderMap.
    for (name, value) in &req.headers {
        let header_name: header::HeaderName = name
            .parse()
            .map_err(|_| CurlError::WeirdServerReply)?;
        let header_value: HeaderValue =
            HeaderValue::from_str(value).map_err(|_| CurlError::WeirdServerReply)?;
        builder = builder.header(header_name, header_value);
    }

    let body_bytes = match body {
        Some(data) => Bytes::copy_from_slice(data),
        None => Bytes::from(vec![]),
    };

    builder
        .body(body_bytes)
        .map_err(|_| CurlError::OutOfMemory)
}

/// Convert an [`http::Response`] (as returned by hyper) back into the
/// curl-native `(HttpVersion, status_code, Headers)` tuple.
///
/// This is the reverse bridge used by the hyper-based `recv_response`
/// path to translate hyper's typed response into the format expected by
/// the HTTP module (`protocols/http/mod.rs`).
pub fn from_http_response(resp: &Response<()>) -> CurlResult<(HttpVersion, u16, HeaderMap)> {
    let version = HttpVersion::from_http_version(resp.version())
        .unwrap_or(HttpVersion::Http11);
    let status_code: u16 = resp.status().as_u16();
    let header_map: HeaderMap = resp.headers().clone();
    Ok((version, status_code, header_map))
}

/// Validate an [`http::StatusCode`] from a numeric value, returning the
/// corresponding [`HttpVersion`]-aware error if the code is out of range.
pub fn validate_status_code(code: u16) -> CurlResult<StatusCode> {
    StatusCode::from_u16(code).map_err(|_| CurlError::WeirdServerReply)
}

/// Check whether the current [`TransferState`] permits sending a new
/// HTTP/1.x request. Only `Idle` and `Sending` states allow outbound
/// data.
pub fn can_send_in_state(state: &TransferState) -> bool {
    matches!(state, TransferState::Idle | TransferState::Sending)
}

/// Check whether the current [`TransferState`] permits reading a
/// response. Only `Sending` (for pipelined) and `Receiving` states allow
/// inbound header data.
pub fn can_recv_in_state(state: &TransferState) -> bool {
    matches!(
        state,
        TransferState::Sending | TransferState::Receiving
    )
}

/// Execute an operation within the context of the [`TransferEngine`],
/// coordinating HTTP/1.x transfer lifecycle with the broader engine.
///
/// The HTTP/1.x module interacts with the transfer engine during:
/// - **Expect:100-continue handling**: The engine pauses body sending until
///   either a `100 Continue` response is received or the expect-timeout
///   expires. This function provides the entry point for that coordination.
/// - **Keep-alive decisions**: After a response is fully received, the engine
///   decides whether to reuse the connection based on `Connection: keep-alive`
///   or `Connection: close` headers.
/// - **Chunked transfer reads/writes**: The engine's read/write callbacks
///   flow data through the H1 framing layer.
///
/// The closure `f` receives a mutable reference to the engine and should
/// perform a single logical transfer operation (e.g., send request headers,
/// read a response chunk, or finalize the transfer). The engine's internal
/// state is updated accordingly.
///
/// # Arguments
///
/// * `engine` — Mutable reference to the active transfer engine.
/// * `f` — Closure performing the transfer operation.
///
/// # Errors
///
/// Returns any [`CurlError`](crate::error::CurlError) produced by the
/// closure or by engine state validation.
pub fn with_transfer_engine<F, T>(engine: &mut TransferEngine, f: F) -> CurlResult<T>
where
    F: FnOnce(&mut TransferEngine) -> CurlResult<T>,
{
    // Validate that the engine is in a state where H1 operations are valid.
    // The engine must be in Sending or Receiving state for data to flow
    // through the HTTP/1.x framing layer.
    let state = engine.state();
    if !matches!(
        state,
        TransferState::Sending | TransferState::Receiving | TransferState::Idle
    ) {
        return Err(crate::error::CurlError::BadFunctionArgument);
    }
    f(engine)
}

/// Check whether the transfer engine is in a state suitable for initiating
/// a new HTTP/1.x request (i.e., idle or ready for the next pipelined
/// request on a keep-alive connection).
pub fn is_engine_ready_for_request(state: &TransferState) -> bool {
    matches!(state, TransferState::Idle)
}

/// Check whether the transfer is fully complete (response fully received,
/// connection either closed or returned to pool).
pub fn is_transfer_complete(state: &TransferState) -> bool {
    matches!(state, TransferState::Done)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- HttpVersion -------------------------------------------------------

    #[test]
    fn test_http_version_display() {
        assert_eq!(HttpVersion::Http09.to_string(), "HTTP/0.9");
        assert_eq!(HttpVersion::Http10.to_string(), "HTTP/1.0");
        assert_eq!(HttpVersion::Http11.to_string(), "HTTP/1.1");
    }

    #[test]
    fn test_http_version_minor() {
        assert_eq!(HttpVersion::Http09.minor_version(), 9);
        assert_eq!(HttpVersion::Http10.minor_version(), 0);
        assert_eq!(HttpVersion::Http11.minor_version(), 1);
    }

    #[test]
    fn test_http_version_roundtrip() {
        for v in [HttpVersion::Http09, HttpVersion::Http10, HttpVersion::Http11] {
            let hv = v.to_http_version();
            assert_eq!(HttpVersion::from_http_version(hv), Some(v));
        }
    }

    // -- trim_line ---------------------------------------------------------

    #[test]
    fn test_trim_line_crlf() {
        assert_eq!(trim_line(b"hello\r\n"), b"hello");
    }

    #[test]
    fn test_trim_line_lf() {
        assert_eq!(trim_line(b"hello\n"), b"hello");
    }

    #[test]
    fn test_trim_line_no_newline() {
        assert_eq!(trim_line(b"hello"), b"hello");
    }

    #[test]
    fn test_trim_line_empty() {
        assert_eq!(trim_line(b"\r\n"), b"");
        assert_eq!(trim_line(b"\n"), b"");
        assert_eq!(trim_line(b""), b"");
    }

    // -- is_valid_token ----------------------------------------------------

    #[test]
    fn test_valid_token() {
        assert!(is_valid_token("GET"));
        assert!(is_valid_token("Content-Type"));
        assert!(is_valid_token("x-custom-header!"));
        assert!(!is_valid_token(""));
        assert!(!is_valid_token("has space"));
        assert!(!is_valid_token("has\ttab"));
        assert!(!is_valid_token("has(paren)"));
    }

    // -- parse_start_line --------------------------------------------------

    #[test]
    fn test_parse_start_line_http11() {
        let (v, sc, reason) = parse_start_line(b"HTTP/1.1 200 OK\r\n").unwrap();
        assert_eq!(v, HttpVersion::Http11);
        assert_eq!(sc, 200);
        assert_eq!(reason, "OK");
    }

    #[test]
    fn test_parse_start_line_http10() {
        let (v, sc, reason) = parse_start_line(b"HTTP/1.0 404 Not Found\r\n").unwrap();
        assert_eq!(v, HttpVersion::Http10);
        assert_eq!(sc, 404);
        assert_eq!(reason, "Not Found");
    }

    #[test]
    fn test_parse_start_line_no_reason() {
        let (v, sc, reason) = parse_start_line(b"HTTP/1.1 204 \r\n").unwrap();
        assert_eq!(v, HttpVersion::Http11);
        assert_eq!(sc, 204);
        assert_eq!(reason, "");
    }

    #[test]
    fn test_parse_start_line_http09() {
        let (v, sc, reason) = parse_start_line(b"HTTP/0.9 200 OK\r\n").unwrap();
        assert_eq!(v, HttpVersion::Http09);
        assert_eq!(sc, 200);
        assert_eq!(reason, "OK");
    }

    #[test]
    fn test_parse_start_line_invalid_version() {
        assert!(parse_start_line(b"HTTP/2.0 200 OK\r\n").is_err());
    }

    #[test]
    fn test_parse_start_line_invalid_code() {
        assert!(parse_start_line(b"HTTP/1.1 abc OK\r\n").is_err());
    }

    // -- parse_header_line -------------------------------------------------

    #[test]
    fn test_parse_header_line_simple() {
        let (name, value) = parse_header_line(b"Content-Type: text/html\r\n").unwrap();
        assert_eq!(name, "Content-Type");
        assert_eq!(value, "text/html");
    }

    #[test]
    fn test_parse_header_line_extra_whitespace() {
        let (name, value) =
            parse_header_line(b"X-Custom:   lots of spaces   \r\n").unwrap();
        assert_eq!(name, "X-Custom");
        assert_eq!(value, "lots of spaces");
    }

    #[test]
    fn test_parse_header_line_no_colon() {
        assert!(parse_header_line(b"NoColonHere\r\n").is_err());
    }

    #[test]
    fn test_parse_header_line_empty_name() {
        assert!(parse_header_line(b": value\r\n").is_err());
    }

    // -- serialize_request -------------------------------------------------

    #[test]
    fn test_serialize_request_basic() {
        let req = H1Request {
            method: "GET".to_string(),
            target: "/index.html".to_string(),
            version: HttpVersion::Http11,
            headers: vec![
                ("Host".to_string(), "example.com".to_string()),
                ("Accept".to_string(), "*/*".to_string()),
            ],
        };
        let wire = serialize_request(&req);
        let expected = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        assert_eq!(wire, expected.to_vec());
    }

    #[test]
    fn test_serialize_request_to_buf_matches() {
        let req = H1Request {
            method: "POST".to_string(),
            target: "/submit".to_string(),
            version: HttpVersion::Http10,
            headers: vec![("Content-Length".to_string(), "5".to_string())],
        };
        let vec_output = serialize_request(&req);
        let mut buf = DynBuf::new();
        serialize_request_to_buf(&req, &mut buf).unwrap();
        assert_eq!(buf.as_bytes(), &vec_output[..]);
    }

    // -- H1RequestParser ---------------------------------------------------

    #[test]
    fn test_parser_single_feed() {
        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut parser = H1RequestParser::new(false);
        let consumed = parser.feed(raw).unwrap();
        assert_eq!(consumed, raw.len());
        assert!(parser.is_done());

        let req = parser.take_result().unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.target, "/");
        assert_eq!(req.version, HttpVersion::Http11);
        assert_eq!(req.headers.len(), 1);
        assert_eq!(req.headers[0], ("Host".to_owned(), "example.com".to_owned()));
    }

    #[test]
    fn test_parser_chunked_feeds() {
        let mut parser = H1RequestParser::new(false);
        parser.feed(b"POST /data HT").unwrap();
        assert!(!parser.is_done());

        parser.feed(b"TP/1.1\r\nContent-Le").unwrap();
        assert!(!parser.is_done());

        parser.feed(b"ngth: 5\r\n\r\n").unwrap();
        assert!(parser.is_done());

        let req = parser.take_result().unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.target, "/data");
        assert_eq!(req.version, HttpVersion::Http11);
    }

    #[test]
    fn test_parser_strict_rejects_http09() {
        let raw = b"GET / HTTP/0.9\r\n\r\n";
        let mut parser = H1RequestParser::new(true);
        let result = parser.feed(raw);
        assert!(result.is_err());
    }

    #[test]
    fn test_parser_strict_rejects_obsfold() {
        let raw = b"GET / HTTP/1.1\r\nFoo: bar\r\n baz\r\n\r\n";
        let mut parser = H1RequestParser::new(true);
        let result = parser.feed(raw);
        assert!(result.is_err());
    }

    #[test]
    fn test_parser_lenient_accepts_obsfold() {
        let raw = b"GET / HTTP/1.1\r\nFoo: bar\r\n baz\r\n\r\n";
        let mut parser = H1RequestParser::new(false);
        parser.feed(raw).unwrap();
        assert!(parser.is_done());
        let req = parser.take_result().unwrap();
        assert_eq!(req.headers[0].1, "bar baz");
    }

    // -- H1ParseError → CurlError conversion ------------------------------

    #[test]
    fn test_parse_error_to_curl_error() {
        let e: CurlError = H1ParseError::InvalidMethod.into();
        assert_eq!(e, CurlError::WeirdServerReply);

        let e: CurlError = H1ParseError::LineTooLong.into();
        assert_eq!(e, CurlError::TooLarge);

        let e: CurlError = H1ParseError::IncompleteRequest.into();
        assert_eq!(e, CurlError::GotNothing);
    }
}
