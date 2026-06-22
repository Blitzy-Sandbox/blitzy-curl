//! The HTTP/1.1 protocol engine — the request/response orchestrator and the
//! hand-rolled HTTP/1.1 wire codec.
//!
//! This module is the Rust port of the HTTP/1.1 execution path of curl's
//! `lib/http.c` (the `Curl_http()` do-it flow, `Curl_http_method`,
//! `http_set_aptr_host`, `http_useragent`, the `http_add_hd` header-assembly
//! loop over the `H1_HD_*` enum, the `addexpect` `Expect: 100-continue` logic,
//! and the status-line / header parsing) together with `lib/http1.c` (the
//! request-line and request-target forms). Both C files are consumed strictly as
//! a behavioral / ABI oracle, never transliterated line-by-line.
//!
//! # Architecture
//!
//! curl builds an entire request into a 1 MiB `dynbuf` and writes it to the
//! connection, then parses the response off the same connection. This port keeps
//! that model but expresses it idiomatically:
//!
//! * **Request building** is split into pure, testable helpers
//!   ([`resolve_http_method`], [`build_host_header_value`],
//!   [`should_add_expect_100`], …) plus [`build_request`], which assembles the
//!   request headers into a [`DynHds`] in curl's exact `H1_HD_*` order. The
//!   *content* of the request — which headers, in what order, with what values —
//!   is where wire parity lives, so it is reproduced faithfully.
//! * **The wire codec** is hand-rolled rather than delegated to `hyper`'s client.
//!   At the protocol layer the engine only borrows the connection
//!   (`&mut `[`crate::conn::Connection`]); it cannot hand a `'static`, owned I/O
//!   object to `hyper`'s connection task. A minimal, allocation-light HTTP/1.1
//!   reader/writer over the byte stream therefore keeps the borrow discipline
//!   intact while reproducing curl's framing behavior exactly.
//! * **Driving** happens through [`crate::transfer::ProtocolExchange`]:
//!   [`H1Exchange`] implements it, sending the request lazily on the first
//!   [`next_event`](crate::transfer::ProtocolExchange::next_event) call and then
//!   yielding the status, header lines, and (de-framed) body chunks that
//!   [`crate::transfer::drive_transfer`] routes through the client-writer chain.
//!
//! # Delegation
//!
//! `h1.rs` orchestrates; it does **not** re-implement the subsystems it depends
//! on. The request-target form comes from [`super::proxy::request_target`],
//! custom headers from [`super::proxy::add_custom_headers`], request-body
//! chunking from [`super::chunks`], and the redirect method-rewrite decision from
//! [`crate::transfer::redirect_method`]. Authentication header values, the
//! `Cookie` request header, and the `Accept-Encoding` value are resolved by the
//! caller (the `Protocol` impl assembled in [`super`]) against the stateful
//! `crate::auth`, `crate::cookie`, and `crate::content_encoding` subsystems and
//! handed to [`build_request`] via [`RequestInputs`]; response **content**
//! decoding (gzip/deflate/br/zstd) is performed by the transfer writer chain,
//! so this codec only **de-frames** (Content-Length / chunked / close-delimited).
//!
//! # Memory safety
//!
//! This subtree inherits `#![forbid(unsafe_code)]` from [`crate::protocols`];
//! it is intentionally **not** re-declared here. The codec is async-only over
//! Tokio and contains no `unsafe` and no raw pointers.

use core::time::Duration;
use std::time::Instant;

use crate::conn::{Connection, Curl_conn_recv, Curl_conn_send, FIRSTSOCKET};
use crate::error::{CurlError, Result};
use crate::headers::DynHds;
use crate::ratelimit::{Direction, RateLimit};
use crate::setopt::HttpReq;
use crate::transfer::{
    self, redirect_method, ClientWriteType, Connection as ByteStream, HttpMethod, PostRedir,
    ProtocolExchange, ReadCallback, ResponseEvent, CURL_READFUNC_ABORT, CURL_READFUNC_PAUSE,
};
use crate::url::{CurlUPart, CurlUrl};

use super::chunks::ChunkedUnencoder;
use super::proxy::{self, CustomHeaderContext};
use crate::content_encoding::UnencodingStack;

// ===========================================================================
// Constants (oracle: lib/http.h, lib/urldata.h)
// ===========================================================================

/// Default scheme ports (`PORT_HTTP` / `PORT_HTTPS`, `lib/urldata.h` L32-L33).
/// Used to reproduce curl's Host-header port-suppression rule.
const PORT_HTTP: u16 = 80;
/// Default HTTPS port (`PORT_HTTPS`, `lib/urldata.h` L33).
const PORT_HTTPS: u16 = 443;

/// `EXPECT_100_THRESHOLD` (`lib/http.h` L159): the request-body size at or below
/// which curl never announces `Expect: 100-continue`. Bodies larger than this —
/// or of unknown length — get the header (when on HTTP/1.1 and not disabled).
const EXPECT_100_THRESHOLD: i64 = 1024 * 1024;

/// `DYN_HTTP_REQUEST` (`lib/dynbuf.h`): the 1 MiB hard cap curl places on the
/// assembled HTTP request head. Exceeding it yields [`CurlError::TooLarge`]
/// (curl's `CURLE_TOO_LARGE`, `lib/http.c` L3103).
const DYN_HTTP_REQUEST_MAX: usize = 1024 * 1024;

/// The default `Expect: 100-continue` wait when `CURLOPT_EXPECT_100_TIMEOUT_MS`
/// is unset (curl's `EXPECT_100_TIMEOUT`, 1000 ms).
const DEFAULT_EXPECT_100_TIMEOUT_MS: u64 = 1000;

// ===========================================================================
// Method mapping (oracle: lib/http.c `Curl_http_method`, L1926)
// ===========================================================================

/// The outcome of resolving a request method: the verb to put on the wire plus
/// the (possibly adjusted) [`HttpReq`] kind that still governs body handling.
///
/// curl's `Curl_http_method` returns both `*method` (the request string) and
/// `*reqp` (the request kind): a `CURLOPT_CUSTOMREQUEST` overrides the *verb*
/// string but leaves the request *kind* — and therefore the body/Content-Length
/// behavior — unchanged. This struct preserves that distinction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMethod {
    /// The method verb written on the request line (`GET`, `POST`, a
    /// `CURLOPT_CUSTOMREQUEST` value such as `DELETE`, …).
    pub method: http::Method,
    /// The request kind that drives body handling (unchanged by a custom verb).
    pub kind: HttpReq,
}

/// Port of `Curl_http_method` (`lib/http.c` L1926): pick the request verb and
/// the effective [`HttpReq`] kind.
///
/// Mirrors the C precedence exactly:
/// 1. WebSocket schemes force `GET` (the Upgrade handshake).
/// 2. An HTTP/FTP upload forces `PUT`.
/// 3. A `CURLOPT_CUSTOMREQUEST` (unless `http_ignorecustom`) overrides the verb
///    *string* — but `kind` keeps the value from steps 1-2.
/// 4. Otherwise `no_body` forces `HEAD`, else the verb follows `kind`
///    (POST/POST_FORM/POST_MIME → `POST`, PUT → `PUT`, HEAD → `HEAD`,
///    GET → `GET`).
///
/// # Errors
///
/// Returns [`CurlError::BadFunctionArgument`] if a custom request string is not a
/// valid HTTP method token (contains spaces or control characters); curl would
/// emit a malformed request line in that case, which this port refuses instead.
pub fn resolve_http_method(
    kind: HttpReq,
    no_body: bool,
    custom_request: Option<&str>,
    is_websocket: bool,
    is_upload: bool,
) -> Result<ResolvedMethod> {
    // C: WS/WSS → HTTPREQ_GET; (HTTP|FTP) && upload → HTTPREQ_PUT.
    let kind = if is_websocket {
        HttpReq::Get
    } else if is_upload {
        HttpReq::Put
    } else {
        kind
    };

    // C: a non-empty CUSTOMREQUEST overrides the verb string (kind is preserved).
    if let Some(custom) = custom_request {
        if !custom.is_empty() {
            let method = http::Method::from_bytes(custom.as_bytes())
                .map_err(|_| CurlError::BadFunctionArgument)?;
            return Ok(ResolvedMethod { method, kind });
        }
    }

    // C: no_body forces HEAD, else switch on the request kind.
    let verb = if no_body {
        http::Method::HEAD
    } else {
        match kind {
            HttpReq::Post | HttpReq::PostForm | HttpReq::PostMime => http::Method::POST,
            HttpReq::Put => http::Method::PUT,
            HttpReq::Head => http::Method::HEAD,
            HttpReq::Get => http::Method::GET,
        }
    };
    Ok(ResolvedMethod { method: verb, kind })
}

// ===========================================================================
// HTTP version token (oracle: lib/http.c `get_http_string`, L1711)
// ===========================================================================

/// The wire version token written after the request target (`get_http_string`,
/// `lib/http.c` L1711). For the HTTP/1.1 path `http_minor` is `1` (`"1.1"`) or
/// `0` (`"1.0"`); higher major versions are handled by the h2/h3 engines.
#[must_use]
pub fn http_version_token(http_minor: u8) -> &'static str {
    if http_minor >= 1 {
        "1.1"
    } else {
        "1.0"
    }
}

// ===========================================================================
// Host header (oracle: lib/http.c `http_set_aptr_host`, L1986)
// ===========================================================================

/// Build the default `Host:` header **value** (without the `Host: ` prefix or
/// trailing CRLF), porting the non-custom branch of `http_set_aptr_host`
/// (`lib/http.c` L2050-L2073).
///
/// Reproduces curl's two rules exactly:
/// * **IPv6 literals** are wrapped in `[ ]` (RFC 2732). A host already bracketed,
///   or any host containing `:`, is treated as an IPv6 literal.
/// * **Port suppression**: the port is omitted when it is the scheme default
///   (HTTPS on 443, HTTP on 80); otherwise `host:port` is emitted.
///
/// The custom-`Host:`-header path (a user-supplied `Host`) is handled by the
/// custom-header machinery ([`super::proxy::add_custom_headers`] keyed off
/// [`CustomHeaderContext::host_header_present`]), not here.
#[must_use]
pub fn build_host_header_value(host: &str, port: u16, is_https: bool) -> String {
    // Strip an existing bracket pair so we never double-bracket.
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let is_ipv6 = bare.contains(':');
    let host_part = if is_ipv6 {
        format!("[{bare}]")
    } else {
        bare.to_string()
    };

    // C: omit the port for (HTTPS && 443) or (HTTP && 80).
    let suppress_port = (is_https && port == PORT_HTTPS) || (!is_https && port == PORT_HTTP);
    if suppress_port {
        host_part
    } else {
        format!("{host_part}:{port}")
    }
}

// ===========================================================================
// User-Agent (oracle: lib/http.c `http_useragent`, L1973; default from url.c)
// ===========================================================================

/// curl's built-in default `User-Agent` value, `curl/<version>` — the string
/// `Curl_init_userdefined` installs into `data->set.str[STRING_USERAGENT]` when
/// the application does not override it. The version is
/// [`crate::version::VERSION`] (`"8.19.0-DEV"`), so this is `"curl/8.19.0-DEV"`.
#[must_use]
pub fn default_user_agent() -> String {
    format!("curl/{}", crate::version::VERSION)
}

// ===========================================================================
// Expect: 100-continue (oracle: lib/http.c `addexpect`, L2408)
// ===========================================================================

/// Decide whether curl announces `Expect: 100-continue`, porting `addexpect`
/// (`lib/http.c` L2408-L2441).
///
/// curl adds the header only when **all** of:
/// * no `Upgrade:` is in flight (`req.upgr101 == UPGR101_NONE`),
/// * the application has not supplied its own `Expect:` header
///   (`has_custom_expect` — that case is honored verbatim, not synthesized),
/// * `Expect:` is not disabled (`!CURLOPT_EXPECT_100_TIMEOUT`-driven
///   `disableexpect`) and the request is HTTP/1.1 (`http_minor == 1`), and
/// * the body is large (`client_len > EXPECT_100_THRESHOLD`) or of unknown
///   length (`client_len < 0`).
#[must_use]
pub fn should_add_expect_100(
    http_minor: u8,
    disable_expect: bool,
    has_custom_expect: bool,
    is_upgrade: bool,
    client_len: i64,
) -> bool {
    if is_upgrade || has_custom_expect {
        return false;
    }
    if disable_expect || http_minor != 1 {
        return false;
    }
    // C: `client_len > EXPECT_100_THRESHOLD || client_len < 0` — i.e. the length
    // is outside the inclusive `0..=EXPECT_100_THRESHOLD` band (too large, or
    // unknown/negative).
    !(0..=EXPECT_100_THRESHOLD).contains(&client_len)
}

// ===========================================================================
// Request target (oracle: lib/http.c `http_target` → super::proxy)
// ===========================================================================

/// Compute the request-target for the request line.
///
/// A thin, intention-revealing wrapper over [`super::proxy::request_target`]
/// (the port of `http_target`): origin-form (`/path?query`) for a direct or
/// tunneled connection, absolute-URI form (`scheme://host/path`) for a forward
/// HTTP proxy. The proxy module owns the form selection; this re-export keeps the
/// h1 request-building flow readable and gives `h1.rs` a single, testable seam.
///
/// # Errors
///
/// Propagates any [`CurlError`] from URL re-serialization in the proxy path.
pub fn request_target(
    url: &CurlUrl,
    conn: &Connection,
    request_target_override: Option<&str>,
    proxy_transfer_mode: bool,
    prefer_ascii: bool,
) -> Result<String> {
    proxy::request_target(
        url,
        conn,
        request_target_override,
        proxy_transfer_mode,
        prefer_ascii,
    )
}

// ===========================================================================
// Status-line parsing (oracle: lib/http.c L4205-L4290 + `checkhttpprefix`)
// ===========================================================================

/// The classification of a response's first line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusLine {
    /// A valid `HTTP/1.x <code> …` status line. `minor` is `0` or `1`; `code`
    /// is the three-digit status.
    Http1 { minor: u8, code: i32 },
    /// The line is not an HTTP status line at all — a candidate HTTP/0.9 body
    /// (the bytes are the start of the response body, not a header).
    NotStatusLine,
}

/// Parse a response status line, porting the HTTP branch of curl's first-header
/// parser (`lib/http.c` L4218-L4266).
///
/// * `HTTP/1.0` → `minor = 0`, `HTTP/1.1` → `minor = 1`, then the three-digit
///   status code (any three digits are accepted, per RFC 7230 §3.1.2 and curl's
///   tolerance).
/// * A line that begins with `HTTP/` but carries an unsupported `1.x` subversion
///   yields [`CurlError::UnsupportedProtocol`] (curl: *"Unsupported HTTP/1
///   subversion in response"*).
/// * A line that does not begin with `HTTP/` is [`StatusLine::NotStatusLine`];
///   the caller decides between HTTP/0.9 acceptance and
///   [`CurlError::WeirdServerReply`] using `http09_allowed` / connection reuse.
///
/// Leading blanks are skipped (`curlx_str_passblanks`). The input is the status
/// line **without** its trailing CRLF.
///
/// # Errors
///
/// [`CurlError::UnsupportedProtocol`] for an `HTTP/`-prefixed line with a bad
/// `1.x` subversion or major version.
pub fn parse_status_line(line: &[u8]) -> Result<StatusLine> {
    // C: curlx_str_passblanks — skip leading SP/TAB.
    let mut p = line;
    while let [first, rest @ ..] = p {
        if *first == b' ' || *first == b'\t' {
            p = rest;
        } else {
            break;
        }
    }

    // Must start with "HTTP/" to be a status line at all.
    if !p.starts_with(b"HTTP/") {
        return Ok(StatusLine::NotStatusLine);
    }
    let after = &p[5..];

    match after.first() {
        // HTTP/1.x
        Some(b'1') => {
            // Expect ".0 " or ".1 " then a 3-digit code.
            if after.len() >= 3 && after[1] == b'.' && (after[2] == b'0' || after[2] == b'1') {
                let minor = after[2] - b'0';
                let rest = &after[3..];
                // RFC 9112 wants a single space; curl tolerates any blank.
                if let Some((&sep, digits)) = rest.split_first() {
                    if (sep == b' ' || sep == b'\t') && digits.len() >= 3 {
                        if let Some(code) = parse_three_digit_code(digits) {
                            return Ok(StatusLine::Http1 { minor, code });
                        }
                    }
                }
            }
            // C: "Unsupported HTTP/1 subversion in response".
            Err(CurlError::UnsupportedProtocol)
        }
        // HTTP/2 or HTTP/3 status lines are not produced on an h1 wire, but curl
        // accepts the textual form; reject anything that is not 1.x for the h1
        // codec with the same error curl uses for an unsupported major version.
        _ => Err(CurlError::UnsupportedProtocol),
    }
}

/// Parse exactly three leading ASCII digits into a status code, returning `None`
/// if any of the first three bytes is not a digit.
fn parse_three_digit_code(digits: &[u8]) -> Option<i32> {
    let d0 = digits.first().copied()?;
    let d1 = digits.get(1).copied()?;
    let d2 = digits.get(2).copied()?;
    if d0.is_ascii_digit() && d1.is_ascii_digit() && d2.is_ascii_digit() {
        let code = i32::from(d0 - b'0') * 100 + i32::from(d1 - b'0') * 10 + i32::from(d2 - b'0');
        Some(code)
    } else {
        None
    }
}

// ===========================================================================
// Header-line parsing
// ===========================================================================

/// Split a single header line into `(name, value)`, trimming the trailing CRLF
/// and the optional whitespace around the value (curl's header handling treats
/// `Name: value` with optional surrounding blanks).
///
/// Returns `None` for a blank line (the headers/body separator) or a line with
/// no `:` (which curl tolerates as a non-header and skips). The returned slices
/// borrow from `line`.
#[must_use]
pub fn parse_header_line(line: &[u8]) -> Option<(&[u8], &[u8])> {
    // Trim a trailing CRLF / LF.
    let mut end = line.len();
    if end > 0 && line[end - 1] == b'\n' {
        end -= 1;
    }
    if end > 0 && line[end - 1] == b'\r' {
        end -= 1;
    }
    let line = &line[..end];
    if line.is_empty() {
        return None;
    }

    let colon = line.iter().position(|&c| c == b':')?;
    let name = &line[..colon];
    // Skip the single delimiter then trim surrounding blanks from the value.
    let mut value = &line[colon + 1..];
    while let [first, rest @ ..] = value {
        if *first == b' ' || *first == b'\t' {
            value = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = value {
        if *last == b' ' || *last == b'\t' {
            value = rest;
        } else {
            break;
        }
    }
    Some((name, value))
}

// ===========================================================================
// Request / response body modeling
// ===========================================================================

/// The request body to send after the head.
///
/// curl pulls the body from its client-reader chain; at the h1 layer the body is
/// modeled as either fully buffered (the common CLI/`CURLOPT_POSTFIELDS` case) or
/// chunked. Streaming larger bodies is supported by
/// [`ProtocolExchange::send_body`](crate::transfer::ProtocolExchange::send_body),
/// which the engine may drive directly.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RequestBody {
    /// No request body (GET/HEAD, or a POST/PUT with an empty body).
    #[default]
    None,
    /// A fully-buffered body of known length, advertised via `Content-Length`.
    Sized(Vec<u8>),
    /// A body sent with `Transfer-Encoding: chunked`. Holds the **raw**
    /// (un-chunked) bytes; the codec frames them via
    /// [`super::chunks::encode_chunked`] when sending.
    Chunked(Vec<u8>),
    /// A body **streamed** incrementally from the upload read source rather than
    /// buffered in memory. Carries only the framing *metadata* — the known body
    /// `size` (advertised via `Content-Length` when `chunked` is `false`) and
    /// whether the application requested `Transfer-Encoding: chunked`. The actual
    /// bytes are pulled, ~64 KiB at a time, from the
    /// [`upload_source`](H1Exchange::upload_source) the engine installs on the
    /// exchange (see [`H1Exchange::set_upload_source`]), so a multi-gigabyte
    /// upload uses bounded memory (QA F11-PERF Issue #5). The engine selects this
    /// variant only when the upload is provably single-pass — a known size, no
    /// redirect-following, and no reactive auth — so the source is never re-read.
    Streaming {
        /// The total body length, when known. `Some(n)` advertises
        /// `Content-Length: n`; `None` is only valid together with `chunked`.
        size: Option<u64>,
        /// `true` when the application announced `Transfer-Encoding: chunked`
        /// (each ~64 KiB read is framed as one chunk; a terminal `0\r\n\r\n`
        /// closes the body). `false` sends the raw bytes under `Content-Length`.
        chunked: bool,
    },
}

/// How the **response** body is delimited on the wire — the result of curl's
/// body-length determination (`Curl_http_size` / the `Content-Length` vs
/// `Transfer-Encoding: chunked` vs close-delimited decision).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    /// No response body at all (a `1xx`, `204`, or `304` status, or a `HEAD`
    /// request). curl's `http_bodyless` / `k->size == 0` case.
    None,
    /// Exactly `len` bytes of body follow (`Content-Length`).
    ContentLength(u64),
    /// Chunked Transfer-Encoding; the body ends at the terminal `0\r\n` chunk.
    Chunked,
    /// No length and not chunked: the body runs until the peer closes the
    /// connection (curl's `k->size == -1`, `Connection: close`-delimited).
    CloseDelimited,
}

/// Determine the response [`BodyFraming`], porting curl's body-delimitation
/// precedence (`lib/http.c` `http_statusline` / the `Transfer-Encoding`-over-
/// `Content-Length` rule of RFC 7230 §3.3.3).
///
/// Precedence:
/// 1. **No body** for a `HEAD` request, a `1xx` interim status, `204 No
///    Content`, or `304 Not Modified`.
/// 2. **Chunked** if `Transfer-Encoding: chunked` is present (this *overrides*
///    any `Content-Length`, per RFC 7230).
/// 3. **Content-Length** if present and the response is not chunked.
/// 4. **Close-delimited** otherwise.
#[must_use]
pub fn response_body_framing(
    status: i32,
    no_body: bool,
    content_length: Option<u64>,
    chunked: bool,
) -> BodyFraming {
    if no_body || status == 204 || status == 304 || (100..200).contains(&status) {
        return BodyFraming::None;
    }
    if chunked {
        return BodyFraming::Chunked;
    }
    match content_length {
        Some(len) => BodyFraming::ContentLength(len),
        None => BodyFraming::CloseDelimited,
    }
}

// ===========================================================================
// Request head serialization (oracle: lib/http1.c `Curl_h1_req_write_head`,
// lib/http.c `http_add_hd` H1_HD_REQUEST + H1_HD_LAST)
// ===========================================================================

/// Serialize the request head: the request line, the assembled header block, and
/// the terminating empty line.
///
/// Reproduces curl's `"%s %s HTTP/1.%d\r\n"` request line (`lib/http1.c`
/// `Curl_h1_req_write_head`) followed by the `Name: value\r\n` header block
/// (from [`DynHds::to_h1_string`], which preserves insertion order) and the final
/// `\r\n` (`H1_HD_LAST`). The total is capped at 1 MiB (`DYN_HTTP_REQUEST`).
///
/// # Errors
///
/// [`CurlError::TooLarge`] if the assembled head exceeds 1 MiB (curl's
/// `CURLE_TOO_LARGE`, `lib/http.c` L3103).
pub fn serialize_request_head(
    method: &http::Method,
    target: &str,
    http_minor: u8,
    headers: &DynHds,
) -> Result<Vec<u8>> {
    let request_line = format!(
        "{} {} HTTP/{}\r\n",
        method.as_str(),
        target,
        http_version_token(http_minor)
    );
    let header_block = headers.to_h1_string();

    // request line + header block + terminating CRLF.
    let total = request_line.len() + header_block.len() + 2;
    if total > DYN_HTTP_REQUEST_MAX {
        return Err(CurlError::TooLarge);
    }

    let mut head = Vec::with_capacity(total);
    head.extend_from_slice(request_line.as_bytes());
    head.extend_from_slice(header_block.as_bytes());
    head.extend_from_slice(b"\r\n");
    Ok(head)
}

// ===========================================================================
// Request building (oracle: lib/http.c `Curl_http` L3011-L3114 + `http_add_hd`)
// ===========================================================================

/// The resolved, delegated inputs that [`build_request`] assembles into a wire
/// request. Every value is pre-computed by the caller (the HTTP `Protocol` impl
/// in [`super`]) so this module stays free of the stateful subsystems it
/// orchestrates: authentication header values come from [`crate::auth`], the
/// `Cookie` value from [`crate::cookie`], and the `Accept-Encoding` value from
/// [`crate::content_encoding`]. A field set to `None`/`false` suppresses the
/// corresponding header exactly as curl's `Curl_checkheaders` guard would.
///
/// The lifetime `'a` borrows the URL, connection, and string inputs for the
/// duration of the build.
pub struct RequestInputs<'a> {
    /// The parsed request URL (`data->state.uh`), used for the request target.
    pub url: &'a CurlUrl,
    /// The connection (forward-proxy / tunnel bits drive the request-target form
    /// and the custom-header selection).
    pub conn: &'a Connection,
    /// The request kind before method shaping (`data->state.httpreq`).
    pub method_kind: HttpReq,
    /// `CURLOPT_NOBODY` — forces `HEAD` and suppresses the response body.
    pub no_body: bool,
    /// `CURLOPT_CUSTOMREQUEST` verb override, if any.
    pub custom_request: Option<&'a str>,
    /// `true` for a `ws://`/`wss://` scheme (forces `GET`).
    pub is_websocket: bool,
    /// `data->state.upload` for an HTTP/FTP upload (forces `PUT`).
    pub is_upload: bool,
    /// The target host (`conn->host.name`) for the default `Host:` header.
    pub host: &'a str,
    /// The remote port (`conn->remote_port`) for `Host:` port suppression.
    pub port: u16,
    /// `true` for an HTTPS/WSS scheme (drives `Host:` port suppression).
    pub is_https: bool,
    /// `true` if the user's custom headers already include a `Host:` header
    /// (suppresses the synthesized default).
    pub host_header_present: bool,
    /// The `User-Agent` value to send, or `None` to omit it.
    pub user_agent: Option<&'a str>,
    /// The `Authorization` value from [`crate::auth`], or `None`.
    pub authorization: Option<&'a str>,
    /// The `Proxy-Authorization` value from [`crate::auth`], or `None`.
    pub proxy_authorization: Option<&'a str>,
    /// The `Range` value (`data->state.aptr.rangeline`), or `None`.
    pub range: Option<&'a str>,
    /// `true` if the user's custom headers already include an `Accept:` header
    /// (suppresses the default `Accept: */*`).
    pub accept_present: bool,
    /// `true` to announce `TE: gzip` (curl's `http_transfer_encoding` with zlib).
    pub te_gzip: bool,
    /// The `Accept-Encoding` value from [`crate::content_encoding`], or `None`.
    pub accept_encoding: Option<&'a str>,
    /// The `Referer` value (`data->state.referer`), or `None`.
    pub referer: Option<&'a str>,
    /// `true` to send `Proxy-Connection: Keep-Alive` (forward HTTP proxy).
    pub proxy_connection_keepalive: bool,
    /// The `Cookie` value from [`crate::cookie`], or `None`.
    pub cookie: Option<&'a str>,
    /// The request body (drives `Content-Length` / `Transfer-Encoding`).
    pub body: RequestBody,
    /// The `Content-Type` value to send, or `None` (e.g. user-overridden).
    pub content_type: Option<&'a str>,
    /// The `Content-Length` to advertise for a sized body, or `None`.
    pub content_length: Option<i64>,
    /// `true` to send the body with `Transfer-Encoding: chunked`.
    pub chunked: bool,
    /// `CURLOPT_EXPECT_100_TIMEOUT`-driven disable (`data->state.disableexpect`).
    pub disable_expect: bool,
    /// `true` if the user already supplied an `Expect:` header.
    pub expect_present: bool,
    /// `true` if the user's `Expect:` header announces `100-continue`.
    pub custom_expect_100: bool,
    /// `true` when an `Upgrade:` is in flight (suppresses `Expect:`).
    pub is_upgrade: bool,
    /// The user's `CURLOPT_HTTPHEADER` lines (applied verbatim in order).
    pub custom_headers: &'a [String],
    /// The user's `CURLOPT_PROXYHEADER` lines (forward proxy + `sep_headers`).
    pub proxy_headers: &'a [String],
    /// `CURLOPT_HEADEROPT == CURLHEADER_SEPARATE`.
    pub sep_headers: bool,
    /// `true` while performing an authentication negotiation round
    /// (`data->state.authhost.multipass`); suppresses some custom headers.
    pub authneg: bool,
    /// Whether sending the host's credentials to this host is permitted.
    pub allowed_to_host: bool,
    /// `1` for HTTP/1.1, `0` for HTTP/1.0.
    pub http_minor: u8,
    /// `CURLOPT_REQUEST_TARGET` override, if any.
    pub request_target_override: Option<&'a str>,
    /// `data->set.proxy_transfer_mode` (FTP-over-proxy `;type=` handling).
    pub proxy_transfer_mode: bool,
    /// `data->set.str[STRING_TARGET]`-style ASCII preference for the target.
    pub prefer_ascii: bool,
    /// `CURLOPT_EXPECT_100_TIMEOUT_MS` (0 → the 1000 ms default).
    pub expect_100_timeout_ms: u16,
}

/// The product of [`build_request`]: the serialized request head plus everything
/// [`H1Exchange`] needs to send the body and drive the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPlan {
    /// The serialized request head (request line + headers + terminating CRLF).
    pub head: Vec<u8>,
    /// The request body to send after the head.
    pub body: RequestBody,
    /// `true` if `Expect: 100-continue` was announced (the codec waits for the
    /// interim `100` before sending the body).
    pub expect_100: bool,
    /// How long to wait for the interim `100` response before sending the body
    /// anyway.
    pub expect_100_timeout: Duration,
    /// `true` for a `HEAD`/`CURLOPT_NOBODY` request (no response body expected).
    pub no_body: bool,
}

/// Find the value of the custom header named `target` (case-insensitive) in the
/// application's `CURLOPT_HTTPHEADER` lines, honoring the
/// [`proxy::parse_custom_header_line`] quirks.
///
/// Used by [`build_request`] to emit a user-supplied `Host:` at the canonical
/// `H1_HD_HOST` position (porting `http_set_aptr_host`'s reuse of the custom
/// value). Returns `None` if no such header is present.
fn find_custom_header_value<'a>(lines: &'a [String], target: &str) -> Option<&'a str> {
    for line in lines {
        if let proxy::CustomHeader::Add { name, value } = proxy::parse_custom_header_line(line) {
            if name.eq_ignore_ascii_case(target) {
                return Some(value);
            }
        }
    }
    None
}

/// Assemble a complete HTTP/1.1 request, porting the `Curl_http` do-it flow
/// (`lib/http.c` L3011-L3114) and the `http_add_hd` header loop.
///
/// Headers are emitted in curl's exact `H1_HD_*` order — Host, Proxy-Auth,
/// Authorization, Range, User-Agent, Accept, TE, Accept-Encoding, Referer,
/// Proxy-Connection, **Transfer-Encoding**, Cookie, **custom headers**, then the
/// content headers (Content-Length, Content-Type, Expect) and finally the
/// internal Connection token — because byte-for-byte header ordering is part of
/// the wire contract the regression suite checks. (Chunked `Transfer-Encoding`
/// is at its own `H1_HD_TRANSFER_ENCODING` slot, ahead of cookies/custom, while
/// `Content-Length`/`Content-Type` live later in `H1_HD_CONTENT`.)
///
/// # Errors
///
/// * [`CurlError::TooLarge`] if the assembled head exceeds 1 MiB.
/// * Any [`CurlError`] from the request-target computation or custom-header
///   application.
pub fn build_request(inputs: &RequestInputs<'_>) -> Result<RequestPlan> {
    let resolved = resolve_http_method(
        inputs.method_kind,
        inputs.no_body,
        inputs.custom_request,
        inputs.is_websocket,
        inputs.is_upload,
    )?;

    let target = request_target(
        inputs.url,
        inputs.conn,
        inputs.request_target_override,
        inputs.proxy_transfer_mode,
        inputs.prefer_ascii,
    )?;

    let mut hds = DynHds::with_request_limits();

    // H1_HD_HOST. Port of `http_set_aptr_host`: the `Host:` header is always
    // emitted at this early position. When the application supplied its own
    // `Host:` (`host_header_present`), curl emits *that value* here (and the
    // H1_HD_CUSTOM loop then drops the duplicate via `CustomHeaderContext`);
    // otherwise the default `host[:port]` value is synthesized.
    if inputs.host_header_present {
        if let Some(value) = find_custom_header_value(inputs.custom_headers, "Host") {
            hds.add("Host", value)?;
        }
    } else {
        let host_value = build_host_header_value(inputs.host, inputs.port, inputs.is_https);
        hds.add("Host", &host_value)?;
    }

    // H1_HD_PROXY_AUTH then H1_HD_USER_AUTH.
    if let Some(pa) = inputs.proxy_authorization {
        hds.add("Proxy-Authorization", pa)?;
    }
    if let Some(auth) = inputs.authorization {
        hds.add("Authorization", auth)?;
    }

    // H1_HD_RANGE. Port of `http_range()` (lib/http.c): a byte range on a
    // GET/HEAD *download* is sent as `Range: bytes=<range>` — the `bytes=`
    // range-unit prefix is mandatory per RFC 7233 and curl always emits it.
    // POST/PUT *uploads* use a `Content-Range` header instead (a distinct code
    // path), so for non-download request kinds the raw range value is preserved
    // here unchanged rather than being mislabeled with a `bytes=` unit.
    if let Some(range) = inputs.range {
        match inputs.method_kind {
            HttpReq::Get | HttpReq::Head => {
                hds.add("Range", &format!("bytes={range}"))?;
            }
            _ => {
                hds.add("Range", range)?;
            }
        }
    }

    // H1_HD_USER_AGENT (only when non-empty, matching curl's guard).
    if let Some(ua) = inputs.user_agent {
        if !ua.is_empty() {
            hds.add("User-Agent", ua)?;
        }
    }

    // H1_HD_ACCEPT.
    if !inputs.accept_present {
        hds.add("Accept", "*/*")?;
    }

    // H1_HD_TE.
    if inputs.te_gzip {
        hds.add("TE", "gzip")?;
    }

    // H1_HD_ACCEPT_ENCODING.
    if let Some(ae) = inputs.accept_encoding {
        hds.add("Accept-Encoding", ae)?;
    }

    // H1_HD_REFERER.
    if let Some(referer) = inputs.referer {
        hds.add("Referer", referer)?;
    }

    // H1_HD_PROXY_CONNECTION.
    if inputs.proxy_connection_keepalive {
        hds.add("Proxy-Connection", "Keep-Alive")?;
    }

    // H1_HD_TRANSFER_ENCODING — chunked upload framing is emitted HERE, before
    // cookies and custom headers (oracle: `http_req_set_TE`, the dedicated
    // `H1_HD_TRANSFER_ENCODING` slot — distinct from `H1_HD_CONTENT`). HTTP/2+
    // never chunks; the caller leaves `inputs.chunked` false on those versions.
    //
    // curl only auto-emits `Transfer-Encoding: chunked` when the application has
    // NOT already supplied one (`Curl_checkheaders(data, "Transfer-Encoding")`):
    // a user-provided `-H 'Transfer-Encoding: chunked'` is what enables chunked
    // upload, and the custom-header machinery (below) emits it — so adding it
    // here too would duplicate the header on the wire. Skip the auto-emit when a
    // custom `Transfer-Encoding` header is present.
    if inputs.chunked
        && !hds.contains("Transfer-Encoding")
        && find_custom_header_value(inputs.custom_headers, "Transfer-Encoding").is_none()
    {
        hds.add("Transfer-Encoding", "chunked")?;
    }

    // H1_HD_COOKIES.
    if let Some(cookie) = inputs.cookie {
        if !cookie.is_empty() {
            hds.add("Cookie", cookie)?;
        }
    }

    // H1_HD_CUSTOM — the user's CURLOPT_HTTPHEADER / CURLOPT_PROXYHEADER lines.
    let ctx = CustomHeaderContext {
        host_header_present: inputs.host_header_present,
        is_post_form: inputs.method_kind == HttpReq::PostForm,
        is_post_mime: inputs.method_kind == HttpReq::PostMime,
        authneg: inputs.authneg,
        httpversion: i32::from(inputs.http_minor) + 10,
        allowed_to_host: inputs.allowed_to_host,
    };
    proxy::add_custom_headers(
        &mut hds,
        inputs.conn,
        inputs.custom_headers,
        inputs.proxy_headers,
        inputs.sep_headers,
        &ctx,
    )?;

    // H1_HD_CONTENT — Content-Length, then Content-Type, then Expect, only for a
    // body-bearing method (oracle: `http_add_content_hds`, which switches on
    // `httpreq` over PUT / POST / POST_FORM / POST_MIME). GET / HEAD emit none
    // of these. `method_kind` (the request *kind*) drives this, not the verb
    // string, so `-X DELETE -d data` (kind = POST) still frames its body.
    let body_method = matches!(
        inputs.method_kind,
        HttpReq::Put | HttpReq::Post | HttpReq::PostForm | HttpReq::PostMime
    );
    if body_method {
        // Content-Length only when not chunked and the length is known. curl
        // keeps a custom Content-Length unless it is suppressed during auth
        // negotiation (`req_clen >= 0 && !chunky && (authneg || !custom CL)`).
        if !inputs.chunked {
            if let Some(cl) = inputs.content_length {
                if inputs.authneg || !hds.contains("Content-Length") {
                    hds.add("Content-Length", &cl.to_string())?;
                }
            }
        }
        // Content-Type: an explicit value if supplied, otherwise the implicit
        // `application/x-www-form-urlencoded` default that curl adds for a plain
        // `HTTPREQ_POST` (only) when the application set none.
        if let Some(ct) = inputs.content_type {
            if !hds.contains("Content-Type") {
                hds.add("Content-Type", ct)?;
            }
        } else if inputs.method_kind == HttpReq::Post && !hds.contains("Content-Type") {
            hds.add("Content-Type", "application/x-www-form-urlencoded")?;
        }
    }

    // Expect: 100-continue (oracle: `addexpect`, called at the tail of
    // `http_add_content_hds` — i.e. only for a body method).
    let client_len = if !body_method {
        0
    } else if inputs.chunked {
        -1
    } else {
        inputs.content_length.unwrap_or(-1)
    };
    let announced_expect_100 = if inputs.expect_present {
        inputs.custom_expect_100
    } else {
        let add = should_add_expect_100(
            inputs.http_minor,
            inputs.disable_expect,
            false,
            inputs.is_upgrade,
            client_len,
        );
        if add {
            hds.add("Expect", "100-continue")?;
        }
        add
    };

    // H1_HD_CONNECTION — curl's internal `Connection:` tokens
    // (`http_add_connection_hd`), comma-joined in curl's fixed order: `TE` (the
    // gzip transfer-encoding token, gated by `data->state.http_hd_te`) then
    // `Upgrade` (the WebSocket / HTTP-Upgrade handshake token, gated by
    // `data->state.http_hd_upgrade`, which `Curl_ws_request` sets — see
    // `lib/ws.c`). `is_websocket` is this seam's analog of `http_hd_upgrade`
    // (curl-rs negotiates HTTP/2 via ALPN/prior-knowledge, never the cleartext
    // `h2c` upgrade, so `Upgrade` here is exclusively the WebSocket token). The
    // tokens are emitted as a single header, and only when the application
    // supplied no `Connection:` of its own (the h1 path does not model curl's
    // interleaving of custom + internal `Connection:` values).
    // When the application supplied its own `Connection:` value, curl MERGES the
    // internal token(s) into it (`http_transfer_encoding` in `lib/http.c`
    // rewrites the custom `Connection:` to append `TE`, e.g.
    // `Connection: close, TE`) rather than emitting a duplicate header — so we
    // splice the internal tokens onto the existing value and re-emit it (last,
    // matching curl's emission order). With no custom `Connection:`, the tokens
    // are emitted as a fresh `Connection:` header as before.
    {
        let mut tokens: Vec<&str> = Vec::new();
        if inputs.te_gzip {
            tokens.push("TE");
        }
        if inputs.is_websocket {
            tokens.push("Upgrade");
        }
        if !tokens.is_empty() {
            let internal = tokens.join(", ");
            // Snapshot the application's `Connection:` values in order (cloned so
            // the immutable borrow ends before the mutable `remove`/`add` below).
            let existing: Vec<String> = hds
                .iter()
                .filter(|e| e.name().eq_ignore_ascii_case("Connection"))
                .map(|e| e.value().to_string())
                .collect();
            if existing.is_empty() {
                // No application `Connection:` — emit the internal token(s) as a
                // fresh header (curl's `Connection: TE\r\n`).
                hds.add("Connection", &internal)?;
            } else {
                // curl merges the internal token(s) into the FIRST application
                // `Connection:` header and leaves any subsequent ones untouched
                // (`Connection: this, TE` then `Connection: that`). An empty
                // custom value (the `Header;` form) yields just the token(s)
                // with no leading separator (`Connection: TE`).
                hds.remove("Connection");
                for (i, val) in existing.iter().enumerate() {
                    if i == 0 {
                        let merged = if val.is_empty() {
                            internal.clone()
                        } else {
                            format!("{val}, {internal}")
                        };
                        hds.add("Connection", &merged)?;
                    } else {
                        hds.add("Connection", val)?;
                    }
                }
            }
        }
    }

    let head = serialize_request_head(&resolved.method, &target, inputs.http_minor, &hds)?;

    let timeout_ms = if inputs.expect_100_timeout_ms == 0 {
        DEFAULT_EXPECT_100_TIMEOUT_MS
    } else {
        u64::from(inputs.expect_100_timeout_ms)
    };

    Ok(RequestPlan {
        head,
        body: inputs.body.clone(),
        expect_100: announced_expect_100,
        expect_100_timeout: Duration::from_millis(timeout_ms),
        no_body: inputs.no_body,
    })
}

// ===========================================================================
// ConnByteStream — adapt `crate::conn::Connection` to `transfer::Connection`
// ===========================================================================

/// The size of a single socket read, matching curl's default network buffer
/// growth (`BUFSIZE`-class reads). The response read buffer grows as needed.
const READ_CHUNK: usize = 16 * 1024;

/// Adapts a borrowed [`crate::conn::Connection`] filter chain to the byte-stream
/// [`crate::transfer::Connection`] trait the codec is generic over.
///
/// Production [`H1Exchange`]s run over this adapter: `recv`/`send` route through
/// [`Curl_conn_recv`] / [`Curl_conn_send`] at the requested socket index (the
/// primary socket by default), so TLS — already applied by the `cf-ssl` filter
/// woven by [`crate::conn`] — and any proxy filters are transparent to the codec.
pub struct ConnByteStream<'a> {
    conn: &'a mut Connection,
    sockindex: usize,
}

impl<'a> ConnByteStream<'a> {
    /// Wrap `conn`, reading and writing on the primary socket ([`FIRSTSOCKET`]).
    #[must_use]
    pub fn new(conn: &'a mut Connection) -> Self {
        Self {
            conn,
            sockindex: FIRSTSOCKET,
        }
    }

    /// Wrap `conn`, reading and writing on an explicit socket index (e.g.
    /// [`crate::conn::SECONDARYSOCKET`] for an FTP-style data connection reusing
    /// the h1 codec).
    #[must_use]
    pub fn with_sockindex(conn: &'a mut Connection, sockindex: usize) -> Self {
        Self { conn, sockindex }
    }
}

impl ByteStream for ConnByteStream<'_> {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        Curl_conn_recv(self.conn, self.sockindex, buf).await
    }

    async fn send(&mut self, data: &[u8]) -> Result<usize> {
        // `eos = false`: a request write is never the end of the connection
        // stream; the connection is reused or closed based on the response.
        Curl_conn_send(self.conn, self.sockindex, data, false).await
    }
}

// ===========================================================================
// H1Exchange — the HTTP/1.1 wire codec implementing `ProtocolExchange`
// ===========================================================================

/// The parsed response head: the classified status plus the framing-relevant
/// header values and the raw header lines to deliver to the client.
#[derive(Debug, Default)]
struct ParsedHead {
    /// The status code from the status line.
    code: i32,
    /// The HTTP minor version (`0`, `1`, or `9` for HTTP/0.9).
    minor: u8,
    /// `Content-Length`, if present and not overridden by chunked encoding.
    content_length: Option<u64>,
    /// `Content-Encoding` value (gzip/deflate/br/zstd), decoded by the writer
    /// chain — *not* by this codec.
    content_encoding: Option<String>,
    /// `true` if `Transfer-Encoding: chunked` is present.
    chunked: bool,
    /// The non-`chunked` transfer codings (e.g. `gzip`, `deflate`) in the order
    /// they were listed across the response's `Transfer-Encoding` header(s).
    /// These drive the transfer-decode stack when the application opted into
    /// transfer decoding (`CURLOPT_TRANSFER_ENCODING` / `--tr-encoding`); curl's
    /// `CURL_CW_TRANSFER_DECODE` phase in `lib/content_encoding.c`. `chunked`
    /// itself is excluded — this codec owns the chunked framing.
    transfer_codings: Vec<String>,
    /// `Some(i)` when a non-`chunked` transfer coding was listed *after*
    /// `chunked` (RFC 9112 §6.1 forbids this — chunked must be the final
    /// transfer coding). `i` is the index, in [`header_lines`], of the offending
    /// `Transfer-Encoding` line. curl rejects such a response with
    /// `CURLE_BAD_CONTENT_ENCODING` (61) after emitting the header lines that
    /// *precede* the offending line (`Curl_build_unencoding_stack`).
    te_violation_line: Option<usize>,
    /// `true` if a `Connection: close` token is present.
    connection_close: bool,
    /// `true` if a `Connection: keep-alive` token is present.
    connection_keepalive: bool,
    /// The raw header lines (each including its trailing CRLF) to deliver as
    /// [`ResponseEvent::Header`], including the status line and the terminating
    /// blank line.
    header_lines: Vec<Vec<u8>>,
}

/// The HTTP/1.1 protocol exchange — a hand-rolled, async wire codec implementing
/// [`crate::transfer::ProtocolExchange`].
///
/// It owns a byte stream `C` (in production a [`ConnByteStream`] over the
/// borrowed connection; in tests an in-memory mock) and the prepared
/// [`RequestPlan`]. On the first
/// [`next_event`](crate::transfer::ProtocolExchange::next_event) it sends the
/// request head — honoring `Expect: 100-continue` — then sends the body and
/// parses the response, yielding [`ResponseEvent::Status`], one
/// [`ResponseEvent::Header`] per header line, [`ResponseEvent::HeadersComplete`],
/// the de-framed [`ResponseEvent::Body`] chunks, and finally
/// [`ResponseEvent::End`].
///
/// Response **content** decoding (gzip/deflate/br/zstd) is *not* performed here:
/// the `Content-Encoding` value is reported on
/// [`ResponseEvent::HeadersComplete`] and the transfer writer chain decodes it.
/// This codec only **de-frames** the body (Content-Length, chunked, or
/// close-delimited).
pub struct H1Exchange<'u, C: ByteStream> {
    /// The underlying byte stream (connection adapter or test mock).
    conn: C,
    /// The serialized request head (request line + headers + CRLF).
    head: Vec<u8>,
    /// The request body to send after the head.
    body: RequestBody,
    /// The upload read source for a [`RequestBody::Streaming`] body, installed
    /// by the engine via [`set_upload_source`](Self::set_upload_source). `None`
    /// for buffered (`Sized`/`Chunked`) bodies and GET/HEAD. The borrow lives on
    /// the engine's transfer stack frame for the duration of the exchange; it is
    /// only ever read once (the engine gates streaming to single-pass uploads).
    upload_source: Option<&'u mut dyn ReadCallback>,
    /// The send-direction rate limiter for a streaming upload
    /// (`CURLOPT_MAX_SEND_SPEED_LARGE` / `--limit-rate`), applied between chunks.
    /// `None` when the upload is unthrottled. QA F11-PERF Issue #4 (send half).
    upload_rate: Option<RateLimit>,
    /// Whether `Expect: 100-continue` was announced.
    expect_100: bool,
    /// How long to wait for the interim `100` before sending the body anyway.
    expect_100_timeout: Duration,
    /// `true` for a `HEAD`/`CURLOPT_NOBODY` request.
    no_body: bool,
    /// `CURLOPT_HTTP09_ALLOWED` — accept an HTTP/0.9 (header-less) response.
    http09_allowed: bool,
    /// `true` if this connection was reused (forbids HTTP/0.9 fallback).
    reuse: bool,
    /// Bytes read from the wire but not yet consumed (response head leftovers,
    /// then pending body bytes).
    rbuf: Vec<u8>,
    /// Status/header events queued by the head parse, drained before the body.
    pending: std::collections::VecDeque<ResponseEvent>,
    /// How the response body is delimited.
    framing: BodyFraming,
    /// Remaining `Content-Length` bytes (for [`BodyFraming::ContentLength`]).
    body_remaining: u64,
    /// The chunked-Transfer-Encoding decoder (for [`BodyFraming::Chunked`]).
    unchunker: Option<ChunkedUnencoder>,
    /// `true` once the request has been sent and the head parsed.
    sent: bool,
    /// `true` once the response body is fully delivered.
    body_done: bool,
    /// The parsed response status code (also reported via
    /// [`ResponseEvent::Status`]).
    status_code: i32,
    /// The response HTTP minor version (`0`, `1`, or `9`).
    resp_minor: u8,
    /// Whether the connection may be kept alive for reuse after this response.
    keepalive: bool,
    /// `true` when the application opted into transfer decoding
    /// (`CURLOPT_TRANSFER_ENCODING` / `--tr-encoding`, i.e.
    /// `data.set.http_transfer_encoding`). Gates both the transfer-decode of a
    /// compressed `Transfer-Encoding` body and the chunked-not-last rejection,
    /// exactly as curl gates its `is_transfer` branch on the same flag.
    transfer_decoding: bool,
    /// The transfer-decode stack (gzip/deflate/…) for a compressed
    /// `Transfer-Encoding` response body, built from the non-`chunked` codings
    /// in [`finish_head`](Self::finish_head) when [`transfer_decoding`] is set.
    /// `None` means the de-framed body is delivered verbatim. Curl's
    /// `CURL_CW_TRANSFER_DECODE` writer chain.
    transfer_decoder: Option<UnencodingStack>,
    /// A deferred error to surface after the queued header events drain — used
    /// for the chunked-not-last rejection, where curl emits the header lines
    /// preceding the offending `Transfer-Encoding` line and *then* fails with
    /// `CURLE_BAD_CONTENT_ENCODING`.
    pending_error: Option<CurlError>,
}

impl<'u, C: ByteStream> H1Exchange<'u, C> {
    /// Build an exchange from a prepared [`RequestPlan`] over the byte stream
    /// `conn`.
    ///
    /// `http09_allowed` mirrors `CURLOPT_HTTP09_ALLOWED` and `reuse` is `true`
    /// when the connection is being reused (both gate the HTTP/0.9 fallback for
    /// a non-status first line).
    #[must_use]
    pub fn new(conn: C, plan: RequestPlan, http09_allowed: bool, reuse: bool) -> Self {
        Self {
            conn,
            head: plan.head,
            body: plan.body,
            upload_source: None,
            upload_rate: None,
            expect_100: plan.expect_100,
            expect_100_timeout: plan.expect_100_timeout,
            no_body: plan.no_body,
            http09_allowed,
            reuse,
            rbuf: Vec::new(),
            pending: std::collections::VecDeque::new(),
            framing: BodyFraming::None,
            body_remaining: 0,
            unchunker: None,
            sent: false,
            body_done: false,
            status_code: 0,
            resp_minor: 0,
            keepalive: false,
            transfer_decoding: false,
            transfer_decoder: None,
            pending_error: None,
        }
    }

    /// Opt into transfer decoding for this exchange (`CURLOPT_TRANSFER_ENCODING`
    /// / `--tr-encoding`). When enabled, a compressed `Transfer-Encoding`
    /// response body (e.g. `gzip`) is decoded after de-framing, and a response
    /// listing a transfer coding after `chunked` is rejected with
    /// `CURLE_BAD_CONTENT_ENCODING` — mirroring curl's `is_transfer` handling in
    /// `lib/content_encoding.c` gated on `data.set.http_transfer_encoding`.
    /// Left off for the WebSocket upgrade path (a 101 carries no decodable body).
    pub(crate) fn set_transfer_decoding(&mut self, enabled: bool) {
        self.transfer_decoding = enabled;
    }

    /// Install the upload read `source` (and optional send-rate `rate`) that a
    /// [`RequestBody::Streaming`] body pulls from when the request body is sent.
    ///
    /// The engine calls this for an upload it has determined is provably
    /// single-pass (known size, no redirect-following, no reactive auth), so the
    /// source is read straight through exactly once with no rewind. For buffered
    /// bodies it is never called and the source stays untouched. `rate` carries
    /// `CURLOPT_MAX_SEND_SPEED_LARGE` / `--limit-rate` for the send direction;
    /// `None` leaves the upload unthrottled.
    pub(crate) fn set_upload_source(
        &mut self,
        source: &'u mut dyn ReadCallback,
        rate: Option<RateLimit>,
    ) {
        self.upload_source = Some(source);
        self.upload_rate = rate;
    }

    /// The parsed response status code (valid once the head has been read).
    #[must_use]
    pub fn status_code(&self) -> i32 {
        self.status_code
    }

    /// The response HTTP minor version (`0`, `1`, or `9` for HTTP/0.9).
    #[must_use]
    pub fn response_minor(&self) -> u8 {
        self.resp_minor
    }

    /// Take the bytes read from the wire but not yet consumed by the response
    /// codec (the `rbuf` leftovers).
    ///
    /// After a header-only response (e.g. a `101 Switching Protocols` upgrade,
    /// which carries no body), any remaining buffered bytes are payload the peer
    /// sent on the upgraded connection — for a WebSocket upgrade, the first
    /// frame(s). The WebSocket driver hands these to
    /// [`WsConnState::buffer_received`](crate::protocols::ws::WsConnState::buffer_received)
    /// so no bytes are lost across the protocol switch (the analog of curl's
    /// `Curl_ws_accept` seeding `ws->recvbuf` with the leftover upgrade bytes).
    pub(crate) fn take_rbuf(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.rbuf)
    }

    /// Whether the connection may be kept alive (reused) after this response —
    /// curl's keep-alive decision (HTTP/1.1 default-keepalive unless
    /// `Connection: close`; HTTP/1.0 close unless `Connection: keep-alive`;
    /// never for a close-delimited or HTTP/0.9 body).
    #[must_use]
    pub fn keepalive(&self) -> bool {
        self.keepalive
    }

    // -- internal driving --------------------------------------------------

    /// Read one socket chunk into [`Self::rbuf`]; `Ok(0)` signals peer EOF.
    async fn recv_more(&mut self) -> Result<usize> {
        let mut tmp = [0u8; READ_CHUNK];
        let n = self.conn.recv(&mut tmp).await?;
        if n > 0 {
            self.rbuf.extend_from_slice(&tmp[..n]);
        }
        Ok(n)
    }

    /// Send the request head, handle `Expect: 100-continue`, send the body, and
    /// parse the response head — the once-per-exchange startup.
    async fn start(&mut self) -> Result<()> {
        send_all(&mut self.conn, &self.head).await?;

        if self.expect_100 {
            match self.await_interim_100().await? {
                InterimOutcome::Continue => {
                    // Got the interim 100 → send the body, then read the real head.
                    self.send_body_now().await?;
                    let head = self.read_response_head().await?;
                    self.finish_head(head)?;
                }
                InterimOutcome::FinalResponse(head) => {
                    // The server answered without 100 (e.g. 417) → do not send
                    // the body; this is the final response.
                    self.finish_head(head)?;
                }
                InterimOutcome::TimedOut => {
                    // No interim within the window → send the body anyway (curl's
                    // behavior), then read the response.
                    self.send_body_now().await?;
                    let head = self.read_response_head().await?;
                    self.finish_head(head)?;
                }
            }
        } else {
            self.send_body_now().await?;
            let head = self.read_response_head().await?;
            self.finish_head(head)?;
        }
        Ok(())
    }

    /// Send the request body (sized verbatim, chunk-framed, or streamed).
    async fn send_body_now(&mut self) -> Result<()> {
        let body = core::mem::take(&mut self.body);
        match body {
            RequestBody::None => Ok(()),
            RequestBody::Sized(bytes) => send_all(&mut self.conn, &bytes).await,
            RequestBody::Chunked(bytes) => {
                let framed = super::chunks::encode_chunked(&bytes, None);
                send_all(&mut self.conn, &framed).await
            }
            RequestBody::Streaming { chunked, .. } => self.stream_upload(chunked).await,
        }
    }

    /// Stream the request body incrementally from the installed
    /// [`upload_source`](Self::upload_source), in ~64 KiB reads, rather than
    /// buffering it in memory. This is the bounded-memory upload path (QA
    /// F11-PERF Issue #5): a multi-gigabyte `-T` upload sends with a flat
    /// resident set instead of materializing the whole file.
    ///
    /// When `chunked` is `true` each read is framed as one `Transfer-Encoding:
    /// chunked` chunk (hex length, the data, then a terminal `0\r\n\r\n` at
    /// EOF); otherwise the raw bytes are written under the `Content-Length` the
    /// head already advertised. Between writes the send-direction rate limiter
    /// (`CURLOPT_MAX_SEND_SPEED_LARGE` / `--limit-rate`, QA Issue #4 send half)
    /// paces the upload using curl's windowed `wait_time`.
    ///
    /// The engine installs the source only for a provably single-pass upload
    /// (known size, no redirect-following, no reactive auth), so the source is
    /// read straight through exactly once; a mid-stream
    /// [`CURL_READFUNC_PAUSE`] cannot be honored on a one-shot stream and is a
    /// read error (matching the buffered `read_full_upload`), and
    /// [`CURL_READFUNC_ABORT`] aborts the transfer.
    async fn stream_upload(&mut self, chunked: bool) -> Result<()> {
        // Heap buffer (not a stack array) so the 64 KiB block does not bloat the
        // size of this async fn's future.
        let mut buf = vec![0u8; super::chunks::CURL_CHUNKED_MAXLEN];
        let mut sent_total: u64 = 0;
        loop {
            // Pull the next block from the upload source. The source borrow is
            // released as soon as the synchronous read returns, before the body
            // bytes are written to the connection (which reborrows `self.conn`).
            let n = {
                let source = self
                    .upload_source
                    .as_deref_mut()
                    .ok_or(CurlError::ReadError)?;
                source.read(&mut buf)
            };
            match n {
                0 => break,
                CURL_READFUNC_ABORT => return Err(CurlError::AbortedByCallback),
                CURL_READFUNC_PAUSE => return Err(CurlError::ReadError),
                n if n <= buf.len() => {
                    if chunked {
                        // Frame this read as one chunk (hex length + CRLF + data
                        // + CRLF); the terminal zero-length chunk is sent at EOF.
                        let mut framed = Vec::with_capacity(n + 16);
                        framed.extend_from_slice(format!("{n:x}\r\n").as_bytes());
                        framed.extend_from_slice(&buf[..n]);
                        framed.extend_from_slice(b"\r\n");
                        send_all(&mut self.conn, &framed).await?;
                    } else {
                        send_all(&mut self.conn, &buf[..n]).await?;
                    }
                    sent_total += n as u64;
                    // Pace the upload between writes (curl's windowed rate
                    // limiter), mirroring the download throttle in the transfer
                    // engine. Unlimited transfers carry no limiter (`None`).
                    if let Some(rl) = self.upload_rate.as_mut() {
                        let delay = rl.wait_time(Direction::Upload, sent_total, Instant::now());
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                    }
                }
                _ => return Err(CurlError::ReadError),
            }
        }
        if chunked {
            // Terminal zero-length chunk closes the chunked body.
            send_all(&mut self.conn, b"0\r\n\r\n").await?;
        }
        Ok(())
    }

    /// Wait (bounded by [`Self::expect_100_timeout`]) for an interim response
    /// before sending the body, porting curl's `cr_exp100_read` wait.
    async fn await_interim_100(&mut self) -> Result<InterimOutcome> {
        let deadline = tokio::time::Instant::now() + self.expect_100_timeout;
        loop {
            if let Some(head) = self.try_parse_head(false)? {
                if head.code == 100 {
                    return Ok(InterimOutcome::Continue);
                }
                return Ok(InterimOutcome::FinalResponse(head));
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Ok(InterimOutcome::TimedOut);
            }
            let remaining = deadline - now;
            let mut tmp = [0u8; READ_CHUNK];
            match tokio::time::timeout(remaining, self.conn.recv(&mut tmp)).await {
                Ok(Ok(0)) => return Ok(InterimOutcome::TimedOut),
                Ok(Ok(n)) => self.rbuf.extend_from_slice(&tmp[..n]),
                Ok(Err(e)) => return Err(e),
                Err(_elapsed) => return Ok(InterimOutcome::TimedOut),
            }
        }
    }

    /// Read and parse the response head (status line + headers), buffering any
    /// trailing body bytes in [`Self::rbuf`].
    async fn read_response_head(&mut self) -> Result<ParsedHead> {
        loop {
            if let Some(head) = self.try_parse_head(false)? {
                return Ok(head);
            }
            let n = self.recv_more().await?;
            if n == 0 {
                // Peer closed: make a final lenient attempt (HTTP/0.9 body, or a
                // header block with no terminator).
                if let Some(head) = self.try_parse_head(true)? {
                    return Ok(head);
                }
                return Err(if self.rbuf.is_empty() {
                    CurlError::GotNothing
                } else {
                    CurlError::WeirdServerReply
                });
            }
        }
    }

    /// Try to parse a complete response head from [`Self::rbuf`]. Returns
    /// `Ok(None)` if more data is needed (unless `at_eof`). On the normal path
    /// the consumed head bytes are drained, leaving body bytes; on the HTTP/0.9
    /// path nothing is drained (the whole buffer is body).
    fn try_parse_head(&mut self, at_eof: bool) -> Result<Option<ParsedHead>> {
        let first_nl = find_subslice(&self.rbuf, b"\n");
        // We can attempt a parse once we have a full first line (a newline), or
        // at EOF with leftover bytes (a terminator-less final line, e.g. 0.9).
        let can_attempt = first_nl.is_some() || (at_eof && !self.rbuf.is_empty());
        if !can_attempt {
            return Ok(None);
        }
        let line_end = first_nl.map_or(self.rbuf.len(), |i| i + 1);
        let first_line = trim_crlf(&self.rbuf[..line_end]);

        match parse_status_line(first_line)? {
            StatusLine::NotStatusLine => {
                // Cannot be 0.9 if the connection was reused (curl: "Invalid
                // status line").
                if self.reuse {
                    return Err(CurlError::WeirdServerReply);
                }
                if !self.http09_allowed {
                    return Err(CurlError::UnsupportedProtocol);
                }
                // HTTP/0.9: no headers; the entire buffer is body (not drained).
                Ok(Some(ParsedHead {
                    code: 200,
                    minor: 9,
                    ..ParsedHead::default()
                }))
            }
            StatusLine::Http1 { minor, code } => {
                let end = match find_header_end(&self.rbuf) {
                    Some(e) => e,
                    None if at_eof => self.rbuf.len(),
                    None => return Ok(None),
                };
                let head_bytes: Vec<u8> = self.rbuf[..end].to_vec();
                self.rbuf.drain(..end);
                let mut head = parse_head_fields(&head_bytes);
                head.code = code;
                head.minor = minor;
                Ok(Some(head))
            }
        }
    }

    /// Queue the status/header events and configure body framing from a parsed
    /// head.
    ///
    /// # Errors
    ///
    /// [`CurlError::BadContentEncoding`] if `--tr-encoding` is in effect and the
    /// transfer-decode stack cannot be built (curl's decompression-bomb guard).
    /// The chunked-not-last rejection is *deferred* (queued via
    /// [`pending_error`](Self::pending_error)) so the preceding header lines are
    /// still delivered, matching curl's wire behavior.
    fn finish_head(&mut self, head: ParsedHead) -> Result<()> {
        self.status_code = head.code;
        self.resp_minor = head.minor;

        self.pending.push_back(ResponseEvent::Status(head.code));

        // Chunked-not-last rejection (`--tr-encoding` only): curl writes the
        // header lines that PRECEDE the offending `Transfer-Encoding` line, then
        // fails the transfer with `CURLE_BAD_CONTENT_ENCODING` (61) — never
        // emitting that line, the terminating blank line, the `HeadersComplete`
        // event, or any body (`lib/content_encoding.c`
        // `Curl_build_unencoding_stack`).
        if self.transfer_decoding {
            if let Some(bad) = head.te_violation_line {
                for line in head.header_lines.iter().take(bad) {
                    self.pending.push_back(ResponseEvent::Header(line.clone()));
                }
                self.body_done = true;
                self.keepalive = false;
                self.pending_error = Some(CurlError::BadContentEncoding);
                return Ok(());
            }
        }

        // Compute body framing first so the transfer-decode decision (which can
        // override the framing) is settled BEFORE the `HeadersComplete` event is
        // emitted. The transfer layer keys its short-read (`PartialFile`) check
        // off the `content_length` reported here, so a transfer-decoded body
        // must report an *unknown* length (curl's `k->ignore_cl = TRUE`).
        self.framing =
            response_body_framing(head.code, self.no_body, head.content_length, head.chunked);

        // Transfer decoding (`--tr-encoding`): build the transfer-decode stack
        // from the non-`chunked` transfer codings. This codec already handles
        // the `chunked` framing above (`BodyFraming::Chunked`); the remaining
        // codings (`gzip`, `deflate`, …) decode the de-framed body bytes. Gated
        // on `data.set.http_transfer_encoding`, exactly as curl gates the
        // `is_transfer` branch of `Curl_build_unencoding_stack`. There is no
        // body to decode for a header-only framing (`HEAD`, 204/304, 1xx).
        // `true` once the decompression-bomb guard trips (more than
        // `MAX_ENCODE_STACK - 1` stacked codings). curl writes the full header
        // block first — `Curl_build_unencoding_stack` runs at header-completion,
        // *after* the headers have been emitted — then fails the transfer with
        // the specific `failf` diagnostic. The error is therefore *deferred*
        // (queued via [`pending_error`](Self::pending_error)) exactly like the
        // chunked-not-last rejection above, so the headers still reach the client.
        let mut encoding_bomb = false;
        if self.transfer_decoding
            && !head.transfer_codings.is_empty()
            && !matches!(self.framing, BodyFraming::None)
        {
            let list = head.transfer_codings.join(", ");
            // `--tr-encoding` is an explicit opt-in, so decoding is force-enabled
            // (curl's `is_transfer && data->set.http_transfer_encoding`).
            match UnencodingStack::from_content_encoding(&list, true) {
                Ok(stack) => {
                    if !stack.is_empty() {
                        self.transfer_decoder = Some(stack);
                    }
                }
                // Decompression-bomb guard → defer the `CURLE_BAD_CONTENT_ENCODING`
                // (61) after the header block is written.
                Err(CurlError::TooManyContentEncodings) => encoding_bomb = true,
                Err(e) => return Err(e),
            }
        }

        // curl ignores `Content-Length` for any transfer-coded body (RFC 7230
        // §3.3.3: a present `Transfer-Encoding` makes `Content-Length` invalid)
        // and sets `k->size = -1`. Report an unknown length so the transfer
        // layer's short-read check is disabled; for a non-`chunked` coding it
        // also `streamclose()`s, since the body is then delimited only by
        // connection close (the encoded byte count is unreliable).
        let mut report_content_length = head.content_length;
        if self.transfer_decoder.is_some() {
            report_content_length = None;
            if matches!(self.framing, BodyFraming::ContentLength(_)) {
                self.framing = BodyFraming::CloseDelimited;
            }
        }

        // Configure per-framing read state from the FINAL framing.
        match self.framing {
            BodyFraming::ContentLength(len) => self.body_remaining = len,
            BodyFraming::Chunked => self.unchunker = Some(ChunkedUnencoder::new()),
            BodyFraming::None => self.body_done = true,
            BodyFraming::CloseDelimited => {}
        }

        for line in &head.header_lines {
            self.pending.push_back(ResponseEvent::Header(line.clone()));
        }
        self.pending.push_back(ResponseEvent::HeadersComplete {
            content_length: report_content_length.and_then(|v| i64::try_from(v).ok()),
            content_encoding: head.content_encoding.clone(),
        });

        // Deferred decompression-bomb failure: the header block is now queued, so
        // raise curl's `CURLE_BAD_CONTENT_ENCODING` (61) with the specific
        // "more than 5 content encodings" diagnostic and deliver no body.
        if encoding_bomb {
            self.body_done = true;
            self.keepalive = false;
            self.pending_error = Some(CurlError::TooManyContentEncodings);
            return Ok(());
        }

        self.keepalive = self.compute_keepalive(&head);

        // A non-`chunked` transfer coding forces connection close (curl's
        // streamclose); chunked stays keep-alive-eligible since chunked framing
        // is self-delimiting.
        if self.transfer_decoder.is_some() && !matches!(self.framing, BodyFraming::Chunked) {
            self.keepalive = false;
        }

        Ok(())
    }

    /// curl's keep-alive / connection-reuse decision for this response.
    fn compute_keepalive(&self, head: &ParsedHead) -> bool {
        if head.minor == 9 {
            return false;
        }
        if matches!(self.framing, BodyFraming::CloseDelimited) {
            return false;
        }
        if head.connection_close {
            return false;
        }
        if head.minor >= 1 {
            true
        } else {
            head.connection_keepalive
        }
    }

    /// Read the next de-framed body chunk; `Ok(None)` marks the body complete.
    async fn read_body_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        match self.framing {
            BodyFraming::None => Ok(None),
            BodyFraming::ContentLength(_) => self.read_body_content_length().await,
            BodyFraming::Chunked => self.read_body_chunked().await,
            BodyFraming::CloseDelimited => self.read_body_close().await,
        }
    }

    /// Body event for a transfer-decoded response (`--tr-encoding`): read the
    /// next de-framed chunk, feed it through the transfer-decode stack, and emit
    /// the decoded output. Reads on (skips) chunks that produce no decoded bytes
    /// (the decoder buffering input), and at end-of-body flushes the decoder's
    /// buffered tail before the terminating [`ResponseEvent::End`]. Mirrors
    /// curl's `CURL_CW_TRANSFER_DECODE` writer chain draining body writes.
    async fn next_decoded_body_event(&mut self) -> Result<ResponseEvent> {
        loop {
            match self.read_body_chunk().await? {
                Some(chunk) => {
                    let mut out = Vec::new();
                    {
                        let dec = self
                            .transfer_decoder
                            .as_mut()
                            .expect("transfer_decoder present");
                        dec.write(true, &chunk, &mut |b| {
                            out.extend_from_slice(b);
                            Ok(())
                        })?;
                    }
                    // The underlying framing can signal completion *together
                    // with* the final data chunk: `read_body_chunked` sets
                    // `body_done` and returns the last data in the SAME call when
                    // the terminal `0`-chunk shares the buffer. Flush the
                    // decoder's buffered tail now — otherwise `next_event` would
                    // short-circuit on `body_done` and never call `finish`,
                    // truncating the decoded body (the decoder may hold most of
                    // its output until the stream's end, e.g. gzip's trailer).
                    if self.body_done {
                        {
                            let dec = self
                                .transfer_decoder
                                .as_mut()
                                .expect("transfer_decoder present");
                            dec.finish(&mut |b| {
                                out.extend_from_slice(b);
                                Ok(())
                            })?;
                        }
                        self.transfer_decoder = None;
                        if !out.is_empty() {
                            self.pending.push_back(ResponseEvent::End);
                            return Ok(ResponseEvent::Body(out));
                        }
                        return Ok(ResponseEvent::End);
                    }
                    if !out.is_empty() {
                        return Ok(ResponseEvent::Body(out));
                    }
                    // The decoder buffered this input without producing output
                    // yet (e.g. a partial gzip member) — read the next chunk.
                }
                None => {
                    // End of the de-framed body reported on its own read (e.g.
                    // close-delimited framing): flush the decoder's buffered
                    // tail. Any flushed bytes are delivered as a final `Body`
                    // event, with `End` queued behind it.
                    let mut out = Vec::new();
                    {
                        let dec = self
                            .transfer_decoder
                            .as_mut()
                            .expect("transfer_decoder present");
                        dec.finish(&mut |b| {
                            out.extend_from_slice(b);
                            Ok(())
                        })?;
                    }
                    self.body_done = true;
                    self.transfer_decoder = None;
                    if !out.is_empty() {
                        self.pending.push_back(ResponseEvent::End);
                        return Ok(ResponseEvent::Body(out));
                    }
                    return Ok(ResponseEvent::End);
                }
            }
        }
    }

    /// Body delimited by `Content-Length`: deliver exactly `body_remaining`
    /// bytes, short-reading to [`CurlError::PartialFile`] on premature EOF.
    async fn read_body_content_length(&mut self) -> Result<Option<Vec<u8>>> {
        if self.body_remaining == 0 {
            self.body_done = true;
            return Ok(None);
        }
        if self.rbuf.is_empty() {
            let n = self.recv_more().await?;
            if n == 0 {
                return Err(CurlError::PartialFile);
            }
        }
        let take = core::cmp::min(self.rbuf.len() as u64, self.body_remaining) as usize;
        let chunk: Vec<u8> = self.rbuf.drain(..take).collect();
        self.body_remaining -= take as u64;
        if self.body_remaining == 0 {
            self.body_done = true;
        }
        Ok(Some(chunk))
    }

    /// Body delimited by chunked Transfer-Encoding: feed wire bytes through the
    /// [`ChunkedUnencoder`] and deliver de-chunked content.
    async fn read_body_chunked(&mut self) -> Result<Option<Vec<u8>>> {
        let no_body = self.no_body;
        loop {
            let is_eof = if self.rbuf.is_empty() {
                self.recv_more().await? == 0
            } else {
                false
            };

            let mut out: Vec<u8> = Vec::new();
            let (consumed, download_done) = {
                let dec = self.unchunker.as_mut().ok_or(CurlError::ChunkFailed)?;
                let mut sink = |data: &[u8], ty: ClientWriteType| -> Result<()> {
                    if ty.contains(ClientWriteType::BODY) {
                        out.extend_from_slice(data);
                    }
                    Ok(())
                };
                let cw = dec.write_body(false, no_body, is_eof, &self.rbuf, &mut sink)?;
                (cw.consumed, cw.download_done)
            };
            self.rbuf.drain(..consumed);

            if download_done {
                self.body_done = true;
                return Ok(if out.is_empty() { None } else { Some(out) });
            }
            if is_eof {
                // EOF before the terminal `0\r\n` chunk.
                return Err(CurlError::PartialFile);
            }
            if !out.is_empty() {
                return Ok(Some(out));
            }
            if consumed == 0 {
                // Partial chunk header consumed nothing; pull more bytes.
                if self.recv_more().await? == 0 {
                    return Err(CurlError::PartialFile);
                }
            }
        }
    }

    /// Body delimited by connection close: deliver everything until EOF.
    async fn read_body_close(&mut self) -> Result<Option<Vec<u8>>> {
        if !self.rbuf.is_empty() {
            return Ok(Some(core::mem::take(&mut self.rbuf)));
        }
        let n = self.recv_more().await?;
        if n == 0 {
            self.body_done = true;
            return Ok(None);
        }
        Ok(Some(core::mem::take(&mut self.rbuf)))
    }
}

impl<'u, C: ByteStream> ProtocolExchange for H1Exchange<'u, C> {
    async fn next_event(&mut self) -> Result<ResponseEvent> {
        if !self.sent {
            self.start().await?;
            self.sent = true;
        }
        if let Some(ev) = self.pending.pop_front() {
            return Ok(ev);
        }
        // Surface a deferred error (the chunked-not-last rejection) only after
        // the queued header events have drained, so the preceding header lines
        // reach the client first — matching curl's wire behavior.
        if let Some(err) = self.pending_error.take() {
            return Err(err);
        }
        if self.body_done {
            return Ok(ResponseEvent::End);
        }
        // A compressed `Transfer-Encoding` body (`--tr-encoding`) is decoded
        // through the transfer-decode stack; otherwise the de-framed body bytes
        // are delivered verbatim.
        if self.transfer_decoder.is_some() {
            return self.next_decoded_body_event().await;
        }
        match self.read_body_chunk().await? {
            Some(chunk) => Ok(ResponseEvent::Body(chunk)),
            None => {
                self.body_done = true;
                Ok(ResponseEvent::End)
            }
        }
    }

    async fn send_body(&mut self, data: &[u8]) -> Result<usize> {
        self.conn.send(data).await
    }
}

/// The result of [`H1Exchange::await_interim_100`].
enum InterimOutcome {
    /// A `100 Continue` interim response was received and consumed.
    Continue,
    /// A final response arrived before any `100` (e.g. `417`); its head is
    /// parsed and the body must not be sent.
    FinalResponse(ParsedHead),
    /// No interim response arrived within the timeout.
    TimedOut,
}

// ===========================================================================
// Free helpers (codec internals)
// ===========================================================================

/// Write `data` in full, looping over partial writes; an accepted count of `0`
/// is treated as a send failure ([`CurlError::SendError`]).
async fn send_all<C: ByteStream>(conn: &mut C, data: &[u8]) -> Result<()> {
    let mut off = 0;
    while off < data.len() {
        let n = conn.send(&data[off..]).await?;
        if n == 0 {
            return Err(CurlError::SendError);
        }
        off += n;
    }
    Ok(())
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Index just past the end-of-headers blank line (the earlier of `CRLFCRLF` or
/// `LFLF`), or `None` if the header block is incomplete.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    let crlf = find_subslice(buf, b"\r\n\r\n").map(|i| i + 4);
    let lf = find_subslice(buf, b"\n\n").map(|i| i + 2);
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
    }
}

/// Strip a trailing `\n` then a trailing `\r` from a line.
fn trim_crlf(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    if end > 0 && line[end - 1] == b'\n' {
        end -= 1;
    }
    if end > 0 && line[end - 1] == b'\r' {
        end -= 1;
    }
    &line[..end]
}

/// Trim ASCII spaces and tabs from both ends of `bytes` (MSRV-safe; avoids the
/// 1.80+ `[u8]::trim_ascii`).
fn trim_ascii_ws(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && (bytes[start] == b' ' || bytes[start] == b'\t') {
        start += 1;
    }
    while end > start && (bytes[end - 1] == b' ' || bytes[end - 1] == b'\t') {
        end -= 1;
    }
    &bytes[start..end]
}

/// `true` if the comma-separated header `value` contains `token` (compared
/// case-insensitively after trimming each element) — for `Connection:` and
/// `Transfer-Encoding:` token tests.
fn header_has_token(value: &[u8], token: &[u8]) -> bool {
    value
        .split(|&c| c == b',')
        .any(|part| trim_ascii_ws(part).eq_ignore_ascii_case(token))
}

/// Parse the framing-relevant fields and raw lines from a response head block
/// (status line + headers + terminating blank line).
fn parse_head_fields(head_bytes: &[u8]) -> ParsedHead {
    let mut head = ParsedHead::default();
    // Tracks whether a `chunked` transfer coding has been seen so far, in list
    // order across all `Transfer-Encoding` header lines — curl's `has_chunked`
    // in `Curl_build_unencoding_stack`. A subsequent non-`chunked` coding is a
    // protocol violation (chunked must be last).
    let mut seen_chunked = false;
    for (line_index, line) in head_bytes.split_inclusive(|&c| c == b'\n').enumerate() {
        head.header_lines.push(line.to_vec());
        if let Some((name, value)) = parse_header_line(line) {
            if name.eq_ignore_ascii_case(b"content-length") {
                if let Ok(s) = core::str::from_utf8(value) {
                    if let Ok(n) = s.trim().parse::<u64>() {
                        head.content_length = Some(n);
                    }
                }
            } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
                // Parse each coding token left-to-right (curl processes the
                // comma list in order). `chunked` sets the framing and must be
                // the LAST coding; any non-`chunked` coding seen after `chunked`
                // is rejected with `CURLE_BAD_CONTENT_ENCODING` (RFC 9112 §6.1).
                // Non-`chunked` codings are collected in order to build the
                // transfer-decode stack (when `--tr-encoding` is in effect).
                for tok in value.split(|&c| c == b',') {
                    let t = trim_ascii_ws(tok);
                    if t.is_empty() {
                        continue;
                    }
                    if t.eq_ignore_ascii_case(b"chunked") {
                        head.chunked = true;
                        seen_chunked = true;
                    } else {
                        if seen_chunked && head.te_violation_line.is_none() {
                            head.te_violation_line = Some(line_index);
                        }
                        if let Ok(s) = core::str::from_utf8(t) {
                            head.transfer_codings.push(s.to_ascii_lowercase());
                        }
                    }
                }
            } else if name.eq_ignore_ascii_case(b"content-encoding") {
                if let Ok(s) = core::str::from_utf8(value) {
                    let t = s.trim();
                    if !t.is_empty() {
                        head.content_encoding = Some(t.to_string());
                    }
                }
            } else if name.eq_ignore_ascii_case(b"connection") {
                if header_has_token(value, b"close") {
                    head.connection_close = true;
                }
                if header_has_token(value, b"keep-alive") {
                    head.connection_keepalive = true;
                }
            }
        }
    }
    // RFC 7230 §3.3.3: chunked Transfer-Encoding overrides any Content-Length.
    if head.chunked {
        head.content_length = None;
    }
    head
}

// ===========================================================================
// Redirect / follow policy (oracle: lib/http.c `Curl_http_follow`)
// ===========================================================================

/// Map a [`crate::setopt::HttpReq`] to the [`crate::transfer::HttpMethod`] the
/// redirect-rewrite logic distinguishes.
fn setopt_to_transfer_method(req: HttpReq) -> HttpMethod {
    match req {
        HttpReq::Get => HttpMethod::Get,
        HttpReq::Post => HttpMethod::Post,
        HttpReq::PostForm => HttpMethod::PostForm,
        HttpReq::PostMime => HttpMethod::PostMime,
        HttpReq::Put => HttpMethod::Put,
        HttpReq::Head => HttpMethod::Head,
    }
}

/// Map a [`crate::transfer::HttpMethod`] back to a [`crate::setopt::HttpReq`].
fn transfer_to_setopt_method(method: HttpMethod) -> HttpReq {
    match method {
        HttpMethod::Get => HttpReq::Get,
        HttpMethod::Post => HttpReq::Post,
        HttpMethod::PostForm => HttpReq::PostForm,
        HttpMethod::PostMime => HttpReq::PostMime,
        HttpMethod::Put => HttpReq::Put,
        HttpMethod::Head => HttpReq::Head,
    }
}

/// Decide how a redirect rewrites the request method, porting the method-rewrite
/// half of `Curl_http_follow` (which delegates to
/// [`crate::transfer::redirect_method`]).
///
/// Returns the (possibly rewritten) request kind and `true` if it changed:
/// `301`/`302` downgrade a POST-family request to `GET` unless the matching
/// `CURLOPT_POSTREDIR` bit is set; `303` downgrades any non-`GET` method to
/// `GET` unless a POST is explicitly kept. Other statuses keep the method.
#[must_use]
pub fn follow_method_rewrite(
    status: i32,
    method: HttpReq,
    post_redir: &PostRedir,
) -> (HttpReq, bool) {
    let (rewritten, changed) =
        redirect_method(status, setopt_to_transfer_method(method), post_redir);
    (transfer_to_setopt_method(rewritten), changed)
}

/// Resolve a `Location` value against the request `base` URL, porting curl's
/// relative-redirect resolution (`Curl_follow` → `curl_url_set(CURLUPART_URL)`).
///
/// An absolute `Location` replaces the URL; a relative one is resolved against
/// `base`'s scheme/host/path. Returns the fully-qualified next URL.
///
/// # Errors
///
/// [`CurlError::UrlMalformat`] (via [`crate::transfer::uc_to_curlcode`]) if the
/// `Location` cannot be resolved into a valid absolute URL.
pub fn resolve_redirect_url(base: &CurlUrl, location: &str) -> Result<String> {
    // `CurlUrl::resolve` is curl's `curl_url_dup` + `curl_url_set(CURLUPART_URL)`
    // — an absolute `location` replaces the URL, a relative one is resolved
    // against `base`. Reading it back yields the fully-qualified next URL.
    let next = base
        .resolve(location, 0)
        .map_err(transfer::uc_to_curlcode)?;
    next.get(CurlUPart::Url, 0)
        .map_err(transfer::uc_to_curlcode)
}

// ===========================================================================
// done / connection reuse (oracle: lib/http.c `Curl_http_done`)
// ===========================================================================

/// Apply the connection-reuse decision after a response, porting the reuse vs
/// close half of `Curl_http_done`.
///
/// `keepalive` is [`H1Exchange::keepalive`]: when `true` the connection is marked
/// for reuse ([`Connection::connkeep`]); otherwise it is marked to close
/// ([`Connection::connclose`]). Per-request authentication credential clearing
/// (`Curl_http_done` clearing `aptr.userpwd` / `aptr.proxyuserpwd`) is owned by
/// the `crate::auth` state on the handle and performed by the caller.
pub fn apply_connection_reuse(conn: &mut Connection, keepalive: bool) {
    if keepalive {
        conn.connkeep("HTTP keep-alive");
    } else {
        conn.connclose("HTTP response indicates connection close");
    }
}

// ===========================================================================
// Tests
//
// The oracle for the wire-parity vectors is curl 8.x's `lib/http.c` /
// `lib/http1.c`: the default request for a simple `GET http://host/` is exactly
// `Host`, `User-Agent`, `Accept` in that order (a plain GET sends no
// `Connection` header), the header order follows the `H1_HD_*` enum, and the
// response header callback delivers the status line and the terminating blank
// line as header lines.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{SchemeDescriptor, TRNSPRT_TCP};

    // ---- construction helpers ---------------------------------------------

    /// Parse a full URL into a handle, as the engine populates `data->state.uh`.
    fn parse_url(s: &str) -> CurlUrl {
        let mut u = CurlUrl::new();
        u.set(CurlUPart::Url, Some(s), 0)
            .unwrap_or_else(|e| panic!("parse {s:?} failed: {e:?}"));
        u
    }

    /// A direct (no-proxy) connection (origin-form request targets).
    fn direct_conn() -> Connection {
        Connection::new(
            "test-dest",
            TRNSPRT_TCP,
            SchemeDescriptor::new("http", 80, 0, 0),
        )
    }

    /// A forward HTTP-proxy connection (absolute-form request targets).
    fn forward_proxy_conn() -> Connection {
        let mut conn = direct_conn();
        conn.bits.httpproxy = true;
        conn.bits.tunnel_proxy = false;
        conn
    }

    /// A baseline `GET` [`RequestInputs`] over `url`/`conn`, every optional field
    /// suppressed. Tests mutate the specific fields they exercise. `user_agent`
    /// is `None` so the bare default-header tests are explicit about it.
    fn get_inputs<'a>(url: &'a CurlUrl, conn: &'a Connection) -> RequestInputs<'a> {
        RequestInputs {
            url,
            conn,
            method_kind: HttpReq::Get,
            no_body: false,
            custom_request: None,
            is_websocket: false,
            is_upload: false,
            host: "example.com",
            port: 80,
            is_https: false,
            host_header_present: false,
            user_agent: None,
            authorization: None,
            proxy_authorization: None,
            range: None,
            accept_present: false,
            te_gzip: false,
            accept_encoding: None,
            referer: None,
            proxy_connection_keepalive: false,
            cookie: None,
            body: RequestBody::None,
            content_type: None,
            content_length: None,
            chunked: false,
            disable_expect: false,
            expect_present: false,
            custom_expect_100: false,
            is_upgrade: false,
            custom_headers: &[],
            proxy_headers: &[],
            sep_headers: false,
            authneg: false,
            allowed_to_host: true,
            http_minor: 1,
            request_target_override: None,
            proxy_transfer_mode: false,
            prefer_ascii: false,
            expect_100_timeout_ms: 0,
        }
    }

    // ---- method mapping (resolve_http_method) -----------------------------

    #[test]
    fn method_get_is_default() {
        let r = resolve_http_method(HttpReq::Get, false, None, false, false).unwrap();
        assert_eq!(r.method, http::Method::GET);
        assert_eq!(r.kind, HttpReq::Get);
    }

    #[test]
    fn method_no_body_forces_head() {
        let r = resolve_http_method(HttpReq::Get, true, None, false, false).unwrap();
        assert_eq!(r.method, http::Method::HEAD);
    }

    #[test]
    fn method_post_family_maps_to_post() {
        for kind in [HttpReq::Post, HttpReq::PostForm, HttpReq::PostMime] {
            let r = resolve_http_method(kind, false, None, false, false).unwrap();
            assert_eq!(r.method, http::Method::POST);
            assert_eq!(r.kind, kind, "kind must be preserved");
        }
    }

    #[test]
    fn method_put_maps_to_put() {
        let r = resolve_http_method(HttpReq::Put, false, None, false, false).unwrap();
        assert_eq!(r.method, http::Method::PUT);
    }

    #[test]
    fn method_websocket_forces_get() {
        // WS/WSS → GET even when the kind says POST.
        let r = resolve_http_method(HttpReq::Post, false, None, true, false).unwrap();
        assert_eq!(r.method, http::Method::GET);
        assert_eq!(r.kind, HttpReq::Get);
    }

    #[test]
    fn method_upload_forces_put() {
        let r = resolve_http_method(HttpReq::Get, false, None, false, true).unwrap();
        assert_eq!(r.method, http::Method::PUT);
        assert_eq!(r.kind, HttpReq::Put);
    }

    #[test]
    fn method_custom_request_overrides_verb_keeps_kind() {
        // `-X DELETE -d data`: verb string = DELETE, kind stays POST (so the
        // body is still framed).
        let r = resolve_http_method(HttpReq::Post, false, Some("DELETE"), false, false).unwrap();
        assert_eq!(r.method.as_str(), "DELETE");
        assert_eq!(r.kind, HttpReq::Post);
    }

    #[test]
    fn method_empty_custom_request_is_ignored() {
        let r = resolve_http_method(HttpReq::Get, false, Some(""), false, false).unwrap();
        assert_eq!(r.method, http::Method::GET);
    }

    #[test]
    fn method_invalid_custom_request_errors() {
        let err =
            resolve_http_method(HttpReq::Get, false, Some("bad method"), false, false).unwrap_err();
        assert!(matches!(err, CurlError::BadFunctionArgument));
    }

    // ---- version token ----------------------------------------------------

    #[test]
    fn version_token_maps_minor() {
        assert_eq!(http_version_token(1), "1.1");
        assert_eq!(http_version_token(0), "1.0");
    }

    // ---- host header (build_host_header_value) ----------------------------

    #[test]
    fn host_http_default_port_suppressed() {
        assert_eq!(
            build_host_header_value("example.com", 80, false),
            "example.com"
        );
    }

    #[test]
    fn host_https_default_port_suppressed() {
        assert_eq!(
            build_host_header_value("example.com", 443, true),
            "example.com"
        );
    }

    #[test]
    fn host_nondefault_port_emitted() {
        assert_eq!(
            build_host_header_value("example.com", 8080, false),
            "example.com:8080"
        );
        // HTTP on 443 is non-default for HTTP → port is kept.
        assert_eq!(
            build_host_header_value("example.com", 443, false),
            "example.com:443"
        );
    }

    #[test]
    fn host_ipv6_is_bracketed() {
        assert_eq!(build_host_header_value("::1", 80, false), "[::1]");
        assert_eq!(build_host_header_value("::1", 8080, false), "[::1]:8080");
        // Already-bracketed input is not double-bracketed.
        assert_eq!(
            build_host_header_value("[2001:db8::1]", 443, true),
            "[2001:db8::1]"
        );
    }

    // ---- user agent -------------------------------------------------------

    #[test]
    fn default_user_agent_is_curl_version() {
        assert_eq!(
            default_user_agent(),
            format!("curl/{}", crate::version::VERSION)
        );
    }

    // ---- Expect: 100-continue triggers ------------------------------------

    #[test]
    fn expect100_triggers_on_large_body() {
        // HTTP/1.1, not disabled, not upgrade, body > 1 MiB → announce.
        assert!(should_add_expect_100(
            1,
            false,
            false,
            false,
            EXPECT_100_THRESHOLD + 1
        ));
    }

    #[test]
    fn expect100_triggers_on_unknown_length() {
        assert!(should_add_expect_100(1, false, false, false, -1));
    }

    #[test]
    fn expect100_suppressed_on_small_body() {
        assert!(!should_add_expect_100(1, false, false, false, 10));
        assert!(!should_add_expect_100(
            1,
            false,
            false,
            false,
            EXPECT_100_THRESHOLD
        ));
    }

    #[test]
    fn expect100_suppressed_on_http10() {
        assert!(!should_add_expect_100(0, false, false, false, -1));
    }

    #[test]
    fn expect100_suppressed_when_disabled_or_custom_or_upgrade() {
        assert!(!should_add_expect_100(1, true, false, false, -1)); // disabled
        assert!(!should_add_expect_100(1, false, true, false, -1)); // custom Expect
        assert!(!should_add_expect_100(1, false, false, true, -1)); // upgrade in flight
    }

    // ---- status-line parsing ----------------------------------------------

    #[test]
    fn status_line_http11_ok() {
        assert_eq!(
            parse_status_line(b"HTTP/1.1 200 OK").unwrap(),
            StatusLine::Http1 {
                minor: 1,
                code: 200
            }
        );
    }

    #[test]
    fn status_line_http10_notfound() {
        assert_eq!(
            parse_status_line(b"HTTP/1.0 404 Not Found").unwrap(),
            StatusLine::Http1 {
                minor: 0,
                code: 404
            }
        );
    }

    #[test]
    fn status_line_leading_blanks_tolerated() {
        assert_eq!(
            parse_status_line(b"  \tHTTP/1.1 204 No Content").unwrap(),
            StatusLine::Http1 {
                minor: 1,
                code: 204
            }
        );
    }

    #[test]
    fn status_line_non_http_is_not_status_line() {
        assert_eq!(
            parse_status_line(b"some random text").unwrap(),
            StatusLine::NotStatusLine
        );
        assert_eq!(
            parse_status_line(b"<html>").unwrap(),
            StatusLine::NotStatusLine
        );
    }

    #[test]
    fn status_line_bad_subversion_errors() {
        // HTTP/1.2 is an unsupported HTTP/1 subversion.
        assert!(matches!(
            parse_status_line(b"HTTP/1.2 200 OK"),
            Err(CurlError::UnsupportedProtocol)
        ));
    }

    // ---- header-line parsing ----------------------------------------------

    #[test]
    fn header_line_basic() {
        let (n, v) = parse_header_line(b"Content-Type: text/html\r\n").unwrap();
        assert_eq!(n, b"Content-Type");
        assert_eq!(v, b"text/html");
    }

    #[test]
    fn header_line_trims_surrounding_blanks() {
        let (n, v) = parse_header_line(b"X-Test:   spaced value  \r\n").unwrap();
        assert_eq!(n, b"X-Test");
        assert_eq!(v, b"spaced value");
    }

    #[test]
    fn header_line_blank_and_colonless_are_none() {
        assert!(parse_header_line(b"\r\n").is_none());
        assert!(parse_header_line(b"no-colon-here\r\n").is_none());
    }

    // ---- request-target selection -----------------------------------------

    #[test]
    fn request_target_direct_is_origin_form() {
        let url = parse_url("http://example.com/path?q=1");
        let conn = direct_conn();
        assert_eq!(
            request_target(&url, &conn, None, false, false).unwrap(),
            "/path?q=1"
        );
    }

    #[test]
    fn request_target_forward_proxy_is_absolute_form() {
        let url = parse_url("http://example.com/path?q=1");
        let conn = forward_proxy_conn();
        assert_eq!(
            request_target(&url, &conn, None, false, false).unwrap(),
            "http://example.com/path?q=1"
        );
    }

    // ---- response body framing --------------------------------------------

    #[test]
    fn framing_no_body_for_head_and_bodyless_status() {
        assert_eq!(
            response_body_framing(200, true, Some(5), false),
            BodyFraming::None
        );
        assert_eq!(
            response_body_framing(204, false, None, false),
            BodyFraming::None
        );
        assert_eq!(
            response_body_framing(304, false, Some(5), false),
            BodyFraming::None
        );
        assert_eq!(
            response_body_framing(100, false, None, false),
            BodyFraming::None
        );
    }

    #[test]
    fn framing_chunked_overrides_content_length() {
        // RFC 7230 §3.3.3: chunked wins over Content-Length.
        assert_eq!(
            response_body_framing(200, false, Some(5), true),
            BodyFraming::Chunked
        );
    }

    #[test]
    fn framing_content_length_then_close() {
        assert_eq!(
            response_body_framing(200, false, Some(42), false),
            BodyFraming::ContentLength(42)
        );
        assert_eq!(
            response_body_framing(200, false, None, false),
            BodyFraming::CloseDelimited
        );
    }

    // ---- redirect method rewrite ------------------------------------------

    #[test]
    fn redirect_301_302_post_downgrades_to_get() {
        for status in [301, 302] {
            let (m, changed) = follow_method_rewrite(status, HttpReq::Post, &PostRedir::default());
            assert_eq!(m, HttpReq::Get);
            assert!(changed);
        }
    }

    #[test]
    fn redirect_301_keeps_post_when_post301_set() {
        let pr = PostRedir {
            post301: true,
            ..PostRedir::default()
        };
        let (m, changed) = follow_method_rewrite(301, HttpReq::Post, &pr);
        assert_eq!(m, HttpReq::Post);
        assert!(!changed);
    }

    #[test]
    fn redirect_303_downgrades_non_get_to_get() {
        let (m, changed) = follow_method_rewrite(303, HttpReq::Post, &PostRedir::default());
        assert_eq!(m, HttpReq::Get);
        assert!(changed);
    }

    #[test]
    fn redirect_307_preserves_method() {
        let (m, changed) = follow_method_rewrite(307, HttpReq::Post, &PostRedir::default());
        assert_eq!(m, HttpReq::Post);
        assert!(!changed);
    }

    #[test]
    fn redirect_get_stays_get() {
        let (m, changed) = follow_method_rewrite(302, HttpReq::Get, &PostRedir::default());
        assert_eq!(m, HttpReq::Get);
        assert!(!changed);
    }

    // ---- relative redirect resolution -------------------------------------

    #[test]
    fn resolve_redirect_relative_against_base() {
        let base = parse_url("http://example.com/a/b/c?x=1");
        assert_eq!(
            resolve_redirect_url(&base, "/d/e").unwrap(),
            "http://example.com/d/e"
        );
        assert_eq!(
            resolve_redirect_url(&base, "other").unwrap(),
            "http://example.com/a/b/other"
        );
    }

    #[test]
    fn resolve_redirect_absolute_replaces() {
        let base = parse_url("http://example.com/a");
        assert_eq!(
            resolve_redirect_url(&base, "https://other.test/x").unwrap(),
            "https://other.test/x"
        );
    }

    // ---- connection reuse (apply_connection_reuse) ------------------------

    #[test]
    fn connection_reuse_marks_keep_or_close() {
        let mut conn = direct_conn();
        apply_connection_reuse(&mut conn, true);
        assert!(!conn.is_closed(), "keepalive must not set the close bit");

        let mut conn2 = direct_conn();
        apply_connection_reuse(&mut conn2, false);
        assert!(conn2.is_closed(), "no-keepalive must set the close bit");
    }

    // ---- build_request: assembled head + wire-parity ----------------------

    /// Assert `first` appears before `second` in `head`.
    fn assert_order(head: &str, first: &str, second: &str) {
        let i = head
            .find(first)
            .unwrap_or_else(|| panic!("{first:?} not found in:\n{head}"));
        let j = head
            .find(second)
            .unwrap_or_else(|| panic!("{second:?} not found in:\n{head}"));
        assert!(i < j, "expected {first:?} before {second:?} in:\n{head}");
    }

    /// THE wire-parity spot check: a simple `GET http://host/` sends exactly
    /// `Host`, `User-Agent`, `Accept` — in that order, and no `Connection`
    /// header (oracle: `lib/http.c` default request).
    #[test]
    fn build_simple_get_exact_default_headers() {
        let url = parse_url("http://example.com/");
        let conn = direct_conn();
        let ua = default_user_agent();
        let mut inputs = get_inputs(&url, &conn);
        inputs.user_agent = Some(&ua);

        let plan = build_request(&inputs).unwrap();
        let head = String::from_utf8(plan.head).unwrap();
        let expected = format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: {ua}\r\nAccept: */*\r\n\r\n"
        );
        assert_eq!(head, expected);
        assert!(!plan.expect_100);
        assert!(
            !head.contains("Connection:"),
            "a plain GET sends no Connection header"
        );
    }

    #[test]
    fn build_post_has_content_length_and_default_type() {
        let url = parse_url("http://example.com/submit");
        let conn = direct_conn();
        let body = b"name=fred".to_vec();
        let mut inputs = get_inputs(&url, &conn);
        inputs.method_kind = HttpReq::Post;
        inputs.content_length = Some(body.len() as i64);
        inputs.body = RequestBody::Sized(body);

        let head = String::from_utf8(build_request(&inputs).unwrap().head).unwrap();
        assert!(head.starts_with("POST /submit HTTP/1.1\r\n"));
        assert!(head.contains("Content-Length: 9\r\n"));
        assert!(head.contains("Content-Type: application/x-www-form-urlencoded\r\n"));
        // http_add_content_hds emits Content-Length before Content-Type.
        assert_order(&head, "Content-Length:", "Content-Type:");
        // A small known body → no Expect.
        assert!(!head.contains("Expect:"));
    }

    #[test]
    fn build_put_keeps_explicit_content_type_no_default() {
        let url = parse_url("http://example.com/r");
        let conn = direct_conn();
        let mut inputs = get_inputs(&url, &conn);
        inputs.method_kind = HttpReq::Put;
        inputs.content_type = Some("application/octet-stream");
        inputs.content_length = Some(3);
        inputs.body = RequestBody::Sized(b"abc".to_vec());

        let head = String::from_utf8(build_request(&inputs).unwrap().head).unwrap();
        assert!(head.contains("Content-Type: application/octet-stream\r\n"));
        // PUT (not POST) gets no implicit form content-type.
        assert!(!head.contains("x-www-form-urlencoded"));
    }

    #[test]
    fn build_chunked_put_te_ordering_and_expect() {
        let url = parse_url("http://example.com/up");
        let conn = direct_conn();
        let mut inputs = get_inputs(&url, &conn);
        inputs.method_kind = HttpReq::Put;
        inputs.chunked = true;
        inputs.cookie = Some("session=abc");
        inputs.body = RequestBody::Chunked(b"data".to_vec());

        let plan = build_request(&inputs).unwrap();
        let head = String::from_utf8(plan.head).unwrap();
        assert!(head.contains("Transfer-Encoding: chunked\r\n"));
        assert!(
            !head.contains("Content-Length:"),
            "chunked must not advertise Content-Length"
        );
        // H1_HD_TRANSFER_ENCODING precedes H1_HD_COOKIES.
        assert_order(&head, "Transfer-Encoding:", "Cookie:");
        // Unknown-length chunked body → Expect: 100-continue.
        assert!(head.contains("Expect: 100-continue\r\n"));
        assert!(plan.expect_100);
    }

    #[test]
    fn build_suppresses_default_host_when_present() {
        let url = parse_url("http://example.com/");
        let conn = direct_conn();
        let custom = vec!["Host: override.example".to_string()];
        let mut inputs = get_inputs(&url, &conn);
        inputs.host_header_present = true;
        inputs.custom_headers = &custom;

        let head = String::from_utf8(build_request(&inputs).unwrap().head).unwrap();
        assert_eq!(
            head.matches("Host:").count(),
            1,
            "default Host must be suppressed"
        );
        assert!(head.contains("Host: override.example\r\n"));
    }

    #[test]
    fn build_suppresses_default_accept_when_present() {
        let url = parse_url("http://example.com/");
        let conn = direct_conn();
        let custom = vec!["Accept: application/json".to_string()];
        let mut inputs = get_inputs(&url, &conn);
        inputs.accept_present = true;
        inputs.custom_headers = &custom;

        let head = String::from_utf8(build_request(&inputs).unwrap().head).unwrap();
        assert!(
            !head.contains("Accept: */*"),
            "default Accept must be suppressed"
        );
        assert!(head.contains("Accept: application/json\r\n"));
    }

    #[test]
    fn build_custom_header_after_cookie() {
        let url = parse_url("http://example.com/");
        let conn = direct_conn();
        let custom = vec!["X-Custom: yes".to_string()];
        let mut inputs = get_inputs(&url, &conn);
        inputs.cookie = Some("c=1");
        inputs.custom_headers = &custom;

        let head = String::from_utf8(build_request(&inputs).unwrap().head).unwrap();
        assert!(head.contains("Cookie: c=1\r\n"));
        assert!(head.contains("X-Custom: yes\r\n"));
        assert_order(&head, "Cookie:", "X-Custom:");
    }

    #[test]
    fn build_forward_proxy_uses_absolute_target() {
        let url = parse_url("http://example.com/path");
        let conn = forward_proxy_conn();
        let mut inputs = get_inputs(&url, &conn);
        inputs.proxy_connection_keepalive = true;

        let head = String::from_utf8(build_request(&inputs).unwrap().head).unwrap();
        assert!(head.starts_with("GET http://example.com/path HTTP/1.1\r\n"));
        assert!(head.contains("Proxy-Connection: Keep-Alive\r\n"));
    }

    #[test]
    fn build_full_header_order_matches_h1_hd() {
        let url = parse_url("http://example.com/");
        let conn = direct_conn();
        let ua = default_user_agent();
        let mut inputs = get_inputs(&url, &conn);
        inputs.user_agent = Some(&ua);
        inputs.authorization = Some("Basic Zm9vOmJhcg==");
        inputs.range = Some("bytes=0-99");
        inputs.accept_encoding = Some("gzip, deflate");
        inputs.referer = Some("http://ref.example/");
        inputs.cookie = Some("c=1");

        let head = String::from_utf8(build_request(&inputs).unwrap().head).unwrap();
        assert_order(&head, "Host:", "Authorization:");
        assert_order(&head, "Authorization:", "Range:");
        assert_order(&head, "Range:", "User-Agent:");
        assert_order(&head, "User-Agent:", "Accept:");
        assert_order(&head, "Accept:", "Accept-Encoding:");
        assert_order(&head, "Accept-Encoding:", "Referer:");
        assert_order(&head, "Referer:", "Cookie:");
    }

    #[test]
    fn build_head_request_uses_head_verb() {
        let url = parse_url("http://example.com/");
        let conn = direct_conn();
        let mut inputs = get_inputs(&url, &conn);
        inputs.no_body = true;

        let head = String::from_utf8(build_request(&inputs).unwrap().head).unwrap();
        assert!(head.starts_with("HEAD / HTTP/1.1\r\n"));
    }

    #[test]
    fn serialize_head_rejects_oversized() {
        // The request line alone exceeds the 1 MiB DYN_HTTP_REQUEST cap.
        let hds = DynHds::with_request_limits();
        let big_target = format!("/{}", "a".repeat(DYN_HTTP_REQUEST_MAX));
        let err = serialize_request_head(&http::Method::GET, &big_target, 1, &hds).unwrap_err();
        assert!(matches!(err, CurlError::TooLarge));
    }

    // ---- H1Exchange codec (in-memory MockConn) ----------------------------

    use std::sync::{Arc, Mutex};

    /// An in-memory [`ByteStream`] for codec tests: serves `to_send` to `recv`
    /// and captures every `send` into a shared `sent` buffer. An optional
    /// one-shot `delay` lets the first `recv` outlast an Expect timeout.
    struct MockConn {
        to_send: Vec<u8>,
        offset: usize,
        sent: Arc<Mutex<Vec<u8>>>,
        delay: Option<Duration>,
    }

    impl MockConn {
        fn new(resp: &[u8]) -> Self {
            Self {
                to_send: resp.to_vec(),
                offset: 0,
                sent: Arc::new(Mutex::new(Vec::new())),
                delay: None,
            }
        }

        fn with_delay(resp: &[u8], d: Duration) -> Self {
            let mut m = Self::new(resp);
            m.delay = Some(d);
            m
        }

        /// A handle to the captured request bytes, cloned before the mock is
        /// moved into the [`H1Exchange`].
        fn sent_handle(&self) -> Arc<Mutex<Vec<u8>>> {
            Arc::clone(&self.sent)
        }
    }

    impl ByteStream for MockConn {
        async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
            if let Some(d) = self.delay.take() {
                tokio::time::sleep(d).await;
            }
            let remaining = self.to_send.len() - self.offset;
            if remaining == 0 {
                return Ok(0);
            }
            let n = remaining.min(buf.len());
            buf[..n].copy_from_slice(&self.to_send[self.offset..self.offset + n]);
            self.offset += n;
            Ok(n)
        }

        async fn send(&mut self, data: &[u8]) -> Result<usize> {
            self.sent.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
    }

    /// A minimal `GET` plan for response-side codec tests.
    fn plan_get() -> RequestPlan {
        RequestPlan {
            head: b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
            body: RequestBody::None,
            expect_100: false,
            expect_100_timeout: Duration::from_millis(1000),
            no_body: false,
        }
    }

    /// Drive an exchange to completion, collecting every event.
    async fn drive_all<C: ByteStream>(ex: &mut H1Exchange<'_, C>) -> Result<Vec<ResponseEvent>> {
        let mut events = Vec::new();
        loop {
            let ev = ex.next_event().await?;
            let is_end = matches!(ev, ResponseEvent::End);
            events.push(ev);
            if is_end {
                break;
            }
        }
        Ok(events)
    }

    /// Concatenate all `Body` events.
    fn collect_body(events: &[ResponseEvent]) -> Vec<u8> {
        events
            .iter()
            .filter_map(|e| match e {
                ResponseEvent::Body(b) => Some(b.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    #[tokio::test]
    async fn codec_get_content_length_body() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let mut ex = H1Exchange::new(MockConn::new(resp), plan_get(), false, false);
        let events = drive_all(&mut ex).await.unwrap();

        assert_eq!(events[0], ResponseEvent::Status(200));
        // curl delivers the status line and the blank terminator as header lines.
        assert!(events
            .iter()
            .any(|e| matches!(e, ResponseEvent::Header(l) if l == b"HTTP/1.1 200 OK\r\n")));
        assert!(events
            .iter()
            .any(|e| matches!(e, ResponseEvent::Header(l) if l == b"Content-Length: 5\r\n")));
        assert!(events
            .iter()
            .any(|e| matches!(e, ResponseEvent::Header(l) if l == b"\r\n")));
        assert!(events.iter().any(|e| matches!(
            e,
            ResponseEvent::HeadersComplete {
                content_length: Some(5),
                ..
            }
        )));
        assert_eq!(collect_body(&events), b"hello");
        assert_eq!(*events.last().unwrap(), ResponseEvent::End);
        assert_eq!(ex.status_code(), 200);
        assert_eq!(ex.response_minor(), 1);
        assert!(ex.keepalive());
    }

    #[tokio::test]
    async fn codec_head_yields_no_body() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        let mut plan = plan_get();
        plan.no_body = true;
        plan.head = b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let mut ex = H1Exchange::new(MockConn::new(resp), plan, false, false);
        let events = drive_all(&mut ex).await.unwrap();

        assert!(
            !events.iter().any(|e| matches!(e, ResponseEvent::Body(_))),
            "HEAD has no body"
        );
        assert_eq!(*events.last().unwrap(), ResponseEvent::End);
        assert_eq!(ex.status_code(), 200);
    }

    #[tokio::test]
    async fn codec_chunked_response_decode() {
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let mut ex = H1Exchange::new(MockConn::new(resp), plan_get(), false, false);
        let events = drive_all(&mut ex).await.unwrap();

        assert_eq!(collect_body(&events), b"Wikipedia");
        // Chunked → no advertised Content-Length on HeadersComplete.
        assert!(events.iter().any(|e| matches!(
            e,
            ResponseEvent::HeadersComplete {
                content_length: None,
                ..
            }
        )));
        assert!(ex.keepalive());
    }

    #[tokio::test]
    async fn codec_close_delimited_body() {
        let resp = b"HTTP/1.1 200 OK\r\n\r\nstreamed body";
        let mut ex = H1Exchange::new(MockConn::new(resp), plan_get(), false, false);
        let events = drive_all(&mut ex).await.unwrap();

        assert_eq!(collect_body(&events), b"streamed body");
        assert!(
            !ex.keepalive(),
            "close-delimited responses disable keepalive"
        );
    }

    #[tokio::test]
    async fn codec_post_sends_head_then_body() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let plan = RequestPlan {
            head: b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 9\r\n\r\n".to_vec(),
            body: RequestBody::Sized(b"name=fred".to_vec()),
            expect_100: false,
            expect_100_timeout: Duration::from_millis(1000),
            no_body: false,
        };
        let mock = MockConn::new(resp);
        let sent = mock.sent_handle();
        let mut ex = H1Exchange::new(mock, plan, false, false);
        drive_all(&mut ex).await.unwrap();

        let sent = sent.lock().unwrap();
        assert!(sent.starts_with(b"POST / HTTP/1.1\r\n"));
        assert!(
            sent.ends_with(b"\r\n\r\nname=fred"),
            "sent: {:?}",
            String::from_utf8_lossy(&sent)
        );
    }

    #[tokio::test]
    async fn codec_chunked_upload_frames_body() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let plan = RequestPlan {
            head: b"PUT / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
                .to_vec(),
            body: RequestBody::Chunked(b"data".to_vec()),
            expect_100: false,
            expect_100_timeout: Duration::from_millis(1000),
            no_body: false,
        };
        let mock = MockConn::new(resp);
        let sent = mock.sent_handle();
        let mut ex = H1Exchange::new(mock, plan, false, false);
        drive_all(&mut ex).await.unwrap();

        let sent = sent.lock().unwrap();
        // The chunk framing of "data": "4\r\ndata\r\n0\r\n\r\n".
        assert!(
            sent.ends_with(b"4\r\ndata\r\n0\r\n\r\n"),
            "sent: {:?}",
            String::from_utf8_lossy(&sent)
        );
    }

    #[tokio::test]
    async fn codec_keepalive_decisions() {
        // HTTP/1.1 + Content-Length → keepalive.
        let mut ex = H1Exchange::new(
            MockConn::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
            plan_get(),
            false,
            false,
        );
        drive_all(&mut ex).await.unwrap();
        assert!(ex.keepalive());

        // Connection: close → no keepalive.
        let mut ex = H1Exchange::new(
            MockConn::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
            plan_get(),
            false,
            false,
        );
        drive_all(&mut ex).await.unwrap();
        assert!(!ex.keepalive());

        // HTTP/1.0 without keep-alive → no keepalive.
        let mut ex = H1Exchange::new(
            MockConn::new(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"),
            plan_get(),
            false,
            false,
        );
        drive_all(&mut ex).await.unwrap();
        assert!(!ex.keepalive());

        // HTTP/1.0 with explicit keep-alive → keepalive.
        let mut ex = H1Exchange::new(
            MockConn::new(
                b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
            ),
            plan_get(),
            false,
            false,
        );
        drive_all(&mut ex).await.unwrap();
        assert!(ex.keepalive());
    }

    #[tokio::test]
    async fn codec_expect_100_continue_then_sends_body() {
        let resp = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        let plan = RequestPlan {
            head: b"PUT / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n".to_vec(),
            body: RequestBody::Sized(b"hello".to_vec()),
            expect_100: true,
            expect_100_timeout: Duration::from_millis(1000),
            no_body: false,
        };
        let mock = MockConn::new(resp);
        let sent = mock.sent_handle();
        let mut ex = H1Exchange::new(mock, plan, false, false);
        let events = drive_all(&mut ex).await.unwrap();

        assert_eq!(ex.status_code(), 200);
        assert_eq!(collect_body(&events), b"hi");
        assert!(
            sent.lock().unwrap().ends_with(b"hello"),
            "body is sent after the interim 100"
        );
    }

    #[tokio::test]
    async fn codec_expect_100_final_response_skips_body() {
        let resp = b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n";
        let plan = RequestPlan {
            head: b"PUT / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n".to_vec(),
            body: RequestBody::Sized(b"hello".to_vec()),
            expect_100: true,
            expect_100_timeout: Duration::from_millis(1000),
            no_body: false,
        };
        let mock = MockConn::new(resp);
        let sent = mock.sent_handle();
        let mut ex = H1Exchange::new(mock, plan, false, false);
        drive_all(&mut ex).await.unwrap();

        assert_eq!(ex.status_code(), 417);
        assert!(
            !sent.lock().unwrap().ends_with(b"hello"),
            "body must NOT be sent when a final response precedes any 100"
        );
    }

    #[tokio::test]
    async fn codec_expect_100_timeout_sends_body_anyway() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let plan = RequestPlan {
            head: b"PUT / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n".to_vec(),
            body: RequestBody::Sized(b"hello".to_vec()),
            expect_100: true,
            expect_100_timeout: Duration::from_millis(20),
            no_body: false,
        };
        // The first recv (the interim wait) is delayed far past the 20 ms
        // timeout; the timeout fires, the body is sent, then the response reads.
        let mock = MockConn::with_delay(resp, Duration::from_secs(30));
        let sent = mock.sent_handle();
        let mut ex = H1Exchange::new(mock, plan, false, false);
        drive_all(&mut ex).await.unwrap();

        assert_eq!(ex.status_code(), 200);
        assert!(
            sent.lock().unwrap().ends_with(b"hello"),
            "body must be sent after the Expect timeout"
        );
    }

    #[tokio::test]
    async fn codec_empty_reply_is_got_nothing() {
        let mut ex = H1Exchange::new(MockConn::new(b""), plan_get(), false, false);
        let err = drive_all(&mut ex).await.unwrap_err();
        assert!(matches!(err, CurlError::GotNothing));
    }

    #[tokio::test]
    async fn codec_short_content_length_is_partial() {
        // Declares 10 bytes but sends 3 then EOF.
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc";
        let mut ex = H1Exchange::new(MockConn::new(resp), plan_get(), false, false);
        let err = drive_all(&mut ex).await.unwrap_err();
        assert!(matches!(err, CurlError::PartialFile));
    }

    #[tokio::test]
    async fn codec_http09_not_allowed_errors() {
        let resp = b"raw 0.9 body with no status line";
        let mut ex = H1Exchange::new(MockConn::new(resp), plan_get(), false, false);
        let err = drive_all(&mut ex).await.unwrap_err();
        assert!(matches!(err, CurlError::UnsupportedProtocol));
    }

    #[tokio::test]
    async fn codec_http09_on_reuse_is_weird_reply() {
        let resp = b"raw body";
        // reuse = true forbids the 0.9 fallback even when allowed.
        let mut ex = H1Exchange::new(MockConn::new(resp), plan_get(), true, true);
        let err = drive_all(&mut ex).await.unwrap_err();
        assert!(matches!(err, CurlError::WeirdServerReply));
    }

    #[tokio::test]
    async fn codec_http09_allowed_delivers_body() {
        let resp = b"raw 0.9 body";
        let mut ex = H1Exchange::new(MockConn::new(resp), plan_get(), true, false);
        let events = drive_all(&mut ex).await.unwrap();

        assert_eq!(ex.status_code(), 200);
        assert_eq!(ex.response_minor(), 9);
        assert_eq!(collect_body(&events), b"raw 0.9 body");
        assert!(!ex.keepalive(), "HTTP/0.9 never keeps the connection alive");
    }
}
