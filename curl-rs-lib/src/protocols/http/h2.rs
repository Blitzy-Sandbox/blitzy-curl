//! The HTTP/2 protocol engine — the Rust rewrite of libcurl's `lib/http2.c`
//! (3011 LoC, the nghttp2-based `cf-h2` connection filter), built on the safe
//! [`h2`](https://docs.rs/h2) crate instead of `nghttp2`.
//!
//! This module executes an HTTP/2 request/response exchange once HTTP/2 has been
//! *selected* — by ALPN (`h2` over the `cf-ssl` rustls filter), by
//! `--http2-prior-knowledge` (cleartext `h2c` with prior knowledge), or by an
//! HTTP/1.1 `Upgrade: h2c` (the C `via_h1_upgrade` path). The selection itself
//! is made by the HTTP `Protocol` dispatcher in [`super`]/[`crate::protocols`]
//! (which reads [`Curl_conn_get_alpn_negotiated`] and the `--http2*` options);
//! this file stays focused on *carrying* the request once the engine is chosen,
//! exactly as the agent brief prescribes.
//!
//! # The central C → Rust transformation (AAP §0.2 / §0.6)
//!
//! curl drives a `nghttp2_session` through ~20 hand-written callbacks
//! (`on_header`, `on_frame_recv`, `on_data_chunk_recv`, `on_stream_close`,
//! `req_body_read_callback`, the `nw_in`/`nw_out` pumps, …) plus manual network
//! `bufq`s. **All of that callback machinery dissolves** into the `h2` crate's
//! awaited client API, mirroring the proven pattern in
//! [`crate::conn::h2_proxy`] (the sibling `cf-h2-proxy.c` rewrite):
//!
//! * the session handshake becomes [`h2::client::Builder::handshake`], yielding
//!   a [`SendRequest`] and a [`h2::client::Connection`] future;
//! * the connection future — which drives every frame's ingress/egress — is
//!   **spawned as a single Tokio task** and kept alive for the connection's
//!   lifetime (curl's `nw_in`/`nw_out` + `progress_ingress`/`_egress` collapse
//!   into it);
//! * each request becomes one [`SendRequest::send_request`] call, returning a
//!   [`ResponseFuture`] and a [`SendStream`];
//! * the request body is written via [`SendStream::send_data`] (respecting
//!   HTTP/2 flow control), and the response body is read via
//!   [`RecvStream::data`] plus the **mandatory** [`h2::FlowControl::release_capacity`]
//!   refill.
//!
//! The C callback *structure* is discarded; the observable HTTP/2 *semantics* —
//! stream multiplexing, HPACK header (de)compression (handled inside `h2`), flow
//! control, server-push handling, and GOAWAY — are preserved so the curl 8.x
//! regression suite (its `HTTP2`-feature-gated tests) passes unmodified.
//!
//! # Request construction — reuse `h1`, then map to pseudo-headers
//!
//! curl builds the HTTP/2 request by **serializing an HTTP/1-style request and
//! parsing it back** (`http2.c` `h2_submit` → `Curl_h1_req_parse_read` →
//! `Curl_http_req_to_h2`, `lib/http.c` L4874). This module is faithful to that:
//! [`build_h2_request`] calls [`super::h1::build_request`] (so `User-Agent`,
//! `Accept`, auth, cookies, and custom-header parity is *identical* to HTTP/1.1)
//! and then [`map_h1_head_to_h2`] translates the serialized head into an
//! [`http::Request`] whose method + [`Uri`] yield the `:method` / `:scheme` /
//! `:authority` / `:path` pseudo-headers, lowercases every field name, and drops
//! the connection-specific headers RFC 9113 §8.2.2 forbids. Only the *framing*
//! differs between the versions.
//!
//! # Flow control — the #1 correctness pitfall (`http2.c`, see curl #10988)
//!
//! On receive, [`H2Exchange`] **must** call
//! [`h2::FlowControl::release_capacity`] for every byte it consumes from a
//! `DATA` frame, or the stream/connection window drains to zero and the transfer
//! **stalls** — the exact issue curl's comment at `HTTP2_HUGE_WINDOW_SIZE`
//! documents. On send, it awaits [`SendStream::poll_capacity`] before writing,
//! applying real backpressure while the peer's window is closed.
//!
//! # Memory safety (AAP §0.7.1) — ABSOLUTE
//!
//! This module contains **zero** `unsafe`. It inherits `#![forbid(unsafe_code)]`
//! from [`crate::lib`](crate) (the crate root) and [`crate::protocols`]; per the
//! agent brief it is intentionally **not** re-declared here. The C
//! `nghttp2_session` + raw callback pointers + manual buffers become the safe
//! [`h2`] client (`SendRequest` / `RecvStream` / `SendStream` / `FlowControl`)
//! plus [`BufQ`] / [`bytes::Bytes`]; there are no raw pointers and no FFI.
//!
//! # Feature gating (AAP §0.7.3 — CRITICAL)
//!
//! The module is declared `#[cfg(feature = "http2")]` by [`super`], so when the
//! `http2` Cargo feature is off it compiles out cleanly. Its compiled state is
//! in lockstep with [`crate::version`]'s `HTTP2` / `CURL_VERSION_HTTP2`
//! capability bit, because `runtests` selects the HTTP/2 test cases from
//! `curl_version_info`. A unit test asserts the coupling holds.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use h2::client::{Builder, ResponseFuture, SendRequest};
use h2::{RecvStream, SendStream};
use http::uri::{Authority, Parts as UriParts, PathAndQuery, Scheme};
use http::{Method, Request, Uri};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

use crate::conn::filters::ConnectionFilter;
use crate::conn::{Connection, Curl_conn_cf_get_alpn_negotiated, Curl_conn_get_alpn_negotiated};
use crate::error::{CurlError, Result};
use crate::transfer::{ProtocolExchange, ResponseEvent};
use crate::util::bufq::BufQ;

use super::h1::{build_request, parse_header_line, RequestBody, RequestInputs};

// =============================================================================
// Phase A — Constants (EXACT, from lib/http2.c L60-90)
//
// These window/buffer dimensions are reproduced byte-for-byte from the C oracle
// because they govern curl's progress reporting and large-transfer behavior; the
// agent brief is explicit that the `h2`-crate defaults must NOT be substituted.
// =============================================================================

/// Working chunk size for the stream send buffer and `DATA`-frame sizing
/// (`H2_CHUNK_SIZE`, `http2.c` L61): `16 * 1024`. "16K fits H2 DATA frames well."
pub const H2_CHUNK_SIZE: usize = 16 * 1024;

/// The connection-level flow-control window curl prepares for (`H2_CONN_WINDOW_SIZE`,
/// `http2.c` L63): `10 * 1024 * 1024` (10 MB).
pub const H2_CONN_WINDOW_SIZE: usize = 10 * 1024 * 1024;

/// Network-receive buffer chunk count (`H2_NW_RECV_CHUNKS`, `http2.c` L65):
/// `H2_CONN_WINDOW_SIZE / H2_CHUNK_SIZE` (640). curl preps to hold a full stream
/// window when reading from TLS.
pub const H2_NW_RECV_CHUNKS: usize = H2_CONN_WINDOW_SIZE / H2_CHUNK_SIZE;

/// Network-send buffer chunk count (`H2_NW_SEND_CHUNKS`, `http2.c` L67): `1`.
/// curl accumulates only small frames before pushing into TLS.
pub const H2_NW_SEND_CHUNKS: usize = 1;

/// The per-stream "in flight, unthrottled" window maximum
/// (`H2_STREAM_WINDOW_SIZE_MAX`, `http2.c` L69): `10 * 1024 * 1024` (10 MB).
pub const H2_STREAM_WINDOW_SIZE_MAX: usize = 10 * 1024 * 1024;

/// The per-stream initial window curl advertises via `SETTINGS_INITIAL_WINDOW_SIZE`
/// (`H2_STREAM_WINDOW_SIZE_INITIAL`, `http2.c` L73): `64 * 1024` (64 KB).
pub const H2_STREAM_WINDOW_SIZE_INITIAL: usize = 64 * 1024;

/// Per-stream send-buffer chunk count (`H2_STREAM_SEND_CHUNKS`, `http2.c` L79):
/// `(64 * 1024) / H2_CHUNK_SIZE` (4). A smaller upload buffer keeps progress
/// reporting close to reality.
pub const H2_STREAM_SEND_CHUNKS: usize = (64 * 1024) / H2_CHUNK_SIZE;

/// Spare buffer chunks kept for a full window (`H2_STREAM_POOL_SPARES`,
/// `http2.c` L81): `H2_CONN_WINDOW_SIZE / H2_CHUNK_SIZE` (640).
pub const H2_STREAM_POOL_SPARES: usize = H2_CONN_WINDOW_SIZE / H2_CHUNK_SIZE;

/// The connection (whole-session) flow-control window curl sets via
/// `nghttp2_session_set_local_window_size` (`HTTP2_HUGE_WINDOW_SIZE`,
/// `http2.c` L87 + L2467): `100 * H2_STREAM_WINDOW_SIZE_MAX` (≈1 GB). Sized so
/// many PAUSED streams cannot block the connection window (curl #10988). Fits in
/// a `u32`/`i32` (1,048,576,000 < 2³¹−1).
pub const HTTP2_HUGE_WINDOW_SIZE: usize = 100 * H2_STREAM_WINDOW_SIZE_MAX;

/// The number of SETTINGS entries curl sends (`H2_SETTINGS_IV_LEN`, `http2.c`
/// L89): MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, ENABLE_PUSH.
pub const H2_SETTINGS_IV_LEN: usize = 3;

/// The packed-SETTINGS payload buffer length (`H2_BINSETTINGS_LEN`, `http2.c`
/// L90): `80`. Used by curl's `Upgrade: h2c` `HTTP2-Settings` base64 blob.
pub const H2_BINSETTINGS_LEN: usize = 80;

/// curl's default `SETTINGS_MAX_CONCURRENT_STREAMS` value advertised to the peer
/// (`lib/multi.c` L255: `multi->max_concurrent_streams = 100`, surfaced via
/// `Curl_multi_max_concurrent_streams`). With server push disabled this chiefly
/// bounds peer-initiated (push) streams; reproduced for SETTINGS parity.
pub const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 100;

// =============================================================================
// Error / IO mapping (mirrors crate::conn::h2_proxy)
// =============================================================================

/// Map an [`h2::Error`] onto the closest [`CurlError`], mirroring how the C code
/// turns `nghttp2` failures into `CURLE_HTTP2` / `CURLE_HTTP2_STREAM`
/// (`http2.c` `cf_h2_header_error` / `on_stream_close`).
///
/// A stream-level `RST_STREAM` ([`h2::Error::is_reset`]) maps to
/// [`CurlError::Http2Stream`] (`CURLE_HTTP2_STREAM`, 92); every other
/// connection-level / framing / IO failure maps to [`CurlError::Http2`]
/// (`CURLE_HTTP2`, 16).
fn h2_to_curl(e: &h2::Error) -> CurlError {
    if e.is_reset() {
        CurlError::Http2Stream
    } else {
        CurlError::Http2
    }
}

/// Map a [`CurlError`] into a [`std::io::Error`] for the
/// [`AsyncRead`]/[`AsyncWrite`] boundary the `h2` connection drives over (it
/// surfaces these as [`h2::Error::is_io`]). Mirrors `h2_proxy::curl_to_io`.
fn curl_to_io(e: &CurlError) -> io::Error {
    io::Error::other(e.to_string())
}

// =============================================================================
// Pseudo-header / hop-by-hop classification
// (oracle: lib/http.c `Curl_http_req_to_h2` L4874 + `h2_permissible_field` L4832)
// =============================================================================

/// Whether `name` is one of the connection-specific header fields that MUST NOT
/// be forwarded as a regular HTTP/2 field (RFC 9113 §8.2.2).
///
/// This is the exact, authoritative `H2_NON_FIELD` set from `lib/http.c`
/// L4823-4830 (`Host`, `Upgrade`, `Connection`, `Keep-Alive`,
/// `Proxy-Connection`, `Transfer-Encoding`), compared case-insensitively just as
/// curl's `curl_strequal` does. `Host` is included because it is conveyed by the
/// `:authority` pseudo-header instead. `TE` is handled separately (it is
/// permitted, but only with the value `trailers`); see [`te_has_trailers`].
fn is_h2_non_field(name: &str) -> bool {
    // Kept in the same order as the C table for easy cross-reference.
    const NON_FIELDS: [&str; 6] = [
        "host",
        "upgrade",
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
    ];
    NON_FIELDS.iter().any(|nf| name.eq_ignore_ascii_case(nf))
}

/// Whether a `TE` header value carries the `trailers` token (RFC 9113 §8.2.2 /
/// `lib/http.c` `http_TE_has_token` L4845). A `TE` field is the *only*
/// connection-specific header HTTP/2 permits, and then only reduced to the value
/// `trailers`. Tokens are comma-separated; any per-token parameters (after `;`)
/// are ignored, and the comparison is case-insensitive — matching the C tokenizer
/// for the common, non-quoted case.
fn te_has_trailers(value: &str) -> bool {
    value.split(',').any(|tok| {
        let tok = tok.trim();
        let head = tok.split(';').next().unwrap_or("").trim();
        head.eq_ignore_ascii_case("trailers")
    })
}

// =============================================================================
// ALPN selection helpers (crate::conn)
//
// The HTTP `Protocol` dispatcher in `mod.rs` decides whether to use this engine;
// these helpers expose curl's "was `h2` negotiated?" check (`Curl_conn_is_alpn_h2`
// analog) over both the filter-level and connection-level ALPN accessors so the
// dispatcher can phrase the decision either way.
// =============================================================================

/// Returns `true` when the connection's negotiated ALPN protocol selects this
/// HTTP/2 engine, reading the connection-level ALPN via
/// [`Curl_conn_get_alpn_negotiated`]. The dispatcher calls this for an
/// ALPN-negotiated (TLS) connection; the `h2c` prior-knowledge and `Upgrade`
/// paths bypass ALPN and select HTTP/2 by configuration instead.
#[must_use]
pub fn connection_selects_h2(conn: &Connection) -> bool {
    matches!(Curl_conn_get_alpn_negotiated(conn).as_deref(), Some("h2"))
}

/// Returns `true` when the negotiated ALPN protocol on the given connection
/// filter selects this HTTP/2 engine, reading it via
/// [`Curl_conn_cf_get_alpn_negotiated`]. This is the filter-scoped counterpart of
/// [`connection_selects_h2`], for callers holding a `cf` rather than the whole
/// [`Connection`].
#[must_use]
pub fn alpn_selects_h2(cf: Option<&dyn ConnectionFilter>) -> bool {
    matches!(Curl_conn_cf_get_alpn_negotiated(cf).as_deref(), Some("h2"))
}

// =============================================================================
// Request mapping: reuse the h1 request builder, then map to HTTP/2
// (oracle: lib/http2.c `h2_submit` L2058 → lib/http.c `Curl_http_req_to_h2` L4874)
// =============================================================================

/// Build a complete HTTP/2 request from the same [`RequestInputs`] the HTTP/1.1
/// engine consumes, returning the mapped [`http::Request`], the request
/// [`RequestBody`] to stream as `DATA`, and the `no_body` flag (a `HEAD`/
/// `CURLOPT_NOBODY` request expects no response body).
///
/// This faithfully reproduces curl's two-step strategy
/// (`h2_submit`): first [`super::h1::build_request`] assembles the logical
/// request — method shaping, target, and the full default + custom header set in
/// curl's exact order, so `User-Agent`, `Accept`, `Authorization`, `Cookie`,
/// `Referer`, etc. are *byte-identical* to the HTTP/1.1 path — then
/// [`map_h1_head_to_h2`] translates the serialized head into HTTP/2
/// pseudo-headers + fields. Only the framing differs between the versions.
///
/// HTTP/2 never chunks a request body, so the caller leaves
/// [`RequestInputs::chunked`] `false` (and curl disables `upload_chunky` on the
/// h2 path). A [`RequestBody::Chunked`] that nonetheless arrives is sent as its
/// raw bytes in `DATA` frames (the chunked transfer-encoding is *not* applied),
/// matching the C behavior.
///
/// # Errors
///
/// Propagates [`super::h1::build_request`] errors, and returns
/// [`CurlError::Http2`] if the serialized head cannot be mapped to a valid
/// HTTP/2 request (e.g. a missing `Host` for `:authority`, or an invalid
/// method/target/header token).
pub fn build_h2_request(inputs: &RequestInputs<'_>) -> Result<(Request<()>, RequestBody, bool)> {
    let plan = build_request(inputs)?;
    let req = map_h1_head_to_h2(&plan.head, inputs.is_https)?;
    Ok((req, plan.body, plan.no_body))
}

/// Translate a serialized HTTP/1-style request head (the
/// `"METHOD TARGET HTTP/1.x\r\n"` line, the `Name: value\r\n` block, and the
/// terminating blank line — exactly what [`super::h1::serialize_request_head`]
/// produces) into an [`http::Request`] carrying the HTTP/2 pseudo-headers and
/// permitted fields.
///
/// Mirrors `Curl_http_req_to_h2` (`lib/http.c` L4874):
///
/// * `:method` ← the request-line verb.
/// * `:scheme` ← `https` when `is_https`, else `http` (curl's
///   `Curl_conn_is_ssl` fallback; this engine has no forward-proxy absolute-form
///   target — that uses the separate h2-proxy tunnel filter).
/// * `:authority` ← the `Host` header value (curl's `req->authority` ||
///   `Host`).
/// * `:path` ← the request-line target (origin-form).
///
/// The `h2` crate derives those four pseudo-headers from the [`Request`]'s
/// [`Method`] and [`Uri`]; regular fields are copied with **lowercased** names
/// (curl's `DYNHDS_OPT_LOWERCASE`), **dropping** the connection-specific headers
/// ([`is_h2_non_field`]) and reducing a `TE` header to `te: trailers` only when
/// it carries that token ([`te_has_trailers`]).
///
/// # Errors
///
/// [`CurlError::Http2`] if the head is malformed (missing/!valid request line,
/// missing `Host` for `:authority`, or an invalid method/URI/header token).
pub fn map_h1_head_to_h2(head: &[u8], is_https: bool) -> Result<Request<()>> {
    // Split the head into CRLF-delimited lines. The first is the request line;
    // the rest are header lines up to (and excluding) the terminating blank.
    let mut lines = split_crlf_lines(head);
    let request_line = lines.next().ok_or(CurlError::Http2)?;
    let (method_bytes, target) = parse_request_line(request_line)?;

    let method = Method::from_bytes(method_bytes).map_err(|_| CurlError::Http2)?;

    // First pass: pull the `Host` value (→ `:authority`) and collect the
    // permissible regular fields (lowercased), applying the C drop/`TE` rules.
    let mut authority: Option<String> = None;
    let mut fields: Vec<(String, Vec<u8>)> = Vec::new();
    for line in lines {
        // A blank line is the header/body separator → stop (parse_header_line
        // returns None for it; any trailing bytes after it are the body, which
        // the head should not contain).
        let Some((name, value)) = parse_header_line(line) else {
            break;
        };
        let name_str = String::from_utf8_lossy(name);
        if name_str.eq_ignore_ascii_case("host") {
            // `Host` becomes `:authority`; keep the last occurrence (curl emits
            // exactly one synthesized/echoed Host).
            authority = Some(String::from_utf8_lossy(value).into_owned());
            continue;
        }
        if is_h2_non_field(&name_str) {
            // Upgrade / Connection / Keep-Alive / Proxy-Connection /
            // Transfer-Encoding — forbidden as HTTP/2 fields; drop.
            continue;
        }
        if name_str.eq_ignore_ascii_case("te") {
            // Only `TE: trailers` is permitted, reduced to that exact value.
            if te_has_trailers(&String::from_utf8_lossy(value)) {
                fields.push(("te".to_string(), b"trailers".to_vec()));
            }
            continue;
        }
        fields.push((name_str.to_ascii_lowercase(), value.to_vec()));
    }

    let authority = authority.ok_or(CurlError::Http2)?;

    // Assemble the absolute-form URI from its parts so `h2` can derive every
    // pseudo-header (`:scheme`, `:authority`, `:path`).
    let uri = build_h2_uri(is_https, &authority, target)?;

    let mut builder = Request::builder().method(method).uri(uri);
    // Attach the request headers; `http::request::Builder` accumulates them and
    // surfaces any invalid name/value at `.body(())`.
    if let Some(hmap) = builder.headers_mut() {
        for (name, value) in fields {
            let hname = http::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| CurlError::Http2)?;
            let hval =
                http::header::HeaderValue::from_bytes(&value).map_err(|_| CurlError::Http2)?;
            hmap.append(hname, hval);
        }
    }
    builder.body(()).map_err(|_| CurlError::Http2)
}

/// Assemble an absolute-form [`Uri`] from a scheme flag, an `:authority`, and an
/// origin-form `:path` target. Used by [`map_h1_head_to_h2`]; factored out so the
/// pseudo-header derivation is unit-testable.
fn build_h2_uri(is_https: bool, authority: &str, target: &str) -> Result<Uri> {
    let mut parts = UriParts::default();
    parts.scheme = Some(if is_https {
        Scheme::HTTPS
    } else {
        Scheme::HTTP
    });
    parts.authority = Some(Authority::try_from(authority).map_err(|_| CurlError::Http2)?);
    parts.path_and_query = Some(PathAndQuery::try_from(target).map_err(|_| CurlError::Http2)?);
    Uri::from_parts(parts).map_err(|_| CurlError::Http2)
}

/// Split a serialized request head into its CRLF-delimited lines, *excluding* the
/// line terminators. A trailing empty element (from the final `\r\n`) and the
/// header/body separator are handled by the caller via [`parse_header_line`].
fn split_crlf_lines(head: &[u8]) -> impl Iterator<Item = &[u8]> {
    // `split` on `\n`, then trim a trailing `\r`, mirroring how curl's line
    // reader treats CRLF. Empty trailing fragments are yielded and recognized as
    // the blank separator by `parse_header_line`.
    head.split(|&b| b == b'\n').map(|line| {
        if let [rest @ .., b'\r'] = line {
            rest
        } else {
            line
        }
    })
}

/// Parse a request line (`"METHOD TARGET HTTP/1.x"`, CRLF already trimmed) into
/// the method token and the request target, mirroring the inverse of
/// [`super::h1::serialize_request_head`]'s `"{method} {target} HTTP/1.{minor}"`.
///
/// # Errors
///
/// [`CurlError::Http2`] if the line does not have at least a method and a target
/// separated by a single space.
fn parse_request_line(line: &[u8]) -> Result<(&[u8], &str)> {
    let mut it = line.splitn(3, |&b| b == b' ');
    let method = it
        .next()
        .filter(|m| !m.is_empty())
        .ok_or(CurlError::Http2)?;
    let target_bytes = it
        .next()
        .filter(|t| !t.is_empty())
        .ok_or(CurlError::Http2)?;
    // The third token ("HTTP/1.x") is irrelevant to HTTP/2 and may be absent for
    // an HTTP/0.9-style line; either way the target is what we need.
    let target = core::str::from_utf8(target_bytes).map_err(|_| CurlError::Http2)?;
    Ok((method, target))
}

// =============================================================================
// `ConnFilterIo` — adapt a `ConnectionFilter` into `AsyncRead + AsyncWrite`
// (mirrors crate::conn::h2_proxy::FilterIo)
// =============================================================================

/// Bridges the [`ConnectionFilter`] byte interface (`send` / `recv`) — the
/// connection below this engine, already TLS-wrapped with ALPN `h2` by the
/// `cf-ssl` filter — into the [`AsyncRead`] + [`AsyncWrite`] stream the `h2`
/// client handshake consumes.
///
/// The `h2` client's [`Connection`](h2::client::Connection) future owns its IO
/// and must be polled for the connection's whole lifetime, so the HTTP
/// dispatcher **moves** the post-TLS filter into a `ConnFilterIo` and hands that
/// to [`h2_client_handshake`]; the resulting connection future is then spawned
/// (see [`H2Connection`]). This is the production transport; tests drive
/// [`h2_client_handshake`] over an in-memory [`tokio::io::duplex`] instead.
///
/// # Cancel-safety of the per-poll future
///
/// [`ConnectionFilter::recv`] / [`send`](ConnectionFilter::send) return boxed
/// futures borrowing the filter. Rather than self-referentially store one, each
/// `poll_*` constructs a fresh future, polls it once with the caller's
/// [`Context`], and — if [`Poll::Pending`] — drops it (the inner future has
/// registered the waker). This is sound because the filters below (Tokio sockets
/// / `tokio-rustls`) are cancel-safe: an incomplete read/write consumes nothing,
/// so re-creating and re-polling resumes the same operation. A synchronous
/// [`CurlError::Again`] is mapped to a self-wake + `Pending` for prompt re-poll.
pub struct ConnFilterIo {
    /// The connection below, moved in for the `h2` connection's lifetime.
    filter: Box<dyn ConnectionFilter>,
    /// Reusable scratch buffer so `poll_read` does not allocate per poll.
    read_buf: Vec<u8>,
}

impl ConnFilterIo {
    /// Wrap `filter`, sizing the scratch read buffer at [`H2_CHUNK_SIZE`].
    #[must_use]
    pub fn new(filter: Box<dyn ConnectionFilter>) -> Self {
        Self {
            filter,
            read_buf: vec![0u8; H2_CHUNK_SIZE],
        }
    }
}

impl AsyncRead for ConnFilterIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // `ConnFilterIo` is `Unpin` (both fields are), so projecting to
        // `&mut Self` needs no `unsafe`.
        let this = self.get_mut();
        let want = buf.remaining().min(this.read_buf.len());
        if want == 0 {
            return Poll::Ready(Ok(()));
        }
        // Disjoint field borrows: `filter` and `read_buf` are distinct fields.
        let n = {
            let mut fut = this.filter.recv(&mut this.read_buf[..want]);
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(CurlError::Again)) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(curl_to_io(&e))),
                Poll::Pending => return Poll::Pending,
            }
        };
        buf.put_slice(&this.read_buf[..n]);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ConnFilterIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut fut = this.filter.send(buf, false);
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(CurlError::Again)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(curl_to_io(&e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The filters below write straight through (socket / TLS buffering is the
        // OS/runtime's concern), so there is nothing extra to flush here.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Graceful teardown of the connection below happens when the spawned
        // connection task ends and drops its `ConnFilterIo` (and thus the
        // moved-in filter), driven by [`H2Connection::close`] / `Drop`.
        Poll::Ready(Ok(()))
    }
}

// =============================================================================
// Phase B — settings, client handshake, and the connection handle
// (oracle: lib/http2.c `populate_settings` L222, `cf_h2_ctx_init` /
//  session creation L1990-2012 + L2440-2495)
// =============================================================================

/// The client-side HTTP/2 SETTINGS curl advertises (`populate_settings`,
/// `http2.c` L222) plus the connection window. The window sizes are fixed by the
/// C constants; only the two values curl actually varies are configurable here.
#[derive(Debug, Clone, Copy)]
pub struct H2Settings {
    /// `SETTINGS_ENABLE_PUSH` — curl sets this to `push_cb != NULL`, i.e. **off**
    /// by default (server push is declined unless `CURLOPT_HTTP2_PUSHFUNCTION`
    /// is set). Default `false`.
    pub enable_push: bool,
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` we advertise to the peer
    /// (`Curl_multi_max_concurrent_streams`, default
    /// [`DEFAULT_MAX_CONCURRENT_STREAMS`] = 100). `None` leaves the `h2` default.
    pub max_concurrent_streams: Option<u32>,
}

impl Default for H2Settings {
    fn default() -> Self {
        // Curl's default build: push disabled, 100 max concurrent streams.
        Self {
            enable_push: false,
            max_concurrent_streams: Some(DEFAULT_MAX_CONCURRENT_STREAMS),
        }
    }
}

impl H2Settings {
    /// Apply these settings and the EXACT C window constants to an `h2`
    /// [`Builder`]. The per-stream window we advertise is
    /// [`H2_STREAM_WINDOW_SIZE_INITIAL`] (64 KB) and the connection window is
    /// [`HTTP2_HUGE_WINDOW_SIZE`] (≈1 GB) — reproducing curl's
    /// `SETTINGS_INITIAL_WINDOW_SIZE` and `nghttp2_session_set_local_window_size`
    /// respectively (`http2.c` L229-230 + L2467). Push is toggled per
    /// [`Self::enable_push`].
    fn apply(&self, builder: &mut Builder) {
        builder
            .initial_window_size(H2_STREAM_WINDOW_SIZE_INITIAL as u32)
            .initial_connection_window_size(HTTP2_HUGE_WINDOW_SIZE as u32)
            .enable_push(self.enable_push);
        if let Some(max) = self.max_concurrent_streams {
            builder.max_concurrent_streams(max);
        }
    }
}

/// Perform the HTTP/2 client handshake over `io` (a post-TLS byte stream — in
/// production a [`ConnFilterIo`], in tests a [`tokio::io::duplex`] half) and
/// return the live [`H2Connection`].
///
/// Mirrors [`crate::conn::h2_proxy`]'s proven sequence:
/// 1. configure an `h2` [`Builder`] with the EXACT C window/SETTINGS values
///    (via [`H2Settings::apply`]);
/// 2. run [`Builder::handshake`], yielding the [`SendRequest`] handle and the
///    [`Connection`](h2::client::Connection) future;
/// 3. **spawn the connection future as a Tokio task** — it drives all frame
///    ingress/egress (HPACK, flow control, multiplexing, GOAWAY) for the
///    connection's lifetime, collapsing curl's `nw_in`/`nw_out` +
///    `progress_ingress`/`_egress` machinery.
///
/// # Errors
///
/// [`CurlError::Http2`] (or [`CurlError::Http2Stream`]) if the handshake fails.
pub async fn h2_client_handshake<IO>(io: IO, settings: H2Settings) -> Result<H2Connection>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let mut builder = Builder::new();
    settings.apply(&mut builder);
    let (send_req, connection) = builder
        .handshake::<IO, Bytes>(io)
        .await
        .map_err(|e| h2_to_curl(&e))?;
    // The connection future must be polled for the whole connection lifetime; it
    // owns the IO and drives every stream's frames. Spawn it (← the C ingress/
    // egress pumps).
    let conn_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(H2Connection {
        send_req: Some(send_req),
        conn_task: Some(conn_task),
    })
}

/// A live HTTP/2 client connection — the Rust mirror of curl's `cf_h2_ctx`
/// (`http2.c`). It owns the [`SendRequest`] handle for issuing streams and the
/// [`JoinHandle`] of the spawned connection-driver task.
///
/// Multiplexing: [`open_stream`](Self::open_stream) / [`start_exchange`](Self::start_exchange)
/// may be called repeatedly to run multiple concurrent streams over the one
/// connection (curl's `cf_h2_ctx.streams` map). For sharing the connection across
/// several easy handles via the multi interface, [`sender`](Self::sender) hands
/// out a cloned [`SendRequest`] (the `h2` crate's `SendRequest` is `Clone` and
/// each clone opens streams on the same connection).
pub struct H2Connection {
    /// The stream-issuing handle (C: the `nghttp2_session` request side).
    send_req: Option<SendRequest<Bytes>>,
    /// The spawned task driving the `h2` connection future (frame I/O for the
    /// connection's lifetime).
    conn_task: Option<JoinHandle<()>>,
}

impl H2Connection {
    /// Open a new stream and send `req`'s HEADERS, returning the
    /// [`ResponseFuture`] to await and the [`SendStream`] for the request body.
    ///
    /// `has_body` controls the `END_STREAM` flag: `false` ⇒ no body (the stream
    /// is half-closed immediately, [`SendStream`] unused); `true` ⇒ body `DATA`
    /// frames follow and the exchange must finish with an end-of-stream frame.
    /// Waits for [`SendRequest::poll_ready`] first (HTTP/2 stream-concurrency /
    /// connection readiness), exactly as `h2_proxy::submit_connect`.
    ///
    /// # Errors
    ///
    /// [`CurlError::FailedInit`] if the connection has been closed;
    /// [`CurlError::Http2`]/[`CurlError::Http2Stream`] on an `h2` failure.
    pub async fn open_stream(
        &mut self,
        req: Request<()>,
        has_body: bool,
    ) -> Result<(ResponseFuture, SendStream<Bytes>)> {
        let send_req = self.send_req.as_mut().ok_or(CurlError::FailedInit)?;
        std::future::poll_fn(|cx| send_req.poll_ready(cx))
            .await
            .map_err(|e| h2_to_curl(&e))?;
        send_req
            .send_request(req, !has_body)
            .map_err(|e| h2_to_curl(&e))
    }

    /// Open a stream for `req` and wrap it in a ready-to-drive [`H2Exchange`].
    ///
    /// This is the engine's primary entry point for the HTTP `Protocol`
    /// dispatcher: it computes the `END_STREAM` flag from `body` (a `None`/empty
    /// body half-closes the stream at HEADERS), opens the stream, and returns the
    /// [`H2Exchange`] implementing [`ProtocolExchange`] that
    /// [`crate::transfer::drive_transfer`] consumes.
    ///
    /// # Errors
    ///
    /// As [`open_stream`](Self::open_stream).
    pub async fn start_exchange(
        &mut self,
        req: Request<()>,
        body: RequestBody,
        no_body: bool,
    ) -> Result<H2Exchange> {
        let has_body = body_has_bytes(&body);
        let (resp_fut, send_stream) = self.open_stream(req, has_body).await?;
        Ok(H2Exchange::new(
            resp_fut,
            send_stream,
            body,
            has_body,
            no_body,
        ))
    }

    /// Hand out a cloned [`SendRequest`] for multiplexing additional streams over
    /// this connection from another owner (e.g. a second easy handle sharing the
    /// connection through the multi interface / connection pool).
    ///
    /// # Errors
    ///
    /// [`CurlError::FailedInit`] if the connection has been closed.
    pub fn sender(&self) -> Result<SendRequest<Bytes>> {
        self.send_req.clone().ok_or(CurlError::FailedInit)
    }

    /// Close the connection: drop the [`SendRequest`] (no new streams) and abort
    /// the connection-driver task, which drops the moved-in transport. Mirrors
    /// `cf_h2_ctx_close` / `cf_h2_close`.
    pub fn close(&mut self) {
        self.send_req = None;
        if let Some(task) = self.conn_task.take() {
            task.abort();
        }
    }
}

impl Drop for H2Connection {
    fn drop(&mut self) {
        // Ensure the spawned connection task does not outlive the handle.
        self.close();
    }
}

/// Whether a [`RequestBody`] carries any bytes to send as `DATA` (drives the
/// `END_STREAM` flag on the opening HEADERS). An empty `Sized`/`Chunked` body and
/// [`RequestBody::None`] both half-close the stream immediately.
fn body_has_bytes(body: &RequestBody) -> bool {
    match body {
        RequestBody::None => false,
        RequestBody::Sized(b) => !b.is_empty(),
        // A chunked body is held as per-read blocks; it carries bytes when any
        // block is non-empty.
        RequestBody::Chunked(blocks, _) => blocks.iter().any(|b| !b.is_empty()),
        // The h2 path materializes a streamed body to a buffered one before it
        // reaches the codec (see `materialize_streaming_body`), so this is not
        // observed at runtime; a known-zero size carries no bytes.
        RequestBody::Streaming { size, .. } => *size != Some(0),
    }
}

// =============================================================================
// Phase C / D — the HTTP/2 exchange (request/response lifecycle, multiplexing,
// trailers, flow control, GOAWAY/RST errors)
// (oracle: lib/http2.c `h2_submit` L2058, `on_frame_recv`/`on_header` L948-1560,
//  `req_body_read_callback`, `on_data_chunk_recv`, `on_stream_close`)
// =============================================================================

/// An HTTP/2 request/response exchange over one stream, implementing
/// [`crate::transfer::ProtocolExchange`] so [`crate::transfer::drive_transfer`]
/// can drive it identically to the HTTP/1.1 codec.
///
/// On the first [`next_event`](ProtocolExchange::next_event) it streams the
/// request body through the [`SendStream`] (honoring HTTP/2 flow control), awaits
/// the [`ResponseFuture`], and queues the response head as
/// [`ResponseEvent::Status`] + one [`ResponseEvent::Header`] per line (the
/// `"HTTP/2 <code> \r\n"` status line, each `name: value\r\n` field, and the
/// terminating blank line — byte-exact with `http2.c`) + [`ResponseEvent::HeadersComplete`].
/// It then streams [`RecvStream`] `DATA` as [`ResponseEvent::Body`], **releasing
/// flow-control capacity** for every consumed byte, captures any HTTP/2 trailers
/// as further [`ResponseEvent::Header`] lines, and finishes with
/// [`ResponseEvent::End`].
///
/// Response content decoding (gzip/deflate/br/zstd) is *not* performed here: the
/// `Content-Encoding` value is reported on [`ResponseEvent::HeadersComplete`] and
/// the transfer writer chain decodes it — matching the HTTP/1.1 engine.
pub struct H2Exchange {
    /// The pending response (taken and awaited on first poll). `None` after.
    resp_fut: Option<ResponseFuture>,
    /// The inbound (response body) half, valid once the response arrives.
    recv: Option<RecvStream>,
    /// The outbound (request body) half; set to `None` once the stream can no
    /// longer accept data (closed/reset) or after the end-of-stream frame.
    send_stream: Option<SendStream<Bytes>>,
    /// The owned request body to stream as `DATA` (consumed on first poll).
    body: RequestBody,
    /// `true` when the opening HEADERS did *not* carry `END_STREAM` (a body
    /// follows and must be finished with an end-of-stream frame).
    has_body: bool,
    /// `true` for a `HEAD`/`CURLOPT_NOBODY` request (no response body expected).
    no_body: bool,
    /// Staging buffer between the body source and the stream, sized per the EXACT
    /// C constants (`H2_CHUNK_SIZE` × `H2_STREAM_SEND_CHUNKS`).
    sendbuf: BufQ,
    /// Status/header/trailer events queued ahead of (and after) the body.
    pending: VecDeque<ResponseEvent>,
    /// `true` once the request has been sent and the response head parsed.
    sent: bool,
    /// `true` once the response body (and trailers) are fully delivered.
    body_done: bool,
}

impl H2Exchange {
    /// Build an exchange from an opened stream's [`ResponseFuture`] and
    /// [`SendStream`]. Usually constructed via [`H2Connection::start_exchange`].
    #[must_use]
    pub fn new(
        resp_fut: ResponseFuture,
        send_stream: SendStream<Bytes>,
        body: RequestBody,
        has_body: bool,
        no_body: bool,
    ) -> Self {
        Self {
            resp_fut: Some(resp_fut),
            recv: None,
            send_stream: Some(send_stream),
            body,
            has_body,
            no_body,
            sendbuf: BufQ::new(H2_CHUNK_SIZE, H2_STREAM_SEND_CHUNKS),
            pending: VecDeque::new(),
            sent: false,
            body_done: false,
        }
    }

    /// Send the request body, await the response, and queue the response head.
    async fn start(&mut self) -> Result<()> {
        self.send_request_body().await?;
        let resp_fut = self.resp_fut.take().ok_or(CurlError::FailedInit)?;
        let resp = resp_fut.await.map_err(|e| h2_to_curl(&e))?;
        self.queue_response_head(&resp);
        let (_parts, recv) = resp.into_parts();
        self.recv = Some(recv);
        if self.no_body {
            // HEAD / CURLOPT_NOBODY: no response body is expected.
            self.body_done = true;
        }
        Ok(())
    }

    /// Stream the owned request body through the [`SendStream`], chunking at
    /// [`H2_CHUNK_SIZE`] and honoring flow control, then finish with an
    /// end-of-stream `DATA` frame. A `None`/empty body (`has_body == false`) sent
    /// nothing — the stream was half-closed at HEADERS — so this is a no-op.
    async fn send_request_body(&mut self) -> Result<()> {
        if !self.has_body {
            return Ok(());
        }
        // HTTP/2 never chunk-encodes; a `Chunked` body's raw bytes are sent as
        // `DATA` (curl disables `upload_chunky` on the h2 path).
        let bytes = match core::mem::take(&mut self.body) {
            RequestBody::None => Vec::new(),
            RequestBody::Sized(b) => b,
            // A chunked body's per-read blocks are flattened to the raw payload
            // (curl disables `upload_chunky` on the h2 path; the bytes ride DATA
            // frames, not chunk framing).
            RequestBody::Chunked(blocks, _) => blocks.concat(),
            // A streamed body is materialized to a buffered body before the h2
            // codec runs (`materialize_streaming_body`); unreachable here.
            RequestBody::Streaming { .. } => Vec::new(),
        };
        let mut off = 0;
        while off < bytes.len() {
            if self.send_stream.is_none() {
                // The stream was reset/closed before the body was fully sent.
                return Err(CurlError::SendError);
            }
            match self.sendbuf.write(&bytes[off..]) {
                Ok(0) => self.drain_sendbuf().await?,
                Ok(n) => off += n,
                Err(CurlError::Again) => self.drain_sendbuf().await?,
                Err(e) => return Err(e),
            }
            if self.sendbuf.is_full() {
                self.drain_sendbuf().await?;
            }
        }
        self.drain_sendbuf().await?;
        self.finish_send()
    }

    /// Drain the staged send buffer into the stream, awaiting flow-control
    /// capacity (curl's egress pump). Awaiting (rather than returning early)
    /// applies real backpressure without deadlocking: [`SendStream::poll_capacity`]
    /// yields `Pending` (never `Ready(Ok(0))`) while the window is zero, and the
    /// spawned connection task supplies the `WINDOW_UPDATE` that wakes it.
    ///
    /// # Flow-control contract (critical — see `h2`'s `proto::streams::send`)
    ///
    /// `h2`'s [`SendStream::poll_capacity`] returns `Ready` **only on a fresh
    /// capacity increment** (the internal `send_capacity_inc` flag, cleared on
    /// each `Ready`); it does **not** re-report capacity that was already granted
    /// but left unsent. Equally, [`SendStream::reserve_capacity`] only re-assigns
    /// (and thus re-arms `poll_capacity`) when the request *grows* the target — a
    /// smaller request takes the `Ordering::Equal`/`Less` path and assigns
    /// nothing. Therefore, after one `poll_capacity` grant we MUST spend the
    /// **entire** granted budget here before awaiting again: leaving granted
    /// capacity unsent while the peer's window is not yet exhausted wedges the
    /// upload (no `WINDOW_UPDATE` is due, and `poll_capacity` will not re-signal
    /// the leftover). Fully consuming each grant also guarantees the window is
    /// driven to zero whenever data remains, which forces the peer's
    /// `WINDOW_UPDATE` that re-arms the next await — exactly curl's "write all the
    /// window allows, then resume on the next socket-writable" loop.
    async fn drain_sendbuf(&mut self) -> Result<()> {
        while !self.sendbuf.is_empty() {
            // Request capacity for everything currently staged; `h2` assigns up to
            // the peer's window.
            let want = self.sendbuf.len();
            match self.send_stream.as_mut() {
                Some(ss) => ss.reserve_capacity(want),
                None => return Ok(()),
            }
            // Await a (re-armed) capacity grant: `Pending` while the window is
            // zero, woken by the connection task on `WINDOW_UPDATE`.
            let granted = {
                let ss = match self.send_stream.as_mut() {
                    Some(s) => s,
                    None => return Ok(()),
                };
                std::future::poll_fn(|cx| ss.poll_capacity(cx)).await
            };
            let mut budget = match granted {
                Some(Ok(c)) => c,
                Some(Err(e)) => return Err(h2_to_curl(&e)),
                None => {
                    // The stream can no longer accept data (closed/reset).
                    self.send_stream = None;
                    return Ok(());
                }
            };
            // Spend the WHOLE granted budget across as many staged chunks as fit
            // (each `peek` yields one ≤ H2_CHUNK_SIZE chunk), so no grant is left
            // stranded and the window is fully consumed when data remains.
            while budget > 0 && !self.sendbuf.is_empty() {
                let chunk: Bytes = match self.sendbuf.peek() {
                    Some(c) if !c.is_empty() => {
                        let n = budget.min(c.len());
                        Bytes::copy_from_slice(&c[..n])
                    }
                    _ => break,
                };
                let n = chunk.len();
                if n == 0 {
                    break;
                }
                match self.send_stream.as_mut() {
                    Some(ss) => ss.send_data(chunk, false).map_err(|e| h2_to_curl(&e))?,
                    None => return Ok(()),
                }
                self.sendbuf.skip(n);
                budget -= n;
            }
        }
        Ok(())
    }

    /// Send the end-of-stream `DATA` frame, half-closing the request side.
    fn finish_send(&mut self) -> Result<()> {
        if let Some(ss) = self.send_stream.as_mut() {
            ss.send_data(Bytes::new(), true)
                .map_err(|e| h2_to_curl(&e))?;
        }
        Ok(())
    }

    /// Queue the response status + header events from the received response,
    /// reproducing the byte-exact wire form `http2.c` delivers to curl's writer
    /// chain (`h2_xfer_write_resp_hd`):
    ///
    /// * the integer status as [`ResponseEvent::Status`];
    /// * the status line `"HTTP/2 <code> \r\n"` (note the trailing space before
    ///   CRLF, `http2.c` L1518-1522);
    /// * each field as `"name: value\r\n"` (names are lowercase from `h2`,
    ///   `http2.c` L1542-1549);
    /// * the terminating blank line `"\r\n"` (`http2.c` L985);
    /// * [`ResponseEvent::HeadersComplete`] carrying `Content-Length` /
    ///   `Content-Encoding` for the writer chain.
    fn queue_response_head(&mut self, resp: &http::Response<RecvStream>) {
        let status = resp.status().as_u16();
        self.pending
            .push_back(ResponseEvent::Status(i32::from(status)));

        let mut status_line = Vec::with_capacity(16);
        status_line.extend_from_slice(b"HTTP/2 ");
        status_line.extend_from_slice(status.to_string().as_bytes());
        status_line.extend_from_slice(b" \r\n");
        self.pending.push_back(ResponseEvent::Header(status_line));

        for (name, value) in resp.headers() {
            self.pending
                .push_back(ResponseEvent::Header(header_line_bytes(
                    name.as_str(),
                    value.as_bytes(),
                )));
        }
        // Terminating blank line completing the header block.
        self.pending
            .push_back(ResponseEvent::Header(b"\r\n".to_vec()));

        let content_length = resp
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<i64>().ok());
        let content_encoding = resp
            .headers()
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        self.pending.push_back(ResponseEvent::HeadersComplete {
            content_length,
            content_encoding,
        });
    }

    /// Pull the next non-empty `DATA` chunk from the response stream, releasing
    /// the consumed flow-control capacity (the **mandatory** window refill, curl
    /// #10988). `Ok(None)` marks the end of the body.
    async fn recv_data(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            let rs = match self.recv.as_mut() {
                Some(r) => r,
                None => return Ok(None),
            };
            match rs.data().await {
                Some(Ok(chunk)) => {
                    let n = chunk.len();
                    if n == 0 {
                        // Empty DATA frame: nothing to deliver; keep pulling.
                        continue;
                    }
                    rs.flow_control()
                        .release_capacity(n)
                        .map_err(|e| h2_to_curl(&e))?;
                    return Ok(Some(chunk.to_vec()));
                }
                Some(Err(e)) => return Err(h2_to_curl(&e)),
                None => return Ok(None),
            }
        }
    }

    /// Capture any HTTP/2 trailers (the `resp_trailers` dynhds in `http2.c`),
    /// queueing each as a `"name: value\r\n"` [`ResponseEvent::Header`] line to be
    /// delivered after the body — matching curl's trailer delivery at stream
    /// close.
    async fn capture_trailers(&mut self) -> Result<()> {
        let rs = match self.recv.as_mut() {
            Some(r) => r,
            None => return Ok(()),
        };
        match rs.trailers().await {
            Ok(Some(map)) => {
                for (name, value) in &map {
                    self.pending
                        .push_back(ResponseEvent::Header(header_line_bytes(
                            name.as_str(),
                            value.as_bytes(),
                        )));
                }
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(e) => Err(h2_to_curl(&e)),
        }
    }
}

/// Format one HTTP/1-style header line `"name: value\r\n"` (the form curl's
/// writer chain consumes), used for both response headers and trailers.
fn header_line_bytes(name: &str, value: &[u8]) -> Vec<u8> {
    let mut line = Vec::with_capacity(name.len() + value.len() + 4);
    line.extend_from_slice(name.as_bytes());
    line.extend_from_slice(b": ");
    line.extend_from_slice(value);
    line.extend_from_slice(b"\r\n");
    line
}

impl ProtocolExchange for H2Exchange {
    async fn next_event(&mut self) -> Result<ResponseEvent> {
        // First poll: send the request and parse the response head.
        if !self.sent {
            self.start().await?;
            self.sent = true;
        }
        // Drain queued status/header/trailer events first.
        if let Some(ev) = self.pending.pop_front() {
            return Ok(ev);
        }
        // Body fully delivered (and trailers queued/drained) → complete.
        if self.body_done {
            return Ok(ResponseEvent::End);
        }
        // Stream the next body chunk; on EOF, capture trailers then complete.
        match self.recv_data().await? {
            Some(chunk) => Ok(ResponseEvent::Body(chunk)),
            None => {
                self.capture_trailers().await?;
                self.body_done = true;
                if let Some(ev) = self.pending.pop_front() {
                    Ok(ev)
                } else {
                    Ok(ResponseEvent::End)
                }
            }
        }
    }

    async fn send_body(&mut self, data: &[u8]) -> Result<usize> {
        // The explicit-push request-body path. `drive_transfer` does not call
        // this (it sends the owned body inside `next_event`); it exists for
        // callers that stream the body separately. Stages into the C-sized send
        // buffer and drains to the stream honoring flow control (mirrors
        // `h2_proxy::do_send`). A full buffer maps to `Again` backpressure.
        if self.send_stream.is_none() {
            return Err(CurlError::SendError);
        }
        let staged = match self.sendbuf.write(data) {
            Ok(n) => n,
            Err(CurlError::Again) => 0,
            Err(e) => return Err(e),
        };
        if staged == 0 {
            return Err(CurlError::Again);
        }
        self.drain_sendbuf().await?;
        Ok(staged)
    }
}

// =============================================================================
// Tests
// =============================================================================
//
// Two tiers, mirroring the sibling `crate::conn::h2_proxy` suite:
//
// * **Unit tests** — pure, synchronous checks of the request mapping
//   (`map_h1_head_to_h2` → `:method`/`:scheme`/`:authority`/`:path`), the
//   hop-by-hop drop rules, the `TE: trailers` reduction, the request-line
//   parser, the EXACT C window/buffer constants, the SETTINGS defaults, and the
//   `version`-capability coupling `runtests` depends on (AAP §0.7.3).
// * **Integration tests** — drive the real `h2` client (`h2_client_handshake` +
//   `H2Connection` / `H2Exchange`) against an in-memory `h2::server` over a
//   `tokio::io::duplex`, exercising a GET round-trip (byte-exact status line /
//   headers / body + end-to-end pseudo-header delivery), stream multiplexing
//   (two concurrent streams over one connection), large-body send flow control
//   (`poll_capacity` / `release_capacity`), trailer capture, and the
//   RST_STREAM → `CURLE_HTTP2_STREAM` and GOAWAY (finish-in-flight) paths.
#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{HeaderName, HeaderValue};
    use http::{HeaderMap, Response};
    use std::time::Duration;
    use tokio::io::DuplexStream;

    // --------------------------------------------------------------------- //
    //                              unit tests                               //
    // --------------------------------------------------------------------- //

    #[test]
    fn constants_match_c_oracle() {
        // lib/http2.c L60-90 — reproduced byte-for-byte (agent brief Phase A).
        assert_eq!(H2_CHUNK_SIZE, 16 * 1024);
        assert_eq!(H2_CONN_WINDOW_SIZE, 10 * 1024 * 1024);
        assert_eq!(H2_NW_RECV_CHUNKS, H2_CONN_WINDOW_SIZE / H2_CHUNK_SIZE);
        assert_eq!(H2_NW_RECV_CHUNKS, 640);
        assert_eq!(H2_NW_SEND_CHUNKS, 1);
        assert_eq!(H2_STREAM_WINDOW_SIZE_MAX, 10 * 1024 * 1024);
        assert_eq!(H2_STREAM_WINDOW_SIZE_INITIAL, 64 * 1024);
        assert_eq!(H2_STREAM_SEND_CHUNKS, (64 * 1024) / H2_CHUNK_SIZE);
        assert_eq!(H2_STREAM_SEND_CHUNKS, 4);
        assert_eq!(H2_STREAM_POOL_SPARES, H2_CONN_WINDOW_SIZE / H2_CHUNK_SIZE);
        assert_eq!(HTTP2_HUGE_WINDOW_SIZE, 100 * H2_STREAM_WINDOW_SIZE_MAX);
        assert_eq!(HTTP2_HUGE_WINDOW_SIZE, 1_048_576_000);
        assert_eq!(H2_SETTINGS_IV_LEN, 3);
        assert_eq!(H2_BINSETTINGS_LEN, 80);
        // The huge connection window MUST fit the 31-bit HTTP/2 window field (and
        // thus a u32/i32), or the SETTINGS / WINDOW_UPDATE values would overflow.
        assert!(u32::try_from(HTTP2_HUGE_WINDOW_SIZE).is_ok());
        assert!(HTTP2_HUGE_WINDOW_SIZE <= i32::MAX as usize);
    }

    #[test]
    fn h2_settings_defaults_match_curl_default_build() {
        let s = H2Settings::default();
        // curl: server push OFF unless CURLOPT_HTTP2_PUSHFUNCTION is set.
        assert!(!s.enable_push);
        // curl: SETTINGS_MAX_CONCURRENT_STREAMS = 100 (multi.c L255).
        assert_eq!(
            s.max_concurrent_streams,
            Some(DEFAULT_MAX_CONCURRENT_STREAMS)
        );
        assert_eq!(DEFAULT_MAX_CONCURRENT_STREAMS, 100);
    }

    #[test]
    fn parse_request_line_extracts_method_and_target() {
        let (m, t) = parse_request_line(b"POST /submit HTTP/1.1").expect("parse");
        assert_eq!(m, &b"POST"[..]);
        assert_eq!(t, "/submit");
        // A target with a query string is preserved verbatim.
        let (m2, t2) = parse_request_line(b"GET /a?b=c&d=e HTTP/1.1").expect("parse2");
        assert_eq!(m2, &b"GET"[..]);
        assert_eq!(t2, "/a?b=c&d=e");
        // A missing HTTP-version token is tolerated (irrelevant to HTTP/2).
        let (m3, t3) = parse_request_line(b"GET /").expect("parse3");
        assert_eq!(m3, &b"GET"[..]);
        assert_eq!(t3, "/");
        // A line with no target, or an empty line, is rejected.
        assert!(parse_request_line(b"GET").is_err());
        assert!(parse_request_line(b"").is_err());
    }

    #[test]
    fn pseudo_header_mapping_for_get() {
        let head = b"GET /index.html?q=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nUser-Agent: curl/8\r\n\r\n";
        let req = map_h1_head_to_h2(head, true).expect("map");
        // :method / :scheme / :authority / :path are derived from method + Uri.
        assert_eq!(req.method(), &Method::GET);
        assert_eq!(req.uri().scheme_str(), Some("https"));
        assert_eq!(
            req.uri().authority().map(|a| a.as_str()),
            Some("example.com")
        );
        assert_eq!(req.uri().path(), "/index.html");
        assert_eq!(
            req.uri().path_and_query().map(|p| p.as_str()),
            Some("/index.html?q=1")
        );
        // Regular fields are carried; Host is consumed by :authority (not a field).
        assert_eq!(
            req.headers().get("accept").map(|v| v.as_bytes()),
            Some(&b"*/*"[..])
        );
        assert_eq!(
            req.headers().get("user-agent").map(|v| v.as_bytes()),
            Some(&b"curl/8"[..])
        );
        assert!(req.headers().get("host").is_none());
    }

    #[test]
    fn scheme_reflects_is_https_flag() {
        let req_http =
            map_h1_head_to_h2(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n", false).expect("http");
        assert_eq!(req_http.uri().scheme_str(), Some("http"));
        let req_https =
            map_h1_head_to_h2(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n", true).expect("https");
        assert_eq!(req_https.uri().scheme_str(), Some("https"));
    }

    #[test]
    fn hop_by_hop_headers_are_stripped() {
        let head = b"GET / HTTP/1.1\r\n\
            Host: h\r\n\
            Connection: keep-alive\r\n\
            Keep-Alive: timeout=5\r\n\
            Proxy-Connection: keep-alive\r\n\
            Upgrade: h2c\r\n\
            Transfer-Encoding: chunked\r\n\
            X-Keep: yes\r\n\r\n";
        let req = map_h1_head_to_h2(head, true).expect("map");
        for forbidden in [
            "connection",
            "keep-alive",
            "proxy-connection",
            "upgrade",
            "transfer-encoding",
            "host",
        ] {
            assert!(
                req.headers().get(forbidden).is_none(),
                "{forbidden} must not be forwarded as an HTTP/2 field"
            );
        }
        // A permitted custom field survives the mapping.
        assert_eq!(
            req.headers().get("x-keep").map(|v| v.as_bytes()),
            Some(&b"yes"[..])
        );
    }

    #[test]
    fn te_header_reduced_to_trailers_only() {
        // `TE: trailers` is the one permitted connection-specific field.
        let r1 = map_h1_head_to_h2(b"GET / HTTP/1.1\r\nHost: h\r\nTE: trailers\r\n\r\n", true)
            .expect("r1");
        assert_eq!(
            r1.headers().get("te").map(|v| v.as_bytes()),
            Some(&b"trailers"[..])
        );
        // Any other TE value is dropped entirely.
        let r2 =
            map_h1_head_to_h2(b"GET / HTTP/1.1\r\nHost: h\r\nTE: gzip\r\n\r\n", true).expect("r2");
        assert!(r2.headers().get("te").is_none());
        // A TE listing `trailers` among other tokens reduces to exactly `trailers`.
        let r3 = map_h1_head_to_h2(
            b"GET / HTTP/1.1\r\nHost: h\r\nTE: gzip, trailers;q=0.5\r\n\r\n",
            true,
        )
        .expect("r3");
        assert_eq!(
            r3.headers().get("te").map(|v| v.as_bytes()),
            Some(&b"trailers"[..])
        );
    }

    #[test]
    fn header_field_names_are_lowercased() {
        let req = map_h1_head_to_h2(
            b"GET / HTTP/1.1\r\nHost: h\r\nX-Mixed-Case: Value\r\n\r\n",
            true,
        )
        .expect("map");
        // The value's case is preserved; the name is stored/retrievable lowercased.
        assert_eq!(
            req.headers().get("x-mixed-case").map(|v| v.as_bytes()),
            Some(&b"Value"[..])
        );
    }

    #[test]
    fn non_field_classifier_matches_c_table() {
        for n in [
            "host",
            "Host",
            "HOST",
            "connection",
            "Connection",
            "keep-alive",
            "Keep-Alive",
            "proxy-connection",
            "Proxy-Connection",
            "upgrade",
            "Upgrade",
            "transfer-encoding",
            "Transfer-Encoding",
        ] {
            assert!(
                is_h2_non_field(n),
                "{n} should be classified as a non-field"
            );
        }
        for n in [
            "accept",
            "content-type",
            "x-custom",
            "te",
            "cookie",
            "authorization",
        ] {
            assert!(!is_h2_non_field(n), "{n} is a permitted field");
        }
    }

    #[test]
    fn te_has_trailers_tokenizer() {
        assert!(te_has_trailers("trailers"));
        assert!(te_has_trailers("Trailers"));
        assert!(te_has_trailers("gzip, trailers"));
        assert!(te_has_trailers("trailers;q=0.5"));
        assert!(te_has_trailers("gzip, trailers;q=1"));
        assert!(!te_has_trailers("gzip"));
        assert!(!te_has_trailers("deflate, gzip"));
        assert!(!te_has_trailers(""));
    }

    #[test]
    fn missing_host_is_an_error() {
        let err = map_h1_head_to_h2(b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n", true);
        assert!(matches!(err, Err(CurlError::Http2)));
    }

    #[test]
    fn malformed_request_line_is_an_error() {
        // No target token.
        assert!(matches!(
            map_h1_head_to_h2(b"GET\r\nHost: h\r\n\r\n", true),
            Err(CurlError::Http2)
        ));
        // Empty head.
        assert!(matches!(
            map_h1_head_to_h2(b"", true),
            Err(CurlError::Http2)
        ));
    }

    #[test]
    fn build_h2_uri_assembles_origin_form() {
        let uri = build_h2_uri(true, "example.com:8443", "/p?x=1").expect("uri");
        assert_eq!(uri.scheme_str(), Some("https"));
        assert_eq!(
            uri.authority().map(|a| a.as_str()),
            Some("example.com:8443")
        );
        assert_eq!(uri.path(), "/p");
        assert_eq!(uri.path_and_query().map(|p| p.as_str()), Some("/p?x=1"));
        let plain = build_h2_uri(false, "h", "/").expect("uri2");
        assert_eq!(plain.scheme_str(), Some("http"));
    }

    #[test]
    fn body_has_bytes_drives_end_stream_flag() {
        assert!(!body_has_bytes(&RequestBody::None));
        assert!(!body_has_bytes(&RequestBody::Sized(Vec::new())));
        assert!(!body_has_bytes(&RequestBody::Chunked(Vec::new(), Vec::new())));
        // An all-empty block list also carries no bytes.
        assert!(!body_has_bytes(&RequestBody::Chunked(vec![Vec::new()], Vec::new())));
        assert!(body_has_bytes(&RequestBody::Sized(vec![1])));
        assert!(body_has_bytes(&RequestBody::Chunked(vec![vec![1, 2, 3]], Vec::new())));
    }

    #[test]
    fn header_line_bytes_formats_name_value_crlf() {
        assert_eq!(
            header_line_bytes("content-type", b"text/plain"),
            b"content-type: text/plain\r\n".to_vec()
        );
        assert_eq!(header_line_bytes("x", b""), b"x: \r\n".to_vec());
    }

    #[test]
    fn version_reports_http2_when_engine_compiled_in() {
        // This module exists only under `#[cfg(feature = "http2")]`; whenever the
        // HTTP/2 engine is built in, `curl_version_info` / `curl --version` MUST
        // advertise `HTTP2`, or `runtests` selects the wrong test subset
        // (AAP §0.7.3 — feature/version lockstep).
        assert!(
            crate::version::feature_names().contains(&"HTTP2"),
            "version must report HTTP2 capability when the http2 engine is enabled"
        );
    }

    // --------------------------------------------------------------------- //
    //                          integration tests                            //
    // --------------------------------------------------------------------- //

    /// Drive a future to completion on a fresh current-thread runtime with all
    /// drivers enabled (the task system for the spawned `h2` connection/server
    /// tasks; timers for the test-side timeouts). Mirrors `h2_proxy`'s helper.
    fn run<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build test runtime")
            .block_on(fut)
    }

    /// Perform the client handshake over `io`, bounded by a timeout so a
    /// regression fails fast rather than hanging the suite.
    async fn connect(io: DuplexStream) -> H2Connection {
        tokio::time::timeout(
            Duration::from_secs(20),
            h2_client_handshake(io, H2Settings::default()),
        )
        .await
        .expect("handshake timed out")
        .expect("handshake failed")
    }

    /// Drive an [`H2Exchange`] to [`ResponseEvent::End`], collecting every event.
    /// Each `next_event` is timeout-bounded so a stall fails fast.
    async fn drive_to_end(ex: &mut H2Exchange) -> Result<Vec<ResponseEvent>> {
        let mut events = Vec::new();
        loop {
            let ev = tokio::time::timeout(Duration::from_secs(20), ex.next_event())
                .await
                .expect("next_event timed out")?;
            let done = matches!(ev, ResponseEvent::End);
            events.push(ev);
            if done {
                break;
            }
        }
        Ok(events)
    }

    fn status_of(events: &[ResponseEvent]) -> Option<i32> {
        events.iter().find_map(|e| match e {
            ResponseEvent::Status(s) => Some(*s),
            _ => None,
        })
    }

    fn body_of(events: &[ResponseEvent]) -> Vec<u8> {
        let mut out = Vec::new();
        for e in events {
            if let ResponseEvent::Body(b) = e {
                out.extend_from_slice(b);
            }
        }
        out
    }

    fn header_lines(events: &[ResponseEvent]) -> Vec<Vec<u8>> {
        events
            .iter()
            .filter_map(|e| match e {
                ResponseEvent::Header(h) => Some(h.clone()),
                _ => None,
            })
            .collect()
    }

    fn has_header_line(events: &[ResponseEvent], needle: &[u8]) -> bool {
        header_lines(events).iter().any(|h| h.as_slice() == needle)
    }

    /// A minimal in-memory HTTP/2 origin that echoes each request's pseudo-headers
    /// (`:method` / `:scheme` / `:authority` / target) back as `x-echo-*` response
    /// headers and returns a fixed `hello` body. The accept loop keeps driving the
    /// connection so queued response frames flush; it returns when the client
    /// closes.
    async fn serve_get_echo(server_io: DuplexStream) {
        let mut conn = match h2::server::handshake(server_io).await {
            Ok(c) => c,
            Err(_) => return,
        };
        while let Some(item) = conn.accept().await {
            let (req, mut respond) = match item {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let method = req.method().to_string();
            let scheme = req.uri().scheme_str().unwrap_or_default().to_string();
            let authority = req
                .uri()
                .authority()
                .map(|a| a.to_string())
                .unwrap_or_default();
            let target = req
                .uri()
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_default();
            let resp = Response::builder()
                .status(200)
                .header("content-type", "text/plain")
                .header("x-echo-method", method)
                .header("x-echo-scheme", scheme)
                .header("x-echo-authority", authority)
                .header("x-echo-target", target)
                .body(())
                .expect("response");
            if let Ok(mut send) = respond.send_response(resp, false) {
                let _ = send.send_data(Bytes::from_static(b"hello"), true);
            }
        }
    }

    /// An origin that answers every stream `200` with a body equal to the
    /// request's `:path` (lets a multiplexing test prove each concurrent stream
    /// reached the right target).
    async fn serve_echo_path(server_io: DuplexStream) {
        let mut conn = match h2::server::handshake(server_io).await {
            Ok(c) => c,
            Err(_) => return,
        };
        while let Some(item) = conn.accept().await {
            let (req, mut respond) = match item {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let path = req.uri().path().to_string();
            let resp = Response::builder().status(200).body(()).expect("response");
            if let Ok(mut send) = respond.send_response(resp, false) {
                let _ = send.send_data(Bytes::from(path), true);
            }
        }
    }

    /// An origin that reads the entire request body (releasing receive
    /// flow-control as it consumes) and then answers `200` with a body equal to
    /// the received byte count. Drives the connection concurrently with the read
    /// so in-flight stream I/O progresses (the documented `h2` server pattern).
    async fn serve_echo_len(server_io: DuplexStream) {
        let mut conn = match h2::server::handshake(server_io).await {
            Ok(c) => c,
            Err(_) => return,
        };
        if let Some(Ok((req, mut respond))) = conn.accept().await {
            let mut body = req.into_body();
            let resp = Response::builder().status(200).body(()).expect("response");
            let mut send = match respond.send_response(resp, false) {
                Ok(s) => s,
                Err(_) => return,
            };
            let echo = async move {
                let mut total = 0usize;
                while let Some(item) = body.data().await {
                    let chunk = match item {
                        Ok(c) => c,
                        Err(_) => break,
                    };
                    let n = chunk.len();
                    let _ = body.flow_control().release_capacity(n);
                    total += n;
                }
                let _ = send.send_data(Bytes::from(total.to_string()), true);
            };
            let drive = async { while conn.accept().await.is_some() {} };
            tokio::join!(drive, echo);
        }
    }

    /// An origin that answers `200` with a `body` and then a single HTTP/2
    /// trailer (`x-checksum: abc123`).
    async fn serve_with_trailer(server_io: DuplexStream) {
        let mut conn = match h2::server::handshake(server_io).await {
            Ok(c) => c,
            Err(_) => return,
        };
        while let Some(item) = conn.accept().await {
            let (_req, mut respond) = match item {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let resp = Response::builder().status(200).body(()).expect("response");
            if let Ok(mut send) = respond.send_response(resp, false) {
                let _ = send.send_data(Bytes::from_static(b"body"), false);
                let mut tr = HeaderMap::new();
                tr.insert(
                    HeaderName::from_static("x-checksum"),
                    HeaderValue::from_static("abc123"),
                );
                let _ = send.send_trailers(tr);
            }
        }
    }

    /// An origin that resets ("refuses") every stream the client opens.
    async fn serve_reset(server_io: DuplexStream) {
        let mut conn = match h2::server::handshake(server_io).await {
            Ok(c) => c,
            Err(_) => return,
        };
        while let Some(item) = conn.accept().await {
            let (_req, mut respond) = match item {
                Ok(pair) => pair,
                Err(_) => return,
            };
            respond.send_reset(h2::Reason::REFUSED_STREAM);
        }
    }

    /// An origin that fully answers one stream and then sends a graceful GOAWAY;
    /// the in-flight (already-complete) stream must still be delivered intact.
    async fn serve_then_goaway(server_io: DuplexStream) {
        let mut conn = match h2::server::handshake(server_io).await {
            Ok(c) => c,
            Err(_) => return,
        };
        if let Some(Ok((_req, mut respond))) = conn.accept().await {
            let resp = Response::builder().status(200).body(()).expect("response");
            if let Ok(mut send) = respond.send_response(resp, false) {
                let _ = send.send_data(Bytes::from_static(b"in-flight-ok"), true);
            }
            // Ask the peer to stop opening new streams; in-flight ones complete.
            conn.graceful_shutdown();
        }
        while conn.accept().await.is_some() {}
    }

    #[test]
    fn get_roundtrip_delivers_status_headers_body_and_pseudo_headers() {
        run(async {
            let (client_io, server_io) = tokio::io::duplex(256 * 1024);
            let server = tokio::spawn(serve_get_echo(server_io));

            let mut conn = connect(client_io).await;
            let head = b"GET /index.html?q=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
            let req = map_h1_head_to_h2(head, true).expect("map");
            let mut ex = conn
                .start_exchange(req, RequestBody::None, false)
                .await
                .expect("start_exchange");

            let events = drive_to_end(&mut ex).await.expect("drive");

            assert_eq!(status_of(&events), Some(200));
            assert_eq!(body_of(&events), b"hello".to_vec());
            // Byte-exact status line ("HTTP/2 200 \r\n" — note the trailing space).
            assert!(
                has_header_line(&events, b"HTTP/2 200 \r\n"),
                "status line not byte-exact; lines = {:?}",
                header_lines(&events)
            );
            // Header block terminated by a blank line.
            assert!(has_header_line(&events, b"\r\n"));
            // The server echoes the pseudo-headers it decoded → end-to-end proof.
            assert!(has_header_line(&events, b"x-echo-method: GET\r\n"));
            assert!(has_header_line(&events, b"x-echo-scheme: https\r\n"));
            assert!(has_header_line(
                &events,
                b"x-echo-authority: example.com\r\n"
            ));
            assert!(has_header_line(
                &events,
                b"x-echo-target: /index.html?q=1\r\n"
            ));
            assert!(events
                .iter()
                .any(|e| matches!(e, ResponseEvent::HeadersComplete { .. })));

            conn.close();
            server.abort();
        });
    }

    #[test]
    fn multiplexes_two_concurrent_streams_on_one_connection() {
        run(async {
            let (client_io, server_io) = tokio::io::duplex(256 * 1024);
            let server = tokio::spawn(serve_echo_path(server_io));

            let mut conn = connect(client_io).await;

            let req_a =
                map_h1_head_to_h2(b"GET /alpha HTTP/1.1\r\nHost: h\r\n\r\n", true).expect("a");
            let req_b =
                map_h1_head_to_h2(b"GET /bravo HTTP/1.1\r\nHost: h\r\n\r\n", true).expect("b");

            // Open BOTH streams before draining either → genuine multiplexing.
            let mut ex_a = conn
                .start_exchange(req_a, RequestBody::None, false)
                .await
                .expect("open a");
            let mut ex_b = conn
                .start_exchange(req_b, RequestBody::None, false)
                .await
                .expect("open b");

            let (res_a, res_b) = tokio::join!(drive_to_end(&mut ex_a), drive_to_end(&mut ex_b));
            let ev_a = res_a.expect("drive a");
            let ev_b = res_b.expect("drive b");

            assert_eq!(status_of(&ev_a), Some(200));
            assert_eq!(status_of(&ev_b), Some(200));
            assert_eq!(body_of(&ev_a), b"/alpha".to_vec());
            assert_eq!(body_of(&ev_b), b"/bravo".to_vec());

            conn.close();
            server.abort();
        });
    }

    #[test]
    fn sender_clone_is_usable_while_live_and_fails_after_close() {
        run(async {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let server = tokio::spawn(serve_echo_path(server_io));

            let mut conn = connect(client_io).await;
            // A live connection hands out a cloned stream-issuing handle.
            assert!(conn.sender().is_ok());
            conn.close();
            // After close, no new streams may be issued.
            assert!(matches!(conn.sender(), Err(CurlError::FailedInit)));

            server.abort();
        });
    }

    #[test]
    fn large_request_body_respects_flow_control() {
        run(async {
            let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
            let server = tokio::spawn(serve_echo_len(server_io));

            let mut conn = connect(client_io).await;
            // 200 KB >> the 64 KB initial stream window, so the upload must await
            // WINDOW_UPDATEs — exercising poll_capacity / release_capacity.
            let body_len = 200 * 1024usize;
            let req =
                map_h1_head_to_h2(b"POST /upload HTTP/1.1\r\nHost: example.com\r\n\r\n", true)
                    .expect("map");
            let mut ex = conn
                .start_exchange(req, RequestBody::Sized(vec![0x61u8; body_len]), false)
                .await
                .expect("start");

            let events = drive_to_end(&mut ex).await.expect("drive");
            assert_eq!(status_of(&events), Some(200));
            assert_eq!(
                String::from_utf8(body_of(&events)).expect("utf8"),
                body_len.to_string(),
                "server must receive exactly the uploaded byte count"
            );

            conn.close();
            server.abort();
        });
    }

    #[test]
    fn captures_response_trailers_after_body() {
        run(async {
            let (client_io, server_io) = tokio::io::duplex(256 * 1024);
            let server = tokio::spawn(serve_with_trailer(server_io));

            let mut conn = connect(client_io).await;
            let req =
                map_h1_head_to_h2(b"GET /t HTTP/1.1\r\nHost: h\r\nTE: trailers\r\n\r\n", true)
                    .expect("map");
            let mut ex = conn
                .start_exchange(req, RequestBody::None, false)
                .await
                .expect("start");

            let events = drive_to_end(&mut ex).await.expect("drive");
            assert_eq!(status_of(&events), Some(200));
            assert_eq!(body_of(&events), b"body".to_vec());
            // The trailer is delivered as a header line, AFTER the body.
            assert!(
                has_header_line(&events, b"x-checksum: abc123\r\n"),
                "trailer not captured; lines = {:?}",
                header_lines(&events)
            );
            let body_idx = events
                .iter()
                .position(|e| matches!(e, ResponseEvent::Body(_)))
                .expect("a body event");
            let trailer_idx = events
                .iter()
                .position(|e| matches!(e, ResponseEvent::Header(h) if h.as_slice() == b"x-checksum: abc123\r\n"))
                .expect("a trailer event");
            assert!(trailer_idx > body_idx, "trailer must follow the body");

            conn.close();
            server.abort();
        });
    }

    #[test]
    fn stream_reset_maps_to_http2_stream_error() {
        run(async {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let server = tokio::spawn(serve_reset(server_io));

            let mut conn = connect(client_io).await;
            let req = map_h1_head_to_h2(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n", true).expect("map");
            let mut ex = conn
                .start_exchange(req, RequestBody::None, false)
                .await
                .expect("start");

            let res = tokio::time::timeout(Duration::from_secs(20), ex.next_event())
                .await
                .expect("next_event timed out");
            assert!(
                matches!(res, Err(CurlError::Http2Stream)),
                "RST_STREAM must map to CURLE_HTTP2_STREAM; got {res:?}"
            );

            conn.close();
            server.abort();
        });
    }

    #[test]
    fn goaway_lets_in_flight_stream_complete() {
        run(async {
            let (client_io, server_io) = tokio::io::duplex(256 * 1024);
            let server = tokio::spawn(serve_then_goaway(server_io));

            let mut conn = connect(client_io).await;
            let req = map_h1_head_to_h2(b"GET /g HTTP/1.1\r\nHost: h\r\n\r\n", true).expect("map");
            let mut ex = conn
                .start_exchange(req, RequestBody::None, false)
                .await
                .expect("start");

            let events = drive_to_end(&mut ex).await.expect("drive");
            assert_eq!(status_of(&events), Some(200));
            assert_eq!(body_of(&events), b"in-flight-ok".to_vec());
            assert!(matches!(events.last(), Some(ResponseEvent::End)));

            conn.close();
            server.abort();
        });
    }
}
