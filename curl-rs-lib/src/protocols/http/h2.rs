// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! HTTP/2 multiplexing and framing (← `lib/http2.c` + `lib/http2.h`).
//!
//! This module is the safe-Rust reimplementation of curl's `nghttp2`-based
//! HTTP/2 connection filter (`Curl_cft_nghttp2`, `lib/http2.c`). The C code
//! drives HPACK compression, frame (de)serialization, stream multiplexing, and
//! per-stream flow control through `nghttp2`; here the same responsibilities
//! are delegated to the [`h2`] crate — the exact HTTP/2 implementation the
//! [`hyper`](https://docs.rs/hyper) client is built on (`hyper` feature
//! `http2`). `h2` performs the framing, HPACK, and connection/stream
//! flow-control bookkeeping; this module supplies curl's *policy*: the SETTINGS
//! values curl advertises, its three activation paths, its error-code mapping,
//! and its `--trace` diagnostic vocabulary.
//!
//! # Negotiation paths (parity with curl)
//!
//! curl reaches HTTP/2 three ways, all reproduced here:
//!
//! * **ALPN** — after a TLS handshake in which the peer selected `h2`
//!   ([`AlpnProtocol::H2`]); driven as [`H2Mode::Alpn`].
//! * **Prior knowledge** — `--http2-prior-knowledge`, where the client speaks
//!   HTTP/2 immediately without negotiation ([`H2Mode::PriorKnowledge`]); the
//!   decision is [`may_switch`], the action is [`switch`]/[`switch_at`].
//! * **h2c Upgrade** — the cleartext `Upgrade: h2c` handshake
//!   ([`H2Mode::Upgrade`]); the request headers are emitted by
//!   [`request_upgrade`] and the connection is switched after a `101 Switching
//!   Protocols` response.
//!
//! When an HTTP/2 stream fails with `HTTP_1_1_REQUIRED`, [`http_1_1_error`]
//! reports it so the transfer layer can transparently retry on HTTP/1.1 —
//! exactly curl's `Curl_h2_http_1_1_error` downgrade behavior.
//!
//! # Multiplexing model
//!
//! curl multiplexes many `Curl_easy` transfers as independent streams over one
//! connection. Here, [`H2Connection`] owns the [`h2::client::SendRequest`]
//! handle and the spawned Tokio connection driver; because `SendRequest` is
//! cheaply cloneable, [`H2Connection::open_stream`] can open many concurrent
//! [`H2Stream`]s over the single underlying connection. [`H2Filter`] wraps an
//! [`H2Connection`] as a [`ConnectionFilter`] so it plugs into the connection
//! filter chain (`crate::conn::filters`).
//!
//! # Safety
//!
//! This module contains **zero** `unsafe`: the crate root's
//! [`forbid(unsafe_code)`](crate) makes any `unsafe` token a hard compile
//! error, satisfying the CI grep gate for the transfer/protocol layer.

use std::future::poll_fn;
use std::pin::Pin;
use std::task::{Context, Poll};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use h2::client::{Builder, ResponseFuture, SendRequest};
use h2::{Reason, RecvStream, SendStream};
use http::header::{HeaderName, HeaderValue};
use http::{Method, Request, Uri};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

use crate::conn::filters::{
    CfFuture, ConnectionFilter, FilterChain, FilterCtx, QueryCtx, QueryOut,
};
use crate::conn::{CfQuery, CfType};
use crate::error::{Error, Result};
use crate::protocols::http::{
    http_req_to_h2, HttpMajors, HttpReqData, HttpResp, CURL_HTTP_V2X, HTTP_PSEUDO_AUTHORITY,
    HTTP_PSEUDO_METHOD, HTTP_PSEUDO_PATH, HTTP_PSEUDO_SCHEME,
};
use crate::tls::AlpnProtocol;

// ===========================================================================
// PHASE 1 — Constants & SETTINGS (exact parity with `lib/http2.c`).
// ===========================================================================

/// The value for `SETTINGS_MAX_CONCURRENT_STREAMS` curl uses until it receives
/// an updated setting from the peer (← `DEFAULT_MAX_CONCURRENT_STREAMS`,
/// `lib/http2.h`).
pub const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 100;

/// DATA-frame chunk size — 16 KiB fits an H2 DATA frame well
/// (← `H2_CHUNK_SIZE`, `lib/http2.c`).
pub const H2_CHUNK_SIZE: usize = 16 * 1024;

/// Connection-level receive window curl advertises (← `H2_CONN_WINDOW_SIZE`).
pub const H2_CONN_WINDOW_SIZE: u32 = 10 * 1024 * 1024;

/// The maximum per-stream window curl allows "in flight", unthrottled
/// (← `H2_STREAM_WINDOW_SIZE_MAX`).
pub const H2_STREAM_WINDOW_SIZE_MAX: u32 = 10 * 1024 * 1024;

/// The initial per-stream window curl advertises in its SETTINGS frame
/// (← `H2_STREAM_WINDOW_SIZE_INITIAL`; the value returned by
/// `cf_h2_initial_win_size` in the common, non-rate-limited case). 64 KiB.
pub const H2_STREAM_WINDOW_SIZE_INITIAL: u32 = 64 * 1024;

/// The `SETTINGS_INITIAL_WINDOW_SIZE` value curl advertises by default; an alias
/// of [`H2_STREAM_WINDOW_SIZE_INITIAL`] kept under the wire-setting name for
/// clarity at the call sites that build the SETTINGS frame.
pub const INITIAL_WINDOW_SIZE: u32 = H2_STREAM_WINDOW_SIZE_INITIAL;

/// curl disables HTTP/2 server push (`SETTINGS_ENABLE_PUSH = 0`) unless a push
/// callback is installed; the CLI installs none, so push is off
/// (← `populate_settings` `iv[2]`, `lib/http2.c`).
pub const ENABLE_PUSH: bool = false;

/// Number of SETTINGS entries curl sends (← `H2_SETTINGS_IV_LEN`).
pub const H2_SETTINGS_IV_LEN: usize = 3;

/// Upper bound on the packed binary SETTINGS payload used in the h2c `Upgrade`
/// handshake (← `H2_BINSETTINGS_LEN`). The three entries curl sends occupy
/// `3 * 6 = 18` bytes; this is the buffer curl reserves for them.
pub const H2_BINSETTINGS_LEN: usize = 80;

/// The HTTP wire-version number for HTTP/2 in curl's `major * 10 + minor`
/// encoding (← `Curl_conn_http_version` returning `20`).
pub const HTTP_VERSION_2: u8 = 20;

/// The ALPN protocol identifier for HTTP/2 over TLS.
pub const ALPN_H2: &str = "h2";

/// The cleartext-HTTP/2 upgrade token (← `NGHTTP2_CLEARTEXT_PROTO_VERSION_ID`,
/// the `"h2c"` value curl writes into the `Upgrade:` request header).
pub const H2C_PROTOCOL_ID: &str = "h2c";

/// The HTTP/2 error code `HTTP_1_1_REQUIRED` (RFC 9113 §7). A stream reset with
/// this code tells the client to retry the request over HTTP/1.1
/// (← `NGHTTP2_HTTP_1_1_REQUIRED`).
pub const HTTP_1_1_REQUIRED: u32 = 0xd;

// HTTP/2 SETTINGS identifiers (RFC 9113 §6.5.2). Only the three curl sends are
// needed to reproduce its SETTINGS frame byte-for-byte.
const SETTINGS_ENABLE_PUSH: u16 = 0x2;
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;

/// The client SETTINGS curl advertises on every HTTP/2 connection
/// (← `populate_settings`, `lib/http2.c`).
///
/// The three fields are exactly curl's `iv[0..3]`, and [`pack_binsettings`]
/// serializes them in the same order so the base64 SETTINGS carried by an h2c
/// `Upgrade` request matches curl's `HTTP2-Settings` header byte-for-byte.
///
/// [`pack_binsettings`]: H2Settings::pack_binsettings
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H2Settings {
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` (← `iv[0]`); curl's multi-handle
    /// default is [`DEFAULT_MAX_CONCURRENT_STREAMS`].
    pub max_concurrent_streams: u32,
    /// `SETTINGS_INITIAL_WINDOW_SIZE` (← `iv[1]`, `cf_h2_initial_win_size`);
    /// [`INITIAL_WINDOW_SIZE`] by default.
    pub initial_window_size: u32,
    /// `SETTINGS_ENABLE_PUSH` (← `iv[2]`); [`ENABLE_PUSH`] (`false`) by default.
    pub enable_push: bool,
}

impl Default for H2Settings {
    fn default() -> Self {
        Self {
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
            initial_window_size: INITIAL_WINDOW_SIZE,
            enable_push: ENABLE_PUSH,
        }
    }
}

impl H2Settings {
    /// The default client SETTINGS curl advertises.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Serialize the SETTINGS into the binary SETTINGS-frame payload, in curl's
    /// `populate_settings` order (`MAX_CONCURRENT_STREAMS`,
    /// `INITIAL_WINDOW_SIZE`, `ENABLE_PUSH`).
    ///
    /// Each entry is six bytes — a big-endian 16-bit identifier followed by a
    /// big-endian 32-bit value (RFC 9113 §6.5.1) — so the three entries occupy
    /// 18 bytes, well within [`H2_BINSETTINGS_LEN`]. This is the exact byte
    /// sequence `nghttp2_pack_settings_payload` produces for curl.
    #[must_use]
    pub fn pack_binsettings(&self) -> Vec<u8> {
        let entries: [(u16, u32); H2_SETTINGS_IV_LEN] = [
            (SETTINGS_MAX_CONCURRENT_STREAMS, self.max_concurrent_streams),
            (SETTINGS_INITIAL_WINDOW_SIZE, self.initial_window_size),
            (SETTINGS_ENABLE_PUSH, u32::from(self.enable_push)),
        ];
        let mut out = Vec::with_capacity(entries.len() * 6);
        for (id, value) in entries {
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&value.to_be_bytes());
        }
        debug_assert!(out.len() <= H2_BINSETTINGS_LEN);
        out
    }

    /// The `HTTP2-Settings` header value for an h2c `Upgrade`: the packed
    /// SETTINGS, base64url-encoded **without** padding
    /// (← `curlx_base64url_encode`, which uses a zero pad byte).
    #[must_use]
    pub fn to_http2_settings_header(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.pack_binsettings())
    }

    /// Configure an [`h2`] client [`Builder`] so the SETTINGS frame it emits
    /// matches curl's: the advertised max-concurrent-streams, the initial
    /// stream window, the large connection window ([`H2_CONN_WINDOW_SIZE`]),
    /// and push disabled.
    fn apply_to_builder(&self, builder: &mut Builder) {
        builder
            .max_concurrent_streams(self.max_concurrent_streams)
            .initial_window_size(self.initial_window_size)
            .initial_connection_window_size(H2_CONN_WINDOW_SIZE)
            .enable_push(self.enable_push);
    }
}

// ===========================================================================
// PHASE 4 — Error mapping (frozen `CURLcode` values) and diagnostic strings.
//
// Placed ahead of the negotiation/driver code so both can use it. curl maps
// nghttp2 outcomes onto two error codes: connection-level failures become
// `CURLE_HTTP2` (16) and per-stream failures (`RST_STREAM`, stream flow-control
// violations, …) become `CURLE_HTTP2_STREAM` (92). An underlying socket error
// is surfaced as the OS error, exactly as curl does.
// ===========================================================================

/// The human-readable name curl's `nghttp2_http2_strerror` gives an HTTP/2
/// error code, preserved so `--trace` output keeps the same vocabulary
/// (RFC 9113 §7 error codes).
///
/// Unknown codes yield `"unknown"`, mirroring nghttp2's fallback.
#[must_use]
pub fn h2_strerror(code: u32) -> &'static str {
    match code {
        0x0 => "NO_ERROR",
        0x1 => "PROTOCOL_ERROR",
        0x2 => "INTERNAL_ERROR",
        0x3 => "FLOW_CONTROL_ERROR",
        0x4 => "SETTINGS_TIMEOUT",
        0x5 => "STREAM_CLOSED",
        0x6 => "FRAME_SIZE_ERROR",
        0x7 => "REFUSED_STREAM",
        0x8 => "CANCEL",
        0x9 => "COMPRESSION_ERROR",
        0xa => "CONNECT_ERROR",
        0xb => "ENHANCE_YOUR_CALM",
        0xc => "INADEQUATE_SECURITY",
        0xd => "HTTP_1_1_REQUIRED",
        _ => "unknown",
    }
}

/// A `--trace`-style description of an HTTP/2 [`Reason`], in curl's
/// `NAME (error N)` shape.
fn reason_str(reason: Reason) -> String {
    let code = u32::from(reason);
    format!("{} (error {code})", h2_strerror(code))
}

/// Maps an [`h2::Error`] to the crate [`Error`] whose integer `CURLcode`
/// matches curl:
///
/// * an underlying I/O failure → [`Error::Io`] (OS-derived code), as curl
///   surfaces the socket error;
/// * an error carrying an HTTP/2 [`Reason`] (`RST_STREAM`/`GOAWAY`) →
///   [`Error::http2_stream`] (`CURLE_HTTP2_STREAM` = 92);
/// * anything else → [`Error::http2`] (`CURLE_HTTP2` = 16).
fn map_h2_err(err: h2::Error) -> Error {
    if let Some(io_err) = err.get_io() {
        return Error::Io(std::io::Error::new(io_err.kind(), io_err.to_string()));
    }
    match err.reason() {
        Some(reason) => Error::http2_stream(format!("HTTP/2 stream error: {}", reason_str(reason))),
        None => Error::http2(format!("HTTP/2 connection error: {err}")),
    }
}

/// The HTTP/2 stream error code carried by an [`h2::Error`], if any, as a raw
/// wire value — used to populate a stream's `error` field and to answer
/// [`CfQuery::StreamError`]. Connection-level or I/O errors have no stream code
/// and yield `None`.
fn h2_err_reason_code(err: &h2::Error) -> Option<u32> {
    err.reason().map(u32::from)
}

// ===========================================================================
// H2Io — the byte transport `h2` frames over.
// ===========================================================================

/// Marker for a byte transport the HTTP/2 connection can be driven over.
///
/// It gathers the bounds [`h2`] requires of its I/O object
/// ([`AsyncRead`] + [`AsyncWrite`] + [`Unpin`] + [`Send`] + `'static`) into one
/// trait so a concrete transport can be stored type-erased as `Box<dyn H2Io>`
/// inside the non-generic [`H2Filter`]. In curl the transport is the next
/// filter down the chain (`cf->next`, typically TCP or TLS); here it is any
/// qualifying async stream (a real TLS/TCP stream in production, an in-process
/// [`tokio::io::duplex`] in tests). A blanket impl makes every qualifying type
/// an `H2Io` automatically.
pub trait H2Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> H2Io for T {}

// ===========================================================================
// PHASE 2 — Negotiation modes (← the switch/upgrade API in `lib/http2.c`).
// ===========================================================================

/// How an HTTP/2 connection was reached, preserved for `--trace` parity with
/// curl's activation paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2Mode {
    /// TLS-ALPN negotiated `h2` (the peer selected [`AlpnProtocol::H2`]).
    Alpn,
    /// `--http2-prior-knowledge`: speak HTTP/2 immediately, no negotiation
    /// (← curl's `h2_prior_knowledge`).
    PriorKnowledge,
    /// Cleartext `Upgrade: h2c` handshake (← curl's `UPGR101_H2` path).
    Upgrade,
}

/// Whether a negotiated ALPN protocol selects HTTP/2 (the [`H2Mode::Alpn`]
/// trigger): `true` only for [`AlpnProtocol::H2`].
#[must_use]
pub fn alpn_is_h2(alpn: AlpnProtocol) -> bool {
    matches!(alpn, AlpnProtocol::H2)
}

/// Whether curl may switch this connection to HTTP/2 by prior knowledge
/// (← `Curl_http2_may_switch`, `lib/http2.c`).
///
/// The C predicate is: the connection is **not already** HTTP/2
/// (`http_version < 20`), the caller **wants** an HTTP/2 variant
/// (`wanted & CURL_HTTP_V2x`), prior knowledge is enabled
/// (`--http2-prior-knowledge`), and we are **not** talking to a plain
/// (non-tunneling) HTTP proxy — over such a proxy the request goes in
/// absolute-form on HTTP/1.x, so prior-knowledge h2 does not apply.
///
/// * `current_http_version` — the connection's current wire version
///   (`major*10+minor`; `20` once it is already HTTP/2).
/// * `wanted` — the requested-version bitmask (test with [`CURL_HTTP_V2X`]).
/// * `prior_knowledge` — the `--http2-prior-knowledge` flag.
/// * `plain_http_proxy` — `true` iff an HTTP proxy is in use **without** a
///   `CONNECT` tunnel (curl's `httpproxy && !tunnel_proxy`).
#[must_use]
pub fn may_switch(
    current_http_version: HttpMajors,
    wanted: HttpMajors,
    prior_knowledge: bool,
    plain_http_proxy: bool,
) -> bool {
    current_http_version < HTTP_VERSION_2
        && (wanted & CURL_HTTP_V2X) != 0
        && prior_knowledge
        && !plain_http_proxy
}

/// Switch a connection to HTTP/2 by installing the HTTP/2 filter at the head of
/// `chain` (← `Curl_http2_switch`, `lib/http2.c`, which adds the nghttp2
/// connection filter to the connection).
///
/// `transport` is the connected lower layer the HTTP/2 connection frames over
/// (in curl, `cf->next`); `config` carries the request to issue and the client
/// SETTINGS. The filter performs the handshake lazily on
/// [`connect`](ConnectionFilter::connect), matching curl adding the filter and
/// connecting it afterwards.
pub fn switch<S>(chain: &mut FilterChain, config: H2FilterConfig, transport: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    chain.add(Box::new(H2Filter::new(config, transport)));
    Ok(())
}

/// Switch a connection to HTTP/2 by installing the HTTP/2 filter directly below
/// the filter at `at_index` in `chain` (← `Curl_http2_switch_at`,
/// `lib/http2.c`).
///
/// This is the placement curl uses when the HTTP/2 filter must sit above an
/// established lower filter (e.g. TLS) rather than at the very head. Returns
/// [`Error::bad_argument`] (via [`FilterChain::insert_after`]) if `at_index` is
/// out of range.
pub fn switch_at<S>(
    chain: &mut FilterChain,
    at_index: usize,
    config: H2FilterConfig,
    transport: S,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    chain.insert_after(at_index, Box::new(H2Filter::new(config, transport)))
}

/// Add the h2c `Upgrade` request headers to `req`
/// (← `Curl_http2_request_upgrade`, `lib/http2.c`).
///
/// curl advertises a cleartext-HTTP/2 upgrade by adding three request header
/// fields, reproduced here exactly:
///
/// * `Connection: Upgrade, HTTP2-Settings` — lists the hop-by-hop fields that
///   carry the upgrade offer;
/// * `Upgrade: h2c` — the HTTP/2-over-cleartext token
///   ([`H2C_PROTOCOL_ID`], curl's `NGHTTP2_CLEARTEXT_PROTO_VERSION_ID`);
/// * `HTTP2-Settings: <base64url>` — the client SETTINGS, packed
///   ([`H2Settings::pack_binsettings`]) and base64url-encoded **without**
///   padding ([`H2Settings::to_http2_settings_header`]).
///
/// On a `101 Switching Protocols` response the caller then invokes
/// [`upgrade`] to switch the live connection to HTTP/2.
///
/// # Errors
///
/// Returns [`Error::bad_argument`] if the request already carries a
/// `Connection`, `Upgrade`, or `HTTP2-Settings` field — curl builds the upgrade
/// request from a clean header set, and a pre-existing field would make the
/// offer ambiguous.
pub fn request_upgrade(req: &mut HttpReqData, settings: &H2Settings) -> Result<()> {
    for field in ["Connection", "Upgrade", "HTTP2-Settings"] {
        if req.headers.contains(field) {
            return Err(Error::bad_argument(format!(
                "cannot build h2c upgrade: request already has a {field} header"
            )));
        }
    }
    req.headers.add("Connection", "Upgrade, HTTP2-Settings");
    req.headers.add("Upgrade", H2C_PROTOCOL_ID);
    req.headers
        .add("HTTP2-Settings", settings.to_http2_settings_header());
    Ok(())
}

/// Complete an h2c `Upgrade` by switching the live connection to HTTP/2 after a
/// `101 Switching Protocols` response (← `Curl_http2_upgrade`, `lib/http2.c`).
///
/// curl, on seeing `101`, installs the HTTP/2 filter *carrying the
/// `via_h1_upgrade` flag* and hands it the bytes already read past the `101`
/// response head (`mem`/`nread`) so they are treated as the start of the HTTP/2
/// connection preface/frames. Here that is expressed by seeding the filter with
/// `pending` (the leftover bytes) and marking the mode [`H2Mode::Upgrade`]; the
/// filter replays `pending` ahead of the transport during the handshake.
///
/// The filter is installed at the head of `chain` (the upgraded connection has
/// no separate TLS filter above it, since h2c is cleartext).
///
/// # Errors
///
/// Propagates any error from installing the filter.
pub fn upgrade<S>(
    chain: &mut FilterChain,
    mut config: H2FilterConfig,
    pending: Bytes,
    transport: S,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    config.mode = H2Mode::Upgrade;
    let mut filter = H2Filter::new(config, transport);
    filter.seed_pending(pending);
    chain.add(Box::new(filter));
    Ok(())
}

/// Whether a stream error signals `HTTP_1_1_REQUIRED`, telling the transfer to
/// retry the request over HTTP/1.1 (← `Curl_h2_http_1_1_error`, `lib/http2.c`).
///
/// curl returns true only when the connection is HTTP/2
/// (`conn->httpversion == 20`) and the stream closed with the
/// `HTTP_1_1_REQUIRED` error code. This is a *parity* behavior: it is not a hard
/// error — the caller transparently downgrades and retries on HTTP/1.1.
///
/// * `conn_http_version` — the connection's wire version (`20` for HTTP/2).
/// * `stream_error` — the stream's HTTP/2 error code
///   (`0` = no error, [`HTTP_1_1_REQUIRED`] = downgrade).
#[must_use]
pub fn http_1_1_error(conn_http_version: HttpMajors, stream_error: u32) -> bool {
    conn_http_version == HTTP_VERSION_2 && stream_error == HTTP_1_1_REQUIRED
}

// ===========================================================================
// PrefixedReader — replays bytes read past the `101` before the transport.
// ===========================================================================

/// An [`AsyncRead`]/[`AsyncWrite`] adapter that yields a prefix of buffered
/// bytes before delegating to an inner transport.
///
/// It exists for the h2c `Upgrade` completion path: after the `101 Switching
/// Protocols` response, curl may have already read some HTTP/2 bytes off the
/// socket (`Curl_http2_upgrade` copies the leftover `mem`/`nread` into the h2
/// input buffer). Wrapping the transport in a `PrefixedReader` seeded with those
/// leftover bytes lets the [`h2`] handshake consume them first, exactly as if
/// they had arrived fresh — all in safe Rust (the inner transport is [`Unpin`],
/// so pinned access needs no `unsafe`).
struct PrefixedReader<S> {
    /// Bytes already read past the `101` head, replayed before the socket.
    prefix: Bytes,
    /// The connected lower transport.
    inner: S,
}

impl<S> PrefixedReader<S> {
    fn new(prefix: Bytes, inner: S) -> Self {
        Self { prefix, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedReader<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.prefix.is_empty() {
            // Drain as much of the replay prefix as fits the caller's buffer.
            let n = self.prefix.len().min(buf.remaining());
            let chunk = self.prefix.split_to(n);
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }
        // Prefix exhausted: `self` is `Unpin`, so pin the inner transport safely.
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedReader<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ===========================================================================
// PHASE 3 — Request building, connection driver, and per-stream context.
// ===========================================================================

/// Build an [`http::Request`] for the [`h2`] client from a neutral
/// [`HttpReqData`], routing the header transform through
/// [`http_req_to_h2`](crate::protocols::http::http_req_to_h2) so pseudo-header
/// order, name lowercasing, and connection-specific-field dropping (RFC 9113
/// §8.2.2) are exactly curl's.
///
/// [`http_req_to_h2`] returns the wire header list with the four pseudo-headers
/// (`:method :scheme :authority :path`) first; this function lifts those back
/// into the request's method/URI (which `h2` re-serializes into pseudo-headers
/// in the same canonical order) and attaches the remaining regular fields. The
/// round-trip is lossless, so the SETTINGS-independent header bytes on the wire
/// match curl's.
///
/// # Errors
///
/// Returns [`Error::bad_argument`] if a required pseudo-header is missing or a
/// header name/value/URI is not valid for HTTP/2.
fn build_h2_request(req: &HttpReqData, is_ssl: bool) -> Result<Request<()>> {
    let fields = http_req_to_h2(req, is_ssl)?;

    let mut method: Option<String> = None;
    let mut scheme: Option<String> = None;
    let mut authority: Option<String> = None;
    let mut path: Option<String> = None;
    let mut regular: Vec<(HeaderName, HeaderValue)> = Vec::with_capacity(fields.count());

    for (name, value) in fields.iter() {
        match name {
            HTTP_PSEUDO_METHOD => method = Some(value.to_owned()),
            HTTP_PSEUDO_SCHEME => scheme = Some(value.to_owned()),
            HTTP_PSEUDO_AUTHORITY => authority = Some(value.to_owned()),
            HTTP_PSEUDO_PATH => path = Some(value.to_owned()),
            other if other.starts_with(':') => {
                // Unknown pseudo-header: curl never emits one, so reject it
                // rather than silently forwarding an invalid field.
                return Err(Error::bad_argument(format!(
                    "unexpected HTTP/2 pseudo-header {other:?}"
                )));
            }
            other => {
                let hn = HeaderName::from_bytes(other.as_bytes()).map_err(|e| {
                    Error::bad_argument(format!("invalid HTTP/2 header name {other:?}: {e}"))
                })?;
                let hv = HeaderValue::from_str(value).map_err(|e| {
                    Error::bad_argument(format!("invalid HTTP/2 header value for {other:?}: {e}"))
                })?;
                regular.push((hn, hv));
            }
        }
    }

    let method = method.ok_or_else(|| Error::bad_argument("HTTP/2 request missing :method"))?;
    let scheme = scheme.ok_or_else(|| Error::bad_argument("HTTP/2 request missing :scheme"))?;
    let authority =
        authority.ok_or_else(|| Error::bad_argument("HTTP/2 request missing :authority"))?;
    let path = path.unwrap_or_else(|| "/".to_owned());

    let method = Method::from_bytes(method.as_bytes())
        .map_err(|e| Error::bad_argument(format!("invalid HTTP/2 :method {method:?}: {e}")))?;
    let uri: Uri = format!("{scheme}://{authority}{path}")
        .parse()
        .map_err(|e| Error::bad_argument(format!("invalid HTTP/2 request URI: {e}")))?;

    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(headers) = builder.headers_mut() {
        for (name, value) in regular {
            headers.append(name, value);
        }
    }
    builder
        .body(())
        .map_err(|e| Error::bad_argument(format!("failed to build HTTP/2 request: {e}")))
}

/// An established HTTP/2 connection: the cloneable [`h2`] request sender plus the
/// spawned connection-driver task (← curl's per-connection `nghttp2_session`).
///
/// Because [`SendRequest`] is cheaply cloneable and the driver runs
/// independently on Tokio, [`open_stream`](Self::open_stream) can open many
/// concurrent [`H2Stream`]s over this single connection — curl's core HTTP/2
/// multiplexing property (many `Curl_easy` transfers over one connection). The
/// driver is aborted on [`Drop`], the safe-Rust analog of curl freeing the
/// session.
pub struct H2Connection {
    /// The multiplexing request sender; cloneable, so many streams share it.
    send_request: SendRequest<Bytes>,
    /// The spawned HTTP/2 connection driver; aborted on drop.
    driver: Option<JoinHandle<()>>,
    /// The client SETTINGS advertised on this connection.
    settings: H2Settings,
}

impl H2Connection {
    /// Run the HTTP/2 client handshake over `io`, advertising curl's client
    /// SETTINGS, and spawn the connection driver.
    ///
    /// # Errors
    ///
    /// Returns [`Error::http2`]/[`Error::Io`] (via [`map_h2_err`]) if the
    /// handshake fails.
    pub async fn handshake<T>(io: T, settings: H2Settings) -> Result<Self>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut builder = Builder::new();
        settings.apply_to_builder(&mut builder);

        let (send_request, connection) = builder
            .handshake::<T, Bytes>(io)
            .await
            .map_err(map_h2_err)?;

        // Drive the connection (framing, flow control, SETTINGS exchange) on a
        // background task; stream errors surface on the per-stream futures, so
        // the connection result is intentionally ignored.
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });

        tracing::trace!(
            target: "curl::cf",
            filter = CF_NAME,
            max_concurrent = settings.max_concurrent_streams,
            initial_window = settings.initial_window_size,
            enable_push = settings.enable_push,
            "HTTP/2 connection established"
        );

        Ok(Self {
            send_request,
            driver: Some(driver),
            settings,
        })
    }

    /// The current maximum number of concurrent streams curl may open,
    /// reproducing curl's `CF_QUERY_MAX_CONCURRENT` answer.
    ///
    /// Until the peer sends its own `SETTINGS_MAX_CONCURRENT_STREAMS` (h2 leaves
    /// the send limit at `usize::MAX`), curl uses its advertised default
    /// ([`DEFAULT_MAX_CONCURRENT_STREAMS`]); afterwards the peer's value governs.
    #[must_use]
    pub fn current_max_concurrent(&self) -> u32 {
        let peer = self.send_request.current_max_send_streams();
        if peer == usize::MAX {
            self.settings.max_concurrent_streams
        } else {
            u32::try_from(peer).unwrap_or(u32::MAX)
        }
    }

    /// The client SETTINGS advertised on this connection.
    #[must_use]
    pub fn settings(&self) -> H2Settings {
        self.settings
    }

    /// Open a new HTTP/2 stream carrying `request`, returning its [`H2Stream`].
    ///
    /// `end_of_stream` is `true` when the request has no body (e.g. `GET`), so
    /// the `HEADERS` frame closes the send half immediately; otherwise the body
    /// is streamed via [`H2Stream::send`]. Waits for the connection to be able
    /// to accept a new stream (`poll_ready`) so opening more than the peer's
    /// `MAX_CONCURRENT_STREAMS` correctly awaits capacity rather than failing.
    ///
    /// # Errors
    ///
    /// Returns an HTTP/2 error (via [`map_h2_err`]) if the connection cannot
    /// accept the request.
    pub async fn open_stream(
        &mut self,
        request: Request<()>,
        end_of_stream: bool,
    ) -> Result<H2Stream> {
        poll_fn(|cx| self.send_request.poll_ready(cx))
            .await
            .map_err(map_h2_err)?;

        let (response, send_stream) = self
            .send_request
            .send_request(request, end_of_stream)
            .map_err(map_h2_err)?;

        let id = send_stream.stream_id().as_u32();
        tracing::trace!(
            target: "curl::cf",
            filter = CF_NAME,
            stream_id = id,
            eos = end_of_stream,
            "FRAME[HEADERS] sent (new stream)"
        );

        Ok(H2Stream {
            id,
            response: Some(response),
            head: None,
            send_stream,
            recv_stream: None,
            status_code: 0,
            error: 0,
            recv_leftover: Bytes::new(),
            send_closed: end_of_stream,
            closed: false,
            reset: false,
        })
    }
}

impl Drop for H2Connection {
    fn drop(&mut self) {
        if let Some(driver) = self.driver.take() {
            driver.abort();
        }
    }
}

/// A single HTTP/2 stream — the safe-Rust analog of curl's `h2_stream_ctx`.
///
/// It bundles the outbound [`SendStream`] (request-body `DATA`), the inbound
/// [`RecvStream`] (response-body `DATA`, available once the response head has
/// arrived), the response status/head, the stream's HTTP/2 error code, and the
/// end-of-stream/close bookkeeping curl tracks in the per-stream bit flags.
pub struct H2Stream {
    /// The HTTP/2 stream identifier (← `h2_stream_ctx.id`).
    id: u32,
    /// The pending response head future, taken once awaited.
    response: Option<ResponseFuture>,
    /// The parsed response head, held until [`recv_response`](Self::recv_response)
    /// hands it to the caller.
    head: Option<HttpResp>,
    /// The outbound half (request-body `DATA` frames).
    send_stream: SendStream<Bytes>,
    /// The inbound half (response-body `DATA` frames); `None` until the response
    /// head has been received.
    recv_stream: Option<RecvStream>,
    /// The response status code (← `h2_stream_ctx.status_code`).
    status_code: i32,
    /// The stream's HTTP/2 error code, `0` if none (← `h2_stream_ctx.error`).
    error: u32,
    /// Received body bytes not yet copied to a caller's buffer.
    recv_leftover: Bytes,
    /// Whether the send half is closed (`END_STREAM` sent or `RST_STREAM`).
    send_closed: bool,
    /// Whether the stream reached end of stream on the receive side
    /// (← `h2_stream_ctx.closed`).
    closed: bool,
    /// Whether the stream was reset (← `h2_stream_ctx.reset`).
    reset: bool,
}

impl H2Stream {
    /// The HTTP/2 stream identifier.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// The response status code, or `0` before the response head is received.
    #[must_use]
    pub fn status(&self) -> i32 {
        self.status_code
    }

    /// The stream's HTTP/2 error code (`0` = none). Feeds
    /// [`CfQuery::StreamError`] and [`http_1_1_error`].
    #[must_use]
    pub fn error(&self) -> u32 {
        self.error
    }

    /// Whether the stream reached end of stream on the receive side.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Whether the stream was reset (`RST_STREAM`).
    #[must_use]
    pub fn was_reset(&self) -> bool {
        self.reset
    }

    /// Record an HTTP/2 error's stream code on this stream, mirroring curl
    /// stashing `rst`/`error` in the stream context for later inspection.
    fn note_err(&mut self, err: &h2::Error) {
        if let Some(code) = h2_err_reason_code(err) {
            self.error = code;
            self.reset = true;
            tracing::trace!(
                target: "curl::cf",
                filter = CF_NAME,
                stream_id = self.id,
                error = code,
                reason = h2_strerror(code),
                "FRAME[RST_STREAM] / stream error"
            );
        }
    }

    /// Await the response head, populating the status code and the inbound
    /// stream, without handing the head out.
    async fn ensure_response(&mut self) -> Result<()> {
        if self.recv_stream.is_some() {
            return Ok(());
        }
        let fut = self
            .response
            .take()
            .ok_or_else(|| Error::http2_stream("HTTP/2 response already consumed"))?;
        let response = match fut.await {
            Ok(r) => r,
            Err(e) => {
                self.note_err(&e);
                return Err(map_h2_err(e));
            }
        };
        let (parts, recv) = response.into_parts();
        self.status_code = i32::from(parts.status.as_u16());
        let mut head = HttpResp::make(self.status_code, parts.status.canonical_reason());
        for (name, value) in parts.headers.iter() {
            let v = value
                .to_str()
                .map(str::to_owned)
                .unwrap_or_else(|_| String::from_utf8_lossy(value.as_bytes()).into_owned());
            head.headers.add(name.as_str(), v);
        }
        tracing::trace!(
            target: "curl::cf",
            filter = CF_NAME,
            stream_id = self.id,
            status = self.status_code,
            "FRAME[HEADERS] received (response head)"
        );
        self.head = Some(head);
        self.recv_stream = Some(recv);
        Ok(())
    }

    /// Await and return the response head as an [`HttpResp`], driving the stream
    /// until the `HEADERS` frame arrives.
    ///
    /// # Errors
    ///
    /// Propagates an HTTP/2 error if the stream fails before the head arrives.
    pub async fn recv_response(&mut self) -> Result<HttpResp> {
        self.ensure_response().await?;
        self.head
            .take()
            .ok_or_else(|| Error::http2_stream("HTTP/2 response head already taken"))
    }

    /// Send `buf` as request-body `DATA`, honoring flow control, setting
    /// `END_STREAM` on the final frame when `eos` is set. Returns the number of
    /// bytes queued (always `buf.len()`).
    ///
    /// The payload is chunked at [`H2_CHUNK_SIZE`] and gated on
    /// [`SendStream::poll_capacity`], so a body larger than the peer's window is
    /// sent across multiple frames as `WINDOW_UPDATE`s arrive (the spawned
    /// driver delivers them concurrently, so this cannot deadlock).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Send`] if the send half is already closed, or an HTTP/2
    /// error if the peer resets the stream mid-send.
    pub async fn send(&mut self, buf: &[u8], eos: bool) -> Result<usize> {
        if self.send_closed {
            return Err(Error::Send);
        }

        if buf.is_empty() {
            if eos {
                self.send_stream
                    .send_data(Bytes::new(), true)
                    .map_err(map_h2_err)?;
                self.send_closed = true;
            }
            return Ok(0);
        }

        let mut offset = 0usize;
        while offset < buf.len() {
            let remaining = buf.len() - offset;
            let want = remaining.min(H2_CHUNK_SIZE);
            self.send_stream.reserve_capacity(want);

            let granted = poll_fn(|cx| self.send_stream.poll_capacity(cx)).await;
            let capacity = match granted {
                Some(Ok(cap)) => cap,
                Some(Err(e)) => {
                    self.note_err(&e);
                    return Err(map_h2_err(e));
                }
                None => {
                    self.send_closed = true;
                    return Err(Error::http2_stream("HTTP/2 send stream closed by peer"));
                }
            };
            if capacity == 0 {
                continue;
            }

            let end = (offset + capacity.min(want)).min(buf.len());
            let is_last = eos && end == buf.len();
            let chunk = Bytes::copy_from_slice(&buf[offset..end]);
            self.send_stream.send_data(chunk, is_last).map_err(|e| {
                self.note_err(&e);
                map_h2_err(e)
            })?;
            offset = end;
            if is_last {
                self.send_closed = true;
            }
        }

        Ok(offset)
    }

    /// Read up to `buf.len()` response-body bytes, returning the count read
    /// (`0` = end of stream). Drives the response head first if needed, then
    /// pulls `DATA` frames, releasing flow-control capacity for each consumed
    /// frame (curl's `nghttp2_session_consume`) and buffering any remainder.
    ///
    /// # Errors
    ///
    /// Returns an HTTP/2 error if the stream fails while reading.
    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.ensure_response().await?;

        while self.recv_leftover.is_empty() {
            let data = match self.recv_stream.as_mut() {
                Some(recv) => recv.data().await,
                None => return Ok(0),
            };
            match data {
                Some(Ok(chunk)) => {
                    let len = chunk.len();
                    if len > 0 {
                        if let Some(recv) = self.recv_stream.as_mut() {
                            let _ = recv.flow_control().release_capacity(len);
                        }
                        self.recv_leftover = chunk;
                    } else {
                        let eos = self
                            .recv_stream
                            .as_ref()
                            .is_some_and(RecvStream::is_end_stream);
                        if eos {
                            self.closed = true;
                            return Ok(0);
                        }
                    }
                }
                Some(Err(e)) => {
                    self.note_err(&e);
                    return Err(map_h2_err(e));
                }
                None => {
                    self.closed = true;
                    return Ok(0);
                }
            }
        }

        let n = self.recv_leftover.len().min(buf.len());
        buf[..n].copy_from_slice(&self.recv_leftover[..n]);
        let _ = self.recv_leftover.split_to(n);
        Ok(n)
    }

    /// Reset the stream, closing the send half (`RST_STREAM(NO_ERROR)`), curl's
    /// stream shutdown. Returns `true` (shutdown completes immediately).
    ///
    /// # Errors
    ///
    /// Never fails; the [`Result`] matches the filter shutdown contract.
    pub async fn shutdown(&mut self) -> Result<bool> {
        if !self.send_closed {
            self.send_stream.send_reset(Reason::NO_ERROR);
            self.send_closed = true;
        }
        Ok(true)
    }
}

// ===========================================================================
// H2Filter — the connection filter (← `Curl_cft_nghttp2`, `lib/http2.c`).
// ===========================================================================

/// The connection-filter name curl reports for the HTTP/2 filter
/// (`Curl_cft_nghttp2.name`), preserved for `--trace` parity.
const CF_NAME: &str = "HTTP/2";

/// Everything the HTTP/2 filter needs to open its primary stream: the request
/// to issue, whether the connection is over TLS (for the `:scheme`
/// pseudo-header), whether the request carries a body, the client SETTINGS, and
/// how HTTP/2 was activated.
///
/// In curl these are read from the `Curl_easy`/`connectdata` state; gathering
/// them into an explicit value keeps [`H2Filter`] self-contained and testable.
#[derive(Debug, Clone)]
pub struct H2FilterConfig {
    /// The request whose headers open the stream (built via
    /// [`http_req_to_h2`](crate::protocols::http::http_req_to_h2)).
    pub request: HttpReqData,
    /// Whether the underlying transport is TLS (selects `https` vs `http`).
    pub is_ssl: bool,
    /// Whether the request has a body to stream after the `HEADERS` frame; when
    /// `false`, the request stream is opened with `END_STREAM` set.
    pub has_body: bool,
    /// The client SETTINGS to advertise.
    pub settings: H2Settings,
    /// How HTTP/2 was reached (ALPN / prior-knowledge / h2c upgrade).
    pub mode: H2Mode,
}

impl H2FilterConfig {
    /// Build a config for `request`, defaulting to no body and curl's standard
    /// client SETTINGS.
    #[must_use]
    pub fn new(request: HttpReqData, is_ssl: bool, mode: H2Mode) -> Self {
        Self {
            request,
            is_ssl,
            has_body: false,
            settings: H2Settings::new(),
            mode,
        }
    }

    /// Set whether the request carries a body (builder style).
    #[must_use]
    pub fn with_body(mut self, has_body: bool) -> Self {
        self.has_body = has_body;
        self
    }

    /// Override the client SETTINGS (builder style).
    #[must_use]
    pub fn with_settings(mut self, settings: H2Settings) -> Self {
        self.settings = settings;
        self
    }
}

/// The HTTP/2 connection filter: the safe-Rust reimplementation of curl's
/// `Curl_cft_nghttp2` (`lib/http2.c`).
///
/// It sits above the socket/TLS filters in a [`FilterChain`]. On
/// [`connect`](ConnectionFilter::connect) it drives the lower filters, then runs
/// the HTTP/2 handshake over the connected transport and opens its primary
/// stream from [`H2FilterConfig::request`]; thereafter
/// [`send`](ConnectionFilter::send)/[`recv`](ConnectionFilter::recv) relay the
/// request body and response body over that stream. Its underlying
/// [`H2Connection`] can multiplex additional concurrent streams
/// ([`H2Connection::open_stream`]) — the property curl relies on to run many
/// transfers over one connection.
pub struct H2Filter {
    /// The stream-opening configuration.
    config: H2FilterConfig,
    /// The connected lower transport, consumed during `connect`; `None` after.
    transport: Option<Box<dyn H2Io>>,
    /// Bytes to replay before the transport (h2c upgrade leftover); usually
    /// empty.
    pending: Bytes,
    /// The established HTTP/2 connection, present once `connect` succeeds.
    conn: Option<H2Connection>,
    /// The filter's primary stream, present once `connect` succeeds.
    stream: Option<H2Stream>,
    /// Whether `connect` has completed.
    connected: bool,
}

impl H2Filter {
    /// Build an HTTP/2 filter that will frame over `transport`.
    #[must_use]
    pub fn new<S>(config: H2FilterConfig, transport: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self {
            config,
            transport: Some(Box::new(transport)),
            pending: Bytes::new(),
            conn: None,
            stream: None,
            connected: false,
        }
    }

    /// Seed bytes to replay before the transport during the handshake, used by
    /// [`upgrade`] to feed the HTTP/2 frames read past a `101` response.
    fn seed_pending(&mut self, pending: Bytes) {
        self.pending = pending;
    }

    /// How HTTP/2 was activated for this filter.
    #[must_use]
    pub fn mode(&self) -> H2Mode {
        self.config.mode
    }

    /// The primary stream's identifier, once opened.
    #[must_use]
    pub fn stream_id(&self) -> Option<u32> {
        self.stream.as_ref().map(H2Stream::id)
    }

    /// The current maximum concurrent streams (peer's value, or curl's default
    /// until the peer's SETTINGS arrive).
    #[must_use]
    pub fn max_concurrent(&self) -> u32 {
        self.conn.as_ref().map_or(
            self.config.settings.max_concurrent_streams,
            H2Connection::current_max_concurrent,
        )
    }

    /// The primary stream's HTTP/2 error code (`0` = none).
    #[must_use]
    pub fn stream_error(&self) -> u32 {
        self.stream.as_ref().map_or(0, H2Stream::error)
    }

    /// Whether the primary stream failed with `HTTP_1_1_REQUIRED`, so the
    /// transfer should downgrade and retry over HTTP/1.1
    /// (parity with [`http_1_1_error`]).
    #[must_use]
    pub fn is_http_1_1_required(&self) -> bool {
        http_1_1_error(HTTP_VERSION_2, self.stream_error())
    }

    /// Await and return the primary stream's response head.
    ///
    /// # Errors
    ///
    /// Returns an HTTP/2 error if the stream is not open or fails before the
    /// head arrives.
    pub async fn read_response(&mut self) -> Result<HttpResp> {
        match self.stream.as_mut() {
            Some(stream) => stream.recv_response().await,
            None => Err(Error::http2("HTTP/2 stream is not open")),
        }
    }

    /// A mutable handle to the established connection, for opening additional
    /// multiplexed streams over the same connection.
    #[must_use]
    pub fn connection_mut(&mut self) -> Option<&mut H2Connection> {
        self.conn.as_mut()
    }
}

impl ConnectionFilter for H2Filter {
    fn name(&self) -> &'static str {
        CF_NAME
    }

    fn cf_type(&self) -> CfType {
        // curl's `Curl_cft_nghttp2` declares `CF_TYPE_MULTIPLEX | CF_TYPE_HTTP`.
        CfType::MULTIPLEX | CfType::HTTP
    }

    fn connect<'a>(
        &'a mut self,
        cx: &'a mut FilterCtx<'_>,
        blocking: bool,
    ) -> CfFuture<'a, Result<bool>> {
        Box::pin(async move {
            if self.connected {
                return Ok(true);
            }

            // Connect the lower filters first (curl connects `cf->next` before
            // running the HTTP/2 handshake).
            let lower_done = cx.connect_next(blocking).await?;
            if !lower_done {
                return Ok(false);
            }

            let transport = self
                .transport
                .take()
                .ok_or_else(|| Error::http2("HTTP/2 filter has no transport to frame over"))?;

            // Replay any bytes read past a `101` (h2c upgrade) before the socket.
            let mut conn = if self.pending.is_empty() {
                H2Connection::handshake(transport, self.config.settings).await?
            } else {
                let io = PrefixedReader::new(std::mem::take(&mut self.pending), transport);
                H2Connection::handshake(io, self.config.settings).await?
            };

            let request = build_h2_request(&self.config.request, self.config.is_ssl)?;
            let stream = conn.open_stream(request, !self.config.has_body).await?;

            tracing::trace!(
                target: "curl::cf",
                filter = CF_NAME,
                mode = ?self.config.mode,
                stream_id = stream.id(),
                "HTTP/2 filter connected"
            );

            self.conn = Some(conn);
            self.stream = Some(stream);
            self.connected = true;
            Ok(true)
        })
    }

    fn send<'a>(
        &'a mut self,
        _cx: &'a mut FilterCtx<'_>,
        buf: &'a [u8],
        eos: bool,
    ) -> CfFuture<'a, Result<usize>> {
        Box::pin(async move {
            match self.stream.as_mut() {
                Some(stream) => stream.send(buf, eos).await,
                None => Err(Error::Send),
            }
        })
    }

    fn recv<'a>(
        &'a mut self,
        _cx: &'a mut FilterCtx<'_>,
        buf: &'a mut [u8],
    ) -> CfFuture<'a, Result<usize>> {
        Box::pin(async move {
            match self.stream.as_mut() {
                Some(stream) => stream.recv(buf).await,
                None => Err(Error::Recv),
            }
        })
    }

    fn shutdown<'a>(&'a mut self, _cx: &'a mut FilterCtx<'_>) -> CfFuture<'a, Result<bool>> {
        Box::pin(async move {
            match self.stream.as_mut() {
                Some(stream) => stream.shutdown().await,
                None => Ok(true),
            }
        })
    }

    fn close(&mut self, cx: &mut FilterCtx<'_>) {
        // Drop the stream and connection (aborting the driver via `Drop`), then
        // close the lower chain — curl's `cf_h2_close`.
        self.stream = None;
        self.conn = None;
        self.connected = false;
        cx.close_next();
    }

    fn data_pending(&self, cx: &QueryCtx<'_>) -> bool {
        // Buffered response bytes are readable without touching the socket.
        let buffered = self
            .stream
            .as_ref()
            .is_some_and(|s| !s.recv_leftover.is_empty());
        buffered || cx.data_pending_next()
    }

    fn query(&self, cx: &QueryCtx<'_>, query: CfQuery, out: &mut QueryOut) -> Result<()> {
        // Mirror `cf_h2_query`: answer MAX_CONCURRENT, HTTP_VERSION,
        // ALPN_NEGOTIATED, STREAM_ERROR and NEED_FLUSH locally; delegate the
        // rest down the chain.
        match query {
            CfQuery::MaxConcurrent => {
                *out = QueryOut::MaxConcurrent(self.max_concurrent());
                Ok(())
            }
            CfQuery::HttpVersion => {
                *out = QueryOut::HttpVersion(HTTP_VERSION_2);
                Ok(())
            }
            CfQuery::AlpnNegotiated => {
                *out = QueryOut::AlpnNegotiated(ALPN_H2.to_owned());
                Ok(())
            }
            CfQuery::StreamError => {
                let code = i32::try_from(self.stream_error()).unwrap_or(i32::MAX);
                *out = QueryOut::StreamError(code);
                Ok(())
            }
            CfQuery::NeedFlush => {
                // Outbound data is written straight into the h2 stream, so the
                // filter holds no backlog of its own.
                *out = QueryOut::NeedFlush(false);
                Ok(())
            }
            _ => cx.query_next(query, out),
        }
    }
}

// ===========================================================================
// Tests — an in-process `h2` mock server (over `tokio::io::duplex`) exercising
// the SETTINGS packing, the three activation paths, single & concurrent
// streams, request-body flow control, the HTTP_1_1_REQUIRED downgrade signal,
// and the header transform. No external daemons.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::FIRSTSOCKET;
    use crate::error::CurlCode;
    use http::{Response, StatusCode};
    use std::collections::BTreeSet;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};

    /// How the in-process mock HTTP/2 server should answer accepted streams.
    #[derive(Clone)]
    enum ServerBehavior {
        /// Respond `200 OK` and send `body` as the response body on each stream.
        OkBody(Vec<u8>),
        /// Echo each stream's request body back as the `200 OK` response body.
        Echo,
        /// Reset the first accepted stream with `HTTP_1_1_REQUIRED`.
        ResetHttp11,
    }

    /// Drives an in-process HTTP/2 mock server over the server half of a duplex.
    ///
    /// The HTTP/2 `Connection` performs socket I/O only while it is polled, and
    /// for the server that polling happens inside
    /// [`accept`](h2::server::Connection::accept). Per-stream handlers are
    /// therefore **spawned** while the `accept` loop keeps running, so the
    /// connection is continuously driven (flushing responses, reading `DATA`)
    /// even while a stream is serviced — the canonical `h2` server pattern. The
    /// loop ends when the client closes the connection and `accept` yields
    /// `None`.
    async fn run_mock_server(io: DuplexStream, behavior: ServerBehavior) {
        let mut conn = h2::server::handshake(io).await.expect("server handshake");
        while let Some(accepted) = conn.accept().await {
            let (req, mut respond) = match accepted {
                Ok(v) => v,
                Err(_) => return,
            };
            match behavior.clone() {
                ServerBehavior::OkBody(body) => {
                    let resp = Response::builder()
                        .status(StatusCode::OK)
                        .header("x-served-by", "mock-h2")
                        .body(())
                        .unwrap();
                    let mut send = respond.send_response(resp, false).unwrap();
                    tokio::spawn(async move {
                        let _ = send.send_data(Bytes::from(body), true);
                    });
                }
                ServerBehavior::Echo => {
                    let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
                    let mut send = respond.send_response(resp, false).unwrap();
                    let mut body = req.into_body();
                    tokio::spawn(async move {
                        let mut buf = Vec::new();
                        while let Some(chunk) = body.data().await {
                            match chunk {
                                Ok(chunk) => {
                                    let _ = body.flow_control().release_capacity(chunk.len());
                                    buf.extend_from_slice(&chunk);
                                }
                                Err(_) => return,
                            }
                        }
                        let _ = send.send_data(Bytes::from(buf), true);
                    });
                }
                ServerBehavior::ResetHttp11 => {
                    // Reject with HTTP_1_1_REQUIRED before any response head so
                    // the client's response future resolves to that reason.
                    respond.send_reset(Reason::HTTP_1_1_REQUIRED);
                }
            }
        }
    }

    /// Reads a stream's whole response body via repeated `recv` until EOS.
    async fn drain_stream(stream: &mut H2Stream) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = stream.recv(&mut buf).await.expect("recv");
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    }

    /// Reads a whole response body through a filter chain until EOS.
    async fn drain_chain(chain: &mut FilterChain) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = chain.recv(&mut buf).await.expect("chain recv");
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    }

    // ---- PHASE 1: constants & SETTINGS ------------------------------------

    #[test]
    fn constants_match_curl() {
        assert_eq!(DEFAULT_MAX_CONCURRENT_STREAMS, 100);
        assert_eq!(INITIAL_WINDOW_SIZE, 65_536);
        assert_eq!(H2_STREAM_WINDOW_SIZE_INITIAL, 65_536);
        assert_eq!(H2_CONN_WINDOW_SIZE, 10 * 1024 * 1024);
        assert_eq!(H2_STREAM_WINDOW_SIZE_MAX, 10 * 1024 * 1024);
        assert_eq!(H2_CHUNK_SIZE, 16 * 1024);
        assert_eq!(H2_BINSETTINGS_LEN, 80);
        assert_eq!(H2_SETTINGS_IV_LEN, 3);
        // curl disables server push; the default SETTINGS carry `ENABLE_PUSH`.
        assert_eq!(H2Settings::new().enable_push, ENABLE_PUSH);
        assert_eq!(HTTP_VERSION_2, 20);
        assert_eq!(HTTP_1_1_REQUIRED, 13);
        assert_eq!(ALPN_H2, "h2");
        assert_eq!(H2C_PROTOCOL_ID, "h2c");
    }

    #[test]
    fn pack_binsettings_layout_matches_curl() {
        let p = H2Settings::new().pack_binsettings();
        // Three 6-byte entries in curl's `populate_settings` order.
        assert_eq!(p.len(), 18);
        assert!(p.len() <= H2_BINSETTINGS_LEN);

        // iv[0] = MAX_CONCURRENT_STREAMS (0x3) = 100.
        assert_eq!(&p[0..2], &[0x00, 0x03]);
        assert_eq!(u32::from_be_bytes([p[2], p[3], p[4], p[5]]), 100);
        // iv[1] = INITIAL_WINDOW_SIZE (0x4) = 65536.
        assert_eq!(&p[6..8], &[0x00, 0x04]);
        assert_eq!(u32::from_be_bytes([p[8], p[9], p[10], p[11]]), 65_536);
        // iv[2] = ENABLE_PUSH (0x2) = 0.
        assert_eq!(&p[12..14], &[0x00, 0x02]);
        assert_eq!(u32::from_be_bytes([p[14], p[15], p[16], p[17]]), 0);
    }

    #[test]
    fn http2_settings_header_is_unpadded_base64url() {
        let settings = H2Settings::new();
        let header = settings.to_http2_settings_header();
        // curl's `curlx_base64url_encode` emits no '=' padding and no '+'/'/'.
        assert!(!header.contains('='));
        assert!(!header.contains('+'));
        assert!(!header.contains('/'));
        // Round-trips back to the exact packed SETTINGS bytes.
        let raw = URL_SAFE_NO_PAD.decode(header.as_bytes()).unwrap();
        assert_eq!(raw, settings.pack_binsettings());
        assert_eq!(raw.len(), 18);
    }

    // ---- PHASE 2: negotiation ---------------------------------------------

    #[test]
    fn may_switch_matches_curl_predicate() {
        // Wants h2, prior knowledge on, no plain proxy => switch.
        assert!(may_switch(11, CURL_HTTP_V2X, true, false));
        // Already HTTP/2 => no switch.
        assert!(!may_switch(20, CURL_HTTP_V2X, true, false));
        // h2 not requested => no switch.
        assert!(!may_switch(11, 0, true, false));
        // Prior knowledge disabled => no switch.
        assert!(!may_switch(11, CURL_HTTP_V2X, false, false));
        // Plain (non-tunneling) HTTP proxy => no switch.
        assert!(!may_switch(11, CURL_HTTP_V2X, true, true));
    }

    #[test]
    fn alpn_is_h2_only_for_h2() {
        assert!(alpn_is_h2(AlpnProtocol::H2));
        assert!(!alpn_is_h2(AlpnProtocol::Http11));
        assert!(!alpn_is_h2(AlpnProtocol::H3));
        assert!(!alpn_is_h2(AlpnProtocol::None));
    }

    #[test]
    fn http_1_1_error_only_on_h2_and_code_13() {
        assert!(http_1_1_error(HTTP_VERSION_2, HTTP_1_1_REQUIRED));
        assert!(!http_1_1_error(11, HTTP_1_1_REQUIRED)); // not an h2 connection
        assert!(!http_1_1_error(HTTP_VERSION_2, 0)); // no stream error
        assert!(!http_1_1_error(HTTP_VERSION_2, 7)); // REFUSED_STREAM, not 13
    }

    #[test]
    fn request_upgrade_adds_h2c_headers_and_base64_settings() {
        let mut req = HttpReqData::make("GET", Some("http"), Some("h.example"), Some("/"));
        let settings = H2Settings::new();
        request_upgrade(&mut req, &settings).unwrap();

        assert_eq!(
            req.headers.get("Connection"),
            Some("Upgrade, HTTP2-Settings")
        );
        assert_eq!(req.headers.get("Upgrade"), Some("h2c"));
        let hs = req.headers.get("HTTP2-Settings").unwrap();
        assert_eq!(hs, settings.to_http2_settings_header());
        // The advertised binary SETTINGS decode to the packed frame payload.
        let raw = URL_SAFE_NO_PAD.decode(hs.as_bytes()).unwrap();
        assert_eq!(raw, settings.pack_binsettings());

        // Re-issuing on the same request must fail (fields already present).
        assert!(request_upgrade(&mut req, &settings).is_err());
    }

    #[test]
    fn switch_installs_filter_at_head() {
        let (client_io, _server_io) = duplex(1024);
        let req = HttpReqData::make("GET", Some("https"), Some("example.com"), Some("/"));
        let config = H2FilterConfig::new(req, true, H2Mode::PriorKnowledge);
        let mut chain = FilterChain::new(FIRSTSOCKET);
        switch(&mut chain, config, client_io).unwrap();
        assert_eq!(chain.len(), 1);
        let head = chain.head().unwrap();
        assert_eq!(head.name(), "HTTP/2");
        assert!(head.cf_type().contains(CfType::MULTIPLEX));
        assert!(head.cf_type().contains(CfType::HTTP));
    }

    #[test]
    fn switch_at_out_of_range_is_bad_argument() {
        let (client_io, _server_io) = duplex(1024);
        let req = HttpReqData::make("GET", Some("https"), Some("example.com"), Some("/"));
        let config = H2FilterConfig::new(req, true, H2Mode::Alpn);
        let mut chain = FilterChain::new(FIRSTSOCKET);
        // Empty chain has no index 0 to insert after.
        let err = switch_at(&mut chain, 0, config, client_io).unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
    }

    // ---- PHASE 3: single, concurrent, upload, filter round trips ----------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn single_request_over_one_stream() {
        let (client_io, server_io) = duplex(64 * 1024);
        let server = tokio::spawn(run_mock_server(
            server_io,
            ServerBehavior::OkBody(b"hello h2".to_vec()),
        ));

        let mut conn = H2Connection::handshake(client_io, H2Settings::new())
            .await
            .unwrap();
        // Until the peer sends MAX_CONCURRENT_STREAMS, curl's default (100) holds.
        assert_eq!(
            conn.current_max_concurrent(),
            DEFAULT_MAX_CONCURRENT_STREAMS
        );
        assert!(!conn.settings().enable_push);

        let req = HttpReqData::make("GET", Some("https"), Some("example.com"), Some("/"));
        let request = build_h2_request(&req, true).unwrap();
        let mut stream = conn.open_stream(request, true).await.unwrap();

        let resp = stream.recv_response().await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("x-served-by"), Some("mock-h2"));

        let body = drain_stream(&mut stream).await;
        assert_eq!(body, b"hello h2");
        assert!(stream.is_closed());
        assert_eq!(stream.error(), 0);

        drop(conn);
        let _ = server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_streams_multiplex_over_one_connection() {
        let (client_io, server_io) = duplex(256 * 1024);
        let server = tokio::spawn(run_mock_server(
            server_io,
            ServerBehavior::OkBody(b"multiplexed".to_vec()),
        ));

        let mut conn = H2Connection::handshake(client_io, H2Settings::new())
            .await
            .unwrap();

        // Open three streams before reading any response — true multiplexing.
        let mut streams = Vec::new();
        for path in ["/a", "/b", "/c"] {
            let req = HttpReqData::make("GET", Some("https"), Some("example.com"), Some(path));
            let request = build_h2_request(&req, true).unwrap();
            streams.push(conn.open_stream(request, true).await.unwrap());
        }

        // Client-initiated stream IDs are the odd numbers 1, 3, 5.
        let ids: BTreeSet<u32> = streams.iter().map(H2Stream::id).collect();
        assert_eq!(ids, BTreeSet::from([1, 3, 5]));

        for stream in &mut streams {
            let resp = stream.recv_response().await.unwrap();
            assert_eq!(resp.status, 200);
            let body = drain_stream(stream).await;
            assert_eq!(body, b"multiplexed");
        }

        drop(conn);
        let _ = server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn request_body_upload_respects_flow_control() {
        let (client_io, server_io) = duplex(256 * 1024);
        let server = tokio::spawn(run_mock_server(server_io, ServerBehavior::Echo));

        let mut conn = H2Connection::handshake(client_io, H2Settings::new())
            .await
            .unwrap();

        let req = HttpReqData::make("POST", Some("https"), Some("example.com"), Some("/echo"));
        let request = build_h2_request(&req, true).unwrap();
        // has_body: open the stream without END_STREAM so DATA frames can follow.
        let mut stream = conn.open_stream(request, false).await.unwrap();

        // 100 KiB exceeds the 64 KiB initial window, forcing multi-frame,
        // WINDOW_UPDATE-gated transmission (the flow-control crux).
        let payload = vec![0x5au8; 100 * 1024];
        let sent = stream.send(&payload, true).await.unwrap();
        assert_eq!(sent, payload.len());

        let resp = stream.recv_response().await.unwrap();
        assert_eq!(resp.status, 200);
        let echoed = drain_stream(&mut stream).await;
        assert_eq!(echoed.len(), payload.len());
        assert_eq!(echoed, payload);

        drop(conn);
        let _ = server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_1_1_required_signals_downgrade() {
        let (client_io, server_io) = duplex(64 * 1024);
        let server = tokio::spawn(run_mock_server(server_io, ServerBehavior::ResetHttp11));

        let mut conn = H2Connection::handshake(client_io, H2Settings::new())
            .await
            .unwrap();
        let req = HttpReqData::make("GET", Some("https"), Some("example.com"), Some("/"));
        let request = build_h2_request(&req, true).unwrap();
        let mut stream = conn.open_stream(request, true).await.unwrap();

        // The stream is reset with HTTP_1_1_REQUIRED before any response head.
        let err = stream.recv_response().await.unwrap_err();
        // A stream-level error maps to CURLE_HTTP2_STREAM (92), never a hard 16.
        assert_eq!(err.code(), CurlCode::Http2Stream);
        // The stream records error code 13, so the downgrade predicate fires.
        assert_eq!(stream.error(), HTTP_1_1_REQUIRED);
        assert!(stream.was_reset());
        assert!(http_1_1_error(HTTP_VERSION_2, stream.error()));

        drop(conn);
        let _ = server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn prior_knowledge_round_trip_through_filter() {
        let (client_io, server_io) = duplex(64 * 1024);
        let server = tokio::spawn(run_mock_server(
            server_io,
            ServerBehavior::OkBody(b"pk-body".to_vec()),
        ));

        // curl would first decide it may switch by prior knowledge.
        assert!(may_switch(11, CURL_HTTP_V2X, true, false));

        let req = HttpReqData::make("GET", Some("https"), Some("example.com"), Some("/"));
        let config = H2FilterConfig::new(req, true, H2Mode::PriorKnowledge);
        let mut chain = FilterChain::new(FIRSTSOCKET);
        switch(&mut chain, config, client_io).unwrap();

        assert!(chain.connect(true).await.unwrap());

        // Filter answers the multiplex/version/alpn queries as curl's `cf_h2_query`.
        let mut out = QueryOut::None;
        chain.query(CfQuery::HttpVersion, &mut out).unwrap();
        assert!(matches!(out, QueryOut::HttpVersion(20)));

        let mut out = QueryOut::None;
        chain.query(CfQuery::AlpnNegotiated, &mut out).unwrap();
        assert!(matches!(out, QueryOut::AlpnNegotiated(ref s) if s == "h2"));

        let mut out = QueryOut::None;
        chain.query(CfQuery::MaxConcurrent, &mut out).unwrap();
        assert!(matches!(
            out,
            QueryOut::MaxConcurrent(n) if n == DEFAULT_MAX_CONCURRENT_STREAMS
        ));

        let body = drain_chain(&mut chain).await;
        assert_eq!(body, b"pk-body");

        drop(chain);
        let _ = server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn h2c_upgrade_round_trip_through_filter() {
        let (client_io, server_io) = duplex(64 * 1024);
        let server = tokio::spawn(run_mock_server(
            server_io,
            ServerBehavior::OkBody(b"upgraded".to_vec()),
        ));

        // The h2c request headers are built by `request_upgrade`.
        let mut upgrade_req =
            HttpReqData::make("GET", Some("http"), Some("example.com"), Some("/"));
        let settings = H2Settings::new();
        request_upgrade(&mut upgrade_req, &settings).unwrap();
        assert_eq!(upgrade_req.headers.get("Upgrade"), Some("h2c"));

        // After a `101`, the connection is switched via `upgrade`; here there are
        // no bytes buffered past the 101, so `pending` is empty.
        let req = HttpReqData::make("GET", Some("https"), Some("example.com"), Some("/"));
        let config = H2FilterConfig::new(req, true, H2Mode::Alpn);
        let mut chain = FilterChain::new(FIRSTSOCKET);
        upgrade(&mut chain, config, Bytes::new(), client_io).unwrap();

        // `upgrade` forces the mode to `Upgrade` regardless of the config default.
        assert_eq!(chain.head().unwrap().name(), "HTTP/2");

        assert!(chain.connect(true).await.unwrap());
        let body = drain_chain(&mut chain).await;
        assert_eq!(body, b"upgraded");

        drop(chain);
        let _ = server.await;
    }

    // ---- PHASE: header transform ------------------------------------------

    #[test]
    fn build_h2_request_applies_curl_header_transform() {
        let mut req = HttpReqData::make("GET", Some("https"), Some("example.com"), Some("/p?q=1"));
        // Host must fold into :authority (already set), and is dropped as a field.
        req.headers.add("Host", "example.com");
        // Mixed-case field name — must be lowercased on the wire.
        req.headers.add("User-Agent", "curl-rs/8.19.0-DEV");
        req.headers.add("Accept", "*/*");
        // Connection-specific field must be dropped per RFC 9113 §8.2.2.
        req.headers.add("Connection", "keep-alive");

        let request = build_h2_request(&req, true).unwrap();
        assert_eq!(request.method(), Method::GET);
        assert_eq!(request.uri().scheme_str(), Some("https"));
        assert_eq!(
            request.uri().authority().map(|a| a.as_str()),
            Some("example.com")
        );
        assert_eq!(request.uri().path(), "/p");
        assert_eq!(request.uri().query(), Some("q=1"));

        let headers = request.headers();
        // Regular fields survive (HeaderMap lookup is case-insensitive).
        assert_eq!(
            headers.get("user-agent").map(|v| v.to_str().unwrap()),
            Some("curl-rs/8.19.0-DEV")
        );
        assert!(headers.get("accept").is_some());
        // Host and connection-specific fields were dropped by `http_req_to_h2`.
        assert!(headers.get("host").is_none());
        assert!(headers.get("connection").is_none());
        // No pseudo-header leaked into the regular field block.
        assert!(headers.keys().all(|k| !k.as_str().starts_with(':')));
    }

    // ---- PrefixedReader (h2c leftover replay) -----------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn prefixed_reader_replays_prefix_then_inner() {
        let (a, mut b) = duplex(1024);
        // Bytes that "arrived" past the 101, replayed before the socket.
        let mut reader = PrefixedReader::new(Bytes::from_static(b"PRE"), a);
        // The rest arrives over the transport.
        tokio::spawn(async move {
            b.write_all(b"POST").await.unwrap();
            b.shutdown().await.unwrap();
        });

        let mut got = Vec::new();
        reader.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"PREPOST");
    }
}
