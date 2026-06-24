//! HTTP/2 `CONNECT` tunnel filter — the Rust rewrite of libcurl's
//! `lib/cf-h2-proxy.c` (1504 LoC) / `lib/cf-h2-proxy.h`, over the safe
//! [`h2`](https://docs.rs/h2) crate instead of `nghttp2`.
//!
//! This connection filter establishes an HTTP/2 `CONNECT` tunnel through an
//! HTTP/2-capable forward proxy (an HTTPS proxy that negotiated ALPN `h2`).
//! Unlike the HTTP/1 tunnel — which, once the `200` response arrives, becomes a
//! fully transparent pass-through — the HTTP/2 tunnel **remains active for the
//! whole connection lifetime**: the tunneled traffic is carried inside HTTP/2
//! `DATA` frames on the single `CONNECT` stream. Consequently this filter has
//! real [`send`](ConnectionFilter::send) / [`recv`](ConnectionFilter::recv)
//! implementations (it is *not* transparent), and a TLS filter plus the real
//! protocol engine stack **above** it and tunnel their bytes through it exactly
//! as in the HTTP/1 case.
//!
//! # The central C → Rust transformation (AAP §0.2 / §0.6)
//!
//! curl drives a `nghttp2_session` with ~10 hand-written callbacks
//! (`proxy_h2_on_header`, `tunnel_recv_callback`, `tunnel_send_callback`,
//! `on_session_send`, `proxy_h2_progress_ingress` / `_egress`, the
//! `proxy_h2_nw_out_*` writers, …) plus manual network in/out `bufq`s. **All of
//! that callback machinery dissolves** into the `h2` crate's awaited client API:
//!
//! * the session handshake becomes [`h2::client::Builder::handshake`], yielding
//!   a [`SendRequest`] and a [`Connection`] future;
//! * the connection future — which drives all frame ingress/egress — is
//!   **spawned as a single Tokio task** (`proxy_h2_progress_*` and the
//!   `nw_out`/`nw_in` pumps collapse into it) and kept alive for the
//!   connection's lifetime;
//! * the `CONNECT` request becomes one [`SendRequest::send_request`] call,
//!   returning a [`ResponseFuture`] and a [`SendStream`];
//! * the tunnel's outbound path is [`SendStream::send_data`] (respecting HTTP/2
//!   flow control), and the inbound path is [`RecvStream::data`] plus the
//!   **mandatory** [`FlowControl::release_capacity`] refill.
//!
//! The C callback *structure* is thrown away; the `CONNECT` *semantics* are
//! preserved exactly.
//!
//! # Flow control — the #1 correctness pitfall (cf-h2-proxy.c)
//!
//! The tunnel advertises a large per-stream window
//! ([`H2_TUNNEL_WINDOW_SIZE`], 10 MB). curl refills it by calling
//! `nghttp2_session_consume(stream_id, n)` for every `n` bytes the upper layer
//! reads out of the tunnel ([`cf_h2_proxy_recv`]). The Rust equivalent is
//! [`FlowControl::release_capacity`]: [`recv`](ConnectionFilter::recv) **must**
//! release capacity for the bytes it hands to the caller, or the 10 MB window
//! drains to zero and the tunnel **deadlocks**. On the send side the filter
//! awaits/observes [`SendStream::capacity`] before writing, applying
//! [`CurlError::Again`] backpressure when the peer's window is exhausted.
//!
//! # Memory safety (AAP §0.7.1) — ABSOLUTE
//!
//! This module contains **zero** `unsafe` and opts into
//! `#![forbid(unsafe_code)]`, so the rule is compiler-enforced. The C
//! `nghttp2_session` + raw callback pointers + manual buffers become the safe
//! [`h2`] client (`SendRequest` / `RecvStream` / `SendStream` / `FlowControl`)
//! plus [`BufQ`] / [`bytes::Bytes`]. There are no raw pointers and no FFI.

#![forbid(unsafe_code)]

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use h2::client::{Builder, ResponseFuture, SendRequest};
use h2::{RecvStream, SendStream};
use http::uri::{Authority, Parts as UriParts};
use http::{HeaderMap, Method, Request, Uri};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

use crate::auth::{
    basic, digest, parse_auth_header, pick_one_auth, proxy_auth_mask, AuthChallenge, AuthState,
    CURLAUTH_BASIC, CURLAUTH_DIGEST, CURLAUTH_NONE,
};
use crate::conn::filters::{
    BoxFuture, CfQuery, CfQueryResult, CfState, ConnectionFilter, FilterChain, FilterData,
    IpQuadruple, CF_CTRL_FLUSH, CF_TYPE_IP_CONNECT, CF_TYPE_PROXY,
};
use crate::error::{CurlError, Result};
use crate::proxy::{Proxy, PROXY_TIMEOUT};
use crate::util::bufq::{BufQ, BUFQ_OPT_SOFT_LIMIT};
use crate::util::sendf::{failf, infof};

// =============================================================================
// Constants — EXACT, from cf-h2-proxy.c L46-55
// =============================================================================

/// Working chunk size for the tunnel `bufq`s (`PROXY_H2_CHUNK_SIZE`,
/// cf-h2-proxy.c L46): `16 * 1024`.
pub const PROXY_H2_CHUNK_SIZE: usize = 16 * 1024;

/// The connection-level (whole-session) flow-control window curl sets via
/// `nghttp2_session_set_local_window_size` (`PROXY_HTTP2_HUGE_WINDOW_SIZE`,
/// cf-h2-proxy.c L48): `100 * 1024 * 1024` (100 MB). Used as the `h2` client's
/// initial **connection** window so the multiplexed session never throttles the
/// single tunnel stream at the connection level.
pub const PROXY_HTTP2_HUGE_WINDOW_SIZE: usize = 100 * 1024 * 1024;

/// The per-stream flow-control window for the tunnel CONNECT stream
/// (`H2_TUNNEL_WINDOW_SIZE`, cf-h2-proxy.c L49): `10 * 1024 * 1024` (10 MB).
/// Used as the `h2` client's initial **stream** window; the tunnel's
/// [`recv`](ConnectionFilter::recv) must release capacity as it consumes so this
/// window keeps refilling.
pub const H2_TUNNEL_WINDOW_SIZE: usize = 10 * 1024 * 1024;

/// Network-receive `bufq` chunk count (`PROXY_H2_NW_RECV_CHUNKS`,
/// cf-h2-proxy.c L51): `H2_TUNNEL_WINDOW_SIZE / PROXY_H2_CHUNK_SIZE` (640).
pub const PROXY_H2_NW_RECV_CHUNKS: usize = H2_TUNNEL_WINDOW_SIZE / PROXY_H2_CHUNK_SIZE;

/// Network-send `bufq` chunk count (`PROXY_H2_NW_SEND_CHUNKS`,
/// cf-h2-proxy.c L52): `1`.
pub const PROXY_H2_NW_SEND_CHUNKS: usize = 1;

/// Tunnel receive-buffer chunk count (`H2_TUNNEL_RECV_CHUNKS`,
/// cf-h2-proxy.c L54): `H2_TUNNEL_WINDOW_SIZE / PROXY_H2_CHUNK_SIZE` (640).
pub const H2_TUNNEL_RECV_CHUNKS: usize = H2_TUNNEL_WINDOW_SIZE / PROXY_H2_CHUNK_SIZE;

/// Tunnel send-buffer chunk count (`H2_TUNNEL_SEND_CHUNKS`,
/// cf-h2-proxy.c L55): `(128 * 1024) / PROXY_H2_CHUNK_SIZE` (8).
pub const H2_TUNNEL_SEND_CHUNKS: usize = (128 * 1024) / PROXY_H2_CHUNK_SIZE;

/// The filter's display name (C: `Curl_cft_h2_proxy.name`, cf-h2-proxy.c L1462).
const CF_NAME: &str = "H2-PROXY";

/// Upper bound on `CONNECT` submit attempts across the proxy-authentication
/// multi-pass loop. curl bounds the same loop through the easy handle's redirect
/// / auth-retry accounting; here a small fixed cap guarantees the 407 retry loop
/// always terminates even against a misbehaving proxy.
const MAX_CONNECT_ATTEMPTS: u32 = 10;

// =============================================================================
// PHASE 1 — tunnel state + per-stream context
// =============================================================================

/// The tunnel CONNECT stream's lifecycle — the Rust mirror of C's
/// `h2_tunnel_state` (cf-h2-proxy.c L58-64).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2TunnelState {
    /// Init / default / no tunnel yet (C: `H2_TUNNEL_INIT`).
    Init,
    /// The `CONNECT` request stream is open and being sent (C:
    /// `H2_TUNNEL_CONNECT`).
    Connect,
    /// The `CONNECT` response has been received completely (C:
    /// `H2_TUNNEL_RESPONSE`).
    Response,
    /// The tunnel is established and carrying `DATA` (C:
    /// `H2_TUNNEL_ESTABLISHED`).
    Established,
    /// The tunnel attempt failed (C: `H2_TUNNEL_FAILED`).
    Failed,
}

/// The tunnel CONNECT stream — the Rust mirror of C's `struct tunnel_stream`
/// (cf-h2-proxy.c L66-77).
///
/// Where C kept an `nghttp2` `stream_id`, raw `recvbuf` / `sendbuf` `bufq`s, and
/// the parsed `http_resp`, the Rust port holds the `h2` stream halves
/// ([`SendStream`] / [`RecvStream`]) obtained once the CONNECT stream is open,
/// the two staging [`BufQ`]s sized per the EXACT constants, the `CONNECT`
/// response status, and the `:authority` (tunnel target) string.
struct TunnelStream {
    /// Tunnel lifecycle state (C: `tunnel_stream.state`).
    state: H2TunnelState,
    /// Receive staging buffer between the `h2` stream and the byte
    /// [`recv`](ConnectionFilter::recv) interface (C: `tunnel_stream.recvbuf`,
    /// init'd with [`BUFQ_OPT_SOFT_LIMIT`] at
    /// `PROXY_H2_CHUNK_SIZE × H2_TUNNEL_RECV_CHUNKS`).
    recvbuf: BufQ,
    /// Send staging buffer between the byte [`send`](ConnectionFilter::send)
    /// interface and the `h2` stream (C: `tunnel_stream.sendbuf`, init'd at
    /// `PROXY_H2_CHUNK_SIZE × H2_TUNNEL_SEND_CHUNKS`).
    sendbuf: BufQ,
    /// Outbound half of the CONNECT stream, valid from submit onward (the C
    /// stream's write side; data is pushed via [`SendStream::send_data`]).
    send_stream: Option<SendStream<Bytes>>,
    /// Inbound half of the CONNECT stream, taken from the `2xx` response body
    /// (the C stream's read side; data is pulled via [`RecvStream::data`]).
    recv_stream: Option<RecvStream>,
    /// The `:authority` (tunnel target `host:port`, IPv6-bracketed) the CONNECT
    /// request addresses (C: `tunnel_stream.authority`).
    authority: String,
    /// The most recent `CONNECT` response status code (C: derived from
    /// `tunnel_stream.resp->status`).
    status: u16,
    /// Whether the tunnel stream has been closed / reached EOF (C:
    /// `tunnel_stream.closed`).
    closed: bool,
}

impl TunnelStream {
    /// Initialise a tunnel stream with the given `:authority` (C:
    /// `tunnel_stream_init`, cf-h2-proxy.c L79-100). The `recvbuf` uses
    /// [`BUFQ_OPT_SOFT_LIMIT`] exactly as the C `Curl_bufq_init2` call does.
    fn new(authority: String) -> Self {
        Self {
            state: H2TunnelState::Init,
            recvbuf: BufQ::new_with_opts(
                PROXY_H2_CHUNK_SIZE,
                H2_TUNNEL_RECV_CHUNKS,
                BUFQ_OPT_SOFT_LIMIT,
            ),
            sendbuf: BufQ::new(PROXY_H2_CHUNK_SIZE, H2_TUNNEL_SEND_CHUNKS),
            send_stream: None,
            recv_stream: None,
            authority,
            status: 0,
            closed: false,
        }
    }

    /// Whether the tunnel has buffered, unsent outbound data (drives the
    /// `CF_QUERY_NEED_FLUSH` answer; C checks `!Curl_bufq_is_empty(sendbuf)`).
    fn needs_flush(&self) -> bool {
        !self.sendbuf.is_empty()
    }
}

// =============================================================================
// `FilterIo` — adapt a `ConnectionFilter` chain into `AsyncRead + AsyncWrite`
// =============================================================================

/// Bridges the [`ConnectionFilter`] byte interface (`send` / `recv`) below this
/// filter into the [`AsyncRead`] + [`AsyncWrite`] stream the `h2` client
/// handshake consumes.
///
/// The `h2` client's [`Connection`] future owns its IO and must be polled for
/// the connection's whole lifetime, so during [`connect`](ConnectionFilter::connect)
/// this filter **moves** its `next` (the proxy connection below, already
/// TLS-wrapped with ALPN `h2`) into a `FilterIo` and hands that to
/// `handshake`; the resulting connection future is then spawned (see
/// [`CfH2Proxy`]).
///
/// # Cancel-safety of the per-poll future
///
/// [`ConnectionFilter::recv`] / [`send`] return boxed futures borrowing the
/// filter. Rather than self-referentially store one, each `poll_*` constructs a
/// fresh `recv` / `send` future, polls it once with the caller's [`Context`],
/// and — if it is `Pending` — drops it and returns [`Poll::Pending`] with the
/// waker already registered by the inner future. This is sound because the
/// filters below (Tokio sockets / `tokio-rustls`) are cancel-safe: a read/write
/// that has not completed consumes nothing, so re-creating and re-polling the
/// future resumes the same operation. A synchronous [`CurlError::Again`] is
/// mapped to a self-wake + `Pending` so the task is re-polled promptly.
struct FilterIo {
    /// The connection below, moved in for the lifetime of the `h2` connection.
    filter: Box<dyn ConnectionFilter>,
    /// A reusable scratch buffer so `poll_read` does not allocate per poll.
    read_buf: Vec<u8>,
}

impl FilterIo {
    /// Wrap `filter`, sizing the scratch buffer at [`PROXY_H2_CHUNK_SIZE`].
    fn new(filter: Box<dyn ConnectionFilter>) -> Self {
        Self {
            filter,
            read_buf: vec![0u8; PROXY_H2_CHUNK_SIZE],
        }
    }
}

/// Map a [`CurlError`] into a [`std::io::Error`] for the `AsyncRead`/`AsyncWrite`
/// boundary (the `h2` connection sees IO errors, which it surfaces as
/// [`h2::Error::is_io`]).
fn curl_to_io(e: &CurlError) -> io::Error {
    io::Error::other(e.to_string())
}

impl AsyncRead for FilterIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // `FilterIo` is `Unpin` (both fields are), so projecting to `&mut Self`
        // is safe and needs no `unsafe`.
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
                    // No data right now and the inner op did not register a
                    // waker: re-poll promptly.
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

impl AsyncWrite for FilterIo {
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
        // The filters below write straight through (a socket / TLS buffer is the
        // OS/runtime's concern), so there is nothing extra to flush here.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Graceful teardown of the connection below happens when the spawned
        // connection task ends (its `FilterIo` — and thus `next` — is dropped),
        // driven by [`CfH2Proxy::close`] / `Drop`.
        Poll::Ready(Ok(()))
    }
}

/// Map an [`h2::Error`] onto the closest [`CurlError`], mirroring how the C code
/// turns `nghttp2` failures into `CURLE_HTTP2` / `CURLE_HTTP2_STREAM`.
fn h2_to_curl(e: &h2::Error) -> CurlError {
    if e.is_reset() {
        // A stream-level RST_STREAM → the HTTP/2 stream error code.
        CurlError::Http2Stream
    } else {
        // Connection-level / framing / IO failures → the HTTP/2 framing error.
        CurlError::Http2
    }
}

/// Strip the `"<Name>: "` prefix and the trailing CRLF from a complete header
/// line, yielding just the field value.
///
/// [`Proxy::proxy_auth`] and [`basic::http_basic_header`] return a full
/// `"Proxy-Authorization: Basic …\r\n"` line (the HTTP/1 form), but an HTTP/2
/// header carries only the value, so the prefix and line terminator are removed.
fn header_value_of(line: &str) -> String {
    let after_colon = line.split_once(": ").map_or(line, |(_, v)| v);
    after_colon.trim_end_matches(['\r', '\n']).to_string()
}

// =============================================================================
// Cached query answers
// =============================================================================

/// Answers to delegatable [`CfQuery`]s, captured from `next` **before** it is
/// moved into the spawned connection task.
///
/// C's `cf_h2_proxy_query` delegates every query it does not handle to
/// `cf->next` (the live socket filter). Because the Rust port moves `next` into
/// the `h2` connection task, those delegatable answers are snapshotted here at
/// connect time so the filter can keep answering `REMOTE_ADDR` / `IP_INFO` /
/// `TRANSPORT` / `SOCKET` afterwards (e.g. for a HAProxy filter stacked above).
#[derive(Default)]
struct CachedQueries {
    /// Cached `CF_QUERY_REMOTE_ADDR` (the proxy connection's peer address).
    remote_addr: Option<SocketAddr>,
    /// Cached `CF_QUERY_IP_INFO` (`is_ipv6` + the endpoint quadruple).
    ip_info: Option<(bool, IpQuadruple)>,
    /// Cached `CF_QUERY_TRANSPORT` (`TRNSPRT_*`).
    transport: Option<u8>,
    /// Cached `CF_QUERY_SOCKET` (the underlying socket descriptor).
    socket: Option<i64>,
}

// =============================================================================
// PHASE 1 — the filter context (← `struct cf_h2_proxy_ctx` L166-185)
// =============================================================================

/// The HTTP/2 `CONNECT`-tunnel filter — the Rust replacement for C's
/// `struct cf_h2_proxy_ctx` plus the per-filter state of its
/// `struct Curl_cfilter` (cf-h2-proxy.c L166-185).
///
/// The C `nghttp2_session *h2`, the network `inbufq` / `outbufq`, and the
/// `goaway`/`conn_closed` bookkeeping collapse into the `h2` client handle
/// ([`SendRequest`]) plus the spawned [`Connection`] task ([`Self::conn_task`]);
/// the C `tunnel` sub-struct becomes [`TunnelStream`].
pub struct CfH2Proxy {
    /// Chain link (`next`) + `connected`/`shutdown` bits (C: `Curl_cfilter`).
    /// After [`connect`](ConnectionFilter::connect) succeeds, `next` is `None`:
    /// it has been moved into [`Self::conn_task`] via [`FilterIo`].
    state: CfState,

    /// The proxy's own host, reported by `CF_QUERY_HOST_PORT` (C:
    /// `cf->conn->http_proxy.host.name`, cf-h2-proxy.c L1413).
    proxy_host: String,
    /// The proxy's own port, reported by `CF_QUERY_HOST_PORT` (C:
    /// `cf->conn->http_proxy.port`).
    proxy_port: u16,

    /// The parsed proxy configuration (credentials + type) consulted for
    /// `Proxy-Authorization` (C: `cf->conn->http_proxy` + `data->set`).
    proxy: Proxy,
    /// The `CURLOPT_PROXYAUTH` `CURLAUTH_*` bitmask.
    auth_mask: u32,
    /// The proxy auth-negotiation state across the 407 multi-pass (C:
    /// `data->state.authproxy`).
    auth_state: AuthState,
    /// Schemes already attempted, to avoid re-sending an unchangeable rejected
    /// credential (notably Basic) and to bound the retry loop.
    auth_tried: u32,
    /// The `Proxy-Authorization` **value** to attach to the next CONNECT
    /// (recomputed across the multi-pass; `None` ⇒ no auth header).
    proxy_authz: Option<String>,
    /// The optional `User-Agent` value to attach to the CONNECT (C: adds
    /// `data->set.str[STRING_USERAGENT]` when present, http_proxy.c L246-252).
    user_agent: Option<String>,

    /// The `h2` client handle used to open the CONNECT stream(s) (C:
    /// `nghttp2_session *h2`).
    send_req: Option<SendRequest<Bytes>>,
    /// The spawned task driving the `h2` [`Connection`] future — it owns the
    /// moved-in `next` (via [`FilterIo`]) and pumps all frame I/O (C: the
    /// `proxy_h2_progress_ingress`/`_egress` + `nw_out` machinery).
    conn_task: Option<JoinHandle<()>>,

    /// The tunnel CONNECT stream + its staging buffers (C: `ctx->tunnel`).
    tunnel: TunnelStream,
    /// Query answers snapshotted from `next` before it was moved away.
    cached: CachedQueries,

    /// Mirrors `data->set.verbose` for [`infof`] traces.
    verbose: bool,
    /// The CONNECT establishment timeout in milliseconds (C: `Curl_timeleft`;
    /// defaults to [`PROXY_TIMEOUT`]).
    connect_timeout_ms: u64,
}

/// The outcome of inspecting a single CONNECT response.
enum InspectOutcome {
    /// `2xx` — the tunnel is established.
    Established,
    /// `407` with a usable follow-up scheme — re-submit a fresh CONNECT stream.
    Retry,
}

impl CfH2Proxy {
    /// Compose the IPv6-aware `:authority` (`host:port`) for the tunnel target,
    /// matching curl's `"%s%s%s:%d"` with `[`/`]` brackets for an IPv6 literal
    /// (cf-h2-proxy.c L94 / http_proxy.c L212).
    fn build_authority(host: &str, port: u16) -> String {
        if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
    }

    /// Build the HTTP/2 CONNECT request (← `Curl_http_proxy_create_CONNECT`
    /// with `http_version_major == 2`, http_proxy.c L197-270).
    ///
    /// Per RFC 7540 §8.3 a CONNECT request carries only `:method = CONNECT` and
    /// `:authority = host:port` (no `:scheme`, no `:path`); the `h2` crate emits
    /// exactly that from an [`http::Request`] whose [`Uri`] has only an
    /// authority component. Unlike the HTTP/1 form, **no** `Host` and **no**
    /// `Proxy-Connection` header is added (HTTP/2 uses `:authority`); any
    /// `Proxy-Authorization` is a regular header, and `User-Agent` is forwarded
    /// when configured.
    fn build_connect_request(&self) -> Result<Request<()>> {
        let authority: Authority = self
            .tunnel
            .authority
            .parse()
            .map_err(|_| CurlError::UnsupportedProtocol)?;
        let mut parts = UriParts::default();
        parts.authority = Some(authority);
        // scheme = None, path_and_query = None ⇒ an authority-only URI, which
        // `http::Uri::from_parts` accepts (a missing scheme only errors when a
        // path is present).
        let uri = Uri::from_parts(parts).map_err(|_| CurlError::UnsupportedProtocol)?;

        let mut builder = Request::builder().method(Method::CONNECT).uri(uri);
        if let Some(authz) = self.proxy_authz.as_deref() {
            builder = builder.header(http::header::PROXY_AUTHORIZATION, authz);
        }
        if let Some(ua) = self.user_agent.as_deref() {
            builder = builder.header(http::header::USER_AGENT, ua);
        }
        builder.body(()).map_err(|_| CurlError::OutOfMemory)
    }

    /// Snapshot the delegatable query answers from `next` before it is moved
    /// into the spawned connection task (see [`CachedQueries`]).
    fn cache_queries_from_next(&mut self) {
        let Some(next) = self.state.next.as_ref() else {
            return;
        };
        if let Ok(CfQueryResult::RemoteAddr(addr)) = next.query(CfQuery::RemoteAddr) {
            self.cached.remote_addr = addr;
        }
        if let Ok(CfQueryResult::IpInfo { is_ipv6, quadruple }) = next.query(CfQuery::IpInfo) {
            self.cached.ip_info = Some((is_ipv6, quadruple));
        }
        if let Ok(CfQueryResult::Transport(t)) = next.query(CfQuery::Transport) {
            self.cached.transport = Some(t);
        }
        if let Ok(CfQueryResult::Socket(s)) = next.query(CfQuery::Socket) {
            self.cached.socket = Some(s);
        }
    }

    /// Open a fresh CONNECT stream and send the request (← `submit_CONNECT`
    /// L744 / `proxy_h2_submit` L688). Returns the [`ResponseFuture`] to await
    /// and moves the tunnel to [`H2TunnelState::Connect`].
    async fn submit_connect(&mut self) -> Result<ResponseFuture> {
        let req = self.build_connect_request()?;
        let send_req = self.send_req.as_mut().ok_or(CurlError::FailedInit)?;
        // Wait until the client can open a new stream (HTTP/2 stream-concurrency
        // / connection readiness).
        std::future::poll_fn(|cx| send_req.poll_ready(cx))
            .await
            .map_err(|e| h2_to_curl(&e))?;
        let (resp_fut, send_stream) = send_req
            .send_request(req, false)
            .map_err(|e| h2_to_curl(&e))?;
        self.tunnel.send_stream = Some(send_stream);
        self.tunnel.state = H2TunnelState::Connect;
        infof(
            self.verbose,
            &format!("Establish HTTP/2 proxy tunnel to {}", self.tunnel.authority),
        );
        Ok(resp_fut)
    }

    /// Await and inspect the CONNECT response (← `inspect_response` L776 /
    /// `proxy_h2_on_header` L529).
    ///
    /// * `2xx` ⇒ take the response body's [`RecvStream`], move to
    ///   [`H2TunnelState::Established`], return [`InspectOutcome::Established`].
    /// * `407` with a usable follow-up scheme ⇒ stage the new
    ///   `Proxy-Authorization`, reset to [`H2TunnelState::Init`], return
    ///   [`InspectOutcome::Retry`].
    /// * otherwise ⇒ [`H2TunnelState::Failed`] + [`CurlError::RecvError`].
    async fn inspect_response(
        &mut self,
        resp_fut: ResponseFuture,
        data: &mut FilterData,
    ) -> Result<InspectOutcome> {
        let resp = resp_fut.await.map_err(|e| h2_to_curl(&e))?;
        let status = resp.status().as_u16();
        self.tunnel.status = status;
        self.tunnel.state = H2TunnelState::Response;

        // Surface the CONNECT response headers as verbose info traces (the
        // header-callback semantics of `proxy_h2_on_header`).
        for (name, value) in resp.headers() {
            infof(
                self.verbose,
                &format!(
                    "< {}: {}",
                    name.as_str(),
                    value.to_str().unwrap_or("<binary>")
                ),
            );
        }

        let (parts, recv_stream) = resp.into_parts();

        // 2xx → tunnel established.
        if (200..300).contains(&status) {
            infof(
                self.verbose,
                &format!("CONNECT tunnel established, response {status}"),
            );
            self.tunnel.recv_stream = Some(recv_stream);
            self.tunnel.state = H2TunnelState::Established;
            return Ok(InspectOutcome::Established);
        }

        // 407 → process Proxy-Authenticate and, if a usable scheme is found,
        // retry with a fresh CONNECT stream (← L799-808 re-INIT).
        if status == 407 {
            if let Some(authz) = self.process_proxy_auth(&parts.headers)? {
                self.proxy_authz = Some(authz);
                self.tunnel.state = H2TunnelState::Init;
                return Ok(InspectOutcome::Retry);
            }
        }

        // non-2xx, no follow-up available → fail.
        self.tunnel.state = H2TunnelState::Failed;
        failf(
            &mut data.error_buffer,
            &format!("Received HTTP code {status} from proxy after CONNECT"),
        );
        Err(CurlError::RecvError)
    }

    /// Process a 407 `Proxy-Authenticate` challenge set and produce the next
    /// `Proxy-Authorization` value, or `None` when no usable follow-up exists
    /// (← `Curl_http_input_auth` via `inspect_response`).
    ///
    /// Basic and Digest are generated here directly (they need no
    /// connection-bound multi-round state); NTLM / Negotiate availability is
    /// recorded but, lacking the connection-bound handshake state at this layer,
    /// is failed gracefully (returns `None`), matching curl when those schemes
    /// cannot be driven.
    fn process_proxy_auth(&mut self, headers: &HeaderMap) -> Result<Option<String>> {
        // Parse every Proxy-Authenticate header value, accumulating challenges
        // and updating `auth_state.avail`.
        let mut challenges: Vec<AuthChallenge> = Vec::new();
        for value in headers.get_all(http::header::PROXY_AUTHENTICATE).iter() {
            if let Ok(v) = value.to_str() {
                let parsed = parse_auth_header(&mut self.auth_state, v);
                challenges.extend(parsed.challenges);
            }
        }
        if challenges.is_empty() {
            return Ok(None);
        }

        // Pick a single scheme among those wanted, available, and permitted for
        // a proxy (Bearer is never a proxy method).
        let mask = proxy_auth_mask(self.auth_mask);
        if !pick_one_auth(&mut self.auth_state, mask) {
            return Ok(None);
        }
        let picked = self.auth_state.picked;

        if picked == CURLAUTH_BASIC {
            // Basic carries no challenge; if we already sent it and it was
            // rejected, there is nothing new to try.
            if self.auth_tried & CURLAUTH_BASIC != 0 {
                return Ok(None);
            }
            self.auth_tried |= CURLAUTH_BASIC;
            let user = self.proxy.user.as_deref().unwrap_or("");
            let passwd = self.proxy.passwd.as_deref().unwrap_or("");
            let line = basic::http_basic_header(user, passwd, true)?;
            return Ok(Some(header_value_of(&line)));
        }

        if picked == CURLAUTH_DIGEST {
            let Some(chlg) = challenges.iter().find(|c| c.method == CURLAUTH_DIGEST) else {
                return Ok(None);
            };
            let mut dd = digest::DigestData::new();
            digest::decode_digest_http_message(chlg.params.as_bytes(), &mut dd)?;
            let user = self.proxy.user.clone().unwrap_or_default();
            let passwd = self.proxy.passwd.clone().unwrap_or_default();
            // For a CONNECT, the request method is "CONNECT" and the digest URI
            // is the tunnel authority.
            let msg = digest::create_digest_http_message(
                &mut dd,
                user.as_bytes(),
                passwd.as_bytes(),
                b"CONNECT",
                self.tunnel.authority.as_bytes(),
            )?;
            self.auth_tried |= CURLAUTH_DIGEST;
            let value = format!("Digest {}", String::from_utf8_lossy(&msg));
            return Ok(Some(value));
        }

        // NTLM / Negotiate need connection-bound multi-round state not driven at
        // this filter layer → fail gracefully.
        Ok(None)
    }

    /// The inner connect driver (← `cf_h2_proxy_connect` L964 + `H2_CONNECT`
    /// L817), wrapped by [`ConnectionFilter::connect`] in the overall timeout.
    ///
    /// Order: bring `next` up (connect + TLS to the proxy), snapshot its query
    /// answers, move it into the `h2` handshake, spawn the connection task, then
    /// run the submit → inspect loop (with 407 multi-pass) to
    /// [`H2TunnelState::Established`].
    async fn do_connect_inner(&mut self, data: &mut FilterData) -> Result<()> {
        // 1. Connect the transport below FIRST (C: `cf->next->cft->do_connect`).
        {
            let next = self.state.next.as_mut().ok_or(CurlError::FailedInit)?;
            next.connect(data).await?;
        }

        // Snapshot delegatable query answers before `next` is moved away.
        self.cache_queries_from_next();

        // 2. Move `next` into the `h2` handshake and spawn the connection task
        //    (← `proxy_h2_client_new` L237).
        let next = self.state.next.take().ok_or(CurlError::FailedInit)?;
        let io = FilterIo::new(next);
        let mut builder = Builder::new();
        builder
            .initial_window_size(H2_TUNNEL_WINDOW_SIZE as u32)
            .initial_connection_window_size(PROXY_HTTP2_HUGE_WINDOW_SIZE as u32)
            .enable_push(false);
        let (send_req, connection) = builder
            .handshake::<FilterIo, Bytes>(io)
            .await
            .map_err(|e| h2_to_curl(&e))?;
        // The connection future drives all frame I/O for the connection's
        // lifetime; it must be polled, so spawn it (C: the ingress/egress pumps).
        self.conn_task = Some(tokio::spawn(async move {
            let _ = connection.await;
        }));
        self.send_req = Some(send_req);

        // 3 + 4. Submit CONNECT and inspect, looping over 407 multi-pass auth.
        self.tunnel.state = H2TunnelState::Init;
        let mut attempts = 0u32;
        loop {
            attempts += 1;
            if attempts > MAX_CONNECT_ATTEMPTS {
                self.tunnel.state = H2TunnelState::Failed;
                failf(
                    &mut data.error_buffer,
                    "Proxy CONNECT aborted: too many authentication attempts",
                );
                return Err(CurlError::RecvError);
            }
            let resp_fut = self.submit_connect().await?;
            match self.inspect_response(resp_fut, data).await? {
                InspectOutcome::Established => break,
                InspectOutcome::Retry => continue,
            }
        }

        self.state.connected = true;
        Ok(())
    }

    /// Drain the tunnel `sendbuf` into the CONNECT stream, honoring HTTP/2 flow
    /// control (← `proxy_h2_progress_egress` + the nghttp2 `DEFERRED` data
    /// source). This is the **awaiting** egress pump: for each staged chunk it
    /// reserves capacity and `poll_capacity().await`s until the peer's window
    /// permits a write, then sends `min(window, chunk)`. Awaiting (rather than
    /// returning early) is the async equivalent of curl's "leave it staged and
    /// resume on the next socket-writable" loop: it applies real backpressure
    /// (it suspends while the window is closed) without ever deadlocking, since
    /// [`h2::SendStream::poll_capacity`] yields `Pending` (never `Ready(Ok(0))`)
    /// while the window is zero and the spawned connection task supplies the
    /// `WINDOW_UPDATE` that wakes it.
    ///
    /// Returns once `sendbuf` is empty (all staged bytes handed to the stream).
    async fn drain_sendbuf(&mut self) -> Result<()> {
        if self.tunnel.send_stream.is_none() {
            return Ok(());
        }
        while !self.tunnel.sendbuf.is_empty() {
            // Hint the desired capacity for what remains, so the peer is asked
            // for enough window to flush the staged data.
            let want = self.tunnel.sendbuf.len();
            if let Some(ss) = self.tunnel.send_stream.as_mut() {
                ss.reserve_capacity(want);
            }
            // Await granted send capacity (`Pending` while the window is zero).
            let granted = {
                let ss = match self.tunnel.send_stream.as_mut() {
                    Some(s) => s,
                    None => return Ok(()),
                };
                std::future::poll_fn(|cx| ss.poll_capacity(cx)).await
            };
            let cap = match granted {
                Some(Ok(c)) => c,
                Some(Err(e)) => return Err(h2_to_curl(&e)),
                None => {
                    // The stream can no longer accept data (closed/reset).
                    self.tunnel.closed = true;
                    return Ok(());
                }
            };
            // Copy a window-sized chunk out of `sendbuf` (releasing the peek
            // borrow before the mutable `send_data`), then send and consume it.
            let chunk: Bytes = match self.tunnel.sendbuf.peek() {
                Some(c) if !c.is_empty() => {
                    let n = cap.min(c.len());
                    Bytes::copy_from_slice(&c[..n])
                }
                _ => return Ok(()),
            };
            let n = chunk.len();
            if let Some(ss) = self.tunnel.send_stream.as_mut() {
                ss.send_data(chunk, false).map_err(|e| h2_to_curl(&e))?;
            }
            self.tunnel.sendbuf.skip(n);
        }
        Ok(())
    }

    /// Best-effort, **non-awaiting** flush of staged egress (used by the
    /// synchronous [`cntrl`](ConnectionFilter::cntrl) `CF_CTRL_FLUSH` and
    /// [`shutdown`](ConnectionFilter::shutdown) paths, which cannot `await`).
    ///
    /// `h2`'s [`SendStream::send_data`] buffers internally and implicitly
    /// requests capacity, so handing the staged bytes to the stream here is a
    /// correct flush hint: the spawned connection task transmits them as the
    /// window opens. Any error simply stops the flush (the real error surfaces
    /// on the next awaited send/recv).
    fn flush_buffered(&mut self) {
        if self.tunnel.send_stream.is_none() {
            return;
        }
        loop {
            let chunk: Bytes = match self.tunnel.sendbuf.peek() {
                Some(c) if !c.is_empty() => Bytes::copy_from_slice(c),
                _ => return,
            };
            let n = chunk.len();
            match self.tunnel.send_stream.as_mut() {
                Some(ss) => {
                    if ss.send_data(chunk, false).is_err() {
                        return;
                    }
                }
                None => return,
            }
            self.tunnel.sendbuf.skip(n);
        }
    }

    /// Release `n` bytes of receive flow-control capacity on the CONNECT stream
    /// (← `nghttp2_session_consume`, cf-h2-proxy.c L1228). **Essential**: the
    /// 10 MB tunnel window only refills as consumed bytes are released, so
    /// omitting this stalls the tunnel.
    fn release_recv_capacity(&mut self, n: usize) -> Result<()> {
        if n == 0 {
            return Ok(());
        }
        if let Some(rs) = self.tunnel.recv_stream.as_mut() {
            rs.flow_control()
                .release_capacity(n)
                .map_err(|e| h2_to_curl(&e))?;
        }
        Ok(())
    }

    /// The tunnel send path (← `cf_h2_proxy_send` L1247). Stages `buf` into the
    /// `sendbuf`, pumps egress, and returns the number of bytes accepted from
    /// the caller; a full `sendbuf` maps to [`CurlError::Again`] backpressure.
    async fn do_send(&mut self, buf: &[u8]) -> Result<usize> {
        if self.tunnel.state != H2TunnelState::Established {
            return Err(CurlError::SendError);
        }
        if self.tunnel.closed {
            return Err(CurlError::SendError);
        }
        let staged = match self.tunnel.sendbuf.write(buf) {
            Ok(n) => n,
            Err(CurlError::Again) => 0,
            Err(e) => return Err(e),
        };
        // A full `sendbuf` (nothing accepted) is the real backpressure signal.
        if staged == 0 {
            return Err(CurlError::Again);
        }
        // Flush the staged bytes through the stream, awaiting flow-control
        // capacity. The connection task transmits them once the window allows.
        self.drain_sendbuf().await?;
        Ok(staged)
    }

    /// The tunnel receive path (← `cf_h2_proxy_recv` L1201). Serves staged bytes
    /// first; otherwise pulls one `DATA` chunk from the CONNECT stream. In all
    /// cases it **releases** flow-control capacity for the bytes handed to the
    /// caller, and pumps egress (curl pumps egress from `cf_recv` too). `0`
    /// means the tunnel stream reached EOF.
    async fn do_recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.tunnel.state != H2TunnelState::Established {
            return Err(CurlError::RecvError);
        }
        // Pump any buffered egress (C: `proxy_h2_progress_egress` in cf_recv).
        // Errors here are non-fatal to the receive path; the real error (if
        // any) surfaces below from the receive stream itself.
        let _ = self.drain_sendbuf().await;

        // 1. Serve from the receive staging buffer if it holds anything.
        if !self.tunnel.recvbuf.is_empty() {
            let n = self.tunnel.recvbuf.read(buf)?;
            self.release_recv_capacity(n)?;
            return Ok(n);
        }
        // 2. Already at EOF, or a zero-length read request.
        if self.tunnel.closed {
            return Ok(0);
        }
        if buf.is_empty() {
            return Ok(0);
        }

        // 3. Pull the next DATA chunk from the CONNECT stream. Skip empty DATA
        //    frames; `None` is the stream's end (EOF).
        loop {
            let chunk = {
                let rs = match self.tunnel.recv_stream.as_mut() {
                    Some(r) => r,
                    None => return Err(CurlError::RecvError),
                };
                match rs.data().await {
                    Some(Ok(b)) => b,
                    Some(Err(e)) => return Err(h2_to_curl(&e)),
                    None => {
                        self.tunnel.closed = true;
                        return Ok(0);
                    }
                }
            };
            if chunk.is_empty() {
                // Empty DATA frame: nothing to stage; keep pulling.
                continue;
            }
            // Stage the chunk, then read out into the caller's buffer. The
            // recvbuf is sized to the 10 MB window and was empty here, so the
            // chunk fits; any partial write is tolerated by looping.
            let mut off = 0usize;
            while off < chunk.len() {
                match self.tunnel.recvbuf.write(&chunk[off..]) {
                    Ok(0) => break,
                    Ok(w) => off += w,
                    Err(CurlError::Again) => break,
                    Err(e) => return Err(e),
                }
            }
            let n = self.tunnel.recvbuf.read(buf)?;
            self.release_recv_capacity(n)?;
            return Ok(n);
        }
    }

    /// Delegate a query to `next` (the C default), answering
    /// [`CurlError::UnknownOption`] at the bottom of the chain. Once `next` has
    /// been moved into the connection task this returns `UnknownOption` for any
    /// non-cached query, matching the C bottom-of-chain behavior.
    fn delegate_query(&self, query: CfQuery) -> Result<CfQueryResult> {
        match self.state.next.as_ref() {
            Some(next) => next.query(query),
            None => Err(CurlError::UnknownOption),
        }
    }
}

// =============================================================================
// PHASE 7 — the `ConnectionFilter` implementation (← `Curl_cft_h2_proxy` L1461)
// =============================================================================

impl ConnectionFilter for CfH2Proxy {
    fn name(&self) -> &'static str {
        // C: `Curl_cft_h2_proxy.name` (cf-h2-proxy.c L1462).
        CF_NAME
    }

    fn cf_state(&self) -> &CfState {
        &self.state
    }

    fn cf_state_mut(&mut self) -> &mut CfState {
        &mut self.state
    }

    fn flags(&self) -> u32 {
        // C: `CF_TYPE_IP_CONNECT | CF_TYPE_PROXY` (cf-h2-proxy.c L1463).
        CF_TYPE_IP_CONNECT | CF_TYPE_PROXY
    }

    /// Establish the tunnel (← `cf_h2_proxy_connect` L964), bounded by the
    /// overall connect timeout (→ [`CurlError::OperationTimedout`]).
    fn connect<'a>(&'a mut self, data: &'a mut FilterData) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Fast path: already established.
            if self.state.connected {
                return Ok(());
            }
            let dur = Duration::from_millis(self.connect_timeout_ms);
            // Scope the timeout future so its borrow of `self`/`data` is released
            // before the error arm touches them again.
            let res = {
                let fut = self.do_connect_inner(data);
                tokio::time::timeout(dur, fut).await
            };
            match res {
                Ok(inner) => inner,
                Err(_elapsed) => {
                    self.tunnel.state = H2TunnelState::Failed;
                    failf(&mut data.error_buffer, "Proxy CONNECT operation timed out");
                    Err(CurlError::OperationTimedout)
                }
            }
        })
    }

    /// Tear down the filter (← `cf_h2_proxy_close` L1045 region): drop the
    /// streams, abort the connection task (which drops the moved-in `next`), and
    /// — if `next` was never moved — close it directly.
    fn close(&mut self) {
        self.state.connected = false;
        self.tunnel.closed = true;
        self.tunnel.state = H2TunnelState::Failed;
        self.tunnel.send_stream = None;
        self.tunnel.recv_stream = None;
        self.send_req = None;
        if let Some(h) = self.conn_task.take() {
            h.abort();
        }
        if let Some(next) = self.state.next.as_mut() {
            next.close();
        }
    }

    /// Gracefully shut down the tunnel (← `cf_h2_proxy_shutdown` L1045): flush
    /// staged egress and half-close the CONNECT stream with an END_STREAM `DATA`
    /// frame (the async analog of curl's GOAWAY + drain). The connection task is
    /// torn down by [`close`](Self::close) / `Drop`.
    fn shutdown<'a>(&'a mut self) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if !self.state.connected || self.state.shutdown || self.tunnel.closed {
                self.state.shutdown = true;
                return Ok(());
            }
            self.flush_buffered();
            if let Some(ss) = self.tunnel.send_stream.as_mut() {
                ss.reserve_capacity(0);
                let _ = ss.send_data(Bytes::new(), true);
            }
            self.state.shutdown = true;
            Ok(())
        })
    }

    /// Whether buffered inbound tunnel data is ready (← `cf_h2_proxy_data_pending`
    /// L1113): the staged `recvbuf` (when established), else delegate to `next`.
    fn data_pending(&self) -> bool {
        if self.tunnel.state == H2TunnelState::Established && !self.tunnel.recvbuf.is_empty() {
            return true;
        }
        match self.state.next.as_ref() {
            Some(next) => next.data_pending(),
            None => false,
        }
    }

    /// Send tunneled bytes (← `cf_h2_proxy_send` L1247). Real implementation —
    /// the tunnel is **not** transparent.
    fn send<'a>(&'a mut self, buf: &'a [u8], _eos: bool) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move { self.do_send(buf).await })
    }

    /// Receive tunneled bytes (← `cf_h2_proxy_recv` L1201). Real implementation,
    /// releasing flow-control capacity as data is consumed.
    fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move { self.do_recv(buf).await })
    }

    /// Handle a control event (← `cf_h2_proxy_cntrl` L1439): only
    /// [`CF_CTRL_FLUSH`] is acted on, pumping buffered egress.
    fn cntrl(&mut self, event: i32, _arg1: i32) -> Result<()> {
        if event == CF_CTRL_FLUSH {
            // Synchronous path: hand staged egress to the stream (`h2` buffers
            // it and the connection task flushes it as the window opens).
            self.flush_buffered();
        }
        Ok(())
    }

    /// Connection liveness (← `cf_h2_proxy_is_alive`): alive while the
    /// connection task runs, the tunnel is established, and not closed;
    /// `input_pending` reflects staged receive data.
    fn is_alive(&mut self) -> (bool, bool) {
        let task_alive = self.conn_task.as_ref().is_some_and(|h| !h.is_finished());
        let alive =
            task_alive && !self.tunnel.closed && self.tunnel.state == H2TunnelState::Established;
        let input_pending = !self.tunnel.recvbuf.is_empty();
        (alive, input_pending)
    }

    /// Answer a query (← `cf_h2_proxy_query` L1405).
    ///
    /// `HOST_PORT` reports the **proxy's** own host/port (not the tunnel
    /// target), `NEED_FLUSH` reflects buffered egress, and `ALPN_NEGOTIATED` is
    /// `None` (the tunnel does not expose ALPN to the layer above — that comes
    /// from the TLS filter stacked on top). Other queries are answered from the
    /// snapshot captured before `next` was moved away, else delegated.
    fn query(&self, query: CfQuery) -> Result<CfQueryResult> {
        match query {
            CfQuery::HostPort => Ok(CfQueryResult::HostPort {
                host: self.proxy_host.clone(),
                port: self.proxy_port,
            }),
            CfQuery::NeedFlush => {
                // C: report `true` when staged egress remains; otherwise fall
                // through to the lower filter (cf-h2-proxy.c L1416-L1424). After
                // connect, `next` has been moved into the connection task, so the
                // fall-through resolves to "nothing more to flush" (`false`).
                if self.tunnel.needs_flush() {
                    Ok(CfQueryResult::NeedFlush(true))
                } else {
                    match self.state.next.as_ref() {
                        Some(next) => next.query(CfQuery::NeedFlush),
                        None => Ok(CfQueryResult::NeedFlush(false)),
                    }
                }
            }
            CfQuery::AlpnNegotiated => Ok(CfQueryResult::AlpnNegotiated(None)),
            CfQuery::RemoteAddr => match self.cached.remote_addr {
                Some(_) => Ok(CfQueryResult::RemoteAddr(self.cached.remote_addr)),
                None => self.delegate_query(query),
            },
            CfQuery::IpInfo => match &self.cached.ip_info {
                Some((is_ipv6, quad)) => Ok(CfQueryResult::IpInfo {
                    is_ipv6: *is_ipv6,
                    quadruple: quad.clone(),
                }),
                None => self.delegate_query(query),
            },
            CfQuery::Transport => match self.cached.transport {
                Some(t) => Ok(CfQueryResult::Transport(t)),
                None => self.delegate_query(query),
            },
            CfQuery::Socket => match self.cached.socket {
                Some(s) => Ok(CfQueryResult::Socket(s)),
                None => self.delegate_query(query),
            },
            other => self.delegate_query(other),
        }
    }

    // C's `cf_h2_proxy_adjust_pollset` slot has no analog under Tokio (the
    // reactor supplies readiness) and is intentionally omitted. `keep_alive`
    // uses the trait's pass-through default (C: `Curl_cf_def_conn_keep_alive`).
}

// C's `cf_h2_proxy_destroy` (→ `cf_h2_proxy_ctx_free`) maps onto `Drop`: the
// streams and buffers free themselves, and the spawned connection task is
// aborted so its owned `next` (and the proxy socket) is released.
impl Drop for CfH2Proxy {
    fn drop(&mut self) {
        if let Some(h) = self.conn_task.take() {
            h.abort();
        }
    }
}

// =============================================================================
// PHASE 8 — constructors (← `Curl_cf_h2_proxy_insert_after` L1479)
// =============================================================================

/// Create an HTTP/2 `CONNECT`-tunnel filter (C: the `ctx` allocation in
/// `Curl_cf_h2_proxy_insert_after`).
///
/// The returned filter is **unlinked** (no `next`); the chain machinery links
/// it when it is added ([`FilterChain::add_filter`]) or spliced
/// ([`h2_proxy_insert_after`]). The configuration the C code reads from the
/// easy handle / connection at connect time is captured here instead:
///
/// * `tunnel_host` / `tunnel_port` — the origin server to reach through the
///   proxy (the CONNECT `:authority`; C: `Curl_http_proxy_get_destination`).
/// * `proxy` — the parsed proxy configuration (its own host/port for
///   `CF_QUERY_HOST_PORT`, and the credentials for `Proxy-Authorization`).
/// * `auth_mask` — the `CURLOPT_PROXYAUTH` `CURLAUTH_*` bitmask.
/// * `user_agent` — the `CURLOPT_USERAGENT` value to forward on the CONNECT,
///   if any.
/// * `verbose` — mirrors `data->set.verbose` for trace output.
///
/// An initial Basic `Proxy-Authorization` is seeded when `auth_mask` permits it
/// and the proxy carries credentials (C: `Curl_http_output_auth` on the first
/// CONNECT).
#[must_use]
pub fn create_h2_proxy_filter(
    tunnel_host: String,
    tunnel_port: u16,
    proxy: Proxy,
    auth_mask: u32,
    user_agent: Option<String>,
    verbose: bool,
) -> Box<dyn ConnectionFilter> {
    let authority = CfH2Proxy::build_authority(&tunnel_host, tunnel_port);
    // Seed the initial Proxy-Authorization (Basic) when applicable; `proxy_auth`
    // returns a full header line, of which we keep only the value.
    let proxy_authz = proxy
        .proxy_auth(auth_mask)
        .ok()
        .flatten()
        .map(|line| header_value_of(&line));
    let auth_tried = if proxy_authz.is_some() {
        CURLAUTH_BASIC
    } else {
        0
    };
    let proxy_host = proxy.host.clone();
    let proxy_port = proxy.port;

    // Seed the proxy auth state. `want` is the proxy-permitted mask (Bearer is
    // never a proxy scheme). `picked` starts at NONE — nothing has been sent
    // yet — so the first `407` Basic challenge is *recorded* rather than
    // mistaken for an already-sent, rejected credential (curl seeds
    // `data->state.authproxy.picked` to 0 before the first request, and
    // `pick_one_auth` sets it once a scheme is chosen).
    let mut auth_state = AuthState::new(proxy_auth_mask(auth_mask));
    auth_state.picked = CURLAUTH_NONE;

    Box::new(CfH2Proxy {
        state: CfState::new(),
        proxy_host,
        proxy_port,
        proxy,
        auth_mask,
        auth_state,
        auth_tried,
        proxy_authz,
        user_agent,
        send_req: None,
        conn_task: None,
        tunnel: TunnelStream::new(authority),
        cached: CachedQueries::default(),
        verbose,
        connect_timeout_ms: PROXY_TIMEOUT,
    })
}

/// Create an HTTP/2 `CONNECT`-tunnel filter and splice it into `chain`
/// immediately after the filter at `after_index` (C:
/// `Curl_cf_h2_proxy_insert_after`, cf-h2-proxy.c L1479).
///
/// `after_index` is the position of the filter the tunnel must sit directly
/// above — in curl this is the (TLS-wrapped) transport to the proxy. Returns
/// [`CurlError::BadFunctionArgument`] if no filter exists at `after_index`
/// (propagated from [`FilterChain::insert_after_index`]).
#[allow(clippy::too_many_arguments)]
pub fn h2_proxy_insert_after(
    chain: &mut FilterChain,
    after_index: usize,
    tunnel_host: String,
    tunnel_port: u16,
    proxy: Proxy,
    auth_mask: u32,
    user_agent: Option<String>,
    verbose: bool,
) -> Result<()> {
    let cf = create_h2_proxy_filter(
        tunnel_host,
        tunnel_port,
        proxy,
        auth_mask,
        user_agent,
        verbose,
    );
    chain.insert_after_index(after_index, cf)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::{
        BoxFuture, CfQuery, CfQueryResult, CfState, ConnectionFilter, FilterData,
    };
    use crate::error::{CurlError, Result};
    use crate::proxy::CurlProxyType;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    /// Drive a future to completion on a fresh current-thread runtime with all
    /// drivers enabled (timers for the connect timeout; the task system for the
    /// spawned `h2` connection/server tasks; the in-memory duplex needs no
    /// reactor). Mirrors the helper used by the sibling `filters`/`haproxy`
    /// tests.
    fn run<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build test runtime")
            .block_on(fut)
    }

    /// Build a representative HTTP/2 proxy configuration. The proxy's own
    /// host/port (`proxy.example:8080`) is what `CF_QUERY_HOST_PORT` must
    /// report; the optional credentials drive the `Proxy-Authorization` path.
    fn test_proxy(user: Option<&str>, passwd: Option<&str>, ptype: CurlProxyType) -> Proxy {
        Proxy {
            proxytype: ptype,
            host: "proxy.example".to_string(),
            port: 8080,
            user: user.map(str::to_string),
            passwd: passwd.map(str::to_string),
            proxy_url: None,
            tls: None,
            unix_socket_path: None,
        }
    }

    /// Construct a [`CfH2Proxy`] wired over `next` for tests (the struct fields
    /// are private, but the test module is a child of the defining module). The
    /// tunnel target is `origin.example:443`; `proxy_authz` is left unset so the
    /// first CONNECT is unauthenticated (exercising the 407 multi-pass when the
    /// server requires auth).
    fn make_cf(next: Box<dyn ConnectionFilter>, proxy: Proxy, auth_mask: u32) -> CfH2Proxy {
        let authority = CfH2Proxy::build_authority("origin.example", 443);
        let proxy_host = proxy.host.clone();
        let proxy_port = proxy.port;
        let mut auth_state = AuthState::new(proxy_auth_mask(auth_mask));
        auth_state.picked = CURLAUTH_NONE;
        CfH2Proxy {
            state: CfState::with_next(next),
            proxy_host,
            proxy_port,
            proxy,
            auth_mask,
            auth_state,
            auth_tried: 0,
            proxy_authz: None,
            user_agent: None,
            send_req: None,
            conn_task: None,
            tunnel: TunnelStream::new(authority),
            cached: CachedQueries::default(),
            verbose: false,
            connect_timeout_ms: 10_000,
        }
    }

    /// A leaf transport mock backed by an in-memory [`DuplexStream`]: its
    /// `send`/`recv` read and write the duplex (the other half is driven by the
    /// mock `h2` proxy server), and it answers [`CfQuery::RemoteAddr`] with a
    /// fixed address so the snapshot-before-move caching can be verified. Its
    /// `connect` uses the trait default (which marks it connected, as it has no
    /// `next`).
    struct MockTransport {
        state: CfState,
        io: DuplexStream,
        remote: Option<SocketAddr>,
    }

    impl MockTransport {
        fn new(io: DuplexStream, remote: Option<SocketAddr>) -> Self {
            Self {
                state: CfState::new(),
                io,
                remote,
            }
        }
    }

    impl ConnectionFilter for MockTransport {
        fn name(&self) -> &'static str {
            "MOCK-DUPLEX"
        }
        fn cf_state(&self) -> &CfState {
            &self.state
        }
        fn cf_state_mut(&mut self) -> &mut CfState {
            &mut self.state
        }
        fn send<'a>(&'a mut self, buf: &'a [u8], _eos: bool) -> BoxFuture<'a, Result<usize>> {
            Box::pin(async move {
                match self.io.write(buf).await {
                    Ok(0) => Err(CurlError::SendError),
                    Ok(n) => Ok(n),
                    Err(_) => Err(CurlError::SendError),
                }
            })
        }
        fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize>> {
            Box::pin(async move {
                match self.io.read(buf).await {
                    Ok(n) => Ok(n),
                    Err(_) => Err(CurlError::RecvError),
                }
            })
        }
        fn query(&self, query: CfQuery) -> Result<CfQueryResult> {
            match query {
                CfQuery::RemoteAddr => Ok(CfQueryResult::RemoteAddr(self.remote)),
                _ => Err(CurlError::UnknownOption),
            }
        }
    }

    /// A minimal mock HTTP/2 forward proxy over the server half of a duplex.
    ///
    /// Accepts a single `CONNECT` stream and, when `require_auth` is set, first
    /// answers `407 Proxy-Authenticate: Basic` and waits for a re-issued
    /// `CONNECT` carrying `Proxy-Authorization`. Once accepted it replies `200`
    /// and echoes every tunneled `DATA` frame back on the response stream,
    /// releasing receive flow-control so the client's window refills. The
    /// connection is driven concurrently with the echo so in-flight stream I/O
    /// makes progress (the documented `h2` server pattern).
    async fn echo_proxy(server_io: DuplexStream, require_auth: bool) {
        let mut conn = match h2::server::handshake(server_io).await {
            Ok(c) => c,
            Err(_) => return,
        };
        loop {
            let (req, mut respond) = match conn.accept().await {
                Some(Ok(pair)) => pair,
                _ => return,
            };
            // Every attempt must be a CONNECT with an :authority pseudo-header.
            assert_eq!(req.method(), http::Method::CONNECT);
            assert!(req.uri().authority().is_some());

            // Challenge the first unauthenticated CONNECT when auth is required.
            if require_auth
                && !req
                    .headers()
                    .contains_key(http::header::PROXY_AUTHORIZATION)
            {
                let resp = http::Response::builder()
                    .status(407)
                    .header(http::header::PROXY_AUTHENTICATE, "Basic realm=\"test\"")
                    .body(())
                    .expect("407 response");
                // No body on the challenge; the client opens a fresh stream.
                let _ = respond.send_response(resp, true);
                continue;
            }

            let mut body = req.into_body();
            let resp = http::Response::builder()
                .status(200)
                .body(())
                .expect("200 response");
            let mut send = match respond.send_response(resp, false) {
                Ok(s) => s,
                Err(_) => return,
            };

            let echo = async move {
                while let Some(item) = body.data().await {
                    let chunk = match item {
                        Ok(c) => c,
                        Err(_) => break,
                    };
                    let n = chunk.len();
                    // Refill the client's send window as we consume its data.
                    let _ = body.flow_control().release_capacity(n);
                    if !chunk.is_empty() {
                        let _ = send.send_data(chunk, false);
                    }
                }
                // Half-close the echo stream when the client is done.
                let _ = send.send_data(Bytes::new(), true);
            };
            let drive = async {
                // Keep driving the connection so the in-flight stream progresses;
                // returns once the client closes the connection.
                while conn.accept().await.is_some() {}
            };
            tokio::join!(drive, echo);
            return;
        }
    }

    // ----------------------------- unit tests -----------------------------

    #[test]
    fn constants_match_c_oracle() {
        // cf-h2-proxy.c L46-55 — exact values.
        assert_eq!(PROXY_H2_CHUNK_SIZE, 16 * 1024);
        assert_eq!(H2_TUNNEL_WINDOW_SIZE, 10 * 1024 * 1024);
        assert_eq!(
            H2_TUNNEL_RECV_CHUNKS,
            H2_TUNNEL_WINDOW_SIZE / PROXY_H2_CHUNK_SIZE
        );
        assert_eq!(H2_TUNNEL_SEND_CHUNKS, (128 * 1024) / PROXY_H2_CHUNK_SIZE);
        assert_eq!(PROXY_H2_NW_SEND_CHUNKS, 1);
        assert_eq!(
            PROXY_H2_NW_RECV_CHUNKS,
            H2_TUNNEL_WINDOW_SIZE / PROXY_H2_CHUNK_SIZE
        );
        // The `h2` initial window is set to the 10 MB tunnel window.
        assert_eq!(H2_TUNNEL_WINDOW_SIZE as u32, 10 * 1024 * 1024);
    }

    #[test]
    fn build_authority_forms() {
        assert_eq!(
            CfH2Proxy::build_authority("example.com", 443),
            "example.com:443"
        );
        // IPv6 literals are bracketed.
        assert_eq!(CfH2Proxy::build_authority("::1", 8080), "[::1]:8080");
        // An already-bracketed literal is not double-bracketed.
        assert_eq!(CfH2Proxy::build_authority("[::1]", 8080), "[::1]:8080");
    }

    #[test]
    fn header_value_of_strips_prefix_and_crlf() {
        assert_eq!(
            header_value_of("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"),
            "Basic dXNlcjpwYXNz"
        );
        // No CRLF, value already bare after the colon.
        assert_eq!(
            header_value_of("Proxy-Authorization: Basic abc"),
            "Basic abc"
        );
    }

    #[test]
    fn name_and_flags_match_c_vtable() {
        // Curl_cft_h2_proxy: name "H2-PROXY", flags CF_TYPE_IP_CONNECT|CF_TYPE_PROXY.
        let proxy = test_proxy(None, None, CurlProxyType::Https2);
        let cf = create_h2_proxy_filter("origin.example".to_string(), 443, proxy, 0, None, false);
        assert_eq!(cf.name(), "H2-PROXY");
        assert_eq!(cf.flags(), CF_TYPE_IP_CONNECT | CF_TYPE_PROXY);
        assert!(cf.has_flag(CF_TYPE_PROXY));
        assert!(cf.has_flag(CF_TYPE_IP_CONNECT));
        // A freshly created filter is not yet connected.
        assert!(!cf.is_connected());
    }

    #[test]
    fn query_reports_proxy_hostport_no_alpn_and_no_flush() {
        let proxy = test_proxy(None, None, CurlProxyType::Https2);
        let cf = create_h2_proxy_filter("origin.example".to_string(), 443, proxy, 0, None, false);

        // HOST_PORT reports the proxy's OWN endpoint (cf-h2-proxy.c L1413).
        match cf.query(CfQuery::HostPort).expect("host_port") {
            CfQueryResult::HostPort { host, port } => {
                assert_eq!(host, "proxy.example");
                assert_eq!(port, 8080);
            }
            other => panic!("unexpected query result: {other:?}"),
        }
        // ALPN is never surfaced by the tunnel itself.
        assert!(matches!(
            cf.query(CfQuery::AlpnNegotiated).expect("alpn"),
            CfQueryResult::AlpnNegotiated(None)
        ));
        // Nothing staged ⇒ no flush needed.
        assert!(matches!(
            cf.query(CfQuery::NeedFlush).expect("need_flush"),
            CfQueryResult::NeedFlush(false)
        ));
    }

    #[test]
    fn unconnected_filter_is_not_alive_and_has_no_pending_data() {
        let proxy = test_proxy(None, None, CurlProxyType::Https2);
        let mut cf =
            create_h2_proxy_filter("origin.example".to_string(), 443, proxy, 0, None, false);
        let (alive, input_pending) = cf.is_alive();
        assert!(!alive);
        assert!(!input_pending);
        assert!(!cf.data_pending());
    }

    // -------------------------- integration tests --------------------------

    #[test]
    fn tunnel_roundtrip_through_mock_h2_proxy() {
        run(async {
            // Large duplex buffers so neither direction backs up in the test.
            let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
            let remote: SocketAddr = "203.0.113.9:8080".parse().expect("addr");
            let server = tokio::spawn(echo_proxy(server_io, false));

            let proxy = test_proxy(None, None, CurlProxyType::Https2);
            let mock = MockTransport::new(client_io, Some(remote));
            let mut cf = make_cf(Box::new(mock), proxy, 0);
            let mut data = FilterData::new();

            // Establish the HTTP/2 CONNECT tunnel (bounded so a regression fails
            // fast rather than hanging the suite).
            tokio::time::timeout(Duration::from_secs(15), cf.connect(&mut data))
                .await
                .expect("connect timed out")
                .expect("connect failed");

            // The connection task is live and the tunnel is established.
            let (alive, _pending) = cf.is_alive();
            assert!(alive, "tunnel should be alive after connect");

            // HOST_PORT is the proxy's own endpoint; ALPN is None; RemoteAddr is
            // the value snapshotted from the transport before it was moved.
            match cf.query(CfQuery::HostPort).expect("host_port") {
                CfQueryResult::HostPort { host, port } => {
                    assert_eq!(host, "proxy.example");
                    assert_eq!(port, 8080);
                }
                other => panic!("unexpected: {other:?}"),
            }
            assert!(matches!(
                cf.query(CfQuery::AlpnNegotiated).expect("alpn"),
                CfQueryResult::AlpnNegotiated(None)
            ));
            match cf.query(CfQuery::RemoteAddr).expect("remote_addr") {
                CfQueryResult::RemoteAddr(Some(addr)) => assert_eq!(addr, remote),
                other => panic!("unexpected: {other:?}"),
            }

            // Push tunneled bytes through `send`.
            let payload = b"the quick brown fox jumps over the lazy dog";
            let mut sent = 0usize;
            while sent < payload.len() {
                let res =
                    tokio::time::timeout(Duration::from_secs(15), cf.send(&payload[sent..], false))
                        .await
                        .expect("send timed out");
                match res {
                    Ok(n) => sent += n,
                    Err(CurlError::Again) => tokio::task::yield_now().await,
                    Err(e) => panic!("send error: {e:?}"),
                }
            }

            // Read them back, echoed by the proxy.
            let mut got = Vec::new();
            while got.len() < payload.len() {
                let mut buf = [0u8; 1024];
                let res = tokio::time::timeout(Duration::from_secs(15), cf.recv(&mut buf))
                    .await
                    .expect("recv timed out");
                match res {
                    Ok(0) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                    Err(CurlError::Again) => tokio::task::yield_now().await,
                    Err(e) => panic!("recv error: {e:?}"),
                }
            }
            assert_eq!(&got[..], &payload[..], "tunnel must echo the payload");

            cf.close();
            server.abort();
        });
    }

    #[test]
    fn tunnel_407_then_basic_auth_succeeds() {
        run(async {
            let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
            // The proxy requires authentication on the first CONNECT.
            let server = tokio::spawn(echo_proxy(server_io, true));

            // Credentials present + Basic permitted; the first CONNECT carries no
            // auth (make_cf leaves proxy_authz unset), so the server answers 407
            // and the multi-pass adds Basic on a fresh CONNECT stream.
            let proxy = test_proxy(Some("alice"), Some("secret"), CurlProxyType::Https2);
            let mock = MockTransport::new(client_io, None);
            let mut cf = make_cf(Box::new(mock), proxy, CURLAUTH_BASIC);
            let mut data = FilterData::new();

            tokio::time::timeout(Duration::from_secs(15), cf.connect(&mut data))
                .await
                .expect("connect timed out")
                .expect("connect failed after 407 auth");

            // The tunnel works after the auth round-trip.
            let payload = b"auth-ok-payload";
            let mut sent = 0usize;
            while sent < payload.len() {
                let res =
                    tokio::time::timeout(Duration::from_secs(15), cf.send(&payload[sent..], false))
                        .await
                        .expect("send timed out");
                match res {
                    Ok(n) => sent += n,
                    Err(CurlError::Again) => tokio::task::yield_now().await,
                    Err(e) => panic!("send error: {e:?}"),
                }
            }
            let mut got = Vec::new();
            while got.len() < payload.len() {
                let mut buf = [0u8; 256];
                let res = tokio::time::timeout(Duration::from_secs(15), cf.recv(&mut buf))
                    .await
                    .expect("recv timed out");
                match res {
                    Ok(0) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                    Err(CurlError::Again) => tokio::task::yield_now().await,
                    Err(e) => panic!("recv error: {e:?}"),
                }
            }
            assert_eq!(&got[..], &payload[..]);

            cf.close();
            server.abort();
        });
    }
}
