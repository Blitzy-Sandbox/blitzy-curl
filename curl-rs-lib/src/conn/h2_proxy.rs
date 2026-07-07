//! HTTP/2 `CONNECT` tunnel proxy filter.
//!
//! This module is the safe-Rust reimplementation of curl's HTTP/2 proxy
//! connection filter, `lib/cf-h2-proxy.c` (1504 lines) and its descriptor
//! header `lib/cf-h2-proxy.h`. In upstream curl the tunnel is driven by
//! **nghttp2**; per the migration plan (AAP §0.5.2, "nghttp2 → `h2`") this
//! rewrite drives it with the pure-Rust [`h2`] crate over the [`tokio`] async
//! runtime, **entirely in safe Rust** (the crate forbids unchecked code at the
//! crate root, so this module contains none).
//!
//! # What an HTTP/2 proxy tunnel is
//!
//! When curl must reach an origin *through* a proxy that itself speaks
//! HTTP/2, it opens a single HTTP/2 connection to the proxy and issues one
//! `CONNECT` request on one stream. The proxy replies `2xx`, after which **that
//! stream's body is the tunnel**: every application byte the transfer wishes to
//! send to the origin is written as HTTP/2 `DATA` frames on the CONNECT stream,
//! and every byte the origin returns arrives as `DATA` frames on the same
//! stream. This mirrors curl's `cf-h2-proxy.c`, where the tunnel is a single
//! `nghttp2` stream (`ctx->tunnel.stream_id`) whose send/receive buffers relay
//! the wrapped protocol.
//!
//! # State machine (preserved for `--trace` parity)
//!
//! curl models the tunnel handshake with the `h2_tunnel_state` enum
//! (`H2_TUNNEL_INIT` → `H2_TUNNEL_CONNECT` → `H2_TUNNEL_RESPONSE` →
//! `H2_TUNNEL_ESTABLISHED`, or `H2_TUNNEL_FAILED`). [`H2TunnelState`] preserves
//! those names so diagnostic output keeps the same vocabulary.
//!
//! # Flow control (the correctness crux)
//!
//! HTTP/2 is flow-controlled: a sender may only transmit as many `DATA` bytes
//! as the peer's window allows, and must wait for `WINDOW_UPDATE` frames to
//! send more. curl mirrors this through nghttp2's
//! `nghttp2_session_consume`/window APIs; here we mirror it through `h2`'s
//! [`SendStream::reserve_capacity`]/[`SendStream::poll_capacity`] on the send
//! side and [`h2::RecvStream::flow_control`] +
//! [`h2::FlowControl::release_capacity`] on the receive side. Getting this
//! right is what keeps large multi-frame transfers from deadlocking.
//!
//! # Layering
//!
//! `h2` drives its framing over a byte transport that implements
//! [`tokio::io::AsyncRead`] + [`tokio::io::AsyncWrite`]. In curl the transport
//! is the next filter down the chain (`cf->next`, typically TCP or TLS). Here
//! the connected lower transport is bridged to the async byte interface `h2`
//! needs by [`NextTransport`], and the resulting HTTP/2 connection driver runs
//! as a spawned Tokio task while the tunnel's single stream carries the
//! application bytes.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use h2::client::SendRequest;
use h2::{Reason, RecvStream, SendStream};
use http::header::PROXY_AUTHORIZATION;
use http::{HeaderValue, Method, Request, StatusCode};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

use crate::auth;
use crate::conn::filters::{
    CfFuture, ConnectionFilter, FilterChain, FilterCtx, Pollset, QueryCtx, QueryOut,
};
use crate::conn::{CfQuery, CfType};
use crate::error::{Error, Result};

// ===========================================================================
// Constants — mirror the tunable sizes in `lib/cf-h2-proxy.c`.
// ===========================================================================

/// Maximum amount of tunnel payload curl moves between its buffers in one step
/// (`PROXY_H2_CHUNK_SIZE` in `cf-h2-proxy.c`). Used to bound the size of a
/// single `DATA` frame we emit so one oversized `send` cannot monopolize the
/// stream.
const PROXY_H2_CHUNK_SIZE: usize = 16 * 1024;

/// The (large) HTTP/2 *connection-level* receive window curl advertises for the
/// proxy connection (`PROXY_HTTP2_HUGE_WINDOW_SIZE` in `cf-h2-proxy.c`,
/// 100 MiB). A generous connection window keeps a fast origin from stalling on
/// connection-level flow control while the tunnel drains.
const PROXY_HTTP2_HUGE_WINDOW_SIZE: u32 = 100 * 1024 * 1024;

/// The HTTP/2 *stream-level* receive window curl advertises for the tunnel
/// stream (`H2_TUNNEL_WINDOW_SIZE` in `cf-h2-proxy.c`, 10 MiB).
const H2_TUNNEL_WINDOW_SIZE: u32 = 10 * 1024 * 1024;

/// The stable filter name, matching curl's `cft->name` for this filter
/// (`"H2-PROXY"`), emitted verbatim in `--trace`/`-v` output.
const CF_NAME: &str = "H2-PROXY";

// ===========================================================================
// Tunnel state — preserves curl's `h2_tunnel_state` names for trace parity.
// ===========================================================================

/// The tunnel handshake state, reproducing curl's `h2_tunnel_state`
/// (`lib/cf-h2-proxy.c`).
///
/// The variant names are preserved verbatim so `--trace` diagnostics keep the
/// same vocabulary as upstream curl. The state advances monotonically through
/// the handshake and comes to rest in [`Established`](Self::Established) once
/// the proxy has accepted the `CONNECT`, or [`Failed`](Self::Failed) if it did
/// not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2TunnelState {
    /// `H2_TUNNEL_INIT` — no request submitted yet (initial state, and the
    /// state re-entered when a `407` triggers a re-issue with credentials).
    Init,
    /// `H2_TUNNEL_CONNECT` — the `CONNECT` request has been submitted and we are
    /// driving the HTTP/2 exchange awaiting the response headers.
    Connect,
    /// `H2_TUNNEL_RESPONSE` — response headers have arrived and are being
    /// inspected (status classification / proxy-auth handling).
    Response,
    /// `H2_TUNNEL_ESTABLISHED` — the proxy returned `2xx`; the CONNECT stream is
    /// now the live tunnel and application bytes may flow.
    Established,
    /// `H2_TUNNEL_FAILED` — the tunnel could not be established.
    Failed,
}

// ===========================================================================
// NextTransport — bridges the connected lower transport to the byte-stream
// interface `h2` drives its framing over.
// ===========================================================================

/// Marker for a byte transport usable as the tunnel's lower layer.
///
/// It is the set of bounds `h2` requires of the I/O object it frames over
/// ([`AsyncRead`] + [`AsyncWrite`] + [`Unpin`] + [`Send`] + `'static`), gathered
/// into one trait so the concrete transport can be stored type-erased as
/// `Box<dyn TunnelIo>` inside the (non-generic) filter. A blanket impl makes
/// every qualifying type a `TunnelIo` automatically.
pub trait TunnelIo: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> TunnelIo for T {}

pin_project! {
    /// Adapter that presents the connected lower transport (curl's `cf->next`)
    /// as the [`AsyncRead`] + [`AsyncWrite`] byte stream `h2` frames over.
    ///
    /// In curl the HTTP/2 proxy filter reads and writes the tunnel bytes with
    /// `Curl_conn_cf_recv`/`Curl_conn_cf_send` on `cf->next`, and a socket that
    /// is not ready yields `CURLE_AGAIN`. The idiomatic async equivalent is a
    /// transport whose `poll_read`/`poll_write` return [`Poll::Pending`] when
    /// no progress can be made yet, registering the task's waker so the Tokio
    /// reactor re-polls once the socket is ready. That "`CURLE_AGAIN` ⇒
    /// `Poll::Pending`" mapping is exactly what an [`AsyncRead`]/[`AsyncWrite`]
    /// transport already encodes, so this adapter is a thin, projection-safe
    /// pass-through: it exists to name the bridge seam and to keep the tunnel
    /// generic over whatever concrete lower transport the connection layer
    /// supplies (a TCP or TLS stream in production; an in-process duplex in
    /// tests).
    ///
    /// The projection is generated by [`pin_project_lite`], so the adapter
    /// forwards pinned access to the inner transport using only safe Rust.
    pub struct NextTransport<S> {
        #[pin]
        inner: S,
    }
}

impl<S> NextTransport<S> {
    /// Wraps a connected lower transport `inner`.
    pub fn new(inner: S) -> Self {
        NextTransport { inner }
    }

    /// Consumes the adapter, returning the wrapped transport.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead> AsyncRead for NextTransport<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Delegate to the inner transport; a not-ready socket naturally yields
        // `Poll::Pending` (curl's `CURLE_AGAIN`) with the waker registered.
        self.project().inner.poll_read(cx, buf)
    }
}

impl<S: AsyncWrite> AsyncWrite for NextTransport<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

// ===========================================================================
// Error mapping — h2::Error -> crate Error, preserving curl error semantics.
// ===========================================================================

/// Converts an [`h2::Error`] into the crate's [`Error`], choosing the variant
/// whose integer `CURLcode` best matches curl's behavior.
///
/// * An underlying I/O failure maps to [`Error::Io`] (whose code derives from
///   the OS error), matching curl surfacing the socket error.
/// * A protocol error carrying an HTTP/2 [`Reason`] (`RST_STREAM`/`GOAWAY`)
///   maps to [`Error::Http2Stream`] (`CURLE_HTTP2_STREAM`).
/// * Anything else maps to [`Error::Http2`] (`CURLE_HTTP2`).
fn map_h2_err(err: h2::Error) -> Error {
    if let Some(io_err) = err.get_io() {
        return Error::Io(io::Error::new(io_err.kind(), io_err.to_string()));
    }
    match err.reason() {
        Some(reason) => Error::http2_stream(format!("HTTP/2 proxy stream error: {reason:?}")),
        None => Error::http2(format!("HTTP/2 proxy error: {err}")),
    }
}

// ===========================================================================
// H2ProxyConfig — the tunnel destination and optional proxy credentials.
// ===========================================================================

/// The configuration a [`H2ProxyFilter`] needs to open a tunnel: the proxy's
/// host/port (the CONNECT `:authority`) and optional proxy credentials.
///
/// In curl this information lives on `cf->conn->http_proxy` (host, port) and
/// `data->state.aptr.proxyuserpwd` (credentials); it is gathered here into an
/// explicit value so the filter is self-contained and testable.
#[derive(Debug, Clone)]
pub struct H2ProxyConfig {
    /// The proxy host name (or IP literal) the tunnel authenticates to.
    pub host: String,
    /// The proxy port.
    pub port: u16,
    /// The proxy user name, if proxy authentication is configured.
    pub user: Option<String>,
    /// The proxy password, if proxy authentication is configured.
    pub pass: Option<String>,
}

impl H2ProxyConfig {
    /// Builds a config for an unauthenticated proxy tunnel to `host:port`.
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        H2ProxyConfig {
            host: host.into(),
            port,
            user: None,
            pass: None,
        }
    }

    /// Builds a config carrying proxy credentials for `Proxy-Authorization`.
    #[must_use]
    pub fn with_credentials(
        host: impl Into<String>,
        port: u16,
        user: Option<String>,
        pass: Option<String>,
    ) -> Self {
        H2ProxyConfig {
            host: host.into(),
            port,
            user,
            pass,
        }
    }

    /// Returns the HTTP/2 `CONNECT` `:authority` in authority-form
    /// (`host:port`), bracketing an IPv6 literal as RFC 3986 requires.
    fn authority(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            // Bare IPv6 literal — bracket it: `[::1]:8080`.
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Whether any proxy credential is present (so a `407` challenge is
    /// answerable).
    fn has_credentials(&self) -> bool {
        self.user.is_some() || self.pass.is_some()
    }
}

/// Builds the `Proxy-Authorization` header **value** for Basic proxy auth.
///
/// Delegates the encoding to the shared authenticator
/// [`crate::auth::basic::http_output_basic`] (the reimplementation of curl's
/// `lib/vauth` Basic output), which returns the full wire line
/// `"Proxy-Authorization: Basic <base64>\r\n"`. This helper strips the field
/// name and trailing CRLF to yield just the value (`"Basic <base64>"`) suitable
/// for the [`http`] header API.
fn proxy_auth_header(user: Option<&str>, pass: Option<&str>) -> Result<HeaderValue> {
    let line = auth::basic::http_output_basic(user, pass, true)?;
    let value = line
        .strip_prefix("Proxy-Authorization: ")
        .and_then(|rest| rest.strip_suffix("\r\n"))
        .ok_or_else(|| Error::proxy("auth layer produced a malformed Proxy-Authorization line"))?;
    HeaderValue::from_str(value)
        .map_err(|e| Error::proxy(format!("invalid Proxy-Authorization header value: {e}")))
}

// ===========================================================================
// H2Tunnel — the established CONNECT stream plus its connection driver.
// ===========================================================================

/// An HTTP/2 `CONNECT` tunnel: the single stream whose body relays the wrapped
/// application bytes, plus the background task driving the HTTP/2 connection.
///
/// This is the safe-Rust analog of curl's `struct cf_h2_proxy_ctx` +
/// `struct tunnel_stream` (`lib/cf-h2-proxy.c`): [`send_stream`](Self::send_stream)
/// is the outbound half (application → origin), [`recv_stream`](Self::recv_stream)
/// is the inbound half (origin → application), and [`driver`](Self::driver) is
/// the spawned [`h2`] connection future that advances framing and flow control
/// (curl advances the nghttp2 session from its event loop).
struct H2Tunnel {
    /// The outbound half of the CONNECT stream (`DATA` frames we send).
    send_stream: SendStream<Bytes>,
    /// The inbound half of the CONNECT stream (`DATA` frames we receive).
    recv_stream: RecvStream,
    /// The spawned HTTP/2 connection driver; aborted on drop.
    driver: Option<JoinHandle<()>>,
    /// Received bytes not yet copied out to a caller's `recv` buffer.
    recv_leftover: Bytes,
    /// The tunnel handshake state (preserved for `--trace` parity).
    state: H2TunnelState,
    /// Whether the outbound half has been closed (`END_STREAM` sent or reset).
    send_closed: bool,
}

impl H2Tunnel {
    /// Opens an HTTP/2 `CONNECT` tunnel to the proxy over `io`.
    ///
    /// Runs the HTTP/2 handshake with curl-equivalent large receive windows,
    /// spawns the connection driver, then issues the extended `CONNECT` and
    /// (if challenged with `407` and credentials are available) re-issues once
    /// with `Proxy-Authorization`. Returns the established tunnel on `2xx`, or
    /// [`Error::Proxy`] (`CURLcode` 97) otherwise.
    async fn establish(
        io: Box<dyn TunnelIo>,
        authority: String,
        user: Option<String>,
        pass: Option<String>,
    ) -> Result<H2Tunnel> {
        tracing::trace!(
            target: "curl::cf",
            filter = CF_NAME,
            state = ?H2TunnelState::Init,
            %authority,
            "opening HTTP/2 proxy tunnel"
        );

        // Advertise the same generous windows curl uses for the proxy
        // connection so a fast origin does not stall on our receive-side flow
        // control (PROXY_HTTP2_HUGE_WINDOW_SIZE / H2_TUNNEL_WINDOW_SIZE).
        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(H2_TUNNEL_WINDOW_SIZE)
            .initial_connection_window_size(PROXY_HTTP2_HUGE_WINDOW_SIZE);

        let (send_req, connection) = builder
            .handshake::<Box<dyn TunnelIo>, Bytes>(io)
            .await
            .map_err(map_h2_err)?;

        // Drive the HTTP/2 connection on a background task. The handle is kept
        // so the task is aborted when the tunnel is dropped (see `Drop`).
        let driver = tokio::spawn(async move {
            // Completes when the connection closes; stream errors surface to the
            // tunnel's send/recv paths, so the result is intentionally ignored.
            let _ = connection.await;
        });

        match Self::run_connect(send_req, &authority, user.as_deref(), pass.as_deref()).await {
            Ok((send_stream, recv_stream)) => Ok(H2Tunnel {
                send_stream,
                recv_stream,
                driver: Some(driver),
                recv_leftover: Bytes::new(),
                state: H2TunnelState::Established,
                send_closed: false,
            }),
            Err(e) => {
                tracing::trace!(
                    target: "curl::cf",
                    filter = CF_NAME,
                    state = ?H2TunnelState::Failed,
                    error = %e,
                    "HTTP/2 proxy tunnel failed"
                );
                // Abort the connection driver so a failed handshake leaks no task.
                driver.abort();
                Err(e)
            }
        }
    }

    /// Issues the `CONNECT` request(s) and classifies the response, returning
    /// the tunnel's send/receive halves on success.
    ///
    /// Reproduces curl's `submit_CONNECT` + `inspect_response` proxy-auth loop
    /// (`lib/cf-h2-proxy.c`): a `407` with credentials that has not yet been
    /// retried re-issues on a fresh stream carrying `Proxy-Authorization`
    /// (curl's `H2_TUNNEL_INIT` re-entry); a `2xx` establishes the tunnel; any
    /// other outcome fails with [`Error::Proxy`].
    async fn run_connect(
        mut send_req: SendRequest<Bytes>,
        authority: &str,
        user: Option<&str>,
        pass: Option<&str>,
    ) -> Result<(SendStream<Bytes>, RecvStream)> {
        let mut auth_value: Option<HeaderValue> = None;
        let mut attempted_auth = false;

        loop {
            // Build the extended CONNECT: `:method = CONNECT`, `:authority =
            // host:port`. h2 omits `:scheme`/`:path` for a CONNECT without a
            // protocol pseudo-header, matching curl's plain tunnel CONNECT.
            let mut req_builder = Request::builder().method(Method::CONNECT).uri(authority);
            if let Some(value) = &auth_value {
                req_builder = req_builder.header(PROXY_AUTHORIZATION, value.clone());
            }
            let request = req_builder
                .body(())
                .map_err(|e| Error::proxy(format!("failed to build CONNECT request: {e}")))?;

            // Wait until the client can accept a new request, then submit it
            // without END_STREAM (the stream body carries the tunnel).
            tracing::trace!(
                target: "curl::cf",
                filter = CF_NAME,
                state = ?H2TunnelState::Connect,
                authority,
                authenticated = auth_value.is_some(),
                "submitting CONNECT"
            );
            send_req = send_req.ready().await.map_err(map_h2_err)?;
            let (response_fut, send_stream) =
                send_req.send_request(request, false).map_err(map_h2_err)?;

            // Await the response headers to the CONNECT stream.
            let response = response_fut.await.map_err(map_h2_err)?;
            let (parts, recv_stream) = response.into_parts();
            let status = parts.status;
            tracing::trace!(
                target: "curl::cf",
                filter = CF_NAME,
                state = ?H2TunnelState::Response,
                status = status.as_u16(),
                "CONNECT response received"
            );

            // 2xx => the proxy accepted the tunnel; the stream body is now live.
            if status.is_success() {
                tracing::trace!(
                    target: "curl::cf",
                    filter = CF_NAME,
                    state = ?H2TunnelState::Established,
                    "proxy tunnel established"
                );
                return Ok((send_stream, recv_stream));
            }

            // 407 => proxy authentication required. Re-issue once with
            // credentials on a fresh stream (curl's proxy-auth re-issue loop).
            if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED
                && !attempted_auth
                && (user.is_some() || pass.is_some())
            {
                attempted_auth = true;
                // Cancel the rejected CONNECT stream before re-issuing.
                let mut rejected = send_stream;
                rejected.send_reset(Reason::CANCEL);
                auth_value = Some(proxy_auth_header(user, pass)?);
                continue;
            }

            // Any other status (or an unanswerable/again-407) is a hard failure.
            let mut rejected = send_stream;
            rejected.send_reset(Reason::CANCEL);
            return Err(Error::proxy(format!(
                "HTTP/2 proxy CONNECT was refused with status {}",
                status.as_u16()
            )));
        }
    }
}

impl H2Tunnel {
    /// The current tunnel handshake state (preserved for `--trace` parity).
    fn state(&self) -> H2TunnelState {
        self.state
    }

    /// Sends `buf` as `DATA` on the CONNECT stream, honoring HTTP/2 flow
    /// control, and returns the number of bytes accepted (always `buf.len()`
    /// once queued). Sets `END_STREAM` on the final frame when `eos` is set.
    ///
    /// The send is chunked at [`PROXY_H2_CHUNK_SIZE`] and gated on
    /// [`SendStream::poll_capacity`], so a payload larger than the peer's window
    /// is transmitted across multiple frames as `WINDOW_UPDATE`s arrive — the
    /// spawned connection driver processes those concurrently, so this never
    /// deadlocks (the correctness crux called out in `cf-h2-proxy.c`).
    async fn send(&mut self, buf: &[u8], eos: bool) -> Result<usize> {
        if self.send_closed {
            // The outbound half is already closed; curl returns CURLE_SEND_ERROR.
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
            // Bound a single DATA frame at curl's PROXY_H2_CHUNK_SIZE.
            let want = remaining.min(PROXY_H2_CHUNK_SIZE);
            self.send_stream.reserve_capacity(want);

            // Await flow-control capacity. The spawned driver delivers
            // WINDOW_UPDATE frames, so a multi-frame payload cannot deadlock.
            let granted = poll_fn(|cx| self.send_stream.poll_capacity(cx)).await;
            let capacity = match granted {
                Some(Ok(cap)) => cap,
                Some(Err(e)) => return Err(map_h2_err(e)),
                None => {
                    // The peer closed the stream before we finished sending.
                    self.send_closed = true;
                    return Err(Error::http2_stream("proxy tunnel send stream closed"));
                }
            };
            if capacity == 0 {
                // No capacity granted yet; loop to await more.
                continue;
            }

            let end = (offset + capacity.min(want)).min(buf.len());
            let is_last = eos && end == buf.len();
            let chunk = Bytes::copy_from_slice(&buf[offset..end]);
            self.send_stream
                .send_data(chunk, is_last)
                .map_err(map_h2_err)?;
            offset = end;
            if is_last {
                self.send_closed = true;
            }
        }

        Ok(offset)
    }

    /// Reads up to `buf.len()` tunnel bytes from the CONNECT stream, returning
    /// the number of bytes read (`0` means the tunnel reached end of stream).
    ///
    /// Pulls `DATA` frames from the stream, releasing flow-control capacity for
    /// each consumed frame (mirroring `nghttp2_session_consume`), and buffers
    /// any remainder that does not fit the caller's `buf` for the next call.
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        // Refill from the stream when we have no buffered bytes to serve.
        while self.recv_leftover.is_empty() {
            match self.recv_stream.data().await {
                Some(Ok(chunk)) => {
                    let len = chunk.len();
                    if len > 0 {
                        // Release the window for the bytes we now own (curl's
                        // nghttp2_session_consume), so the peer may send more.
                        let _ = self.recv_stream.flow_control().release_capacity(len);
                        self.recv_leftover = chunk;
                    } else if self.recv_stream.is_end_stream() {
                        return Ok(0);
                    }
                    // An empty non-final frame: loop to fetch the next one.
                }
                Some(Err(e)) => return Err(map_h2_err(e)),
                None => return Ok(0), // clean end of stream => tunnel EOF
            }
        }

        let n = self.recv_leftover.len().min(buf.len());
        buf[..n].copy_from_slice(&self.recv_leftover[..n]);
        // Drop the consumed prefix, keeping any remainder for the next recv.
        let _ = self.recv_leftover.split_to(n);
        Ok(n)
    }

    /// Gracefully shuts the tunnel down, resetting the CONNECT stream.
    ///
    /// curl submits a `GOAWAY` and resets the tunnel stream during shutdown; the
    /// single-stream analog here is a `RST_STREAM(NO_ERROR)` on the CONNECT
    /// stream. Returns `true` (shutdown is immediately complete).
    async fn shutdown(&mut self) -> Result<bool> {
        if !self.send_closed {
            self.send_stream.send_reset(Reason::NO_ERROR);
            self.send_closed = true;
        }
        Ok(true)
    }
}

impl Drop for H2Tunnel {
    fn drop(&mut self) {
        // Abort the connection driver so the background task does not outlive
        // the tunnel (the safe-Rust analog of curl freeing the nghttp2 session).
        if let Some(driver) = self.driver.take() {
            driver.abort();
        }
    }
}

// ===========================================================================
// H2ProxyFilter — the connection filter implementing `ConnectionFilter`.
// ===========================================================================

/// The HTTP/2 `CONNECT` tunnel connection filter.
///
/// This is the safe-Rust reimplementation of curl's `Curl_cft_h2_proxy`
/// (`lib/cf-h2-proxy.c`). It sits above the socket/TLS filters in a
/// [`FilterChain`]: on [`connect`](ConnectionFilter::connect) it drives the
/// lower filters to connect, then opens an HTTP/2 tunnel over the connected
/// transport and issues the `CONNECT`. Once established, its
/// [`send`](ConnectionFilter::send)/[`recv`](ConnectionFilter::recv) relay the
/// wrapped protocol's bytes over the single CONNECT stream.
pub struct H2ProxyFilter {
    /// The proxy destination and optional credentials for the `CONNECT`.
    config: H2ProxyConfig,
    /// The connected lower transport, taken during `connect` to open the
    /// tunnel; `None` after it has been consumed.
    transport: Option<Box<dyn TunnelIo>>,
    /// The established tunnel, present once `connect` has succeeded.
    tunnel: Option<H2Tunnel>,
    /// Whether this filter has completed its `connect` (curl's `cf->connected`).
    connected: bool,
}

impl H2ProxyFilter {
    /// Builds an HTTP/2 proxy filter that will tunnel over `transport`.
    ///
    /// `transport` is the connected lower layer (curl's `cf->next` socket/TLS
    /// stream; an in-process duplex in tests). It is wrapped in a
    /// [`NextTransport`] adapter so the [`h2`] client can frame over it, and
    /// stored until [`connect`](ConnectionFilter::connect) consumes it.
    #[must_use]
    pub fn new<S>(config: H2ProxyConfig, transport: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        H2ProxyFilter {
            config,
            transport: Some(Box::new(NextTransport::new(transport))),
            tunnel: None,
            connected: false,
        }
    }

    /// The tunnel handshake state, or `None` if the tunnel is not yet open.
    /// Exposed for `--trace`-style observability and for tests.
    #[must_use]
    pub fn tunnel_state(&self) -> Option<H2TunnelState> {
        self.tunnel.as_ref().map(H2Tunnel::state)
    }
}

impl ConnectionFilter for H2ProxyFilter {
    fn name(&self) -> &'static str {
        CF_NAME
    }

    fn cf_type(&self) -> CfType {
        // curl's `Curl_cft_h2_proxy` declares `CF_TYPE_IP_CONNECT | CF_TYPE_PROXY`;
        // the migration spec additionally mandates `HTTP` and `MULTIPLEX` for
        // this filter. The union honors both: the tunnel provides an
        // IP-connection equivalent (IP_CONNECT), proxies (PROXY), speaks HTTP
        // (HTTP), and rides a multiplexed HTTP/2 connection (MULTIPLEX).
        CfType::IP_CONNECT | CfType::PROXY | CfType::HTTP | CfType::MULTIPLEX
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

            // Connect the lower filters first — curl connects `cf->next` before
            // running the HTTP/2 proxy handshake.
            let lower_done = cx.connect_next(blocking).await?;
            if !lower_done {
                // Lower chain not ready yet (non-blocking connect); retry later.
                return Ok(false);
            }

            // Take the connected transport and open the tunnel over it.
            let transport = self
                .transport
                .take()
                .ok_or_else(|| Error::proxy("H2 proxy filter has no transport to tunnel over"))?;
            let authority = self.config.authority();
            let (user, pass) = if self.config.has_credentials() {
                (self.config.user.clone(), self.config.pass.clone())
            } else {
                (None, None)
            };

            let tunnel = H2Tunnel::establish(transport, authority, user, pass).await?;
            tracing::trace!(
                target: "curl::cf",
                filter = CF_NAME,
                state = ?tunnel.state(),
                "HTTP/2 proxy filter connected"
            );
            self.tunnel = Some(tunnel);
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
            match self.tunnel.as_mut() {
                Some(tunnel) => tunnel.send(buf, eos).await,
                // Not established: curl's `cf_h2_proxy_send` returns
                // CURLE_SEND_ERROR when the tunnel is not ESTABLISHED.
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
            match self.tunnel.as_mut() {
                Some(tunnel) => tunnel.recv(buf).await,
                // Not established: curl's `cf_h2_proxy_recv` returns
                // CURLE_RECV_ERROR when the tunnel is not ESTABLISHED.
                None => Err(Error::Recv),
            }
        })
    }

    fn shutdown<'a>(&'a mut self, _cx: &'a mut FilterCtx<'_>) -> CfFuture<'a, Result<bool>> {
        Box::pin(async move {
            match self.tunnel.as_mut() {
                Some(tunnel) => tunnel.shutdown().await,
                None => Ok(true),
            }
        })
    }

    fn close(&mut self, cx: &mut FilterCtx<'_>) {
        // Drop the tunnel (aborting its connection driver) and close the lower
        // chain, mirroring curl's `cf_h2_proxy_close`.
        self.tunnel = None;
        self.connected = false;
        cx.close_next();
    }

    fn data_pending(&self, cx: &QueryCtx<'_>) -> bool {
        // Buffered tunnel bytes are readable without touching the socket;
        // otherwise defer to the lower chain.
        let buffered = self
            .tunnel
            .as_ref()
            .is_some_and(|t| !t.recv_leftover.is_empty());
        buffered || cx.data_pending_next()
    }

    fn adjust_pollset(&self, cx: &QueryCtx<'_>, ps: &mut Pollset) {
        // The tunnel's socket is owned by the spawned Tokio connection driver,
        // whose readiness the runtime reactor manages; there is no descriptor to
        // register in the poll set here (curl registers `cf->next`'s socket —
        // under Tokio the reactor plays that role). Nothing to add.
        let _ = (cx, ps);
    }

    fn query(&self, cx: &QueryCtx<'_>, query: CfQuery, out: &mut QueryOut) -> Result<()> {
        // Mirror `cf_h2_proxy_query`: answer HOST_PORT, NEED_FLUSH and
        // ALPN_NEGOTIATED locally; delegate everything else down the chain.
        match query {
            CfQuery::HostPort => {
                *out = QueryOut::HostPort {
                    host: self.config.host.clone(),
                    port: self.config.port,
                };
                Ok(())
            }
            CfQuery::NeedFlush => {
                // Outbound data is written straight into the h2 stream, so the
                // filter itself never holds a backlog.
                *out = QueryOut::NeedFlush(false);
                Ok(())
            }
            CfQuery::AlpnNegotiated => {
                // curl reports a NULL ALPN for the proxy CONNECT tunnel; the
                // "answered, no value" result is `QueryOut::None`.
                *out = QueryOut::None;
                Ok(())
            }
            _ => cx.query_next(query, out),
        }
    }
}

// ===========================================================================
// Factory — `Curl_cf_h2_proxy_insert_after`.
// ===========================================================================

/// Inserts a freshly built [`H2ProxyFilter`] directly below the filter at
/// `at_index` in `chain`, the safe-Rust equivalent of curl's
/// `Curl_cf_h2_proxy_insert_after` (`lib/cf-h2-proxy.h`).
///
/// `config` supplies the proxy destination and optional credentials (curl reads
/// these from `cf->conn->http_proxy` / `data->state.aptr.proxyuserpwd`);
/// `transport` is the connected lower layer the tunnel frames over. Returns
/// [`Error::bad_argument`] (via [`FilterChain::insert_after`]) if `at_index` is
/// out of range.
pub fn insert_after<S>(
    chain: &mut FilterChain,
    at_index: usize,
    config: H2ProxyConfig,
    transport: S,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let filter = H2ProxyFilter::new(config, transport);
    chain.insert_after(at_index, Box::new(filter))
}

// ===========================================================================
// Tests — an in-process `h2` mock proxy (over `tokio::io::duplex`) exercising
// tunnel establishment, byte relay, multi-frame flow control, the `407`
// proxy-auth re-issue, and the non-2xx failure code.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::FIRSTSOCKET;
    use crate::error::CurlCode;
    use http::Response;
    use std::sync::{Arc, Mutex};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};

    /// A pass-through head filter (curl's `SETUP`), used to prove the H2 proxy
    /// filter also works when it is spliced below another filter via
    /// [`insert_after`] and reached through the chain's delegation.
    struct TestHead;

    impl ConnectionFilter for TestHead {
        fn name(&self) -> &'static str {
            "SETUP"
        }
        fn cf_type(&self) -> CfType {
            CfType::default()
        }
    }

    /// What the mock proxy should do with the `CONNECT` stream(s) it accepts.
    enum MockBehavior {
        /// Accept with `200` and echo every `DATA` frame back on the stream.
        Echo,
        /// Reject with the given status (no tunnel body).
        Status(StatusCode),
        /// Reject the first `CONNECT` with `407`, accept the second (which must
        /// carry `Proxy-Authorization`) with `200` and echo. Records, per
        /// stream, whether `Proxy-Authorization` was present.
        AuthThenEcho(Arc<Mutex<Vec<bool>>>),
    }

    /// Server-side echo: relay every inbound `DATA` frame back out, honoring
    /// flow control on both directions, then close the stream when the client
    /// half-closes.
    async fn echo_stream(mut body: RecvStream, mut send: SendStream<Bytes>) {
        while let Some(chunk) = body.data().await {
            let data = match chunk {
                Ok(d) => d,
                Err(_) => return,
            };
            if !data.is_empty() {
                let _ = body.flow_control().release_capacity(data.len());
            }
            let mut off = 0usize;
            while off < data.len() {
                send.reserve_capacity(data.len() - off);
                match poll_fn(|cx| send.poll_capacity(cx)).await {
                    Some(Ok(0)) => continue,
                    Some(Ok(cap)) => {
                        let end = (off + cap).min(data.len());
                        if send.send_data(data.slice(off..end), false).is_err() {
                            return;
                        }
                        off = end;
                    }
                    _ => return,
                }
            }
        }
        // Client half-closed: close our side too.
        let _ = send.send_data(Bytes::new(), true);
    }

    /// Drives the in-process HTTP/2 mock proxy over the server half of a duplex.
    ///
    /// The HTTP/2 `Connection` only performs socket I/O while it is polled, and
    /// for the server that polling happens inside [`accept`](h2::server::Connection::accept).
    /// Stream handlers are therefore **spawned** while the `accept` loop keeps
    /// running, so the connection is continuously driven (flushing responses and
    /// reading `DATA`) even while a tunnel stream is being serviced — the
    /// canonical `h2` server pattern. The loop ends when the client closes the
    /// connection and `accept` yields `None`.
    async fn run_mock_proxy(io: DuplexStream, behavior: MockBehavior) {
        let mut conn = h2::server::handshake(io).await.expect("server handshake");
        let mut count = 0usize;
        while let Some(accepted) = conn.accept().await {
            let (req, mut respond) = match accepted {
                Ok(v) => v,
                Err(_) => return,
            };
            // Every request through this filter must be an HTTP/2 CONNECT.
            assert_eq!(*req.method(), Method::CONNECT, "proxy must receive CONNECT");
            count += 1;

            match &behavior {
                MockBehavior::Echo => {
                    let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
                    let send = respond.send_response(resp, false).unwrap();
                    let body = req.into_body();
                    // Service the tunnel on its own task so the accept loop keeps
                    // driving the connection (h2 I/O only progresses while the
                    // `Connection` is polled).
                    tokio::spawn(echo_stream(body, send));
                }
                MockBehavior::Status(code) => {
                    let resp = Response::builder().status(*code).body(()).unwrap();
                    let _ = respond.send_response(resp, true).unwrap();
                    // Do NOT return: keep the accept loop running so the response
                    // is flushed to the client before the connection is torn down
                    // (returning here would drop `conn` mid-flush -> BrokenPipe).
                }
                MockBehavior::AuthThenEcho(seen) => {
                    let has_auth = req.headers().contains_key(PROXY_AUTHORIZATION);
                    seen.lock().unwrap().push(has_auth);
                    if count == 1 {
                        // Challenge the first, credential-less attempt.
                        let resp = Response::builder()
                            .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                            .body(())
                            .unwrap();
                        let _ = respond.send_response(resp, true).unwrap();
                        // Loop to accept the authenticated retry stream.
                    } else {
                        let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
                        let send = respond.send_response(resp, false).unwrap();
                        let body = req.into_body();
                        tokio::spawn(echo_stream(body, send));
                    }
                }
            }
        }
    }

    /// Reads exactly `n` bytes from the tunnel via the chain, coalescing frames.
    async fn read_exact_via_chain(chain: &mut FilterChain, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        let mut buf = vec![0u8; 32 * 1024];
        while out.len() < n {
            let got = chain.recv(&mut buf).await.expect("recv");
            if got == 0 {
                break;
            }
            out.extend_from_slice(&buf[..got]);
        }
        out
    }

    #[test]
    fn authority_is_authority_form_and_brackets_ipv6() {
        assert_eq!(
            H2ProxyConfig::new("example.com", 8443).authority(),
            "example.com:8443"
        );
        assert_eq!(H2ProxyConfig::new("::1", 8080).authority(), "[::1]:8080");
        assert_eq!(H2ProxyConfig::new("[::1]", 8080).authority(), "[::1]:8080");
        assert_eq!(
            H2ProxyConfig::new("127.0.0.1", 3128).authority(),
            "127.0.0.1:3128"
        );
    }

    #[test]
    fn filter_descriptor_and_initial_state() {
        let (client_io, _server_io) = duplex(1024);
        let filter = H2ProxyFilter::new(H2ProxyConfig::new("proxy.example", 3128), client_io);
        assert_eq!(filter.name(), "H2-PROXY");
        let t = filter.cf_type();
        // Prompt mandates PROXY | HTTP | MULTIPLEX; the C descriptor adds
        // IP_CONNECT — the union of both is asserted here.
        assert!(t.contains(CfType::PROXY));
        assert!(t.contains(CfType::HTTP));
        assert!(t.contains(CfType::MULTIPLEX));
        assert!(t.contains(CfType::IP_CONNECT));
        // No tunnel until `connect` runs.
        assert_eq!(filter.tunnel_state(), None);
    }

    #[tokio::test]
    async fn next_transport_delegates_reads_and_writes() {
        let (a, mut b) = duplex(1024);
        let mut adapter = NextTransport::new(a);

        // Write through the adapter; read on the peer.
        adapter.write_all(b"ping").await.unwrap();
        adapter.flush().await.unwrap();
        let mut got = [0u8; 4];
        b.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");

        // Write on the peer; read through the adapter.
        b.write_all(b"pong").await.unwrap();
        let mut got2 = [0u8; 4];
        adapter.read_exact(&mut got2).await.unwrap();
        assert_eq!(&got2, b"pong");

        // `into_inner` returns the wrapped transport.
        let _inner: DuplexStream = adapter.into_inner();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tunnel_establishes_and_relays_bytes() {
        let (client_io, server_io) = duplex(64 * 1024);
        let server = tokio::spawn(run_mock_proxy(server_io, MockBehavior::Echo));

        // Build a chain [SETUP, H2-PROXY] via the factory to also cover
        // `insert_after` and delegation through a head filter.
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(TestHead));
        insert_after(
            &mut chain,
            0,
            H2ProxyConfig::new("proxy.local", 8080),
            client_io,
        )
        .unwrap();
        assert_eq!(chain.len(), 2);

        let done = chain.connect(true).await.expect("connect");
        assert!(done, "tunnel should be established");

        let payload = b"the-stream-body-is-the-tunnel";
        let sent = chain.send(payload, true).await.expect("send");
        assert_eq!(sent, payload.len());

        let echoed = read_exact_via_chain(&mut chain, payload.len()).await;
        assert_eq!(echoed, payload);

        drop(chain);
        let _ = server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn flow_control_relays_multi_frame_payload_without_deadlock() {
        let (client_io, server_io) = duplex(64 * 1024);
        let server = tokio::spawn(run_mock_proxy(server_io, MockBehavior::Echo));

        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(H2ProxyFilter::new(
            H2ProxyConfig::new("proxy.local", 8080),
            client_io,
        )));

        assert!(chain.connect(true).await.expect("connect"));

        // 256 KiB forces many DATA frames and WINDOW_UPDATE cycles: this is the
        // deadlock hazard the `h2` capacity APIs must handle correctly.
        let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
        let sent = chain.send(&payload, true).await.expect("send");
        assert_eq!(sent, payload.len());

        let echoed = read_exact_via_chain(&mut chain, payload.len()).await;
        assert_eq!(echoed.len(), payload.len());
        assert_eq!(echoed, payload);

        drop(chain);
        let _ = server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn proxy_auth_407_triggers_reissue_with_credentials() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (client_io, server_io) = duplex(64 * 1024);
        let server = tokio::spawn(run_mock_proxy(
            server_io,
            MockBehavior::AuthThenEcho(seen.clone()),
        ));

        let config = H2ProxyConfig::with_credentials(
            "proxy.local",
            8080,
            Some("aladdin".to_string()),
            Some("opensesame".to_string()),
        );
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(H2ProxyFilter::new(config, client_io)));

        let done = chain.connect(true).await.expect("connect through 407");
        assert!(done);

        // The re-issued tunnel is fully functional.
        let payload = b"authenticated-tunnel";
        assert_eq!(chain.send(payload, true).await.unwrap(), payload.len());
        let echoed = read_exact_via_chain(&mut chain, payload.len()).await;
        assert_eq!(echoed, payload);

        drop(chain);
        let _ = server.await;

        // First CONNECT was unauthenticated; the retry carried the credentials.
        let observed = seen.lock().unwrap().clone();
        assert_eq!(
            observed,
            vec![false, true],
            "first CONNECT unauthenticated, retry carries Proxy-Authorization"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn non_2xx_connect_response_is_proxy_error() {
        let (client_io, server_io) = duplex(16 * 1024);
        let server = tokio::spawn(run_mock_proxy(
            server_io,
            MockBehavior::Status(StatusCode::BAD_GATEWAY),
        ));

        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(H2ProxyFilter::new(
            H2ProxyConfig::new("proxy.local", 8080),
            client_io,
        )));

        let err = chain
            .connect(true)
            .await
            .expect_err("a non-2xx CONNECT response must fail the tunnel");
        // Non-2xx CONNECT maps to CURLE_PROXY (integer value 97).
        assert_eq!(err.code(), CurlCode::Proxy);

        let _ = server.await;
    }
}
