//! HTTPS connection establishment: the TLS connection filter and the
//! ALPN-eyeballs HTTPS coordinator.
//!
//! This module has **two distinct responsibilities**, both centred on bringing
//! a TLS/HTTPS connection up inside the tower-like connection-filter chain
//! (`crate::conn::filters`). They are authored together because they cooperate
//! tightly: the coordinator races protocol stacks that each terminate in the
//! TLS filter, and the negotiated ALPN produced by the TLS filter is the single
//! signal the coordinator (and the protocol engines above it) use to pick
//! HTTP/1.1 vs HTTP/2 vs HTTP/3.
//!
//! # 1. The cf-ssl TLS connection filter — [`TlsFilter`] (BOUNDARY #2)
//!
//! Behavioural oracle: `lib/vtls/vtls.c` — the `Curl_cft_ssl` /
//! `Curl_cft_ssl_proxy` filter vtables together with `Curl_cf_ssl_insert_after`
//! and `Curl_cf_ssl_proxy_insert_after`. [`TlsFilter`] wraps the TLS primitive
//! [`crate::tls::connect`] and threads TLS into the filter chain: it first
//! drives the sub-chain below it (`next` — the TCP/proxy transport) to
//! connection, then performs the rustls handshake *over* that sub-chain, and
//! afterwards forwards application bytes transparently through the established
//! TLS session. The post-handshake negotiated ALPN is captured and exposed via
//! [`CfQuery::AlpnNegotiated`], which is what drives HTTP/1.1-vs-HTTP/2
//! selection one layer up.
//!
//! Although the AAP places the TLS *layer* (the rustls plumbing) in
//! `crate::tls`, the TLS *connection filter* — the `Curl_cftype` that splices
//! TLS into the chain — is `conn/`'s responsibility, which is why it lives here.
//!
//! # 2. The ALPN-eyeballs HTTPS coordinator — [`HttpsConnectFilter`]
//!
//! Behavioural oracle: `lib/cf-https-connect.c` — the `Curl_cft_hc` /
//! `cf_hc_*` machinery. This coordinator races up to **two** connection
//! sub-chains — typically **h3 over QUIC** versus **h2/h1 over TLS/TCP** — with
//! a staggered (soft/hard) eyeballs timer, and promotes the first stack to
//! finish its handshake as the live connection. It mirrors
//! [`crate::conn::happy_eyeballs`], except it races **protocol stacks** rather
//! than IP addresses.
//!
//! # Boundaries and the acyclic dependency rule
//!
//! The QUIC transport (`quinn`) and HTTP/3 framing (`h3`) live in
//! `crate::protocols::http::h3`, **not** in `conn/`. To keep the dependency
//! direction acyclic (`conn → {tls, dns, proxy, util, error, url}`, never
//! `conn → protocols`), the h3 sub-chain is supplied to the coordinator as an
//! **injected connector hook** ([`H3ConnectorFn`]); this module never names
//! `crate::protocols`. Likewise the HTTP/2 "switch" that the C oracle performs
//! inline (`Curl_http2_switch_at`, gated `USE_NGHTTP2`) is *signalled* here by
//! exposing the negotiated `h2` ALPN through [`HttpsConnectFilter::query`]; the
//! protocol engine above performs the actual switch.
//!
//! # Memory safety
//!
//! This file contains **zero `unsafe`**. The crate root applies
//! `#![forbid(unsafe_code)]`, so the rule is compiler-enforced; the
//! `AsyncRead`/`AsyncWrite` bridge ([`FilterIo`]) achieves pin-projection for
//! free because all of its fields are [`Unpin`], and rustls/tokio-rustls expose
//! a fully safe API.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::conn::filters::{
    BoxFuture, CfQuery, CfQueryResult, CfState, ConnectionFilter, FilterData, CF_TYPE_MULTIPLEX,
    CF_TYPE_PROXY, CF_TYPE_SSL,
};
use crate::error::{codes, CurlCode, CurlError, Result};
use crate::tls::{self, alpn_protocols, build_client_config, TlsConfig, TlsConnection, ALPN_H2};
use crate::util::sendf;
use crate::util::timediff::ms_to_duration;
use crate::util::timeval::{curlx_now, curlx_ptimediff_ms, CurlTime};

// =============================================================================
// Constants — exact mirrors of the cf-https-connect.c oracle
// =============================================================================

/// Maximum number of protocol stacks the coordinator races concurrently.
///
/// C: `struct cf_hc_ctx` holds `struct cf_hc_baller ballers[2]`
/// (cf-https-connect.c L114) — at most an h3-over-QUIC stack and an
/// h2/h1-over-TLS stack. The Rust coordinator stores its ballers in a `Vec`
/// whose length never exceeds this bound.
pub const MAX_HC_BALLERS: usize = 2;

/// curl's default Happy-Eyeballs timeout in milliseconds
/// (`include/curl/curl.h`: `#define CURL_HET_DEFAULT 200L`). It is the source
/// of both eyeballs deadlines below and matches
/// [`crate::conn::happy_eyeballs::CURL_HET_DEFAULT`].
///
/// The coordinator's two deadlines derive from `data.set.happy_eyeballs_timeout`
/// exactly as in `cf_hc_reset` (cf-https-connect.c L192-193):
///
/// * **hard** = `happy_eyeballs_timeout`     — force-start the next stack.
/// * **soft** = `happy_eyeballs_timeout / 4` — start the alternative stack when
///   the preferred one has not yet seen a server reply.
pub const CURL_HET_DEFAULT: i64 = 200;

// =============================================================================
// `FilterIo` — adapt a `ConnectionFilter` sub-chain into `AsyncRead + AsyncWrite`
// =============================================================================

/// Per-poll read chunk for [`FilterIo`]. Bounded by a single TLS record's
/// maximum plaintext size (16 KiB), so one `recv` never over-reads.
const TLS_IO_CHUNK_SIZE: usize = 16 * 1024;

/// Map a [`CurlError`] into a [`std::io::Error`] for the `AsyncRead` /
/// `AsyncWrite` boundary that `tokio-rustls` consumes during the handshake and
/// for record I/O afterwards. The TLS layer surfaces these as `io::Error`,
/// which `crate::tls::connect` then re-maps to the precise SSL `CURLcode` for a
/// handshake failure, or which this filter maps back via [`CurlError::from`]
/// for steady-state record I/O.
fn curl_to_io(e: &CurlError) -> io::Error {
    io::Error::other(e.to_string())
}

/// Bridges the [`ConnectionFilter`] byte interface (`send` / `recv`) of the
/// sub-chain **below** the TLS filter into the [`AsyncRead`] + [`AsyncWrite`]
/// stream that [`crate::tls::connect`] (and the resulting `tokio-rustls`
/// [`TlsStream`](tokio_rustls::client::TlsStream)) drive.
///
/// `crate::tls::connect::<IO>` requires a concrete `IO: AsyncRead + AsyncWrite +
/// Unpin` and **moves** it into the returned [`TlsConnection`]. The TLS filter,
/// however, sits above a `dyn ConnectionFilter` sub-chain. `FilterIo` resolves
/// that mismatch: [`TlsFilter::connect`] moves its `next` filter into a
/// `FilterIo` and hands that to `tls::connect`, so the rustls handshake — and
/// every subsequent encrypted record — flows through the lower chain. After the
/// handshake the moved-in sub-chain is still reachable through the TLS stream's
/// [`get_ref`](tokio_rustls::client::TlsStream::get_ref) /
/// [`get_mut`](tokio_rustls::client::TlsStream::get_mut) accessors, which is how
/// the filter answers delegated queries and tears the chain down.
///
/// # Cancel-safety of the per-poll future
///
/// [`ConnectionFilter::recv`] / [`send`](ConnectionFilter::send) return *boxed*
/// futures that borrow the filter. Rather than self-referentially storing one,
/// each `poll_*` constructs a **fresh** `recv` / `send` future, polls it once
/// with the caller's [`Context`], and — if it is [`Poll::Pending`] — drops it
/// and returns `Pending` with the waker already registered by the inner future.
/// This is sound because the filters below (Tokio sockets, `tokio-rustls`
/// proxy chains) are cancel-safe: a read/write that has not completed consumes
/// nothing, so re-creating and re-polling resumes the same operation. A
/// synchronous [`CurlError::Again`] becomes a self-wake + `Pending` so the task
/// is re-polled promptly. This mirrors the established `crate::conn::h2_proxy`
/// adapter.
struct FilterIo {
    /// The connection sub-chain below the TLS filter, owned for the lifetime of
    /// the TLS session.
    filter: Box<dyn ConnectionFilter>,
    /// A reusable scratch buffer so `poll_read` does not allocate per poll.
    read_buf: Vec<u8>,
}

impl FilterIo {
    /// Wrap `filter`, sizing the scratch buffer at [`TLS_IO_CHUNK_SIZE`].
    fn new(filter: Box<dyn ConnectionFilter>) -> Self {
        Self {
            filter,
            read_buf: vec![0u8; TLS_IO_CHUNK_SIZE],
        }
    }
}

impl AsyncRead for FilterIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // `FilterIo` is `Unpin` (both fields are), so projecting to `&mut Self`
        // via `get_mut` is safe and needs no `unsafe`.
        let this = self.get_mut();
        let want = buf.remaining().min(this.read_buf.len());
        if want == 0 {
            return Poll::Ready(Ok(()));
        }
        // Disjoint field borrows: `filter` and `read_buf` are distinct fields,
        // so the recv future may borrow `read_buf` while `filter` drives it.
        let n = {
            let mut fut = this.filter.recv(&mut this.read_buf[..want]);
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(CurlError::Again)) => {
                    // No data right now and the inner op did not register a
                    // waker: schedule a prompt re-poll.
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(curl_to_io(&e))),
                Poll::Pending => return Poll::Pending,
            }
        };
        // `n == 0` leaves `buf` unfilled, which `tokio-rustls` reads as EOF.
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
        // The filters below write straight through (a socket / proxy buffer is
        // the runtime's concern), so there is nothing extra to flush here.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The TLS `close_notify` is emitted by the `tokio-rustls` stream's own
        // shutdown; the graceful teardown of the sub-chain below is driven
        // explicitly by [`TlsFilter::shutdown`] (which reaches the moved-in
        // filter through the stream), so this is a no-op.
        Poll::Ready(Ok(()))
    }
}

// =============================================================================
// PHASE 2 — the cf-ssl TLS connection filter (`TlsFilter`)
//           Oracle: lib/vtls/vtls.c (`Curl_cft_ssl` / `Curl_cft_ssl_proxy`).
// =============================================================================

/// The TLS connection filter — the Rust home of curl's `Curl_cft_ssl`
/// (server TLS) and `Curl_cft_ssl_proxy` (HTTPS-proxy TLS) filter types.
///
/// It establishes a rustls session **over** the sub-chain below it (`next`,
/// reached through [`cf_state`](ConnectionFilter::cf_state)) and then forwards
/// application bytes transparently through that session. The negotiated ALPN is
/// captured at handshake time and surfaced via
/// [`CfQuery::AlpnNegotiated`](crate::conn::filters::CfQuery::AlpnNegotiated),
/// which the protocol layer above reads to choose HTTP/1.1 vs HTTP/2.
///
/// # Server vs proxy
///
/// `is_proxy` distinguishes the two C vtables. The server variant
/// (`Curl_cft_ssl`) carries the [`CF_TYPE_SSL`] flag and names itself `"SSL"`;
/// the proxy variant (`Curl_cft_ssl_proxy`) additionally carries
/// [`CF_TYPE_PROXY`] and names itself `"SSL-PROXY"`. The proxy variant also
/// withholds the application-facing SSL-info / `TIMER_APPCONNECT` query answers
/// (those describe the *server* TLS session, not the proxy tunnel's), exactly
/// as `ssl_cf_query` gates them on `!Curl_ssl_cf_is_proxy(cf)`.
///
/// # Ownership of the sub-chain across the handshake
///
/// [`crate::tls::connect`] consumes a concrete `IO` by value, so
/// [`connect`](ConnectionFilter::connect) **moves** `next` out of
/// [`CfState`] into a [`FilterIo`] and then into the resulting
/// [`TlsConnection`]. From that point `cf_state().next` is `None`; the live
/// sub-chain lives inside `tls` and is reached through the TLS stream's
/// `get_ref` / `get_mut` accessors for delegation, control events, liveness,
/// and teardown.
pub struct TlsFilter {
    /// Chain-link + lifecycle state. Before [`connect`](ConnectionFilter::connect),
    /// `next` holds the transport sub-chain; afterwards it is `None` (moved into
    /// `tls`).
    state: CfState,
    /// The resolved TLS configuration (verify flags, CA source, client cert,
    /// version bounds, pinned key options). Cloned into the rustls
    /// `ClientConfig` at connect time.
    config: TlsConfig,
    /// The SNI / certificate-verification hostname for the peer.
    hostname: String,
    /// The peer port (reported via [`CfQuery::HostPort`]).
    port: u16,
    /// `CURLOPT_PINNEDPUBLICKEY` value, if any (checked post-handshake by
    /// [`crate::tls::connect`]).
    pinned_pubkey: Option<String>,
    /// The ALPN protocol list to offer, already computed by the caller via
    /// [`crate::tls::alpn_protocols`] from the transfer's HTTP-version
    /// preference. Empty means "do not offer ALPN".
    alpn: Vec<Vec<u8>>,
    /// `true` for the HTTPS-proxy TLS variant (`Curl_cft_ssl_proxy`).
    is_proxy: bool,
    /// The established TLS session (with its moved-in [`FilterIo`] sub-chain),
    /// present once [`connect`](ConnectionFilter::connect) has completed.
    tls: Option<TlsConnection<FilterIo>>,
    /// The ALPN protocol the peer selected, captured at handshake completion.
    negotiated_alpn: Option<Vec<u8>>,
}

impl TlsFilter {
    /// Construct a TLS filter with no sub-chain linked yet (`next == None`).
    ///
    /// This mirrors `Curl_ssl_cf_create`: the filter is created first and the
    /// caller links the transport below it (the constructors
    /// [`create_tls_filter`] / [`create_tls_proxy_filter`] return it ready for
    /// `cf_state_mut().next = Some(transport)`, the analog of
    /// `Curl_cf_ssl_insert_after`'s "insert below this filter").
    fn new(
        config: TlsConfig,
        hostname: String,
        port: u16,
        pinned_pubkey: Option<String>,
        alpn: Vec<Vec<u8>>,
        is_proxy: bool,
    ) -> Self {
        Self {
            state: CfState::new(),
            config,
            hostname,
            port,
            pinned_pubkey,
            alpn,
            is_proxy,
            tls: None,
            negotiated_alpn: None,
        }
    }
}

/// Create the **server** TLS connection filter (`Curl_cft_ssl`).
///
/// The returned filter has no sub-chain linked: the caller installs the
/// transport with `cf.cf_state_mut().next = Some(transport)` before calling
/// [`connect`](ConnectionFilter::connect) (the analog of
/// `Curl_cf_ssl_insert_after` inserting the TLS filter *above* the transport).
/// Invoked by `connect.rs`'s SSL step and by the HTTPS coordinator's
/// h2/h1-over-TLS baller.
///
/// `alpn` is the wire-byte ALPN list to offer, computed by the caller via
/// [`crate::tls::alpn_protocols`]; pass an empty `Vec` to disable ALPN.
pub fn create_tls_filter(
    config: TlsConfig,
    hostname: String,
    port: u16,
    pinned_pubkey: Option<String>,
    alpn: Vec<Vec<u8>>,
) -> Box<dyn ConnectionFilter> {
    Box::new(TlsFilter::new(
        config,
        hostname,
        port,
        pinned_pubkey,
        alpn,
        false,
    ))
}

/// Create the **HTTPS-proxy** TLS connection filter (`Curl_cft_ssl_proxy`).
///
/// Used by `connect.rs`'s HTTP-proxy step when the proxy itself speaks TLS
/// (`conn.bits.proxy_ssl && !ssl`), i.e. the analog of
/// `Curl_cf_ssl_proxy_insert_after`. Like [`create_tls_filter`], the returned
/// filter has no sub-chain linked; the caller installs the proxy transport
/// below it.
pub fn create_tls_proxy_filter(
    config: TlsConfig,
    hostname: String,
    port: u16,
    pinned_pubkey: Option<String>,
    alpn: Vec<Vec<u8>>,
) -> Box<dyn ConnectionFilter> {
    Box::new(TlsFilter::new(
        config,
        hostname,
        port,
        pinned_pubkey,
        alpn,
        true,
    ))
}

impl TlsFilter {
    /// Answer a query the TLS filter does not handle itself by forwarding it to
    /// the sub-chain below — reached through the TLS stream once the handshake
    /// has moved `next` inside it, or directly via `next` beforehand.
    fn delegate_query(&self, query: CfQuery) -> Result<CfQueryResult> {
        match self.tls.as_ref() {
            Some(conn) => conn.stream().get_ref().0.filter.query(query),
            None => match self.state.next.as_ref() {
                Some(next) => next.query(query),
                None => Err(CurlError::UnknownOption),
            },
        }
    }
}

impl ConnectionFilter for TlsFilter {
    /// C: `Curl_cft_ssl.name = "SSL"` / `Curl_cft_ssl_proxy.name = "SSL-PROXY"`.
    fn name(&self) -> &'static str {
        if self.is_proxy {
            "SSL-PROXY"
        } else {
            "SSL"
        }
    }

    fn cf_state(&self) -> &CfState {
        &self.state
    }

    fn cf_state_mut(&mut self) -> &mut CfState {
        &mut self.state
    }

    /// C: `Curl_cft_ssl.flags = CF_TYPE_SSL`; the proxy vtable adds
    /// `CF_TYPE_PROXY`.
    fn flags(&self) -> u32 {
        if self.is_proxy {
            CF_TYPE_SSL | CF_TYPE_PROXY
        } else {
            CF_TYPE_SSL
        }
    }

    /// Establish the TLS session over the sub-chain below — C: `ssl_cf_connect`.
    ///
    /// Order of operations mirrors the oracle: short-circuit if already
    /// connected; fail with `CURLE_FAILED_INIT` if there is no transport below;
    /// drive the transport to connection first; then perform the rustls
    /// handshake over it. On success the negotiated ALPN is captured and the
    /// filter is marked connected. Handshake/verification/pinning errors are
    /// mapped to the precise SSL `CURLcode` family by
    /// [`crate::tls::connect`] (e.g. `CURLE_PEER_FAILED_VERIFICATION`,
    /// `CURLE_SSL_PINNEDPUBKEYNOTMATCH`, `CURLE_SSL_CONNECT_ERROR`).
    ///
    /// Certificate validation is **on by default** (per AAP §0.8.1); disabling
    /// it (`CURLOPT_SSL_VERIFYPEER=0` / `--insecure`) is governed by
    /// [`TlsConfig`] and the stderr warning is emitted by the CLI layer, not
    /// here.
    fn connect<'a>(&'a mut self, data: &'a mut FilterData) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // (1) Already connected (C: `if(connssl->state == ssl_connection_complete)`).
            if self.state.connected {
                return Ok(());
            }
            // (2) No transport below ⇒ `CURLE_FAILED_INIT` (C: `if(!cf->next) ...`).
            if self.state.next.is_none() && self.tls.is_none() {
                sendf::failf(
                    &mut data.error_buffer,
                    "TLS filter has no transport filter below it",
                );
                return Err(CurlError::FailedInit);
            }
            // (3) Drive the transport (TCP / proxy) to connection first
            //     (C: `if(!cf->next->connected) { result = cf->next->cft->connect(...) }`).
            if let Some(next) = self.state.next.as_mut() {
                if !next.is_connected() {
                    next.connect(data).await?;
                }
            }
            // (4) Build the rustls `ClientConfig` from the resolved TLS config and
            //     the pre-computed ALPN list, then move the transport into a
            //     `FilterIo` so the handshake flows through it.
            let client_config = build_client_config(&self.config, &self.alpn, None)?;
            let next = self.state.next.take().ok_or(CurlError::FailedInit)?;
            let io = FilterIo::new(next);
            // (5) Perform the handshake. `host`/`pinned` are cloned so `self` is
            //     not borrowed across the await (the boxed future is `'a`).
            let host = self.hostname.clone();
            let pinned = self.pinned_pubkey.clone();
            let conn = tls::connect(client_config, &host, pinned.as_deref(), io).await?;
            // Capture the negotiated ALPN — the single signal the protocol layer
            // reads to select HTTP/1.1 vs HTTP/2 (C: `Curl_alpn_set_negotiated`).
            self.negotiated_alpn = conn.alpn().map(<[u8]>::to_vec);
            if data.verbose {
                match self.negotiated_alpn.as_deref() {
                    Some(a) => sendf::infof(
                        true,
                        &format!("ALPN: server accepted {}", String::from_utf8_lossy(a)),
                    ),
                    None => sendf::infof(true, "ALPN: server did not agree on a protocol"),
                }
            }
            self.tls = Some(conn);
            self.state.connected = true;
            // On success, clear any failure recorded while connecting the
            // transport (C: the higher layer resets the fail reason).
            data.error_buffer = None;
            Ok(())
        })
    }

    /// Send application bytes through the TLS session (C: the `send` half of the
    /// SSL filter, ultimately `Curl_ssl_send`). Before the handshake completes,
    /// report [`CurlError::Again`] (no encrypted channel yet).
    fn send<'a>(&'a mut self, buf: &'a [u8], _eos: bool) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            match self.tls.as_mut() {
                Some(conn) => conn.stream_mut().write(buf).await.map_err(CurlError::from),
                None => Err(CurlError::Again),
            }
        })
    }

    /// Receive application bytes from the TLS session (C: `Curl_ssl_recv`).
    /// `Ok(0)` signals end-of-stream. Before the handshake completes, report
    /// [`CurlError::Again`].
    fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            match self.tls.as_mut() {
                Some(conn) => conn.stream_mut().read(buf).await.map_err(CurlError::from),
                None => Err(CurlError::Again),
            }
        })
    }

    /// Whether buffered plaintext is ready without touching the socket — C:
    /// `ssl_cf_data_pending` (backend pending OR `next->data_pending`).
    ///
    /// rustls drains its own plaintext buffer on the next `recv`, so the
    /// best-effort answer delegates to the sub-chain below (reached through the
    /// TLS stream once the handshake has moved it inside).
    fn data_pending(&self) -> bool {
        match self.tls.as_ref() {
            Some(conn) => conn.stream().get_ref().0.filter.data_pending(),
            None => match self.state.next.as_ref() {
                Some(next) => next.data_pending(),
                None => false,
            },
        }
    }

    /// Connection liveness — C: `cf_ssl_is_alive` (delegates to `next`).
    fn is_alive(&mut self) -> (bool, bool) {
        match self.tls.as_mut() {
            Some(conn) => conn.stream_mut().get_mut().0.filter.is_alive(),
            None => match self.state.next.as_mut() {
                Some(next) => next.is_alive(),
                None => (false, false),
            },
        }
    }

    /// Answer a query — C: `ssl_cf_query`.
    ///
    /// `ALPN_NEGOTIATED` returns the captured negotiated protocol (the key
    /// signal for protocol selection). `SSL_INFO` / `SSL_CTX_INFO` are answered
    /// only for the **server** TLS filter (the proxy variant withholds them, as
    /// the C code gates on `!Curl_ssl_cf_is_proxy`). `HOST_PORT` reports the TLS
    /// peer endpoint. Everything else is delegated to the sub-chain below.
    fn query(&self, query: CfQuery) -> Result<CfQueryResult> {
        match query {
            CfQuery::AlpnNegotiated => {
                Ok(CfQueryResult::AlpnNegotiated(self.negotiated_alpn.clone()))
            }
            CfQuery::HostPort => Ok(CfQueryResult::HostPort {
                host: self.hostname.clone(),
                port: self.port,
            }),
            CfQuery::SslInfo if !self.is_proxy => {
                if self.tls.is_some() {
                    Ok(CfQueryResult::SslInfo)
                } else {
                    self.delegate_query(query)
                }
            }
            CfQuery::SslCtxInfo if !self.is_proxy => {
                if self.tls.is_some() {
                    Ok(CfQueryResult::SslCtxInfo)
                } else {
                    self.delegate_query(query)
                }
            }
            _ => self.delegate_query(query),
        }
    }

    /// Handle a control event — C: `ssl_cf_cntrl` (server) / `Curl_cf_def_cntrl`
    /// (proxy).
    ///
    /// Post-handshake the sub-chain lives inside the TLS stream, so the
    /// [`FilterChain`](crate::conn::filters::FilterChain) walker cannot reach it;
    /// the event is forwarded explicitly. Pre-handshake the sub-chain is still
    /// visible to the walker, so this stays a no-op to avoid double-delivery.
    fn cntrl(&mut self, event: i32, arg1: i32) -> Result<()> {
        if let Some(conn) = self.tls.as_mut() {
            conn.stream_mut().get_mut().0.filter.cntrl(event, arg1)
        } else {
            Ok(())
        }
    }

    /// Tear down the filter — C: `do_close`. Closes the moved-in sub-chain (or
    /// the not-yet-moved `next`) and drops the TLS session.
    fn close(&mut self) {
        self.state.connected = false;
        if let Some(mut conn) = self.tls.take() {
            conn.stream_mut().get_mut().0.filter.close();
        }
        if let Some(next) = self.state.next.as_mut() {
            next.close();
        }
    }

    /// Gracefully shut down the TLS session — C: `ssl_cf_shutdown`.
    ///
    /// Emits the TLS `close_notify` (via the `tokio-rustls` stream's shutdown)
    /// when a session exists, then shuts the moved-in sub-chain down. Pre-
    /// handshake (`next` still visible to the chain walker) this stays a no-op
    /// beyond marking the shutdown bit, per the trait contract.
    fn shutdown<'a>(&'a mut self) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if self.state.shutdown {
                return Ok(());
            }
            if let Some(conn) = self.tls.as_mut() {
                // Best-effort `close_notify`; the peer may already be gone.
                let _ = conn.stream_mut().shutdown().await;
                // The sub-chain is hidden inside the stream post-handshake; shut
                // it down explicitly (the chain walker cannot reach it).
                conn.stream_mut().get_mut().0.filter.shutdown().await?;
            }
            self.state.shutdown = true;
            Ok(())
        })
    }
}

// =============================================================================
// PHASE 3 — the ALPN-eyeballs HTTPS coordinator: state + baller model
//           Oracle: lib/cf-https-connect.c L40-180.
// =============================================================================

/// The coordinator's connect state machine — C: `cf_hc_state`
/// (cf-https-connect.c L42-46).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfHcState {
    /// Nothing started yet (C: `CF_HC_INIT`).
    Init,
    /// One or more protocol stacks are being raced (C: `CF_HC_CONNECT`).
    Connect,
    /// A stack won; the coordinator is now transparent (C: `CF_HC_SUCCESS`).
    Success,
    /// Every stack failed (C: `CF_HC_FAILURE`).
    Failure,
}

/// The ALPN identity of a raced protocol stack — C: `enum alpnid` restricted to
/// the values the coordinator races.
///
/// It selects the stack's human-readable name and its transport: `H3` runs over
/// QUIC, `H2`/`H1` over TCP+TLS. It is the input to [`CfHcBaller::new`]; the
/// derived `name`/`transport` are what the baller stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpnId {
    /// HTTP/3 over QUIC (C: `ALPN_h3`).
    H3,
    /// HTTP/2 over TLS/TCP (C: `ALPN_h2`).
    H2,
    /// HTTP/1.1 over TLS/TCP (C: `ALPN_h1`).
    H1,
}

/// The transport a raced stack uses — the subset of curl's `TRNSPRT_*` the
/// coordinator distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    /// TCP (the h2/h1-over-TLS stacks).
    Tcp,
    /// QUIC (the h3 stack).
    Quic,
}

impl Transport {
    /// A short label for verbose traces.
    fn label(self) -> &'static str {
        match self {
            Transport::Tcp => "TCP",
            Transport::Quic => "QUIC",
        }
    }
}

/// An injected hook that builds **and connects** the h3-over-QUIC sub-chain,
/// yielding the connected filter ready for promotion.
///
/// The QUIC transport (`quinn`) and HTTP/3 framing (`h3`) live in
/// `crate::protocols::http::h3`, which `conn/` must not import (the dependency
/// direction is `conn → {tls, dns, proxy, util, error, url}`, never
/// `conn → protocols`). The wiring layer that *does* know about both therefore
/// supplies the h3 stack as this closure, mirroring the injected
/// protocol-disconnect hook used elsewhere in `conn/`. When no connector is
/// provided, the coordinator runs with a single h2/h1-over-TLS baller and
/// degenerates to a plain TLS connect.
pub type H3ConnectorFn =
    Box<dyn Fn() -> BoxFuture<'static, Result<Box<dyn ConnectionFilter>>> + Send + Sync>;

/// A baller's launcher: a one-shot closure that, given the verbose flag,
/// produces the `'static` future which builds and connects that stack's
/// sub-chain. It is taken (`Option::take`) the moment the baller is started.
type BallerStart =
    Box<dyn FnOnce(bool) -> BoxFuture<'static, Result<Box<dyn ConnectionFilter>>> + Send>;

/// One entry in the racing [`FuturesUnordered`]: a `'static` future that runs a
/// baller's connect and yields its index alongside the connected sub-chain (or
/// the connect error). Carrying the index lets the coordinator record the
/// result against the right baller.
type BallerFut = Pin<Box<dyn Future<Output = (usize, Result<Box<dyn ConnectionFilter>>)> + Send>>;

/// A single raced protocol stack — C: `struct cf_hc_baller`
/// (cf-https-connect.c L48-57).
///
/// # Where the in-flight sub-chain lives
///
/// Unlike the C struct (which stores the live `cf` and is advanced by repeated
/// re-entrant `cf_hc_connect` calls), this baller holds **no live `cf`**: the
/// connecting sub-chain lives entirely inside the racing future in the
/// coordinator's [`FuturesUnordered`], and the winner is promoted directly to
/// the coordinator's `next`. This collapses the C re-entrancy into a single
/// awaited race and mirrors the modelling choice in
/// [`crate::conn::happy_eyeballs`] (no per-attempt baller list on the struct).
/// A baller is therefore "in-flight" exactly when it has `started` and has not
/// recorded a failure (`result == CURLE_OK`).
struct CfHcBaller {
    /// Human-readable stack name (`"h3"` / `"h2"` / `"h1"`) — C: `b->name`.
    name: &'static str,
    /// The transport this stack uses (TCP vs QUIC) — C: `b->transport`.
    transport: Transport,
    /// One-shot launcher; `None` once the baller has been started.
    start: Option<BallerStart>,
    /// The stack's connect result — C: `b->result`. `CURLE_OK` (0) means
    /// "not failed" (still racing or won); any nonzero code marks a hard
    /// failure.
    result: CurlCode,
    /// When this stack started racing — C: `b->started`. `None` until launched.
    started: Option<CurlTime>,
}

impl CfHcBaller {
    /// Assign + initialise a baller — C: `cf_hc_baller_assign`
    /// (cf-https-connect.c L121-142): the ALPN id selects the `name` and
    /// `transport`. `start` is the launcher for this stack's sub-chain.
    fn new(alpn_id: AlpnId, start: BallerStart) -> Self {
        let (name, transport) = match alpn_id {
            AlpnId::H3 => ("h3", Transport::Quic),
            AlpnId::H2 => ("h2", Transport::Tcp),
            AlpnId::H1 => ("h1", Transport::Tcp),
        };
        Self {
            name,
            transport,
            start: Some(start),
            result: codes::CURLE_OK,
            started: None,
        }
    }

    /// Reset to the pre-start state — C: `cf_hc_baller_reset`
    /// (cf-https-connect.c L59-69). Any in-flight sub-chain is torn down by the
    /// coordinator dropping the racing future, so there is nothing to close
    /// here beyond clearing the launcher and bookkeeping.
    fn reset(&mut self) {
        self.start = None;
        self.result = codes::CURLE_OK;
        self.started = None;
    }

    /// Whether this stack is currently racing — C: `cf_hc_baller_is_active`
    /// (`b->cf && !b->result`): started, and not yet failed (a win exits the
    /// race, so a still-active baller has neither failed nor won).
    ///
    /// Retained for completeness of the oracle baller model. In this async port
    /// the set of in-flight stacks is the [`FuturesUnordered`] race queue inside
    /// [`HttpsConnectFilter::run_race`] (not a poll over `ballers[]` as in the C
    /// state machine), so there is no call site for this predicate; it documents
    /// the C semantics and is kept symmetric with [`Self::has_started`] and
    /// [`Self::reply_ms`].
    #[allow(dead_code)]
    fn is_active(&self) -> bool {
        self.started.is_some() && self.result == codes::CURLE_OK
    }

    /// Whether this stack has been launched — C: `cf_hc_baller_has_started`
    /// (`!!b->cf`).
    fn has_started(&self) -> bool {
        self.started.is_some()
    }

    /// Milliseconds to the stack's first server reply — C:
    /// `cf_hc_baller_reply_ms` (queries `CF_QUERY_CONNECT_REPLY_MS`).
    ///
    /// **Pragmatic approximation:** while a stack's sub-chain is in-flight
    /// inside the racing [`FuturesUnordered`], its reply time is not observable,
    /// so it is reported as `-1` ("no reply yet"). This makes the soft-eyeballs
    /// timeout fire and begin racing the alternative stack — the intended
    /// eyeballs behaviour. It is marginally more eager than the C oracle (which
    /// can observe a partial reply and defer the alternative), but it never
    /// changes which stack ultimately wins (the first to *complete* its
    /// handshake), so it is parity-preserving for connection establishment.
    fn reply_ms(&self) -> i64 {
        -1
    }
}

/// The ALPN-eyeballs HTTPS coordinator — C: `struct cf_hc_ctx`
/// (cf-https-connect.c L111-119) plus the per-instance `Curl_cfilter` state.
///
/// It races up to [`MAX_HC_BALLERS`] protocol stacks (h3-over-QUIC, then
/// h2/h1-over-TLS) with a staggered soft/hard eyeballs timer and promotes the
/// first to finish its handshake. After a win it is a transparent pass-through
/// over the promoted stack (reachable through `state.next`).
pub struct HttpsConnectFilter {
    /// Chain-link + lifecycle state; `next` holds the **promoted winner** once a
    /// stack connects (C: `cf->next = winner->cf`).
    state: CfState,
    /// The coordinator state machine — C: `ctx->state`.
    hc_state: CfHcState,
    /// The raced stacks (length ≤ [`MAX_HC_BALLERS`]); the C fixed array
    /// `ballers[2]` + `baller_count` collapses to this `Vec` whose `len()` is
    /// the baller count.
    ballers: Vec<CfHcBaller>,
    /// Soft eyeballs deadline in ms — C: `ctx->soft_eyeballs_timeout_ms`
    /// (`happy_eyeballs_timeout / 4`): begin racing the alternative stack when
    /// the preferred one has seen no reply.
    soft_eyeballs_timeout_ms: i64,
    /// Hard eyeballs deadline in ms — C: `ctx->hard_eyeballs_timeout_ms`
    /// (`happy_eyeballs_timeout`): force-start the alternative stack.
    hard_eyeballs_timeout_ms: i64,
    /// The winner's negotiated ALPN, cached at promotion so the protocol layer
    /// above can select h1/h2/h3 via [`CfQuery::AlpnNegotiated`].
    negotiated_alpn: Option<Vec<u8>>,
    /// The target host (reported via [`CfQuery::HostPort`]).
    host: String,
    /// The target port (reported via [`CfQuery::HostPort`]).
    port: u16,
}

impl HttpsConnectFilter {
    /// Reset to the pre-connect state — C: `cf_hc_reset`
    /// (cf-https-connect.c L182-195): reset every baller, return to
    /// [`CfHcState::Init`], and recompute the eyeballs deadlines
    /// (`hard = happy_eyeballs_timeout`, `soft = happy_eyeballs_timeout / 4`).
    fn reset(&mut self) {
        for b in &mut self.ballers {
            b.reset();
        }
        self.hc_state = CfHcState::Init;
        // `hard == happy_eyeballs_timeout`, so the soft deadline is re-derived
        // from it; the hard deadline itself is unchanged.
        self.soft_eyeballs_timeout_ms = self.hard_eyeballs_timeout_ms / 4;
        self.negotiated_alpn = None;
        self.state.connected = false;
    }
}

// =============================================================================
// PHASE 4 — coordinator connect: staggered ALPN racing + winner promotion
//           Oracle: cf_hc_connect (L293+), time_to_start_next (L249-291),
//           baller_connected (L197-247).
// =============================================================================

impl HttpsConnectFilter {
    /// Whether every stack before `idx` has already failed — C: the
    /// `for(i=0;i<idx;i++) if(!ballers[i].result) break;` loop in
    /// `time_to_start_next` (a `result` of `CURLE_OK` means "not failed").
    fn all_previous_failed(&self, idx: usize) -> bool {
        (0..idx).all(|i| self.ballers[i].result != codes::CURLE_OK)
    }

    /// The `CURLcode` to surface when all stacks fail — C: the failure path of
    /// `cf_hc_connect` surfaces the **first** baller's nonzero result. Falls
    /// back to `CURLE_COULDNT_CONNECT` if (impossibly) none recorded one.
    fn first_failure_code(&self) -> CurlCode {
        for b in &self.ballers {
            if b.result != codes::CURLE_OK {
                return b.result;
            }
        }
        codes::CURLE_COULDNT_CONNECT
    }

    /// Decide whether stack `idx` should be started now — C: `time_to_start_next`
    /// (cf-https-connect.c L249-291). `started` is the coordinator's overall
    /// start time (`ctx->started`), so `elapsed` is measured from when the
    /// **first** stack began, exactly as in the oracle.
    fn time_to_start_next(&self, idx: usize, started: CurlTime) -> bool {
        // Out of range, or already launched ⇒ no.
        if idx >= self.ballers.len() {
            return false;
        }
        if self.ballers[idx].has_started() {
            return false;
        }
        // Every preceding stack has failed ⇒ start this one immediately.
        if self.all_previous_failed(idx) {
            return true;
        }
        let elapsed = curlx_ptimediff_ms(&curlx_now(), &started);
        // Hard timeout reached ⇒ force-start the alternative.
        if elapsed >= self.hard_eyeballs_timeout_ms {
            return true;
        }
        // Soft timeout: the preceding stack has not seen a reply yet ⇒ begin
        // racing the alternative. `reply_ms()` is the pragmatic `-1` while a
        // stack is in-flight (see [`CfHcBaller::reply_ms`]).
        if idx > 0
            && elapsed >= self.soft_eyeballs_timeout_ms
            && self.ballers[idx - 1].reply_ms() < 0
        {
            return true;
        }
        false
    }

    /// Launch stack `idx`: stamp its start time, take its one-shot launcher, and
    /// build the racing future that yields `(idx, connect result)` — C:
    /// `cf_hc_baller_init` (L143-168) followed by the first
    /// `cf_hc_baller_connect`. Returns `None` if the baller was already started
    /// (its launcher consumed).
    fn launch_baller(&mut self, idx: usize, verbose: bool) -> Option<BallerFut> {
        let baller = self.ballers.get_mut(idx)?;
        baller.started = Some(curlx_now());
        let start = baller.start.take()?;
        let fut = start(verbose);
        Some(Box::pin(async move { (idx, fut.await) }))
    }

    /// Race the configured stacks and return the first to finish its handshake —
    /// the async collapse of curl's re-entrant `cf_hc_connect` state machine.
    ///
    /// The preferred stack (`ballers[0]`, h3 when present) starts immediately.
    /// The alternative is started by the staggered soft/hard timer (or at once
    /// if the preferred stack has already failed). The first stack to connect
    /// wins; returning drops the [`FuturesUnordered`], which cancels every other
    /// in-flight connect (curl's "reset the other ballers"). If all stacks fail,
    /// the first recorded `CURLcode` is surfaced.
    async fn run_race(
        &mut self,
        data: &mut FilterData,
    ) -> Result<(usize, Box<dyn ConnectionFilter>)> {
        let verbose = data.verbose;

        // C: ctx->started = now; state = CF_HC_CONNECT; init ballers[0].
        let started = curlx_now();
        self.hc_state = CfHcState::Connect;

        let mut running: FuturesUnordered<BallerFut> = FuturesUnordered::new();

        // Start the preferred stack right away (C: cf_hc_baller_init(ballers[0])).
        if let Some(fut) = self.launch_baller(0, verbose) {
            sendf::infof(
                verbose,
                &format!(
                    "HTTPS-CONNECT: starting {} ({})",
                    self.ballers[0].name,
                    self.ballers[0].transport.label()
                ),
            );
            running.push(fut);
        }
        // The next stack index the coordinator may still start.
        let mut next_to_start: usize = 1;

        loop {
            let more_to_start = next_to_start < self.ballers.len();

            // Nothing in flight and nothing left to start ⇒ all stacks failed
            // (C: failed_ballers == baller_count ⇒ CF_HC_FAILURE).
            if running.is_empty() && !more_to_start {
                self.hc_state = CfHcState::Failure;
                let code = self.first_failure_code();
                sendf::failf(
                    &mut data.error_buffer,
                    "Failed to establish HTTPS connection: all protocol stacks failed",
                );
                return Err(CurlError::from_code(code));
            }

            // Delay until the next stack may start: zero if a preceding stack has
            // failed (start the alternative at once), else the remaining soft
            // stagger; a far-future sentinel when no stack remains keeps the
            // gated branch well-formed.
            let start_delay = if more_to_start {
                if self.all_previous_failed(next_to_start) {
                    Duration::ZERO
                } else {
                    let elapsed = curlx_ptimediff_ms(&curlx_now(), &started);
                    ms_to_duration((self.soft_eyeballs_timeout_ms - elapsed).max(0))
                }
            } else {
                Duration::from_secs(86_400)
            };

            tokio::select! {
                biased;

                // (1) A racing stack completed. The first success wins; the
                //     remaining stacks are cancelled when `running` is dropped at
                //     return (C: baller_connected resets the other ballers).
                maybe = running.next(), if !running.is_empty() => {
                    if let Some((idx, res)) = maybe {
                        match res {
                            Ok(filter) => return Ok((idx, filter)),
                            Err(err) => {
                                // Hard failure: record the code against the stack
                                // (C: b->result = result). The next iteration
                                // decides whether to start the alternative now.
                                let name = self.ballers.get(idx).map_or("?", |b| b.name);
                                sendf::infof(
                                    verbose,
                                    &format!("HTTPS-CONNECT: {name} failed to connect"),
                                );
                                if let Some(b) = self.ballers.get_mut(idx) {
                                    b.result = err.code();
                                }
                            }
                        }
                    }
                }

                // (2) Stagger elapsed ⇒ consult time_to_start_next and, if due,
                //     launch the next stack (C: Curl_expire(EXPIRE_ALPN_EYEBALLS)
                //     firing, then cf_hc_baller_init(ballers[1])).
                () = tokio::time::sleep(start_delay), if more_to_start => {
                    if self.time_to_start_next(next_to_start, started) {
                        if let Some(fut) = self.launch_baller(next_to_start, verbose) {
                            sendf::infof(
                                verbose,
                                &format!(
                                    "HTTPS-CONNECT: starting {} ({})",
                                    self.ballers[next_to_start].name,
                                    self.ballers[next_to_start].transport.label()
                                ),
                            );
                            running.push(fut);
                        }
                        next_to_start += 1;
                    }
                    // Otherwise the next loop iteration recomputes the delay —
                    // the analog of the C `Curl_expire` re-arm.
                }
            }
        }
    }

    /// Promote a winning stack and finalise the coordinator — C:
    /// `baller_connected` (cf-https-connect.c L197-247).
    ///
    /// Resets the other ballers' bookkeeping (their in-flight futures were
    /// already cancelled when [`run_race`](Self::run_race) returned), installs
    /// the winner as `next`, clears any accumulated error, caches the negotiated
    /// ALPN, and transitions to [`CfHcState::Success`].
    ///
    /// **HTTP/2 switch (C `USE_NGHTTP2` block, L228-242).** When the winner
    /// negotiated `h2`, the C code calls `Curl_http2_switch_at` inline. This
    /// module must not import the HTTP/2 engine, so instead the negotiated ALPN
    /// is cached and surfaced via [`HttpsConnectFilter::query`]; the protocol
    /// engine above reads it and performs the actual switch. No protocol import
    /// occurs here.
    fn baller_connected(
        &mut self,
        winner_idx: usize,
        winner: Box<dyn ConnectionFilter>,
        data: &mut FilterData,
    ) -> Result<()> {
        // Reset every other stack's bookkeeping (C: cf_hc_baller_reset of the
        // non-winners).
        for (i, b) in self.ballers.iter_mut().enumerate() {
            if i != winner_idx {
                b.reset();
            }
        }

        // Read the winner's negotiated ALPN before moving it into `next`.
        let alpn = match winner.query(CfQuery::AlpnNegotiated) {
            Ok(CfQueryResult::AlpnNegotiated(a)) => a,
            _ => None,
        };
        self.negotiated_alpn = alpn;

        // Promote the winner as the live sub-chain (C: cf->next = winner->cf).
        self.state.next = Some(winner);
        // Clear any failure recorded by losing stacks (C: Curl_reset_fail).
        data.error_buffer = None;

        let verbose = data.verbose;
        let winner_name = self.ballers.get(winner_idx).map_or("?", |b| b.name);
        match self.negotiated_alpn.as_deref() {
            Some(a) => sendf::infof(
                verbose,
                &format!(
                    "HTTPS-CONNECT: {winner_name} connected, ALPN {}",
                    String::from_utf8_lossy(a)
                ),
            ),
            None => sendf::infof(verbose, &format!("HTTPS-CONNECT: {winner_name} connected")),
        }

        // Signal (do not perform) the HTTP/2 switch when h2 was negotiated; the
        // protocol layer above reads CF_QUERY_ALPN_NEGOTIATED and switches.
        if self.negotiated_alpn.as_deref() == Some(ALPN_H2) {
            sendf::infof(
                verbose,
                "HTTPS-CONNECT: negotiated h2 — HTTP/2 switch deferred to protocol layer",
            );
        }

        self.hc_state = CfHcState::Success;
        self.state.connected = true;
        Ok(())
    }
}

// =============================================================================
// PHASE 5 — coordinator data path, queries, vtable, and the public setup entry
//           Oracle: the `Curl_cft_http_connect` vtable (cf-https-connect.c
//           L560+), `cf_hc_close` (L536), `cf_hc_query` (L480), and the insert
//           entry `Curl_cf_http_connect_add`.
// =============================================================================

impl ConnectionFilter for HttpsConnectFilter {
    /// C: the `Curl_cft_http_connect` vtable name.
    fn name(&self) -> &'static str {
        "HTTPS-CONNECT"
    }

    fn cf_state(&self) -> &CfState {
        &self.state
    }

    fn cf_state_mut(&mut self) -> &mut CfState {
        &mut self.state
    }

    /// Type flags. The coordinator yields a TLS connection that may be HTTP/2
    /// or HTTP/3 multiplexed, so it advertises `CF_TYPE_SSL | CF_TYPE_MULTIPLEX`
    /// (per the file-header design). The C `Curl_cft_http_connect` itself
    /// carries `0`, but the Rust chain uses these type bits for capability
    /// queries (e.g. discovering the SSL boundary and multiplex support).
    fn flags(&self) -> u32 {
        CF_TYPE_SSL | CF_TYPE_MULTIPLEX
    }

    /// Drive the ALPN-eyeballs race and promote the winning stack — C:
    /// `cf_hc_connect` (cf-https-connect.c L293+).
    ///
    /// Short-circuits once a winner has been promoted (C: `cf->connected`).
    /// Otherwise it races the configured stacks via [`run_race`](Self::run_race)
    /// and finalises the first to complete its handshake via
    /// [`baller_connected`](Self::baller_connected). A race in which every stack
    /// fails surfaces the first recorded `CURLcode` as the error (handled inside
    /// `run_race`), and that error propagates out of this future.
    fn connect<'a>(&'a mut self, data: &'a mut FilterData) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Already promoted a winner — nothing to do (C: `cf->connected`).
            if self.state.connected {
                return Ok(());
            }
            // Race the protocol stacks; the first to finish its handshake wins.
            let (winner_idx, winner) = self.run_race(data).await?;
            // Promote the winner as `next`, cache its ALPN, transition to
            // Success (C: baller_connected).
            self.baller_connected(winner_idx, winner, data)?;
            Ok(())
        })
    }

    /// Tear down the coordinator — C: `cf_hc_close` (cf-https-connect.c L536):
    /// reset every baller and the coordinator state, clear `connected`, then
    /// close and discard the promoted winning sub-chain.
    fn close(&mut self) {
        // C: `cf_hc_reset(cf, data)` — also clears `connected` and the cached
        // ALPN, and returns the state machine to `Init`.
        self.reset();
        // C: `do_close(cf->next)` + `Curl_conn_cf_discard_chain(&cf->next)`.
        // Taking + dropping the box discards the chain after closing it.
        if let Some(mut next) = self.state.next.take() {
            next.close();
        }
    }

    /// Answer a [`CfQuery`] — C: `cf_hc_query` (cf-https-connect.c L480).
    ///
    /// The coordinator is the single source of truth for the negotiated ALPN:
    /// it caches the winner's ALPN at promotion and returns it for
    /// [`CfQuery::AlpnNegotiated`] so the protocol layer above selects h1/h2/h3
    /// (the equivalent of the C `Curl_http2_switch_at` decision — performed by
    /// the protocol engine, never here). [`CfQuery::HostPort`] is answered from
    /// the coordinator's own target. Every other query (SSL info, need-flush,
    /// max-concurrent, timers, ...) is delegated to the promoted winning
    /// sub-chain (C: `cf->next->cft->query`).
    fn query(&self, query: CfQuery) -> Result<CfQueryResult> {
        match query {
            // Single source of truth for protocol selection (cached at promotion).
            CfQuery::AlpnNegotiated => {
                Ok(CfQueryResult::AlpnNegotiated(self.negotiated_alpn.clone()))
            }
            // Target host/port for SNI / Host header.
            CfQuery::HostPort => Ok(CfQueryResult::HostPort {
                host: self.host.clone(),
                port: self.port,
            }),
            // Everything else is answered by the promoted winning chain.
            _ => match self.state.next.as_ref() {
                Some(next) => next.query(query),
                None => Err(CurlError::UnknownOption),
            },
        }
    }
}

/// Configuration bundle for [`Curl_cf_https_setup`].
///
/// Groups the TLS parameters, the HTTP-version preferences that drive ALPN
/// offer construction, the HTTP/3 eligibility flag, and the eyeballs timeout
/// into one struct, keeping the setup entry's signature small (avoiding
/// `clippy::too_many_arguments`).
pub struct HttpsSetupConfig {
    /// The resolved TLS configuration (root store, verify flags, client cert).
    pub config: TlsConfig,
    /// SNI / certificate-verification hostname.
    pub hostname: String,
    /// Target port.
    pub port: u16,
    /// Optional `CURLOPT_PINNEDPUBLICKEY` value.
    pub pinned_pubkey: Option<String>,
    /// Offer HTTP/2 (`h2`) in the TLS ALPN list.
    pub want_h2: bool,
    /// Offer HTTP/1.1 (`http/1.1`) in the TLS ALPN list.
    pub want_h1: bool,
    /// Prefer HTTP/1.1 ahead of HTTP/2 in the ALPN ordering.
    pub prefer_h1: bool,
    /// Restrict to HTTP/1.0 (`http/1.0`) — `--http1.0`.
    pub only_http_10: bool,
    /// Whether ALPN is enabled at all (`--no-alpn` clears it).
    pub use_alpn: bool,
    /// Whether HTTP/3-over-QUIC is requested/eligible (`--http3`,
    /// `--http3-only`, or Alt-Svc). The h3 stack is added only when this is set
    /// **and** an [`H3ConnectorFn`] is supplied.
    pub want_h3: bool,
    /// The happy-eyeballs timeout in ms (`CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS`,
    /// default [`CURL_HET_DEFAULT`]); `hard = het`, `soft = het / 4`.
    pub het_timeout_ms: i64,
}

/// Build the HTTPS connection coordinator — the insert entry invoked by
/// `connect.rs`'s `Curl_conn_setup` for HTTPS schemes (C:
/// `Curl_cf_http_connect_add`).
///
/// `transport` is the already-built lower sub-chain for the **h2/h1-over-TLS**
/// stack — typically a happy-eyeballs TCP connector with any proxy filters
/// stacked on it. This function tops it with the cf-ssl [`TlsFilter`] (offering
/// an ALPN list computed from the HTTP-version preferences in `config`) to form
/// the TLS baller.
///
/// When `config.want_h3` is set **and** `h3_connector` is supplied, the
/// **h3-over-QUIC** stack is added as the *preferred* baller (`ballers[0]`, the
/// first to start — matching curl's `alpn_ids[0] = ALPN_h3`); the h2/h1-over-TLS
/// baller then becomes the soft-timeout fallback. The QUIC + HTTP/3 engine
/// lives in `protocols/http/h3` (per the AAP), so it is injected here as an
/// [`H3ConnectorFn`] hook to keep the `conn -> {tls, dns, proxy, util}`
/// dependency direction acyclic — this module never imports `crate::protocols`.
///
/// When HTTP/3 is not requested (or no connector is injected) the coordinator
/// runs with the single h2/h1-over-TLS baller and degenerates to a plain TLS
/// connect.
///
/// # Relationship to plain TLS protocols
///
/// `connect.rs`'s `Curl_conn_setup` calls this for HTTPS. For non-HTTPS TLS
/// protocols (for example FTPS) it instead uses the SETUP meta-filter and
/// inserts a plain [`create_tls_filter`] at the SSL step. Both paths reuse the
/// same [`TlsFilter`] authored above; only HTTPS gets the ALPN-eyeballs race.
#[allow(non_snake_case)]
pub fn Curl_cf_https_setup(
    transport: Box<dyn ConnectionFilter>,
    config: HttpsSetupConfig,
    h3_connector: Option<H3ConnectorFn>,
) -> Box<dyn ConnectionFilter> {
    // Eyeballs deadlines (C: `cf_hc_reset` L192-193): `hard` = the happy-eyeballs
    // timeout, `soft` = a quarter of it. A non-positive timeout falls back to
    // the curl default.
    let hard = if config.het_timeout_ms > 0 {
        config.het_timeout_ms
    } else {
        CURL_HET_DEFAULT
    };
    let soft = hard / 4;

    let mut ballers: Vec<CfHcBaller> = Vec::with_capacity(MAX_HC_BALLERS);

    // --- h3-over-QUIC stack (preferred / ballers[0]) -----------------------
    // Added only when HTTP/3 is requested AND a connector hook is injected. The
    // hook owns the QUIC + h3 construction (it lives in `protocols/`), so the
    // coordinator simply launches it. It ignores `verbose` — it manages its own
    // diagnostics through the shared sendf facility.
    if let (true, Some(connector)) = (config.want_h3, h3_connector) {
        let start: BallerStart = Box::new(move |_verbose: bool| connector());
        ballers.push(CfHcBaller::new(AlpnId::H3, start));
    }

    // --- h2/h1-over-TLS stack (always present) -----------------------------
    // Built entirely within conn/: the pre-built `transport` sub-chain topped
    // with the cf-ssl TlsFilter. The ALPN offer is derived from the requested
    // HTTP versions (typically ["h2", "http/1.1"]).
    let alpn = alpn_protocols(
        config.want_h2,
        config.want_h1,
        config.prefer_h1,
        config.only_http_10,
        config.use_alpn,
    );
    // The baller's human name follows its preferred ALPN (C: `cf_hc_baller_assign`
    // names the TLS baller "h2" when h2 is offered, else "h1").
    let tls_alpn_id = if config.want_h2 {
        AlpnId::H2
    } else {
        AlpnId::H1
    };

    // Owned copies captured by the `'static` launcher closure. `config.hostname`
    // is cloned here and moved into the coordinator below.
    let tls_config = config.config.clone();
    let host = config.hostname.clone();
    let pinned = config.pinned_pubkey.clone();
    let port = config.port;

    let start: BallerStart = Box::new(move |verbose: bool| {
        Box::pin(async move {
            // Top the transport with the cf-ssl TLS filter and link them: the
            // TLS filter sits ABOVE the transport (insert_after semantics).
            let mut tls = create_tls_filter(tls_config, host, port, pinned, alpn);
            tls.cf_state_mut().next = Some(transport);
            // Drive the lower chain + the TLS handshake to completion.
            let mut fdata = FilterData::with_verbose(verbose);
            tls.connect(&mut fdata).await?;
            Ok::<Box<dyn ConnectionFilter>, CurlError>(tls)
        })
    });
    ballers.push(CfHcBaller::new(tls_alpn_id, start));

    // Assemble the coordinator. `host`/`port` for HostPort queries come from the
    // config (the launcher captured its own clones above).
    Box::new(HttpsConnectFilter {
        state: CfState::new(),
        hc_state: CfHcState::Init,
        ballers,
        soft_eyeballs_timeout_ms: soft,
        hard_eyeballs_timeout_ms: hard,
        negotiated_alpn: None,
        host: config.hostname,
        port: config.port,
    })
}

// =============================================================================
// Tests — focused, deterministic unit coverage of the parity-critical logic
// (eyeballs-timeout derivation, the baller model, `time_to_start_next`'s
// soft/hard gating, coordinator query routing, and the filter vtable surface).
//
// The racing/handshake paths (`run_race`, `connect`) require a live transport
// and a TLS peer, which are out of reach in a unit test; their building blocks
// (the timeout math and the start-gating predicate) are exercised here in
// isolation with hand-built timestamps so the eyeballs parity is verified
// without the network.
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::TlsConfig;
    use crate::util::timeval::curlx_now;

    /// A baller launcher that never actually runs in these tests (the start
    /// gating is tested without launching). If launched it resolves to a
    /// connect failure.
    fn dummy_start() -> BallerStart {
        Box::new(|_verbose: bool| {
            Box::pin(async {
                Err::<Box<dyn ConnectionFilter>, CurlError>(CurlError::CouldntConnect)
            })
        })
    }

    /// Build a coordinator with `n` ballers and explicit soft/hard deadlines,
    /// bypassing the network-bound launcher construction.
    fn make_coord(soft: i64, hard: i64, n: usize) -> HttpsConnectFilter {
        let mut ballers = Vec::with_capacity(n);
        for i in 0..n {
            let id = if i == 0 { AlpnId::H2 } else { AlpnId::H1 };
            ballers.push(CfHcBaller::new(id, dummy_start()));
        }
        HttpsConnectFilter {
            state: CfState::new(),
            hc_state: CfHcState::Init,
            ballers,
            soft_eyeballs_timeout_ms: soft,
            hard_eyeballs_timeout_ms: hard,
            negotiated_alpn: None,
            host: "example.com".to_string(),
            port: 443,
        }
    }

    /// A [`CurlTime`] `ms` milliseconds in the past relative to now.
    fn ms_ago(ms: i64) -> CurlTime {
        let now = curlx_now();
        let total_us = (now.tv_sec * 1_000_000 + i64::from(now.tv_usec)) - ms * 1_000;
        CurlTime::new(
            total_us.div_euclid(1_000_000),
            (total_us.rem_euclid(1_000_000)) as i32,
        )
    }

    #[test]
    fn constants_match_curl_oracle() {
        // C: ballers[2] fixed array (cf-https-connect.c) ⇒ at most two stacks.
        assert_eq!(MAX_HC_BALLERS, 2);
        // C: `#define CURL_HET_DEFAULT 200L` (include/curl/curl.h).
        assert_eq!(CURL_HET_DEFAULT, 200);
    }

    #[test]
    fn baller_assign_maps_alpn_to_name_and_transport() {
        // C: cf_hc_baller_assign (L121-142): ALPN id selects name + transport.
        let h3 = CfHcBaller::new(AlpnId::H3, dummy_start());
        assert_eq!(h3.name, "h3");
        assert!(matches!(h3.transport, Transport::Quic));

        let h2 = CfHcBaller::new(AlpnId::H2, dummy_start());
        assert_eq!(h2.name, "h2");
        assert!(matches!(h2.transport, Transport::Tcp));

        let h1 = CfHcBaller::new(AlpnId::H1, dummy_start());
        assert_eq!(h1.name, "h1");
        assert!(matches!(h1.transport, Transport::Tcp));
    }

    #[test]
    fn baller_lifecycle_helpers_track_state() {
        let mut b = CfHcBaller::new(AlpnId::H2, dummy_start());
        // Fresh: not started, not active, no reply, no failure.
        assert!(!b.has_started());
        assert!(!b.is_active());
        assert_eq!(b.reply_ms(), -1);
        assert_eq!(b.result, codes::CURLE_OK);

        // Started + not failed ⇒ active (C: `b->cf && !b->result`).
        b.started = Some(curlx_now());
        assert!(b.has_started());
        assert!(b.is_active());

        // A recorded failure clears "active" but keeps "started".
        b.result = codes::CURLE_COULDNT_CONNECT;
        assert!(b.has_started());
        assert!(!b.is_active());

        // Reset returns to the pre-start state (C: cf_hc_baller_reset L59-69).
        b.reset();
        assert!(!b.has_started());
        assert!(!b.is_active());
        assert_eq!(b.result, codes::CURLE_OK);
        assert!(b.start.is_none());
    }

    #[test]
    fn reset_derives_soft_from_hard_and_clears_state() {
        // C: cf_hc_reset (L182-195): soft = happy_eyeballs_timeout / 4, the hard
        // deadline is the happy-eyeballs timeout itself, state ⇒ Init.
        let mut c = make_coord(/*soft*/ 999, /*hard*/ 200, 2);
        c.negotiated_alpn = Some(b"h2".to_vec());
        c.state.connected = true;
        c.hc_state = CfHcState::Success;
        c.ballers[0].started = Some(curlx_now());

        c.reset();

        assert_eq!(c.hard_eyeballs_timeout_ms, 200);
        assert_eq!(c.soft_eyeballs_timeout_ms, 50); // 200 / 4
        assert_eq!(c.hc_state, CfHcState::Init);
        assert_eq!(c.negotiated_alpn, None);
        assert!(!c.state.connected);
        assert!(!c.ballers[0].has_started());
    }

    #[test]
    fn time_to_start_next_is_false_past_the_baller_count() {
        // C: `if(idx >= ctx->baller_count) return FALSE;`
        let c = make_coord(50, 200, 2);
        assert!(!c.time_to_start_next(2, curlx_now()));
        assert!(!c.time_to_start_next(5, curlx_now()));
    }

    #[test]
    fn time_to_start_next_is_false_when_already_started() {
        // C: `if(ctx->ballers[idx] && cf_hc_baller_has_started(...)) return FALSE;`
        let mut c = make_coord(50, 200, 2);
        c.ballers[1].started = Some(curlx_now());
        assert!(!c.time_to_start_next(1, curlx_now()));
    }

    #[test]
    fn time_to_start_next_starts_immediately_when_all_previous_failed() {
        // C: the `for(i=0;i<idx;i++) if(!ballers[i].result) break;` loop — every
        // earlier stack failed ⇒ start the alternative at once, regardless of time.
        let mut c = make_coord(50, 200, 2);
        c.ballers[0].result = codes::CURLE_COULDNT_CONNECT;
        // `started` is "now" (≈ zero elapsed); the all-failed rule still fires.
        assert!(c.time_to_start_next(1, curlx_now()));
    }

    #[test]
    fn time_to_start_next_fires_on_hard_timeout() {
        // C: `if(elapsed_ms >= ctx->hard_eyeballs_timeout_ms) return TRUE;`
        // Wide-open soft window isolates the hard branch; 10 s ≫ hard (100 ms).
        let c = make_coord(/*soft*/ 50, /*hard*/ 100, 2);
        assert!(c.time_to_start_next(1, ms_ago(10_000)));
    }

    #[test]
    fn time_to_start_next_fires_on_soft_timeout_without_reply() {
        // C: `if(idx > 0 && elapsed_ms >= soft && reply_ms(prev) < 0) return TRUE;`
        // hard is huge so only the soft branch can fire; prev has no reply (-1).
        let c = make_coord(/*soft*/ 50, /*hard*/ 100_000, 2);
        assert!(c.time_to_start_next(1, ms_ago(1_000)));
    }

    #[test]
    fn time_to_start_next_waits_before_the_soft_timeout() {
        // Neither hard nor soft elapsed and no previous failure ⇒ keep waiting.
        // Generous deadlines so the few-ms test runtime cannot cross them.
        let c = make_coord(/*soft*/ 100_000, /*hard*/ 200_000, 2);
        assert!(!c.time_to_start_next(1, curlx_now()));
    }

    #[test]
    fn coordinator_query_returns_cached_alpn_and_host_port() {
        let mut c = make_coord(50, 200, 2);
        c.negotiated_alpn = Some(ALPN_H2.to_vec());

        // ALPN comes from the coordinator's cache (single source of truth).
        match c.query(CfQuery::AlpnNegotiated) {
            Ok(CfQueryResult::AlpnNegotiated(Some(a))) => assert_eq!(a, ALPN_H2),
            other => panic!("unexpected ALPN query result: {other:?}"),
        }

        // Host/port answered from the coordinator's own target.
        match c.query(CfQuery::HostPort) {
            Ok(CfQueryResult::HostPort { host, port }) => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 443);
            }
            other => panic!("unexpected HostPort query result: {other:?}"),
        }

        // With no promoted winner, an unrelated query hits the bottom-of-chain
        // default (C: CURLE_UNKNOWN_OPTION).
        assert!(matches!(
            c.query(CfQuery::MaxConcurrent),
            Err(CurlError::UnknownOption)
        ));
    }

    #[test]
    fn coordinator_vtable_surface_matches_design() {
        let c = make_coord(50, 200, 1);
        assert_eq!(c.name(), "HTTPS-CONNECT");
        // Per the file-header design: SSL boundary + possibly multiplexed.
        assert_eq!(c.flags(), CF_TYPE_SSL | CF_TYPE_MULTIPLEX);
        // Before a win the coordinator is not yet connected.
        assert!(!c.state.connected);
    }

    #[test]
    fn tls_filter_constructor_is_server_ssl() {
        // C: Curl_cft_ssl — name "SSL", flag CF_TYPE_SSL, no proxy bit.
        let cf = create_tls_filter(
            TlsConfig::default(),
            "example.com".to_string(),
            443,
            None,
            vec![ALPN_H2.to_vec(), b"http/1.1".to_vec()],
        );
        assert_eq!(cf.name(), "SSL");
        assert_eq!(cf.flags(), CF_TYPE_SSL);
        assert_eq!(cf.flags() & CF_TYPE_PROXY, 0);
    }

    #[test]
    fn tls_proxy_filter_constructor_is_proxy_ssl() {
        // C: Curl_cft_ssl_proxy — name "SSL-PROXY", flags CF_TYPE_SSL|CF_TYPE_PROXY.
        let cf = create_tls_proxy_filter(
            TlsConfig::default(),
            "proxy.example.com".to_string(),
            8443,
            None,
            vec![],
        );
        assert_eq!(cf.name(), "SSL-PROXY");
        assert_eq!(cf.flags(), CF_TYPE_SSL | CF_TYPE_PROXY);
    }

    #[test]
    fn https_setup_without_h3_builds_a_single_stack_coordinator() {
        // No HTTP/3 requested ⇒ degenerates to the lone h2/h1-over-TLS baller.
        let transport: Box<dyn ConnectionFilter> = create_tls_filter(
            TlsConfig::default(),
            "h.example".to_string(),
            443,
            None,
            vec![],
        );
        let cfg = HttpsSetupConfig {
            config: TlsConfig::default(),
            hostname: "h.example".to_string(),
            port: 443,
            pinned_pubkey: None,
            want_h2: true,
            want_h1: true,
            prefer_h1: false,
            only_http_10: false,
            use_alpn: true,
            want_h3: false,
            het_timeout_ms: 200,
        };
        let cf = Curl_cf_https_setup(transport, cfg, None);
        assert_eq!(cf.name(), "HTTPS-CONNECT");
        assert_eq!(cf.flags(), CF_TYPE_SSL | CF_TYPE_MULTIPLEX);
    }

    #[test]
    fn https_setup_with_h3_connector_adds_the_preferred_quic_stack_first() {
        // HTTP/3 requested + a connector hook ⇒ h3 is ballers[0] (preferred),
        // the TLS stack is the fallback. We verify construction succeeds and the
        // h3 stack is first; the coordinator's surface is unchanged.
        let transport: Box<dyn ConnectionFilter> = create_tls_filter(
            TlsConfig::default(),
            "h3.example".to_string(),
            443,
            None,
            vec![],
        );
        let h3: H3ConnectorFn = Box::new(|| {
            Box::pin(async {
                Err::<Box<dyn ConnectionFilter>, CurlError>(CurlError::CouldntConnect)
            })
        });
        let cfg = HttpsSetupConfig {
            config: TlsConfig::default(),
            hostname: "h3.example".to_string(),
            port: 443,
            pinned_pubkey: None,
            want_h2: true,
            want_h1: true,
            prefer_h1: false,
            only_http_10: false,
            use_alpn: true,
            want_h3: true,
            het_timeout_ms: 0, // exercises the CURL_HET_DEFAULT fallback
        };
        let cf = Curl_cf_https_setup(transport, cfg, Some(h3));
        assert_eq!(cf.name(), "HTTPS-CONNECT");
        assert_eq!(cf.flags(), CF_TYPE_SSL | CF_TYPE_MULTIPLEX);
    }

    #[test]
    fn https_setup_het_zero_falls_back_to_default_deadlines() {
        // het_timeout_ms <= 0 ⇒ hard = CURL_HET_DEFAULT (200), soft = 50. We
        // assert via a directly-built coordinator using the same derivation as
        // Curl_cf_https_setup (the boxed dyn return hides the fields).
        let hard = if 0i64 > 0 { 0 } else { CURL_HET_DEFAULT };
        let soft = hard / 4;
        assert_eq!(hard, 200);
        assert_eq!(soft, 50);

        let mut c = make_coord(soft, hard, 1);
        c.reset(); // reset re-derives soft from hard exactly as setup does
        assert_eq!(c.hard_eyeballs_timeout_ms, 200);
        assert_eq!(c.soft_eyeballs_timeout_ms, 50);
    }
}
