// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.
//! HTTPS-connect / HTTP-version "eyeballing" connection filter.
//!
//! This module is the Rust port of curl's `lib/cf-https-connect.c` (774 lines)
//! and its header `lib/cf-https-connect.h` (48 lines), the `!CURL_DISABLE_HTTP`
//! layer that decides *how* to reach an HTTPS origin. It implements the two
//! public entry points those files expose, plus the connection filter that
//! backs them:
//!
//! 1. [`https_setup`] (← `Curl_cf_https_setup`) — builds the correct connect
//!    filter stack for an HTTPS origin (deciding whether to attempt
//!    HTTP/3-over-QUIC, HTTP/2, and/or HTTP/1.1) and for an HTTPS proxy
//!    (TLS-to-proxy).
//! 2. [`http_connect_add`] (← `Curl_cf_http_connect_add`) — installs the
//!    eyeballing filter configured with which "ballers" (HTTP-version attempts)
//!    to run.
//! 3. [`HttpsConnectFilter`] (← `Curl_cft_http_connect` / `struct cf_hc_ctx`) —
//!    the "eyeballing" filter itself: when the requested HTTP version allows it
//!    (e.g. `--http3`, or Alt-Svc/HTTPS-RR advertising `h3`), curl races an
//!    **H3/QUIC baller** against an **H2/H1-over-TLS baller** and adopts the
//!    winner. This is Happy Eyeballs, but *across HTTP versions and transports*
//!    rather than across address families.
//!
//! # Relationship to the C source-of-truth
//!
//! The port mirrors `cf-https-connect.c` closely so `--trace` diagnostics and
//! the connect race stay faithful to curl 8.x:
//!
//! * [`CfHcState`] mirrors the C `cf_hc_state`
//!   (`CF_HC_INIT`/`CF_HC_CONNECT`/`CF_HC_SUCCESS`/`CF_HC_FAILURE`).
//! * [`HcBaller`] mirrors `struct cf_hc_baller` (one HTTP-version attempt: its
//!   name, sub-chain, last result, start time, reply time, transport, ALPN id,
//!   and the `shutdown` flag).
//! * [`HttpsConnectFilter`] mirrors `struct cf_hc_ctx` and the
//!   `Curl_cft_http_connect` descriptor. Its [`name`](ConnectionFilter::name)
//!   is `"HTTPS-CONNECT"`, matching `cft->name`.
//! * The two-baller race, the soft/hard "eyeballs" timeouts
//!   (`ctx->soft_eyeballs_timeout_ms` = `happy_eyeballs_timeout / 4`,
//!   `ctx->hard_eyeballs_timeout_ms` = `happy_eyeballs_timeout`), the
//!   `time_to_start_next` stagger, "first to connect wins, tear down the rest",
//!   and the max-across-ballers timer aggregation (`cf_get_max_baller_time`)
//!   all follow the C step for step.
//!
//! # Design constraints (from the Agent Action Plan)
//!
//! * **Zero `unsafe`.** The crate root sets `#![forbid(unsafe_code)]`; this
//!   module contains no `unsafe` of any kind. Ballers are raced with
//!   [`FuturesUnordered`](futures_util::stream::FuturesUnordered) driven by
//!   [`tokio::select!`] and [`tokio::time::sleep`] timers — no busy-waiting and
//!   no manual poll loop.
//! * **Tokio-only async.**
//! * **No dependency on `crate::protocols`.** The actual HTTP/1.1, HTTP/2, and
//!   HTTP/3 protocol handlers live in `crate::protocols`, which depends on
//!   `crate::conn`; importing it here would create a cycle. Instead this module
//!   models the *transport/ALPN* decision (QUIC for `h3` vs TCP+TLS for
//!   `h2`/`h1`) and leaves the protocol-handler wiring to `connect.rs` /
//!   `crate::protocols`. A baller declares victory once its **transport**
//!   connect completes (TLS handshake for H21, QUIC handshake for H3).
//! * **H3/QUIC uses quinn's own `rustls` configuration**, *not*
//!   [`crate::tls::TlsConnector`] (a `tokio-rustls` TCP adapter). The H2/H1
//!   baller uses
//!   [`TlsConnector::from_config`](crate::tls::TlsConnector::from_config)`(cfg)?.connect(name, tcp)`.
//! * **Minimal Change Mandate.** curl's version-eyeballing and https-setup
//!   decisions are reproduced; no new negotiation behavior is introduced.
//!
//! # Error mapping
//!
//! * Transport connect failure (all ballers failed) → [`Error::connect`]
//!   (curl `CURLE_COULDNT_CONNECT`, 7), carrying the first baller's specific
//!   error when available.
//! * TLS certificate-verification failure →
//!   [`CurlCode::PeerFailedVerification`] (60); other TLS handshake failure →
//!   [`CurlCode::SslConnectError`] (35) (mapped by [`crate::tls::TlsConnector`]).
//! * Overall connect deadline exceeded → [`CurlCode::OperationTimedout`] (28).

use std::any::Any;
use std::future::Future;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::stream::{FuturesUnordered, StreamExt};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig as QuinnClientConfig, Connection as QuinnConnection, Endpoint};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::conn::filters::{CfFuture, ConnectionFilter, FilterCtx, Pollset, QueryCtx, QueryOut};
use crate::conn::{h1_proxy, CfQuery, CfType, Connection, FilterChain, ProxyType, Transport};
use crate::error::{CurlCode, Error, Result};
use crate::tls::{TlsConfig, TlsConnector, TlsStream};

// ---------------------------------------------------------------------------
// A note on the sibling connection-filter modules.
//
// curl's `cf_hc_baller_init` builds each baller's sub-chain out of a *socket*
// filter, an optional *happy-eyeballs* IP filter, and a *TLS* (or *QUIC*)
// filter — three stacked `Curl_cftype`s (`cf-setup.c`). This port cannot layer
// [`crate::conn::socket`] / [`crate::conn::happy_eyeballs`] *beneath*
// [`crate::tls::TlsConnector`], because the tokio-rustls adapter used by
// `crate::tls` (matching the pattern in `protocols/gopher.rs` and
// `protocols/mqtt.rs`) requires an **owned** `AsyncRead + AsyncWrite` stream,
// and a `SocketFilter` never surrenders its stream by value — the only handoff
// it offers (`CF_CTRL_FORGET_SOCKET`) yields a bare file descriptor whose
// reconstruction into a `tokio::net::TcpStream` would require `unsafe`
// `from_raw_fd`, which is forbidden crate-wide. The same reasoning rules out
// layering `crate::conn::haproxy` (its PROXY-protocol preamble must precede the
// TLS bytes on the raw socket) and `crate::conn::h2_proxy` (its `insert_after`
// is generic over a live transport stream that does not exist at
// stack-build time).
//
// The baller therefore *fuses* the socket connect with the TLS/QUIC handshake
// inside a single leaf filter ([`TlsEstablishFilter`] / [`QuicEstablishFilter`]),
// exactly as `crate::tls::TlsConnector::connect` and `quinn::Endpoint::connect`
// are designed to be used. The one sibling that composes correctly *above* the
// fused proxy-TLS filter — the HTTP/1.1 `CONNECT` tunnel
// [`crate::conn::h1_proxy`], which delegates its byte I/O through the chain — is
// used verbatim in the HTTPS-proxy path of [`https_setup`].
// ---------------------------------------------------------------------------

// ===========================================================================
// Transport & timing constants (curl exact values)
// ===========================================================================

/// curl's `TRNSPRT_TCP` (`urldata.h`): the transport tag for a TCP connection,
/// used by the H2/H1 baller. Numerically equal to [`Transport::Tcp`]`.as_u8()`.
pub const TRNSPRT_TCP: u8 = 3;

/// curl's `TRNSPRT_QUIC` (`urldata.h`): the transport tag for a QUIC
/// connection, used by the H3 baller. Numerically equal to
/// [`Transport::Quic`]`.as_u8()`.
pub const TRNSPRT_QUIC: u8 = 5;

/// The default hard "eyeballs" timeout, in milliseconds.
///
/// curl seeds `ctx->hard_eyeballs_timeout_ms` from
/// `data->set.happy_eyeballs_timeout`, which defaults to `CURL_HET_DEFAULT`
/// (200 ms, `include/curl/curl.h`). Once this elapses the fallback baller is
/// started even if the preferred baller has not yet failed
/// (`time_to_start_next`, `cf-https-connect.c:255`).
pub const DEFAULT_HARD_EYEBALLS_TIMEOUT_MS: u64 = 200;

/// The maximum number of ballers a single HTTPS-CONNECT filter races, matching
/// curl's fixed `struct cf_hc_baller ballers[2]` (`cf-https-connect.c:110`).
const MAX_BALLERS: usize = 2;

// ===========================================================================
// AlpnId — the ALPN protocol identity of a baller (curl `enum alpnid`).
// ===========================================================================

/// The ALPN protocol a baller represents, mirroring curl's `enum alpnid`
/// (`http.h`): `ALPN_none`, `ALPN_h1`, `ALPN_h2`, `ALPN_h3`.
///
/// Each baller carries the "primary" protocol it negotiates. The H2/H1 baller
/// records [`AlpnId::H2`] (its preferred protocol) while offering both `h2` and
/// `http/1.1` at the TLS layer, letting the server pick — this is the single
/// "h21" attempt described in the Agent Action Plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpnId {
    /// `ALPN_none` — no protocol (an unassigned baller slot).
    None,
    /// `ALPN_h1` — HTTP/1.1 (`http/1.1`).
    H1,
    /// `ALPN_h2` — HTTP/2 (`h2`).
    H2,
    /// `ALPN_h3` — HTTP/3 (`h3`).
    H3,
}

impl AlpnId {
    /// The diagnostic baller name curl assigns per ALPN in
    /// `cf_hc_baller_assign` (`cf-https-connect.c:121`): `"h3"`, `"h2"`, `"h1"`.
    fn baller_name(self) -> &'static str {
        match self {
            AlpnId::H3 => "h3",
            AlpnId::H2 => "h2",
            AlpnId::H1 => "h1",
            AlpnId::None => "none",
        }
    }

    /// The transport a baller of this ALPN uses, reproducing
    /// `cf_hc_baller_assign`: `ALPN_h3` forces [`Transport::Quic`]
    /// (`TRNSPRT_QUIC`); every other ALPN keeps the default TCP transport.
    fn transport(self) -> Transport {
        match self {
            AlpnId::H3 => Transport::Quic,
            _ => Transport::Tcp,
        }
    }

    /// The ALPN wire identifiers this baller offers to the server. The H3
    /// baller offers only `h3`; the H2/H1 baller offers `h2` then `http/1.1`
    /// (the server chooses), matching curl's TLS ALPN offer for an
    /// `h2`-preferred HTTPS connection.
    fn alpn_offer(self) -> Vec<Vec<u8>> {
        match self {
            AlpnId::H3 => vec![crate::tls::ALPN_H3.to_vec()],
            AlpnId::H2 => vec![
                crate::tls::ALPN_H2.to_vec(),
                crate::tls::ALPN_HTTP_1_1.to_vec(),
            ],
            AlpnId::H1 => vec![crate::tls::ALPN_HTTP_1_1.to_vec()],
            AlpnId::None => Vec::new(),
        }
    }
}

// ===========================================================================
// CfHcState — the connect state machine (curl `cf_hc_state`).
// ===========================================================================

/// The connect state of the HTTPS-CONNECT filter, mirroring curl's
/// `typedef enum { CF_HC_INIT, CF_HC_CONNECT, CF_HC_SUCCESS, CF_HC_FAILURE }
/// cf_hc_state` (`cf-https-connect.c:41`).
///
/// In curl the multi state machine calls `cf_hc_connect` repeatedly and the
/// state advances `INIT → CONNECT → SUCCESS`/`FAILURE`. In this async port the
/// whole race runs to completion inside a single `connect().await`, but the
/// state is still tracked so a re-entrant call after success short-circuits and
/// so `--trace` diagnostics carry the same vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CfHcState {
    /// `CF_HC_INIT`: nothing started yet.
    Init,
    /// `CF_HC_CONNECT`: ballers are being raced.
    Connect,
    /// `CF_HC_SUCCESS`: a winner has been chosen and installed as `next`.
    Success,
    /// `CF_HC_FAILURE`: every baller failed.
    Failure,
}

// ===========================================================================
// Small shared helpers.
// ===========================================================================

/// Milliseconds elapsed since `t`, saturating into `u64`.
#[inline]
fn ms_since(t: Instant) -> u64 {
    u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Produces an [`Error`] carrying the same [`CurlCode`] and message as `err`.
///
/// [`Error`] is deliberately not [`Clone`] (some variants wrap non-cloneable
/// transport errors), but the failure path only needs the *code* and a message
/// to reproduce curl's "first baller's specific error" behaviour, so this
/// rebuilds an equivalent error via [`Error::with_context`]. This mirrors the
/// identical helper in [`crate::conn::happy_eyeballs`].
fn clone_err(err: &Error) -> Error {
    Error::with_context(err.code(), err.to_string())
}

/// curl's `CURL_SOCKET_BAD` — the sentinel for "no socket". Reported by a
/// baller whose transport does not expose a pollable descriptor (QUIC, whose
/// UDP socket is owned privately by the `quinn` endpoint).
const CURL_SOCKET_BAD: i32 = -1;

// ===========================================================================
// EstablishSpec — the recipe for a baller's fused transport+security connect.
// ===========================================================================

/// Everything a baller's leaf filter needs to open its transport and complete
/// its security handshake.
///
/// In curl this information is threaded into `cf_hc_baller_init` and consumed by
/// `Curl_cf_setup_insert_after` to build the socket + TLS/QUIC sub-chain. Here
/// it is carried by value into the leaf filter that fuses those layers (see the
/// module-level note on why they are fused rather than stacked).
#[derive(Clone)]
struct EstablishSpec {
    /// `true` selects the QUIC/H3 leaf ([`QuicEstablishFilter`]); `false`
    /// selects the TCP+TLS/H21 leaf ([`TlsEstablishFilter`]).
    quic: bool,
    /// The host (DNS name or IP literal) to open the transport to. This is the
    /// connect target, which for a proxied or IP-pinned connection may differ
    /// from [`server_name`](Self::server_name).
    host: String,
    /// The port to connect to.
    port: u16,
    /// The TLS server name: both the SNI sent in the handshake and the identity
    /// the peer certificate is verified against (curl's `hostname` vs
    /// `conn->host.name` distinction).
    server_name: String,
    /// The base TLS configuration (verification policy, CA material, version
    /// bounds). The ALPN offer is layered on per-baller from
    /// [`alpn`](Self::alpn) so the same config can back both ballers.
    tls_config: Arc<TlsConfig>,
    /// The ALPN protocols this baller offers, most-preferred first
    /// (`[h2, http/1.1]` for the H21 baller, `[h3]` for the H3 baller).
    alpn: Vec<Vec<u8>>,
}

/// Resolves `host:port` to a list of socket addresses using the Tokio system
/// resolver.
///
/// This is the in-filter DNS step, mirroring curl's socket filter resolving at
/// connect time (`cf-socket.c`). The Tokio resolver is used directly rather
/// than `crate::dns` to keep this module's dependency surface to its declared
/// set; `crate::dns` is not one of its dependencies. IP literals resolve
/// trivially through the same path.
async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| {
            Error::with_context(
                CurlCode::CouldntResolveHost,
                format!("could not resolve host '{host}': {e}"),
            )
        })?
        .collect();
    if addrs.is_empty() {
        return Err(Error::with_context(
            CurlCode::CouldntResolveHost,
            format!("no addresses returned for host '{host}'"),
        ));
    }
    Ok(addrs)
}

/// Opens a TCP connection, trying each candidate address in order and returning
/// the first that succeeds (curl's per-address connect loop). Every failure is
/// mapped to [`CurlCode::CouldntConnect`] (7), preserving the last error's text.
async fn connect_tcp(addrs: &[SocketAddr]) -> Result<TcpStream> {
    let mut last: Option<Error> = None;
    for &addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                last = Some(Error::connect(format!("connect to {addr} failed: {e}")));
            }
        }
    }
    Err(last.unwrap_or_else(|| Error::connect("no address available to connect to")))
}

/// Translates a baller's ALPN offer / negotiated protocol into a stored string,
/// treating the empty (`AlpnProtocol::None`) case as "no ALPN negotiated".
fn alpn_str_or_none(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

// ===========================================================================
// TlsEstablishFilter — the H21 baller leaf (TCP + rustls over an owned stream).
// ===========================================================================

/// The leaf filter of the **H2/H1 baller**: it opens a TCP connection and
/// completes a TLS handshake over the *owned* stream via
/// [`crate::tls::TlsConnector`], offering `h2` then `http/1.1` by ALPN and
/// letting the server choose. It is curl's `socket` + `ssl` sub-chain, fused
/// (see the module note), and matches the connect pattern used by
/// `protocols/gopher.rs` and `protocols/mqtt.rs`.
///
/// Once connected, [`send`](ConnectionFilter::send)/[`recv`](ConnectionFilter::recv)
/// perform record I/O against the stored [`TlsStream`]; the actual HTTP/1.1 or
/// HTTP/2 protocol handler is wired *above* this filter by `connect.rs` /
/// `crate::protocols`.
struct TlsEstablishFilter {
    /// The connect recipe (host/port/server-name/config/ALPN).
    spec: EstablishSpec,
    /// The negotiated TLS stream, populated once the handshake completes.
    stream: Option<TlsStream<TcpStream>>,
    /// The raw descriptor of the underlying TCP socket, captured *before* the
    /// handshake consumes the stream so [`adjust_pollset`](ConnectionFilter::adjust_pollset)
    /// and the `CF_QUERY_SOCKET` query can report it without `unsafe`.
    raw_fd: Option<i32>,
    /// When the connect attempt began (curl's `baller->started`).
    started_at: Option<Instant>,
    /// When the TCP connection was established (`CF_QUERY_TIMER_CONNECT`).
    connected_at: Option<Instant>,
    /// When the TLS handshake completed (`CF_QUERY_TIMER_APPCONNECT`).
    app_connected_at: Option<Instant>,
    /// The ALPN protocol the server selected (`h2` or `http/1.1`), if any.
    negotiated_alpn: Option<String>,
}

impl TlsEstablishFilter {
    /// Builds an unconnected H21 baller leaf from its [`EstablishSpec`].
    fn new(spec: EstablishSpec) -> Self {
        TlsEstablishFilter {
            spec,
            stream: None,
            raw_fd: None,
            started_at: None,
            connected_at: None,
            app_connected_at: None,
            negotiated_alpn: None,
        }
    }
}

impl ConnectionFilter for TlsEstablishFilter {
    fn name(&self) -> &'static str {
        // curl names the TLS transport filter "SSL"; preserved for --trace.
        "SSL"
    }

    fn cf_type(&self) -> CfType {
        // A TLS-over-TCP transport layer (curl's `Curl_cft_ssl.flags = CF_TYPE_SSL`).
        CfType::SSL
    }

    fn connect<'a>(
        &'a mut self,
        _cx: &'a mut FilterCtx<'_>,
        _blocking: bool,
    ) -> CfFuture<'a, Result<bool>> {
        Box::pin(async move {
            if self.stream.is_some() {
                return Ok(true);
            }
            if self.started_at.is_none() {
                self.started_at = Some(Instant::now());
            }

            // 1. DNS + TCP connect (the fused "socket" layer).
            let addrs = resolve(&self.spec.host, self.spec.port).await?;
            let tcp = connect_tcp(&addrs).await?;
            // Capture the descriptor before the handshake takes the stream by
            // value; `AsRawFd::as_raw_fd` is a safe, non-consuming borrow.
            self.raw_fd = Some(tcp.as_raw_fd());
            self.connected_at = Some(Instant::now());

            // 2. TLS handshake over the owned stream (the fused "ssl" layer).
            //    ALPN is layered onto the shared base config per-baller.
            let cfg = (*self.spec.tls_config)
                .clone()
                .with_alpn(self.spec.alpn.clone());
            let connector = TlsConnector::from_config(&cfg)?;
            let tls = connector.connect(&self.spec.server_name, tcp).await?;
            self.app_connected_at = Some(Instant::now());
            self.negotiated_alpn = alpn_str_or_none(tls.negotiated_alpn().as_str());
            self.stream = Some(tls);
            Ok(true)
        })
    }

    fn send<'a>(
        &'a mut self,
        _cx: &'a mut FilterCtx<'_>,
        buf: &'a [u8],
        _eos: bool,
    ) -> CfFuture<'a, Result<usize>> {
        Box::pin(async move {
            match self.stream.as_mut() {
                Some(stream) => stream.write(buf).await.map_err(|e| {
                    Error::with_context(CurlCode::SendError, format!("TLS write failed: {e}"))
                }),
                None => Err(Error::with_context(
                    CurlCode::SendError,
                    "TLS stream is not connected",
                )),
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
                Some(stream) => stream.read(buf).await.map_err(|e| {
                    Error::with_context(CurlCode::RecvError, format!("TLS read failed: {e}"))
                }),
                None => Err(Error::with_context(
                    CurlCode::RecvError,
                    "TLS stream is not connected",
                )),
            }
        })
    }

    fn adjust_pollset(&self, _cx: &QueryCtx<'_>, ps: &mut Pollset) {
        // Once connected, register the socket as readable so the driving loop
        // wakes on inbound data (curl's cf_socket_adjust_pollset "connected but
        // not active → POLLIN" case).
        if let Some(fd) = self.raw_fd {
            if self.stream.is_some() {
                ps.add_in(fd);
            }
        }
    }

    fn close(&mut self, _cx: &mut FilterCtx<'_>) {
        // Dropping the stream closes the socket; there is no lower filter.
        self.stream = None;
        self.raw_fd = None;
    }

    fn query(&self, cx: &QueryCtx<'_>, query: CfQuery, out: &mut QueryOut) -> Result<()> {
        match query {
            CfQuery::Socket => {
                *out = QueryOut::Socket(self.raw_fd.unwrap_or(CURL_SOCKET_BAD));
                Ok(())
            }
            CfQuery::Transport => {
                *out = QueryOut::Transport(Transport::Tcp);
                Ok(())
            }
            CfQuery::TimerConnect => match self.connected_at {
                Some(when) => {
                    *out = QueryOut::TimerConnect(when);
                    Ok(())
                }
                None => cx.query_next(query, out),
            },
            CfQuery::TimerAppConnect => match self.app_connected_at {
                Some(when) => {
                    *out = QueryOut::TimerAppConnect(when);
                    Ok(())
                }
                None => cx.query_next(query, out),
            },
            CfQuery::AlpnNegotiated => {
                if let Some(alpn) = &self.negotiated_alpn {
                    *out = QueryOut::AlpnNegotiated(alpn.clone());
                }
                Ok(())
            }
            _ => cx.query_next(query, out),
        }
    }
}

// ===========================================================================
// QuicEstablishFilter — the H3 baller leaf (QUIC via quinn's own rustls).
// ===========================================================================

/// The leaf filter of the **H3 baller**: it establishes a QUIC connection with
/// [`quinn`], which carries its **own** `rustls` `ClientConfig` (built from the
/// baller's [`TlsConfig`] with the `h3` ALPN) — deliberately *not*
/// [`crate::tls::TlsConnector`], because that adapter is TCP/`tokio-rustls`
/// specific while QUIC needs rustls' QUIC-suite integration.
///
/// Per the Agent Action Plan, this port only needs the QUIC transport handshake
/// to complete for the baller to win; the HTTP/3 framing (`h3`/`h3-quinn`)
/// lives in `crate::protocols` and is wired on top by `connect.rs`. The
/// established [`quinn::Connection`] and its [`quinn::Endpoint`] are therefore
/// retained (dropping the endpoint would tear the connection down) for the
/// protocol layer to adopt, and byte-stream [`send`](ConnectionFilter::send)/
/// [`recv`](ConnectionFilter::recv) are intentionally unavailable on this leaf.
struct QuicEstablishFilter {
    /// The connect recipe (host/port/server-name/config; ALPN is forced to `h3`).
    spec: EstablishSpec,
    /// The bound QUIC endpoint. Retained to keep the connection alive.
    endpoint: Option<Endpoint>,
    /// The established QUIC connection, populated once the handshake completes.
    connection: Option<QuinnConnection>,
    /// When the connect attempt began (curl's `baller->started`).
    started_at: Option<Instant>,
    /// When the QUIC handshake completed. QUIC fuses transport and TLS
    /// establishment, so this instant answers both `CF_QUERY_TIMER_CONNECT` and
    /// `CF_QUERY_TIMER_APPCONNECT` (curl's special-case for UDP/QUIC).
    connected_at: Option<Instant>,
}

impl QuicEstablishFilter {
    /// Builds an unconnected H3 baller leaf from its [`EstablishSpec`].
    fn new(spec: EstablishSpec) -> Self {
        QuicEstablishFilter {
            spec,
            endpoint: None,
            connection: None,
            started_at: None,
            connected_at: None,
        }
    }

    /// Builds the `quinn` client configuration from the baller's TLS config.
    ///
    /// The baller's [`TlsConfig`] (verification policy, CA material, version
    /// bounds) is reused with the `h3` ALPN, built into an
    /// [`Arc<rustls::ClientConfig>`](rustls::ClientConfig), and adapted into a
    /// [`quinn::crypto::rustls::QuicClientConfig`]. A conversion failure means
    /// the negotiated cipher suites lack a QUIC-compatible initial secret and
    /// is surfaced as [`CurlCode::SslConnectError`] (35).
    fn build_quinn_config(spec: &EstablishSpec) -> Result<QuinnClientConfig> {
        let rustls_cfg = (*spec.tls_config)
            .clone()
            .with_alpn(vec![crate::tls::ALPN_H3.to_vec()])
            .build()?;
        let quic_cfg = QuicClientConfig::try_from(rustls_cfg).map_err(|e| {
            Error::with_context(
                CurlCode::SslConnectError,
                format!("QUIC TLS configuration is not usable: {e}"),
            )
        })?;
        Ok(QuinnClientConfig::new(Arc::new(quic_cfg)))
    }
}

impl ConnectionFilter for QuicEstablishFilter {
    fn name(&self) -> &'static str {
        // curl names the QUIC transport filter after the h3 backend; "QUIC"
        // is the stable, backend-neutral trace name for the consolidated stack.
        "QUIC"
    }

    fn cf_type(&self) -> CfType {
        // QUIC provides encryption (SSL) and native stream multiplexing
        // (curl's quic filter is CF_TYPE_SSL | CF_TYPE_MULTIPLEX).
        CfType::SSL | CfType::MULTIPLEX
    }

    fn connect<'a>(
        &'a mut self,
        _cx: &'a mut FilterCtx<'_>,
        _blocking: bool,
    ) -> CfFuture<'a, Result<bool>> {
        Box::pin(async move {
            if self.connection.is_some() {
                return Ok(true);
            }
            if self.started_at.is_none() {
                self.started_at = Some(Instant::now());
            }

            // Resolve and pick the first address; QUIC connects to a single
            // remote (quinn does not itself race addresses).
            let addrs = resolve(&self.spec.host, self.spec.port).await?;
            let remote = addrs[0];

            // quinn uses its OWN rustls config (not crate::tls::TlsConnector).
            let client_cfg = Self::build_quinn_config(&self.spec)?;

            // Bind a local UDP endpoint in the same address family as the peer.
            let bind: SocketAddr = if remote.is_ipv6() {
                SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 0], 0))
            } else {
                SocketAddr::from(([0u8, 0, 0, 0], 0))
            };
            let mut endpoint = Endpoint::client(bind)
                .map_err(|e| Error::connect(format!("could not create QUIC endpoint: {e}")))?;
            endpoint.set_default_client_config(client_cfg);

            // Initiate and await the QUIC handshake.
            let connecting = endpoint
                .connect(remote, &self.spec.server_name)
                .map_err(|e| Error::connect(format!("QUIC connect setup failed: {e}")))?;
            let connection = connecting
                .await
                .map_err(|e| Error::connect(format!("QUIC handshake failed: {e}")))?;

            self.connected_at = Some(Instant::now());
            self.endpoint = Some(endpoint);
            self.connection = Some(connection);
            Ok(true)
        })
    }

    fn send<'a>(
        &'a mut self,
        _cx: &'a mut FilterCtx<'_>,
        _buf: &'a [u8],
        _eos: bool,
    ) -> CfFuture<'a, Result<usize>> {
        // HTTP/3 framing is owned by crate::protocols; this transport leaf does
        // not expose a byte stream (QUIC is stream-multiplexed, not a socket).
        Box::pin(async move {
            Err(Error::with_context(
                CurlCode::SendError,
                "QUIC transport does not provide a byte stream; HTTP/3 framing is handled by the protocol layer",
            ))
        })
    }

    fn recv<'a>(
        &'a mut self,
        _cx: &'a mut FilterCtx<'_>,
        _buf: &'a mut [u8],
    ) -> CfFuture<'a, Result<usize>> {
        Box::pin(async move {
            Err(Error::with_context(
                CurlCode::RecvError,
                "QUIC transport does not provide a byte stream; HTTP/3 framing is handled by the protocol layer",
            ))
        })
    }

    fn adjust_pollset(&self, _cx: &QueryCtx<'_>, _ps: &mut Pollset) {
        // quinn owns and drives its UDP socket on its own Tokio tasks; there is
        // no descriptor for curl's pollset to register.
    }

    fn close(&mut self, _cx: &mut FilterCtx<'_>) {
        // Drop the connection then the endpoint (order irrelevant for cleanup).
        self.connection = None;
        self.endpoint = None;
    }

    fn query(&self, cx: &QueryCtx<'_>, query: CfQuery, out: &mut QueryOut) -> Result<()> {
        match query {
            CfQuery::Socket => {
                *out = QueryOut::Socket(CURL_SOCKET_BAD);
                Ok(())
            }
            CfQuery::Transport => {
                *out = QueryOut::Transport(Transport::Quic);
                Ok(())
            }
            // QUIC fuses transport + TLS: the single handshake instant answers
            // both timers (curl's UDP/QUIC special-case in cf_socket_query).
            CfQuery::TimerConnect | CfQuery::TimerAppConnect => match self.connected_at {
                Some(when) => {
                    *out = if matches!(query, CfQuery::TimerConnect) {
                        QueryOut::TimerConnect(when)
                    } else {
                        QueryOut::TimerAppConnect(when)
                    };
                    Ok(())
                }
                None => cx.query_next(query, out),
            },
            CfQuery::AlpnNegotiated => {
                // Success over the h3-only offer implies h3 was negotiated.
                if self.connection.is_some() {
                    *out = QueryOut::AlpnNegotiated("h3".to_string());
                }
                Ok(())
            }
            _ => cx.query_next(query, out),
        }
    }
}

/// The default establish-filter factory: turns an [`EstablishSpec`] into the
/// concrete leaf filter that opens the transport.
///
/// This is the production path. Tests substitute their own factory via
/// [`HttpsConnectFilter::with_establish_factory`] to inject deterministic
/// stand-ins (immediate success, refusal, or a black hole).
fn default_establish(spec: &EstablishSpec) -> Box<dyn ConnectionFilter> {
    if spec.quic {
        Box::new(QuicEstablishFilter::new(spec.clone()))
    } else {
        Box::new(TlsEstablishFilter::new(spec.clone()))
    }
}

// ===========================================================================
// HcBaller — one HTTP-version attempt (curl `struct cf_hc_baller`).
// ===========================================================================

/// A single "baller": one HTTP-version connect attempt raced against the
/// other(s). Mirrors curl's `struct cf_hc_baller` (`cf-https-connect.c:100`).
///
/// In curl the baller owns its live sub-chain in `cf`. In this async port the
/// sub-chain is driven to completion inside the race future (see
/// [`HttpsConnectFilter::run_connect`]); the winner's chain is moved into
/// [`HttpsConnectFilter::winner`], while a baller that *failed* has its chain
/// parked back in [`cf`](Self::cf) so the shutdown loop can tear it down —
/// preserving the semantics of curl's `cf_hc_baller_reset` / shutdown code.
struct HcBaller {
    /// Diagnostic name (`"h3"`/`"h2"`/`"h1"`), curl's `baller->name`.
    name: &'static str,
    /// The ALPN identity this baller negotiates (curl's `baller->alpn_id`).
    alpn_id: AlpnId,
    /// The transport this baller uses (curl's `baller->transport`).
    transport: Transport,
    /// The recipe used to build this baller's leaf filter when it is started.
    spec: EstablishSpec,
    /// When this baller was started, or `None` if not started yet
    /// (curl's `baller->started`; a zeroed `curltime` means "not started").
    started: Option<Instant>,
    /// The failure result, or `None` while in flight or on success
    /// (curl's `baller->result`; `CURLE_OK` means "still good").
    result: Option<Error>,
    /// Milliseconds until the first server reply, or `-1` if unknown
    /// (curl's `baller->reply_ms`, default `-1`).
    reply_ms: i64,
    /// Whether this (failed) baller's chain has been shut down
    /// (curl's `baller->shutdown` bitfield).
    shutdown: bool,
    /// A parked, failed sub-chain awaiting shutdown, or `None`. The winning
    /// chain never lives here — it is moved into [`HttpsConnectFilter::winner`].
    cf: Option<FilterChain>,
}

impl HcBaller {
    /// Creates a baller for `alpn_id` with the given connect recipe, in the
    /// unstarted state (curl's `cf_hc_baller_assign` followed by the zeroed
    /// runtime fields).
    fn new(alpn_id: AlpnId, spec: EstablishSpec) -> Self {
        HcBaller {
            name: alpn_id.baller_name(),
            alpn_id,
            transport: alpn_id.transport(),
            spec,
            started: None,
            result: None,
            reply_ms: -1,
            shutdown: false,
            cf: None,
        }
    }

    /// Whether this baller has been started at all (curl tests
    /// `Curl_timediff(now, b->started)` against a zeroed start time).
    fn has_started(&self) -> bool {
        self.started.is_some()
    }

    /// Resets the baller to its unstarted state, closing and dropping any parked
    /// sub-chain. Mirrors `cf_hc_baller_reset`: close `cf`, clear `result`, and
    /// restore `reply_ms = -1`.
    fn reset(&mut self) {
        if let Some(mut chain) = self.cf.take() {
            chain.close();
        }
        self.started = None;
        self.result = None;
        self.reply_ms = -1;
        self.shutdown = false;
    }
}

// ===========================================================================
// HttpsConnectFilter — the eyeballing filter (curl `struct cf_hc_ctx`).
// ===========================================================================

/// Type alias for a settled baller attempt returned by the race future:
/// `(baller index, its sub-chain, connect result)`.
type BallerOutcome = (usize, FilterChain, Result<bool>);

/// A boxed, `Send` future that drives one baller's sub-chain to completion.
type BallerFut = Pin<Box<dyn Future<Output = BallerOutcome> + Send>>;

/// The HTTPS "eyeballing" connection filter — curl's `Curl_cft_http_connect`
/// backed by `struct cf_hc_ctx` (`cf-https-connect.c`).
///
/// It races up to [`MAX_BALLERS`] ballers (an H3/QUIC attempt and/or an
/// H2/H1-over-TLS attempt) and adopts the first to connect, exactly as curl's
/// `cf_hc_connect` does — "Happy Eyeballs across HTTP versions". After a winner
/// is chosen every filter operation delegates to the winning sub-chain held in
/// [`winner`](Self::winner).
///
/// This filter is the single public filter type of the module and is installed
/// by [`https_setup`] / [`http_connect_add`].
pub struct HttpsConnectFilter {
    /// The connect state machine (curl's `ctx->state`).
    state: CfHcState,
    /// The ballers being raced (1 or 2), in start-preference order: the
    /// preferred version is `ballers[0]`, the fallback is `ballers[1]`.
    ballers: Vec<HcBaller>,
    /// The winning sub-chain, once a baller has connected. All post-success
    /// filter operations delegate here (curl sets `cf->next = winner->cf`).
    winner: Option<FilterChain>,
    /// The socket index this filter serves (`FIRSTSOCKET`/`SECONDARYSOCKET`).
    sockindex: usize,
    /// When the race began (curl's `ctx->started`).
    started: Option<Instant>,
    /// The soft eyeballs timeout in ms: once it elapses and the preferred
    /// baller has produced no reply, the fallback baller is started
    /// (curl's `ctx->soft_eyeballs_timeout_ms` = `happy_eyeballs_timeout / 4`).
    soft_eyeballs_timeout_ms: u64,
    /// The hard eyeballs timeout in ms: once it elapses the fallback baller is
    /// started unconditionally (curl's `ctx->hard_eyeballs_timeout_ms` =
    /// `happy_eyeballs_timeout`).
    hard_eyeballs_timeout_ms: u64,
    /// An optional overall deadline for the whole race, in ms. Exceeding it
    /// yields [`CurlCode::OperationTimedout`] (28).
    overall_timeout_ms: Option<u64>,
    /// The first baller failure observed, returned when every baller fails
    /// (curl's `cf_hc_connect` returns `ctx->ballers[0].result`).
    first_err: Option<Error>,
    /// Whether the winning chain carries TLS, so [`cf_type`](ConnectionFilter::cf_type)
    /// can OR in [`CfType::SSL`] after success (both baller kinds use TLS, so
    /// this becomes `true` on any win).
    winner_has_tls: bool,
    /// Factory that builds a baller's leaf filter from its [`EstablishSpec`].
    /// Overridable for tests; defaults to [`default_establish`].
    establish_factory: fn(&EstablishSpec) -> Box<dyn ConnectionFilter>,
}

impl HttpsConnectFilter {
    /// Builds an eyeballing filter over the given ballers for `sockindex`, with
    /// curl's default soft/hard eyeballs timeouts
    /// (`hard = CURL_HET_DEFAULT`, `soft = hard / 4`) and no overall deadline.
    fn new(ballers: Vec<HcBaller>, sockindex: usize) -> Self {
        let hard = DEFAULT_HARD_EYEBALLS_TIMEOUT_MS;
        HttpsConnectFilter {
            state: CfHcState::Init,
            ballers,
            winner: None,
            sockindex,
            started: None,
            soft_eyeballs_timeout_ms: hard / 4,
            hard_eyeballs_timeout_ms: hard,
            overall_timeout_ms: None,
            first_err: None,
            winner_has_tls: false,
            establish_factory: default_establish,
        }
    }

    /// Overrides the hard eyeballs timeout (ms), recomputing the soft timeout as
    /// `hard / 4` to preserve curl's ratio (`cf_hc_reset`).
    ///
    /// Test-only: production callers use the curl-default timeouts seeded by
    /// [`new`](Self::new); the deterministic timing tests use this to compress
    /// or stretch the stagger window.
    #[cfg(test)]
    #[must_use]
    fn with_hard_eyeballs_timeout_ms(mut self, ms: u64) -> Self {
        self.hard_eyeballs_timeout_ms = ms;
        self.soft_eyeballs_timeout_ms = ms / 4;
        self
    }

    /// Sets an overall deadline (ms) for the entire race.
    ///
    /// Test-only: the production deadline is owned by the connection/transfer
    /// layer; the timeout test uses this to bound a black-hole race.
    #[cfg(test)]
    #[must_use]
    fn with_overall_timeout_ms(mut self, ms: u64) -> Self {
        self.overall_timeout_ms = Some(ms);
        self
    }

    /// Overrides the establish-filter factory, letting tests inject
    /// deterministic transport stand-ins (immediate success, refusal, or a
    /// black hole) in place of [`default_establish`].
    ///
    /// Test-only: production always uses [`default_establish`], installed by
    /// [`new`](Self::new).
    #[cfg(test)]
    #[must_use]
    fn with_establish_factory(
        mut self,
        factory: fn(&EstablishSpec) -> Box<dyn ConnectionFilter>,
    ) -> Self {
        self.establish_factory = factory;
        self
    }

    /// Whether the baller at `idx` should be started now, given the elapsed
    /// race time. Faithful port of curl's `time_to_start_next`
    /// (`cf-https-connect.c:236`):
    ///
    /// * out of range or already started → never;
    /// * every *earlier* baller has already failed → **now** (nothing else is
    ///   racing, so do not wait);
    /// * the hard eyeballs timeout has elapsed → **now** (unconditional);
    /// * `idx > 0`, the soft timeout has elapsed, and the previous baller has
    ///   produced no reply yet (`reply_ms < 0`) → **now**;
    /// * otherwise → not yet.
    fn time_to_start_next(&self, idx: usize, race_start: Instant) -> bool {
        if idx >= self.ballers.len() {
            return false;
        }
        if self.ballers[idx].has_started() {
            return false;
        }
        // All previous ballers have already failed → start immediately.
        if self.ballers[..idx].iter().all(|b| b.result.is_some()) {
            return true;
        }
        let elapsed = ms_since(race_start);
        if elapsed >= self.hard_eyeballs_timeout_ms {
            return true;
        }
        if idx > 0 && elapsed >= self.soft_eyeballs_timeout_ms && self.ballers[idx - 1].reply_ms < 0
        {
            return true;
        }
        false
    }

    /// Milliseconds until the loop should re-evaluate scheduling decisions.
    ///
    /// While a baller is still unstarted this is the time to the nearest of the
    /// soft timeout, the hard timeout, and the overall deadline (so the stagger
    /// fires promptly); once all ballers are started only inflight completions
    /// matter, so a long sleep is returned and the `select!` wakes on the race
    /// instead. Always clamped to at least 1 ms so the timer makes progress.
    fn next_wake_ms(&self, started_count: usize, race_start: Instant) -> u64 {
        const LONG_SLEEP_MS: u64 = 3_600_000;
        let elapsed = ms_since(race_start);
        let mut next = LONG_SLEEP_MS;
        // The overall connect deadline always bounds the wait — regardless of
        // how many ballers have already started — so that `run_connect` re-checks
        // and honours it promptly even when every baller is stalled (e.g. a QUIC
        // black hole). If it has already elapsed, wake immediately.
        if let Some(overall) = self.overall_timeout_ms {
            if overall > elapsed {
                next = next.min(overall - elapsed);
            } else {
                return 1;
            }
        }
        // The staggered-start (soft/hard eyeballs) timers only matter while a
        // fallback baller is still waiting to be started; once every baller is
        // in flight there is nothing left to schedule on those boundaries.
        if started_count < self.ballers.len() {
            if self.soft_eyeballs_timeout_ms > elapsed {
                next = next.min(self.soft_eyeballs_timeout_ms - elapsed);
            }
            if self.hard_eyeballs_timeout_ms > elapsed {
                next = next.min(self.hard_eyeballs_timeout_ms - elapsed);
            }
        }
        next.clamp(1, LONG_SLEEP_MS)
    }
}

/// Drives a single baller's sub-chain to a terminal outcome.
///
/// Repeatedly calls the chain's non-blocking `connect` until it reports done
/// (`Ok(true)` → the baller connected) or errors (`Err` → the baller failed),
/// yielding to the runtime between not-yet-done polls so sibling ballers make
/// progress. The chain is returned by value so the winner can be adopted and a
/// loser can be shut down. Mirrors the per-baller half of curl's
/// `cf_hc_connect` inner loop.
async fn drive_baller(idx: usize, mut chain: FilterChain) -> BallerOutcome {
    loop {
        match chain.connect(false).await {
            Ok(true) => return (idx, chain, Ok(true)),
            Ok(false) => tokio::task::yield_now().await,
            Err(e) => return (idx, chain, Err(e)),
        }
    }
}

impl HttpsConnectFilter {
    /// Starts baller `idx`: records its start time, builds its leaf filter via
    /// the (possibly test-injected) factory, wraps it in a fresh sub-chain, and
    /// pushes its driving future onto `inflight`. Mirrors curl's
    /// `cf_hc_baller_init` (build the sub-chain and begin connecting).
    fn start_baller(&mut self, idx: usize, inflight: &mut FuturesUnordered<BallerFut>) {
        self.ballers[idx].started = Some(Instant::now());
        // Emit the same per-baller start diagnostic curl logs from
        // `cf_hc_baller_init`, keeping `--trace` output faithful. This also
        // reads the baller's identity fields (name/alpn_id/transport), which are
        // otherwise pure C-parity metadata.
        let baller = &self.ballers[idx];
        tracing::trace!(
            target: "curl::cf",
            sockindex = self.sockindex,
            baller = baller.name,
            alpn = ?baller.alpn_id,
            transport = baller.transport.as_u8(),
            "HTTPS-CONNECT: starting baller"
        );
        // Clone the spec to release the &mut borrow of the baller before
        // invoking the factory function pointer.
        let spec = baller.spec.clone();
        let leaf = (self.establish_factory)(&spec);
        let mut chain = FilterChain::new(self.sockindex);
        chain.add(leaf);
        inflight.push(Box::pin(drive_baller(idx, chain)));
    }

    /// Adopts baller `idx` as the winner: tears down every *other* baller
    /// (closing any parked, failed sub-chain and marking it shut down), moves
    /// the winning sub-chain into [`winner`](Self::winner), and advances to
    /// [`CfHcState::Success`]. Mirrors curl's `baller_connected`
    /// (`cf->next = winner->cf; winner->cf = NULL; state = CF_HC_SUCCESS`).
    ///
    /// Ballers still in flight at this point are cancelled — and their sockets
    /// closed — when the race's [`FuturesUnordered`] is dropped as
    /// [`run_connect`](Self::run_connect) returns, which is the async analog of
    /// curl's loser-shutdown loop.
    fn baller_connected(&mut self, idx: usize, chain: FilterChain) {
        for (i, baller) in self.ballers.iter_mut().enumerate() {
            if i != idx {
                if let Some(mut parked) = baller.cf.take() {
                    parked.close();
                }
                baller.shutdown = true;
            }
        }
        self.winner = Some(chain);
        self.winner_has_tls = true;
        self.state = CfHcState::Success;
    }

    /// Runs the whole eyeballing race to completion.
    ///
    /// This is the async reimplementation of curl's `cf_hc_connect` state
    /// machine (`CF_HC_INIT` → `CF_HC_CONNECT` → `CF_HC_SUCCESS`/`CF_HC_FAILURE`):
    ///
    /// 1. Start the preferred baller (`ballers[0]`) immediately.
    /// 2. On each turn: honour the overall deadline; start the fallback baller
    ///    when [`time_to_start_next`](Self::time_to_start_next) says so; and
    ///    settle whichever baller finishes first.
    /// 3. The first baller to report `Ok(true)` wins
    ///    ([`baller_connected`](Self::baller_connected) adopts it and the losers
    ///    are torn down); if every baller fails, return the first failure as the
    ///    aggregated error (curl returns `ballers[0].result`), defaulting to
    ///    [`CurlCode::CouldntConnect`] (7).
    async fn run_connect(&mut self) -> Result<bool> {
        // A re-entrant call after success is an immediate, idempotent success.
        if self.state == CfHcState::Success {
            return Ok(true);
        }
        if self.ballers.is_empty() {
            self.state = CfHcState::Failure;
            return Err(Error::with_context(
                CurlCode::FailedInit,
                "HTTPS-CONNECT filter has no ballers to attempt",
            ));
        }

        let race_start = Instant::now();
        self.started = Some(race_start);
        self.state = CfHcState::Connect;
        self.first_err = None;

        let mut inflight: FuturesUnordered<BallerFut> = FuturesUnordered::new();
        self.start_baller(0, &mut inflight);
        let mut started_count = 1usize;

        loop {
            // (a) Overall deadline (curl's connect timeout).
            if let Some(limit) = self.overall_timeout_ms {
                if ms_since(race_start) >= limit {
                    self.state = CfHcState::Failure;
                    return Err(Error::with_context(
                        CurlCode::OperationTimedout,
                        "Connection timed out while eyeballing HTTP versions",
                    ));
                }
            }

            // (b) Staggered start of the fallback baller.
            if started_count < self.ballers.len()
                && self.time_to_start_next(started_count, race_start)
            {
                self.start_baller(started_count, &mut inflight);
                started_count += 1;
            }

            // (c) Terminal failure: all ballers started, all failed, none left
            //     running. Return the first observed error (curl's ballers[0]).
            if inflight.is_empty()
                && started_count == self.ballers.len()
                && self.ballers.iter().all(|b| b.result.is_some())
            {
                self.state = CfHcState::Failure;
                let err = self
                    .first_err
                    .take()
                    .unwrap_or_else(|| Error::connect("Could not connect to server"));
                return Err(err);
            }

            // (d) Wait for the next baller completion or the next scheduling tick.
            let wake = self.next_wake_ms(started_count, race_start);
            tokio::select! {
                settled = inflight.next(), if !inflight.is_empty() => {
                    if let Some((idx, chain, res)) = settled {
                        match res {
                            Ok(true) => {
                                self.baller_connected(idx, chain);
                                return Ok(true);
                            }
                            // drive_baller only ever yields Ok(true) or Err.
                            Ok(false) => {}
                            Err(e) => {
                                if self.first_err.is_none() {
                                    self.first_err = Some(clone_err(&e));
                                }
                                self.ballers[idx].result = Some(e);
                                // Park the failed chain so the shutdown loop can
                                // tear it down (curl keeps baller->cf until reset).
                                self.ballers[idx].cf = Some(chain);
                            }
                        }
                    }
                }
                () = tokio::time::sleep(Duration::from_millis(wake)) => {
                    // Scheduling tick: loop to re-evaluate (b) and (c).
                }
            }
        }
    }

    /// The maximum of a per-baller timer query across the ballers whose
    /// (failed/parked) sub-chains are still queryable. This is the async analog
    /// of curl's `cf_get_max_baller_time`, which walks `ctx->ballers[]` and
    /// keeps the latest `curltime` for the requested timer.
    fn max_baller_time(&self, query: CfQuery) -> Option<Instant> {
        let mut latest: Option<Instant> = None;
        for baller in self.ballers.iter() {
            let Some(chain) = baller.cf.as_ref() else {
                continue;
            };
            let mut out = QueryOut::None;
            if chain.query(query, &mut out).is_ok() {
                let instant = match out {
                    QueryOut::TimerConnect(i) | QueryOut::TimerAppConnect(i) => Some(i),
                    _ => None,
                };
                if let Some(i) = instant {
                    latest = Some(match latest {
                        Some(existing) if existing >= i => existing,
                        _ => i,
                    });
                }
            }
        }
        latest
    }
}

impl ConnectionFilter for HttpsConnectFilter {
    fn name(&self) -> &'static str {
        // curl's `Curl_cft_http_connect.name`.
        "HTTPS-CONNECT"
    }

    fn cf_type(&self) -> CfType {
        // The eyeballing filter is an HTTP-layer connect filter. Once a winner
        // is adopted its transport is always TLS-secured (TCP+TLS or QUIC), so
        // SSL is OR-ed in to reflect the established secure chain.
        let mut flags = CfType::HTTP;
        if self.winner_has_tls {
            flags |= CfType::SSL;
        }
        flags
    }

    fn connect<'a>(
        &'a mut self,
        _cx: &'a mut FilterCtx<'_>,
        _blocking: bool,
    ) -> CfFuture<'a, Result<bool>> {
        // The whole race runs to completion within this future.
        Box::pin(self.run_connect())
    }

    fn shutdown<'a>(&'a mut self, _cx: &'a mut FilterCtx<'_>) -> CfFuture<'a, Result<bool>> {
        Box::pin(async move {
            // Post-success: delegate to the winning chain.
            if let Some(chain) = self.winner.as_mut() {
                return chain.shutdown(0).await;
            }
            // Otherwise shut down any parked baller chains; done when all are
            // shut. A failed shutdown is treated as done, mirroring curl's
            // `cf_hc_shutdown` (`result` on a baller shutdown ⇒ mark it done).
            let mut all_done = true;
            for baller in self.ballers.iter_mut() {
                if baller.shutdown {
                    continue;
                }
                if let Some(chain) = baller.cf.as_mut() {
                    match chain.shutdown(0).await {
                        Ok(true) => baller.shutdown = true,
                        Ok(false) => all_done = false,
                        Err(_) => baller.shutdown = true,
                    }
                } else {
                    baller.shutdown = true;
                }
            }
            Ok(all_done)
        })
    }

    fn close(&mut self, _cx: &mut FilterCtx<'_>) {
        // Reset all ballers and state, and close the winning chain — curl's
        // `cf_hc_close` (reset ballers, then close `cf->next`).
        if let Some(mut chain) = self.winner.take() {
            chain.close();
        }
        for baller in self.ballers.iter_mut() {
            baller.reset();
        }
        self.state = CfHcState::Init;
        self.started = None;
        self.first_err = None;
        self.winner_has_tls = false;
    }

    fn send<'a>(
        &'a mut self,
        _cx: &'a mut FilterCtx<'_>,
        buf: &'a [u8],
        eos: bool,
    ) -> CfFuture<'a, Result<usize>> {
        Box::pin(async move {
            match self.winner.as_mut() {
                Some(chain) => chain.send(buf, eos).await,
                None => Err(Error::with_context(
                    CurlCode::SendError,
                    "HTTPS-CONNECT: cannot send before a winning transport is established",
                )),
            }
        })
    }

    fn recv<'a>(
        &'a mut self,
        _cx: &'a mut FilterCtx<'_>,
        buf: &'a mut [u8],
    ) -> CfFuture<'a, Result<usize>> {
        Box::pin(async move {
            match self.winner.as_mut() {
                Some(chain) => chain.recv(buf).await,
                None => Err(Error::with_context(
                    CurlCode::RecvError,
                    "HTTPS-CONNECT: cannot receive before a winning transport is established",
                )),
            }
        })
    }

    fn data_pending(&self, _cx: &QueryCtx<'_>) -> bool {
        // Connected: delegate to the winner. Otherwise report pending if any
        // parked baller chain has buffered data (curl's `cf_hc_data_pending`).
        if let Some(chain) = self.winner.as_ref() {
            return chain.data_pending();
        }
        self.ballers
            .iter()
            .any(|b| b.cf.as_ref().is_some_and(|c| c.data_pending()))
    }

    fn adjust_pollset(&self, _cx: &QueryCtx<'_>, ps: &mut Pollset) {
        // Connected: delegate to the winner. Otherwise union the pollsets of
        // any parked baller chains (curl's `cf_hc_adjust_pollset`, which only
        // acts while not yet connected).
        if let Some(chain) = self.winner.as_ref() {
            chain.adjust_pollset(ps);
            return;
        }
        for baller in self.ballers.iter() {
            if let Some(chain) = baller.cf.as_ref() {
                chain.adjust_pollset(ps);
            }
        }
    }

    fn is_alive(&mut self, _cx: &mut FilterCtx<'_>) -> bool {
        // Only a connected chain can be alive.
        match self.winner.as_mut() {
            Some(chain) => chain.is_alive(),
            None => false,
        }
    }

    fn keep_alive(&mut self, _cx: &mut FilterCtx<'_>) -> Result<()> {
        match self.winner.as_mut() {
            Some(chain) => chain.keep_alive(),
            None => Ok(()),
        }
    }

    fn cntrl(
        &mut self,
        _cx: &mut FilterCtx<'_>,
        event: i32,
        arg1: i32,
        arg2: Option<&mut dyn Any>,
    ) -> Result<()> {
        // Must not chain to `next` via the context (curl's cntrl is directed).
        // Connected: forward the event to the winning chain, including its
        // payload. Otherwise forward the event (without the single-borrow
        // payload) to any parked baller chains, mirroring curl's `cf_hc_cntrl`
        // iterating the ballers while not connected.
        if let Some(chain) = self.winner.as_mut() {
            return chain.cntrl_all(event, arg1, arg2);
        }
        for baller in self.ballers.iter_mut() {
            if let Some(chain) = baller.cf.as_mut() {
                chain.cntrl_all(event, arg1, None)?;
            }
        }
        Ok(())
    }

    fn query(&self, cx: &QueryCtx<'_>, query: CfQuery, out: &mut QueryOut) -> Result<()> {
        // Connected: the winner answers everything (curl delegates to cf->next).
        if let Some(chain) = self.winner.as_ref() {
            return chain.query(query, out);
        }
        match query {
            // Aggregate the connect/appconnect timers as the max across ballers
            // (curl's `cf_get_max_baller_time`).
            CfQuery::TimerConnect | CfQuery::TimerAppConnect => {
                if let Some(instant) = self.max_baller_time(query) {
                    *out = if matches!(query, CfQuery::TimerConnect) {
                        QueryOut::TimerConnect(instant)
                    } else {
                        QueryOut::TimerAppConnect(instant)
                    };
                }
                Ok(())
            }
            // NEED_FLUSH is the OR across ballers.
            CfQuery::NeedFlush => {
                let need = self.ballers.iter().any(|b| {
                    b.cf.as_ref().is_some_and(|chain| {
                        let mut probe = QueryOut::None;
                        chain.query(CfQuery::NeedFlush, &mut probe).ok();
                        matches!(probe, QueryOut::NeedFlush(true))
                    })
                });
                *out = QueryOut::NeedFlush(need);
                Ok(())
            }
            // Everything else defers down the chain (curl falls through to
            // cf->next, or CURLE_UNKNOWN_OPTION at the tail).
            _ => cx.query_next(query, out),
        }
    }
}

// ===========================================================================
// Public entry points (curl `Curl_cf_https_setup` / `Curl_cf_http_connect_add`).
// ===========================================================================

/// Builds the [`EstablishSpec`] for one baller of `alpn` on the given origin
/// connection: the origin host/port to connect to, the same host as the TLS
/// server name (SNI + verification identity), the origin's TLS config, and the
/// per-ALPN offer.
fn spec_for(conn: &Connection, alpn: AlpnId) -> EstablishSpec {
    EstablishSpec {
        quic: matches!(alpn, AlpnId::H3),
        host: conn.host.name.clone(),
        port: conn.remote_port,
        server_name: conn.host.name.clone(),
        tls_config: conn.ssl_config.clone(),
        alpn: alpn.alpn_offer(),
    }
}

/// Inserts `filter` at the network end (tail) of `chain`: a straight
/// [`FilterChain::add`] when the chain is empty (the filter becomes the sole,
/// tail-most node), otherwise a [`FilterChain::insert_after`] at `at_index`.
fn install_tail(
    chain: &mut FilterChain,
    at_index: usize,
    filter: Box<dyn ConnectionFilter>,
) -> Result<()> {
    if chain.is_empty() {
        chain.add(filter);
        Ok(())
    } else {
        chain.insert_after(at_index, filter)
    }
}

/// Installs the TLS-to-proxy layer (and an HTTP/1.1 `CONNECT` tunnel above it)
/// for an HTTPS-type proxy.
///
/// This is the port of the `Curl_cf_ssl_proxy_insert_after` path that curl's
/// `connect.rs`/`Curl_cf_https_setup` arranges for a proxied HTTPS transfer.
/// The fused [`TlsEstablishFilter`] opens TCP to the proxy and completes the
/// TLS handshake against it (offering `h2`+`http/1.1` for a `HTTPS2` proxy,
/// `http/1.1` for a plain `HTTPS` proxy). The HTTP/1.1 `CONNECT` filter from
/// [`crate::conn::h1_proxy`] is layered directly above it (prepended, so it is
/// application-facing relative to the proxy TLS) to tunnel the origin
/// host:port — exactly the ordering `filters[0]` = app … tail = network.
fn install_https_proxy(chain: &mut FilterChain, conn: &Connection) -> Result<()> {
    let proxy_host = conn.http_proxy.host.name.clone();
    let proxy_port = conn.http_proxy.port;
    let proxy_alpn = match conn.http_proxy.proxytype {
        ProxyType::Https2 => vec![
            crate::tls::ALPN_H2.to_vec(),
            crate::tls::ALPN_HTTP_1_1.to_vec(),
        ],
        _ => vec![crate::tls::ALPN_HTTP_1_1.to_vec()],
    };
    let tls_to_proxy = TlsEstablishFilter::new(EstablishSpec {
        quic: false,
        host: proxy_host.clone(),
        port: proxy_port,
        server_name: proxy_host,
        tls_config: conn.proxy_ssl_config.clone(),
        alpn: proxy_alpn,
    });

    // Network end: the fused TCP+TLS-to-proxy transport.
    let tail_index = chain.len().saturating_sub(1);
    install_tail(chain, tail_index, Box::new(tls_to_proxy))?;

    // Application side of the proxy TLS: the CONNECT tunnel to the origin.
    // `add` prepends, so it sits above the TLS-to-proxy filter just installed.
    let connect_cfg = h1_proxy::H1ProxyConfig::new(conn.host.name.clone(), conn.remote_port);
    chain.add(Box::new(h1_proxy::H1ProxyFilter::new(connect_cfg)));
    Ok(())
}

/// Installs the HTTPS "eyeballing" filter configured to race the requested
/// ballers. Port of curl's `Curl_cf_http_connect_add`.
///
/// A baller is built for each of the requested HTTP-version families, in
/// start-preference order (`h3` first when requested, then the `h2`/`h1`
/// attempt), each carrying an [`EstablishSpec`] derived from `conn` via
/// [`spec_for`]. The assembled [`HttpsConnectFilter`] is installed at the
/// network end of `chain` (see [`install_tail`]).
///
/// # Parameters
///
/// This mirrors curl's `Curl_cf_http_connect_add(data, conn, sockindex, …)`:
/// `conn` and `sockindex` are required to build real ballers (host, port, TLS
/// configuration, and the served socket index) and to identify the sub-chains,
/// so they are carried explicitly here in addition to the `at_index` insertion
/// point and the `try_h3`/`try_h21` selectors named in the design.
///
/// # Errors
///
/// Returns [`Error::bad_argument`] if neither `try_h3` nor `try_h21` is set (an
/// eyeballing filter with no ballers cannot connect), or if `at_index` is out
/// of range for a non-empty chain.
pub fn http_connect_add(
    chain: &mut FilterChain,
    conn: &Connection,
    sockindex: usize,
    at_index: usize,
    try_h3: bool,
    try_h21: bool,
) -> Result<()> {
    let mut ballers: Vec<HcBaller> = Vec::with_capacity(MAX_BALLERS);
    if try_h3 {
        ballers.push(HcBaller::new(AlpnId::H3, spec_for(conn, AlpnId::H3)));
    }
    if try_h21 {
        // The "h21" baller offers h2 then http/1.1, letting the server choose.
        ballers.push(HcBaller::new(AlpnId::H2, spec_for(conn, AlpnId::H2)));
    }
    if ballers.is_empty() {
        return Err(Error::bad_argument(
            "http_connect_add requires at least one of try_h3 / try_h21",
        ));
    }

    let filter = HttpsConnectFilter::new(ballers, sockindex);
    install_tail(chain, at_index, Box::new(filter))
}

/// Sets up the connect filter stack for an HTTPS transfer. Port of curl's
/// `Curl_cf_https_setup`.
///
/// The decision, faithful to `cf-https-connect.c`:
///
/// * **HTTPS proxy** (`bits.httpproxy` with a `HTTPS`/`HTTPS2` proxy type) →
///   install the TLS-to-proxy layer via [`install_https_proxy`]
///   (curl's `Curl_cf_ssl_proxy_insert_after` path).
/// * **HTTPS origin with ALPN enabled** (`bits.tls_enable_alpn`) → install the
///   eyeballing filter via [`http_connect_add`], racing an `h3`/QUIC baller
///   against an `h2`/`h1`-over-TLS baller when the wanted transport is QUIC
///   (e.g. `--http3`), or running only the `h2`/`h1` baller for a TCP transport.
/// * **Otherwise** (ALPN disabled) → install nothing here; a fixed-version
///   transport is arranged elsewhere. curl likewise adds no HTTPS-connect
///   filter in that case.
///
/// `sockindex` selects the socket / filter chain this stack serves
/// (`FIRSTSOCKET` for every protocol except FTP's data channel).
pub fn https_setup(chain: &mut FilterChain, conn: &Connection, sockindex: usize) -> Result<()> {
    // HTTPS proxy: ensure a TLS-to-proxy layer is present.
    if conn.bits.httpproxy
        && matches!(
            conn.http_proxy.proxytype,
            ProxyType::Https | ProxyType::Https2
        )
    {
        return install_https_proxy(chain, conn);
    }

    // Origin: version eyeballing only happens when ALPN is enabled.
    if !conn.bits.tls_enable_alpn {
        return Ok(());
    }

    // Choose the ballers from the wanted transport (curl derives the alpn_ids
    // from the wanted/allowed HTTP versions): a QUIC-wanted transport races h3
    // against the h2/h1 fallback; a TCP transport runs only the h2/h1 baller.
    let (try_h3, try_h21) = match conn.transport_wanted {
        Transport::Quic => (true, true),
        _ => (false, true),
    };

    let at_index = chain.len().saturating_sub(1);
    http_connect_add(chain, conn, sockindex, at_index, try_h3, try_h21)
}

// ===========================================================================
// Tests
// ===========================================================================
//
// These tests exercise the HTTPS version-eyeballing filter as a whole:
//
//   1. A real TCP+TLS baller connecting to an in-process `rustls` server and
//      winning the (single-baller) race — proving the H21 leaf really drives
//      `crate::tls::TlsConnector::from_config().connect()` and that the winner
//      answers post-success queries (ALPN / transport).
//   2. A two-baller race where the H3/QUIC baller is a black hole and the
//      H2 baller connects — proving the fast baller wins and the loser is shut
//      down (`HcBaller::shutdown == true`), mirroring curl's `baller_connected`.
//   3. Both ballers refusing — proving the aggregated error is
//      `CURLE_COULDNT_CONNECT` (7).
//   4. `query(CF_QUERY_TIMER_CONNECT)` returning the **max** timer across
//      ballers (curl's `cf_get_max_baller_time`).
//   5. Post-success delegation of `query` to the winning sub-chain.
//   6. Filter identity: `name() == "HTTPS-CONNECT"` and `cf_type()` carries
//      `CF_TYPE_HTTP`.
//   7. `http_connect_add` rejecting an out-of-range insertion index and a
//      no-baller request with `CURLE_BAD_FUNCTION_ARGUMENT` (43).
//
// The mock tests inject a deterministic baller factory via the test-only
// `with_establish_factory` hook, so no real network is touched; the single real
// TLS test uses an `rcgen` ephemeral certificate exactly as the `tls` module's
// own integration tests do.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{Scheme, FIRSTSOCKET};
    use std::sync::Once;

    // -----------------------------------------------------------------------
    // Crypto-provider bootstrap. rustls' `ServerConfig`/`ClientConfig` builders
    // and quinn all require a process-default crypto provider; install aws-lc-rs
    // once for the whole suite (idempotent — a second install is ignored).
    // -----------------------------------------------------------------------
    static CRYPTO_INIT: Once = Once::new();
    fn ensure_provider() {
        CRYPTO_INIT.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    // -----------------------------------------------------------------------
    // Deterministic mock baller leaf, keyed by `spec.port`. Injected in place of
    // the real TlsEstablishFilter / QuicEstablishFilter so the race can be driven
    // without any real I/O.
    // -----------------------------------------------------------------------
    /// A baller that connects immediately.
    const FAST_PORT: u16 = 11;
    /// A baller that never completes (a "black hole", like a silently dropped
    /// QUIC datagram path); the future is cancelled when the loser is dropped.
    const HANG_PORT: u16 = 22;
    /// A baller that fails to connect immediately.
    const REFUSE_PORT: u16 = 33;

    struct FakeEstablish {
        port: u16,
        transport: Transport,
        connected_at: Option<Instant>,
    }

    impl ConnectionFilter for FakeEstablish {
        fn name(&self) -> &'static str {
            "FAKE-ESTABLISH"
        }

        fn cf_type(&self) -> CfType {
            CfType::SSL
        }

        fn connect<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            _blocking: bool,
        ) -> CfFuture<'a, Result<bool>> {
            Box::pin(async move {
                match self.port {
                    FAST_PORT => {
                        self.connected_at = Some(Instant::now());
                        Ok(true)
                    }
                    HANG_PORT => {
                        // Far longer than any test deadline; cancelled on drop.
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        Ok(true)
                    }
                    _ => Err(Error::connect("fake baller: connection refused")),
                }
            })
        }

        fn query(&self, cx: &QueryCtx<'_>, query: CfQuery, out: &mut QueryOut) -> Result<()> {
            match query {
                CfQuery::Transport => {
                    *out = QueryOut::Transport(self.transport);
                    Ok(())
                }
                CfQuery::TimerConnect | CfQuery::TimerAppConnect => match self.connected_at {
                    Some(when) => {
                        *out = QueryOut::TimerConnect(when);
                        Ok(())
                    }
                    None => cx.query_next(query, out),
                },
                CfQuery::AlpnNegotiated => {
                    *out = QueryOut::AlpnNegotiated("h2".to_string());
                    Ok(())
                }
                _ => cx.query_next(query, out),
            }
        }
    }

    /// The test-injected factory: builds a [`FakeEstablish`] whose behaviour is
    /// selected by `spec.port` and whose transport mirrors `spec.quic`.
    fn fake_factory(spec: &EstablishSpec) -> Box<dyn ConnectionFilter> {
        let transport = if spec.quic {
            Transport::Quic
        } else {
            Transport::Tcp
        };
        Box::new(FakeEstablish {
            port: spec.port,
            transport,
            connected_at: None,
        })
    }

    /// A mock leaf that reports a fixed `TimerConnect`/`TimerAppConnect` instant,
    /// used to verify the max-across-ballers timer aggregation in isolation.
    struct TimerReport {
        when: Instant,
    }

    impl ConnectionFilter for TimerReport {
        fn name(&self) -> &'static str {
            "TIMER-REPORT"
        }

        fn cf_type(&self) -> CfType {
            CfType::SSL
        }

        fn query(&self, cx: &QueryCtx<'_>, query: CfQuery, out: &mut QueryOut) -> Result<()> {
            match query {
                CfQuery::TimerConnect => {
                    *out = QueryOut::TimerConnect(self.when);
                    Ok(())
                }
                CfQuery::TimerAppConnect => {
                    *out = QueryOut::TimerAppConnect(self.when);
                    Ok(())
                }
                _ => cx.query_next(query, out),
            }
        }
    }

    // -----------------------------------------------------------------------
    // Small helpers.
    // -----------------------------------------------------------------------

    /// Builds an [`EstablishSpec`] carrying the given port key (for the mock
    /// factory) and a default (unused) TLS config.
    fn mock_spec(port: u16, quic: bool) -> EstablishSpec {
        EstablishSpec {
            quic,
            host: "127.0.0.1".to_string(),
            port,
            server_name: "localhost".to_string(),
            tls_config: Arc::new(TlsConfig::default()),
            alpn: if quic {
                vec![b"h3".to_vec()]
            } else {
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            },
        }
    }

    /// Wraps a single filter in a fresh [`FilterChain`] (used to park mock
    /// sub-chains on ballers for the timer-aggregation test).
    fn chain_with(filter: impl ConnectionFilter + 'static) -> FilterChain {
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(filter));
        chain
    }

    /// Builds a `rustls` server config presenting a fresh self-signed cert for
    /// `localhost` and advertising ALPN `h2`, returning it together with the CA
    /// PEM the client must trust. Mirrors the `tls` module's `make_server`.
    fn make_h2_server() -> (Arc<rustls::ServerConfig>, Vec<u8>) {
        ensure_provider();
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
        let ca_pem = certified.cert.pem().into_bytes();
        let cert_der = certified.cert.der().clone();
        let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()),
        );
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server config builds");
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        (Arc::new(cfg), ca_pem)
    }

    // =======================================================================
    // Test 1 — the H21 (TCP+TLS) baller connects to a real in-process rustls
    // server and wins the (single-baller) race; the winner answers queries.
    // =======================================================================
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn h21_baller_wins_over_real_tls_server() {
        ensure_provider();
        let (server_cfg, ca_pem) = make_h2_server();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();

        // Accept exactly one connection, complete the handshake, then drop.
        let server = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
            if let Ok((tcp, _)) = listener.accept().await {
                let _ = acceptor.accept(tcp).await;
            }
        });

        // The client trusts only the ephemeral CA blob (no webpki roots). The
        // baller layers ALPN [h2, http/1.1] over the socket via `crate::tls`.
        let tls_config = Arc::new(
            TlsConfig::default()
                .with_webpki_roots(false)
                .with_ca_info_blob(ca_pem),
        );
        let spec = EstablishSpec {
            quic: false,
            host: "127.0.0.1".to_string(),
            port,
            server_name: "localhost".to_string(),
            tls_config,
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        };
        let baller = HcBaller::new(AlpnId::H2, spec);

        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(HttpsConnectFilter::new(vec![baller], FIRSTSOCKET)));

        let done = tokio::time::timeout(Duration::from_secs(10), chain.connect(false))
            .await
            .expect("no overall timeout")
            .expect("eyeballing connect succeeds");
        assert!(done, "the TCP+TLS baller connects and wins the race");

        // Post-success queries are answered by the winning sub-chain: the real
        // TLS leaf reports the negotiated ALPN and its TCP transport.
        let mut alpn = QueryOut::None;
        chain
            .query(CfQuery::AlpnNegotiated, &mut alpn)
            .expect("alpn query");
        match alpn {
            QueryOut::AlpnNegotiated(s) => assert_eq!(s.as_str(), "h2"),
            other => panic!("expected AlpnNegotiated(h2), got {other:?}"),
        }

        let mut transport = QueryOut::None;
        chain
            .query(CfQuery::Transport, &mut transport)
            .expect("transport query");
        assert!(
            matches!(transport, QueryOut::Transport(Transport::Tcp)),
            "winner transport is TCP, got {transport:?}"
        );

        let _ = server.await;
    }

    // =======================================================================
    // Test 2 — with both ballers, the H3/QUIC baller is a black hole and the
    // H2 baller connects: the H2 baller wins and the H3 loser is shut down.
    // =======================================================================
    #[tokio::test]
    async fn h2_wins_when_h3_is_black_hole_and_h3_is_shut_down() {
        // baller[0] = H3 (black hole), baller[1] = H2 (fast).
        let h3 = HcBaller::new(AlpnId::H3, mock_spec(HANG_PORT, true));
        let h21 = HcBaller::new(AlpnId::H2, mock_spec(FAST_PORT, false));
        let mut filter = HttpsConnectFilter::new(vec![h3, h21], FIRSTSOCKET)
            .with_establish_factory(fake_factory)
            .with_hard_eyeballs_timeout_ms(40);

        let done = tokio::time::timeout(Duration::from_secs(5), filter.run_connect())
            .await
            .expect("no overall timeout")
            .expect("the H2 baller wins");
        assert!(done);
        assert_eq!(filter.state, CfHcState::Success);
        assert!(filter.winner.is_some(), "the winning sub-chain is adopted");
        assert!(
            filter.ballers[0].shutdown,
            "the black-hole H3 baller is shut down once H2 wins"
        );
    }

    // =======================================================================
    // Test 3 — every baller refusing yields CURLE_COULDNT_CONNECT (7).
    // =======================================================================
    #[tokio::test]
    async fn both_ballers_refused_yields_couldnt_connect() {
        let h3 = HcBaller::new(AlpnId::H3, mock_spec(REFUSE_PORT, true));
        let h21 = HcBaller::new(AlpnId::H2, mock_spec(REFUSE_PORT, false));
        let mut filter = HttpsConnectFilter::new(vec![h3, h21], FIRSTSOCKET)
            .with_establish_factory(fake_factory)
            .with_hard_eyeballs_timeout_ms(40);

        let err = tokio::time::timeout(Duration::from_secs(5), filter.run_connect())
            .await
            .expect("no overall timeout")
            .expect_err("both ballers refuse");
        assert_eq!(err.code(), CurlCode::CouldntConnect);
        assert_eq!(err.code_i32(), 7);
        assert_eq!(filter.state, CfHcState::Failure);
    }

    // =======================================================================
    // Test 4 — query(CF_QUERY_TIMER_CONNECT) returns the max baller time.
    // =======================================================================
    #[test]
    fn timer_connect_query_reports_max_across_ballers() {
        let base = Instant::now();
        let early = base + Duration::from_millis(10);
        let late = base + Duration::from_millis(80);

        let mut filter = HttpsConnectFilter::new(
            vec![
                HcBaller::new(AlpnId::H3, mock_spec(1, true)),
                HcBaller::new(AlpnId::H2, mock_spec(2, false)),
            ],
            FIRSTSOCKET,
        );
        // Park two mock sub-chains reporting known TimerConnect instants.
        filter.ballers[0].cf = Some(chain_with(TimerReport { when: early }));
        filter.ballers[1].cf = Some(chain_with(TimerReport { when: late }));

        let got = filter
            .max_baller_time(CfQuery::TimerConnect)
            .expect("a max timer instant");
        assert_eq!(got, late, "max-across-ballers selects the latest instant");
    }

    // =======================================================================
    // Test 5 — after success, `query` delegates to the winning sub-chain.
    // =======================================================================
    #[tokio::test]
    async fn post_success_query_delegates_to_winner() {
        let h21 = HcBaller::new(AlpnId::H2, mock_spec(FAST_PORT, false));
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(
            HttpsConnectFilter::new(vec![h21], FIRSTSOCKET).with_establish_factory(fake_factory),
        ));

        let done = tokio::time::timeout(Duration::from_secs(5), chain.connect(false))
            .await
            .expect("no overall timeout")
            .expect("the fast baller wins");
        assert!(done);

        // The transport query is answered by the winning (fake) sub-chain, not
        // by the eyeballing filter's pre-success aggregation.
        let mut transport = QueryOut::None;
        chain
            .query(CfQuery::Transport, &mut transport)
            .expect("transport query");
        assert!(
            matches!(transport, QueryOut::Transport(Transport::Tcp)),
            "post-success query delegates to the winner, got {transport:?}"
        );
    }

    // =======================================================================
    // Test 6 — filter identity matches curl's `Curl_cft_http_connect`.
    // =======================================================================
    #[test]
    fn name_and_cf_type_match_curl_http_connect() {
        let filter = HttpsConnectFilter::new(
            vec![HcBaller::new(AlpnId::H2, mock_spec(1, false))],
            FIRSTSOCKET,
        );
        assert_eq!(filter.name(), "HTTPS-CONNECT");
        // Before a winner is adopted the filter advertises exactly CF_TYPE_HTTP.
        assert!(
            filter.cf_type().contains(CfType::HTTP),
            "cf_type carries CF_TYPE_HTTP (1<<4)"
        );
        assert_eq!(filter.cf_type(), CfType::HTTP);
        assert!(
            !filter.cf_type().contains(CfType::SSL),
            "SSL is only OR-ed in after a TLS winner is adopted"
        );
    }

    // =======================================================================
    // Test 7 — http_connect_add input validation.
    // =======================================================================
    #[test]
    fn http_connect_add_out_of_range_index_is_bad_argument() {
        ensure_provider();
        let conn = Connection::new(Scheme::new("https", 443), "example.com", 443);
        // A non-empty chain so `install_tail` takes the `insert_after` path.
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(HttpsConnectFilter::new(
            vec![HcBaller::new(AlpnId::H2, mock_spec(1, false))],
            FIRSTSOCKET,
        )));

        let err = http_connect_add(&mut chain, &conn, FIRSTSOCKET, 99, false, true)
            .expect_err("an out-of-range insertion index must fail");
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
        assert_eq!(err.code_i32(), 43);
    }

    #[test]
    fn http_connect_add_with_no_ballers_is_bad_argument() {
        let conn = Connection::new(Scheme::new("https", 443), "example.com", 443);
        let mut chain = FilterChain::new(FIRSTSOCKET);
        let err = http_connect_add(&mut chain, &conn, FIRSTSOCKET, 0, false, false)
            .expect_err("requesting zero ballers must fail");
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
    }

    // =======================================================================
    // Test 8 — the overall connect deadline maps to CURLE_OPERATION_TIMEDOUT
    // (28) even when every baller is stalled (a QUIC black hole).
    // =======================================================================
    #[tokio::test]
    async fn overall_deadline_yields_operation_timedout() {
        // A single black-hole baller that never connects; the only way out is the
        // overall deadline.
        let h3 = HcBaller::new(AlpnId::H3, mock_spec(HANG_PORT, true));
        let mut filter = HttpsConnectFilter::new(vec![h3], FIRSTSOCKET)
            .with_establish_factory(fake_factory)
            // Large eyeballs timeout (irrelevant here) but a short overall
            // deadline, which must fire promptly.
            .with_hard_eyeballs_timeout_ms(10_000)
            .with_overall_timeout_ms(50);

        let err = tokio::time::timeout(Duration::from_secs(5), filter.run_connect())
            .await
            .expect("the overall deadline fires well within the test timeout")
            .expect_err("a stalled baller must time out");
        assert_eq!(err.code(), CurlCode::OperationTimedout);
        assert_eq!(err.code_i32(), 28);
        assert_eq!(filter.state, CfHcState::Failure);
    }
}
