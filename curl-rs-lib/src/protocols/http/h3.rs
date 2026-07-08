// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! HTTP/3 over QUIC (← `lib/vquic/curl_ngtcp2.c` + `lib/vquic/curl_quiche.c`
//! + `lib/vquic/vquic.c`).
//!
//! # What this module replaces
//!
//! curl 8.x ships **two** C QUIC/HTTP-3 backends selected at build time by
//! `#ifdef`:
//!
//! * `lib/vquic/curl_ngtcp2.c` — QUIC via **ngtcp2** + HTTP/3 via **nghttp3**.
//! * `lib/vquic/curl_quiche.c` — QUIC + HTTP/3 via Cloudflare **quiche**.
//!
//! plus the shared abstraction `lib/vquic/vquic.c` (socket setup, timers,
//! packet send/recv batching, `Curl_conn_may_http3`, `Curl_qlogdir`). This
//! module **collapses all three onto a single, memory-safe Rust
//! implementation** built on:
//!
//! * [`quinn`] — the QUIC transport (UDP I/O, congestion control, loss
//!   recovery, packetization). It fully owns everything `vquic.c`'s
//!   `vquic_ctx_init`/`recv`/`send` machinery did.
//! * [`h3`] — HTTP/3 framing and QPACK, replacing nghttp3 / quiche's h3 layer.
//! * [`h3_quinn`] — the adapter wiring `h3` onto a [`quinn::Connection`].
//!
//! We reproduce curl's **behavior and contract** (connection lifecycle, ALPN,
//! error semantics, the connection-filter query surface), *not* the byte-level
//! ngtcp2/quiche internals — those are owned by `quinn` + `h3`.
//!
//! # TLS integration
//!
//! HTTP/3 uses **`quinn`'s own `rustls` integration**, never the
//! [`crate::tls::TlsConnector`](crate::tls) tokio-rustls TCP adapter (which is
//! unsuitable for QUIC). We build a [`quinn::ClientConfig`] from a
//! [`rustls::ClientConfig`], but the certificate-validation *policy* (root
//! store, verify-peer/verify-host, the `--insecure` danger verifier) is reused
//! from [`crate::tls::config`] so it stays identical to the TLS layer.
//! Certificate validation is on by default; `--insecure` installs the danger
//! verifier and emits its stderr warning inside the config layer (we do not
//! duplicate it). QUIC mandates TLS 1.3, so the client config is pinned to a
//! TLS 1.3 floor.
//!
//! # Memory safety
//!
//! This module contains **zero** `unsafe`: the crate root's
//! [`forbid(unsafe_code)`](crate) makes any `unsafe` token a hard compile
//! error. All QUIC datagram I/O lives inside `quinn`, so there is nothing to
//! make unsafe here.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::{Buf, Bytes};

use crate::conn::filters::{ConnectionFilter, QueryCtx, QueryOut};
use crate::conn::{CfQuery, CfType, Connection, Transport};
use crate::error::{Error, Result};
use crate::protocols::http::{
    http_req_to_h2, HttpReqData, HttpResp, HTTP_PSEUDO_AUTHORITY, HTTP_PSEUDO_METHOD,
    HTTP_PSEUDO_PATH, HTTP_PSEUDO_SCHEME,
};
use crate::tls::config as tls_config;

// ===========================================================================
// Constants (← `ALPN_SPEC_H3`, the `CF_QUERY_HTTP_VERSION` reply, and curl's
// default multi max-concurrent-streams).
// ===========================================================================

/// The ALPN identifier for the finalized HTTP/3 protocol, RFC 9114 (`"h3"`).
///
/// curl's `ALPN_SPEC_H3` historically advertised `{ "h3", "h3-29" }`; with a
/// current `quinn` + `h3` stack the finalized `h3` token is what servers
/// negotiate, so this is the single protocol advertised on the
/// [`quinn::ClientConfig`] (see [`alpn_protocols`]).
pub const ALPN_H3: &[u8] = b"h3";

/// The ALPN identifier for QUIC draft 29 (`"h3-29"`), retained as a named
/// constant for parity with curl's historical `ALPN_SPEC_H3` compatibility set.
///
/// It is **not** advertised by default: the finalized `h3` token
/// ([`ALPN_H3`]) is the one modern servers negotiate, and the FFI/validation
/// contract fixes the advertised list to `[b"h3"]`.
pub const ALPN_H3_29: &[u8] = b"h3-29";

/// The wire HTTP version number reported for an HTTP/3 connection
/// (`CF_QUERY_HTTP_VERSION` → `30`, `cf_ngtcp2_query`/`cf_quiche_query`).
pub const HTTP3_VERSION: u8 = 30;

/// The fallback maximum number of concurrent streams reported before the peer's
/// QUIC transport parameters have arrived (curl uses
/// `Curl_multi_max_concurrent_streams`, whose default is 100).
const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 100;

// ===========================================================================
// PHASE 1 — Eligibility and ALPN (← `Curl_conn_may_http3`, vquic.c:854).
// ===========================================================================

/// Verify that HTTP/3 is permissible for this connection
/// (← `Curl_conn_may_http3`, `lib/vquic/vquic.c`).
///
/// This reproduces curl's eligibility rules verbatim, including the exact error
/// codes and diagnostic text:
///
/// * QUIC cannot run over a Unix-domain socket → [`Error::quic_connect`]
///   (`CURLE_QUIC_CONNECT_ERROR`, 96).
/// * HTTP/3 requires an HTTPS (TLS) scheme → [`Error::url`]
///   (`CURLE_URL_MALFORMAT`).
/// * HTTP/3 is not supported over a SOCKS proxy → [`Error::url`].
/// * HTTP/3 is not supported through a tunneling HTTP proxy → [`Error::url`].
///
/// The transport that curl passes explicitly (`TRNSPRT_UNIX`) is derived here
/// from the connection: a Unix transport is indicated either by
/// [`Connection::transport_wanted`] being [`Transport::Unix`] or by a configured
/// [`Connection::unix_domain_socket`].
///
/// # Errors
///
/// Returns the mapped [`Error`] described above when HTTP/3 is not permissible;
/// otherwise `Ok(())`.
pub fn conn_may_http3(conn: &Connection) -> Result<()> {
    // "cannot do QUIC over a Unix domain socket" → CURLE_QUIC_CONNECT_ERROR.
    if conn.transport_wanted == Transport::Unix || conn.unix_domain_socket.is_some() {
        return Err(Error::quic_connect(
            "cannot do QUIC over a Unix domain socket",
        ));
    }

    // HTTP/3 requires TLS (PROTOPT_SSL) — a non-HTTPS URL is malformed for h3.
    if !conn.scheme.is_ssl {
        let msg = "HTTP/3 requested for non-HTTPS URL";
        tracing::error!("{msg}");
        return Err(Error::url(msg));
    }

    // No SOCKS proxy: QUIC cannot traverse a SOCKS proxy.
    if conn.bits.socksproxy {
        let msg = "HTTP/3 is not supported over a SOCKS proxy";
        tracing::error!("{msg}");
        return Err(Error::url(msg));
    }

    // No tunneling HTTP proxy: QUIC cannot be tunneled over an HTTP CONNECT.
    if conn.bits.httpproxy && conn.bits.tunnel_proxy {
        let msg = "HTTP/3 is not supported over an HTTP proxy";
        tracing::error!("{msg}");
        return Err(Error::url(msg));
    }

    Ok(())
}

/// The ALPN protocol list advertised for an HTTP/3 handshake (`ALPN_SPEC_H3`).
///
/// Returns `[b"h3"]` — the finalized RFC 9114 token. This is applied to the
/// [`quinn::ClientConfig`]'s underlying [`rustls::ClientConfig`] via
/// [`crate::tls::config::TlsConfig::with_alpn`].
#[must_use]
pub fn alpn_protocols() -> Vec<Vec<u8>> {
    vec![ALPN_H3.to_vec()]
}

/// The QUIC/HTTP-3 backend token reported in the version banner
/// (← `Curl_quic_ver`, `vquic.c:67`).
///
/// The C backends reported `"ngtcp2/<v> nghttp3/<v>"` or `"quiche/<v>"`; the
/// Rust rewrite reports the single `quinn` token. The concrete crate version is
/// intentionally *not* hard-coded here (the workspace owns all versions); the
/// canonical `--version` banner assembled by [`crate::version`] already carries
/// the `quinn` token, and this accessor exists for parity with `Curl_quic_ver`.
#[must_use]
pub fn quic_version() -> &'static str {
    "quinn"
}

// ===========================================================================
// PHASE 2 — QUIC endpoint & connection (replaces the ngtcp2/quiche transport).
//
// `quinn` fully owns UDP I/O, congestion control, loss recovery, and
// packetization — the entire body of `vquic.c`'s `vquic_ctx_init` /
// `vquic_recv_packets` / `vquic_send` machinery, and all of the ngtcp2/quiche
// packet handling. What this layer reproduces is curl's connection
// *lifecycle*: build the client TLS config carrying the h3 ALPN, bind a UDP
// endpoint, and establish the QUIC connection with curl's diagnostic text.
// ===========================================================================

/// Build a [`quinn::ClientConfig`] for an HTTP/3 handshake from a connection's
/// TLS policy.
///
/// The certificate-validation *policy* — root store, verify-peer/verify-host,
/// and the `--insecure` danger verifier — is inherited from the connection's
/// [`crate::tls::config::TlsConfig`] so it stays identical to the TLS layer.
/// Only the two QUIC-mandatory settings are overridden here:
///
/// * ALPN is forced to `[b"h3"]` (see [`alpn_protocols`]).
/// * The TLS floor is pinned to 1.3. QUIC requires TLS 1.3, and
///   [`quinn::crypto::rustls::QuicClientConfig`] rejects a rustls config that
///   lacks a TLS 1.3 initial cipher suite.
///
/// The resulting object is **quinn's** config, produced through
/// [`quinn::crypto::rustls::QuicClientConfig`] — never a `tokio-rustls`
/// connector.
///
/// # Errors
///
/// Returns [`Error::quic_connect`] (`CURLE_QUIC_CONNECT_ERROR`, 96) if the
/// rustls config cannot be built or lacks a TLS 1.3 initial cipher suite.
fn build_quic_client_config(conn: &Connection) -> Result<quinn::ClientConfig> {
    // Clone the connection's TLS policy, then force the QUIC-mandatory bits.
    let tls = (*conn.ssl_config)
        .clone()
        .with_alpn(alpn_protocols())
        .with_min_version(tls_config::TlsVersion::Tlsv1_3);
    let rustls_config = tls.build()?;
    quic_client_config_from_rustls(rustls_config)
}

/// Wrap an already-built [`rustls::ClientConfig`] into a
/// [`quinn::ClientConfig`], mapping a missing TLS 1.3 cipher suite to curl's
/// QUIC-connect error. Split out so tests can supply a bespoke rustls config.
///
/// # Errors
///
/// Returns [`Error::quic_connect`] (96) if `rustls_config` has no TLS 1.3
/// initial cipher suite (QUIC cannot start without one).
fn quic_client_config_from_rustls(
    rustls_config: Arc<rustls::ClientConfig>,
) -> Result<quinn::ClientConfig> {
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
        .map_err(|e| Error::quic_connect(format!("QUIC TLS setup failed: {e}")))?;
    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
}

/// The wildcard local bind address whose family matches the peer's, so the
/// client UDP socket can reach an IPv4 or IPv6 server (← `vquic.c` socket
/// binding).
fn client_bind_addr(peer: SocketAddr) -> SocketAddr {
    if peer.is_ipv6() {
        SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
    } else {
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
    }
}

/// Format curl's canonical QUIC-connect failure text and return the mapped
/// [`Error::quic_connect`] (`CURLE_QUIC_CONNECT_ERROR`, 96).
///
/// Mirrors curl's `"QUIC connect to %s port %u failed: %s"` diagnostic
/// (`vquic.c` / `curl_ngtcp2.c`), preserving the `--trace` vocabulary.
///
/// Takes the host/port by value rather than borrowing the whole
/// [`Connection`]: this lets [`perform`] format transfer-time errors without
/// holding a shared `&Connection` (which is not `Send`) across its `await`
/// points, keeping the returned future `Send` for the multi-threaded runtime.
fn quic_connect_failed(host: &str, port: u16, detail: impl std::fmt::Display) -> Error {
    let msg = format!("QUIC connect to {host} port {port} failed: {detail}");
    tracing::error!("{msg}");
    Error::quic_connect(msg)
}

/// Establish a QUIC connection to `addr` for HTTP/3 (← `vquic_ctx_init` plus
/// the ngtcp2/quiche connect paths, collapsed onto `quinn`).
///
/// Enforces curl's HTTP/3 eligibility rules ([`conn_may_http3`]) first, builds
/// the quinn client config ([`build_quic_client_config`]), binds a UDP
/// endpoint, and performs the QUIC handshake.
///
/// The returned [`quinn::Endpoint`] **must be kept alive** for the whole
/// transfer: quinn's endpoint driver task stops once the last `Endpoint` clone
/// is dropped, which would silently tear down the connection. [`perform`]
/// therefore owns both returned values for the transfer's duration.
///
/// # Errors
///
/// * [`Error::quic_connect`] (96) if HTTP/3 is not permissible
///   ([`conn_may_http3`]), if the UDP endpoint cannot be bound, or if the QUIC
///   handshake fails (bad certificate, ALPN mismatch, timeout, refusal).
pub async fn connect_quic(
    conn: &mut Connection,
    addr: SocketAddr,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    // Enforce curl's HTTP/3 eligibility rules first (exact codes / text).
    conn_may_http3(conn)?;

    let client_config = build_quic_client_config(conn)?;

    // Own the host/port for error text so no shared `&Connection` is held across
    // the handshake `await` below (keeps this future `Send`; `&Connection` is
    // not, because a connection filter is not `Sync`).
    let host = conn.host.name.clone();
    let port = conn.remote_port;

    // Bind a client UDP endpoint. quinn spawns its endpoint driver on the
    // ambient Tokio runtime (Tokio is the sole async runtime, per the AAP).
    let endpoint = quinn::Endpoint::client(client_bind_addr(addr))
        .map_err(|e| quic_connect_failed(&host, port, e))?;

    // The SNI / certificate name is curl's connection host name.
    let connecting = endpoint
        .connect_with(client_config, addr, &host)
        .map_err(|e| quic_connect_failed(&host, port, e))?;

    let connection = connecting
        .await
        .map_err(|e| quic_connect_failed(&host, port, e))?;

    tracing::debug!(
        "QUIC connected to {} port {} (remote {})",
        host,
        port,
        connection.remote_address()
    );

    Ok((endpoint, connection))
}

// ===========================================================================
// PHASE 3 — HTTP/3 request / response over `h3` + `h3-quinn`.
//
// HTTP/3 shares HTTP/2's pseudo-header model, so request-header canonicalization
// is delegated to `crate::protocols::http::http_req_to_h2`. `h3` derives its
// own `:method`/`:scheme`/`:authority`/`:path` from the request URI + method,
// so we translate curl's request model into an `http::Request` and let `h3`
// emit the pseudo-headers. A single QUIC connection multiplexes streams
// natively (like the HTTP/2 model); this driver performs the one request the
// transfer layer drives per call.
// ===========================================================================

/// The default `host[:port]` authority for a connection, omitting the port when
/// it is the scheme default (matches curl's `:authority` construction).
fn default_authority(conn: &Connection) -> String {
    if conn.remote_port == 0 || conn.remote_port == conn.scheme.default_port {
        conn.host.name.clone()
    } else {
        format!("{}:{}", conn.host.name, conn.remote_port)
    }
}

/// Translate curl's request model into an [`http::Request`] for `h3`.
///
/// Header canonicalization (lowercasing field names, dropping
/// connection-specific headers, the `TE: trailers` special case, and building
/// the `:method`/`:scheme`/`:authority`/`:path` pseudo-headers) is delegated to
/// [`crate::protocols::http::http_req_to_h2`], which HTTP/3 shares with
/// HTTP/2. Because `h3` derives its own pseudo-headers from the request URI and
/// method, the pseudo-headers are extracted back out to rebuild the URI, and
/// only the regular fields are placed in the [`http::HeaderMap`] (a colon is
/// not a legal `http::HeaderName` byte, so pseudo-headers must not be added as
/// ordinary headers).
///
/// # Errors
///
/// Returns [`Error::http3`] (`CURLE_HTTP3`, 95) if the method or the assembled
/// URI/headers are not valid for an [`http::Request`].
fn build_http_request(
    req: &HttpReqData,
    is_ssl: bool,
    default_auth: &str,
) -> Result<http::Request<()>> {
    let h2_headers = http_req_to_h2(req, is_ssl)?;

    let mut method = String::new();
    let mut scheme = String::new();
    let mut authority = String::new();
    let mut path = String::new();
    let mut builder = http::Request::builder();

    for (name, value) in h2_headers.iter() {
        match name {
            HTTP_PSEUDO_METHOD => method = value.to_string(),
            HTTP_PSEUDO_SCHEME => scheme = value.to_string(),
            HTTP_PSEUDO_AUTHORITY => authority = value.to_string(),
            HTTP_PSEUDO_PATH => path = value.to_string(),
            // Ordinary (already-lowercased, filtered) request headers.
            _ => builder = builder.header(name, value),
        }
    }

    // Fall back to sensible defaults if any pseudo-header was absent.
    if method.is_empty() {
        method.clone_from(&req.method);
    }
    if scheme.is_empty() {
        scheme = if is_ssl { "https" } else { "http" }.to_string();
    }
    if authority.is_empty() {
        authority = default_auth.to_string();
    }
    if path.is_empty() {
        path.push('/');
    }

    let method = http::Method::from_bytes(method.as_bytes())
        .map_err(|e| Error::http3(format!("invalid HTTP/3 request method: {e}")))?;
    let uri = format!("{scheme}://{authority}{path}");

    builder
        .method(method)
        .uri(uri.as_str())
        .body(())
        .map_err(|e| Error::http3(format!("invalid HTTP/3 request: {e}")))
}

/// Convert an `h3` response head into curl's [`HttpResp`] (← the response-head
/// handling in `curl_ngtcp2.c` / `curl_quiche.c`).
///
/// Non-UTF-8 header values are dropped with a trace note; curl's header model
/// stores text and such values are not representable (nor produced by
/// well-behaved HTTP/3 servers).
fn response_head_to_httpresp(response: &http::Response<()>) -> HttpResp {
    let status = i32::from(response.status().as_u16());
    let description = response.status().canonical_reason();
    let mut resp = HttpResp::make(status, description);
    for (name, value) in response.headers() {
        match value.to_str() {
            Ok(text) => resp.headers.add(name.as_str(), text),
            Err(_) => {
                tracing::debug!(
                    "dropping non-text HTTP/3 response header: {}",
                    name.as_str()
                );
            }
        }
    }
    resp
}

/// Drive a single HTTP/3 request/response exchange to completion (← the request
/// path of `curl_ngtcp2.c` / `curl_quiche.c`, collapsed onto `quinn` + `h3`).
///
/// Establishes a QUIC connection to `addr`, opens one HTTP/3 request stream,
/// streams the optional `body`, then reads the response head into an
/// [`HttpResp`] and streams each response-body chunk to `write_body` (the
/// transfer write-out path) as it arrives. Response trailers, when present, are
/// appended to [`HttpResp::trailers`].
///
/// The single QUIC connection multiplexes streams natively, and `h3`'s
/// `SendRequest` is cloneable, so additional concurrent request streams may be
/// opened over the same connection (curl's multiplexed-transfer model). This
/// entry point performs the one request the transfer layer drives per call.
///
/// The `conn` handle is taken as `&mut` to match the transfer layer's calling
/// convention, but no connection mutation is required: all QUIC/HTTP-3 state is
/// owned locally for the duration of the transfer.
///
/// # Errors
///
/// * [`Error::quic_connect`] (`CURLE_QUIC_CONNECT_ERROR`, 96) — QUIC handshake
///   or HTTP/3 control-stream setup failure.
/// * [`Error::http3`] (`CURLE_HTTP3`, 95) — an HTTP/3 protocol or stream error
///   before any response-body bytes were delivered.
/// * [`Error::PartialFile`] (`CURLE_PARTIAL_FILE`, 18) — a stream/connection
///   error *after* body bytes were already delivered (mirrors
///   `curl_ngtcp2.c:1389`, `data->req.bytecount ? CURLE_PARTIAL_FILE :
///   CURLE_HTTP3`).
pub async fn perform<F>(
    conn: &mut Connection,
    addr: SocketAddr,
    req: HttpReqData,
    body: Option<Bytes>,
    mut write_body: F,
) -> Result<HttpResp>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    // Read the request-shaping inputs and own the connection's identity for
    // error text up front. After the QUIC handshake below, `conn` is no longer
    // referenced, so nothing borrows it across the request/driver `await`s —
    // which is what keeps this future `Send` (a shared `&Connection` is not
    // `Send`, because a connection filter is not `Sync`). The `AtomicU64`
    // byte counter is likewise shared by value, not by borrowing `conn`.
    let is_ssl = conn.scheme.is_ssl;
    let default_auth = default_authority(conn);
    let host = conn.host.name.clone();
    let port = conn.remote_port;

    // Phase 2: establish QUIC. `_endpoint` MUST stay alive for the whole
    // transfer (dropping the last Endpoint clone stops quinn's driver task).
    // This is the last use of `conn`.
    let (_endpoint, quic_conn) = connect_quic(conn, addr).await?;

    // Wrap the quinn connection for `h3` and split it into the connection
    // driver plus the request sender. A failure here is an HTTP/3 control
    // stream setup failure, which curl treats as a QUIC connect error (96).
    let h3_conn = h3_quinn::Connection::new(quic_conn);
    let (mut driver, mut send_request) = h3::client::new(h3_conn)
        .await
        .map_err(|e| quic_connect_failed(&host, port, e))?;

    let http_req = build_http_request(&req, is_ssl, &default_auth)?;

    // Count response-body bytes actually delivered to the write-out path, so a
    // late failure maps to PARTIAL_FILE (18) rather than HTTP3 (95), mirroring
    // `curl_ngtcp2.c:1389`. Shared (by `&`) between the request future and the
    // driver arm; `AtomicU64` keeps the resulting future `Send`.
    let received = AtomicU64::new(0);

    // The request future performs the full send/recv exchange on one stream.
    // It borrows only the owned `host`/`port` (not `conn`) for error text.
    let request_fut = async {
        let mut stream = send_request
            .send_request(http_req)
            .await
            .map_err(|e| map_h3_stream_error(&host, port, &e, false))?;

        // Stream the request body, if any, then half-close the send side.
        if let Some(body) = body {
            if !body.is_empty() {
                stream
                    .send_data(body)
                    .await
                    .map_err(|e| map_h3_stream_error(&host, port, &e, false))?;
            }
        }
        stream
            .finish()
            .await
            .map_err(|e| map_h3_stream_error(&host, port, &e, false))?;

        // Response head.
        let response = stream
            .recv_response()
            .await
            .map_err(|e| map_h3_stream_error(&host, port, &e, false))?;
        let mut resp = response_head_to_httpresp(&response);

        // Response body: stream each chunk to the write-out path as it arrives.
        loop {
            match stream.recv_data().await {
                Ok(Some(mut chunk)) => {
                    while chunk.has_remaining() {
                        let n = {
                            let piece = chunk.chunk();
                            write_body(piece)?;
                            piece.len()
                        };
                        received.fetch_add(n as u64, Ordering::Relaxed);
                        chunk.advance(n);
                    }
                }
                // Clean end of the response body.
                Ok(None) => break,
                // A graceful (H3_NO_ERROR) close is a normal end of stream.
                Err(ref e) if e.is_h3_no_error() => break,
                Err(e) => {
                    let bytes = received.load(Ordering::Relaxed) > 0;
                    return Err(map_h3_stream_error(&host, port, &e, bytes));
                }
            }
        }

        // Optional trailers.
        match stream.recv_trailers().await {
            Ok(Some(trailers)) => {
                for (name, value) in &trailers {
                    match value.to_str() {
                        Ok(text) => resp.trailers.add(name.as_str(), text),
                        Err(_) => {
                            tracing::debug!("dropping non-text HTTP/3 trailer: {}", name.as_str())
                        }
                    }
                }
            }
            Ok(None) => {}
            Err(ref e) if e.is_h3_no_error() => {}
            Err(e) => {
                let bytes = received.load(Ordering::Relaxed) > 0;
                return Err(map_h3_stream_error(&host, port, &e, bytes));
            }
        }

        Ok::<HttpResp, Error>(resp)
    };

    // The connection driver must run concurrently with the request. Racing the
    // request against `poll_close` drives the connection's control streams
    // (SETTINGS, GOAWAY, QPACK) without spawning a task — avoiding `'static` /
    // `Send` bounds and keeping the borrowed endpoint alive. `biased` polls the
    // request first so a fully-buffered response is drained before a trailing
    // connection-close is observed. If the driver resolves while the request is
    // still pending, the connection failed underneath the transfer.
    let driver_fut = std::future::poll_fn(|cx| driver.poll_close(cx));

    tokio::pin!(request_fut);
    tokio::pin!(driver_fut);

    tokio::select! {
        biased;
        result = &mut request_fut => result,
        conn_err = &mut driver_fut => {
            let bytes = received.load(Ordering::Relaxed) > 0;
            Err(map_h3_connection_error(&host, port, &conn_err, bytes))
        }
    }
}

// ===========================================================================
// PHASE 4 — Connection-filter contract & error mapping (FROZEN codes).
// ===========================================================================

/// The frozen-code core shared by every transfer-time HTTP/3 error mapping
/// (← `curl_ngtcp2.c:1389`).
///
/// Logs the `--trace` diagnostic, then chooses curl's exact error code:
///
/// * `bytes_received` true (curl's `data->req.bytecount != 0`) →
///   [`Error::PartialFile`] (`CURLE_PARTIAL_FILE`, 18).
/// * otherwise → [`Error::http3`] (`CURLE_HTTP3`, 95).
fn partial_or_http3(host: &str, port: u16, detail: &str, bytes_received: bool) -> Error {
    let msg = format!("HTTP/3 error on {host} port {port}: {detail}");
    tracing::error!("{msg}");
    if bytes_received {
        // Bytes already reached the write-out path: partial transfer.
        Error::PartialFile
    } else {
        Error::http3(msg)
    }
}

/// Map an `h3` [`StreamError`](h3::error::StreamError) to curl's frozen error
/// codes, preserving the `--trace` message. HTTP/3 stream/protocol failures
/// become [`Error::http3`] (95), or [`Error::PartialFile`] (18) when body bytes
/// were already delivered.
fn map_h3_stream_error(
    host: &str,
    port: u16,
    err: &h3::error::StreamError,
    bytes_received: bool,
) -> Error {
    partial_or_http3(host, port, &format!("stream error: {err}"), bytes_received)
}

/// Map an `h3` [`ConnectionError`](h3::error::ConnectionError) observed *during*
/// a transfer to curl's frozen error codes. A connection that fails underneath
/// an in-flight request is an HTTP/3 error (95), or a partial file (18) when
/// body bytes were already delivered.
fn map_h3_connection_error(
    host: &str,
    port: u16,
    err: &h3::error::ConnectionError,
    bytes_received: bool,
) -> Error {
    partial_or_http3(
        host,
        port,
        &format!("connection error: {err}"),
        bytes_received,
    )
}

/// The HTTP/3 connection filter (← curl's `Curl_cft_http3`, `curl_ngtcp2.c`).
///
/// Integrates with [`crate::conn::filters`] to answer connection-chain queries
/// once QUIC + HTTP/3 are established. It reports the same capabilities curl's
/// C filter did — `CF_TYPE_IP_CONNECT | CF_TYPE_SSL | CF_TYPE_MULTIPLEX |
/// CF_TYPE_HTTP` — and the same query values: HTTP version `30`, transport
/// `QUIC`, negotiated ALPN `"h3"`, and the peer's max concurrent streams.
#[derive(Debug, Clone)]
pub struct Http3Filter {
    /// Whether the QUIC + HTTP/3 layer has finished connecting.
    connected: bool,
    /// The negotiated ALPN protocol (`"h3"` once connected).
    alpn: Option<String>,
    /// The peer's maximum concurrent bidirectional streams (from the QUIC
    /// transport parameters), `0` until they arrive.
    max_bidi_streams: u32,
}

impl Http3Filter {
    /// Create a not-yet-connected HTTP/3 filter (← the filter constructed
    /// during `cf_connect`, before the handshake completes).
    #[must_use]
    pub fn new() -> Self {
        Self {
            connected: false,
            alpn: None,
            max_bidi_streams: 0,
        }
    }

    /// Create a connected HTTP/3 filter reporting `max_bidi_streams` as the
    /// peer's concurrent-stream limit (`0` means "not yet known", which reports
    /// curl's default of [`DEFAULT_MAX_CONCURRENT_STREAMS`]).
    #[must_use]
    pub fn connected(max_bidi_streams: u32) -> Self {
        Self {
            connected: true,
            alpn: Some(String::from("h3")),
            max_bidi_streams,
        }
    }

    /// The value reported for `CF_QUERY_MAX_CONCURRENT` (← `cf_ngtcp2_query`).
    ///
    /// * Not connected → `0` (curl reports no capacity before the handshake).
    /// * Connected but transport params not yet arrived → curl's multi default
    ///   of [`DEFAULT_MAX_CONCURRENT_STREAMS`].
    /// * Otherwise → the peer's limit, capped at [`i32::MAX`] (curl clamps to
    ///   `INT_MAX`).
    fn max_concurrent(&self) -> u32 {
        if !self.connected {
            return 0;
        }
        if self.max_bidi_streams == 0 {
            return DEFAULT_MAX_CONCURRENT_STREAMS;
        }
        self.max_bidi_streams.min(i32::MAX as u32)
    }
}

impl Default for Http3Filter {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionFilter for Http3Filter {
    fn name(&self) -> &'static str {
        // Preserved verbatim from curl's `Curl_cft_http3.name` for `--trace`.
        "HTTP/3"
    }

    fn cf_type(&self) -> CfType {
        // curl: CF_TYPE_IP_CONNECT | CF_TYPE_SSL | CF_TYPE_MULTIPLEX | CF_TYPE_HTTP.
        CfType::IP_CONNECT | CfType::SSL | CfType::MULTIPLEX | CfType::HTTP
    }

    fn query(&self, cx: &QueryCtx<'_>, query: CfQuery, out: &mut QueryOut) -> Result<()> {
        match query {
            // Negotiated HTTP version is always 30 for this filter.
            CfQuery::HttpVersion => {
                *out = QueryOut::HttpVersion(HTTP3_VERSION);
                Ok(())
            }
            // The transport is QUIC.
            CfQuery::Transport => {
                *out = QueryOut::Transport(Transport::Quic);
                Ok(())
            }
            // The peer's max concurrent streams (curl's CF_QUERY_MAX_CONCURRENT).
            CfQuery::MaxConcurrent => {
                *out = QueryOut::MaxConcurrent(self.max_concurrent());
                Ok(())
            }
            // ALPN is "h3" once connected; otherwise defer to the next filter.
            CfQuery::AlpnNegotiated => match self.alpn {
                Some(ref alpn) => {
                    *out = QueryOut::AlpnNegotiated(alpn.clone());
                    Ok(())
                }
                None => cx.query_next(query, out),
            },
            // Everything else is delegated down the chain, as curl's filter does.
            _ => cx.query_next(query, out),
        }
    }
}

// ===========================================================================
// Tests — unit coverage plus an in-process `quinn` + `h3` mock server backed by
// an `rcgen` ephemeral CA. No external daemons are used; every exchange runs
// inside the test's Tokio runtime.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{FilterChain, Scheme, FIRSTSOCKET};
    use crate::error::CurlCode;
    use crate::tls::config::TlsConfig;
    use bytes::Bytes;
    use std::time::Duration;

    // ---- helpers ------------------------------------------------------

    /// Install the aws-lc-rs process default crypto provider (idempotent; the
    /// TLS layer installs the same provider, so this only matters for the
    /// server-side rustls config built directly in tests).
    fn install_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    /// Build an HTTPS [`Connection`] to `host:port` carrying `tls`.
    fn https_conn(host: &str, port: u16, tls: TlsConfig) -> Connection {
        let mut scheme = Scheme::new("https", 443);
        scheme.is_ssl = true;
        let mut conn = Connection::new(scheme, host, port);
        conn.ssl_config = Arc::new(tls);
        conn
    }

    /// A plain (non-TLS) HTTP connection, for the non-HTTPS eligibility test.
    fn http_conn(host: &str, port: u16) -> Connection {
        let scheme = Scheme::new("http", 80);
        Connection::new(scheme, host, port)
    }

    /// What the mock HTTP/3 server does with the one request it accepts.
    #[derive(Clone, Copy)]
    enum ServerBehavior {
        /// Send `200 OK` with a small text body.
        RespondOk,
        /// Reset the request stream with a non-zero HTTP/3 error code.
        ResetStream,
    }

    /// Start an in-process `quinn` + `h3` server on `127.0.0.1:0`, returning its
    /// bound address. The spawned task owns the endpoint so its driver stays
    /// alive for the duration of the test.
    async fn spawn_server(behavior: ServerBehavior) -> SocketAddr {
        install_provider();

        // Ephemeral self-signed certificate for "localhost".
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate self-signed cert");
        let cert_der = issued.cert.der().clone();
        let key = rustls_pki_types::PrivateKeyDer::from(
            rustls_pki_types::PrivatePkcs8KeyDer::from(issued.signing_key.serialize_der()),
        );

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key)
            .expect("server rustls config");
        server_crypto.alpn_protocols = vec![b"h3".to_vec()];

        let quic_crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).expect("quic server");
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
        let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
            .expect("bind server endpoint");
        let addr = endpoint.local_addr().expect("server addr");

        tokio::spawn(async move {
            // `endpoint` is owned by this task so its driver stays alive; it is
            // dropped only once `serve_one` returns (after the client closes).
            if let Some(incoming) = endpoint.accept().await {
                if let Ok(conn) = incoming.await {
                    serve_one(conn, behavior).await;
                }
            }
            drop(endpoint);
        });

        addr
    }

    /// Serve the one HTTP/3 request the client makes, then keep the connection
    /// alive (by continuing to drive `accept`) until the client closes it, so
    /// the response is fully delivered before teardown.
    async fn serve_one(conn: quinn::Connection, behavior: ServerBehavior) {
        let mut h3_conn = match h3::server::Connection::new(h3_quinn::Connection::new(conn)).await {
            Ok(c) => c,
            Err(_) => return,
        };
        // Drive `accept` until the client closes the connection (or an error
        // occurs), which keeps the server connection — and thus quinn's
        // transmission of the buffered response — alive until the client is
        // done reading.
        while let Ok(Some(resolver)) = h3_conn.accept().await {
            let (_req, mut stream) = match resolver.resolve_request().await {
                Ok(pair) => pair,
                Err(_) => continue,
            };
            match behavior {
                ServerBehavior::RespondOk => {
                    let response = http::Response::builder()
                        .status(http::StatusCode::OK)
                        .header("content-type", "text/plain")
                        .body(())
                        .unwrap();
                    let _ = stream.send_response(response).await;
                    let _ = stream.send_data(Bytes::from_static(b"hello world")).await;
                    let _ = stream.finish().await;
                }
                ServerBehavior::ResetStream => {
                    // Reset the response stream with a non-zero code; the client
                    // observes an HTTP/3 stream error (→ CURLE_HTTP3, 95).
                    stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                }
            }
        }
    }

    /// A GET request targeting `localhost:port`.
    fn get_request(port: u16) -> HttpReqData {
        let authority = format!("localhost:{port}");
        HttpReqData::make("GET", Some("https"), Some(&authority), Some("/"))
    }

    // ---- Phase 1: ALPN, version, eligibility --------------------------

    #[test]
    fn alpn_advertises_h3_only() {
        assert_eq!(alpn_protocols(), vec![b"h3".to_vec()]);
        assert_eq!(ALPN_H3, b"h3");
        assert_eq!(ALPN_H3_29, b"h3-29");
    }

    #[test]
    fn version_token_is_quinn() {
        assert_eq!(quic_version(), "quinn");
    }

    #[test]
    fn conn_may_http3_accepts_plain_https() {
        let conn = https_conn("example.com", 443, TlsConfig::new());
        assert!(conn_may_http3(&conn).is_ok());
    }

    #[test]
    fn conn_may_http3_rejects_unix_transport_with_quic_connect() {
        let mut conn = https_conn("example.com", 443, TlsConfig::new());
        conn.transport_wanted = Transport::Unix;
        let err = conn_may_http3(&conn).unwrap_err();
        assert_eq!(err.code(), CurlCode::QuicConnectError);
    }

    #[test]
    fn conn_may_http3_rejects_unix_socket_path_with_quic_connect() {
        let mut conn = https_conn("example.com", 443, TlsConfig::new());
        conn.unix_domain_socket = Some("/tmp/curl-h3.sock".to_string());
        let err = conn_may_http3(&conn).unwrap_err();
        assert_eq!(err.code(), CurlCode::QuicConnectError);
    }

    #[test]
    fn conn_may_http3_rejects_non_https_with_url_malformat() {
        let conn = http_conn("example.com", 80);
        let err = conn_may_http3(&conn).unwrap_err();
        assert_eq!(err.code(), CurlCode::UrlMalformat);
    }

    #[test]
    fn conn_may_http3_rejects_socks_proxy_with_url_malformat() {
        let mut conn = https_conn("example.com", 443, TlsConfig::new());
        conn.bits.socksproxy = true;
        let err = conn_may_http3(&conn).unwrap_err();
        assert_eq!(err.code(), CurlCode::UrlMalformat);
    }

    #[test]
    fn conn_may_http3_rejects_tunneling_http_proxy_with_url_malformat() {
        let mut conn = https_conn("example.com", 443, TlsConfig::new());
        conn.bits.httpproxy = true;
        conn.bits.tunnel_proxy = true;
        let err = conn_may_http3(&conn).unwrap_err();
        assert_eq!(err.code(), CurlCode::UrlMalformat);
    }

    // ---- Phase 3: request construction --------------------------------

    #[test]
    fn build_http_request_produces_absolute_uri_and_method() {
        let req = HttpReqData::make("GET", Some("https"), Some("example.com"), Some("/path?q=1"));
        let http_req = build_http_request(&req, true, "example.com").unwrap();
        assert_eq!(http_req.method(), http::Method::GET);
        assert_eq!(http_req.uri().scheme_str(), Some("https"));
        assert_eq!(
            http_req.uri().authority().map(|a| a.as_str()),
            Some("example.com")
        );
        assert_eq!(http_req.uri().path(), "/path");
        // Pseudo-headers must NOT leak into the ordinary header map.
        assert!(http_req.headers().get(":method").is_none());
    }

    #[test]
    fn default_authority_omits_default_port() {
        let conn = https_conn("example.com", 443, TlsConfig::new());
        assert_eq!(default_authority(&conn), "example.com");
        let conn = https_conn("example.com", 8443, TlsConfig::new());
        assert_eq!(default_authority(&conn), "example.com:8443");
    }

    // ---- Phase 4: error mapping (frozen codes) ------------------------

    #[test]
    fn quic_connect_failure_maps_to_96() {
        assert_eq!(
            quic_connect_failed("example.com", 443, "boom").code(),
            CurlCode::QuicConnectError
        );
    }

    #[test]
    fn transfer_error_without_bytes_is_http3_95() {
        assert_eq!(
            partial_or_http3("example.com", 443, "stream reset", false).code(),
            CurlCode::Http3
        );
    }

    #[test]
    fn transfer_error_with_bytes_is_partial_file_18() {
        assert_eq!(
            partial_or_http3("example.com", 443, "stream reset", true).code(),
            CurlCode::PartialFile
        );
    }

    // ---- Phase 4: Http3Filter contract --------------------------------

    #[test]
    fn filter_name_and_capabilities() {
        let filter = Http3Filter::connected(0);
        assert_eq!(filter.name(), "HTTP/3");
        let ty = filter.cf_type();
        assert!(ty.contains(CfType::IP_CONNECT));
        assert!(ty.contains(CfType::SSL));
        assert!(ty.contains(CfType::MULTIPLEX));
        assert!(ty.contains(CfType::HTTP));
        assert!(!ty.contains(CfType::PROXY));
    }

    #[test]
    fn filter_reports_http_version_30() {
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(Http3Filter::connected(0)));
        let mut out = QueryOut::None;
        chain.query(CfQuery::HttpVersion, &mut out).unwrap();
        assert!(matches!(out, QueryOut::HttpVersion(30)));
    }

    #[test]
    fn filter_reports_transport_quic() {
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(Http3Filter::connected(0)));
        let mut out = QueryOut::None;
        chain.query(CfQuery::Transport, &mut out).unwrap();
        assert!(matches!(out, QueryOut::Transport(Transport::Quic)));
    }

    #[test]
    fn filter_reports_alpn_h3_when_connected() {
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(Http3Filter::connected(0)));
        let mut out = QueryOut::None;
        chain.query(CfQuery::AlpnNegotiated, &mut out).unwrap();
        match out {
            QueryOut::AlpnNegotiated(alpn) => assert_eq!(alpn, "h3"),
            other => panic!("expected ALPN h3, got {other:?}"),
        }
    }

    #[test]
    fn filter_max_concurrent_rules() {
        // Not connected → 0.
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(Http3Filter::new()));
        let mut out = QueryOut::None;
        chain.query(CfQuery::MaxConcurrent, &mut out).unwrap();
        assert!(matches!(out, QueryOut::MaxConcurrent(0)));

        // Connected, params not yet arrived (0) → curl default of 100.
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(Http3Filter::connected(0)));
        let mut out = QueryOut::None;
        chain.query(CfQuery::MaxConcurrent, &mut out).unwrap();
        assert!(matches!(out, QueryOut::MaxConcurrent(100)));

        // Connected with a known peer limit → that limit.
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(Http3Filter::connected(42)));
        let mut out = QueryOut::None;
        chain.query(CfQuery::MaxConcurrent, &mut out).unwrap();
        assert!(matches!(out, QueryOut::MaxConcurrent(42)));
    }

    // ---- End-to-end over a real in-process QUIC + HTTP/3 exchange -----

    #[tokio::test]
    async fn end_to_end_get_receives_response_body() {
        let addr = spawn_server(ServerBehavior::RespondOk).await;
        // `--insecure` client: trust the ephemeral self-signed cert AND exercise
        // the shared danger-verifier wiring from `crate::tls::config`.
        let mut conn = https_conn("localhost", addr.port(), TlsConfig::new().insecure());
        let req = get_request(addr.port());

        let mut body = Vec::new();
        let resp = tokio::time::timeout(
            Duration::from_secs(15),
            perform(&mut conn, addr, req, None, |chunk| {
                body.extend_from_slice(chunk);
                Ok(())
            }),
        )
        .await
        .expect("perform timed out")
        .expect("perform failed");

        assert_eq!(resp.status, 200);
        assert_eq!(body, b"hello world");
        // Response headers were captured from the h3 head.
        assert_eq!(resp.headers.get("content-type"), Some("text/plain"));
    }

    #[tokio::test]
    async fn quic_handshake_failure_maps_to_96() {
        // Server presents a self-signed cert; the client uses DEFAULT
        // verification (no `--insecure`), so the handshake fails fast with a
        // certificate error → CURLE_QUIC_CONNECT_ERROR (96).
        let addr = spawn_server(ServerBehavior::RespondOk).await;
        let mut conn = https_conn("localhost", addr.port(), TlsConfig::new());
        let req = get_request(addr.port());

        let result = tokio::time::timeout(
            Duration::from_secs(15),
            perform(&mut conn, addr, req, None, |_chunk| Ok(())),
        )
        .await
        .expect("perform timed out");

        let err = result.expect_err("handshake should fail against an untrusted cert");
        assert_eq!(err.code(), CurlCode::QuicConnectError);
    }

    #[tokio::test]
    async fn http3_stream_reset_maps_to_95() {
        // Server accepts the request then resets the stream with a non-zero
        // HTTP/3 code before any body → CURLE_HTTP3 (95).
        let addr = spawn_server(ServerBehavior::ResetStream).await;
        let mut conn = https_conn("localhost", addr.port(), TlsConfig::new().insecure());
        let req = get_request(addr.port());

        let result = tokio::time::timeout(
            Duration::from_secs(15),
            perform(&mut conn, addr, req, None, |_chunk| Ok(())),
        )
        .await
        .expect("perform timed out");

        let err = result.expect_err("stream reset should surface as an error");
        assert_eq!(err.code(), CurlCode::Http3);
    }
}
