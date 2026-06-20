//! The HTTP/3 protocol engine — HTTP/3 over QUIC on the pure-Rust
//! `quinn` + `h3` stack.
//!
//! This module is the Rust replacement for curl's QUIC/HTTP-3 backends
//! (`lib/vquic/vquic.c`, `lib/vquic/curl_ngtcp2.c` over ngtcp2+nghttp3, and
//! `lib/vquic/curl_quiche.c` over quiche). Those C files are consumed strictly
//! as a **behavioral / wire oracle** — they are *not* transliterated. curl
//! hand-rolls the UDP socket, GSO segmentation, congestion control, and loss
//! recovery in `vquic.c`; in the Rust port [`quinn`] owns all of that, so the
//! bulk of `vquic.c` has no analog here. What this module reproduces is the
//! *observable* HTTP/3 behavior the regression suite checks: the
//! pseudo-header / status mapping, the synthesized `HTTP/3 <code>` status line,
//! the response-header / body / trailer delivery order, and the QUIC-/H3-error →
//! [`CURLcode`](crate::error::CurlError) mapping.
//!
//! # Architecture
//!
//! The transport is structured to mirror the HTTP/2 engine (`h2.rs`): an
//! HTTP/3 request/response over QUIC streams is analogous to HTTP/2 over a
//! single connection. The pieces are:
//!
//! * [`Http3Session`] — owns the [`quinn::Endpoint`], the established QUIC
//!   connection, the [`h3::client::SendRequest`] handle, and the spawned H3
//!   connection-driver task. One session multiplexes many concurrent requests
//!   (each a separate QUIC stream) over one connection.
//! * [`H3Exchange`] — one request/response stream, implementing
//!   [`crate::transfer::ProtocolExchange`] so the engine's byte-loop driver
//!   ([`crate::transfer::drive_transfer`]) pulls response events and pushes the
//!   request body exactly as it does for HTTP/1.1 and HTTP/2.
//! * [`Http3Protocol`] — the [`Protocol`] handler the protocol registry
//!   dispatches to. Its [`do_it`](Protocol::do_it) builds and validates the
//!   request and *describes* the transfer; the QUIC connect + stream I/O is
//!   performed by [`Http3Session`]/[`H3Exchange`], driven by the engine
//!   (`quinn` endpoint/transport ownership belongs to the connection/multi
//!   layer, not to `do_it`).
//!
//! Request building is delegated to the shared [`super::h1`] helpers so the
//! method, target, authority, and default-header rules are byte-identical
//! across HTTP/1.1, HTTP/2 and HTTP/3; only the framing/transport differs. The
//! HTTP/1-style header set is then mapped to HTTP/3 pseudo-headers
//! (`:method` / `:scheme` / `:authority` / `:path`, derived by `h3` from the
//! request's method and URI) with the hop-by-hop headers stripped. HTTP/3 has
//! no chunked transfer-encoding — request bodies are framed by the QUIC stream.
//!
//! # TLS
//!
//! QUIC's handshake *is* TLS 1.3, and the only TLS backend is [`rustls`]
//! (AAP §0.8.1). [`quinn`] runs over rustls via
//! [`quinn::crypto::rustls::QuicClientConfig`]; ALPN advertises `h3`. There is
//! no OpenSSL-QUIC / ngtcp2 / quiche path. Certificate validation is on by
//! default ([`default_rustls_client_config`]).
//!
//! # Memory safety
//!
//! This module inherits `#![forbid(unsafe_code)]` from [`crate::protocols`] and
//! [`crate`]; it contains no `unsafe` and is async-only over Tokio. It is gated
//! by the `http3` Cargo feature (default ON) and is compiled only when both
//! `http` and `http3` are enabled, so [`super::h1`] is always available.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use http::{HeaderMap, Method, Request, StatusCode, Uri};

use h3::error::{ConnectionError as H3ConnectionError, StreamError as H3StreamError};

use crate::conn::{
    BoxFuture, Connection, Curl_conn_get_current_host, Curl_conn_get_remote_addr, FIRSTSOCKET,
    TRNSPRT_QUIC,
};
use crate::easy::Easy;
use crate::error::{CurlError, Result};
use crate::protocols::{Protocol, ProtocolTransfer, Scheme, TransferDirection, SCHEME_HTTPS};
use crate::setopt::HttpReq;
use crate::transfer::{ProtocolExchange, ResponseEvent};
use crate::url::{CurlUPart, CurlUrl, CURLU_DEFAULT_PORT, CURLU_URLDECODE};

use super::h1;

// ===========================================================================
// Constants
// ===========================================================================

/// The QUIC ALPN identifier for HTTP/3 (RFC 9114 §3.1). curl's QUIC backends
/// advertise the same `"h3"` token at the TLS layer
/// (`lib/vquic/curl_ngtcp2.c` / `curl_quiche.c`).
const ALPN_H3: &[u8] = b"h3";

// Concrete instantiations of the generic `h3` client types over the
// `h3-quinn` QUIC transport, named once so the struct fields and signatures
// below stay readable.
type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type H3RequestStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type H3DriverConnection = h3::client::Connection<h3_quinn::Connection, Bytes>;

// ===========================================================================
// TLS / QUIC client configuration
// ===========================================================================

/// The ALPN protocol list HTTP/3 advertises: exactly `[b"h3"]`.
///
/// Part of the engine's public TLS-configuration surface: the connection/TLS
/// layer uses this to set the QUIC client config's ALPN.
#[must_use]
pub fn h3_alpn() -> Vec<Vec<u8>> {
    vec![ALPN_H3.to_vec()]
}

/// Build the default rustls client configuration for HTTP/3: the webpki
/// (Mozilla) root store, the *ring* crypto provider, safe protocol versions,
/// no client certificate, and ALPN set to `h3`.
///
/// Certificate validation is **on by default** (AAP §0.8.1) — the configuration
/// uses [`rustls::ClientConfig::builder_with_provider`] with the standard root
/// store, so the server certificate chain is verified against the webpki roots.
/// The *ring* provider is selected explicitly (rather than relying on a
/// process-global default) to match `quinn`'s `rustls-ring` feature.
///
/// # Errors
///
/// Returns [`CurlError::SslConnectError`] if the chosen provider does not
/// support the safe default protocol versions (it always does in practice).
pub fn default_rustls_client_config() -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| CurlError::SslConnectError)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = h3_alpn();
    Ok(cfg)
}

/// Wrap a rustls client configuration into a [`quinn::ClientConfig`] for
/// HTTP/3, ensuring the `h3` ALPN token is advertised.
///
/// The caller's rustls configuration (for example one produced by
/// [`default_rustls_client_config`] or by the connection/TLS layer) is reused
/// as-is for its root store and verification policy; this function only
/// guarantees the `h3` ALPN protocol is present before handing the config to
/// QUIC.
///
/// # Errors
///
/// Returns [`CurlError::SslConnectError`] if the rustls provider lacks the
/// TLS 1.3 initial cipher suite QUIC requires
/// ([`quinn::crypto::rustls::QuicClientConfig`] construction fails).
pub fn build_quic_client_config(mut tls: rustls::ClientConfig) -> Result<quinn::ClientConfig> {
    if !tls.alpn_protocols.iter().any(|p| p.as_slice() == ALPN_H3) {
        tls.alpn_protocols.push(ALPN_H3.to_vec());
    }
    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|_| CurlError::SslConnectError)?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_tls)))
}

/// Pick a local wildcard bind address in the same address family as `target`
/// so the client [`quinn::Endpoint`] can reach an IPv4 or IPv6 server.
fn wildcard_bind_addr(target: &SocketAddr) -> SocketAddr {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    match target {
        SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    }
}

/// Strip an `[...]` IPv6 bracket pair (if present) so the host can be used as a
/// TLS server name (SNI). The host returned by the connection layer is already
/// port-less; this only normalizes the literal IPv6 form.
fn host_for_sni(host: &str) -> String {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .to_string()
}

// ===========================================================================
// Request mapping (pure)
// ===========================================================================

/// Whether `name` is a hop-by-hop header that must not be forwarded on an
/// HTTP/3 request. HTTP/2 and HTTP/3 carry the authority in the `:authority`
/// pseudo-header, so `Host` is dropped too, and `Transfer-Encoding` is invalid
/// over HTTP/3 (bodies are framed by the QUIC stream). Comparison is
/// ASCII-case-insensitive.
#[must_use]
pub(crate) fn is_hop_by_hop(name: &str) -> bool {
    const HOP_BY_HOP: [&str; 8] = [
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
        "te",
        "trailer",
        "host",
    ];
    HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

/// Build the logical [`http::Request`] for an HTTP/3 transfer. The `h3` client
/// derives the `:method` / `:scheme` / `:authority` / `:path` pseudo-headers
/// from the request's method and URI, so this constructs an absolute-form URI
/// (`scheme://authority/path`) and copies the remaining (non-hop-by-hop)
/// headers. The body is empty here ([`()`]); request body bytes are streamed
/// separately on the QUIC send stream via [`H3Exchange::send_body`].
///
/// # Errors
///
/// Returns [`CurlError::UrlMalformat`] if the scheme/authority/path do not form
/// a valid URI or the header set is rejected by the [`http`] builder.
pub(crate) fn build_h3_request(
    method: &Method,
    scheme: &str,
    authority: &str,
    path: &str,
    headers: &[(String, String)],
) -> Result<Request<()>> {
    let uri = Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(if path.is_empty() { "/" } else { path })
        .build()
        .map_err(|_| CurlError::UrlMalformat)?;

    let mut builder = Request::builder().method(method.clone()).uri(uri);
    for (name, value) in headers {
        if is_hop_by_hop(name) {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder.body(()).map_err(|_| CurlError::UrlMalformat)
}

// ===========================================================================
// Response-event mapping (pure)
// ===========================================================================

/// The synthesized HTTP/1-style status line for an HTTP/3 response. curl's
/// QUIC backends fabricate `"HTTP/3 <code> \r\n"` (note the trailing space
/// before CRLF and the absence of a reason phrase) when surfacing the
/// `:status` pseudo-header to the header writer
/// (`lib/vquic/curl_quiche.c` `cb_each_header`).
#[must_use]
fn status_line(status: StatusCode) -> Vec<u8> {
    format!("HTTP/3 {} \r\n", status.as_u16()).into_bytes()
}

/// Format a single header field as a wire `"name: value\r\n"` line. HTTP/3
/// header names are already lowercase (QPACK), matching curl's delivery.
#[must_use]
fn header_line(name: &str, value: &[u8]) -> Vec<u8> {
    let mut line = Vec::with_capacity(name.len() + value.len() + 4);
    line.extend_from_slice(name.as_bytes());
    line.extend_from_slice(b": ");
    line.extend_from_slice(value);
    line.extend_from_slice(b"\r\n");
    line
}

/// Translate the response status + header map into the ordered
/// [`ResponseEvent`] stream the engine's byte-loop driver expects, matching the
/// HTTP/1.1 engine's `finish_head` precedent:
///
/// 1. [`ResponseEvent::Status`] with the numeric status code.
/// 2. [`ResponseEvent::Header`] carrying the synthesized `HTTP/3 <code>` status
///    line.
/// 3. one [`ResponseEvent::Header`] per response header (`name: value\r\n`).
/// 4. a terminating blank [`ResponseEvent::Header`] (`\r\n`).
/// 5. [`ResponseEvent::HeadersComplete`] with the parsed `Content-Length` and
///    `Content-Encoding`, if present.
#[must_use]
pub(crate) fn response_head_events(status: StatusCode, headers: &HeaderMap) -> Vec<ResponseEvent> {
    let mut events = Vec::with_capacity(headers.len() + 4);
    events.push(ResponseEvent::Status(i32::from(status.as_u16())));
    events.push(ResponseEvent::Header(status_line(status)));

    let mut content_length: Option<i64> = None;
    let mut content_encoding: Option<String> = None;
    for (name, value) in headers {
        let nm = name.as_str();
        events.push(ResponseEvent::Header(header_line(nm, value.as_bytes())));
        if content_length.is_none() && nm.eq_ignore_ascii_case("content-length") {
            if let Ok(text) = value.to_str() {
                if let Ok(n) = text.trim().parse::<i64>() {
                    content_length = Some(n);
                }
            }
        } else if content_encoding.is_none() && nm.eq_ignore_ascii_case("content-encoding") {
            if let Ok(text) = value.to_str() {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    content_encoding = Some(trimmed.to_string());
                }
            }
        }
    }

    events.push(ResponseEvent::Header(b"\r\n".to_vec()));
    events.push(ResponseEvent::HeadersComplete {
        content_length,
        content_encoding,
    });
    events
}

/// Translate response trailers into [`ResponseEvent::Header`] lines, delivered
/// on the header stream after the body (curl surfaces HTTP/3 trailers the same
/// way it surfaces leading headers).
#[must_use]
pub(crate) fn trailer_events(trailers: &HeaderMap) -> Vec<ResponseEvent> {
    let mut events = Vec::with_capacity(trailers.len());
    for (name, value) in trailers {
        events.push(ResponseEvent::Header(header_line(
            name.as_str(),
            value.as_bytes(),
        )));
    }
    events
}

// ===========================================================================
// Error mapping (pure)
// ===========================================================================

/// Whether a QUIC transport error code denotes a TLS **certificate**
/// verification failure. QUIC encodes a TLS alert as a CRYPTO_ERROR in the
/// `0x0100..0x0200` range whose low byte is the TLS alert number (RFC 9001
/// §4.8); the certificate-related alerts are `bad_certificate` (42),
/// `unsupported_certificate` (43), `certificate_revoked` (44),
/// `certificate_expired` (45), `certificate_unknown` (46) and `unknown_ca`
/// (48).
#[must_use]
pub(crate) fn is_cert_alert_code(raw: u64) -> bool {
    if !(0x0100..0x0200).contains(&raw) {
        return false;
    }
    matches!((raw & 0xff) as u8, 42 | 43 | 44 | 45 | 46 | 48)
}

/// Map a [`quinn::ConnectError`] — a parameter/setup failure raised *before*
/// any QUIC I/O — to [`CurlError::QuicConnectError`], matching curl's
/// `CURLE_QUIC_CONNECT_ERROR` for connection-setup failures.
#[must_use]
pub(crate) fn map_connect_setup_error(_err: &quinn::ConnectError) -> CurlError {
    CurlError::QuicConnectError
}

/// Map a [`quinn::ConnectionError`] to a curl [`CurlError`]. A certificate
/// alert always maps to [`CurlError::PeerFailedVerification`]. Otherwise the
/// `during_connect` flag distinguishes a handshake failure
/// ([`CurlError::QuicConnectError`]) from a mid-transfer loss
/// ([`CurlError::Http3`] for a peer-signalled close, [`CurlError::RecvError`]
/// for a transport drop), mirroring curl's QUIC backends.
#[must_use]
pub(crate) fn map_connection_error(err: &quinn::ConnectionError, during_connect: bool) -> CurlError {
    match err {
        quinn::ConnectionError::TransportError(te) => {
            if is_cert_alert_code(u64::from(te.code)) {
                return CurlError::PeerFailedVerification;
            }
            if during_connect {
                CurlError::QuicConnectError
            } else {
                CurlError::Http3
            }
        }
        quinn::ConnectionError::ApplicationClosed(_) | quinn::ConnectionError::ConnectionClosed(_) => {
            if during_connect {
                CurlError::QuicConnectError
            } else {
                CurlError::Http3
            }
        }
        quinn::ConnectionError::VersionMismatch
        | quinn::ConnectionError::Reset
        | quinn::ConnectionError::TimedOut
        | quinn::ConnectionError::LocallyClosed
        | quinn::ConnectionError::CidsExhausted => {
            if during_connect {
                CurlError::QuicConnectError
            } else {
                CurlError::RecvError
            }
        }
    }
}

/// Map an [`h3`] per-stream error to [`CurlError::Http3`] — an HTTP/3-layer
/// protocol failure (`CURLE_HTTP3`).
#[must_use]
pub(crate) fn map_h3_stream_error(_err: &H3StreamError) -> CurlError {
    CurlError::Http3
}

/// Map an [`h3`] connection-level error to [`CurlError::Http3`].
#[must_use]
pub(crate) fn map_h3_connection_error(_err: &H3ConnectionError) -> CurlError {
    CurlError::Http3
}

// ===========================================================================
// QUIC session
// ===========================================================================

/// An established HTTP/3 session over a single QUIC connection.
///
/// The session owns the client [`quinn::Endpoint`] (kept alive for the
/// connection's lifetime), the [`h3::client::SendRequest`] handle used to open
/// request streams, and the spawned H3 connection-driver task (which runs the
/// HTTP/3 control loop). Multiple concurrent requests are issued over one
/// session by cloning the send handle per stream — the QUIC connection
/// multiplexes them, exactly as the HTTP/2 engine multiplexes streams over one
/// TCP connection.
pub struct Http3Session {
    endpoint: quinn::Endpoint,
    send_request: H3SendRequest,
    driver: tokio::task::JoinHandle<()>,
}

impl Http3Session {
    /// Establish an HTTP/3 session: bind a client QUIC endpoint, perform the
    /// QUIC + TLS 1.3 handshake to `addr` with SNI `server_name`, wrap the
    /// connection for `h3`, and spawn the connection driver.
    ///
    /// `tls` is the rustls client configuration to use (for example
    /// [`default_rustls_client_config`]); the `h3` ALPN token is ensured by
    /// [`build_quic_client_config`].
    ///
    /// # Errors
    ///
    /// * [`CurlError::CouldntConnect`] — the local UDP endpoint could not be
    ///   created.
    /// * [`CurlError::SslConnectError`] — the rustls→QUIC config conversion
    ///   failed.
    /// * [`CurlError::QuicConnectError`] — the QUIC handshake failed.
    /// * [`CurlError::PeerFailedVerification`] — the server certificate did not
    ///   verify.
    /// * [`CurlError::Http3`] — the HTTP/3 control stream could not be set up.
    pub async fn connect(
        addr: SocketAddr,
        server_name: &str,
        tls: rustls::ClientConfig,
    ) -> Result<Self> {
        let bind = wildcard_bind_addr(&addr);
        let mut endpoint =
            quinn::Endpoint::client(bind).map_err(|_| CurlError::CouldntConnect)?;
        endpoint.set_default_client_config(build_quic_client_config(tls)?);

        let connecting = endpoint
            .connect(addr, server_name)
            .map_err(|e| map_connect_setup_error(&e))?;
        let quinn_conn = connecting
            .await
            .map_err(|e| map_connection_error(&e, true))?;

        let h3_conn = h3_quinn::Connection::new(quinn_conn);
        let (driver, send_request): (H3DriverConnection, H3SendRequest) = h3::client::new(h3_conn)
            .await
            .map_err(|e| map_h3_connection_error(&e))?;

        let driver = tokio::spawn(drive_h3_connection(driver));
        Ok(Self {
            endpoint,
            send_request,
            driver,
        })
    }

    /// Open a new request stream and send the request head, returning the
    /// [`H3Exchange`] the engine drives to stream the body and read the
    /// response. The [`Request`] is built by [`build_h3_request`].
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::Http3`] if the request stream cannot be opened or
    /// the request head cannot be sent.
    pub async fn send_request(&self, req: Request<()>) -> Result<H3Exchange> {
        // Clone the send handle so multiple concurrent requests can share the
        // one QUIC connection; the session retains the original to keep the
        // connection open until the session is closed.
        let mut sender = self.send_request.clone();
        let stream = sender
            .send_request(req)
            .await
            .map_err(|e| map_h3_stream_error(&e))?;
        Ok(H3Exchange::new(stream))
    }

    /// Close the session: abort the connection-driver task and close the QUIC
    /// endpoint with a no-error code, flushing the connection-close frame.
    pub fn close(self) {
        self.driver.abort();
        self.endpoint.close(quinn::VarInt::from_u32(0), b"");
    }
}

/// Drive the HTTP/3 connection control loop to completion. `poll_close`
/// resolves with the terminal [`H3ConnectionError`] when the connection ends;
/// the value is intentionally discarded (the per-request streams surface their
/// own errors). Mirrors the HTTP/2 connection-driver task.
async fn drive_h3_connection(mut driver: H3DriverConnection) {
    let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
}

// ===========================================================================
// Request/response exchange
// ===========================================================================

/// The phase of an in-flight [`H3Exchange`]'s response read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// The response head (status + headers) has not been read yet.
    Head,
    /// The head has been delivered; body `DATA` frames are being read.
    Body,
    /// The body is complete; trailers (if any) are being read.
    Trailers,
    /// The exchange is finished.
    Done,
}

/// One HTTP/3 request/response exchange over a single QUIC stream.
///
/// Implements [`ProtocolExchange`] so [`crate::transfer::drive_transfer`] pulls
/// response events ([`next_event`](ProtocolExchange::next_event)) and pushes
/// request-body chunks ([`send_body`](ProtocolExchange::send_body)) identically
/// to the HTTP/1.1 and HTTP/2 engines. Head events are buffered in `pending`
/// and drained one per `next_event` call; body frames and trailers are read
/// lazily from the QUIC stream.
pub struct H3Exchange {
    stream: H3RequestStream,
    pending: VecDeque<ResponseEvent>,
    phase: Phase,
    send_finished: bool,
}

impl H3Exchange {
    /// Wrap a freshly opened request stream.
    fn new(stream: H3RequestStream) -> Self {
        Self {
            stream,
            pending: VecDeque::new(),
            phase: Phase::Head,
            send_finished: false,
        }
    }
}

impl ProtocolExchange for H3Exchange {
    async fn next_event(&mut self) -> Result<ResponseEvent> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Ok(event);
            }

            match self.phase {
                Phase::Head => {
                    // Finish the request-body send side before reading the
                    // response. For a bodyless request (GET/HEAD) this closes
                    // the empty stream; for an upload it signals end-of-body
                    // (HTTP/3 has no chunked encoding — the stream FIN frames
                    // the body).
                    if !self.send_finished {
                        self.stream
                            .finish()
                            .await
                            .map_err(|e| map_h3_stream_error(&e))?;
                        self.send_finished = true;
                    }
                    let resp = self
                        .stream
                        .recv_response()
                        .await
                        .map_err(|e| map_h3_stream_error(&e))?;
                    let (parts, _) = resp.into_parts();
                    self.pending
                        .extend(response_head_events(parts.status, &parts.headers));
                    self.phase = Phase::Body;
                }
                Phase::Body => {
                    match self
                        .stream
                        .recv_data()
                        .await
                        .map_err(|e| map_h3_stream_error(&e))?
                    {
                        Some(mut buf) => {
                            let len = buf.remaining();
                            if len == 0 {
                                continue;
                            }
                            let bytes = buf.copy_to_bytes(len);
                            return Ok(ResponseEvent::Body(bytes.to_vec()));
                        }
                        None => self.phase = Phase::Trailers,
                    }
                }
                Phase::Trailers => {
                    if let Some(trailers) = self
                        .stream
                        .recv_trailers()
                        .await
                        .map_err(|e| map_h3_stream_error(&e))?
                    {
                        self.pending.extend(trailer_events(&trailers));
                    }
                    self.pending.push_back(ResponseEvent::End);
                    self.phase = Phase::Done;
                }
                Phase::Done => return Ok(ResponseEvent::End),
            }
        }
    }

    async fn send_body(&mut self, data: &[u8]) -> Result<usize> {
        // Once the send side is finished (the response read began), or there is
        // nothing to send, no further bytes are accepted.
        if self.send_finished || data.is_empty() {
            return Ok(0);
        }
        self.stream
            .send_data(Bytes::copy_from_slice(data))
            .await
            .map_err(|e| map_h3_stream_error(&e))?;
        Ok(data.len())
    }
}

// ===========================================================================
// Prepared-request handoff state
// ===========================================================================

/// The prepared HTTP/3 request a [`Http3Protocol::do_it`] hands to the engine
/// via the connection's protocol-state slot. The engine reads it to drive the
/// QUIC connect ([`Http3Session::connect`] with [`server_name`](Self::server_name)
/// / [`remote_addr`](Self::remote_addr)) and the request
/// ([`into_request`](Self::into_request) + [`take_body`](Self::take_body)).
pub struct H3RequestState {
    /// The fully built request head (method, absolute-form URI, headers).
    pub request: Request<()>,
    /// The request body bytes, if this is an upload.
    pub body: Option<Bytes>,
    /// The TLS server name (SNI) for the QUIC handshake.
    pub server_name: String,
    /// The resolved remote UDP address, if the connection layer resolved it.
    pub addr: Option<SocketAddr>,
}

impl H3RequestState {
    /// The TLS server name (SNI) to use for the QUIC handshake.
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// The resolved remote address, if known.
    #[must_use]
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.addr
    }

    /// Take the request body out of the state (leaving `None`).
    pub fn take_body(&mut self) -> Option<Bytes> {
        self.body.take()
    }

    /// Consume the state, yielding the prepared request head.
    #[must_use]
    pub fn into_request(self) -> Request<()> {
        self.request
    }
}

// ===========================================================================
// Protocol handler
// ===========================================================================

/// The HTTP/3 [`Protocol`] handler. Registered for the `https` scheme when the
/// connection layer selects QUIC transport (`--http3` / `--http3-only` /
/// Alt-Svc upgrade); the protocol registry dispatches to it.
pub struct Http3Protocol {
    scheme: &'static Scheme,
}

impl Http3Protocol {
    /// Construct the HTTP/3 handler (serving the `https` scheme).
    #[must_use]
    pub fn new() -> Self {
        Self {
            scheme: &SCHEME_HTTPS,
        }
    }
}

impl Default for Http3Protocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for Http3Protocol {
    fn scheme(&self) -> &'static Scheme {
        self.scheme
    }

    fn do_it<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<ProtocolTransfer>> {
        Box::pin(async move {
            // --- Extract everything needed from `data` up front. ---
            let is_upload = data.set.copypostfields.is_some() || data.set.postfields.is_some();
            let no_body = data.set.opt_no_body;
            let method_kind = data.set.method;
            let body: Option<Bytes> = data.set.copypostfields.clone().map(Bytes::from);
            let url_str = data.url().ok_or(CurlError::UrlMalformat)?.to_string();

            // --- Parse the URL; HTTP/3 is https-only. ---
            let mut url = CurlUrl::new();
            url.set(CurlUPart::Url, Some(&url_str), CURLU_DEFAULT_PORT)
                .map_err(|_| CurlError::UrlMalformat)?;
            let scheme = url.get(CurlUPart::Scheme, 0).unwrap_or_default();
            if !scheme.eq_ignore_ascii_case("https") {
                return Err(CurlError::UnsupportedProtocol);
            }

            // --- Resolve the authority: prefer the connection's host/port,
            //     falling back to the URL. ---
            let (host, port) = {
                let (conn_host, conn_port) = Curl_conn_get_current_host(conn, FIRSTSOCKET);
                if conn_host.is_empty() {
                    let url_host = url.get(CurlUPart::Host, CURLU_URLDECODE).unwrap_or_default();
                    let url_port = url
                        .get(CurlUPart::Port, 0)
                        .ok()
                        .and_then(|p| p.parse::<u16>().ok())
                        .unwrap_or(SCHEME_HTTPS.default_port);
                    (url_host, url_port)
                } else {
                    (conn_host, conn_port)
                }
            };
            if host.is_empty() {
                return Err(CurlError::UrlMalformat);
            }

            // --- Build the request head via the shared HTTP helpers (parity
            //     with HTTP/1.1 and HTTP/2), then map to HTTP/3. ---
            let authority = h1::build_host_header_value(&host, port, true);
            let path = h1::request_target(&url, conn, None, false, false)?;
            let resolved =
                h1::resolve_http_method(method_kind, no_body, None, false, is_upload)?;
            let request_headers = vec![
                ("user-agent".to_string(), h1::default_user_agent()),
                ("accept".to_string(), "*/*".to_string()),
            ];
            let request =
                build_h3_request(&resolved.method, "https", &authority, &path, &request_headers)?;

            // --- Snapshot the resolved address + SNI for the QUIC handshake
            //     (still an immutable borrow of `conn`). ---
            let server_name = host_for_sni(&host);
            let addr = Curl_conn_get_remote_addr(conn, FIRSTSOCKET);

            // --- Describe the transfer for the engine. ---
            let direction = if is_upload {
                TransferDirection::Upload
            } else if no_body || resolved.kind == HttpReq::Head {
                TransferDirection::None
            } else {
                TransferDirection::Download
            };
            let mut transfer = ProtocolTransfer::new(direction).with_response_headers(true);
            if is_upload {
                if let Some(b) = body.as_ref() {
                    transfer = transfer.with_size(b.len() as u64);
                }
            }

            // --- Hand the prepared request to the engine and declare the QUIC
            //     transport requirement (mutable borrows of `conn`). ---
            conn.transport_wanted = TRNSPRT_QUIC;
            conn.set_proto_state(Box::new(H3RequestState {
                request,
                body,
                server_name,
                addr,
            }));

            Ok(transfer)
        })
    }

    fn done<'a>(
        &'a self,
        _data: &'a mut Easy,
        conn: &'a mut Connection,
        _status: Result<()>,
        _premature: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Drop any prepared HTTP/3 request state held on the connection.
            let _ = conn.take_proto_state();
            Ok(())
        })
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderValue, Method, StatusCode};

    // ---- ALPN / TLS configuration -----------------------------------------

    #[test]
    fn alpn_is_exactly_h3() {
        assert_eq!(h3_alpn(), vec![b"h3".to_vec()]);
        assert_eq!(ALPN_H3, b"h3");
    }

    #[test]
    fn default_rustls_config_advertises_h3() {
        let cfg = default_rustls_client_config().expect("default rustls config builds");
        assert_eq!(cfg.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[test]
    fn build_quic_config_succeeds_and_keeps_h3_alpn() {
        // A config without ALPN must gain the h3 token; the rustls→QUIC
        // conversion must succeed with the ring provider (TLS 1.3 cipher
        // suites present).
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("safe versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        // No ALPN set on the source config.
        assert!(tls.alpn_protocols.is_empty());
        let quic = build_quic_client_config(tls);
        assert!(quic.is_ok(), "QUIC client config should build over ring");
    }

    #[test]
    fn wildcard_bind_matches_family() {
        let v4: SocketAddr = "93.184.216.34:443".parse().unwrap();
        assert!(wildcard_bind_addr(&v4).is_ipv4());
        assert_eq!(wildcard_bind_addr(&v4).port(), 0);
        let v6: SocketAddr = "[2606:2800:220:1:248:1893:25c8:1946]:443".parse().unwrap();
        assert!(wildcard_bind_addr(&v6).is_ipv6());
        assert_eq!(wildcard_bind_addr(&v6).port(), 0);
    }

    #[test]
    fn host_for_sni_strips_ipv6_brackets() {
        assert_eq!(host_for_sni("example.com"), "example.com");
        assert_eq!(host_for_sni("[::1]"), "::1");
        assert_eq!(host_for_sni("[2606:2800::1]"), "2606:2800::1");
    }

    // ---- Hop-by-hop / request mapping --------------------------------------

    #[test]
    fn hop_by_hop_detection_is_case_insensitive() {
        for h in [
            "connection",
            "Connection",
            "KEEP-ALIVE",
            "proxy-connection",
            "Transfer-Encoding",
            "upgrade",
            "te",
            "trailer",
            "host",
            "Host",
        ] {
            assert!(is_hop_by_hop(h), "{h} should be hop-by-hop");
        }
        for h in ["accept", "user-agent", "content-type", "authorization"] {
            assert!(!is_hop_by_hop(h), "{h} should not be hop-by-hop");
        }
    }

    #[test]
    fn build_h3_request_maps_pseudo_headers_and_strips_hop_by_hop() {
        let headers = vec![
            ("user-agent".to_string(), "curl-rs/8.19".to_string()),
            ("accept".to_string(), "*/*".to_string()),
            // These must be stripped:
            ("host".to_string(), "ignored.example".to_string()),
            ("connection".to_string(), "keep-alive".to_string()),
            ("transfer-encoding".to_string(), "chunked".to_string()),
        ];
        let req = build_h3_request(
            &Method::GET,
            "https",
            "example.com:443",
            "/path?q=1",
            &headers,
        )
        .expect("request builds");

        // Method + URI parts (the h3 client derives the pseudo-headers from
        // these): :method, :scheme, :authority, :path.
        assert_eq!(req.method(), Method::GET);
        assert_eq!(req.uri().scheme_str(), Some("https"));
        assert_eq!(req.uri().authority().map(|a| a.as_str()), Some("example.com:443"));
        assert_eq!(req.uri().path(), "/path");
        assert_eq!(req.uri().query(), Some("q=1"));

        // Forwarded header retained; hop-by-hop + Host stripped.
        assert_eq!(
            req.headers().get("user-agent").map(|v| v.as_bytes()),
            Some(&b"curl-rs/8.19"[..])
        );
        assert!(req.headers().get("accept").is_some());
        assert!(req.headers().get("host").is_none());
        assert!(req.headers().get("connection").is_none());
        assert!(req.headers().get("transfer-encoding").is_none());
    }

    #[test]
    fn build_h3_request_defaults_empty_path_to_root() {
        let req = build_h3_request(&Method::POST, "https", "h.example", "", &[])
            .expect("request builds");
        assert_eq!(req.method(), Method::POST);
        assert_eq!(req.uri().path(), "/");
    }

    // ---- Response-head event mapping ---------------------------------------

    #[test]
    fn status_line_has_trailing_space_and_no_reason_phrase() {
        assert_eq!(status_line(StatusCode::OK), b"HTTP/3 200 \r\n".to_vec());
        assert_eq!(
            status_line(StatusCode::NOT_FOUND),
            b"HTTP/3 404 \r\n".to_vec()
        );
    }

    #[test]
    fn response_head_events_emit_expected_sequence() {
        let mut headers = HeaderMap::new();
        headers.insert("content-length", HeaderValue::from_static("5"));
        headers.insert("content-encoding", HeaderValue::from_static("gzip"));
        headers.insert("x-custom", HeaderValue::from_static("v"));

        let events = response_head_events(StatusCode::OK, &headers);

        // First two events: Status, then the synthesized status line.
        assert_eq!(events[0], ResponseEvent::Status(200));
        assert_eq!(events[1], ResponseEvent::Header(b"HTTP/3 200 \r\n".to_vec()));

        // A header line for each field must be present (order within the map
        // is not asserted, only presence and exact formatting).
        assert!(events
            .iter()
            .any(|e| *e == ResponseEvent::Header(b"content-length: 5\r\n".to_vec())));
        assert!(events
            .iter()
            .any(|e| *e == ResponseEvent::Header(b"content-encoding: gzip\r\n".to_vec())));
        assert!(events
            .iter()
            .any(|e| *e == ResponseEvent::Header(b"x-custom: v\r\n".to_vec())));

        // Penultimate event: terminating blank line. Last: HeadersComplete with
        // the parsed Content-Length / Content-Encoding.
        let n = events.len();
        assert_eq!(events[n - 2], ResponseEvent::Header(b"\r\n".to_vec()));
        assert_eq!(
            events[n - 1],
            ResponseEvent::HeadersComplete {
                content_length: Some(5),
                content_encoding: Some("gzip".to_string()),
            }
        );
    }

    #[test]
    fn response_head_events_without_length_or_encoding() {
        let headers = HeaderMap::new();
        let events = response_head_events(StatusCode::NO_CONTENT, &headers);
        assert_eq!(events[0], ResponseEvent::Status(204));
        assert_eq!(events[1], ResponseEvent::Header(b"HTTP/3 204 \r\n".to_vec()));
        assert_eq!(
            events[events.len() - 1],
            ResponseEvent::HeadersComplete {
                content_length: None,
                content_encoding: None,
            }
        );
    }

    #[test]
    fn trailer_events_are_header_lines() {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-checksum", HeaderValue::from_static("abc"));
        let events = trailer_events(&trailers);
        assert_eq!(
            events,
            vec![ResponseEvent::Header(b"x-checksum: abc\r\n".to_vec())]
        );
    }

    // ---- Error mapping ------------------------------------------------------

    #[test]
    fn cert_alert_code_detection() {
        // Cert-related TLS alerts encoded as QUIC CRYPTO_ERROR (0x100 | alert).
        for alert in [42u64, 43, 44, 45, 46, 48] {
            assert!(is_cert_alert_code(0x0100 | alert), "alert {alert}");
        }
        // Non-cert crypto alerts and non-crypto codes.
        assert!(!is_cert_alert_code(0x0100 | 40)); // handshake_failure
        assert!(!is_cert_alert_code(0x0100 | 50)); // decode_error
        assert!(!is_cert_alert_code(0x0)); // NO_ERROR
        assert!(!is_cert_alert_code(0x7)); // FINAL_SIZE_ERROR
        assert!(!is_cert_alert_code(0x0200)); // out of crypto range
    }

    #[test]
    fn connect_setup_error_maps_to_quic_connect() {
        assert_eq!(
            map_connect_setup_error(&quinn::ConnectError::UnsupportedVersion),
            CurlError::QuicConnectError
        );
        assert_eq!(
            map_connect_setup_error(&quinn::ConnectError::NoDefaultClientConfig),
            CurlError::QuicConnectError
        );
    }

    #[test]
    fn connection_error_phase_mapping() {
        // A transport drop during the handshake is a connect error; mid-transfer
        // it is a receive error.
        assert_eq!(
            map_connection_error(&quinn::ConnectionError::TimedOut, true),
            CurlError::QuicConnectError
        );
        assert_eq!(
            map_connection_error(&quinn::ConnectionError::TimedOut, false),
            CurlError::RecvError
        );
        assert_eq!(
            map_connection_error(&quinn::ConnectionError::Reset, true),
            CurlError::QuicConnectError
        );
        assert_eq!(
            map_connection_error(&quinn::ConnectionError::VersionMismatch, false),
            CurlError::RecvError
        );
        assert_eq!(
            map_connection_error(&quinn::ConnectionError::CidsExhausted, false),
            CurlError::RecvError
        );
        assert_eq!(
            map_connection_error(&quinn::ConnectionError::LocallyClosed, true),
            CurlError::QuicConnectError
        );
    }

    // ---- Prepared-request handoff state ------------------------------------

    #[test]
    fn request_state_accessors() {
        let req = build_h3_request(&Method::PUT, "https", "h.example:443", "/up", &[])
            .expect("request builds");
        let addr: SocketAddr = "203.0.113.1:443".parse().unwrap();
        let mut state = H3RequestState {
            request: req,
            body: Some(Bytes::from_static(b"payload")),
            server_name: "h.example".to_string(),
            addr: Some(addr),
        };
        assert_eq!(state.server_name(), "h.example");
        assert_eq!(state.remote_addr(), Some(addr));
        assert_eq!(state.take_body().as_deref(), Some(&b"payload"[..]));
        assert!(state.take_body().is_none());
        let req = state.into_request();
        assert_eq!(req.method(), Method::PUT);
        assert_eq!(req.uri().path(), "/up");
    }

    // ---- Protocol handler ---------------------------------------------------

    #[test]
    fn http3_protocol_serves_https_scheme() {
        let proto = Http3Protocol::new();
        assert_eq!(proto.scheme().name, "https");
        assert_eq!(proto.scheme().default_port, 443);
        // Default impl is equivalent to new().
        let _ = Http3Protocol::default();
    }

    // ---- Feature/version coupling (AAP §0.7.3) -----------------------------

    #[test]
    fn version_reports_http3_when_feature_enabled() {
        // This test only compiles when the `http3` feature is on (the whole
        // module is gated on it). curl's feature detection drives test
        // selection from curl_version_info(); the HTTP3 capability MUST be
        // reported whenever the engine is compiled in.
        assert!(
            crate::version::feature_names().contains(&"HTTP3"),
            "version must report HTTP3 when the http3 engine is compiled in"
        );
    }

    // ---- Live integration (gated) ------------------------------------------

    /// A real GET over HTTP/3, gated behind the `CURL_RS_H3_LIVE` environment
    /// variable (set it to `host:port` of an HTTP/3-capable server). Skipped by
    /// default because CI has no HTTP/3 server (AAP §0.8.4 step 7). When run, it
    /// exercises the full [`Http3Session`] connect → [`H3Exchange`] response
    /// path end-to-end.
    #[tokio::test]
    async fn live_h3_get() {
        let Ok(target) = std::env::var("CURL_RS_H3_LIVE") else {
            eprintln!("skipping live HTTP/3 test (set CURL_RS_H3_LIVE=host:port to run)");
            return;
        };
        let host = target.split(':').next().unwrap_or("localhost").to_string();
        let addr: SocketAddr = tokio::net::lookup_host(&target)
            .await
            .expect("resolve target")
            .next()
            .expect("at least one address");

        let tls = default_rustls_client_config().expect("rustls config");
        let session = Http3Session::connect(addr, &host, tls)
            .await
            .expect("h3 connect");

        let req = build_h3_request(
            &Method::GET,
            "https",
            &format!("{host}:{}", addr.port()),
            "/",
            &[("user-agent".to_string(), "curl-rs/8.19".to_string())],
        )
        .expect("build request");

        let mut exchange = session.send_request(req).await.expect("send request");

        let mut saw_status = false;
        let mut body_len = 0usize;
        loop {
            match exchange.next_event().await.expect("event") {
                ResponseEvent::Status(code) => {
                    assert!((100..600).contains(&code), "plausible status: {code}");
                    saw_status = true;
                }
                ResponseEvent::Body(chunk) => body_len += chunk.len(),
                ResponseEvent::End => break,
                _ => {}
            }
        }
        assert!(saw_status, "a status event must be delivered");
        let _ = body_len;
        session.close();
    }
}

