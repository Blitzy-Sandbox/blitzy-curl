// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! # TLS layer — the single rustls backend
//!
//! Root of the TLS subtree, a language rewrite of curl's `lib/vtls/` directory. Where curl
//! selected among **seven** C TLS backends (OpenSSL, GnuTLS, mbedTLS, wolfSSL, Schannel,
//! Apple Secure Transport, and rustls-ffi) through `#ifdef` branching in
//! `lib/vtls/vtls.c`, this rewrite collapses them onto a single, always-compiled
//! [`rustls`] implementation with certificate validation on by default (AAP §0.1.1).
//!
//! ## Memory safety
//!
//! The whole subtree is written in safe Rust: the crate root's
//! [`forbid(unsafe_code)`](https://doc.rust-lang.org/reference/attributes/codegen.html)
//! applies here, so any `unsafe` block anywhere under `curl-rs-lib/src/tls/` is a hard
//! **compile error** (AAP §0.6.2 / §0.7.2). This is one of the flagship "no `unsafe`, no
//! exceptions" zones; the CI grep audit `grep -rn 'unsafe' curl-rs-lib/src/` must return
//! nothing. The async handshake below delegates to [`tokio_rustls`] and drives its
//! [`AsyncRead`]/[`AsyncWrite`] wrapper purely through [`Pin::get_mut`], which is safe
//! because the wrapped stream is [`Unpin`].
//!
//! ## What this module provides
//!
//! The 3,500+ lines of dispatch and handshake-state-machine code in `lib/vtls/vtls.c`
//! (`Curl_ssl_*`, ALPN plumbing, `Curl_ssl_version`, `Curl_ssl_supports`) and
//! `lib/vtls/rustls.c` (`cr_connect`, `cr_set_negotiated_alpn`, `cr_version`,
//! `Curl_ssl_rustls`) collapse dramatically here, because `tokio-rustls` owns the async
//! handshake and `rustls` owns certificate verification. This module's job is narrow:
//!
//! 1. declare and re-export the four sibling submodules ([`config`], [`session_cache`],
//!    [`keylog`], [`hostname`]);
//! 2. provide a thin [`TlsConnector`]/[`TlsStream`] pair over `tokio-rustls` that replaces
//!    the C `cr_connect` state machine with a single `.connect().await`;
//! 3. surface ALPN negotiation ([`AlpnProtocol`]), the capability descriptor
//!    ([`supports`]), and the TLS version token ([`version_token`]) for curl parity; and
//! 4. map `rustls` handshake errors to the frozen [`CurlCode`](crate::error::CurlCode)
//!    integers ([`CURLE_SSL_CONNECT_ERROR == 35`](crate::error::CurlCode::SslConnectError)
//!    and
//!    [`CURLE_PEER_FAILED_VERIFICATION == 60`](crate::error::CurlCode::PeerFailedVerification)).
//!
//! Certificate verification (default-on, `--insecure` accept-all + stderr warning) is
//! configured entirely in [`config`]; this module only drives the handshake and reports
//! the negotiated result.
//!
//! ## Submodules
//!
//! * [`config`] — [`rustls::ClientConfig`] construction from curl's SSL option surface.
//! * [`hostname`] — RFC 6125 hostname verification (from `lib/vtls/hostcheck.c`).
//! * [`keylog`] — `SSLKEYLOGFILE` key-material logging (from `lib/vtls/keylog.c`).
//! * [`session_cache`] — TLS session-resumption store (from `lib/vtls/vtls_scache.c`).
//!
//! ## NOTE — connection-filter integration lives in `crate::conn`
//!
//! curl inserts TLS into the connection chain via `Curl_ssl_cfilter_add` /
//! `Curl_cf_ssl_insert_after` (`lib/vtls/vtls.c`). In this rewrite the connection-filter
//! chain is owned by `crate::conn` (a later, currently-empty layer). Per the Minimal
//! Change Mandate this module intentionally does **not** build that filter; it exposes only
//! the connector/stream primitives ([`TlsConnector::from_config`] + [`TlsConnector::connect`])
//! that `conn/filters.rs` will compose. This module is foundational and must never import
//! from `crate::conn` or `crate::protocols`.
//!
//! ## NOTE — HTTP/3 uses quinn's own rustls
//!
//! This connector covers the TCP-based TLS path (HTTP/1.1 and HTTP/2, selected via ALPN
//! `h2`/`http/1.1`). The HTTP/3 path is driven by `protocols/http/h3.rs` over `quinn`,
//! which carries its **own** `rustls` `ClientConfig`; it does not flow through this
//! connector. See [`default_https_alpn`].

pub mod config;
pub mod hostname;
pub mod keylog;
pub mod session_cache;

// Re-export the primary public types so downstream layers use the flat `crate::tls::…`
// path (AAP §0.4.2 example: `use crate::tls::TlsConfig;`).
pub use config::TlsConfig;
pub use session_cache::SessionCache;

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::{ClientConfig, ProtocolVersion, SupportedCipherSuite};
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{Error, Result};

// ===========================================================================
// ALPN — wire constants and the negotiated-protocol model (from `vtls_int.h`).
// ===========================================================================

/// ALPN protocol identifier for HTTP/1.0 (`lib/vtls/vtls_int.h:ALPN_HTTP_1_0`).
pub const ALPN_HTTP_1_0: &[u8] = b"http/1.0";
/// ALPN protocol identifier for HTTP/1.1 (`lib/vtls/vtls_int.h:ALPN_HTTP_1_1`).
pub const ALPN_HTTP_1_1: &[u8] = b"http/1.1";
/// ALPN protocol identifier for HTTP/2 (`lib/vtls/vtls_int.h:ALPN_H2`).
pub const ALPN_H2: &[u8] = b"h2";
/// ALPN protocol identifier for HTTP/3 (`lib/vtls/vtls_int.h:ALPN_H3`).
pub const ALPN_H3: &[u8] = b"h3";

/// The application-layer protocol negotiated during the TLS handshake.
///
/// Mirrors curl's ALPN model in `lib/vtls/vtls.c`
/// (`Curl_alpn_to_proto_buf` / `Curl_alpn_set_negotiated`): the client offers a set of
/// protocol identifiers and the server selects at most one. [`AlpnProtocol::None`]
/// represents the "server did not agree on a protocol" case, where curl falls back to its
/// default (HTTP/1.1) — see `VTLS_INFOF_NO_ALPN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlpnProtocol {
    /// HTTP/1.0 (`http/1.0`).
    Http10,
    /// HTTP/1.1 (`http/1.1`).
    Http11,
    /// HTTP/2 (`h2`).
    H2,
    /// HTTP/3 (`h3`).
    H3,
    /// No protocol was negotiated; the caller falls back to its default.
    None,
}

impl AlpnProtocol {
    /// Classifies an ALPN wire identifier (the raw bytes exchanged on the wire) into a
    /// known [`AlpnProtocol`]. Unrecognized identifiers map to [`AlpnProtocol::None`],
    /// matching curl's "uses default" fallback.
    #[must_use]
    pub fn from_wire(bytes: &[u8]) -> Self {
        match bytes {
            ALPN_HTTP_1_0 => Self::Http10,
            ALPN_HTTP_1_1 => Self::Http11,
            ALPN_H2 => Self::H2,
            ALPN_H3 => Self::H3,
            _ => Self::None,
        }
    }

    /// Classifies the rustls-reported negotiated protocol
    /// ([`ClientConnection::alpn_protocol`](rustls::ClientConnection::alpn_protocol)),
    /// where `None` means the handshake completed without an agreed protocol.
    #[must_use]
    pub fn from_negotiated(proto: Option<&[u8]>) -> Self {
        match proto {
            Some(bytes) => Self::from_wire(bytes),
            None => Self::None,
        }
    }

    /// Returns the ALPN wire identifier for this protocol, or `None` for
    /// [`AlpnProtocol::None`].
    #[must_use]
    pub fn as_wire(&self) -> Option<&'static [u8]> {
        match self {
            Self::Http10 => Some(ALPN_HTTP_1_0),
            Self::Http11 => Some(ALPN_HTTP_1_1),
            Self::H2 => Some(ALPN_H2),
            Self::H3 => Some(ALPN_H3),
            Self::None => Option::None,
        }
    }

    /// Returns the protocol identifier as a UTF-8 string (empty for
    /// [`AlpnProtocol::None`]).
    ///
    /// The vocabulary is preserved so the connection layer can reproduce curl's `--trace`
    /// diagnostics (`VTLS_INFOF_ALPN_ACCEPTED` = `"ALPN: server accepted %s"`). This module
    /// does not itself print any trace output; it only exposes the negotiated result.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Http10 => "http/1.0",
            Self::Http11 => "http/1.1",
            Self::H2 => "h2",
            Self::H3 => "h3",
            Self::None => "",
        }
    }
}

/// Builds the default ALPN offer for an HTTPS (TCP) connection: HTTP/2 preferred, with
/// HTTP/1.1 as the fallback — i.e. `[b"h2", b"http/1.1"]`.
///
/// This is the offer the HTTP layer installs on a [`TlsConfig`] (via
/// [`TlsConfig::with_alpn`](config::TlsConfig::with_alpn)) before building a
/// [`TlsConnector`]. HTTP/3 (`h3`) is **not** included: the QUIC/HTTP-3 path is handled by
/// `protocols/http/h3.rs` over `quinn`, which uses its own `rustls` `ClientConfig` rather
/// than this TCP connector.
#[must_use]
pub fn default_https_alpn() -> Vec<Vec<u8>> {
    vec![ALPN_H2.to_vec(), ALPN_HTTP_1_1.to_vec()]
}

// ===========================================================================
// Capability descriptor (from `vtls.h` `SSLSUPP_*` and `rustls.c` `Curl_ssl_rustls`).
// ===========================================================================

/// Supports `CURLOPT_CAPATH` (`SSLSUPP_CA_PATH`).
pub const SSLSUPP_CA_PATH: u32 = 1 << 0;
/// Supports `CURLOPT_CERTINFO` (`SSLSUPP_CERTINFO`).
pub const SSLSUPP_CERTINFO: u32 = 1 << 1;
/// Supports `CURLOPT_PINNEDPUBLICKEY` (`SSLSUPP_PINNEDPUBKEY`).
pub const SSLSUPP_PINNEDPUBKEY: u32 = 1 << 2;
/// Supports `CURLOPT_SSL_CTX_FUNCTION` (`SSLSUPP_SSL_CTX`). rustls does **not**.
pub const SSLSUPP_SSL_CTX: u32 = 1 << 3;
/// Supports access via HTTPS proxies (`SSLSUPP_HTTPS_PROXY`).
pub const SSLSUPP_HTTPS_PROXY: u32 = 1 << 4;
/// Supports TLS 1.3 ciphersuites (`SSLSUPP_TLS13_CIPHERSUITES`).
pub const SSLSUPP_TLS13_CIPHERSUITES: u32 = 1 << 5;
/// Supports `CURLOPT_CAINFO_BLOB` (`SSLSUPP_CAINFO_BLOB`).
pub const SSLSUPP_CAINFO_BLOB: u32 = 1 << 6;
/// Supports Encrypted Client Hello (`SSLSUPP_ECH`).
pub const SSLSUPP_ECH: u32 = 1 << 7;
/// Supports the CA certificate cache (`SSLSUPP_CA_CACHE`).
pub const SSLSUPP_CA_CACHE: u32 = 1 << 8;
/// Supports TLS 1.0–1.2 cipher lists (`SSLSUPP_CIPHER_LIST`).
pub const SSLSUPP_CIPHER_LIST: u32 = 1 << 9;
/// Supports TLS signature algorithms (`SSLSUPP_SIGNATURE_ALGORITHMS`).
pub const SSLSUPP_SIGNATURE_ALGORITHMS: u32 = 1 << 10;
/// Supports `CURLOPT_ISSUERCERT` (`SSLSUPP_ISSUERCERT`).
pub const SSLSUPP_ISSUERCERT: u32 = 1 << 11;
/// Supports `CURLOPT_SSL_EC_CURVES` (`SSLSUPP_SSL_EC_CURVES`).
pub const SSLSUPP_SSL_EC_CURVES: u32 = 1 << 12;
/// Supports `CURLOPT_CRLFILE` (`SSLSUPP_CRLFILE`).
pub const SSLSUPP_CRLFILE: u32 = 1 << 13;
/// Supports `CURLOPT_ISSUERCERT_BLOB` (`SSLSUPP_ISSUERCERT_BLOB`).
pub const SSLSUPP_ISSUERCERT_BLOB: u32 = 1 << 14;

/// The exact capability bitmask advertised by curl's rustls backend descriptor
/// `Curl_ssl_rustls` in `lib/vtls/rustls.c`:
///
/// ```text
/// SSLSUPP_CAINFO_BLOB | SSLSUPP_HTTPS_PROXY | SSLSUPP_CIPHER_LIST |
/// SSLSUPP_TLS13_CIPHERSUITES | SSLSUPP_CERTINFO | SSLSUPP_ECH | SSLSUPP_CRLFILE
/// ```
///
/// Notably it does **not** include `SSLSUPP_SSL_CTX` (there is no OpenSSL-style
/// `SSL_CTX`/engine surface to expose).
pub const RUSTLS_SUPPORTED: u32 = SSLSUPP_CAINFO_BLOB
    | SSLSUPP_HTTPS_PROXY
    | SSLSUPP_CIPHER_LIST
    | SSLSUPP_TLS13_CIPHERSUITES
    | SSLSUPP_CERTINFO
    | SSLSUPP_ECH
    | SSLSUPP_CRLFILE;

/// Reports whether the rustls backend supports the given `SSLSUPP_*` capability,
/// mirroring `Curl_ssl_supports` in `lib/vtls/vtls.c`.
///
/// `flag` is one (or a bitwise-OR combination) of the `SSLSUPP_*` constants; the result is
/// `true` only when **every** requested bit is supported.
#[must_use]
pub fn supports(flag: u32) -> bool {
    RUSTLS_SUPPORTED & flag == flag
}

// ===========================================================================
// Version reporting (from `vtls.c` `Curl_ssl_version` and `rustls.c` `cr_version`).
// ===========================================================================

/// The TLS token embedded verbatim in the libcurl version string.
///
/// The full version string is `curl-rs/8.19.0-DEV rustls flate2 brotli zstd hyper quinn
/// russh`; this constant is the `rustls` token consumed by the crate's version code. It
/// must **not** be altered (AAP §0.6.3).
pub const VERSION_TOKEN: &str = "rustls";

/// Returns the TLS backend token, exactly `"rustls"`.
///
/// This is what the libcurl version string embeds for the TLS backend.
#[must_use]
pub fn version_token() -> &'static str {
    VERSION_TOKEN
}

/// Returns a curl-style TLS version string, mirroring `Curl_ssl_version` /
/// `cr_version`.
///
/// curl's `cr_version` reports the rustls-ffi runtime version. Pure-Rust `rustls` (0.23)
/// exposes **no** runtime version API, so — per the file contract ("`rustls`'s version if
/// exposed, else the token") — this returns the bare backend token [`VERSION_TOKEN`]
/// (`"rustls"`), which is also exactly what the assembled libcurl version string embeds.
#[must_use]
pub fn version_string() -> String {
    VERSION_TOKEN.to_string()
}

// ===========================================================================
// Negotiated-handshake information (thin accessor bundle for CERTINFO parity).
// ===========================================================================

/// A thin snapshot of the values negotiated during a completed TLS handshake.
///
/// Assembled from the rustls [`ClientConnection`](rustls::ClientConnection) after
/// [`TlsConnector::connect`] succeeds, this bundles the data curl surfaces through
/// `CURLINFO_*` (negotiated ALPN, protocol version, cipher suite). Peer certificates are
/// retrieved separately via [`TlsStream::peer_certificates`] to avoid copying certificate
/// bytes into this value.
#[derive(Debug, Clone, Copy)]
pub struct TlsInfo {
    /// The negotiated ALPN protocol (or [`AlpnProtocol::None`]).
    pub alpn: AlpnProtocol,
    /// The negotiated TLS protocol version, if the handshake exposed one.
    pub protocol_version: Option<ProtocolVersion>,
    /// The negotiated cipher suite, if the handshake exposed one.
    pub cipher_suite: Option<SupportedCipherSuite>,
}

// ===========================================================================
// Async TLS connector (replaces the `cr_connect` handshake state machine).
// ===========================================================================

/// An async TLS client connector over `tokio-rustls`.
///
/// Wraps a [`tokio_rustls::TlsConnector`] built from an
/// [`Arc<rustls::ClientConfig>`](rustls::ClientConfig). This is the primitive that curl's
/// connection filter (`Curl_ssl_cfilter_add`, `lib/vtls/vtls.c`) would compose; here the
/// composition itself lives in `crate::conn` (see the module NOTE). Cloning is cheap — the
/// underlying `ClientConfig` is shared behind an `Arc`.
#[derive(Clone)]
pub struct TlsConnector {
    inner: tokio_rustls::TlsConnector,
}

impl std::fmt::Debug for TlsConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The wrapped `ClientConfig` has no meaningful `Debug`; expose the type only.
        f.debug_struct("TlsConnector").finish_non_exhaustive()
    }
}

impl TlsConnector {
    /// Builds a connector from a [`TlsConfig`], compiling its options into a
    /// [`rustls::ClientConfig`] via [`TlsConfig::build`](config::TlsConfig::build).
    ///
    /// # Errors
    ///
    /// Propagates any error from [`TlsConfig::build`](config::TlsConfig::build) — for
    /// example [`CurlCode::SslCacertBadfile`](crate::error::CurlCode::SslCacertBadfile) for
    /// an unreadable CA source, or
    /// [`CurlCode::SslConnectError`](crate::error::CurlCode::SslConnectError) for a setup
    /// failure.
    pub fn from_config(cfg: &TlsConfig) -> Result<Self> {
        let client_config = cfg.build()?;
        Ok(Self::from_client_config(client_config))
    }

    /// Builds a connector directly from a shared [`rustls::ClientConfig`].
    ///
    /// Useful when the caller has already assembled (or wishes to share) a
    /// `ClientConfig` — for instance to reuse one configuration across many connections.
    #[must_use]
    pub fn from_client_config(cfg: Arc<ClientConfig>) -> Self {
        Self {
            inner: tokio_rustls::TlsConnector::from(cfg),
        }
    }

    /// Performs a TLS client handshake over `stream`, returning the encrypted
    /// [`TlsStream`].
    ///
    /// This replaces curl's `cr_connect` handshake state machine in
    /// `lib/vtls/rustls.c`: `tokio-rustls` drives the entire handshake to completion in a
    /// single `.await`.
    ///
    /// `server_name` is used both for SNI and for certificate hostname verification. It is
    /// parsed by [`rustls_pki_types::ServerName`], which transparently distinguishes a DNS
    /// name from an IP literal; for an IP literal rustls omits the SNI extension (as curl
    /// does) while still validating the certificate against the address.
    ///
    /// # Errors
    ///
    /// * A malformed `server_name` yields
    ///   [`CurlCode::SslConnectError`](crate::error::CurlCode::SslConnectError) (35).
    /// * A certificate/verification failure yields
    ///   [`CurlCode::PeerFailedVerification`](crate::error::CurlCode::PeerFailedVerification)
    ///   (60).
    /// * Any other handshake or I/O failure yields
    ///   [`CurlCode::SslConnectError`](crate::error::CurlCode::SslConnectError) (35).
    pub async fn connect<S>(&self, server_name: &str, stream: S) -> Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // rustls-pki-types parses DNS names and IP literals; an owned name is required
        // because `TlsConnector::connect` takes `ServerName<'static>`.
        let name = ServerName::try_from(server_name.to_owned())
            .map_err(|e| Error::tls(format!("invalid TLS server name '{server_name}': {e}")))?;

        let inner = self
            .inner
            .connect(name, stream)
            .await
            .map_err(map_handshake_error)?;

        Ok(TlsStream { inner })
    }
}

/// Maps a `tokio-rustls` handshake [`io::Error`] to the frozen curl error code,
/// mirroring `map_error` in `lib/vtls/rustls.c`.
///
/// `tokio-rustls` surfaces a failed handshake as an [`io::Error`] whose inner error is a
/// [`rustls::Error`]. A [`rustls::Error::InvalidCertificate`] (the certificate-verification
/// failure class) maps to
/// [`CurlCode::PeerFailedVerification`](crate::error::CurlCode::PeerFailedVerification)
/// (60); every other handshake/transport failure maps to
/// [`CurlCode::SslConnectError`](crate::error::CurlCode::SslConnectError) (35).
fn map_handshake_error(err: io::Error) -> Error {
    if let Some(tls_err) = err
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        if matches!(tls_err, rustls::Error::InvalidCertificate(_)) {
            return Error::peer_failed_verification(format!(
                "TLS certificate verification failed: {tls_err}"
            ));
        }
        return Error::tls(format!("TLS handshake failed: {tls_err}"));
    }
    Error::tls(format!("TLS handshake failed: {err}"))
}

// ===========================================================================
// Encrypted stream wrapper.
// ===========================================================================

/// An established TLS connection: a thin newtype over
/// [`tokio_rustls::client::TlsStream`] that implements [`AsyncRead`] and [`AsyncWrite`] by
/// transparent delegation.
///
/// Because [`tokio_rustls::client::TlsStream`] is [`Unpin`] whenever the wrapped `S` is,
/// delegation is done with [`Pin::get_mut`] and needs **no** `unsafe` and no pin
/// projection — honoring this subtree's zero-`unsafe` guarantee.
pub struct TlsStream<S> {
    inner: tokio_rustls::client::TlsStream<S>,
}

impl<S> std::fmt::Debug for TlsStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Report the negotiated handshake summary rather than the raw byte stream, and do
        // not require `S: Debug` (the inner transport is intentionally opaque here).
        f.debug_struct("TlsStream")
            .field("alpn", &self.negotiated_alpn())
            .field("protocol_version", &self.protocol_version())
            .finish_non_exhaustive()
    }
}

impl<S> TlsStream<S> {
    /// Returns the ALPN protocol negotiated during the handshake, or
    /// [`AlpnProtocol::None`] if the server agreed on none (curl's "uses default" case).
    ///
    /// Reads `self.get_ref().1.alpn_protocol()`, replacing curl's `cr_set_negotiated_alpn`
    /// in `lib/vtls/rustls.c`.
    #[must_use]
    pub fn negotiated_alpn(&self) -> AlpnProtocol {
        AlpnProtocol::from_negotiated(self.inner.get_ref().1.alpn_protocol())
    }

    /// Returns the negotiated TLS protocol version, if available.
    #[must_use]
    pub fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.inner.get_ref().1.protocol_version()
    }

    /// Returns the negotiated cipher suite, if available.
    #[must_use]
    pub fn cipher_suite(&self) -> Option<SupportedCipherSuite> {
        self.inner.get_ref().1.negotiated_cipher_suite()
    }

    /// Returns the peer certificate chain presented during the handshake, if any.
    ///
    /// The leaf certificate is first. Supports curl's `CURLINFO_CERTINFO`. The slice
    /// borrows from the connection; callers that need to retain it should clone.
    #[must_use]
    pub fn peer_certificates(&self) -> Option<&[CertificateDer<'static>]> {
        self.inner.get_ref().1.peer_certificates()
    }

    /// Assembles a [`TlsInfo`] snapshot of the negotiated handshake parameters.
    #[must_use]
    pub fn tls_info(&self) -> TlsInfo {
        TlsInfo {
            alpn: self.negotiated_alpn(),
            protocol_version: self.protocol_version(),
            cipher_suite: self.cipher_suite(),
        }
    }

    /// Borrows the underlying `tokio-rustls` stream (for advanced callers).
    #[must_use]
    pub fn get_ref(&self) -> &tokio_rustls::client::TlsStream<S> {
        &self.inner
    }

    /// Mutably borrows the underlying `tokio-rustls` stream (for advanced callers).
    #[must_use]
    pub fn get_mut(&mut self) -> &mut tokio_rustls::client::TlsStream<S> {
        &mut self.inner
    }

    /// Consumes this wrapper and returns the underlying `tokio-rustls` stream.
    #[must_use]
    pub fn into_inner(self) -> tokio_rustls::client::TlsStream<S> {
        self.inner
    }
}

impl<S> AsyncRead for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

// ===========================================================================
// Tests — hermetic, in-process rustls server (no external daemons, AAP §0.6.4).
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Installs the process-default aws-lc-rs crypto provider.
    ///
    /// `install_default` succeeds at most once per process; a later call (or one racing
    /// with [`TlsConfig::build`](config::TlsConfig::build)) simply returns `Err`, which is
    /// intentionally ignored.
    fn ensure_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    /// Generates an ephemeral self-signed certificate for `localhost` and builds a rustls
    /// server config presenting it, optionally advertising the given ALPN protocols.
    ///
    /// Returns the shared [`rustls::ServerConfig`] and the certificate in PEM form, so the
    /// client side can trust it as a private CA (via
    /// [`TlsConfig::with_ca_info_blob`](config::TlsConfig::with_ca_info_blob)).
    fn make_server(alpn: &[&[u8]]) -> (std::sync::Arc<rustls::ServerConfig>, Vec<u8>) {
        ensure_provider();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen self-signed generation");
        let ca_pem = certified.cert.pem().into_bytes();
        let cert_der = certified.cert.der().clone();
        let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()),
        );
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server config builds");
        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        (std::sync::Arc::new(cfg), ca_pem)
    }

    // ---------------------------------------------------------------------
    // Pure unit tests (no I/O).
    // ---------------------------------------------------------------------

    #[test]
    fn version_token_is_rustls() {
        assert_eq!(version_token(), "rustls");
        assert_eq!(VERSION_TOKEN, "rustls");
        assert!(version_string().starts_with("rustls"));
    }

    #[test]
    fn alpn_wire_roundtrip() {
        assert_eq!(AlpnProtocol::from_wire(b"http/1.0"), AlpnProtocol::Http10);
        assert_eq!(AlpnProtocol::from_wire(b"http/1.1"), AlpnProtocol::Http11);
        assert_eq!(AlpnProtocol::from_wire(b"h2"), AlpnProtocol::H2);
        assert_eq!(AlpnProtocol::from_wire(b"h3"), AlpnProtocol::H3);
        assert_eq!(AlpnProtocol::from_wire(b"spdy/3"), AlpnProtocol::None);

        assert_eq!(AlpnProtocol::H2.as_wire(), Some(ALPN_H2));
        assert_eq!(AlpnProtocol::Http11.as_wire(), Some(ALPN_HTTP_1_1));
        assert_eq!(AlpnProtocol::None.as_wire(), None);

        assert_eq!(AlpnProtocol::from_negotiated(None), AlpnProtocol::None);
        assert_eq!(AlpnProtocol::from_negotiated(Some(b"h2")), AlpnProtocol::H2);

        assert_eq!(AlpnProtocol::H2.as_str(), "h2");
        assert_eq!(AlpnProtocol::None.as_str(), "");
    }

    #[test]
    fn default_https_alpn_offers_h2_then_http11() {
        assert_eq!(
            default_https_alpn(),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn capability_descriptor_matches_curl_ssl_rustls() {
        // The exact set advertised by `Curl_ssl_rustls` in lib/vtls/rustls.c.
        assert!(supports(SSLSUPP_CAINFO_BLOB));
        assert!(supports(SSLSUPP_HTTPS_PROXY));
        assert!(supports(SSLSUPP_CIPHER_LIST));
        assert!(supports(SSLSUPP_TLS13_CIPHERSUITES));
        assert!(supports(SSLSUPP_CERTINFO));
        assert!(supports(SSLSUPP_ECH));
        assert!(supports(SSLSUPP_CRLFILE));
        // rustls exposes no OpenSSL-style SSL_CTX / engine surface.
        assert!(!supports(SSLSUPP_SSL_CTX));
        // A combined query requires *every* requested bit.
        assert!(supports(SSLSUPP_CERTINFO | SSLSUPP_ECH));
        assert!(!supports(SSLSUPP_CERTINFO | SSLSUPP_SSL_CTX));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    fn invalid_server_name_is_ssl_connect_error() {
        // An empty server name is not a valid DNS name or IP literal.
        let cfg = TlsConfig::default();
        let connector = TlsConnector::from_config(&cfg).expect("connector builds");
        // Drive the async fn to completion on a minimal current-thread runtime.
        let (client_io, _server_io) = tokio::io::duplex(1024);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let err = rt
            .block_on(connector.connect("", client_io))
            .expect_err("empty server name must fail");
        assert_eq!(err.code(), crate::error::CurlCode::SslConnectError);
        assert_eq!(err.code_i32(), 35);
    }

    // ---------------------------------------------------------------------
    // Integration tests over an in-process TLS server (tokio::io::duplex).
    // ---------------------------------------------------------------------

    /// Round-trip handshake against a server whose certificate the client trusts (via a
    /// private CA blob), followed by a ping/pong through the encrypted [`TlsStream`].
    #[tokio::test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    async fn round_trip_handshake_and_io() {
        let (server_cfg, ca_pem) = make_server(&[]);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
            let mut tls = acceptor.accept(server_io).await.expect("server accept");
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.expect("server read");
            assert_eq!(&buf, b"ping");
            tls.write_all(b"pong").await.expect("server write");
            tls.flush().await.expect("server flush");
        });

        let cfg = TlsConfig::default()
            .with_webpki_roots(false)
            .with_ca_info_blob(ca_pem);
        let connector = TlsConnector::from_config(&cfg).expect("connector builds");
        let mut stream = connector
            .connect("localhost", client_io)
            .await
            .expect("client handshake succeeds against trusted cert");

        // A successful handshake exposes negotiated parameters.
        assert!(stream.protocol_version().is_some());
        assert!(stream.peer_certificates().is_some());

        stream.write_all(b"ping").await.expect("client write");
        stream.flush().await.expect("client flush");
        let mut resp = [0u8; 4];
        stream.read_exact(&mut resp).await.expect("client read");
        assert_eq!(&resp, b"pong");

        server.await.expect("server task joins");
    }

    /// ALPN negotiation: the server offers only `h2`, the client offers
    /// `[h2, http/1.1]`, so the negotiated protocol must be [`AlpnProtocol::H2`].
    #[tokio::test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    async fn alpn_negotiates_h2() {
        let (server_cfg, ca_pem) = make_server(&[b"h2"]);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
            // Complete the handshake, then let the connection close on drop.
            let _tls = acceptor.accept(server_io).await.expect("server accept");
        });

        let cfg = TlsConfig::default()
            .with_webpki_roots(false)
            .with_ca_info_blob(ca_pem)
            .with_alpn(default_https_alpn());
        let connector = TlsConnector::from_config(&cfg).expect("connector builds");
        let stream = connector
            .connect("localhost", client_io)
            .await
            .expect("client handshake succeeds");

        assert_eq!(stream.negotiated_alpn(), AlpnProtocol::H2);
        assert_eq!(stream.tls_info().alpn, AlpnProtocol::H2);

        drop(stream);
        let _ = server.await;
    }

    /// A certificate the client does not trust (default webpki roots only) must fail with
    /// [`CurlCode::PeerFailedVerification`](crate::error::CurlCode::PeerFailedVerification)
    /// — the frozen integer `60`.
    #[tokio::test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    async fn untrusted_cert_is_peer_failed_verification() {
        let (server_cfg, _ca_pem) = make_server(&[]);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
            // The client rejects our untrusted certificate and sends a fatal alert; the
            // accept therefore fails. That is expected — ignore it.
            let _ = acceptor.accept(server_io).await;
        });

        // Default config trusts only the built-in Mozilla roots, not our self-signed cert.
        let cfg = TlsConfig::default();
        let connector = TlsConnector::from_config(&cfg).expect("connector builds");
        let err = connector
            .connect("localhost", client_io)
            .await
            .expect_err("untrusted certificate must fail verification");

        assert_eq!(err.code(), crate::error::CurlCode::PeerFailedVerification);
        assert_eq!(err.code_i32(), 60);

        let _ = server.await;
    }

    /// `--insecure` ([`TlsConfig::insecure`](config::TlsConfig::insecure)) installs an
    /// accept-all verifier, so the same untrusted certificate now completes the handshake.
    #[tokio::test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    async fn insecure_accepts_untrusted_cert() {
        let (server_cfg, _ca_pem) = make_server(&[]);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
            if let Ok(mut tls) = acceptor.accept(server_io).await {
                let mut buf = [0u8; 4];
                let _ = tls.read_exact(&mut buf).await;
                let _ = tls.write_all(b"pong").await;
                let _ = tls.flush().await;
            }
        });

        // `--insecure`: build() emits the stderr warning, then installs accept-all.
        let cfg = TlsConfig::default().insecure();
        let connector = TlsConnector::from_config(&cfg).expect("connector builds");
        let mut stream = connector
            .connect("localhost", client_io)
            .await
            .expect("insecure handshake succeeds against untrusted cert");

        stream.write_all(b"ping").await.expect("client write");
        stream.flush().await.expect("client flush");
        let mut resp = [0u8; 4];
        stream.read_exact(&mut resp).await.expect("client read");
        assert_eq!(&resp, b"pong");

        let _ = server.await;
    }
}
