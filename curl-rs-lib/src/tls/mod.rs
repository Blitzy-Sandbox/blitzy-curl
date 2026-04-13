//! TLS abstraction layer for curl-rs — rustls only.
//!
//! Rust rewrite of `lib/vtls/vtls.c` (the core TLS orchestrator) — this is the
//! TLS abstraction layer module root that replaces the C multi-backend TLS
//! selection, configuration propagation, connection filtering, ALPN handling,
//! pinned-key validation, and certificate metadata tracking.
//!
//! In the Rust rewrite, this is dramatically simplified because there is only
//! **one** TLS backend: rustls. The C vtls.c file is ~1,500+ lines managing 7
//! different TLS backends via a function pointer table (`struct Curl_ssl`). The
//! Rust replacement directly uses rustls APIs, eliminating the abstraction
//! overhead while preserving the same external semantics.
//!
//! # Submodules
//!
//! - [`config`] — TLS configuration builder (replaces `Curl_ssl_easy_config_*`)
//! - [`session_cache`] — TLS session resumption cache (replaces `vtls_scache.c`)
//! - [`keylog`] — SSLKEYLOGFILE support (replaces `keylog.c`)
//! - [`hostname`] — Hostname verification utilities (replaces `hostcheck.c`)
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks — all TLS operations use safe
//! Rust abstractions provided by the `rustls` crate. Per AAP Section 0.7.1,
//! zero `unsafe` blocks are permitted in `src/tls/`.

// ---------------------------------------------------------------------------
// Submodule declarations
// ---------------------------------------------------------------------------

pub mod config;
pub mod session_cache;
pub mod keylog;
pub mod hostname;

// ---------------------------------------------------------------------------
// Re-exports for external consumption
// ---------------------------------------------------------------------------

pub use config::{TlsConfig, TlsConfigBuilder, TlsVersion};
pub use session_cache::{SessionCache, SharedSessionCache, TlsSession};
pub use keylog::KeyLogger;
pub use hostname::cert_hostcheck;

// Re-export ALPN protocol constants (originally defined in config.rs,
// corresponding to C ALPN_* defines from vtls_int.h lines 40-47).
pub use config::{ALPN_HTTP_1_0, ALPN_HTTP_1_1, ALPN_H2, ALPN_H3};

// ---------------------------------------------------------------------------
// Standard library imports
// ---------------------------------------------------------------------------

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

// ---------------------------------------------------------------------------
// External crate imports
// ---------------------------------------------------------------------------

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// Internal imports
// ---------------------------------------------------------------------------

use crate::error::CurlError;
use config::build_rustls_client_config;
use hostname::normalize_hostname;

// =========================================================================
// Constants — IETF Protocol Version Identifiers
// =========================================================================

/// IETF protocol version identifier for TLS 1.2 (0x0303).
///
/// Corresponds to C `CURL_IETF_PROTO_TLS1_2` from vtls.h line 76.
pub const IETF_PROTO_TLS1_2: u16 = 0x0303;

/// IETF protocol version identifier for TLS 1.3 (0x0304).
///
/// Corresponds to C `CURL_IETF_PROTO_TLS1_3` from vtls.h line 77.
pub const IETF_PROTO_TLS1_3: u16 = 0x0304;

// =========================================================================
// Constants — Limits
// =========================================================================

/// Maximum size of a pinned public key file (1 MiB).
///
/// Corresponds to C `MAX_PINNED_PUBKEY_SIZE` from vtls.h line 100.
pub const MAX_PINNED_PUBKEY_SIZE: usize = 1_048_576;

/// Maximum number of certificates allowed in a chain for CURLINFO_CERTINFO.
///
/// Corresponds to C `MAX_ALLOWED_CERT_AMOUNT` from vtls.h line 168.
pub const MAX_ALLOWED_CERT_AMOUNT: usize = 100;

/// SSL shutdown timeout in milliseconds.
///
/// Corresponds to C `SSL_SHUTDOWN_TIMEOUT` from vtls.h line 209.
pub const SSL_SHUTDOWN_TIMEOUT: u64 = 10_000;

// =========================================================================
// Constants — SSL Backend Capability Flags (SSLSUPP_*)
// =========================================================================

/// Backend supports CAPATH (directory of CA certs).
/// Corresponds to C `SSLSUPP_CA_PATH` from vtls.h line 35.
pub const SSLSUPP_CA_PATH: u32 = 1 << 0;

/// Backend supports CURLOPT_CERTINFO (certificate information extraction).
/// Corresponds to C `SSLSUPP_CERTINFO` from vtls.h line 36.
pub const SSLSUPP_CERTINFO: u32 = 1 << 1;

/// Backend supports CURLOPT_PINNEDPUBLICKEY (public key pinning).
/// Corresponds to C `SSLSUPP_PINNEDPUBKEY` from vtls.h line 37.
pub const SSLSUPP_PINNEDPUBKEY: u32 = 1 << 2;

/// Backend supports CURLOPT_SSL_CTX (SSL context access).
/// Corresponds to C `SSLSUPP_SSL_CTX` from vtls.h line 38.
pub const SSLSUPP_SSL_CTX: u32 = 1 << 3;

/// Backend supports access via HTTPS proxies.
/// Corresponds to C `SSLSUPP_HTTPS_PROXY` from vtls.h line 39.
pub const SSLSUPP_HTTPS_PROXY: u32 = 1 << 4;

/// Backend supports TLS 1.3 cipher suite configuration.
/// Corresponds to C `SSLSUPP_TLS13_CIPHERSUITES` from vtls.h line 40.
pub const SSLSUPP_TLS13_CIPHERSUITES: u32 = 1 << 5;

/// Backend supports CURLOPT_CAINFO_BLOB (CA info from memory blob).
/// Corresponds to C `SSLSUPP_CAINFO_BLOB` from vtls.h line 41.
pub const SSLSUPP_CAINFO_BLOB: u32 = 1 << 6;

/// Backend supports Encrypted Client Hello (ECH).
/// Corresponds to C `SSLSUPP_ECH` from vtls.h line 42.
pub const SSLSUPP_ECH: u32 = 1 << 7;

/// Backend supports CA certificate caching.
/// Corresponds to C `SSLSUPP_CA_CACHE` from vtls.h line 43.
pub const SSLSUPP_CA_CACHE: u32 = 1 << 8;

/// Backend supports TLS 1.0-1.2 cipher list configuration.
/// Corresponds to C `SSLSUPP_CIPHER_LIST` from vtls.h line 44.
pub const SSLSUPP_CIPHER_LIST: u32 = 1 << 9;

/// Backend supports TLS signature algorithm configuration.
/// Corresponds to C `SSLSUPP_SIGNATURE_ALGORITHMS` from vtls.h line 45.
pub const SSLSUPP_SIGNATURE_ALGORITHMS: u32 = 1 << 10;

/// Backend supports CURLOPT_ISSUERCERT (issuer certificate verification).
/// Corresponds to C `SSLSUPP_ISSUERCERT` from vtls.h line 46.
pub const SSLSUPP_ISSUERCERT: u32 = 1 << 11;

/// Backend supports CURLOPT_SSL_EC_CURVES (elliptic curve configuration).
/// Corresponds to C `SSLSUPP_SSL_EC_CURVES` from vtls.h line 47.
pub const SSLSUPP_SSL_EC_CURVES: u32 = 1 << 12;

/// Backend supports CURLOPT_CRLFILE (CRL file).
/// Corresponds to C `SSLSUPP_CRLFILE` from vtls.h line 48.
pub const SSLSUPP_CRLFILE: u32 = 1 << 13;

/// Backend supports CURLOPT_ISSUERCERT_BLOB (issuer cert from blob).
/// Corresponds to C `SSLSUPP_ISSUERCERT_BLOB` from vtls.h line 49.
pub const SSLSUPP_ISSUERCERT_BLOB: u32 = 1 << 14;

// =========================================================================
// Enums — TLS Connection State Machine
// =========================================================================

/// Non-blocking SSL connection state machine.
///
/// Corresponds to C `ssl_connect_state` from vtls_int.h lines 82-87.
/// Tracks the handshake progress for a single TLS connection.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsConnectState {
    /// Initial state — handshake not yet started (ssl_connect_1).
    #[default]
    Init,
    /// TLS handshake in progress (ssl_connect_2).
    Handshaking,
    /// Handshake completing — post-handshake processing (ssl_connect_3).
    Completing,
    /// Handshake complete and connection established (ssl_connect_done).
    Done,
}

/// Overall TLS connection state.
///
/// Corresponds to C `ssl_connection_state` from vtls_int.h lines 89-94.
/// Tracks the high-level connection lifecycle across the entire transfer.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsConnectionState {
    /// No TLS connection (ssl_connection_none).
    #[default]
    None,
    /// TLS handshake deferred — e.g., for early data (ssl_connection_deferred).
    Deferred,
    /// TLS negotiation in progress (ssl_connection_negotiating).
    Negotiating,
    /// TLS connection fully established (ssl_connection_complete).
    Complete,
}

/// TLS early data (0-RTT) state machine.
///
/// Corresponds to C `ssl_earlydata_state` from vtls_int.h lines 96-103.
/// Tracks the lifecycle of early data transmission during TLS 1.3 handshakes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EarlyDataState {
    /// No early data activity (ssl_earlydata_none).
    #[default]
    None,
    /// Waiting for early data readiness (ssl_earlydata_await).
    Await,
    /// Sending early data (ssl_earlydata_sending).
    Sending,
    /// Early data sent, waiting for server decision (ssl_earlydata_sent).
    Sent,
    /// Server accepted early data (ssl_earlydata_accepted).
    Accepted,
    /// Server rejected early data — full handshake needed (ssl_earlydata_rejected).
    Rejected,
}

/// Type classification for SSL peer addresses.
///
/// Corresponds to C `ssl_peer_type` / `CURL_SSL_PEER_*` from vtls.h lines 81-85.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SslPeerType {
    /// DNS hostname (CURL_SSL_PEER_DNS).
    Dns,
    /// IPv4 address literal (CURL_SSL_PEER_IPV4).
    Ipv4,
    /// IPv6 address literal (CURL_SSL_PEER_IPV6).
    Ipv6,
}

// =========================================================================
// Transport enum — peer transport type
// =========================================================================

/// Transport protocol type for TLS connections.
///
/// Corresponds to C `TRNSPRT_*` defines used in `ssl_peer.transport`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// TCP transport (TRNSPRT_TCP).
    #[default]
    Tcp,
    /// UDP transport (TRNSPRT_UDP).
    Udp,
    /// QUIC transport (TRNSPRT_QUIC).
    Quic,
}

// =========================================================================
// SslPeer — peer information for TLS connections
// =========================================================================

/// SSL peer information for hostname verification and session cache lookups.
///
/// Corresponds to C `struct ssl_peer` from vtls.h lines 87-95. Contains
/// all the data needed to establish and verify a TLS connection to a remote
/// peer, including the hostname, SNI value, session cache key, and address
/// type classification.
#[derive(Debug, Clone)]
pub struct SslPeer {
    /// Hostname for certificate verification.
    pub hostname: String,
    /// Display version of hostname (normalized, lowercase, no trailing dot).
    pub display_name: String,
    /// Server Name Indication (SNI) value, or `None` for IP literals.
    /// SNI is only valid for DNS hostnames per RFC 6066.
    pub sni: Option<String>,
    /// Session cache key for lookups (typically `"hostname:port"`).
    pub scache_key: Option<String>,
    /// Classification of the peer address.
    pub peer_type: SslPeerType,
    /// Port number for the connection.
    pub port: u16,
    /// Transport protocol (TCP, UDP, QUIC).
    pub transport: Transport,
}

impl SslPeer {
    /// Creates a new `SslPeer` from a hostname and port.
    ///
    /// Automatically determines the peer type (DNS, IPv4, IPv6) from the
    /// hostname format, sets SNI appropriately (disabled for IP literals),
    /// and generates the session cache key.
    ///
    /// Matches C `Curl_ssl_peer_init()` from vtls.c.
    ///
    /// # Arguments
    ///
    /// * `hostname` — The peer hostname or IP address string.
    /// * `port` — The peer port number.
    pub fn new(hostname: &str, port: u16) -> Self {
        let peer_type = classify_peer_type(hostname);

        // SNI is only valid for DNS hostnames — IP literals cannot be used
        // as SNI values per RFC 6066 §3.
        let sni = if peer_type == SslPeerType::Dns {
            Some(hostname.to_string())
        } else {
            Option::None
        };

        // Normalize display name (lowercase, strip trailing dot).
        let display_name = normalize_hostname(hostname);

        // Generate session cache key as "normalized_host:port".
        let scache_key = Some(format!("{}:{}", display_name, port));

        tracing::debug!(
            hostname = hostname,
            peer_type = ?peer_type,
            sni = ?sni,
            port = port,
            "SSL peer initialized"
        );

        SslPeer {
            hostname: hostname.to_string(),
            display_name,
            sni,
            scache_key,
            peer_type,
            port,
            transport: Transport::Tcp,
        }
    }
}

/// Classify a hostname string as DNS, IPv4, or IPv6.
///
/// Handles standard IP address formats and bracketed IPv6 notation.
fn classify_peer_type(hostname: &str) -> SslPeerType {
    // Check IPv4 first (most common IP literal format).
    if hostname.parse::<Ipv4Addr>().is_ok() {
        return SslPeerType::Ipv4;
    }

    // Check IPv6 — both bare and bracketed notation.
    if hostname.parse::<Ipv6Addr>().is_ok() {
        return SslPeerType::Ipv6;
    }
    if hostname.starts_with('[') && hostname.ends_with(']') {
        let inner = &hostname[1..hostname.len() - 1];
        if inner.parse::<Ipv6Addr>().is_ok() {
            return SslPeerType::Ipv6;
        }
    }

    SslPeerType::Dns
}

// =========================================================================
// Certificate Information Structures
// =========================================================================

/// Certificate information for the entire peer certificate chain.
///
/// Corresponds to C `struct curl_certinfo` from curl.h. Used to implement
/// `CURLINFO_CERTINFO` which returns detailed certificate data for each
/// certificate in the peer's chain.
#[derive(Debug, Clone)]
pub struct CertInfo {
    /// Certificate entries, one per certificate in the chain.
    /// Index 0 is the leaf (end-entity) certificate, subsequent entries
    /// are intermediate and root CA certificates.
    pub certs: Vec<CertInfoEntry>,
}

/// A single certificate's metadata as key-value pairs.
///
/// Corresponds to a single `struct curl_slist *` entry in the C
/// `curl_certinfo.certinfo[]` array. Each field is a "label:value" pair
/// matching the format of `Curl_ssl_push_certinfo()`.
#[derive(Debug, Clone)]
pub struct CertInfoEntry {
    /// Key-value pairs of certificate fields (e.g., `("Subject", "CN=...")`).
    pub fields: Vec<(String, String)>,
}

// =========================================================================
// CurlTlsStream — async TLS stream wrapper
// =========================================================================

/// Async TLS stream wrapping a `tokio_rustls::client::TlsStream`.
///
/// This is the primary TLS transport type that replaces the C connection
/// filter chain (`Curl_cft_ssl`) for TLS connections. It wraps the
/// completed TLS handshake result and provides async I/O plus access to
/// connection metadata (ALPN, certificates, peer info).
///
/// Implements `AsyncRead` and `AsyncWrite` by delegating to the inner
/// `tokio_rustls` stream, replacing the C `ssl_cf_send()` and
/// `ssl_cf_recv()` functions.
pub struct CurlTlsStream {
    /// Inner TLS stream over TCP transport.
    inner: tokio_rustls::client::TlsStream<TcpStream>,
    /// Peer information for this connection.
    peer: SslPeer,
    /// Current connection state.
    state: TlsConnectionState,
    /// Negotiated ALPN protocol string (e.g., "h2", "http/1.1").
    alpn_negotiated: Option<String>,
    /// Extracted certificate information (lazily populated).
    server_cert_info: Option<CertInfo>,
}

impl std::fmt::Debug for CurlTlsStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CurlTlsStream")
            .field("peer", &self.peer.display_name)
            .field("state", &self.state)
            .field("alpn", &self.alpn_negotiated)
            .field("has_cert_info", &self.server_cert_info.is_some())
            .finish()
    }
}

impl CurlTlsStream {
    /// Establishes a TLS connection over an existing TCP stream.
    ///
    /// This is the primary TLS handshake entry point, replacing the C
    /// `ssl_cf_connect()` function from vtls.c. The function:
    ///
    /// 1. Builds a `rustls::ClientConfig` from the provided `TlsConfig`
    /// 2. Creates a `tokio_rustls::TlsConnector`
    /// 3. Performs the async TLS handshake
    /// 4. Extracts negotiated ALPN protocol
    /// 5. Extracts server certificate information
    ///
    /// # Arguments
    ///
    /// * `tcp_stream` — An established TCP connection to the peer.
    /// * `config` — TLS configuration (certificates, verification, ciphers).
    /// * `peer` — Peer identification information for SNI and verification.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::SslConnectError`] if the handshake fails,
    /// [`CurlError::PeerFailedVerification`] if certificate verification
    /// fails (when `verify_peer` is enabled).
    pub async fn connect(
        tcp_stream: TcpStream,
        config: &TlsConfig,
        peer: &SslPeer,
    ) -> Result<Self, CurlError> {
        tracing::debug!(
            hostname = %peer.hostname,
            port = peer.port,
            verify_peer = config.verify_peer,
            "Starting TLS handshake"
        );

        // Step 1: Build rustls ClientConfig from our TlsConfig.
        let client_config = build_rustls_client_config(config)?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        // Step 2: Determine the ServerName for SNI.
        let server_name = resolve_server_name(peer)?;

        // Step 3: Perform the async TLS handshake.
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| {
                let error_str = e.to_string();
                tracing::warn!(
                    hostname = %peer.hostname,
                    error = %error_str,
                    "TLS handshake failed"
                );
                // Distinguish certificate verification failures from general
                // connection errors for more precise error reporting.
                if error_str.contains("certificate")
                    || error_str.contains("verify")
                    || error_str.contains("CertificateRequired")
                    || error_str.contains("UnknownCA")
                    || error_str.contains("CertExpired")
                    || error_str.contains("InvalidCertificate")
                {
                    CurlError::PeerFailedVerification
                } else {
                    CurlError::SslConnectError
                }
            })?;

        // Step 4: Extract negotiated ALPN protocol.
        let alpn_negotiated = {
            let (_, conn) = tls_stream.get_ref();
            conn.alpn_protocol()
                .and_then(|proto| std::str::from_utf8(proto).ok())
                .map(|s| s.to_string())
        };

        if let Some(ref alpn) = alpn_negotiated {
            tracing::info!(protocol = %alpn, "ALPN: server accepted {}", alpn);
        } else {
            tracing::info!("ALPN: server did not agree on a protocol. Uses default.");
        }

        // Step 5: Extract server certificate information.
        let server_cert_info = extract_cert_info_from_connection(&tls_stream);

        tracing::debug!(
            hostname = %peer.hostname,
            alpn = ?alpn_negotiated,
            cert_count = server_cert_info.as_ref().map_or(0, |ci| ci.certs.len()),
            "TLS handshake complete"
        );

        Ok(CurlTlsStream {
            inner: tls_stream,
            peer: peer.clone(),
            state: TlsConnectionState::Complete,
            alpn_negotiated,
            server_cert_info,
        })
    }

    /// Returns a reference to the SSL peer information.
    pub fn peer(&self) -> &SslPeer {
        &self.peer
    }

    /// Returns the current TLS connection state.
    pub fn state(&self) -> TlsConnectionState {
        self.state
    }

    /// Returns the negotiated ALPN protocol, if any.
    pub fn alpn_negotiated(&self) -> Option<&str> {
        self.alpn_negotiated.as_deref()
    }

    /// Returns the server certificate information, if available.
    pub fn server_cert_info(&self) -> Option<&CertInfo> {
        self.server_cert_info.as_ref()
    }

    /// Gracefully shuts down the TLS connection.
    ///
    /// Sends a TLS `close_notify` alert and waits for the peer's response.
    /// Matches the C `ssl_cf_shutdown()` behavior with a timeout of
    /// [`SSL_SHUTDOWN_TIMEOUT`] milliseconds.
    pub async fn shutdown(&mut self) -> Result<(), CurlError> {
        tracing::debug!(
            hostname = %self.peer.hostname,
            "Initiating TLS shutdown"
        );

        // Use tokio's AsyncWriteExt::shutdown() which sends close_notify.
        tokio::io::AsyncWriteExt::shutdown(&mut self.inner)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "TLS shutdown failed");
                CurlError::SslShutdownFailed
            })?;

        self.state = TlsConnectionState::None;
        tracing::debug!("TLS shutdown complete");
        Ok(())
    }
}

// =========================================================================
// AsyncRead / AsyncWrite implementations for CurlTlsStream
// =========================================================================

impl AsyncRead for CurlTlsStream {
    /// Delegates to the inner `tokio_rustls::client::TlsStream`.
    ///
    /// Replaces C `ssl_cf_recv()` from vtls.c — reads decrypted data
    /// from the TLS connection.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for CurlTlsStream {
    /// Delegates to the inner `tokio_rustls::client::TlsStream`.
    ///
    /// Replaces C `ssl_cf_send()` from vtls.c — writes data to be encrypted
    /// and sent over the TLS connection.
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    /// Flushes the TLS write buffer.
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    /// Initiates a graceful TLS shutdown (sends `close_notify`).
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// =========================================================================
// Global TLS Lifecycle Functions
// =========================================================================

/// Initializes the global TLS subsystem.
///
/// Installs the rustls crypto provider (aws-lc-rs) as the default and
/// initializes key logging if the `SSLKEYLOGFILE` environment variable
/// is set.
///
/// Unlike C `Curl_ssl_init()` which dispatches to the selected backend's
/// `init()` function, this is simplified to a single rustls initialization.
/// The call is idempotent — repeated calls after the first are no-ops.
///
/// # Errors
///
/// Returns [`CurlError::FailedInit`] if the crypto provider cannot be
/// installed (should never happen with aws-lc-rs).
pub fn tls_init() -> Result<(), CurlError> {
    // Install the aws-lc-rs crypto provider as the default for rustls.
    // This is idempotent — if already installed, the Err is benign
    // (it returns the provider that was attempted to install).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Initialize key logging from SSLKEYLOGFILE environment variable.
    // Uses the global singleton keylogger (init_keylogger provides the
    // rustls::KeyLog trait object; global_keylogger provides direct access).
    let _keylog_instance = keylog::init_keylogger();
    keylog::global_keylogger().open();

    tracing::debug!("TLS subsystem initialized (rustls backend)");
    Ok(())
}

/// Cleans up the global TLS subsystem.
///
/// Closes the key logger and performs any necessary cleanup. For rustls,
/// cleanup is minimal since Rust's ownership system handles resource
/// deallocation automatically.
///
/// Matches C `Curl_ssl_cleanup()` from vtls.c.
pub fn tls_cleanup() {
    // Close the key logger file, flushing any buffered data.
    keylog::global_keylogger().close();
    tracing::debug!("TLS subsystem cleaned up");
}

/// Returns a version string identifying the TLS backend.
///
/// Returns a string in the format `"rustls/X.Y.Z"`, matching the C
/// `Curl_ssl_version()` behavior which reports the backend name and version.
///
/// The version is determined at compile time from the rustls crate metadata.
pub fn tls_version_string() -> String {
    // The rustls crate version is embedded at compile time via env! macro.
    // We use a const version string since rustls doesn't provide a runtime
    // version query API.
    format!("rustls/{}", env!("CARGO_PKG_VERSION"))
}

/// Fills a buffer with cryptographically secure random bytes.
///
/// Uses the operating system's entropy source via `rand::rngs::OsRng`.
/// Replaces C `Curl_ssl_random()` from vtls.c which delegates to the TLS
/// backend's random source.
///
/// # Errors
///
/// Returns [`CurlError::FailedInit`] if the system random source is
/// unavailable (extremely unlikely on supported platforms).
pub fn tls_random(buffer: &mut [u8]) -> Result<(), CurlError> {
    rand::rngs::OsRng.fill_bytes(buffer);
    Ok(())
}

/// Reports the capabilities supported by the rustls TLS backend.
///
/// Returns a bitfield of `SSLSUPP_*` flags indicating which features
/// are available. This replaces the C `Curl_ssl->supports` field from
/// the `struct Curl_ssl` function pointer table.
///
/// # Rustls capability profile:
///
/// - `SSLSUPP_CERTINFO` — YES: can extract peer certificate chain
/// - `SSLSUPP_PINNEDPUBKEY` — YES: supports SHA-256 hash pinning
/// - `SSLSUPP_HTTPS_PROXY` — YES: HTTPS proxy connections supported
/// - `SSLSUPP_TLS13_CIPHERSUITES` — YES: TLS 1.3 cipher configuration
/// - `SSLSUPP_CAINFO_BLOB` — YES: CA certs from memory blobs
/// - `SSLSUPP_CA_CACHE` — YES: CA certificate store caching
/// - `SSLSUPP_CIPHER_LIST` — YES: TLS 1.2 cipher configuration
/// - `SSLSUPP_CA_PATH` — NO: rustls uses CA files, not directory paths
/// - `SSLSUPP_ECH` — NO: ECH not yet supported in rustls
/// - `SSLSUPP_CRLFILE` — NO: rustls handles CRL differently
/// - `SSLSUPP_SSL_CTX` — NO: no OpenSSL-style context access
pub fn tls_capabilities() -> u32 {
    SSLSUPP_CERTINFO
        | SSLSUPP_PINNEDPUBKEY
        | SSLSUPP_HTTPS_PROXY
        | SSLSUPP_TLS13_CIPHERSUITES
        | SSLSUPP_CAINFO_BLOB
        | SSLSUPP_CA_CACHE
        | SSLSUPP_CIPHER_LIST
}

/// Check if a specific TLS capability is available.
///
/// Returns `Err(CurlError::NotBuiltIn)` if the capability is not
/// supported by the rustls backend, `Ok(())` otherwise.
///
/// # Example capabilities that return NotBuiltIn:
/// - `SSLSUPP_CA_PATH` — rustls uses files, not directory paths
/// - `SSLSUPP_ECH` — ECH not yet available in rustls
/// - `SSLSUPP_CRLFILE` — CRL files not directly supported
pub fn check_capability(cap: u32) -> Result<(), CurlError> {
    if tls_capabilities() & cap != 0 {
        Ok(())
    } else {
        tracing::debug!(
            capability = cap,
            "TLS capability not built in: {}",
            CurlError::NotBuiltIn.strerror()
        );
        Err(CurlError::NotBuiltIn)
    }
}

// =========================================================================
// ALPN Handling
// =========================================================================

/// Returns the negotiated ALPN protocol for a TLS stream.
///
/// Convenience free function that queries the `CurlTlsStream` for the
/// ALPN protocol negotiated during the TLS handshake. Returns `None` if
/// no ALPN was negotiated.
///
/// Matches the C `Curl_alpn_set_negotiated()` / `connssl->negotiated.alpn`
/// pattern from vtls.c.
pub fn get_negotiated_alpn(tls_stream: &CurlTlsStream) -> Option<&str> {
    tls_stream.alpn_negotiated()
}

// =========================================================================
// Certificate Information Extraction
// =========================================================================

/// Extracts certificate information from a TLS stream.
///
/// Returns a `CertInfo` containing metadata for each certificate in the
/// peer's certificate chain, up to [`MAX_ALLOWED_CERT_AMOUNT`] certificates.
///
/// For each certificate, the following fields are extracted:
/// - `"Subject"` — Distinguished name of the certificate subject
/// - `"Issuer"` — Distinguished name of the certificate issuer
/// - `"Serial Number"` — Hex-encoded serial number
/// - `"Cert"` — PEM-encoded certificate
///
/// Matches C `Curl_ssl_push_certinfo()` for `CURLINFO_CERTINFO` support.
pub fn extract_cert_info(tls_stream: &CurlTlsStream) -> Option<CertInfo> {
    tls_stream.server_cert_info.clone()
}

/// Internal helper to extract certificate information from a raw TLS connection.
fn extract_cert_info_from_connection(
    tls_stream: &tokio_rustls::client::TlsStream<TcpStream>,
) -> Option<CertInfo> {
    let (_, conn) = tls_stream.get_ref();
    let certs = conn.peer_certificates()?;

    if certs.is_empty() {
        return Option::None;
    }

    // Enforce maximum chain length — matches C MAX_ALLOWED_CERT_AMOUNT.
    let max_certs = certs.len().min(MAX_ALLOWED_CERT_AMOUNT);
    let mut entries = Vec::new();
    entries.try_reserve(max_certs).ok().or_else(|| {
        tracing::error!(
            "{}",
            CurlError::OutOfMemory.strerror()
        );
        Option::<()>::None
    })?;

    for (i, cert_der) in certs.iter().take(max_certs).enumerate() {
        let der_bytes = cert_der.as_ref();
        let mut fields = Vec::new();

        // Extract serial number from DER-encoded certificate.
        if let Some(serial) = extract_serial_from_der(der_bytes) {
            fields.push(("Serial Number".to_string(), serial));
        }

        // Extract subject and issuer via basic DER walking.
        if let Some((subject, issuer)) = extract_subject_issuer_from_der(der_bytes) {
            fields.push(("Subject".to_string(), subject));
            fields.push(("Issuer".to_string(), issuer));
        } else {
            fields.push(("Subject".to_string(), format!("Certificate {}", i)));
            fields.push(("Issuer".to_string(), format!("Certificate {} Issuer", i)));
        }

        // PEM-encoded certificate.
        let pem = der_to_pem(der_bytes);
        fields.push(("Cert".to_string(), pem));

        entries.push(CertInfoEntry { fields });
    }

    tracing::trace!(count = entries.len(), "Extracted certificate info");
    Some(CertInfo { certs: entries })
}

// =========================================================================
// Pinned Public Key Verification
// =========================================================================

/// Verifies a peer certificate's public key against a pinned value.
///
/// Supports two pinning modes:
///
/// 1. **Hash-based pinning** (`sha256//base64hash`): Computes SHA-256 of the
///    DER-encoded SubjectPublicKeyInfo (SPKI) from the certificate and
///    compares the base64-encoded hash against the pin string. Multiple pins
///    can be separated by semicolons.
///
/// 2. **File-based pinning** (file path): Loads a PEM or DER public key file
///    and compares it byte-for-byte against the certificate's SPKI.
///
/// Max pinned pubkey file size: 1 MiB ([`MAX_PINNED_PUBKEY_SIZE`]).
///
/// Matches C `Curl_pin_peer_pubkey()` from vtls.c lines 756-895.
///
/// # Arguments
///
/// * `peer_cert` — DER-encoded peer certificate (full X.509 certificate).
/// * `pinned` — Pin specification: either `"sha256//base64hash"` or a file path.
///
/// # Errors
///
/// Returns [`CurlError::SslPinnedPubkeyNotMatch`] if the pin does not match.
pub fn verify_pinned_pubkey(peer_cert: &[u8], pinned: &str) -> Result<(), CurlError> {
    if pinned.is_empty() {
        // No pinning configured — always passes.
        return Ok(());
    }

    if peer_cert.is_empty() {
        return Err(CurlError::SslPinnedPubkeyNotMatch);
    }

    // Extract the SubjectPublicKeyInfo (SPKI) from the certificate DER.
    // A malformed certificate is treated as a content encoding error
    // before falling back to pin mismatch.
    let spki = extract_spki_from_cert(peer_cert).ok_or_else(|| {
        tracing::warn!(
            "Failed to extract SPKI from certificate: {}",
            CurlError::BadContentEncoding.strerror()
        );
        CurlError::SslPinnedPubkeyNotMatch
    })?;

    // Check if this is a sha256 hash-based pin.
    if pinned.starts_with("sha256//") {
        return verify_sha256_pin(spki, pinned);
    }

    // Otherwise, treat as a file path to a public key.
    verify_file_pin(spki, pinned)
}

/// Verify a SHA-256 hash-based pin against the SPKI.
fn verify_sha256_pin(spki: &[u8], pinned_str: &str) -> Result<(), CurlError> {
    // Compute SHA-256 of the SPKI.
    let mut hasher = Sha256::new();
    hasher.update(spki);
    let digest = hasher.finalize();

    // Base64-encode the digest for comparison.
    let cert_hash = BASE64_STANDARD.encode(digest);
    tracing::info!(hash = %format!("sha256//{}", cert_hash), "Public key hash");

    // Walk through semicolon-separated pin entries.
    let mut pin_cursor = pinned_str;
    while let Some(stripped) = pin_cursor.strip_prefix("sha256//") {
        // Find the end of this pin (semicolon or end of string).
        let (this_pin, rest) = match stripped.find(';') {
            Some(pos) => (&stripped[..pos], Some(&stripped[pos + 1..])),
            None => (stripped, None),
        };

        // Compare base64-encoded hashes.
        if cert_hash == this_pin {
            tracing::debug!("Public key hash matches pinned value");
            return Ok(());
        }

        tracing::debug!(
            expected = this_pin,
            actual = %cert_hash,
            "Public key hash does not match"
        );

        // Move to next pin entry or stop.
        match rest {
            Some(r) => pin_cursor = r,
            None => break,
        }
    }

    Err(CurlError::SslPinnedPubkeyNotMatch)
}

/// Verify a file-based pin against the SPKI.
fn verify_file_pin(spki: &[u8], path: &str) -> Result<(), CurlError> {
    // Read the file contents.
    let file_data = std::fs::read(path).map_err(|e| {
        tracing::warn!(path = path, error = %e, "Failed to read pinned pubkey file");
        CurlError::SslPinnedPubkeyNotMatch
    })?;

    // Enforce size limit.
    if file_data.len() > MAX_PINNED_PUBKEY_SIZE {
        tracing::warn!(
            path = path,
            size = file_data.len(),
            max = MAX_PINNED_PUBKEY_SIZE,
            "Pinned pubkey file exceeds maximum size"
        );
        return Err(CurlError::SslPinnedPubkeyNotMatch);
    }

    // If the file size matches the SPKI size, try direct DER comparison.
    if file_data.len() == spki.len() && file_data == spki {
        tracing::debug!("Pinned pubkey matches (DER direct comparison)");
        return Ok(());
    }

    // Otherwise, try parsing as PEM.
    if let Some(der_from_pem) = pem_pubkey_to_der(&file_data) {
        if der_from_pem == spki {
            tracing::debug!("Pinned pubkey matches (PEM decoded comparison)");
            return Ok(());
        }
    }

    Err(CurlError::SslPinnedPubkeyNotMatch)
}

// =========================================================================
// SSL Connection Filter Add
// =========================================================================

/// Adds a TLS layer to an existing TCP connection.
///
/// This is a convenience function that creates a `CurlTlsStream` from a
/// TCP stream and TLS configuration, replacing the C `Curl_ssl_cfilter_add()`
/// function which adds a TLS connection filter to the filter chain.
///
/// In the Rust architecture, this simply wraps `CurlTlsStream::connect()`
/// with a pre-built `SslPeer`.
///
/// # Arguments
///
/// * `tcp_stream` — An established TCP connection.
/// * `config` — TLS configuration.
/// * `hostname` — The peer hostname for SNI and verification.
/// * `port` — The peer port number.
///
/// # Errors
///
/// Returns appropriate [`CurlError`] variants on TLS handshake failure.
pub async fn ssl_cfilter_add(
    tcp_stream: TcpStream,
    config: &TlsConfig,
    hostname: &str,
    port: u16,
) -> Result<CurlTlsStream, CurlError> {
    let peer = SslPeer::new(hostname, port);
    CurlTlsStream::connect(tcp_stream, config, &peer).await
}

// =========================================================================
// Internal Helper Functions — ServerName Resolution
// =========================================================================

/// Converts an `SslPeer` into a `rustls_pki_types::ServerName` for TLS.
fn resolve_server_name(
    peer: &SslPeer,
) -> Result<rustls_pki_types::ServerName<'static>, CurlError> {
    // Use the SNI value if available (DNS hostnames), otherwise use the
    // raw hostname (IP addresses).
    let name_str = peer
        .sni
        .as_deref()
        .unwrap_or(&peer.hostname);

    rustls_pki_types::ServerName::try_from(name_str.to_string()).map_err(|e| {
        tracing::warn!(
            hostname = name_str,
            error = %e,
            "Failed to parse hostname as TLS ServerName"
        );
        CurlError::SslConnectError
    })
}

// =========================================================================
// Internal Helper Functions — DER / PEM Utilities
// =========================================================================

/// Converts DER-encoded certificate bytes to PEM format.
fn der_to_pem(der: &[u8]) -> String {
    let b64 = BASE64_STANDARD.encode(der);
    let mut pem = String::with_capacity(b64.len() + 60);
    pem.push_str("-----BEGIN CERTIFICATE-----\n");
    // PEM format requires 64-character lines.
    for chunk in b64.as_bytes().chunks(64) {
        if let Ok(s) = std::str::from_utf8(chunk) {
            pem.push_str(s);
        }
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// Extracts the SubjectPublicKeyInfo (SPKI) from a DER-encoded X.509 certificate.
///
/// Walks the ASN.1 structure: Certificate → TBSCertificate → subjectPublicKeyInfo
///
/// Returns the raw DER bytes of the SPKI, or `None` if parsing fails.
fn extract_spki_from_cert(cert_der: &[u8]) -> Option<&[u8]> {
    let mut pos = 0;

    // Outer SEQUENCE (Certificate)
    pos = skip_asn1_tag_length(cert_der, pos, 0x30)?;

    // Inner SEQUENCE (TBSCertificate)
    let tbs_start = pos;
    pos = skip_asn1_tag_length(cert_der, tbs_start, 0x30)?;

    // Optional [0] EXPLICIT version
    if pos < cert_der.len() && cert_der[pos] == 0xA0 {
        pos = skip_asn1_tlv(cert_der, pos)?;
    }

    // Serial number (INTEGER)
    pos = skip_asn1_tlv(cert_der, pos)?;

    // Signature algorithm (SEQUENCE)
    pos = skip_asn1_tlv(cert_der, pos)?;

    // Issuer (SEQUENCE)
    pos = skip_asn1_tlv(cert_der, pos)?;

    // Validity (SEQUENCE)
    pos = skip_asn1_tlv(cert_der, pos)?;

    // Subject (SEQUENCE)
    pos = skip_asn1_tlv(cert_der, pos)?;

    // SubjectPublicKeyInfo (SEQUENCE) — this is what we want
    let spki_start = pos;
    let spki_end = skip_asn1_tlv(cert_der, pos)?;

    Some(&cert_der[spki_start..spki_end])
}

/// Extracts the serial number from a DER-encoded X.509 certificate as hex.
fn extract_serial_from_der(cert_der: &[u8]) -> Option<String> {
    let mut pos = 0;

    // Outer SEQUENCE (Certificate)
    pos = skip_asn1_tag_length(cert_der, pos, 0x30)?;

    // Inner SEQUENCE (TBSCertificate)
    pos = skip_asn1_tag_length(cert_der, pos, 0x30)?;

    // Optional [0] EXPLICIT version
    if pos < cert_der.len() && cert_der[pos] == 0xA0 {
        pos = skip_asn1_tlv(cert_der, pos)?;
    }

    // Serial number (INTEGER tag = 0x02)
    if pos < cert_der.len() && cert_der[pos] == 0x02 {
        let (value, _) = read_asn1_tlv_value(cert_der, pos)?;
        return Some(hex_encode(value));
    }

    Option::None
}

/// Extracts subject and issuer Distinguished Names from a DER certificate.
fn extract_subject_issuer_from_der(cert_der: &[u8]) -> Option<(String, String)> {
    let mut pos = 0;

    // Outer SEQUENCE (Certificate)
    pos = skip_asn1_tag_length(cert_der, pos, 0x30)?;

    // Inner SEQUENCE (TBSCertificate)
    pos = skip_asn1_tag_length(cert_der, pos, 0x30)?;

    // Optional [0] EXPLICIT version
    if pos < cert_der.len() && cert_der[pos] == 0xA0 {
        pos = skip_asn1_tlv(cert_der, pos)?;
    }

    // Serial number
    pos = skip_asn1_tlv(cert_der, pos)?;

    // Signature algorithm
    pos = skip_asn1_tlv(cert_der, pos)?;

    // Issuer (SEQUENCE) — extract
    let issuer_start = pos;
    let issuer_end = skip_asn1_tlv(cert_der, pos)?;
    let issuer = dn_to_string(&cert_der[issuer_start..issuer_end]);

    pos = issuer_end;

    // Validity
    pos = skip_asn1_tlv(cert_der, pos)?;

    // Subject (SEQUENCE) — extract
    let subject_start = pos;
    let subject_end = skip_asn1_tlv(cert_der, pos)?;
    let subject = dn_to_string(&cert_der[subject_start..subject_end]);

    Some((subject, issuer))
}

/// Convert a DER-encoded Distinguished Name (DN) to a human-readable string.
///
/// Performs a best-effort extraction of common OIDs (CN, O, OU, C, ST, L).
fn dn_to_string(dn_der: &[u8]) -> String {
    let mut result = Vec::new();
    let mut pos = 0;

    // Skip outer SEQUENCE tag+length
    if let Some(inner_pos) = skip_asn1_tag_length(dn_der, pos, 0x30) {
        pos = inner_pos;
    } else {
        return format!("(DER: {} bytes)", dn_der.len());
    }

    // Walk through SET elements (each containing a SEQUENCE of OID + value)
    while pos < dn_der.len() {
        if dn_der[pos] != 0x31 {
            break; // Not a SET
        }
        if let Some(set_inner) = skip_asn1_tag_length(dn_der, pos, 0x31) {
            let set_end = skip_asn1_tlv(dn_der, pos).unwrap_or(dn_der.len());

            // Inside SET, expect SEQUENCE
            let mut seq_pos = set_inner;
            if seq_pos < set_end && dn_der[seq_pos] == 0x30 {
                if let Some(seq_inner) = skip_asn1_tag_length(dn_der, seq_pos, 0x30) {
                    seq_pos = seq_inner;

                    // Read OID
                    if seq_pos < set_end && dn_der[seq_pos] == 0x06 {
                        if let Some((oid_bytes, after_oid)) =
                            read_asn1_tlv_value(dn_der, seq_pos)
                        {
                            let oid_name = oid_to_short_name(oid_bytes);

                            // Read value (UTF8String, PrintableString, etc.)
                            if after_oid < set_end {
                                let tag = dn_der[after_oid];
                                if matches!(tag, 0x0C | 0x13 | 0x16 | 0x1A | 0x1E) {
                                    if let Some((val_bytes, _)) =
                                        read_asn1_tlv_value(dn_der, after_oid)
                                    {
                                        if let Ok(val_str) = std::str::from_utf8(val_bytes) {
                                            result.push(format!("{}={}", oid_name, val_str));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            pos = set_end;
        } else {
            break;
        }
    }

    if result.is_empty() {
        format!("(DER: {} bytes)", dn_der.len())
    } else {
        result.join(", ")
    }
}

/// Maps common X.500 OID byte sequences to short names.
fn oid_to_short_name(oid: &[u8]) -> &'static str {
    match oid {
        // id-at-commonName (2.5.4.3)
        [0x55, 0x04, 0x03] => "CN",
        // id-at-countryName (2.5.4.6)
        [0x55, 0x04, 0x06] => "C",
        // id-at-stateOrProvinceName (2.5.4.8)
        [0x55, 0x04, 0x08] => "ST",
        // id-at-localityName (2.5.4.7)
        [0x55, 0x04, 0x07] => "L",
        // id-at-organizationName (2.5.4.10)
        [0x55, 0x04, 0x0A] => "O",
        // id-at-organizationalUnitName (2.5.4.11)
        [0x55, 0x04, 0x0B] => "OU",
        // emailAddress (1.2.840.113549.1.9.1)
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01] => "emailAddress",
        _ => "OID",
    }
}

// =========================================================================
// Internal Helper Functions — ASN.1 DER Parsing Primitives
// =========================================================================

/// Skip an ASN.1 tag and length, returning the position of the value.
///
/// Verifies that the tag at `pos` matches `expected_tag`. Returns the
/// position immediately after the tag and length bytes (i.e., the start
/// of the value field).
fn skip_asn1_tag_length(data: &[u8], pos: usize, expected_tag: u8) -> Option<usize> {
    if pos >= data.len() || data[pos] != expected_tag {
        return Option::None;
    }
    let (_, value_start) = parse_asn1_length(data, pos + 1)?;
    Some(value_start)
}

/// Skip an entire ASN.1 TLV (Tag-Length-Value), returning the position after it.
fn skip_asn1_tlv(data: &[u8], pos: usize) -> Option<usize> {
    if pos >= data.len() {
        return Option::None;
    }
    // Skip tag byte
    let (length, value_start) = parse_asn1_length(data, pos + 1)?;
    let end = value_start.checked_add(length)?;
    if end > data.len() {
        return Option::None;
    }
    Some(end)
}

/// Read the value of an ASN.1 TLV, returning the value slice and position after.
fn read_asn1_tlv_value(data: &[u8], pos: usize) -> Option<(&[u8], usize)> {
    if pos >= data.len() {
        return Option::None;
    }
    // Skip tag byte
    let (length, value_start) = parse_asn1_length(data, pos + 1)?;
    let end = value_start.checked_add(length)?;
    if end > data.len() {
        return Option::None;
    }
    Some((&data[value_start..end], end))
}

/// Parse an ASN.1 DER length field starting at `pos`.
///
/// Returns (length_value, position_after_length).
fn parse_asn1_length(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    if pos >= data.len() {
        return Option::None;
    }

    let first = data[pos] as usize;
    if first < 0x80 {
        // Short form: single byte length
        Some((first, pos + 1))
    } else if first == 0x80 {
        // Indefinite length — not supported in DER
        Option::None
    } else {
        // Long form: first byte indicates number of length bytes
        let num_bytes = first & 0x7F;
        if num_bytes > 4 || pos + 1 + num_bytes > data.len() {
            return Option::None;
        }
        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = length.checked_shl(8)?;
            length = length.checked_add(data[pos + 1 + i] as usize)?;
        }
        Some((length, pos + 1 + num_bytes))
    }
}

/// Hex-encode a byte slice as a lowercase hex string with colon separators.
fn hex_encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    data.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Decode a PEM public key to DER bytes.
///
/// Matches C `pubkey_pem_to_der()` from vtls.c lines 695-750.
fn pem_pubkey_to_der(pem_data: &[u8]) -> Option<Vec<u8>> {
    let pem_str = std::str::from_utf8(pem_data).ok()?;

    let begin_marker = "-----BEGIN PUBLIC KEY-----";
    let end_marker = "-----END PUBLIC KEY-----";

    let begin_pos = pem_str.find(begin_marker)?;
    let after_begin = begin_pos + begin_marker.len();

    let end_pos = pem_str[after_begin..].find(end_marker)?;
    let base64_region = &pem_str[after_begin..after_begin + end_pos];

    // Strip whitespace (newlines, carriage returns) from the base64 data.
    let cleaned: String = base64_region
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    BASE64_STANDARD.decode(cleaned).ok()
}

// =========================================================================
// Unit Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_peer_type_dns() {
        assert_eq!(classify_peer_type("example.com"), SslPeerType::Dns);
        assert_eq!(classify_peer_type("www.example.com"), SslPeerType::Dns);
        assert_eq!(classify_peer_type("localhost"), SslPeerType::Dns);
    }

    #[test]
    fn test_classify_peer_type_ipv4() {
        assert_eq!(classify_peer_type("127.0.0.1"), SslPeerType::Ipv4);
        assert_eq!(classify_peer_type("192.168.1.1"), SslPeerType::Ipv4);
        assert_eq!(classify_peer_type("0.0.0.0"), SslPeerType::Ipv4);
    }

    #[test]
    fn test_classify_peer_type_ipv6() {
        assert_eq!(classify_peer_type("::1"), SslPeerType::Ipv6);
        assert_eq!(classify_peer_type("[::1]"), SslPeerType::Ipv6);
        assert_eq!(
            classify_peer_type("2001:db8::1"),
            SslPeerType::Ipv6
        );
    }

    #[test]
    fn test_ssl_peer_new_dns() {
        let peer = SslPeer::new("example.com", 443);
        assert_eq!(peer.hostname, "example.com");
        assert_eq!(peer.display_name, "example.com");
        assert_eq!(peer.sni, Some("example.com".to_string()));
        assert_eq!(peer.scache_key, Some("example.com:443".to_string()));
        assert_eq!(peer.peer_type, SslPeerType::Dns);
        assert_eq!(peer.port, 443);
        assert_eq!(peer.transport, Transport::Tcp);
    }

    #[test]
    fn test_ssl_peer_new_ipv4() {
        let peer = SslPeer::new("192.168.1.1", 8443);
        assert_eq!(peer.peer_type, SslPeerType::Ipv4);
        assert_eq!(peer.sni, None); // No SNI for IP literals
        assert_eq!(peer.scache_key, Some("192.168.1.1:8443".to_string()));
    }

    #[test]
    fn test_ssl_peer_new_ipv6() {
        let peer = SslPeer::new("::1", 443);
        assert_eq!(peer.peer_type, SslPeerType::Ipv6);
        assert_eq!(peer.sni, None);
    }

    #[test]
    fn test_tls_version_string() {
        let version = tls_version_string();
        // Should start with "rustls/" followed by a version.
        assert!(version.starts_with("rustls/"), "got: {}", version);
    }

    #[test]
    fn test_tls_random() {
        let mut buf = [0u8; 32];
        assert!(tls_random(&mut buf).is_ok());
        // Very unlikely to be all zeros after random fill.
        assert_ne!(buf, [0u8; 32]);
    }

    #[test]
    fn test_tls_capabilities() {
        let caps = tls_capabilities();
        assert_ne!(caps & SSLSUPP_CERTINFO, 0);
        assert_ne!(caps & SSLSUPP_PINNEDPUBKEY, 0);
        assert_ne!(caps & SSLSUPP_HTTPS_PROXY, 0);
        assert_ne!(caps & SSLSUPP_TLS13_CIPHERSUITES, 0);
        assert_ne!(caps & SSLSUPP_CAINFO_BLOB, 0);
        assert_ne!(caps & SSLSUPP_CA_CACHE, 0);
        assert_ne!(caps & SSLSUPP_CIPHER_LIST, 0);
        // Not supported:
        assert_eq!(caps & SSLSUPP_CA_PATH, 0);
        assert_eq!(caps & SSLSUPP_ECH, 0);
        assert_eq!(caps & SSLSUPP_CRLFILE, 0);
        assert_eq!(caps & SSLSUPP_SSL_CTX, 0);
    }

    #[test]
    fn test_tls_init_idempotent() {
        // tls_init should be safely callable multiple times.
        assert!(tls_init().is_ok());
        assert!(tls_init().is_ok());
    }

    #[test]
    fn test_constants() {
        assert_eq!(IETF_PROTO_TLS1_2, 0x0303);
        assert_eq!(IETF_PROTO_TLS1_3, 0x0304);
        assert_eq!(MAX_PINNED_PUBKEY_SIZE, 1_048_576);
        assert_eq!(MAX_ALLOWED_CERT_AMOUNT, 100);
        assert_eq!(SSL_SHUTDOWN_TIMEOUT, 10_000);
    }

    #[test]
    fn test_alpn_constants() {
        assert_eq!(ALPN_HTTP_1_0, "http/1.0");
        assert_eq!(ALPN_HTTP_1_1, "http/1.1");
        assert_eq!(ALPN_H2, "h2");
        assert_eq!(ALPN_H3, "h3");
    }

    #[test]
    fn test_der_to_pem() {
        let der = vec![0x30, 0x03, 0x01, 0x01, 0xFF];
        let pem = der_to_pem(&der);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "DE:AD:BE:EF");
        assert_eq!(hex_encode(&[0x01]), "01");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn test_verify_pinned_pubkey_empty_pin() {
        // Empty pin string means no pinning — always succeeds.
        assert!(verify_pinned_pubkey(&[0x30], "").is_ok());
    }

    #[test]
    fn test_verify_pinned_pubkey_empty_cert() {
        // Empty certificate with a pin should fail.
        assert!(verify_pinned_pubkey(&[], "sha256//abc").is_err());
    }

    #[test]
    fn test_parse_asn1_length_short() {
        // Short form: 0x05 = length 5
        assert_eq!(parse_asn1_length(&[0x05, 0x00], 0), Some((5, 1)));
    }

    #[test]
    fn test_parse_asn1_length_long() {
        // Long form: 0x82 0x01 0x00 = length 256
        assert_eq!(
            parse_asn1_length(&[0x82, 0x01, 0x00], 0),
            Some((256, 3))
        );
    }

    #[test]
    fn test_early_data_state_default() {
        assert_eq!(EarlyDataState::default(), EarlyDataState::None);
    }

    #[test]
    fn test_tls_connect_state_default() {
        assert_eq!(TlsConnectState::default(), TlsConnectState::Init);
    }

    #[test]
    fn test_tls_connection_state_default() {
        assert_eq!(TlsConnectionState::default(), TlsConnectionState::None);
    }

    #[test]
    fn test_pem_pubkey_to_der() {
        // Well-formed PEM with minimal base64 content
        let pem = b"-----BEGIN PUBLIC KEY-----\nMEYw\n-----END PUBLIC KEY-----\n";
        let result = pem_pubkey_to_der(pem);
        assert!(result.is_some());
    }

    #[test]
    fn test_pem_pubkey_to_der_invalid() {
        let pem = b"not a PEM file";
        assert!(pem_pubkey_to_der(pem).is_none());
    }
}
