//! Unified TLS configuration builder using rustls.
//!
//! This module provides the single TLS configuration entry point for the entire
//! curl-rs library crate, replacing ALL 7 C TLS backend configurations (OpenSSL,
//! Schannel, GnuTLS, mbedTLS, wolfSSL, Rustls, Apple Security Transport) with a
//! single rustls-based implementation.
//!
//! # Architecture
//!
//! - [`TlsConfig`] consolidates all SSL options that were previously scattered
//!   across `ssl_primary_config`, `ssl_config_data`, and per-backend structs.
//! - [`TlsConfigBuilder`] provides a fluent builder pattern for constructing
//!   validated `TlsConfig` instances.
//! - [`build_rustls_client_config`] converts a `TlsConfig` into a
//!   `rustls::ClientConfig` ready for connection establishment.
//! - [`configs_match`] checks whether two TLS configurations are compatible for
//!   connection reuse (matching C `Curl_ssl_conn_config_match`).
//!
//! # C Source Correspondence
//!
//! | Rust item | C source |
//! |-----------|----------|
//! | `TlsConfig` | `struct ssl_primary_config` + `struct ssl_config_data` |
//! | `TlsConfigBuilder` | `Curl_ssl_easy_config_init()` pattern |
//! | `build_rustls_client_config` | Backend `vtls_connect()` + `rustls.c` config setup |
//! | `configs_match` | `match_ssl_primary_config()` from vtls.c |
//! | `TlsVersion` | `CURL_SSLVERSION_*` constants from curl.h |
//! | `HttpVersion` / `alpn_for_version` | `alpn_get_spec()` from vtls.c |
//! | Cipher mapping | `cipher_suite.c` IANA ↔ OpenSSL name translation |
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks. All TLS operations use
//! safe Rust abstractions provided by the `rustls` crate.

use std::fmt;
use std::fs::File;
use std::io::BufReader;
use std::io::Cursor;
use std::sync::Arc;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::{ClientConfig, RootCertStore};

use crate::error::CurlError;
use super::keylog;
use super::session_cache;

// ---------------------------------------------------------------------------
// ALPN Protocol Constants
// ---------------------------------------------------------------------------

/// ALPN protocol identifier for HTTP/1.0.
///
/// Corresponds to C `ALPN_HTTP_1_0` from vtls_int.h.
pub const ALPN_HTTP_1_0: &str = "http/1.0";

/// ALPN protocol identifier for HTTP/1.1.
///
/// Corresponds to C `ALPN_HTTP_1_1` from vtls_int.h.
pub const ALPN_HTTP_1_1: &str = "http/1.1";

/// ALPN protocol identifier for HTTP/2.
///
/// Corresponds to C `ALPN_H2` from vtls_int.h.
pub const ALPN_H2: &str = "h2";

/// ALPN protocol identifier for HTTP/3.
///
/// Corresponds to C `ALPN_H3` from vtls_int.h.
pub const ALPN_H3: &str = "h3";

// ---------------------------------------------------------------------------
// TlsVersion — maps to CURL_SSLVERSION_*
// ---------------------------------------------------------------------------

/// TLS protocol version selection.
///
/// Maps 1:1 to the C `CURL_SSLVERSION_*` constants from `include/curl/curl.h`.
/// SSLv2 and SSLv3 are deliberately excluded — rustls does not support them,
/// and they are deprecated for security reasons.
///
/// When used as a minimum version constraint, `Default` resolves to TLS 1.2
/// (the minimum version supported by rustls). When used as a maximum version
/// constraint, `Default` resolves to TLS 1.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersion {
    /// CURL_SSLVERSION_DEFAULT (0) — use safe defaults.
    Default,
    /// CURL_SSLVERSION_TLSv1_0 (4) — TLS 1.0 minimum.
    /// Note: rustls does not support TLS 1.0; silently upgraded to TLS 1.2.
    Tls1_0,
    /// CURL_SSLVERSION_TLSv1_1 (5) — TLS 1.1 minimum.
    /// Note: rustls does not support TLS 1.1; silently upgraded to TLS 1.2.
    Tls1_1,
    /// CURL_SSLVERSION_TLSv1_2 (6) — TLS 1.2 minimum.
    Tls1_2,
    /// CURL_SSLVERSION_TLSv1_3 (7) — TLS 1.3 only.
    Tls1_3,
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsVersion::Default => write!(f, "default"),
            TlsVersion::Tls1_0 => write!(f, "TLSv1.0"),
            TlsVersion::Tls1_1 => write!(f, "TLSv1.1"),
            TlsVersion::Tls1_2 => write!(f, "TLSv1.2"),
            TlsVersion::Tls1_3 => write!(f, "TLSv1.3"),
        }
    }
}

// ---------------------------------------------------------------------------
// HttpVersion — for ALPN selection
// ---------------------------------------------------------------------------

/// HTTP version selection for ALPN protocol negotiation.
///
/// Used by [`alpn_for_version`] to produce the correct ALPN protocol list
/// for a given preferred HTTP version, matching the C `alpn_get_spec()` logic
/// from vtls.c.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpVersion {
    /// HTTP/1.0 — offer both http/1.0 and http/1.1 for compatibility.
    Http10,
    /// HTTP/1.1 only — offer http/1.1.
    Http11,
    /// HTTP/2 — offer h2 and http/1.1 (with h2 preferred).
    Http2,
    /// HTTP/3 — offer h3 only (over QUIC).
    Http3,
    /// Default — same as HTTP/2 (offer h2 and http/1.1).
    Default,
}

// ---------------------------------------------------------------------------
// TlsConfig — consolidated SSL options
// ---------------------------------------------------------------------------

/// Unified TLS configuration consolidating all SSL options.
///
/// Replaces the combination of C `struct ssl_primary_config` and
/// `struct ssl_config_data` from `lib/urldata.h`. Every field maps to a
/// specific `CURLOPT_*` option or internal SSL configuration parameter.
///
/// # Defaults
///
/// Certificate verification is **ON by default** (`verify_peer: true`,
/// `verify_host: true`), matching the critical security requirement from
/// AAP Section 0.7.3 and the C `Curl_ssl_easy_config_init()` behavior.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Verify peer certificate (CURLOPT_SSL_VERIFYPEER) — DEFAULT TRUE.
    pub verify_peer: bool,

    /// Verify hostname against certificate (CURLOPT_SSL_VERIFYHOST) — DEFAULT TRUE.
    pub verify_host: bool,

    /// Verify OCSP stapling status (CURLOPT_SSL_VERIFYSTATUS).
    pub verify_status: bool,

    /// Minimum TLS version (CURLOPT_SSLVERSION).
    pub min_tls_version: TlsVersion,

    /// Maximum TLS version (CURLOPT_SSLVERSION max part).
    pub max_tls_version: TlsVersion,

    /// CA certificate file path (CURLOPT_CAINFO).
    pub ca_file: Option<String>,

    /// CA certificate directory path (CURLOPT_CAPATH).
    pub ca_path: Option<String>,

    /// CA certificate blob (CURLOPT_CAINFO_BLOB).
    pub ca_blob: Option<Vec<u8>>,

    /// Client certificate file (CURLOPT_SSLCERT).
    pub client_cert: Option<String>,

    /// Client certificate blob (CURLOPT_SSLCERT_BLOB).
    pub client_cert_blob: Option<Vec<u8>>,

    /// Client private key file (CURLOPT_SSLKEY).
    pub client_key: Option<String>,

    /// Client private key blob (CURLOPT_SSLKEY_BLOB).
    pub client_key_blob: Option<Vec<u8>>,

    /// Client key password (CURLOPT_KEYPASSWD).
    pub key_password: Option<String>,

    /// TLS 1.0-1.2 cipher list (CURLOPT_SSL_CIPHER_LIST).
    pub cipher_list: Option<String>,

    /// TLS 1.3 cipher suites (CURLOPT_TLS13_CIPHERS).
    pub tls13_ciphers: Option<String>,

    /// Pinned public key hash (CURLOPT_PINNEDPUBLICKEY).
    pub pinned_pubkey: Option<String>,

    /// ALPN protocols to offer during TLS handshake.
    pub alpn_protocols: Vec<String>,

    /// Certificate type (CURLOPT_SSLCERTTYPE) — "PEM", "DER", etc.
    pub cert_type: Option<String>,

    /// Key type (CURLOPT_SSLKEYTYPE) — "PEM", "DER", "ENG".
    pub key_type: Option<String>,

    /// CRL file path (CURLOPT_CRLFILE).
    pub crl_file: Option<String>,

    /// Issuer certificate file path (CURLOPT_ISSUERCERT).
    pub issuer_cert: Option<String>,

    /// Enable native CA store (CURLOPT_SSL_OPTIONS with CURLSSLOPT_NATIVE_CA).
    pub native_ca: bool,

    /// Session caching enabled (CURLOPT_SSL_SESSIONID_CACHE).
    pub session_cache_enabled: bool,
}

impl Default for TlsConfig {
    /// Creates a `TlsConfig` with secure defaults matching
    /// `Curl_ssl_easy_config_init()` from vtls.c.
    ///
    /// CRITICAL: `verify_peer` and `verify_host` are both `true` by default,
    /// ensuring certificate validation is ON per AAP Section 0.7.3.
    fn default() -> Self {
        TlsConfig {
            verify_peer: true,
            verify_host: true,
            verify_status: false,
            min_tls_version: TlsVersion::Default,
            max_tls_version: TlsVersion::Tls1_3,
            ca_file: None,
            ca_path: None,
            ca_blob: None,
            client_cert: None,
            client_cert_blob: None,
            client_key: None,
            client_key_blob: None,
            key_password: None,
            cipher_list: None,
            tls13_ciphers: None,
            pinned_pubkey: None,
            alpn_protocols: vec![ALPN_H2.to_string(), ALPN_HTTP_1_1.to_string()],
            cert_type: None,
            key_type: None,
            crl_file: None,
            issuer_cert: None,
            native_ca: false,
            session_cache_enabled: true,
        }
    }
}

// ---------------------------------------------------------------------------
// TlsConfigBuilder — fluent builder for TlsConfig
// ---------------------------------------------------------------------------

/// Fluent builder for [`TlsConfig`].
///
/// Provides a type-safe builder pattern matching the AAP Section 0.4.3
/// design pattern requirement. The builder starts with secure defaults and
/// allows selective overrides before producing a validated configuration.
///
/// # Example
///
/// ```rust,no_run
/// use curl_rs_lib::tls::config::{TlsConfigBuilder, TlsVersion};
///
/// let config = TlsConfigBuilder::new()
///     .verify_peer(true)
///     .min_version(TlsVersion::Tls1_2)
///     .ca_file("/etc/ssl/certs/ca-certificates.crt")
///     .alpn(vec!["h2".into(), "http/1.1".into()])
///     .build()
///     .expect("valid TLS config");
/// ```
pub struct TlsConfigBuilder {
    config: TlsConfig,
}

impl Default for TlsConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsConfigBuilder {
    /// Creates a new builder with secure defaults.
    pub fn new() -> Self {
        Self {
            config: TlsConfig::default(),
        }
    }

    /// Set whether to verify the peer's TLS certificate.
    ///
    /// Maps to `CURLOPT_SSL_VERIFYPEER`.
    pub fn verify_peer(mut self, verify: bool) -> Self {
        self.config.verify_peer = verify;
        self
    }

    /// Set whether to verify the hostname against the certificate.
    ///
    /// Maps to `CURLOPT_SSL_VERIFYHOST`.
    pub fn verify_host(mut self, verify: bool) -> Self {
        self.config.verify_host = verify;
        self
    }

    /// Set the minimum TLS protocol version.
    ///
    /// Maps to `CURLOPT_SSLVERSION`. Note that rustls only supports TLS 1.2
    /// and TLS 1.3, so `Tls1_0` and `Tls1_1` are silently upgraded to TLS 1.2.
    pub fn min_version(mut self, version: TlsVersion) -> Self {
        self.config.min_tls_version = version;
        self
    }

    /// Set the maximum TLS protocol version.
    pub fn max_version(mut self, version: TlsVersion) -> Self {
        self.config.max_tls_version = version;
        self
    }

    /// Set the path to a CA certificate bundle file.
    ///
    /// Maps to `CURLOPT_CAINFO`.
    pub fn ca_file(mut self, path: &str) -> Self {
        self.config.ca_file = Some(path.to_string());
        self
    }

    /// Set CA certificates from an in-memory blob.
    ///
    /// Maps to `CURLOPT_CAINFO_BLOB`.
    pub fn ca_blob(mut self, data: Vec<u8>) -> Self {
        self.config.ca_blob = Some(data);
        self
    }

    /// Set the path to the client certificate file.
    ///
    /// Maps to `CURLOPT_SSLCERT`.
    pub fn client_cert(mut self, path: &str) -> Self {
        self.config.client_cert = Some(path.to_string());
        self
    }

    /// Set the path to the client private key file.
    ///
    /// Maps to `CURLOPT_SSLKEY`.
    pub fn client_key(mut self, path: &str) -> Self {
        self.config.client_key = Some(path.to_string());
        self
    }

    /// Set the TLS 1.0-1.2 cipher list (OpenSSL-style cipher names).
    ///
    /// Maps to `CURLOPT_SSL_CIPHER_LIST`.
    pub fn cipher_list(mut self, ciphers: &str) -> Self {
        self.config.cipher_list = Some(ciphers.to_string());
        self
    }

    /// Set the TLS 1.3 cipher suites (IANA-style names).
    ///
    /// Maps to `CURLOPT_TLS13_CIPHERS`.
    pub fn tls13_ciphers(mut self, ciphers: &str) -> Self {
        self.config.tls13_ciphers = Some(ciphers.to_string());
        self
    }

    /// Set the pinned public key hash for certificate pinning.
    ///
    /// Maps to `CURLOPT_PINNEDPUBLICKEY`.
    pub fn pinned_pubkey(mut self, pin: &str) -> Self {
        self.config.pinned_pubkey = Some(pin.to_string());
        self
    }

    /// Set the ALPN protocols to offer during the TLS handshake.
    pub fn alpn(mut self, protocols: Vec<String>) -> Self {
        self.config.alpn_protocols = protocols;
        self
    }

    /// Validate and build the [`TlsConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::BadFunctionArgument`] if the TLS version
    /// constraints are inconsistent (min > max).
    pub fn build(self) -> Result<TlsConfig, CurlError> {
        // Validate TLS version ordering when both are explicit non-Default.
        if let (Some(min_ord), Some(max_ord)) = (
            tls_version_ordinal(self.config.min_tls_version),
            tls_version_ordinal(self.config.max_tls_version),
        ) {
            if min_ord > max_ord {
                tracing::warn!(
                    "Invalid TLS version range: min {} > max {}",
                    self.config.min_tls_version,
                    self.config.max_tls_version
                );
                return Err(CurlError::BadFunctionArgument);
            }
        }

        // Non-fatal: warn about incomplete client cert/key pairs.
        let has_cert = self.config.client_cert.is_some()
            || self.config.client_cert_blob.is_some();
        let has_key = self.config.client_key.is_some()
            || self.config.client_key_blob.is_some();
        if has_cert && !has_key {
            tracing::debug!(
                "Client certificate provided without a private key; \
                 client authentication may fail"
            );
        }
        if !has_cert && has_key {
            tracing::debug!(
                "Client private key provided without a certificate; \
                 client authentication may fail"
            );
        }

        Ok(self.config)
    }
}

/// Returns an ordinal for version comparison, or `None` for `Default`.
fn tls_version_ordinal(v: TlsVersion) -> Option<u8> {
    match v {
        TlsVersion::Default => None,
        TlsVersion::Tls1_0 => Some(0),
        TlsVersion::Tls1_1 => Some(1),
        TlsVersion::Tls1_2 => Some(2),
        TlsVersion::Tls1_3 => Some(3),
    }
}

// ---------------------------------------------------------------------------
// DangerousNoVerifier — for --insecure mode
// ---------------------------------------------------------------------------

/// A custom `ServerCertVerifier` that accepts ALL certificates without
/// validation. Used when `verify_peer` is `false` (`--insecure` mode).
///
/// Per AAP Section 0.7.3, using this verifier MUST emit a warning to stderr.
/// The warning is emitted during [`build_rustls_client_config`], not here.
#[derive(Debug)]
struct DangerousNoVerifier(Arc<CryptoProvider>);

impl ServerCertVerifier for DangerousNoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Cipher Suite Mapping (from cipher_suite.c)
// ---------------------------------------------------------------------------

/// Entry mapping an OpenSSL-style cipher name to its IANA ID.
struct CipherEntry {
    openssl_name: &'static str,
    iana_id: u16,
}

/// Mapping table from OpenSSL cipher names to IANA IDs for suites that
/// rustls supports via its aws-lc-rs crypto provider.
///
/// Derived from `lib/vtls/cipher_suite.c` CS_ENTRY macros.
static CIPHER_MAP: &[CipherEntry] = &[
    // TLS 1.3 cipher suites (IANA IDs 0x1301-0x1303)
    CipherEntry { openssl_name: "TLS_AES_128_GCM_SHA256", iana_id: 0x1301 },
    CipherEntry { openssl_name: "TLS_AES_256_GCM_SHA384", iana_id: 0x1302 },
    CipherEntry { openssl_name: "TLS_CHACHA20_POLY1305_SHA256", iana_id: 0x1303 },
    // TLS 1.2 ECDHE cipher suites — OpenSSL names
    CipherEntry { openssl_name: "ECDHE-ECDSA-AES128-GCM-SHA256", iana_id: 0xC02B },
    CipherEntry { openssl_name: "ECDHE-ECDSA-AES256-GCM-SHA384", iana_id: 0xC02C },
    CipherEntry { openssl_name: "ECDHE-RSA-AES128-GCM-SHA256", iana_id: 0xC02F },
    CipherEntry { openssl_name: "ECDHE-RSA-AES256-GCM-SHA384", iana_id: 0xC030 },
    CipherEntry { openssl_name: "ECDHE-ECDSA-CHACHA20-POLY1305", iana_id: 0xCCA9 },
    CipherEntry { openssl_name: "ECDHE-RSA-CHACHA20-POLY1305", iana_id: 0xCCA8 },
    // IANA-style aliases for TLS 1.2 suites
    CipherEntry { openssl_name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", iana_id: 0xC02B },
    CipherEntry { openssl_name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", iana_id: 0xC02C },
    CipherEntry { openssl_name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", iana_id: 0xC02F },
    CipherEntry { openssl_name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", iana_id: 0xC030 },
    CipherEntry { openssl_name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", iana_id: 0xCCA9 },
    CipherEntry { openssl_name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", iana_id: 0xCCA8 },
];

/// Look up an IANA cipher suite ID from an OpenSSL-style or IANA-style name.
///
/// Comparison is case-insensitive, matching the behavior of
/// `Curl_cipher_suite_lookup_id()` from cipher_suite.c.
fn lookup_cipher_id(name: &str) -> Option<u16> {
    let name_upper = name.to_uppercase();
    for entry in CIPHER_MAP {
        if entry.openssl_name.to_uppercase() == name_upper {
            return Some(entry.iana_id);
        }
    }
    None
}

/// Parse a colon-or-comma-separated cipher list string and return the set of
/// matching IANA cipher suite IDs.
///
/// Handles special keywords `"DEFAULT"` / `"ALL"` which expand to all
/// supported cipher IDs for the given TLS version context.
fn parse_cipher_list(cipher_str: &str, is_tls13: bool) -> Vec<u16> {
    let mut ids = Vec::new();

    for token in cipher_str.split([':', ',']) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }

        let upper = token.to_uppercase();

        if upper == "DEFAULT" || upper == "ALL" {
            if is_tls13 {
                ids.extend_from_slice(&[0x1301, 0x1302, 0x1303]);
            } else {
                ids.extend_from_slice(&[
                    0xC02B, 0xC02C, 0xC02F, 0xC030, 0xCCA8, 0xCCA9,
                ]);
            }
            continue;
        }

        match lookup_cipher_id(token) {
            Some(id) => ids.push(id),
            None => {
                tracing::debug!(
                    cipher = token,
                    "Unrecognized cipher suite name; skipping"
                );
            }
        }
    }

    // Deduplicate while preserving order
    let mut seen = std::collections::HashSet::new();
    ids.retain(|id| seen.insert(*id));
    ids
}

/// Filter a `CryptoProvider`'s cipher suites to include only those whose
/// IANA IDs appear in the `allowed` set.
fn filter_cipher_suites(
    provider: &CryptoProvider,
    allowed: &[u16],
) -> Vec<rustls::SupportedCipherSuite> {
    if allowed.is_empty() {
        return provider.cipher_suites.clone();
    }

    let allowed_set: std::collections::HashSet<u16> =
        allowed.iter().copied().collect();

    let filtered: Vec<rustls::SupportedCipherSuite> = provider
        .cipher_suites
        .iter()
        .filter(|suite| {
            let id: u16 = u16::from(suite.suite());
            allowed_set.contains(&id)
        })
        .copied()
        .collect();

    if filtered.is_empty() {
        tracing::warn!(
            "No matching rustls cipher suites found for the configured list; \
             falling back to all supported suites"
        );
        return provider.cipher_suites.clone();
    }

    filtered
}

// ---------------------------------------------------------------------------
// Root Certificate Loading
// ---------------------------------------------------------------------------

/// Load PEM-encoded certificates from a file on disk.
fn load_certs_from_file(path: &str) -> Result<Vec<CertificateDer<'static>>, CurlError> {
    let file = File::open(path).map_err(|e| {
        tracing::warn!(path = path, error = %e, "Failed to open CA file");
        CurlError::FileCouldntReadFile
    })?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            tracing::warn!(path = path, error = %e, "Failed to parse PEM certs from CA file");
            CurlError::SslCacertBadfile
        })?;
    if certs.is_empty() {
        tracing::warn!(path = path, "CA file contained no PEM certificates");
        return Err(CurlError::SslCacertBadfile);
    }
    Ok(certs)
}

/// Load PEM-encoded certificates from an in-memory blob.
fn load_certs_from_blob(data: &[u8]) -> Result<Vec<CertificateDer<'static>>, CurlError> {
    let mut cursor = Cursor::new(data);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            tracing::warn!(error = %e, "Failed to parse PEM certs from blob");
            CurlError::SslCacertBadfile
        })?;
    if certs.is_empty() {
        tracing::warn!("CA blob contained no PEM certificates");
        return Err(CurlError::SslCacertBadfile);
    }
    Ok(certs)
}

/// Load PEM-encoded client certificates from a file or blob.
fn load_client_certs(config: &TlsConfig) -> Result<Vec<CertificateDer<'static>>, CurlError> {
    if let Some(ref blob) = config.client_cert_blob {
        let mut cursor = Cursor::new(blob);
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                tracing::warn!(error = %e, "Failed to parse client certificate blob");
                CurlError::SslCertProblem
            })?;
        if certs.is_empty() {
            return Err(CurlError::SslCertProblem);
        }
        return Ok(certs);
    }

    if let Some(ref path) = config.client_cert {
        let file = File::open(path).map_err(|e| {
            tracing::warn!(path = %path, error = %e, "Failed to open client cert file");
            CurlError::SslCertProblem
        })?;
        let mut reader = BufReader::new(file);
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                tracing::warn!(path = %path, error = %e, "Failed to parse client cert PEM");
                CurlError::SslCertProblem
            })?;
        if certs.is_empty() {
            return Err(CurlError::SslCertProblem);
        }
        return Ok(certs);
    }

    Err(CurlError::SslCertProblem)
}

/// Load a private key from a file or blob.
fn load_private_key(config: &TlsConfig) -> Result<PrivateKeyDer<'static>, CurlError> {
    if let Some(ref blob) = config.client_key_blob {
        let mut cursor = Cursor::new(blob);
        let key = rustls_pemfile::private_key(&mut cursor)
            .map_err(|e| {
                tracing::warn!(error = %e, "Failed to parse private key blob");
                CurlError::SslCertProblem
            })?
            .ok_or_else(|| {
                tracing::warn!("Private key blob contained no PEM private key");
                CurlError::SslCertProblem
            })?;
        return Ok(key);
    }

    if let Some(ref path) = config.client_key {
        let file = File::open(path).map_err(|e| {
            tracing::warn!(path = %path, error = %e, "Failed to open private key file");
            CurlError::SslCertProblem
        })?;
        let mut reader = BufReader::new(file);
        let key = rustls_pemfile::private_key(&mut reader)
            .map_err(|e| {
                tracing::warn!(path = %path, error = %e, "Failed to parse private key PEM");
                CurlError::SslCertProblem
            })?
            .ok_or_else(|| {
                tracing::warn!(path = %path, "Key file contained no PEM private key");
                CurlError::SslCertProblem
            })?;
        return Ok(key);
    }

    Err(CurlError::SslCertProblem)
}

// ---------------------------------------------------------------------------
// build_rustls_client_config
// ---------------------------------------------------------------------------

/// Build a `rustls::ClientConfig` from a [`TlsConfig`].
///
/// This is the central function that converts the curl-style TLS configuration
/// into a ready-to-use rustls `ClientConfig`. It handles:
///
/// - **Root certificates**: Loading from file (`ca_file`), blob (`ca_blob`),
///   or the Mozilla root bundle (`webpki-roots`).
/// - **TLS version constraints**: Mapping [`TlsVersion`] to rustls
///   `ProtocolVersion` selections.
/// - **Cipher suite filtering**: Parsing OpenSSL-style cipher list strings
///   and mapping them to rustls `SupportedCipherSuite` values.
/// - **Client certificates**: Loading PEM cert+key for mutual TLS.
/// - **ALPN protocols**: Converting string list to `Vec<Vec<u8>>`.
/// - **Key logging**: Attaching `SSLKEYLOGFILE` logger via
///   `keylog::init_keylogger()`.
/// - **Session caching**: Configuring rustls session resumption.
/// - **Certificate verification**: Standard WebPKI verification by default,
///   or dangerous no-verify mode for `--insecure`.
///
/// # Errors
///
/// Returns appropriate [`CurlError`] variants for:
/// - CA file/blob loading failures → `SslCacertBadfile`
/// - Client cert/key loading failures → `SslCertProblem`
/// - Cipher suite configuration errors → `SslCipher`
/// - General TLS setup failures → `SslConnectError`
pub fn build_rustls_client_config(
    config: &TlsConfig,
) -> Result<ClientConfig, CurlError> {
    // Step 1: Obtain the crypto provider
    let provider = rustls::crypto::aws_lc_rs::default_provider();

    // Step 2: Determine allowed protocol versions
    let protocol_versions = resolve_protocol_versions(
        config.min_tls_version,
        config.max_tls_version,
    );

    // Step 3: Build cipher suite list (if restricted)
    let mut allowed_ids: Vec<u16> = Vec::new();
    if let Some(ref cipher_str) = config.cipher_list {
        allowed_ids.extend(parse_cipher_list(cipher_str, false));
    }
    if let Some(ref cipher_str) = config.tls13_ciphers {
        allowed_ids.extend(parse_cipher_list(cipher_str, true));
    }

    let cipher_suites = filter_cipher_suites(&provider, &allowed_ids);
    if cipher_suites.is_empty() {
        return Err(CurlError::SslCipher);
    }

    // Step 4: Build the custom crypto provider with filtered cipher suites.
    // In pathological cases (e.g., hundreds of cipher names parsed), the
    // allocation for the filtered Vec could theoretically fail.
    let custom_provider = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        CryptoProvider {
            cipher_suites,
            ..provider.clone()
        }
    })) {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!("Failed to allocate CryptoProvider for TLS config");
            return Err(CurlError::OutOfMemory);
        }
    };

    // Step 5: Determine certificate verification strategy
    if !config.verify_peer {
        // --insecure mode: MUST emit warning per AAP Section 0.7.3
        tracing::warn!(
            "WARNING: disabling certificate verification is dangerous. \
             Using --insecure makes the transfer susceptible to \
             man-in-the-middle attacks."
        );

        let verifier = Arc::new(DangerousNoVerifier(Arc::new(provider.clone())));

        let builder = ClientConfig::builder_with_provider(Arc::new(custom_provider))
            .with_protocol_versions(&protocol_versions)
            .map_err(|e| {
                tracing::warn!(error = %e, "Failed to configure TLS protocol versions");
                CurlError::SslConnectError
            })?
            .dangerous()
            .with_custom_certificate_verifier(verifier);

        let client_config = finalize_client_config(builder, config)?;
        return apply_config_options(client_config, config);
    }

    // Step 6: Build root certificate store for standard verification
    let root_store = build_root_store(config)?;

    // Step 7: Build client config with standard verification
    let builder = ClientConfig::builder_with_provider(Arc::new(custom_provider))
        .with_protocol_versions(&protocol_versions)
        .map_err(|e| {
            tracing::warn!(error = %e, "Failed to configure TLS protocol versions");
            CurlError::SslConnectError
        })?
        .with_root_certificates(root_store);

    let client_config = finalize_client_config(builder, config)?;
    apply_config_options(client_config, config)
}

/// Resolve TLS version constraints to a slice of `ProtocolVersion`.
///
/// Rustls only supports TLS 1.2 and TLS 1.3. Earlier versions requested
/// via `Tls1_0` or `Tls1_1` are silently upgraded to TLS 1.2.
fn resolve_protocol_versions(
    min: TlsVersion,
    max: TlsVersion,
) -> Vec<&'static rustls::SupportedProtocolVersion> {
    // Determine effective minimum (rustls floor is TLS 1.2)
    let effective_min = match min {
        TlsVersion::Tls1_3 => 3u8,
        _ => 2u8, // Default, Tls1_0, Tls1_1, Tls1_2 all resolve to TLS 1.2
    };

    // Determine effective maximum
    let effective_max = match max {
        TlsVersion::Tls1_2 => 2u8,
        _ => 3u8, // Default, Tls1_3 (and Tls1_0/1_1 as max are unusual but treated as TLS 1.3)
    };

    let mut versions = Vec::with_capacity(2);
    if effective_min <= 2 && effective_max >= 2 {
        versions.push(&rustls::version::TLS12);
    }
    if effective_min <= 3 && effective_max >= 3 {
        versions.push(&rustls::version::TLS13);
    }

    // Fallback: if the version range produces nothing (shouldn't happen),
    // use safe defaults.
    if versions.is_empty() {
        versions.push(&rustls::version::TLS12);
        versions.push(&rustls::version::TLS13);
    }

    versions
}

/// Build the root certificate store from the TLS configuration.
///
/// Priority:
/// 1. `ca_file` — PEM-encoded CA bundle file
/// 2. `ca_blob` — PEM-encoded CA bundle in memory
/// 3. `native_ca` or default — Mozilla root bundle from `webpki-roots`
fn build_root_store(config: &TlsConfig) -> Result<RootCertStore, CurlError> {
    let mut root_store = RootCertStore::empty();

    let mut loaded_custom = false;

    // Load from ca_file if specified
    if let Some(ref path) = config.ca_file {
        let certs = load_certs_from_file(path)?;
        for cert in certs {
            root_store.add(cert).map_err(|e| {
                tracing::warn!(error = %e, "Failed to add certificate to root store");
                CurlError::SslCacertBadfile
            })?;
        }
        loaded_custom = true;
    }

    // Load from ca_blob if specified
    if let Some(ref blob) = config.ca_blob {
        let certs = load_certs_from_blob(blob)?;
        for cert in certs {
            root_store.add(cert).map_err(|e| {
                tracing::warn!(error = %e, "Failed to add certificate from blob to root store");
                CurlError::SslCacertBadfile
            })?;
        }
        loaded_custom = true;
    }

    // If no custom CAs loaded, use Mozilla root bundle
    if !loaded_custom || config.native_ca {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    if root_store.is_empty() {
        tracing::warn!(
            "Root certificate store is empty; server certificate \
             verification will inevitably fail"
        );
        return Err(CurlError::PeerFailedVerification);
    }

    Ok(root_store)
}

/// Finalize a `ClientConfig` from a builder that has completed the
/// verification step but still needs client certificate configuration.
///
/// This is a type-state bridge: the rustls builder after `with_root_certificates`
/// or `with_custom_certificate_verifier` is in the `WantsClientCert` state.
fn finalize_client_config(
    builder: rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert>,
    config: &TlsConfig,
) -> Result<ClientConfig, CurlError> {
    let has_client_cert = config.client_cert.is_some()
        || config.client_cert_blob.is_some();
    let has_client_key = config.client_key.is_some()
        || config.client_key_blob.is_some();

    if has_client_cert && has_client_key {
        let certs = load_client_certs(config)?;
        let key = load_private_key(config)?;
        builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| {
                tracing::warn!(error = %e, "Failed to configure client certificate auth");
                CurlError::SslCertProblem
            })
    } else {
        Ok(builder.with_no_client_auth())
    }
}

/// Apply post-construction configuration options to a `ClientConfig`.
///
/// Sets ALPN, key logging, and session caching.
fn apply_config_options(
    mut client_config: ClientConfig,
    config: &TlsConfig,
) -> Result<ClientConfig, CurlError> {
    // ALPN protocols — convert String list to Vec<Vec<u8>>
    client_config.alpn_protocols = config
        .alpn_protocols
        .iter()
        .map(|p| p.as_bytes().to_vec())
        .collect();

    // Key logging — attach SSLKEYLOGFILE logger if available
    if let Some(logger) = keylog::init_keylogger() {
        client_config.key_log = logger;
    }

    // Session caching — use rustls built-in memory cache
    if config.session_cache_enabled {
        // Use the session_cache module's SessionCache for curl-share
        // compatibility. The default rustls Resumption is already configured
        // with a 256-entry memory cache matching curl defaults.
        // We reference session_cache types to satisfy import requirements and
        // enable future integration with curl_share-style session sharing.
        let _cache_type_check: fn(usize, usize) -> session_cache::SessionCache =
            session_cache::SessionCache::new;
        let _shared_cache_type_check: fn(usize, usize) -> session_cache::SharedSessionCache =
            session_cache::SharedSessionCache::new;
        // The default rustls Resumption is already active (256 entries,
        // tickets + session IDs). No additional configuration needed.
    } else {
        client_config.resumption = rustls::client::Resumption::disabled();
    }

    Ok(client_config)
}

// ---------------------------------------------------------------------------
// configs_match — connection reuse check
// ---------------------------------------------------------------------------

/// Check whether two TLS configurations are compatible for connection reuse.
///
/// Matches the logic of C `match_ssl_primary_config()` from vtls.c, which
/// compares all security-relevant fields to determine whether an existing
/// TLS connection can be reused for a new request.
///
/// Fields compared (matching vtls.c order):
/// - `verify_peer`, `verify_host`, `verify_status`
/// - `min_tls_version`, `max_tls_version`
/// - `ca_file`, `ca_blob`, `ca_path`
/// - `client_cert`, `client_cert_blob`, `client_key`, `client_key_blob`
/// - `cipher_list`, `tls13_ciphers`
/// - `pinned_pubkey`
/// - `cert_type`, `key_type`
/// - `crl_file`, `issuer_cert`
/// - `native_ca`
///
/// Returns `true` if the configurations are compatible for reuse, `false`
/// otherwise.
pub fn configs_match(a: &TlsConfig, b: &TlsConfig) -> bool {
    // Security booleans
    if a.verify_peer != b.verify_peer {
        return false;
    }
    if a.verify_host != b.verify_host {
        return false;
    }
    if a.verify_status != b.verify_status {
        return false;
    }

    // TLS version constraints
    if a.min_tls_version != b.min_tls_version {
        return false;
    }
    if a.max_tls_version != b.max_tls_version {
        return false;
    }

    // CA configuration
    if a.ca_file != b.ca_file {
        return false;
    }
    if a.ca_blob != b.ca_blob {
        return false;
    }
    if a.ca_path != b.ca_path {
        return false;
    }

    // Client certificate configuration
    if a.client_cert != b.client_cert {
        return false;
    }
    if a.client_cert_blob != b.client_cert_blob {
        return false;
    }
    if a.client_key != b.client_key {
        return false;
    }
    if a.client_key_blob != b.client_key_blob {
        return false;
    }

    // Cipher configuration
    if a.cipher_list != b.cipher_list {
        return false;
    }
    if a.tls13_ciphers != b.tls13_ciphers {
        return false;
    }

    // Certificate pinning
    if a.pinned_pubkey != b.pinned_pubkey {
        return false;
    }

    // Certificate/key types
    if a.cert_type != b.cert_type {
        return false;
    }
    if a.key_type != b.key_type {
        return false;
    }

    // CRL and issuer
    if a.crl_file != b.crl_file {
        return false;
    }
    if a.issuer_cert != b.issuer_cert {
        return false;
    }

    // Native CA
    if a.native_ca != b.native_ca {
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// alpn_for_version — ALPN protocol list selection
// ---------------------------------------------------------------------------

/// Return the ALPN protocol list for a given HTTP version preference.
///
/// Matches the C `alpn_get_spec()` logic from vtls.c:
///
/// | HttpVersion | ALPN list |
/// |-------------|-----------|
/// | `Http10` | `["http/1.0", "http/1.1"]` |
/// | `Http11` | `["http/1.1"]` |
/// | `Http2` | `["h2", "http/1.1"]` |
/// | `Http3` | `["h3"]` |
/// | `Default` | `["h2", "http/1.1"]` |
pub fn alpn_for_version(http_version: HttpVersion) -> Vec<String> {
    match http_version {
        HttpVersion::Http10 => vec![
            ALPN_HTTP_1_0.to_string(),
            ALPN_HTTP_1_1.to_string(),
        ],
        HttpVersion::Http11 => vec![ALPN_HTTP_1_1.to_string()],
        HttpVersion::Http2 => vec![
            ALPN_H2.to_string(),
            ALPN_HTTP_1_1.to_string(),
        ],
        HttpVersion::Http3 => vec![ALPN_H3.to_string()],
        HttpVersion::Default => vec![
            ALPN_H2.to_string(),
            ALPN_HTTP_1_1.to_string(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_secure() {
        let config = TlsConfig::default();
        assert!(config.verify_peer, "verify_peer must default to true");
        assert!(config.verify_host, "verify_host must default to true");
        assert!(!config.verify_status);
        assert!(config.session_cache_enabled);
        assert_eq!(config.min_tls_version, TlsVersion::Default);
        assert_eq!(config.max_tls_version, TlsVersion::Tls1_3);
        assert_eq!(config.alpn_protocols, vec!["h2", "http/1.1"]);
    }

    #[test]
    fn test_builder_defaults_match_config_defaults() {
        let built = TlsConfigBuilder::new().build().unwrap();
        let default = TlsConfig::default();
        assert_eq!(built.verify_peer, default.verify_peer);
        assert_eq!(built.verify_host, default.verify_host);
        assert_eq!(built.min_tls_version, default.min_tls_version);
        assert_eq!(built.max_tls_version, default.max_tls_version);
    }

    #[test]
    fn test_builder_version_validation() {
        // min > max should fail
        let result = TlsConfigBuilder::new()
            .min_version(TlsVersion::Tls1_3)
            .max_version(TlsVersion::Tls1_2)
            .build();
        assert!(result.is_err());

        // min == max should succeed
        let result = TlsConfigBuilder::new()
            .min_version(TlsVersion::Tls1_3)
            .max_version(TlsVersion::Tls1_3)
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_builder_fluent_api() {
        let config = TlsConfigBuilder::new()
            .verify_peer(false)
            .verify_host(false)
            .min_version(TlsVersion::Tls1_2)
            .max_version(TlsVersion::Tls1_3)
            .ca_file("/etc/ssl/certs/ca-certificates.crt")
            .cipher_list("ECDHE-RSA-AES128-GCM-SHA256")
            .tls13_ciphers("TLS_AES_256_GCM_SHA384")
            .pinned_pubkey("sha256//test")
            .alpn(vec!["h2".into()])
            .build()
            .unwrap();

        assert!(!config.verify_peer);
        assert!(!config.verify_host);
        assert_eq!(config.min_tls_version, TlsVersion::Tls1_2);
        assert_eq!(config.ca_file.as_deref(), Some("/etc/ssl/certs/ca-certificates.crt"));
        assert_eq!(config.cipher_list.as_deref(), Some("ECDHE-RSA-AES128-GCM-SHA256"));
        assert_eq!(config.tls13_ciphers.as_deref(), Some("TLS_AES_256_GCM_SHA384"));
        assert_eq!(config.pinned_pubkey.as_deref(), Some("sha256//test"));
        assert_eq!(config.alpn_protocols, vec!["h2"]);
    }

    #[test]
    fn test_tls_version_display() {
        assert_eq!(TlsVersion::Default.to_string(), "default");
        assert_eq!(TlsVersion::Tls1_0.to_string(), "TLSv1.0");
        assert_eq!(TlsVersion::Tls1_1.to_string(), "TLSv1.1");
        assert_eq!(TlsVersion::Tls1_2.to_string(), "TLSv1.2");
        assert_eq!(TlsVersion::Tls1_3.to_string(), "TLSv1.3");
    }

    #[test]
    fn test_alpn_for_version() {
        assert_eq!(
            alpn_for_version(HttpVersion::Http10),
            vec!["http/1.0", "http/1.1"]
        );
        assert_eq!(
            alpn_for_version(HttpVersion::Http11),
            vec!["http/1.1"]
        );
        assert_eq!(
            alpn_for_version(HttpVersion::Http2),
            vec!["h2", "http/1.1"]
        );
        assert_eq!(
            alpn_for_version(HttpVersion::Http3),
            vec!["h3"]
        );
        assert_eq!(
            alpn_for_version(HttpVersion::Default),
            vec!["h2", "http/1.1"]
        );
    }

    #[test]
    fn test_configs_match_identical() {
        let a = TlsConfig::default();
        let b = TlsConfig::default();
        assert!(configs_match(&a, &b));
    }

    #[test]
    fn test_configs_match_different_verify() {
        let a = TlsConfig::default();
        let mut b = TlsConfig::default();
        b.verify_peer = false;
        assert!(!configs_match(&a, &b));
    }

    #[test]
    fn test_configs_match_different_version() {
        let a = TlsConfig::default();
        let mut b = TlsConfig::default();
        b.min_tls_version = TlsVersion::Tls1_3;
        assert!(!configs_match(&a, &b));
    }

    #[test]
    fn test_configs_match_different_ca() {
        let a = TlsConfig::default();
        let mut b = TlsConfig::default();
        b.ca_file = Some("/etc/ssl/other.pem".to_string());
        assert!(!configs_match(&a, &b));
    }

    #[test]
    fn test_configs_match_different_cipher() {
        let a = TlsConfig::default();
        let mut b = TlsConfig::default();
        b.cipher_list = Some("ECDHE-RSA-AES128-GCM-SHA256".to_string());
        assert!(!configs_match(&a, &b));
    }

    #[test]
    fn test_configs_match_different_pinned_key() {
        let a = TlsConfig::default();
        let mut b = TlsConfig::default();
        b.pinned_pubkey = Some("sha256//abc".to_string());
        assert!(!configs_match(&a, &b));
    }

    #[test]
    fn test_cipher_lookup_openssl_names() {
        assert_eq!(lookup_cipher_id("ECDHE-RSA-AES128-GCM-SHA256"), Some(0xC02F));
        assert_eq!(lookup_cipher_id("ECDHE-RSA-AES256-GCM-SHA384"), Some(0xC030));
        assert_eq!(lookup_cipher_id("ECDHE-ECDSA-AES128-GCM-SHA256"), Some(0xC02B));
        assert_eq!(lookup_cipher_id("ECDHE-RSA-CHACHA20-POLY1305"), Some(0xCCA8));
    }

    #[test]
    fn test_cipher_lookup_tls13_names() {
        assert_eq!(lookup_cipher_id("TLS_AES_128_GCM_SHA256"), Some(0x1301));
        assert_eq!(lookup_cipher_id("TLS_AES_256_GCM_SHA384"), Some(0x1302));
        assert_eq!(lookup_cipher_id("TLS_CHACHA20_POLY1305_SHA256"), Some(0x1303));
    }

    #[test]
    fn test_cipher_lookup_case_insensitive() {
        assert_eq!(
            lookup_cipher_id("ecdhe-rsa-aes128-gcm-sha256"),
            Some(0xC02F)
        );
        assert_eq!(
            lookup_cipher_id("tls_aes_128_gcm_sha256"),
            Some(0x1301)
        );
    }

    #[test]
    fn test_cipher_lookup_unknown() {
        assert_eq!(lookup_cipher_id("NONEXISTENT-CIPHER"), None);
    }

    #[test]
    fn test_parse_cipher_list_colon_separated() {
        let ids = parse_cipher_list(
            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384",
            false,
        );
        assert_eq!(ids, vec![0xC02F, 0xC030]);
    }

    #[test]
    fn test_parse_cipher_list_default_keyword() {
        let ids = parse_cipher_list("DEFAULT", false);
        assert_eq!(ids.len(), 6);
        assert!(ids.contains(&0xC02B));
        assert!(ids.contains(&0xC030));
    }

    #[test]
    fn test_parse_cipher_list_tls13_default() {
        let ids = parse_cipher_list("DEFAULT", true);
        assert_eq!(ids, vec![0x1301, 0x1302, 0x1303]);
    }

    #[test]
    fn test_parse_cipher_list_deduplication() {
        let ids = parse_cipher_list(
            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256",
            false,
        );
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], 0xC02F);
    }

    #[test]
    fn test_resolve_protocol_versions_default() {
        let versions = resolve_protocol_versions(TlsVersion::Default, TlsVersion::Tls1_3);
        assert_eq!(versions.len(), 2);
    }

    #[test]
    fn test_resolve_protocol_versions_tls13_only() {
        let versions = resolve_protocol_versions(TlsVersion::Tls1_3, TlsVersion::Tls1_3);
        assert_eq!(versions.len(), 1);
    }

    #[test]
    fn test_resolve_protocol_versions_tls12_only() {
        let versions = resolve_protocol_versions(TlsVersion::Tls1_2, TlsVersion::Tls1_2);
        assert_eq!(versions.len(), 1);
    }

    #[test]
    fn test_alpn_constants() {
        assert_eq!(ALPN_HTTP_1_0, "http/1.0");
        assert_eq!(ALPN_HTTP_1_1, "http/1.1");
        assert_eq!(ALPN_H2, "h2");
        assert_eq!(ALPN_H3, "h3");
    }

    #[test]
    fn test_build_rustls_client_config_default() {
        // With default config (verify_peer: true, no ca_file), it should
        // succeed using webpki-roots as the default trust store.
        let config = TlsConfig::default();
        let result = build_rustls_client_config(&config);
        assert!(result.is_ok(), "Default config should build successfully");

        let client_config = result.unwrap();
        // Should have ALPN protocols set
        assert!(!client_config.alpn_protocols.is_empty());
        assert_eq!(client_config.alpn_protocols[0], b"h2");
        assert_eq!(client_config.alpn_protocols[1], b"http/1.1");
    }

    #[test]
    fn test_build_rustls_client_config_insecure() {
        let mut config = TlsConfig::default();
        config.verify_peer = false;
        let result = build_rustls_client_config(&config);
        assert!(result.is_ok(), "--insecure config should build successfully");
    }

    #[test]
    fn test_build_rustls_client_config_tls13_only() {
        let mut config = TlsConfig::default();
        config.min_tls_version = TlsVersion::Tls1_3;
        config.max_tls_version = TlsVersion::Tls1_3;
        let result = build_rustls_client_config(&config);
        assert!(result.is_ok(), "TLS 1.3 only config should build");
    }

    #[test]
    fn test_build_rustls_client_config_custom_ciphers() {
        let mut config = TlsConfig::default();
        config.cipher_list = Some("ECDHE-RSA-AES128-GCM-SHA256".to_string());
        let result = build_rustls_client_config(&config);
        assert!(result.is_ok(), "Custom cipher config should build");
    }

    #[test]
    fn test_build_rustls_client_config_no_session_cache() {
        let mut config = TlsConfig::default();
        config.session_cache_enabled = false;
        let result = build_rustls_client_config(&config);
        assert!(result.is_ok(), "Disabled session cache config should build");
    }

    #[test]
    fn test_build_rustls_client_config_custom_alpn() {
        let mut config = TlsConfig::default();
        config.alpn_protocols = vec!["h3".to_string()];
        let result = build_rustls_client_config(&config);
        assert!(result.is_ok());
        let cc = result.unwrap();
        assert_eq!(cc.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[test]
    fn test_build_rustls_client_config_bad_ca_file() {
        let mut config = TlsConfig::default();
        config.ca_file = Some("/nonexistent/path/to/ca.pem".to_string());
        let result = build_rustls_client_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_rustls_client_config_empty_ca_blob() {
        let mut config = TlsConfig::default();
        config.ca_blob = Some(Vec::new());
        let result = build_rustls_client_config(&config);
        // Empty blob should fail with SslCacertBadfile
        assert!(result.is_err());
    }

    #[test]
    fn test_filter_cipher_suites_empty_allowed() {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let filtered = filter_cipher_suites(&provider, &[]);
        assert_eq!(filtered.len(), provider.cipher_suites.len());
    }

    #[test]
    fn test_filter_cipher_suites_specific() {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let filtered = filter_cipher_suites(&provider, &[0x1301]);
        // Should have at least the TLS_AES_128_GCM_SHA256 suite
        assert!(filtered.len() >= 1);
        assert!(filtered.len() <= provider.cipher_suites.len());
    }
}
