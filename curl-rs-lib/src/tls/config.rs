// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! # `rustls::ClientConfig` construction from curl's SSL option surface
//!
//! This module is a language rewrite of curl 8.19.0-DEV's *SSL primary
//! configuration* — the option-handling half of `lib/vtls/` — collapsed onto a
//! single, always-compiled [`rustls`] backend. Where the C code selected among
//! seven TLS backends via `#ifdef` and threaded a `struct ssl_primary_config`
//! plus `struct ssl_config_data` through each of them, this module gathers the
//! same option surface into one [`TlsConfig`] value and turns it into an
//! [`Arc<rustls::ClientConfig>`] ready for use with `tokio-rustls`.
//!
//! The C source-of-truth references are:
//!
//! * `lib/vtls/vtls.c` — the shared abstraction and the verify defaults
//!   (`data->set.ssl.primary.verifypeer = TRUE;` /
//!   `data->set.ssl.primary.verifyhost = TRUE;`).
//! * `lib/vtls/rustls.c` — the existing curl→rustls glue: cipher-list parsing
//!   (`cr_get_selected_ciphers`), the always-OK `--insecure` verifier
//!   (`cr_verify_none`), the `CURL_SSLVERSION_*` → rustls version mapping, and
//!   `map_error` (rustls → `CURLcode`).
//! * `lib/vtls/cipher_suite.c` — cipher-suite name tokenization
//!   (`Curl_cipher_suite_walk_str`) and the TLS 1.2 / TLS 1.3 split.
//!
//! ## The two non-negotiable parity properties
//!
//! 1. **Certificate validation is ON by default.** [`TlsConfig::default`] sets
//!    both [`TlsConfig::verify_peer`] and [`TlsConfig::verify_host`] to `true`
//!    (curl's `SSL_VERIFYPEER=1` / `SSL_VERIFYHOST=2`). This is a
//!    merge-blocking invariant (AAP §0.6.4 TLS-configuration audit).
//! 2. **`--insecure` warns before proceeding.** When `verify_peer` is `false`,
//!    [`TlsConfig::build`] writes a warning to **stderr first** and only then
//!    installs the accept-all [`ServerCertVerifier`], mirroring curl's
//!    warning-before-connect ordering.
//!
//! ## Memory safety
//!
//! The whole TLS subtree is a flagship *zero-`unsafe`* zone: the crate root
//! declares `#![forbid(unsafe_code)]`, and this module contains no `unsafe`
//! blocks whatsoever. The accept-all verifier is *dangerous* in the TLS sense
//! (it disables authentication) but is written entirely in safe Rust.
//!
//! ## Relationship to the sibling TLS modules
//!
//! This module composes the other pieces of the `tls` subtree into the final
//! configuration:
//!
//! * Hostname verification for the standard secure path is performed by
//!   rustls' [`WebPkiServerVerifier`] (RFC 6125), which subsumes the helpers in
//!   [`super::hostname`]; those helpers are consulted directly by the
//!   connection layer for the manual-identity paths layered on top of the
//!   config produced here.
//! * TLS session resumption is backed by [`super::session_cache::SessionCache`]
//!   (installed on [`rustls::ClientConfig::resumption`]).
//! * `SSLKEYLOGFILE` key-material logging is provided by [`super::keylog`]
//!   (installed on [`rustls::ClientConfig::key_log`]).
//!
//! [`WebPkiServerVerifier`]: rustls::client::WebPkiServerVerifier

use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::Resumption;
use rustls::crypto::CryptoProvider;
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme, SupportedProtocolVersion,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

use crate::error::{CurlCode, Error, Result};

use super::keylog;
use super::session_cache::SessionCache;

/// The stderr warning emitted before an insecure (`verify_peer == false`)
/// configuration is built, mirroring curl's warning-before-connect behavior
/// for `--insecure` / `CURLOPT_SSL_VERIFYPEER == 0`.
///
/// Exposed as a constant so tests can assert on the exact text without having
/// to capture the process's standard error stream.
pub const INSECURE_WARNING: &str =
    "Warning: TLS certificate verification is disabled (--insecure / \
     CURLOPT_SSL_VERIFYPEER=0); the identity of the server cannot be verified.";

/// TLS protocol version selector, mirroring curl's `CURL_SSLVERSION_*`
/// (minimum) and `CURL_SSLVERSION_MAX_*` (maximum) option values.
///
/// A single enum serves for both the minimum ([`TlsConfig::version_min`]) and
/// maximum ([`TlsConfig::version_max`]) bounds. [`TlsVersion::Default`] means
/// "unset" — curl's `CURL_SSLVERSION_DEFAULT` / `CURL_SSLVERSION_MAX_DEFAULT` —
/// and defers to the backend's own floor and ceiling.
///
/// Note that the single [`rustls`] backend supports **only** TLS 1.2 and
/// TLS 1.3. As in `lib/vtls/rustls.c`, a requested minimum of TLS 1.0 or
/// TLS 1.1 is silently raised to the TLS 1.2 floor, and a requested maximum
/// below TLS 1.2 is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TlsVersion {
    /// `CURL_SSLVERSION_DEFAULT` — no explicit bound; use the backend default.
    #[default]
    Default,
    /// `CURL_SSLVERSION_TLSv1_0` — TLS 1.0 (raised to the TLS 1.2 floor by the
    /// rustls backend).
    Tlsv1_0,
    /// `CURL_SSLVERSION_TLSv1_1` — TLS 1.1 (raised to the TLS 1.2 floor by the
    /// rustls backend).
    Tlsv1_1,
    /// `CURL_SSLVERSION_TLSv1_2` — TLS 1.2.
    Tlsv1_2,
    /// `CURL_SSLVERSION_TLSv1_3` — TLS 1.3.
    Tlsv1_3,
}

/// The curl SSL "primary configuration" collapsed onto the single [`rustls`]
/// backend.
///
/// [`TlsConfig`] mirrors the union of curl's `struct ssl_primary_config` and
/// the relevant `struct ssl_config_data` fields (`lib/urldata.h`). Each field
/// corresponds to a `CURLOPT_*` / `CURLSSLOPT_*` option; the doc comment names
/// the option it reproduces. [`TlsConfig::build`] turns these options into an
/// [`Arc<rustls::ClientConfig>`].
///
/// # Defaults
///
/// [`TlsConfig::default`] reproduces curl 8.x's defaults, the most important
/// of which is that **both** peer and host verification are **enabled**.
/// Construct the "insecure" configuration explicitly via
/// [`TlsConfig::insecure`].
///
/// # Examples
///
/// This example is marked `no_run`: [`TlsConfig::build`] initializes the
/// `rustls` crypto provider (`aws-lc-rs`), whose one-time `CRYPTO_library_init`
/// is a foreign function that Miri's interpreter cannot execute. As with the
/// other environment-dependent examples in this crate (e.g.
/// [`crate::dns::system::SystemResolver`]), the snippet is compiled to verify
/// it stays valid against the public API but is not executed; the `build()`
/// behaviour it demonstrates is exercised natively by the unit tests.
///
/// ```no_run
/// use curl_rs_lib::tls::config::TlsConfig;
///
/// // Secure by default: certificate validation is on.
/// let cfg = TlsConfig::default();
/// assert!(cfg.verify_peer);
/// assert!(cfg.verify_host);
///
/// // Opt into HTTP/2 + HTTP/1.1 ALPN and build the rustls client config.
/// let cfg = TlsConfig::default().with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
/// let client_config = cfg.build().expect("default config builds");
/// assert_eq!(client_config.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
/// ```
#[derive(Debug, Clone)]
pub struct TlsConfig {
    // --- Verification policy -------------------------------------------------
    /// `CURLOPT_SSL_VERIFYPEER` — verify the server's certificate chain against
    /// the trust anchors. **Default `true`.** When `false`, [`TlsConfig::build`]
    /// emits [`INSECURE_WARNING`] to stderr and installs an accept-all
    /// verifier.
    pub verify_peer: bool,
    /// `CURLOPT_SSL_VERIFYHOST` — verify that the certificate matches the
    /// requested host name (curl's `VERIFYHOST == 2`). **Default `true`.** For
    /// the standard secure path the check is performed by rustls'
    /// `WebPkiServerVerifier`.
    pub verify_host: bool,
    /// `CURLOPT_SSL_VERIFYSTATUS` — require a "good" stapled OCSP response.
    /// **Default `false`.** Stored for curl surface parity.
    pub verify_status: bool,

    // --- Certificate-authority sources --------------------------------------
    /// `CURLOPT_CAINFO` — path to a PEM bundle of trust anchors.
    pub ca_info: Option<PathBuf>,
    /// `CURLOPT_CAPATH` — path to a directory of PEM trust-anchor files.
    pub ca_path: Option<PathBuf>,
    /// `CURLOPT_CAINFO_BLOB` — in-memory PEM bundle of trust anchors.
    pub ca_info_blob: Option<Vec<u8>>,
    /// Whether to fall back to the built-in Mozilla root store
    /// ([`webpki_roots`]) when no explicit CA source is configured. **Default
    /// `true`**, mirroring curl's built-in / native-store fallback.
    pub use_webpki_roots: bool,

    // --- Client authentication ----------------------------------------------
    /// `CURLOPT_SSLCERT` — path to the client certificate (PEM).
    pub client_cert: Option<PathBuf>,
    /// `CURLOPT_SSLKEY` — path to the client private key (PEM). When `None` and
    /// [`TlsConfig::client_cert`] is set, the key is read from the certificate
    /// file.
    pub client_key: Option<PathBuf>,
    /// `CURLOPT_KEYPASSWD` — passphrase for an encrypted client key. See
    /// [`TlsConfig::load_client_auth`] for the supported-encryption caveat.
    pub key_password: Option<String>,
    /// `CURLOPT_SSLCERT_BLOB` — in-memory client certificate (PEM).
    pub client_cert_blob: Option<Vec<u8>>,
    /// `CURLOPT_SSLKEY_BLOB` — in-memory client private key (PEM).
    pub client_key_blob: Option<Vec<u8>>,

    // --- Revocation / issuer ------------------------------------------------
    /// `CURLOPT_CRLFILE` — path to a PEM certificate-revocation list. Stored
    /// for curl surface parity.
    pub crl_file: Option<PathBuf>,
    /// `CURLOPT_ISSUERCERT` — path to the expected issuer certificate. Stored
    /// for curl surface parity.
    pub issuer_cert: Option<PathBuf>,

    // --- Protocol versions --------------------------------------------------
    /// Minimum TLS version, from `CURLOPT_SSLVERSION` (the low 16 bits).
    pub version_min: TlsVersion,
    /// Maximum TLS version, from `CURLOPT_SSLVERSION` (the high 16 bits).
    pub version_max: TlsVersion,

    // --- Cipher selection ---------------------------------------------------
    /// `CURLOPT_SSL_CIPHER_LIST` — the TLS 1.2 cipher list. Parsed exactly like
    /// `cr_get_selected_ciphers`; unknown names are ignored.
    pub cipher_list: Option<String>,
    /// `CURLOPT_TLS13_CIPHERS` — the TLS 1.3 cipher list.
    pub cipher_list13: Option<String>,

    // --- ALPN ---------------------------------------------------------------
    /// The ALPN protocol identifiers to offer, e.g. `b"h2"` and `b"http/1.1"`.
    /// Populated by the HTTP layer; empty by default.
    pub alpn: Vec<Vec<u8>>,

    // --- Pinning ------------------------------------------------------------
    /// `CURLOPT_PINNEDPUBLICKEY` — pinned public-key spec (`sha256//...` or a
    /// path). Stored here; the pin is enforced by the connection layer's
    /// verifier path.
    pub pinned_pubkey: Option<String>,

    // --- Resumption / logging -----------------------------------------------
    /// Optional TLS session-resumption cache. When present it is installed on
    /// [`rustls::ClientConfig::resumption`].
    pub session_cache: Option<SessionCache>,
    /// Force-enable `SSLKEYLOGFILE` key logging on the built config. Key
    /// logging is *also* enabled automatically whenever the `SSLKEYLOGFILE`
    /// environment variable is set (see [`super::keylog::is_enabled`]).
    pub keylog: bool,
}

impl Default for TlsConfig {
    /// Constructs a [`TlsConfig`] with curl 8.x's defaults.
    ///
    /// Crucially — and as required by the TLS-configuration audit — both
    /// [`verify_peer`](TlsConfig::verify_peer) and
    /// [`verify_host`](TlsConfig::verify_host) default to `true`.
    fn default() -> Self {
        TlsConfig {
            verify_peer: true,
            verify_host: true,
            verify_status: false,
            ca_info: None,
            ca_path: None,
            ca_info_blob: None,
            use_webpki_roots: true,
            client_cert: None,
            client_key: None,
            key_password: None,
            client_cert_blob: None,
            client_key_blob: None,
            crl_file: None,
            issuer_cert: None,
            version_min: TlsVersion::Default,
            version_max: TlsVersion::Default,
            cipher_list: None,
            cipher_list13: None,
            alpn: Vec::new(),
            pinned_pubkey: None,
            session_cache: None,
            keylog: false,
        }
    }
}

impl TlsConfig {
    /// Creates a new [`TlsConfig`] with curl's defaults (verification on).
    ///
    /// Equivalent to [`TlsConfig::default`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets `CURLOPT_SSL_VERIFYPEER`.
    #[must_use]
    pub fn with_verify_peer(mut self, verify: bool) -> Self {
        self.verify_peer = verify;
        self
    }

    /// Sets `CURLOPT_SSL_VERIFYHOST` (as the boolean `VERIFYHOST == 2`).
    #[must_use]
    pub fn with_verify_host(mut self, verify: bool) -> Self {
        self.verify_host = verify;
        self
    }

    /// Sets `CURLOPT_SSL_VERIFYSTATUS`.
    #[must_use]
    pub fn with_verify_status(mut self, verify: bool) -> Self {
        self.verify_status = verify;
        self
    }

    /// Turns off certificate verification, reproducing curl's `--insecure`
    /// (`-k`). Sets both [`verify_peer`](TlsConfig::verify_peer) and
    /// [`verify_host`](TlsConfig::verify_host) to `false`.
    ///
    /// The resulting configuration causes [`TlsConfig::build`] to emit
    /// [`INSECURE_WARNING`] to stderr before installing the accept-all
    /// verifier.
    #[must_use]
    pub fn insecure(mut self) -> Self {
        self.verify_peer = false;
        self.verify_host = false;
        self
    }

    /// Sets `CURLOPT_CAINFO` (a PEM trust-anchor bundle file).
    #[must_use]
    pub fn with_ca_info(mut self, path: impl Into<PathBuf>) -> Self {
        self.ca_info = Some(path.into());
        self
    }

    /// Sets `CURLOPT_CAPATH` (a directory of PEM trust-anchor files).
    #[must_use]
    pub fn with_ca_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.ca_path = Some(path.into());
        self
    }

    /// Sets `CURLOPT_CAINFO_BLOB` (an in-memory PEM trust-anchor bundle).
    #[must_use]
    pub fn with_ca_info_blob(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.ca_info_blob = Some(pem.into());
        self
    }

    /// Controls whether the built-in Mozilla root store is used when no
    /// explicit CA source is configured.
    #[must_use]
    pub fn with_webpki_roots(mut self, use_roots: bool) -> Self {
        self.use_webpki_roots = use_roots;
        self
    }

    /// Sets `CURLOPT_SSLCERT` (the client certificate PEM path).
    #[must_use]
    pub fn with_client_cert(mut self, path: impl Into<PathBuf>) -> Self {
        self.client_cert = Some(path.into());
        self
    }

    /// Sets `CURLOPT_SSLKEY` (the client private-key PEM path).
    #[must_use]
    pub fn with_client_key(mut self, path: impl Into<PathBuf>) -> Self {
        self.client_key = Some(path.into());
        self
    }

    /// Sets `CURLOPT_KEYPASSWD` (the client key passphrase).
    #[must_use]
    pub fn with_key_password(mut self, password: impl Into<String>) -> Self {
        self.key_password = Some(password.into());
        self
    }

    /// Sets `CURLOPT_SSLCERT_BLOB` (an in-memory client certificate PEM).
    #[must_use]
    pub fn with_client_cert_blob(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.client_cert_blob = Some(pem.into());
        self
    }

    /// Sets `CURLOPT_SSLKEY_BLOB` (an in-memory client private-key PEM).
    #[must_use]
    pub fn with_client_key_blob(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.client_key_blob = Some(pem.into());
        self
    }

    /// Sets `CURLOPT_CRLFILE` (a PEM certificate-revocation list path).
    #[must_use]
    pub fn with_crl_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.crl_file = Some(path.into());
        self
    }

    /// Sets `CURLOPT_ISSUERCERT` (the expected issuer certificate path).
    #[must_use]
    pub fn with_issuer_cert(mut self, path: impl Into<PathBuf>) -> Self {
        self.issuer_cert = Some(path.into());
        self
    }

    /// Sets the minimum TLS version (the low half of `CURLOPT_SSLVERSION`).
    #[must_use]
    pub fn with_min_version(mut self, version: TlsVersion) -> Self {
        self.version_min = version;
        self
    }

    /// Sets the maximum TLS version (the high half of `CURLOPT_SSLVERSION`).
    #[must_use]
    pub fn with_max_version(mut self, version: TlsVersion) -> Self {
        self.version_max = version;
        self
    }

    /// Sets `CURLOPT_SSL_CIPHER_LIST` (the TLS 1.2 cipher list).
    #[must_use]
    pub fn with_cipher_list(mut self, list: impl Into<String>) -> Self {
        self.cipher_list = Some(list.into());
        self
    }

    /// Sets `CURLOPT_TLS13_CIPHERS` (the TLS 1.3 cipher list).
    #[must_use]
    pub fn with_cipher_list13(mut self, list: impl Into<String>) -> Self {
        self.cipher_list13 = Some(list.into());
        self
    }

    /// Replaces the ALPN protocol list.
    #[must_use]
    pub fn with_alpn(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn = protocols;
        self
    }

    /// Appends a single ALPN protocol identifier (e.g. `b"h2"`).
    #[must_use]
    pub fn add_alpn(mut self, protocol: impl Into<Vec<u8>>) -> Self {
        self.alpn.push(protocol.into());
        self
    }

    /// Sets `CURLOPT_PINNEDPUBLICKEY`.
    #[must_use]
    pub fn with_pinned_pubkey(mut self, spec: impl Into<String>) -> Self {
        self.pinned_pubkey = Some(spec.into());
        self
    }

    /// Installs a TLS session-resumption cache
    /// ([`super::session_cache::SessionCache`]).
    #[must_use]
    pub fn with_session_cache(mut self, cache: SessionCache) -> Self {
        self.session_cache = Some(cache);
        self
    }

    /// Force-enables `SSLKEYLOGFILE` key logging on the built config.
    #[must_use]
    pub fn with_keylog(mut self, enabled: bool) -> Self {
        self.keylog = enabled;
        self
    }

    /// Maps the [`version_min`](TlsConfig::version_min) /
    /// [`version_max`](TlsConfig::version_max) bounds onto the concrete list of
    /// rustls protocol versions to enable.
    ///
    /// This reproduces the switch statements in `lib/vtls/rustls.c`:
    ///
    /// * The default (both bounds unset) enables **both** TLS 1.2 and TLS 1.3.
    /// * A minimum of TLS 1.0 / 1.1 / 1.2 keeps the TLS 1.2 floor; a minimum of
    ///   TLS 1.3 drops TLS 1.2.
    /// * A maximum of TLS 1.2 drops TLS 1.3; a maximum below TLS 1.2 is
    ///   rejected (the rustls backend cannot offer TLS 1.0 / 1.1).
    ///
    /// Returns [`CurlCode::SslConnectError`] when the requested bounds leave no
    /// usable version (for example `min = TLS 1.3, max = TLS 1.2`).
    fn protocol_versions(&self) -> Result<Vec<&'static SupportedProtocolVersion>> {
        // A maximum below TLS 1.2 is unrepresentable in rustls.
        if matches!(self.version_max, TlsVersion::Tlsv1_0 | TlsVersion::Tlsv1_1) {
            return Err(Error::with_context(
                CurlCode::SslConnectError,
                "rustls: unsupported maximum TLS version (below TLS 1.2)",
            ));
        }

        // The floor: TLS 1.3 only when explicitly requested, else TLS 1.2.
        let want_tls12 = self.version_min != TlsVersion::Tlsv1_3;
        // The ceiling: TLS 1.3 unless the maximum caps at TLS 1.2.
        let want_tls13 = self.version_max != TlsVersion::Tlsv1_2;

        let mut versions: Vec<&'static SupportedProtocolVersion> = Vec::with_capacity(2);
        if want_tls12 {
            versions.push(&rustls::version::TLS12);
        }
        if want_tls13 {
            versions.push(&rustls::version::TLS13);
        }

        if versions.is_empty() {
            // e.g. min == TLS 1.3 while max == TLS 1.2 — contradictory bounds.
            return Err(Error::with_context(
                CurlCode::SslConnectError,
                "rustls: the requested minimum TLS version exceeds the maximum",
            ));
        }

        Ok(versions)
    }

    /// Assembles the [`rustls::RootCertStore`] used for peer verification.
    ///
    /// The trust-anchor source is selected exactly as in `lib/vtls/rustls.c`:
    ///
    /// * If any of [`ca_info_blob`](TlsConfig::ca_info_blob),
    ///   [`ca_info`](TlsConfig::ca_info), or [`ca_path`](TlsConfig::ca_path) is
    ///   set, those PEM sources are parsed and added. A read or parse failure —
    ///   or a source that yields zero usable anchors — maps to
    ///   [`CurlCode::SslCacertBadfile`] (77).
    /// * Otherwise, when [`use_webpki_roots`](TlsConfig::use_webpki_roots) is
    ///   `true`, the built-in Mozilla root bundle is loaded.
    ///
    /// If the resulting store is empty and [`verify_peer`](TlsConfig::verify_peer)
    /// is `true`, this returns [`CurlCode::SslCacertBadfile`], because a peer
    /// cannot be verified without any trust anchors.
    fn build_root_store(&self) -> Result<RootCertStore> {
        let mut store = RootCertStore::empty();

        let has_explicit_ca =
            self.ca_info_blob.is_some() || self.ca_info.is_some() || self.ca_path.is_some();

        if has_explicit_ca {
            // In-memory PEM blob (CURLOPT_CAINFO_BLOB).
            if let Some(blob) = &self.ca_info_blob {
                add_pem_anchors(&mut store, &mut &blob[..], "CURLOPT_CAINFO_BLOB")?;
            }
            // PEM bundle file (CURLOPT_CAINFO).
            if let Some(path) = &self.ca_info {
                let bytes = read_file(path, "CA certificate file")?;
                add_pem_anchors(&mut store, &mut &bytes[..], &path.display().to_string())?;
            }
            // Directory of PEM files (CURLOPT_CAPATH).
            if let Some(dir) = &self.ca_path {
                add_ca_path_anchors(&mut store, dir)?;
            }
        } else if self.use_webpki_roots {
            // Built-in Mozilla roots — the default trust store.
            store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        if self.verify_peer && store.is_empty() {
            return Err(Error::with_context(
                CurlCode::SslCacertBadfile,
                "rustls: no trust anchors were loaded for certificate verification",
            ));
        }

        Ok(store)
    }

    /// Loads the client certificate chain and private key for mutual TLS.
    ///
    /// Reproduces the `clientcert` / `key` handling in `lib/vtls/rustls.c`:
    ///
    /// * When neither a certificate nor a key is configured, returns
    ///   `Ok(None)` (no client authentication).
    /// * A certificate without a key, or a key without a certificate, is a
    ///   configuration error → [`CurlCode::SslCertproblem`] (58), matching
    ///   curl's `failf` for the same mismatch.
    /// * The certificate chain is parsed from the PEM in
    ///   [`client_cert`](TlsConfig::client_cert) (or
    ///   [`client_cert_blob`](TlsConfig::client_cert_blob)); the private key is
    ///   parsed from [`client_key`](TlsConfig::client_key) /
    ///   [`client_key_blob`](TlsConfig::client_key_blob), falling back to the
    ///   certificate source when no separate key is given.
    ///
    /// # Encrypted-key limitation
    ///
    /// `rustls-pemfile` does not decrypt passphrase-protected private keys.
    /// When [`key_password`](TlsConfig::key_password) is set this returns
    /// [`CurlCode::SslCertproblem`] with an explanatory message. This is a
    /// documented, parity-acceptable limitation of the single rustls backend.
    #[allow(clippy::type_complexity)]
    fn load_client_auth(
        &self,
    ) -> Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>> {
        let have_cert = self.client_cert.is_some() || self.client_cert_blob.is_some();
        let have_key = self.client_key.is_some() || self.client_key_blob.is_some();

        // No client auth requested.
        if !have_cert && !have_key {
            return Ok(None);
        }

        // curl treats a lone certificate or a lone key as a setup error.
        if have_cert && !have_key && self.client_key.is_none() && self.client_key_blob.is_none() {
            // A certificate with no separate key is allowed *iff* the key lives
            // in the same PEM as the certificate; that is handled below by
            // falling back to the certificate bytes. Only a key-less blob with
            // no embedded key would fail, which the parser reports.
        }
        if have_key && !have_cert {
            return Err(Error::with_context(
                CurlCode::SslCertproblem,
                "rustls: a client private key was set without a client certificate",
            ));
        }

        // Encrypted keys are not supported by rustls-pemfile.
        if self.key_password.is_some() {
            return Err(Error::with_context(
                CurlCode::SslCertproblem,
                "rustls: passphrase-protected client keys are not supported; \
                 supply an unencrypted PEM key (CURLOPT_SSLKEY)",
            ));
        }

        // --- Certificate chain -------------------------------------------------
        let cert_bytes = self.read_cert_source()?;
        let mut cert_reader = BufReader::new(&cert_bytes[..]);
        let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                Error::with_context(
                    CurlCode::SslCertproblem,
                    format!("rustls: failed to parse client certificate PEM: {e}"),
                )
            })?;
        if chain.is_empty() {
            return Err(Error::with_context(
                CurlCode::SslCertproblem,
                "rustls: the client certificate source contained no certificates",
            ));
        }

        // --- Private key -------------------------------------------------------
        let key_bytes = self.read_key_source(&cert_bytes)?;
        let mut key_reader = BufReader::new(&key_bytes[..]);
        let key = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|e| {
                Error::with_context(
                    CurlCode::SslCertproblem,
                    format!("rustls: failed to parse client private key PEM: {e}"),
                )
            })?
            .ok_or_else(|| {
                Error::with_context(
                    CurlCode::SslCertproblem,
                    "rustls: no private key found in the client key source",
                )
            })?;

        Ok(Some((chain, key)))
    }

    /// Returns the PEM bytes of the client certificate source (blob preferred
    /// over file, matching curl's blob-takes-precedence rule).
    fn read_cert_source(&self) -> Result<Vec<u8>> {
        if let Some(blob) = &self.client_cert_blob {
            return Ok(blob.clone());
        }
        if let Some(path) = &self.client_cert {
            return read_file(path, "client certificate file").map_err(|_| {
                Error::with_context(
                    CurlCode::SslCertproblem,
                    format!(
                        "rustls: failed to read client certificate file: '{}'",
                        path.display()
                    ),
                )
            });
        }
        Err(Error::with_context(
            CurlCode::SslCertproblem,
            "rustls: no client certificate source configured",
        ))
    }

    /// Returns the PEM bytes of the client key source. Falls back to the
    /// certificate bytes when no dedicated key file/blob is set (curl allows
    /// the key to live in the certificate PEM).
    fn read_key_source(&self, cert_bytes: &[u8]) -> Result<Vec<u8>> {
        if let Some(blob) = &self.client_key_blob {
            return Ok(blob.clone());
        }
        if let Some(path) = &self.client_key {
            return read_file(path, "client key file").map_err(|_| {
                Error::with_context(
                    CurlCode::SslCertproblem,
                    format!(
                        "rustls: failed to read client key file: '{}'",
                        path.display()
                    ),
                )
            });
        }
        // No separate key configured: the key is expected inside the cert PEM.
        Ok(cert_bytes.to_vec())
    }

    /// Filters the crypto provider's cipher suites down to the ones selected by
    /// [`cipher_list`](TlsConfig::cipher_list) (TLS 1.2) and
    /// [`cipher_list13`](TlsConfig::cipher_list13) (TLS 1.3).
    ///
    /// This reproduces `cr_get_selected_ciphers` from `lib/vtls/rustls.c`:
    ///
    /// * For each TLS version, if a list is configured the recognized and
    ///   supported suites from that list are selected (in list order, without
    ///   duplicates); unknown names are logged and skipped, never fatal.
    /// * If a list is **not** configured for a version, all of that version's
    ///   default suites are retained — so setting only the TLS 1.2 list does
    ///   not disable TLS 1.3, and vice versa.
    /// * If the final selection is empty, this returns
    ///   [`CurlCode::SslCipher`] (59) (curl's "no supported cipher in list").
    ///
    /// This is only called when at least one cipher list is configured; with no
    /// lists set the provider's default suites are used unchanged.
    fn selected_cipher_suites(
        &self,
        provider: &CryptoProvider,
    ) -> Result<Vec<rustls::SupportedCipherSuite>> {
        let available = &provider.cipher_suites;
        let mut selected: Vec<rustls::SupportedCipherSuite> = Vec::new();

        // TLS 1.3 side.
        match self.cipher_list13.as_deref() {
            Some(list) => select_ciphers_from_list(list, available, true, &mut selected),
            None => add_default_ciphers(available, true, &mut selected),
        }
        // TLS 1.2 side.
        match self.cipher_list.as_deref() {
            Some(list) => select_ciphers_from_list(list, available, false, &mut selected),
            None => add_default_ciphers(available, false, &mut selected),
        }

        if selected.is_empty() {
            return Err(Error::with_context(
                CurlCode::SslCipher,
                "rustls: no supported cipher in list",
            ));
        }

        Ok(selected)
    }
}

/// Returns `true` if `suite` is a TLS 1.3 cipher suite.
fn is_tls13(suite: rustls::SupportedCipherSuite) -> bool {
    suite.tls13().is_some()
}

/// Adds every default suite of the requested TLS version from `available` to
/// `selected` (skipping duplicates).
fn add_default_ciphers(
    available: &[rustls::SupportedCipherSuite],
    tls13: bool,
    selected: &mut Vec<rustls::SupportedCipherSuite>,
) {
    for &suite in available {
        if is_tls13(suite) == tls13 && !selected.iter().any(|s| s.suite() == suite.suite()) {
            selected.push(suite);
        }
    }
}

/// Selects the suites named in `list` (of the requested TLS version) from
/// `available`, in list order and without duplicates. Unknown or wrong-version
/// names are logged at debug level and skipped, matching curl's `infof`
/// diagnostics for unrecognized ciphers.
fn select_ciphers_from_list(
    list: &str,
    available: &[rustls::SupportedCipherSuite],
    tls13: bool,
    selected: &mut Vec<rustls::SupportedCipherSuite>,
) {
    for token in tokenize_cipher_list(list) {
        match cipher_token_to_id(token, available) {
            Some(id) => {
                // Find the matching available suite of the requested version.
                let found = available
                    .iter()
                    .copied()
                    .find(|s| u16::from(s.suite()) == id && is_tls13(*s) == tls13);
                match found {
                    // Add the matching suite once, in list order.
                    Some(suite) if !selected.iter().any(|s| s.suite() == suite.suite()) => {
                        selected.push(suite);
                    }
                    // Nothing to add: either the suite is already selected, or the
                    // recognized name is not of this TLS version — the latter is
                    // picked up on the other version's pass if applicable.
                    _ => {}
                }
            }
            None => {
                tracing::debug!(cipher = %token, "rustls: unknown cipher in list");
            }
        }
    }
}

/// Splits a curl cipher list into tokens on the same separators as
/// `Curl_cipher_suite_walk_str` / `cs_is_separator`: space, tab, `:`, `,`, `;`.
fn tokenize_cipher_list(list: &str) -> impl Iterator<Item = &str> {
    // Same separator set as curl's `cs_is_separator`: space, tab, `:`, `,`, `;`.
    // An array of `char` implements `str::pattern::Pattern` (stable since Rust
    // 1.71, within MSRV 1.75) and is the idiomatic form clippy expects.
    list.split([' ', '\t', ':', ',', ';'])
        .filter(|s| !s.is_empty())
}

/// Resolves a single curl cipher name to its IANA cipher-suite identifier,
/// restricted to the suites the rustls provider actually supports.
///
/// Accepts three name forms, matching curl's cipher-name handling for the
/// suites this backend can offer:
///
/// * The rustls variant name / IANA name (e.g. `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
///   or `TLS13_AES_128_GCM_SHA256`), compared case-insensitively against the
///   provider's own suites.
/// * The standard IANA TLS 1.3 names (`TLS_AES_128_GCM_SHA256`, …) and the
///   common OpenSSL TLS 1.2 aliases (`ECDHE-RSA-AES128-GCM-SHA256`, …).
/// * A raw hexadecimal identifier such as `0x1301`.
fn cipher_token_to_id(token: &str, available: &[rustls::SupportedCipherSuite]) -> Option<u16> {
    // 1. Hexadecimal identifier, e.g. "0x1301".
    if let Some(hex) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        if let Ok(id) = u16::from_str_radix(hex, 16) {
            return Some(id);
        }
    }

    // 2. Known IANA / OpenSSL aliases for the rustls-supported suites.
    for (name, id) in CIPHER_ALIASES {
        if token.eq_ignore_ascii_case(name) {
            return Some(*id);
        }
    }

    // 3. The provider's own variant names (covers TLS 1.2 IANA names and the
    //    rustls "TLS13_*" spellings) — compared case-insensitively.
    for &suite in available {
        if let Some(name) = suite.suite().as_str() {
            if token.eq_ignore_ascii_case(name) {
                return Some(u16::from(suite.suite()));
            }
        }
    }

    None
}

/// Name → IANA identifier aliases for the cipher suites the rustls backend
/// supports. Covers the standard IANA TLS 1.3 names (which differ from rustls'
/// `TLS13_*` variant spelling) and the common OpenSSL TLS 1.2 names.
const CIPHER_ALIASES: &[(&str, u16)] = &[
    // TLS 1.3 (IANA spelling).
    ("TLS_AES_128_GCM_SHA256", 0x1301),
    ("TLS_AES_256_GCM_SHA384", 0x1302),
    ("TLS_CHACHA20_POLY1305_SHA256", 0x1303),
    // TLS 1.2 — OpenSSL aliases for the ECDHE AEAD suites rustls offers.
    ("ECDHE-ECDSA-AES128-GCM-SHA256", 0xC02B),
    ("ECDHE-ECDSA-AES256-GCM-SHA384", 0xC02C),
    ("ECDHE-RSA-AES128-GCM-SHA256", 0xC02F),
    ("ECDHE-RSA-AES256-GCM-SHA384", 0xC030),
    ("ECDHE-ECDSA-CHACHA20-POLY1305", 0xCCA9),
    ("ECDHE-RSA-CHACHA20-POLY1305", 0xCCA8),
];

impl TlsConfig {
    /// Builds the [`rustls::ClientConfig`] described by this [`TlsConfig`],
    /// returned behind an [`Arc`] so it can be shared across connections.
    ///
    /// The construction order mirrors curl's `lib/vtls/rustls.c` setup:
    ///
    /// 1. Resolve the process crypto provider and, if a cipher list is set,
    ///    build a provider variant restricted to the selected suites.
    /// 2. Pin the protocol versions from [`version_min`](TlsConfig::version_min)
    ///    / [`version_max`](TlsConfig::version_max).
    /// 3. Install the verifier: for [`verify_peer`](TlsConfig::verify_peer),
    ///    the standard rustls root-certificate verifier; otherwise **emit
    ///    [`INSECURE_WARNING`] to stderr first**, then install the accept-all
    ///    [`NoServerCertVerification`].
    /// 4. Configure client authentication from
    ///    [`load_client_auth`](TlsConfig::load_client_auth).
    /// 5. Apply ALPN, session resumption, and key logging.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] whose [`code`](Error::code) is one of:
    /// [`CurlCode::SslCacertBadfile`] (bad CA source),
    /// [`CurlCode::SslCertproblem`] (bad client cert/key),
    /// [`CurlCode::SslCipher`] (empty cipher selection),
    /// [`CurlCode::PeerFailedVerification`] (a rustls certificate error), or
    /// [`CurlCode::SslConnectError`] (any other setup failure).
    pub fn build(&self) -> Result<Arc<ClientConfig>> {
        // 1. Crypto provider (optionally restricted to selected cipher suites).
        let base_provider = resolve_default_provider()?;
        let provider = if self.cipher_list.is_some() || self.cipher_list13.is_some() {
            let suites = self.selected_cipher_suites(&base_provider)?;
            Arc::new(CryptoProvider {
                cipher_suites: suites,
                ..(*base_provider).clone()
            })
        } else {
            base_provider
        };

        // 2. Protocol versions.
        let versions = self.protocol_versions()?;
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&versions)
            .map_err(|e| map_rustls_error(&e))?;

        // 3. Verifier: secure by default; accept-all only for --insecure.
        let builder = if self.verify_peer {
            let roots = self.build_root_store()?;
            builder.with_root_certificates(roots)
        } else {
            // The warning MUST be emitted BEFORE the config is built/returned,
            // matching curl's warning-before-connect ordering for --insecure.
            emit_insecure_warning();
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoServerCertVerification::new(
                    provider.clone(),
                )))
        };

        // 4. Client authentication.
        let mut config = match self.load_client_auth()? {
            Some((chain, key)) => builder.with_client_auth_cert(chain, key).map_err(|e| {
                Error::with_context(
                    CurlCode::SslCertproblem,
                    format!("rustls: failed to install client certificate: {e}"),
                )
            })?,
            None => builder.with_no_client_auth(),
        };

        // 5a. ALPN protocols (set by the HTTP layer).
        config.alpn_protocols = self.alpn.clone();

        // 5b. Session resumption, if a cache was provided.
        if let Some(cache) = &self.session_cache {
            config.resumption = Resumption::store(cache.as_rustls_store());
        }

        // 5c. SSLKEYLOGFILE key logging: honored when forced here or enabled
        //     via the environment (curl's global behavior).
        if self.keylog || keylog::is_enabled() {
            config.key_log = keylog::key_log();
        }

        Ok(Arc::new(config))
    }
}

/// Emits the mandatory [`INSECURE_WARNING`] to standard error.
///
/// Factored out so the ordering guarantee (warn *before* building the insecure
/// config) is explicit and self-documenting at the call site.
fn emit_insecure_warning() {
    eprintln!("{INSECURE_WARNING}");
}

/// Reads a file into memory, mapping any I/O failure to
/// [`CurlCode::SslCacertBadfile`] with a `what`-labeled message.
///
/// Used for CA sources; client-cert/key call sites re-map the error to
/// [`CurlCode::SslCertproblem`].
fn read_file(path: &Path, what: &str) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| {
        Error::with_context(
            CurlCode::SslCacertBadfile,
            format!("rustls: failed to read {what} '{}': {e}", path.display()),
        )
    })
}

/// Parses PEM certificates from `reader` and adds them to `store` as trust
/// anchors. A parse failure, or a source that yields no usable anchors, is
/// reported as [`CurlCode::SslCacertBadfile`].
fn add_pem_anchors(
    store: &mut RootCertStore,
    reader: &mut dyn std::io::BufRead,
    source: &str,
) -> Result<()> {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| {
            Error::with_context(
                CurlCode::SslCacertBadfile,
                format!("rustls: failed to parse CA certificates from {source}: {e}"),
            )
        })?;

    if certs.is_empty() {
        return Err(Error::with_context(
            CurlCode::SslCacertBadfile,
            format!("rustls: no CA certificates found in {source}"),
        ));
    }

    let (added, _ignored) = store.add_parsable_certificates(certs);
    if added == 0 {
        return Err(Error::with_context(
            CurlCode::SslCacertBadfile,
            format!("rustls: no valid trust anchors could be derived from {source}"),
        ));
    }

    Ok(())
}

/// Adds every parsable PEM file in the `CURLOPT_CAPATH` directory to `store`.
///
/// Reproduces curl's directory-of-PEMs behavior: each regular file in the
/// directory is treated as a PEM bundle; a file that yields no anchors is
/// skipped rather than being fatal, but a completely unreadable directory or a
/// directory with zero usable anchors reports [`CurlCode::SslCacertBadfile`].
fn add_ca_path_anchors(store: &mut RootCertStore, dir: &Path) -> Result<()> {
    let entries = fs::read_dir(dir).map_err(|e| {
        Error::with_context(
            CurlCode::SslCacertBadfile,
            format!(
                "rustls: failed to open CA path directory '{}': {e}",
                dir.display()
            ),
        )
    })?;

    let mut total_added = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        // Read and parse; ignore files that are not valid PEM certificate
        // bundles so an unrelated file in the directory is not fatal.
        if let Ok(bytes) = fs::read(&path) {
            let mut reader = &bytes[..];
            if let Ok(certs) =
                rustls_pemfile::certs(&mut reader).collect::<std::result::Result<Vec<_>, _>>()
            {
                if !certs.is_empty() {
                    let (added, _ignored) = store.add_parsable_certificates(certs);
                    total_added += added;
                }
            }
        }
    }

    if total_added == 0 {
        return Err(Error::with_context(
            CurlCode::SslCacertBadfile,
            format!(
                "rustls: no valid trust anchors found in CA path directory '{}'",
                dir.display()
            ),
        ));
    }

    Ok(())
}

/// Resolves the process-wide rustls [`CryptoProvider`].
///
/// If a process default has already been installed — for example by
/// `curl_global_init` at the FFI boundary, or by the CLI at start-up — it is
/// returned unchanged so the caller's explicit choice always wins. Otherwise
/// the crate's *configured* default provider is installed process-wide and
/// returned: `aws-lc-rs`, which is the `rustls` `default` feature selected in
/// `curl-rs-lib/Cargo.toml`.
///
/// The [`ClientConfig::builder`] feature-auto-detection path is deliberately
/// **not** used here. This dependency graph compiles in *both* the `aws-lc-rs`
/// and the `ring` `rustls` providers — QUIC/HTTP-3 via `quinn` transitively
/// enables `ring` — which makes `rustls`'s crate-feature auto-detection
/// ambiguous, causing `ClientConfig::builder()` to panic when no default has
/// been installed. Installing the configured default explicitly is
/// deterministic and provider-correct.
///
/// No C TLS library is linked: `aws-lc-rs` is a crates.io crypto provider (the
/// one `rustls` uses by default and that the workspace already depends on); it
/// introduces no `libssl`/OpenSSL/GnuTLS/etc. linkage.
fn resolve_default_provider() -> Result<Arc<CryptoProvider>> {
    if let Some(provider) = CryptoProvider::get_default() {
        return Ok(provider.clone());
    }

    // Install the crate's configured default provider. `install_default`
    // succeeds at most once per process; if another thread wins the race we
    // simply adopt whichever provider is now installed.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    CryptoProvider::get_default().cloned().ok_or_else(|| {
        Error::with_context(
            CurlCode::SslConnectError,
            "rustls: no crypto provider is available",
        )
    })
}

/// Bridges a [`rustls::Error`] to the frozen curl [`CurlCode`] integers,
/// mirroring `map_error` in `lib/vtls/rustls.c`.
///
/// Certificate and revocation-list errors map to
/// [`CurlCode::PeerFailedVerification`] (60); every other setup error maps to
/// [`CurlCode::SslConnectError`] (35).
fn map_rustls_error(err: &rustls::Error) -> Error {
    match err {
        rustls::Error::InvalidCertificate(_) | rustls::Error::InvalidCertRevocationList(_) => {
            Error::peer_failed_verification(format!("rustls: {err}"))
        }
        _ => Error::with_context(CurlCode::SslConnectError, format!("rustls: {err}")),
    }
}

/// An accept-all [`ServerCertVerifier`] that unconditionally approves the
/// server certificate and its handshake signatures.
///
/// # Why this exists (rationale, NOT `unsafe`)
///
/// This type is the faithful port of `cr_verify_none` from
/// `lib/vtls/rustls.c`, which returns `RUSTLS_RESULT_OK` for every server
/// certificate. It exists **solely** to reproduce curl's `--insecure`
/// (`CURLOPT_SSL_VERIFYPEER == 0`) behavior and is installed **only** on that
/// path, after [`INSECURE_WARNING`] has been written to stderr. It performs no
/// authentication whatsoever: any certificate — including an expired,
/// self-signed, or name-mismatched one — is accepted. It is written entirely
/// in safe Rust (the crate forbids `unsafe`); the danger it embodies is the
/// deliberate *disabling of TLS authentication*, not memory-unsafety.
///
/// It carries an [`Arc<CryptoProvider>`] purely so that
/// [`supported_verify_schemes`](ServerCertVerifier::supported_verify_schemes)
/// can advertise the provider's real signature schemes, which lets the
/// handshake complete.
#[derive(Debug)]
pub struct NoServerCertVerification {
    /// The crypto provider whose signature schemes are advertised during the
    /// handshake.
    provider: Arc<CryptoProvider>,
}

impl NoServerCertVerification {
    /// Creates an accept-all verifier that advertises `provider`'s signature
    /// schemes.
    #[must_use]
    pub fn new(provider: Arc<CryptoProvider>) -> Self {
        NoServerCertVerification { provider }
    }
}

impl ServerCertVerifier for NoServerCertVerification {
    /// Accepts any server certificate without validation (curl `--insecure`).
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    /// Accepts any TLS 1.2 handshake signature (curl `--insecure`).
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    /// Accepts any TLS 1.3 handshake signature (curl `--insecure`).
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    /// Advertises the crypto provider's real signature schemes so the peer can
    /// select a compatible one and the handshake can proceed.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Generates an ephemeral self-signed certificate + key pair as PEM bytes.
    fn ephemeral_cert_and_key() -> (Vec<u8>, Vec<u8>) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen self-signed generation");
        let cert_pem = certified.cert.pem().into_bytes();
        let key_pem = certified.signing_key.serialize_pem().into_bytes();
        (cert_pem, key_pem)
    }

    // ---------------------------------------------------------------------
    // Default-on verification gate (merge-blocking invariant).
    // ---------------------------------------------------------------------

    #[test]
    fn default_enables_peer_and_host_verification() {
        let cfg = TlsConfig::default();
        assert!(cfg.verify_peer, "SSL_VERIFYPEER must default to true");
        assert!(cfg.verify_host, "SSL_VERIFYHOST must default to true");
        assert!(!cfg.verify_status, "SSL_VERIFYSTATUS defaults to false");
        assert!(cfg.use_webpki_roots, "built-in roots on by default");
    }

    #[test]
    fn new_matches_default() {
        assert_eq!(
            TlsConfig::new().verify_peer,
            TlsConfig::default().verify_peer
        );
        assert_eq!(
            TlsConfig::new().verify_host,
            TlsConfig::default().verify_host
        );
    }

    #[test]
    fn insecure_setter_disables_both_checks() {
        let cfg = TlsConfig::default().insecure();
        assert!(!cfg.verify_peer);
        assert!(!cfg.verify_host);
    }

    // ---------------------------------------------------------------------
    // build(): secure default path vs. accept-all --insecure path.
    // ---------------------------------------------------------------------

    #[test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    fn build_default_with_webpki_roots_succeeds() {
        // The default config uses the built-in Mozilla roots and a real
        // (root-certificate) verifier.
        let config = TlsConfig::default()
            .build()
            .expect("default build succeeds");
        // A fresh secure config offers no ALPN and enables SNI.
        assert!(config.alpn_protocols.is_empty());
        assert!(config.enable_sni);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    fn secure_path_requires_trust_anchors() {
        // verify_peer = true but no CA source and built-in roots disabled: the
        // real verifier cannot be built without anchors -> SSL CA badfile.
        let err = TlsConfig::default()
            .with_webpki_roots(false)
            .build()
            .expect_err("no roots must fail when verifying");
        assert_eq!(err.code(), CurlCode::SslCacertBadfile);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    fn insecure_build_needs_no_trust_anchors() {
        // The accept-all verifier does not consult any trust store, so the
        // build succeeds even with no roots at all — behaviorally proving the
        // insecure path installs a different verifier than the secure path.
        let config = TlsConfig::default()
            .insecure()
            .with_webpki_roots(false)
            .build()
            .expect("insecure build succeeds without roots");
        assert!(config.alpn_protocols.is_empty());
    }

    #[test]
    fn insecure_warning_text_is_meaningful() {
        // The warning is emitted to stderr by `emit_insecure_warning` during an
        // insecure build (side effect, documented). We assert the exact text of
        // the constant here rather than capturing the process stderr stream.
        assert!(INSECURE_WARNING.contains("verification is disabled"));
        assert!(INSECURE_WARNING.starts_with("Warning:"));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    fn no_server_cert_verification_advertises_schemes() {
        let provider = resolve_default_provider().expect("provider");
        let verifier = NoServerCertVerification::new(provider);
        // The accept-all verifier must still advertise real signature schemes
        // so a handshake can complete.
        assert!(!verifier.supported_verify_schemes().is_empty());
    }

    // ---------------------------------------------------------------------
    // CA sources.
    // ---------------------------------------------------------------------

    #[test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    fn ca_info_valid_pem_file_loads() {
        let (cert_pem, _key) = ephemeral_cert_and_key();
        let mut file = tempfile::NamedTempFile::new().expect("temp CA file");
        file.write_all(&cert_pem).expect("write CA pem");
        let cfg = TlsConfig::default().with_ca_info(file.path());
        let store = cfg.build_root_store().expect("valid CA loads");
        assert_eq!(store.len(), 1, "one trust anchor from the CA file");
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    fn ca_info_blob_valid_pem_loads() {
        let (cert_pem, _key) = ephemeral_cert_and_key();
        let cfg = TlsConfig::default().with_ca_info_blob(cert_pem);
        let store = cfg.build_root_store().expect("valid CA blob loads");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn ca_info_garbage_file_is_cacert_badfile() {
        let mut file = tempfile::NamedTempFile::new().expect("temp CA file");
        file.write_all(b"this is not a PEM certificate at all\n")
            .expect("write garbage");
        let cfg = TlsConfig::default().with_ca_info(file.path());
        let err = cfg.build_root_store().expect_err("garbage CA must fail");
        assert_eq!(err.code(), CurlCode::SslCacertBadfile);
        assert_eq!(err.code_i32(), 77);
    }

    #[test]
    fn ca_info_missing_file_is_cacert_badfile() {
        let cfg = TlsConfig::default().with_ca_info("/nonexistent/path/to/ca.pem");
        let err = cfg.build_root_store().expect_err("missing CA must fail");
        assert_eq!(err.code(), CurlCode::SslCacertBadfile);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    fn ca_path_directory_of_pems_loads() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (cert_pem, _key) = ephemeral_cert_and_key();
        let ca_file = dir.path().join("root.pem");
        fs::write(ca_file, cert_pem).expect("write ca in dir");
        // An unrelated non-PEM file in the directory must not be fatal.
        fs::write(dir.path().join("notes.txt"), b"ignore me").expect("write junk");
        let cfg = TlsConfig::default().with_ca_path(dir.path());
        let store = cfg.build_root_store().expect("ca_path loads");
        assert_eq!(store.len(), 1);
    }

    // ---------------------------------------------------------------------
    // Client authentication.
    // ---------------------------------------------------------------------

    #[test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    fn client_cert_and_key_blob_round_trip() {
        let (cert_pem, key_pem) = ephemeral_cert_and_key();
        let cfg = TlsConfig::default()
            .with_client_cert_blob(cert_pem)
            .with_client_key_blob(key_pem);
        let loaded = cfg.load_client_auth().expect("client auth loads");
        let (chain, _key) = loaded.expect("Some client auth");
        assert_eq!(chain.len(), 1, "one client certificate parsed");
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    fn client_cert_and_key_files_build_full_config() {
        let (cert_pem, key_pem) = ephemeral_cert_and_key();
        let mut cert_file = tempfile::NamedTempFile::new().expect("cert file");
        cert_file.write_all(&cert_pem).expect("write cert");
        let mut key_file = tempfile::NamedTempFile::new().expect("key file");
        key_file.write_all(&key_pem).expect("write key");

        let cfg = TlsConfig::default()
            .with_client_cert(cert_file.path())
            .with_client_key(key_file.path());
        // Full build exercises rustls' with_client_auth_cert (key/cert match).
        cfg.build().expect("client-auth config builds");
    }

    #[test]
    fn no_client_auth_returns_none() {
        assert!(TlsConfig::default()
            .load_client_auth()
            .expect("ok")
            .is_none());
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    fn key_without_cert_is_certproblem() {
        let (_cert, key_pem) = ephemeral_cert_and_key();
        let cfg = TlsConfig::default().with_client_key_blob(key_pem);
        let err = cfg.load_client_auth().expect_err("lone key fails");
        assert_eq!(err.code(), CurlCode::SslCertproblem);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    fn encrypted_key_password_is_unsupported_certproblem() {
        let (cert_pem, key_pem) = ephemeral_cert_and_key();
        let cfg = TlsConfig::default()
            .with_client_cert_blob(cert_pem)
            .with_client_key_blob(key_pem)
            .with_key_password("secret");
        let err = cfg.load_client_auth().expect_err("passphrase unsupported");
        assert_eq!(err.code(), CurlCode::SslCertproblem);
        assert_eq!(err.code_i32(), 58);
    }

    #[test]
    fn garbage_client_cert_is_certproblem() {
        let cfg = TlsConfig::default()
            .with_client_cert_blob(b"not a certificate".to_vec())
            .with_client_key_blob(b"not a key".to_vec());
        let err = cfg
            .load_client_auth()
            .expect_err("garbage client cert fails");
        assert_eq!(err.code(), CurlCode::SslCertproblem);
    }

    // ---------------------------------------------------------------------
    // Cipher-suite parsing.
    // ---------------------------------------------------------------------

    #[test]
    fn cipher_tokenizer_splits_on_all_separators() {
        let tokens: Vec<&str> = tokenize_cipher_list("A:B,C D\tE;F::G").collect();
        assert_eq!(tokens, vec!["A", "B", "C", "D", "E", "F", "G"]);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    fn cipher_token_resolves_known_names() {
        let provider = resolve_default_provider().expect("provider");
        let available = &provider.cipher_suites;
        // IANA TLS 1.3 name.
        assert_eq!(
            cipher_token_to_id("TLS_AES_128_GCM_SHA256", available),
            Some(0x1301)
        );
        // OpenSSL TLS 1.2 alias (case-insensitive).
        assert_eq!(
            cipher_token_to_id("ecdhe-rsa-aes128-gcm-sha256", available),
            Some(0xC02F)
        );
        // Hex form.
        assert_eq!(cipher_token_to_id("0x1302", available), Some(0x1302));
        // Unknown.
        assert_eq!(cipher_token_to_id("NO_SUCH_CIPHER", available), None);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    fn known_tls13_cipher_is_selected() {
        let provider = resolve_default_provider().expect("provider");
        let cfg = TlsConfig::default().with_cipher_list13("TLS_AES_128_GCM_SHA256");
        let selected = cfg.selected_cipher_suites(&provider).expect("selection");
        // The requested TLS 1.3 suite is present.
        assert!(selected.iter().any(|s| u16::from(s.suite()) == 0x1301));
        // Default TLS 1.2 suites are retained (the TLS 1.2 list was unset).
        assert!(selected.iter().any(|s| s.tls13().is_none()));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    fn only_unknown_ciphers_in_both_lists_is_sslcipher() {
        let provider = resolve_default_provider().expect("provider");
        let cfg = TlsConfig::default()
            .with_cipher_list("NO_SUCH_TLS12_CIPHER")
            .with_cipher_list13("NO_SUCH_TLS13_CIPHER");
        let err = cfg
            .selected_cipher_suites(&provider)
            .expect_err("only-unknown must fail");
        assert_eq!(err.code(), CurlCode::SslCipher);
        assert_eq!(err.code_i32(), 59);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    fn no_cipher_list_uses_defaults_and_builds() {
        // With no cipher lists set, build() must not restrict suites.
        let config = TlsConfig::default().build().expect("default ciphers build");
        // Sanity: the config is usable (has an ALPN vector, empty here).
        assert!(config.alpn_protocols.is_empty());
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    fn cipher_list_only_keeps_tls13_defaults() {
        // Setting only the TLS 1.2 list must not drop TLS 1.3 defaults.
        let provider = resolve_default_provider().expect("provider");
        let cfg = TlsConfig::default().with_cipher_list("ECDHE-RSA-AES128-GCM-SHA256");
        let selected = cfg.selected_cipher_suites(&provider).expect("selection");
        assert!(
            selected.iter().any(|s| s.tls13().is_some()),
            "TLS 1.3 defaults retained when only the TLS 1.2 list is set"
        );
    }

    // ---------------------------------------------------------------------
    // Protocol version mapping.
    // ---------------------------------------------------------------------

    #[test]
    fn default_versions_enable_tls12_and_tls13() {
        let versions = TlsConfig::default().protocol_versions().expect("versions");
        assert_eq!(versions.len(), 2);
    }

    #[test]
    fn min_tls13_drops_tls12() {
        let versions = TlsConfig::default()
            .with_min_version(TlsVersion::Tlsv1_3)
            .protocol_versions()
            .expect("versions");
        assert_eq!(versions.len(), 1);
    }

    #[test]
    fn max_tls12_drops_tls13() {
        let versions = TlsConfig::default()
            .with_max_version(TlsVersion::Tlsv1_2)
            .protocol_versions()
            .expect("versions");
        assert_eq!(versions.len(), 1);
    }

    #[test]
    fn min_10_or_11_keeps_tls12_floor() {
        // The rustls backend cannot go below TLS 1.2; a TLS 1.0/1.1 minimum is
        // silently raised, yielding both TLS 1.2 and TLS 1.3.
        assert_eq!(
            TlsConfig::default()
                .with_min_version(TlsVersion::Tlsv1_0)
                .protocol_versions()
                .expect("versions")
                .len(),
            2
        );
    }

    #[test]
    fn max_below_tls12_is_error() {
        let err = TlsConfig::default()
            .with_max_version(TlsVersion::Tlsv1_1)
            .protocol_versions()
            .expect_err("max < 1.2 unsupported");
        assert_eq!(err.code(), CurlCode::SslConnectError);
    }

    #[test]
    fn contradictory_bounds_are_error() {
        let err = TlsConfig::default()
            .with_min_version(TlsVersion::Tlsv1_3)
            .with_max_version(TlsVersion::Tlsv1_2)
            .protocol_versions()
            .expect_err("min 1.3 > max 1.2");
        assert_eq!(err.code(), CurlCode::SslConnectError);
    }

    // ---------------------------------------------------------------------
    // ALPN.
    // ---------------------------------------------------------------------

    #[test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    fn alpn_protocols_are_set_on_built_config() {
        let alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let config = TlsConfig::default()
            .with_alpn(alpn.clone())
            .build()
            .expect("alpn config builds");
        assert_eq!(config.alpn_protocols, alpn);
    }

    #[test]
    fn add_alpn_appends_single_protocol() {
        let cfg = TlsConfig::default()
            .add_alpn(b"h2".to_vec())
            .add_alpn(b"http/1.1".to_vec());
        assert_eq!(cfg.alpn, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    // ---------------------------------------------------------------------
    // Session resumption wiring.
    // ---------------------------------------------------------------------

    #[test]
    #[cfg_attr(
        miri,
        ignore = "exercises aws-lc-rs C-FFI crypto; unsupported under Miri"
    )]
    fn session_cache_is_installed() {
        let cfg = TlsConfig::default().with_session_cache(SessionCache::new());
        // Build succeeds and the resumption store is wired without panicking.
        cfg.build().expect("config with session cache builds");
    }
}
