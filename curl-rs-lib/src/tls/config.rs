//! curl TLS options → [`rustls::ClientConfig`] builder.
//!
//! This is the foundational module of the TLS layer. It defines [`TlsConfig`]
//! — the Rust model of curl's per-transfer TLS configuration surface
//! (`ssl_primary_config` + `ssl_config_data` in `lib/urldata.h`) — and the
//! builder [`TlsConfig::build_client_config`] that translates every curl TLS
//! option onto a [`rustls::ClientConfig`].
//!
//! # Behavioral oracle
//!
//! The option → rustls mapping reproduces, decision-for-decision, libcurl's own
//! rustls binding (`lib/vtls/rustls.c`): the `init_config_builder*` family and
//! the master `cr_init_backend` ordering. Backend-agnostic defaults (the
//! certificate-validation defaults, the pinned-public-key algorithm, the TLS
//! version semantics) come from `lib/vtls/vtls.c`. Those C files are consumed as
//! a *behavioral oracle only* — the logic is re-expressed in safe, idiomatic
//! Rust, never transliterated. The other six C TLS backends and the C cipher
//! parser (`cipher_suite.c`) are out of scope (AAP §0.3.2) and are read only to
//! confirm the option → behavior contract.
//!
//! # Hard rules (AAP §0.8.1)
//!
//! * **`rustls` exclusively.** This module builds a [`rustls::ClientConfig`] and
//!   nothing else. There is no OpenSSL / GnuTLS / mbedTLS / wolfSSL / Schannel /
//!   Secure Transport linkage, and — deliberately — no `rustls-native-certs` or
//!   platform-verifier dependency (see the verifier decision tree in
//!   [`TlsConfig::build_client_config`]).
//! * **Certificate validation is ON by default.** [`TlsConfig::default`] sets
//!   `verify_peer = true` and `verify_host = true`. The accept-all
//!   ([`NoServerVerify`]) verifier is reachable *only* when the caller
//!   explicitly disables verification (curl's `--insecure` /
//!   `CURLOPT_SSL_VERIFYPEER=0`). The mandatory stderr warning that curl prints
//!   when verification is disabled is emitted at the CLI edge (`curl-rs`), not
//!   here — this module merely *models* the disabled state.
//! * **Zero `unsafe`.** The module sets `#![forbid(unsafe_code)]`. The custom
//!   verifiers are ordinary safe Rust; they need no `unsafe`.

// Memory-safety mandate (AAP §0.7.1): this module is part of the safe core and
// contains no `unsafe`. `forbid` makes that compiler-enforced.
#![forbid(unsafe_code)]
// During the parallel rewrite some public/`pub(crate)` helpers (e.g.
// `map_rustls_error`, `verify_pinned_pubkey`) are consumed by sibling modules
// (`tls::mod`, `conn::`) that land in the same migration step; allow dead code
// so a standalone build of this file does not trip the zero-warnings gate. This
// mirrors the sibling TLS modules (`keylog.rs`, `session_cache.rs`,
// `hostname.rs`).
#![allow(dead_code)]

use std::path::Path;
use std::sync::{Arc, Once};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ClientConfig, ClientSessionStore, Resumption, WebPkiServerVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName,
    SubjectPublicKeyInfoDer, UnixTime,
};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error, RootCertStore,
    SignatureScheme, SupportedProtocolVersion,
};

use crate::error::CurlError;
use crate::tls::keylog::key_log;
use crate::util::base64::base64_encode;
use crate::util::sha256::sha256it;

// =============================================================================
// curl public constants (verified against include/curl/curl.h)
// =============================================================================

// ---- CURL_SSLVERSION_* — minimum TLS version (low 16 bits of CURLOPT_SSLVERSION)
/// `CURL_SSLVERSION_DEFAULT` — let the backend pick (curl floor: TLS 1.x).
pub const CURL_SSLVERSION_DEFAULT: u32 = 0;
/// `CURL_SSLVERSION_TLSv1` — TLS 1.x (unspecified minor).
pub const CURL_SSLVERSION_TLSV1: u32 = 1;
/// `CURL_SSLVERSION_SSLv2` — SSL 2 (rejected: rustls cannot do < TLS 1.2).
pub const CURL_SSLVERSION_SSLV2: u32 = 2;
/// `CURL_SSLVERSION_SSLv3` — SSL 3 (rejected: rustls cannot do < TLS 1.2).
pub const CURL_SSLVERSION_SSLV3: u32 = 3;
/// `CURL_SSLVERSION_TLSv1_0` — TLS 1.0 (clamped up to TLS 1.2 by rustls).
pub const CURL_SSLVERSION_TLSV1_0: u32 = 4;
/// `CURL_SSLVERSION_TLSv1_1` — TLS 1.1 (clamped up to TLS 1.2 by rustls).
pub const CURL_SSLVERSION_TLSV1_1: u32 = 5;
/// `CURL_SSLVERSION_TLSv1_2` — TLS 1.2.
pub const CURL_SSLVERSION_TLSV1_2: u32 = 6;
/// `CURL_SSLVERSION_TLSv1_3` — TLS 1.3.
pub const CURL_SSLVERSION_TLSV1_3: u32 = 7;
/// `CURL_SSLVERSION_LAST` — one past the last defined value (never a valid input).
pub const CURL_SSLVERSION_LAST: u32 = 8;

// ---- CURL_SSLVERSION_MAX_* — maximum TLS version (high 16 bits) -------------
/// `CURL_SSLVERSION_MAX_NONE` — no explicit maximum.
pub const CURL_SSLVERSION_MAX_NONE: u32 = 0;
/// `CURL_SSLVERSION_MAX_DEFAULT` — `CURL_SSLVERSION_TLSv1 << 16` (the default).
pub const CURL_SSLVERSION_MAX_DEFAULT: u32 = 1 << 16;
/// `CURL_SSLVERSION_MAX_TLSv1_0` — `CURL_SSLVERSION_TLSv1_0 << 16`.
pub const CURL_SSLVERSION_MAX_TLSV1_0: u32 = 4 << 16;
/// `CURL_SSLVERSION_MAX_TLSv1_1` — `CURL_SSLVERSION_TLSv1_1 << 16`.
pub const CURL_SSLVERSION_MAX_TLSV1_1: u32 = 5 << 16;
/// `CURL_SSLVERSION_MAX_TLSv1_2` — `CURL_SSLVERSION_TLSv1_2 << 16`.
pub const CURL_SSLVERSION_MAX_TLSV1_2: u32 = 6 << 16;
/// `CURL_SSLVERSION_MAX_TLSv1_3` — `CURL_SSLVERSION_TLSv1_3 << 16`.
pub const CURL_SSLVERSION_MAX_TLSV1_3: u32 = 7 << 16;

// ---- CURLSSLOPT_* — CURLOPT_SSL_OPTIONS bit flags --------------------------
/// `CURLSSLOPT_ALLOW_BEAST` — tolerate the BEAST workaround (no-op under rustls).
#[allow(clippy::identity_op)]
pub const CURLSSLOPT_ALLOW_BEAST: u32 = 1 << 0;
/// `CURLSSLOPT_NO_REVOKE` — disable certificate-revocation checks.
pub const CURLSSLOPT_NO_REVOKE: u32 = 1 << 1;
/// `CURLSSLOPT_NO_PARTIALCHAIN` — refuse to accept partial certificate chains.
pub const CURLSSLOPT_NO_PARTIALCHAIN: u32 = 1 << 2;
/// `CURLSSLOPT_REVOKE_BEST_EFFORT` — ignore missing/offline revocation info.
pub const CURLSSLOPT_REVOKE_BEST_EFFORT: u32 = 1 << 3;
/// `CURLSSLOPT_NATIVE_CA` — use the OS native CA store (see verifier tree note).
pub const CURLSSLOPT_NATIVE_CA: u32 = 1 << 4;
/// `CURLSSLOPT_AUTO_CLIENT_CERT` — auto-select a client certificate (Schannel).
pub const CURLSSLOPT_AUTO_CLIENT_CERT: u32 = 1 << 5;
/// `CURLSSLOPT_EARLYDATA` — permit TLS 1.3 early data (0-RTT).
pub const CURLSSLOPT_EARLYDATA: u32 = 1 << 6;

/// Upper bound on the size of a pinned-public-key file (`MAX_PINNED_PUBKEY_SIZE`
/// in `lib/vtls/vtls.h`): 1 MiB. A larger file is rejected rather than read.
pub const MAX_PINNED_PUBKEY_SIZE: usize = 1_048_576;

// =============================================================================
// TlsConfig — the curl TLS configuration surface
// =============================================================================

/// The per-transfer TLS configuration, mirroring curl's `ssl_primary_config`
/// and the relevant parts of `ssl_config_data`.
///
/// Every field maps to a specific `CURLOPT_*` option; the field documentation
/// names the option. Instances are produced by [`TlsConfig::default`] (which
/// installs curl's defaults — crucially **validation on**) and then mutated by
/// `crate::setopt` as the application sets options. The terminal operation is
/// [`build_client_config`](TlsConfig::build_client_config), which consumes the
/// configuration to produce a ready-to-use [`rustls::ClientConfig`].
///
/// The struct is re-exported as `crate::tls::TlsConfig`.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Minimum TLS version (`CURLOPT_SSLVERSION`, low 16 bits). One of the
    /// `CURL_SSLVERSION_*` constants. Default [`CURL_SSLVERSION_DEFAULT`].
    pub version: u32,
    /// Maximum TLS version (`CURLOPT_SSLVERSION`, high 16 bits). One of the
    /// `CURL_SSLVERSION_MAX_*` constants. Default [`CURL_SSLVERSION_MAX_DEFAULT`].
    pub version_max: u32,
    /// `CURLOPT_SSL_VERIFYPEER` — verify the peer's certificate chain. Default
    /// **`true`** (validation on).
    pub verify_peer: bool,
    /// `CURLOPT_SSL_VERIFYHOST` — verify the certificate's name matches the
    /// host. Default **`true`** (validation on). Modelled as a bool: curl's `2`
    /// (and historical `1`) map to `true`, `0` to `false`.
    pub verify_host: bool,
    /// `CURLOPT_SSL_VERIFYSTATUS` — require a stapled OCSP response. Default
    /// `false`. (rustls does not staple-verify; tracked for parity / reporting.)
    pub verify_status: bool,
    /// `CURLOPT_CAINFO` — path to a PEM bundle of trusted CA certificates.
    pub ca_file: Option<std::path::PathBuf>,
    /// `CURLOPT_CAPATH` — directory of hashed CA certificates. Tracked for
    /// parity; rustls consumes a single bundle, so a directory is not loaded
    /// here (documented divergence).
    pub ca_path: Option<std::path::PathBuf>,
    /// `CURLOPT_CAINFO_BLOB` — in-memory PEM CA bundle. **Overrides**
    /// [`ca_file`](Self::ca_file) when both are set.
    pub ca_info_blob: Option<Vec<u8>>,
    /// `CURLOPT_ISSUERCERT` — issuer certificate to match against the peer.
    /// Tracked for parity.
    pub issuer_cert: Option<std::path::PathBuf>,
    /// `CURLOPT_CRLFILE` — certificate revocation list (PEM or DER).
    pub crl_file: Option<std::path::PathBuf>,
    /// `CURLOPT_SSL_CIPHER_LIST` — TLS 1.2 cipher selection (best-effort under
    /// rustls; see [`build_client_config`](Self::build_client_config)).
    pub cipher_list: Option<String>,
    /// `CURLOPT_TLS13_CIPHERS` — TLS 1.3 cipher selection (best-effort).
    pub cipher_list13: Option<String>,
    /// `CURLOPT_SSLCERT` — client certificate (PEM).
    pub client_cert: Option<std::path::PathBuf>,
    /// `CURLOPT_SSLKEY` — client private key (PEM).
    pub client_key: Option<std::path::PathBuf>,
    /// `CURLOPT_KEYPASSWD` — passphrase for an encrypted client key. See the
    /// limitation note in [`build_client_config`](Self::build_client_config).
    pub key_passwd: Option<String>,
    /// `CURLOPT_SSLCERTTYPE` — client-certificate format ("PEM"/"DER"). Tracked
    /// for parity; rustls consumes PEM/DER directly.
    pub cert_type: Option<String>,
    /// `CURLOPT_SSLKEYTYPE` — client-key format. Tracked for parity.
    pub key_type: Option<String>,
    /// `CURLOPT_SSL_OPTIONS` — the raw `CURLSSLOPT_*` bit set. The derived
    /// booleans [`native_ca_store`](Self::native_ca_store) and
    /// [`early_data`](Self::early_data) are kept in sync via
    /// [`set_ssl_options`](Self::set_ssl_options).
    pub ssl_options: u32,
    /// `CURLOPT_PINNEDPUBLICKEY` — a `sha256//<base64>[;…]` hash list, or a path
    /// to a DER/PEM public-key file. Checked post-handshake by
    /// [`verify_pinned_pubkey`].
    pub pinned_pubkey: Option<String>,
    /// Set when `CURLSSLOPT_NATIVE_CA` is present in
    /// [`ssl_options`](Self::ssl_options).
    pub native_ca_store: bool,
    /// Set when `CURLSSLOPT_EARLYDATA` is present in
    /// [`ssl_options`](Self::ssl_options). Gates `enable_early_data`.
    pub early_data: bool,
    /// TLS session-resumption (`CURLOPT_SSL_SESSIONID_CACHE`). Default
    /// **`true`** (resumption enabled when a session store is supplied).
    pub sessionid: bool,
}

impl Default for TlsConfig {
    /// curl's default TLS configuration. The non-obvious defaults — and the ones
    /// that matter most for security parity — are `verify_peer = true`,
    /// `verify_host = true` and `sessionid = true`.
    fn default() -> Self {
        Self {
            version: CURL_SSLVERSION_DEFAULT,
            version_max: CURL_SSLVERSION_MAX_DEFAULT,
            verify_peer: true,
            verify_host: true,
            verify_status: false,
            ca_file: None,
            ca_path: None,
            ca_info_blob: None,
            issuer_cert: None,
            crl_file: None,
            cipher_list: None,
            cipher_list13: None,
            client_cert: None,
            client_key: None,
            key_passwd: None,
            cert_type: None,
            key_type: None,
            ssl_options: 0,
            pinned_pubkey: None,
            native_ca_store: false,
            early_data: false,
            sessionid: true,
        }
    }
}

impl TlsConfig {
    /// Returns a [`TlsConfig`] with curl's defaults (alias for
    /// [`Default::default`]).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores the raw `CURLOPT_SSL_OPTIONS` value and keeps the derived
    /// [`native_ca_store`](Self::native_ca_store) / [`early_data`](Self::early_data)
    /// booleans in sync, matching curl's setopt handling.
    pub fn set_ssl_options(&mut self, options: u32) {
        self.ssl_options = options;
        self.native_ca_store = options & CURLSSLOPT_NATIVE_CA != 0;
        self.early_data = options & CURLSSLOPT_EARLYDATA != 0;
    }

    /// Resolves the curl min/max version selectors to the concrete list of
    /// rustls protocol versions, reproducing `init_config_builder`'s clamping.
    ///
    /// rustls supports only TLS 1.2 and TLS 1.3, so:
    /// * Any minimum below TLS 1.2 (DEFAULT, TLSv1, TLSv1_0, TLSv1_1, TLSv1_2)
    ///   resolves to a TLS 1.2 floor — sub-1.2 requests are silently clamped
    ///   **up** to 1.2 rather than erroring (curl's rustls binding does the
    ///   same). A minimum of TLS 1.3 resolves to a 1.3-only set.
    /// * Only SSLv2 / SSLv3 (and any out-of-range selector) are rejected with
    ///   `CURLE_BAD_FUNCTION_ARGUMENT`.
    /// * A maximum below the resolved minimum (e.g. `MAX_TLSv1_2` with a 1.3
    ///   floor, or any `MAX_TLSv1_1`/`MAX_TLSv1_0`) is an impossible window and
    ///   is rejected with `CURLE_BAD_FUNCTION_ARGUMENT`.
    fn resolve_versions(&self) -> crate::error::Result<Vec<&'static SupportedProtocolVersion>> {
        // The selector lives in the low 16 bits; mask defensively in case a
        // combined CURLOPT_SSLVERSION value was stored.
        let min_token = self.version & 0xffff;
        let min_is_tls13 = match min_token {
            CURL_SSLVERSION_DEFAULT
            | CURL_SSLVERSION_TLSV1
            | CURL_SSLVERSION_TLSV1_0
            | CURL_SSLVERSION_TLSV1_1
            | CURL_SSLVERSION_TLSV1_2 => false,
            CURL_SSLVERSION_TLSV1_3 => true,
            // SSLv2/SSLv3 cannot be honored by rustls and are hard errors, as
            // are LAST and any unknown selector.
            _ => return Err(CurlError::BadFunctionArgument),
        };

        // The maximum selector lives in the high 16 bits.
        let max_token = self.version_max & 0xffff_0000;
        let versions: Vec<&'static SupportedProtocolVersion> = match max_token {
            // No ceiling below 1.3: keep the full window from the resolved floor.
            CURL_SSLVERSION_MAX_NONE
            | CURL_SSLVERSION_MAX_DEFAULT
            | CURL_SSLVERSION_MAX_TLSV1_3 => {
                if min_is_tls13 {
                    vec![&rustls::version::TLS13]
                } else {
                    vec![&rustls::version::TLS12, &rustls::version::TLS13]
                }
            }
            // Ceiling of TLS 1.2: only valid when the floor is also 1.2.
            CURL_SSLVERSION_MAX_TLSV1_2 => {
                if min_is_tls13 {
                    return Err(CurlError::BadFunctionArgument);
                }
                vec![&rustls::version::TLS12]
            }
            // Ceilings below TLS 1.2 are impossible under rustls.
            _ => return Err(CurlError::BadFunctionArgument),
        };
        Ok(versions)
    }
}

// =============================================================================
// Crypto provider
// =============================================================================

/// Guards one-time installation of the process-wide default [`CryptoProvider`].
static PROVIDER_INIT: Once = Once::new();

/// Installs the process-wide default crypto provider exactly once.
///
/// This workspace links **both** the `aws_lc_rs` and `ring` rustls backends
/// (the latter is pulled in transitively by `quinn` for HTTP/3), which makes the
/// zero-argument [`ClientConfig::builder`] ambiguous and panicky at runtime. We
/// resolve the ambiguity deterministically by installing `aws_lc_rs` as the
/// process default and always building via
/// [`ClientConfig::builder_with_provider`]. The installation is idempotent and
/// coordinates with global init in `easy.rs`/`lib.rs`; a late or duplicate call
/// is harmless (the `Err` from a second `install_default` is ignored).
fn install_default_provider() {
    PROVIDER_INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Returns the process-wide default crypto provider, installing it first if
/// necessary. Falls back to a freshly constructed `aws_lc_rs` provider in the
/// (practically unreachable) event no default is registered.
fn provider() -> Arc<CryptoProvider> {
    install_default_provider();
    CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
}

// =============================================================================
// Cipher selection (best-effort, AAP §0.3.2: cipher_suite.c is out of scope)
// =============================================================================

/// Normalizes a cipher token/name for comparison: uppercased, with every
/// non-alphanumeric character removed. This lets `TLS_AES_128_GCM_SHA256` and
/// `TLS-AES-128-GCM-SHA256` compare equal.
fn normalize_cipher(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Splits a curl cipher list into individual tokens. curl accepts `:`, `,`, and
/// whitespace as separators across its various backends.
fn split_cipher_tokens(list: &str) -> Vec<String> {
    list.split([':', ',', ' ', '\t', '\n', '\r'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(normalize_cipher)
        .collect()
}

/// Returns the "core" of a normalized cipher name by stripping a leading `TLS`
/// followed by any version digits. This lets rustls' TLS 1.3 names (e.g.
/// `TLS13_AES_128_GCM_SHA256` → `AES128GCMSHA256`) match curl's standard IANA
/// names (e.g. `TLS_AES_128_GCM_SHA256` → `AES128GCMSHA256`), whose only
/// difference is the `TLS13` vs `TLS` prefix.
fn cipher_core(norm: &str) -> &str {
    norm.strip_prefix("TLS")
        .unwrap_or(norm)
        .trim_start_matches(|c: char| c.is_ascii_digit())
}

/// Returns `true` if `suite` matches any token in `tokens`, by numeric suite id
/// (decimal or `0x` hex), normalized IANA name (exact or substring), or
/// version-prefix-insensitive "core" name.
fn cipher_suite_matches(suite: rustls::SupportedCipherSuite, tokens: &[String]) -> bool {
    let iana = suite.suite();
    let id = u16::from(iana);
    let name_norm = iana.as_str().map(normalize_cipher);
    for token in tokens {
        // Numeric id match (e.g. "0x1301" or "4865").
        if let Some(hex) = token.strip_prefix("0X") {
            if let Ok(v) = u16::from_str_radix(hex, 16) {
                if v == id {
                    return true;
                }
            }
        }
        if let Ok(v) = token.parse::<u16>() {
            if v == id {
                return true;
            }
        }
        // Name match: exact normalized equality, the token appears within the
        // normalized IANA name, or the version-insensitive cores are equal
        // (best-effort, mirroring curl's lenient parsing).
        if let Some(name) = &name_norm {
            if name == token
                || (token.len() >= 4 && name.contains(token.as_str()))
                || cipher_core(name) == cipher_core(token)
            {
                return true;
            }
        }
    }
    false
}

/// Applies the curl cipher selectors to `base`, returning a provider whose
/// `cipher_suites` are filtered to the requested set.
///
/// Behavior mirrors curl's lenient cipher handling: when neither selector is
/// set the provider is returned unchanged (rustls' full default suite set);
/// when a selector is set, the suites for that TLS version are filtered to the
/// matching ones while suites for the *other* version are left intact (a TLS 1.2
/// selector does not disable TLS 1.3 suites and vice versa). Unknown tokens are
/// skipped with a log note rather than erroring. If the final set is empty the
/// call fails with `CURLE_SSL_CIPHER`.
///
/// Fine-grained TLS 1.2 cipher control is inherently limited to the suites
/// rustls supports.
fn apply_cipher_selection(
    base: Arc<CryptoProvider>,
    cipher_list: Option<&str>,
    cipher_list13: Option<&str>,
) -> crate::error::Result<Arc<CryptoProvider>> {
    if cipher_list.is_none() && cipher_list13.is_none() {
        return Ok(base);
    }

    let tokens12 = cipher_list.map(split_cipher_tokens);
    let tokens13 = cipher_list13.map(split_cipher_tokens);

    let mut selected: Vec<rustls::SupportedCipherSuite> = Vec::new();
    for suite in &base.cipher_suites {
        let is_tls13 = suite.version().version == rustls::ProtocolVersion::TLSv1_3;
        let tokens = if is_tls13 { &tokens13 } else { &tokens12 };
        match tokens {
            // A selector was provided for this version: keep only matches.
            Some(tokens) => {
                if cipher_suite_matches(*suite, tokens) {
                    selected.push(*suite);
                } else {
                    tracing::debug!(
                        suite = ?suite.suite(),
                        "skipping cipher suite not in requested list"
                    );
                }
            }
            // No selector for this version: keep all of its suites.
            None => selected.push(*suite),
        }
    }

    if selected.is_empty() {
        tracing::warn!("cipher selection produced an empty suite set");
        return Err(CurlError::SslCipher);
    }

    let mut new_provider = (*base).clone();
    new_provider.cipher_suites = selected;
    Ok(Arc::new(new_provider))
}

// =============================================================================
// Custom certificate verifiers (safe Rust — no `unsafe`)
// =============================================================================

/// The accept-all verifier — curl's `cr_verify_none`.
///
/// This is the **non-default** verifier installed only when the caller has
/// explicitly disabled peer verification (`CURLOPT_SSL_VERIFYPEER=0` /
/// `--insecure`). Every verification method returns success. The mandatory
/// stderr warning about disabled verification is curl's responsibility at the
/// CLI edge (`curl-rs`); this type only models the disabled state. It still
/// reports the provider's real signature schemes so the handshake can proceed.
#[derive(Debug)]
struct NoServerVerify {
    /// Signature schemes advertised during the handshake (from the provider).
    schemes: Vec<SignatureScheme>,
}

impl NoServerVerify {
    /// Builds an accept-all verifier that advertises `provider`'s signature
    /// schemes.
    fn new(provider: &CryptoProvider) -> Self {
        Self {
            schemes: provider
                .signature_verification_algorithms
                .supported_schemes(),
        }
    }
}

impl ServerCertVerifier for NoServerVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

/// A verifier that performs full chain/time/signature validation but suppresses
/// the hostname check — curl's `CURLOPT_SSL_VERIFYHOST=0` with
/// `CURLOPT_SSL_VERIFYPEER=1`.
///
/// rustls' standard [`WebPkiServerVerifier`] always checks the certificate name
/// against the server name, with no opt-out. To reproduce curl's "validate the
/// chain but ignore the name" mode, this wrapper delegates everything to an
/// inner verifier and treats *only* a hostname-mismatch
/// ([`CertificateError::NotValidForName`] / `NotValidForNameContext`) as
/// success. Every other error — expiry, untrusted issuer, bad signature —
/// propagates unchanged. All non-`verify_server_cert` work is delegated
/// verbatim to the inner verifier.
#[derive(Debug)]
struct NoHostnameVerify {
    /// The real verifier whose hostname result is suppressed.
    inner: Arc<dyn ServerCertVerifier>,
}

impl ServerCertVerifier for NoHostnameVerify {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            // Suppress *only* the name-mismatch outcome (verify_host=0).
            Err(Error::InvalidCertificate(CertificateError::NotValidForName))
            | Err(Error::InvalidCertificate(CertificateError::NotValidForNameContext { .. })) => {
                tracing::debug!("suppressing certificate name mismatch (verify_host=0)");
                Ok(ServerCertVerified::assertion())
            }
            // Everything else (expiry, trust, revocation, signature) propagates.
            Err(other) => Err(other),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }
}

// =============================================================================
// Root store / certificate parsing helpers
// =============================================================================

/// Parses zero or more PEM certificates from `pem` into owned
/// [`CertificateDer`]s. A parse error maps to `CURLE_SSL_CACERT_BADFILE`.
fn parse_pem_certs(pem: &[u8]) -> crate::error::Result<Vec<CertificateDer<'static>>> {
    CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CurlError::SslCacertBadfile)
}

/// Builds a [`RootCertStore`] pre-loaded with the bundled `webpki-roots` trust
/// anchors (Mozilla's CA set). This is the default trust source and the
/// documented fallback for the native-CA request.
fn webpki_root_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

impl TlsConfig {
    /// Builds the custom root store for the explicit-CA verifier path (case 3).
    ///
    /// `CURLOPT_CAINFO_BLOB` overrides `CURLOPT_CAINFO` when both are set — the
    /// blob's PEM bytes are used and the file is ignored, matching curl's
    /// `ssl_cafile = blob ? NULL : cafile`. An unreadable file, an unparseable
    /// bundle, or a bundle with no certificates yields
    /// `CURLE_SSL_CACERT_BADFILE`.
    fn build_explicit_root_store(&self) -> crate::error::Result<RootCertStore> {
        let pem_bytes: Vec<u8> = if let Some(blob) = &self.ca_info_blob {
            blob.clone()
        } else if let Some(path) = &self.ca_file {
            std::fs::read(path).map_err(|_| CurlError::SslCacertBadfile)?
        } else {
            // This method is only invoked when at least one CA source is set.
            return Err(CurlError::SslCacertBadfile);
        };

        let certs = parse_pem_certs(&pem_bytes)?;
        if certs.is_empty() {
            return Err(CurlError::SslCacertBadfile);
        }
        let mut roots = RootCertStore::empty();
        for cert in certs {
            roots.add(cert).map_err(|_| CurlError::SslCacertBadfile)?;
        }
        Ok(roots)
    }

    /// Builds the default trust store (case 4): the bundled `webpki-roots` plus
    /// an optional `SSL_CERT_FILE` passthrough.
    ///
    /// curl inherits OpenSSL's `SSL_CERT_FILE` handling (AAP §0.8.3); when the
    /// variable is set we additionally load that PEM file's certificates as
    /// trust anchors. This is best-effort: an unreadable or empty file is logged
    /// and ignored rather than failing the build, keeping the resolver robust.
    fn default_root_store(&self) -> RootCertStore {
        let mut roots = webpki_root_store();
        if let Some(path) = std::env::var_os("SSL_CERT_FILE") {
            match std::fs::read(&path) {
                Ok(bytes) => match parse_pem_certs(&bytes) {
                    Ok(certs) if !certs.is_empty() => {
                        let mut added = 0usize;
                        for cert in certs {
                            if roots.add(cert).is_ok() {
                                added += 1;
                            }
                        }
                        tracing::debug!(added, "loaded additional roots from SSL_CERT_FILE");
                    }
                    _ => {
                        tracing::warn!("SSL_CERT_FILE set but contained no usable certificates");
                    }
                },
                Err(e) => tracing::warn!(error = %e, "failed to read SSL_CERT_FILE; ignoring"),
            }
        }
        roots
    }

    /// Loads the CRLs named by `CURLOPT_CRLFILE`, accepting PEM or DER.
    ///
    /// Returns an empty vector when no CRL is configured. A read or parse
    /// failure maps to `CURLE_SSL_CRL_BADFILE`. A file with no PEM CRL blocks is
    /// treated as a single DER-encoded CRL.
    fn load_crls(&self) -> crate::error::Result<Vec<CertificateRevocationListDer<'static>>> {
        let Some(path) = &self.crl_file else {
            return Ok(Vec::new());
        };
        let bytes = std::fs::read(path).map_err(|_| CurlError::SslCrlBadfile)?;

        let pem_crls: Vec<CertificateRevocationListDer<'static>> = {
            CertificateRevocationListDer::pem_slice_iter(bytes.as_slice())
                .collect::<Result<_, _>>()
                .map_err(|_| CurlError::SslCrlBadfile)?
        };
        if !pem_crls.is_empty() {
            return Ok(pem_crls);
        }
        // No PEM CRL blocks: interpret the whole file as a single DER CRL.
        Ok(vec![CertificateRevocationListDer::from(bytes)])
    }

    /// Constructs the server-certificate verifier per curl's `cr_init_backend`
    /// decision tree (cases 1–4), then applies the `verify_host=0` wrapper when
    /// requested.
    ///
    /// Priority order (exactly as curl):
    /// 1. `!verify_peer` → accept-all [`NoServerVerify`] (the only insecure path).
    /// 2. `native_ca_store` → documented `webpki-roots` fallback (no native-certs
    ///    dependency).
    /// 3. `ca_info_blob` or `ca_file` → custom [`RootCertStore`] (+ optional CRL),
    ///    blob overriding file.
    /// 4. otherwise → bundled `webpki-roots` + `SSL_CERT_FILE` passthrough.
    fn build_verifier(
        &self,
        provider: &Arc<CryptoProvider>,
    ) -> crate::error::Result<Arc<dyn ServerCertVerifier>> {
        // (2d.1) Verification disabled — the sole insecure path.
        if !self.verify_peer {
            tracing::debug!("peer certificate verification disabled");
            return Ok(Arc::new(NoServerVerify::new(provider)));
        }

        // (2d.2 / 2d.3 / 2d.4) Build a WebPki verifier from the chosen roots.
        // Annotating the binding as the trait object lets each `if` arm's
        // `Arc<WebPkiServerVerifier>` unsize-coerce at the binding site.
        let webpki: Arc<dyn ServerCertVerifier> = if self.native_ca_store {
            // (2d.2) Native CA store requested.
            //
            // NOTE: This workspace intentionally carries NO `rustls-native-certs`
            // and NO platform-verifier dependency (HARD TLS RULE, AAP §0.8.1).
            // curl would consult the OS trust store here; we document the
            // divergence and fall back to the bundled `webpki-roots`, which is
            // identical to the default path (case 4 minus SSL_CERT_FILE).
            tracing::info!(
                "native CA store requested; using bundled webpki-roots \
                 (no native-certs dependency)"
            );
            let roots = webpki_root_store();
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .map_err(|_| CurlError::SslCacertBadfile)?
        } else if self.ca_info_blob.is_some() || self.ca_file.is_some() {
            // (2d.3) Explicit CA bundle (+ optional CRL); blob overrides file.
            let roots = self.build_explicit_root_store()?;
            let crls = self.load_crls()?;
            let builder =
                WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone());
            let builder = if crls.is_empty() {
                builder
            } else {
                builder.with_crls(crls)
            };
            builder.build().map_err(|_| CurlError::SslCacertBadfile)?
        } else {
            // (2d.4) Default trust: webpki-roots + SSL_CERT_FILE passthrough.
            let roots = self.default_root_store();
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .map_err(|_| CurlError::SslCacertBadfile)?
        };

        // (2e) verify_host=0 with verify_peer=1: keep chain validation but
        // suppress the hostname check.
        if self.verify_host {
            Ok(webpki)
        } else {
            Ok(Arc::new(NoHostnameVerify { inner: webpki }))
        }
    }

    /// Loads the client certificate chain and private key for mutual TLS
    /// (case 2f, curl's `init_config_builder_client_auth`).
    ///
    /// Returns `Ok(None)` when neither a cert nor a key is configured. curl
    /// requires both or neither: a lone cert or lone key, an unreadable/empty
    /// cert, or an unparseable key all map to `CURLE_SSL_CERTPROBLEM`.
    ///
    /// NOTE: the `rustls-pki-types` PEM decoder does not decrypt encrypted
    /// private keys, so a `CURLOPT_KEYPASSWD`-protected key cannot be loaded
    /// here. This is a known, documented limitation; the curl regression suite
    /// predominantly uses unencrypted keys.
    #[allow(clippy::type_complexity)]
    fn load_client_auth(
        &self,
    ) -> crate::error::Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>> {
        match (&self.client_cert, &self.client_key) {
            (None, None) => Ok(None),
            // curl: "must provide key with certificate" / "...certificate with key".
            (Some(_), None) | (None, Some(_)) => Err(CurlError::SslCertproblem),
            (Some(cert_path), Some(key_path)) => {
                let cert_bytes = std::fs::read(cert_path).map_err(|_| CurlError::SslCertproblem)?;
                let certs: Vec<CertificateDer<'static>> = {
                    CertificateDer::pem_slice_iter(cert_bytes.as_slice())
                        .collect::<Result<_, _>>()
                        .map_err(|_| CurlError::SslCertproblem)?
                };
                if certs.is_empty() {
                    return Err(CurlError::SslCertproblem);
                }

                let key_bytes = std::fs::read(key_path).map_err(|_| CurlError::SslCertproblem)?;
                // `PrivateKeyDer::from_pem_slice` returns the first private key of any
                // supported kind (PKCS#8 / PKCS#1 / SEC1), matching the old
                // `rustls_pemfile::private_key`; `Error::NoItemsFound` (no key present)
                // and any decode error both map to `SslCertproblem`, exactly as before.
                let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_slice(key_bytes.as_slice())
                    .map_err(|_| CurlError::SslCertproblem)?;
                Ok(Some((certs, key)))
            }
        }
    }

    /// Translates this configuration into a ready-to-use
    /// [`rustls::ClientConfig`], reproducing the operation order of curl's
    /// `init_config_builder` → `cr_init_backend`.
    ///
    /// `alpn` is the ordered list of ALPN wire-byte protocol identifiers
    /// (computed by `crate::tls`/`mod.rs`; e.g. `b"h2"`, `b"http/1.1"`).
    /// `session_store` is an optional rustls session store for TLS resumption
    /// (per-easy or shared via `crate::share`); when `None` (or when
    /// [`sessionid`](Self::sessionid) is `false`) resumption is disabled.
    ///
    /// # Errors
    ///
    /// * `CURLE_BAD_FUNCTION_ARGUMENT` — an unsupported TLS version selector.
    /// * `CURLE_SSL_CIPHER` — a cipher list that selects no supported suite.
    /// * `CURLE_SSL_CACERT_BADFILE` — a CA bundle that cannot be read/parsed.
    /// * `CURLE_SSL_CRL_BADFILE` — a CRL file that cannot be read/parsed.
    /// * `CURLE_SSL_CERTPROBLEM` — a client cert/key problem (incl. lone cert/key).
    pub fn build_client_config(
        &self,
        alpn: &[Vec<u8>],
        session_store: Option<Arc<dyn ClientSessionStore>>,
    ) -> crate::error::Result<Arc<ClientConfig>> {
        // (2b) Resolve versions first — this can reject SSLv2/SSLv3 or an
        // impossible max<min window before any allocation.
        let versions = self.resolve_versions()?;

        // (2a) Crypto provider, then (2c) best-effort cipher selection (which
        // can reject an empty resulting suite set).
        let base_provider = provider();
        let selected_provider = apply_cipher_selection(
            base_provider,
            self.cipher_list.as_deref(),
            self.cipher_list13.as_deref(),
        )?;

        // Version-configured builder over the (possibly cipher-filtered) provider.
        let builder = ClientConfig::builder_with_provider(selected_provider.clone())
            .with_protocol_versions(&versions)
            .map_err(map_rustls_error)?;

        // (2d/2e) Verifier decision tree + optional hostname suppression.
        let verifier = self.build_verifier(&selected_provider)?;
        let builder = builder
            .dangerous()
            .with_custom_certificate_verifier(verifier);

        // (2f) Client authentication — both cert+key, or neither.
        let mut config = match self.load_client_auth()? {
            Some((certs, key)) => builder
                .with_client_auth_cert(certs, key)
                .map_err(|_| CurlError::SslCertproblem)?,
            None => builder.with_no_client_auth(),
        };

        // (2g) ALPN — consume the ordered wire-byte list computed by tls::mod.
        config.alpn_protocols = alpn.to_vec();

        // (2h) Key log — honors SSLKEYLOGFILE; NoKeyLog when unset.
        config.key_log = key_log();

        // (2i) Session resumption + early data (0-RTT).
        config.resumption = match (self.sessionid, session_store) {
            (true, Some(store)) => Resumption::store(store),
            _ => Resumption::disabled(),
        };
        config.enable_early_data = self.early_data;

        // (2j) ECH (Encrypted Client Hello) — intentionally omitted.
        // NOTE: curl's `init_config_builder_ech` is `#ifdef USE_ECH`. ECH is not
        // required for curl test-suite parity and is not configured here; it can
        // be added later behind a non-default Cargo feature without changing
        // this surface.

        Ok(Arc::new(config))
    }
}

// =============================================================================
// Pinned public key (CURLOPT_PINNEDPUBLICKEY)
// =============================================================================

/// Prefix that marks the hash-list form of `CURLOPT_PINNEDPUBLICKEY`.
const PINNED_SHA256_PREFIX: &str = "sha256//";

/// Verifies the peer's Subject Public Key Info against `CURLOPT_PINNEDPUBLICKEY`,
/// reproducing curl's `Curl_pin_peer_pubkey` (`lib/vtls/vtls.c`).
///
/// `pinned` is either:
/// * a `sha256//<base64>` hash list (one or more entries separated by `;`) — the
///   SHA-256 digest of `peer_spki_der` is base64-encoded and compared to each
///   entry; a match on **any** entry succeeds; or
/// * a filesystem path to a DER- or PEM-encoded public key — the file's
///   SubjectPublicKeyInfo DER is compared byte-for-byte to `peer_spki_der`. The
///   file is capped at [`MAX_PINNED_PUBKEY_SIZE`] (1 MiB).
///
/// `peer_spki_der` is the DER-encoded SubjectPublicKeyInfo of the negotiated
/// end-entity certificate, supplied by `crate::tls`/`mod.rs`. Because rustls
/// exposes no pre-handshake pinning hook, this check necessarily runs **after**
/// the handshake completes.
///
/// # Errors
///
/// Returns `CURLE_SSL_PINNEDPUBKEYNOTMATCH` when no pin matches (or the file is
/// missing/oversized/unreadable).
pub fn verify_pinned_pubkey(pinned: &str, peer_spki_der: &[u8]) -> crate::error::Result<()> {
    // ---- Hash-list form: sha256//<base64>[;sha256//<base64>...] -------------
    if pinned.starts_with(PINNED_SHA256_PREFIX) {
        // Compute base64(SHA-256(SPKI)) once and compare to every entry.
        let digest = sha256it(peer_spki_der);
        let our_b64 = base64_encode(&digest).map_err(|_| CurlError::OutOfMemory)?;
        for entry in pinned.split(';') {
            let entry = entry.trim();
            // Each entry must carry the sha256// marker; ignore stray tokens.
            let Some(want) = entry.strip_prefix(PINNED_SHA256_PREFIX) else {
                continue;
            };
            let want = want.trim();
            if want.is_empty() {
                continue;
            }
            if want.as_bytes() == our_b64.as_slice() {
                return Ok(());
            }
        }
        return Err(CurlError::SslPinnedpubkeynotmatch);
    }

    // ---- File form: a DER or PEM public key, capped at 1 MiB ---------------
    let path = Path::new(pinned);
    // Reject oversized files up front via metadata, then guard again post-read.
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > MAX_PINNED_PUBKEY_SIZE as u64 {
            return Err(CurlError::SslPinnedpubkeynotmatch);
        }
    }
    let bytes = std::fs::read(path).map_err(|_| CurlError::SslPinnedpubkeynotmatch)?;
    if bytes.len() > MAX_PINNED_PUBKEY_SIZE {
        return Err(CurlError::SslPinnedpubkeynotmatch);
    }

    // Extract the SPKI DER: prefer a PEM "PUBLIC KEY" block; otherwise treat the
    // whole file as raw DER (matching curl's PEM-or-DER acceptance).
    let spki_der: Vec<u8> = {
        let keys: Vec<_> = SubjectPublicKeyInfoDer::pem_slice_iter(bytes.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_default();
        match keys.into_iter().next() {
            Some(spki) => spki.as_ref().to_vec(),
            None => bytes.clone(),
        }
    };

    if spki_der.as_slice() == peer_spki_der {
        Ok(())
    } else {
        Err(CurlError::SslPinnedpubkeynotmatch)
    }
}

// =============================================================================
// rustls error → CurlError mapping (curl's `map_error` analog)
// =============================================================================

/// Maps a [`rustls::Error`] from the handshake to the corresponding
/// [`CurlError`], used by `crate::tls`/`mod.rs` to translate `tokio-rustls`
/// connect failures.
///
/// All certificate-validation failures — expiry, name mismatch, revocation,
/// unknown/untrusted issuer, bad signature, malformed encoding — collapse to
/// `CURLE_PEER_FAILED_VERIFICATION`. (curl `#define`s `CURLE_SSL_CACERT` to the
/// same integer `60`, so issuer/CA-trust failures share this code.) Every other
/// handshake, protocol, or transport error maps to `CURLE_SSL_CONNECT_ERROR`.
pub(crate) fn map_rustls_error(e: rustls::Error) -> CurlError {
    match e {
        Error::InvalidCertificate(_) => CurlError::PeerFailedVerification,
        _ => CurlError::SslConnectError,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ProtocolVersion;
    use std::io::Write;

    // ---- helpers -----------------------------------------------------------

    /// Resolves `cfg` to the concrete list of [`ProtocolVersion`]s (or its error).
    fn pv_list(cfg: &TlsConfig) -> crate::error::Result<Vec<ProtocolVersion>> {
        Ok(cfg.resolve_versions()?.iter().map(|v| v.version).collect())
    }

    /// Generates a fresh self-signed cert + key PEM pair for tests.
    fn self_signed() -> (String, String) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen self-signed");
        (ck.cert.pem(), ck.signing_key.serialize_pem())
    }

    /// Writes `bytes` to a fresh temp file and returns the handle (kept alive by
    /// the caller) and its path.
    fn temp_with(bytes: &[u8]) -> (tempfile::NamedTempFile, std::path::PathBuf) {
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        f.write_all(bytes).expect("write temp");
        f.flush().expect("flush temp");
        let p = f.path().to_path_buf();
        (f, p)
    }

    // ---- (b) defaults: validation ON --------------------------------------

    #[test]
    fn default_has_validation_on() {
        let c = TlsConfig::default();
        assert!(c.verify_peer, "verify_peer must default true");
        assert!(c.verify_host, "verify_host must default true");
        assert!(c.sessionid, "sessionid must default true");
        assert!(!c.verify_status, "verify_status must default false");
        assert_eq!(c.version, CURL_SSLVERSION_DEFAULT);
        assert_eq!(c.version_max, CURL_SSLVERSION_MAX_DEFAULT);
        // `new()` is an alias of `default()`.
        let n = TlsConfig::new();
        assert!(n.verify_peer && n.verify_host && n.sessionid);
    }

    #[test]
    fn set_ssl_options_tracks_native_ca_and_earlydata() {
        let mut c = TlsConfig::default();
        c.set_ssl_options(CURLSSLOPT_NATIVE_CA | CURLSSLOPT_EARLYDATA);
        assert!(c.native_ca_store);
        assert!(c.early_data);
        assert_eq!(c.ssl_options, CURLSSLOPT_NATIVE_CA | CURLSSLOPT_EARLYDATA);

        let mut c2 = TlsConfig::default();
        c2.set_ssl_options(CURLSSLOPT_NO_REVOKE);
        assert!(!c2.native_ca_store);
        assert!(!c2.early_data);
    }

    // ---- (a) version mapping table ----------------------------------------

    #[test]
    fn version_min_sub_tls12_clamps_up_to_tls12() {
        // DEFAULT, TLSv1, TLSv1_0, TLSv1_1, TLSv1_2 all resolve to [TLS1.2, TLS1.3].
        for min in [
            CURL_SSLVERSION_DEFAULT,
            CURL_SSLVERSION_TLSV1,
            CURL_SSLVERSION_TLSV1_0,
            CURL_SSLVERSION_TLSV1_1,
            CURL_SSLVERSION_TLSV1_2,
        ] {
            let c = TlsConfig {
                version: min,
                ..Default::default()
            };
            assert_eq!(
                pv_list(&c).unwrap(),
                vec![ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3],
                "min selector {min} should clamp to TLS1.2 floor"
            );
        }
    }

    #[test]
    fn version_min_tls13_is_tls13_only() {
        let c = TlsConfig {
            version: CURL_SSLVERSION_TLSV1_3,
            ..Default::default()
        };
        assert_eq!(pv_list(&c).unwrap(), vec![ProtocolVersion::TLSv1_3]);
    }

    #[test]
    fn version_sslv2_sslv3_and_out_of_range_error() {
        for min in [
            CURL_SSLVERSION_SSLV2,
            CURL_SSLVERSION_SSLV3,
            CURL_SSLVERSION_LAST,
        ] {
            let c = TlsConfig {
                version: min,
                ..Default::default()
            };
            assert_eq!(
                pv_list(&c).unwrap_err(),
                CurlError::BadFunctionArgument,
                "min selector {min} must be rejected"
            );
        }
    }

    #[test]
    fn version_max_none_default_tls13_keep_full_range() {
        for max in [
            CURL_SSLVERSION_MAX_NONE,
            CURL_SSLVERSION_MAX_DEFAULT,
            CURL_SSLVERSION_MAX_TLSV1_3,
        ] {
            let c = TlsConfig {
                version_max: max,
                ..Default::default()
            };
            assert_eq!(
                pv_list(&c).unwrap(),
                vec![ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3],
                "max selector {max} should keep the full window"
            );
        }
    }

    #[test]
    fn version_max_tls12_with_tls12_min_restricts_to_tls12() {
        let c = TlsConfig {
            version: CURL_SSLVERSION_TLSV1_2,
            version_max: CURL_SSLVERSION_MAX_TLSV1_2,
            ..Default::default()
        };
        assert_eq!(pv_list(&c).unwrap(), vec![ProtocolVersion::TLSv1_2]);
    }

    #[test]
    fn version_max_tls12_with_tls13_min_errors() {
        let c = TlsConfig {
            version: CURL_SSLVERSION_TLSV1_3,
            version_max: CURL_SSLVERSION_MAX_TLSV1_2,
            ..Default::default()
        };
        assert_eq!(pv_list(&c).unwrap_err(), CurlError::BadFunctionArgument);
    }

    #[test]
    fn version_max_below_tls12_errors() {
        for max in [CURL_SSLVERSION_MAX_TLSV1_0, CURL_SSLVERSION_MAX_TLSV1_1] {
            let c = TlsConfig {
                version_max: max,
                ..Default::default()
            };
            assert_eq!(
                pv_list(&c).unwrap_err(),
                CurlError::BadFunctionArgument,
                "max selector {max} must be rejected"
            );
        }
    }

    // ---- (c) verifier selection / config building -------------------------

    #[test]
    fn default_config_builds_with_webpki_roots() {
        let c = TlsConfig::default();
        let cfg = c
            .build_client_config(&[b"http/1.1".to_vec()], None)
            .expect("default config should build");
        assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn insecure_config_builds() {
        let c = TlsConfig {
            verify_peer: false,
            ..Default::default()
        };
        assert!(
            c.build_client_config(&[], None).is_ok(),
            "verify_peer=false (dangerous path) must build"
        );
    }

    #[test]
    fn verify_host_false_builds() {
        let c = TlsConfig {
            verify_host: false,
            ..Default::default()
        };
        assert!(
            c.build_client_config(&[], None).is_ok(),
            "verify_host=false wrapper must build"
        );
    }

    #[test]
    fn native_ca_store_falls_back_and_builds() {
        let mut c = TlsConfig::default();
        c.set_ssl_options(CURLSSLOPT_NATIVE_CA);
        assert!(c.native_ca_store);
        assert!(
            c.build_client_config(&[], None).is_ok(),
            "native CA fallback to webpki-roots must build"
        );
    }

    #[test]
    fn cainfo_blob_builds_custom_roots() {
        let (cert_pem, _key) = self_signed();
        let c = TlsConfig {
            ca_info_blob: Some(cert_pem.into_bytes()),
            ..Default::default()
        };
        assert!(c.build_client_config(&[], None).is_ok());
    }

    #[test]
    fn cainfo_file_builds_custom_roots() {
        let (cert_pem, _key) = self_signed();
        let (_f, path) = temp_with(cert_pem.as_bytes());
        let c = TlsConfig {
            ca_file: Some(path),
            ..Default::default()
        };
        assert!(c.build_client_config(&[], None).is_ok());
    }

    #[test]
    fn cainfo_blob_overrides_file() {
        // Valid blob + bogus file → blob wins → Ok (file ignored).
        let (cert_pem, _key) = self_signed();
        let c = TlsConfig {
            ca_info_blob: Some(cert_pem.into_bytes()),
            ca_file: Some(std::path::PathBuf::from("/nonexistent/ignored-ca.pem")),
            ..Default::default()
        };
        assert!(c.build_client_config(&[], None).is_ok());
    }

    #[test]
    fn cainfo_missing_file_errors() {
        let c = TlsConfig {
            ca_file: Some(std::path::PathBuf::from("/nonexistent/ca-bundle.pem")),
            ..Default::default()
        };
        assert_eq!(
            c.build_client_config(&[], None).unwrap_err(),
            CurlError::SslCacertBadfile
        );
    }

    #[test]
    fn cainfo_empty_blob_errors() {
        let c = TlsConfig {
            ca_info_blob: Some(b"not a pem certificate".to_vec()),
            ..Default::default()
        };
        assert_eq!(
            c.build_client_config(&[], None).unwrap_err(),
            CurlError::SslCacertBadfile
        );
    }

    // ---- (e) client auth: both-or-error -----------------------------------

    #[test]
    fn client_auth_only_cert_errors() {
        let c = TlsConfig {
            client_cert: Some(std::path::PathBuf::from("/some/cert.pem")),
            ..Default::default()
        };
        assert_eq!(
            c.build_client_config(&[], None).unwrap_err(),
            CurlError::SslCertproblem
        );
    }

    #[test]
    fn client_auth_only_key_errors() {
        let c = TlsConfig {
            client_key: Some(std::path::PathBuf::from("/some/key.pem")),
            ..Default::default()
        };
        assert_eq!(
            c.build_client_config(&[], None).unwrap_err(),
            CurlError::SslCertproblem
        );
    }

    #[test]
    fn client_auth_matching_pair_ok() {
        let (cert_pem, key_pem) = self_signed();
        let (_cf, cert_path) = temp_with(cert_pem.as_bytes());
        let (_kf, key_path) = temp_with(key_pem.as_bytes());
        let c = TlsConfig {
            client_cert: Some(cert_path),
            client_key: Some(key_path),
            ..Default::default()
        };
        let r = c.build_client_config(&[], None);
        assert!(
            r.is_ok(),
            "matching client cert/key must build: {:?}",
            r.err()
        );
    }

    // ---- (d) pinned public key --------------------------------------------

    #[test]
    fn pinned_sha256_single_match_and_mismatch() {
        let spki = b"example-subject-public-key-info-bytes";
        let b64 = String::from_utf8(base64_encode(&sha256it(spki)).unwrap()).unwrap();
        let good = format!("sha256//{b64}");
        assert!(verify_pinned_pubkey(&good, spki).is_ok());

        let bad = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert_eq!(
            verify_pinned_pubkey(bad, spki).unwrap_err(),
            CurlError::SslPinnedpubkeynotmatch
        );
    }

    #[test]
    fn pinned_sha256_multi_entry_any_match() {
        let spki = b"multi-entry-spki-payload";
        let b64 = String::from_utf8(base64_encode(&sha256it(spki)).unwrap()).unwrap();
        // First entry wrong, second correct → Ok.
        let pin = format!("sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=;sha256//{b64}");
        assert!(verify_pinned_pubkey(&pin, spki).is_ok());

        // All entries wrong → error.
        let pin_bad =
            "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=;sha256//BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=";
        assert_eq!(
            verify_pinned_pubkey(pin_bad, spki).unwrap_err(),
            CurlError::SslPinnedpubkeynotmatch
        );
    }

    #[test]
    fn pinned_file_der_match_and_mismatch() {
        let spki = b"raw-der-spki-bytes-for-pin-test";
        let (_f, path) = temp_with(spki);
        let p = path.to_str().unwrap();
        assert!(verify_pinned_pubkey(p, spki).is_ok());
        assert_eq!(
            verify_pinned_pubkey(p, b"a-different-spki").unwrap_err(),
            CurlError::SslPinnedpubkeynotmatch
        );
    }

    #[test]
    fn pinned_file_oversize_errors() {
        let spki = b"spki";
        let big = vec![0u8; MAX_PINNED_PUBKEY_SIZE + 1];
        let (_f, path) = temp_with(&big);
        assert_eq!(
            verify_pinned_pubkey(path.to_str().unwrap(), spki).unwrap_err(),
            CurlError::SslPinnedpubkeynotmatch
        );
    }

    #[test]
    fn pinned_file_missing_errors() {
        assert_eq!(
            verify_pinned_pubkey("/nonexistent/pinned.der", b"spki").unwrap_err(),
            CurlError::SslPinnedpubkeynotmatch
        );
    }

    // ---- cipher selection (best-effort) -----------------------------------

    #[test]
    fn cipher_no_selection_keeps_all() {
        let p = provider();
        let total = p.cipher_suites.len();
        let out = apply_cipher_selection(p.clone(), None, None).unwrap();
        assert_eq!(out.cipher_suites.len(), total);
    }

    #[test]
    fn cipher_all_garbage_errors() {
        let p = provider();
        assert_eq!(
            apply_cipher_selection(p, Some("NOSUCHCIPHER12"), Some("ALSO_GARBAGE_XYZ"))
                .unwrap_err(),
            CurlError::SslCipher
        );
    }

    #[test]
    fn cipher_valid_tls13_name_selects() {
        let p = provider();
        // TLS1.3 list set to a known suite (curl's standard name); TLS1.2 list
        // unset, so all TLS1.2 suites are retained.
        let out = apply_cipher_selection(p, None, Some("TLS_AES_128_GCM_SHA256")).unwrap();
        assert!(
            out.cipher_suites
                .iter()
                .any(|s| s.suite().as_str() == Some("TLS13_AES_128_GCM_SHA256")),
            "expected TLS13_AES_128_GCM_SHA256 to survive selection"
        );
    }

    // ---- map_rustls_error --------------------------------------------------

    #[test]
    fn map_error_certificate_failures() {
        for ce in [
            CertificateError::UnknownIssuer,
            CertificateError::Expired,
            CertificateError::NotValidForName,
        ] {
            assert_eq!(
                map_rustls_error(Error::InvalidCertificate(ce)),
                CurlError::PeerFailedVerification
            );
        }
    }

    #[test]
    fn map_error_other_is_connect_error() {
        assert_eq!(
            map_rustls_error(Error::General("boom".to_string())),
            CurlError::SslConnectError
        );
        assert_eq!(
            map_rustls_error(Error::NoCertificatesPresented),
            CurlError::SslConnectError
        );
    }
}
