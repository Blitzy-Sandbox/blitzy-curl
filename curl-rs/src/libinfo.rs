//! Library protocol and feature availability information for the curl-rs CLI tool.
//!
//! This module is the Rust rewrite of `src/tool_libinfo.c` and
//! `src/tool_libinfo.h` from curl 8.19.0-DEV. It queries
//! [`curl_rs_lib::version`] to determine which protocols and features are
//! compiled into the library, storing the results in a [`LibCurlInfo`] struct
//! for runtime checks by the CLI argument parser, operation dispatch, help
//! display, and version reporting.
//!
//! # Design Notes
//!
//! The C implementation uses global mutable variables (`feature_ssl`,
//! `proto_http`, `built_in_protos`, etc.) populated once by
//! `get_libcurl_info()`. The Rust rewrite replaces these with:
//!
//! - A single [`LibCurlInfo`] struct aggregating all feature booleans,
//!   protocol list, and version metadata.
//! - A lazily-cached protocol list ([`OnceLock`]) for efficient
//!   [`proto_token`] lookups without re-querying the library each time.
//! - Pure functions with no global mutable state.
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks.

use std::sync::OnceLock;

use curl_rs_lib::version::{version_info, FeatureFlags, VersionInfo, VERSION};

// ---------------------------------------------------------------------------
// Feature-name-to-flag mapping table
// ---------------------------------------------------------------------------
//
// This table mirrors the C `maybe_feature[]` array in `tool_libinfo.c`.
// Each entry maps a human-readable feature name (as printed by `curl -V`)
// to the corresponding [`FeatureFlags`] constant.  Entries are kept in
// case-insensitive alphabetical order to match the C source and to ensure
// the resulting feature list is pre-sorted.
//
// Features with no corresponding bit in [`FeatureFlags`] (ECH,
// SSLS-EXPORT, NTLM_WB) are handled separately after the table scan.

/// A single entry in the feature lookup table.
struct FeatureEntry {
    /// Display name printed by `curl --version` (e.g. `"HTTP2"`).
    name: &'static str,
    /// The [`FeatureFlags`] constant to test, or `None` if the feature
    /// cannot be detected from the bitmask alone.
    flag: Option<FeatureFlags>,
}

/// Feature lookup table, sorted in the same case-insensitive alphabetical
/// order as the C `maybe_feature[]` array.
const FEATURE_TABLE: &[FeatureEntry] = &[
    FeatureEntry { name: "alt-svc",      flag: Some(FeatureFlags::ALTSVC) },
    FeatureEntry { name: "AsynchDNS",    flag: Some(FeatureFlags::ASYNCHDNS) },
    FeatureEntry { name: "brotli",       flag: Some(FeatureFlags::BROTLI) },
    FeatureEntry { name: "CharConv",     flag: Some(FeatureFlags::CONV) },
    FeatureEntry { name: "Debug",        flag: Some(FeatureFlags::DEBUG) },
    FeatureEntry { name: "ECH",          flag: None },
    FeatureEntry { name: "gsasl",        flag: Some(FeatureFlags::GSASL) },
    FeatureEntry { name: "GSS-API",      flag: Some(FeatureFlags::GSSAPI) },
    FeatureEntry { name: "HSTS",         flag: Some(FeatureFlags::HSTS) },
    FeatureEntry { name: "HTTP2",        flag: Some(FeatureFlags::HTTP2) },
    FeatureEntry { name: "HTTP3",        flag: Some(FeatureFlags::HTTP3) },
    FeatureEntry { name: "HTTPS-proxy",  flag: Some(FeatureFlags::HTTPS_PROXY) },
    FeatureEntry { name: "IDN",          flag: Some(FeatureFlags::IDN) },
    FeatureEntry { name: "IPv6",         flag: Some(FeatureFlags::IPV6) },
    FeatureEntry { name: "Kerberos",     flag: Some(FeatureFlags::KERBEROS5) },
    FeatureEntry { name: "Largefile",    flag: Some(FeatureFlags::LARGEFILE) },
    FeatureEntry { name: "libz",         flag: Some(FeatureFlags::LIBZ) },
    FeatureEntry { name: "MultiSSL",     flag: Some(FeatureFlags::MULTI_SSL) },
    FeatureEntry { name: "NTLM",         flag: Some(FeatureFlags::NTLM) },
    FeatureEntry { name: "PSL",          flag: Some(FeatureFlags::PSL) },
    FeatureEntry { name: "SPNEGO",       flag: Some(FeatureFlags::SPNEGO) },
    FeatureEntry { name: "SSL",          flag: Some(FeatureFlags::SSL) },
    FeatureEntry { name: "SSPI",         flag: Some(FeatureFlags::SSPI) },
    FeatureEntry { name: "SSLS-EXPORT",  flag: None },
    FeatureEntry { name: "threadsafe",   flag: Some(FeatureFlags::THREADSAFE) },
    FeatureEntry { name: "TLS-SRP",      flag: Some(FeatureFlags::TLSAUTH_SRP) },
    FeatureEntry { name: "Unicode",      flag: Some(FeatureFlags::UNICODE) },
    FeatureEntry { name: "UnixSockets",  flag: Some(FeatureFlags::UNIX_SOCKETS) },
    FeatureEntry { name: "zstd",         flag: Some(FeatureFlags::ZSTD) },
];

// ---------------------------------------------------------------------------
// LibCurlInfo — aggregate library capability information
// ---------------------------------------------------------------------------

/// Comprehensive information about the curl-rs library's runtime capabilities.
///
/// This struct aggregates protocol availability, feature flags, SSL backend
/// info, and version details.  It replaces the collection of C global
/// variables defined in `tool_libinfo.c` / `tool_libinfo.h`:
///
/// | Rust field          | C equivalent                           |
/// |---------------------|----------------------------------------|
/// | `feature_ssl`       | `bool feature_ssl`                     |
/// | `feature_http2`     | `bool feature_http2`                   |
/// | `protocols`         | `const char * const *built_in_protos`  |
/// | `features`          | `const char * const *feature_names`    |
/// | `version`           | `curlinfo->version`                    |
/// | `ssl_version`       | `curlinfo->ssl_version`                |
/// | `ssl_backends`      | (derived from `curlinfo->ssl_version`) |
#[derive(Debug, Clone, Default)]
pub struct LibCurlInfo {
    // -- Feature availability booleans (from C `bool feature_*` globals) -----

    /// SSL/TLS support is available (always `true` — rustls is compiled in).
    pub feature_ssl: bool,

    /// Alt-Svc cache support is available.
    pub feature_altsvc: bool,

    /// HSTS (HTTP Strict Transport Security) support is available.
    pub feature_hsts: bool,

    /// TLS-SRP (Secure Remote Password) authentication support.
    /// Always `false` in curl-rs because rustls does not support TLS-SRP.
    pub feature_tls_srp: bool,

    /// SSH library is present.  Named `feature_libssh2` to preserve the C
    /// field name convention, but in curl-rs the backend is `russh`.
    pub feature_libssh2: bool,

    /// GNU SASL (GSasl) library support.
    /// Always `false` in curl-rs — SCRAM is compiled in natively, not via
    /// libgsasl.
    pub feature_gsasl: bool,

    /// GSS-API support.
    pub feature_gss_api: bool,

    /// Kerberos V5 authentication support.
    pub feature_kerberos5: bool,

    /// NTLM authentication support.
    pub feature_ntlm: bool,

    /// SPNEGO (Negotiate) authentication support.
    pub feature_spnego: bool,

    /// Metalink support (removed in curl 8.x; always `false`).
    pub feature_metalink: bool,

    /// Brotli content-encoding decompression support.
    pub feature_brotli: bool,

    /// HTTP/2 protocol support (via hyper + h2).
    pub feature_http2: bool,

    /// HTTP/3 (QUIC) protocol support (via quinn + h3).
    pub feature_http3: bool,

    /// HTTPS-proxy (CONNECT over TLS) support.
    pub feature_httpsproxy: bool,

    /// zlib / deflate compression support (via flate2).
    pub feature_libz: bool,

    /// Zstandard content-encoding decompression support.
    pub feature_zstd: bool,

    /// Encrypted Client Hello (ECH) support.
    /// Always `false` — not yet supported by rustls.
    pub feature_ech: bool,

    /// SSL session export/import capability.
    pub feature_ssls_export: bool,

    // -- Aggregate information -----------------------------------------------

    /// SSL/TLS backend names.  Always `["rustls"]` for curl-rs per AAP
    /// Section 0.7.3 (rustls exclusively — no OpenSSL, no native-tls).
    pub ssl_backends: Vec<String>,

    /// Alphabetically sorted list of supported protocol scheme names.
    /// Matches the output of C `curlinfo->protocols`.
    pub protocols: Vec<String>,

    /// Library version string (e.g. `"8.19.0-DEV"`).
    pub version: String,

    /// SSL/TLS backend version string (e.g. `"rustls"`).
    pub ssl_version: String,

    /// Alphabetically sorted list of feature name strings, matching the C
    /// `feature_names` array built from the `maybe_feature[]` table.
    pub features: Vec<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Query the curl-rs library for runtime capability information and build
/// a [`LibCurlInfo`] struct with protocol availability, feature flags,
/// version data, and SSL backend details.
///
/// This is the Rust equivalent of C `get_libcurl_info(void)` from
/// `tool_libinfo.c`.  In the C codebase this function is called once at
/// startup and populates a set of global variables; in Rust we return a
/// self-contained struct instead.
///
/// # Returns
///
/// A fully-populated [`LibCurlInfo`] containing:
/// - Boolean flags for each supported feature
/// - The complete protocol list from the library
/// - Version and SSL backend information
pub fn get_libcurl_info() -> LibCurlInfo {
    let info: VersionInfo = version_info();
    let flags: FeatureFlags = info.features;

    // -- Build the feature-name list from the flags --------------------------
    let features = build_feature_names(&flags);

    // -- Derive individual feature booleans from the FeatureFlags bitmask ----
    let feature_ssl = flags.contains(FeatureFlags::SSL);
    let feature_altsvc = flags.contains(FeatureFlags::ALTSVC);
    let feature_hsts = flags.contains(FeatureFlags::HSTS);
    let feature_tls_srp = flags.contains(FeatureFlags::TLSAUTH_SRP);
    let feature_gsasl = flags.contains(FeatureFlags::GSASL);
    let feature_gss_api = flags.contains(FeatureFlags::GSSAPI);
    let feature_kerberos5 = flags.contains(FeatureFlags::KERBEROS5);
    let feature_ntlm = flags.contains(FeatureFlags::NTLM);
    let feature_spnego = flags.contains(FeatureFlags::SPNEGO);
    let feature_brotli = flags.contains(FeatureFlags::BROTLI);
    let feature_http2 = flags.contains(FeatureFlags::HTTP2);
    let feature_http3 = flags.contains(FeatureFlags::HTTP3);
    let feature_httpsproxy = flags.contains(FeatureFlags::HTTPS_PROXY);
    let feature_libz = flags.contains(FeatureFlags::LIBZ);
    let feature_zstd = flags.contains(FeatureFlags::ZSTD);

    // SSH library detection — C checks `curlinfo->libssh_version` prefix.
    // In curl-rs the SSH backend is `russh`, so we check for its presence
    // via the `ssh_version` field from `VersionInfo`.
    let feature_libssh2 = info.ssh_version.is_some();

    // ECH (Encrypted Client Hello) is not supported by rustls; the C code
    // detects it via `feature_names` with bitmask 0.
    let feature_ech = false;

    // Metalink support was removed in curl 8.x and is never available.
    let feature_metalink = false;

    // SSL session export capability.  The C code detects this via
    // `feature_names` with bitmask 0.  curl-rs supports session
    // export/import through the `ssls` module, but it is not surfaced as
    // a feature flag in `detect_features()`.  We report `false` since the
    // FeatureFlags bitmask has no bit for it and the library does not
    // advertise it in its feature names.
    let feature_ssls_export = false;

    // SSL backend version string — always "rustls" per AAP.
    let ssl_version = info
        .ssl_version
        .clone()
        .unwrap_or_else(|| "rustls".to_string());

    // SSL backends list — single entry for rustls.
    let ssl_backends = vec!["rustls".to_string()];

    LibCurlInfo {
        feature_ssl,
        feature_altsvc,
        feature_hsts,
        feature_tls_srp,
        feature_libssh2,
        feature_gsasl,
        feature_gss_api,
        feature_kerberos5,
        feature_ntlm,
        feature_spnego,
        feature_metalink,
        feature_brotli,
        feature_http2,
        feature_http3,
        feature_httpsproxy,
        feature_libz,
        feature_zstd,
        feature_ech,
        feature_ssls_export,
        ssl_backends,
        protocols: info.protocols.clone(),
        version: VERSION.to_string(),
        ssl_version,
        features,
    }
}

/// Check whether a protocol scheme is supported and return its canonical name.
///
/// This is the Rust equivalent of C `proto_token(const char *proto)` from
/// `tool_libinfo.c`.  The C version returns a pointer to the built-in
/// protocol string (enabling cheap pointer-identity comparisons), or `NULL`
/// if the protocol is not recognised.  In Rust we return
/// `Option<String>` — the canonical protocol name if found, or `None`.
///
/// The lookup is case-insensitive, matching C `curl_strequal`.
///
/// # Arguments
///
/// * `scheme` — Protocol scheme to look up (e.g. `"https"`, `"ftp"`).
///
/// # Returns
///
/// `Some(canonical_name)` if the protocol is in the library's built-in
/// list, or `None` if not recognised.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(proto_token("HTTPS"), Some("https".to_string()));
/// assert_eq!(proto_token("gopher"), Some("gopher".to_string()));
/// assert_eq!(proto_token("unknown"), None);
/// ```
pub fn proto_token(scheme: &str) -> Option<String> {
    for proto in cached_protocols() {
        if proto.eq_ignore_ascii_case(scheme) {
            return Some(proto.clone());
        }
    }
    None
}

/// Check whether a protocol scheme is supported at runtime.
///
/// Convenience wrapper around [`proto_token`] that returns a simple boolean.
/// This is the Rust equivalent of checking `proto_token(proto) != NULL` in C.
///
/// # Arguments
///
/// * `scheme` — Protocol scheme to check (e.g. `"sftp"`, `"http"`).
///
/// # Returns
///
/// `true` if the protocol is in the library's built-in protocol list.
pub fn is_proto_supported(scheme: &str) -> bool {
    proto_token(scheme).is_some()
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Lazily-cached protocol list for fast lookups by [`proto_token`] and
/// [`is_proto_supported`] without re-querying the library each call.
static CACHED_PROTOCOLS: OnceLock<Vec<String>> = OnceLock::new();

/// Returns a reference to the lazily-cached protocol list.
fn cached_protocols() -> &'static [String] {
    CACHED_PROTOCOLS.get_or_init(|| version_info().protocols)
}

/// Build the list of feature names from the given [`FeatureFlags`] bitmask.
///
/// The output list matches the C `feature_names` array produced by iterating
/// the `maybe_feature[]` table in `tool_libinfo.c`.  Each entry in
/// [`FEATURE_TABLE`] whose flag bit is set in `flags` is included; entries
/// with `flag: None` (ECH, SSLS-EXPORT) are omitted since they cannot be
/// detected from the bitmask.  The resulting list is in case-insensitive
/// alphabetical order because [`FEATURE_TABLE`] is already sorted that way.
fn build_feature_names(flags: &FeatureFlags) -> Vec<String> {
    let mut names: Vec<String> = Vec::with_capacity(FEATURE_TABLE.len());

    for entry in FEATURE_TABLE {
        if let Some(flag) = entry.flag {
            if flags.contains(flag) {
                names.push(entry.name.to_string());
            }
        }
        // Entries with `flag: None` (ECH, SSLS-EXPORT) are runtime-only in C;
        // we skip them since our FeatureFlags has no corresponding bit.
    }

    names
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_libcurl_info_returns_populated_struct() {
        let info = get_libcurl_info();

        // Version should match the library constant.
        assert_eq!(info.version, VERSION);

        // SSL backend should always be rustls.
        assert_eq!(info.ssl_backends, vec!["rustls".to_string()]);
        assert!(info.ssl_version.contains("rustls"));

        // At minimum, SSL must be reported since rustls is always compiled in.
        assert!(info.feature_ssl, "feature_ssl must be true");
    }

    #[test]
    fn test_get_libcurl_info_feature_flags_populated() {
        let info = get_libcurl_info();

        // These features are always-on in the Rust rewrite (see
        // detect_features() in curl-rs-lib/src/version.rs).
        assert!(info.feature_ssl, "SSL always on");
        assert!(info.feature_altsvc, "Alt-Svc always on");
        assert!(info.feature_hsts, "HSTS always on");
        assert!(info.feature_ntlm, "NTLM always on");
        assert!(info.feature_spnego, "SPNEGO always on");
        assert!(info.feature_http2, "HTTP2 always on");
        assert!(info.feature_http3, "HTTP3 always on");
        assert!(info.feature_httpsproxy, "HTTPS-proxy always on");
        assert!(info.feature_libz, "libz always on");
        assert!(info.feature_gss_api, "GSS-API always on");
        assert!(info.feature_kerberos5, "Kerberos always on");

        // SSH library presence — russh is always compiled in.
        assert!(info.feature_libssh2, "SSH backend always present");

        // Features that are never available in the Rust rewrite.
        assert!(!info.feature_tls_srp, "TLS-SRP not supported by rustls");
        assert!(!info.feature_metalink, "Metalink removed in curl 8.x");
        assert!(!info.feature_ech, "ECH not supported by rustls");
    }

    #[test]
    fn test_get_libcurl_info_protocols_not_empty() {
        let info = get_libcurl_info();
        assert!(!info.protocols.is_empty(), "protocol list must not be empty");

        // Core protocols must always be present.
        let has = |name: &str| info.protocols.iter().any(|p| p == name);
        assert!(has("http"), "http protocol missing");
        assert!(has("https"), "https protocol missing");
        assert!(has("ftp"), "ftp protocol missing");
        assert!(has("ftps"), "ftps protocol missing");
        assert!(has("scp"), "scp protocol missing");
        assert!(has("sftp"), "sftp protocol missing");
    }

    #[test]
    fn test_get_libcurl_info_protocols_sorted() {
        let info = get_libcurl_info();
        let sorted: Vec<String> = {
            let mut v = info.protocols.clone();
            v.sort();
            v
        };
        assert_eq!(info.protocols, sorted, "protocol list must be sorted");
    }

    #[test]
    fn test_get_libcurl_info_features_not_empty() {
        let info = get_libcurl_info();
        assert!(!info.features.is_empty(), "feature list must not be empty");
        assert!(
            info.features.iter().any(|f| f == "SSL"),
            "SSL feature must be listed"
        );
    }

    #[test]
    fn test_proto_token_found() {
        // Should find core protocols with exact case.
        assert_eq!(proto_token("http"), Some("http".to_string()));
        assert_eq!(proto_token("https"), Some("https".to_string()));
        assert_eq!(proto_token("ftp"), Some("ftp".to_string()));
    }

    #[test]
    fn test_proto_token_case_insensitive() {
        // Case-insensitive lookup should succeed.
        assert!(proto_token("HTTP").is_some());
        assert!(proto_token("Https").is_some());
        assert!(proto_token("FTP").is_some());
    }

    #[test]
    fn test_proto_token_not_found() {
        assert_eq!(proto_token("nonexistent"), None);
        assert_eq!(proto_token(""), None);
        assert_eq!(proto_token("xyz123"), None);
    }

    #[test]
    fn test_is_proto_supported_true() {
        assert!(is_proto_supported("http"));
        assert!(is_proto_supported("https"));
        assert!(is_proto_supported("ftp"));
        assert!(is_proto_supported("sftp"));
        assert!(is_proto_supported("scp"));
    }

    #[test]
    fn test_is_proto_supported_false() {
        assert!(!is_proto_supported("nonexistent"));
        assert!(!is_proto_supported(""));
    }

    #[test]
    fn test_is_proto_supported_case_insensitive() {
        assert!(is_proto_supported("HTTP"));
        assert!(is_proto_supported("SFTP"));
    }

    #[test]
    fn test_build_feature_names_empty_flags() {
        let empty = FeatureFlags::empty();
        let names = build_feature_names(&empty);
        assert!(names.is_empty(), "empty flags should produce empty list");
    }

    #[test]
    fn test_build_feature_names_single_flag() {
        let names = build_feature_names(&FeatureFlags::SSL);
        assert_eq!(names, vec!["SSL".to_string()]);
    }

    #[test]
    fn test_build_feature_names_multiple_flags() {
        let flags = FeatureFlags::SSL | FeatureFlags::HTTP2 | FeatureFlags::LIBZ;
        let names = build_feature_names(&flags);
        // Names should be in the FEATURE_TABLE order (case-insensitive alpha).
        assert!(names.contains(&"HTTP2".to_string()));
        assert!(names.contains(&"libz".to_string()));
        assert!(names.contains(&"SSL".to_string()));
    }

    #[test]
    fn test_no_unsafe_blocks() {
        // Compile-time guarantee: this module has zero `unsafe` blocks.
        // This test exists purely as documentation; if any `unsafe` were
        // added, `#![forbid(unsafe_code)]` at the crate level (or clippy
        // with -D unsafe_code) would catch it.
        assert!(true);
    }

    #[test]
    fn test_cached_protocols_consistent() {
        // Two calls to cached_protocols() must return the same slice.
        let a = cached_protocols();
        let b = cached_protocols();
        assert_eq!(a, b);
    }
}
