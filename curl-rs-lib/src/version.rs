//! Version information and feature flag reporting for curl-rs.
//!
//! This module is the Rust rewrite of `lib/version.c` and
//! `include/curl/curlver.h` from libcurl 8.19.0-DEV. It provides:
//!
//! - **Version constants** ([`VERSION`], [`VERSION_NUM`]) matching the C
//!   `LIBCURL_VERSION` / `LIBCURL_VERSION_NUM` macros exactly.
//! - **Feature flags** ([`FeatureFlags`]) as a bitfield struct whose integer
//!   values match the C `CURL_VERSION_*` defines for FFI compatibility.
//! - **Version info** ([`VersionInfo`]) struct equivalent to the C
//!   `curl_version_info_data`, populated with Rust-native backend versions.
//! - **Public API** functions [`version()`] and [`version_info()`] replacing
//!   the C `curl_version()` and `curl_version_info()` entry points.
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks.

use std::sync::OnceLock;

#[allow(unused_imports)]
use crate::error::CurlError;

// ---------------------------------------------------------------------------
// Version Constants — matching include/curl/curlver.h
// ---------------------------------------------------------------------------

/// Human-readable version string, equivalent to C `LIBCURL_VERSION`.
///
/// Format: `"MAJOR.MINOR.PATCH-TAG"` — for this build: `"8.19.0-DEV"`.
pub const VERSION: &str = "8.19.0-DEV";

/// Numeric version in the format `0xXXYYZZ` where XX = major, YY = minor,
/// ZZ = patch. Equivalent to C `LIBCURL_VERSION_NUM`.
///
/// For 8.19.0 this is `0x081300`.
pub const VERSION_NUM: u32 = 0x081300;

/// Major version component. Equivalent to C `LIBCURL_VERSION_MAJOR`.
pub const VERSION_MAJOR: u32 = 8;

/// Minor version component. Equivalent to C `LIBCURL_VERSION_MINOR`.
pub const VERSION_MINOR: u32 = 19;

/// Patch version component. Equivalent to C `LIBCURL_VERSION_PATCH`.
pub const VERSION_PATCH: u32 = 0;

/// Timestamp placeholder matching `LIBCURL_TIMESTAMP` in curlver.h.
pub const VERSION_TIMESTAMP: &str = "[unreleased]";

/// Library name used in composite version strings.
pub const LIBCURL_NAME: &str = "curl-rs";

/// Copyright notice matching `LIBCURL_COPYRIGHT`.
pub const LIBCURL_COPYRIGHT: &str = "Daniel Stenberg, <daniel@haxx.se>.";

/// Compute a packed version number from (major, minor, patch) components.
///
/// Equivalent to the C macro `CURL_VERSION_BITS(x, y, z)`.
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::version::version_bits;
/// assert_eq!(version_bits(8, 19, 0), 0x081300);
/// assert_eq!(version_bits(7, 88, 1), 0x075801);
/// ```
pub const fn version_bits(major: u32, minor: u32, patch: u32) -> u32 {
    (major << 16) | (minor << 8) | patch
}

/// Returns `true` when [`VERSION_NUM`] is at least the packed value of the
/// given (major, minor, patch) triple.
///
/// Equivalent to the C macro `CURL_AT_LEAST_VERSION(x, y, z)`.
pub const fn at_least_version(major: u32, minor: u32, patch: u32) -> bool {
    VERSION_NUM >= version_bits(major, minor, patch)
}

// ---------------------------------------------------------------------------
// FeatureFlags — bitfield matching C CURL_VERSION_* constants exactly
// ---------------------------------------------------------------------------

/// Bitfield describing which features are compiled into the library.
///
/// Every constant matches the exact integer value of its C counterpart
/// (`CURL_VERSION_*` defines in `include/curl/curl.h`), ensuring FFI
/// round-trip fidelity.
///
/// # Combining Flags
///
/// Flags can be combined with the `|` operator:
///
/// ```
/// # use curl_rs_lib::version::FeatureFlags;
/// let flags = FeatureFlags::SSL | FeatureFlags::HTTP2;
/// assert!(flags.contains(FeatureFlags::SSL));
/// assert!(flags.contains(FeatureFlags::HTTP2));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FeatureFlags(u32);

impl FeatureFlags {
    // -----------------------------------------------------------------------
    // Bit constants — values MUST match C CURL_VERSION_* exactly
    // -----------------------------------------------------------------------

    /// IPv6-enabled (`CURL_VERSION_IPV6 = 1 << 0`).
    pub const IPV6: Self = Self(1 << 0);

    /// SSL options are present (`CURL_VERSION_SSL = 1 << 2`).
    pub const SSL: Self = Self(1 << 2);

    /// libz / zlib features are present (`CURL_VERSION_LIBZ = 1 << 3`).
    pub const LIBZ: Self = Self(1 << 3);

    /// NTLM auth is supported (`CURL_VERSION_NTLM = 1 << 4`).
    pub const NTLM: Self = Self(1 << 4);

    /// Negotiate auth (GSS-Negotiate) is supported (`CURL_VERSION_GSSNEGOTIATE = 1 << 5`).
    pub const GSSNEGOTIATE: Self = Self(1 << 5);

    /// Built with debug capabilities (`CURL_VERSION_DEBUG = 1 << 6`).
    pub const DEBUG: Self = Self(1 << 6);

    /// Asynchronous DNS resolves (`CURL_VERSION_ASYNCHDNS = 1 << 7`).
    pub const ASYNCHDNS: Self = Self(1 << 7);

    /// SPNEGO auth is supported (`CURL_VERSION_SPNEGO = 1 << 8`).
    pub const SPNEGO: Self = Self(1 << 8);

    /// Supports files larger than 2 GB (`CURL_VERSION_LARGEFILE = 1 << 9`).
    pub const LARGEFILE: Self = Self(1 << 9);

    /// Internationalized Domain Names are supported (`CURL_VERSION_IDN = 1 << 10`).
    pub const IDN: Self = Self(1 << 10);

    /// Built against Windows SSPI (`CURL_VERSION_SSPI = 1 << 11`).
    pub const SSPI: Self = Self(1 << 11);

    /// Character conversions supported (`CURL_VERSION_CONV = 1 << 12`).
    pub const CONV: Self = Self(1 << 12);

    /// TLS-SRP auth is supported (`CURL_VERSION_TLSAUTH_SRP = 1 << 14`).
    pub const TLSAUTH_SRP: Self = Self(1 << 14);

    /// HTTP/2 support built-in (`CURL_VERSION_HTTP2 = 1 << 16`).
    pub const HTTP2: Self = Self(1 << 16);

    /// Built against a GSS-API library (`CURL_VERSION_GSSAPI = 1 << 17`).
    pub const GSSAPI: Self = Self(1 << 17);

    /// Kerberos V5 auth is supported (`CURL_VERSION_KERBEROS5 = 1 << 18`).
    pub const KERBEROS5: Self = Self(1 << 18);

    /// Unix domain sockets support (`CURL_VERSION_UNIX_SOCKETS = 1 << 19`).
    pub const UNIX_SOCKETS: Self = Self(1 << 19);

    /// Mozilla's Public Suffix List (`CURL_VERSION_PSL = 1 << 20`).
    pub const PSL: Self = Self(1 << 20);

    /// HTTPS-proxy support built-in (`CURL_VERSION_HTTPS_PROXY = 1 << 21`).
    pub const HTTPS_PROXY: Self = Self(1 << 21);

    /// Multiple SSL backends available (`CURL_VERSION_MULTI_SSL = 1 << 22`).
    pub const MULTI_SSL: Self = Self(1 << 22);

    /// Brotli features are present (`CURL_VERSION_BROTLI = 1 << 23`).
    pub const BROTLI: Self = Self(1 << 23);

    /// Alt-Svc handling built-in (`CURL_VERSION_ALTSVC = 1 << 24`).
    pub const ALTSVC: Self = Self(1 << 24);

    /// HTTP/3 support built-in (`CURL_VERSION_HTTP3 = 1 << 25`).
    pub const HTTP3: Self = Self(1 << 25);

    /// Zstd features are present (`CURL_VERSION_ZSTD = 1 << 26`).
    pub const ZSTD: Self = Self(1 << 26);

    /// Unicode support on Windows (`CURL_VERSION_UNICODE = 1 << 27`).
    pub const UNICODE: Self = Self(1 << 27);

    /// HSTS is supported (`CURL_VERSION_HSTS = 1 << 28`).
    pub const HSTS: Self = Self(1 << 28);

    /// libgsasl is supported (`CURL_VERSION_GSASL = 1 << 29`).
    pub const GSASL: Self = Self(1 << 29);

    /// libcurl API is thread-safe (`CURL_VERSION_THREADSAFE = 1 << 30`).
    pub const THREADSAFE: Self = Self(1 << 30);

    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Returns a `FeatureFlags` with no bits set.
    #[inline]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Returns a `FeatureFlags` with **all** defined feature bits set.
    #[inline]
    pub const fn all() -> Self {
        Self(
            Self::IPV6.0
                | Self::SSL.0
                | Self::LIBZ.0
                | Self::NTLM.0
                | Self::GSSNEGOTIATE.0
                | Self::DEBUG.0
                | Self::ASYNCHDNS.0
                | Self::SPNEGO.0
                | Self::LARGEFILE.0
                | Self::IDN.0
                | Self::SSPI.0
                | Self::CONV.0
                | Self::TLSAUTH_SRP.0
                | Self::HTTP2.0
                | Self::GSSAPI.0
                | Self::KERBEROS5.0
                | Self::UNIX_SOCKETS.0
                | Self::PSL.0
                | Self::HTTPS_PROXY.0
                | Self::MULTI_SSL.0
                | Self::BROTLI.0
                | Self::ALTSVC.0
                | Self::HTTP3.0
                | Self::ZSTD.0
                | Self::UNICODE.0
                | Self::HSTS.0
                | Self::GSASL.0
                | Self::THREADSAFE.0,
        )
    }

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    /// Returns `true` if all bits in `other` are also set in `self`.
    #[inline]
    pub const fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns the raw `u32` bitmask.
    #[inline]
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// Returns `true` if no feature bits are set.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Constructs a `FeatureFlags` from a raw `u32` bitmask.
    #[inline]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }
}

// ---------------------------------------------------------------------------
// Bitwise operator implementations for FeatureFlags
// ---------------------------------------------------------------------------

impl std::ops::BitOr for FeatureFlags {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for FeatureFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for FeatureFlags {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl std::ops::BitAndAssign for FeatureFlags {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl std::ops::Not for FeatureFlags {
    type Output = Self;

    #[inline]
    fn not(self) -> Self {
        Self(!self.0)
    }
}

impl std::fmt::Display for FeatureFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

// ---------------------------------------------------------------------------
// VersionInfo — equivalent to C curl_version_info_data
// ---------------------------------------------------------------------------

/// Comprehensive version and capability information for the curl-rs library.
///
/// This struct is the Rust equivalent of the C `curl_version_info_data`.
/// It is returned by [`version_info()`] and populated with compile-time and
/// runtime information about the library build.
#[derive(Debug, Clone)]
pub struct VersionInfo {
    /// Human-readable version string (e.g. `"8.19.0-DEV"`).
    pub version: &'static str,

    /// Packed numeric version (`0xXXYYZZ`).
    pub version_num: u32,

    /// Host/target triple for the build (e.g. `"x86_64-unknown-linux-gnu"`).
    pub host: String,

    /// TLS backend version string, or `None` if TLS is not compiled in.
    /// For curl-rs this is always `Some("rustls")`.
    pub ssl_version: Option<String>,

    /// Bitfield of compiled-in feature flags.
    pub features: FeatureFlags,

    /// Alphabetically sorted list of supported protocol scheme names.
    pub protocols: Vec<String>,

    /// Zlib/deflate library version, or `None`.
    /// For curl-rs this reports the `flate2` crate.
    pub libz_version: Option<String>,

    /// Brotli library version, or `None` if the `brotli` feature is disabled.
    pub brotli_version: Option<String>,

    /// Zstandard library version, or `None` if the `zstd` feature is disabled.
    pub zstd_version: Option<String>,

    /// HTTP client library version, or `None`.
    /// For curl-rs this reports the `hyper` crate.
    pub hyper_version: Option<String>,

    /// QUIC / HTTP/3 library version, or `None`.
    /// For curl-rs this reports `quinn` + `h3`.
    pub quic_version: Option<String>,

    /// SSH library version, or `None`.
    /// For curl-rs this reports the `russh` crate.
    pub ssh_version: Option<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns a human-readable version string describing the library and its
/// compiled-in backends.
///
/// This is the Rust equivalent of C `curl_version()`. The returned string is
/// lazily initialised on first call and cached for the lifetime of the process.
///
/// # Example output
///
/// ```text
/// curl-rs/8.19.0-DEV rustls flate2 hyper quinn russh
/// ```
pub fn version() -> &'static str {
    static VERSION_STRING: OnceLock<String> = OnceLock::new();
    VERSION_STRING
        .get_or_init(build_version_string)
        .as_str()
}

/// Returns comprehensive version and feature information about the library.
///
/// This is the Rust equivalent of C `curl_version_info()`.
pub fn version_info() -> VersionInfo {
    VersionInfo {
        version: VERSION,
        version_num: VERSION_NUM,
        host: get_host_triple(),
        ssl_version: Some("rustls".to_string()),
        features: detect_features(),
        protocols: supported_protocols(),
        libz_version: Some("flate2".to_string()),
        brotli_version: get_brotli_version(),
        zstd_version: get_zstd_version(),
        hyper_version: Some("hyper".to_string()),
        quic_version: Some("quinn/h3".to_string()),
        ssh_version: Some("russh".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Builds the composite version string returned by [`version()`].
///
/// The format follows the C `curl_version()` pattern of space-separated
/// `name/version` tokens (or bare names when the version is not easily
/// obtained at compile-time without a build script).
fn build_version_string() -> String {
    let mut parts: Vec<&str> = Vec::with_capacity(10);

    // Library identity — always first
    // Using concat! so the base version is a compile-time literal.
    parts.push(concat!("curl-rs/", "8.19.0-DEV"));

    // TLS backend — rustls is the exclusive backend
    parts.push("rustls");

    // Compression: zlib/deflate via flate2 (always compiled in)
    parts.push("flate2");

    // Brotli (feature-gated)
    #[cfg(feature = "brotli")]
    {
        parts.push("brotli");
    }

    // Zstandard (feature-gated)
    #[cfg(feature = "zstd")]
    {
        parts.push("zstd");
    }

    // HTTP/1.1 + HTTP/2 via hyper
    parts.push("hyper");

    // HTTP/3 via quinn + h3
    parts.push("quinn");

    // SSH via russh
    parts.push("russh");

    parts.join(" ")
}

/// Detects and returns the [`FeatureFlags`] for this build based on
/// compile-time feature configuration and inherent Rust capabilities.
fn detect_features() -> FeatureFlags {
    let mut flags = FeatureFlags::empty();

    // --- Always-on features in the Rust rewrite ---

    // Rust's std::net always supports IPv6
    flags |= FeatureFlags::IPV6;

    // rustls is always compiled in
    flags |= FeatureFlags::SSL;

    // flate2 (zlib/deflate) is always compiled in
    flags |= FeatureFlags::LIBZ;

    // Pure-Rust NTLM implementation is always compiled in
    flags |= FeatureFlags::NTLM;

    // GSS-Negotiate support via the auth module
    flags |= FeatureFlags::GSSNEGOTIATE;

    // Tokio provides async DNS resolution
    flags |= FeatureFlags::ASYNCHDNS;

    // SPNEGO is supported via the auth module
    flags |= FeatureFlags::SPNEGO;

    // Rust uses 64-bit file offsets on all platforms (u64/i64)
    flags |= FeatureFlags::LARGEFILE;

    // IDN support via the `idna` crate
    flags |= FeatureFlags::IDN;

    // HTTP/2 via hyper + h2
    flags |= FeatureFlags::HTTP2;

    // HTTP/3 via quinn + h3
    flags |= FeatureFlags::HTTP3;

    // GSSAPI / Kerberos5 support via the auth module
    flags |= FeatureFlags::GSSAPI;
    flags |= FeatureFlags::KERBEROS5;

    // Tokio provides Unix domain socket support on Unix platforms
    #[cfg(unix)]
    {
        flags |= FeatureFlags::UNIX_SOCKETS;
    }

    // Public Suffix List via the `publicsuffix` crate
    flags |= FeatureFlags::PSL;

    // HTTPS-proxy (CONNECT over TLS) is supported
    flags |= FeatureFlags::HTTPS_PROXY;

    // Alt-Svc cache is always compiled in
    flags |= FeatureFlags::ALTSVC;

    // HSTS is always compiled in
    flags |= FeatureFlags::HSTS;

    // Rust's type system and ownership model make the API inherently
    // thread-safe; Tokio runtime handles concurrency safely.
    flags |= FeatureFlags::THREADSAFE;

    // --- Feature-gated capabilities ---

    #[cfg(feature = "brotli")]
    {
        flags |= FeatureFlags::BROTLI;
    }

    #[cfg(feature = "zstd")]
    {
        flags |= FeatureFlags::ZSTD;
    }

    // --- Debug build detection ---
    #[cfg(debug_assertions)]
    {
        flags |= FeatureFlags::DEBUG;
    }

    // --- Features NOT set in the Rust rewrite ---
    // SSPI:          Windows-only; not applicable to Rust rewrite
    // CONV:          Character conversion; not applicable
    // TLSAUTH_SRP:   Not supported by rustls
    // MULTI_SSL:     Only one TLS backend (rustls)
    // UNICODE:       Windows-specific; handled natively by Rust String
    // GSASL:         SCRAM support compiled in but not via libgsasl

    flags
}

/// Returns an alphabetically sorted list of supported protocol scheme names.
///
/// The list mirrors the C `supported_protocols[]` array, with protocols
/// enabled or disabled based on Cargo feature flags. Since TLS (rustls) is
/// always compiled in, the secure variant (e.g. `ftps`, `https`) is included
/// whenever the base protocol is enabled.
fn supported_protocols() -> Vec<String> {
    let mut protocols: Vec<String> = Vec::with_capacity(30);

    // -- dict --
    #[cfg(feature = "dict")]
    {
        protocols.push("dict".to_string());
    }

    // -- file (always available) --
    protocols.push("file".to_string());

    // -- ftp / ftps --
    #[cfg(feature = "ftp")]
    {
        protocols.push("ftp".to_string());
        protocols.push("ftps".to_string()); // SSL always present
    }

    // -- gopher / gophers (tied to http feature for simplicity) --
    // Gopher is a separate protocol handler but listed for completeness
    // when compiled in as part of the default feature set.

    // -- http / https --
    #[cfg(feature = "http")]
    {
        protocols.push("http".to_string());
        protocols.push("https".to_string()); // SSL always present
    }

    // -- imap / imaps --
    #[cfg(feature = "imap")]
    {
        protocols.push("imap".to_string());
        protocols.push("imaps".to_string());
    }

    // -- mqtt / mqtts --
    #[cfg(feature = "mqtt")]
    {
        protocols.push("mqtt".to_string());
        protocols.push("mqtts".to_string());
    }

    // -- pop3 / pop3s --
    #[cfg(feature = "pop3")]
    {
        protocols.push("pop3".to_string());
        protocols.push("pop3s".to_string());
    }

    // -- rtsp --
    #[cfg(feature = "rtsp")]
    {
        protocols.push("rtsp".to_string());
    }

    // -- scp / sftp (russh is always compiled in) --
    protocols.push("scp".to_string());
    protocols.push("sftp".to_string());

    // -- smtp / smtps --
    #[cfg(feature = "smtp")]
    {
        protocols.push("smtp".to_string());
        protocols.push("smtps".to_string());
    }

    // -- telnet --
    #[cfg(feature = "telnet")]
    {
        protocols.push("telnet".to_string());
    }

    // -- tftp --
    #[cfg(feature = "tftp")]
    {
        protocols.push("tftp".to_string());
    }

    // -- ws / wss (WebSocket requires HTTP) --
    #[cfg(feature = "http")]
    {
        protocols.push("ws".to_string());
        protocols.push("wss".to_string());
    }

    // The C code keeps the list alphabetically sorted; ensure the same.
    protocols.sort();
    protocols
}

/// Returns a host triple string describing the build target.
///
/// This mirrors the C `CURL_OS` macro that is set at configure time.
/// In Rust we construct it from `std::env::consts` values.
fn get_host_triple() -> String {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;

    match os {
        "linux" => format!("{}-unknown-linux-gnu", arch),
        "macos" => format!("{}-apple-darwin", arch),
        "windows" => format!("{}-pc-windows-msvc", arch),
        "freebsd" => format!("{}-unknown-freebsd", arch),
        "openbsd" => format!("{}-unknown-openbsd", arch),
        "netbsd" => format!("{}-unknown-netbsd", arch),
        _ => format!("{}-unknown-{}", arch, os),
    }
}

/// Returns the brotli version string, or `None` if the `brotli` feature is
/// disabled.
fn get_brotli_version() -> Option<String> {
    #[cfg(feature = "brotli")]
    {
        Some("brotli".to_string())
    }
    #[cfg(not(feature = "brotli"))]
    {
        None
    }
}

/// Returns the zstd version string, or `None` if the `zstd` feature is
/// disabled.
fn get_zstd_version() -> Option<String> {
    #[cfg(feature = "zstd")]
    {
        Some("zstd".to_string())
    }
    #[cfg(not(feature = "zstd"))]
    {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_string_matches() {
        assert_eq!(VERSION, "8.19.0-DEV");
    }

    #[test]
    fn test_version_num_matches() {
        assert_eq!(VERSION_NUM, 0x081300);
    }

    #[test]
    fn test_version_bits_computation() {
        assert_eq!(version_bits(8, 19, 0), 0x081300);
        assert_eq!(version_bits(7, 88, 1), 0x075801);
        assert_eq!(version_bits(1, 2, 0), 0x010200);
        assert_eq!(version_bits(9, 11, 7), 0x090b07);
    }

    #[test]
    fn test_at_least_version() {
        assert!(at_least_version(8, 0, 0));
        assert!(at_least_version(8, 19, 0));
        assert!(!at_least_version(8, 20, 0));
        assert!(!at_least_version(9, 0, 0));
    }

    #[test]
    fn test_feature_flags_c_value_ipv6() {
        assert_eq!(FeatureFlags::IPV6.bits(), 1 << 0);
    }

    #[test]
    fn test_feature_flags_c_value_ssl() {
        assert_eq!(FeatureFlags::SSL.bits(), 1 << 2);
    }

    #[test]
    fn test_feature_flags_c_value_libz() {
        assert_eq!(FeatureFlags::LIBZ.bits(), 1 << 3);
    }

    #[test]
    fn test_feature_flags_c_value_ntlm() {
        assert_eq!(FeatureFlags::NTLM.bits(), 1 << 4);
    }

    #[test]
    fn test_feature_flags_c_value_gssnegotiate() {
        assert_eq!(FeatureFlags::GSSNEGOTIATE.bits(), 1 << 5);
    }

    #[test]
    fn test_feature_flags_c_value_debug() {
        assert_eq!(FeatureFlags::DEBUG.bits(), 1 << 6);
    }

    #[test]
    fn test_feature_flags_c_value_asynchdns() {
        assert_eq!(FeatureFlags::ASYNCHDNS.bits(), 1 << 7);
    }

    #[test]
    fn test_feature_flags_c_value_spnego() {
        assert_eq!(FeatureFlags::SPNEGO.bits(), 1 << 8);
    }

    #[test]
    fn test_feature_flags_c_value_largefile() {
        assert_eq!(FeatureFlags::LARGEFILE.bits(), 1 << 9);
    }

    #[test]
    fn test_feature_flags_c_value_idn() {
        assert_eq!(FeatureFlags::IDN.bits(), 1 << 10);
    }

    #[test]
    fn test_feature_flags_c_value_sspi() {
        assert_eq!(FeatureFlags::SSPI.bits(), 1 << 11);
    }

    #[test]
    fn test_feature_flags_c_value_conv() {
        assert_eq!(FeatureFlags::CONV.bits(), 1 << 12);
    }

    #[test]
    fn test_feature_flags_c_value_tlsauth_srp() {
        assert_eq!(FeatureFlags::TLSAUTH_SRP.bits(), 1 << 14);
    }

    #[test]
    fn test_feature_flags_c_value_http2() {
        assert_eq!(FeatureFlags::HTTP2.bits(), 1 << 16);
    }

    #[test]
    fn test_feature_flags_c_value_gssapi() {
        assert_eq!(FeatureFlags::GSSAPI.bits(), 1 << 17);
    }

    #[test]
    fn test_feature_flags_c_value_kerberos5() {
        assert_eq!(FeatureFlags::KERBEROS5.bits(), 1 << 18);
    }

    #[test]
    fn test_feature_flags_c_value_unix_sockets() {
        assert_eq!(FeatureFlags::UNIX_SOCKETS.bits(), 1 << 19);
    }

    #[test]
    fn test_feature_flags_c_value_psl() {
        assert_eq!(FeatureFlags::PSL.bits(), 1 << 20);
    }

    #[test]
    fn test_feature_flags_c_value_https_proxy() {
        assert_eq!(FeatureFlags::HTTPS_PROXY.bits(), 1 << 21);
    }

    #[test]
    fn test_feature_flags_c_value_multi_ssl() {
        assert_eq!(FeatureFlags::MULTI_SSL.bits(), 1 << 22);
    }

    #[test]
    fn test_feature_flags_c_value_brotli() {
        assert_eq!(FeatureFlags::BROTLI.bits(), 1 << 23);
    }

    #[test]
    fn test_feature_flags_c_value_altsvc() {
        assert_eq!(FeatureFlags::ALTSVC.bits(), 1 << 24);
    }

    #[test]
    fn test_feature_flags_c_value_http3() {
        assert_eq!(FeatureFlags::HTTP3.bits(), 1 << 25);
    }

    #[test]
    fn test_feature_flags_c_value_zstd() {
        assert_eq!(FeatureFlags::ZSTD.bits(), 1 << 26);
    }

    #[test]
    fn test_feature_flags_c_value_unicode() {
        assert_eq!(FeatureFlags::UNICODE.bits(), 1 << 27);
    }

    #[test]
    fn test_feature_flags_c_value_hsts() {
        assert_eq!(FeatureFlags::HSTS.bits(), 1 << 28);
    }

    #[test]
    fn test_feature_flags_c_value_gsasl() {
        assert_eq!(FeatureFlags::GSASL.bits(), 1 << 29);
    }

    #[test]
    fn test_feature_flags_c_value_threadsafe() {
        assert_eq!(FeatureFlags::THREADSAFE.bits(), 1 << 30);
    }

    #[test]
    fn test_feature_flags_empty() {
        let empty = FeatureFlags::empty();
        assert_eq!(empty.bits(), 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn test_feature_flags_all_is_non_empty() {
        let all = FeatureFlags::all();
        assert!(!all.is_empty());
        assert!(all.contains(FeatureFlags::SSL));
        assert!(all.contains(FeatureFlags::HTTP2));
        assert!(all.contains(FeatureFlags::HTTP3));
        assert!(all.contains(FeatureFlags::THREADSAFE));
    }

    #[test]
    fn test_feature_flags_contains() {
        let flags = FeatureFlags::SSL | FeatureFlags::HTTP2;
        assert!(flags.contains(FeatureFlags::SSL));
        assert!(flags.contains(FeatureFlags::HTTP2));
        assert!(!flags.contains(FeatureFlags::BROTLI));
        // Contains with combined flags
        assert!(flags.contains(FeatureFlags::SSL | FeatureFlags::HTTP2));
    }

    #[test]
    fn test_feature_flags_bitor() {
        let a = FeatureFlags::SSL;
        let b = FeatureFlags::HTTP2;
        let combined = a | b;
        assert_eq!(combined.bits(), (1 << 2) | (1 << 16));
    }

    #[test]
    fn test_feature_flags_bitand() {
        let a = FeatureFlags::SSL | FeatureFlags::HTTP2;
        let b = FeatureFlags::SSL | FeatureFlags::BROTLI;
        let intersection = a & b;
        assert!(intersection.contains(FeatureFlags::SSL));
        assert!(!intersection.contains(FeatureFlags::HTTP2));
        assert!(!intersection.contains(FeatureFlags::BROTLI));
    }

    #[test]
    fn test_feature_flags_bitor_assign() {
        let mut flags = FeatureFlags::SSL;
        flags |= FeatureFlags::HTTP2;
        assert!(flags.contains(FeatureFlags::SSL));
        assert!(flags.contains(FeatureFlags::HTTP2));
    }

    #[test]
    fn test_feature_flags_not() {
        let flags = FeatureFlags::SSL;
        let inverted = !flags;
        assert!(!inverted.contains(FeatureFlags::SSL));
    }

    #[test]
    fn test_feature_flags_display() {
        let flags = FeatureFlags::SSL;
        let display = format!("{}", flags);
        assert_eq!(display, "0x00000004");
    }

    #[test]
    fn test_feature_flags_from_bits() {
        let flags = FeatureFlags::from_bits(0x04);
        assert!(flags.contains(FeatureFlags::SSL));
    }

    #[test]
    fn test_version_function_starts_with_curl_rs() {
        let ver = version();
        assert!(ver.starts_with("curl-rs/8.19.0-DEV"));
    }

    #[test]
    fn test_version_function_contains_backends() {
        let ver = version();
        assert!(ver.contains("rustls"), "version string should contain 'rustls'");
        assert!(ver.contains("hyper"), "version string should contain 'hyper'");
        assert!(ver.contains("quinn"), "version string should contain 'quinn'");
        assert!(ver.contains("russh"), "version string should contain 'russh'");
        assert!(ver.contains("flate2"), "version string should contain 'flate2'");
    }

    #[test]
    fn test_version_function_is_stable() {
        // Calling version() multiple times should return the same string
        let v1 = version();
        let v2 = version();
        assert_eq!(v1, v2);
        assert!(std::ptr::eq(v1, v2), "should return the same &str pointer");
    }

    #[test]
    fn test_version_info_basic_fields() {
        let info = version_info();
        assert_eq!(info.version, VERSION);
        assert_eq!(info.version_num, VERSION_NUM);
        assert!(!info.host.is_empty());
    }

    #[test]
    fn test_version_info_ssl() {
        let info = version_info();
        assert!(info.ssl_version.is_some());
        assert_eq!(info.ssl_version.as_deref(), Some("rustls"));
    }

    #[test]
    fn test_version_info_features_have_ssl() {
        let info = version_info();
        assert!(info.features.contains(FeatureFlags::SSL));
    }

    #[test]
    fn test_version_info_features_have_ipv6() {
        let info = version_info();
        assert!(info.features.contains(FeatureFlags::IPV6));
    }

    #[test]
    fn test_version_info_features_have_http2() {
        let info = version_info();
        assert!(info.features.contains(FeatureFlags::HTTP2));
    }

    #[test]
    fn test_version_info_features_have_http3() {
        let info = version_info();
        assert!(info.features.contains(FeatureFlags::HTTP3));
    }

    #[test]
    fn test_version_info_features_have_threadsafe() {
        let info = version_info();
        assert!(info.features.contains(FeatureFlags::THREADSAFE));
    }

    #[test]
    fn test_version_info_features_have_largefile() {
        let info = version_info();
        assert!(info.features.contains(FeatureFlags::LARGEFILE));
    }

    #[test]
    fn test_version_info_protocols_sorted() {
        let info = version_info();
        let mut sorted = info.protocols.clone();
        sorted.sort();
        assert_eq!(info.protocols, sorted, "protocols must be alphabetically sorted");
    }

    #[test]
    fn test_version_info_protocols_contain_http() {
        let info = version_info();
        assert!(
            info.protocols.contains(&"http".to_string()),
            "protocols should include 'http' (feature is enabled by default)"
        );
        assert!(
            info.protocols.contains(&"https".to_string()),
            "protocols should include 'https'"
        );
    }

    #[test]
    fn test_version_info_protocols_contain_ftp() {
        let info = version_info();
        assert!(
            info.protocols.contains(&"ftp".to_string()),
            "protocols should include 'ftp' (feature is enabled by default)"
        );
        assert!(
            info.protocols.contains(&"ftps".to_string()),
            "protocols should include 'ftps'"
        );
    }

    #[test]
    fn test_version_info_protocols_contain_ssh() {
        let info = version_info();
        assert!(
            info.protocols.contains(&"scp".to_string()),
            "protocols should include 'scp'"
        );
        assert!(
            info.protocols.contains(&"sftp".to_string()),
            "protocols should include 'sftp'"
        );
    }

    #[test]
    fn test_version_info_protocols_contain_file() {
        let info = version_info();
        assert!(
            info.protocols.contains(&"file".to_string()),
            "protocols should always include 'file'"
        );
    }

    #[test]
    fn test_version_info_hyper() {
        let info = version_info();
        assert!(info.hyper_version.is_some());
        assert_eq!(info.hyper_version.as_deref(), Some("hyper"));
    }

    #[test]
    fn test_version_info_quic() {
        let info = version_info();
        assert!(info.quic_version.is_some());
    }

    #[test]
    fn test_version_info_ssh() {
        let info = version_info();
        assert!(info.ssh_version.is_some());
        assert_eq!(info.ssh_version.as_deref(), Some("russh"));
    }

    #[test]
    fn test_version_info_libz() {
        let info = version_info();
        assert!(info.libz_version.is_some());
        assert_eq!(info.libz_version.as_deref(), Some("flate2"));
    }

    #[test]
    fn test_version_num_encoding() {
        // Verify the encoding matches the documented format 0xXXYYZZ
        let encoded = version_bits(VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH);
        assert_eq!(encoded, VERSION_NUM);
    }

    #[test]
    fn test_no_gap_between_bit_1_and_bit_2() {
        // Bit 1 is KERBEROS4 (obsolete, not exposed). Verify bit 2 is SSL.
        assert_eq!(FeatureFlags::SSL.bits(), 0x04);
        // Bit 0 is IPV6
        assert_eq!(FeatureFlags::IPV6.bits(), 0x01);
    }

    #[test]
    fn test_no_gap_at_bit_13_and_15() {
        // Bit 13 is CURLDEBUG (not exposed as a constant).
        // Bit 14 is TLSAUTH_SRP.
        assert_eq!(FeatureFlags::TLSAUTH_SRP.bits(), 0x4000);
        // Bit 15 is NTLM_WB (obsolete, not exposed).
        // Bit 16 is HTTP2.
        assert_eq!(FeatureFlags::HTTP2.bits(), 0x10000);
    }

    #[test]
    fn test_host_triple_is_not_empty() {
        let host = get_host_triple();
        assert!(!host.is_empty());
        // Should contain at least the architecture
        assert!(
            host.contains(std::env::consts::ARCH),
            "host triple should contain the CPU architecture"
        );
    }
}
