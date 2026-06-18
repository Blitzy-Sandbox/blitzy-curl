//! Version, capability, and protocol reporting — the Rust rewrite of
//! libcurl's `lib/version.c` (`curl_version()` / `curl_version_info()`).
//!
//! # Why this module is parity-critical
//!
//! curl's regression harness (`runtests`) does **not** run every test against
//! every build. Instead it queries `curl_version_info()` and `curl --version`
//! to discover which protocols and features the binary/library was built with,
//! and then selects the applicable subset of `tests/data` definitions
//! accordingly (Agent Action Plan §0.7.3). If the protocol list or feature set
//! reported here diverges — even slightly — from what curl 8.x's *default*
//! build reports, the wrong subset of tests is selected and test-suite parity
//! (goal G7) silently fails.
//!
//! For that reason this module reproduces curl's reporting **exactly**:
//!
//! * the [`protocols()`] scheme list matches `supported_protocols[]` in
//!   `lib/version.c`, in the same order and casing;
//! * the [`feature_names()`] capability list matches the `features_table[]`
//!   entries selected by curl's default build, in the same order and casing;
//! * the [`feature_bits()`] bitmask ORs exactly the `CURL_VERSION_*` flags
//!   (from `include/curl/curl.h`) that correspond to those features;
//! * the [`VersionInfo`] struct carries every field of the C
//!   `struct curl_version_info_data`, so the FFI crate can populate the
//!   `#[repr(C)]` mirror without inventing any data.
//!
//! `lib/version.c`, `include/curl/curlver.h`, and `include/curl/curl.h` are the
//! immutable authority; this module is written against them as a behavioral and
//! ABI oracle, never transliterated line-by-line.
//!
//! # The version ⇔ Cargo-features coupling invariant (MUST hold)
//!
//! Every optional protocol scheme and capability reported here is gated behind
//! the **same** Cargo feature that enables the corresponding implementation in
//! the rest of `curl-rs-lib` (see `curl-rs-lib/Cargo.toml`). The set of features
//! reported by this module is therefore, by construction, equal to the crate's
//! active Cargo feature set. The crate's `default = [...]` feature set is in turn
//! chosen to equal curl's default build (AAP §0.6.2), so that `curl --version`,
//! `curl-config --features`, and `runtests` feature detection are all identical
//! to upstream curl 8.x. **Do not** add a feature/protocol here without a
//! matching Cargo feature, and **do not** report a capability the build lacks.
//!
//! # Memory safety
//!
//! This module contains **zero** `unsafe` code and is compiled under
//! `#![forbid(unsafe_code)]`. All process-lifetime singletons use
//! [`std::sync::OnceLock`] (never `static mut`), which is thread-safe and keeps
//! the "libcurl API is thread-safe" guarantee that [`feature_bits()`] advertises
//! via `CURL_VERSION_THREADSAFE`.

#![forbid(unsafe_code)]

use std::sync::OnceLock;

// =============================================================================
// Version identity constants
// =============================================================================

/// The product name token that prefixes the version banner.
///
/// Upstream libcurl uses `LIBCURL_NAME` (`"libcurl"`). This rewrite reports its
/// own identity, `"curl-rs"`, so consumers can tell the Rust implementation
/// apart from the C original — it does not claim to be C-curl.
pub const NAME: &str = "curl-rs";

/// The human-readable libcurl version string, exactly as defined by
/// `LIBCURL_VERSION` in `include/curl/curlver.h`.
///
/// This module **owns** the `-DEV` pre-release suffix: Cargo's SemVer `version`
/// field (`8.19.0`) cannot carry it (a literal `8.19.0-DEV` there would sort
/// *below* `8.19.0`), so the canonical human string lives here and is the value
/// surfaced by `curl_version()` and `curl --version`.
pub const VERSION: &str = "8.19.0-DEV";

/// The numeric libcurl version, exactly as defined by `LIBCURL_VERSION_NUM` in
/// `include/curl/curlver.h`: a 24-bit value packed as
/// `(MAJOR << 16) | (MINOR << 8) | PATCH`.
///
/// `0x081300` == major 8, minor 19 (`0x13`), patch 0.
pub const VERSION_NUM: u32 = 0x0008_1300;

/// `LIBCURL_VERSION_MAJOR` from `include/curl/curlver.h`.
pub const VERSION_MAJOR: u32 = 8;
/// `LIBCURL_VERSION_MINOR` from `include/curl/curlver.h`.
pub const VERSION_MINOR: u32 = 19;
/// `LIBCURL_VERSION_PATCH` from `include/curl/curlver.h`.
pub const VERSION_PATCH: u32 = 0;

/// The libcurl copyright holder string (`LIBCURL_COPYRIGHT`).
pub const COPYRIGHT: &str = "Daniel Stenberg, <daniel@haxx.se>.";

/// Returns the major component of the libcurl version ([`VERSION_MAJOR`]).
#[inline]
#[must_use]
pub const fn version_major() -> u32 {
    VERSION_MAJOR
}

/// Returns the minor component of the libcurl version ([`VERSION_MINOR`]).
#[inline]
#[must_use]
pub const fn version_minor() -> u32 {
    VERSION_MINOR
}

/// Returns the patch component of the libcurl version ([`VERSION_PATCH`]).
#[inline]
#[must_use]
pub const fn version_patch() -> u32 {
    VERSION_PATCH
}

// =============================================================================
// CURLversion "age" enumeration (include/curl/curl.h)
// =============================================================================

/// The `CURLversion` "age" enumeration from `include/curl/curl.h`.
///
/// `curl_version_info()` returns a struct whose layout has grown over time;
/// the `age` field records the newest field group the struct is guaranteed to
/// contain. The values are sequential from `FIRST = 0`. `LAST` is a sentinel
/// that must never be used as an actual age.
///
/// This rewrite always fills out every field group, so it reports
/// [`CURLVERSION_NOW`] (== [`curlversion::TWELFTH`]).
pub mod curlversion {
    /// `CURLVERSION_FIRST` — 7.10.
    pub const FIRST: i32 = 0;
    /// `CURLVERSION_SECOND` — 7.11.1.
    pub const SECOND: i32 = 1;
    /// `CURLVERSION_THIRD` — 7.12.0.
    pub const THIRD: i32 = 2;
    /// `CURLVERSION_FOURTH` — 7.16.1.
    pub const FOURTH: i32 = 3;
    /// `CURLVERSION_FIFTH` — 7.57.0.
    pub const FIFTH: i32 = 4;
    /// `CURLVERSION_SIXTH` — 7.66.0.
    pub const SIXTH: i32 = 5;
    /// `CURLVERSION_SEVENTH` — 7.70.0.
    pub const SEVENTH: i32 = 6;
    /// `CURLVERSION_EIGHTH` — 7.72.0.
    pub const EIGHTH: i32 = 7;
    /// `CURLVERSION_NINTH` — 7.75.0.
    pub const NINTH: i32 = 8;
    /// `CURLVERSION_TENTH` — 7.77.0.
    pub const TENTH: i32 = 9;
    /// `CURLVERSION_ELEVENTH` — 7.87.0.
    pub const ELEVENTH: i32 = 10;
    /// `CURLVERSION_TWELFTH` — 8.8.0. The newest defined age.
    pub const TWELFTH: i32 = 11;
    /// `CURLVERSION_LAST` — never use as an actual age (sentinel).
    pub const LAST: i32 = 12;
}

/// The age stamp this implementation reports, `CURLVERSION_NOW`.
///
/// `include/curl/curl.h` defines `#define CURLVERSION_NOW CURLVERSION_TWELFTH`,
/// so this is `11`. It is the value placed in [`VersionInfo::age`].
pub const CURLVERSION_NOW: i32 = curlversion::TWELFTH;

// =============================================================================
// CURL_VERSION_* feature bit positions (include/curl/curl.h)
// =============================================================================

/// The `CURL_VERSION_*` feature-bit definitions from `include/curl/curl.h`.
///
/// These are the exact bit positions used in the `features` bitmask of
/// `curl_version_info_data`. They are part of the stable ABI: C consumers and
/// `tests/libtest` programs compare against these literal values, so an
/// off-by-one anywhere breaks parity. The full set (including the deprecated
/// flags) is mirrored here so the FFI crate can reference any of them by name.
///
/// * `#[allow(dead_code)]`: not every flag is used in every build (deprecated
///   flags such as `CURL_VERSION_KERBEROS4` are never reported); they exist as
///   a complete, name-addressable mirror of `include/curl/curl.h`.
/// * `#[allow(clippy::identity_op)]`: `CURL_VERSION_IPV6` is intentionally
///   written `1 << 0` to mirror curl.h's `(1<<0)` bit-position notation, which
///   keeps this table trivially auditable against the header.
#[allow(dead_code, clippy::identity_op)]
pub mod version_bits {
    /// IPv6-enabled.
    pub const CURL_VERSION_IPV6: i32 = 1 << 0;
    /// Kerberos V4 auth supported (deprecated).
    pub const CURL_VERSION_KERBEROS4: i32 = 1 << 1;
    /// SSL options are present.
    pub const CURL_VERSION_SSL: i32 = 1 << 2;
    /// libz features are present.
    pub const CURL_VERSION_LIBZ: i32 = 1 << 3;
    /// NTLM auth is supported.
    pub const CURL_VERSION_NTLM: i32 = 1 << 4;
    /// Negotiate auth is supported (deprecated).
    pub const CURL_VERSION_GSSNEGOTIATE: i32 = 1 << 5;
    /// Built with debug capabilities.
    pub const CURL_VERSION_DEBUG: i32 = 1 << 6;
    /// Asynchronous DNS resolves.
    pub const CURL_VERSION_ASYNCHDNS: i32 = 1 << 7;
    /// SPNEGO auth is supported.
    pub const CURL_VERSION_SPNEGO: i32 = 1 << 8;
    /// Supports files larger than 2GB.
    pub const CURL_VERSION_LARGEFILE: i32 = 1 << 9;
    /// Internationalized Domain Names are supported.
    pub const CURL_VERSION_IDN: i32 = 1 << 10;
    /// Built against Windows SSPI.
    pub const CURL_VERSION_SSPI: i32 = 1 << 11;
    /// Character conversions supported.
    pub const CURL_VERSION_CONV: i32 = 1 << 12;
    /// Debug memory tracking supported (deprecated).
    pub const CURL_VERSION_CURLDEBUG: i32 = 1 << 13;
    /// TLS-SRP auth is supported.
    pub const CURL_VERSION_TLSAUTH_SRP: i32 = 1 << 14;
    /// NTLM delegation to winbind helper is supported.
    pub const CURL_VERSION_NTLM_WB: i32 = 1 << 15;
    /// HTTP/2 support built-in.
    pub const CURL_VERSION_HTTP2: i32 = 1 << 16;
    /// Built against a GSS-API library.
    pub const CURL_VERSION_GSSAPI: i32 = 1 << 17;
    /// Kerberos V5 auth is supported.
    pub const CURL_VERSION_KERBEROS5: i32 = 1 << 18;
    /// Unix domain sockets support.
    pub const CURL_VERSION_UNIX_SOCKETS: i32 = 1 << 19;
    /// Mozilla's Public Suffix List (cookie domain verification).
    pub const CURL_VERSION_PSL: i32 = 1 << 20;
    /// HTTPS-proxy support built-in.
    pub const CURL_VERSION_HTTPS_PROXY: i32 = 1 << 21;
    /// Multiple SSL backends available.
    pub const CURL_VERSION_MULTI_SSL: i32 = 1 << 22;
    /// Brotli features are present.
    pub const CURL_VERSION_BROTLI: i32 = 1 << 23;
    /// Alt-Svc handling built-in.
    pub const CURL_VERSION_ALTSVC: i32 = 1 << 24;
    /// HTTP/3 support built-in.
    pub const CURL_VERSION_HTTP3: i32 = 1 << 25;
    /// zstd features are present.
    pub const CURL_VERSION_ZSTD: i32 = 1 << 26;
    /// Unicode support on Windows.
    pub const CURL_VERSION_UNICODE: i32 = 1 << 27;
    /// HSTS is supported.
    pub const CURL_VERSION_HSTS: i32 = 1 << 28;
    /// libgsasl is supported.
    pub const CURL_VERSION_GSASL: i32 = 1 << 29;
    /// libcurl API is thread-safe.
    pub const CURL_VERSION_THREADSAFE: i32 = 1 << 30;
}

// =============================================================================
// Backend version strings (cosmetic banner / struct data)
// =============================================================================

/// Human-readable version tokens for the Rust backend crates that replace
/// curl's C dependencies.
///
/// These strings are **cosmetic**: curl's test harness selects tests from the
/// `features`/`protocols`/`feature_names` reported by [`version_info()`], never
/// from the backend *version numbers* embedded in the banner. They are
/// hard-coded here (rather than read from each crate at runtime, which would
/// force this otherwise dependency-free module to import every backend) and
/// mirror the exact pins in the workspace `Cargo.toml` (AAP §0.6.1):
/// rustls 0.23.36, h2 0.4, quinn 0.11.9 + h3 0.0.7, russh 0.61.2, flate2 1
/// (zlib-compatible), brotli 8 (Brotli format 1.1.0), zstd 0.13 (Zstandard
/// 1.5.6), idna 1, publicsuffix 2.
///
/// The slot mapping mirrors `curl_version()` in `lib/version.c`: rustls fills
/// the SSL slot, `h2` the nghttp2 slot, quinn/h3 the QUIC slot, flate2 the libz
/// slot (reported as `zlib`), and russh the SSH (libssh) slot.
///
/// `#[allow(dead_code)]`: which constants are referenced depends on the active
/// feature set (e.g. `H2_TOKEN` is only used in the banner when `http` is on),
/// so some are unused in some configurations. They form a reference table and
/// are intentionally all present.
#[allow(dead_code)]
mod backend {
    /// SSL slot — reported with the backend name prefix, like curl's
    /// `Curl_ssl_version()` output (e.g. `"OpenSSL/3.0.0"`).
    pub const SSL_VERSION: &str = "rustls/0.23.36";

    /// libz slot, raw version number (no prefix) — matches `zlibVersion()`,
    /// which the C `version_info.libz_version` stores verbatim.
    pub const LIBZ_VERSION_RAW: &str = "1.3.1";
    /// libz slot banner token — matches curl's `"zlib/%s"` formatting.
    pub const LIBZ_TOKEN: &str = "zlib/1.3.1";

    /// Brotli numeric components (Brotli format version implemented by the
    /// `brotli` crate). Packed with [`super::pack_24_12`].
    pub const BROTLI_MAJOR: u32 = 1;
    pub const BROTLI_MINOR: u32 = 1;
    pub const BROTLI_PATCH: u32 = 0;
    /// Brotli slot string — includes the `"brotli/"` prefix, exactly as curl's
    /// `brotli_version()` helper formats it (and stores in `brotli_version`).
    pub const BROTLI_VERSION_STR: &str = "brotli/1.1.0";

    /// Zstandard numeric components implemented by the `zstd` crate. Packed
    /// with [`super::pack_24_12`] per the field documentation in
    /// `include/curl/curl.h`.
    pub const ZSTD_MAJOR: u32 = 1;
    pub const ZSTD_MINOR: u32 = 5;
    pub const ZSTD_PATCH: u32 = 6;
    /// Zstandard slot string — includes the `"zstd/"` prefix, exactly as curl's
    /// `zstd_version()` helper formats it (and stores in `zstd_version`).
    pub const ZSTD_VERSION_STR: &str = "zstd/1.5.6";

    /// HTTP/2 (nghttp2 slot) numeric components for the `h2` crate. Packed with
    /// [`super::pack_16_8`] per the `nghttp2_ver_num` field documentation.
    pub const H2_MAJOR: u32 = 0;
    pub const H2_MINOR: u32 = 4;
    pub const H2_PATCH: u32 = 7;
    /// HTTP/2 raw version (no prefix) — matches `nghttp2_info::version_str`,
    /// which the C `version_info.nghttp2_version` stores verbatim.
    pub const H2_VERSION_RAW: &str = "0.4.7";
    /// HTTP/2 banner token — names the Rust backend (`h2`) in the nghttp2 slot.
    pub const H2_TOKEN: &str = "h2/0.4.7";

    /// QUIC / HTTP/3 slot — the combined quinn + h3 token, mirroring curl's
    /// single `Curl_quic_ver()` string in the QUIC slot.
    pub const QUIC_TOKEN: &str = "quinn/0.11.9 h3/0.0.7";

    /// SSH slot — the russh token (replaces libssh/libssh2). Stored in
    /// `libssh_version`, which curl fills with a name-prefixed string.
    pub const SSH_TOKEN: &str = "russh/0.61.2";

    /// IDN slot, raw version (no prefix) — matches what curl stores in the
    /// `libidn` field (`idn2_check_version()` returns a bare version string).
    /// Backed by the `idna` crate.
    pub const LIBIDN_VERSION_RAW: &str = "1.0.3";
    /// IDN slot banner token — names the Rust backend (`idna`).
    pub const IDN_TOKEN: &str = "idna/1.0.3";

    /// PSL slot banner token — the Public Suffix List handling is backed by the
    /// `publicsuffix` crate but reported under the conventional `libpsl` name.
    /// PSL has no dedicated struct field; it surfaces only in the banner and as
    /// the `CURL_VERSION_PSL` feature bit.
    pub const PSL_TOKEN: &str = "libpsl/0.21.5";
}

/// Packs a `MAJOR.MINOR.PATCH` triple as `(MAJOR << 24) | (MINOR << 12) | PATCH`.
///
/// This is the numeric encoding curl documents for `brotli_ver_num` and
/// `zstd_ver_num` in `include/curl/curl.h`.
#[inline]
#[must_use]
const fn pack_24_12(major: u32, minor: u32, patch: u32) -> u32 {
    (major << 24) | (minor << 12) | patch
}

/// Packs a `MAJOR.MINOR.PATCH` triple as `(MAJOR << 16) | (MINOR << 8) | PATCH`.
///
/// This is the numeric encoding curl documents for `nghttp2_ver_num` in
/// `include/curl/curl.h`; the `h2` crate fills the nghttp2 slot here.
#[inline]
#[must_use]
const fn pack_16_8(major: u32, minor: u32, patch: u32) -> u32 {
    (major << 16) | (minor << 8) | patch
}

// =============================================================================
// host() — the build target's host string
// =============================================================================

/// Returns the OS/host suffix used to build the [`host()`] triple.
///
/// curl reports `CURL_OS` (an autoconf-style host triple such as
/// `"x86_64-pc-linux-gnu"`). We approximate the vendor/OS portion for the
/// platforms the CI matrix targets and fall back to [`std::env::consts::OS`]
/// elsewhere. Exactly one branch is compiled for any given target.
#[inline]
fn host_os_suffix() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "pc-linux-gnu"
    }
    #[cfg(target_os = "macos")]
    {
        "apple-darwin"
    }
    #[cfg(target_os = "windows")]
    {
        "pc-windows-msvc"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        std::env::consts::OS
    }
}

/// Process-lifetime storage for the composed host string.
static HOST: OnceLock<String> = OnceLock::new();

/// Returns the host/target string reported in
/// [`VersionInfo::host`] / `curl_version_info_data::host`.
///
/// The value is composed once (from the build target's architecture and OS) and
/// cached for the lifetime of the process, so the returned `&'static str` is
/// valid until process exit — matching the C contract, which hands out a
/// pointer that remains valid indefinitely.
#[must_use]
pub fn host() -> &'static str {
    HOST.get_or_init(|| format!("{}-{}", std::env::consts::ARCH, host_os_suffix()))
        .as_str()
}

// =============================================================================
// version() — the curl_version() banner
// =============================================================================

/// Process-lifetime storage for the composed version banner.
static BANNER: OnceLock<String> = OnceLock::new();

/// Appends a space-separated token to the banner being built.
#[inline]
fn push_token(out: &mut String, token: &str) {
    out.push(' ');
    out.push_str(token);
}

/// Builds the full `curl_version()`-style banner.
///
/// The field order mirrors `curl_version()` in `lib/version.c` exactly, with
/// each C backend substituted by its Rust replacement and unavailable slots
/// (c-ares, gsasl, GSS-API, RTMP, LDAP version) omitted:
///
/// 1. product identity — `curl-rs/<VERSION>`
/// 2. SSL — `rustls/...`
/// 3. libz — `zlib/...`
/// 4. brotli — `brotli/...`           (feature `brotli`)
/// 5. zstd — `zstd/...`               (feature `zstd`)
/// 6. *(c-ares slot omitted — the async/threaded resolver carries no token)*
/// 7. IDN — `idna/...`                            (feature `idn`)
/// 8. PSL — `libpsl/...`                          (feature `psl`)
/// 9. SSH — `russh/...`               (feature `scp` or `sftp`)
/// 10. HTTP/2 (nghttp2 slot) — `h2/...`            (feature `http`)
/// 11. QUIC / HTTP/3 — `quinn/... h3/...`          (feature `http`)
fn build_banner() -> String {
    let mut out = String::with_capacity(160);

    // 1. Product identity. Built from NAME/VERSION so it never drifts from the
    //    canonical constants. This is the FIRST token and gets no leading space.
    out.push_str(NAME);
    out.push('/');
    out.push_str(VERSION);

    // 2. SSL backend (rustls) — always present; TLS is non-optional.
    push_token(&mut out, backend::SSL_VERSION);

    // 3. libz (flate2, zlib-compatible) — always present.
    push_token(&mut out, backend::LIBZ_TOKEN);

    // 4. brotli content-encoding.
    #[cfg(feature = "brotli")]
    push_token(&mut out, backend::BROTLI_VERSION_STR);

    // 5. zstd content-encoding.
    #[cfg(feature = "zstd")]
    push_token(&mut out, backend::ZSTD_VERSION_STR);

    // 6. (c-ares slot intentionally omitted.)

    // 7. IDN (idna) — only when the `idn` feature is built (curl's USE_LIBIDN2).
    #[cfg(feature = "idn")]
    push_token(&mut out, backend::IDN_TOKEN);

    // 8. PSL (publicsuffix, reported as libpsl) — only when the `psl` feature is
    //    built (curl's USE_LIBPSL).
    #[cfg(feature = "psl")]
    push_token(&mut out, backend::PSL_TOKEN);

    // 9. SSH (russh) — only when SCP/SFTP support is built.
    #[cfg(any(feature = "scp", feature = "sftp"))]
    push_token(&mut out, backend::SSH_TOKEN);

    // 10. HTTP/2 (h2, in the nghttp2 slot) — requires HTTP.
    #[cfg(feature = "http")]
    push_token(&mut out, backend::H2_TOKEN);

    // 11. QUIC / HTTP/3 (quinn + h3) — requires HTTP.
    #[cfg(feature = "http")]
    push_token(&mut out, backend::QUIC_TOKEN);

    out
}

/// Returns the full version banner, equivalent to C's `curl_version()`.
///
/// The string is composed once and cached for the lifetime of the process, so
/// the returned `&'static str` is valid until process exit (the C contract
/// returns a pointer to a static buffer). Repeated calls return the identical
/// string.
#[must_use]
pub fn version() -> &'static str {
    BANNER.get_or_init(build_banner).as_str()
}

// =============================================================================
// protocols() — the supported URL scheme list
// =============================================================================

/// Process-lifetime storage for the supported-protocol scheme list.
static PROTOCOLS: OnceLock<Vec<&'static str>> = OnceLock::new();

/// Builds the supported URL-scheme list.
///
/// This reproduces `supported_protocols[]` from `lib/version.c` exactly: the
/// same schemes, in the same alphabetical order, all lowercase. Each scheme is
/// gated by the Cargo feature that enables its protocol implementation, so the
/// reported list equals the crate's active protocol feature set (the
/// version ⇔ Cargo-features coupling invariant; see the module docs).
///
/// The TLS (`s`) variants — `ftps`, `https`, `imaps`, … — are gated by the same
/// feature as their plaintext sibling rather than by a separate TLS feature,
/// because TLS (rustls) is non-optional in this rewrite. This mirrors curl,
/// where those entries are guarded by `USE_SSL`, which is always defined in the
/// default build.
fn build_protocols() -> Vec<&'static str> {
    // (scheme, enabled) table in curl's exact order. `cfg!(...)` resolves at
    // compile time; the `filter_map` keeps only the enabled schemes. Building
    // via an iterator (rather than `let mut v; v.push(..)`) keeps this clean
    // when every entry is disabled (e.g. `--no-default-features`).
    [
        ("dict", cfg!(feature = "dict")),
        ("file", cfg!(feature = "file")),
        ("ftp", cfg!(feature = "ftp")),
        ("ftps", cfg!(feature = "ftp")),
        ("gopher", cfg!(feature = "gopher")),
        ("gophers", cfg!(feature = "gopher")),
        ("http", cfg!(feature = "http")),
        ("https", cfg!(feature = "http")),
        ("imap", cfg!(feature = "imap")),
        ("imaps", cfg!(feature = "imap")),
        ("ldap", cfg!(feature = "ldap")),
        ("ldaps", cfg!(feature = "ldap")),
        ("mqtt", cfg!(feature = "mqtt")),
        ("mqtts", cfg!(feature = "mqtt")),
        ("pop3", cfg!(feature = "pop3")),
        ("pop3s", cfg!(feature = "pop3")),
        ("rtsp", cfg!(feature = "rtsp")),
        ("scp", cfg!(feature = "scp")),
        ("sftp", cfg!(feature = "sftp")),
        ("smb", cfg!(feature = "smb")),
        ("smbs", cfg!(feature = "smb")),
        ("smtp", cfg!(feature = "smtp")),
        ("smtps", cfg!(feature = "smtp")),
        ("telnet", cfg!(feature = "telnet")),
        ("tftp", cfg!(feature = "tftp")),
        ("ws", cfg!(feature = "websockets")),
        ("wss", cfg!(feature = "websockets")),
    ]
    .into_iter()
    .filter_map(|(scheme, enabled)| enabled.then_some(scheme))
    .collect()
}

/// Returns the list of URL schemes this build supports, equivalent to the
/// `protocols` array in `curl_version_info_data`.
///
/// The list is built once and cached for the lifetime of the process; every
/// element is a `&'static str` literal, so the returned slice and its contents
/// remain valid until process exit. The FFI layer turns this into the
/// `const char * const *`, `NULL`-terminated array the C ABI requires.
#[must_use]
pub fn protocols() -> &'static [&'static str] {
    PROTOCOLS.get_or_init(build_protocols).as_slice()
}

// =============================================================================
// feature_names() / feature_bits() — the capability set
// =============================================================================

/// Process-lifetime storage for the capability-name list.
static FEATURE_NAMES: OnceLock<Vec<&'static str>> = OnceLock::new();

/// Builds the capability-name list.
///
/// This reproduces the entries of `features_table[]` in `lib/version.c` that a
/// default curl 8.x build reports, in the same alphabetical order and exact
/// casing (`alt-svc`, `AsynchDNS`, `HTTPS-proxy`, `IPv6`, `UnixSockets`, …).
/// `runtests` matches these names verbatim, so neither order nor casing may
/// drift.
///
/// Gating rules:
/// * HTTP-family capabilities (`alt-svc`, `HSTS`, `HTTP2`, `HTTP3`,
///   `HTTPS-proxy`) require the `http` feature.
/// * `brotli` and `zstd` require their like-named content-encoding features.
/// * `IDN` requires the `idn` feature and `PSL` the `psl` feature — the SAME
///   features that compile the [`crate::idn`] / [`crate::psl`] implementations,
///   so a reported capability always corresponds to compiled-in behavior (and
///   vice versa). Both features are ON in the default build (curl's
///   `USE_LIBIDN2` / `USE_LIBPSL`), so a default report includes `IDN`/`PSL`.
/// * The remainder are non-optional in this rewrite and always reported:
///   `AsynchDNS` (the resolver is always async), `IPv6`, `Largefile`,
///   `libz`, `NTLM`, `SSL` (rustls is mandatory), `threadsafe`
///   (the core is thread-safe), and `UnixSockets`.
///
/// Capabilities a default build does **not** have are deliberately omitted
/// (e.g. `Debug`, `SSPI`, `GSS-API`, `Kerberos`, `SPNEGO`, `gsasl`, `MultiSSL`,
/// `TLS-SRP`, `NativeCA`), so this set stays equal to curl's default report.
fn build_feature_names() -> Vec<&'static str> {
    [
        ("alt-svc", cfg!(feature = "http")),
        ("AsynchDNS", true),
        ("brotli", cfg!(feature = "brotli")),
        ("HSTS", cfg!(feature = "http")),
        ("HTTP2", cfg!(feature = "http")),
        ("HTTP3", cfg!(feature = "http")),
        ("HTTPS-proxy", cfg!(feature = "http")),
        ("IDN", cfg!(feature = "idn")),
        ("IPv6", true),
        ("Largefile", true),
        ("libz", true),
        ("NTLM", true),
        ("PSL", cfg!(feature = "psl")),
        ("SSL", true),
        ("threadsafe", true),
        ("UnixSockets", true),
        ("zstd", cfg!(feature = "zstd")),
    ]
    .into_iter()
    .filter_map(|(name, enabled)| enabled.then_some(name))
    .collect()
}

/// Returns the list of capability names this build reports, equivalent to the
/// `feature_names` array in `curl_version_info_data`.
///
/// Built once and cached for the lifetime of the process. The FFI layer turns
/// this into the `NULL`-terminated `const char * const *` the C ABI requires.
#[must_use]
pub fn feature_names() -> &'static [&'static str] {
    FEATURE_NAMES.get_or_init(build_feature_names).as_slice()
}

/// Maps a capability name to its `CURL_VERSION_*` bit.
///
/// Every name produced by [`build_feature_names`] has a corresponding bit here;
/// names without a dedicated bit (none currently) map to `0`. Deriving
/// [`feature_bits()`] from [`feature_names()`] through this single mapping makes
/// the bitmask and the name list **consistent by construction** — they can
/// never disagree about which capabilities are present.
fn name_to_bit(name: &str) -> i32 {
    use version_bits::{
        CURL_VERSION_ALTSVC, CURL_VERSION_ASYNCHDNS, CURL_VERSION_BROTLI, CURL_VERSION_HSTS,
        CURL_VERSION_HTTP2, CURL_VERSION_HTTP3, CURL_VERSION_HTTPS_PROXY, CURL_VERSION_IDN,
        CURL_VERSION_IPV6, CURL_VERSION_LARGEFILE, CURL_VERSION_LIBZ, CURL_VERSION_NTLM,
        CURL_VERSION_PSL, CURL_VERSION_SSL, CURL_VERSION_THREADSAFE, CURL_VERSION_UNIX_SOCKETS,
        CURL_VERSION_ZSTD,
    };
    match name {
        "alt-svc" => CURL_VERSION_ALTSVC,
        "AsynchDNS" => CURL_VERSION_ASYNCHDNS,
        "brotli" => CURL_VERSION_BROTLI,
        "HSTS" => CURL_VERSION_HSTS,
        "HTTP2" => CURL_VERSION_HTTP2,
        "HTTP3" => CURL_VERSION_HTTP3,
        "HTTPS-proxy" => CURL_VERSION_HTTPS_PROXY,
        "IDN" => CURL_VERSION_IDN,
        "IPv6" => CURL_VERSION_IPV6,
        "Largefile" => CURL_VERSION_LARGEFILE,
        "libz" => CURL_VERSION_LIBZ,
        "NTLM" => CURL_VERSION_NTLM,
        "PSL" => CURL_VERSION_PSL,
        "SSL" => CURL_VERSION_SSL,
        "threadsafe" => CURL_VERSION_THREADSAFE,
        "UnixSockets" => CURL_VERSION_UNIX_SOCKETS,
        "zstd" => CURL_VERSION_ZSTD,
        _ => 0,
    }
}

/// Returns the `features` bitmask, equivalent to the `features` field of
/// `curl_version_info_data` (a C `int`).
///
/// The mask is the bitwise-OR of the `CURL_VERSION_*` flags for exactly the
/// capabilities in [`feature_names()`]. Because both are derived from the same
/// source, the bitmask always matches the name list. In every build,
/// `CURL_VERSION_THREADSAFE` is set (the Rust core is thread-safe) and
/// `CURL_VERSION_SSL` is set (rustls is mandatory).
#[must_use]
pub fn feature_bits() -> i32 {
    feature_names()
        .iter()
        .fold(0_i32, |acc, &name| acc | name_to_bit(name))
}

// =============================================================================
// VersionInfo — the safe mirror of struct curl_version_info_data
// =============================================================================

/// A safe-Rust mirror of C's `struct curl_version_info_data`
/// (`include/curl/curl.h`).
///
/// The FFI crate reads this struct to populate the `#[repr(C)]`
/// `curl_version_info_data` returned by `curl_version_info()`. This type is
/// **not** `#[repr(C)]` — it is the idiomatic Rust source of truth, carrying the
/// same data in safe types. Field names and order follow the C struct so the
/// translation is mechanical:
///
/// * nullable C `const char *` fields are [`Option<&'static str>`] (`None` ⇒ a
///   `NULL` pointer);
/// * always-present strings are `&'static str`;
/// * the two `NULL`-terminated C arrays (`protocols`, `feature_names`) are
///   `&'static [&'static str]` (the FFI layer appends the `NULL` terminator).
///
/// Every borrowed value lives for the lifetime of the process (string literals,
/// or data cached in this module's `OnceLock`s), so the pointers the FFI layer
/// derives remain valid until process exit, exactly as the C ABI promises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    /// Age of the struct layout; always [`CURLVERSION_NOW`] here.
    pub age: i32,
    /// The libcurl version string ([`VERSION`]).
    pub version: &'static str,
    /// The numeric libcurl version ([`VERSION_NUM`]).
    pub version_num: u32,
    /// The build host/target string (see [`host()`]).
    pub host: &'static str,
    /// The capability bitmask (see [`feature_bits()`]).
    pub features: i32,
    /// TLS backend version, name-prefixed (e.g. `"rustls/0.23.36"`).
    pub ssl_version: Option<&'static str>,
    /// C `long ssl_version_num`; curl keeps this permanently `0`.
    pub ssl_version_num: i64,
    /// zlib (flate2) version, raw (e.g. `"1.3.1"`); `None` if absent.
    pub libz_version: Option<&'static str>,
    /// Supported URL schemes (see [`protocols()`]).
    pub protocols: &'static [&'static str],
    /// c-ares version string; `None` — the async/threaded resolver is used.
    pub ares: Option<&'static str>,
    /// c-ares numeric version; `0` when c-ares is not used.
    pub ares_num: i32,
    /// IDN library version, raw; backed by the `idna` crate.
    pub libidn: Option<&'static str>,
    /// libiconv numeric version; `0` (no iconv dependency).
    pub iconv_ver_num: i32,
    /// SSH backend version, name-prefixed (e.g. `"russh/0.61.2"`); `None` when
    /// no SSH (SCP/SFTP) support is built.
    pub libssh_version: Option<&'static str>,
    /// Numeric Brotli version, `(MAJOR << 24) | (MINOR << 12) | PATCH`; `0` when
    /// the `brotli` feature is off.
    pub brotli_ver_num: u32,
    /// Brotli version string, prefixed (e.g. `"brotli/1.1.0"`); `None` when off.
    pub brotli_version: Option<&'static str>,
    /// Numeric HTTP/2 (nghttp2-slot) version, `(MAJOR << 16) | (MINOR << 8) |
    /// PATCH`, for the `h2` backend; `0` when the `http` feature is off.
    pub nghttp2_ver_num: u32,
    /// HTTP/2 backend version string, raw (e.g. `"0.4.7"`); `None` when off.
    pub nghttp2_version: Option<&'static str>,
    /// QUIC/HTTP-3 library string (e.g. `"quinn/0.11.9 h3/0.0.7"`); `None` when
    /// the `http` feature is off.
    pub quic_version: Option<&'static str>,
    /// Built-in default CA bundle path; `None` (rustls uses bundled roots).
    pub cainfo: Option<&'static str>,
    /// Built-in default CA directory path; `None` (rustls uses bundled roots).
    pub capath: Option<&'static str>,
    /// Numeric Zstandard version, `(MAJOR << 24) | (MINOR << 12) | PATCH`; `0`
    /// when the `zstd` feature is off.
    pub zstd_ver_num: u32,
    /// Zstandard version string, prefixed (e.g. `"zstd/1.5.6"`); `None` when off.
    pub zstd_version: Option<&'static str>,
    /// Hyper version; `None` (the HTTP engine is `hyper`+`h2` reported in the
    /// nghttp2 slot, not via this legacy field).
    pub hyper_version: Option<&'static str>,
    /// libgsasl version; `None` (SASL is implemented natively).
    pub gsasl_version: Option<&'static str>,
    /// Reported capability names (see [`feature_names()`]).
    pub feature_names: &'static [&'static str],
    /// RTMP (librtmp) version; `None` (RTMP is out of scope).
    pub rtmp_version: Option<&'static str>,
}

/// Process-lifetime storage for the assembled [`VersionInfo`].
static VERSION_INFO: OnceLock<VersionInfo> = OnceLock::new();

/// Assembles the [`VersionInfo`] singleton from this module's constants and
/// feature gates.
///
/// Feature-dependent backend fields are selected with `cfg!(...)` so both
/// branches type-check regardless of the active features; the disabled branch
/// is const-folded away. Optional backends that this rewrite does not provide
/// (c-ares, iconv, hyper-as-such, gsasl, RTMP, a built-in CA path) are reported
/// as `None`/`0`, matching the corresponding `NULL`/`0` initializers in
/// `lib/version.c`.
fn build_version_info() -> VersionInfo {
    // Brotli content-encoding (feature `brotli`).
    let (brotli_ver_num, brotli_version) = if cfg!(feature = "brotli") {
        (
            pack_24_12(
                backend::BROTLI_MAJOR,
                backend::BROTLI_MINOR,
                backend::BROTLI_PATCH,
            ),
            Some(backend::BROTLI_VERSION_STR),
        )
    } else {
        (0, None)
    };

    // Zstandard content-encoding (feature `zstd`).
    let (zstd_ver_num, zstd_version) = if cfg!(feature = "zstd") {
        (
            pack_24_12(
                backend::ZSTD_MAJOR,
                backend::ZSTD_MINOR,
                backend::ZSTD_PATCH,
            ),
            Some(backend::ZSTD_VERSION_STR),
        )
    } else {
        (0, None)
    };

    // HTTP/2 (nghttp2 slot) + QUIC/HTTP-3 — both require HTTP (feature `http`).
    let (nghttp2_ver_num, nghttp2_version, quic_version) = if cfg!(feature = "http") {
        (
            pack_16_8(backend::H2_MAJOR, backend::H2_MINOR, backend::H2_PATCH),
            Some(backend::H2_VERSION_RAW),
            Some(backend::QUIC_TOKEN),
        )
    } else {
        (0, None, None)
    };

    // SSH (russh) — only when SCP/SFTP support is built.
    let libssh_version = if cfg!(any(feature = "scp", feature = "sftp")) {
        Some(backend::SSH_TOKEN)
    } else {
        None
    };

    VersionInfo {
        age: CURLVERSION_NOW,
        version: VERSION,
        version_num: VERSION_NUM,
        host: host(),
        features: feature_bits(),
        // TLS (rustls) is mandatory, so SSL is always reported.
        ssl_version: Some(backend::SSL_VERSION),
        ssl_version_num: 0,
        // libz (flate2) is always available.
        libz_version: Some(backend::LIBZ_VERSION_RAW),
        protocols: protocols(),
        ares: None,
        ares_num: 0,
        // IDN (idna) is always available.
        libidn: Some(backend::LIBIDN_VERSION_RAW),
        iconv_ver_num: 0,
        libssh_version,
        brotli_ver_num,
        brotli_version,
        nghttp2_ver_num,
        nghttp2_version,
        quic_version,
        cainfo: None,
        capath: None,
        zstd_ver_num,
        zstd_version,
        hyper_version: None,
        gsasl_version: None,
        feature_names: feature_names(),
        rtmp_version: None,
    }
}

/// Returns the process-wide [`VersionInfo`], equivalent to C's
/// `curl_version_info()`.
///
/// The struct is assembled once and cached for the lifetime of the process, so
/// the returned `&'static VersionInfo` (and every pointer the FFI layer derives
/// from it) stays valid until process exit. The C entry point ignores its
/// `CURLversion` stamp argument; callers here simply read the singleton.
#[must_use]
pub fn version_info() -> &'static VersionInfo {
    VERSION_INFO.get_or_init(build_version_info)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    // `use super::*` brings the module's public API into scope and, because
    // this is a child module, also its private items (`name_to_bit`, the
    // `backend`/`version_bits` modules) so they can be exercised directly.
    use super::*;

    #[test]
    fn version_constants_match_curlver_h() {
        // Authority: include/curl/curlver.h.
        assert_eq!(NAME, "curl-rs");
        assert_eq!(VERSION, "8.19.0-DEV");
        assert_eq!(VERSION_NUM, 0x0008_1300);
        assert_eq!(VERSION_MAJOR, 8);
        assert_eq!(VERSION_MINOR, 19);
        assert_eq!(VERSION_PATCH, 0);
        assert_eq!(version_major(), VERSION_MAJOR);
        assert_eq!(version_minor(), VERSION_MINOR);
        assert_eq!(version_patch(), VERSION_PATCH);
        // VERSION_NUM packs as (MAJOR << 16) | (MINOR << 8) | PATCH; decode and
        // verify each component (decoding avoids identity/erasing-op lints).
        assert_eq!((VERSION_NUM >> 16) & 0xff, VERSION_MAJOR);
        assert_eq!((VERSION_NUM >> 8) & 0xff, VERSION_MINOR);
        assert_eq!(VERSION_NUM & 0xff, VERSION_PATCH);
    }

    #[test]
    fn curlversion_age_is_twelfth() {
        // Authority: include/curl/curl.h CURLversion enum + CURLVERSION_NOW.
        assert_eq!(curlversion::FIRST, 0);
        assert_eq!(curlversion::TWELFTH, 11);
        assert_eq!(curlversion::LAST, 12);
        assert_eq!(CURLVERSION_NOW, 11);
        assert_eq!(CURLVERSION_NOW, curlversion::TWELFTH);
        assert_eq!(version_info().age, curlversion::TWELFTH);
    }

    #[test]
    fn version_bits_match_curl_h() {
        // Authority: include/curl/curl.h CURL_VERSION_* definitions. A spot
        // check of every bit this build can report, plus a couple of others.
        assert_eq!(version_bits::CURL_VERSION_IPV6, 1); // 1 << 0
        assert_eq!(version_bits::CURL_VERSION_SSL, 1 << 2);
        assert_eq!(version_bits::CURL_VERSION_LIBZ, 1 << 3);
        assert_eq!(version_bits::CURL_VERSION_NTLM, 1 << 4);
        assert_eq!(version_bits::CURL_VERSION_ASYNCHDNS, 1 << 7);
        assert_eq!(version_bits::CURL_VERSION_LARGEFILE, 1 << 9);
        assert_eq!(version_bits::CURL_VERSION_IDN, 1 << 10);
        assert_eq!(version_bits::CURL_VERSION_HTTP2, 1 << 16);
        assert_eq!(version_bits::CURL_VERSION_UNIX_SOCKETS, 1 << 19);
        assert_eq!(version_bits::CURL_VERSION_PSL, 1 << 20);
        assert_eq!(version_bits::CURL_VERSION_HTTPS_PROXY, 1 << 21);
        assert_eq!(version_bits::CURL_VERSION_BROTLI, 1 << 23);
        assert_eq!(version_bits::CURL_VERSION_ALTSVC, 1 << 24);
        assert_eq!(version_bits::CURL_VERSION_HTTP3, 1 << 25);
        assert_eq!(version_bits::CURL_VERSION_ZSTD, 1 << 26);
        assert_eq!(version_bits::CURL_VERSION_HSTS, 1 << 28);
        assert_eq!(version_bits::CURL_VERSION_THREADSAFE, 1 << 30);
    }

    #[test]
    fn banner_starts_with_project_identity() {
        let v = version();
        // First token is the project identity, not C-curl/libcurl.
        assert!(v.starts_with("curl-rs/8.19.0-DEV"), "banner: {v}");
        assert!(!v.starts_with("curl/"), "banner: {v}");
        assert!(!v.starts_with("libcurl/"), "banner: {v}");
        // TLS (rustls) is mandatory, so its token is always present.
        assert!(v.contains("rustls/0.23.36"), "banner: {v}");
        // Cached: repeated calls hand back the identical static buffer.
        assert!(std::ptr::eq(version(), version()));
    }

    #[test]
    fn threadsafe_and_ssl_always_reported() {
        // The Rust core is thread-safe and rustls is mandatory; both must be
        // reported in every build configuration.
        let bits = feature_bits();
        assert_ne!(bits & version_bits::CURL_VERSION_THREADSAFE, 0);
        assert_ne!(bits & version_bits::CURL_VERSION_SSL, 0);
        assert!(feature_names().contains(&"threadsafe"));
        assert!(feature_names().contains(&"SSL"));
    }

    #[test]
    fn feature_bits_consistent_with_feature_names() {
        // The bitmask must equal exactly the OR of the reported names' bits:
        // every name maps to a nonzero bit, and there are no extra bits.
        let mut expected = 0_i32;
        for &name in feature_names() {
            let bit = name_to_bit(name);
            assert_ne!(bit, 0, "feature '{name}' has no CURL_VERSION_* bit");
            expected |= bit;
        }
        assert_eq!(feature_bits(), expected);
    }

    #[test]
    fn idn_psl_reporting_tracks_cargo_features() {
        // CRITICAL lockstep invariant (code review CP1 finding C1): the `IDN` and
        // `PSL` capabilities are reported — as a feature name, as a banner token,
        // and as a `CURL_VERSION_*` bit — IF AND ONLY IF the `idn` / `psl` Cargo
        // features are enabled. Those are the exact same features that compile the
        // real `crate::idn` / `crate::psl` implementations, so a reported
        // capability always corresponds to compiled-in behavior and never to the
        // no-IDN / no-PSL fallback. This test runs in EVERY feature configuration
        // (it is intentionally NOT gated), so it fails immediately if reporting and
        // implementation gating ever drift apart again.
        let names = feature_names();
        let banner = version();
        let bits = feature_bits();

        // IDN: name, banner token (`idna/…`), and CURL_VERSION_IDN bit all agree
        // with the `idn` feature.
        assert_eq!(
            names.contains(&"IDN"),
            cfg!(feature = "idn"),
            "feature_names() must report `IDN` iff the `idn` feature is enabled"
        );
        assert_eq!(
            banner.contains("idna/"),
            cfg!(feature = "idn"),
            "the version banner must carry the IDN token iff the `idn` feature is enabled"
        );
        assert_eq!(
            bits & version_bits::CURL_VERSION_IDN != 0,
            cfg!(feature = "idn"),
            "CURL_VERSION_IDN must be set iff the `idn` feature is enabled"
        );

        // PSL: name, banner token (`libpsl/…`), and CURL_VERSION_PSL bit all agree
        // with the `psl` feature.
        assert_eq!(
            names.contains(&"PSL"),
            cfg!(feature = "psl"),
            "feature_names() must report `PSL` iff the `psl` feature is enabled"
        );
        assert_eq!(
            banner.contains("libpsl/"),
            cfg!(feature = "psl"),
            "the version banner must carry the PSL token iff the `psl` feature is enabled"
        );
        assert_eq!(
            bits & version_bits::CURL_VERSION_PSL != 0,
            cfg!(feature = "psl"),
            "CURL_VERSION_PSL must be set iff the `psl` feature is enabled"
        );
    }

    #[test]
    fn protocols_are_lowercase_sorted_unique() {
        // curl keeps supported_protocols[] alphabetical and lowercase; this
        // holds in every feature configuration (an empty list trivially passes).
        let ps = protocols();
        for &p in ps {
            assert!(
                !p.bytes().any(|b| b.is_ascii_uppercase()),
                "scheme not lowercase: {p}"
            );
        }
        let mut sorted = ps.to_vec();
        sorted.sort_unstable();
        assert_eq!(
            ps,
            sorted.as_slice(),
            "schemes must be alphabetically sorted"
        );
        let mut deduped = sorted.clone();
        deduped.dedup();
        assert_eq!(deduped.len(), ps.len(), "schemes must be unique");
    }

    #[test]
    fn feature_names_unique() {
        let names = feature_names();
        let mut sorted = names.to_vec();
        sorted.sort_unstable();
        let total = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), total, "feature names must be unique");
    }

    #[test]
    fn version_info_matches_accessors_and_is_stable() {
        let info = version_info();
        assert_eq!(info.version, VERSION);
        assert_eq!(info.version_num, VERSION_NUM);
        assert_eq!(info.features, feature_bits());
        assert_eq!(info.protocols, protocols());
        assert_eq!(info.feature_names, feature_names());
        assert_eq!(info.host, host());
        // Mandatory / unconditional fields.
        assert_eq!(info.ssl_version, Some("rustls/0.23.36"));
        assert_eq!(info.ssl_version_num, 0);
        assert_eq!(info.libz_version, Some("1.3.1"));
        assert_eq!(info.libidn, Some("1.0.3"));
        // Backends this rewrite does not provide are reported as None/0.
        assert_eq!(info.ares, None);
        assert_eq!(info.ares_num, 0);
        assert_eq!(info.iconv_ver_num, 0);
        assert_eq!(info.cainfo, None);
        assert_eq!(info.capath, None);
        assert_eq!(info.hyper_version, None);
        assert_eq!(info.gsasl_version, None);
        assert_eq!(info.rtmp_version, None);
        // Singleton identity: repeated calls return the same instance.
        assert!(std::ptr::eq(version_info(), version_info()));
    }

    #[test]
    fn host_is_nonempty_and_contains_arch() {
        let h = host();
        assert!(!h.is_empty());
        assert!(
            h.contains(std::env::consts::ARCH),
            "host '{h}' should contain the target arch"
        );
        assert!(std::ptr::eq(host(), host()));
    }

    // -------------------------------------------------------------------------
    // Default-build parity tests.
    //
    // These assert the EXACT protocol list, feature list, bitmask, banner, and
    // backend fields that curl 8.x's default build reports. They are gated on
    // the full default feature set, so they run under the normal
    // `cargo test` (all default features on) and are simply skipped in reduced
    // configurations (e.g. `--no-default-features`) where the exact lists
    // legitimately differ.
    // -------------------------------------------------------------------------
    #[cfg(all(
        feature = "http",
        feature = "ftp",
        feature = "file",
        feature = "dict",
        feature = "gopher",
        feature = "imap",
        feature = "ldap",
        feature = "mqtt",
        feature = "pop3",
        feature = "rtsp",
        feature = "scp",
        feature = "sftp",
        feature = "smb",
        feature = "smtp",
        feature = "telnet",
        feature = "tftp",
        feature = "websockets",
        feature = "brotli",
        feature = "zstd",
        feature = "idn",
        feature = "psl",
    ))]
    mod default_build {
        use super::super::*;

        /// The exact `supported_protocols[]` of curl's default build, in order.
        const EXPECTED_PROTOCOLS: &[&str] = &[
            "dict", "file", "ftp", "ftps", "gopher", "gophers", "http", "https", "imap", "imaps",
            "ldap", "ldaps", "mqtt", "mqtts", "pop3", "pop3s", "rtsp", "scp", "sftp", "smb",
            "smbs", "smtp", "smtps", "telnet", "tftp", "ws", "wss",
        ];

        /// The exact default-build feature names, in `features_table[]` order.
        const EXPECTED_FEATURES: &[&str] = &[
            "alt-svc",
            "AsynchDNS",
            "brotli",
            "HSTS",
            "HTTP2",
            "HTTP3",
            "HTTPS-proxy",
            "IDN",
            "IPv6",
            "Largefile",
            "libz",
            "NTLM",
            "PSL",
            "SSL",
            "threadsafe",
            "UnixSockets",
            "zstd",
        ];

        #[test]
        fn protocols_exact_default_list() {
            assert_eq!(protocols(), EXPECTED_PROTOCOLS);
        }

        #[test]
        fn feature_names_exact_default_list() {
            assert_eq!(feature_names(), EXPECTED_FEATURES);
        }

        #[test]
        fn feature_bits_exact_default_value() {
            let expected = version_bits::CURL_VERSION_ALTSVC
                | version_bits::CURL_VERSION_ASYNCHDNS
                | version_bits::CURL_VERSION_BROTLI
                | version_bits::CURL_VERSION_HSTS
                | version_bits::CURL_VERSION_HTTP2
                | version_bits::CURL_VERSION_HTTP3
                | version_bits::CURL_VERSION_HTTPS_PROXY
                | version_bits::CURL_VERSION_IDN
                | version_bits::CURL_VERSION_IPV6
                | version_bits::CURL_VERSION_LARGEFILE
                | version_bits::CURL_VERSION_LIBZ
                | version_bits::CURL_VERSION_NTLM
                | version_bits::CURL_VERSION_PSL
                | version_bits::CURL_VERSION_SSL
                | version_bits::CURL_VERSION_THREADSAFE
                | version_bits::CURL_VERSION_UNIX_SOCKETS
                | version_bits::CURL_VERSION_ZSTD;
            assert_eq!(feature_bits(), expected);
        }

        #[test]
        fn version_info_backend_fields_present() {
            let info = version_info();
            assert_eq!(info.libssh_version, Some("russh/0.61.2"));
            assert_eq!(info.brotli_version, Some("brotli/1.1.0"));
            assert_eq!(info.zstd_version, Some("zstd/1.5.6"));
            assert_eq!(info.nghttp2_version, Some("0.4.7"));
            assert_eq!(info.quic_version, Some("quinn/0.11.9 h3/0.0.7"));
            // Numeric packing (hex literals avoid identity/erasing-op lints):
            //   brotli/zstd: (MAJOR << 24) | (MINOR << 12) | PATCH
            //   nghttp2:     (MAJOR << 16) | (MINOR << 8)  | PATCH
            assert_eq!(info.brotli_ver_num, 0x0100_1000); // 1.1.0
            assert_eq!(info.zstd_ver_num, 0x0100_5006); // 1.5.6
            assert_eq!(info.nghttp2_ver_num, 0x0000_0407); // 0.4.7
        }

        #[test]
        fn banner_is_exact_default_field_order() {
            // Field order mirrors curl_version() in lib/version.c, with Rust
            // backends substituted and unavailable slots omitted.
            let expected = "curl-rs/8.19.0-DEV rustls/0.23.36 zlib/1.3.1 \
                 brotli/1.1.0 zstd/1.5.6 idna/1.0.3 libpsl/0.21.5 russh/0.61.2 \
                 h2/0.4.7 quinn/0.11.9 h3/0.0.7";
            assert_eq!(version(), expected);
        }
    }
}
