// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! # curl-rs-lib — the safe-Rust core of the curl/libcurl 8.19.0-DEV rewrite
//!
//! `curl-rs-lib` is the foundation crate of the three-crate workspace. It is a language
//! rewrite of curl's `lib/` tree and owns the protocol handlers, the TLS layer, the
//! authentication mechanisms, DNS resolution, connection management, and the transfer core.
//! It is consumed by both sibling crates — the [`curl-rs`] CLI and the [`curl-rs-ffi`] C-ABI
//! layer — and depends on neither of them.
//!
//! [`curl-rs`]: https://crates.io/crates/curl-rs
//! [`curl-rs-ffi`]: https://crates.io/crates/curl-rs-ffi
//!
//! ## Memory-safety guarantee
//!
//! The entire crate is written in safe Rust: [`forbid(unsafe_code)`] is applied crate-wide
//! below, which makes any `unsafe` block anywhere in this crate a hard **compile error** (not
//! merely a lint). `unsafe` is confined to the `curl-rs-ffi` boundary crate (AAP §0.7.2);
//! eliminating it from the core is the entire reason this rewrite exists. A CI grep audit
//! additionally asserts that the token `unsafe` never appears under `curl-rs-lib/src/`.
//!
//! [`forbid(unsafe_code)`]: https://doc.rust-lang.org/reference/attributes/codegen.html
//!
//! ## Where the sibling crates plug in
//!
//! * [`curl-rs-ffi`] bridges this idiomatic API to the C ABI: the opaque `CURL *` handle is a
//!   boxed [`Easy`], `curl_easy_setopt` writes into the very same [`url::UserDefined`] option
//!   store that [`EasyBuilder`] populates, and `curl_version` / `curl_version_info` report the
//!   strings produced by [`version()`] and [`feature_names()`].
//! * `curl-rs` (the CLI) drives transfers through the [`Easy`]/[`Multi`] handles and renders
//!   `--version` from the same accessors, so the tool and the library never disagree about
//!   capabilities.
//!
//! ## Public API at a glance
//!
//! * Version reporting — [`VERSION`], [`VERSION_NUM`], [`version()`], [`feature_names()`],
//!   [`version_bits`], [`at_least_version`] (mirroring `include/curl/curlver.h` and
//!   `lib/version.c`).
//! * Handles — [`Easy`] (re-exported from [`url`]) with the idiomatic [`EasyBuilder`], and
//!   [`Multi`] (re-exported from [`multi`]).
//! * Process lifecycle — [`global_init`] / [`global_cleanup`] (the safe analogue of
//!   `curl_global_init` / `curl_global_cleanup`).
//! * Errors — [`Error`], [`Result`], [`CurlCode`] (re-exported from [`error`]).
//!
//! ## Feature matrix
//!
//! The Cargo `[features]` in this crate's manifest reproduce curl's `CURL_DISABLE_*` / `USE_*`
//! guards one-to-one (AAP §0.5.3). Feature-gated modules are attached to the tree under a
//! matching `#[cfg(feature = "...")]` so a disabled protocol compiles out exactly as it does
//! in a stock curl build. The default set is
//! `http, ftp, smtp, imap, pop3, tftp, telnet, dict, mqtt, rtsp, cookies, brotli, zstd`;
//! `hickory-dns` is the only catalogued feature that is off by default.

// The memory-safety cornerstone of the whole rewrite: no `unsafe` may appear in this crate.
#![forbid(unsafe_code)]

// ===========================================================================
// Module tree (AAP §0.3.1).
//
// Every module below is authored in its own file (top-level modules) or its own
// `mod.rs` (the `protocols` / `tls` / `auth` / `conn` / `dns` subtrees, authored by
// their respective agents). This crate root only *declares* them so the whole
// `curl-rs-lib/src/` folder forms a single module tree; the per-protocol / per-backend
// feature gating for a subtree lives inside that subtree's `mod.rs`, not here.
// ===========================================================================

// --- Transfer core, request/response state, and metering ---
pub mod error;
pub mod multi;
pub mod progress;
pub mod ratelimit;
pub mod request;
pub mod transfer;

// --- URL handling and percent/IDN encoding ---
pub mod escape;
pub mod idn;
pub mod url;
pub mod urlapi;

// --- Content transformation ---
pub mod content_encoding;
pub mod mime;

// --- On-disk state formats (byte-compatible with curl 8.x) ---
pub mod altsvc;
pub mod hsts;
pub mod netrc;

// The cookie engine maps to curl's `CURL_DISABLE_COOKIES` guard: it is compiled only when the
// (default-on) `cookies` feature is enabled, so a cookie-less build drops it entirely.
#[cfg(feature = "cookies")]
pub mod cookie;
// The Public Suffix List backs cookie-domain validation; it is a self-contained module and is
// declared unconditionally so it remains available to any consumer even in a cookie-less build.
pub mod psl;

// --- Subtrees (each resolves to `<name>/mod.rs`) ---
pub mod auth;
pub mod conn;
pub mod dns;
pub mod protocols;
pub mod tls;

// ===========================================================================
// Curated public re-exports.
//
// Explicit item re-exports only — no glob re-exports across the crate boundary (AAP §0.5.3).
// These give downstream crates (`curl-rs`, `curl-rs-ffi`) short, stable paths:
// `curl_rs_lib::{Easy, Multi, Error, Result, CurlCode}`.
// ===========================================================================

pub use error::{CurlCode, Error, Result};
pub use multi::Multi;
pub use url::Easy;

use std::sync::{Once, OnceLock};

// ===========================================================================
// Version reporting (← `include/curl/curlver.h` + `lib/version.c`).
// ===========================================================================

/// The human-readable libcurl version (`LIBCURL_VERSION`), e.g. `"8.19.0-DEV"`.
///
/// This is the bare version token reported in `curl_version_info_data.version`; the full
/// human-readable banner (with backend names) is produced by [`version()`].
pub const VERSION: &str = "8.19.0-DEV";

/// The numeric libcurl version (`LIBCURL_VERSION_NUM`): `0x00RRSSPP` with `RR` = major,
/// `SS` = minor, `PP` = patch. For 8.19.0 this is `0x081300`.
///
/// The integer value is frozen for ABI parity — a consumer comparing against a hard-coded
/// `0x081300` must keep working (AAP §0.6.1).
pub const VERSION_NUM: u32 = 0x081300;

/// The major component of [`VERSION_NUM`] (`LIBCURL_VERSION_MAJOR`).
pub const VERSION_MAJOR: u8 = 8;

/// The minor component of [`VERSION_NUM`] (`LIBCURL_VERSION_MINOR`).
pub const VERSION_MINOR: u8 = 19;

/// The patch component of [`VERSION_NUM`] (`LIBCURL_VERSION_PATCH`).
pub const VERSION_PATCH: u8 = 0;

/// The libcurl copyright line (`LIBCURL_COPYRIGHT`).
pub const COPYRIGHT: &str = "Daniel Stenberg, <daniel@haxx.se>.";

/// Compose a numeric version from its components — the Rust equivalent of the C
/// `CURL_VERSION_BITS(x, y, z)` macro in `curlver.h`: `(x << 16) | (y << 8) | z`.
///
/// ```
/// assert_eq!(curl_rs_lib::version_bits(8, 19, 0), 0x081300);
/// ```
#[must_use]
pub const fn version_bits(major: u32, minor: u32, patch: u32) -> u32 {
    (major << 16) | (minor << 8) | patch
}

/// Return `true` when the built library is at least version `major.minor.patch` — the Rust
/// equivalent of the C `CURL_AT_LEAST_VERSION(x, y, z)` macro: it compares [`VERSION_NUM`]
/// against [`version_bits`].
///
/// ```
/// assert!(curl_rs_lib::at_least_version(8, 0, 0));
/// assert!(!curl_rs_lib::at_least_version(9, 0, 0));
/// ```
#[must_use]
pub const fn at_least_version(major: u32, minor: u32, patch: u32) -> bool {
    VERSION_NUM >= version_bits(major, minor, patch)
}

/// Return the full human-readable version banner, in the mandated form (AAP §0.6.3):
///
/// ```text
/// curl-rs/8.19.0-DEV rustls flate2 brotli zstd hyper quinn russh
/// ```
///
/// The backend/feature tokens are composed from the enabled Cargo features, mirroring how
/// `lib/version.c` assembles its feature string: `rustls` (the single TLS backend), `flate2`
/// (the libz-equivalent, always present), then `brotli` and `zstd` **only** when their
/// features are enabled, then `hyper` (HTTP/1.1+2), `quinn` (QUIC/HTTP-3) and `russh` (SSH).
/// Under the default feature set this yields the banner shown above; both the CLI `--version`
/// output and the FFI `curl_version()` return this exact string.
///
/// The banner is assembled once and cached, so repeated calls return the same `&'static str`.
#[must_use]
pub fn version() -> &'static str {
    static VERSION_STRING: OnceLock<String> = OnceLock::new();
    VERSION_STRING
        .get_or_init(|| {
            let mut banner = String::with_capacity(64);
            banner.push_str("curl-rs/");
            banner.push_str(VERSION);
            // rustls and flate2 are unconditional: rustls is the sole TLS backend and gzip/
            // deflate (flate2) has no curl disable switch.
            banner.push_str(" rustls flate2");
            // Optional content-encoding backends, gated exactly like `USE_BROTLI` / `USE_ZSTD`.
            #[cfg(feature = "brotli")]
            banner.push_str(" brotli");
            #[cfg(feature = "zstd")]
            banner.push_str(" zstd");
            // HTTP engine, QUIC transport, and SSH stack — always advertised.
            banner.push_str(" hyper quinn russh");
            banner
        })
        .as_str()
}

/// Return the built-in capability names, using the verbatim spellings of `lib/version.c`'s
/// `FEATURE()` table (case-insensitive alphabetical order).
///
/// This is the single source of truth consumed by the CLI `--version` feature line and the
/// FFI `curl_version_info` `feature_names` array, so the tool and the shared library report
/// identical capabilities. Under the default feature set the list is:
///
/// ```text
/// alt-svc brotli HSTS HTTP2 HTTP3 IDN IPv6 libz NTLM PSL SSL zstd
/// ```
///
/// `brotli` / `zstd` appear only when their features are enabled, and `Kerberos` is added
/// (between `IPv6` and `libz`, matching `version.c`'s ordering) only when the optional
/// `gssapi` OS-Kerberos feature is compiled in.
///
/// The list is assembled once and cached, so repeated calls return the same slice.
#[must_use]
pub fn feature_names() -> &'static [&'static str] {
    static FEATURE_NAMES: OnceLock<Vec<&'static str>> = OnceLock::new();
    FEATURE_NAMES
        .get_or_init(|| {
            // `(name, enabled)` candidates filtered to the built set. Composing with `cfg!()`
            // rather than an init-then-push mutable Vec keeps `clippy::vec_init_then_push`
            // quiet while preserving version.c's ordering.
            const CANDIDATES: [(&str, bool); 13] = [
                ("alt-svc", true),
                ("brotli", cfg!(feature = "brotli")),
                ("HSTS", true),
                ("HTTP2", true),
                ("HTTP3", true),
                ("IDN", true),
                ("IPv6", true),
                ("Kerberos", cfg!(feature = "gssapi")),
                ("libz", true),
                ("NTLM", true),
                ("PSL", true),
                ("SSL", true),
                ("zstd", cfg!(feature = "zstd")),
            ];
            CANDIDATES
                .iter()
                .filter_map(|&(name, enabled)| enabled.then_some(name))
                .collect()
        })
        .as_slice()
}

// ===========================================================================
// Process-wide lifecycle (← `lib/easy.c` `curl_global_init` / `curl_global_cleanup`).
// ===========================================================================

/// Process-wide one-time initialization latch.
static GLOBAL_INIT: Once = Once::new();

/// Perform the library's one-time, process-wide initialization — the safe analogue of
/// `curl_global_init`.
///
/// curl's C `global_init()` runs a cascade of subsystem initializers (`Curl_ssl_init`,
/// `Curl_ssh_init`, Win32 socket startup, …) guarded by a reference count. Under this rewrite
/// every subsystem — `rustls`, the Tokio runtime, the resolver — initializes lazily, and the
/// historical C-only steps target unsupported platforms, so there is no eager work to do. The
/// [`Once`] latch supplies exactly the idempotent, thread-safe guarantee curl's refcount did:
/// calling this any number of times, from any threads, is safe and cheap.
///
/// Calling it is optional — the handles initialize what they need on demand — but it is
/// provided so the FFI `curl_global_init` symbol has a single core entry point to delegate to.
pub fn global_init() {
    GLOBAL_INIT.call_once(|| {
        // Intentionally empty: there is no eager process-global state to construct under the
        // Rust ownership model. The value of this call is the `Once` synchronization itself.
    });
}

/// Release process-wide resources acquired by [`global_init`] — the safe analogue of
/// `curl_global_cleanup`.
///
/// Under Rust's ownership model every resource is owned by the handle that created it and is
/// released deterministically when that handle is dropped (RAII); there is therefore no
/// process-global state to tear down here. This mirrors curl, whose own cleanup ultimately
/// just balances the init reference count. The function exists for API symmetry and so the
/// FFI `curl_global_cleanup` symbol has a core entry point to delegate to; it is always safe
/// to call, including without a prior [`global_init`].
pub fn global_cleanup() {
    // Nothing to release: resource lifetimes are bound to their owning handles (RAII).
}

// ===========================================================================
// Idiomatic builder API (← `lib/easy.c` + `lib/setopt.c`).
//
// The builder is the ergonomic, in-language counterpart to `curl_easy_setopt`: both write
// into the SAME option store — an [`Easy`]'s [`url::UserDefined`] (`data->set`) — so a handle
// configured through the builder and one configured through the FFI `curl_easy_setopt` are
// byte-for-byte equivalent. Each setter corresponds 1:1 to a `CURLOPT_*` handled in
// `setopt.c`, and the freshly-opened defaults (notably TLS verification on:
// `CURLOPT_SSL_VERIFYPEER = 1`, `CURLOPT_SSL_VERIFYHOST = 2`) are inherited from
// [`url::UserDefined::default`], which reproduces curl's `Curl_init_userdefined`.
// ===========================================================================

/// A fluent builder for an [`Easy`] handle.
///
/// Construct one with [`Easy::builder`] (or [`EasyBuilder::new`]), chain the option setters,
/// then materialize the handle with [`build`](EasyBuilder::build):
///
/// ```
/// # use curl_rs_lib::Easy;
/// let easy = Easy::builder()
///     .url("https://example.com/")
///     .follow_location(true)
///     .max_redirs(10)
///     .build()
///     .expect("valid URL");
/// // Curl's secure defaults are preserved unless overridden.
/// assert!(easy.set.ssl.verify_peer);
/// assert_eq!(easy.set.ssl.verify_host, 2);
/// ```
///
/// Every setter is `#[must_use]` and consumes `self`, so a discarded intermediate builder is a
/// compile-time warning rather than a silent no-op.
#[derive(Debug, Default)]
pub struct EasyBuilder {
    /// The handle under construction; setters mutate its [`url::UserDefined`] option store.
    easy: Easy,
    /// A deferred `CURLOPT_URL`, applied (and validated) by [`build`](EasyBuilder::build).
    url: Option<String>,
}

impl EasyBuilder {
    /// Create a builder seeded with curl's freshly-opened defaults (`Curl_open` +
    /// `Curl_init_userdefined`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            easy: Easy::open(),
            url: None,
        }
    }

    /// `CURLOPT_URL` — the transfer URL. Stored now and parsed by
    /// [`build`](EasyBuilder::build) (a malformed URL surfaces as a `build` error).
    #[must_use]
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// `CURLOPT_FOLLOWLOCATION` — follow `Location:` redirects.
    #[must_use]
    pub fn follow_location(mut self, on: bool) -> Self {
        self.easy.set.follow_location = on;
        self
    }

    /// `CURLOPT_MAXREDIRS` — redirect limit (`-1` = unlimited).
    #[must_use]
    pub fn max_redirs(mut self, max: i64) -> Self {
        self.easy.set.maxredirs = max;
        self
    }

    /// `CURLOPT_AUTOREFERER` — set `Referer:` to the previous URL when following a redirect.
    #[must_use]
    pub fn auto_referer(mut self, on: bool) -> Self {
        self.easy.set.http_auto_referer = on;
        self
    }

    /// `CURLOPT_UNRESTRICTED_AUTH` — keep sending credentials across hosts on redirect.
    #[must_use]
    pub fn unrestricted_auth(mut self, on: bool) -> Self {
        self.easy.set.allow_auth_to_other_hosts = on;
        self
    }

    /// `CURLOPT_PATH_AS_IS` — do not squash `..` / `.` path segments.
    #[must_use]
    pub fn path_as_is(mut self, on: bool) -> Self {
        self.easy.set.path_as_is = on;
        self
    }

    /// `CURLOPT_PORT` — remote-port override (`0` = use the URL's port).
    #[must_use]
    pub fn port(mut self, port: u16) -> Self {
        self.easy.set.use_port = port;
        self
    }

    /// `CURLOPT_CONNECT_ONLY` — establish the connection but perform no transfer.
    #[must_use]
    pub fn connect_only(mut self, on: bool) -> Self {
        self.easy.set.connect_only = on;
        self
    }

    /// `CURLOPT_BUFFERSIZE` — preferred receive-buffer size, in bytes.
    #[must_use]
    pub fn buffer_size(mut self, bytes: usize) -> Self {
        self.easy.set.buffer_size = bytes;
        self
    }

    /// `CURLOPT_TCP_NODELAY` — disable Nagle's algorithm (default on in curl 8.x).
    #[must_use]
    pub fn tcp_nodelay(mut self, on: bool) -> Self {
        self.easy.set.tcp_nodelay = on;
        self
    }

    /// `CURLOPT_TCP_KEEPALIVE` — enable TCP keep-alive probes.
    #[must_use]
    pub fn tcp_keepalive(mut self, on: bool) -> Self {
        self.easy.set.tcp_keepalive = on;
        self
    }

    /// `CURLOPT_USERNAME` — the user name for authentication.
    #[must_use]
    pub fn username(mut self, user: impl Into<String>) -> Self {
        self.easy.set.username = Some(user.into());
        self
    }

    /// `CURLOPT_PASSWORD` — the password for authentication.
    #[must_use]
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.easy.set.password = Some(password.into());
        self
    }

    /// `CURLOPT_PROXY` — the proxy URL to route the transfer through.
    #[must_use]
    pub fn proxy(mut self, proxy: impl Into<String>) -> Self {
        self.easy.set.proxy = Some(proxy.into());
        self
    }

    /// `CURLOPT_SSL_VERIFYPEER` — verify the peer certificate chain. **On by default**;
    /// setting `false` is the builder equivalent of `--insecure`'s peer half.
    #[must_use]
    pub fn verify_peer(mut self, on: bool) -> Self {
        self.easy.set.ssl.verify_peer = on;
        self
    }

    /// `CURLOPT_SSL_VERIFYHOST` — verify the certificate host name. `true` maps to curl's
    /// historical `2` (**the default**), `false` to `0`.
    #[must_use]
    pub fn verify_host(mut self, on: bool) -> Self {
        self.easy.set.ssl.verify_host = if on { 2 } else { 0 };
        self
    }

    /// `CURLOPT_CAINFO` — path to a CA certificate bundle used to verify the peer.
    #[must_use]
    pub fn ca_info(mut self, path: impl Into<String>) -> Self {
        self.easy.set.ssl.ca_info = Some(path.into());
        self
    }

    /// `CURLOPT_SSLCERT` — client certificate.
    #[must_use]
    pub fn ssl_cert(mut self, cert: impl Into<String>) -> Self {
        self.easy.set.ssl.cert = Some(cert.into());
        self
    }

    /// `CURLOPT_SSLKEY` — client private key.
    #[must_use]
    pub fn ssl_key(mut self, key: impl Into<String>) -> Self {
        self.easy.set.ssl.key = Some(key.into());
        self
    }

    /// Finalize the builder into a configured [`Easy`] handle.
    ///
    /// If a URL was supplied it is parsed and installed via [`Easy::set_url`] here, so the
    /// resulting handle already carries its URL-API state.
    ///
    /// # Errors
    ///
    /// Returns the [`Error`] produced by [`Easy::set_url`] when the configured URL is
    /// malformed.
    pub fn build(mut self) -> Result<Easy> {
        if let Some(url) = self.url.take() {
            self.easy.set_url(&url)?;
        }
        Ok(self.easy)
    }
}

// ===========================================================================
// Handle lifecycle helpers layered onto the core [`Easy`] (← `lib/easy.c`).
//
// `Easy` is defined in `crate::url`; these inherent methods extend it from the crate root
// (both live in this crate, so the inherent impl is legal). Creation (`Easy::open`,
// `curl_easy_init`) and duplication (`Easy::duphandle`, `curl_easy_duphandle`) already live on
// the type; here we add the fluent builder entry point and `curl_easy_reset`. There is no
// explicit `cleanup`: releasing a handle is simply dropping it (RAII), which is the safe
// analogue of `curl_easy_cleanup`.
// ===========================================================================

impl Easy {
    /// Start configuring a fresh handle with the fluent [`EasyBuilder`].
    #[must_use]
    pub fn builder() -> EasyBuilder {
        EasyBuilder::new()
    }

    /// Reset the handle to its freshly-opened defaults — the analogue of `curl_easy_reset`.
    ///
    /// All user options, operational state, and read-back info are restored to the
    /// `Curl_open` + `Curl_init_userdefined` baseline (for example TLS verification returns to
    /// on). This matches curl, whose `curl_easy_reset` re-runs the default initialization.
    pub fn reset(&mut self) {
        *self = Easy::open();
    }
}

// ===========================================================================
// Unit tests — the crate-root contract: version parity, feature reporting, and the
// builder/handle-lifecycle behavior. These exercise only this file's public surface plus the
// already-implemented `crate::url` handle types (no incomplete subtree is touched).
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_constants_match_curlver_h() {
        assert_eq!(VERSION, "8.19.0-DEV");
        assert_eq!(VERSION_NUM, 0x081300);
        assert_eq!(VERSION_MAJOR, 8);
        assert_eq!(VERSION_MINOR, 19);
        assert_eq!(VERSION_PATCH, 0);
        assert_eq!(COPYRIGHT, "Daniel Stenberg, <daniel@haxx.se>.");
    }

    #[test]
    fn version_bits_and_at_least_version() {
        // The C `CURL_VERSION_BITS` composition.
        assert_eq!(version_bits(8, 19, 0), 0x081300);
        assert_eq!(
            version_bits(
                u32::from(VERSION_MAJOR),
                u32::from(VERSION_MINOR),
                u32::from(VERSION_PATCH),
            ),
            VERSION_NUM,
        );
        // The C `CURL_AT_LEAST_VERSION` comparison.
        assert!(at_least_version(8, 19, 0));
        assert!(at_least_version(8, 0, 0));
        assert!(at_least_version(7, 99, 99));
        assert!(!at_least_version(8, 20, 0));
        assert!(!at_least_version(9, 0, 0));
    }

    /// Under the default feature set the banner must match the mandated form byte-for-byte
    /// (AAP §0.6.3) — the exact string the FFI `curl_version()` also returns.
    #[cfg(all(feature = "brotli", feature = "zstd"))]
    #[test]
    fn version_banner_default_features() {
        assert_eq!(
            version(),
            "curl-rs/8.19.0-DEV rustls flate2 brotli zstd hyper quinn russh",
        );
    }

    /// Regardless of the optional content-encoding features, the banner always carries the
    /// crate name/version, the TLS + libz backends, and the HTTP/QUIC/SSH backends, in order.
    #[test]
    fn version_banner_core_backbone() {
        let banner = version();
        assert!(
            banner.starts_with("curl-rs/8.19.0-DEV rustls flate2"),
            "banner = {banner:?}"
        );
        assert!(banner.ends_with("hyper quinn russh"), "banner = {banner:?}");
        // Caching returns a stable pointer/value.
        assert_eq!(banner, version());
    }

    #[test]
    fn feature_names_report_core_capabilities() {
        let names = feature_names();
        for expected in [
            "alt-svc", "HSTS", "HTTP2", "HTTP3", "IDN", "IPv6", "libz", "NTLM", "PSL", "SSL",
        ] {
            assert!(names.contains(&expected), "missing feature {expected:?}");
        }
        // Optional content-encoding capabilities track their features.
        assert_eq!(names.contains(&"brotli"), cfg!(feature = "brotli"));
        assert_eq!(names.contains(&"zstd"), cfg!(feature = "zstd"));
        // `Kerberos` is only reported when the optional OS-GSSAPI feature is compiled in.
        assert_eq!(names.contains(&"Kerberos"), cfg!(feature = "gssapi"));
        // Names are emitted in version.c's case-insensitive-alphabetical order.
        let mut sorted = names.to_vec();
        sorted.sort_by_key(|s| s.to_ascii_lowercase());
        assert_eq!(names, sorted.as_slice());
    }

    #[test]
    fn builder_preserves_curl_secure_defaults() {
        // A builder with no overrides must reproduce curl's `Curl_init_userdefined` defaults,
        // most importantly TLS verification ON (AAP §0.7.3).
        let easy = Easy::builder().build().expect("empty builder builds");
        assert!(
            easy.set.ssl.verify_peer,
            "CURLOPT_SSL_VERIFYPEER must default to on"
        );
        assert_eq!(
            easy.set.ssl.verify_host, 2,
            "CURLOPT_SSL_VERIFYHOST must default to 2"
        );
        // A couple of other well-known curl 8.x defaults for good measure.
        assert!(!easy.set.follow_location);
        assert_eq!(easy.set.maxredirs, 30);
        assert!(easy.set.tcp_nodelay);
    }

    #[test]
    fn builder_setters_write_option_storage() {
        let easy = Easy::builder()
            .url("http://example.com/")
            .follow_location(true)
            .max_redirs(7)
            .auto_referer(true)
            .unrestricted_auth(true)
            .path_as_is(true)
            .verify_peer(false)
            .verify_host(false)
            .port(8080)
            .buffer_size(32_768)
            .tcp_nodelay(false)
            .tcp_keepalive(true)
            .username("neo")
            .password("trinity")
            .proxy("http://proxy.local:3128/")
            .ca_info("/etc/ssl/certs/ca-bundle.crt")
            .ssl_cert("client.pem")
            .ssl_key("client.key")
            .connect_only(true)
            .build()
            .expect("configured builder builds");

        assert!(easy.set.follow_location);
        assert_eq!(easy.set.maxredirs, 7);
        assert!(easy.set.http_auto_referer);
        assert!(easy.set.allow_auth_to_other_hosts);
        assert!(easy.set.path_as_is);
        assert!(!easy.set.ssl.verify_peer);
        assert_eq!(easy.set.ssl.verify_host, 0);
        assert_eq!(easy.set.use_port, 8080);
        assert_eq!(easy.set.buffer_size, 32_768);
        assert!(!easy.set.tcp_nodelay);
        assert!(easy.set.tcp_keepalive);
        assert_eq!(easy.set.username.as_deref(), Some("neo"));
        assert_eq!(easy.set.password.as_deref(), Some("trinity"));
        assert_eq!(easy.set.proxy.as_deref(), Some("http://proxy.local:3128/"));
        assert_eq!(
            easy.set.ssl.ca_info.as_deref(),
            Some("/etc/ssl/certs/ca-bundle.crt")
        );
        assert_eq!(easy.set.ssl.cert.as_deref(), Some("client.pem"));
        assert_eq!(easy.set.ssl.key.as_deref(), Some("client.key"));
        assert!(easy.set.connect_only);
        // Supplying a URL seeds the handle's URL-API state.
        assert!(easy.state.uh.is_some());
    }

    #[test]
    fn builder_propagates_malformed_url_error() {
        // An unterminated IPv6 literal is rejected by the URL parser (CURLUE_BAD_IPV6),
        // and `build()` must surface that as an error rather than swallow it.
        let result = Easy::builder().url("http://[::1").build();
        assert!(result.is_err());
    }

    #[test]
    fn reset_restores_open_defaults() {
        let mut easy = Easy::builder()
            .url("http://example.com/")
            .follow_location(true)
            .verify_peer(false)
            .build()
            .expect("configured builder builds");
        assert!(easy.set.follow_location);
        assert!(!easy.set.ssl.verify_peer);
        assert!(easy.state.uh.is_some());

        easy.reset();

        assert!(!easy.set.follow_location);
        assert!(easy.set.ssl.verify_peer);
        assert_eq!(easy.set.ssl.verify_host, 2);
        assert!(
            easy.state.uh.is_none(),
            "reset must clear operational state"
        );
    }

    #[test]
    fn duphandle_copies_options_but_resets_state() {
        let src = Easy::builder()
            .url("http://example.com/")
            .follow_location(true)
            .build()
            .expect("configured builder builds");
        let dup = src.duphandle();
        assert!(dup.set.follow_location, "duphandle copies options");
        assert!(
            dup.state.uh.is_none(),
            "duphandle resets live operational state"
        );
    }

    #[test]
    fn global_lifecycle_is_idempotent() {
        // Safe to call any number of times, in any order.
        global_init();
        global_init();
        global_cleanup();
        global_cleanup();
        global_init();
    }

    #[test]
    fn easy_builder_default_matches_new() {
        let a = EasyBuilder::default().build().expect("default builds");
        let b = EasyBuilder::new().build().expect("new builds");
        assert_eq!(a.set.ssl.verify_peer, b.set.ssl.verify_peer);
        assert_eq!(a.set.maxredirs, b.set.maxredirs);
    }
}
