// SPDX-License-Identifier: curl
//
//! Proxy subsystem — the module **root**: proxy configuration, the
//! `curl_proxytype` ABI, and the *which-proxy* policy.
//!
//! This module is the Rust home of curl's proxy layer. It is the **policy and
//! configuration hub** of the subsystem: it owns the proxy-type integer ABI,
//! the *which-proxy / no-proxy* decision, and the HTTP/HTTPS-proxy option
//! contract, while delegating the wire-level work to two sibling submodules and
//! to the connection-filter chain in [`crate::conn`]. The transfer engine and
//! the filter chain reach these concerns through ordinary Rust paths
//! (`crate::proxy::<item>`) rather than through curl's C `#include` graph
//! (Agent Action Plan §0.5.1 / §0.5.2).
//!
//! # Subsystem layout
//!
//! * [`socks`] — the SOCKS4 / SOCKS4a / SOCKS5 / SOCKS5h client handshake
//!   *engine* (`lib/socks.c`): the byte-exact, asynchronous reimplementation of
//!   curl's SOCKS negotiation. This module supplies the [`CurlProxyType`] the
//!   engine dispatches on; the engine returns a [`socks::CurlProxyCode`].
//! * [`noproxy`] — the `NO_PROXY` / `CURLOPT_NOPROXY` host *matcher*
//!   (`lib/noproxy.c`): decides whether a target host bypasses the configured
//!   proxy, reproducing curl's domain-suffix, IP, and CIDR matching exactly.
//! * **this `mod.rs`** — the [`Proxy`] configuration type, the [`CurlProxyType`]
//!   enum (with the exact `CURLPROXY_*` integer values), the
//!   [`proxy_for_target`] *which-proxy* decision, and the HTTP-proxy `CONNECT`
//!   option/behavior contract (documented for the filter author).
//!
//! # Engine / filter boundary (what is **not** here)
//!
//! The HTTP `CONNECT` tunnel and the SOCKS connection-filter wrapper are
//! **`crate::conn`'s concern**, not this module's. curl implements them as
//! connection filters (`cf-h1-proxy.c`, `cf-h2-proxy.c`, `cf-https-connect.c`,
//! and the SOCKS `Curl_cft_socks_proxy` vtable in `lib/socks.c`). This module
//! only supplies the *config* (the [`Proxy`] struct), the *policy* (the
//! [`proxy_for_target`] / no-proxy decision), and the *documented contract*
//! (see the [`Curl_http_proxy_create_CONNECT` contract](#http-proxy-connect-contract))
//! those filters consult. The byte-for-byte `CONNECT` request is built by the
//! filter, reproducing the contract documented below.
//!
//! # HTTP-proxy CONNECT contract
//!
//! When an HTTPS origin is reached through an HTTP(S) proxy, curl first opens a
//! tunnel with a `CONNECT` request. That request is built by the connection
//! filter in [`crate::conn`], **not** here, but the byte-for-byte contract it
//! must reproduce is documented here (the oracle is `lib/http_proxy.c`,
//! `Curl_http_proxy_get_destination` and `Curl_http_proxy_create_CONNECT`):
//!
//! 1. **Tunnel destination** (`Curl_http_proxy_get_destination`, L165-190):
//!    * *host* = `conn_to_host` when a "connect-to" override is set; otherwise
//!      the secondary hostname when the socket is the FTP data channel
//!      (`sockindex == SECONDARYSOCKET`); otherwise the request `host.name`.
//!    * *port* = the secondary port for the `SECONDARYSOCKET`; otherwise
//!      `conn_to_port` when a "connect-to" port is set; otherwise the
//!      `remote_port`.
//!    * *ipv6_ip* = when the chosen host differs from `host.name`, it is an IPv6
//!      literal iff it contains a `:`; otherwise the connection's stored
//!      `ipv6_ip` bit is used.
//! 2. **Request line authority** (`Curl_http_proxy_create_CONNECT`, L212-213):
//!    formatted as `"{open}{host}{close}:{port}"`, where `{open}`/`{close}` are
//!    `[` / `]` around an IPv6 literal and empty otherwise — e.g. `example.com:443`
//!    or `[2001:db8::1]:443`. The method is `CONNECT` and the target is that
//!    authority.
//! 3. **Headers, in curl's order** (L227-261):
//!    * `Proxy-Authorization` — emitted from the proxy-auth output (see
//!      [`Proxy::proxy_auth`]); curl produces the `Proxy-`-prefixed line.
//!    * `Host` — **HTTP/1 only**, and only when the user did not supply a custom
//!      proxy `Host` header; its value is the same authority string.
//!    * the cleartext `proxyuserpwd` line, when present.
//!    * `User-Agent` — when not overridden by a custom proxy header and a
//!      user-agent string is set.
//!    * `Proxy-Connection: Keep-Alive` — **HTTP/1 only**, when not overridden.
//!    * the custom proxy headers (`CURLOPT_PROXYHEADER`), selected by
//!      [`ProxyUse`] (`HEADER_CONNECT` for the tunnel request).
//! 4. **Custom-header quirks** (`dynhds_add_custom`, L82-119) — preserved
//!    exactly: a header given as `"Name:"` (a name with an empty value)
//!    **suppresses** that header, while `"Name;"` **sends it empty**. A custom
//!    `Host:` header is dropped if a `Host` was already emitted, to avoid
//!    duplicates.
//!
//! These items are reproduced by the filter author; this module only owns the
//! [`Proxy::proxy_auth`] hook and the [`ProxyUse`] selector that feed them.
//!
//! # Feature gating
//!
//! The whole proxy subsystem mirrors curl's `#ifndef CURL_DISABLE_PROXY` via the
//! `proxy` Cargo feature (default **on**). Faithful to curl's header guards, the
//! pure-ABI items that curl keeps *outside* that guard — the [`CurlProxyType`]
//! enum (a public-header type) and [`is_https_proxy`] (the `IS_HTTPS_PROXY`
//! macro, defined outside `#ifndef CURL_DISABLE_PROXY` in `lib/http_proxy.h`) —
//! are always compiled. Everything else (the submodules, [`Proxy`],
//! [`ProxyConfig`], [`proxy_for_target`], [`ProxyUse`], and [`PROXY_TIMEOUT`])
//! sits behind `#[cfg(feature = "proxy")]`, so a `--no-default-features` build
//! drops the proxy machinery cleanly.
//!
//! # Environment passthrough
//!
//! Per AAP §0.8.3 the only proxy-related environment variables honored are
//! `NO_PROXY` / `no_proxy` (plus `HOME`, consumed elsewhere); no new runtime
//! environment variables are introduced. The environment read for the no-proxy
//! list happens **here**, in [`resolve_no_proxy`] — the [`noproxy`] matcher
//! itself never touches the environment and is always handed an
//! already-resolved string.
//!
//! # Memory safety
//!
//! This module performs no raw-pointer or FFI work: it parses strings with
//! [`crate::url`], joins credentials through [`crate::auth`], and stores plain
//! owned values. It therefore compiles under the module-level
//! `#![forbid(unsafe_code)]` declared below, consistent with the crate-root
//! policy (AAP §0.7.1).

// Defensive, self-documenting restatement of the crate-root guarantee. `forbid`
// is idempotent with the crate's memory-safety posture and keeps this module
// provably `unsafe`-free even when inspected or compiled in isolation.
#![forbid(unsafe_code)]

// ===========================================================================
// Submodule declarations.
//
// Both siblings live under curl's `#ifndef CURL_DISABLE_PROXY` gate (the `proxy`
// Cargo feature, default ON), so a `--no-default-features` build drops the
// SOCKS engine and the no-proxy matcher cleanly — exactly as a
// `CURL_DISABLE_PROXY` C build omits `lib/socks.c` and `lib/noproxy.c`. They are
// `pub` so `crate::conn` can reach the SOCKS handshake engine directly; the
// ergonomic re-exports below give the same items a flat `crate::proxy::*` path.
// ===========================================================================

#[cfg(feature = "proxy")]
pub mod noproxy;

#[cfg(feature = "proxy")]
pub mod socks;

// ---------------------------------------------------------------------------
// Ergonomic re-exports of the sibling public surface, so consumers (notably
// `crate::conn`'s SOCKS and no-proxy filters) can write `crate::proxy::<item>`.
// ---------------------------------------------------------------------------

#[cfg(feature = "proxy")]
pub use noproxy::check_noproxy;

#[cfg(feature = "proxy")]
pub use socks::{proxy_strerror, socks_handshake, to_curlcode, CurlProxyCode, SocksParams};

// ===========================================================================
// `CurlProxyType` — the `curl_proxytype` ABI enum (always compiled).
// ===========================================================================

/// The kind of proxy a connection routes through — the Rust analog of curl's
/// `curl_proxytype` enum (`include/curl/curl.h`), the value carried by
/// `CURLOPT_PROXYTYPE`.
///
/// # ABI contract (do not change the integer values)
///
/// The discriminants reproduce curl's `CURLPROXY_*` constants
/// (`include/curl/curl.h` L790-808) **exactly** so the FFI layer can map the
/// `long` a C caller passes to `CURLOPT_PROXYTYPE` straight onto this enum, and
/// so `curl_easy_getinfo`-style round-trips observe identical values:
///
/// | Variant | C constant | Value |
/// |---------|-----------|-------|
/// | [`Http`](CurlProxyType::Http) | `CURLPROXY_HTTP` | 0 |
/// | [`Http10`](CurlProxyType::Http10) | `CURLPROXY_HTTP_1_0` | 1 |
/// | [`Https`](CurlProxyType::Https) | `CURLPROXY_HTTPS` | 2 |
/// | [`Https2`](CurlProxyType::Https2) | `CURLPROXY_HTTPS2` | 3 |
/// | [`Socks4`](CurlProxyType::Socks4) | `CURLPROXY_SOCKS4` | 4 |
/// | [`Socks5`](CurlProxyType::Socks5) | `CURLPROXY_SOCKS5` | 5 |
/// | [`Socks4a`](CurlProxyType::Socks4a) | `CURLPROXY_SOCKS4A` | 6 |
/// | [`Socks5Hostname`](CurlProxyType::Socks5Hostname) | `CURLPROXY_SOCKS5_HOSTNAME` | 7 |
///
/// (`CURLPROXY_LAST = 8` is curl's sentinel and is intentionally not modeled as
/// a usable variant.)
///
/// The four SOCKS variants are the ones the [`socks`] handshake engine consumes;
/// the HTTP/HTTPS variants are handled by the HTTP-proxy `CONNECT` tunnelling
/// path in [`crate::conn`]. The `Socks4a` / `Socks5Hostname` ("`5h`") variants
/// are the *remote-DNS* forms that send the destination hostname to the proxy
/// instead of resolving it locally.
///
/// [`Default`] is [`Http`](CurlProxyType::Http), matching curl's
/// `set->proxytype = CURLPROXY_HTTP` default (`lib/url.c`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[repr(i32)]
pub enum CurlProxyType {
    /// `CURLPROXY_HTTP` (0) — HTTP proxy (the default), `CONNECT` over HTTP/1.1.
    #[default]
    Http = 0,
    /// `CURLPROXY_HTTP_1_0` (1) — HTTP proxy forced to `CONNECT` over HTTP/1.0.
    Http10 = 1,
    /// `CURLPROXY_HTTPS` (2) — HTTPS proxy, restricted to HTTP/1.
    Https = 2,
    /// `CURLPROXY_HTTPS2` (3) — HTTPS proxy that may negotiate HTTP/2.
    Https2 = 3,
    /// `CURLPROXY_SOCKS4` (4) — SOCKS4 with **local** name resolution.
    Socks4 = 4,
    /// `CURLPROXY_SOCKS5` (5) — SOCKS5 with **local** name resolution.
    Socks5 = 5,
    /// `CURLPROXY_SOCKS4A` (6) — SOCKS4a; the proxy resolves the hostname.
    Socks4a = 6,
    /// `CURLPROXY_SOCKS5_HOSTNAME` (7) — SOCKS5h; the proxy resolves the
    /// hostname ("remote DNS").
    Socks5Hostname = 7,
}

impl CurlProxyType {
    /// Maps a raw `CURLOPT_PROXYTYPE` integer to a [`CurlProxyType`], returning
    /// [`None`] for any value outside curl's defined `CURLPROXY_*` range
    /// (`0..=7`). Mirrors how the C option setter validates the `long` argument
    /// against `CURLPROXY_LAST` before storing it.
    #[must_use]
    pub const fn from_raw(value: i32) -> Option<Self> {
        match value {
            0 => Some(CurlProxyType::Http),
            1 => Some(CurlProxyType::Http10),
            2 => Some(CurlProxyType::Https),
            3 => Some(CurlProxyType::Https2),
            4 => Some(CurlProxyType::Socks4),
            5 => Some(CurlProxyType::Socks5),
            6 => Some(CurlProxyType::Socks4a),
            7 => Some(CurlProxyType::Socks5Hostname),
            _ => None,
        }
    }

    /// Returns the raw `CURLPROXY_*` integer for this proxy type — the value the
    /// FFI layer stores for `CURLOPT_PROXYTYPE` / reports through `getinfo`.
    #[must_use]
    pub const fn as_raw(self) -> i32 {
        self as i32
    }

    /// Returns `true` for any of the four SOCKS proxy types (the ones the
    /// [`socks`] handshake engine handles), `false` for the HTTP/HTTPS types.
    ///
    /// This mirrors curl's `sockstype` computation in `parse_proxy`
    /// (`lib/url.c`), which routes SOCKS types to `conn->socks_proxy` and the
    /// rest to `conn->http_proxy`.
    #[must_use]
    pub const fn is_socks(self) -> bool {
        matches!(
            self,
            CurlProxyType::Socks4
                | CurlProxyType::Socks5
                | CurlProxyType::Socks4a
                | CurlProxyType::Socks5Hostname
        )
    }

    /// Returns `true` for the HTTP-family proxy types (`HTTP`, `HTTP/1.0`,
    /// `HTTPS`, `HTTPS2`) — the ones served by the HTTP `CONNECT` tunnelling
    /// filters in [`crate::conn`] — and `false` for the SOCKS types. This is the
    /// exact complement of [`is_socks`](CurlProxyType::is_socks).
    #[must_use]
    pub const fn is_http(self) -> bool {
        !self.is_socks()
    }

    /// Returns `true` when this proxy speaks TLS to the proxy itself — i.e. an
    /// HTTPS proxy (`CURLPROXY_HTTPS` or `CURLPROXY_HTTPS2`). The method form of
    /// the free function [`is_https_proxy`], reproducing curl's `IS_HTTPS_PROXY`
    /// macro (`lib/http_proxy.h` L61-62).
    #[must_use]
    pub const fn is_https_proxy(self) -> bool {
        matches!(self, CurlProxyType::Https | CurlProxyType::Https2)
    }

    /// Returns `true` for [`Http10`](CurlProxyType::Http10) (`CURLPROXY_HTTP_1_0`),
    /// the proxy type set by `--proxy1.0`, which forces the `CONNECT` request to
    /// be written as `HTTP/1.0` rather than the default `HTTP/1.1`.
    ///
    /// Oracle: `lib/cf-h1-proxy.c` `start_CONNECT` (L223) selects the request's
    /// HTTP minor version with
    /// `http_minor = (proxytype == CURLPROXY_HTTP_1_0) ? 0 : 1;`. This predicate
    /// is the Rust analog of that comparison, letting the `CONNECT`-tunnel builder
    /// pick the matching `http_minor` ([`H1ProxyConfig::with_http_minor`]).
    #[must_use]
    pub const fn is_http_1_0(self) -> bool {
        matches!(self, CurlProxyType::Http10)
    }
}

/// Returns `true` when `t` is an HTTPS proxy type (`CURLPROXY_HTTPS` or
/// `CURLPROXY_HTTPS2`).
///
/// This is the Rust analog of curl's `IS_HTTPS_PROXY(t)` macro
/// (`lib/http_proxy.h` L61-62), which is deliberately defined **outside** the
/// `#ifndef CURL_DISABLE_PROXY` guard and is therefore always available here
/// too. An HTTPS proxy requires the TLS layer ([`crate::tls`]); the capability
/// is reported as `CURL_VERSION_HTTPS_PROXY` (bit `1 << 21`) by
/// [`crate::version`].
#[must_use]
pub const fn is_https_proxy(t: CurlProxyType) -> bool {
    t.is_https_proxy()
}

// ===========================================================================
// Gated proxy machinery (curl's `#ifndef CURL_DISABLE_PROXY`).
//
// Everything below sits behind the `proxy` Cargo feature, mirroring the bulk of
// `lib/http_proxy.h` / `lib/http_proxy.c` / the proxy-handling parts of
// `lib/url.c`, all of which are wrapped in `#if !defined(CURL_DISABLE_PROXY)`.
// ===========================================================================

#[cfg(feature = "proxy")]
mod gated {
    use super::{is_https_proxy, CurlProxyType};
    use crate::error::{CurlError, Result};

    // -----------------------------------------------------------------------
    // Default proxy ports (`lib/url.h` L79-80).
    // -----------------------------------------------------------------------

    /// curl's `CURL_DEFAULT_PROXY_PORT` (`lib/url.h` L79) — the port used for an
    /// HTTP or SOCKS proxy when the proxy string carries no explicit port.
    pub const DEFAULT_PROXY_PORT: u16 = 1080;

    /// curl's `CURL_DEFAULT_HTTPS_PROXY_PORT` (`lib/url.h` L80) — the port used
    /// for an HTTPS proxy (`CURLPROXY_HTTPS` / `CURLPROXY_HTTPS2`) when the proxy
    /// string carries no explicit port.
    pub const DEFAULT_HTTPS_PROXY_PORT: u16 = 443;

    /// The default `CONNECT` tunnel timeout in **milliseconds** — curl's
    /// `PROXY_TIMEOUT` (`lib/http_proxy.h` L48), defined as `3600 * 1000`
    /// (one hour). Consumed by the HTTP-proxy `CONNECT` filter in
    /// [`crate::conn`] to bound how long the tunnel handshake may take.
    pub const PROXY_TIMEOUT: u64 = 3600 * 1000;

    /// Returns the default port for a proxy of type `t` when the proxy string
    /// omits an explicit port: [`DEFAULT_HTTPS_PROXY_PORT`] for an HTTPS proxy,
    /// otherwise [`DEFAULT_PROXY_PORT`]. Mirrors the `else` branch of
    /// `parse_proxy` (`lib/url.c`) that selects the default when no port was
    /// given and no `CURLOPT_PROXYPORT` override is in effect.
    #[must_use]
    pub const fn default_proxy_port(t: CurlProxyType) -> u16 {
        if is_https_proxy(t) {
            DEFAULT_HTTPS_PROXY_PORT
        } else {
            DEFAULT_PROXY_PORT
        }
    }

    // -----------------------------------------------------------------------
    // `ProxyUse` — which header set applies (`enum Curl_proxy_use`).
    // -----------------------------------------------------------------------

    /// Selects which set of request headers applies when talking to a proxy —
    /// the Rust analog of curl's `enum Curl_proxy_use` (`lib/http_proxy.h`
    /// L32-36).
    ///
    /// The HTTP-proxy filter in [`crate::conn`] and the auth output in
    /// [`crate::auth`] consult this to decide whether a request goes direct to
    /// the origin server, through a regular proxy request, or as a `CONNECT`
    /// tunnel-establishment request. It governs custom-header selection
    /// (`CURLOPT_HEADER` vs `CURLOPT_PROXYHEADER`) exactly as curl's
    /// `dynhds_add_custom` does (`lib/http_proxy.c` L40-74).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum ProxyUse {
        /// `HEADER_SERVER` — a request sent direct to the origin server.
        Server,
        /// `HEADER_PROXY` — a regular (non-tunnelled) request to the proxy.
        Proxy,
        /// `HEADER_CONNECT` — a `CONNECT` request establishing a tunnel.
        Connect,
    }

    /// Host literal that marks a SOCKS proxy reachable over a UNIX-domain
    /// socket. Mirrors curl's `#define UNIX_SOCKET_PREFIX "localhost"`
    /// (`lib/url.c` L137, guarded by `USE_UNIX_SOCKETS && !CURL_DISABLE_PROXY`):
    /// when a SOCKS proxy string's host is exactly this literal, the URL path is
    /// the socket path. See [`Proxy::unix_socket_path`].
    pub const UNIX_SOCKET_PREFIX: &str = "localhost";

    // -----------------------------------------------------------------------
    // `Proxy` — the parsed proxy configuration the engine/filters consult.
    // -----------------------------------------------------------------------

    /// A fully parsed proxy configuration — the Rust analog of curl's
    /// `struct proxy_info` (`conn->http_proxy` / `conn->socks_proxy`) combined
    /// with the bits of `data->set` that describe the proxy.
    ///
    /// A `Proxy` is produced by [`Proxy::parse`] from a `CURLOPT_PROXY` /
    /// `CURLOPT_PRE_PROXY` string (or the matching `*_proxy` environment
    /// variable) and is then consulted by the SOCKS handshake engine
    /// ([`super::socks`]) and the HTTP-proxy `CONNECT` filter in
    /// [`crate::conn`].
    ///
    /// `Proxy` is [`Clone`] and [`Debug`] but intentionally **not**
    /// [`PartialEq`]: the HTTPS-proxy [`tls`](Proxy::tls) hook holds a
    /// [`crate::tls::TlsConfig`], which is not comparable. Tests compare the
    /// individual fields instead.
    #[derive(Clone, Debug)]
    pub struct Proxy {
        /// The proxy type (curl `proxy_info.proxytype` / `data->set.proxytype`).
        /// Determines SOCKS-vs-HTTP dispatch and, for HTTP, whether the tunnel
        /// is plain or TLS ([`is_https_proxy`]).
        pub proxytype: CurlProxyType,

        /// The proxy host, with any surrounding IPv6 brackets **stripped** (curl
        /// `proxy_info.host.name`; `parse_proxy` removes the `[` / `]` from a
        /// numeric IPv6 literal in `lib/url.c`). For example a
        /// `http://[::1]:8080` proxy yields `host == "::1"`.
        pub host: String,

        /// The proxy port (curl `proxy_info.port`). When the proxy string omits
        /// a port, [`Proxy::parse`] fills the type default via
        /// [`default_proxy_port`] (`1080` for HTTP/SOCKS, `443` for HTTPS).
        pub port: u16,

        /// The proxy username, URL-decoded, if the proxy string embedded
        /// `user:passwd@` (curl `proxy_info.user`). Used by HTTP(S) proxy
        /// `Proxy-Authorization` and by SOCKS5 username/password subnegotiation.
        pub user: Option<String>,

        /// The proxy password, URL-decoded, if present (curl
        /// `proxy_info.passwd`). Per curl's `parse_proxy`, when a username is
        /// given without a password the password becomes the empty string.
        pub passwd: Option<String>,

        /// The parsed proxy URL handle (curl parses the proxy string through the
        /// URL API in `parse_proxy`). Retained so callers can re-read any
        /// component (e.g. the IPv6 zone id) without re-parsing.
        pub proxy_url: Option<crate::url::CurlUrl>,

        /// TLS settings for the leg to an **HTTPS proxy**, meaningful only when
        /// [`is_https_proxy`]`(self.proxytype)` is `true` (the proxy CA, client
        /// cert/key, and the `--proxy-insecure` toggle live here). [`None`] for
        /// plain HTTP and SOCKS proxies. Uses the same [`crate::tls::TlsConfig`]
        /// type as the rest of the crate; HTTPS-proxy support is reported as
        /// `CURL_VERSION_HTTPS_PROXY` by [`crate::version`].
        pub tls: Option<crate::tls::TlsConfig>,

        /// UNIX-domain socket path for a SOCKS proxy reachable over a UNIX
        /// socket (curl's `--socks5 localhost/path` / `--proxy
        /// socks5h://localhost/path`). curl's `parse_proxy` (`lib/url.c`
        /// L2188-2208, guarded by `USE_UNIX_SOCKETS`) detects this when the
        /// proxy is a SOCKS type AND the host is exactly `localhost`
        /// (`UNIX_SOCKET_PREFIX`) AND the URL carries a path other than `"/"`;
        /// it then records the socket path and rewrites the host to
        /// `"localhost" + path`. When [`Some`], the connection layer dials this
        /// UNIX socket as the bottom transport and runs the SOCKS handshake over
        /// it to reach the origin (the HTTP-proxy unix path is *not* a curl
        /// feature — the detection is `sockstype`-gated). [`None`] for every TCP
        /// proxy. Oracle: tests/data/test1467 (SOCKS5) and test1468 (SOCKS5h).
        pub unix_socket_path: Option<String>,
    }

    impl Proxy {
        /// Parses a proxy string into a [`Proxy`], reproducing curl's
        /// `parse_proxy` (`lib/url.c` L2033-2240) semantics exactly.
        ///
        /// `url_or_host` is a `CURLOPT_PROXY` / `CURLOPT_PRE_PROXY`-style string:
        /// either a full proxy URL (`scheme://[user:passwd@]host[:port]`) or a
        /// bare `host[:port]`. `default_type` is the proxy type implied by the
        /// option the caller used (e.g. [`CurlProxyType::Socks5`] for
        /// `--socks5`); it is kept when the string carries no scheme.
        ///
        /// # Behavior (matching curl)
        ///
        /// * The string is parsed as a URL with `CURLU_NON_SUPPORT_SCHEME |
        ///   CURLU_GUESS_SCHEME`, so curl's made-up proxy schemes are accepted
        ///   and a missing scheme is guessed (a bare host guesses `http`).
        /// * The scheme selects the type: `https` → [`Https`](CurlProxyType::Https)
        ///   (or [`Https2`](CurlProxyType::Https2) when `default_type` was
        ///   already `Https2`), `socks5h` → [`Socks5Hostname`](CurlProxyType::Socks5Hostname),
        ///   `socks5` → [`Socks5`](CurlProxyType::Socks5), `socks4a` →
        ///   [`Socks4a`](CurlProxyType::Socks4a), `socks4`/`socks` →
        ///   [`Socks4`](CurlProxyType::Socks4), and `http` leaves `default_type`
        ///   unchanged (so a `--socks5` bare host stays SOCKS5). Any other scheme
        ///   is rejected.
        /// * Username/password are URL-decoded; a username without a password
        ///   yields an empty password.
        /// * A missing port is filled with [`default_proxy_port`].
        /// * An IPv6 host literal has its `[` / `]` stripped.
        ///
        /// # Errors
        ///
        /// * [`CurlError::CouldntResolveProxy`] (`CURLE_COULDNT_RESOLVE_PROXY`)
        ///   when the string is not valid proxy syntax (URL parse failure) —
        ///   curl's "Unsupported proxy syntax" path.
        /// * [`CurlError::CouldntConnect`] (`CURLE_COULDNT_CONNECT`) when the
        ///   scheme is a valid URL scheme but not a supported proxy scheme —
        ///   curl's "Unsupported proxy scheme" path.
        pub fn parse(url_or_host: &str, default_type: CurlProxyType) -> Result<Proxy> {
            // `CurlUError` is the URL-API error code; it is defined in
            // `crate::error` (and re-used by `crate::url`), so it is imported
            // from there.
            use crate::error::CurlUError;
            use crate::url::{
                CurlUPart, CurlUrl, CURLU_GUESS_SCHEME, CURLU_NON_SUPPORT_SCHEME, CURLU_URLDECODE,
            };

            // Parse the proxy string as a URL. curl uses CURLU_NON_SUPPORT_SCHEME
            // (to accept its made-up `socks*` schemes) and CURLU_GUESS_SCHEME (so
            // a scheme-less `host:port` still parses). A parse failure is curl's
            // "Unsupported proxy syntax" → CURLE_COULDNT_RESOLVE_PROXY.
            let mut uhp = CurlUrl::new();
            uhp.set(
                CurlUPart::Url,
                Some(url_or_host),
                CURLU_NON_SUPPORT_SCHEME | CURLU_GUESS_SCHEME,
            )
            .map_err(|_| CurlError::CouldntResolveProxy)?;

            // Map the scheme to a proxy type. The URL layer stores the scheme
            // lowercased, but we lowercase defensively to match curl's
            // case-insensitive `curl_strequal`.
            let scheme = uhp
                .get(CurlUPart::Scheme, 0)
                .map_err(|_| CurlError::CouldntResolveProxy)?;
            let proxytype = match scheme.to_ascii_lowercase().as_str() {
                "https" => {
                    // Preserve an HTTPS/2 preference; otherwise plain HTTPS.
                    if default_type == CurlProxyType::Https2 {
                        CurlProxyType::Https2
                    } else {
                        CurlProxyType::Https
                    }
                }
                "socks5h" => CurlProxyType::Socks5Hostname,
                "socks5" => CurlProxyType::Socks5,
                "socks4a" => CurlProxyType::Socks4a,
                "socks4" | "socks" => CurlProxyType::Socks4,
                // `http` leaves the caller's type as-is (HTTP or HTTP/1.0, or any
                // type the caller passed for a scheme-less string that guessed
                // to `http`), mirroring curl's empty `; /* leave it */` arm.
                "http" => default_type,
                // Any other valid URL scheme is not a usable proxy scheme.
                _ => return Err(CurlError::CouldntConnect),
            };

            // Username / password, URL-decoded. A missing user/password is not an
            // error (curl tolerates CURLUE_NO_USER / CURLUE_NO_PASSWORD).
            let user = match uhp.get(CurlUPart::User, CURLU_URLDECODE) {
                Ok(u) => Some(u),
                Err(CurlUError::NoUser) => None,
                Err(_) => return Err(CurlError::UrlMalformat),
            };
            let mut passwd = match uhp.get(CurlUPart::Password, CURLU_URLDECODE) {
                Ok(p) => Some(p),
                Err(CurlUError::NoPassword) => None,
                Err(_) => return Err(CurlError::UrlMalformat),
            };
            // curl: when either credential is present but the password is absent,
            // the password becomes the empty string.
            if (user.is_some() || passwd.is_some()) && passwd.is_none() {
                passwd = Some(String::new());
            }

            // Port: use the URL's port when present and numeric (≤ u16::MAX),
            // otherwise the type default. curl additionally honors
            // CURLOPT_PROXYPORT when the URL omits a port; that override has no
            // place in this signature, so the caller applies it afterward (it is
            // documented on the returned `port` field).
            let port = match uhp.get(CurlUPart::Port, 0) {
                Ok(p) => p
                    .parse::<u16>()
                    .unwrap_or_else(|_| default_proxy_port(proxytype)),
                Err(_) => default_proxy_port(proxytype),
            };

            // Host, URL-decoded. The URL layer keeps an IPv6 literal bracketed
            // (`[::1]`); curl's parse_proxy strips the brackets, so we do too.
            let mut host = uhp
                .get(CurlUPart::Host, CURLU_URLDECODE)
                .map_err(|_| CurlError::UrlMalformat)?;
            if host.starts_with('[') && host.ends_with(']') && host.len() >= 2 {
                host = host[1..host.len() - 1].to_string();
            }

            // SOCKS-proxy-over-UNIX-socket detection, mirroring curl's
            // `parse_proxy` (`lib/url.c` L2188-2208, `#ifdef USE_UNIX_SOCKETS`):
            // `if (sockstype && curl_strequal(UNIX_SOCKET_PREFIX, host))`, where
            // `UNIX_SOCKET_PREFIX == "localhost"`. When the proxy is a SOCKS type
            // and the host is exactly `localhost`, the URL path (if not the bare
            // default `"/"`) is the UNIX-domain socket path. curl then rewrites
            // the proxy host to `"localhost" + path` and flags `is_unix_proxy`.
            // The detection is deliberately SOCKS-only (HTTP-proxy-over-unix is
            // not a curl feature). Oracle: tests/data/test1467, test1468.
            let mut unix_socket_path = None;
            if proxytype.is_socks() && host.eq_ignore_ascii_case(UNIX_SOCKET_PREFIX) {
                // The path always resolves (defaulting to `"/"`); a path of
                // exactly `"/"` means "no socket path was given" and leaves the
                // proxy as an ordinary TCP `localhost` SOCKS proxy.
                if let Ok(path) = uhp.get(CurlUPart::Path, CURLU_URLDECODE) {
                    if path != "/" {
                        // Rewrite the host to curl's `"localhost" + path` form so
                        // the reuse key uniquely identifies this socket route, and
                        // record the bare socket path for the dial.
                        host = format!("{UNIX_SOCKET_PREFIX}{path}");
                        unix_socket_path = Some(path);
                    }
                }
            }

            Ok(Proxy {
                proxytype,
                host,
                port,
                user,
                passwd,
                proxy_url: Some(uhp),
                unix_socket_path,
                // An HTTPS proxy starts with a default TLS configuration the
                // caller can populate (proxy CA/cert/key, `--proxy-insecure`);
                // plain HTTP / SOCKS proxies carry no TLS leg.
                tls: if is_https_proxy(proxytype) {
                    Some(crate::tls::TlsConfig::new())
                } else {
                    None
                },
            })
        }

        /// Returns `true` when this is an HTTPS proxy (`CURLPROXY_HTTPS` /
        /// `CURLPROXY_HTTPS2`) — i.e. the [`tls`](Proxy::tls) leg is meaningful.
        #[must_use]
        pub const fn is_https(&self) -> bool {
            is_https_proxy(self.proxytype)
        }

        /// Returns `true` when this is one of the four SOCKS proxy types.
        #[must_use]
        pub const fn is_socks(&self) -> bool {
            self.proxytype.is_socks()
        }

        /// Produces the proxy authentication material for this proxy — the
        /// dispatch hook into [`crate::auth`].
        ///
        /// `authmask` is the `CURLOPT_PROXYAUTH` `CURLAUTH_*` bitmask
        /// (`crate::auth::CURLAUTH_*`). The returned value, when [`Some`], is a
        /// complete `Proxy-Authorization` header line (terminated with `\r\n`)
        /// ready to splice into a `CONNECT` request or a proxied request.
        ///
        /// # Dispatch
        ///
        /// * **SOCKS proxies** ⇒ [`None`]. SOCKS does not use an HTTP auth
        ///   header; the username/password flow through the SOCKS5 RFC 1929
        ///   subnegotiation inside [`super::socks::socks_handshake`] instead.
        /// * **HTTP(S) proxies** ⇒ when the mask permits **Basic**
        ///   ([`crate::auth::CURLAUTH_BASIC`]) and a credential is present, the
        ///   Basic line from [`crate::auth::basic::http_basic_header`] (with the
        ///   `Proxy-` prefix, i.e. `proxy = true`). For the challenge/response
        ///   schemes (Digest, NTLM, Negotiate) the heavy lifting and the actual
        ///   header live in [`crate::auth`] and are driven from the `CONNECT`
        ///   exchange by [`crate::conn`], so this hook returns [`None`] for them
        ///   — it only emits the one scheme (Basic) that needs no server
        ///   challenge.
        ///
        /// # Errors
        ///
        /// Propagates any error from [`crate::auth::basic::http_basic_header`]
        /// (e.g. a base64 sizing failure), mirroring curl's `http_output_basic`.
        pub fn proxy_auth(&self, authmask: u32) -> Result<Option<String>> {
            // SOCKS auth is handled on the wire by the handshake, not via an
            // HTTP header.
            if self.proxytype.is_socks() {
                return Ok(None);
            }

            // Preemptive Basic is emitted only when Basic is the SOLE wanted
            // scheme (`authmask == CURLAUTH_BASIC`), mirroring curl's
            // `output_auth_headers`, which gates the challenge-free Basic header
            // on `authstatus->picked == CURLAUTH_BASIC` — and on the first request
            // `picked == want`. A multi-scheme mask (`--proxy-anyauth`,
            // `CURLAUTH_BASIC | CURLAUTH_DIGEST | CURLAUTH_NTLM`, or
            // `CURLAUTH_ANY`) must NOT send a preemptive Basic: curl issues a
            // credential-less probe and lets the proxy's `407` challenge select
            // the scheme, which the reactive proxy-auth controller then drives
            // (test 548). Testing the bit (`& CURLAUTH_BASIC != 0`) would wrongly
            // emit Basic for every anyauth mask.
            let basic_requested = authmask == crate::auth::CURLAUTH_BASIC;
            let have_credentials = self.user.is_some() || self.passwd.is_some();

            if basic_requested && have_credentials {
                let user = self.user.as_deref().unwrap_or("");
                let passwd = self.passwd.as_deref().unwrap_or("");
                // `proxy = true` ⇒ the `Proxy-Authorization` header prefix.
                let header = crate::auth::basic::http_basic_header(user, passwd, true)?;
                return Ok(Some(header));
            }

            Ok(None)
        }
    }

    // -----------------------------------------------------------------------
    // `ProxyConfig` + the which-proxy decision.
    // -----------------------------------------------------------------------

    /// The resolved proxy configuration for an easy handle — the inputs the
    /// *which-proxy* decision ([`proxy_for_target`]) consults.
    ///
    /// This bundles curl's `data->set.str[STRING_PROXY]` / `STRING_PRE_PROXY`
    /// (already parsed into [`Proxy`] values) with the **resolved** no-proxy
    /// string. The no-proxy string must be resolved *before* it is stored here —
    /// use [`resolve_no_proxy`], which applies `CURLOPT_NOPROXY` first and then
    /// falls back to the `NO_PROXY` / `no_proxy` environment variables.
    #[derive(Clone, Debug, Default)]
    pub struct ProxyConfig {
        /// The main proxy (`CURLOPT_PROXY`). [`None`] when no proxy is set.
        pub proxy: Option<Proxy>,

        /// The pre-proxy (`CURLOPT_PRE_PROXY`) — a SOCKS proxy placed *in front*
        /// of [`proxy`](ProxyConfig::proxy) so the chain is
        /// `client → pre_proxy (SOCKS) → proxy (HTTP) → target`. [`None`] when
        /// unset.
        pub pre_proxy: Option<Proxy>,

        /// The already-resolved no-proxy list (`CURLOPT_NOPROXY`, else the
        /// `NO_PROXY` / `no_proxy` environment variables). A comma-separated set
        /// of host patterns / IPs / CIDRs, or a lone `*` to bypass every proxy.
        /// [`None`] or an empty string means "no bypass list". Build it with
        /// [`resolve_no_proxy`]; the [`noproxy`](super::noproxy) matcher never
        /// reads the environment itself.
        pub no_proxy: Option<String>,
    }

    impl ProxyConfig {
        /// Returns `true` when neither a main proxy nor a pre-proxy is
        /// configured — i.e. the transfer is always direct.
        #[must_use]
        pub const fn is_empty(&self) -> bool {
            self.proxy.is_none() && self.pre_proxy.is_none()
        }
    }

    /// Resolves the effective no-proxy string from the `CURLOPT_NOPROXY` option
    /// and the environment, reproducing curl's precedence.
    ///
    /// `noproxy_opt` is the value of `CURLOPT_NOPROXY` (`data->set.str
    /// [STRING_NOPROXY]`), if the application set one. When it is [`Some`] it
    /// wins outright (even if empty — an explicit empty option disables the
    /// environment fallback, matching curl). When it is [`None`], the
    /// `NO_PROXY` environment variable is consulted first, then its lowercase
    /// `no_proxy` spelling.
    ///
    /// This is the **single place** the proxy subsystem reads the environment
    /// for the no-proxy list (AAP §0.8.3 permits only `NO_PROXY` / `no_proxy`,
    /// plus `HOME` which is consumed elsewhere). The returned string is what
    /// gets stored in [`ProxyConfig::no_proxy`] and handed to
    /// [`check_noproxy`](super::check_noproxy) — which itself never touches the
    /// environment.
    #[must_use]
    pub fn resolve_no_proxy(noproxy_opt: Option<&str>) -> Option<String> {
        // An explicit option (even empty) wins and suppresses the env fallback.
        if let Some(opt) = noproxy_opt {
            return Some(opt.to_string());
        }
        // Environment fallback: uppercase `NO_PROXY` first, then `no_proxy`.
        if let Ok(v) = std::env::var("NO_PROXY") {
            return Some(v);
        }
        if let Ok(v) = std::env::var("no_proxy") {
            return Some(v);
        }
        None
    }

    /// The **which-proxy** decision: returns the proxy a transfer to
    /// `target_host` should route through, or [`None`] when the transfer must be
    /// direct.
    ///
    /// `cfg` is the resolved [`ProxyConfig`] (main proxy, optional pre-proxy, and
    /// the already-resolved no-proxy string). `target_host` is the destination
    /// host **without a port** (the caller strips it, as curl does).
    ///
    /// # Semantics (mirroring curl's proxy selection + `Curl_check_noproxy`)
    ///
    /// 1. If no proxy is configured (`cfg.is_empty()`) ⇒ [`None`].
    /// 2. Otherwise the resolved no-proxy list is consulted via
    ///    [`check_noproxy`](super::check_noproxy). That function returns `true`
    ///    when `target_host` is covered by the list — meaning the proxy **must
    ///    NOT** be used — so a `true` result yields [`None`] (the transfer is
    ///    bypassed). A lone `*` in the list bypasses every host.
    /// 3. Otherwise the applicable proxy is returned. When both a main proxy and
    ///    a pre-proxy are set they form a chain (the SOCKS pre-proxy is the outer
    ///    hop, the HTTP proxy the inner one) and are bypassed together; the
    ///    returned reference is the main [`proxy`](ProxyConfig::proxy) when set,
    ///    otherwise the [`pre_proxy`](ProxyConfig::pre_proxy). The companion hop,
    ///    if any, is reachable through `cfg` directly.
    #[must_use]
    pub fn proxy_for_target<'a>(cfg: &'a ProxyConfig, target_host: &str) -> Option<&'a Proxy> {
        // (1) No proxy configured at all ⇒ direct.
        let chosen = cfg.proxy.as_ref().or(cfg.pre_proxy.as_ref())?;

        // (2) Honor the no-proxy bypass list. `check_noproxy(host, list) == true`
        // means "host is in the no-proxy list → do NOT use a proxy".
        let no_proxy = cfg.no_proxy.as_deref().unwrap_or("");
        if super::check_noproxy(target_host, no_proxy) {
            return None;
        }

        // (3) Not bypassed ⇒ the applicable proxy.
        Some(chosen)
    }
}

// Surface the gated machinery at the module root so consumers use the flat
// `crate::proxy::<item>` path. The `gated` module is a private grouping whose
// sole purpose is to apply `#[cfg(feature = "proxy")]` to the whole block at
// once; everything public within it is re-exported here.
#[cfg(feature = "proxy")]
pub use gated::{
    default_proxy_port, proxy_for_target, resolve_no_proxy, Proxy, ProxyConfig, ProxyUse,
    DEFAULT_HTTPS_PROXY_PORT, DEFAULT_PROXY_PORT, PROXY_TIMEOUT,
};

// ===========================================================================
// Tests.
//
// `tests_abi` covers the always-compiled ABI surface (`CurlProxyType` +
// `is_https_proxy`) and runs in every feature configuration. `tests` covers the
// `proxy`-feature machinery and is itself gated on that feature.
// ===========================================================================

#[cfg(test)]
mod tests_abi {
    use super::{is_https_proxy, CurlProxyType};

    /// The discriminants MUST equal curl's `CURLPROXY_*` integers
    /// (`include/curl/curl.h` L790-808) — this is an ABI contract.
    #[test]
    fn proxytype_discriminants_match_curl_abi() {
        assert_eq!(CurlProxyType::Http.as_raw(), 0);
        assert_eq!(CurlProxyType::Http10.as_raw(), 1);
        assert_eq!(CurlProxyType::Https.as_raw(), 2);
        assert_eq!(CurlProxyType::Https2.as_raw(), 3);
        assert_eq!(CurlProxyType::Socks4.as_raw(), 4);
        assert_eq!(CurlProxyType::Socks5.as_raw(), 5);
        assert_eq!(CurlProxyType::Socks4a.as_raw(), 6);
        assert_eq!(CurlProxyType::Socks5Hostname.as_raw(), 7);
    }

    #[test]
    fn from_raw_round_trips_and_rejects_out_of_range() {
        for raw in 0..=7 {
            let t = CurlProxyType::from_raw(raw).expect("0..=7 are valid");
            assert_eq!(t.as_raw(), raw);
        }
        // 8 is `CURLPROXY_LAST` (the sentinel) and must not map to a variant.
        assert_eq!(CurlProxyType::from_raw(8), None);
        assert_eq!(CurlProxyType::from_raw(-1), None);
        assert_eq!(CurlProxyType::from_raw(i32::MAX), None);
    }

    #[test]
    fn default_is_http() {
        assert_eq!(CurlProxyType::default(), CurlProxyType::Http);
    }

    #[test]
    fn is_socks_and_is_http_are_complements() {
        for raw in 0..=7 {
            let t = CurlProxyType::from_raw(raw).unwrap();
            assert_ne!(t.is_socks(), t.is_http(), "{t:?}");
        }
        assert!(CurlProxyType::Socks4.is_socks());
        assert!(CurlProxyType::Socks5.is_socks());
        assert!(CurlProxyType::Socks4a.is_socks());
        assert!(CurlProxyType::Socks5Hostname.is_socks());
        assert!(CurlProxyType::Http.is_http());
        assert!(CurlProxyType::Http10.is_http());
        assert!(CurlProxyType::Https.is_http());
        assert!(CurlProxyType::Https2.is_http());
    }

    /// `is_https_proxy` (both the free function and the method) reproduces
    /// curl's `IS_HTTPS_PROXY` macro: true only for `HTTPS` and `HTTPS2`.
    #[test]
    fn is_https_proxy_matches_macro() {
        assert!(is_https_proxy(CurlProxyType::Https));
        assert!(is_https_proxy(CurlProxyType::Https2));
        assert!(CurlProxyType::Https.is_https_proxy());
        assert!(CurlProxyType::Https2.is_https_proxy());

        for t in [
            CurlProxyType::Http,
            CurlProxyType::Http10,
            CurlProxyType::Socks4,
            CurlProxyType::Socks5,
            CurlProxyType::Socks4a,
            CurlProxyType::Socks5Hostname,
        ] {
            assert!(!is_https_proxy(t), "{t:?}");
            assert!(!t.is_https_proxy(), "{t:?}");
        }
    }

    /// `is_http_1_0` is true only for `Http10` (`CURLPROXY_HTTP_1_0`, set by
    /// `--proxy1.0`) — the predicate the `CONNECT` builder uses to pick
    /// `http_minor = 0` (oracle: `cf-h1-proxy.c` L223).
    #[test]
    fn is_http_1_0_matches_only_http10() {
        assert!(CurlProxyType::Http10.is_http_1_0());
        for t in [
            CurlProxyType::Http,
            CurlProxyType::Https,
            CurlProxyType::Https2,
            CurlProxyType::Socks4,
            CurlProxyType::Socks5,
            CurlProxyType::Socks4a,
            CurlProxyType::Socks5Hostname,
        ] {
            assert!(!t.is_http_1_0(), "{t:?}");
        }
    }
}

#[cfg(all(test, feature = "proxy"))]
mod tests {
    use super::{
        default_proxy_port, proxy_for_target, resolve_no_proxy, CurlProxyType, Proxy, ProxyConfig,
        ProxyUse, DEFAULT_HTTPS_PROXY_PORT, DEFAULT_PROXY_PORT, PROXY_TIMEOUT,
    };
    use crate::auth::{CURLAUTH_BASIC, CURLAUTH_DIGEST, CURLAUTH_NTLM};

    #[test]
    fn proxy_timeout_is_one_hour_in_ms() {
        assert_eq!(PROXY_TIMEOUT, 3_600_000);
        assert_eq!(PROXY_TIMEOUT, 3600 * 1000);
    }

    #[test]
    fn default_ports_match_curl() {
        assert_eq!(DEFAULT_PROXY_PORT, 1080);
        assert_eq!(DEFAULT_HTTPS_PROXY_PORT, 443);
        assert_eq!(default_proxy_port(CurlProxyType::Http), 1080);
        assert_eq!(default_proxy_port(CurlProxyType::Http10), 1080);
        assert_eq!(default_proxy_port(CurlProxyType::Socks5), 1080);
        assert_eq!(default_proxy_port(CurlProxyType::Https), 443);
        assert_eq!(default_proxy_port(CurlProxyType::Https2), 443);
    }

    #[test]
    fn proxy_use_variants_distinct() {
        assert_ne!(ProxyUse::Server, ProxyUse::Proxy);
        assert_ne!(ProxyUse::Proxy, ProxyUse::Connect);
        assert_ne!(ProxyUse::Server, ProxyUse::Connect);
    }

    #[test]
    fn parse_socks5h_full_url() {
        let p = Proxy::parse("socks5h://user:pass@host:1080", CurlProxyType::Http).unwrap();
        assert_eq!(p.proxytype, CurlProxyType::Socks5Hostname);
        assert_eq!(p.host, "host");
        assert_eq!(p.port, 1080);
        assert_eq!(p.user.as_deref(), Some("user"));
        assert_eq!(p.passwd.as_deref(), Some("pass"));
        assert!(p.is_socks());
        assert!(p.tls.is_none());
    }

    #[test]
    fn parse_socks5_unix_socket_path() {
        // `--socks5 localhost/path` → SOCKS5 over a UNIX-domain socket. curl's
        // parse_proxy records the socket path and rewrites the host to
        // `"localhost" + path`. The default type (Socks5 here) is kept because
        // the scheme is guessed/absent. Oracle: tests/data/test1467.
        let p = Proxy::parse(
            "localhost/tmp/curl-c-build/tests/log/server/socks-uds",
            CurlProxyType::Socks5,
        )
        .unwrap();
        assert_eq!(p.proxytype, CurlProxyType::Socks5);
        assert!(p.is_socks());
        assert_eq!(
            p.unix_socket_path.as_deref(),
            Some("/tmp/curl-c-build/tests/log/server/socks-uds")
        );
        // Host rewritten to the `localhost`+path form (curl's `host.name`).
        assert_eq!(p.host, "localhost/tmp/curl-c-build/tests/log/server/socks-uds");
    }

    #[test]
    fn parse_socks5h_unix_socket_scheme_url() {
        // `--proxy socks5h://localhost/path` → SOCKS5h over a UNIX socket.
        // Oracle: tests/data/test1468.
        let p = Proxy::parse("socks5h://localhost/run/socks.sock", CurlProxyType::Http).unwrap();
        assert_eq!(p.proxytype, CurlProxyType::Socks5Hostname);
        assert_eq!(p.unix_socket_path.as_deref(), Some("/run/socks.sock"));
        assert_eq!(p.host, "localhost/run/socks.sock");
    }

    #[test]
    fn parse_socks5_localhost_without_path_is_tcp() {
        // A bare `localhost` SOCKS proxy (no path, or just `/`) stays an ordinary
        // TCP proxy — `unix_socket_path` must be `None` and the host unchanged.
        let p = Proxy::parse("socks5://localhost:1080", CurlProxyType::Http).unwrap();
        assert_eq!(p.proxytype, CurlProxyType::Socks5);
        assert!(p.unix_socket_path.is_none());
        assert_eq!(p.host, "localhost");
        assert_eq!(p.port, 1080);

        // An explicit trailing `/` is curl's "no path" sentinel → still TCP.
        let p2 = Proxy::parse("socks5://localhost/", CurlProxyType::Http).unwrap();
        assert!(p2.unix_socket_path.is_none());
        assert_eq!(p2.host, "localhost");
    }

    #[test]
    fn parse_http_localhost_with_path_is_not_unix() {
        // The UNIX-socket detection is SOCKS-only (curl's `sockstype` guard): an
        // HTTP proxy with `localhost/path` is NOT a unix proxy.
        let p = Proxy::parse("http://localhost/whatever", CurlProxyType::Http).unwrap();
        assert!(!p.is_socks());
        assert!(p.unix_socket_path.is_none());
        assert_eq!(p.host, "localhost");
    }

    #[test]
    fn parse_scheme_to_type_mapping() {
        let cases = [
            ("http://h", CurlProxyType::Http, CurlProxyType::Http),
            // `http` keeps the caller's HTTP/1.0 default.
            ("http://h", CurlProxyType::Http10, CurlProxyType::Http10),
            ("https://h", CurlProxyType::Http, CurlProxyType::Https),
            // `https` upgrades to HTTPS2 only when the default was already HTTPS2.
            ("https://h", CurlProxyType::Https2, CurlProxyType::Https2),
            ("socks4://h", CurlProxyType::Http, CurlProxyType::Socks4),
            ("socks://h", CurlProxyType::Http, CurlProxyType::Socks4),
            ("socks4a://h", CurlProxyType::Http, CurlProxyType::Socks4a),
            ("socks5://h", CurlProxyType::Http, CurlProxyType::Socks5),
            (
                "socks5h://h",
                CurlProxyType::Http,
                CurlProxyType::Socks5Hostname,
            ),
        ];
        for (s, default_type, expected) in cases {
            let p = Proxy::parse(s, default_type).unwrap();
            assert_eq!(
                p.proxytype, expected,
                "input {s:?} default {default_type:?}"
            );
        }
    }

    #[test]
    fn parse_default_port_applied_when_omitted() {
        // HTTP / SOCKS proxies default to 1080; HTTPS proxies to 443.
        assert_eq!(
            Proxy::parse("http://h", CurlProxyType::Http).unwrap().port,
            1080
        );
        assert_eq!(
            Proxy::parse("socks5://h", CurlProxyType::Http)
                .unwrap()
                .port,
            1080
        );
        assert_eq!(
            Proxy::parse("https://h", CurlProxyType::Http).unwrap().port,
            443
        );
    }

    #[test]
    fn parse_https_proxy_has_tls_config() {
        let p = Proxy::parse("https://secure-proxy", CurlProxyType::Http).unwrap();
        assert!(p.is_https());
        assert!(p.tls.is_some(), "an HTTPS proxy carries a TLS config hook");
    }

    #[test]
    fn parse_bracketed_ipv6_strips_brackets() {
        let p = Proxy::parse("http://[2001:db8::1]:8080", CurlProxyType::Http).unwrap();
        assert_eq!(p.host, "2001:db8::1");
        assert_eq!(p.port, 8080);
    }

    #[test]
    fn parse_user_without_password_yields_empty_password() {
        let p = Proxy::parse("http://onlyuser@host", CurlProxyType::Http).unwrap();
        assert_eq!(p.user.as_deref(), Some("onlyuser"));
        assert_eq!(p.passwd.as_deref(), Some(""));
    }

    #[test]
    fn parse_bare_host_guesses_http_and_keeps_default_type() {
        // A scheme-less host:port guesses `http`; the `http` arm keeps the
        // caller's default type, so a SOCKS5 default stays SOCKS5.
        let http = Proxy::parse("proxy.example.com:3128", CurlProxyType::Http).unwrap();
        assert_eq!(http.proxytype, CurlProxyType::Http);
        assert_eq!(http.host, "proxy.example.com");
        assert_eq!(http.port, 3128);

        let socks = Proxy::parse("proxy.example.com:1080", CurlProxyType::Socks5).unwrap();
        assert_eq!(socks.proxytype, CurlProxyType::Socks5);
        assert_eq!(socks.host, "proxy.example.com");
        assert_eq!(socks.port, 1080);
    }

    #[test]
    fn parse_unsupported_scheme_is_rejected() {
        // `ftp` is a valid URL scheme but not a usable proxy scheme.
        assert!(Proxy::parse("ftp://host", CurlProxyType::Http).is_err());
    }

    #[test]
    fn proxy_auth_http_basic_emits_proxy_authorization() {
        let p = Proxy::parse("http://bob:secret@proxy:3128", CurlProxyType::Http).unwrap();
        let header = p
            .proxy_auth(CURLAUTH_BASIC)
            .unwrap()
            .expect("HTTP proxy with credentials yields a Basic header");
        assert!(
            header.starts_with("Proxy-Authorization: Basic "),
            "got {header:?}"
        );
        assert!(header.ends_with("\r\n"));
    }

    #[test]
    fn proxy_auth_socks_returns_none() {
        let p = Proxy::parse("socks5://bob:secret@proxy:1080", CurlProxyType::Http).unwrap();
        // SOCKS credentials flow through the handshake, not an HTTP header.
        assert_eq!(p.proxy_auth(CURLAUTH_BASIC).unwrap(), None);
    }

    #[test]
    fn proxy_auth_http_without_basic_bit_returns_none() {
        let p = Proxy::parse("http://bob:secret@proxy:3128", CurlProxyType::Http).unwrap();
        // Only Digest requested (no Basic bit) ⇒ this hook emits nothing; the
        // challenge/response scheme is driven from the CONNECT exchange.
        assert_eq!(p.proxy_auth(CURLAUTH_DIGEST).unwrap(), None);
    }

    #[test]
    fn proxy_auth_multibit_anyauth_mask_returns_none() {
        // A multi-scheme mask (`--proxy-anyauth` style) must NOT emit a
        // preemptive Basic even with credentials: curl probes credential-less and
        // lets the `407` challenge pick the scheme (test 548). Only an exact
        // `CURLAUTH_BASIC` mask emits the challenge-free Basic line.
        let p = Proxy::parse("http://testuser:testpass@proxy:3128", CurlProxyType::Http).unwrap();
        let mask = CURLAUTH_BASIC | CURLAUTH_DIGEST | CURLAUTH_NTLM;
        assert_eq!(p.proxy_auth(mask).unwrap(), None);
        // The exact-Basic mask still emits, for the single `--proxy-user` case.
        assert!(p.proxy_auth(CURLAUTH_BASIC).unwrap().is_some());
    }

    #[test]
    fn proxy_auth_http_without_credentials_returns_none() {
        let p = Proxy::parse("http://proxy:3128", CurlProxyType::Http).unwrap();
        assert_eq!(p.proxy_auth(CURLAUTH_BASIC).unwrap(), None);
    }

    fn http_proxy() -> Proxy {
        Proxy::parse("http://proxy.local:3128", CurlProxyType::Http).unwrap()
    }

    #[test]
    fn proxy_for_target_bypasses_listed_host() {
        let cfg = ProxyConfig {
            proxy: Some(http_proxy()),
            pre_proxy: None,
            no_proxy: Some("example.com".to_string()),
        };
        // A subdomain of a listed domain is bypassed.
        assert!(proxy_for_target(&cfg, "www.example.com").is_none());
        // An unrelated host still uses the proxy.
        assert!(proxy_for_target(&cfg, "other.com").is_some());
    }

    #[test]
    fn proxy_for_target_wildcard_bypasses_everything() {
        let cfg = ProxyConfig {
            proxy: Some(http_proxy()),
            pre_proxy: None,
            no_proxy: Some("*".to_string()),
        };
        assert!(proxy_for_target(&cfg, "anything.example").is_none());
        assert!(proxy_for_target(&cfg, "another.host").is_none());
    }

    #[test]
    fn proxy_for_target_no_proxy_configured_is_none() {
        let cfg = ProxyConfig::default();
        assert!(cfg.is_empty());
        assert!(proxy_for_target(&cfg, "any.host").is_none());
    }

    #[test]
    fn proxy_for_target_returns_proxy_when_not_bypassed() {
        let cfg = ProxyConfig {
            proxy: Some(http_proxy()),
            pre_proxy: None,
            no_proxy: None,
        };
        let chosen = proxy_for_target(&cfg, "target.host").expect("proxy applies");
        assert_eq!(chosen.host, "proxy.local");
        assert_eq!(chosen.port, 3128);
    }

    #[test]
    fn proxy_for_target_falls_back_to_pre_proxy() {
        // Only a pre-proxy (SOCKS) is set: it is the applicable proxy.
        let cfg = ProxyConfig {
            proxy: None,
            pre_proxy: Some(
                Proxy::parse("socks5://socks.local:1080", CurlProxyType::Socks5).unwrap(),
            ),
            no_proxy: None,
        };
        let chosen = proxy_for_target(&cfg, "target.host").expect("pre-proxy applies");
        assert!(chosen.is_socks());
        assert_eq!(chosen.host, "socks.local");
    }

    #[test]
    fn resolve_no_proxy_option_wins_over_env() {
        // An explicit option (even empty) is returned verbatim and suppresses
        // the environment fallback.
        assert_eq!(
            resolve_no_proxy(Some("a.com,b.com")),
            Some("a.com,b.com".to_string())
        );
        assert_eq!(resolve_no_proxy(Some("")), Some(String::new()));
    }
}
