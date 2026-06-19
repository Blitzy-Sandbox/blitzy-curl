//! Proxy support — SOCKS, HTTP-proxy tunnelling, and no-proxy matching.
//!
//! This module is the Rust home of curl's proxy layer (`lib/socks.c`,
//! `lib/http_proxy.c`, `lib/noproxy.c`). It groups the proxy concerns the
//! transfer engine and the connection-filter chain consume through ordinary
//! Rust paths (`crate::proxy::<name>`) rather than via curl's C `#include`
//! graph (Agent Action Plan §0.5.1 / §0.5.2).
//!
//! # Submodules
//!
//! * [`noproxy`] — the `NO_PROXY` / `--noproxy` host-matching logic
//!   (`lib/noproxy.c`): decides whether a given host bypasses the configured
//!   proxy, reproducing curl's domain-suffix, IP, and CIDR matching exactly.
//! * [`socks`] — the SOCKS4 / SOCKS4a / SOCKS5 / SOCKS5h client handshake engine
//!   (`lib/socks.c`): the pure, async, byte-exact reimplementation of curl's
//!   SOCKS proxy negotiation. Gated behind the `proxy` Cargo feature (curl's
//!   `#ifndef CURL_DISABLE_PROXY`).
//!
//! Additional proxy concerns enumerated by the AAP (HTTP `CONNECT` tunnelling)
//! are authored as sibling submodules in their own migration steps; this
//! `mod.rs` is the single declaration point that wires them into the crate as
//! they land.

pub mod noproxy;

// The SOCKS handshake engine lives under curl's `CURL_DISABLE_PROXY` gate (the
// `proxy` Cargo feature, default ON). Keeping the declaration feature-gated
// ensures `--no-default-features` drops the SOCKS engine cleanly, exactly as a
// `CURL_DISABLE_PROXY` C build omits `lib/socks.c`.
#[cfg(feature = "proxy")]
pub mod socks;

/// The kind of proxy a connection routes through — the Rust analog of curl's
/// `curl_proxytype` enum (`include/curl/curl.h`), the value carried by
/// `CURLOPT_PROXYTYPE`.
///
/// # ABI contract (do not change the integer values)
///
/// The discriminants reproduce curl's `CURLPROXY_*` constants **exactly** so the
/// FFI layer can transmute the `long` the C caller passes to `CURLOPT_PROXYTYPE`
/// straight into this enum, and so `curl_easy_getinfo`-style round-trips observe
/// identical values:
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
/// the HTTP/HTTPS variants are handled by the HTTP-proxy tunnelling path. The
/// `Socks4a` / `Socks5Hostname` ("`5h`") variants are the *remote-DNS* forms
/// that send the destination hostname to the proxy instead of resolving it
/// locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CurlProxyType {
    /// `CURLPROXY_HTTP` (0) — HTTP proxy (the default).
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

    /// Returns the raw `CURLPROXY_*` integer for this proxy type.
    #[must_use]
    pub const fn as_raw(self) -> i32 {
        self as i32
    }

    /// Returns `true` for any of the four SOCKS proxy types (the ones the
    /// [`socks`] handshake engine handles), `false` for the HTTP/HTTPS types.
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
}
