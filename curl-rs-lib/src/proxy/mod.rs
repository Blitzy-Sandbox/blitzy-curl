//! Proxy support for curl-rs.
//!
//! This module provides:
//! - **SOCKS proxy**: SOCKS4, SOCKS4a, SOCKS5, and SOCKS5-hostname proxy connection filters
//!   with support for no-auth, username/password, and GSSAPI authentication methods.
//!   The [`SocksProxyFilter`] connection filter implements the SOCKS handshake and
//!   then transparently tunnels data once the handshake completes.
//! - **No-proxy matching**: Evaluates hostnames and IP addresses against the `NO_PROXY`
//!   environment variable or `--noproxy` option, supporting hostname suffix matching,
//!   IPv4/IPv6 CIDR notation, and wildcard (`*`) entries. See [`check_noproxy`].
//!
//! # Architecture
//!
//! The SOCKS proxy is implemented as a connection filter (see `crate::conn::filters`)
//! that sits between the socket layer and the next protocol filter. The no-proxy
//! matching is a standalone utility used during connection setup to determine whether
//! to bypass the proxy entirely.
//!
//! HTTP proxy support (CONNECT tunnelling) is handled separately in
//! `crate::conn::h1_proxy` and `crate::conn::h2_proxy` — this module only covers
//! SOCKS proxies and no-proxy evaluation.
//!
//! # Proxy Type Selection
//!
//! The [`ProxyType`] enum enumerates every proxy mode supported by curl-rs,
//! including the HTTP/HTTPS variants handled outside this module. It is
//! defined here as the shared discriminant used by `setopt`, `url`, and
//! connection-setup code to route through the correct proxy path.
//!
//! # C Source Mapping
//!
//! | Rust Module | C Source |
//! |---|---|
//! | [`socks`] | `lib/socks.c` (1,415 lines), `lib/socks_gssapi.c`, `lib/socks_sspi.c` |
//! | [`noproxy`] | `lib/noproxy.c` (~260 lines) |

// ---------------------------------------------------------------------------
// Child module declarations
// ---------------------------------------------------------------------------

pub mod noproxy;
pub mod socks;

// ---------------------------------------------------------------------------
// Re-exports — ergonomic access to the most commonly used items
// ---------------------------------------------------------------------------

// SOCKS proxy filter and supporting types.
pub use socks::{SocksProxyCode, SocksProxyFilter, SocksVersion};

// No-proxy matching functions.
pub use noproxy::{check_noproxy, cidr4_match, cidr6_match};

// ---------------------------------------------------------------------------
// ProxyType — shared proxy mode discriminant
// ---------------------------------------------------------------------------

/// Proxy type discriminant covering all modes supported by curl-rs.
///
/// Maps to the C `CURLPROXY_*` constants in `include/curl/curl.h`:
///
/// | Variant         | C constant                   | Integer value |
/// |-----------------|------------------------------|---------------|
/// | `None`          | (no proxy)                   | —             |
/// | `Http`          | `CURLPROXY_HTTP`             | 0             |
/// | `Https`         | `CURLPROXY_HTTPS`            | 2             |
/// | `Socks4`        | `CURLPROXY_SOCKS4`           | 4             |
/// | `Socks4a`       | `CURLPROXY_SOCKS4A`          | 6             |
/// | `Socks5`        | `CURLPROXY_SOCKS5`           | 5             |
/// | `Socks5Hostname`| `CURLPROXY_SOCKS5_HOSTNAME`  | 7             |
///
/// The integer discriminants intentionally match the C values for FFI
/// round-trip safety.  The `None` variant has no C counterpart — it
/// represents the absence of any proxy configuration.
///
/// # Usage
///
/// ```rust,ignore
/// use curl_rs_lib::proxy::ProxyType;
///
/// let proxy = ProxyType::Socks5;
/// assert!(proxy.is_socks());
/// assert!(!proxy.is_http());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyType {
    /// No proxy configured.
    None,
    /// HTTP proxy (`CURLPROXY_HTTP`, value 0).
    Http,
    /// HTTPS proxy — TLS to proxy, then CONNECT (`CURLPROXY_HTTPS`, value 2).
    Https,
    /// SOCKS4 proxy — client-side DNS, IPv4 only (`CURLPROXY_SOCKS4`, value 4).
    Socks4,
    /// SOCKS4a proxy — proxy-side DNS (`CURLPROXY_SOCKS4A`, value 6).
    Socks4a,
    /// SOCKS5 proxy — client-side DNS, IPv4/IPv6 (`CURLPROXY_SOCKS5`, value 5).
    Socks5,
    /// SOCKS5 with hostname — proxy-side DNS (`CURLPROXY_SOCKS5_HOSTNAME`, value 7).
    Socks5Hostname,
}

impl ProxyType {
    /// Returns `true` if this is any SOCKS variant (V4, V4a, V5, V5Hostname).
    ///
    /// Useful for routing proxy setup through the SOCKS filter path.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// assert!(ProxyType::Socks5.is_socks());
    /// assert!(!ProxyType::Http.is_socks());
    /// assert!(!ProxyType::None.is_socks());
    /// ```
    pub fn is_socks(&self) -> bool {
        matches!(
            self,
            Self::Socks4 | Self::Socks4a | Self::Socks5 | Self::Socks5Hostname
        )
    }

    /// Returns `true` if this is an HTTP or HTTPS proxy.
    ///
    /// HTTP/HTTPS proxies use the CONNECT method for tunnelling and are
    /// handled by `crate::conn::h1_proxy` / `crate::conn::h2_proxy`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// assert!(ProxyType::Http.is_http());
    /// assert!(ProxyType::Https.is_http());
    /// assert!(!ProxyType::Socks5.is_http());
    /// ```
    pub fn is_http(&self) -> bool {
        matches!(self, Self::Http | Self::Https)
    }

    /// Returns `true` if no proxy is configured.
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Converts the proxy type to the corresponding [`SocksVersion`], if
    /// applicable.
    ///
    /// Returns `None` for non-SOCKS proxy types (`None`, `Http`, `Https`).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// assert_eq!(
    ///     ProxyType::Socks5.to_socks_version(),
    ///     Some(SocksVersion::V5),
    /// );
    /// assert_eq!(ProxyType::Http.to_socks_version(), None);
    /// ```
    pub fn to_socks_version(&self) -> Option<SocksVersion> {
        match self {
            Self::Socks4 => Some(SocksVersion::V4),
            Self::Socks4a => Some(SocksVersion::V4a),
            Self::Socks5 => Some(SocksVersion::V5),
            Self::Socks5Hostname => Some(SocksVersion::V5Hostname),
            Self::None | Self::Http | Self::Https => None,
        }
    }

    /// Converts a C `CURLPROXY_*` integer value to the corresponding
    /// `ProxyType`.
    ///
    /// Returns `None` for unrecognised values. This is used at the FFI
    /// boundary when translating `curl_easy_setopt(CURLOPT_PROXYTYPE, ...)`
    /// calls.
    ///
    /// # C value mapping
    ///
    /// | Value | Constant                    | Variant          |
    /// |-------|-----------------------------|------------------|
    /// | 0     | `CURLPROXY_HTTP`            | `Http`           |
    /// | 2     | `CURLPROXY_HTTPS`           | `Https`          |
    /// | 4     | `CURLPROXY_SOCKS4`          | `Socks4`         |
    /// | 5     | `CURLPROXY_SOCKS5`          | `Socks5`         |
    /// | 6     | `CURLPROXY_SOCKS4A`         | `Socks4a`        |
    /// | 7     | `CURLPROXY_SOCKS5_HOSTNAME` | `Socks5Hostname` |
    pub fn from_c_value(value: i64) -> Option<Self> {
        match value {
            0 => Some(Self::Http),
            2 => Some(Self::Https),
            4 => Some(Self::Socks4),
            5 => Some(Self::Socks5),
            6 => Some(Self::Socks4a),
            7 => Some(Self::Socks5Hostname),
            _ => None,
        }
    }

    /// Returns the C `CURLPROXY_*` integer value for this proxy type.
    ///
    /// Returns `None` for `ProxyType::None` since there is no C constant
    /// for "no proxy".
    pub fn to_c_value(&self) -> Option<i64> {
        match self {
            Self::None => Option::None,
            Self::Http => Some(0),
            Self::Https => Some(2),
            Self::Socks4 => Some(4),
            Self::Socks5 => Some(5),
            Self::Socks4a => Some(6),
            Self::Socks5Hostname => Some(7),
        }
    }
}

impl Default for ProxyType {
    /// Defaults to [`ProxyType::None`] — no proxy configured.
    fn default() -> Self {
        Self::None
    }
}

impl core::fmt::Display for ProxyType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Http => write!(f, "HTTP"),
            Self::Https => write!(f, "HTTPS"),
            Self::Socks4 => write!(f, "SOCKS4"),
            Self::Socks4a => write!(f, "SOCKS4a"),
            Self::Socks5 => write!(f, "SOCKS5"),
            Self::Socks5Hostname => write!(f, "SOCKS5_HOSTNAME"),
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── ProxyType enum ─────────────────────────────────────────────────

    #[test]
    fn proxy_type_default_is_none() {
        assert_eq!(ProxyType::default(), ProxyType::None);
    }

    #[test]
    fn proxy_type_is_socks() {
        assert!(ProxyType::Socks4.is_socks());
        assert!(ProxyType::Socks4a.is_socks());
        assert!(ProxyType::Socks5.is_socks());
        assert!(ProxyType::Socks5Hostname.is_socks());
        assert!(!ProxyType::None.is_socks());
        assert!(!ProxyType::Http.is_socks());
        assert!(!ProxyType::Https.is_socks());
    }

    #[test]
    fn proxy_type_is_http() {
        assert!(ProxyType::Http.is_http());
        assert!(ProxyType::Https.is_http());
        assert!(!ProxyType::None.is_http());
        assert!(!ProxyType::Socks4.is_http());
        assert!(!ProxyType::Socks5.is_http());
    }

    #[test]
    fn proxy_type_is_none() {
        assert!(ProxyType::None.is_none());
        assert!(!ProxyType::Http.is_none());
        assert!(!ProxyType::Socks5.is_none());
    }

    #[test]
    fn proxy_type_to_socks_version() {
        assert_eq!(ProxyType::Socks4.to_socks_version(), Some(SocksVersion::V4));
        assert_eq!(ProxyType::Socks4a.to_socks_version(), Some(SocksVersion::V4a));
        assert_eq!(ProxyType::Socks5.to_socks_version(), Some(SocksVersion::V5));
        assert_eq!(
            ProxyType::Socks5Hostname.to_socks_version(),
            Some(SocksVersion::V5Hostname)
        );
        assert_eq!(ProxyType::None.to_socks_version(), None);
        assert_eq!(ProxyType::Http.to_socks_version(), None);
        assert_eq!(ProxyType::Https.to_socks_version(), None);
    }

    #[test]
    fn proxy_type_c_value_roundtrip() {
        // Each SOCKS/HTTP variant should round-trip through C integer values.
        let variants = [
            ProxyType::Http,
            ProxyType::Https,
            ProxyType::Socks4,
            ProxyType::Socks4a,
            ProxyType::Socks5,
            ProxyType::Socks5Hostname,
        ];
        for variant in variants {
            let c_val = variant.to_c_value().expect("should have C value");
            let back = ProxyType::from_c_value(c_val).expect("should parse back");
            assert_eq!(back, variant, "round-trip failed for {:?}", variant);
        }
    }

    #[test]
    fn proxy_type_none_has_no_c_value() {
        assert_eq!(ProxyType::None.to_c_value(), None);
    }

    #[test]
    fn proxy_type_from_c_unknown_value() {
        assert_eq!(ProxyType::from_c_value(-1), None);
        assert_eq!(ProxyType::from_c_value(1), None);
        assert_eq!(ProxyType::from_c_value(3), None);
        assert_eq!(ProxyType::from_c_value(99), None);
    }

    #[test]
    fn proxy_type_display() {
        assert_eq!(format!("{}", ProxyType::None), "none");
        assert_eq!(format!("{}", ProxyType::Http), "HTTP");
        assert_eq!(format!("{}", ProxyType::Https), "HTTPS");
        assert_eq!(format!("{}", ProxyType::Socks4), "SOCKS4");
        assert_eq!(format!("{}", ProxyType::Socks4a), "SOCKS4a");
        assert_eq!(format!("{}", ProxyType::Socks5), "SOCKS5");
        assert_eq!(format!("{}", ProxyType::Socks5Hostname), "SOCKS5_HOSTNAME");
    }

    #[test]
    fn proxy_type_clone_and_copy() {
        let a = ProxyType::Socks5;
        let b = a; // Copy
        let c = a.clone(); // Clone
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn proxy_type_eq_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ProxyType::Http);
        set.insert(ProxyType::Socks5);
        set.insert(ProxyType::Http); // duplicate
        assert_eq!(set.len(), 2);
    }

    // ── Re-exports ────────────────────────────────────────────────────

    #[test]
    fn reexport_socks_types_accessible() {
        // Verify that the re-exported types are reachable through the
        // proxy module (compile-time check turned into a runtime assertion).
        let _v = SocksVersion::V5;
        let _c = SocksProxyCode::Ok;
    }

    #[test]
    fn reexport_noproxy_functions_accessible() {
        // Wildcard should match everything.
        assert!(check_noproxy("example.com", "*"));
        // Empty no_proxy → no bypass.
        assert!(!check_noproxy("example.com", ""));
    }

    #[test]
    fn reexport_cidr_functions_accessible() {
        assert!(cidr4_match("192.168.1.1", "192.168.1.0", 24));
        assert!(cidr6_match("fe80::1", "fe80::", 10));
    }
}
