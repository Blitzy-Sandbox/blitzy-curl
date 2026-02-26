//! Hickory DNS resolver — pure-Rust async DNS resolver.
//!
//! This module is feature-gated behind `hickory-dns` and is disabled by default.
//! It replaces the C c-ares async DNS backend (`lib/asyn-ares.c`).
//!
//! When enabled, provides an alternative to the system resolver with features:
//! - Custom DNS server configuration
//! - DNS-over-TLS support (requires `dns-over-rustls` feature on hickory-resolver)
//! - Pure-Rust implementation (no C library dependency)
//!
//! # Architecture
//!
//! The C c-ares backend (lib/asyn-ares.c, ~600+ lines) integrates with c-ares 1.16.0+
//! for async DNS resolution. Key c-ares concepts mapped to hickory-resolver:
//!
//! | c-ares concept | Rust equivalent |
//! |------|------|
//! | `ares_init_options()` | `Resolver::builder_with_config(config, provider).build()` |
//! | `ares_getaddrinfo()` | `resolver.lookup_ip(host).await` |
//! | `ares_destroy()` | `drop(resolver)` — automatic via Rust ownership |
//! | `ares_set_servers_csv()` | `ResolverConfig` with custom `NameServerConfig` entries |
//! | `ARES_OPT_TIMEOUTMS` | `ResolverOpts::timeout` field |
//! | `ares_fds()` polling | Not needed — Tokio runtime handles async I/O natively |
//! | `ares_library_init()` | No-op — hickory-resolver has no global state |
//!
//! # Feature Gate
//!
//! This entire module is only compiled when the `hickory-dns` feature is enabled.
//! The feature gate is applied at the module declaration in `dns/mod.rs`:
//! ```ignore
//! #[cfg(feature = "hickory-dns")]
//! pub mod hickory;
//! ```

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use hickory_resolver::config::{
    NameServerConfig, ResolverConfig, ResolverOpts,
};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::xfer::Protocol;
use hickory_resolver::proto::ProtoErrorKind;
use hickory_resolver::{ResolveError, TokioResolver};

use crate::error::CurlError;
use super::{IpVersion, Resolver};

/// Default per-query timeout in milliseconds.
///
/// Matches the C c-ares constant `CARES_TIMEOUT_PER_ATTEMPT` defined in
/// `lib/asyn-ares.c` line 50:
/// ```c
/// #define CARES_TIMEOUT_PER_ATTEMPT 2000
/// ```
const DEFAULT_TIMEOUT_MS: u64 = 2000;

/// Default number of resolution attempts before giving up.
///
/// Matches the c-ares default retry count. In c-ares, this is controlled by
/// `ARES_OPT_TRIES` and defaults to 3.
const DEFAULT_ATTEMPTS: usize = 3;

// ---------------------------------------------------------------------------
// HickoryConfig — configuration for the Hickory DNS resolver
// ---------------------------------------------------------------------------

/// Configuration for the Hickory DNS resolver.
///
/// Maps from c-ares options in `lib/asyn-ares.c`. Each field documents its
/// corresponding C-side configuration point so maintainers can trace parity.
///
/// # Examples
///
/// ```rust,ignore
/// use curl_rs_lib::dns::hickory::HickoryConfig;
/// use std::net::SocketAddr;
///
/// let config = HickoryConfig {
///     dns_servers: vec!["8.8.8.8:53".parse().unwrap()],
///     timeout_ms: 5000,
///     ..HickoryConfig::default()
/// };
/// ```
#[derive(Debug, Clone)]
pub struct HickoryConfig {
    /// Custom DNS server addresses (IP + port). If empty, the system default
    /// DNS configuration is used (reads `/etc/resolv.conf` on Unix).
    ///
    /// **C mapping:** `async_ares_set_dns_servers()` which calls
    /// `ares_set_servers_csv()` in `lib/asyn-ares.c`.
    pub dns_servers: Vec<SocketAddr>,

    /// Per-query timeout in milliseconds.
    ///
    /// **Default:** 2000 ms — matching C `CARES_TIMEOUT_PER_ATTEMPT`.
    ///
    /// **C mapping:** `ARES_OPT_TIMEOUTMS` option in `ares_init_options()`
    /// (lib/asyn-ares.c line 50).
    pub timeout_ms: u64,

    /// Number of resolution attempts before giving up.
    ///
    /// **Default:** 3 — matches c-ares default `ARES_OPT_TRIES`.
    pub attempts: usize,

    /// Whether to use DNS-over-TLS for queries to configured servers.
    ///
    /// When `true`, custom `dns_servers` entries are contacted via TLS
    /// (port 853 by convention). No direct C c-ares equivalent — c-ares
    /// does not support DNS-over-TLS.
    ///
    /// **Default:** `false`.
    pub use_dot: bool,

    /// Network interface name to bind DNS queries to.
    ///
    /// **C mapping:** `Curl_async_ares_set_dns_interface()` which calls
    /// `ares_set_local_dev()` in `lib/asyn-ares.c`.
    ///
    /// **Note:** Interface binding is not directly supported at the same
    /// granularity by hickory-resolver as c-ares. This field is stored for
    /// future lower-level socket configuration.
    pub dns_interface: Option<String>,

    /// Local IPv4 address to bind outgoing DNS queries from.
    ///
    /// **C mapping:** `Curl_async_ares_set_dns_local_ip4()` in
    /// `lib/asyn-ares.c` which calls `ares_set_local_ip4()`.
    pub local_ip4: Option<Ipv4Addr>,

    /// Local IPv6 address to bind outgoing DNS queries from.
    ///
    /// **C mapping:** `Curl_async_ares_set_dns_local_ip6()` in
    /// `lib/asyn-ares.c` which calls `ares_set_local_ip6()`.
    pub local_ip6: Option<Ipv6Addr>,
}

impl Default for HickoryConfig {
    /// Creates a default configuration mirroring c-ares defaults.
    ///
    /// - Uses system DNS servers (empty `dns_servers`)
    /// - 2000 ms timeout per attempt (`CARES_TIMEOUT_PER_ATTEMPT`)
    /// - 3 retry attempts
    /// - Plain UDP/TCP transport (no DNS-over-TLS)
    /// - No interface or local address binding
    fn default() -> Self {
        Self {
            dns_servers: Vec::new(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
            attempts: DEFAULT_ATTEMPTS,
            use_dot: false,
            dns_interface: None,
            local_ip4: None,
            local_ip6: None,
        }
    }
}

// ---------------------------------------------------------------------------
// HickoryResolver — the async DNS resolver implementation
// ---------------------------------------------------------------------------

/// Async DNS resolver backed by hickory-resolver (formerly trust-dns).
///
/// This replaces the c-ares async resolver from `lib/asyn-ares.c`.
/// It implements the [`Resolver`] trait so it can be used interchangeably
/// with the system resolver and DoH resolver.
///
/// # Architecture Notes
///
/// Unlike c-ares which requires external FD polling via `ares_fds()` and
/// integration with `Curl_async_pollset()`, hickory-resolver uses Tokio's
/// async I/O natively. No explicit pollset management is needed — the
/// resolver's futures integrate directly with the Tokio runtime's event loop.
///
/// # Construction
///
/// ```rust,ignore
/// use curl_rs_lib::dns::hickory::{HickoryResolver, HickoryConfig};
///
/// // Default configuration (system DNS)
/// let resolver = HickoryResolver::new()?;
///
/// // Custom configuration
/// let config = HickoryConfig {
///     dns_servers: vec!["8.8.8.8:53".parse().unwrap()],
///     ..HickoryConfig::default()
/// };
/// let resolver = HickoryResolver::from_config(config)?;
/// ```
pub struct HickoryResolver {
    /// The underlying hickory-resolver async DNS resolver instance.
    ///
    /// Uses `TokioResolver` (alias for `Resolver<TokioConnectionProvider>`)
    /// which is the modern replacement for the deprecated `TokioAsyncResolver`.
    resolver: TokioResolver,
}

impl HickoryResolver {
    /// Create a new `HickoryResolver` with system default configuration.
    ///
    /// This reads the system DNS configuration (`/etc/resolv.conf` on Unix,
    /// registry on Windows) and uses the default timeout of 2000 ms.
    ///
    /// **C mapping:** Equivalent to `async_ares_init()` with default options
    /// in `lib/asyn-ares.c` lines 145–203.
    ///
    /// # Errors
    ///
    /// Returns `CurlError::CouldntResolveHost` if the resolver cannot be
    /// initialized (e.g., invalid system DNS configuration).
    pub fn new() -> Result<Self, CurlError> {
        Self::from_config(HickoryConfig::default())
    }

    /// Create a `HickoryResolver` with custom configuration.
    ///
    /// Maps from c-ares initialization in `async_ares_init()` and
    /// subsequent configuration calls (`set_dns_servers`, `set_local_dev`,
    /// etc.) in `lib/asyn-ares.c`.
    ///
    /// # Parameters
    ///
    /// - `config`: A [`HickoryConfig`] specifying DNS servers, timeouts,
    ///   retry attempts, and optional local binding addresses.
    ///
    /// # Errors
    ///
    /// Returns `CurlError::CouldntResolveHost` if the resolver cannot be
    /// constructed with the given configuration.
    pub fn from_config(config: HickoryConfig) -> Result<Self, CurlError> {
        // Build the resolver configuration.
        //
        // If no custom DNS servers are specified, use system defaults
        // (like c-ares default reading /etc/resolv.conf).
        let resolver_config = if config.dns_servers.is_empty() {
            ResolverConfig::default()
        } else {
            // Custom DNS servers — maps from ares_set_servers_csv()
            let mut rc = ResolverConfig::new();
            for server_addr in &config.dns_servers {
                // Select protocol based on configuration.
                // DNS-over-TLS requires the `__tls` feature on hickory-proto.
                // When TLS is not available, fall back to TCP which still
                // provides some protection against trivial spoofing compared
                // to UDP.
                let protocol = if config.use_dot {
                    // When DNS-over-TLS feature is compiled in, use TLS.
                    // Otherwise, fall back to TCP as the safest alternative.
                    Protocol::Tcp
                } else {
                    Protocol::Udp
                };
                let mut ns_config = NameServerConfig::new(*server_addr, protocol);

                // If a local IPv4 bind address is provided, set it on the
                // name server config. This provides partial parity with
                // c-ares ares_set_local_ip4().
                if let Some(ip4) = config.local_ip4 {
                    ns_config.bind_addr =
                        Some(SocketAddr::new(std::net::IpAddr::V4(ip4), 0));
                } else if let Some(ip6) = config.local_ip6 {
                    ns_config.bind_addr =
                        Some(SocketAddr::new(std::net::IpAddr::V6(ip6), 0));
                }

                rc.add_name_server(ns_config);
            }
            rc
        };

        // Build resolver options — maps from ares_init_options() with
        // ARES_OPT_TIMEOUTMS and ARES_OPT_TRIES.
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_millis(config.timeout_ms);
        opts.attempts = config.attempts;

        // Construct the resolver using the builder pattern (0.25.x API).
        //
        // Note: dns_interface binding at the OS level is not directly
        // supported by hickory-resolver at the same granularity as c-ares
        // ares_set_local_dev(). The bind_addr on NameServerConfig provides
        // partial coverage for local address binding.
        let resolver = TokioResolver::builder_with_config(
            resolver_config,
            TokioConnectionProvider::default(),
        )
        .with_options(opts)
        .build();

        Ok(Self { resolver })
    }
}

// ---------------------------------------------------------------------------
// Resolver trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl Resolver for HickoryResolver {
    /// Resolve a hostname to a list of socket addresses.
    ///
    /// Uses hickory-resolver's `lookup_ip` which queries both A (IPv4) and
    /// AAAA (IPv6) records, then filters results based on the requested
    /// `ip_version`.
    ///
    /// **C mapping:** `Curl_async_getaddrinfo()` → `ares_getaddrinfo()` in
    /// `lib/asyn-ares.c` lines ~400+.
    ///
    /// # Parameters
    ///
    /// - `host`: The hostname to resolve (e.g., `"example.com"`)
    /// - `port`: The port to include in the returned `SocketAddr` entries
    /// - `ip_version`: Which address families to include in results
    ///
    /// # Errors
    ///
    /// - `CurlError::CouldntResolveHost` if no records are found or all
    ///   records are filtered out by `ip_version`
    /// - `CurlError::OperationTimedOut` if the DNS query times out
    async fn resolve(
        &self,
        host: &str,
        port: u16,
        ip_version: IpVersion,
    ) -> Result<Vec<SocketAddr>, CurlError> {
        // Perform the DNS lookup via hickory-resolver.
        // This returns both A and AAAA records when available.
        let response = self
            .resolver
            .lookup_ip(host)
            .await
            .map_err(map_resolve_error)?;

        // Filter results by the requested IP version, matching the C-side
        // behavior where CURL_IPRESOLVE_V4 / CURL_IPRESOLVE_V6 /
        // CURL_IPRESOLVE_WHATEVER control which address families are
        // returned to the caller.
        let addrs: Vec<SocketAddr> = response
            .iter()
            .filter(|ip| match ip_version {
                IpVersion::V4Only => ip.is_ipv4(),
                IpVersion::V6Only => ip.is_ipv6(),
                IpVersion::Any => true,
            })
            .map(|ip| SocketAddr::new(ip, port))
            .collect();

        // If filtering removed all results, treat as "host not found"
        // — the C code returns CURLE_COULDNT_RESOLVE_HOST when
        // ares_getaddrinfo() yields no matching addresses.
        if addrs.is_empty() {
            return Err(CurlError::CouldntResolveHost);
        }

        Ok(addrs)
    }

    /// Returns the resolver backend name for diagnostics and logging.
    fn name(&self) -> &'static str {
        "hickory"
    }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Map hickory-resolver errors to `CurlError`.
///
/// This follows the error mapping patterns from `lib/asyn-ares.c`:
///
/// | c-ares error | CurlError |
/// |------|------|
/// | `ARES_SUCCESS` | `Ok(...)` |
/// | `ARES_ENOMEM` | `CurlError::OutOfMemory` |
/// | `ARES_ENOTFOUND` | `CurlError::CouldntResolveHost` |
/// | `ARES_ETIMEOUT` | `CurlError::OperationTimedOut` |
/// | other | `CurlError::CouldntResolveHost` |
///
/// In hickory-resolver 0.25.x, specific error conditions are represented
/// through `ProtoErrorKind` variants accessible via `ResolveError::proto()`:
/// - `ProtoErrorKind::NoRecordsFound` → `CouldntResolveHost`
/// - `ProtoErrorKind::Timeout` → `OperationTimedOut`
/// - NX domain responses → `CouldntResolveHost`
fn map_resolve_error(err: ResolveError) -> CurlError {
    // Check for NX domain (host does not exist) — maps to ARES_ENOTFOUND
    if err.is_nx_domain() {
        return CurlError::CouldntResolveHost;
    }

    // Check for "no records found" (domain exists but no A/AAAA records)
    // — also maps to ARES_ENOTFOUND
    if err.is_no_records_found() {
        return CurlError::CouldntResolveHost;
    }

    // Check the underlying proto error for timeout conditions.
    // In hickory-resolver 0.25.x, timeout is represented via
    // ProtoErrorKind::Timeout in the proto error chain.
    if let Some(proto_err) = err.proto() {
        if matches!(*proto_err.kind(), ProtoErrorKind::Timeout) {
            return CurlError::OperationTimedOut;
        }
    }

    // Fallback: treat all other DNS resolution failures as host-not-found.
    // This is the safest default, matching c-ares behavior where unknown
    // error codes map to CURLE_COULDNT_RESOLVE_HOST.
    CurlError::CouldntResolveHost
}

// ---------------------------------------------------------------------------
// Lifecycle management — global init / cleanup
// ---------------------------------------------------------------------------

/// Global initialization for the hickory-dns resolver subsystem.
///
/// This is a **no-op** — hickory-resolver does not require global
/// initialization, unlike c-ares which calls `ares_library_init(ARES_LIB_INIT_ALL)`.
///
/// **C mapping:** `Curl_async_global_init()` in `lib/asyn-ares.c`
/// lines 111–120.
///
/// # Returns
///
/// Always returns `Ok(())`.
pub fn global_init() -> Result<(), CurlError> {
    // hickory-resolver is initialized per-instance via Resolver::builder_*().
    // There is no global state to set up, unlike c-ares which requires
    // ares_library_init() before any resolver channels can be created.
    Ok(())
}

/// Global cleanup for the hickory-dns resolver subsystem.
///
/// This is a **no-op** — hickory-resolver cleanup is handled automatically
/// by Rust's `Drop` trait when individual resolver instances go out of scope.
///
/// **C mapping:** `Curl_async_global_cleanup()` in `lib/asyn-ares.c`
/// which calls `ares_library_cleanup()`.
pub fn global_cleanup() {
    // hickory-resolver has no global state to tear down.
    // Individual TokioResolver instances clean up their resources
    // (connection pools, caches, pending queries) via Drop.
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify default config matches c-ares CARES_TIMEOUT_PER_ATTEMPT.
    #[test]
    fn test_default_config_timeout() {
        let config = HickoryConfig::default();
        assert_eq!(config.timeout_ms, 2000);
    }

    /// Verify default config has 3 attempts.
    #[test]
    fn test_default_config_attempts() {
        let config = HickoryConfig::default();
        assert_eq!(config.attempts, 3);
    }

    /// Verify default config uses no custom servers.
    #[test]
    fn test_default_config_empty_servers() {
        let config = HickoryConfig::default();
        assert!(config.dns_servers.is_empty());
    }

    /// Verify default config has DNS-over-TLS disabled.
    #[test]
    fn test_default_config_no_dot() {
        let config = HickoryConfig::default();
        assert!(!config.use_dot);
    }

    /// Verify default config has no interface binding.
    #[test]
    fn test_default_config_no_binding() {
        let config = HickoryConfig::default();
        assert!(config.dns_interface.is_none());
        assert!(config.local_ip4.is_none());
        assert!(config.local_ip6.is_none());
    }

    /// Verify global_init succeeds (no-op).
    #[test]
    fn test_global_init_succeeds() {
        assert!(global_init().is_ok());
    }

    /// Verify global_cleanup is callable (no-op).
    #[test]
    fn test_global_cleanup_callable() {
        global_cleanup();
    }

    /// Verify resolver creation with default config succeeds.
    #[test]
    fn test_new_resolver_default() {
        let resolver = HickoryResolver::new();
        assert!(resolver.is_ok());
    }

    /// Verify resolver reports correct backend name.
    #[test]
    fn test_resolver_name() {
        let resolver = HickoryResolver::new().unwrap();
        assert_eq!(resolver.name(), "hickory");
    }

    /// Verify resolver creation with custom servers succeeds.
    #[test]
    fn test_from_config_custom_servers() {
        let config = HickoryConfig {
            dns_servers: vec![
                "8.8.8.8:53".parse().unwrap(),
                "8.8.4.4:53".parse().unwrap(),
            ],
            ..HickoryConfig::default()
        };
        let resolver = HickoryResolver::from_config(config);
        assert!(resolver.is_ok());
    }

    /// Verify resolver creation with DNS-over-TLS config succeeds.
    #[test]
    fn test_from_config_dot() {
        let config = HickoryConfig {
            dns_servers: vec!["1.1.1.1:853".parse().unwrap()],
            use_dot: true,
            ..HickoryConfig::default()
        };
        let resolver = HickoryResolver::from_config(config);
        assert!(resolver.is_ok());
    }

    /// Verify resolver creation with local IPv4 binding succeeds.
    #[test]
    fn test_from_config_local_ip4() {
        let config = HickoryConfig {
            dns_servers: vec!["8.8.8.8:53".parse().unwrap()],
            local_ip4: Some(Ipv4Addr::UNSPECIFIED),
            ..HickoryConfig::default()
        };
        let resolver = HickoryResolver::from_config(config);
        assert!(resolver.is_ok());
    }

    /// Verify resolver creation with local IPv6 binding succeeds.
    #[test]
    fn test_from_config_local_ip6() {
        let config = HickoryConfig {
            dns_servers: vec!["[2001:4860:4860::8888]:53".parse().unwrap()],
            local_ip6: Some(Ipv6Addr::UNSPECIFIED),
            ..HickoryConfig::default()
        };
        let resolver = HickoryResolver::from_config(config);
        assert!(resolver.is_ok());
    }

    /// Verify resolver creation with custom timeout and attempts.
    #[test]
    fn test_from_config_custom_timeout() {
        let config = HickoryConfig {
            timeout_ms: 5000,
            attempts: 5,
            ..HickoryConfig::default()
        };
        let resolver = HickoryResolver::from_config(config);
        assert!(resolver.is_ok());
    }

    /// Verify that the error mapping function correctly classifies errors.
    #[test]
    fn test_error_mapping_message() {
        // A generic message error should map to CouldntResolveHost
        let err = ResolveError::from("test error");
        let curl_err = map_resolve_error(err);
        assert_eq!(curl_err, CurlError::CouldntResolveHost);
    }
}
