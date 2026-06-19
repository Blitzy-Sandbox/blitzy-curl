// SPDX-License-Identifier: curl
//
//! Optional pure-Rust asynchronous resolver backend over [`hickory-resolver`].
//!
//! This module is the *alternative* asynchronous name-resolution backend for
//! `curl-rs-lib`, a thin wrapper around the [`hickory_resolver`] crate
//! (version `0.25.2`). It exists alongside, and is interchangeable with, the
//! always-compiled default backend [`crate::dns::system`]: both expose the same
//!
//! ```text
//! pub async fn resolve(host: &str, port: u16, ip_version: IpVersion)
//!     -> Result<ResolvedAddrs>
//! ```
//!
//! contract, so [`crate::dns`]'s `resolve_via_system_backend` dispatch can swap
//! one for the other purely at compile time without any other change.
//!
//! # Default OFF — curl's `USE_ARES` analog
//!
//! The **entire module is feature-gated behind the `hickory-dns` Cargo feature
//! and is OFF by default** (see the module-level `#![cfg(feature =
//! "hickory-dns")]` below). This mirrors curl's `USE_ARES` build switch: curl's
//! default build does *not* link the c-ares asynchronous resolver, and the
//! Agent Action Plan replaces c-ares with this optional `hickory-dns` feature
//! (AAP §0.6.2). When the feature is disabled the whole file is excluded from
//! compilation and has zero effect on the build; [`crate::dns::mod`] gates its
//! `pub mod hickory;` declaration and its dispatch to [`resolve`] with the same
//! `#[cfg(feature = "hickory-dns")]`.
//!
//! # Relationship to the `AsynchDNS` capability bit
//!
//! This backend does **not** drive the `AsynchDNS` (`CURL_VERSION_ASYNCHDNS`)
//! capability reported by [`crate::version`]. The default [`crate::dns::system`]
//! backend is already asynchronous (the analog of curl's threaded resolver,
//! `CURLRES_THREADED` ⇒ `CURLRES_ASYNCH`), so `AsynchDNS` is reported in the
//! default build regardless of whether this module is compiled — exactly as
//! documented on [`crate::dns::ASYNC_DNS`]. `hickory.rs` is an *additional*
//! async backend, never the trigger for the capability.
//!
//! # Behavioral oracle (REFERENCE only — shape, not bytes)
//!
//! curl's asynchronous-resolver shape lives in `lib/asyn-thrdd.c` and
//! `lib/asyn-base.c`: a background worker performs `getaddrinfo`, sets a "done"
//! flag, and notifies the transfer. There is no 1:1 C source to port — the
//! c-ares binding (`lib/asyn-ares.c`) is out of scope (AAP §0.3.2) — so this is
//! idiomatic safe Rust, not a transliteration. The hand-rolled background
//! thread and "resolution in progress" state collapse into an ordinary `async`
//! future: awaiting it *is* the resolve, and the synchronous-vs-asynchronous
//! bridging is handled by the FFI / multi driver, never here.
//!
//! # Memory safety
//!
//! Per the project mandate (AAP §0.7.1 / §0.8.1) this module contains **zero
//! `unsafe`** and is compiled under `#![forbid(unsafe_code)]`.
//! [`hickory_resolver`] is a pure-Rust, safe-API crate, so no raw-pointer or
//! FFI handling is required.

#![cfg(feature = "hickory-dns")]
#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;
use std::time::Duration;

use hickory_resolver::config::{LookupIpStrategy, NameServerConfig, ResolverConfig};
use hickory_resolver::lookup_ip::LookupIp;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;

use crate::dns::{IpVersion, ResolvedAddrs, CURL_TIMEOUT_RESOLVE};
use crate::error::{CurlError, Result};

// ---------------------------------------------------------------------------
// Optional per-resolve DNS configuration (curl's `CURLOPT_DNS_*`).
// ---------------------------------------------------------------------------

/// Optional DNS configuration mirroring the `CURLOPT_DNS_*` family of curl
/// options, consumed by [`resolve_with_options`].
///
/// The primary entrypoint [`resolve`] uses the cached system-configured
/// resolver and ignores these options; callers that need to override the
/// nameservers or the local bind address (the way curl's `--dns-servers`,
/// `--dns-interface`, `--dns-ipv4-addr` and `--dns-ipv6-addr` flags do) build a
/// `DnsOptions` and call [`resolve_with_options`] instead.
///
/// # Supported vs. unsupported options
///
/// * [`servers`](DnsOptions::servers) — `CURLOPT_DNS_SERVERS`. **Supported**:
///   each address is registered as a [`NameServerConfig`] (both UDP and TCP
///   transports, matching curl's UDP-with-TCP-fallback behavior).
/// * [`local_ip4`](DnsOptions::local_ip4) / [`local_ip6`](DnsOptions::local_ip6)
///   — `CURLOPT_DNS_LOCAL_IP4` / `CURLOPT_DNS_LOCAL_IP6`. **Supported when
///   custom [`servers`](DnsOptions::servers) are given**: applied as the
///   per-server [`NameServerConfig::bind_addr`] (the client address used for
///   the query). With no custom servers there is no per-server config to attach
///   the bind address to, so the local IP is not applied (documented, not
///   silently changed).
/// * [`interface`](DnsOptions::interface) — `CURLOPT_DNS_INTERFACE`.
///   **Not supported**: `hickory-resolver` 0.25's [`NameServerConfig`] exposes a
///   `bind_addr` (an IP/port) but no facility to bind a query socket to a named
///   network *interface* (`SO_BINDTODEVICE`). The value is retained on the
///   struct for completeness and for callers that wish to inspect it, but it is
///   not applied to the resolver; behavior is therefore unchanged rather than
///   silently approximated.
/// * [`timeout`](DnsOptions::timeout) — the overall wall-clock budget for the
///   resolve. When `None`, [`CURL_TIMEOUT_RESOLVE`] seconds is used (curl's
///   `CURL_TIMEOUT_RESOLVE`). This bounds the whole operation via
///   [`tokio::time::timeout`]; the resolver's own per-query timeout and retry
///   count keep their `hickory-resolver` defaults.
#[derive(Clone, Debug, Default)]
pub struct DnsOptions {
    /// Custom recursive nameservers to query (`CURLOPT_DNS_SERVERS`). Empty
    /// means "use the system configuration" (`/etc/resolv.conf` on Unix).
    pub servers: Vec<SocketAddr>,
    /// Local IPv4 address to bind outgoing DNS queries to
    /// (`CURLOPT_DNS_LOCAL_IP4`). Applied as a per-server bind address only when
    /// [`servers`](DnsOptions::servers) is non-empty.
    pub local_ip4: Option<Ipv4Addr>,
    /// Local IPv6 address to bind outgoing DNS queries to
    /// (`CURLOPT_DNS_LOCAL_IP6`). Applied as a per-server bind address only when
    /// [`servers`](DnsOptions::servers) is non-empty.
    pub local_ip6: Option<Ipv6Addr>,
    /// Network interface name to bind DNS queries to
    /// (`CURLOPT_DNS_INTERFACE`). **Not applied** — see the type-level note on
    /// unsupported options. Retained for inspection only.
    pub interface: Option<String>,
    /// Overall wall-clock budget for the resolve. `None` ⇒
    /// [`CURL_TIMEOUT_RESOLVE`] seconds.
    pub timeout: Option<Duration>,
}

// ---------------------------------------------------------------------------
// Resolver construction.
// ---------------------------------------------------------------------------

/// Process-wide cache of the default, system-configured resolver.
///
/// Building a resolver parses the system configuration (`/etc/resolv.conf` on
/// Unix), which is wasteful to repeat on every resolve. [`TokioResolver`] is
/// `Clone` (a cheap, `Arc`-backed handle), so it is built once on first use and
/// thereafter cloned. The cache is only ever populated with a *successful*
/// build, so a transient failure (e.g. the configuration file is briefly
/// unreadable) does not get latched permanently — a later call retries.
static DEFAULT_RESOLVER: OnceLock<TokioResolver> = OnceLock::new();

/// Returns a clone of the cached default resolver, building it on first use.
///
/// # Errors
///
/// [`CurlError::CouldntResolveHost`] if the system resolver configuration
/// cannot be read or the resolver cannot be constructed.
fn default_resolver() -> Result<TokioResolver> {
    if let Some(resolver) = DEFAULT_RESOLVER.get() {
        return Ok(resolver.clone());
    }

    let resolver = build_system_resolver()?;

    // Publish our instance. If a concurrent caller won the race, `set` hands our
    // value back unchanged — it is a perfectly valid resolver, so use it.
    if let Err(ours) = DEFAULT_RESOLVER.set(resolver) {
        return Ok(ours);
    }

    DEFAULT_RESOLVER
        .get()
        .cloned()
        .ok_or(CurlError::CouldntResolveHost)
}

/// Builds a resolver from the operating system's configuration.
///
/// The lookup strategy is forced to [`LookupIpStrategy::Ipv4AndIpv6`] so that
/// the [`IpVersion::Any`] path ([`TokioResolver::lookup_ip`]) returns *both*
/// address families (hickory's default `Ipv4thenIpv6` would return only one),
/// matching curl's "whatever" behavior of offering every resolved address to
/// the connection layer.
///
/// # Errors
///
/// [`CurlError::CouldntResolveHost`] if the system configuration cannot be read.
fn build_system_resolver() -> Result<TokioResolver> {
    let mut builder = TokioResolver::builder_tokio().map_err(|_| CurlError::CouldntResolveHost)?;
    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    // hickory-resolver 0.26 made `ResolverBuilder::build` fallible (it returns
    // `Result<Resolver, NetError>`; 0.25 returned the resolver directly).
    builder.build().map_err(|_| CurlError::CouldntResolveHost)
}

/// Builds a resolver honoring [`DnsOptions`].
///
/// With no custom [`servers`](DnsOptions::servers) this defers to
/// [`build_system_resolver`]. With custom servers, each is registered for both
/// UDP and TCP (curl issues UDP queries and falls back to TCP on truncation),
/// and the matching local bind address (if any) is attached per server.
///
/// # Errors
///
/// [`CurlError::CouldntResolveHost`] if no usable resolver can be constructed.
fn build_custom_resolver(options: &DnsOptions) -> Result<TokioResolver> {
    // No explicit nameservers: fall back to the system resolver. The local-IP
    // bind addresses only apply to explicitly configured servers (see the
    // `DnsOptions` documentation), so there is nothing else to honor here.
    if options.servers.is_empty() {
        return build_system_resolver();
    }

    let config = build_resolver_config(options);
    let mut builder =
        TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    builder.build().map_err(|_| CurlError::CouldntResolveHost)
}

/// Assembles the [`ResolverConfig`] for explicitly configured nameservers.
///
/// Each configured server is registered as one [`NameServerConfig`] carrying
/// both a UDP and a TCP [`ConnectionConfig`] (curl issues UDP queries and falls
/// back to TCP on truncation). The server's port comes from the configured
/// [`SocketAddr`], and the matching local bind address (if any) is attached to
/// every connection.
///
/// hickory-resolver 0.26 reshaped this API: a `NameServerConfig` is now keyed by
/// an [`IpAddr`] and holds a `Vec<ConnectionConfig>` (each carrying its own
/// `port` and `bind_addr`), replacing 0.25's per-(addr, protocol)
/// `NameServerConfig::new(socket_addr, protocol)` plus a `bind_addr` field. The
/// resulting resolver behavior — query each server over UDP then TCP, on the
/// configured port, from the configured local address — is identical.
///
/// Kept as a pure, runtime-independent function so the registration logic stays
/// unit-testable without constructing a live resolver (0.26 also removed the
/// `Resolver::config()` accessor the previous test relied on).
fn build_resolver_config(options: &DnsOptions) -> ResolverConfig {
    let mut config = ResolverConfig::default();
    for &server in &options.servers {
        let bind_addr = pick_bind_addr(server, options);
        let port = server.port();
        // `udp_and_tcp` yields a NameServerConfig keyed by the server IP with one
        // UDP and one TCP connection; we then set each connection's remote port
        // (from the configured SocketAddr) and local bind address. The 0.26 config
        // structs are `#[non_exhaustive]`, so they are built via their public
        // constructors and adjusted by field rather than with struct literals.
        let mut name_server = NameServerConfig::udp_and_tcp(server.ip());
        for conn in &mut name_server.connections {
            conn.port = port;
            conn.bind_addr = bind_addr;
        }
        config.add_name_server(name_server);
    }
    config
}

/// Selects the local bind address for a query to `server`, choosing the IPv4 or
/// IPv6 local address ([`CURLOPT_DNS_LOCAL_IP4`] / `..._IP6`) that matches the
/// server's family. Returns `None` when no matching local address is set.
///
/// The port is fixed to `0` so the operating system selects an ephemeral source
/// port, exactly as a normal client socket would.
///
/// [`CURLOPT_DNS_LOCAL_IP4`]: DnsOptions::local_ip4
fn pick_bind_addr(server: SocketAddr, options: &DnsOptions) -> Option<SocketAddr> {
    match server {
        SocketAddr::V4(_) => options
            .local_ip4
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), 0)),
        SocketAddr::V6(_) => options
            .local_ip6
            .map(|ip| SocketAddr::new(IpAddr::V6(ip), 0)),
    }
}

// ---------------------------------------------------------------------------
// Address post-processing (pure, runtime-independent).
// ---------------------------------------------------------------------------

/// Folds resolved [`IpAddr`]s into `host:port` [`SocketAddr`]s, keeping only the
/// addresses of the requested [`IpVersion`] family.
///
/// For [`IpVersion::Any`] every address is kept. For [`IpVersion::V4`] /
/// [`IpVersion::V6`] only the matching family survives — a safety net that
/// reinforces the family-specific query path (`ipv4_lookup` / `ipv6_lookup`) so
/// that a misbehaving resolver returning an off-family record can never leak an
/// address of the wrong family to the caller. This function is pure and free of
/// any async / runtime dependency, which keeps the family-filtering and
/// port-folding logic unit-testable without a network.
fn fold_addrs(ips: Vec<IpAddr>, port: u16, ip_version: IpVersion) -> Vec<SocketAddr> {
    ips.into_iter()
        .filter(|ip| match ip_version {
            IpVersion::Any => true,
            IpVersion::V4 => ip.is_ipv4(),
            IpVersion::V6 => ip.is_ipv6(),
        })
        .map(|ip| SocketAddr::new(ip, port))
        .collect()
}

// ---------------------------------------------------------------------------
// The resolve entrypoints.
// ---------------------------------------------------------------------------

/// Resolves `host` to a set of `host:port` socket addresses using the default,
/// system-configured resolver.
///
/// This is the backend entrypoint dispatched to by [`crate::dns`] when the
/// `hickory-dns` feature is enabled; its signature is identical to
/// [`crate::dns::system::resolve`], so the two backends are interchangeable at
/// compile time.
///
/// `ip_version` honors `CURLOPT_IPRESOLVE`: [`IpVersion::V4`] queries only `A`
/// records, [`IpVersion::V6`] only `AAAA`, and [`IpVersion::Any`] both.
///
/// The shortcuts curl applies *before* the backend — IDN encoding, `.onion`
/// rejection, the DNS cache, the IP-literal and `localhost` short-circuits, and
/// the "is this IP family even buildable" check — are all performed by
/// [`crate::dns::resolve`] in the parent module; this function is reached only
/// for an actual DNS query of a real ASCII hostname.
///
/// # Errors
///
/// * [`CurlError::OperationTimedout`] if the resolve exceeds
///   [`CURL_TIMEOUT_RESOLVE`] seconds.
/// * [`CurlError::CouldntResolveHost`] if the resolver fails or returns no
///   address of the requested family. (The host-vs-proxy distinction —
///   `CURLE_COULDNT_RESOLVE_PROXY` — is applied by [`crate::dns::resolve`] from
///   its `is_proxy` flag; this backend always reports the host variant, exactly
///   like [`crate::dns::system::resolve`].)
pub async fn resolve(host: &str, port: u16, ip_version: IpVersion) -> Result<ResolvedAddrs> {
    let resolver = default_resolver()?;
    let budget = Duration::from_secs(CURL_TIMEOUT_RESOLVE);
    resolve_on(&resolver, host, port, ip_version, budget).await
}

/// Like [`resolve`], but using a resolver configured from `options`
/// (`CURLOPT_DNS_SERVERS` / `..._LOCAL_IP4` / `..._LOCAL_IP6`; see
/// [`DnsOptions`] for which options are honored).
///
/// # Errors
///
/// As [`resolve`], plus [`CurlError::CouldntResolveHost`] if the options-derived
/// resolver cannot be constructed.
pub async fn resolve_with_options(
    host: &str,
    port: u16,
    ip_version: IpVersion,
    options: &DnsOptions,
) -> Result<ResolvedAddrs> {
    let resolver = build_custom_resolver(options)?;
    let budget = options
        .timeout
        .unwrap_or_else(|| Duration::from_secs(CURL_TIMEOUT_RESOLVE));
    resolve_on(&resolver, host, port, ip_version, budget).await
}

/// Drives a single resolve on `resolver`, bounding it by `budget` via
/// [`tokio::time::timeout`]. Exceeding the budget yields
/// [`CurlError::OperationTimedout`]; otherwise the inner lookup's result (or
/// error) is returned unchanged.
async fn resolve_on(
    resolver: &TokioResolver,
    host: &str,
    port: u16,
    ip_version: IpVersion,
    budget: Duration,
) -> Result<ResolvedAddrs> {
    match tokio::time::timeout(budget, run_lookup(resolver, host, port, ip_version)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(CurlError::OperationTimedout),
    }
}

/// Performs the family-appropriate lookup and folds the result into a
/// [`ResolvedAddrs`].
///
/// `V4` uses `ipv4_lookup` (`A` records only), `V6` uses `ipv6_lookup` (`AAAA`
/// only), and `Any` uses `lookup_ip` (both, per the resolver's
/// `Ipv4AndIpv6` strategy). Any resolver error, and an empty address set, map to
/// [`CurlError::CouldntResolveHost`] — an empty result is a failed resolve, the
/// same way [`crate::dns::resolve`] treats a zero-address backend success.
async fn run_lookup(
    resolver: &TokioResolver,
    host: &str,
    port: u16,
    ip_version: IpVersion,
) -> Result<ResolvedAddrs> {
    let ips: Vec<IpAddr> = match ip_version {
        IpVersion::V4 => {
            // `ipv4_lookup` issues an A-only query (preserving curl's `--ipv4`
            // wire behavior). hickory 0.26 returns a generic `Lookup`; wrapping
            // it in `LookupIp` exposes the public `iter()` that maps A-record
            // RData to `IpAddr` (an A-only response carries no AAAA records, so
            // only V4 addresses are produced).
            let lookup = resolver
                .ipv4_lookup(host)
                .await
                .map_err(|_| CurlError::CouldntResolveHost)?;
            LookupIp::from(lookup).iter().collect()
        }
        IpVersion::V6 => {
            // `ipv6_lookup` issues an AAAA-only query (curl's `--ipv6`).
            let lookup = resolver
                .ipv6_lookup(host)
                .await
                .map_err(|_| CurlError::CouldntResolveHost)?;
            LookupIp::from(lookup).iter().collect()
        }
        IpVersion::Any => {
            // `lookup_ip` already yields a `LookupIp`; hickory 0.26 replaced its
            // `IntoIterator` impl with the borrowing `iter()` (Item = `IpAddr`).
            let lookup = resolver
                .lookup_ip(host)
                .await
                .map_err(|_| CurlError::CouldntResolveHost)?;
            lookup.iter().collect()
        }
    };

    let addrs = fold_addrs(ips, port, ip_version);
    if addrs.is_empty() {
        return Err(CurlError::CouldntResolveHost);
    }
    Ok(ResolvedAddrs::from_vec(addrs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("valid IP literal")
    }

    // --- fold_addrs: family filtering + port folding (pure, offline) --------

    #[test]
    fn fold_addrs_any_keeps_both_families_with_port() {
        let ips = vec![ip("1.2.3.4"), ip("2001:db8::1")];
        let out = fold_addrs(ips, 8080, IpVersion::Any);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|s| s.port() == 8080));
        assert!(out.iter().any(SocketAddr::is_ipv4));
        assert!(out.iter().any(SocketAddr::is_ipv6));
    }

    #[test]
    fn fold_addrs_v4_keeps_only_ipv4() {
        let ips = vec![ip("1.2.3.4"), ip("2001:db8::1"), ip("5.6.7.8")];
        let out = fold_addrs(ips, 443, IpVersion::V4);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(SocketAddr::is_ipv4));
        assert!(out.iter().all(|s| s.port() == 443));
    }

    #[test]
    fn fold_addrs_v6_keeps_only_ipv6() {
        let ips = vec![ip("1.2.3.4"), ip("2001:db8::1")];
        let out = fold_addrs(ips, 53, IpVersion::V6);
        assert_eq!(out.len(), 1);
        assert!(out[0].is_ipv6());
        assert_eq!(out[0].port(), 53);
    }

    #[test]
    fn fold_addrs_empty_stays_empty() {
        assert!(fold_addrs(Vec::new(), 80, IpVersion::Any).is_empty());
        // A pool with no member of the requested family folds to empty (which
        // run_lookup turns into CouldntResolveHost).
        assert!(fold_addrs(vec![ip("1.2.3.4")], 80, IpVersion::V6).is_empty());
    }

    // --- pick_bind_addr: CURLOPT_DNS_LOCAL_IP4 / _IP6 selection -------------

    #[test]
    fn bind_addr_picks_matching_family() {
        let options = DnsOptions {
            local_ip4: Some(Ipv4Addr::new(10, 0, 0, 1)),
            local_ip6: Some(Ipv6Addr::LOCALHOST),
            ..DnsOptions::default()
        };
        let v4_server: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let v6_server: SocketAddr = "[2001:4860:4860::8888]:53".parse().unwrap();

        let bind4 = pick_bind_addr(v4_server, &options).expect("ipv4 bind");
        assert_eq!(bind4.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(bind4.port(), 0);

        let bind6 = pick_bind_addr(v6_server, &options).expect("ipv6 bind");
        assert_eq!(bind6.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(bind6.port(), 0);
    }

    #[test]
    fn bind_addr_absent_without_local_ip() {
        let v4_server: SocketAddr = "8.8.8.8:53".parse().unwrap();
        assert!(pick_bind_addr(v4_server, &DnsOptions::default()).is_none());

        // Only an IPv6 local set, but the server is IPv4 → no bind.
        let only_v6 = DnsOptions {
            local_ip6: Some(Ipv6Addr::LOCALHOST),
            ..DnsOptions::default()
        };
        assert!(pick_bind_addr(v4_server, &only_v6).is_none());
    }

    // --- DnsOptions defaults ------------------------------------------------

    #[test]
    fn dns_options_default_is_empty() {
        let options = DnsOptions::default();
        assert!(options.servers.is_empty());
        assert!(options.local_ip4.is_none());
        assert!(options.local_ip6.is_none());
        assert!(options.interface.is_none());
        assert!(options.timeout.is_none());
    }

    // --- Custom resolver construction (offline: builds config, no query) ----

    #[tokio::test]
    async fn custom_resolver_registers_servers_with_binds() {
        let options = DnsOptions {
            servers: vec![
                "8.8.8.8:53".parse().unwrap(),
                "[2001:4860:4860::8888]:53".parse().unwrap(),
            ],
            local_ip4: Some(Ipv4Addr::UNSPECIFIED),
            ..DnsOptions::default()
        };

        // Introspect the assembled config directly (hickory 0.26 removed the
        // `Resolver::config()` accessor). In the 0.26 model each server is ONE
        // `NameServerConfig` (keyed by `ip`) holding a UDP and a TCP
        // `ConnectionConfig`, so two servers yield two entries, each with two
        // connections — behaviorally identical to 0.25's four single-protocol
        // entries.
        let config = build_resolver_config(&options);
        let name_servers = config.name_servers();
        assert_eq!(name_servers.len(), 2);

        // The IPv4 server: a UDP and a TCP connection, both carrying the bind.
        let v4 = name_servers
            .iter()
            .find(|ns| ns.ip.is_ipv4())
            .expect("IPv4 nameserver present");
        assert_eq!(v4.connections.len(), 2);
        assert!(v4.connections.iter().all(|c| c.bind_addr.is_some()));
        assert_eq!(v4.connections[0].port, 53);

        // The IPv6 server has no IPv6 local set, so no bind is attached.
        let v6 = name_servers
            .iter()
            .find(|ns| ns.ip.is_ipv6())
            .expect("IPv6 nameserver present");
        assert_eq!(v6.connections.len(), 2);
        assert!(v6.connections.iter().all(|c| c.bind_addr.is_none()));
    }

    #[tokio::test]
    async fn custom_resolver_without_servers_uses_system_config() {
        // No explicit servers → falls back to the system resolver. This reads
        // the system DNS configuration; if that is unavailable in the test
        // environment the documented error is returned. Either outcome is valid
        // here — we only assert it does not panic and yields a Result.
        let result = build_custom_resolver(&DnsOptions::default());
        match result {
            // The system config built successfully. hickory 0.26 removed the
            // `Resolver::config()` accessor, so we can only assert that a usable
            // resolver was produced (the `Ok` arm itself); the dual-family
            // strategy is exercised by the resolution tests below.
            Ok(resolver) => {
                let _ = resolver;
            }
            Err(err) => assert_eq!(err, CurlError::CouldntResolveHost),
        }
    }

    // --- Real network resolution (opt-in; requires DNS connectivity) --------

    #[tokio::test]
    #[ignore = "requires outbound DNS connectivity"]
    async fn resolve_known_host_and_filters_family() {
        // `one.one.one.one` is a stable dual-stack name (Cloudflare DNS).
        let any = resolve("one.one.one.one", 443, IpVersion::Any)
            .await
            .expect("resolve any");
        assert!(!any.is_empty());
        assert!(any.iter().all(|s| s.port() == 443));

        let v4 = resolve("one.one.one.one", 443, IpVersion::V4)
            .await
            .expect("resolve v4");
        assert!(!v4.is_empty());
        assert!(v4.iter().all(SocketAddr::is_ipv4));

        let v6 = resolve("one.one.one.one", 443, IpVersion::V6)
            .await
            .expect("resolve v6");
        assert!(v6.iter().all(SocketAddr::is_ipv6));
    }
}
