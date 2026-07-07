// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

// Defensive gate: the whole module is also declared behind
// `#[cfg(feature = "hickory-dns")]` in `dns/mod.rs`, so a default build never
// even reaches this file. The inner `#![cfg(...)]` makes the file self-guarding
// — if the `pub mod hickory;` declaration were ever un-gated, nothing
// hickory-specific here would compile without the feature, keeping the default
// four-platform build (system + DoH resolvers only) green.
#![cfg(feature = "hickory-dns")]

//! Optional pure-Rust asynchronous name-resolution backend built on
//! [`hickory-resolver`](https://docs.rs/hickory-resolver), gated behind the
//! default-**off** `hickory-dns` Cargo feature.
//!
//! # Position in the crate
//!
//! This module is the idiomatic-Rust replacement for curl's c-ares async DNS
//! backend, `lib/asyn-ares.c`. **c-ares is not linked** anywhere in the rewrite;
//! when a user wants a userspace asynchronous resolver that is independent of the
//! operating-system resolver, they enable the `hickory-dns` feature and this
//! module provides one through the pure-safe-Rust `hickory-resolver` crate. The
//! *default* resolver remains [`crate::dns::system`] (the Tokio system resolver);
//! hickory is strictly opt-in, mirroring curl's non-default `USE_ARES` build.
//!
//! The [`HickoryResolver`] type implements the [`Resolver`] trait declared in
//! [`crate::dns`], so the connection layer dispatches through `&dyn Resolver`
//! without knowing which backend is active (AAP §0.3.2, "Trait-Based Protocol
//! Dispatch") — exactly as curl selects a resolver with `#ifdef CURLRES_ARES` at
//! compile time.
//!
//! # Mapping from `lib/asyn-ares.c`
//!
//! | curl c-ares construct                                | reproduced here                                   |
//! |------------------------------------------------------|---------------------------------------------------|
//! | `Curl_async_getaddrinfo` (asyn-ares.c:711)           | [`HickoryResolver::resolve`] family selection     |
//! | `async_addr_concat` (asyn-ares.c:463)                | [`order_ipv6_first`] — IPv6 entries kept at head  |
//! | `async_ares_set_dns_servers` (asyn-ares.c:827)       | [`HickoryOptions::servers`] csv parsing           |
//! | `Curl_async_ares_set_dns_interface` (asyn-ares.c:882)| [`HickoryOptions::interface`] → `NOT_BUILT_IN`    |
//! | `Curl_async_ares_set_dns_local_ip4/6` (asyn-ares.c)  | [`HickoryOptions::local_ip4`] / `local_ip6` → bind|
//! | `ARES_ENOTFOUND` → `CURLE_COULDNT_RESOLVE_HOST`      | [`From<ResolveError>`](Error) and empty-answer map|
//!
//! # Memory-safety and async guarantees
//!
//! Like every module in `curl-rs-lib`, this file is written in 100% safe Rust:
//! it inherits the crate-root memory-safety lint and performs no low-level
//! memory operations of its own (AAP §0.7.2), and `hickory-resolver` is itself
//! pure safe Rust. All asynchrony runs on Tokio (the sole async runtime,
//! AAP §0.3.2) through hickory's [`TokioConnectionProvider`]; no other async
//! runtime is used. Per the Minimal Change Mandate this backend reproduces only
//! what the c-ares backend did (A/AAAA lookups, custom DNS servers, and local
//! source-address binding) and adds no new capabilities.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use hickory_resolver::config::{LookupIpStrategy, NameServerConfig, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::proto::xfer::Protocol;
use hickory_resolver::system_conf::read_system_conf;
use hickory_resolver::{ResolveError, TokioResolver};

use crate::dns::{Address, IpVersion, ResolveFuture, Resolver};
use crate::error::{CurlCode, Error, Result};

/// The default DNS service port used when a `CURLOPT_DNS_SERVERS` entry omits an
/// explicit port — the IANA-assigned port 53, matching c-ares's default in
/// `ares_set_servers_ports_csv` (`lib/asyn-ares.c:851`).
const DNS_PORT: u16 = 53;

// ---------------------------------------------------------------------------
// Phase 2 — resolver options (← the CURLOPT_DNS_* knobs consumed by asyn-ares.c)
// ---------------------------------------------------------------------------

/// The subset of curl's per-transfer DNS options that shape a
/// [`HickoryResolver`], transcribed from the four `data->set.str[STRING_DNS_*]`
/// values that `lib/asyn-ares.c` feeds into its c-ares channel.
///
/// Each field maps one-to-one to a curl command-line / `curl_easy_setopt`
/// option; a `None` (or empty-string) field means "unset", exactly as a `NULL`
/// `data->set.str[...]` does in curl. Construct with [`Default`] for the
/// system-configured resolver, or populate individual fields to mirror the
/// corresponding `CURLOPT_*`.
#[derive(Debug, Clone, Default)]
pub struct HickoryOptions {
    /// `CURLOPT_DNS_SERVERS` — a comma-separated list of `ip` or `ip:port` name
    /// servers (an IPv6 literal may be bracketed, e.g.
    /// `[2001:4860:4860::8888]:53`). `None` uses the system resolver
    /// configuration. Mirrors `async_ares_set_dns_servers` →
    /// `ares_set_servers_ports_csv` (`lib/asyn-ares.c:827`).
    pub servers: Option<String>,

    /// `CURLOPT_DNS_INTERFACE` — bind DNS queries to a named network device.
    ///
    /// **Unsupported by the hickory backend**: `hickory-resolver` exposes no
    /// `SO_BINDTODEVICE`-style device binding, so setting a non-empty value
    /// yields [`CurlCode::NotBuiltIn`], exactly as c-ares does when built
    /// without `HAVE_CARES_LOCAL_DEV` (`lib/asyn-ares.c:897`).
    pub interface: Option<String>,

    /// `CURLOPT_DNS_LOCAL_IP4` — the local IPv4 source address to bind outgoing
    /// DNS queries to (← `ares_set_local_ip4`, `lib/asyn-ares.c:922`). Applied
    /// to each IPv4 name server through [`NameServerConfig::bind_addr`].
    pub local_ip4: Option<Ipv4Addr>,

    /// `CURLOPT_DNS_LOCAL_IP6` — the local IPv6 source address to bind outgoing
    /// DNS queries to (← `ares_set_local_ip6`, `lib/asyn-ares.c:952`). Applied
    /// to each IPv6 name server through [`NameServerConfig::bind_addr`].
    pub local_ip6: Option<Ipv6Addr>,
}

// ---------------------------------------------------------------------------
// Phase 2 — the resolver type (← the c-ares channel wrapped by asyn-ares.c)
// ---------------------------------------------------------------------------

/// A [`Resolver`] backed by `hickory-resolver`, the pure-Rust replacement for
/// curl's c-ares channel (`struct async_ares_ctx`, `lib/asyn-ares.c`).
///
/// Build one with [`HickoryResolver::from_system`] (the common case: use the
/// operating system's `/etc/resolv.conf`) or [`HickoryResolver::new`] to apply
/// custom [`HickoryOptions`]. The inner hickory resolver holds an `Arc`-shared
/// connection pool and resolution cache; this type is consumed behind
/// `&dyn Resolver`, so it is intentionally neither `Clone` nor `Copy`.
///
/// `Debug` is derived (per Rust API guideline C-DEBUG for public types); it
/// delegates to hickory's own [`Resolver`] `Debug`, which prints only the
/// resolver's configuration and never its live connection state.
#[derive(Debug)]
pub struct HickoryResolver {
    /// The underlying Tokio-driven hickory resolver. It owns the name-server
    /// pool and hickory's own LRU cache, which sits *below* curl's
    /// [`DnsCache`](crate::dns::DnsCache) (the latter lives above the
    /// [`Resolver`] trait, in the resolution orchestration).
    inner: TokioResolver,
}

impl HickoryResolver {
    /// Builds a resolver from the operating-system configuration
    /// (`/etc/resolv.conf` on Unix) — the direct analogue of a default c-ares
    /// channel created with no `CURLOPT_DNS_*` overrides.
    ///
    /// # Errors
    ///
    /// Returns [`CurlCode::FailedInit`] if the system resolver configuration
    /// cannot be read — the same class of failure curl reports as
    /// `CURLE_FAILED_INIT` when `async_ares_init_lazy` fails
    /// (`lib/asyn-ares.c:719`).
    pub fn from_system() -> Result<Self> {
        Self::new(&HickoryOptions::default())
    }

    /// Builds a resolver honoring the supplied [`HickoryOptions`], reproducing
    /// the option handling of `async_ares_init_lazy` and
    /// `async_ares_set_dns_servers` (`lib/asyn-ares.c:170-192`, `:827`).
    ///
    /// The lookup strategy is fixed to query A and AAAA in parallel
    /// ([`LookupIpStrategy::Ipv4AndIpv6`]) so an unspecified-family request
    /// returns both, matching curl's `PF_UNSPEC` behavior when the IPv6 stack
    /// works (`lib/asyn-ares.c:756`). Per-family narrowing for
    /// [`IpVersion::V4`] / [`IpVersion::V6`] is done with targeted record
    /// lookups in [`resolve`](HickoryResolver::resolve).
    ///
    /// # Errors
    ///
    /// * [`CurlCode::NotBuiltIn`] — [`HickoryOptions::interface`] was set to a
    ///   non-empty value; the hickory backend cannot bind to a named device
    ///   (parity with c-ares built without `HAVE_CARES_LOCAL_DEV`).
    /// * [`CurlCode::BadFunctionArgument`] — [`HickoryOptions::servers`] could
    ///   not be parsed (parity with c-ares mapping `ARES_EBADSTR` →
    ///   `CURLE_BAD_FUNCTION_ARGUMENT`, `lib/asyn-ares.c:862`).
    /// * [`CurlCode::FailedInit`] — the system resolver configuration could not
    ///   be read (only reachable when no custom servers were supplied).
    pub fn new(options: &HickoryOptions) -> Result<Self> {
        // (asyn-ares.c:882) A DNS interface (device) binding has no hickory
        // equivalent; surface CURLE_NOT_BUILT_IN just as c-ares does on a build
        // lacking HAVE_CARES_LOCAL_DEV, rather than silently ignoring it. An
        // empty string is treated as "unset" (curl stores "" for no interface).
        if options
            .interface
            .as_deref()
            .is_some_and(|device| !device.is_empty())
        {
            return Err(Error::with_context(
                CurlCode::NotBuiltIn,
                "CURLOPT_DNS_INTERFACE is not supported by the hickory-dns backend",
            ));
        }

        // (asyn-ares.c:903/932) Local source-address binding IS supported by
        // hickory via NameServerConfig::bind_addr. Port 0 lets the OS pick an
        // ephemeral source port, matching ares_set_local_ip4/6 (which set only
        // the source address, never the port).
        let bind4 = options
            .local_ip4
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), 0));
        let bind6 = options
            .local_ip6
            .map(|ip| SocketAddr::new(IpAddr::V6(ip), 0));

        let provider = TokioConnectionProvider::default();

        let mut builder = match options.servers.as_deref() {
            // (asyn-ares.c:827) Explicit name servers from the CURLOPT_DNS_SERVERS
            // csv, replacing any system configuration — the same effect as c-ares
            // recreating its channel with a pinned server list.
            Some(csv) if !csv.trim().is_empty() => {
                let servers = parse_dns_servers(csv)?;
                let config = build_custom_config(&servers, bind4, bind6);
                TokioResolver::builder_with_config(config, provider)
            }
            // Default: the operating-system resolver configuration.
            _ => {
                let (config, sys_options) = read_system_conf().map_err(|err| {
                    Error::with_context(
                        CurlCode::FailedInit,
                        format!("failed to read system DNS configuration: {err}"),
                    )
                })?;
                let config = apply_bind_addrs(config, bind4, bind6);
                let mut builder = TokioResolver::builder_with_config(config, provider);
                // Preserve the system resolver options (ndots, timeout, attempts,
                // …) instead of hickory defaults; only the family strategy below
                // is overridden.
                *builder.options_mut() = sys_options;
                builder
            }
        };

        // (asyn-ares.c:756) Query both families in parallel for the default /
        // PF_UNSPEC case, so IpVersion::Whatever yields A and AAAA together.
        builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;

        Ok(Self {
            inner: builder.build(),
        })
    }

    /// Issues a single targeted record lookup (A or AAAA) and collects the
    /// resulting addresses in the order the server returned them — the
    /// per-family path used for [`IpVersion::V4`] and [`IpVersion::V6`],
    /// mirroring the family-specific
    /// `ares_gethostbyname(..., PF_INET | PF_INET6, ...)` queries curl fires
    /// (`lib/asyn-ares.c:786-806`). A lookup error maps to
    /// [`CurlCode::CouldntResolveHost`] carrying the queried host name for
    /// `--trace` parity with curl's `failf("Could not resolve host: %s")`.
    async fn lookup_family(&self, host: &str, record_type: RecordType) -> Result<Vec<IpAddr>> {
        let lookup = self
            .inner
            .lookup(host, record_type)
            .await
            .map_err(|_| Error::resolve(host))?;
        Ok(lookup.iter().filter_map(rdata_to_ip).collect())
    }
}

// ---------------------------------------------------------------------------
// Phase 3 — the Resolver trait implementation (← Curl_async_getaddrinfo)
// ---------------------------------------------------------------------------

impl Resolver for HickoryResolver {
    /// Resolves `host`/`port` honoring `ip_version`, reproducing
    /// `Curl_async_getaddrinfo` (`lib/asyn-ares.c:711`).
    ///
    /// Family selection is identical to curl's `ip_version → ai_family`
    /// mapping:
    ///
    /// * [`IpVersion::V4`] → an A-record-only lookup (curl's `PF_INET`).
    /// * [`IpVersion::V6`] → an AAAA-record-only lookup (curl's `PF_INET6`).
    /// * [`IpVersion::Whatever`] → a combined A+AAAA lookup (curl's `PF_UNSPEC`),
    ///   with IPv6 endpoints ordered ahead of IPv4 to honor curl's
    ///   `async_addr_concat` contract (`lib/asyn-ares.c:463`) — the ordering
    ///   `conn/happy_eyeballs.rs` relies on for RFC 8305 interleaving.
    ///
    /// An unresolved host — a lookup error or an empty answer — maps to
    /// [`CurlCode::CouldntResolveHost`], the same code c-ares's `ARES_ENOTFOUND`
    /// path produces (`lib/asyn-ares.c:379`). The port is stamped onto every
    /// endpoint via [`Address::from_ips`], the idiomatic form of
    /// `Curl_addrinfo_set_port`.
    ///
    /// The future is boxed (rather than the trait using an `async fn`) so
    /// [`Resolver`] stays object-safe and compiles on the MSRV — see
    /// [`ResolveFuture`].
    fn resolve<'a>(&'a self, host: &'a str, port: u16, ip_version: IpVersion) -> ResolveFuture<'a> {
        Box::pin(async move {
            let ips = match ip_version {
                IpVersion::V4 => self.lookup_family(host, RecordType::A).await?,
                IpVersion::V6 => self.lookup_family(host, RecordType::AAAA).await?,
                IpVersion::Whatever => {
                    // hickory's lookup_ip performs A+AAAA per the resolver's
                    // ip_strategy (fixed to Ipv4AndIpv6 in `new`); reorder so
                    // IPv6 leads, matching async_addr_concat.
                    let lookup = self
                        .inner
                        .lookup_ip(host)
                        .await
                        .map_err(|_| Error::resolve(host))?;
                    order_ipv6_first(lookup.iter())
                }
            };

            if ips.is_empty() {
                // (asyn-ares.c:379) No addresses found → CURLE_COULDNT_RESOLVE_HOST.
                return Err(Error::resolve(host));
            }

            Ok(Address::from_ips(ips, port))
        })
    }
}

// ---------------------------------------------------------------------------
// Phase 2/3 — free helpers (record extraction, ordering, config construction)
// ---------------------------------------------------------------------------

/// Extracts an [`IpAddr`] from an `A` or `AAAA` [`RData`] record, ignoring every
/// other record type. The `A` / `AAAA` unwrapping mirrors hickory's own
/// `LookupIpIter`, so the address conversion stays byte-identical to what
/// `lookup_ip` would have produced.
fn rdata_to_ip(rdata: &RData) -> Option<IpAddr> {
    match rdata {
        RData::A(ip) => Some(IpAddr::from(Ipv4Addr::from(*ip))),
        RData::AAAA(ip) => Some(IpAddr::from(Ipv6Addr::from(*ip))),
        _ => None,
    }
}

/// Orders a mixed set of addresses so that **IPv6 endpoints precede IPv4**,
/// preserving the relative order within each family — the safe-Rust equivalent
/// of curl's `async_addr_concat` (`lib/asyn-ares.c:463`), which keeps IPv6 at the
/// head of the merged `Curl_addrinfo` list. `conn/happy_eyeballs.rs` depends on
/// this ordering to interleave connection attempts per RFC 8305.
fn order_ipv6_first(addrs: impl Iterator<Item = IpAddr>) -> Vec<IpAddr> {
    let mut v6 = Vec::new();
    let mut v4 = Vec::new();
    for ip in addrs {
        if ip.is_ipv6() {
            v6.push(ip);
        } else {
            v4.push(ip);
        }
    }
    v6.extend(v4);
    v6
}

/// Returns the local source [`SocketAddr`] to bind for a name server of the
/// given family, or `None` when no matching local address was configured. An
/// IPv4 server binds [`HickoryOptions::local_ip4`]; an IPv6 server binds
/// [`HickoryOptions::local_ip6`].
fn bind_for(
    server_ip: IpAddr,
    bind4: Option<SocketAddr>,
    bind6: Option<SocketAddr>,
) -> Option<SocketAddr> {
    match server_ip {
        IpAddr::V4(_) => bind4,
        IpAddr::V6(_) => bind6,
    }
}

/// Parses a `CURLOPT_DNS_SERVERS` csv string into a list of name-server
/// [`SocketAddr`]s, reproducing `ares_set_servers_ports_csv`
/// (`lib/asyn-ares.c:851`). Each comma-separated entry is either a bare IP
/// (defaulting to [`DNS_PORT`]) or an `ip:port` / `[ipv6]:port` pair; blank
/// entries are skipped.
///
/// # Errors
///
/// Returns [`CurlCode::BadFunctionArgument`] if an entry is not a valid address,
/// or if the list contains no usable servers — parity with c-ares mapping
/// `ARES_EBADSTR` → `CURLE_BAD_FUNCTION_ARGUMENT` (`lib/asyn-ares.c:862`).
fn parse_dns_servers(csv: &str) -> Result<Vec<SocketAddr>> {
    let mut servers = Vec::new();
    for raw in csv.split(',') {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        servers.push(parse_one_server(entry)?);
    }
    if servers.is_empty() {
        return Err(Error::bad_argument(
            "CURLOPT_DNS_SERVERS contained no usable name servers",
        ));
    }
    Ok(servers)
}

/// Parses a single name-server entry: `ip`, `ip:port`, or `[ipv6]:port`.
fn parse_one_server(entry: &str) -> Result<SocketAddr> {
    // "1.2.3.4:53" or "[2001:db8::1]:53" — a full socket address with a port.
    if let Ok(socket) = SocketAddr::from_str(entry) {
        return Ok(socket);
    }
    // "1.2.3.4" or "2001:db8::1" — a bare IP literal; default to port 53.
    if let Ok(ip) = IpAddr::from_str(entry) {
        return Ok(SocketAddr::new(ip, DNS_PORT));
    }
    // "[2001:db8::1]" — a bracketed IPv6 literal without a port.
    if let Some(inner) = entry.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        if let Ok(ip) = IpAddr::from_str(inner) {
            return Ok(SocketAddr::new(ip, DNS_PORT));
        }
    }
    Err(Error::bad_argument(format!(
        "invalid CURLOPT_DNS_SERVERS entry: {entry}"
    )))
}

/// Builds a [`ResolverConfig`] from an explicit name-server list, creating both a
/// UDP and a TCP transport per server (as hickory's own `from_ips_clear` does,
/// and as c-ares uses UDP with TCP fallback) and stamping the configured local
/// source address onto each via [`NameServerConfig::bind_addr`]. No search
/// domain is attached — curl performs no suffix search when the caller pins the
/// servers.
fn build_custom_config(
    servers: &[SocketAddr],
    bind4: Option<SocketAddr>,
    bind6: Option<SocketAddr>,
) -> ResolverConfig {
    let mut name_servers = Vec::with_capacity(servers.len() * 2);
    for &socket in servers {
        let bind_addr = bind_for(socket.ip(), bind4, bind6);
        for protocol in [Protocol::Udp, Protocol::Tcp] {
            let mut name_server = NameServerConfig::new(socket, protocol);
            name_server.bind_addr = bind_addr;
            name_servers.push(name_server);
        }
    }
    ResolverConfig::from_parts(None, Vec::new(), name_servers)
}

/// Returns `config` with the configured local source address applied to every
/// name server of the matching family, preserving the domain and search list.
/// When neither `bind4` nor `bind6` is set the configuration is returned
/// unchanged (so a plain system resolver keeps its exact upstream config).
fn apply_bind_addrs(
    config: ResolverConfig,
    bind4: Option<SocketAddr>,
    bind6: Option<SocketAddr>,
) -> ResolverConfig {
    if bind4.is_none() && bind6.is_none() {
        return config;
    }
    let domain = config.domain().cloned();
    let search = config.search().to_vec();
    let mut name_servers = Vec::with_capacity(config.name_servers().len());
    for name_server in config.name_servers() {
        let mut name_server = name_server.clone();
        name_server.bind_addr = bind_for(name_server.socket_addr.ip(), bind4, bind6);
        name_servers.push(name_server);
    }
    ResolverConfig::from_parts(domain, search, name_servers)
}

// ---------------------------------------------------------------------------
// Phase 4 — error bridging (← ARES_* → CURLcode, asyn-ares.c:379)
// ---------------------------------------------------------------------------

impl From<ResolveError> for Error {
    /// Bridges a hickory [`ResolveError`] to the crate [`Error`] type.
    ///
    /// curl's c-ares backend collapses `ARES_ENOTFOUND` and every other
    /// resolution failure to `CURLE_COULDNT_RESOLVE_HOST`
    /// (`lib/asyn-ares.c:379`); this conversion preserves that frozen code (6).
    /// The proxy-vs-host distinction (`CURLE_COULDNT_RESOLVE_PROXY`, 5) is not
    /// visible at the resolver backend — it is applied one layer up by
    /// [`crate::dns::resolver_error`] — so this backend always yields the host
    /// variant. The hickory detail is carried as context for diagnostics
    /// without altering the code.
    ///
    /// Defining this conversion **inside** the feature-gated module keeps the
    /// base `error.rs` free of any dependency on the optional `hickory-resolver`
    /// crate (AAP: the feature is default-off and must not leak).
    fn from(err: ResolveError) -> Self {
        Error::with_context(CurlCode::CouldntResolveHost, err.to_string())
    }
}

// ---------------------------------------------------------------------------
// Unit tests — fully offline: option parsing, family ordering, config building,
// error mapping, and trait conformance. No live DNS is performed.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::rr::rdata::{A, AAAA};
    use hickory_resolver::ResolveErrorKind;

    // -- CURLOPT_DNS_SERVERS csv parsing (← ares_set_servers_ports_csv) ------

    #[test]
    fn parse_servers_bare_ipv4_defaults_to_port_53() {
        let servers = parse_dns_servers("8.8.8.8").unwrap();
        assert_eq!(servers, vec![SocketAddr::from(([8, 8, 8, 8], 53))]);
    }

    #[test]
    fn parse_servers_ipv4_with_explicit_port() {
        let servers = parse_dns_servers("1.1.1.1:5353").unwrap();
        assert_eq!(servers, vec![SocketAddr::from(([1, 1, 1, 1], 5353))]);
    }

    #[test]
    fn parse_servers_ipv6_bare_bracketed_and_ported() {
        let bare = parse_dns_servers("2001:4860:4860::8888").unwrap();
        assert_eq!(bare.len(), 1);
        assert!(bare[0].is_ipv6());
        assert_eq!(bare[0].port(), 53);

        let ported = parse_dns_servers("[2001:4860:4860::8888]:5353").unwrap();
        assert_eq!(ported.len(), 1);
        assert!(ported[0].is_ipv6());
        assert_eq!(ported[0].port(), 5353);

        let bracketed_no_port = parse_dns_servers("[2001:4860:4860::8844]").unwrap();
        assert_eq!(bracketed_no_port[0].port(), 53);
        assert!(bracketed_no_port[0].is_ipv6());
    }

    #[test]
    fn parse_servers_multiple_entries_and_skips_blanks() {
        let servers = parse_dns_servers(" 8.8.8.8 , ,1.1.1.1:53 ").unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0], SocketAddr::from(([8, 8, 8, 8], 53)));
        assert_eq!(servers[1], SocketAddr::from(([1, 1, 1, 1], 53)));
    }

    #[test]
    fn parse_servers_rejects_garbage_with_bad_argument() {
        let err = parse_dns_servers("not-an-ip").unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
    }

    #[test]
    fn parse_servers_rejects_empty_list_with_bad_argument() {
        let err = parse_dns_servers("  , ,  ").unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
    }

    // -- IPv6-at-head merge ordering (← async_addr_concat) -------------------

    #[test]
    fn order_ipv6_first_puts_v6_ahead_preserving_family_order() {
        let v4a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let v4b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let v6a = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let v6b = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        // Interleaved input; IPv6 must lead and order within each family is kept.
        let ordered = order_ipv6_first([v4a, v6a, v4b, v6b].into_iter());
        assert_eq!(ordered, vec![v6a, v6b, v4a, v4b]);
    }

    #[test]
    fn order_ipv6_first_handles_single_family_and_empty() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(order_ipv6_first([v4].into_iter()), vec![v4]);
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(order_ipv6_first([v6].into_iter()), vec![v6]);
        assert!(order_ipv6_first(std::iter::empty()).is_empty());
    }

    // -- RData extraction (matches hickory's own LookupIpIter) ---------------

    #[test]
    fn rdata_to_ip_extracts_a_and_aaaa_only() {
        let a = RData::A(A::from(Ipv4Addr::new(203, 0, 113, 7)));
        let aaaa = RData::AAAA(AAAA::from(Ipv6Addr::LOCALHOST));
        assert_eq!(
            rdata_to_ip(&a),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)))
        );
        assert_eq!(rdata_to_ip(&aaaa), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // A non-address record (TXT) yields nothing.
        let txt = RData::TXT(hickory_resolver::proto::rr::rdata::TXT::new(vec![
            "hello".to_string()
        ]));
        assert_eq!(rdata_to_ip(&txt), None);
    }

    // -- local source-address binding (← ares_set_local_ip4/6) ---------------

    #[test]
    fn bind_for_selects_matching_family() {
        let b4 = SocketAddr::from(([192, 0, 2, 9], 0));
        let b6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        let v4_server = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let v6_server = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));
        assert_eq!(bind_for(v4_server, Some(b4), Some(b6)), Some(b4));
        assert_eq!(bind_for(v6_server, Some(b4), Some(b6)), Some(b6));
        // No matching family bind → None (leaves the OS default source address).
        assert_eq!(bind_for(v4_server, None, Some(b6)), None);
        assert_eq!(bind_for(v6_server, Some(b4), None), None);
    }

    #[test]
    fn build_custom_config_creates_udp_and_tcp_with_family_scoped_bind() {
        let servers = [
            SocketAddr::from(([8, 8, 8, 8], 53)),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53),
        ];
        let bind4 = Some(SocketAddr::from(([192, 0, 2, 1], 0)));
        let config = build_custom_config(&servers, bind4, None);
        // Two protocols (UDP + TCP) per server → four name-server entries.
        assert_eq!(config.name_servers().len(), 4);
        for name_server in config.name_servers() {
            match name_server.socket_addr.ip() {
                IpAddr::V4(_) => assert_eq!(name_server.bind_addr, bind4),
                IpAddr::V6(_) => assert_eq!(name_server.bind_addr, None),
            }
        }
        // Both transports are represented.
        assert!(config
            .name_servers()
            .iter()
            .any(|ns| ns.protocol == Protocol::Udp));
        assert!(config
            .name_servers()
            .iter()
            .any(|ns| ns.protocol == Protocol::Tcp));
    }

    // -- constructor option handling -----------------------------------------

    #[test]
    fn interface_option_maps_to_not_built_in() {
        let options = HickoryOptions {
            interface: Some("eth0".to_string()),
            ..HickoryOptions::default()
        };
        let err = HickoryResolver::new(&options).unwrap_err();
        assert_eq!(err.code(), CurlCode::NotBuiltIn);
    }

    #[test]
    fn empty_interface_is_treated_as_unset() {
        // curl stores "" for "no interface"; it must NOT trigger NotBuiltIn.
        // Use the custom-server path so the test never depends on a readable
        // /etc/resolv.conf.
        let options = HickoryOptions {
            interface: Some(String::new()),
            servers: Some("8.8.8.8".to_string()),
            ..HickoryOptions::default()
        };
        assert!(HickoryResolver::new(&options).is_ok());
    }

    #[test]
    fn bad_servers_option_rejected_by_constructor() {
        let options = HickoryOptions {
            servers: Some("definitely not an ip".to_string()),
            ..HickoryOptions::default()
        };
        let err = HickoryResolver::new(&options).unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
    }

    #[test]
    fn custom_server_with_local_ip_binds_source_address() {
        let options = HickoryOptions {
            servers: Some("8.8.8.8,[2001:4860:4860::8888]:53".to_string()),
            local_ip4: Some(Ipv4Addr::new(192, 0, 2, 5)),
            local_ip6: Some(Ipv6Addr::LOCALHOST),
            ..HickoryOptions::default()
        };
        // Construction succeeds and the resolver is usable as a trait object.
        let resolver = HickoryResolver::new(&options).unwrap();
        let _dyn_ref: &dyn Resolver = &resolver;
    }

    // -- error bridging (← ARES_ENOTFOUND → CURLE_COULDNT_RESOLVE_HOST) ------

    #[test]
    fn from_resolve_error_maps_to_couldnt_resolve_host() {
        let resolve_err = ResolveError::from(ResolveErrorKind::Message("simulated failure"));
        let err: Error = resolve_err.into();
        assert_eq!(err.code(), CurlCode::CouldntResolveHost);
    }

    // -- trait conformance ---------------------------------------------------

    #[test]
    fn hickory_resolver_is_a_send_sync_object_safe_resolver() {
        fn assert_resolver<R: Resolver>() {}
        fn assert_send_sync<T: Send + Sync>() {}
        assert_resolver::<HickoryResolver>();
        assert_send_sync::<HickoryResolver>();
    }
}
