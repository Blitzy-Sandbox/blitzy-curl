// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! The **default, always-on** name-resolution backend: curl's asynchronous
//! system resolver, realized on Tokio.
//!
//! # What this module is
//!
//! `dns::system` is the idiomatic-Rust replacement for curl 8.x's *threaded*
//! asynchronous resolver and its synchronous `getaddrinfo` fallback, unified into
//! a single [`Resolver`] implementation, [`SystemResolver`]. It is curl's
//! `AsynchDNS` feature — but in place of curl's hand-managed dedicated resolver
//! thread it rides Tokio's blocking thread pool. It is a language rewrite derived
//! from these source-of-truth C files (preserved unmodified in `lib/`):
//!
//! | curl C source        | responsibility reproduced here |
//! |----------------------|--------------------------------|
//! | `lib/asyn-thrdd.c`   | PRIMARY. `Curl_async_getaddrinfo` builds the `getaddrinfo` hints from `ip_version` and spawns `getaddrinfo_thread`; that off-thread blocking `getaddrinfo` becomes [`tokio::net::lookup_host`], which offloads the very same call to Tokio's blocking pool. |
//! | `lib/hostip.c`       | the `ip_version` → address-family decision (`can_resolve_ip_version`, `hostip.c:807`) and the synchronous `Curl_sync_getaddrinfo` entry point. |
//! | `lib/hostip4.c`      | the IPv4 hint (`Curl_ipv4_resolve_r`: `PF_INET`, `SOCK_STREAM`). |
//! | `lib/hostip6.c`      | the IPv6 / dual-stack hint (`Curl_ipv6_resolve_r`: `PF_UNSPEC` / `PF_INET6`). |
//!
//! # Why Tokio's `lookup_host` *is* curl's "AsynchDNS"
//!
//! curl's threaded resolver (`asyn-thrdd.c`) spawns a worker thread whose sole
//! job is to run the blocking libc `getaddrinfo` and hand the answer back to the
//! event loop (`getaddrinfo_thread`, polled by `Curl_async_is_resolved` with a
//! 1 ms → 250 ms exponential backoff). [`tokio::net::lookup_host`] performs the
//! *identical* work: it runs the blocking `getaddrinfo` on Tokio's dedicated
//! blocking thread pool and yields the result to the async task when ready. The
//! rewrite therefore does **no** manual thread management — the runtime owns the
//! pool — while preserving curl's non-blocking-resolve semantics. This is the
//! AAP's "Async Runtime Discipline" (§0.3.2) applied to DNS.
//!
//! # Address-family selection (parity with `Curl_async_getaddrinfo`)
//!
//! curl derives a `getaddrinfo` `ai_family` hint from `CURLOPT_IPRESOLVE`
//! (`asyn-thrdd.c:733`):
//!
//! ```text
//! pf = PF_INET;                                   // default: IPv4
//! if (ip_version != CURL_IPRESOLVE_V4 && Curl_ipv6works()) {
//!     pf = (ip_version == CURL_IPRESOLVE_V6) ? PF_INET6    // V6-only
//!                                            : PF_UNSPEC;  // both families
//! }
//! hints.ai_socktype = SOCK_STREAM;                // TCP connect path
//! ```
//!
//! [`tokio::net::lookup_host`] does **not** accept an `ai_family` hint — it always
//! resolves with `AF_UNSPEC` (and, in the Rust standard library, a fixed
//! `SOCK_STREAM` socket type, which is exactly curl's TCP hint, so no duplicate
//! per-socktype entries are produced). Parity is therefore achieved by resolving
//! the broadest family and then **post-filtering** the returned addresses by the
//! requested [`IpVersion`] (see `filter_family`). Narrowing the `AF_UNSPEC` answer
//! down to a single family yields the identical address *set* that curl's hinted
//! `getaddrinfo` would have produced.
//!
//! The socket type is always TCP (`SOCK_STREAM`) here, matching curl's connect
//! path; curl only uses `SOCK_DGRAM` for a handful of datagram protocols, and
//! those resolve through the same address set, so TCP is the correct parity
//! default for this backend.
//!
//! # Ordering is sacred (RFC 8305 Happy Eyeballs)
//!
//! The order of the resolved endpoints is a **behavioral contract**, not an
//! implementation detail. `getaddrinfo` returns addresses in the kernel's RFC 6724
//! source-address-selection order, interleaving IPv4 and IPv6, and the connection
//! layer (`conn/happy_eyeballs.rs`) consumes that exact ordering — and the relative
//! IPv4/IPv6 positioning — to interleave connection attempts by family (RFC 8305).
//! This backend therefore **must not** sort, shuffle, deduplicate, or otherwise
//! reorder the addresses; it only drops entries of the wrong family through a
//! stable, order-preserving retain. Any optional address shuffling
//! (`CURLOPT_DNS_SHUFFLE_ADDRESSES`) is applied later, in
//! [`crate::dns::DnsCache::mk_entry`], never here.
//!
//! # Memory safety
//!
//! Written in 100% safe Rust: it performs no low-level memory operations and no
//! raw libc `getaddrinfo` FFI (Tokio wraps that blocking call for us). This
//! upholds the crate root's compile-time memory-safety guarantee (AAP §0.7.2) —
//! eliminating the manual-allocation defect class is the very reason the rewrite
//! exists — and it keeps this module clear of the CI audit that asserts the
//! forbidden-code token never appears anywhere under `curl-rs-lib/src/`.

use std::net::SocketAddr;

use tokio::net::lookup_host;

use crate::dns::{ipv6_works, Address, IpVersion, ResolveFuture, Resolver};
use crate::error::{Error, Result};

/// curl's default asynchronous name resolver, realized on Tokio's system
/// resolver.
///
/// This is the [`Resolver`] the connection layer uses unless DNS-over-HTTPS
/// ([`crate::dns::doh`]) or the optional `hickory` backend is selected. It is
/// **stateless**: curl's threaded resolver keeps no persistent state between
/// lookups either — each `Curl_async_getaddrinfo` call is self-contained — so the
/// type is a zero-sized unit struct. Every per-lookup input arrives as an argument
/// to [`Resolver::resolve`], and the DNS cache lives in [`crate::dns::DnsCache`],
/// not in the backend.
///
/// # Examples
///
/// ```no_run
/// use curl_rs_lib::dns::system::SystemResolver;
/// use curl_rs_lib::dns::{IpVersion, Resolver};
///
/// # async fn demo() -> curl_rs_lib::error::Result<()> {
/// let resolver = SystemResolver::new();
/// let address = resolver.resolve("example.com", 443, IpVersion::Whatever).await?;
/// assert!(!address.is_empty());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemResolver;

impl SystemResolver {
    /// Creates a new, stateless system resolver.
    ///
    /// Equivalent to [`SystemResolver::default`]; provided as the idiomatic
    /// constructor. Because the resolver carries no state, every instance behaves
    /// identically.
    #[must_use]
    pub fn new() -> Self {
        SystemResolver
    }
}

/// Retains only the endpoints whose IP family satisfies `ip_version`, preserving
/// the resolver's original ordering.
///
/// This is the post-filter that substitutes for curl's `getaddrinfo` `ai_family`
/// hint (see the module-level docs): [`tokio::net::lookup_host`] cannot be told a
/// family, so it resolves every family and this function narrows the result —
/// [`IpVersion::V4`] keeps only IPv4 endpoints (curl's `PF_INET`),
/// [`IpVersion::V6`] keeps only IPv6 (curl's `PF_INET6`), and
/// [`IpVersion::Whatever`] keeps them all (curl's `PF_UNSPEC`).
///
/// The filter is a stable retain: it never reorders, so the RFC 8305 Happy-Eyeballs
/// interleaving the connection layer depends on is preserved (see the module-level
/// ordering contract). The per-address decision is delegated to
/// [`IpVersion::accepts`] — the same predicate [`Address::filter_by_ip_version`]
/// uses — so this backend filter and the orchestration's safety-net filter agree
/// exactly.
fn filter_family(endpoints: Vec<SocketAddr>, ip_version: IpVersion) -> Vec<SocketAddr> {
    endpoints
        .into_iter()
        .filter(|addr| ip_version.accepts(addr))
        .collect()
}

/// Performs one system resolution: the IPv6-availability gate, the Tokio
/// `getaddrinfo`, family post-filtering, and curl-faithful error mapping.
///
/// `host` is taken **by value** (an owned `String`) so the returned future is
/// `'static` and `Send`, letting a resolution outlive the call and run on the
/// multi-threaded Tokio runtime the multi handle uses. [`Resolver::resolve`]
/// performs the `&str` → `String` copy before delegating here, mirroring how curl
/// copies the hostname into the resolver thread's `thread_sync_data`
/// (`asyn-thrdd.c`) before the thread starts.
async fn resolve_system(host: String, port: u16, ip_version: IpVersion) -> Result<Address> {
    // Phase 5 — IPv6-availability gate (← `can_resolve_ip_version`, `hostip.c:807`,
    // and the `Curl_ipv6works` guard inside `Curl_async_getaddrinfo`). A V6-only
    // request cannot be satisfied when the local IPv6 stack does not work; curl
    // refuses it up front rather than issuing a doomed lookup, so we return the
    // resolution error without touching the network. `ipv6_works()` is the shared,
    // process-cached probe defined in `dns::mod` (curl's `Curl_ipv6works`).
    if ip_version == IpVersion::V6 && !ipv6_works() {
        return Err(Error::resolve(host));
    }

    // Phase 3 — the asynchronous lookup. `lookup_host((host, port))` offloads the
    // blocking libc `getaddrinfo` to Tokio's blocking thread pool — the safe
    // equivalent of curl's dedicated `getaddrinfo_thread`. The `(host, port)` tuple
    // form stamps `port` onto every returned `SocketAddr` and brackets IPv6 literals
    // internally, so no manual `[addr]:port` formatting is needed. A `getaddrinfo`
    // failure (`EAI_NONAME`, `EAI_AGAIN`, …) becomes a host-resolution error.
    let resolved = lookup_host((host.as_str(), port))
        .await
        .map_err(|_| Error::resolve(host.clone()))?;

    // Phase 2 — narrow the `AF_UNSPEC` answer to the requested family, preserving
    // the resolver's RFC 6724 ordering (the Happy-Eyeballs contract). The iterator
    // is collected into an ordered `Vec` exactly as the resolver returned it, then
    // filtered in place without reordering.
    let endpoints = filter_family(resolved.collect(), ip_version);

    // Phase 6 — an empty result (no address at all, or none of the requested
    // family) is a resolution *failure*, not an empty success: curl maps this to
    // `CURLE_COULDNT_RESOLVE_HOST` (== 6). The orchestration in `dns::mod`
    // negative-caches the name and returns the same code.
    if endpoints.is_empty() {
        return Err(Error::resolve(host));
    }

    Ok(Address::new(endpoints))
}

impl Resolver for SystemResolver {
    /// Resolves `host`/`port` to an ordered [`Address`], honoring `ip_version`.
    ///
    /// Returns a boxed, `Send`, effectively-`'static` future (see
    /// [`ResolveFuture`]); the hostname is copied into it so the future borrows
    /// neither `self` nor `host`, which is what lets a resolution outlive the call
    /// and run on the multi-threaded runtime. On any failure the future resolves to
    /// an [`Error`] carrying
    /// [`CouldntResolveHost`](crate::error::CurlCode::CouldntResolveHost) (== 6).
    /// The proxy-vs-host distinction (a proxy failure maps to code 5) is applied by
    /// the [`crate::dns::resolve`] orchestration, not by this backend, because the
    /// [`Resolver`] contract carries no proxy flag.
    fn resolve<'a>(&'a self, host: &'a str, port: u16, ip_version: IpVersion) -> ResolveFuture<'a> {
        // Copy the borrowed host into an owned `String` so the returned future is
        // `'static` + `Send` (mirrors curl copying the hostname into the resolver
        // thread's sync data before the thread is created).
        let host = host.to_string();
        Box::pin(resolve_system(host, port, ip_version))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CurlCode;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// Convenience: an IPv4 [`SocketAddr`].
    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    /// Convenience: an IPv6 [`SocketAddr`] from a literal.
    fn v6(literal: &str, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(literal.parse::<Ipv6Addr>().unwrap()), port)
    }

    // -- filter_family: family narrowing + order preservation ---------------

    #[test]
    fn filter_family_v4_keeps_only_ipv4_in_order() {
        let input = vec![
            v4(1, 1, 1, 1, 80),
            v6("::1", 80),
            v4(2, 2, 2, 2, 80),
            v6("2001:db8::1", 80),
        ];
        let out = filter_family(input, IpVersion::V4);
        // Only the IPv4 endpoints survive, and their relative order is untouched.
        assert_eq!(out, vec![v4(1, 1, 1, 1, 80), v4(2, 2, 2, 2, 80)]);
    }

    #[test]
    fn filter_family_v6_keeps_only_ipv6_in_order() {
        let a = v6("2001:db8::1", 80);
        let b = v6("2001:db8::2", 80);
        let input = vec![v4(1, 1, 1, 1, 80), a, v4(2, 2, 2, 2, 80), b];
        let out = filter_family(input, IpVersion::V6);
        assert_eq!(out, vec![a, b]);
    }

    #[test]
    fn filter_family_whatever_keeps_all_in_order() {
        let input = vec![
            v4(1, 1, 1, 1, 80),
            v6("::1", 80),
            v4(2, 2, 2, 2, 80),
            v6("2001:db8::1", 80),
        ];
        let out = filter_family(input.clone(), IpVersion::Whatever);
        // `Whatever` is a no-op filter: the full list is returned verbatim.
        assert_eq!(out, input);
    }

    #[test]
    fn filter_family_empty_input_stays_empty() {
        assert!(filter_family(Vec::new(), IpVersion::Whatever).is_empty());
        assert!(filter_family(Vec::new(), IpVersion::V4).is_empty());
        assert!(filter_family(Vec::new(), IpVersion::V6).is_empty());
    }

    // -- async resolution behavior ------------------------------------------
    //
    // These tests are offline-safe: they resolve only numeric IP literals (which
    // `getaddrinfo` parses without a network round-trip) and `localhost` (served
    // from the hosts database), so they never depend on external DNS.

    #[tokio::test]
    async fn resolve_ipv4_literal_returns_single_stamped_endpoint() {
        let resolver = SystemResolver::new();
        let address = resolver
            .resolve("127.0.0.1", 8080, IpVersion::V4)
            .await
            .expect("a numeric IPv4 literal always resolves");
        // Exactly one endpoint — proving the Rust std `SOCK_STREAM` hint yields no
        // per-socktype duplicates (curl parity) — with the requested port stamped on
        // by `lookup_host`.
        assert_eq!(address.endpoints(), &[v4(127, 0, 0, 1, 8080)]);
    }

    #[tokio::test]
    async fn resolve_whatever_localhost_is_non_empty_and_ordered() {
        let resolver = SystemResolver::new();
        let address = resolver
            .resolve("localhost", 80, IpVersion::Whatever)
            .await
            .expect("localhost resolves via the hosts database");
        assert!(
            !address.is_empty(),
            "localhost must resolve to at least one loopback address"
        );
        // Every returned endpoint carries the requested port.
        assert!(address.endpoints().iter().all(|ep| ep.port() == 80));
    }

    #[tokio::test]
    async fn resolve_ipv4_literal_as_v6_fails_with_couldnt_resolve_host() {
        let resolver = SystemResolver::new();
        // Requesting IPv6-only for a host that only has an IPv4 address is a
        // resolution failure. Whether the V6 gate trips (no IPv6 stack) or the
        // family post-filter empties the result (IPv6 stack present), the mapped
        // code is identical: CURLE_COULDNT_RESOLVE_HOST (== 6).
        let err = resolver
            .resolve("127.0.0.1", 80, IpVersion::V6)
            .await
            .expect_err("an IPv4-only host cannot satisfy a V6-only request");
        assert_eq!(err.code(), CurlCode::CouldntResolveHost);
    }

    #[tokio::test]
    async fn resolve_via_dyn_resolver_is_object_safe() {
        // The backend must be usable as `&dyn Resolver` — that object safety is why
        // the trait returns a boxed `ResolveFuture` rather than using `async fn`.
        let resolver = SystemResolver::new();
        let dynamic: &dyn Resolver = &resolver;
        let address = dynamic
            .resolve("127.0.0.1", 443, IpVersion::Whatever)
            .await
            .expect("dispatch through a trait object resolves identically");
        assert_eq!(address.endpoints(), &[v4(127, 0, 0, 1, 443)]);
    }

    #[tokio::test]
    async fn resolve_v6_respects_ipv6_availability() {
        let resolver = SystemResolver::new();
        let result = resolver.resolve("::1", 80, IpVersion::V6).await;
        if ipv6_works() {
            // A working IPv6 stack: `::1` resolves and only IPv6 endpoints survive
            // the family filter.
            let address = result.expect("::1 resolves when the IPv6 stack works");
            assert!(!address.is_empty());
            assert!(
                address.endpoints().iter().all(SocketAddr::is_ipv6),
                "a V6-only request must yield only IPv6 endpoints"
            );
        } else {
            // No IPv6 stack: the V6-only request is gated to a failure up front
            // (parity with `can_resolve_ip_version`), never attempted.
            let err = result.expect_err("a V6-only request is refused without IPv6");
            assert_eq!(err.code(), CurlCode::CouldntResolveHost);
        }
    }

    #[test]
    fn system_resolver_is_zero_sized_and_default() {
        // Stateless like curl's system resolver: the type carries no data.
        assert_eq!(std::mem::size_of::<SystemResolver>(), 0);
        assert_eq!(SystemResolver::new(), SystemResolver);
    }
}
