// SPDX-License-Identifier: curl
//
//! Default name-resolution backend — the Tokio / standard-library resolver.
//!
//! This is the resolver that is **always compiled in** (there is no feature
//! flag for it) and the one [`crate::dns::resolve`] dispatches to whenever a DoH
//! URL is not configured and the optional `hickory-dns` backend is not enabled.
//! It is the memory-safe, asynchronous Rust analog of curl's *threaded*
//! resolver, and the reason [`crate::dns::ASYNC_DNS`] is `true` in the default
//! build (the `AsynchDNS` capability parity point, Agent Action Plan §0.7.3).
//!
//! # Behavioral oracle (REFERENCE ONLY — not a line-by-line port)
//!
//! The externally observable behavior is reproduced from three C files, which
//! are read as a behavior/ABI oracle and never transliterated:
//!
//! * `lib/hostip4.c` — the IPv4 synchronous path (`Curl_ipv4_resolve_r`,
//!   `Curl_sync_getaddrinfo`): `getaddrinfo` with `ai_family = PF_INET`,
//!   `ai_socktype = SOCK_STREAM`.
//! * `lib/hostip6.c:78-100` — the dual-stack `Curl_sync_getaddrinfo`: the
//!   `pf`/`AI_NUMERICHOST` hint logic and the verbose
//!   `"getaddrinfo(3) failed for %s:%d"` diagnostic on failure.
//! * `lib/asyn-thrdd.c:733-764` — the *threaded* `Curl_async_getaddrinfo`,
//!   whose address-family (`pf`) decision this module reproduces exactly:
//!
//!   ```c
//!   int pf = PF_INET;                       /* default: IPv4 */
//!   #ifdef CURLRES_IPV6
//!     if((ip_version != CURL_IPRESOLVE_V4) && Curl_ipv6works(data)) {
//!       if(ip_version == CURL_IPRESOLVE_V6) pf = PF_INET6;  /* V6 only */
//!       else                                pf = PF_UNSPEC; /* both    */
//!     }
//!   #else
//!     (void)ip_version;                     /* no IPv6 build: always PF_INET */
//!   #endif
//!   ```
//!
//! curl's `asyn-ares.c` (the c-ares binding) is deliberately **out of scope**
//! (the c-ares dependency is removed, AAP §0.3.2 / §0.6.2) and is neither
//! referenced nor reproduced here.
//!
//! # Why there is no thread/socketpair/backoff machinery
//!
//! curl's threaded resolver spawns a `pthread`, signals completion over a
//! wakeup socketpair, reference-counts a shared `addr_ctx`, and polls it on a
//! 1 ms → 250 ms exponential backoff because C cannot simply *await* a thread.
//! None of that is reproduced here: a name resolution is just a future, and the
//! caller `.await`s it directly. Tokio's [`lookup_host`] already moves the
//! blocking `getaddrinfo(3)` call onto the runtime's blocking thread pool — the
//! direct async analog of curl's resolver thread — so the runtime worker is
//! never blocked.
//!
//! # Division of labor with [`crate::dns`]
//!
//! The parent module's [`crate::dns::resolve`] flow performs every step that
//! surrounds a backend query — IDN→ACE encoding, `.onion` rejection, the DNS
//! cache lookup and negative caching, the literal-IP and `localhost`
//! shortcuts, the V6-without-IPv6 gate ([`crate::dns::can_resolve_ip_version`]),
//! the proxy-vs-host error remapping, and the wall-clock deadline
//! ([`crate::dns::resolve_timeout`]). This backend is therefore responsible for
//! exactly one thing: turning a host + port + family preference into a set of
//! [`SocketAddr`]s via the OS resolver, filtered to the requested family. The
//! entrypoint [`resolve`] matches the contract the parent dispatches through
//! verbatim (`async fn resolve(host, port, ip_version)`); the verbose- and
//! proxy-aware [`resolve_verbose`] and the deadline-bounded
//! [`resolve_with_timeout`] are thin, fully-reusable variants over the same
//! core (they let a caller that *does* hold the verbose / proxy / timeout
//! context drive this backend directly).
//!
//! # Memory safety (AAP §0.7.1)
//!
//! This file contains **zero** `unsafe` and compiles under
//! `#![forbid(unsafe_code)]` (also inherited from the `dns` module root). It
//! uses only the safe [`tokio::net::lookup_host`] and [`std::net`] resolution
//! APIs — there is no raw FFI to `getaddrinfo`, no manual socket handling, and
//! no hand-rolled reference counting.

#![forbid(unsafe_code)]

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::lookup_host;

use crate::dns::{IpVersion, ResolvedAddrs};
use crate::error::{CurlError, Result};

// ---------------------------------------------------------------------------
// `CURLOPT_IPRESOLVE` raw values (parity documentation).
//
// The resolver API works in terms of the typed [`crate::dns::IpVersion`] enum,
// not these raw integers; they are reproduced from `include/curl/curl.h` purely
// so the C option values are documented in one place and pinned in lockstep
// with `IpVersion` by the compile-time assertion below. (curl passes the raw
// `CURLOPT_IPRESOLVE` int through `Curl_resolv`; the FFI/setopt layer converts
// it to `IpVersion` via `IpVersion::from_raw` before the request reaches here.)
// ---------------------------------------------------------------------------

/// `CURL_IPRESOLVE_WHATEVER` — no address-family preference (resolve both).
pub const CURL_IPRESOLVE_WHATEVER: i64 = 0;

/// `CURL_IPRESOLVE_V4` — restrict resolution to IPv4 (curl's `pf = PF_INET`).
pub const CURL_IPRESOLVE_V4: i64 = 1;

/// `CURL_IPRESOLVE_V6` — restrict resolution to IPv6 (curl's `pf = PF_INET6`).
pub const CURL_IPRESOLVE_V6: i64 = 2;

// The raw constants above MUST stay in lockstep with `IpVersion`'s own mapping
// (`crate::dns::IpVersion::from_raw`/`as_raw`). This is checked at compile time
// (and incidentally keeps the constants from being dead code in every build).
const _: () = {
    assert!(CURL_IPRESOLVE_WHATEVER == IpVersion::Any.as_raw());
    assert!(CURL_IPRESOLVE_V4 == IpVersion::V4.as_raw());
    assert!(CURL_IPRESOLVE_V6 == IpVersion::V6.as_raw());
};

// ---------------------------------------------------------------------------
// Address-family filtering (the Rust analog of curl's `pf` getaddrinfo hint).
// ---------------------------------------------------------------------------

/// Filters `addrs` to the family requested by `ip_version` and removes
/// duplicates while preserving order.
///
/// curl restricts the family *before* the query by setting `hints.ai_family`
/// (`PF_INET` / `PF_INET6` / `PF_UNSPEC`, see the module docs). Tokio's
/// [`lookup_host`] does not take family hints, so the equivalent restriction is
/// applied here, *after* resolution, which is observably identical: the same
/// addresses survive that curl's `getaddrinfo` would have returned for the
/// corresponding `pf`.
///
/// The compile-time presence of IPv6 (`cfg!(feature = "ipv6")`) is the analog
/// of curl's `CURLRES_IPV6` build gate combined with the `Curl_ipv6works`
/// runtime probe (the latter is, by design, deferred to the connection layer in
/// this port, per `crate::dns::can_resolve_ip_version`). The resulting mapping
/// reproduces `asyn-thrdd.c`'s `pf` decision exactly:
///
/// | `ip_version` | IPv6 built in | kept families            | curl `pf`   |
/// |--------------|---------------|--------------------------|-------------|
/// | `V4`         | either        | IPv4 only                | `PF_INET`   |
/// | `V6`         | yes           | IPv6 only                | `PF_INET6`  |
/// | `V6`         | no            | *(none — empty result)*  | n/a (gated) |
/// | `Any`        | yes           | both                     | `PF_UNSPEC` |
/// | `Any`        | no            | IPv4 only                | `PF_INET`   |
///
/// The de-duplication mirrors the effect of curl pinning `ai_socktype` to a
/// single socket type so `getaddrinfo` does not return the same address once
/// per socktype; the resolved IP set is transport-agnostic (the same addresses
/// serve a TCP or a UDP/QUIC connection), so the socket type is the connection
/// layer's concern, not the resolver's.
fn filter_family(addrs: Vec<SocketAddr>, ip_version: IpVersion) -> ResolvedAddrs {
    let ipv6_built_in = cfg!(feature = "ipv6");
    let (keep_v4, keep_v6) = match ip_version {
        IpVersion::V4 => (true, false),
        IpVersion::V6 => (false, ipv6_built_in),
        IpVersion::Any => (true, ipv6_built_in),
    };

    let mut out: Vec<SocketAddr> = Vec::with_capacity(addrs.len());
    for addr in addrs {
        let keep = if addr.is_ipv4() { keep_v4 } else { keep_v6 };
        // Address lists are tiny (a handful of entries), so a linear
        // membership check is the simplest order-preserving de-duplication.
        if keep && !out.contains(&addr) {
            out.push(addr);
        }
    }

    ResolvedAddrs::from_vec(out)
}

// ---------------------------------------------------------------------------
// Core query (the actual OS resolution).
// ---------------------------------------------------------------------------

/// Runs the OS resolver for `host:port` and returns the addresses filtered to
/// `ip_version`.
///
/// A numeric IP literal short-circuits the OS query entirely — the analog of
/// curl setting `AI_NUMERICHOST` (`hostip6.c:90-100`) so a numeric host is not
/// sent through a (potentially reverse) DNS lookup. The parent
/// [`crate::dns::resolve`] already intercepts IP literals before this backend is
/// reached; the short-circuit here is the defensive, self-contained equivalent
/// so this backend behaves correctly when invoked directly.
///
/// Any resolver failure — `NXDOMAIN`, `EAI_NONAME`, a missing network, etc. —
/// is collapsed into an **empty** result rather than propagated as an
/// [`std::io::Error`]. This is deliberate: a name that does not resolve maps to
/// [`CurlError::CouldntResolveHost`] (done by the callers below), *not* to
/// whatever variant `From<io::Error>` would pick (which could be a send/recv or
/// timeout code). An empty result after family filtering — for example a V6-only
/// request that yielded only IPv4 — is likewise a failed resolve, exactly as
/// curl's `getaddrinfo` would have failed for the corresponding `pf`.
async fn query_os_resolver(host: &str, port: u16, ip_version: IpVersion) -> ResolvedAddrs {
    // AI_NUMERICHOST analog: a numeric literal becomes a SocketAddr directly.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return filter_family(vec![SocketAddr::new(ip, port)], ip_version);
    }

    // Primary path: Tokio's async `getaddrinfo`, which runs the blocking lookup
    // on the runtime's blocking pool (the async analog of curl's resolver
    // thread). A failed lookup yields no addresses.
    match lookup_host((host, port)).await {
        Ok(resolved) => filter_family(resolved.collect(), ip_version),
        Err(_) => ResolvedAddrs::new(),
    }
}

// ---------------------------------------------------------------------------
// Public resolver entrypoints.
// ---------------------------------------------------------------------------

/// Resolves `host:port` using the system resolver, restricted to `ip_version`.
///
/// This is the exact contract [`crate::dns`] dispatches through
/// (`async fn resolve(host, port, ip_version) -> Result<ResolvedAddrs>`), so its
/// signature must not change. It is a thin wrapper over [`resolve_verbose`] with
/// verbose logging off and host (non-proxy) error mapping; the parent flow
/// re-maps the error to [`CurlError::CouldntResolveProxy`] when appropriate and
/// owns the verbose diagnostics around this call, so nothing is lost by the
/// defaults chosen here.
///
/// # Errors
///
/// Returns [`CurlError::CouldntResolveHost`] when the host cannot be resolved to
/// any address of the requested family (an unknown name, an empty result, or a
/// literal of the wrong family).
pub async fn resolve(host: &str, port: u16, ip_version: IpVersion) -> Result<ResolvedAddrs> {
    resolve_verbose(host, port, ip_version, false, false).await
}

/// Resolves `host:port` like [`resolve`], additionally emitting curl's verbose
/// failure diagnostic and choosing the proxy-vs-host error code.
///
/// On failure this mirrors curl's `hostip6.c:109`
/// `infof(data, "getaddrinfo(3) failed for %s:%d", hostname, port)` (gated on
/// `verbose`, i.e. `CURLOPT_VERBOSE`, so the non-verbose path allocates
/// nothing), then returns [`CurlError::CouldntResolveProxy`] when `is_proxy` is
/// set (curl's host→proxy error mapping) or [`CurlError::CouldntResolveHost`]
/// otherwise.
///
/// # Errors
///
/// Returns [`CurlError::CouldntResolveProxy`] (when `is_proxy`) or
/// [`CurlError::CouldntResolveHost`] when the host cannot be resolved to any
/// address of the requested family.
pub async fn resolve_verbose(
    host: &str,
    port: u16,
    ip_version: IpVersion,
    verbose: bool,
    is_proxy: bool,
) -> Result<ResolvedAddrs> {
    let addrs = query_os_resolver(host, port, ip_version).await;
    if addrs.is_empty() {
        // Mirror curl's verbose getaddrinfo-failure line (hostip6.c:109).
        crate::infof!(verbose, "getaddrinfo(3) failed for {host}:{port}");
        return Err(if is_proxy {
            CurlError::CouldntResolveProxy
        } else {
            CurlError::CouldntResolveHost
        });
    }
    Ok(addrs)
}

/// Resolves `host:port` like [`resolve`], bounded by a wall-clock deadline.
///
/// This is the in-backend analog of curl's `Curl_resolv_timeout`
/// (`crate::dns::resolve_timeout` applies the same policy around the whole
/// resolve flow). The `timeout_ms` argument follows curl's sentinels:
///
/// * `timeout_ms < 0` — an already-expired deadline: returns
///   [`CurlError::OperationTimedout`] immediately without resolving.
/// * `timeout_ms == 0` — no deadline; behaves exactly like [`resolve`].
/// * `timeout_ms > 0` — the resolve is bounded by `timeout_ms`; exceeding it
///   yields [`CurlError::OperationTimedout`].
///
/// # Errors
///
/// [`CurlError::OperationTimedout`] on expiry, otherwise as [`resolve`].
pub async fn resolve_with_timeout(
    host: &str,
    port: u16,
    ip_version: IpVersion,
    timeout_ms: i64,
) -> Result<ResolvedAddrs> {
    with_deadline(timeout_ms, resolve(host, port, ip_version)).await
}

/// Applies curl's resolve-timeout policy to an arbitrary resolve future.
///
/// Factored out so the timeout semantics are defined once and can be unit
/// tested deterministically against any future. See [`resolve_with_timeout`]
/// for the meaning of `timeout_ms`.
async fn with_deadline<F>(timeout_ms: i64, fut: F) -> Result<ResolvedAddrs>
where
    F: Future<Output = Result<ResolvedAddrs>>,
{
    if timeout_ms < 0 {
        return Err(CurlError::OperationTimedout);
    }
    if timeout_ms == 0 {
        return fut.await;
    }
    // `timeout_ms` is strictly positive here, so the cast cannot lose meaning.
    match tokio::time::timeout(Duration::from_millis(timeout_ms as u64), fut).await {
        Ok(result) => result,
        Err(_elapsed) => Err(CurlError::OperationTimedout),
    }
}

// ===========================================================================
// Tests
//
// Every test below is hermetic and deterministic: it relies only on numeric IP
// literals, the loopback `localhost` entry (resolved from `/etc/hosts` without
// network access), the RFC 6761 `.invalid` TLD (which is guaranteed never to
// resolve, returning EAI_NONAME immediately and offline), and Tokio's timer.
// No test reaches the public Internet, matching the build/CI environment.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Builds an IPv4 `SocketAddr` from octets and a port.
    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    /// Builds the IPv6 loopback (`::1`) `SocketAddr` for a port.
    fn v6_loopback(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)
    }

    // ---- filter_family: pure, synthetic, no resolution ---------------------

    #[test]
    fn filter_family_v4_keeps_only_ipv4() {
        let input = vec![v4(1, 1, 1, 1, 80), v6_loopback(80), v4(2, 2, 2, 2, 80)];
        let out = filter_family(input, IpVersion::V4);
        assert_eq!(out.addrs, vec![v4(1, 1, 1, 1, 80), v4(2, 2, 2, 2, 80)]);
    }

    #[cfg(feature = "ipv6")]
    #[test]
    fn filter_family_v6_keeps_only_ipv6() {
        let input = vec![v4(1, 1, 1, 1, 80), v6_loopback(80)];
        let out = filter_family(input, IpVersion::V6);
        assert_eq!(out.addrs, vec![v6_loopback(80)]);
    }

    #[cfg(feature = "ipv6")]
    #[test]
    fn filter_family_any_keeps_both_when_ipv6_built_in() {
        let input = vec![v4(1, 1, 1, 1, 80), v6_loopback(80)];
        let out = filter_family(input.clone(), IpVersion::Any);
        assert_eq!(out.addrs, input);
    }

    #[cfg(not(feature = "ipv6"))]
    #[test]
    fn filter_family_any_drops_ipv6_without_feature() {
        // Mirrors curl's `#else` branch in asyn-thrdd.c: no IPv6 build => PF_INET.
        let input = vec![v4(1, 1, 1, 1, 80), v6_loopback(80)];
        let out = filter_family(input, IpVersion::Any);
        assert_eq!(out.addrs, vec![v4(1, 1, 1, 1, 80)]);
    }

    #[test]
    fn filter_family_dedups_preserving_order() {
        let input = vec![v4(1, 1, 1, 1, 80), v4(1, 1, 1, 1, 80), v4(2, 2, 2, 2, 80)];
        let out = filter_family(input, IpVersion::V4);
        assert_eq!(out.addrs, vec![v4(1, 1, 1, 1, 80), v4(2, 2, 2, 2, 80)]);
    }

    // ---- numeric-literal short-circuit (no DNS query) ----------------------

    #[tokio::test]
    async fn resolve_ipv4_literal_short_circuits() {
        let got = resolve("127.0.0.1", 8080, IpVersion::Any).await.unwrap();
        assert_eq!(got.addrs, vec![v4(127, 0, 0, 1, 8080)]);
    }

    #[cfg(feature = "ipv6")]
    #[tokio::test]
    async fn resolve_ipv6_literal_short_circuits() {
        let got = resolve("::1", 443, IpVersion::Any).await.unwrap();
        assert_eq!(got.addrs, vec![v6_loopback(443)]);
    }

    #[tokio::test]
    async fn resolve_v4_literal_under_v6_request_fails() {
        // A V4 literal cannot satisfy a V6-only request (curl: getaddrinfo with
        // PF_INET6 + AI_NUMERICHOST fails) => CURLE_COULDNT_RESOLVE_HOST. Holds
        // with or without the `ipv6` feature.
        let err = resolve("127.0.0.1", 80, IpVersion::V6).await.unwrap_err();
        assert_eq!(err, CurlError::CouldntResolveHost);
    }

    #[cfg(not(feature = "ipv6"))]
    #[tokio::test]
    async fn resolve_ipv6_literal_without_feature_fails() {
        // Without IPv6 compiled in, an IPv6 literal yields no usable address.
        let err = resolve("::1", 443, IpVersion::Any).await.unwrap_err();
        assert_eq!(err, CurlError::CouldntResolveHost);
    }

    // ---- localhost via the OS resolver (offline, from /etc/hosts) -----------

    #[tokio::test]
    async fn resolve_localhost_returns_loopback() {
        let got = resolve("localhost", 80, IpVersion::Any).await.unwrap();
        assert!(!got.is_empty(), "localhost must resolve to loopback");
        assert!(got.addrs.iter().all(|a| a.ip().is_loopback()));
        assert!(got.addrs.iter().all(|a| a.port() == 80));
    }

    #[tokio::test]
    async fn resolve_localhost_v4_only_returns_ipv4_loopback() {
        let got = resolve("localhost", 80, IpVersion::V4).await.unwrap();
        assert!(!got.is_empty());
        assert!(got
            .addrs
            .iter()
            .all(|a| a.is_ipv4() && a.ip().is_loopback()));
    }

    #[cfg(feature = "ipv6")]
    #[tokio::test]
    async fn resolve_localhost_v6_only_returns_ipv6_loopback() {
        let got = resolve("localhost", 80, IpVersion::V6).await.unwrap();
        assert!(!got.is_empty());
        assert!(got
            .addrs
            .iter()
            .all(|a| a.is_ipv6() && a.ip().is_loopback()));
    }

    // ---- unresolvable name + proxy error mapping (offline EAI_NONAME) -------

    #[tokio::test]
    async fn resolve_unresolvable_name_is_couldnt_resolve_host() {
        let err = resolve("blitzy-no-such-host.invalid", 80, IpVersion::Any)
            .await
            .unwrap_err();
        assert_eq!(err, CurlError::CouldntResolveHost);
    }

    #[tokio::test]
    async fn resolve_verbose_proxy_failure_maps_to_proxy_error() {
        let err = resolve_verbose(
            "blitzy-no-such-host.invalid",
            80,
            IpVersion::Any,
            false,
            true,
        )
        .await
        .unwrap_err();
        assert_eq!(err, CurlError::CouldntResolveProxy);
    }

    #[tokio::test]
    async fn resolve_verbose_host_failure_maps_to_host_error() {
        let err = resolve_verbose(
            "blitzy-no-such-host.invalid",
            80,
            IpVersion::Any,
            true,
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(err, CurlError::CouldntResolveHost);
    }

    // ---- timeout policy ----------------------------------------------------

    #[tokio::test]
    async fn timeout_negative_is_immediate_timedout() {
        let err = resolve_with_timeout("127.0.0.1", 80, IpVersion::Any, -1)
            .await
            .unwrap_err();
        assert_eq!(err, CurlError::OperationTimedout);
    }

    #[tokio::test]
    async fn timeout_zero_runs_without_deadline() {
        let got = resolve_with_timeout("127.0.0.1", 80, IpVersion::Any, 0)
            .await
            .unwrap();
        assert_eq!(got.addrs, vec![v4(127, 0, 0, 1, 80)]);
    }

    #[tokio::test]
    async fn timeout_positive_allows_fast_literal() {
        let got = resolve_with_timeout("127.0.0.1", 80, IpVersion::Any, 5_000)
            .await
            .unwrap();
        assert_eq!(got.addrs, vec![v4(127, 0, 0, 1, 80)]);
    }

    #[tokio::test]
    async fn with_deadline_expiry_maps_to_timedout() {
        // A future that cannot finish within the deadline must time out. A 10 ms
        // deadline against a 1-hour sleep is deterministic (the deadline always
        // wins) and needs no `tokio` test-util feature.
        let slow = async {
            tokio::time::sleep(Duration::from_secs(3_600)).await;
            Ok::<ResolvedAddrs, CurlError>(ResolvedAddrs::new())
        };
        let err = with_deadline(10, slow).await.unwrap_err();
        assert_eq!(err, CurlError::OperationTimedout);
    }

    // ---- IPRESOLVE constant lockstep with crate::dns::IpVersion ------------

    #[test]
    fn ipresolve_constants_match_ip_version() {
        assert_eq!(CURL_IPRESOLVE_WHATEVER, IpVersion::Any.as_raw());
        assert_eq!(CURL_IPRESOLVE_V4, IpVersion::V4.as_raw());
        assert_eq!(CURL_IPRESOLVE_V6, IpVersion::V6.as_raw());
    }
}
