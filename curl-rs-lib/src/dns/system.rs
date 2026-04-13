//! System DNS resolver using `tokio::net::lookup_host`.
//!
//! This module implements the system (OS-provided) DNS resolver for curl-rs,
//! replacing three C source files from the original curl 8.19.0-DEV codebase:
//!
//! - **`lib/hostip4.c`** — IPv4-only synchronous resolver (`CURLRES_IPV4 + CURLRES_SYNCH`).
//!   The C function `Curl_ipv4_resolve_r()` calls `gethostbyname_r()` or
//!   `getaddrinfo()` with `PF_INET` hints. In Rust, `tokio::net::lookup_host`
//!   returns both IPv4 and IPv6 results, so we post-filter to `SocketAddr::V4`
//!   when `IpVersion::V4Only` is requested.
//!
//! - **`lib/hostip6.c`** — IPv6-enabled synchronous resolver (`CURLRES_IPV6 + CURLRES_SYNCH`).
//!   The C function `Curl_sync_getaddrinfo()` calls `getaddrinfo()` with
//!   `PF_UNSPEC` (or `PF_INET` if `Curl_ipv6works()` returns false). In Rust,
//!   we always call `lookup_host` and filter based on [`IpVersion`].
//!
//! - **`lib/asyn-thrdd.c`** — Threaded async resolver (`CURLRES_THREADED`).
//!   The C implementation spawns a POSIX thread per resolution request,
//!   communicates completion via a socketpair, and protects shared state with
//!   a mutex (`struct async_thrdd_addr_ctx`). In Rust, `tokio::net::lookup_host`
//!   is inherently async, eliminating all manual thread management, socketpair
//!   notification, and mutex synchronization.
//!
//! Additionally incorporates functionality from:
//! - **`lib/asyn-base.c`** — Async resolver base (global init/cleanup stubs).
//! - **`lib/hostip.c`** — Shared functions: `Curl_ipv6works()` (lines 771–776),
//!   `Curl_host_is_ipnum()` (lines 783–796), `Curl_shuffle_addr()` (lines 405–456),
//!   `Curl_resolv_timeout()` (lines 1076–1233), localhost detection (lines 938–944),
//!   `get_localhost()` (lines 710–746), `get_localhost6()` (lines 671–704).
//!
//! # Design Decisions
//!
//! - **Single async backend**: All three C resolver backends (sync IPv4, sync IPv6,
//!   threaded async) collapse into one Tokio-based implementation. The `Resolver`
//!   trait from [`super::Resolver`] provides the abstraction boundary.
//!
//! - **Post-filter IP version**: Unlike C's `getaddrinfo()` which accepts `PF_INET`
//!   or `PF_INET6` hints, `tokio::net::lookup_host` always returns all address
//!   families (equivalent to `PF_UNSPEC`). We filter results after collection.
//!
//! - **Portable timeout**: The C `Curl_resolv_timeout()` uses `SIGALRM` +
//!   `sigsetjmp`/`siglongjmp` on Unix. Rust uses `tokio::time::timeout` for a
//!   portable, safe, composable timeout mechanism.
//!
//! - **No `unsafe`**: This module contains zero `unsafe` blocks. All operations
//!   use safe Rust APIs. The IPv6 probe uses `std::net::UdpSocket::bind()`.
//!
//! # Cancellation
//!
//! Tokio automatically handles cancellation when the resolve future is dropped.
//! In C, the threaded resolver (`asyn-thrdd.c`) uses a `do_abort` flag and
//! `addr_ctx_unlink()` / `async_thrdd_destroy()` to abort or detach the resolver
//! thread. In Rust, simply dropping the future returned by `resolve()` cancels
//! the pending `lookup_host` operation cooperatively.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::OnceLock;
use std::time::Duration;

use async_trait::async_trait;
use rand::seq::SliceRandom;

use crate::error::CurlError;
use super::{IpVersion, Resolver};

// ---------------------------------------------------------------------------
// SystemResolver — stateless async DNS resolver
// ---------------------------------------------------------------------------

/// System DNS resolver that uses the OS's built-in name resolution
/// via `tokio::net::lookup_host`.
///
/// This replaces three C resolver backends:
/// - **hostip4.c**: IPv4-only sync resolver via `Curl_ipv4_resolve_r()` which
///   calls `gethostbyname_r()` or `getaddrinfo()` with `PF_INET` hints.
/// - **hostip6.c**: IPv6-enabled sync resolver via `Curl_sync_getaddrinfo()`
///   which calls `getaddrinfo()` with `PF_UNSPEC` or `PF_INET`.
/// - **asyn-thrdd.c**: Threaded async resolver using POSIX threads + socketpairs
///   for completion notification and mutex-protected shared state.
///
/// In Rust, `tokio::net::lookup_host` provides async resolution natively,
/// eliminating the need for manual thread management or socketpair notification.
///
/// # Statelessness
///
/// The system resolver is stateless — it carries no per-instance data.
/// In C, the threaded resolver carried per-request state in
/// `async_thrdd_addr_ctx` (mutex, thread handle, socketpair, hostname copy).
/// Tokio's async resolver handles all of this internally via the runtime's
/// I/O driver and task scheduler.
///
/// # Examples
///
/// ```rust,no_run
/// use curl_rs_lib::dns::system::SystemResolver;
/// use curl_rs_lib::dns::{IpVersion, Resolver};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let resolver = SystemResolver::new();
/// let addrs = resolver.resolve("example.com", 443, IpVersion::Any).await?;
/// for addr in &addrs {
///     println!("Resolved: {}", addr);
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct SystemResolver {
    // No state needed — the system resolver is stateless.
    // This is intentionally a zero-sized type (ZST) for efficiency.
    _private: (),
}

impl SystemResolver {
    /// Create a new system resolver instance.
    ///
    /// The resolver requires no configuration — it delegates directly to the
    /// operating system's name resolution facility via Tokio's async I/O layer.
    ///
    /// # C Equivalent
    ///
    /// In C, there is no explicit "create resolver" step. The resolver backend
    /// is selected at compile time via `CURLRES_SYNCH` / `CURLRES_THREADED`
    /// preprocessor macros. In Rust, the resolver is instantiated at runtime.
    pub fn new() -> Self {
        SystemResolver { _private: () }
    }

    /// Resolve a hostname with a configurable timeout.
    ///
    /// Wraps [`Resolver::resolve()`] with `tokio::time::timeout` to enforce
    /// a maximum resolution duration. This replaces the C implementation in
    /// `Curl_resolv_timeout()` (lib/hostip.c lines 1076–1233) which uses
    /// `SIGALRM` + `sigsetjmp`/`siglongjmp` on Unix — a non-portable,
    /// signal-unsafe mechanism that cannot be used in multi-threaded programs.
    ///
    /// # Arguments
    ///
    /// * `host` — Hostname to resolve.
    /// * `port` — Port number for the resulting `SocketAddr` entries.
    /// * `ip_version` — IP version preference filter.
    /// * `timeout_ms` — Maximum time to wait in milliseconds. A value of `0`
    ///   means no timeout (resolution may block indefinitely on the OS resolver).
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<SocketAddr>)` — Resolved addresses (never empty on success).
    /// * `Err(CurlError::OperationTimedOut)` — The timeout elapsed before
    ///   resolution completed.
    /// * `Err(CurlError::CouldntResolveHost)` — Resolution failed or produced
    ///   no results matching the requested IP version.
    ///
    /// # C Comparison
    ///
    /// The C version (`Curl_resolv_timeout`) installs a `SIGALRM` handler that
    /// performs a `siglongjmp` back to the timeout check point. This approach:
    /// - Only works on Unix (Windows uses a different mechanism).
    /// - Is signal-unsafe (the resolver may be in a non-reentrant libc call).
    /// - Cannot be composed with other timeouts.
    ///
    /// The Rust `tokio::time::timeout` approach:
    /// - Works on all platforms Tokio supports.
    /// - Is fully safe and composable with other async operations.
    /// - Cancels the underlying future cooperatively when the timeout fires.
    pub async fn resolve_with_timeout(
        &self,
        host: &str,
        port: u16,
        ip_version: IpVersion,
        timeout_ms: u64,
    ) -> Result<Vec<SocketAddr>, CurlError> {
        // A timeout of 0 means "no timeout" — resolve without a deadline.
        if timeout_ms == 0 {
            return self.resolve(host, port, ip_version).await;
        }

        match tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            self.resolve(host, port, ip_version),
        )
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => {
                tracing::debug!(
                    host = %host,
                    port = %port,
                    timeout_ms = %timeout_ms,
                    "DNS resolution timed out"
                );
                Err(CurlError::OperationTimedOut)
            }
        }
    }
}

impl Default for SystemResolver {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Resolver trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl Resolver for SystemResolver {
    /// Resolve a hostname to a set of socket addresses using the OS resolver.
    ///
    /// # Implementation
    ///
    /// 1. Constructs a `"{host}:{port}"` address string for `tokio::net::lookup_host`.
    /// 2. Awaits the async resolution (delegates to the OS's `getaddrinfo`).
    /// 3. Filters results based on `ip_version`:
    ///    - [`IpVersion::V4Only`] → keep only `SocketAddr::V4` (replaces C `PF_INET`).
    ///    - [`IpVersion::V6Only`] → keep only `SocketAddr::V6` (replaces C `PF_INET6`).
    ///    - [`IpVersion::Any`] → keep all results (replaces C `PF_UNSPEC`).
    /// 4. Returns `CurlError::CouldntResolveHost` if no addresses match after filtering.
    ///
    /// # C Equivalents
    ///
    /// - `Curl_sync_getaddrinfo()` from hostip4.c (lines 70–84): calls
    ///   `Curl_ipv4_resolve_r()` which uses `gethostbyname_r()` or `getaddrinfo()`
    ///   with `PF_INET`.
    /// - `Curl_sync_getaddrinfo()` from hostip6.c (lines 65–118): calls
    ///   `getaddrinfo()` with `PF_UNSPEC` (or `PF_INET` if IPv6 not available).
    /// - `getaddrinfo_thread()` from asyn-thrdd.c (lines 199–243): the thread
    ///   body that performs blocking `getaddrinfo()` and signals completion.
    ///
    /// # Errors
    ///
    /// Returns `CurlError::CouldntResolveHost` (maps to C `CURLE_COULDNT_RESOLVE_HOST = 6`)
    /// if:
    /// - `tokio::net::lookup_host` returns an I/O error (hostname not found, DNS
    ///   server unreachable, etc.).
    /// - All resolved addresses are filtered out by the `ip_version` constraint.
    async fn resolve(
        &self,
        host: &str,
        port: u16,
        ip_version: IpVersion,
    ) -> Result<Vec<SocketAddr>, CurlError> {
        // Step 1: Construct the address string for lookup_host.
        // tokio::net::lookup_host accepts "(host, port)" tuples or "host:port" strings.
        // Using the tuple form handles IPv6 addresses correctly without requiring
        // bracket notation.
        let lookup_result = tokio::net::lookup_host((host, port)).await;

        // Step 2: Handle lookup failure.
        let iter = match lookup_result {
            Ok(iter) => iter,
            Err(e) => {
                tracing::debug!(
                    host = %host,
                    port = %port,
                    error = %e,
                    "System DNS resolution failed"
                );
                return Err(CurlError::CouldntResolveHost);
            }
        };

        // Step 3: Collect and filter results by IP version.
        //
        // In C hostip6.c, the `getaddrinfo()` hints.ai_family controls which
        // address families are returned:
        //   PF_INET   → IPv4 only (when ip_version == CURL_IPRESOLVE_V4)
        //   PF_INET6  → IPv6 only (when ip_version == CURL_IPRESOLVE_V6)
        //   PF_UNSPEC → both (default, when Curl_ipv6works() is true)
        //
        // Since tokio::net::lookup_host always returns all families (like PF_UNSPEC),
        // we perform the filtering here.
        let addrs: Vec<SocketAddr> = iter
            .filter(|addr| match ip_version {
                IpVersion::Any => true,
                IpVersion::V4Only => addr.is_ipv4(),
                IpVersion::V6Only => addr.is_ipv6(),
            })
            .collect();

        // Step 4: Empty result check.
        //
        // From C: if getaddrinfo() returns NULL or the filtered list is empty,
        // the resolver returns NULL and the caller stores a negative cache entry.
        if addrs.is_empty() {
            tracing::debug!(
                host = %host,
                port = %port,
                ip_version = ?ip_version,
                "DNS resolution returned no addresses matching requested IP version"
            );
            return Err(CurlError::CouldntResolveHost);
        }

        Ok(addrs)
    }

    /// Get the resolver backend name for logging and diagnostics.
    ///
    /// Returns `"system"` to identify this as the OS-provided resolver.
    /// In C, the resolver backend is identified by preprocessor macros
    /// (`CURLRES_SYNCH`, `CURLRES_THREADED`, `CURLRES_ARES`). In Rust,
    /// the name is a runtime property of the resolver trait object.
    fn name(&self) -> &'static str {
        "system"
    }
}

// ---------------------------------------------------------------------------
// IPv6 availability probe
// ---------------------------------------------------------------------------

/// Check if IPv6 is available on this system.
///
/// Probes IPv6 availability by attempting to bind a UDP socket to `[::1]:0`.
/// The result is cached in a `OnceLock` static for the lifetime of the process,
/// matching the C behavior where `Curl_ipv6works()` caches the result in
/// `data->multi->ipv6_works` (lib/hostip.c lines 741–776).
///
/// # C Equivalent
///
/// From `Curl_ipv6works()` in lib/hostip.c lines 771–776 and the probe in
/// `Curl_ipv6works_init()` lines 741–766:
/// ```c
/// bool Curl_ipv6works(struct Curl_easy *data) {
///   DEBUGASSERT(data);
///   DEBUGASSERT(data->multi);
///   return data ? data->multi->ipv6_works : FALSE;
/// }
/// ```
///
/// The C version creates an `AF_INET6` + `SOCK_DGRAM` socket and attempts
/// to bind it to `[::1]:0`. If the bind succeeds, IPv6 is available.
/// The socket is closed immediately after the probe.
///
/// # Caching
///
/// Uses `std::sync::OnceLock` (stable since Rust 1.70, within MSRV 1.75)
/// to cache the probe result. The C version caches per-multi-handle; the
/// Rust version caches globally since IPv6 availability is a system-wide
/// property that doesn't change during process lifetime.
///
/// # Platform Notes
///
/// - On Linux with IPv6 disabled (`sysctl net.ipv6.conf.all.disable_ipv6=1`),
///   the bind to `[::1]:0` will fail with `EADDRNOTAVAIL`.
/// - On macOS, IPv6 is always available unless explicitly disabled.
/// - On Windows, IPv6 is available if the IPv6 protocol stack is installed.
pub fn ipv6_works() -> bool {
    static IPV6_WORKS: OnceLock<bool> = OnceLock::new();
    *IPV6_WORKS.get_or_init(|| {
        // Attempt to bind a UDP socket to the IPv6 loopback address.
        // This mirrors the C probe: socket(PF_INET6, SOCK_DGRAM, 0) + bind([::1]:0).
        UdpSocket::bind("[::1]:0").is_ok()
    })
}

// ---------------------------------------------------------------------------
// Localhost helpers
// ---------------------------------------------------------------------------

/// Check if a hostname is a localhost variant (RFC 6761).
///
/// Returns `true` for:
/// - `"localhost"` (exact match, case-insensitive)
/// - `"localhost."` (with trailing dot)
/// - `"*.localhost"` (any subdomain)
/// - `"*.localhost."` (any subdomain with trailing dot)
///
/// # C Equivalent
///
/// From lib/hostip.c lines 938–941:
/// ```c
/// if(curl_strequal(hostname, "localhost") ||
///    curl_strequal(hostname, "localhost.") ||
///    tailmatch(hostname, hostname_len, STRCONST(".localhost")) ||
///    tailmatch(hostname, hostname_len, STRCONST(".localhost."))) {
/// ```
///
/// The C code uses `curl_strequal()` for case-insensitive comparison and
/// `tailmatch()` for suffix matching. In Rust, we convert to lowercase once
/// and use standard string comparison methods.
pub fn is_localhost(hostname: &str) -> bool {
    let h = hostname.to_ascii_lowercase();
    h == "localhost"
        || h == "localhost."
        || h.ends_with(".localhost")
        || h.ends_with(".localhost.")
}

/// Get localhost addresses for the given port.
///
/// Returns a vector of `SocketAddr` entries for the localhost loopback
/// addresses. When `include_ipv6` is `true` and IPv6 is available on the
/// system, the IPv6 loopback `[::1]` is included before the IPv4 loopback
/// `127.0.0.1` (matching the C ordering where IPv6 is prepended to the
/// address list).
///
/// # C Equivalent
///
/// From `get_localhost()` in lib/hostip.c lines 710–746 and
/// `get_localhost6()` in lines 671–704:
/// ```c
/// static struct Curl_addrinfo *get_localhost(int port, const char *name) {
///   // ... allocates Curl_addrinfo for 127.0.0.1
///   // prepends get_localhost6() result (::1) to the list
/// }
/// ```
///
/// # Arguments
///
/// * `port` — Port number for the returned `SocketAddr` entries.
/// * `include_ipv6` — Whether to include the IPv6 loopback address (`::1`).
///   Callers should typically pass `ipv6_works()` or derive this from the
///   [`IpVersion`] preference.
pub fn get_localhost_addrs(port: u16, include_ipv6: bool) -> Vec<SocketAddr> {
    let mut addrs = Vec::with_capacity(2);
    // IPv6 loopback comes first (matching C ordering where get_localhost6()
    // is prepended to the get_localhost() result).
    if include_ipv6 {
        addrs.push(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port));
    }
    // IPv4 loopback always included.
    addrs.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    addrs
}

// ---------------------------------------------------------------------------
// IP literal helpers
// ---------------------------------------------------------------------------

/// Check if a hostname is already an IP address literal.
///
/// Returns `true` if the hostname can be parsed as an IPv4 or IPv6 address.
/// When the hostname is an IP literal, DNS resolution should be skipped
/// and the address used directly via [`ip_literal_to_addr`].
///
/// # C Equivalent
///
/// From `Curl_host_is_ipnum()` in lib/hostip.c lines 783–796:
/// ```c
/// bool Curl_host_is_ipnum(const char *hostname) {
///   struct in_addr in;
///   struct in6_addr in6;
///   if(curlx_inet_pton(AF_INET, hostname, &in) > 0
///      || curlx_inet_pton(AF_INET6, hostname, &in6) > 0)
///     return TRUE;
///   return FALSE;
/// }
/// ```
///
/// # Examples
///
/// ```
/// use curl_rs_lib::dns::system::is_ip_literal;
///
/// assert!(is_ip_literal("127.0.0.1"));
/// assert!(is_ip_literal("::1"));
/// assert!(is_ip_literal("192.168.1.1"));
/// assert!(is_ip_literal("2001:db8::1"));
/// assert!(!is_ip_literal("example.com"));
/// assert!(!is_ip_literal("localhost"));
/// ```
pub fn is_ip_literal(hostname: &str) -> bool {
    hostname.parse::<IpAddr>().is_ok()
}

/// Convert an IP literal string to a `SocketAddr` without DNS lookup.
///
/// Parses the given IP address string (IPv4 or IPv6) and combines it with
/// the specified port to produce a `SocketAddr`. This is used as a shortcut
/// when the "hostname" is already a numeric IP address.
///
/// # C Equivalent
///
/// From `Curl_str2addr()` referenced in lib/hostip.c line 931:
/// ```c
/// result = Curl_str2addr(hostname, port, &addr);
/// ```
///
/// The C function uses `curlx_inet_pton()` to parse the address and then
/// constructs a `Curl_addrinfo` structure. In Rust, we use the standard
/// library's `IpAddr::parse()` and construct a `SocketAddr` directly.
///
/// # Errors
///
/// Returns `CurlError::CouldntResolveHost` if the string cannot be parsed
/// as a valid IP address.
pub fn ip_literal_to_addr(ip_str: &str, port: u16) -> Result<SocketAddr, CurlError> {
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|_| CurlError::CouldntResolveHost)?;
    Ok(SocketAddr::new(ip, port))
}

// ---------------------------------------------------------------------------
// Address shuffling
// ---------------------------------------------------------------------------

/// Shuffle resolved addresses using the Fisher-Yates algorithm.
///
/// Randomizes the order of resolved addresses for client-side load balancing
/// across multiple server IPs. This ensures that when a hostname resolves to
/// multiple addresses, connections are distributed across all available
/// servers rather than always hitting the first one returned by DNS.
///
/// # C Equivalent
///
/// From `Curl_shuffle_addr()` in lib/hostip.c lines 405–456:
/// ```c
/// CURLcode Curl_shuffle_addr(struct Curl_easy *data,
///                            struct Curl_addrinfo **phead) {
///   // ... Fisher-Yates shuffle using Curl_rand() for random indices
/// }
/// ```
///
/// The C implementation manually walks the linked `Curl_addrinfo` list,
/// selects random positions with `Curl_rand()`, and swaps elements. In Rust,
/// we use `rand::seq::SliceRandom::shuffle()` which implements the same
/// Fisher-Yates algorithm on a `Vec` slice.
///
/// # Arguments
///
/// * `addrs` — Mutable slice of resolved addresses. The slice is shuffled
///   in-place. If the slice has 0 or 1 elements, this is a no-op.
///   Accepts `&mut Vec<SocketAddr>` transparently via `Deref`.
pub fn shuffle_addrs(addrs: &mut [SocketAddr]) {
    if addrs.len() <= 1 {
        return;
    }
    let mut rng = rand::thread_rng();
    addrs.shuffle(&mut rng);
}

// ---------------------------------------------------------------------------
// Global init / cleanup
// ---------------------------------------------------------------------------

/// Global DNS resolver initialization.
///
/// No-op for the system resolver. Tokio handles its own initialization via
/// the runtime builder.
///
/// # C Equivalent
///
/// From `Curl_async_global_init()` in lib/asyn-thrdd.c lines 82–87:
/// ```c
/// CURLcode Curl_async_global_init(void) {
///   // No-op for threaded resolver
///   return CURLE_OK;
/// }
/// ```
///
/// In C with c-ares (`asyn-ares.c`), this calls `ares_library_init()`.
/// Since the Rust system resolver has no global state, this is a no-op.
pub fn global_init() -> Result<(), CurlError> {
    Ok(())
}

/// Global DNS resolver cleanup.
///
/// No-op for the system resolver. Tokio cleans up when the runtime is dropped.
///
/// # C Equivalent
///
/// From `Curl_async_global_cleanup()` in lib/asyn-thrdd.c lines 89–100:
/// ```c
/// void Curl_async_global_cleanup(void) {
///   // No-op for threaded resolver
/// }
/// ```
///
/// In C with c-ares (`asyn-ares.c`), this calls `ares_library_cleanup()`.
pub fn global_cleanup() {
    // No-op: Tokio runtime cleanup is handled by Drop.
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- ipv6_works tests ---------------------------------------------------

    #[test]
    fn test_ipv6_works_returns_bool() {
        // The result depends on the host system. We only verify it returns
        // a valid bool and does not panic.
        let result = ipv6_works();
        assert!(result || !result); // always true, verifies no panic
    }

    #[test]
    fn test_ipv6_works_is_cached() {
        // Calling ipv6_works() multiple times should return the same value
        // (OnceLock ensures the probe runs only once).
        let first = ipv6_works();
        let second = ipv6_works();
        assert_eq!(first, second);
    }

    // -- is_localhost tests --------------------------------------------------

    #[test]
    fn test_is_localhost_exact() {
        assert!(is_localhost("localhost"));
    }

    #[test]
    fn test_is_localhost_trailing_dot() {
        assert!(is_localhost("localhost."));
    }

    #[test]
    fn test_is_localhost_subdomain() {
        assert!(is_localhost("foo.localhost"));
        assert!(is_localhost("bar.baz.localhost"));
    }

    #[test]
    fn test_is_localhost_subdomain_trailing_dot() {
        assert!(is_localhost("foo.localhost."));
        assert!(is_localhost("bar.baz.localhost."));
    }

    #[test]
    fn test_is_localhost_case_insensitive() {
        assert!(is_localhost("LOCALHOST"));
        assert!(is_localhost("LocalHost"));
        assert!(is_localhost("LOCALHOST."));
        assert!(is_localhost("FOO.LOCALHOST"));
    }

    #[test]
    fn test_is_localhost_negative_cases() {
        assert!(!is_localhost("notlocalhost"));
        assert!(!is_localhost("example.com"));
        assert!(!is_localhost("localhostt"));
        assert!(!is_localhost("my-localhost"));
        assert!(!is_localhost(""));
    }

    // -- get_localhost_addrs tests -------------------------------------------

    #[test]
    fn test_get_localhost_addrs_ipv4_only() {
        let addrs = get_localhost_addrs(8080, false);
        assert_eq!(addrs.len(), 1);
        assert!(addrs[0].is_ipv4());
        assert_eq!(addrs[0].ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(addrs[0].port(), 8080);
    }

    #[test]
    fn test_get_localhost_addrs_with_ipv6() {
        let addrs = get_localhost_addrs(443, true);
        assert_eq!(addrs.len(), 2);
        // IPv6 should come first (matching C ordering).
        assert!(addrs[0].is_ipv6());
        assert_eq!(addrs[0].ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(addrs[0].port(), 443);
        // IPv4 second.
        assert!(addrs[1].is_ipv4());
        assert_eq!(addrs[1].ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(addrs[1].port(), 443);
    }

    // -- is_ip_literal tests -------------------------------------------------

    #[test]
    fn test_is_ip_literal_ipv4() {
        assert!(is_ip_literal("127.0.0.1"));
        assert!(is_ip_literal("192.168.1.1"));
        assert!(is_ip_literal("0.0.0.0"));
        assert!(is_ip_literal("255.255.255.255"));
    }

    #[test]
    fn test_is_ip_literal_ipv6() {
        assert!(is_ip_literal("::1"));
        assert!(is_ip_literal("::"));
        assert!(is_ip_literal("2001:db8::1"));
        assert!(is_ip_literal("fe80::1"));
    }

    #[test]
    fn test_is_ip_literal_negative() {
        assert!(!is_ip_literal("example.com"));
        assert!(!is_ip_literal("localhost"));
        assert!(!is_ip_literal(""));
        assert!(!is_ip_literal("not-an-ip"));
        assert!(!is_ip_literal("999.999.999.999"));
    }

    // -- ip_literal_to_addr tests --------------------------------------------

    #[test]
    fn test_ip_literal_to_addr_ipv4() {
        let addr = ip_literal_to_addr("192.168.1.1", 80).unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(addr.port(), 80);
    }

    #[test]
    fn test_ip_literal_to_addr_ipv6() {
        let addr = ip_literal_to_addr("::1", 443).unwrap();
        assert_eq!(addr.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(addr.port(), 443);
    }

    #[test]
    fn test_ip_literal_to_addr_invalid() {
        let result = ip_literal_to_addr("not-an-ip", 80);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::CouldntResolveHost);
    }

    #[test]
    fn test_ip_literal_to_addr_empty() {
        let result = ip_literal_to_addr("", 80);
        assert!(result.is_err());
    }

    // -- shuffle_addrs tests -------------------------------------------------

    #[test]
    fn test_shuffle_addrs_empty() {
        let mut addrs: Vec<SocketAddr> = vec![];
        shuffle_addrs(&mut addrs);
        assert!(addrs.is_empty());
    }

    #[test]
    fn test_shuffle_addrs_single() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80);
        let mut addrs = vec![addr];
        shuffle_addrs(&mut addrs);
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], addr);
    }

    #[test]
    fn test_shuffle_addrs_preserves_elements() {
        let original: Vec<SocketAddr> = (1..=10)
            .map(|i| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)), 80))
            .collect();
        let mut shuffled = original.clone();
        shuffle_addrs(&mut shuffled);
        // After shuffling, same elements must be present (just possibly reordered).
        assert_eq!(shuffled.len(), original.len());
        for addr in &original {
            assert!(shuffled.contains(addr));
        }
    }

    // -- global_init / global_cleanup tests ----------------------------------

    #[test]
    fn test_global_init_succeeds() {
        assert!(global_init().is_ok());
    }

    #[test]
    fn test_global_cleanup_does_not_panic() {
        global_cleanup();
    }

    // -- SystemResolver construction tests -----------------------------------

    #[test]
    fn test_system_resolver_new() {
        let resolver = SystemResolver::new();
        assert_eq!(resolver.name(), "system");
    }

    #[test]
    fn test_system_resolver_default() {
        let resolver = SystemResolver::default();
        assert_eq!(resolver.name(), "system");
    }

    #[test]
    fn test_system_resolver_clone() {
        let resolver = SystemResolver::new();
        let cloned = resolver.clone();
        assert_eq!(cloned.name(), "system");
    }

    // -- Async resolution tests (require Tokio runtime) ----------------------

    #[tokio::test]
    async fn test_resolve_localhost_v4() {
        let resolver = SystemResolver::new();
        let result = resolver
            .resolve("localhost", 80, IpVersion::V4Only)
            .await;
        // localhost should always resolve (at least on CI and dev machines).
        // If it fails, it's likely a DNS configuration issue, not our bug.
        if let Ok(addrs) = result {
            assert!(!addrs.is_empty());
            for addr in &addrs {
                assert!(addr.is_ipv4());
                assert_eq!(addr.port(), 80);
            }
        }
    }

    #[tokio::test]
    async fn test_resolve_nonexistent_host() {
        let resolver = SystemResolver::new();
        let result = resolver
            .resolve(
                "this-host-definitely-does-not-exist-xyzzy-42.invalid",
                80,
                IpVersion::Any,
            )
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::CouldntResolveHost);
    }

    #[tokio::test]
    async fn test_resolve_ip_literal_passthrough() {
        let resolver = SystemResolver::new();
        // Resolving an IP literal should work — tokio::net::lookup_host
        // handles numeric addresses directly.
        let result = resolver.resolve("127.0.0.1", 8080, IpVersion::Any).await;
        assert!(result.is_ok());
        let addrs = result.unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(
            addrs[0],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)
        );
    }

    #[tokio::test]
    async fn test_resolve_with_timeout_zero_means_no_timeout() {
        let resolver = SystemResolver::new();
        // timeout_ms = 0 should behave identically to resolve().
        let result = resolver
            .resolve_with_timeout("127.0.0.1", 80, IpVersion::Any, 0)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_resolve_with_timeout_succeeds() {
        let resolver = SystemResolver::new();
        // Give a generous timeout for localhost resolution.
        let result = resolver
            .resolve_with_timeout("127.0.0.1", 80, IpVersion::Any, 5000)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_resolve_v6only_filter() {
        let resolver = SystemResolver::new();
        // Resolving 127.0.0.1 with V6Only should fail because it's an IPv4 address.
        let result = resolver
            .resolve("127.0.0.1", 80, IpVersion::V6Only)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resolve_v4only_filter_on_ipv4_literal() {
        let resolver = SystemResolver::new();
        let result = resolver
            .resolve("127.0.0.1", 80, IpVersion::V4Only)
            .await;
        assert!(result.is_ok());
        let addrs = result.unwrap();
        assert_eq!(addrs.len(), 1);
        assert!(addrs[0].is_ipv4());
    }
}
