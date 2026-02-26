//! DNS resolution subsystem for curl-rs.
//!
//! This module provides async DNS resolution with:
//! - DNS cache with TTL, staleness detection, and negative caching
//! - System resolver via `tokio::net::lookup_host`
//! - DNS-over-HTTPS (DoH) via hyper
//! - Optional hickory-dns resolver (feature-gated)
//! - IPv4/IPv6 dual-stack with Happy Eyeballs support
//! - Localhost shortcircuiting (RFC 6761)
//! - IP literal passthrough
//!
//! Replaces C files: lib/hostip.c, lib/hostip.h, lib/asyn.h, lib/asyn-base.c

pub mod system;
pub mod doh;

#[cfg(feature = "hickory-dns")]
pub mod hickory;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::error::CurlError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum hostname + port cache key length.
/// From C: `#define MAX_HOSTCACHE_LEN (255 + 7)` in lib/hostip.c line 76.
/// 255 bytes for max FQDN + colon + up to 5-digit port number + NUL.
pub const MAX_HOSTCACHE_LEN: usize = 262;

/// Maximum number of DNS cache entries before aggressive pruning is triggered.
/// From C: `#define MAX_DNS_CACHE_SIZE 29999` in lib/hostip.c line 78.
pub const MAX_DNS_CACHE_SIZE: usize = 29999;

/// Default DNS cache timeout in seconds.
/// From C: `#define CURL_TIMEOUT_RESOLVE 300` in lib/hostip.h line 38.
pub const DEFAULT_DNS_CACHE_TIMEOUT_SECS: u64 = 300;

// ---------------------------------------------------------------------------
// IpVersion — IP version preference enum
// ---------------------------------------------------------------------------

/// IP version preference for DNS resolution.
///
/// Maps from C constants in `include/curl/curl.h`:
/// - `CURL_IPRESOLVE_WHATEVER` (0) → [`IpVersion::Any`]
/// - `CURL_IPRESOLVE_V4`       (1) → [`IpVersion::V4Only`]
/// - `CURL_IPRESOLVE_V6`       (2) → [`IpVersion::V6Only`]
///
/// Used in C: `Curl_resolv()`, `Curl_sync_getaddrinfo()`, `getaddrinfo` hints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpVersion {
    /// Resolve both IPv4 and IPv6 (PF_UNSPEC in C getaddrinfo hints).
    #[default]
    Any,
    /// Resolve IPv4 only (PF_INET in C getaddrinfo hints).
    V4Only,
    /// Resolve IPv6 only (PF_INET6 in C getaddrinfo hints).
    V6Only,
}

// ---------------------------------------------------------------------------
// HttpsRrInfo — HTTPS DNS Resource Record information
// ---------------------------------------------------------------------------

/// HTTPS DNS Resource Record information.
///
/// Replaces C `struct Curl_https_rrinfo` (lib/httpsrr.h lines 39-59).
/// Contains parsed fields from the HTTPS DNS resource record as defined
/// in RFC 9460 Section 14.3.2.
#[derive(Debug, Clone)]
pub struct HttpsRrInfo {
    /// SvcPriority — 0 means alias mode, >0 means service mode.
    pub priority: u16,
    /// Target name. If empty, same as the owner name.
    pub target: String,
    /// ALPN protocol identifiers (SvcParamKey=1).
    pub alpns: Vec<String>,
    /// Whether no-default-alpn is set (SvcParamKey=2).
    pub no_def_alpn: bool,
    /// Optional port hint (SvcParamKey=3). `None` means not present.
    pub port: Option<u16>,
    /// IPv4 address hints (SvcParamKey=4).
    pub ipv4_hints: Vec<Ipv4Addr>,
    /// IPv6 address hints (SvcParamKey=6).
    pub ipv6_hints: Vec<Ipv6Addr>,
    /// ECH configuration bytes (SvcParamKey=5). `None` means not present.
    pub ech_config: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// DnsEntry — a single cached DNS resolution result
// ---------------------------------------------------------------------------

/// A cached DNS entry containing resolved addresses.
///
/// Replaces C `struct Curl_dns_entry` (lib/hostip.h lines 56-69):
/// ```c
/// struct Curl_dns_entry {
///   struct Curl_addrinfo *addr;
///   struct Curl_https_rrinfo *hinfo;
///   struct curltime timestamp;
///   size_t refcount;
///   int hostport;
///   char hostname[1];
/// };
/// ```
///
/// In Rust, reference counting is handled by `Arc<DnsEntry>` and addresses
/// use `Vec<SocketAddr>` instead of a linked `Curl_addrinfo` list.
#[derive(Debug)]
pub struct DnsEntry {
    /// Resolved socket addresses (replaces C `Curl_addrinfo` linked list).
    pub addrs: Vec<SocketAddr>,

    /// HTTPS Resource Record info (replaces C `Curl_https_rrinfo` pointer).
    pub https_rr_info: Option<HttpsRrInfo>,

    /// Timestamp when entry was created (replaces C `time_t timestamp`).
    pub created_at: Instant,

    /// Port number for this entry (replaces C `int hostport`).
    pub port: u16,

    /// Hostname for this entry (replaces C `char hostname[]` flexible array member).
    pub hostname: String,

    /// Whether this is a permanent entry (from `CURLOPT_RESOLVE` without `+` prefix).
    /// Permanent entries have `timestamp == 0` in C, meaning they never go stale.
    pub permanent: bool,

    /// Whether this is a negative (failed) resolution entry.
    /// Negative entries have `addr == NULL` in C and age 2× faster in the cache
    /// (from C `dnscache_entry_is_stale()` at lib/hostip.c line 268).
    pub negative: bool,
}

impl DnsEntry {
    /// Check if this cache entry is stale.
    ///
    /// From C: `dnscache_entry_is_stale()` in lib/hostip.c lines 259-275.
    ///
    /// Key logic:
    /// - Permanent entries are **never** stale.
    /// - Negative entries age 2× faster (effective timeout = `timeout / 2`).
    /// - Compares elapsed time since creation against the cache timeout.
    pub fn is_stale(&self, timeout: Duration) -> bool {
        if self.permanent {
            return false;
        }
        let effective_timeout = if self.negative {
            // Negative entries age twice as fast — from C: `age *= 2;`
            // which is equivalent to halving the timeout threshold.
            timeout / 2
        } else {
            timeout
        };
        self.created_at.elapsed() > effective_timeout
    }
}

// ---------------------------------------------------------------------------
// DnsCache — thread-safe DNS resolution cache
// ---------------------------------------------------------------------------

/// DNS resolution cache.
///
/// Replaces C `struct Curl_dnscache` (lib/hostip.h lines 71-73):
/// ```c
/// struct Curl_dnscache {
///   struct Curl_hash entries;
/// };
/// ```
///
/// In Rust, uses `HashMap<String, Arc<DnsEntry>>` with a `Mutex` for thread
/// safety (replacing C `dnscache_lock`/`dnscache_unlock` pattern).
pub struct DnsCache {
    /// Cache entries keyed by `"{hostname}:{port}"` (lowercase hostname).
    entries: Mutex<HashMap<String, Arc<DnsEntry>>>,
    /// Cache entry timeout duration. A value of `Duration::MAX` means entries
    /// never expire (matching C `dns_cache_timeout_ms == -1`).
    timeout: Duration,
}

impl std::fmt::Debug for DnsCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self
            .entries
            .lock()
            .map(|e| e.len())
            .unwrap_or(0);
        f.debug_struct("DnsCache")
            .field("entry_count", &count)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl DnsCache {
    // -- construction -------------------------------------------------------

    /// Create a new DNS cache with the given entry timeout.
    ///
    /// From C: `Curl_dnscache_init()` (lib/hostip.c lines 1268-1272).
    pub fn new(timeout: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            timeout,
        }
    }

    // -- internal helpers ---------------------------------------------------

    /// Create a cache key from hostname and port.
    ///
    /// From C: `create_dnscache_id()` in lib/hostip.c lines 233-244.
    /// The key is `"{hostname_lower}:{port}"`.
    fn cache_key(hostname: &str, port: u16) -> String {
        let mut key = hostname.to_ascii_lowercase();
        // Enforce maximum key length matching C MAX_HOSTCACHE_LEN.
        if key.len() > MAX_HOSTCACHE_LEN - 7 {
            key.truncate(MAX_HOSTCACHE_LEN - 7);
        }
        use std::fmt::Write;
        let _ = write!(key, ":{}", port);
        key
    }

    /// Check whether an entry has an address matching the requested IP version.
    ///
    /// From C: `fetch_addr()` IP version filtering (lib/hostip.c lines 418-441).
    fn entry_matches_ip_version(entry: &DnsEntry, ip_version: IpVersion) -> bool {
        match ip_version {
            IpVersion::Any => true,
            IpVersion::V4Only => entry.addrs.iter().any(|a| a.is_ipv4()),
            IpVersion::V6Only => entry.addrs.iter().any(|a| a.is_ipv6()),
        }
    }

    // -- public API ---------------------------------------------------------

    /// Look up an entry in the cache.
    ///
    /// From C: `fetch_addr()` (lib/hostip.c lines 374-443) and
    /// `Curl_dnscache_get()` (lib/hostip.c lines 459-476).
    ///
    /// Key behaviours from C:
    /// 1. Exact-match lookup by `hostname:port` key.
    /// 2. If not found and `wildcard_resolve` is true, try `*:{port}` key.
    /// 3. Check staleness via `dnscache_entry_is_stale()`:
    ///    - Permanent entries never go stale.
    ///    - Negative entries age 2× faster.
    ///    - If stale → remove from cache and return `None`.
    /// 4. Filter by IP version: if `V4Only`, skip entries with only IPv6
    ///    addresses; vice-versa.
    pub fn get(
        &self,
        hostname: &str,
        port: u16,
        ip_version: IpVersion,
        wildcard_resolve: bool,
    ) -> Option<Arc<DnsEntry>> {
        let mut entries = self.entries.lock().ok()?;

        // Step 1 — exact-match lookup
        let key = Self::cache_key(hostname, port);
        let mut found_key = None;

        if let Some(entry) = entries.get(&key) {
            // Step 3 — staleness check
            if self.timeout != Duration::MAX && entry.is_stale(self.timeout) {
                tracing::debug!(
                    hostname = %hostname,
                    port = %port,
                    "DNS cache entry is stale, removing"
                );
                let k = key.clone();
                entries.remove(&k);
            } else {
                found_key = Some(key.clone());
            }
        }

        // Step 2 — wildcard fallback
        if found_key.is_none() && wildcard_resolve {
            let wc_key = Self::cache_key("*", port);
            if let Some(entry) = entries.get(&wc_key) {
                if self.timeout != Duration::MAX && entry.is_stale(self.timeout) {
                    entries.remove(&wc_key);
                } else {
                    found_key = Some(wc_key);
                }
            }
        }

        // Step 4 — IP version filtering
        if let Some(ref fk) = found_key {
            if let Some(entry) = entries.get(fk) {
                // Negative entries have no addresses to filter
                if entry.negative {
                    return Some(Arc::clone(entry));
                }
                if Self::entry_matches_ip_version(entry, ip_version) {
                    return Some(Arc::clone(entry));
                }
                // Cached entry does not have the needed address family — remove it
                tracing::debug!(
                    hostname = %hostname,
                    port = %port,
                    "DNS cache entry does not match requested IP version, removing"
                );
                let removed_key = fk.clone();
                entries.remove(&removed_key);
            }
        }

        None
    }

    /// Add an entry to the cache.
    ///
    /// From C: `Curl_dnscache_add()` (lib/hostip.c lines 645-667) and
    /// `dnscache_add_addr()` (lib/hostip.c lines 610-643).
    ///
    /// If an entry for the same key already exists, it is replaced.
    /// Returns an `Arc` handle to the cached entry.
    pub fn add(&self, entry: DnsEntry) -> Arc<DnsEntry> {
        let key = Self::cache_key(&entry.hostname, entry.port);
        let arc = Arc::new(entry);
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(key, Arc::clone(&arc));
        }
        arc
    }

    /// Remove stale entries from the cache.
    ///
    /// From C: `Curl_dnscache_prune()` / `dnscache_prune()`
    /// (lib/hostip.c lines 281-353).
    ///
    /// The C implementation iterates the hash table with a callback and also
    /// handles aggressive pruning when the cache exceeds `MAX_DNS_CACHE_SIZE`.
    pub fn prune(&self) {
        if self.timeout == Duration::MAX {
            // Infinite timeout — nothing to prune.
            return;
        }
        if let Ok(mut entries) = self.entries.lock() {
            let timeout = self.timeout;
            // First pass: remove stale entries.
            entries.retain(|_key, entry| !entry.is_stale(timeout));

            // Aggressive pruning if cache is too large — halve the age threshold
            // repeatedly until size is within bounds.
            // From C: lib/hostip.c lines 342-350.
            while entries.len() > MAX_DNS_CACHE_SIZE {
                // Find the oldest non-permanent entry to determine the new threshold.
                let oldest_age = entries
                    .values()
                    .filter(|e| !e.permanent)
                    .map(|e| e.created_at.elapsed())
                    .max()
                    .unwrap_or(Duration::ZERO);
                let shrink_timeout = oldest_age / 2;
                if shrink_timeout.is_zero() {
                    break;
                }
                entries.retain(|_key, entry| !entry.is_stale(shrink_timeout));
            }
        }
    }

    /// Clear all entries from the cache.
    ///
    /// From C: `Curl_dnscache_clear()` (lib/hostip.c lines 355-363).
    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
    }

    /// Destroy the cache — clears all entries.
    ///
    /// From C: `Curl_dnscache_destroy()` (lib/hostip.c lines 1274-1277).
    /// In Rust this is handled by `Drop`, but an explicit method is provided
    /// for compatibility with the C API pattern.
    pub fn destroy(&self) {
        self.clear();
    }
}

// ---------------------------------------------------------------------------
// Resolver trait — async DNS resolver abstraction
// ---------------------------------------------------------------------------

/// Trait for DNS resolver implementations.
///
/// This replaces the C compile-time resolver selection via preprocessor macros:
/// - `CURLRES_SYNCH`    → [`system::SystemResolver`]
/// - `CURLRES_THREADED` → [`system::SystemResolver`] (Tokio is inherently async)
/// - `CURLRES_ARES`     → `hickory::HickoryResolver` (feature-gated)
/// - `CURL_DISABLE_DOH` → [`doh::DohResolver`]
///
/// In Rust, resolver selection is performed at **runtime** via trait objects
/// (`&dyn Resolver`), replacing C's `#ifdef`-based compile-time dispatch.
#[async_trait]
pub trait Resolver: Send + Sync {
    /// Resolve a hostname to a set of socket addresses.
    ///
    /// # Arguments
    /// * `host` — Hostname to resolve (must not be an IP literal or localhost).
    /// * `port` — Port number for the resulting `SocketAddr`s.
    /// * `ip_version` — IP version preference ([`IpVersion::Any`], `V4Only`, `V6Only`).
    ///
    /// # Returns
    /// * `Ok(Vec<SocketAddr>)` — Resolved addresses (never empty on success).
    /// * `Err(CurlError)` — Resolution failed.
    async fn resolve(
        &self,
        host: &str,
        port: u16,
        ip_version: IpVersion,
    ) -> Result<Vec<SocketAddr>, CurlError>;

    /// Get the resolver backend name (for logging/diagnostics).
    fn name(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// Main resolution entry points
// ---------------------------------------------------------------------------

/// Main DNS resolution entry point with caching.
///
/// Replaces C `Curl_resolv()` (lib/hostip.c lines 860-1012).
///
/// Resolution order:
/// 1. Reject `.onion` hostnames (RFC 7686).
/// 2. Check DNS cache (with wildcard support).
/// 3. If the hostname is a localhost variant → return 127.0.0.1 / ::1.
/// 4. If the hostname is an IP literal → convert directly (no DNS lookup).
/// 5. If a DoH resolver is provided → use DoH.
/// 6. Otherwise → use the system/hickory resolver.
///
/// On failure, stores a negative cache entry.
pub async fn resolve_cached(
    cache: &DnsCache,
    resolver: &dyn Resolver,
    hostname: &str,
    port: u16,
    ip_version: IpVersion,
    doh_resolver: Option<&doh::DohResolver>,
    wildcard_resolve: bool,
) -> Result<Arc<DnsEntry>, CurlError> {
    let hostname_len = hostname.len();
    if hostname_len == 0 {
        return Err(CurlError::CouldntResolveHost);
    }

    // ── Step 1: .onion rejection (RFC 7686) ──────────────────────────────
    // From C: lib/hostip.c lines 887-895.
    if is_onion_hostname(hostname) {
        tracing::debug!(hostname = %hostname, "Rejecting .onion address (RFC 7686)");
        return Err(CurlError::CouldntResolveHost);
    }

    // ── Step 2: DNS cache lookup ─────────────────────────────────────────
    // From C: lib/hostip.c lines 897-907.
    if let Some(cached) = cache.get(hostname, port, ip_version, wildcard_resolve) {
        if cached.negative {
            tracing::debug!(hostname = %hostname, port = %port, "Negative DNS cache hit");
            return Err(CurlError::CouldntResolveHost);
        }
        tracing::debug!(hostname = %hostname, port = %port, "DNS cache hit");
        return Ok(cached);
    }

    // ── Step 3: IP literal shortcut ──────────────────────────────────────
    // From C: lib/hostip.c lines 928-936. If the hostname parses as an IP
    // address, construct a DnsEntry directly — no DNS lookup needed.
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        tracing::debug!(hostname = %hostname, "IP literal passthrough");
        let addr = SocketAddr::new(ip, port);
        let entry = DnsEntry {
            addrs: vec![addr],
            https_rr_info: None,
            created_at: Instant::now(),
            port,
            hostname: hostname.to_owned(),
            permanent: false,
            negative: false,
        };
        let arc = cache.add(entry);
        return Ok(arc);
    }

    // ── Step 4: Localhost shortcut (RFC 6761) ────────────────────────────
    // From C: lib/hostip.c lines 938-944 and get_localhost() / get_localhost6().
    if is_localhost(hostname) {
        tracing::debug!(hostname = %hostname, "Localhost shortcut");
        let addrs = get_localhost_addrs(port, ip_version);
        if addrs.is_empty() {
            return Err(CurlError::CouldntResolveHost);
        }
        let entry = DnsEntry {
            addrs,
            https_rr_info: None,
            created_at: Instant::now(),
            port,
            hostname: hostname.to_owned(),
            permanent: false,
            negative: false,
        };
        let arc = cache.add(entry);
        return Ok(arc);
    }

    // ── Step 5: IP version feasibility check ─────────────────────────────
    // From C: lib/hostip.c lines 952-956.
    if !can_resolve_ip_version(ip_version) {
        store_negative(cache, hostname, port);
        return Err(CurlError::CouldntResolveHost);
    }

    // ── Step 6: Perform the actual DNS resolution ────────────────────────
    let result = if let Some(doh) = doh_resolver {
        // From C: lib/hostip.c lines 946-949.
        tracing::debug!(hostname = %hostname, "Resolving via DoH");
        doh.resolve(hostname, port, ip_version).await
    } else {
        tracing::debug!(
            hostname = %hostname,
            resolver = %resolver.name(),
            "Resolving via {}",
            resolver.name()
        );
        resolver.resolve(hostname, port, ip_version).await
    };

    match result {
        Ok(addrs) if addrs.is_empty() => {
            // Should not happen — resolvers should return Err on empty, but be safe.
            store_negative(cache, hostname, port);
            Err(CurlError::CouldntResolveHost)
        }
        Ok(addrs) => {
            let entry = DnsEntry {
                addrs,
                https_rr_info: None,
                created_at: Instant::now(),
                port,
                hostname: hostname.to_owned(),
                permanent: false,
                negative: false,
            };
            let arc = cache.add(entry);
            show_resolve_info(&arc);
            Ok(arc)
        }
        Err(e) => {
            // From C: lib/hostip.c lines 1008-1009.
            store_negative(cache, hostname, port);
            Err(e)
        }
    }
}

/// Blocking resolution — resolve and wait for result.
///
/// From C: `Curl_resolv_blocking()` in lib/hostip.c lines 1014-1040.
/// In Rust async, this simply awaits the `resolve_cached()` future — no
/// separate polling or `Curl_async_await()` path is needed.
pub async fn resolve_blocking(
    cache: &DnsCache,
    resolver: &dyn Resolver,
    hostname: &str,
    port: u16,
    ip_version: IpVersion,
) -> Result<Arc<DnsEntry>, CurlError> {
    resolve_cached(cache, resolver, hostname, port, ip_version, None, false).await
}

/// Resolution with timeout.
///
/// Replaces C `Curl_resolv_timeout()` (lib/hostip.c lines 1076-1233).
/// The C version uses `SIGALRM` + `sigsetjmp`/`siglongjmp` for Unix timeout
/// handling. The Rust version uses `tokio::time::timeout` — portable, safe,
/// and composable.
pub async fn resolve_with_timeout(
    cache: &DnsCache,
    resolver: &dyn Resolver,
    hostname: &str,
    port: u16,
    ip_version: IpVersion,
    timeout_ms: u64,
) -> Result<Arc<DnsEntry>, CurlError> {
    if timeout_ms == 0 {
        return resolve_cached(cache, resolver, hostname, port, ip_version, None, false).await;
    }

    match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        resolve_cached(cache, resolver, hostname, port, ip_version, None, false),
    )
    .await
    {
        Ok(result) => result,
        Err(_elapsed) => Err(CurlError::OperationTimedOut),
    }
}

// ---------------------------------------------------------------------------
// Host-pair loading (CURLOPT_RESOLVE)
// ---------------------------------------------------------------------------

/// Load pre-resolved host pairs from `CURLOPT_RESOLVE` option.
///
/// Format:
/// - `"+hostname:port:address[,address]..."` — add non-permanent entry
/// - `"hostname:port:address[,address]..."` — add permanent entry
/// - `"-hostname:port"` — remove entry
///
/// From C: `Curl_loadhostpairs()` in lib/hostip.c lines 1279-1473.
///
/// # Returns
/// `Ok(true)` if any wildcard `"*"` entries were added, `Ok(false)` otherwise.
pub fn load_host_pairs(
    cache: &DnsCache,
    resolve_list: &[String],
) -> Result<bool, CurlError> {
    let mut wildcard_added = false;

    for entry_str in resolve_list {
        let s = entry_str.as_str();
        if s.is_empty() {
            continue;
        }

        if let Some(rest) = s.strip_prefix('-') {
            // ── Remove entry ─────────────────────────────────────────
            // From C: lib/hostip.c lines 1296-1323.
            if let Some((host, port)) = parse_host_port(rest) {
                let key = DnsCache::cache_key(&host, port);
                if let Ok(mut entries) = cache.entries.lock() {
                    entries.remove(&key);
                }
                tracing::debug!(host = %host, port = %port, "Removed CURLOPT_RESOLVE entry");
            }
        } else {
            // ── Add entry ────────────────────────────────────────────
            let (permanent, rest) = if let Some(r) = s.strip_prefix('+') {
                (false, r)
            } else {
                (true, s)
            };

            // Parse "hostname:port:addr1[,addr2,...]"
            // From C: lib/hostip.c lines 1324-1468.
            let parts: Vec<&str> = rest.splitn(3, ':').collect();
            if parts.len() < 3 {
                tracing::debug!(entry = %entry_str, "Invalid CURLOPT_RESOLVE entry, skipping");
                continue;
            }

            let host = parts[0];
            let port: u16 = match parts[1].parse() {
                Ok(p) => p,
                Err(_) => {
                    tracing::debug!(entry = %entry_str, "Invalid port in CURLOPT_RESOLVE, skipping");
                    continue;
                }
            };

            let addr_str = parts[2];
            let mut addrs = Vec::new();
            for addr_part in addr_str.split(',') {
                let trimmed = addr_part.trim().trim_matches(|c| c == '[' || c == ']');
                if trimmed.is_empty() {
                    continue;
                }
                match trimmed.parse::<IpAddr>() {
                    Ok(ip) => addrs.push(SocketAddr::new(ip, port)),
                    Err(_) => {
                        tracing::debug!(
                            address = %trimmed,
                            "Invalid address in CURLOPT_RESOLVE entry, skipping address"
                        );
                    }
                }
            }

            if addrs.is_empty() {
                tracing::debug!(entry = %entry_str, "No valid addresses in CURLOPT_RESOLVE entry");
                continue;
            }

            // Remove old entry if present (from C: lib/hostip.c lines 1422-1443)
            let key = DnsCache::cache_key(host, port);
            if let Ok(mut entries) = cache.entries.lock() {
                if entries.contains_key(&key) {
                    tracing::debug!(
                        host = %host, port = %port,
                        "Replacing existing DNS cache entry from CURLOPT_RESOLVE"
                    );
                    entries.remove(&key);
                }
            }

            let entry = DnsEntry {
                addrs,
                https_rr_info: None,
                created_at: Instant::now(),
                port,
                hostname: host.to_owned(),
                permanent,
                negative: false,
            };
            cache.add(entry);

            tracing::info!(
                host = %host,
                port = %port,
                permanent = %permanent,
                "Added CURLOPT_RESOLVE entry to DNS cache"
            );

            // Wildcard check (from C: lib/hostip.c lines 1463-1467)
            if host == "*" {
                tracing::info!(port = %port, "RESOLVE wildcard entry added");
                wildcard_added = true;
            }
        }
    }

    Ok(wildcard_added)
}

// ---------------------------------------------------------------------------
// Resolution checking and post-resolution
// ---------------------------------------------------------------------------

/// Check if an async resolution has completed.
///
/// From C: `Curl_resolv_check()` (lib/hostip.c lines 1476-1516).
/// In Rust async, this is largely unnecessary since we simply `await` the
/// resolve future. However, it is provided for compatibility with the
/// multi-handle polling interface where the caller needs to check whether
/// a previously started resolution is done.
pub async fn resolve_check(
    cache: &DnsCache,
    hostname: &str,
    port: u16,
    ip_version: IpVersion,
) -> Result<Option<Arc<DnsEntry>>, CurlError> {
    // In the async Rust model, resolution is either pending (the future has
    // not been polled to completion) or done (it has). When using the multi
    // handle, the Tokio runtime drives the future to completion on the
    // runtime's thread pool, and the result is already in the cache.
    //
    // Attempt a cache lookup — if the entry is there, resolution is complete.
    if let Some(entry) = cache.get(hostname, port, ip_version, false) {
        if entry.negative {
            return Err(CurlError::CouldntResolveHost);
        }
        show_resolve_info(&entry);
        return Ok(Some(entry));
    }
    // Not yet resolved.
    Ok(None)
}

/// Called after async resolution completes to set up the connection.
///
/// From C: `Curl_once_resolved()` (lib/hostip.c lines 1541-1562).
/// In the C codebase this function invokes `Curl_setup_conn()`. In Rust
/// the connection setup is handled by the connection subsystem; this
/// function serves as a hook point for logging and state transitions.
pub fn once_resolved(entry: &DnsEntry) -> Result<(), CurlError> {
    if entry.addrs.is_empty() && !entry.negative {
        return Err(CurlError::CouldntResolveHost);
    }
    tracing::debug!(
        hostname = %entry.hostname,
        port = %entry.port,
        addr_count = entry.addrs.len(),
        "DNS resolution complete, proceeding to connection setup"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Error reporting
// ---------------------------------------------------------------------------

/// Generate a resolver error.
///
/// From C: `Curl_resolver_error()` (lib/hostip.c lines 1569-1590).
/// Returns `CouldntResolveProxy` for proxy resolution failures and
/// `CouldntResolveHost` otherwise.
pub fn resolver_error(
    hostname: &str,
    is_proxy: bool,
    detail: Option<&str>,
) -> CurlError {
    let kind = if is_proxy { "proxy" } else { "host" };
    match detail {
        Some(d) => tracing::debug!(
            hostname = %hostname,
            kind = %kind,
            detail = %d,
            "Could not resolve {} '{}' ({})", kind, hostname, d
        ),
        None => tracing::debug!(
            hostname = %hostname,
            kind = %kind,
            "Could not resolve {} '{}'", kind, hostname
        ),
    }
    if is_proxy {
        CurlError::CouldntResolveProxy
    } else {
        CurlError::CouldntResolveHost
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Convert a `SocketAddr` to a printable IP string (without port).
///
/// From C: `Curl_printable_address()` (lib/hostip.c lines 203-227).
pub fn printable_address(addr: &SocketAddr) -> String {
    addr.ip().to_string()
}

/// Log resolved address information for verbose mode.
///
/// From C: `show_resolve_info()` (lib/hostip.c lines 118-182).
/// Uses `tracing::info!` to log each resolved address, separated by IPv4 and
/// IPv6 families.
pub fn show_resolve_info(entry: &DnsEntry) {
    if entry.hostname.is_empty() || entry.addrs.is_empty() {
        return;
    }
    // Skip logging for IP literals (from C: `Curl_host_is_ipnum()` check)
    if entry.hostname.parse::<IpAddr>().is_ok() {
        return;
    }

    let ipv4: Vec<String> = entry
        .addrs
        .iter()
        .filter(|a| a.is_ipv4())
        .map(|a| a.ip().to_string())
        .collect();

    let ipv6: Vec<String> = entry
        .addrs
        .iter()
        .filter(|a| a.is_ipv6())
        .map(|a| a.ip().to_string())
        .collect();

    tracing::info!(
        hostname = %entry.hostname,
        port = %entry.port,
        "Host {}:{} was resolved.",
        entry.hostname,
        entry.port
    );

    if !ipv6.is_empty() {
        tracing::info!("IPv6: {}", ipv6.join(", "));
    } else {
        tracing::info!("IPv6: (none)");
    }

    if !ipv4.is_empty() {
        tracing::info!("IPv4: {}", ipv4.join(", "));
    } else {
        tracing::info!("IPv4: (none)");
    }
}

/// Check if the requested IP version can be resolved.
///
/// From C: `can_resolve_ip_version()` (lib/hostip.c lines 807-820).
/// Returns `false` if `V6Only` is requested but IPv6 is not available on
/// the system.
pub fn can_resolve_ip_version(ip_version: IpVersion) -> bool {
    match ip_version {
        IpVersion::Any | IpVersion::V4Only => true,
        IpVersion::V6Only => {
            // Probe IPv6 availability. On systems where IPv6 is disabled,
            // a UDP socket bound to [::1]:0 will fail.
            // From C: Curl_ipv6works() in lib/hostip.c lines 771-776.
            system::ipv6_works()
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Check if a hostname is a `.onion` special-use domain (RFC 7686).
///
/// From C: lib/hostip.c lines 888-895.
fn is_onion_hostname(hostname: &str) -> bool {
    let h = hostname.to_ascii_lowercase();
    h.ends_with(".onion") || h.ends_with(".onion.")
}

/// Check if a hostname is a localhost variant (RFC 6761).
///
/// From C: lib/hostip.c lines 938-941.
fn is_localhost(hostname: &str) -> bool {
    let h = hostname.to_ascii_lowercase();
    h == "localhost"
        || h == "localhost."
        || h.ends_with(".localhost")
        || h.ends_with(".localhost.")
}

/// Get localhost addresses for the given port, respecting the IP version
/// preference.
///
/// From C: `get_localhost()` / `get_localhost6()` in lib/hostip.c lines
/// 670-746. Returns `[::1, 127.0.0.1]` (IPv6 first) when IPv6 is available
/// and the version is `Any` or `V6Only`.
fn get_localhost_addrs(port: u16, ip_version: IpVersion) -> Vec<SocketAddr> {
    let mut addrs = Vec::with_capacity(2);
    let ipv6_ok = system::ipv6_works();

    match ip_version {
        IpVersion::V6Only => {
            if ipv6_ok {
                addrs.push(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port));
            }
        }
        IpVersion::V4Only => {
            addrs.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
        }
        IpVersion::Any => {
            if ipv6_ok {
                addrs.push(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port));
            }
            addrs.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
        }
    }
    addrs
}

/// Store a negative (failed) resolution entry in the cache.
///
/// From C: `store_negative_resolve()` (lib/hostip.c lines 822-842).
fn store_negative(cache: &DnsCache, hostname: &str, port: u16) {
    let entry = DnsEntry {
        addrs: Vec::new(),
        https_rr_info: None,
        created_at: Instant::now(),
        port,
        hostname: hostname.to_owned(),
        permanent: false,
        negative: true,
    };
    cache.add(entry);
    tracing::info!(
        hostname = %hostname,
        port = %port,
        "Stored negative DNS cache entry"
    );
}

/// Parse a `"hostname:port"` or `"[hostname]:port"` string.
///
/// Returns `(hostname, port)` on success or `None` on failure.
fn parse_host_port(s: &str) -> Option<(String, u16)> {
    // Handle bracketed IPv6 address: [host]:port
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port_str = after.strip_prefix(':')?;
        let port: u16 = port_str.parse().ok()?;
        return Some((host.to_owned(), port));
    }

    // Regular hostname:port
    let colon = s.rfind(':')?;
    let host = &s[..colon];
    let port: u16 = s[colon + 1..].parse().ok()?;
    Some((host.to_owned(), port))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_version_default() {
        assert_eq!(IpVersion::default(), IpVersion::Any);
    }

    #[test]
    fn test_cache_key_format() {
        assert_eq!(DnsCache::cache_key("example.com", 443), "example.com:443");
        assert_eq!(DnsCache::cache_key("EXAMPLE.COM", 80), "example.com:80");
        assert_eq!(DnsCache::cache_key("*", 8080), "*:8080");
    }

    #[test]
    fn test_dns_entry_staleness() {
        let entry = DnsEntry {
            addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80)],
            https_rr_info: None,
            created_at: Instant::now() - Duration::from_secs(100),
            port: 80,
            hostname: "example.com".to_owned(),
            permanent: false,
            negative: false,
        };
        // 50-second timeout → stale (entry is 100s old)
        assert!(entry.is_stale(Duration::from_secs(50)));
        // 200-second timeout → not stale
        assert!(!entry.is_stale(Duration::from_secs(200)));
    }

    #[test]
    fn test_dns_entry_permanent_never_stale() {
        let entry = DnsEntry {
            addrs: vec![],
            https_rr_info: None,
            created_at: Instant::now() - Duration::from_secs(999_999),
            port: 80,
            hostname: "perm.example.com".to_owned(),
            permanent: true,
            negative: false,
        };
        assert!(!entry.is_stale(Duration::from_secs(1)));
    }

    #[test]
    fn test_dns_entry_negative_ages_faster() {
        let entry = DnsEntry {
            addrs: vec![],
            https_rr_info: None,
            created_at: Instant::now() - Duration::from_secs(60),
            port: 80,
            hostname: "neg.example.com".to_owned(),
            permanent: false,
            negative: true,
        };
        // With a 200s timeout, effective timeout for negative is 100s.
        // Entry is 60s old → not stale.
        assert!(!entry.is_stale(Duration::from_secs(200)));
        // With an 80s timeout, effective timeout for negative is 40s.
        // Entry is 60s old → stale.
        assert!(entry.is_stale(Duration::from_secs(80)));
    }

    #[test]
    fn test_cache_add_and_get() {
        let cache = DnsCache::new(Duration::from_secs(300));
        let entry = DnsEntry {
            addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 80)],
            https_rr_info: None,
            created_at: Instant::now(),
            port: 80,
            hostname: "example.com".to_owned(),
            permanent: false,
            negative: false,
        };
        cache.add(entry);
        let result = cache.get("example.com", 80, IpVersion::Any, false);
        assert!(result.is_some());
        assert_eq!(result.unwrap().hostname, "example.com");
    }

    #[test]
    fn test_cache_wildcard_lookup() {
        let cache = DnsCache::new(Duration::from_secs(300));
        let entry = DnsEntry {
            addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443)],
            https_rr_info: None,
            created_at: Instant::now(),
            port: 443,
            hostname: "*".to_owned(),
            permanent: true,
            negative: false,
        };
        cache.add(entry);
        // Non-wildcard lookup for a different host should miss
        let miss = cache.get("foo.example.com", 443, IpVersion::Any, false);
        assert!(miss.is_none());
        // Wildcard-enabled lookup should hit
        let hit = cache.get("foo.example.com", 443, IpVersion::Any, true);
        assert!(hit.is_some());
    }

    #[test]
    fn test_cache_ip_version_filter() {
        let cache = DnsCache::new(Duration::from_secs(300));
        let entry = DnsEntry {
            addrs: vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 80),
            ],
            https_rr_info: None,
            created_at: Instant::now(),
            port: 80,
            hostname: "v4only.example.com".to_owned(),
            permanent: false,
            negative: false,
        };
        cache.add(entry);
        // V4Only should match
        assert!(cache.get("v4only.example.com", 80, IpVersion::V4Only, false).is_some());
        // V6Only should NOT match (only IPv4 addresses)
        assert!(cache.get("v4only.example.com", 80, IpVersion::V6Only, false).is_none());
    }

    #[test]
    fn test_cache_clear() {
        let cache = DnsCache::new(Duration::from_secs(300));
        let entry = DnsEntry {
            addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80)],
            https_rr_info: None,
            created_at: Instant::now(),
            port: 80,
            hostname: "clear-test.example.com".to_owned(),
            permanent: false,
            negative: false,
        };
        cache.add(entry);
        assert!(cache.get("clear-test.example.com", 80, IpVersion::Any, false).is_some());
        cache.clear();
        assert!(cache.get("clear-test.example.com", 80, IpVersion::Any, false).is_none());
    }

    #[test]
    fn test_cache_prune() {
        let cache = DnsCache::new(Duration::from_secs(1));
        let entry = DnsEntry {
            addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80)],
            https_rr_info: None,
            created_at: Instant::now() - Duration::from_secs(10),
            port: 80,
            hostname: "stale.example.com".to_owned(),
            permanent: false,
            negative: false,
        };
        cache.add(entry);
        cache.prune();
        assert!(cache.get("stale.example.com", 80, IpVersion::Any, false).is_none());
    }

    #[test]
    fn test_is_onion_hostname() {
        assert!(is_onion_hostname("hidden.onion"));
        assert!(is_onion_hostname("hidden.onion."));
        assert!(is_onion_hostname("HIDDEN.ONION"));
        assert!(!is_onion_hostname("onion.example.com"));
        assert!(!is_onion_hostname("example.com"));
    }

    #[test]
    fn test_is_localhost() {
        assert!(is_localhost("localhost"));
        assert!(is_localhost("localhost."));
        assert!(is_localhost("foo.localhost"));
        assert!(is_localhost("foo.localhost."));
        assert!(is_localhost("LOCALHOST"));
        assert!(!is_localhost("notlocalhost"));
        assert!(!is_localhost("example.com"));
    }

    #[test]
    fn test_printable_address() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        assert_eq!(printable_address(&addr), "192.168.1.1");
        let addr6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
        assert_eq!(printable_address(&addr6), "::1");
    }

    #[test]
    fn test_resolver_error_host() {
        let err = resolver_error("example.com", false, None);
        assert_eq!(err, CurlError::CouldntResolveHost);
    }

    #[test]
    fn test_resolver_error_proxy() {
        let err = resolver_error("proxy.example.com", true, Some("timed out"));
        assert_eq!(err, CurlError::CouldntResolveProxy);
    }

    #[test]
    fn test_load_host_pairs_add_and_remove() {
        let cache = DnsCache::new(Duration::from_secs(300));
        let pairs = vec![
            "example.com:80:1.2.3.4".to_string(),
            "+temp.com:443:5.6.7.8".to_string(),
        ];
        let result = load_host_pairs(&cache, &pairs);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // no wildcard
        assert!(cache.get("example.com", 80, IpVersion::Any, false).is_some());
        assert!(cache.get("temp.com", 443, IpVersion::Any, false).is_some());

        // Remove
        let remove = vec!["-example.com:80".to_string()];
        let _ = load_host_pairs(&cache, &remove);
        assert!(cache.get("example.com", 80, IpVersion::Any, false).is_none());
    }

    #[test]
    fn test_load_host_pairs_wildcard() {
        let cache = DnsCache::new(Duration::from_secs(300));
        let pairs = vec!["*:443:10.0.0.1".to_string()];
        let result = load_host_pairs(&cache, &pairs);
        assert!(result.is_ok());
        assert!(result.unwrap()); // wildcard added
    }

    #[test]
    fn test_load_host_pairs_multiple_addresses() {
        let cache = DnsCache::new(Duration::from_secs(300));
        let pairs = vec!["multi.com:80:1.1.1.1,2.2.2.2,::1".to_string()];
        let _ = load_host_pairs(&cache, &pairs);
        let entry = cache.get("multi.com", 80, IpVersion::Any, false);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().addrs.len(), 3);
    }

    #[test]
    fn test_parse_host_port() {
        assert_eq!(
            parse_host_port("example.com:443"),
            Some(("example.com".to_owned(), 443))
        );
        assert_eq!(
            parse_host_port("[::1]:80"),
            Some(("::1".to_owned(), 80))
        );
        assert_eq!(parse_host_port("badformat"), None);
    }

    #[test]
    fn test_constants() {
        assert_eq!(MAX_HOSTCACHE_LEN, 262);
        assert_eq!(MAX_DNS_CACHE_SIZE, 29999);
        assert_eq!(DEFAULT_DNS_CACHE_TIMEOUT_SECS, 300);
    }

    #[test]
    fn test_https_rr_info_clone() {
        let info = HttpsRrInfo {
            priority: 1,
            target: "cdn.example.com".to_owned(),
            alpns: vec!["h2".to_owned(), "h3".to_owned()],
            no_def_alpn: false,
            port: Some(443),
            ipv4_hints: vec![Ipv4Addr::new(1, 2, 3, 4)],
            ipv6_hints: vec![Ipv6Addr::LOCALHOST],
            ech_config: Some(vec![0x00, 0x01]),
        };
        let cloned = info.clone();
        assert_eq!(cloned.priority, 1);
        assert_eq!(cloned.alpns.len(), 2);
        assert_eq!(cloned.ipv4_hints.len(), 1);
    }
}
