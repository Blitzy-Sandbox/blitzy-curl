// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! Name-resolution subsystem root: resolver dispatch, the shared DNS cache, and
//! the address representation.
//!
//! This module is the **foundational root** of the `dns` subtree of
//! `curl-rs-lib`, an idiomatic-Rust, byte-for-byte functional-parity rewrite of
//! curl / libcurl **8.19.0-DEV**. It is a language rewrite of the curl 8.x
//! host-resolution core, derived from the source-of-truth C files:
//!
//! | curl C source            | responsibility reproduced here                    |
//! |--------------------------|---------------------------------------------------|
//! | `lib/hostip.c` / `.h`    | DNS cache, [`resolve`] orchestration (`Curl_resolv`), staleness, `.onion`/localhost handling, `CURLOPT_RESOLVE` loading, negative caching, `can_resolve_ip_version` |
//! | `lib/curl_addrinfo.c`/`.h` | the [`Address`] list (`struct Curl_addrinfo`): literal-IP detection/parse, port stamping, family filtering |
//! | `lib/asyn.h`             | the resolver-backend interface generalized by the [`Resolver`] trait |
//! | `lib/asyn-thrdd.c`       | resolver selection and the `ip_version` → address-family mapping |
//!
//! # Position in the crate
//!
//! `dns` is **foundational**: it is consumed by the connection layer
//! (`conn/`, e.g. `conn/happy_eyeballs.rs`) and by the protocol handlers, and it
//! depends on nothing in those layers. It therefore intentionally does **not**
//! import `crate::conn` — that would create a dependency cycle (`conn` depends on
//! `dns`, never the reverse). Its only intra-crate dependencies are
//! [`crate::error`] (the frozen [`CURLcode`](crate::error::CurlCode) contract)
//! and [`crate::idn`] (IDN / Punycode host normalization).
//!
//! # Backend dispatch (trait-based, replacing curl's `#ifdef`)
//!
//! curl selects a resolver backend at compile time with
//! `#ifdef CURLRES_THREADED` / `CURLRES_ARES` / `CURLRES_SYNCH`. This rewrite
//! replaces that preprocessor branching with the [`Resolver`] trait (AAP §0.3.2,
//! "Trait-Based Protocol Dispatch"). The three backend modules in this folder —
//! [`system`] (the default Tokio system resolver), [`doh`] (DNS-over-HTTPS), and
//! the optional `hickory` (behind the default-off `hickory-dns` feature) —
//! each provide a type implementing [`Resolver`]. The caller (the connection
//! layer) constructs the active backend(s) and hands them to [`resolve`] through
//! [`ResolveOptions`]; this root module owns the resolution *policy* (cache
//! lookup, `.onion` rejection, literal-IP and `localhost` shortcuts, negative
//! caching, family filtering) while delegating the actual network lookup to the
//! chosen backend via the trait. Keeping this module free of concrete
//! backend-type references is what lets the four `dns/*.rs` files evolve
//! independently.
//!
//! # Memory-safety guarantees (AAP §0.6.2, §0.7.2)
//!
//! This module is written entirely in safe Rust, with no low-level memory
//! operations of its own (upholding the crate root's compile-time
//! memory-safety guarantee, AAP §0.7.2). curl's manual `malloc`/`free` of `Curl_addrinfo`
//! linked lists and the hand-rolled `size_t refcount` / `Curl_resolv_unlink`
//! reference counting are replaced by owned Rust collections and [`Arc`]:
//! cloning an `Arc<DnsEntry>` is curl's `refcount++`, and dropping it is
//! `Curl_resolv_unlink`. There is no explicit free — an entry is deallocated
//! automatically when its last `Arc` is dropped, so the `Curl_freeaddrinfo`
//! family of functions has no counterpart here.
//!
//! # Async model
//!
//! Any asynchrony is on Tokio (the sole async runtime, AAP §0.3.2). The
//! [`Resolver`] trait returns a boxed [`Future`] ([`ResolveFuture`]) rather than
//! using an `async fn` in the trait, so the trait stays object-safe (usable as
//! `&dyn Resolver`) and compiles cleanly on the MSRV (Rust 1.75) with no
//! `async_fn_in_trait` lint.

// ---------------------------------------------------------------------------
// Phase 1 — backend submodule declarations
// ---------------------------------------------------------------------------
// The three resolver backends that make up the `dns` subtree (AAP §0.3.1). Each
// provides a `Resolver` implementation. `system` (Tokio system resolver) and
// `doh` (DNS-over-HTTPS) are ALWAYS compiled; `hickory` is gated behind the
// default-OFF `hickory-dns` feature, mirroring `curl-rs-lib/Cargo.toml` and
// curl's non-default `USE_ARES`. The module declaration itself is `#[cfg]`-gated
// so a default build compiles and works with only `system` + `doh`.
pub mod doh;
#[cfg(feature = "hickory-dns")]
pub mod hickory;
pub mod system;

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use rand::seq::SliceRandom;

use crate::error::{CurlCode, Error, Result};
use crate::idn;

// ---------------------------------------------------------------------------
// Constants (transcribed verbatim from lib/hostip.c / lib/hostip.h)
// ---------------------------------------------------------------------------

/// Maximum number of seconds allowed for an asynchronous name resolve before it
/// is abandoned — curl's `CURL_TIMEOUT_RESOLVE` (`lib/hostip.h:38`). Preserved
/// as a frozen constant so timeout parity with curl 8.x is retained.
pub const CURL_TIMEOUT_RESOLVE: u64 = 300;

/// Upper bound on the number of live entries kept in the DNS cache before
/// [`DnsCache::prune`] becomes aggressive — curl's `MAX_DNS_CACHE_SIZE`
/// (`lib/hostip.c:78`). Transcribed verbatim.
pub const MAX_DNS_CACHE_SIZE: usize = 29999;

// ---------------------------------------------------------------------------
// Phase 5 (type) — IpVersion (frozen CURL_IPRESOLVE_* ABI values)
// ---------------------------------------------------------------------------

/// The IP-protocol-version preference for a resolution, mirroring curl's
/// `CURLOPT_IPRESOLVE` option.
///
/// The discriminants are a **frozen ABI contract** transcribed verbatim from
/// `include/curl/curl.h` (the `CURL_IPRESOLVE_*` defines): a consumer that
/// hard-codes `CURL_IPRESOLVE_V4 == 1` must keep working, so the integer values
/// are preserved exactly and bridged through [`IpVersion::as_i32`] /
/// [`From<i32>`](IpVersion::from) at the FFI boundary.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum IpVersion {
    /// `CURL_IPRESOLVE_WHATEVER` (0) — the default; use addresses of every IP
    /// version the system supports.
    #[default]
    Whatever = 0,
    /// `CURL_IPRESOLVE_V4` (1) — use IPv4 addresses/connections only.
    V4 = 1,
    /// `CURL_IPRESOLVE_V6` (2) — use IPv6 addresses/connections only.
    V6 = 2,
}

impl IpVersion {
    /// Returns the frozen C integer value (`CURL_IPRESOLVE_*`) for this variant.
    #[must_use]
    pub fn as_i32(self) -> i32 {
        self as i32
    }

    /// Returns `true` if a [`SocketAddr`] of the given kind satisfies this
    /// preference. [`IpVersion::Whatever`] accepts either family; [`IpVersion::V4`]
    /// accepts only IPv4; [`IpVersion::V6`] accepts only IPv6.
    #[must_use]
    pub fn accepts(self, addr: &SocketAddr) -> bool {
        match self {
            IpVersion::Whatever => true,
            IpVersion::V4 => addr.is_ipv4(),
            IpVersion::V6 => addr.is_ipv6(),
        }
    }
}

impl From<i32> for IpVersion {
    /// Bridges a C `CURL_IPRESOLVE_*` integer to an [`IpVersion`]. Unknown values
    /// map to [`IpVersion::Whatever`] — the same permissive default curl applies
    /// when the option holds an unrecognized value.
    fn from(value: i32) -> Self {
        match value {
            1 => IpVersion::V4,
            2 => IpVersion::V6,
            _ => IpVersion::Whatever,
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 2 — Address representation (← lib/curl_addrinfo.c / .h)
// ---------------------------------------------------------------------------

/// An ordered set of resolved endpoints for a host, the idiomatic-Rust
/// replacement for curl's `struct Curl_addrinfo` linked list
/// (`lib/curl_addrinfo.h:50`).
///
/// curl threads a hand-allocated singly linked list of `Curl_addrinfo` nodes
/// (`ai_family`, `ai_socktype`, `ai_protocol`, `ai_addr`, `ai_canonname`,
/// `ai_next`) and frees it with `Curl_freeaddrinfo`. Here the list becomes an
/// **owned, ordered [`Vec<SocketAddr>`]**; the socket family, address and port
/// all live inside each [`SocketAddr`], and the whole thing is dropped
/// automatically when the [`Address`] goes out of scope — so there is **no**
/// `Curl_freeaddrinfo` counterpart and no manual `malloc`/`free`.
///
/// # Ordering contract
///
/// The order of [`Address::endpoints`] is **significant** and preserved exactly
/// as the producing backend returned it (the system resolver's RFC 6724 /
/// `getaddrinfo` order, a DoH answer's record order, or the fixed `[::1,
/// 127.0.0.1]` order for `localhost`). `conn/happy_eyeballs.rs` relies on this
/// order — and on the relative IPv4/IPv6 positioning — to interleave connection
/// attempts (RFC 8305), so no method here re-sorts the list; only
/// [`Address::filter_by_ip_version`] (a stable retain) and the explicit
/// [`DnsCache::mk_entry`] shuffle ever change it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Address {
    /// The resolved endpoints, in backend-provided order (see the ordering
    /// contract above). An empty vector denotes a **negative** result — the
    /// equivalent of a curl DNS-cache entry whose `addr` pointer is `NULL`.
    endpoints: Vec<SocketAddr>,
    /// The canonical name reported by the resolver (curl's `ai_canonname`), if
    /// any. `None` when the backend supplied no canonical name.
    canonical_name: Option<String>,
    /// The DNS TTL for cache-expiry bookkeeping. A DoH answer supplies this; the
    /// system resolver does not expose a TTL, so it is left `None` there.
    ttl: Option<Duration>,
}

impl Address {
    /// Creates an [`Address`] from an ordered list of endpoints, with no
    /// canonical name and no TTL.
    #[must_use]
    pub fn new(endpoints: Vec<SocketAddr>) -> Self {
        Address {
            endpoints,
            canonical_name: None,
            ttl: None,
        }
    }

    /// Builds an [`Address`] by stamping `port` onto each resolved [`IpAddr`],
    /// preserving order. This is the idiomatic form of curl's `Curl_he2ai` /
    /// `Curl_getaddrinfo_ex` (build an address list from bare IPs) followed by
    /// `Curl_addrinfo_set_port` (attach the port to every node).
    #[must_use]
    pub fn from_ips(ips: impl IntoIterator<Item = IpAddr>, port: u16) -> Self {
        Address::new(
            ips.into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect(),
        )
    }

    /// The literal-IP shortcut — curl's `Curl_is_ipaddr` + `Curl_str2addr`
    /// (`lib/curl_addrinfo.c`). If `host` parses as an IPv4 or IPv6 literal, this
    /// returns a single-endpoint [`Address`] built directly from it, with **no**
    /// network resolution. Returns `None` when `host` is not a numeric IP.
    ///
    /// Like `Curl_str2addr`, this expects a **bare** literal (no surrounding
    /// brackets); the URL layer strips an IPv6 host's brackets before resolution,
    /// and the `CURLOPT_RESOLVE` parser handles brackets itself before delegating
    /// here.
    #[must_use]
    pub fn from_literal(host: &str, port: u16) -> Option<Self> {
        IpAddr::from_str(host)
            .ok()
            .map(|ip| Address::new(vec![SocketAddr::new(ip, port)]))
    }

    /// Overwrites the port on every endpoint — curl's `Curl_addrinfo_set_port`.
    pub fn set_port(&mut self, port: u16) {
        for ep in &mut self.endpoints {
            ep.set_port(port);
        }
    }

    /// Retains only the endpoints whose family matches `ip_version`, preserving
    /// order. This mirrors the family "zap" curl performs in `fetch_addr`
    /// (`lib/hostip.c:418-441`) and the `ai_family` hint it passes to
    /// `getaddrinfo`: [`IpVersion::V4`] keeps only IPv4 endpoints,
    /// [`IpVersion::V6`] keeps only IPv6, and [`IpVersion::Whatever`] keeps all.
    pub fn filter_by_ip_version(&mut self, ip_version: IpVersion) {
        if ip_version != IpVersion::Whatever {
            self.endpoints.retain(|ep| ip_version.accepts(ep));
        }
    }

    /// Returns `true` if at least one endpoint of the given `ip_version` is
    /// present. Used by the cache-family check (`fetch_addr`) to decide whether a
    /// cached entry can satisfy the requested family. [`IpVersion::Whatever`]
    /// only fails on a completely empty (negative) address.
    #[must_use]
    pub fn has_family(&self, ip_version: IpVersion) -> bool {
        match ip_version {
            IpVersion::Whatever => !self.endpoints.is_empty(),
            _ => self.endpoints.iter().any(|ep| ip_version.accepts(ep)),
        }
    }

    /// The resolved endpoints, in order (see the ordering contract on
    /// [`Address`]).
    #[must_use]
    pub fn endpoints(&self) -> &[SocketAddr] {
        &self.endpoints
    }

    /// The canonical name (`ai_canonname`), if the backend supplied one.
    #[must_use]
    pub fn canonical_name(&self) -> Option<&str> {
        self.canonical_name.as_deref()
    }

    /// Sets the canonical name (`ai_canonname`).
    pub fn set_canonical_name(&mut self, name: impl Into<String>) {
        self.canonical_name = Some(name.into());
    }

    /// The DNS TTL, if known (supplied by DoH; `None` for the system resolver).
    #[must_use]
    pub fn ttl(&self) -> Option<Duration> {
        self.ttl
    }

    /// Sets the DNS TTL used for cache-expiry bookkeeping.
    pub fn set_ttl(&mut self, ttl: Duration) {
        self.ttl = Some(ttl);
    }

    /// `true` when there are no endpoints — a **negative** result, equivalent to
    /// a curl `Curl_dns_entry` with a `NULL` `addr`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    /// The number of resolved endpoints.
    #[must_use]
    pub fn len(&self) -> usize {
        self.endpoints.len()
    }
}

// ---------------------------------------------------------------------------
// Phase 3 — HTTPS-RR info, entry timestamp, and DnsEntry (← struct Curl_dns_entry)
// ---------------------------------------------------------------------------

/// Minimal HTTPS resource-record (SVCB / HTTPS RR, RFC 9460) information
/// attached to a resolved entry — the counterpart of curl's
/// `struct Curl_https_rrinfo` (`lib/urldata.h`, guarded by `USE_HTTPSRR`).
///
/// Only the fields the connection layer consults are represented; full record
/// parsing lives in [`doh`] (per the Minimal Change Mandate, nothing more is
/// modeled here). An entry carries this as [`Option<HttpsRrInfo>`] — `None` when
/// no HTTPS RR was seen (the common case and the only possibility for backends
/// that do not fetch the record).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpsRrInfo {
    /// The `TargetName` of the HTTPS RR, when it differs from the queried host.
    pub target: Option<String>,
    /// The `port` SvcParam, if present.
    pub port: Option<u16>,
    /// The ALPN identifiers advertised by the `alpn` SvcParam, in record order.
    pub alpn: Vec<String>,
    /// IPv4 address hints (`ipv4hint` SvcParam), in record order.
    pub ipv4hints: Vec<Ipv4Addr>,
    /// IPv6 address hints (`ipv6hint` SvcParam), in record order.
    pub ipv6hints: Vec<Ipv6Addr>,
}

/// When a [`DnsEntry`] was created, and whether it can ever go stale.
///
/// This encodes the single most important cache semantic in curl: a
/// `Curl_dns_entry` whose `timestamp` is **zero** is a **permanent**
/// `CURLOPT_RESOLVE` entry that never times out (`lib/hostip.h:61`). Modeling it
/// as an explicit enum makes that intent unmissable and guarantees
/// [`DnsEntry::is_stale`] returns `false` for [`DnsTimestamp::Permanent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsTimestamp {
    /// A permanent entry (curl `timestamp == 0`) — supplied via `CURLOPT_RESOLVE`
    /// without the `+` prefix; it never expires.
    Permanent,
    /// A timed entry created at the given instant; it expires once its age
    /// exceeds the configured DNS-cache timeout.
    Created(Instant),
}

/// A single resolved host record held in the [`DnsCache`], the idiomatic-Rust
/// replacement for curl's `struct Curl_dns_entry` (`lib/hostip.h:56`).
///
/// # Reference counting
///
/// curl tracks sharing with a manual `size_t refcount` that is incremented on
/// each hand-out, decremented by `Curl_resolv_unlink`, and freed at zero. Here an
/// entry is always wrapped in an [`Arc<DnsEntry>`]: **cloning the `Arc` is the
/// `refcount++`**, and **dropping it is `Curl_resolv_unlink`** — the allocation
/// is released automatically when the final reference (the cache's own, plus any
/// handed out) is gone. There is no manual free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsEntry {
    /// The resolved [`Address`]. An empty address (`addr.is_empty()`) marks a
    /// **negative** cache entry — curl's `Curl_dns_entry` with a `NULL` `addr`.
    addr: Address,
    /// Optional HTTPS-RR information (curl's `hinfo`, `USE_HTTPSRR`). `None` unless
    /// a DoH lookup attached an HTTPS record.
    hinfo: Option<HttpsRrInfo>,
    /// Creation time / permanence (curl's `timestamp`; see [`DnsTimestamp`]).
    timestamp: DnsTimestamp,
    /// The port that, together with [`DnsEntry::hostname`], keyed this entry
    /// (curl's `hostport`).
    hostport: u16,
    /// The hostname that resolved to [`DnsEntry::addr`] (curl's `hostname[]`). May
    /// be empty (curl permits a `NULL` name for Unix-domain-socket entries).
    hostname: String,
}

impl DnsEntry {
    /// Builds a [`DnsEntry`]. `permanent` selects [`DnsTimestamp::Permanent`]
    /// (a never-expiring `CURLOPT_RESOLVE` entry) versus a timed entry stamped
    /// with [`Instant::now`]. Mirrors the field initialization in
    /// `Curl_dnscache_mk_entry` (`lib/hostip.c:560`).
    #[must_use]
    pub fn new(addr: Address, hostname: impl Into<String>, port: u16, permanent: bool) -> Self {
        DnsEntry {
            addr,
            hinfo: None,
            timestamp: if permanent {
                DnsTimestamp::Permanent
            } else {
                DnsTimestamp::Created(Instant::now())
            },
            hostport: port,
            hostname: hostname.into(),
        }
    }

    /// The resolved [`Address`].
    #[must_use]
    pub fn addr(&self) -> &Address {
        &self.addr
    }

    /// The endpoints of the resolved address, in order — a convenience shortcut
    /// used by `conn/happy_eyeballs.rs`.
    #[must_use]
    pub fn endpoints(&self) -> &[SocketAddr] {
        self.addr.endpoints()
    }

    /// The optional HTTPS-RR information (curl's `hinfo`).
    #[must_use]
    pub fn https_rr(&self) -> Option<&HttpsRrInfo> {
        self.hinfo.as_ref()
    }

    /// Attaches HTTPS-RR information to this entry (used by the DoH backend).
    pub fn set_https_rr(&mut self, hinfo: HttpsRrInfo) {
        self.hinfo = Some(hinfo);
    }

    /// The port this entry was keyed under (curl's `hostport`).
    #[must_use]
    pub fn hostport(&self) -> u16 {
        self.hostport
    }

    /// The hostname this entry was keyed under (curl's `hostname[]`).
    #[must_use]
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// Whether this entry is permanent (a `CURLOPT_RESOLVE` entry that never
    /// times out — curl `timestamp == 0`).
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        matches!(self.timestamp, DnsTimestamp::Permanent)
    }

    /// Whether this is a **negative** entry (no addresses) — curl's `NULL`-`addr`
    /// entry produced by `store_negative_resolve`.
    #[must_use]
    pub fn is_negative(&self) -> bool {
        self.addr.is_empty()
    }

    /// Returns `true` if this entry is stale at `now` under `timeout`, mirroring
    /// `dnscache_entry_is_stale` (`lib/hostip.c:260`).
    ///
    /// Parity rules reproduced exactly:
    /// * a [`DnsTimestamp::Permanent`] entry is **never** stale (curl skips the
    ///   check when `timestamp == 0`);
    /// * a **negative** entry ages **twice as fast** (curl: `if(!dns->addr) age
    ///   *= 2`);
    /// * a timed entry is stale once its (possibly doubled) age is **`>=`** the
    ///   timeout.
    #[must_use]
    pub fn is_stale(&self, now: Instant, timeout: Duration) -> bool {
        match self.timestamp {
            DnsTimestamp::Permanent => false,
            DnsTimestamp::Created(created) => {
                let mut age = now.saturating_duration_since(created);
                if self.is_negative() {
                    // Negative entries age twice as fast (lib/hostip.c:268).
                    age = age.saturating_mul(2);
                }
                age >= timeout
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 4 — the shared DNS cache (← struct Curl_dnscache + hostip.c cache fns)
// ---------------------------------------------------------------------------

/// The shared DNS cache: a hostname→[`DnsEntry`] map, reproducing curl's
/// `struct Curl_dnscache` (`lib/hostip.h:71`, a `Curl_hash` keyed by a
/// lowercased `hostname:port` string).
///
/// # Sharing model
///
/// The map lives behind an [`Arc<Mutex<…>>`] so a single cache can be shared by
/// many easy handles — the `curl_share` / `CURL_LOCK_DATA_DNS` model
/// (AAP §0.3.2, "Ownership over manual allocation"). Cloning a [`DnsCache`]
/// clones the [`Arc`], yielding another handle onto the *same* cache; the
/// [`Mutex`] provides the fine-grained locking curl performs with
/// `Curl_share_lock(CURL_LOCK_DATA_DNS, …)` and protects **only** DNS-cache
/// state, so cookie and other shared-data contention stay independent.
///
/// The lock is never held across an `.await`: every method acquires it, performs
/// a bounded synchronous operation, and releases it before returning, so the
/// [`resolve`] future stays `Send` and cannot deadlock on the async runtime.
#[derive(Debug, Clone, Default)]
pub struct DnsCache {
    /// The entries, keyed by [`DnsCache::cache_key`]. Each value is shared via
    /// [`Arc`], so handing an entry to a caller is a refcount bump and dropping
    /// it is `Curl_resolv_unlink`.
    entries: Arc<Mutex<HashMap<String, Arc<DnsEntry>>>>,
    /// Whether a `CURLOPT_RESOLVE` wildcard (`*:port`) entry has been loaded —
    /// curl's per-handle `data->state.wildcard_resolve`. When set,
    /// [`DnsCache::get`] falls back to the `*:port` key on an exact miss.
    wildcard: Arc<AtomicBool>,
}

impl DnsCache {
    /// Creates an empty DNS cache.
    #[must_use]
    pub fn new() -> Self {
        DnsCache::default()
    }

    /// Acquires the entry-map lock, recovering the guard if the mutex was
    /// poisoned by a panicking thread. Recovery (rather than propagating the
    /// panic) keeps the cache usable and avoids `unwrap`/`expect` in this
    /// library path; a poisoned DNS cache is not a correctness hazard because
    /// every stored value is an immutable, self-contained [`Arc<DnsEntry>`].
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<DnsEntry>>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Builds the cache key for a host/port pair — curl's `create_dnscache_id`
    /// (`lib/hostip.c:233`): the **ASCII-lowercased** hostname, a colon, and the
    /// port (`"example.com:443"`). Lowercasing makes lookups case-insensitive,
    /// exactly as curl's `Curl_strntolower` does when building the id.
    #[must_use]
    fn cache_key(hostname: &str, port: u16) -> String {
        format!("{}:{}", hostname.to_ascii_lowercase(), port)
    }

    /// The wildcard cache key for a port — curl keys wildcard `CURLOPT_RESOLVE`
    /// entries under `"*:port"` (`create_dnscache_id("*", …)`).
    #[must_use]
    fn wildcard_key(port: u16) -> String {
        format!("*:{port}")
    }

    /// Looks up a cached entry, reproducing curl's `fetch_addr`
    /// (`lib/hostip.c:374`) exactly:
    ///
    /// 1. Try the exact `hostname:port` key.
    /// 2. On a miss, if a wildcard entry has been loaded (`wildcard`),
    ///    try the `*:port` key.
    /// 3. If a hit is **stale** — and staleness checking is enabled (`timeout`
    ///    is `Some`, curl's `dns_cache_timeout_ms != -1`) — the entry is zapped
    ///    (removed) and treated as a miss, logging *"Hostname in DNS cache was
    ///    stale, zapped"*.
    /// 4. If a **specific** family is requested (`ip_version != Whatever`) and
    ///    the hit does **not carry it**, the entry is zapped and treated as a
    ///    miss, logging *"Hostname in DNS cache does not have needed family,
    ///    zapped"*. curl guards this with `ip_version != CURL_IPRESOLVE_WHATEVER`
    ///    (`lib/hostip.c:417`), so a `Whatever` lookup never zaps on family —
    ///    which lets a **negative** (empty) entry survive a `Whatever` lookup and
    ///    be surfaced as a cached failure by [`resolve`].
    ///
    /// On success the shared [`Arc<DnsEntry>`] is cloned out (curl's
    /// `refcount++`). The returned entry may still contain other-family
    /// addresses — matching curl, which only checks that the requested family is
    /// *present*, never rewrites the list on a cache hit.
    #[must_use]
    pub fn get(
        &self,
        hostname: &str,
        port: u16,
        ip_version: IpVersion,
        timeout: Option<Duration>,
    ) -> Option<Arc<DnsEntry>> {
        let now = Instant::now();
        let mut map = self.lock();

        // (1) exact key, then (2) wildcard fallback.
        let key = Self::cache_key(hostname, port);
        let matched_key = if map.contains_key(&key) {
            key
        } else if self.wildcard.load(Ordering::Relaxed) {
            let wkey = Self::wildcard_key(port);
            if map.contains_key(&wkey) {
                wkey
            } else {
                return None;
            }
        } else {
            return None;
        };

        // Clone the Arc out (curl's refcount++) before any potential removal.
        let entry = map.get(&matched_key)?.clone();

        // (3) staleness: only when the timeout is not "forever" (curl -1).
        if let Some(timeout) = timeout {
            if entry.is_stale(now, timeout) {
                tracing::info!("Hostname in DNS cache was stale, zapped");
                map.remove(&matched_key);
                return None;
            }
        }

        // (4) family presence: checked ONLY for a specific family. curl guards
        // this with `ip_version != CURL_IPRESOLVE_WHATEVER` (lib/hostip.c:417),
        // so a `Whatever` lookup never zaps on family — which is precisely what
        // lets a **negative** entry (empty address) survive a `Whatever` lookup
        // and be reported as a cached failure by `resolve`. A request for a
        // specific family that the entry cannot satisfy (including any negative
        // entry) is a miss, and the entry is zapped.
        if ip_version != IpVersion::Whatever && !entry.addr.has_family(ip_version) {
            tracing::info!("Hostname in DNS cache does not have needed family, zapped");
            map.remove(&matched_key);
            return None;
        }

        Some(entry)
    }

    /// Builds a [`DnsEntry`] (wrapped in an [`Arc`], i.e. refcount 1) **without**
    /// inserting it — curl's `Curl_dnscache_mk_entry` (`lib/hostip.c:560`).
    ///
    /// When `shuffle` is set (curl's `data->set.dns_shuffle_addresses`) and there
    /// is more than one endpoint, the address order is randomized with a
    /// Fisher-Yates shuffle — curl's `Curl_shuffle_addr` (`lib/hostip.c:506`) —
    /// logging *"Shuffling N addresses"*. `permanent` selects a never-expiring
    /// entry (curl `timestamp == 0`).
    #[must_use]
    pub fn mk_entry(
        mut addr: Address,
        hostname: impl Into<String>,
        port: u16,
        permanent: bool,
        shuffle: bool,
    ) -> Arc<DnsEntry> {
        if shuffle && addr.endpoints.len() > 1 {
            tracing::info!("Shuffling {} addresses", addr.endpoints.len());
            let mut rng = rand::thread_rng();
            addr.endpoints.shuffle(&mut rng);
        }
        Arc::new(DnsEntry::new(addr, hostname, port, permanent))
    }

    /// Inserts an entry, keyed by its own hostname/port — curl's
    /// `Curl_dnscache_add` (`lib/hostip.c:183`). Any existing entry for the same
    /// key is replaced.
    pub fn add(&self, entry: Arc<DnsEntry>) {
        let key = Self::cache_key(entry.hostname(), entry.hostport());
        self.lock().insert(key, entry);
    }

    /// Removes the entry for `hostname:port`, returning it if present. Used by
    /// the `-host:port` form of `CURLOPT_RESOLVE` (`Curl_loadhostpairs`) and to
    /// discard an entry's old addresses before replacement.
    pub fn remove(&self, hostname: &str, port: u16) -> Option<Arc<DnsEntry>> {
        let key = Self::cache_key(hostname, port);
        self.lock().remove(&key)
    }

    /// Returns `true` if an entry exists for `hostname:port` (no staleness or
    /// family filtering — a raw key-presence test).
    #[must_use]
    pub fn contains(&self, hostname: &str, port: u16) -> bool {
        self.lock().contains_key(&Self::cache_key(hostname, port))
    }

    /// Records a **negative** resolution (an entry with no addresses) so a recent
    /// failure is remembered — curl's `store_negative_resolve`
    /// (`lib/hostip.c:822`). Negative entries are timed (never permanent) and age
    /// twice as fast (see [`DnsEntry::is_stale`]). Logs *"Store negative name
    /// resolve for host:port"*.
    pub fn store_negative(&self, hostname: &str, port: u16) {
        let entry = Arc::new(DnsEntry::new(Address::default(), hostname, port, false));
        self.add(entry);
        tracing::info!("Store negative name resolve for {}:{}", hostname, port);
    }

    /// Prunes stale and excess entries — curl's `Curl_dnscache_prune`
    /// (`lib/hostip.c:322`).
    ///
    /// First every entry stale under `timeout` is dropped (permanent entries are
    /// exempt). Then, while the cache still exceeds [`MAX_DNS_CACHE_SIZE`], the
    /// oldest *timed* entry is evicted repeatedly — the observable effect of
    /// curl's "halve the age and re-prune" loop, which keeps the cache bounded
    /// without ever evicting permanent `CURLOPT_RESOLVE` entries.
    pub fn prune(&self, timeout: Duration) {
        let now = Instant::now();
        let mut map = self.lock();
        map.retain(|_, entry| !entry.is_stale(now, timeout));

        while map.len() > MAX_DNS_CACHE_SIZE {
            // Find the oldest timed (non-permanent) entry to evict.
            let oldest = map
                .iter()
                .filter_map(|(k, e)| match e.timestamp {
                    DnsTimestamp::Created(created) => Some((k.clone(), created)),
                    DnsTimestamp::Permanent => None,
                })
                .min_by_key(|(_, created)| *created)
                .map(|(k, _)| k);
            match oldest {
                Some(key) => {
                    map.remove(&key);
                }
                // Only permanent entries remain; nothing more can be pruned.
                None => break,
            }
        }
    }

    /// Empties the cache and clears the wildcard flag — curl's
    /// `Curl_dnscache_clear` (`lib/hostip.c:349`).
    pub fn clear(&self) {
        self.lock().clear();
        self.wildcard.store(false, Ordering::Relaxed);
    }

    /// Sets whether a wildcard (`*:port`) entry is present — curl's
    /// `data->state.wildcard_resolve`. [`DnsCache::get`] consults this for its
    /// wildcard fallback.
    pub fn set_wildcard(&self, enabled: bool) {
        self.wildcard.store(enabled, Ordering::Relaxed);
    }

    /// Returns whether wildcard resolution is enabled for this cache.
    #[must_use]
    pub fn wildcard_enabled(&self) -> bool {
        self.wildcard.load(Ordering::Relaxed)
    }

    /// The number of entries currently in the cache.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }
}

// ---------------------------------------------------------------------------
// Phase 5 — resolver trait, backend dispatch options, and IPv6 probing
// ---------------------------------------------------------------------------

/// The boxed future returned by [`Resolver::resolve`].
///
/// A boxed, `Send`, dynamically-typed future is used (instead of an `async fn`
/// in the trait) so [`Resolver`] stays object-safe — the [`resolve`]
/// orchestration holds backends as `&dyn Resolver` — and so the crate compiles
/// on the MSRV (Rust 1.75) with no `async_fn_in_trait` lint. `Send` allows a
/// resolution to run on the multi-threaded Tokio runtime used by the multi
/// handle.
pub type ResolveFuture<'a> = Pin<Box<dyn Future<Output = Result<Address>> + Send + 'a>>;

/// A pluggable name-resolution backend.
///
/// This is the idiomatic-Rust replacement for curl's compile-time resolver
/// selection (`Curl_async_getaddrinfo` / `Curl_sync_getaddrinfo` chosen by
/// `#ifdef CURLRES_THREADED` / `CURLRES_ARES` / `CURLRES_SYNCH`, `lib/asyn.h`).
/// Each backend module in this folder provides a type implementing this trait:
/// [`system`] (the default Tokio system resolver), [`doh`] (DNS-over-HTTPS), and
/// the optional `hickory`. The [`resolve`] orchestration owns the resolution
/// *policy* and dispatches the actual network lookup through this trait, so the
/// preprocessor branching of the C code becomes runtime trait dispatch
/// (AAP §0.3.2).
///
/// Implementations receive the requested [`IpVersion`] and should honor it as
/// curl's `getaddrinfo` `ai_family` hint does (`lib/asyn-thrdd.c`): resolve only
/// the requested family, or all families for [`IpVersion::Whatever`]. The
/// [`resolve`] orchestration additionally applies
/// [`Address::filter_by_ip_version`] to the result as a safety net.
pub trait Resolver: Send + Sync {
    /// Resolves `host`/`port` to an ordered [`Address`], honoring `ip_version`.
    ///
    /// The returned [`Address`] must preserve the backend's natural ordering (see
    /// the ordering contract on [`Address`]). On failure the future resolves to
    /// an [`Error`] (typically [`Error::resolve`], mapping to
    /// [`CurlCode::CouldntResolveHost`]).
    fn resolve<'a>(&'a self, host: &'a str, port: u16, ip_version: IpVersion) -> ResolveFuture<'a>;
}

/// Configuration for a single [`resolve`] call — the pieces of curl's
/// per-transfer state (`data->set.*`, `data->state.*`) and resolver selection
/// that the resolution policy consults.
///
/// The active backends are supplied here as trait objects rather than being
/// hard-wired: the connection layer picks the general resolver ([`system`] or,
/// when the `hickory-dns` feature is enabled, `hickory`) and, when DoH is
/// configured, the [`doh`] backend, and passes them in. This keeps the `dns`
/// root free of concrete backend-type references (see the module-level docs).
pub struct ResolveOptions<'a> {
    /// The general-purpose resolver (curl's threaded/`getaddrinfo` backend). This
    /// is the fallback used when no more specific path (literal IP, `localhost`,
    /// DoH) applies.
    pub resolver: &'a dyn Resolver,
    /// The DoH resolver, when `CURLOPT_DOH_URL` is configured. When `Some` (and
    /// `allow_doh` is passed to [`resolve`]), a non-literal host is resolved via
    /// DoH — curl's `data->set.doh` branch in `Curl_resolv`.
    pub doh: Option<&'a dyn Resolver>,
    /// Whether resolved address order should be shuffled — curl's
    /// `data->set.dns_shuffle_addresses`.
    pub shuffle_addresses: bool,
    /// Whether the local IPv6 stack works — curl's `Curl_ipv6works(data)`.
    /// Consulted by [`can_resolve_ip_version`]. Defaults to [`ipv6_works`] via
    /// [`ResolveOptions::new`].
    pub ipv6_works: bool,
    /// Whether numeric IP hosts should still be sent to the resolver instead of
    /// short-circuited — curl's `USE_RESOLVE_ON_IPS`. Default (`false`) matches a
    /// stock curl build, which shortcuts literal IPs.
    pub resolve_on_ips: bool,
    /// The DNS-cache entry timeout — curl's `data->set.dns_cache_timeout`.
    /// `None` means entries never expire (curl's `-1`).
    pub cache_timeout: Option<Duration>,
}

impl<'a> ResolveOptions<'a> {
    /// Builds options for the common case: a general `resolver`, no DoH, no
    /// shuffling, literal-IP shortcutting on, IPv6 probed via [`ipv6_works`], and
    /// the default 60-second cache timeout (curl's `CURLOPT_DNS_CACHE_TIMEOUT`
    /// default).
    #[must_use]
    pub fn new(resolver: &'a dyn Resolver) -> Self {
        ResolveOptions {
            resolver,
            doh: None,
            shuffle_addresses: false,
            ipv6_works: ipv6_works(),
            resolve_on_ips: false,
            cache_timeout: Some(Duration::from_secs(60)),
        }
    }
}

/// Cached result of the one-time IPv6 stack probe.
static IPV6_WORKS: OnceLock<bool> = OnceLock::new();

/// Returns whether the local IPv6 stack appears to work — curl's `Curl_probeipv6`
/// / `Curl_ipv6works` (`lib/hostip.c:747`).
///
/// As in curl, the probe runs **once** and the result is cached for the process
/// lifetime (IPv6 availability does not change during a run). The probe attempts
/// to create and bind an IPv6 UDP socket to the loopback address; success means
/// the IPv6 stack is usable. This is the safe-Rust equivalent of curl creating a
/// `PF_INET6` socket to test for support.
#[must_use]
pub fn ipv6_works() -> bool {
    *IPV6_WORKS.get_or_init(|| UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).is_ok())
}

/// Whether the requested `ip_version` can be satisfied — curl's
/// `can_resolve_ip_version` (`lib/hostip.c:807`).
///
/// A [`IpVersion::V6`]-only request cannot be honored when the IPv6 stack does
/// not work; every other combination is resolvable.
#[must_use]
pub fn can_resolve_ip_version(ip_version: IpVersion, ipv6_works: bool) -> bool {
    // De Morgan of `!(V6 && !ipv6_works)`: a V6-only request needs a working
    // IPv6 stack; anything else is always resolvable.
    ip_version != IpVersion::V6 || ipv6_works
}

// ---------------------------------------------------------------------------
// Phase 5/8/9 — resolution helpers (.onion, localhost, IDN, error bridging)
// ---------------------------------------------------------------------------

/// Returns `true` if `host` is a Tor `.onion` name that must **not** be resolved
/// (RFC 7686) — curl's `.onion` guard in `Curl_resolv` (`lib/hostip.c:887`).
///
/// Matches a trailing `.onion` or `.onion.` case-insensitively, requiring at
/// least one leading label (curl's `hostname_len >= 7` guard, i.e. `"x.onion"`
/// is the shortest match). Comparison is done on a lowercased copy, which is
/// UTF-8-safe (unlike curl's byte-offset `strequal`, which is safe only because
/// the suffix is ASCII).
fn is_onion(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    lower.len() >= 7 && (lower.ends_with(".onion") || lower.ends_with(".onion."))
}

/// Returns `true` if `host` names the loopback and should resolve without a
/// network lookup — curl's `localhost` check in `Curl_resolv`
/// (`lib/hostip.c:938`): exactly `"localhost"` / `"localhost."`, or any name
/// ending in `".localhost"` / `".localhost."`, all case-insensitive.
fn is_localhost(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    lower == "localhost"
        || lower == "localhost."
        || lower.ends_with(".localhost")
        || lower.ends_with(".localhost.")
}

/// Builds the synthetic loopback [`Address`] for a `localhost` name — curl's
/// `get_localhost` (`lib/hostip.c:710`).
///
/// The IPv6 loopback `::1` is placed **first**, then IPv4 `127.0.0.1`, exactly
/// as curl links the list (its `get_localhost6` node is prepended to the IPv4
/// node). Both families are always present regardless of `ip_version`; any
/// family preference is applied by the connection layer, matching curl, which
/// caches the full loopback list.
fn localhost_address(port: u16) -> Address {
    Address::new(vec![
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
    ])
}

/// Normalizes a hostname to its on-the-wire (A-label / ASCII) form before it is
/// used as a cache key or handed to a backend — mirroring curl's
/// `Curl_idnconvert_hostname` / `Curl_is_ASCII_name` gate (`lib/url.c`,
/// `lib/idn.c`).
///
/// A pure-ASCII name is returned unchanged (case preserved); a name containing
/// non-ASCII bytes is converted to its Punycode (`xn--…`) form. IDN processing is
/// **not** reimplemented here — it is delegated wholesale to
/// [`crate::idn::to_ascii`]. Case-insensitive matching for the cache key is
/// handled separately by [`DnsCache::cache_key`] (which lowercases).
fn normalize_host(host: &str) -> Result<String> {
    idn::to_ascii(host)
}

/// Produces the resolution [`Error`] for a failed lookup and emits the
/// `failf`-equivalent diagnostic — curl's `Curl_resolver_error`
/// (`lib/hostip.c:1570`).
///
/// A proxy failure maps to [`CurlCode::CouldntResolveProxy`] (**5**) with the
/// message *"Could not resolve proxy: NAME"*; a host failure maps to
/// [`CurlCode::CouldntResolveHost`] (**6**) with *"Could not resolve host:
/// NAME"*. The exact message text is preserved for `--trace` parity.
#[must_use]
pub fn resolver_error(name: &str, is_proxy: bool) -> Error {
    if is_proxy {
        tracing::error!("Could not resolve proxy: {name}");
        Error::resolve_proxy(name)
    } else {
        tracing::error!("Could not resolve host: {name}");
        Error::resolve(name)
    }
}

// ---------------------------------------------------------------------------
// Phase 5 — top-level resolution orchestration (← Curl_resolv, hostip.c:860)
// ---------------------------------------------------------------------------

/// Resolves `host`/`port` to a shared [`DnsEntry`], reproducing curl's
/// `Curl_resolv` (`lib/hostip.c:860`).
///
/// The resolution methods are tried in this exact, **parity-critical** order (do
/// not reorder — it is a behavioral contract):
///
/// 1. **DNS cache** — a hit is returned immediately (its [`Arc`] cloned, i.e.
///    curl's `refcount++`), logging *"Hostname H was found in DNS cache"*. A
///    cached **negative** entry yields a resolution failure ("Negative DNS
///    entry") without being re-stored.
/// 2. **`.onion` rejection** (RFC 7686) — mapped to
///    [`CurlCode::CouldntResolveHost`] with *"Not resolving .onion address (RFC
///    7686)"*.
/// 3. **Literal-IP shortcut** — a numeric host becomes an address directly, with
///    no network lookup (unless [`ResolveOptions::resolve_on_ips`] is set).
/// 4. **`localhost`** — resolves to the loopback list `[::1, 127.0.0.1]`.
/// 5. **DoH** — when `allow_doh` and a [`ResolveOptions::doh`] backend is
///    configured and the host is not a literal IP.
/// 6. **General resolver** — otherwise, via [`ResolveOptions::resolver`], after
///    confirming the family is resolvable ([`can_resolve_ip_version`]).
///
/// A successful lookup from steps 3–6 is stored in the cache as a **timed**
/// (non-permanent) entry; a definitive failure is recorded as a **negative**
/// cache entry and returned as a mapped [`Error`].
///
/// The `host` is first normalized to its A-label form (`normalize_host`); an
/// IDN conversion failure surfaces as whatever error `crate::idn` returns
/// (curl maps this to `CURLE_URL_MALFORMAT`), since curl converts the name
/// before resolving.
pub async fn resolve(
    cache: &DnsCache,
    host: &str,
    port: u16,
    ip_version: IpVersion,
    allow_doh: bool,
    opts: &ResolveOptions<'_>,
) -> Result<Arc<DnsEntry>> {
    // Normalize to the on-the-wire ASCII/A-label form used both as the cache key
    // and when handing the name to a backend. IDN is delegated to `crate::idn`.
    let host = normalize_host(host)?;
    let host = host.as_str();

    // (1) DNS cache — checked first (parity contract).
    if let Some(entry) = cache.get(host, port, ip_version, opts.cache_timeout) {
        if entry.is_negative() {
            // A remembered negative result (curl: "Negative DNS entry"). Report
            // the failure without re-storing it.
            tracing::info!("Negative DNS entry");
            return Err(Error::resolve(host));
        }
        tracing::info!("Hostname {} was found in DNS cache", host);
        return Ok(entry);
    }

    // (2) `.onion` — never resolved (RFC 7686). Intentionally NOT negative-cached
    // so that, under the cache-first ordering, every repeat lookup re-emits the
    // same rejection diagnostic (matching curl's per-lookup `.onion` behavior).
    if is_onion(host) {
        tracing::error!("Not resolving .onion address (RFC 7686)");
        return Err(Error::with_context(
            CurlCode::CouldntResolveHost,
            "Not resolving .onion address (RFC 7686)",
        ));
    }

    // (3) Literal-IP shortcut — a numeric host is turned straight into an
    // address with no network lookup, unless `resolve_on_ips` forces resolution.
    let is_literal = IpAddr::from_str(host).is_ok();
    if is_literal && !opts.resolve_on_ips {
        if let Some(addr) = Address::from_literal(host, port) {
            let entry = DnsCache::mk_entry(addr, host, port, false, opts.shuffle_addresses);
            cache.add(entry.clone());
            return Ok(entry);
        }
    }

    // (4) localhost → loopback (`[::1, 127.0.0.1]`, both families cached).
    if is_localhost(host) {
        let addr = localhost_address(port);
        let entry = DnsCache::mk_entry(addr, host, port, false, opts.shuffle_addresses);
        cache.add(entry.clone());
        return Ok(entry);
    }

    // (5)/(6) Select the backend: DoH for a non-literal host when DoH is allowed
    // and configured, otherwise the general resolver.
    let doh_backend = if !is_literal && allow_doh {
        opts.doh
    } else {
        None
    };

    let result = if let Some(doh) = doh_backend {
        // (5) DoH branch — curl's `data->set.doh` path. DoH handles the family
        // internally; curl performs no `can_resolve_ip_version` check here.
        doh.resolve(host, port, ip_version).await
    } else {
        // (6) General resolver. First confirm the requested family is
        // resolvable (a V6-only request needs a working IPv6 stack).
        if !can_resolve_ip_version(ip_version, opts.ipv6_works) {
            cache.store_negative(host, port);
            return Err(resolver_error(host, false));
        }
        opts.resolver.resolve(host, port, ip_version).await
    };

    match result {
        Ok(mut addr) => {
            // (7) Family filter (a safety net over the backend's own family
            // hint), then store the successful result as a timed cache entry.
            addr.filter_by_ip_version(ip_version);
            if addr.is_empty() {
                // The backend produced no usable address of the requested
                // family — a resolution failure.
                cache.store_negative(host, port);
                return Err(resolver_error(host, false));
            }
            let entry = DnsCache::mk_entry(addr, host, port, false, opts.shuffle_addresses);
            cache.add(entry.clone());
            Ok(entry)
        }
        // (8) Definitive failure — negative-cache and return the mapped error.
        Err(_) => {
            cache.store_negative(host, port);
            Err(resolver_error(host, false))
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 7 — CURLOPT_RESOLVE pre-population (← Curl_loadhostpairs, hostip.c:1279)
// ---------------------------------------------------------------------------

/// Parses the host portion of a `CURLOPT_RESOLVE` spec, returning
/// `(host, rest_at_colon)` or `None` if malformed.
///
/// A bracketed IPv6 host (`"[::1]"`) yields the bracket-free inner text and the
/// remainder after `]`; a bare host yields everything up to the first `:` and
/// the remainder starting at that `:`. `None` (unterminated bracket, or a bare
/// host with no `:` delimiter) is the case curl skips with `continue`.
fn parse_host_token(spec: &str) -> Option<(&str, &str)> {
    if let Some(after_open) = spec.strip_prefix('[') {
        let close = after_open.find(']')?;
        Some((&after_open[..close], &after_open[close + 1..]))
    } else {
        let colon = spec.find(':')?;
        Some((&spec[..colon], &spec[colon..]))
    }
}

/// Consumes the leading `:` and parses the port number, returning
/// `(port, rest_after_port)` or `None` if the `:` is missing or the number is
/// absent / out of range (curl's `str_number(..., 0xffff)`).
fn parse_port_token(rest: &str) -> Option<(u16, &str)> {
    let after_colon = rest.strip_prefix(':')?;
    let end = after_colon.find(':').unwrap_or(after_colon.len());
    let digits = &after_colon[..end];
    let value: u32 = digits.parse().ok()?;
    if value > 0xffff {
        return None;
    }
    Some((value as u16, &after_colon[end..]))
}

/// Parses the comma-separated address list of a `CURLOPT_RESOLVE` add-spec,
/// stamping `port` onto each. Each address may be a bracketed IPv6 literal.
/// Stray/leading/trailing commas are tolerated (curl "survive nothing but just a
/// comma"). Returns `None` if any address is not a valid IP, if there is junk
/// after a bracketed address, or if the list is empty (curl's `if(!head)`).
fn parse_addr_list(list: &str, port: u16) -> Option<Vec<SocketAddr>> {
    let mut out: Vec<SocketAddr> = Vec::new();
    let mut rest = list;
    while !rest.is_empty() {
        // Tolerate empty tokens produced by stray/leading/doubled commas.
        if let Some(next) = rest.strip_prefix(',') {
            rest = next;
            continue;
        }
        let (token, after) = if let Some(after_open) = rest.strip_prefix('[') {
            let close = after_open.find(']')?;
            (&after_open[..close], &after_open[close + 1..])
        } else {
            match rest.find(',') {
                Some(idx) => (&rest[..idx], &rest[idx..]),
                None => (rest, ""),
            }
        };
        let ip = IpAddr::from_str(token).ok()?;
        out.push(SocketAddr::new(ip, port));
        // A single trailing comma separates the next address; anything else
        // after a (bracketed) token is malformed.
        if let Some(next) = after.strip_prefix(',') {
            rest = next;
        } else if after.is_empty() {
            break;
        } else {
            return None;
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Parses the port + address list tail of an add-spec, after the host has been
/// extracted. Returns `(port, addresses, addr_list_str)` or `None` if malformed
/// (which the caller turns into [`CurlCode::SetoptOptionSyntax`]).
fn parse_add_tail(rest: &str) -> Option<(u16, Vec<SocketAddr>, &str)> {
    let (port, after_port) = parse_port_token(rest)?;
    let addr_str = after_port.strip_prefix(':')?;
    let addrs = parse_addr_list(addr_str, port)?;
    Some((port, addrs, addr_str))
}

/// Pre-populates the DNS cache from `CURLOPT_RESOLVE` / `--resolve` entries —
/// curl's `Curl_loadhostpairs` (`lib/hostip.c:1279`). Parsed exactly as curl
/// does:
///
/// * `"-host:port"` — **deletes** the matching cache entry. A malformed delete
///   spec is silently skipped (curl `continue`).
/// * `"+host:port:addr[,addr…]"` — adds a **non-permanent** (timed) entry.
/// * `"host:port:addr[,addr…]"` — adds a **permanent** entry that never times
///   out.
/// * `"[ipv6]"` bracket syntax is accepted for the host and for each address.
/// * `"*"` as the host installs a **wildcard** entry (key `*:port`) and enables
///   [`DnsCache`] wildcard fallback.
/// * Adding a host pair **replaces** any existing entry (old addresses
///   discarded).
///
/// A malformed *add* spec (bad port or address list) fails with
/// [`CurlCode::SetoptOptionSyntax`] and the message *"Could not parse
/// CURLOPT_RESOLVE entry 'ENTRY'"*, preserving curl's error text.
pub fn load_host_pairs(cache: &DnsCache, entries: &[String]) -> Result<()> {
    // curl resets `data->state.wildcard_resolve = FALSE` before (re)loading.
    cache.set_wildcard(false);

    for raw in entries {
        let entry = raw.as_str();
        if entry.is_empty() {
            continue;
        }

        // DELETE: "-host:port". Malformed delete specs are skipped, matching
        // curl's `continue` (they are not a hard error).
        if let Some(spec) = entry.strip_prefix('-') {
            if let Some((host, rest)) = parse_host_token(spec) {
                if let Some((port, _)) = parse_port_token(rest) {
                    cache.remove(host, port);
                }
            }
            continue;
        }

        // ADD: a leading '+' marks a non-permanent (timed) entry; otherwise the
        // entry is permanent (never times out).
        let (spec, permanent) = match entry.strip_prefix('+') {
            Some(rest) => (rest, false),
            None => (entry, true),
        };

        // A malformed host is skipped (curl `continue`); a malformed port /
        // address list is a hard SETOPT syntax error.
        let (host, rest) = match parse_host_token(spec) {
            Some(parsed) => parsed,
            None => continue,
        };
        let (port, addrs, addr_str) = match parse_add_tail(rest) {
            Some(parsed) => parsed,
            None => {
                return Err(Error::with_context(
                    CurlCode::SetoptOptionSyntax,
                    format!("Could not parse CURLOPT_RESOLVE entry '{raw}'"),
                ));
            }
        };

        let is_wildcard = host == "*";

        // Replace any existing entry (curl: "old addresses discarded").
        if cache.contains(host, port) {
            tracing::info!("RESOLVE {}:{} - old addresses discarded", host, port);
            cache.remove(host, port);
        }

        // Permanent entries never expire (timestamp == 0); '+' entries are timed.
        let entry_arc = DnsCache::mk_entry(Address::new(addrs), host, port, permanent, false);
        cache.add(entry_arc);

        tracing::info!(
            "Added {}:{}:{} to DNS cache{}",
            host,
            port,
            addr_str,
            if permanent { "" } else { " (non-permanent)" }
        );

        // A "*" host is a wildcard: subsequent lookups for any host on this port
        // fall back to it (curl sets `data->state.wildcard_resolve = TRUE`).
        if is_wildcard {
            tracing::info!("RESOLVE *:{} using wildcard", port);
            cache.set_wildcard(true);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    // -- test helpers -------------------------------------------------------

    /// Convenience IPv4 socket address for `1.2.3.4:port`.
    fn v4(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), port)
    }

    /// Convenience IPv6 socket address for `[2001:db8::1]:port`.
    fn v6(port: u16) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            port,
        )
    }

    /// A minimal, dependency-free executor that drives a future to completion.
    ///
    /// The [`resolve`] orchestration and the [`MockResolver`] futures used in
    /// these tests are always ready on the first poll (nothing truly pends), so
    /// a no-op waker suffices. This keeps the tests independent of which Tokio
    /// features `curl-rs-lib` happens to enable and MSRV-safe on Rust 1.75.
    fn block_on<F: Future>(fut: F) -> F::Output {
        use std::task::{Context, Poll, Wake, Waker};

        struct NoopWake;
        impl Wake for NoopWake {
            fn wake(self: Arc<Self>) {}
        }

        let waker = Waker::from(Arc::new(NoopWake));
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(fut);
        loop {
            if let Poll::Ready(value) = fut.as_mut().poll(&mut cx) {
                return value;
            }
        }
    }

    /// A test [`Resolver`] that returns a fixed address (or a failure) and counts
    /// how many times it was invoked, so tests can assert whether the network
    /// path was reached at all (e.g. that the literal-IP and cache shortcuts do
    /// **not** call the backend).
    struct MockResolver {
        addr: Address,
        fail: bool,
        calls: Arc<AtomicUsize>,
    }

    impl MockResolver {
        fn ok(endpoints: Vec<SocketAddr>) -> Self {
            MockResolver {
                addr: Address::new(endpoints),
                fail: false,
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn failing() -> Self {
            MockResolver {
                addr: Address::default(),
                fail: true,
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl Resolver for MockResolver {
        fn resolve<'a>(
            &'a self,
            host: &'a str,
            port: u16,
            _ip_version: IpVersion,
        ) -> ResolveFuture<'a> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let fail = self.fail;
            let mut addr = self.addr.clone();
            let host = host.to_string();
            Box::pin(async move {
                if fail {
                    Err(Error::resolve(host))
                } else {
                    // Backends stamp the requested port onto each endpoint,
                    // mirroring `Curl_addrinfo_set_port`.
                    addr.set_port(port);
                    Ok(addr)
                }
            })
        }
    }

    // -- IpVersion (frozen ABI values) --------------------------------------

    #[test]
    fn ip_version_abi_values_are_frozen() {
        // The integer discriminants are a frozen C ABI contract.
        assert_eq!(IpVersion::Whatever.as_i32(), 0);
        assert_eq!(IpVersion::V4.as_i32(), 1);
        assert_eq!(IpVersion::V6.as_i32(), 2);
        // Round-trip through the FFI integer bridge.
        assert_eq!(IpVersion::from(0), IpVersion::Whatever);
        assert_eq!(IpVersion::from(1), IpVersion::V4);
        assert_eq!(IpVersion::from(2), IpVersion::V6);
        // Unknown values fall back to the permissive default, as curl does.
        assert_eq!(IpVersion::from(99), IpVersion::Whatever);
        assert_eq!(IpVersion::from(-1), IpVersion::Whatever);
        assert_eq!(IpVersion::default(), IpVersion::Whatever);
    }

    #[test]
    fn ip_version_accepts_matches_family() {
        assert!(IpVersion::Whatever.accepts(&v4(80)));
        assert!(IpVersion::Whatever.accepts(&v6(80)));
        assert!(IpVersion::V4.accepts(&v4(80)));
        assert!(!IpVersion::V4.accepts(&v6(80)));
        assert!(IpVersion::V6.accepts(&v6(80)));
        assert!(!IpVersion::V6.accepts(&v4(80)));
    }

    // -- Address ------------------------------------------------------------

    #[test]
    fn address_from_ips_stamps_port_and_preserves_order() {
        let addr = Address::from_ips(
            [
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
            443,
        );
        assert_eq!(addr.len(), 2);
        assert!(!addr.is_empty());
        assert!(addr.endpoints()[0].is_ipv4());
        assert!(addr.endpoints()[1].is_ipv6());
        assert!(addr.endpoints().iter().all(|ep| ep.port() == 443));
    }

    #[test]
    fn address_set_port_updates_all_endpoints() {
        let mut addr = Address::new(vec![v4(80), v6(80)]);
        addr.set_port(8080);
        assert!(addr.endpoints().iter().all(|ep| ep.port() == 8080));
    }

    #[test]
    fn address_from_literal_parses_only_numeric_hosts() {
        assert!(Address::from_literal("127.0.0.1", 80).is_some());
        assert!(Address::from_literal("::1", 80).is_some());
        let v4addr = Address::from_literal("192.0.2.9", 80).unwrap();
        assert_eq!(v4addr.len(), 1);
        assert!(v4addr.endpoints()[0].is_ipv4());
        assert_eq!(v4addr.endpoints()[0].port(), 80);
        // Non-literals return None (a network lookup is required).
        assert!(Address::from_literal("example.com", 80).is_none());
        assert!(Address::from_literal("not-an-ip", 80).is_none());
        // Bare literal only — brackets are stripped by callers, not here.
        assert!(Address::from_literal("[::1]", 80).is_none());
    }

    #[test]
    fn address_filter_by_ip_version_retains_in_order() {
        let mixed = vec![v4(80), v6(80), v4(80)];

        let mut only_v4 = Address::new(mixed.clone());
        only_v4.filter_by_ip_version(IpVersion::V4);
        assert_eq!(only_v4.len(), 2);
        assert!(only_v4.endpoints().iter().all(SocketAddr::is_ipv4));

        let mut only_v6 = Address::new(mixed.clone());
        only_v6.filter_by_ip_version(IpVersion::V6);
        assert_eq!(only_v6.len(), 1);
        assert!(only_v6.endpoints()[0].is_ipv6());

        let mut whatever = Address::new(mixed.clone());
        whatever.filter_by_ip_version(IpVersion::Whatever);
        assert_eq!(whatever.endpoints(), mixed.as_slice());
    }

    #[test]
    fn address_has_family_reports_presence() {
        let mixed = Address::new(vec![v4(80), v6(80)]);
        assert!(mixed.has_family(IpVersion::V4));
        assert!(mixed.has_family(IpVersion::V6));
        assert!(mixed.has_family(IpVersion::Whatever));

        let v4_only = Address::new(vec![v4(80)]);
        assert!(v4_only.has_family(IpVersion::V4));
        assert!(!v4_only.has_family(IpVersion::V6));

        let negative = Address::default();
        assert!(!negative.has_family(IpVersion::Whatever));
        assert!(!negative.has_family(IpVersion::V4));
        assert!(!negative.has_family(IpVersion::V6));
    }

    #[test]
    fn address_canonical_name_and_ttl_round_trip() {
        let mut addr = Address::new(vec![v4(80)]);
        assert!(addr.canonical_name().is_none());
        assert!(addr.ttl().is_none());
        addr.set_canonical_name("host.example.");
        addr.set_ttl(Duration::from_secs(30));
        assert_eq!(addr.canonical_name(), Some("host.example."));
        assert_eq!(addr.ttl(), Some(Duration::from_secs(30)));
    }

    // -- DnsEntry / staleness ----------------------------------------------

    #[test]
    fn permanent_entry_never_stale() {
        let entry = DnsEntry::new(Address::new(vec![v4(80)]), "host", 80, true);
        assert!(entry.is_permanent());
        assert!(!entry.is_negative());
        // Even a far-future `now` with a zero timeout cannot make it stale.
        let now = Instant::now() + Duration::from_secs(1_000_000);
        assert!(!entry.is_stale(now, Duration::ZERO));
        assert!(!entry.is_stale(now, Duration::from_secs(1)));
    }

    #[test]
    fn timed_entry_staleness_boundary() {
        let entry = DnsEntry::new(Address::new(vec![v4(80)]), "host", 80, false);
        assert!(!entry.is_permanent());
        // Fresh entry with a generous timeout is not stale.
        assert!(!entry.is_stale(Instant::now(), Duration::from_secs(3600)));
        // A zero timeout makes any timed entry immediately stale (age >= 0).
        assert!(entry.is_stale(Instant::now(), Duration::ZERO));
    }

    #[test]
    fn negative_entry_ages_twice_as_fast() {
        // Both entries are created at ~t0; we then evaluate staleness at a `now`
        // 10 seconds later. The negative entry's age is doubled (~20s), so with
        // a 15s timeout it is stale while the positive entry (~10s) is not.
        let t0 = Instant::now();
        let negative = DnsEntry::new(Address::default(), "host", 80, false);
        let positive = DnsEntry::new(Address::new(vec![v4(80)]), "host", 80, false);
        assert!(negative.is_negative());

        let now = t0 + Duration::from_secs(10);
        assert!(negative.is_stale(now, Duration::from_secs(15)));
        assert!(!positive.is_stale(now, Duration::from_secs(15)));
        // With a 5s timeout even the (un-doubled) positive entry is stale.
        assert!(positive.is_stale(now, Duration::from_secs(5)));
    }

    // -- DnsCache -----------------------------------------------------------

    #[test]
    fn cache_key_is_lowercase_host_colon_port() {
        assert_eq!(DnsCache::cache_key("Example.COM", 80), "example.com:80");
        assert_eq!(DnsCache::cache_key("host", 443), "host:443");
        assert_eq!(DnsCache::wildcard_key(80), "*:80");
    }

    #[test]
    fn cache_add_get_contains_remove() {
        let cache = DnsCache::new();
        assert!(cache.is_empty());
        let entry = DnsCache::mk_entry(Address::new(vec![v4(80)]), "example.com", 80, true, false);
        cache.add(entry);
        assert_eq!(cache.len(), 1);
        assert!(cache.contains("example.com", 80));
        // Case-insensitive key: uppercase lookup still hits.
        assert!(cache.contains("EXAMPLE.COM", 80));
        assert!(cache
            .get("example.com", 80, IpVersion::Whatever, None)
            .is_some());

        let removed = cache.remove("example.com", 80);
        assert!(removed.is_some());
        assert!(!cache.contains("example.com", 80));
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_get_zaps_stale_entry() {
        let cache = DnsCache::new();
        let entry = DnsCache::mk_entry(Address::new(vec![v4(80)]), "host", 80, false, false);
        cache.add(entry);
        // A zero timeout makes the freshly-added timed entry stale on lookup, so
        // it is zapped and reported as a miss.
        assert!(cache
            .get("host", 80, IpVersion::Whatever, Some(Duration::ZERO))
            .is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_get_never_stale_when_timeout_none() {
        let cache = DnsCache::new();
        let entry = DnsCache::mk_entry(Address::new(vec![v4(80)]), "host", 80, false, false);
        cache.add(entry);
        // `None` timeout is curl's dns_cache_timeout == -1 ("forever"): no zap.
        assert!(cache.get("host", 80, IpVersion::Whatever, None).is_some());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_get_zaps_on_specific_family_mismatch() {
        let cache = DnsCache::new();
        let entry = DnsCache::mk_entry(Address::new(vec![v4(80)]), "host", 80, true, false);
        cache.add(entry);
        // The entry has only IPv4; a V6-specific lookup zaps it.
        assert!(cache.get("host", 80, IpVersion::V6, None).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_get_keeps_entry_on_matching_family() {
        let cache = DnsCache::new();
        let entry = DnsCache::mk_entry(Address::new(vec![v4(80)]), "host", 80, true, false);
        cache.add(entry);
        // A V4-specific lookup matches; the entry survives.
        assert!(cache.get("host", 80, IpVersion::V4, None).is_some());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_negative_entry_survives_whatever_lookup() {
        // A negative entry (empty addr) must NOT be zapped on a `Whatever`
        // lookup — curl skips the family check for CURL_IPRESOLVE_WHATEVER — so
        // it can be surfaced as a cached failure.
        let cache = DnsCache::new();
        cache.store_negative("host", 80);
        let hit = cache.get("host", 80, IpVersion::Whatever, None);
        assert!(hit.is_some());
        assert!(hit.unwrap().is_negative());
        // A specific-family lookup, however, zaps the (family-less) negative
        // entry.
        cache.store_negative("host2", 80);
        assert!(cache.get("host2", 80, IpVersion::V4, None).is_none());
    }

    #[test]
    fn cache_wildcard_fallback() {
        let cache = DnsCache::new();
        let entry = DnsCache::mk_entry(Address::new(vec![v4(80)]), "*", 80, true, false);
        cache.add(entry);
        // Without the wildcard flag, an unrelated host is a miss.
        assert!(cache
            .get("anything.example", 80, IpVersion::Whatever, None)
            .is_none());
        // With the wildcard flag set, the `*:80` entry is used as a fallback.
        cache.set_wildcard(true);
        assert!(cache.wildcard_enabled());
        assert!(cache
            .get("anything.example", 80, IpVersion::Whatever, None)
            .is_some());
        // But only for the matching port.
        assert!(cache
            .get("anything.example", 443, IpVersion::Whatever, None)
            .is_none());
    }

    #[test]
    fn cache_clear_empties_and_resets_wildcard() {
        let cache = DnsCache::new();
        cache.add(DnsCache::mk_entry(
            Address::new(vec![v4(80)]),
            "host",
            80,
            true,
            false,
        ));
        cache.set_wildcard(true);
        cache.clear();
        assert!(cache.is_empty());
        assert!(!cache.wildcard_enabled());
    }

    #[test]
    fn cache_prune_drops_stale_keeps_permanent() {
        let cache = DnsCache::new();
        cache.add(DnsCache::mk_entry(
            Address::new(vec![v4(80)]),
            "permanent",
            80,
            true,
            false,
        ));
        cache.add(DnsCache::mk_entry(
            Address::new(vec![v4(80)]),
            "timed",
            80,
            false,
            false,
        ));
        // A zero timeout prunes every timed entry but never the permanent one.
        cache.prune(Duration::ZERO);
        assert!(cache.contains("permanent", 80));
        assert!(!cache.contains("timed", 80));
    }

    #[test]
    fn cache_is_shared_across_clones() {
        // Cloning a DnsCache clones the Arc — both handles see the same entries
        // (the curl_share / CURL_LOCK_DATA_DNS model).
        let cache = DnsCache::new();
        let clone = cache.clone();
        cache.add(DnsCache::mk_entry(
            Address::new(vec![v4(80)]),
            "shared",
            80,
            true,
            false,
        ));
        assert!(clone.contains("shared", 80));
        assert_eq!(clone.len(), 1);
    }

    // -- can_resolve_ip_version / helpers -----------------------------------

    #[test]
    fn can_resolve_ip_version_rules() {
        // V6 requires a working IPv6 stack; everything else is always resolvable.
        assert!(can_resolve_ip_version(IpVersion::Whatever, false));
        assert!(can_resolve_ip_version(IpVersion::V4, false));
        assert!(!can_resolve_ip_version(IpVersion::V6, false));
        assert!(can_resolve_ip_version(IpVersion::V6, true));
    }

    #[test]
    fn onion_detection() {
        assert!(is_onion("example.onion"));
        assert!(is_onion("EXAMPLE.ONION"));
        assert!(is_onion("sub.example.onion."));
        assert!(!is_onion("example.com"));
        // Too short to be "x.onion" (must have a leading label).
        assert!(!is_onion(".onion"));
        assert!(!is_onion("onion"));
    }

    #[test]
    fn localhost_detection_and_address_order() {
        assert!(is_localhost("localhost"));
        assert!(is_localhost("localhost."));
        assert!(is_localhost("LocalHost"));
        assert!(is_localhost("foo.localhost"));
        assert!(is_localhost("foo.localhost."));
        assert!(!is_localhost("localhost.example.com"));
        assert!(!is_localhost("notlocalhost"));

        // curl's get_localhost lists IPv6 (::1) FIRST, then IPv4 (127.0.0.1).
        let addr = localhost_address(80);
        assert_eq!(addr.len(), 2);
        assert!(addr.endpoints()[0].is_ipv6());
        assert!(addr.endpoints()[1].is_ipv4());
        assert_eq!(addr.endpoints()[0].ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(addr.endpoints()[1].ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    // -- resolver_error (error bridging, frozen CURLcode integers) ----------

    #[test]
    fn resolver_error_maps_to_frozen_codes() {
        let host_err = resolver_error("example.com", false);
        assert_eq!(host_err.code(), CurlCode::CouldntResolveHost);
        assert_eq!(host_err.code() as i32, 6);

        let proxy_err = resolver_error("proxy.example", true);
        assert_eq!(proxy_err.code(), CurlCode::CouldntResolveProxy);
        assert_eq!(proxy_err.code() as i32, 5);
    }

    // -- resolve() orchestration (Curl_resolv parity flow) ------------------

    #[test]
    fn resolve_returns_cache_hit_without_calling_backend() {
        let cache = DnsCache::new();
        cache.add(DnsCache::mk_entry(
            Address::new(vec![v4(80)]),
            "example.com",
            80,
            true,
            false,
        ));
        let resolver = MockResolver::ok(vec![v4(80)]);
        let opts = ResolveOptions::new(&resolver);

        let entry = block_on(resolve(
            &cache,
            "example.com",
            80,
            IpVersion::Whatever,
            false,
            &opts,
        ))
        .unwrap();
        assert_eq!(entry.endpoints().len(), 1);
        // A cache hit must not reach the network backend.
        assert_eq!(resolver.calls(), 0);
    }

    #[test]
    fn resolve_negative_cache_hit_is_failure() {
        let cache = DnsCache::new();
        cache.store_negative("bad.example", 80);
        let resolver = MockResolver::ok(vec![v4(80)]);
        let opts = ResolveOptions::new(&resolver);

        let err = block_on(resolve(
            &cache,
            "bad.example",
            80,
            IpVersion::Whatever,
            false,
            &opts,
        ))
        .unwrap_err();
        assert_eq!(err.code(), CurlCode::CouldntResolveHost);
        // The backend is not consulted on a negative-cache hit.
        assert_eq!(resolver.calls(), 0);
    }

    #[test]
    fn resolve_rejects_onion_addresses() {
        let cache = DnsCache::new();
        let resolver = MockResolver::ok(vec![v4(80)]);
        let opts = ResolveOptions::new(&resolver);

        let err = block_on(resolve(
            &cache,
            "secret.onion",
            80,
            IpVersion::Whatever,
            false,
            &opts,
        ))
        .unwrap_err();
        assert_eq!(err.code(), CurlCode::CouldntResolveHost);
        assert_eq!(resolver.calls(), 0);
        // `.onion` is intentionally NOT negative-cached.
        assert!(cache.is_empty());
    }

    #[test]
    fn resolve_literal_ip_shortcut_skips_backend() {
        let cache = DnsCache::new();
        let resolver = MockResolver::ok(vec![v4(80)]);
        let opts = ResolveOptions::new(&resolver);

        let entry = block_on(resolve(
            &cache,
            "192.0.2.10",
            8080,
            IpVersion::Whatever,
            false,
            &opts,
        ))
        .unwrap();
        assert_eq!(entry.endpoints().len(), 1);
        assert!(entry.endpoints()[0].is_ipv4());
        assert_eq!(entry.endpoints()[0].port(), 8080);
        // No network resolution for a literal IP.
        assert_eq!(resolver.calls(), 0);
        // The result is cached.
        assert!(cache.contains("192.0.2.10", 8080));
    }

    #[test]
    fn resolve_localhost_returns_loopback_without_backend() {
        let cache = DnsCache::new();
        let resolver = MockResolver::ok(vec![v4(80)]);
        let opts = ResolveOptions::new(&resolver);

        let entry = block_on(resolve(
            &cache,
            "localhost",
            80,
            IpVersion::Whatever,
            false,
            &opts,
        ))
        .unwrap();
        // Both loopback families are present, IPv6 first.
        assert_eq!(entry.endpoints().len(), 2);
        assert!(entry.endpoints()[0].is_ipv6());
        assert!(entry.endpoints()[1].is_ipv4());
        assert_eq!(resolver.calls(), 0);
    }

    #[test]
    fn resolve_uses_general_backend_and_caches_result() {
        let cache = DnsCache::new();
        let resolver = MockResolver::ok(vec![v4(0), v4(0)]);
        let opts = ResolveOptions::new(&resolver);

        let entry = block_on(resolve(
            &cache,
            "example.com",
            80,
            IpVersion::Whatever,
            false,
            &opts,
        ))
        .unwrap();
        assert_eq!(entry.endpoints().len(), 2);
        assert!(entry.endpoints().iter().all(|ep| ep.port() == 80));
        assert_eq!(resolver.calls(), 1);

        // A second lookup is served from the cache (backend not called again).
        let _ = block_on(resolve(
            &cache,
            "example.com",
            80,
            IpVersion::Whatever,
            false,
            &opts,
        ))
        .unwrap();
        assert_eq!(resolver.calls(), 1);
    }

    #[test]
    fn resolve_dispatches_to_doh_when_allowed() {
        let cache = DnsCache::new();
        let general = MockResolver::ok(vec![v4(80)]);
        let doh = MockResolver::ok(vec![v6(80)]);
        let mut opts = ResolveOptions::new(&general);
        opts.doh = Some(&doh);

        let entry = block_on(resolve(
            &cache,
            "example.com",
            80,
            IpVersion::Whatever,
            true, // allow_doh
            &opts,
        ))
        .unwrap();
        // DoH backend answered (IPv6), general backend untouched.
        assert!(entry.endpoints()[0].is_ipv6());
        assert_eq!(doh.calls(), 1);
        assert_eq!(general.calls(), 0);
    }

    #[test]
    fn resolve_skips_doh_when_not_allowed() {
        let cache = DnsCache::new();
        let general = MockResolver::ok(vec![v4(80)]);
        let doh = MockResolver::ok(vec![v6(80)]);
        let mut opts = ResolveOptions::new(&general);
        opts.doh = Some(&doh);

        let _ = block_on(resolve(
            &cache,
            "example.com",
            80,
            IpVersion::Whatever,
            false, // allow_doh = false
            &opts,
        ))
        .unwrap();
        // With DoH disallowed, the general resolver is used instead.
        assert_eq!(general.calls(), 1);
        assert_eq!(doh.calls(), 0);
    }

    #[test]
    fn resolve_v6_request_fails_without_ipv6_and_skips_backend() {
        let cache = DnsCache::new();
        let resolver = MockResolver::ok(vec![v6(80)]);
        let mut opts = ResolveOptions::new(&resolver);
        opts.ipv6_works = false;

        let err = block_on(resolve(
            &cache,
            "example.com",
            80,
            IpVersion::V6,
            false,
            &opts,
        ))
        .unwrap_err();
        assert_eq!(err.code(), CurlCode::CouldntResolveHost);
        // The family gate fails before the backend is invoked.
        assert_eq!(resolver.calls(), 0);
        // The failure is negative-cached.
        let cached = cache.get("example.com", 80, IpVersion::Whatever, None);
        assert!(cached.is_some());
        assert!(cached.unwrap().is_negative());
    }

    #[test]
    fn resolve_family_filter_empties_result_into_failure() {
        // Backend returns only IPv4 but a V6 answer was requested; after the
        // family filter the address is empty, which is a resolution failure.
        let cache = DnsCache::new();
        let resolver = MockResolver::ok(vec![v4(80)]);
        let mut opts = ResolveOptions::new(&resolver);
        opts.ipv6_works = true; // pass the can_resolve gate

        let err = block_on(resolve(
            &cache,
            "example.com",
            80,
            IpVersion::V6,
            false,
            &opts,
        ))
        .unwrap_err();
        assert_eq!(err.code(), CurlCode::CouldntResolveHost);
        assert_eq!(resolver.calls(), 1);
    }

    #[test]
    fn resolve_backend_failure_is_negative_cached() {
        let cache = DnsCache::new();
        let resolver = MockResolver::failing();
        let opts = ResolveOptions::new(&resolver);

        let err = block_on(resolve(
            &cache,
            "nxdomain.example",
            80,
            IpVersion::Whatever,
            false,
            &opts,
        ))
        .unwrap_err();
        assert_eq!(err.code(), CurlCode::CouldntResolveHost);
        assert_eq!(resolver.calls(), 1);
        // The failure is remembered as a negative entry.
        let cached = cache.get("nxdomain.example", 80, IpVersion::Whatever, None);
        assert!(cached.is_some());
        assert!(cached.unwrap().is_negative());
    }

    // -- load_host_pairs (CURLOPT_RESOLVE parsing) --------------------------

    #[test]
    fn load_host_pairs_adds_permanent_entry() {
        let cache = DnsCache::new();
        load_host_pairs(&cache, &["example.com:80:192.0.2.1".to_string()]).unwrap();
        let entry = cache
            .get("example.com", 80, IpVersion::Whatever, None)
            .unwrap();
        assert!(entry.is_permanent());
        assert_eq!(entry.endpoints().len(), 1);
        assert_eq!(
            entry.endpoints()[0].ip(),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
        );
        assert_eq!(entry.endpoints()[0].port(), 80);
    }

    #[test]
    fn load_host_pairs_plus_prefix_is_non_permanent() {
        let cache = DnsCache::new();
        load_host_pairs(&cache, &["+example.com:80:192.0.2.1".to_string()]).unwrap();
        let entry = cache
            .get("example.com", 80, IpVersion::Whatever, None)
            .unwrap();
        assert!(!entry.is_permanent());
    }

    #[test]
    fn load_host_pairs_multiple_addresses_preserve_order() {
        let cache = DnsCache::new();
        load_host_pairs(
            &cache,
            &["example.com:80:192.0.2.1,192.0.2.2,192.0.2.3".to_string()],
        )
        .unwrap();
        let entry = cache
            .get("example.com", 80, IpVersion::Whatever, None)
            .unwrap();
        assert_eq!(entry.endpoints().len(), 3);
        assert_eq!(
            entry.endpoints()[0].ip(),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
        );
        assert_eq!(
            entry.endpoints()[2].ip(),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3))
        );
    }

    #[test]
    fn load_host_pairs_accepts_bracketed_ipv6() {
        let cache = DnsCache::new();
        load_host_pairs(&cache, &["[::1]:443:[2001:db8::1]".to_string()]).unwrap();
        let entry = cache.get("::1", 443, IpVersion::Whatever, None).unwrap();
        assert_eq!(entry.endpoints().len(), 1);
        assert!(entry.endpoints()[0].is_ipv6());
        assert_eq!(entry.endpoints()[0].port(), 443);
    }

    #[test]
    fn load_host_pairs_delete_removes_entry() {
        let cache = DnsCache::new();
        load_host_pairs(&cache, &["example.com:80:192.0.2.1".to_string()]).unwrap();
        assert!(cache.contains("example.com", 80));
        // A "-host:port" spec deletes the entry.
        load_host_pairs(&cache, &["-example.com:80".to_string()]).unwrap();
        assert!(!cache.contains("example.com", 80));
    }

    #[test]
    fn load_host_pairs_wildcard_sets_flag_and_fallback() {
        let cache = DnsCache::new();
        load_host_pairs(&cache, &["*:80:192.0.2.1".to_string()]).unwrap();
        assert!(cache.wildcard_enabled());
        // Any host on port 80 now falls back to the wildcard entry.
        let entry = cache
            .get("whatever.example", 80, IpVersion::Whatever, None)
            .unwrap();
        assert_eq!(entry.endpoints().len(), 1);
    }

    #[test]
    fn load_host_pairs_replaces_existing_entry() {
        let cache = DnsCache::new();
        load_host_pairs(&cache, &["example.com:80:192.0.2.1".to_string()]).unwrap();
        // Re-adding replaces the old addresses.
        load_host_pairs(&cache, &["example.com:80:192.0.2.99".to_string()]).unwrap();
        let entry = cache
            .get("example.com", 80, IpVersion::Whatever, None)
            .unwrap();
        assert_eq!(entry.endpoints().len(), 1);
        assert_eq!(
            entry.endpoints()[0].ip(),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99))
        );
    }

    #[test]
    fn load_host_pairs_malformed_add_is_syntax_error() {
        let cache = DnsCache::new();
        // Missing the address list is a hard SETOPT syntax error.
        let err = load_host_pairs(&cache, &["example.com:80".to_string()]).unwrap_err();
        assert_eq!(err.code(), CurlCode::SetoptOptionSyntax);

        // A non-numeric address is likewise a syntax error.
        let err = load_host_pairs(&cache, &["example.com:80:not-an-ip".to_string()]).unwrap_err();
        assert_eq!(err.code(), CurlCode::SetoptOptionSyntax);

        // An out-of-range port is a syntax error.
        let err =
            load_host_pairs(&cache, &["example.com:99999:192.0.2.1".to_string()]).unwrap_err();
        assert_eq!(err.code(), CurlCode::SetoptOptionSyntax);
    }

    #[test]
    fn load_host_pairs_malformed_delete_is_skipped() {
        let cache = DnsCache::new();
        // A malformed delete spec (no port) is silently skipped, not an error.
        load_host_pairs(&cache, &["-example.com".to_string()]).unwrap();
        assert!(cache.is_empty());
    }

    #[test]
    fn load_host_pairs_resets_wildcard_each_call() {
        let cache = DnsCache::new();
        load_host_pairs(&cache, &["*:80:192.0.2.1".to_string()]).unwrap();
        assert!(cache.wildcard_enabled());
        // A subsequent load with no wildcard entry clears the flag (curl resets
        // data->state.wildcard_resolve = FALSE at the start of the load).
        load_host_pairs(&cache, &["example.com:80:192.0.2.1".to_string()]).unwrap();
        assert!(!cache.wildcard_enabled());
    }
}
