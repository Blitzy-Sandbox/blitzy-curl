// SPDX-License-Identifier: curl
//
//! DNS subsystem root — the resolver abstraction and the DNS cache.
//!
//! This module is the memory-safe Rust reimplementation of the
//! method-independent half of libcurl's name-resolution machinery, curl's
//! `lib/hostip.c` (`lib/hostip.h`). It owns the pieces every resolver backend
//! shares: the resolved-address output type ([`ResolvedAddrs`]), the cache
//! entry ([`DnsEntry`]) and cache ([`DnsCache`]) that replace curl's
//! `Curl_dns_entry` / `Curl_dnscache`, the cache-id construction and TTL/prune
//! rules, the central resolve flow ([`resolve`]) that mirrors `Curl_resolv`,
//! the `CURLOPT_RESOLVE` loader ([`load_host_pairs`]) that mirrors
//! `Curl_loadhostpairs`, and the `AsynchDNS` capability signal ([`ASYNC_DNS`])
//! that `version.rs` consults.
//!
//! The three resolver *backends* live in sibling submodules and all produce the
//! single [`ResolvedAddrs`] type this module defines:
//!
//! * [`system`] — the default backend, the Tokio/standard-library resolver.
//!   It is the async analog of curl's threaded resolver (`asyn-thrdd.c`) and is
//!   always compiled in.
//! * [`doh`] — DNS-over-HTTPS (`lib/doh.c`), selected when a DoH URL is
//!   configured and allowed for the transfer.
//! * [`hickory`] — the optional pure-Rust async resolver behind the
//!   `hickory-dns` Cargo feature (curl's `USE_ARES` analog, default **off**).
//!
//! # Behavioral parity (the C file is a REFERENCE oracle, not a transliteration)
//!
//! `lib/hostip.c` defines *behavior and semantics only*; this module is
//! idiomatic, safe Rust, not a line-by-line port. The externally observable
//! contract is reproduced exactly because the immutable `tests/data` regression
//! definitions pin it down (Agent Action Plan §0.6 G6/G7, §0.8.2): the cache-id
//! format, the TTL/prune rules (including that negative entries age twice as
//! fast and that permanent `CURLOPT_RESOLVE` entries never expire), the resolve
//! ordering (`.onion` rejection → cache → literal-IP shortcut → `localhost`
//! shortcut → backend), the result codes, and the `CURLOPT_RESOLVE` line syntax.
//!
//! `lib/asyn-ares.c` (the c-ares binding) is deliberately **out of scope** — the
//! AAP removes c-ares (§0.3.2 / §0.6.2) — and is neither referenced nor
//! reproduced here. The async orchestration that curl's `asyn-base.c` performed
//! by hand around a background resolver thread is replaced by ordinary `async`
//! futures: "resolution in progress" is simply an unresolved future, so there
//! is no internal `CURLE_AGAIN` state to track (see the FFI-mapping note on
//! [`resolve`]).
//!
//! # Memory safety
//!
//! Per the project mandate (AAP §0.7.1 / §0.8.1) this module contains **zero
//! `unsafe`** and is compiled under `#![forbid(unsafe_code)]`, which also
//! applies to the resolver-backend submodules. curl's hand-rolled reference
//! counting (`Curl_dns_entry::refcount` + `Curl_resolv_unlink`) is replaced by
//! [`Arc`]: cache entries are shared as `Arc<DnsEntry>`, so cloning shares and
//! `Drop` frees automatically. IP literals are parsed with [`std::net`]
//! (`IpAddr`/`SocketAddr`), the safe analogue of curl's `inet_pton` /
//! `Curl_str2addr`.
//!
//! # Thread-safety / sharing
//!
//! [`DnsCache`] (and [`DnsEntry`]) are `Send + Sync`, so `crate::share` can wrap
//! the cache in `Arc<Mutex<…>>` for the `CURL_LOCK_DATA_DNS` shared cache, and
//! `crate::easy` can hold a per-handle cache. This module performs no locking of
//! its own — the cache is borrowed `&mut` for mutation and `&` for reads, and
//! the owner (a per-handle cache or a shared `Mutex`) decides the locking
//! discipline. The resolve flow never holds a cache borrow across an `.await`,
//! so a caller using a shared cache can lock for the lookup, release for the
//! network round-trip, and re-lock for the insert.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use crate::error::{CurlError, Result};
use crate::idn;
use crate::util::strparse::{curlx_str_casecompare, Str};
use crate::util::timeval::{curlx_now, curlx_timediff_ms, CurlTime};

// ---------------------------------------------------------------------------
// Resolver backend submodules.
//
// `system` and `doh` are always compiled; `hickory` is gated behind the
// optional `hickory-dns` feature (curl's `USE_ARES` analog, default OFF), so a
// `--no-default-features` build — or any build without that feature — does not
// reference it. All three expose an `async fn resolve(...) -> Result<ResolvedAddrs>`
// consumed by [`resolve`] in this file; this module is authored first so that
// type/contract surface is fixed before the backends are filled in.
// ---------------------------------------------------------------------------
pub mod doh;
pub mod system;

#[cfg(feature = "hickory-dns")]
pub mod hickory;

// ---------------------------------------------------------------------------
// Capability signal — `AsynchDNS` (consumed by `version.rs`).
// ---------------------------------------------------------------------------

/// The `CURL_VERSION_ASYNCHDNS` capability bit (`1 << 7`).
///
/// Reproduced here from `include/curl/curl.h` purely for documentation and for
/// the lockstep relationship with [`ASYNC_DNS`]. The authoritative place that
/// ORs this bit into `curl_version_info`'s feature mask is `version.rs`; this
/// constant lets the two modules refer to the same value by name.
pub const CURL_VERSION_ASYNCHDNS: u32 = 1 << 7;

/// Whether an asynchronous resolver is compiled in.
///
/// The default [`system`] resolver is the async analog of curl's threaded
/// resolver (curl's `CURLRES_THREADED`, which implies `CURLRES_ASYNCH`), so this
/// is `true` in the default build — matching curl reporting `AsynchDNS` by
/// default. `version.rs` reads this to decide whether to OR in
/// [`CURL_VERSION_ASYNCHDNS`].
///
/// # The `AsynchDNS` coupling (AAP §0.7.3)
///
/// There are two readings of how `AsynchDNS` should be reported, and they must
/// be reconciled so this module and `version.rs` stay in lockstep:
///
/// * *Reading 1 (literal):* `version.rs` adds the `AsynchDNS` bit only when the
///   `hickory-dns` feature is on (treating an explicit async backend as the
///   trigger, mirroring `USE_ARES`).
/// * *Reading 2 (parity-correct, recommended):* curl's **default** build
///   enables the threaded resolver, which defines `CURLRES_ASYNCH`, so
///   `curl --version` reports `AsynchDNS` **by default** (verified at
///   `lib/version.c:457-459`: `FEATURE("AsynchDNS", NULL, CURL_VERSION_ASYNCHDNS)`
///   guarded by `#ifdef CURLRES_ASYNCH`). c-ares is merely an *alternative*
///   async backend, not the thing that turns the capability on. Because the
///   [`system`] backend is always compiled and *is* the async analog of the
///   threaded resolver, `AsynchDNS` is effectively always-on in the default
///   build.
///
/// This module exposes `ASYNC_DNS = true` and recommends Reading 2 so the Rust
/// `curl --version` matches curl 8.x's default build. The final authority for
/// the bit is `version.rs`; keeping the two in lockstep is what this constant
/// (and this doc) exist to guarantee. The [`hickory`] backend is unambiguously
/// `#[cfg(feature = "hickory-dns")]`, default **off**, and never changes this
/// signal.
pub const ASYNC_DNS: bool = true;

// ---------------------------------------------------------------------------
// Cache sizing / timeout constants (← lib/hostip.c, lib/hostip.h).
// ---------------------------------------------------------------------------

/// Hard cap on the number of entries kept in the DNS cache
/// (`MAX_DNS_CACHE_SIZE`, `lib/hostip.c:78`). When [`DnsCache::prune`] finds the
/// cache still larger than this after a normal timeout pass, it re-prunes with
/// progressively halved age limits until the cache fits (or nothing more can be
/// dropped).
pub const MAX_DNS_CACHE_SIZE: usize = 29999;

/// Maximum length of a cache-id string: a full FQDN (255) plus the `:`, the
/// decimal port, and the terminating NUL (`MAX_HOSTCACHE_LEN = 255 + 7`,
/// `lib/hostip.c:76`). The Rust cache key is an owned [`String`] that carries
/// its own length, so this constant is informational / parity-documentation: it
/// is the width of the fixed C buffer the id was formatted into.
pub const MAX_HOSTCACHE_LEN: usize = 255 + 7;

/// curl's `CURL_HOSTENT_SIZE` (`lib/hostip.h:36`) — the size of the scratch
/// buffer the C resolver used to hold a `struct hostent` and all of its alias /
/// address storage. It has no functional role in the Rust port (addresses are
/// owned [`Vec`]s), and is reproduced only for parity documentation.
pub const CURL_HOSTENT_SIZE: usize = 9000;

/// Seconds an asynchronous name resolve is allowed to run
/// (`CURL_TIMEOUT_RESOLVE`, `lib/hostip.h:38`). It is the default per-resolve
/// wall-clock budget honored by [`resolve_timeout`].
pub const CURL_TIMEOUT_RESOLVE: u64 = 300;

/// Default value of `CURLOPT_DNS_CACHE_TIMEOUT`, in milliseconds (curl's
/// default is 60 seconds). Owned by `easy`/`setopt`; surfaced here as the
/// documented default for the `max_age_ms` arguments threaded through the cache
/// API. The sentinel values are: `-1` = entries never expire, `0` = caching
/// disabled (non-permanent entries are immediately stale), positive = maximum
/// age in milliseconds.
pub const DEFAULT_DNS_CACHE_TIMEOUT_MS: i64 = 60_000;

/// Sentinel for "DNS cache entries never expire" (`CURLOPT_DNS_CACHE_TIMEOUT`
/// set to `-1`). When the configured timeout equals this value the stale check
/// is skipped entirely.
pub const DNS_CACHE_TIMEOUT_NEVER: i64 = -1;

// ===========================================================================
// Phase B — the resolved-address output type and the IP-version preference.
// ===========================================================================

/// The set of socket addresses a host resolved to.
///
/// This is the single output type every resolver backend ([`system`], [`doh`],
/// [`hickory`]) produces and the cache stores. It is the idiomatic replacement
/// for curl's `Curl_addrinfo` linked list (`lib/curl_addrinfo.h`): a flat
/// [`Vec`] of [`SocketAddr`] unifies the IPv4/IPv6 family split and folds the
/// port into each entry, so consumers no longer walk `ai_next` or inspect
/// `ai_family`/`ai_addr` by hand.
///
/// An **empty** `addrs` is meaningful: it marks a *negative* (failed) resolve
/// when stored in a [`DnsEntry`] (see [`DnsEntry::is_negative`]).
///
/// Address *ordering* is preserved as produced by the backend (optionally
/// shuffled, see [`ResolvedAddrs::shuffle`]); Happy-Eyeballs interleaving and
/// connection ordering are **not** done here — that is handed off to
/// `crate::conn::happy_eyeballs`, which receives this set verbatim.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResolvedAddrs {
    /// The resolved socket addresses (host + port), in backend order. Empty
    /// denotes a negative resolve when held by a cached [`DnsEntry`].
    pub addrs: Vec<SocketAddr>,
}

impl ResolvedAddrs {
    /// Creates an empty address set (a negative result).
    #[must_use]
    pub const fn new() -> Self {
        ResolvedAddrs { addrs: Vec::new() }
    }

    /// Wraps an existing vector of socket addresses.
    #[must_use]
    pub const fn from_vec(addrs: Vec<SocketAddr>) -> Self {
        ResolvedAddrs { addrs }
    }

    /// Builds a single-address set from one [`IpAddr`] and a port — the safe
    /// analogue of curl's `Curl_str2addr` result for one literal address.
    #[must_use]
    pub fn from_ip(ip: IpAddr, port: u16) -> Self {
        ResolvedAddrs {
            addrs: vec![SocketAddr::new(ip, port)],
        }
    }

    /// Returns `true` when no addresses were resolved (a negative result).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }

    /// Returns the number of resolved addresses.
    #[must_use]
    pub fn len(&self) -> usize {
        self.addrs.len()
    }

    /// Iterates the resolved socket addresses in order.
    pub fn iter(&self) -> std::slice::Iter<'_, SocketAddr> {
        self.addrs.iter()
    }

    /// Returns `true` if at least one address of the given [`IpVersion`] family
    /// is present. [`IpVersion::Any`] matches whenever any address exists. This
    /// backs the cache's family-match check (curl's `fetch_addr` family scan).
    #[must_use]
    pub fn has_family(&self, ip_version: IpVersion) -> bool {
        match ip_version {
            IpVersion::Any => !self.addrs.is_empty(),
            _ => self.addrs.iter().any(|a| ip_version.matches(a)),
        }
    }

    /// Randomly shuffles the address order in place (Fisher-Yates), the safe
    /// analogue of curl's `Curl_shuffle_addr`, used when
    /// `CURLOPT_DNS_SHUFFLE_ADDRESSES` is set. A set of fewer than two addresses
    /// is left untouched.
    pub fn shuffle(&mut self) {
        if self.addrs.len() > 1 {
            use rand::seq::SliceRandom;
            self.addrs.shuffle(&mut rand::thread_rng());
        }
    }
}

/// The IP-version preference for a resolve, mirroring curl's `CURLOPT_IPRESOLVE`
/// values exactly (`CURL_IPRESOLVE_WHATEVER` = 0, `CURL_IPRESOLVE_V4` = 1,
/// `CURL_IPRESOLVE_V6` = 2). It selects which address family the backend is
/// asked for and which family a cached entry must contain to be reused.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum IpVersion {
    /// `CURL_IPRESOLVE_WHATEVER` (0) — no preference; accept any family.
    #[default]
    Any,
    /// `CURL_IPRESOLVE_V4` (1) — restrict to IPv4.
    V4,
    /// `CURL_IPRESOLVE_V6` (2) — restrict to IPv6.
    V6,
}

impl IpVersion {
    /// Maps a raw `CURLOPT_IPRESOLVE` integer to an [`IpVersion`]. Any value
    /// other than `1` (V4) or `2` (V6) — including the documented `0`
    /// (`WHATEVER`) — maps to [`IpVersion::Any`], matching curl's treatment of
    /// the option as "whatever" unless explicitly V4 or V6.
    #[must_use]
    pub const fn from_raw(value: i64) -> Self {
        match value {
            1 => IpVersion::V4,
            2 => IpVersion::V6,
            _ => IpVersion::Any,
        }
    }

    /// Returns the raw `CURLOPT_IPRESOLVE` integer for this preference.
    #[must_use]
    pub const fn as_raw(self) -> i64 {
        match self {
            IpVersion::Any => 0,
            IpVersion::V4 => 1,
            IpVersion::V6 => 2,
        }
    }

    /// Returns `true` if the given address belongs to this version's family.
    /// [`IpVersion::Any`] matches every address.
    #[must_use]
    pub const fn matches(self, addr: &SocketAddr) -> bool {
        match self {
            IpVersion::Any => true,
            IpVersion::V4 => addr.is_ipv4(),
            IpVersion::V6 => addr.is_ipv6(),
        }
    }
}

// ===========================================================================
// Phase C — the cache entry (`DnsEntry`) and the cache (`DnsCache`).
// ===========================================================================

/// One cached name-resolution result — the Rust analog of curl's
/// `struct Curl_dns_entry` (`lib/hostip.h`).
///
/// Unlike the C struct, there is **no manual `refcount` field**: entries are
/// shared as [`Arc<DnsEntry>`], so cloning the `Arc` shares the entry and the
/// last `Drop` frees it. This replaces curl's `refcount` together with
/// `Curl_resolv_unlink` / `dnscache_entry_dtor` wholesale.
///
/// An entry whose [`addrs`](DnsEntry::addrs) is empty is a *negative* entry —
/// the in-cache record of a failed resolve (curl stores these via
/// `store_negative_resolve`). Negative entries age twice as fast during pruning
/// (see [`DnsCache::prune`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsEntry {
    /// The resolved socket addresses. Empty denotes a negative (failed) resolve.
    pub addrs: ResolvedAddrs,
    /// When the entry was created, used for staleness. `None` marks a
    /// **permanent** entry (a `CURLOPT_RESOLVE` entry without the `+` prefix)
    /// that never expires — the analog of curl's `timestamp == 0` sentinel.
    pub timestamp: Option<CurlTime>,
    /// The port this entry was resolved for (curl's `hostport`).
    pub hostport: u16,
    /// The (already IDN-/ACE-encoded) hostname this entry was resolved for.
    pub hostname: String,
}

impl DnsEntry {
    /// Returns `true` for a permanent entry (a prefix-less `CURLOPT_RESOLVE`
    /// entry) that pruning never removes (curl's `timestamp == 0`).
    #[must_use]
    pub const fn is_permanent(&self) -> bool {
        self.timestamp.is_none()
    }

    /// Returns `true` for a negative entry — a cached failed resolve carrying no
    /// addresses (curl's `!dns->addr`).
    #[must_use]
    pub fn is_negative(&self) -> bool {
        self.addrs.is_empty()
    }
}

/// The DNS cache — the Rust analog of curl's `struct Curl_dnscache`.
///
/// Backed by a [`HashMap`] keyed by the cache id ([`create_dnscache_id`]) with
/// [`Arc<DnsEntry>`] values. A plain `HashMap` is used (rather than the sibling
/// `crate::util::hash::CurlHash`) because the keys are owned [`String`]s and the
/// only specialised operation required — predicate pruning equivalent to curl's
/// `Curl_hash_clean_with_criterium` — is expressed directly with
/// [`HashMap::retain`]; this keeps the type free of any extra abstraction while
/// preserving the exact prune semantics (see [`DnsCache::prune`]).
///
/// Both `DnsCache` and [`DnsEntry`] are `Send + Sync`, so `crate::share` can
/// wrap a cache in `Arc<Mutex<…>>` for the `CURL_LOCK_DATA_DNS` shared cache and
/// `crate::easy` can hold a per-handle cache. This type performs no locking
/// itself: mutating operations take `&mut self`, so the owner's `Mutex` (shared
/// case) or unique ownership (per-handle case) provides the required exclusion.
#[derive(Clone, Debug, Default)]
pub struct DnsCache {
    /// Cache id → shared entry.
    entries: HashMap<String, Arc<DnsEntry>>,
    /// Set when a `CURLOPT_RESOLVE` `*` (wildcard) entry has been loaded; makes
    /// [`DnsCache::lookup`] / [`DnsCache::get`] fall back to the `*:PORT` key on
    /// an exact-host miss (curl's `data->state.wildcard_resolve`).
    wildcard_resolve: bool,
}

impl DnsCache {
    /// Creates an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty cache pre-sized for `size` entries — the analog of
    /// curl's `Curl_dnscache_init(dns, size)`. `size` is a capacity hint only;
    /// the cache still grows as needed and is still bounded at prune time by
    /// [`MAX_DNS_CACHE_SIZE`].
    #[must_use]
    pub fn init(size: usize) -> Self {
        DnsCache {
            entries: HashMap::with_capacity(size),
            wildcard_resolve: false,
        }
    }

    /// Returns whether a `CURLOPT_RESOLVE` wildcard (`*`) entry is active.
    #[must_use]
    pub const fn wildcard_resolve(&self) -> bool {
        self.wildcard_resolve
    }

    /// Sets the wildcard-resolve flag. [`load_host_pairs`] clears it before
    /// (re)loading and sets it when it encounters a `*` host, exactly as curl's
    /// `Curl_loadhostpairs` manages `data->state.wildcard_resolve`.
    pub fn set_wildcard_resolve(&mut self, on: bool) {
        self.wildcard_resolve = on;
    }

    /// Number of entries currently held (curl's `Curl_hash_count`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Parity-named alias of [`DnsCache::len`] (curl's `Curl_hash_count`).
    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Removes every entry (curl's `Curl_dnscache_clear` / `Curl_hash_clean`).
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Read-only lookup by host + port with the wildcard fallback, but **no**
    /// staleness or family filtering — the equivalent of a bare
    /// `Curl_hash_pick`. On an exact-host miss, and only when a wildcard entry
    /// is active, the `*:PORT` key is tried (curl's `fetch_addr` wildcard
    /// retry). Returns a shared clone of the entry, or `None`.
    ///
    /// Use [`DnsCache::get`] for the full resolve-path lookup that also evicts
    /// stale / wrong-family entries.
    #[must_use]
    pub fn lookup(&self, host: &str, port: u16) -> Option<Arc<DnsEntry>> {
        let id = create_dnscache_id(host, port);
        if let Some(entry) = self.entries.get(&id) {
            return Some(Arc::clone(entry));
        }
        if self.wildcard_resolve {
            let wid = create_dnscache_id("*", port);
            if let Some(entry) = self.entries.get(&wid) {
                return Some(Arc::clone(entry));
            }
        }
        None
    }

    /// Exact-id lookup (no wildcard fallback, no eviction) — the direct analog
    /// of curl's `Curl_hash_pick(entry_id)` used by `Curl_loadhostpairs` to
    /// detect a pre-existing entry.
    #[must_use]
    pub fn get_by_id(&self, id: &str) -> Option<Arc<DnsEntry>> {
        self.entries.get(id).map(Arc::clone)
    }

    /// Full resolve-path cache fetch — the analog of curl's `fetch_addr`
    /// (`lib/hostip.c`). It performs the wildcard-aware lookup and then, exactly
    /// as curl does, *evicts* (zaps) the entry it found when it is unusable:
    ///
    /// * **Stale** — only checked when `max_age_ms != -1`. When the entry is
    ///   stale (see [`prune`](DnsCache::prune) for the aging rule, including the
    ///   2× factor for negative entries) it is removed and `None` is returned,
    ///   logging *"Hostname in DNS cache was stale, zapped"*.
    /// * **Wrong family** — only checked when `ip_version != Any`. When no
    ///   address of the requested family is present (which, as in curl,
    ///   includes every negative entry) the entry is removed and `None`
    ///   returned, logging *"Hostname in DNS cache does not have needed family,
    ///   zapped"*.
    ///
    /// Otherwise the shared entry is returned.
    pub fn get(
        &mut self,
        host: &str,
        port: u16,
        ip_version: IpVersion,
        max_age_ms: i64,
        now: CurlTime,
        verbose: bool,
    ) -> Option<Arc<DnsEntry>> {
        // Resolve the id that actually matched so the right key can be zapped.
        let id = create_dnscache_id(host, port);
        let (matched_id, entry) = if let Some(entry) = self.entries.get(&id) {
            (id, Arc::clone(entry))
        } else if self.wildcard_resolve {
            let wid = create_dnscache_id("*", port);
            match self.entries.get(&wid) {
                Some(entry) => (wid, Arc::clone(entry)),
                None => return None,
            }
        } else {
            return None;
        };

        // Staleness eviction (skipped entirely when caching "never expires").
        if max_age_ms != DNS_CACHE_TIMEOUT_NEVER && entry_is_stale(&entry, now, max_age_ms) {
            crate::infof!(verbose, "Hostname in DNS cache was stale, zapped");
            self.entries.remove(&matched_id);
            return None;
        }

        // Family eviction: a specific IP version was requested but this entry
        // carries no address of that family (a negative entry never does).
        if ip_version != IpVersion::Any && !entry.addrs.has_family(ip_version) {
            crate::infof!(
                verbose,
                "Hostname in DNS cache does not have needed family, zapped"
            );
            self.entries.remove(&matched_id);
            return None;
        }

        Some(entry)
    }

    /// Inserts `entry`, keyed by its own hostname + port, replacing any existing
    /// entry under the same id (curl's `Curl_dnscache_add` / `Curl_hash_add`
    /// replace-on-collision). Returns the now-shared entry.
    pub fn add(&mut self, entry: Arc<DnsEntry>) -> Arc<DnsEntry> {
        let id = create_dnscache_id(&entry.hostname, entry.hostport);
        self.entries.insert(id, Arc::clone(&entry));
        entry
    }

    /// Removes the entry for `host` + `port`. Returns `true` if one was present
    /// (curl's `Curl_hash_delete`, whose "ignore if absent" behavior this
    /// mirrors via the boolean result).
    pub fn remove(&mut self, host: &str, port: u16) -> bool {
        let id = create_dnscache_id(host, port);
        self.entries.remove(&id).is_some()
    }

    /// Removes the entry stored under an already-built cache id. Returns `true`
    /// if one was present. Used by [`load_host_pairs`], which constructs the id
    /// once for both the existence check and the deletion.
    pub fn remove_by_id(&mut self, id: &str) -> bool {
        self.entries.remove(id).is_some()
    }

    /// Builds a shared cache entry — the analog of curl's
    /// `Curl_dnscache_mk_entry`. When `shuffle` is set the addresses are
    /// randomly reordered first (curl's `dns_shuffle_addresses` path); a
    /// `permanent` entry gets no timestamp (`None`, never stale) while a normal
    /// entry is stamped with `now`.
    #[must_use]
    pub fn mk_entry(
        mut addrs: ResolvedAddrs,
        hostname: &str,
        port: u16,
        permanent: bool,
        shuffle: bool,
        now: CurlTime,
    ) -> Arc<DnsEntry> {
        if shuffle {
            addrs.shuffle();
        }
        Arc::new(DnsEntry {
            addrs,
            timestamp: if permanent { None } else { Some(now) },
            hostport: port,
            hostname: hostname.to_string(),
        })
    }

    // -----------------------------------------------------------------------
    // Phase D — TTL / prune.
    // -----------------------------------------------------------------------

    /// Prunes stale entries — the analog of curl's `Curl_dnscache_prune`.
    ///
    /// `max_age_ms` is `CURLOPT_DNS_CACHE_TIMEOUT` in milliseconds:
    ///
    /// * `-1` ([`DNS_CACHE_TIMEOUT_NEVER`]) — entries never expire; this is a
    ///   no-op.
    /// * `0` — caching disabled; every non-permanent entry is immediately stale.
    /// * positive — the maximum age, in milliseconds, for a non-permanent entry.
    ///
    /// Permanent entries (those with no timestamp) are always kept. A *negative*
    /// entry ages twice as fast (its computed age is doubled), matching curl's
    /// `dnscache_entry_is_stale`.
    ///
    /// After a normal pass, if the cache still exceeds [`MAX_DNS_CACHE_SIZE`] the
    /// age limit is lowered to half the oldest surviving entry's age and the
    /// pass repeats — curl's `do { … } while(timeout_ms)` shrink loop — until
    /// the cache fits or the limit reaches zero.
    pub fn prune(&mut self, max_age_ms: i64, now: CurlTime) {
        if max_age_ms == DNS_CACHE_TIMEOUT_NEVER {
            // -1: the cache never expires, so there is nothing to prune.
            return;
        }

        let mut timeout_ms = max_age_ms;
        loop {
            let oldest_ms = self.prune_pass(timeout_ms, now);
            if self.entries.len() > MAX_DNS_CACHE_SIZE {
                // Still too big: re-prune over half the oldest surviving age.
                timeout_ms = oldest_ms / 2;
            } else {
                break;
            }
            // C's `while(timeout_ms)`: stop once the limit collapses to zero.
            if timeout_ms == 0 {
                break;
            }
        }
    }

    /// A single prune pass: removes every stale non-permanent entry and returns
    /// the age (ms) of the oldest entry that was *kept*, mirroring curl's
    /// `dnscache_prune` + `dnscache_entry_is_stale` callback.
    fn prune_pass(&mut self, max_age_ms: i64, now: CurlTime) -> i64 {
        let mut oldest_ms: i64 = 0;
        self.entries.retain(|_id, entry| {
            match entry.timestamp {
                // Permanent entry: never stale, always kept.
                None => true,
                Some(ts) => {
                    let mut age = curlx_timediff_ms(now, ts);
                    if entry.is_negative() {
                        // Negative entries age twice as fast.
                        age = age.saturating_mul(2);
                    }
                    if age >= max_age_ms {
                        false // stale → remove
                    } else {
                        if age > oldest_ms {
                            oldest_ms = age;
                        }
                        true // fresh → keep
                    }
                }
            }
        });
        oldest_ms
    }
}

/// Builds the DNS cache id for a host + port — the analog of curl's
/// `create_dnscache_id` (`lib/hostip.c`).
///
/// The id is `"<lowercased-host>:<port>"`. The host is lowercased with ASCII
/// case folding (curl's `Curl_strntolower`) so that lookups are
/// case-insensitive, and — for parity with curl's fixed `MAX_HOSTCACHE_LEN`
/// buffer — a host longer than `MAX_HOSTCACHE_LEN - 7` (255) is truncated. By
/// the time a host reaches the cache it has already been IDN-/ACE-encoded and is
/// therefore ASCII, so the (defensive) character-based truncation here coincides
/// with curl's byte-based truncation.
#[must_use]
pub fn create_dnscache_id(host: &str, port: u16) -> String {
    const MAX_HOST: usize = MAX_HOSTCACHE_LEN - 7; // 255 — curl's `buflen - 7`.
    let lowered = host.to_ascii_lowercase();
    if lowered.len() > MAX_HOST {
        // Defensive truncation; never reached for real (ASCII) hostnames.
        let truncated: String = lowered.chars().take(MAX_HOST).collect();
        format!("{truncated}:{port}")
    } else {
        format!("{lowered}:{port}")
    }
}

/// Staleness predicate — the analog of curl's `dnscache_entry_is_stale`.
///
/// Permanent entries (no timestamp) are never stale. For a timestamped entry the
/// age in milliseconds is `now - timestamp`; a negative entry's age is doubled
/// (it ages twice as fast). The entry is stale when its (possibly doubled) age
/// is greater than or equal to `max_age_ms`.
fn entry_is_stale(entry: &DnsEntry, now: CurlTime, max_age_ms: i64) -> bool {
    match entry.timestamp {
        None => false,
        Some(ts) => {
            let mut age = curlx_timediff_ms(now, ts);
            if entry.is_negative() {
                age = age.saturating_mul(2);
            }
            age >= max_age_ms
        }
    }
}

// ===========================================================================
// Phase E — the central resolve flow.
// ===========================================================================

/// Inputs to a single name resolution.
///
/// This bundles the per-transfer DNS configuration that curl reads from
/// `data->set` / `data->conn` inside `Curl_resolv`, so the resolve free
/// functions stay small and the caller (`crate::transfer` / `crate::conn`) fills
/// in one place. It is `Copy`, so the blocking/timeout wrappers can cheaply
/// derive an adjusted copy.
#[derive(Clone, Copy, Debug)]
pub struct ResolveParams<'a> {
    /// The host to resolve. Callers pass the *unbracketed* host (curl's
    /// `conn->host.name`); IDN/non-ASCII hosts are converted to their `xn--`
    /// ACE form by [`resolve`] before use.
    pub host: &'a str,
    /// The port the connection targets; folded into every resolved
    /// [`SocketAddr`] and into the cache id.
    pub port: u16,
    /// `CURLOPT_IPRESOLVE` — restrict resolution to a single address family.
    pub ip_version: IpVersion,
    /// `CURLOPT_DOH_URL`, when configured. DoH is used only when this is `Some`,
    /// [`allow_doh`](ResolveParams::allow_doh) is set, and the host is not an IP
    /// literal.
    pub doh_url: Option<&'a str>,
    /// Whether DoH is permitted for this particular resolution (curl's
    /// `allowDOH` argument to `Curl_resolv`). [`resolve_blocking`] forces this
    /// to `false`.
    pub allow_doh: bool,
    /// `CURLOPT_DNS_CACHE_TIMEOUT` in milliseconds — `-1` never expires, `0`
    /// disables caching, positive is the max entry age. Passed to the cache
    /// lookup so a stale entry is evicted rather than reused.
    pub dns_cache_timeout_ms: i64,
    /// `CURLOPT_DNS_SHUFFLE_ADDRESSES` — randomize the resolved address order
    /// before caching.
    pub shuffle: bool,
    /// curl's `USE_RESOLVE_ON_IPS`: when `true`, an IP-literal host is sent
    /// through the resolver backend instead of being short-circuited. Defaults
    /// to `false` (curl's default), i.e. IP literals are used directly.
    pub resolve_ip_literals: bool,
    /// When `true`, a resolve failure is reported as
    /// [`CurlError::CouldntResolveProxy`] instead of
    /// [`CurlError::CouldntResolveHost`]. curl performs this host→proxy mapping
    /// in its connect code; modeling it here via a flag keeps the distinction
    /// without a second entrypoint.
    pub is_proxy: bool,
    /// `CURLOPT_VERBOSE` — gate the informational resolve logging.
    pub verbose: bool,
}

impl<'a> ResolveParams<'a> {
    /// Builds parameters for resolving `host:port` with curl's defaults: any IP
    /// family, no DoH URL, DoH permitted, the default 60 s cache timeout, no
    /// shuffle, IP literals short-circuited, host (not proxy) error mapping, and
    /// non-verbose. Adjust the public fields as needed before calling
    /// [`resolve`].
    #[must_use]
    pub const fn new(host: &'a str, port: u16) -> Self {
        ResolveParams {
            host,
            port,
            ip_version: IpVersion::Any,
            doh_url: None,
            allow_doh: true,
            dns_cache_timeout_ms: DEFAULT_DNS_CACHE_TIMEOUT_MS,
            shuffle: false,
            resolve_ip_literals: false,
            is_proxy: false,
            verbose: false,
        }
    }
}

/// Resolves a hostname to a cached [`DnsEntry`], the analog of curl's
/// `Curl_resolv` (`lib/hostip.c`).
///
/// The flow reproduces curl's ordering exactly:
///
/// 1. **IDN → ACE.** A non-ASCII host is converted to its `xn--` form up front
///    (via [`crate::idn::to_ascii`]) so every later step — the `.onion` check,
///    the cache key, and the backend query — operates on the ASCII host curl's
///    resolver would see. Conversion is a no-op for ASCII hosts.
/// 2. **`.onion` rejection** (RFC 7686): a host of length ≥ 7 ending in
///    `.onion` or `.onion.` is refused with [`CurlError::CouldntResolveHost`].
/// 3. **Cache lookup** ([`DnsCache::get`]): a positive hit returns immediately;
///    a *negative* hit is itself a resolve failure.
/// 4. **Literal-IP shortcut**: an IP-literal host is used directly (unless
///    [`ResolveParams::resolve_ip_literals`] is set).
/// 5. **`localhost` shortcut**: `localhost`, `localhost.`, and any `.localhost`
///    / `.localhost.` host synthesize loopback addresses without a query.
/// 6. **Backend dispatch**: DoH when configured + permitted for a non-IP host,
///    otherwise the system resolver (or hickory, under that feature).
/// 7. **Success**: a non-permanent entry is cached and returned.
/// 8. **Failure**: a [`CurlError::CouldntResolveHost`] outcome stores a negative
///    cache entry (which ages twice as fast) before the error is returned.
///
/// # Async / FFI mapping
///
/// Because resolution is modeled as an `async fn`, "resolution in progress" is
/// simply this future being unresolved — there is no internal `CURLE_AGAIN`
/// state as in curl's threaded resolver. The FFI layer that drives a synchronous
/// C `curl_easy_perform` runs this future to completion (`block_on`); a
/// `curl_multi_*` driver polls it. `CURLE_AGAIN` is therefore only ever
/// synthesized at the FFI boundary, never here.
///
/// # Errors
///
/// * [`CurlError::CouldntResolveHost`] (or [`CurlError::CouldntResolveProxy`]
///   when [`ResolveParams::is_proxy`] is set) — the host could not be resolved,
///   including a negative cache hit and the `.onion` refusal.
/// * Any error surfaced by [`crate::idn::to_ascii`] for a malformed IDN host.
/// * Errors propagated unchanged from the resolver backend (for example
///   [`CurlError::OperationTimedout`] or [`CurlError::OutOfMemory`]).
pub async fn resolve(
    cache: &mut DnsCache,
    params: &ResolveParams<'_>,
    errbuf: &mut Option<String>,
) -> Result<Arc<DnsEntry>> {
    let verbose = params.verbose;
    let port = params.port;
    let ip_version = params.ip_version;
    let now = curlx_now();

    // (1) IDN → ACE, hoisted so the cache key and the .onion check both see the
    // ASCII host (curl's `Curl_resolv` always receives the already-encoded
    // host). `to_ascii` is an ASCII passthrough, so this is observably identical
    // for ASCII hosts; an IDN error propagates unchanged.
    let ace_host: String;
    let host: &str = if idn::needs_idn(params.host) {
        ace_host = idn::to_ascii(params.host)?;
        &ace_host
    } else {
        params.host
    };

    // (2) Refuse to resolve .onion addresses (RFC 7686). curl guards with
    // length >= 7, so a bare ".onion" (6 bytes) is intentionally *not* rejected.
    if host.len() >= 7 && (ends_with_ci(host, ".onion") || ends_with_ci(host, ".onion.")) {
        crate::failf!(errbuf, "Not resolving .onion address (RFC 7686)");
        return Err(resolve_error(params.is_proxy));
    }

    // (3) DNS cache first. A hit short-circuits the resolve; a negative hit
    // (cached failure) is itself an error.
    if let Some(entry) = cache.get(
        host,
        port,
        ip_version,
        params.dns_cache_timeout_ms,
        now,
        verbose,
    ) {
        crate::infof!(verbose, "Hostname {host} was found in DNS cache");
        if entry.is_negative() {
            crate::infof!(verbose, "Negative DNS entry");
            return Err(resolve_error(params.is_proxy));
        }
        return Ok(entry);
    }

    // (4)-(6) Perform the actual resolution.
    match resolve_addrs(host, params).await {
        Ok(addrs) if !addrs.is_empty() => {
            // (7) Success: cache (non-permanent), log, return.
            let entry = DnsCache::mk_entry(addrs, host, port, false, params.shuffle, now);
            let stored = cache.add(entry);
            show_resolve_info(&stored, verbose);
            Ok(stored)
        }
        Ok(_) => {
            // A backend that succeeds with zero addresses is a failed resolve.
            store_negative_resolve(cache, host, port, now, verbose);
            Err(resolve_error(params.is_proxy))
        }
        Err(CurlError::CouldntResolveHost) | Err(CurlError::CouldntResolveProxy) => {
            // (8) Remember the failure as a negative entry (ages 2× as fast).
            store_negative_resolve(cache, host, port, now, verbose);
            Err(resolve_error(params.is_proxy))
        }
        // Timeout / OOM / IDN and other errors pass through unchanged.
        Err(other) => Err(other),
    }
}

/// Steps (4)–(6) of [`resolve`]: produce the address set for `host`, either from
/// a shortcut (IP literal / `localhost`) or a resolver backend. Returns the
/// resolved addresses (possibly empty, which the caller treats as a failure) or
/// an error.
async fn resolve_addrs(host: &str, params: &ResolveParams<'_>) -> Result<ResolvedAddrs> {
    let port = params.port;
    let ip_version = params.ip_version;

    // (4) Literal-IP shortcut: an IP literal is used directly unless the caller
    // explicitly asked to resolve IPs (curl's `USE_RESOLVE_ON_IPS`).
    let literal = parse_ip_literal(host);
    if !params.resolve_ip_literals {
        if let Some(ip) = literal {
            return Ok(ResolvedAddrs::from_ip(ip, port));
        }
    }

    // (5) localhost shortcut: synthesize loopback addresses without a query.
    if is_localhost(host) {
        return Ok(localhost_addrs(port));
    }

    // (6) Backend dispatch. DoH is used only for a non-IP host when a DoH URL is
    // configured and permitted; otherwise the system (or hickory) resolver.
    if literal.is_none() && params.allow_doh {
        if let Some(doh_url) = params.doh_url {
            return doh::resolve(doh_url, host, port, ip_version).await;
        }
    }

    // Bail before querying if V6 is required but no IPv6 support is built in.
    if !can_resolve_ip_version(ip_version) {
        return Err(CurlError::CouldntResolveHost);
    }

    resolve_via_system_backend(host, port, ip_version).await
}

/// Selects the non-DoH resolver backend at compile time: the optional
/// `hickory-dns` backend when that feature is enabled, otherwise the default
/// system resolver. Both implement the same
/// `async fn resolve(host, port, ip_version) -> Result<ResolvedAddrs>` contract.
async fn resolve_via_system_backend(
    host: &str,
    port: u16,
    ip_version: IpVersion,
) -> Result<ResolvedAddrs> {
    #[cfg(feature = "hickory-dns")]
    {
        hickory::resolve(host, port, ip_version).await
    }
    #[cfg(not(feature = "hickory-dns"))]
    {
        system::resolve(host, port, ip_version).await
    }
}

/// Resolves with DoH disabled — the analog of curl's `Curl_resolv_blocking`,
/// which calls `Curl_resolv` with `allowDOH = FALSE`. (In curl the "blocking"
/// aspect is awaiting the threaded resolver; here awaiting the returned future
/// *is* the blocking step, performed by the caller.)
///
/// # Errors
///
/// Same as [`resolve`].
pub async fn resolve_blocking(
    cache: &mut DnsCache,
    params: &ResolveParams<'_>,
    errbuf: &mut Option<String>,
) -> Result<Arc<DnsEntry>> {
    let mut p = *params;
    p.allow_doh = false;
    resolve(cache, &p, errbuf).await
}

/// Resolves with a wall-clock deadline — the analog of curl's
/// `Curl_resolv_timeout`.
///
/// * `timeout_ms < 0` — an already-expired timeout: returns
///   [`CurlError::OperationTimedout`] immediately, without resolving.
/// * `timeout_ms == 0`, or a DoH URL is configured — no deadline is applied
///   (curl never interrupts a DoH resolve with its alarm), so this behaves like
///   [`resolve`].
/// * otherwise the resolve is bounded by `timeout_ms`; exceeding it yields
///   [`CurlError::OperationTimedout`].
///
/// # Errors
///
/// [`CurlError::OperationTimedout`] on expiry, otherwise as [`resolve`].
pub async fn resolve_timeout(
    cache: &mut DnsCache,
    params: &ResolveParams<'_>,
    errbuf: &mut Option<String>,
    timeout_ms: i64,
) -> Result<Arc<DnsEntry>> {
    if timeout_ms < 0 {
        // Already-expired timeout (curl returns CURLE_OPERATION_TIMEDOUT here).
        return Err(CurlError::OperationTimedout);
    }

    // curl skips its alarm timeout when no timeout is requested or when the
    // resolve will go through DoH (`data->set.doh`).
    let doh_configured = params.doh_url.is_some();
    if timeout_ms == 0 || doh_configured {
        return resolve(cache, params, errbuf).await;
    }

    let dur = std::time::Duration::from_millis(timeout_ms as u64);
    match tokio::time::timeout(dur, resolve(cache, params, errbuf)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(CurlError::OperationTimedout),
    }
}

// ---------------------------------------------------------------------------
// Resolve-flow helpers (file-private unless they form part of the public API).
// ---------------------------------------------------------------------------

/// Maps a resolve failure to the proxy or host error code per `is_proxy`.
fn resolve_error(is_proxy: bool) -> CurlError {
    if is_proxy {
        CurlError::CouldntResolveProxy
    } else {
        CurlError::CouldntResolveHost
    }
}

/// ASCII case-insensitive "does `host` end with `suffix`?" — the analog of
/// curl's `curl_strequal(&host[len - n], suffix)` tail comparisons.
fn ends_with_ci(host: &str, suffix: &str) -> bool {
    let hb = host.as_bytes();
    let sb = suffix.as_bytes();
    hb.len() >= sb.len() && hb[hb.len() - sb.len()..].eq_ignore_ascii_case(sb)
}

/// Returns `true` for the names curl treats as the local host:
/// `localhost`, `localhost.`, or any `*.localhost` / `*.localhost.` host
/// (case-insensitive).
fn is_localhost(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.eq_ignore_ascii_case("localhost.")
        || ends_with_ci(host, ".localhost")
        || ends_with_ci(host, ".localhost.")
}

/// Parses an IP-literal host, accepting a bracketed IPv6 form (`[::1]`) as well
/// as the bare `::1` / `127.0.0.1` forms. Returns the parsed [`IpAddr`], or
/// `None` when `host` is not a numeric address — the safe analog of curl's
/// `Curl_host_is_ipnum` / `Curl_str2addr`.
fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    let trimmed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    trimmed.parse::<IpAddr>().ok()
}

/// Returns `true` if `host` is a numeric IPv4 (or, when IPv6 is supported, IPv6)
/// address — the analog of curl's `Curl_host_is_ipnum`. A bracketed IPv6 literal
/// is accepted.
#[must_use]
pub fn host_is_ipnum(host: &str) -> bool {
    parse_ip_literal(host).is_some()
}

/// Returns whether the requested IP version can be resolved in this build — the
/// analog of curl's `can_resolve_ip_version`.
///
/// A V6 request requires IPv6 support to be compiled in (the `ipv6` Cargo
/// feature, on by default). The *runtime* "is IPv6 actually reachable" probe
/// that curl's `Curl_ipv6works` performs is deferred to the connection layer
/// (`crate::conn` / Happy-Eyeballs), which is where reachability is exercised;
/// the resolver only declines a family it cannot represent at all.
#[must_use]
pub fn can_resolve_ip_version(ip_version: IpVersion) -> bool {
    // Whether IPv6 is compiled in. Binding the `cfg!` result to a local (instead
    // of placing the literal directly in the match arm) means the arms are not
    // both bool *literals*, so the expression is not reducible to a `matches!`
    // call. That keeps the function clippy-clean (`clippy::match_like_matches_macro`)
    // in BOTH builds — with the `ipv6` feature on (`true`) and off (`false`) —
    // which the `--no-default-features` lint gate exercises (AAP §0.6.2).
    let ipv6_supported = cfg!(feature = "ipv6");
    match ip_version {
        IpVersion::V6 => ipv6_supported,
        _ => true,
    }
}

/// Synthesizes the loopback addresses for `localhost`, matching curl's
/// `get_localhost`: IPv6 `::1` first (only when IPv6 support is compiled in),
/// then IPv4 `127.0.0.1`.
fn localhost_addrs(port: u16) -> ResolvedAddrs {
    #[cfg(feature = "ipv6")]
    let addrs = vec![
        SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), port),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
    ];
    #[cfg(not(feature = "ipv6"))]
    let addrs = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)];
    ResolvedAddrs::from_vec(addrs)
}

/// Records a failed resolve as a negative cache entry — the analog of curl's
/// `store_negative_resolve`. The entry carries no addresses and is
/// non-permanent (so it ages, twice as fast as a positive entry).
fn store_negative_resolve(
    cache: &mut DnsCache,
    host: &str,
    port: u16,
    now: CurlTime,
    verbose: bool,
) {
    let entry = DnsCache::mk_entry(ResolvedAddrs::new(), host, port, false, false, now);
    cache.add(entry);
    crate::infof!(verbose, "Store negative name resolve for {host}:{port}");
}

/// Emits the verbose "resolved to …" line for a successful resolve — the analog
/// of curl's `show_resolve_info`. No-op when not verbose or for a negative
/// entry.
fn show_resolve_info(entry: &DnsEntry, verbose: bool) {
    if !verbose || entry.is_negative() {
        return;
    }
    let rendered = entry
        .addrs
        .iter()
        .map(|addr| addr.ip().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    crate::infof!(
        verbose,
        "Resolved {}:{} to {}",
        entry.hostname,
        entry.hostport,
        rendered
    );
}

// ===========================================================================
// Phase G — Happy-Eyeballs hand-off.
//
// This module deliberately stops at producing the resolved address *set*
// (optionally shuffled via `CURLOPT_DNS_SHUFFLE_ADDRESSES`, see
// `ResolvedAddrs::shuffle`). It performs **no** Happy-Eyeballs / IPv4-IPv6
// interleaving and **no** connection ordering: that is owned by
// `crate::conn::happy_eyeballs`, which consumes the `Vec<SocketAddr>` exposed by
// `ResolvedAddrs`/`DnsEntry` and decides attempt order and timing. Keeping the
// resolver free of connection policy mirrors curl's split between `hostip.c`
// (resolution) and `connect.c` (ordering/attempts).
// ===========================================================================

// ===========================================================================
// Phase F — the CURLOPT_RESOLVE loader.
// ===========================================================================

/// Maximum length of a single textual address token, matching curl's
/// `MAX_IPADR_LEN` (`sizeof("ffff:…:255.255.255.255")` = 46), used as the cap
/// when reading a bracketed `[IPv6]` host or address.
const MAX_IPADR_LEN: usize = 46;

/// Maximum length of an un-bracketed host/address token, matching the literal
/// `4096` curl passes to `curlx_str_until` for those tokens.
const MAX_RESOLVE_TOKEN_LEN: usize = 4096;

/// Upper bound on an address token before parsing, matching curl's fixed
/// `char address[64]` scratch buffer (a token of length ≥ 64 is rejected).
const MAX_RESOLVE_ADDR_LEN: usize = 64;

/// Loads `CURLOPT_RESOLVE` entries into the cache — the analog of curl's
/// `Curl_loadhostpairs` (`lib/hostip.c`).
///
/// Each entry is one of:
///
/// * `-HOST:PORT` — **delete** the cached entry for `HOST:PORT` (ignored if
///   absent). `HOST` may be a bracketed `[IPv6]` literal.
/// * `[+]HOST:PORT:ADDR[,ADDR…]` — **add** a pre-resolved entry. Without the
///   leading `+` the entry is **permanent** (never pruned); with `+` it is
///   non-permanent (subject to the cache timeout). `HOST` and each `ADDR` may be
///   bracketed `[IPv6]`; multiple comma-separated addresses are allowed.
///
/// A `*` host (case-insensitive) installs a wildcard entry and enables the
/// `*:PORT` lookup fallback ([`DnsCache::set_wildcard_resolve`]). When an entry
/// with the same id already exists it is deleted first, so the replacement gets
/// a fresh timeout and can demote a permanent entry to non-permanent.
///
/// `entries` is the raw `CURLOPT_RESOLVE` string list (any `&[String]`,
/// `&[&str]`, …). `now` stamps freshly added non-permanent entries; `verbose`
/// gates the informational logging; `errbuf` receives the parse-error message.
///
/// The wildcard flag is reset at the start of every call, matching curl, which
/// reloads the full list each time the option changes.
///
/// # Errors
///
/// * [`CurlError::SetoptOptionSyntax`] — a malformed entry (after a valid host
///   token): a bad `:PORT:` section, an illegal or missing address, or an
///   address whose length exceeds the limit. The offending entry is reported
///   via `errbuf` as `Could not parse CURLOPT_RESOLVE entry '…'`. Entries that
///   fail to yield even a host token are skipped, exactly as curl does.
pub fn load_host_pairs(
    cache: &mut DnsCache,
    entries: &[impl AsRef<str>],
    now: CurlTime,
    verbose: bool,
    errbuf: &mut Option<String>,
) -> Result<()> {
    // Default is no wildcard found (curl resets this before the loop).
    cache.set_wildcard_resolve(false);

    for entry in entries {
        apply_resolve_entry(cache, entry.as_ref(), now, verbose, errbuf)?;
    }

    Ok(())
}

/// Parses and applies a single `CURLOPT_RESOLVE` entry. Returns `Ok(())` both
/// when the entry is applied and when it is silently skipped (curl's `continue`
/// paths — an empty line or a host token that fails to parse); returns
/// `Err(CurlError::SetoptOptionSyntax)` for a hard parse error (curl's
/// `goto err`).
fn apply_resolve_entry(
    cache: &mut DnsCache,
    line: &str,
    now: CurlTime,
    verbose: bool,
    errbuf: &mut Option<String>,
) -> Result<()> {
    // curl skips null/empty slist data.
    let Some(&first) = line.as_bytes().first() else {
        return Ok(());
    };

    if first == b'-' {
        return apply_resolve_delete(cache, line);
    }

    apply_resolve_add(cache, line, now, verbose, errbuf)
}

/// Handles a `-HOST:PORT` delete entry. Parse failures are silently skipped
/// (curl's `continue`); a successful parse deletes the entry, ignoring absence.
fn apply_resolve_delete(cache: &mut DnsCache, line: &str) -> Result<()> {
    let mut p = Str::new(&line[1..]); // skip the leading '-'
    let mut source = Str::default();

    if p.curlx_str_single(b'[').is_ok() {
        // Bracketed [IPv6] host: read to ']', then consume ']' and ':'.
        if p.curlx_str_until(&mut source, MAX_IPADR_LEN, b']').is_err()
            || p.curlx_str_single(b']').is_err()
            || p.curlx_str_single(b':').is_err()
        {
            return Ok(()); // malformed → skip
        }
    } else if p
        .curlx_str_until(&mut source, MAX_RESOLVE_TOKEN_LEN, b':')
        .is_err()
        || p.curlx_str_single(b':').is_err()
    {
        return Ok(()); // malformed → skip
    }

    let mut num: u64 = 0;
    if p.curlx_str_number(&mut num, 0xffff).is_ok() {
        if let Ok(host) = std::str::from_utf8(source.curlx_str()) {
            let id = create_dnscache_id(host, num as u16);
            // Delete the entry; absence is ignored.
            let _ = cache.remove_by_id(&id);
        }
    }
    Ok(())
}

/// Handles a `[+]HOST:PORT:ADDR[,ADDR…]` add entry.
fn apply_resolve_add(
    cache: &mut DnsCache,
    line: &str,
    now: CurlTime,
    verbose: bool,
    errbuf: &mut Option<String>,
) -> Result<()> {
    let mut p = Str::new(line);

    // A leading '+' marks a non-permanent entry; otherwise it is permanent.
    let permanent = p.curlx_str_single(b'+').is_err();

    // ---- host (a parse failure here is a skip, matching curl's `continue`) ----
    let mut source = Str::default();
    if p.curlx_str_single(b'[').is_ok() {
        if p.curlx_str_until(&mut source, MAX_IPADR_LEN, b']').is_err()
            || p.curlx_str_single(b']').is_err()
        {
            return Ok(()); // malformed host → skip
        }
    } else if p
        .curlx_str_until(&mut source, MAX_RESOLVE_TOKEN_LEN, b':')
        .is_err()
    {
        return Ok(()); // malformed host → skip
    }

    // ---- ":PORT:" (failures here are HARD errors, curl's `goto err`) ----
    let mut port_num: u64 = 0;
    if p.curlx_str_single(b':').is_err()
        || p.curlx_str_number(&mut port_num, 0xffff).is_err()
        || p.curlx_str_single(b':').is_err()
    {
        return Err(resolve_syntax_error(line, errbuf));
    }
    let port = port_num as u16;

    // Snapshot the address section for the verbose "Added …" log.
    let addresses_text = std::str::from_utf8(p.curlx_str()).unwrap_or("");

    // ---- address list ----
    let addrs = parse_resolve_addresses(&mut p, port, verbose, line, errbuf)?;
    if addrs.is_empty() {
        return Err(resolve_syntax_error(line, errbuf));
    }

    // Host token as text (hostnames/IPs are ASCII).
    let host = match std::str::from_utf8(source.curlx_str()) {
        Ok(host) => host,
        Err(_) => return Err(resolve_syntax_error(line, errbuf)),
    };

    // Replace any existing entry so the new one gets a fresh timeout and can
    // demote a permanent entry (curl deletes then re-adds for these reasons).
    let id = create_dnscache_id(host, port);
    if cache.get_by_id(&id).is_some() {
        crate::infof!(verbose, "RESOLVE {host}:{port} - old addresses discarded");
        cache.remove_by_id(&id);
    }

    let entry = DnsCache::mk_entry(
        ResolvedAddrs::from_vec(addrs),
        host,
        port,
        permanent,
        false,
        now,
    );
    cache.add(entry);
    crate::infof!(
        verbose,
        "Added {host}:{port}:{addresses_text} to DNS cache{}",
        if permanent { "" } else { " (non-permanent)" }
    );

    // A '*' host enables the wildcard lookup fallback.
    if curlx_str_casecompare(&source, "*") {
        crate::infof!(verbose, "RESOLVE *:{port} using wildcard");
        cache.set_wildcard_resolve(true);
    }

    Ok(())
}

/// Parses the comma-separated address list of an add entry, each address either
/// bracketed `[IPv6]` or bare, producing `SocketAddr`s bound to `port`. Mirrors
/// curl's address loop, including surviving a lone comma and skipping IPv6
/// addresses when IPv6 support is not compiled in.
fn parse_resolve_addresses(
    p: &mut Str<'_>,
    port: u16,
    verbose: bool,
    line: &str,
    errbuf: &mut Option<String>,
) -> Result<Vec<SocketAddr>> {
    let mut addrs: Vec<SocketAddr> = Vec::new();

    while !p.is_empty() {
        let mut target = Str::default();

        if p.curlx_str_single(b'[').is_ok() {
            // Bracketed [IPv6] address.
            if p.curlx_str_until(&mut target, MAX_IPADR_LEN, b']').is_err()
                || p.curlx_str_single(b']').is_err()
            {
                return Err(resolve_syntax_error(line, errbuf));
            }
        } else if p
            .curlx_str_until(&mut target, MAX_RESOLVE_TOKEN_LEN, b',')
            .is_err()
        {
            // Empty token before a ',': survive a lone comma, else hard error.
            if p.curlx_str_single(b',').is_err() {
                return Err(resolve_syntax_error(line, errbuf));
            }
            continue;
        }

        let target_bytes = target.curlx_str();

        // An IPv6 address with no IPv6 support compiled in is skipped, exactly
        // as curl does under `#ifndef USE_IPV6`.
        if !cfg!(feature = "ipv6") && target_bytes.contains(&b':') {
            if let Ok(addr_str) = std::str::from_utf8(target_bytes) {
                crate::infof!(
                    verbose,
                    "Ignoring resolve address '{addr_str}', missing IPv6 support."
                );
            }
            if p.curlx_str_single(b',').is_err() {
                return Err(resolve_syntax_error(line, errbuf));
            }
            continue;
        }

        // Reject an over-long token (curl's fixed 64-byte buffer).
        if target.curlx_strlen() >= MAX_RESOLVE_ADDR_LEN {
            return Err(resolve_syntax_error(line, errbuf));
        }

        let parsed = std::str::from_utf8(target_bytes)
            .ok()
            .and_then(|addr_str| addr_str.parse::<IpAddr>().ok());
        match parsed {
            Some(ip) => addrs.push(SocketAddr::new(ip, port)),
            None => {
                if let Ok(addr_str) = std::str::from_utf8(target_bytes) {
                    crate::infof!(verbose, "Resolve address '{addr_str}' found illegal");
                }
                return Err(resolve_syntax_error(line, errbuf));
            }
        }

        // Stop when no comma follows the address.
        if p.curlx_str_single(b',').is_err() {
            break;
        }
    }

    Ok(addrs)
}

/// Records the `CURLOPT_RESOLVE` parse-error message and returns the syntax
/// error code (curl's `failf` + `CURLE_SETOPT_OPTION_SYNTAX`).
fn resolve_syntax_error(line: &str, errbuf: &mut Option<String>) -> CurlError {
    crate::failf!(errbuf, "Could not parse CURLOPT_RESOLVE entry '{line}'");
    CurlError::SetoptOptionSyntax
}


// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::timeval::CurlTime;
    use std::net::SocketAddr;

    fn sa(s: &str) -> SocketAddr {
        s.parse().expect("valid socket addr literal")
    }

    // ---- create_dnscache_id -------------------------------------------------

    #[test]
    fn cache_id_lowercases_and_appends_port() {
        assert_eq!(create_dnscache_id("Example.COM", 443), "example.com:443");
        assert_eq!(create_dnscache_id("host", 80), "host:80");
        // Case-insensitivity: differently cased hosts share one id.
        assert_eq!(
            create_dnscache_id("WWW.Example.Org", 8080),
            create_dnscache_id("www.example.org", 8080)
        );
        // Wildcard id used by the wildcard fallback.
        assert_eq!(create_dnscache_id("*", 80), "*:80");
    }

    // ---- IpVersion ----------------------------------------------------------

    #[test]
    fn ip_version_raw_roundtrip_and_matching() {
        assert_eq!(IpVersion::from_raw(0), IpVersion::Any);
        assert_eq!(IpVersion::from_raw(1), IpVersion::V4);
        assert_eq!(IpVersion::from_raw(2), IpVersion::V6);
        // Unknown values fold to Any (curl treats non-1/2 as "whatever").
        assert_eq!(IpVersion::from_raw(99), IpVersion::Any);
        assert_eq!(IpVersion::Any.as_raw(), 0);
        assert_eq!(IpVersion::V4.as_raw(), 1);
        assert_eq!(IpVersion::V6.as_raw(), 2);

        let v4 = sa("1.2.3.4:80");
        let v6 = sa("[::1]:80");
        assert!(IpVersion::Any.matches(&v4));
        assert!(IpVersion::Any.matches(&v6));
        assert!(IpVersion::V4.matches(&v4));
        assert!(!IpVersion::V4.matches(&v6));
        assert!(IpVersion::V6.matches(&v6));
        assert!(!IpVersion::V6.matches(&v4));
    }

    // ---- ResolvedAddrs ------------------------------------------------------

    #[test]
    fn resolved_addrs_basics() {
        let empty = ResolvedAddrs::new();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let one = ResolvedAddrs::from_ip("9.9.9.9".parse().unwrap(), 53);
        assert_eq!(one.len(), 1);
        assert_eq!(one.addrs[0], sa("9.9.9.9:53"));

        let many = ResolvedAddrs::from_vec(vec![sa("1.2.3.4:80"), sa("[::1]:80")]);
        assert!(many.has_family(IpVersion::V4));
        assert!(many.has_family(IpVersion::V6));
        assert!(many.has_family(IpVersion::Any));
        // A negative (empty) set never has a concrete family.
        assert!(!empty.has_family(IpVersion::V4));
        assert!(!empty.has_family(IpVersion::Any));
    }

    #[test]
    fn resolved_addrs_shuffle_preserves_membership() {
        let original = vec![
            sa("1.1.1.1:80"),
            sa("2.2.2.2:80"),
            sa("3.3.3.3:80"),
            sa("4.4.4.4:80"),
        ];
        let mut addrs = ResolvedAddrs::from_vec(original.clone());
        addrs.shuffle();
        assert_eq!(addrs.len(), original.len());
        for a in &original {
            assert!(addrs.addrs.contains(a));
        }
    }

    // ---- DnsEntry -----------------------------------------------------------

    #[test]
    fn dns_entry_permanent_and_negative_flags() {
        let now = curlx_now();
        let permanent = DnsEntry {
            addrs: ResolvedAddrs::from_vec(vec![sa("1.2.3.4:80")]),
            timestamp: None,
            hostport: 80,
            hostname: "h".to_string(),
        };
        assert!(permanent.is_permanent());
        assert!(!permanent.is_negative());

        let negative = DnsEntry {
            addrs: ResolvedAddrs::new(),
            timestamp: Some(now),
            hostport: 80,
            hostname: "h".to_string(),
        };
        assert!(!negative.is_permanent());
        assert!(negative.is_negative());
    }

    // ---- DnsCache: add / lookup / remove / clear ----------------------------

    #[test]
    fn cache_add_lookup_remove_clear() {
        let now = curlx_now();
        let mut cache = DnsCache::new();
        assert!(cache.is_empty());

        let entry = DnsCache::mk_entry(
            ResolvedAddrs::from_vec(vec![sa("1.2.3.4:80")]),
            "Example.com",
            80,
            true,
            false,
            now,
        );
        cache.add(entry);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.count(), 1);

        // Lookup is case-insensitive on the host.
        let hit = cache.lookup("example.com", 80).expect("entry present");
        assert_eq!(hit.hostname, "Example.com");
        assert_eq!(hit.addrs.addrs, vec![sa("1.2.3.4:80")]);
        // Wrong port misses.
        assert!(cache.lookup("example.com", 81).is_none());

        assert!(cache.remove("EXAMPLE.COM", 80));
        assert!(!cache.remove("example.com", 80)); // already gone
        assert!(cache.is_empty());

        cache.add(DnsCache::mk_entry(ResolvedAddrs::new(), "h", 1, true, false, now));
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_add_replaces_existing() {
        let now = curlx_now();
        let mut cache = DnsCache::new();
        cache.add(DnsCache::mk_entry(
            ResolvedAddrs::from_vec(vec![sa("1.1.1.1:80")]),
            "h",
            80,
            true,
            false,
            now,
        ));
        cache.add(DnsCache::mk_entry(
            ResolvedAddrs::from_vec(vec![sa("2.2.2.2:80")]),
            "h",
            80,
            true,
            false,
            now,
        ));
        assert_eq!(cache.len(), 1);
        let hit = cache.lookup("h", 80).unwrap();
        assert_eq!(hit.addrs.addrs, vec![sa("2.2.2.2:80")]);
    }

    // ---- DnsCache::get eviction (stale / family / never-expire) -------------

    #[test]
    fn get_evicts_stale_entry() {
        let now = CurlTime::new(100, 0);
        let mut cache = DnsCache::new();
        // Created 50s ago.
        cache.add(DnsCache::mk_entry(
            ResolvedAddrs::from_vec(vec![sa("1.2.3.4:80")]),
            "h",
            80,
            false,
            false,
            CurlTime::new(50, 0),
        ));
        // max_age 10s → 50s old entry is stale → zapped.
        assert!(cache.get("h", 80, IpVersion::Any, 10_000, now, false).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn get_keeps_permanent_entry_even_when_caching_disabled() {
        let now = CurlTime::new(100, 0);
        let mut cache = DnsCache::new();
        cache.add(DnsCache::mk_entry(
            ResolvedAddrs::from_vec(vec![sa("1.2.3.4:80")]),
            "h",
            80,
            true, // permanent
            false,
            CurlTime::new(1, 0),
        ));
        // Even with max_age 0 (caching disabled) a permanent entry survives.
        assert!(cache.get("h", 80, IpVersion::Any, 0, now, false).is_some());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn get_never_expire_skips_stale_check() {
        let now = CurlTime::new(1_000, 0);
        let mut cache = DnsCache::new();
        cache.add(DnsCache::mk_entry(
            ResolvedAddrs::from_vec(vec![sa("1.2.3.4:80")]),
            "h",
            80,
            false,
            false,
            CurlTime::new(1, 0), // very old
        ));
        // max_age == -1 → never expire → returned despite age.
        assert!(cache
            .get("h", 80, IpVersion::Any, DNS_CACHE_TIMEOUT_NEVER, now, false)
            .is_some());
    }

    #[test]
    fn get_evicts_wrong_family_entry() {
        let now = CurlTime::new(100, 0);
        let mut cache = DnsCache::new();
        // IPv4-only, permanent (so staleness cannot interfere).
        cache.add(DnsCache::mk_entry(
            ResolvedAddrs::from_vec(vec![sa("1.2.3.4:80")]),
            "h",
            80,
            true,
            false,
            now,
        ));
        // Requesting V6 finds no matching family → zapped.
        assert!(cache.get("h", 80, IpVersion::V6, 60_000, now, false).is_none());
        assert!(cache.is_empty());
    }

    // ---- DnsCache::prune ----------------------------------------------------

    #[test]
    fn prune_removes_stale_keeps_permanent_and_fresh() {
        let now = CurlTime::new(100, 0);
        let mut cache = DnsCache::new();
        cache.add(DnsCache::mk_entry(
            ResolvedAddrs::from_vec(vec![sa("1.1.1.1:80")]),
            "permanent",
            80,
            true,
            false,
            CurlTime::new(1, 0),
        ));
        cache.add(DnsCache::mk_entry(
            ResolvedAddrs::from_vec(vec![sa("2.2.2.2:80")]),
            "fresh",
            80,
            false,
            false,
            CurlTime::new(99, 0), // 1s old
        ));
        cache.add(DnsCache::mk_entry(
            ResolvedAddrs::from_vec(vec![sa("3.3.3.3:80")]),
            "stale",
            80,
            false,
            false,
            CurlTime::new(40, 0), // 60s old
        ));
        assert_eq!(cache.len(), 3);

        cache.prune(10_000, now); // 10s limit
        assert!(cache.lookup("permanent", 80).is_some());
        assert!(cache.lookup("fresh", 80).is_some());
        assert!(cache.lookup("stale", 80).is_none());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn prune_ages_negative_entries_twice_as_fast() {
        let now = CurlTime::new(100, 0);
        let mut cache = DnsCache::new();
        // Both created 10s ago; max_age 15s.
        // positive: age 10s  < 15s -> kept.
        // negative: age 10s*2 = 20s >= 15s -> removed.
        cache.add(DnsCache::mk_entry(
            ResolvedAddrs::from_vec(vec![sa("1.1.1.1:80")]),
            "positive",
            80,
            false,
            false,
            CurlTime::new(90, 0),
        ));
        cache.add(DnsCache::mk_entry(
            ResolvedAddrs::new(),
            "negative",
            80,
            false,
            false,
            CurlTime::new(90, 0),
        ));

        cache.prune(15_000, now);
        assert!(cache.lookup("positive", 80).is_some());
        assert!(cache.lookup("negative", 80).is_none());
    }

    #[test]
    fn prune_never_is_a_noop() {
        let now = CurlTime::new(10_000, 0);
        let mut cache = DnsCache::new();
        cache.add(DnsCache::mk_entry(
            ResolvedAddrs::from_vec(vec![sa("1.1.1.1:80")]),
            "old",
            80,
            false,
            false,
            CurlTime::new(1, 0),
        ));
        cache.prune(DNS_CACHE_TIMEOUT_NEVER, now);
        assert_eq!(cache.len(), 1);
    }

    // ---- wildcard lookup ----------------------------------------------------

    #[test]
    fn wildcard_fallback_lookup() {
        let now = curlx_now();
        let mut cache = DnsCache::new();
        cache.set_wildcard_resolve(true);
        cache.add(DnsCache::mk_entry(
            ResolvedAddrs::from_vec(vec![sa("1.2.3.4:80")]),
            "*",
            80,
            true,
            false,
            now,
        ));
        // An exact-host miss falls back to the "*:80" entry.
        let hit = cache.lookup("anything.example", 80).expect("wildcard hit");
        assert_eq!(hit.hostname, "*");
        // Without the wildcard flag, the same lookup misses.
        cache.set_wildcard_resolve(false);
        assert!(cache.lookup("anything.example", 80).is_none());
    }

    // ---- helpers: host_is_ipnum / can_resolve_ip_version --------------------

    #[test]
    fn host_is_ipnum_detection() {
        assert!(host_is_ipnum("1.2.3.4"));
        assert!(host_is_ipnum("::1"));
        assert!(host_is_ipnum("[::1]")); // bracketed IPv6 accepted
        assert!(host_is_ipnum("2001:db8::1"));
        assert!(!host_is_ipnum("example.com"));
        assert!(!host_is_ipnum("not-an-ip"));
    }

    #[test]
    fn can_resolve_ip_version_respects_ipv6_feature() {
        assert!(can_resolve_ip_version(IpVersion::Any));
        assert!(can_resolve_ip_version(IpVersion::V4));
        assert_eq!(
            can_resolve_ip_version(IpVersion::V6),
            cfg!(feature = "ipv6")
        );
    }

    // ---- CURLOPT_RESOLVE loader ---------------------------------------------

    #[test]
    fn load_pairs_plain_entry_is_permanent() {
        let now = curlx_now();
        let mut cache = DnsCache::new();
        let mut err = None;
        load_host_pairs(&mut cache, &["example.com:80:1.2.3.4"], now, false, &mut err)
            .expect("valid entry");
        assert!(err.is_none());
        let hit = cache.lookup("example.com", 80).expect("entry present");
        assert!(hit.is_permanent());
        assert_eq!(hit.addrs.addrs, vec![sa("1.2.3.4:80")]);
    }

    #[test]
    fn load_pairs_plus_entry_is_non_permanent() {
        let now = curlx_now();
        let mut cache = DnsCache::new();
        let mut err = None;
        load_host_pairs(&mut cache, &["+example.com:80:1.2.3.4"], now, false, &mut err)
            .expect("valid entry");
        let hit = cache.lookup("example.com", 80).expect("entry present");
        assert!(!hit.is_permanent());
    }

    #[test]
    fn load_pairs_delete_entry() {
        let now = curlx_now();
        let mut cache = DnsCache::new();
        let mut err = None;
        load_host_pairs(&mut cache, &["example.com:80:1.2.3.4"], now, false, &mut err).unwrap();
        assert!(cache.lookup("example.com", 80).is_some());
        // A '-' prefix deletes the entry.
        load_host_pairs(&mut cache, &["-example.com:80"], now, false, &mut err).unwrap();
        assert!(cache.lookup("example.com", 80).is_none());
        // Deleting an absent entry is silently ignored (still Ok).
        load_host_pairs(&mut cache, &["-nope.example:443"], now, false, &mut err).unwrap();
        assert!(err.is_none());
    }

    #[test]
    fn load_pairs_multi_address() {
        let now = curlx_now();
        let mut cache = DnsCache::new();
        let mut err = None;
        load_host_pairs(
            &mut cache,
            &["h.example:80:1.2.3.4,5.6.7.8"],
            now,
            false,
            &mut err,
        )
        .expect("valid entry");
        let hit = cache.lookup("h.example", 80).unwrap();
        assert_eq!(hit.addrs.addrs, vec![sa("1.2.3.4:80"), sa("5.6.7.8:80")]);
    }

    #[cfg(feature = "ipv6")]
    #[test]
    fn load_pairs_bracketed_ipv6() {
        let now = curlx_now();
        let mut cache = DnsCache::new();
        let mut err = None;
        load_host_pairs(
            &mut cache,
            &["[2001:db8::1]:443:[2001:db8::1],[2001:db8::2]"],
            now,
            false,
            &mut err,
        )
        .expect("valid entry");
        let hit = cache.lookup("2001:db8::1", 443).expect("entry present");
        assert_eq!(
            hit.addrs.addrs,
            vec![sa("[2001:db8::1]:443"), sa("[2001:db8::2]:443")]
        );
    }

    #[test]
    fn load_pairs_wildcard_sets_flag() {
        let now = curlx_now();
        let mut cache = DnsCache::new();
        let mut err = None;
        load_host_pairs(&mut cache, &["*:80:1.2.3.4"], now, false, &mut err)
            .expect("valid entry");
        assert!(cache.wildcard_resolve());
        // The wildcard entry is then reachable for any host on that port.
        assert!(cache.lookup("whatever.example", 80).is_some());
    }

    #[test]
    fn load_pairs_resets_wildcard_each_call() {
        let now = curlx_now();
        let mut cache = DnsCache::new();
        let mut err = None;
        load_host_pairs(&mut cache, &["*:80:1.2.3.4"], now, false, &mut err).unwrap();
        assert!(cache.wildcard_resolve());
        // A subsequent load without a wildcard clears the flag.
        load_host_pairs(&mut cache, &["h:80:1.2.3.4"], now, false, &mut err).unwrap();
        assert!(!cache.wildcard_resolve());
    }

    #[test]
    fn load_pairs_syntax_errors() {
        let now = curlx_now();

        // Non-numeric port.
        let mut cache = DnsCache::new();
        let mut err = None;
        let res = load_host_pairs(&mut cache, &["example.com:bad:1.2.3.4"], now, false, &mut err);
        assert_eq!(res, Err(CurlError::SetoptOptionSyntax));
        assert!(err.is_some());

        // Illegal address.
        let mut cache = DnsCache::new();
        let mut err = None;
        assert_eq!(
            load_host_pairs(&mut cache, &["example.com:80:not-an-ip"], now, false, &mut err),
            Err(CurlError::SetoptOptionSyntax)
        );

        // Missing address section.
        let mut cache = DnsCache::new();
        let mut err = None;
        assert_eq!(
            load_host_pairs(&mut cache, &["example.com:80:"], now, false, &mut err),
            Err(CurlError::SetoptOptionSyntax)
        );

        // Host with no port at all is a hard error (curl's `goto err`).
        let mut cache = DnsCache::new();
        let mut err = None;
        assert_eq!(
            load_host_pairs(&mut cache, &["justhost"], now, false, &mut err),
            Err(CurlError::SetoptOptionSyntax)
        );
    }

    #[test]
    fn load_pairs_skips_unparseable_host_without_error() {
        let now = curlx_now();
        let mut cache = DnsCache::new();
        let mut err = None;
        // Empty entry and an unterminated bracket are skipped, not errors.
        load_host_pairs(&mut cache, &["", "[::1"], now, false, &mut err)
            .expect("malformed-host entries are skipped");
        assert!(err.is_none());
        assert!(cache.is_empty());
    }

    // ---- central resolve flow (shortcuts only; no network) ------------------

    #[tokio::test]
    async fn resolve_rejects_onion() {
        let mut cache = DnsCache::new();
        let mut err = None;
        let params = ResolveParams::new("secret.onion", 80);
        assert_eq!(
            resolve(&mut cache, &params, &mut err).await,
            Err(CurlError::CouldntResolveHost)
        );
        assert_eq!(
            err.as_deref(),
            Some("Not resolving .onion address (RFC 7686)")
        );

        // Trailing-dot form is also refused.
        let params = ResolveParams::new("secret.onion.", 80);
        assert_eq!(
            resolve(&mut cache, &params, &mut None).await,
            Err(CurlError::CouldntResolveHost)
        );
    }

    #[tokio::test]
    async fn resolve_onion_maps_to_proxy_error_when_proxy() {
        let mut cache = DnsCache::new();
        let mut params = ResolveParams::new("secret.onion", 80);
        params.is_proxy = true;
        assert_eq!(
            resolve(&mut cache, &params, &mut None).await,
            Err(CurlError::CouldntResolveProxy)
        );
    }

    #[tokio::test]
    async fn resolve_literal_ip_shortcut() {
        let mut cache = DnsCache::new();
        let params = ResolveParams::new("93.184.216.34", 443);
        let entry = resolve(&mut cache, &params, &mut None)
            .await
            .expect("literal IP resolves without a query");
        assert_eq!(entry.addrs.addrs, vec![sa("93.184.216.34:443")]);
        // It is now cached.
        assert!(cache.lookup("93.184.216.34", 443).is_some());
    }

    #[tokio::test]
    async fn resolve_localhost_shortcut() {
        let mut cache = DnsCache::new();
        let params = ResolveParams::new("localhost", 8080);
        let entry = resolve(&mut cache, &params, &mut None)
            .await
            .expect("localhost resolves to loopback");
        assert!(entry.addrs.addrs.contains(&sa("127.0.0.1:8080")));
        #[cfg(feature = "ipv6")]
        {
            // IPv6 loopback is offered first when IPv6 support is built in.
            assert_eq!(entry.addrs.addrs[0], sa("[::1]:8080"));
        }
    }

    #[tokio::test]
    async fn resolve_negative_cache_hit_is_error() {
        let now = curlx_now();
        let mut cache = DnsCache::new();
        // Pre-store a (fresh) negative entry.
        cache.add(DnsCache::mk_entry(
            ResolvedAddrs::new(),
            "neg.example",
            80,
            false,
            false,
            now,
        ));
        let params = ResolveParams::new("neg.example", 80);
        assert_eq!(
            resolve(&mut cache, &params, &mut None).await,
            Err(CurlError::CouldntResolveHost)
        );
    }

    #[tokio::test]
    async fn resolve_positive_cache_hit() {
        let now = curlx_now();
        let mut cache = DnsCache::new();
        cache.add(DnsCache::mk_entry(
            ResolvedAddrs::from_vec(vec![sa("1.2.3.4:80")]),
            "cached.example",
            80,
            true,
            false,
            now,
        ));
        let params = ResolveParams::new("cached.example", 80);
        let entry = resolve(&mut cache, &params, &mut None)
            .await
            .expect("cache hit");
        assert_eq!(entry.addrs.addrs, vec![sa("1.2.3.4:80")]);
    }

    #[tokio::test]
    async fn resolve_timeout_negative_is_immediate_timeout() {
        let mut cache = DnsCache::new();
        let params = ResolveParams::new("example.com", 80);
        assert_eq!(
            resolve_timeout(&mut cache, &params, &mut None, -1).await,
            Err(CurlError::OperationTimedout)
        );
    }

    #[tokio::test]
    async fn resolve_timeout_zero_runs_without_deadline() {
        let mut cache = DnsCache::new();
        // A literal IP returns without any backend, even via the timeout path.
        let params = ResolveParams::new("10.0.0.1", 80);
        let entry = resolve_timeout(&mut cache, &params, &mut None, 0)
            .await
            .expect("literal IP resolves under timeout=0");
        assert_eq!(entry.addrs.addrs, vec![sa("10.0.0.1:80")]);
    }

    // ---- Send + Sync (required for crate::share's Arc<Mutex<…>>) ------------

    #[test]
    fn dns_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ResolvedAddrs>();
        assert_send_sync::<DnsEntry>();
        assert_send_sync::<DnsCache>();
        assert_send_sync::<Arc<DnsEntry>>();
        assert_send_sync::<ResolveParams<'_>>();
    }
}

