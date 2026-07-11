// SPDX-License-Identifier: curl

//! TLS session-resumption cache — a [`rustls`] [`ClientSessionStore`] port of
//! curl's backend-agnostic SSL session cache.
//!
//! This module is a faithful Rust rewrite of curl's `lib/vtls/vtls_scache.c`
//! (1,221 lines) together with its declaration header
//! `lib/vtls/vtls_scache.h`. It caches TLS session tickets and session IDs so
//! that a subsequent connection to the same peer can *resume* an earlier
//! session — skipping a full handshake and, for TLS 1.3, optionally sending
//! 0-RTT early data.
//!
//! # From curl's cache to a `rustls` store
//!
//! In the C tree the cache was *backend-agnostic*: every TLS backend
//! (OpenSSL, GnuTLS, …) handed opaque session blobs to a shared cache keyed by
//! a composite "peer key" ([`Curl_ssl_peer_key_make`]). In this rewrite
//! `rustls` is the single TLS backend, and it already models the whole
//! ticket/session lifecycle through its
//! [`rustls::client::ClientSessionStore`] trait. The bulk of the C file — the
//! composite-key builder and the manual linked-list bookkeeping — is therefore
//! subsumed by `rustls`'s typed session values plus an `Arc<Mutex<…>>`-guarded
//! map. What remains, and what this module implements, is a *thin, bounded,
//! thread-safe, expiry-aware* store.
//!
//! [`Curl_ssl_peer_key_make`]: https://github.com/curl/curl/blob/master/lib/vtls/vtls_scache.c
//!
//! # The two parity invariants
//!
//! Only two behaviors of the C cache are wire/semantically observable, and both
//! are preserved exactly:
//!
//! 1. **Lifetime caps.** Per RFC 8446 §4.6.1 a TLS 1.3 ticket is honored for at
//!    most **seven days**; older protocol versions are capped at **one day**.
//!    A cached session's effective expiry is
//!    `min(server_supplied_expiry, now + cap_for_version)`. See
//!    [`MAX_TLS13_LIFETIME_SECS`] / [`MAX_TLS12_LIFETIME_SECS`] — the direct
//!    analogs of curl's `CURL_SCACHE_MAX_13_LIFETIME_SEC` /
//!    `CURL_SCACHE_MAX_12_LIFETIME_SEC`.
//! 2. **Configuration isolation.** curl folded the full TLS configuration
//!    (verify flags, protocol-version window, cipher list, CA/CRL/issuer paths,
//!    client-cert and SRP identity, …) into the composite peer key so that a
//!    session established under one configuration could never be resumed under
//!    a *different* one. In this rewrite that isolation is provided
//!    structurally: each distinct [`rustls::ClientConfig`] owns its own
//!    [`SessionCache`] instance, so sessions never cross a configuration
//!    boundary. We therefore key the store by [`ServerName`] alone (exactly as
//!    `rustls` does) and rely on per-config store ownership for isolation
//!    rather than reproducing the composite-key string.
//!
//! # Capacity and eviction
//!
//! Like curl's `Curl_ssl_scache_create(max_peers, max_sessions_per_peer)`, the
//! store is bounded on two axes: a maximum number of *peers* (server
//! endpoints) and a maximum number of *sessions per peer*. The curl-parity
//! defaults are [`DEFAULT_MAX_PEERS`] = 25 (curl's `CURL_TLS_SESSION_SIZE`,
//! used for both the multi handle and the `curl_share` object) and
//! [`DEFAULT_MAX_SESSIONS_PER_PEER`] = 2. When a peer overflows,
//! the oldest session is evicted first; when the peer table overflows, the
//! least-recently-used peer is evicted (mirroring `cf_ssl_get_free_peer`).
//! Expired entries are dropped lazily on access (mirroring
//! `cf_scache_peer_remove_expired`).
//!
//! # Sharing across handles (`curl_share`)
//!
//! [`SessionCache`] is a cheap `Arc<Mutex<…>>` handle: cloning it yields a
//! second handle onto the *same* underlying store. A single cache can thus be
//! installed on several [`rustls::ClientConfig`]s (or held by a shared
//! `Arc<Mutex<Shared>>` "share" object) so that easy handles which share a
//! `CURLSH` also share resumption state — the direct analog of curl's
//! `CURL_LOCK_DATA_SSL_SESSION`. When no share is configured, each config
//! keeps its own private store, which is also the isolation mechanism above.
//!
//! # Wiring into `config.rs`
//!
//! `tls::config` installs the store on the client configuration by assigning
//! the [`rustls::client::Resumption`] built from this cache:
//!
//! ```ignore
//! use std::sync::Arc;
//! use rustls::client::Resumption;
//! use curl_rs_lib::tls::session_cache::SessionCache;
//!
//! let cache = SessionCache::new();                 // or a shared clone
//! client_config.resumption = Resumption::store(cache.as_rustls_store());
//! ```
//!
//! # Safety and robustness
//!
//! This module is written wholly in safe Rust, keeping the crate-wide TLS
//! memory-safety audit green (the audit greps the TLS source tree and must
//! find no forbidden constructs). Every method is **non-panicking**: a
//! poisoned lock is recovered rather than propagated (a poisoned cache is at
//! worst a resumption miss, never a crashed transfer), and all time arithmetic
//! uses checked addition so pathological inputs cannot overflow-panic.
//!
//! # NOTE — session export (`USE_SSLS_EXPORT` / `vtls_spack.c`)
//!
//! curl optionally supports exporting/importing sessions in the SPACK TLV wire
//! format (`Curl_ssl_session_import` / `Curl_ssl_session_export` in
//! `lib/vtls/vtls_spack.c`, gated by `USE_SSLS_EXPORT`). Per the Minimal Change
//! Mandate that feature is intentionally **not** implemented here: no consuming
//! code path requires it yet, and inventing an on-disk format would exceed
//! parity. A later agent that needs cross-process session export should add it
//! against `lib/vtls/vtls_spack.c` as the source of truth.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use rustls::client::{ClientSessionStore, Tls12ClientSessionValue, Tls13ClientSessionValue};
use rustls::pki_types::ServerName;
use rustls::NamedGroup;

/// Maximum lifetime, in seconds, of a cached **TLS 1.3** session (7 days).
///
/// Per RFC 8446 §4.6.1 a ticket's `ticket_lifetime` must not exceed one week;
/// curl enforces the same ceiling via `CURL_SCACHE_MAX_13_LIFETIME_SEC`.
pub const MAX_TLS13_LIFETIME_SECS: u64 = 60 * 60 * 24 * 7;

/// Maximum lifetime, in seconds, of a cached **≤ TLS 1.2** session (1 day).
///
/// Older, less forward-secret protocol versions are held for at most a day,
/// matching curl's `CURL_SCACHE_MAX_12_LIFETIME_SEC`.
pub const MAX_TLS12_LIFETIME_SECS: u64 = 60 * 60 * 24;

/// Default assumed lifetime, in seconds, when a session's server-supplied
/// expiry is unknown (1 day).
///
/// Mirrors curl's `scache->default_lifetime_secs`, which is applied in
/// `cf_scache_add_session` whenever `valid_until <= 0`.
pub const DEFAULT_LIFETIME_SECS: u64 = 60 * 60 * 24;

/// Default maximum number of distinct peers (server endpoints) held in the
/// cache.
///
/// Equals curl's `CURL_TLS_SESSION_SIZE` (`lib/multi.c`), the value passed to
/// `Curl_ssl_scache_create` for both the multi handle and the `curl_share`
/// object (`lib/curl_share.c`).
pub const DEFAULT_MAX_PEERS: usize = 25;

/// Default maximum number of sessions retained per peer.
///
/// Equals the `max_sessions_per_peer` argument curl passes at every
/// `Curl_ssl_scache_create` call site.
pub const DEFAULT_MAX_SESSIONS_PER_PEER: usize = 2;

/// IETF protocol identifier for TLS 1.3 (`0x0304`), as used by curl's
/// `ietf_tls_id` field and `CURL_IETF_PROTO_TLS1_3`.
const IETF_PROTO_TLS1_3: u16 = 0x0304;

/// A single cached TLS session — the Rust analog of curl's
/// `struct Curl_ssl_session` (`lib/vtls/vtls_scache.h`).
///
/// It carries the opaque session/ticket bytes plus the metadata curl tracked
/// alongside them: the negotiated protocol version, the selected ALPN
/// protocol, the peer's maximum 0-RTT (early-data) size, and — for QUIC — the
/// transport parameters needed to resume a QUIC connection.
///
/// `rustls`'s own [`Tls12ClientSessionValue`] / [`Tls13ClientSessionValue`]
/// model the sessions produced by an in-process handshake and are what the
/// [`ClientSessionStore`] trait exchanges. `StoredSession` is the parallel,
/// fully-constructible curl-parity representation used for the generic /
/// QUIC-transport-parameter path and for session export
/// (`Curl_ssl_session_create` / `Curl_ssl_session_create2`).
#[derive(Clone)]
pub struct StoredSession {
    /// Opaque session/ticket bytes (curl's `sdata` + `sdata_len`).
    pub sdata: Vec<u8>,
    /// Absolute expiry instant, or `None` when unknown.
    ///
    /// `None` corresponds to curl's `valid_until == 0` sentinel ("never
    /// expire"); see [`StoredSession::is_expired`].
    pub valid_until: Option<SystemTime>,
    /// Negotiated IETF protocol identifier, e.g. `0x0304` for TLS 1.3 (curl's
    /// `ietf_tls_id`).
    pub ietf_tls_id: u16,
    /// Selected ALPN protocol identifier bytes, if any (curl's `alpn`).
    pub alpn: Option<Vec<u8>>,
    /// Maximum early-data (0-RTT) size advertised by the peer (curl's
    /// `earlydata_max`).
    pub earlydata_max: usize,
    /// Optional QUIC transport parameters (curl's `quic_tp` + `quic_tp_len`),
    /// present only for QUIC/HTTP-3 sessions.
    pub quic_tp: Option<Vec<u8>>,
}

impl StoredSession {
    /// Create a session without QUIC transport parameters — the analog of
    /// curl's `Curl_ssl_session_create`.
    ///
    /// `valid_until` is the server-supplied absolute expiry, or `None` when
    /// unknown (curl's `0`); call [`StoredSession::clamp_valid_until`] before
    /// caching to apply the default lifetime and per-version cap.
    pub fn new(
        sdata: Vec<u8>,
        ietf_tls_id: u16,
        alpn: Option<Vec<u8>>,
        valid_until: Option<SystemTime>,
        earlydata_max: usize,
    ) -> Self {
        Self {
            sdata,
            valid_until,
            ietf_tls_id,
            alpn,
            earlydata_max,
            quic_tp: None,
        }
    }

    /// Create a session carrying QUIC transport parameters — the analog of
    /// curl's `Curl_ssl_session_create2`.
    pub fn with_quic_transport_params(
        sdata: Vec<u8>,
        ietf_tls_id: u16,
        alpn: Option<Vec<u8>>,
        valid_until: Option<SystemTime>,
        earlydata_max: usize,
        quic_tp: Vec<u8>,
    ) -> Self {
        Self {
            sdata,
            valid_until,
            ietf_tls_id,
            alpn,
            earlydata_max,
            quic_tp: Some(quic_tp),
        }
    }

    /// Return `true` if the session is a TLS 1.3 session.
    #[inline]
    pub fn is_tls13(&self) -> bool {
        self.ietf_tls_id == IETF_PROTO_TLS1_3
    }

    /// Return `true` if the session has expired relative to `now`.
    ///
    /// Mirrors curl's `cf_scache_session_expired`: a session with an unknown
    /// expiry (`valid_until == None`, curl's `0`) never expires; otherwise it
    /// is expired once its expiry instant is strictly in the past.
    #[inline]
    pub fn is_expired(&self, now: SystemTime) -> bool {
        self.valid_until.is_some_and(|t| t < now)
    }

    /// The maximum cached lifetime, in seconds, permitted for `ietf_tls_id`.
    ///
    /// Returns [`MAX_TLS13_LIFETIME_SECS`] for TLS 1.3 and
    /// [`MAX_TLS12_LIFETIME_SECS`] for every older version, matching the
    /// `max_lifetime` selection in curl's `cf_scache_add_session`.
    #[inline]
    pub fn lifetime_cap_secs(ietf_tls_id: u16) -> u64 {
        if ietf_tls_id == IETF_PROTO_TLS1_3 {
            MAX_TLS13_LIFETIME_SECS
        } else {
            MAX_TLS12_LIFETIME_SECS
        }
    }

    /// Apply curl's expiry policy in place: fill in the default lifetime when
    /// the server expiry is unknown, then clamp to the per-version cap.
    ///
    /// Mirrors `cf_scache_add_session`: an unknown expiry becomes
    /// `now + DEFAULT_LIFETIME_SECS`, and any expiry beyond `now + cap` is
    /// pulled back to `now + cap`. All arithmetic is checked so it can never
    /// panic on overflow.
    pub fn clamp_valid_until(&mut self, now: SystemTime) {
        let cap_secs = Self::lifetime_cap_secs(self.ietf_tls_id);
        let cap_until = now.checked_add(Duration::from_secs(cap_secs));
        // Unknown/zero expiry takes the one-day default, exactly as in curl.
        let base = match self.valid_until {
            Some(t) => Some(t),
            None => now.checked_add(Duration::from_secs(DEFAULT_LIFETIME_SECS)),
        };
        self.valid_until = match (base, cap_until) {
            (Some(b), Some(c)) => Some(b.min(c)),
            // A cap overflow means `now` is absurdly close to the maximum
            // representable instant; keep the base rather than panicking.
            (Some(b), None) => Some(b),
            // The default overflowed but the cap did not: fall back to the cap.
            (None, Some(c)) => Some(c),
            // Both overflowed: treat as never-expire (safe, matches `0`).
            (None, None) => None,
        };
    }
}

impl fmt::Debug for StoredSession {
    /// Redacts the secret session bytes (and QUIC parameters), printing only
    /// their lengths alongside the non-secret metadata.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredSession")
            .field("sdata_len", &self.sdata.len())
            .field("valid_until", &self.valid_until)
            .field("ietf_tls_id", &format_args!("0x{:04x}", self.ietf_tls_id))
            .field("alpn", &self.alpn)
            .field("earlydata_max", &self.earlydata_max)
            .field("quic_tp_len", &self.quic_tp.as_ref().map(Vec::len))
            .finish()
    }
}

/// A stored value paired with the absolute instant at which it must be
/// considered expired.
///
/// The opaque `rustls` session values do not expose their own expiry to the
/// store, so this wrapper attaches curl's per-version lifetime cap
/// ([`MAX_TLS13_LIFETIME_SECS`] / [`MAX_TLS12_LIFETIME_SECS`]) to each of them.
struct TimedValue<T> {
    value: T,
    /// Expiry instant, or `None` for "never expire".
    expires_at: Option<SystemTime>,
}

impl<T> TimedValue<T> {
    /// Wrap `value` with the given absolute expiry.
    fn new(value: T, expires_at: Option<SystemTime>) -> Self {
        Self { value, expires_at }
    }

    /// `true` once `now` is past the expiry instant (an unknown expiry never
    /// expires), matching [`StoredSession::is_expired`].
    fn is_expired(&self, now: SystemTime) -> bool {
        self.expires_at.is_some_and(|t| t < now)
    }
}

/// Per-peer cache slot — the Rust analog of curl's
/// `struct Curl_ssl_scache_peer` (`lib/vtls/vtls_scache.c`).
///
/// Holds the `rustls` key-exchange group hint, at most one TLS 1.2 session,
/// up to `max_sessions_per_peer` TLS 1.3 tickets (oldest at the front), and the
/// curl-parity raw [`StoredSession`] list used by the generic / QUIC path.
struct PeerBucket {
    /// Most recently observed key-exchange group for this peer
    /// (`rustls` `set_kx_hint` / `kx_hint`).
    kx_hint: Option<NamedGroup>,
    /// At most one TLS 1.2 session (curl kept a single pre-1.3 session too).
    tls12: Option<TimedValue<Tls12ClientSessionValue>>,
    /// TLS 1.3 tickets, oldest first, capped at `max_sessions_per_peer`.
    tls13: VecDeque<TimedValue<Tls13ClientSessionValue>>,
    /// Raw curl-parity sessions (used by the generic / QUIC-transport path),
    /// oldest first, capped at `max_sessions_per_peer`.
    sessions: VecDeque<StoredSession>,
    /// Recency marker for LRU peer eviction (curl's `peer->age`); a higher
    /// value means more recently used.
    age: u64,
}

impl PeerBucket {
    /// A fresh, empty peer slot.
    fn new() -> Self {
        Self {
            kx_hint: None,
            tls12: None,
            tls13: VecDeque::new(),
            sessions: VecDeque::new(),
            age: 0,
        }
    }

    /// `true` when the peer holds no cached state at all.
    ///
    /// Such a peer is reused before any live peer is evicted, mirroring the
    /// "empty/session-less peer" preference in curl's `cf_ssl_get_free_peer`.
    fn is_empty(&self) -> bool {
        self.kx_hint.is_none()
            && self.tls12.is_none()
            && self.tls13.is_empty()
            && self.sessions.is_empty()
    }

    /// Drop every expired TLS 1.2 / TLS 1.3 / raw session (lazy expiry on
    /// access), mirroring `cf_scache_peer_remove_expired`.
    fn prune_expired(&mut self, now: SystemTime) {
        if self.tls12.as_ref().is_some_and(|t| t.is_expired(now)) {
            self.tls12 = None;
        }
        self.tls13.retain(|t| !t.is_expired(now));
        self.sessions.retain(|s| !s.is_expired(now));
    }

    /// Insert a raw [`StoredSession`], reproducing `cf_scache_peer_add_session`.
    ///
    /// A non-TLS-1.3 session replaces *all* existing sessions (a resumable
    /// pre-1.3 session is single-valued). A TLS 1.3 session is appended after
    /// expired and non-1.3 sessions are dropped, then the list is trimmed from
    /// the front so at most `max` sessions remain (oldest evicted first). A
    /// `max` of `0` disables session caching, matching a zero-`max_sessions`
    /// peer in curl.
    fn add_stored_session(&mut self, session: StoredSession, max: usize, now: SystemTime) {
        if !session.is_tls13() {
            self.sessions.clear();
            self.sessions.push_back(session);
            return;
        }
        self.prune_expired(now);
        self.sessions.retain(StoredSession::is_tls13);
        self.sessions.push_back(session);
        while self.sessions.len() > max {
            self.sessions.pop_front();
        }
    }

    /// Append a TLS 1.3 ticket, dropping expired tickets first and then
    /// trimming the oldest (front) so at most `max` remain — the same bounded
    /// FIFO discipline curl applies to its per-peer session list.
    fn push_tls13(
        &mut self,
        value: TimedValue<Tls13ClientSessionValue>,
        max: usize,
        now: SystemTime,
    ) {
        self.tls13.retain(|t| !t.is_expired(now));
        self.tls13.push_back(value);
        while self.tls13.len() > max {
            self.tls13.pop_front();
        }
    }
}

/// The shared, mutex-guarded interior of a [`SessionCache`] — the analog of
/// curl's `struct Curl_ssl_scache`.
struct Inner {
    /// Peer table keyed by [`ServerName`]. Configuration isolation is provided
    /// by per-config store ownership (see the module docs), so the peer key is
    /// the server name alone, exactly as `rustls` keys its own store.
    peers: HashMap<ServerName<'static>, PeerBucket>,
    /// Maximum number of peers (curl's `max_peers`); `0` disables caching.
    max_peers: usize,
    /// Maximum number of sessions per peer (curl's `max_sessions`).
    max_sessions_per_peer: usize,
    /// Monotonic recency counter (curl's `scache->age`). Each access advances
    /// it and stamps the touched peer, yielding LRU semantics for eviction.
    age: u64,
}

impl Inner {
    /// Construct an empty interior with the given capacity limits.
    fn new(max_peers: usize, max_sessions_per_peer: usize) -> Self {
        Self {
            peers: HashMap::new(),
            max_peers,
            max_sessions_per_peer,
            age: 1,
        }
    }

    /// Advance and return the global recency counter (curl's `++scache->age`).
    fn next_age(&mut self) -> u64 {
        self.age = self.age.saturating_add(1);
        self.age
    }

    /// Number of peers currently tracked.
    fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Evict a single peer, preferring a wholly empty peer and otherwise the
    /// least-recently-used one — the ordering of curl's `cf_ssl_get_free_peer`.
    fn evict_one(&mut self) {
        if let Some(key) = self
            .peers
            .iter()
            .find(|(_, p)| p.is_empty())
            .map(|(k, _)| k.clone())
        {
            self.peers.remove(&key);
            return;
        }
        if let Some(key) = self
            .peers
            .iter()
            .min_by_key(|(_, p)| p.age)
            .map(|(k, _)| k.clone())
        {
            self.peers.remove(&key);
        }
    }

    /// Borrow the peer for `key` (bumping its recency), inserting a fresh peer
    /// and evicting to stay within `max_peers` when necessary.
    ///
    /// Returns `None` only when `max_peers == 0` (caching disabled).
    fn peer_entry(&mut self, key: ServerName<'static>) -> Option<&mut PeerBucket> {
        if self.max_peers == 0 {
            return None;
        }
        let age = self.next_age();
        // Only evict when we are about to grow the table past its bound with a
        // brand-new key; touching an existing peer never evicts.
        if !self.peers.contains_key(&key) && self.peers.len() >= self.max_peers {
            self.evict_one();
        }
        let peer = self.peers.entry(key).or_insert_with(PeerBucket::new);
        peer.age = age;
        Some(peer)
    }
}

/// Operations over the cache interior. Each takes an explicit `now` so the
/// public API and the [`ClientSessionStore`] trait can pass
/// [`SystemTime::now`] while tests inject a deterministic clock.
impl Inner {
    // ---- curl-parity raw StoredSession API ----

    /// Cache a raw session, applying the default lifetime and per-version cap
    /// first and dropping it outright if it is already expired — the body of
    /// `Curl_ssl_scache_put` / `cf_scache_add_session`.
    fn put_stored(
        &mut self,
        key: ServerName<'static>,
        mut session: StoredSession,
        now: SystemTime,
    ) {
        session.clamp_valid_until(now);
        if session.is_expired(now) {
            return;
        }
        let max = self.max_sessions_per_peer;
        if let Some(peer) = self.peer_entry(key) {
            peer.add_stored_session(session, max, now);
        }
    }

    /// Take (remove and return) the oldest unexpired raw session — the body of
    /// `Curl_ssl_scache_take`. A successful take bumps the peer's recency.
    fn take_stored(&mut self, key: &ServerName<'_>, now: SystemTime) -> Option<StoredSession> {
        let owned = key.to_owned();
        let peer = self.peers.get_mut(&owned)?;
        peer.prune_expired(now);
        let session = peer.sessions.pop_front()?;
        let age = self.next_age();
        if let Some(peer) = self.peers.get_mut(&owned) {
            peer.age = age;
        }
        Some(session)
    }

    /// Remove all cached state for a peer — the body of
    /// `Curl_ssl_scache_remove_all`.
    fn remove_all(&mut self, key: &ServerName<'_>) {
        let owned = key.to_owned();
        self.peers.remove(&owned);
    }

    // ---- rustls ClientSessionStore operations ----

    /// Remember the peer's chosen key-exchange group.
    fn set_kx_hint(&mut self, key: ServerName<'static>, group: NamedGroup) {
        if let Some(peer) = self.peer_entry(key) {
            peer.kx_hint = Some(group);
        }
    }

    /// Return the most recently remembered key-exchange group for the peer.
    fn kx_hint(&self, key: &ServerName<'_>) -> Option<NamedGroup> {
        let owned = key.to_owned();
        self.peers.get(&owned).and_then(|p| p.kx_hint)
    }

    /// Store the single TLS 1.2 session for the peer, capped at one day.
    fn set_tls12(
        &mut self,
        key: ServerName<'static>,
        value: Tls12ClientSessionValue,
        now: SystemTime,
    ) {
        let expires_at = now.checked_add(Duration::from_secs(MAX_TLS12_LIFETIME_SECS));
        if let Some(peer) = self.peer_entry(key) {
            peer.tls12 = Some(TimedValue::new(value, expires_at));
        }
    }

    /// Return a clone of the peer's TLS 1.2 session, dropping it first if it
    /// has expired.
    fn tls12(&mut self, key: &ServerName<'_>, now: SystemTime) -> Option<Tls12ClientSessionValue> {
        let owned = key.to_owned();
        let peer = self.peers.get_mut(&owned)?;
        if peer.tls12.as_ref().is_some_and(|t| t.is_expired(now)) {
            peer.tls12 = None;
        }
        peer.tls12.as_ref().map(|t| t.value.clone())
    }

    /// Forget any saved TLS 1.2 session for the peer.
    fn remove_tls12(&mut self, key: &ServerName<'_>) {
        let owned = key.to_owned();
        if let Some(peer) = self.peers.get_mut(&owned) {
            peer.tls12 = None;
        }
    }

    /// Insert a TLS 1.3 ticket, capped at seven days and bounded per peer.
    fn insert_tls13(
        &mut self,
        key: ServerName<'static>,
        value: Tls13ClientSessionValue,
        now: SystemTime,
    ) {
        let expires_at = now.checked_add(Duration::from_secs(MAX_TLS13_LIFETIME_SECS));
        let max = self.max_sessions_per_peer;
        if let Some(peer) = self.peer_entry(key) {
            peer.push_tls13(TimedValue::new(value, expires_at), max, now);
        }
    }

    /// Take (remove and return) the oldest unexpired TLS 1.3 ticket for the
    /// peer. Tickets are single-use per RFC 8446 §C.4, so this both returns and
    /// removes the ticket.
    fn take_tls13(
        &mut self,
        key: &ServerName<'_>,
        now: SystemTime,
    ) -> Option<Tls13ClientSessionValue> {
        let owned = key.to_owned();
        let peer = self.peers.get_mut(&owned)?;
        peer.prune_expired(now);
        peer.tls13.pop_front().map(|t| t.value)
    }
}

/// A bounded, thread-safe, expiry-aware TLS session-resumption cache.
///
/// This is the public handle described at the module level. It implements
/// [`rustls::client::ClientSessionStore`], so it can be installed directly on a
/// [`rustls::ClientConfig`] via [`SessionCache::as_rustls_store`], and it also
/// exposes a small curl-parity raw API ([`put_session`](Self::put_session) /
/// [`take_session`](Self::take_session) / [`remove_all`](Self::remove_all)) for
/// the generic and QUIC-transport-parameter paths.
///
/// Cloning a `SessionCache` is cheap and yields a second handle onto the *same*
/// underlying store — the mechanism by which resumption state is shared across
/// easy handles under curl's `curl_share` model (`CURL_LOCK_DATA_SSL_SESSION`).
/// When no share is configured, each [`rustls::ClientConfig`] simply keeps its
/// own private cache, which is also what enforces configuration isolation.
pub struct SessionCache {
    inner: Arc<Mutex<Inner>>,
}

impl SessionCache {
    /// Create a cache with the curl-parity default capacities
    /// ([`DEFAULT_MAX_PEERS`] peers × [`DEFAULT_MAX_SESSIONS_PER_PEER`] sessions
    /// per peer).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_PEERS, DEFAULT_MAX_SESSIONS_PER_PEER)
    }

    /// Create a cache sized for up to `max_peers` endpoints, each holding up to
    /// `max_sessions_per_peer` sessions — the analog of curl's
    /// `Curl_ssl_scache_create(max_peers, max_sessions_per_peer)`.
    ///
    /// A `max_peers` or `max_sessions_per_peer` of `0` disables caching on that
    /// axis, matching curl's behavior for a zero-sized cache.
    pub fn with_capacity(max_peers: usize, max_sessions_per_peer: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::new(max_peers, max_sessions_per_peer))),
        }
    }

    /// Return an `Arc<dyn ClientSessionStore>` for installation on a client
    /// configuration:
    ///
    /// ```ignore
    /// client_config.resumption = rustls::client::Resumption::store(cache.as_rustls_store());
    /// ```
    ///
    /// The returned trait object shares this cache's storage (it is an `Arc`
    /// clone of this handle), so sessions learned through the `rustls`
    /// handshake and sessions inserted through the raw API coexist in one
    /// place.
    pub fn as_rustls_store(&self) -> Arc<dyn ClientSessionStore> {
        Arc::new(self.clone())
    }

    /// Lock the interior, recovering rather than propagating a poisoned lock.
    ///
    /// A poisoned mutex is downgraded to "use the data anyway"
    /// ([`std::sync::PoisonError::into_inner`]): the worst outcome is a
    /// stale or skipped resumption, never a panicked transfer. This is what
    /// keeps every method non-panicking, as required for a TLS-layer leaf.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    // ---- curl-parity raw StoredSession API ----

    /// Cache a raw [`StoredSession`] for `server_name`, applying the default
    /// lifetime and per-version lifetime cap — the analog of
    /// `Curl_ssl_scache_put`.
    ///
    /// A session that is already expired after clamping is dropped rather than
    /// stored, exactly as curl does.
    pub fn put_session(&self, server_name: ServerName<'static>, session: StoredSession) {
        self.put_session_at(server_name, session, SystemTime::now());
    }

    /// Take (remove and return) the oldest unexpired raw session for
    /// `server_name` — the analog of `Curl_ssl_scache_take`. Returns `None`
    /// when no live session is cached.
    pub fn take_session(&self, server_name: &ServerName<'_>) -> Option<StoredSession> {
        self.take_session_at(server_name, SystemTime::now())
    }

    /// Remove *all* cached state (raw sessions, TLS 1.2 / TLS 1.3 values, and
    /// the key-exchange hint) for `server_name` — the analog of
    /// `Curl_ssl_scache_remove_all`.
    pub fn remove_all(&self, server_name: &ServerName<'_>) {
        self.lock().remove_all(server_name);
    }

    /// Number of peers currently tracked. Primarily for tests and diagnostics.
    pub fn peer_count(&self) -> usize {
        self.lock().peer_count()
    }

    /// `true` when the cache holds no peers.
    pub fn is_empty(&self) -> bool {
        self.peer_count() == 0
    }

    // ---- time-injectable inherent helpers ----

    /// [`put_session`](Self::put_session) with an explicit clock.
    fn put_session_at(
        &self,
        server_name: ServerName<'static>,
        session: StoredSession,
        now: SystemTime,
    ) {
        self.lock().put_stored(server_name, session, now);
    }

    /// [`take_session`](Self::take_session) with an explicit clock.
    fn take_session_at(
        &self,
        server_name: &ServerName<'_>,
        now: SystemTime,
    ) -> Option<StoredSession> {
        self.lock().take_stored(server_name, now)
    }
}

impl Default for SessionCache {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for SessionCache {
    /// Clones the *handle*, not the data: the clone shares the same underlying
    /// store (the `curl_share` sharing model).
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl fmt::Debug for SessionCache {
    /// Never prints session contents (they are secret); reports only the
    /// configured capacity and the current peer count. This also satisfies the
    /// [`fmt::Debug`] supertrait required by [`ClientSessionStore`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let guard = self.lock();
        f.debug_struct("SessionCache")
            .field("peers", &guard.peers.len())
            .field("max_peers", &guard.max_peers)
            .field("max_sessions_per_peer", &guard.max_sessions_per_peer)
            .finish_non_exhaustive()
    }
}

/// `rustls`'s client-side session store, backed by this bounded, expiry-aware
/// cache.
///
/// Every method takes `&self` (interior mutability via the [`Mutex`]) and is
/// non-panicking. Expiry and capacity are enforced here — TLS 1.2 sessions are
/// held for at most one day, TLS 1.3 tickets for at most seven days, and both
/// are bounded per peer. The trait's supertraits `Debug + Send + Sync` are
/// satisfied by the redacting [`fmt::Debug`] impl above and by the fact that
/// `Arc<Mutex<Inner>>` — whose contents (`ServerName`, the `rustls` value
/// types, `NamedGroup`) are all `Send + Sync` — is itself `Send + Sync`.
impl ClientSessionStore for SessionCache {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        self.lock().set_kx_hint(server_name, group);
    }

    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
        self.lock().kx_hint(server_name)
    }

    fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.lock().set_tls12(server_name, value, SystemTime::now());
    }

    fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.lock().tls12(server_name, SystemTime::now())
    }

    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.lock().remove_tls12(server_name);
    }

    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: Tls13ClientSessionValue,
    ) {
        self.lock()
            .insert_tls13(server_name, value, SystemTime::now());
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue> {
        self.lock().take_tls13(server_name, SystemTime::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed, deterministic clock base (~2023-11-14T22:13:20Z) so time-based
    /// assertions never depend on the wall clock.
    fn base() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    /// Build an owned `ServerName` from a DNS name for use as a cache key.
    fn name(host: &str) -> ServerName<'static> {
        ServerName::try_from(host.to_string()).expect("valid dns name")
    }

    fn tls13_session(sdata: Vec<u8>, valid_until: Option<SystemTime>) -> StoredSession {
        StoredSession::new(sdata, IETF_PROTO_TLS1_3, None, valid_until, 0)
    }

    // ---- StoredSession (Phase 1) ----

    #[test]
    fn stored_session_is_expired() {
        let now = base();
        // Unknown expiry never expires (curl's `valid_until == 0`).
        assert!(!tls13_session(vec![1], None).is_expired(now));
        // Strictly-past expiry is expired.
        assert!(tls13_session(vec![1], Some(now - Duration::from_secs(1))).is_expired(now));
        // Future expiry is live.
        assert!(!tls13_session(vec![1], Some(now + Duration::from_secs(1))).is_expired(now));
    }

    #[test]
    fn stored_session_clamp_default_and_caps() {
        let now = base();

        // Unknown expiry gets the one-day default (which is within the 7-day
        // TLS 1.3 cap, so it is not reduced further).
        let mut s = tls13_session(vec![], None);
        s.clamp_valid_until(now);
        assert_eq!(
            s.valid_until,
            Some(now + Duration::from_secs(DEFAULT_LIFETIME_SECS))
        );

        // A far-future TLS 1.3 expiry is clamped to the seven-day cap.
        let mut s = tls13_session(vec![], Some(now + Duration::from_secs(100 * 86_400)));
        s.clamp_valid_until(now);
        assert_eq!(
            s.valid_until,
            Some(now + Duration::from_secs(MAX_TLS13_LIFETIME_SECS))
        );

        // A far-future TLS 1.2 expiry is clamped to the one-day cap.
        let mut s = StoredSession::new(
            vec![],
            0x0303,
            None,
            Some(now + Duration::from_secs(100 * 86_400)),
            0,
        );
        s.clamp_valid_until(now);
        assert_eq!(
            s.valid_until,
            Some(now + Duration::from_secs(MAX_TLS12_LIFETIME_SECS))
        );

        // A server expiry that is *earlier* than the cap is preserved (the cap
        // is a ceiling, not a floor).
        let mut s = tls13_session(vec![], Some(now + Duration::from_secs(3600)));
        s.clamp_valid_until(now);
        assert_eq!(s.valid_until, Some(now + Duration::from_secs(3600)));
    }

    #[test]
    fn timed_value_is_expired() {
        let now = base();
        assert!(!TimedValue::new(0u8, None).is_expired(now));
        assert!(TimedValue::new(0u8, Some(now - Duration::from_secs(1))).is_expired(now));
        assert!(!TimedValue::new(0u8, Some(now + Duration::from_secs(1))).is_expired(now));
    }

    // ---- Raw session store: single-use, replace, remove (Phases 2 & 5) ----

    #[test]
    fn raw_tls13_single_use() {
        let cache = SessionCache::with_capacity(4, 4);
        let host = name("single.example");
        cache.put_session_at(host.clone(), tls13_session(vec![0xAB], None), base());

        // First take returns the ticket; the second finds it gone (single-use).
        let taken = cache.take_session_at(&host, base()).expect("first take");
        assert_eq!(taken.sdata, vec![0xAB]);
        assert!(cache.take_session_at(&host, base()).is_none());
    }

    #[test]
    fn raw_pre_tls13_replaces_and_remove() {
        let cache = SessionCache::with_capacity(4, 4);
        let host = name("legacy.example");

        // A pre-1.3 session is single-valued: the second put replaces the first.
        cache.put_session_at(
            host.clone(),
            StoredSession::new(vec![1], 0x0303, None, None, 0),
            base(),
        );
        cache.put_session_at(
            host.clone(),
            StoredSession::new(vec![2], 0x0303, None, None, 0),
            base(),
        );
        let taken = cache.take_session_at(&host, base()).expect("take");
        assert_eq!(taken.sdata, vec![2]);
        assert!(cache.take_session_at(&host, base()).is_none());

        // remove_all clears the peer entirely.
        cache.put_session_at(
            host.clone(),
            StoredSession::new(vec![3], 0x0303, None, None, 0),
            base(),
        );
        cache.remove_all(&host);
        assert!(cache.take_session_at(&host, base()).is_none());
        assert_eq!(cache.peer_count(), 0);
    }

    // ---- Expiry and lifetime cap through the store (Phase 5) ----

    #[test]
    fn raw_past_expiry_not_returned() {
        let cache = SessionCache::with_capacity(4, 4);
        let host = name("expiring.example");
        // Live when stored, but expired by the time it is accessed.
        cache.put_session_at(
            host.clone(),
            tls13_session(vec![9], Some(base() + Duration::from_secs(10))),
            base(),
        );
        assert!(cache
            .take_session_at(&host, base() + Duration::from_secs(20))
            .is_none());
    }

    #[test]
    fn raw_far_future_clamped_to_seven_days() {
        let far = Some(base() + Duration::from_secs(100 * 86_400));

        // Within the seven-day cap the session is still returned.
        let cache = SessionCache::with_capacity(4, 4);
        let host = name("cap.example");
        cache.put_session_at(host.clone(), tls13_session(vec![1], far), base());
        assert!(cache
            .take_session_at(&host, base() + Duration::from_secs(6 * 86_400))
            .is_some());

        // Just past the cap it is gone — proving the far-future expiry was
        // clamped to `now + 7 days` on insertion.
        let cache = SessionCache::with_capacity(4, 4);
        let host = name("cap.example");
        cache.put_session_at(host.clone(), tls13_session(vec![1], far), base());
        assert!(cache
            .take_session_at(
                &host,
                base() + Duration::from_secs(MAX_TLS13_LIFETIME_SECS + 60)
            )
            .is_none());
    }

    // ---- Capacity / eviction (Phase 5) ----

    #[test]
    fn capacity_evicts_oldest_session_per_peer() {
        // Two sessions per peer; a third insert evicts the oldest (front).
        let cache = SessionCache::with_capacity(4, 2);
        let host = name("busy.example");
        for tag in [1u8, 2, 3] {
            cache.put_session_at(host.clone(), tls13_session(vec![tag], None), base());
        }
        // The oldest ([1]) was evicted; [2] then [3] remain, oldest-first.
        assert_eq!(cache.take_session_at(&host, base()).unwrap().sdata, vec![2]);
        assert_eq!(cache.take_session_at(&host, base()).unwrap().sdata, vec![3]);
        assert!(cache.take_session_at(&host, base()).is_none());
    }

    #[test]
    fn capacity_evicts_lru_peer() {
        // Room for two peers; inserting a third evicts the least-recently-used.
        let cache = SessionCache::with_capacity(2, 2);
        let (a, b, c) = (name("a.example"), name("b.example"), name("c.example"));
        cache.put_session_at(a.clone(), tls13_session(vec![1], None), base());
        cache.put_session_at(b.clone(), tls13_session(vec![2], None), base());
        cache.put_session_at(c.clone(), tls13_session(vec![3], None), base());

        assert_eq!(cache.peer_count(), 2);
        // `a` was the least recently used, so it was evicted.
        assert!(cache.take_session_at(&a, base()).is_none());
        assert!(cache.take_session_at(&b, base()).is_some());
        assert!(cache.take_session_at(&c, base()).is_some());
    }

    // ---- Sharing across clones (Phase 5) ----

    #[test]
    fn sharing_between_clones() {
        let cache = SessionCache::new();
        let shared = cache.clone();
        // An insert on one handle is visible through the other (same `Arc`).
        cache.put_session_at(name("shared.example"), tls13_session(vec![7], None), base());
        assert_eq!(shared.peer_count(), 1);
        let taken = shared
            .take_session_at(&name("shared.example"), base())
            .expect("clone observes insert");
        assert_eq!(taken.sdata, vec![7]);
    }

    // ---- rustls ClientSessionStore surface ----

    #[test]
    fn rustls_kx_hint_roundtrip() {
        let cache = SessionCache::new();
        let host = name("kx.example");
        cache.set_kx_hint(host.clone(), NamedGroup::X25519);
        assert_eq!(cache.kx_hint(&host), Some(NamedGroup::X25519));
        // A later hint replaces the earlier one.
        cache.set_kx_hint(host.clone(), NamedGroup::secp256r1);
        assert_eq!(cache.kx_hint(&host), Some(NamedGroup::secp256r1));
        // An unknown peer has no hint.
        assert_eq!(cache.kx_hint(&name("unknown.example")), None);
    }

    #[test]
    fn rustls_empty_lookups_return_none() {
        let cache = SessionCache::new();
        let host = name("empty.example");
        // No sessions of any kind for an untouched peer; nothing panics.
        assert!(cache.tls12_session(&host).is_none());
        assert!(cache.take_tls13_ticket(&host).is_none());
        cache.remove_tls12_session(&host);
        assert!(cache.is_empty());
    }

    #[test]
    fn as_rustls_store_shares_storage() {
        let cache = SessionCache::new();
        let store = cache.as_rustls_store();
        let host = name("store.example");
        // A hint set through the owning handle is visible through the trait
        // object returned by `as_rustls_store` (they share one `Arc`).
        cache.set_kx_hint(host.clone(), NamedGroup::secp256r1);
        assert_eq!(store.kx_hint(&host), Some(NamedGroup::secp256r1));
    }

    #[test]
    fn implements_send_sync_and_store() {
        fn assert_send_sync<T: Send + Sync>() {}
        fn assert_store<T: ClientSessionStore>() {}
        assert_send_sync::<SessionCache>();
        assert_store::<SessionCache>();
        // The handle can be erased to the trait object `config.rs` installs.
        let _store: Arc<dyn ClientSessionStore> = SessionCache::new().as_rustls_store();
    }
}
