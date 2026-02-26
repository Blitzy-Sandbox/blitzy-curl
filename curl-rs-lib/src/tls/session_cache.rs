//! TLS Session Resumption Cache.
//!
//! Rust rewrite of `lib/vtls/vtls_scache.c` and `lib/vtls/vtls_spack.c` — TLS
//! session resumption cache that stores and retrieves TLS session tickets/IDs
//! for connection reuse across transfers.
//!
//! # Architecture
//!
//! The session cache is organized as a two-level structure:
//! - **Level 1 (peers)**: A `HashMap<String, PeerEntry>` keyed by a composite
//!   peer key string that encodes the hostname, port, and TLS configuration.
//! - **Level 2 (sessions)**: Each peer entry contains a `VecDeque<TlsSession>`
//!   holding session tickets in FIFO order.
//!
//! # Thread Safety
//!
//! - [`SessionCache`] is **not** thread-safe and requires external synchronization.
//! - [`SharedSessionCache`] wraps `SessionCache` in `Arc<Mutex<...>>` for use with
//!   `curl_share` session sharing across handles.
//!
//! # TLS Version Lifetime Limits
//!
//! - TLS 1.3 sessions: maximum 7-day lifetime (RFC 8446).
//! - TLS 1.2 and below: maximum 1-day lifetime (conservative).
//! - TLS 1.3 sessions are single-use per RFC 8446 Appendix C.4 and are NOT
//!   returned to the cache after being taken.
//!
//! # Serialization
//!
//! Sessions can be serialized to a TLV (Tag-Length-Value) binary format for
//! export/import, matching the C `vtls_spack.c` wire format for interoperability.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::CurlError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// RFC 8446: TLS 1.3 sessions restricted to 7-day max lifetime.
///
/// Matches C `CURL_SCACHE_MAX_13_LIFETIME_SEC` (604,800 seconds).
pub const MAX_TLS13_LIFETIME: Duration = Duration::from_secs(60 * 60 * 24 * 7);

/// Pre-TLS 1.3 sessions restricted to 1-day max lifetime.
///
/// Matches C `CURL_SCACHE_MAX_12_LIFETIME_SEC` (86,400 seconds).
pub const MAX_TLS12_LIFETIME: Duration = Duration::from_secs(60 * 60 * 24);

/// Default maximum number of cached peers.
pub const DEFAULT_MAX_PEERS: usize = 100;

/// Default maximum sessions per peer.
pub const DEFAULT_MAX_SESSIONS_PER_PEER: usize = 8;

/// IETF protocol version identifier for TLS 1.3 (0x0304).
/// Sessions at or above this version follow TLS 1.3 caching rules.
const IETF_PROTO_TLS1_3: u16 = 0x0304;

/// Default session lifetime when no explicit `valid_until` is provided.
/// Matches C `scache->default_lifetime_secs = (24 * 60 * 60)`.
const DEFAULT_LIFETIME: Duration = Duration::from_secs(86_400);

// ---------------------------------------------------------------------------
// TLV serialization tag constants (from vtls_spack.c)
// ---------------------------------------------------------------------------

/// Version marker byte — must be the first byte in a serialized stream.
const SPACK_VERSION: u8 = 0x01;

/// IETF TLS protocol version identifier (followed by 16-bit big-endian value).
const SPACK_IETF_ID: u8 = 0x02;

/// Session valid_until as Unix timestamp (followed by 64-bit big-endian value).
const SPACK_VALID_UNTIL: u8 = 0x03;

/// Session ticket data (followed by 16-bit big-endian length, then raw bytes).
const SPACK_TICKET: u8 = 0x04;

/// ALPN protocol string (followed by 16-bit big-endian length, then UTF-8 bytes).
const SPACK_ALPN: u8 = 0x05;

/// Maximum early data size (followed by 32-bit big-endian value).
const SPACK_EARLYDATA: u8 = 0x06;

/// QUIC transport parameters (followed by 16-bit big-endian length, then raw bytes).
const SPACK_QUICTP: u8 = 0x07;

// ---------------------------------------------------------------------------
// TlsSession
// ---------------------------------------------------------------------------

/// A single TLS session ticket/ID with associated metadata.
///
/// Replaces C `struct Curl_ssl_session` from `vtls_scache.h` lines 124-134.
/// The session contains serialized ticket data, protocol information, and
/// expiry tracking for resumption on subsequent connections to the same peer.
#[derive(Debug, Clone)]
pub struct TlsSession {
    /// Serialized session ticket data (opaque to the cache).
    ///
    /// Contains the raw session ticket bytes produced by the TLS implementation
    /// (rustls). This data is passed back to the TLS handshake for resumption.
    pub ticket_data: Vec<u8>,

    /// ALPN protocol negotiated during the session (e.g., `"h2"`, `"http/1.1"`).
    ///
    /// Stored so that resumed sessions can verify ALPN compatibility.
    pub alpn: Option<String>,

    /// IETF TLS protocol version identifier (e.g., `0x0304` for TLS 1.3).
    ///
    /// Used to determine lifetime limits and single-use policy (TLS 1.3+).
    pub ietf_tls_id: u16,

    /// Expiry timestamp. Sessions are considered expired after this point.
    ///
    /// Set by the server's NewSessionTicket message lifetime field, clamped
    /// to the maximum allowed lifetime for the TLS version.
    pub valid_until: SystemTime,

    /// Maximum early data (0-RTT) size supported by the peer.
    ///
    /// Zero if the peer does not support early data.
    pub earlydata_max: u32,

    /// QUIC transport parameters associated with this session.
    ///
    /// Present only for sessions established over QUIC transport, used during
    /// 0-RTT connection resumption.
    pub quic_transport_params: Option<Vec<u8>>,

    /// When this session object was created, used for internal age tracking.
    ///
    /// Not serialized — set to `Instant::now()` on creation or deserialization.
    pub created_at: Instant,
}

impl TlsSession {
    /// Returns `true` if this session has expired.
    ///
    /// Matches C `cf_scache_session_expired()` from vtls_scache.c lines 499-503.
    /// A session with `valid_until` at or before `UNIX_EPOCH` (timestamp 0) is
    /// never considered expired — it has no explicit expiry set.
    pub fn is_expired(&self) -> bool {
        // Match C behavior: valid_until > 0 && valid_until < now
        if self.valid_until <= UNIX_EPOCH {
            return false;
        }
        SystemTime::now() >= self.valid_until
    }

    /// Returns the maximum allowed lifetime for this session based on its TLS
    /// protocol version.
    ///
    /// - TLS 1.3 (`>= 0x0304`): 7 days (`MAX_TLS13_LIFETIME`)
    /// - TLS 1.2 and below: 1 day (`MAX_TLS12_LIFETIME`)
    fn max_lifetime(&self) -> Duration {
        if self.ietf_tls_id >= IETF_PROTO_TLS1_3 {
            MAX_TLS13_LIFETIME
        } else {
            MAX_TLS12_LIFETIME
        }
    }

    /// Serialize this session into a TLV binary format.
    ///
    /// Matches C `Curl_ssl_session_pack()` from vtls_spack.c lines 191-237.
    /// All multi-byte integers are encoded in **big-endian** byte order.
    ///
    /// # Wire Format
    ///
    /// ```text
    /// [VERSION:u8=0x01]
    /// [TICKET_TAG:u8=0x04] [ticket_len:u16] [ticket_data:bytes]
    /// [IETF_ID_TAG:u8=0x02] [ietf_tls_id:u16]
    /// [VALID_UNTIL_TAG:u8=0x03] [unix_secs:u64]
    /// [ALPN_TAG:u8=0x05] [alpn_len:u16] [alpn_bytes:bytes]      (optional)
    /// [EARLYDATA_TAG:u8=0x06] [earlydata_max:u32]                (optional)
    /// [QUICTP_TAG:u8=0x07] [quic_tp_len:u16] [quic_tp:bytes]    (optional)
    /// ```
    pub fn serialize(&self) -> Vec<u8> {
        // Pre-calculate capacity for a single allocation
        let capacity = 1  // version marker
            + 1 + 2 + self.ticket_data.len()  // ticket tag + len + data
            + 1 + 2  // ietf_id tag + value
            + 1 + 8  // valid_until tag + value
            + self.alpn.as_ref().map_or(0, |a| 1 + 2 + a.len())  // optional alpn
            + if self.earlydata_max > 0 { 1 + 4 } else { 0 }  // optional earlydata
            + self.quic_transport_params.as_ref().map_or(0, |q| 1 + 2 + q.len());

        let mut buf = Vec::with_capacity(capacity);

        // 1. Version marker
        buf.push(SPACK_VERSION);

        // 2. Ticket data: tag + 16-bit big-endian length + raw bytes
        buf.push(SPACK_TICKET);
        let ticket_len = self.ticket_data.len().min(u16::MAX as usize) as u16;
        buf.extend_from_slice(&ticket_len.to_be_bytes());
        buf.extend_from_slice(&self.ticket_data[..ticket_len as usize]);

        // 3. IETF TLS protocol version: tag + 16-bit big-endian
        buf.push(SPACK_IETF_ID);
        buf.extend_from_slice(&self.ietf_tls_id.to_be_bytes());

        // 4. Valid until: tag + 64-bit big-endian Unix timestamp
        buf.push(SPACK_VALID_UNTIL);
        let unix_secs = self
            .valid_until
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        buf.extend_from_slice(&unix_secs.to_be_bytes());

        // 5. ALPN (optional): tag + 16-bit length + UTF-8 string
        if let Some(ref alpn) = self.alpn {
            let alpn_bytes = alpn.as_bytes();
            if !alpn_bytes.is_empty() && alpn_bytes.len() <= u16::MAX as usize {
                buf.push(SPACK_ALPN);
                let alpn_len = alpn_bytes.len() as u16;
                buf.extend_from_slice(&alpn_len.to_be_bytes());
                buf.extend_from_slice(alpn_bytes);
            }
        }

        // 6. Early data max (optional): tag + 32-bit big-endian (only if non-zero)
        if self.earlydata_max > 0 {
            buf.push(SPACK_EARLYDATA);
            buf.extend_from_slice(&self.earlydata_max.to_be_bytes());
        }

        // 7. QUIC transport parameters (optional): tag + 16-bit length + bytes
        if let Some(ref quic_tp) = self.quic_transport_params {
            if !quic_tp.is_empty() && quic_tp.len() <= u16::MAX as usize {
                buf.push(SPACK_QUICTP);
                let tp_len = quic_tp.len() as u16;
                buf.extend_from_slice(&tp_len.to_be_bytes());
                buf.extend_from_slice(quic_tp);
            }
        }

        buf
    }

    /// Deserialize a session from a TLV binary format.
    ///
    /// Matches C `Curl_ssl_session_unpack()` from vtls_spack.c lines 239-327.
    ///
    /// # Errors
    ///
    /// - [`CurlError::ReadError`] — data is truncated or the version marker is
    ///   invalid or an unknown tag is encountered.
    /// - [`CurlError::BadFunctionArgument`] — malformed TLV (e.g., non-UTF-8
    ///   ALPN, missing ticket data).
    /// - [`CurlError::OutOfMemory`] — memory allocation failure when decoding
    ///   variable-length fields.
    pub fn deserialize(data: &[u8]) -> Result<Self, CurlError> {
        if data.is_empty() {
            return Err(CurlError::ReadError);
        }

        let mut pos: usize = 0;

        // First byte must be the version marker (0x01)
        let version = read_u8(data, &mut pos)?;
        if version != SPACK_VERSION {
            return Err(CurlError::ReadError);
        }

        let mut ticket_data: Option<Vec<u8>> = None;
        let mut alpn: Option<String> = None;
        let mut ietf_tls_id: u16 = 0;
        let mut valid_until_secs: u64 = 0;
        let mut earlydata_max: u32 = 0;
        let mut quic_transport_params: Option<Vec<u8>> = None;

        // Parse tag-value pairs until end of data
        while pos < data.len() {
            let tag = read_u8(data, &mut pos)?;

            match tag {
                SPACK_TICKET => {
                    ticket_data = Some(read_data16(data, &mut pos)?);
                }
                SPACK_IETF_ID => {
                    ietf_tls_id = read_u16(data, &mut pos)?;
                }
                SPACK_VALID_UNTIL => {
                    valid_until_secs = read_u64(data, &mut pos)?;
                }
                SPACK_ALPN => {
                    let alpn_bytes = read_data16(data, &mut pos)?;
                    alpn = Some(
                        String::from_utf8(alpn_bytes)
                            .map_err(|_| CurlError::BadFunctionArgument)?,
                    );
                }
                SPACK_EARLYDATA => {
                    earlydata_max = read_u32(data, &mut pos)?;
                }
                SPACK_QUICTP => {
                    quic_transport_params = Some(read_data16(data, &mut pos)?);
                }
                _ => {
                    // Unknown tag — matching C behavior (returns CURLE_READ_ERROR
                    // in the default switch case of Curl_ssl_session_unpack)
                    return Err(CurlError::ReadError);
                }
            }
        }

        // Ticket data is mandatory — matches C validation where sdata must be
        // non-NULL and sdata_len must be > 0
        let ticket = ticket_data.ok_or(CurlError::BadFunctionArgument)?;
        if ticket.is_empty() {
            return Err(CurlError::BadFunctionArgument);
        }

        let valid_until = UNIX_EPOCH + Duration::from_secs(valid_until_secs);

        Ok(TlsSession {
            ticket_data: ticket,
            alpn,
            ietf_tls_id,
            valid_until,
            earlydata_max,
            quic_transport_params,
            created_at: Instant::now(),
        })
    }
}

// ---------------------------------------------------------------------------
// Peer Key Generation
// ---------------------------------------------------------------------------

/// Generate a composite peer key for session cache lookup.
///
/// Combines hostname, port, and TLS configuration hash into a unique string
/// key used to look up cached sessions. This matches the concept of C
/// `Curl_ssl_peer_key_make()` from vtls_scache.c lines 138-297, which builds
/// a composite key from the peer hostname, port, transport, TLS verification
/// options, cipher configuration, CA paths, client certificate, and TLS
/// implementation identifier.
///
/// # Arguments
///
/// * `hostname` — Target server hostname (e.g., `"example.com"`).
/// * `port` — Target server port (e.g., `443`).
/// * `tls_config_hash` — A hash or identifier string representing the TLS
///   configuration (version, ciphers, CA, client cert, etc.). An empty string
///   is valid for default configuration.
///
/// # Returns
///
/// A unique string key in the format `"hostname:port:config_hash"`.
///
/// # Examples
///
/// ```ignore
/// let key = make_peer_key("example.com", 443, "rustls-default");
/// assert_eq!(key, "example.com:443:rustls-default");
/// ```
pub fn make_peer_key(hostname: &str, port: u16, tls_config_hash: &str) -> String {
    // Pre-allocate: hostname + ':' + port(max 5 digits) + ':' + hash
    let mut key = String::with_capacity(hostname.len() + tls_config_hash.len() + 8);
    key.push_str(hostname);
    key.push(':');
    // Format port as decimal string without external crate
    let port_str = format!("{}", port);
    key.push_str(&port_str);
    if !tls_config_hash.is_empty() {
        key.push(':');
        key.push_str(tls_config_hash);
    }
    key
}

// ---------------------------------------------------------------------------
// PeerEntry (internal)
// ---------------------------------------------------------------------------

/// Internal per-peer session storage.
///
/// Replaces C `struct Curl_ssl_scache_peer` from vtls_scache.c lines 50-64.
/// Uses `VecDeque` instead of C `Curl_llist` for efficient FIFO operations
/// with O(1) push_back and pop_front.
struct PeerEntry {
    /// Session tickets for this peer, ordered oldest-first (FIFO).
    sessions: VecDeque<TlsSession>,
    /// Maximum number of sessions allowed for this peer.
    max_sessions: usize,
    /// Last time this peer entry was accessed, for LRU eviction.
    /// Replaces C `scache->age` counter with timestamp-based tracking.
    last_used: Instant,
}

impl PeerEntry {
    /// Create a new empty peer entry with the given session capacity.
    fn new(max_sessions: usize) -> Self {
        PeerEntry {
            sessions: VecDeque::new(),
            max_sessions,
            last_used: Instant::now(),
        }
    }

    /// Remove all expired sessions from this peer's queue.
    ///
    /// Matches C `cf_scache_peer_remove_expired()` from vtls_scache.c
    /// lines 505-515.
    fn remove_expired(&mut self) {
        let now = SystemTime::now();
        self.sessions.retain(|s| {
            // Keep sessions that have no explicit expiry (valid_until <= EPOCH)
            // or have not yet expired
            s.valid_until <= UNIX_EPOCH || s.valid_until > now
        });
    }

    /// Remove all non-TLS 1.3 sessions.
    ///
    /// Used when adding a TLS 1.3 session to ensure only TLS 1.3 sessions
    /// coexist in the queue. Matches C `cf_scache_peer_remove_non13()` from
    /// vtls_scache.c lines 517-526.
    fn remove_non_tls13(&mut self) {
        self.sessions
            .retain(|s| s.ietf_tls_id >= IETF_PROTO_TLS1_3);
    }

    /// Add a session following TLS-version-specific rules.
    ///
    /// Matches C `cf_scache_peer_add_session()` from vtls_scache.c lines
    /// 760-778:
    /// - **Non-TLS 1.3**: Clears all existing sessions and stores only the
    ///   new session (pre-1.3 sessions are not accumulated).
    /// - **TLS 1.3**: Removes expired and non-1.3 sessions, appends the new
    ///   session, and trims the oldest sessions to enforce `max_sessions`.
    fn add_session(&mut self, session: TlsSession) {
        if session.ietf_tls_id < IETF_PROTO_TLS1_3 {
            // Non-TLS 1.3: replace all existing sessions with the new one
            self.sessions.clear();
            self.sessions.push_back(session);
        } else {
            // TLS 1.3: accumulate sessions up to max_sessions
            self.remove_expired();
            self.remove_non_tls13();
            self.sessions.push_back(session);
            // Trim from front (oldest first) to enforce capacity limit
            while self.sessions.len() > self.max_sessions {
                self.sessions.pop_front();
            }
        }
        self.last_used = Instant::now();
    }

    /// Take the first non-expired session from the queue.
    ///
    /// Removes expired sessions encountered during the scan, then pops the
    /// first remaining session. Updates the LRU timestamp.
    fn take_session(&mut self) -> Option<TlsSession> {
        self.remove_expired();
        self.last_used = Instant::now();
        self.sessions.pop_front()
    }

    /// Returns `true` if this peer has no sessions.
    fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

// ---------------------------------------------------------------------------
// SessionCache
// ---------------------------------------------------------------------------

/// TLS session resumption cache.
///
/// Stores TLS session tickets per peer for connection reuse across transfers.
/// This is the non-thread-safe variant intended for single-handle use; use
/// [`SharedSessionCache`] when session sharing across handles is required
/// (e.g., via `curl_share`).
///
/// Replaces C `struct Curl_ssl_scache` from vtls_scache.c lines 299-305 and
/// the associated `Curl_ssl_scache_*` API functions.
///
/// # Capacity Management
///
/// The cache enforces two capacity limits:
/// - `max_peers`: Maximum number of distinct peers (host+port+config combos)
///   that can have sessions cached simultaneously. When this limit is reached,
///   the least-recently-used peer is evicted to make room.
/// - `max_sessions_per_peer`: Maximum sessions stored per peer. For TLS 1.3,
///   where servers may issue multiple session tickets, the oldest tickets are
///   evicted when this limit is exceeded. For TLS 1.2 and below, only one
///   session is stored per peer.
pub struct SessionCache {
    /// Map of peer key string → per-peer session storage.
    peers: HashMap<String, PeerEntry>,
    /// Maximum number of distinct peers in the cache.
    max_peers: usize,
    /// Maximum sessions stored per peer.
    max_sessions_per_peer: usize,
}

impl SessionCache {
    /// Create a new session cache with the given capacity limits.
    ///
    /// Matches C `Curl_ssl_scache_create()` from vtls_scache.c lines 528-560.
    ///
    /// # Arguments
    ///
    /// * `max_peers` — Maximum number of distinct peers to cache sessions for.
    ///   A value of 0 effectively disables caching.
    /// * `max_sessions_per_peer` — Maximum sessions per peer (primarily
    ///   relevant for TLS 1.3 where multiple session tickets may be issued).
    pub fn new(max_peers: usize, max_sessions_per_peer: usize) -> Self {
        SessionCache {
            // Pre-allocate up to 64 entries to avoid excessive initial allocation
            // for very large max_peers values
            peers: HashMap::with_capacity(max_peers.min(64)),
            max_peers,
            max_sessions_per_peer,
        }
    }

    /// Store a session in the cache for the given peer key.
    ///
    /// Matches C `Curl_ssl_scache_put()` / `cf_scache_add_session()` from
    /// vtls_scache.c lines 780-855.
    ///
    /// # Behavior
    ///
    /// 1. If `max_peers` is 0, the session is silently dropped (caching disabled).
    /// 2. If `valid_until` is at or before `UNIX_EPOCH`, a default 1-day lifetime
    ///    is applied (matching C `scache->default_lifetime_secs`).
    /// 3. `valid_until` is clamped to the maximum allowed lifetime for the TLS
    ///    version (7 days for TLS 1.3, 1 day for TLS 1.2 and below).
    /// 4. Already-expired sessions are silently dropped.
    /// 5. If the peer cache is full, the least-recently-used peer is evicted.
    /// 6. The session is added following TLS-version-specific rules (see
    ///    [`PeerEntry::add_session`]).
    pub fn put(&mut self, peer_key: &str, mut session: TlsSession) {
        if self.max_peers == 0 {
            return;
        }

        let now = SystemTime::now();

        // Apply default lifetime if valid_until is not explicitly set
        // Matches C: if(s->valid_until <= 0) s->valid_until = now + default_lifetime
        if session.valid_until <= UNIX_EPOCH {
            session.valid_until = now + DEFAULT_LIFETIME;
        }

        // Clamp valid_until to the maximum allowed lifetime for this TLS version
        // Matches C: if(s->valid_until > (now + max_lifetime))
        //                s->valid_until = now + max_lifetime;
        let max_lifetime = session.max_lifetime();
        if let Ok(remaining) = session.valid_until.duration_since(now) {
            if remaining > max_lifetime {
                session.valid_until = now + max_lifetime;
            }
        }

        // Drop already-expired sessions
        // Matches C: if(cf_scache_session_expired(s, now)) { destroy; return OK; }
        if session.valid_until <= UNIX_EPOCH {
            return;
        }
        if now >= session.valid_until {
            return;
        }

        // Find existing peer or create a new one
        if !self.peers.contains_key(peer_key) {
            // Evict LRU peer if cache is at capacity
            if self.peers.len() >= self.max_peers {
                self.evict_lru_peer();
            }
            self.peers.insert(
                peer_key.to_owned(),
                PeerEntry::new(self.max_sessions_per_peer),
            );
        }

        if let Some(peer) = self.peers.get_mut(peer_key) {
            peer.add_session(session);
        }
    }

    /// Take a session from the cache for the given peer key.
    ///
    /// Returns the first non-expired session, or `None` if no valid session
    /// exists for this peer. Expired sessions are pruned during the lookup.
    ///
    /// Matches C `Curl_ssl_scache_take()` from vtls_scache.c lines 870-911.
    ///
    /// # Note
    ///
    /// The returned session is **removed** from the cache. For TLS 1.3 sessions
    /// this is final (single-use per RFC 8446 C.4). For pre-TLS 1.3 sessions,
    /// callers should use [`return_session`](Self::return_session) to put the
    /// session back if it was not actually consumed.
    pub fn take(&mut self, peer_key: &str) -> Option<TlsSession> {
        let session = self.peers.get_mut(peer_key)?.take_session();

        // Clean up empty peer entries to free memory
        if self
            .peers
            .get(peer_key)
            .is_some_and(PeerEntry::is_empty)
        {
            self.peers.remove(peer_key);
        }

        session
    }

    /// Return a previously-taken session back to the cache.
    ///
    /// Per RFC 8446 Appendix C.4, TLS 1.3 sessions SHOULD NOT be reused for
    /// multiple connections. Therefore, only pre-TLS 1.3 sessions (`ietf_tls_id
    /// < 0x0304`) are returned to the cache. TLS 1.3+ sessions are silently
    /// dropped.
    ///
    /// Matches C `Curl_ssl_scache_return()` from vtls_scache.c lines 857-868.
    pub fn return_session(&mut self, peer_key: &str, session: TlsSession) {
        // RFC 8446 C.4: "Clients SHOULD NOT reuse a ticket for multiple
        // connections." — only pre-TLS 1.3 sessions are returned.
        if session.ietf_tls_id < IETF_PROTO_TLS1_3 {
            self.put(peer_key, session);
        }
        // TLS 1.3+ sessions are dropped (not returned to cache)
    }

    /// Remove all sessions for a specific peer.
    ///
    /// Matches C `Curl_ssl_scache_remove_all()` from vtls_scache.c
    /// lines 972-991.
    pub fn remove_all(&mut self, peer_key: &str) {
        self.peers.remove(peer_key);
    }

    /// Remove all expired sessions across all peers, then remove empty peers.
    ///
    /// This is a maintenance operation that should be called periodically
    /// (e.g., before a batch of new connections) to prevent stale sessions
    /// from accumulating memory.
    pub fn cleanup_expired(&mut self) {
        // Remove expired sessions from each peer
        for peer in self.peers.values_mut() {
            peer.remove_expired();
        }
        // Remove peers with no remaining sessions
        self.peers.retain(|_, peer| !peer.is_empty());
    }

    /// Evict the least-recently-used peer to make room for a new entry.
    ///
    /// Matches C `cf_ssl_get_free_peer()` from vtls_scache.c lines 684-712.
    /// Preference order:
    /// 1. An empty peer (no sessions) — free slot.
    /// 2. The peer with the oldest `last_used` timestamp (LRU).
    fn evict_lru_peer(&mut self) {
        if self.peers.is_empty() {
            return;
        }

        // First, try to find and remove a peer with no sessions (free entry)
        let empty_key = self
            .peers
            .iter()
            .find(|(_, p)| p.is_empty())
            .map(|(k, _)| k.clone());

        if let Some(key) = empty_key {
            self.peers.remove(&key);
            return;
        }

        // Otherwise, evict the least-recently-used peer (oldest last_used)
        let lru_key = self
            .peers
            .iter()
            .min_by_key(|(_, p)| p.last_used)
            .map(|(k, _)| k.clone());

        if let Some(key) = lru_key {
            self.peers.remove(&key);
        }
    }
}

// ---------------------------------------------------------------------------
// SharedSessionCache
// ---------------------------------------------------------------------------

/// Thread-safe shared TLS session cache.
///
/// Wraps [`SessionCache`] in `Arc<Mutex<...>>` for concurrent access from
/// multiple handles, as required by `curl_share` SSL session sharing.
///
/// Replaces C `Curl_ssl_scache_lock()` / `Curl_ssl_scache_unlock()` patterns
/// from vtls_scache.c lines 584-596 with Rust's `Mutex` for automatic
/// locking/unlocking.
///
/// # Poisoned Mutex Handling
///
/// All methods gracefully handle a poisoned mutex by silently skipping the
/// operation. This matches the fail-safe behavior expected in a networking
/// library — a poisoned lock (caused by a panic in another thread) should not
/// crash the entire process.
#[derive(Clone)]
pub struct SharedSessionCache {
    inner: Arc<Mutex<SessionCache>>,
}

impl SharedSessionCache {
    /// Create a new thread-safe shared session cache.
    ///
    /// See [`SessionCache::new`] for parameter details.
    pub fn new(max_peers: usize, max_sessions_per_peer: usize) -> Self {
        SharedSessionCache {
            inner: Arc::new(Mutex::new(SessionCache::new(
                max_peers,
                max_sessions_per_peer,
            ))),
        }
    }

    /// Store a session in the shared cache.
    ///
    /// See [`SessionCache::put`] for behavior details.
    pub fn put(&self, peer_key: &str, session: TlsSession) {
        if let Ok(mut cache) = self.inner.lock() {
            cache.put(peer_key, session);
        }
    }

    /// Take a session from the shared cache.
    ///
    /// See [`SessionCache::take`] for behavior details.
    /// Returns `None` if the mutex is poisoned or no session is available.
    pub fn take(&self, peer_key: &str) -> Option<TlsSession> {
        self.inner.lock().ok()?.take(peer_key)
    }

    /// Return a previously-taken session back to the shared cache.
    ///
    /// See [`SessionCache::return_session`] for behavior details.
    pub fn return_session(&self, peer_key: &str, session: TlsSession) {
        if let Ok(mut cache) = self.inner.lock() {
            cache.return_session(peer_key, session);
        }
    }

    /// Remove all sessions for a specific peer from the shared cache.
    ///
    /// See [`SessionCache::remove_all`] for behavior details.
    pub fn remove_all(&self, peer_key: &str) {
        if let Ok(mut cache) = self.inner.lock() {
            cache.remove_all(peer_key);
        }
    }

    /// Remove all expired sessions from the shared cache.
    ///
    /// See [`SessionCache::cleanup_expired`] for behavior details.
    pub fn cleanup_expired(&self) {
        if let Ok(mut cache) = self.inner.lock() {
            cache.cleanup_expired();
        }
    }
}

// ---------------------------------------------------------------------------
// TLV deserialization helpers (matching vtls_spack.c encoding primitives)
// ---------------------------------------------------------------------------

/// Read a single byte from the data buffer at `pos`, advancing `pos` by 1.
///
/// Matches C `spack_dec8()` from vtls_spack.c lines 54-62.
fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8, CurlError> {
    if *pos >= data.len() {
        return Err(CurlError::ReadError);
    }
    let val = data[*pos];
    *pos += 1;
    Ok(val)
}

/// Read a big-endian 16-bit unsigned integer from the data buffer.
///
/// Matches C `spack_dec16()` from vtls_spack.c lines 72-80.
fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16, CurlError> {
    if *pos + 2 > data.len() {
        return Err(CurlError::ReadError);
    }
    let val = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
    *pos += 2;
    Ok(val)
}

/// Read a big-endian 32-bit unsigned integer from the data buffer.
///
/// Matches C `spack_dec32()` from vtls_spack.c lines 92-101.
fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, CurlError> {
    if *pos + 4 > data.len() {
        return Err(CurlError::ReadError);
    }
    let val = u32::from_be_bytes([
        data[*pos],
        data[*pos + 1],
        data[*pos + 2],
        data[*pos + 3],
    ]);
    *pos += 4;
    Ok(val)
}

/// Read a big-endian 64-bit unsigned integer from the data buffer.
///
/// Matches C `spack_dec64()` from vtls_spack.c lines 117-128.
fn read_u64(data: &[u8], pos: &mut usize) -> Result<u64, CurlError> {
    if *pos + 8 > data.len() {
        return Err(CurlError::ReadError);
    }
    let val = u64::from_be_bytes([
        data[*pos],
        data[*pos + 1],
        data[*pos + 2],
        data[*pos + 3],
        data[*pos + 4],
        data[*pos + 5],
        data[*pos + 6],
        data[*pos + 7],
    ]);
    *pos += 8;
    Ok(val)
}

/// Read a 16-bit-length-prefixed data blob from the buffer.
///
/// Matches C `spack_decdata16()` from vtls_spack.c lines 173-189.
/// Returns `CurlError::OutOfMemory` if memory allocation for the decoded
/// blob fails, matching the C behavior of returning `CURLE_OUT_OF_MEMORY`
/// when `curlx_memdup0()` fails.
fn read_data16(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, CurlError> {
    let len = read_u16(data, pos)? as usize;
    if *pos + len > data.len() {
        return Err(CurlError::ReadError);
    }
    let mut blob = Vec::new();
    blob.try_reserve(len).map_err(|_| CurlError::OutOfMemory)?;
    blob.extend_from_slice(&data[*pos..*pos + len]);
    *pos += len;
    Ok(blob)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// Helper to create a test session with sensible defaults.
    fn make_test_session(tls_id: u16, lifetime_secs: u64) -> TlsSession {
        TlsSession {
            ticket_data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            alpn: Some("h2".to_string()),
            ietf_tls_id: tls_id,
            valid_until: SystemTime::now() + Duration::from_secs(lifetime_secs),
            earlydata_max: 0,
            quic_transport_params: None,
            created_at: Instant::now(),
        }
    }

    /// Helper to create a TLS 1.3 test session.
    fn make_tls13_session(lifetime_secs: u64) -> TlsSession {
        make_test_session(0x0304, lifetime_secs)
    }

    /// Helper to create a TLS 1.2 test session.
    fn make_tls12_session(lifetime_secs: u64) -> TlsSession {
        make_test_session(0x0303, lifetime_secs)
    }

    #[test]
    fn test_constants_match_c() {
        // CURL_SCACHE_MAX_13_LIFETIME_SEC = 604800
        assert_eq!(MAX_TLS13_LIFETIME.as_secs(), 604_800);
        // CURL_SCACHE_MAX_12_LIFETIME_SEC = 86400
        assert_eq!(MAX_TLS12_LIFETIME.as_secs(), 86_400);
        assert_eq!(DEFAULT_MAX_PEERS, 100);
        assert_eq!(DEFAULT_MAX_SESSIONS_PER_PEER, 8);
    }

    #[test]
    fn test_make_peer_key_basic() {
        let key = make_peer_key("example.com", 443, "rustls-v1");
        assert_eq!(key, "example.com:443:rustls-v1");
    }

    #[test]
    fn test_make_peer_key_empty_hash() {
        let key = make_peer_key("example.com", 443, "");
        assert_eq!(key, "example.com:443");
    }

    #[test]
    fn test_make_peer_key_non_standard_port() {
        let key = make_peer_key("localhost", 8443, "test");
        assert_eq!(key, "localhost:8443:test");
    }

    #[test]
    fn test_session_not_expired() {
        let session = make_tls13_session(3600);
        assert!(!session.is_expired());
    }

    #[test]
    fn test_session_expired() {
        let session = TlsSession {
            ticket_data: vec![1, 2, 3],
            alpn: None,
            ietf_tls_id: 0x0304,
            valid_until: UNIX_EPOCH + Duration::from_secs(1),
            earlydata_max: 0,
            quic_transport_params: None,
            created_at: Instant::now(),
        };
        assert!(session.is_expired());
    }

    #[test]
    fn test_session_epoch_not_expired() {
        // Sessions with valid_until at UNIX_EPOCH are never considered expired
        let session = TlsSession {
            ticket_data: vec![1, 2, 3],
            alpn: None,
            ietf_tls_id: 0x0304,
            valid_until: UNIX_EPOCH,
            earlydata_max: 0,
            quic_transport_params: None,
            created_at: Instant::now(),
        };
        assert!(!session.is_expired());
    }

    #[test]
    fn test_cache_put_and_take() {
        let mut cache = SessionCache::new(10, 4);
        let session = make_tls13_session(3600);
        let ticket_data = session.ticket_data.clone();

        cache.put("host:443", session);
        let taken = cache.take("host:443");

        assert!(taken.is_some());
        let taken = taken.unwrap();
        assert_eq!(taken.ticket_data, ticket_data);
        assert_eq!(taken.ietf_tls_id, 0x0304);
    }

    #[test]
    fn test_cache_take_nonexistent() {
        let mut cache = SessionCache::new(10, 4);
        assert!(cache.take("nonexistent:443").is_none());
    }

    #[test]
    fn test_cache_remove_all() {
        let mut cache = SessionCache::new(10, 4);
        cache.put("host:443", make_tls13_session(3600));
        cache.put("host:443", make_tls13_session(3600));

        cache.remove_all("host:443");
        assert!(cache.take("host:443").is_none());
    }

    #[test]
    fn test_cache_max_sessions_per_peer_tls13() {
        let mut cache = SessionCache::new(10, 2);

        // Add 3 TLS 1.3 sessions — only 2 should survive (oldest evicted)
        cache.put("host:443", make_tls13_session(3600));
        cache.put("host:443", make_tls13_session(3600));
        cache.put("host:443", make_tls13_session(3600));

        // Should be able to take 2 sessions
        assert!(cache.take("host:443").is_some());
        assert!(cache.take("host:443").is_some());
        assert!(cache.take("host:443").is_none());
    }

    #[test]
    fn test_cache_tls12_replaces_all() {
        let mut cache = SessionCache::new(10, 4);

        // Add TLS 1.3 sessions
        cache.put("host:443", make_tls13_session(3600));
        cache.put("host:443", make_tls13_session(3600));

        // Adding a TLS 1.2 session should replace all
        cache.put("host:443", make_tls12_session(3600));

        // Should only get one session back (the TLS 1.2 one)
        let taken = cache.take("host:443");
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().ietf_tls_id, 0x0303);
        assert!(cache.take("host:443").is_none());
    }

    #[test]
    fn test_cache_max_peers_eviction() {
        let mut cache = SessionCache::new(2, 4);

        cache.put("host1:443", make_tls13_session(3600));
        cache.put("host2:443", make_tls13_session(3600));

        // Touch host2 to make host1 the LRU
        let _ = cache.take("host2:443");
        cache.put("host2:443", make_tls13_session(3600));

        // Adding a third peer should evict host1 (LRU)
        cache.put("host3:443", make_tls13_session(3600));

        assert!(cache.take("host1:443").is_none()); // evicted
        assert!(cache.take("host2:443").is_some());
        assert!(cache.take("host3:443").is_some());
    }

    #[test]
    fn test_cache_return_session_tls12() {
        let mut cache = SessionCache::new(10, 4);
        let session = make_tls12_session(3600);

        cache.put("host:443", session);
        let taken = cache.take("host:443").unwrap();

        // Return TLS 1.2 session — should go back to cache
        cache.return_session("host:443", taken);
        assert!(cache.take("host:443").is_some());
    }

    #[test]
    fn test_cache_return_session_tls13_dropped() {
        let mut cache = SessionCache::new(10, 4);
        let session = make_tls13_session(3600);

        cache.put("host:443", session);
        let taken = cache.take("host:443").unwrap();

        // Return TLS 1.3 session — should be dropped (RFC 8446 C.4)
        cache.return_session("host:443", taken);
        assert!(cache.take("host:443").is_none());
    }

    #[test]
    fn test_cache_cleanup_expired() {
        let mut cache = SessionCache::new(10, 4);

        // Add an already-expired session (valid_until in the past)
        // This won't be added by put() because put() drops expired sessions
        // So we test cleanup of sessions that expire after insertion
        let mut session = make_tls13_session(3600);
        session.valid_until = SystemTime::now() + Duration::from_secs(3600);
        cache.put("active:443", session);

        // The active session should survive cleanup
        cache.cleanup_expired();
        assert!(cache.take("active:443").is_some());
    }

    #[test]
    fn test_cache_zero_max_peers() {
        let mut cache = SessionCache::new(0, 4);
        cache.put("host:443", make_tls13_session(3600));
        assert!(cache.take("host:443").is_none());
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let original = TlsSession {
            ticket_data: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            alpn: Some("h2".to_string()),
            ietf_tls_id: 0x0304,
            valid_until: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            earlydata_max: 16384,
            quic_transport_params: Some(vec![0xAA, 0xBB, 0xCC]),
            created_at: Instant::now(),
        };

        let serialized = original.serialize();
        let deserialized = TlsSession::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.ticket_data, original.ticket_data);
        assert_eq!(deserialized.alpn, original.alpn);
        assert_eq!(deserialized.ietf_tls_id, original.ietf_tls_id);
        assert_eq!(deserialized.valid_until, original.valid_until);
        assert_eq!(deserialized.earlydata_max, original.earlydata_max);
        assert_eq!(
            deserialized.quic_transport_params,
            original.quic_transport_params
        );
    }

    #[test]
    fn test_serialize_deserialize_minimal() {
        let original = TlsSession {
            ticket_data: vec![0xFF],
            alpn: None,
            ietf_tls_id: 0x0303,
            valid_until: UNIX_EPOCH + Duration::from_secs(1_000_000),
            earlydata_max: 0,
            quic_transport_params: None,
            created_at: Instant::now(),
        };

        let serialized = original.serialize();
        let deserialized = TlsSession::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.ticket_data, vec![0xFF]);
        assert_eq!(deserialized.alpn, None);
        assert_eq!(deserialized.ietf_tls_id, 0x0303);
        assert_eq!(deserialized.earlydata_max, 0);
        assert_eq!(deserialized.quic_transport_params, None);
    }

    #[test]
    fn test_deserialize_empty_data() {
        let result = TlsSession::deserialize(&[]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::ReadError);
    }

    #[test]
    fn test_deserialize_wrong_version() {
        let result = TlsSession::deserialize(&[0xFF]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::ReadError);
    }

    #[test]
    fn test_deserialize_truncated_ticket() {
        // Version marker + ticket tag + incomplete length
        let data = vec![SPACK_VERSION, SPACK_TICKET, 0x00];
        let result = TlsSession::deserialize(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_missing_ticket() {
        // Version marker + IETF_ID only, no ticket
        let data = vec![SPACK_VERSION, SPACK_IETF_ID, 0x03, 0x04];
        let result = TlsSession::deserialize(&data);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::BadFunctionArgument);
    }

    #[test]
    fn test_deserialize_unknown_tag() {
        let data = vec![SPACK_VERSION, 0xFF];
        let result = TlsSession::deserialize(&data);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::ReadError);
    }

    #[test]
    fn test_shared_cache_basic() {
        let cache = SharedSessionCache::new(10, 4);
        let session = make_tls13_session(3600);

        cache.put("host:443", session);
        let taken = cache.take("host:443");
        assert!(taken.is_some());
    }

    #[test]
    fn test_shared_cache_clone_shares_state() {
        let cache1 = SharedSessionCache::new(10, 4);
        let cache2 = cache1.clone();

        cache1.put("host:443", make_tls13_session(3600));
        let taken = cache2.take("host:443");
        assert!(taken.is_some());
    }

    #[test]
    fn test_shared_cache_return_session() {
        let cache = SharedSessionCache::new(10, 4);

        cache.put("host:443", make_tls12_session(3600));
        let taken = cache.take("host:443").unwrap();

        cache.return_session("host:443", taken);
        assert!(cache.take("host:443").is_some());
    }

    #[test]
    fn test_shared_cache_remove_all() {
        let cache = SharedSessionCache::new(10, 4);

        cache.put("host:443", make_tls13_session(3600));
        cache.remove_all("host:443");
        assert!(cache.take("host:443").is_none());
    }

    #[test]
    fn test_shared_cache_cleanup_expired() {
        let cache = SharedSessionCache::new(10, 4);

        cache.put("host:443", make_tls13_session(3600));
        cache.cleanup_expired();
        assert!(cache.take("host:443").is_some());
    }

    #[test]
    fn test_lifetime_clamping_tls13() {
        let mut cache = SessionCache::new(10, 4);

        // Session with valid_until 30 days from now — should be clamped to 7 days
        let mut session = make_tls13_session(0);
        session.valid_until = SystemTime::now() + Duration::from_secs(30 * 86_400);
        cache.put("host:443", session);

        let taken = cache.take("host:443").unwrap();
        let remaining = taken
            .valid_until
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO);

        // Should be at most 7 days (with a small tolerance for test execution)
        assert!(remaining.as_secs() <= MAX_TLS13_LIFETIME.as_secs() + 1);
    }

    #[test]
    fn test_lifetime_clamping_tls12() {
        let mut cache = SessionCache::new(10, 4);

        // Session with valid_until 30 days from now — should be clamped to 1 day
        let mut session = make_tls12_session(0);
        session.valid_until = SystemTime::now() + Duration::from_secs(30 * 86_400);
        cache.put("host:443", session);

        let taken = cache.take("host:443").unwrap();
        let remaining = taken
            .valid_until
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO);

        // Should be at most 1 day
        assert!(remaining.as_secs() <= MAX_TLS12_LIFETIME.as_secs() + 1);
    }

    #[test]
    fn test_default_lifetime_applied() {
        let mut cache = SessionCache::new(10, 4);

        // Session with valid_until at UNIX_EPOCH (no explicit expiry)
        let session = TlsSession {
            ticket_data: vec![1, 2, 3],
            alpn: None,
            ietf_tls_id: 0x0303,
            valid_until: UNIX_EPOCH,
            earlydata_max: 0,
            quic_transport_params: None,
            created_at: Instant::now(),
        };
        cache.put("host:443", session);

        let taken = cache.take("host:443").unwrap();
        // Should have a valid_until in the future (default lifetime applied)
        assert!(taken.valid_until > SystemTime::now());
    }

    #[test]
    fn test_serialize_version_marker() {
        let session = TlsSession {
            ticket_data: vec![0x42],
            alpn: None,
            ietf_tls_id: 0x0303,
            valid_until: UNIX_EPOCH + Duration::from_secs(1_000_000),
            earlydata_max: 0,
            quic_transport_params: None,
            created_at: Instant::now(),
        };
        let data = session.serialize();
        assert_eq!(data[0], SPACK_VERSION);
    }

    #[test]
    fn test_tls13_sessions_accumulate() {
        let mut cache = SessionCache::new(10, 8);

        for i in 0u8..5 {
            let session = TlsSession {
                ticket_data: vec![i],
                alpn: None,
                ietf_tls_id: 0x0304,
                valid_until: SystemTime::now() + Duration::from_secs(3600),
                earlydata_max: 0,
                quic_transport_params: None,
                created_at: Instant::now(),
            };
            cache.put("host:443", session);
        }

        // Should be able to take 5 sessions (all TLS 1.3, accumulated)
        for _ in 0..5 {
            assert!(cache.take("host:443").is_some());
        }
        assert!(cache.take("host:443").is_none());
    }
}
