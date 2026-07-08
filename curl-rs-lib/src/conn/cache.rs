// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-FileCopyrightText: Linus Nielsen Feltzing, <linus@haxx.se>

//! # Connection pool / cache (`ConnCache`)
//!
//! This module is the Rust rewrite of curl's **connection pool** — the `cpool`
//! machinery in `lib/conncache.c` / `lib/conncache.h`. The pool stores idle
//! connections keyed by *destination* so they can be reused, enforces the
//! configured connection limits (both total and per-host), performs the
//! multiplex/stream bookkeeping that lets an HTTP/2 or HTTP/3 connection carry
//! several transfers at once, assigns the monotonic connection/easy ids, and
//! prunes dead connections.
//!
//! ## Sharing model (`curl_share`)
//!
//! A [`ConnCache`] is a cheap, cloneable handle around an
//! [`Arc`]`<`[`Mutex`]`<…>>`. Cloning the handle **shares the same underlying
//! pool**, which is exactly curl's `curl_share` connection-sharing model
//! (`CURL_LOCK_DATA_CONNECT`): a single pool can be handed to many easy handles
//! or held by a multi handle, and every clone observes the same bundles and
//! counters. Because the pool sits behind its *own* mutex, contention on the
//! connection cache stays independent of the cookie jar, DNS cache, and other
//! shared resources (AAP §0.3.2, fine-grained locking).
//!
//! ## `CPOOL_LOCK`/`CPOOL_UNLOCK` → the Rust `Mutex`
//!
//! curl guards every pool mutation with the `CPOOL_LOCK`/`CPOOL_UNLOCK` macros,
//! which (for a shared pool) take the share lock `CURL_LOCK_DATA_CONNECT` with
//! single-access semantics and flip a `locked` bookkeeping bit. In this rewrite
//! the [`Mutex`] guard **is** the lock: acquiring [`CpoolInner`] via the private
//! `lock()` helper reproduces `CPOOL_LOCK`, and dropping the guard reproduces
//! `CPOOL_UNLOCK`. The C `locked` bool is therefore unnecessary — the borrow
//! checker and the guard's lifetime enforce the same "exactly one holder"
//! invariant that curl asserted with `DEBUGASSERT(!(c)->locked)`. Whether a pool
//! is *shared* or *private* is expressed purely by whether the same
//! [`ConnCache`] handle (i.e. the same [`Arc`]) is cloned to multiple owners.
//!
//! ## Ownership model vs. curl
//!
//! curl keeps a raw `struct connectdata *` in the bundle and tracks "idle" vs.
//! "in use" through `attached_xfers`. Because Rust's [`Connection`] is
//! move-only (it owns live sockets and TLS state and therefore cannot be
//! cloned), this rewrite models reuse as **detach-on-checkout**: an idle,
//! reusable connection is *removed* from its bundle and handed to the caller by
//! value ([`ConnCache::get_conn`]); when the transfer finishes the caller
//! returns it with [`ConnCache::conn_now_idle`] (or [`ConnCache::add`]).
//! Multiplexed connections are the exception — they must be shared
//! concurrently, so they stay in the pool and hand out *stream slots* via
//! [`ConnCache::try_multiplex`], which increments `attached_xfers` while the
//! connection remains pooled and under its `CF_QUERY_MAX_CONCURRENT` limit.
//!
//! ## Memory safety
//!
//! The whole module is written in safe Rust — the crate-wide prohibition on
//! raw memory operations declared at the crate root applies here as everywhere.
//! The `HashMap<destination, ConnBundle>` replaces curl's
//! `dest2bundle` hash *and* the flexible-array-member `char dest[1]` allocation
//! of `struct cpool_bundle`, eliminating the manual sizing and raw-pointer
//! handling the C code needed. Dropping the pool drops every bundle, which drops every
//! [`Connection`], which tears down its filter chains and sockets — the
//! ownership-based replacement for `Curl_cpool_destroy`.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use crate::conn::shutdown;
use crate::conn::{Connection, FIRSTSOCKET};
use crate::error::Result;
use crate::tls::config::TlsConfig;

// ===========================================================================
// Tunables mirrored from curl's connection-pool behavior.
// ===========================================================================

/// Minimum interval between successive dead-connection sweeps
/// ([`ConnCache::prune_dead`]), mirroring curl's "clean up at most once per
/// second" throttle in `Curl_cpool_prune_dead` (`elapsed >= 1000L`).
const PRUNE_INTERVAL_MS: u128 = 1000;

// ===========================================================================
// LimitResult — the `CPOOL_LIMIT_*` result codes (`lib/conncache.h`).
// ===========================================================================

/// The outcome of a connection-limit check ([`ConnCache::check_limits`]),
/// reproducing curl's `CPOOL_LIMIT_OK` / `CPOOL_LIMIT_DEST` / `CPOOL_LIMIT_TOTAL`
/// integer codes.
///
/// The discriminants are frozen to curl's values (`0`/`1`/`2`) so the result can
/// be compared or bridged to the C surface without translation.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LimitResult {
    /// `CPOOL_LIMIT_OK` — there is room for another connection (possibly after
    /// discarding idle connections to make space).
    Ok = 0,
    /// `CPOOL_LIMIT_DEST` — the per-destination (per-host) limit is reached and
    /// no idle connection to that destination could be discarded.
    Dest = 1,
    /// `CPOOL_LIMIT_TOTAL` — the total connection limit is reached and no idle
    /// connection anywhere could be discarded.
    Total = 2,
}

impl LimitResult {
    /// Returns the raw `CPOOL_LIMIT_*` integer for this outcome.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Whether the pool has room (`CPOOL_LIMIT_OK`).
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(self, LimitResult::Ok)
    }
}

// ===========================================================================
// ReuseKey — the connection-reuse "needle" (`ConnectionExists`/`url_match_conn`).
// ===========================================================================

/// The set of identity fields curl compares when deciding whether a pooled
/// connection may be reused for a new transfer — the "needle" that
/// `ConnectionExists` (`lib/url.c`) fills in and that `url_match_conn` matches
/// against every candidate in the destination bundle.
///
/// A [`ReuseKey`] is normally built from a freshly prepared template connection
/// with [`ReuseKey::from_connection`], then handed to [`ConnCache::get_conn`] /
/// [`ConnCache::try_multiplex`]. The public fields are also exposed directly so
/// callers can construct or tweak a needle without a template.
///
/// [`ReuseKey::matches`] implements curl's acceptance rules: it rejects any
/// connection flagged `bits.close` or `bits.no_reuse`, and otherwise requires
/// the destination, scheme, effective host/port, `--connect-to` overrides,
/// proxy identity, credentials, and TLS configuration to all agree.
#[derive(Debug, Clone)]
pub struct ReuseKey {
    /// The normalized bundle key (`conn->destination`) — `scope/port/host`,
    /// lowercased. This selects the candidate bundle before the finer match.
    pub destination: String,

    /// The scheme/handler name that must match (`conn->handler->scheme`).
    pub scheme_name: String,
    /// The requested host name (`conn->host.name`).
    pub host: String,
    /// The effective remote port actually connected to (`conn->remote_port`).
    pub port: u16,

    /// The `--connect-to` host override, when active (`conn->conn_to_host`).
    pub conn_to_host: Option<String>,
    /// The `--connect-to` port override, when active (`conn->conn_to_port`).
    pub conn_to_port: Option<u16>,

    /// Whether the transfer rides a proxy of any kind (`conn->bits.proxy`).
    pub want_proxy: bool,
    /// The proxy kind (`conn->http_proxy.proxytype` / `conn->socks_proxy`).
    pub proxy_type: crate::conn::ProxyType,
    /// The proxy host name (empty when no proxy).
    pub proxy_host: String,
    /// The proxy port (`0` when no proxy).
    pub proxy_port: u16,
    /// The proxy username, if any.
    pub proxy_user: Option<String>,
    /// The proxy password, if any.
    pub proxy_passwd: Option<String>,

    /// The resolved username (`conn->user`).
    pub user: Option<String>,
    /// The resolved password (`conn->passwd`).
    pub passwd: Option<String>,
    /// The login `;options` field (`conn->options`).
    pub options: Option<String>,
    /// The SASL authorization identity (`conn->sasl_authzid`).
    pub sasl_authzid: Option<String>,
    /// The OAuth 2.0 bearer token (`conn->oauth_bearer`).
    pub oauth_bearer: Option<String>,

    /// A compact fingerprint of the server TLS configuration
    /// (`conn->ssl_config`). Two connections may only be shared when their TLS
    /// parameters agree; see [`tls_fingerprint`].
    pub tls_fingerprint: String,
    /// A compact fingerprint of the proxy-side TLS configuration
    /// (`conn->proxy_ssl_config`), only meaningful when [`want_proxy`] is set
    /// and the proxy is HTTPS.
    ///
    /// [`want_proxy`]: ReuseKey::want_proxy
    pub proxy_tls_fingerprint: String,
}

impl ReuseKey {
    /// Builds a reuse needle from a template [`Connection`], copying exactly the
    /// fields curl's `ConnectionExists` fills before consulting the pool.
    ///
    /// The template is the freshly-prepared connection for the new transfer; its
    /// [`destination`](Connection::destination) selects the bundle and its
    /// identity fields drive [`ReuseKey::matches`].
    #[must_use]
    pub fn from_connection(conn: &Connection) -> Self {
        ReuseKey {
            destination: conn.destination.clone(),
            scheme_name: conn.scheme.name.clone(),
            host: conn.host.name.clone(),
            port: conn.port,
            conn_to_host: conn.conn_to_host.as_ref().map(|h| h.name.clone()),
            conn_to_port: conn.conn_to_port,
            want_proxy: conn.bits.proxy,
            proxy_type: conn.http_proxy.proxytype,
            proxy_host: conn.http_proxy.host.name.clone(),
            proxy_port: conn.http_proxy.port,
            proxy_user: conn.http_proxy.user.clone(),
            proxy_passwd: conn.http_proxy.passwd.clone(),
            user: conn.user.clone(),
            passwd: conn.passwd.clone(),
            options: conn.options.clone(),
            sasl_authzid: conn.sasl_authzid.clone(),
            oauth_bearer: conn.oauth_bearer.clone(),
            tls_fingerprint: tls_fingerprint(&conn.ssl_config),
            proxy_tls_fingerprint: tls_fingerprint(&conn.proxy_ssl_config),
        }
    }

    /// Returns whether the pooled `conn` may be reused for this needle,
    /// reproducing curl's `url_match_conn` acceptance rules.
    ///
    /// A connection is rejected outright when it is flagged for closure
    /// (`bits.close`) or explicitly non-reusable (`bits.no_reuse`). Otherwise it
    /// must agree on:
    ///
    /// * destination (the bundle key), scheme, effective host and port;
    /// * `--connect-to` host/port overrides;
    /// * proxy presence, kind, endpoint, and proxy credentials;
    /// * credentials (`user`/`passwd`/`options`/`sasl_authzid`/`oauth_bearer`) —
    ///   compared unconditionally, which is conservative: it never reuses a
    ///   connection whose bound credentials differ, matching curl's behavior for
    ///   the connection-bound auth mechanisms (NTLM/Negotiate) and being safe for
    ///   the rest;
    /// * the server (and, when proxying, the proxy) TLS configuration
    ///   fingerprint.
    #[must_use]
    pub fn matches(&self, conn: &Connection) -> bool {
        // A connection marked for closure or non-reuse is never a candidate
        // (curl skips `bits.close` in `cpool_get_oldest_idle`/`url_match_conn`
        // and `bits.no_reuse` in the reaper).
        if conn.bits.close || conn.bits.no_reuse {
            return false;
        }

        // Destination + scheme + effective endpoint.
        if self.destination != conn.destination
            || self.scheme_name != conn.scheme.name
            || self.host != conn.host.name
            || self.port != conn.port
        {
            return false;
        }

        // `--connect-to` overrides must agree (both absent or both equal).
        let conn_to_host = conn.conn_to_host.as_ref().map(|h| h.name.as_str());
        if self.conn_to_host.as_deref() != conn_to_host || self.conn_to_port != conn.conn_to_port {
            return false;
        }

        // Proxy identity: presence, then (when present) kind/endpoint/creds.
        if self.want_proxy != conn.bits.proxy {
            return false;
        }
        if self.want_proxy
            && (self.proxy_type != conn.http_proxy.proxytype
                || self.proxy_host != conn.http_proxy.host.name
                || self.proxy_port != conn.http_proxy.port
                || self.proxy_user != conn.http_proxy.user
                || self.proxy_passwd != conn.http_proxy.passwd
                || self.proxy_tls_fingerprint != tls_fingerprint(&conn.proxy_ssl_config))
        {
            return false;
        }

        // Credentials (connection-bound-auth safe).
        if self.user != conn.user
            || self.passwd != conn.passwd
            || self.options != conn.options
            || self.sasl_authzid != conn.sasl_authzid
            || self.oauth_bearer != conn.oauth_bearer
        {
            return false;
        }

        // Server TLS parameters.
        self.tls_fingerprint == tls_fingerprint(&conn.ssl_config)
    }
}

/// Computes a compact, comparable fingerprint of the reuse-relevant fields of a
/// [`TlsConfig`], mirroring the field set curl compares in
/// `Curl_ssl_conn_config_match` (`lib/vtls/vtls.c`): verification policy, TLS
/// version bounds, CA/client-auth sources, cipher lists, and public-key pinning.
///
/// Secret-bearing values (in-memory PEM blobs and the key passphrase) are folded
/// into a single non-reversible hash rather than embedded verbatim, so the
/// fingerprint — and any `Debug` rendering of the [`ReuseKey`] that carries it —
/// never exposes key material.
#[must_use]
fn tls_fingerprint(cfg: &TlsConfig) -> String {
    // Hash the secret-bearing blobs/passphrase so they never appear in cleartext
    // inside the fingerprint string.
    let mut hasher = DefaultHasher::new();
    cfg.ca_info_blob.hash(&mut hasher);
    cfg.client_cert_blob.hash(&mut hasher);
    cfg.client_key_blob.hash(&mut hasher);
    cfg.key_password.hash(&mut hasher);
    let secret_digest = hasher.finish();

    format!(
        "vp={vp}|vh={vh}|vs={vs}|wr={wr}|min={min:?}|max={max:?}|\
         ca={ca:?}|cap={cap:?}|cert={cert:?}|key={key:?}|crl={crl:?}|iss={iss:?}|\
         cl={cl:?}|cl13={cl13:?}|pin={pin:?}|sec={sec:016x}",
        vp = u8::from(cfg.verify_peer),
        vh = u8::from(cfg.verify_host),
        vs = u8::from(cfg.verify_status),
        wr = u8::from(cfg.use_webpki_roots),
        min = cfg.version_min,
        max = cfg.version_max,
        ca = cfg.ca_info,
        cap = cfg.ca_path,
        cert = cfg.client_cert,
        key = cfg.client_key,
        crl = cfg.crl_file,
        iss = cfg.issuer_cert,
        cl = cfg.cipher_list,
        cl13 = cfg.cipher_list13,
        pin = cfg.pinned_pubkey,
        sec = secret_digest,
    )
}

// ===========================================================================
// ConnBundle — a per-destination connection list (`struct cpool_bundle`).
// ===========================================================================

/// All connections to a single destination, mirroring curl's
/// `struct cpool_bundle` (`Curl_llist conns; size_t dest_len; char dest[1]`).
///
/// curl allocates the destination string inline via a flexible array member and
/// walks the connections through an intrusive linked list. Here the connections
/// live in a [`Vec`] and the destination is not duplicated inside the bundle at
/// all: the owning [`HashMap`] key already holds it, and every access path
/// reaches a bundle *through* that key, so there is no manual sizing and no
/// raw-pointer handling. (curl's inline `dest[]` / `dest_len` existed only so
/// `cpool_remove_bundle` could recover the hash key *from* the bundle; the
/// [`HashMap`] makes that unnecessary, since the key is always in hand.)
///
/// Dropping a bundle drops its [`Connection`]s, tearing down their sockets —
/// the ownership-based replacement for `cpool_bundle_destroy`.
#[derive(Debug)]
struct ConnBundle {
    /// The connections in this bundle (curl's intrusive `conns` list).
    conns: Vec<Connection>,
}

impl ConnBundle {
    /// Creates an empty bundle (`cpool_bundle_create`). The destination is held
    /// by the owning [`HashMap`] key rather than duplicated inside the bundle.
    fn new() -> Self {
        ConnBundle { conns: Vec::new() }
    }

    /// The number of connections currently in the bundle
    /// (`Curl_llist_count(&bundle->conns)`).
    fn len(&self) -> usize {
        self.conns.len()
    }

    /// Whether the bundle holds no connections.
    fn is_empty(&self) -> bool {
        self.conns.is_empty()
    }
}

// ===========================================================================
// CpoolInner — the mutex-guarded pool state (`struct cpool`).
// ===========================================================================

/// The mutable state of a connection pool, guarded by the [`ConnCache`]'s
/// [`Mutex`]. This is the direct analog of curl's `struct cpool`, minus the
/// `locked` bool (subsumed by the guard) and the raw `idata`/`share`
/// back-pointers (the sharing relationship is expressed by cloning the owning
/// [`Arc`] instead of storing a `struct Curl_share *`).
#[derive(Debug)]
struct CpoolInner {
    /// Idle/pooled connections grouped by destination (`cpool->dest2bundle`).
    bundles: HashMap<String, ConnBundle>,
    /// The number of connections held across all bundles (`cpool->num_conn`).
    num_conn: usize,
    /// The next connection id to assign (`cpool->next_connection_id`).
    next_connection_id: i64,
    /// The next easy-handle id to assign (`cpool->next_easy_id`).
    next_easy_id: i64,
    /// When the last dead-connection sweep ran (`cpool->last_cleanup`), or
    /// `None` if no sweep has run yet. curl zero-initializes `last_cleanup` so
    /// the *first* [`ConnCache::prune_dead`] always proceeds; modeling it as an
    /// [`Option`] reproduces that "never cleaned ⇒ run now" semantics without
    /// risking an [`Instant`] underflow.
    last_cleanup: Option<Instant>,
    /// The total connection limit (`multi->max_total_connections`); `0` = no
    /// limit.
    max_total: usize,
    /// The per-destination connection limit (`multi->max_host_connections`);
    /// `0` = no limit.
    max_per_host: usize,
}

impl CpoolInner {
    /// Creates an empty pool with the given limits (`Curl_cpool_init`).
    fn new(max_total: usize, max_per_host: usize) -> Self {
        CpoolInner {
            bundles: HashMap::new(),
            num_conn: 0,
            next_connection_id: 0,
            next_easy_id: 0,
            last_cleanup: None,
            max_total,
            max_per_host,
        }
    }

    /// The number of connections currently in `dest`'s bundle (`0` if none).
    fn dest_count(&self, dest: &str) -> usize {
        self.bundles.get(dest).map_or(0, ConnBundle::len)
    }

    /// Removes the bundle for `dest` if it has become empty
    /// (`cpool_remove_bundle`).
    fn drop_bundle_if_empty(&mut self, dest: &str) {
        if self.bundles.get(dest).is_some_and(ConnBundle::is_empty) {
            self.bundles.remove(dest);
        }
    }

    /// Finds the destination + index of the oldest idle, reusable connection in
    /// `dest`'s bundle, if any (`cpool_bundle_get_oldest_idle`). "Idle" means
    /// not in use, not marked for closure, and not connect-only; "oldest" is the
    /// smallest [`Connection::lastused`].
    fn oldest_idle_in(&self, dest: &str) -> Option<usize> {
        let bundle = self.bundles.get(dest)?;
        oldest_idle_index(&bundle.conns)
    }

    /// Finds the destination + index of the oldest idle, reusable connection
    /// across the entire pool, if any (`cpool_get_oldest_idle`).
    fn oldest_idle_any(&self) -> Option<(String, usize)> {
        let mut best: Option<(String, usize, Instant)> = None;
        for (dest, bundle) in &self.bundles {
            for (idx, conn) in bundle.conns.iter().enumerate() {
                if conn.in_use() || conn.bits.close || conn.bits.no_reuse {
                    continue;
                }
                match best {
                    Some((_, _, ts)) if conn.lastused >= ts => {}
                    _ => best = Some((dest.clone(), idx, conn.lastused)),
                }
            }
        }
        best.map(|(dest, idx, _)| (dest, idx))
    }

    /// Removes and returns the connection at `dest[idx]`, updating `num_conn`,
    /// clearing its `in_cpool` flag, and dropping the bundle if it empties
    /// (`cpool_remove_conn`). Returns `None` if the index is stale.
    fn remove_at(&mut self, dest: &str, idx: usize) -> Option<Connection> {
        let bundle = self.bundles.get_mut(dest)?;
        if idx >= bundle.conns.len() {
            return None;
        }
        let mut conn = bundle.conns.remove(idx);
        conn.bits.in_cpool = false;
        self.num_conn = self.num_conn.saturating_sub(1);
        self.drop_bundle_if_empty(dest);
        Some(conn)
    }
}

impl Drop for CpoolInner {
    /// Mirrors `Curl_cpool_destroy`: the connections are torn down as the
    /// bundles (and thus every owned [`Connection`]) drop. Each connection's own
    /// `Drop` closes its filter chains and sockets, so no manual free loop is
    /// required — this is the ownership-based replacement for the C destroy
    /// path. A trace line preserves curl's `[CPOOL] destroy` diagnostic.
    fn drop(&mut self) {
        if self.num_conn > 0 {
            tracing::trace!(
                target: "curl::cpool",
                connections = self.num_conn,
                "[CPOOL] destroy"
            );
        }
    }
}

/// Returns the index of the oldest idle, reusable connection in `conns`
/// (smallest [`Connection::lastused`] among connections that are not in use,
/// not marked for closure, and not non-reusable), or `None`.
fn oldest_idle_index(conns: &[Connection]) -> Option<usize> {
    let mut best: Option<(usize, Instant)> = None;
    for (idx, conn) in conns.iter().enumerate() {
        if conn.in_use() || conn.bits.close || conn.bits.no_reuse {
            continue;
        }
        match best {
            Some((_, ts)) if conn.lastused >= ts => {}
            _ => best = Some((idx, conn.lastused)),
        }
    }
    best.map(|(idx, _)| idx)
}

// ===========================================================================
// ConnCache — the shareable pool handle (`struct cpool` + `CPOOL_LOCK`).
// ===========================================================================

/// The connection pool — a cheap, cloneable handle to a shared set of pooled
/// connections. This is the type re-exported as `crate::conn::ConnCache`,
/// reused by the URL/connection-setup layer and shared across easy handles by
/// the multi handle.
///
/// Cloning a [`ConnCache`] clones the inner [`Arc`], so every clone refers to
/// the **same** pool — curl's `curl_share` connection-sharing model. The handle
/// is [`Send`] + [`Sync`], so it can be moved into and shared between tasks.
///
/// See the [module documentation](self) for the locking, ownership, and
/// multiplex models.
#[derive(Debug, Clone)]
pub struct ConnCache {
    /// The shared, mutex-guarded pool state. Cloning shares it.
    inner: Arc<Mutex<CpoolInner>>,
}

impl ConnCache {
    /// Creates a new, empty pool with the given limits and returns a handle to
    /// it (`Curl_cpool_init`).
    ///
    /// `max_total` caps the total number of pooled connections
    /// (`multi->max_total_connections`) and `max_per_host` caps the number per
    /// destination (`multi->max_host_connections`); a value of `0` disables the
    /// corresponding limit, exactly as curl treats an unset maximum. Cloning the
    /// returned handle shares this same pool.
    #[must_use]
    pub fn new(max_total: usize, max_per_host: usize) -> Self {
        ConnCache {
            inner: Arc::new(Mutex::new(CpoolInner::new(max_total, max_per_host))),
        }
    }

    /// Acquires the pool lock (`CPOOL_LOCK`), recovering from a poisoned mutex.
    ///
    /// A mutex is only poisoned if a thread panicked while holding the guard;
    /// because the pool state remains structurally valid (a panic mid-mutation
    /// leaves the collections consistent), recovering the inner value via
    /// [`std::sync::PoisonError::into_inner`] is preferable to propagating the
    /// panic to every subsequent caller. This keeps the pool available and
    /// matches the tolerant `if let Ok(..) = .lock()` handling used elsewhere in
    /// the crate.
    fn lock(&self) -> MutexGuard<'_, CpoolInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// The number of connections currently pooled (`cpool->num_conn`).
    #[must_use]
    pub fn num_conn(&self) -> usize {
        self.lock().num_conn
    }

    /// Whether the pool holds no connections.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().num_conn == 0
    }

    /// The number of connections pooled to `destination` (its bundle size).
    #[must_use]
    pub fn dest_count(&self, destination: &str) -> usize {
        self.lock().dest_count(destination)
    }

    /// The number of in-use (checked-out or multiplex-attached) connections
    /// still tracked by the pool — connections with `attached_xfers > 0`. Idle
    /// connections that were detached via [`ConnCache::get_conn`] are no longer
    /// counted because they have left the pool.
    #[must_use]
    pub fn in_use(&self) -> usize {
        let inner = self.lock();
        inner
            .bundles
            .values()
            .flat_map(|b| b.conns.iter())
            .filter(|c| c.in_use())
            .count()
    }

    /// Initializes this transfer within the pool, assigning and returning its
    /// easy-handle id (`Curl_cpool_xfer_init`, which sets `data->id`).
    ///
    /// Ids are handed out monotonically from `next_easy_id`; as in curl, if the
    /// counter would wrap past the signed maximum it is reset to `0`.
    pub fn xfer_init(&self) -> i64 {
        let mut inner = self.lock();
        let id = inner.next_easy_id;
        inner.next_easy_id = inner.next_easy_id.wrapping_add(1);
        if inner.next_easy_id <= 0 {
            inner.next_easy_id = 0;
        }
        id
    }
}

// ---------------------------------------------------------------------------
// Synchronous pool API (pure state manipulation; each method locks internally).
// ---------------------------------------------------------------------------

impl ConnCache {
    /// Adds `conn` to the pool (`Curl_cpool_add`).
    ///
    /// The connection is placed in the bundle for its
    /// [`destination`](Connection::destination) (creating the bundle if needed),
    /// `num_conn` is incremented, and its `bits.in_cpool` flag is set. A
    /// connection id is assigned from `next_connection_id` **only when the
    /// connection does not already have one** (`connection_id == 0`), so a
    /// connection keeps a stable identity across the detach/re-add cycle that the
    /// Rust ownership model uses for reuse. Ids are handed out monotonically
    /// starting at `1`; `0` is reserved as the "unassigned" sentinel (the value
    /// [`Connection::new`] leaves in place).
    ///
    /// # Errors
    /// Returns [`Ok`] in all cases. The result type mirrors curl's
    /// `WARN_UNUSED_RESULT CURLcode Curl_cpool_add`; the C `CURLE_OUT_OF_MEMORY`
    /// path is subsumed by Rust's allocator (an allocation failure aborts rather
    /// than surfacing here), so no error is produced.
    pub fn add(&self, mut conn: Connection) -> Result<()> {
        let mut inner = self.lock();

        if conn.connection_id == 0 {
            inner.next_connection_id = inner.next_connection_id.wrapping_add(1);
            if inner.next_connection_id <= 0 {
                inner.next_connection_id = 1;
            }
            conn.connection_id = inner.next_connection_id;
        }
        conn.bits.in_cpool = true;

        let dest = conn.destination.clone();
        inner
            .bundles
            .entry(dest)
            .or_insert_with(ConnBundle::new)
            .conns
            .push(conn);
        inner.num_conn += 1;

        tracing::trace!(
            target: "curl::cpool",
            num_conn = inner.num_conn,
            "[CPOOL] added connection"
        );
        Ok(())
    }

    /// Checks whether the pool has room for another connection to `dest`,
    /// returning the corresponding [`LimitResult`] (`Curl_cpool_check_limits`).
    ///
    /// As in curl, this first tries to *make room* by discarding the oldest idle
    /// connections: per-destination pressure discards the oldest idle connection
    /// in `dest`'s bundle, and total pressure discards the oldest idle connection
    /// anywhere. Only when no idle connection can be discarded — i.e. the
    /// remaining connections are all in use — does it report
    /// [`LimitResult::Dest`] or [`LimitResult::Total`]. A limit of `0` disables
    /// that check.
    ///
    /// Eviction here closes the idle connection immediately (dropping it, which
    /// tears down its sockets) so the check stays synchronous; graceful,
    /// negotiated shutdown of a live connection is available via
    /// [`ConnCache::conn_terminate`]. Discarding an *idle* connection abruptly is
    /// safe and is exactly the pressure-relief behavior curl performs.
    #[must_use]
    pub fn check_limits(&self, dest: &str) -> LimitResult {
        let mut inner = self.lock();
        let dest_limit = inner.max_per_host;
        let total_limit = inner.max_total;

        if dest_limit == 0 && total_limit == 0 {
            return LimitResult::Ok;
        }

        // Per-destination limit: discard oldest idle in this bundle to make room.
        if dest_limit != 0 {
            while inner.dest_count(dest) >= dest_limit {
                match inner.oldest_idle_in(dest) {
                    Some(idx) => {
                        if inner.remove_at(dest, idx).is_none() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            if inner.dest_count(dest) >= dest_limit {
                return LimitResult::Dest;
            }
        }

        // Total limit: discard oldest idle anywhere to make room.
        if total_limit != 0 {
            while inner.num_conn >= total_limit {
                match inner.oldest_idle_any() {
                    Some((d, idx)) => {
                        if inner.remove_at(&d, idx).is_none() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            if inner.num_conn >= total_limit {
                return LimitResult::Total;
            }
        }

        LimitResult::Ok
    }

    /// Finds and **detaches** an idle, reusable, non-multiplexed connection
    /// matching `key`, transferring ownership to the caller
    /// (curl's `ConnectionExists` reuse path via `Curl_cpool_find`).
    ///
    /// The candidate bundle is selected by [`ReuseKey::destination`]; within it,
    /// the first connection that is idle (`attached_xfers == 0`), not
    /// multiplexed, and accepted by [`ReuseKey::matches`] is removed from the
    /// pool and returned. Multiplexed connections are intentionally skipped here:
    /// they are shared *in place* via [`ConnCache::try_multiplex`] rather than
    /// detached, because a multiplexed connection may serve several transfers at
    /// once. Returns `None` when no suitable connection exists.
    #[must_use]
    pub fn get_conn(&self, key: &ReuseKey) -> Option<Connection> {
        let mut inner = self.lock();
        let idx = match inner.bundles.get(&key.destination) {
            Some(bundle) => bundle
                .conns
                .iter()
                .position(|c| !c.in_use() && !c.is_multiplex(FIRSTSOCKET) && key.matches(c)),
            None => None,
        }?;
        inner.remove_at(&key.destination, idx)
    }

    /// Attempts to reuse a **multiplexed** pooled connection matching `key` by
    /// reserving a stream slot on it, returning its `connection_id` on success
    /// (curl's `CHECK_MULTIPLEX_OK` / `Curl_attach_connection` path).
    ///
    /// The connection **stays in the pool** and its `attached_xfers` counter is
    /// incremented, so the same connection can be handed to several transfers
    /// concurrently — up to the stream ceiling reported by the filter chain's
    /// `CF_QUERY_MAX_CONCURRENT` query. Returns `None` when no matching
    /// multiplexed connection exists or every match is already at its stream
    /// limit. Release a slot with [`ConnCache::detach_stream`].
    #[must_use]
    pub fn try_multiplex(&self, key: &ReuseKey) -> Option<i64> {
        let mut inner = self.lock();
        let bundle = inner.bundles.get_mut(&key.destination)?;
        for conn in &mut bundle.conns {
            if !conn.is_multiplex(FIRSTSOCKET) || !key.matches(conn) {
                continue;
            }
            let max = max_concurrent(conn);
            if (conn.attached_xfers as usize) < max {
                conn.attached_xfers += 1;
                return Some(conn.connection_id);
            }
        }
        None
    }

    /// Releases one stream slot previously reserved by [`ConnCache::try_multiplex`]
    /// on the pooled connection with `id`, decrementing its `attached_xfers`.
    ///
    /// Returns `true` if the connection was found (and a slot released). This is
    /// the bookkeeping counterpart used when a multiplexed transfer finishes but
    /// the connection remains pooled for other streams.
    pub fn detach_stream(&self, id: i64) -> bool {
        let mut inner = self.lock();
        for bundle in inner.bundles.values_mut() {
            if let Some(conn) = bundle.conns.iter_mut().find(|c| c.connection_id == id) {
                if conn.attached_xfers > 0 {
                    conn.attached_xfers -= 1;
                }
                return true;
            }
        }
        false
    }

    /// Invokes `conn_cb` for each connection in `destination`'s bundle until it
    /// returns `true`, and reports whether any invocation did so
    /// (`Curl_cpool_find`).
    ///
    /// The callback receives a shared reference and inspects the connection
    /// (matching curl's read-oriented match callbacks); use
    /// [`ConnCache::do_by_id`] or [`ConnCache::do_locked`] when a mutation is
    /// required. The pool lock is held for the duration, so the callback must not
    /// re-enter the pool.
    pub fn find<F>(&self, destination: &str, mut conn_cb: F) -> bool
    where
        F: FnMut(&Connection) -> bool,
    {
        let inner = self.lock();
        if let Some(bundle) = inner.bundles.get(destination) {
            for conn in &bundle.conns {
                if conn_cb(conn) {
                    return true;
                }
            }
        }
        false
    }

    /// Invokes `cb` against the pooled connection whose `connection_id` equals
    /// `id`, under the pool lock, returning whether such a connection was found
    /// (`Curl_cpool_do_by_id`).
    pub fn do_by_id<F>(&self, id: i64, cb: F) -> bool
    where
        F: FnOnce(&mut Connection),
    {
        let mut inner = self.lock();
        for bundle in inner.bundles.values_mut() {
            if let Some(conn) = bundle.conns.iter_mut().find(|c| c.connection_id == id) {
                cb(conn);
                return true;
            }
        }
        false
    }

    /// Invokes `cb` for the caller-owned `conn` while holding the pool lock,
    /// returning the callback's result (`Curl_cpool_do_locked`).
    ///
    /// Unlike [`ConnCache::do_by_id`], the connection is not looked up in the
    /// pool — it is supplied by the caller (it may already be checked out) — and
    /// the callback is always invoked. Holding the lock serializes the callback
    /// against concurrent pool operations, matching curl's contract that the
    /// callback runs "under the connection pool's lock".
    pub fn do_locked<F, R>(&self, conn: &mut Connection, cb: F) -> R
    where
        F: FnOnce(&mut Connection) -> R,
    {
        let _guard = self.lock();
        cb(conn)
    }

    /// Performs periodic keep-alive/upkeep on every pooled connection
    /// (`Curl_cpool_upkeep`).
    ///
    /// Each connection's per-socket filter chains are given a chance to run
    /// their keep-alive work (`Curl_conn_upkeep` → `Curl_conn_keep_alive`).
    /// Per-connection errors are logged and skipped rather than aborting the
    /// sweep, exactly as curl's upkeep returns `CURLE_OK` regardless.
    ///
    /// # Errors
    /// Returns [`Ok`] in all cases (per-connection keep-alive failures are
    /// swallowed), mirroring curl's `Curl_cpool_upkeep`.
    pub fn upkeep(&self) -> Result<()> {
        let mut inner = self.lock();
        for bundle in inner.bundles.values_mut() {
            for conn in &mut bundle.conns {
                let conn_id = conn.connection_id;
                for chain in conn.cfilter.iter_mut().flatten() {
                    if let Err(err) = chain.keep_alive() {
                        tracing::debug!(
                            target: "curl::cpool",
                            connection_id = conn_id,
                            error = %err,
                            "[CPOOL] keep-alive failed"
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

/// The maximum number of concurrent transfers a connection can carry, from its
/// primary filter chain's `CF_QUERY_MAX_CONCURRENT` answer (curl's
/// `Curl_conn_get_max_concurrent`), clamped to at least `1`. A connection with
/// no installed chain reports `1`.
fn max_concurrent(conn: &Connection) -> usize {
    conn.cfilter[FIRSTSOCKET]
        .as_ref()
        .map_or(1, |chain| chain.max_concurrent())
        .max(1)
}

// ---------------------------------------------------------------------------
// Asynchronous pool API (operations that hand connections to graceful teardown).
//
// Every method here follows the same discipline demanded by the crate's
// `std::sync::Mutex`: acquire the lock in a short synchronous scope, collect any
// connections that must be torn down into an owned `Vec<Connection>`, drop the
// guard, and only then `await` `shutdown::terminate`. The mutex guard is NEVER
// held across an `.await` point.
// ---------------------------------------------------------------------------

impl ConnCache {
    /// Returns a just-finished connection to the pool, or closes it, and reports
    /// whether it was kept (`Curl_cpool_conn_now_idle`).
    ///
    /// The connection's `lastused` timestamp is stamped first. A connection
    /// flagged `bits.close` or `bits.no_reuse` is not pooled — it is gracefully
    /// shut down and `false` is returned. Otherwise the connection is added back
    /// to the pool; if that pushes the pool above its `max_total` ceiling, the
    /// oldest idle connection anywhere is discarded (immediately, since it is
    /// idle). The return value is `true` when *this* connection remains pooled
    /// and `false` when it was the one discarded — exactly curl's
    /// `kept = (oldest_idle != conn)`.
    ///
    /// When `max_total` is `0` (no limit) the connection is always kept.
    pub async fn conn_now_idle(&self, mut conn: Connection) -> bool {
        conn.lastused = Instant::now();

        // Non-reusable connections are never pooled; shut them down gracefully
        // (the transfer finished cleanly, so a negotiated close is appropriate).
        if conn.bits.close || conn.bits.no_reuse {
            conn.bits.in_cpool = false;
            tracing::trace!(
                target: "curl::cpool",
                connection_id = conn.connection_id,
                "[CPOOL] connection not reusable, closing"
            );
            shutdown::terminate(conn, true).await;
            return false;
        }

        let (evicted, kept) = {
            let mut inner = self.lock();

            // Add back to the pool (assigning an id only if it lacks one).
            if conn.connection_id == 0 {
                inner.next_connection_id = inner.next_connection_id.wrapping_add(1);
                if inner.next_connection_id <= 0 {
                    inner.next_connection_id = 1;
                }
                conn.connection_id = inner.next_connection_id;
            }
            conn.bits.in_cpool = true;
            let this_id = conn.connection_id;
            let dest = conn.destination.clone();
            inner
                .bundles
                .entry(dest)
                .or_insert_with(ConnBundle::new)
                .conns
                .push(conn);
            inner.num_conn += 1;

            // Enforce the soft pool-size ceiling by discarding the oldest idle
            // connection when we are over `max_total`.
            let mut evicted = None;
            let mut kept = true;
            if inner.max_total != 0 && inner.num_conn > inner.max_total {
                if let Some((dest, idx)) = inner.oldest_idle_any() {
                    if let Some(old) = inner.remove_at(&dest, idx) {
                        kept = old.connection_id != this_id;
                        tracing::trace!(
                            target: "curl::cpool",
                            num_conn = inner.num_conn,
                            max_total = inner.max_total,
                            "[CPOOL] pool full, discarding oldest idle connection"
                        );
                        evicted = Some(old);
                    }
                }
            }
            (evicted, kept)
        };

        // Idle connection discarded for pool pressure: close it immediately.
        if let Some(old) = evicted {
            shutdown::terminate(old, false).await;
        }
        kept
    }

    /// Scans the pool for dead (and explicitly non-reusable) idle connections and
    /// evicts them, at most once per second (`Curl_cpool_prune_dead`).
    ///
    /// The sweep is throttled: if fewer than [`PRUNE_INTERVAL_MS`] milliseconds
    /// have elapsed since the previous sweep it returns immediately (the very
    /// first sweep always runs, matching curl's zero-initialized `last_cleanup`).
    /// A connection is evicted when it is not in use and either marked
    /// `bits.no_reuse` or judged dead by [`conn_seems_dead`] (its primary filter
    /// chain reports it is not alive and no buffered data is pending). Dead
    /// connections are closed immediately; a connection removed only because it
    /// is `no_reuse` but still appears alive is shut down gracefully.
    pub async fn prune_dead(&self) {
        let victims: Vec<(Connection, bool)> = {
            let mut inner = self.lock();

            if let Some(last) = inner.last_cleanup {
                if last.elapsed().as_millis() < PRUNE_INTERVAL_MS {
                    return;
                }
            }
            inner.last_cleanup = Some(Instant::now());

            let dests: Vec<String> = inner.bundles.keys().cloned().collect();
            let mut victims = Vec::new();
            for dest in dests {
                // Decide which indices in this bundle are dead/non-reusable. The
                // liveness probe needs `&mut` on the chain, so it runs here while
                // the pool is locked (it is synchronous).
                let mut doomed: Vec<(usize, bool)> = Vec::new();
                if let Some(bundle) = inner.bundles.get_mut(&dest) {
                    for (idx, conn) in bundle.conns.iter_mut().enumerate() {
                        if conn.in_use() {
                            continue;
                        }
                        let dead = conn_seems_dead(conn);
                        if conn.bits.no_reuse || dead {
                            // Graceful shutdown only makes sense while alive.
                            doomed.push((idx, !dead));
                        }
                    }
                }
                // Remove highest indices first so earlier indices stay valid.
                for (idx, do_shutdown) in doomed.into_iter().rev() {
                    if let Some(conn) = inner.remove_at(&dest, idx) {
                        victims.push((conn, do_shutdown));
                    }
                }
            }
            victims
        };

        for (conn, do_shutdown) in victims {
            shutdown::terminate(conn, do_shutdown).await;
        }
    }

    /// Reacts to a network change by preventing reuse of every existing
    /// connection and closing all idle ones (`Curl_cpool_nw_changed`).
    ///
    /// Every pooled connection is marked `bits.no_reuse` (so any that are
    /// currently in use will be reaped once they go idle), and every idle
    /// connection is removed and closed immediately — after a network change the
    /// old connections are assumed unusable, so no graceful shutdown is
    /// attempted.
    pub async fn nw_changed(&self) {
        let stale: Vec<Connection> = {
            let mut inner = self.lock();

            for bundle in inner.bundles.values_mut() {
                for conn in &mut bundle.conns {
                    conn.bits.no_reuse = true;
                }
            }

            let dests: Vec<String> = inner.bundles.keys().cloned().collect();
            let mut stale = Vec::new();
            for dest in dests {
                let idxs: Vec<usize> = match inner.bundles.get(&dest) {
                    Some(bundle) => bundle
                        .conns
                        .iter()
                        .enumerate()
                        .filter(|(_, conn)| !conn.in_use())
                        .map(|(idx, _)| idx)
                        .collect(),
                    None => Vec::new(),
                };
                for idx in idxs.into_iter().rev() {
                    if let Some(conn) = inner.remove_at(&dest, idx) {
                        stale.push(conn);
                    }
                }
            }
            stale
        };

        for conn in stale {
            shutdown::terminate(conn, false).await;
        }
    }

    /// Terminates a caller-owned connection, handing it to graceful (or, when
    /// `aborted`, immediate) teardown (`Curl_conn_terminate`).
    ///
    /// The connection is guaranteed to be marked out of the pool
    /// (`bits.in_cpool = false`) and its `bits.aborted` flag is set to `aborted`
    /// before it is passed to [`shutdown::terminate`]. When `aborted` is `true`
    /// the connection is closed without a graceful shutdown (curl skips the
    /// shutdown for aborted transfers so the peer does not mistake the abort for
    /// a clean completion); otherwise a graceful shutdown is attempted first.
    /// Takes ownership of `conn`; on return the connection has been closed and
    /// dropped.
    pub async fn conn_terminate(&self, mut conn: Connection, aborted: bool) {
        conn.bits.in_cpool = false;
        conn.bits.aborted = aborted;
        tracing::trace!(
            target: "curl::cpool",
            connection_id = conn.connection_id,
            aborted,
            "[CPOOL] terminating connection"
        );
        shutdown::terminate(conn, !aborted).await;
    }
}

/// Judges whether an idle connection appears dead (curl's `Curl_conn_seems_dead`
/// as consulted by the connection-pool reaper).
///
/// A connection with buffered inbound data pending is considered alive (there is
/// readable data waiting); otherwise its primary filter chain's liveness probe
/// (`Curl_conn_is_alive`) is consulted. A connection with no installed chain is
/// treated as dead, since it is not a usable live network connection.
fn conn_seems_dead(conn: &mut Connection) -> bool {
    if conn.data_pending(FIRSTSOCKET) {
        return false;
    }
    match conn.cfilter[FIRSTSOCKET].as_mut() {
        Some(chain) => !chain.is_alive(),
        None => true,
    }
}

// ===========================================================================
// Tests
//
// The pool is exercised in isolation with lightweight in-process connections.
// A tiny `TestFilter` stands in for a real transport filter so the liveness
// probe (`is_alive`) and the multiplex/stream-limit query
// (`CF_QUERY_MAX_CONCURRENT`) can be driven deterministically without any
// sockets — mirroring the mock-filter approach the sibling `filters` module
// uses in its own tests. No external daemons are required (AAP §0.6.4).
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::{ConnectionFilter, FilterChain, FilterCtx, QueryCtx, QueryOut};
    use crate::conn::{CfQuery, CfType, Scheme};

    // -- Test doubles -------------------------------------------------------

    /// A minimal [`ConnectionFilter`] used to drive pool behavior in tests.
    ///
    /// * `alive` controls the liveness probe consulted by [`prune_dead`] via
    ///   [`conn_seems_dead`].
    /// * `multiplex` toggles the `CF_TYPE_MULTIPLEX` capability so the
    ///   connection is treated as shareable in place.
    /// * `max_concurrent` is the answer to the `CF_QUERY_MAX_CONCURRENT` query
    ///   that caps [`ConnCache::try_multiplex`] hand-outs.
    struct TestFilter {
        alive: bool,
        multiplex: bool,
        max_concurrent: Option<u32>,
    }

    impl TestFilter {
        /// A plain (non-multiplex) filter whose liveness probe returns `alive`.
        fn alive(alive: bool) -> Self {
            TestFilter {
                alive,
                multiplex: false,
                max_concurrent: None,
            }
        }

        /// A multiplex-capable, live filter advertising `max` concurrent streams.
        fn mux(max: u32) -> Self {
            TestFilter {
                alive: true,
                multiplex: true,
                max_concurrent: Some(max),
            }
        }
    }

    impl ConnectionFilter for TestFilter {
        fn name(&self) -> &'static str {
            "TEST"
        }

        fn cf_type(&self) -> CfType {
            if self.multiplex {
                CfType::MULTIPLEX
            } else {
                CfType::default()
            }
        }

        fn is_alive(&mut self, _cx: &mut FilterCtx<'_>) -> bool {
            self.alive
        }

        fn query(&self, cx: &QueryCtx<'_>, query: CfQuery, out: &mut QueryOut) -> Result<()> {
            match (query, self.max_concurrent) {
                (CfQuery::MaxConcurrent, Some(n)) => {
                    *out = QueryOut::MaxConcurrent(n);
                    Ok(())
                }
                _ => cx.query_next(query, out),
            }
        }
    }

    // -- Builders -----------------------------------------------------------

    fn scheme(name: &str, port: u16) -> Scheme {
        let mut s = Scheme::new(name, port);
        s.is_ssl = matches!(name, "https" | "ftps");
        s
    }

    /// A bare connection (no filter chain) to `name://host:port`.
    fn make_conn(name: &str, host: &str, port: u16) -> Connection {
        Connection::new(scheme(name, port), host, port)
    }

    /// A connection carrying `filter` on its primary socket, so the pool's
    /// liveness/multiplex queries have something to consult.
    fn conn_with_filter(name: &str, host: &str, port: u16, filter: TestFilter) -> Connection {
        let mut conn = make_conn(name, host, port);
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(filter));
        conn.cfilter[FIRSTSOCKET] = Some(chain);
        conn
    }

    // -- add / get_conn -----------------------------------------------------

    #[test]
    fn add_then_get_conn_matches_and_rejects_nonmatching() {
        let cache = ConnCache::new(0, 0);
        cache.add(make_conn("https", "example.com", 443)).unwrap();
        assert_eq!(cache.num_conn(), 1);

        // A key for a different destination finds no bundle → None, and the
        // pooled connection is left untouched.
        let miss = ReuseKey::from_connection(&make_conn("https", "other.com", 443));
        assert!(cache.get_conn(&miss).is_none());
        assert_eq!(cache.num_conn(), 1);

        // A matching key detaches the connection, transferring ownership out.
        let hit = ReuseKey::from_connection(&make_conn("https", "example.com", 443));
        let got = cache.get_conn(&hit);
        assert!(got.is_some());
        assert_eq!(got.unwrap().destination, "0/443/example.com");
        assert_eq!(cache.num_conn(), 0);
    }

    #[test]
    fn add_assigns_ids_monotonically() {
        let cache = ConnCache::new(0, 0);
        cache.add(make_conn("http", "a.example.com", 80)).unwrap();
        cache.add(make_conn("http", "b.example.com", 80)).unwrap();

        let mut ids = Vec::new();
        cache.find("0/80/a.example.com", |c| {
            ids.push(c.connection_id);
            false
        });
        cache.find("0/80/b.example.com", |c| {
            ids.push(c.connection_id);
            false
        });
        ids.sort_unstable();
        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn xfer_init_hands_out_monotonic_easy_ids() {
        let cache = ConnCache::new(0, 0);
        assert_eq!(cache.xfer_init(), 0);
        assert_eq!(cache.xfer_init(), 1);
        assert_eq!(cache.xfer_init(), 2);
    }

    // -- limit checks -------------------------------------------------------

    #[test]
    fn per_host_limit_returns_dest() {
        let cache = ConnCache::new(0, 1); // per-host cap = 1
        let mut conn = make_conn("https", "example.com", 443);
        conn.attached_xfers = 1; // in use → cannot be discarded to make room
        let dest = conn.destination.clone();
        cache.add(conn).unwrap();

        assert_eq!(cache.check_limits(&dest), LimitResult::Dest);
        assert_eq!(cache.check_limits(&dest).as_i32(), 1);
    }

    #[test]
    fn total_limit_returns_total() {
        let cache = ConnCache::new(1, 0); // total cap = 1
        let mut conn = make_conn("https", "example.com", 443);
        conn.attached_xfers = 1; // in use → cannot be discarded
        cache.add(conn).unwrap();

        // Room for a *different* destination is denied by the total limit.
        assert_eq!(cache.check_limits("0/443/other.com"), LimitResult::Total);
        assert_eq!(cache.check_limits("0/443/other.com").as_i32(), 2);
    }

    #[test]
    fn limits_ok_when_unbounded() {
        let cache = ConnCache::new(0, 0);
        assert!(cache.check_limits("0/443/example.com").is_ok());
        assert_eq!(cache.check_limits("0/443/example.com"), LimitResult::Ok);
    }

    #[test]
    fn check_limits_evicts_idle_to_make_room() {
        let cache = ConnCache::new(0, 1); // per-host cap = 1
        cache.add(make_conn("https", "example.com", 443)).unwrap(); // idle
        let dest = "0/443/example.com";
        assert_eq!(cache.dest_count(dest), 1);

        // The idle connection can be discarded to make room, so the check
        // succeeds *and* the connection is evicted.
        assert_eq!(cache.check_limits(dest), LimitResult::Ok);
        assert_eq!(cache.dest_count(dest), 0);
    }

    // -- reuse matching -----------------------------------------------------

    #[test]
    fn reuse_rejects_close_and_no_reuse() {
        let key = ReuseKey::from_connection(&make_conn("https", "example.com", 443));

        // Positive control: a fresh, clean connection matches.
        assert!(key.matches(&make_conn("https", "example.com", 443)));

        // `bits.close` and `bits.no_reuse` each disqualify a connection.
        let mut closed = make_conn("https", "example.com", 443);
        closed.bits.close = true;
        assert!(!key.matches(&closed));

        let mut no_reuse = make_conn("https", "example.com", 443);
        no_reuse.bits.no_reuse = true;
        assert!(!key.matches(&no_reuse));

        // And through the pool: a pooled close-flagged connection is never
        // handed out, and stays in place (it is not detached).
        let cache = ConnCache::new(0, 0);
        let mut pooled = make_conn("https", "example.com", 443);
        pooled.bits.close = true;
        cache.add(pooled).unwrap();
        assert!(cache.get_conn(&key).is_none());
        assert_eq!(cache.num_conn(), 1);
    }

    #[test]
    fn reuse_rejects_credential_mismatch() {
        let key = ReuseKey::from_connection(&make_conn("https", "example.com", 443));
        let mut other_user = make_conn("https", "example.com", 443);
        other_user.user = Some("alice".to_string());
        assert!(!key.matches(&other_user));
    }

    // -- multiplexing -------------------------------------------------------

    #[test]
    fn multiplexed_connection_shared_up_to_stream_limit() {
        let cache = ConnCache::new(0, 0);
        cache
            .add(conn_with_filter(
                "https",
                "h2.example.com",
                443,
                TestFilter::mux(3),
            ))
            .unwrap();
        let key = ReuseKey::from_connection(&make_conn("https", "h2.example.com", 443));

        // A multiplexed connection is shared in place, never detached by
        // `get_conn`.
        assert!(cache.get_conn(&key).is_none());
        assert_eq!(cache.num_conn(), 1);

        // Stream slots are handed out up to the ceiling (3), then refused.
        let id1 = cache.try_multiplex(&key);
        let id2 = cache.try_multiplex(&key);
        let id3 = cache.try_multiplex(&key);
        assert!(id1.is_some());
        assert_eq!(id1, id2);
        assert_eq!(id2, id3);
        assert!(cache.try_multiplex(&key).is_none()); // at the stream limit
        assert_eq!(cache.num_conn(), 1); // stayed pooled throughout

        // Releasing a slot lets one more transfer attach.
        assert!(cache.detach_stream(id1.unwrap()));
        assert!(cache.try_multiplex(&key).is_some());
    }

    // -- pruning ------------------------------------------------------------

    #[tokio::test]
    async fn prune_dead_evicts_not_alive_keeps_live() {
        let cache = ConnCache::new(0, 0);
        let mut dead = conn_with_filter("https", "example.com", 443, TestFilter::alive(false));
        dead.connection_id = 100;
        let mut live = conn_with_filter("https", "example.com", 443, TestFilter::alive(true));
        live.connection_id = 200;
        cache.add(dead).unwrap();
        cache.add(live).unwrap();
        assert_eq!(cache.num_conn(), 2);

        cache.prune_dead().await;

        assert_eq!(cache.num_conn(), 1);
        assert!(!cache.do_by_id(100, |_| {})); // the dead one is gone
        assert!(cache.do_by_id(200, |_| {})); // the live one is kept
    }

    #[tokio::test]
    async fn prune_dead_reaps_no_reuse_even_when_alive() {
        let cache = ConnCache::new(0, 0);
        let mut conn = conn_with_filter("https", "example.com", 443, TestFilter::alive(true));
        conn.bits.no_reuse = true;
        cache.add(conn).unwrap();
        assert_eq!(cache.num_conn(), 1);

        cache.prune_dead().await;
        assert_eq!(cache.num_conn(), 0); // reaped despite being alive
    }

    #[tokio::test]
    async fn prune_dead_keeps_in_use_connection() {
        let cache = ConnCache::new(0, 0);
        let mut conn = conn_with_filter("https", "example.com", 443, TestFilter::alive(false));
        conn.attached_xfers = 1; // in use
        conn.connection_id = 9;
        cache.add(conn).unwrap();

        cache.prune_dead().await;
        // An in-use connection is never pruned, even if it probes as dead.
        assert_eq!(cache.num_conn(), 1);
        assert!(cache.do_by_id(9, |_| {}));
    }

    // -- conn_now_idle ------------------------------------------------------

    #[tokio::test]
    async fn conn_now_idle_pools_reusable() {
        let cache = ConnCache::new(0, 0);
        let kept = cache
            .conn_now_idle(make_conn("https", "example.com", 443))
            .await;
        assert!(kept);
        assert_eq!(cache.num_conn(), 1);
    }

    #[tokio::test]
    async fn conn_now_idle_closes_non_reusable() {
        let cache = ConnCache::new(0, 0);
        let mut conn = make_conn("https", "example.com", 443);
        conn.bits.close = true;
        let kept = cache.conn_now_idle(conn).await;
        assert!(!kept);
        assert_eq!(cache.num_conn(), 0);
    }

    #[tokio::test]
    async fn conn_now_idle_over_limit_discards_oldest() {
        let cache = ConnCache::new(1, 0); // total cap = 1
        let mut a = make_conn("https", "example.com", 443);
        a.connection_id = 1;
        cache.add(a).unwrap(); // A pooled first (older `lastused`)

        // `conn_now_idle` stamps B with a fresh `lastused` (≥ A's), so within
        // the shared bundle A is the oldest idle and is the one discarded.
        let mut b = make_conn("https", "example.com", 443);
        b.connection_id = 2;
        let kept = cache.conn_now_idle(b).await;

        assert!(kept); // B (the freshly idled one) is kept
        assert_eq!(cache.num_conn(), 1);
        assert!(cache.do_by_id(2, |_| {})); // B present
        assert!(!cache.do_by_id(1, |_| {})); // A (oldest) discarded
    }

    // -- network change / termination --------------------------------------

    #[tokio::test]
    async fn nw_changed_closes_idle_and_marks_in_use_no_reuse() {
        let cache = ConnCache::new(0, 0);
        cache
            .add(make_conn("https", "idle.example.com", 443))
            .unwrap();
        let mut busy = make_conn("https", "busy.example.com", 443);
        busy.attached_xfers = 1;
        busy.connection_id = 42;
        cache.add(busy).unwrap();
        assert_eq!(cache.num_conn(), 2);

        cache.nw_changed().await;

        // The idle connection is closed; the in-use one survives but is now
        // flagged non-reusable so it is reaped once it goes idle.
        assert_eq!(cache.num_conn(), 1);
        let mut flagged = false;
        assert!(cache.do_by_id(42, |c| {
            flagged = c.bits.no_reuse;
        }));
        assert!(flagged);
    }

    #[tokio::test]
    async fn conn_terminate_consumes_connection_without_touching_pool() {
        let cache = ConnCache::new(0, 0);
        cache
            .add(make_conn("https", "keep.example.com", 443))
            .unwrap();
        assert_eq!(cache.num_conn(), 1);

        // A caller-owned connection (here flagged as if pooled) is cleanly
        // torn down; `conn_terminate` must clear `in_cpool` before shutdown so
        // the shutdown path's invariant holds, and it must not disturb the
        // unrelated pooled connection.
        let mut victim = make_conn("https", "victim.example.com", 443);
        victim.bits.in_cpool = true;
        cache.conn_terminate(victim, true).await;

        assert_eq!(cache.num_conn(), 1);
    }

    // -- upkeep -------------------------------------------------------------

    #[test]
    fn upkeep_runs_without_error() {
        let cache = ConnCache::new(0, 0);
        cache
            .add(conn_with_filter(
                "https",
                "example.com",
                443,
                TestFilter::alive(true),
            ))
            .unwrap();
        assert!(cache.upkeep().is_ok());
        assert_eq!(cache.num_conn(), 1); // upkeep does not evict
    }

    // -- sharing / concurrency ---------------------------------------------

    #[test]
    fn conn_cache_is_clone_send_sync_and_reexported() {
        fn assert_traits<T: Clone + Send + Sync>() {}
        assert_traits::<ConnCache>();

        // This binding only compiles if `crate::conn::ConnCache` resolves to
        // *this* type — i.e. the module is correctly re-exported by `mod.rs`.
        let via_reexport: crate::conn::ConnCache = ConnCache::new(0, 0);
        let _cloned: ConnCache = via_reexport.clone();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shared_across_tasks_accounts_correctly() {
        let cache = ConnCache::new(0, 0);
        let n = 50usize;

        // Two tasks concurrently add to disjoint destinations on ONE shared
        // pool (cloned `Arc`), exercising the mutex under contention.
        let c1 = cache.clone();
        let c2 = cache.clone();
        let t1 = tokio::spawn(async move {
            for i in 0..n {
                c1.add(make_conn("http", &format!("a{i}.example.com"), 80))
                    .unwrap();
            }
        });
        let t2 = tokio::spawn(async move {
            for i in 0..n {
                c2.add(make_conn("http", &format!("b{i}.example.com"), 80))
                    .unwrap();
            }
        });
        t1.await.unwrap();
        t2.await.unwrap();
        assert_eq!(cache.num_conn(), 2 * n);

        // Detach every "a" connection from the shared pool; the "b" ones remain.
        let mut detached = 0;
        for i in 0..n {
            let key =
                ReuseKey::from_connection(&make_conn("http", &format!("a{i}.example.com"), 80));
            if cache.get_conn(&key).is_some() {
                detached += 1;
            }
        }
        assert_eq!(detached, n);
        assert_eq!(cache.num_conn(), n);
    }
}
