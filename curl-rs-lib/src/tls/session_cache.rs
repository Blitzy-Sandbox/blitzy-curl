// curl-rs — a memory-safe Rust rewrite of curl / libcurl.
//
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// This software is licensed as described in the file COPYING, which you should
// have received as part of this distribution. The terms are also available at
// https://curl.se/docs/copyright.html.
//
// You may opt to use, copy, modify, merge, publish, distribute and/or sell
// copies of the Software, and permit persons to whom the Software is furnished
// to do so, under the terms of the COPYING file.
//
// This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
// KIND, either express or implied.
//
// SPDX-License-Identifier: curl

//! TLS session-resumption cache — the safe Rust replacement for libcurl's
//! `lib/vtls/vtls_scache.c` / `vtls_scache.h` (consulted as a *behavioral
//! oracle*, **not** transliterated line-by-line).
//!
//! # Purpose
//!
//! Caching TLS session state lets a reconnection to the *same* peer **resume**
//! a previous session instead of performing a full handshake: TLS 1.2 session
//! IDs / tickets and TLS 1.3 tickets (optionally with 0-RTT "early data") are
//! remembered so the second connection is cheaper. curl stores this state in a
//! bounded cache shared by all easy handles of a multi handle (or, when a
//! [`curl_share`] is configured, across many easy handles via
//! `CURL_LOCK_DATA_SSL_SESSION`).
//!
//! This module reproduces that behaviour on top of [`rustls`], which drives
//! resumption through the [`rustls::client::ClientSessionStore`] trait installed
//! into [`rustls::client::ClientConfig`]`.resumption`.
//!
//! # Strategy — bridge curl's cache onto rustls' resumption store
//!
//! The implemented design ("PRIMARY") wraps rustls'
//! [`ClientSessionMemoryCache`](rustls::client::ClientSessionMemoryCache): it
//! already *is* a [`ClientSessionStore`](rustls::client::ClientSessionStore),
//! is internally synchronized (so no external `Mutex` is required to use it),
//! applies an LRU bound, and lets rustls itself enforce ticket lifetime/age
//! limits. [`SessionCache`] owns one behind an [`Arc`] and exposes it through
//! [`SessionCache::rustls_store`] so `crate::tls::config` can install it with
//! `Resumption::store(...)`.
//!
//! ## Peer / verify isolation (the critical correctness rule)
//!
//! curl keys every cached session under a *peer key*
//! (`Curl_ssl_peer_key_make`) that encodes scheme/host/port/transport **and**
//! the negotiated TLS version **and** the relevant verify configuration, so a
//! session is reused **only** for an identical peer *and* identical security
//! settings — never across mismatched verify settings or ports.
//!
//! With the rustls-backed design that isolation is achieved *structurally*:
//!
//! * rustls keys entries internally by
//!   [`ServerName`](rustls::pki_types::ServerName); and
//! * the verify configuration lives in the per-connection `ClientConfig`, so a
//!   *per-config* store can never leak a session across mismatched security
//!   settings.
//!
//! For the **shared-store** case (one cache living behind `crate::share`), reuse
//! is still keyed by `ServerName`, so callers must only share a cache among
//! connections with *compatible* verify settings — which is exactly the scope
//! curl's `CURL_LOCK_DATA_SSL_SESSION` already enforces. [`SessionCache::peer_key`]
//! reproduces curl's key composition for explicit-keying needs and for tests.
//!
//! ## Lifetime caps (parity-critical)
//!
//! Following RFC 8446, curl clamps a TLS 1.3 session's cached lifetime to **7
//! days** and a TLS 1.2 (or earlier) session's to **1 day**
//! ([`CURL_SCACHE_MAX_13_LIFETIME_SEC`] / [`CURL_SCACHE_MAX_12_LIFETIME_SEC`]),
//! so a server cannot keep a stale session reusable indefinitely. rustls'
//! `ClientSessionMemoryCache` enforces ticket age internally; the explicit
//! [`capped_expiry`] / [`clamp_valid_until`] helpers reproduce curl's exact
//! `now + min(ticket_lifetime, cap)` arithmetic for auditable parity and back
//! the [`SessionEntry`] metadata model.
//!
//! ## The explicit-parity alternative (documented, not implemented)
//!
//! An alternative layering would implement [`ClientSessionStore`] by hand over a
//! `Mutex<HashMap<peer_key, Vec<SessionEntry>>>` and enforce the 7-day / 1-day
//! caps directly on insert (discarding expired entries on take). That is only
//! warranted if `ClientSessionMemoryCache` proves insufficient for the
//! lifetime-cap requirement — it does not, because rustls bounds ticket
//! age/lifetime itself. The PRIMARY path is therefore preferred; the cap helpers
//! and [`SessionEntry`] are nonetheless provided (and tested) so the parity math
//! is auditable and so such a custom store could be built without new logic.
//!
//! # Shareability
//!
//! [`SessionCache`] is `Send + Sync` and cheaply [`Clone`] (an `Arc` bump), so
//! `crate::share` can embed it in `SharedData` behind the share's
//! `Arc<Mutex<...>>` and obtain the underlying rustls store for each connection
//! via [`rustls_store`](SessionCache::rustls_store) (which takes `&self`).
//! Cloning a [`SessionCache`], or calling `rustls_store()` on two clones, yields
//! handles to the **same** underlying cache.
//!
//! # Memory safety
//!
//! This module contains **no `unsafe`** (it carries `#![forbid(unsafe_code)]`)
//! and uses only safe `std` and `rustls` types.
//!
//! [`curl_share`]: https://curl.se/libcurl/c/curl_share_setopt.html

#![forbid(unsafe_code)]
// Several parity helpers (the explicit cap/expiry math, the `SessionEntry`
// metadata model) are part of this module's public, auditable surface but are
// consumed by `crate::tls::config` / `crate::share`, which are wired up by
// sibling files. Allow dead_code here — consistent with `tls/hostname.rs` and
// `util/timeval.rs` — so the zero-warnings build/lint gate stays green while
// those consumers land.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::client::{ClientSessionMemoryCache, ClientSessionStore, Resumption};

// `crate::error` — curl's session functions are fallible (`CURLcode`); the
// session-metadata constructor mirrors `Curl_ssl_session_create2`'s
// `CURLE_BAD_FUNCTION_ARGUMENT` rejection of empty session data.
use crate::error::{CurlError, Result};
// `crate::util::timeval::curlx_gmtime` is the epoch-seconds -> calendar
// conversion used to render a session's `valid_until` for diagnostics.
//
// NOTE: `crate::util::timeval::curlx_now` is intentionally NOT used here: it is
// a *monotonic* clock with an arbitrary origin ("not a Unix timestamp", per its
// own docs), whereas curl's `valid_until` is a wall-clock epoch second computed
// from `time(NULL)`. Wall-clock "now" therefore comes from [`std::time`]
// (see [`epoch_now_secs`]). `crate::util::timediff` is likewise not used: it
// converts milliseconds <-> `Timeval`/`Duration` for select()/poll() timeout
// math, which the session cache (which works purely in epoch *seconds*) has no
// need of.
use crate::util::timeval::curlx_gmtime;

// =============================================================================
// Constants (verified against lib/vtls/vtls_scache.h and lib/vtls/vtls.h)
// =============================================================================

/// Maximum cached lifetime, in seconds, for a **TLS 1.3** session: **7 days**.
///
/// RFC 8446 restricts TLS 1.3 ticket lifetime to one week; curl clamps cached
/// sessions to the same bound. Mirrors C's
/// `CURL_SCACHE_MAX_13_LIFETIME_SEC == (60 * 60 * 24 * 7)`.
pub const CURL_SCACHE_MAX_13_LIFETIME_SEC: i64 = 60 * 60 * 24 * 7;

/// Maximum cached lifetime, in seconds, for a **TLS 1.2** (and earlier)
/// session: **1 day**.
///
/// Less-secure versions are restricted to a single day. Mirrors C's
/// `CURL_SCACHE_MAX_12_LIFETIME_SEC == (60 * 60 * 24)`.
pub const CURL_SCACHE_MAX_12_LIFETIME_SEC: i64 = 60 * 60 * 24;

/// Default lifetime, in seconds, applied when a session's expiry is unknown
/// (`valid_until <= 0`): **1 day**.
///
/// Mirrors C's `scache->default_lifetime_secs = (24 * 60 * 60)` set in
/// `Curl_ssl_scache_create`.
pub const DEFAULT_LIFETIME_SEC: i64 = 60 * 60 * 24;

/// IETF protocol identifier for **TLS 1.2** (`0x0303`).
///
/// Mirrors C's `CURL_IETF_PROTO_TLS1_2` (lib/vtls/vtls.h).
pub const IETF_PROTO_TLS1_2: u16 = 0x0303;

/// IETF protocol identifier for **TLS 1.3** (`0x0304`).
///
/// Mirrors C's `CURL_IETF_PROTO_TLS1_3` (lib/vtls/vtls.h). Used to select the
/// per-version lifetime cap.
pub const IETF_PROTO_TLS1_3: u16 = 0x0304;

/// Default number of distinct peers a cache tracks.
///
/// curl's `curl_multi_init` builds the cache with `CURL_TLS_SESSION_SIZE == 25`
/// peers (and a `curl_share` likewise uses 25).
pub const DEFAULT_MAX_PEERS: usize = 25;

/// Default number of sessions retained per peer.
///
/// curl passes `max_sessions_per_peer == 2` to `Curl_ssl_scache_create`.
pub const DEFAULT_MAX_SESSIONS_PER_PEER: usize = 2;

/// Default total session capacity = [`DEFAULT_MAX_PEERS`] *
/// [`DEFAULT_MAX_SESSIONS_PER_PEER`] = **50**.
///
/// curl bounds the cache as `max_peers * max_sessions_per_peer`; the
/// rustls-backed store takes a single total bound, so the product is used.
pub const DEFAULT_CACHE_CAPACITY: usize = DEFAULT_MAX_PEERS * DEFAULT_MAX_SESSIONS_PER_PEER;

// =============================================================================
// Lifetime-cap / expiry helpers (mirror cf_scache_add_session arithmetic)
// =============================================================================

/// Return the maximum cached lifetime, in seconds, for the given negotiated TLS
/// version id.
///
/// TLS 1.3 ([`IETF_PROTO_TLS1_3`]) yields [`CURL_SCACHE_MAX_13_LIFETIME_SEC`]
/// (7 days); every other version yields [`CURL_SCACHE_MAX_12_LIFETIME_SEC`]
/// (1 day). This matches curl's
/// `(ietf_tls_id == CURL_IETF_PROTO_TLS1_3) ? MAX_13 : MAX_12`.
#[must_use]
pub fn max_lifetime_for(ietf_tls_id: u16) -> i64 {
    if ietf_tls_id == IETF_PROTO_TLS1_3 {
        CURL_SCACHE_MAX_13_LIFETIME_SEC
    } else {
        CURL_SCACHE_MAX_12_LIFETIME_SEC
    }
}

/// Compute a capped absolute expiry (epoch seconds) from a server-advertised
/// ticket **lifetime** (a duration in seconds).
///
/// Implements curl's `now + min(ticket_lifetime, cap)` rule: the lifetime is
/// floored at `0` (a negative advertisement is treated as "already expired
/// duration") and capped at [`max_lifetime_for`] for the TLS version, then added
/// to `now_epoch_secs`. All arithmetic is saturating, so no input can overflow.
#[must_use]
pub fn capped_expiry(now_epoch_secs: i64, ticket_lifetime_secs: i64, ietf_tls_id: u16) -> i64 {
    let cap = max_lifetime_for(ietf_tls_id);
    // min(max(lifetime, 0), cap) — `cap` is always positive so `clamp`'s
    // `min <= max` precondition holds.
    let effective = ticket_lifetime_secs.clamp(0, cap);
    now_epoch_secs.saturating_add(effective)
}

/// Wall-clock variant of [`capped_expiry`] that reads "now" from the system
/// clock (epoch seconds), matching curl's use of `time(NULL)`.
///
/// Use this when computing a freshly-negotiated session's `valid_until` at
/// caching time.
#[must_use]
pub fn capped_expiry_now(ticket_lifetime_secs: i64, ietf_tls_id: u16) -> i64 {
    capped_expiry(epoch_now_secs(), ticket_lifetime_secs, ietf_tls_id)
}

/// Clamp an **absolute** `valid_until` (epoch seconds) to curl's per-version
/// ceiling, reproducing `cf_scache_add_session`'s add-time logic:
///
/// * an unknown/unset expiry (`valid_until <= 0`) defaults to
///   `now + `[`DEFAULT_LIFETIME_SEC`] (1 day); then
/// * the value is capped at `now + `[`max_lifetime_for`]`(ietf_tls_id)`.
///
/// All arithmetic is saturating.
#[must_use]
pub fn clamp_valid_until(now_epoch_secs: i64, valid_until: i64, ietf_tls_id: u16) -> i64 {
    let vu = if valid_until <= 0 {
        now_epoch_secs.saturating_add(DEFAULT_LIFETIME_SEC)
    } else {
        valid_until
    };
    let ceiling = now_epoch_secs.saturating_add(max_lifetime_for(ietf_tls_id));
    vu.min(ceiling)
}

/// Render an epoch-second timestamp as an RFC 3339 / ISO 8601 UTC string, or
/// `None` if the value is out of the representable calendar range.
///
/// This is the one genuine consumer of
/// [`crate::util::timeval::curlx_gmtime`]; it is intended for diagnostics /
/// trace output of a session's `valid_until` (curl logs session validity in
/// `cf_scache_add_session`).
#[must_use]
pub fn format_epoch_rfc3339(epoch_secs: i64) -> Option<String> {
    curlx_gmtime(epoch_secs).map(|dt| dt.to_rfc3339())
}

/// Current wall-clock time as epoch seconds (the Rust image of C's
/// `(curl_off_t)time(NULL)`).
///
/// A clock reading before the Unix epoch (which `SystemTime` can in principle
/// report) is treated as `0`; an absurdly large reading saturates to
/// [`i64::MAX`]. Never panics.
fn epoch_now_secs() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

// =============================================================================
// SessionEntry — parity model of `struct Curl_ssl_session`
// =============================================================================

/// The metadata curl tracks for a single cached TLS session, the Rust image of
/// the relevant fields of C's `struct Curl_ssl_session`.
///
/// In the PRIMARY (rustls-backed) design, rustls owns the actual session
/// values; this struct exists for **auditable parity** — it carries the
/// session bytes plus the fields curl uses to decide reuse and expiry
/// (`valid_until`, `ietf_tls_id`, `alpn`, `earlydata_max`) and would back the
/// documented explicit-parity [`ClientSessionStore`] alternative if it were ever
/// needed. It is also the natural unit the cap helpers operate on.
///
/// (curl's optional QUIC transport parameters `quic_tp`/`quic_tp_len` are not
/// modelled here: in this workspace HTTP/3 resumption is handled by the
/// `quinn`/`h3` stack rather than this cache.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionEntry {
    /// Opaque session ticket / id bytes (C: `sdata` + `sdata_len`).
    sdata: Vec<u8>,
    /// Seconds since the Unix epoch until the session expires (C: `valid_until`,
    /// a `curl_off_t`). `0` means "unknown" until [`cap_lifetime`](Self::cap_lifetime).
    valid_until: i64,
    /// Negotiated IETF TLS version id, e.g. [`IETF_PROTO_TLS1_3`] (C:
    /// `ietf_tls_id`). Selects the per-version lifetime cap.
    ietf_tls_id: u16,
    /// ALPN protocol selected for the session, if any (C: `alpn`).
    alpn: Option<String>,
    /// Maximum 0-RTT "early data" the peer advertised (C: `earlydata_max`).
    earlydata_max: usize,
}

impl SessionEntry {
    /// Create a session-metadata record, mirroring `Curl_ssl_session_create2`.
    ///
    /// Returns [`CurlError::BadFunctionArgument`] when `sdata` is empty —
    /// reproducing curl's `if(!sdata || !sdata_len) return
    /// CURLE_BAD_FUNCTION_ARGUMENT`. The `valid_until` passed here is the raw
    /// (un-capped) expiry; apply [`cap_lifetime`](Self::cap_lifetime) (or
    /// construct it from [`capped_expiry`]) to enforce curl's caps.
    ///
    /// # Errors
    /// Returns [`CurlError::BadFunctionArgument`] if `sdata` is empty.
    pub fn new(
        sdata: Vec<u8>,
        ietf_tls_id: u16,
        alpn: Option<String>,
        valid_until: i64,
        earlydata_max: usize,
    ) -> Result<Self> {
        if sdata.is_empty() {
            return Err(CurlError::BadFunctionArgument);
        }
        Ok(Self {
            sdata,
            valid_until,
            ietf_tls_id,
            alpn,
            earlydata_max,
        })
    }

    /// The opaque session ticket / id bytes.
    #[must_use]
    pub fn session_data(&self) -> &[u8] {
        &self.sdata
    }

    /// Expiry as seconds since the Unix epoch (C: `valid_until`).
    #[must_use]
    pub fn valid_until(&self) -> i64 {
        self.valid_until
    }

    /// Negotiated IETF TLS version id (C: `ietf_tls_id`).
    #[must_use]
    pub fn ietf_tls_id(&self) -> u16 {
        self.ietf_tls_id
    }

    /// Selected ALPN protocol, if any (C: `alpn`).
    #[must_use]
    pub fn alpn(&self) -> Option<&str> {
        self.alpn.as_deref()
    }

    /// Maximum 0-RTT early data advertised by the peer (C: `earlydata_max`).
    ///
    /// NOTE (early data / 0-RTT): curl gates early data on `CURLSSLOPT_EARLYDATA`
    /// and tracks this maximum. In the PRIMARY design rustls handles 0-RTT
    /// internally through the resumption store plus
    /// `ClientConfig::enable_early_data` (which `crate::tls::config` only turns
    /// on when the option requests it). This module simply preserves the value
    /// rather than acting on it.
    #[must_use]
    pub fn earlydata_max(&self) -> usize {
        self.earlydata_max
    }

    /// Whether the session was negotiated with TLS 1.3.
    #[must_use]
    pub fn is_tls13(&self) -> bool {
        self.ietf_tls_id == IETF_PROTO_TLS1_3
    }

    /// Whether the session has expired relative to `now_epoch_secs`.
    ///
    /// Mirrors curl's `cf_scache_session_expired`:
    /// `(valid_until > 0) && (valid_until < now)`. An unknown expiry
    /// (`valid_until <= 0`) is treated as not-expired.
    #[must_use]
    pub fn is_expired(&self, now_epoch_secs: i64) -> bool {
        self.valid_until > 0 && self.valid_until < now_epoch_secs
    }

    /// Clamp this entry's `valid_until` to curl's per-version ceiling, exactly as
    /// `cf_scache_add_session` does at insert time (see [`clamp_valid_until`]).
    pub fn cap_lifetime(&mut self, now_epoch_secs: i64) {
        self.valid_until = clamp_valid_until(now_epoch_secs, self.valid_until, self.ietf_tls_id);
    }

    /// Render this entry's `valid_until` as an RFC 3339 UTC string for
    /// diagnostics, or `None` if it is out of the representable range.
    #[must_use]
    pub fn valid_until_rfc3339(&self) -> Option<String> {
        format_epoch_rfc3339(self.valid_until)
    }
}

// =============================================================================
// SessionCache — the rustls-backed, shareable session store (PRIMARY design)
// =============================================================================

/// A bounded, shareable TLS session-resumption cache.
///
/// Wraps a single [`rustls::client::ClientSessionMemoryCache`] behind an
/// [`Arc`]. It is the Rust replacement for curl's `struct Curl_ssl_scache`
/// (`Curl_ssl_scache_create`):
///
/// * **Bounded** — [`with_capacity`](Self::with_capacity) maps curl's
///   `max_peers * max_sessions_per_peer` to rustls' single total session bound;
///   [`new`](Self::new) uses curl's default of [`DEFAULT_CACHE_CAPACITY`] (50).
/// * **Shareable** — it is `Send + Sync` and cheaply [`Clone`] (an `Arc` bump),
///   so `crate::share` can embed it in `SharedData` for
///   `CURL_LOCK_DATA_SSL_SESSION`. Clones share the **same** underlying cache.
/// * **Installable** — [`rustls_store`](Self::rustls_store) hands the inner
///   store to `crate::tls::config`, which installs it via `Resumption::store`
///   (or call [`resumption`](Self::resumption) for the wrapped value directly).
///
/// Caching is **on by default** in curl (`primary.cache_session = TRUE`); this
/// type is always constructible and `crate::tls::config` simply declines to
/// install it when the user turns session reuse off.
#[derive(Clone, Debug)]
pub struct SessionCache {
    /// The shared, internally-synchronized rustls store. `Arc<dyn ...>` is
    /// `Send + Sync` because [`ClientSessionStore`] requires both, so cloning it
    /// for several `ClientConfig`s shares one cache.
    store: Arc<dyn ClientSessionStore>,
    /// The effective total session bound (after flooring at 1).
    capacity: usize,
}

impl SessionCache {
    /// Create a cache with curl's default capacity ([`DEFAULT_CACHE_CAPACITY`],
    /// i.e. 25 peers * 2 sessions = 50 total).
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CACHE_CAPACITY)
    }

    /// Create a cache bounded to at most `max_sessions` stored sessions in total.
    ///
    /// `max_sessions` is floored at `1` so the returned cache is always usable;
    /// to disable resumption, simply do not install the store. The value
    /// reported by [`capacity`](Self::capacity) is this effective (floored)
    /// bound.
    #[must_use]
    pub fn with_capacity(max_sessions: usize) -> Self {
        let effective = max_sessions.max(1);
        Self {
            store: Arc::new(ClientSessionMemoryCache::new(effective)),
            capacity: effective,
        }
    }

    /// Return a clone of the inner rustls store handle.
    ///
    /// Takes `&self` (no `&mut`) so it works through the share's
    /// `Arc<Mutex<...>>`. `crate::tls::config` installs the returned value with
    /// `ClientConfig.resumption = Resumption::store(cache.rustls_store())`. Every
    /// clone of this [`SessionCache`] — and every call to this method — returns a
    /// handle to the **same** underlying cache.
    #[must_use]
    pub fn rustls_store(&self) -> Arc<dyn ClientSessionStore> {
        Arc::clone(&self.store)
    }

    /// Convenience wrapper returning a [`Resumption`] already configured with
    /// this cache's store, ready to assign to `ClientConfig.resumption`.
    #[must_use]
    pub fn resumption(&self) -> Resumption {
        Resumption::store(self.rustls_store())
    }

    /// The effective total session capacity of this cache.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Compose a curl-style **peer key** from the security-relevant connection
    /// inputs.
    ///
    /// This reproduces the *composition* of `Curl_ssl_peer_key_make`: every
    /// distinguishing field contributes a labelled, delimited segment, so two
    /// keys are equal **iff** every field matches and differ as soon as any
    /// field differs. The labels echo curl's tokens — host:port, the transport
    /// (curl emits `:UDP` / `:QUIC` / `:UNIX`; TCP is the unmarked default), the
    /// verify configuration (curl emits `:NO-VRFY-PEER` etc.), and the
    /// negotiated TLS implementation/version (`:IMPL-...`).
    ///
    /// rustls performs the actual per-`ServerName` keying internally, so this
    /// helper is provided for explicit-keying needs (e.g. the documented custom
    /// store), diagnostics, and tests rather than being required by the PRIMARY
    /// path.
    #[must_use]
    pub fn peer_key(
        scheme: &str,
        host: &str,
        port: u16,
        transport: &str,
        tls_version_id: u16,
        verify: &str,
    ) -> String {
        format!(
            "{host}:{port}:TRNSPRT-{transport}:SCHEME-{scheme}:VRFY-{verify}:IMPL-{tls_version_id:#06x}"
        )
    }
}

impl Default for SessionCache {
    /// Equivalent to [`SessionCache::new`].
    fn default() -> Self {
        Self::new()
    }
}

// NOTE (USE_SSLS_EXPORT): curl's `vtls_scache.c` has an optional
// session import/export feature (`Curl_ssl_session_import` /
// `Curl_ssl_session_export`, gated on `USE_SSLS_EXPORT`) for sharing tickets
// across *processes*. It is not part of curl's default build and is not
// required for test-suite parity, so it is intentionally omitted here. It would
// belong behind a dedicated, non-default Cargo feature if ever needed.

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    // `use super::*` re-imports the module's `ClientSessionStore` binding, which
    // is what lets us call `set_kx_hint` / `kx_hint` on the
    // `Arc<dyn ClientSessionStore>` returned by `rustls_store()`.
    use super::*;
    use rustls::pki_types::ServerName;
    use rustls::NamedGroup;

    /// Compile-time assertion helper: only instantiable for `Send + Sync` types.
    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn lifetime_constants_match_curl() {
        // (a) the exact values from lib/vtls/vtls_scache.h.
        assert_eq!(CURL_SCACHE_MAX_13_LIFETIME_SEC, 604_800); // 7 days
        assert_eq!(CURL_SCACHE_MAX_12_LIFETIME_SEC, 86_400); // 1 day
        assert_eq!(DEFAULT_LIFETIME_SEC, 86_400); // default_lifetime_secs

        // version ids from lib/vtls/vtls.h
        assert_eq!(IETF_PROTO_TLS1_2, 0x0303);
        assert_eq!(IETF_PROTO_TLS1_3, 0x0304);
        // default capacity = 25 peers * 2 sessions
        assert_eq!(DEFAULT_MAX_PEERS, 25);
        assert_eq!(DEFAULT_MAX_SESSIONS_PER_PEER, 2);
        assert_eq!(
            DEFAULT_CACHE_CAPACITY,
            DEFAULT_MAX_PEERS * DEFAULT_MAX_SESSIONS_PER_PEER
        );
        assert_eq!(DEFAULT_CACHE_CAPACITY, 50);
    }

    #[test]
    fn peer_key_is_stable_and_distinct() {
        // (b) identical inputs -> identical key.
        let base = SessionCache::peer_key(
            "https",
            "example.com",
            443,
            "tcp",
            IETF_PROTO_TLS1_3,
            "verify",
        );
        let same = SessionCache::peer_key(
            "https",
            "example.com",
            443,
            "tcp",
            IETF_PROTO_TLS1_3,
            "verify",
        );
        assert_eq!(base, same, "identical inputs must produce identical keys");

        // Each differing field must change the key.
        assert_ne!(
            base,
            SessionCache::peer_key(
                "https",
                "example.org",
                443,
                "tcp",
                IETF_PROTO_TLS1_3,
                "verify"
            ),
            "host must affect the key"
        );
        assert_ne!(
            base,
            SessionCache::peer_key(
                "https",
                "example.com",
                8443,
                "tcp",
                IETF_PROTO_TLS1_3,
                "verify"
            ),
            "port must affect the key"
        );
        assert_ne!(
            base,
            SessionCache::peer_key(
                "https",
                "example.com",
                443,
                "quic",
                IETF_PROTO_TLS1_3,
                "verify"
            ),
            "transport must affect the key"
        );
        assert_ne!(
            base,
            SessionCache::peer_key(
                "https",
                "example.com",
                443,
                "tcp",
                IETF_PROTO_TLS1_2,
                "verify"
            ),
            "TLS version must affect the key"
        );
        assert_ne!(
            base,
            SessionCache::peer_key(
                "https",
                "example.com",
                443,
                "tcp",
                IETF_PROTO_TLS1_3,
                "noverify"
            ),
            "verify configuration must affect the key"
        );
        assert_ne!(
            base,
            SessionCache::peer_key(
                "http",
                "example.com",
                443,
                "tcp",
                IETF_PROTO_TLS1_3,
                "verify"
            ),
            "scheme must affect the key"
        );

        // The negotiated version is rendered as a fixed-width hex token.
        assert!(base.contains("IMPL-0x0304"), "got {base}");
    }

    #[test]
    fn rustls_store_is_shared_across_clones() {
        // (c) two clones observe the SAME underlying cache.
        let cache = SessionCache::new();
        let clone = cache.clone();

        let store_a = cache.rustls_store();
        let store_b = clone.rustls_store();

        // Structural proof: both handles point at the same allocation.
        assert!(
            Arc::ptr_eq(&store_a, &store_b),
            "clones must share one underlying store"
        );

        // Functional proof: set via one handle, observe via the other.
        let name = ServerName::try_from("rustls.example.com")
            .expect("static hostname literal is a valid DNS name");
        store_a.set_kx_hint(name.clone(), NamedGroup::X25519);
        assert_eq!(
            store_b.kx_hint(&name),
            Some(NamedGroup::X25519),
            "a value set through one clone must be visible through the other"
        );
    }

    #[test]
    fn capped_expiry_clamps_long_lived_tickets() {
        // (d) a 30-day ticket lifetime is clamped to 7 days (TLS 1.3) / 1 day
        // (TLS 1.2), via the `now + min(lifetime, cap)` helper.
        let now = 1_700_000_000_i64;
        let thirty_days = 30 * 24 * 60 * 60;

        assert_eq!(
            capped_expiry(now, thirty_days, IETF_PROTO_TLS1_3),
            now + CURL_SCACHE_MAX_13_LIFETIME_SEC
        );
        assert_eq!(
            capped_expiry(now, thirty_days, IETF_PROTO_TLS1_2),
            now + CURL_SCACHE_MAX_12_LIFETIME_SEC
        );

        // A short-lived ticket is left untouched.
        assert_eq!(capped_expiry(now, 3_600, IETF_PROTO_TLS1_3), now + 3_600);
        // A negative advertisement floors at "now".
        assert_eq!(capped_expiry(now, -10, IETF_PROTO_TLS1_3), now);

        // max_lifetime_for picks the right ceiling.
        assert_eq!(
            max_lifetime_for(IETF_PROTO_TLS1_3),
            CURL_SCACHE_MAX_13_LIFETIME_SEC
        );
        assert_eq!(
            max_lifetime_for(IETF_PROTO_TLS1_2),
            CURL_SCACHE_MAX_12_LIFETIME_SEC
        );
        assert_eq!(max_lifetime_for(0x0301), CURL_SCACHE_MAX_12_LIFETIME_SEC); // TLS 1.0 -> 1 day
    }

    #[test]
    fn clamp_valid_until_matches_curl_add_path() {
        let now = 1_700_000_000_i64;

        // 30-day absolute expiry clamped to the per-version ceiling.
        assert_eq!(
            clamp_valid_until(now, now + 30 * 86_400, IETF_PROTO_TLS1_3),
            now + CURL_SCACHE_MAX_13_LIFETIME_SEC
        );
        assert_eq!(
            clamp_valid_until(now, now + 30 * 86_400, IETF_PROTO_TLS1_2),
            now + CURL_SCACHE_MAX_12_LIFETIME_SEC
        );

        // Unknown / unset (<= 0) -> now + 1 day default.
        assert_eq!(
            clamp_valid_until(now, 0, IETF_PROTO_TLS1_2),
            now + DEFAULT_LIFETIME_SEC
        );
        assert_eq!(
            clamp_valid_until(now, -5, IETF_PROTO_TLS1_3),
            now + DEFAULT_LIFETIME_SEC
        );

        // An in-range value passes through unchanged.
        assert_eq!(
            clamp_valid_until(now, now + 600, IETF_PROTO_TLS1_3),
            now + 600
        );
    }

    #[test]
    fn session_entry_rejects_empty_data() {
        // Mirrors Curl_ssl_session_create2's CURLE_BAD_FUNCTION_ARGUMENT.
        let err = SessionEntry::new(Vec::new(), IETF_PROTO_TLS1_3, None, 0, 0)
            .expect_err("empty session data must be rejected");
        assert_eq!(err, CurlError::BadFunctionArgument);
    }

    #[test]
    fn session_entry_tracks_metadata_and_caps() {
        let now = 1_700_000_000_i64;
        let mut entry = SessionEntry::new(
            vec![1, 2, 3, 4],
            IETF_PROTO_TLS1_3,
            Some("h2".to_string()),
            now + 30 * 86_400,
            16_384,
        )
        .expect("non-empty session data is accepted");

        assert_eq!(entry.session_data(), &[1, 2, 3, 4]);
        assert_eq!(entry.ietf_tls_id(), IETF_PROTO_TLS1_3);
        assert_eq!(entry.alpn(), Some("h2"));
        assert_eq!(entry.earlydata_max(), 16_384);
        assert!(entry.is_tls13());
        assert!(!entry.is_expired(now));

        // Capping clamps the 30-day expiry down to the 7-day TLS 1.3 ceiling.
        entry.cap_lifetime(now);
        assert_eq!(entry.valid_until(), now + CURL_SCACHE_MAX_13_LIFETIME_SEC);

        // An entry whose expiry is in the past reports expired.
        let past = SessionEntry::new(vec![9], IETF_PROTO_TLS1_2, None, now - 1, 0)
            .expect("non-empty session data is accepted");
        assert!(past.is_expired(now));
    }

    #[test]
    fn format_epoch_rfc3339_renders_unix_epoch() {
        let s = format_epoch_rfc3339(0).expect("epoch 0 is representable");
        assert!(s.starts_with("1970-01-01"), "got {s}");
        // A SessionEntry exposes the same rendering for its valid_until.
        let entry = SessionEntry::new(vec![1], IETF_PROTO_TLS1_3, None, 0, 0).unwrap();
        assert!(entry
            .valid_until_rfc3339()
            .expect("epoch 0 is representable")
            .starts_with("1970-01-01"));
    }

    #[test]
    fn with_capacity_reports_bound_and_builds_usable_store() {
        let cache = SessionCache::with_capacity(10);
        assert_eq!(cache.capacity(), 10);

        // capacity is floored at 1 (never a zero-capacity store).
        assert_eq!(SessionCache::with_capacity(0).capacity(), 1);

        // The Resumption wrapper is constructible (this is what config.rs installs).
        let _resumption = cache.resumption();

        // The store is usable on its own.
        let store = cache.rustls_store();
        let name = ServerName::try_from("cap.example.com").expect("valid DNS name");
        store.set_kx_hint(name.clone(), NamedGroup::secp256r1);
        assert_eq!(store.kx_hint(&name), Some(NamedGroup::secp256r1));
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            SessionCache::default().capacity(),
            SessionCache::new().capacity()
        );
        assert_eq!(SessionCache::default().capacity(), DEFAULT_CACHE_CAPACITY);
    }

    #[test]
    fn types_are_send_sync() {
        // Required so `crate::share` can embed a SessionCache in SharedData
        // behind the share's Arc<Mutex<...>>.
        assert_send_sync::<SessionCache>();
        assert_send_sync::<SessionEntry>();
    }
}
