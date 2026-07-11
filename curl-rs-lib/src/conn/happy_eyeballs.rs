// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.
//! RFC 8305 "Happy Eyeballs" dual-stack connection racer.
//!
//! This module is the Rust port of curl's `lib/cf-ip-happy.c` (the
//! `Curl_cft_ip_happy` connection filter). It implements the **Happy Eyeballs
//! v2** algorithm (RFC 8305): given the ordered, family-interleaved list of
//! candidate addresses produced by name resolution, it opens connection
//! attempts to them in a staggered fashion — alternating between IPv6 and IPv4
//! — and the **first attempt to connect wins**. Every other in-flight or parked
//! attempt is then torn down.
//!
//! The filter sits *above* the socket filter(s) in a [`FilterChain`]: for each
//! candidate address it constructs a fresh single-address socket sub-chain (via
//! the per-transport [`CfIpConnectCreate`] factory) and drives them
//! concurrently. Once a winner emerges, this filter becomes a transparent
//! passthrough that delegates `send`/`recv`/`shutdown`/`query`/… to the winning
//! sub-chain — exactly as curl splices `winner->cf` in as `cf->next`.
//!
//! # Relationship to the C source-of-truth
//!
//! The implementation mirrors `cf-ip-happy.c` (982 lines) and its header
//! `cf-ip-happy.h` (56 lines) closely so that timing behaviour and diagnostics
//! remain faithful to curl 8.x:
//!
//! * [`CfConnectState`] mirrors the C `cf_connect_state`
//!   (`SCFST_INIT`/`SCFST_WAITING`/`SCFST_DONE`).
//! * [`IpAttempt`] mirrors `struct cf_ip_attempt` (one racing attempt: its
//!   sub-chain, address, family, last result, and the `connected` /
//!   `inconclusive` / `shutdown` flags).
//! * [`IpBallers`] mirrors `struct cf_ip_ballers` (the balancer: the running
//!   attempts, the two per-family address iterators, the connect-filter
//!   factory, the attempt-delay budget, and the family-interleaving cursor
//!   `last_attempt_ai_family`).
//! * [`HappyEyeballsFilter`] mirrors `struct cf_ip_happy_ctx` and the
//!   `Curl_cft_ip_happy` filter descriptor. Its [`name`](ConnectionFilter::name)
//!   is `"HAPPY-EYEBALLS"`, matching `cft->name` so `--trace`/`-v` output is
//!   identical.
//! * The family-selection rule, the [`CURL_HET_DEFAULT_MS`] 200 ms stagger, the
//!   "first to connect wins, tear down the rest" behaviour, the inconclusive
//!   restart, and the exhaustion / deadline error mapping all follow
//!   `cf_ip_ballers_run` (`cf-ip-happy.c:345`) step for step.
//!
//! # Design constraints
//!
//! * **Zero `unsafe`.** The crate root sets `#![forbid(unsafe_code)]`; this
//!   module contains no `unsafe` blocks of any kind. Address families are
//!   tracked with the small integer tags [`AF_INET`]/[`AF_INET6`] purely for
//!   interleaving bookkeeping — they are never handed to a syscall (the real
//!   family is always read from [`SocketAddr::is_ipv6`]).
//! * **Tokio-only async.** The staggered-attempt timer is
//!   [`tokio::time::sleep`]; attempts race through a
//!   [`FuturesUnordered`](futures_util::stream::FuturesUnordered) driven by a
//!   [`tokio::select!`]. There is no busy-waiting and no manual poll loop —
//!   this is the safe replacement for curl's
//!   `Curl_expire(…, EXPIRE_HAPPY_EYEBALLS)` scheduling.
//! * **Minimal Change Mandate.** No behaviour, timing, or option is introduced
//!   beyond what curl 8.x does; the RFC 8305 timing is preserved exactly.
//!
//! # Error mapping
//!
//! * All candidate addresses exhausted with no success →
//!   [`Error::Connect`] (curl `CURLE_COULDNT_CONNECT`, 7), carrying the last
//!   attempt's specific error when one is available.
//! * Overall connect deadline exceeded → [`Error::with_context`] with
//!   [`CurlCode::OperationTimedout`] (curl `CURLE_OPERATION_TIMEDOUT`, 28).

use std::any::Any;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::{Duration, Instant};

use futures_util::stream::{FuturesUnordered, StreamExt};

use crate::conn::filters::CfFuture;
use crate::conn::filters::{ConnectionFilter, FilterCtx, Pollset, QueryCtx, QueryOut};
use crate::conn::{socket, CfQuery, CfType, FilterChain, Transport, FIRSTSOCKET};
use crate::dns;
use crate::error::{CurlCode, Error, Result};

// ===========================================================================
// Timing & family constants (curl exact values)
// ===========================================================================

/// Default Happy-Eyeballs attempt delay, in milliseconds.
///
/// This is the minimum time that must elapse before a *new* parallel attempt is
/// started while earlier attempts are still in progress. It mirrors curl's
/// `CURL_HET_DEFAULT` (`include/curl/curl.h:967`), which `url.c:439` assigns to
/// the easy handle's `happy_eyeballs_timeout` unless the application overrides
/// it with `CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS`.
pub const CURL_HET_DEFAULT_MS: u64 = 200;

/// The DNS-phase Happy-Eyeballs timeout, in milliseconds.
///
/// curl arms `EXPIRE_HAPPY_EYEBALLS_DNS` for this long while a resolve that can
/// answer for either family is in flight, so a slow AAAA lookup does not stall
/// an otherwise-ready A result (`hostip.c`). It is exposed here for parity with
/// the C timing vocabulary; the resolver layer owns the DNS race itself.
pub const EXPIRE_HAPPY_EYEBALLS_DNS_MS: u64 = 5000;

/// Interleaving tag for the IPv4 address family.
///
/// This is **only** an internal bookkeeping tag used to alternate families
/// between attempts (curl compares `baller->last_attempt_ai_family` against
/// `AF_INET`). It is deliberately *not* taken from `libc` — the crate does not
/// link `libc`, and this value is never passed to a socket syscall. The real
/// family of any address is always determined via [`SocketAddr::is_ipv6`].
const AF_INET: i32 = 2;

/// Interleaving tag for the IPv6 address family. See [`AF_INET`] for why this is
/// a local constant rather than a `libc` import. The concrete numeric value is
/// irrelevant (it must merely differ from [`AF_INET`]); `10` matches Linux's
/// `AF_INET6` for readability when reading `--trace` alongside curl.
const AF_INET6: i32 = 10;

/// Returns the interleaving family tag ([`AF_INET`] or [`AF_INET6`]) for `addr`.
#[inline]
fn family_of(addr: &SocketAddr) -> i32 {
    if addr.is_ipv6() {
        AF_INET6
    } else {
        AF_INET
    }
}

/// The connect state of the Happy-Eyeballs filter, mirroring curl's
/// `enum cf_connect_state` (`cf-ip-happy.c:619`).
///
/// In curl the multi state machine calls `cf_ip_happy_connect` repeatedly and
/// the state advances `INIT → WAITING → DONE`. In this async port the whole
/// race runs to completion inside a single `connect().await`, but the state is
/// still tracked so a re-entrant call after success short-circuits and so
/// `--trace` diagnostics carry the same vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CfConnectState {
    /// `SCFST_INIT`: nothing started yet; the next `connect` initialises the
    /// balancer from the resolved address list.
    Init,
    /// `SCFST_WAITING`: attempts are being raced.
    Waiting,
    /// `SCFST_DONE`: a winner has been chosen and installed as `next`.
    Done,
}

// ===========================================================================
// AddrIter — per-family cursor over the resolved address list (cf_ai_iter).
// ===========================================================================

/// A cursor that walks a shared address slice yielding only the entries of one
/// address family, in list order. This is the port of curl's `struct
/// cf_ai_iter` plus `cf_ai_iter_next` / `cf_ai_iter_has_more`
/// (`cf-ip-happy.c:108`).
///
/// The address slice itself lives on [`IpBallers`] (curl keeps the head
/// `addr`/`iter->head` on the balancer); this cursor only stores the family it
/// selects and the position it has reached, so two cursors (one per family) can
/// walk the same list independently — exactly as curl's `addr_iter` and
/// `ipv6_iter` do.
#[derive(Debug, Clone)]
struct AddrIter {
    /// The family this cursor yields ([`AF_INET`] or [`AF_INET6`]).
    ai_family: i32,
    /// Index of the next slice element to examine.
    pos: usize,
}

impl AddrIter {
    /// Creates a cursor over `addrs` that yields only `ai_family` entries,
    /// positioned at the start (curl's `cf_ai_iter_init`).
    fn new(ai_family: i32) -> Self {
        AddrIter { ai_family, pos: 0 }
    }

    /// Returns the next address of this cursor's family, advancing the cursor
    /// past it (curl's `cf_ai_iter_next`). Returns `None` once the family is
    /// exhausted.
    fn next(&mut self, addrs: &[SocketAddr]) -> Option<SocketAddr> {
        while self.pos < addrs.len() {
            let addr = addrs[self.pos];
            self.pos += 1;
            if family_of(&addr) == self.ai_family {
                return Some(addr);
            }
        }
        None
    }

    /// Returns whether any further address of this cursor's family remains
    /// (curl's `cf_ai_iter_has_more`), without advancing the cursor.
    fn has_more(&self, addrs: &[SocketAddr]) -> bool {
        addrs[self.pos.min(addrs.len())..]
            .iter()
            .any(|addr| family_of(addr) == self.ai_family)
    }
}

// ===========================================================================
// CfIpConnectCreate — the per-transport socket-filter factory (cf-ip-happy.h).
// ===========================================================================

/// The factory that builds the single-address socket filter for one attempt.
///
/// This is the port of curl's `cf_ip_connect_create` typedef
/// (`cf-ip-happy.h:33`): given a concrete socket address and the transport, it
/// produces the connection filter that actually opens the socket. curl selects
/// the concrete function per transport in `get_cf_create`
/// (`cf-ip-happy.c:921`) — `Curl_cf_tcp_create` for TCP, `Curl_cf_udp_create`
/// for UDP/QUIC, `Curl_cf_unix_create` for a Unix socket.
///
/// It is a plain function pointer (not a boxed closure) so that
/// [`HappyEyeballsFilter`] stays `Send` and `Clone`-free, matching curl's
/// `cf_create` field which is likewise a bare function pointer. A test build
/// can substitute a fake factory (see the `cf_create` field of
/// [`HappyEyeballsFilter`] and [`HappyEyeballsFilter::with_cf_create`]),
/// mirroring curl's `UNITTESTS` `Curl_debug_set_transport_provider` override.
pub type CfIpConnectCreate = fn(socket::SockAddrEx, Transport) -> Box<dyn ConnectionFilter>;

/// The default [`CfIpConnectCreate`]: maps a transport to the matching
/// `crate::conn::socket` factory, reproducing curl's `get_cf_create`
/// (`cf-ip-happy.c:921`).
///
/// * [`Transport::Tcp`] → [`socket::tcp_create`]
/// * [`Transport::Udp`] / [`Transport::Quic`] → [`socket::udp_create`]
///   (QUIC runs over a UDP socket)
/// * [`Transport::Unix`] → [`socket::unix_create`]
/// * [`Transport::None`] → falls back to [`socket::tcp_create`] (curl never
///   reaches Happy Eyeballs without a real transport; this keeps the factory
///   total rather than panicking).
fn default_cf_create(addr: socket::SockAddrEx, transport: Transport) -> Box<dyn ConnectionFilter> {
    match transport {
        Transport::Udp | Transport::Quic => socket::udp_create(addr, transport),
        Transport::Unix => socket::unix_create(addr, transport),
        Transport::Tcp | Transport::None => socket::tcp_create(addr, transport),
    }
}

// ===========================================================================
// IpAttempt — one racing attempt (cf_ip_attempt).
// ===========================================================================

/// One Happy-Eyeballs connection attempt, mirroring curl's
/// `struct cf_ip_attempt` (`cf-ip-happy.c:159`).
///
/// In curl an attempt owns `a->cf`, a *sub-chain* of connection filters (the
/// comment at `cf-ip-happy.c:214` notes "the new filter might have
/// sub-filters"). Because [`FilterCtx`] can only be constructed by a
/// [`FilterChain`] (its constructor is private), the faithful Rust
/// representation of `a->cf` is an owned [`FilterChain`] — the single public
/// driver of a boxed [`ConnectionFilter`]. The chain is wrapped in [`Option`]
/// because, while the attempt's connect future is racing inside the
/// [`FuturesUnordered`](futures_util::stream::FuturesUnordered), ownership of the
/// chain is moved into that future; on completion the chain is returned and
/// stored back here (or promoted to the winner).
struct IpAttempt {
    /// Monotonic id used to correlate a completed race future back to its
    /// record in [`IpBallers::running`]. (Rust bookkeeping; curl correlates via
    /// the `a->cf` pointer identity.)
    id: u64,
    /// The attempt's socket sub-chain (`a->cf`). `None` while the attempt's
    /// connect future is in flight; `Some` when parked (e.g. inconclusive) or
    /// after completion.
    chain: Option<FilterChain>,
    /// The concrete address this attempt targets (`a->addr`).
    addr: SocketAddr,
    /// The interleaving family tag of [`addr`](Self::addr) (`a->ai_family`).
    ai_family: i32,
    /// The last connect result for this attempt (`a->result`): `None` while
    /// pending, `Some(err)` after a failed attempt.
    result: Option<Error>,
    /// Whether this attempt has connected (`a->connected`).
    connected: bool,
    /// Whether this attempt connected at the transport layer but a higher layer
    /// was undecided — curl's `CURLE_WEIRD_SERVER_REPLY` case (`a->inconclusive`,
    /// set in `cf_ip_attempt_connect`, `cf-ip-happy.c:227`).
    inconclusive: bool,
    /// Whether this attempt has finished shutting down (`a->shutdown`).
    shutdown: bool,
}

impl IpAttempt {
    /// Creates a fresh, not-yet-connected attempt record for `addr`.
    fn new(id: u64, addr: SocketAddr, ai_family: i32) -> Self {
        IpAttempt {
            id,
            chain: None,
            addr,
            ai_family,
            result: None,
            connected: false,
            inconclusive: false,
            shutdown: false,
        }
    }
}

// ===========================================================================
// IpBallers — the balancer (cf_ip_ballers).
// ===========================================================================

/// The Happy-Eyeballs balancer: the set of running attempts plus the state that
/// drives *which* address is tried *when*. This mirrors curl's
/// `struct cf_ip_ballers` (`cf-ip-happy.c:247`).
struct IpBallers {
    /// The resolved candidate addresses, already family-interleaved by the
    /// resolver (`crate::dns`). This is the shared list both [`AddrIter`]
    /// cursors walk. **Never re-sorted here** — the ordering is the resolver's
    /// responsibility; Happy Eyeballs only applies family *alternation* over
    /// it.
    addrs: Vec<SocketAddr>,
    /// Currently racing / parked attempts (`bs->running`, a linked list in C).
    running: Vec<IpAttempt>,
    /// Cursor over the IPv4 addresses (`bs->addr_iter`).
    addr_iter: AddrIter,
    /// Cursor over the IPv6 addresses (`bs->ipv6_iter`), present unless the
    /// resolve was restricted to IPv4 (curl gates this on `USE_IPV6` and
    /// `CURL_IPRESOLVE_V4`).
    ipv6_iter: Option<AddrIter>,
    /// The socket-filter factory for this transport (`bs->cf_create`).
    cf_create: CfIpConnectCreate,
    /// When the most recent attempt was started (`bs->last_attempt_started`);
    /// the 200 ms stagger is measured from here.
    last_attempt_started: Option<Instant>,
    /// The family of the most recently started attempt
    /// (`bs->last_attempt_ai_family`). **Initialised to [`AF_INET`]** so that
    /// the very first attempt selects [`AF_INET6`] — this is the seed of curl's
    /// family interleaving and must not be changed.
    last_attempt_ai_family: i32,
    /// The inter-attempt delay budget in milliseconds (`bs->attempt_delay_ms`),
    /// defaulting to [`CURL_HET_DEFAULT_MS`].
    attempt_delay_ms: u64,
    /// The transport being connected (`bs->transport`).
    transport: Transport,
    /// Monotonic id source for [`IpAttempt::id`].
    next_id: u64,
}

impl IpBallers {
    /// Initialises the balancer from a resolved address list, mirroring
    /// `cf_ip_ballers_init` (`cf-ip-happy.c:307`).
    ///
    /// The address list is first filtered to the requested family (curl relies
    /// on the resolver having done this, but filtering here keeps the cursors
    /// honest under an explicit `CURL_IPRESOLVE_*`). `addr_iter` walks IPv4 and
    /// `ipv6_iter` walks IPv6; the latter is omitted when the request is pinned
    /// to IPv4. Crucially, `last_attempt_ai_family` is seeded to [`AF_INET`] so
    /// the first selection prefers IPv6.
    fn init(
        addrs: &[SocketAddr],
        ip_version: dns::IpVersion,
        cf_create: CfIpConnectCreate,
        attempt_delay_ms: u64,
        transport: Transport,
    ) -> Self {
        let filtered: Vec<SocketAddr> = addrs
            .iter()
            .copied()
            .filter(|a| ip_version.accepts(a))
            .collect();
        // ipv6_iter is present unless the caller pinned IPv4 (curl's USE_IPV6 /
        // CURL_IPRESOLVE_V4 gate). Under a V6 pin, addr_iter simply yields
        // nothing because the filtered list holds no IPv4 entries.
        let ipv6_iter = if ip_version == dns::IpVersion::V4 {
            None
        } else {
            Some(AddrIter::new(AF_INET6))
        };
        IpBallers {
            addrs: filtered,
            running: Vec::new(),
            addr_iter: AddrIter::new(AF_INET),
            ipv6_iter,
            cf_create,
            last_attempt_started: None,
            last_attempt_ai_family: AF_INET,
            attempt_delay_ms,
            transport,
            next_id: 0,
        }
    }

    /// Returns whether any candidate address of either family remains untried
    /// (curl's `more_possible`, `cf-ip-happy.c:401`).
    fn has_more(&self) -> bool {
        self.addr_iter.has_more(&self.addrs)
            || self
                .ipv6_iter
                .as_ref()
                .is_some_and(|it| it.has_more(&self.addrs))
    }

    /// Selects the next address to try, alternating families, and records it as
    /// the new `last_attempt_ai_family`. This is the exact port of curl's
    /// family-selection block (`cf-ip-happy.c:419`):
    ///
    /// ```text
    /// if (last_attempt_ai_family == AF_INET || !addr_iter.has_more)
    ///     addr = ipv6_iter.next(); family = AF_INET6;
    /// if (!addr)
    ///     addr = addr_iter.next(); family = AF_INET;
    /// ```
    ///
    /// Seeded with `last_attempt_ai_family == AF_INET`, the first call therefore
    /// prefers IPv6, the next prefers IPv4, and so on — and whenever one family
    /// is exhausted the other is drained. Returns the chosen `(addr, family)` or
    /// `None` when no candidate remains.
    fn next_interleaved(&mut self) -> Option<(SocketAddr, i32)> {
        let mut chosen: Option<SocketAddr> = None;
        let mut ai_family = AF_INET;

        let v4_has_more = self.addr_iter.has_more(&self.addrs);
        if self.last_attempt_ai_family == AF_INET || !v4_has_more {
            if let Some(iter) = self.ipv6_iter.as_mut() {
                if let Some(addr) = iter.next(&self.addrs) {
                    chosen = Some(addr);
                    ai_family = AF_INET6;
                }
            }
        }
        if chosen.is_none() {
            if let Some(addr) = self.addr_iter.next(&self.addrs) {
                chosen = Some(addr);
                ai_family = AF_INET;
            }
        }

        chosen.map(|addr| {
            // Mirror curl setting `bs->last_attempt_ai_family = ai_family` after
            // the pick; `last_attempt_started` is stamped by the caller (it owns
            // "now").
            self.last_attempt_ai_family = ai_family;
            (addr, ai_family)
        })
    }
}

/// The staggered-start decision, extracted as a pure function so the RFC 8305
/// timing rule can be unit-tested deterministically (without wall-clock
/// flakiness). This encodes curl's `do_more` computation
/// (`cf-ip-happy.c:395`):
///
/// * If **nothing** is currently in flight (`ongoing == 0`), start immediately —
///   curl sets `do_more = TRUE` unconditionally so the first attempt (or a
///   fresh attempt after all others failed) begins without waiting.
/// * Otherwise start another attempt only if there is another address to try
///   **and** at least `attempt_delay_ms` has elapsed since the last attempt
///   began (the 200 ms [`CURL_HET_DEFAULT_MS`] Happy-Eyeballs stagger).
#[inline]
fn should_start_new_attempt(
    ongoing: usize,
    more_addrs: bool,
    elapsed_since_last_ms: u64,
    attempt_delay_ms: u64,
) -> bool {
    if ongoing == 0 {
        true
    } else {
        more_addrs && elapsed_since_last_ms >= attempt_delay_ms
    }
}

// ===========================================================================
// HappyEyeballsFilter — the connection filter (cf_ip_happy_ctx / Curl_cft_ip_happy).
// ===========================================================================

/// The Happy-Eyeballs connection filter, mirroring curl's `struct
/// cf_ip_happy_ctx` (`cf-ip-happy.c:625`) and the `Curl_cft_ip_happy` descriptor
/// (`cf-ip-happy.c:903`).
///
/// Insert one of these above the point where the transport socket filter would
/// otherwise be created (see [`insert_after`]); it races the resolved addresses
/// and, on success, becomes a transparent passthrough to the winning socket
/// sub-chain.
///
/// The candidate addresses are supplied out of band via
/// [`with_dns`](Self::with_dns) / [`set_dns`](Self::set_dns) before `connect`,
/// exactly as curl's `start_connect` reads `data->conn`'s resolved list at
/// connect time (`cf-ip-happy.c:700`).
pub struct HappyEyeballsFilter {
    /// The transport being connected (`ctx->transport`).
    transport: Transport,
    /// The per-transport socket-filter factory (`ctx->cf_create`). Overridable
    /// for tests, mirroring curl's `UNITTESTS` transport-provider hook.
    cf_create: CfIpConnectCreate,
    /// Connect state machine (`ctx->state`).
    state: CfConnectState,
    /// The live balancer (`ctx->ballers`). curl embeds the balancer directly in
    /// the context; here it is `Some` only while a race is active (state
    /// [`CfConnectState::Waiting`]) and cleared to `None` on success/failure,
    /// matching curl freeing the balancer once a winner is chosen.
    ballers: Option<IpBallers>,
    /// The resolved candidate addresses to race (populated via `set_dns`).
    addrs: Vec<SocketAddr>,
    /// The requested IP-version restriction applied when the balancer is built.
    ip_version: dns::IpVersion,
    /// The inter-attempt stagger budget (defaults to [`CURL_HET_DEFAULT_MS`]).
    attempt_delay_ms: u64,
    /// Optional overall connect deadline. When `Some`, exceeding it aborts the
    /// race with [`CurlCode::OperationTimedout`], reproducing curl's
    /// `Curl_timeleft_ms(data) < 0` check (`cf-ip-happy.c:505`). `None` leaves
    /// the deadline to the enclosing connection layer.
    overall_timeout_ms: Option<u64>,
    /// The socket index the constructed sub-chains serve (`FIRSTSOCKET` by
    /// default).
    sockindex: usize,
    /// The winning sub-chain once a race completes (curl's `cf->next =
    /// winner->cf`). All passthrough methods delegate here.
    winner: Option<FilterChain>,
    /// When `connect` first began racing (`ctx->started`), used for the overall
    /// deadline.
    started: Option<Instant>,
}

impl HappyEyeballsFilter {
    /// Creates an address-less filter for `transport` using the default socket
    /// factory. This is the ABI-parity constructor matching curl's
    /// `cf_ip_happy_insert_after`, which builds the context before the resolved
    /// addresses are known. Call [`set_dns`](Self::set_dns) before `connect`,
    /// or prefer [`with_dns`](Self::with_dns) / [`create_with_dns`].
    #[must_use]
    pub fn new(transport: Transport) -> Self {
        HappyEyeballsFilter {
            transport,
            cf_create: default_cf_create,
            state: CfConnectState::Init,
            ballers: None,
            addrs: Vec::new(),
            ip_version: dns::IpVersion::Whatever,
            attempt_delay_ms: CURL_HET_DEFAULT_MS,
            overall_timeout_ms: None,
            sockindex: FIRSTSOCKET,
            winner: None,
            started: None,
        }
    }

    /// Creates a filter for `transport` seeded with the resolved candidate
    /// addresses and family restriction.
    #[must_use]
    pub fn with_dns(
        transport: Transport,
        addrs: Vec<SocketAddr>,
        ip_version: dns::IpVersion,
    ) -> Self {
        let mut cf = Self::new(transport);
        cf.addrs = addrs;
        cf.ip_version = ip_version;
        cf
    }

    /// Overrides the inter-attempt stagger delay (curl's
    /// `CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS`). Defaults to
    /// [`CURL_HET_DEFAULT_MS`].
    #[must_use]
    pub fn with_attempt_delay_ms(mut self, delay_ms: u64) -> Self {
        self.attempt_delay_ms = delay_ms;
        self
    }

    /// Sets an overall connect deadline in milliseconds. When the elapsed
    /// connect time reaches it and no winner has emerged, `connect` fails with
    /// [`CurlCode::OperationTimedout`].
    #[must_use]
    pub fn with_overall_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.overall_timeout_ms = Some(timeout_ms);
        self
    }

    /// Overrides the socket index the constructed sub-chains serve. Defaults to
    /// [`FIRSTSOCKET`].
    #[must_use]
    pub fn with_sockindex(mut self, sockindex: usize) -> Self {
        self.sockindex = sockindex;
        self
    }

    /// Overrides the socket-filter factory. This is the safe, per-instance
    /// analogue of curl's `UNITTESTS` `Curl_debug_set_transport_provider`
    /// override (`cf-ip-happy.h:51`): tests inject a factory that produces mock
    /// socket filters instead of touching a real network.
    #[must_use]
    pub fn with_cf_create(mut self, cf_create: CfIpConnectCreate) -> Self {
        self.cf_create = cf_create;
        self
    }

    /// Supplies (or replaces) the resolved candidate addresses and family
    /// restriction to race, mirroring curl's `start_connect` reading the
    /// resolved list from the connection at connect time. Must be called before
    /// `connect` on a filter built with [`new`](Self::new).
    pub fn set_dns(&mut self, addrs: Vec<SocketAddr>, ip_version: dns::IpVersion) {
        self.addrs = addrs;
        self.ip_version = ip_version;
    }
}

/// Creates a boxed Happy-Eyeballs filter for `transport` (address-less), the
/// direct analogue of the context built by curl's `cf_ip_happy_insert_after`
/// (`cf-ip-happy.c:961`). The caller must populate addresses via
/// [`HappyEyeballsFilter::set_dns`] before connecting.
#[must_use]
pub fn create(transport: Transport) -> Box<dyn ConnectionFilter> {
    Box::new(HappyEyeballsFilter::new(transport))
}

/// Creates a boxed Happy-Eyeballs filter for `transport`, fully seeded with the
/// resolved addresses, family restriction, and stagger/deadline budgets — the
/// practical constructor used by the connection layer.
#[must_use]
pub fn create_with_dns(
    transport: Transport,
    addrs: Vec<SocketAddr>,
    ip_version: dns::IpVersion,
    attempt_delay_ms: u64,
    overall_timeout_ms: Option<u64>,
) -> Box<dyn ConnectionFilter> {
    let mut cf = HappyEyeballsFilter::with_dns(transport, addrs, ip_version)
        .with_attempt_delay_ms(attempt_delay_ms);
    cf.overall_timeout_ms = overall_timeout_ms;
    Box::new(cf)
}

/// Inserts a Happy-Eyeballs filter directly below the filter at `at_index` in
/// `chain`, the port of curl's `cf_ip_happy_insert_after`
/// (`cf-ip-happy.c:961`). The transport selects the socket factory the balancer
/// will use for each attempt.
///
/// Returns [`Error::bad_argument`] (via [`FilterChain::insert_after`]) if
/// `at_index` is out of range.
pub fn insert_after(chain: &mut FilterChain, at_index: usize, transport: Transport) -> Result<()> {
    chain.insert_after(at_index, create(transport))
}

// ===========================================================================
// The racing algorithm (cf_ip_attempt_connect + cf_ip_ballers_run).
// ===========================================================================

/// The `Output` of one racing attempt: its correlation id, the (returned) owned
/// sub-chain, and the connect result.
type AttemptOutcome = (u64, FilterChain, Result<bool>);

/// A boxed, `Send`, `'static` future racing a single attempt. It **owns** its
/// [`FilterChain`], so starting later staggered attempts never borrows or
/// cancels it; only choosing a winner (which drops the
/// [`FuturesUnordered`](futures_util::stream::FuturesUnordered)) tears the
/// losers down.
type AttemptFut = Pin<Box<dyn Future<Output = AttemptOutcome> + Send>>;

/// Drives one attempt's sub-chain connect to completion, returning the owned
/// chain alongside the result. This is the async analogue of curl's
/// `cf_ip_attempt_connect` (`cf-ip-happy.c:227`): a socket sub-chain resolves
/// atomically to `Ok(true)` (connected) or `Err` (failed / inconclusive), so
/// the loop body runs once; the `Ok(false)` yield-and-retry arm is a defensive
/// guard for a hypothetical multi-step mock and never busy-waits on real
/// sockets.
async fn drive_attempt(mut chain: FilterChain) -> (FilterChain, Result<bool>) {
    loop {
        match chain.connect(false).await {
            Ok(true) => return (chain, Ok(true)),
            Ok(false) => tokio::task::yield_now().await,
            Err(err) => return (chain, Err(err)),
        }
    }
}

impl HappyEyeballsFilter {
    /// Runs the whole Happy-Eyeballs race to completion, returning `Ok(true)`
    /// once a winner is installed. This is the port of `cf_ip_happy_connect` +
    /// `cf_ip_ballers_run` (`cf-ip-happy.c:345`), collapsed into a single
    /// `async` because the enclosing connection layer awaits `connect` once
    /// (the atomic-async model), rather than polling it from a multi loop.
    async fn run_connect(&mut self) -> Result<bool> {
        // Re-entrant call after a prior success: nothing to do.
        if self.state == CfConnectState::Done && self.winner.is_some() {
            return Ok(true);
        }

        // Locals that are not owned by the balancer.
        let sockindex = self.sockindex;
        let overall_timeout_ms = self.overall_timeout_ms;

        // start_connect: build the balancer from the resolved address list.
        let now = Instant::now();
        self.started = Some(now);
        self.state = CfConnectState::Waiting;
        self.ballers = Some(IpBallers::init(
            &self.addrs,
            self.ip_version,
            self.cf_create,
            self.attempt_delay_ms,
            self.transport,
        ));

        // The balancer owns the connect configuration (curl's `bs->cf_create` /
        // `bs->transport` / `bs->attempt_delay_ms`); read it back into locals so
        // the race body only ever borrows `self.ballers` / `self.winner`,
        // keeping every borrow disjoint and short-lived across `.await` points.
        let (cf_create, transport, attempt_delay_ms) = {
            let bs = self.ballers.as_ref().expect("balancer just initialised");
            (bs.cf_create, bs.transport, bs.attempt_delay_ms)
        };

        let mut inflight: FuturesUnordered<AttemptFut> = FuturesUnordered::new();
        let mut last_err: Option<Error> = None;

        loop {
            // --- Overall deadline (curl: Curl_timeleft_ms(data) < 0). ---
            if let Some(timeout) = overall_timeout_ms {
                let elapsed = self.started.map_or(0, ms_since);
                if elapsed >= timeout {
                    self.ballers = None;
                    return Err(Error::with_context(
                        CurlCode::OperationTimedout,
                        format!("Connection timeout after {elapsed} ms"),
                    ));
                }
            }

            // --- Snapshot the balancer decision inputs (short-lived borrows). ---
            let ongoing = inflight.len();
            let more_addrs = self.ballers.as_ref().is_some_and(IpBallers::has_more);
            let elapsed_since_last = self
                .ballers
                .as_ref()
                .and_then(|bs| bs.last_attempt_started)
                .map_or(u64::MAX, ms_since);
            let has_inconclusive = self
                .ballers
                .as_ref()
                .is_some_and(|bs| bs.running.iter().any(|a| a.inconclusive));

            // --- Staggered start (curl: do_more). ---
            if should_start_new_attempt(ongoing, more_addrs, elapsed_since_last, attempt_delay_ms) {
                // Pick the next address, alternating families (v6 first).
                let pick = self.ballers.as_mut().and_then(IpBallers::next_interleaved);

                if let Some((addr, family)) = pick {
                    let id = {
                        let bs = self
                            .ballers
                            .as_mut()
                            .expect("balancer present while waiting");
                        let id = bs.next_id;
                        bs.next_id += 1;
                        bs.last_attempt_started = Some(Instant::now());
                        bs.running.push(IpAttempt::new(id, addr, family));
                        id
                    };

                    let is_first = inflight.is_empty();
                    let sa = socket::SockAddrEx::for_transport(addr, transport);
                    let mut chain = FilterChain::new(sockindex);
                    chain.add(cf_create(sa, transport));
                    tracing::trace!(
                        target: "curl::cf",
                        transport = ?transport,
                        id,
                        "starting {} attempt for ipv{}",
                        if is_first { "first" } else { "next" },
                        if family == AF_INET { "4" } else { "6" },
                    );
                    inflight.push(Box::pin(async move {
                        let (chain, res) = drive_attempt(chain).await;
                        (id, chain, res)
                    }));
                    // goto evaluate: re-run the loop immediately.
                    continue;
                }

                // No more addresses to start.
                if has_inconclusive {
                    // Inconclusive handling (curl: restart one after the delay).
                    if elapsed_since_last >= attempt_delay_ms {
                        if let Some(fut) =
                            self.restart_one_inconclusive(cf_create, transport, sockindex)
                        {
                            tracing::trace!(
                                target: "curl::cf",
                                "all attempts inconclusive, restarting one",
                            );
                            inflight.push(fut);
                        }
                        continue;
                    }
                    let wait = attempt_delay_ms.saturating_sub(elapsed_since_last).max(1);
                    tracing::debug!(
                        target: "curl::cf",
                        "connect attempts inconclusive, retrying in {}ms",
                        wait,
                    );
                    tokio::time::sleep(Duration::from_millis(wait)).await;
                    continue;
                }

                if ongoing == 0 {
                    // Exhaustion (curl: CURLE_COULDNT_CONNECT, or the last
                    // attempt's specific error).
                    self.ballers = None;
                    return Err(last_err
                        .take()
                        .unwrap_or_else(|| Error::connect("Could not connect to server")));
                }
                // else: addresses exhausted but attempts still in flight — fall
                // through to wait for them.
            }

            // --- Compute the wakeup budget and wait (curl: Curl_expire). ---
            let wait = self.compute_wait(
                more_addrs,
                has_inconclusive,
                elapsed_since_last,
                overall_timeout_ms,
            );

            tokio::select! {
                // Race the in-flight attempts; the guard prevents polling an
                // empty set (which would resolve to `None`).
                outcome = inflight.next(), if !inflight.is_empty() => {
                    if let Some((id, chain, res)) = outcome {
                        match res {
                            Ok(true) => {
                                // Winner! Install as `next`; dropping `inflight`
                                // and clearing the balancer tears the losers
                                // down (curl: cf->next = winner->cf; free rest).
                                self.mark_connected(id);
                                self.winner = Some(chain);
                                self.state = CfConnectState::Done;
                                self.ballers = None;
                                tracing::trace!(target: "curl::cf", id, "attempt won");
                                return Ok(true);
                            }
                            Ok(false) => {
                                // Not connected and not an error: treat as a
                                // soft failure so the race can proceed.
                                self.fail_attempt(id, None);
                            }
                            Err(err) if err.code() == CurlCode::WeirdServerReply => {
                                // Inconclusive: TCP connected but a higher layer
                                // was undecided. Park for a later restart; the
                                // spent sub-chain is dropped here (restart builds
                                // a fresh socket / local port).
                                drop(chain);
                                self.mark_inconclusive(id, err);
                            }
                            Err(err) => {
                                // Hard failure: remember it and drop the record.
                                last_err = Some(clone_err(&err));
                                self.fail_attempt(id, Some(err));
                            }
                        }
                    }
                    continue;
                }
                () = tokio::time::sleep(Duration::from_millis(wait)) => {
                    // Timer elapsed: re-evaluate (maybe start a new attempt).
                    continue;
                }
            }
        }
    }

    /// Computes how long to sleep before re-evaluating, mirroring curl's
    /// `next_expire_ms = CURLMIN(timeleft, CURLMAX(attempt_delay - elapsed, 0))`
    /// (`cf-ip-happy.c:520`). Returns at least `1` ms so the loop never spins;
    /// when only waiting on in-flight attempts (no deadline, no pending
    /// addresses) it falls back to a periodic `attempt_delay_ms` re-evaluation
    /// tick (harmless, since [`tokio::select!`] also wakes on completion).
    fn compute_wait(
        &self,
        more_addrs: bool,
        has_inconclusive: bool,
        elapsed_since_last: u64,
        overall_timeout_ms: Option<u64>,
    ) -> u64 {
        let mut wait = u64::MAX;
        if more_addrs || has_inconclusive {
            wait = wait.min(self.attempt_delay_ms.saturating_sub(elapsed_since_last));
        }
        if let Some(timeout) = overall_timeout_ms {
            let elapsed = self.started.map_or(0, ms_since);
            wait = wait.min(timeout.saturating_sub(elapsed));
        }
        if wait == u64::MAX {
            wait = self.attempt_delay_ms;
        }
        wait.max(1)
    }

    /// Marks the running record `id` as connected (parity bookkeeping before the
    /// balancer is cleared on a win).
    fn mark_connected(&mut self, id: u64) {
        if let Some(bs) = self.ballers.as_mut() {
            if let Some(rec) = bs.running.iter_mut().find(|a| a.id == id) {
                rec.connected = true;
            }
        }
    }

    /// Marks the running record `id` inconclusive (curl `a->inconclusive`),
    /// keeping it in `running` so [`restart_one_inconclusive`] can rebuild it.
    fn mark_inconclusive(&mut self, id: u64, err: Error) {
        if let Some(bs) = self.ballers.as_mut() {
            if let Some(rec) = bs.running.iter_mut().find(|a| a.id == id) {
                rec.inconclusive = true;
                rec.connected = false;
                rec.chain = None;
                rec.result = Some(err);
            }
        }
    }

    /// Records a hard failure for record `id` and removes it from `running`
    /// (the attempt is dead; curl leaves the failed baller but it is neither
    /// ongoing nor inconclusive — removing it here is behaviourally identical).
    fn fail_attempt(&mut self, id: u64, err: Option<Error>) {
        if let Some(bs) = self.ballers.as_mut() {
            if let Some(pos) = bs.running.iter().position(|a| a.id == id) {
                if let Some(err) = err {
                    bs.running[pos].result = Some(err);
                }
                bs.running.remove(pos);
            }
        }
    }

    /// Restarts one inconclusive attempt with a fresh sub-chain (new socket /
    /// local port), mirroring `cf_ip_attempt_restart` (`cf-ip-happy.c:262`).
    /// Returns the new racing future, or `None` if there is nothing to restart.
    fn restart_one_inconclusive(
        &mut self,
        cf_create: CfIpConnectCreate,
        transport: Transport,
        sockindex: usize,
    ) -> Option<AttemptFut> {
        let bs = self.ballers.as_mut()?;
        let rec = bs.running.iter_mut().find(|a| a.inconclusive)?;
        // Reset the attempt's transient state; the new attempt either succeeds
        // or records a fresh failure (curl: Curl_reset_fail).
        rec.inconclusive = false;
        rec.connected = false;
        rec.result = None;
        rec.chain = None;
        let id = rec.id;
        let addr = rec.addr;
        let ai_family = rec.ai_family;

        let sa = socket::SockAddrEx::for_transport(addr, transport);
        let mut chain = FilterChain::new(sockindex);
        chain.add(cf_create(sa, transport));
        bs.last_attempt_started = Some(Instant::now());
        tracing::trace!(
            target: "curl::cf",
            id,
            "restarting inconclusive attempt for ipv{}",
            if ai_family == AF_INET { "4" } else { "6" },
        );

        let fut: AttemptFut = Box::pin(async move {
            let (chain, res) = drive_attempt(chain).await;
            (id, chain, res)
        });
        Some(fut)
    }
}

/// Milliseconds elapsed since `t`, saturating into `u64`.
#[inline]
fn ms_since(t: Instant) -> u64 {
    u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Produces an [`Error`] carrying the same [`CurlCode`] and message as `err`.
///
/// [`Error`] is not [`Clone`] (some variants wrap non-cloneable transport
/// errors), but the exhaustion path only needs the *code* and a message to
/// reproduce curl's "last attempt's specific error" behaviour, so this rebuilds
/// an equivalent error via [`Error::with_context`].
fn clone_err(err: &Error) -> Error {
    Error::with_context(err.code(), err.to_string())
}

// ===========================================================================
// ConnectionFilter impl — races on connect, then delegates to the winner.
// ===========================================================================

impl ConnectionFilter for HappyEyeballsFilter {
    /// `cft->name` — matches curl verbatim for `--trace`/`-v` parity.
    fn name(&self) -> &'static str {
        "HAPPY-EYEBALLS"
    }

    /// curl's `Curl_cft_ip_happy` declares no capability flags (`flags = 0`), so
    /// this reports the empty capability set. In particular it is *not* an
    /// `IP_CONNECT` filter itself — it composes the socket sub-chains that are.
    fn cf_type(&self) -> CfType {
        CfType::from_bits(0)
    }

    /// Drives the full RFC 8305 race to completion (see [`Self::run_connect`]).
    /// The enclosing chain calls this once and awaits it; on success a winner is
    /// installed and every method below delegates to it.
    fn connect<'a>(
        &'a mut self,
        _cx: &'a mut FilterCtx<'_>,
        _blocking: bool,
    ) -> CfFuture<'a, Result<bool>> {
        Box::pin(self.run_connect())
    }

    /// Gracefully shuts the connection down. Once a winner exists this delegates
    /// to it; otherwise it shuts down any parked attempt sub-chains, treating a
    /// failed shutdown as done (curl's `cf_ip_ballers_shutdown`,
    /// `cf-ip-happy.c:535`).
    fn shutdown<'a>(&'a mut self, _cx: &'a mut FilterCtx<'_>) -> CfFuture<'a, Result<bool>> {
        Box::pin(async move {
            if let Some(chain) = self.winner.as_mut() {
                return chain.shutdown(0).await;
            }
            let mut all_done = true;
            if let Some(bs) = self.ballers.as_mut() {
                for att in bs.running.iter_mut() {
                    if att.shutdown {
                        continue;
                    }
                    if let Some(chain) = att.chain.as_mut() {
                        match chain.shutdown(0).await {
                            Ok(true) | Err(_) => att.shutdown = true,
                            Ok(false) => all_done = false,
                        }
                    } else {
                        att.shutdown = true;
                    }
                }
            }
            Ok(all_done)
        })
    }

    /// Closes the winning sub-chain (and any parked attempts) and resets to the
    /// initial state (curl's `cf_ip_happy_close`, `cf-ip-happy.c:836`).
    fn close(&mut self, _cx: &mut FilterCtx<'_>) {
        if let Some(chain) = self.winner.as_mut() {
            chain.close();
        }
        if let Some(bs) = self.ballers.as_mut() {
            for att in bs.running.iter_mut() {
                if let Some(chain) = att.chain.as_mut() {
                    chain.close();
                }
            }
        }
        self.ballers = None;
        self.state = CfConnectState::Init;
    }

    /// Sends down the winning sub-chain. Before a winner exists there is no
    /// "next" filter, so this reproduces curl's empty-chain send error
    /// ([`Error::Send`], `CURLE_SEND_ERROR`).
    fn send<'a>(
        &'a mut self,
        _cx: &'a mut FilterCtx<'_>,
        buf: &'a [u8],
        eos: bool,
    ) -> CfFuture<'a, Result<usize>> {
        Box::pin(async move {
            match self.winner.as_mut() {
                Some(chain) => chain.send(buf, eos).await,
                None => Err(Error::Send),
            }
        })
    }

    /// Receives from the winning sub-chain. Before a winner exists this
    /// reproduces curl's empty-chain receive error ([`Error::Recv`],
    /// `CURLE_RECV_ERROR`).
    fn recv<'a>(
        &'a mut self,
        _cx: &'a mut FilterCtx<'_>,
        buf: &'a mut [u8],
    ) -> CfFuture<'a, Result<usize>> {
        Box::pin(async move {
            match self.winner.as_mut() {
                Some(chain) => chain.recv(buf).await,
                None => Err(Error::Recv),
            }
        })
    }

    /// Whether buffered data is ready. Delegates to the winner, or unions the
    /// active attempts' pending state pre-winner (curl's
    /// `cf_ip_ballers_pending`, `cf-ip-happy.c:560`).
    fn data_pending(&self, _cx: &QueryCtx<'_>) -> bool {
        if let Some(chain) = self.winner.as_ref() {
            return chain.data_pending();
        }
        self.ballers.as_ref().is_some_and(|bs| {
            bs.running
                .iter()
                .any(|att| att.chain.as_ref().is_some_and(FilterChain::data_pending))
        })
    }

    /// Registers socket-readiness interest. Delegates to the winner, or unions
    /// every active attempt's pollset pre-winner (curl's
    /// `cf_ip_ballers_pollset`, `cf-ip-happy.c:548`).
    fn adjust_pollset(&self, _cx: &QueryCtx<'_>, ps: &mut Pollset) {
        if let Some(chain) = self.winner.as_ref() {
            chain.adjust_pollset(ps);
            return;
        }
        if let Some(bs) = self.ballers.as_ref() {
            for att in &bs.running {
                if let Some(chain) = att.chain.as_ref() {
                    chain.adjust_pollset(ps);
                }
            }
        }
    }

    /// Connection liveness — meaningful only once a winner exists.
    fn is_alive(&mut self, _cx: &mut FilterCtx<'_>) -> bool {
        self.winner.as_mut().is_some_and(FilterChain::is_alive)
    }

    /// Periodic keep-alive — delegated to the winner when present.
    fn keep_alive(&mut self, _cx: &mut FilterCtx<'_>) -> Result<()> {
        match self.winner.as_mut() {
            Some(chain) => chain.keep_alive(),
            None => Ok(()),
        }
    }

    /// Forwards a control event to **every** filter of the winning sub-chain
    /// (via [`FilterChain::cntrl_all`]). This is how `CF_CTRL_CONN_INFO_UPDATE`
    /// (which activates the winning socket) and the other `CF_CTRL_*` events
    /// reach the winner, since it lives in a nested chain the outer driver does
    /// not descend into.
    fn cntrl(
        &mut self,
        _cx: &mut FilterCtx<'_>,
        event: i32,
        arg1: i32,
        arg2: Option<&mut dyn Any>,
    ) -> Result<()> {
        match self.winner.as_mut() {
            Some(chain) => chain.cntrl_all(event, arg1, arg2),
            None => Ok(()),
        }
    }

    /// Answers a connection property query. After a winner is chosen every query
    /// is delegated to it. Before that, the timing queries are aggregated across
    /// the racing attempts, mirroring curl's `cf_ip_happy_query`
    /// (`cf-ip-happy.c:855`): the *minimum* reply time
    /// (`cf_ip_ballers_min_reply_ms`) and the *maximum* connect/appconnect
    /// instant (`cf_ip_ballers_max_time`). All other queries fall through to the
    /// chain default.
    fn query(&self, cx: &QueryCtx<'_>, query: CfQuery, out: &mut QueryOut) -> Result<()> {
        if let Some(chain) = self.winner.as_ref() {
            return chain.query(query, out);
        }

        match query {
            CfQuery::ConnectReplyMs => {
                let mut best: Option<i64> = None;
                if let Some(bs) = self.ballers.as_ref() {
                    for att in &bs.running {
                        if let Some(chain) = att.chain.as_ref() {
                            let mut sub = QueryOut::None;
                            if chain.query(CfQuery::ConnectReplyMs, &mut sub).is_ok() {
                                if let QueryOut::ConnectReplyMs(ms) = sub {
                                    if ms >= 0 {
                                        best = Some(best.map_or(ms, |b| b.min(ms)));
                                    }
                                }
                            }
                        }
                    }
                }
                *out = QueryOut::ConnectReplyMs(best.unwrap_or(-1));
                Ok(())
            }
            CfQuery::TimerConnect | CfQuery::TimerAppConnect => {
                let mut best: Option<Instant> = None;
                if let Some(bs) = self.ballers.as_ref() {
                    for att in &bs.running {
                        if let Some(chain) = att.chain.as_ref() {
                            let mut sub = QueryOut::None;
                            if chain.query(query, &mut sub).is_ok() {
                                match sub {
                                    QueryOut::TimerConnect(t) | QueryOut::TimerAppConnect(t) => {
                                        best = Some(best.map_or(t, |b| b.max(t)));
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                match best {
                    Some(t) if matches!(query, CfQuery::TimerAppConnect) => {
                        *out = QueryOut::TimerAppConnect(t);
                        Ok(())
                    }
                    Some(t) => {
                        *out = QueryOut::TimerConnect(t);
                        Ok(())
                    }
                    None => cx.query_next(query, out),
                }
            }
            _ => cx.query_next(query, out),
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// A loopback IPv4 `SocketAddr` on `port`.
    fn v4(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
    }

    /// A loopback IPv6 `SocketAddr` on `port`.
    fn v6(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port)
    }

    // --- Test doubles -----------------------------------------------------
    //
    // The ports below select a fake socket-filter behaviour, mirroring curl's
    // `UNITTESTS` transport-provider override: the test `cf_create` inspects the
    // address it is handed and returns a mock filter instead of touching the
    // network.

    const FAST_PORT: u16 = 1; // connects immediately
    const HANG_PORT: u16 = 2; // never completes (a "black hole")
    const REFUSE_PORT: u16 = 3; // fails immediately (connection refused)

    #[derive(Clone, Copy)]
    enum FakeKind {
        Fast,
        Hang,
        Refuse,
    }

    /// A mock socket filter whose connect behaviour is chosen by [`FakeKind`].
    /// `send`/`recv` return recognisable values so winner delegation can be
    /// asserted.
    struct FakeSocket {
        kind: FakeKind,
    }

    impl ConnectionFilter for FakeSocket {
        fn name(&self) -> &'static str {
            "FAKE-SOCKET"
        }

        fn cf_type(&self) -> CfType {
            CfType::IP_CONNECT
        }

        fn connect<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            _blocking: bool,
        ) -> CfFuture<'a, Result<bool>> {
            let kind = self.kind;
            Box::pin(async move {
                match kind {
                    FakeKind::Fast => Ok(true),
                    FakeKind::Hang => {
                        // A black hole: sleep far longer than any test runs; the
                        // future is dropped (cancelled) when a winner is chosen.
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        Ok(true)
                    }
                    FakeKind::Refuse => Err(Error::connect("fake: connection refused")),
                }
            })
        }

        fn send<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            buf: &'a [u8],
            _eos: bool,
        ) -> CfFuture<'a, Result<usize>> {
            // Delegation marker: report all bytes "written".
            let n = buf.len();
            Box::pin(async move { Ok(n) })
        }

        fn recv<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            buf: &'a mut [u8],
        ) -> CfFuture<'a, Result<usize>> {
            // Delegation marker: yield a single recognisable byte.
            Box::pin(async move {
                if buf.is_empty() {
                    Ok(0)
                } else {
                    buf[0] = 0xAB;
                    Ok(1)
                }
            })
        }
    }

    /// The test `cf_create`: picks a [`FakeSocket`] behaviour from the port.
    fn fake_cf_create(
        addr: socket::SockAddrEx,
        _transport: Transport,
    ) -> Box<dyn ConnectionFilter> {
        let port = addr.as_inet().map_or(0, |s| s.port());
        let kind = match port {
            FAST_PORT => FakeKind::Fast,
            HANG_PORT => FakeKind::Hang,
            _ => FakeKind::Refuse,
        };
        Box::new(FakeSocket { kind })
    }

    // --- Constant & descriptor parity ------------------------------------

    #[test]
    fn constants_match_curl() {
        // CURL_HET_DEFAULT (include/curl/curl.h:967) and the DNS phase timeout.
        assert_eq!(CURL_HET_DEFAULT_MS, 200);
        assert_eq!(EXPIRE_HAPPY_EYEBALLS_DNS_MS, 5000);
        // Interleaving seed: v6 must be tried first.
        assert_ne!(AF_INET, AF_INET6);
    }

    #[test]
    fn filter_name_and_type_match_curl() {
        let cf = HappyEyeballsFilter::new(Transport::Tcp);
        assert_eq!(cf.name(), "HAPPY-EYEBALLS");
        // curl's Curl_cft_ip_happy declares flags = 0.
        assert_eq!(cf.cf_type().bits(), 0);
    }

    #[test]
    fn family_of_classifies_addresses() {
        assert_eq!(family_of(&v4(80)), AF_INET);
        assert_eq!(family_of(&v6(80)), AF_INET6);
    }

    // --- Family interleaving (RFC 8305 alternation) ----------------------

    #[test]
    fn family_interleaving_prefers_v6_then_alternates() {
        // Given [v6a, v4a, v6b, v4b] and the mandated seed
        // last_attempt_ai_family = AF_INET, selection must yield v6, v4, v6, v4.
        let addrs = vec![v6(10), v4(20), v6(30), v4(40)];
        let mut bs = IpBallers::init(
            &addrs,
            dns::IpVersion::Whatever,
            default_cf_create,
            CURL_HET_DEFAULT_MS,
            Transport::Tcp,
        );
        assert_eq!(bs.last_attempt_ai_family, AF_INET, "seed must be AF_INET");

        let (a1, f1) = bs.next_interleaved().expect("1st");
        assert_eq!((a1, f1), (v6(10), AF_INET6), "first attempt must be IPv6");
        let (a2, f2) = bs.next_interleaved().expect("2nd");
        assert_eq!((a2, f2), (v4(20), AF_INET), "second attempt must be IPv4");
        let (a3, f3) = bs.next_interleaved().expect("3rd");
        assert_eq!((a3, f3), (v6(30), AF_INET6), "third attempt must be IPv6");
        let (a4, f4) = bs.next_interleaved().expect("4th");
        assert_eq!((a4, f4), (v4(40), AF_INET), "fourth attempt must be IPv4");
        assert!(bs.next_interleaved().is_none(), "list must be exhausted");
    }

    #[test]
    fn family_interleaving_drains_remaining_family() {
        // Only IPv6 addresses: after the first (v6) pick, the v4 iterator is
        // empty so the balancer keeps draining v6 rather than stalling.
        let addrs = vec![v6(10), v6(20)];
        let mut bs = IpBallers::init(
            &addrs,
            dns::IpVersion::Whatever,
            default_cf_create,
            CURL_HET_DEFAULT_MS,
            Transport::Tcp,
        );
        assert_eq!(bs.next_interleaved().map(|(_, f)| f), Some(AF_INET6));
        assert_eq!(bs.next_interleaved().map(|(_, f)| f), Some(AF_INET6));
        assert!(bs.next_interleaved().is_none());
    }

    #[test]
    fn ipv4_restriction_omits_ipv6_iterator() {
        // A V4-pinned resolve drops IPv6 candidates entirely.
        let addrs = vec![v6(10), v4(20)];
        let mut bs = IpBallers::init(
            &addrs,
            dns::IpVersion::V4,
            default_cf_create,
            CURL_HET_DEFAULT_MS,
            Transport::Tcp,
        );
        assert!(bs.ipv6_iter.is_none());
        assert_eq!(bs.next_interleaved(), Some((v4(20), AF_INET)));
        assert!(bs.next_interleaved().is_none());
    }

    // --- Staggered start (200 ms) decision, tested deterministically ------

    #[test]
    fn staggered_start_holds_second_attempt_until_delay() {
        let delay = CURL_HET_DEFAULT_MS; // 200
                                         // Nothing in flight: always start (first attempt / retry after all fail).
        assert!(should_start_new_attempt(0, false, 0, delay));
        assert!(should_start_new_attempt(0, true, 0, delay));
        // One attempt in flight, another address available: a SECOND attempt is
        // NOT started before 200 ms has elapsed...
        assert!(!should_start_new_attempt(1, true, 0, delay));
        assert!(!should_start_new_attempt(1, true, 199, delay));
        // ...and IS started at/after 200 ms.
        assert!(should_start_new_attempt(1, true, 200, delay));
        assert!(should_start_new_attempt(1, true, 250, delay));
        // No further addresses: never start a new attempt (only wait/inconclusive).
        assert!(!should_start_new_attempt(1, false, 5_000, delay));
    }

    // --- Racing behaviour -------------------------------------------------

    /// Builds a chain whose only filter is a Happy-Eyeballs filter using the
    /// fake factory, seeded with `addrs`.
    fn fake_chain(
        addrs: Vec<SocketAddr>,
        attempt_delay_ms: u64,
        overall_timeout_ms: Option<u64>,
    ) -> FilterChain {
        let mut cf = HappyEyeballsFilter::with_dns(Transport::Tcp, addrs, dns::IpVersion::Whatever)
            .with_attempt_delay_ms(attempt_delay_ms)
            .with_cf_create(fake_cf_create);
        if let Some(to) = overall_timeout_ms {
            cf = cf.with_overall_timeout_ms(to);
        }
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(cf));
        chain
    }

    #[tokio::test]
    async fn fast_attempt_wins_and_slow_is_torn_down() {
        // v6 is a black hole started first; v4 connects immediately after the
        // (short) stagger. The fast one must win and become the delegated
        // `next`, while the hanging one is dropped.
        let addrs = vec![v6(HANG_PORT), v4(FAST_PORT)];
        let mut chain = fake_chain(addrs, 20, None);

        let done = tokio::time::timeout(Duration::from_secs(5), chain.connect(false))
            .await
            .expect("race must not hang")
            .expect("connect must succeed");
        assert!(done, "connect must report done");

        // Winner delegation: send/recv flow through to the FakeSocket.
        let n = chain.send(b"hello", false).await.expect("send delegates");
        assert_eq!(n, 5, "send must delegate to the winning sub-chain");
        let mut buf = [0u8; 4];
        let r = chain.recv(&mut buf).await.expect("recv delegates");
        assert_eq!(r, 1);
        assert_eq!(buf[0], 0xAB, "recv must delegate to the winning sub-chain");
    }

    #[tokio::test]
    async fn first_address_wins_immediately() {
        // When the very first (v6) address connects, it wins with no stagger.
        let addrs = vec![v6(FAST_PORT), v4(HANG_PORT)];
        let mut chain = fake_chain(addrs, CURL_HET_DEFAULT_MS, None);
        let done = tokio::time::timeout(Duration::from_secs(5), chain.connect(false))
            .await
            .expect("must not hang")
            .expect("connect must succeed");
        assert!(done);
        assert_eq!(chain.send(b"xyz", true).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn all_addresses_refused_yields_couldnt_connect() {
        // Every candidate refuses -> CURLE_COULDNT_CONNECT (7).
        let addrs = vec![v6(REFUSE_PORT), v4(REFUSE_PORT)];
        let mut chain = fake_chain(addrs, 10, None);
        let err = tokio::time::timeout(Duration::from_secs(5), chain.connect(false))
            .await
            .expect("must not hang")
            .expect_err("connect must fail");
        assert_eq!(err.code(), CurlCode::CouldntConnect);
        assert_eq!(err.code() as i32, 7);
    }

    #[tokio::test]
    async fn no_addresses_yields_couldnt_connect() {
        // An address-less filter cannot connect: exhaustion -> COULDNT_CONNECT.
        let mut chain = fake_chain(Vec::new(), CURL_HET_DEFAULT_MS, None);
        let err = tokio::time::timeout(Duration::from_secs(5), chain.connect(false))
            .await
            .expect("must not hang")
            .expect_err("connect must fail");
        assert_eq!(err.code(), CurlCode::CouldntConnect);
    }

    #[tokio::test]
    async fn overall_deadline_yields_operation_timedout() {
        // Every candidate is a black hole and an overall deadline is set: the
        // race must abort with CURLE_OPERATION_TIMEDOUT (28).
        let addrs = vec![v6(HANG_PORT), v4(HANG_PORT)];
        let mut chain = fake_chain(addrs, 20, Some(40));
        let err = tokio::time::timeout(Duration::from_secs(5), chain.connect(false))
            .await
            .expect("must not hang")
            .expect_err("connect must time out");
        assert_eq!(err.code(), CurlCode::OperationTimedout);
        assert_eq!(err.code() as i32, 28);
    }

    #[tokio::test]
    async fn create_with_dns_builds_usable_filter() {
        // The public boxed constructor produces a working filter (default
        // factory would touch the network, so we only assert it constructs and
        // exposes the right descriptor here).
        let cf = create_with_dns(
            Transport::Tcp,
            vec![v4(FAST_PORT)],
            dns::IpVersion::Whatever,
            CURL_HET_DEFAULT_MS,
            Some(1_000),
        );
        assert_eq!(cf.name(), "HAPPY-EYEBALLS");
        assert_eq!(cf.cf_type().bits(), 0);
    }

    #[test]
    fn insert_after_rejects_out_of_range_index() {
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(socket::tcp_create(
            socket::SockAddrEx::tcp(v4(80)),
            Transport::Tcp,
        ));
        // Index 0 is valid (one filter present); index 5 is out of range.
        assert!(insert_after(&mut chain, 0, Transport::Tcp).is_ok());
        assert!(insert_after(&mut chain, 5, Transport::Tcp).is_err());
    }
}
