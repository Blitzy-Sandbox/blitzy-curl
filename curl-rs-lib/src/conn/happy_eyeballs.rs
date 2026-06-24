//! Happy Eyeballs v2 (RFC 8305) — parallel IPv4/IPv6 connection racing.
//!
//! The Rust rewrite of libcurl's `lib/cf-ip-happy.c`. This filter sits at the
//! **bottom** of the connection-filter chain — the "EYEBALLS" step the SETUP
//! builder (`connect.rs`) inserts first — and is responsible for establishing
//! the underlying transport connection by *racing* several address attempts:
//!
//! 1. It alternates IPv4 and IPv6 candidate addresses (IPv6 first), starting a
//!    new connection attempt roughly every `happy_eyeballs_timeout` ms (the
//!    [`CURL_HET_DEFAULT`] 200 ms stagger by default).
//! 2. The first attempt that connects becomes the **winner**; every other
//!    in-flight attempt is torn down.
//! 3. The winning socket filter is **promoted into this filter's `next` slot**,
//!    so after a successful connect the Happy-Eyeballs filter becomes a thin
//!    pass-through above the live socket.
//!
//! It consumes resolved addresses from [`crate::dns`] (a [`ResolvedAddrs`]) and
//! creates one per-attempt socket filter per candidate address via the
//! constructors in [`crate::conn::socket`]. It never touches the OS socket API
//! itself — that is entirely the socket filter's job.
//!
//! # BOUNDARY #3 — racing lives here, not in `dns/`
//!
//! `dns/mod.rs` resolves names to a flat [`ResolvedAddrs`] and explicitly defers
//! Happy-Eyeballs interleaving / connection ordering to this module
//! (`crate::conn::happy_eyeballs`). The address set arrives here verbatim and is
//! split into IPv4/IPv6 iterators *here*.
//!
//! # The great C → Tokio collapse
//!
//! curl's implementation is a hand-rolled non-blocking state machine: a linked
//! "baller" list ([`struct cf_ip_attempt`]), a `cf_ip_ballers_run` routine built
//! around an `evaluate:` `goto` loop, and an `EXPIRE_HAPPY_EYEBALLS` multi-timer
//! that schedules the next staggered attempt and the next poll. Under Tokio all
//! of that dissolves into three safe primitives:
//!
//! * a [`FuturesUnordered`] of in-flight connect attempts (the "running"
//!   ballers),
//! * a [`tokio::time::sleep`] "start the next attempt" stagger timer, and
//! * a [`tokio::select!`] loop that races attempt completion against the stagger
//!   timer (and an optional overall connect deadline).
//!
//! The single most important consequence: **dropping the [`FuturesUnordered`]
//! cancels every still-pending connect for free**, which is exactly curl's
//! "declare the winner, tear down the losers" behavior — Rust's `Drop` of an
//! in-flight `TcpStream::connect` future closes the half-open socket. The C
//! `EXPIRE_HAPPY_EYEBALLS` timer needs no identifier; it is just the next
//! `sleep(attempt_delay)`.
//!
//! # Memory safety (AAP §0.7.1) — ABSOLUTE
//!
//! This module is `#![forbid(unsafe_code)]`: **zero** `unsafe`, no raw pointers.
//! The C baller list (`a->next` pointers), the manual `evaluate:` `goto`, and
//! the `curlx_calloc`/`curlx_free` lifecycle are all replaced by owned Rust
//! values whose teardown is `Drop`-driven.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};

use crate::conn::filters::{
    BoxFuture, CfState, ConnectionFilter, FilterChain, FilterData, CF_TYPE_IP_CONNECT,
};
use crate::conn::socket::{
    create_tcp_filter, create_udp_filter, BindConfig, SocketOptions, TRNSPRT_QUIC, TRNSPRT_TCP,
    TRNSPRT_UDP, TRNSPRT_UNIX,
};
use crate::dns::{IpVersion, ResolvedAddrs};
use crate::error::{CurlError, Result};
use crate::util::timediff::ms_to_duration;
use crate::util::timeval::{curlx_now, curlx_ptimediff_ms, CurlTime};

// The UNIX-domain transport is `cfg(unix)`-only (it needs `tokio::net::UnixStream`
// behind `crate::conn::socket::create_unix_filter`). The AAP build matrix is
// Linux + macOS, both UNIX, so this is always available on the supported targets.
#[cfg(unix)]
use crate::conn::socket::{create_unix_filter, UnixTarget};

// =============================================================================
// Constants — C: `include/curl/curl.h` + `lib/cf-ip-happy.c`
// =============================================================================

/// The default Happy-Eyeballs staggered-attempt delay, in milliseconds — curl's
/// `CURL_HET_DEFAULT` (`include/curl/curl.h`: `#define CURL_HET_DEFAULT 200L`).
///
/// This is the delay between starting one connection attempt and starting the
/// next when the first has not yet connected. The effective value comes from the
/// easy-handle option `CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS`
/// (`data.set.happy_eyeballs_timeout`), which defaults to this constant; the
/// filter accepts it as the `happy_eyeballs_timeout` constructor parameter.
pub const CURL_HET_DEFAULT: i64 = 200;

// =============================================================================
// Address family — the safe stand-in for C's `ai_family` (`AF_INET`/`AF_INET6`)
// =============================================================================

/// Which IP address family a candidate / attempt belongs to.
///
/// curl tracks this as the integer `ai_family` (`AF_INET` / `AF_INET6`) on each
/// attempt and on the ballers' `last_attempt_ai_family`. Here it is a small,
/// `Copy` enum: only the *relative* family of successive attempts matters (for
/// the IPv4/IPv6 alternation), never the OS-specific numeric `AF_*` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddrFamily {
    /// IPv4 (C: `AF_INET`).
    V4,
    /// IPv6 (C: `AF_INET6`).
    V6,
}

// =============================================================================
// PHASE 1 — dual-family address iteration (C: `cf_ai_iter*`, L108-157, and the
//           per-family iterators set up in `cf_ip_ballers_init`, L307-343).
// =============================================================================

/// The dual-family candidate-address iterator — the safe rewrite of C's pair of
/// `struct cf_ai_iter` (the IPv4 `addr_iter` and the IPv6 `ipv6_iter`) plus the
/// `last_attempt_ai_family` alternation state.
///
/// Where curl walks a single `Curl_addrinfo` linked list twice (once per family,
/// skipping the other family's nodes), this pre-splits the flat
/// [`ResolvedAddrs`] into one [`Vec`] per family and advances a cursor into each.
/// The split honors the [`IpVersion`] preference exactly as
/// `cf_ip_ballers_init` does:
///
/// * [`IpVersion::V6`] — the IPv4 list is initialized empty (C: `cf_ai_iter_init(
///   &addr_iter, NULL, AF_INET)`), so only IPv6 is tried.
/// * [`IpVersion::V4`] — the IPv6 list is initialized empty, so only IPv4.
/// * [`IpVersion::Any`] — both families are populated and alternated.
///
/// The alternation is seeded with `last_family = V4` so that the **first**
/// attempt prefers IPv6 when available — preserving curl's exact
/// `bs->last_attempt_ai_family = AF_INET; /* so AF_INET6 is next */` (L317).
struct AddrPicker {
    /// Remaining IPv4 candidates (empty when `ip_version == V6`).
    v4: Vec<SocketAddr>,
    /// Remaining IPv6 candidates (empty when `ip_version == V4`).
    v6: Vec<SocketAddr>,
    /// Cursor into [`v4`](Self::v4).
    i4: usize,
    /// Cursor into [`v6`](Self::v6).
    i6: usize,
    /// The family of the most recently *started* attempt. Initialized to
    /// [`AddrFamily::V4`] so the first [`next`](Self::next) prefers IPv6
    /// (C L317).
    last_family: AddrFamily,
}

impl AddrPicker {
    /// Split `addrs` into per-family cursors, honoring the [`IpVersion`]
    /// preference (C: `cf_ip_ballers_init`, L307-343).
    fn new(addrs: &ResolvedAddrs, ip_version: IpVersion) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for addr in &addrs.addrs {
            match addr {
                // IPv4 candidate: kept unless the caller restricted to V6.
                SocketAddr::V4(_) if ip_version != IpVersion::V6 => v4.push(*addr),
                // IPv6 candidate: kept unless the caller restricted to V4.
                SocketAddr::V6(_) if ip_version != IpVersion::V4 => v6.push(*addr),
                // Wrong family for the requested `ip_version`: dropped, exactly
                // as curl initializes the unwanted iterator with a NULL list.
                _ => {}
            }
        }
        Self {
            v4,
            v6,
            i4: 0,
            i6: 0,
            last_family: AddrFamily::V4,
        }
    }

    /// Whether another IPv4 candidate remains (C: `cf_ai_iter_has_more` on the
    /// IPv4 iterator).
    fn has_more_v4(&self) -> bool {
        self.i4 < self.v4.len()
    }

    /// Whether another IPv6 candidate remains (C: `cf_ai_iter_has_more` on the
    /// IPv6 iterator).
    fn has_more_v6(&self) -> bool {
        self.i6 < self.v6.len()
    }

    /// Whether any candidate of either family remains untried.
    fn has_more(&self) -> bool {
        self.has_more_v4() || self.has_more_v6()
    }

    /// The next candidate to attempt, alternating address families — the exact
    /// rewrite of the family-selection block in `cf_ip_ballers_run` (L417-429).
    ///
    /// The C logic: try the next IPv6 address when the last attempt was IPv4
    /// **or** no IPv4 candidates remain; otherwise (and when IPv6 is exhausted)
    /// try the next IPv4 address. Seeded with `last_family == V4`, the first call
    /// therefore yields IPv6 when present, then the families alternate, and once
    /// one family is exhausted the other is drained.
    fn next(&mut self) -> Option<(SocketAddr, AddrFamily)> {
        // Prefer IPv6 when the previous attempt was IPv4, or IPv4 is exhausted
        // (C L420-421: `last_attempt_ai_family == AF_INET || !has_more(addr_iter)`).
        if (self.last_family == AddrFamily::V4 || !self.has_more_v4()) && self.has_more_v6() {
            let addr = self.v6[self.i6];
            self.i6 += 1;
            self.last_family = AddrFamily::V6;
            return Some((addr, AddrFamily::V6));
        }
        // Otherwise take the next IPv4 candidate (C L426-429: the `if(!addr)`
        // fallback to `addr_iter`).
        if self.has_more_v4() {
            let addr = self.v4[self.i4];
            self.i4 += 1;
            self.last_family = AddrFamily::V4;
            return Some((addr, AddrFamily::V4));
        }
        None
    }
}

// =============================================================================
// PHASE 2 — the per-attempt "baller" (C: `struct cf_ip_attempt` + the transport
//           → constructor mapping `transport_providers` / `get_cf_create`,
//           L61-93, including the `Curl_debug_set_transport_provider` unit-test
//           hook, L93-106).
// =============================================================================

/// A boxed, `Send` socket-filter factory keyed by one candidate address.
///
/// This is the [`crate::conn::socket`] constructor a [`HappyEyeballsFilter`]
/// uses to build a fresh socket filter for each attempt — the safe analog of
/// the C `cf_ip_connect_create *cf_create` function pointer selected by
/// `get_cf_create(transport)`. The production variants ([`CfCreate::Tcp`] /
/// [`CfCreate::Udp`]) carry the per-connection socket options/binding so each
/// attempt is configured identically.
///
/// The `#[cfg(test)]` [`CfCreate::Custom`] variant is the safe equivalent of
/// curl's `Curl_debug_set_transport_provider` test hook: it injects an arbitrary
/// filter factory so the racing engine can be driven with deterministic mock
/// connects (controlled delays, success/failure) without any real network I/O.
/// A test-only socket-filter factory: address → boxed mock filter (the safe
/// analog of curl's `Curl_debug_set_transport_provider`). Factored into a type
/// alias to keep the field/variant/parameter types within
/// `clippy::type_complexity` limits.
#[cfg(test)]
type CustomCreateFn = std::sync::Arc<dyn Fn(SocketAddr) -> Box<dyn ConnectionFilter> + Send + Sync>;

#[derive(Clone)]
enum CfCreate {
    /// Build a TCP socket filter (C: `Curl_cf_tcp_create`).
    Tcp {
        /// `TCP_NODELAY` / keepalive settings applied at connect.
        opts: SocketOptions,
        /// `CURLOPT_INTERFACE` / `LOCALPORT` binding applied before connect.
        bind: BindConfig,
    },
    /// Build a UDP or QUIC datagram socket filter (C: `Curl_cf_udp_create` /
    /// `Curl_cf_quic_create`); `transport` is [`TRNSPRT_UDP`] or [`TRNSPRT_QUIC`].
    Udp {
        /// The datagram transport ([`TRNSPRT_UDP`] or [`TRNSPRT_QUIC`]).
        transport: u8,
        /// Local-port binding applied before connect.
        bind: BindConfig,
    },
    /// A test-only injected filter factory (mirrors
    /// `Curl_debug_set_transport_provider`).
    #[cfg(test)]
    Custom(CustomCreateFn),
}

impl CfCreate {
    /// Materialize a socket filter for `addr` (C: `a->cf_create(&a->cf, ...,
    /// a->addr, transport)` in `cf_ip_attempt_new`, L209).
    fn make(&self, addr: SocketAddr) -> Box<dyn ConnectionFilter> {
        match self {
            CfCreate::Tcp { opts, bind } => create_tcp_filter(addr, opts.clone(), bind.clone()),
            CfCreate::Udp { transport, bind } => create_udp_filter(addr, *transport, bind.clone()),
            #[cfg(test)]
            CfCreate::Custom(factory) => factory(addr),
        }
    }
}

/// The result of one connection attempt — the value a running "baller" future
/// resolves to.
///
/// In C the attempt's outcome lives in mutable fields of `struct cf_ip_attempt`
/// (`result`, `connected`, `inconclusive`) read back by `cf_ip_ballers_run`.
/// Here the attempt is a self-contained future that **owns** its socket filter
/// and, on completion, hands the filter back inside this struct: a successful
/// attempt's [`filter`](Self::filter) is promoted as the winner, while a failed
/// one is dropped (closing its socket). Moving the filter out is sound because
/// the borrow taken by `filter.connect(..)` has already ended by the time the
/// future resolves.
struct AttemptOutcome {
    /// The socket filter that ran this attempt, handed back for promotion (on
    /// success) or teardown (on failure / when dropped as a loser).
    filter: Box<dyn ConnectionFilter>,
    /// The connect result: `Ok(())` ⇒ this attempt is the winner.
    result: Result<()>,
    /// The candidate address this attempt targeted (used to re-create an
    /// inconclusive attempt on restart).
    addr: SocketAddr,
    /// The attempt's address family (carried for restart bookkeeping).
    family: AddrFamily,
}

/// A pinned, boxed, `Send` in-flight connection attempt — one entry in the
/// [`FuturesUnordered`] "running" set (the safe replacement for a node of curl's
/// `bs->running` baller list).
type AttemptFut = Pin<Box<dyn Future<Output = AttemptOutcome> + Send>>;

/// Wrap a freshly-created socket filter as an in-flight connect attempt
/// (C: `cf_ip_attempt_new` + the first `cf_ip_attempt_connect`, L185-245).
///
/// The returned future **owns** `filter` and a private [`FilterData`]; it awaits
/// the filter's `connect`, then yields the filter back in an [`AttemptOutcome`].
/// Because the future owns the filter, several attempts run concurrently in a
/// [`FuturesUnordered`] without aliasing, and dropping the set cancels each
/// pending `connect` (closing its socket) — curl's "tear down the losers".
fn spawn_attempt(
    mut filter: Box<dyn ConnectionFilter>,
    verbose: bool,
    addr: SocketAddr,
    family: AddrFamily,
) -> AttemptFut {
    Box::pin(async move {
        // Each attempt carries its own diagnostics context; the racing engine
        // merges nothing back from losers (curl resets the error buffer on win).
        let mut fdata = FilterData::with_verbose(verbose);
        let result = filter.connect(&mut fdata).await;
        AttemptOutcome {
            filter,
            result,
            addr,
            family,
        }
    })
}

// =============================================================================
// The Happy-Eyeballs connection filter — C: `struct cf_ip_happy_ctx`
//           (+ `struct Curl_cfilter`), the `Curl_cft_ip_happy` vtable (L903),
//           and `cf_ip_happy_*` callbacks.
// =============================================================================

/// The Happy-Eyeballs connection filter.
///
/// This is the Rust home of curl's `struct cf_ip_happy_ctx` together with the
/// per-instance state of its `struct Curl_cfilter`. It stores the transport, the
/// IP-version preference, the staggered-attempt delay, the resolved candidate
/// addresses, and the socket-filter configuration — everything needed to
/// (re-)run the race on [`connect`](ConnectionFilter::connect).
///
/// Unlike the C `cf_ip_ballers`, **no per-attempt "baller list" is stored on the
/// struct**: the in-flight attempts live only inside the `connect` future (in a
/// [`FuturesUnordered`]) and are torn down when that future resolves or is
/// dropped. Consequently the address-iteration cursors are rebuilt fresh on each
/// `connect` (from [`addrs`](Self::addrs)), so a `close` → `connect` cycle
/// re-runs cleanly, matching curl re-initializing its iterators in
/// `start_connect` (L698).
///
/// After a successful connect the winning socket filter is promoted into
/// [`CfState::next`], so this filter becomes a transparent pass-through above the
/// live socket and every delegating vtable method (`send`/`recv`/`query`/…)
/// reaches the winner through the default [`ConnectionFilter`] behavior.
pub struct HappyEyeballsFilter {
    /// Chain link (`next`) + `connected`/`shutdown` bits (C: the per-instance
    /// fields of `struct Curl_cfilter`). After a win, `next` holds the promoted
    /// winning socket filter.
    state: CfState,
    /// The transport to connect (`TRNSPRT_*`); C: `cf_ip_happy_ctx.transport`.
    transport: u8,
    /// IP-version preference honored when splitting candidates by family
    /// (C: `conn->ip_version`).
    ip_version: IpVersion,
    /// Staggered-attempt delay in ms (C: `bs->attempt_delay_ms`, from
    /// `data.set.happy_eyeballs_timeout`); defaults to [`CURL_HET_DEFAULT`].
    attempt_delay_ms: i64,
    /// Optional overall connect deadline in ms. When `None`, the racing engine
    /// imposes no internal limit and relies on the chain-level connect timeout
    /// ([`FilterChain::connect`]'s wrapper). When `Some`, the race itself returns
    /// [`CurlError::OperationTimedout`] on expiry (C: `Curl_timeleft_ms`).
    connect_timeout_ms: Option<i64>,
    /// The resolved candidate addresses (C: `dns->addr`). Re-split into
    /// per-family cursors on each connect.
    addrs: ResolvedAddrs,
    /// The UNIX-domain destination for `TRNSPRT_UNIX` (C: the `AF_UNIX` addrinfo).
    /// `None` for IP transports.
    #[cfg(unix)]
    unix_target: Option<UnixTarget>,
    /// `TCP_NODELAY` / keepalive options applied to TCP attempts (C: `data->set`
    /// slices read by the socket filter).
    socket_options: SocketOptions,
    /// `CURLOPT_INTERFACE` / `LOCALPORT` binding applied to attempts.
    bind_config: BindConfig,
    /// Test-only injected socket-filter factory (the safe analog of
    /// `Curl_debug_set_transport_provider`). Production builds always use the
    /// real [`crate::conn::socket`] constructors.
    #[cfg(test)]
    custom_create: Option<CustomCreateFn>,
    /// Count of connections successfully made by this filter — the safe local
    /// stand-in for curl's `data->info.numconnects++` (L818). The chain driver
    /// (`mod.rs`), which owns the easy handle, reads it via
    /// [`connections_made`](Self::connections_made) to bump the public info.
    connections_made: u64,
}

impl HappyEyeballsFilter {
    /// Assemble the per-attempt socket-filter factory (C: `get_cf_create`,
    /// L83-91 — select the `cf_create` for the transport). The `#[cfg(test)]`
    /// injected factory takes precedence when present.
    fn cf_create(&self) -> CfCreate {
        #[cfg(test)]
        if let Some(factory) = &self.custom_create {
            return CfCreate::Custom(factory.clone());
        }
        match self.transport {
            TRNSPRT_UDP | TRNSPRT_QUIC => CfCreate::Udp {
                transport: self.transport,
                bind: self.bind_config.clone(),
            },
            // TCP (and any unspecified IP transport) use the TCP constructor.
            _ => CfCreate::Tcp {
                opts: self.socket_options.clone(),
                bind: self.bind_config.clone(),
            },
        }
    }

    /// The number of connections this filter has successfully established
    /// (curl's `data->info.numconnects` contribution, L818).
    #[must_use]
    pub fn connections_made(&self) -> u64 {
        self.connections_made
    }

    /// Run a single UNIX-domain connect attempt — C: the `TRNSPRT_UNIX` branch of
    /// `cf_ip_ballers_init` (L319-325) which builds a single-address `AF_UNIX`
    /// iterator. There is no family alternation and no racing: a UNIX path has
    /// exactly one candidate, so this is one attempt.
    //
    // Takes `&mut self` (rather than `&self`) so the returned future captures a
    // `&mut HappyEyeballsFilter`, which is `Send` whenever the filter is `Send`.
    // A `&self` capture would instead require the filter to be `Sync`, which it
    // is not (`Box<dyn ConnectionFilter>` is `Send` but not `Sync`), making the
    // `connect` future non-`Send` and violating the [`ConnectionFilter`]
    // contract.
    #[cfg(unix)]
    async fn run_unix(&mut self, data: &mut FilterData) -> Result<Box<dyn ConnectionFilter>> {
        let Some(target) = self.unix_target.clone() else {
            data.error_buffer =
                Some("no UNIX domain socket path configured for happy-eyeballs".to_string());
            return Err(CurlError::CouldntConnect);
        };
        let mut filter = create_unix_filter(target);
        filter.connect(data).await?;
        Ok(filter)
    }

    /// Run the Happy-Eyeballs race to completion and return the winning socket
    /// filter — the heart of the algorithm (C: `cf_ip_ballers_run`, L345-535).
    ///
    /// Reproduces the v2 semantics exactly, but with Tokio primitives instead of
    /// the C baller list + `evaluate:` `goto` + `EXPIRE_HAPPY_EYEBALLS` timer:
    ///
    /// 1. The first attempt starts immediately; each subsequent attempt starts
    ///    after the `attempt_delay_ms` stagger (C: `!ongoing` ⇒ start now, else
    ///    start only once `elapsed >= attempt_delay`).
    /// 2. Address families alternate, IPv6 first (via [`AddrPicker`]).
    /// 3. The first attempt to connect wins; returning drops the
    ///    [`FuturesUnordered`], which cancels every other in-flight connect — the
    ///    losers are torn down for free.
    /// 4. A soft (`WeirdServerReply`) failure makes an address eligible for one
    ///    restart after the delay (C: `cf_ip_attempt_restart`, L262).
    /// 5. An optional overall deadline yields [`CurlError::OperationTimedout`];
    ///    exhausting every address with no success yields
    ///    [`CurlError::CouldntConnect`].
    async fn run_race(&mut self, data: &mut FilterData) -> Result<Box<dyn ConnectionFilter>> {
        // ---- UNIX: a single attempt, no family alternation ----
        #[cfg(unix)]
        if self.transport == TRNSPRT_UNIX {
            return self.run_unix(data).await;
        }
        #[cfg(not(unix))]
        if self.transport == TRNSPRT_UNIX {
            data.error_buffer =
                Some("UNIX domain sockets are not supported on this platform".to_string());
            return Err(CurlError::CouldntConnect);
        }

        // ---- snapshot config into owned locals (the loop never touches `self`,
        //      so nothing of `self` is borrowed across an `.await`) ----
        let verbose = data.verbose;
        let attempt_delay_ms = self.attempt_delay_ms;
        let cf_create = self.cf_create();
        let make_filter = move |addr: SocketAddr| cf_create.make(addr);
        let mut picker = AddrPicker::new(&self.addrs, self.ip_version);

        // Optional overall connect deadline, anchored at race start.
        let deadline: Option<tokio::time::Instant> = self
            .connect_timeout_ms
            .map(|ms| tokio::time::Instant::now() + ms_to_duration(ms));

        // In-flight attempts ("running" ballers), the soft-failure restart queue,
        // and the alternation/stagger bookkeeping.
        let mut running: FuturesUnordered<AttemptFut> = FuturesUnordered::new();
        let mut inconclusive: VecDeque<(SocketAddr, AddrFamily)> = VecDeque::new();
        let mut attempts_started: usize = 0;
        let mut last_started: Option<CurlTime> = None;
        let mut last_err: Option<CurlError> = None;

        loop {
            // (a) Overall deadline guard (C: `Curl_timeleft_ms < 0`, L505-509).
            if let Some(dl) = deadline {
                if tokio::time::Instant::now() >= dl {
                    data.error_buffer = Some("Connection timed out".to_string());
                    return Err(CurlError::OperationTimedout);
                }
            }

            let has_new = picker.has_more();
            let want_start = has_new || !inconclusive.is_empty();

            // (b) Nothing in flight and nothing left to start ⇒ all attempts
            //     failed (C L486-496: `CURLE_COULDNT_CONNECT`, or the last
            //     attempt's hard-failure code).
            if running.is_empty() && !want_start {
                data.error_buffer = Some(format!(
                    "Failed to connect: all {attempts_started} address attempt(s) failed"
                ));
                return Err(last_err.unwrap_or(CurlError::CouldntConnect));
            }

            // (c) Fast path — nothing in flight and a *new* candidate available:
            //     start it immediately, no stagger (C L395-399: `!ongoing` ⇒
            //     `do_more = TRUE`).
            if running.is_empty() && has_new {
                if let Some((addr, family)) = picker.next() {
                    running.push(spawn_attempt(make_filter(addr), verbose, addr, family));
                    attempts_started += 1;
                    last_started = Some(curlx_now());
                }
                continue;
            }

            // (d) Time until the next attempt may start: the staggered delay
            //     `max(attempt_delay - elapsed_since_last_attempt, 0)` (C L406-408
            //     and L517-529).
            let start_delay = match last_started {
                Some(ls) => {
                    let elapsed = curlx_ptimediff_ms(&curlx_now(), &ls);
                    ms_to_duration((attempt_delay_ms - elapsed).max(0))
                }
                None => Duration::ZERO,
            };

            // A concrete Instant for the deadline branch; a far-future placeholder
            // keeps `sleep_until` well-formed when the branch is gated off.
            let deadline_set = deadline.is_some();
            let dl_instant = deadline
                .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(86_400));

            tokio::select! {
                biased;

                // (1) Overall connect timeout fired.
                () = tokio::time::sleep_until(dl_instant), if deadline_set => {
                    data.error_buffer = Some("Connection timed out".to_string());
                    return Err(CurlError::OperationTimedout);
                }

                // (2) A running attempt completed. The first success is the
                //     winner; remaining attempts are dropped at return, cancelling
                //     their in-flight connects (C L369-383).
                maybe = running.next(), if !running.is_empty() => {
                    if let Some(outcome) = maybe {
                        match outcome.result {
                            // Winner. Returning drops `running`, cancelling every
                            // other in-flight connect (the losers) (C L369-383).
                            Ok(()) => return Ok(outcome.filter),
                            // Soft failure: peer may be a restarting server ⇒
                            // eligible for one restart (C L241-242 / L262).
                            Err(CurlError::WeirdServerReply) => {
                                inconclusive.push_back((outcome.addr, outcome.family));
                                last_err = Some(CurlError::WeirdServerReply);
                            }
                            // Hard failure: remember the code, drop the filter
                            // (C records `a->result`, L491-495).
                            Err(other) => last_err = Some(other),
                        }
                    }
                }

                // (3) Stagger expired ⇒ start the next attempt: a fresh candidate
                //     (C L435-453) or, when none remain, restart an inconclusive
                //     one (C L455-481).
                () = tokio::time::sleep(start_delay), if want_start => {
                    if let Some((addr, family)) = picker.next() {
                        running.push(spawn_attempt(make_filter(addr), verbose, addr, family));
                        attempts_started += 1;
                        last_started = Some(curlx_now());
                    } else if let Some((addr, family)) = inconclusive.pop_front() {
                        // No fresh candidates remain: restart an inconclusive one.
                        running.push(spawn_attempt(make_filter(addr), verbose, addr, family));
                        attempts_started += 1;
                        last_started = Some(curlx_now());
                    }
                }
            }
        }
    }
}

// =============================================================================
// PHASE 4 + PHASE 5 — the `ConnectionFilter` vtable (C: `Curl_cft_ip_happy`,
//           L903-929, plus the `cf_ip_happy_*` callbacks).
//
// Only `name`/`cf_state`/`cf_state_mut`/`flags`/`connect`/`close` are overridden.
// Every other method (`send`/`recv`/`shutdown`/`data_pending`/`query`/`cntrl`/
// `is_alive`/`keep_alive`) uses the delegating `ConnectionFilter` default, which
// forwards to `cf_state().next` — i.e. to the **promoted winner** once a connect
// has succeeded. That is exactly curl's post-win behavior, where this filter is a
// thin pass-through above the winning socket filter. `adjust_pollset`
// (cf-ip-happy.c L748) is intentionally OMITTED: the Tokio reactor drives
// per-attempt socket readiness, so there is no fd-set for the caller to poll.
// =============================================================================

impl ConnectionFilter for HappyEyeballsFilter {
    /// C: `cft->name = "HAPPY-EYEBALLS"` (L905).
    fn name(&self) -> &'static str {
        "HAPPY-EYEBALLS"
    }

    fn cf_state(&self) -> &CfState {
        &self.state
    }

    fn cf_state_mut(&mut self) -> &mut CfState {
        &mut self.state
    }

    /// C: `cft->flags = CF_TYPE_IP_CONNECT` (L906) — this filter establishes the
    /// underlying IP connection.
    fn flags(&self) -> u32 {
        CF_TYPE_IP_CONNECT
    }

    /// Establish the transport by racing the candidate addresses, then promote
    /// the winner — C: `cf_ip_happy_connect` (L762-826).
    ///
    /// The C re-entrant state machine (`SCFST_INIT` → `SCFST_WAITING` →
    /// `SCFST_DONE`, driven by repeated `do_connect` calls until `*done`)
    /// collapses into a single `run_race(..).await`: the future resolves exactly
    /// when curl would have set `*done = TRUE`.
    fn connect<'a>(&'a mut self, data: &'a mut FilterData) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // SCFST_DONE short-circuit (L772-775): already connected.
            if self.state.connected {
                return Ok(());
            }

            // SCFST_INIT + SCFST_WAITING (L777-794): initialize the ballers and
            // run the race to completion. `run_race` borrows `&self` + `&mut
            // data`; both borrows end at this `.await`, after which `self` is
            // exclusively ours again to mutate.
            let winner = self.run_race(data).await?;

            // Winner promotion (L796): `cf->next = ctx->ballers.winner->cf`. The
            // winning socket filter becomes the live bottom of the chain; from
            // now on every delegating method reaches it through `next`.
            self.state.next = Some(winner);
            self.state.connected = true;

            // L818 `data->info.numconnects++`. `FilterData` is intentionally
            // decoupled from the easy handle, so the count is tracked locally and
            // surfaced via `connections_made()` for the chain driver to apply.
            self.connections_made = self.connections_made.saturating_add(1);

            // NOTE (L803-804): curl marks `Curl_pgrsTimeWas(TIMER_APPCONNECT)`
            // here for SSH-family protocols. That requires easy-handle/progress
            // access which `FilterData` does not carry; it is deferred to the
            // chain driver, which owns the easy handle.

            // On success curl clears the accumulated failure reason
            // (Curl_reset_fail-style), so a winning race leaves no stale error.
            data.error_buffer = None;

            Ok(())
        })
    }

    /// Tear down the filter — C: `cf_ip_happy_close` (L828-841).
    ///
    /// Clears the `connected` bit and **discards the promoted winner chain**
    /// (curl's `Curl_conn_cf_discard_chain(&cf->next, ...)`, L838): the winner is
    /// closed and dropped so the freed socket is released immediately rather than
    /// lingering until this filter is itself dropped. Any in-flight ballers were
    /// already torn down when the `connect` future resolved, so there is no
    /// separate baller list to clear here. A subsequent `connect` re-runs the
    /// race from scratch (curl re-initializes its iterators in `start_connect`).
    fn close(&mut self) {
        let state = self.cf_state_mut();
        state.connected = false;
        if let Some(mut winner) = state.next.take() {
            winner.close();
        }
    }
}

// =============================================================================
// PHASE 6 — constructors / chain insertion (C: `cf_ip_happy_create`, L931-959,
//           and `cf_ip_happy_insert_after`, L961-981).
// =============================================================================

/// Normalize the caller-supplied Happy-Eyeballs stagger.
///
/// The effective delay comes from `CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS`
/// (`data.set.happy_eyeballs_timeout`), which curl defaults to
/// [`CURL_HET_DEFAULT`]. A *negative* value is never meaningful for this option,
/// so it is treated as "unset" and mapped back to the default; `0` is preserved
/// as a valid override that disables the stagger (start every candidate as soon
/// as the loop can).
const fn normalize_delay(happy_eyeballs_timeout: i64) -> i64 {
    if happy_eyeballs_timeout < 0 {
        CURL_HET_DEFAULT
    } else {
        happy_eyeballs_timeout
    }
}

impl HappyEyeballsFilter {
    /// Create a Happy-Eyeballs filter for an **IP** transport (TCP/UDP/QUIC) over
    /// the resolved `addrs` — C: `cf_ip_happy_create` (L931) with the ballers'
    /// configuration carried for a later `start_connect` (L698).
    ///
    /// `happy_eyeballs_timeout` is the staggered-attempt delay in milliseconds
    /// (typically `data.set.happy_eyeballs_timeout`, defaulting to
    /// [`CURL_HET_DEFAULT`]); see [`normalize_delay`]. Socket options, interface
    /// binding, and an overall connect deadline can be layered on with the
    /// `with_*` builder methods.
    #[must_use]
    pub fn new(
        transport: u8,
        ip_version: IpVersion,
        happy_eyeballs_timeout: i64,
        addrs: ResolvedAddrs,
    ) -> Self {
        debug_assert!(
            matches!(transport, TRNSPRT_TCP | TRNSPRT_UDP | TRNSPRT_QUIC),
            "happy-eyeballs IP race expects an IP transport (TCP/UDP/QUIC)"
        );
        Self {
            state: CfState::new(),
            transport,
            ip_version,
            attempt_delay_ms: normalize_delay(happy_eyeballs_timeout),
            connect_timeout_ms: None,
            addrs,
            #[cfg(unix)]
            unix_target: None,
            socket_options: SocketOptions::default(),
            bind_config: BindConfig::default(),
            #[cfg(test)]
            custom_create: None,
            connections_made: 0,
        }
    }

    /// Create a Happy-Eyeballs filter for the **UNIX-domain** transport — C: the
    /// `TRNSPRT_UNIX` path of `cf_ip_ballers_init` (L319-325), which yields a
    /// single-address iterator. There is exactly one candidate, so `connect`
    /// performs a single attempt with no family alternation or stagger.
    #[cfg(unix)]
    #[must_use]
    pub fn new_unix(unix_target: UnixTarget) -> Self {
        Self {
            state: CfState::new(),
            transport: TRNSPRT_UNIX,
            ip_version: IpVersion::Any,
            // Unused for UNIX (single attempt) but kept well-defined.
            attempt_delay_ms: CURL_HET_DEFAULT,
            connect_timeout_ms: None,
            addrs: ResolvedAddrs::default(),
            unix_target: Some(unix_target),
            socket_options: SocketOptions::default(),
            bind_config: BindConfig::default(),
            #[cfg(test)]
            custom_create: None,
            connections_made: 0,
        }
    }

    /// Apply per-connection socket options (`TCP_NODELAY`, keepalive) to every
    /// TCP attempt. Builder-style; returns `self`.
    #[must_use]
    pub fn with_socket_options(mut self, options: SocketOptions) -> Self {
        self.socket_options = options;
        self
    }

    /// Apply the local interface / port binding (`CURLOPT_INTERFACE`,
    /// `LOCALPORT`) to every attempt. Builder-style; returns `self`.
    #[must_use]
    pub fn with_bind_config(mut self, bind: BindConfig) -> Self {
        self.bind_config = bind;
        self
    }

    /// Set an overall connect deadline for the race, in milliseconds. A value
    /// `<= 0` means "no internal deadline" — the race then relies on the
    /// chain-level connect timeout. On expiry the race returns
    /// [`CurlError::OperationTimedout`] (C: `Curl_timeleft_ms`). Builder-style;
    /// returns `self`.
    #[must_use]
    pub fn with_connect_timeout_ms(mut self, timeout_ms: i64) -> Self {
        self.connect_timeout_ms = if timeout_ms > 0 {
            Some(timeout_ms)
        } else {
            None
        };
        self
    }

    /// Inject a test-only socket-filter factory (the safe analog of
    /// `Curl_debug_set_transport_provider`, L93-106). Production code always uses
    /// the real [`crate::conn::socket`] constructors. Builder-style.
    #[cfg(test)]
    #[must_use]
    fn with_custom_create(mut self, factory: CustomCreateFn) -> Self {
        self.custom_create = Some(factory);
        self
    }
}

/// Create the Happy-Eyeballs filter for an IP transport as a boxed
/// [`ConnectionFilter`] — the convenience the SETUP builder (`connect.rs`) calls
/// to place this filter at the **bottom** of the chain (the "EYEBALLS" step).
///
/// Equivalent to [`HappyEyeballsFilter::new`] followed by `Box::new`; use the
/// builder directly when socket options, binding, or a connect deadline are
/// needed. C: `cf_ip_happy_create` (L931).
#[must_use]
pub fn create_ip_happy_filter(
    transport: u8,
    ip_version: IpVersion,
    happy_eyeballs_timeout: i64,
    addrs: ResolvedAddrs,
) -> Box<dyn ConnectionFilter> {
    Box::new(HappyEyeballsFilter::new(
        transport,
        ip_version,
        happy_eyeballs_timeout,
        addrs,
    ))
}

/// Create the Happy-Eyeballs filter for an IP transport with an explicit
/// **overall connect deadline** (`CURLOPT_CONNECTTIMEOUT(_MS)`, the CLI
/// `--connect-timeout`), in milliseconds. A value `<= 0` means "no connect
/// deadline" — identical to [`create_ip_happy_filter`]. On expiry the connect
/// race returns [`CurlError::OperationTimedout`] (exit code 28), matching curl's
/// `Curl_timeleft`-driven connect-phase abort so a black-hole peer no longer
/// hangs the connect forever.
///
/// This is the deadline-aware counterpart the SETUP builder uses so the
/// configured connect timeout actually arms the race; the racing engine's
/// deadline guard already exists (see [`HappyEyeballsFilter::with_connect_timeout_ms`]).
#[must_use]
pub fn create_ip_happy_filter_with_timeout(
    transport: u8,
    ip_version: IpVersion,
    happy_eyeballs_timeout: i64,
    connect_timeout_ms: i64,
    addrs: ResolvedAddrs,
) -> Box<dyn ConnectionFilter> {
    create_ip_happy_filter_bound(
        transport,
        ip_version,
        happy_eyeballs_timeout,
        connect_timeout_ms,
        addrs,
        BindConfig::default(),
    )
}

/// Like [`create_ip_happy_filter_with_timeout`] but also applies a local
/// **interface / port binding** (`CURLOPT_INTERFACE`, `CURLOPT_LOCALPORT`) to
/// every connect attempt in the race. C: the `bindlocal` call performed inside
/// `cf_socket_open` before each `connect`. An inactive [`BindConfig`] (the
/// default) makes this identical to [`create_ip_happy_filter_with_timeout`].
#[must_use]
pub fn create_ip_happy_filter_bound(
    transport: u8,
    ip_version: IpVersion,
    happy_eyeballs_timeout: i64,
    connect_timeout_ms: i64,
    addrs: ResolvedAddrs,
    bind: BindConfig,
) -> Box<dyn ConnectionFilter> {
    Box::new(
        HappyEyeballsFilter::new(transport, ip_version, happy_eyeballs_timeout, addrs)
            .with_connect_timeout_ms(connect_timeout_ms)
            .with_bind_config(bind),
    )
}

/// Create the Happy-Eyeballs filter for the UNIX-domain transport as a boxed
/// [`ConnectionFilter`]. C: the `TRNSPRT_UNIX` path of `cf_ip_ballers_init`.
#[cfg(unix)]
#[must_use]
pub fn create_ip_happy_filter_unix(unix_target: UnixTarget) -> Box<dyn ConnectionFilter> {
    Box::new(HappyEyeballsFilter::new_unix(unix_target))
}

/// Insert a freshly-created Happy-Eyeballs filter into `chain` immediately after
/// the filter at `after_index` — C: `cf_ip_happy_insert_after` (L961-981), which
/// creates the filter and splices it in after `cf_at`.
///
/// Returns [`CurlError::BadFunctionArgument`] if no filter exists at
/// `after_index` (mirroring [`FilterChain::insert_after_index`]).
pub fn ip_happy_insert_after(
    chain: &mut FilterChain,
    after_index: usize,
    transport: u8,
    ip_version: IpVersion,
    happy_eyeballs_timeout: i64,
    addrs: ResolvedAddrs,
) -> Result<()> {
    let cf = create_ip_happy_filter(transport, ip_version, happy_eyeballs_timeout, addrs);
    chain.insert_after_index(after_index, cf)
}

// =============================================================================
// Tests — the racing engine driven with a deterministic mock socket filter
// (the safe analog of curl's `Curl_debug_set_transport_provider` unit-test
// hook). Timing-sensitive cases run under a paused Tokio clock so the 200 ms
// stagger and the overall deadline are exact and reproducible.
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    // ---- shared per-test instrumentation --------------------------------

    /// Counters and ordered logs shared between every mock attempt of one test.
    struct Stats {
        started_v4: AtomicUsize,
        started_v6: AtomicUsize,
        completed_v4: AtomicUsize,
        completed_v6: AtomicUsize,
        /// The family of each attempt in the order its connect was first polled.
        start_order: Mutex<Vec<AddrFamily>>,
        /// The ms-since-race-start at which each attempt's connect was first
        /// polled (for asserting the staggered delay under a paused clock).
        start_ms: Mutex<Vec<u64>>,
        /// Race origin, captured once (after `pause`) so `start_ms` is relative.
        origin: tokio::time::Instant,
    }

    impl Stats {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                started_v4: AtomicUsize::new(0),
                started_v6: AtomicUsize::new(0),
                completed_v4: AtomicUsize::new(0),
                completed_v6: AtomicUsize::new(0),
                start_order: Mutex::new(Vec::new()),
                start_ms: Mutex::new(Vec::new()),
                origin: tokio::time::Instant::now(),
            })
        }

        fn started_v4(&self) -> usize {
            self.started_v4.load(Ordering::SeqCst)
        }
        fn started_v6(&self) -> usize {
            self.started_v6.load(Ordering::SeqCst)
        }
        fn completed_v4(&self) -> usize {
            self.completed_v4.load(Ordering::SeqCst)
        }
        fn completed_v6(&self) -> usize {
            self.completed_v6.load(Ordering::SeqCst)
        }
        fn start_order(&self) -> Vec<AddrFamily> {
            self.start_order.lock().unwrap().clone()
        }
        fn start_ms(&self) -> Vec<u64> {
            self.start_ms.lock().unwrap().clone()
        }
    }

    /// The outcome a mock attempt yields after its (optional) delay.
    #[derive(Clone, Copy)]
    enum Probe {
        /// Connect succeeds (eligible to win).
        Ok,
        /// Hard failure (`CURLE_COULDNT_CONNECT`).
        Hard,
        /// Soft / inconclusive failure (`CURLE_WEIRD_SERVER_REPLY`) — eligible
        /// for one restart.
        Soft,
    }

    /// A mock socket filter: records when it is polled, waits `delay`, records
    /// completion, then returns `outcome`. If its future is dropped mid-`delay`
    /// (a cancelled loser), the *completion* counter is never bumped — that gap
    /// is exactly how the tests prove losers are torn down.
    struct ProbeFilter {
        state: CfState,
        name: &'static str,
        family: AddrFamily,
        delay: Duration,
        outcome: Probe,
        stats: Arc<Stats>,
    }

    impl ConnectionFilter for ProbeFilter {
        fn name(&self) -> &'static str {
            self.name
        }
        fn cf_state(&self) -> &CfState {
            &self.state
        }
        fn cf_state_mut(&mut self) -> &mut CfState {
            &mut self.state
        }
        fn flags(&self) -> u32 {
            CF_TYPE_IP_CONNECT
        }
        fn connect<'a>(&'a mut self, _data: &'a mut FilterData) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                // ---- record "started" (first poll) ----
                match self.family {
                    AddrFamily::V4 => self.stats.started_v4.fetch_add(1, Ordering::SeqCst),
                    AddrFamily::V6 => self.stats.started_v6.fetch_add(1, Ordering::SeqCst),
                };
                let elapsed_ms =
                    (tokio::time::Instant::now() - self.stats.origin).as_millis() as u64;
                self.stats.start_order.lock().unwrap().push(self.family);
                self.stats.start_ms.lock().unwrap().push(elapsed_ms);

                // ---- the in-flight connect; cancelled losers stop here ----
                if !self.delay.is_zero() {
                    tokio::time::sleep(self.delay).await;
                }

                // ---- record "completed" (only reached if not cancelled) ----
                match self.family {
                    AddrFamily::V4 => self.stats.completed_v4.fetch_add(1, Ordering::SeqCst),
                    AddrFamily::V6 => self.stats.completed_v6.fetch_add(1, Ordering::SeqCst),
                };
                match self.outcome {
                    Probe::Ok => {
                        self.state.connected = true;
                        Ok(())
                    }
                    Probe::Hard => Err(CurlError::CouldntConnect),
                    Probe::Soft => Err(CurlError::WeirdServerReply),
                }
            })
        }
    }

    // ---- helpers --------------------------------------------------------

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }
    fn v6(port: u16) -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0))
    }
    fn family_of(addr: SocketAddr) -> AddrFamily {
        match addr {
            SocketAddr::V4(_) => AddrFamily::V4,
            SocketAddr::V6(_) => AddrFamily::V6,
        }
    }
    fn probe(
        stats: &Arc<Stats>,
        name: &'static str,
        family: AddrFamily,
        delay_ms: u64,
        outcome: Probe,
    ) -> Box<dyn ConnectionFilter> {
        Box::new(ProbeFilter {
            state: CfState::new(),
            name,
            family,
            delay: Duration::from_millis(delay_ms),
            outcome,
            stats: stats.clone(),
        })
    }

    /// Build a filter whose attempts are produced by `f` (addr → mock filter).
    fn he_with<F>(
        ip_version: IpVersion,
        stagger_ms: i64,
        addrs: Vec<SocketAddr>,
        f: F,
    ) -> HappyEyeballsFilter
    where
        F: Fn(SocketAddr) -> Box<dyn ConnectionFilter> + Send + Sync + 'static,
    {
        HappyEyeballsFilter::new(
            TRNSPRT_TCP,
            ip_version,
            stagger_ms,
            ResolvedAddrs::from_vec(addrs),
        )
        .with_custom_create(Arc::new(f))
    }

    // ---- tests ----------------------------------------------------------

    /// The default stagger constant is exactly 200 ms, and `normalize_delay`
    /// maps "unset" (negative) back to it while preserving an explicit `0`.
    #[test]
    fn het_default_is_200_and_normalizes() {
        assert_eq!(CURL_HET_DEFAULT, 200);
        assert_eq!(normalize_delay(-1), CURL_HET_DEFAULT);
        assert_eq!(normalize_delay(0), 0);
        assert_eq!(normalize_delay(350), 350);
        // A filter built with the default option value carries the 200 ms stagger.
        let cf = HappyEyeballsFilter::new(
            TRNSPRT_TCP,
            IpVersion::Any,
            CURL_HET_DEFAULT,
            ResolvedAddrs::new(),
        );
        assert_eq!(cf.attempt_delay_ms, 200);
        assert_eq!(cf.connections_made(), 0);
    }

    /// No candidate addresses ⇒ `CURLE_COULDNT_CONNECT`, not a hang.
    #[tokio::test]
    async fn no_addresses_is_couldnt_connect() {
        let stats = Stats::new();
        let s = stats.clone();
        let mut cf = he_with(IpVersion::Any, 0, vec![], move |addr| {
            probe(&s, "x", family_of(addr), 0, Probe::Ok)
        });
        let mut data = FilterData::new();
        let err = cf.connect(&mut data).await.unwrap_err();
        assert!(matches!(err, CurlError::CouldntConnect));
        assert!(!cf.is_connected());
        assert_eq!(stats.started_v4() + stats.started_v6(), 0);
    }

    /// Family alternation is seeded so the FIRST attempt is IPv6 (curl L317);
    /// when it fails the engine falls through to IPv4. Even though the IPv4
    /// address is listed first, IPv6 is tried first.
    #[tokio::test]
    async fn family_alternation_tries_ipv6_first() {
        let stats = Stats::new();
        let s = stats.clone();
        // IPv4 listed first; IPv6 fails hard so IPv4 is then tried and wins.
        let mut cf = he_with(
            IpVersion::Any,
            0,
            vec![v4(81), v6(82)],
            move |addr| match family_of(addr) {
                AddrFamily::V6 => probe(&s, "v6", AddrFamily::V6, 0, Probe::Hard),
                AddrFamily::V4 => probe(&s, "v4", AddrFamily::V4, 0, Probe::Ok),
            },
        );
        let mut data = FilterData::new();
        cf.connect(&mut data).await.unwrap();
        assert_eq!(stats.start_order(), vec![AddrFamily::V6, AddrFamily::V4]);
        assert_eq!(stats.started_v6(), 1);
        assert_eq!(stats.started_v4(), 1);
        assert!(cf.is_connected());
        assert_eq!(cf.next_ref().unwrap().name(), "v4");
        assert_eq!(cf.connections_made(), 1);
    }

    /// `IpVersion::V4` honors IPv4-only: no IPv6 attempt is ever started.
    #[tokio::test]
    async fn ip_version_v4_only() {
        let stats = Stats::new();
        let s = stats.clone();
        let mut cf = he_with(IpVersion::V4, 0, vec![v4(91), v6(92)], move |addr| {
            probe(&s, "x", family_of(addr), 0, Probe::Ok)
        });
        let mut data = FilterData::new();
        cf.connect(&mut data).await.unwrap();
        assert_eq!(stats.started_v6(), 0, "IPv6 must not be attempted under V4");
        assert_eq!(stats.started_v4(), 1);
        assert!(cf.is_connected());
        assert_eq!(cf.connections_made(), 1);
    }

    /// `IpVersion::V6` honors IPv6-only: no IPv4 attempt is ever started.
    #[tokio::test]
    async fn ip_version_v6_only() {
        let stats = Stats::new();
        let s = stats.clone();
        let mut cf = he_with(IpVersion::V6, 0, vec![v4(101), v6(102)], move |addr| {
            probe(&s, "x", family_of(addr), 0, Probe::Ok)
        });
        let mut data = FilterData::new();
        cf.connect(&mut data).await.unwrap();
        assert_eq!(stats.started_v4(), 0, "IPv4 must not be attempted under V6");
        assert_eq!(stats.started_v6(), 1);
        assert!(cf.is_connected());
    }

    /// First connect wins; the slower in-flight attempt is cancelled (its
    /// completion is never recorded). The fast attempt starts second (after the
    /// 200 ms stagger) yet still wins, proving racing + loser teardown.
    #[tokio::test(start_paused = true)]
    async fn fast_wins_and_slow_is_cancelled() {
        let stats = Stats::new();
        let s = stats.clone();
        // First attempt (IPv6) is slow; second (IPv4) is fast.
        let mut cf = he_with(
            IpVersion::Any,
            200,
            vec![v6(11), v4(12)],
            move |addr| match family_of(addr) {
                AddrFamily::V6 => probe(&s, "slow", AddrFamily::V6, 5_000, Probe::Ok),
                AddrFamily::V4 => probe(&s, "fast", AddrFamily::V4, 10, Probe::Ok),
            },
        );
        let mut data = FilterData::new();
        cf.connect(&mut data).await.unwrap();

        assert_eq!(stats.started_v6(), 1, "slow attempt started");
        assert_eq!(stats.started_v4(), 1, "fast attempt started");
        assert_eq!(stats.completed_v4(), 1, "fast attempt completed (winner)");
        assert_eq!(
            stats.completed_v6(),
            0,
            "slow attempt was cancelled, never completed"
        );
        assert!(cf.is_connected());
        assert_eq!(cf.next_ref().unwrap().name(), "fast");
        assert_eq!(cf.connections_made(), 1);
    }

    /// Successive attempts start exactly one stagger apart (200 ms), and the
    /// overall connect deadline yields `CURLE_OPERATION_TIMEDOUT`. Three slow
    /// IPv4 attempts start at 0/200/400 ms, then the 1 s deadline fires.
    #[cfg_attr(miri, ignore)]
    #[tokio::test(start_paused = true)]
    async fn stagger_is_200ms_and_deadline_times_out() {
        let stats = Stats::new();
        let s = stats.clone();
        let mut cf = he_with(IpVersion::V4, 200, vec![v4(1), v4(2), v4(3)], move |addr| {
            probe(&s, "slow", family_of(addr), 10_000, Probe::Ok)
        })
        .with_connect_timeout_ms(1_000);
        let mut data = FilterData::new();
        let err = cf.connect(&mut data).await.unwrap_err();

        assert!(matches!(err, CurlError::OperationTimedout));
        assert_eq!(
            stats.start_ms(),
            vec![0, 200, 400],
            "attempts staggered by 200 ms"
        );
        assert_eq!(stats.started_v4(), 3);
        assert_eq!(
            stats.completed_v4(),
            0,
            "all attempts cancelled at deadline"
        );
        assert!(!cf.is_connected());
    }

    /// A soft (`WEIRD_SERVER_REPLY`) failure is inconclusive: once the fresh
    /// candidates are exhausted the inconclusive attempt is restarted, and the
    /// restart can win.
    #[tokio::test(start_paused = true)]
    async fn inconclusive_attempt_is_restarted() {
        // One V4 address: first attempt is inconclusive, the restart succeeds.
        // A shared toggle flips the outcome between the two attempts.
        let stats = Stats::new();
        let s = stats.clone();
        let attempt_no = Arc::new(AtomicUsize::new(0));
        let an = attempt_no.clone();
        let mut cf = he_with(IpVersion::V4, 200, vec![v4(7)], move |addr| {
            let n = an.fetch_add(1, Ordering::SeqCst);
            let outcome = if n == 0 { Probe::Soft } else { Probe::Ok };
            probe(&s, "retry", family_of(addr), 0, outcome)
        });
        let mut data = FilterData::new();
        cf.connect(&mut data).await.unwrap();
        // Two attempts on the same address: the inconclusive one, then the win.
        assert_eq!(stats.started_v4(), 2, "address was retried once");
        assert_eq!(stats.completed_v4(), 2);
        assert!(cf.is_connected());
        assert_eq!(cf.connections_made(), 1);
    }

    /// The UNIX-domain transport is a single attempt with no family alternation:
    /// a real `UnixListener` is bound and the filter connects to it, promoting
    /// the `"UNIX"` socket filter as its `next`.
    #[cfg(unix)]
    #[cfg_attr(miri, ignore)]
    #[tokio::test]
    async fn unix_transport_single_attempt() {
        let path = std::env::temp_dir().join(format!(
            "curlrs_he_unix_{}_{}.sock",
            std::process::id(),
            // a small nonce to avoid collisions across repeated runs
            tokio::time::Instant::now().elapsed().as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).expect("bind unix listener");

        let mut cf = HappyEyeballsFilter::new_unix(UnixTarget::path(path.clone()));
        let mut data = FilterData::new();
        let res = cf.connect(&mut data).await;

        assert!(res.is_ok(), "unix connect should succeed: {res:?}");
        assert!(cf.is_connected());
        assert_eq!(cf.connections_made(), 1);
        assert_eq!(cf.next_ref().unwrap().name(), "UNIX");

        drop(listener);
        let _ = std::fs::remove_file(&path);
    }

    /// `create_ip_happy_filter` produces a filter named `"HAPPY-EYEBALLS"`
    /// carrying `CF_TYPE_IP_CONNECT`, and `ip_happy_insert_after` splices it into
    /// a chain after the head (C: `cf_ip_happy_insert_after`).
    #[test]
    fn constructors_and_chain_insertion() {
        let cf = create_ip_happy_filter(
            TRNSPRT_TCP,
            IpVersion::Any,
            CURL_HET_DEFAULT,
            ResolvedAddrs::from_vec(vec![v4(1)]),
        );
        assert_eq!(cf.name(), "HAPPY-EYEBALLS");
        assert!(cf.has_flag(CF_TYPE_IP_CONNECT));
        assert!(!cf.is_connected());

        // Build a one-filter chain, then insert HAPPY-EYEBALLS after index 0.
        let head = create_ip_happy_filter(
            TRNSPRT_TCP,
            IpVersion::Any,
            CURL_HET_DEFAULT,
            ResolvedAddrs::new(),
        );
        let mut chain = FilterChain::from_head(head);
        ip_happy_insert_after(
            &mut chain,
            0,
            TRNSPRT_TCP,
            IpVersion::Any,
            CURL_HET_DEFAULT,
            ResolvedAddrs::from_vec(vec![v6(2)]),
        )
        .expect("insert after index 0");
        assert_eq!(chain.len(), 2);
        // Inserting after a non-existent index is a bad-argument error.
        assert!(matches!(
            ip_happy_insert_after(
                &mut chain,
                99,
                TRNSPRT_TCP,
                IpVersion::Any,
                CURL_HET_DEFAULT,
                ResolvedAddrs::new(),
            ),
            Err(CurlError::BadFunctionArgument)
        ));
    }
}
