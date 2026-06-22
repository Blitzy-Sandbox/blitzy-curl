//! Connection setup and the **SETUP meta-filter** chain-builder.
//!
//! This module reconstructs the behavior of curl's `lib/connect.c` (603 LoC) and
//! `lib/connect.h`. It is the single most architecturally central file in
//! [`crate::conn`]: it owns the assembly of the connection-filter stack.
//!
//! # The SETUP meta-filter
//!
//! curl establishes a connection by stacking small, composable *connection
//! filters* (transport → SOCKS → HTTP-proxy tunnel → HAProxy → TLS), each driven
//! to connect before the next is added. The C source bootstraps this with a
//! special filter, `Curl_cft_setup`, whose only job is to **build the real
//! filter chain in the exact canonical order and then become transparent** —
//! once assembly is complete it delegates every `send`/`recv`/`query`/… call to
//! the chain it built.
//!
//! [`SetupFilter`] is the Rust analog. Where the C code uses a re-entrant
//! `cf_setup_connect` driven by `goto connect_sub_chain`, the async port
//! collapses that into a single `async fn` that loops over the assembly state
//! machine ([`CfSetupState`]), `.await`ing each newly inserted filter's
//! `connect()` to completion before adding the next one. The **assembly order is
//! the binary parity contract** and is preserved byte-for-byte:
//!
//! ```text
//! EYEBALLS(transport) → SOCKS? → HTTPS-PROXY-TLS? → HTTP-PROXY(h1/h2)? → HAPROXY? → TLS?
//! ```
//!
//! The protocol engine (HTTP, FTP, …) sits *above* this entire stack and is
//! never imported here.
//!
//! # What this module provides
//!
//! * Connect-timeout budgeting: [`timeleft_now_ms`] / [`timeleft_ms`] and
//!   [`DEFAULT_CONNECT_TIMEOUT`], reproducing curl's "0 means no limit, fake a
//!   1 ms expiry" quirk exactly.
//! * The connection-control primitive [`conncontrol`] — the single place that
//!   decides whether a connection is marked for close.
//! * The SETUP filter ([`SetupFilter`]) and its public installation entrypoints
//!   ([`Curl_conn_setup`], [`Curl_cf_setup_insert_after`]).
//! * Address formatting ([`Curl_addr2string`]).
//!
//! # Architectural adaptation
//!
//! curl threads a single `struct connectdata`/`Curl_easy` god-object through
//! every helper. This crate is deliberately decoupled: there is no
//! `ConnectionData` aggregate. Functions therefore take only the precise inputs
//! they need (a [`FilterChain`], a `close` bit, a timing snapshot), and the
//! per-step filter construction is supplied as opaque factories
//! ([`FilterFactory`]) so this module depends on its siblings' *constructors*
//! without owning their configuration types. The observable behavior — above
//! all the assembly order — is identical to the C oracle.
//!
//! `unsafe` is forbidden crate-wide at the root (`lib.rs`); nothing here needs
//! it.

use std::net::SocketAddr;
use std::time::Duration;

use crate::conn::filters::{
    BoxFuture, CfState, ConnectionFilter, FilterChain, FilterData, CF_TYPE_SSL,
};
use crate::conn::happy_eyeballs::create_ip_happy_filter_with_timeout;
use crate::conn::haproxy::create_haproxy_filter;
use crate::conn::https_connect::{
    create_tls_filter, create_tls_proxy_filter, Curl_cf_https_setup, H3ConnectorFn,
    HttpsSetupConfig,
};
use crate::dns::{IpVersion, ResolvedAddrs};
use crate::error::{CurlError, Result};
use crate::tls::TlsConfig;
use crate::util::sendf;
use crate::util::timediff::ms_to_duration;
use crate::util::timeval::{curlx_now, curlx_ptimediff_ms, CurlTime};

// =============================================================================
// Re-exports — single source of truth for shared constants
// =============================================================================

// The SSL tri-state (`-1` default / `0` disable / `1` enable) is defined by the
// filter layer; re-export it so callers of `connect` can spell it without
// reaching across modules (and so we never duplicate the values). C: the
// `CF_SSL_*` macros referenced throughout `connect.c`.
pub use crate::conn::filters::{CURL_CF_SSL_DEFAULT, CURL_CF_SSL_DISABLE, CURL_CF_SSL_ENABLE};

// The transport tags live with the socket filter that consumes them; re-export
// for convenient construction of the SETUP filter's transport argument. C:
// `TRNSPRT_*` in `urldata.h`.
pub use crate::conn::socket::{
    TRNSPRT_NONE, TRNSPRT_QUIC, TRNSPRT_TCP, TRNSPRT_UDP, TRNSPRT_UNIX,
};

// The shutdown budget is owned by the shutdown filter; re-export rather than
// duplicate so there is exactly one definition. C: `DEFAULT_SHUTDOWN_TIMEOUT_MS`
// in `connect.h`.
pub use crate::conn::shutdown::DEFAULT_SHUTDOWN_TIMEOUT_MS;

// =============================================================================
// Constants (exact, from `lib/connect.h`)
// =============================================================================

/// Default connection timeout, in milliseconds (300 s / 5 min).
///
/// C: `#define DEFAULT_CONNECT_TIMEOUT 300000` (`connect.h`). Used as the connect
/// budget whenever the caller has not set an explicit `CURLOPT_CONNECTTIMEOUT`.
pub const DEFAULT_CONNECT_TIMEOUT: i64 = 300_000;

/// `Curl_conncontrol` action: leave the connection's close state untouched.
///
/// C: `CONNCTRL_KEEP 0` (`connect.h`).
pub const CONNCTRL_KEEP: i32 = 0;

/// `Curl_conncontrol` action: the whole connection is finished — mark for close.
///
/// C: `CONNCTRL_CONNECTION 1` (`connect.h`).
pub const CONNCTRL_CONNECTION: i32 = 1;

/// `Curl_conncontrol` action: a single stream is finished. Only forces a close
/// when the connection is **not** multiplexed (on a multiplexed connection a
/// finished stream must not tear down the shared connection).
///
/// C: `CONNCTRL_STREAM 2` (`connect.h`).
pub const CONNCTRL_STREAM: i32 = 2;

// =============================================================================
// Connect-timeout helpers (oracle: `Curl_timeleft_now_ms` / `Curl_timeleft_ms`,
// connect.c L99-142)
// =============================================================================

/// The timing inputs `Curl_timeleft_now_ms` reads off the easy handle.
///
/// curl pulls these from `data->set`, `data->progress`, and the shutdown filter.
/// Because this crate has no `Curl_easy` god-object, the caller gathers the
/// relevant fields into this struct. Every field maps 1:1 to a C source:
///
/// | field | C source |
/// |-------|----------|
/// | `shutdown_timeleft_ms` | `Curl_shutdown_started(data, FIRSTSOCKET)` ? `Curl_shutdown_timeleft(...)` : `None` |
/// | `is_connecting` | `Curl_is_connecting(data)` |
/// | `connect_only` | `data->set.connect_only` |
/// | `connecttimeout_ms` | `data->set.connecttimeout` |
/// | `timeout_ms` | `data->set.timeout` (`0` = unset) |
/// | `t_startsingle` | `data->progress.t_startsingle` |
/// | `t_startop` | `data->progress.t_startop` |
#[derive(Debug, Clone, Default)]
pub struct ConnectTimeout {
    /// `Some(remaining_ms)` when a shutdown is in progress on the first socket
    /// (the value is the shutdown filter's own remaining budget); `None`
    /// otherwise. When set it short-circuits everything else, exactly as the C
    /// `Curl_shutdown_started` branch does.
    pub shutdown_timeleft_ms: Option<i64>,
    /// Whether the handle is still in the connect phase (`Curl_is_connecting`).
    pub is_connecting: bool,
    /// `CURLOPT_CONNECT_ONLY`: connect but perform no transfer.
    pub connect_only: bool,
    /// `CURLOPT_CONNECTTIMEOUT_MS` in milliseconds; `<= 0` selects
    /// [`DEFAULT_CONNECT_TIMEOUT`].
    pub connecttimeout_ms: i64,
    /// `CURLOPT_TIMEOUT_MS` in milliseconds; `0` means "no overall timeout".
    pub timeout_ms: i64,
    /// Timestamp the current single connect attempt started
    /// (`progress.t_startsingle`).
    pub t_startsingle: CurlTime,
    /// Timestamp the overall operation started (`progress.t_startop`).
    pub t_startop: CurlTime,
}

/// Milliseconds of transfer/connection time left, evaluated at `now`.
///
/// Mirrors `Curl_timeleft_now_ms` (connect.c L105-137) **exactly**, including its
/// sign conventions:
///
/// * `0`  → no timeout in place (infinite time left).
/// * `> 0` → that many milliseconds remain.
/// * `< 0` → the deadline has already elapsed.
///
/// The infamous "fake 1 ms expiry" quirk is preserved verbatim: whenever a
/// computed budget lands exactly on `0` it is forced to `-1`, because `0` is
/// reserved to mean "no limit" and a just-expired timer must not be mistaken for
/// "infinite" (L118-119, L128-129).
#[must_use]
pub fn timeleft_now_ms(cfg: &ConnectTimeout, now: &CurlTime) -> i64 {
    let mut timeleft_ms: i64 = 0;
    let mut ctimeleft_ms: i64 = 0;

    // Branch 1: a shutdown on the first socket overrides the connect/transfer
    // timers entirely (L111-112).
    if let Some(shutdown_left) = cfg.shutdown_timeleft_ms {
        return shutdown_left;
    } else if cfg.is_connecting {
        // Connecting: budget the connect attempt. `connecttimeout <= 0` selects
        // the 5-minute default (L114-115).
        let ctimeout_ms = if cfg.connecttimeout_ms > 0 {
            cfg.connecttimeout_ms
        } else {
            DEFAULT_CONNECT_TIMEOUT
        };
        ctimeleft_ms = ctimeout_ms - curlx_ptimediff_ms(now, &cfg.t_startsingle);
        if ctimeleft_ms == 0 {
            // 0 is "no limit", fake 1 ms expiry (L118-119).
            ctimeleft_ms = -1;
        }
    } else if cfg.timeout_ms == 0 || cfg.connect_only {
        // Not connecting and either no overall timeout or connect-only: there is
        // nothing to limit (L121-122).
        return 0;
    }

    // The overall transfer timeout applies independently of the connect timer
    // (L125-130) — note this runs even while still connecting.
    if cfg.timeout_ms != 0 {
        timeleft_ms = cfg.timeout_ms - curlx_ptimediff_ms(now, &cfg.t_startop);
        if timeleft_ms == 0 {
            // 0 is "no limit", fake 1 ms expiry (L128-129).
            timeleft_ms = -1;
        }
    }

    // Combine the two budgets, preferring whichever is actually set, else the
    // tighter of the two (L132-136).
    if ctimeleft_ms == 0 {
        timeleft_ms
    } else if timeleft_ms == 0 {
        ctimeleft_ms
    } else {
        ctimeleft_ms.min(timeleft_ms)
    }
}

/// Milliseconds of time left, evaluated at the current instant.
///
/// C: `Curl_timeleft_ms` (L139-141) → `Curl_timeleft_now_ms(data, Curl_pgrs_now(data))`.
#[must_use]
pub fn timeleft_ms(cfg: &ConnectTimeout) -> i64 {
    timeleft_now_ms(cfg, &curlx_now())
}

/// Convert a `timeleft_ms` budget (as returned by [`timeleft_now_ms`]) into a
/// Tokio-friendly [`Duration`] deadline for use with `tokio::time::timeout`.
///
/// This is the bridge that threads curl's timeout budget into the async connect
/// machinery in [`crate::conn::happy_eyeballs`] / [`crate::conn::socket`]:
///
/// * `0`  → `None`: no limit, do not wrap the attempt in a timeout.
/// * `< 0` → `Some(Duration::ZERO)`: already expired, the attempt should fail
///   immediately with a timeout.
/// * `> 0` → `Some(_)`: that many milliseconds.
#[must_use]
pub fn timeleft_to_timeout(timeleft_ms: i64) -> Option<Duration> {
    use std::cmp::Ordering;
    match timeleft_ms.cmp(&0) {
        Ordering::Equal => None,
        Ordering::Less => Some(Duration::ZERO),
        Ordering::Greater => Some(ms_to_duration(timeleft_ms)),
    }
}


// =============================================================================
// Connection control (oracle: `Curl_conncontrol`, connect.c L298-322)
// =============================================================================

/// Mark a connection (or one of its streams) for closure.
///
/// This is the Rust analog of `Curl_conncontrol`. In curl the function pokes
/// `conn->bits.close`; here the caller passes that bit by mutable reference along
/// with whether the connection is multiplexed (in C this is read on the fly via
/// `Curl_conn_is_multiplex`). The decision table is reproduced exactly:
///
/// | `ctrl` | `is_multiplex` | effect |
/// |--------|----------------|--------|
/// | [`CONNCTRL_CONNECTION`] | any | `close = true` |
/// | [`CONNCTRL_STREAM`] | `false` | `close = true` |
/// | [`CONNCTRL_STREAM`] | `true` | **no change** (a finished stream must never tear down a shared multiplexed connection) |
/// | [`CONNCTRL_KEEP`] | any | `close = false` |
///
/// # The single writer of `close`
///
/// Per the oracle comment at connect.c L319-320, this is **the only place in the
/// source that should assign the connection's close bit**. The C code guards the
/// store behind a `closeit != conn->bits.close` comparison purely to avoid a
/// redundant write and a debug log line; the net assigned value is identical, so
/// the guard is elided here.
pub fn conncontrol(close_bit: &mut bool, is_multiplex: bool, ctrl: i32) {
    // A stream signal on a multiplexed connection never affects close state
    // (connect.c L316-317): bail before touching the bit.
    if ctrl == CONNCTRL_STREAM && is_multiplex {
        return;
    }

    // Close if this is a whole connection, or a stream that is not multiplexed
    // (connect.c L314-315).
    let closeit = (ctrl == CONNCTRL_CONNECTION) || (ctrl == CONNCTRL_STREAM && !is_multiplex);

    // The ONLY assignment of the connection close bit (connect.c L319-320).
    *close_bit = closeit;
}

/// Debug-only variant of [`conncontrol`] that additionally records a human
/// `reason` for the close decision.
///
/// Mirrors the `#if defined(DEBUGBUILD) && defined(CURLVERBOSE)` form of
/// `Curl_conncontrol`, where `reason` is `(void)`-discarded but invaluable when
/// stepping through a debugger. Release builds expose only the clean
/// three-argument [`conncontrol`], keeping the public signature uncluttered.
#[cfg(debug_assertions)]
pub fn conncontrol_with_reason(
    close_bit: &mut bool,
    is_multiplex: bool,
    ctrl: i32,
    reason: &str,
) {
    // Intentionally ignored at runtime, exactly like C's `(void)reason`; present
    // so a breakpoint here can inspect *why* a close was requested.
    let _ = reason;
    conncontrol(close_bit, is_multiplex, ctrl);
}


// =============================================================================
// The SETUP meta-filter (oracle: `cf_setup_state` / `cf_setup_ctx` /
// `cf_setup_connect` / `cf_setup_close`, connect.c L324-460)
// =============================================================================

/// A one-shot builder for a single connection filter.
///
/// curl's `cf_setup_connect` calls `cf_ip_happy_insert_after`,
/// `Curl_cf_socks_proxy_insert_after`, … which read the live `connectdata`/
/// `Curl_easy` to construct each filter. This crate has no such god-object, so
/// the per-step construction is supplied as an opaque factory closure captured
/// when the [`SetupFilter`] is built. Each factory is consumed exactly once,
/// matching the C contract where a given filter is inserted exactly once per
/// assembly. Use the builders in [the factory section](#factory-builders) (e.g.
/// [`eyeballs_factory`]) to produce these from the sibling constructors.
pub type FilterFactory = Box<dyn FnOnce() -> Box<dyn ConnectionFilter> + Send>;

/// The SETUP filter's assembly state — the order in which sub-filters are added.
///
/// **The variant order is the parity contract.** It mirrors `cf_setup_state`
/// (connect.c L324-332) exactly: the chain is built bottom-up as
/// EYEBALLS → SOCKS → HTTP-PROXY → HAPROXY → SSL, each step driven to connect
/// before the next is added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfSetupState {
    /// Nothing inserted yet (C: `CF_SETUP_INIT`).
    Init,
    /// The Happy-Eyeballs transport filter has been inserted
    /// (C: `CF_SETUP_CNNCT_EYEBALLS`).
    CnnctEyeballs,
    /// The SOCKS-proxy step has been processed (C: `CF_SETUP_CNNCT_SOCKS`).
    CnnctSocks,
    /// The HTTP-proxy step has been processed (C: `CF_SETUP_CNNCT_HTTP_PROXY`).
    CnnctHttpProxy,
    /// The HAProxy step has been processed (C: `CF_SETUP_CNNCT_HAPROXY`).
    CnnctHaproxy,
    /// The TLS step has been processed (C: `CF_SETUP_CNNCT_SSL`).
    CnnctSsl,
    /// Assembly complete; the filter is now transparent (C: `CF_SETUP_DONE`).
    Done,
}

/// Everything the SETUP filter needs to assemble a chain.
///
/// `ssl_mode` is the SSL tri-state ([`CURL_CF_SSL_DEFAULT`] / [`CURL_CF_SSL_DISABLE`]
/// / [`CURL_CF_SSL_ENABLE`]); `scheme_is_ssl` is curl's
/// `conn->scheme->flags & PROTOPT_SSL` (whether the URL scheme implies TLS, e.g.
/// `ftps`). The transport tag is captured inside `eyeballs`, the only mandatory
/// factory. The optional factories are present exactly when curl would take the
/// corresponding branch:
///
/// * `socks` — `conn->bits.socksproxy`
/// * `ssl_proxy` — `IS_HTTPS_PROXY(conn->http_proxy.proxytype)` (its insertion is
///   additionally gated at runtime on the chain not already being TLS)
/// * `http_proxy` — `conn->bits.tunnel_proxy` (the constructor itself picks h1
///   vs h2 based on negotiated proxy ALPN)
/// * `haproxy` — `data->set.haproxyprotocol`
/// * `ssl` — provided whenever TLS to the target may be required; actual
///   insertion is gated on `ssl_mode`/`scheme_is_ssl` and the chain not already
///   being TLS
pub struct SetupConfig {
    /// SSL tri-state controlling the final TLS step.
    pub ssl_mode: i32,
    /// Whether the URL scheme implies TLS (`PROTOPT_SSL`).
    pub scheme_is_ssl: bool,
    /// Whether name resolution has produced addresses (C:
    /// `data->state.dns[sockindex] != NULL`). `false` makes `connect` fail with
    /// [`CurlError::FailedInit`], reproducing connect.c L355-356.
    pub dns_available: bool,
    /// Mandatory transport factory (Happy-Eyeballs); carries the transport tag.
    pub eyeballs: FilterFactory,
    /// SOCKS-proxy wrapper factory, if `conn->bits.socksproxy`.
    pub socks: Option<FilterFactory>,
    /// TLS-to-proxy factory, if the proxy is an HTTPS proxy.
    pub ssl_proxy: Option<FilterFactory>,
    /// HTTP `CONNECT`-tunnel factory (h1/h2), if `conn->bits.tunnel_proxy`.
    pub http_proxy: Option<FilterFactory>,
    /// HAProxy PROXY-protocol factory, if `data->set.haproxyprotocol`.
    pub haproxy: Option<FilterFactory>,
    /// Target TLS factory, gated at assembly time by `ssl_mode`/`scheme_is_ssl`.
    pub ssl: Option<FilterFactory>,
}

impl SetupConfig {
    /// Construct a config with only the mandatory transport factory; all proxy
    /// and TLS steps default to absent and `dns_available` defaults to `true`.
    #[must_use]
    pub fn new(ssl_mode: i32, scheme_is_ssl: bool, eyeballs: FilterFactory) -> Self {
        Self {
            ssl_mode,
            scheme_is_ssl,
            dns_available: true,
            eyeballs,
            socks: None,
            ssl_proxy: None,
            http_proxy: None,
            haproxy: None,
            ssl: None,
        }
    }

    /// Attach the SOCKS-proxy step (`conn->bits.socksproxy`).
    #[must_use]
    pub fn with_socks(mut self, factory: FilterFactory) -> Self {
        self.socks = Some(factory);
        self
    }

    /// Attach the TLS-to-proxy step (HTTPS proxy).
    #[must_use]
    pub fn with_ssl_proxy(mut self, factory: FilterFactory) -> Self {
        self.ssl_proxy = Some(factory);
        self
    }

    /// Attach the HTTP `CONNECT`-tunnel step (`conn->bits.tunnel_proxy`).
    #[must_use]
    pub fn with_http_proxy(mut self, factory: FilterFactory) -> Self {
        self.http_proxy = Some(factory);
        self
    }

    /// Attach the HAProxy PROXY-protocol step (`data->set.haproxyprotocol`).
    #[must_use]
    pub fn with_haproxy(mut self, factory: FilterFactory) -> Self {
        self.haproxy = Some(factory);
        self
    }

    /// Attach the target TLS step.
    #[must_use]
    pub fn with_ssl(mut self, factory: FilterFactory) -> Self {
        self.ssl = Some(factory);
        self
    }

    /// Override `dns_available` (defaults to `true`).
    #[must_use]
    pub fn with_dns_available(mut self, available: bool) -> Self {
        self.dns_available = available;
        self
    }
}

/// The SETUP meta-filter.
///
/// Built once from a [`SetupConfig`], inserted at the bottom of a fresh chain,
/// and driven by [`ConnectionFilter::connect`]. Its `connect` assembles the real
/// filter stack in the canonical order and then marks itself connected; from
/// that point on every other trait method delegates transparently to the chain
/// it built (the default trait impls already pass through to `next`).
///
/// The factories are [`FnOnce`] and consumed during assembly, so a single SETUP
/// filter performs a single assembly. After [`close`](ConnectionFilter::close)
/// the sub-chain is discarded and the factories are spent; reconnecting requires
/// a freshly built SETUP filter (the normal flow rebuilds via
/// [`Curl_conn_setup`]). This matches the C lifecycle, where `cf_setup_close`
/// resets to `CF_SETUP_INIT` and discards the sub-chain so the next connect
/// rebuilds it from the (still live) `connectdata`.
pub struct SetupFilter {
    /// Standard filter state (the assembled sub-chain lives in `state.next`).
    state: CfState,
    /// Where assembly currently stands.
    setup_state: CfSetupState,
    /// SSL tri-state for the final TLS decision.
    ssl_mode: i32,
    /// Whether the scheme implies TLS (`PROTOPT_SSL`).
    scheme_is_ssl: bool,
    /// Whether resolved addresses are available (gates `CURLE_FAILED_INIT`).
    dns_available: bool,
    /// Remaining per-step factories (each taken exactly once during assembly).
    eyeballs: Option<FilterFactory>,
    socks: Option<FilterFactory>,
    ssl_proxy: Option<FilterFactory>,
    http_proxy: Option<FilterFactory>,
    haproxy: Option<FilterFactory>,
    ssl: Option<FilterFactory>,
}

impl SetupFilter {
    /// The current assembly state (useful for tests/diagnostics).
    #[must_use]
    pub fn setup_state(&self) -> CfSetupState {
        self.setup_state
    }

    /// The SSL tri-state this filter was configured with.
    #[must_use]
    pub fn ssl_mode(&self) -> i32 {
        self.ssl_mode
    }

    /// Walk the assembled sub-chain (everything below this filter) looking for a
    /// TLS filter. This is the Rust analog of `Curl_conn_is_ssl(conn, sockindex)`
    /// scoped to the SETUP filter's own `next` chain, used to gate the
    /// TLS-to-proxy and target-TLS insertions and the HAProxy guard.
    fn chain_has_ssl_below(&self) -> bool {
        let mut cur = self.state.next.as_deref();
        while let Some(cf) = cur {
            if cf.has_flag(CF_TYPE_SSL) {
                return true;
            }
            cur = cf.next_ref();
        }
        false
    }

    /// Splice `new_cf` immediately below this filter, pushing the existing
    /// sub-chain underneath it — the Rust analog of `Curl_conn_cf_add` /
    /// `*_insert_after(cf, ...)`, where the freshly created filter becomes
    /// `cf->next` and the previous `cf->next` hangs off the new filter's tail.
    fn insert_after_self(&mut self, mut new_cf: Box<dyn ConnectionFilter>) {
        let old_next = self.state.next.take();
        attach_tail(&mut new_cf, old_next);
        self.state.next = Some(new_cf);
    }
}

/// Attach `tail` at the very bottom of the `chain` filter's own `next` list.
///
/// The sibling constructors return single filters (`next == None`), so this is
/// normally a one-level set; recursion keeps it correct should a constructor
/// ever return a pre-assembled multi-filter stack.
fn attach_tail(chain: &mut Box<dyn ConnectionFilter>, tail: Option<Box<dyn ConnectionFilter>>) {
    if chain.cf_state().next.is_some() {
        let next = chain
            .cf_state_mut()
            .next
            .as_mut()
            .expect("next checked present");
        attach_tail(next, tail);
    } else {
        chain.cf_state_mut().next = tail;
    }
}

impl ConnectionFilter for SetupFilter {
    fn name(&self) -> &'static str {
        "SETUP"
    }

    fn cf_state(&self) -> &CfState {
        &self.state
    }

    fn cf_state_mut(&mut self) -> &mut CfState {
        &mut self.state
    }

    /// The SETUP filter contributes no capability bits of its own; capability is
    /// reported by the filters it inserts (C: `Curl_cft_setup.flags == 0`).
    fn flags(&self) -> u32 {
        0
    }

    /// Assemble the connection-filter chain in the canonical order, driving each
    /// inserted filter to connect before adding the next.
    ///
    /// This reproduces `cf_setup_connect` (connect.c L340-445). The C function is
    /// re-entrant and uses `goto connect_sub_chain` to (a) re-drive the current
    /// sub-chain and (b) re-evaluate which filter to add next. Because every
    /// `connect` here is `async`, "drive the sub-chain to completion and resume"
    /// collapses into a simple `.await`: the loop drives `next` to connection at
    /// the top of every iteration, then performs exactly one assembly step. The
    /// resulting insertion order is byte-for-byte identical to the C oracle:
    ///
    /// ```text
    /// EYEBALLS → SOCKS? → HTTPS-PROXY-TLS? → HTTP-PROXY(h1/h2)? → HAPROXY? → TLS?
    /// ```
    fn connect<'a>(&'a mut self, data: &'a mut FilterData) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Fast path: already assembled and connected (C L348-351).
            if self.state.connected {
                return Ok(());
            }

            loop {
                // C L355-356: without resolved addresses there is nothing to
                // connect — fail init. Re-checked each iteration, matching the
                // `connect_sub_chain` re-entry.
                if !self.dns_available {
                    return Err(CurlError::FailedInit);
                }

                // C L358-362: drive the current sub-chain to connection before
                // deciding whether to add another filter. The `.await` is the
                // async equivalent of the C "return until *done" re-entry.
                if let Some(next) = self.state.next.as_mut() {
                    if !next.is_connected() {
                        next.connect(data).await?;
                    }
                }

                match self.setup_state {
                    // C L364-371: ALWAYS insert the Happy-Eyeballs transport
                    // filter first (the bottom of the chain). It builds the
                    // socket filter itself.
                    CfSetupState::Init => {
                        match self.eyeballs.take() {
                            Some(factory) => self.insert_after_self(factory()),
                            // Spent factory (post-`close` reuse): cannot build the
                            // transport — the closest faithful failure is init.
                            None => return Err(CurlError::FailedInit),
                        }
                        self.setup_state = CfSetupState::CnnctEyeballs;
                    }

                    // C L375-382: SOCKS wrapper, only when `conn->bits.socksproxy`
                    // (encoded as `socks.is_some()`). Gated behind the `proxy`
                    // feature (C: `#ifndef CURL_DISABLE_PROXY`); when the feature
                    // is off the factory is simply never supplied.
                    CfSetupState::CnnctEyeballs => {
                        if let Some(factory) = self.socks.take() {
                            self.insert_after_self(factory());
                        }
                        self.setup_state = CfSetupState::CnnctSocks;
                    }

                    // C L384-404: the HTTP-proxy step. The TLS-to-proxy filter is
                    // inserted FIRST (C L386-391, gated on the chain not already
                    // being TLS), then the HTTP `CONNECT`-tunnel filter (C
                    // L395-399). Because both splice in immediately below SETUP,
                    // the second insert lands ABOVE the first — so the CONNECT
                    // tunnel correctly runs over the proxy-TLS connection.
                    CfSetupState::CnnctSocks => {
                        let ssl_below = self.chain_has_ssl_below();
                        if !ssl_below {
                            if let Some(factory) = self.ssl_proxy.take() {
                                self.insert_after_self(factory());
                            }
                        }
                        if let Some(factory) = self.http_proxy.take() {
                            self.insert_after_self(factory());
                        }
                        self.setup_state = CfSetupState::CnnctHttpProxy;
                    }

                    // C L407-423: the HAProxy step. The state advances
                    // unconditionally; the insertion is conditional on
                    // `data->set.haproxyprotocol` (encoded as `haproxy.is_some()`).
                    // GUARD (C L410-414): the PROXY header must be emitted in
                    // cleartext beneath TLS, so if the chain is already TLS this
                    // is an unsupported configuration.
                    CfSetupState::CnnctHttpProxy => {
                        if let Some(factory) = self.haproxy.take() {
                            if self.chain_has_ssl_below() {
                                sendf::failf(
                                    &mut data.error_buffer,
                                    "haproxy protocol not support with SSL \
                                     encryption in place (QUIC?)",
                                );
                                return Err(CurlError::UnsupportedProtocol);
                            }
                            self.insert_after_self(factory());
                        }
                        self.setup_state = CfSetupState::CnnctHaproxy;
                    }

                    // C L425-439: the target-TLS step. `want_ssl` reproduces the
                    // exact predicate at L427-429; the filter is inserted only
                    // when SSL is wanted AND the chain is not already TLS
                    // (C L430).
                    CfSetupState::CnnctHaproxy => {
                        let want_ssl = self.ssl_mode == CURL_CF_SSL_ENABLE
                            || (self.ssl_mode != CURL_CF_SSL_DISABLE && self.scheme_is_ssl);
                        if want_ssl && !self.chain_has_ssl_below() {
                            if let Some(factory) = self.ssl.take() {
                                self.insert_after_self(factory());
                            }
                        }
                        self.setup_state = CfSetupState::CnnctSsl;
                    }

                    // C L441-444: assembly complete — become transparent.
                    CfSetupState::CnnctSsl => {
                        self.setup_state = CfSetupState::Done;
                        self.state.connected = true;
                        return Ok(());
                    }

                    // Defensive: a connected filter takes the fast path above;
                    // reaching `Done` here simply confirms completion.
                    CfSetupState::Done => {
                        self.state.connected = true;
                        return Ok(());
                    }
                }
            }
        })
    }

    /// Tear down the assembled sub-chain and reset for a fresh assembly.
    ///
    /// C: `cf_setup_close` (connect.c L447-460) — clears `connected`, resets the
    /// assembly state to `CF_SETUP_INIT`, closes the sub-chain, and discards it
    /// (`Curl_conn_cf_discard_chain`) so a later connect rebuilds it. Here the
    /// factories were consumed during the prior assembly, so a rebuilt SETUP
    /// filter is required to reconnect (see the type docs).
    fn close(&mut self) {
        self.state.connected = false;
        self.setup_state = CfSetupState::Init;
        if let Some(next) = self.state.next.as_mut() {
            next.close();
        }
        // Discard the sub-chain (each filter's `Drop` runs its teardown).
        self.state.next = None;
    }
}


// =============================================================================
// Factory builders
//
// These wrap the sibling filter constructors into [`FilterFactory`] closures so
// a [`SetupConfig`] can be assembled without this module owning the siblings'
// configuration types. Each is a thin, allocation-free adapter; the closure
// captures the construction inputs and produces the filter on demand during
// assembly.
// =============================================================================

/// Factory for the bottom Happy-Eyeballs transport filter
/// (`crate::conn::happy_eyeballs::create_ip_happy_filter`). The `transport` tag
/// (TCP/UDP/QUIC/…) is captured here, which is why [`SetupFilter`] need not
/// store it separately.
///
/// `connect_timeout_ms` arms the race's overall connect deadline
/// (`CURLOPT_CONNECTTIMEOUT(_MS)` / `--connect-timeout`); `<= 0` means no connect
/// deadline. Wiring it here is what makes the configured connect timeout
/// effective — without it a black-hole peer would hang the connect indefinitely.
#[must_use]
pub fn eyeballs_factory(
    transport: u8,
    ip_version: IpVersion,
    happy_eyeballs_timeout_ms: i64,
    connect_timeout_ms: i64,
    addrs: ResolvedAddrs,
) -> FilterFactory {
    Box::new(move || {
        create_ip_happy_filter_with_timeout(
            transport,
            ip_version,
            happy_eyeballs_timeout_ms,
            connect_timeout_ms,
            addrs,
        )
    })
}

/// Factory for the HAProxy PROXY-protocol filter
/// (`crate::conn::haproxy::create_haproxy_filter`).
#[must_use]
pub fn haproxy_factory(unix_domain_socket: bool, client_ip: Option<String>) -> FilterFactory {
    Box::new(move || create_haproxy_filter(unix_domain_socket, client_ip))
}

/// Factory for the target-TLS filter
/// (`crate::conn::https_connect::create_tls_filter`).
#[must_use]
pub fn tls_factory(
    config: TlsConfig,
    hostname: String,
    port: u16,
    pinned_pubkey: Option<String>,
    alpn: Vec<Vec<u8>>,
) -> FilterFactory {
    Box::new(move || create_tls_filter(config, hostname, port, pinned_pubkey, alpn))
}

/// Factory for the TLS-to-proxy filter
/// (`crate::conn::https_connect::create_tls_proxy_filter`).
#[must_use]
pub fn tls_proxy_factory(
    config: TlsConfig,
    hostname: String,
    port: u16,
    pinned_pubkey: Option<String>,
    alpn: Vec<Vec<u8>>,
) -> FilterFactory {
    Box::new(move || create_tls_proxy_filter(config, hostname, port, pinned_pubkey, alpn))
}

/// Factory for the SOCKS-proxy wrapper filter
/// (`crate::conn::socket::create_socks_proxy_filter`). Gated on the `proxy`
/// feature, mirroring curl's `#ifndef CURL_DISABLE_PROXY`.
#[cfg(feature = "proxy")]
#[must_use]
pub fn socks_factory(config: crate::conn::socket::SocksProxyConfig) -> FilterFactory {
    Box::new(move || crate::conn::socket::create_socks_proxy_filter(config))
}

/// Factory for the HTTP/1.x `CONNECT`-tunnel filter
/// (`crate::conn::h1_proxy::create_h1_proxy_filter`). Gated on `proxy + http`,
/// mirroring curl's `!CURL_DISABLE_PROXY && !CURL_DISABLE_HTTP`.
#[cfg(all(feature = "proxy", feature = "http"))]
#[must_use]
pub fn h1_proxy_factory(config: crate::conn::h1_proxy::H1ProxyConfig) -> FilterFactory {
    Box::new(move || crate::conn::h1_proxy::create_h1_proxy_filter(config))
}

/// Factory for the HTTP/2 `CONNECT`-tunnel filter
/// (`crate::conn::h2_proxy::create_h2_proxy_filter`). Gated on
/// `proxy + http + http2`, mirroring curl's
/// `!CURL_DISABLE_PROXY && !CURL_DISABLE_HTTP && USE_NGHTTP2`.
#[cfg(all(feature = "proxy", feature = "http", feature = "http2"))]
#[must_use]
pub fn h2_proxy_factory(
    tunnel_host: String,
    tunnel_port: u16,
    proxy: crate::proxy::Proxy,
    auth_mask: u32,
    user_agent: Option<String>,
    verbose: bool,
) -> FilterFactory {
    Box::new(move || {
        crate::conn::h2_proxy::create_h2_proxy_filter(
            tunnel_host,
            tunnel_port,
            proxy,
            auth_mask,
            user_agent,
            verbose,
        )
    })
}

// =============================================================================
// SETUP filter installation (oracle: `cf_setup_create` / `cf_setup_add` /
// `Curl_cf_setup_insert_after`, connect.c L488-553)
// =============================================================================

/// Build a SETUP meta-filter in the initial (unassembled) state.
///
/// C: `cf_setup_create` (L488-518). Where C stores `transport` and `ssl_mode`
/// in the filter context, the Rust [`SetupConfig`] additionally carries the
/// per-step factories (the transport itself is captured by `config.eyeballs`).
#[must_use]
pub fn setup_create(config: SetupConfig) -> SetupFilter {
    SetupFilter {
        state: CfState::new(),
        setup_state: CfSetupState::Init,
        ssl_mode: config.ssl_mode,
        scheme_is_ssl: config.scheme_is_ssl,
        dns_available: config.dns_available,
        eyeballs: Some(config.eyeballs),
        socks: config.socks,
        ssl_proxy: config.ssl_proxy,
        http_proxy: config.http_proxy,
        haproxy: config.haproxy,
        ssl: config.ssl,
    }
}

/// Create a SETUP filter and add it at the **bottom** of `chain`.
///
/// C: `cf_setup_add` (L520-536) → `Curl_conn_cf_add` (adds at the chain head,
/// which is the bottom of the to-be-built stack).
fn setup_add(chain: &mut FilterChain, config: SetupConfig) {
    chain.add_filter(Box::new(setup_create(config)));
}

/// Create a SETUP filter and insert it immediately after the filter at
/// `after_index`.
///
/// C: `Curl_cf_setup_insert_after` (L538-553) → `Curl_conn_cf_insert_after`.
/// Returns [`CurlError::BadFunctionArgument`] if `after_index` is out of range.
#[allow(non_snake_case)]
pub fn Curl_cf_setup_insert_after(
    chain: &mut FilterChain,
    after_index: usize,
    config: SetupConfig,
) -> Result<()> {
    chain.insert_after_index(after_index, Box::new(setup_create(config)))
}

// =============================================================================
// The primary setup entrypoint (oracle: `Curl_conn_setup`, connect.c L555-593)
// =============================================================================

/// How [`Curl_conn_setup`] should establish the connection-filter chain.
///
/// This encodes the C dispatch at connect.c L570-586: HTTPS schemes go to the
/// ALPN-eyeballs coordinator (built by `Curl_cf_https_setup`), while every other
/// scheme uses the linear SETUP meta-filter. The caller — which owns the parsed
/// URL and therefore knows the scheme — selects the variant.
pub enum ConnSetup {
    /// HTTPS: install the pre-built ALPN-eyeballs coordinator directly,
    /// bypassing the linear SETUP filter (C L570-577).
    Https(Box<dyn ConnectionFilter>),
    /// Every other scheme: assemble the chain via the SETUP meta-filter
    /// (C L580-586).
    Default(SetupConfig),
}

/// Build a [`ConnSetup::Https`] by running the HTTPS ALPN-eyeballs coordinator
/// constructor (`crate::conn::https_connect::Curl_cf_https_setup`).
///
/// `transport` is the bottom transport filter the coordinator's ballers connect
/// over; `config` selects the h1/h2/h3 preferences and ALPN; `h3_connector` is
/// the optional HTTP/3-over-QUIC launcher. This is the Rust analog of the
/// `Curl_cf_https_setup(data, conn, sockindex)` call at connect.c L574.
#[must_use]
pub fn https_dispatch(
    transport: Box<dyn ConnectionFilter>,
    config: HttpsSetupConfig,
    h3_connector: Option<H3ConnectorFn>,
) -> ConnSetup {
    ConnSetup::Https(Curl_cf_https_setup(transport, config, h3_connector))
}

/// Establish the connection-filter chain for one socket — the primary entry
/// point, the Rust analog of `Curl_conn_setup` (connect.c L555-593).
///
/// In C this also unlinks/relinks `data->state.dns[sockindex]`; in this
/// decoupled design the resolved addresses are captured by the `eyeballs`
/// factory inside the [`SetupConfig`] (or by the HTTPS coordinator), so DNS
/// ownership is the caller's responsibility and is not threaded here. The
/// `dns_available` flag on the config preserves the C "no dns ⇒
/// `CURLE_FAILED_INIT`" precondition at connect time.
///
/// If `chain` already holds filters this is a no-op, exactly as the C guards
/// `if(!conn->cfilter[sockindex])` make it (L571, L581).
#[allow(non_snake_case)]
pub fn Curl_conn_setup(chain: &mut FilterChain, ssl_mode: i32, dispatch: ConnSetup) -> Result<()> {
    // C L571/L581: only install when the chain is empty.
    if chain.is_setup() {
        return Ok(());
    }

    match dispatch {
        ConnSetup::Https(coordinator) => {
            // C L573: HTTPS must never be requested with SSL disabled.
            debug_assert!(
                ssl_mode != CURL_CF_SSL_DISABLE,
                "Curl_conn_setup: HTTPS scheme with CURL_CF_SSL_DISABLE"
            );
            chain.add_filter(coordinator);
        }
        ConnSetup::Default(mut config) => {
            // The explicit `ssl_mode` argument is authoritative for the SETUP
            // filter (C passes it straight to `cf_setup_add`, L583).
            config.ssl_mode = ssl_mode;
            setup_add(chain, config);
        }
    }
    Ok(())
}

/// Mark a connection as multiplexed.
///
/// C: `Curl_conn_set_multiplex` (L595-603). Returns `true` when the bit actually
/// changed from `false` to `true`; on a `true` return the caller must notify the
/// attached multi handle (the C `Curl_multi_connchanged(conn->attached_multi)`
/// step), which this decoupled function cannot reach on its own.
#[allow(non_snake_case)]
pub fn Curl_conn_set_multiplex(multiplex: &mut bool) -> bool {
    if !*multiplex {
        *multiplex = true;
        true
    } else {
        false
    }
}

// =============================================================================
// Address formatting (oracle: `Curl_addr2string`, connect.c L211-260)
// =============================================================================

/// Format an IP socket address into its textual address and port.
///
/// C: `Curl_addr2string` (L211-260) for the `AF_INET`/`AF_INET6` cases. The C
/// function returns a `bool` because `inet_ntop` can fail and the address family
/// may be unknown; with a well-typed Rust [`SocketAddr`] both are impossible, so
/// this returns the `(address, port)` pair directly. IPv6 is rendered in the
/// bare form (no brackets), matching `inet_ntop`.
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_addr2string(addr: SocketAddr) -> (String, u16) {
    (addr.ip().to_string(), addr.port())
}

/// Format an `AF_UNIX` socket path into its textual form (port is always `0`).
///
/// C: the `AF_UNIX` case of `Curl_addr2string` (L242-250), which prints
/// `sun_path` with `%s` (stopping at the first NUL) or the empty string for an
/// unnamed socket. Abstract-namespace sockets (a leading NUL byte) are rendered
/// with a leading `@` followed by the name, the convention curl uses elsewhere.
#[must_use]
pub fn addr2string_unix(sun_path: &[u8]) -> (String, u16) {
    // AF_UNIX never carries a port (C sets `*port = 0`).
    if sun_path.is_empty() {
        // Socket with no name (C L247-248).
        return (String::new(), 0);
    }
    if sun_path[0] == 0 {
        // Abstract-namespace socket: '@' + name up to the next NUL.
        let rest = &sun_path[1..];
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        let mut s = String::with_capacity(end + 1);
        s.push('@');
        s.push_str(&String::from_utf8_lossy(&rest[..end]));
        return (s, 0);
    }
    // Pathname socket: C `%s` stops at the first NUL (C L245).
    let end = sun_path
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(sun_path.len());
    (String::from_utf8_lossy(&sun_path[..end]).into_owned(), 0)
}


// =============================================================================
// Tests
//
// The parity-critical property is the *assembly order* of the filter chain. It
// is verified deterministically and network-free using mock filters that record
// only their name and capability flags — the SETUP filter's job is purely to
// insert filters in the canonical order and drive each to connect, which mocks
// exercise faithfully (a mock's `connect` uses the trait default: drive `next`,
// then mark connected). The remaining tests cover the timeout quirk, the
// `conncontrol` truth table, address formatting, and the dispatch entrypoints.
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    // ---- Mock filter -------------------------------------------------------

    /// A no-op connection filter that records a name and capability flags. Its
    /// `connect` falls through to the trait default (drive `next`, mark
    /// connected), so chains of mocks connect instantly without any I/O.
    struct MockFilter {
        state: CfState,
        label: &'static str,
        flag_bits: u32,
    }

    impl MockFilter {
        fn new(label: &'static str, flag_bits: u32) -> Self {
            Self {
                state: CfState::new(),
                label,
                flag_bits,
            }
        }
    }

    impl ConnectionFilter for MockFilter {
        fn name(&self) -> &'static str {
            self.label
        }
        fn cf_state(&self) -> &CfState {
            &self.state
        }
        fn cf_state_mut(&mut self) -> &mut CfState {
            &mut self.state
        }
        fn flags(&self) -> u32 {
            self.flag_bits
        }
    }

    /// A [`FilterFactory`] producing a named mock with the given flags.
    fn mock_factory(label: &'static str, flag_bits: u32) -> FilterFactory {
        Box::new(move || Box::new(MockFilter::new(label, flag_bits)) as Box<dyn ConnectionFilter>)
    }

    /// Collect the names of the SETUP filter's assembled sub-chain, top-down
    /// (the filter immediately below SETUP first, the transport last).
    fn chain_names(setup: &SetupFilter) -> Vec<&'static str> {
        let mut names = Vec::new();
        let mut cur = setup.cf_state().next.as_deref();
        while let Some(cf) = cur {
            names.push(cf.name());
            cur = cf.next_ref();
        }
        names
    }

    /// Drive a SETUP filter to completion, returning the connect result.
    fn drive(setup: &mut SetupFilter) -> Result<()> {
        let mut data = FilterData::with_verbose(false);
        tokio_test::block_on(setup.connect(&mut data))
    }

    /// Drive a SETUP filter to completion, returning both the result and the
    /// captured error-buffer message.
    fn drive_capture(setup: &mut SetupFilter) -> (Result<()>, Option<String>) {
        let mut data = FilterData::with_verbose(false);
        let res = tokio_test::block_on(setup.connect(&mut data));
        (res, data.error_buffer)
    }

    // ---- Assembly-order parity (the binary success condition) --------------

    #[test]
    fn order_plain_http_is_eyeballs_only() {
        let config = SetupConfig::new(CURL_CF_SSL_DEFAULT, false, mock_factory("EYEBALLS", 0));
        let mut setup = setup_create(config);
        drive(&mut setup).expect("plain HTTP connect");
        assert_eq!(chain_names(&setup), vec!["EYEBALLS"]);
        assert_eq!(setup.setup_state(), CfSetupState::Done);
    }

    #[test]
    fn order_ftps_ssl_enable_is_eyeballs_then_ssl() {
        // ssl_mode == ENABLE forces TLS even over a non-PROTOPT_SSL scheme.
        let config = SetupConfig::new(CURL_CF_SSL_ENABLE, false, mock_factory("EYEBALLS", 0))
            .with_ssl(mock_factory("SSL", CF_TYPE_SSL));
        let mut setup = setup_create(config);
        drive(&mut setup).expect("ftps connect");
        // Top-down: SSL sits above the transport; bottom-up that is
        // EYEBALLS -> SSL, the canonical order.
        assert_eq!(chain_names(&setup), vec!["SSL", "EYEBALLS"]);
    }

    #[test]
    fn order_scheme_ssl_default_inserts_tls() {
        // ssl_mode == DEFAULT but the scheme implies TLS (PROTOPT_SSL).
        let config = SetupConfig::new(CURL_CF_SSL_DEFAULT, true, mock_factory("EYEBALLS", 0))
            .with_ssl(mock_factory("SSL", CF_TYPE_SSL));
        let mut setup = setup_create(config);
        drive(&mut setup).expect("connect");
        assert_eq!(chain_names(&setup), vec!["SSL", "EYEBALLS"]);
    }

    #[test]
    fn order_ssl_disable_suppresses_tls_even_for_ssl_scheme() {
        // ssl_mode == DISABLE must suppress TLS even when the scheme implies it.
        let config = SetupConfig::new(CURL_CF_SSL_DISABLE, true, mock_factory("EYEBALLS", 0))
            .with_ssl(mock_factory("SSL", CF_TYPE_SSL));
        let mut setup = setup_create(config);
        drive(&mut setup).expect("connect");
        assert_eq!(chain_names(&setup), vec!["EYEBALLS"]);
    }

    #[test]
    fn order_socks_httpproxy_ssl_full_stack() {
        // SOCKS + tunnel HTTP proxy + TLS target: the agent prompt's headline
        // ordering case -> bottom-up EYEBALLS -> SOCKS -> HTTP-PROXY -> TLS.
        let config = SetupConfig::new(CURL_CF_SSL_ENABLE, false, mock_factory("EYEBALLS", 0))
            .with_socks(mock_factory("SOCKS", 0))
            .with_http_proxy(mock_factory("HTTP-PROXY", 0))
            .with_ssl(mock_factory("SSL", CF_TYPE_SSL));
        let mut setup = setup_create(config);
        drive(&mut setup).expect("full-stack connect");
        assert_eq!(
            chain_names(&setup),
            vec!["SSL", "HTTP-PROXY", "SOCKS", "EYEBALLS"]
        );
    }

    #[test]
    fn order_ssl_proxy_is_below_http_proxy() {
        // Within the HTTP-proxy step the TLS-to-proxy filter is inserted first
        // (so it ends up BELOW), then the CONNECT tunnel (which ends up ABOVE):
        // the tunnel runs over the proxy-TLS connection.
        let config = SetupConfig::new(CURL_CF_SSL_DEFAULT, false, mock_factory("EYEBALLS", 0))
            .with_ssl_proxy(mock_factory("SSL-PROXY", CF_TYPE_SSL))
            .with_http_proxy(mock_factory("HTTP-PROXY", 0));
        let mut setup = setup_create(config);
        drive(&mut setup).expect("proxy connect");
        assert_eq!(
            chain_names(&setup),
            vec!["HTTP-PROXY", "SSL-PROXY", "EYEBALLS"]
        );
    }

    #[test]
    fn haproxy_over_ssl_is_unsupported_with_exact_message() {
        // An HTTPS proxy puts TLS below before the HAProxy step; the PROXY header
        // cannot be emitted under TLS, so this must fail with the exact message.
        let config = SetupConfig::new(CURL_CF_SSL_DEFAULT, false, mock_factory("EYEBALLS", 0))
            .with_ssl_proxy(mock_factory("SSL-PROXY", CF_TYPE_SSL))
            .with_haproxy(mock_factory("HAPROXY", 0));
        let mut setup = setup_create(config);
        let (result, err_buf) = drive_capture(&mut setup);
        assert!(matches!(result, Err(CurlError::UnsupportedProtocol)));
        assert_eq!(
            err_buf.as_deref(),
            Some("haproxy protocol not support with SSL encryption in place (QUIC?)")
        );
    }

    #[test]
    fn haproxy_without_ssl_is_inserted() {
        // Without TLS below, the HAProxy filter is added normally.
        let config = SetupConfig::new(CURL_CF_SSL_DEFAULT, false, mock_factory("EYEBALLS", 0))
            .with_haproxy(mock_factory("HAPROXY", 0));
        let mut setup = setup_create(config);
        drive(&mut setup).expect("haproxy connect");
        assert_eq!(chain_names(&setup), vec!["HAPROXY", "EYEBALLS"]);
    }

    #[test]
    fn dns_unavailable_fails_init() {
        let config = SetupConfig::new(CURL_CF_SSL_DEFAULT, false, mock_factory("EYEBALLS", 0))
            .with_dns_available(false);
        let mut setup = setup_create(config);
        assert!(matches!(drive(&mut setup), Err(CurlError::FailedInit)));
    }

    // ---- Timeout helpers ---------------------------------------------------

    fn at(sec: i64) -> CurlTime {
        CurlTime {
            tv_sec: sec,
            tv_usec: 0,
        }
    }

    #[test]
    fn timeleft_connecttimeout_zero_uses_default() {
        // connecttimeout <= 0 selects DEFAULT_CONNECT_TIMEOUT; with no elapsed
        // time and no overall timeout the budget is the full default.
        let cfg = ConnectTimeout {
            is_connecting: true,
            connecttimeout_ms: 0,
            t_startsingle: at(0),
            ..ConnectTimeout::default()
        };
        assert_eq!(timeleft_now_ms(&cfg, &at(0)), DEFAULT_CONNECT_TIMEOUT);
    }

    #[test]
    fn timeleft_zero_remaining_is_faked_to_minus_one() {
        // connecttimeout 1000 ms, exactly 1000 ms elapsed -> 0 -> faked to -1.
        let cfg = ConnectTimeout {
            is_connecting: true,
            connecttimeout_ms: 1000,
            t_startsingle: at(0),
            ..ConnectTimeout::default()
        };
        assert_eq!(timeleft_now_ms(&cfg, &at(1)), -1);
    }

    #[test]
    fn timeleft_shutdown_short_circuits() {
        let cfg = ConnectTimeout {
            shutdown_timeleft_ms: Some(42),
            is_connecting: true,
            connecttimeout_ms: 1000,
            ..ConnectTimeout::default()
        };
        assert_eq!(timeleft_now_ms(&cfg, &at(0)), 42);
    }

    #[test]
    fn timeleft_no_limit_when_idle() {
        // Not connecting, no overall timeout -> "no limit" (0).
        let cfg = ConnectTimeout::default();
        assert_eq!(timeleft_now_ms(&cfg, &at(0)), 0);
        // connect_only also short-circuits to 0.
        let cfg = ConnectTimeout {
            connect_only: true,
            timeout_ms: 5000,
            ..ConnectTimeout::default()
        };
        assert_eq!(timeleft_now_ms(&cfg, &at(0)), 0);
    }

    #[test]
    fn timeleft_combines_connect_and_transfer_budgets() {
        // Both budgets set: the tighter (smaller) one wins.
        let cfg = ConnectTimeout {
            is_connecting: true,
            connecttimeout_ms: 10_000,
            t_startsingle: at(0),
            timeout_ms: 3_000,
            t_startop: at(0),
            ..ConnectTimeout::default()
        };
        // ctimeleft = 10000 - 1000 = 9000; timeleft = 3000 - 1000 = 2000; min = 2000.
        assert_eq!(timeleft_now_ms(&cfg, &at(1)), 2_000);
    }

    #[test]
    fn timeleft_to_timeout_conventions() {
        assert_eq!(timeleft_to_timeout(0), None);
        assert_eq!(timeleft_to_timeout(-5), Some(Duration::ZERO));
        assert_eq!(timeleft_to_timeout(1000), Some(ms_to_duration(1000)));
    }

    // ---- conncontrol truth table -------------------------------------------

    #[test]
    fn conncontrol_truth_table() {
        // CONNECTION always closes, regardless of multiplex.
        let mut close = false;
        conncontrol(&mut close, false, CONNCTRL_CONNECTION);
        assert!(close);
        let mut close = false;
        conncontrol(&mut close, true, CONNCTRL_CONNECTION);
        assert!(close);

        // STREAM on a non-multiplexed connection closes.
        let mut close = false;
        conncontrol(&mut close, false, CONNCTRL_STREAM);
        assert!(close);

        // STREAM on a multiplexed connection never changes the bit.
        let mut close = false;
        conncontrol(&mut close, true, CONNCTRL_STREAM);
        assert!(!close);
        let mut close = true;
        conncontrol(&mut close, true, CONNCTRL_STREAM);
        assert!(close);

        // KEEP clears the bit.
        let mut close = true;
        conncontrol(&mut close, false, CONNCTRL_KEEP);
        assert!(!close);
    }

    // ---- Address formatting ------------------------------------------------

    #[test]
    fn addr2string_ipv4_and_ipv6() {
        let v4 = "127.0.0.1:80".parse().unwrap();
        assert_eq!(Curl_addr2string(v4), ("127.0.0.1".to_string(), 80));
        let v6 = "[::1]:443".parse().unwrap();
        assert_eq!(Curl_addr2string(v6), ("::1".to_string(), 443));
    }

    #[test]
    fn addr2string_unix_variants() {
        // Pathname socket: stops at the first NUL.
        assert_eq!(
            addr2string_unix(b"/tmp/sock\0junk"),
            ("/tmp/sock".to_string(), 0)
        );
        // Pathname socket with no trailing NUL.
        assert_eq!(addr2string_unix(b"/tmp/sock"), ("/tmp/sock".to_string(), 0));
        // Unnamed socket.
        assert_eq!(addr2string_unix(b""), (String::new(), 0));
        // Abstract-namespace socket (leading NUL) -> '@' + name.
        assert_eq!(addr2string_unix(&[0, b'a', b'b', b'c']), ("@abc".to_string(), 0));
    }

    // ---- Multiplex + dispatch entrypoints ----------------------------------

    #[test]
    fn set_multiplex_reports_change() {
        let mut m = false;
        assert!(Curl_conn_set_multiplex(&mut m));
        assert!(m);
        // Already multiplexed: no change.
        assert!(!Curl_conn_set_multiplex(&mut m));
        assert!(m);
    }

    #[test]
    fn conn_setup_default_installs_setup_filter() {
        let mut chain = FilterChain::new();
        let config = SetupConfig::new(CURL_CF_SSL_DEFAULT, false, mock_factory("EYEBALLS", 0));
        Curl_conn_setup(&mut chain, CURL_CF_SSL_DEFAULT, ConnSetup::Default(config))
            .expect("default setup");
        assert!(chain.is_setup());
        assert_eq!(chain.position_by_name("SETUP"), Some(0));
    }

    #[test]
    fn conn_setup_https_installs_coordinator_not_setup() {
        let mut chain = FilterChain::new();
        let coordinator =
            Box::new(MockFilter::new("HTTPS-COORD", 0)) as Box<dyn ConnectionFilter>;
        Curl_conn_setup(&mut chain, CURL_CF_SSL_ENABLE, ConnSetup::Https(coordinator))
            .expect("https setup");
        assert!(chain.is_setup());
        // The HTTPS coordinator is installed directly; no linear SETUP filter.
        assert_eq!(chain.position_by_name("HTTPS-COORD"), Some(0));
        assert_eq!(chain.position_by_name("SETUP"), None);
    }

    #[test]
    fn conn_setup_is_noop_on_nonempty_chain() {
        // A chain that already has filters is left untouched.
        let mut chain = FilterChain::from_head(
            Box::new(MockFilter::new("EXISTING", 0)) as Box<dyn ConnectionFilter>
        );
        let config = SetupConfig::new(CURL_CF_SSL_DEFAULT, false, mock_factory("EYEBALLS", 0));
        Curl_conn_setup(&mut chain, CURL_CF_SSL_DEFAULT, ConnSetup::Default(config))
            .expect("noop setup");
        assert_eq!(chain.position_by_name("EXISTING"), Some(0));
        assert_eq!(chain.position_by_name("SETUP"), None);
    }

    #[test]
    fn cf_setup_insert_after_places_setup_below_anchor() {
        let mut chain = FilterChain::from_head(
            Box::new(MockFilter::new("ANCHOR", 0)) as Box<dyn ConnectionFilter>
        );
        let config = SetupConfig::new(CURL_CF_SSL_DEFAULT, false, mock_factory("EYEBALLS", 0));
        Curl_cf_setup_insert_after(&mut chain, 0, config).expect("insert after anchor");
        assert_eq!(chain.position_by_name("ANCHOR"), Some(0));
        assert_eq!(chain.position_by_name("SETUP"), Some(1));
    }

    #[test]
    fn setup_create_starts_in_init() {
        let setup = setup_create(SetupConfig::new(
            CURL_CF_SSL_ENABLE,
            true,
            mock_factory("EYEBALLS", 0),
        ));
        assert_eq!(setup.setup_state(), CfSetupState::Init);
        assert_eq!(setup.ssl_mode(), CURL_CF_SSL_ENABLE);
    }

    // ---- Factory smoke (genuinely exercises a sibling constructor) ----------

    #[test]
    fn haproxy_factory_builds_a_filter() {
        let factory = haproxy_factory(false, Some("203.0.113.7".to_string()));
        let cf = factory();
        assert!(!cf.name().is_empty());
    }

    // ---- close() resets and discards the sub-chain -------------------------

    #[test]
    fn close_resets_state_and_discards_chain() {
        let config = SetupConfig::new(CURL_CF_SSL_ENABLE, false, mock_factory("EYEBALLS", 0))
            .with_ssl(mock_factory("SSL", CF_TYPE_SSL));
        let mut setup = setup_create(config);
        drive(&mut setup).expect("connect");
        assert_eq!(chain_names(&setup), vec!["SSL", "EYEBALLS"]);

        setup.close();
        assert_eq!(setup.setup_state(), CfSetupState::Init);
        assert!(setup.cf_state().next.is_none());
        assert!(!setup.cf_state().connected);
    }
}

