// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-FileCopyrightText: Linus Nielsen Feltzing, <linus@haxx.se>

//! # Connection shutdown manager (`cshutdn`)
//!
//! This module is the idiomatic-Rust rewrite of curl's connection shutdown
//! manager (`lib/cshutdn.c` / `lib/cshutdn.h`). When a connection is finished
//! being used but still needs a *graceful* teardown — a TLS `close_notify`, or a
//! protocol-level disconnect handshake such as FTP `QUIT`, IMAP `LOGOUT`, SMTP
//! `QUIT`, or the SFTP/SSH channel close — it is not slammed shut. Instead it is
//! handed to a [`Shutdown`] pool owned by the multi handle, drained a little at a
//! time as the event loop turns, and only then closed and freed.
//!
//! ## What lives here
//!
//! * [`Shutdown`] — the drain pool (curl's `struct cshutdn`): the list of
//!   connections being shut down, the opaque owning-multi identity, and the
//!   bookkeeping to add/drain/evict them.
//! * [`run_once`] — the single, non-blocking shutdown step for one connection
//!   (`Curl_cshutdn_run_once` / `cshutdn_run_once`): it drives `shutdown` on
//!   **both** socket filter chains and reports whether the teardown is done.
//! * [`terminate`] / [`terminate_with`] — the force-close path
//!   (`Curl_cshutdn_terminate`): run the protocol disconnect handler, optionally
//!   make a final shutdown attempt, close **`SECONDARYSOCKET` before
//!   `FIRSTSOCKET`**, and free the connection (Rust `Drop` replaces
//!   `Curl_conn_free`).
//! * The per-connection shutdown timing helpers ([`shutdown_start`],
//!   [`shutdown_started`], [`shutdown_clear`], [`shutdown_timeleft`]) that mirror
//!   curl's `Curl_shutdown_*` family.
//!
//! ## Memory-safety and cycle avoidance
//!
//! The crate-wide safe-code policy applies here: this module is **100% safe
//! Rust** — no raw pointers, no manual allocation, no FFI. Freeing a connection
//! is expressed purely by letting its owning value drop — the [`Connection`]
//! owns its filter chains and, through them, the live sockets, so a `drop`
//! releases every resource exactly where curl called `Curl_conn_free`.
//!
//! To avoid a module dependency cycle this file never imports `crate::protocols`.
//! curl reaches the protocol teardown through `conn->scheme->run->disconnect`; the
//! rewritten [`Connection`] does not carry that callback, so the protocol
//! disconnect is modeled here as a small [`DisconnectHandler`] trait object that
//! the protocol-dispatch layer supplies. Likewise the multi handle is reached
//! only through the opaque [`MultiId`] identity plus an optional
//! [`MultiNotifier`] callback, so no strong reference cycle can form between a
//! connection, its shutdown pool, and the owning multi.
//!
//! ## `--trace` parity
//!
//! curl emits a distinctive `[SHUTDOWN] …` trace vocabulary while draining
//! connections. That wording is reproduced verbatim (see the `msg_*` helpers)
//! and emitted through [`tracing`] so `--trace` / `--verbose` diagnostics stay
//! byte-for-byte equivalent to curl 8.x.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use crate::conn::filters::Pollset;
use crate::conn::{Connection, MultiId, FIRSTSOCKET, SECONDARYSOCKET};
use crate::error::Result;

// ===========================================================================
// Constants.
// ===========================================================================

/// The default per-connection graceful-shutdown budget, in milliseconds
/// (curl's `DEFAULT_SHUTDOWN_TIMEOUT_MS`).
///
/// A connection that has not finished its graceful teardown within this window
/// is force-closed. curl also caps the *internal* admin handle's overall
/// operation timeout to this value while running blocking protocol disconnect
/// handlers (FTP/IMAP/SMTP/SFTP), so a stuck server cannot hang the default
/// 120-second transfer timeout during shutdown.
pub const DEFAULT_SHUTDOWN_TIMEOUT_MS: u64 = 2000;

/// The `tracing` target under which the `[SHUTDOWN]` diagnostics are emitted.
///
/// curl routes these through its multi-trace channel (`CURL_TRC_M`); the
/// `[SHUTDOWN]` message prefix is what makes them recognizable in `--trace`
/// output, and that prefix is preserved verbatim in the [`msg_*`](msg_shutdown_done)
/// helpers below.
const TRACE_TARGET: &str = "curl::shutdown";

// ===========================================================================
// Trace-message helpers.
//
// The exact wording of every `[SHUTDOWN]` line is factored into these tiny
// pure functions so the strings live in exactly one place, are emitted through
// `tracing`, AND can be asserted directly by the unit tests without having to
// install a tracing subscriber. Each mirrors a `CURL_TRC_M` / `infof` call in
// `lib/cshutdn.c`.
// ===========================================================================

/// `"[SHUTDOWN] shutdown, done=%d"` (`cshutdn.c` line 117). curl formats the
/// boolean with `%d`, i.e. `done=1` / `done=0`, so the numeric form is kept for
/// exact `--trace` parity.
fn msg_shutdown_done(done: bool) -> String {
    format!("[SHUTDOWN] shutdown, done={}", u8::from(done))
}

/// `"[SHUTDOWN] %sclosing connection #%d"` (`cshutdn.c` line 150). The `%s`
/// prefix is `"force "` when the filters have **not** been shut down cleanly
/// (a forced close) and empty otherwise (a graceful close).
fn msg_closing(forced: bool, connection_id: i64) -> String {
    let prefix = if forced { "force " } else { "" };
    format!("[SHUTDOWN] {prefix}closing connection #{connection_id}")
}

/// `"[SHUTDOWN] trigger multi connchanged"` (`cshutdn.c` line 162).
fn msg_connchanged() -> &'static str {
    "[SHUTDOWN] trigger multi connchanged"
}

/// `"connection #%d, shutdown protocol handler (aborted=%d)"` (`cshutdn.c`
/// line 57). Note this line has **no** `[SHUTDOWN]` prefix in curl — it is an
/// `infof`/`DEBUGF` diagnostic, not a `CURL_TRC_M` line — so the prefix is
/// intentionally omitted here too.
fn msg_conn_handler(connection_id: i64, aborted: bool) -> String {
    format!(
        "connection #{connection_id}, shutdown protocol handler (aborted={})",
        u8::from(aborted)
    )
}

// ===========================================================================
// Collaborator abstractions.
//
// curl reaches the protocol teardown via `conn->scheme->run->disconnect` and the
// owning multi via `conn->data->multi`. The rewritten `Connection` carries
// neither, and importing `crate::protocols` (for the disconnect) or
// `crate::multi` (for the notifications) here would create a module cycle
// (protocols and multi both depend on the connection layer). Both collaborators
// are therefore modeled as small trait objects defined locally and supplied by
// the caller through a `ShutdownCx`.
// ===========================================================================

/// A boxed, `Send` future, matching the object-safe async pattern used by the
/// connection-filter layer (`crate::conn::filters::CfFuture`).
///
/// Returning a *named, boxed* future (rather than `async fn` sugar) keeps the
/// [`DisconnectHandler`] trait object-safe, which is required because the
/// concrete disconnect handler is stored and invoked as `dyn DisconnectHandler`.
pub type ShutdownFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The protocol-level disconnect handler for a connection — the rewrite of
/// curl's `conn->scheme->run->disconnect`.
///
/// A concrete implementation (supplied by the protocol-dispatch layer, which
/// depends on the connection layer and therefore cannot be imported here) runs
/// the protocol's graceful goodbye: FTP `QUIT`, IMAP `LOGOUT`, SMTP `QUIT`, the
/// SFTP/SSH channel close, and so on. It is optional: a connection whose scheme
/// has no disconnect handler (curl's `disconnect == NULL`) simply has none
/// supplied, exactly as in curl.
///
/// The `aborted` flag mirrors `conn->bits.aborted` — when the connection is
/// being torn down in an unclean state the handler may skip the polite
/// handshake.
pub trait DisconnectHandler: Send {
    /// Runs the protocol disconnect for `conn`. Any error is treated by the
    /// shutdown manager as "give up gracefully and force-close", exactly as
    /// curl ignores the disconnect handler's return value during teardown.
    fn disconnect<'a>(
        &'a mut self,
        conn: &'a mut Connection,
        aborted: bool,
    ) -> ShutdownFuture<'a, Result<()>>;
}

/// The subset of the owning multi handle the shutdown manager needs to notify —
/// the rewrite of the `Curl_multi_ev_conn_done` + `Curl_multi_connchanged`
/// calls in `Curl_cshutdn_terminate`.
///
/// Modeling this as a callback (rather than importing `crate::multi`) keeps the
/// connection/shutdown layer free of any strong or cyclic reference to the multi
/// handle; the multi handle passes itself as the notifier when it drains the
/// pool.
pub trait MultiNotifier: Send {
    /// A connection has finished shutting down and is about to be freed
    /// (`Curl_multi_ev_conn_done`).
    fn conn_done(&mut self, connection_id: i64);

    /// The set of live connections changed, so the multi should recompute its
    /// socket/timer expectations (`Curl_multi_connchanged`).
    fn connchanged(&mut self);
}

/// The optional collaborators threaded into the shutdown operations that need to
/// reach outside the connection layer.
///
/// All fields are optional so the pure teardown mechanics remain testable in
/// isolation: a connection with no protocol disconnect handler and no attached
/// multi (a perfectly valid curl state) is driven with a
/// [`ShutdownCx::default()`].
#[derive(Default)]
pub struct ShutdownCx<'a> {
    /// The protocol disconnect handler, if the connection's scheme has one.
    pub handler: Option<&'a mut dyn DisconnectHandler>,
    /// The owning-multi notifier, if the connection is attached to a multi.
    pub notifier: Option<&'a mut dyn MultiNotifier>,
    /// Whether the teardown is being driven by curl's internal "admin" handle.
    ///
    /// When `true`, the protocol disconnect handler's timeout is capped to
    /// [`DEFAULT_SHUTDOWN_TIMEOUT_MS`] so a blocking disconnect cannot hang the
    /// default 120-second timeout (curl sets `data->set.timeout` for the
    /// internal handle in `cshutdn_run_conn_handler`).
    pub internal: bool,
}

impl<'a> ShutdownCx<'a> {
    /// Creates an empty context (no handler, no notifier, not internal),
    /// equivalent to [`ShutdownCx::default()`].
    #[must_use]
    pub fn new() -> Self {
        ShutdownCx::default()
    }
}

// ===========================================================================
// Per-connection shutdown timing (curl's `Curl_shutdown_*` family).
//
// curl stores a per-socket start timestamp (`conn->shutdown.start[sockindex]`)
// and a single shutdown budget (`conn->shutdown.timeout_ms`). These free
// functions read/write that state, which lives on the `Connection` as the
// public `shutdown: ShutdownState` field.
// ===========================================================================

/// Records that filter shutdown has started on `sockindex` right now
/// (`Curl_shutdown_start`).
///
/// The per-socket start instant bounds the graceful-teardown window; an
/// out-of-range index is a no-op, matching curl's `CONN_SOCK_IDX_VALID` guard.
pub fn shutdown_start(conn: &mut Connection, sockindex: usize) {
    if let Some(slot) = conn.shutdown.start.get_mut(sockindex) {
        *slot = Some(Instant::now());
    }
}

/// Returns whether filter shutdown has already been started on `sockindex`
/// (`Curl_shutdown_started`). An out-of-range index reports `false`.
#[must_use]
pub fn shutdown_started(conn: &Connection, sockindex: usize) -> bool {
    conn.shutdown
        .start
        .get(sockindex)
        .is_some_and(Option::is_some)
}

/// Clears the shutdown start timestamp for `sockindex` (`Curl_shutdown_clear`).
/// An out-of-range index is a no-op.
pub fn shutdown_clear(conn: &mut Connection, sockindex: usize) {
    if let Some(slot) = conn.shutdown.start.get_mut(sockindex) {
        *slot = None;
    }
}

/// Returns the milliseconds left in the graceful-shutdown window for
/// `sockindex` (`Curl_shutdown_timeleft`).
///
/// The budget is [`ShutdownState::timeout_ms`](crate::conn::ShutdownState) when
/// non-zero, otherwise [`DEFAULT_SHUTDOWN_TIMEOUT_MS`]. The result is **positive**
/// while time remains, and **negative** once the window has been exceeded — the
/// signed convention curl relies on to decide when to force-close. When shutdown
/// has not been started on the socket (or the index is out of range), `0` is
/// returned (no pending deadline), matching curl.
#[must_use]
pub fn shutdown_timeleft(conn: &Connection, sockindex: usize) -> i64 {
    let start = match conn.shutdown.start.get(sockindex).copied().flatten() {
        Some(t) => t,
        None => return 0,
    };
    let budget_ms = if conn.shutdown.timeout_ms == 0 {
        DEFAULT_SHUTDOWN_TIMEOUT_MS
    } else {
        conn.shutdown.timeout_ms
    };
    let timeout = Duration::from_millis(budget_ms);
    let elapsed = start.elapsed();
    if elapsed >= timeout {
        // Window exceeded: report the overage as a negative value.
        let over_ms = i64::try_from((elapsed - timeout).as_millis()).unwrap_or(i64::MAX);
        -over_ms
    } else {
        i64::try_from((timeout - elapsed).as_millis()).unwrap_or(i64::MAX)
    }
}

/// Returns the connection-wide time left for shutdown: the minimum of the time
/// left across every socket whose shutdown has started
/// (`Curl_conn_shutdown_timeleft`).
///
/// Used by [`Shutdown::perform`] to decide when a draining connection has
/// overstayed its window. Returns `0` when no socket has started shutting down.
fn conn_shutdown_timeleft(conn: &Connection) -> i64 {
    let mut min_left: Option<i64> = None;
    for sockindex in [FIRSTSOCKET, SECONDARYSOCKET] {
        if shutdown_started(conn, sockindex) {
            let left = shutdown_timeleft(conn, sockindex);
            min_left = Some(min_left.map_or(left, |m| m.min(left)));
        }
    }
    min_left.unwrap_or(0)
}

// ===========================================================================
// Protocol disconnect handler (curl's `cshutdn_run_conn_handler`).
// ===========================================================================

/// Runs the protocol-level disconnect handler for `conn` exactly once
/// (`cshutdn_run_conn_handler`).
///
/// If the connection's protocol teardown has not yet run
/// (`!conn.bits.shutdown_handler`) and a handler is supplied via
/// [`cx.handler`](ShutdownCx::handler) (curl's
/// `conn->scheme->run->disconnect != NULL`), the handler is invoked with the
/// connection's `aborted` flag. For an internal admin handle
/// ([`cx.internal`](ShutdownCx::internal)) the shutdown budget is first capped
/// to [`DEFAULT_SHUTDOWN_TIMEOUT_MS`] so a blocking disconnect
/// (FTP/IMAP/SMTP/SFTP) cannot hang the default 120-second timeout.
///
/// Regardless of whether a handler was supplied or how it fared,
/// `conn.bits.shutdown_handler` is set to `true` afterward, so a subsequent call
/// is a no-op — mirroring curl, where the handler runs at most once per
/// connection. The handler's error (if any) is intentionally ignored: a failed
/// polite disconnect just means the connection is force-closed next.
pub async fn run_conn_handler(conn: &mut Connection, cx: &mut ShutdownCx<'_>) {
    if conn.bits.shutdown_handler {
        return;
    }

    let internal = cx.internal;
    if let Some(handler) = cx.handler.as_deref_mut() {
        // Some disconnect handlers block on server responses (FTP/IMAP/SMTP and
        // SFTP are among them). When driven by the internal handle, cap the
        // shutdown budget so we do not hang for the default 120 seconds.
        if internal {
            conn.shutdown.timeout_ms = DEFAULT_SHUTDOWN_TIMEOUT_MS;
        }

        let aborted = conn.bits.aborted;
        tracing::trace!(
            target: TRACE_TARGET,
            "{}",
            msg_conn_handler(conn.connection_id, aborted)
        );

        // curl discards the disconnect handler's result during teardown; a
        // failed goodbye simply escalates to a force-close.
        let _ = handler.disconnect(conn, aborted).await;
    }

    conn.bits.shutdown_handler = true;
}

// ===========================================================================
// Run-once shutdown step (curl's `Curl_cshutdn_run_once` / `cshutdn_run_once`).
// ===========================================================================

/// The full run-once step, mirroring `cshutdn_run_once`: start the shutdown
/// clock, run the protocol disconnect handler, then drive filter shutdown on
/// both socket chains.
///
/// Factored out so the public [`run_once`] (which has no handler to supply) and
/// the pool's [`Shutdown::perform`] / [`terminate_with`] (which do) share one
/// implementation, exactly as `cshutdn_run_once` is shared in curl.
async fn run_once_inner(conn: &mut Connection, cx: &mut ShutdownCx<'_>) -> Result<bool> {
    // curl starts the FIRSTSOCKET shutdown clock at the top of cshutdn_run_once.
    if !shutdown_started(conn, FIRSTSOCKET) {
        shutdown_start(conn, FIRSTSOCKET);
    }

    // Run the protocol disconnect handler (idempotent via `shutdown_handler`).
    run_conn_handler(conn, cx).await;

    // If the filters have already been shut down, there is nothing left to do.
    if conn.bits.shutdown_filters {
        let done = true;
        tracing::trace!(target: TRACE_TARGET, "{}", msg_shutdown_done(done));
        return Ok(done);
    }

    // Drive graceful shutdown on BOTH socket chains. A socket with no chain (or
    // one that is not connected) reports "done" immediately — this is handled
    // inside `Connection::shutdown`, which returns `Ok(true)` when there is
    // nothing to tear down, matching curl's `is_connected` guard.
    let r1 = conn.shutdown(FIRSTSOCKET).await;
    let r2 = conn.shutdown(SECONDARYSOCKET).await;

    let done1 = matches!(r1, Ok(true));
    let done2 = matches!(r2, Ok(true));
    let errored = r1.is_err() || r2.is_err();

    // curl's rule: done when EITHER socket errored OR BOTH report success.
    let done = errored || (done1 && done2);
    if done {
        conn.bits.shutdown_filters = true;
    }
    tracing::trace!(target: TRACE_TARGET, "{}", msg_shutdown_done(done));
    Ok(done)
}

/// Runs the shutdown of `conn` once (`Curl_cshutdn_run_once`).
///
/// Drives `shutdown` on both socket filter chains and reports whether the
/// teardown is complete. Per curl's semantics the connection is **done** when
/// *either* socket's shutdown errored *or* *both* sockets report success; a
/// socket with no filter chain is treated as immediately done. On completion
/// `conn.bits.shutdown_filters` is set so the work is not repeated, and the
/// `[SHUTDOWN] shutdown, done=…` trace line is emitted for `--trace` parity.
///
/// # Errors
/// Never returns `Err` in practice: per-socket shutdown failures are folded into
/// `done == true` (curl treats an errored shutdown as "finished, force-close
/// next"), exactly as `cshutdn_run_once` swallows the per-socket `CURLcode`. The
/// `Result` is retained to match the fallible connection-layer API and to allow
/// a genuinely fatal error to propagate in the future.
pub async fn run_once(conn: &mut Connection) -> Result<bool> {
    let mut cx = ShutdownCx::default();
    run_once_inner(conn, &mut cx).await
}

// ===========================================================================
// Terminate / force-close (curl's `Curl_cshutdn_terminate`).
// ===========================================================================

/// Terminates `conn`: force-closes and frees it, optionally running a final
/// graceful shutdown first (`Curl_cshutdn_terminate`).
///
/// This is the convenience form used when there is no protocol disconnect
/// handler and no multi to notify (a detached / best-effort close). It is
/// equivalent to [`terminate_with`] with an internal, handler-less,
/// notifier-less [`ShutdownCx`].
///
/// Takes ownership of `conn`; when the function returns the connection has been
/// closed and dropped.
pub async fn terminate(conn: Connection, do_shutdown: bool) {
    let mut cx = ShutdownCx {
        internal: true,
        ..ShutdownCx::default()
    };
    terminate_with(conn, do_shutdown, &mut cx).await;
}

/// Terminates `conn` with explicit collaborators (`Curl_cshutdn_terminate`).
///
/// The sequence mirrors curl exactly:
/// 1. Run the protocol disconnect handler (via [`cx.handler`](ShutdownCx::handler)).
/// 2. If `do_shutdown` and the filters have not already been shut down, make one
///    last [`run_once`] attempt.
/// 3. Emit `[SHUTDOWN] closing connection #…` (prefixed `force ` when the
///    filters were not shut down cleanly).
/// 4. Close **`SECONDARYSOCKET` first, then `FIRSTSOCKET`** — curl's exact
///    ordering (`Curl_conn_close(SECONDARYSOCKET)` then
///    `Curl_conn_close(FIRSTSOCKET)`).
/// 5. Notify the multi that the connection is done (`Curl_multi_ev_conn_done`),
///    then that the connection set changed (`Curl_multi_connchanged`), via
///    [`cx.notifier`](ShutdownCx::notifier).
/// 6. Free the connection — expressed by dropping the owned value, which tears
///    down its filter chains and sockets (Rust's replacement for
///    `Curl_conn_free`; no manual free, all in safe Rust).
///
/// [`cx.internal`](ShutdownCx::internal) selects curl's internal-admin-handle
/// behavior (capping a blocking disconnect handler's timeout).
///
/// The collaborators are threaded as a single `&mut ShutdownCx` (rather than
/// separate `Option<&mut dyn …>` arguments) so this async operation can be
/// invoked repeatedly in the pool's drain loops by reborrowing `&mut *cx` —
/// sequential reborrows of one `&mut` are exactly what the borrow checker
/// permits across `.await` points, whereas reborrowing the individual
/// trait-object fields in a loop is not.
///
/// In debug builds this asserts the connection has already been removed from the
/// connection pool (`!conn.bits.in_cpool`), matching curl's `DEBUGASSERT`.
pub async fn terminate_with(mut conn: Connection, do_shutdown: bool, cx: &mut ShutdownCx<'_>) {
    // The connection must have been removed from the pool before termination.
    debug_assert!(
        !conn.bits.in_cpool,
        "terminate: connection #{} must be removed from the pool first",
        conn.connection_id
    );

    // 1. Protocol disconnect handler.
    run_conn_handler(&mut conn, cx).await;

    // 2. A last attempt to shut the filters down, if requested and not done.
    if do_shutdown && !conn.bits.shutdown_filters {
        let _ = run_once_inner(&mut conn, cx).await;
    }

    // 3. Trace the (possibly forced) close.
    let forced = !conn.bits.shutdown_filters;
    let connection_id = conn.connection_id;
    tracing::trace!(target: TRACE_TARGET, "{}", msg_closing(forced, connection_id));

    // 4. Close SECONDARYSOCKET first, then FIRSTSOCKET (curl's exact order).
    conn.close(SECONDARYSOCKET);
    conn.close(FIRSTSOCKET);

    // 5. Notify the owning multi: first that this connection is done, then that
    //    the connection set changed.
    if let Some(notifier) = cx.notifier.as_deref_mut() {
        notifier.conn_done(connection_id);
        tracing::trace!(target: TRACE_TARGET, "{}", msg_connchanged());
        notifier.connchanged();
    }

    // 6. Free the connection: dropping the owned value releases its filter
    //    chains and sockets. This is Rust's replacement for `Curl_conn_free`.
    drop(conn);
}

// ===========================================================================
// The shutdown pool (curl's `struct cshutdn`).
// ===========================================================================

/// The multi handle's pool of connections being gracefully shut down (curl's
/// `struct cshutdn`).
///
/// A [`Shutdown`] owns the connections it is draining: each is pushed onto an
/// ordered list (oldest at the front), driven a step at a time by
/// [`perform`](Shutdown::perform) as the event loop turns, and terminated once
/// it finishes or overstays its window. The pool is always owned by exactly one
/// multi handle; that ownership is recorded as the opaque [`MultiId`] identity
/// (compared, never dereferenced), so no reference cycle can form between the
/// pool and its multi.
///
/// Dropping the pool force-closes any still-draining connections (see the
/// [`Drop`] impl); to shut them down *gracefully* first, call
/// [`terminate_all`](Shutdown::terminate_all) before the pool is dropped — the
/// async equivalent of curl's `Curl_cshutdn_destroy`, which Rust cannot express
/// in `Drop` because `Drop` is synchronous.
#[derive(Debug)]
pub struct Shutdown {
    /// Connections being shut down, oldest first (`cshutdn->list`).
    list: VecDeque<Connection>,
    /// The opaque identity of the owning multi handle (`cshutdn->multi`).
    multi: Option<MultiId>,
    /// The multi's total connection cap (`multi->max_total_connections`); `0`
    /// means unlimited. When adding would breach the cap, the oldest draining
    /// connection is evicted to make room.
    max_total_connections: usize,
    /// Whether the pool was created via [`init`](Shutdown::init)
    /// (`cshutdn->initialised`).
    initialised: bool,
}

impl Default for Shutdown {
    /// Creates an uninitialised, unattached pool (no owning multi, unlimited
    /// cap). Prefer [`Shutdown::init`] to attach it to a multi handle.
    fn default() -> Self {
        Shutdown {
            list: VecDeque::new(),
            multi: None,
            max_total_connections: 0,
            initialised: false,
        }
    }
}

impl Shutdown {
    /// Initializes the pool as part of the given multi handle
    /// (`Curl_cshutdn_init`).
    ///
    /// `multi` is the opaque identity of the owning handle and
    /// `max_total_connections` is that multi's total connection cap (`0` for
    /// unlimited), used by [`add`](Shutdown::add) to evict the oldest draining
    /// connection when the limit would be exceeded.
    #[must_use]
    pub fn init(multi: MultiId, max_total_connections: usize) -> Self {
        Shutdown {
            list: VecDeque::new(),
            multi: Some(multi),
            max_total_connections,
            initialised: true,
        }
    }

    /// The number of connections currently being shut down
    /// (`Curl_cshutdn_count`).
    #[must_use]
    pub fn count(&self) -> usize {
        self.list.len()
    }

    /// Whether the pool has no connections draining.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// The number of draining connections whose reuse key equals `destination`
    /// (`Curl_cshutdn_dest_count`).
    #[must_use]
    pub fn dest_count(&self, destination: &str) -> usize {
        self.list
            .iter()
            .filter(|conn| conn.destination == destination)
            .count()
    }

    /// The opaque identity of the owning multi handle, if the pool has been
    /// [`init`](Shutdown::init)ialized.
    #[must_use]
    pub fn multi_id(&self) -> Option<MultiId> {
        self.multi
    }

    /// Adds `conn` to the drain list for non-blocking shutdown
    /// (`Curl_cshutdn_add`).
    ///
    /// `conns_in_pool` is the number of connections still held in the live
    /// connection pool; when the multi's total cap
    /// ([`max_total_connections`](Shutdown::max_total_connections)) would be
    /// breached by the combined live + draining count, the oldest draining
    /// connection is evicted first (`cshutdn_destroy_oldest`) to make room. The
    /// new connection is then appended (becoming the newest), preserving the
    /// oldest-first ordering the drain loop relies on.
    pub async fn add(&mut self, conn: Connection, conns_in_pool: usize, cx: &mut ShutdownCx<'_>) {
        let max_total = self.max_total_connections;
        if max_total > 0 && max_total <= conns_in_pool + self.list.len() {
            tracing::trace!(
                target: TRACE_TARGET,
                "[SHUTDOWN] discarding oldest shutdown connection due to connection limit of {max_total}"
            );
            self.destroy_oldest(None, cx).await;
        }

        let connection_id = conn.connection_id;
        self.list.push_back(conn);
        tracing::trace!(
            target: TRACE_TARGET,
            "[SHUTDOWN] added #{connection_id} to shutdowns, now {} conns in shutdown",
            self.list.len()
        );
    }

    /// Force-terminates the oldest draining connection, optionally restricted to
    /// one `destination`, to make room (`cshutdn_destroy_oldest`).
    ///
    /// Returns `true` if a connection was found and terminated. When
    /// `destination` is `None` the front (oldest) connection is taken; otherwise
    /// the oldest connection whose reuse key matches is taken.
    pub async fn destroy_oldest(
        &mut self,
        destination: Option<&str>,
        cx: &mut ShutdownCx<'_>,
    ) -> bool {
        let position = match destination {
            None => (!self.list.is_empty()).then_some(0),
            Some(dest) => self.list.iter().position(|conn| conn.destination == dest),
        };

        let Some(index) = position else {
            return false;
        };
        let Some(conn) = self.list.remove(index) else {
            return false;
        };

        terminate_with(conn, false, cx).await;
        true
    }

    /// Closes the oldest draining connection to `destination` (or any, when
    /// `None`) (`Curl_cshutdn_close_oldest`). Returns `true` if one was closed.
    pub async fn close_oldest(
        &mut self,
        destination: Option<&str>,
        cx: &mut ShutdownCx<'_>,
    ) -> bool {
        self.destroy_oldest(destination, cx).await
    }

    /// Runs one maintenance pass over every draining connection
    /// (`Curl_cshutdn_perform`).
    ///
    /// Each connection gets a [`run_once`] step; those that finish, or that have
    /// exceeded their [`shutdown_timeleft`], are removed and
    /// [`terminate_with`]-ed. Returns `true` when connections remain in the pool
    /// afterward, so the caller (the multi handle) knows to schedule another
    /// wakeup — the Rust analog of curl arming `EXPIRE_SHUTDOWN`.
    ///
    /// # Errors
    /// Never returns `Err` in practice (per-connection shutdown errors are
    /// absorbed as "done", matching [`run_once`]); the `Result` mirrors the
    /// fallible connection-layer API.
    pub async fn perform(&mut self, cx: &mut ShutdownCx<'_>) -> Result<bool> {
        if self.list.is_empty() {
            return Ok(false);
        }

        tracing::trace!(
            target: TRACE_TARGET,
            "[SHUTDOWN] perform on {} connections",
            self.list.len()
        );

        let mut remaining: VecDeque<Connection> = VecDeque::with_capacity(self.list.len());
        let mut finished: Vec<Connection> = Vec::new();

        while let Some(mut conn) = self.list.pop_front() {
            let done = run_once_inner(&mut conn, &mut *cx).await.unwrap_or(true);
            // A connection that finished, or overstayed its shutdown window, is
            // terminated; the rest are kept for the next pass.
            let timed_out = conn_shutdown_timeleft(&conn) < 0;
            if done || timed_out {
                finished.push(conn);
            } else {
                remaining.push_back(conn);
            }
        }

        self.list = remaining;

        for conn in finished {
            terminate_with(conn, false, &mut *cx).await;
        }

        Ok(!self.list.is_empty())
    }

    /// Gracefully drains and terminates every remaining connection, bounded by
    /// `timeout_ms` (`cshutdn_terminate_all`, reached from `Curl_cshutdn_destroy`).
    ///
    /// This is the async counterpart to curl's synchronous destroy path: it
    /// repeatedly [`perform`](Shutdown::perform)s, yielding briefly between
    /// passes via [`tokio::time`], until the pool empties or the budget is spent;
    /// any still-draining connections are then force-terminated. A `timeout_ms`
    /// of `0` means "best effort" — a single pass, then force-close the rest.
    pub async fn terminate_all(&mut self, cx: &mut ShutdownCx<'_>, timeout_ms: u64) {
        tracing::trace!(target: TRACE_TARGET, "[SHUTDOWN] shutdown all");
        let started = Instant::now();

        while !self.list.is_empty() {
            let _ = self.perform(&mut *cx).await;

            if self.list.is_empty() {
                tracing::trace!(target: TRACE_TARGET, "[SHUTDOWN] shutdown finished cleanly");
                break;
            }

            let spent_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            if spent_ms >= timeout_ms {
                tracing::trace!(
                    target: TRACE_TARGET,
                    "[SHUTDOWN] shutdown finished, {}",
                    if timeout_ms > 0 { "timeout" } else { "best effort done" }
                );
                break;
            }

            // Wait a little before the next pass. curl polls the draining
            // sockets (`cshutdn_wait`) with `CURLMIN(timeout, 1000)`; here we
            // cap the inter-pass delay similarly via Tokio's timer so we neither
            // busy-spin nor oversleep past the remaining budget.
            let remain_ms = timeout_ms - spent_ms;
            let nap_ms = remain_ms.min(50);
            tokio::time::sleep(Duration::from_millis(nap_ms)).await;
        }

        // Force-terminate anything still draining after the graceful window.
        while let Some(conn) = self.list.pop_front() {
            terminate_with(conn, false, &mut *cx).await;
        }
    }

    /// Adds the sockets (and their readiness interests) of every draining
    /// connection to `pfds` (`Curl_cshutdn_add_pollfds`).
    ///
    /// Used by `curl_multi_poll` to include shutting-down connections in the
    /// poll set. Each connection's per-socket filter chains contribute their
    /// interests via [`FilterChain::adjust_pollset`](crate::conn::filters::FilterChain::adjust_pollset),
    /// accumulated into the shared [`Pollset`].
    pub fn add_pollfds(&self, pfds: &mut Pollset) {
        for conn in &self.list {
            for chain in conn.cfilter.iter().flatten() {
                chain.adjust_pollset(pfds);
            }
        }
    }

    /// Adds the sockets of every draining connection to `wfds` and returns how
    /// many socket interests were contributed (`Curl_cshutdn_add_waitfds`).
    ///
    /// Used by `curl_multi_wait`; the return count lets the caller size its wait
    /// array, mirroring curl's `unsigned int` return.
    pub fn add_waitfds(&self, wfds: &mut Pollset) -> u32 {
        let before = wfds.len();
        self.add_pollfds(wfds);
        u32::try_from(wfds.len().saturating_sub(before)).unwrap_or(u32::MAX)
    }
}

impl Drop for Shutdown {
    /// Force-closes any still-draining connections when the pool is dropped
    /// (the synchronous fallback of `Curl_cshutdn_destroy`).
    ///
    /// A graceful drain cannot run here because `Drop` is synchronous — call
    /// [`terminate_all`](Shutdown::terminate_all) beforehand for that. Each
    /// remaining connection has its sockets closed in curl's order
    /// (`SECONDARYSOCKET` then `FIRSTSOCKET`) and is then dropped, which releases
    /// its filter chains and sockets.
    fn drop(&mut self) {
        if self.initialised && !self.list.is_empty() {
            tracing::trace!(
                target: TRACE_TARGET,
                "[SHUTDOWN] destroy, {} connections force-closed at drop",
                self.list.len()
            );
            while let Some(mut conn) = self.list.pop_front() {
                conn.close(SECONDARYSOCKET);
                conn.close(FIRSTSOCKET);
                // `conn` is dropped here, releasing its chains and sockets.
            }
        }
        self.multi = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};

    use crate::conn::filters::{CfFuture, ConnectionFilter, FilterChain, FilterCtx};
    use crate::conn::{CfType, Scheme};
    use crate::error::Error;

    // -----------------------------------------------------------------------
    // Test doubles.
    // -----------------------------------------------------------------------

    /// How a [`RecordingFilter`]'s `shutdown` should behave.
    #[derive(Debug, Clone, Copy)]
    enum ShutdownBehavior {
        /// Report shutdown complete (`Ok(true)`).
        DoneOk,
        /// Report shutdown still in progress (`Ok(false)`).
        NotDone,
        /// Fail the shutdown (`Err`).
        Fail,
    }

    /// A mock connection filter that records the socket index it is closed on
    /// (so close-ordering can be asserted) and produces a configurable
    /// `shutdown` outcome.
    struct RecordingFilter {
        closed: Arc<Mutex<Vec<usize>>>,
        behavior: ShutdownBehavior,
    }

    impl ConnectionFilter for RecordingFilter {
        fn name(&self) -> &'static str {
            "MOCK"
        }

        fn cf_type(&self) -> CfType {
            CfType::IP_CONNECT
        }

        fn connect<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            _blocking: bool,
        ) -> CfFuture<'a, Result<bool>> {
            // Connect immediately so the chain marks this filter connected,
            // which is what makes `shutdown` actually walk it.
            Box::pin(async { Ok(true) })
        }

        fn shutdown<'a>(&'a mut self, _cx: &'a mut FilterCtx<'_>) -> CfFuture<'a, Result<bool>> {
            let behavior = self.behavior;
            Box::pin(async move {
                match behavior {
                    ShutdownBehavior::DoneOk => Ok(true),
                    ShutdownBehavior::NotDone => Ok(false),
                    ShutdownBehavior::Fail => Err(Error::Send),
                }
            })
        }

        fn close(&mut self, cx: &mut FilterCtx<'_>) {
            self.closed
                .lock()
                .expect("closed lock")
                .push(cx.sockindex());
            cx.close_next();
        }
    }

    /// A mock protocol disconnect handler that counts its invocations.
    struct CountingDisconnect {
        calls: Arc<Mutex<u32>>,
    }

    impl DisconnectHandler for CountingDisconnect {
        fn disconnect<'a>(
            &'a mut self,
            _conn: &'a mut Connection,
            _aborted: bool,
        ) -> ShutdownFuture<'a, Result<()>> {
            let calls = Arc::clone(&self.calls);
            Box::pin(async move {
                *calls.lock().expect("calls lock") += 1;
                Ok(())
            })
        }
    }

    /// A mock multi notifier that records the events the shutdown manager sends.
    #[derive(Default)]
    struct RecordingNotifier {
        done_ids: Vec<i64>,
        connchanged_calls: u32,
    }

    impl MultiNotifier for RecordingNotifier {
        fn conn_done(&mut self, connection_id: i64) {
            self.done_ids.push(connection_id);
        }

        fn connchanged(&mut self) {
            self.connchanged_calls += 1;
        }
    }

    // -----------------------------------------------------------------------
    // Builders.
    // -----------------------------------------------------------------------

    /// A minimal `https` scheme (TLS on, port 443).
    fn https_scheme() -> Scheme {
        let mut scheme = Scheme::new("https", 443);
        scheme.is_ssl = true;
        scheme
    }

    /// A bare connection with the given id and reuse key, no filter chains.
    fn make_conn(id: i64, destination: &str) -> Connection {
        let mut conn = Connection::new(https_scheme(), "example.com", 443);
        conn.connection_id = id;
        conn.destination = destination.to_string();
        conn
    }

    /// Installs a freshly connected mock chain at `sockindex`, recording closes
    /// into `closed` and shutting down per `behavior`.
    async fn install_chain(
        conn: &mut Connection,
        sockindex: usize,
        behavior: ShutdownBehavior,
        closed: Arc<Mutex<Vec<usize>>>,
    ) {
        let mut chain = FilterChain::new(sockindex);
        chain.add(Box::new(RecordingFilter { closed, behavior }));
        chain.connect(true).await.expect("mock connect");
        conn.cfilter[sockindex] = Some(chain);
    }

    // -----------------------------------------------------------------------
    // Trace-wording parity (curl `--trace`).
    // -----------------------------------------------------------------------

    #[test]
    fn trace_strings_match_curl_wording() {
        assert_eq!(msg_shutdown_done(true), "[SHUTDOWN] shutdown, done=1");
        assert_eq!(msg_shutdown_done(false), "[SHUTDOWN] shutdown, done=0");
        assert_eq!(msg_closing(false, 5), "[SHUTDOWN] closing connection #5");
        assert_eq!(
            msg_closing(true, 5),
            "[SHUTDOWN] force closing connection #5"
        );
        assert_eq!(msg_connchanged(), "[SHUTDOWN] trigger multi connchanged");
        assert_eq!(
            msg_conn_handler(7, false),
            "connection #7, shutdown protocol handler (aborted=0)"
        );
        assert_eq!(
            msg_conn_handler(7, true),
            "connection #7, shutdown protocol handler (aborted=1)"
        );
    }

    // -----------------------------------------------------------------------
    // Per-connection timing.
    // -----------------------------------------------------------------------

    #[test]
    fn shutdown_start_started_clear_roundtrip() {
        let mut conn = make_conn(1, "0/443/example.com");
        assert!(!shutdown_started(&conn, FIRSTSOCKET));
        shutdown_start(&mut conn, FIRSTSOCKET);
        assert!(shutdown_started(&conn, FIRSTSOCKET));
        shutdown_clear(&mut conn, FIRSTSOCKET);
        assert!(!shutdown_started(&conn, FIRSTSOCKET));
        // Out-of-range indices are inert.
        assert!(!shutdown_started(&conn, 99));
    }

    #[test]
    fn shutdown_timeleft_zero_when_not_started() {
        let conn = make_conn(1, "0/443/example.com");
        assert_eq!(shutdown_timeleft(&conn, FIRSTSOCKET), 0);
    }

    #[test]
    fn shutdown_timeleft_positive_within_window() {
        let mut conn = make_conn(1, "0/443/example.com");
        conn.shutdown.timeout_ms = DEFAULT_SHUTDOWN_TIMEOUT_MS;
        shutdown_start(&mut conn, FIRSTSOCKET);
        let left = shutdown_timeleft(&conn, FIRSTSOCKET);
        assert!(left > 0, "expected positive time left, got {left}");
        assert!(
            left <= i64::try_from(DEFAULT_SHUTDOWN_TIMEOUT_MS).unwrap(),
            "time left {left} should not exceed the budget"
        );
    }

    #[test]
    fn shutdown_timeleft_negative_after_timeout() {
        let mut conn = make_conn(1, "0/443/example.com");
        // Tiny budget so a short, deterministic real sleep exceeds it.
        conn.shutdown.timeout_ms = 1;
        shutdown_start(&mut conn, FIRSTSOCKET);
        std::thread::sleep(Duration::from_millis(15));
        let left = shutdown_timeleft(&conn, FIRSTSOCKET);
        assert!(
            left < 0,
            "expected negative time left after timeout, got {left}"
        );
    }

    #[test]
    fn shutdown_timeleft_uses_default_budget_when_unset() {
        let mut conn = make_conn(1, "0/443/example.com");
        // timeout_ms left at 0 -> the DEFAULT_SHUTDOWN_TIMEOUT_MS budget applies.
        assert_eq!(conn.shutdown.timeout_ms, 0);
        shutdown_start(&mut conn, FIRSTSOCKET);
        let left = shutdown_timeleft(&conn, FIRSTSOCKET);
        assert!(left > 0);
        assert!(left <= i64::try_from(DEFAULT_SHUTDOWN_TIMEOUT_MS).unwrap());
    }

    // -----------------------------------------------------------------------
    // run_once done-semantics.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn run_once_done_when_both_socket_chains_done() {
        let closed = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(1, "0/443/example.com");
        install_chain(
            &mut conn,
            FIRSTSOCKET,
            ShutdownBehavior::DoneOk,
            Arc::clone(&closed),
        )
        .await;
        install_chain(&mut conn, SECONDARYSOCKET, ShutdownBehavior::DoneOk, closed).await;

        let done = run_once(&mut conn).await.expect("run_once");
        assert!(done, "both chains report done => connection is done");
        assert!(conn.bits.shutdown_filters, "shutdown_filters set when done");
    }

    #[tokio::test]
    async fn run_once_done_when_second_socket_absent() {
        let closed = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(1, "0/443/example.com");
        // Only FIRSTSOCKET has a chain; SECONDARYSOCKET (no chain) is done.
        install_chain(&mut conn, FIRSTSOCKET, ShutdownBehavior::DoneOk, closed).await;

        let done = run_once(&mut conn).await.expect("run_once");
        assert!(done);
        assert!(conn.bits.shutdown_filters);
    }

    #[tokio::test]
    async fn run_once_done_when_a_socket_errors() {
        let closed = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(1, "0/443/example.com");
        install_chain(&mut conn, FIRSTSOCKET, ShutdownBehavior::Fail, closed).await;

        // Either socket erroring means the connection is treated as done.
        let done = run_once(&mut conn).await.expect("run_once");
        assert!(
            done,
            "an errored shutdown counts as done (force-close next)"
        );
        assert!(conn.bits.shutdown_filters);
    }

    #[tokio::test]
    async fn run_once_not_done_when_a_socket_pending() {
        let closed = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(1, "0/443/example.com");
        install_chain(&mut conn, FIRSTSOCKET, ShutdownBehavior::NotDone, closed).await;

        let done = run_once(&mut conn).await.expect("run_once");
        assert!(
            !done,
            "a still-draining socket keeps the connection not-done"
        );
        assert!(!conn.bits.shutdown_filters);
    }

    #[tokio::test]
    async fn run_once_no_chains_is_immediately_done() {
        let mut conn = make_conn(1, "0/443/example.com");
        let done = run_once(&mut conn).await.expect("run_once");
        assert!(done, "no filter chains => nothing to tear down => done");
        assert!(conn.bits.shutdown_filters);
        // The protocol handler was marked run even without a handler supplied.
        assert!(conn.bits.shutdown_handler);
        // The FIRSTSOCKET shutdown clock was started.
        assert!(shutdown_started(&conn, FIRSTSOCKET));
    }

    // -----------------------------------------------------------------------
    // Protocol disconnect handler.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn internal_handle_caps_timeout_and_runs_handler() {
        let calls = Arc::new(Mutex::new(0));
        let mut handler = CountingDisconnect {
            calls: Arc::clone(&calls),
        };
        let mut conn = make_conn(1, "0/443/example.com");
        assert_eq!(conn.shutdown.timeout_ms, 0);

        let mut cx = ShutdownCx {
            handler: Some(&mut handler),
            notifier: None,
            internal: true,
        };
        run_conn_handler(&mut conn, &mut cx).await;

        assert_eq!(
            conn.shutdown.timeout_ms, DEFAULT_SHUTDOWN_TIMEOUT_MS,
            "internal handle caps the shutdown budget to the default"
        );
        assert_eq!(*calls.lock().unwrap(), 1, "the disconnect handler ran once");
        assert!(
            conn.bits.shutdown_handler,
            "shutdown_handler set after running"
        );
    }

    #[tokio::test]
    async fn non_internal_handle_does_not_cap_timeout() {
        let calls = Arc::new(Mutex::new(0));
        let mut handler = CountingDisconnect {
            calls: Arc::clone(&calls),
        };
        let mut conn = make_conn(1, "0/443/example.com");

        let mut cx = ShutdownCx {
            handler: Some(&mut handler),
            notifier: None,
            internal: false,
        };
        run_conn_handler(&mut conn, &mut cx).await;

        assert_eq!(
            conn.shutdown.timeout_ms, 0,
            "non-internal handle leaves the budget alone"
        );
        assert_eq!(*calls.lock().unwrap(), 1);
        assert!(conn.bits.shutdown_handler);
    }

    #[tokio::test]
    async fn conn_handler_idempotent_and_noop_without_handler() {
        // No handler supplied: still marks the protocol teardown as run.
        let mut conn = make_conn(1, "0/443/example.com");
        let mut empty_cx = ShutdownCx {
            handler: None,
            notifier: None,
            internal: true,
        };
        run_conn_handler(&mut conn, &mut empty_cx).await;
        assert!(conn.bits.shutdown_handler);

        // Already-run handler is not invoked again.
        let calls = Arc::new(Mutex::new(0));
        let mut handler = CountingDisconnect {
            calls: Arc::clone(&calls),
        };
        let mut cx = ShutdownCx {
            handler: Some(&mut handler),
            notifier: None,
            internal: true,
        };
        run_conn_handler(&mut conn, &mut cx).await;
        assert_eq!(
            *calls.lock().unwrap(),
            0,
            "handler skipped once already shut down"
        );
    }

    // -----------------------------------------------------------------------
    // terminate: close ordering, notification, freeing.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn terminate_closes_secondary_before_first() {
        let closed = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(1, "0/443/example.com");
        install_chain(
            &mut conn,
            FIRSTSOCKET,
            ShutdownBehavior::DoneOk,
            Arc::clone(&closed),
        )
        .await;
        install_chain(
            &mut conn,
            SECONDARYSOCKET,
            ShutdownBehavior::DoneOk,
            Arc::clone(&closed),
        )
        .await;

        terminate(conn, false).await;

        let order = closed.lock().unwrap().clone();
        assert_eq!(
            order,
            vec![SECONDARYSOCKET, FIRSTSOCKET],
            "curl closes SECONDARYSOCKET before FIRSTSOCKET"
        );
    }

    #[tokio::test]
    async fn terminate_with_notifies_multi_conn_done_then_connchanged() {
        let mut notifier = RecordingNotifier::default();
        let conn = make_conn(42, "0/443/example.com");

        {
            let mut cx = ShutdownCx {
                handler: None,
                notifier: Some(&mut notifier),
                internal: true,
            };
            terminate_with(conn, false, &mut cx).await;
        } // `cx` dropped here, releasing the `&mut notifier` borrow.

        assert_eq!(
            notifier.done_ids,
            vec![42],
            "conn_done fired with the connection id"
        );
        assert_eq!(
            notifier.connchanged_calls, 1,
            "connchanged fired exactly once"
        );
    }

    #[tokio::test]
    async fn terminate_with_do_shutdown_runs_final_pass() {
        // A connection whose chain reports done: terminate(do_shutdown=true)
        // completes the graceful shutdown, so the close is NOT forced.
        let closed = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(1, "0/443/example.com");
        install_chain(&mut conn, FIRSTSOCKET, ShutdownBehavior::DoneOk, closed).await;

        let mut notifier = RecordingNotifier::default();
        {
            let mut cx = ShutdownCx {
                handler: None,
                notifier: Some(&mut notifier),
                internal: true,
            };
            terminate_with(conn, true, &mut cx).await;
        } // `cx` dropped here, releasing the `&mut notifier` borrow.
        assert_eq!(notifier.done_ids, vec![1]);
        assert_eq!(notifier.connchanged_calls, 1);
    }

    // -----------------------------------------------------------------------
    // Pool bookkeeping.
    // -----------------------------------------------------------------------

    #[test]
    fn init_and_counts() {
        let mut pool = Shutdown::init(MultiId(7), 0);
        assert!(pool.is_empty());
        assert_eq!(pool.count(), 0);
        assert_eq!(pool.multi_id(), Some(MultiId(7)));
        pool.list.push_back(make_conn(1, "0/443/a"));
        pool.list.push_back(make_conn(2, "0/443/a"));
        pool.list.push_back(make_conn(3, "0/80/b"));
        assert_eq!(pool.count(), 3);
        assert_eq!(pool.dest_count("0/443/a"), 2);
        assert_eq!(pool.dest_count("0/80/b"), 1);
        assert_eq!(pool.dest_count("0/21/none"), 0);
    }

    #[tokio::test]
    async fn add_beyond_capacity_evicts_oldest() {
        let mut pool = Shutdown::init(MultiId(1), 2);
        let mut cx = ShutdownCx::default();

        pool.add(make_conn(1, "0/443/a"), 0, &mut cx).await;
        pool.add(make_conn(2, "0/443/a"), 0, &mut cx).await;
        // Adding the third breaches the cap of 2 => the oldest (#1) is evicted.
        pool.add(make_conn(3, "0/443/a"), 0, &mut cx).await;

        assert_eq!(pool.count(), 2, "capacity is enforced");
        let ids: Vec<i64> = pool.list.iter().map(|c| c.connection_id).collect();
        assert_eq!(
            ids,
            vec![2, 3],
            "the oldest connection was evicted, order preserved"
        );
    }

    #[tokio::test]
    async fn destroy_oldest_matches_destination() {
        let mut pool = Shutdown::init(MultiId(1), 0);
        let mut cx = ShutdownCx::default();
        pool.list.push_back(make_conn(1, "0/443/a"));
        pool.list.push_back(make_conn(2, "0/80/b"));
        pool.list.push_back(make_conn(3, "0/80/b"));

        // Destroy the oldest connection to destination "b" (#2), leaving #1 and #3.
        let removed = pool.destroy_oldest(Some("0/80/b"), &mut cx).await;
        assert!(removed);
        let ids: Vec<i64> = pool.list.iter().map(|c| c.connection_id).collect();
        assert_eq!(ids, vec![1, 3]);

        // No connection to a missing destination.
        assert!(!pool.destroy_oldest(Some("0/21/none"), &mut cx).await);
    }

    #[tokio::test]
    async fn perform_drains_finished_and_reports_remaining() {
        let mut pool = Shutdown::init(MultiId(1), 0);
        let mut cx = ShutdownCx::default();

        // #1 has no chains => finishes immediately and is terminated.
        pool.add(make_conn(1, "0/443/a"), 0, &mut cx).await;

        // #2 has a still-draining chain => remains after the pass.
        let closed = Arc::new(Mutex::new(Vec::new()));
        let mut pending = make_conn(2, "0/443/a");
        install_chain(&mut pending, FIRSTSOCKET, ShutdownBehavior::NotDone, closed).await;
        pool.add(pending, 0, &mut cx).await;

        let more = pool.perform(&mut cx).await.expect("perform");
        assert!(more, "a still-draining connection means more work remains");
        assert_eq!(pool.count(), 1);
        assert_eq!(pool.list.front().unwrap().connection_id, 2);
    }

    #[tokio::test]
    async fn perform_terminates_timed_out_connection() {
        let mut pool = Shutdown::init(MultiId(1), 0);
        let mut cx = ShutdownCx::default();

        let closed = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(9, "0/443/a");
        install_chain(&mut conn, FIRSTSOCKET, ShutdownBehavior::NotDone, closed).await;
        // Give it a tiny budget and start its clock in the (real) past via sleep.
        conn.shutdown.timeout_ms = 1;
        shutdown_start(&mut conn, FIRSTSOCKET);
        pool.list.push_back(conn);
        std::thread::sleep(Duration::from_millis(15));

        let more = pool.perform(&mut cx).await.expect("perform");
        assert!(
            !more,
            "the timed-out connection is terminated, leaving the pool empty"
        );
        assert_eq!(pool.count(), 0);
    }

    #[tokio::test]
    async fn perform_on_empty_pool_reports_no_work() {
        let mut pool = Shutdown::init(MultiId(1), 0);
        let mut cx = ShutdownCx::default();
        assert!(!pool.perform(&mut cx).await.expect("perform"));
    }

    #[tokio::test]
    async fn terminate_all_drains_everything() {
        let mut pool = Shutdown::init(MultiId(1), 0);
        let mut cx = ShutdownCx::default();
        pool.add(make_conn(1, "0/443/a"), 0, &mut cx).await;
        pool.add(make_conn(2, "0/443/a"), 0, &mut cx).await;

        pool.terminate_all(&mut cx, 0).await;
        assert!(pool.is_empty(), "best-effort terminate_all clears the pool");
    }

    // -----------------------------------------------------------------------
    // Poll/wait fd exposure.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn add_pollfds_and_waitfds_expose_draining_sockets() {
        let mut pool = Shutdown::init(MultiId(1), 0);
        let mut cx = ShutdownCx::default();
        let closed = Arc::new(Mutex::new(Vec::new()));
        let mut conn = make_conn(1, "0/443/a");
        install_chain(&mut conn, FIRSTSOCKET, ShutdownBehavior::NotDone, closed).await;
        pool.add(conn, 0, &mut cx).await;

        // The mock socket filter exposes no real fd, so the pollset stays empty;
        // the call must nonetheless be a safe no-op over the draining list.
        let mut pfds = Pollset::new();
        pool.add_pollfds(&mut pfds);
        let mut wfds = Pollset::new();
        let added = pool.add_waitfds(&mut wfds);
        assert_eq!(added as usize, wfds.len());
    }

    // -----------------------------------------------------------------------
    // ShutdownCx defaults.
    // -----------------------------------------------------------------------

    #[test]
    fn shutdown_cx_default_is_empty() {
        let cx = ShutdownCx::new();
        assert!(cx.handler.is_none());
        assert!(cx.notifier.is_none());
        assert!(!cx.internal);
    }
}
