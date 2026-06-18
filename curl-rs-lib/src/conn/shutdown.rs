//! Graceful connection-shutdown sequencing — the Rust rewrite of libcurl's
//! `lib/cshutdn.c` / `lib/cshutdn.h`.
//!
//! This module implements the **`cshutdn` subsystem**: the per-multi-handle
//! registry of connections that are being shut down *gracefully* after the
//! transfer that used them has detached. Its job is to drive each registered
//! connection's shutdown — the protocol-specific disconnect (e.g. FTP `QUIT`,
//! IMAP `LOGOUT`) followed by the per-socket filter-chain shutdown (TLS
//! `close_notify`, …) — to completion (or to a timeout), and then to
//! **terminate** the connection: close its sockets and free it.
//!
//! It exists so that a connection can finish its TLS / protocol close
//! handshake *without blocking the application*: the easy handle detaches as
//! soon as the payload transfer is done, the connection is handed to the multi
//! handle's [`Cshutdn`] registry, and the multi event loop finishes the close
//! in the background. This subsystem is therefore owned by the **multi handle**
//! (`multi.rs`), not the easy handle.
//!
//! # Relationship to the C oracle
//!
//! The C tree is consumed strictly as a **behavioral oracle** (Agent Action
//! Plan §0.3). The mapping of C functions to this module's API is:
//!
//! | C (`lib/cshutdn.c`) | Rust (`this module`) |
//! |---------------------|----------------------|
//! | `struct cshutdn` | [`Cshutdn`] |
//! | `Curl_cshutdn_init` | [`Cshutdn::new`] |
//! | `Curl_cshutdn_destroy` | [`Cshutdn::destroy`] + [`Drop`] |
//! | `cshutdn_run_conn_handler` | [`Cshutdn::run_conn_handler`] (private) |
//! | `cshutdn_run_once` / `Curl_cshutdn_run_once` | [`Cshutdn::run_once`] (private) |
//! | `Curl_cshutdn_terminate` | [`Cshutdn::terminate`] (private) |
//! | `cshutdn_destroy_oldest` / `Curl_cshutdn_close_oldest` | [`Cshutdn::close_oldest`] |
//! | `Curl_cshutdn_add` | [`Cshutdn::add`] |
//! | `Curl_cshutdn_count` | [`Cshutdn::count`] |
//! | `Curl_cshutdn_dest_count` | [`Cshutdn::dest_count`] |
//! | `cshutdn_perform` / `Curl_cshutdn_perform` | [`Cshutdn::perform`] |
//! | `cshutdn_terminate_all` | [`Cshutdn::terminate_all`] (private) |
//!
//! # Memory safety (AAP §0.7.1)
//!
//! The whole module compiles under `#![forbid(unsafe_code)]` (declared below,
//! mirroring the per-module policy used across this crate). The C
//! `Curl_llist` of `connectdata*` plus its sigpipe handling and manual
//! `Curl_conn_free` collapse into a safe [`std::collections::VecDeque`] whose
//! `Drop` frees the owned connections — there are **no raw pointers** and no
//! `Curl_node_*` pointer walking. "Anything allocated by Rust is freed by
//! Rust": a connection is owned by exactly one [`ShutdownConn`] slot and is
//! dropped (its sockets closed first) when it leaves the registry.
//!
//! # The async collapse
//!
//! curl's shutdown is a re-entrant, non-blocking "call me again later" state
//! machine driven by `select`/`poll` and an `EXPIRE_SHUTDOWN` timer. Under
//! Tokio that dance mostly disappears: a connection's per-socket shutdown is a
//! future ([`ConnShutdown::shutdown_socket`]) that resolves when curl's
//! `*done` would become `TRUE`, and the runtime's reactor supplies the socket
//! readiness that `Curl_poll` used to provide. [`Cshutdn::perform`] still
//! exposes the step-wise contract the multi loop expects — it runs one
//! maintenance pass over the registry and returns the smallest remaining
//! shutdown budget as the next wake-up delay (the [`Option<Duration>`] that
//! replaces C's `Curl_expire_ex(..., EXPIRE_SHUTDOWN)` timer id).
//!
//! # Intentionally omitted: the poll/fd_set integration (C parity note)
//!
//! The C functions `Curl_cshutdn_add_pollfds`, `Curl_cshutdn_add_waitfds`, and
//! `Curl_cshutdn_setfds` build `pollfd` / `fd_set` / `waitfd` sets out of
//! `Curl_conn_adjust_pollset` so that the application's `select`/`poll` loop
//! can wait on the shutting-down sockets. **They have no analog here and are
//! deliberately not reproduced.** Under Tokio, in-flight shutdowns are driven
//! by awaiting their futures (optionally spawned as tasks owned by the multi
//! runtime); the reactor — not a hand-built descriptor set — tracks socket
//! readiness. Reproducing `Curl_poll` / `easy_pollset` / `fd_set` machinery
//! would be dead weight, so it is omitted by design. The same reasoning makes
//! the C `Curl_multi_ev_conn_done` socket-deregistration a no-op here: dropping
//! the connection deregisters its sockets from the reactor structurally.
//!
//! # The `conn → protocols` dependency inversion (AAP §0.5.2)
//!
//! C's `cshutdn_run_conn_handler` calls `conn->scheme->run->disconnect(...)` —
//! the protocol-specific disconnect, which for FTP/IMAP/SMTP/SFTP blocks on
//! server responses. Because `protocols/` depends on `conn/`, `conn/` must
//! **never** import `protocols/`. This module therefore never names a protocol
//! type: the protocol disconnect is modeled as a boxed async callback
//! ([`DisconnectHook`]) that the protocol layer *installs on the connection*
//! when it takes the connection over. [`Cshutdn`] only invokes whatever hook is
//! present — preserving the one-directional `protocols → conn` dependency.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use crate::conn::filters::BoxFuture;
use crate::error::Result;
use crate::util::select::wait_ms;
use crate::util::timediff::{duration_to_ms, ms_to_duration};
use crate::util::timeval::{curlx_now, elapsed_since, CurlTime};

/// Default graceful-shutdown timeout, in milliseconds (`2 * 1000`).
///
/// Mirrors the C `DEFAULT_SHUTDOWN_TIMEOUT_MS` from `lib/connect.h`. It bounds
/// protocol-handler disconnects that block on server responses (FTP / IMAP /
/// SMTP / SFTP) so that a single stuck connection cannot hang the registry for
/// curl's default 120-second transfer timeout. It is also the default overall
/// deadline applied to each connection's filter-chain shutdown.
pub const DEFAULT_SHUTDOWN_TIMEOUT_MS: i64 = 2 * 1000;

/// Identifies one of a connection's two socket slots.
///
/// curl models every connection as having up to two sockets, indexed
/// `FIRSTSOCKET` (`0`) and `SECONDARYSOCKET` (`1`) in `lib/urldata.h`. The
/// primary socket carries the control/data stream of single-socket protocols
/// (HTTP, the FTP control channel, …); the secondary socket is the FTP/etc.
/// data connection. Shutdown and close operate on both, and **close order is
/// significant** — see [`Cshutdn::terminate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketIndex {
    /// `FIRSTSOCKET` (C value `0`) — the primary socket.
    First,
    /// `SECONDARYSOCKET` (C value `1`) — the secondary socket (e.g. an FTP
    /// data connection).
    Secondary,
}

impl SocketIndex {
    /// The C integer index for this socket slot (`FIRSTSOCKET` = 0,
    /// `SECONDARYSOCKET` = 1).
    ///
    /// Provided so that a [`ConnShutdown`] implementor can index its
    /// per-socket arrays exactly as the C code indexes
    /// `conn->sock[sockindex]`.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            SocketIndex::First => 0,
            SocketIndex::Secondary => 1,
        }
    }
}

/// A protocol-specific disconnect callback, installed on a connection by the
/// protocol layer and invoked once by the shutdown subsystem.
///
/// This is the safe, dependency-inverted replacement for the C
/// `conn->scheme->run->disconnect(data, conn, aborted)` call. The boolean
/// argument is the C `conn->bits.aborted` flag: `true` when the transfer was
/// aborted (so the handler should tear down quickly rather than exchange a
/// clean protocol goodbye), `false` for a graceful close. The returned future
/// is `'static` and `Send` so it can be bounded by a timeout and driven on any
/// worker thread of the multi runtime.
///
/// It is a `FnOnce` because a connection is disconnected at most once; the
/// shutdown subsystem *takes* it out of the connection (see
/// [`ConnShutdown::take_disconnect_hook`]) before invoking it.
pub type DisconnectHook = Box<dyn FnOnce(bool) -> BoxFuture<'static, ()> + Send>;

/// The behavior the shutdown subsystem requires of a connection.
///
/// This trait is the deliberate seam that keeps `conn/` free of any
/// `protocols/` dependency (see the module docs). The concrete connection type
/// (authored in `conn/mod.rs`) implements it; tests implement it with a mock.
/// `shutdown.rs` drives connections **only** through this contract and never
/// names a protocol type.
///
/// All methods operate on data the connection *owns*, so the C "attach an
/// internal admin handle so the application handle isn't disturbed during
/// shutdown" concern is satisfied structurally — there is no shared mutable
/// application state to disturb.
///
/// # Async style
///
/// Following the established pattern of [`crate::conn::filters::ConnectionFilter`],
/// the asynchronous methods return a boxed future ([`BoxFuture`]) rather than
/// using `async fn`, so the trait stays object-safe and a heterogeneous set of
/// connections (different protocols) can live behind `Box<dyn ConnShutdown>` in
/// one registry — exactly as the C list held `connectdata*` regardless of
/// protocol.
pub trait ConnShutdown: Send {
    /// The connection's stable id (the C `conn->connection_id`), used only for
    /// trace logging.
    fn connection_id(&self) -> i64;

    /// The connection's destination key (the C `conn->destination`): the
    /// `scheme://host:port` (plus proxy / zone) string that connections to the
    /// same endpoint share. Used to match connections in
    /// [`Cshutdn::close_oldest`] and to count them in
    /// [`Cshutdn::dest_count`].
    fn destination(&self) -> &str;

    /// Whether the connection was set up with `CURLOPT_CONNECT_ONLY` (the C
    /// `conn->connect_only`). Such connections hand their socket to the
    /// application, so the filter chain is **not** shut down for them — only
    /// the protocol handler (if any) runs.
    fn connect_only(&self) -> bool;

    /// Whether the owning transfer was aborted (the C `conn->bits.aborted`).
    /// Passed to the [`DisconnectHook`] so the protocol disconnect can choose a
    /// fast teardown over a clean goodbye.
    fn is_aborted(&self) -> bool;

    /// Whether the given socket slot currently has a connected filter chain
    /// (the C `Curl_conn_is_connected(conn, sockindex)`). A slot that was never
    /// connected needs no shutdown.
    fn is_connected(&self, socket: SocketIndex) -> bool;

    /// Take the installed protocol-disconnect callback, if any, leaving `None`
    /// behind.
    ///
    /// Mirrors the one-shot nature of the C `disconnect` handler: it runs at
    /// most once. Returning `None` means the connection has no protocol-level
    /// disconnect to perform (or it has already been taken).
    fn take_disconnect_hook(&mut self) -> Option<DisconnectHook>;

    /// Drive the graceful shutdown of one socket's filter chain a single step,
    /// resolving to `true` when that socket is fully shut down (the C
    /// `Curl_conn_shutdown(data, sockindex, &done)` with its `*done` out-param
    /// folded into the resolved value).
    ///
    /// The concrete implementation delegates to the socket's
    /// [`crate::conn::filters::FilterChain::shutdown`], which bounds itself
    /// with the connection's shutdown timeout; the shutdown subsystem therefore
    /// does not wrap this call in an additional timeout (faithful to C, where
    /// `Curl_conn_shutdown` reads `conn->shutdown.timeout_ms`). An `Err` is
    /// treated by [`Cshutdn::run_once`] as "this socket is done (with an
    /// error)", matching curl's `*done = (r1 || r2 || …)` rule.
    fn shutdown_socket<'a>(&'a mut self, socket: SocketIndex) -> BoxFuture<'a, Result<bool>>;

    /// Close one socket's filter chain (the C `Curl_conn_close(data,
    /// sockindex)`): synchronous, like the C callback. Idempotent — closing an
    /// already-closed or never-connected slot is a no-op.
    fn close_socket(&mut self, socket: SocketIndex);
}

/// A registry slot: an owned connection plus the per-connection shutdown
/// bookkeeping that C keeps in `conn->shutdown` and `conn->bits`.
///
/// Holding the bookkeeping here (rather than on the connection) keeps it local
/// to the shutdown subsystem — the connection only has to satisfy
/// [`ConnShutdown`]. The connection is owned exclusively by this slot; when the
/// slot is dropped, the connection is freed (its sockets having been closed
/// first by [`Cshutdn::terminate`]).
struct ShutdownConn {
    /// The connection being shut down, behind the dependency-inverted contract.
    conn: Box<dyn ConnShutdown>,
    /// When the graceful shutdown was first driven (the C
    /// `conn->shutdown.start[FIRSTSOCKET]`). `None` until the first
    /// [`Cshutdn::run_once`]; used to compute the remaining budget.
    started: Option<CurlTime>,
    /// The overall shutdown deadline for this connection, in milliseconds (the
    /// C `conn->shutdown.timeout_ms`). Defaults to
    /// [`DEFAULT_SHUTDOWN_TIMEOUT_MS`]; `<= 0` means "no limit".
    timeout_ms: i64,
    /// Whether the protocol-disconnect handler has already run (the C
    /// `conn->bits.shutdown_handler`). Ensures the one-shot
    /// [`DisconnectHook`] is invoked at most once.
    shutdown_handler: bool,
    /// Whether the filter chains have finished shutting down (the C
    /// `conn->bits.shutdown_filters`). Once set, [`Cshutdn::run_once`] reports
    /// done immediately.
    shutdown_filters: bool,
}

impl ShutdownConn {
    /// Wrap a freshly-registered connection with cleared bookkeeping and the
    /// default shutdown deadline.
    fn new(conn: Box<dyn ConnShutdown>) -> Self {
        Self {
            conn,
            started: None,
            timeout_ms: DEFAULT_SHUTDOWN_TIMEOUT_MS,
            shutdown_handler: false,
            shutdown_filters: false,
        }
    }

    /// The time left before this connection's shutdown deadline, or `None` when
    /// timing has not started or no finite limit applies.
    ///
    /// Mirrors `Curl_conn_shutdown_timeleft` (`lib/connect.c`): un-started or
    /// "no limit" connections contribute nothing to the next-wake computation.
    /// An already-expired deadline clamps to [`Duration::ZERO`] so the multi
    /// loop wakes immediately to terminate the connection.
    fn shutdown_timeleft(&self) -> Option<Duration> {
        let started = self.started?;
        if self.timeout_ms <= 0 {
            return None; /* no limit in place */
        }
        let elapsed_ms = duration_to_ms(elapsed_since(started));
        let left_ms = self.timeout_ms - elapsed_ms;
        Some(ms_to_duration(left_ms.max(0)))
    }
}

/// A signal raised back to the owning multi handle when the set of connections
/// changes (the C `Curl_multi_connchanged`).
///
/// Modeled as an injected callback rather than a hard call into `multi.rs`, so
/// that `conn/` never has to depend on the multi engine (which depends on
/// `conn/`). The multi handle installs it via
/// [`Cshutdn::set_connchanged_notifier`]; when absent (e.g. in unit tests) the
/// notification is simply skipped. It is `Fn() + Send + Sync` and held in an
/// [`Arc`] so the multi can share the same waker it uses elsewhere.
pub type ConnChangedNotifier = Arc<dyn Fn() + Send + Sync>;

/// The per-multi-handle registry of connections being shut down gracefully.
///
/// Rust rewrite of the C `struct cshutdn { Curl_llist list; Curl_multi *multi;
/// BIT(initialised); }`. Instead of a back-pointer to the multi handle, it
/// holds the small pieces of multi state it actually needs — the total
/// connection limit and the "connections changed" notifier — which keeps the
/// type free of a `multi.rs` dependency and trivially testable. It is owned by
/// the [`crate::multi`] handle (authored elsewhere); this module only defines
/// the type and its behavior.
pub struct Cshutdn {
    /// Connections currently being shut down, oldest at the front. A
    /// [`VecDeque`] is used in place of the C `Curl_llist` (the agent prompt
    /// permits either): front-is-oldest matches the C "head is oldest"
    /// eviction order, and `Drop` frees every owned connection without any
    /// manual node walking.
    list: VecDeque<ShutdownConn>,
    /// The multi handle's `max_total_connections` (the C
    /// `multi->max_total_connections`). `0` means "no limit"; a positive value
    /// triggers oldest-connection eviction in [`Cshutdn::add`].
    max_total_connections: usize,
    /// Optional "connections changed" notifier (the C
    /// `Curl_multi_connchanged`), invoked after a connection is terminated.
    connchanged: Option<ConnChangedNotifier>,
    /// Whether the registry has been initialised (the C
    /// `cshutdn.initialised`). Guards [`Cshutdn::destroy`] so a double-destroy
    /// is a no-op.
    initialised: bool,
}

impl Cshutdn {
    /// Create a registry for a multi handle (the C `Curl_cshutdn_init`).
    ///
    /// `max_total_connections` is the multi handle's connection cap (`0` =
    /// unlimited). The "connections changed" notifier is installed separately
    /// via [`Cshutdn::set_connchanged_notifier`], since the multi handle
    /// usually wires it after both itself and this registry exist.
    #[must_use]
    pub fn new(max_total_connections: usize) -> Self {
        Self {
            list: VecDeque::new(),
            max_total_connections,
            connchanged: None,
            initialised: true,
        }
    }

    /// Install the "connections changed" notifier (the C
    /// `Curl_multi_connchanged` target). Replaces any previously-installed
    /// notifier.
    pub fn set_connchanged_notifier(&mut self, notifier: ConnChangedNotifier) {
        self.connchanged = Some(notifier);
    }

    /// Update the multi handle's total-connection limit (`0` = unlimited).
    ///
    /// Mirrors reading `multi->max_total_connections` at
    /// [`Cshutdn::add`]-time; exposed as a setter so the multi handle can keep
    /// the registry in step when the application changes
    /// `CURLMOPT_MAX_TOTAL_CONNECTIONS`.
    pub fn set_max_total_connections(&mut self, max_total_connections: usize) {
        self.max_total_connections = max_total_connections;
    }

    /// Number of connections currently being shut down (the C
    /// `Curl_cshutdn_count`).
    #[must_use]
    pub fn count(&self) -> usize {
        self.list.len()
    }

    /// Number of connections to `destination` currently being shut down (the C
    /// `Curl_cshutdn_dest_count`). Used by the connection cache when enforcing
    /// per-destination limits.
    #[must_use]
    pub fn dest_count(&self, destination: &str) -> usize {
        self.list
            .iter()
            .filter(|sc| sc.conn.destination() == destination)
            .count()
    }

    /// Whether the registry currently holds no connections.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    // -- shutdown driving ---------------------------------------------------

    /// Run the connection's protocol-specific disconnect once (the C
    /// `cshutdn_run_conn_handler`, `lib/cshutdn.c` L41).
    ///
    /// If the handler has not yet run and the connection has an installed
    /// [`DisconnectHook`], the hook is taken and awaited with the
    /// [`DEFAULT_SHUTDOWN_TIMEOUT_MS`] bound. The bound is unconditional here
    /// because the registry always drives shutdown on owned data
    /// (equivalent to C's "internal admin handle"); the C code applies the same
    /// short timeout precisely so a protocol handler that blocks on a server
    /// response (FTP / IMAP / SMTP / SFTP) cannot hang for the default
    /// 120-second transfer timeout. Whether or not a hook is present, the
    /// `shutdown_handler` flag is set so this is a one-shot.
    async fn run_conn_handler(sc: &mut ShutdownConn) {
        if sc.shutdown_handler {
            return;
        }
        if let Some(hook) = sc.conn.take_disconnect_hook() {
            let aborted = sc.conn.is_aborted();
            tracing::trace!(
                connection_id = sc.conn.connection_id(),
                aborted,
                "[SHUTDOWN] running protocol disconnect handler"
            );
            // Bound the (possibly server-blocking) disconnect. We ignore the
            // outcome: whether it completed or timed out, the handler has had
            // its single chance and we move on, exactly like the C code, which
            // does not propagate the handler's result either.
            let bound = Duration::from_millis(DEFAULT_SHUTDOWN_TIMEOUT_MS as u64);
            let _ = tokio::time::timeout(bound, hook(aborted)).await;
        }
        sc.shutdown_handler = true;
    }

    /// Drive one connection's shutdown a single step (the C `cshutdn_run_once`
    /// / `Curl_cshutdn_run_once`, `lib/cshutdn.c` L69-L119).
    ///
    /// Returns `true` when the connection is shut down — i.e. when the C
    /// `*done` would be `TRUE`. The C attach/detach of the admin handle around
    /// this call is unnecessary: the connection owns its own state.
    ///
    /// The exact C completion rule is preserved (L104-107):
    ///
    /// ```text
    /// *done = (r1 || r2 || (done1 && done2));
    /// ```
    ///
    /// i.e. *done when **either** socket's shutdown errored, **or** both
    /// sockets report success. A per-socket `Err` from
    /// [`ConnShutdown::shutdown_socket`] plays the role of curl's non-zero
    /// `CURLcode` `r`, which counts as "done" (the error is folded into the
    /// done flag and not propagated, matching the C `void` return).
    async fn run_once(sc: &mut ShutdownConn) -> bool {
        // Start shutdown timing on the first socket if not started yet
        // (C `Curl_shutdown_start(data, FIRSTSOCKET, 0)`).
        if sc.started.is_none() {
            sc.started = Some(curlx_now());
        }

        // Run the protocol handler once.
        Self::run_conn_handler(sc).await;

        // If the filters already shut down, we are done (C L85-88).
        if sc.shutdown_filters {
            return true;
        }

        let connect_only = sc.conn.connect_only();

        // FIRSTSOCKET: shut down only if not connect-only and connected,
        // else treat as already done with no error (C L90-95).
        let (err1, done1) = if !connect_only && sc.conn.is_connected(SocketIndex::First) {
            match sc.conn.shutdown_socket(SocketIndex::First).await {
                Ok(done) => (false, done),
                Err(_) => (true, false),
            }
        } else {
            (false, true)
        };

        // SECONDARYSOCKET: same treatment (C L97-102).
        let (err2, done2) = if !connect_only && sc.conn.is_connected(SocketIndex::Secondary) {
            match sc.conn.shutdown_socket(SocketIndex::Secondary).await {
                Ok(done) => (false, done),
                Err(_) => (true, false),
            }
        } else {
            (false, true)
        };

        // We are done when any failed or both report success (C L104-107).
        let done = err1 || err2 || (done1 && done2);
        if done {
            sc.shutdown_filters = true;
        }
        tracing::trace!(
            connection_id = sc.conn.connection_id(),
            done,
            "[SHUTDOWN] run_once"
        );
        done
    }

    // -- termination --------------------------------------------------------

    /// Terminate a connection: close its sockets and free it (the C
    /// `Curl_cshutdn_terminate`, `lib/cshutdn.c` L121-L165).
    ///
    /// Takes ownership of the [`ShutdownConn`] — Rust move semantics make the C
    /// comment "Takes ownership of `conn`" explicit, and the drop at the end of
    /// this function *is* the C `Curl_conn_free`.
    ///
    /// Steps, in C order:
    /// 1. Run the protocol disconnect handler once (no-op if already run).
    /// 2. If `do_shutdown`, make one last graceful [`Self::run_once`] attempt.
    /// 3. Close `SECONDARYSOCKET` **then** `FIRSTSOCKET`. The order is
    ///    significant and preserved from C (L153-154): the secondary (data)
    ///    socket is torn down before the primary (control) socket.
    /// 4. Drop the connection (frees it; its sockets are deregistered from the
    ///    Tokio reactor structurally — the C `Curl_multi_ev_conn_done` has no
    ///    explicit analog, see the module docs).
    /// 5. Raise the "connections changed" notification (the C
    ///    `Curl_multi_connchanged`).
    async fn terminate(&mut self, mut sc: ShutdownConn, do_shutdown: bool) {
        // Always give the protocol handler its chance (C L144).
        Self::run_conn_handler(&mut sc).await;

        if do_shutdown {
            // A last attempt to shut down handlers and filters, if not done so
            // already (C L145-149).
            let _ = Self::run_once(&mut sc).await;
        }

        tracing::trace!(
            connection_id = sc.conn.connection_id(),
            forced = !sc.shutdown_filters,
            "[SHUTDOWN] closing connection"
        );

        // Close SECONDARYSOCKET then FIRSTSOCKET — order matters (C L153-154).
        sc.conn.close_socket(SocketIndex::Secondary);
        sc.conn.close_socket(SocketIndex::First);

        // Drop the connection (C `Curl_conn_free`). Dropping the box frees the
        // connection and, with it, deregisters its sockets from the reactor.
        drop(sc);

        // Notify the multi handle that the connection set changed
        // (C `Curl_multi_connchanged`).
        if let Some(notifier) = &self.connchanged {
            tracing::trace!("[SHUTDOWN] trigger multi connchanged");
            notifier();
        }
    }

    // -- registry operations ------------------------------------------------

    /// Register a connection for graceful shutdown (the C `Curl_cshutdn_add`,
    /// `lib/cshutdn.c` L395-L424).
    ///
    /// `conns_in_pool` is the number of *live* connections still held by the
    /// connection cache. If the multi handle has a finite
    /// `max_total_connections` and adding this connection would push the
    /// combined total (pooled + shutting-down) to or over the limit, the oldest
    /// connection already in shutdown is evicted and force-terminated first
    /// (the C `cshutdn_destroy_oldest(cshutdn, data, NULL)`).
    ///
    /// The C `socket_cb` event-registration step (`cshutdn_update_ev`) has no
    /// analog here: there is no external poll set to update — the reactor
    /// tracks the sockets of the in-flight shutdown future (see the module
    /// docs). The connection is then appended to the shutdown list.
    pub async fn add(&mut self, conn: Box<dyn ConnShutdown>, conns_in_pool: usize) {
        if self.max_total_connections > 0
            && self.max_total_connections <= conns_in_pool + self.list.len()
        {
            tracing::trace!(
                max_total = self.max_total_connections,
                "[SHUTDOWN] discarding oldest shutdown connection due to connection limit"
            );
            // Evict the oldest connection to any destination (C `NULL` dest).
            self.close_oldest(None).await;
        }

        let connection_id = conn.connection_id();
        self.list.push_back(ShutdownConn::new(conn));
        tracing::trace!(
            connection_id,
            in_shutdown = self.list.len(),
            "[SHUTDOWN] added connection to shutdowns"
        );
    }

    /// Close the oldest connection being shut down — to `destination` when
    /// `Some`, or to any destination when `None`.
    ///
    /// Rust rewrite of the C `cshutdn_destroy_oldest` /
    /// `Curl_cshutdn_close_oldest` (`lib/cshutdn.c` L167-L203). Returns `true`
    /// if a connection was closed. The matched connection is removed from the
    /// registry and force-terminated (no extra graceful attempt:
    /// `do_shutdown = false`, matching the C call). Used by the connection
    /// cache (`cache.rs`) when it must reclaim a slot to honor a connection
    /// limit.
    ///
    /// "Oldest" is the front-most matching entry, since connections are
    /// appended at the back (the C list head is the oldest).
    pub async fn close_oldest(&mut self, destination: Option<&str>) -> bool {
        let index = self.list.iter().position(|sc| match destination {
            None => true,
            Some(dest) => sc.conn.destination() == dest,
        });

        match index {
            Some(i) => {
                // `remove` shifts the rest down; the returned slot is the one we
                // matched. It is always `Some` because `i` came from `position`.
                if let Some(sc) = self.list.remove(i) {
                    self.terminate(sc, false).await;
                    return true;
                }
                false
            }
            None => false,
        }
    }

    // -- maintenance --------------------------------------------------------

    /// Run one maintenance pass over every connection being shut down (the C
    /// `cshutdn_perform` / `Curl_cshutdn_perform`, `lib/cshutdn.c` L228-L264).
    ///
    /// This is the non-blocking entry point the multi event loop calls each
    /// turn. For every connection it drives one [`Self::run_once`] step:
    /// connections that report done are removed and terminated; the rest are
    /// retained. It returns the **smallest remaining shutdown budget** across
    /// the retained connections as the delay until the registry next needs
    /// servicing — the [`Option<Duration>`] that replaces C's
    /// `Curl_expire_ex(data, next_expire_ms, EXPIRE_SHUTDOWN)`. `None` means
    /// "nothing pending" (either the registry is empty or no retained
    /// connection has a finite deadline).
    ///
    /// The C `next_expire_ms` is the smallest time left over all connections;
    /// this implements that documented intent directly (the agent prompt
    /// specifies "compute the smallest remaining shutdown time").
    pub async fn perform(&mut self) -> Option<Duration> {
        if self.list.is_empty() {
            return None;
        }

        tracing::trace!(
            connections = self.list.len(),
            "[SHUTDOWN] perform on connections"
        );

        // Drain the whole list so we can `await` per-connection work and call
        // `&mut self` methods (`terminate`) without holding a borrow of
        // `self.list`. Connections that are not yet done are pushed back.
        let mut pending: VecDeque<ShutdownConn> = std::mem::take(&mut self.list);
        let mut kept: VecDeque<ShutdownConn> = VecDeque::with_capacity(pending.len());
        let mut next_wake: Option<Duration> = None;

        while let Some(mut sc) = pending.pop_front() {
            let done = Self::run_once(&mut sc).await;
            if done {
                self.terminate(sc, false).await;
            } else {
                if let Some(remaining) = sc.shutdown_timeleft() {
                    next_wake = Some(match next_wake {
                        Some(current) => current.min(remaining),
                        None => remaining,
                    });
                }
                kept.push_back(sc);
            }
        }

        self.list = kept;
        next_wake
    }

    /// Gracefully shut down the whole registry within an overall deadline, then
    /// force-terminate anything that remains (the C `cshutdn_terminate_all`,
    /// `lib/cshutdn.c` L266-L317).
    ///
    /// Repeatedly runs [`Self::perform`]; between rounds it waits for activity
    /// (the C `cshutdn_wait`, which polled the sockets for up to
    /// `min(remaining, 1000)` ms) using [`wait_ms`] over `tokio::time::sleep`,
    /// capping each wait at the smaller of the per-pass next-wake delay and the
    /// C 1000 ms ceiling. The loop ends when the list drains or the overall
    /// `timeout_ms` elapses; a `timeout_ms <= 0` means "best effort" — one pass,
    /// then force-terminate the rest. Any survivors are force-terminated
    /// (`do_shutdown = false`).
    async fn terminate_all(&mut self, timeout_ms: i64) {
        tracing::trace!(timeout_ms, "[SHUTDOWN] shutdown all");
        let started = curlx_now();

        while !self.list.is_empty() {
            let next_wake = self.perform().await;

            if self.list.is_empty() {
                tracing::trace!("[SHUTDOWN] shutdown finished cleanly");
                break;
            }

            // Stop once the overall budget is spent. For `timeout_ms <= 0`
            // (best effort) `spent_ms >= timeout_ms` holds immediately, so we
            // run exactly one pass before force-terminating the remainder —
            // matching the C "best effort done" path.
            let spent_ms = duration_to_ms(elapsed_since(started));
            if spent_ms >= timeout_ms {
                tracing::trace!(
                    timed_out = timeout_ms > 0,
                    "[SHUTDOWN] shutdown finished (timeout / best effort)"
                );
                break;
            }

            // Wait for activity or the smallest remaining budget, capped at the
            // C 1000 ms ceiling (`CURLMIN(remain, 1000)`).
            let remain_ms = timeout_ms - spent_ms;
            let wake_ms = next_wake
                .map(duration_to_ms)
                .unwrap_or(remain_ms)
                .min(remain_ms)
                .min(1000);
            wait_ms(wake_ms).await;
        }

        // Terminate any remaining connections (C L306-313).
        let mut remaining: VecDeque<ShutdownConn> = std::mem::take(&mut self.list);
        while let Some(sc) = remaining.pop_front() {
            self.terminate(sc, false).await;
        }
    }

    /// Terminate all remaining connections and tear down the registry (the C
    /// `Curl_cshutdn_destroy`, `lib/cshutdn.c` L329-L351).
    ///
    /// This is the graceful, `await`-able teardown the multi handle calls
    /// during its own destruction (while a Tokio runtime is still available).
    /// It runs at most once — a second call is a no-op (the C `initialised`
    /// guard).
    ///
    /// In debug builds it honors the `CURL_GRACEFUL_SHUTDOWN` environment
    /// variable (an integer millisecond budget), exactly like the C
    /// `#ifdef DEBUGBUILD` block, so the test suite can exercise the graceful
    /// path; release builds always use a `0` (best-effort) budget. The value is
    /// clamped to a non-negative `i32` range to match the C
    /// `curlx_str_number(&p, &l, INT_MAX)` parse.
    pub async fn destroy(&mut self) {
        if !self.initialised {
            return;
        }

        // In debug builds, honor `CURL_GRACEFUL_SHUTDOWN` (an integer ms budget)
        // exactly like the C `#ifdef DEBUGBUILD` block; release builds always
        // use a best-effort `0`. The `cfg`-split `let` keeps the binding
        // immutable in both configurations (no `unused_mut` in release).
        #[cfg(debug_assertions)]
        let timeout_ms: i64 = std::env::var("CURL_GRACEFUL_SHUTDOWN")
            .ok()
            .and_then(|value| value.trim().parse::<i64>().ok())
            .map(|parsed| parsed.clamp(0, i64::from(i32::MAX)))
            .unwrap_or(0);
        #[cfg(not(debug_assertions))]
        let timeout_ms: i64 = 0;

        tracing::trace!(
            connections = self.list.len(),
            timeout_ms,
            "[SHUTDOWN] destroy"
        );
        self.terminate_all(timeout_ms).await;
        self.initialised = false;
    }
}

impl Drop for Cshutdn {
    /// Last-resort synchronous cleanup.
    ///
    /// Graceful, awaited shutdown belongs to [`Cshutdn::destroy`]; by the time
    /// a well-behaved multi handle drops this registry the list is already
    /// empty. If any connections remain (e.g. the multi handle was dropped
    /// without calling [`Cshutdn::destroy`], or a panic unwound past it), they
    /// are force-closed here. `Drop` cannot run `async` graceful shutdown, so
    /// this only performs the synchronous close — preserving the
    /// `SECONDARYSOCKET`-then-`FIRSTSOCKET` order — and then frees each
    /// connection. The "connections changed" notifier is intentionally not
    /// fired from `Drop`, since the owning multi handle is itself going away.
    fn drop(&mut self) {
        while let Some(mut sc) = self.list.pop_front() {
            sc.conn.close_socket(SocketIndex::Secondary);
            sc.conn.close_socket(SocketIndex::First);
            // `sc` (and its boxed connection) is dropped here.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CurlError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// Shared, observable state for [`MockConn`]. Held behind an
    /// `Arc<Mutex<…>>` so the test can inspect what happened to a connection
    /// even after the registry has terminated (dropped) it.
    #[derive(Default)]
    struct MockState {
        /// How many times `shutdown_socket(First)` has been invoked.
        shutdown_calls: usize,
        /// `shutdown_socket(First)` reports done once `shutdown_calls` reaches
        /// this threshold (`0` ⇒ done on the first call).
        done_after: usize,
        /// What `shutdown_socket(Secondary)` resolves to.
        secondary_done: bool,
        /// When `true`, `shutdown_socket(First)` resolves to `Err` (used to
        /// exercise the "error counts as done" rule).
        err_on_first: bool,
        /// The order in which sockets were closed, recorded by `close_socket`.
        close_order: Vec<SocketIndex>,
        /// Whether the installed disconnect hook actually ran.
        hook_ran: bool,
        /// The `aborted` flag the disconnect hook received, if it ran.
        hook_aborted: Option<bool>,
    }

    /// A test double implementing [`ConnShutdown`] with scriptable behavior.
    struct MockConn {
        id: i64,
        destination: String,
        connect_only: bool,
        aborted: bool,
        connected_first: bool,
        connected_secondary: bool,
        install_hook: bool,
        hook_taken: bool,
        state: Arc<Mutex<MockState>>,
    }

    impl MockConn {
        fn new(id: i64, destination: &str, state: Arc<Mutex<MockState>>) -> Self {
            Self {
                id,
                destination: destination.to_string(),
                connect_only: false,
                aborted: false,
                connected_first: true,
                connected_secondary: false,
                install_hook: false,
                hook_taken: false,
                state,
            }
        }
    }

    impl ConnShutdown for MockConn {
        fn connection_id(&self) -> i64 {
            self.id
        }

        fn destination(&self) -> &str {
            &self.destination
        }

        fn connect_only(&self) -> bool {
            self.connect_only
        }

        fn is_aborted(&self) -> bool {
            self.aborted
        }

        fn is_connected(&self, socket: SocketIndex) -> bool {
            match socket {
                SocketIndex::First => self.connected_first,
                SocketIndex::Secondary => self.connected_secondary,
            }
        }

        fn take_disconnect_hook(&mut self) -> Option<DisconnectHook> {
            if self.install_hook && !self.hook_taken {
                self.hook_taken = true;
                let state = self.state.clone();
                Some(Box::new(move |aborted| {
                    Box::pin(async move {
                        let mut s = state.lock().expect("mock state poisoned");
                        s.hook_ran = true;
                        s.hook_aborted = Some(aborted);
                    })
                }))
            } else {
                None
            }
        }

        fn shutdown_socket<'a>(&'a mut self, socket: SocketIndex) -> BoxFuture<'a, Result<bool>> {
            let state = self.state.clone();
            Box::pin(async move {
                let mut s = state.lock().expect("mock state poisoned");
                match socket {
                    SocketIndex::First => {
                        s.shutdown_calls += 1;
                        if s.err_on_first {
                            return Err(CurlError::SslShutdownFailed);
                        }
                        Ok(s.shutdown_calls >= s.done_after)
                    }
                    SocketIndex::Secondary => Ok(s.secondary_done),
                }
            })
        }

        fn close_socket(&mut self, socket: SocketIndex) {
            self.state
                .lock()
                .expect("mock state poisoned")
                .close_order
                .push(socket);
        }
    }

    /// Build a fresh shared state with the given "done after N calls" script
    /// and a secondary socket that completes immediately when connected.
    fn state(done_after: usize) -> Arc<Mutex<MockState>> {
        Arc::new(Mutex::new(MockState {
            done_after,
            secondary_done: true,
            ..MockState::default()
        }))
    }

    #[test]
    fn constant_and_socket_index_values() {
        // EXACT parity with the C `DEFAULT_SHUTDOWN_TIMEOUT_MS` and the
        // FIRSTSOCKET / SECONDARYSOCKET indices.
        assert_eq!(DEFAULT_SHUTDOWN_TIMEOUT_MS, 2000);
        assert_eq!(SocketIndex::First.index(), 0);
        assert_eq!(SocketIndex::Secondary.index(), 1);
    }

    #[tokio::test]
    async fn perform_retains_not_done_then_terminates_when_done() {
        // The connection's first socket reports "not done" on the first
        // shutdown step and "done" on the second.
        let st = state(2);
        let conn = MockConn::new(1, "https://a.example:443", st.clone());
        let mut csd = Cshutdn::new(0);
        csd.add(Box::new(conn), 0).await;
        assert_eq!(csd.count(), 1);

        // First pass: not done → retained, with a finite next-wake budget.
        let wake = csd.perform().await;
        assert_eq!(csd.count(), 1, "connection retained while not done");
        let wake = wake.expect("a finite shutdown budget should remain");
        assert!(
            wake <= Duration::from_millis(DEFAULT_SHUTDOWN_TIMEOUT_MS as u64),
            "next-wake bounded by the shutdown timeout"
        );

        // Second pass: done → removed and terminated.
        let _ = csd.perform().await;
        assert_eq!(csd.count(), 0, "connection terminated once it reports done");

        let s = st.lock().unwrap();
        assert!(
            s.shutdown_calls >= 2,
            "shutdown driven across multiple steps"
        );
        // terminate() must close SECONDARYSOCKET before FIRSTSOCKET.
        assert_eq!(
            s.close_order,
            vec![SocketIndex::Secondary, SocketIndex::First],
            "close order is SECONDARY then FIRST"
        );
    }

    #[tokio::test]
    async fn close_oldest_matches_by_destination() {
        let mut csd = Cshutdn::new(0);
        csd.add(Box::new(MockConn::new(1, "A", state(99))), 0).await;
        csd.add(Box::new(MockConn::new(2, "B", state(99))), 0).await;
        csd.add(Box::new(MockConn::new(3, "A", state(99))), 0).await;

        assert_eq!(csd.count(), 3);
        assert_eq!(csd.dest_count("A"), 2);
        assert_eq!(csd.dest_count("B"), 1);

        // Closing the oldest "A" removes id=1 (front-most A), leaving id=3.
        assert!(csd.close_oldest(Some("A")).await);
        assert_eq!(csd.dest_count("A"), 1);
        assert_eq!(csd.count(), 2);

        // Closing the oldest of any destination removes id=2 (now front-most).
        assert!(csd.close_oldest(None).await);
        assert_eq!(csd.count(), 1);
        assert_eq!(csd.dest_count("B"), 0);

        // No "B" remains to close.
        assert!(!csd.close_oldest(Some("B")).await);
        // The lone remaining "A" can still be closed.
        assert!(csd.close_oldest(Some("A")).await);
        assert_eq!(csd.count(), 0);
    }

    #[tokio::test]
    async fn socket_error_counts_as_done() {
        // err1 == true ⇒ done == TRUE (the `r1 || r2 || …` rule), so the
        // connection is terminated even though it never reported clean success.
        let st = Arc::new(Mutex::new(MockState {
            done_after: 99,
            err_on_first: true,
            secondary_done: true,
            ..MockState::default()
        }));
        let conn = MockConn::new(7, "https://err.example:443", st.clone());
        let mut csd = Cshutdn::new(0);
        csd.add(Box::new(conn), 0).await;

        let _ = csd.perform().await;
        assert_eq!(csd.count(), 0, "an errored shutdown is treated as done");
    }

    #[tokio::test]
    async fn both_sockets_must_complete() {
        // First socket done, secondary not yet → overall not done (done1 &&
        // done2 is false and neither errored).
        let st = Arc::new(Mutex::new(MockState {
            done_after: 1,
            secondary_done: false,
            ..MockState::default()
        }));
        let mut conn = MockConn::new(5, "ftp://files.example:21", st.clone());
        conn.connected_first = true;
        conn.connected_secondary = true;
        let mut csd = Cshutdn::new(0);
        csd.add(Box::new(conn), 0).await;

        let _ = csd.perform().await;
        assert_eq!(csd.count(), 1, "not done until BOTH sockets complete");

        // Let the secondary socket finish; now both report done.
        st.lock().unwrap().secondary_done = true;
        let _ = csd.perform().await;
        assert_eq!(csd.count(), 0, "done once both sockets complete");
    }

    #[tokio::test]
    async fn connect_only_skips_filter_shutdown() {
        // A connect-only connection hands its socket to the application, so the
        // filter chain is never shut down; run_once still completes it.
        let st = state(99);
        let mut conn = MockConn::new(9, "https://co.example:443", st.clone());
        conn.connect_only = true;
        conn.connected_first = true;
        let mut csd = Cshutdn::new(0);
        csd.add(Box::new(conn), 0).await;

        let _ = csd.perform().await;
        assert_eq!(
            st.lock().unwrap().shutdown_calls,
            0,
            "connect_only must not drive filter shutdown"
        );
        assert_eq!(csd.count(), 0, "connect_only connection still terminates");
    }

    #[tokio::test]
    async fn disconnect_hook_runs_once_with_aborted_flag() {
        let st = state(0);
        let mut conn = MockConn::new(3, "imap://mail.example:143", st.clone());
        conn.install_hook = true;
        conn.aborted = true;
        // No connected sockets, so completion hinges on the handler running.
        conn.connected_first = false;
        conn.connected_secondary = false;
        let mut csd = Cshutdn::new(0);
        csd.add(Box::new(conn), 0).await;

        let _ = csd.perform().await;
        let s = st.lock().unwrap();
        assert!(s.hook_ran, "the protocol-disconnect hook must run");
        assert_eq!(
            s.hook_aborted,
            Some(true),
            "the aborted flag is forwarded to the hook"
        );
        assert_eq!(csd.count(), 0);
    }

    #[tokio::test]
    async fn add_evicts_oldest_when_over_total_limit() {
        // max_total_connections == 2.
        let mut csd = Cshutdn::new(2);
        csd.add(Box::new(MockConn::new(1, "A", state(99))), 0).await;
        csd.add(Box::new(MockConn::new(2, "B", state(99))), 0).await;
        assert_eq!(csd.count(), 2);

        // Adding a third with no pooled connections trips the limit
        // (2 <= 0 + 2): the oldest (id=1, dest "A") is evicted first.
        csd.add(Box::new(MockConn::new(3, "C", state(99))), 0).await;
        assert_eq!(csd.count(), 2, "registry stays within the limit");
        assert_eq!(csd.dest_count("A"), 0, "oldest connection evicted");
        assert_eq!(csd.dest_count("C"), 1, "new connection added");
    }

    #[tokio::test]
    async fn connchanged_notifier_fires_on_terminate() {
        let counter = Arc::new(AtomicUsize::new(0));
        let observed = counter.clone();
        let mut csd = Cshutdn::new(0);
        csd.set_connchanged_notifier(Arc::new(move || {
            observed.fetch_add(1, Ordering::SeqCst);
        }));

        // A connection with no connected sockets completes on the first pass.
        let mut conn = MockConn::new(4, "https://n.example:443", state(0));
        conn.connected_first = false;
        csd.add(Box::new(conn), 0).await;

        let _ = csd.perform().await;
        assert_eq!(csd.count(), 0);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "connchanged fires once per terminated connection"
        );
    }

    #[tokio::test]
    async fn destroy_terminates_all_and_is_idempotent() {
        let mut csd = Cshutdn::new(0);
        // Connections that complete immediately (no connected sockets).
        for id in 0..3 {
            let mut conn = MockConn::new(id, "https://d.example:443", state(0));
            conn.connected_first = false;
            csd.add(Box::new(conn), 0).await;
        }
        assert_eq!(csd.count(), 3);

        csd.destroy().await;
        assert_eq!(csd.count(), 0, "destroy terminates all connections");

        // A second destroy is a no-op (the `initialised` guard).
        csd.destroy().await;
        assert_eq!(csd.count(), 0);
    }

    #[tokio::test]
    async fn drop_force_closes_remaining_in_order() {
        // A never-completing connection left in the registry when it is dropped
        // (no `destroy` call) must still be force-closed, SECONDARY then FIRST.
        let st = state(99);
        {
            let mut csd = Cshutdn::new(0);
            let conn = MockConn::new(1, "https://x.example:443", st.clone());
            csd.add(Box::new(conn), 0).await;
            assert_eq!(csd.count(), 1);
            // `csd` dropped here without a graceful destroy.
        }
        let s = st.lock().unwrap();
        assert_eq!(
            s.close_order,
            vec![SocketIndex::Secondary, SocketIndex::First],
            "Drop force-closes SECONDARY then FIRST"
        );
    }
}
