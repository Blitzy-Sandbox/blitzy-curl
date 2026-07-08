//! Connection-setup orchestration and the `SETUP` meta-filter
//! (`lib/connect.c` / `lib/connect.h`).
//!
//! This module owns the top of the connection-filter stack: it assembles the
//! per-socket [`FilterChain`] in the **exact order curl uses** and drives the
//! handshake to completion under a connect timeout. The pieces mirror curl's
//! `lib/connect.c` one-to-one:
//!
//! * [`conn_setup`] ← `Curl_conn_setup` — the entry point that installs the
//!   chain for a socket index, routing HTTPS through
//!   [`crate::conn::https_connect`] and otherwise building the default `SETUP`
//!   stack.
//! * [`SetupFilter`] ← `Curl_cft_setup` / `cf_setup_connect` — the `SETUP`
//!   meta-filter whose state machine (`CF_SETUP_INIT` → … → `CF_SETUP_DONE`)
//!   is reproduced by [`CfSetupState`].
//! * [`conncontrol`] ← `Curl_conncontrol`, with the [`connclose!`],
//!   [`streamclose!`] and [`connkeep!`] convenience macros.
//! * [`timeleft_ms`] ← `Curl_timeleft_ms`.
//!
//! # NOTE — eager assembly vs. curl's lazy insertion
//!
//! curl's `cf_setup_connect` *inserts* the sub-filters (proxy → haproxy → ssl)
//! lazily, from inside the running `SETUP` filter, calling
//! `Curl_cf_*_insert_after` as its state machine advances. That is impossible
//! in this codebase because the filter builders
//! ([`h1_proxy::insert_after`](crate::conn::h1_proxy::insert_after),
//! [`haproxy::insert_after`](crate::conn::haproxy::insert_after), …) operate on
//! `&mut FilterChain`, whereas a *running* filter is handed only a
//! [`FilterCtx`], which cannot splice new nodes.
//!
//! The chain is therefore assembled **eagerly** in [`build_setup_chain`], in
//! curl's precise state order, so the physical layout — and thus the
//! `--trace`/`-v` diagnostics that depend on it — is byte-for-byte identical:
//!
//! ```text
//! SETUP → [HTTP-PROXY] → [HAPROXY] → [SSL] → HAPPY-EYEBALLS ( → sockets )
//! ```
//!
//! The [`SetupFilter`] at runtime replays the state sequence for trace parity
//! and then delegates the connect downward through the pre-assembled chain.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use crate::conn::filters::{CfFuture, ConnectionFilter, FilterChain, FilterCtx};
use crate::conn::{
    h1_proxy, happy_eyeballs, haproxy, https_connect, CfType, ConnControl, Connection, ProxyType,
    Transport, CURL_CF_SSL_DISABLE, CURL_CF_SSL_ENABLE,
};
use crate::dns::DnsEntry;
use crate::error::{Error, Result};
use crate::tls::{TlsConnector, TlsStream};

// ===========================================================================
// Phase 1 — constants and connection control.
// ===========================================================================

/// The default connect timeout in milliseconds (`DEFAULT_CONNECT_TIMEOUT` in
/// `lib/connect.h`): 300000 ms = 5 minutes. Used unless the caller supplies a
/// `--connect-timeout`.
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 300_000;

/// Size of the in-memory bridge between the TLS engine and the byte-delegating
/// filter chain (each direction). Sized well above a TLS record so a full
/// handshake flight never blocks the concurrent pump.
const SSL_BRIDGE_BUF: usize = 64 * 1024;

/// Scratch buffer size for pumping ciphertext/plaintext through the SSL filter.
const SSL_PUMP_BUF: usize = 16 * 1024;

/// Bounded wait used to detect that the TLS engine has no more buffered
/// outbound ciphertext to flush. The bytes are already buffered locally, so a
/// read returns immediately when data is present; the timeout only elapses
/// once, at the tail of a flight, to break out of the drain loop.
const SSL_FLUSH_DRAIN_MS: u64 = 50;

/// Marks the connection for close (or stream-close), mirroring
/// `Curl_conncontrol` (`lib/connect.c`).
///
/// `ctrl` selects the action, exactly as curl's `CONNCTRL_*` values do:
///
/// * [`ConnControl::Connection`] (`CONNCTRL_CONNECTION`) forces the whole
///   connection closed after the current transfer (`conn->bits.close = TRUE`).
/// * [`ConnControl::Stream`] (`CONNCTRL_STREAM`) closes only the current stream
///   on a multiplexed connection — leaving the shared connection intact — but
///   closes the connection when it is *not* multiplexed.
/// * [`ConnControl::Keep`] (`CONNCTRL_KEEP`) clears any pending close.
///
/// `reason` is emitted to the trace log exactly as curl's `infof`/`DEBUGF`
/// does, so `--trace` output stays identical. The bit manipulation itself is
/// delegated to [`Connection::conn_control`], which owns curl's precise
/// multiplex-aware semantics.
pub fn conncontrol(conn: &mut Connection, ctrl: ConnControl, reason: &str) {
    match ctrl {
        ConnControl::Keep => {
            tracing::trace!(target: "curl::conn", reason, "The connection is used");
        }
        ConnControl::Connection => {
            tracing::debug!(target: "curl::conn", reason, "Marked for [connection] close");
        }
        ConnControl::Stream => {
            tracing::debug!(target: "curl::conn", reason, "Marked for [stream] close");
        }
    }
    conn.conn_control(ctrl);
}

/// Marks the whole connection for close (`connclose(conn, reason)` in
/// `lib/connect.h`) — `Curl_conncontrol(conn, CONNCTRL_CONNECTION, reason)`.
#[macro_export]
macro_rules! connclose {
    ($conn:expr, $reason:expr) => {
        $crate::conn::connect::conncontrol($conn, $crate::conn::ConnControl::Connection, $reason)
    };
}

/// Marks the current stream for close (`streamclose(conn, reason)` in
/// `lib/connect.h`) — `Curl_conncontrol(conn, CONNCTRL_STREAM, reason)`.
#[macro_export]
macro_rules! streamclose {
    ($conn:expr, $reason:expr) => {
        $crate::conn::connect::conncontrol($conn, $crate::conn::ConnControl::Stream, $reason)
    };
}

/// Clears any pending close, keeping the connection alive (`connkeep(conn,
/// reason)` in `lib/connect.h`) — `Curl_conncontrol(conn, CONNCTRL_KEEP,
/// reason)`.
#[macro_export]
macro_rules! connkeep {
    ($conn:expr, $reason:expr) => {
        $crate::conn::connect::conncontrol($conn, $crate::conn::ConnControl::Keep, $reason)
    };
}

/// Computes the time left (in milliseconds) before the connect / overall
/// deadline, mirroring `Curl_timeleft_ms` (`lib/connect.c`).
///
/// curl derives the effective deadline from the *sooner* of the operation-wide
/// timeout (`--max-time`) and the connect timeout (`--connect-timeout`). This
/// rewrite has no `Curl_easy`, so the deadlines are passed explicitly:
///
/// * `now` — the current instant.
/// * `connect_start` / `connect_timeout_ms` — when the connect attempt began
///   and its budget; `0` means no connect timeout is set.
/// * `overall_start` / `overall_timeout_ms` — when the whole operation began
///   and its budget; `overall_start == None` or `overall_timeout_ms == 0` means
///   no overall timeout is set.
///
/// Returns:
/// * `0` when **no** deadline is set (infinite, matching curl's "no timeout").
/// * a positive value = milliseconds remaining.
/// * a negative value = the deadline has already passed (curl's callers test
///   `timeleft < 0` for expiry); a set-but-exactly-reached deadline returns
///   `-1` so it is never confused with the `0` "no timeout" sentinel.
#[must_use]
pub fn timeleft_ms(
    now: Instant,
    connect_start: Instant,
    connect_timeout_ms: u64,
    overall_start: Option<Instant>,
    overall_timeout_ms: u64,
) -> i64 {
    /// Milliseconds elapsed between two instants, saturating into `i64`.
    fn elapsed_ms(now: Instant, start: Instant) -> i64 {
        i64::try_from(now.saturating_duration_since(start).as_millis()).unwrap_or(i64::MAX)
    }

    let mut timeleft: i64 = 0;
    let mut has_deadline = false;

    // Overall (operation-wide, `--max-time`) deadline.
    if overall_timeout_ms > 0 {
        if let Some(start) = overall_start {
            let budget = i64::try_from(overall_timeout_ms).unwrap_or(i64::MAX);
            timeleft = budget - elapsed_ms(now, start);
            has_deadline = true;
        }
    }

    // Connect (`--connect-timeout`) deadline; use it when it is the only one or
    // when it expires sooner than the overall deadline.
    if connect_timeout_ms > 0 {
        let budget = i64::try_from(connect_timeout_ms).unwrap_or(i64::MAX);
        let connect_left = budget - elapsed_ms(now, connect_start);
        if !has_deadline || connect_left < timeleft {
            timeleft = connect_left;
        }
        has_deadline = true;
    }

    if !has_deadline {
        return 0;
    }
    if timeleft == 0 {
        // A deadline is set and exactly reached: report expiry, never the
        // `0` "no deadline" sentinel.
        -1
    } else {
        timeleft
    }
}

// ===========================================================================
// Phase 2 — the SETUP meta-filter (mirrors `cf_setup_connect`).
// ===========================================================================

/// The `SETUP` meta-filter state machine (`cf_setup_state` in `lib/connect.c`).
///
/// curl's full enum also carries `CF_SETUP_CNNCT_EYEBALLS` and
/// `CF_SETUP_CNNCT_SOCKS`; the happy-eyeballs base is installed directly by
/// [`conn_setup`] here (and SOCKS is not part of this build), so the reproduced
/// progression is the proxy → haproxy → ssl core plus the `Init`/`Done`
/// bookends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfSetupState {
    /// `CF_SETUP_INIT` — nothing installed yet.
    Init,
    /// `CF_SETUP_CNNCT_HTTP_PROXY` — HTTP CONNECT tunnel stage.
    CnnctHttpProxy,
    /// `CF_SETUP_CNNCT_HAPROXY` — HAProxy PROXY-protocol stage.
    CnnctHaProxy,
    /// `CF_SETUP_CNNCT_SSL` — TLS stage.
    CnnctSsl,
    /// `CF_SETUP_DONE` — the sub-chain is fully connected.
    Done,
}

/// Returns the fixed state progression of the `SETUP` meta-filter, matching
/// curl's `cf_setup_connect` (`CF_SETUP_INIT` → `CF_SETUP_CNNCT_HTTP_PROXY` →
/// `CF_SETUP_CNNCT_HAPROXY` → `CF_SETUP_CNNCT_SSL` → `CF_SETUP_DONE`).
///
/// This is the canonical order the filter walks; it is exposed so order-parity
/// tests can assert it directly.
#[must_use]
pub fn setup_state_sequence() -> [CfSetupState; 5] {
    [
        CfSetupState::Init,
        CfSetupState::CnnctHttpProxy,
        CfSetupState::CnnctHaProxy,
        CfSetupState::CnnctSsl,
        CfSetupState::Done,
    ]
}

/// Which stages the `SETUP` filter considers "active", captured at build time
/// from the connection so the runtime state replay can emit the same per-stage
/// trace lines curl does (the physical splicing already happened eagerly in
/// [`build_setup_chain`]).
#[derive(Debug, Clone, Copy, Default)]
struct SetupFlags {
    httpproxy: bool,
    haproxy: bool,
    want_ssl: bool,
}

/// Context of the `SETUP` meta-filter (`cf_setup_ctx` in `lib/connect.c`).
struct CfSetupCtx {
    state: CfSetupState,
    ssl_mode: i32,
    transport: Transport,
    flags: SetupFlags,
}

/// The `SETUP` meta-filter (`Curl_cft_setup`).
///
/// Its capability flags are `0` (curl's `Curl_cft_setup.flags == 0`), so it
/// delegates every I/O method to the chain below via the defaults in
/// [`crate::conn::filters`]; it overrides only `connect`/`close`.
struct SetupFilter {
    ctx: CfSetupCtx,
}

impl SetupFilter {
    /// Builds a `SETUP` filter capturing the transport, SSL mode, and the
    /// active-stage flags used for trace parity.
    fn new(transport: Transport, ssl_mode: i32, flags: SetupFlags) -> Self {
        SetupFilter {
            ctx: CfSetupCtx {
                state: CfSetupState::Init,
                ssl_mode,
                transport,
                flags,
            },
        }
    }
}

impl ConnectionFilter for SetupFilter {
    fn name(&self) -> &'static str {
        "SETUP"
    }

    fn cf_type(&self) -> CfType {
        // curl's `Curl_cft_setup` has flags 0 — no capability bits.
        CfType::default()
    }

    fn connect<'a>(
        &'a mut self,
        cx: &'a mut FilterCtx<'_>,
        blocking: bool,
    ) -> CfFuture<'a, Result<bool>> {
        Box::pin(async move {
            tracing::trace!(
                target: "curl::cf",
                filter = "SETUP",
                transport = ?self.ctx.transport,
                ssl_mode = self.ctx.ssl_mode,
                httpproxy = self.ctx.flags.httpproxy,
                haproxy = self.ctx.flags.haproxy,
                want_ssl = self.ctx.flags.want_ssl,
                "connect",
            );

            // Replay the `cf_setup_connect` state sequence once for --trace
            // parity. The sub-filters are already spliced into the chain by
            // `build_setup_chain` (the builders need `&mut FilterChain`, which a
            // running filter's `FilterCtx` cannot provide — see the module
            // NOTE), so this loop only advances diagnostic state and emits the
            // stage lines curl emits, stopping before `Done`.
            if self.ctx.state == CfSetupState::Init {
                for &state in &setup_state_sequence() {
                    if state == CfSetupState::Done {
                        break;
                    }
                    self.ctx.state = state;
                    match state {
                        CfSetupState::CnnctHttpProxy if self.ctx.flags.httpproxy => {
                            tracing::trace!(target: "curl::cf", filter = "SETUP", "stage: HTTP proxy");
                        }
                        CfSetupState::CnnctHaProxy if self.ctx.flags.haproxy => {
                            tracing::trace!(target: "curl::cf", filter = "SETUP", "stage: HAProxy");
                        }
                        CfSetupState::CnnctSsl if self.ctx.flags.want_ssl => {
                            tracing::trace!(target: "curl::cf", filter = "SETUP", "stage: SSL");
                        }
                        _ => {}
                    }
                }
            }

            // Drive the pre-assembled sub-chain (proxy → haproxy → ssl →
            // happy-eyeballs → socket) to completion.
            if !cx.connect_next(blocking).await? {
                return Ok(false);
            }

            self.ctx.state = CfSetupState::Done;
            Ok(true)
        })
    }

    fn close(&mut self, cx: &mut FilterCtx<'_>) {
        // `cf_setup_close`: reset to the initial state and tear the sub-chain
        // down. The chain clears our `connected` bit.
        self.ctx.state = CfSetupState::Init;
        cx.close_next();
    }
}

// ===========================================================================
// The SSL filter — TLS over the byte-delegating chain, via `crate::tls`.
// ===========================================================================
//
// `crate::tls` deliberately exposes only stream primitives (a
// `TlsConnector::connect` that consumes an owned `AsyncRead + AsyncWrite`), and
// defers filter composition to this layer (see the `crate::tls` module NOTE).
// The chain below the SSL filter, however, is *byte-delegating*
// (`FilterCtx::send_next`/`recv_next`), not a stream.
//
// The adapter is an in-memory `tokio::io::duplex`: rustls drives one end
// (`tls_side`); this filter owns the other (`bridge`) and pumps ciphertext
// between it and the chain below with `send_next`/`recv_next`. The whole thing
// is pure safe Rust, honoring the crate-wide forbid attribute and the AAP's
// mandate of zero raw-pointer memory management anywhere in the TLS layer.

/// The TLS filter (`"SSL"`, `CF_TYPE_SSL`). Wraps the stream produced by the
/// chain below with a rustls session built from the connection's
/// [`TlsConfig`](crate::tls::TlsConfig).
struct SslFilter {
    connector: TlsConnector,
    server_name: String,
    /// The established rustls session (client side of the bridge), set once the
    /// handshake completes.
    tls: Option<TlsStream<DuplexStream>>,
    /// The chain-facing end of the bridge; ciphertext is pumped across it.
    bridge: Option<DuplexStream>,
    established: bool,
}

impl SslFilter {
    /// Builds an SSL filter from a [`TlsConfig`](crate::tls::TlsConfig) and the
    /// server name to validate against.
    ///
    /// # Errors
    ///
    /// Propagates [`TlsConnector::from_config`] failures (e.g. an unreadable CA
    /// source), preserving curl's TLS-setup error codes.
    fn new(config: &crate::tls::TlsConfig, server_name: String) -> Result<Self> {
        let connector = TlsConnector::from_config(config)?;
        Ok(SslFilter {
            connector,
            server_name,
            tls: None,
            bridge: None,
            established: false,
        })
    }
}

/// Polls a future exactly once, converting `Pending` into `None` so the caller
/// can interleave I/O between advances. Never drops the polled future (the
/// caller retains it), so no progress or wakeups are lost across iterations.
async fn poll_once<F>(mut fut: Pin<&mut F>) -> Option<F::Output>
where
    F: Future,
{
    std::future::poll_fn(|cx| match fut.as_mut().poll(cx) {
        Poll::Ready(v) => Poll::Ready(Some(v)),
        Poll::Pending => Poll::Ready(None),
    })
    .await
}

/// Drains all ciphertext the TLS engine has buffered on `bridge` down to the
/// chain below via `cx.send_next`. Returns once the buffer is empty (a bounded
/// wait distinguishes "empty" from "more coming" without a peek API) or on EOF.
async fn drain_outbound(
    cx: &mut FilterCtx<'_>,
    bridge: &mut DuplexStream,
    buf: &mut [u8],
) -> Result<()> {
    loop {
        match tokio::time::timeout(Duration::from_millis(SSL_FLUSH_DRAIN_MS), bridge.read(buf))
            .await
        {
            Ok(Ok(0)) => return Ok(()), // the TLS engine closed its side
            Ok(Ok(n)) => {
                let mut off = 0;
                while off < n {
                    let sent = cx.send_next(&buf[off..n], false).await?;
                    if sent == 0 {
                        return Err(Error::tls(
                            "TLS: peer closed while flushing handshake ciphertext",
                        ));
                    }
                    off += sent;
                }
            }
            Ok(Err(e)) => return Err(Error::tls(format!("TLS bridge read failed: {e}"))),
            Err(_elapsed) => return Ok(()), // no more buffered outbound
        }
    }
}

impl ConnectionFilter for SslFilter {
    fn name(&self) -> &'static str {
        "SSL"
    }

    fn cf_type(&self) -> CfType {
        CfType::SSL
    }

    fn connect<'a>(
        &'a mut self,
        cx: &'a mut FilterCtx<'_>,
        blocking: bool,
    ) -> CfFuture<'a, Result<bool>> {
        Box::pin(async move {
            if self.established {
                return Ok(true);
            }
            // The transport below must be connected before the TLS handshake.
            if !cx.connect_next(blocking).await? {
                return Ok(false);
            }

            // Clone the (Arc-backed, cheap) connector + name so the handshake
            // future borrows locals, never `self`, across await points.
            let connector = self.connector.clone();
            let server_name = self.server_name.clone();

            let (tls_side, mut bridge) = tokio::io::duplex(SSL_BRIDGE_BUF);
            let mut handshake = Box::pin(connector.connect(&server_name, tls_side));
            let mut obuf = vec![0u8; SSL_PUMP_BUF];
            let mut ibuf = vec![0u8; SSL_PUMP_BUF];

            let stream = loop {
                // Push whatever ciphertext rustls has produced down the chain.
                drain_outbound(cx, &mut bridge, &mut obuf).await?;

                // Advance the handshake as far as it can go without more input.
                if let Some(res) = poll_once(handshake.as_mut()).await {
                    break res?;
                }

                // Still pending: the handshake needs a flight from the peer.
                let n = cx.recv_next(&mut ibuf).await?;
                if n == 0 {
                    return Err(Error::tls(
                        "TLS handshake aborted: peer closed the connection",
                    ));
                }
                bridge
                    .write_all(&ibuf[..n])
                    .await
                    .map_err(|e| Error::tls(format!("TLS bridge write failed: {e}")))?;
            };

            // Flush the client's final flight, buffered during the last poll.
            drain_outbound(cx, &mut bridge, &mut obuf).await?;

            tracing::trace!(target: "curl::cf", filter = "SSL", server = %server_name, "TLS handshake complete");
            self.tls = Some(stream);
            self.bridge = Some(bridge);
            self.established = true;
            Ok(true)
        })
    }

    fn send<'a>(
        &'a mut self,
        cx: &'a mut FilterCtx<'_>,
        buf: &'a [u8],
        _eos: bool,
    ) -> CfFuture<'a, Result<usize>> {
        Box::pin(async move {
            {
                let tls = self
                    .tls
                    .as_mut()
                    .ok_or_else(|| Error::tls("SSL send before handshake completed"))?;
                tls.write_all(buf)
                    .await
                    .map_err(|e| Error::tls(format!("TLS write failed: {e}")))?;
                tls.flush()
                    .await
                    .map_err(|e| Error::tls(format!("TLS flush failed: {e}")))?;
            }
            // Push the produced ciphertext down the chain.
            let mut obuf = vec![0u8; SSL_PUMP_BUF];
            let bridge = self
                .bridge
                .as_mut()
                .ok_or_else(|| Error::tls("SSL send before handshake completed"))?;
            drain_outbound(cx, bridge, &mut obuf).await?;
            Ok(buf.len())
        })
    }

    fn recv<'a>(
        &'a mut self,
        cx: &'a mut FilterCtx<'_>,
        buf: &'a mut [u8],
    ) -> CfFuture<'a, Result<usize>> {
        Box::pin(async move {
            let mut ibuf = vec![0u8; SSL_PUMP_BUF];
            let mut obuf = vec![0u8; SSL_PUMP_BUF];
            loop {
                // Relieve any outbound backpressure (post-handshake tickets /
                // key updates rustls may emit while processing a read).
                {
                    let bridge = self
                        .bridge
                        .as_mut()
                        .ok_or_else(|| Error::tls("SSL recv before handshake completed"))?;
                    drain_outbound(cx, bridge, &mut obuf).await?;
                }

                // Try to read decrypted plaintext without blocking.
                {
                    let tls = self
                        .tls
                        .as_mut()
                        .ok_or_else(|| Error::tls("SSL recv before handshake completed"))?;
                    let read = tls.read(buf);
                    tokio::pin!(read);
                    if let Some(res) = poll_once(read.as_mut()).await {
                        return res.map_err(|e| Error::tls(format!("TLS read failed: {e}")));
                    }
                }

                // Not enough ciphertext yet: pull a chunk from below.
                let n = cx.recv_next(&mut ibuf).await?;
                let bridge = self
                    .bridge
                    .as_mut()
                    .ok_or_else(|| Error::tls("SSL recv before handshake completed"))?;
                if n == 0 {
                    // Peer closed: signal EOF to the TLS engine and let the read
                    // resolve (clean `0`, or an error for a truncated stream).
                    let _ = bridge.shutdown().await;
                    let tls = self
                        .tls
                        .as_mut()
                        .ok_or_else(|| Error::tls("SSL recv before handshake completed"))?;
                    return tls
                        .read(buf)
                        .await
                        .map_err(|e| Error::tls(format!("TLS read after close failed: {e}")));
                }
                bridge
                    .write_all(&ibuf[..n])
                    .await
                    .map_err(|e| Error::tls(format!("TLS bridge write failed: {e}")))?;
            }
        })
    }

    fn close(&mut self, cx: &mut FilterCtx<'_>) {
        self.tls = None;
        self.bridge = None;
        self.established = false;
        cx.close_next();
    }
}

// ===========================================================================
// Phase 3 — top-level setup entry (mirrors `Curl_conn_setup`).
// ===========================================================================

/// Whether `conn`'s chain for `sockindex` is missing or empty (curl's
/// `!conn->cfilter[sockindex]`).
fn chain_is_empty(conn: &Connection, sockindex: usize) -> bool {
    conn.cfilter
        .get(sockindex)
        .and_then(Option::as_ref)
        .map_or(true, FilterChain::is_empty)
}

/// Sets up the connection-filter chain for `sockindex`, mirroring
/// `Curl_conn_setup` (`lib/connect.c`).
///
/// Routing follows curl exactly:
/// 1. If no chain exists yet **and** the scheme is HTTPS, delegate to
///    [`https_connect::https_setup`], which builds its own stack (HTTP version
///    eyeballing, or a TLS-to-proxy + tunnel for an HTTPS proxy). When ALPN is
///    disabled that call installs nothing and we fall through to step 2, so a
///    plain single-version HTTPS connection uses the default `SETUP` stack with
///    a single [`SslFilter`].
/// 2. If the chain is still empty, install the default `SETUP` stack over a
///    happy-eyeballs base via [`build_setup_chain`].
///
/// `dns` is the resolved address entry for this socket. curl stores it in
/// `data->state.dns[sockindex]` and releases it with `Curl_resolv_unlink`; this
/// rewrite has no such slot, so the `Arc` simply keeps the entry alive while
/// its endpoints seed the happy-eyeballs base, and is released when this
/// function returns — including on an early `Err`, which subsumes
/// `Curl_resolv_unlink`.
///
/// `ssl_mode` is one of [`CURL_CF_SSL_DEFAULT`](crate::conn::CURL_CF_SSL_DEFAULT),
/// [`CURL_CF_SSL_ENABLE`], or [`CURL_CF_SSL_DISABLE`].
///
/// # Errors
///
/// Returns [`Error::bad_argument`] for an out-of-range `sockindex`, and
/// propagates any chain-assembly failure (for example the
/// [`Error::UnsupportedProtocol`] raised when HAProxy is requested with TLS
/// already in place).
pub async fn conn_setup(
    conn: &mut Connection,
    sockindex: usize,
    dns: Arc<DnsEntry>,
    ssl_mode: i32,
) -> Result<()> {
    if sockindex >= conn.cfilter.len() {
        return Err(Error::bad_argument(format!(
            "conn_setup: invalid socket index {sockindex}"
        )));
    }

    let transport = conn.transport_wanted;
    let is_https = conn.scheme.name.eq_ignore_ascii_case("https");

    // HTTPS builds its own stack first (curl tries `Curl_cf_https_setup` before
    // the default setup filter).
    if is_https && chain_is_empty(conn, sockindex) {
        let mut chain = FilterChain::new(sockindex);
        https_connect::https_setup(&mut chain, conn, sockindex)?;
        if !chain.is_empty() {
            conn.cfilter[sockindex] = Some(chain);
        }
    }

    // Still nothing installed → the default `SETUP` stack (proxy/haproxy/ssl
    // over a happy-eyeballs base).
    if chain_is_empty(conn, sockindex) {
        let chain = build_setup_chain(conn, dns.as_ref(), sockindex, transport, ssl_mode)?;
        conn.cfilter[sockindex] = Some(chain);
    }

    Ok(())
}

/// Assembles the default `SETUP` stack for `sockindex`, in curl's exact
/// `cf_setup_connect` insertion order, and returns the ready chain.
///
/// The physical layout is `SETUP → [HTTP-PROXY] → [HAPROXY] → [SSL] →
/// HAPPY-EYEBALLS`. Because the filter builders require `&mut FilterChain` (a
/// running filter cannot splice new nodes; see the module NOTE), the chain is
/// built eagerly here rather than lazily inside the `SETUP` filter's connect —
/// preserving the identical order, and therefore identical `--trace` output.
///
/// # Errors
///
/// Returns [`Error::UnsupportedProtocol`] if the HAProxy protocol is requested
/// while TLS is already in place (curl: *"haproxy protocol not support with SSL
/// encryption in place (QUIC?)"*), and propagates filter-builder failures.
fn build_setup_chain(
    conn: &Connection,
    dns: &DnsEntry,
    sockindex: usize,
    transport: Transport,
    ssl_mode: i32,
) -> Result<FilterChain> {
    let mut chain = FilterChain::new(sockindex);

    // Whether the origin scheme wants TLS (curl's `ssl_mode`/`PROTOPT_SSL`
    // logic): explicitly enabled, or default-on for an SSL scheme.
    let want_ssl =
        ssl_mode == CURL_CF_SSL_ENABLE || (ssl_mode != CURL_CF_SSL_DISABLE && conn.scheme.is_ssl);

    // --- Top: the SETUP meta-filter (curl prepends `Curl_cft_setup`). ---
    let flags = SetupFlags {
        httpproxy: conn.bits.httpproxy,
        haproxy: conn.haproxy_protocol,
        want_ssl,
    };
    chain.add(Box::new(SetupFilter::new(transport, ssl_mode, flags)));

    // QUIC carries its own TLS, so TLS counts as already "in place".
    let mut ssl_in_place = transport == Transport::Quic;

    // --- CF_SETUP_CNNCT_HTTP_PROXY ---
    if conn.bits.httpproxy {
        // Insert the CONNECT tunnel first so it sits *above* the proxy-TLS layer
        // (curl composes TLS-to-proxy at the tail with the tunnel prepended).
        //
        // curl's `cf_setup_connect` chooses between the HTTP/1 and HTTP/2 CONNECT
        // tunnel filters here (`Curl_cf_h1_proxy_insert_after` vs
        // `Curl_cf_h2_proxy_insert_after` for a `CURLPROXY_HTTPS2` proxy). In this
        // eager-assembly chain the tunnel is realized by the *byte-delegating*
        // [`crate::conn::h1_proxy`] filter, which pumps CONNECT bytes through the
        // chain below (the proxy-TLS `SSL` filter, then the socket) rather than
        // owning a transport of its own. The socket-owning HTTP/2 proxy filter
        // ([`crate::conn::h2_proxy`], whose `insert_after` takes an owned
        // `transport: S`) is composed in the dedicated HTTP-version-eyeballing
        // stack built by [`crate::conn::https_connect`], which — like this path —
        // layers `h1_proxy` for the CONNECT request while negotiating HTTP/2 to
        // the proxy through the proxy-TLS ALPN. Keeping the tunnel filter uniform
        // here preserves curl's insertion *order* (the load-bearing `--trace`
        // parity concern) without depending on a not-yet-created socket.
        if conn.bits.tunnel_proxy {
            let at = chain.len() - 1;
            let cfg = h1_proxy::H1ProxyConfig::new(conn.host.name.clone(), conn.remote_port);
            h1_proxy::insert_after(&mut chain, at, cfg)?;
        }
        // An HTTPS proxy needs TLS to the proxy, established below the tunnel.
        if matches!(
            conn.http_proxy.proxytype,
            ProxyType::Https | ProxyType::Https2
        ) && !ssl_in_place
        {
            let at = chain.len() - 1;
            let ssl = SslFilter::new(&conn.proxy_ssl_config, conn.http_proxy.host.name.clone())?;
            chain.insert_after(at, Box::new(ssl))?;
            ssl_in_place = true;
        }
    }

    // --- CF_SETUP_CNNCT_HAPROXY ---
    if conn.haproxy_protocol {
        if ssl_in_place {
            // curl fails here with CURLE_UNSUPPORTED_PROTOCOL and this message.
            tracing::error!(
                target: "curl::cf",
                "haproxy protocol not support with SSL encryption in place (QUIC?)"
            );
            return Err(Error::UnsupportedProtocol);
        }
        let at = chain.len() - 1;
        haproxy::insert_after(&mut chain, at)?;
    }

    // --- CF_SETUP_CNNCT_SSL ---
    if want_ssl && !ssl_in_place {
        let at = chain.len() - 1;
        let ssl = SslFilter::new(&conn.ssl_config, conn.host.name.clone())?;
        chain.insert_after(at, Box::new(ssl))?;
    }

    // --- Base: happy-eyeballs (owns the per-address socket sub-chains). ---
    let at = chain.len() - 1;
    let addrs = dns.endpoints().to_vec();
    let base = happy_eyeballs::create_with_dns(
        transport,
        addrs,
        conn.ip_version,
        happy_eyeballs::CURL_HET_DEFAULT_MS,
        None,
    );
    chain.insert_after(at, base)?;

    Ok(chain)
}

/// Adds the `SETUP` meta-filter at the top of `conn`'s chain for `sockindex`
/// (`cf_setup_add` in `lib/connect.c`), creating the chain if none exists yet.
///
/// The `SETUP` filter is always prepended (curl's `Curl_conn_cf_add`).
///
/// # Errors
///
/// Returns [`Error::bad_argument`] for an out-of-range `sockindex`.
pub fn cf_setup_add(
    conn: &mut Connection,
    sockindex: usize,
    transport: Transport,
    ssl_mode: i32,
) -> Result<()> {
    if sockindex >= conn.cfilter.len() {
        return Err(Error::bad_argument(format!(
            "cf_setup_add: invalid socket index {sockindex}"
        )));
    }
    let flags = SetupFlags {
        httpproxy: conn.bits.httpproxy,
        haproxy: conn.haproxy_protocol,
        want_ssl: ssl_mode == CURL_CF_SSL_ENABLE
            || (ssl_mode != CURL_CF_SSL_DISABLE && conn.scheme.is_ssl),
    };
    let chain = conn.cfilter[sockindex].get_or_insert_with(|| FilterChain::new(sockindex));
    chain.add(Box::new(SetupFilter::new(transport, ssl_mode, flags)));
    Ok(())
}

/// Inserts a `SETUP` meta-filter directly below the filter at `at_index`
/// (`Curl_cf_setup_insert_after` in `lib/connect.c`).
///
/// # Errors
///
/// Propagates [`FilterChain::insert_after`]'s [`Error::bad_argument`] when
/// `at_index` is out of range.
pub fn setup_insert_after(
    chain: &mut FilterChain,
    at_index: usize,
    transport: Transport,
    ssl_mode: i32,
) -> Result<()> {
    chain.insert_after(
        at_index,
        Box::new(SetupFilter::new(transport, ssl_mode, SetupFlags::default())),
    )
}

/// Marks the connection as multiplexed, mirroring `Curl_conn_set_multiplex`
/// (`lib/connect.c`).
///
/// Sets `conn->bits.multiplex` and, when a multi handle is attached, records
/// that the multi must be told the connection changed. The notification is a
/// pending flag drained by the multi layer (via
/// [`Connection::take_multi_connchanged`]), so no direct `crate::multi` import —
/// and therefore no module cycle — is needed.
pub fn set_multiplex(conn: &mut Connection) {
    conn.set_multiplex();
}

// ===========================================================================
// Phase 4 — connect timeout & address iteration.
// ===========================================================================

/// Drives the connection at `sockindex` to completion under the connect
/// timeout, mirroring how curl bounds `connect` with `DEFAULT_CONNECT_TIMEOUT`
/// (unless a `--connect-timeout` is set).
///
/// The chain must already be installed by [`conn_setup`]. Address racing across
/// the resolved endpoints is owned by
/// [`happy_eyeballs`](crate::conn::happy_eyeballs) at the base of the chain;
/// this function only drives the head filter to `done` and applies the timeout.
///
/// `connect_timeout_ms` is the user's connect budget; `0` selects
/// [`DEFAULT_CONNECT_TIMEOUT_MS`].
///
/// # Errors
///
/// * [`Error::Timeout`] (curl `CURLE_OPERATION_TIMEDOUT`, 28) if the budget
///   elapses first.
/// * [`Error::Connect`] (curl `CURLE_COULDNT_CONNECT`, 7) surfaced from the
///   socket layer when every candidate address fails.
pub async fn connect_with_timeout(
    conn: &mut Connection,
    sockindex: usize,
    connect_timeout_ms: u64,
) -> Result<()> {
    let budget = if connect_timeout_ms > 0 {
        connect_timeout_ms
    } else {
        DEFAULT_CONNECT_TIMEOUT_MS
    };

    match tokio::time::timeout(
        Duration::from_millis(budget),
        drive_connect(conn, sockindex),
    )
    .await
    {
        Ok(res) => res,
        Err(_elapsed) => {
            tracing::error!(
                target: "curl::conn",
                sockindex,
                timeout_ms = budget,
                "Connection timed out"
            );
            Err(Error::Timeout)
        }
    }
}

/// Repeatedly drives the chain head until the connect reports `done`, yielding
/// between non-blocking attempts. Connection failures surface immediately from
/// the socket layer (typically [`Error::Connect`]).
async fn drive_connect(conn: &mut Connection, sockindex: usize) -> Result<()> {
    loop {
        if conn.connect(sockindex, true).await? {
            return Ok(());
        }
        tokio::task::yield_now().await;
    }
}

// ===========================================================================
// Tests.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{Scheme, CURL_CF_SSL_DEFAULT, FIRSTSOCKET};
    use crate::dns::Address;
    use crate::error::CurlCode;
    use crate::tls::TlsConfig;
    use std::net::SocketAddr;

    // -- helpers ------------------------------------------------------------

    fn scheme(name: &str, default_port: u16, is_ssl: bool) -> Scheme {
        Scheme {
            name: name.to_string(),
            default_port,
            is_ssl,
            no_network: false,
        }
    }

    fn http_conn(host: &str, port: u16) -> Connection {
        Connection::new(scheme("http", 80, false), host, port)
    }

    fn dns_entry(addrs: Vec<SocketAddr>) -> Arc<DnsEntry> {
        Arc::new(DnsEntry::new(Address::new(addrs), "example.com", 80, false))
    }

    /// A leaf filter that reports connected immediately.
    struct ReadyTail;
    impl ConnectionFilter for ReadyTail {
        fn name(&self) -> &'static str {
            "TCP"
        }
        fn cf_type(&self) -> CfType {
            CfType::IP_CONNECT
        }
        fn connect<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            _blocking: bool,
        ) -> CfFuture<'a, Result<bool>> {
            Box::pin(async { Ok(true) })
        }
    }

    /// A leaf filter that never finishes connecting (parks), used to exercise
    /// the connect-timeout path deterministically.
    struct PendingTail;
    impl ConnectionFilter for PendingTail {
        fn name(&self) -> &'static str {
            "PENDING"
        }
        fn cf_type(&self) -> CfType {
            CfType::default()
        }
        fn connect<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            _blocking: bool,
        ) -> CfFuture<'a, Result<bool>> {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                Ok(false)
            })
        }
    }

    /// A leaf filter whose connect fails as if the peer refused the connection.
    struct RefusedTail;
    impl ConnectionFilter for RefusedTail {
        fn name(&self) -> &'static str {
            "TCP"
        }
        fn cf_type(&self) -> CfType {
            CfType::IP_CONNECT
        }
        fn connect<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            _blocking: bool,
        ) -> CfFuture<'a, Result<bool>> {
            Box::pin(async { Err(Error::connect("Connection refused")) })
        }
    }

    // -- Phase 1: constants, conncontrol, timeleft --------------------------

    #[test]
    fn default_connect_timeout_matches_curl() {
        // curl's DEFAULT_CONNECT_TIMEOUT is 300000 ms (5 minutes).
        assert_eq!(DEFAULT_CONNECT_TIMEOUT_MS, 300_000);
    }

    #[test]
    fn conncontrol_marks_connection_close() {
        let mut conn = http_conn("example.com", 80);
        assert!(!conn.bits.close);
        conncontrol(&mut conn, ConnControl::Connection, "test reason");
        assert!(conn.bits.close);
    }

    #[test]
    fn conncontrol_macros_set_and_clear_close() {
        let mut conn = http_conn("example.com", 80);
        crate::connclose!(&mut conn, "close via macro");
        assert!(conn.bits.close);
        crate::connkeep!(&mut conn, "keep via macro");
        assert!(!conn.bits.close);
    }

    #[test]
    fn streamclose_on_non_multiplex_closes_connection() {
        // On a non-multiplexed connection a stream-close escalates to a
        // connection-close (curl's `Curl_conncontrol` semantics).
        let mut conn = http_conn("example.com", 80);
        assert!(!conn.is_multiplex(FIRSTSOCKET));
        crate::streamclose!(&mut conn, "stream close");
        assert!(conn.bits.close);
    }

    #[test]
    fn set_multiplex_sets_bit() {
        let mut conn = http_conn("example.com", 80);
        assert!(!conn.bits.multiplex);
        set_multiplex(&mut conn);
        assert!(conn.bits.multiplex);
    }

    #[test]
    fn timeleft_no_deadline_is_zero() {
        let start = Instant::now();
        assert_eq!(timeleft_ms(start, start, 0, None, 0), 0);
    }

    #[test]
    fn timeleft_reports_remaining_and_expiry() {
        let start = Instant::now();
        // 1s into a 5s connect budget → 4000 ms remaining.
        let now = start + Duration::from_millis(1000);
        assert_eq!(timeleft_ms(now, start, 5000, None, 0), 4000);
        // 6s into a 5s budget → expired (negative).
        let now = start + Duration::from_millis(6000);
        assert!(timeleft_ms(now, start, 5000, None, 0) < 0);
    }

    #[test]
    fn timeleft_uses_the_sooner_deadline() {
        let start = Instant::now();
        let now = start + Duration::from_millis(500);
        // overall: 1000 - 500 = 500; connect: 5000 - 500 = 4500 → sooner = 500.
        assert_eq!(timeleft_ms(now, start, 5000, Some(start), 1000), 500);
    }

    // -- Phase 2: SETUP state machine ---------------------------------------

    #[test]
    fn setup_state_sequence_is_curl_order() {
        assert_eq!(
            setup_state_sequence(),
            [
                CfSetupState::Init,
                CfSetupState::CnnctHttpProxy,
                CfSetupState::CnnctHaProxy,
                CfSetupState::CnnctSsl,
                CfSetupState::Done,
            ]
        );
    }

    #[tokio::test]
    async fn setup_filter_completes_via_delegation() {
        // Driving the SETUP filter to Ok(true) proves its state machine ran to
        // `Done` (it only reports done after delegating a connected sub-chain).
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(ReadyTail)); // tail
        chain.add(Box::new(SetupFilter::new(
            Transport::Tcp,
            CURL_CF_SSL_DISABLE,
            SetupFlags::default(),
        ))); // head = SETUP
        let done = chain.connect(true).await.expect("connect ok");
        assert!(done);
        assert_eq!(chain.head().map(ConnectionFilter::name), Some("SETUP"));
    }

    #[test]
    fn ssl_filter_identity() {
        let cfg = TlsConfig::default();
        let ssl = SslFilter::new(&cfg, "example.com".to_string()).expect("connector builds");
        assert_eq!(ssl.name(), "SSL");
        assert_eq!(ssl.cf_type(), CfType::SSL);
        assert!(!ssl.established);
    }

    // -- Phase 2/3: filter INSERTION ORDER (the critical parity test) -------

    #[test]
    fn ordering_httpproxy_tunnel_ssl() {
        let mut conn = http_conn("example.com", 80);
        conn.bits.httpproxy = true;
        conn.bits.tunnel_proxy = true;
        let dns = DnsEntry::new(Address::new(vec![]), "example.com", 80, false);
        let chain = build_setup_chain(&conn, &dns, FIRSTSOCKET, Transport::Tcp, CURL_CF_SSL_ENABLE)
            .expect("chain builds");
        assert_eq!(
            chain.names(),
            vec!["SETUP", "HTTP-PROXY", "SSL", "HAPPY-EYEBALLS"]
        );
    }

    #[test]
    fn ordering_httpproxy_tunnel_haproxy_ssl() {
        let mut conn = http_conn("example.com", 80);
        conn.bits.httpproxy = true;
        conn.bits.tunnel_proxy = true;
        conn.haproxy_protocol = true;
        let dns = DnsEntry::new(Address::new(vec![]), "example.com", 80, false);
        let chain = build_setup_chain(&conn, &dns, FIRSTSOCKET, Transport::Tcp, CURL_CF_SSL_ENABLE)
            .expect("chain builds");
        assert_eq!(
            chain.names(),
            vec!["SETUP", "HTTP-PROXY", "HAPROXY", "SSL", "HAPPY-EYEBALLS"]
        );
    }

    #[test]
    fn ssl_filter_sits_at_the_ssl_stage() {
        // Confirm the "SSL" node carries the SSL capability bit at its position.
        let conn = http_conn("example.com", 80);
        let dns = DnsEntry::new(Address::new(vec![]), "example.com", 80, false);
        let chain = build_setup_chain(&conn, &dns, FIRSTSOCKET, Transport::Tcp, CURL_CF_SSL_ENABLE)
            .expect("chain builds");
        let layout = chain.layout();
        // SETUP (no bits) → SSL (CfType::SSL) → HAPPY-EYEBALLS.
        assert_eq!(layout[0].0, "SETUP");
        assert!(layout[0].1.is_empty());
        assert_eq!(layout[1].0, "SSL");
        assert!(layout[1].1.contains(CfType::SSL));
    }

    #[test]
    fn haproxy_with_ssl_in_place_is_unsupported_protocol() {
        // QUIC carries its own TLS, so requesting HAProxy conflicts with it.
        let mut conn = http_conn("example.com", 80);
        conn.haproxy_protocol = true;
        let dns = DnsEntry::new(Address::new(vec![]), "example.com", 80, false);
        let err = build_setup_chain(
            &conn,
            &dns,
            FIRSTSOCKET,
            Transport::Quic,
            CURL_CF_SSL_DISABLE,
        )
        .expect_err("must conflict");
        assert_eq!(err.code(), CurlCode::UnsupportedProtocol);
    }

    // -- Phase 3: conn_setup routing ----------------------------------------

    #[tokio::test]
    async fn conn_setup_http_installs_setup_over_eyeballs() {
        let mut conn = http_conn("example.com", 80);
        let dns = dns_entry(vec!["127.0.0.1:80".parse().unwrap()]);
        conn_setup(&mut conn, FIRSTSOCKET, dns, CURL_CF_SSL_DEFAULT)
            .await
            .expect("setup ok");
        let names = conn.cfilter[FIRSTSOCKET]
            .as_ref()
            .expect("chain present")
            .names();
        // Plain http: SETUP over the happy-eyeballs base, no SSL.
        assert_eq!(names, vec!["SETUP", "HAPPY-EYEBALLS"]);
    }

    #[tokio::test]
    async fn conn_setup_https_routes_through_https_connect() {
        let mut conn = Connection::new(scheme("https", 443, true), "example.com", 443);
        // ALPN on → https_setup installs its version-eyeballing filter.
        conn.bits.tls_enable_alpn = true;
        let dns = dns_entry(vec!["127.0.0.1:443".parse().unwrap()]);
        conn_setup(&mut conn, FIRSTSOCKET, dns, CURL_CF_SSL_DEFAULT)
            .await
            .expect("setup ok");
        let head = conn.cfilter[FIRSTSOCKET]
            .as_ref()
            .expect("chain present")
            .head()
            .map(ConnectionFilter::name);
        assert_eq!(head, Some("HTTPS-CONNECT"));
    }

    #[tokio::test]
    async fn conn_setup_rejects_bad_socket_index() {
        let mut conn = http_conn("example.com", 80);
        let dns = dns_entry(vec![]);
        let err = conn_setup(&mut conn, 99, dns, CURL_CF_SSL_DEFAULT)
            .await
            .expect_err("bad index");
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
    }

    // -- Phase 3: cf_setup_add / setup_insert_after -------------------------

    #[test]
    fn cf_setup_add_prepends_setup() {
        let mut conn = http_conn("example.com", 80);
        cf_setup_add(&mut conn, FIRSTSOCKET, Transport::Tcp, CURL_CF_SSL_DISABLE).expect("add ok");
        assert_eq!(
            conn.cfilter[FIRSTSOCKET].as_ref().unwrap().names(),
            vec!["SETUP"]
        );
        // A second, spliced-in SETUP lands directly below the first.
        let chain = conn.cfilter[FIRSTSOCKET].as_mut().unwrap();
        setup_insert_after(chain, 0, Transport::Tcp, CURL_CF_SSL_DISABLE).expect("insert ok");
        assert_eq!(chain.names(), vec!["SETUP", "SETUP"]);
    }

    #[test]
    fn cf_setup_add_rejects_bad_socket_index() {
        let mut conn = http_conn("example.com", 80);
        assert!(cf_setup_add(&mut conn, 99, Transport::Tcp, CURL_CF_SSL_DISABLE).is_err());
    }

    // -- Phase 4: connect timeout & failure ---------------------------------

    #[tokio::test]
    async fn connect_timeout_returns_operation_timedout() {
        let mut conn = http_conn("example.com", 80);
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(PendingTail));
        conn.cfilter[FIRSTSOCKET] = Some(chain);
        let err = connect_with_timeout(&mut conn, FIRSTSOCKET, 50)
            .await
            .expect_err("must time out");
        assert_eq!(err.code(), CurlCode::OperationTimedout);
    }

    #[tokio::test]
    async fn connect_refused_returns_couldnt_connect() {
        let mut conn = http_conn("example.com", 80);
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(RefusedTail));
        conn.cfilter[FIRSTSOCKET] = Some(chain);
        let err = connect_with_timeout(&mut conn, FIRSTSOCKET, 5_000)
            .await
            .expect_err("must fail");
        assert_eq!(err.code(), CurlCode::CouldntConnect);
    }
}
