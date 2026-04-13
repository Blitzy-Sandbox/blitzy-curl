//! Happy Eyeballs v2 (RFC 8305) connection filter.
//!
//! Rust rewrite of `lib/cf-ip-happy.c` (982 lines) — implements the Happy
//! Eyeballs Version 2 algorithm for dual-stack IPv4/IPv6 connection racing.
//! This filter tries both IPv6 and IPv4 connections in parallel with a
//! staggered start, selecting the first one that succeeds.
//!
//! # Algorithm Summary (RFC 8305)
//!
//! 1. **Address interleaving** (Section 4): DNS-resolved addresses are sorted
//!    by alternating between IPv6 and IPv4: `[v6_0, v4_0, v6_1, v4_1, …]`.
//!    IPv6 is preferred and tried first.
//!
//! 2. **Staggered starts** (Section 5): The first preferred-family address
//!    starts immediately. After a configurable delay (default 200 ms), the
//!    next address starts in parallel. Additional addresses start at
//!    subsequent stagger intervals.
//!
//! 3. **First-wins**: The first connection attempt to complete successfully
//!    becomes the winner. All other in-flight attempts are cancelled.
//!
//! 4. **Error aggregation**: If all attempts fail, the most informative error
//!    is returned (connection-refused preferred over timeout).
//!
//! # Architecture
//!
//! `HappyEyeballsFilter` implements [`ConnectionFilter`] and sits in the
//! connection filter chain at the IP-connect level. During the `connect()`
//! phase it races multiple TCP connections via `tokio::spawn`, using
//! `tokio::sync::mpsc` to collect results. After a winner is found, the
//! winning `TcpStream` is owned by the filter and used directly for all
//! subsequent `send()`/`recv()` operations.
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, trace, warn};

use crate::conn::filters::{
    ConnectionFilter, PollAction, PollSet, QueryResult, TransferData,
    CF_QUERY_CONNECT_REPLY_MS, CF_QUERY_TIMER_APPCONNECT, CF_QUERY_TIMER_CONNECT,
    CF_TYPE_IP_CONNECT,
};
use crate::conn::socket::SocketConfig;
use crate::error::CurlError;

// ===========================================================================
// Constants
// ===========================================================================

/// Default Happy Eyeballs stagger delay in milliseconds.
///
/// RFC 8305 Section 5 recommends 250 ms; curl 8.x uses 200 ms
/// (`HAPPY_EYEBALLS_TIMEOUT` in `lib/connect.h`). We match curl 8.x.
pub const DEFAULT_HAPPY_EYEBALLS_DELAY_MS: u64 = 200;

/// Default overall connection timeout when none is specified (5 minutes).
///
/// Matches `CURL_TIMEOUT_DEFAULT` in the C implementation.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(300);

// ===========================================================================
// Internal Types
// ===========================================================================

/// State machine for the Happy Eyeballs algorithm.
///
/// Corresponds to the C `cf_connect_state` enum (`SCFST_INIT`, `SCFST_WAITING`,
/// `SCFST_DONE`) with an additional `Failed` terminal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EyeballsState {
    /// Initial state — addresses have been provided but no connection
    /// attempts have started yet.
    Init,
    /// Connection attempts are in flight. The stagger timer may fire to
    /// start additional attempts.
    Connecting,
    /// A winner has been found. The winning stream is owned by the filter.
    Connected,
    /// All connection attempts failed. The aggregated error is stored.
    Failed,
}

/// IP version resolve preference, matching `CURLOPT_IPRESOLVE` values.
///
/// - `Whatever` (0): Try both IPv6 and IPv4 (default, Happy Eyeballs).
/// - `V4Only` (1): Restrict to IPv4 addresses only.
/// - `V6Only` (2): Restrict to IPv6 addresses only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum IpResolve {
    /// Use both IPv4 and IPv6 (CURL_IPRESOLVE_WHATEVER = 0).
    #[default]
    Whatever,
    /// IPv4 only (CURL_IPRESOLVE_V4 = 1).
    V4Only,
    /// IPv6 only (CURL_IPRESOLVE_V6 = 2).
    V6Only,
}

/// Result message sent from a spawned connection attempt back to the
/// coordinator via the mpsc channel.
struct AttemptResult {
    /// The target address this attempt was connecting to.
    addr: SocketAddr,
    /// Index of this attempt in the interleaved address list.
    index: usize,
    /// The connected TCP stream on success, or the I/O error on failure.
    outcome: Result<TcpStream, io::Error>,
}

// ===========================================================================
// Address Interleaving — RFC 8305 Section 4
// ===========================================================================

/// Interleave IPv6 and IPv4 addresses per RFC 8305 Section 4.
///
/// The resulting order is: `[v6_0, v4_0, v6_1, v4_1, …]`, with IPv6
/// addresses preferred (started first). If only one address family is
/// present, all addresses are returned in their original DNS order.
///
/// # Arguments
///
/// * `addresses` — DNS-resolved addresses in their original order.
/// * `resolve` — IP version preference from `CURLOPT_IPRESOLVE`.
///
/// # Returns
///
/// A new `Vec<SocketAddr>` with addresses interleaved by family.
fn interleave_addresses(addresses: &[SocketAddr], resolve: IpResolve) -> Vec<SocketAddr> {
    match resolve {
        IpResolve::V4Only => {
            // Filter to IPv4 only, preserve DNS order.
            return addresses.iter().copied().filter(|a| a.is_ipv4()).collect();
        }
        IpResolve::V6Only => {
            // Filter to IPv6 only, preserve DNS order.
            return addresses.iter().copied().filter(|a| a.is_ipv6()).collect();
        }
        IpResolve::Whatever => {
            // Interleave IPv6 and IPv4.
        }
    }

    let mut ipv6: VecDeque<SocketAddr> = VecDeque::new();
    let mut ipv4: VecDeque<SocketAddr> = VecDeque::new();

    for &addr in addresses {
        if addr.is_ipv6() {
            ipv6.push_back(addr);
        } else {
            ipv4.push_back(addr);
        }
    }

    // If only one family available, return in DNS order.
    if ipv6.is_empty() {
        return ipv4.into_iter().collect();
    }
    if ipv4.is_empty() {
        return ipv6.into_iter().collect();
    }

    // Interleave: IPv6 first (preferred), then alternate.
    let mut result = Vec::with_capacity(ipv6.len() + ipv4.len());
    loop {
        match (ipv6.pop_front(), ipv4.pop_front()) {
            (Some(v6), Some(v4)) => {
                result.push(v6);
                result.push(v4);
            }
            (Some(v6), None) => {
                result.push(v6);
                // Drain remaining IPv6.
                result.extend(ipv6.drain(..));
                break;
            }
            (None, Some(v4)) => {
                result.push(v4);
                // Drain remaining IPv4.
                result.extend(ipv4.drain(..));
                break;
            }
            (None, None) => break,
        }
    }

    result
}

// ===========================================================================
// Error Mapping and Aggregation
// ===========================================================================

/// Map an `io::Error` from a TCP connection attempt to the most appropriate
/// [`CurlError`] variant.
fn io_to_connect_error(e: &io::Error) -> CurlError {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => CurlError::CouldntConnect,
        io::ErrorKind::ConnectionReset => CurlError::CouldntConnect,
        io::ErrorKind::ConnectionAborted => CurlError::CouldntConnect,
        io::ErrorKind::TimedOut => CurlError::OperationTimedOut,
        io::ErrorKind::AddrInUse => CurlError::CouldntConnect,
        io::ErrorKind::AddrNotAvailable => CurlError::CouldntConnect,
        io::ErrorKind::PermissionDenied => CurlError::CouldntConnect,
        _ => CurlError::CouldntConnect,
    }
}

/// Map an `io::Error` from a send operation to [`CurlError`].
fn io_to_send_error(e: io::Error) -> CurlError {
    match e.kind() {
        io::ErrorKind::WouldBlock => CurlError::Again,
        io::ErrorKind::BrokenPipe => CurlError::SendError,
        io::ErrorKind::ConnectionReset => CurlError::SendError,
        io::ErrorKind::ConnectionAborted => CurlError::SendError,
        _ => CurlError::SendError,
    }
}

/// Map an `io::Error` from a recv operation to [`CurlError`].
fn io_to_recv_error(e: io::Error) -> CurlError {
    match e.kind() {
        io::ErrorKind::WouldBlock => CurlError::Again,
        io::ErrorKind::ConnectionReset => CurlError::RecvError,
        io::ErrorKind::ConnectionAborted => CurlError::RecvError,
        _ => CurlError::RecvError,
    }
}

/// Select the "best" (most informative) error from a list of per-attempt
/// errors. Connection-refused errors are preferred over timeouts because
/// they give the user more actionable information.
///
/// Error priority (highest first):
/// 1. `CouldntConnect` (connection refused — server is up but rejecting)
/// 2. `OperationTimedOut` (server unreachable or network issue)
/// 3. `Again` (transient — should not normally reach here)
/// 4. Any other variant
fn select_best_error(errors: &[(SocketAddr, CurlError)]) -> CurlError {
    if errors.is_empty() {
        return CurlError::CouldntConnect;
    }

    // Priority ranking: lower value = higher priority.
    fn priority(e: &CurlError) -> u32 {
        match e {
            CurlError::CouldntConnect => 0,
            CurlError::OperationTimedOut => 1,
            CurlError::WeirdServerReply => 2,
            CurlError::Again => 3,
            _ => 4,
        }
    }

    errors
        .iter()
        .min_by_key(|(_, e)| priority(e))
        .map(|(_, e)| *e)
        .unwrap_or(CurlError::CouldntConnect)
}

// ===========================================================================
// Socket Option Application
// ===========================================================================

/// Apply TCP socket options to a connected `TcpStream` via `socket2::SockRef`.
///
/// Called after the winning connection is established. Applies:
/// - `TCP_NODELAY` (Nagle disable, default: on)
/// - `SO_KEEPALIVE` and related parameters (idle, interval, count)
/// - `SO_SNDBUF` / `SO_RCVBUF` buffer size overrides
///
/// Individual option failures are logged but do not abort the connection.
#[cfg(unix)]
fn apply_stream_tcp_options(
    stream: &TcpStream,
    config: &SocketConfig,
) -> Result<(), CurlError> {
    let sock_ref = socket2::SockRef::from(stream);

    // TCP_NODELAY — default on, matching curl 8.x
    if let Err(e) = sock_ref.set_nodelay(config.tcp_nodelay) {
        warn!(error = %e, "Failed to set TCP_NODELAY on winning stream");
    }

    // SO_KEEPALIVE
    if config.tcp_keepalive {
        let mut keepalive = socket2::TcpKeepalive::new()
            .with_time(config.keepalive_idle)
            .with_interval(config.keepalive_interval);

        #[cfg(any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "netbsd",
        ))]
        {
            keepalive = keepalive.with_retries(config.keepalive_count);
        }

        if let Err(e) = sock_ref.set_tcp_keepalive(&keepalive) {
            warn!(error = %e, "Failed to set TCP keepalive on winning stream");
        }
    }

    // SO_SNDBUF
    if let Some(size) = config.sndbuf_size {
        if let Err(e) = sock_ref.set_send_buffer_size(size) {
            warn!(error = %e, size = size, "Failed to set SO_SNDBUF");
        }
    }

    // SO_RCVBUF
    if let Some(size) = config.rcvbuf_size {
        if let Err(e) = sock_ref.set_recv_buffer_size(size) {
            warn!(error = %e, size = size, "Failed to set SO_RCVBUF");
        }
    }

    trace!(
        nodelay = config.tcp_nodelay,
        keepalive = config.tcp_keepalive,
        "Socket options applied to winning stream"
    );

    Ok(())
}

/// Non-Unix fallback: apply basic options via Tokio's limited API.
#[cfg(not(unix))]
fn apply_stream_tcp_options(
    stream: &TcpStream,
    config: &SocketConfig,
) -> Result<(), CurlError> {
    if let Err(e) = stream.set_nodelay(config.tcp_nodelay) {
        warn!(error = %e, "Failed to set TCP_NODELAY");
    }
    Ok(())
}

// ===========================================================================
// HappyEyeballsFilter — the main exported type
// ===========================================================================

/// Happy Eyeballs v2 (RFC 8305) connection filter.
///
/// Races IPv6 and IPv4 TCP connections with a staggered start, selecting
/// the first successful connection. Implements [`ConnectionFilter`] to
/// integrate into the connection filter chain.
///
/// After connecting, all `send()`/`recv()` operations delegate directly to
/// the winning `TcpStream`.
///
/// # Construction
///
/// ```ignore
/// use std::time::Duration;
/// use curl_rs_lib::conn::happy_eyeballs::{HappyEyeballsFilter, DEFAULT_HAPPY_EYEBALLS_DELAY_MS};
///
/// let addrs = vec![/* resolved addresses */];
/// let delay = Duration::from_millis(DEFAULT_HAPPY_EYEBALLS_DELAY_MS);
/// let filter = HappyEyeballsFilter::new(addrs, delay);
/// ```
pub struct HappyEyeballsFilter {
    // -- Configuration --
    /// Original addresses as provided (pre-interleaving).
    raw_addresses: Vec<SocketAddr>,
    /// Interleaved addresses per RFC 8305 (computed from `raw_addresses`).
    addresses: Vec<SocketAddr>,
    /// Stagger delay between starting successive connection attempts.
    delay: Duration,
    /// Socket-level configuration (TCP_NODELAY, keepalive, buffers).
    socket_config: SocketConfig,
    /// IP version resolve preference.
    ip_resolve: IpResolve,

    // -- State Machine --
    /// Current algorithm state.
    state: EyeballsState,
    /// Whether the filter considers itself connected (post-winner).
    connected: bool,
    /// Whether graceful shutdown has been completed.
    is_shut_down: bool,

    // -- Winning Connection --
    /// The winning TCP stream (set after the race completes successfully).
    stream: Option<TcpStream>,
    /// Remote address of the winning connection.
    remote_addr: Option<SocketAddr>,
    /// Local address of the winning connection.
    local_addr: Option<SocketAddr>,

    // -- Timing --
    /// When the overall Happy Eyeballs algorithm started.
    started: Option<Instant>,
    /// When the winning connection was fully established.
    connect_completed: Option<Instant>,
    /// When the first byte of data was received (post-connect).
    first_byte_at: Option<Instant>,

    // -- Error Tracking --
    /// Per-attempt errors collected during the race.
    errors: Vec<(SocketAddr, CurlError)>,
}

impl HappyEyeballsFilter {
    /// Create a new Happy Eyeballs filter for the given resolved addresses.
    ///
    /// Addresses are interleaved per RFC 8305 Section 4 (IPv6-first
    /// alternation). The `delay` parameter controls the stagger timer
    /// between successive connection attempt starts.
    ///
    /// # Arguments
    ///
    /// * `addresses` — DNS-resolved addresses in their original order.
    /// * `delay` — Stagger delay between attempts. Use
    ///   `Duration::from_millis(DEFAULT_HAPPY_EYEBALLS_DELAY_MS)` for the
    ///   curl 8.x default of 200 ms.
    pub fn new(addresses: Vec<SocketAddr>, delay: Duration) -> Self {
        let interleaved = interleave_addresses(&addresses, IpResolve::Whatever);
        debug!(
            total_addrs = addresses.len(),
            interleaved_addrs = interleaved.len(),
            delay_ms = delay.as_millis() as u64,
            "HappyEyeballsFilter created"
        );
        Self {
            raw_addresses: addresses,
            addresses: interleaved,
            delay,
            socket_config: SocketConfig::default(),
            ip_resolve: IpResolve::Whatever,
            state: EyeballsState::Init,
            connected: false,
            is_shut_down: false,
            stream: None,
            remote_addr: None,
            local_addr: None,
            started: None,
            connect_completed: None,
            first_byte_at: None,
            errors: Vec::new(),
        }
    }

    /// Set the IP resolve preference, re-interleaving addresses as needed.
    ///
    /// This must be called before `connect()` starts. Calling it after
    /// the `Init` state has no effect.
    pub fn set_ip_resolve(&mut self, resolve: IpResolve) {
        if self.state == EyeballsState::Init {
            self.ip_resolve = resolve;
            self.addresses = interleave_addresses(&self.raw_addresses, resolve);
            debug!(
                resolve = ?resolve,
                interleaved_addrs = self.addresses.len(),
                "IP resolve preference updated"
            );
        }
    }

    /// Set socket-level configuration (TCP_NODELAY, keepalive, buffers).
    ///
    /// Applied to the winning stream after the race completes.
    pub fn set_socket_config(&mut self, config: SocketConfig) {
        self.socket_config = config;
    }

    // -- Private helpers --

    /// Compute the connection timeout from `TransferData`, falling back to
    /// the 5-minute default.
    fn connection_timeout(data: &TransferData) -> Duration {
        if data.timeout_ms > 0 {
            Duration::from_millis(data.timeout_ms)
        } else {
            DEFAULT_CONNECT_TIMEOUT
        }
    }

    /// Run the Happy Eyeballs race algorithm.
    ///
    /// Spawns connection attempts with staggered starts and returns when
    /// either a winner is found or all attempts have failed.
    async fn race_connections(&mut self, data: &mut TransferData) -> Result<(), CurlError> {
        let addrs = self.addresses.clone();
        if addrs.is_empty() {
            warn!("No addresses to connect to");
            return Err(CurlError::CouldntConnect);
        }

        let timeout_dur = Self::connection_timeout(data);
        let deadline = tokio::time::Instant::now() + timeout_dur;

        // Channel for receiving results from spawned attempt tasks.
        let (tx, mut rx) =
            tokio::sync::mpsc::unbounded_channel::<AttemptResult>();

        // Track spawned task handles for cancellation.
        let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::with_capacity(addrs.len());

        let mut next_idx: usize = 0;
        let mut active_count: usize = 0;
        let mut errors: Vec<(SocketAddr, CurlError)> = Vec::new();

        // Helper closure-like block: start the attempt at `next_idx`.
        // We inline this since closures capturing `&mut self` fields is
        // complex; instead we capture only what we need.
        macro_rules! start_attempt {
            ($idx:expr) => {{
                let addr = addrs[$idx];
                let idx = $idx;
                let tx_clone = tx.clone();
                let handle = tokio::spawn(async move {
                    let outcome = TcpStream::connect(addr).await;
                    // Best-effort send; if receiver dropped, we were cancelled.
                    let _ = tx_clone.send(AttemptResult {
                        addr,
                        index: idx,
                        outcome,
                    });
                });
                handles.push(handle);
                trace!(
                    addr = %addr,
                    index = $idx,
                    is_ipv6 = addr.is_ipv6(),
                    "Started connection attempt"
                );
            }};
        }

        // Start first attempt immediately.
        start_attempt!(next_idx);
        next_idx += 1;
        active_count += 1;
        let mut last_start = tokio::time::Instant::now();

        info!(
            addr = %addrs[0],
            total_addresses = addrs.len(),
            "Happy Eyeballs: first attempt started"
        );

        // Note: we keep `tx` alive so the macro can clone it for
        // subsequent attempts. We rely on `active_count` tracking
        // (not channel closure) to know when the race is over.

        loop {
            let has_more = next_idx < addrs.len();

            // Compute time remaining until the next stagger interval.
            let stagger_remaining = if has_more {
                let elapsed = tokio::time::Instant::now().duration_since(last_start);
                if elapsed >= self.delay {
                    Duration::ZERO
                } else {
                    self.delay - elapsed
                }
            } else {
                // No more addresses to start — use a very large duration so
                // this branch of select! is effectively disabled.
                Duration::from_secs(86400)
            };

            // If stagger already expired and we have more addresses, start
            // the next one immediately (before entering select!).
            if has_more && stagger_remaining.is_zero() {
                start_attempt!(next_idx);
                next_idx += 1;
                active_count += 1;
                last_start = tokio::time::Instant::now();
                continue;
            }

            // If nothing is running and nothing more to start, we are done.
            if active_count == 0 && !has_more {
                break;
            }

            // Race: (a) next result from any attempt, (b) stagger timer,
            //        (c) overall deadline.
            let time_to_deadline = deadline
                .saturating_duration_since(tokio::time::Instant::now());

            tokio::select! {
                biased;

                // (a) A connection attempt completed (success or failure).
                msg = rx.recv() => {
                    match msg {
                        Some(AttemptResult { addr, index, outcome: Ok(stream) }) => {
                            // Winner! Cancel all other in-flight attempts.
                            debug!(
                                addr = %addr,
                                index = index,
                                is_ipv6 = addr.is_ipv6(),
                                elapsed_ms = self.started
                                    .map(|s| s.elapsed().as_millis() as u64)
                                    .unwrap_or(0),
                                "Happy Eyeballs: winner found"
                            );
                            for h in &handles {
                                h.abort();
                            }

                            // Apply socket options to the winning stream.
                            apply_stream_tcp_options(&stream, &self.socket_config)?;

                            self.stream = Some(stream);
                            self.remote_addr = Some(addr);
                            self.local_addr = self.stream
                                .as_ref()
                                .and_then(|s| s.local_addr().ok());
                            self.connect_completed = Some(Instant::now());
                            self.errors = errors;
                            return Ok(());
                        }
                        Some(AttemptResult { addr, index, outcome: Err(e) }) => {
                            let curl_err = io_to_connect_error(&e);
                            warn!(
                                addr = %addr,
                                index = index,
                                error = %e,
                                "Connection attempt failed"
                            );
                            errors.push((addr, curl_err));
                            active_count = active_count.saturating_sub(1);

                            // If no running attempts remain and there are
                            // more addresses, start the next one immediately
                            // (bypassing the stagger timer). This matches the
                            // C behaviour where `!ongoing` triggers
                            // `do_more = TRUE`.
                            if active_count == 0 && next_idx < addrs.len() {
                                start_attempt!(next_idx);
                                next_idx += 1;
                                active_count += 1;
                                last_start = tokio::time::Instant::now();
                            }
                        }
                        None => {
                            // Channel closed — all senders dropped.
                            break;
                        }
                    }
                }

                // (b) Stagger timer expired — start next address.
                _ = tokio::time::sleep(stagger_remaining), if has_more => {
                    debug!(
                        next_addr = %addrs[next_idx],
                        next_index = next_idx,
                        "Happy Eyeballs: stagger timer expired, starting next attempt"
                    );
                    start_attempt!(next_idx);
                    next_idx += 1;
                    active_count += 1;
                    last_start = tokio::time::Instant::now();
                }

                // (c) Overall connection timeout.
                _ = tokio::time::sleep(time_to_deadline) => {
                    warn!(
                        elapsed_ms = self.started
                            .map(|s| s.elapsed().as_millis() as u64)
                            .unwrap_or(0),
                        "Happy Eyeballs: overall connection timeout"
                    );
                    for h in &handles {
                        h.abort();
                    }
                    self.errors = errors;
                    return Err(CurlError::OperationTimedOut);
                }
            }
        }

        // All attempts exhausted without a winner.
        self.errors = errors;
        Err(select_best_error(&self.errors))
    }

    /// Close all in-flight attempts and release resources.
    fn close_all(&mut self) {
        // The spawned tokio tasks are fire-and-forget; they will be
        // cancelled if their JoinHandles were aborted. The winning
        // stream (if any) is dropped here.
        if let Some(stream) = self.stream.take() {
            drop(stream);
        }
        self.remote_addr = None;
        self.local_addr = None;
        self.connected = false;
    }

    /// Return the aggregated error from all failed attempts.
    fn aggregate_error(&self) -> CurlError {
        select_best_error(&self.errors)
    }
}

// ===========================================================================
// ConnectionFilter Implementation
// ===========================================================================

#[async_trait]
impl ConnectionFilter for HappyEyeballsFilter {
    // -- Identity --

    fn name(&self) -> &str {
        "HAPPY-EYEBALLS"
    }

    fn type_flags(&self) -> u32 {
        CF_TYPE_IP_CONNECT
    }

    fn log_level(&self) -> i32 {
        0
    }

    // -- Connection Lifecycle --

    async fn connect(&mut self, data: &mut TransferData) -> Result<bool, CurlError> {
        // Already connected — short-circuit.
        if self.connected {
            return Ok(true);
        }

        match self.state {
            EyeballsState::Init => {
                // Validate that we have addresses to try.
                if self.addresses.is_empty() {
                    warn!("Happy Eyeballs: no addresses provided");
                    self.state = EyeballsState::Failed;
                    return Err(CurlError::FailedInit);
                }

                // Record overall start time.
                self.started = Some(Instant::now());
                self.state = EyeballsState::Connecting;

                debug!(
                    num_addresses = self.addresses.len(),
                    delay_ms = self.delay.as_millis() as u64,
                    "Happy Eyeballs: starting connection race"
                );

                // Run the race algorithm. This is an async operation that
                // will complete when a winner is found or all fail.
                match self.race_connections(data).await {
                    Ok(()) => {
                        self.state = EyeballsState::Connected;
                        self.connected = true;
                        info!(
                            addr = ?self.remote_addr,
                            elapsed_ms = self.started
                                .map(|s| s.elapsed().as_millis() as u64)
                                .unwrap_or(0),
                            "Happy Eyeballs: connected"
                        );
                        Ok(true)
                    }
                    Err(e) => {
                        self.state = EyeballsState::Failed;
                        warn!(
                            error = %e,
                            num_errors = self.errors.len(),
                            "Happy Eyeballs: all attempts failed"
                        );
                        Err(e)
                    }
                }
            }

            EyeballsState::Connecting => {
                // This state should not be reached because `race_connections`
                // runs to completion in a single `connect()` call. However,
                // for defensive programming, return `Again` to indicate the
                // caller should retry.
                Err(CurlError::Again)
            }

            EyeballsState::Connected => {
                self.connected = true;
                Ok(true)
            }

            EyeballsState::Failed => {
                Err(self.aggregate_error())
            }
        }
    }

    fn close(&mut self) {
        trace!("Happy Eyeballs: close");
        self.close_all();
        self.state = EyeballsState::Init;
        self.is_shut_down = false;
        self.errors.clear();
    }

    async fn shutdown(&mut self) -> Result<bool, CurlError> {
        if self.is_shut_down {
            return Ok(true);
        }

        if let Some(ref mut stream) = self.stream {
            // Graceful TCP shutdown (FIN). We try the shutdown; if it
            // fails we log and continue — the stream will be dropped
            // (and RST sent) when the filter is closed/dropped.
            match stream.shutdown().await {
                Ok(()) => {
                    trace!("Happy Eyeballs: TCP shutdown complete");
                }
                Err(e) => {
                    trace!(error = %e, "Happy Eyeballs: TCP shutdown error (non-fatal)");
                }
            }
        }

        self.is_shut_down = true;
        Ok(true)
    }

    // -- Data Transfer --

    async fn send(&mut self, buf: &[u8], _eos: bool) -> Result<usize, CurlError> {
        let stream = self.stream.as_mut().ok_or(CurlError::SendError)?;

        match stream.write(buf).await {
            Ok(n) => {
                trace!(bytes = n, "Happy Eyeballs: send");
                Ok(n)
            }
            Err(e) => {
                trace!(error = %e, "Happy Eyeballs: send error");
                Err(io_to_send_error(e))
            }
        }
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, CurlError> {
        let stream = self.stream.as_mut().ok_or(CurlError::RecvError)?;

        match stream.read(buf).await {
            Ok(0) => {
                trace!("Happy Eyeballs: recv EOF");
                Ok(0)
            }
            Ok(n) => {
                if self.first_byte_at.is_none() {
                    self.first_byte_at = Some(Instant::now());
                }
                trace!(bytes = n, "Happy Eyeballs: recv");
                Ok(n)
            }
            Err(e) => {
                trace!(error = %e, "Happy Eyeballs: recv error");
                Err(io_to_recv_error(e))
            }
        }
    }

    // -- Polling and State --

    fn adjust_pollset(
        &self,
        _data: &TransferData,
        ps: &mut PollSet,
    ) -> Result<(), CurlError> {
        // After connected, add the winning socket to the poll set.
        #[cfg(unix)]
        if let Some(ref stream) = self.stream {
            if self.connected {
                let fd = stream.as_raw_fd();
                ps.add(fd, PollAction::POLL_IN);
            }
        }
        Ok(())
    }

    fn data_pending(&self) -> bool {
        // The raw TCP stream does not buffer data internally, so there
        // is never application-level data pending at this layer.
        false
    }

    fn control(&mut self, _event: i32, _arg1: i32) -> Result<(), CurlError> {
        // The Happy Eyeballs filter does not need to handle control
        // events — it passes through all events unchanged. This matches
        // the C `Curl_cf_def_cntrl` behaviour.
        Ok(())
    }

    fn is_alive(&self) -> bool {
        match self.stream {
            Some(ref stream) => {
                // Best-effort liveness check: verify peer address is
                // accessible and try a zero-length read.
                if stream.peer_addr().is_err() {
                    return false;
                }
                let mut buf = [0u8; 1];
                match stream.try_read(&mut buf) {
                    Ok(0) => false,       // EOF — peer closed
                    Ok(_) => true,        // Data available — alive
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => true,
                    Err(_) => false,
                }
            }
            None => false,
        }
    }

    fn keep_alive(&mut self) -> Result<(), CurlError> {
        // TCP keepalive probes are handled at the socket level via
        // SO_KEEPALIVE options applied during connection. No explicit
        // action needed here.
        Ok(())
    }

    fn query(&self, query: i32) -> QueryResult {
        match query {
            q if q == CF_QUERY_CONNECT_REPLY_MS => {
                // Return the time from attempt start to connection
                // completion, or -1 if not yet connected.
                match (self.started, self.connect_completed) {
                    (Some(start), Some(end)) => {
                        let elapsed = end.duration_since(start).as_millis() as i64;
                        QueryResult::Int(elapsed as i32)
                    }
                    _ => QueryResult::Int(-1),
                }
            }
            q if q == CF_QUERY_TIMER_CONNECT => {
                // Timestamp when TCP connection was established.
                match self.connect_completed {
                    Some(t) => QueryResult::Time(t),
                    None => QueryResult::NotHandled,
                }
            }
            q if q == CF_QUERY_TIMER_APPCONNECT => {
                // For plain TCP, app-connect time equals connect time
                // (no TLS handshake at this layer). The TLS filter above
                // will override this with the actual TLS completion time.
                match self.connect_completed {
                    Some(t) => QueryResult::Time(t),
                    None => QueryResult::NotHandled,
                }
            }
            _ => QueryResult::NotHandled,
        }
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn is_shutdown(&self) -> bool {
        self.is_shut_down
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    /// Create a sample IPv4 address.
    fn v4(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port))
    }

    /// Create a sample IPv6 address.
    fn v6(port: u16) -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
            port,
            0,
            0,
        ))
    }

    #[test]
    fn test_interleave_both_families() {
        let addrs = vec![v6(80), v6(81), v4(80), v4(81)];
        let result = interleave_addresses(&addrs, IpResolve::Whatever);
        // Expected: v6(80), v4(80), v6(81), v4(81)
        assert_eq!(result.len(), 4);
        assert!(result[0].is_ipv6());
        assert!(result[1].is_ipv4());
        assert!(result[2].is_ipv6());
        assert!(result[3].is_ipv4());
    }

    #[test]
    fn test_interleave_ipv6_only_addresses() {
        let addrs = vec![v6(80), v6(81), v6(82)];
        let result = interleave_addresses(&addrs, IpResolve::Whatever);
        assert_eq!(result.len(), 3);
        for addr in &result {
            assert!(addr.is_ipv6());
        }
    }

    #[test]
    fn test_interleave_ipv4_only_addresses() {
        let addrs = vec![v4(80), v4(81)];
        let result = interleave_addresses(&addrs, IpResolve::Whatever);
        assert_eq!(result.len(), 2);
        for addr in &result {
            assert!(addr.is_ipv4());
        }
    }

    #[test]
    fn test_interleave_empty() {
        let addrs: Vec<SocketAddr> = vec![];
        let result = interleave_addresses(&addrs, IpResolve::Whatever);
        assert!(result.is_empty());
    }

    #[test]
    fn test_interleave_unequal_families() {
        let addrs = vec![v6(80), v6(81), v6(82), v4(80)];
        let result = interleave_addresses(&addrs, IpResolve::Whatever);
        // Expected: v6(80), v4(80), v6(81), v6(82)
        assert_eq!(result.len(), 4);
        assert!(result[0].is_ipv6());
        assert!(result[1].is_ipv4());
        assert!(result[2].is_ipv6());
        assert!(result[3].is_ipv6());
    }

    #[test]
    fn test_interleave_v4_only_resolve() {
        let addrs = vec![v6(80), v4(80), v4(81)];
        let result = interleave_addresses(&addrs, IpResolve::V4Only);
        assert_eq!(result.len(), 2);
        assert!(result[0].is_ipv4());
        assert!(result[1].is_ipv4());
    }

    #[test]
    fn test_interleave_v6_only_resolve() {
        let addrs = vec![v6(80), v6(81), v4(80)];
        let result = interleave_addresses(&addrs, IpResolve::V6Only);
        assert_eq!(result.len(), 2);
        assert!(result[0].is_ipv6());
        assert!(result[1].is_ipv6());
    }

    #[test]
    fn test_default_delay_constant() {
        assert_eq!(DEFAULT_HAPPY_EYEBALLS_DELAY_MS, 200);
    }

    #[test]
    fn test_select_best_error_empty() {
        assert_eq!(select_best_error(&[]), CurlError::CouldntConnect);
    }

    #[test]
    fn test_select_best_error_prefers_connect_over_timeout() {
        let errors = vec![
            (v4(80), CurlError::OperationTimedOut),
            (v6(80), CurlError::CouldntConnect),
        ];
        assert_eq!(select_best_error(&errors), CurlError::CouldntConnect);
    }

    #[test]
    fn test_select_best_error_timeout_only() {
        let errors = vec![
            (v4(80), CurlError::OperationTimedOut),
            (v6(80), CurlError::OperationTimedOut),
        ];
        assert_eq!(select_best_error(&errors), CurlError::OperationTimedOut);
    }

    #[test]
    fn test_new_creates_filter_in_init_state() {
        let addrs = vec![v4(80), v6(80)];
        let filter = HappyEyeballsFilter::new(
            addrs,
            Duration::from_millis(DEFAULT_HAPPY_EYEBALLS_DELAY_MS),
        );
        assert_eq!(filter.state, EyeballsState::Init);
        assert!(!filter.connected);
        assert!(!filter.is_shut_down);
        assert!(filter.stream.is_none());
        assert!(filter.errors.is_empty());
    }

    #[test]
    fn test_new_interleaves_addresses() {
        let addrs = vec![v6(80), v6(81), v4(80), v4(81)];
        let filter = HappyEyeballsFilter::new(
            addrs,
            Duration::from_millis(DEFAULT_HAPPY_EYEBALLS_DELAY_MS),
        );
        // Should be interleaved: v6, v4, v6, v4
        assert_eq!(filter.addresses.len(), 4);
        assert!(filter.addresses[0].is_ipv6());
        assert!(filter.addresses[1].is_ipv4());
    }

    #[test]
    fn test_filter_name() {
        let filter = HappyEyeballsFilter::new(
            vec![v4(80)],
            Duration::from_millis(DEFAULT_HAPPY_EYEBALLS_DELAY_MS),
        );
        assert_eq!(filter.name(), "HAPPY-EYEBALLS");
    }

    #[test]
    fn test_filter_type_flags() {
        let filter = HappyEyeballsFilter::new(
            vec![v4(80)],
            Duration::from_millis(DEFAULT_HAPPY_EYEBALLS_DELAY_MS),
        );
        assert_eq!(filter.type_flags(), CF_TYPE_IP_CONNECT);
    }

    #[test]
    fn test_filter_initial_state() {
        let filter = HappyEyeballsFilter::new(
            vec![v4(80)],
            Duration::from_millis(DEFAULT_HAPPY_EYEBALLS_DELAY_MS),
        );
        assert!(!filter.is_connected());
        assert!(!filter.is_shutdown());
        assert!(!filter.data_pending());
        assert!(!filter.is_alive());
    }

    #[test]
    fn test_set_ip_resolve() {
        let addrs = vec![v6(80), v4(80), v6(81)];
        let mut filter = HappyEyeballsFilter::new(
            addrs,
            Duration::from_millis(DEFAULT_HAPPY_EYEBALLS_DELAY_MS),
        );
        filter.set_ip_resolve(IpResolve::V4Only);
        assert_eq!(filter.addresses.len(), 1);
        assert!(filter.addresses[0].is_ipv4());
    }

    #[test]
    fn test_query_not_connected() {
        let filter = HappyEyeballsFilter::new(
            vec![v4(80)],
            Duration::from_millis(DEFAULT_HAPPY_EYEBALLS_DELAY_MS),
        );
        assert!(matches!(
            filter.query(CF_QUERY_CONNECT_REPLY_MS),
            QueryResult::Int(-1)
        ));
        assert!(matches!(
            filter.query(CF_QUERY_TIMER_CONNECT),
            QueryResult::NotHandled
        ));
    }

    #[test]
    fn test_ip_resolve_default() {
        assert_eq!(IpResolve::default(), IpResolve::Whatever);
    }

    #[test]
    fn test_error_mapping() {
        let refused = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        assert_eq!(io_to_connect_error(&refused), CurlError::CouldntConnect);

        let timeout = io::Error::new(io::ErrorKind::TimedOut, "timeout");
        assert_eq!(io_to_connect_error(&timeout), CurlError::OperationTimedOut);
    }

    #[tokio::test]
    async fn test_connect_empty_addresses() {
        let mut filter = HappyEyeballsFilter::new(
            vec![],
            Duration::from_millis(DEFAULT_HAPPY_EYEBALLS_DELAY_MS),
        );
        let mut data = TransferData::default();
        let result = filter.connect(&mut data).await;
        assert!(result.is_err());
    }
}
