//! Socket-level connection filter — TCP and UDP transport.
//!
//! Rust rewrite of `lib/cf-socket.c` (2,233 lines) — implements the
//! lowest-level connection filters for TCP and UDP sockets. These filters
//! sit at the bottom of every connection filter chain, responsible for
//! actual network I/O via Tokio's async networking primitives.
//!
//! # Exported Types
//!
//! * [`TcpSocketFilter`] — TCP socket filter implementing [`ConnectionFilter`].
//! * [`UdpSocketFilter`] — UDP socket filter for QUIC/HTTP3.
//! * [`SocketConfig`] — Socket configuration (nodelay, keepalive, buffers).
//! * [`SocketType`] — Enum of socket transport types.
//!
//! # Exported Functions
//!
//! * [`apply_tcp_options`] — Apply socket options via `socket2::Socket`.
//! * [`check_alive`] — Best-effort connection liveness check.
//! * [`parse_interface`] — Parse `CURLOPT_INTERFACE` input string.
//!
//! # Design Notes
//!
//! The C implementation manipulates raw sockets with manual non-blocking I/O
//! via `select()`/`poll()`. This Rust version replaces that with:
//! - `tokio::net::TcpStream` / `tokio::net::UdpSocket` for async I/O
//! - `socket2` crate for low-level socket option configuration
//! - `tokio::time::timeout` for connection timeout enforcement
//!
//! All socket options (TCP_NODELAY, SO_KEEPALIVE, SO_SNDBUF, SO_RCVBUF,
//! SO_BINDTODEVICE) are applied via the `socket2` crate's cross-platform
//! API, eliminating all `#ifdef` platform branching from the C original.
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

use async_trait::async_trait;
use socket2::{Domain, Protocol, SockAddr, Socket, TcpKeepalive, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{debug, trace, warn};

use crate::conn::filters::{
    ConnectionFilter, PollAction, PollSet, QueryResult, TransferData,
    CF_CTRL_CONN_INFO_UPDATE, CF_CTRL_DATA_SETUP, CF_CTRL_FORGET_SOCKET, CF_QUERY_CONNECT_REPLY_MS,
    CF_QUERY_IP_INFO, CF_QUERY_REMOTE_ADDR, CF_QUERY_SOCKET, CF_QUERY_TIMER_CONNECT,
    CF_QUERY_TRANSPORT, CF_TYPE_IP_CONNECT,
};
use crate::error::CurlError;
use crate::util::nonblock::make_tokio_socket;

// ===========================================================================
// Transport type constants (matching C TRNSPRT_* values)
// ===========================================================================

/// TCP transport identifier (matches C `TRNSPRT_TCP = 0`).
const TRANSPORT_TCP: i32 = 0;

/// UDP transport identifier (matches C `TRNSPRT_UDP = 1`).
const TRANSPORT_UDP: i32 = 1;

/// QUIC transport identifier (matches C `TRNSPRT_QUIC = 5`).
const TRANSPORT_QUIC: i32 = 5;

/// Unix domain socket transport (matches C `TRNSPRT_UNIX = 3`).
const TRANSPORT_UNIX: i32 = 3;

/// Default connection timeout when none specified (5 minutes).
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(300);

// ===========================================================================
// SocketType — transport type enum
// ===========================================================================

/// The type of underlying socket transport.
///
/// Maps to the C `TRNSPRT_TCP`, `TRNSPRT_UDP`, `TRNSPRT_UNIX` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketType {
    /// TCP stream socket (SOCK_STREAM, IPPROTO_TCP).
    Tcp,
    /// UDP datagram socket (SOCK_DGRAM, IPPROTO_UDP) — used for QUIC.
    Udp,
    /// Unix domain stream socket (SOCK_STREAM, AF_UNIX).
    Unix,
}

impl SocketType {
    /// Returns the integer transport identifier matching the C constants.
    pub fn transport_id(self) -> i32 {
        match self {
            Self::Tcp => TRANSPORT_TCP,
            Self::Udp => TRANSPORT_UDP,
            Self::Unix => TRANSPORT_UNIX,
        }
    }
}

// ===========================================================================
// SocketConfig — socket option configuration
// ===========================================================================

/// Configuration for socket-level options applied before or after connection.
///
/// Mirrors the socket-related fields from the C `struct UserDefined` (the
/// `data->set.*` fields consulted in `cf-socket.c`). Each field maps to a
/// specific `setsockopt()` call or socket creation parameter.
#[derive(Debug, Clone)]
pub struct SocketConfig {
    /// Enable TCP_NODELAY (Nagle algorithm disable).
    ///
    /// Default: `true` — matches curl 8.x default where TCP_NODELAY is ON.
    pub tcp_nodelay: bool,

    /// Enable SO_KEEPALIVE on TCP sockets.
    ///
    /// Default: `false` — keepalive is off unless explicitly enabled via
    /// `CURLOPT_TCP_KEEPALIVE`.
    pub tcp_keepalive: bool,

    /// Keepalive idle time before first probe (TCP_KEEPIDLE on Linux,
    /// TCP_KEEPALIVE on macOS).
    ///
    /// Default: 60 seconds — matches curl 8.x `CURLOPT_TCP_KEEPIDLE`.
    pub keepalive_idle: Duration,

    /// Interval between keepalive probes (TCP_KEEPINTVL).
    ///
    /// Default: 60 seconds — matches curl 8.x `CURLOPT_TCP_KEEPINTVL`.
    pub keepalive_interval: Duration,

    /// Number of keepalive probes before declaring dead (TCP_KEEPCNT).
    ///
    /// Default: 9 — matches Linux default. Not settable on macOS.
    pub keepalive_count: u32,

    /// Override for SO_SNDBUF (send buffer size). `None` uses OS default.
    pub sndbuf_size: Option<usize>,

    /// Override for SO_RCVBUF (receive buffer size). `None` uses OS default.
    pub rcvbuf_size: Option<usize>,

    /// Interface name for SO_BINDTODEVICE (Linux-specific).
    ///
    /// Parsed from `CURLOPT_INTERFACE` via [`parse_interface`].
    pub bind_interface: Option<String>,

    /// Local address and/or port to bind before connect.
    ///
    /// Set via `CURLOPT_LOCALPORT` / `CURLOPT_LOCALPORTRANGE`.
    pub local_addr: Option<SocketAddr>,

    /// Enable TCP Fast Open (TFO).
    ///
    /// Default: `false` — TFO requires both client and server support.
    pub tcp_fastopen: bool,
}

impl Default for SocketConfig {
    /// Returns the default socket configuration matching curl 8.x defaults.
    fn default() -> Self {
        Self {
            tcp_nodelay: true,
            tcp_keepalive: false,
            keepalive_idle: Duration::from_secs(60),
            keepalive_interval: Duration::from_secs(60),
            keepalive_count: 9,
            sndbuf_size: None,
            rcvbuf_size: None,
            bind_interface: None,
            local_addr: None,
            tcp_fastopen: false,
        }
    }
}

// ===========================================================================
// Error mapping helpers
// ===========================================================================

/// Map an `io::Error` from a connection attempt to the appropriate
/// [`CurlError`] variant.
fn io_to_connect_error(e: io::Error) -> CurlError {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => CurlError::CouldntConnect,
        io::ErrorKind::ConnectionReset => CurlError::CouldntConnect,
        io::ErrorKind::ConnectionAborted => CurlError::CouldntConnect,
        io::ErrorKind::TimedOut => CurlError::OperationTimedOut,
        io::ErrorKind::AddrInUse => CurlError::InterfaceFailed,
        io::ErrorKind::AddrNotAvailable => CurlError::InterfaceFailed,
        io::ErrorKind::PermissionDenied => CurlError::InterfaceFailed,
        _ => CurlError::CouldntConnect,
    }
}

/// Map an `io::Error` from a send operation to the appropriate [`CurlError`].
fn io_to_send_error(e: io::Error) -> CurlError {
    match e.kind() {
        io::ErrorKind::WouldBlock => CurlError::Again,
        io::ErrorKind::BrokenPipe => CurlError::SendError,
        io::ErrorKind::ConnectionReset => CurlError::SendError,
        io::ErrorKind::ConnectionAborted => CurlError::SendError,
        _ => CurlError::SendError,
    }
}

/// Map an `io::Error` from a recv operation to the appropriate [`CurlError`].
fn io_to_recv_error(e: io::Error) -> CurlError {
    match e.kind() {
        io::ErrorKind::WouldBlock => CurlError::Again,
        io::ErrorKind::ConnectionReset => CurlError::RecvError,
        io::ErrorKind::ConnectionAborted => CurlError::RecvError,
        _ => CurlError::RecvError,
    }
}

/// Map an `io::Error` from a socket option operation to [`CurlError`].
fn io_to_option_error(e: io::Error) -> CurlError {
    warn!(error = %e, "Socket option error");
    CurlError::CouldntConnect
}

/// Compute connection timeout from transfer data, falling back to the
/// default 5-minute timeout.
fn connection_timeout(data: &TransferData) -> Duration {
    if data.timeout_ms > 0 {
        Duration::from_millis(data.timeout_ms)
    } else {
        DEFAULT_CONNECT_TIMEOUT
    }
}

// ===========================================================================
// apply_tcp_options — public socket option application
// ===========================================================================

/// Apply TCP socket options to a `socket2::Socket` before connection.
///
/// This function sets the following options based on the provided
/// [`SocketConfig`]:
///
/// - `TCP_NODELAY` — disables Nagle algorithm (default: on)
/// - `SO_KEEPALIVE` + keepalive parameters (idle, interval, count)
/// - `SO_SNDBUF` / `SO_RCVBUF` — send/receive buffer sizes
/// - `SO_REUSEADDR` — always enabled for address reuse
///
/// Platform-specific keepalive parameters:
/// - **Linux**: `TCP_KEEPIDLE`, `TCP_KEEPINTVL`, `TCP_KEEPCNT`
/// - **macOS**: `TCP_KEEPALIVE` (idle only), `TCP_KEEPINTVL`
/// - **Windows**: `SIO_KEEPALIVE_VALS` or `TCP_KEEPIDLE`/`TCP_KEEPINTVL`
///
/// # Errors
///
/// Returns [`CurlError::CouldntConnect`] if any socket option fails to apply.
/// Individual option failures are logged at warn level but do not stop
/// application of subsequent options.
pub fn apply_tcp_options(socket: &Socket, config: &SocketConfig) -> Result<(), CurlError> {
    // SO_REUSEADDR — always enable for faster rebind after close
    if let Err(e) = socket.set_reuse_address(true) {
        trace!(error = %e, "Failed to set SO_REUSEADDR (non-fatal)");
    }

    // TCP_NODELAY (default: true, matching curl 8.x)
    socket.set_nodelay(config.tcp_nodelay).map_err(|e| {
        warn!(error = %e, "Failed to set TCP_NODELAY");
        io_to_option_error(e)
    })?;

    // SO_KEEPALIVE and related parameters
    if config.tcp_keepalive {
        let mut keepalive = TcpKeepalive::new()
            .with_time(config.keepalive_idle)
            .with_interval(config.keepalive_interval);

        // TCP_KEEPCNT is not available on macOS/iOS via socket2.
        // It IS available on Linux, FreeBSD, Windows, etc.
        #[cfg(any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "netbsd",
            target_os = "windows",
        ))]
        {
            keepalive = keepalive.with_retries(config.keepalive_count);
        }

        socket.set_tcp_keepalive(&keepalive).map_err(|e| {
            warn!(error = %e, "Failed to set TCP keepalive parameters");
            io_to_option_error(e)
        })?;

        trace!(
            idle_secs = config.keepalive_idle.as_secs(),
            interval_secs = config.keepalive_interval.as_secs(),
            count = config.keepalive_count,
            "TCP keepalive configured"
        );
    }

    // SO_SNDBUF
    if let Some(size) = config.sndbuf_size {
        if let Err(e) = socket.set_send_buffer_size(size) {
            warn!(error = %e, size = size, "Failed to set SO_SNDBUF");
        }
    }

    // SO_RCVBUF
    if let Some(size) = config.rcvbuf_size {
        if let Err(e) = socket.set_recv_buffer_size(size) {
            warn!(error = %e, size = size, "Failed to set SO_RCVBUF");
        }
    }

    trace!(
        nodelay = config.tcp_nodelay,
        keepalive = config.tcp_keepalive,
        "TCP socket options applied"
    );

    Ok(())
}

// ===========================================================================
// Post-connect option application (via SockRef on connected stream)
// ===========================================================================

/// Apply TCP socket options to an already-connected `TcpStream` via
/// `socket2::SockRef`. Used when the connection was established directly
/// through `tokio::net::TcpStream::connect()` without a pre-configured
/// `socket2::Socket`.
#[cfg(unix)]
fn apply_stream_options(stream: &TcpStream, config: &SocketConfig) -> Result<(), CurlError> {
    let sock_ref = socket2::SockRef::from(stream);

    // TCP_NODELAY
    sock_ref.set_nodelay(config.tcp_nodelay).map_err(|e| {
        warn!(error = %e, "Failed to set TCP_NODELAY on connected stream");
        io_to_option_error(e)
    })?;

    // SO_KEEPALIVE and parameters
    if config.tcp_keepalive {
        let mut keepalive = TcpKeepalive::new()
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
            warn!(error = %e, "Failed to set TCP keepalive on connected stream");
        }
    }

    // SO_SNDBUF
    if let Some(size) = config.sndbuf_size {
        if let Err(e) = sock_ref.set_send_buffer_size(size) {
            warn!(error = %e, size = size, "Failed to set SO_SNDBUF on connected stream");
        }
    }

    // SO_RCVBUF
    if let Some(size) = config.rcvbuf_size {
        if let Err(e) = sock_ref.set_recv_buffer_size(size) {
            warn!(error = %e, size = size, "Failed to set SO_RCVBUF on connected stream");
        }
    }

    trace!(nodelay = config.tcp_nodelay, keepalive = config.tcp_keepalive, "Stream options applied");
    Ok(())
}

/// Non-Unix fallback: apply options via Tokio's limited API.
#[cfg(not(unix))]
fn apply_stream_options(stream: &TcpStream, config: &SocketConfig) -> Result<(), CurlError> {
    stream.set_nodelay(config.tcp_nodelay).map_err(|e| {
        warn!(error = %e, "Failed to set TCP_NODELAY");
        io_to_option_error(e)
    })?;
    Ok(())
}

/// Apply options to a connected `UdpSocket` via `socket2::SockRef`.
#[cfg(unix)]
fn apply_udp_stream_options(socket: &UdpSocket, config: &SocketConfig) -> Result<(), CurlError> {
    let sock_ref = socket2::SockRef::from(socket);

    if let Some(size) = config.sndbuf_size {
        if let Err(e) = sock_ref.set_send_buffer_size(size) {
            warn!(error = %e, size = size, "Failed to set SO_SNDBUF on UDP socket");
        }
    }
    if let Some(size) = config.rcvbuf_size {
        if let Err(e) = sock_ref.set_recv_buffer_size(size) {
            warn!(error = %e, size = size, "Failed to set SO_RCVBUF on UDP socket");
        }
    }

    trace!("UDP socket options applied");
    Ok(())
}

/// Non-Unix fallback for UDP option application.
#[cfg(not(unix))]
fn apply_udp_stream_options(_socket: &UdpSocket, _config: &SocketConfig) -> Result<(), CurlError> {
    Ok(())
}

// ===========================================================================
// check_alive - connection liveness check
// ===========================================================================

/// Best-effort check whether a TCP connection is still alive.
///
/// In the C implementation (`cf_socket_conn_is_alive` in `cf-socket.c`),
/// this uses `poll()` with a zero timeout to detect closed/reset connections.
/// The Rust equivalent uses `try_read` with a 1-byte buffer to detect EOF
/// and errors, returning `WouldBlock` for idle-but-alive sockets.
///
/// Returns `true` if the connection appears alive, `false` if dead.
pub fn check_alive(stream: &TcpStream) -> bool {
    // Verify peer address is still accessible
    if stream.peer_addr().is_err() {
        return false;
    }

    let mut buf = [0u8; 1];
    match stream.try_read(&mut buf) {
        // EOF - peer closed the connection
        Ok(0) => false,
        // Data available - connection is alive
        Ok(_) => true,
        // No data ready - socket is idle but alive
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => true,
        // Any other error - assume dead
        Err(_) => false,
    }
}

// ===========================================================================
// parse_interface - CURLOPT_INTERFACE parser
// ===========================================================================

/// Parse a `CURLOPT_INTERFACE` input string into its component parts.
///
/// Formats (matching C `Curl_parse_interface()` in `cf-socket.c`):
///
/// | Format | Meaning |
/// |--------|---------|
/// | `"if!<iface>"` | Interface name only |
/// | `"host!<host>"` | Hostname/IP only |
/// | `"ifhost!<iface>!<host>"` | Interface name and hostname |
/// | `"<iface_or_host>"` | Ambiguous - treated as device name |
///
/// Returns a tuple `(dev, iface, host)` where each component is
/// `Some(String)` if present.
///
/// # Errors
///
/// Returns [`CurlError::BadFunctionArgument`] on empty input, input
/// exceeding 512 bytes, or malformed `"ifhost!"` format.
#[allow(clippy::type_complexity)]
pub fn parse_interface(
    input: &str,
) -> Result<(Option<String>, Option<String>, Option<String>), CurlError> {
    if input.is_empty() {
        return Err(CurlError::BadFunctionArgument);
    }
    if input.len() > 512 {
        return Err(CurlError::BadFunctionArgument);
    }

    // "if!<iface>" - interface name only
    if let Some(rest) = input.strip_prefix("if!") {
        if rest.is_empty() {
            return Err(CurlError::BadFunctionArgument);
        }
        return Ok((None, Some(rest.to_string()), None));
    }

    // "host!<host>" - hostname only
    if let Some(rest) = input.strip_prefix("host!") {
        if rest.is_empty() {
            return Err(CurlError::BadFunctionArgument);
        }
        return Ok((None, None, Some(rest.to_string())));
    }

    // "ifhost!<iface>!<host>" - both interface and hostname
    if let Some(rest) = input.strip_prefix("ifhost!") {
        if let Some(separator_pos) = rest.find('!') {
            let iface_part = &rest[..separator_pos];
            let host_part = &rest[separator_pos + 1..];
            if iface_part.is_empty() || host_part.is_empty() {
                return Err(CurlError::BadFunctionArgument);
            }
            return Ok((
                None,
                Some(iface_part.to_string()),
                Some(host_part.to_string()),
            ));
        }
        // "ifhost!" without a second "!" separator
        return Err(CurlError::BadFunctionArgument);
    }

    // Plain "<iface_or_host>" - treated as a device name
    Ok((Some(input.to_string()), None, None))
}

// ===========================================================================
// Socket forget helpers (for CF_CTRL_FORGET_SOCKET)
// ===========================================================================

/// Forget a TCP stream without closing the underlying socket.
fn forget_tcp_stream(stream: TcpStream) {
    match stream.into_std() {
        Ok(std_stream) => {
            #[cfg(unix)]
            {
                use std::os::unix::io::IntoRawFd;
                let _fd = std_stream.into_raw_fd();
            }
            #[cfg(not(unix))]
            {
                std::mem::forget(std_stream);
            }
        }
        Err(_) => {
            warn!("Failed to deregister TCP socket from Tokio during forget");
        }
    }
}

/// Forget a UDP socket without closing it.
fn forget_udp_socket(socket: UdpSocket) {
    match socket.into_std() {
        Ok(std_socket) => {
            #[cfg(unix)]
            {
                use std::os::unix::io::IntoRawFd;
                let _fd = std_socket.into_raw_fd();
            }
            #[cfg(not(unix))]
            {
                std::mem::forget(std_socket);
            }
        }
        Err(_) => {
            warn!("Failed to deregister UDP socket from Tokio during forget");
        }
    }
}


// ===========================================================================
// TcpSocketFilter - TCP connection filter
// ===========================================================================

/// TCP socket connection filter implementing `ConnectionFilter`.
///
/// This is the lowest-level filter in the connection filter chain for TCP
/// connections. It owns a `tokio::net::TcpStream` and delegates all I/O
/// to Tokio's async runtime.
///
/// Corresponds to C `Curl_cft_tcp` / `cf_socket_ctx` in `cf-socket.c`.
pub struct TcpSocketFilter {
    /// Socket configuration (options to apply).
    config: SocketConfig,
    /// The connected TCP stream (`None` before `connect()` completes).
    stream: Option<TcpStream>,
    /// Whether the connection is fully established.
    connected: bool,
    /// Whether shutdown has been initiated.
    is_shut_down: bool,
    /// Remote address once connected.
    remote_addr: Option<SocketAddr>,
    /// Local address once connected.
    local_addr_resolved: Option<SocketAddr>,
    /// Timestamp when connection attempt started.
    connect_started: Option<Instant>,
    /// Timestamp when connection was fully established.
    connect_completed: Option<Instant>,
    /// Timestamp when first byte of data was received.
    first_byte_at: Option<Instant>,
}

impl TcpSocketFilter {
    /// Create a new TCP socket filter with the given configuration.
    pub fn new(config: SocketConfig) -> Self {
        Self {
            config,
            stream: None,
            connected: false,
            is_shut_down: false,
            remote_addr: None,
            local_addr_resolved: None,
            connect_started: None,
            connect_completed: None,
            first_byte_at: None,
        }
    }
}

#[async_trait]
impl ConnectionFilter for TcpSocketFilter {
    fn name(&self) -> &str {
        "tcp"
    }

    fn type_flags(&self) -> u32 {
        CF_TYPE_IP_CONNECT
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn is_shutdown(&self) -> bool {
        self.is_shut_down
    }

    fn data_pending(&self) -> bool {
        false
    }

    async fn connect(&mut self, data: &mut TransferData) -> Result<bool, CurlError> {
        if self.connected {
            return Ok(true);
        }

        let addr = match self.remote_addr {
            Some(a) => a,
            None => {
                warn!("TCP connect called without remote address");
                return Err(CurlError::CouldntConnect);
            }
        };

        let connect_timeout = connection_timeout(data);
        self.connect_started = Some(Instant::now());

        debug!(
            remote = %addr,
            timeout_ms = connect_timeout.as_millis() as u64,
            "TCP connection attempt"
        );

        // Determine if we need a pre-configured socket (local bind, interface
        // binding). If so, use socket2 for creation and option setting, then
        // initiate a non-blocking connect and convert to a Tokio TcpStream.
        // If not, use the simpler TcpStream::connect path.
        let needs_preconfigure = self.config.local_addr.is_some()
            || self.config.bind_interface.is_some();

        let stream = if needs_preconfigure {
            // Create socket via socket2 for pre-connect configuration
            let domain = if addr.is_ipv6() {
                Domain::IPV6
            } else {
                Domain::IPV4
            };

            let raw_socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
                .map_err(io_to_connect_error)?;

            // Apply TCP options before connect
            apply_tcp_options(&raw_socket, &self.config)?;

            // Bind to local address if configured
            if let Some(local) = self.config.local_addr {
                let sa = SockAddr::from(local);
                raw_socket.bind(&sa).map_err(|e| {
                    warn!(error = %e, local = %local, "Failed to bind to local address");
                    io_to_connect_error(e)
                })?;
                trace!(local = %local, "Bound to local address");
            }

            // Bind to network interface if configured (Linux-specific)
            #[cfg(target_os = "linux")]
            if let Some(ref iface) = self.config.bind_interface {
                let iface_bytes = iface.as_bytes();
                // socket2 0.5.x provides bind_device on Linux
                if let Err(e) = raw_socket.bind_device(Some(iface_bytes)) {
                    warn!(error = %e, interface = %iface, "Failed to bind to interface");
                    return Err(CurlError::InterfaceFailed);
                }
                trace!(interface = %iface, "Bound to network interface");
            }

            // Set non-blocking before initiating connect
            raw_socket.set_nonblocking(true).map_err(io_to_connect_error)?;

            // Initiate non-blocking connect. On non-blocking sockets this
            // returns EINPROGRESS (mapped to a platform-specific io::Error).
            // We ignore the error here and verify via writable() + take_error().
            let sock_addr = SockAddr::from(addr);
            let _connect_result = raw_socket.connect(&sock_addr);

            // Convert socket2::Socket → std::net::TcpStream → tokio::net::TcpStream
            // via make_tokio_socket. socket2::Socket implements Into<TcpStream>.
            let std_stream: std::net::TcpStream = raw_socket.into();
            let tokio_stream = make_tokio_socket(std_stream)?;

            // Wait for the connection to complete (socket becomes writable)
            // with the configured timeout.
            let writable_result = timeout(connect_timeout, tokio_stream.writable()).await;
            match writable_result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    warn!(error = %e, remote = %addr, "TCP connect wait failed");
                    return Err(io_to_connect_error(e));
                }
                Err(_) => {
                    warn!(remote = %addr, "TCP connect timed out");
                    return Err(CurlError::OperationTimedOut);
                }
            }

            // Check SO_ERROR to verify the connection completed successfully
            if let Ok(Some(err)) = tokio_stream.take_error() {
                warn!(error = %err, remote = %addr, "TCP connect failed (SO_ERROR)");
                return Err(io_to_connect_error(err));
            }

            tokio_stream
        } else {
            // Simple path: use TcpStream::connect directly and apply options after
            let result = timeout(connect_timeout, TcpStream::connect(addr)).await;
            match result {
                Ok(Ok(s)) => {
                    // Apply options post-connect
                    apply_stream_options(&s, &self.config)?;
                    s
                }
                Ok(Err(e)) => {
                    warn!(error = %e, remote = %addr, "TCP connect failed");
                    return Err(io_to_connect_error(e));
                }
                Err(_) => {
                    warn!(remote = %addr, "TCP connect timed out");
                    return Err(CurlError::OperationTimedOut);
                }
            }
        };

        // Record connection details
        let local = stream.local_addr().ok();
        let peer = stream.peer_addr().ok();
        self.local_addr_resolved = local;
        self.connected = true;
        self.connect_completed = Some(Instant::now());
        self.stream = Some(stream);

        debug!(
            remote = ?peer,
            local = ?local,
            elapsed_ms = self.connect_started
                .map(|s| s.elapsed().as_millis() as u64)
                .unwrap_or(0),
            "TCP connection established"
        );

        Ok(true)
    }

    async fn send(&mut self, buf: &[u8], _eos: bool) -> Result<usize, CurlError> {
        let stream = self.stream.as_mut().ok_or(CurlError::SendError)?;

        match stream.write(buf).await {
            Ok(n) => {
                trace!(bytes = n, "TCP send");
                Ok(n)
            }
            Err(e) => {
                trace!(error = %e, "TCP send error");
                Err(io_to_send_error(e))
            }
        }
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, CurlError> {
        let stream = self.stream.as_mut().ok_or(CurlError::RecvError)?;

        match stream.read(buf).await {
            Ok(0) => {
                trace!("TCP recv: EOF");
                Ok(0)
            }
            Ok(n) => {
                // Record first byte timestamp
                if self.first_byte_at.is_none() {
                    self.first_byte_at = Some(Instant::now());
                }
                trace!(bytes = n, "TCP recv");
                Ok(n)
            }
            Err(e) => {
                trace!(error = %e, "TCP recv error");
                Err(io_to_recv_error(e))
            }
        }
    }

    fn close(&mut self) {
        if let Some(stream) = self.stream.take() {
            drop(stream);
        }
        self.connected = false;
        self.is_shut_down = false;
        debug!("TCP socket closed");
    }

    async fn shutdown(&mut self) -> Result<bool, CurlError> {
        if let Some(ref mut stream) = self.stream {
            stream.shutdown().await.map_err(|e| {
                trace!(error = %e, "TCP shutdown error");
                io_to_send_error(e)
            })?;
        }
        self.is_shut_down = true;
        debug!("TCP shutdown complete");
        Ok(true)
    }

    fn is_alive(&self) -> bool {
        match self.stream {
            Some(ref stream) => check_alive(stream),
            None => false,
        }
    }

    fn adjust_pollset(&self, _data: &TransferData, ps: &mut PollSet) -> Result<(), CurlError> {
        #[cfg(unix)]
        if let Some(ref stream) = self.stream {
            let fd = stream.as_raw_fd();
            if self.connected {
                // Connected: interested in readable data
                ps.add(fd, PollAction::POLL_IN);
            } else {
                // Connecting: interested in writability (connect completion)
                ps.add(fd, PollAction::POLL_OUT);
            }
        }
        Ok(())
    }

    fn control(&mut self, event: i32, _arg1: i32) -> Result<(), CurlError> {
        match event {
            x if x == CF_CTRL_DATA_SETUP => {
                trace!("TCP filter: data setup event");
                Ok(())
            }
            x if x == CF_CTRL_CONN_INFO_UPDATE => {
                trace!("TCP filter: conn info update");
                Ok(())
            }
            x if x == CF_CTRL_FORGET_SOCKET => {
                debug!("TCP filter: forgetting socket (ownership transferred)");
                if let Some(stream) = self.stream.take() {
                    forget_tcp_stream(stream);
                }
                self.connected = false;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn query(&self, query: i32) -> QueryResult {
        match query {
            x if x == CF_QUERY_SOCKET => {
                #[cfg(unix)]
                if let Some(ref stream) = self.stream {
                    return QueryResult::Socket(stream.as_raw_fd());
                }
                QueryResult::NotHandled
            }
            x if x == CF_QUERY_TRANSPORT => {
                QueryResult::Int(TRANSPORT_TCP)
            }
            x if x == CF_QUERY_REMOTE_ADDR => {
                match self.remote_addr {
                    Some(addr) => QueryResult::Addr(addr),
                    None => QueryResult::NotHandled,
                }
            }
            x if x == CF_QUERY_CONNECT_REPLY_MS => {
                match (self.connect_started, self.connect_completed) {
                    (Some(start), Some(end)) => {
                        let elapsed = end.duration_since(start).as_millis() as i64;
                        QueryResult::Int(elapsed as i32)
                    }
                    _ => QueryResult::Int(0),
                }
            }
            x if x == CF_QUERY_TIMER_CONNECT => {
                match self.connect_completed {
                    Some(t) => QueryResult::Time(t),
                    None => QueryResult::NotHandled,
                }
            }
            x if x == CF_QUERY_IP_INFO => {
                // Return local + remote as a formatted string
                let local = self.local_addr_resolved
                    .map(|a| a.to_string())
                    .unwrap_or_default();
                let remote = self.remote_addr
                    .map(|a| a.to_string())
                    .unwrap_or_default();
                QueryResult::String(format!("{} -> {}", local, remote))
            }
            _ => QueryResult::NotHandled,
        }
    }
}


// ===========================================================================
// UdpSocketFilter - UDP connection filter
// ===========================================================================

/// UDP socket connection filter implementing `ConnectionFilter`.
///
/// Sits at the bottom of the connection filter chain for UDP-based
/// connections (primarily QUIC/HTTP3). Owns a `tokio::net::UdpSocket`
/// in connected mode.
///
/// Corresponds to C `Curl_cft_udp` in `cf-socket.c`.
pub struct UdpSocketFilter {
    /// Socket configuration.
    config: SocketConfig,
    /// The connected UDP socket (`None` before `connect()` completes).
    socket: Option<UdpSocket>,
    /// Whether the socket is "connected" (bound + associated with peer).
    connected: bool,
    /// Whether shutdown has been initiated.
    is_shut_down: bool,
    /// Remote peer address.
    remote_addr: Option<SocketAddr>,
    /// Local bound address.
    local_addr_resolved: Option<SocketAddr>,
    /// Timestamp when connect attempt started.
    connect_started: Option<Instant>,
    /// Timestamp when connect completed.
    connect_completed: Option<Instant>,
    /// Timestamp when first datagram was received.
    first_byte_at: Option<Instant>,
}

impl UdpSocketFilter {
    /// Create a new UDP socket filter with the given configuration.
    pub fn new(config: SocketConfig) -> Self {
        Self {
            config,
            socket: None,
            connected: false,
            is_shut_down: false,
            remote_addr: None,
            local_addr_resolved: None,
            connect_started: None,
            connect_completed: None,
            first_byte_at: None,
        }
    }
}

#[async_trait]
impl ConnectionFilter for UdpSocketFilter {
    fn name(&self) -> &str {
        "udp"
    }

    fn type_flags(&self) -> u32 {
        CF_TYPE_IP_CONNECT
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn is_shutdown(&self) -> bool {
        self.is_shut_down
    }

    fn data_pending(&self) -> bool {
        false
    }

    async fn connect(&mut self, data: &mut TransferData) -> Result<bool, CurlError> {
        if self.connected {
            return Ok(true);
        }

        let addr = match self.remote_addr {
            Some(a) => a,
            None => {
                warn!("UDP connect called without remote address");
                return Err(CurlError::CouldntConnect);
            }
        };

        let connect_timeout = connection_timeout(data);
        self.connect_started = Some(Instant::now());

        debug!(
            remote = %addr,
            timeout_ms = connect_timeout.as_millis() as u64,
            "UDP socket setup"
        );

        // Create UDP socket via socket2 for option control
        let domain = if addr.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };

        let raw_socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
            .map_err(io_to_connect_error)?;

        // SO_REUSEADDR
        if let Err(e) = raw_socket.set_reuse_address(true) {
            trace!(error = %e, "Failed to set SO_REUSEADDR on UDP (non-fatal)");
        }

        // Buffer sizes
        if let Some(size) = self.config.sndbuf_size {
            if let Err(e) = raw_socket.set_send_buffer_size(size) {
                warn!(error = %e, size = size, "Failed to set SO_SNDBUF on UDP");
            }
        }
        if let Some(size) = self.config.rcvbuf_size {
            if let Err(e) = raw_socket.set_recv_buffer_size(size) {
                warn!(error = %e, size = size, "Failed to set SO_RCVBUF on UDP");
            }
        }

        // Bind to local address if configured, otherwise bind to any
        let bind_addr = self.config.local_addr.unwrap_or_else(|| {
            if addr.is_ipv6() {
                SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
            } else {
                SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))
            }
        });
        let sa = SockAddr::from(bind_addr);
        raw_socket.bind(&sa).map_err(|e| {
            warn!(error = %e, bind = %bind_addr, "Failed to bind UDP socket");
            io_to_connect_error(e)
        })?;

        // Interface binding (Linux only)
        #[cfg(target_os = "linux")]
        if let Some(ref iface) = self.config.bind_interface {
            if let Err(e) = raw_socket.bind_device(Some(iface.as_bytes())) {
                warn!(error = %e, interface = %iface, "Failed to bind UDP to interface");
                return Err(CurlError::InterfaceFailed);
            }
        }

        raw_socket.set_nonblocking(true).map_err(io_to_connect_error)?;

        // Convert to tokio UdpSocket
        let std_socket: std::net::UdpSocket = raw_socket.into();
        let tokio_socket = UdpSocket::from_std(std_socket)
            .map_err(io_to_connect_error)?;

        // "Connect" the UDP socket to the remote address (sets default peer)
        let connect_result = timeout(
            connect_timeout,
            tokio_socket.connect(addr),
        ).await;

        match connect_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                warn!(error = %e, remote = %addr, "UDP connect failed");
                return Err(io_to_connect_error(e));
            }
            Err(_) => {
                warn!(remote = %addr, "UDP connect timed out");
                return Err(CurlError::OperationTimedOut);
            }
        }

        // Apply post-connect options
        apply_udp_stream_options(&tokio_socket, &self.config)?;

        // Record connection details
        let local = tokio_socket.local_addr().ok();
        let peer = tokio_socket.peer_addr().ok();
        self.local_addr_resolved = local;
        self.connected = true;
        self.connect_completed = Some(Instant::now());
        self.socket = Some(tokio_socket);

        debug!(
            remote = ?peer,
            local = ?local,
            elapsed_ms = self.connect_started
                .map(|s| s.elapsed().as_millis() as u64)
                .unwrap_or(0),
            "UDP socket connected"
        );

        Ok(true)
    }

    async fn send(&mut self, buf: &[u8], _eos: bool) -> Result<usize, CurlError> {
        let socket = self.socket.as_ref().ok_or(CurlError::SendError)?;

        match socket.send(buf).await {
            Ok(n) => {
                trace!(bytes = n, "UDP send");
                Ok(n)
            }
            Err(e) => {
                trace!(error = %e, "UDP send error");
                Err(io_to_send_error(e))
            }
        }
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, CurlError> {
        let socket = self.socket.as_ref().ok_or(CurlError::RecvError)?;

        match socket.recv(buf).await {
            Ok(0) => {
                trace!("UDP recv: no data");
                Ok(0)
            }
            Ok(n) => {
                if self.first_byte_at.is_none() {
                    self.first_byte_at = Some(Instant::now());
                }
                trace!(bytes = n, "UDP recv");
                Ok(n)
            }
            Err(e) => {
                trace!(error = %e, "UDP recv error");
                Err(io_to_recv_error(e))
            }
        }
    }

    fn close(&mut self) {
        if let Some(socket) = self.socket.take() {
            drop(socket);
        }
        self.connected = false;
        self.is_shut_down = false;
        debug!("UDP socket closed");
    }

    async fn shutdown(&mut self) -> Result<bool, CurlError> {
        // UDP is connectionless; shutdown is a no-op but we mark state
        self.is_shut_down = true;
        debug!("UDP shutdown (no-op for connectionless)");
        Ok(true)
    }

    fn is_alive(&self) -> bool {
        match self.socket {
            Some(ref socket) => socket.peer_addr().is_ok(),
            None => false,
        }
    }

    fn adjust_pollset(&self, _data: &TransferData, ps: &mut PollSet) -> Result<(), CurlError> {
        #[cfg(unix)]
        if let Some(ref socket) = self.socket {
            let fd = socket.as_raw_fd();
            if self.connected {
                ps.add(fd, PollAction::POLL_IN | PollAction::POLL_OUT);
            }
        }
        Ok(())
    }

    fn control(&mut self, event: i32, _arg1: i32) -> Result<(), CurlError> {
        match event {
            x if x == CF_CTRL_DATA_SETUP => {
                trace!("UDP filter: data setup event");
                Ok(())
            }
            x if x == CF_CTRL_CONN_INFO_UPDATE => {
                trace!("UDP filter: conn info update");
                Ok(())
            }
            x if x == CF_CTRL_FORGET_SOCKET => {
                debug!("UDP filter: forgetting socket");
                if let Some(socket) = self.socket.take() {
                    forget_udp_socket(socket);
                }
                self.connected = false;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn query(&self, query: i32) -> QueryResult {
        match query {
            x if x == CF_QUERY_SOCKET => {
                #[cfg(unix)]
                if let Some(ref socket) = self.socket {
                    return QueryResult::Socket(socket.as_raw_fd());
                }
                QueryResult::NotHandled
            }
            x if x == CF_QUERY_TRANSPORT => {
                QueryResult::Int(TRANSPORT_QUIC)
            }
            x if x == CF_QUERY_REMOTE_ADDR => {
                match self.remote_addr {
                    Some(addr) => QueryResult::Addr(addr),
                    None => QueryResult::NotHandled,
                }
            }
            x if x == CF_QUERY_CONNECT_REPLY_MS => {
                match (self.connect_started, self.connect_completed) {
                    (Some(start), Some(end)) => {
                        let elapsed = end.duration_since(start).as_millis() as i64;
                        QueryResult::Int(elapsed as i32)
                    }
                    _ => QueryResult::Int(0),
                }
            }
            x if x == CF_QUERY_TIMER_CONNECT => {
                match self.connect_completed {
                    Some(t) => QueryResult::Time(t),
                    None => QueryResult::NotHandled,
                }
            }
            x if x == CF_QUERY_IP_INFO => {
                let local = self.local_addr_resolved
                    .map(|a| a.to_string())
                    .unwrap_or_default();
                let remote = self.remote_addr
                    .map(|a| a.to_string())
                    .unwrap_or_default();
                QueryResult::String(format!("{} -> {}", local, remote))
            }
            _ => QueryResult::NotHandled,
        }
    }
}
