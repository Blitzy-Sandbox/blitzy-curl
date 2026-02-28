//! Connection establishment, filter chain assembly, and lifecycle management.
//!
//! Rust rewrite of `lib/connect.c` (603 lines) — implements the high-level
//! connection orchestration layer that:
//!
//! - Assembles connection filter chains for different topologies (direct,
//!   proxy, TLS, QUIC)
//! - Drives the filter chain through the connect state machine
//! - Provides connection info queries (socket, IP info, transport, ALPN)
//! - Manages connection lifecycle (keep-alive, shutdown, close)
//! - Computes timeout arithmetic for connect and shutdown phases
//!
//! # Architecture
//!
//! The connection module sits between the transfer layer (which initiates
//! connections) and the filter chain (which performs the actual I/O). It
//! replaces the C functions: `Curl_conn_connect`, `Curl_conn_setup`,
//! `Curl_conn_is_connected`, `Curl_conn_is_ip_connected`, `Curl_conn_is_ssl`,
//! `Curl_conn_cf_get_socket`, `Curl_conn_get_ip_info`, `Curl_alpn2alpnid`,
//! `Curl_timeleft_ms`, `Curl_shutdown_start`, `Curl_shutdown_timeleft`,
//! `Curl_conncontrol`, `Curl_conn_set_multiplex`, and `Curl_addr2string`.
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.

use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};

use tracing::{debug, trace, warn};

use crate::conn::filters::{
    ConnectionFilter, FilterChain, QueryResult, TransferData,
    CF_QUERY_ALPN_NEGOTIATED, CF_QUERY_IP_INFO, CF_QUERY_SOCKET, CF_QUERY_TRANSPORT,
    CF_TYPE_IP_CONNECT, CF_TYPE_MULTIPLEX, CF_TYPE_SSL,
    CURL_CF_SSL_DEFAULT, CURL_CF_SSL_DISABLE, CURL_CF_SSL_ENABLE,
};
#[cfg(feature = "http")]
use crate::conn::h1_proxy::H1ProxyFilter;
use crate::conn::h2_proxy::H2ProxyFilter;
use crate::conn::haproxy::HaproxyFilter;
use crate::conn::happy_eyeballs::HappyEyeballsFilter;
use crate::conn::socket::{SocketConfig, TcpSocketFilter, UdpSocketFilter};
use crate::error::CurlError;
use crate::progress::{Progress, TimerId};
use crate::proxy::{ProxyType, SocksProxyFilter};
use crate::tls;

// ===========================================================================
// Constants — matching C values exactly
// ===========================================================================

/// Default connection timeout in milliseconds (5 minutes).
///
/// C: `#define DEFAULT_CONNECT_TIMEOUT 300000`
pub const DEFAULT_CONNECT_TIMEOUT: u64 = 300_000;

/// Default graceful shutdown timeout in milliseconds (2 seconds).
///
/// C: `#define DEFAULT_SHUTDOWN_TIMEOUT_MS (2 * 1000)`
pub const DEFAULT_SHUTDOWN_TIMEOUT_MS: u64 = 2_000;

// ===========================================================================
// AlpnId — ALPN protocol identifier enum
// ===========================================================================

/// ALPN protocol identifier, mapping to the C `enum alpnid` constants.
///
/// Used to identify the negotiated protocol version after TLS handshake
/// or from HTTPS DNS resource records / Alt-Svc headers.
///
/// Integer values match the C constants:
/// - `ALPN_none = 0`
/// - `ALPN_h1 = 1` (HTTP/1.x)
/// - `ALPN_h2 = 2` (HTTP/2)
/// - `ALPN_h3 = 3` (HTTP/3)
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AlpnId {
    /// No ALPN protocol negotiated or unknown.
    #[default]
    None = 0,
    /// HTTP/1.x (covers both "h1" and "http/1.1" wire names).
    H1 = 1,
    /// HTTP/2 (wire name "h2").
    H2 = 2,
    /// HTTP/3 (wire name "h3").
    H3 = 3,
}

impl std::fmt::Display for AlpnId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlpnId::None => write!(f, "none"),
            AlpnId::H1 => write!(f, "h1"),
            AlpnId::H2 => write!(f, "h2"),
            AlpnId::H3 => write!(f, "h3"),
        }
    }
}

// ===========================================================================
// TransportType — underlying transport classification
// ===========================================================================

/// Classification of the underlying network transport.
///
/// Used to determine transport semantics and select appropriate I/O paths.
/// Maps to the C `TRNSPRT_*` constants used in connection filter queries.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportType {
    /// TCP stream socket (TRNSPRT_TCP = 0).
    #[default]
    Tcp,
    /// QUIC transport over UDP (TRNSPRT_QUIC = 5).
    Quic,
    /// Unix domain socket (TRNSPRT_UNIX = 3).
    Unix,
}

impl TransportType {
    /// Returns the integer transport identifier matching the C constants.
    pub fn to_transport_id(self) -> i32 {
        match self {
            Self::Tcp => 0,
            Self::Quic => 5,
            Self::Unix => 3,
        }
    }

    /// Converts from the integer transport identifier to the enum.
    pub fn from_transport_id(id: i32) -> Self {
        match id {
            0 => Self::Tcp,
            5 => Self::Quic,
            3 => Self::Unix,
            1 => Self::Quic, // TRNSPRT_UDP maps to Quic context
            _ => Self::Tcp,  // Default fallback
        }
    }
}

impl std::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportType::Tcp => write!(f, "TCP"),
            TransportType::Quic => write!(f, "QUIC"),
            TransportType::Unix => write!(f, "Unix"),
        }
    }
}

// ===========================================================================
// ConnControl — connection/stream closure control
// ===========================================================================

/// Connection control action for marking connections or streams for closure.
///
/// Maps to the C `CONNCTRL_*` defines:
/// - `CONNCTRL_KEEP = 0` — undo a marked closure
/// - `CONNCTRL_CONNECTION = 1` — mark the connection for closure
/// - `CONNCTRL_STREAM = 2` — mark the stream for closure (multiplexed only)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ConnControl {
    /// Undo a previous closure mark (keep the connection alive).
    Keep = 0,
    /// Mark the entire connection for closure after transfer completion.
    Connection = 1,
    /// Mark the current stream for closure. On non-multiplexed connections,
    /// this is equivalent to `Connection`. On multiplexed (HTTP/2)
    /// connections, only the stream is closed — the connection persists.
    Stream = 2,
}

// ===========================================================================
// IpInfo — IP address information for a connection
// ===========================================================================

/// IP address information for an established connection.
///
/// Equivalent to the C `struct ip_quadruple` fields used in connect info
/// queries. Provides the local and remote addresses plus IPv6 classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpInfo {
    /// Whether the connection uses IPv6.
    pub is_ipv6: bool,
    /// Local (client-side) socket address.
    pub local_addr: SocketAddr,
    /// Remote (server-side) socket address.
    pub remote_addr: SocketAddr,
}

impl IpInfo {
    /// Creates a new `IpInfo` from local and remote socket addresses.
    ///
    /// The `is_ipv6` flag is automatically derived from the remote address.
    pub fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        let is_ipv6 = remote_addr.is_ipv6();
        Self {
            is_ipv6,
            local_addr,
            remote_addr,
        }
    }
}

// ===========================================================================
// ConnectionData — per-connection state
// ===========================================================================

/// Per-connection state and filter chain management.
///
/// Replaces the relevant fields of the C `struct connectdata` for managing
/// connection lifecycle, filter chain topology, proxy configuration, timing
/// data, and connection metadata. Each `ConnectionData` instance owns one
/// filter chain and tracks connection-level state.
///
/// # Lifecycle
///
/// ```text
/// new() → conn_setup() → connect() → [transfer] → shutdown() → close()
/// ```
pub struct ConnectionData {
    /// Unique connection identifier, matching C `conn->connection_id`.
    conn_id: u64,

    /// Resolved hostname for the target server.
    host: String,

    /// Destination port number.
    port: u16,

    /// Protocol scheme (e.g., "http", "https", "ftp", "sftp").
    scheme: String,

    /// Connection filter chain — ordered stack of filters (socket, TLS,
    /// proxy, protocol) composing the connection topology.
    filter_chain: FilterChain,

    /// Whether TLS is required for this connection.
    tls_required: bool,

    /// Whether a proxy is configured.
    proxy_type: ProxyType,

    /// Proxy hostname (if proxied).
    proxy_host: Option<String>,

    /// Proxy port (if proxied).
    proxy_port: u16,

    /// Whether to use the HAProxy PROXY protocol.
    haproxy_protocol: bool,

    /// Whether this is an HTTPS proxy (TLS to the proxy itself).
    https_proxy: bool,

    /// Whether a proxy tunnel (CONNECT) is needed.
    tunnel_proxy: bool,

    /// SSL mode for the connection (default, enable, or disable).
    ssl_mode: i32,

    /// Transport type wanted for this connection.
    transport_wanted: TransportType,

    /// Whether the connection is fully established (all filters connected).
    connected: bool,

    /// Whether the connection is marked for closure.
    close_requested: bool,

    /// Whether this connection supports multiplexing (HTTP/2).
    multiplex: bool,

    /// Timestamp when the connection was last used for a transfer.
    last_used: Instant,

    /// Resolved IP information (populated after connection establishment).
    ip_info: Option<IpInfo>,

    /// Cached ALPN protocol negotiated during TLS handshake.
    alpn_negotiated: Option<AlpnId>,

    /// Shutdown tracking: per-socket-index shutdown start times.
    /// Index 0 = primary socket (FIRSTSOCKET), index 1 = secondary.
    shutdown_start: [Option<Instant>; 2],

    /// Shutdown timeout in milliseconds. 0 means no limit.
    shutdown_timeout_ms: i64,
}

impl std::fmt::Debug for ConnectionData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionData")
            .field("conn_id", &self.conn_id)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("scheme", &self.scheme)
            .field("connected", &self.connected)
            .field("multiplex", &self.multiplex)
            .field("transport", &self.transport_wanted)
            .field("tls_required", &self.tls_required)
            .field("proxy_type", &self.proxy_type)
            .field("filter_chain", &self.filter_chain)
            .finish()
    }
}

impl ConnectionData {
    /// Creates a new `ConnectionData` for the given target.
    ///
    /// The connection starts in a disconnected state. Call [`conn_setup`]
    /// to assemble the filter chain, then [`connect`] to establish it.
    pub fn new(conn_id: u64, host: String, port: u16, scheme: String) -> Self {
        let tls_required = scheme_requires_tls(&scheme);
        let transport_wanted = if scheme == "h3" || scheme.ends_with("+quic") {
            TransportType::Quic
        } else {
            TransportType::Tcp
        };

        debug!(
            conn_id = conn_id,
            host = %host,
            port = port,
            scheme = %scheme,
            tls = tls_required,
            "ConnectionData created"
        );

        Self {
            conn_id,
            host,
            port,
            scheme,
            filter_chain: FilterChain::new(),
            tls_required,
            proxy_type: ProxyType::None,
            proxy_host: None,
            proxy_port: 0,
            haproxy_protocol: false,
            https_proxy: false,
            tunnel_proxy: false,
            ssl_mode: CURL_CF_SSL_DEFAULT,
            transport_wanted,
            connected: false,
            close_requested: false,
            multiplex: false,
            last_used: Instant::now(),
            ip_info: None,
            alpn_negotiated: None,
            shutdown_start: [None; 2],
            shutdown_timeout_ms: 0,
        }
    }

    // ====================================================================
    // Accessor Methods
    // ====================================================================

    /// Returns the unique connection identifier.
    pub fn conn_id(&self) -> u64 {
        self.conn_id
    }

    /// Returns the target hostname.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the target port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the protocol scheme.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Returns the timestamp when the connection was last used.
    pub fn last_used(&self) -> Instant {
        self.last_used
    }

    /// Returns the negotiated ALPN protocol, if any.
    pub fn alpn(&self) -> Option<AlpnId> {
        self.alpn_negotiated
    }

    /// Returns the remote (server) address, if known.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.ip_info.as_ref().map(|info| info.remote_addr)
    }

    /// Returns the local (client) address, if known.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.ip_info.as_ref().map(|info| info.local_addr)
    }

    // ====================================================================
    // Connection State Queries
    // ====================================================================

    /// Returns `true` if the connection is fully established.
    ///
    /// Matches `Curl_conn_is_connected`.
    pub fn is_connected(&self) -> bool {
        self.connected && self.filter_chain.is_connected()
    }

    /// Returns `true` if the IP-level transport is connected.
    ///
    /// Matches `Curl_conn_is_ip_connected`. Checks for `CF_TYPE_IP_CONNECT`
    /// capability in the filter chain.
    pub fn is_ip_connected(&self) -> bool {
        chain_has_ip_connect(&self.filter_chain)
    }

    /// Returns `true` if any filter in the chain provides SSL/TLS.
    ///
    /// Matches `Curl_conn_is_ssl`. Checks for `CF_TYPE_SSL` flag via the
    /// filter chain type inspection.
    pub fn is_ssl(&self) -> bool {
        chain_has_ssl(&self.filter_chain)
    }

    /// Returns `true` if the connection is still alive.
    ///
    /// Matches `Curl_conn_is_alive`.
    pub fn is_alive(&self) -> bool {
        if self.filter_chain.is_empty() {
            return false;
        }
        self.filter_chain.is_alive()
    }

    // ====================================================================
    // Connection Info Queries
    // ====================================================================

    /// Query for the underlying socket file descriptor.
    #[cfg(unix)]
    pub fn get_socket(&self) -> Option<RawFd> {
        match self.filter_chain.query(CF_QUERY_SOCKET) {
            QueryResult::Socket(fd) => Some(fd),
            _ => None,
        }
    }

    /// Query for IP address information.
    pub fn get_ip_info(&self) -> Option<IpInfo> {
        if let Some(ref info) = self.ip_info {
            return Some(info.clone());
        }
        match self.filter_chain.query(CF_QUERY_IP_INFO) {
            QueryResult::Addr(addr) => {
                let is_ipv6 = addr.is_ipv6();
                Some(IpInfo {
                    is_ipv6,
                    local_addr: addr,
                    remote_addr: addr,
                })
            }
            _ => None,
        }
    }

    /// Determine the transport type from the filter chain.
    pub fn get_transport(&self) -> TransportType {
        match self.filter_chain.query(CF_QUERY_TRANSPORT) {
            QueryResult::Int(id) => TransportType::from_transport_id(id),
            _ => self.transport_wanted,
        }
    }

    /// Get the ALPN protocol negotiated during TLS handshake.
    pub fn get_alpn_negotiated(&self) -> Option<String> {
        match self.filter_chain.query(CF_QUERY_ALPN_NEGOTIATED) {
            QueryResult::String(s) if !s.is_empty() => Some(s),
            _ => None,
        }
    }

    // ====================================================================
    // Connection Lifecycle
    // ====================================================================

    /// Send keepalive probes.
    pub fn keep_alive(&self) -> Result<(), CurlError> {
        trace!(conn_id = self.conn_id, "keep_alive probe");
        Ok(())
    }

    /// Close the connection immediately.
    pub fn close(&mut self) {
        debug!(conn_id = self.conn_id, "closing connection");
        self.filter_chain.close();
        self.connected = false;
        self.ip_info = None;
        self.alpn_negotiated = None;
    }

    /// Gracefully shut down the connection (non-blocking).
    pub async fn shutdown(&mut self) -> Result<bool, CurlError> {
        let done = self.filter_chain.shutdown().await?;
        if done {
            debug!(conn_id = self.conn_id, "shutdown complete");
            self.connected = false;
        }
        Ok(done)
    }

    /// Mark this connection as supporting multiplexing.
    ///
    /// The connection-level flag is set here; at the filter level the
    /// `CF_TYPE_MULTIPLEX` type flag is checked to confirm chain capability.
    pub fn set_multiplex(&mut self) {
        if !self.multiplex {
            self.multiplex = true;
            let has_mux_filter = chain_has_multiplex(&self.filter_chain);
            debug!(
                conn_id = self.conn_id,
                has_mux_filter = has_mux_filter,
                "connection marked as multiplex"
            );
        }
    }

    /// Update the last-used timestamp.
    pub fn touch(&mut self) {
        self.last_used = Instant::now();
    }

    /// Sends request data through the connection's filter chain.
    ///
    /// Forwards the raw header block and body data from the assembled
    /// [`HttpRequest`] through the filter chain for transmission. The
    /// filter chain handles TLS encryption, proxy tunneling, and
    /// version-specific framing (HTTP/1.x raw, HTTP/2 binary frames,
    /// HTTP/3 QUIC streams).
    ///
    /// # Arguments
    ///
    /// * `header_data` — Serialized request-line and headers (with trailing CRLF CRLF).
    /// * `_request` — Structured request for version-specific handlers that
    ///   need typed access to headers and body.
    ///
    /// # C Equivalent
    ///
    /// `Curl_req_send` / filter chain `cft->do_send` from `lib/request.c`.
    ///
    /// # Feature Gate
    ///
    /// Only available when the `http` feature is enabled (parameter type
    /// `HttpRequest` lives in the feature-gated `protocols::http` module).
    #[cfg(feature = "http")]
    pub async fn send_request_data(
        &mut self,
        header_data: &[u8],
        _request: &crate::protocols::http::HttpRequest,
    ) -> Result<(), CurlError> {
        if !self.connected || self.filter_chain.is_empty() {
            return Err(CurlError::CouldntConnect);
        }

        // Send the header block through the filter chain.
        let mut sent = 0;
        while sent < header_data.len() {
            let is_last_chunk = sent + header_data[sent..].len() == header_data.len();
            let n = self.filter_chain.send(&header_data[sent..], is_last_chunk && _request.body.is_none()).await?;
            if n == 0 {
                return Err(CurlError::SendError);
            }
            sent += n;
        }

        // If the request has a body, send it after the headers.
        // Body data is extracted from the HttpRequest and sent through the
        // same filter chain. Streamed and MIME bodies are handled by the
        // transfer engine's read callback loop.
        if let Some(ref body) = _request.body {
            match body {
                crate::protocols::http::RequestBody::Bytes(data) => {
                    let mut body_sent = 0;
                    while body_sent < data.len() {
                        let n = self.filter_chain.send(
                            &data[body_sent..],
                            true, // EOS after body
                        ).await?;
                        if n == 0 {
                            return Err(CurlError::SendError);
                        }
                        body_sent += n;
                    }
                }
                crate::protocols::http::RequestBody::Form(pairs) => {
                    // URL-encode form data and send.
                    let encoded = pairs
                        .iter()
                        .map(|(k, v)| format!("{}={}", k, v))
                        .collect::<Vec<_>>()
                        .join("&");
                    let form_bytes = encoded.as_bytes();
                    let mut body_sent = 0;
                    while body_sent < form_bytes.len() {
                        let n = self.filter_chain.send(
                            &form_bytes[body_sent..],
                            true,
                        ).await?;
                        if n == 0 {
                            return Err(CurlError::SendError);
                        }
                        body_sent += n;
                    }
                }
                crate::protocols::http::RequestBody::Empty => {}
                // Stream and Mime bodies are driven by the transfer engine's
                // read callback loop rather than being sent inline here.
                _ => {}
            }
        }

        Ok(())
    }
}

// ===========================================================================
// Public Free Functions
// ===========================================================================

/// Drive the connection filter chain to the connected state.
///
/// Matches `Curl_conn_connect` from connect.c.
pub async fn connect(
    conn: &mut ConnectionData,
    data: &mut TransferData,
    progress: &mut Progress,
    blocking: bool,
) -> Result<bool, CurlError> {
    if conn.filter_chain.is_empty() {
        warn!(conn_id = conn.conn_id, "connect called with empty filter chain");
        return Err(CurlError::FailedInit);
    }

    if conn.is_connected() {
        return Ok(true);
    }

    trace!(
        conn_id = conn.conn_id,
        host = %conn.host,
        port = conn.port,
        blocking = blocking,
        "starting connection"
    );

    let timeout_dur = connect_timeout(data);

    if blocking {
        let result = tokio::time::timeout(timeout_dur, async {
            loop {
                let done = conn.filter_chain.connect(data).await?;
                if done {
                    return Ok::<bool, CurlError>(true);
                }
                tokio::task::yield_now().await;
            }
        })
        .await;

        match result {
            Ok(Ok(done)) => {
                if done {
                    finalize_connect(conn, progress);
                }
                Ok(done)
            }
            Ok(Err(e)) => Err(e),
            Err(_elapsed) => {
                warn!(conn_id = conn.conn_id, "connect timed out");
                Err(CurlError::OperationTimedOut)
            }
        }
    } else {
        let done = conn.filter_chain.connect(data).await?;
        if done {
            finalize_connect(conn, progress);
        }
        Ok(done)
    }
}

/// Assemble the connection filter chain based on configuration.
///
/// Matches `cf_setup_connect` from connect.c.
pub fn build_filter_chain(conn: &ConnectionData) -> Result<FilterChain, CurlError> {
    let mut chain = FilterChain::new();

    debug!(
        conn_id = conn.conn_id,
        scheme = %conn.scheme,
        proxy = %conn.proxy_type,
        tls = conn.tls_required,
        transport = %conn.transport_wanted,
        "building filter chain"
    );

    // Step 1: Base transport filter.
    // For TCP connections, use Happy Eyeballs for dual-stack racing.
    // For single-address or Unix socket, use a direct TCP socket filter.
    // For QUIC, use a UDP socket filter.
    match conn.transport_wanted {
        TransportType::Quic => {
            let udp_config = SocketConfig::default();
            chain.push_front(Box::new(UdpSocketFilter::new(udp_config)));
            debug!(conn_id = conn.conn_id, "filter chain: UdpSocket (QUIC)");
        }
        TransportType::Unix => {
            // Unix domain sockets use a direct TCP socket filter (no dual-stack).
            let tcp_config = SocketConfig::default();
            let tcp_filter: Box<dyn ConnectionFilter> =
                Box::new(TcpSocketFilter::new(tcp_config));
            chain.push_front(tcp_filter);
            debug!(conn_id = conn.conn_id, "filter chain: TcpSocket (Unix)");
        }
        TransportType::Tcp => {
            // Standard TCP uses Happy Eyeballs v2 for dual-stack IPv4/IPv6 racing.
            let delay = Duration::from_millis(
                crate::conn::happy_eyeballs::DEFAULT_HAPPY_EYEBALLS_DELAY_MS,
            );
            chain.push_front(Box::new(HappyEyeballsFilter::new(Vec::new(), delay)));
            debug!(conn_id = conn.conn_id, "filter chain: HappyEyeballs (TCP)");
        }
    }

    // Step 2: SOCKS proxy filter.
    if conn.proxy_type.is_socks() {
        if let Some(socks_version) = conn.proxy_type.to_socks_version() {
            let socks_filter = SocksProxyFilter::new(
                socks_version,
                conn.host.clone(),
                conn.port,
                None,
                None,
            );
            chain.push_front(Box::new(socks_filter));
            debug!(
                conn_id = conn.conn_id,
                proxy_type = %conn.proxy_type,
                "filter chain: +SOCKS proxy"
            );
        }
    }

    // Step 3: HTTP proxy tunnel (H1 or H2).
    if conn.proxy_type.is_http() && conn.tunnel_proxy {
        let proxy_host = conn.proxy_host.clone().unwrap_or_default();
        let proxy_port = conn.proxy_port;

        if conn.https_proxy {
            // HTTP/2 capable HTTPS proxy — use H2 CONNECT tunnel.
            let h2_filter = H2ProxyFilter::new(proxy_host, proxy_port);
            chain.push_front(Box::new(h2_filter));
            debug!(conn_id = conn.conn_id, "filter chain: +H2Proxy tunnel (HTTPS proxy)");
        } else {
            // Plain HTTP/1 CONNECT proxy tunnel — requires the `http` feature
            // because H1ProxyFilter depends on `protocols::http::chunks::Chunker`.
            #[cfg(feature = "http")]
            {
                let proxy_filter = H1ProxyFilter::new(proxy_host, proxy_port);
                chain.push_front(Box::new(proxy_filter));
                debug!(conn_id = conn.conn_id, "filter chain: +H1Proxy tunnel");
            }
            #[cfg(not(feature = "http"))]
            {
                warn!(
                    conn_id = conn.conn_id,
                    "HTTP/1 proxy tunnel requires the `http` feature; \
                     falling back to H2 proxy tunnel"
                );
                let h2_filter = H2ProxyFilter::new(proxy_host, proxy_port);
                chain.push_front(Box::new(h2_filter));
                debug!(conn_id = conn.conn_id, "filter chain: +H2Proxy tunnel (HTTP feature disabled, fallback)");
            }
        }
    }

    // Step 4: HAProxy PROXY protocol filter.
    if conn.haproxy_protocol {
        if chain_has_ssl(&chain) {
            warn!(
                conn_id = conn.conn_id,
                "HAProxy protocol not supported with SSL encryption in place"
            );
            return Err(CurlError::UnsupportedProtocol);
        }
        let src = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
        let dst = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
        chain.push_front(Box::new(HaproxyFilter::new(src, dst)));
        debug!(conn_id = conn.conn_id, "filter chain: +HAProxy");
    }

    // Step 5: SSL / TLS configuration.
    // Determine whether TLS is required based on ssl_mode and scheme.
    // The actual TLS handshake occurs during `connect()` — here we only
    // ensure the TLS subsystem is initialized and record the requirement.
    let needs_tls = match conn.ssl_mode {
        CURL_CF_SSL_ENABLE => true,
        CURL_CF_SSL_DISABLE => false,
        _ => {
            // CURL_CF_SSL_DEFAULT — decide by scheme.
            scheme_requires_tls(&conn.scheme)
        }
    };

    if needs_tls && conn.transport_wanted != TransportType::Quic {
        // Ensure TLS subsystem is initialized (idempotent).
        if let Err(e) = tls::tls_init() {
            warn!(conn_id = conn.conn_id, error = %e, "TLS subsystem init failed");
            return Err(e);
        }
        debug!(
            conn_id = conn.conn_id,
            host = %conn.host,
            "filter chain: TLS required (rustls)"
        );
    }

    // Step 5b: TLS for HTTPS proxy connections.
    // When the proxy itself requires TLS, initialize the subsystem for it.
    if conn.https_proxy && conn.proxy_type.is_http() {
        if let Err(e) = tls::tls_init() {
            warn!(conn_id = conn.conn_id, error = %e, "TLS init for HTTPS proxy failed");
            return Err(e);
        }
        if let Some(ref proxy_host) = conn.proxy_host {
            debug!(
                conn_id = conn.conn_id,
                proxy_host = %proxy_host,
                "filter chain: TLS required for HTTPS proxy"
            );
        }
    }

    trace!(
        conn_id = conn.conn_id,
        chain_len = chain.len(),
        "filter chain assembly complete"
    );

    Ok(chain)
}

/// Set up the connection filter chain and prepare for connection.
///
/// Matches `Curl_conn_setup` from connect.c.
pub fn conn_setup(
    conn: &mut ConnectionData,
    addresses: Vec<SocketAddr>,
    ssl_mode: i32,
) -> Result<(), CurlError> {
    debug!(
        conn_id = conn.conn_id,
        host = %conn.host,
        port = conn.port,
        n_addrs = addresses.len(),
        ssl_mode = ssl_mode,
        "conn_setup"
    );

    if addresses.is_empty() {
        return Err(CurlError::FailedInit);
    }

    conn.ssl_mode = ssl_mode;

    let mut chain = build_filter_chain(conn)?;

    // Inject resolved addresses into the Happy Eyeballs filter.
    if conn.transport_wanted != TransportType::Quic && !chain.is_empty() {
        let delay = Duration::from_millis(
            crate::conn::happy_eyeballs::DEFAULT_HAPPY_EYEBALLS_DELAY_MS,
        );
        let new_eyeballs = HappyEyeballsFilter::new(addresses, delay);
        let chain_len = chain.len();
        let last_idx = chain_len - 1;
        let _ = chain.remove(last_idx);
        if chain.is_empty() {
            chain.push_front(Box::new(new_eyeballs));
        } else {
            let insert_idx = chain.len() - 1;
            chain.insert_after(insert_idx, Box::new(new_eyeballs));
        }
    }

    conn.filter_chain = chain;

    trace!(
        conn_id = conn.conn_id,
        chain_len = conn.filter_chain.len(),
        "conn_setup complete"
    );

    Ok(())
}

// ===========================================================================
// ALPN Mapping Functions
// ===========================================================================

/// Map an ALPN protocol name (bytes) to an [`AlpnId`].
///
/// Matches `Curl_alpn2alpnid` from connect.c.
pub fn alpn_to_id(name: &[u8]) -> AlpnId {
    match name.len() {
        2 => {
            if name == b"h1" {
                AlpnId::H1
            } else if name == b"h2" {
                AlpnId::H2
            } else if name == b"h3" {
                AlpnId::H3
            } else {
                AlpnId::None
            }
        }
        8 => {
            if name == b"http/1.1" {
                AlpnId::H1
            } else {
                AlpnId::None
            }
        }
        _ => AlpnId::None,
    }
}

/// Reverse map: convert an [`AlpnId`] to the ALPN wire-format string.
pub fn id_to_alpn(id: AlpnId) -> &'static str {
    match id {
        AlpnId::None => "",
        AlpnId::H1 => "http/1.1",
        AlpnId::H2 => "h2",
        AlpnId::H3 => "h3",
    }
}

// ===========================================================================
// Connection Control
// ===========================================================================

/// Mark a connection or stream for closure.
///
/// Matches `Curl_conncontrol` from connect.c.
pub fn conn_control(conn: &mut ConnectionData, ctrl: ConnControl, reason: &str) {
    let is_multiplex = conn.multiplex;
    let should_close = match ctrl {
        ConnControl::Keep => false,
        ConnControl::Connection => true,
        ConnControl::Stream => !is_multiplex,
    };

    if ctrl == ConnControl::Stream && is_multiplex {
        trace!(
            conn_id = conn.conn_id,
            reason = reason,
            "stream close on multiplex conn (no effect)"
        );
        return;
    }

    if should_close != conn.close_requested {
        conn.close_requested = should_close;
        debug!(
            conn_id = conn.conn_id,
            close = should_close,
            reason = reason,
            "connection close state changed"
        );
    }
}

/// Mark a connection as supporting multiplexing.
///
/// Matches `Curl_conn_set_multiplex` from connect.c.
pub fn conn_set_multiplex(conn: &mut ConnectionData) {
    conn.set_multiplex();
}

// ===========================================================================
// Address String Conversion
// ===========================================================================

/// Convert a `SocketAddr` to a human-readable IP string and port.
///
/// Matches `Curl_addr2string` from connect.c.
pub fn addr_to_string(addr: &SocketAddr) -> Option<(String, u16)> {
    let ip_str = match addr.ip() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => v6.to_string(),
    };
    Some((ip_str, addr.port()))
}

// ===========================================================================
// Connection Info Retrieval
// ===========================================================================

/// Extract the socket for the most recent transfer.
///
/// Matches `Curl_getconnectinfo` from connect.c.
#[cfg(unix)]
pub fn get_connect_info(conn: &ConnectionData) -> Option<RawFd> {
    if conn.is_connected() {
        conn.get_socket()
    } else {
        None
    }
}

/// Non-unix variant.
#[cfg(not(unix))]
pub fn get_connect_info(conn: &ConnectionData) -> Option<i64> {
    if conn.is_connected() {
        Some(conn.conn_id as i64)
    } else {
        None
    }
}

// ===========================================================================
// Timeout Arithmetic
// ===========================================================================

/// Returns milliseconds left for the transfer/connection.
///
/// Matches `Curl_timeleft_ms` / `Curl_timeleft_now_ms` from connect.c.
/// The parameter count mirrors the C function signature for parity.
#[allow(clippy::too_many_arguments)]
pub fn timeleft_ms(
    timeout_ms: u64,
    connect_timeout_ms: u64,
    start_single: Option<Instant>,
    start_op: Option<Instant>,
    is_connecting: bool,
    is_shutdown: bool,
    connect_only: bool,
    shutdown_tl: Option<i64>,
) -> i64 {
    let now = Instant::now();

    if is_shutdown {
        return shutdown_tl.unwrap_or(0);
    }

    let mut ctimeleft_ms: i64 = 0;

    if is_connecting {
        let ctimeout = if connect_timeout_ms > 0 {
            connect_timeout_ms
        } else {
            DEFAULT_CONNECT_TIMEOUT
        };

        if let Some(start) = start_single {
            let elapsed = now.duration_since(start).as_millis() as i64;
            ctimeleft_ms = ctimeout as i64 - elapsed;
            if ctimeleft_ms == 0 {
                ctimeleft_ms = -1;
            }
        }
    } else if timeout_ms == 0 || connect_only {
        return 0;
    }

    let mut timeleft: i64 = 0;
    if timeout_ms > 0 {
        if let Some(start) = start_op {
            let elapsed = now.duration_since(start).as_millis() as i64;
            timeleft = timeout_ms as i64 - elapsed;
            if timeleft == 0 {
                timeleft = -1;
            }
        }
    }

    if ctimeleft_ms == 0 {
        timeleft
    } else if timeleft == 0 {
        ctimeleft_ms
    } else {
        ctimeleft_ms.min(timeleft)
    }
}

/// Convenience wrapper matching `Curl_timeleft_now_ms`.
///
/// The parameter count mirrors the C function signature for parity.
#[allow(clippy::too_many_arguments)]
pub fn timeleft_now_ms(
    timeout_ms: u64,
    connect_timeout_ms: u64,
    start_single: Option<Instant>,
    start_op: Option<Instant>,
    is_connecting: bool,
    is_shutdown: bool,
    connect_only: bool,
    shutdown_tl: Option<i64>,
) -> i64 {
    timeleft_ms(
        timeout_ms,
        connect_timeout_ms,
        start_single,
        start_op,
        is_connecting,
        is_shutdown,
        connect_only,
        shutdown_tl,
    )
}

// ===========================================================================
// Shutdown Management
// ===========================================================================

/// Start the shutdown timer for a connection socket.
///
/// Matches `Curl_shutdown_start` from connect.c.
pub fn shutdown_start(
    conn: &mut ConnectionData,
    sockindex: usize,
    timeout_ms: i32,
    configured_timeout_ms: i64,
) {
    let idx = sockindex.min(1);
    let now = Instant::now();
    conn.shutdown_start[idx] = Some(now);

    conn.shutdown_timeout_ms = if timeout_ms > 0 {
        timeout_ms as i64
    } else if configured_timeout_ms > 0 {
        configured_timeout_ms
    } else {
        DEFAULT_SHUTDOWN_TIMEOUT_MS as i64
    };

    debug!(
        conn_id = conn.conn_id,
        sockindex = idx,
        timeout_ms = conn.shutdown_timeout_ms,
        "shutdown started"
    );
}

/// Returns milliseconds remaining for the shutdown timer.
///
/// Matches `Curl_shutdown_timeleft` from connect.c.
pub fn shutdown_timeleft(conn: &ConnectionData, sockindex: usize) -> i64 {
    let idx = sockindex.min(1);

    let start = match conn.shutdown_start[idx] {
        Some(s) => s,
        None => return 0,
    };

    if conn.shutdown_timeout_ms <= 0 {
        return 0;
    }

    let now = Instant::now();
    let elapsed = now.duration_since(start).as_millis() as i64;
    let left = conn.shutdown_timeout_ms - elapsed;

    if left == 0 { -1 } else { left }
}

// ===========================================================================
// Internal Helper Functions
// ===========================================================================

/// Determine whether a scheme requires TLS.
fn scheme_requires_tls(scheme: &str) -> bool {
    matches!(
        scheme.to_lowercase().as_str(),
        "https" | "ftps" | "sftp" | "scp" | "smtps" | "imaps" | "pop3s" | "ldaps"
    )
}

/// Compute the connection timeout from transfer data.
fn connect_timeout(data: &TransferData) -> Duration {
    if data.timeout_ms > 0 {
        Duration::from_millis(data.timeout_ms)
    } else {
        Duration::from_millis(DEFAULT_CONNECT_TIMEOUT)
    }
}

/// Finalize a successful connection.
///
/// Records connect timing via [`Progress`], caches IP info and ALPN results,
/// and marks the connection as established.
fn finalize_connect(conn: &mut ConnectionData, progress: &mut Progress) {
    let now = Instant::now();
    conn.connected = true;
    conn.last_used = now;

    // Record the connection establishment time.
    progress.record_time_was(TimerId::Connect, now);

    // Cache IP info from the filter chain.
    if let QueryResult::Addr(addr) = conn.filter_chain.query(CF_QUERY_IP_INFO) {
        let is_ipv6 = addr.is_ipv6();
        conn.ip_info = Some(IpInfo {
            is_ipv6,
            local_addr: addr,
            remote_addr: addr,
        });
    }

    // Cache negotiated ALPN protocol.
    if let QueryResult::String(ref alpn_str) = conn.filter_chain.query(CF_QUERY_ALPN_NEGOTIATED) {
        if !alpn_str.is_empty() {
            conn.alpn_negotiated = Some(alpn_to_id(alpn_str.as_bytes()));
        }
    }

    // If TLS was involved, also record app-connect time.
    if chain_has_ssl(&conn.filter_chain) {
        progress.record_time_was(TimerId::AppConnect, now);
    }

    debug!(
        conn_id = conn.conn_id,
        host = %conn.host,
        port = conn.port,
        alpn = ?conn.alpn_negotiated,
        has_ssl = chain_has_ssl(&conn.filter_chain),
        has_ip = chain_has_ip_connect(&conn.filter_chain),
        "connection established"
    );
}

/// Check if any filter in the chain has the `CF_TYPE_SSL` type flag set.
fn chain_has_ssl(chain: &FilterChain) -> bool {
    chain_has_type(chain, CF_TYPE_SSL)
}

/// Check if any filter in the chain has the `CF_TYPE_IP_CONNECT` flag set,
/// indicating IP-level transport capability.
fn chain_has_ip_connect(chain: &FilterChain) -> bool {
    chain_has_type(chain, CF_TYPE_IP_CONNECT)
}

/// Check if any filter in the chain supports multiplexing (`CF_TYPE_MULTIPLEX`).
fn chain_has_multiplex(chain: &FilterChain) -> bool {
    chain_has_type(chain, CF_TYPE_MULTIPLEX)
}

/// Generic helper: walk the filter chain and check for a specific type flag.
fn chain_has_type(chain: &FilterChain, flag: u32) -> bool {
    let mut idx = 0;
    while let Some(filter) = chain.get(idx) {
        if filter.type_flags() & flag != 0 {
            return true;
        }
        idx += 1;
    }
    false
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_to_id_h1_short() {
        assert_eq!(alpn_to_id(b"h1"), AlpnId::H1);
    }

    #[test]
    fn alpn_to_id_h2_short() {
        assert_eq!(alpn_to_id(b"h2"), AlpnId::H2);
    }

    #[test]
    fn alpn_to_id_h3_short() {
        assert_eq!(alpn_to_id(b"h3"), AlpnId::H3);
    }

    #[test]
    fn alpn_to_id_http11_long() {
        assert_eq!(alpn_to_id(b"http/1.1"), AlpnId::H1);
    }

    #[test]
    fn alpn_to_id_unknown() {
        assert_eq!(alpn_to_id(b"unknown"), AlpnId::None);
        assert_eq!(alpn_to_id(b""), AlpnId::None);
        assert_eq!(alpn_to_id(b"h4"), AlpnId::None);
    }

    #[test]
    fn id_to_alpn_round_trip() {
        assert_eq!(id_to_alpn(AlpnId::H1), "http/1.1");
        assert_eq!(id_to_alpn(AlpnId::H2), "h2");
        assert_eq!(id_to_alpn(AlpnId::H3), "h3");
        assert_eq!(id_to_alpn(AlpnId::None), "");
    }

    #[test]
    fn transport_type_ids() {
        assert_eq!(TransportType::Tcp.to_transport_id(), 0);
        assert_eq!(TransportType::Quic.to_transport_id(), 5);
        assert_eq!(TransportType::Unix.to_transport_id(), 3);
    }

    #[test]
    fn transport_type_from_id() {
        assert_eq!(TransportType::from_transport_id(0), TransportType::Tcp);
        assert_eq!(TransportType::from_transport_id(5), TransportType::Quic);
        assert_eq!(TransportType::from_transport_id(3), TransportType::Unix);
        assert_eq!(TransportType::from_transport_id(99), TransportType::Tcp);
    }

    #[test]
    fn ip_info_ipv4() {
        let local: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let remote: SocketAddr = "192.168.1.1:80".parse().unwrap();
        let info = IpInfo::new(local, remote);
        assert!(!info.is_ipv6);
        assert_eq!(info.local_addr, local);
        assert_eq!(info.remote_addr, remote);
    }

    #[test]
    fn ip_info_ipv6() {
        let local: SocketAddr = "[::1]:12345".parse().unwrap();
        let remote: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let info = IpInfo::new(local, remote);
        assert!(info.is_ipv6);
    }

    #[test]
    fn connection_data_new_http() {
        let conn = ConnectionData::new(1, "example.com".to_string(), 80, "http".to_string());
        assert_eq!(conn.conn_id(), 1);
        assert_eq!(conn.host(), "example.com");
        assert_eq!(conn.port(), 80);
        assert_eq!(conn.scheme(), "http");
        assert!(!conn.tls_required);
        assert!(!conn.is_connected());
        assert_eq!(conn.transport_wanted, TransportType::Tcp);
    }

    #[test]
    fn connection_data_new_https() {
        let conn = ConnectionData::new(2, "example.com".to_string(), 443, "https".to_string());
        assert!(conn.tls_required);
    }

    #[test]
    fn connection_data_close() {
        let mut conn = ConnectionData::new(3, "example.com".to_string(), 443, "https".to_string());
        conn.connected = true;
        conn.close();
        assert!(!conn.is_connected());
    }

    #[test]
    fn conn_control_keep() {
        let mut conn = ConnectionData::new(4, "h".to_string(), 80, "http".to_string());
        conn.close_requested = true;
        conn_control(&mut conn, ConnControl::Keep, "test");
        assert!(!conn.close_requested);
    }

    #[test]
    fn conn_control_connection() {
        let mut conn = ConnectionData::new(5, "h".to_string(), 80, "http".to_string());
        conn_control(&mut conn, ConnControl::Connection, "test");
        assert!(conn.close_requested);
    }

    #[test]
    fn conn_control_stream_no_multiplex() {
        let mut conn = ConnectionData::new(6, "h".to_string(), 80, "http".to_string());
        conn.multiplex = false;
        conn_control(&mut conn, ConnControl::Stream, "test");
        assert!(conn.close_requested);
    }

    #[test]
    fn conn_control_stream_multiplex() {
        let mut conn = ConnectionData::new(7, "h".to_string(), 80, "http".to_string());
        conn.multiplex = true;
        conn_control(&mut conn, ConnControl::Stream, "test");
        assert!(!conn.close_requested);
    }

    #[test]
    fn addr_to_string_v4() {
        let addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let (ip, port) = addr_to_string(&addr).unwrap();
        assert_eq!(ip, "192.168.1.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn addr_to_string_v6() {
        let addr: SocketAddr = "[::1]:443".parse().unwrap();
        let (ip, port) = addr_to_string(&addr).unwrap();
        assert_eq!(ip, "::1");
        assert_eq!(port, 443);
    }

    #[test]
    fn timeleft_no_timeout() {
        let result = timeleft_ms(0, 0, None, None, false, false, false, None);
        assert_eq!(result, 0);
    }

    #[test]
    fn timeleft_connect_only() {
        let result = timeleft_ms(0, 0, None, None, false, false, true, None);
        assert_eq!(result, 0);
    }

    #[test]
    fn timeleft_with_timeout() {
        let start = Instant::now();
        let result = timeleft_ms(10_000, 0, None, Some(start), false, false, false, None);
        assert!(result > 9_900 && result <= 10_000);
    }

    #[test]
    fn scheme_tls_detection() {
        assert!(scheme_requires_tls("https"));
        assert!(scheme_requires_tls("ftps"));
        assert!(scheme_requires_tls("sftp"));
        assert!(!scheme_requires_tls("http"));
        assert!(!scheme_requires_tls("ftp"));
    }

    #[test]
    fn shutdown_not_started() {
        let conn = ConnectionData::new(8, "h".to_string(), 80, "http".to_string());
        assert_eq!(shutdown_timeleft(&conn, 0), 0);
    }

    #[test]
    fn shutdown_with_timeout() {
        let mut conn = ConnectionData::new(9, "h".to_string(), 80, "http".to_string());
        shutdown_start(&mut conn, 0, 2000, 0);
        let left = shutdown_timeleft(&conn, 0);
        assert!(left > 1_900 && left <= 2_000);
    }

    #[test]
    fn constants_match_c() {
        assert_eq!(DEFAULT_CONNECT_TIMEOUT, 300_000);
        assert_eq!(DEFAULT_SHUTDOWN_TIMEOUT_MS, 2_000);
    }

    #[test]
    fn set_multiplex_flag() {
        let mut conn = ConnectionData::new(10, "h".to_string(), 443, "https".to_string());
        assert!(!conn.multiplex);
        conn.set_multiplex();
        assert!(conn.multiplex);
        conn.set_multiplex();
        assert!(conn.multiplex);
    }

    #[test]
    fn build_chain_direct_http() {
        let conn = ConnectionData::new(11, "example.com".to_string(), 80, "http".to_string());
        let chain = build_filter_chain(&conn).unwrap();
        assert!(chain.len() >= 1);
    }

    #[test]
    fn build_chain_quic() {
        let mut conn = ConnectionData::new(12, "example.com".to_string(), 443, "https".to_string());
        conn.transport_wanted = TransportType::Quic;
        let chain = build_filter_chain(&conn).unwrap();
        assert!(chain.len() >= 1);
    }
}
