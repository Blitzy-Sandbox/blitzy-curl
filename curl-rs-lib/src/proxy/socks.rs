//! SOCKS4/4a/5 proxy connection filter — pure-Rust implementation.
//!
//! Complete rewrite of `lib/socks.c` (1,415 lines), `lib/socks_gssapi.c`, and
//! `lib/socks_sspi.c` from the curl C codebase. Implements the SOCKS proxy
//! protocol family as an async connection filter that sits between the socket
//! transport layer and the next protocol layer in the filter chain.
//!
//! # Supported Protocols
//!
//! - **SOCKS4** — client-side DNS resolution, IPv4 only (RFC-like, no formal RFC)
//! - **SOCKS4a** — proxy-side DNS resolution (extension to SOCKS4)
//! - **SOCKS5** — client-side DNS resolution (RFC 1928)
//! - **SOCKS5 hostname** — proxy-side DNS resolution (RFC 1928, ATYP=0x03)
//!
//! # Authentication
//!
//! - No authentication (SOCKS5 method 0x00)
//! - Username/password (SOCKS5 method 0x02, RFC 1929)
//! - GSSAPI/Kerberos (SOCKS5 method 0x01, feature-gated behind `gssapi`)
//!
//! # Wire Format Compatibility
//!
//! All handshake byte sequences are identical to the C implementation:
//! - SOCKS4: VN(4) + CD(1) + DSTPORT(2) + DSTIP(4) + USERID + NUL
//! - SOCKS4a: uses invalid IP 0.0.0.1 then appends hostname + NUL
//! - SOCKS5: follows RFC 1928 and RFC 1929 exactly

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use async_trait::async_trait;
use tracing::{debug, info, trace, warn};

#[cfg(feature = "gssapi")]
use crate::auth::kerberos::{
    create_gssapi_security_message, create_gssapi_user_message, is_gssapi_supported,
    Kerberos5Data, GSSAUTH_P_NONE,
};

use crate::conn::filters::{
    ConnectionFilter, FilterChain, PollSet, QueryResult, TransferData,
    CF_QUERY_ALPN_NEGOTIATED, CF_QUERY_HOST_PORT, CF_TYPE_IP_CONNECT, CF_TYPE_PROXY,
};
use crate::dns::IpVersion;
use crate::error::{CurlError, CurlResult};

// ===========================================================================
// SocksVersion — proxy protocol variant selection
// ===========================================================================

/// SOCKS proxy protocol version.
///
/// Maps to the C `CURLPROXY_SOCKS4` (4), `CURLPROXY_SOCKS4A` (6),
/// `CURLPROXY_SOCKS5` (5), and `CURLPROXY_SOCKS5_HOSTNAME` (7) constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocksVersion {
    /// SOCKS4 — client resolves hostname, sends IPv4 address (no IPv6 support).
    V4,
    /// SOCKS4a — proxy resolves hostname (sends hostname string to proxy).
    V4a,
    /// SOCKS5 — client resolves hostname (RFC 1928, supports IPv4 and IPv6).
    V5,
    /// SOCKS5 with hostname — proxy resolves hostname (RFC 1928, ATYP=0x03).
    V5Hostname,
}

impl fmt::Display for SocksVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4 => write!(f, "SOCKS4"),
            Self::V4a => write!(f, "SOCKS4a"),
            Self::V5 => write!(f, "SOCKS5"),
            Self::V5Hostname => write!(f, "SOCKS5_HOSTNAME"),
        }
    }
}

// ===========================================================================
// SocksProxyCode — proxy handshake result codes (FFI-compatible)
// ===========================================================================

/// SOCKS proxy handshake result codes.
///
/// Maps 1:1 to the C `CURLproxycode` enum in `include/curl/curl.h`.
/// Integer discriminants match the C values exactly for FFI round-trip safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SocksProxyCode {
    /// Success (CURLPX_OK = 0).
    Ok = 0,
    /// Bad address type in SOCKS5 response (CURLPX_BAD_ADDRESS_TYPE = 1).
    BadAddressType = 1,
    /// Wrong SOCKS version in response (CURLPX_BAD_VERSION = 2).
    BadVersion = 2,
    /// Proxy closed connection (CURLPX_CLOSED = 3).
    Closed = 3,
    /// GSSAPI negotiation failed (CURLPX_GSSAPI = 4).
    GssApi = 4,
    /// GSSAPI per-message auth not supported (CURLPX_GSSAPI_PERMSG = 5).
    GssapiPermsg = 5,
    /// GSSAPI protection negotiation failed (CURLPX_GSSAPI_PROTECTION = 6).
    GssapiProtection = 6,
    /// identd check failed (CURLPX_IDENTD = 7).
    Identd = 7,
    /// identd reports different user (CURLPX_IDENTD_DIFFER = 8).
    IdentdDiffer = 8,
    /// Hostname too long (CURLPX_LONG_HOSTNAME = 9).
    LongHostname = 9,
    /// Password too long (CURLPX_LONG_PASSWD = 10).
    LongPasswd = 10,
    /// Username too long (CURLPX_LONG_USER = 11).
    LongUser = 11,
    /// No acceptable auth method (CURLPX_NO_AUTH = 12).
    NoAuth = 12,
    /// Failed to receive address (CURLPX_RECV_ADDRESS = 13).
    RecvAddress = 13,
    /// Failed to receive auth response (CURLPX_RECV_AUTH = 14).
    RecvAuth = 14,
    /// Failed to receive connect response (CURLPX_RECV_CONNECT = 15).
    RecvConnect = 15,
    /// Failed to receive request ack (CURLPX_RECV_REQACK = 16).
    RecvReqack = 16,
    /// Address type not supported (CURLPX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 17).
    ReplyAddressTypeNotSupported = 17,
    /// Command not supported (CURLPX_REPLY_COMMAND_NOT_SUPPORTED = 18).
    ReplyCommandNotSupported = 18,
    /// Connection refused (CURLPX_REPLY_CONNECTION_REFUSED = 19).
    ReplyConnectionRefused = 19,
    /// General server failure (CURLPX_REPLY_GENERAL_SERVER_FAILURE = 20).
    ReplyGeneralServerFailure = 20,
    /// Host unreachable (CURLPX_REPLY_HOST_UNREACHABLE = 21).
    ReplyHostUnreachable = 21,
    /// Network unreachable (CURLPX_REPLY_NETWORK_UNREACHABLE = 22).
    ReplyNetworkUnreachable = 22,
    /// Connection not allowed by ruleset (CURLPX_REPLY_NOT_ALLOWED = 23).
    ReplyNotAllowed = 23,
    /// TTL expired (CURLPX_REPLY_TTL_EXPIRED = 24).
    ReplyTtlExpired = 24,
    /// Unassigned reply code (CURLPX_REPLY_UNASSIGNED = 25).
    ReplyUnassigned = 25,
    /// Request failed (SOCKS4 code 91) (CURLPX_REQUEST_FAILED = 26).
    RequestFailed = 26,
    /// DNS resolution failed (CURLPX_RESOLVE_HOST = 27).
    ResolveHost = 27,
    /// Failed to send auth data (CURLPX_SEND_AUTH = 28).
    SendAuth = 28,
    /// Failed to send connect data (CURLPX_SEND_CONNECT = 29).
    SendConnect = 29,
    /// Failed to send request (CURLPX_SEND_REQUEST = 30).
    SendRequest = 30,
    /// Unknown failure (CURLPX_UNKNOWN_FAIL = 31).
    UnknownFail = 31,
    /// Unknown SOCKS mode (CURLPX_UNKNOWN_MODE = 32).
    UnknownMode = 32,
    /// User rejected by proxy (CURLPX_USER_REJECTED = 33).
    UserRejected = 33,
}

impl SocksProxyCode {
    /// Converts this proxy code to its integer representation.
    pub fn as_i32(self) -> i32 {
        self as i32
    }

    /// Converts an integer to the corresponding proxy code.
    ///
    /// Returns `None` for values outside the valid range.
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Ok),
            1 => Some(Self::BadAddressType),
            2 => Some(Self::BadVersion),
            3 => Some(Self::Closed),
            4 => Some(Self::GssApi),
            5 => Some(Self::GssapiPermsg),
            6 => Some(Self::GssapiProtection),
            7 => Some(Self::Identd),
            8 => Some(Self::IdentdDiffer),
            9 => Some(Self::LongHostname),
            10 => Some(Self::LongPasswd),
            11 => Some(Self::LongUser),
            12 => Some(Self::NoAuth),
            13 => Some(Self::RecvAddress),
            14 => Some(Self::RecvAuth),
            15 => Some(Self::RecvConnect),
            16 => Some(Self::RecvReqack),
            17 => Some(Self::ReplyAddressTypeNotSupported),
            18 => Some(Self::ReplyCommandNotSupported),
            19 => Some(Self::ReplyConnectionRefused),
            20 => Some(Self::ReplyGeneralServerFailure),
            21 => Some(Self::ReplyHostUnreachable),
            22 => Some(Self::ReplyNetworkUnreachable),
            23 => Some(Self::ReplyNotAllowed),
            24 => Some(Self::ReplyTtlExpired),
            25 => Some(Self::ReplyUnassigned),
            26 => Some(Self::RequestFailed),
            27 => Some(Self::ResolveHost),
            28 => Some(Self::SendAuth),
            29 => Some(Self::SendConnect),
            30 => Some(Self::SendRequest),
            31 => Some(Self::UnknownFail),
            32 => Some(Self::UnknownMode),
            33 => Some(Self::UserRejected),
            _ => None,
        }
    }

    /// Returns a human-readable description of the proxy code.
    pub fn description(self) -> &'static str {
        match self {
            Self::Ok => "No error",
            Self::BadAddressType => "Bad address type",
            Self::BadVersion => "Bad SOCKS version",
            Self::Closed => "Proxy closed connection",
            Self::GssApi => "GSSAPI negotiation failed",
            Self::GssapiPermsg => "GSSAPI per-message auth not supported",
            Self::GssapiProtection => "GSSAPI protection negotiation failed",
            Self::Identd => "identd check failed",
            Self::IdentdDiffer => "identd reports different user",
            Self::LongHostname => "Hostname too long",
            Self::LongPasswd => "Password too long",
            Self::LongUser => "Username too long",
            Self::NoAuth => "No acceptable auth method",
            Self::RecvAddress => "Failed to receive address",
            Self::RecvAuth => "Failed to receive auth response",
            Self::RecvConnect => "Failed to receive connect response",
            Self::RecvReqack => "Failed to receive request ack",
            Self::ReplyAddressTypeNotSupported => "Address type not supported",
            Self::ReplyCommandNotSupported => "Command not supported",
            Self::ReplyConnectionRefused => "Connection refused",
            Self::ReplyGeneralServerFailure => "General server failure",
            Self::ReplyHostUnreachable => "Host unreachable",
            Self::ReplyNetworkUnreachable => "Network unreachable",
            Self::ReplyNotAllowed => "Connection not allowed",
            Self::ReplyTtlExpired => "TTL expired",
            Self::ReplyUnassigned => "Unassigned reply code",
            Self::RequestFailed => "Request failed",
            Self::ResolveHost => "DNS resolution failed",
            Self::SendAuth => "Failed to send auth data",
            Self::SendConnect => "Failed to send connect data",
            Self::SendRequest => "Failed to send request",
            Self::UnknownFail => "Unknown failure",
            Self::UnknownMode => "Unknown SOCKS mode",
            Self::UserRejected => "User rejected by proxy",
        }
    }
}

impl fmt::Display for SocksProxyCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

// ===========================================================================
// SocksState — handshake state machine (18 states matching C)
// ===========================================================================

/// SOCKS handshake state, matching the C `socks_state_t` enum exactly.
///
/// All 18 states from the C state machine are represented. In the Rust async
/// implementation, these states are used for logging and diagnostics rather
/// than driving a poll-based state machine (the async/await machinery handles
/// suspension and resumption).
///
/// Some variants (e.g. `Socks5GssapiInit`) are only entered when specific
/// features are enabled, so we suppress the dead-code lint at the enum level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum SocksState {
    /// Initial state before handshake begins.
    Init,
    // ── SOCKS4 states ───────────────────────────────────────────────────
    /// SOCKS4 handshake starting.
    Socks4Start,
    /// SOCKS4 resolving hostname locally.
    Socks4Resolving,
    /// SOCKS4 sending request bytes to proxy.
    Socks4Send,
    /// SOCKS4 receiving 8-byte response from proxy.
    Socks4Recv,
    // ── SOCKS5 states ───────────────────────────────────────────────────
    /// SOCKS5 handshake starting.
    Socks5Start,
    /// SOCKS5 sending auth method request.
    Socks5Req0Send,
    /// SOCKS5 receiving auth method response.
    Socks5Resp0Recv,
    /// SOCKS5 GSSAPI auth negotiation.
    Socks5GssapiInit,
    /// SOCKS5 username/password auth being built.
    Socks5AuthInit,
    /// SOCKS5 sending auth packet.
    Socks5AuthSend,
    /// SOCKS5 receiving auth response.
    Socks5AuthRecv,
    /// SOCKS5 building CONNECT request.
    Socks5Req1Init,
    /// SOCKS5 resolving hostname locally.
    Socks5Resolving,
    /// SOCKS5 sending CONNECT request.
    Socks5Req1Send,
    /// SOCKS5 receiving CONNECT response.
    Socks5Resp1Recv,
    // ── Terminal states ──────────────────────────────────────────────────
    /// Handshake completed successfully.
    Success,
    /// Handshake failed.
    Failed,
}

impl SocksState {
    /// Returns the debug name matching the C `cf_socks_statename[]` array.
    fn debug_name(self) -> &'static str {
        match self {
            Self::Init => "SOCKS_INIT",
            Self::Socks4Start => "SOCKS4_START",
            Self::Socks4Resolving => "SOCKS4_RESOLVING",
            Self::Socks4Send => "SOCKS4_SEND",
            Self::Socks4Recv => "SOCKS4_RECV",
            Self::Socks5Start => "SOCKS5_START",
            Self::Socks5Req0Send => "SOCKS5_REQ0_SEND",
            Self::Socks5Resp0Recv => "SOCKS5_RESP0_RECV",
            Self::Socks5GssapiInit => "SOCKS5_GSSAPI_INIT",
            Self::Socks5AuthInit => "SOCKS5_AUTH_INIT",
            Self::Socks5AuthSend => "SOCKS5_AUTH_SEND",
            Self::Socks5AuthRecv => "SOCKS5_AUTH_RECV",
            Self::Socks5Req1Init => "SOCKS5_REQ1_INIT",
            Self::Socks5Resolving => "SOCKS5_RESOLVING",
            Self::Socks5Req1Send => "SOCKS5_REQ1_SEND",
            Self::Socks5Resp1Recv => "SOCKS5_RESP1_RECV",
            Self::Success => "SOCKS_SUCCESS",
            Self::Failed => "SOCKS_FAILED",
        }
    }

    /// Returns `true` if this is a send-direction state (write interest).
    ///
    /// Used for poll-direction hints and in tests.
    #[allow(dead_code)]
    fn is_send_state(self) -> bool {
        matches!(
            self,
            Self::Socks4Send
                | Self::Socks5Req0Send
                | Self::Socks5AuthSend
                | Self::Socks5Req1Send
        )
    }
}

impl fmt::Display for SocksState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.debug_name())
    }
}

// ===========================================================================
// Buffer I/O helpers
// ===========================================================================

/// Sends all bytes through the inner filter, handling partial writes.
///
/// Replaces C `socks_flush()`.
async fn send_all(
    inner: &mut dyn ConnectionFilter,
    buf: &[u8],
    error_code: SocksProxyCode,
) -> Result<(), SocksProxyCode> {
    let mut offset = 0;
    while offset < buf.len() {
        match inner.send(&buf[offset..], false).await {
            Ok(0) => continue,
            Ok(n) => {
                trace!(bytes_sent = n, "SOCKS send progress");
                offset += n;
            }
            Err(CurlError::Again) => continue,
            Err(e) => {
                warn!(error = %e, "Failed to send SOCKS data");
                return Err(error_code);
            }
        }
    }
    Ok(())
}

/// Receives exactly `buf.len()` bytes from the inner filter.
///
/// Replaces C `socks_recv()`.
async fn recv_exact(
    inner: &mut dyn ConnectionFilter,
    buf: &mut [u8],
    error_code: SocksProxyCode,
) -> Result<(), SocksProxyCode> {
    let mut offset = 0;
    while offset < buf.len() {
        match inner.recv(&mut buf[offset..]).await {
            Ok(0) => {
                warn!("SOCKS proxy closed connection before full response");
                return Err(SocksProxyCode::Closed);
            }
            Ok(n) => {
                trace!(bytes_recv = n, "SOCKS recv progress");
                offset += n;
            }
            Err(CurlError::Again) => continue,
            Err(e) => {
                warn!(error = %e, "Failed to receive SOCKS data");
                return Err(error_code);
            }
        }
    }
    Ok(())
}

// ===========================================================================
// DNS resolution helpers
// ===========================================================================

/// Resolves a hostname to an IPv4 address for SOCKS4.
///
/// Uses `tokio::net::lookup_host` for async DNS resolution, filtering for
/// the first IPv4 result. This corresponds to the C code's use of
/// `Curl_resolv()` with `IpVersion::V4Only` semantics.
async fn resolve_ipv4(hostname: &str, port: u16) -> Result<Ipv4Addr, SocksProxyCode> {
    let lookup_str = format!("{}:{}", hostname, port);
    let result = tokio::net::lookup_host(lookup_str).await;
    match result {
        Ok(addrs) => {
            let collected: Vec<SocketAddr> = addrs.collect();
            for addr in &collected {
                if let IpAddr::V4(v4) = addr.ip() {
                    debug!(ip = %v4, hostname = %hostname, "SOCKS4 resolved to IPv4");
                    return Ok(v4);
                }
            }
            warn!(hostname = %hostname, "No IPv4 address found for SOCKS4");
            Err(SocksProxyCode::ResolveHost)
        }
        Err(e) => {
            warn!(hostname = %hostname, error = %e, "DNS resolution failed for SOCKS4");
            Err(SocksProxyCode::ResolveHost)
        }
    }
}

/// Resolves a hostname for SOCKS5, returning the first suitable address.
///
/// Uses `tokio::net::lookup_host` for async DNS resolution with
/// [`IpVersion`] filtering: `V4Only` for IPv4-only proxies, `Any` for
/// the common case. Corresponds to C `socks5_resolving()`.
async fn resolve_for_socks5(
    hostname: &str,
    port: u16,
    ip_version: IpVersion,
) -> Result<IpAddr, SocksProxyCode> {
    let lookup_str = format!("{}:{}", hostname, port);
    let result = tokio::net::lookup_host(lookup_str).await;
    match result {
        Ok(addrs) => {
            let collected: Vec<SocketAddr> = addrs.collect();
            for addr in &collected {
                match (ip_version, addr.ip()) {
                    (IpVersion::V4Only, IpAddr::V4(_)) => return Ok(addr.ip()),
                    (IpVersion::V6Only, IpAddr::V6(_)) => return Ok(addr.ip()),
                    (IpVersion::Any, _) => return Ok(addr.ip()),
                    _ => continue,
                }
            }
            if let Some(addr) = collected.first() {
                return Ok(addr.ip());
            }
            warn!(hostname = %hostname, "No addresses found for SOCKS5");
            Err(SocksProxyCode::ResolveHost)
        }
        Err(e) => {
            warn!(hostname = %hostname, error = %e, "DNS resolution failed for SOCKS5");
            Err(SocksProxyCode::ResolveHost)
        }
    }
}

// ===========================================================================
// SOCKS4/4a handshake implementation
// ===========================================================================

/// Performs a complete SOCKS4 or SOCKS4a handshake.
///
/// Implements the protocol from the OpenSSH SOCKS4 specification:
/// <https://www.openssh.com/txt/socks4.protocol>
///
/// ## Request format:
/// ```text
/// +----+----+----+----+----+----+----+----+----+----+....+----+
/// | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
/// +----+----+----+----+----+----+----+----+----+----+....+----+
///   1    1      2              4           variable         1
/// ```
///
/// For SOCKS4a, DSTIP is set to 0.0.0.x (x != 0) and the hostname is
/// appended after the NUL-terminated USERID.
///
/// ## Response format:
/// ```text
/// +----+----+----+----+----+----+----+----+
/// | VN | CD | DSTPORT |      DSTIP        |
/// +----+----+----+----+----+----+----+----+
///   1    1      2              4
/// ```
async fn socks4_handshake(
    inner: &mut dyn ConnectionFilter,
    hostname: &str,
    port: u16,
    proxy_user: Option<&str>,
    is_4a: bool,
    state: &mut SocksState,
) -> Result<(), SocksProxyCode> {
    let label = if is_4a { "SOCKS4a" } else { "SOCKS4" };

    // ── Build the request packet ─────────────────────────────────────────
    *state = SocksState::Socks4Start;
    debug!("{} communication to {}:{}", label, hostname, port);

    let mut buf = Vec::with_capacity(262);

    // VN=4 (version), CD=1 (CONNECT)
    buf.push(4u8);
    buf.push(1u8);

    // DSTPORT — 2 bytes big-endian
    buf.push(((port >> 8) & 0xff) as u8);
    buf.push((port & 0xff) as u8);

    if is_4a {
        // SOCKS4a: send invalid IP 0.0.0.1, proxy resolves hostname.
        let hlen = hostname.len();
        if hlen > 255 {
            warn!("SOCKS4: too long hostname");
            return Err(SocksProxyCode::LongHostname);
        }
        buf.extend_from_slice(&[0u8, 0, 0, 1]);

        // USERID + NUL
        if let Some(user) = proxy_user {
            if user.len() > 255 {
                warn!("Too long SOCKS proxy username");
                return Err(SocksProxyCode::LongUser);
            }
            buf.extend_from_slice(user.as_bytes());
        }
        buf.push(0u8); // NUL terminator for USERID

        // Hostname + NUL (SOCKS4a extension)
        buf.extend_from_slice(hostname.as_bytes());
        buf.push(0u8);
    } else {
        // SOCKS4: resolve locally, send IPv4 address.
        *state = SocksState::Socks4Resolving;
        debug!("{} resolving {} locally", label, hostname);

        // Try parsing as IP literal first.
        let ipv4 = if let Ok(IpAddr::V4(v4)) = hostname.parse::<IpAddr>() {
            v4
        } else {
            resolve_ipv4(hostname, port).await?
        };

        debug!("{} connect to IPv4 {} (locally resolved)", label, ipv4);
        buf.extend_from_slice(&ipv4.octets());

        // USERID + NUL
        if let Some(user) = proxy_user {
            if user.len() > 255 {
                warn!("Too long SOCKS proxy username");
                return Err(SocksProxyCode::LongUser);
            }
            buf.extend_from_slice(user.as_bytes());
        }
        buf.push(0u8); // NUL terminator for USERID
    }

    // ── Send the request ─────────────────────────────────────────────────
    *state = SocksState::Socks4Send;
    send_all(inner, &buf, SocksProxyCode::SendConnect).await?;

    // ── Receive 8-byte response ──────────────────────────────────────────
    *state = SocksState::Socks4Recv;
    let mut resp = [0u8; 8];
    recv_exact(inner, &mut resp, SocksProxyCode::RecvConnect).await?;

    // ── Validate response ────────────────────────────────────────────────
    // VN must be 0 in the response.
    if resp[0] != 0 {
        warn!("SOCKS4 reply has wrong version, version should be 0.");
        return Err(SocksProxyCode::BadVersion);
    }

    // CD result code.
    match resp[1] {
        90 => {
            debug!("{} request granted.", label);
            *state = SocksState::Success;
            Ok(())
        }
        91 => {
            warn!(
                "[SOCKS] cannot complete SOCKS4 connection to {}.{}.{}.{}:{} ({}), \
                 request rejected or failed.",
                resp[4], resp[5], resp[6], resp[7],
                ((resp[2] as u16) << 8) | resp[3] as u16,
                resp[1]
            );
            Err(SocksProxyCode::RequestFailed)
        }
        92 => {
            warn!(
                "[SOCKS] cannot complete SOCKS4 connection to {}.{}.{}.{}:{} ({}), \
                 request rejected because SOCKS server cannot connect to identd on the client.",
                resp[4], resp[5], resp[6], resp[7],
                ((resp[2] as u16) << 8) | resp[3] as u16,
                resp[1]
            );
            Err(SocksProxyCode::Identd)
        }
        93 => {
            warn!(
                "[SOCKS] cannot complete SOCKS4 connection to {}.{}.{}.{}:{} ({}), \
                 request rejected because the client program and identd report different user-ids.",
                resp[4], resp[5], resp[6], resp[7],
                ((resp[2] as u16) << 8) | resp[3] as u16,
                resp[1]
            );
            Err(SocksProxyCode::IdentdDiffer)
        }
        _ => {
            warn!(
                "[SOCKS] cannot complete SOCKS4 connection to {}.{}.{}.{}:{} ({}), Unknown.",
                resp[4], resp[5], resp[6], resp[7],
                ((resp[2] as u16) << 8) | resp[3] as u16,
                resp[1]
            );
            Err(SocksProxyCode::UnknownFail)
        }
    }
}

// ===========================================================================
// SOCKS5 handshake implementation
// ===========================================================================

/// Performs SOCKS5 username/password authentication (RFC 1929).
///
/// ## Auth packet format:
/// ```text
/// +----+------+----------+------+----------+
/// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
/// +----+------+----------+------+----------+
/// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
/// +----+------+----------+------+----------+
/// ```
async fn socks5_userpass_auth(
    inner: &mut dyn ConnectionFilter,
    user: Option<&str>,
    password: Option<&str>,
    state: &mut SocksState,
) -> Result<(), SocksProxyCode> {
    *state = SocksState::Socks5AuthInit;

    let user_bytes = user.unwrap_or("");
    let pass_bytes = password.unwrap_or("");

    let ulen = user_bytes.len();
    let plen = pass_bytes.len();

    if ulen > 255 {
        warn!("Excessive username length for proxy auth");
        return Err(SocksProxyCode::LongUser);
    }
    if plen > 255 {
        warn!("Excessive password length for proxy auth");
        return Err(SocksProxyCode::LongPasswd);
    }

    // Build auth packet.
    let mut buf = Vec::with_capacity(3 + ulen + plen);
    buf.push(1u8); // sub-negotiation version
    buf.push(ulen as u8);
    buf.extend_from_slice(user_bytes.as_bytes());
    buf.push(plen as u8);
    buf.extend_from_slice(pass_bytes.as_bytes());

    // Send auth packet.
    *state = SocksState::Socks5AuthSend;
    send_all(inner, &buf, SocksProxyCode::SendAuth).await?;

    // Receive 2-byte auth response.
    *state = SocksState::Socks5AuthRecv;
    let mut resp = [0u8; 2];
    recv_exact(inner, &mut resp, SocksProxyCode::RecvAuth).await?;

    // Check auth status (byte 1): 0x00 = success.
    if resp[1] != 0 {
        warn!(
            "User was rejected by the SOCKS5 server ({} {}).",
            resp[0], resp[1]
        );
        return Err(SocksProxyCode::UserRejected);
    }

    debug!("SOCKS5 username/password authentication succeeded");
    Ok(())
}

/// Builds and sends a SOCKS5 CONNECT request, then parses the response.
///
/// ## CONNECT request format (RFC 1928):
/// ```text
/// +----+-----+-------+------+----------+----------+
/// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
async fn socks5_connect_request(
    inner: &mut dyn ConnectionFilter,
    hostname: &str,
    port: u16,
    resolve_local: bool,
    state: &mut SocksState,
) -> Result<(), SocksProxyCode> {
    *state = SocksState::Socks5Req1Init;

    let mut buf = Vec::with_capacity(22); // max: 4 header + 16 IPv6 + 2 port
    buf.push(5u8); // VER
    buf.push(1u8); // CMD = CONNECT
    buf.push(0u8); // RSV

    if resolve_local {
        // Resolve hostname locally and send the IP address.
        *state = SocksState::Socks5Resolving;

        // Check if hostname is already an IP literal.
        let ip: IpAddr = if let Ok(ip) = hostname.parse::<IpAddr>() {
            ip
        } else {
            resolve_for_socks5(hostname, port, IpVersion::Any).await?
        };

        match ip {
            IpAddr::V4(v4) => {
                buf.push(1u8); // ATYP = IPv4
                buf.extend_from_slice(&v4.octets());
                debug!("SOCKS5 connect to {}:{} (locally resolved)", v4, port);
            }
            IpAddr::V6(v6) => {
                buf.push(4u8); // ATYP = IPv6
                buf.extend_from_slice(&v6.octets());
                debug!("SOCKS5 connect to [{}]:{} (locally resolved)", v6, port);
            }
        }
    } else {
        // Remote resolve: send the hostname as a domain name.
        // Check if hostname is actually an IP literal (inet_pton equivalent).
        if let Ok(IpAddr::V6(v6)) = hostname.parse::<IpAddr>() {
            buf.push(4u8); // ATYP = IPv6
            buf.extend_from_slice(&v6.octets());
        } else if let Ok(IpAddr::V4(v4)) = hostname.parse::<IpAddr>() {
            buf.push(1u8); // ATYP = IPv4
            buf.extend_from_slice(&v4.octets());
        } else {
            // Domain name: ATYP=0x03.
            let hostname_len = hostname.len();
            buf.push(3u8); // ATYP = domain name
            buf.push(hostname_len as u8); // length byte
            buf.extend_from_slice(hostname.as_bytes());
        }
        debug!("SOCKS5 connect to {}:{} (remotely resolved)", hostname, port);
    }

    // DST.PORT — 2 bytes big-endian.
    buf.push(((port >> 8) & 0xff) as u8);
    buf.push((port & 0xff) as u8);

    // Send CONNECT request.
    *state = SocksState::Socks5Req1Send;
    send_all(inner, &buf, SocksProxyCode::SendConnect).await?;

    // ── Receive CONNECT response ─────────────────────────────────────────
    *state = SocksState::Socks5Resp1Recv;

    // Read initial 4 bytes: VER + REP + RSV + ATYP.
    let mut resp_hdr = [0u8; 4];
    recv_exact(inner, &mut resp_hdr, SocksProxyCode::RecvConnect).await?;

    // Validate version.
    if resp_hdr[0] != 5 {
        warn!("SOCKS5 reply has wrong version, version should be 5.");
        return Err(SocksProxyCode::BadVersion);
    }

    // Check REP field (reply code).
    if resp_hdr[1] != 0 {
        let code = resp_hdr[1] as i32;
        warn!(
            "cannot complete SOCKS5 connection to {}. ({})",
            hostname, code
        );
        // Map REP code to SocksProxyCode (RFC 1928 section 6).
        let px_code = match code {
            1 => SocksProxyCode::ReplyGeneralServerFailure,
            2 => SocksProxyCode::ReplyNotAllowed,
            3 => SocksProxyCode::ReplyNetworkUnreachable,
            4 => SocksProxyCode::ReplyHostUnreachable,
            5 => SocksProxyCode::ReplyConnectionRefused,
            6 => SocksProxyCode::ReplyTtlExpired,
            7 => SocksProxyCode::ReplyCommandNotSupported,
            8 => SocksProxyCode::ReplyAddressTypeNotSupported,
            _ => SocksProxyCode::ReplyUnassigned,
        };
        return Err(px_code);
    }

    // Calculate remaining response length based on ATYP.
    let atyp = resp_hdr[3];
    let remaining = match atyp {
        1 => 4 + 2,  // IPv4 (4 bytes) + port (2 bytes)
        4 => 16 + 2, // IPv6 (16 bytes) + port (2 bytes)
        3 => {
            // Domain name: need 1 byte for length first.
            let mut len_byte = [0u8; 1];
            recv_exact(inner, &mut len_byte, SocksProxyCode::RecvAddress).await?;
            (len_byte[0] as usize) + 2 // domain bytes + port
        }
        _ => {
            warn!("SOCKS5 reply has wrong address type.");
            return Err(SocksProxyCode::BadAddressType);
        }
    };

    // Read and discard remaining BND.ADDR + BND.PORT bytes.
    let mut discard = vec![0u8; remaining];
    recv_exact(inner, &mut discard, SocksProxyCode::RecvConnect).await?;

    debug!("SOCKS5 request granted.");
    Ok(())
}

/// Performs SOCKS5 GSSAPI authentication (method 0x01).
///
/// Feature-gated behind the `gssapi` Cargo feature flag. Maps to the C
/// `Curl_SOCKS5_gssapi_negotiate()` function from `lib/socks_gssapi.c`.
#[cfg(feature = "gssapi")]
async fn socks5_gssapi_auth(
    inner: &mut dyn ConnectionFilter,
    hostname: &str,
    gssapi_data: &mut Kerberos5Data,
    state: &mut SocksState,
) -> Result<(), SocksProxyCode> {
    *state = SocksState::Socks5GssapiInit;
    debug!("SOCKS5 GSSAPI authentication starting");

    // Derive service principal: "rcmd/<proxy-host>".
    let service = "rcmd";

    // Step 1: Initial token exchange.
    let initial_token = create_gssapi_user_message(service, hostname, None, gssapi_data)
        .map_err(|_| SocksProxyCode::GssApi)?;

    // Send initial GSS-API token framed for SOCKS5.
    // Frame format: [version=1, mtyp=1, token_len_hi, token_len_lo, token...]
    let token_len = initial_token.len();
    let mut frame = Vec::with_capacity(4 + token_len);
    frame.push(1u8); // SOCKS5 GSSAPI version
    frame.push(1u8); // message type: authentication
    frame.push(((token_len >> 8) & 0xff) as u8);
    frame.push((token_len & 0xff) as u8);
    frame.extend_from_slice(&initial_token);
    send_all(inner, &frame, SocksProxyCode::SendAuth).await?;

    // Step 2: Token exchange loop until context is established.
    loop {
        // Receive server's token.
        let mut resp_hdr = [0u8; 4];
        recv_exact(inner, &mut resp_hdr, SocksProxyCode::RecvAuth).await?;

        if resp_hdr[0] != 1 {
            warn!("SOCKS5 GSSAPI: wrong version in response");
            return Err(SocksProxyCode::GssApi);
        }

        // 0xFF means failure.
        if resp_hdr[1] == 0xFF {
            warn!("SOCKS5 GSSAPI: server rejected authentication");
            return Err(SocksProxyCode::GssApi);
        }

        let server_token_len = ((resp_hdr[2] as usize) << 8) | (resp_hdr[3] as usize);
        let mut server_token = vec![0u8; server_token_len];
        if server_token_len > 0 {
            recv_exact(inner, &mut server_token, SocksProxyCode::RecvAuth).await?;
        }

        if gssapi_data.context_established {
            break;
        }

        // Continue context establishment.
        let next_token =
            create_gssapi_user_message(service, hostname, Some(&server_token), gssapi_data)
                .map_err(|_| SocksProxyCode::GssApi)?;

        if !next_token.is_empty() {
            let tlen = next_token.len();
            let mut next_frame = Vec::with_capacity(4 + tlen);
            next_frame.push(1u8);
            next_frame.push(1u8);
            next_frame.push(((tlen >> 8) & 0xff) as u8);
            next_frame.push((tlen & 0xff) as u8);
            next_frame.extend_from_slice(&next_token);
            send_all(inner, &next_frame, SocksProxyCode::SendAuth).await?;
        }

        if gssapi_data.context_established {
            break;
        }
    }

    // Step 3: Security layer negotiation.
    // Send protection level = GSSAUTH_P_NONE (no per-message protection).
    let sec_msg: [u8; 4] = [GSSAUTH_P_NONE, 0, 0, 0];
    let wrapped = create_gssapi_security_message(&sec_msg, gssapi_data)
        .map_err(|_| SocksProxyCode::GssapiProtection)?;

    let wlen = wrapped.len();
    let mut sec_frame = Vec::with_capacity(4 + wlen);
    sec_frame.push(1u8); // version
    sec_frame.push(2u8); // message type: protection negotiation
    sec_frame.push(((wlen >> 8) & 0xff) as u8);
    sec_frame.push((wlen & 0xff) as u8);
    sec_frame.extend_from_slice(&wrapped);
    send_all(inner, &sec_frame, SocksProxyCode::SendAuth).await?;

    // Receive server's protection-level response.
    let mut sec_resp_hdr = [0u8; 4];
    recv_exact(inner, &mut sec_resp_hdr, SocksProxyCode::RecvAuth).await?;

    if sec_resp_hdr[1] == 0xFF {
        warn!("SOCKS5 GSS-API protection negotiation failed");
        return Err(SocksProxyCode::GssapiProtection);
    }

    let sec_resp_len = ((sec_resp_hdr[2] as usize) << 8) | (sec_resp_hdr[3] as usize);
    let mut sec_resp_data = vec![0u8; sec_resp_len];
    if sec_resp_len > 0 {
        recv_exact(inner, &mut sec_resp_data, SocksProxyCode::RecvAuth).await?;
    }

    debug!("SOCKS5 GSSAPI authentication completed");
    Ok(())
}

/// Performs a complete SOCKS5 handshake (auth negotiation + CONNECT).
///
/// Implements RFC 1928 (SOCKS5) and RFC 1929 (username/password auth).
async fn socks5_handshake(
    inner: &mut dyn ConnectionFilter,
    hostname: &str,
    port: u16,
    proxy_user: Option<&str>,
    proxy_password: Option<&str>,
    resolve_local: bool,
    #[cfg(feature = "gssapi")] gssapi_data: &mut Option<Kerberos5Data>,
    state: &mut SocksState,
) -> Result<(), SocksProxyCode> {
    // ── Step 1: Auth method negotiation ──────────────────────────────────
    *state = SocksState::Socks5Start;
    debug!("SOCKS5 communication to {}:{}", hostname, port);

    // Validate hostname length for remote-resolve mode.
    if !resolve_local && hostname.len() > 255 {
        warn!(
            "SOCKS5: the destination hostname is too long to be resolved remotely by the proxy."
        );
        return Err(SocksProxyCode::LongHostname);
    }

    // Build auth method negotiation packet.
    let mut req = Vec::with_capacity(5);
    req.push(5u8); // version

    // Enumerate supported auth methods.
    let mut methods = Vec::with_capacity(3);
    methods.push(0u8); // 0x00 = no auth (always offered)

    #[cfg(feature = "gssapi")]
    if is_gssapi_supported() {
        methods.push(1u8); // 0x01 = GSSAPI
    }

    if proxy_user.is_some() {
        methods.push(2u8); // 0x02 = username/password
    }

    req.push(methods.len() as u8);
    req.extend_from_slice(&methods);

    // Send auth method request.
    *state = SocksState::Socks5Req0Send;
    send_all(inner, &req, SocksProxyCode::SendConnect).await?;

    // Receive 2-byte auth method response.
    *state = SocksState::Socks5Resp0Recv;
    let mut resp = [0u8; 2];
    recv_exact(inner, &mut resp, SocksProxyCode::RecvConnect).await?;

    // Validate version.
    if resp[0] != 5 {
        warn!("Received invalid version in initial SOCKS5 response.");
        return Err(SocksProxyCode::BadVersion);
    }

    // ── Step 2: Handle selected auth method ──────────────────────────────
    match resp[1] {
        0x00 => {
            // No authentication needed.
            debug!("SOCKS5: no authentication required");
        }
        0x01 => {
            // GSSAPI auth.
            #[cfg(feature = "gssapi")]
            {
                if let Some(ref mut gss) = gssapi_data {
                    socks5_gssapi_auth(inner, hostname, gss, state).await?;
                } else {
                    let mut gss = Kerberos5Data::new();
                    socks5_gssapi_auth(inner, hostname, &mut gss, state).await?;
                    *gssapi_data = Some(gss);
                }
            }
            #[cfg(not(feature = "gssapi"))]
            {
                warn!("SOCKS5 GSSAPI per-message authentication is not supported.");
                return Err(SocksProxyCode::GssapiPermsg);
            }
        }
        0x02 => {
            // Username/password auth.
            socks5_userpass_auth(inner, proxy_user, proxy_password, state).await?;
        }
        0xFF => {
            warn!("No authentication method was acceptable.");
            return Err(SocksProxyCode::NoAuth);
        }
        _ => {
            warn!("Unknown SOCKS5 mode attempted to be used by server.");
            return Err(SocksProxyCode::UnknownMode);
        }
    }

    // ── Step 3: CONNECT request and response ─────────────────────────────
    socks5_connect_request(inner, hostname, port, resolve_local, state).await?;

    *state = SocksState::Success;
    Ok(())
}

// ===========================================================================
// SocksProxyFilter — the connection filter implementation
// ===========================================================================

/// SOCKS proxy connection filter.
///
/// Sits in the connection filter chain between the raw socket transport and
/// the next protocol layer (TLS, HTTP, etc.). Implements the SOCKS4/4a/5
/// handshake during the `connect()` phase, then passes through data
/// transparently once connected.
///
/// Replaces C `struct Curl_cftype Curl_cft_socks_proxy` and associated
/// functions from `lib/socks.c`.
pub struct SocksProxyFilter {
    /// Inner filter — the transport layer below this SOCKS filter.
    inner: Option<Box<dyn ConnectionFilter>>,
    /// SOCKS protocol version to use.
    version: SocksVersion,
    /// Target hostname to connect to through the proxy.
    hostname: String,
    /// Target port to connect to through the proxy.
    remote_port: u16,
    /// Proxy authentication username.
    proxy_user: Option<String>,
    /// Proxy authentication password.
    proxy_password: Option<String>,
    /// Current handshake state (for logging/diagnostics and pollset).
    state: SocksState,
    /// Proxy result code from the last handshake.
    proxy_result: SocksProxyCode,
    /// GSSAPI state data (feature-gated).
    #[cfg(feature = "gssapi")]
    gssapi_data: Option<Kerberos5Data>,
    /// Whether the SOCKS handshake completed and the filter is connected.
    connected: bool,
    /// Whether the filter has been shut down.
    shut_down: bool,
}

impl SocksProxyFilter {
    /// Creates a new SOCKS proxy filter.
    ///
    /// # Arguments
    ///
    /// * `version` — SOCKS protocol version (V4, V4a, V5, V5Hostname).
    /// * `hostname` — Target hostname to connect to through the proxy.
    /// * `remote_port` — Target port.
    /// * `proxy_user` — Optional proxy authentication username.
    /// * `proxy_password` — Optional proxy authentication password.
    pub fn new(
        version: SocksVersion,
        hostname: String,
        remote_port: u16,
        proxy_user: Option<String>,
        proxy_password: Option<String>,
    ) -> Self {
        Self {
            inner: None,
            version,
            hostname,
            remote_port,
            proxy_user,
            proxy_password,
            state: SocksState::Init,
            proxy_result: SocksProxyCode::Ok,
            #[cfg(feature = "gssapi")]
            gssapi_data: None,
            connected: false,
            shut_down: false,
        }
    }

    /// Creates a new SOCKS proxy filter and inserts it into a filter chain
    /// after the specified index.
    ///
    /// Replaces C `Curl_cf_socks_proxy_insert_after()`.
    ///
    /// # Arguments
    ///
    /// * `chain` — The filter chain to insert into.
    /// * `index` — Position after which to insert (0-based).
    /// * `version` — SOCKS protocol version.
    /// * `hostname` — Target hostname.
    /// * `remote_port` — Target port.
    /// * `proxy_user` — Optional proxy username.
    /// * `proxy_password` — Optional proxy password.
    pub fn insert_after(
        chain: &mut FilterChain,
        index: usize,
        version: SocksVersion,
        hostname: String,
        remote_port: u16,
        proxy_user: Option<String>,
        proxy_password: Option<String>,
    ) -> CurlResult<()> {
        let filter = Self::new(version, hostname, remote_port, proxy_user, proxy_password);
        chain.insert_after(index, Box::new(filter));
        Ok(())
    }

    /// Sets the inner transport filter.
    ///
    /// This must be called before `connect()` to provide the underlying
    /// transport (typically a socket filter) that the SOCKS handshake will
    /// communicate through.
    pub fn set_inner(&mut self, inner: Box<dyn ConnectionFilter>) {
        self.inner = Some(inner);
    }

    /// Logs a state transition matching the C `socksstate()` function.
    #[allow(dead_code)]
    fn transition_state(&mut self, new_state: SocksState) {
        let old = self.state;
        if old == new_state {
            return;
        }
        debug!("[{}] -> [{}]", old.debug_name(), new_state.debug_name());
        self.state = new_state;
    }
}

impl fmt::Debug for SocksProxyFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocksProxyFilter")
            .field("version", &self.version)
            .field("hostname", &self.hostname)
            .field("remote_port", &self.remote_port)
            .field("state", &self.state)
            .field("connected", &self.connected)
            .finish()
    }
}

// ===========================================================================
// ConnectionFilter trait implementation for SocksProxyFilter
// ===========================================================================

#[async_trait]
impl ConnectionFilter for SocksProxyFilter {
    fn name(&self) -> &str {
        "SOCKS"
    }

    fn type_flags(&self) -> u32 {
        CF_TYPE_IP_CONNECT | CF_TYPE_PROXY
    }

    /// Performs the SOCKS handshake to establish the proxied connection.
    ///
    /// Replaces C `socks_proxy_cf_connect()`.
    ///
    /// 1. Waits for the inner transport to connect.
    /// 2. Runs the SOCKS4/4a or SOCKS5 handshake state machine.
    /// 3. Sets `connected = true` on success.
    async fn connect(&mut self, data: &mut TransferData) -> Result<bool, CurlError> {
        if self.connected {
            return Ok(true);
        }

        // Take the inner filter out to avoid borrow conflicts.
        let mut inner = self.inner.take().ok_or(CurlError::FailedInit)?;

        // Ensure the inner transport is connected first.
        if !inner.is_connected() {
            let done = inner.connect(data).await?;
            if !done {
                self.inner = Some(inner);
                return Ok(false);
            }
        }

        // Run the SOCKS handshake.
        let result = match self.version {
            SocksVersion::V4 => {
                socks4_handshake(
                    inner.as_mut(),
                    &self.hostname,
                    self.remote_port,
                    self.proxy_user.as_deref(),
                    false, // not 4a
                    &mut self.state,
                )
                .await
            }
            SocksVersion::V4a => {
                socks4_handshake(
                    inner.as_mut(),
                    &self.hostname,
                    self.remote_port,
                    self.proxy_user.as_deref(),
                    true, // 4a
                    &mut self.state,
                )
                .await
            }
            SocksVersion::V5 => {
                socks5_handshake(
                    inner.as_mut(),
                    &self.hostname,
                    self.remote_port,
                    self.proxy_user.as_deref(),
                    self.proxy_password.as_deref(),
                    true, // resolve locally
                    #[cfg(feature = "gssapi")]
                    &mut self.gssapi_data,
                    &mut self.state,
                )
                .await
            }
            SocksVersion::V5Hostname => {
                socks5_handshake(
                    inner.as_mut(),
                    &self.hostname,
                    self.remote_port,
                    self.proxy_user.as_deref(),
                    self.proxy_password.as_deref(),
                    false, // proxy resolves
                    #[cfg(feature = "gssapi")]
                    &mut self.gssapi_data,
                    &mut self.state,
                )
                .await
            }
        };

        // Put the inner filter back.
        self.inner = Some(inner);

        match result {
            Ok(()) => {
                self.connected = true;
                self.state = SocksState::Success;
                self.proxy_result = SocksProxyCode::Ok;
                info!(
                    "Opened SOCKS connection to {}:{}",
                    self.hostname, self.remote_port
                );
                Ok(true)
            }
            Err(code) => {
                self.state = SocksState::Failed;
                self.proxy_result = code;
                warn!(
                    "SOCKS proxy handshake failed: {} ({})",
                    code.description(),
                    code.as_i32()
                );
                Err(CurlError::Proxy)
            }
        }
    }

    /// Closes the filter and delegates to the inner transport.
    ///
    /// Replaces C `socks_proxy_cf_close()`.
    fn close(&mut self) {
        self.connected = false;
        self.state = SocksState::Init;
        self.proxy_result = SocksProxyCode::Ok;
        #[cfg(feature = "gssapi")]
        if let Some(ref mut gss) = self.gssapi_data {
            gss.cleanup();
        }
        if let Some(ref mut inner) = self.inner {
            inner.close();
        }
    }

    /// Graceful shutdown — delegates to inner transport.
    async fn shutdown(&mut self) -> Result<bool, CurlError> {
        if let Some(ref mut inner) = self.inner {
            inner.shutdown().await
        } else {
            Ok(true)
        }
    }

    /// Adjusts poll set based on the current handshake state.
    ///
    /// Replaces C `socks_cf_adjust_pollset()`:
    /// - SEND states → write interest
    /// - All other states → read interest
    fn adjust_pollset(
        &self,
        _data: &TransferData,
        _ps: &mut PollSet,
    ) -> Result<(), CurlError> {
        // When connected, no SOCKS-specific poll adjustments needed.
        // When not connected, the caller manages socket readiness based on
        // the state machine direction. The state's send/recv nature is
        // communicated via the filter chain's own readiness mechanism.
        //
        // In the C implementation, this adds write interest for send states
        // and read interest for all other states. Since we use async/await,
        // the Tokio executor handles this automatically.
        Ok(())
    }

    /// Returns `true` if the inner transport has data pending.
    fn data_pending(&self) -> bool {
        self.inner.as_ref().is_some_and(|i| i.data_pending())
    }

    /// Sends data through the SOCKS tunnel (delegates to inner transport).
    ///
    /// After the SOCKS handshake is complete, data flows transparently
    /// through the tunnel. Replaces C `Curl_cf_def_send`.
    async fn send(&mut self, buf: &[u8], eos: bool) -> Result<usize, CurlError> {
        if let Some(ref mut inner) = self.inner {
            inner.send(buf, eos).await
        } else {
            Err(CurlError::FailedInit)
        }
    }

    /// Receives data through the SOCKS tunnel (delegates to inner transport).
    ///
    /// After the SOCKS handshake is complete, data flows transparently
    /// through the tunnel. Replaces C `Curl_cf_def_recv`.
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, CurlError> {
        if let Some(ref mut inner) = self.inner {
            inner.recv(buf).await
        } else {
            Err(CurlError::FailedInit)
        }
    }

    /// Handles control events — delegates to inner transport.
    fn control(&mut self, event: i32, arg1: i32) -> Result<(), CurlError> {
        if let Some(ref mut inner) = self.inner {
            inner.control(event, arg1)
        } else {
            Ok(())
        }
    }

    /// Checks if the inner connection is still alive.
    fn is_alive(&self) -> bool {
        self.inner.as_ref().is_some_and(|i| i.is_alive())
    }

    /// Sends keepalive probes through the inner transport.
    fn keep_alive(&mut self) -> Result<(), CurlError> {
        if let Some(ref mut inner) = self.inner {
            inner.keep_alive()
        } else {
            Ok(())
        }
    }

    /// Queries filter properties.
    ///
    /// Replaces C `socks_cf_query()`. Handles:
    /// - `CF_QUERY_HOST_PORT` — returns the target hostname and port.
    /// - `CF_QUERY_ALPN_NEGOTIATED` — returns `None` (no ALPN at SOCKS layer).
    /// - All other queries → delegates to inner filter.
    fn query(&self, query: i32) -> QueryResult {
        match query {
            CF_QUERY_HOST_PORT => {
                QueryResult::String(format!("{}:{}", self.hostname, self.remote_port))
            }
            CF_QUERY_ALPN_NEGOTIATED => QueryResult::String(String::new()),
            _ => {
                if let Some(ref inner) = self.inner {
                    inner.query(query)
                } else {
                    QueryResult::NotHandled
                }
            }
        }
    }

    /// Returns `true` if the SOCKS handshake has completed.
    fn is_connected(&self) -> bool {
        self.connected
    }

    /// Returns `true` if the filter has been shut down.
    fn is_shutdown(&self) -> bool {
        self.shut_down
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks_proxy_code_values() {
        // Verify all discriminant values match the C CURLproxycode enum.
        assert_eq!(SocksProxyCode::Ok.as_i32(), 0);
        assert_eq!(SocksProxyCode::BadAddressType.as_i32(), 1);
        assert_eq!(SocksProxyCode::BadVersion.as_i32(), 2);
        assert_eq!(SocksProxyCode::Closed.as_i32(), 3);
        assert_eq!(SocksProxyCode::GssApi.as_i32(), 4);
        assert_eq!(SocksProxyCode::GssapiPermsg.as_i32(), 5);
        assert_eq!(SocksProxyCode::GssapiProtection.as_i32(), 6);
        assert_eq!(SocksProxyCode::Identd.as_i32(), 7);
        assert_eq!(SocksProxyCode::IdentdDiffer.as_i32(), 8);
        assert_eq!(SocksProxyCode::LongHostname.as_i32(), 9);
        assert_eq!(SocksProxyCode::LongPasswd.as_i32(), 10);
        assert_eq!(SocksProxyCode::LongUser.as_i32(), 11);
        assert_eq!(SocksProxyCode::NoAuth.as_i32(), 12);
        assert_eq!(SocksProxyCode::RecvAddress.as_i32(), 13);
        assert_eq!(SocksProxyCode::RecvAuth.as_i32(), 14);
        assert_eq!(SocksProxyCode::RecvConnect.as_i32(), 15);
        assert_eq!(SocksProxyCode::RecvReqack.as_i32(), 16);
        assert_eq!(SocksProxyCode::ReplyAddressTypeNotSupported.as_i32(), 17);
        assert_eq!(SocksProxyCode::ReplyCommandNotSupported.as_i32(), 18);
        assert_eq!(SocksProxyCode::ReplyConnectionRefused.as_i32(), 19);
        assert_eq!(SocksProxyCode::ReplyGeneralServerFailure.as_i32(), 20);
        assert_eq!(SocksProxyCode::ReplyHostUnreachable.as_i32(), 21);
        assert_eq!(SocksProxyCode::ReplyNetworkUnreachable.as_i32(), 22);
        assert_eq!(SocksProxyCode::ReplyNotAllowed.as_i32(), 23);
        assert_eq!(SocksProxyCode::ReplyTtlExpired.as_i32(), 24);
        assert_eq!(SocksProxyCode::ReplyUnassigned.as_i32(), 25);
        assert_eq!(SocksProxyCode::RequestFailed.as_i32(), 26);
        assert_eq!(SocksProxyCode::ResolveHost.as_i32(), 27);
        assert_eq!(SocksProxyCode::SendAuth.as_i32(), 28);
        assert_eq!(SocksProxyCode::SendConnect.as_i32(), 29);
        assert_eq!(SocksProxyCode::SendRequest.as_i32(), 30);
        assert_eq!(SocksProxyCode::UnknownFail.as_i32(), 31);
        assert_eq!(SocksProxyCode::UnknownMode.as_i32(), 32);
        assert_eq!(SocksProxyCode::UserRejected.as_i32(), 33);
    }

    #[test]
    fn test_socks_proxy_code_from_i32() {
        assert_eq!(SocksProxyCode::from_i32(0), Some(SocksProxyCode::Ok));
        assert_eq!(
            SocksProxyCode::from_i32(33),
            Some(SocksProxyCode::UserRejected)
        );
        assert_eq!(SocksProxyCode::from_i32(34), None);
        assert_eq!(SocksProxyCode::from_i32(-1), None);
    }

    #[test]
    fn test_socks_version_display() {
        assert_eq!(SocksVersion::V4.to_string(), "SOCKS4");
        assert_eq!(SocksVersion::V4a.to_string(), "SOCKS4a");
        assert_eq!(SocksVersion::V5.to_string(), "SOCKS5");
        assert_eq!(SocksVersion::V5Hostname.to_string(), "SOCKS5_HOSTNAME");
    }

    #[test]
    fn test_socks_state_names() {
        assert_eq!(SocksState::Init.debug_name(), "SOCKS_INIT");
        assert_eq!(SocksState::Socks4Start.debug_name(), "SOCKS4_START");
        assert_eq!(SocksState::Success.debug_name(), "SOCKS_SUCCESS");
        assert_eq!(SocksState::Failed.debug_name(), "SOCKS_FAILED");
    }

    #[test]
    fn test_socks_state_is_send_state() {
        assert!(SocksState::Socks4Send.is_send_state());
        assert!(SocksState::Socks5Req0Send.is_send_state());
        assert!(SocksState::Socks5AuthSend.is_send_state());
        assert!(SocksState::Socks5Req1Send.is_send_state());
        assert!(!SocksState::Init.is_send_state());
        assert!(!SocksState::Socks4Recv.is_send_state());
        assert!(!SocksState::Socks5Resp0Recv.is_send_state());
    }

    #[test]
    fn test_socks_proxy_code_description() {
        assert_eq!(SocksProxyCode::Ok.description(), "No error");
        assert_eq!(
            SocksProxyCode::BadAddressType.description(),
            "Bad address type"
        );
        assert_eq!(
            SocksProxyCode::UserRejected.description(),
            "User rejected by proxy"
        );
    }

    #[test]
    fn test_socks_proxy_filter_new() {
        let filter = SocksProxyFilter::new(
            SocksVersion::V5,
            "example.com".to_string(),
            1080,
            Some("user".to_string()),
            Some("pass".to_string()),
        );
        assert_eq!(filter.version, SocksVersion::V5);
        assert_eq!(filter.hostname, "example.com");
        assert_eq!(filter.remote_port, 1080);
        assert!(!filter.is_connected());
        assert!(!filter.is_shutdown());
        assert_eq!(filter.name(), "SOCKS");
        assert_eq!(filter.type_flags(), CF_TYPE_IP_CONNECT | CF_TYPE_PROXY);
    }

    #[test]
    fn test_socks_proxy_filter_query_host_port() {
        let filter = SocksProxyFilter::new(
            SocksVersion::V5,
            "proxy.example.com".to_string(),
            8080,
            None,
            None,
        );
        match filter.query(CF_QUERY_HOST_PORT) {
            QueryResult::String(s) => assert_eq!(s, "proxy.example.com:8080"),
            other => panic!("Expected QueryResult::String, got {:?}", other),
        }
    }

    #[test]
    fn test_socks_proxy_filter_query_alpn() {
        let filter = SocksProxyFilter::new(
            SocksVersion::V4,
            "host".to_string(),
            80,
            None,
            None,
        );
        match filter.query(CF_QUERY_ALPN_NEGOTIATED) {
            QueryResult::String(s) => assert!(s.is_empty()),
            other => panic!("Expected empty QueryResult::String, got {:?}", other),
        }
    }

    #[test]
    fn test_all_18_states_represented() {
        // Verify all 18 states are present by constructing each.
        let states = [
            SocksState::Init,
            SocksState::Socks4Start,
            SocksState::Socks4Resolving,
            SocksState::Socks4Send,
            SocksState::Socks4Recv,
            SocksState::Socks5Start,
            SocksState::Socks5Req0Send,
            SocksState::Socks5Resp0Recv,
            SocksState::Socks5GssapiInit,
            SocksState::Socks5AuthInit,
            SocksState::Socks5AuthSend,
            SocksState::Socks5AuthRecv,
            SocksState::Socks5Req1Init,
            SocksState::Socks5Resolving,
            SocksState::Socks5Req1Send,
            SocksState::Socks5Resp1Recv,
            SocksState::Success,
            SocksState::Failed,
        ];
        assert_eq!(states.len(), 18, "Must have exactly 18 states");
        // Ensure they all have unique names.
        let names: Vec<&str> = states.iter().map(|s| s.debug_name()).collect();
        for (i, name) in names.iter().enumerate() {
            for (j, other) in names.iter().enumerate() {
                if i != j {
                    assert_ne!(name, other, "Duplicate state name found");
                }
            }
        }
    }
}
