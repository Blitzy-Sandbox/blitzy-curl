// curl-rs/src/callbacks/socket.rs
//
// Rust rewrite of src/tool_cb_soc.c and src/tool_cb_soc.h.
//
// Implements the CURLOPT_OPENSOCKETFUNCTION callback for creating sockets
// with optional MPTCP (Multipath TCP) support on Linux. Uses the `socket2`
// crate for safe socket creation — zero `unsafe` blocks.
//
// The callback is registered when the user requests MPTCP (--mptcp). On
// Linux, it replaces the default TCP protocol with MPTCP (protocol 262) so
// the kernel establishes a Multipath TCP connection when available. If the
// kernel does not support MPTCP, the implementation falls back to a standard
// TCP socket transparently.
//
// On non-Linux platforms, MPTCP is not available and a standard socket is
// always created with the original protocol parameters.
//
// SPDX-License-Identifier: curl

use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Linux kernel constant for the MPTCP protocol number.
///
/// Defined in `<netinet/in.h>` on Linux kernels >= 5.6 as `IPPROTO_MPTCP`.
/// When the header does not define it (older toolchains), curl's C source
/// hard-codes the value 262. We mirror that here for all platforms so the
/// constant is available for comparison even when not on Linux.
pub const IPPROTO_MPTCP: i32 = 262;

/// Standard TCP protocol number (IPPROTO_TCP from POSIX / IANA).
pub const IPPROTO_TCP: i32 = 6;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Socket purpose indicator for the open-socket callback.
///
/// Maps 1:1 to the C `curlsocktype` enum from `<curl/curl.h>`:
///
/// ```c
/// typedef enum {
///   CURLSOCKTYPE_IPCXN,  /* socket created for a specific IP connection */
///   CURLSOCKTYPE_ACCEPT, /* socket created by accept() call */
///   CURLSOCKTYPE_LAST    /* never use */
/// } curlsocktype;
/// ```
///
/// `CURLSOCKTYPE_LAST` is a sentinel and is not represented here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurlSockType {
    /// Socket created for a specific IP connection (`CURLSOCKTYPE_IPCXN`).
    IpConnection,
    /// Socket created by an `accept()` call (`CURLSOCKTYPE_ACCEPT`).
    Accept,
}

/// Socket address information passed to the open-socket callback.
///
/// Rust-idiomatic equivalent of the C `struct curl_sockaddr`:
///
/// ```c
/// struct curl_sockaddr {
///   int family;        // AF_INET, AF_INET6, …
///   int socktype;      // SOCK_STREAM, SOCK_DGRAM, …
///   int protocol;      // IPPROTO_TCP, IPPROTO_UDP, …
///   unsigned int addrlen;
///   struct sockaddr addr;
/// };
/// ```
///
/// The `addr` field uses `std::net::SocketAddr` instead of the raw C
/// `struct sockaddr`, providing a safe, Rust-friendly representation of
/// the resolved endpoint address.
#[derive(Debug, Clone)]
pub struct CurlSockAddr {
    /// Address family (e.g., `libc::AF_INET` = 2, `libc::AF_INET6` = 10).
    pub family: i32,
    /// Socket type (e.g., `libc::SOCK_STREAM` = 1 for TCP).
    pub socktype: i32,
    /// Protocol number (e.g., [`IPPROTO_TCP`] = 6).
    pub protocol: i32,
    /// Length of the address structure in bytes.
    pub addrlen: u32,
    /// Resolved endpoint address (replaces C `struct sockaddr`).
    pub addr: SocketAddr,
}

// ---------------------------------------------------------------------------
// Socket Creation
// ---------------------------------------------------------------------------

/// Creates a socket with optional MPTCP upgrade.
///
/// This is the low-level socket factory used by
/// [`tool_socket_open_mptcp_cb`]. It returns a [`socket2::Socket`] that the
/// caller can further configure (e.g., set socket options) before converting
/// to a `std::net::TcpStream` for Tokio integration.
///
/// # MPTCP Logic
///
/// On **Linux** when `use_mptcp` is `true` *and* the requested protocol is
/// [`IPPROTO_TCP`]:
///
/// 1. Attempt `socket(family, type, IPPROTO_MPTCP)` — protocol 262.
/// 2. If that fails (e.g., `EPROTONOSUPPORT` on kernels < 5.6, or
///    `ENOPROTOOPT` when the MPTCP module is not loaded), fall back to
///    `socket(family, type, IPPROTO_TCP)`.
///
/// On **non-Linux** platforms the `use_mptcp` flag is ignored; a standard
/// socket is always created with the original protocol.
///
/// # Errors
///
/// Returns `io::Error` if socket creation fails entirely (both MPTCP and
/// fallback on Linux, or the single attempt on other platforms).
pub fn create_socket(addr: &CurlSockAddr, use_mptcp: bool) -> io::Result<Socket> {
    let domain = Domain::from(addr.family);
    let sock_type = Type::from(addr.socktype);

    // --- Linux MPTCP path ---------------------------------------------------
    #[cfg(target_os = "linux")]
    {
        if use_mptcp && addr.protocol == IPPROTO_TCP {
            // Attempt MPTCP socket creation first.
            let mptcp_protocol = Protocol::from(IPPROTO_MPTCP);
            match Socket::new(domain, sock_type, Some(mptcp_protocol)) {
                Ok(socket) => return Ok(socket),
                Err(_mptcp_err) => {
                    // MPTCP not available on this kernel / configuration.
                    // Fall through to standard TCP below.
                }
            }
        }
    }

    // --- Non-Linux: suppress unused-variable warning for `use_mptcp` --------
    #[cfg(not(target_os = "linux"))]
    {
        let _ = use_mptcp;
    }

    // --- Standard socket with original protocol -----------------------------
    let protocol = Protocol::from(addr.protocol);
    Socket::new(domain, sock_type, Some(protocol))
}

/// Converts a [`socket2::Socket`] into a [`std::net::TcpStream`].
///
/// This function performs a safe ownership transfer of the underlying file
/// descriptor (Unix) or socket handle (Windows) without any `unsafe` code.
///
/// The returned `TcpStream` is in a pre-connection state — the caller is
/// expected to connect it afterward (e.g., via Tokio's
/// `TcpStream::from_std`).
fn socket_to_tcp_stream(socket: Socket) -> std::net::TcpStream {
    // On Unix: Socket → OwnedFd → TcpStream (safe conversion chain).
    // On Windows: Socket → OwnedSocket → TcpStream (safe conversion chain).
    //
    // socket2 0.5.x implements `From<Socket> for OwnedFd` on Unix and
    // `From<Socket> for OwnedSocket` on Windows. The standard library
    // implements `From<OwnedFd> for TcpStream` and
    // `From<OwnedSocket> for TcpStream`, completing the chain.
    #[cfg(unix)]
    {
        let owned_fd: std::os::unix::io::OwnedFd = socket.into();
        std::net::TcpStream::from(owned_fd)
    }
    #[cfg(windows)]
    {
        let owned_socket: std::os::windows::io::OwnedSocket = socket.into();
        std::net::TcpStream::from(owned_socket)
    }
}

/// CURLOPT_OPENSOCKETFUNCTION callback for MPTCP-aware socket creation.
///
/// Rust rewrite of the C function `tool_socket_open_mptcp_cb` from
/// `src/tool_cb_soc.c`. This callback is registered on the easy handle
/// when the user enables MPTCP support (e.g., via `--mptcp`).
///
/// # Behavior
///
/// | Platform | Purpose = `IpConnection` & protocol = TCP | Other cases          |
/// |----------|-------------------------------------------|----------------------|
/// | Linux    | Try MPTCP → fallback TCP                  | Standard socket      |
/// | Non-Linux| Standard socket                           | Standard socket      |
///
/// The returned `TcpStream` is an unconnected socket ready for the
/// connection layer to call `connect()` on. In the async path, it is
/// typically converted to a `tokio::net::TcpStream` via
/// `TcpStream::from_std()`.
///
/// # Errors
///
/// Returns `io::Error` if socket creation fails completely, which maps to
/// `CURL_SOCKET_BAD` at the FFI boundary.
///
/// # Examples
///
/// ```rust,no_run
/// use curl_rs::callbacks::socket::*;
/// use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
///
/// let addr = CurlSockAddr {
///     family: 2,       // AF_INET
///     socktype: 1,     // SOCK_STREAM
///     protocol: IPPROTO_TCP,
///     addrlen: 16,
///     addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443)),
/// };
///
/// let tcp_stream = tool_socket_open_mptcp_cb(CurlSockType::IpConnection, &addr);
/// // On Linux with MPTCP support: returns an MPTCP socket.
/// // On Linux without MPTCP: returns a standard TCP socket.
/// // On non-Linux: returns a standard TCP socket.
/// ```
pub fn tool_socket_open_mptcp_cb(
    purpose: CurlSockType,
    addr: &CurlSockAddr,
) -> io::Result<std::net::TcpStream> {
    // MPTCP upgrade is only attempted when the callback is invoked for an
    // IP connection socket AND the requested protocol is TCP. All other
    // cases (e.g., accept sockets, UDP) use the original protocol.
    let use_mptcp = purpose == CurlSockType::IpConnection && addr.protocol == IPPROTO_TCP;

    let socket = create_socket(addr, use_mptcp)?;

    Ok(socket_to_tcp_stream(socket))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    /// Helper to build a CurlSockAddr for AF_INET / SOCK_STREAM / TCP.
    fn make_tcp_v4_addr() -> CurlSockAddr {
        CurlSockAddr {
            family: 2,       // AF_INET
            socktype: 1,     // SOCK_STREAM
            protocol: IPPROTO_TCP,
            addrlen: 16,
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)),
        }
    }

    /// Helper to build a CurlSockAddr for AF_INET6 / SOCK_STREAM / TCP.
    fn make_tcp_v6_addr() -> CurlSockAddr {
        CurlSockAddr {
            family: 10,      // AF_INET6
            socktype: 1,     // SOCK_STREAM
            protocol: IPPROTO_TCP,
            addrlen: 28,
            addr: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8080, 0, 0)),
        }
    }

    #[test]
    fn test_constants() {
        assert_eq!(IPPROTO_MPTCP, 262);
        assert_eq!(IPPROTO_TCP, 6);
    }

    #[test]
    fn test_curl_sock_type_equality() {
        assert_eq!(CurlSockType::IpConnection, CurlSockType::IpConnection);
        assert_ne!(CurlSockType::IpConnection, CurlSockType::Accept);
        assert_eq!(CurlSockType::Accept, CurlSockType::Accept);
    }

    #[test]
    fn test_curl_sock_addr_clone() {
        let addr = make_tcp_v4_addr();
        let cloned = addr.clone();
        assert_eq!(cloned.family, addr.family);
        assert_eq!(cloned.socktype, addr.socktype);
        assert_eq!(cloned.protocol, addr.protocol);
        assert_eq!(cloned.addrlen, addr.addrlen);
        assert_eq!(cloned.addr, addr.addr);
    }

    #[test]
    fn test_create_socket_tcp_v4_no_mptcp() {
        let addr = make_tcp_v4_addr();
        let result = create_socket(&addr, false);
        assert!(result.is_ok(), "Standard TCP socket creation should succeed");
    }

    #[test]
    fn test_create_socket_tcp_v6_no_mptcp() {
        let addr = make_tcp_v6_addr();
        let result = create_socket(&addr, false);
        assert!(result.is_ok(), "Standard TCP v6 socket creation should succeed");
    }

    #[test]
    fn test_create_socket_tcp_v4_with_mptcp() {
        // On Linux: may succeed with MPTCP or fall back to TCP.
        // On non-Linux: MPTCP flag is ignored, standard TCP socket created.
        let addr = make_tcp_v4_addr();
        let result = create_socket(&addr, true);
        assert!(
            result.is_ok(),
            "Socket creation should succeed (MPTCP or TCP fallback)"
        );
    }

    #[test]
    fn test_callback_ip_connection_tcp() {
        let addr = make_tcp_v4_addr();
        let result = tool_socket_open_mptcp_cb(CurlSockType::IpConnection, &addr);
        assert!(
            result.is_ok(),
            "Callback should return Ok for IpConnection + TCP"
        );
    }

    #[test]
    fn test_callback_accept_purpose() {
        let addr = make_tcp_v4_addr();
        // Accept purpose should NOT trigger MPTCP, just standard socket.
        let result = tool_socket_open_mptcp_cb(CurlSockType::Accept, &addr);
        assert!(
            result.is_ok(),
            "Callback should return Ok for Accept purpose"
        );
    }

    #[test]
    fn test_callback_non_tcp_protocol() {
        // UDP-like protocol — should not trigger MPTCP.
        let addr = CurlSockAddr {
            family: 2,       // AF_INET
            socktype: 2,     // SOCK_DGRAM
            protocol: 17,    // IPPROTO_UDP
            addrlen: 16,
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)),
        };
        let result = create_socket(&addr, true);
        // MPTCP should NOT be attempted for UDP.
        assert!(
            result.is_ok(),
            "Non-TCP socket creation should succeed with original protocol"
        );
    }

    #[test]
    fn test_callback_ipv6_tcp() {
        let addr = make_tcp_v6_addr();
        let result = tool_socket_open_mptcp_cb(CurlSockType::IpConnection, &addr);
        assert!(
            result.is_ok(),
            "Callback should return Ok for IPv6 IpConnection + TCP"
        );
    }

    #[test]
    fn test_curl_sock_type_debug() {
        // Ensure Debug is implemented.
        let debug_str = format!("{:?}", CurlSockType::IpConnection);
        assert!(debug_str.contains("IpConnection"));
    }

    #[test]
    fn test_curl_sock_addr_debug() {
        let addr = make_tcp_v4_addr();
        let debug_str = format!("{:?}", addr);
        assert!(debug_str.contains("family"));
    }
}
