//! The bottom transport filter — TCP / UDP / UNIX socket I/O plus the SOCKS
//! proxy connection-filter wrapper. The Rust rewrite of curl's
//! `lib/cf-socket.c` (+ `lib/cf-socket.h`) and the SOCKS filter portion of
//! `lib/socks.c` (L1198-1415).
//!
//! # Role in the chain
//!
//! This module owns the *innermost* (bottom) filters of the connection-filter
//! chain — the ones that hold the actual operating-system socket and perform
//! raw byte reads and writes. Every other filter (TLS, HAProxy, HTTP CONNECT,
//! SOCKS, Happy-Eyeballs) sits *above* one of these and ultimately forwards its
//! `send`/`recv` down to here. The filters implemented here are:
//!
//! * **TCP** (`Curl_cft_tcp`) — a connected `tokio::net::TcpStream`.
//! * **UDP / QUIC** (`Curl_cft_udp`) — a `tokio::net::UdpSocket`; for QUIC it is
//!   `connect()`-ed to the peer so it has a default destination, supplying the
//!   datagram substrate consumed by the HTTP/3 (`quinn`) layer above.
//! * **UNIX** (`Curl_cft_unix`) — a `tokio::net::UnixStream` realizing
//!   `CURLOPT_UNIX_SOCKET_PATH` / `CURLOPT_ABSTRACT_UNIX_SOCKET` (the
//!   `UnixSockets` capability, version bit `1 << 19`).
//! * **TCP-ACCEPT** (`Curl_cft_tcp_accept`) — a `tokio::net::TcpListener` whose
//!   `accept()` realizes FTP *active* mode (the client listens, the server
//!   connects back).
//! * **SOCKS** (`Curl_cft_socks_proxy`, from `socks.c`) — wraps the transport
//!   below: it connects that transport to the SOCKS proxy, then runs the SOCKS4
//!   / SOCKS4a / SOCKS5 / SOCKS5h handshake (delegating to the pure engine in
//!   [`crate::proxy::socks`]) and afterwards is a transparent pass-through.
//!
//! # The great async collapse (AAP §0.4.4 / §0.7)
//!
//! curl's transport layer is an elaborate, hand-rolled non-blocking state
//! machine: `cf_socket_open` creates a non-blocking socket, `do_connect` issues
//! `connect()` and tolerates `EINPROGRESS`, the caller re-enters while polling
//! the fd for writability (`SOCKET_WRITABLE`), and `verifyconnect` reads
//! `getsockopt(SO_ERROR)` to confirm the connect actually completed. **All of
//! that dissolves into a single `await`**: `TcpSocket::connect(addr).await`
//! resolves only once the connection is verified by the OS (its completion *is*
//! the `SO_ERROR == 0` check), and Tokio's reactor supplies the readiness that
//! curl polled for by hand. Consequently the C `adjust_pollset` slot has **no
//! analog** here and is intentionally omitted everywhere it appears in the C
//! oracle; the same applies to the `SOCKS*_ST_*` send/recv state machine, which
//! is replaced by awaiting [`crate::proxy::socks::socks_handshake`].
//!
//! # Memory safety (AAP §0.7.1) — ABSOLUTE
//!
//! This module is `#![forbid(unsafe_code)]`: **zero** `unsafe`. Every socket is
//! created and driven through the safe `tokio::net` and `socket2` APIs. There
//! are no raw `libc::socket`/`bind`/`connect`/`setsockopt` calls, no
//! `curl_socket_t` fd juggling, no `fd_set`, and no raw `pollfd`. The C
//! `getsockopt(SO_ERROR)` verifyconnect and the `SOCKET_WRITABLE` poll loop are
//! replaced by awaiting Tokio connect futures; option setting and pre-connect
//! binding use `socket2::Socket`/`SockRef` and `tokio::net::TcpSocket`, which
//! are themselves safe wrappers. Sockets close via `Drop` (replacing
//! `socket_close`), so there is no manual `free`.

#![forbid(unsafe_code)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::task::noop_waker_ref;
use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};

use crate::conn::filters::{
    BoxFuture, CfQuery, CfQueryResult, CfState, ConnectionFilter, FilterChain, FilterData,
    IpQuadruple, CF_CTRL_CONN_INFO_UPDATE, CF_CTRL_DATA_SETUP, CF_CTRL_FORGET_SOCKET,
    CF_TYPE_IP_CONNECT,
};
use crate::error::{CurlError, Result};
use crate::util::sendf;
use crate::util::timeval::{curlx_now, curlx_ptimediff_ms, CurlTime};

// `tokio::net::UnixStream` and the abstract-socket helpers are UNIX-only; the
// whole UNIX-domain transport (variant, target, filter, constructor) is gated
// behind `cfg(unix)` accordingly. The AAP build matrix is Linux + macOS, both of
// which are UNIX, so this is always available on the supported targets.
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
#[cfg(unix)]
use tokio::net::UnixStream;

// The SOCKS connection-filter wrapper (boundary #1, the SOCKS portion of
// `lib/socks.c`) is compiled only when the `proxy` capability is enabled (curl's
// `CURL_DISABLE_PROXY` gate). It bridges the trait-based filter `recv`/`send`
// into the `AsyncRead`/`AsyncWrite` the pure SOCKS engine consumes, so it pulls
// in the async-IO traits, future/pin plumbing, and the proxy/DNS types.
#[cfg(feature = "proxy")]
use crate::conn::filters::CF_TYPE_PROXY;
#[cfg(feature = "proxy")]
use crate::dns::{DnsCache, IpVersion};
#[cfg(feature = "proxy")]
use crate::proxy::socks::{socks_handshake, to_curlcode, CurlProxyCode, SocksParams};
#[cfg(feature = "proxy")]
use crate::proxy::CurlProxyType;
#[cfg(feature = "proxy")]
use std::pin::Pin;
#[cfg(feature = "proxy")]
use tokio::io::{AsyncRead, AsyncWrite};

// =============================================================================
// Transport-type constants (C: `urldata.h` `TRNSPRT_*`)
// =============================================================================

/// No transport selected (C: `TRNSPRT_NONE`).
pub const TRNSPRT_NONE: u8 = 0;
/// TCP stream transport (C: `TRNSPRT_TCP`).
pub const TRNSPRT_TCP: u8 = 3;
/// UDP datagram transport (C: `TRNSPRT_UDP`).
pub const TRNSPRT_UDP: u8 = 4;
/// QUIC transport — a connected UDP socket used as the HTTP/3 datagram
/// substrate (C: `TRNSPRT_QUIC`).
pub const TRNSPRT_QUIC: u8 = 5;
/// UNIX-domain socket transport (C: `TRNSPRT_UNIX`).
pub const TRNSPRT_UNIX: u8 = 6;

/// Sentinel returned by the [`CfQuery::Socket`] query when no live socket is
/// held — the safe-Rust stand-in for C's `CURL_SOCKET_BAD`. The live socket is
/// modelled as an [`Option`] ([`SocketFilter::sock`]); this constant only
/// surfaces at the query boundary where the contract is an `i64` fd value
/// (`-1` meaning "no socket"), matching [`CfQueryResult::Socket`].
pub const SOCKET_BAD: i64 = -1;

/// Default accept timeout for the TCP-accept (FTP active-mode) filter, in
/// milliseconds — C's `DEFAULT_ACCEPT_TIMEOUT` (`lib/ftp.h`: 60000 == one
/// minute).
pub const DEFAULT_ACCEPT_TIMEOUT_MS: i64 = 60_000;

// =============================================================================
// The live socket — the safe replacement for `curl_socket_t sock`
// =============================================================================

/// The live operating-system socket owned by a [`SocketFilter`].
///
/// This is the safe-Rust replacement for C's `curl_socket_t sock` field plus
/// the `CURL_SOCKET_BAD` sentinel: an absent socket is modelled as
/// [`SocketFilter::sock`] being [`None`], never a magic file descriptor. Each
/// variant wraps the appropriate Tokio socket type, so all I/O goes through
/// safe, reactor-driven, non-blocking APIs. Dropping a `Transport` closes the
/// underlying fd (replacing C's explicit `socket_close`).
#[derive(Debug)]
pub enum Transport {
    /// A connected TCP stream (C: a `TRNSPRT_TCP` socket).
    Tcp(TcpStream),
    /// A UDP socket — connected to the peer for `TRNSPRT_QUIC`, otherwise merely
    /// bound (C: a `TRNSPRT_UDP` / `TRNSPRT_QUIC` socket).
    Udp(UdpSocket),
    /// A connected UNIX-domain stream (C: a `TRNSPRT_UNIX` socket).
    #[cfg(unix)]
    Unix(UnixStream),
}

impl Transport {
    /// The locally-bound address of this socket, if it has one and the platform
    /// can report it (mirrors C's `getsockname` via `set_local_ip`). UNIX-domain
    /// sockets have no IP address, so they report [`None`].
    fn local_addr(&self) -> Option<SocketAddr> {
        match self {
            Transport::Tcp(s) => s.local_addr().ok(),
            Transport::Udp(s) => s.local_addr().ok(),
            #[cfg(unix)]
            Transport::Unix(_) => None,
        }
    }

    /// The connected peer address of this socket, if any (mirrors C's
    /// `getpeername`). UNIX-domain sockets have no IP peer, so they report
    /// [`None`].
    fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            Transport::Tcp(s) => s.peer_addr().ok(),
            Transport::Udp(s) => s.peer_addr().ok(),
            #[cfg(unix)]
            Transport::Unix(_) => None,
        }
    }

    /// The raw file descriptor backing this socket (UNIX only), for the
    /// [`CfQuery::Socket`] query and for `CF_CTRL_FORGET_SOCKET` hand-off. This
    /// only *reads* the descriptor (via the safe [`AsRawFd`] trait); it does not
    /// transfer ownership.
    #[cfg(unix)]
    fn raw_fd(&self) -> RawFd {
        match self {
            Transport::Tcp(s) => s.as_raw_fd(),
            Transport::Udp(s) => s.as_raw_fd(),
            Transport::Unix(s) => s.as_raw_fd(),
        }
    }

    /// Relinquish the descriptor *without closing it* — the safe-Rust
    /// realization of C's `CF_CTRL_FORGET_SOCKET` (which sets `ctx->sock =
    /// CURL_SOCKET_BAD` after the fd has been handed to another subsystem, e.g.
    /// FTP moving the data socket). Converting the Tokio socket back to a
    /// `std` socket and then to a raw fd via [`IntoRawFd`] leaks the descriptor
    /// out of Rust's ownership (no `Drop`-close), exactly matching the C
    /// behavior where the new owner is responsible for closing it. Returns the
    /// fd, or [`None`] if the conversion failed.
    #[cfg(unix)]
    fn into_forgotten_fd(self) -> Option<RawFd> {
        match self {
            Transport::Tcp(s) => s.into_std().ok().map(IntoRawFd::into_raw_fd),
            Transport::Udp(s) => s.into_std().ok().map(IntoRawFd::into_raw_fd),
            Transport::Unix(s) => s.into_std().ok().map(IntoRawFd::into_raw_fd),
        }
    }
}

// =============================================================================
// Connect target — the safe replacement for `struct Curl_sockaddr_ex`
// =============================================================================

/// A single resolved endpoint the socket filter connects to — the safe mirror
/// of C's `struct Curl_sockaddr_ex` (`cf-socket.h`).
///
/// The socket filter is created *per candidate address*; Happy-Eyeballs
/// (`crate::conn::happy_eyeballs`, when authored) races several of these and
/// promotes the winner. Each filter therefore connects to exactly one target.
#[derive(Debug, Clone)]
pub enum SocketTarget {
    /// An IP endpoint for TCP / UDP / QUIC.
    Inet(SocketAddr),
    /// A UNIX-domain socket path (`CURLOPT_UNIX_SOCKET_PATH` /
    /// `CURLOPT_ABSTRACT_UNIX_SOCKET`).
    #[cfg(unix)]
    Unix(UnixTarget),
}

/// A UNIX-domain socket destination (`cfg(unix)` only).
///
/// For a filesystem socket, `name` is the path. For a Linux *abstract* socket
/// (`CURLOPT_ABSTRACT_UNIX_SOCKET`, whose C representation is a `sun_path`
/// beginning with a NUL byte) `abstract_namespace` is `true` and `name` holds
/// the abstract name *without* the leading NUL.
#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct UnixTarget {
    /// The filesystem path, or — when `abstract_namespace` is set — the abstract
    /// name without its leading NUL byte.
    pub name: std::path::PathBuf,
    /// Whether `name` denotes a Linux abstract-namespace socket.
    pub abstract_namespace: bool,
}

#[cfg(unix)]
impl UnixTarget {
    /// A filesystem-path UNIX-domain target.
    #[must_use]
    pub fn path<P: Into<std::path::PathBuf>>(path: P) -> Self {
        Self {
            name: path.into(),
            abstract_namespace: false,
        }
    }

    /// A Linux abstract-namespace UNIX-domain target (`name` excludes the
    /// leading NUL).
    #[must_use]
    pub fn abstract_name<P: Into<std::path::PathBuf>>(name: P) -> Self {
        Self {
            name: name.into(),
            abstract_namespace: true,
        }
    }
}

// =============================================================================
// Socket options + local-binding configuration (`data->set.*` slices)
// =============================================================================

/// TCP socket options applied around connect — the slice of `data->set` that
/// `tcpnodelay` (`cf-socket.c` L79) and `tcpkeepalive` (L114) read.
///
/// curl applies `TCP_NODELAY` by default and only enables keepalive when
/// `CURLOPT_TCP_KEEPALIVE` is set, in which case it programs the idle /
/// interval / count from `CURLOPT_TCP_KEEPIDLE` / `KEEPINTVL` / `KEEPCNT`.
#[derive(Debug, Clone)]
pub struct SocketOptions {
    /// Whether to set `TCP_NODELAY` (C: `CURLOPT_TCP_NODELAY`; curl's default is
    /// **on**).
    pub tcp_nodelay: bool,
    /// Whether to enable `SO_KEEPALIVE` (C: `CURLOPT_TCP_KEEPALIVE`; default
    /// off).
    pub tcp_keepalive: bool,
    /// Keepalive idle time in **seconds** (C: `CURLOPT_TCP_KEEPIDLE`, default
    /// 60).
    pub tcp_keepidle: u32,
    /// Keepalive probe interval in **seconds** (C: `CURLOPT_TCP_KEEPINTVL`,
    /// default 60).
    pub tcp_keepintvl: u32,
    /// Keepalive probe count before the connection is dropped (C:
    /// `CURLOPT_TCP_KEEPCNT`, default 9). Applied only when the `socket2` `all`
    /// feature is available (see [`apply_socket_options`]); otherwise the OS
    /// default is used.
    pub tcp_keepcnt: u32,
}

impl Default for SocketOptions {
    /// curl's defaults: `TCP_NODELAY` on, keepalive off, idle/intvl 60s, cnt 9.
    fn default() -> Self {
        Self {
            tcp_nodelay: true,
            tcp_keepalive: false,
            tcp_keepidle: 60,
            tcp_keepintvl: 60,
            tcp_keepcnt: 9,
        }
    }
}

/// Local-binding configuration applied before connect — the inputs to
/// `bindlocal` (`cf-socket.c` L532, guarded by `CURL_DISABLE_BINDLOCAL`):
/// `CURLOPT_INTERFACE`, `CURLOPT_LOCALPORT`, and `CURLOPT_LOCALPORTRANGE`.
///
/// `CURLOPT_INTERFACE` is first split by [`parse_interface`] into a device,
/// interface name, and/or bind host; the relevant pieces are then placed here.
/// An all-default `BindConfig` (no device, no host, port 0) means "do not bind"
/// and [`bindlocal`] is skipped.
#[derive(Debug, Clone, Default)]
pub struct BindConfig {
    /// Interface/device name to bind to via `SO_BINDTODEVICE` (Linux/Android).
    /// Sourced from the `if!`/`ifhost!` form, or a bare device, of
    /// `CURLOPT_INTERFACE`.
    pub device: Option<String>,
    /// Local IP address to bind to. Sourced from the `host!`/`ifhost!` form of
    /// `CURLOPT_INTERFACE`.
    pub bind_host: Option<IpAddr>,
    /// The first local port to try (C: `CURLOPT_LOCALPORT`; `0` means "any").
    pub local_port: u16,
    /// How many consecutive ports to try, starting at `local_port` (C:
    /// `CURLOPT_LOCALPORTRANGE`; `0`/`1` means "only `local_port`").
    pub local_port_range: u16,
}

impl BindConfig {
    /// Whether any binding is requested at all. When `false`, [`bindlocal`] is a
    /// no-op (matching curl, which only calls `bindlocal` when an interface or a
    /// local port is configured).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.device.is_some() || self.bind_host.is_some() || self.local_port != 0
    }
}

// =============================================================================
// PHASE 2 — `Curl_parse_interface` (C: cf-socket.c L475-529)
// =============================================================================

/// The decomposition of a `CURLOPT_INTERFACE` string — the typed result of
/// [`parse_interface`], mirroring the three out-parameters (`dev`, `iface`,
/// `host`) that C's `Curl_parse_interface` writes.
///
/// curl lets `CURLOPT_INTERFACE` select a binding by *device*, by *interface
/// name*, by *host (local IP)*, or by an *interface + host* pair, distinguished
/// by an optional `if!` / `host!` / `ifhost!` prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedInterface {
    /// A bare device name (no prefix) — C writes `*dev`.
    Device(String),
    /// An interface name (the `if!` prefix, or the interface half of `ifhost!`)
    /// — C writes `*iface`.
    Interface(String),
    /// A bind host / local IP (the `host!` prefix, or the host half of
    /// `ifhost!`) — C writes `*host`.
    Host(String),
    /// Both an interface name and a bind host (the `ifhost!` prefix) — C writes
    /// `*iface` and `*host`.
    InterfaceAndHost(String, String),
}

/// Parse a `CURLOPT_INTERFACE` string, reproducing `Curl_parse_interface`
/// (`cf-socket.c` L475-529) exactly.
///
/// Recognized forms, in C's order of testing:
///
/// * `"if!<name>"` → [`ParsedInterface::Interface`]. An empty name after the
///   prefix is [`CurlError::BadFunctionArgument`].
/// * `"host!<host>"` → [`ParsedInterface::Host`]. An empty host after the prefix
///   is [`CurlError::BadFunctionArgument`].
/// * `"ifhost!<iface>!<host>"` → [`ParsedInterface::InterfaceAndHost`]. A missing
///   `!` separator, or an empty host after it, is
///   [`CurlError::BadFunctionArgument`].
/// * anything else → [`ParsedInterface::Device`] (a bare device). An empty input
///   is [`CurlError::BadFunctionArgument`].
///
/// An input longer than 512 bytes is rejected with
/// [`CurlError::BadFunctionArgument`] (C: `if(len > 512)`).
///
/// The C version uses `memchr`/`curlx_memdup0` over raw pointers; this safe port
/// uses `str::strip_prefix` and `str::find`. The separator and prefixes are
/// ASCII, so the byte indices `find` returns always fall on `char` boundaries
/// and the slicing is sound.
///
/// # Errors
///
/// Returns [`CurlError::BadFunctionArgument`] for an over-length input, an empty
/// device, an empty `if!`/`host!` value, or a malformed `ifhost!` value, exactly
/// as the C function returns `CURLE_BAD_FUNCTION_ARGUMENT`. (The C
/// `CURLE_OUT_OF_MEMORY` paths correspond to allocation failures of
/// `curlx_memdup0`, which have no analog in the infallible Rust string copies.)
pub fn parse_interface(input: &str) -> Result<ParsedInterface> {
    // C: `len = strlen(input); if(len > 512) return CURLE_BAD_FUNCTION_ARGUMENT;`
    if input.len() > 512 {
        return Err(CurlError::BadFunctionArgument);
    }

    // C: `if(!strncmp(if_prefix, input, strlen(if_prefix)))` — interface only.
    if let Some(rest) = input.strip_prefix("if!") {
        if rest.is_empty() {
            return Err(CurlError::BadFunctionArgument);
        }
        return Ok(ParsedInterface::Interface(rest.to_string()));
    }

    // C: `else if(!strncmp(host_prefix, input, ...))` — host only.
    if let Some(rest) = input.strip_prefix("host!") {
        if rest.is_empty() {
            return Err(CurlError::BadFunctionArgument);
        }
        return Ok(ParsedInterface::Host(rest.to_string()));
    }

    // C: `else if(!strncmp(if_host_prefix, input, ...))` — interface + host,
    // split on the next `!` (`host_part = memchr(input, '!', len)`); a missing
    // separator or an empty host (`!*(host_part + 1)`) is a bad argument.
    if let Some(rest) = input.strip_prefix("ifhost!") {
        match rest.find('!') {
            Some(sep) => {
                let host = &rest[sep + 1..];
                if host.is_empty() {
                    return Err(CurlError::BadFunctionArgument);
                }
                let iface = &rest[..sep];
                return Ok(ParsedInterface::InterfaceAndHost(
                    iface.to_string(),
                    host.to_string(),
                ));
            }
            None => return Err(CurlError::BadFunctionArgument),
        }
    }

    // C: the final fallthrough — `if(!*input) return CURLE_BAD_FUNCTION_ARGUMENT;
    // *dev = curlx_memdup0(input, len);`
    if input.is_empty() {
        return Err(CurlError::BadFunctionArgument);
    }
    Ok(ParsedInterface::Device(input.to_string()))
}

// =============================================================================
// PHASE 1 — the socket-filter context (C: `struct cf_socket_ctx`, L868-892)
// =============================================================================

/// The bottom transport filter — the safe-Rust replacement for C's
/// `struct cf_socket_ctx` together with the per-filter state of its
/// `struct Curl_cfilter`.
///
/// A single `SocketFilter` value backs every one of curl's bottom transport
/// `cft`s (`Curl_cft_tcp`, `Curl_cft_udp`, `Curl_cft_unix`,
/// `Curl_cft_tcp_accept`); the active [`transport`](Self::transport) field and
/// the held [`sock`](Self::sock) / [`listener`](Self::listener) distinguish
/// them, exactly as the four C vtables all share `cf_socket_send`/`recv`/`cntrl`
/// /`query` and differ only in their `do_connect`.
///
/// curl's `DEBUGBUILD` fault-injection knobs (`CURL_DBG_SOCK_WBLOCK` /
/// `WPARTIAL` / `RBLOCK` / `RMAX`, L908-934) are **omitted**: they exist only to
/// exercise curl's *own* C buffering by simulating partial/blocked I/O and are
/// not needed for parity of the Rust artifacts.
pub struct SocketFilter {
    /// Chain link (`next`) plus the `connected`/`shutdown` bits every filter
    /// embeds (C: the per-instance fields of `struct Curl_cfilter`). For a
    /// transport filter this is the bottom of the chain, so `next` is normally
    /// [`None`].
    state: CfState,
    /// The active transport (`TRNSPRT_*`); C: `cf_socket_ctx.transport`.
    transport: u8,
    /// The endpoint to connect to (C: `cf_socket_ctx.addr`, a
    /// `Curl_sockaddr_ex`).
    target: SocketTarget,
    /// The live OS socket, or [`None`] when not (yet) connected — the safe
    /// stand-in for `cf_socket_ctx.sock` + `CURL_SOCKET_BAD`.
    sock: Option<Transport>,
    /// The connection's local/remote address quadruple (C:
    /// `cf_socket_ctx.ip`).
    ip: IpQuadruple,
    /// When the socket was created (C: `cf_socket_ctx.started_at`).
    started_at: Option<CurlTime>,
    /// When the socket finished connecting (C: `cf_socket_ctx.connected_at`).
    connected_at: Option<CurlTime>,
    /// When the first byte arrived from the peer (C:
    /// `cf_socket_ctx.first_byte_at`).
    first_byte_at: Option<CurlTime>,
    /// The errno-equivalent of the last failure, for diagnostics (C:
    /// `cf_socket_ctx.error`).
    error: i32,
    /// Whether the first byte has been received (C: `BIT(got_first_byte)`).
    got_first_byte: bool,
    /// Whether the socket is a listening socket (C: `BIT(listening)`).
    listening: bool,
    /// Whether the socket was accepted rather than connected (C:
    /// `BIT(accepted)`).
    accepted: bool,
    /// Whether a UDP/QUIC socket has been `connect()`-ed to its peer (C:
    /// `BIT(sock_connected)`).
    sock_connected: bool,
    /// Whether this socket has been made the connection's active socket (C:
    /// `BIT(active)`), set on `CF_CTRL_CONN_INFO_UPDATE`.
    active: bool,
    /// TCP option configuration applied around connect (C: `data->set` slices
    /// read by `tcpnodelay`/`tcpkeepalive`).
    opts: SocketOptions,
    /// Local-binding configuration applied before connect (C: `bindlocal`
    /// inputs).
    bind: BindConfig,
    /// The listening socket for the TCP-accept filter (C: the listen
    /// `ctx->sock`); [`None`] for connecting filters.
    listener: Option<TcpListener>,
    /// Accept timeout in milliseconds for the TCP-accept filter (C:
    /// `DEFAULT_ACCEPT_TIMEOUT` or `data->set.accepttimeout`).
    accept_timeout_ms: i64,
    /// A descriptor relinquished by `CF_CTRL_FORGET_SOCKET` but not yet reclaimed
    /// by a new owner; surfaced by the [`CfQuery::Socket`] query so the hand-off
    /// recipient can find it (C: after `FORGET_SOCKET`, `ctx->sock` still held
    /// the value until the recipient took it).
    #[cfg(unix)]
    forgotten_fd: Option<RawFd>,
}

impl SocketFilter {
    /// Construct an IP (TCP / UDP / QUIC) transport filter for one resolved
    /// address. The IP quadruple's *remote* half is filled from `addr` up front
    /// (C: `sock_assign_addr` records the remote endpoint at init); the *local*
    /// half is filled after connect from the socket's `local_addr()`.
    #[must_use]
    fn new_inet(addr: SocketAddr, transport: u8, opts: SocketOptions, bind: BindConfig) -> Self {
        let mut ip = IpQuadruple {
            transport,
            ..IpQuadruple::default()
        };
        ip.remote_ip = addr.ip().to_string();
        ip.remote_port = addr.port();
        Self {
            state: CfState::new(),
            transport,
            target: SocketTarget::Inet(addr),
            sock: None,
            ip,
            started_at: None,
            connected_at: None,
            first_byte_at: None,
            error: 0,
            got_first_byte: false,
            listening: false,
            accepted: false,
            sock_connected: false,
            active: false,
            opts,
            bind,
            listener: None,
            accept_timeout_ms: DEFAULT_ACCEPT_TIMEOUT_MS,
            #[cfg(unix)]
            forgotten_fd: None,
        }
    }

    /// Construct a UNIX-domain transport filter for one path/abstract target.
    #[cfg(unix)]
    #[must_use]
    fn new_unix(target: UnixTarget) -> Self {
        let ip = IpQuadruple {
            transport: TRNSPRT_UNIX,
            ..IpQuadruple::default()
        };
        Self {
            state: CfState::new(),
            transport: TRNSPRT_UNIX,
            target: SocketTarget::Unix(target),
            sock: None,
            ip,
            started_at: None,
            connected_at: None,
            first_byte_at: None,
            error: 0,
            got_first_byte: false,
            listening: false,
            accepted: false,
            sock_connected: false,
            active: false,
            opts: SocketOptions::default(),
            bind: BindConfig::default(),
            listener: None,
            accept_timeout_ms: DEFAULT_ACCEPT_TIMEOUT_MS,
            #[cfg(unix)]
            forgotten_fd: None,
        }
    }

    /// Construct a TCP-accept (FTP active-mode) filter wrapping an existing
    /// listening socket (C: `Curl_conn_tcp_listen_set` building a ctx with
    /// `listening = TRUE`). `started_at` is set now so the accept timeout counts
    /// from chain set-up, matching `cf_tcp_accept_timeleft`.
    #[must_use]
    fn new_accept(listener: TcpListener, accept_timeout_ms: i64) -> Self {
        let mut ip = IpQuadruple {
            transport: TRNSPRT_TCP,
            ..IpQuadruple::default()
        };
        // The listen socket's local endpoint is known immediately.
        if let Ok(local) = listener.local_addr() {
            ip.local_ip = local.ip().to_string();
            ip.local_port = local.port();
        }
        let local_target = listener
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        Self {
            state: CfState::new(),
            transport: TRNSPRT_TCP,
            target: SocketTarget::Inet(local_target),
            sock: None,
            ip,
            started_at: Some(curlx_now()),
            connected_at: None,
            first_byte_at: None,
            error: 0,
            got_first_byte: false,
            listening: true,
            accepted: false,
            sock_connected: false,
            active: false,
            opts: SocketOptions::default(),
            bind: BindConfig::default(),
            listener: Some(listener),
            accept_timeout_ms,
            #[cfg(unix)]
            forgotten_fd: None,
        }
    }

    /// Whether this filter's `transport` denotes a datagram (UDP/QUIC) socket,
    /// which affects the `TIMER_CONNECT` query fallthrough (C: `cf_socket_query`
    /// special-cases `TRNSPRT_UDP`/`TRNSPRT_QUIC`).
    fn is_datagram(&self) -> bool {
        self.transport == TRNSPRT_UDP || self.transport == TRNSPRT_QUIC
    }

    /// Whether the connected endpoint is IPv6 (C: `cf_socket_query`'s
    /// `addr.family == AF_INET6` for `CF_QUERY_IP_INFO`). UNIX-domain sockets
    /// report `false`.
    fn is_ipv6(&self) -> bool {
        match &self.target {
            SocketTarget::Inet(addr) => addr.is_ipv6(),
            #[cfg(unix)]
            SocketTarget::Unix(_) => false,
        }
    }

    /// Refresh the local half of the IP quadruple from the live socket (C:
    /// `set_local_ip` via `getsockname`).
    fn set_local_ip(&mut self) {
        if let Some(local) = self.sock.as_ref().and_then(Transport::local_addr) {
            self.ip.local_ip = local.ip().to_string();
            self.ip.local_port = local.port();
        }
    }

    /// Record receipt of the first byte from the peer if not already recorded
    /// (C: `cf_socket_recv` setting `first_byte_at`/`got_first_byte` on the
    /// first successful read, EOF included).
    fn note_first_byte(&mut self) {
        if !self.got_first_byte {
            self.first_byte_at = Some(curlx_now());
            self.got_first_byte = true;
        }
    }
}

// =============================================================================
// PHASE 4 — socket options (C: `tcpnodelay` L79, `tcpkeepalive` L114,
//           `Curl_sock_nosigpipe` L301)
// =============================================================================

/// Suppress `SIGPIPE` on writes to a closed peer, the Rust analog of
/// `Curl_sock_nosigpipe` (C: `cf-socket.c` L301, gated by `USE_SO_NOSIGPIPE`).
///
/// On Apple platforms the per-socket `SO_NOSIGPIPE` option exists and is applied
/// (best-effort) through `socket2`. On Linux and the other supported targets
/// there is **no** `SO_NOSIGPIPE`: instead the Rust standard runtime installs a
/// process-wide `SIG_IGN` disposition for `SIGPIPE`, so a write to a broken pipe
/// surfaces as an `EPIPE` `io::Error` (which [`SocketFilter::send`] maps to
/// [`CurlError::SendError`]) rather than terminating the process. The function
/// is therefore a documented no-op off Apple, exactly mirroring the C `#ifdef`
/// that compiles `Curl_sock_nosigpipe` only where the option is available.
fn apply_nosigpipe(socket: &TcpSocket) {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))]
    {
        // `SockRef` derefs to `socket2::Socket`, which exposes `set_nosigpipe`
        // on Apple targets. Errors are non-fatal (C ignores the return too).
        let _ = SockRef::from(socket).set_nosigpipe(true);
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    )))]
    {
        // No `SO_NOSIGPIPE` on this platform; rely on the runtime's `SIG_IGN`.
        let _ = socket;
    }
}

/// Apply curl's pre-connect TCP socket options to a freshly created
/// [`tokio::net::TcpSocket`], reproducing `tcpnodelay` (C: L79) and
/// `tcpkeepalive` (C: L114) plus the `SIGPIPE` suppression of
/// `Curl_sock_nosigpipe`.
///
/// curl applies these only to TCP sockets, in `cf_socket_open` (C: L1104-L1107):
/// `tcpnodelay` runs when `data->set.tcp_nodelay` (default **on** —
/// `CURLOPT_TCP_NODELAY` defaults to 1) and `tcpkeepalive` runs when
/// `data->set.tcp_keepalive` (default **off**). Both C helpers return `void`:
/// an option failure is *traced* and the connection proceeds. This port mirrors
/// that — every option error is reported through [`sendf::infof`] (gated on
/// verbosity) and **never** propagated.
///
/// Keepalive uses `socket2`'s [`TcpKeepalive`]: the idle time
/// (`CURLOPT_TCP_KEEPIDLE`) is always set via `with_time`, and the probe
/// interval (`CURLOPT_TCP_KEEPINTVL`) via `with_interval` on the platforms where
/// `socket2` supports it. The probe **count** (`CURLOPT_TCP_KEEPCNT`,
/// `TCP_KEEPCNT`) is intentionally omitted: `socket2`'s `with_retries` requires
/// the crate's `"all"` feature, which the workspace does not enable. This is a
/// documented, behavior-preserving omission — C itself only sets `TCP_KEEPCNT`
/// under `#ifdef TCP_KEEPCNT`, and a missing probe count merely defers to the
/// OS default (9 on Linux, the same value curl would request).
fn apply_socket_options(socket: &TcpSocket, opts: &SocketOptions, data: &FilterData) {
    // C `tcpnodelay` (L79): `setsockopt(TCP_NODELAY, 1)`. Applied when the
    // (default-on) `CURLOPT_TCP_NODELAY` option is set.
    if opts.tcp_nodelay {
        if let Err(e) = socket.set_nodelay(true) {
            sendf::infof(data.verbose, &format!("Could not set TCP_NODELAY: {e}"));
        }
    }

    // C `tcpkeepalive` (L114): `setsockopt(SO_KEEPALIVE, 1)` then
    // `TCP_KEEPIDLE`/`TCP_KEEPINTVL`/`TCP_KEEPCNT`. Applied when
    // `CURLOPT_TCP_KEEPALIVE` is set.
    if opts.tcp_keepalive {
        // `with_time` enables `SO_KEEPALIVE` and sets the idle period; it is
        // available on every platform `socket2` supports.
        let mut keepalive =
            TcpKeepalive::new().with_time(Duration::from_secs(u64::from(opts.tcp_keepidle)));

        // `with_interval` (the probe interval) is only present on the platforms
        // listed below in `socket2` 0.5; this `cfg` is a subset of `socket2`'s
        // own gate, so it compiles on every supported target (notably Linux and
        // macOS) and silently omits the interval elsewhere.
        #[cfg(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "windows"
        ))]
        {
            keepalive = keepalive.with_interval(Duration::from_secs(u64::from(opts.tcp_keepintvl)));
        }

        // `SockRef::from(&TcpSocket)` is sound because `tokio::net::TcpSocket`
        // implements `AsFd`; the borrow lasts only for this call.
        if let Err(e) = SockRef::from(socket).set_tcp_keepalive(&keepalive) {
            sendf::infof(
                data.verbose,
                &format!("Failed to set SO_KEEPALIVE/TCP_KEEP*: {e}"),
            );
        }
    }

    // C `Curl_sock_nosigpipe` (L301): apply where the per-socket option exists.
    apply_nosigpipe(socket);
}

// =============================================================================
// PHASE 3 — local binding (C: `bindlocal`, cf-socket.c L532-783,
//           guarded by `CURL_DISABLE_BINDLOCAL`)
// =============================================================================

/// Bind the local end of a socket to an interface, address, and/or port before
/// `connect`, reproducing `bindlocal` (C: `cf-socket.c` L532-783) for the
/// `CURLOPT_INTERFACE`, `CURLOPT_LOCALPORT`, and `CURLOPT_LOCALPORTRANGE`
/// options.
///
/// The [`BindConfig`] carries the already-parsed result of
/// [`parse_interface`]: `device` is the interface name (C's `iface`, from
/// either `STRING_INTERFACE` or a bare `STRING_DEVICE`), and `bind_host` is the
/// explicit local IP (C's `host_input`, from `STRING_BINDHOST`). The presence of
/// `bind_host` therefore corresponds exactly to C's `host_input != NULL` test.
///
/// Behavior, matching the C control flow:
///
/// 1. If nothing is requested (`!device && !bind_host && port == 0`) → `Ok` with
///    no binding (C: `if(!iface && !host && !port) return CURLE_OK;`).
/// 2. An interface name of 255 bytes or more → [`CurlError::BadFunctionArgument`]
///    (C: `else if(iface && (strlen(iface) >= 255)) ...`).
/// 3. With an interface, `SO_BINDTODEVICE` is attempted (Linux/Android, mirroring
///    C's `#ifdef SO_BINDTODEVICE`):
///    * success **and** no explicit `bind_host` → trace and return `Ok`
///      immediately (C returns `CURLE_OK` here without also binding a port —
///      reproduced faithfully);
///    * failure **and** no explicit `bind_host` → [`CurlError::InterfaceFailed`]
///      with the C `failf` "Could not bind to interface '…'" message;
///    * otherwise fall through to bind the explicit `bind_host`.
/// 4. The local bind IP is the explicit `bind_host` if present, else the
///    wildcard address of the connection's family (`0.0.0.0` / `[::]`).
/// 5. The port range is tried `localport .. localport + localportrange - 1`,
///    binding the first that succeeds (C: the `for(;;)` loop decrementing
///    `portnum`). Exhaustion or wrap-around yields the C `failf`
///    "bind failed …" + [`CurlError::InterfaceFailed`].
///
/// curl's interface→IP discovery (`Curl_if2ip`) and bind-host name resolution
/// (`Curl_resolv_blocking`) have no in-scope analog; `SO_BINDTODEVICE` covers
/// the interface case on Linux and `bind_host` is taken as an already-resolved
/// IP, which is sufficient for the supported targets. This narrowing is the only
/// deviation and is otherwise behavior-preserving.
///
/// # Errors
///
/// [`CurlError::BadFunctionArgument`] for an over-long interface name;
/// [`CurlError::InterfaceFailed`] if the interface bind or every port bind fails.
fn bindlocal(
    socket: &TcpSocket,
    bind: &BindConfig,
    af_is_v6: bool,
    data: &mut FilterData,
) -> Result<()> {
    let mut port = bind.local_port;

    // C: `if(!iface && !host && !port) return CURLE_OK;`
    if bind.device.is_none() && bind.bind_host.is_none() && port == 0 {
        return Ok(());
    }

    // C: `else if(iface && (strlen(iface) >= 255)) return BAD_FUNCTION_ARGUMENT;`
    if let Some(dev) = &bind.device {
        if dev.len() >= 255 {
            return Err(CurlError::BadFunctionArgument);
        }
    }

    // C: the `SO_BINDTODEVICE` block (`#ifdef SO_BINDTODEVICE`). The option is a
    // Linux/Android facility; on other platforms curl falls back to `if2ip`,
    // which is out of scope here, so the block is compiled only where the option
    // exists and a device-only request elsewhere degrades to a wildcard bind.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if let Some(dev) = &bind.device {
            match socket.bind_device(Some(dev.as_bytes())) {
                Ok(()) => {
                    // C: `if(!host_input) { infof("socket successfully bound to
                    // interface '%s'"); return CURLE_OK; }` — note this returns
                    // before any port bind, which is reproduced exactly.
                    if bind.bind_host.is_none() {
                        sendf::infof(
                            data.verbose,
                            &format!("socket successfully bound to interface '{dev}'"),
                        );
                        return Ok(());
                    }
                    // Else: an explicit host was also given (the `ifhost!` case);
                    // fall through to bind that host below.
                }
                Err(e) => {
                    // C: on `SO_BINDTODEVICE` failure with no host fallback the
                    // interface bind is fatal.
                    if bind.bind_host.is_none() {
                        sendf::failf(
                            &mut data.error_buffer,
                            &format!("Could not bind to interface '{dev}': {e}"),
                        );
                        return Err(CurlError::InterfaceFailed);
                    }
                    // Else: fall through and try the explicit host bind.
                }
            }
        }
    }

    // C: choose the bind address — the explicit host, else the family wildcard
    // (`si4->sin_family = AF_INET` / `si6->sin6_family = AF_INET6` with the
    // requested port).
    let bind_ip: IpAddr = match bind.bind_host {
        Some(ip) => ip,
        None if af_is_v6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };

    // C: the `for(;;)` port-range loop. `portnum` counts how many ports to try
    // (`CURLOPT_LOCALPORTRANGE`); each failed `bind` decrements it and advances
    // the port, exactly as the C loop does. The loop yields the error of the
    // final (un-retried) attempt; intermediate errors are reported via `infof`
    // and then dropped, so there is no dead-assignment.
    let mut portnum = i32::from(bind.local_port_range);
    let final_err: io::Error = loop {
        match socket.bind(SocketAddr::new(bind_ip, port)) {
            Ok(()) => {
                // C: `infof("Local port: %hu"); conn->bits.bound = TRUE;`
                sendf::infof(data.verbose, &format!("Local port: {port}"));
                return Ok(());
            }
            // C: `if(--portnum > 0) { port++; if(port == 0) break; infof("Bind to
            // local port %d failed, trying next", port - 1); } else break;`
            Err(e) => {
                portnum -= 1;
                if portnum > 0 {
                    let failed = port;
                    port = port.wrapping_add(1);
                    if port == 0 {
                        // Wrapped past 65535 — give up (C's `if(port == 0) break`).
                        break e;
                    }
                    sendf::infof(
                        data.verbose,
                        &format!("Bind to local port {failed} failed, trying next"),
                    );
                } else {
                    break e;
                }
            }
        }
    };

    // C: `failf("bind failed with errno %d: %s", ...); return CURLE_INTERFACE_FAILED;`
    sendf::failf(&mut data.error_buffer, &format!("bind failed: {final_err}"));
    Err(CurlError::InterfaceFailed)
}

// =============================================================================
// PHASE 5 — the TCP socket filter: connect helper + raw-fd / forget plumbing
//           (C: `cf_tcp_connect` L1239, `cf_socket_open` L1043, `do_connect`
//           L1184, `set_local_ip` L990, the `CF_CTRL_FORGET_SOCKET` arm L1574)
// =============================================================================

impl SocketFilter {
    /// Establish a TCP connection to this filter's single resolved address —
    /// the Rust collapse of curl's `cf_tcp_connect`/`cf_socket_open`/`do_connect`
    /// (C: `cf-socket.c` L1239 / L1043 / L1184).
    ///
    /// curl's machinery — open a non-blocking socket, issue `connect`, poll for
    /// `SOCKET_WRITABLE`, then confirm with `verifyconnect`/`getsockopt(SO_ERROR)`
    /// — exists solely to drive a non-blocking connect to completion. Under Tokio
    /// the reactor does exactly that, so the whole sequence becomes a single
    /// `TcpSocket::connect(addr).await`: a successful await **is** the verified
    /// connection (the `SO_ERROR` check is implicit in connect completion). The
    /// pre-connect option/bind steps (`tcpnodelay`, `tcpkeepalive`, `bindlocal`)
    /// run in curl's order (C: `cf_socket_open` L1104-L1132).
    ///
    /// # Errors
    ///
    /// [`CurlError::CouldntConnect`] if the socket cannot be created or the
    /// connect fails (with curl's `infof` "connect to … failed: …" diagnostic);
    /// the binding error [`CurlError::InterfaceFailed`] propagates from
    /// [`bindlocal`].
    async fn connect_tcp(&mut self, data: &mut FilterData) -> Result<()> {
        // C: `ctx->started_at = *Curl_pgrs_now(data)` at the top of cf_socket_open.
        if self.started_at.is_none() {
            self.started_at = Some(curlx_now());
        }

        let addr = match &self.target {
            SocketTarget::Inet(a) => *a,
            #[cfg(unix)]
            SocketTarget::Unix(_) => {
                // A UNIX target should never reach the TCP path; treat as a
                // connect failure rather than panicking.
                return Err(CurlError::CouldntConnect);
            }
        };

        // C: `set_remote_ip` records the remote endpoint + transport.
        self.ip.remote_ip = addr.ip().to_string();
        self.ip.remote_port = addr.port();
        self.ip.transport = self.transport;

        // C: `infof("  Trying %s:%d...")` / `"  Trying [%s]:%d..."` (IPv6).
        if addr.is_ipv6() {
            sendf::infof(
                data.verbose,
                &format!("  Trying [{}]:{}...", addr.ip(), addr.port()),
            );
        } else {
            sendf::infof(
                data.verbose,
                &format!("  Trying {}:{}...", addr.ip(), addr.port()),
            );
        }

        // C: `socket_open` — create the socket for the address family.
        let socket = if addr.is_ipv6() {
            TcpSocket::new_v6()
        } else {
            TcpSocket::new_v4()
        }
        .map_err(|e| {
            self.error = e.raw_os_error().unwrap_or(0);
            CurlError::CouldntConnect
        })?;

        // C: `tcpnodelay`/`tcpkeepalive` (L1104-L1107) then `bindlocal` (L1132),
        // in that order.
        apply_socket_options(&socket, &self.opts, data);
        bindlocal(&socket, &self.bind, addr.is_ipv6(), data)?;

        // Capture the (possibly bound) local endpoint for the failure diagnostic
        // before `connect` consumes the socket.
        if let Ok(local) = socket.local_addr() {
            // Only record a meaningful (bound) local address; an unbound socket
            // reports the wildcard, which we leave for the post-connect refresh.
            if !local.ip().is_unspecified() || local.port() != 0 {
                self.ip.local_ip = local.ip().to_string();
                self.ip.local_port = local.port();
            }
        }

        // The great async collapse: the awaited connect IS the verified
        // connection (C's non-blocking connect + SOCKET_WRITABLE + verifyconnect).
        match socket.connect(addr).await {
            Ok(stream) => {
                // C: `set_local_ip` via getsockname on the connected socket.
                if let Ok(local) = stream.local_addr() {
                    self.ip.local_ip = local.ip().to_string();
                    self.ip.local_port = local.port();
                }
                self.sock = Some(Transport::Tcp(stream));
                // C: `ctx->connected_at = *Curl_pgrs_now(data); cf->connected = TRUE`.
                self.connected_at = Some(curlx_now());
                self.sock_connected = true; // C: `sock_connected = (socktype != SOCK_DGRAM)`
                self.cf_state_mut().connected = true;
                Ok(())
            }
            Err(e) => {
                self.error = e.raw_os_error().unwrap_or(0);
                // C: `infof("connect to %s port %u from %s port %d failed: %s")`.
                sendf::infof(
                    data.verbose,
                    &format!(
                        "connect to {} port {} from {} port {} failed: {}",
                        self.ip.remote_ip,
                        self.ip.remote_port,
                        self.ip.local_ip,
                        self.ip.local_port,
                        e
                    ),
                );
                Err(CurlError::CouldntConnect)
            }
        }
    }

    /// Open the datagram socket for the UDP / QUIC transports — the Rust port of
    /// curl's `cf_udp_connect` (C: `cf-socket.c` L1813) together with the QUIC
    /// arm `cf_udp_setup_quic` (L1778).
    ///
    /// curl creates the UDP socket via `cf_socket_open` (applying `bindlocal`)
    /// and, for the *plain* UDP transport, leaves it unconnected —
    /// `sock_connected` stays false because `socktype == SOCK_DGRAM`. For
    /// `TRNSPRT_QUIC` it additionally `connect()`s the socket so the kernel
    /// records a default peer (`cf_udp_setup_quic`), sets `sock_connected`, and
    /// runs the Linux MTU/GRO tuning.
    ///
    /// Tokio materialises a `UdpSocket` only by binding, so we bind the family
    /// wildcard at curl's local port (`CURLOPT_LOCALPORT`; `0` ⇒ ephemeral),
    /// which is the `bindlocal` case the datagram path needs. The full
    /// device/host `bindlocal` matrix is only meaningful on the
    /// connection-oriented (TCP) path and is applied there; documenting that
    /// divergence here keeps the datagram path simple while honouring the local
    /// port the test-suite cares about for the QUIC substrate.
    ///
    /// The Linux QUIC MTU probe (`linux_quic_mtu`, L1741) and GRO toggle
    /// (`linux_quic_gro`, L1768) are **DOCUMENTED-OMITTED**: `quinn` performs its
    /// own path-MTU discovery and GRO/segmentation-offload management, so curl's
    /// hand-applied best-effort socket tuning is redundant under this backend.
    ///
    /// # Errors
    ///
    /// [`CurlError::CouldntConnect`] if the socket cannot be bound or — for QUIC
    /// — the default-peer `connect` fails.
    async fn connect_udp(&mut self, data: &mut FilterData) -> Result<()> {
        // C: `ctx->started_at = *Curl_pgrs_now(data)` at the top of cf_socket_open.
        if self.started_at.is_none() {
            self.started_at = Some(curlx_now());
        }

        let remote = match &self.target {
            SocketTarget::Inet(a) => *a,
            #[cfg(unix)]
            SocketTarget::Unix(_) => return Err(CurlError::CouldntConnect),
        };

        // C: `set_remote_ip` records the remote endpoint + transport.
        self.ip.remote_ip = remote.ip().to_string();
        self.ip.remote_port = remote.port();
        self.ip.transport = self.transport;

        // C: `infof("  Trying %s:%d...")` / bracketed for IPv6.
        if remote.is_ipv6() {
            sendf::infof(
                data.verbose,
                &format!("  Trying [{}]:{}...", remote.ip(), remote.port()),
            );
        } else {
            sendf::infof(
                data.verbose,
                &format!("  Trying {}:{}...", remote.ip(), remote.port()),
            );
        }

        // C: `socket_open` (a DGRAM socket). Tokio binds to materialise it; the
        // family wildcard at curl's local port (0 ⇒ kernel-chosen ephemeral).
        let bind_addr = if remote.is_ipv6() {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), self.bind.local_port)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), self.bind.local_port)
        };
        let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
            self.error = e.raw_os_error().unwrap_or(0);
            sendf::infof(
                data.verbose,
                &format!("UDP socket bind to {bind_addr} failed: {e}"),
            );
            CurlError::CouldntConnect
        })?;

        // C: `cf_udp_setup_quic` — for QUIC, connect() fixes the default peer.
        if self.transport == TRNSPRT_QUIC {
            socket.connect(remote).await.map_err(|e| {
                self.error = e.raw_os_error().unwrap_or(0);
                sendf::infof(
                    data.verbose,
                    &format!("QUIC UDP connect to {remote} failed: {e}"),
                );
                CurlError::CouldntConnect
            })?;
            // C: `ctx->sock_connected = TRUE` inside cf_udp_setup_quic. Plain UDP
            // leaves this false, mirroring `socktype != SOCK_DGRAM`.
            self.sock_connected = true;
            // linux_quic_mtu / linux_quic_gro — DOCUMENTED-OMITTED (quinn owns it).
        }

        // C: `set_local_ip` via getsockname on the bound/connected socket.
        if let Ok(local) = socket.local_addr() {
            self.ip.local_ip = local.ip().to_string();
            self.ip.local_port = local.port();
        }

        self.sock = Some(Transport::Udp(socket));
        // C: `ctx->connected_at = *Curl_pgrs_now(data); cf->connected = TRUE`.
        self.connected_at = Some(curlx_now());
        self.cf_state_mut().connected = true;
        Ok(())
    }

    /// Connect the UNIX-domain transport — the Rust port of curl's UNIX filter,
    /// whose `Curl_cft_unix` vtable (C: `cf-socket.c` L1902) routes its connect
    /// through `cf_tcp_connect`/`cf_socket_open` against an `AF_UNIX` address.
    /// Tokio offers a dedicated `UnixStream::connect`, so curl's `socket_open` +
    /// non-blocking `connect` + `verifyconnect` sequence collapses to one `await`
    /// exactly as it does for TCP.
    ///
    /// This realises `CURLOPT_UNIX_SOCKET_PATH` and `CURLOPT_ABSTRACT_UNIX_SOCKET`
    /// — the `UnixSockets` capability (feature bit `1 << 19`) reported by
    /// `version()`. Filesystem-path sockets use `UnixStream::connect`; Linux
    /// abstract-namespace sockets (curl's `sun_path[0] == '\0'` convention) are
    /// reached via the all-safe std bridge `SocketAddrExt::from_abstract_name` →
    /// `UnixStream::connect_addr` → `set_nonblocking(true)` →
    /// `tokio::net::UnixStream::from_std`. Abstract sockets are a Linux-only
    /// facility; on other UNIX platforms an abstract target is rejected.
    ///
    /// # Errors
    ///
    /// [`CurlError::CouldntConnect`] if the socket path cannot be reached (curl's
    /// `infof "connect to … failed"` diagnostic style is preserved).
    #[cfg(unix)]
    async fn connect_unix(&mut self, data: &mut FilterData) -> Result<()> {
        // C: `started_at` is stamped at the top of cf_socket_open.
        if self.started_at.is_none() {
            self.started_at = Some(curlx_now());
        }

        // Pull the path out (ending the borrow of `self.target`) before the
        // error closures below take `&mut self`.
        let (abstract_ns, name) = match &self.target {
            SocketTarget::Unix(t) => (t.abstract_namespace, t.name.clone()),
            SocketTarget::Inet(_) => return Err(CurlError::CouldntConnect),
        };
        self.ip.transport = self.transport;

        // C: `infof("  Trying …")`. UNIX targets are paths, not IP:port; the `@`
        // prefix marks the abstract namespace (curl's leading-NUL convention).
        if abstract_ns {
            sendf::infof(
                data.verbose,
                &format!("  Trying @{} (abstract unix socket)...", name.display()),
            );
        } else {
            sendf::infof(
                data.verbose,
                &format!("  Trying {} (unix socket)...", name.display()),
            );
        }

        let stream = if abstract_ns {
            #[cfg(target_os = "linux")]
            {
                use std::os::linux::net::SocketAddrExt;
                use std::os::unix::ffi::OsStrExt;
                // The abstract name excludes the leading NUL; pass the raw bytes.
                let bytes = name.as_os_str().as_bytes();
                let sa =
                    std::os::unix::net::SocketAddr::from_abstract_name(bytes).map_err(|e| {
                        self.error = e.raw_os_error().unwrap_or(0);
                        sendf::infof(data.verbose, &format!("invalid abstract unix name: {e}"));
                        CurlError::CouldntConnect
                    })?;
                let std_stream =
                    std::os::unix::net::UnixStream::connect_addr(&sa).map_err(|e| {
                        self.error = e.raw_os_error().unwrap_or(0);
                        sendf::infof(
                            data.verbose,
                            &format!("connect to abstract unix socket failed: {e}"),
                        );
                        CurlError::CouldntConnect
                    })?;
                // Tokio adopts only non-blocking std sockets.
                std_stream.set_nonblocking(true).map_err(|e| {
                    self.error = e.raw_os_error().unwrap_or(0);
                    CurlError::CouldntConnect
                })?;
                UnixStream::from_std(std_stream).map_err(|e| {
                    self.error = e.raw_os_error().unwrap_or(0);
                    CurlError::CouldntConnect
                })?
            }
            #[cfg(not(target_os = "linux"))]
            {
                // Abstract-namespace sockets exist only on Linux.
                sendf::failf(
                    &mut data.error_buffer,
                    "abstract UNIX sockets are only supported on Linux",
                );
                return Err(CurlError::CouldntConnect);
            }
        } else {
            UnixStream::connect(&name).await.map_err(|e| {
                self.error = e.raw_os_error().unwrap_or(0);
                sendf::infof(
                    data.verbose,
                    &format!("connect to unix socket {} failed: {e}", name.display()),
                );
                CurlError::CouldntConnect
            })?
        };

        // A UNIX stream socket is connection-oriented (not DGRAM), so
        // `sock_connected` is true. The IP quadruple stays blank — UNIX
        // endpoints have no IP:port, and the query handlers report `None` for
        // `RemoteAddr` accordingly.
        self.sock = Some(Transport::Unix(stream));
        self.connected_at = Some(curlx_now());
        self.sock_connected = true;
        self.cf_state_mut().connected = true;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // PHASE 6 — TCP accept filter (FTP active mode). C: `cf_tcp_accept_timeleft`
    //           L1955, `cf_tcp_set_accepted_remote_ip` L1983,
    //           `cf_tcp_accept_connect` L2015.
    // -------------------------------------------------------------------------

    /// Remaining time to wait for the server's inbound connection (C:
    /// `cf_tcp_accept_timeleft`, L1955).
    ///
    /// The base budget is [`self.accept_timeout_ms`](SocketFilter), which the
    /// accept-filter constructor sets to curl's `DEFAULT_ACCEPT_TIMEOUT`
    /// (60 000 ms) or the user's `CURLOPT_ACCEPTTIMEOUT_MS` when positive — the
    /// `timeout_ms = DEFAULT_ACCEPT_TIMEOUT; if(accepttimeout>0) timeout_ms =
    /// accepttimeout;` step of the C function. C then clamps by the generic
    /// transfer timeout (`Curl_timeleft_ms`); this design has no transfer-level
    /// deadline in [`FilterData`], so that clamp is a documented no-op
    /// (equivalent to C's `other_ms == 0`, which takes the `else` branch). The
    /// elapsed time since `started_at` is subtracted, and a result of exactly
    /// `0` is mapped to `-1` so it is never mistaken for "no timeout" — both
    /// exactly as in C.
    fn accept_timeleft(&self) -> i64 {
        let mut timeout_ms: i64 = self.accept_timeout_ms;
        // C subtracts the elapsed time since the listen socket was established.
        if let Some(started) = self.started_at.as_ref() {
            timeout_ms -= curlx_ptimediff_ms(&curlx_now(), started);
            if timeout_ms == 0 {
                // C: "avoid returning 0 as that means no timeout!"
                timeout_ms = -1;
            }
        }
        timeout_ms
    }

    /// Record the accepted peer's address (C: `cf_tcp_set_accepted_remote_ip`,
    /// L1983, a `getpeername` on the just-accepted socket). The remote fields are
    /// cleared first — exactly like C — then refilled from the live socket's peer
    /// via the safe [`Transport::peer_addr`] (the Tokio analog of `getpeername`).
    fn set_accepted_remote_ip(&mut self) {
        // C: `ctx->ip.remote_ip[0] = 0; ctx->ip.remote_port = 0;`
        self.ip.remote_ip = String::new();
        self.ip.remote_port = 0;
        if let Some(peer) = self.sock.as_ref().and_then(Transport::peer_addr) {
            self.ip.remote_ip = peer.ip().to_string();
            self.ip.remote_port = peer.port();
        }
    }

    /// Await the server's inbound connection on the listening socket — the Rust
    /// port of curl's `cf_tcp_accept_connect` (C: `cf-socket.c` L2015), used by
    /// **FTP active mode** where the client listens and the server connects back.
    ///
    /// curl's multi loop calls `cf_tcp_accept_connect` repeatedly, each time
    /// doing a zero-timeout `SOCKET_READABLE` poll and returning `CURLE_OK` with
    /// `*done = FALSE` until an inbound connection is pending, then `accept()`ing
    /// it. Under Tokio that cooperative poll-loop collapses into a single
    /// `tokio::time::timeout(remaining, listener.accept()).await`: the await
    /// resolves exactly when the connection arrives, bounded by the remaining
    /// accept budget.
    ///
    /// On success the listening socket is dropped (C: `socket_close` of the
    /// listen fd), the accepted stream becomes the live socket, the peer/local IP
    /// quadruple is filled (`cf_tcp_set_accepted_remote_ip` + `set_local_ip`),
    /// and `accepted`/`active`/`connected` are set. curl's optional
    /// `fsockopt(CURLSOCKTYPE_ACCEPT)` hook has no `FilterData` analog here and is
    /// omitted.
    ///
    /// # Errors
    ///
    /// * [`CurlError::FtpAcceptTimeout`] if the accept budget is already spent or
    ///   elapses while waiting. **Parity note:** curl returns
    ///   `CURLE_FTP_ACCEPT_TIMEOUT` (28→ no; the integer is `12`), *not*
    ///   `CURLE_OPERATION_TIMEDOUT`; the C oracle is authoritative for test
    ///   parity, so this deviates from the prose checklist which named
    ///   `OPERATION_TIMEDOUT`.
    /// * [`CurlError::FtpAcceptFailed`] if the `accept()` itself fails (C's
    ///   `CURLE_FTP_ACCEPT_FAILED`).
    async fn connect_accept(&mut self, data: &mut FilterData) -> Result<()> {
        // C: "we start accepted, if we ever close, we cannot go on" — idempotent.
        if self.cf_state().connected {
            return Ok(());
        }

        // C: `timeout_ms = cf_tcp_accept_timeleft(cf, data); if(timeout_ms < 0)`.
        let timeout_ms = self.accept_timeleft();
        if timeout_ms < 0 {
            sendf::failf(
                &mut data.error_buffer,
                "Accept timeout occurred while waiting server connect",
            );
            return Err(CurlError::FtpAcceptTimeout);
        }

        // C: a listen socket must exist (`ctx->sock != CURL_SOCKET_BAD`).
        let listener = match self.listener.as_ref() {
            Some(l) => l,
            None => {
                sendf::failf(
                    &mut data.error_buffer,
                    "Error while waiting for server connect",
                );
                return Err(CurlError::FtpAcceptFailed);
            }
        };

        // The async collapse: C's repeated `SOCKET_READABLE(0)` polling plus the
        // eventual `accept()` becomes one awaited accept, bounded by the budget.
        let dur = std::time::Duration::from_millis(u64::try_from(timeout_ms).unwrap_or(0));
        let stream = match tokio::time::timeout(dur, listener.accept()).await {
            // C: budget elapsed without an inbound connection.
            Err(_elapsed) => {
                sendf::failf(
                    &mut data.error_buffer,
                    "Accept timeout occurred while waiting server connect",
                );
                return Err(CurlError::FtpAcceptTimeout);
            }
            // C: `accept()` returned `CURL_SOCKET_BAD`.
            Ok(Err(e)) => {
                self.error = e.raw_os_error().unwrap_or(0);
                sendf::failf(&mut data.error_buffer, "Error accept()ing server connect");
                return Err(CurlError::FtpAcceptFailed);
            }
            // The peer address is recorded below via `getpeername` semantics
            // (`set_accepted_remote_ip`) rather than the address `accept`
            // returned, matching C exactly.
            Ok(Ok((stream, _peer))) => stream,
        };

        // C: `infof("Connection accepted from server")`.
        sendf::infof(data.verbose, "Connection accepted from server");

        // C: `ctx->listening = FALSE; ctx->accepted = TRUE; socket_close(listen);
        // ctx->sock = s_accepted;`. Dropping the listener closes the listen fd.
        self.listening = false;
        self.accepted = true;
        self.listener = None;
        self.sock = Some(Transport::Tcp(stream));

        // C: `cf_tcp_set_accepted_remote_ip` then `set_local_ip`.
        self.ip.transport = self.transport;
        self.set_accepted_remote_ip();
        self.set_local_ip();

        // C: `ctx->active = TRUE; ctx->connected_at = …; cf->connected = TRUE;`.
        self.active = true;
        self.connected_at = Some(curlx_now());
        self.sock_connected = true;
        self.cf_state_mut().connected = true;
        // fsockopt(CURLSOCKTYPE_ACCEPT) — no FilterData hook; omitted.
        Ok(())
    }

    /// The raw descriptor of the live socket for [`CfQuery::Socket`] (C:
    /// `cf_socket_query`'s `CF_QUERY_SOCKET` returning `ctx->sock`).
    ///
    /// Reports, in order, the connected/datagram socket, the listening socket of
    /// an accept filter, or a descriptor relinquished by `CF_CTRL_FORGET_SOCKET`
    /// but not yet reclaimed — then [`SOCKET_BAD`] (`-1`) when there is none.
    /// Raw descriptors are a UNIX concept; on other platforms this is always
    /// `-1` (the supported targets are Linux and macOS, both UNIX).
    fn live_raw_fd(&self) -> i64 {
        #[cfg(unix)]
        {
            if let Some(t) = &self.sock {
                return i64::from(t.raw_fd());
            }
            if let Some(listener) = &self.listener {
                return i64::from(listener.as_raw_fd());
            }
            if let Some(fd) = self.forgotten_fd {
                return i64::from(fd);
            }
        }
        SOCKET_BAD
    }

    /// Relinquish the socket without closing it (C: the `CF_CTRL_FORGET_SOCKET`
    /// arm of `cf_socket_cntrl`, L1574, which sets `ctx->sock = CURL_SOCKET_BAD`).
    ///
    /// Rust would close the descriptor on `Drop`; to hand it off intact we
    /// convert the live [`Transport`] into a bare descriptor via
    /// [`Transport::into_forgotten_fd`] (which leaks it from Rust's ownership)
    /// and remember it so a later [`CfQuery::Socket`] can still surface it. On
    /// non-UNIX targets, where we cannot extract a descriptor, the socket is
    /// simply dropped.
    fn forget_socket(&mut self) {
        #[cfg(unix)]
        {
            if let Some(t) = self.sock.take() {
                self.forgotten_fd = t.into_forgotten_fd();
            }
        }
        #[cfg(not(unix))]
        {
            self.sock = None;
        }
    }
}

// =============================================================================
// PHASE 5 — `ConnectionFilter` for the TCP socket filter (C: `Curl_cft_tcp`
//           vtable L1682, sharing `cf_socket_send`/`recv`/`cntrl`/`query`/
//           `conn_is_alive`/`shutdown`)
// =============================================================================

impl ConnectionFilter for SocketFilter {
    /// C: `cft->name`. One struct backs every socket-family vtable, so the name
    /// is derived from the role/transport: the accept filter is `"TCP-ACCEPT"`
    /// (C: `Curl_cft_tcp_accept`), otherwise `"UNIX"` / `"UDP"` / `"TCP"`
    /// (C: `Curl_cft_unix` / `Curl_cft_udp` / `Curl_cft_tcp`).
    fn name(&self) -> &'static str {
        if self.listening || self.accepted {
            "TCP-ACCEPT"
        } else if self.transport == TRNSPRT_UNIX {
            "UNIX"
        } else if self.is_datagram() {
            "UDP"
        } else {
            "TCP"
        }
    }

    /// C: `cft->flags`. Every socket-family vtable carries `CF_TYPE_IP_CONNECT`
    /// (it is the filter that actually reaches the IP endpoint).
    fn flags(&self) -> u32 {
        CF_TYPE_IP_CONNECT
    }

    fn cf_state(&self) -> &CfState {
        &self.state
    }

    fn cf_state_mut(&mut self) -> &mut CfState {
        &mut self.state
    }

    /// Establish the connection. Idempotent: a second call once connected just
    /// returns `Ok` (C: `if(cf->connected) { *done = TRUE; return CURLE_OK; }`).
    ///
    /// One Rust struct backs every socket-family vtable, so this dispatches on
    /// the transport to the same `connect` each C vtable installs: UDP/QUIC open
    /// a datagram socket (`Curl_cft_udp` → `cf_udp_connect`); UNIX and TCP open a
    /// stream socket (`Curl_cft_unix` and `Curl_cft_tcp` both → the
    /// `cf_tcp_connect` open/connect path, which Tokio collapses to a single
    /// `await`). The listening/accept role (`Curl_cft_tcp_accept` →
    /// `cf_tcp_accept_connect`) is handled by the accept filter and is wired into
    /// this dispatcher alongside that implementation.
    fn connect<'a>(&'a mut self, data: &'a mut FilterData) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if self.cf_state().connected {
                return Ok(());
            }
            // C: the `Curl_cft_tcp_accept` vtable points its connect at
            // `cf_tcp_accept_connect`. A listening filter awaits the server's
            // inbound connection rather than dialing out.
            if self.listening {
                return self.connect_accept(data).await;
            }
            if self.transport == TRNSPRT_UDP || self.transport == TRNSPRT_QUIC {
                self.connect_udp(data).await
            } else if self.transport == TRNSPRT_UNIX {
                #[cfg(unix)]
                {
                    self.connect_unix(data).await
                }
                #[cfg(not(unix))]
                {
                    sendf::failf(
                        &mut data.error_buffer,
                        "UNIX domain sockets are not supported on this platform",
                    );
                    Err(CurlError::CouldntConnect)
                }
            } else {
                self.connect_tcp(data).await
            }
        })
    }

    /// Tear down the socket (C: `cf_socket_close` L940 — close the fd and clear
    /// `connected`). The Rust `Drop` of the [`Transport`]/listener performs the
    /// actual `close(2)`.
    fn close(&mut self) {
        self.sock = None;
        self.listener = None;
        self.sock_connected = false;
        self.cf_state_mut().connected = false;
        if let Some(next) = self.cf_state_mut().next.as_mut() {
            next.close();
        }
    }

    /// Graceful shutdown (C: `cf_socket_shutdown` L958). For a *connected TCP*
    /// socket curl drains up to 1024 dangling bytes before close to avoid
    /// provoking an RST, then signals completion (`*done = TRUE`). It performs
    /// **no** `shutdown(2)` — adding one would emit an extra FIN and perturb the
    /// observed teardown, so this port drains only, exactly like C. The drain is
    /// a single non-blocking `try_read` (the Tokio analog of C's non-blocking
    /// `sread`). The chain drive marks the `shutdown` bit; this must not chain.
    fn shutdown<'a>(&'a mut self) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if self.cf_state().connected && self.transport == TRNSPRT_TCP {
                if let Some(Transport::Tcp(stream)) = &self.sock {
                    let mut buf = [0u8; 1024];
                    let _ = stream.try_read(&mut buf);
                }
            }
            Ok(())
        })
    }

    /// Send bytes on the socket (C: `cf_socket_send` L1387 → `swrite`). Maps a
    /// `WouldBlock`/`Interrupted` result to [`CurlError::Again`] (C's
    /// `EWOULDBLOCK`/`EAGAIN`/`EINTR`/`EINPROGRESS` → `CURLE_AGAIN`); any other
    /// error records the errno and returns [`CurlError::SendError`] (C's
    /// `failf("Send failure")` + `CURLE_SEND_ERROR` — the `failf` message is
    /// omitted because the trait's `send` is not handed a `FilterData`, but the
    /// observable `CURLcode` is preserved). A partial write returns the count
    /// accepted, as in C.
    fn send<'a>(&'a mut self, buf: &'a [u8], _eos: bool) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let res = match self.sock.as_mut() {
                Some(Transport::Tcp(s)) => s.write(buf).await,
                #[cfg(unix)]
                Some(Transport::Unix(s)) => s.write(buf).await,
                Some(Transport::Udp(s)) => s.send(buf).await,
                None => return Err(CurlError::SendError),
            };
            match res {
                Ok(n) => Ok(n),
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted =>
                {
                    Err(CurlError::Again)
                }
                Err(e) => {
                    self.error = e.raw_os_error().unwrap_or(0);
                    Err(CurlError::SendError)
                }
            }
        })
    }

    /// Receive bytes from the socket (C: `cf_socket_recv` L1471 → `sread`). `0`
    /// bytes means EOF. `WouldBlock`/`Interrupted` → [`CurlError::Again`]; any
    /// other error records the errno and returns [`CurlError::RecvError`]. On the
    /// first successful read (EOF included) the first-byte timestamp is recorded
    /// (C: `if(!result && !ctx->got_first_byte) { ctx->first_byte_at = …; }`).
    ///
    /// `WouldBlock` must be checked explicitly: the crate's `From<io::Error>`
    /// does **not** map it to `Again` (it would otherwise become `RecvError`).
    fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let res = match self.sock.as_mut() {
                Some(Transport::Tcp(s)) => s.read(buf).await,
                #[cfg(unix)]
                Some(Transport::Unix(s)) => s.read(buf).await,
                Some(Transport::Udp(s)) => s.recv(buf).await,
                None => return Err(CurlError::RecvError),
            };
            match res {
                Ok(n) => {
                    // C records the first byte on any successful read, EOF too.
                    self.note_first_byte();
                    Ok(n)
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted =>
                {
                    Err(CurlError::Again)
                }
                Err(e) => {
                    self.error = e.raw_os_error().unwrap_or(0);
                    Err(CurlError::RecvError)
                }
            }
        })
    }

    /// Handle a `CF_CTRL_*` event (C: `cf_socket_cntrl` L1559). Per the trait
    /// contract this must **not** chain to `next`.
    ///
    /// * `CF_CTRL_CONN_INFO_UPDATE` → `cf_socket_active`: mark this the active
    ///   socket and refresh the local IP (C also assigns `conn->sock[idx]` and
    ///   the IPv6 bit, which the engine owns in this design).
    /// * `CF_CTRL_DATA_SETUP` → `cf_socket_update_data`: a no-op here — the
    ///   engine pulls the IP quadruple via [`CfQuery::IpInfo`] rather than having
    ///   it pushed into `data->info`.
    /// * `CF_CTRL_FORGET_SOCKET` → relinquish the socket without closing it.
    fn cntrl(&mut self, event: i32, _arg1: i32) -> Result<()> {
        match event {
            CF_CTRL_CONN_INFO_UPDATE => {
                self.active = true;
                self.set_local_ip();
            }
            CF_CTRL_DATA_SETUP => {
                // Info is pulled via query; nothing to push.
            }
            CF_CTRL_FORGET_SOCKET => {
                self.forget_socket();
            }
            _ => {}
        }
        Ok(())
    }

    /// Liveness probe for connection reuse (C: `cf_socket_conn_is_alive` L1582,
    /// a zero-timeout `Curl_poll`). Returns `(alive, input_pending)`.
    ///
    /// With no socket the connection is dead. For TCP a non-blocking
    /// [`TcpStream::poll_peek`] (driven by a no-op waker) classifies the state:
    /// `Pending` mirrors C's poll-timeout → `(alive, no input)`; a peek of `0`
    /// bytes is EOF → dead (a stricter, correct call for reuse than C's
    /// POLLIN-based heuristic, which defers the EOF to the next read); a peek of
    /// `n > 0` bytes → `(alive, input pending)`; a peek error → dead. UNIX/UDP
    /// sockets have no `poll_peek`, so they are conservatively reported alive
    /// with no pending input.
    fn is_alive(&mut self) -> (bool, bool) {
        match &self.sock {
            None => (false, false),
            Some(Transport::Tcp(stream)) => {
                let mut cx = Context::from_waker(noop_waker_ref());
                let mut probe = [0u8; 1];
                let mut rb = ReadBuf::new(&mut probe);
                match stream.poll_peek(&mut cx, &mut rb) {
                    Poll::Pending => (true, false),
                    Poll::Ready(Ok(0)) => (false, false),
                    Poll::Ready(Ok(_)) => (true, true),
                    Poll::Ready(Err(_)) => (false, false),
                }
            }
            #[cfg(unix)]
            Some(Transport::Unix(_)) => (true, false),
            Some(Transport::Udp(_)) => (true, false),
        }
    }

    /// Answer a connection query (C: `cf_socket_query` L1619). Implements every
    /// case the socket filter owns and delegates the rest to `next` (or returns
    /// [`CurlError::UnknownOption`] at the bottom of the chain).
    fn query(&self, query: CfQuery) -> Result<CfQueryResult> {
        match query {
            // C: `*pres2 = ctx->sock`.
            CfQuery::Socket => Ok(CfQueryResult::Socket(self.live_raw_fd())),
            // C: `*pres1 = ctx->transport`.
            CfQuery::Transport => Ok(CfQueryResult::Transport(self.transport)),
            // C: `*pres2 = cf->connected ? &ctx->addr : NULL`. UNIX endpoints
            // have no `SocketAddr`, so they report `None`.
            CfQuery::RemoteAddr => {
                let addr = if self.cf_state().connected {
                    match &self.target {
                        SocketTarget::Inet(a) => Some(*a),
                        #[cfg(unix)]
                        SocketTarget::Unix(_) => None,
                    }
                } else {
                    None
                };
                Ok(CfQueryResult::RemoteAddr(addr))
            }
            // C: `got_first_byte ? min(ptimediff_ms(first_byte_at, started_at),
            // INT_MAX) : -1`.
            CfQuery::ConnectReplyMs => {
                let ms = if self.got_first_byte {
                    match (&self.first_byte_at, &self.started_at) {
                        (Some(fb), Some(st)) => curlx_ptimediff_ms(fb, st).min(i64::from(i32::MAX)),
                        _ => -1,
                    }
                } else {
                    -1
                };
                Ok(CfQueryResult::ConnectReplyMs(ms))
            }
            // C: for UDP/QUIC use `first_byte_at` once seen, else `connected_at`;
            // for everything else `connected_at`.
            CfQuery::TimerConnect => {
                let when = if self.is_datagram() && self.got_first_byte {
                    self.first_byte_at.unwrap_or_else(CurlTime::zero)
                } else {
                    self.connected_at.unwrap_or_else(CurlTime::zero)
                };
                Ok(CfQueryResult::TimerConnect(when))
            }
            // C: `*pres1 = (addr.family == AF_INET6); *pres2 = ctx->ip`.
            CfQuery::IpInfo => Ok(CfQueryResult::IpInfo {
                is_ipv6: self.is_ipv6(),
                quadruple: self.ip.clone(),
            }),
            // C: `cf->next ? next->query(...) : CURLE_UNKNOWN_OPTION`.
            other => match self.cf_state().next.as_ref() {
                Some(next) => next.query(other),
                None => Err(CurlError::UnknownOption),
            },
        }
    }
}

// NOTE: curl's `cf_socket_adjust_pollset` (C: `cf-socket.c` L1328) is
// deliberately **omitted**. It exists to register the socket fd with curl's
// hand-rolled `select`/`poll` multi loop; under Tokio the runtime reactor owns
// readiness notification, so there is no pollset to populate.

// =============================================================================
// PHASE 8 — the SOCKS connection-filter wrapper (BOUNDARY #1). C: `lib/socks.c`
//           L1198-1415 (`socks_proxy_cf_connect`, `Curl_cft_socks_proxy`,
//           `socks_cf_query`, `socks_proxy_cf_close`,
//           `Curl_cf_socks_proxy_insert_after`).
//
// This is the thin filter that sits *above* the socket filter: it first drives
// the underlying socket to a verified connection, then performs the SOCKS
// negotiation over it. curl's entire SOCKS state machine — `socks5_connect` /
// `socks4_connect`, the `SOCKS_ST_*` / `SOCKS5_ST_*` states, the `iobuf` BufQ,
// and `socks_cf_adjust_pollset` — collapses into a single awaited call to the
// pure engine `crate::proxy::socks::socks_handshake`, which negotiates directly
// on the async stream. The negotiation logic itself lives in `proxy/socks.rs`;
// this filter only wires it into the connection-filter chain.
//
// Gated behind the `proxy` feature (curl's `CURL_DISABLE_PROXY`).
// =============================================================================

/// An [`AsyncRead`] + [`AsyncWrite`] view over the *next* filter in the chain,
/// so the pure SOCKS engine (which is generic over `AsyncRead + AsyncWrite +
/// Unpin`) can negotiate directly over `ConnectionFilter::recv`/`send`.
///
/// The trait exposes `recv`/`send` as one-shot futures rather than `poll_*`
/// methods, so each `poll_read`/`poll_write` here creates a fresh future, polls
/// it exactly once, and drops it:
///
/// * `Ready(Ok(n))` → the bytes are committed and the poll completes.
/// * `Ready(Err(CurlError::Again))` → no data yet; the future is dropped and the
///   task is re-scheduled via `wake_by_ref` so the next poll issues a fresh
///   `recv`/`send` (the Tokio analog of curl's pollset wait, which this adapter
///   replaces — see the omitted `socks_cf_adjust_pollset`).
/// * `Ready(Err(e))` → surfaced as an [`io::Error`].
/// * `Pending` → propagated; the underlying future registered the waker.
///
/// Holding only references, `CfStream` is automatically [`Unpin`].
#[cfg(feature = "proxy")]
struct CfStream<'a> {
    /// The filter below the SOCKS wrapper — the already-connected socket filter.
    next: &'a mut dyn ConnectionFilter,
}

#[cfg(feature = "proxy")]
impl<'a> CfStream<'a> {
    /// Wrap the next filter as an async byte stream.
    fn new(next: &'a mut dyn ConnectionFilter) -> Self {
        Self { next }
    }
}

#[cfg(feature = "proxy")]
impl AsyncRead for CfStream<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        // `dst` borrows `buf`; it is moved into the `recv` future, so `buf`
        // cannot be touched again until that future is dropped.
        let dst = buf.initialize_unfilled();
        let mut fut = me.next.recv(dst);
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(n)) => {
                drop(fut); // releases the borrow of `dst`/`buf` (and of `next`)
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(CurlError::Again)) => {
                drop(fut);
                // No readiness is wired through this one-shot adapter; ask the
                // executor to poll us again so a fresh `recv` is issued.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => {
                drop(fut);
                Poll::Ready(Err(io::Error::other(e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(feature = "proxy")]
impl AsyncWrite for CfStream<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let mut fut = me.next.send(buf, false);
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(n)) => {
                drop(fut);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(CurlError::Again)) => {
                drop(fut);
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => {
                drop(fut);
                Poll::Ready(Err(io::Error::other(e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// The socket below buffers nothing of its own, so a flush is a no-op
    /// (curl's SOCKS filter likewise defines no flush).
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// Shutting down the SOCKS-negotiation view must not close the underlying
    /// socket (the chain owns its lifecycle), so this is a no-op.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// The connection-level inputs the SOCKS filter needs to derive the tunnel
/// target and the [`SocksParams`] — the Rust home for the `conn`/`data` fields
/// curl reads inside `socks_proxy_cf_connect` (C: `socks.c` L1244-1257).
///
/// The filter has no `connectdata` handle, so the caller (the SETUP builder in
/// `connect.rs`) populates these raw inputs from `conn`, and the *exact* curl
/// precedence is reproduced here by [`resolved_hostname`](Self::resolved_hostname)
/// and [`resolved_port`](Self::resolved_port). Note the host and port
/// precedences deliberately **differ** (curl orders them differently).
#[cfg(feature = "proxy")]
pub struct SocksProxyConfig {
    /// C: `conn->bits.httpproxy` — an HTTP proxy is layered in front, so the
    /// SOCKS tunnel target is the HTTP proxy itself.
    pub httpproxy: bool,
    /// C: `sockindex == SECONDARYSOCKET` — this is the FTP data channel.
    pub secondary: bool,
    /// C: `conn->bits.conn_to_host` — a `--connect-to` host override is active.
    pub conn_to_host_set: bool,
    /// C: `conn->bits.conn_to_port` — a `--connect-to` port override is active.
    pub conn_to_port_set: bool,
    /// C: `conn->http_proxy.host.name`.
    pub proxy_host: Option<String>,
    /// C: `conn->http_proxy.port`.
    pub proxy_port: u16,
    /// C: `conn->conn_to_host.name`.
    pub conn_to_host: Option<String>,
    /// C: `conn->conn_to_port`.
    pub conn_to_port: u16,
    /// C: `conn->secondaryhostname`.
    pub secondary_host: Option<String>,
    /// C: `conn->secondary_port`.
    pub secondary_port: u16,
    /// C: `conn->host.name` — the primary target host.
    pub target_host: String,
    /// C: `conn->remote_port` — the primary target port.
    pub target_port: u16,
    /// C: `conn->socks_proxy.user`.
    pub proxy_user: Option<String>,
    /// C: `conn->socks_proxy.passwd`.
    pub proxy_password: Option<String>,
    /// C: `conn->socks_proxy.proxytype`.
    pub proxytype: CurlProxyType,
    /// C: `data->set.socks5auth` — the SOCKS5 auth-method bitmask.
    pub socks5_auth: u32,
    /// C: `conn->ip_version` — address-family preference for local resolution.
    pub ip_version: IpVersion,
    /// C: `conn->bits.ipv6_ip` — the target host is an IPv6 literal.
    pub ipv6_ip: bool,
    /// C: `data->set.verbose` — gates informational handshake tracing.
    pub verbose: bool,
}

#[cfg(feature = "proxy")]
impl SocksProxyConfig {
    /// The SOCKS tunnel target host (C: `sx->hostname`, socks.c L1244-1251):
    /// HTTP-proxy host → `--connect-to` host → secondary host → target host.
    fn resolved_hostname(&self) -> &str {
        if self.httpproxy {
            self.proxy_host.as_deref().unwrap_or("")
        } else if self.conn_to_host_set {
            self.conn_to_host.as_deref().unwrap_or("")
        } else if self.secondary {
            self.secondary_host.as_deref().unwrap_or("")
        } else {
            &self.target_host
        }
    }

    /// The SOCKS tunnel target port (C: `sx->remote_port`, socks.c L1252-1256):
    /// HTTP-proxy port → secondary port → `--connect-to` port → target port.
    /// The order differs from [`resolved_hostname`](Self::resolved_hostname),
    /// exactly as in curl.
    fn resolved_port(&self) -> u16 {
        if self.httpproxy {
            self.proxy_port
        } else if self.secondary {
            self.secondary_port
        } else if self.conn_to_port_set {
            self.conn_to_port
        } else {
            self.target_port
        }
    }

    /// Build the [`SocksParams`] consumed by [`socks_handshake`] from the
    /// resolved target and the proxy credentials/options (C: the `sx->…`
    /// assignments in `socks_proxy_cf_connect`).
    fn to_socks_params(&self) -> SocksParams {
        let mut params = SocksParams::new(
            self.resolved_hostname().to_string(),
            self.resolved_port(),
            self.proxytype,
        );
        params.proxy_user = self.proxy_user.clone();
        params.proxy_password = self.proxy_password.clone();
        params.socks5_auth = self.socks5_auth;
        params.ip_version = self.ip_version;
        params.ipv6_ip = self.ipv6_ip;
        params.verbose = self.verbose;
        params
    }
}

/// The SOCKS proxy connection filter (C: `Curl_cft_socks_proxy`, socks.c L1384).
///
/// It owns no socket of its own; it wraps the filter below (the socket filter)
/// and, once that is connected, negotiates the SOCKS tunnel over it via
/// [`socks_handshake`]. The underlying filter is held in `state.next`, exactly
/// like every other non-bottom filter.
#[cfg(feature = "proxy")]
pub struct CfSocksProxy {
    /// Shared filter state (the `next` filter, `connected`/`shutdown` bits).
    state: CfState,
    /// The connection-derived inputs for the tunnel target + negotiation.
    config: SocksProxyConfig,
    /// A private resolver for any local SOCKS5 name resolution
    /// (`socks_handshake` takes `&mut DnsCache`). curl resolves via the easy
    /// handle's cache; this filter carries its own.
    dns: DnsCache,
    /// The last SOCKS proxy result (C: `data->info.pxcode`), surfaced for
    /// `CURLINFO_PROXY_ERROR`. Initialised to [`CurlProxyCode::Ok`].
    pxcode: CurlProxyCode,
}

#[cfg(feature = "proxy")]
impl CfSocksProxy {
    /// Create a SOCKS filter for the given connection config, with no `next`
    /// yet (the chain splices the socket filter in below — see
    /// [`create_socks_proxy_filter`] and the Phase-9 `insert_after` helper).
    fn new(config: SocksProxyConfig) -> Self {
        Self {
            state: CfState::new(),
            config,
            dns: DnsCache::new(),
            pxcode: CurlProxyCode::Ok,
        }
    }

    /// The last SOCKS proxy error recorded by [`connect`](ConnectionFilter::connect)
    /// (C: `data->info.pxcode`). [`CurlProxyCode::Ok`] until a negotiation fails.
    #[must_use]
    pub fn proxy_code(&self) -> CurlProxyCode {
        self.pxcode
    }
}

#[cfg(feature = "proxy")]
impl ConnectionFilter for CfSocksProxy {
    /// C: `cft->name` = `"SOCKS"`.
    fn name(&self) -> &'static str {
        "SOCKS"
    }

    /// C: `cft->flags` = `CF_TYPE_IP_CONNECT | CF_TYPE_PROXY`.
    fn flags(&self) -> u32 {
        CF_TYPE_IP_CONNECT | CF_TYPE_PROXY
    }

    fn cf_state(&self) -> &CfState {
        &self.state
    }

    fn cf_state_mut(&mut self) -> &mut CfState {
        &mut self.state
    }

    /// Connect through the SOCKS proxy (C: `socks_proxy_cf_connect`, socks.c
    /// L1215). The underlying socket is connected first; then the SOCKS
    /// negotiation runs over it.
    ///
    /// curl's multi-call state machine (`socks5_connect`/`socks4_connect`, the
    /// `SOCKS_ST_*`/`SOCKS5_ST_*` states, the `iobuf` BufQ, and
    /// `socks_cf_adjust_pollset`) collapses into the single awaited
    /// [`socks_handshake`] call: the pure engine negotiates directly on the
    /// async stream exposed by [`CfStream`].
    ///
    /// # Errors
    ///
    /// * Propagates any error from connecting the filter below.
    /// * [`CurlError::CouldntConnect`] for a non-SOCKS proxy type (C's
    ///   `failf("unknown proxytype option given")` + `CURLE_COULDNT_CONNECT`).
    /// * [`CurlError::Proxy`] (`CURLE_PROXY`) if the handshake fails; the
    ///   [`CurlProxyCode`] is stored (C: `data->info.pxcode = pxresult`) and the
    ///   `CURLPX_*` → `CURLcode` mapping goes through [`to_curlcode`].
    fn connect<'a>(&'a mut self, data: &'a mut FilterData) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // C: `if(cf->connected) { *done = TRUE; return CURLE_OK; }`.
            if self.state.connected {
                return Ok(());
            }

            // C: `result = cf->next->cft->do_connect(...); if(result || !*done)
            // return result;` — connect the socket below FIRST. The awaited
            // connect resolves only on a verified connection, so the `!*done`
            // re-poll loop is unnecessary.
            match self.state.next.as_mut() {
                Some(next) => next.connect(data).await?,
                None => return Err(CurlError::CouldntConnect),
            }

            // C: the `switch(conn->socks_proxy.proxytype)` default arm rejects
            // any non-SOCKS type with CURLE_COULDNT_CONNECT (not CURLE_PROXY).
            if !self.config.proxytype.is_socks() {
                sendf::failf(&mut data.error_buffer, "unknown proxytype option given");
                return Err(CurlError::CouldntConnect);
            }

            // C: build `sx` (hostname/port/credentials) from `conn`/`data`.
            let params = self.config.to_socks_params();

            // Run the negotiation over the socket below. `next` (a borrow of
            // `self.state.next`) and `self.dns` are disjoint fields, so both can
            // be borrowed across the await; the borrows end when `stream` drops.
            let result = {
                let next = match self.state.next.as_mut() {
                    Some(n) => n,
                    None => return Err(CurlError::CouldntConnect),
                };
                let mut stream = CfStream::new(&mut **next);
                socks_handshake(&mut stream, &params, &mut self.dns, &mut data.error_buffer).await
            };

            match result {
                Ok(()) => {
                    // C: `socks_proxy_cf_free(cf); cf->connected = TRUE;`. There
                    // is no persistent handshake state to free in this design.
                    self.state.connected = true;
                    Ok(())
                }
                Err(px) => {
                    // C: `result = CURLE_PROXY; data->info.pxcode = pxresult;`.
                    self.pxcode = px;
                    let (code, _) = to_curlcode(px);
                    Err(CurlError::from_code(code))
                }
            }
        })
    }

    /// Answer a connection query (C: `socks_cf_query`, socks.c L1356).
    ///
    /// * [`CfQuery::HostPort`] → the SOCKS tunnel target `(host, port)`.
    ///   **Parity note:** curl frees its `sx` state on a successful connect, so
    ///   its `socks_cf_query` only returns the target *during* negotiation and
    ///   delegates afterwards; this design retains [`SocksProxyConfig`] for the
    ///   filter's lifetime and therefore reports the same target consistently —
    ///   a behavior-preserving improvement over curl's accidental post-free
    ///   delegation.
    /// * [`CfQuery::AlpnNegotiated`] → `None` (SOCKS negotiates no ALPN).
    /// * everything else → delegate to `next` (or `CURLE_UNKNOWN_OPTION`).
    fn query(&self, query: CfQuery) -> Result<CfQueryResult> {
        match query {
            CfQuery::HostPort => Ok(CfQueryResult::HostPort {
                host: self.config.resolved_hostname().to_string(),
                port: self.config.resolved_port(),
            }),
            CfQuery::AlpnNegotiated => Ok(CfQueryResult::AlpnNegotiated(None)),
            // C: `cf->next ? next->query(...) : CURLE_UNKNOWN_OPTION`.
            other => match self.state.next.as_ref() {
                Some(next) => next.query(other),
                None => Err(CurlError::UnknownOption),
            },
        }
    }

    // `close`, `shutdown`, `send`, `recv`, `cntrl`, `is_alive`, `keep_alive`,
    // and `data_pending` are inherited from the trait defaults, which delegate
    // to `next` exactly like curl's `Curl_cf_def_*` entries in the
    // `Curl_cft_socks_proxy` vtable (the SOCKS filter is transparent once the
    // tunnel is established). `socks_cf_adjust_pollset` (socks.c L1311) is
    // omitted for the same reason as the socket filter's pollset (Tokio reactor).
}

/// Create a SOCKS proxy filter from a [`SocksProxyConfig`] (C:
/// `Curl_cf_socks_proxy_insert_after` creating a `Curl_cft_socks_proxy`
/// instance, socks.c L1402). The returned filter has no `next` yet; the SETUP
/// builder splices the socket filter in below it (see the Phase-9
/// `socks_proxy_insert_after` chain helper).
#[cfg(feature = "proxy")]
#[must_use]
pub fn create_socks_proxy_filter(config: SocksProxyConfig) -> Box<dyn ConnectionFilter> {
    Box::new(CfSocksProxy::new(config))
}

// =============================================================================
// PHASE 9 — filter constructors and public chain surface. C: `Curl_cf_tcp_create`
//           (L1668), `Curl_cf_udp_create` (L1866), `Curl_cf_unix_create` (L1920),
//           `Curl_conn_tcp_listen_set` (L2150), `Curl_conn_is_tcp_listen`
//           (L2191), `Curl_cf_socket_peek` (L2214), and the SOCKS
//           `Curl_cf_socks_proxy_insert_after` (socks.c L1402).
//
// These are the entry points the SETUP builder in `connect.rs` and the
// Happy-Eyeballs racer in `happy_eyeballs.rs` call to materialise socket filters
// and wire them into a [`FilterChain`].
// =============================================================================

/// Create the bottom **TCP** socket filter for one resolved address (C:
/// `Curl_cf_tcp_create`, L1668, with `transport == TRNSPRT_TCP`). `opts` carries
/// the `CURLOPT_TCP_NODELAY`/`TCP_KEEPALIVE` settings and `bind` the
/// `CURLOPT_INTERFACE`/`LOCALPORT` binding, both applied at connect time.
///
/// The socket filter is created **per candidate address**; `happy_eyeballs.rs`
/// races several and promotes the winner — this filter connects to exactly the
/// one `addr` it is given.
#[must_use]
pub fn create_tcp_filter(
    addr: SocketAddr,
    opts: SocketOptions,
    bind: BindConfig,
) -> Box<dyn ConnectionFilter> {
    Box::new(SocketFilter::new_inet(addr, TRNSPRT_TCP, opts, bind))
}

/// Create the bottom **UDP / QUIC** datagram filter for one resolved address (C:
/// `Curl_cf_udp_create`, L1866). `transport` must be [`TRNSPRT_UDP`] or
/// [`TRNSPRT_QUIC`]; QUIC additionally `connect()`s the datagram socket to fix
/// the default peer (the substrate `quinn`/`h3` build on). `bind` honours the
/// local port; TCP-only options do not apply to datagrams.
#[must_use]
pub fn create_udp_filter(
    addr: SocketAddr,
    transport: u8,
    bind: BindConfig,
) -> Box<dyn ConnectionFilter> {
    debug_assert!(
        transport == TRNSPRT_UDP || transport == TRNSPRT_QUIC,
        "create_udp_filter requires TRNSPRT_UDP or TRNSPRT_QUIC"
    );
    Box::new(SocketFilter::new_inet(
        addr,
        transport,
        SocketOptions::default(),
        bind,
    ))
}

/// Create the bottom **UNIX-domain** socket filter (C: `Curl_cf_unix_create`,
/// L1920, with `transport == TRNSPRT_UNIX`). Realises
/// `CURLOPT_UNIX_SOCKET_PATH`/`ABSTRACT_UNIX_SOCKET`. UNIX-only; the supported
/// build targets (Linux, macOS) are both UNIX.
#[cfg(unix)]
#[must_use]
pub fn create_unix_filter(target: UnixTarget) -> Box<dyn ConnectionFilter> {
    Box::new(SocketFilter::new_unix(target))
}

/// Create the **TCP-accept** filter that listens on `listener` for a server's
/// inbound connection (C: the `Curl_cft_tcp_accept` filter built by
/// `Curl_conn_tcp_listen_set`), used by FTP active mode. `accept_timeout_ms` is
/// the base accept budget (curl's `DEFAULT_ACCEPT_TIMEOUT` or
/// `CURLOPT_ACCEPTTIMEOUT_MS`).
#[must_use]
pub fn create_tcp_accept_filter(
    listener: TcpListener,
    accept_timeout_ms: i64,
) -> Box<dyn ConnectionFilter> {
    Box::new(SocketFilter::new_accept(listener, accept_timeout_ms))
}

/// Replace the chain with a single TCP-accept filter listening on `listener`
/// (C: `Curl_conn_tcp_listen_set`, L2150). curl discards any existing filters,
/// then installs the listen filter; this mirrors that exactly via
/// [`FilterChain::discard_all`] + [`FilterChain::add_filter`].
pub fn tcp_listen_set(chain: &mut FilterChain, listener: TcpListener, accept_timeout_ms: i64) {
    // C: `Curl_conn_cf_discard_all(...)` then `Curl_conn_cf_add(...)`.
    chain.discard_all();
    chain.add_filter(create_tcp_accept_filter(listener, accept_timeout_ms));
}

/// Whether `chain` contains a TCP-accept (listen) filter (C:
/// `Curl_conn_is_tcp_listen`, L2191, which walks the chain for
/// `&Curl_cft_tcp_accept`). Here the accept filter is identified by its
/// `"TCP-ACCEPT"` name.
#[must_use]
pub fn is_tcp_listen(chain: &FilterChain) -> bool {
    chain.position_by_name("TCP-ACCEPT").is_some()
}

/// Whether a filter name denotes a bottom socket filter (C: `cf_is_socket`,
/// L2206, matching the `tcp`/`udp`/`unix`/`tcp_accept` vtables). The SOCKS proxy
/// filter is deliberately excluded.
#[must_use]
fn is_socket_filter(name: &str) -> bool {
    matches!(name, "TCP" | "UDP" | "UNIX" | "TCP-ACCEPT")
}

/// The socket-level information surfaced by [`socket_peek`] — the Rust analog of
/// C's `Curl_cf_socket_peek` out-parameters (`psock`, `paddr`, `pip`).
#[derive(Clone, Debug)]
pub struct SocketPeek {
    /// The raw socket descriptor (C: `*psock = ctx->sock`); [`SOCKET_BAD`]
    /// (`-1`) when there is none or on non-UNIX targets.
    pub socket: i64,
    /// The connected remote endpoint, if any (C: `&ctx->addr`). `None` for a
    /// UNIX-domain target or before connect.
    pub remote_addr: Option<SocketAddr>,
    /// The full IP quadruple (C: `*pip = ctx->ip`): remote endpoint (recorded at
    /// construction) plus the local endpoint (filled once connected).
    pub ip: IpQuadruple,
}

/// Peek at the bottom socket filter's descriptor, remote address, and IP
/// quadruple (C: `Curl_cf_socket_peek`, L2214). Returns
/// [`CurlError::FailedInit`] (C's `CURLE_FAILED_INIT`) if `cf` is not a socket
/// filter.
///
/// The values are pulled through the [`ConnectionFilter::query`] interface
/// (`Socket`, `RemoteAddr`, `IpInfo`) since `cf` is a trait object; this mirrors
/// C reading `ctx->sock`/`ctx->addr`/`ctx->ip` directly.
///
/// # Errors
///
/// [`CurlError::FailedInit`] if `cf` is not one of the socket filters.
pub fn socket_peek(cf: &dyn ConnectionFilter) -> Result<SocketPeek> {
    // C: `if(cf_is_socket(cf) && cf->ctx) { … } return CURLE_FAILED_INIT;`.
    if !is_socket_filter(cf.name()) {
        return Err(CurlError::FailedInit);
    }
    let socket = match cf.query(CfQuery::Socket) {
        Ok(CfQueryResult::Socket(fd)) => fd,
        _ => SOCKET_BAD,
    };
    let remote_addr = match cf.query(CfQuery::RemoteAddr) {
        Ok(CfQueryResult::RemoteAddr(addr)) => addr,
        _ => None,
    };
    let ip = match cf.query(CfQuery::IpInfo) {
        Ok(CfQueryResult::IpInfo { quadruple, .. }) => quadruple,
        _ => IpQuadruple::default(),
    };
    Ok(SocketPeek {
        socket,
        remote_addr,
        ip,
    })
}

/// Create a SOCKS proxy filter and splice it into `chain` immediately after the
/// filter at `after_index` (C: `Curl_cf_socks_proxy_insert_after`, socks.c
/// L1402, which calls `Curl_conn_cf_insert_after`). The SETUP builder calls this
/// in the SOCKS step so the SOCKS filter wraps the socket filter below it.
///
/// # Errors
///
/// [`CurlError::BadFunctionArgument`] if no filter exists at `after_index`
/// (propagated from [`FilterChain::insert_after_index`]).
#[cfg(feature = "proxy")]
pub fn socks_proxy_insert_after(
    chain: &mut FilterChain,
    after_index: usize,
    config: SocksProxyConfig,
) -> Result<()> {
    chain.insert_after_index(after_index, create_socks_proxy_filter(config))
}

// =============================================================================
// Tests. The C behaviours under test are anchored to their `cf-socket.c` /
// `socks.c` oracle line numbers in each test's comment. None of these compile
// into the shipped library (`#[cfg(test)]`).
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    /// Drive a future to completion on a fresh current-thread runtime with both
    /// the time and I/O drivers enabled (the integration tests use real
    /// `tokio::net` sockets and `tokio::time::timeout`).
    fn run<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build test runtime")
            .block_on(fut)
    }

    // ---- Transport constants (C: `urldata.h` `TRNSPRT_*`) -------------------

    #[test]
    fn transport_constants_match_c() {
        assert_eq!(TRNSPRT_NONE, 0);
        assert_eq!(TRNSPRT_TCP, 3);
        assert_eq!(TRNSPRT_UDP, 4);
        assert_eq!(TRNSPRT_QUIC, 5);
        assert_eq!(TRNSPRT_UNIX, 6);
        // The "no socket" sentinel is `-1`, the safe-Rust stand-in for
        // `CURL_SOCKET_BAD`.
        assert_eq!(SOCKET_BAD, -1);
    }

    // ---- `parse_interface` (C: `Curl_parse_interface`, cf-socket.c L475-529)
    //      Every prefix branch plus the error branches, reproduced exactly.

    #[test]
    fn parse_interface_plain_device() {
        // No recognised prefix → the whole string is a device name.
        assert_eq!(
            parse_interface("eth0").expect("device"),
            ParsedInterface::Device("eth0".to_string())
        );
    }

    #[test]
    fn parse_interface_if_prefix() {
        // `if!<name>` → interface only.
        assert_eq!(
            parse_interface("if!eth0").expect("iface"),
            ParsedInterface::Interface("eth0".to_string())
        );
    }

    #[test]
    fn parse_interface_if_prefix_empty_is_error() {
        // `if!` with nothing after it → CURLE_BAD_FUNCTION_ARGUMENT.
        assert_eq!(parse_interface("if!"), Err(CurlError::BadFunctionArgument));
    }

    #[test]
    fn parse_interface_host_prefix() {
        // `host!<name>` → host only.
        assert_eq!(
            parse_interface("host!example.com").expect("host"),
            ParsedInterface::Host("example.com".to_string())
        );
    }

    #[test]
    fn parse_interface_ifhost_prefix() {
        // `ifhost!<iface>!<host>` → both.
        assert_eq!(
            parse_interface("ifhost!eth0!example.com").expect("ifhost"),
            ParsedInterface::InterfaceAndHost("eth0".to_string(), "example.com".to_string())
        );
    }

    #[test]
    fn parse_interface_ifhost_missing_separator_is_error() {
        // `ifhost!<iface>` with no second `!` → error.
        assert_eq!(
            parse_interface("ifhost!eth0"),
            Err(CurlError::BadFunctionArgument)
        );
    }

    #[test]
    fn parse_interface_ifhost_empty_host_is_error() {
        // `ifhost!<iface>!` with an empty host → error.
        assert_eq!(
            parse_interface("ifhost!eth0!"),
            Err(CurlError::BadFunctionArgument)
        );
    }

    #[test]
    fn parse_interface_too_long_is_error() {
        // Input longer than 512 bytes → error (C's `if(strlen(input) > 512)`).
        let long = "a".repeat(513);
        assert_eq!(parse_interface(&long), Err(CurlError::BadFunctionArgument));
        // Exactly 512 is still accepted (as a device name).
        let max = "b".repeat(512);
        assert_eq!(
            parse_interface(&max).expect("512 ok"),
            ParsedInterface::Device(max.clone())
        );
    }

    // ---- `cf_socket_query` exactness on an unconnected TCP filter
    //      (C: `cf_socket_query`, cf-socket.c L1619). -------------------------

    fn make_tcp_filter_v4() -> Box<dyn ConnectionFilter> {
        let addr: SocketAddr = "127.0.0.1:80".parse().expect("addr");
        create_tcp_filter(addr, SocketOptions::default(), BindConfig::default())
    }

    #[test]
    fn tcp_query_transport_is_tcp() {
        let cf = make_tcp_filter_v4();
        match cf.query(CfQuery::Transport).expect("transport") {
            CfQueryResult::Transport(t) => assert_eq!(t, TRNSPRT_TCP),
            other => panic!("expected Transport, got {other:?}"),
        }
    }

    #[test]
    fn tcp_query_socket_is_bad_when_unconnected() {
        // No live socket yet → `CURL_SOCKET_BAD` (-1).
        let cf = make_tcp_filter_v4();
        match cf.query(CfQuery::Socket).expect("socket") {
            CfQueryResult::Socket(fd) => assert_eq!(fd, SOCKET_BAD),
            other => panic!("expected Socket, got {other:?}"),
        }
    }

    #[test]
    fn tcp_query_connect_reply_ms_is_minus_one_without_first_byte() {
        // `got_first_byte == false` → `-1` (C L1644-1647).
        let cf = make_tcp_filter_v4();
        match cf.query(CfQuery::ConnectReplyMs).expect("reply ms") {
            CfQueryResult::ConnectReplyMs(ms) => assert_eq!(ms, -1),
            other => panic!("expected ConnectReplyMs, got {other:?}"),
        }
    }

    #[test]
    fn tcp_query_remote_addr_none_when_unconnected() {
        // Remote addr is reported only once connected (C returns the stored
        // `addr` but our typed query gates on the live socket).
        let cf = make_tcp_filter_v4();
        match cf.query(CfQuery::RemoteAddr).expect("remote") {
            CfQueryResult::RemoteAddr(addr) => assert!(addr.is_none()),
            other => panic!("expected RemoteAddr, got {other:?}"),
        }
    }

    #[test]
    fn tcp_query_ip_info_carries_target_and_family() {
        // The remote endpoint of the quadruple is recorded at construction; the
        // family flag is derived from the target address.
        let cf = make_tcp_filter_v4();
        match cf.query(CfQuery::IpInfo).expect("ip info") {
            CfQueryResult::IpInfo { is_ipv6, quadruple } => {
                assert!(!is_ipv6);
                assert_eq!(quadruple.remote_ip, "127.0.0.1");
                assert_eq!(quadruple.remote_port, 80);
                assert_eq!(quadruple.transport, TRNSPRT_TCP);
            }
            other => panic!("expected IpInfo, got {other:?}"),
        }
    }

    #[test]
    fn tcp_query_ip_info_v6_family() {
        let addr: SocketAddr = "[::1]:443".parse().expect("addr");
        let cf = create_tcp_filter(addr, SocketOptions::default(), BindConfig::default());
        match cf.query(CfQuery::IpInfo).expect("ip info") {
            CfQueryResult::IpInfo { is_ipv6, quadruple } => {
                assert!(is_ipv6);
                assert_eq!(quadruple.remote_port, 443);
            }
            other => panic!("expected IpInfo, got {other:?}"),
        }
    }

    // ---- Filter naming / `cf_is_socket` / `socket_peek`
    //      (C: `cf_is_socket` L2206, `Curl_cf_socket_peek` L2214). -----------

    #[test]
    fn filter_names_match_c_vtables() {
        let tcp: SocketAddr = "127.0.0.1:80".parse().unwrap();
        assert_eq!(
            create_tcp_filter(tcp, SocketOptions::default(), BindConfig::default()).name(),
            "TCP"
        );
        assert_eq!(
            create_udp_filter(tcp, TRNSPRT_UDP, BindConfig::default()).name(),
            "UDP"
        );
    }

    #[test]
    fn is_socket_filter_matches_the_four_vtables() {
        assert!(is_socket_filter("TCP"));
        assert!(is_socket_filter("UDP"));
        assert!(is_socket_filter("UNIX"));
        assert!(is_socket_filter("TCP-ACCEPT"));
        // The SOCKS proxy filter is deliberately not a socket filter.
        assert!(!is_socket_filter("SOCKS"));
        assert!(!is_socket_filter("HAPROXY"));
    }

    /// A minimal non-socket filter for the negative `socket_peek` path.
    struct NonSocketMock {
        state: CfState,
    }
    impl ConnectionFilter for NonSocketMock {
        fn name(&self) -> &'static str {
            "NOT-A-SOCKET"
        }
        fn cf_state(&self) -> &CfState {
            &self.state
        }
        fn cf_state_mut(&mut self) -> &mut CfState {
            &mut self.state
        }
    }

    #[test]
    fn socket_peek_succeeds_on_socket_filter() {
        // On a (yet unconnected) TCP filter, peek reports SOCKET_BAD + the
        // construction-time quadruple, mirroring C reading `ctx->sock`/`ctx->ip`.
        let cf = make_tcp_filter_v4();
        let peek = socket_peek(cf.as_ref()).expect("peek ok");
        assert_eq!(peek.socket, SOCKET_BAD);
        assert!(peek.remote_addr.is_none());
        assert_eq!(peek.ip.remote_ip, "127.0.0.1");
        assert_eq!(peek.ip.remote_port, 80);
    }

    #[test]
    fn socket_peek_rejects_non_socket_filter() {
        // C: `cf_is_socket(cf)` false → `CURLE_FAILED_INIT`.
        let cf = NonSocketMock {
            state: CfState::new(),
        };
        assert!(matches!(socket_peek(&cf), Err(CurlError::FailedInit)));
    }

    // ---- `SocksProxyConfig` host/port precedence
    //      (C: `socks_proxy_cf_connect`, socks.c L1244-1257). The host and port
    //      precedences deliberately differ; these tests pin both orders. ------

    #[cfg(feature = "proxy")]
    fn base_socks_config() -> SocksProxyConfig {
        // Every override channel is populated with a distinct value, all
        // *disabled* by default, so each test enables exactly the bits it needs
        // and can assert which value won.
        SocksProxyConfig {
            httpproxy: false,
            secondary: false,
            conn_to_host_set: false,
            conn_to_port_set: false,
            proxy_host: Some("proxy.example".to_string()),
            proxy_port: 1080,
            conn_to_host: Some("connect-to.example".to_string()),
            conn_to_port: 8080,
            secondary_host: Some("secondary.example".to_string()),
            secondary_port: 2121,
            target_host: "target.example".to_string(),
            target_port: 443,
            proxy_user: None,
            proxy_password: None,
            proxytype: CurlProxyType::Socks5,
            socks5_auth: 1, // CURLAUTH_BASIC
            ip_version: IpVersion::Any,
            ipv6_ip: false,
            verbose: false,
        }
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn socks_precedence_default_is_target() {
        let cfg = base_socks_config();
        let p = cfg.to_socks_params();
        assert_eq!(p.hostname, "target.example");
        assert_eq!(p.remote_port, 443);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn socks_precedence_httpproxy_wins_both() {
        let mut cfg = base_socks_config();
        cfg.httpproxy = true;
        // Even with everything else set, the HTTP proxy host/port win.
        cfg.conn_to_host_set = true;
        cfg.secondary = true;
        let p = cfg.to_socks_params();
        assert_eq!(p.hostname, "proxy.example");
        assert_eq!(p.remote_port, 1080);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn socks_precedence_host_vs_port_diverge() {
        // The crux: with `conn_to_host` AND `secondary` both active (no
        // httpproxy), the *host* resolves to `conn_to_host` (checked first for
        // the host) while the *port* resolves to the secondary port (checked
        // first for the port). This is curl's deliberate asymmetry.
        let mut cfg = base_socks_config();
        cfg.conn_to_host_set = true;
        cfg.conn_to_port_set = true;
        cfg.secondary = true;
        let p = cfg.to_socks_params();
        assert_eq!(p.hostname, "connect-to.example");
        assert_eq!(p.remote_port, 2121);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn socks_precedence_secondary_only() {
        let mut cfg = base_socks_config();
        cfg.secondary = true;
        let p = cfg.to_socks_params();
        assert_eq!(p.hostname, "secondary.example");
        assert_eq!(p.remote_port, 2121);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn socks_to_params_maps_all_fields() {
        let mut cfg = base_socks_config();
        cfg.proxy_user = Some("alice".to_string());
        cfg.proxy_password = Some("s3cr3t".to_string());
        cfg.socks5_auth = 3;
        cfg.ipv6_ip = true;
        cfg.verbose = true;
        cfg.proxytype = CurlProxyType::Socks5Hostname;
        let p = cfg.to_socks_params();
        assert_eq!(p.proxy_user.as_deref(), Some("alice"));
        assert_eq!(p.proxy_password.as_deref(), Some("s3cr3t"));
        assert_eq!(p.socks5_auth, 3);
        assert!(p.ipv6_ip);
        assert!(p.verbose);
        assert_eq!(p.proxytype, CurlProxyType::Socks5Hostname);
    }

    // ---- Integration: real `tokio::net` round-trips ------------------------
    // (`AsyncReadExt`/`AsyncWriteExt` for the server-side raw socket I/O are
    // already in scope via `use super::*`, which re-exports the module imports.)

    /// Connect the TCP filter to a local listener and exchange bytes, exercising
    /// the async-collapsed `connect`, `send`, `recv`, and the post-connect
    /// queries (C: `cf_tcp_connect`/`cf_socket_send`/`cf_socket_recv`).
    #[cfg_attr(miri, ignore)]
    #[test]
    fn tcp_connect_send_recv_roundtrip() {
        run(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("local_addr");
            let server = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.expect("accept");
                let mut buf = [0u8; 4];
                s.read_exact(&mut buf).await.expect("server read");
                assert_eq!(&buf, b"ping");
                s.write_all(b"pong").await.expect("server write");
            });

            let mut data = FilterData::new();
            let mut cf = create_tcp_filter(addr, SocketOptions::default(), BindConfig::default());
            cf.connect(&mut data).await.expect("connect");
            assert!(cf.is_connected());

            // Post-connect queries now report a live socket and the peer.
            match cf.query(CfQuery::Socket).expect("socket") {
                CfQueryResult::Socket(fd) => assert!(fd >= 0, "expected live fd, got {fd}"),
                other => panic!("expected Socket, got {other:?}"),
            }
            match cf.query(CfQuery::RemoteAddr).expect("remote") {
                CfQueryResult::RemoteAddr(a) => assert_eq!(a, Some(addr)),
                other => panic!("expected RemoteAddr, got {other:?}"),
            }

            assert_eq!(cf.send(b"ping", false).await.expect("send"), 4);

            let mut got = [0u8; 4];
            let mut filled = 0;
            while filled < 4 {
                match cf.recv(&mut got[filled..]).await {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(CurlError::Again) => tokio::task::yield_now().await,
                    Err(e) => panic!("recv failed: {e:?}"),
                }
            }
            assert_eq!(&got, b"pong");

            // `close` is the synchronous trait method (drops the socket via
            // `Drop`, clears the connected bit).
            cf.close();
            assert!(!cf.is_connected());
            server.await.expect("server task");
        });
    }

    /// UNIX-domain round-trip (C: the `Curl_cft_unix` filter / `TRNSPRT_UNIX`),
    /// realising `CURLOPT_UNIX_SOCKET_PATH`.
    #[cfg(unix)]
    #[cfg_attr(miri, ignore)]
    #[test]
    fn unix_connect_send_recv_roundtrip() {
        run(async {
            let path = std::env::temp_dir().join(format!(
                "blitzy_adhoc_test_curlrs_unix_{}.sock",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&path);
            let listener = tokio::net::UnixListener::bind(&path).expect("unix bind");
            let server = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.expect("unix accept");
                let mut buf = [0u8; 4];
                s.read_exact(&mut buf).await.expect("server read");
                assert_eq!(&buf, b"PING");
                s.write_all(b"PONG").await.expect("server write");
            });

            let mut data = FilterData::new();
            let mut cf = create_unix_filter(UnixTarget::path(&path));
            cf.connect(&mut data).await.expect("unix connect");
            assert!(cf.is_connected());
            // UNIX transport is reported by the query.
            match cf.query(CfQuery::Transport).expect("transport") {
                CfQueryResult::Transport(t) => assert_eq!(t, TRNSPRT_UNIX),
                other => panic!("expected Transport, got {other:?}"),
            }

            assert_eq!(cf.send(b"PING", false).await.expect("send"), 4);
            let mut got = [0u8; 4];
            let mut filled = 0;
            while filled < 4 {
                match cf.recv(&mut got[filled..]).await {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(CurlError::Again) => tokio::task::yield_now().await,
                    Err(e) => panic!("recv failed: {e:?}"),
                }
            }
            assert_eq!(&got, b"PONG");

            cf.close();
            server.await.expect("server task");
            let _ = std::fs::remove_file(&path);
        });
    }

    /// The accept filter times out when no server connects back, mapping to
    /// `CurlError::FtpAcceptTimeout` (C: `cf_tcp_accept_connect`'s
    /// `CURLE_FTP_ACCEPT_TIMEOUT` branch, cf-socket.c L2015+).
    #[test]
    fn accept_filter_times_out() {
        run(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let mut data = FilterData::new();
            // Small budget; nobody connects → timeout.
            let mut cf = create_tcp_accept_filter(listener, 120);
            let res = cf.connect(&mut data).await;
            assert!(
                matches!(res, Err(CurlError::FtpAcceptTimeout)),
                "expected FtpAcceptTimeout, got {res:?}"
            );
        });
    }

    /// The accept filter completes when a client connects back (FTP active
    /// mode happy path).
    #[test]
    fn accept_filter_accepts_inbound() {
        run(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("local_addr");
            let client = tokio::spawn(async move {
                let mut s = tokio::net::TcpStream::connect(addr)
                    .await
                    .expect("client connect");
                s.write_all(b"hi").await.expect("client write");
                tokio::time::sleep(Duration::from_millis(50)).await;
            });

            let mut data = FilterData::new();
            let mut cf = create_tcp_accept_filter(listener, 5_000);
            cf.connect(&mut data).await.expect("accept");
            assert!(cf.is_connected());
            match cf.query(CfQuery::Socket).expect("socket") {
                CfQueryResult::Socket(fd) => assert!(fd >= 0),
                other => panic!("expected Socket, got {other:?}"),
            }
            client.await.expect("client task");
        });
    }

    /// End-to-end SOCKS5: the SOCKS filter connects the socket below to a mock
    /// SOCKS5 proxy, then negotiates the tunnel through the [`CfStream`] adapter
    /// (C: `socks_proxy_cf_connect`, socks.c L1215). This validates the adapter
    /// bridging `recv`/`send` ↔ `AsyncRead`/`AsyncWrite` and the filter wiring.
    #[cfg(feature = "proxy")]
    #[cfg_attr(miri, ignore)]
    #[test]
    fn socks5_filter_negotiates_through_cfstream() {
        run(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let proxy_addr = listener.local_addr().expect("local_addr");
            let server = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.expect("accept");
                // Greeting: VER=5, NMETHODS=1, METHOD=00 (no-auth; BASIC-only).
                let mut greet = [0u8; 3];
                s.read_exact(&mut greet).await.expect("read greeting");
                assert_eq!(greet, [0x05, 0x01, 0x00]);
                s.write_all(&[0x05, 0x00]).await.expect("method reply");
                // CONNECT to 127.0.0.1:80 → [05 01 00 01 127 0 0 1 00 50].
                let mut req = [0u8; 10];
                s.read_exact(&mut req).await.expect("read connect");
                assert_eq!(req, [0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50]);
                // Success reply with a bound IPv4 0.0.0.0:0.
                s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .expect("connect reply");
                tokio::time::sleep(Duration::from_millis(50)).await;
            });

            let mut data = FilterData::new();
            // Bottom TCP filter connected to the proxy itself.
            let mut tcp =
                create_tcp_filter(proxy_addr, SocketOptions::default(), BindConfig::default());
            tcp.connect(&mut data).await.expect("tcp connect to proxy");

            // SOCKS filter wrapping that TCP filter, targeting 127.0.0.1:80.
            let mut cfg = base_socks_config();
            cfg.target_host = "127.0.0.1".to_string();
            cfg.target_port = 80;
            cfg.proxytype = CurlProxyType::Socks5;
            cfg.socks5_auth = 1; // CURLAUTH_BASIC → deterministic single-method greeting
            let mut socks = CfSocksProxy::new(cfg);
            socks.state = CfState::with_next(tcp);

            // Guard against a hang so any adapter bug is a clean failure.
            let res = tokio::time::timeout(Duration::from_secs(5), socks.connect(&mut data))
                .await
                .expect("socks connect did not hang");
            res.expect("socks handshake");
            assert!(socks.is_connected());
            assert!(matches!(socks.proxy_code(), CurlProxyCode::Ok));
            server.await.expect("server task");
        });
    }

    /// A SOCKS filter built over an HTTP (non-SOCKS) proxytype must reject with
    /// `CouldntConnect` *before* attempting any handshake (C: the `default:`
    /// branch of the proxytype switch → "unknown proxytype option given",
    /// socks.c L1273-1276).
    #[cfg(feature = "proxy")]
    #[test]
    fn socks_filter_rejects_non_socks_proxytype() {
        run(async {
            // A trivial already-connected leaf so `next.connect()` succeeds.
            struct Connected {
                state: CfState,
            }
            impl ConnectionFilter for Connected {
                fn name(&self) -> &'static str {
                    "CONNECTED-LEAF"
                }
                fn cf_state(&self) -> &CfState {
                    &self.state
                }
                fn cf_state_mut(&mut self) -> &mut CfState {
                    &mut self.state
                }
            }
            // `next.connect()` (the trait default) marks this leaf connected, so
            // the SOCKS filter reaches the proxytype check and rejects there.
            let leaf = Connected {
                state: CfState::new(),
            };

            let mut cfg = base_socks_config();
            cfg.proxytype = CurlProxyType::Http; // not a SOCKS type
            let mut socks = CfSocksProxy::new(cfg);
            socks.state = CfState::with_next(Box::new(leaf));

            let mut data = FilterData::new();
            let res = socks.connect(&mut data).await;
            assert!(
                matches!(res, Err(CurlError::CouldntConnect)),
                "expected CouldntConnect, got {res:?}"
            );
            assert!(!socks.is_connected());
        });
    }
}
