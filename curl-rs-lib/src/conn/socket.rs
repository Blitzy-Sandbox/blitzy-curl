//! The socket connection filter — the bottom (tail) filter of every chain.
//!
//! This module is the safe-Rust reimplementation of curl's `lib/cf-socket.c`
//! (the TCP/UDP/UNIX socket filters) and `lib/cf-socket.h` (the
//! `Curl_sockaddr_ex` address type, the `Curl_cf_tcp_create` /
//! `Curl_cf_udp_create` / `Curl_cf_unix_create` factories, the four
//! `Curl_cft_tcp` / `Curl_cft_udp` / `Curl_cft_unix` / `Curl_cft_tcp_accept`
//! type descriptors, and the `Curl_cf_socket_peek` /
//! `Curl_conn_tcp_listen_set` / `Curl_conn_is_tcp_listen` helpers).
//!
//! # Role in the filter chain
//!
//! The socket filter is the **tail** of every connection chain: it owns the
//! operating-system socket and performs the actual TCP connect, UDP setup, or
//! UNIX-domain-socket connect, plus all `send`/`recv` traffic and socket-option
//! configuration. Because it is the tail it **never delegates**
//! `connect`/`send`/`recv` to a `next` filter — it *is* the bottom.
//!
//! # Memory-safety contract
//!
//! Per the workspace-wide `#![forbid(unsafe_code)]` policy this module contains
//! **zero `unsafe`**. All networking uses [`tokio::net`] and all socket-option
//! and raw-file-descriptor access goes through [`socket2`]'s safe wrappers
//! ([`socket2::SockRef::from`] borrows the descriptor of an established Tokio
//! stream without dropping to raw `libc`). This is precisely the class of
//! manual-memory / raw-syscall bugs the C-to-Rust rewrite exists to eliminate.
//!
//! # Async model
//!
//! curl's C code performs a *non-blocking* `connect(2)` and drives it to
//! completion by polling the descriptor for writability. Under Tokio the
//! equivalent is `TcpSocket::connect(..).await`, which registers the descriptor
//! with the reactor and yields until the connect completes; the overall connect
//! deadline (`--connect-timeout`) is enforced with [`tokio::time::timeout`].

use std::any::Any;
use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, IntoRawFd};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, SockRef, TcpKeepalive, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket, UnixStream};
use tokio::time::timeout;

use crate::conn::filters::{
    CfFuture, ConnectionFilter, FilterChain, FilterCtx, IpQuadruple, Pollset, QueryCtx, QueryOut,
    POLL_IN, POLL_OUT,
};
use crate::conn::{CfQuery, CfType, Transport, CF_CTRL_CONN_INFO_UPDATE, CF_CTRL_FORGET_SOCKET};
use crate::dns;
use crate::error::{CurlCode, Error, Result};

// ===========================================================================
// Raw descriptor alias — the reimplementation of curl's `curl_socket_t`.
// ===========================================================================

/// A raw socket file descriptor, mirroring curl's `curl_socket_t`.
///
/// On the supported Unix targets (`*-linux-gnu`, `*-apple-darwin`) a file
/// descriptor is a `c_int`, i.e. an [`i32`]; this matches the `i32` payload of
/// [`QueryOut::Socket`](crate::conn::filters::QueryOut::Socket) so the value
/// answered by [`CfQuery::Socket`] needs no conversion.
pub type RawSocket = i32;

/// The invalid-socket sentinel, mirroring curl's `CURL_SOCKET_BAD`
/// (`(curl_socket_t)-1`). Returned by [`CfQuery::Socket`] when no descriptor is
/// currently held (e.g. before connect or after `close`).
pub const CURL_SOCKET_BAD: RawSocket = -1;

// The IPPROTO_IP protocol number (0). curl's `sock_assign_addr` assigns this
// protocol to UNIX-domain sockets, which have no IP-level protocol.
const IPPROTO_IP: i32 = 0;

// ===========================================================================
// SockAddrEx — the reimplementation of `struct Curl_sockaddr_ex`.
// ===========================================================================

/// The concrete address a socket filter connects (or binds) to, together with
/// the socket `family` / `socktype` / `protocol` triple.
///
/// This is the safe-Rust reimplementation of curl's `struct Curl_sockaddr_ex`
/// (`lib/cf-socket.h`), which stores `int family; int socktype; int protocol;`
/// alongside a `union { struct sockaddr sa; ... }` address. Here the raw
/// `sockaddr` union is replaced by the strongly-typed [`SocketAddrKind`], and
/// the C `addrlen` field is implicit in that enum (it is recomputed on demand
/// by [`to_sockaddr`](Self::to_sockaddr)).
///
/// The `family` / `socktype` / `protocol` values are assigned exactly as curl's
/// `sock_assign_addr` does:
///
/// | transport      | family                | socktype       | protocol       |
/// |----------------|-----------------------|----------------|----------------|
/// | TCP            | `AF_INET`/`AF_INET6`  | `SOCK_STREAM`  | `IPPROTO_TCP`  |
/// | UDP / QUIC     | `AF_INET`/`AF_INET6`  | `SOCK_DGRAM`   | `IPPROTO_UDP`  |
/// | UNIX           | `AF_UNIX`             | `SOCK_STREAM`  | `IPPROTO_IP` 0 |
#[derive(Debug, Clone)]
pub struct SockAddrEx {
    /// The address family (`AF_INET` / `AF_INET6` / `AF_UNIX`), as the platform
    /// integer obtained from [`socket2::Domain`].
    pub family: i32,
    /// The socket type (`SOCK_STREAM` / `SOCK_DGRAM`), as the platform integer
    /// obtained from [`socket2::Type`].
    pub socktype: i32,
    /// The protocol (`IPPROTO_TCP` / `IPPROTO_UDP` / `IPPROTO_IP`), as the
    /// platform integer obtained from [`socket2::Protocol`].
    pub protocol: i32,
    /// The address itself: an IP socket address or a UNIX-domain path.
    pub addr: SocketAddrKind,
}

/// The address payload of a [`SockAddrEx`]: either an IP `SocketAddr`
/// (IPv4/IPv6) or a UNIX-domain path.
///
/// This replaces the raw `union` in curl's `Curl_sockaddr_ex`. For UNIX
/// addresses the `abstract_ns` flag mirrors curl's
/// `conn->bits.abstract_unix_socket`: when set, the `path` names an entry in the
/// Linux *abstract* namespace (curl represents this with a leading NUL byte);
/// the stored `path` never includes that leading NUL.
#[derive(Debug, Clone)]
pub enum SocketAddrKind {
    /// An IPv4 or IPv6 socket address.
    Inet(SocketAddr),
    /// A UNIX-domain socket path (`abstract_ns` selects the abstract namespace).
    Unix {
        /// The filesystem path (or abstract name, without the leading NUL).
        path: String,
        /// Whether `path` names an entry in the Linux abstract namespace.
        abstract_ns: bool,
    },
}

impl SockAddrEx {
    /// Builds a TCP address descriptor for `addr`
    /// (`SOCK_STREAM` + `IPPROTO_TCP`), matching `sock_assign_addr` for the
    /// `TRNSPRT_TCP` transport.
    #[must_use]
    pub fn tcp(addr: SocketAddr) -> Self {
        SockAddrEx {
            family: i32::from(domain_of(&addr)),
            socktype: i32::from(Type::STREAM),
            protocol: i32::from(Protocol::TCP),
            addr: SocketAddrKind::Inet(addr),
        }
    }

    /// Builds a UDP address descriptor for `addr`
    /// (`SOCK_DGRAM` + `IPPROTO_UDP`), matching `sock_assign_addr` for the
    /// `TRNSPRT_UDP` / `TRNSPRT_QUIC` transports (QUIC runs over a UDP socket).
    #[must_use]
    pub fn udp(addr: SocketAddr) -> Self {
        SockAddrEx {
            family: i32::from(domain_of(&addr)),
            socktype: i32::from(Type::DGRAM),
            protocol: i32::from(Protocol::UDP),
            addr: SocketAddrKind::Inet(addr),
        }
    }

    /// Builds a UNIX-domain address descriptor for `path`
    /// (`AF_UNIX` + `SOCK_STREAM` + `IPPROTO_IP`), matching `sock_assign_addr`
    /// for the `TRNSPRT_UNIX` transport. `abstract_ns` selects the Linux
    /// abstract namespace.
    #[must_use]
    pub fn unix(path: impl Into<String>, abstract_ns: bool) -> Self {
        SockAddrEx {
            family: i32::from(Domain::UNIX),
            socktype: i32::from(Type::STREAM),
            protocol: IPPROTO_IP,
            addr: SocketAddrKind::Unix {
                path: path.into(),
                abstract_ns,
            },
        }
    }

    /// Builds the address descriptor appropriate for `transport`, given an IP
    /// `addr`. TCP transports produce a stream descriptor; UDP/QUIC transports
    /// produce a datagram descriptor; other transports default to TCP so an
    /// IP address always yields a usable descriptor.
    ///
    /// UNIX-domain addresses are not IP addresses and must be constructed with
    /// [`unix`](Self::unix) instead.
    #[must_use]
    pub fn for_transport(addr: SocketAddr, transport: Transport) -> Self {
        match transport {
            Transport::Udp | Transport::Quic => Self::udp(addr),
            _ => Self::tcp(addr),
        }
    }

    /// Returns the contained IP socket address, or `None` for a UNIX address.
    #[must_use]
    pub fn as_inet(&self) -> Option<SocketAddr> {
        match self.addr {
            SocketAddrKind::Inet(addr) => Some(addr),
            SocketAddrKind::Unix { .. } => None,
        }
    }

    /// Returns the UNIX-domain `(path, abstract_ns)` pair, or `None` for an IP
    /// address.
    #[must_use]
    pub fn as_unix(&self) -> Option<(&str, bool)> {
        match &self.addr {
            SocketAddrKind::Unix { path, abstract_ns } => Some((path.as_str(), *abstract_ns)),
            SocketAddrKind::Inet(_) => None,
        }
    }

    /// Returns `true` if this is an IPv6 address (used to answer
    /// [`CfQuery::IpInfo`]'s `is_ipv6` flag).
    #[must_use]
    pub fn is_ipv6(&self) -> bool {
        matches!(self.addr, SocketAddrKind::Inet(SocketAddr::V6(_)))
    }

    /// Converts this address to a [`socket2::SockAddr`] for use with the
    /// `socket2` socket API.
    ///
    /// For a non-abstract UNIX path this delegates to
    /// [`socket2::SockAddr::unix`]. Abstract UNIX names cannot be expressed as a
    /// `socket2::SockAddr` on stable Rust and are handled directly by the
    /// connect path instead, so this returns [`Error::bad_argument`] for them.
    pub fn to_sockaddr(&self) -> Result<SockAddr> {
        match &self.addr {
            SocketAddrKind::Inet(addr) => Ok(SockAddr::from(*addr)),
            SocketAddrKind::Unix {
                path,
                abstract_ns: false,
            } => SockAddr::unix(path)
                .map_err(|e| Error::bad_argument(format!("invalid unix socket path: {e}"))),
            SocketAddrKind::Unix {
                abstract_ns: true, ..
            } => Err(Error::bad_argument(
                "abstract unix socket addresses are handled by the connect path",
            )),
        }
    }
}

impl From<SocketAddr> for SockAddrEx {
    /// Converts a bare [`SocketAddr`] into a **TCP** descriptor — the most
    /// common case (Happy-Eyeballs feeds resolved IP endpoints straight into
    /// [`tcp_create`]). Use [`SockAddrEx::udp`] / [`SockAddrEx::for_transport`]
    /// for datagram transports.
    fn from(addr: SocketAddr) -> Self {
        SockAddrEx::tcp(addr)
    }
}

/// Returns the [`socket2::Domain`] (`AF_INET` / `AF_INET6`) for an IP address.
fn domain_of(addr: &SocketAddr) -> Domain {
    match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    }
}

// ===========================================================================
// SocketKind — the four `Curl_cft_*` socket-filter descriptors.
// ===========================================================================

/// Which of curl's four socket-filter descriptors this filter embodies.
///
/// curl declares four `Curl_cftype` descriptors that all share the socket
/// implementation but differ in name and connect entry point: `Curl_cft_tcp`,
/// `Curl_cft_udp`, `Curl_cft_unix`, and `Curl_cft_tcp_accept`. Modeling them as
/// one struct with a `kind` field (rather than four structs) keeps the shared
/// `send`/`recv`/`query`/option logic in one place, exactly as `cf-socket.c`
/// shares `cf_socket_send` etc. across all four descriptors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketKind {
    /// A TCP stream socket (`Curl_cft_tcp`).
    Tcp,
    /// A UDP datagram socket (`Curl_cft_udp`), also the base for QUIC/HTTP-3.
    Udp,
    /// A UNIX-domain stream socket (`Curl_cft_unix`).
    Unix,
    /// A TCP listen/accept socket (`Curl_cft_tcp_accept`) for active-mode FTP.
    TcpAccept,
}

impl SocketKind {
    /// The filter's stable trace name, matching curl's `cft->name` verbatim so
    /// `--trace`/`-v` output is byte-identical: `"TCP"`, `"UDP"`, `"UNIX"`, or
    /// `"TCP-ACCEPT"`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            SocketKind::Tcp => "TCP",
            SocketKind::Udp => "UDP",
            SocketKind::Unix => "UNIX",
            SocketKind::TcpAccept => "TCP-ACCEPT",
        }
    }
}

/// Returns `true` if `name` is one of the socket-filter names, mirroring curl's
/// `cf_is_socket` (true for the TCP, UDP, UNIX, and TCP-ACCEPT descriptors).
///
/// Used by [`is_tcp_listen`] and by [`SockAddrEx`]-level peek guards to decide
/// whether a filter in a chain is a socket filter.
#[must_use]
pub fn is_socket_filter(name: &str) -> bool {
    matches!(name, "TCP" | "UDP" | "UNIX" | "TCP-ACCEPT")
}

// ===========================================================================
// SocketStream — the established Tokio socket, one variant per transport.
// ===========================================================================

/// The established operating-system socket owned by a connected socket filter.
///
/// Holding the Tokio socket by value means dropping the [`SocketFilter`] (or
/// clearing this field in `close`) closes the descriptor via `Drop` — the
/// safe-Rust replacement for curl's explicit `Curl_socket_close`.
enum SocketStream {
    /// A connected TCP stream.
    Tcp(TcpStream),
    /// A connected (peer-associated) UDP socket.
    Udp(UdpSocket),
    /// A connected UNIX-domain stream.
    Unix(UnixStream),
}

impl SocketStream {
    /// Returns the raw file descriptor of the underlying socket (safe;
    /// [`AsRawFd`] never touches unsafe code).
    fn raw_fd(&self) -> RawSocket {
        match self {
            SocketStream::Tcp(s) => s.as_raw_fd(),
            SocketStream::Udp(s) => s.as_raw_fd(),
            SocketStream::Unix(s) => s.as_raw_fd(),
        }
    }

    /// Consumes the stream, returning its raw descriptor **without closing it**
    /// (converts the Tokio socket back to a std socket, then releases ownership
    /// of the descriptor). This is the safe implementation of curl's
    /// `CF_CTRL_FORGET_SOCKET` handoff, where the descriptor's lifetime passes
    /// to another owner. Returns `None` if the socket could not be converted
    /// back to blocking std form.
    fn into_forgotten_fd(self) -> Option<RawSocket> {
        match self {
            SocketStream::Tcp(s) => s.into_std().ok().map(|s| s.into_raw_fd()),
            SocketStream::Udp(s) => s.into_std().ok().map(|s| s.into_raw_fd()),
            SocketStream::Unix(s) => s.into_std().ok().map(|s| s.into_raw_fd()),
        }
    }
}

// ===========================================================================
// SocketOptions — the socket-option toggles curl reads from `data->set.*`.
// ===========================================================================

/// The socket options a socket filter applies before/after connect, mirroring
/// the `data->set.*` fields curl consults in `cf-socket.c`.
///
/// The defaults match curl 8.x: `TCP_NODELAY` **on** (curl enables it unless
/// `--no-tcp-nodelay`), keepalive **off**, and — when keepalive is later
/// enabled — the 60-second idle/interval and 9-probe defaults curl seeds in
/// `Curl_init_userdefined` (`CURL_KEEPALIVE_*`).
#[derive(Debug, Clone)]
pub struct SocketOptions {
    /// Enable `TCP_NODELAY` (disable Nagle's algorithm). Default `true`.
    pub tcp_nodelay: bool,
    /// Enable `SO_KEEPALIVE` and the keepalive timers below. Default `false`.
    pub tcp_keepalive: bool,
    /// Idle time before the first keepalive probe (`TCP_KEEPIDLE`).
    pub keepidle: Duration,
    /// Interval between keepalive probes (`TCP_KEEPINTVL`).
    ///
    /// Note: curl also exposes `TCP_KEEPCNT` (probe count), but that option is
    /// only reachable through `socket2`'s `"all"` feature, which the workspace
    /// does not enable; idle and interval fully satisfy the keepalive parity the
    /// agent specification requires.
    pub keepintvl: Duration,
    /// Explicit `SO_SNDBUF` size, if curl set `CURLOPT_UPLOAD_BUFFERSIZE`-style
    /// buffering; `None` leaves the OS default.
    pub sndbuf: Option<u32>,
    /// Explicit `SO_RCVBUF` size; `None` leaves the OS default.
    pub rcvbuf: Option<u32>,
    /// Request TCP Fast Open (`bits.tcp_fastopen`). Default `false`. Applied on
    /// a best-effort basis where the platform exposes it through `socket2`.
    pub tcp_fastopen: bool,
}

impl Default for SocketOptions {
    fn default() -> Self {
        SocketOptions {
            tcp_nodelay: true,
            tcp_keepalive: false,
            keepidle: Duration::from_secs(60),
            keepintvl: Duration::from_secs(60),
            sndbuf: None,
            rcvbuf: None,
            tcp_fastopen: false,
        }
    }
}

// ===========================================================================
// LocalBind — the local-endpoint binding curl derives from CURLOPT_INTERFACE.
// ===========================================================================

/// The optional local endpoint a socket binds to before connecting, mirroring
/// curl's `bindlocal` inputs (`data->set.device` / `localport` /
/// `localportrange`).
///
/// All fields are optional/zero by default (bind to any address and any port).
#[derive(Debug, Clone, Default)]
pub struct LocalBind {
    /// A network interface name to bind to (`--interface eth0`), applied via
    /// `SO_BINDTODEVICE` where supported. curl's `data->set.device`.
    pub interface: Option<String>,
    /// A specific local IP address to bind to. curl's parsed `--interface`
    /// host form.
    pub address: Option<IpAddr>,
    /// The first local port to try (`--local-port`); `0` means any port.
    pub port: u16,
    /// How many sequential ports to try starting at [`port`](Self::port)
    /// (`--local-port low-high`).
    pub port_range: u16,
}

// ===========================================================================
// SocketFilter — the connection filter itself (one `cf_socket_ctx`).
// ===========================================================================

/// The socket connection filter: the tail filter that owns the OS socket.
///
/// This is the reimplementation of curl's `struct cf_socket_ctx` plus the four
/// `Curl_cft_*` descriptors it backs. One value is created **per candidate
/// address** by Happy-Eyeballs (via [`tcp_create`] / [`udp_create`] /
/// [`unix_create`]); the winner is promoted to the *active* filter (curl's
/// `_active` distinction) via [`set_active`](Self::set_active).
pub struct SocketFilter {
    /// Which of the four socket descriptors this filter embodies.
    kind: SocketKind,
    /// The transport this socket carries (`TRNSPRT_TCP`/`UDP`/`QUIC`/`UNIX`).
    transport: Transport,
    /// The remote address to connect to (or, for `TcpAccept`, unused).
    remote: SockAddrEx,
    /// Socket options to apply around connect.
    opts: SocketOptions,
    /// Optional local-endpoint binding.
    local_bind: LocalBind,
    /// The overall connect deadline (`--connect-timeout`); `None` = no deadline
    /// beyond the OS default.
    connect_timeout: Option<Duration>,
    /// The connected IP quadruple (remote/local IP+port), for `--trace` and the
    /// HAProxy PROXY header. Empty until connected.
    ip: IpQuadruple,
    /// The established socket, set once connect completes.
    stream: Option<SocketStream>,
    /// When the connect attempt started (curl's `started_at`).
    started_at: Option<Instant>,
    /// When the connect completed (curl's `connected_at`).
    connected_at: Option<Instant>,
    /// When the first inbound byte arrived (curl's `first_byte_at`).
    first_byte_at: Option<Instant>,
    /// Whether the first inbound byte has been observed.
    got_first_byte: bool,
    /// For the accept variant: whether the socket is currently listening.
    listening: bool,
    /// For the accept variant: whether an inbound connection was accepted.
    accepted: bool,
    /// Whether this filter has been promoted to the active/winning filter
    /// (curl's `cf_socket_active`).
    active: bool,
    /// For the accept variant: the local address to bind+listen on.
    listen_bind: Option<SocketAddr>,
    /// For the accept variant: the bound listening socket, awaiting an inbound
    /// connection. Established by [`listen`](SocketFilter::listen) and consumed
    /// by the accept `connect`.
    listener: Option<TcpListener>,
    /// A descriptor handed off via `CF_CTRL_FORGET_SOCKET` (kept so
    /// [`CfQuery::Socket`] can still report it after the stream is released).
    forgotten_fd: Option<RawSocket>,
}

impl SocketFilter {
    /// Creates a socket filter of the given `kind` for `remote` on `transport`,
    /// with default options and no local binding. This is the shared
    /// constructor behind the public factories.
    fn new(kind: SocketKind, remote: SockAddrEx, transport: Transport) -> Self {
        SocketFilter {
            kind,
            transport,
            remote,
            opts: SocketOptions::default(),
            local_bind: LocalBind::default(),
            connect_timeout: None,
            ip: IpQuadruple::default(),
            stream: None,
            started_at: None,
            connected_at: None,
            first_byte_at: None,
            got_first_byte: false,
            listening: false,
            accepted: false,
            active: false,
            listen_bind: None,
            listener: None,
            forgotten_fd: None,
        }
    }

    /// Overrides the socket options (builder style). Returns `self` for
    /// chaining at construction time.
    #[must_use]
    pub fn with_options(mut self, opts: SocketOptions) -> Self {
        self.opts = opts;
        self
    }

    /// Sets the local-endpoint binding (builder style).
    #[must_use]
    pub fn with_local_bind(mut self, local_bind: LocalBind) -> Self {
        self.local_bind = local_bind;
        self
    }

    /// Sets the overall connect deadline (builder style).
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Promotes this filter to the active/winning filter, mirroring curl's
    /// `cf_socket_active` transition (invoked when Happy-Eyeballs selects this
    /// candidate). Idempotent.
    pub fn set_active(&mut self) {
        self.active = true;
    }

    /// Returns whether the socket is connected (has an established stream).
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.stream.is_some() && self.connected_at.is_some()
    }

    /// Returns whether this accept filter has accepted an inbound connection
    /// (curl's `ctx->accepted`). Always `false` for the non-accept variants.
    #[must_use]
    pub fn is_accepted(&self) -> bool {
        self.accepted
    }

    /// Returns the current raw descriptor: the live stream's fd, else a
    /// forgotten (handed-off) fd, else `None`.
    fn raw_fd(&self) -> Option<RawSocket> {
        match &self.stream {
            Some(stream) => Some(stream.raw_fd()),
            None => self.forgotten_fd,
        }
    }

    /// The connected IP quadruple (remote/local IP+port). Read by
    /// `haproxy.rs` to build the PROXY header and by the chain's
    /// established-connection trace.
    #[must_use]
    pub fn ip_quadruple(&self) -> &IpQuadruple {
        &self.ip
    }

    /// Peeks at the socket's descriptor, address, and IP quadruple, mirroring
    /// curl's `Curl_cf_socket_peek`.
    ///
    /// Returns [`Error::Code`]`(`[`CurlCode::FailedInit`]`)` when invoked on a
    /// filter that is not a socket filter — the same `CURLE_FAILED_INIT` guard
    /// curl applies via `cf_is_socket`. Since a [`SocketFilter`] is always a
    /// socket filter this guard is defensive and, in practice, always passes.
    pub fn socket_peek(&self) -> Result<(RawSocket, &SockAddrEx, &IpQuadruple)> {
        if !is_socket_filter(self.kind.name()) {
            return Err(Error::Code(CurlCode::FailedInit));
        }
        Ok((
            self.raw_fd().unwrap_or(CURL_SOCKET_BAD),
            &self.remote,
            &self.ip,
        ))
    }

    /// Eagerly binds and starts listening on the accept filter's configured
    /// address, returning the bound local address. Mirrors the socket-creation
    /// half of curl's `Curl_conn_tcp_listen_set`, which binds the listen socket
    /// so the local port is known (e.g. for the FTP `PORT`/`EPRT` command)
    /// before an inbound connection is accepted.
    ///
    /// Idempotent: if already listening it simply returns the current local
    /// address. Returns [`Error::bad_argument`] if invoked on a non-accept
    /// filter or when no bind address was configured.
    pub async fn listen(&mut self) -> Result<SocketAddr> {
        if self.kind != SocketKind::TcpAccept {
            return Err(Error::bad_argument(
                "listen() is only valid on a TCP-ACCEPT socket filter",
            ));
        }
        if let Some(listener) = &self.listener {
            return listener.local_addr().map_err(map_connect_err);
        }
        let bind_addr = self
            .listen_bind
            .ok_or_else(|| Error::bad_argument("no listen bind address configured"))?;
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(map_connect_err)?;
        let local = listener.local_addr().map_err(map_connect_err)?;
        self.ip.local_ip = local.ip().to_string();
        self.ip.local_port = local.port();
        self.listening = true;
        self.listener = Some(listener);
        Ok(local)
    }

    /// Returns the bound local address of the accept filter's listening socket,
    /// or `None` if it is not yet listening.
    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.listener.as_ref().and_then(|l| l.local_addr().ok())
    }
}

// ===========================================================================
// Factory functions — the `Curl_cf_*_create` constructors.
// ===========================================================================

/// Creates a TCP socket filter for `addr`, mirroring curl's
/// `Curl_cf_tcp_create`. Happy-Eyeballs calls this once per candidate address.
#[must_use]
pub fn tcp_create(addr: SockAddrEx, transport: Transport) -> Box<dyn ConnectionFilter> {
    Box::new(SocketFilter::new(SocketKind::Tcp, addr, transport))
}

/// Creates a UDP socket filter for `addr`, mirroring curl's
/// `Curl_cf_udp_create`. This is also the base socket for QUIC/HTTP-3
/// (`TRNSPRT_QUIC`), which runs its handshake over the UDP datagram socket.
#[must_use]
pub fn udp_create(addr: SockAddrEx, transport: Transport) -> Box<dyn ConnectionFilter> {
    Box::new(SocketFilter::new(SocketKind::Udp, addr, transport))
}

/// Creates a UNIX-domain socket filter for `addr`, mirroring curl's
/// `Curl_cf_unix_create`.
#[must_use]
pub fn unix_create(addr: SockAddrEx, transport: Transport) -> Box<dyn ConnectionFilter> {
    Box::new(SocketFilter::new(SocketKind::Unix, addr, transport))
}

/// Creates a TCP accept/listen filter that binds and listens on `bind_addr`,
/// then accepts one inbound connection. This mirrors curl's
/// `Curl_cft_tcp_accept` descriptor, used for active-mode FTP data channels.
#[must_use]
pub fn tcp_accept_create(bind_addr: SocketAddr) -> Box<dyn ConnectionFilter> {
    let mut cf = SocketFilter::new(
        SocketKind::TcpAccept,
        SockAddrEx::tcp(bind_addr),
        Transport::Tcp,
    );
    cf.listening = true;
    cf.listen_bind = Some(bind_addr);
    Box::new(cf)
}

/// Builds one [`SockAddrEx`] per resolved endpoint in `addr` for the given
/// `transport`, ready to be fed into [`tcp_create`] / [`udp_create`] by the
/// Happy-Eyeballs candidate loop.
///
/// This bridges [`crate::dns::Address`] (the resolver's result) to the socket
/// layer without coupling the socket module to any particular resolver: it
/// simply maps each `SocketAddr` endpoint to the transport-appropriate
/// descriptor.
#[must_use]
pub fn sockaddrs_from_address(addr: &dns::Address, transport: Transport) -> Vec<SockAddrEx> {
    addr.endpoints()
        .iter()
        .map(|ep| SockAddrEx::for_transport(*ep, transport))
        .collect()
}

// ===========================================================================
// Listen-chain helpers — `Curl_conn_is_tcp_listen`.
// ===========================================================================

/// Returns `true` if the tail of `chain` is a TCP accept/listen filter,
/// mirroring curl's `Curl_conn_is_tcp_listen` (which walks the chain looking
/// for a `Curl_cft_tcp_accept` filter).
///
/// The accept filter is always installed at the tail of a listen chain, so
/// inspecting [`FilterChain::tail`] is sufficient.
#[must_use]
pub fn is_tcp_listen(chain: &FilterChain) -> bool {
    chain
        .tail()
        .is_some_and(|f| f.name() == SocketKind::TcpAccept.name())
}

// ===========================================================================
// Connect helpers — the socket-open + option + bind + connect machinery.
//
// These are free functions (not methods) so the async connect future does not
// need to hold a long-lived borrow of `self`: `connect` copies the small
// configuration out of `self`, awaits the helper, then writes the resulting
// stream and IP quadruple back. This keeps the borrow checker happy without any
// interior mutability or unsafe.
// ===========================================================================

/// Maps a connect-time [`std::io::Error`] to the curl-parity [`Error`].
///
/// curl's `socket_connect_result` maps **all** kernel connect failures
/// (`ECONNREFUSED`, `ENETUNREACH`, `EHOSTUNREACH`, kernel `ETIMEDOUT`, …) to
/// `CURLE_COULDNT_CONNECT`. The *overall* connect deadline (`--connect-timeout`)
/// is enforced separately by [`tokio::time::timeout`] and maps to
/// [`Error::Timeout`] (`CURLE_OPERATION_TIMEDOUT`); it is never routed through
/// this function.
fn map_connect_err(e: std::io::Error) -> Error {
    Error::connect(e.to_string())
}

/// Builds the connected [`IpQuadruple`] from a stream's local and peer
/// addresses. The IP fields store the bare textual address (no brackets), which
/// is how curl records them; the chain's established-connection trace adds
/// IPv6 brackets when it formats the line.
fn ip_quadruple_from(local: SocketAddr, remote: SocketAddr) -> IpQuadruple {
    IpQuadruple {
        remote_ip: remote.ip().to_string(),
        remote_port: remote.port(),
        local_ip: local.ip().to_string(),
        local_port: local.port(),
    }
}

/// Applies curl's pre-connect socket options to a freshly created
/// [`TcpSocket`]. Matches curl's behavior of **logging and continuing** on an
/// option failure rather than aborting the connect (`tcpnodelay`/`tcpkeepalive`
/// in `cf-socket.c` only emit a trace on `setsockopt` failure).
fn apply_tcp_options(socket: &TcpSocket, opts: &SocketOptions) {
    // TCP_NODELAY: curl enables it by default (disabled only via
    // `--no-tcp-nodelay`).
    if let Err(e) = socket.set_nodelay(opts.tcp_nodelay) {
        tracing::debug!(error = %e, "could not set TCP_NODELAY");
    }

    // SO_KEEPALIVE + TCP_KEEPIDLE/TCP_KEEPINTVL when keepalive is requested.
    if opts.tcp_keepalive {
        let keepalive = TcpKeepalive::new()
            .with_time(opts.keepidle)
            .with_interval(opts.keepintvl);
        if let Err(e) = SockRef::from(socket).set_tcp_keepalive(&keepalive) {
            tracing::debug!(error = %e, "could not set SO_KEEPALIVE");
        }
    }

    // Explicit send/receive buffer sizes, when curl configured them.
    if let Some(size) = opts.sndbuf {
        if let Err(e) = socket.set_send_buffer_size(size) {
            tracing::debug!(error = %e, "could not set SO_SNDBUF");
        }
    }
    if let Some(size) = opts.rcvbuf {
        if let Err(e) = socket.set_recv_buffer_size(size) {
            tracing::debug!(error = %e, "could not set SO_RCVBUF");
        }
    }

    // TCP Fast Open: socket2 0.5 (without the `all` feature) exposes no
    // unsafe-free, portable TFO setter. Per the parity mandate we neither drop
    // to raw `libc` nor change observable behavior — the connect proceeds
    // without TFO, which differs only in first-flight latency.
    if opts.tcp_fastopen {
        tracing::debug!("TCP Fast Open requested but not applied (no unsafe-free socket2 API)");
    }
}

/// Returns `true` if any local-endpoint binding (interface / address / port) is
/// configured, mirroring the condition under which curl runs `bindlocal`.
fn wants_local_bind(bind: &LocalBind) -> bool {
    bind.interface.is_some() || bind.address.is_some() || bind.port != 0
}

/// Applies the pre-bind local-endpoint setup — interface binding
/// (`SO_BINDTODEVICE`) and `SO_REUSEADDR` — to a freshly created [`TcpSocket`].
///
/// Interface binding is fatal on failure (as in curl, since `--interface` is an
/// explicit user request) and maps to `CURLE_INTERFACE_FAILED`; `SO_REUSEADDR`
/// is best-effort (curl sets it in `bindlocal` so an explicit local port can be
/// reused promptly).
fn prepare_local_bind(socket: &TcpSocket, bind: &LocalBind) -> Result<()> {
    if let Some(interface) = &bind.interface {
        socket
            .bind_device(Some(interface.as_bytes()))
            .map_err(|e| {
                Error::with_context(
                    CurlCode::InterfaceFailed,
                    format!("could not bind to interface {interface}: {e}"),
                )
            })?;
    }
    if let Err(e) = socket.set_reuseaddr(true) {
        tracing::debug!(error = %e, "could not set SO_REUSEADDR");
    }
    Ok(())
}

/// Computes the local [`SocketAddr`] to bind for the given family and port. An
/// explicit local address wins; otherwise the wildcard address of the correct
/// family is used so only the port is pinned.
fn local_bind_addr(bind: &LocalBind, is_v6: bool, port: u16) -> SocketAddr {
    let local_ip = match bind.address {
        Some(addr) => addr,
        None if is_v6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };
    SocketAddr::new(local_ip, port)
}

/// Returns the sequence of local ports to attempt for a bind, honoring curl's
/// `--local-port low[-high]` range. When no explicit port is configured this is
/// a single "any port" (`0`) attempt.
fn local_port_attempts(bind: &LocalBind) -> Vec<u16> {
    if bind.port == 0 {
        return vec![0];
    }
    let range = bind.port_range.max(1);
    (0..range)
        .map(|offset| bind.port.saturating_add(offset))
        .collect()
}

/// Opens, options, binds, and connects a TCP socket to `remote`, honoring the
/// optional local-port range and the overall connect deadline. Returns the
/// established stream plus its connected IP quadruple.
///
/// This is the async equivalent of curl's `cf_tcp_connect`: open the socket,
/// apply options, `bindlocal`, then non-blocking connect driven to completion.
async fn tcp_connect_inner(
    remote: SocketAddr,
    opts: &SocketOptions,
    bind: &LocalBind,
    deadline: Option<Duration>,
) -> Result<(TcpStream, IpQuadruple)> {
    let is_v6 = matches!(remote, SocketAddr::V6(_));
    let need_bind = wants_local_bind(bind);

    // Create the socket to connect with. When a local bind is requested, try
    // each candidate local port until one binds (curl retries the range on
    // EADDRINUSE); otherwise a single unbound socket is used.
    let socket = if need_bind {
        let ports = local_port_attempts(bind);
        let last_index = ports.len() - 1;
        let mut bound = None;
        for (index, port) in ports.into_iter().enumerate() {
            let candidate = new_tcp_socket(is_v6)?;
            apply_tcp_options(&candidate, opts);
            prepare_local_bind(&candidate, bind)?;

            let local_addr = local_bind_addr(bind, is_v6, port);
            match candidate.bind(local_addr) {
                Ok(()) => {
                    bound = Some(candidate);
                    break;
                }
                // Retry the next port in the range only on EADDRINUSE.
                Err(e) if index < last_index && e.kind() == ErrorKind::AddrInUse => continue,
                Err(e) => {
                    return Err(Error::with_context(
                        CurlCode::InterfaceFailed,
                        format!("could not bind to {local_addr}: {e}"),
                    ))
                }
            }
        }
        // The loop either bound a socket or returned an error on the final port.
        match bound {
            Some(s) => s,
            None => new_tcp_socket(is_v6)?,
        }
    } else {
        let candidate = new_tcp_socket(is_v6)?;
        apply_tcp_options(&candidate, opts);
        candidate
    };

    tracing::debug!(%remote, "  Trying {remote}...");

    // Drive the non-blocking connect to completion, bounded by the connect
    // deadline. A timeout maps to CURLE_OPERATION_TIMEDOUT; any kernel connect
    // error maps to CURLE_COULDNT_CONNECT.
    let stream = match deadline {
        Some(dur) => match timeout(dur, socket.connect(remote)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => return Err(map_connect_err(e)),
            Err(_elapsed) => return Err(Error::Timeout),
        },
        None => socket.connect(remote).await.map_err(map_connect_err)?,
    };

    let local = stream.local_addr().map_err(map_connect_err)?;
    let peer = stream.peer_addr().unwrap_or(remote);
    Ok((stream, ip_quadruple_from(local, peer)))
}

/// Creates a fresh [`TcpSocket`] of the correct address family, mapping a
/// creation failure to `CURLE_COULDNT_CONNECT`.
fn new_tcp_socket(is_v6: bool) -> Result<TcpSocket> {
    if is_v6 {
        TcpSocket::new_v6()
    } else {
        TcpSocket::new_v4()
    }
    .map_err(map_connect_err)
}

/// Binds and connects a UDP socket to `remote`. Used both for plain UDP
/// transports and as the base datagram socket for QUIC/HTTP-3 — curl's
/// `cf_udp_connect` likewise establishes the UDP socket that the QUIC filter
/// then drives.
async fn udp_connect_inner(
    remote: SocketAddr,
    deadline: Option<Duration>,
) -> Result<(UdpSocket, IpQuadruple)> {
    let bind_addr = match remote {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind_addr).await.map_err(map_connect_err)?;

    // Associate the peer so subsequent send/recv target it (curl connects the
    // UDP socket in `cf_udp_connect`). This is effectively instantaneous, but
    // honor the deadline for symmetry with the TCP path.
    match deadline {
        Some(dur) => match timeout(dur, socket.connect(remote)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(map_connect_err(e)),
            Err(_elapsed) => return Err(Error::Timeout),
        },
        None => socket.connect(remote).await.map_err(map_connect_err)?,
    }

    let local = socket.local_addr().map_err(map_connect_err)?;
    let peer = socket.peer_addr().unwrap_or(remote);
    Ok((socket, ip_quadruple_from(local, peer)))
}

/// Connects a UNIX-domain stream to `path`, honoring the connect deadline and
/// the Linux abstract namespace. Mirrors curl's UNIX-socket connect path.
async fn unix_connect_inner(
    path: &str,
    abstract_ns: bool,
    deadline: Option<Duration>,
) -> Result<(UnixStream, IpQuadruple)> {
    let stream = if abstract_ns {
        connect_abstract_unix(path)?
    } else {
        let connect = UnixStream::connect(path);
        match deadline {
            Some(dur) => match timeout(dur, connect).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => return Err(map_connect_err(e)),
                Err(_elapsed) => return Err(Error::Timeout),
            },
            None => connect.await.map_err(map_connect_err)?,
        }
    };

    // UNIX-domain sockets have no IP quadruple; record the path as the remote
    // "address" so `--trace` and PROXY-header consumers have a stable value.
    let ip = IpQuadruple {
        remote_ip: path.to_string(),
        remote_port: 0,
        local_ip: String::new(),
        local_port: 0,
    };
    Ok((stream, ip))
}

/// Connects to a UNIX-domain socket in the Linux **abstract** namespace.
///
/// The abstract namespace has no filesystem entry (curl represents it with a
/// leading NUL byte); Rust's std exposes it through
/// [`std::os::linux::net::SocketAddrExt::from_abstract_name`]. The connect is
/// performed on a blocking std socket (an abstract connect completes locally and
/// immediately) which is then switched to non-blocking and adopted by Tokio via
/// [`UnixStream::from_std`] — all without `unsafe`.
#[cfg(target_os = "linux")]
fn connect_abstract_unix(name: &str) -> Result<UnixStream> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr as StdUnixSocketAddr, UnixStream as StdUnixStream};

    let addr = StdUnixSocketAddr::from_abstract_name(name.as_bytes())
        .map_err(|e| Error::connect(format!("invalid abstract unix name: {e}")))?;
    let std_stream = StdUnixStream::connect_addr(&addr).map_err(map_connect_err)?;
    std_stream.set_nonblocking(true).map_err(map_connect_err)?;
    UnixStream::from_std(std_stream).map_err(map_connect_err)
}

/// Abstract UNIX sockets are a Linux-only feature; on other platforms a request
/// for one is a connect error rather than a silent fallback.
#[cfg(not(target_os = "linux"))]
fn connect_abstract_unix(_name: &str) -> Result<UnixStream> {
    Err(Error::connect(
        "abstract unix sockets are only supported on Linux",
    ))
}

// ===========================================================================
// Per-transport connect drivers (inherent async methods).
//
// `connect` dispatches to one of these based on `kind`. They are inherent
// methods (not free functions) because they write their results back into
// `self`; each copies the small immutable config it needs out of `self` before
// awaiting a free helper, so no long-lived borrow of `self` crosses the await.
// ===========================================================================

impl SocketFilter {
    /// Connects a TCP stream (curl's `cf_tcp_connect`).
    async fn connect_tcp(&mut self) -> Result<bool> {
        let remote = self
            .remote
            .as_inet()
            .ok_or_else(|| Error::Code(CurlCode::FailedInit))?;
        let opts = self.opts.clone();
        let bind = self.local_bind.clone();
        let deadline = self.connect_timeout;

        let (stream, ip) = tcp_connect_inner(remote, &opts, &bind, deadline).await?;
        self.ip = ip;
        self.connected_at = Some(Instant::now());
        self.stream = Some(SocketStream::Tcp(stream));
        Ok(true)
    }

    /// Establishes the UDP datagram socket (curl's `cf_udp_connect`); also the
    /// base socket for QUIC/HTTP-3.
    async fn connect_udp(&mut self) -> Result<bool> {
        let remote = self
            .remote
            .as_inet()
            .ok_or_else(|| Error::Code(CurlCode::FailedInit))?;
        let deadline = self.connect_timeout;

        let (socket, ip) = udp_connect_inner(remote, deadline).await?;
        self.ip = ip;
        self.connected_at = Some(Instant::now());
        self.stream = Some(SocketStream::Udp(socket));
        Ok(true)
    }

    /// Connects a UNIX-domain stream.
    async fn connect_unix(&mut self) -> Result<bool> {
        let (path, abstract_ns) = self
            .remote
            .as_unix()
            .map(|(p, a)| (p.to_string(), a))
            .ok_or_else(|| Error::Code(CurlCode::FailedInit))?;
        let deadline = self.connect_timeout;

        let (stream, ip) = unix_connect_inner(&path, abstract_ns, deadline).await?;
        self.ip = ip;
        self.connected_at = Some(Instant::now());
        self.stream = Some(SocketStream::Unix(stream));
        Ok(true)
    }

    /// Accepts an inbound connection on the listening socket (curl's
    /// `cf_tcp_accept_connect`), binding+listening lazily if the caller did not
    /// already call [`listen`](Self::listen).
    async fn connect_accept(&mut self) -> Result<bool> {
        if self.listener.is_none() {
            self.listen().await?;
        }
        let deadline = self.connect_timeout;
        // Own the listener so the accept future does not borrow `self`.
        let listener = self
            .listener
            .take()
            .ok_or_else(|| Error::Code(CurlCode::FailedInit))?;

        let result = match deadline {
            Some(dur) => match timeout(dur, listener.accept()).await {
                Ok(inner) => {
                    inner.map_err(|e| Error::with_context(CurlCode::FtpAcceptFailed, e.to_string()))
                }
                Err(_elapsed) => Err(Error::Code(CurlCode::FtpAcceptTimeout)),
            },
            None => listener
                .accept()
                .await
                .map_err(|e| Error::with_context(CurlCode::FtpAcceptFailed, e.to_string())),
        };

        let (stream, peer) = match result {
            Ok(pair) => pair,
            Err(e) => {
                // Restore the listener so a later connect can retry the accept.
                self.listener = Some(listener);
                return Err(e);
            }
        };

        let local = stream.local_addr().unwrap_or(peer);
        self.ip = ip_quadruple_from(local, peer);
        self.accepted = true;
        self.listening = false;
        self.connected_at = Some(Instant::now());
        self.stream = Some(SocketStream::Tcp(stream));
        // The listen socket is closed once a connection is accepted (curl closes
        // it in cf_tcp_accept_connect); dropping `listener` here does that.
        Ok(true)
    }
}

// ===========================================================================
// Stream I/O helpers — generic over the Tokio stream types.
// ===========================================================================

/// Writes `buf` to a byte stream, mapping errors to curl's send-error codes.
///
/// curl's `cf_socket_send` maps `EWOULDBLOCK`/`EAGAIN`/`EINTR`/`EINPROGRESS` to
/// `CURLE_AGAIN` and any other error to `CURLE_SEND_ERROR`. Under Tokio the
/// `.await` normally waits out the would-block condition, but the mapping is
/// preserved for the rare surfaced case.
async fn write_stream<S>(stream: &mut S, buf: &[u8]) -> Result<usize>
where
    S: AsyncWriteExt + Unpin,
{
    stream.write(buf).await.map_err(map_send_err)
}

/// Reads into `buf` from a byte stream, mapping errors to curl's recv-error
/// codes (`CURLE_AGAIN` for would-block/interrupted, `CURLE_RECV_ERROR`
/// otherwise). A return of `0` is end-of-stream, exactly as `cf_socket_recv`.
async fn read_stream<S>(stream: &mut S, buf: &mut [u8]) -> Result<usize>
where
    S: AsyncReadExt + Unpin,
{
    stream.read(buf).await.map_err(map_recv_err)
}

/// Maps a send-time [`std::io::Error`] to a curl-parity [`Error`].
fn map_send_err(e: std::io::Error) -> Error {
    match e.kind() {
        ErrorKind::WouldBlock | ErrorKind::Interrupted => Error::Again,
        _ => Error::Send,
    }
}

/// Maps a recv-time [`std::io::Error`] to a curl-parity [`Error`].
fn map_recv_err(e: std::io::Error) -> Error {
    match e.kind() {
        ErrorKind::WouldBlock | ErrorKind::Interrupted => Error::Again,
        _ => Error::Recv,
    }
}

/// Performs curl's cheap liveness probe: a non-blocking one-byte peek.
///
/// Mirrors `cf_socket_conn_is_alive`'s use of a zero-timeout poll + peek: a peek
/// returning `0` means the peer closed (dead); returning data means alive;
/// `WouldBlock` means idle-but-open (alive); any other error means dead.
fn socket_is_alive(sref: SockRef<'_>) -> bool {
    let mut probe = [MaybeUninit::<u8>::uninit(); 1];
    match sref.peek(&mut probe) {
        Ok(0) => false,
        Ok(_) => true,
        Err(e) if e.kind() == ErrorKind::WouldBlock => true,
        Err(_) => false,
    }
}

// ===========================================================================
// ConnectionFilter impl — the socket filter's vtable (the tail of the chain).
// ===========================================================================

impl ConnectionFilter for SocketFilter {
    fn name(&self) -> &'static str {
        self.kind.name()
    }

    fn cf_type(&self) -> CfType {
        // All four socket descriptors are CF_TYPE_IP_CONNECT in curl.
        CfType::IP_CONNECT
    }

    fn connect<'a>(
        &'a mut self,
        _cx: &'a mut FilterCtx<'_>,
        _blocking: bool,
    ) -> CfFuture<'a, Result<bool>> {
        Box::pin(async move {
            // Idempotent: already established (connected or accepted).
            if self.stream.is_some() {
                return Ok(true);
            }
            self.started_at.get_or_insert_with(Instant::now);

            // The socket filter is the chain tail: it never delegates connect.
            match self.kind {
                SocketKind::Tcp => self.connect_tcp().await,
                SocketKind::Udp => self.connect_udp().await,
                SocketKind::Unix => self.connect_unix().await,
                SocketKind::TcpAccept => self.connect_accept().await,
            }
        })
    }

    fn shutdown<'a>(&'a mut self, _cx: &'a mut FilterCtx<'_>) -> CfFuture<'a, Result<bool>> {
        Box::pin(async move {
            // Mirror cf_socket_shutdown: for a connected TCP socket, drain any
            // dangling inbound bytes (best-effort, non-blocking) so the peer's
            // FIN is observed cleanly. A socket shuts down immediately, so the
            // shutdown is always reported done.
            if let Some(SocketStream::Tcp(stream)) = self.stream.as_ref() {
                let mut scratch = [0u8; 1024];
                let _ = stream.try_read(&mut scratch);
            }
            Ok(true)
        })
    }

    fn close(&mut self, _cx: &mut FilterCtx<'_>) {
        // Dropping the owned socket closes the descriptor — the safe-Rust
        // replacement for curl's Curl_socket_close. As the chain tail there is
        // no next filter to delegate the close to.
        self.stream = None;
        self.listener = None;
        self.active = false;
        self.connected_at = None;
        self.started_at = None;
    }

    fn send<'a>(
        &'a mut self,
        _cx: &'a mut FilterCtx<'_>,
        buf: &'a [u8],
        _eos: bool,
    ) -> CfFuture<'a, Result<usize>> {
        Box::pin(async move {
            match self.stream.as_mut() {
                Some(SocketStream::Tcp(stream)) => write_stream(stream, buf).await,
                Some(SocketStream::Unix(stream)) => write_stream(stream, buf).await,
                Some(SocketStream::Udp(socket)) => socket.send(buf).await.map_err(map_send_err),
                // No established socket: nothing to send to.
                None => Err(Error::Send),
            }
        })
    }

    fn recv<'a>(
        &'a mut self,
        _cx: &'a mut FilterCtx<'_>,
        buf: &'a mut [u8],
    ) -> CfFuture<'a, Result<usize>> {
        Box::pin(async move {
            let n = match self.stream.as_mut() {
                Some(SocketStream::Tcp(stream)) => read_stream(stream, buf).await?,
                Some(SocketStream::Unix(stream)) => read_stream(stream, buf).await?,
                Some(SocketStream::Udp(socket)) => socket.recv(buf).await.map_err(map_recv_err)?,
                // No established socket: nothing to receive from.
                None => return Err(Error::Recv),
            };
            // Record the first-byte timestamp (curl's `first_byte_at`) used by
            // the CONNECT_REPLY_MS / TIMER_CONNECT queries.
            if n > 0 && !self.got_first_byte {
                self.got_first_byte = true;
                self.first_byte_at = Some(Instant::now());
            }
            Ok(n)
        })
    }

    fn adjust_pollset(&self, _cx: &QueryCtx<'_>, ps: &mut Pollset) {
        // Determine the descriptor to register: the live stream, else (for an
        // accept filter still awaiting a connection) the listening socket.
        let fd = match self.raw_fd() {
            Some(fd) => fd,
            None => match &self.listener {
                Some(listener) => listener.as_raw_fd(),
                None => return,
            },
        };

        // Mirror cf_socket_adjust_pollset's ordering exactly.
        if self.listening {
            // Waiting to accept an inbound connection → readable.
            ps.set(fd, POLL_IN);
        } else if self.connected_at.is_none() {
            // Connect still in progress → writable (curl waits for POLLOUT).
            ps.set(fd, POLL_OUT);
        } else if !self.active {
            // Connected but not yet the active filter → readable.
            ps.add_in(fd);
        }
    }

    fn is_alive(&mut self, _cx: &mut FilterCtx<'_>) -> bool {
        match self.stream.as_ref() {
            Some(SocketStream::Tcp(stream)) => socket_is_alive(SockRef::from(stream)),
            Some(SocketStream::Unix(stream)) => socket_is_alive(SockRef::from(stream)),
            // A connected UDP socket has no peer-close signal; treat it as alive.
            Some(SocketStream::Udp(_)) => true,
            None => false,
        }
    }

    fn cntrl(
        &mut self,
        _cx: &mut FilterCtx<'_>,
        event: i32,
        _arg1: i32,
        _arg2: Option<&mut dyn Any>,
    ) -> Result<()> {
        match event as u32 {
            // The socket filter has been selected as the active/winning filter.
            CF_CTRL_CONN_INFO_UPDATE => self.active = true,
            // Hand off the descriptor without closing it (curl sets sock=BAD):
            // release ownership of the Tokio stream, remembering the raw fd so
            // CF_QUERY_SOCKET can still report it.
            CF_CTRL_FORGET_SOCKET => {
                if let Some(stream) = self.stream.take() {
                    self.forgotten_fd = stream.into_forgotten_fd();
                }
            }
            // All other control events (DATA_SETUP, DATA_DONE, FLUSH, …) are
            // no-ops at the socket layer, matching cf_socket_cntrl.
            _ => {}
        }
        Ok(())
    }

    fn query(&self, cx: &QueryCtx<'_>, query: CfQuery, out: &mut QueryOut) -> Result<()> {
        match query {
            // The socket file descriptor (CURL_SOCKET_BAD if none held).
            CfQuery::Socket => {
                *out = QueryOut::Socket(self.raw_fd().unwrap_or(CURL_SOCKET_BAD));
                Ok(())
            }
            // The transport this socket carries.
            CfQuery::Transport => {
                *out = QueryOut::Transport(self.transport);
                Ok(())
            }
            // The IPv6 flag plus the connected IP quadruple; consumed by the
            // chain's established-connection trace and by haproxy.rs.
            CfQuery::IpInfo => {
                *out = QueryOut::IpInfo {
                    is_ipv6: self.remote.is_ipv6(),
                    quad: self.ip.clone(),
                };
                Ok(())
            }
            // The connected remote address as text; curl returns the address or
            // NULL, always with CURLE_OK.
            CfQuery::RemoteAddr => {
                if self.is_connected() {
                    *out = QueryOut::RemoteAddr(self.ip.remote_ip.clone());
                }
                Ok(())
            }
            // Milliseconds from connect-start to the first server byte, or -1 if
            // no byte has arrived (curl's CF_QUERY_CONNECT_REPLY_MS).
            CfQuery::ConnectReplyMs => {
                let ms = match (self.started_at, self.first_byte_at) {
                    (Some(start), Some(first)) => {
                        i64::try_from(first.saturating_duration_since(start).as_millis())
                            .unwrap_or(i64::MAX)
                    }
                    _ => -1,
                };
                *out = QueryOut::ConnectReplyMs(ms);
                Ok(())
            }
            // The instant the connection was established. For UDP/QUIC the
            // meaningful instant is the first-byte time (curl's special case).
            CfQuery::TimerConnect => {
                let when = match self.transport {
                    Transport::Udp | Transport::Quic => self.first_byte_at.or(self.connected_at),
                    _ => self.connected_at,
                };
                match when {
                    Some(instant) => {
                        *out = QueryOut::TimerConnect(instant);
                        Ok(())
                    }
                    // Not yet connected: fall through to the chain default.
                    None => cx.query_next(query, out),
                }
            }
            // Any other query is delegated; at the tail the chain default
            // returns CURLE_UNKNOWN_OPTION (curl's cf_socket_query default).
            _ => cx.query_next(query, out),
        }
    }
}
