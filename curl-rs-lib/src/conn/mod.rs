// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! # Connection subsystem — root module
//!
//! This is the root of curl's connection layer, rewritten from C to idiomatic,
//! memory-safe Rust. It is a language rewrite of curl's connection-filter
//! abstraction (`lib/cfilters.c` / `lib/cfilters.h`) together with the
//! connection portion of the `connectdata` structure (`lib/urldata.h`).
//!
//! ## What lives here
//!
//! * The [`Connection`] type — the Rust rewrite of curl's `struct connectdata`,
//!   restricted to the connection-relevant state (identity used for reuse
//!   matching, the per-socket filter chains, timestamps, and shutdown
//!   bookkeeping). A `Connection` **owns** its filter chains and, through them,
//!   the live sockets; dropping the value releases every resource, which is how
//!   Rust ownership replaces curl's manual `Curl_conn_free`.
//! * The [`Transport`] enum with the exact `TRNSPRT_*` numeric identity curl
//!   relies on (`lib/urldata.h`).
//! * The connection-filter type/control/query identity ([`CfType`], the
//!   `CF_CTRL_*` control events, [`CfQuery`]) shared by every filter module.
//! * [`ConnectBits`] — the per-connection diagnostic state flags, field-named
//!   identically to curl so `--trace` output stays equivalent.
//! * The high-level connection API (the `Curl_conn_*` entry points of
//!   `lib/cfilters.h`), surfaced as methods on [`Connection`].
//!
//! ## Filter chain
//!
//! Each socket index owns an optional [`FilterChain`] — a tower-inspired
//! middleware stack that composes layered transport behavior from the network
//! upward: **TCP → TLS → HTTP/2 → application**. Filters implement the
//! [`ConnectionFilter`] trait (defined in [`filters`]); the chain container
//! drives `connect`/`send`/`recv`/`shutdown` top-down exactly as curl's
//! `Curl_cfilter` chain does. The high-level predicates on [`Connection`]
//! (`is_ssl`, `is_ip_connected`, `is_multiplex`, …) walk the chain checking the
//! [`CfType`] capability bits, mirroring `cf_is_ssl` and friends in
//! `lib/cfilters.c`.
//!
//! ## Memory-safety and cycle avoidance
//!
//! The whole subtree is safe Rust: the crate root's `#![forbid(unsafe_code)]`
//! applies here, so there is zero `unsafe` in the connection logic. To avoid a
//! module dependency cycle, this module never imports `crate::protocols` (the
//! protocol handlers depend on the connection layer, not the other way around)
//! and never holds a strong reference back to the owning multi handle — the
//! [`Connection::attached_multi`] back-reference is an opaque [`MultiId`].

use std::sync::Arc;
use std::time::Instant;

use crate::dns;
use crate::error::{CurlCode, Error, Result};
use crate::tls::config::TlsConfig;

// ===========================================================================
// Sibling submodules of the connection subsystem.
//
// `mod.rs` owns the cross-cutting identity (constants, `Connection`,
// `ConnectBits`, `Transport`); the sibling modules below own the concrete
// connection-filter implementations (the socket, proxy-tunnel, and shutdown
// filters). They are declared here so the `conn/` folder forms a single module
// tree, and are intentionally left ungated: the per-protocol / per-transport
// feature gating lives inside the individual modules, not on the module
// declaration.
// ===========================================================================

pub mod filters;
pub mod h1_proxy;
pub mod h2_proxy;
pub mod shutdown;
pub mod socket;

// ---------------------------------------------------------------------------
// Curated public surface re-exported from the sibling modules.
// ---------------------------------------------------------------------------

/// The connection-filter trait and the chain container that composes filters
/// into a tower-style middleware stack. Defined in [`filters`].
pub use filters::{ConnectionFilter, FilterChain};

// ===========================================================================
// Socket index constants (`lib/urldata.h`).
//
// A connection can have one or two sockets (and therefore one or two filter
// chains). The protocol using the second one is FTP, for its separate CONTROL
// and DATA channels.
// ===========================================================================

/// Index of the primary socket / filter chain (`FIRSTSOCKET`).
pub const FIRSTSOCKET: usize = 0;

/// Index of the secondary socket / filter chain (`SECONDARYSOCKET`), used by
/// FTP for the data channel.
pub const SECONDARYSOCKET: usize = 1;

/// The number of sockets (and filter chains) a connection may hold.
///
/// Mirrors the fixed `sock[2]` / `cfilter[2]` arrays in curl's `connectdata`
/// and the `CONN_SOCK_IDX_VALID` bound.
pub const CONN_SOCKET_COUNT: usize = 2;

// ===========================================================================
// SSL mode selectors for the connection-setup filter (`lib/cfilters.h`).
//
// Consumed by the connection-setup logic to decide whether a TLS filter is
// installed when the connection filter chain is being assembled.
// ===========================================================================

/// `CURL_CF_SSL_DEFAULT` — use the scheme's default TLS policy.
pub const CURL_CF_SSL_DEFAULT: i32 = -1;

/// `CURL_CF_SSL_DISABLE` — force TLS off for this chain.
pub const CURL_CF_SSL_DISABLE: i32 = 0;

/// `CURL_CF_SSL_ENABLE` — force TLS on for this chain.
pub const CURL_CF_SSL_ENABLE: i32 = 1;

// ===========================================================================
// Transport — the `TRNSPRT_*` identity (`lib/urldata.h`).
//
// curl relies on the exact numeric values (they are stored in `connectdata`
// and reported through the `CF_QUERY_TRANSPORT` query), so the discriminants
// are frozen here: NONE=0, TCP=3, UDP=4, QUIC=5, UNIX=6.
// ===========================================================================

/// The transport a connection uses (or wants to use), mirroring curl's
/// `TRNSPRT_*` defines. The discriminants are part of the ABI/trace identity
/// and must not change.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Transport {
    /// `TRNSPRT_NONE` — no transport selected yet.
    #[default]
    None = 0,
    /// `TRNSPRT_TCP` — a stream (TCP) transport.
    Tcp = 3,
    /// `TRNSPRT_UDP` — a datagram (UDP) transport.
    Udp = 4,
    /// `TRNSPRT_QUIC` — a QUIC transport (HTTP/3).
    Quic = 5,
    /// `TRNSPRT_UNIX` — a Unix-domain-socket transport.
    Unix = 6,
}

impl Transport {
    /// Returns the raw `TRNSPRT_*` byte value for this transport.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Maps a raw `TRNSPRT_*` byte to a [`Transport`], returning [`None`](Option::None)
    /// for values that do not correspond to a known transport.
    ///
    /// This is the lossy/optional counterpart to the fallible
    /// [`TryFrom<u8>`](Transport::try_from) conversion.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Transport::None),
            3 => Some(Transport::Tcp),
            4 => Some(Transport::Udp),
            5 => Some(Transport::Quic),
            6 => Some(Transport::Unix),
            _ => None,
        }
    }
}

impl From<Transport> for u8 {
    fn from(value: Transport) -> Self {
        value as u8
    }
}

impl TryFrom<u8> for Transport {
    type Error = Error;

    /// Converts a raw `TRNSPRT_*` byte into a [`Transport`]. An unrecognized
    /// value is rejected as a bad argument (`CURLE_BAD_FUNCTION_ARGUMENT`),
    /// mirroring curl's treatment of out-of-range enum inputs.
    fn try_from(value: u8) -> Result<Self> {
        Transport::from_u8(value)
            .ok_or_else(|| Error::BadFunctionArgument(format!("invalid transport value: {value}")))
    }
}

// ===========================================================================
// Connection-filter TYPE flags (`lib/cfilters.h`).
//
// A filter can carry none, one, or many of these capability bits; the chain
// predicates (`is_ssl`, `is_ip_connected`, `is_multiplex`) evaluate them while
// walking the chain. Modeled as a small `u32` bitflag newtype so no external
// `bitflags` crate is required.
// ===========================================================================

/// A set of connection-filter capability bits (`CF_TYPE_*`).
///
/// The individual bits are exposed as associated constants; combine them with
/// `|` and test membership with [`CfType::contains`] / [`CfType::intersects`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CfType(u32);

impl CfType {
    /// `CF_TYPE_IP_CONNECT` (`1 << 0`) — provides an IP connection or an
    /// equivalent (a `CONNECT` tunnel, a Unix-domain socket, a QUIC connection).
    pub const IP_CONNECT: CfType = CfType(1);
    /// `CF_TYPE_SSL` (`1 << 1`) — provides SSL/TLS.
    pub const SSL: CfType = CfType(1 << 1);
    /// `CF_TYPE_MULTIPLEX` (`1 << 2`) — provides multiplexing of easy handles.
    pub const MULTIPLEX: CfType = CfType(1 << 2);
    /// `CF_TYPE_PROXY` (`1 << 3`) — provides proxying.
    pub const PROXY: CfType = CfType(1 << 3);
    /// `CF_TYPE_HTTP` (`1 << 4`) — implements a version of the HTTP protocol.
    pub const HTTP: CfType = CfType(1 << 4);

    /// Creates a [`CfType`] set from its raw bit representation.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        CfType(bits)
    }

    /// Returns the raw bit representation of this flag set.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns `true` if this set has no bits set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if this set contains **all** bits of `other`.
    #[must_use]
    pub const fn contains(self, other: CfType) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns `true` if this set shares **any** bit with `other`.
    #[must_use]
    pub const fn intersects(self, other: CfType) -> bool {
        (self.0 & other.0) != 0
    }
}

impl std::ops::BitOr for CfType {
    type Output = CfType;

    fn bitor(self, rhs: CfType) -> CfType {
        CfType(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for CfType {
    fn bitor_assign(&mut self, rhs: CfType) {
        self.0 |= rhs.0;
    }
}

// ===========================================================================
// Connection-filter CONTROL events (`lib/cfilters.h`).
//
// Control messages are passed down the filter chain top-down. The values are
// frozen for parity with any FFI/trace path. The two "connection info" groups
// live at the 256+ offset in curl; the exact integers are preserved.
// ===========================================================================

/// `CF_CTRL_DATA_SETUP` — filters should set up data for a transfer.
pub const CF_CTRL_DATA_SETUP: u32 = 4;
/// `CF_CTRL_DATA_PAUSE` — the transfer is being paused/unpaused.
pub const CF_CTRL_DATA_PAUSE: u32 = 6;
/// `CF_CTRL_DATA_DONE` — the transfer finished (possibly prematurely).
pub const CF_CTRL_DATA_DONE: u32 = 7;
/// `CF_CTRL_DATA_DONE_SEND` — the transfer finished sending its request body.
pub const CF_CTRL_DATA_DONE_SEND: u32 = 8;
/// `CF_CTRL_CONN_INFO_UPDATE` (`256 + 0`) — persist connection info.
pub const CF_CTRL_CONN_INFO_UPDATE: u32 = 256;
/// `CF_CTRL_FORGET_SOCKET` (`256 + 1`) — filters should forget the socket.
pub const CF_CTRL_FORGET_SOCKET: u32 = 257;
/// `CF_CTRL_FLUSH` (`256 + 2`) — flush any buffered outbound data.
pub const CF_CTRL_FLUSH: u32 = 258;

// ===========================================================================
// Connection-filter QUERY selectors (`lib/cfilters.h`).
//
// A query travels down the chain; a filter ignorant of it passes it on. The
// exact integer values matter for parity of any FFI/trace paths, so the
// discriminants are frozen (1..=15).
// ===========================================================================

/// The property queried from a filter chain (`CF_QUERY_*`).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfQuery {
    /// `CF_QUERY_MAX_CONCURRENT` — max parallel transfers the chain expects.
    MaxConcurrent = 1,
    /// `CF_QUERY_CONNECT_REPLY_MS` — ms until the first server response.
    ConnectReplyMs = 2,
    /// `CF_QUERY_SOCKET` — the socket used by the chain.
    Socket = 3,
    /// `CF_QUERY_TIMER_CONNECT` — the connect timestamp.
    TimerConnect = 4,
    /// `CF_QUERY_TIMER_APPCONNECT` — the app-connect (TLS done) timestamp.
    TimerAppConnect = 5,
    /// `CF_QUERY_STREAM_ERROR` — the underlying stream error code.
    StreamError = 6,
    /// `CF_QUERY_NEED_FLUSH` — whether any filter has unsent data.
    NeedFlush = 7,
    /// `CF_QUERY_IP_INFO` — IPv6 flag plus the ip quadruple.
    IpInfo = 8,
    /// `CF_QUERY_HTTP_VERSION` — negotiated HTTP version (10/11/20/30).
    HttpVersion = 9,
    /// `CF_QUERY_REMOTE_ADDR` — the connected remote address.
    RemoteAddr = 10,
    /// `CF_QUERY_HOST_PORT` — the remote host name and port.
    HostPort = 11,
    /// `CF_QUERY_SSL_INFO` — TLS session info.
    SslInfo = 12,
    /// `CF_QUERY_SSL_CTX_INFO` — TLS context info.
    SslCtxInfo = 13,
    /// `CF_QUERY_TRANSPORT` — the `TRNSPRT_*` in use.
    Transport = 14,
    /// `CF_QUERY_ALPN_NEGOTIATED` — the ALPN protocol the server selected.
    AlpnNegotiated = 15,
}

impl CfQuery {
    /// Returns the raw `CF_QUERY_*` integer value for this selector.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl TryFrom<i32> for CfQuery {
    type Error = Error;

    /// Converts a raw `CF_QUERY_*` integer into a [`CfQuery`]. Values outside
    /// `1..=15` are rejected as a bad argument (`CURLE_BAD_FUNCTION_ARGUMENT`).
    fn try_from(value: i32) -> Result<Self> {
        let query = match value {
            1 => CfQuery::MaxConcurrent,
            2 => CfQuery::ConnectReplyMs,
            3 => CfQuery::Socket,
            4 => CfQuery::TimerConnect,
            5 => CfQuery::TimerAppConnect,
            6 => CfQuery::StreamError,
            7 => CfQuery::NeedFlush,
            8 => CfQuery::IpInfo,
            9 => CfQuery::HttpVersion,
            10 => CfQuery::RemoteAddr,
            11 => CfQuery::HostPort,
            12 => CfQuery::SslInfo,
            13 => CfQuery::SslCtxInfo,
            14 => CfQuery::Transport,
            15 => CfQuery::AlpnNegotiated,
            _ => {
                return Err(Error::BadFunctionArgument(format!(
                    "invalid CF_QUERY selector: {value}"
                )))
            }
        };
        Ok(query)
    }
}

// ===========================================================================
// ConnectBits — per-connection diagnostic state flags (`lib/urldata.h`).
//
// The field names are preserved verbatim from curl's `struct ConnectBits` so
// that `--trace`/diagnostic output remains equivalent. In C several of these
// live behind `#ifdef` guards (proxy, FTP, netrc, DOH, Unix sockets); here they
// are always present as plain `bool`s — a disabled feature simply leaves the
// corresponding flag `false`, which is behavior-equivalent.
// ===========================================================================

/// The boolean state flags carried by a [`Connection`], mirroring curl's
/// `struct ConnectBits`. All flags default to `false`.
///
/// The `close` flag must only ever be changed through
/// [`Connection::conn_control`] (curl's `connclose`/`connkeep`/`streamclose`
/// macros), never assigned directly, so that stream-vs-connection closure
/// semantics on multiplexed connections are honored.
#[derive(Debug, Default, Clone)]
pub struct ConnectBits {
    /// This transfer is done through an HTTP proxy.
    pub httpproxy: bool,
    /// This transfer is done through a SOCKS proxy.
    pub socksproxy: bool,
    /// A username + password is set for the proxy.
    pub proxy_user_passwd: bool,
    /// `CONNECT` is used to tunnel through the proxy.
    pub tunnel_proxy: bool,
    /// This transfer is done through a proxy of any type.
    pub proxy: bool,
    /// The connection is closed after this request (assign only via
    /// [`Connection::conn_control`]).
    pub close: bool,
    /// This is a reused connection.
    pub reuse: bool,
    /// This connection is an Alt-Svc "redirect".
    pub altused: bool,
    /// A `--connect-to` host override is active.
    pub conn_to_host: bool,
    /// A `--connect-to` port override is active.
    pub conn_to_port: bool,
    /// The remote site is specified as a pure IPv6 address.
    pub ipv6_ip: bool,
    /// Communicating with a site using an IPv6 address.
    pub ipv6: bool,
    /// The protocol's `do_more` step must run after `do`.
    pub do_more: bool,
    /// The protocol layer has started after the TCP connect.
    pub protoconnstart: bool,
    /// This connection is about to be closed and retried elsewhere.
    pub retry: bool,
    /// FTP: use EPSV (cleared if EPSV turns out not to work).
    pub ftp_use_epsv: bool,
    /// FTP: use EPRT (cleared if EPRT turns out not to work).
    pub ftp_use_eprt: bool,
    /// FTP: SSL enabled for the data connection.
    pub ftp_use_data_ssl: bool,
    /// FTP: SSL enabled for the control connection.
    pub ftp_use_control_ssl: bool,
    /// Credentials were provided by a `.netrc` file.
    pub netrc: bool,
    /// `bind()` has already been done on this socket/connection.
    pub bound: bool,
    /// A protocol upgrade is in progress.
    pub upgrade_in_progress: bool,
    /// The connection is multiplexed.
    pub multiplex: bool,
    /// Use TCP Fast Open.
    pub tcp_fastopen: bool,
    /// The TLS ALPN extension is enabled.
    pub tls_enable_alpn: bool,
    /// Name resolution is performed over DNS-over-HTTPS.
    pub doh: bool,
    /// The Unix-domain socket path is in the abstract namespace.
    pub abstract_unix_socket: bool,
    /// The `SECONDARYSOCKET` was created with `accept()`.
    pub sock_accepted: bool,
    /// A parallel connect attempt (Happy Eyeballs) has started.
    pub parallel_connect: bool,
    /// The connection was aborted, e.g. left in an unclean state.
    pub aborted: bool,
    /// This connection must not be reused.
    pub no_reuse: bool,
    /// Connection shutdown: the protocol handler has shut down.
    pub shutdown_handler: bool,
    /// Connection shutdown: the filters have shut down.
    pub shutdown_filters: bool,
    /// The connection is currently held in a connection pool.
    pub in_cpool: bool,
}

// ===========================================================================
// ConnControl — connection/stream closure control (`lib/connect.h`).
//
// The values match curl's `CONNCTRL_*` defines and back the
// `connkeep`/`connclose`/`streamclose` macros. Applied via
// [`Connection::conn_control`].
// ===========================================================================

/// The kind of closure signal passed to [`Connection::conn_control`]
/// (curl's `Curl_conncontrol` `ctrl` argument).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnControl {
    /// `CONNCTRL_KEEP` — undo a previously marked closure (`connkeep`).
    Keep = 0,
    /// `CONNCTRL_CONNECTION` — mark the whole connection for closure
    /// (`connclose`).
    Connection = 1,
    /// `CONNCTRL_STREAM` — mark the current stream for closure
    /// (`streamclose`); on a multiplexed connection this never closes the
    /// connection itself.
    Stream = 2,
}

// ===========================================================================
// HostName — a rewrite of curl's `struct hostname` (`lib/urldata.h`).
// ===========================================================================

/// A host name in the forms curl tracks: the internal `name` (possibly
/// IDN/punycode-encoded), the `dispname` used for display/diagnostics, and the
/// optional IDN-`encoded` form.
///
/// This corresponds to curl's `struct hostname` whose members are
/// `rawalloc` / `encalloc` / `name` / `dispname`; in Rust the owning
/// allocations collapse into owned `String`s.
#[derive(Debug, Default, Clone)]
pub struct HostName {
    /// The name used internally (may be IDN/punycode-encoded).
    pub name: String,
    /// The name to display, as `name` might be encoded.
    pub dispname: String,
    /// The IDN-encoded (ACE/punycode) form, when the host required encoding.
    pub encoded: Option<String>,
}

impl HostName {
    /// Creates a [`HostName`] whose display name equals its internal name and
    /// which carries no separate IDN-encoded form.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        HostName {
            dispname: name.clone(),
            name,
            encoded: None,
        }
    }
}

// ===========================================================================
// ProxyType / ProxyInfo — rewrite of curl's `struct proxy_info` and the
// `CURLPROXY_*` proxy-type values (`lib/urldata.h`, `include/curl/curl.h`).
// ===========================================================================

/// The kind of proxy in use. The discriminants match curl's `CURLPROXY_*`
/// values (`include/curl/curl.h`) and are frozen for ABI/trace parity.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyType {
    /// `CURLPROXY_HTTP` — HTTP proxy (the default).
    #[default]
    Http = 0,
    /// `CURLPROXY_HTTP_1_0` — force `CONNECT` over HTTP/1.0.
    Http1_0 = 1,
    /// `CURLPROXY_HTTPS` — HTTPS proxy, HTTP/1 only.
    Https = 2,
    /// `CURLPROXY_HTTPS2` — HTTPS proxy, may negotiate HTTP/2.
    Https2 = 3,
    /// `CURLPROXY_SOCKS4`.
    Socks4 = 4,
    /// `CURLPROXY_SOCKS5`.
    Socks5 = 5,
    /// `CURLPROXY_SOCKS4A`.
    Socks4a = 6,
    /// `CURLPROXY_SOCKS5_HOSTNAME` — SOCKS5 with proxy-side name resolution.
    Socks5Hostname = 7,
}

/// A proxy endpoint, mirroring curl's `struct proxy_info` (a host name, a port,
/// the proxy type, and optional credentials).
#[derive(Debug, Default, Clone)]
pub struct ProxyInfo {
    /// The proxy host name.
    pub host: HostName,
    /// The proxy port.
    pub port: u16,
    /// The kind of proxy.
    pub proxytype: ProxyType,
    /// The proxy username, if any.
    pub user: Option<String>,
    /// The proxy password, if any.
    pub passwd: Option<String>,
}

// ===========================================================================
// Scheme — a lightweight protocol-handler identity.
//
// This intentionally does NOT reference `crate::protocols` (protocols depend on
// the connection layer, so importing back would create a cycle). It records
// only the connection-relevant facts about the protocol the connection speaks:
// its scheme name, default port, whether it is inherently TLS, and whether it
// uses the network at all (curl's `PROTOPT_NONETWORK`, e.g. `file:`).
// ===========================================================================

/// A minimal, connection-local view of a protocol handler — the Rust analog of
/// the connection-relevant parts of curl's `struct Curl_scheme`.
#[derive(Debug, Clone, Default)]
pub struct Scheme {
    /// The lowercase scheme name, e.g. `"https"`, `"ftp"`.
    pub name: String,
    /// The default port for the scheme.
    pub default_port: u16,
    /// Whether the scheme is inherently TLS-secured (e.g. `https`, `ftps`).
    pub is_ssl: bool,
    /// Whether the scheme uses no network transport (curl's
    /// `PROTOPT_NONETWORK`, e.g. `file:`), in which case a connection is
    /// considered "connected" without any filter chain.
    pub no_network: bool,
}

impl Scheme {
    /// Creates a network scheme with the given name and default port (not TLS,
    /// uses the network). Set [`is_ssl`](Scheme::is_ssl) /
    /// [`no_network`](Scheme::no_network) afterward for other schemes.
    #[must_use]
    pub fn new(name: impl Into<String>, default_port: u16) -> Self {
        Scheme {
            name: name.into(),
            default_port,
            is_ssl: false,
            no_network: false,
        }
    }
}

// ===========================================================================
// Per-connection auth negotiation state (`lib/urldata.h`, USE_NTLM / USE_SPNEGO).
//
// The connection must remember how far NTLM / Negotiate got, because those
// mechanisms bind authentication to the *connection* rather than the request.
// The actual crypto lives in the `auth` subsystem; these enums are only the
// state the connection carries across requests, with curl's state vocabulary
// preserved for `--trace` parity.
// ===========================================================================

/// NTLM handshake progress remembered on a connection (curl's `curlntlm`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum NtlmState {
    /// `NTLMSTATE_NONE` — no NTLM negotiation has happened.
    #[default]
    None,
    /// `NTLMSTATE_TYPE1` — a type-1 (negotiate) message has been sent.
    Type1,
    /// `NTLMSTATE_TYPE2` — a type-2 (challenge) message has been received.
    Type2,
    /// `NTLMSTATE_TYPE3` — a type-3 (authenticate) message has been sent.
    Type3,
}

/// Negotiate (SPNEGO/GSSAPI) handshake progress remembered on a connection
/// (curl's `curlnegotiate`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum NegotiateState {
    /// `GSS_AUTHNONE` — no Negotiate handshake in progress.
    #[default]
    None,
    /// `GSS_AUTHRECV` — a challenge token has been received.
    Recv,
    /// `GSS_AUTHSENT` — a response token has been sent.
    Sent,
    /// `GSS_AUTHDONE` — the handshake has completed.
    Done,
    /// `GSS_AUTHSUCC` — the handshake completed successfully.
    Succeeded,
}

// ===========================================================================
// Opaque owning-multi identity and per-connection shutdown bookkeeping.
// ===========================================================================

/// A non-owning identity for the multi handle a connection is attached to.
///
/// curl stores a raw `struct Curl_multi *attached_multi` used **only** for
/// equality checks (never dereferenced from the connection). Modeling it as an
/// opaque id keeps that "compare, never follow" contract while guaranteeing no
/// strong reference cycle between a connection and its multi handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MultiId(pub u64);

/// Per-socket connection-shutdown bookkeeping, mirroring the anonymous
/// `shutdown` struct inside curl's `connectdata`.
#[derive(Debug, Default, Clone)]
pub struct ShutdownState {
    /// When filter shutdown started, per socket index (`None` = not started).
    pub start: [Option<Instant>; CONN_SOCKET_COUNT],
    /// The shutdown timeout in milliseconds (`0` means no timeout).
    pub timeout_ms: u64,
}

// ===========================================================================
// Connection — the connection portion of curl's `struct connectdata`.
// ===========================================================================

/// A network connection — the Rust rewrite of the connection-relevant portion
/// of curl's `struct connectdata`.
///
/// A `Connection` owns its per-socket [`FilterChain`]s and, through them, the
/// live sockets and any TLS/HTTP state. It is therefore **move-only**: it
/// deliberately does not implement [`Clone`], because cloning would duplicate
/// live OS resources. Dropping the value tears everything down, which is how
/// Rust ownership replaces curl's manual `Curl_conn_free`.
///
/// The public fields fall into two groups:
///
/// * **Reuse identity** — the data the connection is *created* with and matched
///   on for pooling (`ConnectionExists` / `url_match_conn`): scheme, host, port,
///   proxy, credentials, and TLS configuration. These mirror the "needle" a
///   fresh `connectdata` is filled with before the pool is consulted.
/// * **Live state** — the filter chains, timestamps, transfer accounting, and
///   the [`ConnectBits`] diagnostic flags.
#[derive(Debug)]
pub struct Connection {
    // --- Identity assigned by the connection pool ---------------------------
    /// A unique, monotonically-increasing id assigned by the connection pool
    /// (`conn->connection_id`).
    pub connection_id: i64,
    /// The normalized reuse key — `hostname+port+scope`, plus proxy/`--connect-to`
    /// overrides — exactly as curl builds `conn->destination`. Kept lowercase.
    /// Rebuild with [`Connection::build_destination`] after changing the host,
    /// port, scope, or proxy identity.
    pub destination: String,

    // --- Host identity ------------------------------------------------------
    /// The destination host (`conn->host`).
    pub host: HostName,
    /// The host name actually resolved to an address, when it differs from
    /// [`host`](Connection::host) (`conn->hostname_resolve`).
    pub hostname_resolve: Option<String>,
    /// The `--connect-to` host override, valid only when
    /// [`ConnectBits::conn_to_host`] is set (`conn->conn_to_host`).
    pub conn_to_host: Option<HostName>,
    /// The secondary-socket host name (FTP data channel)
    /// (`conn->secondaryhostname`).
    pub secondaryhostname: Option<String>,

    // --- Ports --------------------------------------------------------------
    /// The remote port — not the proxy port (`conn->remote_port`).
    pub remote_port: u16,
    /// The `--connect-to` port override, valid only when
    /// [`ConnectBits::conn_to_port`] is set (`conn->conn_to_port`).
    pub conn_to_port: Option<u16>,
    /// The bound local port (`conn->localport`).
    pub localport: u16,
    /// The secondary-socket remote port (FTP data channel)
    /// (`conn->secondary_port`).
    pub secondary_port: u16,
    /// The IPv6 scope id (`conn->scope_id`).
    pub scope_id: u32,
    /// The effective port actually connected to (the `--connect-to` port when
    /// set, otherwise the remote port).
    pub port: u16,

    // --- Scheme / protocol-handler identity ---------------------------------
    /// The protocol handler this connection currently speaks (`conn->scheme`).
    pub scheme: Scheme,
    /// The protocol handler originally requested, before any Alt-Svc/redirect
    /// change (`conn->given`).
    pub given: Scheme,

    // --- Proxy identity -----------------------------------------------------
    /// The HTTP proxy endpoint (`conn->http_proxy`).
    pub http_proxy: ProxyInfo,
    /// The SOCKS proxy endpoint (`conn->socks_proxy`).
    pub socks_proxy: ProxyInfo,

    // --- Credentials (reuse matching) ---------------------------------------
    /// The resolved username (`conn->user`).
    pub user: Option<String>,
    /// The resolved password (`conn->passwd`).
    pub passwd: Option<String>,
    /// The login `;options` field (`conn->options`).
    pub options: Option<String>,
    /// The SASL authorization identity (`conn->sasl_authzid`).
    pub sasl_authzid: Option<String>,
    /// The OAuth 2.0 bearer token (`conn->oauth_bearer`).
    pub oauth_bearer: Option<String>,

    // --- TLS configuration identity (reuse matching) ------------------------
    /// The server TLS configuration this connection was created with
    /// (`conn->ssl_config`). Shared cheaply via [`Arc`] so reuse-matching can
    /// compare the negotiated parameters without deep copies.
    pub ssl_config: Arc<TlsConfig>,
    /// The proxy-side TLS configuration for an HTTPS proxy
    /// (`conn->proxy_ssl_config`).
    pub proxy_ssl_config: Arc<TlsConfig>,

    // --- Interface binding / Unix socket ------------------------------------
    /// The Unix-domain socket path, if this connection uses one
    /// (`conn->unix_domain_socket`).
    pub unix_domain_socket: Option<String>,
    /// The bound local device/interface, if any (`conn->localdev`).
    pub localdev: Option<String>,
    /// The bound local-port range (`conn->localportrange`).
    pub localportrange: u16,

    // --- Resolution preference ----------------------------------------------
    /// The IP-version preference this connection resolved with
    /// (`conn->ip_version`).
    pub ip_version: dns::IpVersion,

    // --- Live filter chains (owned) -----------------------------------------
    /// The per-socket filter chains. Index [`FIRSTSOCKET`] is the primary
    /// chain; index [`SECONDARYSOCKET`] is the FTP data-channel chain. `None`
    /// means no chain has been assembled for that socket yet
    /// (`conn->cfilter[2]`).
    pub cfilter: [Option<FilterChain>; CONN_SOCKET_COUNT],
    /// The socket index currently used for receiving (`conn->recv_idx`,
    /// default [`FIRSTSOCKET`]).
    pub recv_idx: usize,
    /// The socket index currently used for sending (`conn->send_idx`,
    /// default [`FIRSTSOCKET`]).
    pub send_idx: usize,

    // --- Timestamps ---------------------------------------------------------
    /// When the connection was created (`conn->created`).
    pub created: Instant,
    /// When the connection was last returned to the pool as idle
    /// (`conn->lastused`), used for pool age/prune decisions.
    pub lastused: Instant,
    /// The last time the protocol's keep-alive mechanism ran, if ever
    /// (`conn->keepalive`).
    pub keepalive: Option<Instant>,

    // --- Shutdown bookkeeping -----------------------------------------------
    /// Per-socket filter-shutdown timing (`conn->shutdown`).
    pub shutdown: ShutdownState,

    // --- Multi attachment & transfer accounting -----------------------------
    /// The multi handle this connection is attached to, as an opaque,
    /// non-owning id (`conn->attached_multi`). Compared for equality only,
    /// never followed, so no reference cycle can form.
    pub attached_multi: Option<MultiId>,
    /// The number of easy handles currently attached to this connection
    /// (`conn->attached_xfers`); see [`Connection::in_use`] (curl's
    /// `CONN_INUSE`).
    pub attached_xfers: u32,

    // --- Per-connection auth negotiation state ------------------------------
    /// NTLM state for host authentication (`conn->http_ntlm_state`).
    pub http_ntlm_state: NtlmState,
    /// NTLM state for proxy authentication (`conn->proxy_ntlm_state`).
    pub proxy_ntlm_state: NtlmState,
    /// Negotiate state for host authentication (`conn->http_negotiate_state`).
    pub http_negotiate_state: NegotiateState,
    /// Negotiate state for proxy authentication (`conn->proxy_negotiate_state`).
    pub proxy_negotiate_state: NegotiateState,

    // --- Version / delegation ------------------------------------------------
    /// The HTTP version last responded with or negotiated via ALPN — `0` at
    /// start, then `9`/`10`/`11`/`20`/`30` (`conn->httpversion_seen`).
    pub httpversion_seen: u8,
    /// The GSSAPI credential-delegation policy inherited from the easy handle
    /// (`conn->gssapi_delegation`).
    pub gssapi_delegation: u8,

    // --- Transport + flags ---------------------------------------------------
    /// The transport the connection wants (`conn->transport_wanted`). The
    /// actual transport once connected is obtained via
    /// [`Connection::get_transport`].
    pub transport_wanted: Transport,
    /// The per-connection diagnostic state flags (`conn->bits`).
    pub bits: ConnectBits,

    // --- Notification model for multiplexing --------------------------------
    // Set by `set_multiplex` when an attached multi must be told the
    // connection became multiplexed (curl calls `Curl_multi_connchanged`).
    // The multi layer drains it via `take_multi_connchanged`, so no direct
    // `crate::multi` import — and therefore no module cycle — is required.
    multi_connchanged_pending: bool,
}

impl Connection {
    /// Create a new connection for `scheme` targeting `host:remote_port`.
    ///
    /// This mirrors the connection-relevant initialization performed by curl's
    /// `allocate_conn` (`lib/url.c`): identity fields are zeroed, timestamps are
    /// stamped with the current instant, TLS configs default to a validating
    /// [`TlsConfig`], and the wanted transport is derived from the scheme
    /// (`Transport::None` for non-network schemes such as `file`, otherwise
    /// `Transport::Tcp`; QUIC/UNIX are selected later by the connect setup).
    ///
    /// The reuse key ([`Connection::destination`]) is computed before returning,
    /// exactly as curl builds `conn->destination`.
    #[must_use]
    pub fn new(scheme: Scheme, host: impl Into<String>, remote_port: u16) -> Self {
        let transport_wanted = if scheme.no_network {
            Transport::None
        } else {
            Transport::Tcp
        };
        let now = Instant::now();
        let mut conn = Self {
            connection_id: 0,
            destination: String::new(),
            host: HostName::new(host),
            hostname_resolve: None,
            conn_to_host: None,
            secondaryhostname: None,
            remote_port,
            conn_to_port: None,
            localport: 0,
            secondary_port: 0,
            scope_id: 0,
            port: remote_port,
            // `given` records the originally requested handler; at allocation it
            // equals `scheme` and only diverges when a proxy alters dispatch.
            given: scheme.clone(),
            scheme,
            http_proxy: ProxyInfo::default(),
            socks_proxy: ProxyInfo::default(),
            user: None,
            passwd: None,
            options: None,
            sasl_authzid: None,
            oauth_bearer: None,
            ssl_config: Arc::new(TlsConfig::default()),
            proxy_ssl_config: Arc::new(TlsConfig::default()),
            unix_domain_socket: None,
            localdev: None,
            localportrange: 0,
            ip_version: dns::IpVersion::default(),
            cfilter: [None, None],
            recv_idx: FIRSTSOCKET,
            send_idx: FIRSTSOCKET,
            created: now,
            lastused: now,
            keepalive: None,
            shutdown: ShutdownState::default(),
            attached_multi: None,
            attached_xfers: 0,
            http_ntlm_state: NtlmState::None,
            proxy_ntlm_state: NtlmState::None,
            http_negotiate_state: NegotiateState::None,
            proxy_negotiate_state: NegotiateState::None,
            httpversion_seen: 0,
            gssapi_delegation: 0,
            transport_wanted,
            bits: ConnectBits::default(),
            multi_connchanged_pending: false,
        };
        conn.build_destination();
        conn
    }

    /// (Re)compute [`Connection::destination`], the normalized connection-reuse
    /// key, exactly as curl does in `lib/url.c` (`create_conn`, ≈lines
    /// 1909–1935).
    ///
    /// The format is `"{scope_id}/{port}/{hostname}"`, lowercased. When a
    /// non-tunneling HTTP proxy is in play the proxy host and port form the key;
    /// otherwise the effective host is the connect-to override when present, and
    /// the port is the connection's `remote_port`. Callers must invoke this
    /// after mutating any of the inputs (proxy bits, `conn_to_host`, `scope_id`,
    /// `remote_port`, or `host`) so the pooled key stays consistent, mirroring
    /// curl's explicit `conn->destination` construction.
    pub fn build_destination(&mut self) {
        let (hostname, port) = if self.bits.httpproxy && !self.bits.tunnel_proxy {
            // A non-tunneling HTTP proxy: the reuse key is keyed on the proxy
            // endpoint, since every request rides the same proxy socket.
            (self.http_proxy.host.name.clone(), self.http_proxy.port)
        } else {
            let hostname = match (self.bits.conn_to_host, self.conn_to_host.as_ref()) {
                (true, Some(target)) => target.name.clone(),
                _ => self.host.name.clone(),
            };
            (hostname, self.remote_port)
        };
        // `scope_id` and `port` are decimal digits (unaffected by lowercasing);
        // only the hostname is case-folded, matching curl's `Curl_strntolower`
        // over the whole key.
        let mut destination = format!("{}/{}/{}", self.scope_id, port, hostname);
        destination.make_ascii_lowercase();
        self.destination = destination;
    }

    /// Return whether any easy handle is currently attached to this connection
    /// (curl's `CONN_INUSE(conn)` — `conn->attached_xfers != 0`). Connections in
    /// use must never be pruned or closed by the pool.
    #[must_use]
    pub fn in_use(&self) -> bool {
        self.attached_xfers > 0
    }

    /// Borrow the filter chain installed at `sockindex`, if any. Out-of-range
    /// indices yield `None` (the C code guards with `CONN_SOCK_IDX_VALID`).
    fn chain(&self, sockindex: usize) -> Option<&FilterChain> {
        self.cfilter.get(sockindex).and_then(Option::as_ref)
    }

    /// Mutably borrow the filter chain installed at `sockindex`, if any.
    fn chain_mut(&mut self, sockindex: usize) -> Option<&mut FilterChain> {
        self.cfilter.get_mut(sockindex).and_then(Option::as_mut)
    }

    /// Whether a filter chain has been installed for `sockindex`
    /// (`Curl_conn_is_setup`). Setup means the chain exists, not that it has
    /// connected.
    #[must_use]
    pub fn is_setup(&self, sockindex: usize) -> bool {
        self.chain(sockindex).is_some()
    }

    /// Whether the connection at `sockindex` is fully connected
    /// (`Curl_conn_is_connected`). With a chain installed this reflects the head
    /// filter's connected state; with no chain it is `true` only for
    /// non-network schemes (curl's `PROTOPT_NONETWORK`), and `false` for an
    /// out-of-range index.
    #[must_use]
    pub fn is_connected(&self, sockindex: usize) -> bool {
        match self.cfilter.get(sockindex) {
            None => false,
            Some(Some(chain)) => chain.is_connected(),
            Some(None) => self.scheme.no_network,
        }
    }

    /// Whether the underlying IP (TCP/UDP) transport at `sockindex` is connected
    /// (`Curl_conn_is_ip_connected`), regardless of higher filters such as TLS.
    #[must_use]
    pub fn is_ip_connected(&self, sockindex: usize) -> bool {
        self.chain(sockindex)
            .is_some_and(|chain| chain.is_ip_connected())
    }

    /// Whether the connection at `sockindex` runs over TLS (`Curl_conn_is_ssl` —
    /// a filter advertising `CF_TYPE_SSL` is present below the application).
    #[must_use]
    pub fn is_ssl(&self, sockindex: usize) -> bool {
        self.chain(sockindex).is_some_and(|chain| chain.is_ssl())
    }

    /// Whether the connection at `sockindex` supports multiplexing
    /// (`Curl_conn_is_multiplex` — e.g. HTTP/2 or HTTP/3). When a live chain is
    /// present its capability is authoritative; otherwise the cached
    /// `bits.multiplex` flag is used so the state survives before/without an
    /// installed chain.
    #[must_use]
    pub fn is_multiplex(&self, sockindex: usize) -> bool {
        self.chain(sockindex)
            .map_or(self.bits.multiplex, FilterChain::is_multiplex)
    }

    /// Drive the connect state machine for `sockindex` (`Curl_conn_connect`).
    ///
    /// Returns `Ok(true)` once the chain is fully connected, `Ok(false)` while
    /// the (non-blocking) connect is still progressing. An out-of-range index is
    /// [`Error::BadFunctionArgument`]; a missing chain is
    /// [`CurlCode::FailedInit`], matching the C entry point. On completion the
    /// connection's `keepalive` timestamp is stamped, exactly as curl does.
    ///
    /// # Errors
    /// Propagates any transport, TLS, or protocol error surfaced while
    /// establishing the connection, plus the argument/setup errors above.
    pub async fn connect(&mut self, sockindex: usize, blocking: bool) -> Result<bool> {
        if sockindex >= CONN_SOCKET_COUNT {
            return Err(Error::BadFunctionArgument(format!(
                "connect: invalid socket index {sockindex}"
            )));
        }
        let done = match self.chain_mut(sockindex) {
            Some(chain) => chain.connect(blocking).await?,
            None => return Err(Error::Code(CurlCode::FailedInit)),
        };
        if done {
            self.keepalive = Some(Instant::now());
        }
        Ok(done)
    }

    /// Close the connection at `sockindex` (`Curl_conn_close`). Delegates
    /// `do_close` to the installed chain (if any), then clears the shutdown
    /// bookkeeping for that socket (curl's `Curl_shutdown_clear`). A missing
    /// chain or out-of-range index is a no-op, matching the C behavior.
    pub fn close(&mut self, sockindex: usize) {
        if let Some(chain) = self.chain_mut(sockindex) {
            chain.close();
        }
        if let Some(slot) = self.shutdown.start.get_mut(sockindex) {
            *slot = None;
        }
    }

    /// Perform a graceful shutdown of the connection at `sockindex`
    /// (`Curl_conn_shutdown`).
    ///
    /// Returns `Ok(true)` when shutdown has completed (immediately so when no
    /// chain is installed — nothing to tear down), or `Ok(false)` while a
    /// non-blocking shutdown is still draining. The per-socket start instant is
    /// recorded on the first attempt (curl's `Curl_shutdown_start`) so the
    /// configured `timeout_ms` can bound the sequence.
    ///
    /// # Errors
    /// [`Error::BadFunctionArgument`] for an out-of-range index; otherwise any
    /// error surfaced by the chain while shutting the filters down.
    pub async fn shutdown(&mut self, sockindex: usize) -> Result<bool> {
        if sockindex >= CONN_SOCKET_COUNT {
            return Err(Error::BadFunctionArgument(format!(
                "shutdown: invalid socket index {sockindex}"
            )));
        }
        if self.chain(sockindex).is_none() {
            // No filters installed: there is nothing to shut down.
            return Ok(true);
        }
        if self.shutdown.start[sockindex].is_none() {
            self.shutdown.start[sockindex] = Some(Instant::now());
        }
        let timeout_ms = self.shutdown.timeout_ms;
        match self.chain_mut(sockindex) {
            Some(chain) => chain.shutdown(timeout_ms).await,
            // Unreachable: presence was verified above. Reported as done rather
            // than panicking, keeping this method total.
            None => Ok(true),
        }
    }

    /// Whether buffered inbound data is pending at `sockindex`
    /// (`Curl_conn_data_pending`) — e.g. bytes already decrypted inside the TLS
    /// filter that the socket poll would not reveal.
    #[must_use]
    pub fn data_pending(&self, sockindex: usize) -> bool {
        self.chain(sockindex)
            .is_some_and(|chain| chain.data_pending())
    }

    /// Whether the chain at `sockindex` has buffered outbound data awaiting a
    /// flush (`Curl_conn_needs_flush`).
    #[must_use]
    pub fn needs_flush(&self, sockindex: usize) -> bool {
        self.chain(sockindex)
            .is_some_and(|chain| chain.needs_flush())
    }

    /// Flush any buffered outbound data at `sockindex` (`Curl_conn_flush`). A
    /// missing chain is a successful no-op.
    ///
    /// # Errors
    /// Propagates any I/O or protocol error surfaced while flushing the chain.
    pub async fn flush(&mut self, sockindex: usize) -> Result<()> {
        match self.chain_mut(sockindex) {
            Some(chain) => chain.flush().await,
            None => Ok(()),
        }
    }

    /// The primary transport socket file descriptor, if the first-socket chain
    /// exposes one (`Curl_conn_get_first_socket`). Returns `None` before the IP
    /// transport is established or for socketless schemes.
    #[must_use]
    pub fn get_first_socket(&self) -> Option<i32> {
        self.chain(FIRSTSOCKET).and_then(FilterChain::socket)
    }

    /// The negotiated HTTP version on the first socket, encoded as curl does
    /// (`0` unknown, `9`/`10`/`11`/`20`/`30`) — `Curl_conn_http_version`.
    #[must_use]
    pub fn http_version(&self) -> u8 {
        self.chain(FIRSTSOCKET).map_or(0, FilterChain::http_version)
    }

    /// The effective transport of the established connection
    /// (`Curl_conn_get_transport`). Falls back to [`Connection::transport_wanted`]
    /// until a chain reports its concrete transport.
    #[must_use]
    pub fn get_transport(&self) -> Transport {
        self.chain(FIRSTSOCKET)
            .and_then(FilterChain::transport)
            .unwrap_or(self.transport_wanted)
    }

    /// The ALPN protocol negotiated over TLS on the first socket, if any
    /// (`Curl_conn_get_alpn_negotiated`) — e.g. `"h2"` or `"http/1.1"`.
    #[must_use]
    pub fn get_alpn_negotiated(&self) -> Option<String> {
        self.chain(FIRSTSOCKET)
            .and_then(FilterChain::alpn_negotiated)
    }

    /// Mark the connection as multiplexed (`Curl_conn_set_multiplex`). The first
    /// transition to multiplexed also arms a pending notification to the
    /// attached multi handle (curl calls `Curl_multi_connchanged`); the multi
    /// layer consumes it via [`Connection::take_multi_connchanged`], avoiding a
    /// direct `crate::multi` dependency and the module cycle it would create.
    pub fn set_multiplex(&mut self) {
        if !self.bits.multiplex {
            self.bits.multiplex = true;
            if self.attached_multi.is_some() {
                self.multi_connchanged_pending = true;
            }
        }
    }

    /// Consume and return the pending "connection changed" notification armed by
    /// [`Connection::set_multiplex`]. Returns `true` at most once per transition;
    /// the multi layer polls this to learn it must recompute the connection's
    /// socket/multiplex expectations (curl's `Curl_multi_connchanged`).
    #[must_use]
    pub fn take_multi_connchanged(&mut self) -> bool {
        std::mem::take(&mut self.multi_connchanged_pending)
    }

    /// Apply connection/stream close control (`Curl_conncontrol`), preserving
    /// curl's exact semantics:
    ///
    /// * [`ConnControl::Connection`] — mark the connection to be closed
    ///   (`connclose`).
    /// * [`ConnControl::Stream`] on a non-multiplexed connection — also closes
    ///   the connection (the stream *is* the connection).
    /// * [`ConnControl::Stream`] on a multiplexed connection — leaves the close
    ///   state untouched (other streams keep using the connection).
    /// * [`ConnControl::Keep`] — clears the close flag (`connkeep`).
    pub fn conn_control(&mut self, ctrl: ConnControl) {
        let is_multiplex = self.is_multiplex(FIRSTSOCKET);
        if matches!(ctrl, ConnControl::Stream) && is_multiplex {
            // A single stream signaling close on a multiplexed connection must
            // not tear down the shared connection.
            return;
        }
        let close_it = matches!(ctrl, ConnControl::Connection)
            || (matches!(ctrl, ConnControl::Stream) && !is_multiplex);
        self.bits.close = close_it;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal network scheme for tests (`https`, TLS on, port 443).
    fn https_scheme() -> Scheme {
        let mut scheme = Scheme::new("https", 443);
        scheme.is_ssl = true;
        scheme
    }

    /// Build a minimal non-network scheme for tests (`file`).
    fn file_scheme() -> Scheme {
        let mut scheme = Scheme::new("file", 0);
        scheme.no_network = true;
        scheme
    }

    #[test]
    fn transport_has_exact_discriminants() {
        // curl relies on the numeric identity (urldata.h:567-571).
        assert_eq!(Transport::None.as_u8(), 0);
        assert_eq!(Transport::Tcp.as_u8(), 3);
        assert_eq!(Transport::Udp.as_u8(), 4);
        assert_eq!(Transport::Quic.as_u8(), 5);
        assert_eq!(Transport::Unix.as_u8(), 6);
    }

    #[test]
    fn transport_round_trips_through_u8() {
        for t in [
            Transport::None,
            Transport::Tcp,
            Transport::Udp,
            Transport::Quic,
            Transport::Unix,
        ] {
            let raw = t.as_u8();
            assert_eq!(Transport::from_u8(raw), Some(t));
            assert_eq!(u8::from(t), raw);
            assert_eq!(Transport::try_from(raw).unwrap(), t);
        }
    }

    #[test]
    fn transport_rejects_unknown_values() {
        for bad in [1u8, 2, 7, 8, 42, 255] {
            assert_eq!(Transport::from_u8(bad), None);
            assert!(Transport::try_from(bad).is_err());
        }
    }

    #[test]
    fn transport_default_is_none() {
        assert_eq!(Transport::default(), Transport::None);
    }

    #[test]
    fn conn_control_has_exact_values() {
        // Mirrors CONNCTRL_KEEP/CONNECTION/STREAM (connect.h).
        assert_eq!(ConnControl::Keep as u8, 0);
        assert_eq!(ConnControl::Connection as u8, 1);
        assert_eq!(ConnControl::Stream as u8, 2);
    }

    #[test]
    fn cf_type_flags_have_exact_bits() {
        // cfilters.h:203-207.
        assert_eq!(CfType::IP_CONNECT.bits(), 1 << 0);
        assert_eq!(CfType::SSL.bits(), 1 << 1);
        assert_eq!(CfType::MULTIPLEX.bits(), 1 << 2);
        assert_eq!(CfType::PROXY.bits(), 1 << 3);
        assert_eq!(CfType::HTTP.bits(), 1 << 4);
    }

    #[test]
    fn cf_type_combines_and_queries() {
        let combined = CfType::SSL | CfType::MULTIPLEX;
        assert!(combined.contains(CfType::SSL));
        assert!(combined.contains(CfType::MULTIPLEX));
        assert!(!combined.contains(CfType::IP_CONNECT));
        assert!(combined.intersects(CfType::SSL));
        assert!(!combined.intersects(CfType::PROXY));
        assert!(CfType::from_bits(0).is_empty());
        assert!(!combined.is_empty());

        let mut acc = CfType::from_bits(0);
        acc |= CfType::HTTP;
        assert!(acc.contains(CfType::HTTP));
    }

    #[test]
    fn cf_ctrl_constants_have_exact_values() {
        // cfilters.h:119-127.
        assert_eq!(CF_CTRL_DATA_SETUP, 4);
        assert_eq!(CF_CTRL_DATA_PAUSE, 6);
        assert_eq!(CF_CTRL_DATA_DONE, 7);
        assert_eq!(CF_CTRL_DATA_DONE_SEND, 8);
        assert_eq!(CF_CTRL_CONN_INFO_UPDATE, 256);
        assert_eq!(CF_CTRL_FORGET_SOCKET, 257);
        assert_eq!(CF_CTRL_FLUSH, 258);
    }

    #[test]
    fn cf_query_has_exact_values_and_round_trips() {
        // cfilters.h:165-181 — selectors 1..=15.
        let all = [
            (CfQuery::MaxConcurrent, 1),
            (CfQuery::ConnectReplyMs, 2),
            (CfQuery::Socket, 3),
            (CfQuery::TimerConnect, 4),
            (CfQuery::TimerAppConnect, 5),
            (CfQuery::StreamError, 6),
            (CfQuery::NeedFlush, 7),
            (CfQuery::IpInfo, 8),
            (CfQuery::HttpVersion, 9),
            (CfQuery::RemoteAddr, 10),
            (CfQuery::HostPort, 11),
            (CfQuery::SslInfo, 12),
            (CfQuery::SslCtxInfo, 13),
            (CfQuery::Transport, 14),
            (CfQuery::AlpnNegotiated, 15),
        ];
        for (query, value) in all {
            assert_eq!(query.as_i32(), value);
            assert_eq!(CfQuery::try_from(value).unwrap(), query);
        }
        assert!(CfQuery::try_from(0).is_err());
        assert!(CfQuery::try_from(16).is_err());
    }

    #[test]
    fn ssl_mode_constants_have_exact_values() {
        // cfilters.h:351-353.
        assert_eq!(CURL_CF_SSL_DEFAULT, -1);
        assert_eq!(CURL_CF_SSL_DISABLE, 0);
        assert_eq!(CURL_CF_SSL_ENABLE, 1);
    }

    #[test]
    fn socket_index_constants_have_exact_values() {
        // urldata.h:421-422 plus curl's two-socket model.
        assert_eq!(FIRSTSOCKET, 0);
        assert_eq!(SECONDARYSOCKET, 1);
        assert_eq!(CONN_SOCKET_COUNT, 2);
    }

    #[test]
    fn connect_bits_default_is_all_false() {
        let bits = ConnectBits::default();
        assert!(!bits.httpproxy);
        assert!(!bits.socksproxy);
        assert!(!bits.proxy_user_passwd);
        assert!(!bits.tunnel_proxy);
        assert!(!bits.proxy);
        assert!(!bits.close);
        assert!(!bits.reuse);
        assert!(!bits.altused);
        assert!(!bits.conn_to_host);
        assert!(!bits.conn_to_port);
        assert!(!bits.ipv6_ip);
        assert!(!bits.ipv6);
        assert!(!bits.do_more);
        assert!(!bits.protoconnstart);
        assert!(!bits.retry);
        assert!(!bits.ftp_use_epsv);
        assert!(!bits.ftp_use_eprt);
        assert!(!bits.ftp_use_data_ssl);
        assert!(!bits.ftp_use_control_ssl);
        assert!(!bits.netrc);
        assert!(!bits.bound);
        assert!(!bits.upgrade_in_progress);
        assert!(!bits.multiplex);
        assert!(!bits.tcp_fastopen);
        assert!(!bits.tls_enable_alpn);
        assert!(!bits.doh);
        assert!(!bits.abstract_unix_socket);
        assert!(!bits.sock_accepted);
        assert!(!bits.parallel_connect);
        assert!(!bits.aborted);
        assert!(!bits.no_reuse);
        assert!(!bits.shutdown_handler);
        assert!(!bits.shutdown_filters);
        assert!(!bits.in_cpool);
    }

    #[test]
    fn hostname_new_populates_name_and_dispname() {
        let host = HostName::new("Example.COM");
        assert_eq!(host.name, "Example.COM");
        assert_eq!(host.dispname, "Example.COM");
        assert!(host.encoded.is_none());
    }

    #[test]
    fn proxy_type_default_is_http() {
        assert_eq!(ProxyType::default(), ProxyType::Http);
        assert_eq!(ProxyType::Http as u8, 0);
        assert_eq!(ProxyType::Socks5Hostname as u8, 7);
    }

    #[test]
    fn connection_new_sets_sane_defaults() {
        let conn = Connection::new(https_scheme(), "example.com", 443);
        assert_eq!(conn.connection_id, 0);
        assert!(!conn.in_use());
        assert_eq!(conn.attached_xfers, 0);
        assert_eq!(conn.remote_port, 443);
        assert_eq!(conn.port, 443);
        assert_eq!(conn.transport_wanted, Transport::Tcp);
        // No filter chain installed yet.
        assert!(!conn.is_setup(FIRSTSOCKET));
        assert!(!conn.is_setup(SECONDARYSOCKET));
        assert!(!conn.is_connected(FIRSTSOCKET));
        assert!(!conn.is_ip_connected(FIRSTSOCKET));
        assert!(!conn.is_ssl(FIRSTSOCKET));
        assert!(!conn.is_multiplex(FIRSTSOCKET));
        assert!(!conn.data_pending(FIRSTSOCKET));
        assert!(!conn.needs_flush(FIRSTSOCKET));
        assert_eq!(conn.get_first_socket(), None);
        assert_eq!(conn.http_version(), 0);
        assert_eq!(conn.get_alpn_negotiated(), None);
        // Falls back to the wanted transport until a chain reports one.
        assert_eq!(conn.get_transport(), Transport::Tcp);
        // Defaults derived from dependencies.
        assert_eq!(conn.ip_version, dns::IpVersion::default());
    }

    #[test]
    fn connection_new_uses_none_transport_for_non_network_scheme() {
        let conn = Connection::new(file_scheme(), "localhost", 0);
        assert_eq!(conn.transport_wanted, Transport::None);
        // Non-network schemes are considered connected without a chain.
        assert!(conn.is_connected(FIRSTSOCKET));
    }

    #[test]
    fn destination_key_matches_curl_format() {
        // curl builds "%u/%d/%s" (scope_id/port/hostname), lowercased.
        let conn = Connection::new(https_scheme(), "example.com", 443);
        assert_eq!(conn.destination, "0/443/example.com");
    }

    #[test]
    fn destination_key_is_lowercased() {
        let conn = Connection::new(https_scheme(), "EXAMPLE.CoM", 443);
        assert_eq!(conn.destination, "0/443/example.com");
    }

    #[test]
    fn destination_key_includes_scope_id() {
        let mut conn = Connection::new(https_scheme(), "fe80::1", 443);
        conn.scope_id = 3;
        conn.build_destination();
        assert_eq!(conn.destination, "3/443/fe80::1");
    }

    #[test]
    fn destination_key_honors_conn_to_host_override() {
        let mut conn = Connection::new(https_scheme(), "example.com", 443);
        conn.bits.conn_to_host = true;
        conn.conn_to_host = Some(HostName::new("origin.internal"));
        conn.build_destination();
        // Port stays the connection's remote_port; host is the override.
        assert_eq!(conn.destination, "0/443/origin.internal");
    }

    #[test]
    fn destination_key_uses_proxy_endpoint_when_not_tunneling() {
        let mut conn = Connection::new(https_scheme(), "example.com", 443);
        conn.bits.httpproxy = true;
        conn.bits.tunnel_proxy = false;
        conn.http_proxy.host = HostName::new("proxy.example");
        conn.http_proxy.port = 8080;
        conn.build_destination();
        assert_eq!(conn.destination, "0/8080/proxy.example");
    }

    #[test]
    fn conn_control_matches_curl_semantics_without_multiplex() {
        let mut conn = Connection::new(https_scheme(), "example.com", 443);
        assert!(!conn.bits.close);

        // STREAM on a non-multiplexed connection closes it.
        conn.conn_control(ConnControl::Stream);
        assert!(conn.bits.close);

        // KEEP clears the close flag.
        conn.conn_control(ConnControl::Keep);
        assert!(!conn.bits.close);

        // CONNECTION always closes.
        conn.conn_control(ConnControl::Connection);
        assert!(conn.bits.close);

        conn.conn_control(ConnControl::Keep);
        assert!(!conn.bits.close);
    }

    #[test]
    fn conn_control_stream_is_noop_when_multiplexed() {
        let mut conn = Connection::new(https_scheme(), "example.com", 443);
        // Force the cached multiplex state (no live chain in this unit test).
        conn.bits.multiplex = true;
        assert!(conn.is_multiplex(FIRSTSOCKET));

        // STREAM on a multiplexed connection must not change close state.
        assert!(!conn.bits.close);
        conn.conn_control(ConnControl::Stream);
        assert!(!conn.bits.close);

        // CONNECTION still closes even when multiplexed.
        conn.conn_control(ConnControl::Connection);
        assert!(conn.bits.close);
    }

    #[test]
    fn set_multiplex_sets_flag_and_arms_notification_when_attached() {
        let mut conn = Connection::new(https_scheme(), "example.com", 443);
        conn.attached_multi = Some(MultiId(7));
        assert!(!conn.bits.multiplex);

        conn.set_multiplex();
        assert!(conn.bits.multiplex);
        // Notification is armed exactly once for the attached multi.
        assert!(conn.take_multi_connchanged());
        assert!(!conn.take_multi_connchanged());

        // A second call is a no-op (already multiplexed).
        conn.set_multiplex();
        assert!(!conn.take_multi_connchanged());
    }

    #[test]
    fn set_multiplex_without_attached_multi_arms_nothing() {
        let mut conn = Connection::new(https_scheme(), "example.com", 443);
        assert!(conn.attached_multi.is_none());
        conn.set_multiplex();
        assert!(conn.bits.multiplex);
        assert!(!conn.take_multi_connchanged());
    }

    #[tokio::test]
    async fn connect_rejects_out_of_range_socket_index() {
        let mut conn = Connection::new(https_scheme(), "example.com", 443);
        let err = conn.connect(CONN_SOCKET_COUNT, false).await.unwrap_err();
        assert!(matches!(err, Error::BadFunctionArgument(_)));
    }

    #[tokio::test]
    async fn connect_without_chain_reports_failed_init() {
        let mut conn = Connection::new(https_scheme(), "example.com", 443);
        let err = conn.connect(FIRSTSOCKET, false).await.unwrap_err();
        assert!(matches!(err, Error::Code(CurlCode::FailedInit)));
    }

    #[tokio::test]
    async fn shutdown_without_chain_is_immediately_done() {
        let mut conn = Connection::new(https_scheme(), "example.com", 443);
        assert!(conn.shutdown(FIRSTSOCKET).await.unwrap());
    }

    #[tokio::test]
    async fn shutdown_rejects_out_of_range_socket_index() {
        let mut conn = Connection::new(https_scheme(), "example.com", 443);
        let err = conn.shutdown(CONN_SOCKET_COUNT).await.unwrap_err();
        assert!(matches!(err, Error::BadFunctionArgument(_)));
    }

    #[tokio::test]
    async fn flush_without_chain_is_ok() {
        let mut conn = Connection::new(https_scheme(), "example.com", 443);
        assert!(conn.flush(FIRSTSOCKET).await.is_ok());
    }

    #[test]
    fn close_without_chain_clears_shutdown_slot() {
        let mut conn = Connection::new(https_scheme(), "example.com", 443);
        conn.shutdown.start[FIRSTSOCKET] = Some(Instant::now());
        conn.close(FIRSTSOCKET);
        assert!(conn.shutdown.start[FIRSTSOCKET].is_none());
    }
}
