//! Connection layer — the connection-filter chain, the [`Connection`] object,
//! and the chain-level `Curl_conn_*` / `Curl_conn_cf_*` public surface.
//!
//! This module is the Rust home of curl's connection machinery (`lib/connect.c`,
//! `lib/cfilters.c`, `lib/conncache.c`, `lib/cf-socket.c`, and the `lib/cf-*.c`
//! filter units). Where the C tree dispatched through the `Curl_cftype`
//! function-pointer vtable and a hand-linked `cf->next` chain, the rewrite models
//! each transport/protocol concern (raw socket, Happy Eyeballs, SOCKS, HTTP
//! CONNECT tunnels, the HAProxy PROXY header, TLS) as an implementor of the
//! [`filters::ConnectionFilter`] trait, stacked into a [`filters::FilterChain`]
//! whose ownership-based teardown replaces C's manual `destroy`/`Curl_free` walk
//! (Agent Action Plan §0.4.3 / §0.5.2). The whole subtree consumes its peers
//! through ordinary Rust paths (`crate::conn::<name>`) rather than via curl's C
//! `#include` graph.
//!
//! # `mod.rs` is the public face of `conn/`
//!
//! `mod.rs` plays three roles, mirroring `lib/cfilters.h` (the connection-level
//! API header) plus the connection-relevant slice of `lib/urldata.h`:
//!
//! 1. **It declares the whole `conn/` module tree** — every sibling file is a
//!    `pub mod` below, so the crate sees the complete connection subsystem
//!    (`cargo build` cannot resolve `crate::conn::socket`, … without these).
//! 2. **It defines [`Connection`]** — the Rust analog of C's
//!    `struct connectdata`. A `Connection` owns one [`filters::FilterChain`] per
//!    socket index and carries the per-connection metadata (destination key,
//!    transport, id, status bits, proxy descriptors, scheme) that the pool,
//!    the multi handle, and the protocol engines read.
//! 3. **It exposes the connection-level verbs** — the `Curl_conn_*` and
//!    `Curl_conn_cf_*` free functions (`lib/cfilters.h` L285-616) that
//!    `protocols/`, `transfer`, `multi`, `easy`, and the FFI layer call. Each
//!    delegates to the appropriate [`filters::FilterChain`] drive method; this
//!    file adds no transport logic of its own.
//!
//! # Architectural contracts
//!
//! * **`Connection` holds `cfilter[2]`.** The chain for `FIRSTSOCKET` carries
//!   the control/data stream of single-socket protocols (HTTP, the FTP control
//!   channel, …); `SECONDARYSOCKET` carries the FTP/etc. data connection.
//! * **`connect.rs` owns chain *construction* order;** `mod.rs` owns the
//!   connection-level *verbs*. The canonical bottom-up assembly
//!   (EYEBALLS → SOCKS → HTTP-PROXY → HAPROXY → SSL) lives in
//!   [`connect::Curl_conn_setup`]; the HTTPS ALPN-eyeballs variant lives in
//!   [`https_connect`]. [`establish_connection`] ties the two together.
//! * **ALPN flows upward.** The TLS / HTTPS coordinator filter negotiates ALPN;
//!   [`Curl_conn_cf_get_alpn_negotiated`] / [`Curl_conn_get_alpn_negotiated`]
//!   surface it so the protocol engines can pick h1/h2/h3.
//! * **The pool bundles by `destination`.** [`cache::ConnectionPool`] groups
//!   `Connection`s by their `destination` key; reuse-eligibility is
//!   `crate::url`'s job. `Connection` implements [`cache::PoolConn`] (and thus
//!   [`shutdown::ConnShutdown`]) so it can live in the pool and the
//!   graceful-shutdown registry directly.
//! * **Protocol-specific disconnect runs via an injected hook** (the
//!   `disconnect_hook` field), set by the protocol layer at attach time, so
//!   `conn/` never imports `crate::protocols` (avoiding a dependency cycle).
//!
//! # Memory safety
//!
//! The whole crate is compiled under the crate-root `#![forbid(unsafe_code)]`
//! declared in `lib.rs`; this module restates nothing and contains **zero**
//! `unsafe`. The only raw-fd exposure is the socket descriptor surfaced as a
//! plain `i64` through the safe [`std::os::unix::io::AsRawFd`] path inside
//! `socket.rs` (queried here via [`filters::FilterChain::get_socket`]); no
//! `pollfd`/`fd_set` is fabricated.

// ===========================================================================
// Module declarations — the 10 sibling files of `conn/`.
//
// This list MUST be exhaustive: a missing `pub mod` makes that sibling invisible
// to the crate and is a hard build failure. The order below is bottom-up
// (foundation → transport → proxy/tls filters → orchestration → pool) purely for
// readability; declaration order is not significant to the compiler.
//
// The `proxy`/`http`/`http2` feature gates on the proxy-tunnel filters mirror
// curl's `!CURL_DISABLE_PROXY` / `!CURL_DISABLE_HTTP` / `USE_NGHTTP2` build
// switches and MUST match the gates the sibling files were authored under.
// ===========================================================================

/// The asynchronous [`filters::ConnectionFilter`] trait (the `Curl_cftype`
/// vtable), the per-filter chain-link/lifecycle state ([`filters::CfState`]),
/// and the [`filters::FilterChain`] drive logic (`lib/cfilters.c`). This is the
/// contract every concrete filter implements and the engine every
/// `Curl_conn_*` verb here delegates to.
pub mod filters;

/// The bottom transport filter (`lib/cf-socket.c`) that owns the OS socket and
/// performs raw byte I/O (TCP, UDP/QUIC, UNIX-domain, TCP-accept for FTP active
/// mode), plus the SOCKS proxy connection-filter wrapper (`lib/socks.c`). Home
/// of the `TRNSPRT_*` transport tags re-exported below.
pub mod socket;

/// RFC 8305 Happy-Eyeballs v2 (`lib/cf-ip-happy.c`): the bottom "EYEBALLS"
/// filter that establishes the transport by racing IPv4/IPv6 candidate
/// addresses (alternating families, staggered ~200 ms attempts), promoting the
/// first to connect as its `next` and tearing down the losers.
pub mod happy_eyeballs;

/// The HAProxy PROXY-protocol v1 header emitter filter (`lib/cf-haproxy.c`):
/// immediately after the transport below connects it sends a single `PROXY …`
/// header line, then becomes a fully transparent pass-through (activated by
/// `CURLOPT_HAPROXYPROTOCOL`).
pub mod haproxy;

/// The HTTP/1.x `CONNECT` tunnel filter (`lib/cf-h1-proxy.c`): sends a
/// `CONNECT host:port HTTP/1.x` request through a forward proxy, processes the
/// response (including `407` proxy-auth and the multi-pass NTLM/Negotiate
/// handshake), and on a `2xx` becomes a transparent pass-through. Gated on
/// curl's `!CURL_DISABLE_PROXY && !CURL_DISABLE_HTTP` ⇒ the `proxy` + `http`
/// features.
#[cfg(all(feature = "proxy", feature = "http"))]
pub mod h1_proxy;

/// The HTTP/2 `CONNECT` tunnel filter (`lib/cf-h2-proxy.c`): tunnels traffic
/// inside HTTP/2 `DATA` frames on the CONNECT stream and stays active for the
/// connection's lifetime. Gated on curl's `!CURL_DISABLE_HTTP &&
/// !CURL_DISABLE_PROXY && USE_NGHTTP2` ⇒ the `proxy` + `http` + `http2`
/// features.
#[cfg(all(feature = "proxy", feature = "http", feature = "http2"))]
pub mod h2_proxy;

/// HTTPS connection establishment (`lib/vtls/vtls.c` cf-ssl +
/// `lib/cf-https-connect.c`): the TLS connection filter and the ALPN-eyeballs
/// HTTPS coordinator that races h3-over-QUIC against h2/h1-over-TLS and promotes
/// the first protocol stack to connect.
pub mod https_connect;

/// Connection setup and the SETUP meta-filter chain-builder (`lib/connect.c` +
/// `lib/connect.h`): assembles the connection-filter stack in the canonical
/// order, plus the connect-timeout budget, `conncontrol`, and address
/// formatting. Owns the chain *construction* order.
pub mod connect;

/// The `cshutdn` graceful-shutdown registry (`lib/cshutdn.c`): the per-multi
/// set of connections finishing their protocol/TLS close handshake in the
/// background after the transfer that used them detaches. Defines the
/// [`shutdown::ConnShutdown`] contract that [`Connection`] implements.
pub mod shutdown;

/// The connection pool / cache (`lib/conncache.c`): per-destination bundles of
/// reusable connections, the per-host/total/idle limits, oldest-idle eviction,
/// dead-connection pruning, and network-change invalidation. Shareable across
/// easy handles as a [`cache::SharedPool`]; defines the [`cache::PoolConn`]
/// contract that [`Connection`] implements.
pub mod cache;

// ===========================================================================
// Imports
// ===========================================================================

use std::net::SocketAddr;

use crate::error::{CurlError, Result};
use crate::proxy::CurlProxyType;
use crate::util::timeval::{self, CurlTime};

use crate::conn::filters::{
    CfQuery, CfQueryResult, ConnectionFilter, FilterChain, FilterData, IpQuadruple,
    CF_CTRL_FORGET_SOCKET, CF_TYPE_IP_CONNECT,
};
use crate::conn::shutdown::{ConnChangedNotifier, ConnShutdown, DisconnectHook, SocketIndex};

// ===========================================================================
// Ergonomic re-exports — short crate-internal paths for the most-used items.
//
// `pub use` re-exports (not imports): they never trip "unused import" and give
// callers `crate::conn::<Item>` without reaching into the leaf modules.
// ===========================================================================

pub use crate::conn::cache::{
    ConnectionPool, PoolConn, SharedPool, CPOOL_LIMIT_DEST, CPOOL_LIMIT_OK, CPOOL_LIMIT_TOTAL,
};
pub use crate::conn::connect::{
    ConnSetup, Curl_conn_set_multiplex, Curl_conn_setup, CONNCTRL_CONNECTION, CONNCTRL_KEEP,
    CONNCTRL_STREAM, CURL_CF_SSL_DEFAULT, CURL_CF_SSL_DISABLE, CURL_CF_SSL_ENABLE,
    DEFAULT_CONNECT_TIMEOUT,
};
pub use crate::conn::filters::{
    BoxFuture, CF_CTRL_CONN_INFO_UPDATE, CF_CTRL_DATA_DONE, CF_CTRL_DATA_DONE_SEND,
    CF_CTRL_DATA_PAUSE, CF_CTRL_DATA_SETUP, CF_CTRL_FLUSH, CF_TYPE_HTTP, CF_TYPE_MULTIPLEX,
    CF_TYPE_PROXY, CF_TYPE_SSL,
};
pub use crate::conn::shutdown::DEFAULT_SHUTDOWN_TIMEOUT_MS;

// The `TRNSPRT_*` transport tags are defined canonically in `socket.rs` (the
// filter that consumes them) and re-exported by `connect.rs`. Re-export them
// here too so `crate::conn::TRNSPRT_*` resolves — a single source of truth in
// `socket.rs`, never a second definition. (The AAP brief names `mod.rs` as the
// "canonical home"; because the already-authored `socket.rs` defines them and
// is out of scope for modification, honoring single-source-of-truth means
// re-exporting rather than redefining — the values are identical: 0/3/4/5/6.)
pub use crate::conn::socket::{TRNSPRT_NONE, TRNSPRT_QUIC, TRNSPRT_TCP, TRNSPRT_UDP, TRNSPRT_UNIX};

// ===========================================================================
// Socket-index constants — the two per-connection socket slots.
// ===========================================================================

/// The primary socket slot (C `FIRSTSOCKET`, `lib/urldata.h`). Carries the
/// control/data stream of single-socket protocols and the FTP control channel.
pub const FIRSTSOCKET: usize = 0;

/// The secondary socket slot (C `SECONDARYSOCKET`, `lib/urldata.h`). Carries the
/// FTP (and similar) data connection.
pub const SECONDARYSOCKET: usize = 1;

/// The number of socket slots a [`Connection`] tracks (`cfilter[2]`).
const NUM_SOCKETS: usize = 2;

// ===========================================================================
// Poll-bridge ABI surface (multi / FFI) — see the `Curl_conn_*_pollset` family
// in Phase 4 below. The C select/poll machinery is re-conceived on Tokio
// readiness (AAP §0.7.4); within `conn/`, per-filter `adjust_pollset` is
// deliberately omitted (the runtime drives readiness). These plain-data types
// exist purely so `curl_multi_socket_action` / `curl_multi_fdset` ABI consumers
// can still learn a connection's socket fd and the directions it wants polled.
// No `pollfd`/`fd_set`/`unsafe` is involved.
// ===========================================================================

/// A connection's socket-level poll request, in plain data.
///
/// This is the safe, Tokio-era replacement for the per-call mutation of C's
/// `struct easy_pollset`. [`Curl_conn_adjust_pollset`] fills one from a socket
/// chain: the bottom socket's descriptor plus the read/write interest derived
/// from the chain's `data_pending` / `needs_flush` state. The `multi` layer (or
/// the FFI) translates this into whatever the consumer's event loop expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Pollset {
    /// The connection's socket descriptor, or `-1` (C `CURL_SOCKET_BAD`) when
    /// the chain has no socket yet.
    pub socket: i64,
    /// Whether the connection wants to be polled for readability.
    pub want_read: bool,
    /// Whether the connection wants to be polled for writability.
    pub want_write: bool,
}

impl Pollset {
    /// An empty pollset with no socket and no interest (C `CURL_SOCKET_BAD`).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            socket: -1,
            want_read: false,
            want_write: false,
        }
    }

    /// Whether this pollset references a real socket and at least one direction.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.socket >= 0 && (self.want_read || self.want_write)
    }
}

// ===========================================================================
// PHASE 2 — the `Connection` type (the Rust `struct connectdata`).
//
// Oracle: `lib/urldata.h` `struct connectdata`. Only the *connection-relevant*
// fields live here; per-transfer / easy-handle state belongs in `crate::easy`.
// ===========================================================================

// --- Protocol scheme descriptor flags (subset, exact from urldata.h L526-535) -

/// `PROTOPT_NONE` — no special protocol options (`urldata.h` L526).
pub const PROTOPT_NONE: u32 = 0;
/// `PROTOPT_SSL` — the scheme uses TLS (`urldata.h` L527). Read by
/// `connect.rs`'s SSL step to decide whether to splice the TLS filter.
pub const PROTOPT_SSL: u32 = 1 << 0;
/// `PROTOPT_DUAL` — the scheme uses two connections, i.e. it needs the
/// `SECONDARYSOCKET` data channel (FTP) (`urldata.h` L528).
pub const PROTOPT_DUAL: u32 = 1 << 1;
/// `PROTOPT_NONETWORK` — the scheme uses no network at all (FILE)
/// (`urldata.h` L535). Makes [`Curl_conn_is_connected`] report `true` even
/// without a filter chain, matching curl.
pub const PROTOPT_NONETWORK: u32 = 1 << 4;

/// A lightweight descriptor of the protocol scheme a connection speaks — the
/// connection-visible slice of C's `struct Curl_handler`.
///
/// It carries the scheme's `name`, `default_port`, capability `flags`
/// (`PROTOPT_*`), and protocol id (`protocol`, a `CURLPROTO_*` bit). The full
/// protocol *engine* (the `Protocol` trait) lives in `crate::protocols`; storing
/// only this descriptor here is the deliberate split that keeps `conn/` free of
/// any `crate::protocols` dependency (no import cycle — AAP §0.5.2). The
/// connection-level code that needs scheme awareness ([`connect`]'s SSL step,
/// [`Curl_conn_is_connected`]'s no-network fallback) reads these flags only.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SchemeDescriptor {
    /// The scheme name in lower case (e.g. `"https"`); C `Curl_handler.scheme`.
    pub name: String,
    /// The scheme's default port; C `Curl_handler.defport`.
    pub default_port: u16,
    /// The `PROTOPT_*` capability bitset; C `Curl_handler.flags`.
    pub flags: u32,
    /// The `CURLPROTO_*` protocol id; C `Curl_handler.protocol`.
    pub protocol: u32,
}

impl SchemeDescriptor {
    /// Build a scheme descriptor.
    #[must_use]
    pub fn new(name: impl Into<String>, default_port: u16, flags: u32, protocol: u32) -> Self {
        Self {
            name: name.into(),
            default_port,
            flags,
            protocol,
        }
    }

    /// Whether the scheme uses TLS (`PROTOPT_SSL`).
    #[must_use]
    pub const fn is_ssl(&self) -> bool {
        (self.flags & PROTOPT_SSL) != 0
    }

    /// Whether the scheme uses no network (`PROTOPT_NONETWORK`, e.g. FILE).
    #[must_use]
    pub const fn is_nonetwork(&self) -> bool {
        (self.flags & PROTOPT_NONETWORK) != 0
    }

    /// Whether the scheme uses a second (data) connection (`PROTOPT_DUAL`).
    #[must_use]
    pub const fn uses_dual(&self) -> bool {
        (self.flags & PROTOPT_DUAL) != 0
    }
}

/// A connection's view of a configured proxy — the endpoint identity only.
///
/// The full proxy parser, credentials, and no-proxy machinery is
/// `crate::proxy`'s responsibility; the connection records just the display
/// host, port, and [`CurlProxyType`] for tracing, reuse keys, and to drive the
/// CONNECT/SOCKS filters. Mirrors the connection-relevant fields of C's
/// `conn->http_proxy` / `conn->socks_proxy` (`struct proxy_info`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProxyDescriptor {
    /// The proxy's display host name (C `proxy_info.host.dispname`).
    pub host: String,
    /// The proxy's port (C `proxy_info.port`).
    pub port: u16,
    /// The proxy type (C `proxy_info.proxytype`).
    pub proxytype: CurlProxyType,
}

impl ProxyDescriptor {
    /// Build a proxy descriptor.
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16, proxytype: CurlProxyType) -> Self {
        Self {
            host: host.into(),
            port,
            proxytype,
        }
    }
}

/// The per-connection status bits — the Rust face of C's `struct ConnectionBits`
/// (`urldata.h`), holding the connection-relevant subset.
///
/// # The `close` invariant
///
/// The `close` bit (C `conn->bits.close`) is **assigned only** through
/// [`connect::conncontrol`], reached via [`Connection::connclose`] /
/// [`Connection::connkeep`] — mirroring curl's rule (`urldata.h` L348) that the
/// `connclose()` / `connkeep()` macros are its sole mutators. The field is
/// therefore module-private (read it with [`Connection::is_closed`] /
/// [`ConnectionBits::close`]); every other bit is a plain `pub` boolean.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnectionBits {
    /// `conn->bits.close`: the connection must be closed, not reused. Private to
    /// preserve the conncontrol-only invariant.
    close: bool,
    /// `conn->bits.multiplex`: the connection multiplexes streams (HTTP/2/3).
    pub multiplex: bool,
    /// `conn->bits.socksproxy`: a SOCKS proxy is in use.
    pub socksproxy: bool,
    /// `conn->bits.httpproxy`: an HTTP proxy is in use.
    pub httpproxy: bool,
    /// `conn->bits.tunnel_proxy`: the proxy is tunneled through (CONNECT).
    pub tunnel_proxy: bool,
    /// `conn->bits.proxy_ssl_connected`-style flag: TLS to the proxy is up.
    pub proxy_ssl: bool,
    /// `conn->bits.in_cpool`: the connection currently lives in the pool.
    pub in_cpool: bool,
    /// `conn->bits.reuse`: this connection was taken from the pool (reused).
    pub reuse: bool,
    /// `conn->bits.no_reuse`: the connection must not be reused (e.g. after a
    /// network change).
    pub no_reuse: bool,
    /// `conn->bits.aborted`: the owning transfer was aborted (fast teardown).
    pub aborted: bool,
    /// `conn->bits.tcp_fastopen`: TCP Fast Open was requested for this
    /// connection.
    pub tcp_fastopen: bool,
}

impl ConnectionBits {
    /// Read the `close` bit (C `conn->bits.close`). The bit is only ever set via
    /// [`connect::conncontrol`] (see [`Connection::connclose`] /
    /// [`Connection::connkeep`]).
    #[must_use]
    pub const fn close(&self) -> bool {
        self.close
    }
}

/// The Rust analog of curl's `struct connectdata` — a single network connection
/// and the object every protocol runs over.
///
/// A `Connection` owns one [`FilterChain`] per socket index (the heart of the
/// connection) plus the connection-level metadata the pool, the multi handle,
/// and the protocol engines read. The public connection verbs (`Curl_conn_*` /
/// `Curl_conn_cf_*`, defined below) operate on a `Connection` by delegating to
/// the appropriate [`FilterChain`].
///
/// Construction: build with [`Connection::new`], then let [`connect::Curl_conn_setup`]
/// (via [`establish_connection`]) populate `cfilter[sockindex]`. The pool assigns
/// `connection_id` when the connection is added ([`cache::ConnectionPool::add`]).
pub struct Connection {
    /// One connection-filter chain per socket index — `cfilter[FIRSTSOCKET]` and
    /// `cfilter[SECONDARYSOCKET]` (C `conn->cfilter[2]`). This is the heart of
    /// the connection; an empty chain means the slot is unused.
    pub cfilter: [FilterChain; NUM_SOCKETS],
    /// The normalized `hostname+port+scope` pool key (C `conn->destination`,
    /// `urldata.h` L614). The cache bundles connections by this string.
    pub destination: String,
    /// The connection's target remote host name (C `conn->host.name`). Used as
    /// the destination fallback by [`Curl_conn_get_current_host`] and for
    /// tracing; the live peer address (post-connect) is the `remote_addr` cache.
    pub remote_host: String,
    /// The connection's target remote port (C `conn->remote_port`).
    pub remote_port: u16,
    /// The wanted transport — one of `TRNSPRT_*` (C `conn->transport_wanted`,
    /// `urldata.h` L719).
    pub transport_wanted: u8,
    /// The pool-assigned stable id (C `conn->connection_id`); `-1` until the
    /// connection is added to a [`cache::ConnectionPool`].
    pub connection_id: i64,
    /// The per-connection status bits (C `conn->bits`).
    pub bits: ConnectionBits,
    /// The forward HTTP proxy descriptor, if any (C `conn->http_proxy`).
    pub http_proxy: Option<ProxyDescriptor>,
    /// The SOCKS proxy descriptor, if any (C `conn->socks_proxy`).
    pub socks_proxy: Option<ProxyDescriptor>,
    /// The protocol scheme descriptor (the lightweight `Curl_handler` stand-in,
    /// C `conn->handler`).
    pub scheme: SchemeDescriptor,
    /// The diagnostics context threaded into the [`FilterChain`] drive methods
    /// (verbosity + the captured `failf` error string). Built from the owning
    /// easy handle's `set.verbose`.
    pub filter_data: FilterData,
    /// The connect-timeout budget in ms (C `data->set.connecttimeout`),
    /// defaulting to [`DEFAULT_CONNECT_TIMEOUT`].
    pub connect_timeout_ms: i64,
    /// The graceful-shutdown budget in ms (C `conn->shutdown.timeout_ms`),
    /// defaulting to [`DEFAULT_SHUTDOWN_TIMEOUT_MS`].
    pub shutdown_timeout_ms: i64,
    /// Whether the connection was set up with `CURLOPT_CONNECT_ONLY`
    /// (C `conn->connect_only`); such connections hand their socket to the app.
    pub connect_only: bool,
    /// Cached connected remote address per socket (C `conn->primary` /
    /// `conn->remote_addr`); filled from the chain's `RemoteAddr` query.
    remote_addr: [Option<SocketAddr>; NUM_SOCKETS],
    /// The injected protocol-disconnect hook (BOUNDARY): set by the protocol
    /// layer at attach time so `shutdown`/`terminate` can run the
    /// protocol-specific disconnect WITHOUT `conn/` importing `crate::protocols`.
    /// One-shot, mirroring the C `disconnect` handler.
    disconnect_hook: Option<DisconnectHook>,
    /// Opaque per-connection protocol state — the Rust analog of curl's
    /// `conn->proto` union and the `CURL_META_*` connection meta map (e.g.
    /// `CURL_META_SSH_CONN`). A protocol engine (for example
    /// `crate::protocols::ssh`) boxes its per-connection state here on connect
    /// and reclaims it on done/disconnect. It is stored as `dyn Any` so that
    /// `conn/` stays strictly acyclic: it persists protocol state without ever
    /// naming a `crate::protocols` type. Access is via [`Connection::set_proto_state`],
    /// [`Connection::proto_state_mut`], and [`Connection::take_proto_state`].
    ///
    /// The bound is `Send` (not `Send + Sync`) to match the connection's other
    /// boxed-trait field [`disconnect_hook`](Self::set_disconnect_hook) (also
    /// `Send`-only) — a `Connection` is moved between async tasks but never
    /// shared, so protocol sessions that are `Send` but not `Sync` (e.g. a
    /// `russh` client handle) can be parked here.
    proto_state: Option<Box<dyn core::any::Any + Send>>,
    /// An optional notifier for the owning multi handle, invoked when the
    /// connection becomes multiplexed (the C `Curl_multi_connchanged`).
    attached_multi: Option<ConnChangedNotifier>,
    /// The number of transfers currently attached (C `conn->attached_xfers`);
    /// `> 0` means the connection is in use and not idle-evictable.
    attached_xfers: u32,
    /// When the connection was last used (C `conn->lastused`); the pool measures
    /// idle age from this instant.
    lastused: CurlTime,
    /// When the connection was created (C `conn->created`).
    pub created: CurlTime,
}

impl Connection {
    /// Build an empty connection for a destination/transport/scheme.
    ///
    /// Both filter chains start empty (call [`establish_connection`] /
    /// [`connect::Curl_conn_setup`] to populate `cfilter[sockindex]`).
    /// `connection_id` is `-1` until a [`cache::ConnectionPool`] assigns one.
    #[must_use]
    pub fn new(
        destination: impl Into<String>,
        transport_wanted: u8,
        scheme: SchemeDescriptor,
    ) -> Self {
        let now = timeval::curlx_now();
        Self {
            cfilter: [FilterChain::new(), FilterChain::new()],
            destination: destination.into(),
            remote_host: String::new(),
            remote_port: 0,
            transport_wanted,
            connection_id: -1,
            bits: ConnectionBits::default(),
            http_proxy: None,
            socks_proxy: None,
            scheme,
            filter_data: FilterData::new(),
            connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT,
            shutdown_timeout_ms: DEFAULT_SHUTDOWN_TIMEOUT_MS,
            connect_only: false,
            remote_addr: [None; NUM_SOCKETS],
            disconnect_hook: None,
            proto_state: None,
            attached_multi: None,
            attached_xfers: 0,
            lastused: now,
            created: now,
        }
    }

    /// Builder: set the diagnostics verbosity (mirrors `data->set.verbose`).
    #[must_use]
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.filter_data = FilterData::with_verbose(verbose);
        self
    }

    /// Record the connection's target remote host and port (C `conn->host.name`
    /// / `conn->remote_port`). These are the destination identity used by
    /// [`Curl_conn_get_current_host`] and tracing.
    pub fn set_remote(&mut self, host: impl Into<String>, port: u16) {
        self.remote_host = host.into();
        self.remote_port = port;
    }

    // ---- the `close` invariant: connclose / connkeep -------------------

    /// Mark the connection to be closed and not reused (C `connclose(conn,
    /// reason)`, `urldata.h` L348).
    ///
    /// This is one of the only two sanctioned mutators of `bits.close`; it
    /// routes through [`connect::conncontrol`] with [`CONNCTRL_CONNECTION`],
    /// preserving curl's invariant that the close bit is never assigned directly.
    pub fn connclose(&mut self, reason: &str) {
        #[cfg(debug_assertions)]
        connect::conncontrol_with_reason(
            &mut self.bits.close,
            self.bits.multiplex,
            CONNCTRL_CONNECTION,
            reason,
        );
        #[cfg(not(debug_assertions))]
        {
            let _ = reason;
            connect::conncontrol(
                &mut self.bits.close,
                self.bits.multiplex,
                CONNCTRL_CONNECTION,
            );
        }
    }

    /// Mark the connection to be kept alive for reuse (C `connkeep(conn,
    /// reason)`, `urldata.h` L348).
    ///
    /// The companion of [`connclose`](Self::connclose); routes through
    /// [`connect::conncontrol`] with [`CONNCTRL_KEEP`].
    pub fn connkeep(&mut self, reason: &str) {
        #[cfg(debug_assertions)]
        connect::conncontrol_with_reason(
            &mut self.bits.close,
            self.bits.multiplex,
            CONNCTRL_KEEP,
            reason,
        );
        #[cfg(not(debug_assertions))]
        {
            let _ = reason;
            connect::conncontrol(&mut self.bits.close, self.bits.multiplex, CONNCTRL_KEEP);
        }
    }

    /// Read the `close` bit (C `conn->bits.close`).
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.bits.close()
    }

    // ---- multiplex / multi notification --------------------------------

    /// Mark the connection as multiplexed and, if the bit actually changed,
    /// notify the attached multi handle (the C `Curl_conn_set_multiplex` +
    /// `Curl_multi_connchanged(conn->attached_multi)` pair, `connect.c` L595).
    ///
    /// Returns `true` when the multiplex bit transitioned from `false` to
    /// `true`. Delegates the bit flip to [`connect::Curl_conn_set_multiplex`].
    pub fn set_multiplex(&mut self) -> bool {
        let changed = connect::Curl_conn_set_multiplex(&mut self.bits.multiplex);
        if changed {
            if let Some(notify) = self.attached_multi.as_ref() {
                notify();
            }
        }
        changed
    }

    // ---- injected boundaries (set by protocol / multi layers) ----------

    /// Install the one-shot protocol-disconnect hook (the BOUNDARY that lets
    /// `shutdown`/`terminate` run a protocol-specific disconnect without `conn/`
    /// importing `crate::protocols`).
    pub fn set_disconnect_hook(&mut self, hook: DisconnectHook) {
        self.disconnect_hook = Some(hook);
    }

    /// Install opaque per-connection protocol state (the C `conn->proto` /
    /// `CURL_META_SSH_CONN` analog). Any previously stored state is dropped.
    ///
    /// The state is type-erased (`dyn Any`) so that `conn/` never depends on
    /// `crate::protocols`; protocol engines retrieve their concrete type via
    /// [`proto_state_mut`](Self::proto_state_mut).
    pub fn set_proto_state(&mut self, state: Box<dyn core::any::Any + Send>) {
        self.proto_state = Some(state);
    }

    /// Borrow the per-connection protocol state, downcast to the protocol's
    /// concrete type `T`. Returns `None` if no state is installed or the stored
    /// state is not a `T`.
    #[must_use]
    pub fn proto_state_mut<T: core::any::Any>(&mut self) -> Option<&mut T> {
        self.proto_state.as_mut().and_then(|b| b.downcast_mut::<T>())
    }

    /// Borrow the per-connection protocol state immutably, downcast to `T`.
    #[must_use]
    pub fn proto_state_ref<T: core::any::Any>(&self) -> Option<&T> {
        self.proto_state.as_ref().and_then(|b| b.downcast_ref::<T>())
    }

    /// Remove and return the per-connection protocol state, so the protocol
    /// engine can take ownership during done/disconnect (e.g. to move the live
    /// session into the [`disconnect_hook`](Self::set_disconnect_hook) closure).
    #[must_use]
    pub fn take_proto_state(&mut self) -> Option<Box<dyn core::any::Any + Send>> {
        self.proto_state.take()
    }

    /// Attach the owning multi handle's change notifier (invoked by
    /// [`set_multiplex`](Self::set_multiplex)).
    pub fn set_attached_multi(&mut self, notifier: ConnChangedNotifier) {
        self.attached_multi = Some(notifier);
    }

    // ---- transfer attach bookkeeping (C `conn->attached_xfers`) --------

    /// The number of transfers currently riding this connection
    /// (C `conn->attached_xfers`).
    #[must_use]
    pub const fn attached_xfers(&self) -> u32 {
        self.attached_xfers
    }

    /// Record that one more transfer attached to this connection.
    pub fn attach_xfer(&mut self) {
        self.attached_xfers = self.attached_xfers.saturating_add(1);
    }

    /// Record that one transfer detached from this connection.
    pub fn detach_xfer(&mut self) {
        self.attached_xfers = self.attached_xfers.saturating_sub(1);
    }

    /// Record that the connection was used as of `when` (C `conn->lastused`).
    pub fn mark_used(&mut self, when: CurlTime) {
        self.lastused = when;
    }

    /// The cached connected remote address for `sockindex`, if known.
    #[must_use]
    pub fn cached_remote_addr(&self, sockindex: usize) -> Option<SocketAddr> {
        self.remote_addr.get(sockindex).copied().flatten()
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `disconnect_hook` / `attached_multi` are closures (not `Debug`);
        // summarise the connection by its identity and observable state.
        f.debug_struct("Connection")
            .field("connection_id", &self.connection_id)
            .field("destination", &self.destination)
            .field("remote_host", &self.remote_host)
            .field("remote_port", &self.remote_port)
            .field("scheme", &self.scheme.name)
            .field("transport_wanted", &self.transport_wanted)
            .field("bits", &self.bits)
            .field("cfilter", &self.cfilter)
            .field("attached_xfers", &self.attached_xfers)
            .field("has_disconnect_hook", &self.disconnect_hook.is_some())
            .finish()
    }
}

// ===========================================================================
// Internal helper — socket-index validity (the C `CONN_SOCK_IDX_VALID`).
// ===========================================================================

/// Whether `sockindex` names a valid socket slot (`0` or `1`) — the Rust face
/// of curl's `CONN_SOCK_IDX_VALID` guard. Every `Curl_conn_*` /
/// `Curl_conn_cf_*` entry validates its index through this, returning the same
/// "bad argument" / "false" defaults curl uses for an out-of-range index.
#[inline]
#[must_use]
fn sock_idx_valid(sockindex: usize) -> bool {
    sockindex < NUM_SOCKETS
}

// ===========================================================================
// Chain-level filter primitives — the `Curl_conn_cf_*` surface
// (oracle `lib/cfilters.h` L285-348, `lib/cfilters.c` L329-947).
//
// These operate on a *single filter* (`cf`) within a chain — the raw,
// per-filter verbs, as distinct from the per-sockindex `Curl_conn_*` surface
// (Phase 4 below) that drives a whole chain.
//
// # Modelling `cf` without raw pointers
//
// C addresses an interior filter by the bare `struct Curl_cfilter *cf`. The
// safe core owns filters inside their [`FilterChain`] (head-first, `Box`-linked)
// and never aliases them with raw pointers, so the Rust surface splits by intent:
//
// * **Structural** ops (`add` / `insert_after` / `discard*`) mutate a chain's
//   shape, so they take `(conn, sockindex, …)` and delegate to the owning
//   [`FilterChain`] (which performs the `Box` splicing/teardown).
// * **Behavioral** ops (`connect` / `close` / `send` / `recv` / `cntrl`) act on
//   one filter, so they take `cf: Option<&mut dyn ConnectionFilter>` — `Some`
//   is C's non-NULL `cf`, `None` is C's `cf == NULL`, reproducing the exact
//   default error codes (`cfilters.c` L389-432).
// * **Query** getters take `cf: Option<&dyn ConnectionFilter>` and ask the
//   filter directly; an unanswered query (or `None`) yields curl's fallback.
//
// Callers reach the filter they want with [`FilterChain::head_ref`] /
// [`FilterChain::head_mut`] (curl's `conn->cfilter[sockindex]`) or, for an
// interior filter, the trait's [`ConnectionFilter::next_ref`] /
// [`ConnectionFilter::next_mut`].
// ===========================================================================

// --- Structural: add / insert / discard ------------------------------------

/// Add a single filter at the **top** of the `sockindex` chain on `conn`
/// (`Curl_conn_cf_add`, `cfilters.c` L329).
///
/// The new filter becomes the outermost (head) filter, its `next` pointing at
/// the previous head — matching C's `cf->next = conn->cfilter[sockindex];
/// conn->cfilter[sockindex] = cf;`. (The AAP brief's phrasing "append at the
/// bottom" is superseded by the authoritative `cfilters.c` + [`FilterChain`]
/// semantics, which both insert at the top; [`FilterChain`] is the single
/// source of truth.) An out-of-range `sockindex` is a no-op and the filter is
/// dropped, mirroring curl's `DEBUGASSERT`-guarded contract.
#[allow(non_snake_case)]
pub fn Curl_conn_cf_add(conn: &mut Connection, sockindex: usize, cf: Box<dyn ConnectionFilter>) {
    if !sock_idx_valid(sockindex) {
        return;
    }
    conn.cfilter[sockindex].add_filter(cf);
}

/// Splice `cf_new` (a filter or whole sub-chain) into the `sockindex` chain
/// immediately after the filter at `at_index` (`Curl_conn_cf_insert_after`,
/// `cfilters.c` L345).
///
/// This is the primitive every `*_insert_after` constructor uses — how the
/// SETUP meta-filter and the eyeballs/proxy/SSL filters splice themselves in.
/// The filters previously below `at_index` are reattached below `cf_new`'s
/// tail, preserving order. Returns [`CurlError::BadFunctionArgument`] for an
/// invalid `sockindex` or a missing `at_index`.
#[allow(non_snake_case)]
pub fn Curl_conn_cf_insert_after(
    conn: &mut Connection,
    sockindex: usize,
    at_index: usize,
    cf_new: Box<dyn ConnectionFilter>,
) -> Result<()> {
    if !sock_idx_valid(sockindex) {
        return Err(CurlError::BadFunctionArgument);
    }
    conn.cfilter[sockindex].insert_after_index(at_index, cf_new)
}

/// Extract and destroy the single filter at `index` in the `sockindex` chain,
/// reconnecting the chain around it (`Curl_conn_cf_discard`, `cfilters.c`
/// L365). Returns `true` if a filter existed there.
///
/// Teardown is deterministic: the removed filter's [`Drop`] runs its cleanup
/// (curl's explicit `Curl_conn_cf_discard_chain` of the unlinked node).
#[allow(non_snake_case)]
pub fn Curl_conn_cf_discard(conn: &mut Connection, sockindex: usize, index: usize) -> bool {
    if !sock_idx_valid(sockindex) {
        return false;
    }
    conn.cfilter[sockindex].remove_at(index)
}

/// Discard the filter at `from_index` and **every filter below it** in the
/// `sockindex` chain (`Curl_conn_cf_discard_chain`, `cfilters.c` L118).
///
/// Implemented by repeatedly removing the filter that occupies `from_index`:
/// each [`FilterChain::remove_at`] pulls the successor up into that slot, so the
/// loop strips `from_index, from_index+1, …` to the chain end. Each removed
/// filter is dropped (its teardown runs) as it is unlinked.
#[allow(non_snake_case)]
pub fn Curl_conn_cf_discard_chain(conn: &mut Connection, sockindex: usize, from_index: usize) {
    if !sock_idx_valid(sockindex) {
        return;
    }
    while conn.cfilter[sockindex].remove_at(from_index) {}
}

/// Remove and destroy every filter in the `sockindex` chain on `conn`
/// (`Curl_conn_cf_discard_all`, `cfilters.c` L138).
///
/// Dropping the chain's head `Box` drops the whole owned, `next`-linked stack,
/// running each filter's teardown in order.
#[allow(non_snake_case)]
pub fn Curl_conn_cf_discard_all(conn: &mut Connection, sockindex: usize) {
    if !sock_idx_valid(sockindex) {
        return;
    }
    conn.cfilter[sockindex].discard_all();
}

// --- Behavioral: connect / close / send / recv / cntrl on one filter --------

/// Connect a single filter `cf` (`Curl_conn_cf_connect`, `cfilters.c` L389).
///
/// This is the raw per-filter connect — curl's `cf->cft->do_connect(cf, data,
/// done)` — *not* the whole-chain drive (that is [`Curl_conn_connect`], which
/// loops and broadcasts the post-connect info update). C's `*done` out-param
/// collapses into the future resolving: awaiting to `Ok(())` is `*done == TRUE`.
/// A `None` filter (C's `cf == NULL`) yields [`CurlError::FailedInit`], exactly
/// as in C.
#[allow(non_snake_case)]
pub async fn Curl_conn_cf_connect(
    cf: Option<&mut dyn ConnectionFilter>,
    data: &mut FilterData,
) -> Result<()> {
    match cf {
        Some(c) => c.connect(data).await,
        None => Err(CurlError::FailedInit),
    }
}

/// Close a single filter `cf` (`Curl_conn_cf_close`, `cfilters.c` L398): clears
/// its connected bit and closes its `next`. A `None` filter is a no-op, matching
/// C's `if(cf) …` guard.
#[allow(non_snake_case)]
pub fn Curl_conn_cf_close(cf: Option<&mut dyn ConnectionFilter>) {
    if let Some(c) = cf {
        c.close();
    }
}

/// Send `buf` through a single filter `cf` (`Curl_conn_cf_send`, `cfilters.c`
/// L404), optionally signalling end-of-stream with `eos`. Returns the number of
/// bytes accepted.
///
/// A `None` filter (C's `cf == NULL`) returns [`CurlError::SendError`] — curl's
/// exact `*pnwritten = 0; return CURLE_SEND_ERROR;` default. (Note this is the
/// NULL-`cf` path; the *bottom-of-chain* default of a real filter's `send` is
/// curl's counter-intuitive `CURLE_RECV_ERROR`, preserved in
/// [`ConnectionFilter::send`].)
#[allow(non_snake_case)]
pub async fn Curl_conn_cf_send(
    cf: Option<&mut dyn ConnectionFilter>,
    buf: &[u8],
    eos: bool,
) -> Result<usize> {
    match cf {
        Some(c) => c.send(buf, eos).await,
        None => Err(CurlError::SendError),
    }
}

/// Receive into `buf` through a single filter `cf` (`Curl_conn_cf_recv`,
/// `cfilters.c` L414). Returns the number of bytes read; `0` means EOF.
///
/// A `None` filter (C's `cf == NULL`) returns [`CurlError::RecvError`] — curl's
/// exact `*pnread = 0; return CURLE_RECV_ERROR;` default. (The *bottom-of-chain*
/// default of a real filter's `recv` is curl's counter-intuitive
/// `CURLE_SEND_ERROR`, preserved in [`ConnectionFilter::recv`].)
#[allow(non_snake_case)]
pub async fn Curl_conn_cf_recv(
    cf: Option<&mut dyn ConnectionFilter>,
    buf: &mut [u8],
) -> Result<usize> {
    match cf {
        Some(c) => c.recv(buf).await,
        None => Err(CurlError::RecvError),
    }
}

/// Broadcast a control event down the chain starting at `cf`
/// (`Curl_conn_cf_cntrl`, `cfilters.c` L866): invoke each filter's
/// [`ConnectionFilter::cntrl`] from `cf` toward the socket.
///
/// When `ignore_result` is `false`, the first filter returning an error stops
/// the walk and that error is returned; otherwise every filter is visited and
/// the result is `Ok(())`. A `None` starting filter visits nothing and returns
/// `Ok(())`.
#[allow(non_snake_case)]
pub fn Curl_conn_cf_cntrl(
    cf: Option<&mut (dyn ConnectionFilter + 'static)>,
    ignore_result: bool,
    event: i32,
    arg1: i32,
) -> Result<()> {
    // `cf` is annotated `+ 'static` to match [`ConnectionFilter::next_mut`]'s
    // `&mut (dyn ConnectionFilter + 'static)` return: every chained filter is
    // owned as a `Box<dyn ConnectionFilter + 'static>`, so the walk reseats
    // `cur` with each successor. (Mutable references are invariant over the
    // trait-object lifetime, so the elided form would not type-check here.)
    let mut cur = cf;
    while let Some(c) = cur {
        let result = c.cntrl(event, arg1);
        if !ignore_result {
            result?;
        }
        cur = c.next_mut();
    }
    Ok(())
}

// --- Query getters: socket / ip-info / flush / transport / ALPN -------------

/// The raw socket descriptor of the filter chain starting at `cf`
/// (`Curl_conn_cf_get_socket`, `cfilters.c` L883), or `-1` (C
/// `CURL_SOCKET_BAD`) when unavailable.
///
/// Returned as a plain `i64` obtained through the safe `AsRawFd` path inside
/// `socket.rs` (surfaced via [`CfQuery::Socket`]); no `unsafe`, no fabricated
/// `pollfd`. This fd is what the multi socket-action ABI needs.
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_cf_get_socket(cf: Option<&dyn ConnectionFilter>) -> i64 {
    match cf.map(|c| c.query(CfQuery::Socket)) {
        Some(Ok(CfQueryResult::Socket(s))) => s,
        _ => -1,
    }
}

/// IP-level info for the connection at `cf` (`Curl_conn_cf_get_ip_info`,
/// `cfilters.c` L923): the IPv6 flag plus the [`IpQuadruple`] (local/remote
/// addresses + ports + transport). `None` when the query is unanswered or `cf`
/// is absent (C's `CURLE_UNKNOWN_OPTION`).
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_cf_get_ip_info(cf: Option<&dyn ConnectionFilter>) -> Option<(bool, IpQuadruple)> {
    match cf.map(|c| c.query(CfQuery::IpInfo)) {
        Some(Ok(CfQueryResult::IpInfo { is_ipv6, quadruple })) => Some((is_ipv6, quadruple)),
        _ => None,
    }
}

/// Whether the filter at `cf` has unsent buffered data
/// (`Curl_conn_cf_needs_flush`, `cfilters.c` L751): `true` only when the
/// [`CfQuery::NeedFlush`] query succeeds and reports pending data, matching
/// curl's `(result || !pending) ? FALSE : TRUE`.
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_cf_needs_flush(cf: Option<&dyn ConnectionFilter>) -> bool {
    matches!(
        cf.map(|c| c.query(CfQuery::NeedFlush)),
        Some(Ok(CfQueryResult::NeedFlush(true)))
    )
}

/// The transport (`TRNSPRT_*`) the filter at `cf` uses
/// (`Curl_conn_cf_get_transport`, `cfilters.c` L892).
///
/// Falls back to `fallback_transport` (the connection's `transport_wanted`)
/// when the [`CfQuery::Transport`] query is unanswered — curl's
/// `data->conn->transport_wanted` default.
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_cf_get_transport(cf: Option<&dyn ConnectionFilter>, fallback_transport: u8) -> u8 {
    match cf.map(|c| c.query(CfQuery::Transport)) {
        Some(Ok(CfQueryResult::Transport(t))) => t,
        _ => fallback_transport,
    }
}

/// The ALPN protocol the server selected on the chain at `cf`
/// (`Curl_conn_cf_get_alpn_negotiated`, `cfilters.c` L901), or `None`.
///
/// This is the signal the HTTPS coordinator ([`https_connect`]) and the HTTP
/// engines use to pick h1/h2/h3. C returns a `const char *` into filter-owned
/// storage; the memory-safe equivalent returns an owned [`String`] decoded from
/// the negotiated ALPN identifier bytes (a non-UTF-8 identifier — never emitted
/// by the TLS layer for the registered ALPN ids — decodes lossily).
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_cf_get_alpn_negotiated(cf: Option<&dyn ConnectionFilter>) -> Option<String> {
    match cf.map(|c| c.query(CfQuery::AlpnNegotiated)) {
        Some(Ok(CfQueryResult::AlpnNegotiated(Some(alpn)))) => {
            Some(String::from_utf8_lossy(&alpn).into_owned())
        }
        _ => None,
    }
}

/// The peer (server) certificate chain in DER form for the chain at `cf`
/// (the [`CfQuery::PeerCerts`] query the non-proxy SSL filter answers from the
/// `rustls` `TlsConnection::peer_certificates` it retained at connect), leaf
/// first. Empty when the query is unanswered, `cf` is absent, or the
/// connection is not TLS.
///
/// There is no direct C analog — curl's TLS backends push the chain into
/// `data->info` during the handshake (`Curl_ssl_push_certinfo_len`). The
/// memory-safe core defers that to a post-connect pull through this query so
/// the TLS layer stays free of a back-reference to the easy handle. Backs
/// `CURLINFO_CERTINFO` / `%{certs}`.
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_cf_get_peer_certs(cf: Option<&dyn ConnectionFilter>) -> Vec<Vec<u8>> {
    match cf.map(|c| c.query(CfQuery::PeerCerts)) {
        Some(Ok(CfQueryResult::PeerCerts(certs))) => certs,
        _ => Vec::new(),
    }
}

// ===========================================================================
// Connection-level API — the `Curl_conn_*` per-sockindex surface
// (oracle `lib/cfilters.h` L362-616, `lib/cfilters.c` L144-1130).
//
// These are the verbs `protocols/`, `transfer`, `multi`, `easy`, and the FFI
// layer call. Each validates `sockindex`, then delegates to the appropriate
// [`FilterChain`] drive method on `conn.cfilter[sockindex]` (curl's
// `data->conn->cfilter[sockindex]`); this file adds no transport logic.
//
// The asynchronous methods need both the chain (`&mut`) and the connection's
// `filter_data` diagnostics context (`&mut`) at once; that is expressed as two
// disjoint field borrows of `conn`.
// ===========================================================================

// --- Establishment ---------------------------------------------------------

/// Bring the `sockindex` filter chain into the fully-connected state
/// (`Curl_conn_connect`, `cfilters.c` L491) — the main connection-establishment
/// entry the transfer engine calls.
///
/// Drives the chain's head filter (the SETUP meta-filter or, for HTTPS, the
/// ALPN-eyeballs coordinator) to completion, bounded by the connection's
/// `connect_timeout_ms`. On success the chain broadcasts its post-connect info
/// update (handled inside [`FilterChain::connect`]).
///
/// # The `blocking` flag and `*done`
///
/// curl loops `do_connect` + `Curl_poll` until `*done == TRUE`, optionally
/// non-blocking. Here the `.await` *is* that loop: the future resolves exactly
/// when curl's `*done` would be set, and the Tokio reactor supplies the
/// readiness curl's `Curl_poll`/`easy_pollset` provided (AAP §0.4.4). The
/// `blocking` parameter is retained for ABI-surface parity; awaiting always
/// drives the chain to completion, while a non-blocking caller (the multi
/// layer) achieves "return while filters negotiate" by polling this future
/// rather than by a flag here. An empty chain yields [`CurlError::FailedInit`]
/// (curl's `*done = FALSE; return CURLE_FAILED_INIT`).
#[allow(non_snake_case)]
pub async fn Curl_conn_connect(
    conn: &mut Connection,
    sockindex: usize,
    blocking: bool,
) -> Result<()> {
    let _ = blocking; // see doc: the await drives to completion; advisory only.
    if !sock_idx_valid(sockindex) {
        return Err(CurlError::BadFunctionArgument);
    }
    let timeout = conn.connect_timeout_ms;
    let data = &mut conn.filter_data;
    let chain = &mut conn.cfilter[sockindex];
    chain.connect(Some(timeout), data).await
}

// --- State queries ----------------------------------------------------------

/// Whether the `sockindex` chain has been set up with at least one filter
/// (`Curl_conn_is_setup`, `cfilters.c` L583: `conn->cfilter[sockindex] != NULL`).
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_is_setup(conn: &Connection, sockindex: usize) -> bool {
    sock_idx_valid(sockindex) && conn.cfilter[sockindex].is_setup()
}

/// Whether the `sockindex` chain is fully connected (`Curl_conn_is_connected`,
/// `cfilters.c` L591).
///
/// True when the head (top) filter reports connected; for a scheme that uses no
/// network (`PROTOPT_NONETWORK`, e.g. FILE) an empty chain still counts as
/// connected, exactly as curl's `conn->scheme->flags & PROTOPT_NONETWORK`
/// fallback.
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_is_connected(conn: &Connection, sockindex: usize) -> bool {
    if !sock_idx_valid(sockindex) {
        return false;
    }
    match conn.cfilter[sockindex].head_ref() {
        Some(head) => head.is_connected(),
        None => conn.scheme.is_nonetwork(),
    }
}

/// Whether the transport (IP-level) connection is up, even if higher filters
/// (TLS, proxy tunnel) have not finished (`Curl_conn_is_ip_connected`,
/// `cfilters.c` L607).
///
/// Walks the chain top-down: the first connected filter means "yes"; reaching
/// an unconnected [`CF_TYPE_IP_CONNECT`] filter (the transport itself, not yet
/// up) means "no".
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_is_ip_connected(conn: &Connection, sockindex: usize) -> bool {
    if !sock_idx_valid(sockindex) {
        return false;
    }
    let mut cur = conn.cfilter[sockindex].head_ref();
    while let Some(cf) = cur {
        if cf.is_connected() {
            return true;
        }
        if cf.has_flag(CF_TYPE_IP_CONNECT) {
            return false;
        }
        cur = cf.next_ref();
    }
    false
}

/// Whether the `sockindex` chain includes a TLS filter (`Curl_conn_is_ssl`,
/// `cfilters.c` L633: any filter carrying [`CF_TYPE_SSL`]).
///
/// (curl's `cf_is_ssl` stops descending at the IP-connect layer; because TLS is
/// always layered above the transport, "any SSL filter in the chain" is
/// equivalent for every real chain — and is the contract [`FilterChain::is_ssl`]
/// documents.)
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_is_ssl(conn: &Connection, sockindex: usize) -> bool {
    sock_idx_valid(sockindex) && conn.cfilter[sockindex].is_ssl()
}

/// Whether the `sockindex` chain multiplexes streams (`Curl_conn_is_multiplex`,
/// `cfilters.c` L678: a filter carrying [`CF_TYPE_MULTIPLEX`], e.g. HTTP/2/3).
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_is_multiplex(conn: &Connection, sockindex: usize) -> bool {
    sock_idx_valid(sockindex) && conn.cfilter[sockindex].is_multiplex()
}

// --- Info getters -----------------------------------------------------------

/// Whether TLS session info is available for the secured `sockindex` chain
/// (`Curl_conn_get_ssl_info`, `cfilters.c` L645).
///
/// Reports availability only (true when the chain is SSL and answers the
/// [`CfQuery::SslInfo`] query); the opaque, backend-specific session payload is
/// retrieved through the `tls` layer, matching the
/// [`CfQueryResult::SslInfo`](filters::CfQueryResult::SslInfo) contract.
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_get_ssl_info(conn: &Connection, sockindex: usize) -> bool {
    Curl_conn_is_ssl(conn, sockindex)
        && matches!(
            conn.cfilter[sockindex].query(CfQuery::SslInfo),
            Ok(CfQueryResult::SslInfo)
        )
}

/// IP-level info (IPv6 flag + [`IpQuadruple`]) for the `sockindex` chain
/// (`Curl_conn_get_ip_info`, `cfilters.c` L673). `None` when unavailable.
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_get_ip_info(conn: &Connection, sockindex: usize) -> Option<(bool, IpQuadruple)> {
    if !sock_idx_valid(sockindex) {
        return None;
    }
    Curl_conn_cf_get_ip_info(conn.cfilter[sockindex].head_ref())
}

/// The HTTP version in use on the primary chain
/// (`Curl_conn_http_version`, `cfilters.c` L706): `9`/`10`/`11`/`20`/`30`, or
/// `0` when no HTTP filter answers.
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_http_version(conn: &Connection) -> u8 {
    conn.cfilter[FIRSTSOCKET].http_version().unwrap_or(0)
}

/// The transport (`TRNSPRT_*`) the connection uses (`Curl_conn_get_transport`,
/// `cfilters.c` L693), falling back to the connection's `transport_wanted`.
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_get_transport(conn: &Connection) -> u8 {
    Curl_conn_cf_get_transport(conn.cfilter[FIRSTSOCKET].head_ref(), conn.transport_wanted)
}

/// The ALPN protocol negotiated on the primary chain
/// (`Curl_conn_get_alpn_negotiated`, `cfilters.c` L701), or `None`. This is the
/// signal the HTTP engines use to select h1/h2/h3.
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_get_alpn_negotiated(conn: &Connection) -> Option<String> {
    Curl_conn_cf_get_alpn_negotiated(conn.cfilter[FIRSTSOCKET].head_ref())
}

/// The peer (server) certificate chain in DER form for the `sockindex` chain,
/// leaf first (the connection-level wrapper over
/// [`Curl_conn_cf_get_peer_certs`]). Empty when `sockindex` is invalid or no
/// TLS chain was captured. The HTTP engine pulls this post-connect to populate
/// `CURLINFO_CERTINFO` (`%{certs}` / `%{num_certs}`) when `CURLOPT_CERTINFO`
/// is set.
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_get_peer_certs(conn: &Connection, sockindex: usize) -> Vec<Vec<u8>> {
    if !sock_idx_valid(sockindex) {
        return Vec::new();
    }
    Curl_conn_cf_get_peer_certs(conn.cfilter[sockindex].head_ref())
}

/// The host and port the `sockindex` chain currently talks to
/// (`Curl_conn_get_current_host`, `cfilters.c` L821).
///
/// While a tunneling proxy filter (`CF_TYPE_IP_CONNECT | CF_TYPE_PROXY`) is
/// still connecting, authentication and similar concerns apply to that interim
/// proxy host, so its [`CfQuery::HostPort`] answer is returned. Once everything
/// is connected (or the query is unanswered), the connection's overall
/// destination (`remote_host`/`remote_port`) is returned.
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_get_current_host(conn: &Connection, sockindex: usize) -> (String, u16) {
    if sock_idx_valid(sockindex) {
        // Find the lowest not-yet-connected tunneling-proxy filter.
        let mut cf_proxy: Option<&dyn ConnectionFilter> = None;
        let mut cur = conn.cfilter[sockindex].head_ref();
        while let Some(cf) = cur {
            if cf.is_connected() {
                break;
            }
            if cf.has_flag(CF_TYPE_IP_CONNECT) && cf.has_flag(CF_TYPE_PROXY) {
                cf_proxy = Some(cf);
            }
            cur = cf.next_ref();
        }
        if let Some(proxy) = cf_proxy {
            if let Ok(CfQueryResult::HostPort { host, port }) = proxy.query(CfQuery::HostPort) {
                return (host, port);
            }
        }
    }
    (conn.remote_host.clone(), conn.remote_port)
}

/// The maximum number of concurrent transfers the `sockindex` chain supports
/// (`Curl_conn_get_max_concurrent`, `cfilters.c` L1016): `1` for a
/// non-multiplexed connection, more for HTTP/2/3, `0` for an invalid index.
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_get_max_concurrent(conn: &Connection, sockindex: usize) -> usize {
    if !sock_idx_valid(sockindex) {
        return 0;
    }
    conn.cfilter[sockindex].max_concurrent() as usize
}

/// The underlying stream error code for the `sockindex` chain
/// (`Curl_conn_get_stream_error`, `cfilters.c` L1037); `0` when there is none.
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_get_stream_error(conn: &Connection, sockindex: usize) -> i32 {
    if !sock_idx_valid(sockindex) {
        return 0;
    }
    conn.cfilter[sockindex].stream_error()
}

// --- Lifecycle: close / shutdown -------------------------------------------

/// Close the `sockindex` chain immediately (`Curl_conn_close`, `cfilters.c`
/// L144): close the head filter (clearing its connected bit and closing the
/// filters below it) and clear all per-filter shutdown state. Valid to call
/// with no filters present (a no-op then), matching curl.
#[allow(non_snake_case)]
pub fn Curl_conn_close(conn: &mut Connection, sockindex: usize) {
    if !sock_idx_valid(sockindex) {
        return;
    }
    conn.cfilter[sockindex].close();
}

/// Gracefully shut down the `sockindex` chain (`Curl_conn_shutdown`,
/// `cfilters.c` L157), bounded by the connection's `shutdown_timeout_ms`.
///
/// Returns `Ok(true)` when the shutdown handshake is complete for every
/// connected filter (curl's `*done == TRUE`). curl's re-entrant `*done` polling
/// collapses into awaiting each filter's shutdown to completion in order; an
/// invalid index yields [`CurlError::BadFunctionArgument`].
#[allow(non_snake_case)]
pub async fn Curl_conn_shutdown(conn: &mut Connection, sockindex: usize) -> Result<bool> {
    if !sock_idx_valid(sockindex) {
        return Err(CurlError::BadFunctionArgument);
    }
    let timeout = conn.shutdown_timeout_ms;
    let data = &mut conn.filter_data;
    let chain = &mut conn.cfilter[sockindex];
    chain.shutdown(Some(timeout), data).await
}

// --- I/O readiness: data_pending / needs_flush / flush ----------------------

/// Whether the `sockindex` chain has buffered inbound data ready to read
/// (`Curl_conn_data_pending`, `cfilters.c` L731).
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_data_pending(conn: &Connection, sockindex: usize) -> bool {
    sock_idx_valid(sockindex) && conn.cfilter[sockindex].data_pending()
}

/// Whether the `sockindex` chain has unsent buffered outbound data
/// (`Curl_conn_needs_flush`, `cfilters.c` L761).
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_needs_flush(conn: &Connection, sockindex: usize) -> bool {
    sock_idx_valid(sockindex) && conn.cfilter[sockindex].needs_flush()
}

/// Flush buffered outbound data through the `sockindex` chain
/// (`Curl_conn_flush`, `cfilters.c` L966): a `CF_CTRL_FLUSH` control event
/// (first-fail). An invalid index yields [`CurlError::BadFunctionArgument`].
#[allow(non_snake_case)]
pub fn Curl_conn_flush(conn: &mut Connection, sockindex: usize) -> Result<()> {
    if !sock_idx_valid(sockindex) {
        return Err(CurlError::BadFunctionArgument);
    }
    conn.cfilter[sockindex].flush()
}

// --- Socket access ----------------------------------------------------------

/// The primary socket descriptor of the connection
/// (`Curl_conn_get_first_socket`, `cfilters.c` L935), or `-1` (C
/// `CURL_SOCKET_BAD`) when unavailable.
///
/// Returned as a plain `i64` (the safe `AsRawFd` value the socket filter holds);
/// the multi socket-action ABI consumes this fd. The bottom socket filter
/// answers the same descriptor whether or not the upper chain has finished
/// connecting, so no separate `conn->sock[]` cache is needed.
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_get_first_socket(conn: &Connection) -> i64 {
    conn.cfilter[FIRSTSOCKET].get_socket()
}

/// The connected remote socket address for the `sockindex` chain
/// (`Curl_conn_get_remote_addr`, `cfilters.c` L959), or `None`.
///
/// Prefers the live address the socket filter reports; falls back to the
/// connection's cached `remote_addr` (filled at connect time) when the chain no
/// longer answers (e.g. mid-teardown).
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_get_remote_addr(conn: &Connection, sockindex: usize) -> Option<SocketAddr> {
    if !sock_idx_valid(sockindex) {
        return None;
    }
    conn.cfilter[sockindex]
        .get_remote_addr()
        .or_else(|| conn.cached_remote_addr(sockindex))
}

/// Tell the `sockindex` chain's filters to forget about their socket
/// (`Curl_conn_forget_socket`, `cfilters.h` L468): broadcast a
/// [`CF_CTRL_FORGET_SOCKET`] control event (ignored result) so the socket
/// filter releases ownership of the fd without closing it — used when the
/// socket is handed to the application (`CURLOPT_CONNECT_ONLY`) or to the multi
/// event machinery.
#[allow(non_snake_case)]
pub fn Curl_conn_forget_socket(conn: &mut Connection, sockindex: usize) {
    if !sock_idx_valid(sockindex) {
        return;
    }
    // Ignored-result broadcast, mirroring curl's `cf_cntrl` with ignore=TRUE.
    let _ = conn.cfilter[sockindex].cntrl_chain(true, CF_CTRL_FORGET_SOCKET, 0);
}

/// Map a socket descriptor back to its socket index on this connection
/// (`Curl_conn_sockindex`, `cfilters.c` L1075): [`SECONDARYSOCKET`] when `sockfd`
/// is the connection's secondary (data) socket, otherwise [`FIRSTSOCKET`].
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_sockindex(conn: &Connection, sockfd: i64) -> usize {
    if sockfd >= 0 && sockfd == conn.cfilter[SECONDARYSOCKET].get_socket() {
        SECONDARYSOCKET
    } else {
        FIRSTSOCKET
    }
}

// --- Poll integration (multi / FFI ABI surface) -----------------------------
//
// AAP §0.7.4: the C `select`/`poll` machinery is re-conceived on Tokio
// readiness. Within `conn/`, per-filter `adjust_pollset` is deliberately
// omitted — the runtime drives readiness. These functions exist ONLY so the
// `curl_multi_socket_action` / `curl_multi_fdset` ABI consumers can still learn
// a connection's socket fd and the directions it wants polled. They return the
// readiness request as plain [`Pollset`] data (raw fd via `AsRawFd` + r/w
// flags); the actual waiting is performed by `crate::multi` / the FFI bridge.
// No `pollfd`/`fd_set` is fabricated and no `unsafe` is used.

/// Build the [`Pollset`] for one filter chain (`Curl_conn_cf_adjust_pollset`,
/// `cfilters.c` L767, reconceived on Tokio readiness).
///
/// Reports the chain's bottom socket fd plus the directions of interest: while
/// connecting, writability (curl "wants to send after connect"); once
/// connected, readability; plus writability whenever there is buffered data to
/// flush and readability whenever inbound data is already pending. An empty /
/// socket-less chain yields [`Pollset::empty`].
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_cf_adjust_pollset(conn: &Connection, sockindex: usize) -> Pollset {
    if !sock_idx_valid(sockindex) {
        return Pollset::empty();
    }
    let chain = &conn.cfilter[sockindex];
    let socket = chain.get_socket();
    if socket < 0 {
        return Pollset::empty();
    }
    let connected = Curl_conn_is_connected(conn, sockindex);
    Pollset {
        socket,
        want_read: connected || chain.data_pending(),
        want_write: !connected || chain.needs_flush(),
    }
}

/// Build the active [`Pollset`]s across both of the connection's chains
/// (`Curl_conn_adjust_pollset`, `cfilters.c` L789, which loops both socket
/// indices). Only chains with a real socket and at least one direction of
/// interest are returned.
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_adjust_pollset(conn: &Connection) -> Vec<Pollset> {
    let mut sets = Vec::with_capacity(NUM_SOCKETS);
    for sockindex in 0..NUM_SOCKETS {
        let ps = Curl_conn_cf_adjust_pollset(conn, sockindex);
        if ps.is_active() {
            sets.push(ps);
        }
    }
    sets
}

/// The [`Pollset`] a caller should wait on for the `sockindex` chain
/// (`Curl_conn_cf_poll`, `cfilters.c` L803, reconceived on Tokio readiness).
///
/// In curl this builds a pollset and blocks in `Curl_poll` for up to
/// `timeout_ms`. Here the actual waiting is the Tokio runtime's job (driven by
/// `crate::multi` / the FFI bridge), so this returns the readiness request as
/// data; `timeout_ms` is retained for ABI-surface parity and is advisory.
#[allow(non_snake_case)]
#[must_use]
pub fn Curl_conn_cf_poll(conn: &Connection, sockindex: usize, timeout_ms: i64) -> Pollset {
    let _ = timeout_ms; // the wait is Tokio-driven at the multi/FFI layer.
    Curl_conn_cf_adjust_pollset(conn, sockindex)
}

// --- Transfer lifecycle events (broadcast across BOTH chains) ---------------
//
// curl's `cf_cntrl_all` loops over `conn->cfilter[0..2]`; these span both
// chains, so they live here (the single-chain `cntrl` lives in `FilterChain`).

/// Notify all filters on both chains that a transfer is being set up
/// (`Curl_conn_ev_data_setup`, `cfilters.c` L967 → `CF_CTRL_DATA_SETUP`,
/// first-fail).
#[allow(non_snake_case)]
pub fn Curl_conn_ev_data_setup(conn: &mut Connection) -> Result<()> {
    for sockindex in 0..NUM_SOCKETS {
        conn.cfilter[sockindex].ev_data_setup()?;
    }
    Ok(())
}

/// Notify all filters on both chains that the transfer finished sending data
/// (`Curl_conn_ev_data_done_send`, `cfilters.c` L1075 → `CF_CTRL_DATA_DONE_SEND`,
/// ignored result).
#[allow(non_snake_case)]
pub fn Curl_conn_ev_data_done_send(conn: &mut Connection) {
    for sockindex in 0..NUM_SOCKETS {
        conn.cfilter[sockindex].ev_data_done_send();
    }
}

/// Notify all filters on both chains that the transfer is done
/// (`Curl_conn_ev_data_done`, `cfilters.c` L987 → `CF_CTRL_DATA_DONE`, ignored
/// result). `premature` marks an early/aborted finish.
#[allow(non_snake_case)]
pub fn Curl_conn_ev_data_done(conn: &mut Connection, premature: bool) {
    for sockindex in 0..NUM_SOCKETS {
        conn.cfilter[sockindex].ev_data_done(premature);
    }
}

/// Pause or unpause the transfer across both chains (`Curl_conn_ev_data_pause`,
/// `cfilters.c` L992 → `CF_CTRL_DATA_PAUSE`, first-fail).
#[allow(non_snake_case)]
pub fn Curl_conn_ev_data_pause(conn: &mut Connection, do_pause: bool) -> Result<()> {
    for sockindex in 0..NUM_SOCKETS {
        conn.cfilter[sockindex].ev_data_pause(do_pause)?;
    }
    Ok(())
}

// --- Liveness ---------------------------------------------------------------

/// Whether the connection is still usable, plus whether input is pending
/// (`Curl_conn_is_alive`, `cfilters.c` L997).
///
/// Returns `(false, false)` when the connection is marked to close
/// (`bits.close`) — curl's `!cf->conn->bits.close` guard — otherwise asks the
/// primary chain's head filter.
#[allow(non_snake_case)]
pub fn Curl_conn_is_alive(conn: &mut Connection) -> (bool, bool) {
    if conn.is_closed() {
        return (false, false);
    }
    conn.cfilter[FIRSTSOCKET].is_alive()
}

/// Send a keep-alive probe through the `sockindex` chain
/// (`Curl_conn_keep_alive`, `cfilters.c` L1005). An invalid index yields
/// [`CurlError::BadFunctionArgument`]; an empty chain is `Ok(())`.
#[allow(non_snake_case)]
pub fn Curl_conn_keep_alive(conn: &mut Connection, sockindex: usize) -> Result<()> {
    if !sock_idx_valid(sockindex) {
        return Err(CurlError::BadFunctionArgument);
    }
    conn.cfilter[sockindex].keep_alive()
}

// --- Data transfer ----------------------------------------------------------

/// Receive up to `buf.len()` bytes from the `sockindex` chain
/// (`Curl_conn_recv`, `cfilters.c` L1083) — a primary read entry for the
/// transfer engine and protocol handlers. Returns the number of bytes read;
/// `0` means EOF.
///
/// Walks to the first connected filter and awaits its `recv`. An invalid index
/// yields [`CurlError::BadFunctionArgument`]; with no connected filter the chain
/// returns [`CurlError::FailedInit`] (curl's no-recv-path default). The
/// transient [`CurlError::Again`] and the filters' `RecvError`/`SendError`
/// codes propagate unchanged.
#[allow(non_snake_case)]
pub async fn Curl_conn_recv(
    conn: &mut Connection,
    sockindex: usize,
    buf: &mut [u8],
) -> Result<usize> {
    if !sock_idx_valid(sockindex) {
        return Err(CurlError::BadFunctionArgument);
    }
    let data = &mut conn.filter_data;
    let chain = &mut conn.cfilter[sockindex];
    chain.recv(buf, data).await
}

/// Send `buf` through the `sockindex` chain (`Curl_conn_send`, `cfilters.c`
/// L1096), optionally signalling end-of-stream with `eos` — a primary write
/// entry for the transfer engine and protocol handlers. Returns the number of
/// bytes accepted.
///
/// Walks to the first connected filter and awaits its `send`. An invalid index
/// yields [`CurlError::BadFunctionArgument`]; with no connected filter the chain
/// returns [`CurlError::FailedInit`] (curl's no-send-path default). The
/// transient [`CurlError::Again`] propagates unchanged.
#[allow(non_snake_case)]
pub async fn Curl_conn_send(
    conn: &mut Connection,
    sockindex: usize,
    buf: &[u8],
    eos: bool,
) -> Result<usize> {
    if !sock_idx_valid(sockindex) {
        return Err(CurlError::BadFunctionArgument);
    }
    let data = &mut conn.filter_data;
    let chain = &mut conn.cfilter[sockindex];
    chain.send(buf, eos, data).await
}

// ===========================================================================
// Filter-stack assembly glue — the construct-then-drive entry
// (oracle: the `Curl_conn_setup` + `Curl_conn_connect` pairing, connect.c).
//
// Division of responsibility:
//   * `connect.rs`        owns chain CONSTRUCTION order (the canonical bottom-up
//                         EYEBALLS → SOCKS → HTTP-PROXY → HAPROXY → SSL stack,
//                         built by `Curl_conn_setup`).
//   * `https_connect.rs`  owns the HTTPS ALPN-eyeballs variant (a coordinator
//                         filter passed in as `ConnSetup::Https`).
//   * `mod.rs` (here)     owns the connection-level VERBS and this thin glue
//                         that builds-then-drives.
// ===========================================================================

/// Establish a connection on `sockindex`: build its filter chain, then drive it
/// to the connected state.
///
/// This is the high-level entry the protocol/transfer layers call. It is the
/// composition of the two halves of curl's connect path:
///
/// 1. [`connect::Curl_conn_setup`] assembles `conn.cfilter[sockindex]` — either
///    the linear SETUP meta-filter ([`ConnSetup::Default`], which expands into
///    the canonical bottom-up stack) or the pre-built HTTPS ALPN-eyeballs
///    coordinator ([`ConnSetup::Https`]). It is a no-op if the chain is already
///    set up, exactly as curl's `if(!conn->cfilter[sockindex])` guard.
/// 2. [`Curl_conn_connect`] then drives that chain to completion (bounded by
///    `connect_timeout_ms`), broadcasting the post-connect info update.
///
/// `ssl_mode` is the SSL tri-state ([`CURL_CF_SSL_DEFAULT`] /
/// [`CURL_CF_SSL_DISABLE`] / [`CURL_CF_SSL_ENABLE`]) passed through to the SETUP
/// filter; `dispatch` selects the construction variant and carries the protocol
/// layer's filter factories. `blocking` is forwarded to [`Curl_conn_connect`]
/// (advisory in the async model — see its docs).
///
/// An invalid `sockindex` yields [`CurlError::BadFunctionArgument`]; setup or
/// connect failures propagate unchanged.
#[allow(non_snake_case)]
pub async fn establish_connection(
    conn: &mut Connection,
    sockindex: usize,
    ssl_mode: i32,
    dispatch: ConnSetup,
    blocking: bool,
) -> Result<()> {
    if !sock_idx_valid(sockindex) {
        return Err(CurlError::BadFunctionArgument);
    }
    // 1. Build the chain (connect.rs / https_connect.rs own construction order).
    connect::Curl_conn_setup(&mut conn.cfilter[sockindex], ssl_mode, dispatch)?;
    // 2. Drive the assembled chain to the connected state.
    Curl_conn_connect(conn, sockindex, blocking).await
}

// ===========================================================================
// Pool / shutdown integration — `Connection` as a poolable, shutdownable conn.
//
// Implementing [`shutdown::ConnShutdown`] and [`cache::PoolConn`] lets a
// `Connection` live directly in the [`cache::ConnectionPool`] and be handed to
// the graceful-shutdown registry, with no `crate::protocols` dependency: the
// protocol-specific disconnect runs through the injected `disconnect_hook`
// (taken by [`ConnShutdown::take_disconnect_hook`]).
//
// These impls live in `mod.rs` (with the struct) so they may read the
// connection's private bookkeeping fields (`lastused`, `attached_xfers`,
// `disconnect_hook`).
// ===========================================================================

impl ConnShutdown for Connection {
    fn connection_id(&self) -> i64 {
        self.connection_id
    }

    fn destination(&self) -> &str {
        &self.destination
    }

    fn connect_only(&self) -> bool {
        self.connect_only
    }

    fn is_aborted(&self) -> bool {
        self.bits.aborted
    }

    fn is_connected(&self, socket: SocketIndex) -> bool {
        // Reuse the connection-level verb (handles the PROTOPT_NONETWORK case).
        Curl_conn_is_connected(self, socket.index())
    }

    fn take_disconnect_hook(&mut self) -> Option<DisconnectHook> {
        // One-shot: leave `None` behind, mirroring the C `disconnect` handler.
        self.disconnect_hook.take()
    }

    fn shutdown_socket<'a>(&'a mut self, socket: SocketIndex) -> BoxFuture<'a, Result<bool>> {
        // Delegate to the connection-level shutdown verb, which bounds itself
        // with `shutdown_timeout_ms` (faithful to C's `Curl_conn_shutdown`
        // reading `conn->shutdown.timeout_ms`). Boxed because the trait method
        // is object-safe (returns a `BoxFuture`, not an `async fn`).
        Box::pin(async move { Curl_conn_shutdown(self, socket.index()).await })
    }

    fn close_socket(&mut self, socket: SocketIndex) {
        // Idempotent: closing an already-closed / never-connected slot is a
        // no-op inside `Curl_conn_close`.
        Curl_conn_close(self, socket.index());
    }
}

impl PoolConn for Connection {
    fn set_connection_id(&mut self, id: i64) {
        self.connection_id = id;
    }

    fn lastused(&self) -> CurlTime {
        self.lastused
    }

    fn set_lastused(&mut self, when: CurlTime) {
        self.lastused = when;
    }

    fn is_in_use(&self) -> bool {
        // C `CONN_INUSE(conn)`: `conn->attached_xfers > 0`.
        self.attached_xfers > 0
    }

    fn marked_close(&self) -> bool {
        // C `conn->bits.close`.
        self.is_closed()
    }

    fn no_reuse(&self) -> bool {
        self.bits.no_reuse
    }

    fn set_no_reuse(&mut self, value: bool) {
        self.bits.no_reuse = value;
    }

    fn set_aborted(&mut self, value: bool) {
        self.bits.aborted = value;
    }

    fn seems_dead(&self) -> bool {
        // C `Curl_conn_seems_dead` (url.c L655): never reap an in-use
        // connection (the `CONN_INUSE` guard).
        if self.attached_xfers > 0 {
            return false;
        }
        // Otherwise report the observable "looks dead" signals: a marked-close
        // or non-reusable connection, or — matching curl's `input_pending`
        // rule — an idle connection with readable data (a TLS close-notify or
        // other unexpected bytes is "not a clean state for reuse"). curl's full
        // liveness probe (`Curl_conn_is_alive`) needs `&mut` and is performed by
        // the pool's pruning path through [`Curl_conn_is_alive`]; this `&self`
        // predicate reports what can be observed without mutation.
        self.is_closed() || self.bits.no_reuse || self.cfilter[FIRSTSOCKET].data_pending()
    }

    fn upkeep(&mut self) {
        // C `Curl_conn_upkeep` default branch: a generic keep-alive on the
        // primary chain. Best-effort — the pool ignores the resulting `CURLcode`.
        let _ = Curl_conn_keep_alive(self, FIRSTSOCKET);
    }

    fn into_shutdown(self: Box<Self>) -> Box<dyn ConnShutdown> {
        // Unsizing coercion `Box<Connection> -> Box<dyn ConnShutdown>` (Connection
        // implements ConnShutdown); not a `dyn`-to-`dyn` up-cast, so it builds at
        // the project MSRV.
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        // Unsizing coercion `Box<Connection> -> Box<dyn Any>`; lets
        // [`pool_checkout`] recover the concrete `Connection` for by-value reuse.
        self
    }
}

/// Check out a reusable idle [`Connection`] for `key` from the shared pool,
/// returning it **by value** for a fresh transfer, or `None` if the pool holds
/// no eligible connection.
///
/// This is the production driver of connection reuse (the QA F11-PERF Issue 3
/// fix). It runs [`cache::ConnectionPool::checkout`] under the pool lock and
/// downcasts the type-erased `Box<dyn PoolConn>` back to the concrete
/// `Connection` via [`cache::PoolConn::into_any`]. `key` is the connection's
/// `destination` (the scheme-aware reuse key the HTTP connect path stores). The
/// `|_| true` matcher accepts any connection in the keyed bundle: the key
/// already encodes scheme + dial target + remote target, and per-request
/// headers/credentials never bind to a kept-alive HTTP/1.x socket, so any
/// connection under the same key is reuse-eligible. The caller is responsible
/// for the final liveness probe ([`Curl_conn_is_alive`]) before driving I/O.
pub fn pool_checkout(pool: &cache::SharedPool, key: &str) -> Option<Connection> {
    let boxed = cache::do_locked(pool, |p| p.checkout(key, |_| true))?;
    boxed
        .into_any()
        .downcast::<Connection>()
        .ok()
        .map(|b| *b)
}

/// Return a keep-alive-eligible [`Connection`] to the shared pool after a
/// transfer completes, so a subsequent transfer to the same destination reuses
/// it (the QA F11-PERF Issue 3 fix, check-in half).
///
/// Runs [`cache::ConnectionPool::checkin`] under the pool lock with the handle's
/// `CURLOPT_MAXCONNECTS` cap, then drains and drops any connections the idle
/// ceiling evicted: dropping a [`cache::DiscardedConn`] runs the connection's
/// `Drop`, closing its socket promptly (the synchronous easy/CLI reuse path has
/// no asynchronous shutdown registry to hand them to).
pub fn pool_checkin(pool: &cache::SharedPool, conn: Connection, maxconnects: u32) {
    let now = timeval::curlx_now();
    cache::do_locked(pool, |p| {
        p.checkin(Box::new(conn), maxconnects, now);
        // Drop evicted connections (close their sockets) — see doc above.
        let _evicted = p.take_discards();
    });
}

/// Drain **all** connections from the shared pool, returning them **by value**
/// for a graceful synchronous teardown (the easy/CLI end-of-run path where a
/// protocol goodbye such as FTP `QUIT` must be sent before the sockets close).
///
/// Each connection is recovered as a concrete [`Connection`] (downcast via
/// [`cache::PoolConn::into_any`], the same mechanism [`pool_checkout`] uses) and
/// the pool is left empty. The caller is responsible for running each
/// connection's protocol goodbye and/or dropping it to force-close its sockets
/// (the analog of curl tearing down its connection cache in
/// `Curl_cpool_destroy`). A connection whose type is not [`Connection`] (none
/// exist in production; only test doubles) is silently discarded.
#[must_use]
pub fn pool_take_all(pool: &cache::SharedPool) -> Vec<Connection> {
    cache::do_locked(pool, cache::ConnectionPool::take_all)
        .into_iter()
        .filter_map(|b| b.into_any().downcast::<Connection>().ok().map(|x| *x))
        .collect()
}
