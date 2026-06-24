//! Connection-filter trait and chain machinery — the tower-like core of the
//! `conn/` module tree.
//!
//! This is the Rust rewrite of libcurl's `lib/cfilters.c` / `lib/cfilters.h`.
//! It is the **foundation** every other file in `conn/` builds on: it defines
//! the asynchronous [`ConnectionFilter`] trait (the safe replacement for the C
//! `Curl_cftype` function-pointer vtable) and the filter-chain machinery — add
//! / insert / discard filters, and drive connect / close / shutdown / send /
//! recv / cntrl / query through the chain. All of the concrete filters
//! (`socket`, `happy_eyeballs`, `h1_proxy`, `h2_proxy`, `haproxy`,
//! `https_connect`, and the SOCKS / TLS wrappers) implement
//! [`ConnectionFilter`].
//!
//! # Chain model
//!
//! A connection has one filter chain per socket index. The chain is a stack of
//! owned filters, head-first: a new filter is pushed onto the **top** (head)
//! and the previous head becomes the new filter's `next`. The head is the
//! "outermost" filter (e.g. TLS) and the tail the "innermost" (e.g. the raw
//! socket). The assembly order that `connect.rs`'s SETUP logic builds, from the
//! socket up, is:
//!
//! ```text
//! happy_eyeballs(socket) -> socks -> http_proxy(tls_proxy + h1/h2 tunnel) -> haproxy -> tls
//! ```
//!
//! so after assembly the chain, walked head-to-tail, is
//! `tls -> haproxy -> http_proxy -> socks -> happy_eyeballs(socket)`.
//!
//! Ownership is expressed by each filter owning its `next` inside [`CfState`]
//! (`Option<Box<dyn ConnectionFilter>>`). This mirrors the C `cf->next`
//! ownership exactly while giving **`Drop`-based teardown for free**: dropping
//! the head drops the whole chain, and each filter's `Drop` impl replaces the
//! C `destroy` callback. There are **no raw pointers and no `unsafe`** — the C
//! `cf->next` / `cf->ctx` / `Box::from_raw`-style chain becomes a safe owned
//! stack of `Box<dyn ConnectionFilter>` (AAP §0.7.1; this file compiles under
//! the crate-wide `#![forbid(unsafe_code)]` declared in `lib.rs`).
//!
//! # The async collapse (the central C -> Rust transformation)
//!
//! curl's `Curl_conn_connect` (cfilters.c L491-592) drives a filter's
//! `do_connect` in a loop, calling `Curl_poll` on the connection sockets and
//! re-invoking `do_connect` until it sets its `*done` out-parameter to `TRUE`.
//! Under Tokio that entire blocking/non-blocking poll loop **collapses to a
//! single `async fn connect(...).await`**: the future resolves exactly when the
//! C code would have set `*done = TRUE`, and the Tokio reactor provides the
//! socket readiness that `Curl_poll` / `easy_pollset` provided in C. The same
//! collapse applies to `do_shutdown`'s `*done` polling.
//!
//! Consequently this module does **not** reproduce any of the
//! `Curl_poll` / `pollfd` / `easy_pollset` / `adjust_pollset` machinery — it has
//! no analog in an async runtime. The C `adjust_pollset` vtable slot is
//! intentionally dropped (its C default was a NOP anyway, cfilters.c L55-64).
//!
//! # Boundary with `mod.rs`
//!
//! This file owns the **trait + chain mechanics** only. The public
//! `Curl_conn_*` connection surface — `is_setup`, `is_connected`, `is_ssl`,
//! `get_ssl_info`, `http_version`, `get_transport`, `get_alpn_negotiated`,
//! `get_first_socket`, `get_remote_addr`, and the cross-socket-index event
//! broadcasts (`data_setup`, `data_done`, …) — is exposed by `mod.rs`'s
//! `Connection` type, which OWNS the per-socket-index [`FilterChain`]s and
//! delegates to the machinery here. A [`FilterChain`] models exactly **one**
//! socket index; `Connection` composes one chain per index.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use crate::error::{CurlError, Result};
use crate::util::bufq::BufQ;
use crate::util::sendf;
use crate::util::timediff::{duration_to_ms, ms_to_duration};
use crate::util::timeval::{self, CurlTime};

// =============================================================================
// Async return type
// =============================================================================

/// Boxed, `Send` future returned by the asynchronous [`ConnectionFilter`]
/// methods.
///
/// The workspace does not depend on the `async-trait` crate, so object-safe
/// async trait methods are hand-rolled: each async method returns a
/// `Pin<Box<dyn Future<Output = T> + Send + 'a>>` instead of being written as
/// `async fn`. The `+ Send` bound lets filters move across Tokio tasks (the
/// `Multi` handle runs on a multi-thread runtime, AAP §0.4.4), and boxing keeps
/// `dyn ConnectionFilter` object-safe and the recursion through `next` finite
/// in size.
///
/// Implementors construct one with `Box::pin(async move { … })`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// =============================================================================
// Filter type flags — `CF_TYPE_*` (cfilters.h L203-207)
// =============================================================================
//
// A filter type carries zero or more of these flags, used to reason about the
// state/capabilities of a chain (e.g. "is this connection using TLS?", "does it
// multiplex?"). The integer values are part of the observable contract that
// `connect.rs` / `mod.rs` and the protocol modules depend on, so they match
// `cfilters.h` bit-for-bit. They are combined with bit-or and tested with
// bit-and against the value returned by [`ConnectionFilter::flags`].

/// Filter provides an IP connection or its equivalent — a CONNECT tunnel, a
/// UNIX-domain socket, a QUIC connection, etc. (`CF_TYPE_IP_CONNECT`).
pub const CF_TYPE_IP_CONNECT: u32 = 1 << 0;
/// Filter provides SSL/TLS (`CF_TYPE_SSL`).
pub const CF_TYPE_SSL: u32 = 1 << 1;
/// Filter multiplexes several easy handles over one connection
/// (`CF_TYPE_MULTIPLEX`).
pub const CF_TYPE_MULTIPLEX: u32 = 1 << 2;
/// Filter provides proxying (`CF_TYPE_PROXY`).
pub const CF_TYPE_PROXY: u32 = 1 << 3;
/// Filter implements a version of the HTTP protocol (`CF_TYPE_HTTP`).
pub const CF_TYPE_HTTP: u32 = 1 << 4;

// =============================================================================
// Control events — `CF_CTRL_*` (cfilters.h L115-126)
// =============================================================================
//
// Events distributed across a chain via [`FilterChain::cntrl_chain`]. Filter
// callbacks are invoked top-down. Return-code handling per event is either
// "first fail" (the first filter returning an error aborts distribution and
// determines the result) or "ignored" (every filter is visited and the overall
// result is always OK) — see the `ignore_result` flag threaded through the
// cntrl machinery. The C `arg2` (`void *`) is `NULL` for every event in curl
// 8.x (see the table in cfilters.h), so it is omitted from the Rust signature;
// only the integer `arg1` is carried.

/// Notify filters to set up data for a transfer (`CF_CTRL_DATA_SETUP`,
/// arg1 = 0, "first fail").
pub const CF_CTRL_DATA_SETUP: i32 = 4;
/// Pause/unpause the transfer (`CF_CTRL_DATA_PAUSE`, arg1 = on/off,
/// "first fail"). (Event 5 is unused in curl 8.x.)
pub const CF_CTRL_DATA_PAUSE: i32 = 6;
/// The transfer is finished, possibly prematurely (`CF_CTRL_DATA_DONE`,
/// arg1 = premature, "ignored").
pub const CF_CTRL_DATA_DONE: i32 = 7;
/// The transfer is done sending data (`CF_CTRL_DATA_DONE_SEND`, arg1 = 0,
/// "ignored").
pub const CF_CTRL_DATA_DONE_SEND: i32 = 8;
/// Persist connection info after connect (`CF_CTRL_CONN_INFO_UPDATE`,
/// `256 + 0`, arg1 = 0, "ignored").
pub const CF_CTRL_CONN_INFO_UPDATE: i32 = 256;
/// Tell filters to forget about their socket (`CF_CTRL_FORGET_SOCKET`,
/// `256 + 1`, arg1 = 0, "ignored").
pub const CF_CTRL_FORGET_SOCKET: i32 = 257;
/// Flush any buffered outbound data (`CF_CTRL_FLUSH`, `256 + 2`, arg1 = 0,
/// "first fail").
pub const CF_CTRL_FLUSH: i32 = 258;

// =============================================================================
// SSL-mode markers — `CURL_CF_SSL_*` (cfilters.h L347-349)
// =============================================================================

/// Use the connection's default decision about TLS (`CURL_CF_SSL_DEFAULT`).
pub const CURL_CF_SSL_DEFAULT: i32 = -1;
/// Force TLS off for this filter insertion (`CURL_CF_SSL_DISABLE`).
pub const CURL_CF_SSL_DISABLE: i32 = 0;
/// Force TLS on for this filter insertion (`CURL_CF_SSL_ENABLE`).
pub const CURL_CF_SSL_ENABLE: i32 = 1;

// =============================================================================
// Query codes — `CF_QUERY_*` (cfilters.h L162-177)
// =============================================================================
//
// Both a strongly-typed [`CfQuery`] enum (preferred at call sites within the
// workspace) and the raw `CF_QUERY_*` integer constants (for parity and for
// code that passes the raw `int`) are provided. The discriminants match
// `cfilters.h` exactly because the protocol modules pass these values.

/// Maximum number of parallel transfers the chain expects to handle.
pub const CF_QUERY_MAX_CONCURRENT: i32 = 1;
/// Milliseconds until the first server response was seen on connect.
pub const CF_QUERY_CONNECT_REPLY_MS: i32 = 2;
/// The socket used by the chain.
pub const CF_QUERY_SOCKET: i32 = 3;
/// The `TIMER_CONNECT` timestamp.
pub const CF_QUERY_TIMER_CONNECT: i32 = 4;
/// The `TIMER_APPCONNECT` timestamp.
pub const CF_QUERY_TIMER_APPCONNECT: i32 = 5;
/// The underlying stream error code.
pub const CF_QUERY_STREAM_ERROR: i32 = 6;
/// Whether any filter has unsent data.
pub const CF_QUERY_NEED_FLUSH: i32 = 7;
/// IP-level info (IPv6 flag + the ip quadruple).
pub const CF_QUERY_IP_INFO: i32 = 8;
/// The HTTP version in use (`9`/`10`/`11`/`20`/`30`).
pub const CF_QUERY_HTTP_VERSION: i32 = 9;
/// The connected remote socket address.
pub const CF_QUERY_REMOTE_ADDR: i32 = 10;
/// The remote hostname and port the filter talks to.
pub const CF_QUERY_HOST_PORT: i32 = 11;
/// TLS session info for the secured connection.
pub const CF_QUERY_SSL_INFO: i32 = 12;
/// TLS context info for the secured connection.
pub const CF_QUERY_SSL_CTX_INFO: i32 = 13;
/// The transport (`TRNSPRT_*`) the connection uses.
pub const CF_QUERY_TRANSPORT: i32 = 14;
/// The ALPN protocol the server selected, if any.
pub const CF_QUERY_ALPN_NEGOTIATED: i32 = 15;
/// The peer (server) certificate chain in DER form, leaf first.
///
/// Not a `CF_QUERY_*` code in the C oracle (curl's TLS backends push certinfo
/// directly into `data->info` during the handshake via
/// `Curl_ssl_push_certinfo_len`). The memory-safe core instead retains the DER
/// chain on the `rustls` filter and exposes it through this internal query,
/// which the HTTP engine pulls post-connect to populate `CURLINFO_CERTINFO`
/// (`%{certs}` / `%{num_certs}`). Internal-only: it is not an exported
/// `curl_*` symbol and so does not affect the libcurl ABI surface.
pub const CF_QUERY_PEER_CERTS: i32 = 16;

/// Strongly-typed connection-filter query selector (the Rust face of the
/// `CF_QUERY_*` integers).
///
/// A query is asked of a chain via [`ConnectionFilter::query`]; a filter that
/// does not understand a query passes it down to `next` (and the chain bottom
/// answers [`CurlError::UnknownOption`], matching `Curl_cf_def_query`). The
/// `#[repr(i32)]` discriminants are identical to the `CF_QUERY_*` constants so
/// the enum and the raw integers are interchangeable across the FFI/protocol
/// boundary.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CfQuery {
    /// `CF_QUERY_MAX_CONCURRENT`.
    MaxConcurrent = CF_QUERY_MAX_CONCURRENT,
    /// `CF_QUERY_CONNECT_REPLY_MS`.
    ConnectReplyMs = CF_QUERY_CONNECT_REPLY_MS,
    /// `CF_QUERY_SOCKET`.
    Socket = CF_QUERY_SOCKET,
    /// `CF_QUERY_TIMER_CONNECT`.
    TimerConnect = CF_QUERY_TIMER_CONNECT,
    /// `CF_QUERY_TIMER_APPCONNECT`.
    TimerAppConnect = CF_QUERY_TIMER_APPCONNECT,
    /// `CF_QUERY_STREAM_ERROR`.
    StreamError = CF_QUERY_STREAM_ERROR,
    /// `CF_QUERY_NEED_FLUSH`.
    NeedFlush = CF_QUERY_NEED_FLUSH,
    /// `CF_QUERY_IP_INFO`.
    IpInfo = CF_QUERY_IP_INFO,
    /// `CF_QUERY_HTTP_VERSION`.
    HttpVersion = CF_QUERY_HTTP_VERSION,
    /// `CF_QUERY_REMOTE_ADDR`.
    RemoteAddr = CF_QUERY_REMOTE_ADDR,
    /// `CF_QUERY_HOST_PORT`.
    HostPort = CF_QUERY_HOST_PORT,
    /// `CF_QUERY_SSL_INFO`.
    SslInfo = CF_QUERY_SSL_INFO,
    /// `CF_QUERY_SSL_CTX_INFO`.
    SslCtxInfo = CF_QUERY_SSL_CTX_INFO,
    /// `CF_QUERY_TRANSPORT`.
    Transport = CF_QUERY_TRANSPORT,
    /// `CF_QUERY_ALPN_NEGOTIATED`.
    AlpnNegotiated = CF_QUERY_ALPN_NEGOTIATED,
    /// `CF_QUERY_PEER_CERTS`.
    PeerCerts = CF_QUERY_PEER_CERTS,
}

impl CfQuery {
    /// The raw `CF_QUERY_*` integer for this query.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Map a raw `CF_QUERY_*` integer back to a [`CfQuery`], or `None` if it is
    /// not a known query code.
    #[must_use]
    pub const fn from_i32(value: i32) -> Option<Self> {
        match value {
            CF_QUERY_MAX_CONCURRENT => Some(Self::MaxConcurrent),
            CF_QUERY_CONNECT_REPLY_MS => Some(Self::ConnectReplyMs),
            CF_QUERY_SOCKET => Some(Self::Socket),
            CF_QUERY_TIMER_CONNECT => Some(Self::TimerConnect),
            CF_QUERY_TIMER_APPCONNECT => Some(Self::TimerAppConnect),
            CF_QUERY_STREAM_ERROR => Some(Self::StreamError),
            CF_QUERY_NEED_FLUSH => Some(Self::NeedFlush),
            CF_QUERY_IP_INFO => Some(Self::IpInfo),
            CF_QUERY_HTTP_VERSION => Some(Self::HttpVersion),
            CF_QUERY_REMOTE_ADDR => Some(Self::RemoteAddr),
            CF_QUERY_HOST_PORT => Some(Self::HostPort),
            CF_QUERY_SSL_INFO => Some(Self::SslInfo),
            CF_QUERY_SSL_CTX_INFO => Some(Self::SslCtxInfo),
            CF_QUERY_TRANSPORT => Some(Self::Transport),
            CF_QUERY_ALPN_NEGOTIATED => Some(Self::AlpnNegotiated),
            CF_QUERY_PEER_CERTS => Some(Self::PeerCerts),
            _ => None,
        }
    }
}

/// The local/remote address pair of an established connection — the Rust mirror
/// of C's `struct ip_quadruple` (urldata.h).
///
/// The transport (socket) filter fills one of these when answering a
/// [`CfQuery::IpInfo`] query, so that filters layered above it (notably the
/// HAProxy PROTOCOL header emitter, `crate::conn::haproxy`) can read the
/// connection's endpoints without performing any OS call themselves. The C
/// layout is `{ char remote_ip[]; char local_ip[]; uint16_t remote_port;
/// uint16_t local_port; uint8_t transport; }`; the textual IPs are kept as
/// owned [`String`]s (already rendered in presentation form, e.g. `"127.0.0.1"`
/// or `"::1"`) and the ports as [`u16`], matching how curl stores and prints
/// them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IpQuadruple {
    /// Presentation-form remote (peer) IP address (C: `ip_quadruple.remote_ip`).
    pub remote_ip: String,
    /// Presentation-form local IP address (C: `ip_quadruple.local_ip`).
    pub local_ip: String,
    /// Remote (peer) port (C: `ip_quadruple.remote_port`).
    pub remote_port: u16,
    /// Local port (C: `ip_quadruple.local_port`).
    pub local_port: u16,
    /// Transport identifier (`TRNSPRT_*`); C: `ip_quadruple.transport`.
    pub transport: u8,
}

/// Heterogeneous result of a [`ConnectionFilter::query`] call.
///
/// In C a query returns its answer through two out-parameters — `int *pres1`
/// and `void *pres2` — whose meaning depends on the query code. That untyped
/// pair is modelled here as one tagged enum: a filter answers a [`CfQuery`]
/// with the matching variant. Callers match on the variant corresponding to
/// the query they issued (the [`FilterChain`] query helpers below do exactly
/// that).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfQueryResult {
    /// Max parallel transfers (`CF_QUERY_MAX_CONCURRENT`).
    MaxConcurrent(u32),
    /// Milliseconds to first server reply (`CF_QUERY_CONNECT_REPLY_MS`).
    ConnectReplyMs(i64),
    /// The chain's socket (`CF_QUERY_SOCKET`); `-1` means "no socket".
    Socket(i64),
    /// The `TIMER_CONNECT` timestamp (`CF_QUERY_TIMER_CONNECT`).
    TimerConnect(CurlTime),
    /// The `TIMER_APPCONNECT` timestamp (`CF_QUERY_TIMER_APPCONNECT`).
    TimerAppConnect(CurlTime),
    /// Underlying stream error code (`CF_QUERY_STREAM_ERROR`).
    StreamError(i32),
    /// Whether the filter has unsent data (`CF_QUERY_NEED_FLUSH`).
    NeedFlush(bool),
    /// IP-level info (`CF_QUERY_IP_INFO`): the connection's address family flag
    /// together with its local/remote endpoint quadruple.
    ///
    /// C's `Curl_conn_cf_get_ip_info` answers this query through two
    /// out-parameters — `bool *is_ipv6` and `struct ip_quadruple *ipquad` — so
    /// the typed result carries both: the address-family flag and the
    /// [`IpQuadruple`]. The HAProxy filter (`crate::conn::haproxy`) consumes
    /// both to build its PROXY protocol header line.
    IpInfo {
        /// `true` if the established connection is IPv6.
        is_ipv6: bool,
        /// The local/remote address pair of the established connection.
        quadruple: IpQuadruple,
    },
    /// HTTP version in use (`CF_QUERY_HTTP_VERSION`): `9`/`10`/`11`/`20`/`30`.
    HttpVersion(u8),
    /// The connected remote address (`CF_QUERY_REMOTE_ADDR`).
    RemoteAddr(Option<SocketAddr>),
    /// The remote host and port (`CF_QUERY_HOST_PORT`).
    HostPort {
        /// The hostname the filter currently talks to.
        host: String,
        /// The port the filter currently talks to.
        port: u16,
    },
    /// TLS session info is available (`CF_QUERY_SSL_INFO`). The opaque,
    /// backend-specific session payload is retrieved through the `tls` layer;
    /// this marker only reports availability across the generic query channel.
    SslInfo,
    /// TLS context info is available (`CF_QUERY_SSL_CTX_INFO`). See
    /// [`CfQueryResult::SslInfo`].
    SslCtxInfo,
    /// The transport (`TRNSPRT_*`) the connection uses (`CF_QUERY_TRANSPORT`).
    Transport(u8),
    /// The ALPN protocol the server selected, or `None`
    /// (`CF_QUERY_ALPN_NEGOTIATED`).
    AlpnNegotiated(Option<Vec<u8>>),
    /// The peer certificate chain in DER form, leaf first; empty when the
    /// connection is not TLS or no chain was captured (`CF_QUERY_PEER_CERTS`).
    /// Backs `CURLINFO_CERTINFO` (`%{certs}` / `%{num_certs}`).
    PeerCerts(Vec<Vec<u8>>),
}

// =============================================================================
// Per-filter chain link + lifecycle state — the C `Curl_cfilter` instance
// =============================================================================

/// The chain-link and lifecycle state every [`ConnectionFilter`] embeds.
///
/// This is the safe equivalent of the per-instance fields of the C
/// `struct Curl_cfilter` (cfilters.h): the `cf->next` chain pointer and the
/// `BIT(connected)` / `BIT(shutdown)` status bits. By embedding it (rather than
/// inheriting), each concrete filter holds exactly one `CfState`, owns its
/// successor through `next`, and the whole chain tears down via `Drop` when the
/// head is dropped — replacing the C `destroy` callback and `Curl_free` with no
/// raw pointers.
///
/// A filter exposes its state through the required
/// [`ConnectionFilter::cf_state`] / [`ConnectionFilter::cf_state_mut`] accessors
/// so the default trait methods and the [`FilterChain`] machinery can walk and
/// mutate the chain generically.
#[derive(Default)]
pub struct CfState {
    /// The next (lower) filter in the chain, owned by this filter. `None` marks
    /// the bottom of the chain.
    pub next: Option<Box<dyn ConnectionFilter>>,
    /// Whether this filter has completed its connect (`BIT(connected)`).
    pub connected: bool,
    /// Whether this filter has completed its shutdown (`BIT(shutdown)`).
    pub shutdown: bool,
}

impl CfState {
    /// A fresh, unconnected, bottom-of-chain state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next: None,
            connected: false,
            shutdown: false,
        }
    }

    /// A fresh state whose `next` is the given lower filter.
    #[must_use]
    pub fn with_next(next: Box<dyn ConnectionFilter>) -> Self {
        Self {
            next: Some(next),
            connected: false,
            shutdown: false,
        }
    }
}

impl std::fmt::Debug for CfState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `dyn ConnectionFilter` is not `Debug`; summarise the link by the
        // successor filter's name instead of attempting to format it.
        f.debug_struct("CfState")
            .field("next", &self.next.as_ref().map(|cf| cf.name()))
            .field("connected", &self.connected)
            .field("shutdown", &self.shutdown)
            .finish()
    }
}

// =============================================================================
// Diagnostics / timing context threaded through the chain drive
// =============================================================================

/// The slice of easy-handle state the connection-filter layer needs.
///
/// In C every cfilter callback receives `struct Curl_easy *data`, used almost
/// exclusively for diagnostics (`infof` / `failf` / `CURL_TRC_CF`) and for
/// reading timeout deadlines. Because `crate::util::sendf`'s `infof` / `failf`
/// are decoupled from the easy handle (they take the verbose flag and the error
/// buffer directly), the filter layer only needs this small context object.
/// `mod.rs`'s `Connection` constructs one from the owning easy handle and
/// threads it through the [`FilterChain`] drive methods.
#[derive(Debug, Default)]
pub struct FilterData {
    /// Mirrors `data->set.verbose`: gate for `infof` trace output.
    pub verbose: bool,
    /// Mirrors `data->set.errorbuffer` (as owned storage): the most recent
    /// `failf` message, surfaced to the caller as the connection error string.
    pub error_buffer: Option<String>,
}

impl FilterData {
    /// A non-verbose context with no captured error.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A context with the given verbosity.
    #[must_use]
    pub fn with_verbose(verbose: bool) -> Self {
        Self {
            verbose,
            error_buffer: None,
        }
    }

    /// Emit a verbose info trace (routes through [`sendf::infof`]).
    fn infof(&self, message: &str) {
        sendf::infof(self.verbose, message);
    }

    /// Record a fatal diagnostic (routes through [`sendf::failf`], which both
    /// stores into `error_buffer` and logs).
    fn failf(&mut self, message: &str) {
        sendf::failf(&mut self.error_buffer, message);
    }
}

// =============================================================================
// PHASE 1 — the `ConnectionFilter` async trait (`Curl_cftype` vtable)
// =============================================================================

/// An asynchronous connection filter — the Rust replacement for the C
/// `struct Curl_cftype` function-pointer vtable.
///
/// Each protocol/transport concern (raw socket, Happy Eyeballs, SOCKS, HTTP
/// CONNECT tunnels, HAProxy header, TLS) is one implementor. Filters are
/// stacked into a [`FilterChain`]; a filter forwards work it does not handle to
/// its `next` (lower) filter. The default method bodies below reproduce curl's
/// `Curl_cf_def_*` pass-through behavior **including its exact, sometimes
/// counter-intuitive, return codes** (see each method).
///
/// # Required methods
///
/// An implementor must provide only [`name`](Self::name),
/// [`cf_state`](Self::cf_state) and [`cf_state_mut`](Self::cf_state_mut); every
/// other method has a pass-through default. Concrete filters override the
/// methods that carry their behavior (e.g. the TLS filter overrides
/// [`connect`](Self::connect) / [`send`](Self::send) / [`recv`](Self::recv) and
/// sets [`CF_TYPE_SSL`] in [`flags`](Self::flags)).
///
/// # Object safety and `Send`
///
/// The trait has [`Send`] as a supertrait so `Box<dyn ConnectionFilter>` is
/// `Send` and filters can move across Tokio tasks. The async methods return
/// [`BoxFuture`] (hand-rolled boxed futures, since the workspace does not use
/// `async-trait`), which keeps the trait object-safe.
///
/// # The async collapse
///
/// [`connect`](Self::connect) and [`shutdown`](Self::shutdown) are `async`: the
/// C `*done` out-parameter plus the `Curl_poll` loop in `Curl_conn_connect` is
/// subsumed by awaiting the future to completion (see the module docs). The C
/// `adjust_pollset` slot has no analog and is intentionally omitted.
pub trait ConnectionFilter: Send {
    /// The filter type's human-readable name (the C `cft->name`), used in
    /// traces.
    fn name(&self) -> &'static str;

    /// Borrow this filter's chain-link / lifecycle state.
    fn cf_state(&self) -> &CfState;

    /// Mutably borrow this filter's chain-link / lifecycle state.
    fn cf_state_mut(&mut self) -> &mut CfState;

    /// The filter type's `CF_TYPE_*` flag bitset (the C `cft->flags`). The
    /// default is `0` (no flags).
    fn flags(&self) -> u32 {
        0
    }

    /// Establish this filter (and, by delegation, the filters below it).
    ///
    /// The default drives the sub-chain to connection and then marks this
    /// (pass-through) filter connected. C has no `Curl_cf_def_connect` — every
    /// `cft` defines `do_connect` — so this default is a Rust convenience that
    /// captures the common pass-through case; behavioral filters override it and
    /// set `cf_state_mut().connected` themselves when fully connected.
    ///
    /// Returns once connected (the C `*done == TRUE`); a transient condition
    /// surfaces as [`CurlError::Again`].
    fn connect<'a>(&'a mut self, data: &'a mut FilterData) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if let Some(next) = self.cf_state_mut().next.as_mut() {
                next.connect(data).await?;
            }
            self.cf_state_mut().connected = true;
            Ok(())
        })
    }

    /// Tear down this filter's resources (the C `do_close`).
    ///
    /// Matches `Curl_cf_def_close`: clears `connected`, then closes `next`.
    /// Synchronous, like the C callback.
    fn close(&mut self) {
        let state = self.cf_state_mut();
        state.connected = false;
        if let Some(next) = state.next.as_mut() {
            next.close();
        }
    }

    /// Gracefully shut down this filter (the C `do_shutdown`).
    ///
    /// Matches `Curl_cf_def_shutdown` (cfilters.c L46-53): immediate success.
    /// Per the C contract this default **must not** chain to `next` — the
    /// [`FilterChain::shutdown`] drive walks the chain itself. The C `*done`
    /// polling collapses into awaiting this future.
    fn shutdown<'a>(&'a mut self) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { Ok(()) })
    }

    /// Whether this filter (or one below it) has buffered data ready to read.
    ///
    /// Matches `Curl_cf_def_data_pending` (cfilters.c L66-71): delegate to
    /// `next`, or `false` at the bottom of the chain.
    fn data_pending(&self) -> bool {
        match self.cf_state().next.as_ref() {
            Some(next) => next.data_pending(),
            None => false,
        }
    }

    /// Send up to `buf.len()` bytes, optionally signalling end-of-stream.
    /// Returns the number of bytes accepted.
    ///
    /// Matches `Curl_cf_def_send` (cfilters.c L73-83): delegate to `next`, or —
    /// at the bottom of the chain — return [`CurlError::RecvError`]. **This is
    /// curl's exact (counter-intuitive) code**: the no-`next` default of *send*
    /// is `CURLE_RECV_ERROR`. Preserve it; it is observable and tested.
    fn send<'a>(&'a mut self, buf: &'a [u8], eos: bool) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            match self.cf_state_mut().next.as_mut() {
                Some(next) => next.send(buf, eos).await,
                None => Err(CurlError::RecvError),
            }
        })
    }

    /// Receive into `buf`. Returns the number of bytes read; `0` means EOF.
    ///
    /// Matches `Curl_cf_def_recv` (cfilters.c L85-91): delegate to `next`, or —
    /// at the bottom of the chain — return [`CurlError::SendError`]. **This is
    /// curl's exact (counter-intuitive) code**: the no-`next` default of *recv*
    /// is `CURLE_SEND_ERROR`. Preserve it; it is observable and tested.
    fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            match self.cf_state_mut().next.as_mut() {
                Some(next) => next.recv(buf).await,
                None => Err(CurlError::SendError),
            }
        })
    }

    /// Handle a `CF_CTRL_*` control event. `arg1` is the event's integer
    /// argument (curl's `arg2`/`void*` is always `NULL` in 8.x and is omitted).
    ///
    /// Matches `Curl_cf_def_cntrl` (cfilters.c L854): a **no-op** returning
    /// success. Per the C header, `cntrl` defaults must **not** chain to
    /// `next` — the [`FilterChain::cntrl_chain`] drive performs the iteration,
    /// invoking each filter's `cntrl` in turn.
    fn cntrl(&mut self, _event: i32, _arg1: i32) -> Result<()> {
        Ok(())
    }

    /// Whether the connection is still usable, plus whether input is pending.
    /// Returns `(alive, input_pending)`.
    ///
    /// Matches `Curl_cf_def_conn_is_alive` (cfilters.c L92-99): delegate to
    /// `next`, or — pessimistically — `(false, false)` at the bottom of the
    /// chain (curl returns `FALSE` "in absence of data").
    fn is_alive(&mut self) -> (bool, bool) {
        match self.cf_state_mut().next.as_mut() {
            Some(next) => next.is_alive(),
            None => (false, false),
        }
    }

    /// Send a keep-alive probe if the filter supports one.
    ///
    /// Matches `Curl_cf_def_conn_keep_alive` (cfilters.c L101-107): delegate to
    /// `next`, or `Ok(())` at the bottom of the chain.
    fn keep_alive(&mut self) -> Result<()> {
        match self.cf_state_mut().next.as_mut() {
            Some(next) => next.keep_alive(),
            None => Ok(()),
        }
    }

    /// Answer a [`CfQuery`] about the connection.
    ///
    /// Matches `Curl_cf_def_query` (cfilters.c L109-116): delegate to `next`,
    /// or — at the bottom of the chain — return [`CurlError::UnknownOption`].
    fn query(&self, query: CfQuery) -> Result<CfQueryResult> {
        match self.cf_state().next.as_ref() {
            Some(next) => next.query(query),
            None => Err(CurlError::UnknownOption),
        }
    }

    /// Return the HTTP/1.x CONNECT-tunnel response header lines captured by a
    /// CONNECT filter ([`crate::conn::h1_proxy::CfH1Proxy`]) in this chain —
    /// the proxy's status line, each response header, and the terminating blank
    /// line, every line retaining its original CRLF — or `None` when no CONNECT
    /// filter is present.
    ///
    /// curl emits these lines to the client as it parses them, tagged
    /// `CLIENTWRITE_HEADER | CLIENTWRITE_CONNECT` (`cf-h1-proxy.c` `single_header`
    /// → `Curl_client_write` → `cw_download_write`). For a `--proxytunnel`
    /// transfer to a plain-HTTP origin `cw_download_write` forwards those header
    /// bytes onto the body writer, so they surface on the data stream ahead of
    /// the tunneled response (oracle: tests/data/test80/83/95). This accessor
    /// lets the transfer engine read them back out of the chain after the
    /// tunnel is established.
    ///
    /// The default delegates to the next (lower) filter — the same transparent
    /// pass-through every non-CONNECT filter exhibits once the tunnel is up; the
    /// CONNECT filter overrides it to return its captured lines.
    fn connect_response_headers(&self) -> Option<Vec<Vec<u8>>> {
        match self.cf_state().next.as_ref() {
            Some(next) => next.connect_response_headers(),
            None => None,
        }
    }

    /// The user-visible informational trace lines a CONNECT filter captured while
    /// parsing the proxy's CONNECT response (the connection-filter counterpart of
    /// curl's `infof` calls in `cf-h1-proxy.c`, e.g. "Ignoring Content-Length in
    /// CONNECT 200 response"). The transfer engine surfaces them as
    /// `CURLINFO_TEXT` (`* ` lines on stderr) after the tunnel is established,
    /// since the filter layer has no debug-callback handle of its own.
    ///
    /// The default delegates to the next (lower) filter — the same transparent
    /// pass-through every non-CONNECT filter exhibits; the CONNECT filter
    /// overrides it to return its captured lines.
    fn connect_info_text(&self) -> Option<Vec<String>> {
        match self.cf_state().next.as_ref() {
            Some(next) => next.connect_info_text(),
            None => None,
        }
    }

    /// The HTTP status code of the proxy's `CONNECT` response, if a CONNECT
    /// filter is present in (or below) this filter (C: `data->info.httpproxycode`,
    /// surfaced as `CURLINFO_HTTP_CONNECTCODE` / the `%{http_connect}` write-out
    /// variable). `0` means no CONNECT status line was parsed (no tunnel, or the
    /// status line never arrived).
    ///
    /// curl records `info.httpproxycode` the moment the CONNECT status line is
    /// parsed, so this is valid whether the tunnel ultimately succeeded (2xx) or
    /// failed (e.g. a 405/407 with no auth to satisfy it). The transfer engine
    /// reads it after driving the connect — on both the success and the failure
    /// path — so `%{http_connect}` reports the real code even when the tunnel
    /// failed (oracle: tests/data/test217 — a 405 CONNECT yields `%{http_connect}`
    /// == 405 while the transfer fails with `CURLE_RECV_ERROR`).
    ///
    /// The default delegates to the next (lower) filter — every non-CONNECT
    /// filter is transparent here; the CONNECT filter overrides it to return its
    /// parsed status code.
    fn connect_proxy_code(&self) -> Option<i32> {
        match self.cf_state().next.as_ref() {
            Some(next) => next.connect_proxy_code(),
            None => None,
        }
    }

    // ---- non-overridable convenience accessors --------------------------

    /// Whether this filter's type carries the given `CF_TYPE_*` flag.
    fn has_flag(&self, flag: u32) -> bool {
        (self.flags() & flag) != 0
    }

    /// Whether this filter has completed its connect (reads `BIT(connected)`).
    fn is_connected(&self) -> bool {
        self.cf_state().connected
    }

    /// Whether this filter has completed its shutdown (reads `BIT(shutdown)`).
    fn is_shutdown(&self) -> bool {
        self.cf_state().shutdown
    }

    /// Borrow the next (lower) filter, if any.
    fn next_ref(&self) -> Option<&dyn ConnectionFilter> {
        self.cf_state().next.as_deref()
    }

    /// Mutably borrow the next (lower) filter, if any.
    fn next_mut(&mut self) -> Option<&mut (dyn ConnectionFilter + 'static)> {
        self.cf_state_mut().next.as_deref_mut()
    }
}

// =============================================================================
// PHASE 3 — the filter chain (per socket index)
// =============================================================================

/// One connection-filter chain — the owned, head-first stack of filters for a
/// single socket index.
///
/// This is the Rust model of C's `conn->cfilter[sockindex]`: a singly-linked
/// list whose **head is the top/outermost filter** (e.g. TLS) and whose tail is
/// the innermost (e.g. the raw socket). Filters are added at the top
/// ([`add_filter`](Self::add_filter), mirroring `Curl_conn_cf_add`) and spliced
/// in the middle ([`insert_after_index`](Self::insert_after_index) /
/// [`insert_after_name`](Self::insert_after_name), mirroring
/// `Curl_conn_cf_insert_after`). Ownership is the chain itself — dropping the
/// chain (or any node) runs each filter's [`Drop`], replacing C's manual
/// `destroy`/`Curl_free` walk (`Curl_conn_cf_discard_*`).
///
/// `mod.rs`'s `Connection` owns one `FilterChain` per socket index and exposes
/// the public `Curl_conn_*` surface by delegating to the drive methods here.
#[derive(Default)]
pub struct FilterChain {
    /// The top/outermost filter; `None` for an un-setup chain.
    head: Option<Box<dyn ConnectionFilter>>,
    /// When a graceful shutdown began, used to enforce the shutdown timeout
    /// across the re-entrant [`shutdown`](Self::shutdown) calls (the multi loop
    /// drives shutdown repeatedly until done).
    shutdown_started: Option<CurlTime>,
}

impl std::fmt::Debug for FilterChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Render the chain as the ordered list of filter names (head -> tail).
        let mut names: Vec<&'static str> = Vec::new();
        let mut cur = self.head.as_deref();
        while let Some(cf) = cur {
            names.push(cf.name());
            cur = cf.next_ref();
        }
        f.debug_struct("FilterChain")
            .field("filters", &names)
            .field("shutdown_started", &self.shutdown_started)
            .finish()
    }
}

impl FilterChain {
    /// An empty (un-setup) chain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            head: None,
            shutdown_started: None,
        }
    }

    /// A chain whose head (and its already-linked sub-chain) is `head`.
    #[must_use]
    pub fn from_head(head: Box<dyn ConnectionFilter>) -> Self {
        Self {
            head: Some(head),
            shutdown_started: None,
        }
    }

    /// Whether the chain has no filters.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    /// Whether the chain has at least one filter (the C `Curl_conn_is_setup`:
    /// `conn->cfilter[sockindex] != NULL`).
    #[must_use]
    pub fn is_setup(&self) -> bool {
        self.head.is_some()
    }

    /// The number of filters in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        let mut n = 0;
        let mut cur = self.head.as_deref();
        while let Some(cf) = cur {
            n += 1;
            cur = cf.next_ref();
        }
        n
    }

    /// Borrow the head (top) filter, if any.
    #[must_use]
    pub fn head_ref(&self) -> Option<&dyn ConnectionFilter> {
        self.head.as_deref()
    }

    /// Mutably borrow the head (top) filter, if any.
    #[must_use]
    pub fn head_mut(&mut self) -> Option<&mut (dyn ConnectionFilter + 'static)> {
        self.head.as_deref_mut()
    }

    /// Detach and return the head (top) filter, leaving the chain empty.
    ///
    /// The entire already-linked sub-chain travels with the returned head —
    /// each filter owns its `next` (see the module-level chain description) — so
    /// this hands ownership of the whole connected stack to the caller in one
    /// move, leaving `self` empty (`is_setup()` becomes `false`).
    ///
    /// This is the move-out counterpart of [`head_mut`](Self::head_mut)/
    /// [`head_ref`](Self::head_ref): the HTTP/2 engine uses it to **move** the
    /// connected (post-TLS) filter chain out of a [`crate::conn::Connection`]
    /// and into an `h2`-owned I/O adapter
    /// ([`crate::protocols::http::h2::ConnFilterIo`]), which the spawned `h2`
    /// connection task then owns for the connection's lifetime — satisfying the
    /// `'static` bound of `h2_client_handshake`. The byte path is unchanged:
    /// reads/writes still route through the same filter, now driven by the `h2`
    /// task instead of the borrowing [`crate::conn::Curl_conn_recv`]/`send`.
    #[must_use]
    pub fn take_head(&mut self) -> Option<Box<dyn ConnectionFilter>> {
        self.head.take()
    }

    /// The index (0 = head) of the first filter whose [`name`](ConnectionFilter::name)
    /// equals `name`, if present.
    #[must_use]
    pub fn position_by_name(&self, name: &str) -> Option<usize> {
        let mut cur = self.head.as_deref();
        let mut idx = 0usize;
        while let Some(cf) = cur {
            if cf.name() == name {
                return Some(idx);
            }
            cur = cf.next_ref();
            idx += 1;
        }
        None
    }

    /// Add a single filter at the **top** of the chain (`Curl_conn_cf_add`,
    /// cfilters.c L329).
    ///
    /// The new filter's `next` becomes the previous head, so it is now the
    /// outermost filter. As in C (which asserts `cf->next == NULL`), this
    /// expects a *single* filter — splice sub-chains in with
    /// [`insert_after_index`](Self::insert_after_index).
    pub fn add_filter(&mut self, mut cf: Box<dyn ConnectionFilter>) {
        debug_assert!(
            cf.cf_state().next.is_none(),
            "add_filter expects a single filter; use insert_after_* for sub-chains"
        );
        cf.cf_state_mut().next = self.head.take();
        self.head = Some(cf);
    }

    /// Splice `cf_new` (a filter or whole sub-chain) into the chain immediately
    /// after the filter at `index` (`Curl_conn_cf_insert_after`, cfilters.c
    /// L345).
    ///
    /// The filters previously below `index` are reattached below `cf_new`'s own
    /// tail, preserving order. Returns [`CurlError::BadFunctionArgument`] if no
    /// filter exists at `index`.
    pub fn insert_after_index(
        &mut self,
        index: usize,
        cf_new: Box<dyn ConnectionFilter>,
    ) -> Result<()> {
        let at = self
            .node_at_mut(index)
            .ok_or(CurlError::BadFunctionArgument)?;
        Self::splice_after(at, cf_new);
        Ok(())
    }

    /// Splice `cf_new` immediately after the first filter named `name`. Returns
    /// [`CurlError::BadFunctionArgument`] if no such filter exists.
    pub fn insert_after_name(
        &mut self,
        name: &str,
        cf_new: Box<dyn ConnectionFilter>,
    ) -> Result<()> {
        let index = self
            .position_by_name(name)
            .ok_or(CurlError::BadFunctionArgument)?;
        self.insert_after_index(index, cf_new)
    }

    /// Discard the entire chain (`Curl_conn_cf_discard_all`, cfilters.c L138):
    /// every filter is dropped (each filter's [`Drop`] runs its teardown).
    pub fn discard_all(&mut self) {
        // Dropping the head Box drops the whole owned chain.
        self.head = None;
        self.shutdown_started = None;
    }

    /// Unlink and discard the single filter at `index`, reconnecting the chain
    /// around it (`Curl_conn_cf_discard`, cfilters.c L365). The removed filter's
    /// successor is spliced into its former position. Returns `true` if a filter
    /// existed at `index`.
    pub fn remove_at(&mut self, index: usize) -> bool {
        if index == 0 {
            match self.head.take() {
                Some(mut node) => {
                    // Detach the successor and reseat it as the new head; `node`
                    // is then dropped alone (its `next` is now None).
                    self.head = node.cf_state_mut().next.take();
                    true
                }
                None => false,
            }
        } else {
            match self.node_at_mut(index - 1) {
                Some(parent) => match parent.cf_state_mut().next.take() {
                    Some(mut node) => {
                        parent.cf_state_mut().next = node.cf_state_mut().next.take();
                        // `node` dropped here alone.
                        true
                    }
                    None => false,
                },
                None => false,
            }
        }
    }

    // ---- internal chain-traversal helpers -------------------------------

    /// A mutable reference to the filter at `index` (0 = head).
    fn node_at_mut(&mut self, index: usize) -> Option<&mut Box<dyn ConnectionFilter>> {
        let head = self.head.as_mut()?;
        Self::nth_mut(head, index)
    }

    /// Recursively descend `index` links from `cf` and return that node.
    fn nth_mut(
        cf: &mut Box<dyn ConnectionFilter>,
        index: usize,
    ) -> Option<&mut Box<dyn ConnectionFilter>> {
        if index == 0 {
            Some(cf)
        } else {
            let next = cf.cf_state_mut().next.as_mut()?;
            Self::nth_mut(next, index - 1)
        }
    }

    /// Splice `cf_new` in after the node `at`: detach `at`'s successor, attach
    /// it below `cf_new`'s tail, then make `cf_new` `at`'s successor.
    fn splice_after(at: &mut Box<dyn ConnectionFilter>, mut cf_new: Box<dyn ConnectionFilter>) {
        let tail = at.cf_state_mut().next.take();
        Self::attach_tail(&mut cf_new, tail);
        at.cf_state_mut().next = Some(cf_new);
    }

    /// Recursively walk `chain` to its last node and set that node's `next`
    /// slot to `tail`.
    fn attach_tail(chain: &mut Box<dyn ConnectionFilter>, tail: Option<Box<dyn ConnectionFilter>>) {
        if chain.cf_state().next.is_some() {
            let next = chain
                .cf_state_mut()
                .next
                .as_mut()
                .expect("next is Some per the guard above");
            Self::attach_tail(next, tail);
        } else {
            chain.cf_state_mut().next = tail;
        }
    }
}

// =============================================================================
// PHASE 4 — chain-level drive logic (the `Curl_conn_*` per-sockindex surface)
// =============================================================================
//
// These methods drive a whole chain and are what `mod.rs`'s `Connection`
// delegates to. The cross-socket-index broadcasts (curl's `cf_cntrl_all`, which
// loops over `conn->cfilter[0..2]`) live in `mod.rs` because they span multiple
// chains; here we provide the single-chain `cntrl_chain` they call per index.

impl FilterChain {
    /// Drive the chain to a fully-connected state (`Curl_conn_connect`,
    /// cfilters.c L491).
    ///
    /// # The async collapse
    ///
    /// curl loops `do_connect` + `Curl_poll` until the head filter sets
    /// `*done = TRUE`. Here that whole loop is a single `head.connect(...).await`
    /// — the future resolves exactly when curl's `*done` would be set, and the
    /// Tokio reactor supplies the readiness `Curl_poll`/`easy_pollset` used to
    /// provide. No `pollfd`/`adjust_pollset` machinery is reproduced.
    ///
    /// `timeout_ms` is the overall connect deadline in milliseconds (the easy
    /// handle's `Curl_timeleft_ms`); `None` or a negative value means "no
    /// limit". On expiry this returns [`CurlError::OperationTimedout`] after a
    /// `failf`. On success it broadcasts [`CF_CTRL_CONN_INFO_UPDATE`] so filters
    /// persist their socket / IP info (curl's `cf_cntrl_update_info`,
    /// L463-467). [`CurlError::Again`] is propagated unchanged (transient).
    pub async fn connect(&mut self, timeout_ms: Option<i64>, data: &mut FilterData) -> Result<()> {
        // No chain: curl returns CURLE_FAILED_INIT with *done = FALSE.
        if self.head.is_none() {
            return Err(CurlError::FailedInit);
        }
        // Already connected fast-path (curl reads head->connected for *done).
        let already = self
            .head
            .as_deref()
            .map(ConnectionFilter::is_connected)
            .unwrap_or(false);
        if already {
            return Ok(());
        }

        // Drive the head filter's connect to completion, optionally bounded by
        // the connect timeout. The borrow of `self.head` and `data` is scoped
        // to this block so it is released before the post-connect broadcast.
        let result: Result<()> = {
            let head = self.head.as_mut().expect("head present per guard above");
            let fut = head.connect(data);
            match timeout_ms {
                Some(ms) if ms >= 0 => match tokio::time::timeout(ms_to_duration(ms), fut).await {
                    Ok(inner) => inner,
                    Err(_elapsed) => Err(CurlError::OperationTimedout),
                },
                _ => fut.await,
            }
        };

        match result {
            Ok(()) => {
                // Post-connect info update is "ignored result" in curl.
                let _ = self.cntrl_chain(true, CF_CTRL_CONN_INFO_UPDATE, 0);
                Ok(())
            }
            Err(CurlError::OperationTimedout) => {
                data.failf("Connection timed out");
                Err(CurlError::OperationTimedout)
            }
            Err(other) => Err(other),
        }
    }

    /// Close the chain (`Curl_conn_close`, cfilters.c L144): close the head
    /// filter (which clears its `connected` bit and closes `next`), then clear
    /// all per-filter shutdown state (curl's `Curl_shutdown_clear`).
    pub fn close(&mut self) {
        if let Some(head) = self.head.as_mut() {
            head.close();
        }
        self.clear_shutdown_state();
    }

    /// Gracefully shut down every connected filter (`Curl_conn_shutdown`,
    /// cfilters.c L157). Returns `Ok(true)` when shutdown is complete.
    ///
    /// curl's re-entrant `*done` polling (each call shuts down filters top-down,
    /// returning early while a filter is "not done") collapses into awaiting
    /// each connected filter's [`ConnectionFilter::shutdown`] to completion in
    /// order. `timeout_ms` bounds the whole sequence using a deadline anchored
    /// on the first call (`curlx_now`); on expiry this emits an `infof`
    /// ("shutdown timeout") and returns [`CurlError::OperationTimedout`].
    pub async fn shutdown(
        &mut self,
        timeout_ms: Option<i64>,
        data: &mut FilterData,
    ) -> Result<bool> {
        // Empty chain or nothing left to shut down: done.
        if self.head.is_none() || !self.any_needs_shutdown() {
            self.shutdown_started = None;
            return Ok(true);
        }

        // Anchor the shutdown deadline on the first call.
        let started = *self.shutdown_started.get_or_insert_with(timeval::curlx_now);

        // Compute the remaining time budget, if a finite timeout is set.
        let remaining: Option<Duration> = match timeout_ms {
            Some(ms) if ms >= 0 => {
                let elapsed_ms = duration_to_ms(timeval::elapsed_since(started));
                let left = ms - elapsed_ms;
                if left < 0 {
                    data.infof("shutdown timeout");
                    return Err(CurlError::OperationTimedout);
                }
                Some(ms_to_duration(left))
            }
            _ => None,
        };

        // Drive each connected filter's shutdown to completion, top-down.
        let result = match remaining {
            Some(dur) => match tokio::time::timeout(dur, self.drive_shutdown()).await {
                Ok(inner) => inner,
                Err(_elapsed) => {
                    data.infof("shutdown timeout");
                    return Err(CurlError::OperationTimedout);
                }
            },
            None => self.drive_shutdown().await,
        };

        match result {
            Ok(()) => {
                self.shutdown_started = None;
                Ok(true)
            }
            Err(other) => Err(other),
        }
    }

    /// Walk the chain top-down, awaiting `shutdown` on each filter that is
    /// connected and not yet shut down, marking each done as it completes.
    async fn drive_shutdown(&mut self) -> Result<()> {
        let mut idx = 0usize;
        loop {
            if idx >= self.len() {
                break;
            }
            if self.node_needs_shutdown(idx) {
                // Scope the mutable borrow of the node across the await.
                {
                    let node = self.node_at_mut(idx).expect("idx < len");
                    node.shutdown().await?;
                }
                if let Some(node) = self.node_at_mut(idx) {
                    node.cf_state_mut().shutdown = true;
                }
            }
            idx += 1;
        }
        Ok(())
    }

    /// Send via the first connected filter (`Curl_cf_send`, cfilters.c L237).
    /// If no filter is connected this is a hard error: `failf` then
    /// [`CurlError::FailedInit`].
    pub async fn send(&mut self, buf: &[u8], eos: bool, data: &mut FilterData) -> Result<usize> {
        match self.first_connected_index() {
            Some(idx) => {
                let node = self
                    .node_at_mut(idx)
                    .expect("index from first_connected_index");
                node.send(buf, eos).await
            }
            None => {
                data.failf("send: no filter connected");
                Err(CurlError::FailedInit)
            }
        }
    }

    /// Receive via the first connected filter (`Curl_cf_recv`, cfilters.c L212).
    /// If no filter is connected this is a hard error: `failf` then
    /// [`CurlError::FailedInit`]. A return of `0` means EOF.
    pub async fn recv(&mut self, buf: &mut [u8], data: &mut FilterData) -> Result<usize> {
        match self.first_connected_index() {
            Some(idx) => {
                let node = self
                    .node_at_mut(idx)
                    .expect("index from first_connected_index");
                node.recv(buf).await
            }
            None => {
                data.failf("recv: no filter connected");
                Err(CurlError::FailedInit)
            }
        }
    }

    /// Distribute a control event across this chain (`Curl_conn_cf_cntrl`,
    /// cfilters.c L866): invoke each filter's [`ConnectionFilter::cntrl`]
    /// top-down. When `ignore_result` is `false`, the first filter returning an
    /// error stops distribution and that error is returned; otherwise every
    /// filter is visited and the result is always `Ok(())`.
    ///
    /// (curl skips filters whose `cntrl` is the no-op default; here invoking the
    /// default is itself a harmless no-op returning `Ok(())`, so the observable
    /// behavior is identical.)
    pub fn cntrl_chain(&mut self, ignore_result: bool, event: i32, arg1: i32) -> Result<()> {
        if let Some(head) = self.head.as_mut() {
            Self::cntrl_walk(head, ignore_result, event, arg1)?;
        }
        Ok(())
    }

    fn cntrl_walk(
        cf: &mut Box<dyn ConnectionFilter>,
        ignore_result: bool,
        event: i32,
        arg1: i32,
    ) -> Result<()> {
        let result = cf.cntrl(event, arg1);
        if !ignore_result {
            result?;
        }
        if let Some(next) = cf.cf_state_mut().next.as_mut() {
            Self::cntrl_walk(next, ignore_result, event, arg1)?;
        }
        Ok(())
    }

    // ---- control-event conveniences (curl's `Curl_conn_ev_*` / flush) ----

    /// `CF_CTRL_DATA_SETUP` (first-fail): notify filters to set up for the
    /// transfer.
    pub fn ev_data_setup(&mut self) -> Result<()> {
        self.cntrl_chain(false, CF_CTRL_DATA_SETUP, 0)
    }

    /// `CF_CTRL_DATA_DONE_SEND` (ignored): the transfer finished sending.
    pub fn ev_data_done_send(&mut self) {
        let _ = self.cntrl_chain(true, CF_CTRL_DATA_DONE_SEND, 0);
    }

    /// `CF_CTRL_DATA_DONE` (ignored): the transfer is done (`premature` marks an
    /// early/aborted finish).
    pub fn ev_data_done(&mut self, premature: bool) {
        let _ = self.cntrl_chain(true, CF_CTRL_DATA_DONE, i32::from(premature));
    }

    /// `CF_CTRL_DATA_PAUSE` (first-fail): pause/unpause the transfer.
    pub fn ev_data_pause(&mut self, do_pause: bool) -> Result<()> {
        self.cntrl_chain(false, CF_CTRL_DATA_PAUSE, i32::from(do_pause))
    }

    /// Flush buffered outbound data through the chain (`Curl_conn_flush`):
    /// a `CF_CTRL_FLUSH` control event (first-fail).
    pub fn flush(&mut self) -> Result<()> {
        self.cntrl_chain(false, CF_CTRL_FLUSH, 0)
    }

    // ---- liveness / pending / queries ------------------------------------

    /// Whether the chain has buffered inbound data ready (`Curl_conn_data_pending`).
    #[must_use]
    pub fn data_pending(&self) -> bool {
        self.head
            .as_deref()
            .map(ConnectionFilter::data_pending)
            .unwrap_or(false)
    }

    /// Whether the connection is still usable, plus whether input is pending
    /// (`Curl_conn_is_alive`). `(false, false)` for an empty chain.
    pub fn is_alive(&mut self) -> (bool, bool) {
        match self.head.as_mut() {
            Some(head) => head.is_alive(),
            None => (false, false),
        }
    }

    /// Send a keep-alive probe through the chain (`Curl_conn_keep_alive`).
    pub fn keep_alive(&mut self) -> Result<()> {
        match self.head.as_mut() {
            Some(head) => head.keep_alive(),
            None => Ok(()),
        }
    }

    /// Whether any filter has unsent buffered data (`CF_QUERY_NEED_FLUSH`).
    #[must_use]
    pub fn needs_flush(&self) -> bool {
        matches!(
            self.query(CfQuery::NeedFlush),
            Ok(CfQueryResult::NeedFlush(true))
        )
    }

    /// Issue a [`CfQuery`] to the chain (the head answers or delegates down;
    /// the chain bottom returns [`CurlError::UnknownOption`]).
    pub fn query(&self, q: CfQuery) -> Result<CfQueryResult> {
        match self.head.as_deref() {
            Some(head) => head.query(q),
            None => Err(CurlError::UnknownOption),
        }
    }

    /// The HTTP/1.x CONNECT-tunnel response header lines captured by a CONNECT
    /// filter in this chain (see
    /// [`ConnectionFilter::connect_response_headers`]), or `None` if the chain
    /// has no CONNECT filter. The head answers or delegates down the chain.
    #[must_use]
    pub fn connect_response_headers(&self) -> Option<Vec<Vec<u8>>> {
        match self.head.as_deref() {
            Some(head) => head.connect_response_headers(),
            None => None,
        }
    }

    /// The user-visible CONNECT-response informational trace lines captured by a
    /// CONNECT filter in this chain (see
    /// [`ConnectionFilter::connect_info_text`]), or `None` if the chain has no
    /// CONNECT filter. The head answers or delegates down the chain.
    #[must_use]
    pub fn connect_info_text(&self) -> Option<Vec<String>> {
        match self.head.as_deref() {
            Some(head) => head.connect_info_text(),
            None => None,
        }
    }

    /// The HTTP status code of the proxy's `CONNECT` response captured by a
    /// CONNECT filter in this chain (see
    /// [`ConnectionFilter::connect_proxy_code`]), or `None` if the chain has no
    /// CONNECT filter. Backs `CURLINFO_HTTP_CONNECTCODE` / `%{http_connect}`.
    #[must_use]
    pub fn connect_proxy_code(&self) -> Option<i32> {
        match self.head.as_deref() {
            Some(head) => head.connect_proxy_code(),
            None => None,
        }
    }

    /// The chain's socket descriptor (`CF_QUERY_SOCKET`); `-1` if unavailable.
    #[must_use]
    pub fn get_socket(&self) -> i64 {
        match self.query(CfQuery::Socket) {
            Ok(CfQueryResult::Socket(s)) => s,
            _ => -1,
        }
    }

    /// The connected remote address (`CF_QUERY_REMOTE_ADDR`), if available.
    #[must_use]
    pub fn get_remote_addr(&self) -> Option<SocketAddr> {
        match self.query(CfQuery::RemoteAddr) {
            Ok(CfQueryResult::RemoteAddr(addr)) => addr,
            _ => None,
        }
    }

    /// The transport in use (`CF_QUERY_TRANSPORT`), if known.
    #[must_use]
    pub fn get_transport(&self) -> Option<u8> {
        match self.query(CfQuery::Transport) {
            Ok(CfQueryResult::Transport(t)) => Some(t),
            _ => None,
        }
    }

    /// The negotiated ALPN protocol (`CF_QUERY_ALPN_NEGOTIATED`), if any.
    #[must_use]
    pub fn get_alpn_negotiated(&self) -> Option<Vec<u8>> {
        match self.query(CfQuery::AlpnNegotiated) {
            Ok(CfQueryResult::AlpnNegotiated(alpn)) => alpn,
            _ => None,
        }
    }

    /// The peer certificate chain in DER form (`CF_QUERY_PEER_CERTS`), leaf
    /// first; empty when the connection is not TLS or no chain was captured.
    #[must_use]
    pub fn get_peer_certs(&self) -> Vec<Vec<u8>> {
        match self.query(CfQuery::PeerCerts) {
            Ok(CfQueryResult::PeerCerts(certs)) => certs,
            _ => Vec::new(),
        }
    }

    /// The HTTP version in use (`CF_QUERY_HTTP_VERSION`), if known.
    #[must_use]
    pub fn http_version(&self) -> Option<u8> {
        match self.query(CfQuery::HttpVersion) {
            Ok(CfQueryResult::HttpVersion(v)) => Some(v),
            _ => None,
        }
    }

    /// Max parallel transfers the chain supports (`CF_QUERY_MAX_CONCURRENT`).
    /// Defaults to `1` when no filter answers (a single, non-multiplexed
    /// connection).
    #[must_use]
    pub fn max_concurrent(&self) -> u32 {
        match self.query(CfQuery::MaxConcurrent) {
            Ok(CfQueryResult::MaxConcurrent(n)) => n,
            _ => 1,
        }
    }

    /// The underlying stream error code (`CF_QUERY_STREAM_ERROR`); `0` if none.
    #[must_use]
    pub fn stream_error(&self) -> i32 {
        match self.query(CfQuery::StreamError) {
            Ok(CfQueryResult::StreamError(e)) => e,
            _ => 0,
        }
    }

    /// Whether the chain includes a TLS filter (`Curl_conn_is_ssl`:
    /// any filter with [`CF_TYPE_SSL`]).
    #[must_use]
    pub fn is_ssl(&self) -> bool {
        self.has_flag_in_chain(CF_TYPE_SSL)
    }

    /// Whether the chain includes a multiplexing filter ([`CF_TYPE_MULTIPLEX`]).
    #[must_use]
    pub fn is_multiplex(&self) -> bool {
        self.has_flag_in_chain(CF_TYPE_MULTIPLEX)
    }

    /// Whether the chain includes an IP-connect (or equivalent) filter
    /// ([`CF_TYPE_IP_CONNECT`]).
    #[must_use]
    pub fn is_ip_connect(&self) -> bool {
        self.has_flag_in_chain(CF_TYPE_IP_CONNECT)
    }

    // ---- internal predicates / traversal --------------------------------

    /// `true` if any filter in the chain carries `flag`.
    fn has_flag_in_chain(&self, flag: u32) -> bool {
        let mut cur = self.head.as_deref();
        while let Some(cf) = cur {
            if cf.has_flag(flag) {
                return true;
            }
            cur = cf.next_ref();
        }
        false
    }

    /// Index of the first connected filter (top-down), if any.
    fn first_connected_index(&self) -> Option<usize> {
        let mut cur = self.head.as_deref();
        let mut idx = 0usize;
        while let Some(cf) = cur {
            if cf.is_connected() {
                return Some(idx);
            }
            cur = cf.next_ref();
            idx += 1;
        }
        None
    }

    /// Whether any filter still needs shutting down (connected and not yet
    /// shut down).
    fn any_needs_shutdown(&self) -> bool {
        let mut cur = self.head.as_deref();
        while let Some(cf) = cur {
            if cf.is_connected() && !cf.is_shutdown() {
                return true;
            }
            cur = cf.next_ref();
        }
        false
    }

    /// Whether the filter at `index` is connected and not yet shut down.
    fn node_needs_shutdown(&self, index: usize) -> bool {
        self.node_at(index)
            .map(|cf| cf.is_connected() && !cf.is_shutdown())
            .unwrap_or(false)
    }

    /// Immutable reference to the filter at `index` (0 = head).
    fn node_at(&self, index: usize) -> Option<&dyn ConnectionFilter> {
        let mut cur = self.head.as_deref();
        let mut i = 0usize;
        while let Some(cf) = cur {
            if i == index {
                return Some(cf);
            }
            cur = cf.next_ref();
            i += 1;
        }
        None
    }

    /// Reset all per-filter shutdown bits and the shutdown timer (curl's
    /// `Curl_shutdown_clear`).
    fn clear_shutdown_state(&mut self) {
        self.shutdown_started = None;
        if let Some(head) = self.head.as_mut() {
            Self::clear_shutdown_bits(head);
        }
    }

    fn clear_shutdown_bits(cf: &mut Box<dyn ConnectionFilter>) {
        cf.cf_state_mut().shutdown = false;
        if let Some(next) = cf.cf_state_mut().next.as_mut() {
            Self::clear_shutdown_bits(next);
        }
    }
}

// =============================================================================
// PHASE 6 — BufQ I/O adapters (readiness-buffered helpers)
// =============================================================================
//
// These bridge a filter's async `recv`/`send` to the synchronous chunked
// [`BufQ`] from `crate::util::bufq`, reproducing curl's `Curl_cf_recv_bufq`
// (cfilters.c L263) and `Curl_cf_send_bufq` (L288). They are free functions
// over a single `&mut dyn ConnectionFilter` (the C functions take one `cf`).
//
// curl's `BufQ` helpers (`sipn` / `pass` / `write_pass`) take a *synchronous*
// `FnMut` source/sink, but a filter's `recv`/`send` are *async* and cannot be
// awaited from inside a sync closure (that would require blocking the runtime).
// So the bridge is hand-rolled: `recv` reads into a temporary then enqueues via
// `BufQ::write`; `send` peeks each queued slice and awaits `send` on it, then
// `skip`s exactly what was accepted. The `CURLE_AGAIN` full/empty contract of
// `BufQ` is honored throughout.
//
// curl's `!cf || !data -> CURLE_BAD_FUNCTION_ARGUMENT` guard is unreachable here
// because a `&mut dyn ConnectionFilter` can never be null; it is therefore
// omitted by construction (the safe-Rust equivalent of that check).

/// Default per-call read budget for [`cf_recv_bufq`] when `max_len == 0`
/// (curl's `sipn(0, …)` reads up to the tail chunk's free space; this safe port
/// reads into a temporary of this size). Callers should size their `BufQ` to
/// hold at least this many bytes (the normal recv-buffer invariant).
pub const DEFAULT_RECV_CHUNK: usize = 16 * 1024;

/// Fill `bufq` from `cf`'s `recv`, returning the number of bytes buffered
/// (`Curl_cf_recv_bufq`, cfilters.c L263). `0` means the filter reached EOF.
///
/// Reads at most `max_len` bytes in one `recv` (or [`DEFAULT_RECV_CHUNK`] when
/// `max_len == 0`) and appends them to `bufq`. Returns
/// [`CurlError::Again`](crate::error::CurlError::Again) when `bufq` is already
/// full (no room to read into) — the readiness signal the chain relies on.
///
/// The caller must size `bufq` to accept the requested `max_len`; under that
/// invariant (the normal recv-buffer sizing) every received byte is buffered.
pub async fn cf_recv_bufq(
    cf: &mut dyn ConnectionFilter,
    bufq: &mut BufQ,
    max_len: usize,
) -> Result<usize> {
    // Full queue: nothing can be read into it right now -> would block.
    if bufq.is_full() {
        return Err(CurlError::Again);
    }

    let budget = if max_len == 0 {
        DEFAULT_RECV_CHUNK
    } else {
        max_len
    };
    let mut tmp = vec![0u8; budget];

    // One async read from the filter (subsumes curl's single `sipn` source call).
    let n = cf.recv(&mut tmp).await?;
    if n == 0 {
        return Ok(0); // EOF
    }

    // Enqueue what we read. `BufQ::write` grows the queue (up to its
    // `max_chunks`) and reports the count buffered; we loop to absorb any
    // partial write while there is still room.
    let mut buffered = 0usize;
    while buffered < n {
        match bufq.write(&tmp[buffered..n]) {
            Ok(0) => break,
            Ok(w) => buffered += w,
            Err(CurlError::Again) => break, // queue filled mid-write
            Err(other) => return Err(other),
        }
    }
    debug_assert!(
        buffered == n,
        "cf_recv_bufq over-read past BufQ capacity; size the queue for max_len"
    );
    Ok(buffered)
}

/// Send through `cf`, buffering via `bufq` (`Curl_cf_send_bufq`, cfilters.c
/// L288). Returns the number of bytes **of `buf`** that were accepted into the
/// queue.
///
/// * When `buf` is non-empty this is curl's `Curl_bufq_write_pass`: buffer
///   `buf`, draining the queue to `cf` only to make room when it is full.
/// * When `buf` is empty this is curl's `Curl_bufq_pass`: just drain whatever is
///   queued to `cf`.
///
/// Blocking/partial-progress semantics match `BufQ`: a block after partial
/// progress yields `Ok(progress)`; a block before any progress yields
/// [`CurlError::Again`](crate::error::CurlError::Again); real I/O errors
/// propagate.
pub async fn cf_send_bufq(
    cf: &mut dyn ConnectionFilter,
    bufq: &mut BufQ,
    buf: &[u8],
) -> Result<usize> {
    // Empty input: pure drain (`Curl_bufq_pass`).
    if buf.is_empty() {
        return drain_bufq_to_cf(cf, bufq).await;
    }

    // Non-empty input: `Curl_bufq_write_pass` — buffer, draining to make room.
    let mut written = 0usize;
    let mut rest = buf;
    while !rest.is_empty() {
        if bufq.is_full() {
            match drain_bufq_to_cf(cf, bufq).await {
                Ok(_) => {}
                Err(CurlError::Again) => break, // can't make room; queue stays full
                Err(other) => return Err(other),
            }
        }
        match bufq.write(rest) {
            Ok(0) => break,
            Ok(w) => {
                rest = &rest[w..];
                written += w;
            }
            Err(CurlError::Again) => {
                return if written > 0 {
                    Ok(written)
                } else {
                    Err(CurlError::Again)
                };
            }
            Err(other) => return Err(other),
        }
    }

    if written == 0 {
        // Had input but buffered nothing (queue full and undrainable).
        return Err(CurlError::Again);
    }
    Ok(written)
}

/// Drain `bufq` into `cf` by peeking each queued slice and awaiting `send` on
/// it (curl's `Curl_bufq_pass` body, with an async sink). Returns the total
/// bytes sent. Mirrors `pass`'s blocking semantics: a block on the very first
/// slice yields [`CurlError::Again`](crate::error::CurlError::Again); a block
/// after progress yields `Ok(total)`.
async fn drain_bufq_to_cf(cf: &mut dyn ConnectionFilter, bufq: &mut BufQ) -> Result<usize> {
    let mut total = 0usize;
    // Copy each front slice to an owned buffer so the immutable `peek` borrow of
    // `bufq` is released (before the `await`, which needs `bufq` mutably for
    // `skip`, and so the future stays `Send`). `None` ends the drain.
    while let Some(chunk) = bufq.peek().map(|slice| slice.to_vec()) {
        match cf.send(&chunk, false).await {
            Ok(0) => {
                if total == 0 {
                    return Err(CurlError::Again);
                }
                break;
            }
            Ok(sent) => {
                bufq.skip(sent);
                total += sent;
                if sent < chunk.len() {
                    break; // sink would block on the remainder
                }
            }
            Err(CurlError::Again) => {
                if total > 0 {
                    break;
                }
                return Err(CurlError::Again);
            }
            Err(other) => return Err(other),
        }
    }
    Ok(total)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::codes;
    use std::sync::{Arc, Mutex};

    /// Drive a future to completion on a fresh current-thread runtime with the
    /// time driver enabled (so the connect/shutdown timeout paths work).
    fn run<F: Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("failed to build test runtime")
            .block_on(fut)
    }

    /// A filter using only trait defaults (the three required methods). Exercises
    /// the `Curl_cf_def_*` pass-through behavior.
    struct PassThrough {
        state: CfState,
        name: &'static str,
    }

    impl PassThrough {
        fn new(name: &'static str) -> Self {
            Self {
                state: CfState::new(),
                name,
            }
        }
    }

    impl ConnectionFilter for PassThrough {
        fn name(&self) -> &'static str {
            self.name
        }
        fn cf_state(&self) -> &CfState {
            &self.state
        }
        fn cf_state_mut(&mut self) -> &mut CfState {
            &mut self.state
        }
    }

    /// Shared, inspectable record of what a [`MockFilter`] observed (kept behind
    /// `Arc<Mutex<..>>` so the test can read it after the filter is buried in a
    /// chain, while remaining `Send`).
    #[derive(Default)]
    struct Log {
        sent: Vec<u8>,
        shutdown_called: bool,
        cntrl_events: Vec<(i32, i32)>,
    }

    /// A configurable leaf filter: records sends / shutdown / cntrl, can yield a
    /// fixed recv payload, and can answer selected queries.
    struct MockFilter {
        state: CfState,
        name: &'static str,
        flags: u32,
        to_recv: Vec<u8>,
        answer_socket: Option<i64>,
        answer_transport: Option<u8>,
        log: Arc<Mutex<Log>>,
    }

    impl MockFilter {
        fn new(name: &'static str, log: Arc<Mutex<Log>>) -> Self {
            Self {
                state: CfState::new(),
                name,
                flags: 0,
                to_recv: Vec::new(),
                answer_socket: None,
                answer_transport: None,
                log,
            }
        }
    }

    impl ConnectionFilter for MockFilter {
        fn name(&self) -> &'static str {
            self.name
        }
        fn cf_state(&self) -> &CfState {
            &self.state
        }
        fn cf_state_mut(&mut self) -> &mut CfState {
            &mut self.state
        }
        fn flags(&self) -> u32 {
            self.flags
        }
        fn send<'a>(&'a mut self, buf: &'a [u8], _eos: bool) -> BoxFuture<'a, Result<usize>> {
            Box::pin(async move {
                self.log.lock().expect("log").sent.extend_from_slice(buf);
                Ok(buf.len())
            })
        }
        fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize>> {
            Box::pin(async move {
                if self.to_recv.is_empty() {
                    return Ok(0);
                }
                let n = self.to_recv.len().min(buf.len());
                buf[..n].copy_from_slice(&self.to_recv[..n]);
                self.to_recv.drain(..n);
                Ok(n)
            })
        }
        fn shutdown<'a>(&'a mut self) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                self.log.lock().expect("log").shutdown_called = true;
                Ok(())
            })
        }
        fn cntrl(&mut self, event: i32, arg1: i32) -> Result<()> {
            self.log
                .lock()
                .expect("log")
                .cntrl_events
                .push((event, arg1));
            Ok(())
        }
        fn query(&self, query: CfQuery) -> Result<CfQueryResult> {
            match query {
                CfQuery::Socket if self.answer_socket.is_some() => {
                    Ok(CfQueryResult::Socket(self.answer_socket.expect("socket")))
                }
                CfQuery::Transport if self.answer_transport.is_some() => Ok(
                    CfQueryResult::Transport(self.answer_transport.expect("transport")),
                ),
                _ => match self.cf_state().next.as_ref() {
                    Some(next) => next.query(query),
                    None => Err(CurlError::UnknownOption),
                },
            }
        }
    }

    fn log() -> Arc<Mutex<Log>> {
        Arc::new(Mutex::new(Log::default()))
    }

    fn names(chain: &FilterChain) -> Vec<&'static str> {
        let mut out = Vec::new();
        let mut cur = chain.head_ref();
        while let Some(cf) = cur {
            out.push(cf.name());
            cur = cf.next_ref();
        }
        out
    }

    // ---- constant parity (cross-check vs cfilters.h) --------------------

    #[test]
    fn constants_match_oracle() {
        // CF_TYPE_* bitset.
        assert_eq!(CF_TYPE_IP_CONNECT, 1 << 0);
        assert_eq!(CF_TYPE_SSL, 1 << 1);
        assert_eq!(CF_TYPE_MULTIPLEX, 1 << 2);
        assert_eq!(CF_TYPE_PROXY, 1 << 3);
        assert_eq!(CF_TYPE_HTTP, 1 << 4);
        // CF_CTRL_* events.
        assert_eq!(CF_CTRL_DATA_SETUP, 4);
        assert_eq!(CF_CTRL_DATA_PAUSE, 6);
        assert_eq!(CF_CTRL_DATA_DONE, 7);
        assert_eq!(CF_CTRL_DATA_DONE_SEND, 8);
        assert_eq!(CF_CTRL_CONN_INFO_UPDATE, 256);
        assert_eq!(CF_CTRL_FORGET_SOCKET, 257);
        assert_eq!(CF_CTRL_FLUSH, 258);
        // CF_QUERY_* codes 1..=15, and the enum mirrors them exactly.
        assert_eq!(CF_QUERY_MAX_CONCURRENT, 1);
        assert_eq!(CF_QUERY_ALPN_NEGOTIATED, 15);
        assert_eq!(CfQuery::MaxConcurrent.as_i32(), 1);
        assert_eq!(CfQuery::AlpnNegotiated.as_i32(), 15);
        assert_eq!(CfQuery::from_i32(3), Some(CfQuery::Socket));
        assert_eq!(CfQuery::from_i32(99), None);
        // SSL-mode markers.
        assert_eq!(CURL_CF_SSL_DEFAULT, -1);
        assert_eq!(CURL_CF_SSL_DISABLE, 0);
        assert_eq!(CURL_CF_SSL_ENABLE, 1);
    }

    // ---- chain management: add / insert_after / discard -----------------

    #[test]
    fn add_filter_pushes_onto_head() {
        let mut chain = FilterChain::new();
        assert!(chain.is_empty());
        chain.add_filter(Box::new(PassThrough::new("A")));
        chain.add_filter(Box::new(PassThrough::new("B")));
        chain.add_filter(Box::new(PassThrough::new("C")));
        // Last added is the head; chain is C -> B -> A.
        assert_eq!(names(&chain), vec!["C", "B", "A"]);
        assert_eq!(chain.len(), 3);
        assert!(chain.is_setup());
        assert_eq!(chain.position_by_name("A"), Some(2));
        assert_eq!(chain.position_by_name("C"), Some(0));
        assert_eq!(chain.position_by_name("Z"), None);
    }

    #[test]
    fn insert_after_splices_in_order() {
        let mut chain = FilterChain::new();
        chain.add_filter(Box::new(PassThrough::new("A"))); // [A]
        chain
            .insert_after_index(0, Box::new(PassThrough::new("B")))
            .expect("insert after A"); // [A, B]
        chain
            .insert_after_name("A", Box::new(PassThrough::new("C")))
            .expect("insert after A"); // [A, C, B]
        assert_eq!(names(&chain), vec!["A", "C", "B"]);
        // Inserting after a missing filter is a bad argument.
        assert_eq!(
            chain
                .insert_after_name("Z", Box::new(PassThrough::new("X")))
                .unwrap_err()
                .code(),
            codes::CURLE_BAD_FUNCTION_ARGUMENT
        );
    }

    #[test]
    fn insert_after_relinks_subchain_tail() {
        // cf_new is itself a 2-filter sub-chain [N1 -> N2]; splicing it after A
        // must reattach the old tail (B) below N2: [A, N1, N2, B].
        let mut chain = FilterChain::new();
        chain.add_filter(Box::new(PassThrough::new("B")));
        chain.add_filter(Box::new(PassThrough::new("A"))); // [A, B]

        let mut sub = Box::new(PassThrough::new("N1"));
        sub.cf_state_mut().next = Some(Box::new(PassThrough::new("N2")));
        chain.insert_after_index(0, sub).expect("splice sub-chain");

        assert_eq!(names(&chain), vec!["A", "N1", "N2", "B"]);
    }

    #[test]
    fn remove_at_unlinks_single_filter() {
        let mut chain = FilterChain::new();
        chain.add_filter(Box::new(PassThrough::new("C")));
        chain.add_filter(Box::new(PassThrough::new("B")));
        chain.add_filter(Box::new(PassThrough::new("A"))); // [A, B, C]

        assert!(chain.remove_at(1)); // drop B -> [A, C]
        assert_eq!(names(&chain), vec!["A", "C"]);
        assert!(chain.remove_at(0)); // drop A -> [C]
        assert_eq!(names(&chain), vec!["C"]);
        assert!(!chain.remove_at(5)); // out of range
    }

    #[test]
    fn discard_all_empties_chain() {
        let mut chain = FilterChain::new();
        chain.add_filter(Box::new(PassThrough::new("A")));
        chain.add_filter(Box::new(PassThrough::new("B")));
        chain.discard_all();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
    }

    // ---- default pass-through return-code quirks ------------------------

    #[test]
    fn default_send_recv_quirks_no_next() {
        // Curl_cf_def_send with no next returns CURLE_RECV_ERROR; def_recv
        // returns CURLE_SEND_ERROR. These exact (counter-intuitive) codes are
        // observable and must be preserved.
        let mut leaf = PassThrough::new("leaf");
        let send_err = run(async { leaf.send(b"x", false).await }).unwrap_err();
        assert_eq!(send_err.code(), codes::CURLE_RECV_ERROR);

        let mut buf = [0u8; 4];
        let recv_err = run(async { leaf.recv(&mut buf).await }).unwrap_err();
        assert_eq!(recv_err.code(), codes::CURLE_SEND_ERROR);
    }

    #[test]
    fn default_query_no_next_is_unknown_option() {
        let leaf = PassThrough::new("leaf");
        assert_eq!(
            leaf.query(CfQuery::Socket).unwrap_err().code(),
            codes::CURLE_UNKNOWN_OPTION
        );
        // And the chain-level query on an empty chain agrees.
        let chain = FilterChain::new();
        assert_eq!(
            chain.query(CfQuery::Socket).unwrap_err().code(),
            codes::CURLE_UNKNOWN_OPTION
        );
    }

    #[test]
    fn default_is_alive_pessimistic_without_next() {
        let mut leaf = PassThrough::new("leaf");
        assert_eq!(leaf.is_alive(), (false, false));
    }

    // ---- chain drive: connect / send / recv / shutdown ------------------

    #[test]
    fn connect_default_marks_chain_connected_and_broadcasts_info_update() {
        let top_log = log();
        let leaf_log = log();
        let mut chain = FilterChain::new();
        chain.add_filter(Box::new(MockFilter::new("leaf", leaf_log.clone())));
        chain.add_filter(Box::new(MockFilter::new("top", top_log.clone())));

        let mut data = FilterData::new();
        run(chain.connect(None, &mut data)).expect("connect ok");

        // Default connect drives the sub-chain then marks each filter connected.
        assert!(chain.head_ref().expect("head").is_connected());
        assert_eq!(chain.first_connected_index(), Some(0));
        // On success the chain broadcasts CF_CTRL_CONN_INFO_UPDATE to every
        // filter (cf_cntrl_update_info).
        assert!(top_log
            .lock()
            .unwrap()
            .cntrl_events
            .contains(&(CF_CTRL_CONN_INFO_UPDATE, 0)));
        assert!(leaf_log
            .lock()
            .unwrap()
            .cntrl_events
            .contains(&(CF_CTRL_CONN_INFO_UPDATE, 0)));
    }

    #[test]
    fn connect_empty_chain_is_failed_init() {
        let mut chain = FilterChain::new();
        let mut data = FilterData::new();
        assert_eq!(
            run(chain.connect(None, &mut data)).unwrap_err().code(),
            codes::CURLE_FAILED_INIT
        );
    }

    #[test]
    fn connect_times_out() {
        // A filter whose connect never resolves; a small timeout must surface
        // CURLE_OPERATION_TIMEDOUT and record a failf message.
        struct Pending {
            state: CfState,
        }
        impl ConnectionFilter for Pending {
            fn name(&self) -> &'static str {
                "pending"
            }
            fn cf_state(&self) -> &CfState {
                &self.state
            }
            fn cf_state_mut(&mut self) -> &mut CfState {
                &mut self.state
            }
            fn connect<'a>(&'a mut self, _d: &'a mut FilterData) -> BoxFuture<'a, Result<()>> {
                Box::pin(async move {
                    std::future::pending::<()>().await;
                    Ok(())
                })
            }
        }
        let mut chain = FilterChain::from_head(Box::new(Pending {
            state: CfState::new(),
        }));
        let mut data = FilterData::with_verbose(false);
        let err = run(chain.connect(Some(30), &mut data)).unwrap_err();
        assert_eq!(err.code(), codes::CURLE_OPERATION_TIMEDOUT);
        assert!(data.error_buffer.is_some());
    }

    #[test]
    fn send_walks_to_first_connected_filter() {
        // Chain: top (NOT connected) -> leaf (connected). send must reach leaf.
        let leaf_log = log();
        let mut leaf = MockFilter::new("leaf", leaf_log.clone());
        leaf.state.connected = true;
        let mut chain = FilterChain::new();
        chain.add_filter(Box::new(leaf));
        chain.add_filter(Box::new(PassThrough::new("top"))); // top not connected

        let mut data = FilterData::new();
        let n = run(chain.send(b"hello", false, &mut data)).expect("send ok");
        assert_eq!(n, 5);
        assert_eq!(leaf_log.lock().unwrap().sent, b"hello");
    }

    #[test]
    fn recv_walks_to_first_connected_filter() {
        let leaf_log = log();
        let mut leaf = MockFilter::new("leaf", leaf_log);
        leaf.state.connected = true;
        leaf.to_recv = b"data".to_vec();
        let mut chain = FilterChain::new();
        chain.add_filter(Box::new(leaf));
        chain.add_filter(Box::new(PassThrough::new("top")));

        let mut data = FilterData::new();
        let mut buf = [0u8; 16];
        let n = run(chain.recv(&mut buf, &mut data)).expect("recv ok");
        assert_eq!(n, 4);
        assert_eq!(&buf[..4], b"data");
    }

    #[test]
    fn send_recv_no_connected_filter_is_failed_init() {
        let mut chain = FilterChain::new();
        chain.add_filter(Box::new(PassThrough::new("top"))); // not connected
        let mut data = FilterData::new();
        assert_eq!(
            run(chain.send(b"x", false, &mut data)).unwrap_err().code(),
            codes::CURLE_FAILED_INIT
        );
        let mut buf = [0u8; 4];
        assert_eq!(
            run(chain.recv(&mut buf, &mut data)).unwrap_err().code(),
            codes::CURLE_FAILED_INIT
        );
    }

    #[test]
    fn shutdown_sequences_connected_filters_and_marks_done() {
        let a_log = log();
        let b_log = log();
        let mut a = MockFilter::new("A", a_log.clone());
        a.state.connected = true;
        let mut b = MockFilter::new("B", b_log.clone());
        b.state.connected = true;

        let mut chain = FilterChain::new();
        chain.add_filter(Box::new(b)); // tail
        chain.add_filter(Box::new(a)); // middle
        chain.add_filter(Box::new(PassThrough::new("X"))); // head, NOT connected

        let mut data = FilterData::new();
        let done = run(chain.shutdown(None, &mut data)).expect("shutdown ok");
        assert!(done);
        // Only the connected filters were shut down.
        assert!(a_log.lock().unwrap().shutdown_called);
        assert!(b_log.lock().unwrap().shutdown_called);
        // All connected filters are now marked shut down -> nothing left.
        assert!(!chain.any_needs_shutdown());
    }

    #[test]
    fn shutdown_empty_chain_is_done() {
        let mut chain = FilterChain::new();
        let mut data = FilterData::new();
        assert!(run(chain.shutdown(None, &mut data)).expect("ok"));
    }

    // ---- cntrl distribution ---------------------------------------------

    #[test]
    fn cntrl_chain_visits_all_filters() {
        let a_log = log();
        let b_log = log();
        let mut chain = FilterChain::new();
        chain.add_filter(Box::new(MockFilter::new("B", b_log.clone())));
        chain.add_filter(Box::new(MockFilter::new("A", a_log.clone())));

        chain.ev_data_done(true); // ignored-result broadcast
        assert!(a_log
            .lock()
            .unwrap()
            .cntrl_events
            .contains(&(CF_CTRL_DATA_DONE, 1)));
        assert!(b_log
            .lock()
            .unwrap()
            .cntrl_events
            .contains(&(CF_CTRL_DATA_DONE, 1)));
    }

    // ---- queries ---------------------------------------------------------

    #[test]
    fn queries_delegate_and_flags_walk() {
        let leaf_log = log();
        let mut leaf = MockFilter::new("tls", leaf_log);
        leaf.flags = CF_TYPE_SSL;
        leaf.answer_socket = Some(42);
        leaf.answer_transport = Some(1);
        let mut chain = FilterChain::new();
        chain.add_filter(Box::new(leaf));
        chain.add_filter(Box::new(PassThrough::new("top"))); // delegates queries

        assert_eq!(chain.get_socket(), 42);
        assert_eq!(chain.get_transport(), Some(1));
        assert!(chain.is_ssl());
        assert!(!chain.is_multiplex());
        // No filter answers MAX_CONCURRENT -> default of 1.
        assert_eq!(chain.max_concurrent(), 1);
        // No filter answers STREAM_ERROR -> default 0.
        assert_eq!(chain.stream_error(), 0);
    }

    // ---- BufQ I/O adapters ----------------------------------------------

    #[test]
    fn recv_bufq_then_send_bufq_roundtrip() {
        run(async {
            // Read 6 bytes from a source filter into a BufQ.
            let src_log = log();
            let mut src = MockFilter::new("src", src_log);
            src.state.connected = true;
            src.to_recv = b"abcdef".to_vec();

            let mut bufq = BufQ::new(8, 4);
            let got = cf_recv_bufq(&mut src, &mut bufq, 0).await.expect("recv");
            assert_eq!(got, 6);
            assert_eq!(bufq.len(), 6);

            // Drain the BufQ to a sink filter (empty `buf` => pure pass/drain).
            let sink_log = log();
            let mut sink = MockFilter::new("sink", sink_log.clone());
            sink.state.connected = true;
            let sent = cf_send_bufq(&mut sink, &mut bufq, &[]).await.expect("send");
            assert_eq!(sent, 6);
            assert_eq!(sink_log.lock().unwrap().sent, b"abcdef");
            assert!(bufq.is_empty());
        });
    }

    #[test]
    fn recv_bufq_reports_eof() {
        run(async {
            let mut src = MockFilter::new("src", log());
            src.state.connected = true; // no to_recv => EOF
            let mut bufq = BufQ::new(8, 4);
            assert_eq!(cf_recv_bufq(&mut src, &mut bufq, 0).await.expect("recv"), 0);
        });
    }

    #[test]
    fn send_bufq_write_pass_buffers_and_drains() {
        run(async {
            let sink_log = log();
            let mut sink = MockFilter::new("sink", sink_log.clone());
            sink.state.connected = true;
            let mut bufq = BufQ::new(4, 2); // small: capacity 8

            // Write 6 bytes; they fit in the queue (capacity 8) without needing
            // a drain, so all 6 are buffered.
            let n = cf_send_bufq(&mut sink, &mut bufq, b"123456")
                .await
                .expect("write_pass");
            assert_eq!(n, 6);
            assert_eq!(bufq.len(), 6);
            // Now drain.
            let drained = cf_send_bufq(&mut sink, &mut bufq, &[])
                .await
                .expect("drain");
            assert_eq!(drained, 6);
            assert_eq!(sink_log.lock().unwrap().sent, b"123456");
        });
    }
}
