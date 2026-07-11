// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! # Connection filters — the composable transport chain
//!
//! This module is the direct, memory-safe Rust analog of curl's connection
//! filter subsystem (`lib/cfilters.c`, `lib/cfilters.h`). It defines the
//! [`ConnectionFilter`] trait (the reimplementation of curl's `struct
//! Curl_cftype` vtable) and the [`FilterChain`] container (the reimplementation
//! of curl's `cf->next` singly-linked list of `struct Curl_cfilter` instances).
//!
//! Every transport behavior in curl — the raw socket, the TLS handshake, an
//! HTTP `CONNECT` tunnel, the PROXY protocol prefix, HTTPS "eyeballing", the
//! per-connection setup step — is a *filter*. Filters are stacked so that the
//! **top** filter faces the application (protocol handlers call `send`/`recv`
//! on it) and the **bottom** filter is the socket. Data flows down the stack on
//! send and up the stack on receive, exactly like curl:
//!
//! ```text
//!   application  ──►  [ SETUP ] ─► [ HTTP-PROXY ] ─► [ SSL ] ─► [ TCP ]  ──►  network
//!    (top / head)                                                (bottom / tail)
//! ```
//!
//! ## The chain model (replacing `cf->next`)
//!
//! curl links filters with a raw `cf->next` pointer and frees nodes by hand in
//! `Curl_conn_cf_discard`. This crate is compiled under a deny-all memory-safety
//! policy (declared at the crate root), so the chain is an **owned, ordered
//! container** with no raw pointers:
//!
//! * [`FilterChain`] holds a `Vec<FilterNode>`; **index `0` is the head/top**
//!   (application-facing) and the **last element is the tail/bottom** (the
//!   socket). This preserves curl's *prepend-at-top* insertion semantics: a new
//!   filter added via [`FilterChain::add`] is inserted at index `0`, exactly as
//!   `Curl_conn_cf_add` does `cf->next = *pfilter; *pfilter = cf`.
//! * Each [`FilterNode`] wraps a `Box<dyn ConnectionFilter>` plus the two
//!   per-instance bits curl stores on `struct Curl_cfilter`: `connected` and
//!   `shutdown`.
//! * Dropping a node (via `Vec::remove`, `Vec::clear`, or the chain being
//!   dropped) replaces curl's explicit `destroy` — there is no manual free and
//!   no raw-pointer manipulation.
//!
//! ## Delegation (`cf->next`) without raw pointers
//!
//! curl filters delegate to the next filter down the stack by calling through
//! `cf->next`. Because a Rust node cannot hold a mutable reference to its
//! successor while also living inside the same `Vec`, delegation is expressed
//! by *splitting the slice*: when the driver invokes the head filter it hands
//! it a [`FilterCtx`] (for mutating operations) or a [`QueryCtx`] (for
//! read-only operations) that borrows the **remainder of the chain** (`tail`).
//! A filter that wants to delegate calls e.g. [`FilterCtx::connect_next`], which
//! splits off the next node and recurses on the shorter tail. Each recursion
//! crosses a `Box` boundary, so the async future sizes stay finite.
//!
//! Two context types mirror curl's (imperfect) const-correctness and keep the
//! borrow checker satisfied:
//!
//! * [`FilterCtx`] borrows `&mut [FilterNode]` — used by the mutating lifecycle
//!   and I/O methods (`connect`, `shutdown`, `close`, `send`, `recv`,
//!   `is_alive`, `keep_alive`, `cntrl`).
//! * [`QueryCtx`] borrows `&[FilterNode]` — used by the read-only methods
//!   (`data_pending`, `adjust_pollset`, `query`).
//!
//! ## Error-code parity (reproduced verbatim, quirks included)
//!
//! The Minimal Change Mandate forbids "fixing" curl's idiosyncrasies. The
//! no-next / no-head error codes are therefore copied exactly from
//! `lib/cfilters.c`:
//!
//! | Situation | curl function | `CURLcode` | Rust |
//! |-----------|---------------|-----------|------|
//! | `send` reaches chain end | `Curl_cf_def_send` | `CURLE_RECV_ERROR` (56) | [`Error::Recv`] |
//! | `recv` reaches chain end | `Curl_cf_def_recv` | `CURLE_SEND_ERROR` (55) | [`Error::Send`] |
//! | `query` reaches chain end | `Curl_cf_def_query` | `CURLE_UNKNOWN_OPTION` (48) | `Error::Code(UnknownOption)` |
//! | `connect` on empty chain | `Curl_conn_cf_connect` | `CURLE_FAILED_INIT` (2) | `Error::Code(FailedInit)` |
//! | `send` on empty chain | `Curl_conn_cf_send` | `CURLE_SEND_ERROR` (55) | [`Error::Send`] |
//! | `recv` on empty chain | `Curl_conn_cf_recv` | `CURLE_RECV_ERROR` (56) | [`Error::Recv`] |
//!
//! Note that the *delegate* helpers and the *driver* methods use **opposite**
//! send/recv codes — this is curl's actual behavior, not a transcription error.
//!
//! ## Filter-name convention (`--trace` parity)
//!
//! Each concrete filter reports a stable `name()` matching curl's `cft->name`
//! so `--trace`/`-v` diagnostics remain byte-identical. The canonical names the
//! concrete filter modules use are: `"TCP"`, `"UDP"`, `"UNIX"`, `"SETUP"`,
//! `"SSL"`, `"HAPROXY"`, `"HTTP-PROXY"`, `"H2-PROXY"`, `"HTTPS-CONNECT"`, and
//! `"HAPPY-EYEBALLS"`. This module provides the trace plumbing (the `"added"`,
//! connect-established, `"close"`, and `"shutdown"` lines) via `tracing`.

use std::any::Any;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Instant;

use crate::conn::{
    CfQuery, CfType, Transport, CF_CTRL_CONN_INFO_UPDATE, CF_CTRL_FLUSH, SECONDARYSOCKET,
};
use crate::error::{CurlCode, Error, Result};

/// A boxed, `Send` future returned by the asynchronous [`ConnectionFilter`]
/// methods.
///
/// `async fn` in traits is stable on our MSRV (1.75), but returning a *named,
/// boxed* future keeps the trait object-safe under recursive delegation across
/// `Box<dyn ConnectionFilter>` boundaries (an `async fn` desugars to an opaque
/// `impl Future` whose size would otherwise be infinite for a self-recursive
/// chain). The `'a` lifetime ties the future to the borrow of the filter and
/// its [`FilterCtx`].
pub type CfFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// ===========================================================================
// Pollset — mirrors curl's `struct easy_pollset`.
//
// A filter's `adjust_pollset` registers the sockets it wants the event loop to
// wait on and with which readiness events. The bit values match curl's
// `CURL_POLL_*` (include/curl/multi.h): NONE=0, IN=1, OUT=2, INOUT=3.
// ===========================================================================

/// No readiness interest (`CURL_POLL_NONE`).
pub const POLL_NONE: u8 = 0;
/// Wait for the socket to become readable (`CURL_POLL_IN`).
pub const POLL_IN: u8 = 1;
/// Wait for the socket to become writable (`CURL_POLL_OUT`).
pub const POLL_OUT: u8 = 2;
/// Wait for readable **or** writable (`CURL_POLL_INOUT`).
pub const POLL_INOUT: u8 = POLL_IN | POLL_OUT;

/// The set of `(socket, readiness-events)` a filter chain wants to wait on.
///
/// This is the safe-Rust equivalent of curl's `struct easy_pollset`, which a
/// filter fills in during [`ConnectionFilter::adjust_pollset`]. Lower (closer
/// to the socket) filters run last and can therefore override the interest a
/// higher filter registered for the same socket — the same "lower wins"
/// ordering curl uses in `Curl_conn_cf_adjust_pollset`.
#[derive(Debug, Clone, Default)]
pub struct Pollset {
    /// One entry per distinct socket, holding the merged `POLL_*` bitmask.
    entries: Vec<(i32, u8)>,
}

impl Pollset {
    /// Creates an empty poll set.
    #[must_use]
    pub fn new() -> Self {
        Pollset {
            entries: Vec::new(),
        }
    }

    /// Returns `true` if no socket is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of distinct sockets registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns the current `POLL_*` bitmask registered for `sock`
    /// (`POLL_NONE` if the socket is not present).
    #[must_use]
    pub fn events(&self, sock: i32) -> u8 {
        self.entries
            .iter()
            .find(|(s, _)| *s == sock)
            .map_or(POLL_NONE, |(_, ev)| *ev)
    }

    /// Sets the readiness interest for `sock` to exactly `events`, replacing any
    /// previous interest. Passing [`POLL_NONE`] removes the socket entirely.
    pub fn set(&mut self, sock: i32, events: u8) {
        if events == POLL_NONE {
            self.entries.retain(|(s, _)| *s != sock);
            return;
        }
        if let Some(entry) = self.entries.iter_mut().find(|(s, _)| *s == sock) {
            entry.1 = events;
        } else {
            self.entries.push((sock, events));
        }
    }

    /// Adds "readable" interest (`POLL_IN`) for `sock`, preserving any existing
    /// bits.
    pub fn add_in(&mut self, sock: i32) {
        let ev = self.events(sock) | POLL_IN;
        self.set(sock, ev);
    }

    /// Adds "writable" interest (`POLL_OUT`) for `sock`, preserving any existing
    /// bits.
    pub fn add_out(&mut self, sock: i32) {
        let ev = self.events(sock) | POLL_OUT;
        self.set(sock, ev);
    }

    /// Clears "readable" interest for `sock`; removes the socket if no interest
    /// remains.
    pub fn clear_in(&mut self, sock: i32) {
        let ev = self.events(sock) & !POLL_IN;
        self.set(sock, ev);
    }

    /// Clears "writable" interest for `sock`; removes the socket if no interest
    /// remains.
    pub fn clear_out(&mut self, sock: i32) {
        let ev = self.events(sock) & !POLL_OUT;
        self.set(sock, ev);
    }

    /// Iterates over the registered `(socket, events)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (i32, u8)> + '_ {
        self.entries.iter().copied()
    }
}

// ===========================================================================
// Query results — the typed union filled in by `ConnectionFilter::query`.
// ===========================================================================

/// The connected IP "quadruple": the remote and local address/port pair for a
/// connection, mirroring curl's `struct ip_quadruple`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpQuadruple {
    /// The remote (peer) IP address, formatted as text.
    pub remote_ip: String,
    /// The remote (peer) port.
    pub remote_port: u16,
    /// The local IP address, formatted as text.
    pub local_ip: String,
    /// The local port.
    pub local_port: u16,
}

/// The result of a [`ConnectionFilter::query`] call.
///
/// A query is an out-parameter mechanism (curl passes `void *pres1, *pres2`):
/// the caller starts with [`QueryOut::None`] and the answering filter overwrites
/// it with the variant matching the requested [`CfQuery`]. Callers then match
/// on the expected variant. A filter that does not understand the query
/// delegates to the next filter (see [`QueryCtx::query_next`]).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum QueryOut {
    /// No answer was produced (the initial value).
    None,
    /// `CF_QUERY_MAX_CONCURRENT`: maximum parallel transfers the chain expects.
    MaxConcurrent(u32),
    /// `CF_QUERY_CONNECT_REPLY_MS`: milliseconds until the first server reply.
    ConnectReplyMs(i64),
    /// `CF_QUERY_SOCKET`: the socket file descriptor used by the chain.
    Socket(i32),
    /// `CF_QUERY_TIMER_CONNECT`: the timestamp the connection was established.
    TimerConnect(Instant),
    /// `CF_QUERY_TIMER_APPCONNECT`: the timestamp the TLS handshake completed.
    TimerAppConnect(Instant),
    /// `CF_QUERY_STREAM_ERROR`: the underlying stream/protocol error code.
    StreamError(i32),
    /// `CF_QUERY_NEED_FLUSH`: whether a filter still holds unsent data.
    NeedFlush(bool),
    /// `CF_QUERY_IP_INFO`: the IPv6 flag plus the connected IP quadruple.
    IpInfo {
        /// `true` if the connection is over IPv6.
        is_ipv6: bool,
        /// The remote/local address/port quadruple.
        quad: IpQuadruple,
    },
    /// `CF_QUERY_HTTP_VERSION`: negotiated HTTP version (`10`, `11`, `20`, `30`).
    HttpVersion(u8),
    /// `CF_QUERY_REMOTE_ADDR`: the connected remote address, formatted as text.
    RemoteAddr(String),
    /// `CF_QUERY_HOST_PORT`: the remote host name and port.
    HostPort {
        /// The remote host name.
        host: String,
        /// The remote port.
        port: u16,
    },
    /// `CF_QUERY_TRANSPORT`: the `TRNSPRT_*` transport in use.
    Transport(Transport),
    /// `CF_QUERY_ALPN_NEGOTIATED`: the ALPN protocol the server selected.
    AlpnNegotiated(String),
}

// ===========================================================================
// The ConnectionFilter trait — the reimplementation of `struct Curl_cftype`.
// ===========================================================================

/// A single connection filter: one layer of transport behavior.
///
/// This is the Rust reimplementation of curl's `struct Curl_cftype` vtable. A
/// concrete filter (TCP socket, TLS, HTTP `CONNECT` tunnel, PROXY protocol,
/// Happy-Eyeballs, per-connection setup, …) implements this trait and is stored
/// in a [`FilterChain`] as a `Box<dyn ConnectionFilter>`.
///
/// # Delegation
///
/// The two required methods, [`name`](Self::name) and
/// [`cf_type`](Self::cf_type), describe the filter. Every other method has a
/// **default body that delegates to the next filter down the chain** through the
/// supplied context ([`FilterCtx`] for mutating methods, [`QueryCtx`] for
/// read-only ones), reproducing curl's `Curl_cf_def_*` behavior exactly. A
/// concrete filter overrides only the methods for which it has real work to do
/// (a socket filter overrides `connect`/`send`/`recv`; a pure setup filter
/// overrides nothing and relies on the delegating defaults).
///
/// # Object safety
///
/// The asynchronous methods return the boxed [`CfFuture`] alias rather than
/// using `async fn` sugar, so the trait remains object-safe under recursive
/// delegation across `Box<dyn ConnectionFilter>` boundaries. The trait requires
/// [`Send`] so chains can be driven on Tokio's multi-threaded runtime.
pub trait ConnectionFilter: Send {
    /// The filter's stable name, matching curl's `cft->name` (e.g. `"TCP"`,
    /// `"SSL"`, `"HTTP-PROXY"`). Used verbatim in `--trace`/`-v` output.
    fn name(&self) -> &'static str;

    /// The capability bits this filter provides (`CF_TYPE_*`), e.g.
    /// [`CfType::IP_CONNECT`] for a socket filter or [`CfType::SSL`] for TLS.
    fn cf_type(&self) -> CfType;

    /// Drives the connection handshake for this filter, returning whether the
    /// connect is `done`.
    ///
    /// Default (curl's pass-through connect): delegate to the next filter and
    /// report `done` once the remainder of the chain is connected. A filter
    /// with real handshake work (socket, TLS) overrides this.
    fn connect<'a>(
        &'a mut self,
        cx: &'a mut FilterCtx<'_>,
        blocking: bool,
    ) -> CfFuture<'a, Result<bool>> {
        cx.connect_next(blocking)
    }

    /// Performs a graceful shutdown of this filter's layer, returning whether
    /// the shutdown is `done`.
    ///
    /// Default (`Curl_cf_def_shutdown`): a filter with nothing to shut down is
    /// immediately done — `*done = TRUE; return CURLE_OK`.
    fn shutdown<'a>(&'a mut self, _cx: &'a mut FilterCtx<'_>) -> CfFuture<'a, Result<bool>> {
        Box::pin(async { Ok(true) })
    }

    /// Closes this filter's layer, releasing any resource it owns.
    ///
    /// Default (`Curl_cf_def_close`): mark this filter not-connected (handled by
    /// the chain) and delegate the close downward.
    fn close(&mut self, cx: &mut FilterCtx<'_>) {
        cx.close_next();
    }

    /// Sends up to `buf.len()` bytes down the chain, returning the number of
    /// bytes written. `eos` signals that this is the final chunk of the stream.
    ///
    /// Default (`Curl_cf_def_send`): delegate to the next filter. At the end of
    /// the chain (no next), curl returns **`CURLE_RECV_ERROR`** — reproduced
    /// verbatim as [`Error::Recv`].
    fn send<'a>(
        &'a mut self,
        cx: &'a mut FilterCtx<'_>,
        buf: &'a [u8],
        eos: bool,
    ) -> CfFuture<'a, Result<usize>> {
        cx.send_next(buf, eos)
    }

    /// Receives up to `buf.len()` bytes from the chain, returning the number of
    /// bytes read (`0` means end of stream).
    ///
    /// Default (`Curl_cf_def_recv`): delegate to the next filter. At the end of
    /// the chain (no next), curl returns **`CURLE_SEND_ERROR`** — reproduced
    /// verbatim as [`Error::Send`].
    fn recv<'a>(
        &'a mut self,
        cx: &'a mut FilterCtx<'_>,
        buf: &'a mut [u8],
    ) -> CfFuture<'a, Result<usize>> {
        cx.recv_next(buf)
    }

    /// Returns whether this filter (or one below it) has buffered data ready to
    /// be read without touching the socket.
    ///
    /// Default (`Curl_cf_def_data_pending`): delegate to the next filter;
    /// `false` at the end of the chain.
    fn data_pending(&self, cx: &QueryCtx<'_>) -> bool {
        cx.data_pending_next()
    }

    /// Registers this filter's socket-readiness interest into `ps`.
    ///
    /// Default (`Curl_cf_def_adjust_pollset`): NOP. Filters that own a socket
    /// (or that must wait to write) override this. The chain driver invokes
    /// lower filters last, so they can override higher filters' interest.
    fn adjust_pollset(&self, cx: &QueryCtx<'_>, ps: &mut Pollset) {
        let _ = (cx, ps);
    }

    /// Returns whether the connection is still alive (usable for reuse).
    ///
    /// Default (`Curl_cf_def_conn_is_alive`): delegate to the next filter;
    /// `false` (pessimistic) at the end of the chain.
    fn is_alive(&mut self, cx: &mut FilterCtx<'_>) -> bool {
        cx.is_alive_next()
    }

    /// Performs any periodic keep-alive work for this filter's layer.
    ///
    /// Default (`Curl_cf_def_conn_keep_alive`): delegate to the next filter;
    /// `Ok(())` at the end of the chain.
    fn keep_alive(&mut self, cx: &mut FilterCtx<'_>) -> Result<()> {
        cx.keep_alive_next()
    }

    /// Handles a control event (`CF_CTRL_*`) targeted at this filter.
    ///
    /// Per curl's contract, a `cntrl` implementation **must not** chain the call
    /// to `cf->next`; the chain-level [`FilterChain::cntrl`] driver iterates
    /// every filter. `arg2` is an optional type-erased payload (curl's
    /// `void *arg2`).
    ///
    /// Default (`Curl_cf_def_cntrl`): NOP, returns `Ok(())`.
    fn cntrl(
        &mut self,
        cx: &mut FilterCtx<'_>,
        event: i32,
        arg1: i32,
        arg2: Option<&mut dyn Any>,
    ) -> Result<()> {
        let _ = (cx, event, arg1, arg2);
        Ok(())
    }

    /// Answers a property [`CfQuery`] about the connection, writing the result
    /// into `out`.
    ///
    /// Default (`Curl_cf_def_query`): delegate to the next filter. At the end of
    /// the chain (no next), curl returns **`CURLE_UNKNOWN_OPTION`**.
    fn query(&self, cx: &QueryCtx<'_>, query: CfQuery, out: &mut QueryOut) -> Result<()> {
        cx.query_next(query, out)
    }
}

// ===========================================================================
// FilterNode — one filter plus its per-instance state bits.
// ===========================================================================

/// One element of a [`FilterChain`]: an owned filter together with the two
/// per-instance state bits curl keeps on `struct Curl_cfilter` (`connected` and
/// `shutdown`).
///
/// The filter is owned as a `Box<dyn ConnectionFilter>`; dropping the node
/// drops the filter, which is the safe-Rust replacement for curl's explicit
/// `destroy` callback.
pub struct FilterNode {
    filter: Box<dyn ConnectionFilter>,
    connected: bool,
    shutdown: bool,
}

impl FilterNode {
    /// Wraps a freshly created filter (not yet connected, not yet shut down).
    fn new(filter: Box<dyn ConnectionFilter>) -> Self {
        FilterNode {
            filter,
            connected: false,
            shutdown: false,
        }
    }

    /// The wrapped filter's name (see [`ConnectionFilter::name`]).
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.filter.name()
    }

    /// The wrapped filter's capability bits (see [`ConnectionFilter::cf_type`]).
    #[must_use]
    pub fn cf_type(&self) -> CfType {
        self.filter.cf_type()
    }

    /// Whether this filter has completed its connect handshake.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Whether this filter has completed its graceful shutdown.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.shutdown
    }
}

impl fmt::Debug for FilterNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FilterNode")
            .field("name", &self.filter.name())
            .field("connected", &self.connected)
            .field("shutdown", &self.shutdown)
            .finish()
    }
}

// ===========================================================================
// FilterCtx — the mutating per-call context (replaces `(cf, data)` for the
// mutating vtable methods). Borrows the remainder of the chain (`tail`) so a
// filter can delegate to the next filter down with no raw pointers.
// ===========================================================================

/// The context handed to a filter's **mutating** methods (`connect`,
/// `shutdown`, `close`, `send`, `recv`, `is_alive`, `keep_alive`, `cntrl`).
///
/// It replaces curl's `(struct Curl_cfilter *cf, struct Curl_easy *data)`
/// argument pair. Instead of exposing `cf->next` as a raw pointer, it borrows
/// the remainder of the chain below the current filter and offers `*_next`
/// helpers that split off the next node and recurse on the shorter tail — safe
/// delegation with no aliasing and no manual memory management.
pub struct FilterCtx<'c> {
    /// The filters *below* the current one (index 0 is the immediate next).
    tail: &'c mut [FilterNode],
    /// The socket index this chain serves (`FIRSTSOCKET`/`SECONDARYSOCKET`).
    sockindex: usize,
}

impl<'c> FilterCtx<'c> {
    /// Builds a context over `tail` for the given socket index.
    fn new(tail: &'c mut [FilterNode], sockindex: usize) -> Self {
        FilterCtx { tail, sockindex }
    }

    /// The socket index this chain serves.
    #[must_use]
    pub fn sockindex(&self) -> usize {
        self.sockindex
    }

    /// Whether there is another filter below the current one.
    #[must_use]
    pub fn has_next(&self) -> bool {
        !self.tail.is_empty()
    }

    /// Delegates `connect` to the next filter (curl's `cf->next` connect).
    ///
    /// Returns `Ok(true)` when there is no next filter (a pure pass-through has
    /// nothing to connect below it). When a lower filter reports `done`, its
    /// `connected` bit is set, exactly as curl marks `cf->connected`.
    pub fn connect_next(&mut self, blocking: bool) -> CfFuture<'_, Result<bool>> {
        Box::pin(async move {
            match self.tail.split_first_mut() {
                Some((next, rest)) => {
                    let mut inner = FilterCtx::new(rest, self.sockindex);
                    let done = next.filter.connect(&mut inner, blocking).await?;
                    if done {
                        next.connected = true;
                    }
                    Ok(done)
                }
                None => Ok(true),
            }
        })
    }

    /// Delegates `send` to the next filter.
    ///
    /// At the end of the chain curl's `Curl_cf_def_send` returns
    /// `CURLE_RECV_ERROR` — reproduced verbatim as [`Error::Recv`].
    pub fn send_next<'a>(&'a mut self, buf: &'a [u8], eos: bool) -> CfFuture<'a, Result<usize>> {
        Box::pin(async move {
            match self.tail.split_first_mut() {
                Some((next, rest)) => {
                    let mut inner = FilterCtx::new(rest, self.sockindex);
                    next.filter.send(&mut inner, buf, eos).await
                }
                None => Err(Error::Recv),
            }
        })
    }

    /// Delegates `recv` to the next filter.
    ///
    /// At the end of the chain curl's `Curl_cf_def_recv` returns
    /// `CURLE_SEND_ERROR` — reproduced verbatim as [`Error::Send`].
    pub fn recv_next<'a>(&'a mut self, buf: &'a mut [u8]) -> CfFuture<'a, Result<usize>> {
        Box::pin(async move {
            match self.tail.split_first_mut() {
                Some((next, rest)) => {
                    let mut inner = FilterCtx::new(rest, self.sockindex);
                    next.filter.recv(&mut inner, buf).await
                }
                None => Err(Error::Send),
            }
        })
    }

    /// Delegates `close` to the next filter, clearing its `connected` bit
    /// (curl's `Curl_cf_def_close` sets `cf->connected = FALSE`).
    pub fn close_next(&mut self) {
        if let Some((next, rest)) = self.tail.split_first_mut() {
            let mut inner = FilterCtx::new(rest, self.sockindex);
            next.filter.close(&mut inner);
            next.connected = false;
        }
    }

    /// Delegates `is_alive` to the next filter; `false` (pessimistic) at the end
    /// of the chain (`Curl_cf_def_conn_is_alive`).
    pub fn is_alive_next(&mut self) -> bool {
        match self.tail.split_first_mut() {
            Some((next, rest)) => {
                let mut inner = FilterCtx::new(rest, self.sockindex);
                next.filter.is_alive(&mut inner)
            }
            None => false,
        }
    }

    /// Delegates `keep_alive` to the next filter; `Ok(())` at the end of the
    /// chain (`Curl_cf_def_conn_keep_alive`).
    pub fn keep_alive_next(&mut self) -> Result<()> {
        match self.tail.split_first_mut() {
            Some((next, rest)) => {
                let mut inner = FilterCtx::new(rest, self.sockindex);
                next.filter.keep_alive(&mut inner)
            }
            None => Ok(()),
        }
    }

    /// Delegates a **read-only** [`query`](ConnectionFilter::query) to the next
    /// filter *without relinquishing the mutable borrow of the chain tail*.
    ///
    /// The mutating lifecycle methods — `connect` in particular — occasionally
    /// need to read a property of the layer directly below them. curl does
    /// exactly this in `cf_haproxy_date_out_set`, which calls
    /// `Curl_conn_cf_get_ip_info(cf->next, …)` from *inside* the HAProxy
    /// filter's connect handshake to learn the local/remote address it must
    /// stamp into the PROXY-protocol header. Those methods receive a
    /// [`FilterCtx`] (holding `&mut [FilterNode]`) rather than a [`QueryCtx`],
    /// so this helper reborrows the tail **immutably** and dispatches the query,
    /// mirroring [`QueryCtx::query_next`] byte-for-byte.
    ///
    /// At the end of the chain curl's `Curl_cf_def_query` returns
    /// `CURLE_UNKNOWN_OPTION` — reproduced verbatim.
    pub fn query_next(&self, query: CfQuery, out: &mut QueryOut) -> Result<()> {
        match self.tail.split_first() {
            Some((next, rest)) => {
                let inner = QueryCtx::new(rest, self.sockindex);
                next.filter.query(&inner, query, out)
            }
            None => Err(Error::Code(CurlCode::UnknownOption)),
        }
    }
}

// ===========================================================================
// QueryCtx — the read-only per-call context (for `data_pending`,
// `adjust_pollset`, `query`). Borrows the remainder of the chain immutably.
// ===========================================================================

/// The context handed to a filter's **read-only** methods (`data_pending`,
/// `adjust_pollset`, `query`).
///
/// It borrows the remainder of the chain immutably, mirroring the fact that
/// these queries never mutate chain state. Delegation splits the immutable tail
/// and recurses, just like [`FilterCtx`] does for the mutating methods.
pub struct QueryCtx<'c> {
    /// The filters *below* the current one (index 0 is the immediate next).
    tail: &'c [FilterNode],
    /// The socket index this chain serves (`FIRSTSOCKET`/`SECONDARYSOCKET`).
    sockindex: usize,
}

impl<'c> QueryCtx<'c> {
    /// Builds a read-only context over `tail` for the given socket index.
    fn new(tail: &'c [FilterNode], sockindex: usize) -> Self {
        QueryCtx { tail, sockindex }
    }

    /// The socket index this chain serves.
    #[must_use]
    pub fn sockindex(&self) -> usize {
        self.sockindex
    }

    /// Whether there is another filter below the current one.
    #[must_use]
    pub fn has_next(&self) -> bool {
        !self.tail.is_empty()
    }

    /// Delegates `data_pending` to the next filter; `false` at the end of the
    /// chain (`Curl_cf_def_data_pending`).
    #[must_use]
    pub fn data_pending_next(&self) -> bool {
        match self.tail.split_first() {
            Some((next, rest)) => {
                let inner = QueryCtx::new(rest, self.sockindex);
                next.filter.data_pending(&inner)
            }
            None => false,
        }
    }

    /// Delegates `query` to the next filter.
    ///
    /// At the end of the chain curl's `Curl_cf_def_query` returns
    /// `CURLE_UNKNOWN_OPTION` — reproduced verbatim.
    pub fn query_next(&self, query: CfQuery, out: &mut QueryOut) -> Result<()> {
        match self.tail.split_first() {
            Some((next, rest)) => {
                let inner = QueryCtx::new(rest, self.sockindex);
                next.filter.query(&inner, query, out)
            }
            None => Err(Error::Code(CurlCode::UnknownOption)),
        }
    }
}

// ===========================================================================
// FilterChain — the owned, ordered container that replaces curl's `cf->next`
// singly-linked list of `struct Curl_cfilter`.
// ===========================================================================

/// An ordered stack of connection filters for one socket.
///
/// This is the safe-Rust reimplementation of curl's per-socket
/// `conn->cfilter[sockindex]` linked list. **Index `0` is the head/top**
/// (application-facing); the **last element is the tail/bottom** (the socket).
/// Filters are added *prepend-at-top* (see [`add`](Self::add)), preserving
/// curl's `Curl_conn_cf_add` insertion order.
///
/// The chain drives `connect`/`send`/`recv`/`shutdown` by handing the head
/// filter a [`FilterCtx`] that borrows the remainder of the chain, so filters
/// delegate downward without any raw pointers or manual freeing.
pub struct FilterChain {
    /// Head at index `0`, socket/tail at the last index.
    filters: Vec<FilterNode>,
    /// The socket index this chain serves (`FIRSTSOCKET`/`SECONDARYSOCKET`).
    sockindex: usize,
}

impl fmt::Debug for FilterChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FilterChain")
            .field("sockindex", &self.sockindex)
            .field("filters", &self.filters)
            .finish()
    }
}

impl FilterChain {
    // -- Construction and structural mutation ------------------------------

    /// Creates an empty chain for the given socket index
    /// (`FIRSTSOCKET` or `SECONDARYSOCKET`).
    #[must_use]
    pub fn new(sockindex: usize) -> Self {
        FilterChain {
            filters: Vec::new(),
            sockindex,
        }
    }

    /// The socket index this chain serves.
    #[must_use]
    pub fn sockindex(&self) -> usize {
        self.sockindex
    }

    /// Returns `true` if the chain has no filters.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }

    /// Returns the number of filters in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.filters.len()
    }

    /// Borrows the head (top, application-facing) filter, if any.
    #[must_use]
    pub fn head(&self) -> Option<&dyn ConnectionFilter> {
        self.filters.first().map(|n| n.filter.as_ref())
    }

    /// Borrows the tail (bottom, socket) filter, if any.
    #[must_use]
    pub fn tail(&self) -> Option<&dyn ConnectionFilter> {
        self.filters.last().map(|n| n.filter.as_ref())
    }

    /// Returns the filter names top-to-bottom (head first).
    ///
    /// This exposes the assembled chain order for `--trace` order-parity
    /// assertions (the connection-setup layer must build the chain in curl's
    /// exact `cf_setup_connect` insertion order). It is the public counterpart
    /// of the internal `filters[i].name()` inspection.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.filters.iter().map(FilterNode::name).collect()
    }

    /// Returns each filter's capability bits top-to-bottom (head first),
    /// paired with its name, for order/-type parity assertions.
    #[must_use]
    pub fn layout(&self) -> Vec<(&'static str, CfType)> {
        self.filters
            .iter()
            .map(|n| (n.name(), n.filter.cf_type()))
            .collect()
    }

    /// Adds a filter at the **top** of the chain (index `0`).
    ///
    /// This mirrors curl's `Curl_conn_cf_add`, which prepends: `cf->next =
    /// *pfilter; *pfilter = cf`. Emits the `"added"` trace line curl produces
    /// via `CURL_TRC_CF`.
    pub fn add(&mut self, filter: Box<dyn ConnectionFilter>) {
        let name = filter.name();
        self.filters.insert(0, FilterNode::new(filter));
        tracing::trace!(target: "curl::cf", sockindex = self.sockindex, filter = name, "added");
    }

    /// Inserts a filter directly **below** the filter at `at_index`, mirroring
    /// curl's `Curl_conn_cf_insert_after`.
    ///
    /// The new filter takes position `at_index + 1`, pushing the previous tail
    /// downward. Returns [`Error::BadFunctionArgument`] if `at_index` is out of
    /// range (there is no filter to insert after).
    ///
    /// A single [`ConnectionFilter`] is one node; to splice a multi-filter
    /// sub-chain, call this repeatedly for each node in bottom-up order.
    pub fn insert_after(
        &mut self,
        at_index: usize,
        filter: Box<dyn ConnectionFilter>,
    ) -> Result<()> {
        if at_index >= self.filters.len() {
            return Err(Error::bad_argument(format!(
                "insert_after: index {at_index} is out of range (len {})",
                self.filters.len()
            )));
        }
        let name = filter.name();
        self.filters.insert(at_index + 1, FilterNode::new(filter));
        tracing::trace!(
            target: "curl::cf",
            sockindex = self.sockindex,
            filter = name,
            at = at_index,
            "inserted after"
        );
        Ok(())
    }

    /// Removes and drops the filter at `index`, returning whether a filter was
    /// present there.
    ///
    /// Dropping the [`FilterNode`] runs the filter's `Drop`, which is the
    /// safe-Rust replacement for curl's explicit `destroy` in
    /// `Curl_conn_cf_discard`.
    pub fn discard(&mut self, index: usize) -> bool {
        if index < self.filters.len() {
            drop(self.filters.remove(index));
            tracing::trace!(target: "curl::cf", sockindex = self.sockindex, index, "discarded");
            true
        } else {
            false
        }
    }

    /// Removes and drops **all** filters (curl's `Curl_conn_cf_discard_all`).
    pub fn discard_all(&mut self) {
        self.filters.clear();
        tracing::trace!(target: "curl::cf", sockindex = self.sockindex, "discarded all");
    }
}

impl FilterChain {
    // -- High-level drivers (mirror `Curl_conn_cf_*`) ----------------------

    /// Drives the connection handshake on the head filter, returning whether the
    /// whole chain is connected (`Curl_conn_cf_connect`).
    ///
    /// Returns [`CurlCode::FailedInit`] on an empty chain (curl returns
    /// `CURLE_FAILED_INIT` when the head filter pointer is `NULL`). Once the
    /// head reports `done`, its `connected` bit is set and the established-
    /// connection trace is emitted.
    pub async fn connect(&mut self, blocking: bool) -> Result<bool> {
        let sockindex = self.sockindex;
        let done = match self.filters.split_first_mut() {
            Some((head, tail)) => {
                if head.connected {
                    // Already connected — nothing more to do (matches curl's
                    // early `*done = cf->connected` short-circuit).
                    return Ok(true);
                }
                let mut cx = FilterCtx::new(tail, sockindex);
                let done = head.filter.connect(&mut cx, blocking).await?;
                if done {
                    head.connected = true;
                }
                done
            }
            None => return Err(Error::Code(CurlCode::FailedInit)),
        };
        if done {
            self.trace_established();
        }
        Ok(done)
    }

    /// Gracefully shuts the chain down, returning whether the shutdown is `done`
    /// (`Curl_conn_shutdown`).
    ///
    /// Shuts down each connected, not-yet-shut-down filter top-down. If a filter
    /// reports "not done", returns `Ok(false)` so the caller retries later
    /// (curl returns `CURLE_OK` with `*done = FALSE`). Returns `Ok(true)` once
    /// every filter has shut down (or there was nothing connected to shut down).
    ///
    /// `timeout_ms` is the caller's shutdown budget; the authoritative deadline
    /// is owned by the connection layer (curl's `Curl_shutdown_*` state lives on
    /// the easy handle, not the filter), so it is threaded here for `--trace`
    /// parity rather than enforced within the chain.
    pub async fn shutdown(&mut self, timeout_ms: u64) -> Result<bool> {
        let sockindex = self.sockindex;
        tracing::trace!(target: "curl::cf", sockindex, timeout_ms, "shutdown");
        // Find the first connected, not-yet-shut-down filter.
        let start = self.filters.iter().position(|n| n.connected && !n.shutdown);
        let mut i = match start {
            Some(i) => i,
            None => return Ok(true),
        };
        while i < self.filters.len() {
            if !self.filters[i].shutdown {
                if let Some((node, tail)) = self.filters[i..].split_first_mut() {
                    let mut cx = FilterCtx::new(tail, sockindex);
                    let done = node.filter.shutdown(&mut cx).await?;
                    if !done {
                        return Ok(false);
                    }
                    node.shutdown = true;
                }
            }
            i += 1;
        }
        Ok(true)
    }

    /// Closes the chain, delegating `close` down from the head and clearing every
    /// filter's `connected`/`shutdown` bits (`Curl_conn_cf_close`).
    pub fn close(&mut self) {
        let sockindex = self.sockindex;
        if let Some((head, tail)) = self.filters.split_first_mut() {
            let mut cx = FilterCtx::new(tail, sockindex);
            head.filter.close(&mut cx);
        }
        for node in &mut self.filters {
            node.connected = false;
            node.shutdown = false;
        }
        tracing::trace!(target: "curl::cf", sockindex, "close");
    }

    /// Sends `buf` down the chain from the head, returning bytes written
    /// (`Curl_conn_cf_send`).
    ///
    /// On an empty chain curl returns `CURLE_SEND_ERROR` — reproduced as
    /// [`Error::Send`]. (Note this differs from the *delegate* default
    /// [`FilterCtx::send_next`], which returns `CURLE_RECV_ERROR` — the two
    /// asymmetric codes are curl's actual behavior.)
    pub async fn send(&mut self, buf: &[u8], eos: bool) -> Result<usize> {
        let sockindex = self.sockindex;
        match self.filters.split_first_mut() {
            Some((head, tail)) => {
                let mut cx = FilterCtx::new(tail, sockindex);
                head.filter.send(&mut cx, buf, eos).await
            }
            None => Err(Error::Send),
        }
    }

    /// Receives from the chain into `buf`, returning bytes read (`0` = EOF)
    /// (`Curl_conn_cf_recv`).
    ///
    /// On an empty chain curl returns `CURLE_RECV_ERROR` — reproduced as
    /// [`Error::Recv`]. (This differs from the *delegate* default
    /// [`FilterCtx::recv_next`], which returns `CURLE_SEND_ERROR`.)
    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let sockindex = self.sockindex;
        match self.filters.split_first_mut() {
            Some((head, tail)) => {
                let mut cx = FilterCtx::new(tail, sockindex);
                head.filter.recv(&mut cx, buf).await
            }
            None => Err(Error::Recv),
        }
    }

    /// Flushes any buffered outbound data by sending the `CF_CTRL_FLUSH` control
    /// event down the chain first-fail (`Curl_conn_flush`).
    pub async fn flush(&mut self) -> Result<()> {
        self.cntrl(CF_CTRL_FLUSH as i32, 0, None)
    }

    /// Whether the connection is still alive/usable for reuse
    /// (`Curl_conn_is_alive`). Delegates to the head filter; `false` on an empty
    /// chain (pessimistic, matching curl's default).
    pub fn is_alive(&mut self) -> bool {
        let sockindex = self.sockindex;
        match self.filters.split_first_mut() {
            Some((head, tail)) => {
                let mut cx = FilterCtx::new(tail, sockindex);
                head.filter.is_alive(&mut cx)
            }
            None => false,
        }
    }

    /// Performs any periodic keep-alive work down the chain
    /// (`Curl_conn_keep_alive`); `Ok(())` on an empty chain.
    pub fn keep_alive(&mut self) -> Result<()> {
        let sockindex = self.sockindex;
        match self.filters.split_first_mut() {
            Some((head, tail)) => {
                let mut cx = FilterCtx::new(tail, sockindex);
                head.filter.keep_alive(&mut cx)
            }
            None => Ok(()),
        }
    }

    /// Sends a control event down the chain **first-fail** (returns the first
    /// error encountered), mirroring `Curl_conn_cf_cntrl` with
    /// `ignore_result = FALSE`.
    pub fn cntrl(&mut self, event: i32, arg1: i32, arg2: Option<&mut dyn Any>) -> Result<()> {
        self.cntrl_iter(event, arg1, arg2, false)
    }

    /// Sends a control event to **every** filter in the chain, ignoring
    /// per-filter errors (returns the first error seen but does not stop). This
    /// is the per-chain analog of curl's `cf_cntrl_all`
    /// (`ignore_result = TRUE`); the connection layer applies it across both
    /// sockets.
    pub fn cntrl_all(&mut self, event: i32, arg1: i32, arg2: Option<&mut dyn Any>) -> Result<()> {
        self.cntrl_iter(event, arg1, arg2, true)
    }

    /// Broadcasts `CF_CTRL_CONN_INFO_UPDATE` down the chain so filters persist
    /// their connection info (`cf_cntrl_update_info`).
    pub fn cntrl_update_info(&mut self) -> Result<()> {
        self.cntrl_all(CF_CTRL_CONN_INFO_UPDATE as i32, 0, None)
    }

    /// Shared control-event iteration.
    ///
    /// Iterates the chain from the head. For `ignore_result == false`, returns
    /// the first error immediately (first-fail). For `ignore_result == true`,
    /// visits every filter and returns the first error observed without
    /// stopping. A no-op default `cntrl` (returning `Ok(())`) never clobbers a
    /// recorded error, which reproduces curl's "skip default-cntrl filters"
    /// intent without relying on function-pointer identity.
    fn cntrl_iter(
        &mut self,
        event: i32,
        arg1: i32,
        mut arg2: Option<&mut dyn Any>,
        ignore_result: bool,
    ) -> Result<()> {
        let sockindex = self.sockindex;
        let mut first_err: Result<()> = Ok(());
        let mut i = 0;
        while i < self.filters.len() {
            if let Some((node, tail)) = self.filters[i..].split_first_mut() {
                let mut cx = FilterCtx::new(tail, sockindex);
                if let Err(e) = node.filter.cntrl(&mut cx, event, arg1, arg2.as_deref_mut()) {
                    if !ignore_result {
                        return Err(e);
                    }
                    if first_err.is_ok() {
                        first_err = Err(e);
                    }
                }
            }
            i += 1;
        }
        first_err
    }

    /// Registers the chain's socket-readiness interest into `ps`
    /// (`Curl_conn_cf_adjust_pollset`).
    ///
    /// Starts at the lowest not-connected filter, skips filters that have shut
    /// down, then gives every remaining filter a chance to adjust the poll set;
    /// lower (closer to the socket) filters run last and can override the
    /// interest a higher filter registered.
    pub fn adjust_pollset(&self, ps: &mut Pollset) {
        let sockindex = self.sockindex;
        let n = self.filters.len();
        // Lowest not-connected filter: advance while this and the next are both
        // not connected (curl: `!cf->connected && cf->next && !cf->next->connected`).
        let mut i = 0;
        while i + 1 < n && !self.filters[i].connected && !self.filters[i + 1].connected {
            i += 1;
        }
        // Skip filters that have completed shutdown.
        while i < n && self.filters[i].shutdown {
            i += 1;
        }
        // Give each remaining filter a chance to adjust the poll set.
        while i < n {
            if let Some((node, tail)) = self.filters[i..].split_first() {
                let qctx = QueryCtx::new(tail, sockindex);
                node.filter.adjust_pollset(&qctx, ps);
            }
            i += 1;
        }
    }
}

impl FilterChain {
    // -- Capability predicates and property queries ------------------------

    /// Whether the head filter reports it is connected
    /// (`Curl_conn_is_connected`).
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.filters.first().is_some_and(|n| n.connected)
    }

    /// Whether an IP-level connection has been established
    /// (`Curl_conn_is_ip_connected`).
    ///
    /// Walks down the chain: the first `connected` filter means yes; reaching an
    /// [`CfType::IP_CONNECT`] filter that is not yet connected means no.
    #[must_use]
    pub fn is_ip_connected(&self) -> bool {
        for n in &self.filters {
            if n.connected {
                return true;
            }
            if n.filter.cf_type().contains(CfType::IP_CONNECT) {
                return false;
            }
        }
        false
    }

    /// Whether the connection is secured by TLS (`Curl_conn_is_ssl` /
    /// `cf_is_ssl`).
    ///
    /// Walks down the chain: an [`CfType::SSL`] filter means yes; reaching an
    /// [`CfType::IP_CONNECT`] filter first means no (the SSL filter, if any,
    /// always sits above the socket).
    #[must_use]
    pub fn is_ssl(&self) -> bool {
        for n in &self.filters {
            let t = n.filter.cf_type();
            if t.contains(CfType::SSL) {
                return true;
            }
            if t.contains(CfType::IP_CONNECT) {
                return false;
            }
        }
        false
    }

    /// Whether the connection multiplexes transfers (HTTP/2, HTTP/3)
    /// (`Curl_conn_is_multiplex`).
    ///
    /// Walks down the chain: an [`CfType::MULTIPLEX`] filter means yes; reaching
    /// an IP-connect or SSL filter first means no.
    #[must_use]
    pub fn is_multiplex(&self) -> bool {
        for n in &self.filters {
            let t = n.filter.cf_type();
            if t.contains(CfType::MULTIPLEX) {
                return true;
            }
            if t.intersects(CfType::IP_CONNECT | CfType::SSL) {
                return false;
            }
        }
        false
    }

    /// Whether the chain has buffered data ready to read without touching the
    /// socket (`Curl_conn_data_pending`).
    ///
    /// Skips leading not-connected filters, then asks the first connected filter
    /// (which delegates further down as needed).
    #[must_use]
    pub fn data_pending(&self) -> bool {
        let sockindex = self.sockindex;
        match self.filters.iter().position(|n| n.connected) {
            Some(i) => match self.filters[i..].split_first() {
                Some((node, tail)) => {
                    let qctx = QueryCtx::new(tail, sockindex);
                    node.filter.data_pending(&qctx)
                }
                None => false,
            },
            None => false,
        }
    }

    /// Whether any filter still holds unsent outbound data
    /// (`CF_QUERY_NEED_FLUSH`). `false` unless a filter positively reports a
    /// pending flush.
    #[must_use]
    pub fn needs_flush(&self) -> bool {
        matches!(
            self.query_head(CfQuery::NeedFlush),
            Ok(QueryOut::NeedFlush(true))
        )
    }

    /// The socket file descriptor used by the chain, if any
    /// (`Curl_conn_cf_get_socket`).
    #[must_use]
    pub fn socket(&self) -> Option<i32> {
        match self.query_head(CfQuery::Socket) {
            Ok(QueryOut::Socket(fd)) => Some(fd),
            _ => None,
        }
    }

    /// The transport the chain reports via `CF_QUERY_TRANSPORT`, if any
    /// (`Curl_conn_cf_get_transport`). Returns `None` when no filter answers, so
    /// the caller can fall back to the connection's wanted transport.
    #[must_use]
    pub fn transport(&self) -> Option<Transport> {
        match self.query_head(CfQuery::Transport) {
            Ok(QueryOut::Transport(t)) => Some(t),
            _ => None,
        }
    }

    /// The negotiated HTTP version as a curl-style integer (`10`, `11`, `20`,
    /// `30`), or `0` if unknown (`Curl_conn_http_version`).
    ///
    /// Walks the chain looking for the [`CfType::HTTP`] filter and queries it;
    /// stops early if an IP-connect or SSL layer is reached first.
    #[must_use]
    pub fn http_version(&self) -> u8 {
        let sockindex = self.sockindex;
        for (i, node) in self.filters.iter().enumerate() {
            let t = node.filter.cf_type();
            if t.contains(CfType::HTTP) {
                if let Some((h, tail)) = self.filters[i..].split_first() {
                    let qctx = QueryCtx::new(tail, sockindex);
                    let mut out = QueryOut::None;
                    if h.filter
                        .query(&qctx, CfQuery::HttpVersion, &mut out)
                        .is_ok()
                    {
                        if let QueryOut::HttpVersion(v) = out {
                            return v;
                        }
                    }
                }
                return 0;
            }
            if t.intersects(CfType::IP_CONNECT | CfType::SSL) {
                break;
            }
        }
        0
    }

    /// The ALPN protocol the server selected, if any
    /// (`Curl_conn_cf_get_alpn_negotiated`).
    #[must_use]
    pub fn alpn_negotiated(&self) -> Option<String> {
        match self.query_head(CfQuery::AlpnNegotiated) {
            Ok(QueryOut::AlpnNegotiated(s)) => Some(s),
            _ => None,
        }
    }

    /// The maximum number of concurrent transfers the chain expects, defaulting
    /// to `1` when unknown (`Curl_conn_get_max_concurrent`).
    #[must_use]
    pub fn max_concurrent(&self) -> usize {
        match self.query_head(CfQuery::MaxConcurrent) {
            Ok(QueryOut::MaxConcurrent(n)) => n as usize,
            _ => 1,
        }
    }

    /// The underlying stream/protocol error code, defaulting to `0` when unknown
    /// (`Curl_conn_get_stream_error`).
    #[must_use]
    pub fn stream_error(&self) -> i32 {
        match self.query_head(CfQuery::StreamError) {
            Ok(QueryOut::StreamError(n)) if n >= 0 => n,
            _ => 0,
        }
    }

    /// Answers a property [`CfQuery`] by asking the head filter (which delegates
    /// down the chain as needed), writing the result into `out`.
    ///
    /// Returns [`CurlCode::UnknownOption`] on an empty chain or when no filter
    /// answers, matching curl's `Curl_cf_def_query` terminal behavior.
    pub fn query(&self, query: CfQuery, out: &mut QueryOut) -> Result<()> {
        let sockindex = self.sockindex;
        match self.filters.split_first() {
            Some((head, tail)) => {
                let qctx = QueryCtx::new(tail, sockindex);
                head.filter.query(&qctx, query, out)
            }
            None => Err(Error::Code(CurlCode::UnknownOption)),
        }
    }

    /// Convenience wrapper: run [`query`](Self::query) and return the filled-in
    /// [`QueryOut`].
    fn query_head(&self, query: CfQuery) -> Result<QueryOut> {
        let mut out = QueryOut::None;
        self.query(query, &mut out)?;
        Ok(out)
    }

    // -- `--trace` diagnostics --------------------------------------------

    /// Formats curl's verbose "Established … connection …" line verbatim.
    ///
    /// Reproduces `cf_verboseconnect`'s exact wording, including the `"2nd "`
    /// prefix used for the [`SECONDARYSOCKET`] connection:
    ///
    /// ```text
    /// Established connection to example.com (93.184.216.34 port 443) from 10.0.0.2 port 51000
    /// Established 2nd connection to example.com (…) from … port …
    /// ```
    ///
    /// The trailing space is part of curl's format string and is preserved.
    #[must_use]
    pub fn format_established_connection(
        sockindex: usize,
        host: &str,
        remote_ip: &str,
        remote_port: u16,
        local_ip: &str,
        local_port: u16,
    ) -> String {
        let prefix = if sockindex == SECONDARYSOCKET {
            "2nd "
        } else {
            ""
        };
        format!(
            "Established {prefix}connection to {host} ({remote_ip} port {remote_port}) \
             from {local_ip} port {local_port} "
        )
    }

    /// Emits the established-connection trace on a successful connect.
    ///
    /// Best-effort: if the socket filter answers `CF_QUERY_IP_INFO` (and
    /// optionally `CF_QUERY_HOST_PORT`), the full curl-style line is logged;
    /// otherwise a simpler "chain connected" trace is emitted (as happens when
    /// no socket filter is present, e.g. in unit tests).
    fn trace_established(&self) {
        let host = match self.query_head(CfQuery::HostPort) {
            Ok(QueryOut::HostPort { host, .. }) => Some(host),
            _ => None,
        };
        match self.query_head(CfQuery::IpInfo) {
            Ok(QueryOut::IpInfo { quad, .. }) => {
                let host = host.unwrap_or_else(|| quad.remote_ip.clone());
                let msg = Self::format_established_connection(
                    self.sockindex,
                    &host,
                    &quad.remote_ip,
                    quad.remote_port,
                    &quad.local_ip,
                    quad.local_port,
                );
                tracing::debug!(target: "curl::cf", sockindex = self.sockindex, "{msg}");
            }
            _ => {
                tracing::trace!(
                    target: "curl::cf",
                    sockindex = self.sockindex,
                    "connect: chain connected"
                );
            }
        }
    }
}

// ===========================================================================
// Unit tests — a chain of mock filters exercising the trait defaults, the
// chain drivers, prepend/insert ordering, the exact no-next / no-head error
// codes, the capability queries, and the established-connection trace string.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::FIRSTSOCKET;

    /// A pure pass-through filter (curl's `SETUP` filter): overrides nothing,
    /// so every method exercises the trait's delegating defaults.
    struct PassThrough;

    impl ConnectionFilter for PassThrough {
        fn name(&self) -> &'static str {
            "SETUP"
        }
        fn cf_type(&self) -> CfType {
            CfType::default()
        }
    }

    /// A TLS-like filter (`SSL`): reports the SSL capability but delegates all
    /// I/O, so it exercises `is_ssl` and the connect cascade.
    struct SslFilter;

    impl ConnectionFilter for SslFilter {
        fn name(&self) -> &'static str {
            "SSL"
        }
        fn cf_type(&self) -> CfType {
            CfType::SSL
        }
    }

    /// An HTTP/2-like filter (`H2`): multiplexing + HTTP, answering the
    /// HTTP-version / max-concurrent / stream-error queries. Delegates connect.
    struct HttpFilter;

    impl ConnectionFilter for HttpFilter {
        fn name(&self) -> &'static str {
            "H2"
        }
        fn cf_type(&self) -> CfType {
            CfType::HTTP | CfType::MULTIPLEX
        }
        fn query(&self, _cx: &QueryCtx<'_>, query: CfQuery, out: &mut QueryOut) -> Result<()> {
            match query {
                CfQuery::HttpVersion => {
                    *out = QueryOut::HttpVersion(20);
                    Ok(())
                }
                CfQuery::MaxConcurrent => {
                    *out = QueryOut::MaxConcurrent(100);
                    Ok(())
                }
                CfQuery::StreamError => {
                    *out = QueryOut::StreamError(7);
                    Ok(())
                }
                _ => Err(Error::Code(CurlCode::UnknownOption)),
            }
        }
    }

    /// The bottom/socket filter (curl's `TCP`): provides the IP connection and
    /// terminates the chain by overriding connect/send/recv and answering the
    /// socket/transport/need-flush queries.
    struct SocketTail {
        fd: i32,
        recv_bytes: Vec<u8>,
        need_flush: bool,
    }

    impl SocketTail {
        fn new(fd: i32, recv_bytes: Vec<u8>) -> Self {
            SocketTail {
                fd,
                recv_bytes,
                need_flush: false,
            }
        }
    }

    impl ConnectionFilter for SocketTail {
        fn name(&self) -> &'static str {
            "TCP"
        }
        fn cf_type(&self) -> CfType {
            CfType::IP_CONNECT
        }
        fn connect<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            _blocking: bool,
        ) -> CfFuture<'a, Result<bool>> {
            Box::pin(async { Ok(true) })
        }
        fn send<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            buf: &'a [u8],
            _eos: bool,
        ) -> CfFuture<'a, Result<usize>> {
            let n = buf.len();
            Box::pin(async move { Ok(n) })
        }
        fn recv<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            buf: &'a mut [u8],
        ) -> CfFuture<'a, Result<usize>> {
            let src = self.recv_bytes.clone();
            Box::pin(async move {
                let n = src.len().min(buf.len());
                buf[..n].copy_from_slice(&src[..n]);
                Ok(n)
            })
        }
        fn data_pending(&self, _cx: &QueryCtx<'_>) -> bool {
            !self.recv_bytes.is_empty()
        }
        fn query(&self, _cx: &QueryCtx<'_>, query: CfQuery, out: &mut QueryOut) -> Result<()> {
            match query {
                CfQuery::Socket => {
                    *out = QueryOut::Socket(self.fd);
                    Ok(())
                }
                CfQuery::Transport => {
                    *out = QueryOut::Transport(Transport::Tcp);
                    Ok(())
                }
                CfQuery::NeedFlush => {
                    *out = QueryOut::NeedFlush(self.need_flush);
                    Ok(())
                }
                _ => Err(Error::Code(CurlCode::UnknownOption)),
            }
        }
    }

    /// A filter whose `cntrl` always fails, used to test first-fail vs
    /// ignore-result iteration.
    struct FailCntrl;

    impl ConnectionFilter for FailCntrl {
        fn name(&self) -> &'static str {
            "FAIL"
        }
        fn cf_type(&self) -> CfType {
            CfType::default()
        }
        fn cntrl(
            &mut self,
            _cx: &mut FilterCtx<'_>,
            _event: i32,
            _arg1: i32,
            _arg2: Option<&mut dyn Any>,
        ) -> Result<()> {
            Err(Error::Code(CurlCode::BadFunctionArgument))
        }
    }

    /// Builds the canonical `[SETUP, TCP]` two-filter chain (head = SETUP,
    /// tail = TCP), added in curl's prepend order (add TCP, then add SETUP).
    fn setup_tcp_chain(fd: i32, recv_bytes: Vec<u8>) -> FilterChain {
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(SocketTail::new(fd, recv_bytes)));
        chain.add(Box::new(PassThrough));
        chain
    }

    #[test]
    fn add_prepends_at_top() {
        // add(TCP) then add(SETUP) => SETUP at head (index 0), TCP at tail.
        let chain = setup_tcp_chain(7, Vec::new());
        assert_eq!(chain.len(), 2);
        assert!(!chain.is_empty());
        assert_eq!(chain.head().map(ConnectionFilter::name), Some("SETUP"));
        assert_eq!(chain.tail().map(ConnectionFilter::name), Some("TCP"));
    }

    #[test]
    fn insert_after_splices_below_index() {
        // [SETUP, TCP] -> insert_after(0, SSL) -> [SETUP, SSL, TCP].
        let mut chain = setup_tcp_chain(7, Vec::new());
        chain.insert_after(0, Box::new(SslFilter)).unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain.head().map(ConnectionFilter::name), Some("SETUP"));
        assert_eq!(chain.tail().map(ConnectionFilter::name), Some("TCP"));
        // The spliced filter sits at index 1 (directly below SETUP).
        let names: Vec<&str> = (0..chain.len()).map(|i| chain.filters[i].name()).collect();
        assert_eq!(names, vec!["SETUP", "SSL", "TCP"]);
    }

    #[test]
    fn insert_after_out_of_range_is_bad_argument() {
        let mut chain = FilterChain::new(FIRSTSOCKET);
        let err = chain.insert_after(0, Box::new(PassThrough)).unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
    }

    #[test]
    fn discard_and_discard_all() {
        let mut chain = setup_tcp_chain(7, Vec::new());
        assert!(chain.discard(0)); // remove SETUP
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.head().map(ConnectionFilter::name), Some("TCP"));
        assert!(!chain.discard(5)); // out of range
        chain.discard_all();
        assert!(chain.is_empty());
    }

    #[tokio::test]
    async fn connect_cascades_and_marks_connected() {
        let mut chain = setup_tcp_chain(7, Vec::new());
        assert!(!chain.is_connected());
        let done = chain.connect(false).await.unwrap();
        assert!(done);
        assert!(chain.is_connected());
        // Both filters are now connected -> the IP connection is established.
        assert!(chain.is_ip_connected());
        // Second connect on an already-connected chain is a no-op `true`.
        assert!(chain.connect(false).await.unwrap());
    }

    #[tokio::test]
    async fn empty_chain_connect_is_failed_init() {
        let mut chain = FilterChain::new(FIRSTSOCKET);
        let err = chain.connect(false).await.unwrap_err();
        assert_eq!(err.code(), CurlCode::FailedInit);
    }

    #[tokio::test]
    async fn send_recv_delegate_head_to_tail() {
        let mut chain = setup_tcp_chain(7, vec![b'h', b'i', b'!']);
        assert!(chain.connect(false).await.unwrap());
        // SETUP delegates send down to TCP, which reports all bytes written.
        let n = chain.send(b"hello", false).await.unwrap();
        assert_eq!(n, 5);
        // SETUP delegates recv down to TCP, which yields its fixed bytes.
        let mut buf = [0u8; 8];
        let got = chain.recv(&mut buf).await.unwrap();
        assert_eq!(got, 3);
        assert_eq!(&buf[..3], b"hi!");
    }

    #[tokio::test]
    async fn no_next_send_recv_use_curls_asymmetric_codes() {
        // A lone pass-through has a head but nothing below it: the delegating
        // defaults hit the end of the chain.
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(PassThrough));
        assert!(chain.connect(false).await.unwrap());
        // Curl_cf_def_send at chain end -> CURLE_RECV_ERROR (56).
        let send_err = chain.send(b"x", false).await.unwrap_err();
        assert_eq!(send_err.code(), CurlCode::RecvError);
        // Curl_cf_def_recv at chain end -> CURLE_SEND_ERROR (55).
        let mut buf = [0u8; 4];
        let recv_err = chain.recv(&mut buf).await.unwrap_err();
        assert_eq!(recv_err.code(), CurlCode::SendError);
    }

    #[tokio::test]
    async fn empty_chain_send_recv_use_driver_codes() {
        // An empty chain (no head): the *driver* codes apply, which are the
        // opposite of the delegate defaults above.
        let mut chain = FilterChain::new(FIRSTSOCKET);
        // Curl_conn_cf_send NULL cf -> CURLE_SEND_ERROR (55).
        assert_eq!(
            chain.send(b"x", false).await.unwrap_err().code(),
            CurlCode::SendError
        );
        let mut buf = [0u8; 4];
        // Curl_conn_cf_recv NULL cf -> CURLE_RECV_ERROR (56).
        assert_eq!(
            chain.recv(&mut buf).await.unwrap_err().code(),
            CurlCode::RecvError
        );
    }

    #[test]
    fn empty_chain_query_is_unknown_option() {
        let chain = FilterChain::new(FIRSTSOCKET);
        let mut out = QueryOut::None;
        let err = chain.query(CfQuery::Socket, &mut out).unwrap_err();
        assert_eq!(err.code(), CurlCode::UnknownOption);
    }

    #[test]
    fn socket_and_transport_queries_delegate_to_tail() {
        // SETUP does not answer these; it delegates down to TCP.
        let chain = setup_tcp_chain(42, Vec::new());
        assert_eq!(chain.socket(), Some(42));
        assert_eq!(chain.transport(), Some(Transport::Tcp));
    }

    #[test]
    fn capability_walkers_reflect_chain_shape() {
        // [SETUP, TCP]: no SSL, not multiplexed.
        let chain = setup_tcp_chain(7, Vec::new());
        assert!(!chain.is_ssl());
        assert!(!chain.is_multiplex());

        // [H2, SSL, SETUP, TCP]: multiplexed + secure + HTTP/2.
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(SocketTail::new(7, Vec::new())));
        chain.add(Box::new(PassThrough));
        chain.add(Box::new(SslFilter));
        chain.add(Box::new(HttpFilter));
        assert!(chain.is_ssl());
        assert!(chain.is_multiplex());
        assert_eq!(chain.http_version(), 20);
        assert_eq!(chain.max_concurrent(), 100);
        assert_eq!(chain.stream_error(), 7);
    }

    #[test]
    fn query_defaults_when_unanswered() {
        // TCP answers none of these -> curl's documented defaults apply.
        let chain = setup_tcp_chain(7, Vec::new());
        assert_eq!(chain.http_version(), 0);
        assert_eq!(chain.max_concurrent(), 1);
        assert_eq!(chain.stream_error(), 0);
        assert_eq!(chain.alpn_negotiated(), None);
        assert!(!chain.needs_flush());
    }

    #[test]
    fn needs_flush_reflects_filter_state() {
        let mut chain = FilterChain::new(FIRSTSOCKET);
        let mut tail = SocketTail::new(7, Vec::new());
        tail.need_flush = true;
        chain.add(Box::new(tail));
        chain.add(Box::new(PassThrough));
        assert!(chain.needs_flush());
    }

    #[tokio::test]
    async fn data_pending_skips_unconnected_then_delegates() {
        let mut chain = setup_tcp_chain(7, vec![1, 2, 3]);
        // Nothing connected yet -> no data pending.
        assert!(!chain.data_pending());
        assert!(chain.connect(false).await.unwrap());
        // After connect, the first connected filter (SETUP) delegates down to
        // TCP, which reports its buffered bytes.
        assert!(chain.data_pending());
    }

    #[tokio::test]
    async fn shutdown_walks_connected_filters() {
        let mut chain = setup_tcp_chain(7, Vec::new());
        // Nothing connected -> shutdown is immediately done.
        assert!(chain.shutdown(1000).await.unwrap());
        // Connect, then shut down: both filters use the default (immediately
        // done) shutdown, so the whole chain reports done.
        assert!(chain.connect(false).await.unwrap());
        assert!(chain.shutdown(1000).await.unwrap());
    }

    #[tokio::test]
    async fn close_clears_connected_bits() {
        let mut chain = setup_tcp_chain(7, Vec::new());
        assert!(chain.connect(false).await.unwrap());
        assert!(chain.is_connected());
        chain.close();
        assert!(!chain.is_connected());
        assert!(!chain.is_ip_connected());
    }

    #[test]
    fn cntrl_first_fail_vs_ignore_result() {
        // [FAIL, TCP]: the FAIL filter errors on cntrl.
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(SocketTail::new(7, Vec::new())));
        chain.add(Box::new(FailCntrl));
        // First-fail returns the error.
        let err = chain.cntrl(1, 0, None).unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
        // Ignore-result also surfaces the first error but does not stop early.
        let err = chain.cntrl_all(1, 0, None).unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
        // A chain with no failing filter succeeds.
        let mut ok_chain = setup_tcp_chain(7, Vec::new());
        assert!(ok_chain.cntrl(1, 0, None).is_ok());
        assert!(ok_chain.cntrl_update_info().is_ok());
    }

    #[tokio::test]
    async fn flush_sends_control_event() {
        // No filter fails on the FLUSH control event -> Ok.
        let mut chain = setup_tcp_chain(7, Vec::new());
        assert!(chain.connect(false).await.unwrap());
        assert!(chain.flush().await.is_ok());
    }

    #[test]
    fn established_connection_string_matches_curl_wording() {
        // FIRSTSOCKET: no prefix.
        let s = FilterChain::format_established_connection(
            FIRSTSOCKET,
            "example.com",
            "93.184.216.34",
            443,
            "10.0.0.2",
            51000,
        );
        assert_eq!(
            s,
            "Established connection to example.com (93.184.216.34 port 443) from 10.0.0.2 port 51000 "
        );
        // SECONDARYSOCKET: the "2nd " prefix, matching cf_verboseconnect.
        let s2 = FilterChain::format_established_connection(
            SECONDARYSOCKET,
            "example.com",
            "93.184.216.34",
            21,
            "10.0.0.2",
            51001,
        );
        assert_eq!(
            s2,
            "Established 2nd connection to example.com (93.184.216.34 port 21) from 10.0.0.2 port 51001 "
        );
    }

    #[test]
    fn chain_is_object_safe_and_debuggable() {
        // The trait is usable as a boxed trait object and the chain is Debug.
        let chain = setup_tcp_chain(7, Vec::new());
        let dbg = format!("{chain:?}");
        assert!(dbg.contains("FilterChain"));
        assert!(dbg.contains("SETUP"));
        assert!(dbg.contains("TCP"));
    }

    #[test]
    fn pollset_add_and_clear() {
        let mut ps = Pollset::new();
        assert!(ps.is_empty());
        ps.add_in(3);
        ps.add_out(3);
        assert_eq!(ps.events(3), POLL_INOUT);
        assert_eq!(ps.len(), 1);
        ps.clear_out(3);
        assert_eq!(ps.events(3), POLL_IN);
        ps.clear_in(3);
        assert!(ps.is_empty());
    }
}
