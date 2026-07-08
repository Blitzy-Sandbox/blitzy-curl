// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! Application-protocol handlers behind a common trait + scheme-dispatch table.
//! Ported from curl `lib/url.c` protocol registration and the `struct
//! Curl_protocol` vtable in `lib/urldata.h`. RTMP/RTMPS intentionally absent.
//!
//! # What this module is
//!
//! This is the **foundational root** of the protocol-handler subsystem. It is
//! the language rewrite of two C artifacts:
//!
//! * `struct Curl_protocol` (`lib/urldata.h`) — the per-protocol vtable of 17
//!   function pointers (`do_it`, `done`, `connect_it`, `disconnect`, …). It
//!   becomes the [`Protocol`] trait: polymorphic *runtime* dispatch replaces the
//!   C function-pointer indirection and the `#ifdef CURL_DISABLE_*` branching.
//! * `struct Curl_scheme` + the `Curl_get_scheme_handler` lookup (`lib/url.c`)
//!   — the URL-scheme registration table. It becomes [`SchemeHandler`] plus the
//!   [`scheme_handler`] lookup and the [`protocol_family`] mapping.
//!
//! This module defines the shared machinery through which per-protocol behavior
//! is dispatched: the [`Protocol`] trait, the [`SchemeHandler`] record, and the
//! [`PROTOPT_NONE`]-family and `CURLPROTO_*` constants. The scheme table
//! registers each scheme's identity/ABI metadata (name, protocol and family
//! bits, characteristic flags, default port); a scheme's behavior vtable is
//! carried in its optional `handler` slot (see *Handler binding*).
//!
//! # Design (AAP §0.3.2)
//!
//! * **Trait-based dispatch.** curl selects protocol behavior with compile-time
//!   `#ifdef` branches and a function-pointer vtable; here each protocol
//!   implements [`Protocol`] and is dispatched through a `&dyn Protocol`,
//!   exactly as curl calls through `conn->handler->do_it(...)`.
//! * **Async on Tokio only.** The fallible async steps of [`Protocol`] return a
//!   boxed [`ProtoFuture`] rather than using an `async fn` in the trait. That
//!   keeps the trait object-safe (usable as `&dyn Protocol`, which the scheme
//!   table requires) and compiles on the MSRV (Rust 1.75) with no
//!   `async_fn_in_trait` lint — the same pattern the sibling [`crate::dns`]
//!   `Resolver` trait uses. No `async-std`/`smol`, no `async-trait`.
//! * **Memory safety.** The crate root's compiler-enforced safe-code policy
//!   applies here; `protocols/` is one of the audited safe-code zones
//!   (AAP §0.6.2, §0.7.2). There is no FFI and there are no raw pointers in
//!   this subtree.
//! * **Minimal change.** The supported scheme set, the flag bits, the default
//!   ports, and the `CURLPROTO_*`/`PROTOPT_*` numeric identities reproduce curl
//!   8.19.0-DEV exactly. **RTMP/RTMPS are dropped** (AAP §0.2.2, §1.3.2.5): no
//!   `rtmp*` scheme is ever registered and no RTMP handler exists. The C
//!   `lib/curl_rtmp.c` reference file is left untouched; the protocol is simply
//!   never wired in.
//!
//! # Transfer lifecycle
//!
//! The [`Protocol`] methods mirror curl's multi state machine (`lib/multi.c`,
//! the `MSTATE_*` phases). A protocol author overrides only the steps a
//! protocol needs; everything else uses the faithful no-op default (exactly as
//! curl leaves the corresponding C function pointer `NULL`). The driving loop
//! itself lives in the consumers [`crate::multi`] / [`crate::transfer`], which
//! call these methods in this order:
//!
//! ```text
//! CONNECT     → setup_connection, then connect (repeated via connecting)
//! DO          → do_it            (the required request-issuing step)
//! DO_MORE     → do_more          (optional 2nd half of DO, e.g. FTP PASV/PORT)
//! DOING       → doing            (repeated until the DO phase completes)
//! PERFORM     → write_resp / write_resp_hd post-process streamed response bytes
//! DONE        → done             (the required teardown step)
//! (teardown)  → disconnect       (protocol-dependent connection shutdown)
//! ```
//!
//! The `*_pollset` hooks feed the protocol's desired socket-readiness into the
//! event loop during the matching phase; [`connection_check`] answers liveness
//! probes for pooled connections; [`Protocol::attach`] binds a transfer to a
//! connection; [`Protocol::follow`] decides whether a redirect is followed.
//!
//! # Handler binding
//!
//! [`SchemeHandler::handler`](SchemeHandler#structfield.handler) is an
//! `Option<&'static dyn Protocol>`. Every scheme record always carries the
//! scheme *metadata* (name, protocol bit, family bit, [`PROTOPT_NONE`]-family
//! flags, default port); the `handler` slot holds a `&dyn Protocol` behavior
//! vtable when one is bound to the scheme, and is `None` otherwise.
//!
//! Binding follows curl's one-handler-per-family rule: a TLS variant shares its
//! base scheme's handler because TLS is layered by the connection filter chain,
//! exactly as curl's `Curl_scheme_https` reuses `Curl_protocol_http`. The same
//! pairing applies to `http`/`https`, `ftp`/`ftps`, `imap`/`imaps`,
//! `pop3`/`pop3s`, `smtp`/`smtps`, `ldap`/`ldaps`, `smb`/`smbs`,
//! `gopher`/`gophers`, `mqtt`/`mqtts`, and `ws`/`wss`; `sftp` and `scp` are the
//! two distinct members of the SSH family.

// The memory-safety cornerstone is inherited from the crate root
// (the `#![forbid(...)]` safe-code lint in `lib.rs`): any escape-hatch token
// anywhere in this file is a hard compile error, and a CI grep audit asserts
// the token never appears under `curl-rs-lib/src/`.

// Feature matrix: the protocol features {file, gopher, ldap, smb, websockets}
// and the SSH family {ssh, sftp, scp} are declared in curl-rs-lib/Cargo.toml as
// DEFAULT-OFF (opt-in). The AAP §0.5.3 default-on set is exactly the thirteen
// capabilities {http, ftp, smtp, imap, pop3, tftp, telnet, dict, mqtt, rtsp,
// cookies, brotli, zstd} enumerated in that manifest's `default`, and it does
// not include them; the only catalogued default-off resolver feature is
// `hickory-dns`. A scheme whose feature is off is simply not registered
// (`scheme_handler` returns None) — exactly like a stock curl compiled with the
// matching CURL_DISABLE_* guard.

// ===========================================================================
// Submodule declarations.
//
// This root module owns the protocol-dispatch scaffold shared by every
// protocol: the [`Protocol`] trait, the [`SchemeHandler`] registry, the
// `SCHEME_*` tables, and the `PROTOPT_*` / `PROTOCOL_*` identity constants.
// Concrete per-protocol handler modules are feature-gated (reproducing curl's
// per-protocol `CURL_DISABLE_*` / `USE_*` guards — AAP §0.5.3) and declared
// here as they are implemented; the self-contained FTP directory-listing
// parser is declared below.
// ===========================================================================

// FTP directory-listing parser (`lib/ftplistparser.c`), gated by the `ftp`
// feature. Self-contained: it parses listing lines and does not depend on the
// FTP protocol handler.
#[cfg(feature = "ftp")]
pub mod ftp_list;

// ---------------------------------------------------------------------------
// Concrete per-protocol handler modules (declared here "as they are
// implemented", per the note above). Each module is gated by the same Cargo
// feature as its `SCHEME_*` registry entry below (AAP §0.5.3): when a
// protocol's feature is disabled, neither its module nor its scheme entry is
// compiled — exactly like a stock curl built with the matching
// `CURL_DISABLE_*` guard.
// ---------------------------------------------------------------------------

// Generic line-based command/response ("ping-pong") engine shared by the text
// protocols FTP/IMAP/POP3/SMTP (`lib/pingpong.c`, guarded in C by
// `USE_PINGPONG`, i.e. whenever any of those four protocols is enabled).
#[cfg(any(
    feature = "ftp",
    feature = "imap",
    feature = "pop3",
    feature = "smtp"
))]
pub mod pingpong;

// TFTP over UDP (`lib/tftp.c`).
#[cfg(feature = "tftp")]
pub mod tftp;

// TELNET (`lib/telnet.c`).
#[cfg(feature = "telnet")]
pub mod telnet;

// DICT (`lib/dict.c`).
#[cfg(feature = "dict")]
pub mod dict;

// MQTT (`lib/mqtt.c`).
#[cfg(feature = "mqtt")]
pub mod mqtt;

// RTSP (`lib/rtsp.c`).
#[cfg(feature = "rtsp")]
pub mod rtsp;

// FILE (`lib/file.c`).
#[cfg(feature = "file")]
pub mod file;

// GOPHER (`lib/gopher.c`).
#[cfg(feature = "gopher")]
pub mod gopher;

// LDAP (`lib/openldap.c`).
#[cfg(feature = "ldap")]
pub mod ldap;

// SMB (`lib/smb.c`).
#[cfg(feature = "smb")]
pub mod smb;

// WebSocket (`lib/ws.c`), gated by `websockets` (curl `CURL_DISABLE_WEBSOCKETS`).
#[cfg(feature = "websockets")]
pub mod ws;

use std::any::Any;
use std::fmt;
use std::future::Future;
use std::os::fd::RawFd;
use std::pin::Pin;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::conn::Transport;
use crate::error::Result;

// ===========================================================================
// PROTOPT_* — per-protocol characteristic flags (`lib/urldata.h`).
//
// These bit values are load-bearing and reproduce the C `#define PROTOPT_*`
// macros exactly; they are stored in [`SchemeHandler::flags`]. Bit `1 << 9`
// (formerly `PROTOPT_STREAM`) is intentionally left free, matching curl.
// ===========================================================================

/// Nothing extra (`PROTOPT_NONE`).
pub const PROTOPT_NONE: u32 = 0;
/// Uses SSL/TLS (`PROTOPT_SSL`).
pub const PROTOPT_SSL: u32 = 1 << 0;
/// This protocol uses two connections — FTP (`PROTOPT_DUAL`).
pub const PROTOPT_DUAL: u32 = 1 << 1;
/// Needs an action before the socket is closed (`PROTOPT_CLOSEACTION`).
pub const PROTOPT_CLOSEACTION: u32 = 1 << 2;
/// Protocol needs the connection's directory lock (`PROTOPT_DIRLOCK`).
pub const PROTOPT_DIRLOCK: u32 = 1 << 3;
/// Protocol does not use the network — FILE (`PROTOPT_NONETWORK`).
pub const PROTOPT_NONETWORK: u32 = 1 << 4;
/// Needs a password; a missing one defaults to the anonymous credential
/// (`PROTOPT_NEEDSPWD`).
pub const PROTOPT_NEEDSPWD: u32 = 1 << 5;
/// Protocol cannot handle a URL query part (`PROTOPT_NOURLQUERY`).
pub const PROTOPT_NOURLQUERY: u32 = 1 << 6;
/// Requires login credentials to be sent on every request
/// (`PROTOPT_CREDSPERREQUEST`).
pub const PROTOPT_CREDSPERREQUEST: u32 = 1 << 7;
/// Set ALPN for this protocol (`PROTOPT_ALPN`).
pub const PROTOPT_ALPN: u32 = 1 << 8;
// Bit `1 << 9` was `PROTOPT_STREAM`; it is now free and deliberately unused.
/// Allow an options part in the userinfo (`PROTOPT_URLOPTIONS`).
pub const PROTOPT_URLOPTIONS: u32 = 1 << 10;
/// Allow this non-HTTP scheme to be tunneled over an HTTP proxy
/// (`PROTOPT_PROXY_AS_HTTP`).
pub const PROTOPT_PROXY_AS_HTTP: u32 = 1 << 11;
/// Protocol supports wildcard matching (`PROTOPT_WILDCARD`).
pub const PROTOPT_WILDCARD: u32 = 1 << 12;
/// Allow "control bytes" (`< 32` ASCII) in the user/password
/// (`PROTOPT_USERPWDCTRL`).
pub const PROTOPT_USERPWDCTRL: u32 = 1 << 13;
/// This protocol cannot proxy over TCP — TFTP (`PROTOPT_NOTCPPROXY`).
pub const PROTOPT_NOTCPPROXY: u32 = 1 << 14;
/// This protocol may reuse an existing (SSL) connection without itself having
/// [`PROTOPT_SSL`] (`PROTOPT_SSL_REUSE`).
pub const PROTOPT_SSL_REUSE: u32 = 1 << 15;
/// This protocol can reuse connections (`PROTOPT_CONN_REUSE`).
pub const PROTOPT_CONN_REUSE: u32 = 1 << 16;

// ===========================================================================
// CURLPROTO_* — protocol identity bits (`include/curl/curl.h`, plus the two
// internal WebSocket bits from `lib/urldata.h`).
//
// These are part of the frozen public ABI (`CURLOPT_PROTOCOLS_STR`,
// `CURLINFO_PROTOCOL`, `CURLOPT_PROTOCOLS`/`CURLOPT_REDIR_PROTOCOLS` masks). A
// scheme stores its single protocol bit in [`SchemeHandler::protocol`] and its
// family bit in [`SchemeHandler::family`]. The RTMP family (bits 19–24) is
// deliberately left undefined: the protocol is dropped from this rewrite
// (AAP §0.2.2), and its bits are owned by the FFI/`curl.h` layer.
// ===========================================================================

/// `CURLPROTO_HTTP`.
pub const CURLPROTO_HTTP: u32 = 1 << 0;
/// `CURLPROTO_HTTPS`.
pub const CURLPROTO_HTTPS: u32 = 1 << 1;
/// `CURLPROTO_FTP`.
pub const CURLPROTO_FTP: u32 = 1 << 2;
/// `CURLPROTO_FTPS`.
pub const CURLPROTO_FTPS: u32 = 1 << 3;
/// `CURLPROTO_SCP`.
pub const CURLPROTO_SCP: u32 = 1 << 4;
/// `CURLPROTO_SFTP`.
pub const CURLPROTO_SFTP: u32 = 1 << 5;
/// `CURLPROTO_TELNET`.
pub const CURLPROTO_TELNET: u32 = 1 << 6;
/// `CURLPROTO_LDAP`.
pub const CURLPROTO_LDAP: u32 = 1 << 7;
/// `CURLPROTO_LDAPS`.
pub const CURLPROTO_LDAPS: u32 = 1 << 8;
/// `CURLPROTO_DICT`.
pub const CURLPROTO_DICT: u32 = 1 << 9;
/// `CURLPROTO_FILE`.
pub const CURLPROTO_FILE: u32 = 1 << 10;
/// `CURLPROTO_TFTP`.
pub const CURLPROTO_TFTP: u32 = 1 << 11;
/// `CURLPROTO_IMAP`.
pub const CURLPROTO_IMAP: u32 = 1 << 12;
/// `CURLPROTO_IMAPS`.
pub const CURLPROTO_IMAPS: u32 = 1 << 13;
/// `CURLPROTO_POP3`.
pub const CURLPROTO_POP3: u32 = 1 << 14;
/// `CURLPROTO_POP3S`.
pub const CURLPROTO_POP3S: u32 = 1 << 15;
/// `CURLPROTO_SMTP`.
pub const CURLPROTO_SMTP: u32 = 1 << 16;
/// `CURLPROTO_SMTPS`.
pub const CURLPROTO_SMTPS: u32 = 1 << 17;
/// `CURLPROTO_RTSP`.
pub const CURLPROTO_RTSP: u32 = 1 << 18;
// Bits 19–24 (RTMP, RTMPT, RTMPE, RTMPTE, RTMPS, RTMPTS) are deliberately left
// undefined: the RTMP family is dropped from this rewrite (AAP §0.2.2).
/// `CURLPROTO_GOPHER`.
pub const CURLPROTO_GOPHER: u32 = 1 << 25;
/// `CURLPROTO_SMB`.
pub const CURLPROTO_SMB: u32 = 1 << 26;
/// `CURLPROTO_SMBS`.
pub const CURLPROTO_SMBS: u32 = 1 << 27;
/// `CURLPROTO_MQTT`.
pub const CURLPROTO_MQTT: u32 = 1 << 28;
/// `CURLPROTO_GOPHERS`.
pub const CURLPROTO_GOPHERS: u32 = 1 << 29;
/// `CURLPROTO_MQTTS`.
///
/// `CURLPROTO_GOPHERS` (bit 29) is the highest bit exposed in the public
/// `curl.h` enum before this one; `MQTTS` occupies bit 30 there.
pub const CURLPROTO_MQTTS: u32 = 1 << 30;
/// `CURLPROTO_WS` — WebSocket (`lib/urldata.h`, internal).
///
/// curl defines this at bit 30, **deliberately overlapping** [`CURLPROTO_MQTTS`]
/// (the `urldata.h` comment notes that GOPHERS at bit 29 is the highest publicly
/// used bit and that WS/WSS are internal information reusing the top bits). The
/// two are never used by the same handle, so the shared bit is a harmless
/// space-saving detail, preserved here for numeric parity.
pub const CURLPROTO_WS: u32 = 1 << 30;
/// `CURLPROTO_WSS` — WebSocket over TLS (`lib/urldata.h`, internal, bit 31).
pub const CURLPROTO_WSS: u32 = 1 << 31;

// ===========================================================================
// CURL_POLL_* — socket-readiness actions (`include/curl/multi.h`).
//
// These mirror the public `CURL_POLL_*` values and are the per-socket action
// codes stored in a [`Pollset`] (curl's `easy_pollset.actions`, an
// `unsigned char` array — hence `u8`).
// ===========================================================================

/// No readiness interest (`CURL_POLL_NONE`).
pub const CURL_POLL_NONE: u8 = 0;
/// Interested in readability (`CURL_POLL_IN`).
pub const CURL_POLL_IN: u8 = 1;
/// Interested in writability (`CURL_POLL_OUT`).
pub const CURL_POLL_OUT: u8 = 2;
/// Interested in both readability and writability (`CURL_POLL_INOUT`).
pub const CURL_POLL_INOUT: u8 = CURL_POLL_IN | CURL_POLL_OUT;
/// Remove the socket from the poll set (`CURL_POLL_REMOVE`).
pub const CURL_POLL_REMOVE: u8 = 4;

// ===========================================================================
// Pollset — a protocol's desired socket-readiness set.
//
// Faithful rewrite of curl's `easy_pollset` (`lib/select.h`) and the
// `Curl_pollset_*` helpers. A protocol's `*_pollset` hook contributes the
// sockets it wants the event loop to watch (and with which interest) for the
// current transfer phase. The connection filter chain and the multi event loop
// (the consumers) drain this into the actual poll/epoll registration.
//
// curl's `curl_socket_t` is a file descriptor on the supported (Unix) target
// platforms, so [`RawFd`] is the faithful socket-handle type here. Windows is
// out of scope (AAP §0.6.5), so no Windows socket variant is modeled.
// ===========================================================================

/// A single socket plus the readiness interest requested for it.
///
/// `action` is a bitmask of [`CURL_POLL_IN`] / [`CURL_POLL_OUT`] (equivalently
/// [`CURL_POLL_INOUT`]); it is never [`CURL_POLL_NONE`] for a socket that is
/// present in a [`Pollset`] (a socket whose interest drops to nothing is
/// removed instead — matching curl).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollSocket {
    /// The socket (file descriptor) to watch.
    pub socket: RawFd,
    /// Readiness interest bitmask: [`CURL_POLL_IN`] and/or [`CURL_POLL_OUT`].
    pub action: u8,
}

/// The set of sockets a protocol wants watched for a given transfer phase.
///
/// Mirrors curl's `easy_pollset`: a small, order-preserving collection of
/// `(socket, action)` pairs. It is intentionally minimal — a protocol's
/// pollset hook typically adds zero or one socket beyond the connection's own.
#[derive(Clone, Debug, Default)]
pub struct Pollset {
    sockets: Vec<PollSocket>,
}

impl Pollset {
    /// Create an empty poll set (← the zeroed `easy_pollset`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sockets: Vec::new(),
        }
    }

    /// Set the exact readiness interest for `socket` (← `Curl_pollset_set`).
    ///
    /// `action` is interpreted as a [`CURL_POLL_IN`]/[`CURL_POLL_OUT`] bitmask.
    /// If the resulting interest is empty — i.e. [`CURL_POLL_NONE`] or
    /// [`CURL_POLL_REMOVE`], neither of which carries an `IN`/`OUT` bit — the
    /// socket is removed from the set. Otherwise the socket's interest is
    /// inserted or updated in place, preserving insertion order.
    pub fn set(&mut self, socket: RawFd, action: u8) {
        let want = action & CURL_POLL_INOUT;
        if want == CURL_POLL_NONE {
            self.sockets.retain(|e| e.socket != socket);
            return;
        }
        if let Some(entry) = self.sockets.iter_mut().find(|e| e.socket == socket) {
            entry.action = want;
        } else {
            self.sockets.push(PollSocket {
                socket,
                action: want,
            });
        }
    }

    /// Add read (`IN`) interest for `socket` (← `Curl_pollset_add_in`),
    /// preserving any existing write interest.
    pub fn add_in(&mut self, socket: RawFd) {
        let action = self.action_of(socket) | CURL_POLL_IN;
        self.set(socket, action);
    }

    /// Add write (`OUT`) interest for `socket` (← `Curl_pollset_add_out`),
    /// preserving any existing read interest.
    pub fn add_out(&mut self, socket: RawFd) {
        let action = self.action_of(socket) | CURL_POLL_OUT;
        self.set(socket, action);
    }

    /// The current readiness interest for `socket`, or [`CURL_POLL_NONE`] if the
    /// socket is not in the set.
    #[must_use]
    pub fn action_of(&self, socket: RawFd) -> u8 {
        self.sockets
            .iter()
            .find(|e| e.socket == socket)
            .map_or(CURL_POLL_NONE, |e| e.action)
    }

    /// The sockets in this set, in insertion order.
    #[must_use]
    pub fn sockets(&self) -> &[PollSocket] {
        &self.sockets
    }

    /// Number of sockets in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sockets.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sockets.is_empty()
    }
}

// ===========================================================================
// FollowType — redirect/retry disposition (`lib/http.h`, `enum followtype`).
//
// Consumed by [`Protocol::follow`] to decide how (and whether) a new target URL
// is pursued. Values reproduce curl 8.19.0-DEV's `followtype` exactly.
// ===========================================================================

/// How a new target URL is to be followed (← `enum followtype`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FollowType {
    /// Not a follow — no new URL is pursued (`FOLLOW_NONE`).
    None = 0,
    /// A "fake" follow: the redirect is accounted for (e.g. against the
    /// redirect limit) but no new request is set up (`FOLLOW_FAKE`).
    Fake = 1,
    /// Retry the *same* request on a fresh connection (`FOLLOW_RETRY`).
    Retry = 2,
    /// A real redirect to a new URL (`Location:`), setting up a new request
    /// (`FOLLOW_REDIR`).
    Redir = 3,
}

// ===========================================================================
// TransferCtx — the per-call context passed to every [`Protocol`] hook.
// ===========================================================================

/// A live, bidirectional byte transport a [`Protocol`] handler drives during
/// its DO/DOING phases — the rewrite of the socket curl reaches through
/// `conn->sock[sockindex]`.
///
/// It is the object-safe union of Tokio's [`AsyncRead`] and [`AsyncWrite`]
/// (plus [`Unpin`] and [`Send`]), so a boxed stream can be stored in
/// [`TransferCtx::io`] and handed to the generic per-protocol engines (e.g.
/// `dict::Dict::transfer`, `gopher::Gopher::perform`), which are bounded on
/// `AsyncRead + AsyncWrite + Unpin`: because those bounds are *supertraits*,
/// `dyn TransferStream` (and thus `&mut dyn TransferStream`) satisfies them
/// directly, with no trait upcasting (keeping the MSRV at 1.75).
///
/// The blanket impl means *any* Tokio stream — a real TLS/TCP connection or an
/// in-memory [`tokio::io::duplex`](tokio::io::duplex) pipe used by tests — is a
/// `TransferStream` automatically; no concrete type ever needs to name it. It
/// is defined here in `protocols` (not in `conn`) so the module keeps no
/// dependency on the connection layer, matching the one-way `conn → protocols`
/// direction of the rest of the crate.
pub trait TransferStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> TransferStream for T {}

/// A sink for received body bytes — the rewrite of curl's client write path
/// (`Curl_client_write` → the `CURLOPT_WRITEFUNCTION` callback).
///
/// A handler pushes decoded body chunks here during its DO/PERFORM phase; the
/// concrete implementation forwards them to the client write callback and
/// applies the same accept / short-write / pause accounting curl does. The
/// trait is object-safe (no generics, no by-value `self`, no `Self` return) so
/// it can live behind `Box<dyn TransferSink>` in [`TransferCtx::sink`], and is
/// `Send` so [`TransferCtx`] can cross the multi handle's worker threads.
pub trait TransferSink: Send {
    /// Deliver one chunk of received body bytes to the client.
    ///
    /// Returns `Err` with curl's `CURLE_WRITE_ERROR` when the client rejected
    /// the data (the write callback returned a short count).
    fn write(&mut self, data: &[u8]) -> Result<()>;
}

/// The per-transfer request parameters a [`Protocol`] handler reads to drive
/// its engine — the subset of curl's `struct UserDefined` / `struct
/// SingleRequest` that the auxiliary protocols consume.
///
/// It is plain owned data (no borrows, no trait objects), so it is `Clone`,
/// `Debug`, and `Default`, and lives inline in [`TransferCtx`]. Fields default
/// to empty/zero, which every handler treats as "option not set" — exactly
/// curl's zero-initialized `UserDefined`.
#[derive(Clone, Debug, Default)]
pub struct TransferRequest {
    /// URL scheme, lowercase (← `data->state.up.scheme`).
    pub scheme: String,
    /// Target host (← `conn->host.name`).
    pub host: String,
    /// Target port, already defaulted from the scheme when the URL omits one
    /// (← `conn->remote_port`).
    pub port: u16,
    /// URL path — for most schemes the `data->state.up.path` string carrying
    /// the protocol-specific payload (the DICT word, the GOPHER selector, the
    /// FILE path, the TFTP filename, the SMB share/file, the MQTT topic).
    pub path: String,
    /// URL query component (← `data->state.up.query`), without the leading `'?'`,
    /// or `None` when the URL carries no query. GOPHER appends it to the path
    /// (`path?query`) to derive the selector's search string; kept separate from
    /// [`path`](Self::path) exactly as curl's URL parser keeps `up.path` and
    /// `up.query` distinct.
    pub query: Option<String>,
    /// The full effective URL (← `data->state.url`), used by the HTTP-derived
    /// protocols (RTSP, WebSocket) that emit a request line.
    pub url: String,
    /// Request method / verb (← `data->state.httpreq` or the protocol command):
    /// e.g. HTTP `"GET"`, an RTSP method, or a protocol-specific verb.
    pub method: String,
    /// Extra request headers as `"Name: value"` lines (← the
    /// `CURLOPT_HTTPHEADER` / `CURLOPT_RTSPHEADER` slist), for the HTTP-derived
    /// protocols.
    pub headers: Vec<String>,
    /// In-memory request body / upload payload (← the read-callback source when
    /// the caller supplied `CURLOPT_POSTFIELDS`-style data), or `None`.
    pub body: Option<Vec<u8>>,
    /// Whether this is an upload (← `CURLOPT_UPLOAD` / `data->state.upload`).
    pub upload: bool,
    /// Byte-range spec `"start-end"` (← `CURLOPT_RANGE` / `data->state.range`),
    /// or `None` for the whole resource.
    pub range: Option<String>,
    /// Headers-only request with no body transfer (← `data->req.no_body` /
    /// `CURLOPT_NOBODY` / `-I`). The transfer layer derives this from the
    /// request options; protocol handlers (e.g. FILE) read it to emit metadata
    /// and stop before the body.
    pub no_body: bool,
    /// Resume/range low offset in bytes (← `data->state.resume_from`, as
    /// computed by curl's `Curl_range` from [`range`](Self::range) /
    /// `CURLOPT_RESUME_FROM`). A negative value counts back from the end of the
    /// resource. `0` means start at the beginning.
    pub resume_from: i64,
    /// Range high-water mark: the maximum number of body bytes to transfer
    /// (← `data->req.maxdownload`, derived from [`range`](Self::range) by
    /// `Curl_range`). `0` means "no cap" (transfer to the natural end).
    pub maxdownload: i64,
    /// `CONNECT_ONLY` mode: establish the connection but perform no transfer
    /// (← `CURLOPT_CONNECT_ONLY`).
    pub connect_only: bool,
    /// Connection-phase timeout (← `CURLOPT_CONNECTTIMEOUT[_MS]`), or `None`.
    pub connect_timeout: Option<Duration>,
    /// Whole-transfer timeout (← `CURLOPT_TIMEOUT[_MS]`), or `None`.
    pub timeout: Option<Duration>,
    /// Username for authentication (← `conn->user` / `CURLOPT_USERNAME`).
    pub user: Option<String>,
    /// Password for authentication (← `conn->passwd` / `CURLOPT_PASSWORD`).
    pub password: Option<String>,
    /// `CURLOPT_TIMECONDITION` selector as its raw `CURL_TIMECOND_*` integer
    /// (`0` = none). Kept as the raw curl value so this always-present struct
    /// stays free of any feature-gated enum; the FILE handler maps it to its
    /// `TimeCond`.
    pub time_condition: i32,
    /// `CURLOPT_TIMEVALUE` reference time in Unix seconds, paired with
    /// [`time_condition`](Self::time_condition).
    pub time_value: i64,
    /// `CURLOPT_WS_OPTIONS` bitmask as its raw `CURLWS_*` integer (`0` = the
    /// default framed, auto-ponging WebSocket mode). Kept as the raw curl value
    /// — like [`time_condition`](Self::time_condition) — so this always-present
    /// struct stays free of any feature-gated type; the WebSocket handler
    /// decodes the `CURLWS_RAW_MODE` / `CURLWS_NOAUTOPONG` bits from it.
    pub ws_options: u32,
    /// `CURLOPT_TELNETOPTIONS` list (← `data->set.telnet_options`, a
    /// `curl_slist`): the raw `NAME=value` strings (`TTYPE=`, `XDISPLOC=`,
    /// `NEW_ENV=`, `WS=`, `BINARY=`) the TELNET handler feeds to
    /// `check_telnet_options` to seed its negotiation preferences. Empty for
    /// every non-TELNET transfer (and for TELNET transfers that set no options).
    pub telnet_options: Vec<String>,
    /// `CURLOPT_RTSP_REQUEST` (← `data->set.rtspreq`) as its raw
    /// `CURL_RTSPREQ_*` integer (`0` = `RTSPREQ_NONE`). The RTSP handler maps it
    /// to a `RtspReq` to select the method and drive `rtsp_do`. Kept as the raw
    /// curl value — like [`time_condition`](Self::time_condition) — so this
    /// always-present struct stays free of any feature-gated enum.
    pub rtsp_request: i64,
    /// `CURLOPT_RTSP_STREAM_URI` (← `data->set.str[STRING_RTSP_STREAM_URI]`):
    /// the request-target URI emitted on the RTSP request line. When `None` the
    /// server-wide `"*"` target is used, exactly as `rtsp_do` defaults it.
    pub rtsp_stream_uri: Option<String>,
    /// `CURLOPT_RTSP_TRANSPORT` (← `data->set.str[STRING_RTSP_TRANSPORT]`): the
    /// value of the `Transport:` header, required for `SETUP`.
    pub rtsp_transport: Option<String>,
    /// `CURLOPT_RTSP_SESSION_ID` (← `data->set.str[STRING_RTSP_SESSION_ID]`):
    /// the pinned session id emitted as `Session:` and compared against a
    /// response's `Session:` header. `None` until a `SETUP` response captures
    /// one.
    pub rtsp_session_id: Option<String>,
    /// `CURLOPT_USERAGENT` (← `data->set.str[STRING_USERAGENT]` /
    /// `data->state.aptr.uagent`): the `User-Agent:` header value emitted by the
    /// HTTP-derived handlers (RTSP, and the HTTP family). `None` = no
    /// `User-Agent` header (libcurl core emits none unless the option is set;
    /// the curl CLI defaults it to `curl/<version>`).
    pub user_agent: Option<String>,
    /// `CURLOPT_REFERER` (← `data->state.referer`): the `Referer:` header value
    /// emitted by the HTTP-derived handlers. `None` = no `Referer` header.
    pub referer: Option<String>,
    /// `CURLOPT_ACCEPT_ENCODING` (← `data->set.str[STRING_ENCODING]`): the
    /// `Accept-Encoding:` header value. `None` = no `Accept-Encoding` header
    /// (libcurl core emits none unless the option is set). For RTSP this is
    /// emitted only on `DESCRIBE`, matching `rtsp_do`.
    pub accept_encoding: Option<String>,
}

/// The per-call context threaded through every [`Protocol`] method — the
/// rewrite of the `struct Curl_easy *data` argument curl passes to each vtable
/// function, from which a handler reaches its connection, its active socket,
/// the request options, and the client write sink.
///
/// The connection is referenced by [`conn_id`](Self::conn_id) rather than
/// borrowed, which keeps [`Protocol`] object-safe (`&dyn Protocol`, as
/// [`SchemeHandler`] requires) and free of a lifetime parameter; the mutable
/// borrow of the context is expressed on each method's receiver instead. The
/// owning connection lives in the driver ([`crate::transfer`] /
/// [`crate::multi`]) and is referenced here by id, never owned or borrowed, so
/// `protocols` takes no dependency on those driver modules (which depend on
/// `protocols`, not the other way round).
///
/// Beyond that identity, the context carries the state a handler needs to
/// actually run its exchange: the live transport ([`io`](Self::io)), the body
/// sink ([`sink`](Self::sink)), the request parameters
/// ([`request`](Self::request)), the concrete socket handle
/// ([`socket_fd`](Self::socket_fd)) for pollset registration, and a
/// type-erased per-protocol scratch slot ([`proto_state`](Self::proto_state))
/// in which a handler keeps its live engine across the transfer's phases. These
/// are distinct public fields so a handler can borrow the stream, the sink, the
/// (immutable) request, and its own `proto_state` simultaneously under the
/// borrow checker.
#[derive(Default)]
#[non_exhaustive]
pub struct TransferCtx {
    /// The connection this transfer is bound to, identified the way curl reaches
    /// it through `data->conn`; `None` before a connection has been assigned.
    pub conn_id: Option<i64>,
    /// The connection-socket index this transfer operates on (← curl's
    /// `conn->sockindex`): `0` is the primary socket (curl's `FIRSTSOCKET`) and
    /// `1` the secondary socket (e.g. the FTP data connection).
    pub sockindex: usize,
    /// The live byte transport for this transfer's active socket, once the
    /// driver (or a test) has installed one; `None` before the transport is
    /// connected. Stream-oriented handlers drive their engine over
    /// `ctx.io.as_deref_mut()` (a `&mut dyn `[`TransferStream`]). The datagram
    /// (TFTP) and local-filesystem (FILE) handlers create their own transport
    /// instead of reading this field.
    pub io: Option<Box<dyn TransferStream>>,
    /// The client write sink for received body bytes; `None` when the transfer
    /// discards its body. Handlers push decoded chunks here during DO/PERFORM
    /// via [`TransferSink::write`].
    pub sink: Option<Box<dyn TransferSink>>,
    /// The request parameters the handler reads to build its protocol exchange
    /// (URL, method, headers, credentials, ranges, timeouts). Defaults to an
    /// all-empty [`TransferRequest`].
    pub request: TransferRequest,
    /// The concrete OS handle of the [`sockindex`](Self::sockindex) socket
    /// (← curl's `conn->sock[sockindex]`), when a real socket is bound; `None`
    /// for a transfer that has not connected yet or that runs over a non-socket
    /// transport (e.g. an in-memory test pipe). A handler's `perform_pollset`
    /// reads this to register the socket's readiness interest with the event
    /// loop, since the boxed [`io`](Self::io) transport does not itself expose a
    /// file descriptor.
    pub socket_fd: Option<RawFd>,
    /// Per-protocol live scratch state (← curl's `struct SingleRequest`
    /// protocol union `data->req.p`, e.g. `req.p.ws` for a WebSocket transfer).
    /// A handler installs its own engine/state here during setup or the DO
    /// phase and retrieves it — by downcasting from the type-erased box — in the
    /// later phases (PERFORM's `write_resp`, DONE's `done`, and the pollset
    /// hooks). `None` until a handler installs state.
    ///
    /// It is deliberately type-erased (`dyn Any`) so this generic context names
    /// no protocol-specific type, exactly as curl's union keeps `SingleRequest`
    /// protocol-agnostic. `Send` is required so [`TransferCtx`] can still cross
    /// the multi handle's worker threads.
    pub proto_state: Option<Box<dyn Any + Send>>,
}

impl TransferCtx {
    /// Create a context for a transfer that has not yet been assigned a
    /// connection: no connection id, positioned on the primary socket
    /// (`sockindex` `0`), with no transport, no sink, and a default
    /// (all-empty) [`TransferRequest`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl fmt::Debug for TransferCtx {
    /// Hand-written because the [`io`](Self::io) and [`sink`](Self::sink) trait
    /// objects are not `Debug`; they are rendered as a presence marker instead.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransferCtx")
            .field("conn_id", &self.conn_id)
            .field("sockindex", &self.sockindex)
            .field("io", &self.io.as_ref().map(|_| "<stream>"))
            .field("sink", &self.sink.as_ref().map(|_| "<sink>"))
            .field("request", &self.request)
            .field("socket_fd", &self.socket_fd)
            .field("proto_state", &self.proto_state.as_ref().map(|_| "<proto_state>"))
            .finish()
    }
}

/// The boxed, `Send` future returned by every fallible async [`Protocol`] step.
///
/// Using an explicit boxed future (rather than an `async fn` in the trait)
/// keeps [`Protocol`] object-safe so it can be stored as
/// `&'static dyn Protocol` in a [`SchemeHandler`], and keeps it free of the
/// `async_fn_in_trait` lint on the MSRV (Rust 1.75). This mirrors the sibling
/// [`crate::dns`] `Resolver` trait. `Send` (not `Sync`) is required so the
/// future can be driven on Tokio's multi-threaded runtime.
pub type ProtoFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

// ===========================================================================
// Protocol — the per-protocol behavior trait (← `struct Curl_protocol`,
// `lib/urldata.h`).
//
// Each of the 17 C function pointers becomes a trait method. curl's comment
// marks exactly two pointers as mandatory — "These two functions MUST be set"
// — namely `do_it` and `done`; those have no default here. Every other method
// has a faithful no-op default, which is precisely how curl leaves an optional
// function pointer `NULL` and falls back to generic behavior.
// ===========================================================================

/// Per-protocol behavior, dispatched polymorphically through `&dyn Protocol`.
///
/// This is the rewrite of curl's `struct Curl_protocol` vtable. Implementors
/// override only the phases their protocol needs; the defaults reproduce curl's
/// "pointer is `NULL`" fallback. See the module-level *Transfer lifecycle* for
/// the order in which these fire.
///
/// The trait is `Send + Sync` so a handler singleton can be shared as
/// `&'static dyn Protocol` across the multi handle's worker threads.
pub trait Protocol: Send + Sync {
    /// Prepare protocol state before the transfer "owns" the connection
    /// (← `setup_connection`). Runs once, early. Default: succeed.
    fn setup_connection<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, ()> {
        let _ = ctx;
        Box::pin(async { Ok(()) })
    }

    /// Protocol-dependent step performed right after the transport connects
    /// (← `connect_it`). Returns `true` when the protocol connect is already
    /// complete, or `false` to continue via [`connecting`](Protocol::connecting).
    /// Default: complete immediately (`true`).
    fn connect<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(async { Ok(true) })
    }

    /// Called repeatedly while the protocol connect is still in progress
    /// (← `connecting`). Returns `true` once connected. Default: `true`.
    fn connecting<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(async { Ok(true) })
    }

    /// The **required** "DO" phase: issue the request (← `do_it`). Returns
    /// `true` when the DO phase is complete, or `false` to continue via
    /// [`doing`](Protocol::doing) / [`do_more`](Protocol::do_more). No default —
    /// curl requires this pointer to be set.
    fn do_it<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool>;

    /// Optional second half of the DO phase (← `do_more`), e.g. FTP after
    /// PASV/PORT establishes the data connection. The `i32` mirrors curl's
    /// `*completed` out-parameter (`0` = not yet complete). Default: `0`.
    fn do_more<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, i32> {
        let _ = ctx;
        Box::pin(async { Ok(0) })
    }

    /// Called repeatedly during the DOING phase (← `doing`). Returns `true` once
    /// the DO phase is complete. Default: `true`.
    fn doing<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(async { Ok(true) })
    }

    /// The **required** teardown of a completed (or, if `premature`, an aborted)
    /// transfer (← `done`). `status` is the transfer's outcome so the protocol
    /// can react to failure. No default — curl requires this pointer to be set.
    fn done<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        status: Result<()>,
        premature: bool,
    ) -> ProtoFuture<'a, ()>;

    /// Protocol-dependent disconnection step (← `disconnect`). `dead_connection`
    /// is `true` when the connection is already known to be unusable (skip
    /// graceful shutdown chatter). Default: nothing to do.
    fn disconnect<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        dead_connection: bool,
    ) -> ProtoFuture<'a, ()> {
        let _ = (ctx, dead_connection);
        Box::pin(async { Ok(()) })
    }

    /// Let the protocol post-process a chunk of response *body* bytes on their
    /// way to the client (← `write_resp`). `is_eos` marks the final chunk.
    /// Default: pass through unchanged.
    fn write_resp<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        buf: &'a [u8],
        is_eos: bool,
    ) -> ProtoFuture<'a, ()> {
        let _ = (ctx, buf, is_eos);
        Box::pin(async { Ok(()) })
    }

    /// Let the protocol post-process a single response *header* line
    /// (← `write_resp_hd`). `is_eos` marks the final header. Default: pass
    /// through unchanged.
    fn write_resp_hd<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        hd: &'a [u8],
        is_eos: bool,
    ) -> ProtoFuture<'a, ()> {
        let _ = (ctx, hd, is_eos);
        Box::pin(async { Ok(()) })
    }

    /// Liveness/keepalive probe for a pooled connection (← `connection_check`).
    /// `checks` is a bitmask of the checks to perform (curl's
    /// `CONNCHECK_ISDEAD`/`CONNCHECK_KEEPALIVE`); the return is the
    /// `CONNRESULT_*` bitmask of results. Synchronous, like curl. Default: `0`
    /// (no result — treated as alive).
    fn connection_check(&self, ctx: &mut TransferCtx, checks: u32) -> u32 {
        let _ = (ctx, checks);
        0
    }

    /// Associate a transfer with this connection (← `attach`). Synchronous.
    /// Default: nothing to do.
    fn attach(&self, ctx: &mut TransferCtx) {
        let _ = ctx;
    }

    /// Decide whether a redirect/retry to `newurl` (of the given
    /// [`FollowType`]) is followed (← `follow`). Return `Ok(())` to follow;
    /// return an error (curl's `CURLE_TOO_MANY_REDIRECTS`) to refuse. Default:
    /// follow.
    fn follow<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        newurl: &'a str,
        kind: FollowType,
    ) -> ProtoFuture<'a, ()> {
        let _ = (ctx, newurl, kind);
        Box::pin(async { Ok(()) })
    }

    /// Contribute the sockets this protocol wants watched during the generic
    /// transfer phase (← `proto_pollset`). Not overriding leaves the connection
    /// filter chain's generic default in effect. Synchronous.
    fn proto_pollset(&self, ctx: &mut TransferCtx, ps: &mut Pollset) {
        let _ = (ctx, ps);
    }

    /// Contribute desired sockets during the DOING phase (← `doing_pollset`).
    /// Default: none.
    fn doing_pollset(&self, ctx: &mut TransferCtx, ps: &mut Pollset) {
        let _ = (ctx, ps);
    }

    /// Contribute desired sockets during the DO_MORE phase (← `domore_pollset`),
    /// e.g. FTP's second (data) connection. Default: none.
    fn domore_pollset(&self, ctx: &mut TransferCtx, ps: &mut Pollset) {
        let _ = (ctx, ps);
    }

    /// Contribute desired sockets during the PERFORM phase (← `perform_pollset`).
    /// Default: none.
    fn perform_pollset(&self, ctx: &mut TransferCtx, ps: &mut Pollset) {
        let _ = (ctx, ps);
    }
}

// ===========================================================================
// SchemeHandler — a URL-scheme registration record (← `struct Curl_scheme`,
// `lib/urldata.h`).
//
// One `SchemeHandler` per supported scheme, mirroring curl's `Curl_scheme_*`
// constants. It binds the scheme name and its ABI/behavioral metadata to the
// protocol module's handler singleton.
// ===========================================================================

/// A URL-scheme registration record (← `struct Curl_scheme`).
///
/// Combines the scheme's identity/ABI metadata with the [`Protocol`] handler
/// that implements it. Handlers are `'static` singletons owned by the protocol
/// modules; a TLS variant reuses the base scheme's handler (TLS is layered by
/// the connection filter chain), exactly as curl's `Curl_scheme_https` reuses
/// `Curl_protocol_http`.
pub struct SchemeHandler {
    /// The URL scheme name, in lowercase (← `Curl_scheme.name`). Lookup via
    /// [`scheme_handler`] is case-insensitive, so `HTTP`, `Http`, and `http`
    /// all resolve here.
    pub name: &'static str,
    /// This scheme's single `CURLPROTO_*` bit (← `Curl_scheme.protocol`).
    pub protocol: u32,
    /// This scheme's protocol-family `CURLPROTO_*` bit (← `Curl_scheme.family`);
    /// e.g. `https`, `ws`, and `wss` all report the `HTTP` family.
    pub family: u32,
    /// The `PROTOPT_*` characteristic-flags bitset (← `Curl_scheme.flags`).
    pub flags: u32,
    /// The default port used when the URL omits one (← `Curl_scheme.defport`).
    pub defport: u16,
    /// The behavior implementation for this scheme (← `Curl_scheme.run`, the
    /// `struct Curl_protocol *` vtable pointer), or `None` when the record
    /// carries only the scheme's identity/ABI metadata without a bound behavior
    /// vtable. See the module-level *Handler binding*.
    pub handler: Option<&'static (dyn Protocol + 'static)>,
}

impl SchemeHandler {
    /// The transport this scheme's connection uses.
    ///
    /// Derived from the scheme's characteristics rather than stored (curl's
    /// `Curl_scheme` has no transport field; the transport is chosen when the
    /// connection is set up):
    ///
    /// * [`PROTOPT_NONETWORK`] schemes (`file`) use no transport
    ///   ([`Transport::None`]).
    /// * TFTP is datagram-based ([`Transport::Udp`]).
    /// * everything else is stream-based ([`Transport::Tcp`]).
    ///
    /// HTTP/3's QUIC transport is *not* selected here: `https` can negotiate
    /// HTTP/1.1, HTTP/2, or HTTP/3 at connection time, so the QUIC choice is
    /// made inside the `http/` connection setup, not by the scheme.
    #[must_use]
    pub fn transport(&self) -> Transport {
        if self.flags & PROTOPT_NONETWORK != 0 {
            Transport::None
        } else if self.protocol == CURLPROTO_TFTP {
            Transport::Udp
        } else {
            Transport::Tcp
        }
    }

    /// Whether this scheme is a TLS-secured scheme (← the [`PROTOPT_SSL`] flag).
    #[must_use]
    pub fn is_secure(&self) -> bool {
        self.flags & PROTOPT_SSL != 0
    }
}

// ===========================================================================
// Scheme registration table (← the `Curl_scheme_*` constants).
//
// Each record is feature-gated exactly as its C counterpart is guarded by
// `CURL_DISABLE_*` / `USE_*`. `name` is stored lowercase (curl stores `WS`,
// `WSS`, `SFTP`, and `SCP` uppercase, but [`scheme_handler`] matches
// case-insensitively, so the lowercase spelling is behavior-equivalent and
// follows the documented "URL scheme name in lowercase" contract).
//
// Each record carries the scheme's identity/ABI metadata (name, protocol and
// family bits, characteristic flags, default port). The `handler` slot binds
// the scheme to its `&'static dyn Protocol` behavior vtable where that behavior
// exists in this build: the auxiliary application protocols (TFTP, TELNET,
// DICT, LDAP/LDAPS, FILE, GOPHER/GOPHERS, SMB/SMBS, RTSP, MQTT/MQTTS, WS/WSS)
// point at their module's `HANDLER`, each TLS variant sharing its base scheme's
// handler (see the module-level *Handler binding*). The HTTP and FTP/mail
// families keep `handler: None` here until their own handlers are wired.
// ===========================================================================

// --- HTTP family -----------------------------------------------------------

/// `http` (← `Curl_scheme_http`).
#[cfg(feature = "http")]
pub static SCHEME_HTTP: SchemeHandler = SchemeHandler {
    name: "http",
    protocol: CURLPROTO_HTTP,
    family: CURLPROTO_HTTP,
    flags: PROTOPT_CREDSPERREQUEST | PROTOPT_USERPWDCTRL | PROTOPT_CONN_REUSE,
    defport: 80,
    handler: None,
};

/// `https` (← `Curl_scheme_https`).
#[cfg(feature = "http")]
pub static SCHEME_HTTPS: SchemeHandler = SchemeHandler {
    name: "https",
    protocol: CURLPROTO_HTTPS,
    family: CURLPROTO_HTTP,
    flags: PROTOPT_SSL
        | PROTOPT_CREDSPERREQUEST
        | PROTOPT_ALPN
        | PROTOPT_USERPWDCTRL
        | PROTOPT_CONN_REUSE,
    defport: 443,
    handler: None,
};

/// `ws` — WebSocket (← `Curl_scheme_ws`).
#[cfg(feature = "websockets")]
pub static SCHEME_WS: SchemeHandler = SchemeHandler {
    name: "ws",
    protocol: CURLPROTO_WS,
    family: CURLPROTO_HTTP,
    flags: PROTOPT_CREDSPERREQUEST | PROTOPT_USERPWDCTRL,
    defport: 80,
    handler: Some(&ws::HANDLER),
};

/// `wss` — WebSocket over TLS (← `Curl_scheme_wss`).
#[cfg(feature = "websockets")]
pub static SCHEME_WSS: SchemeHandler = SchemeHandler {
    name: "wss",
    protocol: CURLPROTO_WSS,
    family: CURLPROTO_HTTP,
    flags: PROTOPT_SSL | PROTOPT_CREDSPERREQUEST | PROTOPT_USERPWDCTRL,
    defport: 443,
    handler: Some(&ws::HANDLER),
};

// --- FTP family ------------------------------------------------------------

/// `ftp` (← `Curl_scheme_ftp`).
#[cfg(feature = "ftp")]
pub static SCHEME_FTP: SchemeHandler = SchemeHandler {
    name: "ftp",
    protocol: CURLPROTO_FTP,
    family: CURLPROTO_FTP,
    flags: PROTOPT_DUAL
        | PROTOPT_CLOSEACTION
        | PROTOPT_NEEDSPWD
        | PROTOPT_NOURLQUERY
        | PROTOPT_PROXY_AS_HTTP
        | PROTOPT_WILDCARD
        | PROTOPT_SSL_REUSE
        | PROTOPT_CONN_REUSE,
    defport: 21,
    handler: None,
};

/// `ftps` (← `Curl_scheme_ftps`). Note: unlike `ftp`, curl grants `ftps`
/// neither `PROTOPT_PROXY_AS_HTTP` nor `PROTOPT_SSL_REUSE`.
#[cfg(feature = "ftp")]
pub static SCHEME_FTPS: SchemeHandler = SchemeHandler {
    name: "ftps",
    protocol: CURLPROTO_FTPS,
    family: CURLPROTO_FTP,
    flags: PROTOPT_SSL
        | PROTOPT_DUAL
        | PROTOPT_CLOSEACTION
        | PROTOPT_NEEDSPWD
        | PROTOPT_NOURLQUERY
        | PROTOPT_WILDCARD
        | PROTOPT_CONN_REUSE,
    defport: 990,
    handler: None,
};

// --- SSH family (subfolder handlers) ---------------------------------------

/// `sftp` (← `Curl_scheme_sftp`).
#[cfg(feature = "ssh")]
pub static SCHEME_SFTP: SchemeHandler = SchemeHandler {
    name: "sftp",
    protocol: CURLPROTO_SFTP,
    family: CURLPROTO_SFTP,
    flags: PROTOPT_DIRLOCK | PROTOPT_CLOSEACTION | PROTOPT_NOURLQUERY | PROTOPT_CONN_REUSE,
    defport: 22,
    handler: None,
};

/// `scp` (← `Curl_scheme_scp`).
#[cfg(feature = "ssh")]
pub static SCHEME_SCP: SchemeHandler = SchemeHandler {
    name: "scp",
    protocol: CURLPROTO_SCP,
    family: CURLPROTO_SCP,
    flags: PROTOPT_DIRLOCK | PROTOPT_CLOSEACTION | PROTOPT_NOURLQUERY | PROTOPT_CONN_REUSE,
    defport: 22,
    handler: None,
};

// --- Mail protocols --------------------------------------------------------

/// `imap` (← `Curl_scheme_imap`).
#[cfg(feature = "imap")]
pub static SCHEME_IMAP: SchemeHandler = SchemeHandler {
    name: "imap",
    protocol: CURLPROTO_IMAP,
    family: CURLPROTO_IMAP,
    flags: PROTOPT_CLOSEACTION | PROTOPT_URLOPTIONS | PROTOPT_SSL_REUSE | PROTOPT_CONN_REUSE,
    defport: 143,
    handler: None,
};

/// `imaps` (← `Curl_scheme_imaps`).
#[cfg(feature = "imap")]
pub static SCHEME_IMAPS: SchemeHandler = SchemeHandler {
    name: "imaps",
    protocol: CURLPROTO_IMAPS,
    family: CURLPROTO_IMAP,
    flags: PROTOPT_CLOSEACTION | PROTOPT_SSL | PROTOPT_URLOPTIONS | PROTOPT_CONN_REUSE,
    defport: 993,
    handler: None,
};

/// `pop3` (← `Curl_scheme_pop3`).
#[cfg(feature = "pop3")]
pub static SCHEME_POP3: SchemeHandler = SchemeHandler {
    name: "pop3",
    protocol: CURLPROTO_POP3,
    family: CURLPROTO_POP3,
    flags: PROTOPT_CLOSEACTION
        | PROTOPT_NOURLQUERY
        | PROTOPT_URLOPTIONS
        | PROTOPT_SSL_REUSE
        | PROTOPT_CONN_REUSE,
    defport: 110,
    handler: None,
};

/// `pop3s` (← `Curl_scheme_pop3s`).
#[cfg(feature = "pop3")]
pub static SCHEME_POP3S: SchemeHandler = SchemeHandler {
    name: "pop3s",
    protocol: CURLPROTO_POP3S,
    family: CURLPROTO_POP3,
    flags: PROTOPT_CLOSEACTION
        | PROTOPT_SSL
        | PROTOPT_NOURLQUERY
        | PROTOPT_URLOPTIONS
        | PROTOPT_CONN_REUSE,
    defport: 995,
    handler: None,
};

/// `smtp` (← `Curl_scheme_smtp`).
#[cfg(feature = "smtp")]
pub static SCHEME_SMTP: SchemeHandler = SchemeHandler {
    name: "smtp",
    protocol: CURLPROTO_SMTP,
    family: CURLPROTO_SMTP,
    flags: PROTOPT_CLOSEACTION
        | PROTOPT_NOURLQUERY
        | PROTOPT_URLOPTIONS
        | PROTOPT_SSL_REUSE
        | PROTOPT_CONN_REUSE,
    defport: 25,
    handler: None,
};

/// `smtps` (← `Curl_scheme_smtps`).
#[cfg(feature = "smtp")]
pub static SCHEME_SMTPS: SchemeHandler = SchemeHandler {
    name: "smtps",
    protocol: CURLPROTO_SMTPS,
    family: CURLPROTO_SMTP,
    flags: PROTOPT_CLOSEACTION
        | PROTOPT_SSL
        | PROTOPT_NOURLQUERY
        | PROTOPT_URLOPTIONS
        | PROTOPT_CONN_REUSE,
    defport: 465,
    handler: None,
};

// --- Auxiliary protocols ---------------------------------------------------

/// `tftp` (← `Curl_scheme_tftp`).
#[cfg(feature = "tftp")]
pub static SCHEME_TFTP: SchemeHandler = SchemeHandler {
    name: "tftp",
    protocol: CURLPROTO_TFTP,
    family: CURLPROTO_TFTP,
    flags: PROTOPT_NOTCPPROXY | PROTOPT_NOURLQUERY,
    defport: 69,
    handler: Some(&tftp::HANDLER),
};

/// `telnet` (← `Curl_scheme_telnet`).
#[cfg(feature = "telnet")]
pub static SCHEME_TELNET: SchemeHandler = SchemeHandler {
    name: "telnet",
    protocol: CURLPROTO_TELNET,
    family: CURLPROTO_TELNET,
    flags: PROTOPT_NONE | PROTOPT_NOURLQUERY,
    defport: 23,
    handler: Some(&telnet::HANDLER),
};

/// `dict` (← `Curl_scheme_dict`).
#[cfg(feature = "dict")]
pub static SCHEME_DICT: SchemeHandler = SchemeHandler {
    name: "dict",
    protocol: CURLPROTO_DICT,
    family: CURLPROTO_DICT,
    flags: PROTOPT_NONE | PROTOPT_NOURLQUERY,
    defport: 2628,
    handler: Some(&dict::HANDLER),
};

/// `ldap` (← `Curl_scheme_ldap`).
#[cfg(feature = "ldap")]
pub static SCHEME_LDAP: SchemeHandler = SchemeHandler {
    name: "ldap",
    protocol: CURLPROTO_LDAP,
    family: CURLPROTO_LDAP,
    flags: PROTOPT_SSL_REUSE,
    defport: 389,
    handler: Some(&ldap::HANDLER),
};

/// `ldaps` (← `Curl_scheme_ldaps`).
#[cfg(feature = "ldap")]
pub static SCHEME_LDAPS: SchemeHandler = SchemeHandler {
    name: "ldaps",
    protocol: CURLPROTO_LDAPS,
    family: CURLPROTO_LDAP,
    flags: PROTOPT_SSL,
    defport: 636,
    handler: Some(&ldap::HANDLER),
};

/// `file` (← `Curl_scheme_file`).
#[cfg(feature = "file")]
pub static SCHEME_FILE: SchemeHandler = SchemeHandler {
    name: "file",
    protocol: CURLPROTO_FILE,
    family: CURLPROTO_FILE,
    flags: PROTOPT_NONETWORK | PROTOPT_NOURLQUERY,
    defport: 0,
    handler: Some(&file::HANDLER),
};

/// `gopher` (← `Curl_scheme_gopher`).
#[cfg(feature = "gopher")]
pub static SCHEME_GOPHER: SchemeHandler = SchemeHandler {
    name: "gopher",
    protocol: CURLPROTO_GOPHER,
    family: CURLPROTO_GOPHER,
    flags: PROTOPT_NONE,
    defport: 70,
    handler: Some(&gopher::HANDLER),
};

/// `gophers` (← `Curl_scheme_gophers`).
#[cfg(feature = "gopher")]
pub static SCHEME_GOPHERS: SchemeHandler = SchemeHandler {
    name: "gophers",
    protocol: CURLPROTO_GOPHERS,
    family: CURLPROTO_GOPHER,
    flags: PROTOPT_SSL,
    defport: 70,
    handler: Some(&gopher::HANDLER),
};

/// `smb` (← `Curl_scheme_smb`).
#[cfg(feature = "smb")]
pub static SCHEME_SMB: SchemeHandler = SchemeHandler {
    name: "smb",
    protocol: CURLPROTO_SMB,
    family: CURLPROTO_SMB,
    flags: PROTOPT_CONN_REUSE,
    defport: 445,
    handler: Some(&smb::HANDLER),
};

/// `smbs` (← `Curl_scheme_smbs`).
#[cfg(feature = "smb")]
pub static SCHEME_SMBS: SchemeHandler = SchemeHandler {
    name: "smbs",
    protocol: CURLPROTO_SMBS,
    family: CURLPROTO_SMB,
    flags: PROTOPT_SSL | PROTOPT_CONN_REUSE,
    defport: 445,
    handler: Some(&smb::HANDLER),
};

/// `rtsp` (← `Curl_scheme_rtsp`).
#[cfg(feature = "rtsp")]
pub static SCHEME_RTSP: SchemeHandler = SchemeHandler {
    name: "rtsp",
    protocol: CURLPROTO_RTSP,
    family: CURLPROTO_RTSP,
    flags: PROTOPT_CONN_REUSE,
    defport: 554,
    handler: Some(&rtsp::HANDLER),
};

/// `mqtt` (← `Curl_scheme_mqtt`).
#[cfg(feature = "mqtt")]
pub static SCHEME_MQTT: SchemeHandler = SchemeHandler {
    name: "mqtt",
    protocol: CURLPROTO_MQTT,
    family: CURLPROTO_MQTT,
    flags: PROTOPT_NONE,
    defport: 1883,
    handler: Some(&mqtt::HANDLER),
};

/// `mqtts` (← `Curl_scheme_mqtts`). Its protocol bit [`CURLPROTO_MQTTS`] shares
/// value `1 << 30` with [`CURLPROTO_WS`]; the authoritative family for this
/// scheme is nonetheless [`CURLPROTO_MQTT`], recorded directly in `family`.
#[cfg(feature = "mqtt")]
pub static SCHEME_MQTTS: SchemeHandler = SchemeHandler {
    name: "mqtts",
    protocol: CURLPROTO_MQTTS,
    family: CURLPROTO_MQTT,
    flags: PROTOPT_SSL,
    defport: 8883,
    handler: Some(&mqtt::HANDLER),
};

// ===========================================================================
// Scheme lookup + family mapping (← `Curl_get_scheme_handler`,
// `get_protocol_family`).
// ===========================================================================

/// Look up the [`SchemeHandler`] for a URL scheme (← `Curl_get_scheme_handler`).
///
/// Matching is **case-insensitive** — curl accepts `HTTP://`, `Ws://`, etc. An
/// unknown or disabled scheme yields `None`; callers translate that to
/// [`crate::error::CurlCode::UnsupportedProtocol`] (integer value `1`). A scheme
/// whose Cargo feature is disabled is treated exactly like an unknown scheme, so
/// it is not registered here and returns `None`, matching a stock curl build
/// compiled without that protocol.
#[must_use]
pub fn scheme_handler(scheme: &str) -> Option<&'static SchemeHandler> {
    // URL schemes are ASCII (RFC 3986); normalize to lowercase for matching.
    let lower = scheme.to_ascii_lowercase();
    match lower.as_str() {
        #[cfg(feature = "http")]
        "http" => Some(&SCHEME_HTTP),
        #[cfg(feature = "http")]
        "https" => Some(&SCHEME_HTTPS),
        #[cfg(feature = "websockets")]
        "ws" => Some(&SCHEME_WS),
        #[cfg(feature = "websockets")]
        "wss" => Some(&SCHEME_WSS),
        #[cfg(feature = "ftp")]
        "ftp" => Some(&SCHEME_FTP),
        #[cfg(feature = "ftp")]
        "ftps" => Some(&SCHEME_FTPS),
        #[cfg(feature = "ssh")]
        "sftp" => Some(&SCHEME_SFTP),
        #[cfg(feature = "ssh")]
        "scp" => Some(&SCHEME_SCP),
        #[cfg(feature = "imap")]
        "imap" => Some(&SCHEME_IMAP),
        #[cfg(feature = "imap")]
        "imaps" => Some(&SCHEME_IMAPS),
        #[cfg(feature = "pop3")]
        "pop3" => Some(&SCHEME_POP3),
        #[cfg(feature = "pop3")]
        "pop3s" => Some(&SCHEME_POP3S),
        #[cfg(feature = "smtp")]
        "smtp" => Some(&SCHEME_SMTP),
        #[cfg(feature = "smtp")]
        "smtps" => Some(&SCHEME_SMTPS),
        #[cfg(feature = "tftp")]
        "tftp" => Some(&SCHEME_TFTP),
        #[cfg(feature = "telnet")]
        "telnet" => Some(&SCHEME_TELNET),
        #[cfg(feature = "dict")]
        "dict" => Some(&SCHEME_DICT),
        #[cfg(feature = "ldap")]
        "ldap" => Some(&SCHEME_LDAP),
        #[cfg(feature = "ldap")]
        "ldaps" => Some(&SCHEME_LDAPS),
        #[cfg(feature = "file")]
        "file" => Some(&SCHEME_FILE),
        #[cfg(feature = "gopher")]
        "gopher" => Some(&SCHEME_GOPHER),
        #[cfg(feature = "gopher")]
        "gophers" => Some(&SCHEME_GOPHERS),
        #[cfg(feature = "smb")]
        "smb" => Some(&SCHEME_SMB),
        #[cfg(feature = "smb")]
        "smbs" => Some(&SCHEME_SMBS),
        #[cfg(feature = "rtsp")]
        "rtsp" => Some(&SCHEME_RTSP),
        #[cfg(feature = "mqtt")]
        "mqtt" => Some(&SCHEME_MQTT),
        #[cfg(feature = "mqtt")]
        "mqtts" => Some(&SCHEME_MQTTS),
        _ => None,
    }
}

/// Map a single `CURLPROTO_*` protocol bit to its protocol-family bit
/// (← `get_protocol_family`).
///
/// This reproduces the family recorded on each scheme (`Curl_scheme.family`).
/// It is a pure ABI mapping, independent of which Cargo features are enabled.
///
/// Note the one ambiguity inherited from curl's bit layout:
/// [`CURLPROTO_WS`] and [`CURLPROTO_MQTTS`] share value `1 << 30`, so this
/// function cannot tell them apart from the bit alone and resolves it to the
/// `HTTP` family (the WebSocket interpretation). For `mqtts` specifically, the
/// authoritative family is available without ambiguity as
/// [`SCHEME_MQTTS`]`.family` ([`CURLPROTO_MQTT`]). Any unrecognized bit maps to
/// `0`.
#[must_use]
pub fn protocol_family(proto: u32) -> u32 {
    match proto {
        // HTTP family: HTTP, HTTPS, WS (1<<30), WSS (1<<31). CURLPROTO_WS and
        // CURLPROTO_MQTTS collide at 1<<30; WS wins here (see the doc note).
        CURLPROTO_HTTP | CURLPROTO_HTTPS | CURLPROTO_WS | CURLPROTO_WSS => CURLPROTO_HTTP,
        CURLPROTO_FTP | CURLPROTO_FTPS => CURLPROTO_FTP,
        // SFTP and SCP are each their own family (per the scheme records).
        CURLPROTO_SFTP => CURLPROTO_SFTP,
        CURLPROTO_SCP => CURLPROTO_SCP,
        CURLPROTO_IMAP | CURLPROTO_IMAPS => CURLPROTO_IMAP,
        CURLPROTO_POP3 | CURLPROTO_POP3S => CURLPROTO_POP3,
        CURLPROTO_SMTP | CURLPROTO_SMTPS => CURLPROTO_SMTP,
        CURLPROTO_LDAP | CURLPROTO_LDAPS => CURLPROTO_LDAP,
        CURLPROTO_GOPHER | CURLPROTO_GOPHERS => CURLPROTO_GOPHER,
        CURLPROTO_SMB | CURLPROTO_SMBS => CURLPROTO_SMB,
        CURLPROTO_TELNET => CURLPROTO_TELNET,
        CURLPROTO_DICT => CURLPROTO_DICT,
        CURLPROTO_FILE => CURLPROTO_FILE,
        CURLPROTO_TFTP => CURLPROTO_TFTP,
        CURLPROTO_RTSP => CURLPROTO_RTSP,
        // CURLPROTO_MQTT only; MQTTS shares WS's bit and is handled above.
        CURLPROTO_MQTT => CURLPROTO_MQTT,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // `Transport` is only referenced by the transport()-asserting tests, each of
    // which is gated behind its own protocol feature (`http`/`tftp`/`file`). Gate
    // the import identically so a minimal feature set (e.g. `--no-default-features`)
    // does not surface an unused-import warning.
    #[cfg(any(feature = "http", feature = "tftp", feature = "file"))]
    use crate::conn::Transport;
    use crate::error::{CurlCode, Result};
    use std::sync::Arc;

    /// A minimal, dependency-free executor that drives a future to completion.
    ///
    /// Every [`Protocol`] default and the [`MockProto`] futures used here are
    /// ready on the first poll (nothing truly pends), so a no-op waker suffices.
    /// This keeps the tests independent of which Tokio features `curl-rs-lib`
    /// enables and MSRV-safe on Rust 1.75 (`Waker::noop()` only exists from
    /// 1.85). Mirrors the sibling `dns` module's test executor. Fully safe —
    /// `Waker::from(Arc<W: Wake>)` is the safe constructor.
    fn block_on<F: Future>(fut: F) -> F::Output {
        use std::task::{Context, Poll, Wake, Waker};

        struct NoopWake;
        impl Wake for NoopWake {
            fn wake(self: Arc<Self>) {}
        }

        let waker = Waker::from(Arc::new(NoopWake));
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(fut);
        loop {
            if let Poll::Ready(value) = fut.as_mut().poll(&mut cx) {
                return value;
            }
        }
    }

    // A minimal handler implementing only the two required methods, used to
    // prove the trait is object-safe (`&dyn Protocol`) and that all defaults
    // behave.
    struct MockProto;
    impl Protocol for MockProto {
        fn do_it<'a>(&'a self, _ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
            Box::pin(async { Ok(true) })
        }
        fn done<'a>(
            &'a self,
            _ctx: &'a mut TransferCtx,
            _status: Result<()>,
            _premature: bool,
        ) -> ProtoFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn protopt_bit_values_are_frozen() {
        assert_eq!(PROTOPT_NONE, 0);
        assert_eq!(PROTOPT_SSL, 1);
        assert_eq!(PROTOPT_DUAL, 1 << 1);
        assert_eq!(PROTOPT_CLOSEACTION, 1 << 2);
        assert_eq!(PROTOPT_DIRLOCK, 1 << 3);
        assert_eq!(PROTOPT_NONETWORK, 1 << 4);
        assert_eq!(PROTOPT_NEEDSPWD, 1 << 5);
        assert_eq!(PROTOPT_NOURLQUERY, 1 << 6);
        assert_eq!(PROTOPT_CREDSPERREQUEST, 1 << 7);
        assert_eq!(PROTOPT_ALPN, 1 << 8);
        assert_eq!(PROTOPT_URLOPTIONS, 1 << 10);
        assert_eq!(PROTOPT_PROXY_AS_HTTP, 1 << 11);
        assert_eq!(PROTOPT_WILDCARD, 1 << 12);
        assert_eq!(PROTOPT_USERPWDCTRL, 1 << 13);
        assert_eq!(PROTOPT_NOTCPPROXY, 1 << 14);
        assert_eq!(PROTOPT_SSL_REUSE, 1 << 15);
        assert_eq!(PROTOPT_CONN_REUSE, 0x1_0000);
        // Bit 1 << 9 (formerly PROTOPT_STREAM) is intentionally free.
    }

    #[test]
    fn curlproto_bit_values_are_frozen() {
        assert_eq!(CURLPROTO_HTTP, 1 << 0);
        assert_eq!(CURLPROTO_HTTPS, 1 << 1);
        assert_eq!(CURLPROTO_FTP, 1 << 2);
        assert_eq!(CURLPROTO_FTPS, 1 << 3);
        assert_eq!(CURLPROTO_SCP, 1 << 4);
        assert_eq!(CURLPROTO_SFTP, 1 << 5);
        assert_eq!(CURLPROTO_TELNET, 1 << 6);
        assert_eq!(CURLPROTO_LDAP, 1 << 7);
        assert_eq!(CURLPROTO_LDAPS, 1 << 8);
        assert_eq!(CURLPROTO_DICT, 1 << 9);
        assert_eq!(CURLPROTO_FILE, 1 << 10);
        assert_eq!(CURLPROTO_TFTP, 1 << 11);
        assert_eq!(CURLPROTO_IMAP, 1 << 12);
        assert_eq!(CURLPROTO_IMAPS, 1 << 13);
        assert_eq!(CURLPROTO_POP3, 1 << 14);
        assert_eq!(CURLPROTO_POP3S, 1 << 15);
        assert_eq!(CURLPROTO_SMTP, 1 << 16);
        assert_eq!(CURLPROTO_SMTPS, 1 << 17);
        assert_eq!(CURLPROTO_RTSP, 1 << 18);
        assert_eq!(CURLPROTO_GOPHER, 1 << 25);
        assert_eq!(CURLPROTO_SMB, 1 << 26);
        assert_eq!(CURLPROTO_SMBS, 1 << 27);
        assert_eq!(CURLPROTO_MQTT, 1 << 28);
        assert_eq!(CURLPROTO_GOPHERS, 1 << 29);
        assert_eq!(CURLPROTO_MQTTS, 1 << 30);
        assert_eq!(CURLPROTO_WSS, 1 << 31);
        // curl reuses bit 30 for WS and MQTTS; verify the (intentional) overlap.
        assert_eq!(CURLPROTO_WS, CURLPROTO_MQTTS);
    }

    #[test]
    fn curl_poll_values_match_multi_h() {
        assert_eq!(CURL_POLL_NONE, 0);
        assert_eq!(CURL_POLL_IN, 1);
        assert_eq!(CURL_POLL_OUT, 2);
        assert_eq!(CURL_POLL_INOUT, 3);
        assert_eq!(CURL_POLL_REMOVE, 4);
    }

    #[test]
    fn followtype_discriminants_match_c() {
        assert_eq!(FollowType::None as i32, 0);
        assert_eq!(FollowType::Fake as i32, 1);
        assert_eq!(FollowType::Retry as i32, 2);
        assert_eq!(FollowType::Redir as i32, 3);
    }

    #[test]
    fn pollset_add_and_query() {
        let mut ps = Pollset::new();
        assert!(ps.is_empty());
        assert_eq!(ps.len(), 0);

        ps.add_in(5);
        assert_eq!(ps.action_of(5), CURL_POLL_IN);
        ps.add_out(5);
        assert_eq!(ps.action_of(5), CURL_POLL_INOUT);
        assert_eq!(ps.len(), 1);

        ps.add_in(7);
        assert_eq!(ps.len(), 2);
        assert_eq!(ps.action_of(7), CURL_POLL_IN);

        // Unknown socket → NONE.
        assert_eq!(ps.action_of(99), CURL_POLL_NONE);
        assert_eq!(ps.sockets().len(), 2);
    }

    #[test]
    fn pollset_set_removes_on_empty_interest() {
        let mut ps = Pollset::new();
        ps.set(3, CURL_POLL_INOUT);
        assert_eq!(ps.action_of(3), CURL_POLL_INOUT);
        // NONE removes it.
        ps.set(3, CURL_POLL_NONE);
        assert!(ps.is_empty());
        // REMOVE (which carries no IN/OUT bit) also removes.
        ps.set(4, CURL_POLL_IN);
        ps.set(4, CURL_POLL_REMOVE);
        assert!(ps.is_empty());
    }

    #[test]
    fn unknown_and_dropped_schemes_are_none() {
        assert!(scheme_handler("definitely-not-a-scheme").is_none());
        assert!(scheme_handler("").is_none());
        // RTMP family is intentionally dropped from this rewrite.
        for dropped in ["rtmp", "rtmpt", "rtmpe", "rtmpte", "rtmps", "rtmpts"] {
            assert!(
                scheme_handler(dropped).is_none(),
                "{dropped} must not be registered"
            );
        }
        // The unsupported-protocol error code the caller uses is the frozen 1.
        assert_eq!(CurlCode::UnsupportedProtocol.to_i32(), 1);
    }

    #[test]
    fn protocol_family_mapping() {
        assert_eq!(protocol_family(CURLPROTO_HTTP), CURLPROTO_HTTP);
        assert_eq!(protocol_family(CURLPROTO_HTTPS), CURLPROTO_HTTP);
        assert_eq!(protocol_family(CURLPROTO_WS), CURLPROTO_HTTP);
        assert_eq!(protocol_family(CURLPROTO_WSS), CURLPROTO_HTTP);
        assert_eq!(protocol_family(CURLPROTO_FTPS), CURLPROTO_FTP);
        assert_eq!(protocol_family(CURLPROTO_SFTP), CURLPROTO_SFTP);
        assert_eq!(protocol_family(CURLPROTO_SCP), CURLPROTO_SCP);
        assert_eq!(protocol_family(CURLPROTO_IMAPS), CURLPROTO_IMAP);
        assert_eq!(protocol_family(CURLPROTO_POP3S), CURLPROTO_POP3);
        assert_eq!(protocol_family(CURLPROTO_SMTPS), CURLPROTO_SMTP);
        assert_eq!(protocol_family(CURLPROTO_LDAPS), CURLPROTO_LDAP);
        assert_eq!(protocol_family(CURLPROTO_GOPHERS), CURLPROTO_GOPHER);
        assert_eq!(protocol_family(CURLPROTO_SMBS), CURLPROTO_SMB);
        assert_eq!(protocol_family(CURLPROTO_MQTT), CURLPROTO_MQTT);
        assert_eq!(protocol_family(CURLPROTO_RTSP), CURLPROTO_RTSP);
        // Unknown / RTMP bit → 0.
        assert_eq!(protocol_family(1 << 19), 0);
        assert_eq!(protocol_family(0xDEAD_BEEF), 0);
    }

    #[test]
    fn protocol_trait_is_object_safe_and_defaults_work() {
        let mock = MockProto;
        let dynref: &dyn Protocol = &mock;
        let mut ctx = TransferCtx::new();

        // Required methods.
        assert!(block_on(dynref.do_it(&mut ctx)).unwrap());
        assert!(block_on(dynref.done(&mut ctx, Ok(()), false)).is_ok());

        // Async defaults.
        assert!(block_on(dynref.setup_connection(&mut ctx)).is_ok());
        assert!(block_on(dynref.connect(&mut ctx)).unwrap());
        assert!(block_on(dynref.connecting(&mut ctx)).unwrap());
        assert_eq!(block_on(dynref.do_more(&mut ctx)).unwrap(), 0);
        assert!(block_on(dynref.doing(&mut ctx)).unwrap());
        assert!(block_on(dynref.disconnect(&mut ctx, false)).is_ok());
        assert!(block_on(dynref.write_resp(&mut ctx, b"body", false)).is_ok());
        assert!(block_on(dynref.write_resp_hd(&mut ctx, b"H: v", true)).is_ok());
        assert!(block_on(dynref.follow(&mut ctx, "http://e/", FollowType::Redir)).is_ok());

        // Sync defaults.
        assert_eq!(dynref.connection_check(&mut ctx, 0), 0);
        dynref.attach(&mut ctx);
        let mut ps = Pollset::new();
        dynref.proto_pollset(&mut ctx, &mut ps);
        dynref.doing_pollset(&mut ctx, &mut ps);
        dynref.domore_pollset(&mut ctx, &mut ps);
        dynref.perform_pollset(&mut ctx, &mut ps);
        assert!(ps.is_empty());
    }

    #[test]
    fn transfer_ctx_defaults_carry_no_io_sink_and_empty_request() {
        // The enriched context (finding: `TransferCtx` was too thin to let a
        // handler run its exchange) still defaults to "nothing installed yet":
        // no connection, primary socket, no transport, no sink, empty request.
        let ctx = TransferCtx::new();
        assert_eq!(ctx.conn_id, None);
        assert_eq!(ctx.sockindex, 0);
        assert!(ctx.io.is_none());
        assert!(ctx.sink.is_none());
        let r = &ctx.request;
        assert!(r.scheme.is_empty() && r.host.is_empty() && r.path.is_empty());
        assert!(r.url.is_empty() && r.method.is_empty());
        assert_eq!(r.port, 0);
        assert!(r.headers.is_empty() && r.body.is_none() && r.range.is_none());
        assert!(!r.upload && !r.connect_only);
        assert!(r.connect_timeout.is_none() && r.timeout.is_none());
        assert!(r.user.is_none() && r.password.is_none());
        assert_eq!(r.time_condition, 0);
        assert_eq!(r.time_value, 0);
        // The hand-written Debug renders the trait objects as presence markers
        // (they are not `Debug`) and never panics.
        let rendered = format!("{ctx:?}");
        assert!(rendered.contains("TransferCtx") && rendered.contains("request"));
    }

    #[test]
    fn transfer_ctx_accepts_a_boxed_stream_and_sink() {
        // A tokio duplex pipe is a `TransferStream` via the blanket impl, so it
        // boxes into `TransferCtx::io` with no wrapper type. (Constructing the
        // pipe needs no runtime; nothing is polled here.)
        let (client, _server) = tokio::io::duplex(64);
        let mut ctx = TransferCtx::new();
        ctx.io = Some(Box::new(client));
        assert!(ctx.io.is_some());

        // A Vec-backed sink implements the object-safe `TransferSink`.
        struct VecSink(Vec<u8>);
        impl TransferSink for VecSink {
            fn write(&mut self, data: &[u8]) -> Result<()> {
                self.0.extend_from_slice(data);
                Ok(())
            }
        }
        let mut sink = VecSink(Vec::new());
        sink.write(b"abc").unwrap();
        assert_eq!(sink.0, b"abc");
        ctx.sink = Some(Box::new(VecSink(Vec::new())));
        assert!(ctx.sink.is_some());

        // The critical property the handler engines rely on: a
        // `&mut dyn TransferStream` borrowed from `io` satisfies the engines'
        // `AsyncRead + AsyncWrite + Unpin` bound directly (supertraits; no
        // trait upcasting, so this holds on the 1.75 MSRV).
        fn requires_async_rw<S: AsyncRead + AsyncWrite + Unpin>(_: &mut S) {}
        let mut stream = ctx.io.as_deref_mut().unwrap();
        requires_async_rw(&mut stream);
    }

    #[test]
    fn auxiliary_scheme_handlers_are_bound() {
        // Finding: all 15 auxiliary scheme slots were `handler: None`, leaving
        // the schemes registered but unable to dispatch. Each auxiliary scheme
        // present in this build now points at its module `HANDLER`, with the
        // TLS variant sharing its base scheme's handler. Assertions are
        // feature-gated to match the compiled scheme set.
        #[cfg(feature = "tftp")]
        assert!(scheme_handler("tftp").unwrap().handler.is_some());
        #[cfg(feature = "telnet")]
        assert!(scheme_handler("telnet").unwrap().handler.is_some());
        #[cfg(feature = "dict")]
        assert!(scheme_handler("dict").unwrap().handler.is_some());
        #[cfg(feature = "rtsp")]
        assert!(scheme_handler("rtsp").unwrap().handler.is_some());
        #[cfg(feature = "mqtt")]
        {
            assert!(scheme_handler("mqtt").unwrap().handler.is_some());
            assert!(scheme_handler("mqtts").unwrap().handler.is_some());
        }
        #[cfg(feature = "file")]
        assert!(scheme_handler("file").unwrap().handler.is_some());
        #[cfg(feature = "gopher")]
        {
            assert!(scheme_handler("gopher").unwrap().handler.is_some());
            assert!(scheme_handler("gophers").unwrap().handler.is_some());
        }
        #[cfg(feature = "ldap")]
        {
            assert!(scheme_handler("ldap").unwrap().handler.is_some());
            assert!(scheme_handler("ldaps").unwrap().handler.is_some());
        }
        #[cfg(feature = "smb")]
        {
            assert!(scheme_handler("smb").unwrap().handler.is_some());
            assert!(scheme_handler("smbs").unwrap().handler.is_some());
        }
        #[cfg(feature = "websockets")]
        {
            assert!(scheme_handler("ws").unwrap().handler.is_some());
            assert!(scheme_handler("wss").unwrap().handler.is_some());
        }
    }

    #[cfg(feature = "http")]
    #[test]
    fn http_scheme_lookup_is_case_insensitive() {
        for spelling in ["http", "HTTP", "HtTp"] {
            let h = scheme_handler(spelling).expect("http is registered");
            assert_eq!(h.name, "http");
            assert_eq!(h.protocol, CURLPROTO_HTTP);
            assert_eq!(h.family, CURLPROTO_HTTP);
            assert_eq!(h.defport, 80);
            assert_eq!(h.transport(), Transport::Tcp);
            assert!(!h.is_secure());
        }
        let hs = scheme_handler("https").unwrap();
        assert_eq!(hs.protocol, CURLPROTO_HTTPS);
        assert_eq!(hs.family, CURLPROTO_HTTP);
        assert_eq!(hs.defport, 443);
        assert!(hs.is_secure());
        assert_ne!(hs.flags & PROTOPT_ALPN, 0);
    }

    #[cfg(feature = "ftp")]
    #[test]
    fn ftp_and_ftps_flags_match_c() {
        let ftp = scheme_handler("ftp").unwrap();
        assert_eq!(ftp.defport, 21);
        assert_ne!(ftp.flags & PROTOPT_DUAL, 0);
        assert_ne!(ftp.flags & PROTOPT_PROXY_AS_HTTP, 0);
        assert_ne!(ftp.flags & PROTOPT_SSL_REUSE, 0);

        let ftps = scheme_handler("ftps").unwrap();
        assert_eq!(ftps.defport, 990);
        assert!(ftps.is_secure());
        assert_ne!(ftps.flags & PROTOPT_DUAL, 0);
        // Verified against C: ftps carries NEITHER PROXY_AS_HTTP NOR SSL_REUSE.
        assert_eq!(ftps.flags & PROTOPT_PROXY_AS_HTTP, 0);
        assert_eq!(ftps.flags & PROTOPT_SSL_REUSE, 0);
    }

    #[cfg(feature = "pop3")]
    #[test]
    fn pop3_carries_nourlquery() {
        // Verified against C: both pop3 and pop3s set PROTOPT_NOURLQUERY.
        assert_ne!(
            scheme_handler("pop3").unwrap().flags & PROTOPT_NOURLQUERY,
            0
        );
        assert_ne!(
            scheme_handler("pop3s").unwrap().flags & PROTOPT_NOURLQUERY,
            0
        );
        assert_eq!(scheme_handler("pop3").unwrap().defport, 110);
        assert_eq!(scheme_handler("pop3s").unwrap().defport, 995);
    }

    #[cfg(feature = "tftp")]
    #[test]
    fn tftp_uses_udp_transport() {
        let t = scheme_handler("tftp").unwrap();
        assert_eq!(t.defport, 69);
        assert_eq!(t.transport(), Transport::Udp);
    }

    #[cfg(feature = "ssh")]
    #[test]
    fn ssh_schemes_carry_conn_reuse() {
        // C stores the names uppercase ("SFTP"/"SCP"); we store lowercase and
        // match case-insensitively, so an uppercase query still resolves.
        let sftp = scheme_handler("SFTP").unwrap();
        assert_eq!(sftp.name, "sftp");
        assert_eq!(sftp.defport, 22);
        assert_eq!(sftp.family, CURLPROTO_SFTP);
        // Verified against C: sftp/scp set PROTOPT_CONN_REUSE.
        assert_ne!(sftp.flags & PROTOPT_CONN_REUSE, 0);

        let scp = scheme_handler("scp").unwrap();
        assert_eq!(scp.defport, 22);
        assert_eq!(scp.family, CURLPROTO_SCP);
        assert_ne!(scp.flags & PROTOPT_CONN_REUSE, 0);
    }

    #[cfg(feature = "file")]
    #[test]
    fn file_scheme_uses_no_transport() {
        let f = scheme_handler("file").unwrap();
        assert_eq!(f.defport, 0);
        assert_eq!(f.transport(), Transport::None);
        assert_ne!(f.flags & PROTOPT_NONETWORK, 0);
    }

    #[cfg(feature = "websockets")]
    #[test]
    fn websocket_schemes_report_http_family() {
        assert_eq!(scheme_handler("ws").unwrap().family, CURLPROTO_HTTP);
        let wss = scheme_handler("WSS").unwrap();
        assert_eq!(wss.name, "wss");
        assert_eq!(wss.family, CURLPROTO_HTTP);
        assert!(wss.is_secure());
    }

    #[cfg(feature = "mqtt")]
    #[test]
    fn mqtts_family_is_mqtt_despite_ws_bit_overlap() {
        let mqtts = scheme_handler("mqtts").unwrap();
        assert_eq!(mqtts.protocol, CURLPROTO_MQTTS);
        // Authoritative family for mqtts is MQTT, recorded directly, even though
        // its protocol bit collides with CURLPROTO_WS.
        assert_eq!(mqtts.family, CURLPROTO_MQTT);
        assert_eq!(mqtts.defport, 8883);
        assert!(mqtts.is_secure());
    }
}
