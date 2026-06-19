#![forbid(unsafe_code)]

//! Protocol engines — the `protocols/` subtree root, `Protocol` trait, and the
//! scheme registry.
//!
//! This is the **capstone + foundation** of the per-protocol layer. It hosts the
//! pieces every protocol module builds on:
//!
//! * The async [`Protocol`] trait — the Rust analog of curl's C
//!   `struct Curl_protocol` function-pointer vtable (`lib/urldata.h`). Each
//!   protocol module implements it; the engine dispatches through `&dyn Protocol`
//!   / `Box<dyn Protocol>` trait objects instead of a C dispatch table
//!   (AAP §0.4.3 — "trait-based protocol dispatch").
//! * The lightweight [`Scheme`] descriptor — the Rust analog of C
//!   `struct Curl_scheme` (the value that wraps a `Curl_protocol` vtable with a
//!   name, the `CURLPROTO_*` protocol/family bits, the `PROTOPT_*` flags, and a
//!   default port).
//! * The [`PROTOPT_NONE`]…[`PROTOPT_CONN_REUSE`] flag family, the
//!   [`CURLPROTO_HTTP`]…[`CURLPROTO_MQTTS`] protocol-bit family (public ABI), and
//!   the per-scheme default-port constants.
//! * The scheme → handler [`scheme_handler`] / scheme → descriptor
//!   [`scheme_descriptor`] **registry / dispatch** — the idiomatic analog of
//!   `lib/url.c`'s `all_schemes[]` table plus `Curl_get_scheme_handler` /
//!   `findprotocol` (a case-insensitive lookup, *not* the C perfect-hash).
//!
//! It also declares every sibling protocol module with `pub mod`, each behind
//! the Cargo feature that mirrors curl's `CURL_DISABLE_*` compile gate.
//!
//! # How a protocol runs
//!
//! A protocol never touches sockets or the event loop directly. The asynchronous
//! transfer engine ([`crate::transfer`]) drives a handler over the
//! connection-filter chain ([`crate::conn::Connection`]): the engine decides
//! *when* a protocol's state machine advances while the handler decides *how*.
//! Because curl's re-entrant `connecting()` / `doing()` / `*_done`-out-param /
//! `*_pollset()` machinery exists only to cooperate with a hand-rolled
//! `select`/`poll` loop, it collapses here into ordinary `async fn … .await`:
//! Tokio drives readiness, so there are **no** file-descriptor pollsets and the
//! four C `*_pollset` callbacks have no analog (they are deliberately omitted —
//! see [`Protocol`]).
//!
//! # The `Scheme` / `Protocol` split (mirrors C two-level structure)
//!
//! curl models a scheme in two levels: a `struct Curl_scheme` value (name, bits,
//! flags, port) that *embeds a pointer* (`run`) to a `struct Curl_protocol`
//! vtable. We keep the same split: [`Scheme`] is a pure [`Copy`] value type that
//! carries **no** reference to the [`Protocol`] trait object, and the registry
//! functions here play the role of the C `run` pointer (name → handler). Keeping
//! `Scheme` free of any trait-object reference is what lets
//! [`crate::conn::Connection`] embed a lightweight scheme descriptor without a
//! `conn → protocols` import cycle (AAP §0.5.2).
//!
//! # Disconnect inversion (no `conn → protocols` cycle)
//!
//! A protocol's [`Protocol::disconnect`] cleans up its session (FTP `QUIT`, IMAP
//! `LOGOUT`, …). The engine does **not** let [`crate::conn`] call back into
//! `protocols`; instead it registers the disconnect as a boxed-async
//! `disconnect_hook` on the [`crate::conn::Connection`]
//! ([`crate::conn::Connection::set_disconnect_hook`]) and the connection
//! shutdown path runs that hook. This dependency inversion keeps
//! `protocols → conn` acyclic.
//!
//! # Capability / scheme lockstep (parity-critical, AAP §0.7.3)
//!
//! [`supported_schemes`] MUST enumerate exactly the same scheme set, gated by
//! exactly the same Cargo features, as [`crate::version::protocols`]. curl's
//! `runtests` harness selects the protocol-specific subset of `tests/data` from
//! `curl_version_info()`, so any divergence silently runs the wrong tests. The
//! `pub mod` gates below and the registry table are kept in lockstep with
//! `crate::version`; a unit test asserts the two lists are byte-for-byte equal.
//!
//! # Memory safety
//!
//! The protocol layer is pure, allocation-safe Rust with no operating-system
//! pointer handling (sockets and raw file-descriptor work live in
//! [`crate::conn`]), so this subtree opts into `#![forbid(unsafe_code)]` at its
//! root (mandated by AAP §0.7.1, which names the protocol module root
//! explicitly). The attribute propagates to every descendant module, making the
//! "zero `unsafe` outside the FFI crate" rule compiler-enforced across the whole
//! protocol tree; descendant leaf modules therefore do **not** re-declare it.

use std::sync::OnceLock;

use crate::conn::{BoxFuture, Connection};
use crate::easy::Easy;
use crate::error::{CurlError, Result};

// The redirect-reason enum is owned by the transfer engine (curl's `followtype`,
// `lib/transfer.rs`); re-export it so the [`Protocol::follow`] hook and protocol
// implementations name a single canonical type rather than a duplicate.
pub use crate::transfer::FollowType;

// ===========================================================================
// Sibling protocol-module declarations.
//
// Every per-protocol module named in AAP §0.4.1 is declared here, each behind
// the Cargo feature that mirrors curl's `CURL_DISABLE_<PROTO>` compile gate so
// that disabling a feature compiles the protocol out entirely (matching curl's
// default build when every default feature is on).
//
// LOCKSTEP (AAP §0.7.3): the cfg-gated module set here, the registry
// `SCHEME_TABLE` below, and `crate::version::protocols()` / the `HTTP2`/`HTTP3`
// capability bits MUST all describe the same enabled protocol set. The
// `s`-variant schemes (https, ftps, imaps, …) are NOT separate modules — they
// are served by their base module — and in the registry they are gated by the
// SAME feature as their plaintext sibling (https→`http`, ftps→`ftp`, …), exactly
// as `crate::version::protocols()` gates them. Edit this file and
// `crate::version` together.
// ===========================================================================

/// The HTTP protocol family (HTTP/1.1, HTTP/2, HTTP/3 plus the shared codecs).
/// curl `CURL_DISABLE_HTTP`. HTTP is always on in curl's default build.
#[cfg(feature = "http")]
pub mod http;

// ---------------------------------------------------------------------------
// Construction-order staging: the protocol modules below are forward-declared
// by this module's design but their source files are authored in a later step
// of the migration sequence. Their `#[cfg(feature = "...")] pub mod` lines are
// commented out until each module file lands; re-enable a declaration (strip
// the leading `// `) at the moment its `.rs` file is added. Only `http` is
// implemented so far. This keeps the crate building while preserving the full
// protocol registry/dispatch infrastructure defined further down in this file.
// ---------------------------------------------------------------------------
/// The pingpong command/response state machine shared by the line-based
/// protocols (`lib/pingpong.c`); used by FTP and the mail family. Compiled when
/// any of those protocols is enabled, mirroring curl's `lib/pingpong.c` guard.
#[cfg(any(feature = "ftp", feature = "imap", feature = "pop3", feature = "smtp"))]
pub mod pingpong;

// /// FTP / FTPS (`lib/ftp.c`). curl `CURL_DISABLE_FTP`.
// #[cfg(feature = "ftp")]
// pub mod ftp;

/// FTP `LIST` response parser (`lib/ftplistparser.c`); part of the FTP feature.
#[cfg(feature = "ftp")]
pub mod ftp_list;

// /// IMAP / IMAPS (`lib/imap.c`). curl `CURL_DISABLE_IMAP`.
// #[cfg(feature = "imap")]
// pub mod imap;

// /// POP3 / POP3S (`lib/pop3.c`). curl `CURL_DISABLE_POP3`.
// #[cfg(feature = "pop3")]
// pub mod pop3;

// /// SMTP / SMTPS (`lib/smtp.c`). curl `CURL_DISABLE_SMTP`.
// #[cfg(feature = "smtp")]
// pub mod smtp;

/// RTSP (`lib/rtsp.c`). curl `CURL_DISABLE_RTSP`.
#[cfg(feature = "rtsp")]
pub mod rtsp;

/// MQTT / MQTTS (`lib/mqtt.c`). curl `CURL_DISABLE_MQTT`.
#[cfg(feature = "mqtt")]
pub mod mqtt;

// /// WebSocket `ws` / `wss` (`lib/ws.c`). curl `CURL_DISABLE_WEBSOCKETS`.
// #[cfg(feature = "websockets")]
// pub mod ws;

/// TELNET (`lib/telnet.c`). curl `CURL_DISABLE_TELNET`.
#[cfg(feature = "telnet")]
pub mod telnet;

/// TFTP (`lib/tftp.c`). curl `CURL_DISABLE_TFTP`.
#[cfg(feature = "tftp")]
pub mod tftp;

/// GOPHER / GOPHERS (`lib/gopher.c`). curl `CURL_DISABLE_GOPHER`.
#[cfg(feature = "gopher")]
pub mod gopher;

/// SMB / SMBS (`lib/smb.c`). curl `CURL_DISABLE_SMB` **and** `USE_CURL_NTLM_CORE`
/// — SMB authenticates with NTLM, so the C source compiles `lib/smb.c` only when
/// both `!CURL_DISABLE_SMB` and `USE_CURL_NTLM_CORE` hold. We mirror that with a
/// combined `smb` + `ntlm` feature gate (the `smb`/`smbs` *schemes* stay
/// registered in [`SCHEME_TABLE`] whenever `smb` is on, but their handler is only
/// available when `ntlm` is also on — exactly as curl's `Curl_scheme_smb` keeps
/// the scheme but sets the protocol vtable to `ZERO_NULL` without NTLM).
#[cfg(all(feature = "smb", feature = "ntlm"))]
pub mod smb;

/// DICT (`lib/dict.c`). curl `CURL_DISABLE_DICT`.
#[cfg(feature = "dict")]
pub mod dict;

// /// FILE (`lib/file.c`). curl `CURL_DISABLE_FILE`.
// #[cfg(feature = "file")]
// pub mod file;

/// LDAP / LDAPS (`lib/ldap.c`, `lib/openldap.c`). curl `CURL_DISABLE_LDAP`.
#[cfg(feature = "ldap")]
pub mod ldap;

// /// The SSH family — SFTP and SCP (`lib/vssh/`). Compiled when either SSH-based
// /// scheme is enabled. curl `USE_SSH` (`CURL_DISABLE_*` per scheme).
// ///
// /// Construction-order staging: the `ssh` module root (`ssh/mod.rs`) is present
// /// and complete, but it forward-declares its `scp` and `sftp` submodules whose
// /// source files (`ssh/scp.rs`, `ssh/sftp.rs`) are authored in a later step. Per
// /// the staging convention above, `pub mod ssh;` stays commented until those
// /// submodule files land — re-enable it (and the SCP/SFTP `scheme_handler` arms
// /// below) at that moment. Until then `scp`/`sftp` remain registered schemes in
// /// `SCHEME_TABLE` and dispatch to the stub handler, exactly like the other
// /// not-yet-completed protocols above.
// #[cfg(any(feature = "scp", feature = "sftp"))]
// pub mod ssh;

// ===========================================================================
// `PROTOPT_*` — per-scheme capability flags (C `Curl_scheme.flags`).
//
// Exact bit values from `lib/urldata.h` L526-558 (a `u32` bitset). `PROTOPT_NONE`
// and the four flags already centralized by `crate::conn` (`NONE`, `SSL`,
// `DUAL`, `NONETWORK`) are RE-EXPORTED from there rather than redefined, so
// there is a single source of truth and no risk of drift; the remaining flags
// are defined here. Note that bit 9 (`1 << 9`) is intentionally unused in curl
// — there is a gap between `PROTOPT_ALPN` (1 << 8) and `PROTOPT_URLOPTIONS`
// (1 << 10).
// ===========================================================================

pub use crate::conn::{PROTOPT_DUAL, PROTOPT_NONE, PROTOPT_NONETWORK, PROTOPT_SSL};

/// Connection needs an action (e.g. FTP `QUIT`, IMAP `LOGOUT`) before the
/// socket is closed (`urldata.h` `PROTOPT_CLOSEACTION`).
pub const PROTOPT_CLOSEACTION: u32 = 1 << 2;
/// The protocol needs a "directory lock" during a transfer (the SSH family)
/// (`urldata.h` `PROTOPT_DIRLOCK`).
pub const PROTOPT_DIRLOCK: u32 = 1 << 3;
/// The protocol needs a password, and if none is set curl supplies a default
/// (FTP) (`urldata.h` `PROTOPT_NEEDSPWD`).
pub const PROTOPT_NEEDSPWD: u32 = 1 << 5;
/// The protocol cannot handle a URL query (`?…`) part (`urldata.h`
/// `PROTOPT_NOURLQUERY`).
pub const PROTOPT_NOURLQUERY: u32 = 1 << 6;
/// The protocol requires login credentials per request rather than per
/// connection (HTTP, WebSocket) (`urldata.h` `PROTOPT_CREDSPERREQUEST`).
pub const PROTOPT_CREDSPERREQUEST: u32 = 1 << 7;
/// Set ALPN for this scheme during the TLS handshake (HTTPS) (`urldata.h`
/// `PROTOPT_ALPN`).
pub const PROTOPT_ALPN: u32 = 1 << 8;
/// The scheme allows an `;options` part in the userinfo (IMAP/POP3/SMTP)
/// (`urldata.h` `PROTOPT_URLOPTIONS`). Bit 9 is intentionally skipped in curl.
pub const PROTOPT_URLOPTIONS: u32 = 1 << 10;
/// This non-HTTP scheme may be tunneled over an HTTP proxy (FTP) (`urldata.h`
/// `PROTOPT_PROXY_AS_HTTP`).
pub const PROTOPT_PROXY_AS_HTTP: u32 = 1 << 11;
/// The protocol supports wildcard matching (FTP globbing) (`urldata.h`
/// `PROTOPT_WILDCARD`).
pub const PROTOPT_WILDCARD: u32 = 1 << 12;
/// Allow control bytes (`< 0x20` ASCII) in the user/password (FTP) (`urldata.h`
/// `PROTOPT_USERPWDCTRL`).
pub const PROTOPT_USERPWDCTRL: u32 = 1 << 13;
/// This protocol cannot be proxied over TCP (TFTP, which is UDP) (`urldata.h`
/// `PROTOPT_NOTCPPROXY`).
pub const PROTOPT_NOTCPPROXY: u32 = 1 << 14;
/// The protocol may reuse an existing TLS-based connection (IMAP/POP3/SMTP/FTP/
/// LDAP) (`urldata.h` `PROTOPT_SSL_REUSE`).
pub const PROTOPT_SSL_REUSE: u32 = 1 << 15;
/// The protocol can reuse connections (`urldata.h` `PROTOPT_CONN_REUSE`).
pub const PROTOPT_CONN_REUSE: u32 = 1 << 16;

// ===========================================================================
// `CURLPROTO_*` — the protocol identifier bits.
//
// The bits 1<<0 … 1<<30 plus `CURLPROTO_ALL` are part of the PUBLIC libcurl ABI
// (`include/curl/curl.h` L1076-1107) and are reproduced here with their exact
// values; they back `CURLOPT_PROTOCOLS_STR`, `CURLINFO_PROTOCOL`, and the
// `Curl_scheme.protocol` / `Curl_scheme.family` bits. `curl_prot_t` is a
// `uint32_t` in this build (`PROTO_TYPE_SMALL`), so all values are `u32`.
//
// `CURLPROTO_WS` / `CURLPROTO_WSS` are INTERNAL (defined in `lib/urldata.h`
// L70-71, NOT in the public header): WebSocket handlers use them in their
// `protocol` field while their `family` stays `CURLPROTO_HTTP`. WS reuses bit
// 30 (the same bit as the public `CURLPROTO_MQTTS`) and WSS uses bit 31 — see
// the note on `CURLPROTO_WS`.
//
// The RTMP family (1<<19 … 1<<24) is part of the public ABI and is defined for
// completeness, but RTMP is OUT OF SCOPE (AAP §0.3.2): there is no handler and
// no `rtmp*` entry in the scheme registry.
// ===========================================================================

/// `CURLPROTO_HTTP` — HTTP (`curl.h` 1 << 0).
pub const CURLPROTO_HTTP: u32 = 1 << 0;
/// `CURLPROTO_HTTPS` — HTTPS (`curl.h` 1 << 1).
pub const CURLPROTO_HTTPS: u32 = 1 << 1;
/// `CURLPROTO_FTP` — FTP (`curl.h` 1 << 2).
pub const CURLPROTO_FTP: u32 = 1 << 2;
/// `CURLPROTO_FTPS` — FTPS (`curl.h` 1 << 3).
pub const CURLPROTO_FTPS: u32 = 1 << 3;
/// `CURLPROTO_SCP` — SCP (`curl.h` 1 << 4).
pub const CURLPROTO_SCP: u32 = 1 << 4;
/// `CURLPROTO_SFTP` — SFTP (`curl.h` 1 << 5).
pub const CURLPROTO_SFTP: u32 = 1 << 5;
/// `CURLPROTO_TELNET` — TELNET (`curl.h` 1 << 6).
pub const CURLPROTO_TELNET: u32 = 1 << 6;
/// `CURLPROTO_LDAP` — LDAP (`curl.h` 1 << 7).
pub const CURLPROTO_LDAP: u32 = 1 << 7;
/// `CURLPROTO_LDAPS` — LDAPS (`curl.h` 1 << 8).
pub const CURLPROTO_LDAPS: u32 = 1 << 8;
/// `CURLPROTO_DICT` — DICT (`curl.h` 1 << 9).
pub const CURLPROTO_DICT: u32 = 1 << 9;
/// `CURLPROTO_FILE` — FILE (`curl.h` 1 << 10).
pub const CURLPROTO_FILE: u32 = 1 << 10;
/// `CURLPROTO_TFTP` — TFTP (`curl.h` 1 << 11).
pub const CURLPROTO_TFTP: u32 = 1 << 11;
/// `CURLPROTO_IMAP` — IMAP (`curl.h` 1 << 12).
pub const CURLPROTO_IMAP: u32 = 1 << 12;
/// `CURLPROTO_IMAPS` — IMAPS (`curl.h` 1 << 13).
pub const CURLPROTO_IMAPS: u32 = 1 << 13;
/// `CURLPROTO_POP3` — POP3 (`curl.h` 1 << 14).
pub const CURLPROTO_POP3: u32 = 1 << 14;
/// `CURLPROTO_POP3S` — POP3S (`curl.h` 1 << 15).
pub const CURLPROTO_POP3S: u32 = 1 << 15;
/// `CURLPROTO_SMTP` — SMTP (`curl.h` 1 << 16).
pub const CURLPROTO_SMTP: u32 = 1 << 16;
/// `CURLPROTO_SMTPS` — SMTPS (`curl.h` 1 << 17).
pub const CURLPROTO_SMTPS: u32 = 1 << 17;
/// `CURLPROTO_RTSP` — RTSP (`curl.h` 1 << 18).
pub const CURLPROTO_RTSP: u32 = 1 << 18;
/// `CURLPROTO_RTMP` — RTMP (`curl.h` 1 << 19). Defined for ABI completeness;
/// RTMP is out of scope (no handler).
pub const CURLPROTO_RTMP: u32 = 1 << 19;
/// `CURLPROTO_RTMPT` — RTMPT (`curl.h` 1 << 20). ABI-only (out of scope).
pub const CURLPROTO_RTMPT: u32 = 1 << 20;
/// `CURLPROTO_RTMPE` — RTMPE (`curl.h` 1 << 21). ABI-only (out of scope).
pub const CURLPROTO_RTMPE: u32 = 1 << 21;
/// `CURLPROTO_RTMPTE` — RTMPTE (`curl.h` 1 << 22). ABI-only (out of scope).
pub const CURLPROTO_RTMPTE: u32 = 1 << 22;
/// `CURLPROTO_RTMPS` — RTMPS (`curl.h` 1 << 23). ABI-only (out of scope).
pub const CURLPROTO_RTMPS: u32 = 1 << 23;
/// `CURLPROTO_RTMPTS` — RTMPTS (`curl.h` 1 << 24). ABI-only (out of scope).
pub const CURLPROTO_RTMPTS: u32 = 1 << 24;
/// `CURLPROTO_GOPHER` — GOPHER (`curl.h` 1 << 25).
pub const CURLPROTO_GOPHER: u32 = 1 << 25;
/// `CURLPROTO_SMB` — SMB (`curl.h` 1 << 26).
pub const CURLPROTO_SMB: u32 = 1 << 26;
/// `CURLPROTO_SMBS` — SMBS (`curl.h` 1 << 27).
pub const CURLPROTO_SMBS: u32 = 1 << 27;
/// `CURLPROTO_MQTT` — MQTT (`curl.h` 1 << 28).
pub const CURLPROTO_MQTT: u32 = 1 << 28;
/// `CURLPROTO_GOPHERS` — GOPHERS (`curl.h` 1 << 29). The highest *publicly*
/// used protocol bit number.
pub const CURLPROTO_GOPHERS: u32 = 1 << 29;
/// `CURLPROTO_MQTTS` — MQTTS (`curl.h` 1 << 30).
pub const CURLPROTO_MQTTS: u32 = 1 << 30;

/// `CURLPROTO_WS` — WebSocket (INTERNAL, `lib/urldata.h` 1 << 30).
///
/// This is **not** in the public header. It deliberately shares bit 30 with the
/// public [`CURLPROTO_MQTTS`]: bits above [`CURLPROTO_GOPHERS`] (29) are
/// internal-only, and a connection never carries both a WebSocket and an MQTTS
/// handler, so the overlap is unobservable. A WebSocket scheme's `family` is
/// [`CURLPROTO_HTTP`], not `CURLPROTO_WS`.
pub const CURLPROTO_WS: u32 = 1 << 30;
/// `CURLPROTO_WSS` — secure WebSocket (INTERNAL, `lib/urldata.h` 1 << 31 =
/// `0x8000_0000`). Not in the public header; its `family` is
/// [`CURLPROTO_HTTP`].
pub const CURLPROTO_WSS: u32 = 1 << 31;

/// `CURLPROTO_ALL` — enable every protocol (`curl.h` `0xffffffff`).
pub const CURLPROTO_ALL: u32 = 0xffff_ffff;

// ===========================================================================
// Default-port constants (C `PORT_*`, `lib/urldata.h` L29-53).
//
// Named for clarity and used by the `SCHEME_*` descriptors below; `crate::url`
// keeps its own copy for URL parsing, and the values are identical.
// ===========================================================================

/// FTP default port (21).
pub const DEFAULT_PORT_FTP: u16 = 21;
/// FTPS default port (990).
pub const DEFAULT_PORT_FTPS: u16 = 990;
/// SSH (SCP/SFTP) default port (22).
pub const DEFAULT_PORT_SSH: u16 = 22;
/// TELNET default port (23).
pub const DEFAULT_PORT_TELNET: u16 = 23;
/// SMTP default port (25).
pub const DEFAULT_PORT_SMTP: u16 = 25;
/// TFTP default port (69).
pub const DEFAULT_PORT_TFTP: u16 = 69;
/// GOPHER (and GOPHERS) default port (70).
pub const DEFAULT_PORT_GOPHER: u16 = 70;
/// HTTP (and `ws`) default port (80).
pub const DEFAULT_PORT_HTTP: u16 = 80;
/// POP3 default port (110).
pub const DEFAULT_PORT_POP3: u16 = 110;
/// IMAP default port (143).
pub const DEFAULT_PORT_IMAP: u16 = 143;
/// LDAP default port (389).
pub const DEFAULT_PORT_LDAP: u16 = 389;
/// HTTPS (and `wss`) default port (443).
pub const DEFAULT_PORT_HTTPS: u16 = 443;
/// SMTPS default port (465).
pub const DEFAULT_PORT_SMTPS: u16 = 465;
/// SMB (and SMBS) default port (445).
pub const DEFAULT_PORT_SMB: u16 = 445;
/// RTSP default port (554).
pub const DEFAULT_PORT_RTSP: u16 = 554;
/// LDAPS default port (636).
pub const DEFAULT_PORT_LDAPS: u16 = 636;
/// IMAPS default port (993).
pub const DEFAULT_PORT_IMAPS: u16 = 993;
/// POP3S default port (995).
pub const DEFAULT_PORT_POP3S: u16 = 995;
/// MQTT default port (1883).
pub const DEFAULT_PORT_MQTT: u16 = 1883;
/// DICT default port (2628).
pub const DEFAULT_PORT_DICT: u16 = 2628;
/// MQTTS default port (8883).
pub const DEFAULT_PORT_MQTTS: u16 = 8883;

// ===========================================================================
// `Scheme` — the lightweight scheme descriptor (C `struct Curl_scheme`).
// ===========================================================================

/// A URL scheme descriptor — the Rust analog of C `struct Curl_scheme`
/// (`lib/urldata.h`), minus the `run` vtable pointer (whose role the registry
/// functions [`scheme_handler`] / [`scheme_descriptor`] play).
///
/// It is a pure [`Copy`] value type carrying only data — the scheme `name`, the
/// single [`CURLPROTO_HTTP`]-style `protocol` bit, the `family` bit (the
/// non-TLS protocol this is a member of), the [`PROTOPT_NONE`]-style `flags`,
/// and the `default_port`. Holding **no** reference to the [`Protocol`] trait
/// object is deliberate: it lets [`crate::conn::Connection`] embed a copy of a
/// scheme's data without importing `crate::protocols`, keeping the
/// `protocols → conn` dependency acyclic (AAP §0.5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Scheme {
    /// The scheme name in lower case (e.g. `"https"`); C `Curl_scheme.name`.
    pub name: &'static str,
    /// The single protocol bit (a `CURLPROTO_*` value); C
    /// `Curl_scheme.protocol`.
    pub protocol: u32,
    /// The protocol-family bit — the non-TLS protocol this scheme belongs to
    /// (e.g. `https`'s family is [`CURLPROTO_HTTP`]); C `Curl_scheme.family`.
    pub family: u32,
    /// The `PROTOPT_*` capability bitset; C `Curl_scheme.flags`.
    pub flags: u32,
    /// The default port (`0` for network-less schemes such as `file`); C
    /// `Curl_scheme.defport`.
    pub default_port: u16,
}

impl Scheme {
    /// Whether the scheme uses TLS ([`PROTOPT_SSL`]).
    #[must_use]
    pub const fn is_ssl(&self) -> bool {
        (self.flags & PROTOPT_SSL) != 0
    }

    /// Whether the scheme uses no network at all ([`PROTOPT_NONETWORK`], e.g.
    /// `file`).
    #[must_use]
    pub const fn is_nonetwork(&self) -> bool {
        (self.flags & PROTOPT_NONETWORK) != 0
    }

    /// Whether the scheme uses a second (data) connection ([`PROTOPT_DUAL`],
    /// e.g. FTP).
    #[must_use]
    pub const fn uses_dual(&self) -> bool {
        (self.flags & PROTOPT_DUAL) != 0
    }

    /// Whether the scheme requires credentials, supplying a default if none is
    /// set ([`PROTOPT_NEEDSPWD`], e.g. FTP).
    #[must_use]
    pub const fn needs_password(&self) -> bool {
        (self.flags & PROTOPT_NEEDSPWD) != 0
    }

    /// Whether the scheme can reuse connections ([`PROTOPT_CONN_REUSE`]).
    #[must_use]
    pub const fn can_reuse(&self) -> bool {
        (self.flags & PROTOPT_CONN_REUSE) != 0
    }

    /// Whether the scheme accepts a URL `;options` part ([`PROTOPT_URLOPTIONS`],
    /// the IMAP/POP3/SMTP family).
    #[must_use]
    pub const fn allows_url_options(&self) -> bool {
        (self.flags & PROTOPT_URLOPTIONS) != 0
    }
}

// ---------------------------------------------------------------------------
// The `SCHEME_*` descriptors. Every value (protocol/family bits, `PROTOPT_*`
// flags, default port) is reproduced EXACTLY from the corresponding C
// `const struct Curl_scheme Curl_scheme_<name>` in its protocol `.c` file
// (parity-critical: these drive proxy behavior, connection reuse, credential
// prompting, wildcard globbing, and TLS). `PROTOPT_NONE` is `0`, so
// `PROTOPT_NONE | X == X`; it is written explicitly only where the C source
// writes it.
// ---------------------------------------------------------------------------

/// `dict://` — `lib/dict.c` `Curl_scheme_dict`.
pub const SCHEME_DICT: Scheme = Scheme {
    name: "dict",
    protocol: CURLPROTO_DICT,
    family: CURLPROTO_DICT,
    flags: PROTOPT_NONE | PROTOPT_NOURLQUERY,
    default_port: DEFAULT_PORT_DICT,
};

/// `file://` — `lib/file.c` `Curl_scheme_file`.
pub const SCHEME_FILE: Scheme = Scheme {
    name: "file",
    protocol: CURLPROTO_FILE,
    family: CURLPROTO_FILE,
    flags: PROTOPT_NONETWORK | PROTOPT_NOURLQUERY,
    default_port: 0,
};

/// `ftp://` — `lib/ftp.c` `Curl_scheme_ftp`.
pub const SCHEME_FTP: Scheme = Scheme {
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
    default_port: DEFAULT_PORT_FTP,
};

/// `ftps://` — `lib/ftp.c` `Curl_scheme_ftps`. Note: relative to `ftp` this
/// adds [`PROTOPT_SSL`] but DROPS `PROTOPT_PROXY_AS_HTTP` and
/// `PROTOPT_SSL_REUSE` (exactly as the C source does).
pub const SCHEME_FTPS: Scheme = Scheme {
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
    default_port: DEFAULT_PORT_FTPS,
};

/// `gopher://` — `lib/gopher.c` `Curl_scheme_gopher`.
pub const SCHEME_GOPHER: Scheme = Scheme {
    name: "gopher",
    protocol: CURLPROTO_GOPHER,
    family: CURLPROTO_GOPHER,
    flags: PROTOPT_NONE,
    default_port: DEFAULT_PORT_GOPHER,
};

/// `gophers://` — `lib/gopher.c` `Curl_scheme_gophers` (default port stays 70).
pub const SCHEME_GOPHERS: Scheme = Scheme {
    name: "gophers",
    protocol: CURLPROTO_GOPHERS,
    family: CURLPROTO_GOPHER,
    flags: PROTOPT_SSL,
    default_port: DEFAULT_PORT_GOPHER,
};

/// `http://` — `lib/http.c` `Curl_scheme_http`.
pub const SCHEME_HTTP: Scheme = Scheme {
    name: "http",
    protocol: CURLPROTO_HTTP,
    family: CURLPROTO_HTTP,
    flags: PROTOPT_CREDSPERREQUEST | PROTOPT_USERPWDCTRL | PROTOPT_CONN_REUSE,
    default_port: DEFAULT_PORT_HTTP,
};

/// `https://` — `lib/http.c` `Curl_scheme_https`.
pub const SCHEME_HTTPS: Scheme = Scheme {
    name: "https",
    protocol: CURLPROTO_HTTPS,
    family: CURLPROTO_HTTP,
    flags: PROTOPT_SSL
        | PROTOPT_CREDSPERREQUEST
        | PROTOPT_ALPN
        | PROTOPT_USERPWDCTRL
        | PROTOPT_CONN_REUSE,
    default_port: DEFAULT_PORT_HTTPS,
};

/// `imap://` — `lib/imap.c` `Curl_scheme_imap`.
pub const SCHEME_IMAP: Scheme = Scheme {
    name: "imap",
    protocol: CURLPROTO_IMAP,
    family: CURLPROTO_IMAP,
    flags: PROTOPT_CLOSEACTION | PROTOPT_URLOPTIONS | PROTOPT_SSL_REUSE | PROTOPT_CONN_REUSE,
    default_port: DEFAULT_PORT_IMAP,
};

/// `imaps://` — `lib/imap.c` `Curl_scheme_imaps`.
pub const SCHEME_IMAPS: Scheme = Scheme {
    name: "imaps",
    protocol: CURLPROTO_IMAPS,
    family: CURLPROTO_IMAP,
    flags: PROTOPT_CLOSEACTION | PROTOPT_SSL | PROTOPT_URLOPTIONS | PROTOPT_CONN_REUSE,
    default_port: DEFAULT_PORT_IMAPS,
};

/// `ldap://` — `lib/openldap.c` `Curl_scheme_ldap`.
pub const SCHEME_LDAP: Scheme = Scheme {
    name: "ldap",
    protocol: CURLPROTO_LDAP,
    family: CURLPROTO_LDAP,
    flags: PROTOPT_SSL_REUSE,
    default_port: DEFAULT_PORT_LDAP,
};

/// `ldaps://` — `lib/openldap.c` `Curl_scheme_ldaps`.
pub const SCHEME_LDAPS: Scheme = Scheme {
    name: "ldaps",
    protocol: CURLPROTO_LDAPS,
    family: CURLPROTO_LDAP,
    flags: PROTOPT_SSL,
    default_port: DEFAULT_PORT_LDAPS,
};

/// `mqtt://` — `lib/mqtt.c` `Curl_scheme_mqtt`.
pub const SCHEME_MQTT: Scheme = Scheme {
    name: "mqtt",
    protocol: CURLPROTO_MQTT,
    family: CURLPROTO_MQTT,
    flags: PROTOPT_NONE,
    default_port: DEFAULT_PORT_MQTT,
};

/// `mqtts://` — `lib/mqtt.c` `Curl_scheme_mqtts`.
pub const SCHEME_MQTTS: Scheme = Scheme {
    name: "mqtts",
    protocol: CURLPROTO_MQTTS,
    family: CURLPROTO_MQTT,
    flags: PROTOPT_SSL,
    default_port: DEFAULT_PORT_MQTTS,
};

/// `pop3://` — `lib/pop3.c` `Curl_scheme_pop3`.
pub const SCHEME_POP3: Scheme = Scheme {
    name: "pop3",
    protocol: CURLPROTO_POP3,
    family: CURLPROTO_POP3,
    flags: PROTOPT_CLOSEACTION
        | PROTOPT_NOURLQUERY
        | PROTOPT_URLOPTIONS
        | PROTOPT_SSL_REUSE
        | PROTOPT_CONN_REUSE,
    default_port: DEFAULT_PORT_POP3,
};

/// `pop3s://` — `lib/pop3.c` `Curl_scheme_pop3s`.
pub const SCHEME_POP3S: Scheme = Scheme {
    name: "pop3s",
    protocol: CURLPROTO_POP3S,
    family: CURLPROTO_POP3,
    flags: PROTOPT_CLOSEACTION
        | PROTOPT_SSL
        | PROTOPT_NOURLQUERY
        | PROTOPT_URLOPTIONS
        | PROTOPT_CONN_REUSE,
    default_port: DEFAULT_PORT_POP3S,
};

/// `rtsp://` — `lib/rtsp.c` `Curl_scheme_rtsp`.
pub const SCHEME_RTSP: Scheme = Scheme {
    name: "rtsp",
    protocol: CURLPROTO_RTSP,
    family: CURLPROTO_RTSP,
    flags: PROTOPT_CONN_REUSE,
    default_port: DEFAULT_PORT_RTSP,
};

/// `scp://` — `lib/vssh/vssh.c` `Curl_scheme_scp`.
pub const SCHEME_SCP: Scheme = Scheme {
    name: "scp",
    protocol: CURLPROTO_SCP,
    family: CURLPROTO_SCP,
    flags: PROTOPT_DIRLOCK | PROTOPT_CLOSEACTION | PROTOPT_NOURLQUERY | PROTOPT_CONN_REUSE,
    default_port: DEFAULT_PORT_SSH,
};

/// `sftp://` — `lib/vssh/vssh.c` `Curl_scheme_sftp` (identical flags to `scp`).
pub const SCHEME_SFTP: Scheme = Scheme {
    name: "sftp",
    protocol: CURLPROTO_SFTP,
    family: CURLPROTO_SFTP,
    flags: PROTOPT_DIRLOCK | PROTOPT_CLOSEACTION | PROTOPT_NOURLQUERY | PROTOPT_CONN_REUSE,
    default_port: DEFAULT_PORT_SSH,
};

/// `smb://` — `lib/smb.c` `Curl_scheme_smb`.
pub const SCHEME_SMB: Scheme = Scheme {
    name: "smb",
    protocol: CURLPROTO_SMB,
    family: CURLPROTO_SMB,
    flags: PROTOPT_CONN_REUSE,
    default_port: DEFAULT_PORT_SMB,
};

/// `smbs://` — `lib/smb.c` `Curl_scheme_smbs` (default port stays 445).
pub const SCHEME_SMBS: Scheme = Scheme {
    name: "smbs",
    protocol: CURLPROTO_SMBS,
    family: CURLPROTO_SMB,
    flags: PROTOPT_SSL | PROTOPT_CONN_REUSE,
    default_port: DEFAULT_PORT_SMB,
};

/// `smtp://` — `lib/smtp.c` `Curl_scheme_smtp`.
pub const SCHEME_SMTP: Scheme = Scheme {
    name: "smtp",
    protocol: CURLPROTO_SMTP,
    family: CURLPROTO_SMTP,
    flags: PROTOPT_CLOSEACTION
        | PROTOPT_NOURLQUERY
        | PROTOPT_URLOPTIONS
        | PROTOPT_SSL_REUSE
        | PROTOPT_CONN_REUSE,
    default_port: DEFAULT_PORT_SMTP,
};

/// `smtps://` — `lib/smtp.c` `Curl_scheme_smtps`.
pub const SCHEME_SMTPS: Scheme = Scheme {
    name: "smtps",
    protocol: CURLPROTO_SMTPS,
    family: CURLPROTO_SMTP,
    flags: PROTOPT_CLOSEACTION
        | PROTOPT_SSL
        | PROTOPT_NOURLQUERY
        | PROTOPT_URLOPTIONS
        | PROTOPT_CONN_REUSE,
    default_port: DEFAULT_PORT_SMTPS,
};

/// `telnet://` — `lib/telnet.c` `Curl_scheme_telnet`.
pub const SCHEME_TELNET: Scheme = Scheme {
    name: "telnet",
    protocol: CURLPROTO_TELNET,
    family: CURLPROTO_TELNET,
    flags: PROTOPT_NONE | PROTOPT_NOURLQUERY,
    default_port: DEFAULT_PORT_TELNET,
};

/// `tftp://` — `lib/tftp.c` `Curl_scheme_tftp`.
pub const SCHEME_TFTP: Scheme = Scheme {
    name: "tftp",
    protocol: CURLPROTO_TFTP,
    family: CURLPROTO_TFTP,
    flags: PROTOPT_NOTCPPROXY | PROTOPT_NOURLQUERY,
    default_port: DEFAULT_PORT_TFTP,
};

/// `ws://` — `lib/ws.c` `Curl_scheme_ws`. Its `family` is [`CURLPROTO_HTTP`]
/// (WebSocket is layered over HTTP); the default port is 80.
pub const SCHEME_WS: Scheme = Scheme {
    name: "ws",
    protocol: CURLPROTO_WS,
    family: CURLPROTO_HTTP,
    flags: PROTOPT_CREDSPERREQUEST | PROTOPT_USERPWDCTRL,
    default_port: DEFAULT_PORT_HTTP,
};

/// `wss://` — `lib/ws.c` `Curl_scheme_wss`. Its `family` is [`CURLPROTO_HTTP`];
/// the default port is 443.
pub const SCHEME_WSS: Scheme = Scheme {
    name: "wss",
    protocol: CURLPROTO_WSS,
    family: CURLPROTO_HTTP,
    flags: PROTOPT_SSL | PROTOPT_CREDSPERREQUEST | PROTOPT_USERPWDCTRL,
    default_port: DEFAULT_PORT_HTTPS,
};

// ===========================================================================
// `ProtocolTransfer` — the transfer descriptor returned by `Protocol::do_it`.
// ===========================================================================

/// The direction(s) of body data a transfer moves once a protocol's request has
/// been issued — the safe analog of curl's per-transfer download/upload state
/// bits (`conn->bits.upload` / the keepon read/write flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransferDirection {
    /// No body transfer — a command-only exchange (e.g. an FTP control command,
    /// an SMTP `NOOP`).
    #[default]
    None,
    /// The client is downloading a response body from the server.
    Download,
    /// The client is uploading a request body to the server.
    Upload,
    /// Both directions are active simultaneously (a duplex exchange).
    Bidirectional,
}

/// A description of the transfer a protocol's [`Protocol::do_it`] has set up,
/// handed back to the transfer engine so it can drive the byte loop.
///
/// This is a *descriptor*, not the byte stream itself: the engine pumps bytes
/// through the [`crate::transfer::ProtocolExchange`] contract and the
/// [`crate::conn::Connection`] filter chain, while this struct tells it the
/// shape of what to expect — the [`TransferDirection`], the expected size if the
/// protocol knows it up front (curl's `k->size`, `None` for "unknown", curl's
/// `-1`), and whether a response carries protocol headers the client-writer must
/// parse (curl's `k->getheader`). Keeping it a plain owned value (no borrows, no
/// trait object) lets `do_it` return it across the `async` boundary cheaply.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProtocolTransfer {
    /// Which direction(s) of body data this transfer moves.
    pub direction: TransferDirection,
    /// The expected transfer size in bytes if known up front, else `None`
    /// (curl's `k->size == -1`).
    pub expected_size: Option<u64>,
    /// Whether the response carries protocol headers the client-writer chain
    /// must parse (curl's `k->getheader`).
    pub has_response_headers: bool,
}

impl ProtocolTransfer {
    /// A transfer in the given direction with an unknown size and no response
    /// headers — the common starting point a protocol then refines.
    #[must_use]
    pub const fn new(direction: TransferDirection) -> Self {
        Self {
            direction,
            expected_size: None,
            has_response_headers: false,
        }
    }

    /// Builder-style: set the expected size (in bytes).
    #[must_use]
    pub const fn with_size(mut self, size: u64) -> Self {
        self.expected_size = Some(size);
        self
    }

    /// Builder-style: mark that the response carries parseable protocol headers.
    #[must_use]
    pub const fn with_response_headers(mut self, has_headers: bool) -> Self {
        self.has_response_headers = has_headers;
        self
    }
}

// ===========================================================================
// `Protocol` — the per-protocol engine trait (C `struct Curl_protocol`).
// ===========================================================================

/// The asynchronous per-protocol engine — the Rust analog of curl's C
/// `struct Curl_protocol` function-pointer vtable (`lib/urldata.h`).
///
/// Every protocol module implements `Protocol` for its handler type, and the
/// transfer engine dispatches through `&dyn Protocol` / [`Box<dyn Protocol>`]
/// instead of a C dispatch table. A handler is **stateless** — all per-transfer
/// and per-connection state lives in the [`Easy`] handle and the
/// [`Connection`], exactly as the C callbacks take `Curl_easy *` and
/// `connectdata *` rather than a `self`. This keeps handlers cheaply shareable
/// (a zero-sized singleton can serve every transfer of its scheme).
///
/// # Async convention
///
/// The I/O-bearing methods return a [`BoxFuture`] (the crate's object-safe
/// async-trait convention, matching [`crate::conn`]'s `ConnectionFilter`), so
/// the trait stays object-safe for `Box<dyn Protocol>`. curl's re-entrant
/// `connecting()` / `doing()` loops and the four `*_pollset()` callbacks exist
/// only to cooperate with a hand-rolled `select`/`poll` loop; under Tokio they
/// collapse into `async fn … .await`, so:
///
/// * `connect_it` + the `connecting` loop fuse into [`connect`](Protocol::connect),
/// * `do_it` + the `doing` loop fuse into [`do_it`](Protocol::do_it), and
/// * the `proto_pollset` / `doing_pollset` / `domore_pollset` /
///   `perform_pollset` callbacks are **omitted entirely** (Tokio drives
///   readiness — there are no file-descriptor pollsets).
///
/// # Disconnect inversion
///
/// [`disconnect`](Protocol::disconnect) is how a protocol tears down its session
/// (FTP `QUIT`, IMAP `LOGOUT`). To keep `conn` free of any dependency on
/// `protocols`, the engine registers this as a boxed-async `disconnect_hook` on
/// the [`Connection`] (via [`crate::conn::Connection::set_disconnect_hook`]) and
/// the connection-shutdown path invokes it — `conn` never calls back into
/// `protocols`.
///
/// # Defaults
///
/// Every method except [`scheme`](Protocol::scheme) has a default so a
/// not-yet-implemented protocol can be a compiling stub: the lifecycle hooks
/// default to success/no-op, [`do_it`](Protocol::do_it) defaults to
/// [`CurlError::UnsupportedProtocol`], and the response-interception hooks
/// default to "not handled" so the engine uses its generic path.
pub trait Protocol: Send + Sync {
    /// The static [`Scheme`] descriptor this handler serves (name, port, flags,
    /// protocol/family bits). The only required method.
    fn scheme(&self) -> &'static Scheme;

    /// Pre-transfer per-handle setup, before the transfer "owns" the connection
    /// (C `setup_connection`). Allocate any protocol state on the handle here.
    /// Defaults to success.
    fn setup_connection<'a>(
        &'a self,
        _data: &'a mut Easy,
        _conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { Ok(()) })
    }

    /// Establish the protocol session over an already-connected filter chain
    /// (C `connect_it` fused with the `connecting` loop): e.g. read the FTP
    /// greeting and log in, or issue IMAP `CAPABILITY`. Returns once the session
    /// is fully established. Defaults to success (protocols with nothing to do
    /// at connect time, such as `file`).
    fn connect<'a>(
        &'a self,
        _data: &'a mut Easy,
        _conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { Ok(()) })
    }

    /// Issue the request and describe the transfer to drive (C `do_it` fused
    /// with the `doing` loop). Returns a [`ProtocolTransfer`] telling the engine
    /// the direction, expected size, and whether the response carries headers.
    ///
    /// **Required behavior**, but defaulted to [`CurlError::UnsupportedProtocol`]
    /// so a stub protocol still compiles; every real protocol overrides it.
    fn do_it<'a>(
        &'a self,
        _data: &'a mut Easy,
        _conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<ProtocolTransfer>> {
        Box::pin(async move { Err(CurlError::UnsupportedProtocol) })
    }

    /// The optional second half of `do_it` (C `do_more`): used by FTP to set up
    /// the data connection after `PASV`/`PORT`. Defaults to success.
    fn do_more<'a>(
        &'a self,
        _data: &'a mut Easy,
        _conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { Ok(()) })
    }

    /// Post-transfer finalization (C `done`): read a final status line, flush
    /// state, etc. `status` is the transfer's result so far and `premature` is
    /// `true` if the transfer is ending early (e.g. aborted). Defaults to
    /// success.
    fn done<'a>(
        &'a self,
        _data: &'a mut Easy,
        _conn: &'a mut Connection,
        _status: Result<()>,
        _premature: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { Ok(()) })
    }

    /// Tear down the protocol session (C `disconnect`): FTP `QUIT`, IMAP
    /// `LOGOUT`, etc. `dead` is `true` when the connection is already considered
    /// dead (skip graceful shutdown chatter). Defaults to a no-op.
    ///
    /// The engine registers this as the [`Connection`]'s boxed-async
    /// `disconnect_hook` (see the trait-level "Disconnect inversion" note);
    /// implementations should not assume they are called synchronously from the
    /// transfer path.
    fn disconnect<'a>(
        &'a self,
        _data: &'a mut Easy,
        _conn: &'a mut Connection,
        _dead: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { Ok(()) })
    }

    /// Protocol-specific interception of response **body** bytes as they are
    /// written to the client (C `write_resp`). Return `Ok(true)` if the protocol
    /// fully handled `buf`, or `Ok(false)` (the default) to let the engine's
    /// generic client-writer path handle it. `is_eos` marks the final chunk.
    fn write_resp(&self, _data: &mut Easy, _buf: &[u8], _is_eos: bool) -> Result<bool> {
        Ok(false)
    }

    /// Protocol-specific interception of a single response **header** line
    /// (C `write_resp_hd`). Return `Ok(true)` if handled, else `Ok(false)` (the
    /// default). `is_eos` marks the final header.
    fn write_resp_hd(&self, _data: &mut Easy, _hd: &[u8], _is_eos: bool) -> Result<bool> {
        Ok(false)
    }

    /// Perform connection liveness/health checks (C `connection_check`):
    /// `checks` is a `CONNCHECK_*` bitset and the return value is a
    /// `CONNRESULT_*` bitset. Defaults to `0` (no result bits).
    fn connection_check(&self, _data: &mut Easy, _conn: &mut Connection, _checks: u32) -> u32 {
        0
    }

    /// Associate this transfer with this connection (C `attach`). Defaults to a
    /// no-op.
    fn attach(&self, _data: &mut Easy, _conn: &mut Connection) {}

    /// Redirect policy hook (C `follow`): decide whether a redirect to `newurl`
    /// of the given [`FollowType`] should be followed, returning `Ok(())` to
    /// follow or [`CurlError::TooManyRedirects`] to refuse, and optionally
    /// adjusting `data` to shape the follow request. Defaults to allowing the
    /// follow; HTTP overrides it with curl's full `Curl_http_follow` policy.
    fn follow<'a>(
        &'a self,
        _data: &'a mut Easy,
        _newurl: &'a str,
        _follow_type: FollowType,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { Ok(()) })
    }
}

// ===========================================================================
// Scheme registry / dispatch — the idiomatic analog of `lib/url.c`'s
// `all_schemes[]` table plus `Curl_get_scheme` / `findprotocol`.
//
// curl uses a build-time perfect hash over a fixed `all_schemes[]` array; we
// use a feature-gated `&'static [Scheme]` table and a case-insensitive linear
// scan. The table is small (≤27 entries) so the scan is negligible, and it
// avoids both the perfect-hash build step and any `unsafe`.
//
// (!) LOCKSTEP: the cfg-gated set below MUST equal `crate::version::protocols()`
// and the `CURL_VERSION_HTTP2` / `CURL_VERSION_HTTP3` capability bits. The
// `runtests` harness selects protocol test cases from `curl_version_info`, so a
// mismatch silently runs the wrong test subset (AAP §0.7.3). The table is in the
// SAME alphabetical order and uses the SAME feature gates (each `s`-variant
// gated by its base feature) as `crate::version::protocols()`; edit the two
// together.
// ===========================================================================

/// The compiled-in scheme table, in the exact alphabetical order — and gated by
/// the exact same Cargo features — as [`crate::version::protocols()`].
///
/// Each TLS (`s`-suffixed) variant is gated by its **base** protocol feature
/// (e.g. `ftps` is gated by `feature = "ftp"`, `https` by `feature = "http"`),
/// mirroring curl's build, where enabling a protocol enables its TLS variant.
/// RTMP is intentionally absent: its `CURLPROTO_*` bits exist for ABI
/// completeness but it has no handler and is out of scope (AAP §0.3.2).
static SCHEME_TABLE: &[Scheme] = &[
    #[cfg(feature = "dict")]
    SCHEME_DICT,
    #[cfg(feature = "file")]
    SCHEME_FILE,
    #[cfg(feature = "ftp")]
    SCHEME_FTP,
    #[cfg(feature = "ftp")]
    SCHEME_FTPS,
    #[cfg(feature = "gopher")]
    SCHEME_GOPHER,
    #[cfg(feature = "gopher")]
    SCHEME_GOPHERS,
    #[cfg(feature = "http")]
    SCHEME_HTTP,
    #[cfg(feature = "http")]
    SCHEME_HTTPS,
    #[cfg(feature = "imap")]
    SCHEME_IMAP,
    #[cfg(feature = "imap")]
    SCHEME_IMAPS,
    #[cfg(feature = "ldap")]
    SCHEME_LDAP,
    #[cfg(feature = "ldap")]
    SCHEME_LDAPS,
    #[cfg(feature = "mqtt")]
    SCHEME_MQTT,
    #[cfg(feature = "mqtt")]
    SCHEME_MQTTS,
    #[cfg(feature = "pop3")]
    SCHEME_POP3,
    #[cfg(feature = "pop3")]
    SCHEME_POP3S,
    #[cfg(feature = "rtsp")]
    SCHEME_RTSP,
    #[cfg(feature = "scp")]
    SCHEME_SCP,
    #[cfg(feature = "sftp")]
    SCHEME_SFTP,
    #[cfg(feature = "smb")]
    SCHEME_SMB,
    #[cfg(feature = "smb")]
    SCHEME_SMBS,
    #[cfg(feature = "smtp")]
    SCHEME_SMTP,
    #[cfg(feature = "smtp")]
    SCHEME_SMTPS,
    #[cfg(feature = "telnet")]
    SCHEME_TELNET,
    #[cfg(feature = "tftp")]
    SCHEME_TFTP,
    #[cfg(feature = "websockets")]
    SCHEME_WS,
    #[cfg(feature = "websockets")]
    SCHEME_WSS,
];

/// A self-contained placeholder [`Protocol`] handler returned by
/// [`scheme_handler`] for a recognized scheme whose dedicated handler has not
/// yet been wired into the registry.
///
/// It carries the scheme's [`Scheme`] descriptor (so `scheme()` is correct and
/// callers can read flags/ports/bits) and inherits every default trait method —
/// most importantly [`Protocol::do_it`], which yields
/// [`CurlError::UnsupportedProtocol`]. This mirrors curl's behavior of
/// recognizing a scheme while reporting it unsupported when the corresponding
/// handler is unavailable, and lets the registry compile and dispatch standalone
/// while the per-protocol modules are authored.
struct StubProtocol {
    scheme: &'static Scheme,
}

impl Protocol for StubProtocol {
    fn scheme(&self) -> &'static Scheme {
        self.scheme
    }
}

/// Look up the static [`Scheme`] descriptor for a URL scheme name,
/// case-insensitively (the analog of resolving an entry in `all_schemes[]`).
///
/// Returns `None` for unknown schemes and for schemes whose feature is disabled
/// (e.g. `"rtmp"`, which has no handler in any build). Used by [`crate::url`]
/// for default-port assignment and by [`crate::conn`] for the lightweight scheme
/// descriptor it embeds on a connection.
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::protocols::scheme_descriptor;
/// let https = scheme_descriptor("HTTPS").expect("https is a default scheme");
/// assert_eq!(https.default_port, 443);
/// assert!(scheme_descriptor("rtmp").is_none());
/// ```
#[must_use]
pub fn scheme_descriptor(scheme_name: &str) -> Option<&'static Scheme> {
    SCHEME_TABLE
        .iter()
        .find(|scheme| scheme.name.eq_ignore_ascii_case(scheme_name))
}

/// Resolve a URL scheme name to its [`Protocol`] handler, case-insensitively —
/// the central dispatch the transfer engine uses to pick a handler by scheme
/// (the analog of curl's `Curl_get_scheme` returning a `Curl_handler`).
///
/// Returns `None` exactly when [`scheme_descriptor`] does (unknown scheme, or a
/// scheme whose feature is disabled). For a recognized scheme whose engine has
/// landed, the protocol's own handler constructor is returned; the remaining
/// recognized schemes fall back to a [`StubProtocol`] bound to the scheme's
/// descriptor. Because the stub inherits the trait's default [`Protocol::do_it`],
/// invoking a transfer on a not-yet-implemented protocol yields
/// [`CurlError::UnsupportedProtocol`] rather than a panic.
///
/// The SSH family (`scp`/`sftp`) dispatches to the real handlers in
/// [`crate::protocols::ssh`]; each arm is feature-gated identically to the
/// scheme's presence in [`SCHEME_TABLE`], so dispatch and descriptor resolution
/// stay in lockstep.
#[must_use]
pub fn scheme_handler(scheme_name: &str) -> Option<Box<dyn Protocol>> {
    let scheme = scheme_descriptor(scheme_name)?;
    // SMB / SMBS are served by [`smb::SmbProtocol`] when both the `smb` scheme
    // and the `ntlm` auth core are compiled in (curl's
    // `!CURL_DISABLE_SMB && USE_CURL_NTLM_CORE`). Without `ntlm` the scheme stays
    // recognized but unsupported (the stub), mirroring curl's `ZERO_NULL` vtable.
    #[cfg(all(feature = "smb", feature = "ntlm"))]
    {
        if scheme.name == SCHEME_SMB.name {
            return Some(Box::new(smb::SmbProtocol::new(&SCHEME_SMB)) as Box<dyn Protocol>);
        }
        if scheme.name == SCHEME_SMBS.name {
            return Some(Box::new(smb::SmbProtocol::new(&SCHEME_SMBS)) as Box<dyn Protocol>);
        }
    }

    // TELNET is implemented (`telnet::Telnet`, `lib/telnet.c`).
    #[cfg(feature = "telnet")]
    {
        if scheme.name == SCHEME_TELNET.name {
            return Some(Box::new(telnet::Telnet::new()) as Box<dyn Protocol>);
        }
    }

    let handler: Box<dyn Protocol> = match scheme.name {
        // TFTP has a full handler (`lib/tftp.c`).
        #[cfg(feature = "tftp")]
        "tftp" => Box::new(tftp::TftpHandler::new()),
        // LDAP and LDAPS share the single `ldap::LdapHandler`, distinguished by
        // the scheme descriptor it carries.
        #[cfg(feature = "ldap")]
        "ldap" | "ldaps" => Box::new(ldap::LdapHandler::new(scheme)),
        // MQTT / MQTTS are fully implemented (`lib/mqtt.c` analog).
        #[cfg(feature = "mqtt")]
        "mqtt" | "mqtts" => Box::new(mqtt::MqttProtocol::new(scheme)),
        // SCP / SFTP — the pure-Rust `russh`-backed engines (`lib/vssh/`). Staged
        // off together with `pub mod ssh;` above until `ssh/scp.rs` and
        // `ssh/sftp.rs` land; `scp`/`sftp` fall through to the stub handler in the
        // meantime (they stay registered in `SCHEME_TABLE`).
        // #[cfg(feature = "scp")]
        // "scp" => ssh::scp_handler(),
        // #[cfg(feature = "sftp")]
        // "sftp" => ssh::sftp_handler(),
        // Every other recognized scheme falls back to the self-contained stub
        // until its dedicated handler is wired in.
        _ => Box::new(StubProtocol { scheme }),
    };
    Some(handler)
}

/// The sorted list of scheme names compiled into this build, in the exact order
/// and set reported by [`crate::version::protocols()`].
///
/// **This list MUST stay in lockstep with [`crate::version`]** — `runtests`
/// selects which protocol test cases to run from `curl_version_info`, so any
/// divergence silently runs the wrong subset of the parity suite (AAP §0.7.3).
/// The names are derived from [`SCHEME_TABLE`], which is feature-gated
/// identically to `crate::version::protocols()`.
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::protocols::supported_schemes;
/// assert!(supported_schemes().contains(&"https"));
/// assert!(!supported_schemes().contains(&"rtmp"));
/// ```
#[must_use]
pub fn supported_schemes() -> &'static [&'static str] {
    static NAMES: OnceLock<Vec<&'static str>> = OnceLock::new();
    NAMES
        .get_or_init(|| SCHEME_TABLE.iter().map(|scheme| scheme.name).collect())
        .as_slice()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Constant ABI parity — `CURLPROTO_*` bits are PUBLIC values that must
    // match `include/curl/curl.h` exactly.
    // -----------------------------------------------------------------------
    #[test]
    fn curlproto_bits_match_public_abi() {
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
        assert_eq!(CURLPROTO_RTMP, 1 << 19);
        assert_eq!(CURLPROTO_RTMPT, 1 << 20);
        assert_eq!(CURLPROTO_RTMPE, 1 << 21);
        assert_eq!(CURLPROTO_RTMPTE, 1 << 22);
        assert_eq!(CURLPROTO_RTMPS, 1 << 23);
        assert_eq!(CURLPROTO_RTMPTS, 1 << 24);
        assert_eq!(CURLPROTO_GOPHER, 1 << 25);
        assert_eq!(CURLPROTO_SMB, 1 << 26);
        assert_eq!(CURLPROTO_SMBS, 1 << 27);
        assert_eq!(CURLPROTO_MQTT, 1 << 28);
        assert_eq!(CURLPROTO_GOPHERS, 1 << 29);
        assert_eq!(CURLPROTO_MQTTS, 1 << 30);
        assert_eq!(CURLPROTO_ALL, 0xffff_ffff);
    }

    #[test]
    fn curlproto_ws_is_internal_bit_30_31() {
        // WS/WSS are internal (NOT in the public `CURLPROTO_*` ABI). WS shares
        // bit 30 with the public MQTTS (curl's `curl_prot_t` is a u32 and the
        // websockets bits reuse the high end); WSS occupies bit 31.
        assert_eq!(CURLPROTO_WS, 1 << 30);
        assert_eq!(CURLPROTO_WSS, 1 << 31);
        assert_eq!(CURLPROTO_WS, CURLPROTO_MQTTS, "documented bit-30 overlap");
    }

    // -----------------------------------------------------------------------
    // `PROTOPT_*` bit values, including the intentional bit-9 gap.
    // -----------------------------------------------------------------------
    #[test]
    fn protopt_bits_match_oracle() {
        assert_eq!(PROTOPT_NONE, 0);
        assert_eq!(PROTOPT_SSL, 1 << 0);
        assert_eq!(PROTOPT_DUAL, 1 << 1);
        assert_eq!(PROTOPT_CLOSEACTION, 1 << 2);
        assert_eq!(PROTOPT_DIRLOCK, 1 << 3);
        assert_eq!(PROTOPT_NONETWORK, 1 << 4);
        assert_eq!(PROTOPT_NEEDSPWD, 1 << 5);
        assert_eq!(PROTOPT_NOURLQUERY, 1 << 6);
        assert_eq!(PROTOPT_CREDSPERREQUEST, 1 << 7);
        assert_eq!(PROTOPT_ALPN, 1 << 8);
        // bit 9 (`PROTOPT_STREAM` in old curl) is intentionally unused here.
        assert_eq!(PROTOPT_URLOPTIONS, 1 << 10);
        assert_eq!(PROTOPT_PROXY_AS_HTTP, 1 << 11);
        assert_eq!(PROTOPT_WILDCARD, 1 << 12);
        assert_eq!(PROTOPT_USERPWDCTRL, 1 << 13);
        assert_eq!(PROTOPT_NOTCPPROXY, 1 << 14);
        assert_eq!(PROTOPT_SSL_REUSE, 1 << 15);
        assert_eq!(PROTOPT_CONN_REUSE, 1 << 16);
    }

    // -----------------------------------------------------------------------
    // Default-port constants.
    // -----------------------------------------------------------------------
    #[test]
    fn default_ports_match_oracle() {
        assert_eq!(DEFAULT_PORT_FTP, 21);
        assert_eq!(DEFAULT_PORT_SSH, 22);
        assert_eq!(DEFAULT_PORT_TELNET, 23);
        assert_eq!(DEFAULT_PORT_SMTP, 25);
        assert_eq!(DEFAULT_PORT_TFTP, 69);
        assert_eq!(DEFAULT_PORT_GOPHER, 70);
        assert_eq!(DEFAULT_PORT_HTTP, 80);
        assert_eq!(DEFAULT_PORT_POP3, 110);
        assert_eq!(DEFAULT_PORT_IMAP, 143);
        assert_eq!(DEFAULT_PORT_LDAP, 389);
        assert_eq!(DEFAULT_PORT_HTTPS, 443);
        assert_eq!(DEFAULT_PORT_SMB, 445);
        assert_eq!(DEFAULT_PORT_SMTPS, 465);
        assert_eq!(DEFAULT_PORT_RTSP, 554);
        assert_eq!(DEFAULT_PORT_LDAPS, 636);
        assert_eq!(DEFAULT_PORT_FTPS, 990);
        assert_eq!(DEFAULT_PORT_IMAPS, 993);
        assert_eq!(DEFAULT_PORT_POP3S, 995);
        assert_eq!(DEFAULT_PORT_MQTT, 1883);
        assert_eq!(DEFAULT_PORT_DICT, 2628);
        assert_eq!(DEFAULT_PORT_MQTTS, 8883);
    }

    // -----------------------------------------------------------------------
    // `scheme_descriptor` — port + flag parity, case-insensitive lookup.
    // -----------------------------------------------------------------------
    #[cfg(feature = "http")]
    #[test]
    fn https_descriptor_has_443_and_ssl() {
        let s = scheme_descriptor("https").expect("https present with `http` feature");
        assert_eq!(s.default_port, 443);
        assert!(s.is_ssl(), "https must carry PROTOPT_SSL");
        assert_eq!(s.protocol, CURLPROTO_HTTPS);
        assert_eq!(s.family, CURLPROTO_HTTP, "https family is HTTP");
        assert!(s.flags & PROTOPT_ALPN != 0, "https negotiates via ALPN");
    }

    #[cfg(feature = "ftp")]
    #[test]
    fn scheme_lookup_is_case_insensitive() {
        let upper = scheme_descriptor("FTP").expect("FTP resolves case-insensitively");
        let lower = scheme_descriptor("ftp").expect("ftp present with `ftp` feature");
        assert_eq!(upper, lower);
        assert_eq!(upper.default_port, 21);
        assert_eq!(upper.name, "ftp", "the canonical name is lower-case");
    }

    #[cfg(feature = "file")]
    #[test]
    fn file_descriptor_is_networkless() {
        let s = scheme_descriptor("file").expect("file present with `file` feature");
        assert_eq!(s.default_port, 0);
        assert!(s.is_nonetwork());
        assert!(!s.is_ssl());
    }

    #[cfg(feature = "ftp")]
    #[test]
    fn ftp_and_ftps_flag_parity() {
        // ftp carries the full proxy/reuse/wildcard flag set.
        let ftp = scheme_descriptor("ftp").expect("ftp present");
        assert!(ftp.uses_dual(), "ftp uses a dual (control+data) connection");
        assert!(ftp.flags & PROTOPT_PROXY_AS_HTTP != 0);
        assert!(ftp.flags & PROTOPT_SSL_REUSE != 0);
        assert!(ftp.flags & PROTOPT_WILDCARD != 0);
        assert!(ftp.needs_password());

        // ftps shares ftp's family but, per the C oracle, DROPS PROXY_AS_HTTP
        // and SSL_REUSE while adding SSL.
        let ftps = scheme_descriptor("ftps").expect("ftps present with `ftp` feature");
        assert_eq!(ftps.default_port, 990);
        assert!(ftps.is_ssl());
        assert_eq!(ftps.family, CURLPROTO_FTP);
        assert_eq!(
            ftps.flags & PROTOPT_PROXY_AS_HTTP,
            0,
            "ftps drops PROXY_AS_HTTP relative to ftp"
        );
        assert_eq!(
            ftps.flags & PROTOPT_SSL_REUSE,
            0,
            "ftps drops SSL_REUSE relative to ftp"
        );
    }

    #[cfg(all(feature = "scp", feature = "sftp"))]
    #[test]
    fn scp_and_sftp_share_port_and_flags() {
        let scp = scheme_descriptor("scp").expect("scp present");
        let sftp = scheme_descriptor("sftp").expect("sftp present");
        assert_eq!(scp.default_port, 22);
        assert_eq!(sftp.default_port, 22);
        // Both SSH schemes lock the directory and run a close action.
        assert!(scp.flags & PROTOPT_DIRLOCK != 0);
        assert!(sftp.flags & PROTOPT_DIRLOCK != 0);
        assert_eq!(scp.flags, sftp.flags, "scp and sftp carry identical flags");
    }

    #[cfg(feature = "websockets")]
    #[test]
    fn ws_family_is_http_without_alpn() {
        let ws = scheme_descriptor("ws").expect("ws present with `websockets` feature");
        let wss = scheme_descriptor("wss").expect("wss present with `websockets` feature");
        assert_eq!(ws.default_port, 80);
        assert_eq!(wss.default_port, 443);
        // The websockets schemes belong to the HTTP family (they upgrade an
        // HTTP connection) and do NOT advertise ALPN themselves.
        assert_eq!(ws.family, CURLPROTO_HTTP);
        assert_eq!(wss.family, CURLPROTO_HTTP);
        assert_eq!(ws.flags & PROTOPT_ALPN, 0);
        assert_eq!(wss.flags & PROTOPT_ALPN, 0);
        assert!(wss.is_ssl());
    }

    #[test]
    fn unknown_and_rtmp_descriptors_are_none() {
        // RTMP is out of scope: its `CURLPROTO_*` bits exist for ABI
        // completeness but it is never a recognized scheme.
        assert!(scheme_descriptor("rtmp").is_none());
        assert!(scheme_descriptor("rtmps").is_none());
        assert!(scheme_descriptor("not-a-scheme").is_none());
        assert!(scheme_descriptor("").is_none());
    }

    // -----------------------------------------------------------------------
    // `scheme_handler` — resolves every supported scheme, rejects the rest.
    // -----------------------------------------------------------------------
    #[test]
    fn scheme_handler_resolves_all_supported_and_rejects_others() {
        for name in supported_schemes() {
            let handler = scheme_handler(name)
                .unwrap_or_else(|| panic!("a handler must exist for supported scheme {name:?}"));
            assert_eq!(
                handler.scheme().name,
                *name,
                "the handler's scheme name must match the registry key"
            );
        }
        // Out-of-scope and unknown schemes resolve to no handler.
        assert!(scheme_handler("rtmp").is_none());
        assert!(scheme_handler("rtmps").is_none());
        assert!(scheme_handler("nonesuch").is_none());
        assert!(scheme_handler("").is_none());
    }

    #[cfg(feature = "http")]
    #[test]
    fn scheme_handler_is_case_insensitive() {
        let handler = scheme_handler("HtTpS").expect("HTTPS resolves case-insensitively");
        assert_eq!(handler.scheme().name, "https");
        assert_eq!(handler.scheme().default_port, 443);
    }

    // -----------------------------------------------------------------------
    // LOCKSTEP (AAP §0.7.3): the compiled scheme set MUST equal
    // `crate::version::protocols()` for the active feature set. This holds for
    // every feature combination because both are built from identically-gated,
    // identically-ordered tables — if either drifts, `runtests` selects the
    // wrong protocol test subset.
    // -----------------------------------------------------------------------
    #[test]
    fn supported_schemes_match_version_protocols() {
        assert_eq!(
            supported_schemes(),
            crate::version::protocols(),
            "protocols::supported_schemes() and version::protocols() must stay in lockstep (AAP §0.7.3)"
        );
    }

    #[test]
    fn supported_schemes_exclude_rtmp_and_are_sorted() {
        let schemes = supported_schemes();
        assert!(!schemes.contains(&"rtmp"), "rtmp is out of scope");
        assert!(!schemes.contains(&"rtmps"), "rtmps is out of scope");
        // curl reports `supported_protocols[]` in alphabetical order.
        let mut sorted = schemes.to_vec();
        sorted.sort_unstable();
        assert_eq!(
            schemes,
            sorted.as_slice(),
            "scheme list must be alphabetical"
        );
    }

    // -----------------------------------------------------------------------
    // `ProtocolTransfer` / `TransferDirection`.
    // -----------------------------------------------------------------------
    #[test]
    fn protocol_transfer_builder_and_default() {
        let t = ProtocolTransfer::new(TransferDirection::Download)
            .with_size(1234)
            .with_response_headers(true);
        assert_eq!(t.direction, TransferDirection::Download);
        assert_eq!(t.expected_size, Some(1234));
        assert!(t.has_response_headers);

        let d = ProtocolTransfer::default();
        assert_eq!(d.direction, TransferDirection::None);
        assert_eq!(d.expected_size, None);
        assert!(!d.has_response_headers);
    }

    // -----------------------------------------------------------------------
    // The stub handler returned for a recognized-but-unimplemented scheme
    // reports the correct descriptor and yields `UnsupportedProtocol` from
    // `do_it` (curl's "recognized scheme, unsupported handler" behavior).
    // -----------------------------------------------------------------------
    #[cfg(feature = "http")]
    #[tokio::test]
    async fn stub_handler_do_it_is_unsupported() {
        use crate::conn::{SchemeDescriptor, TRNSPRT_TCP};

        let handler = scheme_handler("https").expect("https present with `http` feature");
        let scheme = handler.scheme();
        assert_eq!(scheme.name, "https");

        let mut data = Easy::new();
        let desc = SchemeDescriptor::new(
            scheme.name,
            scheme.default_port,
            scheme.flags,
            scheme.protocol,
        );
        let mut conn = Connection::new(
            format!("{}:{}", scheme.name, scheme.default_port),
            TRNSPRT_TCP,
            desc,
        );

        let result = handler.do_it(&mut data, &mut conn).await;
        assert!(
            matches!(result, Err(CurlError::UnsupportedProtocol)),
            "the stub handler's do_it must report UnsupportedProtocol"
        );
    }
}
