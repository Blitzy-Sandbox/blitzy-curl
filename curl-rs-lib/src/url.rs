// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! # Handle / connection URL setup and easy-handle option storage
//!
//! This module is a language rewrite of curl's `lib/url.c` (≈3,900 lines) — one
//! of the largest core modules in libcurl. It is responsible for turning a
//! *configured easy handle* plus a *URL* into a ready-to-connect transfer:
//!
//! * It owns the easy-handle configuration store — [`UserDefined`] (the C
//!   `struct UserDefined`, i.e. the `set.*` options) and the operational
//!   [`Easy`] state (`struct Curl_easy`). The idiomatic Rust builder in
//!   `lib.rs` and the `curl_easy_setopt` FFI shim both write into these,
//!   preserving curl's option **defaults byte-for-byte** (for example
//!   [`UserDefined::maxredirs`] `= 30`, and TLS verification on by default —
//!   `verifypeer = 1`, `verifyhost = 2`; AAP §0.7.3).
//! * It performs the `Curl_connect`/`create_conn` work: parse the URL (via
//!   [`crate::urlapi`]), resolve proxy / no-proxy (the `lib/noproxy.c`
//!   behavior), select the protocol handler by scheme, and either reuse a
//!   pooled connection from [`ConnCache`] or create a fresh one — preserving
//!   curl's connection-reuse matching rules ([`Connection::matches`], the
//!   `ConnectionExists`/`url_match_conn` logic) bug-for-bug.
//! * It builds redirect targets ([`Easy::follow`], curl's `Curl_http_follow`):
//!   relative-URL resolution through the URL API, [`UserDefined::maxredirs`]
//!   enforcement, `CURLOPT_REDIR_PROTOCOLS` gating, and credential stripping on
//!   cross-origin redirects.
//! * It wires credential resolution: URL userinfo parsing plus `.netrc`
//!   lookups through [`crate::netrc`] when `--netrc` is requested.
//! * It manages disconnect/cleanup ([`ConnCache::disconnect`], curl's
//!   `Curl_disconnect`): returning connections to the cache or closing them.
//!
//! ## Memory safety
//!
//! Like the rest of `curl-rs-lib`, this module is 100% safe Rust — the manual
//! `malloc`/`free` of `struct Curl_easy` and `struct connectdata` in `url.c`
//! becomes ownership and borrowing. The crate-wide `#![forbid(unsafe_code)]`
//! (see `lib.rs`) makes any `unsafe` here a hard compile error.
//!
//! ## Scheme gating and dropped protocols
//!
//! Each scheme handler is attached under the matching Cargo `#[cfg(feature =
//! "…")]` (mirroring curl's `CURL_DISABLE_*`). The RTMP family (`rtmp`,
//! `rtmpt`, `rtmpe`, `rtmpte`, `rtmps`, `rtmpts`) is **not** registered — the
//! protocol was dropped from this rewrite (AAP §0.2.2) because no pure-Rust
//! `librtmp` equivalent exists — so those schemes are reported as unsupported.

use std::cmp::Ordering;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;

use crate::error::{CurlCode, Error, Result};
use crate::escape;
use crate::idn;
use crate::multi::Share;
use crate::netrc::{Netrc, NetrcCode};
use crate::urlapi::{self, CurlUPart, Url};

// ===========================================================================
// Parity constants — buffer sizes and reuse limits (from `lib/urldata.h` and
// `include/curl/curl.h`). These are reproduced verbatim so that a handle's
// observable defaults match curl 8.x exactly.
// ===========================================================================

/// The maximum size of a single write-callback delivery (`CURL_MAX_WRITE_SIZE`,
/// `include/curl/curl.h`). Also the default receive-buffer size.
pub const CURL_MAX_WRITE_SIZE: usize = 16384;

/// The maximum receive-buffer size accepted for `CURLOPT_BUFFERSIZE`
/// (`CURL_MAX_READ_SIZE`, `include/curl/curl.h`).
pub const CURL_MAX_READ_SIZE: usize = 10 * 1024 * 1024;

/// Default receive-buffer size (`READBUFFER_SIZE` = `CURL_MAX_WRITE_SIZE`).
pub const READBUFFER_SIZE: usize = CURL_MAX_WRITE_SIZE;

/// Upper clamp for the receive buffer (`READBUFFER_MAX`).
pub const READBUFFER_MAX: usize = CURL_MAX_READ_SIZE;

/// Lower clamp for the receive buffer (`READBUFFER_MIN`).
pub const READBUFFER_MIN: usize = 1024;

/// Default upload-buffer size (`UPLOADBUFFER_DEFAULT`).
pub const UPLOADBUFFER_DEFAULT: usize = 65536;

/// Upper clamp for the upload buffer (`UPLOADBUFFER_MAX`).
pub const UPLOADBUFFER_MAX: usize = 2 * 1024 * 1024;

/// Lower clamp for the upload buffer (`UPLOADBUFFER_MIN` = `CURL_MAX_WRITE_SIZE`).
pub const UPLOADBUFFER_MIN: usize = CURL_MAX_WRITE_SIZE;

/// Default connection-cache size for an easy handle (`DEFAULT_CONNCACHE_SIZE`,
/// `lib/urldata.h`).
pub const DEFAULT_CONNCACHE_SIZE: usize = 5;

/// Default Happy-Eyeballs timeout in milliseconds (`CURL_HET_DEFAULT`,
/// `include/curl/curl.h`).
pub const CURL_HET_DEFAULT: u64 = 200;

/// Default connection-upkeep interval in milliseconds
/// (`CURL_UPKEEP_INTERVAL_DEFAULT`, `include/curl/curl.h`).
pub const CURL_UPKEEP_INTERVAL_DEFAULT: u64 = 60000;

/// The default value of `CURLOPT_MAXREDIRS` as set by `Curl_init_userdefined`
/// (`set->maxredirs = 30`). A value of `-1` means "unlimited".
pub const DEFAULT_MAXREDIRS: i64 = 30;

// ===========================================================================
// CURLPROTO_* protocol bit flags (`include/curl/curl.h`, lines 1076-1107).
//
// `curl_prot_t` is an unsigned 32-bit mask; these are the bit positions. The
// RTMP family (bits 19-24) is intentionally omitted from the named set because
// the protocol is dropped (AAP §0.2.2), but the numeric layout of every other
// flag is preserved so `CURLOPT_PROTOCOLS`/`CURLOPT_REDIR_PROTOCOLS` masks
// remain integer-compatible with curl 8.x.
// ===========================================================================

/// The `CURLPROTO_*` protocol-selection bit flags, reproduced with their exact
/// curl 8.x bit positions.
pub mod proto {
    /// `CURLPROTO_HTTP`.
    pub const HTTP: u32 = 1 << 0;
    /// `CURLPROTO_HTTPS`.
    pub const HTTPS: u32 = 1 << 1;
    /// `CURLPROTO_FTP`.
    pub const FTP: u32 = 1 << 2;
    /// `CURLPROTO_FTPS`.
    pub const FTPS: u32 = 1 << 3;
    /// `CURLPROTO_SCP`.
    pub const SCP: u32 = 1 << 4;
    /// `CURLPROTO_SFTP`.
    pub const SFTP: u32 = 1 << 5;
    /// `CURLPROTO_TELNET`.
    pub const TELNET: u32 = 1 << 6;
    /// `CURLPROTO_LDAP`.
    pub const LDAP: u32 = 1 << 7;
    /// `CURLPROTO_LDAPS`.
    pub const LDAPS: u32 = 1 << 8;
    /// `CURLPROTO_DICT`.
    pub const DICT: u32 = 1 << 9;
    /// `CURLPROTO_FILE`.
    pub const FILE: u32 = 1 << 10;
    /// `CURLPROTO_TFTP`.
    pub const TFTP: u32 = 1 << 11;
    /// `CURLPROTO_IMAP`.
    pub const IMAP: u32 = 1 << 12;
    /// `CURLPROTO_IMAPS`.
    pub const IMAPS: u32 = 1 << 13;
    /// `CURLPROTO_POP3`.
    pub const POP3: u32 = 1 << 14;
    /// `CURLPROTO_POP3S`.
    pub const POP3S: u32 = 1 << 15;
    /// `CURLPROTO_SMTP`.
    pub const SMTP: u32 = 1 << 16;
    /// `CURLPROTO_SMTPS`.
    pub const SMTPS: u32 = 1 << 17;
    /// `CURLPROTO_RTSP`.
    pub const RTSP: u32 = 1 << 18;
    // Bits 19-24 (RTMP, RTMPT, RTMPE, RTMPTE, RTMPS, RTMPTS) are deliberately
    // left undefined: the RTMP family is dropped from this rewrite.
    /// `CURLPROTO_GOPHER`.
    pub const GOPHER: u32 = 1 << 25;
    /// `CURLPROTO_SMB`.
    pub const SMB: u32 = 1 << 26;
    /// `CURLPROTO_SMBS`.
    pub const SMBS: u32 = 1 << 27;
    /// `CURLPROTO_MQTT`.
    pub const MQTT: u32 = 1 << 28;
    /// `CURLPROTO_GOPHERS`.
    pub const GOPHERS: u32 = 1 << 29;
    /// `CURLPROTO_MQTTS`.
    pub const MQTTS: u32 = 1 << 30;

    /// `CURLPROTO_WS` — WebSocket. curl defines this internally
    /// (`lib/urldata.h`) at bit 30, deliberately overlapping [`MQTTS`]; the two
    /// are never used by the same handle, so the overlap is a harmless
    /// space-saving detail preserved here for numeric parity.
    pub const WS: u32 = 1 << 30;
    /// `CURLPROTO_WSS` — WebSocket over TLS, at bit 31 (`lib/urldata.h`).
    pub const WSS: u32 = 1 << 31;

    /// `CURLPROTO_ALL` — enable everything (all 32 bits set).
    pub const ALL: u32 = 0xffff_ffff;

    /// `CURLPROTO_REDIR` — the protocols a redirect is permitted to target by
    /// default (`lib/urldata.h`): HTTP, HTTPS, FTP and FTPS.
    pub const REDIR: u32 = HTTP | HTTPS | FTP | FTPS;
}

// ===========================================================================
// CURLAUTH_* HTTP authentication bit flags (`include/curl/curl.h`, lines
// 828-847). Stored in `unsigned long` fields in curl; represented as `u64`
// here to match `unsigned long` semantics on LP64 targets.
// ===========================================================================

/// The `CURLAUTH_*` authentication-method bit flags.
pub mod authmask {
    /// `CURLAUTH_NONE` — no authentication.
    pub const NONE: u64 = 0;
    /// `CURLAUTH_BASIC`.
    pub const BASIC: u64 = 1 << 0;
    /// `CURLAUTH_DIGEST`.
    pub const DIGEST: u64 = 1 << 1;
    /// `CURLAUTH_NEGOTIATE` (also `CURLAUTH_GSSAPI` / `CURLAUTH_GSSNEGOTIATE`).
    pub const NEGOTIATE: u64 = 1 << 2;
    /// `CURLAUTH_GSSAPI` — alias of [`NEGOTIATE`] (SOCKS5 GSS-API).
    pub const GSSAPI: u64 = NEGOTIATE;
    /// `CURLAUTH_NTLM`.
    pub const NTLM: u64 = 1 << 3;
    /// `CURLAUTH_DIGEST_IE`.
    pub const DIGEST_IE: u64 = 1 << 4;
    /// `CURLAUTH_NTLM_WB` (retained for numeric compatibility).
    pub const NTLM_WB: u64 = 1 << 5;
    /// `CURLAUTH_BEARER`.
    pub const BEARER: u64 = 1 << 6;
    /// `CURLAUTH_AWS_SIGV4`.
    pub const AWS_SIGV4: u64 = 1 << 7;
    /// `CURLAUTH_ONLY`.
    pub const ONLY: u64 = 1 << 31;
}

/// The HTTP request method, mirroring curl's `Curl_HttpReq` (`lib/http.h`).
///
/// The discriminants match the C enumeration order (`HTTPREQ_GET` is `0`), and
/// [`HttpReq::Get`] is the default set by `Curl_init_userdefined`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpReq {
    /// `HTTPREQ_GET` — the default request.
    #[default]
    Get = 0,
    /// `HTTPREQ_POST` — a plain `POST` (`CURLOPT_POSTFIELDS`).
    Post = 1,
    /// `HTTPREQ_POST_FORM` — a multipart form built the legacy way.
    PostForm = 2,
    /// `HTTPREQ_POST_MIME` — a multipart form built via the MIME API.
    PostMime = 3,
    /// `HTTPREQ_PUT`.
    Put = 4,
    /// `HTTPREQ_HEAD`.
    Head = 5,
}

impl HttpReq {
    /// Returns `true` for the three `POST`-family methods (`HTTPREQ_POST`,
    /// `HTTPREQ_POST_FORM`, `HTTPREQ_POST_MIME`), matching the grouped tests
    /// curl performs in its redirect method-switching logic.
    #[must_use]
    pub fn is_post_family(self) -> bool {
        matches!(self, HttpReq::Post | HttpReq::PostForm | HttpReq::PostMime)
    }
}

/// The `.netrc` usage level, mirroring the `CURL_NETRC_*` enumeration
/// (`include/curl/curl.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetrcLevel {
    /// `CURL_NETRC_IGNORED` — never read `.netrc` (the default).
    #[default]
    Ignored = 0,
    /// `CURL_NETRC_OPTIONAL` — URL credentials win over `.netrc`.
    Optional = 1,
    /// `CURL_NETRC_REQUIRED` — `.netrc` wins over URL credentials.
    Required = 2,
}

/// The IP-version resolve preference, mirroring `CURL_IPRESOLVE_*`
/// (`include/curl/curl.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpResolve {
    /// `CURL_IPRESOLVE_WHATEVER` — use any address family (the default).
    #[default]
    Whatever = 0,
    /// `CURL_IPRESOLVE_V4` — IPv4 only.
    V4 = 1,
    /// `CURL_IPRESOLVE_V6` — IPv6 only.
    V6 = 2,
}

/// The proxy type, mirroring the `CURLPROXY_*` enumeration
/// (`include/curl/curl.h`). [`ProxyType::Http`] (`0`) is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyType {
    /// `CURLPROXY_HTTP` — HTTP proxy (default).
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
    /// `CURLPROXY_SOCKS5_HOSTNAME` — SOCKS5, resolve host name proxy-side.
    Socks5Hostname = 7,
}

impl ProxyType {
    /// Returns `true` if this is one of the SOCKS proxy variants.
    #[must_use]
    pub fn is_socks(self) -> bool {
        matches!(
            self,
            ProxyType::Socks4 | ProxyType::Socks5 | ProxyType::Socks4a | ProxyType::Socks5Hostname
        )
    }

    /// Returns `true` if this is an HTTPS (TLS) proxy variant
    /// (`IS_HTTPS_PROXY` in curl).
    #[must_use]
    pub fn is_https(self) -> bool {
        matches!(self, ProxyType::Https | ProxyType::Https2)
    }
}

/// The kind of redirect follow being performed, mirroring curl's `followtype`
/// enumeration (`lib/http.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowType {
    /// `FOLLOW_FAKE` — only record the would-be-redirect target, do not follow
    /// (used once `maxredirs` has been reached, and for `wouldredirect`).
    Fake,
    /// `FOLLOW_RETRY` — a request retry rather than a true redirect.
    Retry,
    /// `FOLLOW_REDIR` — a full, real redirect (a `3xx` `Location:` follow).
    Redir,
}

/// Where the currently-effective credentials came from, mirroring curl's
/// `enum creds_source` used to arbitrate URL vs option vs `.netrc` precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CredsFrom {
    /// No credentials resolved yet.
    #[default]
    None,
    /// Credentials came from an explicit option (`CURLOPT_USERNAME`/`_PASSWORD`
    /// or `CURLOPT_USERPWD`).
    Option,
    /// Credentials came from the URL userinfo.
    Url,
    /// Credentials came from a `.netrc` lookup.
    Netrc,
}

// ===========================================================================
// Protocol option flags (`PROTOPT_*`, `lib/urldata.h` lines 526-558) and the
// per-scheme handler descriptor.
// ===========================================================================

/// The `PROTOPT_*` per-protocol option flags, reproduced with curl's exact bit
/// positions. These describe intrinsic properties of a scheme's handler and
/// drive connection-reuse decisions (for example [`SSL`](protopt::SSL) and
/// [`CREDSPERREQUEST`](protopt::CREDSPERREQUEST)).
pub mod protopt {
    /// `PROTOPT_NONE` — no special properties.
    pub const NONE: u32 = 0;
    /// `PROTOPT_SSL` — the protocol uses TLS at the transport layer.
    pub const SSL: u32 = 1 << 0;
    /// `PROTOPT_DUAL` — the protocol uses two connections (e.g. FTP).
    pub const DUAL: u32 = 1 << 1;
    /// `PROTOPT_CLOSEACTION` — needs an action before the socket closes.
    pub const CLOSEACTION: u32 = 1 << 2;
    /// `PROTOPT_DIRLOCK` — directory-listing lock (SCP).
    pub const DIRLOCK: u32 = 1 << 3;
    /// `PROTOPT_NONETWORK` — the protocol does not use the network (FILE).
    pub const NONETWORK: u32 = 1 << 4;
    /// `PROTOPT_NEEDSPWD` — a password is required if none is set.
    pub const NEEDSPWD: u32 = 1 << 5;
    /// `PROTOPT_NOURLQUERY` — the protocol cannot handle a URL query part.
    pub const NOURLQUERY: u32 = 1 << 6;
    /// `PROTOPT_CREDSPERREQUEST` — credentials are supplied per request, so a
    /// connection may be reused across differing credentials (HTTP).
    pub const CREDSPERREQUEST: u32 = 1 << 7;
    /// `PROTOPT_ALPN` — negotiate ALPN on the TLS connection.
    pub const ALPN: u32 = 1 << 8;
    /// `PROTOPT_URLOPTIONS` — an `;options` field is allowed in the userinfo
    /// (IMAP/POP3/SMTP).
    pub const URLOPTIONS: u32 = 1 << 10;
    /// `PROTOPT_PROXY_AS_HTTP` — this non-HTTP scheme may tunnel over an HTTP
    /// proxy.
    pub const PROXY_AS_HTTP: u32 = 1 << 11;
    /// `PROTOPT_WILDCARD` — the protocol supports wildcard matching (FTP).
    pub const WILDCARD: u32 = 1 << 12;
    /// `PROTOPT_USERPWDCTRL` — control bytes (`< 0x20`) are permitted in the
    /// user and password fields.
    pub const USERPWDCTRL: u32 = 1 << 13;
    /// `PROTOPT_NOTCPPROXY` — this protocol cannot proxy over TCP (TFTP).
    pub const NOTCPPROXY: u32 = 1 << 14;
    /// `PROTOPT_SSL_REUSE` — an existing TLS connection of the family may be
    /// reused for this scheme.
    pub const SSL_REUSE: u32 = 1 << 15;
    /// `PROTOPT_CONN_REUSE` — this protocol can reuse connections.
    pub const CONN_REUSE: u32 = 1 << 16;
}

/// A scheme handler descriptor — the metadata portion of curl's
/// `struct Curl_handler` (`lib/urldata.h`): the scheme name, its `CURLPROTO_*`
/// protocol bit, its protocol *family* bit, the default port, and its
/// `PROTOPT_*` flags.
///
/// In curl the handler also carries a vtable of protocol I/O callbacks (`->run`);
/// that behavioral part lives in `crate::protocols`. This descriptor is the URL
/// layer's view — exactly what `Curl_get_scheme`/`findprotocol` consult to map a
/// scheme string onto a protocol and to make connection-reuse and
/// redirect-gating decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemeHandler {
    /// The lowercase scheme name, e.g. `"https"` (curl `->scheme`).
    pub name: &'static str,
    /// The `CURLPROTO_*` bit identifying this exact scheme (curl `->protocol`).
    pub protocol: u32,
    /// The `CURLPROTO_*` bit of this scheme's protocol *family* — the base
    /// protocol used for family-compatible reuse (curl `->family`). For example
    /// `https`, `ws` and `wss` all report the `http` family bit.
    pub family: u32,
    /// The default TCP/UDP port (curl `->defport`). `0` for schemes with no
    /// network port (FILE).
    pub default_port: u16,
    /// The `PROTOPT_*` flag set (curl `->flags`).
    pub flags: u32,
}

impl SchemeHandler {
    /// Builds a descriptor. `const` so the whole scheme registry can be
    /// evaluated at compile time.
    #[must_use]
    const fn new(
        name: &'static str,
        protocol: u32,
        family: u32,
        default_port: u16,
        flags: u32,
    ) -> Self {
        SchemeHandler {
            name,
            protocol,
            family,
            default_port,
            flags,
        }
    }

    /// Returns `true` if the flag set contains `flag`.
    #[must_use]
    pub const fn has_flag(&self, flag: u32) -> bool {
        (self.flags & flag) != 0
    }

    /// `true` if the scheme uses TLS (`PROTOPT_SSL`).
    #[must_use]
    pub const fn is_ssl(&self) -> bool {
        self.has_flag(protopt::SSL)
    }

    /// `true` if credentials are supplied per request (`PROTOPT_CREDSPERREQUEST`),
    /// meaning a connection may be reused across differing credentials.
    #[must_use]
    pub const fn is_creds_per_request(&self) -> bool {
        self.has_flag(protopt::CREDSPERREQUEST)
    }

    /// `true` if an `;options` field is allowed in the userinfo
    /// (`PROTOPT_URLOPTIONS`).
    #[must_use]
    pub const fn allows_url_options(&self) -> bool {
        self.has_flag(protopt::URLOPTIONS)
    }

    /// `true` if control bytes are permitted in credentials
    /// (`PROTOPT_USERPWDCTRL`); governs whether URL credential decoding rejects
    /// control characters.
    #[must_use]
    pub const fn allows_userpwd_ctrl(&self) -> bool {
        self.has_flag(protopt::USERPWDCTRL)
    }

    /// `true` if the protocol does not use the network (`PROTOPT_NONETWORK`,
    /// i.e. FILE).
    #[must_use]
    pub const fn is_nonetwork(&self) -> bool {
        self.has_flag(protopt::NONETWORK)
    }

    /// Returns the protocol *family* bit — curl's `get_protocol_family`.
    #[must_use]
    pub const fn protocol_family(&self) -> u32 {
        self.family
    }
}

// Precomputed flag combinations matching the curl handler definitions, kept as
// module-private aliases so the registry reads cleanly and stays in sync with
// `lib/*.c`.
#[cfg(feature = "http")]
const F_HTTP: u32 = protopt::CREDSPERREQUEST | protopt::USERPWDCTRL | protopt::CONN_REUSE;
#[cfg(feature = "http")]
const F_HTTPS: u32 = protopt::SSL
    | protopt::CREDSPERREQUEST
    | protopt::ALPN
    | protopt::USERPWDCTRL
    | protopt::CONN_REUSE;
const F_WS: u32 = protopt::CREDSPERREQUEST | protopt::USERPWDCTRL;
const F_WSS: u32 = protopt::SSL | protopt::CREDSPERREQUEST | protopt::USERPWDCTRL;
#[cfg(feature = "ftp")]
const F_FTP: u32 = protopt::DUAL
    | protopt::CLOSEACTION
    | protopt::NEEDSPWD
    | protopt::NOURLQUERY
    | protopt::WILDCARD
    | protopt::SSL_REUSE
    | protopt::CONN_REUSE;
#[cfg(feature = "ftp")]
const F_FTPS: u32 = protopt::SSL
    | protopt::DUAL
    | protopt::CLOSEACTION
    | protopt::NEEDSPWD
    | protopt::NOURLQUERY
    | protopt::WILDCARD
    | protopt::CONN_REUSE;
#[cfg(feature = "sftp")]
const F_SFTP: u32 = protopt::NEEDSPWD;
#[cfg(feature = "scp")]
const F_SCP: u32 = protopt::DIRLOCK | protopt::CLOSEACTION | protopt::NEEDSPWD;
#[cfg(feature = "imap")]
const F_IMAP: u32 = protopt::CLOSEACTION
    | protopt::NEEDSPWD
    | protopt::URLOPTIONS
    | protopt::SSL_REUSE
    | protopt::CONN_REUSE;
#[cfg(feature = "imap")]
const F_IMAPS: u32 = protopt::CLOSEACTION
    | protopt::SSL
    | protopt::NEEDSPWD
    | protopt::URLOPTIONS
    | protopt::CONN_REUSE;
#[cfg(feature = "pop3")]
const F_POP3: u32 = protopt::CLOSEACTION
    | protopt::NEEDSPWD
    | protopt::URLOPTIONS
    | protopt::SSL_REUSE
    | protopt::CONN_REUSE;
#[cfg(feature = "pop3")]
const F_POP3S: u32 = protopt::CLOSEACTION
    | protopt::SSL
    | protopt::NEEDSPWD
    | protopt::NOURLQUERY
    | protopt::URLOPTIONS
    | protopt::CONN_REUSE;
#[cfg(feature = "smtp")]
const F_SMTP: u32 = protopt::URLOPTIONS | protopt::SSL_REUSE | protopt::CONN_REUSE;
#[cfg(feature = "smtp")]
const F_SMTPS: u32 = protopt::CLOSEACTION
    | protopt::SSL
    | protopt::NOURLQUERY
    | protopt::URLOPTIONS
    | protopt::CONN_REUSE;
#[cfg(feature = "telnet")]
const F_TELNET: u32 = protopt::NONE | protopt::NOURLQUERY;
#[cfg(feature = "dict")]
const F_DICT: u32 = protopt::NONE | protopt::NOURLQUERY;
#[cfg(feature = "tftp")]
const F_TFTP: u32 = protopt::NOTCPPROXY | protopt::NOURLQUERY;
const F_LDAP: u32 = protopt::NONE | protopt::NOURLQUERY;
const F_LDAPS: u32 = protopt::SSL | protopt::NOURLQUERY;
const F_SMB: u32 = protopt::CONN_REUSE;
const F_SMBS: u32 = protopt::SSL | protopt::CONN_REUSE;
#[cfg(feature = "rtsp")]
const F_RTSP: u32 = protopt::CONN_REUSE;
const F_GOPHER: u32 = protopt::NONE;
const F_GOPHERS: u32 = protopt::SSL;
#[cfg(feature = "mqtt")]
const F_MQTT: u32 = protopt::NONE;
#[cfg(feature = "mqtt")]
const F_MQTTS: u32 = protopt::SSL;
const F_FILE: u32 = protopt::NONETWORK | protopt::NOURLQUERY;

/// Looks up the built-in handler for a scheme, curl's `Curl_get_scheme`.
///
/// The comparison is case-insensitive (curl lowercases the scheme first). Each
/// scheme is gated by the Cargo feature that mirrors its curl `CURL_DISABLE_*`
/// guard; schemes with no dedicated feature in this workspace (`file`, `ldap`,
/// `smb`, `gopher`, `ws` and their TLS variants) are always available. The RTMP
/// family is intentionally absent — see the module docs — so `rtmp://` &c.
/// resolve to `None`.
#[must_use]
pub fn get_scheme_handler(scheme: &str) -> Option<SchemeHandler> {
    // curl's `Curl_get_scheme` matches on a lowercased copy of the scheme.
    let lower = scheme.to_ascii_lowercase();
    match lower.as_str() {
        #[cfg(feature = "http")]
        "http" => Some(SchemeHandler::new(
            "http",
            proto::HTTP,
            proto::HTTP,
            80,
            F_HTTP,
        )),
        #[cfg(feature = "http")]
        "https" => Some(SchemeHandler::new(
            "https",
            proto::HTTPS,
            proto::HTTP,
            443,
            F_HTTPS,
        )),
        // WebSockets ride the HTTP handler in curl and share its family; there
        // is no dedicated `websockets` feature in this workspace, so they are
        // always registered (curl gates them on CURL_DISABLE_WEBSOCKETS).
        "ws" => Some(SchemeHandler::new("ws", proto::WS, proto::HTTP, 80, F_WS)),
        "wss" => Some(SchemeHandler::new(
            "wss",
            proto::WSS,
            proto::HTTP,
            443,
            F_WSS,
        )),
        #[cfg(feature = "ftp")]
        "ftp" => Some(SchemeHandler::new("ftp", proto::FTP, proto::FTP, 21, F_FTP)),
        #[cfg(feature = "ftp")]
        "ftps" => Some(SchemeHandler::new(
            "ftps",
            proto::FTPS,
            proto::FTP,
            990,
            F_FTPS,
        )),
        #[cfg(feature = "sftp")]
        "sftp" => Some(SchemeHandler::new(
            "sftp",
            proto::SFTP,
            proto::SFTP,
            22,
            F_SFTP,
        )),
        #[cfg(feature = "scp")]
        "scp" => Some(SchemeHandler::new("scp", proto::SCP, proto::SCP, 22, F_SCP)),
        #[cfg(feature = "imap")]
        "imap" => Some(SchemeHandler::new(
            "imap",
            proto::IMAP,
            proto::IMAP,
            143,
            F_IMAP,
        )),
        #[cfg(feature = "imap")]
        "imaps" => Some(SchemeHandler::new(
            "imaps",
            proto::IMAPS,
            proto::IMAP,
            993,
            F_IMAPS,
        )),
        #[cfg(feature = "pop3")]
        "pop3" => Some(SchemeHandler::new(
            "pop3",
            proto::POP3,
            proto::POP3,
            110,
            F_POP3,
        )),
        #[cfg(feature = "pop3")]
        "pop3s" => Some(SchemeHandler::new(
            "pop3s",
            proto::POP3S,
            proto::POP3,
            995,
            F_POP3S,
        )),
        #[cfg(feature = "smtp")]
        "smtp" => Some(SchemeHandler::new(
            "smtp",
            proto::SMTP,
            proto::SMTP,
            25,
            F_SMTP,
        )),
        #[cfg(feature = "smtp")]
        "smtps" => Some(SchemeHandler::new(
            "smtps",
            proto::SMTPS,
            proto::SMTP,
            465,
            F_SMTPS,
        )),
        #[cfg(feature = "telnet")]
        "telnet" => Some(SchemeHandler::new(
            "telnet",
            proto::TELNET,
            proto::TELNET,
            23,
            F_TELNET,
        )),
        #[cfg(feature = "dict")]
        "dict" => Some(SchemeHandler::new(
            "dict",
            proto::DICT,
            proto::DICT,
            2628,
            F_DICT,
        )),
        #[cfg(feature = "tftp")]
        "tftp" => Some(SchemeHandler::new(
            "tftp",
            proto::TFTP,
            proto::TFTP,
            69,
            F_TFTP,
        )),
        #[cfg(feature = "rtsp")]
        "rtsp" => Some(SchemeHandler::new(
            "rtsp",
            proto::RTSP,
            proto::RTSP,
            554,
            F_RTSP,
        )),
        #[cfg(feature = "mqtt")]
        "mqtt" => Some(SchemeHandler::new(
            "mqtt",
            proto::MQTT,
            proto::MQTT,
            1883,
            F_MQTT,
        )),
        #[cfg(feature = "mqtt")]
        "mqtts" => Some(SchemeHandler::new(
            "mqtts",
            proto::MQTTS,
            proto::MQTT,
            8883,
            F_MQTTS,
        )),
        // Schemes without a dedicated Cargo feature: always registered.
        "ldap" => Some(SchemeHandler::new(
            "ldap",
            proto::LDAP,
            proto::LDAP,
            389,
            F_LDAP,
        )),
        "ldaps" => Some(SchemeHandler::new(
            "ldaps",
            proto::LDAPS,
            proto::LDAP,
            636,
            F_LDAPS,
        )),
        "smb" => Some(SchemeHandler::new(
            "smb",
            proto::SMB,
            proto::SMB,
            445,
            F_SMB,
        )),
        "smbs" => Some(SchemeHandler::new(
            "smbs",
            proto::SMBS,
            proto::SMB,
            445,
            F_SMBS,
        )),
        "gopher" => Some(SchemeHandler::new(
            "gopher",
            proto::GOPHER,
            proto::GOPHER,
            70,
            F_GOPHER,
        )),
        "gophers" => Some(SchemeHandler::new(
            "gophers",
            proto::GOPHERS,
            proto::GOPHER,
            70,
            F_GOPHERS,
        )),
        "file" => Some(SchemeHandler::new(
            "file",
            proto::FILE,
            proto::FILE,
            0,
            F_FILE,
        )),
        _ => None,
    }
}

/// Selects the protocol handler for a scheme, curl's `findprotocol`
/// (`lib/url.c`).
///
/// The scheme must resolve to a built-in handler ([`get_scheme_handler`]) that
/// is permitted by `allowed_protocols` (`CURLOPT_PROTOCOLS`). When this lookup
/// happens as the result of a redirect (`is_follow == true`), the scheme must
/// additionally be permitted by `redir_protocols` (`CURLOPT_REDIR_PROTOCOLS`).
///
/// # Errors
///
/// Returns [`Error::UnsupportedProtocol`] (curl's `CURLE_UNSUPPORTED_PROTOCOL`)
/// when the scheme is unknown, disabled by the protocol mask, or — on a
/// redirect — not in the redirect-permitted set.
pub fn findprotocol(
    scheme: &str,
    allowed_protocols: u32,
    redir_protocols: u32,
    is_follow: bool,
) -> Result<SchemeHandler> {
    if let Some(handler) = get_scheme_handler(scheme) {
        // Protocol found and supported. Check if allowed for a normal request.
        if (allowed_protocols & handler.protocol) != 0 {
            // Extra check when this is the result of a redirect.
            if is_follow && (redir_protocols & handler.protocol) == 0 {
                // Not permitted as a redirect target: fall through to the error.
            } else {
                return Ok(handler);
            }
        }
    }
    Err(Error::UnsupportedProtocol)
}

/// Maps a URL-API error code to the transfer-level [`CurlCode`], curl's
/// `Curl_uc_to_curlcode` (`lib/url.c`).
///
/// The mapping is exact: `CURLUE_UNSUPPORTED_SCHEME` becomes
/// `CURLE_UNSUPPORTED_PROTOCOL`, `CURLUE_OUT_OF_MEMORY` becomes
/// `CURLE_OUT_OF_MEMORY`, `CURLUE_USER_NOT_ALLOWED` becomes
/// `CURLE_LOGIN_DENIED`, and every other URL error becomes
/// `CURLE_URL_MALFORMAT`.
#[must_use]
pub fn uc_to_curlcode(uc: urlapi::UrlCode) -> CurlCode {
    match uc {
        urlapi::UrlCode::UnsupportedScheme => CurlCode::UnsupportedProtocol,
        urlapi::UrlCode::OutOfMemory => CurlCode::OutOfMemory,
        urlapi::UrlCode::UserNotAllowed => CurlCode::LoginDenied,
        _ => CurlCode::UrlMalformat,
    }
}

/// Converts a URL-API result into a crate [`Result`], applying
/// [`uc_to_curlcode`] to any error — the idiomatic form of curl's pervasive
/// `return Curl_uc_to_curlcode(uc);` idiom.
fn uc<T>(res: core::result::Result<T, urlapi::UrlCode>) -> Result<T> {
    res.map_err(|code| Error::from(uc_to_curlcode(code)))
}

/// `CURL_HTTP_VERSION_NONE` — the default `CURLOPT_HTTP_VERSION` (do not care).
pub const CURL_HTTP_VERSION_NONE: i64 = 0;

/// `CURL_SSLVERSION_DEFAULT` — the default `CURLOPT_SSLVERSION`.
pub const CURL_SSLVERSION_DEFAULT: i64 = 0;

/// `CURLSSH_AUTH_ANY` / `CURLSSH_AUTH_DEFAULT` — allow any SSH auth type. curl
/// defines this as `~0`, which stored in the `long` `ssh_auth_types` field is
/// `-1`.
pub const CURLSSH_AUTH_ANY: i64 = -1;

/// The FTP file-retrieval directory-traversal method, mirroring curl's
/// `curl_ftpfile` enumeration (`include/curl/curl.h`). The default set by
/// `Curl_init_userdefined` is [`FtpFileMethod::MultiCwd`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FtpFileMethod {
    /// `FTPFILE_MULTICWD` — one `CWD` per path segment (the default).
    #[default]
    MultiCwd = 1,
    /// `FTPFILE_NOCWD` — no `CWD` at all; use the full path.
    NoCwd = 2,
    /// `FTPFILE_SINGLECWD` — a single `CWD` to the target directory.
    SingleCwd = 3,
}

/// The TLS configuration for a transfer, mirroring the fields of curl's
/// `struct ssl_primary_config` that participate in connection-reuse matching
/// and that carry non-trivial defaults.
///
/// **Defaults enforce TLS verification** (AAP §0.7.3): [`verify_peer`] is `true`
/// (`CURLOPT_SSL_VERIFYPEER = 1`) and [`verify_host`] is `2`
/// (`CURLOPT_SSL_VERIFYHOST = 2`), exactly as `Curl_ssl_easy_config_init`
/// (`lib/vtls/vtls.c`) sets them. The CLI's `--insecure` is the only way to
/// lower them, and it must warn before proceeding.
///
/// [`verify_peer`]: SslConfig::verify_peer
/// [`verify_host`]: SslConfig::verify_host
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SslConfig {
    /// `CURLOPT_SSL_VERIFYPEER` — verify the peer certificate chain. Default
    /// `true` (option value `1`).
    pub verify_peer: bool,
    /// `CURLOPT_SSL_VERIFYHOST` — verify the certificate's host name. Default
    /// `2` (the historical "verify" value; `0` disables). Stored as the option
    /// integer so the default reads back as `2`.
    pub verify_host: u8,
    /// `CURLOPT_SSL_VERIFYSTATUS` — verify the certificate's OCSP status.
    /// Default `false`.
    pub verify_status: bool,
    /// `CURLOPT_SSLVERSION` — minimum/maximum TLS version selector. Default
    /// [`CURL_SSLVERSION_DEFAULT`] (`0`).
    pub version: i64,
    /// `CURLOPT_CAINFO` — path to a CA certificate bundle.
    pub ca_info: Option<String>,
    /// `CURLOPT_CAPATH` — path to a directory of CA certificates.
    pub ca_path: Option<String>,
    /// `CURLOPT_SSLCERT` — client certificate.
    pub cert: Option<String>,
    /// `CURLOPT_SSLKEY` — client private key.
    pub key: Option<String>,
    /// `CURLOPT_SSL_CIPHER_LIST` — allowed cipher list.
    pub ciphers: Option<String>,
    /// `CURLOPT_PINNEDPUBLICKEY` — pinned public key.
    pub pinned_key: Option<String>,
}

impl Default for SslConfig {
    /// Reproduces `Curl_ssl_easy_config_init` — verification **on** by default.
    fn default() -> Self {
        SslConfig {
            verify_peer: true,
            verify_host: 2,
            verify_status: false,
            version: CURL_SSLVERSION_DEFAULT,
            ca_info: None,
            ca_path: None,
            cert: None,
            key: None,
            ciphers: None,
            pinned_key: None,
        }
    }
}

impl SslConfig {
    /// Returns `true` if two TLS configurations are equivalent for the purpose
    /// of connection reuse — curl's `Curl_ssl_conn_config_match`. Every field
    /// that would change the negotiated security properties must match.
    #[must_use]
    pub fn matches(&self, other: &SslConfig) -> bool {
        self.verify_peer == other.verify_peer
            && self.verify_host == other.verify_host
            && self.verify_status == other.verify_status
            && self.version == other.version
            && self.ca_info == other.ca_info
            && self.ca_path == other.ca_path
            && self.cert == other.cert
            && self.key == other.key
            && self.ciphers == other.ciphers
            && self.pinned_key == other.pinned_key
    }
}

/// The easy-handle configuration store — the `set.*` options.
///
/// This is a Rust rewrite of curl's `struct UserDefined` (`lib/urldata.h`),
/// holding the user-tunable options for a transfer. Both the idiomatic builder
/// in `lib.rs` and the `curl_easy_setopt` FFI shim write into an instance of
/// this struct, so its field defaults are the single source of truth for a
/// freshly-opened handle's behavior.
///
/// [`UserDefined::default`] reproduces `Curl_init_userdefined` field-for-field;
/// any drift from curl's defaults is a parity bug. Only the options consulted by
/// the URL/connection layer (and the ones with non-trivial defaults) are modeled
/// here — the exhaustive option set is filled in as sibling modules that own
/// each option are implemented.
#[derive(Debug, Clone)]
pub struct UserDefined {
    // --- transfer sizing ---
    /// `CURLOPT_INFILESIZE` — known upload size, `-1` if unknown (default).
    pub filesize: i64,
    /// `CURLOPT_POSTFIELDSIZE` — POST body size, `-1` if unknown (default).
    pub postfieldsize: i64,
    /// `CURLOPT_BUFFERSIZE` — receive buffer size. Default [`READBUFFER_SIZE`].
    pub buffer_size: usize,
    /// `CURLOPT_UPLOAD_BUFFERSIZE` — upload buffer size. Default
    /// [`UPLOADBUFFER_DEFAULT`].
    pub upload_buffer_size: usize,

    // --- HTTP request / redirect ---
    /// `CURLOPT_CUSTOMREQUEST`-independent request method. Default
    /// [`HttpReq::Get`].
    pub method: HttpReq,
    /// `CURLOPT_MAXREDIRS` — redirect limit. Default [`DEFAULT_MAXREDIRS`]
    /// (`30`); `-1` means unlimited.
    pub maxredirs: i64,
    /// `CURLOPT_FOLLOWLOCATION` — follow `Location:` redirects. Default `false`.
    pub follow_location: bool,
    /// `CURLOPT_FOLLOWLOCATION == CURLFOLLOW_FIRSTONLY` — drop a custom method
    /// after the first redirect. Default `false`.
    pub follow_first_only: bool,
    /// `CURLOPT_POSTREDIR & CURL_REDIR_POST_301` — keep `POST` across a 301.
    /// Default `false` (so a 301 switches `POST`→`GET`).
    pub post301: bool,
    /// `CURLOPT_POSTREDIR & CURL_REDIR_POST_302` — keep `POST` across a 302.
    pub post302: bool,
    /// `CURLOPT_POSTREDIR & CURL_REDIR_POST_303` — keep `POST` across a 303.
    pub post303: bool,
    /// `CURLOPT_AUTOREFERER` — automatically set the `Referer:` header to the
    /// previous URL when following a redirect. Default `false`.
    pub http_auto_referer: bool,
    /// `CURLOPT_PORT` — an explicit remote-port override that supersedes the
    /// port embedded in the URL (when [`EasyState::allow_port`] is set). `0`
    /// means "unset — use the URL's port". Default `0`.
    pub use_port: u16,
    /// `CURLOPT_UNRESTRICTED_AUTH` — keep sending credentials across hosts on
    /// redirect. Default `false` (credentials are stripped cross-origin).
    pub allow_auth_to_other_hosts: bool,
    /// `CURLOPT_PATH_AS_IS` — do not squash `..`/`.` in the path. Default
    /// `false`.
    pub path_as_is: bool,
    /// `CURLOPT_HTTP_VERSION`. Default [`CURL_HTTP_VERSION_NONE`].
    pub httpwant: i64,
    /// `CURLOPT_HTTP09_ALLOWED`. Default `false`.
    pub http09_allowed: bool,

    // --- protocol gating ---
    /// `CURLOPT_PROTOCOLS(_STR)` — permitted protocols. Default
    /// [`proto::ALL`].
    pub allowed_protocols: u32,
    /// `CURLOPT_REDIR_PROTOCOLS(_STR)` — protocols permitted as redirect
    /// targets. Default [`proto::REDIR`].
    pub redir_protocols: u32,

    // --- authentication ---
    /// `CURLOPT_HTTPAUTH` — HTTP auth methods. Default [`authmask::BASIC`].
    pub httpauth: u64,
    /// `CURLOPT_PROXYAUTH` — proxy auth methods. Default [`authmask::BASIC`].
    pub proxyauth: u64,
    /// `CURLOPT_SOCKS5_AUTH` — SOCKS5 auth methods. Default
    /// [`authmask::BASIC`]` | `[`authmask::GSSAPI`].
    pub socks5auth: u64,

    // --- credentials (string options) ---
    /// `CURLOPT_USERNAME`.
    pub username: Option<String>,
    /// `CURLOPT_PASSWORD`.
    pub password: Option<String>,
    /// `CURLOPT_OPTIONS` (the login `;options`, e.g. for IMAP/POP3/SMTP).
    pub login_options: Option<String>,

    // --- .netrc ---
    /// `CURLOPT_NETRC` — `.netrc` usage level. Default [`NetrcLevel::Ignored`].
    pub use_netrc: NetrcLevel,
    /// `CURLOPT_NETRC_FILE` — explicit `.netrc` path, if any.
    pub netrc_file: Option<PathBuf>,

    // --- cookies ---
    /// `CURLOPT_COOKIE` — an inline cookie string (`-b name=value`) sent
    /// verbatim in the `Cookie:` request header. This is NOT stored in the jar
    /// (it never appears in a `-c` save), matching curl's `data->set.str`
    /// `[STRING_COOKIE]`. Multiple `-b` values are concatenated with `"; "`.
    pub cookie: Option<String>,
    /// `CURLOPT_COOKIEFILE` — cookie files to read (`-b file`). A non-empty list
    /// (or a set [`cookiejar`](UserDefined::cookiejar)) turns the jar engine on.
    /// Mirrors curl's `data->state.cookielist`.
    pub cookiefiles: Vec<String>,
    /// `CURLOPT_COOKIEJAR` — path the jar is written to at end of transfer
    /// (`-c`). Setting it enables the jar engine even with no read file.
    pub cookiejar: Option<String>,
    /// `CURLOPT_COOKIESESSION` — start a new cookie session (`-j`), discarding
    /// session cookies when loading the jar file (`data->set.cookiesession`).
    pub cookiesession: bool,
    /// `CURLOPT_HSTS` — the HSTS cache file (`--hsts`). Setting it enables the
    /// HSTS engine: the file is read at init (if present) and rewritten after
    /// the transfer. Mirrors curl's `data->set.str[STRING_HSTS]`.
    pub hsts_file: Option<String>,
    /// `CURLOPT_ALTSVC` — the Alt-Svc cache file (`--alt-svc`). Setting it
    /// enables the Alt-Svc engine (read at init, rewritten after the
    /// transfer). Mirrors curl's `data->set.str[STRING_ALTSVC]`.
    pub altsvc_file: Option<String>,

    // --- addressing ---
    /// `CURLOPT_RESOLVE` — custom `host:port:addr[,addr…]` pre-resolution
    /// entries (`--resolve`), stored verbatim in curl's `--resolve` syntax
    /// (including the `+`/`-`/`*` prefixes). Applied to each hop's DNS cache via
    /// [`crate::dns::load_host_pairs`] before name resolution, so a matching
    /// host short-circuits to the caller-supplied address. Empty by default.
    /// Mirrors curl's `data->set.resolve` `curl_slist`, so `duphandle` clones it.
    pub resolve: Vec<String>,
    /// `CURLOPT_IPRESOLVE`. Default [`IpResolve::Whatever`].
    pub ipver: IpResolve,
    /// `CURLOPT_LOCALPORT` — bind to a specific local port (`0` = any).
    pub localport: u16,
    /// `CURLOPT_LOCALPORTRANGE` — number of local ports to try.
    pub localportrange: u16,
    /// `CURLOPT_INTERFACE` — bind to a specific local device/interface.
    pub localdev: Option<String>,

    // --- proxy ---
    /// `CURLOPT_PROXY` — proxy URL, if any.
    pub proxy: Option<String>,
    /// `CURLOPT_NOPROXY` — comma-separated no-proxy host list.
    pub no_proxy: Option<String>,
    /// `CURLOPT_PROXYTYPE`. Default [`ProxyType::Http`].
    pub proxytype: ProxyType,
    /// `CURLOPT_PROXYPORT`. Default `0` (use the proxy scheme's default).
    pub proxyport: u16,
    /// `CURLOPT_PROXYUSERNAME`.
    pub proxy_user: Option<String>,
    /// `CURLOPT_PROXYPASSWORD`.
    pub proxy_password: Option<String>,
    /// `socks5_gssapi_nec` — permit unprotected SOCKS5 GSS-API negotiation.
    /// Default `false`.
    pub socks5_gssapi_nec: bool,

    // --- TLS ---
    /// The server TLS configuration (see [`SslConfig`]).
    pub ssl: SslConfig,
    /// The proxy TLS configuration (HTTPS proxies).
    pub proxy_ssl: SslConfig,
    /// `CURLOPT_SSL_ENABLE_ALPN`. Default `true`.
    pub ssl_enable_alpn: bool,

    // --- FTP ---
    /// `CURLOPT_FTP_USE_EPSV`. Default `true`.
    pub ftp_use_epsv: bool,
    /// `CURLOPT_FTP_USE_EPRT`. Default `true`.
    pub ftp_use_eprt: bool,
    /// `CURLOPT_FTP_USE_PRET`. Default `false`.
    pub ftp_use_pret: bool,
    /// `CURLOPT_FTP_SKIP_PASV_IP`. Default `true`.
    pub ftp_skip_ip: bool,
    /// `CURLOPT_FTP_FILEMETHOD`. Default [`FtpFileMethod::MultiCwd`].
    pub ftp_filemethod: FtpFileMethod,
    /// `CURLOPT_WILDCARDMATCH`. Default `false`.
    pub wildcard_enabled: bool,

    // --- SSH ---
    /// `CURLOPT_SSH_AUTH_TYPES`. Default [`CURLSSH_AUTH_ANY`].
    pub ssh_auth_types: i64,
    /// `CURLOPT_NEW_DIRECTORY_PERMS`. Default `0o755`.
    pub new_directory_perms: u32,
    /// `CURLOPT_NEW_FILE_PERMS`. Default `0o644`.
    pub new_file_perms: u32,

    // --- TCP / connection tuning ---
    /// `CURLOPT_TCP_KEEPALIVE`. Default `false`.
    pub tcp_keepalive: bool,
    /// `CURLOPT_TCP_KEEPINTVL` (seconds). Default `60`.
    pub tcp_keepintvl: i64,
    /// `CURLOPT_TCP_KEEPIDLE` (seconds). Default `60`.
    pub tcp_keepidle: i64,
    /// `CURLOPT_TCP_KEEPCNT`. Default `9`.
    pub tcp_keepcnt: i64,
    /// `CURLOPT_TCP_FASTOPEN`. Default `false`.
    pub tcp_fastopen: bool,
    /// `CURLOPT_TCP_NODELAY`. Default `true`.
    pub tcp_nodelay: bool,
    /// `CURLOPT_EXPECT_100_TIMEOUT_MS`. Default `1000`.
    pub expect_100_timeout: i64,
    /// Whether header lists are kept separate. Default `true`.
    pub sep_headers: bool,

    // --- DNS / cache / reuse ---
    /// `CURLOPT_DNS_CACHE_TIMEOUT` (ms). Default `60000`.
    pub dns_cache_timeout_ms: i64,
    /// CA-cache timeout (seconds). Default `86400` (24h).
    pub ca_cache_timeout: i64,
    /// `CURLOPT_MAXCONNECTS`. Default [`DEFAULT_CONNCACHE_SIZE`] (`5`).
    pub maxconnects: usize,
    /// `CURLOPT_MAXLIFETIME_CONN` — max connection idle time (ms). Default
    /// `118000` (118s).
    pub conn_max_idle_ms: i64,
    /// `CURLOPT_MAXAGE_CONN` — max connection age (ms). Default `86400000`
    /// (24h).
    pub conn_max_age_ms: i64,
    /// `CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS`. Default [`CURL_HET_DEFAULT`] (`200`).
    pub happy_eyeballs_timeout: u64,
    /// `CURLOPT_UPKEEP_INTERVAL_MS`. Default [`CURL_UPKEEP_INTERVAL_DEFAULT`]
    /// (`60000`).
    pub upkeep_interval_ms: u64,

    // --- DoH ---
    /// `CURLOPT_DOH_SSL_VERIFYHOST`. Default `true`.
    pub doh_verifyhost: bool,
    /// `CURLOPT_DOH_SSL_VERIFYPEER`. Default `true`.
    pub doh_verifypeer: bool,

    // --- misc ---
    /// `CURLOPT_QUICK_EXIT`. Default `false`.
    pub quick_exit: bool,
    /// WebSocket raw mode (`CURLWS_RAW_MODE`). Default `false`.
    pub ws_raw_mode: bool,
    /// WebSocket: suppress automatic `PONG`. Default `false`.
    pub ws_no_auto_pong: bool,
    /// `CURLOPT_CONNECT_ONLY`. Default `false`.
    pub connect_only: bool,
}

impl Default for UserDefined {
    /// Reproduces `Curl_init_userdefined` (`lib/url.c`) exactly — every default
    /// here is a byte-for-byte match with curl 8.x.
    fn default() -> Self {
        UserDefined {
            filesize: -1,
            postfieldsize: -1,
            buffer_size: READBUFFER_SIZE,
            upload_buffer_size: UPLOADBUFFER_DEFAULT,

            method: HttpReq::Get,
            maxredirs: DEFAULT_MAXREDIRS,
            follow_location: false,
            follow_first_only: false,
            post301: false,
            post302: false,
            post303: false,
            http_auto_referer: false,
            use_port: 0,
            allow_auth_to_other_hosts: false,
            path_as_is: false,
            httpwant: CURL_HTTP_VERSION_NONE,
            http09_allowed: false,

            allowed_protocols: proto::ALL,
            redir_protocols: proto::REDIR,

            httpauth: authmask::BASIC,
            proxyauth: authmask::BASIC,
            socks5auth: authmask::BASIC | authmask::GSSAPI,

            username: None,
            password: None,
            login_options: None,

            use_netrc: NetrcLevel::Ignored,
            netrc_file: None,

            cookie: None,
            cookiefiles: Vec::new(),
            cookiejar: None,
            cookiesession: false,
            hsts_file: None,
            altsvc_file: None,

            resolve: Vec::new(),
            ipver: IpResolve::Whatever,
            localport: 0,
            localportrange: 0,
            localdev: None,

            proxy: None,
            no_proxy: None,
            proxytype: ProxyType::Http,
            proxyport: 0,
            proxy_user: None,
            proxy_password: None,
            socks5_gssapi_nec: false,

            ssl: SslConfig::default(),
            proxy_ssl: SslConfig::default(),
            ssl_enable_alpn: true,

            ftp_use_epsv: true,
            ftp_use_eprt: true,
            ftp_use_pret: false,
            ftp_skip_ip: true,
            ftp_filemethod: FtpFileMethod::MultiCwd,
            wildcard_enabled: false,

            ssh_auth_types: CURLSSH_AUTH_ANY,
            new_directory_perms: 0o755,
            new_file_perms: 0o644,

            tcp_keepalive: false,
            tcp_keepintvl: 60,
            tcp_keepidle: 60,
            tcp_keepcnt: 9,
            tcp_fastopen: false,
            tcp_nodelay: true,
            expect_100_timeout: 1000,
            sep_headers: true,

            dns_cache_timeout_ms: 60000,
            ca_cache_timeout: 24 * 60 * 60,
            maxconnects: DEFAULT_CONNCACHE_SIZE,
            conn_max_idle_ms: 118 * 1000,
            conn_max_age_ms: 24 * 3600 * 1000,
            happy_eyeballs_timeout: CURL_HET_DEFAULT,
            upkeep_interval_ms: CURL_UPKEEP_INTERVAL_DEFAULT,

            doh_verifyhost: true,
            doh_verifypeer: true,

            quick_exit: false,
            ws_raw_mode: false,
            ws_no_auto_pong: false,
            connect_only: false,
        }
    }
}

impl UserDefined {
    /// Creates a fully-defaulted option store, curl's `Curl_init_userdefined`.
    #[must_use]
    pub fn new() -> Self {
        UserDefined::default()
    }
}

// ===========================================================================
// The easy handle: operational state (`struct Curl_easy`) plus the info curl
// exposes about the last/active connection (`struct PureInfo`).
// ===========================================================================

/// Read-back information about the active/most-recent connection, a subset of
/// curl's `struct PureInfo` (`lib/urldata.h`) needed by the redirect logic.
///
/// These fields are populated once a connection is established and are consulted
/// by [`Easy::follow`] to decide whether a redirect crosses an origin boundary
/// (and must therefore strip credentials).
#[derive(Debug, Clone, Default)]
pub struct Info {
    /// The remote port of the current connection (`info.conn_remote_port`).
    pub conn_remote_port: u16,
    /// The `CURLPROTO_*` bit of the current connection's protocol
    /// (`info.conn_protocol`).
    pub conn_protocol: u32,
    /// The scheme name of the current connection (`info.conn_scheme`).
    pub conn_scheme: Option<String>,
    /// The would-be redirect target recorded when following is disabled or the
    /// redirect limit is hit (`info.wouldredirect`).
    pub wouldredirect: Option<String>,
    /// The HTTP status code of the most recent response (`info.httpcode` /
    /// `req.httpcode`). Consulted by [`Easy::follow`] to decide `POST`→`GET`
    /// method switching and whether a redirect is auth-related (`401`/`407`).
    pub httpcode: i32,
    /// The `Content-Type` of the most recently retrieved document, as read back
    /// by `CURLINFO_CONTENT_TYPE` (curl's `data->info.contenttype`). It is set
    /// by the HTTP response-header processing path when a `Content-Type:` header
    /// is seen (see [`set_content_type`](Info::set_content_type)) and is `None`
    /// when the response carried no such header — exactly as curl leaves
    /// `data->info.contenttype` `NULL`. The CLI consults it for `--xattr`
    /// (`user.mime_type`) and `--write-out %{content_type}`.
    pub contenttype: Option<String>,
    /// Total number of body bytes received during the transfer, as read back by
    /// `CURLINFO_SIZE_DOWNLOAD_T` (curl's `data->progress.dl.cur_size`). Counts
    /// every body byte delivered to the client sink regardless of the output
    /// destination (including the `/dev/null` bit-bucket), so `--write-out
    /// %{size_download}` reports the real received size. `0` until a transfer
    /// runs.
    pub size_download: i64,
    /// Total number of body bytes uploaded during the transfer, as read back by
    /// `CURLINFO_SIZE_UPLOAD_T` (curl's `data->progress.ul.cur_size`). Set to the
    /// length of the request body actually sent (`-d`/`-T` payload). `0` until a
    /// transfer runs or when no body is sent.
    pub size_upload: i64,
    /// Time, in **microseconds**, from the start of the transfer until the name
    /// resolution completed, as read back by `CURLINFO_NAMELOOKUP_TIME_T`
    /// (curl's `data->progress.t_nslookup`). `0` until a transfer runs; curl's
    /// `*_TIME_T` getinfo variants likewise report `0` when unmeasured.
    pub namelookup_time_us: i64,
    /// Time, in **microseconds**, from the start of the transfer until the TCP
    /// connection to the remote (or proxy) completed, as read back by
    /// `CURLINFO_CONNECT_TIME_T` (curl's `data->progress.t_connect`). `0` until a
    /// transfer runs.
    pub connect_time_us: i64,
    /// Time, in **microseconds**, from the start of the transfer until the
    /// TLS/SSL handshake completed, as read back by `CURLINFO_APPCONNECT_TIME_T`
    /// (curl's `data->progress.t_appconnect`). `0` for cleartext connections
    /// (curl reports `0` for a non-TLS transfer) and `0` until a transfer runs.
    pub appconnect_time_us: i64,
    /// Time, in **microseconds**, from the start of the transfer until just
    /// before the request is sent (all connection setup complete), as read back
    /// by `CURLINFO_PRETRANSFER_TIME_T` (curl's `data->progress.t_pretransfer`).
    /// `0` until a transfer runs.
    pub pretransfer_time_us: i64,
    /// Time, in **microseconds**, from the start of the transfer until the first
    /// byte of the response was received, as read back by
    /// `CURLINFO_STARTTRANSFER_TIME_T` (curl's `data->progress.t_starttransfer`).
    /// `0` until a transfer runs.
    pub starttransfer_time_us: i64,
    /// Total transfer time, in **microseconds**, from start to completion, as
    /// read back by `CURLINFO_TOTAL_TIME_T` (curl's `data->progress.timespent`).
    /// This is the value reported by `--write-out %{time_total}` and the
    /// denominator for the `%{speed_download}` / `%{speed_upload}` rates. `0`
    /// until a transfer runs.
    pub total_time_us: i64,
    /// The reason phrase of the most recent HTTP response (e.g. `"OK"` for a
    /// `200`), when the response carried one. Recorded alongside
    /// [`httpcode`](Info::httpcode) so the `-v`/`--trace` formatter can
    /// reconstruct the received status line (`< HTTP/1.1 <code> <reason>`);
    /// `None` when the response had no reason phrase or no transfer has run.
    pub resp_reason: Option<String>,
    /// The ordered `(name, value)` header fields of the most recent HTTP
    /// response head, captured for the `-v`/`--trace` `< ` (HEADER_IN) dump.
    /// Empty until an HTTP transfer records a response; not consulted by any
    /// non-trace path, so it costs nothing when tracing is off.
    pub resp_headers: Vec<(String, String)>,
}

/// A [`TransferSink`](crate::protocols::TransferSink) adapter that counts the body bytes it
/// forwards to an inner sink, feeding `CURLINFO_SIZE_DOWNLOAD_T`. It wraps the client's sink
/// inside [`Easy::perform_transfer`] so the received-byte total is measured independently of
/// where the client ultimately writes the data (a file, stdout, or the `/dev/null`
/// bit-bucket), exactly as curl's internal `dl.cur_size` counter is decoupled from the write
/// callback's destination.
struct CountingSink {
    /// The client's real body sink.
    inner: Box<dyn crate::protocols::TransferSink>,
    /// Shared running total of forwarded body bytes.
    counter: Arc<std::sync::atomic::AtomicI64>,
    /// When `Some` (only while `-v`/`--trace` is active), a shared buffer that accumulates a copy
    /// of every received body byte so [`Easy::perform_transfer`] can render the `{ [N bytes
    /// data]` summary (or, under `--trace`, the hex/ascii dump) after the response head. `None`
    /// on the normal path, so no body copy is made when tracing is off.
    capture: Option<Arc<std::sync::Mutex<Vec<u8>>>>,
}

impl crate::protocols::TransferSink for CountingSink {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        // Count first, then forward; a rejected write still reflects the bytes curl's counter
        // would have tallied before the write callback signalled failure.
        self.counter
            .fetch_add(data.len() as i64, std::sync::atomic::Ordering::SeqCst);
        // Copy into the trace buffer when tracing is active (curl's debug callback sees the same
        // body bytes it delivers to the write callback).
        if let Some(buf) = &self.capture {
            if let Ok(mut b) = buf.lock() {
                b.extend_from_slice(data);
            }
        }
        self.inner.write(data)
    }
}

/// A body sink that buffers received bytes in memory instead of forwarding them
/// to the client.
///
/// Used by [`Easy::perform_transfer`] for each hop of a redirect chain while
/// `CURLOPT_FOLLOWLOCATION` is active: a followed `3xx` response body is
/// discarded (curl's `k->ignorebody` on a redirect), and the final response's
/// buffered body is flushed to the real client sink once the loop terminates.
/// This keeps intermediate redirect bodies off the output exactly as curl does.
struct BufferSink {
    /// Shared accumulator; the owning transfer either discards it (redirect) or
    /// drains it into the client sink (final response).
    buf: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl crate::protocols::TransferSink for BufferSink {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        if let Ok(mut b) = self.buf.lock() {
            b.extend_from_slice(data);
        }
        Ok(())
    }
}

/// Maps a request method verb onto the [`HttpReq`] state kind so the RFC 7231
/// redirect method-switch (`apply_redirect_method_switch`, driven by
/// [`Easy::follow`]) operates on the real method rather than the `Get` default.
///
/// The three standard body-bearing verbs map to their kinds; a bodiless `GET`
/// (`-I`/`--head` forces the `HEAD` verb, but a `GET` with `no_body` is still a
/// HEAD-shaped request) maps to `Head`. Any other verb — including a custom
/// `-X`/`CURLOPT_CUSTOMREQUEST` method such as `DELETE` or `PATCH` — maps to
/// `Get`, which curl treats as method-preserving across a redirect (a custom
/// method is carried through unchanged), matching curl's `CUSTOMREQUEST`
/// behavior.
fn httpreq_from_method(method: &str, no_body: bool) -> HttpReq {
    match method {
        "POST" => HttpReq::Post,
        "PUT" => HttpReq::Put,
        "HEAD" => HttpReq::Head,
        "GET" if no_body => HttpReq::Head,
        _ => HttpReq::Get,
    }
}

/// The ALPN protocol identifiers to offer on an HTTPS handshake, derived from
/// the handle's effective `CURLOPT_HTTP_VERSION` preference
/// ([`UserDefined::httpwant`]) — a faithful port of curl's ALPN-offer selection
/// in `lib/http.c` (`Curl_http_size`/`alpn_setup`).
///
/// * `CURL_HTTP_VERSION_1_0` (`1`) / `CURL_HTTP_VERSION_1_1` (`2`) restrict the
///   offer to `http/1.1`.
/// * Every other value — `NONE` (`0`), `2_0` (`3`), `2TLS` (`4`), and the
///   HTTP/3 selectors (`30`/`31`, which negotiate `h3` over QUIC on a separate
///   path) — offers `h2, http/1.1`, matching curl's default HTTPS ALPN set.
fn alpn_offer_for_httpwant(httpwant: i64) -> Vec<Vec<u8>> {
    // CURL_HTTP_VERSION_1_0 == 1, CURL_HTTP_VERSION_1_1 == 2.
    if httpwant == 1 || httpwant == 2 {
        vec![crate::tls::ALPN_HTTP_1_1.to_vec()]
    } else {
        crate::tls::default_https_alpn()
    }
}

/// Returns the redirect target from a completed response when it is a `3xx`
/// carrying a `Location:` header that the follow logic should chase.
///
/// The status codes are curl's redirect set (`301`, `302`, `303`, `307`,
/// `308`); the header lookup is case-insensitive per RFC 7230. Returns `None`
/// for any non-redirect status or a redirect without a usable `Location`.
fn redirect_location(info: &Info) -> Option<String> {
    if !matches!(info.httpcode, 301 | 302 | 303 | 307 | 308) {
        return None;
    }
    info.resp_headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("location"))
        .map(|(_, value)| value.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Appends the `-v`/`--trace` response-head records (status line + one record
/// per header + the terminating blank line) for an HTTP(S) hop, mirroring
/// curl's per-line `CURLINFO_HEADER_IN` delivery. A no-op for a non-HTTP scheme
/// or a hop that recorded no status.
fn push_response_head_trace(
    records: &mut Vec<(crate::protocols::DebugInfoType, Vec<u8>)>,
    info: &Info,
    scheme: &str,
) {
    use crate::protocols::DebugInfoType;
    if !matches!(scheme, "http" | "https") || info.httpcode == 0 {
        return;
    }
    let reason = info.resp_reason.clone().unwrap_or_default();
    let status_line = if reason.is_empty() {
        format!("HTTP/1.1 {}\r\n", info.httpcode)
    } else {
        format!("HTTP/1.1 {} {reason}\r\n", info.httpcode)
    };
    records.push((DebugInfoType::HeaderIn, status_line.into_bytes()));
    for (name, value) in &info.resp_headers {
        records.push((
            DebugInfoType::HeaderIn,
            format!("{name}: {value}\r\n").into_bytes(),
        ));
    }
    records.push((DebugInfoType::HeaderIn, b"\r\n".to_vec()));
}

impl Info {
    /// Record the response `Content-Type` header value (← the `data->info.contenttype`
    /// assignment in curl's `Curl_http_readwrite_headers`, `lib/http.c`).
    ///
    /// The value is stored verbatim (the full header value after the `Content-Type:`
    /// name and its optional whitespace), matching curl, which keeps the entire value
    /// including any `; charset=…` parameter. Passing an empty string clears the field
    /// so that a `Content-Type:` header with no value is reported as absent, mirroring
    /// curl's behavior of only recording a non-empty type.
    pub fn set_content_type(&mut self, value: &str) {
        let trimmed = value.trim();
        self.contenttype = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
    }
}

/// The mutable, per-transfer operational state of an easy handle — the parts of
/// curl's `struct Curl_easy` (its `->state` sub-struct) that the URL/redirect
/// layer manipulates.
#[derive(Debug, Default)]
pub struct EasyState {
    /// The URL-API handle holding the current (and, during a redirect, the
    /// base) URL — curl's `state.uh`. Populated by [`Easy::set_url`].
    pub uh: Option<Url>,
    /// The number of `Location:` redirects followed so far — curl's
    /// `state.followlocation`. Compared against [`UserDefined::maxredirs`].
    pub followlocation: i64,
    /// The total number of real requests issued (including redirect follows) —
    /// curl's `state.requests`.
    pub requests: i64,
    /// Whether the current URL was reached by following a redirect — curl's
    /// `state.this_is_a_follow`. Gates `CURLOPT_REDIR_PROTOCOLS`.
    pub this_is_a_follow: bool,
    /// Whether a custom port is permitted for the current URL — curl's
    /// `state.allow_port`. Cleared for absolute redirect targets.
    pub allow_port: bool,
    /// Where the currently-effective credentials came from — curl's
    /// `state.creds_from` — used to arbitrate URL vs option vs `.netrc`.
    pub creds_from: CredsFrom,
    /// The resolved user name (curl's `state.aptr.user`).
    pub aptr_user: Option<String>,
    /// The resolved password (curl's `state.aptr.passwd`).
    pub aptr_passwd: Option<String>,
    /// The auto-referer value for the next request (curl's `state.referer`).
    pub referer: Option<String>,
    /// The `.netrc` store, cached across lookups (curl's `state.netrc`).
    pub netrc: Netrc,
    /// The live cookie jar (curl's `data->cookies`), present when the cookie
    /// engine is enabled (a `CURLOPT_COOKIEFILE`/`-b file` was given or a
    /// `CURLOPT_COOKIEJAR`/`-c` path is set). Created and seeded by
    /// [`Easy::cookie_init`], consulted per hop to emit the `Cookie:` header,
    /// updated from each response's `Set-Cookie:`, and written by
    /// [`Easy::save_cookies`]. `None` when no jar engine is active (inline
    /// `-b name=value` cookies are sent without a jar). Compiled only with the
    /// `cookies` feature (curl's `CURL_DISABLE_COOKIES` removes the engine).
    #[cfg(feature = "cookies")]
    pub cookies: Option<crate::cookie::CookieJar>,
    /// The live HSTS cache (curl's `data->hsts`), present when `CURLOPT_HSTS`/
    /// `--hsts` supplied a cache file. Created and seeded from the file (if it
    /// exists) by [`Easy::hsts_init`], consulted per hop to upgrade an
    /// `http://` URL to `https://` for a known HSTS host, updated from each
    /// response's `Strict-Transport-Security:` header, and written back by
    /// [`Easy::save_hsts`]. `None` when no HSTS engine is active. The save
    /// target file path lives on [`UserDefined::hsts_file`].
    pub hsts: Option<crate::hsts::Hsts>,
    /// The live Alt-Svc cache (curl's `data->asi`), present when
    /// `CURLOPT_ALTSVC`/`--alt-svc` supplied a cache file. Created and seeded
    /// by [`Easy::altsvc_init`], updated from each response's `Alt-Svc:`
    /// header, and written back by [`Easy::save_altsvc`]. `None` when inactive.
    /// The save target file path lives on [`UserDefined::altsvc_file`].
    pub altsvc: Option<crate::altsvc::AltSvc>,
    /// The HTTP status code of the response that triggered the current redirect
    /// (curl's `state.httpreq`/`req.httpcode` context); tracked so
    /// [`Easy::follow`] can decide `POST`→`GET` switching.
    pub httpreq: HttpReq,
}

/// A libcurl easy handle — a Rust rewrite of curl's `struct Curl_easy` as it is
/// created and configured by `lib/url.c`.
///
/// An `Easy` bundles the user options ([`set`](Easy::set)), the operational
/// state ([`state`](Easy::state)), and the connection info
/// ([`info`](Easy::info)). It is created with [`Easy::open`] (curl's
/// `Curl_open`) and copied with [`Easy::duphandle`] (curl's
/// `curl_easy_duphandle`).
#[derive(Debug, Default)]
pub struct Easy {
    /// The user-defined options (`data->set`).
    pub set: UserDefined,
    /// The operational state (`data->state`).
    pub state: EasyState,
    /// Read-back connection info (`data->info`).
    pub info: Info,
    /// The cross-handle sharing object attached via `CURLOPT_SHARE`
    /// (curl's `data->share`), or `None` when this handle shares nothing.
    ///
    /// Holding the [`Arc<Share>`](Share) both keeps the fine-grained shared
    /// caches (cookies / DNS / connection pool / PSL / HSTS / SSL sessions)
    /// reachable — gated by the share's `specifier` — and keeps the share's
    /// attach count (`dirty`) correct: [`Easy::attach_share`] bumps it and both
    /// [`Easy::detach_share`] and [`Drop`] release it, so `curl_share_cleanup`
    /// observes `CURLSHE_IN_USE` for exactly as long as a handle is attached.
    pub share: Option<Arc<Share>>,
    /// Whether the owner wants `-v`/`--trace` diagnostics captured for the next transfer
    /// (curl's `data->set.verbose` / an installed `CURLOPT_DEBUGFUNCTION`). When `true`,
    /// [`Easy::perform_transfer`] records the transfer's trace events into
    /// [`debug_log`](Easy::debug_log); when `false` (the default) no records are captured and the
    /// hot path is unaffected. The CLI sets it from `global.tracetype` before each transfer.
    pub trace_enabled: bool,
    /// Buffered `-v`/`--trace` records captured during the last transfer, in emission order
    /// (curl streams each to `CURLOPT_DEBUGFUNCTION` as it happens; the CLI drives the library
    /// directly rather than through the FFI, so records are buffered here and drained afterwards
    /// with [`take_debug_log`](Easy::take_debug_log)). Empty unless
    /// [`trace_enabled`](Easy::trace_enabled) was set. Each entry pairs a
    /// [`DebugInfoType`](crate::protocols::DebugInfoType) with its raw payload bytes, which the
    /// CLI renders through curl's byte-exact trace formatter.
    pub debug_log: Vec<(crate::protocols::DebugInfoType, Vec<u8>)>,
}

impl Easy {
    /// Creates and initializes a fresh easy handle — curl's `Curl_open`.
    ///
    /// The options are set to their `Curl_init_userdefined` defaults and all
    /// operational state starts empty, mirroring `Curl_open` followed by
    /// `Curl_init_userdefined`.
    #[must_use]
    pub fn open() -> Self {
        Easy::default()
    }

    /// Duplicates the handle — curl's `curl_easy_duphandle`.
    ///
    /// The **options** ([`set`](Easy::set)) are copied verbatim, while the live
    /// operational state ([`state`](Easy::state)) and connection info
    /// ([`info`](Easy::info)) are reset to a freshly-opened condition. This
    /// matches curl, which duplicates the configuration but never the active
    /// transfer/connection of the source handle.
    #[must_use]
    pub fn duphandle(&self) -> Easy {
        Easy {
            set: self.set.clone(),
            state: EasyState::default(),
            info: Info::default(),
            // curl's `dupset` does not copy `data->share`: a duplicated handle
            // starts attached to no share (the caller must re-issue
            // `CURLOPT_SHARE` to share), so `dirty` is not inadvertently bumped.
            share: None,
            // A duplicated handle starts with a fresh operational state, so it captures no
            // trace and carries no buffered `-v`/`--trace` records until its owner opts in.
            trace_enabled: false,
            debug_log: Vec::new(),
        }
    }

    /// Installs the transfer URL, seeding the URL-API handle
    /// (`state.uh`) used for parsing and later relative redirect resolution —
    /// the effect of `parseurlandfillconn` setting `data->state.uh`.
    ///
    /// The URL is parsed permissively (`GUESS_SCHEME`), matching curl's default
    /// behavior of accepting a schemeless URL like `example.com`.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] derived from the URL-API failure (via
    /// [`uc_to_curlcode`]) when the URL cannot be parsed.
    pub fn set_url(&mut self, url: &str) -> Result<()> {
        let flags = urlapi::GUESS_SCHEME
            | urlapi::NON_SUPPORT_SCHEME
            | if self.set.path_as_is {
                urlapi::PATH_AS_IS
            } else {
                0
            };
        let parsed = uc(Url::parse(url, flags))?;
        self.state.uh = Some(parsed);
        // A freshly-set URL permits its embedded port (curl sets allow_port
        // TRUE for the initial URL; only absolute redirect targets clear it).
        self.state.allow_port = true;
        Ok(())
    }

    /// Attaches a cross-handle [`Share`] to this easy handle — the core of
    /// `curl_easy_setopt(CURLOPT_SHARE, sh)` (curl's `data->share = set;
    /// data->share->dirty++`).
    ///
    /// Any share previously attached is released first (via
    /// [`detach_share`](Easy::detach_share)), so the share's attach count stays
    /// balanced when `CURLOPT_SHARE` is issued more than once. The handle then
    /// records the new share and bumps its attach count so that a concurrent
    /// `curl_share_cleanup` correctly reports `CURLSHE_IN_USE`.
    pub fn attach_share(&mut self, share: Arc<Share>) {
        self.detach_share();
        share.attach();
        self.share = Some(share);
    }

    /// Detaches any currently attached [`Share`], decrementing its attach count
    /// (curl's `data->share->dirty--; data->share = NULL`). A no-op when no
    /// share is attached; idempotent, so [`Drop`] can call it unconditionally.
    pub fn detach_share(&mut self) {
        if let Some(share) = self.share.take() {
            share.detach();
        }
    }

    /// The cross-handle [`Share`] currently attached (`data->share`), if any.
    #[must_use]
    pub fn share(&self) -> Option<&Arc<Share>> {
        self.share.as_ref()
    }
}

impl Drop for Easy {
    /// Releases any attached [`Share`] so its `dirty` attach count drops when
    /// the handle is cleaned up — the effect of `curl_easy_cleanup` on a handle
    /// that still references a share (`Curl_share ... dirty--`). Without this,
    /// `curl_share_cleanup` would forever see the share as `CURLSHE_IN_USE`.
    fn drop(&mut self) {
        self.detach_share();
    }
}

// ===========================================================================
// Connection model (`struct connectdata`) and the connection pool
// (`struct cpool`/`conncache`).
//
// NOTE: the concrete transport, filter chain, and multiplex state of a live
// connection are owned by the connection subsystem (`crate::conn`). What lives
// here is the URL layer's own view — the identity a connection is *created*
// with and matched on for reuse: destination, credentials, TLS parameters and
// proxy configuration. This is exactly the data curl's `create_conn` fills into
// a "needle" `connectdata` and that `url_match_conn` compares.
// ===========================================================================

/// The per-connection boolean flags relevant to reuse matching — a subset of
/// curl's `struct ConnectBits`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnBits {
    /// This connection was obtained by reuse (`bits.reuse`).
    pub reuse: bool,
    /// This connection must be closed after the current transfer and must not
    /// be reused (`bits.close`).
    pub close: bool,
    /// Reuse of this connection is explicitly forbidden (`bits.no_reuse`).
    pub no_reuse: bool,
    /// The handle is in `CURLOPT_CONNECT_ONLY` mode (`connect_only`).
    pub connect_only: bool,
    /// An HTTP proxy is in use (`bits.httpproxy`).
    pub httpproxy: bool,
    /// A SOCKS proxy is in use (`bits.socksproxy`).
    pub socksproxy: bool,
    /// The HTTP proxy is tunneled (`CONNECT`) rather than plain (`bits.tunnel_proxy`).
    pub tunnel_proxy: bool,
    /// A `--connect-to` host override is active (`bits.conn_to_host`).
    pub conn_to_host: bool,
    /// A `--connect-to` port override is active (`bits.conn_to_port`).
    pub conn_to_port: bool,
    /// The Unix-domain socket path is an abstract-namespace socket
    /// (`bits.abstract_unix_socket`).
    pub abstract_unix_socket: bool,
    /// The credentials were obtained from a `.netrc` file (`bits.netrc`), so
    /// they remain safe to reuse even after following a redirect to a
    /// different host.
    pub netrc: bool,
}

/// A proxy endpoint, mirroring the reuse-relevant fields of curl's
/// `struct proxy_info`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyInfo {
    /// The proxy type (`proxytype`).
    pub proxytype: ProxyType,
    /// The proxy host name (`host.name`).
    pub host: String,
    /// The proxy port (`port`).
    pub port: u16,
    /// The proxy user name, if any (`user`).
    pub user: Option<String>,
    /// The proxy password, if any (`passwd`).
    pub passwd: Option<String>,
}

impl ProxyInfo {
    /// curl's `proxy_info_matches`: same type, port and host (host compared
    /// case-insensitively, like `curl_strequal`).
    #[must_use]
    pub fn matches(&self, other: &ProxyInfo) -> bool {
        self.proxytype == other.proxytype
            && self.port == other.port
            && self.host.eq_ignore_ascii_case(&other.host)
    }

    /// curl's `socks_proxy_info_matches`: [`ProxyInfo::matches`] **and** an
    /// exact (case-sensitive, per RFC 3986 §3.2.1) user/password match.
    #[must_use]
    pub fn socks_matches(&self, other: &ProxyInfo) -> bool {
        self.matches(other) && self.user == other.user && self.passwd == other.passwd
    }
}

/// The URL layer's view of a connection — a Rust rewrite of the reuse-relevant
/// portion of curl's `struct connectdata`.
///
/// A `Connection` records the identity a connection is created with: its scheme
/// handler, destination host/port, credentials, TLS parameters and proxy
/// configuration. [`Connection::can_reuse_for`] implements curl's
/// `url_match_conn` matching over exactly these fields.
#[derive(Debug, Clone)]
pub struct Connection {
    /// A monotonically-increasing identifier assigned by [`ConnCache`]
    /// (`conn->connection_id`).
    pub connection_id: u64,
    /// The scheme handler this connection speaks (`conn->handler`/`->scheme`).
    pub handler: SchemeHandler,
    /// The destination host name (`conn->host.name`). Compared
    /// case-insensitively.
    pub host: String,
    /// The destination port (`conn->remote_port`).
    pub port: u16,
    /// The resolved user name (`conn->user`).
    pub user: Option<String>,
    /// The resolved password (`conn->passwd`).
    pub passwd: Option<String>,
    /// The login `;options` field (`conn->options`).
    pub options: Option<String>,
    /// The SASL authorization identity (`conn->sasl_authzid`).
    pub sasl_authzid: Option<String>,
    /// The OAuth 2.0 bearer token (`conn->oauth_bearer`).
    pub oauth_bearer: Option<String>,
    /// The IP-version family this connection resolved with (`conn->ip_version`).
    pub ip_version: IpResolve,
    /// The bound local device/interface, if any (`conn->localdev`).
    pub localdev: Option<String>,
    /// The bound local port, if any (`conn->localport`).
    pub localport: u16,
    /// The bound local-port range (`conn->localportrange`).
    pub localportrange: u16,
    /// The `--connect-to` host override, if active (`conn->conn_to_host.name`).
    pub conn_to_host: Option<String>,
    /// The `--connect-to` port override, if active (`conn->conn_to_port`).
    pub conn_to_port: Option<u16>,
    /// The Unix-domain socket path, if any (`conn->unix_domain_socket`).
    pub unix_domain_socket: Option<String>,
    /// The server TLS configuration this connection negotiated (`conn->ssl_config`).
    pub ssl: SslConfig,
    /// The proxy-side TLS configuration for an HTTPS proxy
    /// (`conn->proxy_ssl_config`).
    pub proxy_ssl: SslConfig,
    /// The HTTP proxy endpoint (`conn->http_proxy`).
    pub http_proxy: ProxyInfo,
    /// The SOCKS proxy endpoint (`conn->socks_proxy`).
    pub socks_proxy: ProxyInfo,
    /// GSS-API credential-delegation policy (`conn->gssapi_delegation`).
    pub gssapi_delegation: i64,
    /// The per-connection boolean flags (`conn->bits`).
    pub bits: ConnBits,
}

impl Connection {
    /// Creates a connection prototype ("needle") for `handler` targeting
    /// `host:port`, with every other field at its neutral default. The connect
    /// flow fills in credentials, TLS and proxy details before matching.
    #[must_use]
    pub fn new(handler: SchemeHandler, host: impl Into<String>, port: u16) -> Self {
        Connection {
            connection_id: 0,
            handler,
            host: host.into(),
            port,
            user: None,
            passwd: None,
            options: None,
            sasl_authzid: None,
            oauth_bearer: None,
            ip_version: IpResolve::Whatever,
            localdev: None,
            localport: 0,
            localportrange: 0,
            conn_to_host: None,
            conn_to_port: None,
            unix_domain_socket: None,
            ssl: SslConfig::default(),
            proxy_ssl: SslConfig::default(),
            http_proxy: ProxyInfo::default(),
            socks_proxy: ProxyInfo::default(),
            gssapi_delegation: 0,
            bits: ConnBits::default(),
        }
    }

    // --- individual matchers, mirroring the `url_match_*` helpers in url.c ---

    /// curl's `url_match_connect_config`: reject non-reusable connections and
    /// require matching bind, `--connect-to` and Unix-socket settings.
    fn match_connect_config(&self, needle: &Connection) -> bool {
        // connect-only or to-be-closed connections will not be reused.
        if self.bits.connect_only || self.bits.close || self.bits.no_reuse {
            return false;
        }

        // ip_version must match when the needle constrains it.
        if needle.ip_version != IpResolve::Whatever && needle.ip_version != self.ip_version {
            return false;
        }

        // A bound local end (device or port) must match.
        if needle.localdev.is_some() || needle.localport != 0 {
            if self.localport != needle.localport || self.localportrange != needle.localportrange {
                return false;
            }
            if needle.localdev.is_some() && self.localdev != needle.localdev {
                return false;
            }
        }

        // Do not mix connections that use "--connect-to host/port" with those
        // that do not.
        if needle.bits.conn_to_host != self.bits.conn_to_host {
            return false;
        }
        if needle.bits.conn_to_port != self.bits.conn_to_port {
            return false;
        }

        // Unix-domain socket must match exactly (both present & equal, or both
        // absent).
        match (&needle.unix_domain_socket, &self.unix_domain_socket) {
            (Some(n), Some(c)) => {
                if n != c || needle.bits.abstract_unix_socket != self.bits.abstract_unix_socket {
                    return false;
                }
            }
            (Some(_), None) | (None, Some(_)) => return false,
            (None, None) => {}
        }

        true
    }

    /// curl's `url_match_destination`: scheme (or SSL-family-compatible scheme),
    /// `--connect-to` overrides, and — decisively — host name and remote port.
    fn match_destination(&self, needle: &Connection) -> bool {
        // These destination checks apply when talking TLS, or not going through
        // an HTTP proxy, or tunneling through a proxy. For the direct and
        // tunneled cases (the ones this URL layer models) they always apply.
        if !needle.handler.name.eq_ignore_ascii_case(self.handler.name) {
            // Different scheme names: only compatible if the candidate's
            // protocol family equals the needle's protocol and the candidate is
            // an SSL connection (the IMAPS-can-serve-IMAP case).
            if self.handler.protocol_family() != needle.handler.protocol {
                return false;
            }
            if !self.handler.is_ssl() {
                return false;
            }
        }

        // If the needle uses --connect-to, the candidate must match it.
        if needle.bits.conn_to_host && needle.conn_to_host != self.conn_to_host {
            return false;
        }
        if needle.bits.conn_to_port && needle.conn_to_port != self.conn_to_port {
            return false;
        }

        // Host name (case-insensitive) and remote port must match.
        self.host.eq_ignore_ascii_case(&needle.host) && self.port == needle.port
    }

    /// curl's `url_match_ssl_use`: an SSL needle requires an SSL candidate.
    fn match_ssl_use(&self, needle: &Connection) -> bool {
        if needle.handler.is_ssl() {
            return self.handler.is_ssl();
        }
        // A non-SSL needle over an SSL candidate is only acceptable when the
        // candidate permits SSL reuse and shares the protocol family; the URL
        // layer keeps this conservative and treats family+SSL_REUSE as the gate.
        if self.handler.is_ssl()
            && (!self.handler.has_flag(protopt::SSL_REUSE)
                || self.handler.protocol_family() != needle.handler.protocol)
        {
            return false;
        }
        true
    }

    /// curl's `url_match_proxy_use`: proxy presence and endpoint identity must
    /// match; HTTPS proxies additionally require matching proxy TLS config.
    fn match_proxy_use(&self, needle: &Connection) -> bool {
        if needle.bits.httpproxy != self.bits.httpproxy
            || needle.bits.socksproxy != self.bits.socksproxy
        {
            return false;
        }

        if needle.bits.socksproxy && !needle.socks_proxy.socks_matches(&self.socks_proxy) {
            return false;
        }

        if needle.bits.httpproxy {
            if needle.bits.tunnel_proxy != self.bits.tunnel_proxy {
                return false;
            }
            if !needle.http_proxy.matches(&self.http_proxy) {
                return false;
            }
            if needle.http_proxy.proxytype.is_https() {
                // Match the proxy-side TLS configuration (the proxy type itself
                // is already compared by `ProxyInfo::matches`).
                if !needle.proxy_ssl.matches(&self.proxy_ssl) {
                    return false;
                }
            }
        }
        true
    }

    /// curl's `url_match_ssl_config`: an SSL needle requires matching server
    /// TLS parameters.
    fn match_ssl_config(&self, needle: &Connection) -> bool {
        if needle.handler.is_ssl() {
            return needle.ssl.matches(&self.ssl);
        }
        true
    }

    /// curl's `url_match_auth`: for protocols whose credentials are bound to the
    /// connection (everything except HTTP's `PROTOPT_CREDSPERREQUEST`), the
    /// user, password, SASL authzid and bearer token must match; GSS-API
    /// delegation must always match.
    fn match_auth(&self, needle: &Connection) -> bool {
        if !needle.handler.is_creds_per_request()
            && (self.user != needle.user
                || self.passwd != needle.passwd
                || self.sasl_authzid != needle.sasl_authzid
                || self.oauth_bearer != needle.oauth_bearer)
        {
            return false;
        }
        self.gssapi_delegation == needle.gssapi_delegation
    }

    /// Returns `true` if this (existing, pooled) connection can be reused for a
    /// transfer described by `needle` — curl's `url_match_conn` restricted to
    /// the deterministic URL-layer criteria: general connect config,
    /// destination, TLS use, proxy use, TLS parameters and per-connection
    /// authentication.
    ///
    /// Multiplex limits and the NTLM/Negotiate "connection affinity" that curl
    /// layers on top are decided by the connection/auth subsystems once a
    /// live connection exists; here we implement the identity-level match the
    /// URL layer is responsible for, in curl's exact short-circuit order.
    #[must_use]
    pub fn can_reuse_for(&self, needle: &Connection) -> bool {
        self.match_connect_config(needle)
            && self.match_destination(needle)
            && self.match_ssl_use(needle)
            && self.match_proxy_use(needle)
            && self.match_ssl_config(needle)
            && self.match_auth(needle)
    }
}

/// The outcome of resolving a connection for a transfer — the identity of the
/// connection to use and whether it was reused from the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectResult {
    /// The identifier of the connection to use (`conn->connection_id`).
    pub connection_id: u64,
    /// `true` if an existing pooled connection was reused (`conn->bits.reuse`).
    pub reused: bool,
}

/// The connection pool for an easy handle — a Rust rewrite of curl's connection
/// cache (`struct cpool`) as consulted by `create_conn`.
///
/// Idle, reusable connections live here keyed by identity. [`ConnCache::find_or_create`]
/// implements the reuse-or-create decision (`url_find_or_create_conn`), and
/// [`ConnCache::disconnect`] implements the teardown side (`Curl_disconnect`).
#[derive(Debug, Default)]
pub struct ConnCache {
    conns: Vec<Connection>,
    maxconnects: usize,
    next_id: u64,
}

impl ConnCache {
    /// Creates an empty pool holding at most `maxconnects` idle connections
    /// (curl's `CURLOPT_MAXCONNECTS`; use [`DEFAULT_CONNCACHE_SIZE`] for the
    /// easy-handle default).
    #[must_use]
    pub fn new(maxconnects: usize) -> Self {
        ConnCache {
            conns: Vec::new(),
            maxconnects,
            next_id: 1,
        }
    }

    /// The number of connections currently held in the pool.
    #[must_use]
    pub fn len(&self) -> usize {
        self.conns.len()
    }

    /// Whether the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.conns.is_empty()
    }

    /// The configured maximum number of pooled connections.
    #[must_use]
    pub fn max_connects(&self) -> usize {
        self.maxconnects
    }

    /// Borrows a pooled connection by id, if present.
    #[must_use]
    pub fn get(&self, connection_id: u64) -> Option<&Connection> {
        self.conns.iter().find(|c| c.connection_id == connection_id)
    }

    /// Resolves a connection for `needle` — curl's `url_find_or_create_conn`.
    ///
    /// If an existing pooled connection matches ([`Connection::can_reuse_for`]),
    /// it is marked reused and returned; otherwise `needle` is assigned a fresh
    /// id, inserted (evicting the oldest closable connection first if the pool
    /// is at capacity), and returned as a new connection.
    pub fn find_or_create(&mut self, mut needle: Connection) -> ConnectResult {
        // Try to reuse an existing connection (ConnectionExists).
        if let Some(existing) = self.conns.iter_mut().find(|c| c.can_reuse_for(&needle)) {
            existing.bits.reuse = true;
            return ConnectResult {
                connection_id: existing.connection_id,
                reused: true,
            };
        }

        // No match: create a new connection.
        let id = self.next_id;
        self.next_id += 1;
        needle.connection_id = id;
        needle.bits.reuse = false;

        // Respect the pool capacity, evicting the oldest reusable (not in-use,
        // not close-marked) connection, matching curl's cache-pruning behavior.
        if self.maxconnects != 0 && self.conns.len() >= self.maxconnects {
            if let Some(pos) = self.conns.iter().position(|c| !c.bits.close) {
                self.conns.remove(pos);
            } else {
                self.conns.remove(0);
            }
        }

        self.conns.push(needle);
        ConnectResult {
            connection_id: id,
            reused: false,
        }
    }

    /// Tears down a connection — curl's `Curl_disconnect`.
    ///
    /// The connection identified by `connection_id` is removed from the pool
    /// (closed). When `dead` is `false` and the connection is reusable (its
    /// `close`/`no_reuse` bits are clear and the pool is under capacity) it is
    /// instead retained for future reuse, mirroring curl's decision to return a
    /// still-good connection to the cache rather than close it.
    ///
    /// Returns `true` if the connection was closed (removed), `false` if it was
    /// retained for reuse.
    pub fn disconnect(&mut self, connection_id: u64, dead: bool) -> bool {
        let Some(pos) = self
            .conns
            .iter()
            .position(|c| c.connection_id == connection_id)
        else {
            return false;
        };

        let reusable = {
            let conn = &self.conns[pos];
            !dead
                && !conn.bits.close
                && !conn.bits.no_reuse
                && !conn.bits.connect_only
                && (self.maxconnects == 0 || self.conns.len() <= self.maxconnects)
        };

        if reusable {
            // Return to the cache: clear the in-use reuse marker and keep it.
            self.conns[pos].bits.reuse = false;
            false
        } else {
            self.conns.remove(pos);
            true
        }
    }
}

// ===========================================================================
// Credential resolution: URL userinfo, login-string parsing, `.netrc`.
// ===========================================================================

/// The default user for protocols that require a login but were given none —
/// curl's `CURL_DEFAULT_USER` (`"anonymous"`, for anonymous FTP).
pub const CURL_DEFAULT_USER: &str = "anonymous";

/// The default password paired with [`CURL_DEFAULT_USER`] — curl's
/// `CURL_DEFAULT_PASSWORD` (`"ftp@example.com"`).
pub const CURL_DEFAULT_PASSWORD: &str = "ftp@example.com";

/// Splits a `user:password;options` login string into its three parts — a
/// direct rewrite of curl's `Curl_parse_login_details`.
///
/// All of the following forms (and their partial variants) are recognized,
/// with `:` separating the password and `;` separating the options, in either
/// order:
///
/// ```text
/// user            user:password            user:password;options
/// user;options    user;options:password    :password
/// :password;options   ;options             ;options:password
/// ```
///
/// The returned user portion is always present (possibly empty, exactly like
/// curl's always-allocated `ubuf`). The password is `Some` only when a `:`
/// separator was present (`pbuf` allocated). The options are `Some` only when a
/// `;` separator introduced a **non-empty** value (curl leaves `obuf` `NULL`
/// for a zero-length options field).
#[must_use]
pub fn parse_login_details(login: &str) -> (String, Option<String>, Option<String>) {
    let bytes = login.as_bytes();
    let len = bytes.len();

    // curl: memchr for ':' (password separator) and ';' (options separator).
    let psep = bytes.iter().position(|&b| b == b':');
    let osep = bytes.iter().position(|&b| b == b';');

    // ulen: user runs to whichever separator comes first (or to end).
    let ulen = match psep {
        Some(p) => match osep {
            Some(o) if p > o => o,
            _ => p,
        },
        None => osep.unwrap_or(len),
    };
    let user = String::from_utf8_lossy(&bytes[..ulen]).into_owned();

    // Password: only when ':' present; runs from just after ':' to the next
    // ';' that follows it, else to end.
    let password = psep.map(|p| {
        let end = match osep {
            Some(o) if o > p => o,
            _ => len,
        };
        String::from_utf8_lossy(&bytes[p + 1..end]).into_owned()
    });

    // Options: only when ';' present *and* the value is non-empty.
    let options = osep.and_then(|o| {
        let end = match psep {
            Some(p) if p > o => p,
            _ => len,
        };
        if end - o - 1 > 0 {
            Some(String::from_utf8_lossy(&bytes[o + 1..end]).into_owned())
        } else {
            None
        }
    });

    (user, password, options)
}

/// Returns `true` if `s` contains any ASCII control character (`< 0x20` or the
/// DEL `0x7f`) — curl's `str_has_ctrl` / `ISCNTRL` guard, used to reject
/// control codes in `.netrc` credentials for protocols that forbid them.
#[must_use]
fn str_has_ctrl(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

/// Percent-decodes a URL userinfo field (user or password), rejecting control
/// codes unless the scheme permits them — curl's `Curl_urldecode` call with
/// `REJECT_CTRL`/`REJECT_ZERO`.
fn decode_userinfo(encoded: &str, reject_ctrl: bool) -> Result<String> {
    let decoded = escape::unescape(encoded.as_bytes(), reject_ctrl)?;
    Ok(String::from_utf8_lossy(&decoded).into_owned())
}

// --- no-proxy matching (a rewrite of lib/noproxy.c) -----------------------

/// Parses the `/bits` suffix of a CIDR pattern — curl's
/// `curlx_str_number(&p, &value, 128)` followed by the "no trailing chars"
/// check. Returns `None` (reject the token) for a missing, non-numeric,
/// oversized (`> 128`), or trailing-garbage value.
fn parse_cidr_bits(s: &str) -> Option<u32> {
    match s.parse::<u32>() {
        Ok(v) if v <= 128 => Some(v),
        _ => None,
    }
}

/// curl's `Curl_cidr4_match`: is `ipv4` within `network/bits`?
fn cidr4_match(ipv4: &str, network: &str, bits: u32) -> bool {
    if bits > 32 {
        return false;
    }
    let (Ok(addr), Ok(net)) = (ipv4.parse::<Ipv4Addr>(), network.parse::<Ipv4Addr>()) else {
        return false;
    };
    let a = u32::from(addr);
    let c = u32::from(net);
    if bits != 0 && bits != 32 {
        // Mask the top `bits` bits (network prefix) and require equality.
        let mask: u32 = 0xffff_ffffu32 << (32 - bits);
        (a ^ c) & mask == 0
    } else {
        // curl's quirk: /0 and /32 both fall through to an exact match.
        a == c
    }
}

/// curl's `Curl_cidr6_match`: is `ipv6` within `network/bits`?
fn cidr6_match(ipv6: &str, network: &str, bits: u32) -> bool {
    let bits = if bits == 0 { 128 } else { bits };
    let bytes = (bits / 8) as usize;
    let rest = (bits & 0x07) as usize;
    if bytes > 16 || (bytes == 16 && rest != 0) {
        return false;
    }
    let (Ok(addr), Ok(net)) = (ipv6.parse::<Ipv6Addr>(), network.parse::<Ipv6Addr>()) else {
        return false;
    };
    let a = addr.octets();
    let c = net.octets();
    if bytes > 0 && a[..bytes] != c[..bytes] {
        return false;
    }
    if rest != 0 {
        let mask = 0xffu8 << (8 - rest);
        if (a[bytes] ^ c[bytes]) & mask != 0 {
            return false;
        }
    }
    true
}

/// curl's `match_ip`: match `name` (an IP literal) against a `network[/bits]`
/// token.
fn match_ip(is_v6: bool, token: &str, name: &str) -> bool {
    // curl copies the token into a 128-byte buffer; an over-long token cannot
    // match.
    if token.len() >= 128 {
        return false;
    }
    let (netstr, bits) = match token.split_once('/') {
        Some((net, bitstr)) => match parse_cidr_bits(bitstr) {
            Some(b) => (net, b),
            None => return false,
        },
        None => (token, 0u32),
    };
    if is_v6 {
        cidr6_match(name, netstr, bits)
    } else {
        cidr4_match(name, netstr, bits)
    }
}

/// curl's `match_host`: match a host `name` against a no-proxy `token`,
/// honoring leading/trailing-dot trimming and domain tail-matching.
///
/// * `A`: `example.com` matches token `example.com` (exact).
/// * `B`: `www.example.com` matches token `example.com` (domain tail).
/// * `C`: `nonexample.com` does **not** match token `example.com`.
fn match_host(token: &str, name: &str) -> bool {
    let tb = token.as_bytes();
    let mut tokenlen = tb.len();
    if tokenlen == 0 {
        return false;
    }
    // Ignore a trailing dot in the token.
    if tb[tokenlen - 1] == b'.' {
        tokenlen -= 1;
    }
    // Ignore a leading dot in the token as well.
    let mut start = 0usize;
    if tokenlen > 0 && tb[start] == b'.' {
        start += 1;
        tokenlen -= 1;
    }
    let token = &token[start..start + tokenlen];

    let nb = name.as_bytes();
    let namelen = nb.len();
    let tlen = token.len();
    match tlen.cmp(&namelen) {
        // Case A: exact, case-insensitive match.
        Ordering::Equal => token.eq_ignore_ascii_case(name),
        // Case B: tail-match a domain — the boundary char must be a dot.
        Ordering::Less => {
            nb[namelen - tlen - 1] == b'.' && name[namelen - tlen..].eq_ignore_ascii_case(token)
        }
        // Case C: token longer than name — never a match.
        Ordering::Greater => false,
    }
}

/// Returns `true` if `name` is covered by the comma-separated `no_proxy` list
/// and the proxy should therefore **not** be used — a rewrite of curl's
/// `Curl_check_noproxy`.
///
/// A lone `"*"` matches everything. Each token is matched either as a host
/// pattern ([`match_host`]) or, when `name` is an IP literal, as a
/// `network[/bits]` CIDR range ([`match_ip`]). The idiosyncratic tokenizer —
/// which stops a token at whitespace or a comma and abandons the scan if a
/// token is not comma-terminated — is preserved for bug-for-bug parity.
#[must_use]
pub fn check_noproxy(name: &str, no_proxy: &str) -> bool {
    if name.is_empty() || no_proxy.is_empty() {
        return false;
    }
    if no_proxy == "*" {
        return true;
    }

    // Classify `name`: IPv4 literal, IPv6 literal, or host name (with a single
    // trailing dot ignored).
    let (is_ip, is_v6, name_for_match): (bool, bool, &str) = match name.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => (true, false, name),
        Ok(IpAddr::V6(_)) => (true, true, name),
        Err(_) => (false, false, name.strip_suffix('.').unwrap_or(name)),
    };

    let bytes = no_proxy.as_bytes();
    let n = bytes.len();
    let is_blank = |b: u8| b == b' ' || b == b'\t';
    let mut i = 0usize;
    while i < n {
        // Pass leading blanks.
        while i < n && is_blank(bytes[i]) {
            i += 1;
        }
        // Read the token up to a blank or comma.
        let start = i;
        while i < n && !is_blank(bytes[i]) && bytes[i] != b',' {
            i += 1;
        }
        if i > start {
            let token = &no_proxy[start..i];
            let matched = if is_ip {
                match_ip(is_v6, token, name_for_match)
            } else {
                match_host(token, name_for_match)
            };
            if matched {
                return true;
            }
        }
        // Pass trailing blanks; the scan ends unless a comma follows.
        while i < n && is_blank(bytes[i]) {
            i += 1;
        }
        if i >= n || bytes[i] != b',' {
            break;
        }
        while i < n && bytes[i] == b',' {
            i += 1;
        }
    }
    false
}

// ===========================================================================
// Easy-handle credential wiring (`create_conn` login block + `override_login`
// + `set_login`).
// ===========================================================================

impl Easy {
    /// Fetches a URL part from the current handle, mapping the "part not
    /// present" code (`missing`) to `None` and any other failure to a
    /// [`CurlCode`] via [`uc_to_curlcode`].
    fn url_get_part(
        &self,
        part: CurlUPart,
        flags: u32,
        missing: urlapi::UrlCode,
    ) -> Result<Option<String>> {
        match &self.state.uh {
            Some(uh) => match uh.get(part, flags) {
                Ok(value) => Ok(Some(value)),
                Err(code) if code == missing => Ok(None),
                Err(code) => Err(Error::from(uc_to_curlcode(code))),
            },
            None => Ok(None),
        }
    }

    /// Extracts user/password/options from the URL userinfo into `conn` — the
    /// credential block of curl's `create_conn`.
    ///
    /// Credentials supplied through their own options (`CURLOPT_USERNAME` /
    /// `CURLOPT_PASSWORD`) take precedence over URL-embedded ones (the
    /// `creds_from != CREDS_OPTION` guard); `.netrc` does **not** override the
    /// URL here (that happens later, in [`Easy::override_login`]). Control
    /// codes are permitted in the user/password only for schemes carrying
    /// [`protopt::USERPWDCTRL`].
    fn extract_url_credentials(&mut self, conn: &mut Connection) -> Result<()> {
        let reject_ctrl = !conn.handler.allows_userpwd_ctrl();

        // Password (option-guarded).
        if self.state.aptr_passwd.is_none() || self.state.creds_from != CredsFrom::Option {
            if let Some(enc) =
                self.url_get_part(CurlUPart::Password, 0, urlapi::UrlCode::NoPassword)?
            {
                let decoded = decode_userinfo(&enc, reject_ctrl)?;
                conn.passwd = Some(decoded.clone());
                self.state.aptr_passwd = Some(decoded);
                self.state.creds_from = CredsFrom::Url;
            }
        }

        // User (option-guarded). curl deliberately avoids the URL API decoder
        // here so control codes can be permitted per-scheme.
        if self.state.aptr_user.is_none() || self.state.creds_from != CredsFrom::Option {
            if let Some(enc) = self.url_get_part(CurlUPart::User, 0, urlapi::UrlCode::NoUser)? {
                let decoded = decode_userinfo(&enc, reject_ctrl)?;
                conn.user = Some(decoded.clone());
                self.state.aptr_user = Some(decoded);
                self.state.creds_from = CredsFrom::Url;
            }
        }

        // Options (URL-decoded).
        if let Some(opts) = self.url_get_part(
            CurlUPart::Options,
            urlapi::URLDECODE,
            urlapi::UrlCode::NoOptions,
        )? {
            conn.options = Some(opts);
        }

        Ok(())
    }

    /// Applies `.netrc` lookups and propagates the effective credentials into
    /// the handle and URL — a rewrite of curl's `override_login`.
    ///
    /// `CURLOPT_OPTIONS` overrides the URL options unconditionally. When
    /// `--netrc`/`--netrc-optional` is requested and no `CURLOPT_USERNAME` was
    /// given, [`crate::netrc`] is consulted for the destination host; a match
    /// sets [`ConnBits::netrc`] so the credentials survive a later cross-host
    /// redirect. Finally the effective user/password are mirrored into
    /// `state.aptr.*` and written back into the URL handle (URL-encoded),
    /// exactly as curl does before connection matching.
    fn override_login(&mut self, conn: &mut Connection) -> Result<()> {
        // CURLOPT_OPTIONS (set.str[STRING_OPTIONS]) overrides URL options.
        if let Some(opts) = &self.set.login_options {
            conn.options = Some(opts.clone());
        }

        // --- .netrc resolution ---
        if self.set.use_netrc == NetrcLevel::Required {
            conn.user = None;
            conn.passwd = None;
        }
        conn.bits.netrc = false;

        if self.set.use_netrc != NetrcLevel::Ignored && self.set.username.is_none() {
            // A URL-supplied username (not itself from a prior netrc pass) is
            // preferred as the lookup key and preserved over the netrc login.
            let url_provided =
                self.state.aptr_user.is_some() && self.state.creds_from != CredsFrom::Netrc;
            let lookup_user = if url_provided {
                self.state.aptr_user.clone()
            } else {
                conn.user.clone()
            };

            if conn.passwd.is_none() {
                let host = conn.host.clone();
                let netrcfile = self.set.netrc_file.clone();
                match self
                    .state
                    .netrc
                    .parse(&host, lookup_user.as_deref(), netrcfile.as_deref())
                {
                    Ok(creds) => {
                        let new_user = creds.login.or_else(|| lookup_user.clone());
                        let new_pass = creds.password;
                        // Control-code guard for schemes that forbid them.
                        if !conn.handler.allows_userpwd_ctrl()
                            && (new_user.as_deref().is_some_and(str_has_ctrl)
                                || new_pass.as_deref().is_some_and(str_has_ctrl))
                        {
                            return Err(Error::with_context(
                                CurlCode::ReadError,
                                "control code detected in .netrc credentials",
                            ));
                        }
                        conn.bits.netrc = true;
                        conn.user = new_user;
                        conn.passwd = new_pass;
                    }
                    // Allocation failure maps straight through.
                    Err(NetrcCode::OutOfMemory) => {
                        return Err(Error::from(CurlCode::OutOfMemory));
                    }
                    // "No match" (or any failure under --netrc-optional) is
                    // non-fatal: fall back to the defaults.
                    Err(NetrcCode::NoMatch) => {}
                    Err(_) if self.set.use_netrc == NetrcLevel::Optional => {}
                    // A hard .netrc error under --netrc (required) is fatal.
                    Err(_) => {
                        return Err(Error::with_context(CurlCode::ReadError, ".netrc error"));
                    }
                }
            }

            if url_provided {
                conn.user = lookup_user;
            }
            // A password but no user: use a blank user (curl's strdup("")).
            if conn.user.is_none() && conn.passwd.is_some() {
                conn.user = Some(String::new());
            }
        }

        // --- propagate the effective credentials (tail of override_login) ---
        if let Some(user) = conn.user.clone() {
            if self.state.aptr_user.as_deref() != Some(user.as_str()) {
                self.state.aptr_user = Some(user);
                self.state.creds_from = CredsFrom::Netrc;
            }
        }
        if let Some(auser) = self.state.aptr_user.clone() {
            if let Some(uh) = &mut self.state.uh {
                uc(uh.set(CurlUPart::User, Some(&auser), urlapi::URLENCODE))?;
            }
            if conn.user.is_none() {
                conn.user = Some(auser);
            }
        }
        if let Some(passwd) = conn.passwd.clone() {
            self.state.aptr_passwd = Some(passwd);
            self.state.creds_from = CredsFrom::Netrc;
        }
        if let Some(apass) = self.state.aptr_passwd.clone() {
            if let Some(uh) = &mut self.state.uh {
                uc(uh.set(CurlUPart::Password, Some(&apass), urlapi::URLENCODE))?;
            }
            if conn.passwd.is_none() {
                conn.passwd = Some(apass);
            }
        }

        Ok(())
    }

    /// Initialises the cookie jar from the handle's cookie options — the
    /// analogue of curl's `Curl_cookie_init` driven by `CURLOPT_COOKIEFILE` /
    /// `CURLOPT_COOKIEJAR`.
    ///
    /// The jar engine is enabled when at least one cookie file was registered
    /// (`-b file`) or a jar-write path was set (`-c`); an inline
    /// `-b name=value` cookie alone does NOT create a jar (it is sent verbatim
    /// from [`UserDefined::cookie`]). When enabled, every registered file is
    /// read (a missing/unreadable file is non-fatal — curl warns and
    /// continues), the `-j` new-session flag is applied, and the `-c` write
    /// path is remembered for [`save_cookies`](Easy::save_cookies). Calling it
    /// again rebuilds the jar from the current options.
    ///
    /// Compiled only with the `cookies` feature (curl's `CURL_DISABLE_COOKIES`).
    #[cfg(feature = "cookies")]
    pub fn cookie_init(&mut self) {
        let engine_on = !self.set.cookiefiles.is_empty() || self.set.cookiejar.is_some();
        if !engine_on {
            self.state.cookies = None;
            return;
        }
        let mut jar = crate::cookie::CookieJar::new();
        // `-j` / `CURLOPT_COOKIESESSION`: discard session cookies on load.
        jar.set_newsession(self.set.cookiesession);
        // Register the read files (`-b file`); the special name "-" is stdin.
        for file in &self.set.cookiefiles {
            if !file.is_empty() {
                jar.add_file(file.clone());
            }
        }
        // Read them now. curl treats a missing/unreadable cookie file as a
        // non-fatal warning (the jar simply starts empty), so a load error is
        // logged and swallowed rather than failing the transfer.
        if let Err(e) = jar.load_files() {
            tracing::warn!("failed to read a cookie file: {e}");
        }
        // Remember the `-c` write target for the end-of-transfer save.
        if let Some(jarfile) = &self.set.cookiejar {
            jar.set_jar_file(jarfile.clone());
        }
        self.state.cookies = Some(jar);
    }

    /// Writes the cookie jar to the `CURLOPT_COOKIEJAR` (`-c`) file — curl's
    /// end-of-transfer cookie flush at handle cleanup. A no-op when no `-c`
    /// path was set or the jar engine is off. Any I/O failure is logged and
    /// swallowed (curl warns to stderr yet still exits successfully).
    ///
    /// Compiled only with the `cookies` feature (curl's `CURL_DISABLE_COOKIES`).
    #[cfg(feature = "cookies")]
    pub fn save_cookies(&mut self) {
        let jarfile = self.set.cookiejar.clone();
        if jarfile.is_none() {
            return;
        }
        if let Some(jar) = self.state.cookies.as_mut() {
            if let Err(e) = jar.save(jarfile.as_deref()) {
                tracing::warn!("failed to save cookie jar: {e}");
            }
        }
    }

    /// Initialises the HSTS cache from `CURLOPT_HSTS` / `--hsts` — the analogue
    /// of curl's `Curl_hsts_loadfile` driven at `curl_easy_perform` setup.
    ///
    /// The engine is enabled only when a cache file path is set. The file is
    /// read now if it exists; a missing file is non-fatal (curl starts with an
    /// empty cache and creates the file on save), and any other read error is
    /// logged and swallowed so the transfer still proceeds. Calling it again
    /// rebuilds the cache from the current path.
    pub fn hsts_init(&mut self) {
        let path = match self.set.hsts_file.as_deref().filter(|p| !p.is_empty()) {
            Some(p) => p.to_string(),
            None => {
                self.state.hsts = None;
                return;
            }
        };
        let mut hsts = crate::hsts::Hsts::new();
        // Seed from the existing file when present. A non-existent file is the
        // normal first-run case and must not fail the transfer.
        if std::path::Path::new(&path).exists() {
            if let Err(e) = hsts.load_file(&path) {
                tracing::warn!("failed to read the HSTS cache file: {e}");
            }
        }
        self.state.hsts = Some(hsts);
    }

    /// Writes the HSTS cache back to the `--hsts` file — curl's end-of-transfer
    /// `Curl_hsts_save`. A no-op when no HSTS path was set or the engine is
    /// off. Any I/O failure is logged and swallowed (curl warns yet still
    /// exits successfully).
    pub fn save_hsts(&mut self) {
        let file = self.set.hsts_file.clone();
        if file.as_deref().filter(|p| !p.is_empty()).is_none() {
            return;
        }
        if let Some(hsts) = self.state.hsts.as_ref() {
            if let Err(e) = hsts.save(file.as_deref()) {
                tracing::warn!("failed to save the HSTS cache: {e}");
            }
        }
    }

    /// Initialises the Alt-Svc cache from `CURLOPT_ALTSVC` / `--alt-svc` — the
    /// analogue of curl's `Curl_altsvc_init`.
    ///
    /// The engine is enabled only when a cache file path is set. The file is
    /// read now if it exists (a missing file is the normal first-run case; any
    /// read error is logged and swallowed). Calling it again rebuilds the cache
    /// from the current path.
    pub fn altsvc_init(&mut self) {
        let path = match self.set.altsvc_file.as_deref().filter(|p| !p.is_empty()) {
            Some(p) => p.to_string(),
            None => {
                self.state.altsvc = None;
                return;
            }
        };
        let mut altsvc = crate::altsvc::AltSvc::new();
        if std::path::Path::new(&path).exists() {
            if let Err(e) = altsvc.load(&path) {
                tracing::warn!("failed to read the alt-svc cache file: {e}");
            }
        }
        self.state.altsvc = Some(altsvc);
    }

    /// Writes the Alt-Svc cache back to the `--alt-svc` file — curl's
    /// end-of-transfer `Curl_altsvc_save`. A no-op when no path was set or the
    /// engine is off. Any I/O failure is logged and swallowed.
    pub fn save_altsvc(&mut self) {
        let file = self.set.altsvc_file.clone();
        if file.as_deref().filter(|p| !p.is_empty()).is_none() {
            return;
        }
        if let Some(altsvc) = self.state.altsvc.as_ref() {
            if let Err(e) = altsvc.save(file.as_deref()) {
                tracing::warn!("failed to save the alt-svc cache: {e}");
            }
        }
    }

    /// Fills in default credentials for a connection that still has none — a
    /// rewrite of curl's `set_login`.
    ///
    /// A protocol that needs a password ([`protopt::NEEDSPWD`], e.g. FTP) and
    /// was given no username receives the anonymous defaults
    /// ([`CURL_DEFAULT_USER`] / [`CURL_DEFAULT_PASSWORD`]); every other case
    /// gets empty strings.
    fn apply_default_login(&self, conn: &mut Connection) {
        let (setuser, setpasswd) =
            if conn.handler.has_flag(protopt::NEEDSPWD) && self.state.aptr_user.is_none() {
                (CURL_DEFAULT_USER, CURL_DEFAULT_PASSWORD)
            } else {
                ("", "")
            };
        if conn.user.is_none() {
            conn.user = Some(setuser.to_string());
        }
        if conn.passwd.is_none() {
            conn.passwd = Some(setpasswd.to_string());
        }
    }

    /// Resolves the credentials for `conn` end-to-end, in curl's order:
    /// option credentials (highest precedence) → URL userinfo → `.netrc`
    /// override → protocol defaults. This is the credential spine of
    /// `create_conn`.
    ///
    /// # Errors
    ///
    /// Propagates URL-decode failures, malformed URL parts, `.netrc` I/O and
    /// syntax errors (under `--netrc`), and control codes in `.netrc`
    /// credentials for schemes that forbid them.
    pub fn resolve_login(&mut self, conn: &mut Connection) -> Result<()> {
        // (1) Credentials from CURLOPT_USERNAME / CURLOPT_PASSWORD win over the
        //     URL (curl seeds these into state.aptr with creds_from = OPTION in
        //     Curl_pretransfer).
        if self.set.username.is_some() || self.set.password.is_some() {
            self.state.creds_from = CredsFrom::Option;
        }
        self.state.aptr_user = self.set.username.clone();
        self.state.aptr_passwd = self.set.password.clone();

        // (2) URL userinfo (option-guarded).
        self.extract_url_credentials(conn)?;

        // (3) .netrc override + effective-credential propagation.
        self.override_login(conn)?;

        // (4) Protocol default credentials.
        self.apply_default_login(conn);

        Ok(())
    }
}

// ===========================================================================
// Host / proxy helpers used by the connect flow.
// ===========================================================================

/// Converts a host name to its IDNA/Punycode (ACE) form when it is not already
/// ASCII — curl's `Curl_idnconvert_hostname`. ASCII hosts pass through
/// unchanged.
fn idnconvert_host(host: &str) -> Result<String> {
    if idn::is_ascii_name(host) {
        Ok(host.to_string())
    } else {
        idn::to_ascii(host)
    }
}

/// Parses a proxy string (`[scheme://]host[:port]`) into a host and port. The
/// explicit `CURLOPT_PROXYPORT` wins; otherwise the URL's port is used, falling
/// back to curl's default proxy port (`1080`).
fn parse_proxy_endpoint(proxy: &str, proxyport: u16) -> (String, u16) {
    /// curl's fallback proxy port when none is otherwise specified.
    const DEFAULT_PROXY_PORT: u16 = 1080;
    // Parse permissively so a bare "host:port" (no scheme) is also accepted.
    if let Ok(u) = Url::parse(proxy, urlapi::GUESS_SCHEME | urlapi::NON_SUPPORT_SCHEME) {
        let host = u.get(CurlUPart::Host, 0).unwrap_or_default();
        let port = if proxyport != 0 {
            proxyport
        } else {
            u.get(CurlUPart::Port, 0)
                .ok()
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(DEFAULT_PROXY_PORT)
        };
        (host, port)
    } else {
        (
            proxy.to_string(),
            if proxyport != 0 {
                proxyport
            } else {
                DEFAULT_PROXY_PORT
            },
        )
    }
}

/// Returns `true` if `url` begins with an explicit scheme (`scheme:/…`) — the
/// URL-layer form of curl's `Curl_is_absolute_url` with `guess_scheme = false`.
/// Used to decide whether a redirect target's custom port must be disallowed.
fn is_absolute_url(url: &str) -> bool {
    let bytes = url.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    let mut i = 1;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_alphanumeric() || c == b'+' || c == b'-' || c == b'.' {
            i += 1;
        } else {
            break;
        }
    }
    // curl (guess_scheme = false) requires the scheme to be followed by ":/".
    bytes.get(i) == Some(&b':') && bytes.get(i + 1) == Some(&b'/')
}

// ===========================================================================
// Connect flow (`create_conn` / `Curl_connect`) and redirects
// (`Curl_http_follow`).
// ===========================================================================

impl Easy {
    /// Determines the effective remote port — curl's `parse_remote_port`
    /// combined with the URL-API default-port lookup.
    ///
    /// A non-zero `CURLOPT_PORT` (with [`EasyState::allow_port`] set) overrides
    /// the URL; otherwise the URL's port is used, defaulting to the scheme's
    /// well-known port.
    fn resolve_remote_port(&self, handler: &SchemeHandler) -> Result<u16> {
        if self.set.use_port != 0 && self.state.allow_port {
            return Ok(self.set.use_port);
        }
        match self.url_get_part(
            CurlUPart::Port,
            urlapi::DEFAULT_PORT,
            urlapi::UrlCode::NoPort,
        )? {
            Some(port) => port
                .parse::<u16>()
                .map_err(|_| Error::from(CurlCode::UrlMalformat)),
            None => Ok(handler.default_port),
        }
    }

    /// Applies proxy / no-proxy resolution to the connection needle — the proxy
    /// portion of curl's `create_conn` plus `Curl_check_noproxy`.
    ///
    /// A configured `CURLOPT_PROXY` is used unless the destination host matches
    /// `CURLOPT_NOPROXY`. SOCKS proxy types populate [`Connection::socks_proxy`]
    /// (and set [`ConnBits::socksproxy`]); HTTP/HTTPS proxy types populate
    /// [`Connection::http_proxy`] (and set [`ConnBits::httpproxy`], tunneling
    /// for TLS destinations).
    fn resolve_proxy(&self, conn: &mut Connection) -> Result<()> {
        let Some(proxy) = self.set.proxy.as_deref().filter(|p| !p.is_empty()) else {
            return Ok(());
        };
        if let Some(no_proxy) = self.set.no_proxy.as_deref() {
            if check_noproxy(&conn.host, no_proxy) {
                return Ok(());
            }
        }

        let (host, port) = parse_proxy_endpoint(proxy, self.set.proxyport);
        let info = ProxyInfo {
            proxytype: self.set.proxytype,
            host,
            port,
            user: self.set.proxy_user.clone(),
            passwd: self.set.proxy_password.clone(),
        };

        if self.set.proxytype.is_socks() {
            conn.socks_proxy = info;
            conn.bits.socksproxy = true;
        } else {
            conn.http_proxy = info;
            conn.bits.httpproxy = true;
            // A TLS destination must be tunneled (CONNECT) through an HTTP proxy.
            conn.bits.tunnel_proxy = conn.handler.is_ssl();
            conn.proxy_ssl = self.set.proxy_ssl.clone();
        }
        Ok(())
    }

    /// Turns the configured handle plus its parsed URL into a ready-to-use
    /// connection — a rewrite of curl's `create_conn` / `Curl_connect` core.
    ///
    /// The scheme selects a protocol [`SchemeHandler`] (rejecting unsupported or
    /// dropped schemes such as RTMP, and honoring `CURLOPT_PROTOCOLS` /
    /// `CURLOPT_REDIR_PROTOCOLS`); the host is IDN-converted; the port,
    /// credentials, TLS config and proxy settings are resolved; and finally a
    /// matching pooled connection is reused from `cache` or a new one is
    /// created ([`ConnCache::find_or_create`], curl's `ConnectionExists`).
    ///
    /// # Errors
    ///
    /// Returns [`CurlCode::UnsupportedProtocol`] for a missing/unknown/dropped
    /// scheme, [`CurlCode::UrlMalformat`] for a malformed port, and any error
    /// surfaced by credential resolution.
    pub fn create_conn(&mut self, cache: &mut ConnCache) -> Result<ConnectResult> {
        // Scheme → handler.
        let scheme = self
            .url_get_part(CurlUPart::Scheme, 0, urlapi::UrlCode::NoScheme)?
            .ok_or_else(|| Error::from(CurlCode::UnsupportedProtocol))?;
        let handler = findprotocol(
            &scheme,
            self.set.allowed_protocols,
            self.set.redir_protocols,
            self.state.this_is_a_follow,
        )?;

        // Assemble the connection needle from the handle configuration.
        let mut conn = Connection::new(handler, String::new(), 0);
        conn.bits.connect_only = self.set.connect_only;
        conn.ip_version = self.set.ipver;
        conn.localdev = self.set.localdev.clone();
        conn.localport = self.set.localport;
        conn.localportrange = self.set.localportrange;
        conn.ssl = self.set.ssl.clone();

        // Host + port (skipped for non-network schemes such as `file://`).
        if !handler.is_nonetwork() {
            if let Some(host) = self.url_get_part(CurlUPart::Host, 0, urlapi::UrlCode::NoHost)? {
                conn.host = idnconvert_host(&host)?;
            }
            conn.port = self.resolve_remote_port(&handler)?;
        }

        // Credentials (option → URL → netrc → defaults).
        self.resolve_login(&mut conn)?;

        // Proxy / no-proxy.
        self.resolve_proxy(&mut conn)?;

        // Record the connection identity for later redirect decisions.
        self.info.conn_remote_port = conn.port;
        self.info.conn_protocol = handler.protocol;
        self.info.conn_scheme = Some(handler.name.to_string());

        // Reuse an existing pooled connection or create a fresh one.
        Ok(cache.find_or_create(conn))
    }

    /// Drive this fully-configured handle through one real network transfer,
    /// streaming received body bytes to `sink` and recording the response
    /// diagnostics into [`self.info`](Easy::info).
    ///
    /// This is the async core of `curl_easy_perform` (`lib/easy.c`) — the
    /// DO/PERFORM counterpart to [`create_conn`](Easy::create_conn) (curl's
    /// `Curl_connect`). Where `create_conn` resolves the *connection identity*
    /// against the pool, this method establishes a **live** connection and runs
    /// the protocol exchange:
    ///
    /// 1. map the URL scheme to its protocol handler (identity + `&dyn Protocol`
    ///    behavior vtable);
    /// 2. derive host / port / path / query from the parsed URL and stamp them
    ///    onto `request` (the caller supplies only the request-specific options —
    ///    method, headers, body, …);
    /// 3. build a live [`Connection`](crate::conn::Connection), resolve the host
    ///    ([`crate::dns::resolve`]), and connect its filter chain
    ///    ([`conn_setup`](crate::conn::connect::conn_setup) +
    ///    [`connect_with_timeout`](crate::conn::connect::connect_with_timeout));
    /// 4. drive the handler lifecycle — `setup_connection` → `connect` →
    ///    `connecting` → `do_it` → `done` — over that connection, exactly as
    ///    curl's `multi_runsingle` steps the state machine;
    /// 5. copy the per-transfer [`Info`] the handler populated
    ///    (`CURLINFO_RESPONSE_CODE`, `CURLINFO_CONTENT_TYPE`, …) back onto the
    ///    handle so the CLI's `--write-out`/xattr and `curl_easy_getinfo`
    ///    observe it.
    ///
    /// A non-network scheme (`file:`) skips DNS, socket setup, and connect,
    /// exactly as curl treats `PROTOPT_NONETWORK`.
    ///
    /// # Errors
    ///
    /// Surfaces every failure from URL parsing, protocol lookup, DNS resolution,
    /// connection setup, and the protocol exchange as the corresponding
    /// [`CurlCode`]. The `done` phase always runs (with the DO status forwarded)
    /// so the handler can release resources even when the DO phase failed.
    ///
    /// Enable or disable `-v`/`--trace` diagnostic capture for the next
    /// [`perform_transfer`](Easy::perform_transfer) (curl's `data->set.verbose` /
    /// `CURLOPT_DEBUGFUNCTION` registration). When enabled, that transfer records its trace
    /// events into [`debug_log`](Easy::debug_log) for the caller to drain; when disabled (the
    /// default) the transfer captures nothing.
    pub fn set_trace_enabled(&mut self, on: bool) {
        self.trace_enabled = on;
    }

    /// Take the `-v`/`--trace` records captured by the last transfer, leaving the buffer empty
    /// (curl's `CURLOPT_DEBUGFUNCTION` fires per event; the CLI drives the library directly, so it
    /// drains the buffered records here and renders them through curl's trace formatter). Returns
    /// an empty vector when tracing was disabled or no transfer has run.
    pub fn take_debug_log(&mut self) -> Vec<(crate::protocols::DebugInfoType, Vec<u8>)> {
        std::mem::take(&mut self.debug_log)
    }

    pub async fn perform_transfer(
        &mut self,
        base_request: crate::protocols::TransferRequest,
        sink: Box<dyn crate::protocols::TransferSink>,
    ) -> Result<()> {
        use crate::conn::connect::{conn_setup, connect_with_timeout};
        use crate::conn::{
            Connection as LiveConn, Scheme as LiveScheme, CURL_CF_SSL_DEFAULT, FIRSTSOCKET,
        };
        use crate::dns::system::SystemResolver;
        use crate::dns::{resolve, DnsCache, IpVersion, ResolveOptions};
        use crate::protocols::{scheme_handler, TransferCtx};

        // Transfer-clock origin (← curl's `Curl_pgrsStartNow`, which stamps
        // `data->progress.t_startsingle` at the top of a transfer). Every
        // `CURLINFO_*_TIME_T` value is an offset in **microseconds** from this
        // instant, so `--write-out %{time_total}` and the `%{speed_*}` rates
        // report real elapsed time. The clock is started once and spans the
        // whole redirect chain, so `%{time_total}` is cumulative exactly as
        // curl reports it; the per-phase timers (declared per-hop inside the
        // loop and written onto `info` each hop) track the final request, and
        // `total_time` is stamped once after the loop.
        let t_start = std::time::Instant::now();

        // `-v`/`--trace` capture (curl's `CURLOPT_DEBUGFUNCTION` stream). When tracing is on,
        // records are buffered here in emission order and drained by the CLI afterwards; when off
        // the whole block is skipped, leaving the hot path untouched. Records accumulate across
        // every hop of a redirect chain, so `-v` shows each request/response pair like curl.
        use crate::protocols::DebugInfoType;
        let trace_on = self.trace_enabled;
        let mut trace_records: Vec<(DebugInfoType, Vec<u8>)> = Vec::new();

        // Whether HTTP `Location:` redirects are followed (`-L` /
        // `CURLOPT_FOLLOWLOCATION`). When off, the loop below runs exactly once
        // and streams straight to the client sink — the pre-redirect behavior,
        // byte-for-byte unchanged.
        let follow_enabled = self.set.follow_location;

        // Sync the handle's request-method state from the inbound request so the
        // RFC 7231 redirect method-switch (`apply_redirect_method_switch`,
        // invoked by `follow`) operates on the actual method rather than the
        // `HttpReq::Get` default. Without this, a redirected `POST` would not be
        // downgraded to `GET`.
        self.state.httpreq = httpreq_from_method(&base_request.method, base_request.no_body);

        // The client sink is installed on the FINAL response only; each followed
        // `3xx` response body is discarded (curl's `k->ignorebody` on a
        // redirect). Held in an `Option` so a single non-redirected transfer
        // still hands it straight to the engine.
        let mut client_sink: Option<Box<dyn crate::protocols::TransferSink>> = Some(sink);
        // Running total of body bytes delivered to the client (the final
        // response's size, matching curl's `CURLINFO_SIZE_DOWNLOAD_T`).
        let downloaded = Arc::new(std::sync::atomic::AtomicI64::new(0));
        // Trace copy of the *final* response body (`{ ` DATA_IN), populated
        // after the loop decides which hop is terminal.
        let body_capture: Option<Arc<std::sync::Mutex<Vec<u8>>>> = if trace_on {
            Some(Arc::new(std::sync::Mutex::new(Vec::new())))
        } else {
            None
        };

        // The working method and body; the RFC 7231 switch may turn a redirected
        // POST/PUT into a bodiless GET across hops. Seeded from the request.
        let mut method = base_request.method.clone();
        let mut body = base_request.body.clone();

        // Working authentication credentials and the origin they belong to
        // (← curl's `data->state.aptr.user/passwd` plus `data->state.first_host`
        // / `data->state.first_remote_port`). The first hop fixes the credential
        // origin; a redirect to any *different* scheme/host/port drops the Basic
        // credentials and a caller-supplied `Authorization:`/`Cookie:` header so
        // they are never re-sent to a foreign host — exactly the cross-origin
        // strip performed by `Curl_http_follow` / `Curl_auth_allowed_to_host`.
        // Once stripped they stay stripped for the remainder of the chain.
        // `--location-trusted` (`CURLOPT_UNRESTRICTED_AUTH`) opts out of the
        // strip and keeps sending credentials to every host in the chain.
        let unrestricted_auth = self.set.allow_auth_to_other_hosts;
        let mut cred_user = base_request.user.clone();
        let mut cred_password = base_request.password.clone();
        let mut cred_origin: Option<(String, String, u16)> = None;
        let mut strip_sensitive_headers = false;

        // `--max-time` / `CURLOPT_TIMEOUT`: the overall deadline for the whole
        // transfer, spanning the entire redirect chain (← curl arms
        // `Curl_expire(data, timeout, EXPIRE_TIMEOUT)` at transfer start and
        // fails the transfer with `CURLE_OPERATION_TIMEDOUT` when it fires, no
        // matter which phase is in flight). It is distinct from the per-connect
        // `--connect-timeout` budget applied inside the loop below. `None`
        // (option unset / zero) means "no overall limit", matching curl.
        let overall_timeout = base_request.timeout;

        // Redirect-follow loop (← curl's `multi_runsingle` re-entering the SETUP
        // state after `Curl_follow` installs a new URL on the handle). A single
        // iteration for a non-redirected transfer; each followed `3xx`
        // re-resolves the new host and reconnects. The loop is packaged as one
        // future so the overall `--max-time` deadline can bound the entire chain
        // with a single `tokio::time::timeout`; on expiry the in-flight future is
        // cancelled at its next await point and the transfer reports code 28.
        let redirect_loop = async {
            loop {
            let mut peer_ip: Option<String> = None;
            // Per-hop phase timers (microseconds from `t_start`). A phase that
            // never runs for this hop (e.g. name resolution for a `file://`
            // transfer) stays `0`, exactly as curl reports an unmeasured phase.
            let mut t_namelookup_us: i64 = 0;
            let mut t_connect_us: i64 = 0;
            let mut t_appconnect_us: i64 = 0;

            // --- 1. Scheme → protocol handler (identity + behavior vtable),
            // read from the *current* URL (updated by `follow` on each hop). ---
            let scheme = self
                .url_get_part(CurlUPart::Scheme, 0, urlapi::UrlCode::NoScheme)?
                .ok_or_else(|| Error::from(CurlCode::UnsupportedProtocol))?;
            let scheme_lc = scheme.to_ascii_lowercase();

            // The identity handler (default port, no-network flag) drives port
            // resolution; the behavior handler carries the `&dyn Protocol` vtable
            // used to run the exchange. Both are keyed on the same scheme string.
            let ident = get_scheme_handler(&scheme_lc)
                .ok_or_else(|| Error::from(CurlCode::UnsupportedProtocol))?;
            let psh = scheme_handler(&scheme_lc)
                .ok_or_else(|| Error::from(CurlCode::UnsupportedProtocol))?;
            let handler = psh
                .handler
                .ok_or_else(|| Error::from(CurlCode::UnsupportedProtocol))?;

            // --- 2. Host / port / path / query from the parsed URL. ---
            let host = self
                .url_get_part(CurlUPart::Host, 0, urlapi::UrlCode::NoHost)?
                .ok_or_else(|| Error::from(CurlCode::UrlMalformat))?;
            let host = idnconvert_host(&host)?;
            let port = self.resolve_remote_port(&ident)?;
            // Path is never "missing" (the URL parser defaults it to "/"); Query is
            // absent as `NoQuery`, which `url_get_part` maps to `None`.
            let path = self
                .url_get_part(CurlUPart::Path, 0, urlapi::UrlCode::UnknownPart)?
                .unwrap_or_else(|| "/".to_string());
            let query = self.url_get_part(CurlUPart::Query, 0, urlapi::UrlCode::NoQuery)?;
            // The full effective URL of this hop (← `data->state.url`), used by
            // the HTTP-derived request-line assemblers and `%{url_effective}`.
            let effective_url = self
                .url_get_part(CurlUPart::Url, 0, urlapi::UrlCode::UnknownPart)?
                .unwrap_or_default();

            // --- 2b. HSTS upgrade (← curl's `Curl_hsts` check in `create_conn`).
            // When the scheme is cleartext `http` and the host is a known HSTS
            // host, upgrade this hop to `https` before any connection is made —
            // this is the read side of the HSTS cache that complements the
            // `Strict-Transport-Security:` capture below. curl keeps an explicit
            // port (or a `CURLOPT_PORT`/`--port` override) and promotes only the
            // default http port (80) to the https default (443); the scheme,
            // scheme handlers, port, and effective URL are all rewritten so the
            // TLS filter is selected and `%{url_effective}` reports the https
            // URL. A `* Switched from HTTP to HTTPS due to HSTS => …` note is
            // emitted under `-v`/`--trace`, mirroring curl's `infof`. All later
            // per-hop logic (connection build, TLS posture, request line, cookie
            // scoping, Alt-Svc source ALPN) then observes the upgraded values. ---
            let (scheme_lc, ident, psh, handler, port, effective_url) = if scheme_lc == "http"
                && self.state.hsts.as_ref().is_some_and(|h| h.is_hsts(&host))
            {
                let up_ident = get_scheme_handler("https")
                    .ok_or_else(|| Error::from(CurlCode::UnsupportedProtocol))?;
                let up_psh = scheme_handler("https")
                    .ok_or_else(|| Error::from(CurlCode::UnsupportedProtocol))?;
                let up_handler = up_psh
                    .handler
                    .ok_or_else(|| Error::from(CurlCode::UnsupportedProtocol))?;
                // An explicit URL port or a `--port` override is preserved; a
                // bare `http://host` (default port 80) becomes the https default.
                let explicit_port = self.set.use_port != 0
                    || self
                        .url_get_part(CurlUPart::Port, 0, urlapi::UrlCode::NoPort)?
                        .is_some();
                let up_port = if explicit_port {
                    port
                } else {
                    up_ident.default_port
                };
                // Swap the effective URL's leading `http://` → `https://` for
                // `%{url_effective}` and the upgrade trace line.
                let up_url = match effective_url.strip_prefix("http://") {
                    Some(rest) => format!("https://{rest}"),
                    None => effective_url.clone(),
                };
                if trace_on {
                    trace_records.push((
                        DebugInfoType::Text,
                        format!("Switched from HTTP to HTTPS due to HSTS => {up_url}\n")
                            .into_bytes(),
                    ));
                }
                (
                    "https".to_string(),
                    up_ident,
                    up_psh,
                    up_handler,
                    up_port,
                    up_url,
                )
            } else {
                (scheme_lc, ident, psh, handler, port, effective_url)
            };

            // Build this hop's request from the caller's template, stamping the
            // URL-derived fields and the (possibly switched) method/body.
            let mut request = base_request.clone();
            request.scheme = scheme_lc.clone();
            request.host = host.clone();
            request.port = port;
            // Keep this hop's path for cookie storage after `request` is consumed
            // by the DO phase (the `Set-Cookie:` capture needs the request path).
            // Only needed when the `cookies` feature compiles the capture block.
            #[cfg(feature = "cookies")]
            let cookie_path = path.clone();
            request.path = path;
            request.query = query;
            if !effective_url.is_empty() {
                request.url = effective_url;
            }
            request.method = method.clone();
            request.body = body.clone();

            // Cross-origin credential strip (← `Curl_http_follow` +
            // `Curl_auth_allowed_to_host`). The first hop records the credential
            // origin; any later hop whose (scheme, host, port) differs drops the
            // Basic credentials and any caller-supplied `Authorization:`/`Cookie:`
            // header so they never leak to a foreign host. The decision latches:
            // once a foreign origin is reached the credentials stay stripped for
            // every remaining hop. `--location-trusted` disables the strip.
            if !unrestricted_auth {
                let this_origin = (scheme_lc.clone(), host.clone(), port);
                match &cred_origin {
                    None => cred_origin = Some(this_origin),
                    Some(origin) => {
                        if *origin != this_origin {
                            cred_user = None;
                            cred_password = None;
                            strip_sensitive_headers = true;
                        }
                    }
                }
            }
            // Working credentials for this hop: the (possibly cross-origin-stripped)
            // `--user` credentials by default.
            let mut hop_user = cred_user.clone();
            let mut hop_password = cred_password.clone();

            // `.netrc` credential source (← curl's `override_login`, run per
            // connection): when `--netrc`/`--netrc-optional` is active and no
            // `--user` was supplied, look up THIS hop's host in the `.netrc` file.
            // A match supplies the credentials for this hop. Because the lookup is
            // per-host, netrc credentials are naturally scoped to each host in a
            // redirect chain (curl's `conn->bits.netrc`) rather than being carried
            // forward and stripped like `--user` credentials, so a redirect to a
            // different machine listed in `.netrc` picks up that machine's login.
            // `--netrc` (required) treats a hard file error as fatal
            // (`CURLE_READ_ERROR`); `--netrc-optional` and a plain "no match" fall
            // back to sending no credentials, exactly as curl does.
            if self.set.use_netrc != NetrcLevel::Ignored && base_request.user.is_none() {
                let netrcfile = self.set.netrc_file.clone();
                match self.state.netrc.parse(&host, None, netrcfile.as_deref()) {
                    Ok(creds) => {
                        if creds.login.is_some() || creds.password.is_some() {
                            // A password but no login uses a blank user (curl's
                            // `strdup("")`), so Basic auth still forms `:password`.
                            hop_user = creds
                                .login
                                .or_else(|| creds.password.as_ref().map(|_| String::new()));
                            hop_password = creds.password;
                        }
                    }
                    Err(NetrcCode::NoMatch) => {}
                    Err(_) if self.set.use_netrc == NetrcLevel::Optional => {}
                    Err(_) => {
                        break Err(Error::with_context(CurlCode::ReadError, ".netrc error"));
                    }
                }
            }

            // Use the working credentials for this hop and, once a foreign origin
            // has been reached, drop sensitive caller-supplied headers so
            // `Authorization:`/`Cookie:` are not forwarded cross-host.
            request.user = hop_user;
            request.password = hop_password;
            if strip_sensitive_headers {
                request.headers.retain(|line| {
                    let name = line.split(':').next().unwrap_or("").trim();
                    !name.eq_ignore_ascii_case("Authorization")
                        && !name.eq_ignore_ascii_case("Cookie")
                });
            }

            // --- 2b. Outgoing `Cookie:` header (← curl's `Curl_cookie_getlist`
            // joined with the inline `CURLOPT_COOKIE` string). The inline cookie
            // string set via `-b name=value` mirrors libcurl's `CURLOPT_COOKIE`:
            // it is emitted verbatim on every hop of the transfer, including
            // cross-host redirects. It is deliberately NOT one of the
            // caller-supplied headers subject to the cross-origin strip above —
            // curl only strips an explicit `-H 'Cookie: …'` header cross-host
            // (verified against curl 8.x), while the `CURLOPT_COOKIE` string
            // persists. Jar cookies are always domain/path/scheme-scoped by
            // `cookie_header`, so they too are safe to emit on every hop. The
            // synthesized header is added only when the caller has no surviving
            // `Cookie:` header of their own (an explicit `-H 'Cookie: …'` wins,
            // and the cross-host strip above has already removed a foreign one).
            // Compiled only with the `cookies` feature — curl's
            // `CURL_DISABLE_COOKIES` removes the whole engine, `CURLOPT_COOKIE`
            // (inline `-b`) included, so no `Cookie:` header is synthesized. ---
            #[cfg(feature = "cookies")]
            {
                let mut cookie_parts: Vec<String> = Vec::new();
                if let Some(inline) = self.set.cookie.as_deref().filter(|s| !s.is_empty()) {
                    cookie_parts.push(inline.to_string());
                }
                if let Some(jar) = self.state.cookies.as_mut() {
                    if let Some(h) = jar.cookie_header(&host, &request.path, psh.is_secure()) {
                        cookie_parts.push(h);
                    }
                }
                let has_manual_cookie = request.headers.iter().any(|line| {
                    line.split(':')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .eq_ignore_ascii_case("Cookie")
                });
                if !cookie_parts.is_empty() && !has_manual_cookie {
                    request
                        .headers
                        .push(format!("Cookie: {}", cookie_parts.join("; ")));
                }
            }

            // --- 3. Build the live connection. ---
            let is_nonetwork = ident.is_nonetwork();
            let live_scheme = LiveScheme {
                name: scheme_lc.clone(),
                default_port: ident.default_port,
                is_ssl: psh.is_secure(),
                no_network: is_nonetwork,
            };
            let mut conn = LiveConn::new(live_scheme, host.clone(), port);
            // Map the handle's `CURLOPT_IPRESOLVE` onto the resolver's family
            // preference (the discriminants match curl's `CURL_IPRESOLVE_*`).
            conn.ip_version = match self.set.ipver {
                IpResolve::V4 => IpVersion::V4,
                IpResolve::V6 => IpVersion::V6,
                IpResolve::Whatever => IpVersion::Whatever,
            };

            // --- 3b. Thread the handle's TLS posture + ALPN into the connection
            // for secure schemes (F10-TLS-01/02/03; ← curl's `ssl_config`
            // propagation in `create_conn`/`cf-ssl`). Without this the
            // connection always used the hardcoded default-secure config with no
            // ALPN, so `--insecure`, `--cacert`/`--capath`, and HTTP/2-over-TLS
            // negotiation were all inert. A cleartext scheme keeps the default
            // (its `ssl_config` is never consulted). ---
            if psh.is_secure() {
                let s = &self.set.ssl;
                let mut tls = crate::tls::TlsConfig::new()
                    .with_verify_peer(s.verify_peer)
                    // `CURLOPT_SSL_VERIFYHOST` is the integer `2` when enabled; any
                    // non-zero value means "verify" (curl treats `1` as `2`).
                    .with_verify_host(s.verify_host != 0)
                    .with_verify_status(s.verify_status)
                    // The curl tool already emitted the `--insecure` warning at the
                    // CLI layer (honoring `-s`); the library engine must not print a
                    // second, silent-mode-ignoring copy.
                    .with_insecure_warning(false)
                    // Offer ALPN derived from the effective HTTP-version preference
                    // so HTTPS handshakes advertise `h2, http/1.1` (curl wire parity).
                    .with_alpn(alpn_offer_for_httpwant(self.set.httpwant));
                // Custom trust anchors (`--cacert` / `--capath`) when supplied.
                if let Some(ca) = &s.ca_info {
                    tls = tls.with_ca_info(ca.clone());
                }
                if let Some(cap) = &s.ca_path {
                    tls = tls.with_ca_path(cap.clone());
                }
                conn.ssl_config = Arc::new(tls);
                conn.bits.tls_enable_alpn = true;
            }

            // --- 4. Resolve + connect the filter chain (network schemes only). ---
            if !is_nonetwork {
                // A per-transfer DNS cache seeds the resolve; a shared handle would
                // consult its shared cache, but a single serial transfer needs only
                // a fresh one (localhost / IP literals resolve without the network).
                let cache = DnsCache::new();
                // `--resolve` / `CURLOPT_RESOLVE`: pre-populate this hop's cache so a
                // named `host:port` short-circuits real resolution to the supplied
                // address (← curl seeds `data->dns.hostcache` via
                // `Curl_loadhostpairs` before `Curl_resolv`). Applied every hop so a
                // redirect target listed in `--resolve` is honored too; a malformed
                // entry surfaces curl's `CURLE_SETOPT_OPTION_SYNTAX`.
                if !self.set.resolve.is_empty() {
                    crate::dns::load_host_pairs(&cache, &self.set.resolve)?;
                }
                let resolver = SystemResolver::new();
                let opts = ResolveOptions::new(&resolver);
                let dns = resolve(&cache, &host, port, conn.ip_version, false, &opts).await?;
                // Name resolution complete (← `data->progress.t_nslookup`).
                t_namelookup_us = t_start.elapsed().as_micros() as i64;
                // Record the connected remote address for the `-v`/`--trace` `* Trying …` /
                // `* Connected to …` text lines (curl's `Curl_verboseconnect`).
                if trace_on {
                    peer_ip = dns.endpoints().first().map(|sa| sa.ip().to_string());
                    if let Some(ip) = &peer_ip {
                        trace_records.push((
                            DebugInfoType::Text,
                            format!("  Trying {ip}:{port}...\n").into_bytes(),
                        ));
                    }
                }

                // Build the default `SETUP` filter stack (TCP → [proxy] → [TLS] →
                // happy-eyeballs) and drive it to connected. `CURL_CF_SSL_DEFAULT`
                // lets the scheme decide TLS (on for `https`/`ftps`/…, off for
                // cleartext), matching curl's `ssl_mode` default.
                conn_setup(&mut conn, FIRSTSOCKET, dns, CURL_CF_SSL_DEFAULT).await?;
                let connect_ms = request
                    .connect_timeout
                    .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                    .unwrap_or(0);
                connect_with_timeout(&mut conn, FIRSTSOCKET, connect_ms).await?;
                // Connection established (← `data->progress.t_connect`). The filter
                // chain drives TCP and, for a secure scheme, the TLS handshake in one
                // step here, so the app-connect timer (TLS-handshake-complete,
                // `data->progress.t_appconnect`) coincides with connect for a secure
                // transfer and stays `0` for a cleartext one — matching curl, which
                // reports `t_appconnect == 0` for a non-TLS connection.
                t_connect_us = t_start.elapsed().as_micros() as i64;
                if psh.is_secure() {
                    t_appconnect_us = t_connect_us;
                }
                // `* Connected to <host> (<ip>) port <port>` (curl's `Curl_verboseconnect`).
                if trace_on {
                    let ip = peer_ip.as_deref().unwrap_or(host.as_str());
                    trace_records.push((
                        DebugInfoType::Text,
                        format!("Connected to {host} ({ip}) port {port}\n").into_bytes(),
                    ));
                }
            }

            // Bytes actually sent as the request body (`-d`/`-T` payload), recorded for
            // `CURLINFO_SIZE_UPLOAD_T` once the transfer completes.
            let upload_bytes = request.body.as_ref().map_or(0, |b| b.len() as i64);

            // `-v`/`--trace` request-side records, built from `request` before it is moved into the
            // transfer context. For HTTP(S) the sent request head is rendered by the handler's own
            // assembler (so the `> ` block matches the wire, `Authorization` included); the request
            // body, if any, is the `} ` (DATA_OUT) payload.
            if trace_on {
                // The HTTP(S) request-head assembler lives in `protocols::http`, which is
                // compiled only under the `http` feature. Gate the call so `--no-default-features`
                // (and any build without `http`) still compiles; without the HTTP handler there is
                // no `http`/`https` transfer and hence no request head to render here.
                #[cfg(feature = "http")]
                {
                    if matches!(scheme_lc.as_str(), "http" | "https") {
                        let head = crate::protocols::http::trace_request_head_bytes(&request);
                        if !head.is_empty() {
                            trace_records.push((DebugInfoType::HeaderOut, head));
                        }
                    }
                }
                if let Some(b) = request.body.as_ref() {
                    if !b.is_empty() {
                        trace_records.push((DebugInfoType::DataOut, b.clone()));
                    }
                }
            }

            // --- 5. Drive the protocol exchange over the live connection. ---
            let mut ctx = TransferCtx::new();
            ctx.request = request;
            ctx.conn = Some(Box::new(conn));
            // Choose this hop's sink. When following redirects the terminal hop
            // is not yet known, so buffer the body: a followed `3xx` body is
            // discarded and the final body is flushed to the client sink after
            // the loop. When not following, wrap the client sink so every
            // delivered byte is counted for `CURLINFO_SIZE_DOWNLOAD_T` and, when
            // tracing, copied for the `{ ` (DATA_IN) dump — the unchanged
            // single-transfer path (direct streaming, no buffering).
            let iter_buffer: Option<Arc<std::sync::Mutex<Vec<u8>>>>;
            if follow_enabled {
                let buf = Arc::new(std::sync::Mutex::new(Vec::new()));
                iter_buffer = Some(Arc::clone(&buf));
                ctx.sink = Some(Box::new(BufferSink { buf }));
            } else {
                iter_buffer = None;
                let real = client_sink
                    .take()
                    .expect("client sink present for a non-redirected transfer");
                ctx.sink = Some(Box::new(CountingSink {
                    inner: real,
                    counter: Arc::clone(&downloaded),
                    capture: body_capture.as_ref().map(Arc::clone),
                }));
            }

            // Handler lifecycle (← `multi_runsingle`): SETUP → CONNECT → CONNECTING →
            // DO → DONE. The default `connect`/`connecting` report "ready" in one
            // step (the filter chain already connected the socket above); a protocol
            // that needs extra round-trips (e.g. a pingpong greeting) drives them
            // here, yielding between non-ready polls.
            handler.setup_connection(&mut ctx).await?;
            while !handler.connect(&mut ctx).await? {
                tokio::task::yield_now().await;
            }
            while !handler.connecting(&mut ctx).await? {
                tokio::task::yield_now().await;
            }

            // All connection setup (transport + protocol handshake) is complete and
            // the request is about to be sent (← `data->progress.t_pretransfer`).
            let t_pretransfer_us = t_start.elapsed().as_micros() as i64;

            // DO phase (send the request, read the response, stream the body to the
            // sink, record diagnostics). The DONE phase runs unconditionally with the
            // DO status forwarded so the handler can clean up on both paths (curl's
            // `Curl_done(..., status, premature)`), then the original DO result is
            // propagated (preserving its full error context).
            let do_res = handler.do_it(&mut ctx).await;
            // The response has been received (← `data->progress.t_starttransfer`).
            let t_starttransfer_us = t_start.elapsed().as_micros() as i64;
            let premature = do_res.is_err();
            let status_for_done: Result<()> = match &do_res {
                Ok(_) => Ok(()),
                Err(e) => Err(Error::from(e.code())),
            };
            handler.done(&mut ctx, status_for_done, premature).await?;

            // --- 6. Reconcile response diagnostics into the handle. ---
            self.info = std::mem::take(&mut ctx.info);
            // Stamp the connection scheme (`info.conn_scheme`, ← `create_conn`);
            // the CLI retry classifier and `CURLINFO_SCHEME` read it.
            self.info.conn_scheme = Some(scheme_lc.clone());
            self.info.size_upload = upload_bytes;
            // Record this hop's phase timers (microseconds from `t_start`) for
            // the `CURLINFO_*_TIME_T` getinfo variants and `--write-out
            // %{time_*}`/`%{speed_*}`. Set after the `info` move so they are not
            // overwritten; on a redirect chain the final hop's values persist,
            // matching curl, which reports the last request's phase times.
            self.info.namelookup_time_us = t_namelookup_us;
            self.info.connect_time_us = t_connect_us;
            self.info.appconnect_time_us = t_appconnect_us;
            self.info.pretransfer_time_us = t_pretransfer_us;
            self.info.starttransfer_time_us = t_starttransfer_us;

            // --- 6b. Ingest this hop's `Set-Cookie:` response headers into the
            // jar (← curl's `Curl_cookie_add` invoked per `Set-Cookie:` during
            // the header callback). The headers are collected first so the
            // immutable `info` borrow is released before the jar is mutated. Each
            // cookie is stored against THIS hop's host/path/scheme, so a later
            // hop (and a `-c` save) sees it with the correct domain scoping. A
            // cookie the jar rejects (bad domain, supercookie, …) is dropped
            // silently, exactly as curl does. Compiled only with the `cookies`
            // feature (curl's `CURL_DISABLE_COOKIES` removes the engine). ---
            #[cfg(feature = "cookies")]
            if self.state.cookies.is_some() {
                let set_cookies: Vec<String> = self
                    .info
                    .resp_headers
                    .iter()
                    .filter(|(name, _)| name.eq_ignore_ascii_case("Set-Cookie"))
                    .map(|(_, value)| value.clone())
                    .collect();
                if !set_cookies.is_empty() {
                    let is_tls = psh.is_secure();
                    if let Some(jar) = self.state.cookies.as_mut() {
                        for line in &set_cookies {
                            let _ =
                                jar.add(true, false, line, Some(&host), Some(&cookie_path), is_tls);
                        }
                    }
                }
            }

            // --- 6c. Ingest this hop's `Strict-Transport-Security:` response
            // header into the HSTS cache (← curl's `Curl_hsts_parse`, invoked
            // from the header callback). Values are collected first so the
            // immutable `info` borrow is released before the cache is mutated.
            // The parser stores the entry against THIS hop's host, ignores an
            // IP-literal host (RFC 6797 §8.3), and rejects a malformed header
            // without failing the transfer — exactly as curl does. ---
            if self.state.hsts.is_some() {
                let sts_values: Vec<String> = self
                    .info
                    .resp_headers
                    .iter()
                    .filter(|(name, _)| name.eq_ignore_ascii_case("Strict-Transport-Security"))
                    .map(|(_, value)| value.clone())
                    .collect();
                if let Some(hsts) = self.state.hsts.as_mut() {
                    for value in &sts_values {
                        let _ = hsts.parse(&host, value);
                    }
                }
            }

            // --- 6d. Ingest this hop's `Alt-Svc:` response header into the
            // Alt-Svc cache (← curl's `Curl_altsvc_parse`). The source ALPN is
            // the HTTP version negotiated on this connection
            // (← `Curl_conn_get_alpn_id`): `h2`/`h3` map directly and everything
            // else (HTTP/1.x, or a torn-down/unknown connection) is recorded as
            // `h1`, matching curl for a completed HTTP/1.1 exchange. `srchost`/
            // `srcport` are this hop's origin. Invalid alternatives are rejected
            // individually without failing the header or the transfer. ---
            if self.state.altsvc.is_some() {
                let altsvc_values: Vec<String> = self
                    .info
                    .resp_headers
                    .iter()
                    .filter(|(name, _)| name.eq_ignore_ascii_case("Alt-Svc"))
                    .map(|(_, value)| value.clone())
                    .collect();
                if !altsvc_values.is_empty() {
                    let src_alpn = match ctx.conn.as_ref().map_or(0, |c| c.http_version()) {
                        20 => crate::altsvc::AlpnId::H2,
                        30 => crate::altsvc::AlpnId::H3,
                        _ => crate::altsvc::AlpnId::H1,
                    };
                    if let Some(altsvc) = self.state.altsvc.as_mut() {
                        for value in &altsvc_values {
                            let _ = altsvc.parse(value, src_alpn, &host, port);
                        }
                    }
                }
            }

            // Response-head trace for this hop (one `< ` line per header),
            // recorded for every hop so a redirect chain shows each response.
            if trace_on {
                push_response_head_trace(&mut trace_records, &self.info, &scheme_lc);
            }

            // --- 7. Redirect decision. Follow only a real `3xx` carrying a
            // `Location:` and only when the DO phase itself succeeded (a
            // transport error is surfaced, never chased). ---
            let redirect_target = if follow_enabled && do_res.is_ok() {
                redirect_location(&self.info)
            } else {
                None
            };

            if let Some(location) = redirect_target {
                // Intermediate redirect: its buffered body is discarded (curl
                // suppresses the redirect body). Advance the URL, enforce
                // `CURLOPT_MAXREDIRS`, strip cross-origin credentials, and switch
                // the method per RFC 7231 — all via the existing `follow`.
                let prev = self.state.httpreq;
                if let Err(e) = self.follow(&location, FollowType::Redir) {
                    // Redirect limit exceeded (`CURLE_TOO_MANY_REDIRECTS`) or an
                    // unparsable target: surface it, finalizing diagnostics below.
                    break Err(e);
                }
                // Propagate a POST/other → GET switch onto the working request
                // (`follow` applied it to `state.httpreq`); a bodiless GET drops
                // the request body. A 307/308 leaves the method untouched.
                if self.state.httpreq == HttpReq::Get && prev != HttpReq::Get {
                    method = "GET".to_string();
                    body = None;
                }
                // The buffered redirect body is intentionally dropped here.
                drop(iter_buffer);
                continue;
            }

            // --- Final response. Flush a buffered body to the client sink and
            // account it for `CURLINFO_SIZE_DOWNLOAD_T`. (The non-following path
            // already streamed directly through `CountingSink`.) ---
            if let Some(buf) = iter_buffer {
                let bytes = buf.lock().map(|b| b.clone()).unwrap_or_default();
                downloaded.store(bytes.len() as i64, std::sync::atomic::Ordering::SeqCst);
                if let Some(mut real) = client_sink.take() {
                    if !bytes.is_empty() {
                        real.write(&bytes)?;
                    }
                    // `real` drops here; the transfer is complete and the sink is
                    // never consulted again (the loop is about to break).
                }
                if let Some(cap) = &body_capture {
                    if let Ok(mut c) = cap.lock() {
                        *c = bytes;
                    }
                }
            }
            break do_res.map(|_done| ());
            }
        };

        // Drive the redirect loop, bounding the whole chain by the overall
        // `--max-time` deadline when one is set. A fired deadline maps to curl's
        // `CURLE_OPERATION_TIMEDOUT` (28); the post-loop reconciliation below
        // still runs so `%{time_total}` and any partial `-v` trace are recorded.
        let final_do_res: Result<()> = match overall_timeout {
            Some(d) => match tokio::time::timeout(d, redirect_loop).await {
                Ok(res) => res,
                Err(_elapsed) => Err(Error::from(CurlCode::OperationTimedout)),
            },
            None => redirect_loop.await,
        };

        // --- 8. Reconcile the cumulative byte count + total time onto the final
        // `info`. The per-hop phase timers were stamped inside the loop; here we
        // record the total downloaded size (`CURLINFO_SIZE_DOWNLOAD_T`, summed by
        // the counting sink / final flush) and `total_time`, stamped last so it
        // always covers the whole transfer including any redirect chain and the
        // DONE phase (← `data->progress.timespent`, set by `Curl_pgrsDone`). ---
        self.info.size_download = downloaded.load(std::sync::atomic::Ordering::SeqCst);
        self.info.total_time_us = t_start.elapsed().as_micros() as i64;

        // --- 8a. Persist the cookie jar (← curl's cookie flush at handle
        // cleanup): write the `-c` file with every jar cookie, including those
        // just captured from this transfer's `Set-Cookie:` headers. Runs
        // regardless of transfer outcome (curl saves on cleanup even after an
        // error) and is a no-op when no `-c` path was set. Compiled only with
        // the `cookies` feature (curl's `CURL_DISABLE_COOKIES`). ---
        #[cfg(feature = "cookies")]
        self.save_cookies();

        // --- 8a'. Persist the HSTS and Alt-Svc caches (← curl's
        // `Curl_hsts_save` / `Curl_altsvc_save` at handle cleanup): rewrite the
        // `--hsts` / `--alt-svc` files with every cached entry, including those
        // just captured from this transfer's `Strict-Transport-Security:` /
        // `Alt-Svc:` headers. Each is a no-op when its file path was not set. ---
        self.save_hsts();
        self.save_altsvc();

        // --- 8b. Finish the `-v`/`--trace` stream: the final response body
        // (`{ ` DATA_IN) then curl's connection-teardown note. ---
        if trace_on {
            if let Some(buf) = &body_capture {
                if let Ok(b) = buf.lock() {
                    if !b.is_empty() {
                        trace_records.push((DebugInfoType::DataIn, b.clone()));
                    }
                }
            }
            let final_host = self
                .url_get_part(CurlUPart::Host, 0, urlapi::UrlCode::NoHost)
                .ok()
                .flatten()
                .unwrap_or_default();
            trace_records.push((
                DebugInfoType::Text,
                format!("Connection #0 to host {final_host} left intact\n").into_bytes(),
            ));
            self.debug_log = trace_records;
        }
        final_do_res
    }

    /// Blocking wrapper around [`perform_transfer`](Easy::perform_transfer) for
    /// the synchronous C easy API (`curl_easy_perform`), which curl documents as
    /// blocking the calling thread until the transfer completes.
    ///
    /// curl's easy interface is single-threaded (`lib/easy.c` runs the transfer
    /// on the caller's thread), so this builds a private **current-thread** Tokio
    /// runtime — the same flavor the CLI selects (`#[tokio::main(flavor =
    /// "current_thread")]`) — and drives the async transfer to completion on it.
    /// The runtime is created per call and dropped when the transfer finishes,
    /// mirroring curl's per-`curl_easy_perform` execution model and leaving the
    /// handle reusable for a subsequent perform.
    ///
    /// This is memory-safe (no `unsafe`), so the FFI crate can call through here
    /// and keep its dependency profile to the core crate alone — the Tokio
    /// runtime construction stays in `curl-rs-lib`, never in the `unsafe` FFI
    /// boundary. The cookie-jar flush, HSTS/Alt-Svc persistence, and all wire
    /// behavior are performed by [`perform_transfer`](Easy::perform_transfer)
    /// exactly as on the CLI path.
    ///
    /// Returns [`CurlCode::FailedInit`] (curl's `CURLE_FAILED_INIT`) if the
    /// runtime cannot be created, otherwise the transfer's own result.
    pub fn perform_blocking(
        &mut self,
        base_request: crate::protocols::TransferRequest,
        sink: Box<dyn crate::protocols::TransferSink>,
    ) -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                Error::with_context(
                    CurlCode::FailedInit,
                    format!("failed to create the transfer runtime: {e}"),
                )
            })?;
        runtime.block_on(self.perform_transfer(base_request, sink))
    }

    /// Sets the auto-referer for the next request from the current URL, stripping
    /// credentials and the fragment — the `CURLOPT_AUTOREFERER` branch of
    /// `Curl_http_follow`.
    fn set_auto_referer(&mut self) {
        if let Some(uh) = &self.state.uh {
            let mut u = uh.dup();
            // Best-effort: a failure to strip a part simply leaves it in place.
            let _ = u.set(CurlUPart::Fragment, None, 0);
            let _ = u.set(CurlUPart::User, None, 0);
            let _ = u.set(CurlUPart::Password, None, 0);
            if let Ok(referer) = u.get(CurlUPart::Url, 0) {
                self.state.referer = Some(referer);
            }
        }
    }

    /// Clears the resolved credentials if a redirect crosses to a different port
    /// or protocol — the cross-origin auth-stripping branch of
    /// `Curl_http_follow` (gated by `CURLOPT_UNRESTRICTED_AUTH`).
    fn maybe_clear_auth_on_redirect(&mut self) -> Result<()> {
        // Determine the redirect target's port.
        let new_port: i32 = if self.set.use_port != 0 && self.state.allow_port {
            i32::from(self.set.use_port)
        } else {
            match self.url_get_part(
                CurlUPart::Port,
                urlapi::DEFAULT_PORT,
                urlapi::UrlCode::NoPort,
            )? {
                Some(p) => p.parse::<i32>().unwrap_or(0),
                None => 0,
            }
        };

        let mut clear = new_port != i32::from(self.info.conn_remote_port);
        if !clear {
            // Same port: compare the scheme's protocol against the connection's.
            if let Some(scheme) =
                self.url_get_part(CurlUPart::Scheme, 0, urlapi::UrlCode::NoScheme)?
            {
                if let Some(h) = get_scheme_handler(&scheme) {
                    if h.protocol != self.info.conn_protocol {
                        clear = true;
                    }
                }
            }
        }

        if clear {
            self.state.aptr_user = None;
            self.state.aptr_passwd = None;
        }
        Ok(())
    }

    /// Applies the RFC 7231 method switch after a redirect — the `switch`
    /// statement of `Curl_http_follow`.
    ///
    /// A `POST` becomes a `GET` after a 301/302 (unless `CURLOPT_POSTREDIR`
    /// preserves it); a 303 switches any non-`GET` method to `GET` (unless it is
    /// a `POST` that `CURLOPT_POSTREDIR` preserves). All other codes leave the
    /// method unchanged.
    fn apply_redirect_method_switch(&mut self) {
        let is_post = self.state.httpreq.is_post_family();
        match self.info.httpcode {
            301 => {
                if is_post && !self.set.post301 {
                    self.state.httpreq = HttpReq::Get;
                }
            }
            302 => {
                if is_post && !self.set.post302 {
                    self.state.httpreq = HttpReq::Get;
                }
            }
            // A 303 switches any non-GET method to GET, except a POST that
            // CURLOPT_POSTREDIR opts to preserve. Written as a match guard so the
            // "leave the method unchanged" case falls through to the catch-all
            // arm below (identical behavior to the previous inner `if`).
            303 if self.state.httpreq != HttpReq::Get && (!is_post || !self.set.post303) => {
                self.state.httpreq = HttpReq::Get;
            }
            _ => {}
        }
    }

    /// Constructs the next URL from a `Location:` target and updates handle
    /// state accordingly — a rewrite of curl's `Curl_http_follow`.
    ///
    /// `newurl` may be relative; it is resolved against the current URL through
    /// the URL API (with `CURLU_URLENCODE` / `CURLU_ALLOW_SPACE` /
    /// `CURLU_PATH_AS_IS` exactly as curl selects them). The redirect limit
    /// ([`UserDefined::maxredirs`]) is enforced, credentials are stripped on a
    /// cross-origin redirect, and the request method is switched per the HTTP
    /// status code. In [`FollowType::Fake`] mode the resolved target is recorded
    /// in [`Info::wouldredirect`] without issuing a request.
    ///
    /// # Errors
    ///
    /// Returns [`CurlCode::TooManyRedirects`] when the redirect limit is hit,
    /// or a URL-parse error code when a non-fake target cannot be parsed.
    pub fn follow(&mut self, newurl: &str, follow_type: FollowType) -> Result<()> {
        let mut ftype = follow_type;
        let mut reached_max = false;

        // Count real follows.
        if ftype != FollowType::Fake {
            self.state.requests += 1;
        }

        if ftype == FollowType::Redir {
            if self.set.maxredirs != -1 && self.state.followlocation >= self.set.maxredirs {
                // Hit the limit: switch to FAKE to still compute the target,
                // then fail below.
                reached_max = true;
                ftype = FollowType::Fake;
            } else {
                self.state.followlocation += 1;
                if self.set.http_auto_referer {
                    self.set_auto_referer();
                }
            }
        }

        // An absolute redirect target (not from a 401/407) must not carry a
        // custom port over to the new request.
        let httpcode = self.info.httpcode;
        let disallowport = ftype != FollowType::Retry
            && httpcode != 401
            && httpcode != 407
            && is_absolute_url(newurl);

        // Resolve the (possibly relative) target against the base URL.
        let set_flags = if ftype == FollowType::Fake {
            urlapi::NON_SUPPORT_SCHEME
        } else {
            (if ftype == FollowType::Redir {
                urlapi::URLENCODE
            } else {
                0
            }) | urlapi::ALLOW_SPACE
                | if self.set.path_as_is {
                    urlapi::PATH_AS_IS
                } else {
                    0
                }
        };

        // A base URL handle must exist for relative resolution; create one so a
        // fully-absolute target still resolves.
        if self.state.uh.is_none() {
            self.state.uh = Some(Url::new());
        }

        let follow_url = {
            let uh = self.state.uh.as_mut().expect("URL handle just ensured");
            match uh.set(CurlUPart::Url, Some(newurl), set_flags) {
                Ok(()) => uc(uh.get(CurlUPart::Url, 0))?,
                Err(code) => {
                    if code == urlapi::UrlCode::OutOfMemory || ftype != FollowType::Fake {
                        return Err(Error::from(uc_to_curlcode(code)));
                    }
                    // FAKE mode tolerates an unparsable target: keep it verbatim.
                    newurl.to_string()
                }
            }
        };

        // Strip credentials on a cross-origin redirect (never in FAKE mode).
        if ftype != FollowType::Fake && !self.set.allow_auth_to_other_hosts {
            self.maybe_clear_auth_on_redirect()?;
        }

        if ftype == FollowType::Fake {
            self.info.wouldredirect = Some(follow_url);
            if reached_max {
                return Err(Error::from(CurlCode::TooManyRedirects));
            }
            return Ok(());
        }

        if disallowport {
            self.state.allow_port = false;
        }

        // The next request is a follow (gates CURLOPT_REDIR_PROTOCOLS), and the
        // method may switch per the HTTP status code.
        self.state.this_is_a_follow = true;
        self.apply_redirect_method_switch();

        Ok(())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a bare connection needle for a known scheme.
    #[cfg(feature = "http")]
    fn mk_conn(scheme: &str, host: &str, port: u16) -> Connection {
        let handler = get_scheme_handler(scheme).expect("known scheme");
        Connection::new(handler, host, port)
    }

    // --- scheme → handler selection -----------------------------------------

    #[cfg(all(feature = "http", feature = "ftp"))]
    #[test]
    fn scheme_handler_core_schemes() {
        let http = get_scheme_handler("http").expect("http");
        assert_eq!(http.name, "http");
        assert_eq!(http.protocol, proto::HTTP);
        assert_eq!(http.default_port, 80);
        assert!(!http.is_ssl());
        assert!(http.is_creds_per_request());

        let https = get_scheme_handler("https").expect("https");
        assert_eq!(https.default_port, 443);
        assert!(https.is_ssl());
        assert!(https.has_flag(protopt::ALPN));

        let ftp = get_scheme_handler("ftp").expect("ftp");
        assert_eq!(ftp.default_port, 21);
        assert!(ftp.has_flag(protopt::NEEDSPWD));
        assert!(!ftp.is_creds_per_request());

        let file = get_scheme_handler("file").expect("file");
        assert!(file.is_nonetwork());
    }

    #[cfg(feature = "http")]
    #[test]
    fn scheme_handler_is_case_insensitive() {
        // curl's Curl_get_scheme lowercases before matching.
        assert_eq!(get_scheme_handler("HTTP").expect("HTTP").name, "http");
        assert_eq!(get_scheme_handler("Https").expect("Https").name, "https");
    }

    #[test]
    fn rtmp_family_is_not_registered() {
        // RTMP/RTMPS are dropped (AAP §0.2.2): no handler, and findprotocol
        // rejects them as unsupported.
        for s in ["rtmp", "rtmps", "rtmpt", "rtmpe", "rtmpte", "rtmpts"] {
            assert!(
                get_scheme_handler(s).is_none(),
                "{s} must not be registered"
            );
            let err = findprotocol(s, proto::ALL, proto::REDIR, false).unwrap_err();
            assert_eq!(err.code(), CurlCode::UnsupportedProtocol);
        }
    }

    #[cfg(feature = "http")]
    #[test]
    fn findprotocol_honors_allowed_and_redir_protocols() {
        // Allowed on a normal request.
        assert!(findprotocol("http", proto::ALL, proto::REDIR, false).is_ok());

        // Disallowed when not in the allowed set.
        let err = findprotocol("http", proto::FTP, proto::REDIR, false).unwrap_err();
        assert_eq!(err.code(), CurlCode::UnsupportedProtocol);

        // Allowed as a normal request but forbidden as a redirect target.
        assert!(findprotocol("http", proto::ALL, proto::FTP, true).is_err());
        // Permitted as a redirect target when REDIR includes it.
        assert!(findprotocol("http", proto::ALL, proto::HTTP, true).is_ok());
    }

    #[test]
    fn uc_to_curlcode_mapping_is_exact() {
        assert_eq!(
            uc_to_curlcode(urlapi::UrlCode::UnsupportedScheme),
            CurlCode::UnsupportedProtocol
        );
        assert_eq!(
            uc_to_curlcode(urlapi::UrlCode::OutOfMemory),
            CurlCode::OutOfMemory
        );
        assert_eq!(
            uc_to_curlcode(urlapi::UrlCode::UserNotAllowed),
            CurlCode::LoginDenied
        );
        assert_eq!(
            uc_to_curlcode(urlapi::UrlCode::MalformedInput),
            CurlCode::UrlMalformat
        );
    }

    // --- default option values ----------------------------------------------

    #[test]
    fn userdefined_defaults_match_curl() {
        let s = UserDefined::default();
        assert_eq!(s.maxredirs, DEFAULT_MAXREDIRS);
        assert_eq!(s.maxredirs, 30);
        assert_eq!(s.buffer_size, 16384);
        assert_eq!(s.upload_buffer_size, 65536);
        assert_eq!(s.method, HttpReq::Get);
        assert_eq!(s.use_netrc, NetrcLevel::Ignored);
        assert_eq!(s.allowed_protocols, proto::ALL);
        assert_eq!(s.redir_protocols, proto::REDIR);
        assert!(s.ftp_use_epsv);
        assert!(s.ftp_use_eprt);
        assert!(!s.ftp_use_pret);
        assert_eq!(s.ftp_filemethod, FtpFileMethod::MultiCwd);
        assert!(s.tcp_nodelay);
        assert!(!s.tcp_keepalive);
        assert!(s.ssl_enable_alpn);
        assert_eq!(s.maxconnects, DEFAULT_CONNCACHE_SIZE);
    }

    #[test]
    fn tls_verification_is_on_by_default() {
        // The core safety default (AAP §0.7.3): verifypeer = 1, verifyhost = 2.
        let s = UserDefined::default();
        assert!(s.ssl.verify_peer);
        assert_eq!(s.ssl.verify_host, 2);
        assert!(!s.ssl.verify_status);
        // The DoH verification defaults mirror the primary transfer.
        assert!(s.doh_verifypeer);
        assert!(s.doh_verifyhost);
    }

    #[test]
    fn easy_open_has_curl_defaults() {
        let e = Easy::open();
        assert_eq!(e.set.maxredirs, 30);
        assert!(e.set.ssl.verify_peer);
        assert_eq!(e.set.ssl.verify_host, 2);
        assert_eq!(e.state.followlocation, 0);
        assert!(!e.state.this_is_a_follow);
        assert_eq!(e.state.creds_from, CredsFrom::None);
    }

    #[test]
    fn duphandle_copies_options_and_resets_state() {
        let mut e = Easy::open();
        e.set.maxredirs = 7;
        e.set.username = Some("bob".to_string());
        e.state.followlocation = 3;
        e.set_url("http://example.com/").expect("set url");

        let dup = e.duphandle();
        // Options copied verbatim.
        assert_eq!(dup.set.maxredirs, 7);
        assert_eq!(dup.set.username.as_deref(), Some("bob"));
        // Live state reset.
        assert_eq!(dup.state.followlocation, 0);
        assert!(dup.state.uh.is_none());
    }

    // --- login-string parsing (Curl_parse_login_details) --------------------

    #[test]
    fn parse_login_details_all_forms() {
        assert_eq!(
            parse_login_details("user"),
            ("user".to_string(), None, None)
        );
        assert_eq!(
            parse_login_details("user:pass"),
            ("user".to_string(), Some("pass".to_string()), None)
        );
        assert_eq!(
            parse_login_details("user:pass;opt"),
            (
                "user".to_string(),
                Some("pass".to_string()),
                Some("opt".to_string())
            )
        );
        assert_eq!(
            parse_login_details("user;opt"),
            ("user".to_string(), None, Some("opt".to_string()))
        );
        assert_eq!(
            parse_login_details("user;opt:pass"),
            (
                "user".to_string(),
                Some("pass".to_string()),
                Some("opt".to_string())
            )
        );
        assert_eq!(
            parse_login_details(":pass"),
            (String::new(), Some("pass".to_string()), None)
        );
        assert_eq!(
            parse_login_details(";opt"),
            (String::new(), None, Some("opt".to_string()))
        );
        // Empty password after ':' is a deliberate (Some) empty string; empty
        // options after ';' collapse to None (curl leaves obuf NULL).
        assert_eq!(
            parse_login_details("user:"),
            ("user".to_string(), Some(String::new()), None)
        );
        assert_eq!(
            parse_login_details("user;"),
            ("user".to_string(), None, None)
        );
        assert_eq!(parse_login_details(""), (String::new(), None, None));
    }

    // --- no-proxy matching (Curl_check_noproxy) -----------------------------

    #[test]
    fn check_noproxy_host_patterns() {
        assert!(check_noproxy("example.com", "*"));
        assert!(check_noproxy("example.com", "example.com"));
        // Domain tail match.
        assert!(check_noproxy("www.example.com", "example.com"));
        // Not a tail match — "nonexample.com" must not match "example.com".
        assert!(!check_noproxy("nonexample.com", "example.com"));
        // Comma/space separated list.
        assert!(check_noproxy("example.com", "example.org, example.com"));
        assert!(!check_noproxy("example.com", "example.org,example.net"));
        // Leading dot in the token is ignored.
        assert!(check_noproxy("host.example.com", ".example.com"));
        // Trailing dots (in name and in token) are ignored.
        assert!(check_noproxy("example.com.", "example.com"));
        assert!(check_noproxy("example.com", "example.com."));
    }

    #[test]
    fn check_noproxy_empty_inputs() {
        assert!(!check_noproxy("", "*"));
        assert!(!check_noproxy("example.com", ""));
    }

    #[test]
    fn check_noproxy_ipv4_cidr() {
        assert!(check_noproxy("192.168.1.5", "192.168.1.0/24"));
        assert!(!check_noproxy("192.168.2.5", "192.168.1.0/24"));
        assert!(check_noproxy("10.0.0.1", "10.0.0.1"));
        assert!(check_noproxy("127.0.0.1", "127.0.0.0/8"));
        assert!(!check_noproxy("10.0.0.1", "192.168.0.0/16"));
    }

    #[test]
    fn check_noproxy_ipv6_cidr() {
        assert!(check_noproxy("::1", "::1/128"));
        assert!(check_noproxy("2001:db8::1", "2001:db8::/32"));
        assert!(!check_noproxy("2001:dead::1", "2001:db8::/32"));
    }

    // --- connection reuse matching (url_match_conn) -------------------------

    #[cfg(feature = "http")]
    #[test]
    fn reuse_exact_match() {
        let a = mk_conn("http", "example.com", 80);
        let b = mk_conn("http", "example.com", 80);
        assert!(a.can_reuse_for(&b));
        // Host comparison is case-insensitive.
        let c = mk_conn("http", "EXAMPLE.COM", 80);
        assert!(a.can_reuse_for(&c));
    }

    #[cfg(feature = "http")]
    #[test]
    fn reuse_rejects_host_or_port_mismatch() {
        let a = mk_conn("http", "example.com", 80);
        assert!(!a.can_reuse_for(&mk_conn("http", "other.com", 80)));
        assert!(!a.can_reuse_for(&mk_conn("http", "example.com", 8080)));
    }

    #[cfg(feature = "http")]
    #[test]
    fn reuse_rejects_scheme_mismatch() {
        // An http candidate cannot serve an https needle (needs TLS)...
        let http = mk_conn("http", "example.com", 443);
        assert!(!http.can_reuse_for(&mk_conn("https", "example.com", 443)));
        // ...and an https candidate cannot serve a plain-http needle.
        let https = mk_conn("https", "example.com", 80);
        assert!(!https.can_reuse_for(&mk_conn("http", "example.com", 80)));
    }

    #[cfg(all(feature = "http", feature = "ftp"))]
    #[test]
    fn reuse_credentials_matter_only_when_not_creds_per_request() {
        // HTTP carries credentials per request: differing creds still match.
        let mut a = mk_conn("http", "example.com", 80);
        let mut b = mk_conn("http", "example.com", 80);
        a.user = Some("alice".to_string());
        b.user = Some("bob".to_string());
        assert!(a.can_reuse_for(&b));

        // FTP binds credentials to the connection: differing users do NOT match.
        let mut fa = mk_conn("ftp", "ftp.example.com", 21);
        let mut fb = mk_conn("ftp", "ftp.example.com", 21);
        fa.user = Some("alice".to_string());
        fa.passwd = Some("secret".to_string());
        fb.user = Some("bob".to_string());
        fb.passwd = Some("secret".to_string());
        assert!(!fa.can_reuse_for(&fb));
    }

    #[cfg(feature = "http")]
    #[test]
    fn reuse_rejects_tls_config_mismatch() {
        let a = mk_conn("https", "example.com", 443);
        let mut b = mk_conn("https", "example.com", 443);
        // A needle that disables peer verification must not reuse a verifying
        // connection.
        b.ssl.verify_peer = false;
        assert!(!a.can_reuse_for(&b));
    }

    #[cfg(feature = "http")]
    #[test]
    fn reuse_rejects_proxy_mismatch_and_unusable_conn() {
        let a = mk_conn("http", "example.com", 80);
        let mut proxied = mk_conn("http", "example.com", 80);
        proxied.bits.httpproxy = true;
        proxied.http_proxy = ProxyInfo {
            proxytype: ProxyType::Http,
            host: "proxy.local".to_string(),
            port: 3128,
            user: None,
            passwd: None,
        };
        // One goes through a proxy, the other does not.
        assert!(!a.can_reuse_for(&proxied));

        // A connect-only / to-be-closed candidate is never reusable.
        let mut connect_only = mk_conn("http", "example.com", 80);
        connect_only.bits.connect_only = true;
        assert!(!connect_only.can_reuse_for(&mk_conn("http", "example.com", 80)));
        let mut closing = mk_conn("http", "example.com", 80);
        closing.bits.close = true;
        assert!(!closing.can_reuse_for(&mk_conn("http", "example.com", 80)));
    }

    // --- connection cache (find_or_create / disconnect) ---------------------

    #[cfg(feature = "http")]
    #[test]
    fn conn_cache_reuses_and_creates() {
        let mut cache = ConnCache::new(DEFAULT_CONNCACHE_SIZE);
        assert!(cache.is_empty());

        let r1 = cache.find_or_create(mk_conn("http", "example.com", 80));
        assert!(!r1.reused);
        assert_eq!(cache.len(), 1);

        // Identical needle → reuse the same connection.
        let r2 = cache.find_or_create(mk_conn("http", "example.com", 80));
        assert!(r2.reused);
        assert_eq!(r2.connection_id, r1.connection_id);
        assert_eq!(cache.len(), 1);

        // Different destination → a brand new connection.
        let r3 = cache.find_or_create(mk_conn("http", "other.com", 80));
        assert!(!r3.reused);
        assert_eq!(cache.len(), 2);
        assert_ne!(r3.connection_id, r1.connection_id);
    }

    #[cfg(feature = "http")]
    #[test]
    fn conn_cache_disconnect_closes_or_retains() {
        let mut cache = ConnCache::new(DEFAULT_CONNCACHE_SIZE);
        let r = cache.find_or_create(mk_conn("http", "example.com", 80));

        // A dead connection is closed (removed).
        assert!(cache.disconnect(r.connection_id, true));
        assert!(cache.is_empty());

        // A healthy, reusable connection is retained for future reuse.
        let r2 = cache.find_or_create(mk_conn("http", "example.com", 80));
        assert!(!cache.disconnect(r2.connection_id, false));
        assert!(cache.get(r2.connection_id).is_some());

        // Disconnecting an unknown id is a no-op.
        assert!(!cache.disconnect(9999, true));
    }

    // --- create_conn (connect flow) -----------------------------------------

    #[cfg(feature = "http")]
    #[test]
    fn create_conn_selects_handler_and_resolves_endpoint() {
        let mut e = Easy::open();
        e.set_url("http://user:pass@example.com:8080/path")
            .expect("set url");
        let mut cache = ConnCache::new(DEFAULT_CONNCACHE_SIZE);

        let r = e.create_conn(&mut cache).expect("create_conn");
        assert!(!r.reused);
        let c = cache.get(r.connection_id).expect("pooled conn");
        assert_eq!(c.handler.name, "http");
        assert_eq!(c.host, "example.com");
        assert_eq!(c.port, 8080);
        assert_eq!(c.user.as_deref(), Some("user"));
        assert_eq!(c.passwd.as_deref(), Some("pass"));
    }

    #[cfg(feature = "http")]
    #[test]
    fn create_conn_reuses_second_time() {
        let mut e = Easy::open();
        e.set_url("http://example.com/").expect("set url");
        let mut cache = ConnCache::new(DEFAULT_CONNCACHE_SIZE);

        let r1 = e.create_conn(&mut cache).expect("first");
        assert!(!r1.reused);
        let r2 = e.create_conn(&mut cache).expect("second");
        assert!(r2.reused);
        assert_eq!(r1.connection_id, r2.connection_id);
    }

    #[test]
    fn create_conn_rejects_rtmp_scheme() {
        let mut e = Easy::open();
        // set_url tolerates the unknown scheme (NON_SUPPORT_SCHEME); create_conn
        // is where the dropped protocol is rejected.
        if e.set_url("rtmp://media.example.com/live").is_ok() {
            let mut cache = ConnCache::new(DEFAULT_CONNCACHE_SIZE);
            let err = e.create_conn(&mut cache).unwrap_err();
            assert_eq!(err.code(), CurlCode::UnsupportedProtocol);
        }
    }

    #[cfg(all(feature = "http", feature = "ftp"))]
    #[test]
    fn create_conn_applies_default_credentials() {
        // FTP (needs a password) with no credentials → anonymous defaults.
        let mut ftp = Easy::open();
        ftp.set_url("ftp://ftp.example.com/file").expect("set url");
        let mut cache = ConnCache::new(DEFAULT_CONNCACHE_SIZE);
        let r = ftp.create_conn(&mut cache).expect("create_conn");
        let c = cache.get(r.connection_id).expect("pooled");
        assert_eq!(c.user.as_deref(), Some(CURL_DEFAULT_USER));
        assert_eq!(c.passwd.as_deref(), Some(CURL_DEFAULT_PASSWORD));

        // HTTP (no password required) with no credentials → empty strings.
        let mut http = Easy::open();
        http.set_url("http://example.com/").expect("set url");
        let mut cache2 = ConnCache::new(DEFAULT_CONNCACHE_SIZE);
        let r2 = http.create_conn(&mut cache2).expect("create_conn");
        let c2 = cache2.get(r2.connection_id).expect("pooled");
        assert_eq!(c2.user.as_deref(), Some(""));
        assert_eq!(c2.passwd.as_deref(), Some(""));
    }

    // --- redirect handling (Curl_http_follow) -------------------------------

    #[test]
    fn follow_resolves_relative_target() {
        let mut e = Easy::open();
        e.set_url("http://example.com/a/b").expect("set url");
        e.info.conn_remote_port = 80;
        e.info.conn_protocol = proto::HTTP;
        e.info.httpcode = 302;
        e.state.httpreq = HttpReq::Get;

        e.follow("/c/d", FollowType::Redir).expect("follow");
        let resolved = e.state.uh.as_ref().unwrap().get(CurlUPart::Url, 0).unwrap();
        assert_eq!(resolved, "http://example.com/c/d");
        assert_eq!(e.state.followlocation, 1);
    }

    #[test]
    fn follow_enforces_maxredirs() {
        let mut e = Easy::open();
        e.set.maxredirs = 0; // no redirects permitted
        e.set_url("http://example.com/").expect("set url");
        e.info.httpcode = 302;

        let err = e
            .follow("http://example.com/next", FollowType::Redir)
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::TooManyRedirects);
        // The would-be target is still recorded.
        assert!(e.info.wouldredirect.is_some());
    }

    #[test]
    fn follow_switches_post_to_get_on_301_302_303() {
        for code in [301, 302, 303] {
            let mut e = Easy::open();
            e.set_url("http://example.com/").expect("set url");
            e.info.conn_remote_port = 80;
            e.info.conn_protocol = proto::HTTP;
            e.info.httpcode = code;
            e.state.httpreq = HttpReq::Post;
            e.follow("http://example.com/next", FollowType::Redir)
                .expect("follow");
            assert_eq!(
                e.state.httpreq,
                HttpReq::Get,
                "code {code} should switch POST→GET"
            );
        }
    }

    #[test]
    fn follow_keeps_method_on_307() {
        let mut e = Easy::open();
        e.set_url("http://example.com/").expect("set url");
        e.info.conn_remote_port = 80;
        e.info.conn_protocol = proto::HTTP;
        e.info.httpcode = 307;
        e.state.httpreq = HttpReq::Post;
        e.follow("http://example.com/next", FollowType::Redir)
            .expect("follow");
        assert_eq!(e.state.httpreq, HttpReq::Post);
    }

    #[test]
    fn follow_keeps_post_when_postredir_set() {
        let mut e = Easy::open();
        e.set.post301 = true; // CURLOPT_POSTREDIR keeps POST across 301
        e.set_url("http://example.com/").expect("set url");
        e.info.conn_remote_port = 80;
        e.info.conn_protocol = proto::HTTP;
        e.info.httpcode = 301;
        e.state.httpreq = HttpReq::Post;
        e.follow("http://example.com/next", FollowType::Redir)
            .expect("follow");
        assert_eq!(e.state.httpreq, HttpReq::Post);
    }

    #[test]
    fn follow_strips_credentials_across_origin() {
        let mut e = Easy::open();
        e.set_url("http://user:pass@example.com/").expect("set url");
        e.info.conn_remote_port = 80;
        e.info.conn_protocol = proto::HTTP;
        e.info.httpcode = 302;
        e.state.aptr_user = Some("user".to_string());
        e.state.aptr_passwd = Some("pass".to_string());

        // Redirect to a different port → credentials are cleared.
        e.follow("http://example.com:8080/next", FollowType::Redir)
            .expect("follow");
        assert!(e.state.aptr_user.is_none());
        assert!(e.state.aptr_passwd.is_none());
    }

    #[test]
    fn follow_keeps_credentials_same_origin() {
        let mut e = Easy::open();
        e.set_url("http://user:pass@example.com/").expect("set url");
        e.info.conn_remote_port = 80;
        e.info.conn_protocol = proto::HTTP;
        e.info.httpcode = 302;
        e.state.aptr_user = Some("user".to_string());
        e.state.aptr_passwd = Some("pass".to_string());

        e.follow("http://example.com/other", FollowType::Redir)
            .expect("follow");
        assert_eq!(e.state.aptr_user.as_deref(), Some("user"));
        assert_eq!(e.state.aptr_passwd.as_deref(), Some("pass"));
    }

    #[test]
    fn follow_disallows_port_for_absolute_target() {
        let mut e = Easy::open();
        e.set_url("http://example.com/").expect("set url");
        e.state.allow_port = true;
        e.info.conn_remote_port = 80;
        e.info.conn_protocol = proto::HTTP;
        e.info.httpcode = 302;

        // Absolute redirect target → custom port disallowed henceforth.
        e.follow("http://example.com/x", FollowType::Redir)
            .expect("follow");
        assert!(!e.state.allow_port);
    }

    #[test]
    fn follow_keeps_allow_port_for_relative_target() {
        let mut e = Easy::open();
        e.set_url("http://example.com/").expect("set url");
        e.state.allow_port = true;
        e.info.conn_remote_port = 80;
        e.info.conn_protocol = proto::HTTP;
        e.info.httpcode = 302;

        e.follow("/relative", FollowType::Redir).expect("follow");
        assert!(e.state.allow_port);
    }

    #[test]
    fn is_absolute_url_detection() {
        assert!(is_absolute_url("http://example.com/"));
        assert!(is_absolute_url("https://example.com"));
        assert!(is_absolute_url("ftp://host/"));
        assert!(!is_absolute_url("/relative/path"));
        assert!(!is_absolute_url("relative"));
        assert!(!is_absolute_url("//scheme-relative"));
    }

    // --- perform_transfer (the curl_easy_perform DO/PERFORM core) ------------

    /// A minimal recording sink that accumulates the received body bytes, so a
    /// test can assert exactly what `perform_transfer` streamed out.
    #[cfg(feature = "http")]
    struct VecSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    #[cfg(feature = "http")]
    impl crate::protocols::TransferSink for VecSink {
        fn write(&mut self, data: &[u8]) -> Result<()> {
            self.0.lock().expect("sink lock").extend_from_slice(data);
            Ok(())
        }
    }

    /// End-to-end proof that [`Easy::perform_transfer`] performs **real network
    /// I/O**: it resolves `127.0.0.1`, connects a live filter chain, sends a
    /// GET, streams the response body to the sink, and records the response
    /// diagnostics onto the handle (review finding F8-1: the CLI performed no
    /// network I/O because this driver did not exist / was unwired).
    #[cfg(feature = "http")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_transfer_drives_real_http_get() {
        use std::sync::{Arc, Mutex};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // A one-shot HTTP/1.1 origin server on an ephemeral loopback port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let mut data = Vec::new();
            while !data.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
            }
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\
                  Connection: close\r\n\r\nhello",
            )
            .await
            .unwrap();
            let _ = sock.shutdown().await;
            data
        });

        // Configure a handle exactly as the CLI does: parse the URL onto the
        // handle, then drive the transfer through the library core.
        let mut easy = Easy::open();
        easy.set_url(&format!("http://127.0.0.1:{}/e2e", addr.port()))
            .expect("set_url");

        let collected = Arc::new(Mutex::new(Vec::new()));
        let sink = Box::new(VecSink(Arc::clone(&collected)));

        let req = crate::protocols::TransferRequest {
            method: "GET".to_string(),
            ..Default::default()
        };

        easy.perform_transfer(req, sink)
            .await
            .expect("perform_transfer drives a real GET");

        // The server observed a GET on the requested path.
        let captured = srv.await.unwrap();
        assert!(
            captured.starts_with(b"GET /e2e HTTP/1.1\r\n"),
            "server must observe the GET request line"
        );

        // The body was streamed to the sink and the diagnostics recorded.
        assert_eq!(collected.lock().expect("sink").as_slice(), b"hello");
        assert_eq!(easy.info.httpcode, 200);
        assert_eq!(easy.info.contenttype.as_deref(), Some("text/plain"));
    }

    /// End-to-end proof that [`Easy::perform_blocking`] — the synchronous
    /// wrapper the FFI `curl_easy_perform` drives — builds its own
    /// current-thread runtime and runs a **real** HTTP GET to completion
    /// (FA-FMT-001 step 3: the FFI transfer engine now performs network I/O).
    /// The test itself stays synchronous (no `#[tokio::test]`) because
    /// `perform_blocking` calls `Runtime::block_on`, which must not run inside
    /// an existing runtime; the one-shot origin server therefore lives on a
    /// plain OS thread.
    #[cfg(feature = "http")]
    #[test]
    fn perform_blocking_drives_real_http_get() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let srv = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let mut data = Vec::new();
            // Drain the request head so the client's write completes before we
            // answer (mirrors the async sibling test's read loop).
            loop {
                let n = sock.read(&mut buf).expect("read");
                if n == 0 || data.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
                if data.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\
                  Connection: close\r\n\r\nhello",
            )
            .expect("write response");
            let _ = sock.flush();
        });

        let mut easy = Easy::open();
        easy.set_url(&format!("http://127.0.0.1:{}/e2e", addr.port()))
            .expect("set url");
        let collected = Arc::new(Mutex::new(Vec::new()));
        let sink = Box::new(VecSink(Arc::clone(&collected)));
        let req = crate::protocols::TransferRequest {
            method: "GET".to_string(),
            ..Default::default()
        };
        easy.perform_blocking(req, sink)
            .expect("perform_blocking drives a real GET");
        srv.join().expect("server thread");
        assert_eq!(collected.lock().expect("sink").as_slice(), b"hello");
        assert_eq!(easy.info.httpcode, 200);
    }

    // --- F10 redirect + TLS-threading helper logic ---------------------------

    /// The request-method → [`HttpReq`] mapping that seeds the redirect
    /// method-switch (F10-REDIR-01). The three body-bearing verbs map to their
    /// kinds; a bodiless `GET` maps to `Head`; any custom verb maps to `Get`
    /// (curl carries a `CUSTOMREQUEST` method through a redirect unchanged).
    #[test]
    fn httpreq_from_method_maps_verbs() {
        assert_eq!(httpreq_from_method("POST", false), HttpReq::Post);
        assert_eq!(httpreq_from_method("PUT", false), HttpReq::Put);
        assert_eq!(httpreq_from_method("HEAD", true), HttpReq::Head);
        assert_eq!(httpreq_from_method("GET", false), HttpReq::Get);
        // A GET forced bodiless (`-I` shape) is a HEAD-kind request.
        assert_eq!(httpreq_from_method("GET", true), HttpReq::Head);
        // A custom method is method-preserving (mapped to the Get kind, which
        // `apply_redirect_method_switch` leaves untouched).
        assert_eq!(httpreq_from_method("DELETE", false), HttpReq::Get);
        assert_eq!(httpreq_from_method("PATCH", false), HttpReq::Get);
    }

    /// The ALPN offer derived from `CURLOPT_HTTP_VERSION` (F10-TLS-03). A forced
    /// HTTP/1.0 or 1.1 preference restricts the offer to `http/1.1`; every other
    /// value offers the default `h2, http/1.1` set (curl's HTTPS ALPN parity).
    #[test]
    fn alpn_offer_reflects_http_version_preference() {
        // CURL_HTTP_VERSION_1_0 == 1, CURL_HTTP_VERSION_1_1 == 2.
        assert_eq!(
            alpn_offer_for_httpwant(1),
            vec![crate::tls::ALPN_HTTP_1_1.to_vec()]
        );
        assert_eq!(
            alpn_offer_for_httpwant(2),
            vec![crate::tls::ALPN_HTTP_1_1.to_vec()]
        );
        // NONE (0), 2_0 (3), 2TLS (4) → default h2 + http/1.1.
        let default = crate::tls::default_https_alpn();
        assert_eq!(alpn_offer_for_httpwant(0), default);
        assert_eq!(alpn_offer_for_httpwant(3), default);
        assert_eq!(alpn_offer_for_httpwant(4), default);
        // The default set advertises HTTP/2 ahead of HTTP/1.1.
        assert_eq!(
            default.first().map(Vec::as_slice),
            Some(crate::tls::ALPN_H2)
        );
    }

    /// Redirect detection (F10-REDIR-01): a `3xx` status with a `Location:`
    /// yields the trimmed target (header lookup case-insensitive); a
    /// non-redirect status, or a redirect without a usable `Location`, yields
    /// `None` so the loop terminates.
    #[test]
    fn redirect_location_detects_3xx_with_location() {
        let redir = Info {
            httpcode: 302,
            resp_headers: vec![
                ("Server".to_string(), "test".to_string()),
                ("LOCATION".to_string(), "  /next  ".to_string()),
            ],
            ..Default::default()
        };
        assert_eq!(redirect_location(&redir).as_deref(), Some("/next"));

        // 200 is not a redirect even with a (spurious) Location.
        let ok = Info {
            httpcode: 200,
            resp_headers: vec![("Location".to_string(), "/x".to_string())],
            ..Default::default()
        };
        assert_eq!(redirect_location(&ok), None);

        // 301/303/307/308 are all in the redirect set.
        for code in [301, 303, 307, 308] {
            let r = Info {
                httpcode: code,
                resp_headers: vec![("Location".to_string(), "/y".to_string())],
                ..Default::default()
            };
            assert_eq!(redirect_location(&r).as_deref(), Some("/y"), "code {code}");
        }

        // A 302 without a Location does not redirect.
        let no_loc = Info {
            httpcode: 302,
            resp_headers: vec![("Server".to_string(), "test".to_string())],
            ..Default::default()
        };
        assert_eq!(redirect_location(&no_loc), None);
    }

    /// The `-v`/`--trace` response-head record stream: status line + one record
    /// per header + a terminating blank line, all `HeaderIn`; a no-op for a
    /// non-HTTP scheme or a hop with no status.
    #[test]
    fn push_response_head_trace_emits_status_and_headers() {
        use crate::protocols::DebugInfoType;
        let info = Info {
            httpcode: 200,
            resp_reason: Some("OK".to_string()),
            resp_headers: vec![
                ("Content-Type".to_string(), "text/plain".to_string()),
                ("Content-Length".to_string(), "5".to_string()),
            ],
            ..Default::default()
        };
        let mut recs: Vec<(DebugInfoType, Vec<u8>)> = Vec::new();
        push_response_head_trace(&mut recs, &info, "https");
        // Status line + 2 headers + blank line = 4 records, all HeaderIn.
        assert_eq!(recs.len(), 4);
        assert!(recs
            .iter()
            .all(|(t, _)| matches!(t, DebugInfoType::HeaderIn)));
        assert_eq!(recs[0].1, b"HTTP/1.1 200 OK\r\n");
        assert_eq!(recs[1].1, b"Content-Type: text/plain\r\n");
        assert_eq!(recs[3].1, b"\r\n");

        // A non-HTTP scheme records nothing.
        let mut none: Vec<(DebugInfoType, Vec<u8>)> = Vec::new();
        push_response_head_trace(&mut none, &info, "ftp");
        assert!(none.is_empty());
    }

    /// End-to-end proof that [`Easy::perform_transfer`] follows an HTTP `302`
    /// when `CURLOPT_FOLLOWLOCATION` is set (review finding F10-REDIR-01: the
    /// driver never invoked the redirect logic, so `-L` returned the `302`
    /// itself with `num_redirects == 0`). The origin serves a `302 → /final` on
    /// the first connection and `200 hello` on the second; the handle must land
    /// on the final response, deliver only the final body, and count one
    /// redirect.
    #[cfg(feature = "http")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_transfer_follows_302_redirect() {
        use std::sync::{Arc, Mutex};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        async fn read_request_head(sock: &mut tokio::net::TcpStream) -> Vec<u8> {
            let mut buf = [0u8; 4096];
            let mut data = Vec::new();
            while !data.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
            }
            data
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            // Hop 1: 302 → /final (empty body, curl suppresses the redirect body).
            let (mut s1, _) = listener.accept().await.unwrap();
            let _ = read_request_head(&mut s1).await;
            s1.write_all(
                b"HTTP/1.1 302 Found\r\nLocation: /final\r\n\
                  Content-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
            let _ = s1.shutdown().await;

            // Hop 2: the followed request, answered with the real body.
            let (mut s2, _) = listener.accept().await.unwrap();
            let req2 = read_request_head(&mut s2).await;
            s2.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\
                  Connection: close\r\n\r\nhello",
            )
            .await
            .unwrap();
            let _ = s2.shutdown().await;
            req2
        });

        let mut easy = Easy::open();
        easy.set_url(&format!("http://127.0.0.1:{}/start", addr.port()))
            .expect("set_url");
        // `-L` / CURLOPT_FOLLOWLOCATION.
        easy.set.follow_location = true;

        let collected = Arc::new(Mutex::new(Vec::new()));
        let sink = Box::new(VecSink(Arc::clone(&collected)));
        let req = crate::protocols::TransferRequest {
            method: "GET".to_string(),
            ..Default::default()
        };

        easy.perform_transfer(req, sink)
            .await
            .expect("perform_transfer follows the redirect");

        // The second (followed) request targeted the redirect location.
        let req2 = srv.await.unwrap();
        assert!(
            req2.starts_with(b"GET /final HTTP/1.1\r\n"),
            "the followed request must target /final"
        );

        // The handle landed on the final 200 response, delivered only the final
        // body, and counted exactly one followed redirect.
        assert_eq!(easy.info.httpcode, 200);
        assert_eq!(collected.lock().expect("sink").as_slice(), b"hello");
        assert_eq!(
            easy.state.followlocation, 1,
            "exactly one redirect was followed"
        );
    }

    /// End-to-end proof that [`Easy::perform_transfer`] strips Basic credentials
    /// on a *cross-origin* redirect — the AAP §0.6.1 cross-host `Authorization`
    /// stripping gate, surfaced while re-verifying F10-REDIR-01. curl sends the
    /// `-u` credentials to the first origin but must never forward them to a
    /// redirect target on a different origin (here a different port) unless
    /// `CURLOPT_UNRESTRICTED_AUTH` / `--location-trusted` opts in. Two listeners
    /// on distinct ports model the two origins; the followed request to the
    /// second origin must carry no `Authorization` header.
    #[cfg(feature = "http")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn perform_transfer_strips_credentials_on_cross_origin_redirect() {
        use std::sync::{Arc, Mutex};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        async fn read_request_head(sock: &mut tokio::net::TcpStream) -> Vec<u8> {
            let mut buf = [0u8; 4096];
            let mut data = Vec::new();
            while !data.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
            }
            data
        }

        // Origin A issues the redirect; origin B is the cross-origin target
        // (a distinct ephemeral port ⇒ a different origin).
        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_a = listener_a.local_addr().unwrap();
        let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_b = listener_b.local_addr().unwrap();
        let port_b = addr_b.port();

        // Origin A: 302 → an *absolute* URL on origin B.
        let srv_a = tokio::spawn(async move {
            let (mut s1, _) = listener_a.accept().await.unwrap();
            let req1 = read_request_head(&mut s1).await;
            let redirect = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port_b}/final\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
            s1.write_all(redirect.as_bytes()).await.unwrap();
            let _ = s1.shutdown().await;
            req1
        });

        // Origin B: answers the followed request with the real body.
        let srv_b = tokio::spawn(async move {
            let (mut s2, _) = listener_b.accept().await.unwrap();
            let req2 = read_request_head(&mut s2).await;
            s2.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\
                  Connection: close\r\n\r\nhello",
            )
            .await
            .unwrap();
            let _ = s2.shutdown().await;
            req2
        });

        let mut easy = Easy::open();
        easy.set_url(&format!("http://127.0.0.1:{}/start", addr_a.port()))
            .expect("set_url");
        // `-L` / CURLOPT_FOLLOWLOCATION.
        easy.set.follow_location = true;

        let collected = Arc::new(Mutex::new(Vec::new()));
        let sink = Box::new(VecSink(Arc::clone(&collected)));
        // `-u secretuser:secretpass` → Basic credentials on the request template.
        let req = crate::protocols::TransferRequest {
            method: "GET".to_string(),
            user: Some("secretuser".to_string()),
            password: Some("secretpass".to_string()),
            ..Default::default()
        };

        easy.perform_transfer(req, sink)
            .await
            .expect("perform_transfer follows the cross-origin redirect");

        let req1 = srv_a.await.unwrap();
        let req2 = srv_b.await.unwrap();
        let head1 = String::from_utf8_lossy(&req1).to_ascii_lowercase();
        let head2 = String::from_utf8_lossy(&req2).to_ascii_lowercase();

        // Hop 1 (the credential origin) carries the Basic header…
        assert!(
            head1.contains("authorization: basic"),
            "the first request to the credential origin must carry Basic auth; got: {head1}"
        );
        // …but hop 2 (a different origin) must NOT — the credentials are stripped
        // so they never leak to a foreign host.
        assert!(
            !head2.contains("authorization"),
            "credentials must be stripped on the cross-origin redirect; leaked in: {head2}"
        );

        // The handle still lands on the final 200 and counts exactly one redirect.
        assert_eq!(easy.info.httpcode, 200);
        assert_eq!(collected.lock().expect("sink").as_slice(), b"hello");
        assert_eq!(easy.state.followlocation, 1);
    }
}
