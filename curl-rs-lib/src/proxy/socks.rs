// SPDX-License-Identifier: curl
//
//! SOCKS4 / SOCKS4a / SOCKS5 / SOCKS5h client handshake engine.
//!
//! This module is the memory-safe, asynchronous Rust reimplementation of the
//! SOCKS handshakes in libcurl's `lib/socks.c` (`socks4_connect`,
//! `socks5_connect`, and all of their sub-functions). It performs the proxy
//! negotiation over an **already-connected** byte stream and, on success,
//! leaves that stream positioned at the start of the tunnelled payload — exactly
//! where curl's connection-filter chain expects to continue the real transfer.
//!
//! # Wire parity (the C file is a behavioral/ABI oracle, not a transliteration)
//!
//! The SOCKS handshake is **wire-observable** and is exercised unmodified by the
//! curl 8.x regression suite (the `tests/data` SOCKS tests driven through the
//! stunnel/socks test servers). Every byte this engine puts on the wire — the
//! version/command bytes, the big-endian port, the address-type selection, the
//! NUL terminators, and the RFC 1929 username/password layout — is therefore
//! **byte-for-byte identical** to curl 8.x (AAP §0.6 G6, §0.8.2). Likewise the
//! reply parsing (including the SOCKS5 *variable-length* `BND.ADDR` recompute)
//! and the `CURLproxycode` (`CURLPX_*`) result values are reproduced exactly so
//! that `CURLINFO_PROXY_ERROR` round-trips identically.
//!
//! # State machine → linear `async`
//!
//! curl drives a non-blocking `enum socks_state_t` that returns to the
//! `select`/`poll` event loop between every send and receive. That machine is an
//! artifact of curl's hand-rolled I/O loop, not of the protocol. Here it
//! collapses into a single linear `async fn` per SOCKS version: each "send then
//! yield" becomes [`AsyncWriteExt::write_all`](tokio::io::AsyncWriteExt::write_all)
//! `.await`, and each "receive N bytes" becomes
//! [`AsyncReadExt::read_exact`](tokio::io::AsyncReadExt::read_exact) `.await`.
//! The send/receive ordering and byte counts are preserved precisely.
//!
//! # Engine / filter boundary (what is **not** here)
//!
//! This file is the **pure handshake engine** only. The connection-filter
//! wrapper that curl defines at `lib/socks.c` L1198-1415 —
//! `socks_proxy_cf_connect`, `adjust_pollset`, the `free`/`close`/`destroy`
//! callbacks, the `Curl_cft_socks_proxy` vtable, and
//! `Curl_cf_socks_proxy_insert_after` — is **`crate::conn`'s concern** and is
//! intentionally absent. The async runtime makes `adjust_pollset` unnecessary
//! (it collapses into `.await`), and the C teardown callbacks become Rust
//! [`Drop`] on the owning filter. This engine knows nothing about `conn`; it
//! receives a [`SocksParams`] the filter derives from `conn`/`data` and operates
//! on the stream it is handed.
//!
//! # Memory safety
//!
//! The engine performs no raw-pointer or socket work — it reads and writes a
//! generic [`AsyncRead`](tokio::io::AsyncRead) + [`AsyncWrite`](tokio::io::AsyncWrite)
//! stream and parses fixed/length-prefixed byte buffers with `std::net` address
//! types and `to_be_bytes`. There is no FFI here (`inet_pton`/`htons` are
//! replaced by [`std::net`] parsing and big-endian byte conversion), so the
//! module compiles under the module-level `#![forbid(unsafe_code)]` declared
//! below (consistent with the crate-root policy, AAP §0.7.1).
//!
//! # Feature gating
//!
//! The whole module sits under the `proxy` Cargo feature (default ON), curl's
//! `#ifndef CURL_DISABLE_PROXY`; the parent [`crate::proxy`] `mod.rs` declares
//! it `#[cfg(feature = "proxy")]`, so `--no-default-features` drops it cleanly.
//! The optional SOCKS5 GSSAPI path is additionally gated on the `gssapi`
//! feature (curl's `HAVE_GSSAPI` / `USE_KERBEROS5`), which is **off** in the
//! default build — so the default build behaves exactly as a no-GSSAPI curl.

// A module-level `#![forbid(unsafe_code)]` reinforces the crate-root memory-
// safety policy (AAP §0.7.1, §0.8.1): this engine is provably free of raw
// pointers and `unsafe`, so the strongest lint is appropriate and idempotent
// with the crate root.
#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::auth::{CURLAUTH_BASIC, CURLAUTH_GSSAPI};
use crate::dns::{resolve, DnsCache, IpVersion, ResolveParams};
use crate::error::{codes, CurlCode};
use crate::util::sendf;

// `CurlProxyType` lives in the sibling `mod.rs` (the parent of this module),
// mirroring curl's `curl_proxytype` enum with the exact `CURLPROXY_*` integer
// values. The handshake dispatches on it to pick the SOCKS version and the
// local-vs-remote resolution mode.
use super::CurlProxyType;

// ===========================================================================
// CURLproxycode (`CURLPX_*`) — the SOCKS handshake result codes.
// ===========================================================================

/// SOCKS proxy result code — the Rust analog of curl's `CURLproxycode`
/// (`include/curl/curl.h`), surfaced to C consumers via `CURLINFO_PROXY_ERROR`.
///
/// # ABI contract (do not change the integer values)
///
/// `crate::error` deliberately does **not** define the proxy codes (they are a
/// separate enum from `CURLcode`), so they are defined here. The discriminants
/// reproduce curl's `CURLproxycode` **exactly**: `CURLPX_OK = 0` followed by the
/// remaining names in alphabetical order, each `+1` (verified against
/// `include/curl/curl.h` L743-778). An off-by-one would break
/// `CURLINFO_PROXY_ERROR` ABI parity, so the values are explicit and pinned by a
/// unit test below.
///
/// [`CurlProxyCode::Last`] is curl's `CURLPX_LAST` sentinel — it is never
/// returned by the engine and exists only to mirror the C enum's tail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CurlProxyCode {
    /// `CURLPX_OK` (0) — handshake succeeded.
    Ok = 0,
    /// `CURLPX_BAD_ADDRESS_TYPE` (1) — an address type could not be encoded
    /// (e.g. a malformed IPv6 literal) or the SOCKS5 reply carried an unknown
    /// `ATYP`.
    BadAddressType = 1,
    /// `CURLPX_BAD_VERSION` (2) — the proxy reply carried the wrong version
    /// byte.
    BadVersion = 2,
    /// `CURLPX_CLOSED` (3) — the proxy connection was closed (filter-level).
    Closed = 3,
    /// `CURLPX_GSSAPI` (4) — GSS-API context negotiation failed.
    Gssapi = 4,
    /// `CURLPX_GSSAPI_PERMSG` (5) — GSS-API per-message authentication was
    /// selected but is not available/enabled.
    GssapiPermsg = 5,
    /// `CURLPX_GSSAPI_PROTECTION` (6) — GSS-API message protection was requested
    /// but is not supported.
    GssapiProtection = 6,
    /// `CURLPX_IDENTD` (7) — SOCKS4: the server could not reach `identd` on the
    /// client.
    Identd = 7,
    /// `CURLPX_IDENTD_DIFFER` (8) — SOCKS4: client program and `identd` reported
    /// different user IDs.
    IdentdDiffer = 8,
    /// `CURLPX_LONG_HOSTNAME` (9) — the destination hostname exceeds 255 bytes.
    LongHostname = 9,
    /// `CURLPX_LONG_PASSWD` (10) — the proxy password exceeds 255 bytes.
    LongPasswd = 10,
    /// `CURLPX_LONG_USER` (11) — the proxy username exceeds 255 bytes.
    LongUser = 11,
    /// `CURLPX_NO_AUTH` (12) — no acceptable authentication method.
    NoAuth = 12,
    /// `CURLPX_RECV_ADDRESS` (13) — failed to receive the bound address.
    RecvAddress = 13,
    /// `CURLPX_RECV_AUTH` (14) — failed to receive the auth response.
    RecvAuth = 14,
    /// `CURLPX_RECV_CONNECT` (15) — failed to receive the connect response (or
    /// the proxy closed the connection mid-handshake).
    RecvConnect = 15,
    /// `CURLPX_RECV_REQACK` (16) — failed to receive the request acknowledgement.
    RecvReqack = 16,
    /// `CURLPX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED` (17) — SOCKS5 `REP = 8`.
    ReplyAddressTypeNotSupported = 17,
    /// `CURLPX_REPLY_COMMAND_NOT_SUPPORTED` (18) — SOCKS5 `REP = 7`.
    ReplyCommandNotSupported = 18,
    /// `CURLPX_REPLY_CONNECTION_REFUSED` (19) — SOCKS5 `REP = 5`.
    ReplyConnectionRefused = 19,
    /// `CURLPX_REPLY_GENERAL_SERVER_FAILURE` (20) — SOCKS5 `REP = 1`.
    ReplyGeneralServerFailure = 20,
    /// `CURLPX_REPLY_HOST_UNREACHABLE` (21) — SOCKS5 `REP = 4`.
    ReplyHostUnreachable = 21,
    /// `CURLPX_REPLY_NETWORK_UNREACHABLE` (22) — SOCKS5 `REP = 3`.
    ReplyNetworkUnreachable = 22,
    /// `CURLPX_REPLY_NOT_ALLOWED` (23) — SOCKS5 `REP = 2`.
    ReplyNotAllowed = 23,
    /// `CURLPX_REPLY_TTL_EXPIRED` (24) — SOCKS5 `REP = 6`.
    ReplyTtlExpired = 24,
    /// `CURLPX_REPLY_UNASSIGNED` (25) — SOCKS5 `REP >= 9` (unassigned).
    ReplyUnassigned = 25,
    /// `CURLPX_REQUEST_FAILED` (26) — SOCKS4 request rejected/failed (`CD 91`).
    RequestFailed = 26,
    /// `CURLPX_RESOLVE_HOST` (27) — local resolution of the destination failed.
    ResolveHost = 27,
    /// `CURLPX_SEND_AUTH` (28) — failed to send the auth request.
    SendAuth = 28,
    /// `CURLPX_SEND_CONNECT` (29) — failed to send the connect request.
    SendConnect = 29,
    /// `CURLPX_SEND_REQUEST` (30) — failed to assemble/send the request.
    SendRequest = 30,
    /// `CURLPX_UNKNOWN_FAIL` (31) — an unknown failure.
    UnknownFail = 31,
    /// `CURLPX_UNKNOWN_MODE` (32) — the server selected an unknown SOCKS5 mode.
    UnknownMode = 32,
    /// `CURLPX_USER_REJECTED` (33) — the SOCKS5 server rejected the credentials.
    UserRejected = 33,
    /// `CURLPX_LAST` (34) — sentinel; never returned.
    Last = 34,
}

impl CurlProxyCode {
    /// Returns the raw `CURLproxycode` integer for this code, the value stored
    /// in `data->info.pxcode` and read back through `CURLINFO_PROXY_ERROR`.
    #[must_use]
    pub const fn as_raw(self) -> i32 {
        self as i32
    }
}

/// Returns the human-readable message for a [`CurlProxyCode`], mirroring curl's
/// `Curl_proxy_strerror` table in `lib/strerror.c`.
///
/// These are the exact strings curl reports for a SOCKS failure; the engine's
/// own `failf` diagnostics (which include runtime context such as the offending
/// IP/port) are emitted separately at each failure site, but this table is the
/// canonical fallback message per code.
#[must_use]
pub fn proxy_strerror(code: CurlProxyCode) -> &'static str {
    use CurlProxyCode::*;
    match code {
        Ok => "No error",
        BadAddressType => "Bad address type",
        BadVersion => "Bad version",
        Closed => "Closed",
        Gssapi => "GSSAPI error",
        GssapiPermsg => "Permission denied (GSSAPI)",
        GssapiProtection => "Message protection (GSSAPI)",
        Identd => "Failure to connect to identd on client",
        IdentdDiffer => "Different user identifier reported by identd",
        LongHostname => "Too long hostname",
        LongPasswd => "Too long password",
        LongUser => "Too long username",
        NoAuth => "No authentication method was acceptable",
        RecvAddress => "Failure receiving address",
        RecvAuth => "Failure receiving authentication",
        RecvConnect => "Failure receiving connect request acknowledgement",
        RecvReqack => "Failure receiving request acknowledgement",
        ReplyAddressTypeNotSupported => "Address type not supported",
        ReplyCommandNotSupported => "Command not supported",
        ReplyConnectionRefused => "Connection refused",
        ReplyGeneralServerFailure => "General SOCKS server failure",
        ReplyHostUnreachable => "Host unreachable",
        ReplyNetworkUnreachable => "Network unreachable",
        ReplyNotAllowed => "Connection not allowed by ruleset",
        ReplyTtlExpired => "TTL expired",
        ReplyUnassigned => "Unassigned error code",
        RequestFailed => "Request rejected or failed",
        ResolveHost => "Failed to resolve hostname",
        SendAuth => "Failure sending authentication",
        SendConnect => "Failure sending connect request",
        SendRequest => "Failure sending request",
        UnknownFail => "Unknown error",
        UnknownMode => "Unknown mode",
        UserRejected => "User rejected by SOCKS server",
        Last => "Unknown error",
    }
}

/// Converts a [`CurlProxyCode`] to the `(CURLcode, CURLproxycode)` pair the
/// connection filter records at the engine/filter boundary, mirroring curl's
/// `socks_proxy_cf_connect` mapping (`lib/socks.c` L1279-1283).
///
/// In curl, a successful handshake (`CURLPX_OK`) yields `CURLE_OK`; any other
/// proxy code is stored into `data->info.pxcode` (for `CURLINFO_PROXY_ERROR`)
/// and the connect returns the generic [`CURLE_PROXY`](codes::CURLE_PROXY). This
/// helper returns **both** values so the `crate::conn` filter can set the easy
/// handle's `pxcode` *and* return the right `CURLcode` in one step:
///
/// * [`CurlProxyCode::Ok`] ⇒ `(CURLE_OK, CURLPX_OK)`.
/// * any other `px` ⇒ `(CURLE_PROXY, px)`.
#[must_use]
pub fn to_curlcode(px: CurlProxyCode) -> (CurlCode, CurlProxyCode) {
    match px {
        CurlProxyCode::Ok => (codes::CURLE_OK, CurlProxyCode::Ok),
        other => (codes::CURLE_PROXY, other),
    }
}

// ===========================================================================
// SocksParams — the inputs the connection filter derives from `conn`/`data`.
// ===========================================================================

/// The inputs the SOCKS handshake needs, all derived by the `crate::conn`
/// connection filter from `conn`/`data` before it calls [`socks_handshake`].
///
/// This struct is the explicit, `conn`-free contract between the filter and the
/// engine: the engine has no knowledge of `connectdata`/`Curl_easy`, so every
/// value curl's `socks_proxy_cf_connect` reads off those structures is captured
/// here. The derivation rules (so the filter author reproduces curl exactly) are
/// documented per field.
#[derive(Clone, Debug)]
pub struct SocksParams {
    /// The **target** host to reach *through* the proxy (curl `sx->hostname`).
    ///
    /// Filter derivation (curl `socks_proxy_cf_connect`): `http_proxy.host.name`
    /// if this hop is also an HTTP proxy; else `conn_to_host.name` if a
    /// "connect-to" is set; else `secondaryhostname` when the socket is the
    /// `SECONDARYSOCKET` (FTP data channel); else `host.name`.
    pub hostname: String,

    /// The **target** port reached through the proxy (curl `sx->remote_port`).
    ///
    /// Filter derivation: `http_proxy.port` if HTTP-proxying; else
    /// `secondary_port` for the `SECONDARYSOCKET`; else `conn_to_port` if set;
    /// else `remote_port`.
    pub remote_port: u16,

    /// The proxy username (curl `conn->socks_proxy.user`), if any. Used by
    /// SOCKS4/4a (the `USERID` field) and by SOCKS5 username/password
    /// subnegotiation / method advertisement.
    pub proxy_user: Option<String>,

    /// The proxy password (curl `conn->socks_proxy.passwd`), if any. Used only
    /// by SOCKS5 username/password subnegotiation.
    pub proxy_password: Option<String>,

    /// The proxy type (curl `conn->socks_proxy.proxytype`). Only the four SOCKS
    /// variants are valid here; the dispatcher branches on this to choose the
    /// SOCKS4 vs SOCKS5 path and the local-vs-remote resolution mode.
    pub proxytype: CurlProxyType,

    /// The `CURLOPT_SOCKS5_AUTH` bitmask (curl `data->set.socks5auth`); default
    /// `CURLAUTH_BASIC | CURLAUTH_GSSAPI`. Gates which SOCKS5 authentication
    /// methods are advertised in the greeting.
    pub socks5_auth: u32,

    /// `CURLOPT_IPRESOLVE` (curl `data->set.ipver` / `conn->ip_version`) — the
    /// address-family preference applied during **local** SOCKS5 resolution.
    /// SOCKS4 ignores this and forces IPv4 (curl sets
    /// `conn->ip_version = CURL_IPRESOLVE_V4`).
    pub ip_version: IpVersion,

    /// Whether the target `hostname` was flagged as an IPv6 IP literal (curl
    /// `conn->bits.ipv6_ip`). Consulted only by the SOCKS5h (remote-DNS) request
    /// builder to choose `ATYP = 4` for an IPv6 literal; a parse failure under
    /// this flag yields [`CurlProxyCode::BadAddressType`], mirroring curl's
    /// `inet_pton(AF_INET6, …) != 1` branch.
    pub ipv6_ip: bool,

    /// `CURLOPT_VERBOSE` (curl `data->set.verbose`) — gates the informational
    /// (`infof`) handshake diagnostics. Error (`failf`) messages are emitted
    /// regardless.
    pub verbose: bool,
}

impl SocksParams {
    /// Builds parameters for `hostname:remote_port` through a `proxytype` proxy
    /// with curl's defaults for everything else: no credentials, the default
    /// `CURLOPT_SOCKS5_AUTH` mask ([`CURLAUTH_BASIC`] `|` [`CURLAUTH_GSSAPI`]),
    /// any IP family, not an IPv6 literal, and non-verbose. Adjust the public
    /// fields as needed before calling [`socks_handshake`].
    #[must_use]
    pub fn new(hostname: impl Into<String>, remote_port: u16, proxytype: CurlProxyType) -> Self {
        SocksParams {
            hostname: hostname.into(),
            remote_port,
            proxy_user: None,
            proxy_password: None,
            proxytype,
            socks5_auth: CURLAUTH_BASIC | CURLAUTH_GSSAPI,
            ip_version: IpVersion::Any,
            ipv6_ip: false,
            verbose: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal staging-buffer sizing (curl `SOCKS_CHUNK_SIZE` / `SOCKS_CHUNKS`).
// ---------------------------------------------------------------------------
//
// curl stages handshake bytes in a `struct bufq iobuf` initialized with
// `Curl_bufq_init2(SOCKS_CHUNK_SIZE = 1024, SOCKS_CHUNKS = 1, ...)`. In the
// async port a plain `Vec<u8>` request buffer plays the same role; we keep
// curl's chunk size as the initial capacity so the common single-packet request
// never reallocates, matching curl's single-chunk staging.
const SOCKS_CHUNK_SIZE: usize = 1024;

// ===========================================================================
// Public entry point — the handshake dispatcher.
// ===========================================================================

/// Performs a complete SOCKS handshake over an already-connected `stream`,
/// returning `Ok(())` once the proxy has established the tunnel to the target.
///
/// This is the public entry the `crate::conn` SOCKS filter calls after its
/// transport below has connected to the proxy. It dispatches on
/// [`SocksParams::proxytype`] to the SOCKS4/4a or SOCKS5/5h handshake and runs
/// it to completion; on success the `stream` is left at the first byte of the
/// tunnelled payload.
///
/// # Parameters
///
/// * `stream` — the connected byte stream to the proxy (any
///   [`AsyncRead`](tokio::io::AsyncRead) + [`AsyncWrite`](tokio::io::AsyncWrite)).
///   The engine never opens sockets itself.
/// * `params` — the [`SocksParams`] the filter derived from `conn`/`data`.
/// * `cache` — the shared DNS cache (curl's host cache) used for **local**
///   resolution in the SOCKS4 / SOCKS5 paths. IP-literal targets short-circuit
///   without a network query, so a fresh [`DnsCache`] is sufficient for those.
/// * `error_buffer` — the easy handle's `CURLOPT_ERRORBUFFER` slot; failure
///   diagnostics are recorded here (first-write-wins) exactly as curl's `failf`
///   does inside `lib/socks.c`.
///
/// # Errors
///
/// Returns the [`CurlProxyCode`] (`CURLPX_*`) of the first failed step, matching
/// curl byte-for-byte. The `crate::conn` filter converts it via [`to_curlcode`]
/// (storing `CURLINFO_PROXY_ERROR` and returning [`CURLE_PROXY`](codes::CURLE_PROXY)).
///
/// # Boundary note
///
/// The signature extends the minimal `(stream, params)` shape with `cache` and
/// `error_buffer` because the engine subsumes curl's `socks4_resolving` /
/// `socks5_resolving` (which need the host cache) and its `failf` sites (which
/// write the error buffer); `verbose` lives in [`SocksParams`]. This keeps all
/// handshake behavior — including resolution and diagnostics — inside the engine
/// while the filter retains only `conn` plumbing.
pub async fn socks_handshake<S>(
    stream: &mut S,
    params: &SocksParams,
    cache: &mut DnsCache,
    error_buffer: &mut Option<String>,
) -> Result<(), CurlProxyCode>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match params.proxytype {
        CurlProxyType::Socks4 | CurlProxyType::Socks4a => {
            socks4_connect(stream, params, cache, error_buffer).await
        }
        CurlProxyType::Socks5 | CurlProxyType::Socks5Hostname => {
            socks5_connect(stream, params, cache, error_buffer).await
        }
        // The filter performs the proxytype switch and only routes SOCKS hops
        // here; a non-SOCKS type is a filter bug. curl's analogous default arm
        // (`socks_proxy_cf_connect`) fails the connect — we surface an unknown
        // failure defensively rather than panic.
        _ => {
            sendf::failf(error_buffer, "unknown proxytype option given");
            Err(CurlProxyCode::UnknownFail)
        }
    }
}

// ===========================================================================
// Low-level I/O helpers — the async collapse of curl's socks_flush/socks_recv.
// ===========================================================================

/// Sends the entire `bytes` buffer to the proxy, the async collapse of curl's
/// `socks_flush` (which loops until `iobuf` drains).
///
/// Maps any write error to [`CurlProxyCode::SendConnect`], matching curl's
/// `socks_flush` returning `CURLPX_SEND_CONNECT` on a send failure.
async fn socks_send<S>(stream: &mut S, bytes: &[u8]) -> Result<(), CurlProxyCode>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(bytes)
        .await
        .map_err(|_| CurlProxyCode::SendConnect)
}

/// Receives **exactly** `buf.len()` bytes from the proxy into `buf`, the async
/// collapse of curl's `socks_recv(min_bytes)`.
///
/// curl's `socks_recv` reads into `iobuf` until at least `min_bytes` are
/// buffered; an I/O error or a premature EOF ("proxy closed connection") both
/// yield `CURLPX_RECV_CONNECT`. [`AsyncReadExt::read_exact`](tokio::io::AsyncReadExt::read_exact)
/// reproduces this precisely: it returns
/// [`UnexpectedEof`](std::io::ErrorKind::UnexpectedEof) when the stream ends
/// before `buf` is filled, which — like any other read error — we map to
/// [`CurlProxyCode::RecvConnect`].
async fn socks_recv<S>(stream: &mut S, buf: &mut [u8]) -> Result<(), CurlProxyCode>
where
    S: AsyncRead + Unpin,
{
    stream
        .read_exact(buf)
        .await
        .map(|_| ())
        .map_err(|_| CurlProxyCode::RecvConnect)
}

// ===========================================================================
// SOCKS4 / SOCKS4a — `socks4_connect` and helpers.
// ===========================================================================
//
// Request layout (curl `socks4_connect`):
//
//   +----+----+----+----+----+----+----+----+----+----+....+----+
//   | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
//   +----+----+----+----+----+----+----+----+----+----+....+----+
//   # bytes  1    1      2              4         variable     1
//
//   * SOCKS4  (local resolve): DSTIP = the resolved IPv4 address.
//   * SOCKS4a (remote resolve): DSTIP = 0.0.0.1, and the destination hostname
//     (NUL-terminated) is appended after USERID+NUL.

/// Appends the SOCKS4 `USERID` field plus its trailing NUL to `req`, mirroring
/// curl's `socks4_req_add_user`.
///
/// * Present username → the username bytes followed by a single NUL (curl's
///   `Curl_bufq_cwrite(user, plen + 1)` writes the C-string including its NUL).
///   A username longer than 255 bytes is [`CurlProxyCode::LongUser`].
/// * Absent (or empty) username → just the single terminating NUL (curl's
///   "empty username" branch).
fn socks4_append_user(
    req: &mut Vec<u8>,
    proxy_user: Option<&str>,
    error_buffer: &mut Option<String>,
) -> Result<(), CurlProxyCode> {
    match proxy_user {
        Some(user) => {
            // There is no hard size limit in the protocol, but curl rejects an
            // over-long username (>255) as either a mistake or malicious input.
            if user.len() > 255 {
                sendf::failf(error_buffer, "Too long SOCKS proxy username");
                return Err(CurlProxyCode::LongUser);
            }
            req.extend_from_slice(user.as_bytes());
            req.push(0); // trailing NUL (an empty user collapses to just this)
        }
        None => req.push(0), // empty username → lone NUL
    }
    Ok(())
}

/// Drives the SOCKS4 / SOCKS4a handshake to completion — curl's
/// `socks4_connect` collapsed to linear `.await`s.
async fn socks4_connect<S>(
    stream: &mut S,
    params: &SocksParams,
    cache: &mut DnsCache,
    error_buffer: &mut Option<String>,
) -> Result<(), CurlProxyCode>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // SOCKS4a sends the hostname for the proxy to resolve; plain SOCKS4 resolves
    // locally. (curl: `socks4a = (proxytype == CURLPROXY_SOCKS4A)`,
    // `resolve_local = !socks4a`.)
    let socks4a = params.proxytype == CurlProxyType::Socks4a;
    let resolve_local = !socks4a;

    sendf::infof(
        params.verbose,
        &format!(
            "SOCKS4{} communication to {}:{}",
            if socks4a { "a" } else { "" },
            params.hostname,
            params.remote_port
        ),
    );

    // ---- Request header: VN=4, CD=1 (CONNECT), DSTPORT big-endian. ----------
    let mut req: Vec<u8> = Vec::with_capacity(SOCKS_CHUNK_SIZE);
    req.push(0x04); // VN: SOCKS version 4
    req.push(0x01); // CD: CONNECT
    req.extend_from_slice(&params.remote_port.to_be_bytes()); // DSTPORT MSB,LSB

    if !resolve_local {
        // ---- SOCKS4a: fake DSTIP 0.0.0.1, then USERID+NUL, then host+NUL. ---
        // curl validates the hostname length *before* writing the fake IP, so
        // `CURLPX_LONG_HOSTNAME` is reported ahead of any `CURLPX_LONG_USER`.
        let hlen = params.hostname.len() + 1; // including the trailing NUL
        if hlen > 255 {
            sendf::failf(error_buffer, "SOCKS4: too long hostname");
            return Err(CurlProxyCode::LongHostname);
        }
        req.extend_from_slice(&[0, 0, 0, 1]); // DSTIP signalling SOCKS4a
        socks4_append_user(&mut req, params.proxy_user.as_deref(), error_buffer)?;
        // Destination hostname WITH trailing NUL (curl `cwrite(host, hlen)`).
        req.extend_from_slice(params.hostname.as_bytes());
        req.push(0);
    } else {
        // ---- SOCKS4: resolve locally to an IPv4 DSTIP, then USERID+NUL. ------
        // curl forces IPv4 for SOCKS4 (`conn->ip_version = CURL_IPRESOLVE_V4`).
        let mut rp = ResolveParams::new(&params.hostname, params.remote_port);
        rp.ip_version = IpVersion::V4;
        rp.verbose = params.verbose;

        let entry = match resolve(cache, &rp, error_buffer).await {
            Ok(entry) => entry,
            Err(_) => {
                sendf::failf(
                    error_buffer,
                    &format!(
                        "Failed to resolve \"{}\" for SOCKS4 connect.",
                        params.hostname
                    ),
                );
                return Err(CurlProxyCode::ResolveHost);
            }
        };

        // Scan for the first IPv4 address (curl walks `dns->addr` for AF_INET).
        let v4 = entry.addrs.iter().find_map(|addr| match addr {
            SocketAddr::V4(s) => Some(*s.ip()),
            SocketAddr::V6(_) => None,
        });
        match v4 {
            Some(ip) => {
                sendf::infof(
                    params.verbose,
                    &format!("SOCKS4 connect to IPv4 {ip} (locally resolved)"),
                );
                // `Ipv4Addr::octets()` is network byte order, matching curl
                // writing `sin_addr.s_addr` directly.
                req.extend_from_slice(&ip.octets());
            }
            None => {
                sendf::failf(
                    error_buffer,
                    &format!("SOCKS4 connection to {} not supported", params.hostname),
                );
                return Err(CurlProxyCode::ResolveHost);
            }
        }
        socks4_append_user(&mut req, params.proxy_user.as_deref(), error_buffer)?;
    }

    // ---- Send the assembled request. ----------------------------------------
    socks_send(stream, &req).await?;

    // ---- Receive and validate the fixed 8-byte response. --------------------
    let mut resp = [0u8; 8];
    socks_recv(stream, &mut resp).await?;
    socks4_check_resp(&resp, socks4a, params.verbose, error_buffer)
}

/// Parses the fixed 8-byte SOCKS4 reply `[VN][CD][DSTPORT(2)][DSTIP(4)]`,
/// mirroring curl's `socks4_check_resp`.
///
/// `VN` must be 0; `CD` is the result code (90 grant, 91/92/93 the documented
/// rejections, anything else unknown). The failure `failf` messages reproduce
/// curl's exact text, including the echoed `DSTIP:DSTPORT` and `CD` value.
fn socks4_check_resp(
    resp: &[u8; 8],
    socks4a: bool,
    verbose: bool,
    error_buffer: &mut Option<String>,
) -> Result<(), CurlProxyCode> {
    // VN (reply version) must be 0.
    if resp[0] != 0 {
        sendf::failf(
            error_buffer,
            "SOCKS4 reply has wrong version, version should be 0.",
        );
        return Err(CurlProxyCode::BadVersion);
    }

    // The echoed destination, used verbatim in curl's rejection messages.
    let dport = (u16::from(resp[2]) << 8) | u16::from(resp[3]);
    let (a, b, c, d) = (resp[4], resp[5], resp[6], resp[7]);
    let cd = resp[1];

    match cd {
        90 => {
            // Request granted.
            sendf::infof(
                verbose,
                &format!("SOCKS4{} request granted.", if socks4a { "a" } else { "" }),
            );
            Ok(())
        }
        91 => {
            sendf::failf(
                error_buffer,
                &format!(
                    "[SOCKS] cannot complete SOCKS4 connection to {a}.{b}.{c}.{d}:{dport}. ({cd})\
                    , request rejected or failed."
                ),
            );
            Err(CurlProxyCode::RequestFailed)
        }
        92 => {
            sendf::failf(
                error_buffer,
                &format!(
                    "[SOCKS] cannot complete SOCKS4 connection to {a}.{b}.{c}.{d}:{dport}. ({cd})\
                    , request rejected because SOCKS server cannot connect to identd on the client."
                ),
            );
            Err(CurlProxyCode::Identd)
        }
        93 => {
            sendf::failf(
                error_buffer,
                &format!(
                    "[SOCKS] cannot complete SOCKS4 connection to {a}.{b}.{c}.{d}:{dport}. ({cd})\
                    , request rejected because the client program and identd report different \
                    user-ids."
                ),
            );
            Err(CurlProxyCode::IdentdDiffer)
        }
        _ => {
            sendf::failf(
                error_buffer,
                &format!(
                    "[SOCKS] cannot complete SOCKS4 connection to {a}.{b}.{c}.{d}:{dport}. ({cd})\
                    , Unknown."
                ),
            );
            Err(CurlProxyCode::UnknownFail)
        }
    }
}

// ===========================================================================
// SOCKS5 / SOCKS5h — `socks5_connect` and helpers.
// ===========================================================================

/// SOCKS5 `REP` (reply) value → [`CurlProxyCode`] mapping for `REP` in `1..=8`,
/// per RFC 1928 §6 (curl's `lookup[]` in `socks5_recv_resp1`). Index 0 is unused
/// (a `REP` of 0 is success and never looked up here). Any `REP >= 9` maps to
/// [`CurlProxyCode::ReplyUnassigned`].
const SOCKS5_REP_LOOKUP: [CurlProxyCode; 9] = [
    CurlProxyCode::Ok,                           // 0 — success (unused here)
    CurlProxyCode::ReplyGeneralServerFailure,    // 1
    CurlProxyCode::ReplyNotAllowed,              // 2
    CurlProxyCode::ReplyNetworkUnreachable,      // 3
    CurlProxyCode::ReplyHostUnreachable,         // 4
    CurlProxyCode::ReplyConnectionRefused,       // 5
    CurlProxyCode::ReplyTtlExpired,              // 6
    CurlProxyCode::ReplyCommandNotSupported,     // 7
    CurlProxyCode::ReplyAddressTypeNotSupported, // 8
];

/// Runs the SOCKS5 RFC 1929 username/password subnegotiation — curl's
/// `socks5_auth_init` + `socks5_check_auth_resp` collapsed to linear `.await`s.
///
/// Request layout (RFC 1929):
///
/// ```text
/// +----+------+----------+------+----------+
/// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
/// +----+------+----------+------+----------+
/// | 1  |  1   | 0 to 255 |  1   | 0 to 255 |
/// +----+------+----------+------+----------+
/// ```
///
/// **Subtle parity point:** curl only populates `ULEN`/`UNAME`/`PLEN`/`PASSWD`
/// when **both** the username and password are present (`if(proxy_user &&
/// proxy_password)`); if either is missing both lengths are sent as `0`. This
/// reproduces that exactly.
async fn socks5_userpass_auth<S>(
    stream: &mut S,
    proxy_user: Option<&str>,
    proxy_password: Option<&str>,
    error_buffer: &mut Option<String>,
) -> Result<(), CurlProxyCode>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut ulen = 0usize;
    let mut plen = 0usize;
    // Lengths are only taken when BOTH credentials are present (curl's guard).
    if let (Some(user), Some(pass)) = (proxy_user, proxy_password) {
        ulen = user.len();
        plen = pass.len();
        // The lengths must each fit in a single byte.
        if ulen > 255 {
            sendf::failf(error_buffer, "Excessive username length for proxy auth");
            return Err(CurlProxyCode::LongUser);
        }
        if plen > 255 {
            sendf::failf(error_buffer, "Excessive password length for proxy auth");
            return Err(CurlProxyCode::LongPasswd);
        }
    }

    // VER, ULEN, UNAME, PLEN, PASSWD — in that exact order.
    let mut buf: Vec<u8> = Vec::with_capacity(3 + ulen + plen);
    buf.push(0x01); // username/password subnegotiation version
    buf.push(ulen as u8);
    if ulen > 0 {
        // `ulen > 0` implies both credentials were present.
        buf.extend_from_slice(proxy_user.unwrap_or_default().as_bytes());
    }
    buf.push(plen as u8);
    if plen > 0 {
        buf.extend_from_slice(proxy_password.unwrap_or_default().as_bytes());
    }
    socks_send(stream, &buf).await?;

    // Reply: [VER][STATUS]; a non-zero STATUS means the credentials were
    // rejected. curl ignores VER and reports both bytes in the message.
    let mut resp = [0u8; 2];
    socks_recv(stream, &mut resp).await?;
    if resp[1] != 0 {
        sendf::failf(
            error_buffer,
            &format!(
                "User was rejected by the SOCKS5 server ({} {}).",
                resp[0], resp[1]
            ),
        );
        return Err(CurlProxyCode::UserRejected);
    }
    Ok(())
}

/// Stub SOCKS5 GSS-API negotiation — only compiled under the `gssapi` feature
/// (curl's `HAVE_GSSAPI` / `USE_KERBEROS5`), which is **off** in the default
/// build.
///
/// curl performs the full GSS-API context exchange in `Curl_SOCKS5_gssapi_negotiate`
/// (`lib/socks_gssapi.c` / `socks_sspi.c`); those bodies are REFERENCE-ONLY and
/// are deliberately **not** ported. This stub builds the service principal name
/// the way curl does (so the integration point exists) and then fails the
/// negotiation with [`CurlProxyCode::Gssapi`] and curl's exact message — i.e.
/// the default build behaves as if GSS-API is unavailable, which is the
/// supported configuration.
#[cfg(feature = "gssapi")]
async fn socks5_gssapi_negotiate<S>(
    _stream: &mut S,
    params: &SocksParams,
    error_buffer: &mut Option<String>,
) -> Result<(), CurlProxyCode>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // curl builds the SPN as the "rcmd" service for the proxy host. `build_spn`
    // is the shared helper in `crate::auth`; the full exchange is unimplemented.
    let _spn = crate::auth::build_spn("rcmd", Some(&params.hostname), None);
    sendf::failf(error_buffer, "Unable to negotiate SOCKS5 GSS-API context.");
    Err(CurlProxyCode::Gssapi)
}

/// Drives the SOCKS5 / SOCKS5h handshake to completion — curl's
/// `socks5_connect` collapsed to linear `.await`s.
async fn socks5_connect<S>(
    stream: &mut S,
    params: &SocksParams,
    cache: &mut DnsCache,
    error_buffer: &mut Option<String>,
) -> Result<(), CurlProxyCode>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // SOCKS5 resolves locally; SOCKS5h ("hostname") sends the hostname for the
    // proxy to resolve. (curl: `resolve_local = (proxytype == CURLPROXY_SOCKS5)`.)
    let resolve_local = params.proxytype == CurlProxyType::Socks5;

    let auth = params.socks5_auth;

    // ---- Phase 0: build & send the method greeting (socks5_req0_init). -------
    //
    // For SOCKS5h the hostname is sent to the proxy, so an over-long name is
    // rejected up front (RFC 1928 caps the domain at 255 bytes).
    if !resolve_local && params.hostname.len() > 255 {
        sendf::failf(
            error_buffer,
            "SOCKS5: the destination hostname is too long to be resolved remotely by the proxy.",
        );
        return Err(CurlProxyCode::LongHostname);
    }

    // Warn (verbose only) about auth bits curl's SOCKS5 path does not support.
    if auth & !(CURLAUTH_BASIC | CURLAUTH_GSSAPI) != 0 {
        sendf::infof(
            params.verbose,
            &format!("warning: unsupported value passed to CURLOPT_SOCKS5_AUTH: {auth}"),
        );
    }

    // Without BASIC enabled, username/password auth is disabled — drop the user
    // so neither the method-2 advertisement nor the subnegotiation is attempted.
    let effective_user: Option<&str> = if auth & CURLAUTH_BASIC != 0 {
        params.proxy_user.as_deref()
    } else {
        None
    };

    // Greeting: VER, NMETHODS, METHODS…
    //   * 0x00 (NO AUTH)            — always offered.
    //   * 0x01 (GSSAPI)            — only if compiled in AND requested.
    //   * 0x02 (USERNAME/PASSWORD) — only if a username is available.
    let mut methods: Vec<u8> = Vec::with_capacity(3);
    methods.push(0x00); // NO AUTH is always advertised
    #[cfg(feature = "gssapi")]
    {
        if auth & CURLAUTH_GSSAPI != 0 {
            methods.push(0x01);
        }
    }
    if effective_user.is_some() {
        methods.push(0x02);
    }

    let mut greeting: Vec<u8> = Vec::with_capacity(2 + methods.len());
    greeting.push(0x05); // VER = SOCKS5
    greeting.push(methods.len() as u8); // NMETHODS
    greeting.extend_from_slice(&methods);
    socks_send(stream, &greeting).await?;

    // ---- Phase 0 reply: [VER][METHOD] (socks5_check_resp0). -----------------
    let mut resp0 = [0u8; 2];
    socks_recv(stream, &mut resp0).await?;
    if resp0[0] != 5 {
        sendf::failf(
            error_buffer,
            "Received invalid version in initial SOCKS5 response.",
        );
        return Err(CurlProxyCode::BadVersion);
    }

    match resp0[1] {
        0x00 => {
            // No authentication needed — proceed straight to the CONNECT request.
        }
        0x01 => {
            // GSS-API selected.
            if auth & CURLAUTH_GSSAPI != 0 {
                #[cfg(feature = "gssapi")]
                {
                    socks5_gssapi_negotiate(stream, params, error_buffer).await?;
                }
                #[cfg(not(feature = "gssapi"))]
                {
                    sendf::failf(
                        error_buffer,
                        "SOCKS5 GSSAPI per-message authentication is not supported.",
                    );
                    return Err(CurlProxyCode::GssapiPermsg);
                }
            } else {
                sendf::failf(
                    error_buffer,
                    "SOCKS5 GSSAPI per-message authentication is not enabled.",
                );
                return Err(CurlProxyCode::GssapiPermsg);
            }
        }
        0x02 => {
            // Username/password authentication selected.
            if auth & CURLAUTH_BASIC != 0 {
                socks5_userpass_auth(
                    stream,
                    effective_user,
                    params.proxy_password.as_deref(),
                    error_buffer,
                )
                .await?;
            } else {
                sendf::failf(
                    error_buffer,
                    "BASIC authentication proposed but not enabled.",
                );
                return Err(CurlProxyCode::NoAuth);
            }
        }
        0xFF => {
            sendf::failf(error_buffer, "No authentication method was acceptable.");
            return Err(CurlProxyCode::NoAuth);
        }
        _ => {
            sendf::failf(
                error_buffer,
                "Unknown SOCKS5 mode attempted to be used by server.",
            );
            return Err(CurlProxyCode::UnknownMode);
        }
    }

    // ---- CONNECT request: VER, CMD=CONNECT, RSV, ATYP, ADDR, PORT. ----------
    // (curl `socks5_req1_init` for the header + 5h address, `socks5_resolving`
    //  for the locally-resolved address; the final byte stream is identical and
    //  is sent in a single flush either way.)
    let mut req: Vec<u8> = Vec::with_capacity(SOCKS_CHUNK_SIZE);
    req.push(0x05); // VER
    req.push(0x01); // CMD = CONNECT
    req.push(0x00); // RSV (must be zero)

    if resolve_local {
        // Local resolution honouring the IP-family preference.
        let mut rp = ResolveParams::new(&params.hostname, params.remote_port);
        rp.ip_version = params.ip_version;
        rp.verbose = params.verbose;

        let entry = match resolve(cache, &rp, error_buffer).await {
            Ok(entry) => entry,
            Err(_) => {
                sendf::failf(
                    error_buffer,
                    &format!(
                        "Failed to resolve \"{}\" for SOCKS5 connect.",
                        params.hostname
                    ),
                );
                return Err(CurlProxyCode::ResolveHost);
            }
        };

        // When a family is forced, take the first address of that family;
        // otherwise take the first address overall (curl's `socks5_resolving`).
        let chosen: Option<SocketAddr> = if params.ip_version != IpVersion::Any {
            entry
                .addrs
                .iter()
                .find(|addr| params.ip_version.matches(addr))
                .copied()
        } else {
            entry.addrs.iter().next().copied()
        };
        let chosen = match chosen {
            Some(addr) => addr,
            None => {
                sendf::failf(
                    error_buffer,
                    &format!(
                        "Failed to resolve \"{}\" for SOCKS5 connect.",
                        params.hostname
                    ),
                );
                return Err(CurlProxyCode::ResolveHost);
            }
        };

        match chosen.ip() {
            IpAddr::V4(ip) => {
                sendf::infof(
                    params.verbose,
                    &format!(
                        "SOCKS5 connect to {}:{} (locally resolved)",
                        ip, params.remote_port
                    ),
                );
                req.push(0x01); // ATYP = IPv4
                req.extend_from_slice(&ip.octets()); // 4 bytes, network order
            }
            IpAddr::V6(ip) => {
                sendf::infof(
                    params.verbose,
                    &format!(
                        "SOCKS5 connect to [{}]:{} (locally resolved)",
                        ip, params.remote_port
                    ),
                );
                req.push(0x04); // ATYP = IPv6
                req.extend_from_slice(&ip.octets()); // 16 bytes, network order
            }
        }
    } else {
        // SOCKS5h: send the address for the proxy to resolve. An IP-literal
        // target is still sent as the literal (curl's `inet_pton` branches);
        // anything else is a domain name.
        if params.ipv6_ip {
            // The connection flagged the host as an IPv6 literal; a parse
            // failure mirrors curl's `inet_pton(AF_INET6) != 1` → BAD_ADDRESS_TYPE.
            match params.hostname.parse::<Ipv6Addr>() {
                Ok(ip) => {
                    req.push(0x04); // ATYP = IPv6
                    req.extend_from_slice(&ip.octets());
                }
                Err(_) => return Err(CurlProxyCode::BadAddressType),
            }
        } else if let Ok(ip) = params.hostname.parse::<Ipv4Addr>() {
            req.push(0x01); // ATYP = IPv4 literal
            req.extend_from_slice(&ip.octets());
        } else {
            // Domain name: ATYP = 3, one length byte, then the hostname bytes.
            // The length was validated (≤ 255) at the greeting phase.
            let host = params.hostname.as_bytes();
            req.push(0x03); // ATYP = DOMAINNAME
            req.push(host.len() as u8);
            req.extend_from_slice(host);
        }
        sendf::infof(
            params.verbose,
            &format!(
                "SOCKS5 connect to {}:{} (remotely resolved)",
                params.hostname, params.remote_port
            ),
        );
    }

    // PORT: 2 bytes, big-endian (MSB, LSB), after the address.
    req.extend_from_slice(&params.remote_port.to_be_bytes());
    socks_send(stream, &req).await?;

    // ---- CONNECT reply (socks5_recv_resp1). ---------------------------------
    socks5_recv_resp1(stream, params, error_buffer).await
}

/// Reads and validates the SOCKS5 CONNECT reply, consuming the **entire**
/// variable-length packet — curl's `socks5_recv_resp1`.
///
/// Reply layout (RFC 1928):
///
/// ```text
/// +----+-----+-------+------+----------+----------+
/// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
///
/// The minimum length is 8 bytes; the true length depends on `ATYP`. curl reads
/// the minimum, then recomputes the full length and reads the remainder so no
/// stray reply bytes are left to corrupt the subsequent protocol layer.
async fn socks5_recv_resp1<S>(
    stream: &mut S,
    params: &SocksParams,
    error_buffer: &mut Option<String>,
) -> Result<(), CurlProxyCode>
where
    S: AsyncRead + Unpin,
{
    // Read the fixed 8-byte minimum first.
    let mut resp = [0u8; 8];
    socks_recv(stream, &mut resp).await?;

    if resp[0] != 5 {
        sendf::failf(
            error_buffer,
            "SOCKS5 reply has wrong version, version should be 5.",
        );
        return Err(CurlProxyCode::BadVersion);
    }

    // Anything other than REP = 0 is a failure; map it via the RFC 1928 table.
    if resp[1] != 0 {
        let code = resp[1];
        sendf::failf(
            error_buffer,
            &format!(
                "cannot complete SOCKS5 connection to {}. ({})",
                params.hostname, code
            ),
        );
        let rc = if (code as usize) < SOCKS5_REP_LOOKUP.len() {
            SOCKS5_REP_LOOKUP[code as usize]
        } else {
            CurlProxyCode::ReplyUnassigned
        };
        return Err(rc);
    }

    // Recompute the full packet length from ATYP and drain the remainder.
    let total = match resp[3] {
        0x01 => 4 + 4 + 2,                        // IPv4:   header + 4 + port
        0x03 => 4 + 1 + usize::from(resp[4]) + 2, // domain: header + len + str + port
        0x04 => 4 + 16 + 2,                       // IPv6:   header + 16 + port
        _ => {
            sendf::failf(error_buffer, "SOCKS5 reply has wrong address type.");
            return Err(CurlProxyCode::BadAddressType);
        }
    };

    // Consume any bytes beyond the initial 8 so the whole reply is read.
    if total > resp.len() {
        let mut rest = vec![0u8; total - resp.len()];
        socks_recv(stream, &mut rest).await?;
    }

    sendf::infof(params.verbose, "SOCKS5 request granted.");
    Ok(())
}

// ===========================================================================
// Tests — exercise the engine over an in-memory `tokio::io::duplex` pair,
// asserting both the EXACT request bytes the engine emits and the resulting
// `CurlProxyCode`. All targets use IP-literal / hostname forms; the IP-literal
// SOCKS4/SOCKS5 cases short-circuit DNS in `crate::dns::resolve` (no network).
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    /// Runs a handshake against a canned proxy response and returns the result
    /// together with the **exact** bytes the engine sent to the proxy.
    ///
    /// The full `canned_response` is staged before the engine runs; the engine's
    /// `read_exact` calls consume it in order across handshake rounds. Afterwards
    /// the client half is closed and every request byte is drained for assertion.
    async fn run_socks(
        params: &SocksParams,
        canned_response: &[u8],
    ) -> (std::result::Result<(), CurlProxyCode>, Vec<u8>) {
        let (mut client, mut server) = tokio::io::duplex(8192);
        if !canned_response.is_empty() {
            server.write_all(canned_response).await.unwrap();
        }
        let mut cache = DnsCache::new();
        let mut errbuf: Option<String> = None;
        let result = socks_handshake(&mut client, params, &mut cache, &mut errbuf).await;
        // Close the client side so the request drain terminates at EOF.
        drop(client);
        let mut sent = Vec::new();
        server.read_to_end(&mut sent).await.unwrap();
        (result, sent)
    }

    // ---- SOCKS4 / SOCKS4a ---------------------------------------------------

    #[tokio::test]
    async fn socks4_success_no_user() {
        let params = SocksParams::new("127.0.0.1", 80, CurlProxyType::Socks4);
        // VN=0, CD=90 (granted), DSTPORT(2)+DSTIP(4) ignored.
        let resp = [0x00u8, 0x5A, 0, 0, 0, 0, 0, 0];
        let (result, sent) = run_socks(&params, &resp).await;
        assert_eq!(result, Ok(()));
        // [VN=4][CD=1][port 0x0050][127.0.0.1][NUL] (empty username → lone NUL).
        assert_eq!(sent, vec![0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, 0x00]);
    }

    #[tokio::test]
    async fn socks4_success_with_user() {
        let mut params = SocksParams::new("127.0.0.1", 80, CurlProxyType::Socks4);
        params.proxy_user = Some("curl".to_string());
        let resp = [0x00u8, 0x5A, 0, 0, 0, 0, 0, 0];
        let (result, sent) = run_socks(&params, &resp).await;
        assert_eq!(result, Ok(()));
        // USERID "curl" then the trailing NUL.
        assert_eq!(
            sent,
            vec![0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, b'c', b'u', b'r', b'l', 0x00]
        );
    }

    #[tokio::test]
    async fn socks4_reply_codes() {
        for (cd, expected) in [
            (0x5Bu8, CurlProxyCode::RequestFailed),
            (0x5C, CurlProxyCode::Identd),
            (0x5D, CurlProxyCode::IdentdDiffer),
            (0x42, CurlProxyCode::UnknownFail),
        ] {
            let params = SocksParams::new("127.0.0.1", 80, CurlProxyType::Socks4);
            let resp = [0x00u8, cd, 0, 0, 0, 0, 0, 0];
            let (result, _sent) = run_socks(&params, &resp).await;
            assert_eq!(result, Err(expected), "CD={cd:#x}");
        }
    }

    #[tokio::test]
    async fn socks4_bad_version() {
        let params = SocksParams::new("127.0.0.1", 80, CurlProxyType::Socks4);
        // VN must be 0; a non-zero reply version is rejected.
        let resp = [0x01u8, 0x5A, 0, 0, 0, 0, 0, 0];
        let (result, _sent) = run_socks(&params, &resp).await;
        assert_eq!(result, Err(CurlProxyCode::BadVersion));
    }

    #[tokio::test]
    async fn socks4a_fake_ip_and_hostname() {
        let params = SocksParams::new("example.com", 80, CurlProxyType::Socks4a);
        let resp = [0x00u8, 0x5A, 0, 0, 0, 0, 0, 0];
        let (result, sent) = run_socks(&params, &resp).await;
        assert_eq!(result, Ok(()));
        // [4][1][port][fake IP 0.0.0.1][user NUL][hostname][NUL].
        let mut expect = vec![0x04u8, 0x01, 0x00, 0x50, 0, 0, 0, 1, 0x00];
        expect.extend_from_slice(b"example.com");
        expect.push(0x00);
        assert_eq!(sent, expect);
    }

    #[tokio::test]
    async fn socks4_long_user() {
        let mut params = SocksParams::new("127.0.0.1", 80, CurlProxyType::Socks4);
        params.proxy_user = Some("u".repeat(256));
        // Fails while building the request; no proxy response is consumed.
        let (result, _sent) = run_socks(&params, &[]).await;
        assert_eq!(result, Err(CurlProxyCode::LongUser));
    }

    #[tokio::test]
    async fn socks4a_long_hostname() {
        // hostname length + 1 (NUL) must be <= 255, so 255 chars overflows.
        let params = SocksParams::new("h".repeat(255), 80, CurlProxyType::Socks4a);
        let (result, _sent) = run_socks(&params, &[]).await;
        assert_eq!(result, Err(CurlProxyCode::LongHostname));
    }

    // ---- SOCKS5 / SOCKS5h ---------------------------------------------------

    #[tokio::test]
    async fn socks5_noauth_ipv4_success() {
        let mut params = SocksParams::new("127.0.0.1", 80, CurlProxyType::Socks5);
        // Pin BASIC-only auth so the advertised method set (and thus the greeting
        // bytes) is deterministic regardless of the `gssapi` feature.
        params.socks5_auth = CURLAUTH_BASIC;
        // method reply [05 00] then CONNECT reply [05 00 00 01 <ip4> <port>].
        let mut resp = vec![0x05u8, 0x00];
        resp.extend_from_slice(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        let (result, sent) = run_socks(&params, &resp).await;
        assert_eq!(result, Ok(()));
        // greeting [05 01 00] then CONNECT [05 01 00 01 127.0.0.1 00 50].
        assert_eq!(
            sent,
            vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50]
        );
    }

    #[tokio::test]
    async fn socks5_userpass_success() {
        let mut params = SocksParams::new("127.0.0.1", 80, CurlProxyType::Socks5);
        params.proxy_user = Some("u".to_string());
        params.proxy_password = Some("p".to_string());
        // Pin BASIC-only auth so the greeting offers exactly NO-AUTH + USER/PASS
        // (no GSSAPI method) regardless of the `gssapi` feature.
        params.socks5_auth = CURLAUTH_BASIC;
        // method reply selects 0x02; auth reply status 0; CONNECT reply success.
        let mut resp = vec![0x05u8, 0x02, 0x05, 0x00];
        resp.extend_from_slice(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        let (result, sent) = run_socks(&params, &resp).await;
        assert_eq!(result, Ok(()));
        // greeting offers NO-AUTH + USER/PASS: [05 02 00 02].
        // RFC1929 subneg: [01 ulen 'u' plen 'p'] = [01 01 75 01 70].
        // CONNECT: [05 01 00 01 127.0.0.1 00 50].
        let mut expect = vec![0x05u8, 0x02, 0x00, 0x02];
        expect.extend_from_slice(&[0x01, 0x01, b'u', 0x01, b'p']);
        expect.extend_from_slice(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50]);
        assert_eq!(sent, expect);
    }

    #[tokio::test]
    async fn socks5_userpass_rejected() {
        let mut params = SocksParams::new("127.0.0.1", 80, CurlProxyType::Socks5);
        params.proxy_user = Some("u".to_string());
        params.proxy_password = Some("p".to_string());
        // method 0x02, then auth reply with a non-zero status byte.
        let resp = vec![0x05u8, 0x02, 0x05, 0x01];
        let (result, _sent) = run_socks(&params, &resp).await;
        assert_eq!(result, Err(CurlProxyCode::UserRejected));
    }

    #[tokio::test]
    async fn socks5_no_acceptable_method() {
        let params = SocksParams::new("127.0.0.1", 80, CurlProxyType::Socks5);
        let resp = vec![0x05u8, 0xFF];
        let (result, _sent) = run_socks(&params, &resp).await;
        assert_eq!(result, Err(CurlProxyCode::NoAuth));
    }

    #[tokio::test]
    async fn socks5_resp0_bad_version() {
        let params = SocksParams::new("127.0.0.1", 80, CurlProxyType::Socks5);
        let resp = vec![0x04u8, 0x00];
        let (result, _sent) = run_socks(&params, &resp).await;
        assert_eq!(result, Err(CurlProxyCode::BadVersion));
    }

    #[cfg(not(feature = "gssapi"))]
    #[tokio::test]
    async fn socks5_gssapi_method_not_supported() {
        // Default build has the `gssapi` feature OFF. If the server selects the
        // GSS-API method (0x01) anyway, the engine must reject it as unsupported.
        let params = SocksParams::new("127.0.0.1", 80, CurlProxyType::Socks5);
        let resp = vec![0x05u8, 0x01];
        let (result, _sent) = run_socks(&params, &resp).await;
        assert_eq!(result, Err(CurlProxyCode::GssapiPermsg));
    }

    #[cfg(feature = "gssapi")]
    #[tokio::test]
    async fn socks5_gssapi_negotiation_stub_fails() {
        // With the `gssapi` feature ON, selecting method 0x01 drives the
        // negotiation stub, which (the full GSS-API exchange being REFERENCE-only)
        // fails with CURLPX_GSSAPI — i.e. the default build still behaves as if
        // GSS-API were unavailable.
        let params = SocksParams::new("127.0.0.1", 80, CurlProxyType::Socks5);
        let resp = vec![0x05u8, 0x01];
        let (result, _sent) = run_socks(&params, &resp).await;
        assert_eq!(result, Err(CurlProxyCode::Gssapi));
    }

    #[tokio::test]
    async fn socks5_connect_reply_codes() {
        // REP 1..=8 map through the RFC 1928 table; REP >= 9 is "unassigned".
        let cases = [
            (1u8, CurlProxyCode::ReplyGeneralServerFailure),
            (2, CurlProxyCode::ReplyNotAllowed),
            (3, CurlProxyCode::ReplyNetworkUnreachable),
            (4, CurlProxyCode::ReplyHostUnreachable),
            (5, CurlProxyCode::ReplyConnectionRefused),
            (6, CurlProxyCode::ReplyTtlExpired),
            (7, CurlProxyCode::ReplyCommandNotSupported),
            (8, CurlProxyCode::ReplyAddressTypeNotSupported),
            (9, CurlProxyCode::ReplyUnassigned),
            (255, CurlProxyCode::ReplyUnassigned),
        ];
        for (rep, expected) in cases {
            let params = SocksParams::new("127.0.0.1", 80, CurlProxyType::Socks5);
            // method reply [05 00] then CONNECT reply with the failing REP.
            let resp = vec![0x05u8, 0x00, 0x05, rep, 0x00, 0x01, 0, 0, 0, 0];
            let (result, _sent) = run_socks(&params, &resp).await;
            assert_eq!(result, Err(expected), "REP={rep}");
        }
    }

    #[tokio::test]
    async fn socks5_connect_reply_bad_version() {
        let params = SocksParams::new("127.0.0.1", 80, CurlProxyType::Socks5);
        // method ok, but the CONNECT reply has the wrong version byte.
        let resp = vec![0x05u8, 0x00, 0x04, 0x00, 0x00, 0x01, 0, 0, 0, 0];
        let (result, _sent) = run_socks(&params, &resp).await;
        assert_eq!(result, Err(CurlProxyCode::BadVersion));
    }

    #[tokio::test]
    async fn socks5h_domain_request() {
        let mut params = SocksParams::new("example.com", 80, CurlProxyType::Socks5Hostname);
        // Deterministic greeting (no GSSAPI method) across feature configurations.
        params.socks5_auth = CURLAUTH_BASIC;
        let mut resp = vec![0x05u8, 0x00];
        resp.extend_from_slice(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        let (result, sent) = run_socks(&params, &resp).await;
        assert_eq!(result, Ok(()));
        // greeting [05 01 00] then CONNECT with ATYP=3 (domain): [05 01 00 03
        // <len=11> "example.com" <port 00 50>].
        let mut expect = vec![0x05u8, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 11];
        expect.extend_from_slice(b"example.com");
        expect.extend_from_slice(&[0x00, 0x50]);
        assert_eq!(sent, expect);
    }

    #[tokio::test]
    async fn socks5_variable_length_domain_reply_fully_consumed() {
        // A CONNECT reply whose BND.ADDR is a domain name must be drained in full
        // (header 4 + len 1 + 5 name bytes + 2 port = 12 bytes total).
        let (mut client, mut server) = tokio::io::duplex(8192);
        server.write_all(&[0x05u8, 0x00]).await.unwrap(); // method reply
        let reply = [
            0x05u8, 0x00, 0x00, 0x03, 0x05, b'a', b'b', b'c', b'd', b'e', 0x00, 0x50,
        ];
        server.write_all(&reply).await.unwrap();
        let params = SocksParams::new("127.0.0.1", 80, CurlProxyType::Socks5);
        let mut cache = DnsCache::new();
        let mut errbuf = None;
        let result = socks_handshake(&mut client, &params, &mut cache, &mut errbuf).await;
        assert_eq!(result, Ok(()));
        // Every reply byte must have been consumed: closing the server yields EOF
        // with no residue. (A wrong length recompute would leave bytes behind.)
        drop(server);
        let mut leftover = Vec::new();
        client.read_to_end(&mut leftover).await.unwrap();
        assert!(
            leftover.is_empty(),
            "engine left {} unconsumed reply byte(s)",
            leftover.len()
        );
    }

    #[tokio::test]
    async fn socks5_long_user() {
        let mut params = SocksParams::new("127.0.0.1", 80, CurlProxyType::Socks5);
        params.proxy_user = Some("u".repeat(256));
        params.proxy_password = Some("p".to_string());
        // Server selects username/password auth; the subneg then rejects the
        // over-long username.
        let resp = vec![0x05u8, 0x02];
        let (result, _sent) = run_socks(&params, &resp).await;
        assert_eq!(result, Err(CurlProxyCode::LongUser));
    }

    #[tokio::test]
    async fn socks5_long_passwd() {
        let mut params = SocksParams::new("127.0.0.1", 80, CurlProxyType::Socks5);
        params.proxy_user = Some("u".to_string());
        params.proxy_password = Some("p".repeat(256));
        let resp = vec![0x05u8, 0x02];
        let (result, _sent) = run_socks(&params, &resp).await;
        assert_eq!(result, Err(CurlProxyCode::LongPasswd));
    }

    #[tokio::test]
    async fn socks5h_long_hostname() {
        // SOCKS5h sends the hostname; a name over 255 bytes is rejected up front.
        let params = SocksParams::new("h".repeat(256), 80, CurlProxyType::Socks5Hostname);
        let (result, _sent) = run_socks(&params, &[]).await;
        assert_eq!(result, Err(CurlProxyCode::LongHostname));
    }

    // ---- EOF, dispatch, and boundary conversion -----------------------------

    #[tokio::test]
    async fn eof_mid_handshake_recv_connect() {
        // The proxy accepts the request but closes before replying → RECV_CONNECT.
        let (mut client, server) = tokio::io::duplex(8192);
        let drainer = tokio::spawn(async move {
            let mut server = server;
            let mut buf = [0u8; 64];
            // Drain the request so the engine's write completes, then drop the
            // server, closing the stream so the engine's read hits EOF.
            let _ = server.read(&mut buf).await;
        });
        let params = SocksParams::new("127.0.0.1", 80, CurlProxyType::Socks4);
        let mut cache = DnsCache::new();
        let mut errbuf = None;
        let result = socks_handshake(&mut client, &params, &mut cache, &mut errbuf).await;
        drainer.await.unwrap();
        assert_eq!(result, Err(CurlProxyCode::RecvConnect));
    }

    #[tokio::test]
    async fn dispatch_rejects_non_socks_proxytype() {
        // The dispatcher only handles SOCKS variants; an HTTP proxytype is a
        // filter-side bug and is surfaced defensively.
        let params = SocksParams::new("127.0.0.1", 80, CurlProxyType::Http);
        let (result, sent) = run_socks(&params, &[]).await;
        assert_eq!(result, Err(CurlProxyCode::UnknownFail));
        assert!(sent.is_empty());
    }

    #[test]
    fn to_curlcode_boundary_conversion() {
        // OK maps to CURLE_OK with the OK proxy code preserved.
        assert_eq!(
            to_curlcode(CurlProxyCode::Ok),
            (codes::CURLE_OK, CurlProxyCode::Ok)
        );
        // Any error maps to CURLE_PROXY while preserving the proxy code for
        // CURLINFO_PROXY_ERROR.
        assert_eq!(
            to_curlcode(CurlProxyCode::BadVersion),
            (codes::CURLE_PROXY, CurlProxyCode::BadVersion)
        );
        assert_eq!(
            to_curlcode(CurlProxyCode::UserRejected),
            (codes::CURLE_PROXY, CurlProxyCode::UserRejected)
        );
    }

    #[test]
    fn curlproxycode_discriminants_match_curl_header() {
        // Exact integer parity with include/curl/curl.h's `CURLproxycode`:
        // CURLPX_OK = 0, the rest alphabetical +1, CURLPX_LAST = 34.
        let table = [
            (CurlProxyCode::Ok, 0),
            (CurlProxyCode::BadAddressType, 1),
            (CurlProxyCode::BadVersion, 2),
            (CurlProxyCode::Closed, 3),
            (CurlProxyCode::Gssapi, 4),
            (CurlProxyCode::GssapiPermsg, 5),
            (CurlProxyCode::GssapiProtection, 6),
            (CurlProxyCode::Identd, 7),
            (CurlProxyCode::IdentdDiffer, 8),
            (CurlProxyCode::LongHostname, 9),
            (CurlProxyCode::LongPasswd, 10),
            (CurlProxyCode::LongUser, 11),
            (CurlProxyCode::NoAuth, 12),
            (CurlProxyCode::RecvAddress, 13),
            (CurlProxyCode::RecvAuth, 14),
            (CurlProxyCode::RecvConnect, 15),
            (CurlProxyCode::RecvReqack, 16),
            (CurlProxyCode::ReplyAddressTypeNotSupported, 17),
            (CurlProxyCode::ReplyCommandNotSupported, 18),
            (CurlProxyCode::ReplyConnectionRefused, 19),
            (CurlProxyCode::ReplyGeneralServerFailure, 20),
            (CurlProxyCode::ReplyHostUnreachable, 21),
            (CurlProxyCode::ReplyNetworkUnreachable, 22),
            (CurlProxyCode::ReplyNotAllowed, 23),
            (CurlProxyCode::ReplyTtlExpired, 24),
            (CurlProxyCode::ReplyUnassigned, 25),
            (CurlProxyCode::RequestFailed, 26),
            (CurlProxyCode::ResolveHost, 27),
            (CurlProxyCode::SendAuth, 28),
            (CurlProxyCode::SendConnect, 29),
            (CurlProxyCode::SendRequest, 30),
            (CurlProxyCode::UnknownFail, 31),
            (CurlProxyCode::UnknownMode, 32),
            (CurlProxyCode::UserRejected, 33),
            (CurlProxyCode::Last, 34),
        ];
        for (code, expected) in table {
            assert_eq!(code.as_raw(), expected, "{code:?}");
        }
    }
}
