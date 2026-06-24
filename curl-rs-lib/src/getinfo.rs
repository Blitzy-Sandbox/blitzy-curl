// Typed info-retrieval surface (`curl_easy_getinfo` dispatch core) for the
// curl-rs workspace.
//
// SPDX-License-Identifier: curl
//
// This file is a memory-safe Rust reimplementation of curl's info-retrieval
// logic (`lib/getinfo.c` plus the public `CURLINFO` enumeration declared in
// `include/curl/curl.h`). The original C sources are
//   Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// and are licensed under the curl license (https://curl.se/docs/copyright.html).
// This Rust port preserves the observable behavior, the exact `CURLINFO`
// integer ids, and the per-field semantics of that logic; it is a behavioral
// and ABI translation, not a line-by-line transliteration.

//! Typed retrieval of post-transfer information — the safe core of
//! `curl_easy_getinfo` (`lib/getinfo.c`).
//!
//! # The variadic-getinfo split
//!
//! curl's public `curl_easy_getinfo(CURL *handle, CURLINFO info, ...)` is a
//! C-variadic function: the caller passes a single trailing out-pointer whose
//! pointee type is implied by `info` (a `char**`, `long*`, `double*`,
//! `curl_off_t*`, `struct curl_slist**`, or `curl_socket_t*`). Defining safe,
//! correct variadic `extern "C"` shims is delicate, so the implementation is
//! split in two (Agent Action Plan §0.7.2):
//!
//! * **This module** is the *typed* half. [`retrieve`] takes a strongly-typed
//!   [`CurlInfo`] selector and a borrow of the handle-owned [`Info`] store and
//!   returns a strongly-typed [`InfoValue`]. It contains **no** `unsafe` and
//!   touches **no** raw pointers.
//! * `curl-rs-ffi`'s `curl_easy_getinfo` is the *untyped* half. It reads the
//!   single trailing `va_arg` out-pointer, calls [`CurlInfo::from_raw`] then
//!   [`retrieve`], and writes the returned [`InfoValue`] through that pointer
//!   using the C type implied by [`CurlInfo::type_group`]. All pointer writes —
//!   and therefore all `unsafe` — live there.
//!
//! Keeping [`CurlInfo`], [`InfoValue`], and [`retrieve`] public and stable is
//! part of the cross-crate contract: the FFI crate depends on them by name.
//!
//! # The owned-string lifetime contract (AAP §0.7.1)
//!
//! Several `CURLINFO_*` values are C strings (`CURLINFO_EFFECTIVE_URL`,
//! `CURLINFO_CONTENT_TYPE`, …). curl's documented contract is that the returned
//! `char*` remains valid **until the next call on the same handle or until the
//! handle is cleaned up** — the caller must never free it. This module honors
//! that by storing every such string as an owned [`CString`] (or [`SList`])
//! *on the [`Info`] store, which itself lives on the easy handle*, and by
//! having [`retrieve`] return a **borrow** into that storage:
//! [`InfoValue::Str`] carries an `Option<&'a CStr>` tied to the `&'a Info`
//! argument's lifetime. The borrow checker therefore guarantees, at compile
//! time, that the FFI cannot hand C code a pointer that outlives the buffer.
//! No value is ever returned by pointer into a temporary.
//!
//! # Relationship to the easy handle
//!
//! In C, `Curl_getinfo` reads fields scattered across `struct Curl_easy`'s
//! `info` (`struct PureInfo`), `progress` (`struct Progress`), `state`, and
//! `set` sub-structs. This module gathers every field that getinfo reads into a
//! single owned [`Info`] struct. The easy-handle implementation (`easy.rs`,
//! authored separately) embeds one [`Info`] and the transfer/progress/setopt
//! engines write its fields as a transfer proceeds; [`retrieve`] only ever
//! reads them. [`Info`] is deliberately self-contained so that this module
//! depends on nothing beyond [`crate::error`] and [`crate::slist`].
//!
//! # Memory safety
//!
//! This module contains **zero** `unsafe` and compiles under the module-level
//! `#![forbid(unsafe_code)]` declared below (reinforcing the crate-root
//! attribute). All ownership and freeing is handled by [`CString`], [`SList`],
//! and [`Vec`]; the only pointer-shaped value it ever carries is the opaque
//! `CURLINFO_PRIVATE` user pointer, kept as a plain [`usize`] (see
//! [`InfoPtr::Private`]) so the store stays `Send`/`Sync` and never dereferences
//! anything.
#![forbid(unsafe_code)]

use crate::error::{CurlError, Result};
use crate::slist::SList;
use std::ffi::{CStr, CString};

// ===========================================================================
// Platform/socket aliases
// ===========================================================================

/// The typed-core mirror of curl's `curl_socket_t`.
///
/// curl's socket type is platform-dependent (`int` on Unix, `SOCKET` —
/// pointer-width and unsigned — on Windows). The safe core models it as a wide
/// signed integer; the FFI crate narrows it to the platform `curl_socket_t`
/// when writing through the caller's out-pointer for `CURLINFO_ACTIVESOCKET`.
pub type CurlSocket = i64;

/// The typed-core mirror of curl's `CURL_SOCKET_BAD` sentinel ("no socket").
///
/// On the Unix targets of the parity matrix `curl_socket_t` is a signed `int`
/// and `CURL_SOCKET_BAD` is `-1`; that is the value [`Info::active_socket`]
/// holds when there is no active connection, and what `CURLINFO_LASTSOCKET`
/// reports as `-1`.
pub const CURL_SOCKET_BAD: CurlSocket = -1;

// ===========================================================================
// CURLINFO type-group bit masks (include/curl/curl.h)
// ===========================================================================
//
// Every `CURLINFO_*` id encodes its result type in its high bits. The low bits
// are a per-type sequence number. `CURLINFO_PTR` deliberately shares the
// `CURLINFO_SLIST` mask in curl (both `0x400000`): a pointer result and an
// slist result are written through the same `void**`-shaped out-pointer.

/// `CURLINFO_STRING` — result is a `char*`.
pub const CURLINFO_STRING: i32 = 0x10_0000;
/// `CURLINFO_LONG` — result is a `long`.
pub const CURLINFO_LONG: i32 = 0x20_0000;
/// `CURLINFO_DOUBLE` — result is a `double`.
pub const CURLINFO_DOUBLE: i32 = 0x30_0000;
/// `CURLINFO_SLIST` — result is a `struct curl_slist*`.
pub const CURLINFO_SLIST: i32 = 0x40_0000;
/// `CURLINFO_PTR` — result is an opaque pointer. Shares the `CURLINFO_SLIST`
/// mask value (`0x400000`) by design in curl.
pub const CURLINFO_PTR: i32 = 0x40_0000;
/// `CURLINFO_SOCKET` — result is a `curl_socket_t`.
pub const CURLINFO_SOCKET: i32 = 0x50_0000;
/// `CURLINFO_OFF_T` — result is a `curl_off_t`.
pub const CURLINFO_OFF_T: i32 = 0x60_0000;
/// `CURLINFO_MASK` — mask isolating the per-type sequence number (low bits).
pub const CURLINFO_MASK: i32 = 0x0f_ffff;
/// `CURLINFO_TYPEMASK` — mask isolating the result-type group (high bits).
pub const CURLINFO_TYPEMASK: i32 = 0xf0_0000;

// ---------------------------------------------------------------------------
// CURL_HTTP_VERSION_* values reported by CURLINFO_HTTP_VERSION
// (include/curl/curl.h). These are the *reported* version codes, distinct from
// the internal `Info::http_version` encoding (0/10/11/20/30) that maps to them.
// ---------------------------------------------------------------------------
const CURL_HTTP_VERSION_NONE: i64 = 0;
const CURL_HTTP_VERSION_1_0: i64 = 1;
const CURL_HTTP_VERSION_1_1: i64 = 2;
const CURL_HTTP_VERSION_2_0: i64 = 3;
const CURL_HTTP_VERSION_3: i64 = 30;

// ---------------------------------------------------------------------------
// curl_sslbackend ids reported by CURLINFO_TLS_SSL_PTR / CURLINFO_TLS_SESSION
// (include/curl/curl.h). rustls is the workspace's exclusive TLS backend.
// ---------------------------------------------------------------------------
const CURLSSLBACKEND_NONE: i32 = 0;
const CURLSSLBACKEND_RUSTLS: i32 = 14;

/// The result-type group of a [`CurlInfo`], mirroring curl's `CURLINFO_TYPEMASK`
/// classification.
///
/// The FFI crate uses this to decide which C out-pointer type to read for the
/// trailing `va_arg` and which C type to write. Note that curl's `CURLINFO_PTR`
/// shares the `CURLINFO_SLIST` mask, so both opaque-pointer and slist results
/// map to [`InfoType::Slist`] here — they are read/written through the same
/// `void**`-shaped pointer; the concrete pointee is distinguished by the
/// returned [`InfoValue`] variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InfoType {
    /// `CURLINFO_STRING` — a `char*`.
    String,
    /// `CURLINFO_LONG` — a `long`.
    Long,
    /// `CURLINFO_DOUBLE` — a `double`.
    Double,
    /// `CURLINFO_SLIST` / `CURLINFO_PTR` — a pointer (`curl_slist*`,
    /// `curl_certinfo*`, or `curl_tlssessioninfo*`).
    Slist,
    /// `CURLINFO_SOCKET` — a `curl_socket_t`.
    Socket,
    /// `CURLINFO_OFF_T` — a `curl_off_t`.
    OffT,
}

impl InfoType {
    /// Returns the raw `CURLINFO_*` type-group mask value for this group.
    ///
    /// Inverse-ish of [`InfoType::from_mask`]; [`InfoType::Slist`] maps back to
    /// `CURLINFO_SLIST` (which equals `CURLINFO_PTR`).
    #[must_use]
    pub const fn mask(self) -> i32 {
        match self {
            InfoType::String => CURLINFO_STRING,
            InfoType::Long => CURLINFO_LONG,
            InfoType::Double => CURLINFO_DOUBLE,
            InfoType::Slist => CURLINFO_SLIST,
            InfoType::Socket => CURLINFO_SOCKET,
            InfoType::OffT => CURLINFO_OFF_T,
        }
    }

    /// Classifies a raw `CURLINFO` integer's high bits into an [`InfoType`].
    ///
    /// Returns [`None`] if the masked value is not one of the six defined type
    /// groups (for example `CURLINFO_NONE`, whose type bits are `0`).
    #[must_use]
    pub const fn from_mask(raw: i32) -> Option<InfoType> {
        match raw & CURLINFO_TYPEMASK {
            CURLINFO_STRING => Some(InfoType::String),
            CURLINFO_LONG => Some(InfoType::Long),
            CURLINFO_DOUBLE => Some(InfoType::Double),
            // CURLINFO_SLIST == CURLINFO_PTR (0x400000): a single arm covers both.
            CURLINFO_SLIST => Some(InfoType::Slist),
            CURLINFO_SOCKET => Some(InfoType::Socket),
            CURLINFO_OFF_T => Some(InfoType::OffT),
            _ => None,
        }
    }
}

// ===========================================================================
// CurlInfo — the typed CURLINFO selector
// ===========================================================================

/// A strongly-typed `CURLINFO` selector.
///
/// Each variant's discriminant is the **exact** `CURLINFO_*` integer from
/// `include/curl/curl.h` (a type-group base bit-or'd with a per-type sequence
/// number), so [`as_raw`](CurlInfo::as_raw) is a plain cast and
/// [`from_raw`](CurlInfo::from_raw) round-trips losslessly. The discriminants
/// are pinned by unit tests; changing one would break the libcurl ABI.
///
/// `CURLINFO_NONE` (`0`, "never use this") is intentionally **not** a variant:
/// [`from_raw(0)`](CurlInfo::from_raw) returns [`None`], which the FFI maps to
/// `CURLE_UNKNOWN_OPTION` exactly as C's `Curl_getinfo` does for an
/// unrecognized id.
///
/// Variants are declared in `include/curl/curl.h` order. Several entries are
/// marked deprecated in the C headers (for example
/// [`SizeUpload`](CurlInfo::SizeUpload), superseded by
/// [`SizeUploadT`](CurlInfo::SizeUploadT)); they remain part of the ABI and are
/// fully supported here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum CurlInfo {
    /// `CURLINFO_EFFECTIVE_URL` — the last effective URL.
    EffectiveUrl = CURLINFO_STRING + 1,
    /// `CURLINFO_RESPONSE_CODE` — the last received response code.
    ResponseCode = CURLINFO_LONG + 2,
    /// `CURLINFO_TOTAL_TIME` — total transfer time, in seconds.
    TotalTime = CURLINFO_DOUBLE + 3,
    /// `CURLINFO_NAMELOOKUP_TIME` — name-resolution time, in seconds.
    NamelookupTime = CURLINFO_DOUBLE + 4,
    /// `CURLINFO_CONNECT_TIME` — TCP connect time, in seconds.
    ConnectTime = CURLINFO_DOUBLE + 5,
    /// `CURLINFO_PRETRANSFER_TIME` — time until transfer start, in seconds.
    PretransferTime = CURLINFO_DOUBLE + 6,
    /// `CURLINFO_SIZE_UPLOAD` (deprecated; use [`SizeUploadT`](Self::SizeUploadT))
    /// — bytes uploaded, as a `double`.
    SizeUpload = CURLINFO_DOUBLE + 7,
    /// `CURLINFO_SIZE_UPLOAD_T` — bytes uploaded, as a `curl_off_t`.
    SizeUploadT = CURLINFO_OFF_T + 7,
    /// `CURLINFO_SIZE_DOWNLOAD` (deprecated; use
    /// [`SizeDownloadT`](Self::SizeDownloadT)) — bytes downloaded, as a `double`.
    SizeDownload = CURLINFO_DOUBLE + 8,
    /// `CURLINFO_SIZE_DOWNLOAD_T` — bytes downloaded, as a `curl_off_t`.
    SizeDownloadT = CURLINFO_OFF_T + 8,
    /// `CURLINFO_SPEED_DOWNLOAD` (deprecated; use
    /// [`SpeedDownloadT`](Self::SpeedDownloadT)) — download speed (bytes/s) as a
    /// `double`.
    SpeedDownload = CURLINFO_DOUBLE + 9,
    /// `CURLINFO_SPEED_DOWNLOAD_T` — download speed (bytes/s) as a `curl_off_t`.
    SpeedDownloadT = CURLINFO_OFF_T + 9,
    /// `CURLINFO_SPEED_UPLOAD` (deprecated; use
    /// [`SpeedUploadT`](Self::SpeedUploadT)) — upload speed (bytes/s) as a
    /// `double`.
    SpeedUpload = CURLINFO_DOUBLE + 10,
    /// `CURLINFO_SPEED_UPLOAD_T` — upload speed (bytes/s) as a `curl_off_t`.
    SpeedUploadT = CURLINFO_OFF_T + 10,
    /// `CURLINFO_HEADER_SIZE` — total size of all received headers.
    HeaderSize = CURLINFO_LONG + 11,
    /// `CURLINFO_REQUEST_SIZE` — total size of issued requests.
    RequestSize = CURLINFO_LONG + 12,
    /// `CURLINFO_SSL_VERIFYRESULT` — certificate verification result.
    SslVerifyResult = CURLINFO_LONG + 13,
    /// `CURLINFO_FILETIME` — remote file time (Unix epoch seconds) as a `long`.
    Filetime = CURLINFO_LONG + 14,
    /// `CURLINFO_FILETIME_T` — remote file time as a `curl_off_t`.
    FiletimeT = CURLINFO_OFF_T + 14,
    /// `CURLINFO_CONTENT_LENGTH_DOWNLOAD` (deprecated; use
    /// [`ContentLengthDownloadT`](Self::ContentLengthDownloadT)) — content length
    /// of the download, as a `double`.
    ContentLengthDownload = CURLINFO_DOUBLE + 15,
    /// `CURLINFO_CONTENT_LENGTH_DOWNLOAD_T` — content length of the download, as
    /// a `curl_off_t`.
    ContentLengthDownloadT = CURLINFO_OFF_T + 15,
    /// `CURLINFO_CONTENT_LENGTH_UPLOAD` (deprecated; use
    /// [`ContentLengthUploadT`](Self::ContentLengthUploadT)) — content length of
    /// the upload, as a `double`.
    ContentLengthUpload = CURLINFO_DOUBLE + 16,
    /// `CURLINFO_CONTENT_LENGTH_UPLOAD_T` — content length of the upload, as a
    /// `curl_off_t`.
    ContentLengthUploadT = CURLINFO_OFF_T + 16,
    /// `CURLINFO_STARTTRANSFER_TIME` — time until first byte, in seconds.
    StarttransferTime = CURLINFO_DOUBLE + 17,
    /// `CURLINFO_CONTENT_TYPE` — the `Content-Type` of the downloaded object.
    ContentType = CURLINFO_STRING + 18,
    /// `CURLINFO_REDIRECT_TIME` — total time spent in redirects, in seconds.
    RedirectTime = CURLINFO_DOUBLE + 19,
    /// `CURLINFO_REDIRECT_COUNT` — number of redirects followed.
    RedirectCount = CURLINFO_LONG + 20,
    /// `CURLINFO_PRIVATE` — the user pointer set via `CURLOPT_PRIVATE`.
    Private = CURLINFO_STRING + 21,
    /// `CURLINFO_HTTP_CONNECTCODE` — the last proxy `CONNECT` response code.
    HttpConnectCode = CURLINFO_LONG + 22,
    /// `CURLINFO_HTTPAUTH_AVAIL` — bitmask of HTTP auth methods available.
    HttpAuthAvail = CURLINFO_LONG + 23,
    /// `CURLINFO_PROXYAUTH_AVAIL` — bitmask of proxy auth methods available.
    ProxyAuthAvail = CURLINFO_LONG + 24,
    /// `CURLINFO_OS_ERRNO` — the errno from the last failure, if any.
    OsErrno = CURLINFO_LONG + 25,
    /// `CURLINFO_NUM_CONNECTS` — connections created for the transfer.
    NumConnects = CURLINFO_LONG + 26,
    /// `CURLINFO_SSL_ENGINES` — list of available SSL crypto engines.
    SslEngines = CURLINFO_SLIST + 27,
    /// `CURLINFO_COOKIELIST` — all known cookies, in Netscape format.
    CookieList = CURLINFO_SLIST + 28,
    /// `CURLINFO_LASTSOCKET` (deprecated; use
    /// [`ActiveSocket`](Self::ActiveSocket)) — the last socket used, as a `long`.
    LastSocket = CURLINFO_LONG + 29,
    /// `CURLINFO_FTP_ENTRY_PATH` — the FTP entry path of the last connection.
    FtpEntryPath = CURLINFO_STRING + 30,
    /// `CURLINFO_REDIRECT_URL` — the URL a redirect would have gone to.
    RedirectUrl = CURLINFO_STRING + 31,
    /// `CURLINFO_PRIMARY_IP` — the remote IP of the primary connection.
    PrimaryIp = CURLINFO_STRING + 32,
    /// `CURLINFO_APPCONNECT_TIME` — time until the SSL/SSH handshake completed.
    AppconnectTime = CURLINFO_DOUBLE + 33,
    /// `CURLINFO_CERTINFO` — certificate chain information.
    Certinfo = CURLINFO_PTR + 34,
    /// `CURLINFO_CONDITION_UNMET` — whether a time-conditional request was unmet.
    ConditionUnmet = CURLINFO_LONG + 35,
    /// `CURLINFO_RTSP_SESSION_ID` — the RTSP session id.
    RtspSessionId = CURLINFO_STRING + 36,
    /// `CURLINFO_RTSP_CLIENT_CSEQ` — the next RTSP client `CSeq`.
    RtspClientCseq = CURLINFO_LONG + 37,
    /// `CURLINFO_RTSP_SERVER_CSEQ` — the next RTSP server `CSeq`.
    RtspServerCseq = CURLINFO_LONG + 38,
    /// `CURLINFO_RTSP_CSEQ_RECV` — the last received RTSP `CSeq`.
    RtspCseqRecv = CURLINFO_LONG + 39,
    /// `CURLINFO_PRIMARY_PORT` — the remote port of the primary connection.
    PrimaryPort = CURLINFO_LONG + 40,
    /// `CURLINFO_LOCAL_IP` — the local IP of the primary connection.
    LocalIp = CURLINFO_STRING + 41,
    /// `CURLINFO_LOCAL_PORT` — the local port of the primary connection.
    LocalPort = CURLINFO_LONG + 42,
    /// `CURLINFO_TLS_SESSION` (deprecated; use [`TlsSslPtr`](Self::TlsSslPtr)) —
    /// TLS backend/session info.
    TlsSession = CURLINFO_PTR + 43,
    /// `CURLINFO_ACTIVESOCKET` — the active socket, as a `curl_socket_t`.
    ActiveSocket = CURLINFO_SOCKET + 44,
    /// `CURLINFO_TLS_SSL_PTR` — TLS backend/session info.
    TlsSslPtr = CURLINFO_PTR + 45,
    /// `CURLINFO_HTTP_VERSION` — the HTTP version used (a `CURL_HTTP_VERSION_*`).
    HttpVersion = CURLINFO_LONG + 46,
    /// `CURLINFO_PROXY_SSL_VERIFYRESULT` — proxy certificate verification result.
    ProxySslVerifyResult = CURLINFO_LONG + 47,
    /// `CURLINFO_PROTOCOL` (deprecated; use [`Scheme`](Self::Scheme)) — the
    /// protocol used, as a `CURLPROTO_*` bit.
    Protocol = CURLINFO_LONG + 48,
    /// `CURLINFO_SCHEME` — the URL scheme used, lower-cased (e.g. `http`).
    Scheme = CURLINFO_STRING + 49,
    /// `CURLINFO_TOTAL_TIME_T` — total transfer time, in microseconds.
    TotalTimeT = CURLINFO_OFF_T + 50,
    /// `CURLINFO_NAMELOOKUP_TIME_T` — name-resolution time, in microseconds.
    NamelookupTimeT = CURLINFO_OFF_T + 51,
    /// `CURLINFO_CONNECT_TIME_T` — TCP connect time, in microseconds.
    ConnectTimeT = CURLINFO_OFF_T + 52,
    /// `CURLINFO_PRETRANSFER_TIME_T` — time until transfer start, in microseconds.
    PretransferTimeT = CURLINFO_OFF_T + 53,
    /// `CURLINFO_STARTTRANSFER_TIME_T` — time until first byte, in microseconds.
    StarttransferTimeT = CURLINFO_OFF_T + 54,
    /// `CURLINFO_REDIRECT_TIME_T` — time spent in redirects, in microseconds.
    RedirectTimeT = CURLINFO_OFF_T + 55,
    /// `CURLINFO_APPCONNECT_TIME_T` — time until the app-layer handshake
    /// completed, in microseconds.
    AppconnectTimeT = CURLINFO_OFF_T + 56,
    /// `CURLINFO_RETRY_AFTER` — the `Retry-After` value, in seconds.
    RetryAfter = CURLINFO_OFF_T + 57,
    /// `CURLINFO_EFFECTIVE_METHOD` — the effective HTTP method used.
    EffectiveMethod = CURLINFO_STRING + 58,
    /// `CURLINFO_PROXY_ERROR` — the detailed proxy error (`CURLproxycode`).
    ProxyError = CURLINFO_LONG + 59,
    /// `CURLINFO_REFERER` — the `Referer:` header sent, if any.
    Referer = CURLINFO_STRING + 60,
    /// `CURLINFO_CAINFO` — the default CA bundle path (build-time), if any.
    CaInfo = CURLINFO_STRING + 61,
    /// `CURLINFO_CAPATH` — the default CA directory path (build-time), if any.
    CaPath = CURLINFO_STRING + 62,
    /// `CURLINFO_XFER_ID` — the transfer's unique identifier.
    XferId = CURLINFO_OFF_T + 63,
    /// `CURLINFO_CONN_ID` — the connection's unique identifier.
    ConnId = CURLINFO_OFF_T + 64,
    /// `CURLINFO_QUEUE_TIME_T` — time the transfer was queued, in microseconds.
    QueueTimeT = CURLINFO_OFF_T + 65,
    /// `CURLINFO_USED_PROXY` — whether the transfer used a proxy.
    UsedProxy = CURLINFO_LONG + 66,
    /// `CURLINFO_POSTTRANSFER_TIME_T` — time from request start to last byte
    /// sent, in microseconds.
    PosttransferTimeT = CURLINFO_OFF_T + 67,
    /// `CURLINFO_EARLYDATA_SENT_T` — TLS early-data bytes sent.
    EarlydataSentT = CURLINFO_OFF_T + 68,
    /// `CURLINFO_HTTPAUTH_USED` — bitmask of the HTTP auth method used.
    HttpAuthUsed = CURLINFO_LONG + 69,
    /// `CURLINFO_PROXYAUTH_USED` — bitmask of the proxy auth method used.
    ProxyAuthUsed = CURLINFO_LONG + 70,
}

impl CurlInfo {
    /// Returns the exact `CURLINFO` integer for this selector.
    ///
    /// Because each variant's discriminant *is* its `CURLINFO_*` id, this is a
    /// zero-cost cast. Round-trips with [`from_raw`](Self::from_raw).
    #[inline]
    #[must_use]
    pub const fn as_raw(self) -> i32 {
        self as i32
    }

    /// Returns the result-type group of this info (its `CURLINFO_TYPEMASK`
    /// classification).
    ///
    /// The FFI crate uses this to choose the C out-pointer type for the trailing
    /// `va_arg`. Total and infallible: every variant's discriminant carries a
    /// valid type-group mask by construction (verified by unit tests).
    #[inline]
    #[must_use]
    pub const fn type_group(self) -> InfoType {
        match InfoType::from_mask(self as i32) {
            Some(t) => t,
            // Unreachable: every CurlInfo discriminant has a valid type mask.
            // Pinned by the `type_group_is_total` unit test.
            None => InfoType::Long,
        }
    }

    /// Builds a [`CurlInfo`] from a raw C `CURLINFO` integer.
    ///
    /// Returns [`None`] for any unrecognized id — including `CURLINFO_NONE`
    /// (`0`), retired ids, and out-of-range integers — which the FFI layer maps
    /// to `CURLE_UNKNOWN_OPTION`, matching C's `Curl_getinfo` default arm.
    /// Round-trips with [`as_raw`](Self::as_raw) for every variant.
    #[must_use]
    pub const fn from_raw(raw: i32) -> Option<CurlInfo> {
        // The match mirrors the variant declaration order above. Keeping the two
        // in lock-step is what guarantees the round-trip property.
        let info = match raw {
            x if x == CurlInfo::EffectiveUrl as i32 => CurlInfo::EffectiveUrl,
            x if x == CurlInfo::ResponseCode as i32 => CurlInfo::ResponseCode,
            x if x == CurlInfo::TotalTime as i32 => CurlInfo::TotalTime,
            x if x == CurlInfo::NamelookupTime as i32 => CurlInfo::NamelookupTime,
            x if x == CurlInfo::ConnectTime as i32 => CurlInfo::ConnectTime,
            x if x == CurlInfo::PretransferTime as i32 => CurlInfo::PretransferTime,
            x if x == CurlInfo::SizeUpload as i32 => CurlInfo::SizeUpload,
            x if x == CurlInfo::SizeUploadT as i32 => CurlInfo::SizeUploadT,
            x if x == CurlInfo::SizeDownload as i32 => CurlInfo::SizeDownload,
            x if x == CurlInfo::SizeDownloadT as i32 => CurlInfo::SizeDownloadT,
            x if x == CurlInfo::SpeedDownload as i32 => CurlInfo::SpeedDownload,
            x if x == CurlInfo::SpeedDownloadT as i32 => CurlInfo::SpeedDownloadT,
            x if x == CurlInfo::SpeedUpload as i32 => CurlInfo::SpeedUpload,
            x if x == CurlInfo::SpeedUploadT as i32 => CurlInfo::SpeedUploadT,
            x if x == CurlInfo::HeaderSize as i32 => CurlInfo::HeaderSize,
            x if x == CurlInfo::RequestSize as i32 => CurlInfo::RequestSize,
            x if x == CurlInfo::SslVerifyResult as i32 => CurlInfo::SslVerifyResult,
            x if x == CurlInfo::Filetime as i32 => CurlInfo::Filetime,
            x if x == CurlInfo::FiletimeT as i32 => CurlInfo::FiletimeT,
            x if x == CurlInfo::ContentLengthDownload as i32 => CurlInfo::ContentLengthDownload,
            x if x == CurlInfo::ContentLengthDownloadT as i32 => CurlInfo::ContentLengthDownloadT,
            x if x == CurlInfo::ContentLengthUpload as i32 => CurlInfo::ContentLengthUpload,
            x if x == CurlInfo::ContentLengthUploadT as i32 => CurlInfo::ContentLengthUploadT,
            x if x == CurlInfo::StarttransferTime as i32 => CurlInfo::StarttransferTime,
            x if x == CurlInfo::ContentType as i32 => CurlInfo::ContentType,
            x if x == CurlInfo::RedirectTime as i32 => CurlInfo::RedirectTime,
            x if x == CurlInfo::RedirectCount as i32 => CurlInfo::RedirectCount,
            x if x == CurlInfo::Private as i32 => CurlInfo::Private,
            x if x == CurlInfo::HttpConnectCode as i32 => CurlInfo::HttpConnectCode,
            x if x == CurlInfo::HttpAuthAvail as i32 => CurlInfo::HttpAuthAvail,
            x if x == CurlInfo::ProxyAuthAvail as i32 => CurlInfo::ProxyAuthAvail,
            x if x == CurlInfo::OsErrno as i32 => CurlInfo::OsErrno,
            x if x == CurlInfo::NumConnects as i32 => CurlInfo::NumConnects,
            x if x == CurlInfo::SslEngines as i32 => CurlInfo::SslEngines,
            x if x == CurlInfo::CookieList as i32 => CurlInfo::CookieList,
            x if x == CurlInfo::LastSocket as i32 => CurlInfo::LastSocket,
            x if x == CurlInfo::FtpEntryPath as i32 => CurlInfo::FtpEntryPath,
            x if x == CurlInfo::RedirectUrl as i32 => CurlInfo::RedirectUrl,
            x if x == CurlInfo::PrimaryIp as i32 => CurlInfo::PrimaryIp,
            x if x == CurlInfo::AppconnectTime as i32 => CurlInfo::AppconnectTime,
            x if x == CurlInfo::Certinfo as i32 => CurlInfo::Certinfo,
            x if x == CurlInfo::ConditionUnmet as i32 => CurlInfo::ConditionUnmet,
            x if x == CurlInfo::RtspSessionId as i32 => CurlInfo::RtspSessionId,
            x if x == CurlInfo::RtspClientCseq as i32 => CurlInfo::RtspClientCseq,
            x if x == CurlInfo::RtspServerCseq as i32 => CurlInfo::RtspServerCseq,
            x if x == CurlInfo::RtspCseqRecv as i32 => CurlInfo::RtspCseqRecv,
            x if x == CurlInfo::PrimaryPort as i32 => CurlInfo::PrimaryPort,
            x if x == CurlInfo::LocalIp as i32 => CurlInfo::LocalIp,
            x if x == CurlInfo::LocalPort as i32 => CurlInfo::LocalPort,
            x if x == CurlInfo::TlsSession as i32 => CurlInfo::TlsSession,
            x if x == CurlInfo::ActiveSocket as i32 => CurlInfo::ActiveSocket,
            x if x == CurlInfo::TlsSslPtr as i32 => CurlInfo::TlsSslPtr,
            x if x == CurlInfo::HttpVersion as i32 => CurlInfo::HttpVersion,
            x if x == CurlInfo::ProxySslVerifyResult as i32 => CurlInfo::ProxySslVerifyResult,
            x if x == CurlInfo::Protocol as i32 => CurlInfo::Protocol,
            x if x == CurlInfo::Scheme as i32 => CurlInfo::Scheme,
            x if x == CurlInfo::TotalTimeT as i32 => CurlInfo::TotalTimeT,
            x if x == CurlInfo::NamelookupTimeT as i32 => CurlInfo::NamelookupTimeT,
            x if x == CurlInfo::ConnectTimeT as i32 => CurlInfo::ConnectTimeT,
            x if x == CurlInfo::PretransferTimeT as i32 => CurlInfo::PretransferTimeT,
            x if x == CurlInfo::StarttransferTimeT as i32 => CurlInfo::StarttransferTimeT,
            x if x == CurlInfo::RedirectTimeT as i32 => CurlInfo::RedirectTimeT,
            x if x == CurlInfo::AppconnectTimeT as i32 => CurlInfo::AppconnectTimeT,
            x if x == CurlInfo::RetryAfter as i32 => CurlInfo::RetryAfter,
            x if x == CurlInfo::EffectiveMethod as i32 => CurlInfo::EffectiveMethod,
            x if x == CurlInfo::ProxyError as i32 => CurlInfo::ProxyError,
            x if x == CurlInfo::Referer as i32 => CurlInfo::Referer,
            x if x == CurlInfo::CaInfo as i32 => CurlInfo::CaInfo,
            x if x == CurlInfo::CaPath as i32 => CurlInfo::CaPath,
            x if x == CurlInfo::XferId as i32 => CurlInfo::XferId,
            x if x == CurlInfo::ConnId as i32 => CurlInfo::ConnId,
            x if x == CurlInfo::QueueTimeT as i32 => CurlInfo::QueueTimeT,
            x if x == CurlInfo::UsedProxy as i32 => CurlInfo::UsedProxy,
            x if x == CurlInfo::PosttransferTimeT as i32 => CurlInfo::PosttransferTimeT,
            x if x == CurlInfo::EarlydataSentT as i32 => CurlInfo::EarlydataSentT,
            x if x == CurlInfo::HttpAuthUsed as i32 => CurlInfo::HttpAuthUsed,
            x if x == CurlInfo::ProxyAuthUsed as i32 => CurlInfo::ProxyAuthUsed,
            _ => return None,
        };
        Some(info)
    }
}

// ===========================================================================
// Supporting value types
// ===========================================================================

/// The effective request method, used to compute `CURLINFO_EFFECTIVE_METHOD`.
///
/// Mirrors the relevant `HTTPREQ_*` states of `lib/getinfo.c`'s
/// `CURLINFO_EFFECTIVE_METHOD` case: when no explicit custom request is set, the
/// method string is derived from this (with `POST`-family requests all
/// collapsing to `Post`, as they do in C).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum HttpMethod {
    /// `GET` — the default.
    #[default]
    Get,
    /// `HEAD`.
    Head,
    /// `POST` (covers C's `HTTPREQ_POST`, `HTTPREQ_POST_FORM`, and
    /// `HTTPREQ_POST_MIME`).
    Post,
    /// `PUT`.
    Put,
}

impl HttpMethod {
    /// Returns the canonical, uppercased method name as a `&'static CStr`.
    #[inline]
    #[must_use]
    pub fn as_cstr(self) -> &'static CStr {
        match self {
            HttpMethod::Get => cstr_lit(b"GET\0"),
            HttpMethod::Head => cstr_lit(b"HEAD\0"),
            HttpMethod::Post => cstr_lit(b"POST\0"),
            HttpMethod::Put => cstr_lit(b"PUT\0"),
        }
    }
}

/// Certificate-chain information — the safe model of `struct curl_certinfo`
/// (`include/curl/curl.h`) returned by `CURLINFO_CERTINFO`.
///
/// C's `curl_certinfo` is `{ int num_of_certs; struct curl_slist **certinfo; }`:
/// an array of per-certificate string lists, each entry of the form
/// `"name:content"` (e.g. `"Subject:..."`, `"Issuer:..."`). Here that is an
/// owned `Vec<SList>` — one [`SList`] per certificate, in chain order. The FFI
/// crate materializes the `#[repr(C)] curl_certinfo` (and the backing
/// `curl_slist*` array) from a borrow of this when answering `CURLINFO_CERTINFO`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertInfo {
    /// One string list per certificate in the verified chain, leaf first.
    certs: Vec<SList>,
}

impl CertInfo {
    /// Creates an empty certificate-info set (`num_of_certs == 0`).
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        CertInfo { certs: Vec::new() }
    }

    /// Returns the number of certificates — C's `num_of_certs`.
    #[inline]
    #[must_use]
    pub fn num_of_certs(&self) -> usize {
        self.certs.len()
    }

    /// Returns `true` if no certificate information is present.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }

    /// Borrows the per-certificate string lists, in chain order.
    #[inline]
    #[must_use]
    pub fn certs(&self) -> &[SList] {
        &self.certs
    }

    /// Appends the string list for one more certificate (chain order).
    #[inline]
    pub fn push(&mut self, cert: SList) {
        self.certs.push(cert);
    }

    /// Removes all certificate information — the analog of
    /// `Curl_ssl_free_certinfo` invoked by C's `Curl_initinfo`.
    #[inline]
    pub fn clear(&mut self) {
        self.certs.clear();
    }
}

/// TLS backend / session information — the safe model of
/// `struct curl_tlssessioninfo` (`include/curl/curl.h`) returned by
/// `CURLINFO_TLS_SSL_PTR` and the deprecated `CURLINFO_TLS_SESSION`.
///
/// C's struct is `{ curl_sslbackend backend; void *internals; }`. The safe core
/// records the backend id and keeps `internals` as a plain [`usize`] (a raw
/// pointer value, `0` for "none") so the store never dereferences anything and
/// stays `Send`/`Sync`. In this workspace the backend is always rustls; the C
/// code likewise reports `Curl_ssl_backend()` when no live handle is exposed,
/// and rustls does not expose a stable internal handle, so `internals` is `0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TlsSessionInfo {
    backend: i32,
    internals: usize,
}

impl TlsSessionInfo {
    /// Creates a session-info value reporting the rustls backend with no
    /// exposed internal handle (`internals == 0`) — the workspace default.
    #[inline]
    #[must_use]
    pub const fn rustls() -> Self {
        TlsSessionInfo {
            backend: CURLSSLBACKEND_RUSTLS,
            internals: 0,
        }
    }

    /// Creates a session-info value reporting no backend
    /// (`CURLSSLBACKEND_NONE`).
    #[inline]
    #[must_use]
    pub const fn none() -> Self {
        TlsSessionInfo {
            backend: CURLSSLBACKEND_NONE,
            internals: 0,
        }
    }

    /// Returns the `curl_sslbackend` id (e.g. `CURLSSLBACKEND_RUSTLS == 14`).
    #[inline]
    #[must_use]
    pub const fn backend(&self) -> i32 {
        self.backend
    }

    /// Returns the opaque `internals` pointer value (`0` for none).
    #[inline]
    #[must_use]
    pub const fn internals(&self) -> usize {
        self.internals
    }

    /// Sets the opaque `internals` pointer value.
    #[inline]
    pub fn set_internals(&mut self, internals: usize) {
        self.internals = internals;
    }
}

impl Default for TlsSessionInfo {
    /// The workspace default is the rustls backend with no exposed internals.
    #[inline]
    fn default() -> Self {
        TlsSessionInfo::rustls()
    }
}

/// A pointer-typed `CURLINFO` result — the safe contents of an [`InfoValue::Ptr`].
///
/// Groups the three `CURLINFO_PTR`/`CURLINFO_STRING`-pointer results that the
/// FFI writes through a `void**`-shaped (or, for [`Private`](Self::Private), a
/// `char**`-shaped) out-pointer. Distinguishing the concrete pointee is the
/// FFI's job, keyed on the originating [`CurlInfo`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfoPtr<'a> {
    /// `CURLINFO_PRIVATE` — the opaque user pointer previously set via
    /// `CURLOPT_PRIVATE`, as a raw address (`0` == `NULL`). The FFI writes it,
    /// unchanged, through the caller's `char**`/`void**` out-pointer. Although
    /// `CURLINFO_PRIVATE` is classified `CURLINFO_STRING`, its value is an
    /// opaque pointer, not a C string — so it is represented here, not in
    /// [`InfoValue::Str`].
    Private(usize),
    /// `CURLINFO_CERTINFO` — a borrow of the handle-owned certificate chain
    /// info. The FFI builds the `#[repr(C)] curl_certinfo` from it.
    CertInfo(&'a CertInfo),
    /// `CURLINFO_TLS_SSL_PTR` / `CURLINFO_TLS_SESSION` — TLS backend/session
    /// info. The FFI builds the `#[repr(C)] curl_tlssessioninfo` from it.
    TlsSession(&'a TlsSessionInfo),
}

/// A strongly-typed `CURLINFO` result value.
///
/// The variant is determined by the queried [`CurlInfo`]'s
/// [`type_group`](CurlInfo::type_group); the FFI crate matches on it and writes
/// the contained value through the caller's trailing out-pointer using the
/// corresponding C type:
///
/// | Variant | C out-pointer type | Notes |
/// |---------|--------------------|-------|
/// | [`Long`](Self::Long) | `long*` | narrowed to the platform `long` |
/// | [`OffT`](Self::OffT) | `curl_off_t*` | |
/// | [`Double`](Self::Double) | `double*` | |
/// | [`Str`](Self::Str) | `char**` | [`None`] → `NULL`; borrow valid until next call/cleanup |
/// | [`Slist`](Self::Slist) | `struct curl_slist**` | [`None`] → `NULL` |
/// | [`Socket`](Self::Socket) | `curl_socket_t*` | |
/// | [`Ptr`](Self::Ptr) | `void**` / `char**` | see [`InfoPtr`] |
///
/// All borrows (`&'a CStr`, `&'a SList`, the references inside [`InfoPtr`]) are
/// tied to the `&'a Info` passed to [`retrieve`], enforcing the owned-string
/// lifetime contract at compile time.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InfoValue<'a> {
    /// A `CURLINFO_LONG` result.
    Long(i64),
    /// A `CURLINFO_OFF_T` result.
    OffT(i64),
    /// A `CURLINFO_DOUBLE` result.
    Double(f64),
    /// A `CURLINFO_STRING` result; [`None`] represents a `NULL` `char*`.
    Str(Option<&'a CStr>),
    /// A `CURLINFO_SLIST` result; [`None`] represents a `NULL` `curl_slist*`.
    Slist(Option<&'a SList>),
    /// A `CURLINFO_SOCKET` result.
    Socket(CurlSocket),
    /// A `CURLINFO_PTR` (or pointer-valued `CURLINFO_STRING`) result.
    Ptr(InfoPtr<'a>),
}

/// Validates and returns a compile-time `b"...\0"` byte literal as a
/// `&'static CStr`.
///
/// Used for the static method-name strings of `CURLINFO_EFFECTIVE_METHOD`. This
/// is `unsafe`-free (unlike `CStr::from_ptr`) and avoids the C-string literal
/// syntax (`c"..."`), which is newer than the workspace MSRV (1.75). The input
/// is always a literal authored in this module, so the NUL-termination
/// precondition holds by construction; a violation is a programming error and
/// panics, but cannot occur for the call sites here (covered by unit tests).
#[inline]
#[must_use]
fn cstr_lit(bytes_with_nul: &'static [u8]) -> &'static CStr {
    match CStr::from_bytes_with_nul(bytes_with_nul) {
        Ok(s) => s,
        Err(_) => panic!("getinfo: internal C-string literal is not NUL-terminated"),
    }
}

// ===========================================================================
// Info — the handle-owned info store
// ===========================================================================

/// The handle-owned store of every value `curl_easy_getinfo` can report.
///
/// In C these fields are spread across `struct Curl_easy`'s `info`
/// (`struct PureInfo`), `progress` (`struct Progress`), `state`, and `set`
/// sub-structs; here they are gathered into one owned struct that the easy
/// handle embeds. The transfer, progress, DNS, TLS, and setopt engines **write**
/// these fields as a transfer proceeds; [`retrieve`] only **reads** them.
///
/// Fields are `pub` so the engines can populate them directly, exactly as curl's
/// C code assigns into `data->info.*` / `data->progress.*`. The owned
/// [`CString`]/[`SList`] string fields back the values returned by reference
/// from [`retrieve`], satisfying the owned-string lifetime contract
/// (AAP §0.7.1): a returned `&CStr` stays valid until the field is next
/// overwritten (the next call/transfer) or the handle is dropped.
///
/// # Units
///
/// All `*_us` time fields are **microseconds** (matching curl's internal
/// `curl_off_t` timers). [`retrieve`] reports the `CURLINFO_*_TIME` doubles as
/// seconds (`microseconds / 1_000_000.0`) and the `CURLINFO_*_TIME_T` integers
/// as the raw microseconds, so both forms of a timer are always consistent.
#[derive(Debug, Clone, PartialEq)]
pub struct Info {
    // ---- PureInfo-derived (C: data->info) --------------------------------
    /// Last HTTP response code (C: `info.httpcode`). `CURLINFO_RESPONSE_CODE`.
    pub response_code: i64,
    /// Last proxy `CONNECT` response code (C: `info.httpproxycode`).
    pub http_connect_code: i64,
    /// Negotiated HTTP version in curl's internal encoding: `0` (none), `10`,
    /// `11`, `20`, or `30` (C: `info.httpversion`). Mapped to a
    /// `CURL_HTTP_VERSION_*` value by `CURLINFO_HTTP_VERSION`.
    pub http_version: i64,
    /// Remote file modification time (Unix epoch seconds), or `-1` if unknown
    /// (C: `info.filetime`). `CURLINFO_FILETIME` / `CURLINFO_FILETIME_T`.
    pub filetime: i64,
    /// Whether a time-conditional request prevented the transfer
    /// (C: `info.timecond`). Feeds `CURLINFO_CONDITION_UNMET`.
    pub timecond: bool,
    /// Total size of all received headers (C: `info.header_size`).
    pub header_size: i64,
    /// Internal scratch: the byte total of a proxy `CONNECT` response's header
    /// lines (status line + headers + the terminating blank line), captured once
    /// per established tunnel. curl folds these into `info.header_size` via
    /// `Curl_bump_headersize` in `single_header` (lib/cf-h1-proxy.c) REGARDLESS
    /// of `--suppress-connect-headers` (which hides them from display/dump only,
    /// not from the byte statistics). The transfer engine adds this to the origin
    /// response's header bytes when publishing `CURLINFO_HEADER_SIZE`
    /// (`%{size_header}`). Not itself exposed as a `CURLINFO_*` value (oracle:
    /// tests/data/test1288).
    pub connect_header_size: i64,
    /// Total size of all issued requests (C: `info.request_size`).
    pub request_size: i64,
    /// Bitmask of HTTP auth methods the server offered
    /// (C: `info.httpauthavail`). `CURLINFO_HTTPAUTH_AVAIL`.
    pub httpauth_avail: i64,
    /// Bitmask of proxy auth methods the proxy offered
    /// (C: `info.proxyauthavail`). `CURLINFO_PROXYAUTH_AVAIL`.
    pub proxyauth_avail: i64,
    /// Bitmask of the HTTP auth method actually used
    /// (C: `info.httpauthpicked`). `CURLINFO_HTTPAUTH_USED`.
    pub httpauth_used: i64,
    /// Bitmask of the proxy auth method actually used
    /// (C: `info.proxyauthpicked`). `CURLINFO_PROXYAUTH_USED`.
    pub proxyauth_used: i64,
    /// Number of new connections created for the transfer
    /// (C: `info.numconnects`). `CURLINFO_NUM_CONNECTS`.
    pub num_connects: i64,
    /// `Content-Type` of the downloaded object (C: `info.contenttype`), owned.
    pub content_type: Option<CString>,
    /// URL a redirect would have gone to had following been disabled
    /// (C: `info.wouldredirect`), owned. `CURLINFO_REDIRECT_URL`.
    pub redirect_url: Option<CString>,
    /// `Retry-After` value in seconds (C: `info.retry_after`).
    pub retry_after: i64,
    /// URL scheme used, lower-cased (C: `info.conn_scheme = conn->scheme->name`,
    /// the lowercase `Curl_scheme.name`), owned.
    pub scheme: Option<CString>,
    /// Protocol used, as a `CURLPROTO_*` bit (C: `info.conn_protocol`).
    /// `CURLINFO_PROTOCOL` (deprecated).
    pub conn_protocol: i64,
    /// Whether the transfer used a proxy (C: `info.used_proxy`, `0`/`1`).
    pub used_proxy: i64,
    /// Detailed proxy error, a `CURLproxycode` (C: `info.pxcode`).
    pub proxy_error: i64,
    /// Remote IP of the primary connection (C: `info.primary.remote_ip`), owned.
    pub primary_ip: Option<CString>,
    /// Local IP of the primary connection (C: `info.primary.local_ip`), owned.
    pub local_ip: Option<CString>,
    /// Remote port of the primary connection (C: `info.primary.remote_port`).
    /// Only reported when [`primary_has_ports`](Self::primary_has_ports) is set;
    /// otherwise `CURLINFO_PRIMARY_PORT` reports `-1`.
    pub primary_port: i64,
    /// Local port of the primary connection (C: `info.primary.local_port`).
    /// Gated by [`primary_has_ports`](Self::primary_has_ports) as above.
    pub local_port: i64,
    /// Whether the primary connection has known ports
    /// (C: `CUR_IP_QUAD_HAS_PORTS(&info.primary)`).
    pub primary_has_ports: bool,
    /// Certificate chain information (C: `info.certs`). `CURLINFO_CERTINFO`.
    pub certinfo: CertInfo,

    // ---- set-derived TLS verify results (C: data->set.ssl / proxy_ssl) ---
    /// Certificate verification result (C: `set.ssl.certverifyresult`).
    /// `CURLINFO_SSL_VERIFYRESULT`.
    pub ssl_verifyresult: i64,
    /// Proxy certificate verification result
    /// (C: `set.proxy_ssl.certverifyresult`).
    pub proxy_ssl_verifyresult: i64,

    // ---- Progress-derived (C: data->progress); times in microseconds -----
    /// Total transfer time (C: `progress.timespent`). `CURLINFO_TOTAL_TIME(_T)`.
    pub total_time_us: i64,
    /// Name-resolution time (C: `progress.t_nslookup`).
    pub namelookup_time_us: i64,
    /// TCP connect time (C: `progress.t_connect`).
    pub connect_time_us: i64,
    /// App-layer (TLS/SSH) handshake time (C: `progress.t_appconnect`).
    pub appconnect_time_us: i64,
    /// Pre-transfer time (C: `progress.t_pretransfer`).
    pub pretransfer_time_us: i64,
    /// Post-transfer time, request start → last byte sent
    /// (C: `progress.t_posttransfer`).
    pub posttransfer_time_us: i64,
    /// Start-transfer time, until first byte (C: `progress.t_starttransfer`).
    pub starttransfer_time_us: i64,
    /// Time spent in redirects (C: `progress.t_redirect`).
    pub redirect_time_us: i64,
    /// Time the transfer spent queued (C: `progress.t_postqueue`).
    /// `CURLINFO_QUEUE_TIME_T`.
    pub queue_time_us: i64,
    /// TLS early-data bytes sent (C: `progress.earlydata_sent`).
    /// `CURLINFO_EARLYDATA_SENT_T`.
    pub earlydata_sent: i64,
    /// Bytes uploaded so far (C: `progress.ul.cur_size`).
    /// `CURLINFO_SIZE_UPLOAD(_T)`.
    pub size_upload: i64,
    /// Bytes downloaded so far (C: `progress.dl.cur_size`).
    /// `CURLINFO_SIZE_DOWNLOAD(_T)`.
    pub size_download: i64,
    /// Download speed, bytes/second (C: `progress.dl.speed`).
    pub speed_download: i64,
    /// Upload speed, bytes/second (C: `progress.ul.speed`).
    pub speed_upload: i64,
    /// Total expected download size (C: `progress.dl.total_size`); only reported
    /// when [`dl_size_known`](Self::dl_size_known) is set.
    pub content_length_download: i64,
    /// Total expected upload size (C: `progress.ul.total_size`); only reported
    /// when [`ul_size_known`](Self::ul_size_known) is set.
    pub content_length_upload: i64,
    /// Whether the download's total size is known (C: `progress.dl_size_known`).
    /// When `false`, `CURLINFO_CONTENT_LENGTH_DOWNLOAD(_T)` reports `-1`.
    pub dl_size_known: bool,
    /// Whether the upload's total size is known (C: `progress.ul_size_known`).
    /// When `false`, `CURLINFO_CONTENT_LENGTH_UPLOAD(_T)` reports `-1`.
    pub ul_size_known: bool,

    // ---- state-derived (C: data->state) ----------------------------------
    /// The last effective URL (C: `state.url`), owned. `CURLINFO_EFFECTIVE_URL`.
    /// When unset, `CURLINFO_EFFECTIVE_URL` reports the empty string (matching
    /// C, which returns `""` for a `NULL` url).
    pub effective_url: Option<CString>,
    /// The `Referer:` header that was sent (C: `state.referer`), owned.
    pub referer: Option<CString>,
    /// The FTP entry path of the most recent connection
    /// (C: `state.most_recent_ftp_entrypath`), owned.
    pub ftp_entry_path: Option<CString>,
    /// Number of redirects followed (C: `state.followlocation`).
    /// `CURLINFO_REDIRECT_COUNT`.
    pub redirect_count: i64,
    /// The errno of the last failure, if any (C: `state.os_errno`).
    pub os_errno: i64,
    /// Next RTSP client `CSeq` (C: `state.rtsp_next_client_CSeq`).
    pub rtsp_client_cseq: i64,
    /// Next RTSP server `CSeq` (C: `state.rtsp_next_server_CSeq`).
    pub rtsp_server_cseq: i64,
    /// Last received RTSP `CSeq` (C: `state.rtsp_CSeq_recv`).
    pub rtsp_cseq_recv: i64,
    /// The request method, used to compute `CURLINFO_EFFECTIVE_METHOD` when no
    /// custom request is set (C: `state.httpreq`).
    pub method: HttpMethod,

    // ---- set-derived (C: data->set) --------------------------------------
    /// An explicit custom request method set via `CURLOPT_CUSTOMREQUEST`
    /// (C: `set.str[STRING_CUSTOMREQUEST]`), owned. Takes precedence in
    /// `CURLINFO_EFFECTIVE_METHOD`.
    pub custom_request: Option<CString>,
    /// Whether a body-less request was requested via `CURLOPT_NOBODY`
    /// (C: `set.opt_no_body`). Forces `HEAD` in `CURLINFO_EFFECTIVE_METHOD`.
    pub opt_no_body: bool,
    /// The opaque user pointer from `CURLOPT_PRIVATE` (C: `set.private_data`),
    /// as a raw address; `0` means unset/`NULL`. `CURLINFO_PRIVATE`.
    pub private_ptr: usize,
    /// The RTSP session id (C: `set.str[STRING_RTSP_SESSION_ID]`), owned.
    pub rtsp_session_id: Option<CString>,
    /// The default CA bundle path, if any, owned. `CURLINFO_CAINFO`.
    ///
    /// In C this returns the **build-time** `CURL_CA_BUNDLE` constant (or `NULL`).
    /// This rustls-based workspace has no compile-time CA bundle, so the default
    /// is [`None`] (reported as a `NULL` `char*`); the field exists so a
    /// configured value can be surfaced if one is ever set.
    pub cainfo: Option<CString>,
    /// The default CA directory path, if any, owned. `CURLINFO_CAPATH`. Same
    /// build-time semantics and default as [`cainfo`](Self::cainfo).
    pub capath: Option<CString>,
    /// Available SSL crypto engines (C: `Curl_ssl_engines_list`).
    /// `CURLINFO_SSL_ENGINES`. Empty in a rustls build (no engine concept), in
    /// which case the info reports a `NULL` list — matching C.
    pub ssl_engines: SList,
    /// All known cookies in Netscape format (C: `Curl_cookie_list`).
    /// `CURLINFO_COOKIELIST`. Empty reports a `NULL` list, matching C.
    pub cookielist: SList,

    // ---- identifiers / sockets / TLS (C: data->id, data->conn, data->tsi) -
    /// The transfer's unique identifier (C: `data->id`); `-1` until assigned.
    /// `CURLINFO_XFER_ID`.
    pub xfer_id: i64,
    /// The connection's unique identifier (C: `conn->connection_id` /
    /// `state.recent_conn_id`); `-1` until assigned. `CURLINFO_CONN_ID`.
    pub conn_id: i64,
    /// The active socket (C: `Curl_getconnectinfo`), or [`CURL_SOCKET_BAD`] when
    /// there is no active connection. `CURLINFO_ACTIVESOCKET` /
    /// `CURLINFO_LASTSOCKET`.
    pub active_socket: CurlSocket,
    /// TLS backend / session info (C: `data->tsi`). `CURLINFO_TLS_SSL_PTR` /
    /// `CURLINFO_TLS_SESSION`.
    pub tls_session: TlsSessionInfo,
}

impl Info {
    /// Creates a fresh info store with curl's documented initial values.
    ///
    /// Mirrors the post-`Curl_initinfo` state for the session fields and the
    /// natural zero/empty defaults for the option-derived fields:
    /// [`filetime`](Self::filetime) is `-1` ("unknown"), the identifiers are
    /// `-1` ("unassigned"), [`active_socket`](Self::active_socket) is
    /// [`CURL_SOCKET_BAD`], and [`tls_session`](Self::tls_session) reports the
    /// rustls backend.
    #[must_use]
    pub const fn new() -> Self {
        Info {
            // PureInfo-derived
            response_code: 0,
            http_connect_code: 0,
            http_version: 0,
            filetime: -1,
            timecond: false,
            header_size: 0,
            connect_header_size: 0,
            request_size: 0,
            httpauth_avail: 0,
            proxyauth_avail: 0,
            httpauth_used: 0,
            proxyauth_used: 0,
            num_connects: 0,
            content_type: None,
            redirect_url: None,
            retry_after: 0,
            scheme: None,
            conn_protocol: 0,
            used_proxy: 0,
            proxy_error: 0,
            primary_ip: None,
            local_ip: None,
            primary_port: 0,
            local_port: 0,
            primary_has_ports: false,
            certinfo: CertInfo::new(),
            // set-derived TLS verify
            ssl_verifyresult: 0,
            proxy_ssl_verifyresult: 0,
            // Progress-derived (microseconds)
            total_time_us: 0,
            namelookup_time_us: 0,
            connect_time_us: 0,
            appconnect_time_us: 0,
            pretransfer_time_us: 0,
            posttransfer_time_us: 0,
            starttransfer_time_us: 0,
            redirect_time_us: 0,
            queue_time_us: 0,
            earlydata_sent: 0,
            size_upload: 0,
            size_download: 0,
            speed_download: 0,
            speed_upload: 0,
            content_length_download: 0,
            content_length_upload: 0,
            dl_size_known: false,
            ul_size_known: false,
            // state-derived
            effective_url: None,
            referer: None,
            ftp_entry_path: None,
            redirect_count: 0,
            os_errno: 0,
            rtsp_client_cseq: 0,
            rtsp_server_cseq: 0,
            rtsp_cseq_recv: 0,
            method: HttpMethod::Get,
            // set-derived
            custom_request: None,
            opt_no_body: false,
            private_ptr: 0,
            rtsp_session_id: None,
            cainfo: None,
            capath: None,
            ssl_engines: SList::new(),
            cookielist: SList::new(),
            // identifiers / sockets / TLS
            xfer_id: -1,
            conn_id: -1,
            active_socket: CURL_SOCKET_BAD,
            tls_session: TlsSessionInfo::rustls(),
        }
    }

    /// Resets the **session** information, mirroring C's `Curl_initinfo`.
    ///
    /// `Curl_initinfo` is called from `curl_easy_reset`, `curl_easy_duphandle`,
    /// and at the start of every transfer; it clears the `progress` timers and
    /// the `PureInfo` results **only**. This method matches that scope exactly:
    /// it does **not** touch the option-derived fields ([`custom_request`],
    /// [`opt_no_body`], [`private_ptr`], [`cainfo`]/[`capath`],
    /// [`ssl_verifyresult`]/[`proxy_ssl_verifyresult`]) or the `state`-derived
    /// fields (`effective_url`, `referer`, `redirect_count`, the RTSP `CSeq`s),
    /// which C resets elsewhere.
    ///
    /// [`custom_request`]: Self::custom_request
    /// [`opt_no_body`]: Self::opt_no_body
    /// [`private_ptr`]: Self::private_ptr
    /// [`cainfo`]: Self::cainfo
    /// [`capath`]: Self::capath
    /// [`ssl_verifyresult`]: Self::ssl_verifyresult
    /// [`proxy_ssl_verifyresult`]: Self::proxy_ssl_verifyresult
    pub fn reset(&mut self) {
        // progress timers (C: struct Progress)
        self.namelookup_time_us = 0;
        self.connect_time_us = 0;
        self.appconnect_time_us = 0;
        self.pretransfer_time_us = 0;
        self.posttransfer_time_us = 0;
        self.starttransfer_time_us = 0;
        self.total_time_us = 0;
        self.redirect_time_us = 0;

        // PureInfo results (C: struct PureInfo)
        self.response_code = 0;
        self.http_connect_code = 0;
        self.http_version = 0;
        self.filetime = -1; // -1 is an illegal time and thus means "unknown"
        self.timecond = false;
        self.header_size = 0;
        self.connect_header_size = 0;
        self.request_size = 0;
        self.proxyauth_avail = 0;
        self.httpauth_avail = 0;
        self.proxyauth_used = 0;
        self.httpauth_used = 0;
        self.num_connects = 0;
        self.content_type = None;
        self.redirect_url = None;
        self.primary_ip = None;
        self.local_ip = None;
        self.primary_port = 0;
        self.local_port = 0;
        self.primary_has_ports = false;
        self.retry_after = 0;
        self.scheme = None;
        self.conn_protocol = 0;
        self.certinfo.clear();
    }

    /// Convenience method equivalent to [`retrieve(self, which)`](retrieve).
    ///
    /// Lets the easy handle write `self.info.get(which)` instead of
    /// `getinfo::retrieve(&self.info, which)`.
    ///
    /// # Errors
    ///
    /// Propagates the same errors as [`retrieve`].
    #[inline]
    pub fn get(&self, which: CurlInfo) -> Result<InfoValue<'_>> {
        retrieve(self, which)
    }
}

impl Default for Info {
    #[inline]
    fn default() -> Self {
        Info::new()
    }
}

// ===========================================================================
// retrieve — the central dispatch (mirrors lib/getinfo.c)
// ===========================================================================

/// Converts a microsecond timer to seconds, mirroring C's
/// `DOUBLE_SECS(x) = (double)(x) / 1000000`.
#[inline]
fn double_secs(microseconds: i64) -> f64 {
    microseconds as f64 / 1_000_000.0
}

/// Maps curl's internal HTTP-version encoding (`0`/`10`/`11`/`20`/`30`) to the
/// `CURL_HTTP_VERSION_*` value reported by `CURLINFO_HTTP_VERSION`, mirroring
/// the `switch` in `lib/getinfo.c`.
#[inline]
fn map_http_version(internal: i64) -> i64 {
    match internal {
        10 => CURL_HTTP_VERSION_1_0,
        11 => CURL_HTTP_VERSION_1_1,
        20 => CURL_HTTP_VERSION_2_0,
        30 => CURL_HTTP_VERSION_3,
        _ => CURL_HTTP_VERSION_NONE,
    }
}

/// Retrieves a single piece of post-transfer information from the handle-owned
/// [`Info`] store — the typed core of `curl_easy_getinfo`.
///
/// This mirrors `lib/getinfo.c`'s `Curl_getinfo` dispatch field-for-field, but
/// returns a strongly-typed [`InfoValue`] instead of writing through a C
/// out-pointer. The FFI crate calls [`CurlInfo::from_raw`] to obtain `which`,
/// calls this, and then writes the result through the caller's pointer using
/// the C type implied by [`CurlInfo::type_group`].
///
/// # Owned-string lifetime
///
/// String, slist, and pointer results borrow from `info`: the returned
/// [`InfoValue`]'s lifetime `'a` is tied to `&'a Info`. The borrow checker
/// therefore guarantees the FFI cannot expose a `char*`/`curl_slist*` that
/// outlives the handle-owned buffer, satisfying curl's "valid until the next
/// call or cleanup" contract (AAP §0.7.1).
///
/// # Errors
///
/// Currently total for every defined [`CurlInfo`] (curl's default build answers
/// every defined `CURLINFO`). The [`Result`] return type is part of the stable
/// signature: unrecognized raw ids are rejected upstream by
/// [`CurlInfo::from_raw`] returning [`None`], which the FFI maps to
/// `CURLE_UNKNOWN_OPTION` exactly as C's `Curl_getinfo` does; a `NULL` handle or
/// `NULL` out-pointer is likewise rejected by the FFI as
/// `CURLE_BAD_FUNCTION_ARGUMENT` (`CurlError::BadFunctionArgument`), matching
/// the top-level checks in `Curl_getinfo`.
pub fn retrieve(info: &Info, which: CurlInfo) -> Result<InfoValue<'_>> {
    use CurlInfo as I;

    let value = match which {
        // ---- CURLINFO_STRING ------------------------------------------------
        // C `getinfo_char`. Every string result is either a borrow into a
        // handle-owned CString or a `&'static` literal; `None` becomes a NULL
        // `char*` at the FFI edge.
        I::EffectiveUrl => {
            // C: `s ? s : ""` — a NULL effective URL is reported as "" (an
            // empty, non-NULL C string), never as NULL.
            let s = info
                .effective_url
                .as_deref()
                .unwrap_or_else(|| cstr_lit(b"\0"));
            InfoValue::Str(Some(s))
        }
        I::ContentType => InfoValue::Str(info.content_type.as_deref()),
        I::FtpEntryPath => InfoValue::Str(info.ftp_entry_path.as_deref()),
        I::RedirectUrl => InfoValue::Str(info.redirect_url.as_deref()),
        I::PrimaryIp => InfoValue::Str(info.primary_ip.as_deref()),
        I::RtspSessionId => InfoValue::Str(info.rtsp_session_id.as_deref()),
        I::LocalIp => InfoValue::Str(info.local_ip.as_deref()),
        I::Scheme => InfoValue::Str(info.scheme.as_deref()),
        I::Referer => InfoValue::Str(info.referer.as_deref()),
        I::CaInfo => InfoValue::Str(info.cainfo.as_deref()),
        I::CaPath => InfoValue::Str(info.capath.as_deref()),
        I::EffectiveMethod => {
            // C: custom request wins; else NOBODY forces HEAD; else the method.
            let m = match info.custom_request.as_deref() {
                Some(custom) => custom,
                None if info.opt_no_body => HttpMethod::Head.as_cstr(),
                None => info.method.as_cstr(),
            };
            InfoValue::Str(Some(m))
        }
        // CURLINFO_PRIVATE is classified STRING but its value is the opaque
        // CURLOPT_PRIVATE pointer, surfaced via InfoPtr::Private.
        I::Private => InfoValue::Ptr(InfoPtr::Private(info.private_ptr)),

        // ---- CURLINFO_LONG --------------------------------------------------
        // C `getinfo_long`.
        I::ResponseCode => InfoValue::Long(info.response_code),
        I::HttpConnectCode => InfoValue::Long(info.http_connect_code),
        // C clamps `filetime` to `[LONG_MIN, LONG_MAX]`. On every target this
        // workspace supports (all Unix LP64), `long` is 64-bit, so that clamp is
        // the identity — `filetime` already fits — and the value is returned
        // directly, exactly as C does on those platforms. FILETIME_T returns the
        // same value as a `curl_off_t`.
        I::Filetime => InfoValue::Long(info.filetime),
        I::HeaderSize => InfoValue::Long(info.header_size),
        I::RequestSize => InfoValue::Long(info.request_size),
        I::SslVerifyResult => InfoValue::Long(info.ssl_verifyresult),
        I::ProxySslVerifyResult => InfoValue::Long(info.proxy_ssl_verifyresult),
        I::RedirectCount => InfoValue::Long(info.redirect_count),
        I::HttpAuthAvail => InfoValue::Long(info.httpauth_avail),
        I::ProxyAuthAvail => InfoValue::Long(info.proxyauth_avail),
        I::HttpAuthUsed => InfoValue::Long(info.httpauth_used),
        I::ProxyAuthUsed => InfoValue::Long(info.proxyauth_used),
        I::OsErrno => InfoValue::Long(info.os_errno),
        // C clamps to `LONG_MAX` only `#if SIZEOF_LONG < SIZEOF_CURL_OFF_T`,
        // which is false on the LP64 targets — so the clamp is not even compiled
        // there and the value is returned directly.
        I::NumConnects => InfoValue::Long(info.num_connects),
        I::LastSocket => {
            // C: report the active socket as a long, or -1 if there is none.
            let v = if info.active_socket != CURL_SOCKET_BAD {
                info.active_socket
            } else {
                -1
            };
            InfoValue::Long(v)
        }
        I::PrimaryPort => {
            let v = if info.primary_has_ports {
                info.primary_port
            } else {
                -1
            };
            InfoValue::Long(v)
        }
        I::LocalPort => {
            let v = if info.primary_has_ports {
                info.local_port
            } else {
                -1
            };
            InfoValue::Long(v)
        }
        I::ProxyError => InfoValue::Long(info.proxy_error),
        I::ConditionUnmet => {
            // C: a 304 always counts as "unmet"; otherwise report whether a
            // time-conditional request suppressed the transfer.
            let v = if info.response_code == 304 || info.timecond {
                1
            } else {
                0
            };
            InfoValue::Long(v)
        }
        I::RtspClientCseq => InfoValue::Long(info.rtsp_client_cseq),
        I::RtspServerCseq => InfoValue::Long(info.rtsp_server_cseq),
        I::RtspCseqRecv => InfoValue::Long(info.rtsp_cseq_recv),
        I::HttpVersion => InfoValue::Long(map_http_version(info.http_version)),
        I::Protocol => InfoValue::Long(info.conn_protocol),
        I::UsedProxy => InfoValue::Long(info.used_proxy),

        // ---- CURLINFO_DOUBLE ------------------------------------------------
        // C `getinfo_double`. Times are reported in seconds; sizes/speeds as a
        // double of the same value the OFF_T variant reports.
        I::TotalTime => InfoValue::Double(double_secs(info.total_time_us)),
        I::NamelookupTime => InfoValue::Double(double_secs(info.namelookup_time_us)),
        I::ConnectTime => InfoValue::Double(double_secs(info.connect_time_us)),
        I::AppconnectTime => InfoValue::Double(double_secs(info.appconnect_time_us)),
        I::PretransferTime => InfoValue::Double(double_secs(info.pretransfer_time_us)),
        I::StarttransferTime => InfoValue::Double(double_secs(info.starttransfer_time_us)),
        I::RedirectTime => InfoValue::Double(double_secs(info.redirect_time_us)),
        I::SizeUpload => InfoValue::Double(info.size_upload as f64),
        I::SizeDownload => InfoValue::Double(info.size_download as f64),
        I::SpeedDownload => InfoValue::Double(info.speed_download as f64),
        I::SpeedUpload => InfoValue::Double(info.speed_upload as f64),
        I::ContentLengthDownload => {
            let v = if info.dl_size_known {
                info.content_length_download as f64
            } else {
                -1.0
            };
            InfoValue::Double(v)
        }
        I::ContentLengthUpload => {
            let v = if info.ul_size_known {
                info.content_length_upload as f64
            } else {
                -1.0
            };
            InfoValue::Double(v)
        }

        // ---- CURLINFO_OFF_T -------------------------------------------------
        // C `getinfo_offt`. Times are reported as raw microseconds.
        I::SizeUploadT => InfoValue::OffT(info.size_upload),
        I::SizeDownloadT => InfoValue::OffT(info.size_download),
        I::SpeedDownloadT => InfoValue::OffT(info.speed_download),
        I::SpeedUploadT => InfoValue::OffT(info.speed_upload),
        I::FiletimeT => InfoValue::OffT(info.filetime),
        I::ContentLengthDownloadT => {
            let v = if info.dl_size_known {
                info.content_length_download
            } else {
                -1
            };
            InfoValue::OffT(v)
        }
        I::ContentLengthUploadT => {
            let v = if info.ul_size_known {
                info.content_length_upload
            } else {
                -1
            };
            InfoValue::OffT(v)
        }
        I::TotalTimeT => InfoValue::OffT(info.total_time_us),
        I::NamelookupTimeT => InfoValue::OffT(info.namelookup_time_us),
        I::ConnectTimeT => InfoValue::OffT(info.connect_time_us),
        I::AppconnectTimeT => InfoValue::OffT(info.appconnect_time_us),
        I::PretransferTimeT => InfoValue::OffT(info.pretransfer_time_us),
        I::PosttransferTimeT => InfoValue::OffT(info.posttransfer_time_us),
        I::StarttransferTimeT => InfoValue::OffT(info.starttransfer_time_us),
        I::QueueTimeT => InfoValue::OffT(info.queue_time_us),
        I::RedirectTimeT => InfoValue::OffT(info.redirect_time_us),
        I::RetryAfter => InfoValue::OffT(info.retry_after),
        I::XferId => InfoValue::OffT(info.xfer_id),
        I::ConnId => InfoValue::OffT(info.conn_id),
        I::EarlydataSentT => InfoValue::OffT(info.earlydata_sent),

        // ---- CURLINFO_SLIST -------------------------------------------------
        // C `getinfo_slist`. An empty list is reported as a NULL `curl_slist*`,
        // matching curl (which returns NULL when there is nothing to report).
        I::SslEngines => {
            let list = if info.ssl_engines.is_empty() {
                None
            } else {
                Some(&info.ssl_engines)
            };
            InfoValue::Slist(list)
        }
        I::CookieList => {
            let list = if info.cookielist.is_empty() {
                None
            } else {
                Some(&info.cookielist)
            };
            InfoValue::Slist(list)
        }

        // ---- CURLINFO_PTR ---------------------------------------------------
        // C `getinfo_slist` (PTR shares the SLIST type group). CERTINFO always
        // yields a (possibly empty) struct pointer, matching C's `&info.certs`.
        I::Certinfo => InfoValue::Ptr(InfoPtr::CertInfo(&info.certinfo)),
        // TLS_SESSION (deprecated) and TLS_SSL_PTR report the same struct.
        I::TlsSession | I::TlsSslPtr => InfoValue::Ptr(InfoPtr::TlsSession(&info.tls_session)),

        // ---- CURLINFO_SOCKET ------------------------------------------------
        // C `getinfo_socket`.
        I::ActiveSocket => InfoValue::Socket(info.active_socket),
    };

    Ok(value)
}

/// Retrieves info by **raw** C `CURLINFO` integer — the convenience entry point
/// the FFI can use to obtain exact-`CURLcode` behavior for an unrecognized id.
///
/// This validates `raw` with [`CurlInfo::from_raw`]; an id that is not a defined
/// `CURLINFO` (including `CURLINFO_NONE == 0`, retired ids, and out-of-range
/// integers) yields [`CurlError::UnknownOption`] — exactly the
/// `CURLE_UNKNOWN_OPTION` that C's `Curl_getinfo` returns from its `default:`
/// arm. On a recognized id it forwards to [`retrieve`].
///
/// `curl-rs-ffi`'s `curl_easy_getinfo` may call this directly with the C
/// `CURLINFO` argument, or it may call [`CurlInfo::from_raw`] and [`retrieve`]
/// separately; both paths produce identical results.
///
/// # Errors
///
/// Returns [`CurlError::UnknownOption`] (`CURLE_UNKNOWN_OPTION`) if `raw` is not
/// a defined `CURLINFO` id. (A `NULL` handle or `NULL` out-pointer is detected
/// by the FFI before this is reached and reported as
/// `CURLE_BAD_FUNCTION_ARGUMENT`, matching `Curl_getinfo`.)
pub fn retrieve_raw(info: &Info, raw: i32) -> Result<InfoValue<'_>> {
    let which = CurlInfo::from_raw(raw).ok_or(CurlError::UnknownOption)?;
    retrieve(info, which)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every [`CurlInfo`] variant, in `include/curl/curl.h` declaration order.
    /// The slice length pins the variant count; iterating it gives exhaustive
    /// coverage for the round-trip and type-group properties.
    const ALL_INFOS: &[CurlInfo] = &[
        CurlInfo::EffectiveUrl,
        CurlInfo::ResponseCode,
        CurlInfo::TotalTime,
        CurlInfo::NamelookupTime,
        CurlInfo::ConnectTime,
        CurlInfo::PretransferTime,
        CurlInfo::SizeUpload,
        CurlInfo::SizeUploadT,
        CurlInfo::SizeDownload,
        CurlInfo::SizeDownloadT,
        CurlInfo::SpeedDownload,
        CurlInfo::SpeedDownloadT,
        CurlInfo::SpeedUpload,
        CurlInfo::SpeedUploadT,
        CurlInfo::HeaderSize,
        CurlInfo::RequestSize,
        CurlInfo::SslVerifyResult,
        CurlInfo::Filetime,
        CurlInfo::FiletimeT,
        CurlInfo::ContentLengthDownload,
        CurlInfo::ContentLengthDownloadT,
        CurlInfo::ContentLengthUpload,
        CurlInfo::ContentLengthUploadT,
        CurlInfo::StarttransferTime,
        CurlInfo::ContentType,
        CurlInfo::RedirectTime,
        CurlInfo::RedirectCount,
        CurlInfo::Private,
        CurlInfo::HttpConnectCode,
        CurlInfo::HttpAuthAvail,
        CurlInfo::ProxyAuthAvail,
        CurlInfo::OsErrno,
        CurlInfo::NumConnects,
        CurlInfo::SslEngines,
        CurlInfo::CookieList,
        CurlInfo::LastSocket,
        CurlInfo::FtpEntryPath,
        CurlInfo::RedirectUrl,
        CurlInfo::PrimaryIp,
        CurlInfo::AppconnectTime,
        CurlInfo::Certinfo,
        CurlInfo::ConditionUnmet,
        CurlInfo::RtspSessionId,
        CurlInfo::RtspClientCseq,
        CurlInfo::RtspServerCseq,
        CurlInfo::RtspCseqRecv,
        CurlInfo::PrimaryPort,
        CurlInfo::LocalIp,
        CurlInfo::LocalPort,
        CurlInfo::TlsSession,
        CurlInfo::ActiveSocket,
        CurlInfo::TlsSslPtr,
        CurlInfo::HttpVersion,
        CurlInfo::ProxySslVerifyResult,
        CurlInfo::Protocol,
        CurlInfo::Scheme,
        CurlInfo::TotalTimeT,
        CurlInfo::NamelookupTimeT,
        CurlInfo::ConnectTimeT,
        CurlInfo::PretransferTimeT,
        CurlInfo::StarttransferTimeT,
        CurlInfo::RedirectTimeT,
        CurlInfo::AppconnectTimeT,
        CurlInfo::RetryAfter,
        CurlInfo::EffectiveMethod,
        CurlInfo::ProxyError,
        CurlInfo::Referer,
        CurlInfo::CaInfo,
        CurlInfo::CaPath,
        CurlInfo::XferId,
        CurlInfo::ConnId,
        CurlInfo::QueueTimeT,
        CurlInfo::UsedProxy,
        CurlInfo::PosttransferTimeT,
        CurlInfo::EarlydataSentT,
        CurlInfo::HttpAuthUsed,
        CurlInfo::ProxyAuthUsed,
    ];

    /// Builds a fully-populated [`Info`] with distinctive, recognizable values
    /// so each retrieval can be checked independently.
    fn sample() -> Info {
        let mut i = Info::new();
        // strings
        i.effective_url = Some(CString::new("https://example.com/path").unwrap());
        i.content_type = Some(CString::new("text/html; charset=utf-8").unwrap());
        i.ftp_entry_path = Some(CString::new("/pub").unwrap());
        i.redirect_url = Some(CString::new("https://example.com/next").unwrap());
        i.primary_ip = Some(CString::new("93.184.216.34").unwrap());
        i.local_ip = Some(CString::new("10.0.0.2").unwrap());
        i.scheme = Some(CString::new("https").unwrap());
        i.referer = Some(CString::new("https://ref.example/").unwrap());
        i.rtsp_session_id = Some(CString::new("ABCD1234").unwrap());
        // longs
        i.response_code = 200;
        i.http_connect_code = 0;
        i.header_size = 321;
        i.request_size = 99;
        i.ssl_verifyresult = 0;
        i.proxy_ssl_verifyresult = 0;
        i.redirect_count = 1;
        i.httpauth_avail = 0x0000_0008; // CURLAUTH_NTLM
        i.proxyauth_avail = 0x0000_0001; // CURLAUTH_BASIC
        i.httpauth_used = 0x0000_0008;
        i.proxyauth_used = 0x0000_0001;
        i.os_errno = 0;
        i.num_connects = 2;
        i.filetime = 1_600_000_000;
        i.primary_port = 443;
        i.local_port = 51_000;
        i.primary_has_ports = true;
        i.http_version = 20; // -> CURL_HTTP_VERSION_2_0 (3)
        i.conn_protocol = 0x0000_0002; // CURLPROTO_HTTPS
        i.used_proxy = 0;
        i.proxy_error = 0;
        i.rtsp_client_cseq = 3;
        i.rtsp_server_cseq = 4;
        i.rtsp_cseq_recv = 2;
        // doubles / off_t (times in microseconds)
        i.total_time_us = 1_500_000;
        i.namelookup_time_us = 250_000;
        i.connect_time_us = 300_000;
        i.appconnect_time_us = 450_000;
        i.pretransfer_time_us = 500_000;
        i.posttransfer_time_us = 1_400_000;
        i.starttransfer_time_us = 700_000;
        i.redirect_time_us = 120_000;
        i.queue_time_us = 50_000;
        i.earlydata_sent = 64;
        i.size_upload = 128;
        i.size_download = 4096;
        i.speed_download = 2048;
        i.speed_upload = 64;
        i.content_length_download = 4096;
        i.dl_size_known = true;
        i.content_length_upload = 0;
        i.ul_size_known = false;
        i.retry_after = 30;
        // identifiers / socket / private / method
        i.xfer_id = 5;
        i.conn_id = 9;
        i.active_socket = 7;
        i.private_ptr = 0xdead_beef;
        i.method = HttpMethod::Post;
        i
    }

    // -- id / mask / type-group properties ---------------------------------

    #[test]
    fn all_infos_slice_has_expected_count() {
        // 13 STRING + 25 LONG + 13 DOUBLE + 20 OFF_T + 2 SLIST + 3 PTR + 1 SOCKET.
        assert_eq!(ALL_INFOS.len(), 77);
    }

    #[test]
    fn discriminants_match_header_values() {
        // A spot-check that each variant is (type-mask | sequence-number), which
        // is the exact CURLINFO integer from include/curl/curl.h.
        assert_eq!(CurlInfo::EffectiveUrl.as_raw(), 0x10_0000 + 1);
        assert_eq!(CurlInfo::ResponseCode.as_raw(), 0x20_0000 + 2);
        assert_eq!(CurlInfo::TotalTime.as_raw(), 0x30_0000 + 3);
        assert_eq!(CurlInfo::SizeUploadT.as_raw(), 0x60_0000 + 7);
        assert_eq!(CurlInfo::SslEngines.as_raw(), 0x40_0000 + 27);
        assert_eq!(CurlInfo::ActiveSocket.as_raw(), 0x50_0000 + 44);
        assert_eq!(CurlInfo::ProxyAuthUsed.as_raw(), 0x20_0000 + 70);
        // CURLINFO_PRIVATE is STRING-classified even though its value is a ptr.
        assert_eq!(CurlInfo::Private.as_raw(), 0x10_0000 + 21);
        assert_eq!(CurlInfo::Private.type_group(), InfoType::String);
    }

    #[test]
    fn raw_round_trips_for_every_variant() {
        for &info in ALL_INFOS {
            let raw = info.as_raw();
            assert_eq!(
                CurlInfo::from_raw(raw),
                Some(info),
                "round-trip failed for {info:?} (raw {raw:#x})"
            );
        }
    }

    #[test]
    fn from_raw_rejects_unknown_ids() {
        // CURLINFO_NONE (0) is deliberately not a variant.
        assert_eq!(CurlInfo::from_raw(0), None);
        assert_eq!(CurlInfo::from_raw(-1), None);
        assert_eq!(CurlInfo::from_raw(i32::MAX), None);
        // Valid type group, unused sequence number.
        assert_eq!(CurlInfo::from_raw(CURLINFO_LONG + 9_999), None);
        assert_eq!(CurlInfo::from_raw(CURLINFO_STRING + 9_999), None);
    }

    #[test]
    fn type_group_is_total_and_matches_mask() {
        // Pins the `type_group` fallback as unreachable: from_mask is Some for
        // every variant, so type_group never hits its defensive arm.
        for &info in ALL_INFOS {
            let expected =
                InfoType::from_mask(info.as_raw()).expect("every variant has a valid type mask");
            assert_eq!(info.type_group(), expected, "{info:?}");
        }
    }

    #[test]
    fn info_type_mask_round_trips() {
        for t in [
            InfoType::String,
            InfoType::Long,
            InfoType::Double,
            InfoType::Slist,
            InfoType::Socket,
            InfoType::OffT,
        ] {
            assert_eq!(InfoType::from_mask(t.mask()), Some(t));
        }
        // PTR shares the SLIST mask.
        assert_eq!(InfoType::from_mask(CURLINFO_PTR), Some(InfoType::Slist));
    }

    /// The variant returned by `retrieve` must be consistent with the queried
    /// info's `type_group` (with the two documented exceptions: `CURLINFO_PRIVATE`
    /// is STRING-classified but yields a `Ptr`, and PTR shares the SLIST group).
    fn value_consistent(info: CurlInfo, v: &InfoValue<'_>) -> bool {
        matches!(
            (info.type_group(), v),
            (InfoType::Long, InfoValue::Long(_))
                | (InfoType::OffT, InfoValue::OffT(_))
                | (InfoType::Double, InfoValue::Double(_))
                | (InfoType::String, InfoValue::Str(_))
                | (InfoType::String, InfoValue::Ptr(InfoPtr::Private(_)))
                | (InfoType::Slist, InfoValue::Slist(_))
                | (InfoType::Slist, InfoValue::Ptr(_))
                | (InfoType::Socket, InfoValue::Socket(_))
        )
    }

    #[test]
    fn retrieve_returns_type_consistent_value_for_every_variant() {
        let info = sample();
        for &which in ALL_INFOS {
            let v = retrieve(&info, which).expect("retrieve is total over CurlInfo");
            assert!(
                value_consistent(which, &v),
                "type mismatch for {which:?}: {v:?}"
            );
        }
    }

    // -- string family -----------------------------------------------------

    #[test]
    fn string_infos_borrow_handle_owned_buffers() {
        let info = sample();
        match retrieve(&info, CurlInfo::EffectiveUrl).unwrap() {
            InfoValue::Str(Some(s)) => {
                assert_eq!(s.to_bytes(), b"https://example.com/path");
            }
            other => panic!("expected Str, got {other:?}"),
        }
        match retrieve(&info, CurlInfo::ContentType).unwrap() {
            InfoValue::Str(Some(s)) => assert_eq!(s.to_bytes(), b"text/html; charset=utf-8"),
            other => panic!("expected Str, got {other:?}"),
        }
        match retrieve(&info, CurlInfo::Scheme).unwrap() {
            InfoValue::Str(Some(s)) => assert_eq!(s.to_bytes(), b"https"),
            other => panic!("expected Str, got {other:?}"),
        }
    }

    #[test]
    fn effective_url_reports_empty_string_when_unset() {
        // C returns "" (non-NULL) for a NULL url, never NULL.
        let info = Info::new();
        match retrieve(&info, CurlInfo::EffectiveUrl).unwrap() {
            InfoValue::Str(Some(s)) => assert_eq!(s.to_bytes(), b""),
            other => panic!("expected empty Str, got {other:?}"),
        }
    }

    #[test]
    fn null_string_infos_report_none() {
        // An unset Content-Type is reported as a NULL char* (Str(None)).
        let info = Info::new();
        assert_eq!(
            retrieve(&info, CurlInfo::ContentType).unwrap(),
            InfoValue::Str(None)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::RedirectUrl).unwrap(),
            InfoValue::Str(None)
        );
        // No build-time CA bundle/path in the rustls workspace.
        assert_eq!(
            retrieve(&info, CurlInfo::CaInfo).unwrap(),
            InfoValue::Str(None)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::CaPath).unwrap(),
            InfoValue::Str(None)
        );
    }

    #[test]
    fn effective_method_precedence() {
        let mut info = sample();
        // No custom request, not NOBODY: the stored method (POST) wins.
        match retrieve(&info, CurlInfo::EffectiveMethod).unwrap() {
            InfoValue::Str(Some(s)) => assert_eq!(s.to_bytes(), b"POST"),
            other => panic!("expected POST, got {other:?}"),
        }
        // NOBODY forces HEAD.
        info.opt_no_body = true;
        match retrieve(&info, CurlInfo::EffectiveMethod).unwrap() {
            InfoValue::Str(Some(s)) => assert_eq!(s.to_bytes(), b"HEAD"),
            other => panic!("expected HEAD, got {other:?}"),
        }
        // An explicit custom request takes precedence over everything.
        info.custom_request = Some(CString::new("PATCH").unwrap());
        match retrieve(&info, CurlInfo::EffectiveMethod).unwrap() {
            InfoValue::Str(Some(s)) => assert_eq!(s.to_bytes(), b"PATCH"),
            other => panic!("expected PATCH, got {other:?}"),
        }
        // The default method (no custom, not NOBODY) is GET.
        let def = Info::new();
        match retrieve(&def, CurlInfo::EffectiveMethod).unwrap() {
            InfoValue::Str(Some(s)) => assert_eq!(s.to_bytes(), b"GET"),
            other => panic!("expected GET, got {other:?}"),
        }
    }

    #[test]
    fn private_pointer_is_returned_verbatim() {
        let info = sample();
        assert_eq!(
            retrieve(&info, CurlInfo::Private).unwrap(),
            InfoValue::Ptr(InfoPtr::Private(0xdead_beef))
        );
        // Unset private pointer is 0 (NULL).
        let def = Info::new();
        assert_eq!(
            retrieve(&def, CurlInfo::Private).unwrap(),
            InfoValue::Ptr(InfoPtr::Private(0))
        );
    }

    // -- long family -------------------------------------------------------

    #[test]
    fn long_infos_report_expected_values() {
        let info = sample();
        assert_eq!(
            retrieve(&info, CurlInfo::ResponseCode).unwrap(),
            InfoValue::Long(200)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::HeaderSize).unwrap(),
            InfoValue::Long(321)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::RequestSize).unwrap(),
            InfoValue::Long(99)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::RedirectCount).unwrap(),
            InfoValue::Long(1)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::NumConnects).unwrap(),
            InfoValue::Long(2)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::HttpAuthAvail).unwrap(),
            InfoValue::Long(0x0000_0008)
        );
    }

    #[test]
    fn http_version_is_mapped() {
        let mut info = Info::new();
        for (internal, reported) in [(0, 0), (10, 1), (11, 2), (20, 3), (30, 30), (99, 0)] {
            info.http_version = internal;
            assert_eq!(
                retrieve(&info, CurlInfo::HttpVersion).unwrap(),
                InfoValue::Long(reported),
                "internal {internal}"
            );
        }
    }

    #[test]
    fn condition_unmet_logic() {
        let mut info = Info::new();
        // Neither 304 nor a time condition: met (0).
        info.response_code = 200;
        info.timecond = false;
        assert_eq!(
            retrieve(&info, CurlInfo::ConditionUnmet).unwrap(),
            InfoValue::Long(0)
        );
        // A 304 always counts as unmet (1).
        info.response_code = 304;
        assert_eq!(
            retrieve(&info, CurlInfo::ConditionUnmet).unwrap(),
            InfoValue::Long(1)
        );
        // A time condition that suppressed the transfer: unmet (1).
        info.response_code = 200;
        info.timecond = true;
        assert_eq!(
            retrieve(&info, CurlInfo::ConditionUnmet).unwrap(),
            InfoValue::Long(1)
        );
    }

    #[test]
    fn ports_are_gated_on_known_ports() {
        let mut info = sample();
        assert_eq!(
            retrieve(&info, CurlInfo::PrimaryPort).unwrap(),
            InfoValue::Long(443)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::LocalPort).unwrap(),
            InfoValue::Long(51_000)
        );
        // Without known ports both report -1, regardless of the stored numbers.
        info.primary_has_ports = false;
        assert_eq!(
            retrieve(&info, CurlInfo::PrimaryPort).unwrap(),
            InfoValue::Long(-1)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::LocalPort).unwrap(),
            InfoValue::Long(-1)
        );
    }

    #[test]
    fn filetime_long_and_offt_forms_agree() {
        let mut info = Info::new();
        info.filetime = 1_600_000_000;
        // On the LP64 targets `long` holds the full curl_off_t range, so both
        // forms report the same value.
        assert_eq!(
            retrieve(&info, CurlInfo::Filetime).unwrap(),
            InfoValue::Long(1_600_000_000)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::FiletimeT).unwrap(),
            InfoValue::OffT(1_600_000_000)
        );
        // Unknown file time is -1 in both forms.
        let def = Info::new();
        assert_eq!(
            retrieve(&def, CurlInfo::Filetime).unwrap(),
            InfoValue::Long(-1)
        );
        assert_eq!(
            retrieve(&def, CurlInfo::FiletimeT).unwrap(),
            InfoValue::OffT(-1)
        );
    }

    // -- socket family -----------------------------------------------------

    #[test]
    fn lastsocket_and_activesocket() {
        let mut info = sample();
        // LASTSOCKET reports the active socket as a long.
        assert_eq!(
            retrieve(&info, CurlInfo::LastSocket).unwrap(),
            InfoValue::Long(7)
        );
        // ACTIVESOCKET reports it through the socket channel.
        assert_eq!(
            retrieve(&info, CurlInfo::ActiveSocket).unwrap(),
            InfoValue::Socket(7)
        );
        // With no active socket, LASTSOCKET is -1 and ACTIVESOCKET is BAD.
        info.active_socket = CURL_SOCKET_BAD;
        assert_eq!(
            retrieve(&info, CurlInfo::LastSocket).unwrap(),
            InfoValue::Long(-1)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::ActiveSocket).unwrap(),
            InfoValue::Socket(CURL_SOCKET_BAD)
        );
    }

    // -- double / off_t families and their consistency ---------------------

    #[test]
    fn double_times_are_seconds_offt_times_are_microseconds() {
        let info = sample();
        assert_eq!(
            retrieve(&info, CurlInfo::TotalTime).unwrap(),
            InfoValue::Double(1.5)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::TotalTimeT).unwrap(),
            InfoValue::OffT(1_500_000)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::NamelookupTime).unwrap(),
            InfoValue::Double(0.25)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::NamelookupTimeT).unwrap(),
            InfoValue::OffT(250_000)
        );
    }

    #[test]
    fn double_and_offt_sizes_speeds_are_consistent() {
        let info = sample();
        // sizes
        assert_eq!(
            retrieve(&info, CurlInfo::SizeDownload).unwrap(),
            InfoValue::Double(4096.0)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::SizeDownloadT).unwrap(),
            InfoValue::OffT(4096)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::SizeUpload).unwrap(),
            InfoValue::Double(128.0)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::SizeUploadT).unwrap(),
            InfoValue::OffT(128)
        );
        // speeds
        assert_eq!(
            retrieve(&info, CurlInfo::SpeedDownload).unwrap(),
            InfoValue::Double(2048.0)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::SpeedDownloadT).unwrap(),
            InfoValue::OffT(2048)
        );
    }

    #[test]
    fn content_length_is_gated_on_known_size() {
        let info = sample(); // dl_size_known = true, ul_size_known = false
        assert_eq!(
            retrieve(&info, CurlInfo::ContentLengthDownload).unwrap(),
            InfoValue::Double(4096.0)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::ContentLengthDownloadT).unwrap(),
            InfoValue::OffT(4096)
        );
        // Upload size unknown -> -1 in both forms.
        assert_eq!(
            retrieve(&info, CurlInfo::ContentLengthUpload).unwrap(),
            InfoValue::Double(-1.0)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::ContentLengthUploadT).unwrap(),
            InfoValue::OffT(-1)
        );
    }

    #[test]
    fn offt_identifiers_and_misc() {
        let info = sample();
        assert_eq!(
            retrieve(&info, CurlInfo::XferId).unwrap(),
            InfoValue::OffT(5)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::ConnId).unwrap(),
            InfoValue::OffT(9)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::RetryAfter).unwrap(),
            InfoValue::OffT(30)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::QueueTimeT).unwrap(),
            InfoValue::OffT(50_000)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::EarlydataSentT).unwrap(),
            InfoValue::OffT(64)
        );
    }

    // -- slist / ptr families ---------------------------------------------

    #[test]
    fn empty_slists_report_none_populated_report_some() {
        let mut info = Info::new();
        // Empty -> NULL list, matching C.
        assert_eq!(
            retrieve(&info, CurlInfo::SslEngines).unwrap(),
            InfoValue::Slist(None)
        );
        assert_eq!(
            retrieve(&info, CurlInfo::CookieList).unwrap(),
            InfoValue::Slist(None)
        );
        // Populated -> Some, borrowing the handle-owned list.
        info.ssl_engines.append("dynamic").unwrap();
        info.cookielist
            .append(".example.com\tTRUE\t/\tFALSE\t0\tname\tvalue")
            .unwrap();
        match retrieve(&info, CurlInfo::SslEngines).unwrap() {
            InfoValue::Slist(Some(list)) => {
                assert_eq!(list.len(), 1);
                assert_eq!(list.first().unwrap().to_bytes(), b"dynamic");
            }
            other => panic!("expected Slist(Some), got {other:?}"),
        }
        match retrieve(&info, CurlInfo::CookieList).unwrap() {
            InfoValue::Slist(Some(list)) => assert_eq!(list.len(), 1),
            other => panic!("expected Slist(Some), got {other:?}"),
        }
    }

    #[test]
    fn certinfo_is_always_a_pointer() {
        let mut info = Info::new();
        // Even an empty cert set yields a (zero-count) struct pointer, as C
        // returns `&data->info.certs` unconditionally.
        match retrieve(&info, CurlInfo::Certinfo).unwrap() {
            InfoValue::Ptr(InfoPtr::CertInfo(c)) => assert_eq!(c.num_of_certs(), 0),
            other => panic!("expected CertInfo ptr, got {other:?}"),
        }
        let mut leaf = SList::new();
        leaf.append("Subject:CN=example.com").unwrap();
        info.certinfo.push(leaf);
        match retrieve(&info, CurlInfo::Certinfo).unwrap() {
            InfoValue::Ptr(InfoPtr::CertInfo(c)) => {
                assert_eq!(c.num_of_certs(), 1);
                assert_eq!(c.certs()[0].len(), 1);
            }
            other => panic!("expected CertInfo ptr, got {other:?}"),
        }
    }

    #[test]
    fn tls_session_and_ssl_ptr_report_rustls() {
        let info = Info::new();
        for which in [CurlInfo::TlsSession, CurlInfo::TlsSslPtr] {
            match retrieve(&info, which).unwrap() {
                InfoValue::Ptr(InfoPtr::TlsSession(t)) => {
                    assert_eq!(t.backend(), 14); // CURLSSLBACKEND_RUSTLS
                    assert_eq!(t.internals(), 0);
                }
                other => panic!("expected TlsSession ptr for {which:?}, got {other:?}"),
            }
        }
    }

    // -- raw entry point / error path --------------------------------------

    #[test]
    fn retrieve_raw_rejects_unknown_with_unknown_option() {
        let info = sample();
        assert_eq!(retrieve_raw(&info, 0), Err(CurlError::UnknownOption));
        assert_eq!(retrieve_raw(&info, -12345), Err(CurlError::UnknownOption));
        assert_eq!(
            retrieve_raw(&info, CURLINFO_LONG + 9_999),
            Err(CurlError::UnknownOption)
        );
    }

    #[test]
    fn retrieve_raw_matches_typed_retrieve_for_known_ids() {
        let info = sample();
        for &which in ALL_INFOS {
            let by_raw = retrieve_raw(&info, which.as_raw());
            let by_typed = retrieve(&info, which);
            assert_eq!(by_raw, by_typed, "mismatch for {which:?}");
        }
    }

    #[test]
    fn get_method_delegates_to_retrieve() {
        let info = sample();
        assert_eq!(
            info.get(CurlInfo::ResponseCode).unwrap(),
            retrieve(&info, CurlInfo::ResponseCode).unwrap()
        );
    }

    // -- reset() scope (mirrors Curl_initinfo) ------------------------------

    #[test]
    fn reset_clears_session_info_but_keeps_options() {
        let mut info = sample();
        // Option/state-derived fields that Curl_initinfo does NOT touch.
        info.private_ptr = 0x1234;
        info.opt_no_body = true;
        info.custom_request = Some(CString::new("PUT").unwrap());
        info.ssl_verifyresult = 1;
        info.proxy_ssl_verifyresult = 1;
        info.cainfo = Some(CString::new("/etc/ssl/cert.pem").unwrap());
        info.redirect_count = 3;
        info.os_errno = 5;

        info.reset();

        // Session info is cleared.
        assert_eq!(info.response_code, 0);
        assert_eq!(info.http_connect_code, 0);
        assert_eq!(info.http_version, 0);
        assert_eq!(info.filetime, -1);
        assert!(!info.timecond);
        assert_eq!(info.header_size, 0);
        assert_eq!(info.request_size, 0);
        assert_eq!(info.num_connects, 0);
        assert_eq!(info.content_type, None);
        assert_eq!(info.redirect_url, None);
        assert_eq!(info.primary_ip, None);
        assert_eq!(info.local_ip, None);
        assert_eq!(info.primary_port, 0);
        assert_eq!(info.local_port, 0);
        assert!(!info.primary_has_ports);
        assert_eq!(info.retry_after, 0);
        assert_eq!(info.scheme, None);
        assert_eq!(info.conn_protocol, 0);
        assert_eq!(info.total_time_us, 0);
        assert_eq!(info.starttransfer_time_us, 0);
        assert!(info.certinfo.is_empty());

        // Option/state-derived fields are preserved.
        assert_eq!(info.private_ptr, 0x1234);
        assert!(info.opt_no_body);
        assert_eq!(info.custom_request, Some(CString::new("PUT").unwrap()));
        assert_eq!(info.ssl_verifyresult, 1);
        assert_eq!(info.proxy_ssl_verifyresult, 1);
        assert_eq!(
            info.cainfo,
            Some(CString::new("/etc/ssl/cert.pem").unwrap())
        );
        assert_eq!(info.redirect_count, 3);
        assert_eq!(info.os_errno, 5);
    }

    // -- small helper behaviors --------------------------------------------

    #[test]
    fn double_secs_helper() {
        assert!((double_secs(1_500_000) - 1.5).abs() < f64::EPSILON);
        assert!((double_secs(0) - 0.0).abs() < f64::EPSILON);
        assert!((double_secs(250_000) - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn new_and_default_agree() {
        assert_eq!(Info::new(), Info::default());
    }
}
