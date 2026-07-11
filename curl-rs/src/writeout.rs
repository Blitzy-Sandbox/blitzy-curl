// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// Rust rewrite of curl's src/tool_writeout.c (--write-out format).

//! # `writeout` — the `--write-out` / `-w` format engine
//!
//! This module is the faithful Rust rewrite of curl 8.19.0-DEV's
//! `src/tool_writeout.c` (871 lines). It implements the `--write-out`
//! (`-w`) format-string mini-language documented authoritatively in
//! `docs/cmdline-opts/write-out.md`.
//!
//! ## Responsibilities
//!
//! * Define the shared variable catalogue — [`WriteoutId`] (curl's `VAR_*`
//!   enum), [`WriteoutVar`] (curl's `struct writeoutvar`) and the alpha-sorted
//!   [`VARIABLES`] table — that the sibling [`crate::writeout_json`] module
//!   consumes to emit the `%{json}` object.
//! * Parse a `--write-out` format string byte-for-byte the way
//!   [`ourWriteOut`][our_writeout] does and emit the resulting text.
//!
//! ## Format-string grammar (preserved verbatim from `write-out.md`)
//!
//! * Plain text is emitted literally.
//! * `%%` emits a single `%`.
//! * `\n`, `\r`, `\t` are the only recognised backslash escapes; any other
//!   `\x` is emitted verbatim (both characters).
//! * `%{variable}` looks the name up in [`VARIABLES`]; an unknown name emits a
//!   warning to stderr and is otherwise skipped.
//! * `%{stdout}` / `%{stderr}` switch the destination stream for everything
//!   that follows.
//! * `%output{name}` / `%output{>>name}` redirect subsequent output to a file
//!   (truncate / append). A failed open keeps the previous stream.
//! * `%header{name}` and `%header{name:all:[sep]}` emit response header values.
//! * `%{json}` / `%{header_json}` delegate to [`crate::writeout_json`].
//! * `%{onerror}` emits the remainder only when the transfer failed.
//! * `%{time{FORMAT}}` formats the current UTC time with a strftime-style
//!   format (with curl's `%f`/`%z`/`%Z` extensions).
//!
//! ## Exit-code invariance
//!
//! Per curl parity, **failures inside `--write-out` never change the process
//! exit code**: every `write`/`open`/format error here is deliberately
//! ignored. There is no `unsafe` in this module.
//!
//! ## Note on visibility
//!
//! `curl-rs` is a binary crate, so most items defined here have no consumer
//! *inside `main.rs` yet* — `operate.rs` wires them in a later checkpoint
//! (AAP §0.7.3), and `writeout_json.rs` imports [`VARIABLES`]/[`emit_var`] by
//! name. The module-level `#![allow(dead_code)]` reflects that these items are
//! the deliberate, stable vocabulary of the `--write-out` engine.

#![allow(dead_code)]

use std::fs::{File, OpenOptions};
use std::io::Write;
// Brings `write!(String, …)` (the `core::fmt::Write` impl) into scope for the
// `%{time{…}}` formatter; the `as _` avoids clashing with `std::io::Write`.
use std::fmt::Write as _;

use chrono::{TimeZone, Utc};

use curl_rs_lib::urlapi::{CurlUPart, Url, DEFAULT_PORT, GUESS_SCHEME, NON_SUPPORT_SCHEME};
use curl_rs_lib::{CurlCode, Easy};

use crate::args::OperationConfig;
use crate::writeout_json::{header_json, json_write_string, our_writeout_json};

// ===========================================================================
// Constants
// ===========================================================================

/// Longest accepted `%{name}` variable name — curl's `MAX_WRITEOUT_NAME_LENGTH`.
///
/// curl backs the name accumulator with a `dynbuf` capped at this size; a
/// longer name makes the append fail, which in `ourWriteOut` `break`s out of
/// the whole parse loop. We reproduce that abort exactly.
pub const MAX_WRITEOUT_NAME_LENGTH: usize = 24;

/// Longest accepted `%output{...}` filename — curl's `sizeof(fname)` (512).
///
/// A longer name is silently ignored (no redirect) while parsing still
/// advances past the `}`, matching curl.
const MAX_OUTPUT_FILENAME: usize = 512;

// `CURL_HTTP_VERSION_*` integer values, frozen to the public `curl.h` ABI so
// the `%{http_version}` mapping below is byte-identical to curl 8.x.
const CURL_HTTP_VERSION_NONE: i64 = 0;
const CURL_HTTP_VERSION_1_0: i64 = 1;
const CURL_HTTP_VERSION_1_1: i64 = 2;
const CURL_HTTP_VERSION_2: i64 = 3;
const CURL_HTTP_VERSION_3: i64 = 30;

/// The `http_version[]` table from `tool_writeout.c`: maps the numeric
/// `CURLINFO_HTTP_VERSION` value to the string emitted for `%{http_version}`.
///
/// `"0" → NONE, "1" → 1.0, "1.1" → 1.1, "2" → 2, "3" → 3`.
pub static HTTP_VERSION_MAP: &[(&str, i64)] = &[
    ("0", CURL_HTTP_VERSION_NONE),
    ("1", CURL_HTTP_VERSION_1_0),
    ("1.1", CURL_HTTP_VERSION_1_1),
    ("2", CURL_HTTP_VERSION_2),
    ("3", CURL_HTTP_VERSION_3),
];

// ===========================================================================
// WriteoutId — curl's `writeoutid` (VAR_*) enum
// ===========================================================================

/// Identifier for one `--write-out` variable — curl's `writeoutid` enum.
///
/// The declaration order is preserved byte-for-byte from `tool_writeout.h`,
/// which matters because `urlpart` compares `vid >= VAR_INPUT_URLESCHEME` to
/// pick the *effective* URL for the `urle.*` family. `derive(PartialOrd, Ord)`
/// gives that comparison for free (variants order by declaration position).
///
/// The `VAR_INPUT_URL*` catalogue is present in full: the raw family
/// ([`InputUrlScheme`](WriteoutId::InputUrlScheme)…
/// [`InputUrlZoneid`](WriteoutId::InputUrlZoneid)) and the `E`-escaped family
/// ([`InputUrlEScheme`](WriteoutId::InputUrlEScheme)…
/// [`InputUrlEZoneid`](WriteoutId::InputUrlEZoneid)).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum WriteoutId {
    /// `VAR_NONE` — must remain the first variant.
    None,
    /// `VAR_APPCONNECT_TIME`.
    AppconnectTime,
    /// `VAR_CERT`.
    Cert,
    /// `VAR_CONNECT_TIME`.
    ConnectTime,
    /// `VAR_CONTENT_TYPE`.
    ContentType,
    /// `VAR_CONN_ID`.
    ConnId,
    /// `VAR_EASY_ID`.
    EasyId,
    /// `VAR_EFFECTIVE_FILENAME`.
    EffectiveFilename,
    /// `VAR_EFFECTIVE_METHOD`.
    EffectiveMethod,
    /// `VAR_EFFECTIVE_URL`.
    EffectiveUrl,
    /// `VAR_ERRORMSG`.
    Errormsg,
    /// `VAR_EXITCODE`.
    Exitcode,
    /// `VAR_FTP_ENTRY_PATH`.
    FtpEntryPath,
    /// `VAR_HEADER_JSON`.
    HeaderJson,
    /// `VAR_HEADER_SIZE`.
    HeaderSize,
    /// `VAR_HTTP_CODE`.
    HttpCode,
    /// `VAR_HTTP_CODE_PROXY`.
    HttpCodeProxy,
    /// `VAR_HTTP_VERSION`.
    HttpVersion,
    /// `VAR_INPUT_URL`.
    InputUrl,
    /// `VAR_INPUT_URLSCHEME`.
    InputUrlScheme,
    /// `VAR_INPUT_URLUSER`.
    InputUrlUser,
    /// `VAR_INPUT_URLPASSWORD`.
    InputUrlPassword,
    /// `VAR_INPUT_URLOPTIONS`.
    InputUrlOptions,
    /// `VAR_INPUT_URLHOST`.
    InputUrlHost,
    /// `VAR_INPUT_URLPORT`.
    InputUrlPort,
    /// `VAR_INPUT_URLPATH`.
    InputUrlPath,
    /// `VAR_INPUT_URLQUERY`.
    InputUrlQuery,
    /// `VAR_INPUT_URLFRAGMENT`.
    InputUrlFragment,
    /// `VAR_INPUT_URLZONEID`.
    InputUrlZoneid,
    /// `VAR_INPUT_URLESCHEME` — keep this the first `URLE*` variant.
    InputUrlEScheme,
    /// `VAR_INPUT_URLEUSER`.
    InputUrlEUser,
    /// `VAR_INPUT_URLEPASSWORD`.
    InputUrlEPassword,
    /// `VAR_INPUT_URLEOPTIONS`.
    InputUrlEOptions,
    /// `VAR_INPUT_URLEHOST`.
    InputUrlEHost,
    /// `VAR_INPUT_URLEPORT`.
    InputUrlEPort,
    /// `VAR_INPUT_URLEPATH`.
    InputUrlEPath,
    /// `VAR_INPUT_URLEQUERY`.
    InputUrlEQuery,
    /// `VAR_INPUT_URLEFRAGMENT`.
    InputUrlEFragment,
    /// `VAR_INPUT_URLEZONEID`.
    InputUrlEZoneid,
    /// `VAR_JSON`.
    Json,
    /// `VAR_LOCAL_IP`.
    LocalIp,
    /// `VAR_LOCAL_PORT`.
    LocalPort,
    /// `VAR_NAMELOOKUP_TIME`.
    NamelookupTime,
    /// `VAR_NUM_CERTS`.
    NumCerts,
    /// `VAR_NUM_CONNECTS`.
    NumConnects,
    /// `VAR_NUM_HEADERS`.
    NumHeaders,
    /// `VAR_NUM_RETRY`.
    NumRetry,
    /// `VAR_ONERROR`.
    Onerror,
    /// `VAR_PRETRANSFER_TIME`.
    PretransferTime,
    /// `VAR_POSTTRANSFER_TIME`.
    PosttransferTime,
    /// `VAR_PRIMARY_IP`.
    PrimaryIp,
    /// `VAR_PRIMARY_PORT`.
    PrimaryPort,
    /// `VAR_PROXY_SSL_VERIFY_RESULT`.
    ProxySslVerifyResult,
    /// `VAR_PROXY_USED`.
    ProxyUsed,
    /// `VAR_QUEUE_TIME`.
    QueueTime,
    /// `VAR_REDIRECT_COUNT`.
    RedirectCount,
    /// `VAR_REDIRECT_TIME`.
    RedirectTime,
    /// `VAR_REDIRECT_URL`.
    RedirectUrl,
    /// `VAR_REFERER`.
    Referer,
    /// `VAR_REQUEST_SIZE`.
    RequestSize,
    /// `VAR_SCHEME`.
    Scheme,
    /// `VAR_SIZE_DOWNLOAD`.
    SizeDownload,
    /// `VAR_SIZE_UPLOAD`.
    SizeUpload,
    /// `VAR_SPEED_DOWNLOAD`.
    SpeedDownload,
    /// `VAR_SPEED_UPLOAD`.
    SpeedUpload,
    /// `VAR_SSL_VERIFY_RESULT`.
    SslVerifyResult,
    /// `VAR_STARTTRANSFER_TIME`.
    StarttransferTime,
    /// `VAR_STDERR`.
    Stderr,
    /// `VAR_STDOUT`.
    Stdout,
    /// `VAR_TLS_EARLYDATA_SENT`.
    TlsEarlydataSent,
    /// `VAR_TOTAL_TIME`.
    TotalTime,
    /// `VAR_URLNUM`.
    Urlnum,
    /// `VAR_NUM_OF_VARS` — must remain the last variant.
    NumOfVars,
}

// ===========================================================================
// CurlInfo — the `CURLINFO_*` selector attached to each variable
// ===========================================================================

/// The `CURLINFO_*` value a variable reads from the easy handle — curl's
/// `writeoutvar.ci` field. `None` in the table (`CURLINFO_NONE`) means the
/// value is produced by the variable's own special-case logic instead.
///
/// Only the selectors referenced by [`VARIABLES`] are modelled. Each maps to
/// the best-available field of [`curl_rs_lib::Easy`]; where the core library
/// does not yet expose a datum, the value functions fall back to curl's
/// "getinfo succeeded with a zero/empty value" convention, so output stays
/// well-formed and the mapping is forward-compatible with a future getinfo
/// surface.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CurlInfo {
    /// `CURLINFO_CONN_ID`.
    ConnId,
    /// `CURLINFO_CONTENT_TYPE`.
    ContentType,
    /// `CURLINFO_FTP_ENTRY_PATH`.
    FtpEntryPath,
    /// `CURLINFO_RESPONSE_CODE`.
    ResponseCode,
    /// `CURLINFO_HTTP_CONNECTCODE`.
    HttpConnectCode,
    /// `CURLINFO_HTTP_VERSION` (a `long`, rendered as a string).
    HttpVersion,
    /// `CURLINFO_LOCAL_IP`.
    LocalIp,
    /// `CURLINFO_LOCAL_PORT`.
    LocalPort,
    /// `CURLINFO_EFFECTIVE_METHOD`.
    EffectiveMethod,
    /// `CURLINFO_NUM_CONNECTS`.
    NumConnects,
    /// `CURLINFO_REDIRECT_COUNT`.
    RedirectCount,
    /// `CURLINFO_PROXY_SSL_VERIFYRESULT`.
    ProxySslVerifyResult,
    /// `CURLINFO_USED_PROXY`.
    UsedProxy,
    /// `CURLINFO_REDIRECT_URL`.
    RedirectUrl,
    /// `CURLINFO_REFERER`.
    Referer,
    /// `CURLINFO_PRIMARY_IP`.
    PrimaryIp,
    /// `CURLINFO_PRIMARY_PORT`.
    PrimaryPort,
    /// `CURLINFO_SCHEME`.
    Scheme,
    /// `CURLINFO_SIZE_DOWNLOAD_T`.
    SizeDownloadT,
    /// `CURLINFO_HEADER_SIZE`.
    HeaderSize,
    /// `CURLINFO_REQUEST_SIZE`.
    RequestSize,
    /// `CURLINFO_SIZE_UPLOAD_T`.
    SizeUploadT,
    /// `CURLINFO_SPEED_DOWNLOAD_T`.
    SpeedDownloadT,
    /// `CURLINFO_SPEED_UPLOAD_T`.
    SpeedUploadT,
    /// `CURLINFO_SSL_VERIFYRESULT`.
    SslVerifyResult,
    /// `CURLINFO_APPCONNECT_TIME_T`.
    AppconnectTimeT,
    /// `CURLINFO_CONNECT_TIME_T`.
    ConnectTimeT,
    /// `CURLINFO_NAMELOOKUP_TIME_T`.
    NamelookupTimeT,
    /// `CURLINFO_POSTTRANSFER_TIME_T`.
    PosttransferTimeT,
    /// `CURLINFO_PRETRANSFER_TIME_T`.
    PretransferTimeT,
    /// `CURLINFO_QUEUE_TIME_T`.
    QueueTimeT,
    /// `CURLINFO_REDIRECT_TIME_T`.
    RedirectTimeT,
    /// `CURLINFO_STARTTRANSFER_TIME_T`.
    StarttransferTimeT,
    /// `CURLINFO_TOTAL_TIME_T`.
    TotalTimeT,
    /// `CURLINFO_EARLYDATA_SENT_T`.
    EarlydataSentT,
    /// `CURLINFO_EFFECTIVE_URL`.
    EffectiveUrl,
    /// `CURLINFO_XFER_ID`.
    XferId,
}

// ===========================================================================
// WriteKind — which emitter formats a variable (curl's `writefunc` pointer)
// ===========================================================================

/// Selects the emitter used for a variable — the Rust stand-in for curl's
/// `writeoutvar.writefunc` function pointer.
///
/// [`Special`](WriteKind::Special) corresponds to a `NULL` `writefunc` in the C
/// table (`json`, `header_json`, `onerror`, `stderr`, `stdout`): these are
/// handled directly by the parse loop and are *skipped* by the `%{json}`
/// emitter, exactly like curl's `if(mappings[i].writefunc && …)` guard.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WriteKind {
    /// String-valued — curl's `writeString`.
    Str,
    /// `long`-valued — curl's `writeLong`.
    Long,
    /// `curl_off_t`-valued — curl's `writeOffset`.
    Offset,
    /// Microsecond time value rendered as `secs.useconds` — curl's `writeTime`.
    Time,
    /// No emitter (`NULL` `writefunc`): driven by the parse loop; JSON skips it.
    Special,
}

// ===========================================================================
// WriteoutVar — one row of the variable table (curl's `struct writeoutvar`)
// ===========================================================================

/// One entry of the `--write-out` variable table — curl's `struct writeoutvar`.
///
/// The C struct is `{ const char *name; writeoutid id; CURLINFO ci; int
/// (*writefunc)(...); }`. Here the function pointer is replaced by the
/// [`kind`](WriteoutVar::kind) discriminant, which [`emit_var`] dispatches on.
#[derive(Clone, Copy, Debug)]
pub struct WriteoutVar {
    /// The `%{name}` token, e.g. `"http_code"`.
    pub name: &'static str,
    /// The variable identifier (curl's `id`).
    pub id: WriteoutId,
    /// The `CURLINFO_*` source, or `None` for `CURLINFO_NONE`.
    pub ci: Option<CurlInfo>,
    /// Which emitter renders the value (curl's `writefunc`).
    pub kind: WriteKind,
}

/// Convenience constructor keeping the [`VARIABLES`] table terse and readable.
const fn v(
    name: &'static str,
    id: WriteoutId,
    ci: Option<CurlInfo>,
    kind: WriteKind,
) -> WriteoutVar {
    WriteoutVar { name, id, ci, kind }
}

// ===========================================================================
// VARIABLES — the alpha-sorted `--write-out` variable table
// ===========================================================================

/// The complete `--write-out` variable table — curl's `variables[]`.
///
/// The designated emitter matches the `CURLINFO` return type, with exceptions
/// special-cased in the emitter. For example `http_version` reads
/// `CURLINFO_HTTP_VERSION` (a `long`) but is emitted as a *string*, so it uses
/// [`WriteKind::Str`]:
///
/// ```text
/// Yes: "http_version": "1.1"
/// No:  "http_version": 1.1
/// ```
///
/// **The names MUST stay in ascending byte order** — [`lookup`] binary-searches
/// this table (curl uses `bsearch` with `strcmp`). The full catalogue from
/// `docs/cmdline-opts/write-out.md` is present: nothing added, nothing omitted
/// (72 rows).
#[rustfmt::skip]
pub static VARIABLES: &[WriteoutVar] = &[
    v("certs", WriteoutId::Cert, None, WriteKind::Str),
    v("conn_id", WriteoutId::ConnId, Some(CurlInfo::ConnId), WriteKind::Offset),
    v("content_type", WriteoutId::ContentType, Some(CurlInfo::ContentType), WriteKind::Str),
    v("errormsg", WriteoutId::Errormsg, None, WriteKind::Str),
    v("exitcode", WriteoutId::Exitcode, None, WriteKind::Long),
    v("filename_effective", WriteoutId::EffectiveFilename, None, WriteKind::Str),
    v("ftp_entry_path", WriteoutId::FtpEntryPath, Some(CurlInfo::FtpEntryPath), WriteKind::Str),
    v("header_json", WriteoutId::HeaderJson, None, WriteKind::Special),
    v("http_code", WriteoutId::HttpCode, Some(CurlInfo::ResponseCode), WriteKind::Long),
    v("http_connect", WriteoutId::HttpCodeProxy, Some(CurlInfo::HttpConnectCode), WriteKind::Long),
    v("http_version", WriteoutId::HttpVersion, Some(CurlInfo::HttpVersion), WriteKind::Str),
    v("json", WriteoutId::Json, None, WriteKind::Special),
    v("local_ip", WriteoutId::LocalIp, Some(CurlInfo::LocalIp), WriteKind::Str),
    v("local_port", WriteoutId::LocalPort, Some(CurlInfo::LocalPort), WriteKind::Long),
    v("method", WriteoutId::EffectiveMethod, Some(CurlInfo::EffectiveMethod), WriteKind::Str),
    v("num_certs", WriteoutId::NumCerts, None, WriteKind::Long),
    v("num_connects", WriteoutId::NumConnects, Some(CurlInfo::NumConnects), WriteKind::Long),
    v("num_headers", WriteoutId::NumHeaders, None, WriteKind::Long),
    v("num_redirects", WriteoutId::RedirectCount, Some(CurlInfo::RedirectCount), WriteKind::Long),
    v("num_retries", WriteoutId::NumRetry, None, WriteKind::Long),
    v("onerror", WriteoutId::Onerror, None, WriteKind::Special),
    v("proxy_ssl_verify_result", WriteoutId::ProxySslVerifyResult, Some(CurlInfo::ProxySslVerifyResult), WriteKind::Long),
    v("proxy_used", WriteoutId::ProxyUsed, Some(CurlInfo::UsedProxy), WriteKind::Long),
    v("redirect_url", WriteoutId::RedirectUrl, Some(CurlInfo::RedirectUrl), WriteKind::Str),
    v("referer", WriteoutId::Referer, Some(CurlInfo::Referer), WriteKind::Str),
    v("remote_ip", WriteoutId::PrimaryIp, Some(CurlInfo::PrimaryIp), WriteKind::Str),
    v("remote_port", WriteoutId::PrimaryPort, Some(CurlInfo::PrimaryPort), WriteKind::Long),
    v("response_code", WriteoutId::HttpCode, Some(CurlInfo::ResponseCode), WriteKind::Long),
    v("scheme", WriteoutId::Scheme, Some(CurlInfo::Scheme), WriteKind::Str),
    v("size_download", WriteoutId::SizeDownload, Some(CurlInfo::SizeDownloadT), WriteKind::Offset),
    v("size_header", WriteoutId::HeaderSize, Some(CurlInfo::HeaderSize), WriteKind::Long),
    v("size_request", WriteoutId::RequestSize, Some(CurlInfo::RequestSize), WriteKind::Long),
    v("size_upload", WriteoutId::SizeUpload, Some(CurlInfo::SizeUploadT), WriteKind::Offset),
    v("speed_download", WriteoutId::SpeedDownload, Some(CurlInfo::SpeedDownloadT), WriteKind::Offset),
    v("speed_upload", WriteoutId::SpeedUpload, Some(CurlInfo::SpeedUploadT), WriteKind::Offset),
    v("ssl_verify_result", WriteoutId::SslVerifyResult, Some(CurlInfo::SslVerifyResult), WriteKind::Long),
    v("stderr", WriteoutId::Stderr, None, WriteKind::Special),
    v("stdout", WriteoutId::Stdout, None, WriteKind::Special),
    v("time_appconnect", WriteoutId::AppconnectTime, Some(CurlInfo::AppconnectTimeT), WriteKind::Time),
    v("time_connect", WriteoutId::ConnectTime, Some(CurlInfo::ConnectTimeT), WriteKind::Time),
    v("time_namelookup", WriteoutId::NamelookupTime, Some(CurlInfo::NamelookupTimeT), WriteKind::Time),
    v("time_posttransfer", WriteoutId::PosttransferTime, Some(CurlInfo::PosttransferTimeT), WriteKind::Time),
    v("time_pretransfer", WriteoutId::PretransferTime, Some(CurlInfo::PretransferTimeT), WriteKind::Time),
    v("time_queue", WriteoutId::QueueTime, Some(CurlInfo::QueueTimeT), WriteKind::Time),
    v("time_redirect", WriteoutId::RedirectTime, Some(CurlInfo::RedirectTimeT), WriteKind::Time),
    v("time_starttransfer", WriteoutId::StarttransferTime, Some(CurlInfo::StarttransferTimeT), WriteKind::Time),
    v("time_total", WriteoutId::TotalTime, Some(CurlInfo::TotalTimeT), WriteKind::Time),
    v("tls_earlydata", WriteoutId::TlsEarlydataSent, Some(CurlInfo::EarlydataSentT), WriteKind::Offset),
    v("url", WriteoutId::InputUrl, None, WriteKind::Str),
    v("url.fragment", WriteoutId::InputUrlFragment, None, WriteKind::Str),
    v("url.host", WriteoutId::InputUrlHost, None, WriteKind::Str),
    v("url.options", WriteoutId::InputUrlOptions, None, WriteKind::Str),
    v("url.password", WriteoutId::InputUrlPassword, None, WriteKind::Str),
    v("url.path", WriteoutId::InputUrlPath, None, WriteKind::Str),
    v("url.port", WriteoutId::InputUrlPort, None, WriteKind::Str),
    v("url.query", WriteoutId::InputUrlQuery, None, WriteKind::Str),
    v("url.scheme", WriteoutId::InputUrlScheme, None, WriteKind::Str),
    v("url.user", WriteoutId::InputUrlUser, None, WriteKind::Str),
    v("url.zoneid", WriteoutId::InputUrlZoneid, None, WriteKind::Str),
    v("url_effective", WriteoutId::EffectiveUrl, Some(CurlInfo::EffectiveUrl), WriteKind::Str),
    v("urle.fragment", WriteoutId::InputUrlEFragment, None, WriteKind::Str),
    v("urle.host", WriteoutId::InputUrlEHost, None, WriteKind::Str),
    v("urle.options", WriteoutId::InputUrlEOptions, None, WriteKind::Str),
    v("urle.password", WriteoutId::InputUrlEPassword, None, WriteKind::Str),
    v("urle.path", WriteoutId::InputUrlEPath, None, WriteKind::Str),
    v("urle.port", WriteoutId::InputUrlEPort, None, WriteKind::Str),
    v("urle.query", WriteoutId::InputUrlEQuery, None, WriteKind::Str),
    v("urle.scheme", WriteoutId::InputUrlEScheme, None, WriteKind::Str),
    v("urle.user", WriteoutId::InputUrlEUser, None, WriteKind::Str),
    v("urle.zoneid", WriteoutId::InputUrlEZoneid, None, WriteKind::Str),
    v("urlnum", WriteoutId::Urlnum, None, WriteKind::Offset),
    v("xfer_id", WriteoutId::EasyId, Some(CurlInfo::XferId), WriteKind::Offset),
];

/// Binary-search [`VARIABLES`] for `name` — curl's `bsearch(... matchvar)`.
///
/// The needle is a raw byte slice (the bytes between `%{` and `}`), compared
/// with `[u8]::cmp` which reproduces `strcmp`'s unsigned-byte ordering.
fn lookup(name: &[u8]) -> Option<&'static WriteoutVar> {
    VARIABLES
        .binary_search_by(|probe| probe.name.as_bytes().cmp(name))
        .ok()
        .map(|idx| &VARIABLES[idx])
}

/// Maps a numeric `CURLINFO_HTTP_VERSION` value to its `%{http_version}`
/// string via [`HTTP_VERSION_MAP`] (curl's `http_version[]` walk).
fn http_version_str(version: i64) -> Option<&'static str> {
    HTTP_VERSION_MAP
        .iter()
        .find(|(_, num)| *num == version)
        .map(|(s, _)| *s)
}

// ===========================================================================
// Value sourcing
// ===========================================================================
//
// The C emitters read their value straight out of `curl_easy_getinfo`. The
// core `curl-rs-lib` handle does not yet expose a getinfo surface, so these
// helpers source each datum from the best-available field of `Easy` and
// otherwise return curl's "getinfo succeeded, value is zero/empty" default.
// That keeps `%{json}` output well-formed and makes the mapping trivially
// forward-compatible: when a getinfo layer lands, only these helpers change.

/// The reassembled current URL — the Rust proxy for `CURLINFO_EFFECTIVE_URL`,
/// read from the handle's URL-API object (`state.uh`).
fn effective_url(easy: &Easy) -> Option<String> {
    easy.state
        .uh
        .as_ref()
        .and_then(|u| u.get(CurlUPart::Url, 0).ok())
}

/// The input URL — the Rust proxy for curl's `per->url`. With no separate raw
/// string retained, the parsed handle (`state.uh`) is the faithful source.
fn input_url(easy: &Easy) -> Option<String> {
    easy.state
        .uh
        .as_ref()
        .and_then(|u| u.get(CurlUPart::Url, 0).ok())
}

/// The numeric `CURLINFO_HTTP_VERSION` value. Absent a negotiated-version
/// datum on the handle, this is `CURL_HTTP_VERSION_NONE` (`0`), which maps to
/// `"0"` — curl's behaviour when no HTTP version was recorded.
fn http_version_long(_easy: &Easy) -> i64 {
    CURL_HTTP_VERSION_NONE
}

/// Extract a single URL component — the Rust port of curl's `urlpart()`.
///
/// The base URL is the *effective* URL for the `urle.*` family (ids at or
/// after [`WriteoutId::InputUrlEScheme`]) and the input URL otherwise; it is
/// re-parsed with `GUESS_SCHEME | NON_SUPPORT_SCHEME` and the component fetched
/// with `DEFAULT_PORT`, exactly like curl.
fn urlpart_value(id: WriteoutId, easy: &Easy) -> Option<String> {
    let base = if id >= WriteoutId::InputUrlEScheme {
        effective_url(easy)?
    } else {
        input_url(easy)?
    };

    let part = match id {
        WriteoutId::InputUrlScheme | WriteoutId::InputUrlEScheme => CurlUPart::Scheme,
        WriteoutId::InputUrlUser | WriteoutId::InputUrlEUser => CurlUPart::User,
        WriteoutId::InputUrlPassword | WriteoutId::InputUrlEPassword => CurlUPart::Password,
        WriteoutId::InputUrlOptions | WriteoutId::InputUrlEOptions => CurlUPart::Options,
        WriteoutId::InputUrlHost | WriteoutId::InputUrlEHost => CurlUPart::Host,
        WriteoutId::InputUrlPort | WriteoutId::InputUrlEPort => CurlUPart::Port,
        WriteoutId::InputUrlPath | WriteoutId::InputUrlEPath => CurlUPart::Path,
        WriteoutId::InputUrlQuery | WriteoutId::InputUrlEQuery => CurlUPart::Query,
        WriteoutId::InputUrlFragment | WriteoutId::InputUrlEFragment => CurlUPart::Fragment,
        WriteoutId::InputUrlZoneid | WriteoutId::InputUrlEZoneid => CurlUPart::ZoneId,
        // Not a URL-part id (curl's `rc = 4` "not implemented" branch).
        _ => return None,
    };

    let uh = Url::parse(&base, GUESS_SCHEME | NON_SUPPORT_SCHEME).ok()?;
    uh.get(part, DEFAULT_PORT).ok()
}

/// String value for a variable whose `ci` is a string-typed `CURLINFO_*`
/// (everything except `HTTP_VERSION`, which the caller special-cases).
fn string_from_info(ci: CurlInfo, easy: &Easy) -> Option<String> {
    match ci {
        CurlInfo::Scheme => easy.info.conn_scheme.clone(),
        CurlInfo::RedirectUrl => easy.info.wouldredirect.clone(),
        CurlInfo::EffectiveUrl => effective_url(easy),
        // The response `Content-Type`, recorded by the transfer engine
        // (`data->info.contenttype`); `None` when the response carried no such
        // header, which the emitter renders as absent (nothing / `null`).
        CurlInfo::ContentType => easy.info.contenttype.clone(),
        // No corresponding datum exposed by the core handle yet; curl's getinfo
        // returns a NULL pointer here, which the emitter renders as absent
        // (nothing / `null`).
        CurlInfo::FtpEntryPath
        | CurlInfo::LocalIp
        | CurlInfo::EffectiveMethod
        | CurlInfo::Referer
        | CurlInfo::PrimaryIp => None,
        _ => None,
    }
}

/// String value for a `CURLINFO_NONE` (special-cased) string variable — curl's
/// `writeString` switch over `wovar->id`.
fn string_special(id: WriteoutId, easy: &Easy, per_result: CurlCode) -> Option<String> {
    match id {
        // No certificate chain available: curl leaves `valid` false, so the
        // value is absent (nothing / `null`).
        WriteoutId::Cert => None,
        // Only produced on failure: the error buffer, or the code's message.
        WriteoutId::Errormsg => {
            if per_result != CurlCode::Ok {
                Some(per_result.message().to_string())
            } else {
                None
            }
        }
        // The saved-to filename is a per-transfer datum not modelled here.
        WriteoutId::EffectiveFilename => None,
        WriteoutId::InputUrl => input_url(easy),
        // The raw and `E`-escaped URL-part families.
        WriteoutId::InputUrlScheme
        | WriteoutId::InputUrlUser
        | WriteoutId::InputUrlPassword
        | WriteoutId::InputUrlOptions
        | WriteoutId::InputUrlHost
        | WriteoutId::InputUrlPort
        | WriteoutId::InputUrlPath
        | WriteoutId::InputUrlQuery
        | WriteoutId::InputUrlFragment
        | WriteoutId::InputUrlZoneid
        | WriteoutId::InputUrlEScheme
        | WriteoutId::InputUrlEUser
        | WriteoutId::InputUrlEPassword
        | WriteoutId::InputUrlEOptions
        | WriteoutId::InputUrlEHost
        | WriteoutId::InputUrlEPort
        | WriteoutId::InputUrlEPath
        | WriteoutId::InputUrlEQuery
        | WriteoutId::InputUrlEFragment
        | WriteoutId::InputUrlEZoneid => urlpart_value(id, easy),
        _ => None,
    }
}

/// `long` value for a variable whose `ci` is a `long`-typed `CURLINFO_*`.
/// getinfo of a `long` always succeeds, so this always yields a value.
fn long_from_info(ci: CurlInfo, easy: &Easy) -> i64 {
    match ci {
        CurlInfo::ResponseCode => i64::from(easy.info.httpcode),
        CurlInfo::PrimaryPort => i64::from(easy.info.conn_remote_port),
        CurlInfo::RedirectCount => easy.state.followlocation,
        // Not yet exposed by the core handle; getinfo returns 0.
        CurlInfo::HttpConnectCode
        | CurlInfo::LocalPort
        | CurlInfo::NumConnects
        | CurlInfo::ProxySslVerifyResult
        | CurlInfo::UsedProxy
        | CurlInfo::HeaderSize
        | CurlInfo::RequestSize
        | CurlInfo::SslVerifyResult => 0,
        _ => 0,
    }
}

/// `long` value for a `CURLINFO_NONE` (special-cased) long variable — curl's
/// `writeLong` switch over `wovar->id`.
fn long_special(id: WriteoutId, easy: &Easy, per_result: CurlCode) -> Option<i64> {
    match id {
        // Per-transfer counters not tracked by the core handle default to zero here.
        WriteoutId::NumRetry | WriteoutId::NumCerts => Some(0),
        // `%{num_headers}` is the count of response headers in the final response
        // (curl's `per->num_headers`, maintained by the header callback). The core
        // handle stores exactly those headers, so their count is the faithful value.
        WriteoutId::NumHeaders => Some(easy.info.resp_headers.len() as i64),
        WriteoutId::Exitcode => Some(i64::from(per_result.to_i32())),
        _ => None,
    }
}

/// `curl_off_t` value for a variable whose `ci` is an off_t-typed `CURLINFO_*`.
/// getinfo of an off_t always succeeds, so this always yields a value.
fn offset_from_info(ci: CurlInfo, easy: &Easy) -> i64 {
    match ci {
        // Body bytes received / sent, measured by the transfer engine
        // (`data->progress.dl.cur_size` / `ul.cur_size`).
        CurlInfo::SizeDownloadT => easy.info.size_download,
        CurlInfo::SizeUploadT => easy.info.size_upload,
        // Average transfer rates over the whole transfer (`bytes / time_total`),
        // derived from the measured byte counts and the total-time timer.
        CurlInfo::SpeedDownloadT => speed_per_sec(easy.info.size_download, easy.info.total_time_us),
        CurlInfo::SpeedUploadT => speed_per_sec(easy.info.size_upload, easy.info.total_time_us),
        // Connection / transfer ids and early-data counters are not measured on
        // the core handle; getinfo returns 0.
        CurlInfo::ConnId | CurlInfo::EarlydataSentT | CurlInfo::XferId => 0,
        _ => 0,
    }
}

/// `curl_off_t` value for a `CURLINFO_NONE` (special-cased) offset variable.
fn offset_special(id: WriteoutId, _easy: &Easy) -> Option<i64> {
    match id {
        // `per->urlnum` (`<= INT_MAX`); defaults to 0 here.
        WriteoutId::Urlnum => Some(0),
        _ => None,
    }
}

/// Microsecond time value for a `*_TIME_T` `CURLINFO_*`. getinfo of a time
/// value always succeeds (0 when unmeasured), so this yields `Some`.
///
/// The phase timers are stamped by [`Easy::perform_transfer`] as microsecond
/// offsets from the transfer clock's origin (curl's `data->progress.t_*`), so an
/// `Easy` that has not run a transfer reports `0` for every timer — matching
/// curl's getinfo, which returns `0` for an unmeasured phase.
fn time_us(ci: Option<CurlInfo>, easy: &Easy) -> Option<i64> {
    let info = &easy.info;
    match ci {
        Some(CurlInfo::NamelookupTimeT) => Some(info.namelookup_time_us),
        Some(CurlInfo::ConnectTimeT) => Some(info.connect_time_us),
        Some(CurlInfo::AppconnectTimeT) => Some(info.appconnect_time_us),
        Some(CurlInfo::PretransferTimeT) => Some(info.pretransfer_time_us),
        Some(CurlInfo::StarttransferTimeT) => Some(info.starttransfer_time_us),
        Some(CurlInfo::TotalTimeT) => Some(info.total_time_us),
        // POSTTRANSFER (the instant the request finished being sent) is not
        // separately measured; curl's value lies between pretransfer and
        // starttransfer, so report pretransfer (the request-send origin).
        Some(CurlInfo::PosttransferTimeT) => Some(info.pretransfer_time_us),
        // The easy path performs no request queuing, and this single-exchange
        // driver follows no redirect, so both report `0` (curl reports `0` for
        // an unqueued, non-redirected transfer).
        Some(CurlInfo::QueueTimeT | CurlInfo::RedirectTimeT) => Some(0),
        _ => None,
    }
}

/// Transfer rate in bytes/second for `CURLINFO_SPEED_DOWNLOAD_T` /
/// `CURLINFO_SPEED_UPLOAD_T`: `bytes / total_time_seconds`, i.e.
/// `bytes * 1_000_000 / total_time_us` (curl computes the average speed over the
/// whole transfer, `data->progress.dl.speed`). Returns `0` when no time has
/// elapsed (an `Easy` that has not transferred), matching curl's `0` rate.
fn speed_per_sec(bytes: i64, total_us: i64) -> i64 {
    if total_us <= 0 {
        0
    } else {
        bytes.saturating_mul(1_000_000) / total_us
    }
}

// ===========================================================================
// Output sink
// ===========================================================================

/// Which destination the parse loop is currently writing to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Cur {
    /// The primary stream (process stdout).
    Primary,
    /// The secondary stream (process stderr).
    Secondary,
    /// The open `%output{...}` file.
    File,
}

/// The switchable output sink — curl's `FILE *stream` plus its `fclose_stream`
/// bookkeeping.
///
/// `primary`/`secondary` are borrowed writers (stdout/stderr in production, or
/// capture buffers under test); `file` holds any `%output{...}` redirect.
/// Dropping/replacing `file` closes it, exactly like curl's `curlx_fclose`.
struct Out<'a> {
    primary: &'a mut dyn Write,
    secondary: &'a mut dyn Write,
    file: Option<File>,
    cur: Cur,
}

impl Out<'_> {
    /// Borrow the writer for the current destination.
    fn cur(&mut self) -> &mut dyn Write {
        if matches!(self.cur, Cur::File) {
            if let Some(f) = self.file.as_mut() {
                return f;
            }
        }
        match self.cur {
            Cur::Secondary => &mut *self.secondary,
            _ => &mut *self.primary,
        }
    }

    /// Write raw bytes to the current stream, ignoring I/O errors (parity: a
    /// `--write-out` failure never alters the exit code).
    fn emit_bytes(&mut self, bytes: &[u8]) {
        let _ = self.cur().write_all(bytes);
    }

    /// Write a UTF-8 string to the current stream.
    fn emit_str(&mut self, s: &str) {
        self.emit_bytes(s.as_bytes());
    }

    /// Write a single byte to the current stream.
    fn emit_byte(&mut self, byte: u8) {
        self.emit_bytes(&[byte]);
    }

    /// Write raw bytes to the warning stream (always stderr), mirroring curl's
    /// use of `tool_stderr` for the unknown-variable diagnostic regardless of
    /// the current output stream.
    fn warn_bytes(&mut self, bytes: &[u8]) {
        let _ = self.secondary.write_all(bytes);
    }

    /// Switch subsequent output to stdout (closing any redirect file).
    fn set_stdout(&mut self) {
        self.file = None;
        self.cur = Cur::Primary;
    }

    /// Switch subsequent output to stderr (closing any redirect file).
    fn set_stderr(&mut self) {
        self.file = None;
        self.cur = Cur::Secondary;
    }

    /// Redirect subsequent output to `f` (closing any previous redirect file).
    fn set_file(&mut self, f: File) {
        self.file = Some(f);
        self.cur = Cur::File;
    }
}

// ===========================================================================
// Emitters (curl's writeString / writeLong / writeOffset / writeTime)
// ===========================================================================

/// Emit a string-valued variable — curl's `writeString`.
fn write_string(
    w: &mut dyn Write,
    var: &WriteoutVar,
    easy: &Easy,
    per_result: CurlCode,
    use_json: bool,
) -> bool {
    let value: Option<String> = match var.ci {
        // `http_version` reads a `long` but is rendered via the string table.
        Some(CurlInfo::HttpVersion) => {
            http_version_str(http_version_long(easy)).map(str::to_string)
        }
        Some(ci) => string_from_info(ci, easy),
        None => string_special(var.id, easy, per_result),
    };
    match value {
        Some(s) => {
            if use_json {
                let _ = write!(w, "\"{}\":", var.name);
                json_write_string(w, s.as_bytes(), false);
            } else {
                let _ = w.write_all(s.as_bytes());
            }
        }
        None => {
            if use_json {
                let _ = write!(w, "\"{}\":null", var.name);
            }
        }
    }
    true
}

/// Emit a `long`-valued variable — curl's `writeLong`.
fn write_long(
    w: &mut dyn Write,
    var: &WriteoutVar,
    easy: &Easy,
    per_result: CurlCode,
    use_json: bool,
) -> bool {
    let value: Option<i64> = match var.ci {
        Some(ci) => Some(long_from_info(ci, easy)),
        None => long_special(var.id, easy, per_result),
    };
    match value {
        Some(n) => {
            if use_json {
                let _ = write!(w, "\"{}\":{}", var.name, n);
            } else if matches!(var.id, WriteoutId::HttpCode | WriteoutId::HttpCodeProxy) {
                // HTTP status codes are zero-padded to three digits (`%03ld`).
                let _ = write!(w, "{n:03}");
            } else {
                let _ = write!(w, "{n}");
            }
        }
        None => {
            if use_json {
                let _ = write!(w, "\"{}\":null", var.name);
            }
        }
    }
    true
}

/// Emit a `curl_off_t`-valued variable — curl's `writeOffset`.
fn write_offset(w: &mut dyn Write, var: &WriteoutVar, easy: &Easy, use_json: bool) -> bool {
    let value: Option<i64> = match var.ci {
        Some(ci) => Some(offset_from_info(ci, easy)),
        None => offset_special(var.id, easy),
    };
    match value {
        Some(n) => {
            if use_json {
                let _ = write!(w, "\"{}\":", var.name);
            }
            let _ = write!(w, "{n}");
        }
        None => {
            if use_json {
                let _ = write!(w, "\"{}\":null", var.name);
            }
        }
    }
    true
}

/// Emit a time variable — curl's `writeTime`. The microsecond `CURLINFO`
/// value is split into whole seconds and a zero-padded six-digit remainder.
fn write_time(w: &mut dyn Write, var: &WriteoutVar, easy: &Easy, use_json: bool) -> bool {
    match time_us(var.ci, easy) {
        Some(us) => {
            let secs = us / 1_000_000;
            let usec = us % 1_000_000;
            if use_json {
                let _ = write!(w, "\"{}\":", var.name);
            }
            let _ = write!(w, "{secs}.{usec:06}");
        }
        None => {
            if use_json {
                let _ = write!(w, "\"{}\":null", var.name);
            }
        }
    }
    true
}

/// Dispatch a variable to its emitter — the Rust stand-in for calling curl's
/// `wovar->writefunc`.
///
/// Returns `true` if the variable has a real emitter (so the `%{json}` caller
/// should append a comma), matching curl's `writefunc` returning `1`.
/// [`WriteKind::Special`] rows have a `NULL` `writefunc`: they return `false`
/// and write nothing.
pub fn emit_var(
    w: &mut dyn Write,
    var: &WriteoutVar,
    easy: &Easy,
    per_result: CurlCode,
    use_json: bool,
) -> bool {
    match var.kind {
        WriteKind::Str => write_string(w, var, easy, per_result, use_json),
        WriteKind::Long => write_long(w, var, easy, per_result, use_json),
        WriteKind::Offset => write_offset(w, var, easy, use_json),
        WriteKind::Time => write_time(w, var, easy, use_json),
        WriteKind::Special => false,
    }
}

// ===========================================================================
// Format-string parser (curl's ourWriteOut and its helpers)
// ===========================================================================

/// Find the first `needle` at or after `start` in `b` — a bounds-checked
/// `strchr`/`memchr` starting from an offset.
fn memchr_from(b: &[u8], start: usize, needle: u8) -> Option<usize> {
    b.get(start..)
        .and_then(|s| s.iter().position(|&c| c == needle))
        .map(|p| start + p)
}

/// Open a `%output{...}` destination — `"w"` (truncate) or `"a"` (append),
/// both creating the file. Returns `None` on failure so the caller keeps the
/// previous stream, exactly like curl.
fn open_output(name: &str, append: bool) -> Option<File> {
    let mut opts = OpenOptions::new();
    opts.create(true);
    if append {
        opts.append(true);
    } else {
        opts.write(true).truncate(true);
    }
    opts.open(name).ok()
}

/// The current wall-clock time as `(seconds, microseconds)` for `%{time{…}}`.
///
/// In debug builds, `CURL_TIME` (leading decimal digits) overrides the clock —
/// curl's `DEBUGBUILD` hook that makes test output deterministic. curl assigns
/// `secs = val` and `usecs = val % 1_000_000`, which is reproduced verbatim.
fn current_time() -> (i64, u32) {
    #[cfg(debug_assertions)]
    {
        if let Ok(ts) = std::env::var("CURL_TIME") {
            let digits: String = ts.chars().take_while(char::is_ascii_digit).collect();
            if let Ok(val) = digits.parse::<i64>() {
                let usecs = (val % 1_000_000) as u32;
                return (val, usecs);
            }
        }
    }
    let now = Utc::now();
    (now.timestamp(), now.timestamp_subsec_micros())
}

/// Fetch one response header value — the Rust seam for curl's
/// `curl_easy_header`. Returns `(value, index, amount)` where `amount` is the
/// total number of headers matching `name` and `index` is the 0-based
/// occurrence just returned.
///
/// Reads the response headers captured by the core handle
/// ([`Easy::info`]`.resp_headers`). Only the final response's headers are
/// retained, so any `request` index beyond the last (`request > 0`) has no
/// stored headers: curl's `CURLH_HEADER` selects the last request for
/// `request == -1`, and `request == 0` is that same (only) response here.
/// Header names are matched case-insensitively, mirroring libcurl's
/// case-insensitive header hash.
fn easy_header(
    easy: &Easy,
    name: &[u8],
    index: usize,
    request: i32,
) -> Option<(String, usize, usize)> {
    if request > 0 {
        return None;
    }
    let name = core::str::from_utf8(name).ok()?;
    // `amount` counts every header matching `name`; `hit` captures the value of
    // the `index`-th match (0-based) as we pass it.
    let mut amount = 0usize;
    let mut hit: Option<String> = None;
    for (hname, hvalue) in &easy.info.resp_headers {
        if hname.eq_ignore_ascii_case(name) {
            if amount == index {
                hit = Some(hvalue.clone());
            }
            amount += 1;
        }
    }
    hit.map(|value| (value, index, amount))
}

/// Emit a `name:all:[sep]` separator, honouring the `\r \n \t \}` escapes —
/// curl's `separator()`.
fn separator(w: &mut dyn Write, sep: &[u8]) {
    let mut i = 0;
    while i < sep.len() {
        if sep[i] == b'\\' {
            match sep.get(i + 1).copied() {
                Some(b'r') => {
                    let _ = w.write_all(b"\r");
                }
                Some(b'n') => {
                    let _ = w.write_all(b"\n");
                }
                Some(b't') => {
                    let _ = w.write_all(b"\t");
                }
                Some(b'}') => {
                    let _ = w.write_all(b"}");
                }
                // Trailing backslash (curl's `case '\0'`): emit nothing.
                None => {}
                // Unknown escape: emit both characters verbatim.
                Some(other) => {
                    let _ = w.write_all(&[b'\\', other]);
                }
            }
            i += 2;
        } else {
            let _ = w.write_all(&[sep[i]]);
            i += 1;
        }
    }
}

/// Handle `%header{...}` — curl's `output_header`. `start` points just past
/// `%header{`; returns the index just past the closing `}` (or `start` if
/// there is no close, after emitting the literal `%header{`).
fn output_header(out: &mut Out, easy: &Easy, start: usize, b: &[u8]) -> usize {
    // Find the first `}` that is not backslash-escaped (`\}`).
    let mut end = memchr_from(b, start, b'}');
    while let Some(e) = end {
        if e == 0 || b[e - 1] != b'\\' {
            break;
        }
        end = memchr_from(b, e + 1, b'}');
    }

    let Some(e) = end else {
        out.emit_str("%header{");
        return start;
    };

    let spec = &b[start..e];
    // Optional `:all:[sep]` instruction selecting every matching header.
    let mut name: &[u8] = spec;
    let mut sep: Option<&[u8]> = None;
    if let Some(colon) = spec.iter().position(|&c| c == b':') {
        let after = &spec[colon + 1..];
        if after.len() >= 4 && &after[..4] == b"all:" {
            name = &spec[..colon];
            sep = Some(&after[4..]);
        }
    }

    // curl caps the header name at `sizeof(hname)` (256).
    if name.len() < 256 {
        if let Some(sepbytes) = sep {
            // Gather the header from every request/index, joined by `sep`.
            let mut reqno: i32 = 0;
            let mut indno: usize = 0;
            let mut output = false;
            while let Some((value, index, amount)) = easy_header(easy, name, indno, reqno) {
                if output {
                    let w = out.cur();
                    separator(w, sepbytes);
                }
                out.emit_str(&value);
                output = true;
                if index + 1 < amount {
                    indno += 1;
                } else {
                    reqno += 1;
                    indno = 0;
                }
            }
        } else if let Some((value, _, _)) = easy_header(easy, name, 0, -1) {
            out.emit_str(&value);
        }
    }

    e + 1
}

/// Handle `%time{FORMAT}` — curl's `outtime`. `start` points at the leading
/// `%`; returns the index just past the closing `}` (or `start + 6` if there
/// is no close, after emitting the literal `%time{`).
fn outtime(out: &mut Out, start: usize, b: &[u8]) -> usize {
    // Skip the six bytes of "%time{".
    let p = start + 6;
    let Some(e) = memchr_from(b, p, b'}') else {
        out.emit_str("%time{");
        return p;
    };

    let spec = &b[p..e];
    let (secs, usecs) = current_time();

    // Rewrite curl's portable extensions into literal text before handing the
    // format to the strftime-style formatter:
    //   %f -> the six-digit microseconds, %z -> "+0000", %Z -> "UTC".
    let mut fmt_bytes: Vec<u8> = Vec::with_capacity(spec.len());
    let mut i = 0;
    let vlen = spec.len();
    while i < vlen {
        if i + 1 < vlen && spec[i] == b'%' && (spec[i + 1] == b'f' || (spec[i + 1] | 0x20) == b'z')
        {
            match spec[i + 1] {
                b'f' => {
                    let mut num = String::new();
                    let _ = write!(&mut num, "{usecs:06}");
                    fmt_bytes.extend_from_slice(num.as_bytes());
                }
                b'Z' => fmt_bytes.extend_from_slice(b"UTC"),
                // lowercase 'z'
                _ => fmt_bytes.extend_from_slice(b"+0000"),
            }
            i += 2;
        } else {
            fmt_bytes.push(spec[i]);
            i += 1;
        }
    }

    // Only ASCII was inserted and original bytes were copied verbatim, so this
    // is lossless for valid UTF-8 formats.
    let fmt = String::from_utf8_lossy(&fmt_bytes);
    if !fmt.is_empty() {
        if let Some(dt) = Utc.timestamp_opt(secs, 0).single() {
            let mut rendered = String::new();
            // `write!` returns `Err` (never panics) on an invalid specifier, in
            // which case nothing is emitted — matching strftime returning 0.
            if write!(&mut rendered, "{}", dt.format(&fmt)).is_ok() {
                out.emit_str(&rendered);
            }
        }
    }

    e + 1
}

/// The `--write-out` format-string interpreter — curl's `ourWriteOut` main
/// loop, operating on the raw bytes of `format`.
fn run(out: &mut Out, format: &str, easy: &Easy, per_result: CurlCode) {
    let b = format.as_bytes();
    let n = b.len();
    let mut i = 0usize;
    let mut done = false;

    while i < n && !done {
        let c = b[i];
        if c == b'%' && i + 1 < n {
            let d = b[i + 1];
            if d == b'%' {
                // Escaped percent.
                out.emit_byte(b'%');
                i += 2;
            } else if d == b'{' {
                match memchr_from(b, i, b'}') {
                    None => {
                        out.emit_str("%{");
                        i += 2;
                    }
                    Some(e) => {
                        let name = &b[i + 2..e];
                        i = e + 1;
                        // curl's name accumulator (dynbuf) rejects names longer
                        // than the cap, which aborts the whole parse.
                        if name.len() > MAX_WRITEOUT_NAME_LENGTH {
                            break;
                        }
                        match lookup(name) {
                            Some(wv) => match wv.id {
                                WriteoutId::Onerror => {
                                    // Only continue emitting when the transfer
                                    // failed; on success, stop here.
                                    if per_result == CurlCode::Ok {
                                        done = true;
                                    }
                                }
                                WriteoutId::Stdout => out.set_stdout(),
                                WriteoutId::Stderr => out.set_stderr(),
                                WriteoutId::Json => {
                                    let w = out.cur();
                                    our_writeout_json(w, easy, per_result);
                                }
                                WriteoutId::HeaderJson => {
                                    let w = out.cur();
                                    header_json(w, easy);
                                }
                                _ => {
                                    let w = out.cur();
                                    emit_var(w, wv, easy, per_result, false);
                                }
                            },
                            None => {
                                out.warn_bytes(b"curl: unknown --write-out variable: '");
                                out.warn_bytes(name);
                                out.warn_bytes(b"'\n");
                            }
                        }
                    }
                }
            } else if b[i + 1..].starts_with(b"header{") {
                // "%header{" spans 8 bytes.
                i = output_header(out, easy, i + 8, b);
            } else if b[i + 1..].starts_with(b"time{") {
                i = outtime(out, i, b);
            } else if b[i + 1..].starts_with(b"output{") {
                // "%output{" spans 8 bytes.
                let mut p = i + 8;
                let mut append = false;
                if p + 1 < n && b[p] == b'>' && b[p + 1] == b'>' {
                    append = true;
                    p += 2;
                }
                match memchr_from(b, p, b'}') {
                    Some(e) => {
                        let fname = &b[p..e];
                        if fname.len() < MAX_OUTPUT_FILENAME {
                            if let Ok(name) = std::str::from_utf8(fname) {
                                if let Some(file) = open_output(name, append) {
                                    // Only switch if the open succeeded.
                                    out.set_file(file);
                                }
                            }
                        }
                        i = e + 1;
                    }
                    None => {
                        out.emit_str("%output{");
                        i = p;
                    }
                }
            } else {
                // Illegal syntax: emit the `%` and the following character.
                out.emit_byte(b'%');
                out.emit_byte(b[i + 1]);
                i += 2;
            }
        } else if c == b'\\' && i + 1 < n {
            match b[i + 1] {
                b'r' => out.emit_byte(b'\r'),
                b'n' => out.emit_byte(b'\n'),
                b't' => out.emit_byte(b'\t'),
                // Unknown escape: emit both characters verbatim.
                other => {
                    out.emit_byte(b'\\');
                    out.emit_byte(other);
                }
            }
            i += 2;
        } else {
            out.emit_byte(c);
            i += 1;
        }
    }
}

// ===========================================================================
// Public entry point
// ===========================================================================

/// Render the `--write-out` format from `config` for a finished transfer —
/// curl's `ourWriteOut`.
///
/// `easy` is the completed easy handle whose `CURLINFO_*` values are emitted,
/// and `per_result` is that transfer's result code (drives `%{onerror}`,
/// `%{exitcode}` and `%{errormsg}`). Output goes to stdout by default;
/// `%{stderr}` / `%output{...}` switch it. Consistent with curl, **any failure
/// inside this function is ignored and never changes the process exit code**.
pub fn our_writeout(config: &OperationConfig, easy: &Easy, per_result: CurlCode) {
    let Some(format) = config.writeout.as_deref() else {
        return;
    };

    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut so = stdout.lock();
    let mut se = stderr.lock();
    let mut out = Out {
        primary: &mut so,
        secondary: &mut se,
        file: None,
        cur: Cur::Primary,
    };
    run(&mut out, format, easy, per_result);
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Render `format` against `easy`/`per_result`, capturing the primary
    /// (stdout) and secondary (stderr) streams into strings.
    fn render(format: &str, easy: &Easy, per_result: CurlCode) -> (String, String) {
        let mut primary: Vec<u8> = Vec::new();
        let mut secondary: Vec<u8> = Vec::new();
        {
            let mut out = Out {
                primary: &mut primary,
                secondary: &mut secondary,
                file: None,
                cur: Cur::Primary,
            };
            run(&mut out, format, easy, per_result);
        }
        (
            String::from_utf8_lossy(&primary).into_owned(),
            String::from_utf8_lossy(&secondary).into_owned(),
        )
    }

    #[test]
    fn table_is_complete_and_byte_sorted() {
        // The full write-out.md catalogue: exactly 72 rows.
        assert_eq!(VARIABLES.len(), 72);
        // Strictly ascending by name (required for the binary search) and every
        // name within the accumulator cap (so valid names never trip the break).
        for w in VARIABLES.windows(2) {
            assert!(
                w[0].name.as_bytes() < w[1].name.as_bytes(),
                "not sorted: {:?} !< {:?}",
                w[0].name,
                w[1].name
            );
        }
        for var in VARIABLES {
            assert!(var.name.len() <= MAX_WRITEOUT_NAME_LENGTH, "{}", var.name);
        }
    }

    #[test]
    fn lookup_matches_and_rejects() {
        assert_eq!(lookup(b"http_code").unwrap().id, WriteoutId::HttpCode);
        assert_eq!(
            lookup(b"urle.scheme").unwrap().id,
            WriteoutId::InputUrlEScheme
        );
        assert_eq!(lookup(b"xfer_id").unwrap().id, WriteoutId::EasyId);
        assert!(lookup(b"bogus").is_none());
        assert!(lookup(b"").is_none());
    }

    #[test]
    fn plain_text_percent_and_escapes() {
        let easy = Easy::default();
        // "%%" -> "%"; "\n\t\r" escapes; unknown "\q" emits both chars.
        let (out, err) = render("ab%%cd\\n\\t\\r\\q", &easy, CurlCode::Ok);
        assert_eq!(out, "ab%cd\n\t\r\\q");
        assert!(err.is_empty());
    }

    #[test]
    fn unknown_variable_warns_to_stderr() {
        let easy = Easy::default();
        let (out, err) = render("x%{bogus}y", &easy, CurlCode::Ok);
        assert_eq!(out, "xy");
        assert!(err.contains("curl: unknown --write-out variable: 'bogus'"));
    }

    #[test]
    fn http_code_is_zero_padded_to_three_digits() {
        let mut easy = Easy::default();
        easy.info.httpcode = 200;
        assert_eq!(render("%{http_code}", &easy, CurlCode::Ok).0, "200");
        assert_eq!(render("%{response_code}", &easy, CurlCode::Ok).0, "200");
        easy.info.httpcode = 80;
        assert_eq!(render("%{http_code}", &easy, CurlCode::Ok).0, "080");
        easy.info.httpcode = 7;
        assert_eq!(render("%{http_code}", &easy, CurlCode::Ok).0, "007");
    }

    #[test]
    fn exitcode_reflects_result_code() {
        let easy = Easy::default();
        assert_eq!(render("%{exitcode}", &easy, CurlCode::Ok).0, "0");
        let code = CurlCode::OperationTimedout;
        assert_eq!(
            render("%{exitcode}", &easy, code).0,
            code.to_i32().to_string()
        );
    }

    #[test]
    fn onerror_gates_the_remainder() {
        let easy = Easy::default();
        // Success: the text after %{onerror} is suppressed.
        assert_eq!(render("A%{onerror}B", &easy, CurlCode::Ok).0, "A");
        // Failure: the remainder is emitted.
        assert_eq!(
            render("A%{onerror}B", &easy, CurlCode::OperationTimedout).0,
            "AB"
        );
    }

    #[test]
    fn stdout_stderr_switch_the_stream() {
        let easy = Easy::default();
        let (out, err) = render("a%{stderr}b%{stdout}c", &easy, CurlCode::Ok);
        assert_eq!(out, "ac");
        assert_eq!(err, "b");
    }

    #[test]
    fn time_values_render_with_six_decimals() {
        let easy = Easy::default();
        assert_eq!(render("%{time_total}", &easy, CurlCode::Ok).0, "0.000000");
        assert_eq!(
            render("%{time_namelookup}", &easy, CurlCode::Ok).0,
            "0.000000"
        );
    }

    #[test]
    fn json_is_well_formed_and_carries_fields() {
        let mut easy = Easy::default();
        easy.info.httpcode = 200;
        let (out, _) = render("%{json}", &easy, CurlCode::Ok);
        let value: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(value["http_code"], 200);
        assert_eq!(value["response_code"], 200);
        assert!(value["certs"].is_null());
        assert_eq!(value["time_total"], 0.0);
        let version = value["curl_version"].as_str().expect("curl_version string");
        assert!(version.starts_with("curl-rs/8.19.0-DEV"));
        // Special (NULL writefunc) variables are omitted from the object.
        assert!(value.get("json").is_none());
        assert!(value.get("stdout").is_none());
    }

    #[test]
    fn header_json_is_empty_object() {
        let easy = Easy::default();
        // No header API on the core handle yet: curl emits "{\n}".
        assert_eq!(render("%{header_json}", &easy, CurlCode::Ok).0, "{\n}");
    }

    #[test]
    fn url_parts_are_extracted() {
        let mut easy = Easy::default();
        easy.state.uh = Some(
            Url::parse(
                "http://user:pass@example.com:8080/a/b?x=1#frag",
                GUESS_SCHEME | NON_SUPPORT_SCHEME,
            )
            .expect("parse"),
        );
        assert_eq!(render("%{url.scheme}", &easy, CurlCode::Ok).0, "http");
        assert_eq!(render("%{url.host}", &easy, CurlCode::Ok).0, "example.com");
        assert_eq!(render("%{url.port}", &easy, CurlCode::Ok).0, "8080");
        assert_eq!(render("%{urle.host}", &easy, CurlCode::Ok).0, "example.com");
    }

    #[test]
    fn scheme_comes_from_connection_info() {
        let mut easy = Easy::default();
        easy.info.conn_scheme = Some("HTTPS".to_string());
        assert_eq!(render("%{scheme}", &easy, CurlCode::Ok).0, "HTTPS");
    }

    #[test]
    fn output_redirect_writes_to_file() {
        let easy = Easy::default();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("wo.txt");
        let fmt = format!("before%output{{{}}}INFILE%{{stdout}}after", path.display());
        let (out, _) = render(&fmt, &easy, CurlCode::Ok);
        assert_eq!(out, "beforeafter");
        let contents = std::fs::read_to_string(&path).expect("read redirect file");
        assert_eq!(contents, "INFILE");
    }

    #[test]
    fn time_format_expands_strftime() {
        let easy = Easy::default();
        // %Y yields a 4-digit year; %f/%z/%Z are curl's portable extensions.
        let (year, _) = render("%time{%Y}", &easy, CurlCode::Ok);
        assert_eq!(year.len(), 4);
        assert!(year.bytes().all(|c| c.is_ascii_digit()));
        assert_eq!(render("%time{%z}", &easy, CurlCode::Ok).0, "+0000");
        assert_eq!(render("%time{%Z}", &easy, CurlCode::Ok).0, "UTC");
        // %f is six microsecond digits.
        let (usecs, _) = render("%time{%f}", &easy, CurlCode::Ok);
        assert_eq!(usecs.len(), 6);
        assert!(usecs.bytes().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn unterminated_specifiers_emit_literally() {
        let easy = Easy::default();
        assert_eq!(render("%{abc", &easy, CurlCode::Ok).0, "%{abc");
        assert_eq!(render("%time{", &easy, CurlCode::Ok).0, "%time{");
        assert_eq!(render("%output{foo", &easy, CurlCode::Ok).0, "%output{foo");
        assert_eq!(render("[%header{X}]", &easy, CurlCode::Ok).0, "[]");
        assert_eq!(render("%header{", &easy, CurlCode::Ok).0, "%header{");
    }

    #[test]
    fn trailing_percent_is_literal() {
        let easy = Easy::default();
        assert_eq!(render("done%", &easy, CurlCode::Ok).0, "done%");
    }
}
