// curl-rs — the `--write-out` engine of the command-line tool.
//
// SPDX-License-Identifier: curl
//
// This module is the Rust reimplementation of curl's `--write-out` engine. The
// original C sources are
//   Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// and are licensed under the curl license (https://curl.se/docs/copyright.html).
//
// It is the behavioral port of two C translation units of the `src/` CLI tree:
//   * `src/tool_writeout.h` — the `writeoutid` id enum, the `struct writeoutvar`
//     table-row type, and the `ourWriteOut` entry point declaration.
//   * `src/tool_writeout.c` — the alphabetical `variables[]` table, the four
//     value writers (`writeString` / `writeLong` / `writeOffset` / `writeTime`),
//     the `%time{}` / `%header{}` sub-syntax handlers, and the `ourWriteOut`
//     format-string parser.
//
// The C constructs are consumed as a behavioral oracle, not transliterated:
// curl's function-pointer `writefunc` becomes the [`WriteFn`] dispatch enum, the
// file-scope `FILE *stream` becomes a [`Box<dyn Write>`] active sink, the
// `CURLINFO`-backed lookups go through [`curl_rs_lib`]'s typed
// [`Easy::getinfo`](curl_rs_lib::Easy::getinfo), and the tool-computed
// (`CURLINFO_NONE`) values are read through the [`PerTransfer`] accessor trait.
// No variable name, number/time formatting, escape, or sub-syntax behavior is
// altered: the observable `--write-out` bytes are reproduced exactly (the
// observable-output-parity mandate, AAP §0.7.3 / §0.8.2).

//! The `--write-out` engine for `curl-rs`.
//!
//! [`our_write_out`] is the public entry point (the port of curl's
//! `ourWriteOut`). It parses the `--write-out` format string held in
//! [`OperationConfig::writeout`](crate::config::OperationConfig) and, for each
//! recognized directive, emits the requested value after a transfer completes.
//!
//! # Directives (byte-for-byte faithful to curl)
//!
//! | Directive             | Meaning                                                  |
//! |-----------------------|----------------------------------------------------------|
//! | `%{name}`             | a `--write-out` variable (see [`VARIABLES`])              |
//! | `%header{name}`       | a response header value (optionally `name:all:SEP`)      |
//! | `%time{fmt}`          | the current time, `strftime`-formatted (UTC)             |
//! | `%output{file}`       | redirect subsequent output to `file` (truncate)          |
//! | `%output{>>file}`     | redirect subsequent output to `file` (append)            |
//! | `%%`                  | a literal `%`                                             |
//! | `\n` `\r` `\t`        | the corresponding control byte                           |
//!
//! # Value sources
//!
//! Each [`VARIABLES`] row carries an optional [`CurlInfo`] selector. Rows with a
//! selector read their value from the transfer's easy handle via
//! [`Easy::getinfo`](curl_rs_lib::Easy::getinfo); rows whose C counterpart used
//! `CURLINFO_NONE` are *tool-computed* and read from the [`PerTransfer`] state
//! (the exit code, the error buffer, header/cert counts, the output filename,
//! the input URL and its parsed components, …).
//!
//! # JSON mode and the `writeout_json` seam
//!
//! `%{json}` and `%{header_json}` are delegated to [`crate::writeout_json`]. That
//! module owns only the JSON envelope; this module owns the single
//! source-of-truth [`VARIABLES`] table and the per-variable rendering. The
//! coupling is the two traits [`JsonVar`] (implemented here for [`WriteOutVar`])
//! and [`HeaderSource`] (a supertrait of [`PerTransfer`]), exactly as curl
//! threads its `writefunc` pointer and `curl_easy_header` walk. Because the
//! same writers run in both plain and JSON mode (switched by a `json: bool`,
//! mirroring curl's `use_json`), the two outputs can never drift apart.
//!
//! # Memory safety
//!
//! Per the rewrite's hard rule (AAP §0.7.1 / §0.8.1) this module contains no
//! `unsafe` and depends only on [`curl_rs_lib`] (never on the FFI crate).

#![forbid(unsafe_code)]

use std::io::{self, Write};

use chrono::format::{Item, StrftimeItems};
use chrono::{TimeZone, Utc};

use curl_rs_lib::error::{codes, CurlError};
use curl_rs_lib::url::{
    CurlUPart, CurlUrl, CURLU_DEFAULT_PORT, CURLU_GUESS_SCHEME, CURLU_NON_SUPPORT_SCHEME,
};
use curl_rs_lib::{version, CurlInfo, Easy, InfoValue};

use crate::config::OperationConfig;
use crate::writeout_json::{
    header_json, json_write_string, write_out_json, HeaderSource, JsonVar,
};

// ===========================================================================
// Phase A — Types
// ===========================================================================

/// The canonical `--write-out` variable id, the Rust analog of curl's
/// `typedef enum { … } writeoutid` (`src/tool_writeout.h`).
///
/// The variants appear in the exact order of the C enum (which is *not* the
/// alphabetical order of the [`VARIABLES`] table — that ordering is a separate
/// contract). curl's two zero/count sentinels `VAR_NONE` and `VAR_NUM_OF_VARS`
/// are intentionally omitted: they exist in C only to seed `bsearch`'s
/// zero-initialized key and to size arrays, neither of which this port needs.
/// Every variant below is referenced by at least one [`VARIABLES`] row.
///
/// The `INPUT_URL*` group is the parsed components of the *input* URL; the
/// `INPUT_URLE*` group is the same components of the *effective* URL. curl keeps
/// `INPUT_URLESCHEME` as the first effective-URL id and switches behavior on
/// `id >= VAR_INPUT_URLESCHEME`; this port instead dispatches each id explicitly
/// in [`url_part`], so the precise discriminant values are unimportant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteOutId {
    /// `VAR_APPCONNECT_TIME` — `time_appconnect`.
    AppconnectTime,
    /// `VAR_CERT` — `certs` (the PEM/text certificate chain).
    Cert,
    /// `VAR_CONNECT_TIME` — `time_connect`.
    ConnectTime,
    /// `VAR_CONTENT_TYPE` — `content_type`.
    ContentType,
    /// `VAR_CONN_ID` — `conn_id`.
    ConnId,
    /// `VAR_EASY_ID` — `xfer_id`.
    EasyId,
    /// `VAR_EFFECTIVE_FILENAME` — `filename_effective`.
    EffectiveFilename,
    /// `VAR_EFFECTIVE_METHOD` — `method`.
    EffectiveMethod,
    /// `VAR_EFFECTIVE_URL` — `url_effective`.
    EffectiveUrl,
    /// `VAR_ERRORMSG` — `errormsg`.
    ErrorMsg,
    /// `VAR_EXITCODE` — `exitcode`.
    ExitCode,
    /// `VAR_FTP_ENTRY_PATH` — `ftp_entry_path`.
    FtpEntryPath,
    /// `VAR_HEADER_JSON` — `header_json` (special, no writer).
    HeaderJson,
    /// `VAR_HEADER_SIZE` — `size_header`.
    HeaderSize,
    /// `VAR_HTTP_CODE` — `http_code` and its alias `response_code`.
    HttpCode,
    /// `VAR_HTTP_CODE_PROXY` — `http_connect`.
    HttpCodeProxy,
    /// `VAR_HTTP_VERSION` — `http_version` (a long rendered as a string).
    HttpVersion,
    /// `VAR_INPUT_URL` — `url` (the raw input URL).
    InputUrl,
    /// `VAR_INPUT_URLSCHEME` — `url.scheme`.
    InputUrlScheme,
    /// `VAR_INPUT_URLUSER` — `url.user`.
    InputUrlUser,
    /// `VAR_INPUT_URLPASSWORD` — `url.password`.
    InputUrlPassword,
    /// `VAR_INPUT_URLOPTIONS` — `url.options`.
    InputUrlOptions,
    /// `VAR_INPUT_URLHOST` — `url.host`.
    InputUrlHost,
    /// `VAR_INPUT_URLPORT` — `url.port`.
    InputUrlPort,
    /// `VAR_INPUT_URLPATH` — `url.path`.
    InputUrlPath,
    /// `VAR_INPUT_URLQUERY` — `url.query`.
    InputUrlQuery,
    /// `VAR_INPUT_URLFRAGMENT` — `url.fragment`.
    InputUrlFragment,
    /// `VAR_INPUT_URLZONEID` — `url.zoneid`.
    InputUrlZoneId,
    /// `VAR_INPUT_URLESCHEME` — `urle.scheme` (first effective-URL id in C).
    InputUrlEScheme,
    /// `VAR_INPUT_URLEUSER` — `urle.user`.
    InputUrlEUser,
    /// `VAR_INPUT_URLEPASSWORD` — `urle.password`.
    InputUrlEPassword,
    /// `VAR_INPUT_URLEOPTIONS` — `urle.options`.
    InputUrlEOptions,
    /// `VAR_INPUT_URLEHOST` — `urle.host`.
    InputUrlEHost,
    /// `VAR_INPUT_URLEPORT` — `urle.port`.
    InputUrlEPort,
    /// `VAR_INPUT_URLEPATH` — `urle.path`.
    InputUrlEPath,
    /// `VAR_INPUT_URLEQUERY` — `urle.query`.
    InputUrlEQuery,
    /// `VAR_INPUT_URLEFRAGMENT` — `urle.fragment`.
    InputUrlEFragment,
    /// `VAR_INPUT_URLEZONEID` — `urle.zoneid`.
    InputUrlEZoneId,
    /// `VAR_JSON` — `json` (special, no writer).
    Json,
    /// `VAR_LOCAL_IP` — `local_ip`.
    LocalIp,
    /// `VAR_LOCAL_PORT` — `local_port`.
    LocalPort,
    /// `VAR_NAMELOOKUP_TIME` — `time_namelookup`.
    NamelookupTime,
    /// `VAR_NUM_CERTS` — `num_certs`.
    NumCerts,
    /// `VAR_NUM_CONNECTS` — `num_connects`.
    NumConnects,
    /// `VAR_NUM_HEADERS` — `num_headers`.
    NumHeaders,
    /// `VAR_NUM_RETRY` — `num_retries`.
    NumRetry,
    /// `VAR_ONERROR` — `onerror` (special, gates the remainder on failure).
    OnError,
    /// `VAR_PRETRANSFER_TIME` — `time_pretransfer`.
    PretransferTime,
    /// `VAR_POSTTRANSFER_TIME` — `time_posttransfer`.
    PosttransferTime,
    /// `VAR_PRIMARY_IP` — `remote_ip`.
    PrimaryIp,
    /// `VAR_PRIMARY_PORT` — `remote_port`.
    PrimaryPort,
    /// `VAR_PROXY_SSL_VERIFY_RESULT` — `proxy_ssl_verify_result`.
    ProxySslVerifyResult,
    /// `VAR_PROXY_USED` — `proxy_used`.
    ProxyUsed,
    /// `VAR_QUEUE_TIME` — `time_queue`.
    QueueTime,
    /// `VAR_REDIRECT_COUNT` — `num_redirects`.
    RedirectCount,
    /// `VAR_REDIRECT_TIME` — `time_redirect`.
    RedirectTime,
    /// `VAR_REDIRECT_URL` — `redirect_url`.
    RedirectUrl,
    /// `VAR_REFERER` — `referer`.
    Referer,
    /// `VAR_REQUEST_SIZE` — `size_request`.
    RequestSize,
    /// `VAR_SCHEME` — `scheme`.
    Scheme,
    /// `VAR_SIZE_DOWNLOAD` — `size_download`.
    SizeDownload,
    /// `VAR_SIZE_UPLOAD` — `size_upload`.
    SizeUpload,
    /// `VAR_SPEED_DOWNLOAD` — `speed_download`.
    SpeedDownload,
    /// `VAR_SPEED_UPLOAD` — `speed_upload`.
    SpeedUpload,
    /// `VAR_SSL_VERIFY_RESULT` — `ssl_verify_result`.
    SslVerifyResult,
    /// `VAR_STARTTRANSFER_TIME` — `time_starttransfer`.
    StarttransferTime,
    /// `VAR_STDERR` — `stderr` (special, switches the active stream).
    Stderr,
    /// `VAR_STDOUT` — `stdout` (special, switches the active stream).
    Stdout,
    /// `VAR_TLS_EARLYDATA_SENT` — `tls_earlydata`.
    TlsEarlydataSent,
    /// `VAR_TOTAL_TIME` — `time_total`.
    TotalTime,
    /// `VAR_URLNUM` — `urlnum`.
    UrlNum,
}

/// Selects which value writer renders a [`WriteOutVar`], the Rust analog of
/// curl's `int (*writefunc)(…)` function pointer (`struct writeoutvar`).
///
/// curl's table stores either one of four writer functions or `NULL`. The four
/// functions become [`String`](WriteFn::String) / [`Long`](WriteFn::Long) /
/// [`Offset`](WriteFn::Offset) / [`Time`](WriteFn::Time); the `NULL` rows
/// (`json`, `header_json`, `onerror`, `stdout`, `stderr`) become
/// [`Special`](WriteFn::Special) and are handled inline by [`our_write_out`]
/// (and contribute nothing to `%{json}`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteFn {
    /// curl `writeString` — a string from `getinfo` or tool state.
    String,
    /// curl `writeLong` — a `long` from `getinfo` or tool state.
    Long,
    /// curl `writeOffset` — a `curl_off_t` from `getinfo` or tool state.
    Offset,
    /// curl `writeTime` — a microsecond `*_TIME_T` `getinfo`, printed as
    /// fractional seconds.
    Time,
    /// curl `NULL` writefunc — handled inline; produces no `%{json}` member.
    Special,
}

/// One row of the `--write-out` variable table, the Rust analog of curl's
/// `struct writeoutvar` (`src/tool_writeout.h`).
///
/// * `name` — the `%{name}` spelling (the bsearch key in C).
/// * `id` — the [`WriteOutId`], used for the inline special cases and the
///   per-id branches inside the writers.
/// * `ci` — the [`CurlInfo`] selector, or [`None`] for the tool-computed
///   (`CURLINFO_NONE`) rows.
/// * `write` — which [`WriteFn`] renders the value.
#[derive(Clone, Copy, Debug)]
pub struct WriteOutVar {
    /// The `%{name}` spelling.
    pub name: &'static str,
    /// The canonical variable id.
    pub id: WriteOutId,
    /// The `getinfo` selector, or [`None`] for tool-computed values.
    pub ci: Option<CurlInfo>,
    /// The value writer that renders this variable.
    pub write: WriteFn,
}

use WriteFn::{Long as L, Offset as O, Special as X, String as S, Time as T};
use WriteOutId as V;

/// The complete `--write-out` variable table — the single source of truth, the
/// Rust port of curl's `static const struct writeoutvar variables[]`
/// (`src/tool_writeout.c`).
///
/// The rows are in the **exact alphabetical order by `name`** of the C table
/// (which curl relies on for `bsearch`, and which [`crate::writeout_json`] relies
/// on for the member order of `%{json}`). This ordering is a parity contract:
/// the row count (72) and every `name → (id, ci, write)` triple match
/// `tool_writeout.c` byte-for-byte, including the two id aliases
/// (`http_code` and `response_code` both map to [`WriteOutId::HttpCode`]) and
/// the `getinfo` substitutions curl documents inline (e.g. `size_download` reads
/// the `_T` offset variant `CURLINFO_SIZE_DOWNLOAD_T`, and `http_version` reads
/// the `long` `CURLINFO_HTTP_VERSION` but is rendered by the string writer).
pub static VARIABLES: &[WriteOutVar] = &[
    row("certs", V::Cert, None, S),
    row("conn_id", V::ConnId, Some(CurlInfo::ConnId), O),
    row("content_type", V::ContentType, Some(CurlInfo::ContentType), S),
    row("errormsg", V::ErrorMsg, None, S),
    row("exitcode", V::ExitCode, None, L),
    row("filename_effective", V::EffectiveFilename, None, S),
    row("ftp_entry_path", V::FtpEntryPath, Some(CurlInfo::FtpEntryPath), S),
    row("header_json", V::HeaderJson, None, X),
    row("http_code", V::HttpCode, Some(CurlInfo::ResponseCode), L),
    row("http_connect", V::HttpCodeProxy, Some(CurlInfo::HttpConnectCode), L),
    row("http_version", V::HttpVersion, Some(CurlInfo::HttpVersion), S),
    row("json", V::Json, None, X),
    row("local_ip", V::LocalIp, Some(CurlInfo::LocalIp), S),
    row("local_port", V::LocalPort, Some(CurlInfo::LocalPort), L),
    row("method", V::EffectiveMethod, Some(CurlInfo::EffectiveMethod), S),
    row("num_certs", V::NumCerts, None, L),
    row("num_connects", V::NumConnects, Some(CurlInfo::NumConnects), L),
    row("num_headers", V::NumHeaders, None, L),
    row("num_redirects", V::RedirectCount, Some(CurlInfo::RedirectCount), L),
    row("num_retries", V::NumRetry, None, L),
    row("onerror", V::OnError, None, X),
    row(
        "proxy_ssl_verify_result",
        V::ProxySslVerifyResult,
        Some(CurlInfo::ProxySslVerifyResult),
        L,
    ),
    row("proxy_used", V::ProxyUsed, Some(CurlInfo::UsedProxy), L),
    row("redirect_url", V::RedirectUrl, Some(CurlInfo::RedirectUrl), S),
    row("referer", V::Referer, Some(CurlInfo::Referer), S),
    row("remote_ip", V::PrimaryIp, Some(CurlInfo::PrimaryIp), S),
    row("remote_port", V::PrimaryPort, Some(CurlInfo::PrimaryPort), L),
    row("response_code", V::HttpCode, Some(CurlInfo::ResponseCode), L),
    row("scheme", V::Scheme, Some(CurlInfo::Scheme), S),
    row("size_download", V::SizeDownload, Some(CurlInfo::SizeDownloadT), O),
    row("size_header", V::HeaderSize, Some(CurlInfo::HeaderSize), L),
    row("size_request", V::RequestSize, Some(CurlInfo::RequestSize), L),
    row("size_upload", V::SizeUpload, Some(CurlInfo::SizeUploadT), O),
    row(
        "speed_download",
        V::SpeedDownload,
        Some(CurlInfo::SpeedDownloadT),
        O,
    ),
    row("speed_upload", V::SpeedUpload, Some(CurlInfo::SpeedUploadT), O),
    row(
        "ssl_verify_result",
        V::SslVerifyResult,
        Some(CurlInfo::SslVerifyResult),
        L,
    ),
    row("stderr", V::Stderr, None, X),
    row("stdout", V::Stdout, None, X),
    row(
        "time_appconnect",
        V::AppconnectTime,
        Some(CurlInfo::AppconnectTimeT),
        T,
    ),
    row("time_connect", V::ConnectTime, Some(CurlInfo::ConnectTimeT), T),
    row(
        "time_namelookup",
        V::NamelookupTime,
        Some(CurlInfo::NamelookupTimeT),
        T,
    ),
    row(
        "time_posttransfer",
        V::PosttransferTime,
        Some(CurlInfo::PosttransferTimeT),
        T,
    ),
    row(
        "time_pretransfer",
        V::PretransferTime,
        Some(CurlInfo::PretransferTimeT),
        T,
    ),
    row("time_queue", V::QueueTime, Some(CurlInfo::QueueTimeT), T),
    row("time_redirect", V::RedirectTime, Some(CurlInfo::RedirectTimeT), T),
    row(
        "time_starttransfer",
        V::StarttransferTime,
        Some(CurlInfo::StarttransferTimeT),
        T,
    ),
    row("time_total", V::TotalTime, Some(CurlInfo::TotalTimeT), T),
    row(
        "tls_earlydata",
        V::TlsEarlydataSent,
        Some(CurlInfo::EarlydataSentT),
        O,
    ),
    row("url", V::InputUrl, None, S),
    row("url.fragment", V::InputUrlFragment, None, S),
    row("url.host", V::InputUrlHost, None, S),
    row("url.options", V::InputUrlOptions, None, S),
    row("url.password", V::InputUrlPassword, None, S),
    row("url.path", V::InputUrlPath, None, S),
    row("url.port", V::InputUrlPort, None, S),
    row("url.query", V::InputUrlQuery, None, S),
    row("url.scheme", V::InputUrlScheme, None, S),
    row("url.user", V::InputUrlUser, None, S),
    row("url.zoneid", V::InputUrlZoneId, None, S),
    row("url_effective", V::EffectiveUrl, Some(CurlInfo::EffectiveUrl), S),
    row("urle.fragment", V::InputUrlEFragment, None, S),
    row("urle.host", V::InputUrlEHost, None, S),
    row("urle.options", V::InputUrlEOptions, None, S),
    row("urle.password", V::InputUrlEPassword, None, S),
    row("urle.path", V::InputUrlEPath, None, S),
    row("urle.port", V::InputUrlEPort, None, S),
    row("urle.query", V::InputUrlEQuery, None, S),
    row("urle.scheme", V::InputUrlEScheme, None, S),
    row("urle.user", V::InputUrlEUser, None, S),
    row("urle.zoneid", V::InputUrlEZoneId, None, S),
    row("urlnum", V::UrlNum, None, O),
    row("xfer_id", V::EasyId, Some(CurlInfo::XferId), O),
];

/// `const` helper that builds one [`WriteOutVar`] row, keeping the [`VARIABLES`]
/// table compact and readable (a `const fn` so the whole table is a compile-time
/// constant, just like curl's static initializer).
const fn row(
    name: &'static str,
    id: WriteOutId,
    ci: Option<CurlInfo>,
    write: WriteFn,
) -> WriteOutVar {
    WriteOutVar {
        name,
        id,
        ci,
        write,
    }
}

/// The maximum `%{name}` length curl accepts, mirroring
/// `#define MAX_WRITEOUT_NAME_LENGTH 24` (`src/tool_writeout.c`). A `%{...}`
/// whose name would exceed this is treated as unknown, exactly as curl's bounded
/// `curlx_dyn` name buffer forces.
const MAX_WRITEOUT_NAME_LENGTH: usize = 24;

/// Looks up a variable row by `%{name}`, the Rust analog of curl's `bsearch`
/// over the alphabetical `variables[]` (`matchvar`).
///
/// A linear scan is used rather than a binary search: the table is small (72
/// rows) and a linear scan does not depend on the byte ordering matching C's
/// `strcmp` (it nonetheless does, for ASCII). Returns [`None`] for an unknown
/// name, which [`our_write_out`] reports with curl's exact diagnostic.
fn find_variable(name: &str) -> Option<&'static WriteOutVar> {
    VARIABLES.iter().find(|v| v.name == name)
}

// ===========================================================================
// Phase C — the per-transfer accessor trait
// ===========================================================================

/// Read access to a finished transfer's easy handle and the CLI tool state that
/// `--write-out` reports.
///
/// This is the Rust analog of curl's `struct per_transfer` (`src/tool_operate.h`)
/// as consumed by `tool_writeout.c`. The C writers reach into `per` for two
/// kinds of data:
///
/// * the **libcurl-owned** values, fetched with `curl_easy_getinfo(per->curl,…)`
///   — surfaced here through [`easy`](PerTransfer::easy), which returns the
///   [`curl_rs_lib::Easy`] handle the value writers call
///   [`Easy::getinfo`](curl_rs_lib::Easy::getinfo) on; and
/// * the **tool-computed** (`CURLINFO_NONE`) values — `per->num_retries`,
///   `per->num_headers`, `per->errorbuffer`, `per->outs.filename`, `per->url`,
///   `per->urlnum`, and the certificate chain `per->certinfo` — surfaced through
///   the remaining accessors.
///
/// # Why a trait
///
/// The concrete per-transfer type lives in `crate::operate` (curl's
/// `tool_operate.c`), which depends on this module; defining the surface as a
/// trait here — exactly as the file specification sanctions ("accept a small
/// trait or a `&PerTransfer` reference") — lets `operate.rs` implement it without
/// a dependency cycle, and lets the unit tests below drive the engine with a
/// lightweight mock.
///
/// [`HeaderSource`] is a supertrait so the same per-transfer value satisfies both
/// the `%header{}` / `%{header_json}` header walk (via
/// [`response_headers`](HeaderSource::response_headers)) and the variable writers
/// here, mirroring how C's `per->curl` answers both `curl_easy_header` and
/// `curl_easy_getinfo`.
pub trait PerTransfer: HeaderSource {
    /// The transfer's easy handle (C: `per->curl`), the source of every
    /// `getinfo`-backed value. A shared borrow suffices: the writers only read.
    fn easy(&self) -> &Easy;

    /// Number of retries performed for this transfer (C: `per->num_retries`).
    /// Backs `%{num_retries}` (`VAR_NUM_RETRY`).
    fn num_retries(&self) -> i64;

    /// Number of response headers received (C: `per->num_headers`). Backs
    /// `%{num_headers}` (`VAR_NUM_HEADERS`).
    fn num_headers(&self) -> i64;

    /// The transfer's error message buffer if it holds a message
    /// (C: `per->errorbuffer`, used only when `per_result != CURLE_OK` and the
    /// first byte is non-NUL). Backs `%{errormsg}` (`VAR_ERRORMSG`); when [`None`]
    /// the writer falls back to the [`CurlError::description`] of `per_result`.
    fn error_buffer(&self) -> Option<&str>;

    /// The local file the transfer was saved to, if any (C: `per->outs.filename`).
    /// Backs `%{filename_effective}` (`VAR_EFFECTIVE_FILENAME`).
    fn output_filename(&self) -> Option<&str>;

    /// The transfer's input URL exactly as given on the command line
    /// (C: `per->url`). Backs `%{url}` (`VAR_INPUT_URL`) and gates every
    /// `%{url.*}` / `%{urle.*}` component (curl emits nothing for those unless
    /// `per->url` is set).
    fn input_url(&self) -> Option<&str>;

    /// The 1-based ordinal of this URL within a globbed set (C: `per->urlnum`).
    /// Backs `%{urlnum}` (`VAR_URLNUM`), which curl only emits when the value
    /// fits in an `int`.
    fn urlnum(&self) -> i64;

    /// The captured certificate chain, or [`None`] when no certificate
    /// information is available (C: `per->certinfo`, populated lazily by the C
    /// `certinfo()` helper from `CURLINFO_CERTINFO`).
    ///
    /// Each outer element is one certificate; each inner element is one
    /// `"name: value"` info line as libcurl reports it (the C `curl_slist` of a
    /// `certinfo[i]`). [`None`] reproduces "no `per->certinfo`" — for which
    /// `%{certs}` emits nothing (and `null` in JSON) — while `Some` (even when
    /// empty) reproduces "certinfo present", for which `%{num_certs}` is its
    /// length and `%{certs}` is the concatenated, newline-terminated chain.
    fn cert_chain(&self) -> Option<Vec<Vec<String>>>;
}

// ===========================================================================
// Output-sink adapter
// ===========================================================================

/// Adapts a `&mut dyn Write` into a `Sized` [`Write`], so it can be handed to the
/// generic [`crate::writeout_json`] helpers (which require `W: Write` — a sized
/// writer) from a context that only holds a trait object.
///
/// The value writers below take `&mut dyn Write` (object-safe, so the same
/// function serves both the plain and the JSON-member call paths). The JSON
/// envelope helpers (`json_write_string`, `write_out_json`, `header_json`) are
/// generic over a sized `W`, so a `dyn Write` cannot be passed to them directly;
/// wrapping it here once bridges the gap with a zero-cost forwarding shim.
struct SizedSink<'a>(&'a mut dyn Write);

impl Write for SizedSink<'_> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.write_all(buf)
    }
}

// ===========================================================================
// Phase B — the value writers
// ===========================================================================

/// Reads a `CURLINFO_LONG` value, returning [`None`] unless `getinfo` both
/// succeeds and yields a `long` (the Rust analog of C's
/// `if(!curl_easy_getinfo(...)) valid = true;`).
fn info_long(easy: &Easy, ci: CurlInfo) -> Option<i64> {
    match easy.getinfo(ci) {
        Ok(InfoValue::Long(v)) => Some(v),
        _ => None,
    }
}

/// Reads a `CURLINFO_OFF_T` value (used by both the offset and the time
/// writers, since curl's `*_TIME_T` infos are `curl_off_t`), returning [`None`]
/// unless `getinfo` succeeds and yields an `off_t`.
fn info_offset(easy: &Easy, ci: CurlInfo) -> Option<i64> {
    match easy.getinfo(ci) {
        Ok(InfoValue::OffT(v)) => Some(v),
        _ => None,
    }
}

/// Maps a `CURLINFO_HTTP_VERSION` `long` to its `--write-out` string, the Rust
/// port of curl's `static const struct httpmap http_version[]`. Returns [`None`]
/// for a value absent from the table (curl's loop then finds no match and emits
/// nothing / `null`).
fn http_version_str(version: i64) -> Option<&'static str> {
    match version {
        0 => Some("0"),    // CURL_HTTP_VERSION_NONE
        1 => Some("1"),    // CURL_HTTP_VERSION_1_0
        2 => Some("1.1"),  // CURL_HTTP_VERSION_1_1
        3 => Some("2"),    // CURL_HTTP_VERSION_2 (== _2_0)
        30 => Some("3"),   // CURL_HTTP_VERSION_3
        _ => None,
    }
}

/// Maps a URL-component variable id to its [`CurlUPart`] and whether it targets
/// the **effective** URL (the `urle.*` group) rather than the raw input URL (the
/// `url.*` group). Returns [`None`] for any non-URL-component id.
///
/// This is the Rust analog of the `switch(vid)` inside curl's `urlpart`, plus
/// the `vid >= VAR_INPUT_URLESCHEME` test that selects the effective URL.
fn url_part_kind(id: WriteOutId) -> Option<(CurlUPart, bool)> {
    use WriteOutId::{
        InputUrlEFragment, InputUrlEHost, InputUrlEOptions, InputUrlEPassword, InputUrlEPath,
        InputUrlEPort, InputUrlEQuery, InputUrlEScheme, InputUrlEUser, InputUrlEZoneId,
        InputUrlFragment, InputUrlHost, InputUrlOptions, InputUrlPassword, InputUrlPath,
        InputUrlPort, InputUrlQuery, InputUrlScheme, InputUrlUser, InputUrlZoneId,
    };
    Some(match id {
        InputUrlScheme => (CurlUPart::Scheme, false),
        InputUrlUser => (CurlUPart::User, false),
        InputUrlPassword => (CurlUPart::Password, false),
        InputUrlOptions => (CurlUPart::Options, false),
        InputUrlHost => (CurlUPart::Host, false),
        InputUrlPort => (CurlUPart::Port, false),
        InputUrlPath => (CurlUPart::Path, false),
        InputUrlQuery => (CurlUPart::Query, false),
        InputUrlFragment => (CurlUPart::Fragment, false),
        InputUrlZoneId => (CurlUPart::ZoneId, false),
        InputUrlEScheme => (CurlUPart::Scheme, true),
        InputUrlEUser => (CurlUPart::User, true),
        InputUrlEPassword => (CurlUPart::Password, true),
        InputUrlEOptions => (CurlUPart::Options, true),
        InputUrlEHost => (CurlUPart::Host, true),
        InputUrlEPort => (CurlUPart::Port, true),
        InputUrlEPath => (CurlUPart::Path, true),
        InputUrlEQuery => (CurlUPart::Query, true),
        InputUrlEFragment => (CurlUPart::Fragment, true),
        InputUrlEZoneId => (CurlUPart::ZoneId, true),
        _ => return None,
    })
}

/// Extracts one component of the input or effective URL, the Rust port of curl's
/// `urlpart()`.
///
/// The URL to parse is the effective URL (`CURLINFO_EFFECTIVE_URL`) for the
/// `urle.*` group and the raw input URL (`per->url`) for the `url.*` group. The
/// component is parsed with `CURLU_GUESS_SCHEME | CURLU_NON_SUPPORT_SCHEME` on
/// set and `CURLU_DEFAULT_PORT` on get — byte-identical to the C flags. Any
/// failure (effective-URL lookup, parse, or a missing component) yields [`None`],
/// reproducing curl's nonzero `rc`, for which the caller emits nothing / `null`.
fn url_part<P: PerTransfer>(per: &P, id: WriteOutId) -> Option<String> {
    let (part, effective) = url_part_kind(id)?;
    let url = if effective {
        match per.easy().getinfo(CurlInfo::EffectiveUrl) {
            Ok(InfoValue::Str(Some(cstr))) => cstr.to_str().ok()?.to_owned(),
            _ => return None,
        }
    } else {
        per.input_url()?.to_owned()
    };

    let mut uh = CurlUrl::new();
    if uh
        .set(
            CurlUPart::Url,
            Some(&url),
            CURLU_GUESS_SCHEME | CURLU_NON_SUPPORT_SCHEME,
        )
        .is_err()
    {
        return None;
    }
    uh.get(part, CURLU_DEFAULT_PORT).ok()
}

/// Computes the bytes a [`WriteFn::String`] variable should emit, or [`None`]
/// when the value is invalid (curl's `valid == false`).
///
/// The result is always owned to keep the borrow graph simple (the engine runs
/// once per transfer, so the copies are immaterial). It unifies the three C
/// value sources: the `CURLINFO_HTTP_VERSION` long-to-string map, the generic
/// `getinfo` string fetch, and the tool-computed (`CURLINFO_NONE`) values.
fn string_value<P: PerTransfer>(
    var: &WriteOutVar,
    per: &P,
    per_result: i32,
) -> Option<Vec<u8>> {
    if let Some(ci) = var.ci {
        // The one long-valued string row: HTTP version, mapped through the table.
        if ci == CurlInfo::HttpVersion {
            let v = match per.easy().getinfo(ci) {
                Ok(InfoValue::Long(v)) => v,
                _ => return None,
            };
            return http_version_str(v).map(|s| s.as_bytes().to_vec());
        }
        // Every other `ci` string row: valid only if getinfo yields a non-NULL
        // string (C: `!curl_easy_getinfo(...) && strinfo`).
        return match per.easy().getinfo(ci) {
            Ok(InfoValue::Str(Some(cstr))) => Some(cstr.to_bytes().to_vec()),
            _ => None,
        };
    }

    // CURLINFO_NONE rows — computed from the per-transfer tool state.
    match var.id {
        WriteOutId::Cert => {
            // No certinfo at all → invalid (`%{certs}` emits nothing / null).
            let chain = per.cert_chain()?;
            // certinfo present (even if empty) → valid; build the chain text,
            // stripping a leading case-insensitive "cert:" and ensuring each
            // line ends in '\n' (C: writeString's VAR_CERT dynbuf loop).
            let mut buf: Vec<u8> = Vec::new();
            for cert in &chain {
                for line in cert {
                    let bytes = line.as_bytes();
                    let data: &[u8] =
                        if bytes.len() >= 5 && bytes[..5].eq_ignore_ascii_case(b"cert:") {
                            &bytes[5..]
                        } else {
                            bytes
                        };
                    buf.extend_from_slice(data);
                    if let Some(&last) = buf.last() {
                        if last != b'\n' {
                            buf.push(b'\n');
                        }
                    }
                }
            }
            Some(buf)
        }
        WriteOutId::ErrorMsg => {
            // Only meaningful on failure (C: `if(per_result)`).
            if per_result != codes::CURLE_OK {
                match per.error_buffer() {
                    // A populated error buffer wins (C: `per->errorbuffer[0]`).
                    Some(msg) if !msg.is_empty() => Some(msg.as_bytes().to_vec()),
                    // Otherwise fall back to the strerror text for the code.
                    _ => Some(
                        CurlError::from_code(per_result)
                            .description()
                            .as_bytes()
                            .to_vec(),
                    ),
                }
            } else {
                None
            }
        }
        WriteOutId::EffectiveFilename => per.output_filename().map(|s| s.as_bytes().to_vec()),
        WriteOutId::InputUrl => per.input_url().map(|s| s.as_bytes().to_vec()),
        // The URL-component groups: gated on the input URL being set (the C
        // `if(per->url)` outer guard applies to the effective group too).
        id if url_part_kind(id).is_some() => {
            if per.input_url().is_some() {
                url_part(per, id).map(String::into_bytes)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Renders a `WriteFn::String` variable (the port of C's `writeString`).
fn write_string<P: PerTransfer>(
    out: &mut dyn Write,
    var: &WriteOutVar,
    per: &P,
    per_result: i32,
    use_json: bool,
) -> io::Result<()> {
    match string_value(var, per, per_result) {
        Some(bytes) => {
            if use_json {
                write!(out, "\"{}\":", var.name)?;
                // The JSON envelope is byte-faithful for the ASCII/UTF-8 values
                // these rows carry; the rare non-UTF-8 byte becomes U+FFFD.
                let text = String::from_utf8_lossy(&bytes);
                json_write_string(&mut SizedSink(&mut *out), &text, false)?;
            } else {
                out.write_all(&bytes)?;
            }
        }
        None => {
            if use_json {
                write!(out, "\"{}\":null", var.name)?;
            }
        }
    }
    Ok(())
}

/// Renders a `WriteFn::Long` variable (the port of C's `writeLong`).
fn write_long<P: PerTransfer>(
    out: &mut dyn Write,
    var: &WriteOutVar,
    per: &P,
    per_result: i32,
    use_json: bool,
) -> io::Result<()> {
    let value = match var.ci {
        Some(ci) => info_long(per.easy(), ci),
        None => match var.id {
            WriteOutId::NumRetry => Some(per.num_retries()),
            // certinfo present → its length; absent → 0; always valid.
            WriteOutId::NumCerts => Some(per.cert_chain().map_or(0, |c| c.len() as i64)),
            WriteOutId::NumHeaders => Some(per.num_headers()),
            WriteOutId::ExitCode => Some(i64::from(per_result)),
            _ => None,
        },
    };
    match value {
        Some(v) => {
            if use_json {
                write!(out, "\"{}\":{}", var.name, v)?;
            } else if matches!(var.id, WriteOutId::HttpCode | WriteOutId::HttpCodeProxy) {
                // C: `%03ld` for the two HTTP status codes only.
                write!(out, "{v:03}")?;
            } else {
                write!(out, "{v}")?;
            }
        }
        None => {
            if use_json {
                write!(out, "\"{}\":null", var.name)?;
            }
        }
    }
    Ok(())
}

/// Renders a `WriteFn::Offset` variable (the port of C's `writeOffset`).
fn write_offset<P: PerTransfer>(
    out: &mut dyn Write,
    var: &WriteOutVar,
    per: &P,
    _per_result: i32,
    use_json: bool,
) -> io::Result<()> {
    let value = match var.ci {
        Some(ci) => info_offset(per.easy(), ci),
        None => match var.id {
            // C: only valid when it fits in an `int` (`<= INT_MAX`).
            WriteOutId::UrlNum => {
                let n = per.urlnum();
                if n <= i64::from(i32::MAX) {
                    Some(n)
                } else {
                    None
                }
            }
            _ => None,
        },
    };
    match value {
        Some(v) => {
            if use_json {
                write!(out, "\"{}\":", var.name)?;
            }
            write!(out, "{v}")?;
        }
        None => {
            if use_json {
                write!(out, "\"{}\":null", var.name)?;
            }
        }
    }
    Ok(())
}

/// Renders a `WriteFn::Time` variable (the port of C's `writeTime`).
///
/// The microsecond `*_TIME_T` value is split with integer arithmetic into whole
/// seconds and a zero-padded six-digit fraction — `secs.us` — exactly as curl's
/// `"%…U.%06…U"` format does, so the bytes match without floating-point rounding
/// drift. curl's timers are non-negative, so the `{:06}` fraction is always a
/// plain six-digit field.
fn write_time<P: PerTransfer>(
    out: &mut dyn Write,
    var: &WriteOutVar,
    per: &P,
    _per_result: i32,
    use_json: bool,
) -> io::Result<()> {
    let value = var.ci.and_then(|ci| info_offset(per.easy(), ci));
    match value {
        Some(us) => {
            let secs = us / 1_000_000;
            let frac = us % 1_000_000;
            if use_json {
                write!(out, "\"{}\":", var.name)?;
            }
            write!(out, "{secs}.{frac:06}")?;
        }
        None => {
            if use_json {
                write!(out, "\"{}\":null", var.name)?;
            }
        }
    }
    Ok(())
}

/// Dispatches to the value writer selected by a row's [`WriteFn`].
///
/// [`WriteFn::Special`] rows (curl's `NULL` `writefunc` — `json`, `header_json`,
/// `onerror`, `stdout`, `stderr`) write nothing here; they are handled inline by
/// [`our_write_out`]. This helper is the shared core of both the plain dispatch
/// (`use_json = false`) and the [`JsonVar`] implementation (`use_json = true`).
fn dispatch_write<P: PerTransfer>(
    out: &mut dyn Write,
    var: &WriteOutVar,
    per: &P,
    per_result: i32,
    use_json: bool,
) -> io::Result<()> {
    match var.write {
        WriteFn::String => write_string(out, var, per, per_result, use_json),
        WriteFn::Long => write_long(out, var, per, per_result, use_json),
        WriteFn::Offset => write_offset(out, var, per, per_result, use_json),
        WriteFn::Time => write_time(out, var, per, per_result, use_json),
        WriteFn::Special => Ok(()),
    }
}

// ===========================================================================
// JSON integration — `impl JsonVar` so `%{json}` reuses the writers above
// ===========================================================================

/// Lets [`crate::writeout_json::write_out_json`] render each table row as one
/// `%{json}` object member by reusing the very same value writers in JSON mode.
///
/// Returning `Ok(true)` for the four real writers means the member is emitted
/// (and followed by a comma in the envelope); returning `Ok(false)` for
/// [`WriteFn::Special`] rows means they contribute nothing — exactly curl's
/// "every real `writefunc` returns 1, the `NULL` rows are skipped" behavior.
impl<P: PerTransfer> JsonVar<P, i32> for WriteOutVar {
    fn write_json_member(
        &self,
        out: &mut dyn Write,
        per: &P,
        per_result: i32,
    ) -> io::Result<bool> {
        if self.write == WriteFn::Special {
            return Ok(false);
        }
        dispatch_write(out, self, per, per_result, true)?;
        Ok(true)
    }
}

// ===========================================================================
// Phase D — the format-string engine
// ===========================================================================

/// Which of the three possible destinations the active output stream currently
/// points at. The Rust analog of curl's mutable `FILE *stream` plus its
/// `fclose_stream` flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    /// The process (or test) standard output — the default.
    Stdout,
    /// The process (or test) standard error.
    Stderr,
    /// An open `%output{}` file.
    File,
}

/// The active output stream of [`our_write_out`], routing every write to one of
/// standard output, standard error, or a `%output{}` file.
///
/// This replaces curl's file-scope `FILE *stream` / `bool fclose_stream`: the
/// `stdout`/`stderr` sinks are persistent (so `%{stdout}` and `%{stderr}` switch
/// back and forth without losing buffered output), while the optional `file`
/// holds any `%output{}` redirect. Switching away from a file — or finishing —
/// drops it, which flushes and closes it exactly as curl's `curlx_fclose` does.
struct Sink<O: Write, E: Write> {
    /// Persistent standard-output sink.
    stdout: O,
    /// Persistent standard-error sink (also the target of the unknown-variable
    /// diagnostic, matching curl's `tool_stderr`).
    stderr: E,
    /// The currently open `%output{}` file, if any.
    file: Option<std::fs::File>,
    /// Which sink writes receive.
    target: Target,
}

impl<O: Write, E: Write> Sink<O, E> {
    /// Creates a sink writing to `stdout` by default.
    fn new(stdout: O, stderr: E) -> Self {
        Sink {
            stdout,
            stderr,
            file: None,
            target: Target::Stdout,
        }
    }

    /// Returns the active stream as a trait object (the value writers and the
    /// JSON helpers all write through this).
    fn active(&mut self) -> &mut dyn Write {
        match self.target {
            Target::Stdout => &mut self.stdout,
            Target::Stderr => &mut self.stderr,
            Target::File => {
                if let Some(f) = self.file.as_mut() {
                    f
                } else {
                    // Unreachable in practice (`target == File` implies `file`
                    // is set); fall back to stdout rather than panic.
                    &mut self.stdout
                }
            }
        }
    }

    /// Handles `%{stdout}`: closes any open file and routes to standard output
    /// (C: `if(fclose_stream) curlx_fclose(stream); stream = stdout;`).
    fn switch_stdout(&mut self) {
        self.file = None;
        self.target = Target::Stdout;
    }

    /// Handles `%{stderr}`: closes any open file and routes to standard error.
    fn switch_stderr(&mut self) {
        self.file = None;
        self.target = Target::Stderr;
    }

    /// Handles `%output{...}`: opens `name` for writing (truncating) or
    /// appending, switching to it **only if the open succeeds** — byte-faithful
    /// to curl ("only change if the open worked"). A failed open leaves the
    /// current stream untouched. Opening a new file while one is already open
    /// drops (closes) the previous one, as curl's `curlx_fclose` does.
    fn open_file(&mut self, name: &str, append: bool) {
        let opened = if append {
            std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(name)
        } else {
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(name)
        };
        if let Ok(f) = opened {
            self.file = Some(f);
            self.target = Target::File;
        }
    }

    /// Emits curl's unknown-variable diagnostic to standard error, byte-for-byte:
    /// `curl: unknown --write-out variable: '<name>'\n` (C:
    /// `curl_mfprintf(tool_stderr, …)`). It always targets stderr regardless of
    /// the active stream, and the raw name bytes are written verbatim.
    fn diagnostic(&mut self, name: &[u8]) -> io::Result<()> {
        self.stderr
            .write_all(b"curl: unknown --write-out variable: '")?;
        self.stderr.write_all(name)?;
        self.stderr.write_all(b"'\n")
    }

    /// Flushes the active stream so buffered output is emitted before returning.
    fn finish(&mut self) -> io::Result<()> {
        self.active().flush()
    }
}

/// Finds the next occurrence of `target` in `bytes` at or after `from`, returning
/// its absolute index. The Rust analog of C's `strchr(ptr, target)`.
fn find_byte(bytes: &[u8], from: usize, target: u8) -> Option<usize> {
    bytes[from..].iter().position(|&b| b == target).map(|p| from + p)
}

/// Reports whether `bytes[at..]` begins with `prefix`. The Rust analog of C's
/// `!strncmp(&ptr[…], prefix, len)`.
fn starts_with(bytes: &[u8], at: usize, prefix: &[u8]) -> bool {
    bytes.len() >= at + prefix.len() && &bytes[at..at + prefix.len()] == prefix
}

/// The public entry point — the Rust port of curl's `ourWriteOut`.
///
/// Parses `config`'s [`writeout`](OperationConfig::writeout) format string and
/// writes the rendered result to standard output (the default), to standard
/// error, or to any `%output{}` file the string selects, after the transfer
/// described by `per` finished with `per_result`. A `None`/absent format string
/// is a no-op, exactly as curl returns early when `config->writeout` is `NULL`.
///
/// `per_result` is the transfer's `CURLcode` as an integer (curl's `CURLcode`),
/// driving `%{exitcode}`, `%{errormsg}`, and the `%{onerror}` gate.
///
/// # Errors
///
/// Propagates the first I/O error from the active stream. curl's `void`
/// `ourWriteOut` ignores write failures; surfacing them here is the idiomatic
/// Rust choice and lets the caller in `crate::operate` decide. The rendered
/// bytes are identical either way.
pub fn our_write_out<P: PerTransfer>(
    config: &OperationConfig,
    per: &P,
    per_result: i32,
) -> io::Result<()> {
    let writeinfo = match config.writeout.as_deref() {
        Some(w) => w,
        None => return Ok(()),
    };
    run(
        writeinfo,
        per,
        per_result,
        io::stdout().lock(),
        io::stderr().lock(),
    )
}

/// The format-string interpreter, generic over the standard-output and
/// standard-error sinks so the unit tests can capture both into buffers while
/// production uses the locked process streams.
fn run<P, O, E>(
    writeinfo: &str,
    per: &P,
    per_result: i32,
    stdout: O,
    stderr: E,
) -> io::Result<()>
where
    P: PerTransfer,
    O: Write,
    E: Write,
{
    let mut sink = Sink::new(stdout, stderr);
    let bytes = writeinfo.as_bytes();
    let n = bytes.len();
    let mut i = 0usize;
    let mut done = false;

    while i < n && !done {
        let c = bytes[i];
        if c == b'%' && i + 1 < n {
            let c1 = bytes[i + 1];
            if c1 == b'%' {
                // `%%` → a literal percent sign.
                sink.active().write_all(b"%")?;
                i += 2;
            } else if c1 == b'{' {
                // `%{name}` — a variable reference.
                let end = find_byte(bytes, i, b'}');
                i += 2; // pass the `%` and the `{`
                let end = match end {
                    Some(e) => e,
                    None => {
                        // No closing brace: emit `%{` and resume after it.
                        sink.active().write_all(b"%{")?;
                        continue;
                    }
                };
                let name_len = end - i;
                if name_len >= MAX_WRITEOUT_NAME_LENGTH {
                    // curl's bounded name buffer overflows here and aborts the
                    // whole walk; reproduce that hard stop.
                    break;
                }
                let name_bytes = &bytes[i..end];
                let found = std::str::from_utf8(name_bytes).ok().and_then(find_variable);
                if let Some(wv) = found {
                    handle_variable(wv, &mut sink, per, per_result, &mut done)?;
                } else {
                    sink.diagnostic(name_bytes)?;
                }
                i = end + 1; // pass the `}`
            } else if starts_with(bytes, i + 1, b"header{") {
                i += 8; // pass `%header{`
                output_header(per, &mut sink, bytes, &mut i)?;
            } else if starts_with(bytes, i + 1, b"time{") {
                i = out_time(bytes, i, &mut sink)?;
            } else if starts_with(bytes, i + 1, b"output{") {
                i += 8; // pass `%output{`
                let mut append = false;
                if i + 1 < n && bytes[i] == b'>' && bytes[i + 1] == b'>' {
                    append = true;
                    i += 2;
                }
                match find_byte(bytes, i, b'}') {
                    Some(e) => {
                        let fname_bytes = &bytes[i..e];
                        // curl's `fname[512]` bound: only open when it fits.
                        if fname_bytes.len() < 512 {
                            if let Ok(fname) = std::str::from_utf8(fname_bytes) {
                                sink.open_file(fname, append);
                            }
                        }
                        i = e + 1;
                    }
                    None => {
                        // No closing brace: emit the literal and resume (curl
                        // leaves `ptr` past `%output{` and any `>>`).
                        sink.active().write_all(b"%output{")?;
                    }
                }
            } else {
                // Any other `%X`: emit both bytes verbatim (curl's "illegal
                // syntax" fall-through).
                sink.active().write_all(&[b'%', c1])?;
                i += 2;
            }
        } else if c == b'\\' && i + 1 < n {
            // Backslash escapes recognised outside the sub-syntaxes.
            match bytes[i + 1] {
                b'r' => sink.active().write_all(b"\r")?,
                b'n' => sink.active().write_all(b"\n")?,
                b't' => sink.active().write_all(b"\t")?,
                other => sink.active().write_all(&[b'\\', other])?,
            }
            i += 2;
        } else {
            // An ordinary byte (this also covers a trailing lone `%` or `\`,
            // which curl emits as-is because the `ptr[1]` guard failed).
            sink.active().write_all(&[c])?;
            i += 1;
        }
    }

    sink.finish()
}

/// Dispatches a matched `%{name}` variable, handling the five inline special
/// rows (curl's `NULL`-`writefunc` cases) and otherwise invoking the value
/// writer. Mirrors the `switch(wv->id)` in curl's `ourWriteOut`.
fn handle_variable<P, O, E>(
    wv: &WriteOutVar,
    sink: &mut Sink<O, E>,
    per: &P,
    per_result: i32,
    done: &mut bool,
) -> io::Result<()>
where
    P: PerTransfer,
    O: Write,
    E: Write,
{
    match wv.id {
        // `%{onerror}`: when the transfer SUCCEEDED, skip the rest of the format.
        WriteOutId::OnError => {
            if per_result == codes::CURLE_OK {
                *done = true;
            }
        }
        // `%{stdout}` / `%{stderr}`: redirect subsequent output.
        WriteOutId::Stdout => sink.switch_stdout(),
        WriteOutId::Stderr => sink.switch_stderr(),
        // `%{json}`: the whole-object dump, delegated to `writeout_json`. The
        // single source-of-truth table and `curl_version()` are supplied here.
        WriteOutId::Json => {
            let active = sink.active();
            write_out_json(
                &mut SizedSink(active),
                VARIABLES,
                per,
                per_result,
                version(),
            )?;
        }
        // `%{header_json}`: the response-header object, delegated to
        // `writeout_json` (which walks `PerTransfer`'s `HeaderSource`).
        WriteOutId::HeaderJson => {
            let active = sink.active();
            header_json(&mut SizedSink(active), per)?;
        }
        // Every ordinary variable: render through its value writer.
        _ => {
            let active = sink.active();
            dispatch_write(active, wv, per, per_result, false)?;
        }
    }
    Ok(())
}

/// Renders `%time{strftime-format}` to the active stream, the Rust port of curl's
/// `outtime()`. `start` indexes the opening `%` of `%time{`.
///
/// Returns the index at which the main parser should resume: just past the
/// closing `}` when present, or just past `%time{` when there is no `}` (in which
/// case the literal `%time{` is emitted and the remainder is parsed normally) —
/// matching curl's `return ptr` in both branches.
fn out_time<O: Write, E: Write>(
    bytes: &[u8],
    start: usize,
    sink: &mut Sink<O, E>,
) -> io::Result<usize> {
    let p = start + 6; // pass `%time{`
    let end = match find_byte(bytes, p, b'}') {
        Some(e) => e,
        None => {
            sink.active().write_all(b"%time{")?;
            return Ok(p);
        }
    };

    // Resolve the current time (or the `CURL_TIME` override in debug builds).
    let (secs, usecs) = current_time();

    // Pre-substitute the non-portable `%f` / `%z` / `%Z` specifiers before
    // handing the format to the strftime engine, exactly as curl does.
    let resolved = resolve_time_format(&bytes[p..end], usecs);
    if resolved.is_empty() {
        // C: an empty resolved format produces no output (`if(curlx_dyn_len…)`).
        return Ok(end + 1);
    }

    // The slice sits between two ASCII braces of a `str`, and every substitution
    // is ASCII, so the resolved buffer is valid UTF-8; bail out quietly if not.
    let fmt = match std::str::from_utf8(&resolved) {
        Ok(s) => s,
        Err(_) => return Ok(end + 1),
    };

    if let Some(dt) = Utc.timestamp_opt(secs, 0).single() {
        // Reject an unparseable format rather than letting chrono panic on
        // `Display`; curl's `strftime` would likewise produce nothing useful.
        let items: Vec<Item> = StrftimeItems::new(fmt).collect();
        if !items.iter().any(|it| matches!(it, Item::Error)) {
            let formatted = dt.format_with_items(items.iter()).to_string();
            // C writes only when strftime succeeds and the result fits in its
            // 256-byte buffer (so an output of 256+ bytes is dropped whole).
            if !formatted.is_empty() && formatted.len() < 256 {
                sink.active().write_all(formatted.as_bytes())?;
            }
        }
    }

    Ok(end + 1)
}

/// Returns `(seconds, microseconds)` for `%time{}`.
///
/// Uses the wall clock, except that debug builds honor the `CURL_TIME`
/// environment variable — the deterministic clock override curl exposes under
/// `DEBUGBUILD` for its test suite (`secs = val`, `usecs = val % 1_000_000`).
fn current_time() -> (i64, u32) {
    let now = Utc::now();
    #[allow(unused_mut)]
    let mut secs = now.timestamp();
    #[allow(unused_mut)]
    let mut usecs = now.timestamp_subsec_micros();

    #[cfg(debug_assertions)]
    {
        if let Ok(timestr) = std::env::var("CURL_TIME") {
            if let Some(val) = parse_leading_i64(&timestr) {
                secs = val;
                usecs = (val.rem_euclid(1_000_000)) as u32;
            }
        }
    }

    (secs, usecs)
}

/// Parses the leading decimal digits of `s` into an `i64`, the minimal analog of
/// curl's `curlx_str_number` as used by the `CURL_TIME` override. Returns
/// [`None`] when there are no leading digits or the value overflows.
#[cfg(debug_assertions)]
fn parse_leading_i64(s: &str) -> Option<i64> {
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse::<i64>().ok()
    }
}

/// Pre-substitutes the three non-portable strftime specifiers curl handles
/// itself before calling the platform `strftime`:
///
/// * `%f` → the six-digit zero-padded microseconds,
/// * `%z` → the literal `+0000`, and
/// * `%Z` → the literal `UTC`
///
/// (the timezone is always UTC). Every other byte is copied verbatim. The
/// `i + 1 < len` guard reproduces curl's `i < vlen - 1`, so a trailing `%`
/// cannot start a sequence. The lower-case test `b | 0x20 == b'z'` matches both
/// `%z` and `%Z`, with the exact case then distinguishing them — identical to
/// curl's `(ptr[i + 1] | 0x20) == 'z'`.
fn resolve_time_format(fmt: &[u8], usecs: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(fmt.len());
    let len = fmt.len();
    let mut i = 0;
    while i < len {
        if i + 1 < len && fmt[i] == b'%' && (fmt[i + 1] == b'f' || (fmt[i + 1] | 0x20) == b'z') {
            match fmt[i + 1] {
                b'f' => out.extend_from_slice(format!("{usecs:06}").as_bytes()),
                b'Z' => out.extend_from_slice(b"UTC"),
                _ => out.extend_from_slice(b"+0000"), // lower-case `%z`
            }
            i += 2;
        } else {
            out.push(fmt[i]);
            i += 1;
        }
    }
    out
}

/// Renders `%header{name}` / `%header{name:all:SEP}` to the active stream, the
/// Rust port of curl's `output_header()`. `i` enters positioned just past
/// `%header{` and is advanced past the closing `}` (or left unchanged when there
/// is none, in which case the literal `%header{` is emitted and parsing resumes).
fn output_header<P, O, E>(
    per: &P,
    sink: &mut Sink<O, E>,
    bytes: &[u8],
    i: &mut usize,
) -> io::Result<()>
where
    P: PerTransfer,
    O: Write,
    E: Write,
{
    let start = *i;
    // Find the first `}` that is not backslash-escaped (curl's do/while).
    let mut end = find_byte(bytes, start, b'}');
    while let Some(e) = end {
        if bytes[e - 1] != b'\\' {
            break;
        }
        end = find_byte(bytes, e + 1, b'}');
    }

    let Some(e) = end else {
        sink.active().write_all(b"%header{")?;
        return Ok(()); // leave *i == start; the remainder is parsed normally
    };

    let content = &bytes[start..e];
    // Split off an optional `:all:SEP` instruction; the header name is the text
    // before the first `:` only when that `:` introduces `all:`.
    let mut name: &[u8] = content;
    let mut sep: Option<&[u8]> = None;
    if let Some(colon) = content.iter().position(|&b| b == b':') {
        if content[colon + 1..].starts_with(b"all:") {
            name = &content[..colon];
            sep = Some(&content[colon + 5..]);
        }
    }

    // curl's `hname[256]` bound: a longer name is silently ignored.
    if name.len() < 256 {
        let headers = per.response_headers();
        match sep {
            // `:all:` — every matching header, separated by SEP.
            Some(sep_bytes) => {
                let mut output = false;
                for field in &headers {
                    if field.name.eq_ignore_ascii_case(name) {
                        if output {
                            write_separator(sink.active(), sep_bytes)?;
                        }
                        sink.active().write_all(field.value)?;
                        output = true;
                    }
                }
            }
            // Single header — the first matching occurrence only.
            None => {
                if let Some(field) = headers
                    .iter()
                    .find(|f| f.name.eq_ignore_ascii_case(name))
                {
                    sink.active().write_all(field.value)?;
                }
            }
        }
    }

    *i = e + 1; // pass the `}`
    Ok(())
}

/// Writes a `%header{…:all:SEP}` separator, decoding the `\r`, `\n`, `\t`, and
/// `\}` escapes curl recognises (`separator()`); any other `\X` is emitted as
/// the two literal bytes, and a trailing lone `\` is dropped (curl's
/// `case '\0'`).
fn write_separator(out: &mut dyn Write, sep: &[u8]) -> io::Result<()> {
    let mut i = 0;
    let len = sep.len();
    while i < len {
        if sep[i] == b'\\' {
            if i + 1 < len {
                match sep[i + 1] {
                    b'r' => out.write_all(b"\r")?,
                    b'n' => out.write_all(b"\n")?,
                    b't' => out.write_all(b"\t")?,
                    b'}' => out.write_all(b"}")?,
                    other => out.write_all(&[b'\\', other])?,
                }
                i += 2;
            } else {
                // Lone trailing backslash: curl's `case '\0'` writes nothing.
                break;
            }
        } else {
            out.write_all(&[sep[i]])?;
            i += 1;
        }
    }
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writeout_json::HeaderField;
    use curl_rs_lib::Easy;
    use std::ffi::CString;
    use std::sync::atomic::{AtomicU32, Ordering};

    // --- mock per-transfer ------------------------------------------------

    /// A lightweight [`PerTransfer`] for the tests, owning an [`Easy`] whose
    /// public [`info`](Easy::info) store is populated directly to drive
    /// `getinfo`, plus the tool-computed fields.
    struct MockPer {
        easy: Easy,
        num_retries: i64,
        num_headers: i64,
        error_buffer: Option<String>,
        output_filename: Option<String>,
        input_url: Option<String>,
        urlnum: i64,
        cert_chain: Option<Vec<Vec<String>>>,
        headers: Vec<(Vec<u8>, Vec<u8>)>,
    }

    impl MockPer {
        fn new() -> Self {
            MockPer {
                easy: Easy::new(),
                num_retries: 0,
                num_headers: 0,
                error_buffer: None,
                output_filename: None,
                input_url: None,
                urlnum: 0,
                cert_chain: None,
                headers: Vec::new(),
            }
        }
    }

    impl HeaderSource for MockPer {
        fn response_headers(&self) -> Vec<HeaderField<'_>> {
            self.headers
                .iter()
                .map(|(n, v)| HeaderField {
                    name: n.as_slice(),
                    value: v.as_slice(),
                })
                .collect()
        }
    }

    impl PerTransfer for MockPer {
        fn easy(&self) -> &Easy {
            &self.easy
        }
        fn num_retries(&self) -> i64 {
            self.num_retries
        }
        fn num_headers(&self) -> i64 {
            self.num_headers
        }
        fn error_buffer(&self) -> Option<&str> {
            self.error_buffer.as_deref()
        }
        fn output_filename(&self) -> Option<&str> {
            self.output_filename.as_deref()
        }
        fn input_url(&self) -> Option<&str> {
            self.input_url.as_deref()
        }
        fn urlnum(&self) -> i64 {
            self.urlnum
        }
        fn cert_chain(&self) -> Option<Vec<Vec<String>>> {
            self.cert_chain.clone()
        }
    }

    /// Renders `writeout` against `per`, returning `(stdout, stderr)` bytes.
    fn render(writeout: &str, per: &MockPer, per_result: i32) -> (Vec<u8>, Vec<u8>) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        run(writeout, per, per_result, &mut out, &mut err).expect("render");
        (out, err)
    }

    /// Renders `writeout` and returns the stdout bytes as a `String`.
    fn out_str(writeout: &str, per: &MockPer, per_result: i32) -> String {
        String::from_utf8(render(writeout, per, per_result).0).unwrap()
    }

    fn cstr(s: &str) -> Option<CString> {
        Some(CString::new(s).unwrap())
    }

    // --- Phase A: table audit --------------------------------------------

    #[test]
    fn table_has_exactly_72_rows() {
        assert_eq!(VARIABLES.len(), 72, "the variables table must have 72 rows");
    }

    #[test]
    fn table_is_strictly_alphabetical_by_name() {
        for pair in VARIABLES.windows(2) {
            assert!(
                pair[0].name < pair[1].name,
                "table not sorted: {:?} !< {:?}",
                pair[0].name,
                pair[1].name
            );
        }
    }

    #[test]
    fn table_names_are_unique() {
        for (i, a) in VARIABLES.iter().enumerate() {
            for b in &VARIABLES[i + 1..] {
                assert_ne!(a.name, b.name, "duplicate name {:?}", a.name);
            }
        }
    }

    #[test]
    fn table_aliases_match_c() {
        // http_code == response_code (same id + ci + writer).
        let http_code = find_variable("http_code").unwrap();
        let response_code = find_variable("response_code").unwrap();
        assert_eq!(http_code.id, WriteOutId::HttpCode);
        assert_eq!(response_code.id, WriteOutId::HttpCode);
        assert_eq!(http_code.ci, Some(CurlInfo::ResponseCode));
        assert_eq!(response_code.ci, Some(CurlInfo::ResponseCode));
        assert_eq!(http_code.write, WriteFn::Long);
        assert_eq!(response_code.write, WriteFn::Long);

        // num_redirects -> REDIRECT_COUNT.
        let num_redirects = find_variable("num_redirects").unwrap();
        assert_eq!(num_redirects.id, WriteOutId::RedirectCount);
        assert_eq!(num_redirects.ci, Some(CurlInfo::RedirectCount));
    }

    #[test]
    fn table_spot_check_rows() {
        let cases: &[(&str, WriteOutId, Option<CurlInfo>, WriteFn)] = &[
            ("certs", WriteOutId::Cert, None, WriteFn::String),
            ("conn_id", WriteOutId::ConnId, Some(CurlInfo::ConnId), WriteFn::Offset),
            ("exitcode", WriteOutId::ExitCode, None, WriteFn::Long),
            ("header_json", WriteOutId::HeaderJson, None, WriteFn::Special),
            ("json", WriteOutId::Json, None, WriteFn::Special),
            ("onerror", WriteOutId::OnError, None, WriteFn::Special),
            ("stdout", WriteOutId::Stdout, None, WriteFn::Special),
            ("stderr", WriteOutId::Stderr, None, WriteFn::Special),
            (
                "http_version",
                WriteOutId::HttpVersion,
                Some(CurlInfo::HttpVersion),
                WriteFn::String,
            ),
            (
                "size_download",
                WriteOutId::SizeDownload,
                Some(CurlInfo::SizeDownloadT),
                WriteFn::Offset,
            ),
            (
                "time_total",
                WriteOutId::TotalTime,
                Some(CurlInfo::TotalTimeT),
                WriteFn::Time,
            ),
            ("url", WriteOutId::InputUrl, None, WriteFn::String),
            (
                "url_effective",
                WriteOutId::EffectiveUrl,
                Some(CurlInfo::EffectiveUrl),
                WriteFn::String,
            ),
            ("urlnum", WriteOutId::UrlNum, None, WriteFn::Offset),
            ("xfer_id", WriteOutId::EasyId, Some(CurlInfo::XferId), WriteFn::Offset),
        ];
        for &(name, id, ci, write) in cases {
            let v = find_variable(name).unwrap_or_else(|| panic!("missing {name}"));
            assert_eq!(v.id, id, "{name} id");
            assert_eq!(v.ci, ci, "{name} ci");
            assert_eq!(v.write, write, "{name} writer");
        }
    }

    #[test]
    fn every_url_part_row_is_classified() {
        // All 20 url.* / urle.* rows must map through url_part_kind.
        for v in VARIABLES {
            let is_part_name =
                v.name.starts_with("url.") || v.name.starts_with("urle.");
            if is_part_name {
                assert!(
                    url_part_kind(v.id).is_some(),
                    "{} should be a URL component",
                    v.name
                );
            }
        }
    }

    // --- Phase B: value formatting parity --------------------------------

    #[test]
    fn http_code_uses_three_digit_padding() {
        let mut per = MockPer::new();
        per.easy.info.response_code = 200;
        assert_eq!(out_str("%{http_code}", &per, 0), "200");

        per.easy.info.response_code = 7;
        assert_eq!(out_str("%{http_code}", &per, 0), "007");

        per.easy.info.response_code = 0;
        assert_eq!(out_str("%{http_code}", &per, 0), "000");
    }

    #[test]
    fn response_code_alias_renders_like_http_code() {
        let mut per = MockPer::new();
        per.easy.info.response_code = 404;
        assert_eq!(out_str("%{response_code}", &per, 0), "404");
    }

    #[test]
    fn plain_long_has_no_padding() {
        let mut per = MockPer::new();
        per.easy.info.header_size = 42;
        assert_eq!(out_str("%{size_header}", &per, 0), "42");
    }

    #[test]
    fn time_total_is_seconds_with_six_decimals() {
        let mut per = MockPer::new();
        per.easy.info.total_time_us = 123_456;
        assert_eq!(out_str("%{time_total}", &per, 0), "0.123456");

        per.easy.info.total_time_us = 1_500_000;
        assert_eq!(out_str("%{time_total}", &per, 0), "1.500000");

        per.easy.info.total_time_us = 2_000_007;
        assert_eq!(out_str("%{time_total}", &per, 0), "2.000007");

        per.easy.info.total_time_us = 0;
        assert_eq!(out_str("%{time_total}", &per, 0), "0.000000");
    }

    #[test]
    fn size_download_is_integer_offset() {
        let mut per = MockPer::new();
        per.easy.info.size_download = 2048;
        assert_eq!(out_str("%{size_download}", &per, 0), "2048");
    }

    #[test]
    fn scheme_is_a_plain_string() {
        let mut per = MockPer::new();
        per.easy.info.scheme = cstr("HTTPS");
        assert_eq!(out_str("%{scheme}", &per, 0), "HTTPS");
    }

    #[test]
    fn http_version_maps_long_to_string() {
        let mut per = MockPer::new();
        // internal encodings map to the CURL_HTTP_VERSION_* longs, which map to
        // the write-out strings.
        per.easy.info.http_version = 11; // -> 2 -> "1.1"
        assert_eq!(out_str("%{http_version}", &per, 0), "1.1");
        per.easy.info.http_version = 10; // -> 1 -> "1"
        assert_eq!(out_str("%{http_version}", &per, 0), "1");
        per.easy.info.http_version = 20; // -> 3 -> "2"
        assert_eq!(out_str("%{http_version}", &per, 0), "2");
        per.easy.info.http_version = 30; // -> 30 -> "3"
        assert_eq!(out_str("%{http_version}", &per, 0), "3");
        per.easy.info.http_version = 0; // -> 0 -> "0"
        assert_eq!(out_str("%{http_version}", &per, 0), "0");
    }

    #[test]
    fn exitcode_is_the_result_integer() {
        let per = MockPer::new();
        assert_eq!(out_str("%{exitcode}", &per, 0), "0");
        assert_eq!(out_str("%{exitcode}", &per, 7), "7");
        assert_eq!(out_str("%{exitcode}", &per, 60), "60");
    }

    #[test]
    fn errormsg_uses_buffer_then_strerror_then_nothing() {
        let mut per = MockPer::new();
        // populated buffer wins on failure
        per.error_buffer = Some("custom failure".into());
        assert_eq!(out_str("%{errormsg}", &per, 7), "custom failure");

        // empty buffer on failure -> strerror description (non-empty)
        per.error_buffer = Some(String::new());
        let s = out_str("%{errormsg}", &per, 7);
        assert!(!s.is_empty(), "strerror fallback should be non-empty");

        // no buffer on failure -> strerror description
        per.error_buffer = None;
        let s = out_str("%{errormsg}", &per, 7);
        assert!(!s.is_empty());

        // success -> nothing
        assert_eq!(out_str("%{errormsg}", &per, 0), "");
    }

    #[test]
    fn num_retries_and_num_headers_are_tool_computed() {
        let mut per = MockPer::new();
        per.num_retries = 3;
        per.num_headers = 11;
        assert_eq!(out_str("%{num_retries}", &per, 0), "3");
        assert_eq!(out_str("%{num_headers}", &per, 0), "11");
    }

    #[test]
    fn num_certs_counts_chain_or_zero() {
        let mut per = MockPer::new();
        assert_eq!(out_str("%{num_certs}", &per, 0), "0"); // no certinfo -> 0
        per.cert_chain = Some(vec![vec!["Subject:a".into()], vec!["Subject:b".into()]]);
        assert_eq!(out_str("%{num_certs}", &per, 0), "2");
    }

    #[test]
    fn certs_strips_prefix_and_newline_terminates() {
        let mut per = MockPer::new();
        per.cert_chain = Some(vec![vec![
            "Cert:-----BEGIN-----".into(),
            "Subject:CN=example".into(),
        ]]);
        // "cert:" (case-insensitive) is stripped; each line ends in '\n'.
        assert_eq!(
            out_str("%{certs}", &per, 0),
            "-----BEGIN-----\nSubject:CN=example\n"
        );
    }

    #[test]
    fn certs_without_certinfo_emits_nothing() {
        let per = MockPer::new();
        assert_eq!(out_str("%{certs}", &per, 0), "");
    }

    #[test]
    fn urlnum_respects_int_max_ceiling() {
        let mut per = MockPer::new();
        per.urlnum = 5;
        assert_eq!(out_str("%{urlnum}", &per, 0), "5");
        per.urlnum = i64::from(i32::MAX) + 1;
        assert_eq!(out_str("%{urlnum}", &per, 0), ""); // too large -> nothing
    }

    #[test]
    fn input_url_and_components() {
        let mut per = MockPer::new();
        per.input_url = Some("https://user:pw@example.com:8080/a/b?q=1#frag".into());
        assert_eq!(
            out_str("%{url}", &per, 0),
            "https://user:pw@example.com:8080/a/b?q=1#frag"
        );
        assert_eq!(out_str("%{url.scheme}", &per, 0), "https");
        assert_eq!(out_str("%{url.host}", &per, 0), "example.com");
        assert_eq!(out_str("%{url.port}", &per, 0), "8080");
        assert_eq!(out_str("%{url.path}", &per, 0), "/a/b");
        assert_eq!(out_str("%{url.user}", &per, 0), "user");
    }

    #[test]
    fn url_components_require_input_url() {
        let per = MockPer::new(); // no input_url
        assert_eq!(out_str("%{url.host}", &per, 0), "");
        assert_eq!(out_str("%{url}", &per, 0), "");
    }

    #[test]
    fn effective_url_components_use_getinfo() {
        let mut per = MockPer::new();
        // urle.* still requires per->url to be set (C outer guard).
        per.input_url = Some("http://input.example/".into());
        per.easy.info.effective_url = cstr("https://eff.example:443/x?y=2");
        assert_eq!(out_str("%{urle.host}", &per, 0), "eff.example");
        assert_eq!(out_str("%{urle.scheme}", &per, 0), "https");
    }

    // --- Phase D: parser & escapes ---------------------------------------

    #[test]
    fn literal_text_and_percent_escape() {
        let per = MockPer::new();
        assert_eq!(out_str("hello world", &per, 0), "hello world");
        assert_eq!(out_str("100%% done", &per, 0), "100% done");
    }

    #[test]
    fn backslash_escapes() {
        let per = MockPer::new();
        assert_eq!(out_str("a\\nb", &per, 0), "a\nb");
        assert_eq!(out_str("a\\tb", &per, 0), "a\tb");
        assert_eq!(out_str("a\\rb", &per, 0), "a\rb");
        // unknown escape: both bytes emitted verbatim
        assert_eq!(out_str("a\\qb", &per, 0), "a\\qb");
    }

    #[test]
    fn unknown_variable_warns_on_stderr() {
        let per = MockPer::new();
        let (out, err) = render("x%{bogus}y", &per, 0);
        assert_eq!(out, b"xy"); // the unknown var emits nothing to stdout
        assert_eq!(
            String::from_utf8(err).unwrap(),
            "curl: unknown --write-out variable: 'bogus'\n"
        );
    }

    #[test]
    fn overlong_variable_name_stops_processing() {
        let per = MockPer::new();
        // A 24+ byte name overflows curl's bounded buffer and aborts the walk,
        // so nothing after (or at) it is emitted.
        let name = "a".repeat(MAX_WRITEOUT_NAME_LENGTH);
        let (out, err) = render(&format!("before%{{{name}}}after"), &per, 0);
        assert_eq!(out, b"before");
        assert!(err.is_empty(), "no diagnostic is emitted on the hard stop");
    }

    #[test]
    fn unterminated_brace_emits_literal_and_resumes() {
        let per = MockPer::new();
        // No closing brace: curl emits "%{" and parses the rest normally.
        assert_eq!(out_str("%{abc", &per, 0), "%{abc");
    }

    #[test]
    fn trailing_percent_is_literal() {
        let per = MockPer::new();
        assert_eq!(out_str("done%", &per, 0), "done%");
    }

    // --- onerror / stdout / stderr ---------------------------------------

    #[test]
    fn onerror_gates_remainder_on_failure() {
        let per = MockPer::new();
        // On success: %{onerror} stops the rest.
        assert_eq!(out_str("a%{onerror}b", &per, 0), "a");
        // On failure: the rest is emitted.
        assert_eq!(out_str("a%{onerror}b", &per, 7), "ab");
    }

    #[test]
    fn stderr_switches_active_stream() {
        let per = MockPer::new();
        let (out, err) = render("out1%{stderr}err1%{stdout}out2", &per, 0);
        assert_eq!(out, b"out1out2");
        assert_eq!(err, b"err1");
    }

    // --- %header{} --------------------------------------------------------

    #[test]
    fn header_single_is_case_insensitive_first_match() {
        let mut per = MockPer::new();
        per.headers = vec![
            (b"Content-Type".to_vec(), b"text/html".to_vec()),
            (b"X-Dup".to_vec(), b"one".to_vec()),
            (b"X-Dup".to_vec(), b"two".to_vec()),
        ];
        assert_eq!(out_str("%header{Content-Type}", &per, 0), "text/html");
        assert_eq!(out_str("%header{content-type}", &per, 0), "text/html");
        assert_eq!(out_str("%header{X-Dup}", &per, 0), "one"); // first only
        assert_eq!(out_str("%header{Missing}", &per, 0), ""); // no match
    }

    #[test]
    fn header_all_joins_with_separator() {
        let mut per = MockPer::new();
        per.headers = vec![
            (b"Set-Cookie".to_vec(), b"a=1".to_vec()),
            (b"Set-Cookie".to_vec(), b"b=2".to_vec()),
            (b"Set-Cookie".to_vec(), b"c=3".to_vec()),
        ];
        assert_eq!(
            out_str("%header{Set-Cookie:all:, }", &per, 0),
            "a=1, b=2, c=3"
        );
        // escaped separator: \n
        assert_eq!(
            out_str("%header{Set-Cookie:all:\\n}", &per, 0),
            "a=1\nb=2\nc=3"
        );
    }

    #[test]
    fn header_unterminated_emits_literal() {
        let per = MockPer::new();
        assert_eq!(out_str("%header{oops", &per, 0), "%header{oops");
    }

    // --- %time{} ----------------------------------------------------------

    #[test]
    fn resolve_time_format_substitutes_percent_codes() {
        assert_eq!(resolve_time_format(b"%Y-%m-%d", 0), b"%Y-%m-%d");
        assert_eq!(resolve_time_format(b"%f", 123_456), b"123456");
        assert_eq!(resolve_time_format(b"%f", 7), b"000007");
        assert_eq!(resolve_time_format(b"%z", 0), b"+0000");
        assert_eq!(resolve_time_format(b"%Z", 0), b"UTC");
        assert_eq!(
            resolve_time_format(b"%H:%M:%S.%f", 42),
            b"%H:%M:%S.000042"
        );
        // a trailing lone '%' cannot start a sequence
        assert_eq!(resolve_time_format(b"x%", 0), b"x%");
    }

    #[test]
    fn time_unterminated_emits_literal() {
        let per = MockPer::new();
        assert_eq!(out_str("%time{oops", &per, 0), "%time{oops");
    }

    #[cfg(debug_assertions)]
    #[test]
    fn time_strftime_with_curl_time_override() {
        // CURL_TIME pins the clock under debug builds. This is the only test
        // touching that process-global, and no other test renders %time{}.
        let per = MockPer::new();
        std::env::set_var("CURL_TIME", "1234567");
        let date = out_str("%time{%Y-%m-%d}", &per, 0);
        let frac = out_str("%time{%f}", &per, 0);
        std::env::remove_var("CURL_TIME");
        assert_eq!(date, "1970-01-15"); // 1234567s after the epoch
        assert_eq!(frac, "234567"); // 1234567 % 1_000_000
    }

    // --- %output{} --------------------------------------------------------

    fn unique_temp_path(tag: &str) -> std::path::PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "blitzy_adhoc_writeout_{}_{}_{}.txt",
            std::process::id(),
            tag,
            n
        ))
    }

    #[test]
    fn output_redirects_to_file_then_back_to_stdout() {
        let per = MockPer::new();
        let path = unique_temp_path("trunc");
        let p = path.to_str().unwrap();
        let (out, _err) = render(&format!("%output{{{p}}}infile%{{stdout}}onstdout"), &per, 0);
        let file = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(file, b"infile");
        assert_eq!(out, b"onstdout");
    }

    #[test]
    fn output_truncates_and_append_appends() {
        let per = MockPer::new();
        let path = unique_temp_path("append");
        let p = path.to_str().unwrap();
        std::fs::write(&path, b"existing\n").unwrap();

        // `%output{file}` truncates.
        render(&format!("%output{{{p}}}fresh"), &per, 0);
        assert_eq!(std::fs::read(&path).unwrap(), b"fresh");

        // `%output{>>file}` appends.
        render(&format!("%output{{>>{p}}}more"), &per, 0);
        assert_eq!(std::fs::read(&path).unwrap(), b"freshmore");

        let _ = std::fs::remove_file(&path);
    }

    // --- JSON delegation --------------------------------------------------

    #[test]
    fn json_wraps_object_with_curl_version_tail() {
        let mut per = MockPer::new();
        per.easy.info.response_code = 200;
        per.easy.info.scheme = cstr("https");
        per.easy.info.total_time_us = 123_456;
        per.easy.info.size_download = 2048;
        let s = out_str("%{json}", &per, 0);
        assert!(s.starts_with('{'), "must open with brace: {s}");
        assert!(s.ends_with('}'), "must close with brace");
        // a few members rendered through the same writers, in JSON mode
        assert!(s.contains("\"http_code\":200"), "http_code: {s}");
        assert!(s.contains("\"scheme\":\"https\""), "scheme: {s}");
        assert!(s.contains("\"time_total\":0.123456"), "time_total: {s}");
        assert!(s.contains("\"size_download\":2048"), "size_download: {s}");
        // the synthetic trailing key with no dangling comma before `}`
        assert!(s.contains("\"curl_version\":"), "curl_version tail: {s}");
        // the Special rows contribute no members
        assert!(!s.contains("\"json\":"));
        assert!(!s.contains("\"onerror\":"));
        assert!(!s.contains("\"stdout\":"));
    }

    #[test]
    fn json_renders_null_for_absent_values() {
        let per = MockPer::new(); // nothing populated
        let s = out_str("%{json}", &per, 0);
        // an unset string getinfo row is null; content_type is a plain example
        assert!(s.contains("\"content_type\":null"), "content_type null: {s}");
    }

    #[test]
    fn header_json_delegates_and_groups() {
        let mut per = MockPer::new();
        per.headers = vec![
            (b"Content-Type".to_vec(), b"text/html".to_vec()),
            (b"Set-Cookie".to_vec(), b"a=1".to_vec()),
            (b"Set-Cookie".to_vec(), b"b=2".to_vec()),
        ];
        let s = out_str("%{header_json}", &per, 0);
        assert!(s.starts_with('{'));
        assert!(s.trim_end().ends_with('}'));
        // names lower-cased, repeated header grouped into an array
        assert!(s.contains("\"content-type\":[\"text/html\"]"), "{s}");
        assert!(s.contains("\"set-cookie\":[\"a=1\",\"b=2\"]"), "{s}");
    }

    #[test]
    fn absent_writeout_is_noop() {
        let per = MockPer::new();
        let cfg = OperationConfig::default();
        // config.writeout defaults to None -> our_write_out returns Ok with no
        // output (it writes to the process stdout, which we cannot capture here,
        // but the call must succeed and do nothing observable).
        assert!(cfg.writeout.is_none());
        our_write_out(&cfg, &per, 0).expect("noop");
    }
}

