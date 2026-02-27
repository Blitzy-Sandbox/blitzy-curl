// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
// Rust rewrite of src/tool_writeout.c and src/tool_writeout.h from curl
// 8.19.0-DEV.
//
// Implements `--write-out` (`-w`) template rendering with all curl write-out
// variables, supporting plain text, JSON output modes, stream redirection
// (`%{stdout}`, `%{stderr}`, `%output{}`), time formatting (`%time{}`),
// and header extraction (`%header{}`).
//
// Design notes:
//   * `VarId` is a Rust enum whose variants map 1:1 to the C `writeoutid`
//     enum in `tool_writeout.h`.
//   * `WriteOutVar` holds a variable's name, id, optional `CurlInfo` for
//     info retrieval, and an optional write-type discriminant.
//   * `VARIABLES` is a `const` array sorted alphabetically by name for
//     binary search lookups, matching the C `variables[]` table exactly.
//   * `our_write_out` is the main template engine that parses `%{var}`,
//     `%header{name}`, `%time{fmt}`, `%output{file}`, escape sequences,
//     and literal text — byte-for-byte matching curl 8.x output where
//     deterministic.
//   * Zero `unsafe` blocks — AAP Section 0.7.1.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};

use anyhow::{Context, Result};
use chrono::Utc;

use crate::config::{GlobalConfig, OperationConfig};
use crate::msgs;
use crate::stderr::tool_stderr;
use crate::writeout_json;

use curl_rs_lib::getinfo::{CurlInfo, InfoValue};
use curl_rs_lib::headers::{CurlHcode, Header, Headers, CURLH_HEADER};
use curl_rs_lib::url::{CurlUrl, CurlUrlPart};
use curl_rs_lib::{CurlError, EasyHandle, version};

// Re-export types required by the module API surface. HeaderOrigin is the
// bitflag type underlying the CURLH_HEADER constant used for origin-based
// header filtering in output_header(). CurlResult is the library-level
// Result alias used by callers constructing PerTransfer instances.
#[allow(unused_imports)]
pub use curl_rs_lib::headers::HeaderOrigin;
#[allow(unused_imports)]
pub use curl_rs_lib::CurlResult;

// ---------------------------------------------------------------------------
// VarId — write-out variable identifier enum
// ---------------------------------------------------------------------------

/// Identifies a write-out variable for the `--write-out` template engine.
///
/// Each variant maps 1:1 to a C `writeoutid` value from `tool_writeout.h`.
/// The enum is used in the [`WriteOutVar`] table to dispatch formatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VarId {
    /// `%{http_code}` — HTTP response code (3-digit zero-padded).
    HttpCode,
    /// `%{http_version}` — HTTP version as display string ("1.0", "1.1", "2", "3").
    HttpVersion,
    /// `%{http_connect}` — HTTP CONNECT proxy response code.
    HttpCodeProxy,
    /// `%{num_connects}` — number of new connections opened.
    NumConnects,
    /// `%{size_download}` — total bytes downloaded.
    SizeDownload,
    /// `%{size_upload}` — total bytes uploaded.
    SizeUpload,
    /// `%{speed_download}` — average download speed (bytes/sec).
    SpeedDownload,
    /// `%{speed_upload}` — average upload speed (bytes/sec).
    SpeedUpload,
    /// `%{time_total}` — total transfer time.
    TimeTotal,
    /// `%{time_namelookup}` — DNS resolution time.
    TimeNamelookup,
    /// `%{time_connect}` — TCP connection time.
    TimeConnect,
    /// `%{time_appconnect}` — TLS handshake time.
    TimeAppconnect,
    /// `%{time_starttransfer}` — time to first byte.
    TimeStarttransfer,
    /// `%{time_redirect}` — total redirect time.
    TimeRedirect,
    /// `%{time_pretransfer}` — pre-transfer time.
    TimePretransfer,
    /// `%{time_posttransfer}` — post-transfer time.
    TimePosttransfer,
    /// `%{time_queue}` — queue wait time.
    TimeQueue,
    /// `%{url_effective}` — last effective URL after redirects.
    UrlEffective,
    /// `%{content_type}` — Content-Type header value.
    ContentType,
    /// `%{num_redirects}` — redirect count.
    NumRedirects,
    /// `%{redirect_url}` — URL for the next redirect.
    RedirectUrl,
    /// `%{scheme}` — URL scheme of the connection.
    Scheme,
    /// `%{exitcode}` — numeric exit/error code.
    ExitCode,
    /// `%{method}` — effective HTTP method used.
    EffectiveMethod,
    /// `%{response_code}` — alias for HTTP response code.
    ResponseCode,
    /// `%{json}` — emit all variables as a JSON object.
    Json,
    /// `%{header_json}` — emit response headers as JSON.
    HeaderJson,
    /// `%{stdout}` — switch output to stdout.
    Stdout,
    /// `%{stderr}` — switch output to stderr.
    Stderr,
    /// `%{onerror}` — only output if transfer failed.
    Onerror,
    /// `%{certs}` — TLS certificate chain info.
    Certs,
    /// `%{num_certs}` — number of certificates in the chain.
    NumCerts,
    /// `%{curl_version}` — curl library version string.
    CurlVersion,
    /// `%{urle.host}` — hostname from effective URL.
    UrlHost,
    /// `%{urle.port}` — port from effective URL.
    UrlPort,
    /// `%{urle.path}` — path from effective URL.
    UrlPath,
    /// `%{urle.query}` — query from effective URL.
    UrlQuery,
    /// `%{urle.scheme}` — scheme from effective URL.
    UrlScheme,
    /// `%{urle.user}` — user from effective URL.
    UrlUser,
    /// `%{urle.password}` — password from effective URL.
    UrlPassword,
    /// `%{urle.options}` — options from effective URL.
    UrlOptions,
    /// `%{urle.fragment}` — fragment from effective URL.
    UrlFragment,
    /// `%{urle.zoneid}` — zone ID from effective URL.
    UrlZoneid,
    /// `%{url}` — the input URL used for this transfer.
    InputUrl,
    /// `%{url.host}` — hostname from input URL.
    InputUrlHost,
    /// `%{url.port}` — port from input URL.
    InputUrlPort,
    /// `%{url.path}` — path from input URL.
    InputUrlPath,
    /// `%{url.query}` — query from input URL.
    InputUrlQuery,
    /// `%{url.scheme}` — scheme from input URL.
    InputUrlScheme,
    /// `%{url.user}` — user from input URL.
    InputUrlUser,
    /// `%{url.password}` — password from input URL.
    InputUrlPassword,
    /// `%{url.options}` — options from input URL.
    InputUrlOptions,
    /// `%{url.fragment}` — fragment from input URL.
    InputUrlFragment,
    /// `%{url.zoneid}` — zone ID from input URL.
    InputUrlZoneid,
    /// `%{remote_ip}` — IP address of the remote peer.
    PrimaryIp,
    /// `%{remote_port}` — port of the remote peer.
    PrimaryPort,
    /// `%{local_ip}` — local IP address used.
    LocalIp,
    /// `%{local_port}` — local port used.
    LocalPort,
    /// `%{ssl_verify_result}` — SSL certificate verification result.
    SslVerifyResult,
    /// `%{proxy_ssl_verify_result}` — proxy SSL verification result.
    ProxySslVerifyResult,
    /// `%{size_header}` — total header size in bytes.
    HeaderSize,
    /// `%{size_request}` — total request size in bytes.
    RequestSize,
    /// `%{referer}` — Referer header value.
    Referer,
    /// `%{ftp_entry_path}` — FTP entry path returned by server.
    FtpEntryPath,
    /// `%{errormsg}` — error message for failed transfers.
    ErrMsg,
    /// `%{filename_effective}` — effective output filename.
    EffectiveFilename,
    /// `%{urlnum}` — URL sequence number in globbing.
    Urlnum,
    /// `%{conn_id}` — connection ID.
    ConnId,
    /// `%{xfer_id}` — transfer ID.
    XferId,
    /// `%{num_headers}` — number of response headers.
    NumHeaders,
    /// `%{num_retries}` — number of retries performed.
    NumRetry,
    /// `%{proxy_used}` — whether a proxy was used (0/1).
    ProxyUsed,
    /// `%{tls_earlydata}` — bytes of TLS early data sent.
    EarlydataSent,
}

// ---------------------------------------------------------------------------
// WriteOutType — formatter type discriminant
// ---------------------------------------------------------------------------

/// Discriminant for the write-out variable's formatting strategy.
///
/// Variables with `None` write type are handled specially by the template
/// engine (e.g., `json`, `header_json`, `stdout`, `stderr`, `onerror`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutType {
    /// Microsecond timing value formatted as `seconds.microseconds` (6 decimals).
    Time,
    /// String value with optional special handling (HTTP version, certs, etc.).
    String,
    /// Long integer value.
    Long,
    /// Large integer / offset value (`curl_off_t`).
    Offset,
}

// ---------------------------------------------------------------------------
// PerTransfer — per-transfer state for write-out rendering
// ---------------------------------------------------------------------------

/// Per-transfer state aggregating all data needed for write-out rendering.
///
/// This struct mirrors the relevant fields of the C `struct per_transfer`
/// from `tool_operate.h`. Callers (e.g., `operate.rs`) construct a
/// `PerTransfer` from the current transfer context and pass it to
/// [`our_write_out`].
pub struct PerTransfer<'a> {
    /// The easy handle used for this transfer — used for `get_info()` calls
    /// to retrieve response code, timing, URLs, sizes, and other metrics.
    pub curl: &'a EasyHandle,
    /// The input URL string for this transfer (before redirects).
    pub url: Option<&'a str>,
    /// Response headers from this transfer (for `%header{}` and `%{header_json}`).
    /// The [`HeaderOrigin`] filtering is performed internally via [`CURLH_HEADER`].
    pub headers: Option<&'a Headers>,
    /// Error buffer content when the transfer failed.
    pub errorbuffer: &'a str,
    /// Effective output filename (from `-o` / `-O` / `-J`).
    pub outs_filename: Option<&'a str>,
    /// Number of retries performed for this transfer.
    pub num_retries: i64,
    /// Number of response headers received.
    pub num_headers: i64,
    /// URL sequence number (from URL globbing).
    pub urlnum: i64,
    /// Per-operation configuration (contains the `writeout` template field).
    pub config: &'a OperationConfig,
    /// Global configuration reference (for `warnf` calls on unknown vars).
    pub global: &'a GlobalConfig,
}

// ---------------------------------------------------------------------------
// WriteOutVar — variable table entry
// ---------------------------------------------------------------------------

/// A single entry in the write-out variable lookup table.
///
/// Matches the C `struct writeoutvar` from `tool_writeout.h`.
/// The `write_fn` field uses [`WriteOutType`] instead of a C function pointer.
pub struct WriteOutVar {
    /// Variable name as it appears in `%{name}` (e.g., `"http_code"`).
    pub name: &'static str,
    /// Internal variable identifier.
    pub id: VarId,
    /// Optional `CurlInfo` enum variant for `get_info()` queries.
    /// `None` means the formatter handles the value itself.
    pub info: Option<CurlInfo>,
    /// Formatting type, or `None` for specially-handled variables
    /// (`json`, `header_json`, `stdout`, `stderr`, `onerror`).
    pub write_fn: Option<WriteOutType>,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length of a write-out variable name (including NUL in C).
///
/// Matches the C `#define MAX_WRITEOUT_NAME_LENGTH 24`.
pub const MAX_WRITEOUT_NAME_LENGTH: usize = 24;

// ---------------------------------------------------------------------------
// HTTP version display map
// ---------------------------------------------------------------------------

/// Maps the numeric HTTP version value from `CURLINFO_HTTP_VERSION` to
/// its display string. Matches the C `http_version[]` array.
const HTTP_VERSION_MAP: &[(i64, &str)] = &[
    (0, "0"),   // CURL_HTTP_VERSION_NONE
    (1, "1"),   // CURL_HTTP_VERSION_1_0
    (2, "1.1"), // CURL_HTTP_VERSION_1_1
    (3, "2"),   // CURL_HTTP_VERSION_2
    (4, "3"),   // CURL_HTTP_VERSION_3
];

// ---------------------------------------------------------------------------
// Info retrieval helpers
// ---------------------------------------------------------------------------

/// Query a string-typed info value from the easy handle.
fn get_info_string(easy: &EasyHandle, info: CurlInfo) -> Option<String> {
    match easy.get_info(info) {
        Ok(InfoValue::String(opt)) => opt,
        _ => None,
    }
}

/// Query a long-typed info value from the easy handle.
fn get_info_long(easy: &EasyHandle, info: CurlInfo) -> Option<i64> {
    match easy.get_info(info) {
        Ok(InfoValue::Long(v)) => Some(v),
        _ => None,
    }
}

/// Query an offset-typed info value from the easy handle.
fn get_info_off_t(easy: &EasyHandle, info: CurlInfo) -> Option<i64> {
    match easy.get_info(info) {
        Ok(InfoValue::OffT(v)) => Some(v),
        _ => None,
    }
}

// ===========================================================================
// Formatter functions
// ===========================================================================

/// Format a timing value from `CurlInfo` as `seconds.microseconds`.
///
/// Matches the C `writeTime()` function. The value is retrieved from the
/// easy handle as a microsecond `off_t`, then formatted with 6 decimal
/// places. In JSON mode, the key is prepended.
fn write_time(
    stream: &mut dyn Write,
    wovar: &WriteOutVar,
    per: &PerTransfer<'_>,
    _per_result: i32,
    use_json: bool,
) -> Result<()> {
    let ci = match wovar.info {
        Some(ci) => ci,
        None => return Ok(()),
    };
    match get_info_off_t(per.curl, ci) {
        Some(us) => {
            let secs = us / 1_000_000;
            let micros = (us % 1_000_000).unsigned_abs();
            if use_json {
                write!(stream, "\"{}\":", wovar.name)?;
            }
            write!(stream, "{}.{:06}", secs, micros)?;
        }
        None => {
            if use_json {
                write!(stream, "\"{}\":null", wovar.name)?;
            }
        }
    }
    Ok(())
}

/// Extract a URL component from the effective URL or the input URL.
///
/// Matches the C `urlpart()` function. When the variant is a `Url*` type
/// (effective URL), the URL is fetched via `CURLINFO_EFFECTIVE_URL`.
/// When the variant is an `InputUrl*` type, the input URL from the
/// `PerTransfer` is used.
fn urlpart(per: &PerTransfer<'_>, vid: VarId) -> Option<String> {
    let use_effective = matches!(
        vid,
        VarId::UrlScheme
            | VarId::UrlUser
            | VarId::UrlPassword
            | VarId::UrlOptions
            | VarId::UrlHost
            | VarId::UrlPort
            | VarId::UrlPath
            | VarId::UrlQuery
            | VarId::UrlFragment
            | VarId::UrlZoneid
    );

    let url_str = if use_effective {
        get_info_string(per.curl, CurlInfo::EffectiveUrl)?
    } else {
        per.url?.to_string()
    };

    let mut uh = CurlUrl::new();
    let set_flags = curl_rs_lib::url::CURLU_GUESS_SCHEME
        | curl_rs_lib::url::CURLU_NON_SUPPORT_SCHEME;
    if uh.set(CurlUrlPart::Url, &url_str, set_flags).is_err() {
        return None;
    }

    let cpart = match vid {
        VarId::InputUrlScheme | VarId::UrlScheme => CurlUrlPart::Scheme,
        VarId::InputUrlUser | VarId::UrlUser => CurlUrlPart::User,
        VarId::InputUrlPassword | VarId::UrlPassword => CurlUrlPart::Password,
        VarId::InputUrlOptions | VarId::UrlOptions => CurlUrlPart::Options,
        VarId::InputUrlHost | VarId::UrlHost => CurlUrlPart::Host,
        VarId::InputUrlPort | VarId::UrlPort => CurlUrlPart::Port,
        VarId::InputUrlPath | VarId::UrlPath => CurlUrlPart::Path,
        VarId::InputUrlQuery | VarId::UrlQuery => CurlUrlPart::Query,
        VarId::InputUrlFragment | VarId::UrlFragment => CurlUrlPart::Fragment,
        VarId::InputUrlZoneid | VarId::UrlZoneid => CurlUrlPart::ZoneId,
        _ => return None,
    };

    // Use CURLU_DEFAULT_PORT for port queries so a default port is returned
    // even when the URL does not include an explicit port component.
    let get_flags = if matches!(cpart, CurlUrlPart::Port) {
        curl_rs_lib::url::CURLU_DEFAULT_PORT
    } else {
        0
    };
    uh.get(cpart, get_flags).ok()
}

/// Retrieve certificate info from the easy handle as a single string.
///
/// Matches the C `certinfo()` helper.
fn get_certinfo_string(per: &PerTransfer<'_>) -> String {
    match per.curl.get_info(CurlInfo::CertInfo) {
        Ok(InfoValue::SList(slist)) => {
            let items = slist.as_slice();
            if items.is_empty() {
                return String::new();
            }
            let mut buf = String::new();
            for item in items {
                if let Some(stripped) = item.strip_prefix("cert:") {
                    buf.push_str(stripped);
                } else {
                    buf.push_str(item);
                }
                if !buf.ends_with('\n') {
                    buf.push('\n');
                }
            }
            buf
        }
        _ => String::new(),
    }
}

/// Count the number of certificates in the chain.
fn get_num_certs(per: &PerTransfer<'_>) -> i64 {
    match per.curl.get_info(CurlInfo::CertInfo) {
        Ok(InfoValue::SList(slist)) => slist.len() as i64,
        _ => 0,
    }
}

/// Format a string-typed write-out variable.
///
/// Matches the C `writeString()` function. Handles several special cases:
/// - `HttpVersion`: maps the numeric version to a display string.
/// - `Certs`: retrieves and formats the TLS certificate chain.
/// - `ErrMsg`: shows the error message for failed transfers.
/// - `EffectiveFilename`: shows the effective output filename.
/// - `InputUrl`: shows the input URL.
/// - `CurlVersion`: shows the curl library version.
/// - URL-part variables: extracts components from input or effective URL.
fn write_string(
    stream: &mut dyn Write,
    wovar: &WriteOutVar,
    per: &PerTransfer<'_>,
    per_result: i32,
    use_json: bool,
) -> Result<()> {
    let mut valid = false;
    let mut strinfo: Option<String> = None;

    if let Some(ci) = wovar.info {
        if ci == CurlInfo::None {
            // No CurlInfo — handle based on VarId below
        } else if ci == CurlInfo::HttpVersion {
            // Special case: map numeric HTTP version to display string.
            if let Some(ver) = get_info_long(per.curl, CurlInfo::HttpVersion) {
                for &(num, display) in HTTP_VERSION_MAP {
                    if num == ver {
                        strinfo = Some(display.to_string());
                        valid = true;
                        break;
                    }
                }
            }
        } else {
            // Standard string info query.
            if let Some(s) = get_info_string(per.curl, ci) {
                strinfo = Some(s);
                valid = true;
            }
        }
    }

    // Handle variables without a CurlInfo or with CurlInfo::None.
    if !valid && wovar.info.map_or(true, |ci| ci == CurlInfo::None) {
        match wovar.id {
            VarId::Certs => {
                strinfo = Some(get_certinfo_string(per));
                valid = true;
            }
            VarId::ErrMsg => {
                if per_result != 0 {
                    let msg = if !per.errorbuffer.is_empty() {
                        per.errorbuffer.to_string()
                    } else {
                        // Fall back to CurlError strerror.
                        let err = CurlError::from(per_result);
                        err.strerror().to_string()
                    };
                    strinfo = Some(msg);
                    valid = true;
                }
            }
            VarId::EffectiveFilename => {
                if let Some(fname) = per.outs_filename {
                    strinfo = Some(fname.to_string());
                    valid = true;
                }
            }
            VarId::InputUrl => {
                if let Some(u) = per.url {
                    strinfo = Some(u.to_string());
                    valid = true;
                }
            }
            VarId::CurlVersion => {
                strinfo = Some(version().to_string());
                valid = true;
            }
            // URL part extraction variables (input or effective).
            VarId::InputUrlScheme
            | VarId::InputUrlUser
            | VarId::InputUrlPassword
            | VarId::InputUrlOptions
            | VarId::InputUrlHost
            | VarId::InputUrlPort
            | VarId::InputUrlPath
            | VarId::InputUrlQuery
            | VarId::InputUrlFragment
            | VarId::InputUrlZoneid
            | VarId::UrlScheme
            | VarId::UrlUser
            | VarId::UrlPassword
            | VarId::UrlOptions
            | VarId::UrlHost
            | VarId::UrlPort
            | VarId::UrlPath
            | VarId::UrlQuery
            | VarId::UrlFragment
            | VarId::UrlZoneid => {
                if let Some(part) = urlpart(per, wovar.id) {
                    strinfo = Some(part);
                    valid = true;
                }
            }
            _ => {}
        }
    }

    if valid {
        let s = strinfo.as_deref().unwrap_or("");
        if use_json {
            write!(stream, "\"{}\":", wovar.name)?;
            json_write_string_value(stream, s)?;
        } else {
            write!(stream, "{}", s)?;
        }
    } else if use_json {
        write!(stream, "\"{}\":null", wovar.name)?;
    }
    Ok(())
}

/// Write a JSON-escaped string value (with surrounding quotes).
fn json_write_string_value(stream: &mut dyn Write, s: &str) -> Result<()> {
    write!(stream, "\"")?;
    for ch in s.chars() {
        match ch {
            '\\' => write!(stream, "\\\\")?,
            '"' => write!(stream, "\\\"")?,
            '\n' => write!(stream, "\\n")?,
            '\r' => write!(stream, "\\r")?,
            '\t' => write!(stream, "\\t")?,
            '\u{0008}' => write!(stream, "\\b")?,
            '\u{000C}' => write!(stream, "\\f")?,
            c if (c as u32) < 0x20 => write!(stream, "\\u{:04x}", c as u32)?,
            c => write!(stream, "{}", c)?,
        }
    }
    write!(stream, "\"")?;
    Ok(())
}

/// Format a long-integer write-out variable.
///
/// Matches the C `writeLong()` function. Special cases:
/// - `ExitCode`: uses the transfer result code directly.
/// - `NumCerts`: counts certs from `CURLINFO_CERTINFO`.
/// - `NumHeaders`: uses the per-transfer header count.
/// - `NumRetry`: uses the per-transfer retry count.
/// - `HttpCode`/`HttpCodeProxy`/`ResponseCode`: zero-padded to 3 digits.
fn write_long(
    stream: &mut dyn Write,
    wovar: &WriteOutVar,
    per: &PerTransfer<'_>,
    per_result: i32,
    use_json: bool,
) -> Result<()> {
    let mut valid = false;
    let mut longinfo: i64 = 0;

    if let Some(ci) = wovar.info {
        if ci != CurlInfo::None {
            if let Some(v) = get_info_long(per.curl, ci) {
                longinfo = v;
                valid = true;
            }
        }
    }

    if !valid {
        match wovar.id {
            VarId::NumRetry => {
                longinfo = per.num_retries;
                valid = true;
            }
            VarId::NumCerts => {
                longinfo = get_num_certs(per);
                valid = true;
            }
            VarId::NumHeaders => {
                longinfo = per.num_headers;
                valid = true;
            }
            VarId::ExitCode => {
                longinfo = per_result as i64;
                valid = true;
            }
            _ => {}
        }
    }

    if valid {
        if use_json {
            write!(stream, "\"{}\":{}", wovar.name, longinfo)?;
        } else if wovar.id == VarId::HttpCode
            || wovar.id == VarId::HttpCodeProxy
            || wovar.id == VarId::ResponseCode
        {
            write!(stream, "{:03}", longinfo)?;
        } else {
            write!(stream, "{}", longinfo)?;
        }
    } else if use_json {
        write!(stream, "\"{}\":null", wovar.name)?;
    }
    Ok(())
}

/// Format an offset (large integer) write-out variable.
///
/// Matches the C `writeOffset()` function. Special case:
/// - `Urlnum`: uses the per-transfer URL sequence number.
fn write_offset(
    stream: &mut dyn Write,
    wovar: &WriteOutVar,
    per: &PerTransfer<'_>,
    _per_result: i32,
    use_json: bool,
) -> Result<()> {
    let mut valid = false;
    let mut offinfo: i64 = 0;

    if let Some(ci) = wovar.info {
        if ci != CurlInfo::None {
            if let Some(v) = get_info_off_t(per.curl, ci) {
                offinfo = v;
                valid = true;
            }
        }
    }

    if !valid && wovar.id == VarId::Urlnum {
        offinfo = per.urlnum;
        valid = true;
    }

    if valid {
        if use_json {
            write!(stream, "\"{}\":", wovar.name)?;
        }
        write!(stream, "{}", offinfo)?;
    } else if use_json {
        write!(stream, "\"{}\":null", wovar.name)?;
    }
    Ok(())
}

/// Dispatch to the appropriate formatter based on the variable's write type.
fn format_var(
    stream: &mut dyn Write,
    wovar: &WriteOutVar,
    per: &PerTransfer<'_>,
    per_result: i32,
    use_json: bool,
) -> Result<()> {
    match wovar.write_fn {
        Some(WriteOutType::Time) => write_time(stream, wovar, per, per_result, use_json),
        Some(WriteOutType::String) => write_string(stream, wovar, per, per_result, use_json),
        Some(WriteOutType::Long) => write_long(stream, wovar, per, per_result, use_json),
        Some(WriteOutType::Offset) => write_offset(stream, wovar, per, per_result, use_json),
        None => Ok(()), // Handled specially in the main loop
    }
}

// ===========================================================================
// Special directive handlers
// ===========================================================================

/// Process the `%time{format}` directive.
///
/// Matches the C `outtime()` function. Gets the current UTC time and formats
/// it using strftime-compatible patterns via `chrono`. Supports:
/// - `%f` — sub-second microseconds (6 digits)
/// - `%z` — timezone offset (always `+0000` for UTC)
/// - `%Z` — timezone name (always `UTC`)
///
/// Returns the number of bytes consumed from `input` (starting after
/// `%time{`).
fn outtime(input: &str, stream: &mut dyn Write) -> Result<usize> {
    if let Some(end_pos) = input.find('}') {
        let fmt_str = &input[..end_pos];
        let now = Utc::now();
        let usecs = now.timestamp_subsec_micros();

        // Pre-process the format string: replace %f, %z, %Z with their
        // values before passing to chrono's strftime.
        let mut processed = String::with_capacity(fmt_str.len() * 2);
        let bytes = fmt_str.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if i + 1 < bytes.len() && bytes[i] == b'%' {
                match bytes[i + 1] {
                    b'f' => {
                        processed.push_str(&format!("{:06}", usecs));
                        i += 2;
                        continue;
                    }
                    b'Z' => {
                        processed.push_str("UTC");
                        i += 2;
                        continue;
                    }
                    b'z' => {
                        processed.push_str("+0000");
                        i += 2;
                        continue;
                    }
                    _ => {
                        processed.push('%');
                        processed.push(bytes[i + 1] as char);
                        i += 2;
                        continue;
                    }
                }
            }
            processed.push(bytes[i] as char);
            i += 1;
        }

        if !processed.is_empty() {
            let formatted = now.format(&processed).to_string();
            write!(stream, "{}", formatted)?;
        }
        Ok(end_pos + 1) // skip past '}'
    } else {
        // No closing brace — output the literal "%time{" text.
        write!(stream, "%time{{")?;
        Ok(0)
    }
}

/// Process backslash-escape sequences in separator strings.
///
/// Matches the C `separator()` function. Supports `\r`, `\n`, `\t`, `\}`.
fn write_separator(sep: &str, stream: &mut dyn Write) -> Result<()> {
    let bytes = sep.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'r' => write!(stream, "\r")?,
                b'n' => writeln!(stream)?,
                b't' => write!(stream, "\t")?,
                b'}' => write!(stream, "}}")?,
                0 => break,
                other => {
                    write!(stream, "\\{}", other as char)?;
                }
            }
            i += 2;
        } else {
            write!(stream, "{}", bytes[i] as char)?;
            i += 1;
        }
    }
    Ok(())
}

/// Process the `%header{name}` directive.
///
/// Matches the C `output_header()` function. Supports:
/// - `%header{Name}` — get the last value of header `Name`
/// - `%header{Name:all:sep}` — get all values separated by `sep`
///
/// The separator supports escape sequences via [`write_separator`].
///
/// Returns the number of bytes consumed from `input` (which starts right
/// after `%header{`).
fn output_header(
    per: &PerTransfer<'_>,
    input: &str,
    stream: &mut dyn Write,
) -> Result<usize> {
    // Find the closing '}', skipping escaped '\}'
    let bytes = input.as_bytes();
    let mut search_start: usize = 0;
    let end_pos = loop {
        if let Some(pos) = input[search_start..].find('}') {
            let abs_pos = search_start + pos;
            // Check if preceded by backslash
            if abs_pos > 0 && bytes[abs_pos - 1] == b'\\' {
                search_start = abs_pos + 1;
                continue;
            }
            break Some(abs_pos);
        } else {
            break None;
        }
    };

    let Some(end) = end_pos else {
        // No closing brace — output literal text
        write!(stream, "%header{{")?;
        return Ok(0);
    };

    let content = &input[..end];
    let headers = match per.headers {
        Some(h) => h,
        None => return Ok(end + 1),
    };

    // Check for ":all:" instruction
    let (hname, sep) = if let Some(colon_pos) = content.find(':') {
        let after_colon = &content[colon_pos + 1..];
        if let Some(separator) = after_colon.strip_prefix("all:") {
            (&content[..colon_pos], Some(separator))
        } else {
            (content, None)
        }
    } else {
        (content, None)
    };

    if hname.len() < 256 {
        if let Some(separator) = sep {
            // Get all matching headers across all requests.
            // The origin mask uses CURLH_HEADER (HeaderOrigin bit for
            // response headers); CurlHcode distinguishes success/failure.
            let _origin_check: u32 = CURLH_HEADER; // HeaderOrigin-based mask
            let mut reqno: i32 = 0;
            let mut indno: usize = 0;
            let mut first = true;
            loop {
                let result: Result<Header, CurlHcode> =
                    headers.get(hname, indno, CURLH_HEADER, reqno);
                match result {
                    Ok(header) => {
                        if !first {
                            write_separator(separator, stream)?;
                        }
                        write!(stream, "{}", header.value())?;
                        first = false;
                        if (header.index() + 1) < header.amount() {
                            indno += 1;
                        } else {
                            reqno += 1;
                            indno = 0;
                        }
                    }
                    Err(_hcode) => break,
                }
            }
        } else {
            // Get single header from the last request
            let result: Result<Header, CurlHcode> =
                headers.get(hname, 0, CURLH_HEADER, -1);
            if let Ok(header) = result {
                write!(stream, "{}", header.value())?;
            }
        }
    }
    Ok(end + 1)
}

/// Find a variable by name using binary search on the sorted [`VARIABLES`]
/// array.
///
/// Matches the C `bsearch()` call with `matchvar()` comparator.
fn find_var(name: &str) -> Option<&'static WriteOutVar> {
    VARIABLES
        .binary_search_by(|wovar| wovar.name.cmp(name))
        .ok()
        .map(|idx| &VARIABLES[idx])
}

// ===========================================================================
// Variable lookup table — sorted alphabetically for binary search
// ===========================================================================

/// The complete list of write-out variables, sorted alphabetically by name.
///
/// This table is the Rust equivalent of the C `variables[]` array from
/// `tool_writeout.c`. Binary search is used by [`find_var`] for O(log n)
/// lookup.
pub static VARIABLES: [WriteOutVar; 73] = [
    WriteOutVar { name: "certs",                     id: VarId::Certs,                info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "conn_id",                   id: VarId::ConnId,               info: Some(CurlInfo::ConnId),                write_fn: Some(WriteOutType::Offset) },
    WriteOutVar { name: "content_type",              id: VarId::ContentType,          info: Some(CurlInfo::ContentType),           write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "curl_version",              id: VarId::CurlVersion,          info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "earlydata_sent",            id: VarId::EarlydataSent,        info: Some(CurlInfo::EarlydataSentT),        write_fn: Some(WriteOutType::Offset) },
    WriteOutVar { name: "errormsg",                  id: VarId::ErrMsg,               info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "exitcode",                  id: VarId::ExitCode,             info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::Long) },
    WriteOutVar { name: "filename_effective",         id: VarId::EffectiveFilename,    info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "ftp_entry_path",            id: VarId::FtpEntryPath,         info: Some(CurlInfo::FtpEntryPath),          write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "header_json",               id: VarId::HeaderJson,           info: Some(CurlInfo::None),                  write_fn: None },
    WriteOutVar { name: "http_code",                 id: VarId::HttpCode,             info: Some(CurlInfo::ResponseCode),          write_fn: Some(WriteOutType::Long) },
    WriteOutVar { name: "http_connect",              id: VarId::HttpCodeProxy,        info: Some(CurlInfo::HttpConnectCode),       write_fn: Some(WriteOutType::Long) },
    WriteOutVar { name: "http_version",              id: VarId::HttpVersion,          info: Some(CurlInfo::HttpVersion),           write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "json",                      id: VarId::Json,                 info: Some(CurlInfo::None),                  write_fn: None },
    WriteOutVar { name: "local_ip",                  id: VarId::LocalIp,              info: Some(CurlInfo::LocalIp),               write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "local_port",                id: VarId::LocalPort,            info: Some(CurlInfo::LocalPort),             write_fn: Some(WriteOutType::Long) },
    WriteOutVar { name: "method",                    id: VarId::EffectiveMethod,      info: Some(CurlInfo::EffectiveMethod),       write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "num_certs",                 id: VarId::NumCerts,             info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::Long) },
    WriteOutVar { name: "num_connects",              id: VarId::NumConnects,          info: Some(CurlInfo::NumConnects),           write_fn: Some(WriteOutType::Long) },
    WriteOutVar { name: "num_headers",               id: VarId::NumHeaders,           info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::Long) },
    WriteOutVar { name: "num_redirects",             id: VarId::NumRedirects,         info: Some(CurlInfo::RedirectCount),         write_fn: Some(WriteOutType::Long) },
    WriteOutVar { name: "num_retries",               id: VarId::NumRetry,             info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::Long) },
    WriteOutVar { name: "onerror",                   id: VarId::Onerror,              info: Some(CurlInfo::None),                  write_fn: None },
    WriteOutVar { name: "proxy_ssl_verify_result",   id: VarId::ProxySslVerifyResult, info: Some(CurlInfo::ProxySslVerifyResult),  write_fn: Some(WriteOutType::Long) },
    WriteOutVar { name: "proxy_used",                id: VarId::ProxyUsed,            info: Some(CurlInfo::UsedProxy),             write_fn: Some(WriteOutType::Long) },
    WriteOutVar { name: "redirect_url",              id: VarId::RedirectUrl,          info: Some(CurlInfo::RedirectUrl),           write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "referer",                   id: VarId::Referer,              info: Some(CurlInfo::Referer),               write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "remote_ip",                 id: VarId::PrimaryIp,            info: Some(CurlInfo::PrimaryIp),             write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "remote_port",               id: VarId::PrimaryPort,          info: Some(CurlInfo::PrimaryPort),           write_fn: Some(WriteOutType::Long) },
    WriteOutVar { name: "response_code",             id: VarId::ResponseCode,         info: Some(CurlInfo::ResponseCode),          write_fn: Some(WriteOutType::Long) },
    WriteOutVar { name: "scheme",                    id: VarId::Scheme,               info: Some(CurlInfo::Scheme),                write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "size_download",             id: VarId::SizeDownload,         info: Some(CurlInfo::SizeDownloadT),         write_fn: Some(WriteOutType::Offset) },
    WriteOutVar { name: "size_header",               id: VarId::HeaderSize,           info: Some(CurlInfo::HeaderSize),            write_fn: Some(WriteOutType::Long) },
    WriteOutVar { name: "size_request",              id: VarId::RequestSize,          info: Some(CurlInfo::RequestSize),           write_fn: Some(WriteOutType::Long) },
    WriteOutVar { name: "size_upload",               id: VarId::SizeUpload,           info: Some(CurlInfo::SizeUploadT),           write_fn: Some(WriteOutType::Offset) },
    WriteOutVar { name: "speed_download",            id: VarId::SpeedDownload,        info: Some(CurlInfo::SpeedDownloadT),        write_fn: Some(WriteOutType::Offset) },
    WriteOutVar { name: "speed_upload",              id: VarId::SpeedUpload,          info: Some(CurlInfo::SpeedUploadT),          write_fn: Some(WriteOutType::Offset) },
    WriteOutVar { name: "ssl_verify_result",         id: VarId::SslVerifyResult,      info: Some(CurlInfo::SslVerifyResult),       write_fn: Some(WriteOutType::Long) },
    WriteOutVar { name: "stderr",                    id: VarId::Stderr,               info: Some(CurlInfo::None),                  write_fn: None },
    WriteOutVar { name: "stdout",                    id: VarId::Stdout,               info: Some(CurlInfo::None),                  write_fn: None },
    WriteOutVar { name: "time_appconnect",           id: VarId::TimeAppconnect,       info: Some(CurlInfo::AppconnectTimeT),       write_fn: Some(WriteOutType::Time) },
    WriteOutVar { name: "time_connect",              id: VarId::TimeConnect,          info: Some(CurlInfo::ConnectTimeT),          write_fn: Some(WriteOutType::Time) },
    WriteOutVar { name: "time_namelookup",           id: VarId::TimeNamelookup,       info: Some(CurlInfo::NamelookupTimeT),       write_fn: Some(WriteOutType::Time) },
    WriteOutVar { name: "time_posttransfer",         id: VarId::TimePosttransfer,     info: Some(CurlInfo::PosttransferTimeT),     write_fn: Some(WriteOutType::Time) },
    WriteOutVar { name: "time_pretransfer",          id: VarId::TimePretransfer,      info: Some(CurlInfo::PretransferTimeT),      write_fn: Some(WriteOutType::Time) },
    WriteOutVar { name: "time_queue",                id: VarId::TimeQueue,            info: Some(CurlInfo::QueueTimeT),            write_fn: Some(WriteOutType::Time) },
    WriteOutVar { name: "time_redirect",             id: VarId::TimeRedirect,         info: Some(CurlInfo::RedirectTimeT),         write_fn: Some(WriteOutType::Time) },
    WriteOutVar { name: "time_starttransfer",        id: VarId::TimeStarttransfer,    info: Some(CurlInfo::StarttransferTimeT),    write_fn: Some(WriteOutType::Time) },
    WriteOutVar { name: "time_total",                id: VarId::TimeTotal,            info: Some(CurlInfo::TotalTimeT),            write_fn: Some(WriteOutType::Time) },
    WriteOutVar { name: "url",                       id: VarId::InputUrl,             info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "url.fragment",              id: VarId::InputUrlFragment,     info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "url.host",                  id: VarId::InputUrlHost,         info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "url.options",               id: VarId::InputUrlOptions,      info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "url.password",              id: VarId::InputUrlPassword,     info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "url.path",                  id: VarId::InputUrlPath,         info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "url.port",                  id: VarId::InputUrlPort,         info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "url.query",                 id: VarId::InputUrlQuery,        info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "url.scheme",                id: VarId::InputUrlScheme,       info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "url.user",                  id: VarId::InputUrlUser,         info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "url.zoneid",                id: VarId::InputUrlZoneid,       info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "url_effective",             id: VarId::UrlEffective,         info: Some(CurlInfo::EffectiveUrl),          write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "urle.fragment",             id: VarId::UrlFragment,          info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "urle.host",                 id: VarId::UrlHost,              info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "urle.options",              id: VarId::UrlOptions,           info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "urle.password",             id: VarId::UrlPassword,          info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "urle.path",                 id: VarId::UrlPath,              info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "urle.port",                 id: VarId::UrlPort,              info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "urle.query",                id: VarId::UrlQuery,             info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "urle.scheme",               id: VarId::UrlScheme,            info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "urle.user",                 id: VarId::UrlUser,              info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "urle.zoneid",               id: VarId::UrlZoneid,            info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::String) },
    WriteOutVar { name: "urlnum",                    id: VarId::Urlnum,               info: Some(CurlInfo::None),                  write_fn: Some(WriteOutType::Offset) },
    WriteOutVar { name: "xfer_id",                   id: VarId::XferId,               info: Some(CurlInfo::XferId),                write_fn: Some(WriteOutType::Offset) },
];

// ===========================================================================
// Stream destination tracking for output redirection
// ===========================================================================

/// Which stream `our_write_out` is currently writing to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamDest {
    Stdout,
    Stderr,
    File,
}

/// Write buffered data to the currently active stream.
///
/// Uses [`tool_stderr`] for stderr output, matching the C code's use of
/// the global `tool_stderr` FILE handle.
fn flush_to_stream(
    dest: StreamDest,
    file: &mut Option<BufWriter<File>>,
    data: &[u8],
) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    match dest {
        StreamDest::Stdout => {
            io::stdout()
                .write_all(data)
                .context("failed to write to stdout")?;
        }
        StreamDest::Stderr => {
            // Use the centralized tool_stderr handle, which may have been
            // redirected by the --stderr option (matching C tool_stderr).
            let handle = tool_stderr();
            let mut guard = handle.lock().unwrap();
            guard.stream
                .write_all(data)
                .context("failed to write to stderr")?;
        }
        StreamDest::File => {
            if let Some(f) = file.as_mut() {
                f.write_all(data).context("failed to write to output file")?;
            } else {
                // Fallback to stdout if file is unexpectedly None
                io::stdout()
                    .write_all(data)
                    .context("failed to write to stdout")?;
            }
        }
    }
    Ok(())
}

// ===========================================================================
// Template engine — our_write_out
// ===========================================================================

/// Render a `--write-out` template string, replacing `%{variable}` tokens
/// with transfer metadata from the supplied [`PerTransfer`] context.
///
/// This is the Rust equivalent of the C `ourWriteOut()` function from
/// `src/tool_writeout.c`. It processes the template character by character,
/// handling:
/// - `%%` — literal percent character
/// - `%{name}` — variable lookup via binary search in [`VARIABLES`]
/// - `%header{name}` — HTTP header extraction
/// - `%header{name:all:sep}` — all matching headers with separator
/// - `%time{fmt}` — strftime-based timestamp formatting
/// - `%output{path}` — switch output to a file (with `>>` append support)
/// - `\n`, `\r`, `\t`, `\\` — backslash escape sequences
///
/// Special variables:
/// - `%{json}` — emit all variables as a JSON object
/// - `%{header_json}` — emit response headers as JSON
/// - `%{stdout}` — switch output to stdout
/// - `%{stderr}` — switch output to stderr
/// - `%{onerror}` — suppress remaining output if transfer succeeded
pub fn our_write_out(
    template: &str,
    per: &PerTransfer<'_>,
    per_result: i32,
) -> Result<()> {
    let bytes = template.as_bytes();
    let len = bytes.len();
    let mut pos: usize = 0;
    let mut dest = StreamDest::Stdout;
    let mut opened_file: Option<BufWriter<File>> = None;

    // Reusable buffer for formatted output that gets flushed to the active
    // stream after each write operation.
    let mut buf: Vec<u8> = Vec::with_capacity(512);

    while pos < len {
        match bytes[pos] {
            // ---------------------------------------------------------------
            // Percent directives
            // ---------------------------------------------------------------
            b'%' => {
                if pos + 1 >= len {
                    // Trailing % at end of template — output literal %
                    buf.clear();
                    buf.push(b'%');
                    flush_to_stream(dest, &mut opened_file, &buf)?;
                    pos += 1;
                    continue;
                }

                match bytes[pos + 1] {
                    // %% — literal percent
                    b'%' => {
                        buf.clear();
                        buf.push(b'%');
                        flush_to_stream(dest, &mut opened_file, &buf)?;
                        pos += 2;
                    }

                    // %{variable}
                    b'{' => {
                        pos += 2; // skip "%{"
                        if let Some(close) = template[pos..].find('}') {
                            let var_name = &template[pos..pos + close];
                            // Truncate to MAX_WRITEOUT_NAME_LENGTH
                            let lookup_name = if var_name.len() > MAX_WRITEOUT_NAME_LENGTH {
                                &var_name[..MAX_WRITEOUT_NAME_LENGTH]
                            } else {
                                var_name
                            };

                            if let Some(wovar) = find_var(lookup_name) {
                                match wovar.id {
                                    VarId::Json => {
                                        buf.clear();
                                        writeout_json::our_write_out_json(
                                            per.curl,
                                            per.headers,
                                            &mut buf,
                                        )?;
                                        flush_to_stream(dest, &mut opened_file, &buf)?;
                                    }
                                    VarId::HeaderJson => {
                                        if let Some(hdrs) = per.headers {
                                            buf.clear();
                                            writeout_json::header_json(hdrs, &mut buf)?;
                                            flush_to_stream(dest, &mut opened_file, &buf)?;
                                        }
                                    }
                                    VarId::Stdout => {
                                        dest = StreamDest::Stdout;
                                    }
                                    VarId::Stderr => {
                                        dest = StreamDest::Stderr;
                                    }
                                    VarId::Onerror => {
                                        if per_result == 0 {
                                            // Transfer succeeded — stop all output
                                            // Clean up file handle before returning
                                            if let Some(mut f) = opened_file.take() {
                                                let _ = f.flush();
                                            }
                                            return Ok(());
                                        }
                                    }
                                    _ => {
                                        // Standard variable formatting
                                        buf.clear();
                                        format_var(&mut buf, wovar, per, per_result, false)?;
                                        flush_to_stream(dest, &mut opened_file, &buf)?;
                                    }
                                }
                            } else {
                                // Unknown variable — warn the user
                                msgs::warnf(
                                    per.global,
                                    &format!(
                                        "unknown --write-out variable: '{}'",
                                        lookup_name
                                    ),
                                );
                            }
                            pos += close + 1; // skip past '}'
                        } else {
                            // No closing brace — output literal "%{"
                            buf.clear();
                            buf.extend_from_slice(b"%{");
                            flush_to_stream(dest, &mut opened_file, &buf)?;
                            // pos already advanced past "%{", will continue scanning
                        }
                    }

                    _ => {
                        let remaining = &template[pos + 1..];

                        // %header{...}
                        if remaining.starts_with("header{") {
                            let after_header = &template[pos + 8..]; // skip "%header{"
                            buf.clear();
                            let consumed = output_header(per, after_header, &mut buf)?;
                            flush_to_stream(dest, &mut opened_file, &buf)?;
                            pos += 8 + consumed;
                        }
                        // %time{...}
                        else if remaining.starts_with("time{") {
                            let after_time = &template[pos + 6..]; // skip "%time{"
                            buf.clear();
                            let consumed = outtime(after_time, &mut buf)?;
                            flush_to_stream(dest, &mut opened_file, &buf)?;
                            pos += 6 + consumed;
                        }
                        // %output{...}
                        else if remaining.starts_with("output{") {
                            let after_output = &template[pos + 8..]; // skip "%output{"
                            if let Some(close) = after_output.find('}') {
                                let mut path = &after_output[..close];
                                let append_mode = path.starts_with(">>");
                                if append_mode {
                                    path = path[2..].trim_start();
                                }

                                // Close previously opened file
                                if let Some(mut f) = opened_file.take() {
                                    let _ = f.flush();
                                    // f is dropped and closed here
                                }

                                if !path.is_empty() {
                                    let file = if append_mode {
                                        OpenOptions::new()
                                            .create(true)
                                            .append(true)
                                            .open(path)
                                            .with_context(|| {
                                                format!("failed to open output file: {}", path)
                                            })?
                                    } else {
                                        File::create(path).with_context(|| {
                                            format!("failed to create output file: {}", path)
                                        })?
                                    };
                                    opened_file = Some(BufWriter::new(file));
                                    dest = StreamDest::File;
                                }
                                pos += 8 + close + 1;
                            } else {
                                // No closing brace — output literal "%output{"
                                buf.clear();
                                buf.extend_from_slice(b"%output{");
                                flush_to_stream(dest, &mut opened_file, &buf)?;
                                pos += 8;
                            }
                        }
                        // Unknown % sequence — output literal character
                        else {
                            buf.clear();
                            buf.push(b'%');
                            flush_to_stream(dest, &mut opened_file, &buf)?;
                            pos += 1;
                        }
                    }
                }
            }

            // ---------------------------------------------------------------
            // Backslash escape sequences
            // ---------------------------------------------------------------
            b'\\' => {
                if pos + 1 < len {
                    let escaped = match bytes[pos + 1] {
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        b'\\' => b'\\',
                        b'"' => b'"',
                        _ => {
                            // Unknown escape — output the backslash and the
                            // character as-is.
                            buf.clear();
                            buf.push(b'\\');
                            buf.push(bytes[pos + 1]);
                            flush_to_stream(dest, &mut opened_file, &buf)?;
                            pos += 2;
                            continue;
                        }
                    };
                    buf.clear();
                    buf.push(escaped);
                    flush_to_stream(dest, &mut opened_file, &buf)?;
                    pos += 2;
                } else {
                    // Trailing backslash — output it
                    buf.clear();
                    buf.push(b'\\');
                    flush_to_stream(dest, &mut opened_file, &buf)?;
                    pos += 1;
                }
            }

            // ---------------------------------------------------------------
            // Literal characters
            // ---------------------------------------------------------------
            ch => {
                buf.clear();
                buf.push(ch);
                flush_to_stream(dest, &mut opened_file, &buf)?;
                pos += 1;
            }
        }
    }

    // Flush and close any opened output file
    if let Some(mut f) = opened_file.take() {
        f.flush().context("failed to flush output file")?;
    }

    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the VARIABLES array is sorted alphabetically by name.
    #[test]
    fn variables_are_sorted() {
        for window in VARIABLES.windows(2) {
            assert!(
                window[0].name < window[1].name,
                "VARIABLES not sorted: '{}' should come before '{}'",
                window[0].name,
                window[1].name,
            );
        }
    }

    /// Verify binary search finds all defined variables.
    #[test]
    fn find_all_variables() {
        for v in &VARIABLES {
            let found = find_var(v.name);
            assert!(found.is_some(), "find_var failed for '{}'", v.name);
            assert_eq!(found.unwrap().name, v.name);
        }
    }

    /// Unknown variables should not be found.
    #[test]
    fn find_unknown_variable() {
        assert!(find_var("nonexistent_variable").is_none());
        assert!(find_var("").is_none());
    }

    /// Verify MAX_WRITEOUT_NAME_LENGTH matches the longest variable name.
    #[test]
    fn max_name_length_valid() {
        let max_len = VARIABLES.iter().map(|v| v.name.len()).max().unwrap_or(0);
        assert!(
            max_len <= MAX_WRITEOUT_NAME_LENGTH,
            "longest variable name ({}) exceeds MAX_WRITEOUT_NAME_LENGTH ({})",
            max_len,
            MAX_WRITEOUT_NAME_LENGTH
        );
    }

    /// JSON string escaping should handle all special characters.
    #[test]
    fn json_escape_special_chars() {
        let mut buf = Vec::new();
        json_write_string_value(&mut buf, "hello\n\r\t\"\\world").unwrap();
        let result = std::str::from_utf8(&buf).unwrap();
        assert_eq!(result, r#""hello\n\r\t\"\\world""#);
    }

    /// JSON string escaping should handle control characters.
    #[test]
    fn json_escape_control_chars() {
        let mut buf = Vec::new();
        let input = "a\x01b\x1fc";
        json_write_string_value(&mut buf, input).unwrap();
        let result = std::str::from_utf8(&buf).unwrap();
        assert_eq!(result, r#""a\u0001b\u001fc""#);
    }

    /// Verify all 73 VarId variants are present in VARIABLES.
    #[test]
    fn all_var_ids_present() {
        let all_ids: Vec<VarId> = vec![
            VarId::HttpCode, VarId::HttpVersion, VarId::HttpCodeProxy,
            VarId::NumConnects, VarId::SizeDownload, VarId::SizeUpload,
            VarId::SpeedDownload, VarId::SpeedUpload, VarId::TimeTotal,
            VarId::TimeNamelookup, VarId::TimeConnect, VarId::TimeAppconnect,
            VarId::TimeStarttransfer, VarId::TimeRedirect, VarId::TimePretransfer,
            VarId::TimePosttransfer, VarId::TimeQueue, VarId::UrlEffective,
            VarId::ContentType, VarId::NumRedirects, VarId::RedirectUrl,
            VarId::Scheme, VarId::ExitCode, VarId::EffectiveMethod,
            VarId::ResponseCode, VarId::Json, VarId::HeaderJson,
            VarId::Stdout, VarId::Stderr, VarId::Onerror,
            VarId::Certs, VarId::NumCerts, VarId::CurlVersion,
            VarId::UrlHost, VarId::UrlPort, VarId::UrlPath,
            VarId::UrlQuery, VarId::UrlScheme, VarId::UrlUser,
            VarId::UrlPassword, VarId::UrlOptions, VarId::UrlFragment,
            VarId::UrlZoneid, VarId::InputUrl, VarId::InputUrlHost,
            VarId::InputUrlPort, VarId::InputUrlPath, VarId::InputUrlQuery,
            VarId::InputUrlScheme, VarId::InputUrlUser, VarId::InputUrlPassword,
            VarId::InputUrlOptions, VarId::InputUrlFragment, VarId::InputUrlZoneid,
            VarId::PrimaryIp, VarId::PrimaryPort, VarId::LocalIp,
            VarId::LocalPort, VarId::SslVerifyResult, VarId::ProxySslVerifyResult,
            VarId::HeaderSize, VarId::RequestSize, VarId::Referer,
            VarId::FtpEntryPath, VarId::ErrMsg, VarId::EffectiveFilename,
            VarId::Urlnum, VarId::ConnId, VarId::XferId,
            VarId::NumHeaders, VarId::NumRetry, VarId::ProxyUsed,
            VarId::EarlydataSent,
        ];
        for id in &all_ids {
            let found = VARIABLES.iter().any(|v| v.id == *id);
            assert!(found, "VarId::{:?} not found in VARIABLES", id);
        }
    }
}
