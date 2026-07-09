// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! `FILE` protocol handler — the memory-safe Rust port of curl's `lib/file.c`
//! (+ `lib/file.h`) for the byte-for-byte functional-parity rewrite of
//! curl / libcurl **8.19.0-DEV**.
//!
//! The `file:` scheme reads and writes the **local filesystem**; it has **no
//! network transport** (`PROTOPT_NONETWORK`). curl models it as a
//! connect-then-transfer protocol purely to fit the generic transfer state
//! machine, but every byte moved here comes from or goes to a local file, never
//! a socket. Accordingly this module routes I/O through [`tokio::fs`] /
//! [`tokio::io`] — never through the socket / connection-filter chain — so the
//! multi event loop is never blocked on a blocking `read(2)`/`write(2)`, exactly
//! matching curl's intent of doing the whole FILE do-phase without `select()`.
//!
//! # What is reproduced (Minimal Change Mandate)
//!
//! Everything `lib/file.c` does, and nothing more:
//!
//! * **URL → path resolution** (← `file_connect` / `Curl_urldecode`): the URL
//!   path is percent-decoded with curl's `REJECT_ZERO` rule (any decoded NUL
//!   byte is [`CurlCode::UrlMalformat`]). On the four supported Unix targets
//!   (Linux/macOS) the path is used verbatim — a leading `/` denotes an absolute
//!   path — with none of the DOS drive-letter or AmigaOS volume rewriting from
//!   the excluded platforms. [`file_url_to_path`] additionally strips the
//!   scheme and the (empty / `localhost` / RFC 1738-ignored) authority so that
//!   both `file:///path` and `file://localhost/path` resolve identically.
//! * **Download** (← `file_do`): `stat` for size + modification time; the
//!   modification time is exposed for `CURLINFO_FILETIME`; `CURLOPT_TIMECONDITION`
//!   is honored ([`meets_timecondition`]) so an unmet condition completes with
//!   [`CurlCode::Ok`] and no transfer; range / resume
//!   (`CURLOPT_RANGE` / `CURLOPT_RESUME_FROM`) is applied by seeking; the
//!   synthesized `Content-Length` / `Accept-ranges` / `Last-Modified` headers are
//!   emitted byte-for-byte; the body is streamed in curl-sized chunks; a
//!   directory is rendered as a newline-separated listing (dot-files skipped),
//!   just like curl's `opendir`/`readdir` branch.
//! * **Upload** (← `file_upload`): the destination is created / truncated, or
//!   opened for append when resuming (curl keys append off a non-zero
//!   `resume_from`, *not* `CURLOPT_APPEND`, in `lib/file.c`); a negative
//!   `resume_from` resolves to the current file size; the read-callback bytes are
//!   written after the resume offset is skipped across chunk boundaries.
//! * **Error codes**: open failure on download → [`CurlCode::FileCouldntReadFile`];
//!   open/stat failure on upload → [`CurlCode::WriteError`]; a bad resume offset →
//!   [`CurlCode::BadDownloadResume`]; a short write → [`CurlCode::SendError`]; a
//!   directory-listing failure → [`CurlCode::ReadError`] — each at exactly the
//!   point curl returns it.
//!
//! # Module shape: engine + handler
//!
//! The reusable FILE behavior lives in free functions and plain data types
//! ([`download`], [`upload`], [`resolve_url_path`], [`file_url_to_path`],
//! [`meets_timecondition`], [`DownloadRequest`]/[`DownloadOutcome`],
//! [`UploadRequest`]/[`UploadOutcome`], and the [`ClientWrite`] sink that models
//! curl's `Curl_client_write` `CLIENTWRITE_HEADER`/`CLIENTWRITE_BODY` split).
//! They take the same inputs `file_do`/`file_upload` read out of
//! `struct Curl_easy` (`data->state`/`data->set`/`data->req`), so they are the
//! faithful, fully-testable core of the handler.
//!
//! [`HANDLER`] is the `&'static dyn Protocol` singleton the scheme table in
//! [`crate::protocols`] points `file` at. Its trait methods reproduce FILE's
//! phase results: connect completes in a single shot (curl sets `*done = TRUE`),
//! the DO phase resolves the URL path from the [`TransferCtx`] request and
//! drives the engine — [`download`] for a fetch or [`upload`] for a
//! `--upload-file`, streaming the body to the transfer's download sink — and
//! teardown is a no-op close (local I/O owns nothing beyond the open file,
//! which the transfer state drops). Because file descriptors cannot be
//! `select()`-ed, the DO phase performs the whole transfer in one call and
//! reports completion, exactly as `file_do` sets `*done = TRUE`.
//!
//! # Safety
//!
//! Written entirely in safe Rust: no escape-hatch blocks, no raw file
//! descriptors, no `libc` — only [`std::fs`]-style paths via [`tokio::fs`]. The
//! crate root's `#![forbid(...)]` safe-code lint is enforced here, and this
//! module is one of the audited safe-code zones. It depends only on [`crate::protocols`] and
//! [`crate::error`].

use std::borrow::Cow;
use std::ffi::OsStr;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::error::{CurlCode, Error, Result};
use crate::protocols::{ProtoFuture, Protocol, TransferCtx, TransferSink};

// ===========================================================================
// Buffer sizes and permissions — curl defaults reproduced verbatim.
// ===========================================================================

/// Download transfer-buffer size (← `CURL_MAX_WRITE_SIZE`, the default
/// `data->set.buffer_size`). curl reads at most `buffer_size - 1` bytes per
/// iteration (reserving one byte for a C NUL terminator); the chunk boundaries
/// are reproduced so the body-write callback fires with the same sizes.
pub const CURL_MAX_WRITE_SIZE: usize = 16_384;

/// Upload transfer-buffer size (← `UPLOADBUFFER_DEFAULT`, the default
/// `data->set.upload_buffer_size`), the amount curl pulls from the read
/// callback per iteration in `file_upload`.
pub const UPLOAD_BUFFER_SIZE: usize = 65_536;

/// Default permission bits for a file created by an upload (← curl's
/// `data->set.new_file_perms`, initialized to `0644` in `lib/url.c`). Applied
/// on Unix targets when the destination is created.
pub const DEFAULT_NEW_FILE_PERMS: u32 = 0o644;

/// Abbreviated weekday names (← `Curl_wkday`, `lib/parsedate.c`), ordered
/// Monday-first exactly as curl stores them.
const WKDAY: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

/// Abbreviated month names (← `Curl_month`, `lib/parsedate.c`), indexed by the
/// zero-based month (January = 0).
const MONTH: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

// ===========================================================================
// TimeCond — CURLOPT_TIMECONDITION selector (← `curl_TimeCond`, curl.h).
// ===========================================================================

/// The `CURLOPT_TIMECONDITION` selector (← the `CURL_TIMECOND_*` values in
/// `include/curl/curl.h`). Discriminants are frozen to the public ABI values.
#[repr(i64)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TimeCond {
    /// `CURL_TIMECOND_NONE` — no time condition (the transfer always proceeds).
    #[default]
    None = 0,
    /// `CURL_TIMECOND_IFMODSINCE` — transfer only if newer than the reference
    /// time (`If-Modified-Since` semantics).
    IfModifiedSince = 1,
    /// `CURL_TIMECOND_IFUNMODSINCE` — transfer only if older than the reference
    /// time (`If-Unmodified-Since` semantics).
    IfUnmodifiedSince = 2,
    /// `CURL_TIMECOND_LASTMOD` — behaves like [`TimeCond::IfModifiedSince`] for
    /// the comparison (curl's `switch` folds `LASTMOD` into the default arm).
    LastModified = 3,
}

impl TimeCond {
    /// Map a raw `CURL_TIMECOND_*` integer (as carried by
    /// [`TransferRequest::time_condition`](crate::protocols::TransferRequest::time_condition))
    /// to a [`TimeCond`]. Any unrecognized value folds to [`TimeCond::None`],
    /// matching curl's `switch` default (no condition ⇒ always transfer).
    #[must_use]
    pub fn from_raw(value: i32) -> Self {
        match value {
            1 => TimeCond::IfModifiedSince,
            2 => TimeCond::IfUnmodifiedSince,
            3 => TimeCond::LastModified,
            _ => TimeCond::None,
        }
    }
}

/// Evaluate a `CURLOPT_TIMECONDITION` against a document's modification time
/// (← `Curl_meets_timecondition`, `lib/transfer.c`).
///
/// `filetime` and `timevalue` are Unix timestamps (seconds). Returns `true`
/// when the condition is *met* (the transfer should proceed) and `false` when
/// it is not (the caller completes with [`CurlCode::Ok`] and moves no data —
/// curl's `data->info.timecond = TRUE` path).
///
/// Matching curl exactly: if either time is `0` (unknown / unset) the condition
/// is treated as met. [`TimeCond::IfModifiedSince`] and [`TimeCond::LastModified`]
/// require `filetime > timevalue`; [`TimeCond::IfUnmodifiedSince`] requires
/// `filetime < timevalue`. [`TimeCond::None`] is always met.
#[must_use]
pub fn meets_timecondition(filetime: i64, timevalue: i64, cond: TimeCond) -> bool {
    if filetime == 0 || timevalue == 0 {
        return true;
    }
    match cond {
        // curl's `switch` handles only IFUNMODSINCE specially; IFMODSINCE,
        // LASTMOD, and any other value fall through to the default arm.
        TimeCond::IfUnmodifiedSince => filetime < timevalue,
        TimeCond::None | TimeCond::IfModifiedSince | TimeCond::LastModified => filetime > timevalue,
    }
}

// ===========================================================================
// gmtime — UTC broken-down time for the Last-Modified header.
//
// A pure-integer reimplementation of the calendar math curl reaches via
// `Curl_gmtime`/`gmtime_r`. It is total for every `i64` second value a file
// mtime can hold, so — unlike the C wrapper, whose only failure is a NULL
// `gmtime` return for out-of-range input — it needs no error path.
// ===========================================================================

/// Broken-down UTC time (the fields of `struct tm` this module needs).
struct Tm {
    /// Full year, e.g. `1994` (curl's `tm_year + 1900`).
    year: i64,
    /// Month, zero-based (January = 0), matching `tm_mon`.
    mon: u32,
    /// Day of month, `1..=31` (`tm_mday`).
    mday: u32,
    /// Hour, `0..=23`.
    hour: u32,
    /// Minute, `0..=59`.
    min: u32,
    /// Second, `0..=60`.
    sec: u32,
    /// Day of week, `0 = Sunday ..= 6 = Saturday` (`tm_wday`).
    wday: u32,
}

/// Convert days-since-1970-01-01 to `(year, month[1..=12], day[1..=31])` using
/// Howard Hinnant's `civil_from_days` algorithm (proleptic Gregorian, the same
/// calendar `gmtime` uses). Uses C-style truncating division deliberately: the
/// `z - 146096` adjustment makes the era division behave as a floor for
/// negative day counts.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097; // day of era, [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year, [0, 365]
    let mp = (5 * doy + 2) / 153; // month, [0, 11] (March = 0)
    let d = doy - (153 * mp + 2) / 5 + 1; // day, [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // month, [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32, d as u32)
}

/// Compute UTC broken-down time from a Unix timestamp (← `Curl_gmtime`).
fn gmtime(secs: i64) -> Tm {
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let hour = (tod / 3_600) as u32;
    let min = ((tod % 3_600) / 60) as u32;
    let sec = (tod % 60) as u32;
    // 1970-01-01 is a Thursday (tm_wday == 4); rem_euclid keeps it non-negative
    // for pre-epoch timestamps.
    let wday = ((days + 4).rem_euclid(7)) as u32;
    let (year, month, mday) = civil_from_days(days);
    Tm {
        year,
        mon: month - 1,
        mday,
        hour,
        min,
        sec,
        wday,
    }
}

/// Format the `Last-Modified` response header line curl synthesizes for a
/// `file:` download, including the trailing CRLF (← the `curl_msnprintf`
/// `"Last-Modified: %s, %02d %s %4d %02d:%02d:%02d GMT\r\n"` in `file_do`).
///
/// The weekday index reproduces curl's `Curl_wkday[tm->tm_wday ? tm->tm_wday - 1 : 6]`
/// expression, which maps the Sunday-first `tm_wday` onto the Monday-first
/// [`WKDAY`] table.
fn format_last_modified(tm: &Tm) -> String {
    let wday_idx = if tm.wday != 0 {
        (tm.wday - 1) as usize
    } else {
        6
    };
    format!(
        "Last-Modified: {}, {:02} {} {:4} {:02}:{:02}:{:02} GMT\r\n",
        WKDAY[wday_idx], tm.mday, MONTH[tm.mon as usize], tm.year, tm.hour, tm.min, tm.sec,
    )
}

/// Convert a [`SystemTime`] to a signed Unix timestamp in whole seconds,
/// matching the `time_t` resolution of curl's `statbuf.st_mtime`.
fn systemtime_to_unix_secs(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX),
    }
}

// ===========================================================================
// URL → local path (← `file_connect` / `Curl_urldecode`).
// ===========================================================================

/// Numeric value of a single ASCII hex digit, or `None` if it is not one.
fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode a URL path with curl's `REJECT_ZERO` rule
/// (← `Curl_urldecode(..., REJECT_ZERO)`).
///
/// A `%XX` sequence with two hex digits decodes to the corresponding byte;
/// every other byte is passed through unchanged (a stray `%` not followed by
/// two hex digits is literal, exactly as curl treats it). If any resulting byte
/// is a NUL the whole path is rejected as [`CurlCode::UrlMalformat`] — this is
/// both curl's `REJECT_ZERO` check and the redundant `memchr(..., 0, ...)`
/// guard `file_connect` performs afterward.
fn urldecode_reject_zero(input: &str) -> Result<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let decoded = if bytes[i] == b'%' && i + 2 < bytes.len() {
            match (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                (Some(hi), Some(lo)) => {
                    i += 3;
                    (hi << 4) | lo
                }
                _ => {
                    // Not a valid escape: keep the literal '%'.
                    i += 1;
                    b'%'
                }
            }
        } else {
            let b = bytes[i];
            i += 1;
            b
        };
        if decoded == 0 {
            return Err(Error::url("file: URL path contains a zero byte"));
        }
        out.push(decoded);
    }
    Ok(out)
}

/// Build a [`PathBuf`] from raw decoded bytes. On Unix the bytes are used
/// verbatim (paths are arbitrary NUL-free byte strings there); on other targets
/// they are interpreted lossily as UTF-8. No escape-hatch code is involved — the Unix
/// path is built through the safe [`std::os::unix::ffi::OsStrExt`] adapter.
#[cfg(unix)]
fn bytes_to_path(bytes: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    PathBuf::from(OsStr::from_bytes(bytes))
}

#[cfg(not(unix))]
fn bytes_to_path(bytes: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
}

/// Return a directory entry's file name as raw bytes (borrowed on Unix).
#[cfg(unix)]
fn os_name_bytes(name: &OsStr) -> Cow<'_, [u8]> {
    use std::os::unix::ffi::OsStrExt;
    Cow::Borrowed(name.as_bytes())
}

#[cfg(not(unix))]
fn os_name_bytes(name: &OsStr) -> Cow<'_, [u8]> {
    Cow::Owned(name.to_string_lossy().into_owned().into_bytes())
}

/// Resolve a URL **path component** (curl's `data->state.up.path`, already
/// separated from scheme and authority by the URL parser) to a local
/// filesystem path (← the decode step of `file_connect`).
///
/// The path is percent-decoded with the `REJECT_ZERO` rule and used verbatim on
/// the supported Unix targets — a leading `/` is an absolute path. The
/// platform-specific DOS drive-letter and AmigaOS volume rewriting of curl's
/// excluded platforms is intentionally not reproduced (those targets are out of
/// scope, AAP §0.2.2).
///
/// # Errors
///
/// Returns [`CurlCode::UrlMalformat`] if the decoded path contains a NUL byte.
pub fn resolve_url_path(path: &str) -> Result<PathBuf> {
    let decoded = urldecode_reject_zero(path)?;
    Ok(bytes_to_path(&decoded))
}

/// Resolve a full `file:` URL to a local filesystem path, stripping the scheme
/// and the authority before delegating to [`resolve_url_path`].
///
/// Reproduces curl's handling of both `file:///path` (empty authority) and
/// `file://localhost/path`, and — per RFC 1738 and the note in `file_do` — an
/// arbitrary host authority (`file://host/path`) whose host is simply ignored
/// for a local file. A `file:` URL with no `//` authority marker
/// (`file:/path`) is accepted with the remainder taken as the path. A bare path
/// with no `file:` scheme is decoded as-is, so callers may pass either form.
///
/// # Errors
///
/// Returns [`CurlCode::UrlMalformat`] if the decoded path contains a NUL byte.
pub fn file_url_to_path(url: &str) -> Result<PathBuf> {
    // Strip a leading, case-insensitive "file:" scheme if present.
    let after_scheme = if url.len() >= 5 && url[..5].eq_ignore_ascii_case("file:") {
        &url[5..]
    } else {
        url
    };

    // If an authority marker "//" follows the scheme, drop the authority
    // (everything up to the next '/'), keeping the path from that '/'. curl
    // ignores the host for local files (RFC 1738); an empty or "localhost"
    // authority is the common case. When no path-separator follows the
    // authority the remainder is treated as an (empty-authority) path.
    let path = if let Some(rest) = after_scheme.strip_prefix("//") {
        match rest.find('/') {
            Some(slash) => &rest[slash..],
            None => "",
        }
    } else {
        after_scheme
    };

    resolve_url_path(path)
}

// ===========================================================================
// ClientWrite — the download output sink (← `Curl_client_write`).
// ===========================================================================

/// Sink for the bytes a `file:` download produces, modeling curl's
/// `Curl_client_write` with its `CLIENTWRITE_HEADER` / `CLIENTWRITE_BODY`
/// split.
///
/// A `file:` download synthesizes response headers (`Content-Length`,
/// `Accept-ranges`, `Last-Modified`) and then streams the body (or a directory
/// listing). curl routes the two through one callback distinguished by a flag;
/// this trait keeps them as two methods so a consumer can direct headers and
/// body independently, exactly as the header (`CURLOPT_HEADERFUNCTION`) and
/// write (`CURLOPT_WRITEFUNCTION`) callbacks do.
pub trait ClientWrite {
    /// Consume a chunk of synthesized **header** bytes (← `CLIENTWRITE_HEADER`).
    ///
    /// # Errors
    ///
    /// Propagates any error the sink raises; curl surfaces a header-callback
    /// failure as [`CurlCode::WriteError`].
    fn write_header(&mut self, data: &[u8]) -> Result<()>;

    /// Consume a chunk of **body** bytes (← `CLIENTWRITE_BODY`).
    ///
    /// # Errors
    ///
    /// Propagates any error the sink raises; curl surfaces a write-callback
    /// failure as [`CurlCode::WriteError`].
    fn write_body(&mut self, data: &[u8]) -> Result<()>;
}

// ===========================================================================
// Download (← `file_do`).
// ===========================================================================

/// The download inputs `file_do` reads out of `struct Curl_easy`.
///
/// These mirror the exact fields curl consults, so [`download`] reproduces
/// `file_do` without needing the full easy handle.
#[derive(Clone, Copy, Debug)]
pub struct DownloadRequest {
    /// `data->req.no_body` (`CURLOPT_NOBODY` / `-I`): emit headers only, then
    /// stop with success.
    pub no_body: bool,
    /// Whether a byte range was requested (`data->state.range != NULL`). When
    /// set, the `CURLOPT_TIMECONDITION` early-out is skipped, matching curl.
    pub range_requested: bool,
    /// `data->state.resume_from` (`CURLOPT_RESUME_FROM`, or the low end of
    /// `CURLOPT_RANGE`). A negative value counts back from the end of the file.
    pub resume_from: i64,
    /// `data->req.maxdownload` (the high-water mark derived from
    /// `CURLOPT_RANGE`). A positive value caps the number of bytes transferred.
    pub maxdownload: i64,
    /// `data->set.timecondition` (`CURLOPT_TIMECONDITION`).
    pub timecondition: TimeCond,
    /// `data->set.timevalue` (`CURLOPT_TIMEVALUE`), a Unix timestamp in seconds.
    pub timevalue: i64,
}

impl Default for DownloadRequest {
    /// A plain download: whole file, no HEAD, no range, no time condition —
    /// the state of a freshly initialized easy handle.
    fn default() -> Self {
        Self {
            no_body: false,
            range_requested: false,
            resume_from: 0,
            maxdownload: 0,
            timecondition: TimeCond::None,
            timevalue: 0,
        }
    }
}

/// The observable results of a `file:` download, carrying what curl records on
/// the easy handle for post-transfer inspection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DownloadOutcome {
    /// The file's modification time in Unix seconds, exposed for
    /// `CURLINFO_FILETIME` (← `data->info.filetime`). `None` if the file could
    /// not be `stat`-ed.
    pub filetime: Option<i64>,
    /// The transfer size curl would report via `Curl_pgrsSetDownloadSize`
    /// (`Content-Length`-equivalent). `None` when the size is unknown (e.g. a
    /// directory listing).
    pub size: Option<i64>,
    /// Total body bytes written to the sink (← curl's downloaded-bytes count).
    pub body_bytes: u64,
    /// `true` when a `CURLOPT_TIMECONDITION` was not met and the transfer
    /// completed with success but moved no data (← `data->info.timecond`).
    pub timecondition_unmet: bool,
}

/// Perform a `file:` download from an already-resolved local `path`
/// (← `file_do`, download branch).
///
/// The file is opened for reading (a failure is [`CurlCode::FileCouldntReadFile`],
/// as in `file_connect` for a non-upload transfer), `stat`-ed for size and
/// modification time, checked against the time condition, and then — unless
/// `no_body` is set — streamed to `sink` after any range/resume seek. A
/// directory is rendered as a newline-separated listing with dot-entries
/// skipped, reproducing curl's `readdir` branch.
///
/// # Errors
///
/// * [`CurlCode::FileCouldntReadFile`] — the path could not be opened.
/// * [`CurlCode::ReadError`] — a negative resume offset with an unknown file
///   size, or a directory listing failure.
/// * [`CurlCode::BadDownloadResume`] — the resume offset exceeds the file size,
///   the target is a directory, or the seek did not land on the requested
///   offset.
/// * [`CurlCode::WriteError`] — the sink rejected header or body bytes.
pub async fn download<W: ClientWrite>(
    path: &Path,
    sink: &mut W,
    req: &DownloadRequest,
) -> Result<DownloadOutcome> {
    // ── Open (← file_connect: curlx_open(path, O_RDONLY)) ──────────────────
    let mut file = match fs::File::open(path).await {
        Ok(f) => f,
        Err(_) => {
            return Err(Error::with_context(
                CurlCode::FileCouldntReadFile,
                format!("Could not open file {}", path.display()),
            ));
        }
    };

    // ── stat: size + modification time (← curlx_fstat) ─────────────────────
    let mut expected_size: i64 = -1;
    let mut raw_size: i64 = 0;
    let mut filetime: Option<i64> = None;
    let mut fstated = false;
    let mut is_dir = false;
    if let Ok(md) = file.metadata().await {
        fstated = true;
        is_dir = md.is_dir();
        raw_size = i64::try_from(md.len()).unwrap_or(i64::MAX);
        if !is_dir {
            expected_size = raw_size;
        }
        // Store the modification time for CURLINFO_FILETIME.
        filetime = md.modified().ok().map(systemtime_to_unix_secs);
    }
    let filetime_secs = filetime.unwrap_or(0);

    // ── Time condition (← Curl_meets_timecondition early-out) ──────────────
    // Only consulted when the file was stat-ed, no range was requested, and a
    // condition other than NONE is active.
    if fstated
        && !req.range_requested
        && req.timecondition != TimeCond::None
        && !meets_timecondition(filetime_secs, req.timevalue, req.timecondition)
    {
        return Ok(DownloadOutcome {
            filetime,
            size: None,
            body_bytes: 0,
            timecondition_unmet: true,
        });
    }

    // ── Synthesized response headers (← the `if(fstated)` block) ───────────
    if fstated {
        if expected_size >= 0 {
            sink.write_header(format!("Content-Length: {expected_size}\r\n").as_bytes())?;
            sink.write_header(b"Accept-ranges: bytes\r\n")?;
        }
        let tm = gmtime(filetime_secs);
        sink.write_header(format_last_modified(&tm).as_bytes())?;
        // End of headers.
        sink.write_header(b"\r\n")?;

        if req.no_body {
            // HEAD-style request: headers only, no body (← `if(data->req.no_body)`).
            return Ok(DownloadOutcome {
                filetime,
                size: (expected_size >= 0).then_some(expected_size),
                body_bytes: 0,
                timecondition_unmet: false,
            });
        }
    }

    // ── Range / resume offset resolution (← the Curl_range follow-up) ──────
    // `req.resume_from` / `req.maxdownload` arrive already parsed (curl's
    // `Curl_range` populates `data->state`/`data->req` before this point).
    let mut resume_from = req.resume_from;
    if resume_from < 0 {
        if !fstated {
            return Err(Error::with_context(
                CurlCode::ReadError,
                "cannot get the size of file.",
            ));
        }
        // Count back from the end of the file (curl adds the raw st_size).
        resume_from += raw_size;
    }
    if resume_from > 0 {
        if resume_from <= expected_size {
            expected_size -= resume_from;
        } else {
            return Err(Error::with_context(
                CurlCode::BadDownloadResume,
                "failed to resume file:// transfer",
            ));
        }
    }
    // A high-water mark caps the transfer size.
    if req.maxdownload > 0 {
        expected_size = req.maxdownload;
    }
    let size_known = fstated && expected_size > 0;
    let reported_size = size_known.then_some(expected_size);

    // ── Seek to the resume offset (← curl_lseek) ───────────────────────────
    // curl treats any non-zero resume offset here (including a still-negative
    // one, which means the negative offset exceeded the file size) as a seek;
    // a directory, a negative offset, or a short/failed seek is a bad resume.
    if resume_from != 0 {
        if is_dir || resume_from < 0 {
            return Err(Error::from(CurlCode::BadDownloadResume));
        }
        let landed = file
            .seek(SeekFrom::Start(resume_from as u64))
            .await
            .map_err(|_| Error::from(CurlCode::BadDownloadResume))?;
        if landed != resume_from as u64 {
            return Err(Error::from(CurlCode::BadDownloadResume));
        }
    }

    // ── Stream the body ────────────────────────────────────────────────────
    let mut body_bytes: u64 = 0;
    if is_dir {
        body_bytes += write_directory_listing(path, sink).await?;
    } else {
        body_bytes += stream_file_body(&mut file, sink, size_known, expected_size).await?;
    }

    Ok(DownloadOutcome {
        filetime,
        size: reported_size,
        body_bytes,
        timecondition_unmet: false,
    })
}

/// Stream a regular file's bytes to `sink` in curl-sized chunks
/// (← the `if(!S_ISDIR(...))` read loop in `file_do`).
///
/// When the size is known each read is capped at `min(remaining, BUFSIZE - 1)`
/// and `remaining` is decremented, so the loop stops after exactly
/// `expected_size` bytes (reproducing curl's high-water behavior); otherwise it
/// reads until EOF. Returns the number of body bytes written.
async fn stream_file_body<W: ClientWrite>(
    file: &mut fs::File,
    sink: &mut W,
    size_known: bool,
    expected_size: i64,
) -> Result<u64> {
    let mut buf = vec![0u8; CURL_MAX_WRITE_SIZE];
    let mut remaining = expected_size;
    let mut body_bytes: u64 = 0;
    loop {
        let bytestoread = if size_known {
            // `- 1` mirrors curl reserving one byte for its C NUL terminator.
            remaining.min((CURL_MAX_WRITE_SIZE - 1) as i64).max(0) as usize
        } else {
            CURL_MAX_WRITE_SIZE - 1
        };
        let n = file
            .read(&mut buf[..bytestoread])
            .await
            .map_err(Error::Io)?;
        if n == 0 || (size_known && remaining == 0) {
            break;
        }
        if size_known {
            remaining -= n as i64;
        }
        sink.write_body(&buf[..n])?;
        body_bytes += n as u64;
    }
    Ok(body_bytes)
}

/// Render a directory as a newline-separated listing (← curl's
/// `opendir`/`readdir` branch), skipping entries whose name begins with `.`.
/// Returns the number of body bytes written.
async fn write_directory_listing<W: ClientWrite>(path: &Path, sink: &mut W) -> Result<u64> {
    let mut entries = fs::read_dir(path)
        .await
        .map_err(|_| Error::from(CurlCode::ReadError))?;
    let mut body_bytes: u64 = 0;
    loop {
        match entries.next_entry().await {
            Ok(Some(entry)) => {
                let name = entry.file_name();
                let name_bytes = os_name_bytes(&name);
                // curl: `if(entry->d_name[0] != '.')`.
                if name_bytes.first() != Some(&b'.') {
                    sink.write_body(name_bytes.as_ref())?;
                    sink.write_body(b"\n")?;
                    body_bytes += name_bytes.len() as u64 + 1;
                }
            }
            Ok(None) => break,
            Err(_) => return Err(Error::from(CurlCode::ReadError)),
        }
    }
    Ok(body_bytes)
}

// ===========================================================================
// Upload (← `file_upload`).
// ===========================================================================

/// The upload inputs `file_upload` reads out of `struct Curl_easy`.
#[derive(Clone, Copy, Debug)]
pub struct UploadRequest {
    /// `data->state.resume_from`. A non-zero value opens the destination for
    /// **append** (rather than truncate) and skips that many bytes of the input
    /// stream; a negative value resolves to the destination's current size.
    ///
    /// Note: in `lib/file.c` the append-vs-truncate decision is keyed off this
    /// resume offset, **not** `CURLOPT_APPEND` (which drives FTP/SFTP instead),
    /// and this reproduces that exactly.
    pub resume_from: i64,
    /// `data->state.infilesize` (`CURLOPT_INFILESIZE`): the known upload size,
    /// or `-1` if unknown. Reported as the progress upload size; it does not
    /// bound the number of bytes written (the source's EOF does).
    pub infilesize: i64,
    /// `data->set.new_file_perms` (`CURLOPT_NEW_FILE_PERMS`): permission bits
    /// applied when the destination is created (Unix). Defaults to
    /// [`DEFAULT_NEW_FILE_PERMS`].
    pub new_file_perms: u32,
}

impl Default for UploadRequest {
    /// A plain upload: truncating write, unknown input size, default perms.
    fn default() -> Self {
        Self {
            resume_from: 0,
            infilesize: -1,
            new_file_perms: DEFAULT_NEW_FILE_PERMS,
        }
    }
}

/// The observable results of a `file:` upload.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UploadOutcome {
    /// The known input size curl would report via `Curl_pgrsSetUploadSize`
    /// (← `data->state.infilesize` when not `-1`). `None` if unknown.
    pub upload_size: Option<i64>,
    /// Total bytes actually written to the destination (after the resume offset
    /// was skipped).
    pub uploaded_bytes: u64,
}

/// Perform a `file:` upload to a local `path`, reading the payload from
/// `source` (← `file_upload`).
///
/// The destination is opened write + create, then **truncated** for a fresh
/// upload or opened for **append** when `resume_from` is non-zero. A negative
/// `resume_from` is resolved to the destination's current size. Each chunk read
/// from `source` has the leading `resume_from` bytes skipped (across chunk
/// boundaries) before the remainder is appended.
///
/// # Errors
///
/// * [`CurlCode::WriteError`] — the destination could not be opened for
///   writing, or its size could not be determined for a negative resume.
/// * [`CurlCode::ReadError`] — reading from `source` failed.
/// * [`CurlCode::SendError`] — writing to the destination failed or was short.
pub async fn upload<R: AsyncRead + Unpin>(
    path: &Path,
    source: &mut R,
    req: &UploadRequest,
) -> Result<UploadOutcome> {
    // ── Open the destination (← curlx_open with the computed mode) ─────────
    // O_WRONLY | O_CREAT, plus O_APPEND when resuming or O_TRUNC otherwise.
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true);
    if req.resume_from != 0 {
        opts.append(true);
    } else {
        opts.truncate(true);
    }
    #[cfg(unix)]
    {
        // `tokio::fs::OpenOptions::mode` is an inherent Unix method; the OS
        // honors these permission bits only when the file is created.
        opts.mode(req.new_file_perms);
    }
    let mut file = match opts.open(path).await {
        Ok(f) => f,
        Err(_) => {
            return Err(Error::with_context(
                CurlCode::WriteError,
                format!("cannot open {} for writing", path.display()),
            ));
        }
    };

    // Progress upload size (← `if(data->state.infilesize != -1)`).
    let upload_size = (req.infilesize != -1).then_some(req.infilesize);

    // ── Resolve a negative resume offset to the current file size ──────────
    // (← `if(data->state.resume_from < 0)` fstat block).
    let mut resume_from = req.resume_from;
    if resume_from < 0 {
        match file.metadata().await {
            Ok(md) => resume_from = i64::try_from(md.len()).unwrap_or(i64::MAX),
            Err(_) => {
                return Err(Error::with_context(
                    CurlCode::WriteError,
                    format!("cannot get the size of {}", path.display()),
                ));
            }
        }
    }

    // ── Read/skip/write loop (← the `while(!result && !eos)` loop) ─────────
    let mut buf = vec![0u8; UPLOAD_BUFFER_SIZE];
    let mut uploaded_bytes: u64 = 0;
    loop {
        let readcount = source.read(&mut buf).await.map_err(Error::Io)?;
        if readcount == 0 {
            // End of the upload stream (curl's `!readcount` / eos break).
            break;
        }
        // Skip bytes before the resume point, spanning chunk boundaries.
        let sendbuf: &[u8] = if resume_from > 0 {
            if (readcount as i64) <= resume_from {
                resume_from -= readcount as i64;
                &buf[..0]
            } else {
                let skip = resume_from as usize;
                resume_from = 0;
                &buf[skip..readcount]
            }
        } else {
            &buf[..readcount]
        };
        if !sendbuf.is_empty() {
            // curl treats a short write as CURLE_SEND_ERROR; write_all maps
            // both a short write and an I/O error to that.
            file.write_all(sendbuf)
                .await
                .map_err(|_| Error::from(CurlCode::SendError))?;
            uploaded_bytes += sendbuf.len() as u64;
        }
    }
    file.flush()
        .await
        .map_err(|_| Error::from(CurlCode::SendError))?;

    Ok(UploadOutcome {
        upload_size,
        uploaded_bytes,
    })
}

// ===========================================================================
// Protocol handler (← `Curl_protocol_file` / `Curl_scheme_file`).
// ===========================================================================

/// The `file:` protocol handler singleton's type (← `Curl_protocol_file`).
///
/// A zero-sized dispatcher: the FILE scheme keeps no per-handler state (the
/// per-transfer state — the resolved path and open file — lives with the
/// transfer, curl's `struct FILEPROTO` behind `CURL_META_FILE_EASY`). The
/// substantive behavior is the free-function engine above ([`download`],
/// [`upload`], [`resolve_url_path`]).
#[derive(Clone, Copy, Debug, Default)]
pub struct FileProtocol;

/// Adapts the transfer's body [`TransferSink`] to the engine's [`ClientWrite`]
/// contract for the DO phase: **body** bytes are forwarded to the download sink
/// while the synthesized **header** bytes curl routes to `CLIENTWRITE_HEADER`
/// are dropped (a plain `file://` fetch surfaces only the body; there is no
/// header sink in [`TransferCtx`]). Holds `None` when the transfer installed no
/// download sink, in which case the body is discarded and the transfer still
/// completes — the engine's byte accounting is unaffected.
struct SinkClientWrite<'s>(&'s mut dyn TransferSink);

impl ClientWrite for SinkClientWrite<'_> {
    fn write_header(&mut self, _data: &[u8]) -> Result<()> {
        // No header sink in this context (← a header callback that writes
        // nowhere visible for a plain FILE fetch).
        Ok(())
    }

    fn write_body(&mut self, data: &[u8]) -> Result<()> {
        self.0.write(data)
    }
}

/// A [`ClientWrite`] that discards every byte, used when the transfer installed
/// no download sink (← curl still runs the do-phase and its byte accounting even
/// when the write callback has nowhere to go — e.g. `-o /dev/null`-style sinks).
/// Keeping the download path uniform (always driven through a `ClientWrite`)
/// mirrors `file_do`, which always calls `Curl_client_write` regardless of the
/// user's output configuration.
struct DiscardClientWrite;

impl ClientWrite for DiscardClientWrite {
    fn write_header(&mut self, _data: &[u8]) -> Result<()> {
        Ok(())
    }

    fn write_body(&mut self, _data: &[u8]) -> Result<()> {
        Ok(())
    }
}

impl Protocol for FileProtocol {
    /// Prepare FILE state before the transfer (← `file_setup_connection`, which
    /// merely allocates the `FILEPROTO` scratch struct). Nothing to do here
    /// until the transfer context carries that state.
    fn setup_connection<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, ()> {
        let _ = ctx;
        Box::pin(async { Ok(()) })
    }

    /// "Connect" to the file (← `file_connect`). FILE emulates a connect phase
    /// that resolves and opens the path; it completes in a single shot (curl
    /// sets `*done = TRUE`), so this reports the connect as finished. The path
    /// resolution and open are performed by [`resolve_url_path`] / [`download`]
    /// once the context supplies the URL.
    fn connect<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(async { Ok(true) })
    }

    /// The DO phase (← `file_do`): read for a download or write for an upload.
    /// curl performs the entire FILE do-phase in one call (`*done = TRUE`,
    /// unconditionally), because file descriptors cannot be `select()`-ed like
    /// sockets; this reports the DO phase as complete once the transfer is done.
    ///
    /// The URL path ([`TransferCtx::request`]'s `path`) is resolved to a local
    /// filesystem path by [`resolve_url_path`], then the direction is chosen
    /// from [`TransferRequest::upload`](crate::protocols::TransferRequest::upload):
    ///
    /// * **Upload** — the request body ([`TransferRequest::body`](crate::protocols::TransferRequest::body))
    ///   is written to the destination by [`upload`], honoring
    ///   [`resume_from`](crate::protocols::TransferRequest::resume_from) for the
    ///   append-vs-truncate decision (← `file_upload`).
    /// * **Download** — the file is streamed to the download sink
    ///   ([`TransferCtx::sink`]) by [`download`], honoring `no_body`, the
    ///   resume/range offsets, and the time condition (← `file_do`).
    ///
    /// # Errors
    ///
    /// Propagates the errors of [`resolve_url_path`], [`download`], and
    /// [`upload`] (e.g. [`CurlCode::UrlMalformat`], [`CurlCode::FileCouldntReadFile`],
    /// [`CurlCode::WriteError`]) with the frozen curl codes intact.
    fn do_it<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        Box::pin(async move {
            // Resolve the URL path to a local filesystem path (← file_connect's
            // curlx_open target derivation). Owned `PathBuf`, so the immutable
            // borrow of `ctx.request` ends before the sink borrow below.
            let path = resolve_url_path(&ctx.request.path)?;

            if ctx.request.upload {
                // ── Upload branch (← file_upload). The payload is the in-memory
                // request body; its length is the known upload size.
                let up_req = UploadRequest {
                    resume_from: ctx.request.resume_from,
                    infilesize: ctx.request.body.as_ref().map_or(-1, |b| b.len() as i64),
                    new_file_perms: DEFAULT_NEW_FILE_PERMS,
                };
                // `&[u8]` implements `AsyncRead`; an absent body is an empty
                // source (a zero-byte upload, exactly as curl would send).
                let mut source: &[u8] = ctx.request.body.as_deref().unwrap_or(&[]);
                upload(&path, &mut source, &up_req).await?;
            } else {
                // ── Download branch (← file_do). Map the request options to the
                // engine's inputs; `resume_from`/`maxdownload` are the values
                // curl's `Curl_range` computes at the transfer layer.
                let dl_req = DownloadRequest {
                    no_body: ctx.request.no_body,
                    range_requested: ctx.request.range.is_some(),
                    resume_from: ctx.request.resume_from,
                    maxdownload: ctx.request.maxdownload,
                    timecondition: TimeCond::from_raw(ctx.request.time_condition),
                    timevalue: ctx.request.time_value,
                };
                // Adapt the transfer's body sink to the engine's `ClientWrite`:
                // body bytes go to the sink; the synthesized headers curl routes
                // to `CLIENTWRITE_HEADER` have no header sink here and are
                // dropped (a plain `file://` fetch shows only the body). The
                // `Option` is unwrapped to a bare `&mut dyn TransferSink` *before*
                // the adapter is built so the trait-object lifetime shortens to
                // the borrow (an `Option<&mut dyn …>` field would force the
                // pointee `'static` under `&mut`'s invariance). A missing sink
                // still runs the full do-phase through a discarding writer,
                // exactly as `file_do` always calls the client-write path.
                match ctx.sink.as_deref_mut() {
                    Some(s) => {
                        let mut sink = SinkClientWrite(s);
                        download(&path, &mut sink, &dl_req).await?;
                    }
                    None => {
                        let mut sink = DiscardClientWrite;
                        download(&path, &mut sink, &dl_req).await?;
                    }
                }
            }
            Ok(true)
        })
    }

    /// Tear down a completed (or, if `premature`, aborted) FILE transfer
    /// (← `file_done`, which closes the descriptor and frees the path). Local
    /// I/O owns nothing beyond the open file, which is dropped with the
    /// transfer state, so there is nothing to do here.
    fn done<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        status: Result<()>,
        premature: bool,
    ) -> ProtoFuture<'a, ()> {
        let _ = (ctx, status, premature);
        Box::pin(async { Ok(()) })
    }

    /// Disconnect (← `file_disconnect`, which simply calls `file_done`). No
    /// network connection exists, so this is a no-op.
    fn disconnect<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        dead_connection: bool,
    ) -> ProtoFuture<'a, ()> {
        let _ = (ctx, dead_connection);
        Box::pin(async { Ok(()) })
    }
}

/// The `file:` protocol handler singleton (← `Curl_protocol_file`).
///
/// [`crate::protocols`]'s scheme table points its `file` entry at this static
/// via `&file::HANDLER`, coercing it to `&'static dyn Protocol`.
pub static HANDLER: FileProtocol = FileProtocol;

// ===========================================================================
// Tests — behavioral parity checks for the FILE engine and handler.
//
// These exercise the free-function engine (URL→path resolution, time
// condition, the Last-Modified calendar math, download, upload) and the
// `Protocol` handler singleton against `lib/file.c` behavior. They use only
// `std` + `tokio` (a self-cleaning std-only temp directory, no external
// test-only crate), so they build wherever the crate does.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    // ---- test scaffolding -------------------------------------------------

    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    /// A self-cleaning unique temporary directory built with `std` only, so
    /// these tests need no external test-only dependency. Removed on drop.
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let mut p = std::env::temp_dir();
            p.push(format!(
                "blitzy_adhoc_test_file_rs_{tag}_{}_{nanos}_{seq}",
                std::process::id()
            ));
            std::fs::create_dir_all(&p).expect("create temp dir");
            TmpDir(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A [`ClientWrite`] sink that records header and body bytes separately.
    #[derive(Default)]
    struct VecSink {
        headers: Vec<u8>,
        body: Vec<u8>,
    }

    impl ClientWrite for VecSink {
        fn write_header(&mut self, data: &[u8]) -> Result<()> {
            self.headers.extend_from_slice(data);
            Ok(())
        }
        fn write_body(&mut self, data: &[u8]) -> Result<()> {
            self.body.extend_from_slice(data);
            Ok(())
        }
    }

    /// A sink that always fails, proving a write-callback error surfaces as
    /// [`CurlCode::WriteError`].
    struct FailingSink;

    impl ClientWrite for FailingSink {
        fn write_header(&mut self, _: &[u8]) -> Result<()> {
            Err(Error::from(CurlCode::WriteError))
        }
        fn write_body(&mut self, _: &[u8]) -> Result<()> {
            Err(Error::from(CurlCode::WriteError))
        }
    }

    /// A shared-buffer [`TransferSink`] (the transfer-layer download sink, as
    /// opposed to the engine-facing [`ClientWrite`]) that records every chunk
    /// the handler streams, so a test can assert what reached the download (←
    /// the bytes curl would hand to `CURLOPT_WRITEFUNCTION`). Installed into
    /// [`TransferCtx::sink`] to drive the handler end-to-end.
    struct RecordingSink(Arc<Mutex<Vec<u8>>>);

    impl TransferSink for RecordingSink {
        fn write(&mut self, data: &[u8]) -> Result<()> {
            self.0.lock().expect("sink lock").extend_from_slice(data);
            Ok(())
        }
    }

    /// Build a [`TransferCtx`] whose request path points at `path`, matching how
    /// curl's URL parser hands `file_do` the (percent-decoded) local path.
    fn ctx_for(path: &Path) -> TransferCtx {
        let mut ctx = TransferCtx::new();
        ctx.request.path = path.to_str().expect("utf-8 temp path").to_string();
        ctx
    }

    // ---- constants & TimeCond --------------------------------------------

    #[test]
    fn constants_match_curl_defaults() {
        assert_eq!(CURL_MAX_WRITE_SIZE, 16_384);
        assert_eq!(UPLOAD_BUFFER_SIZE, 65_536);
        assert_eq!(DEFAULT_NEW_FILE_PERMS, 0o644);
    }

    #[test]
    fn timecond_discriminants_are_abi_stable() {
        assert_eq!(TimeCond::None as i64, 0);
        assert_eq!(TimeCond::IfModifiedSince as i64, 1);
        assert_eq!(TimeCond::IfUnmodifiedSince as i64, 2);
        assert_eq!(TimeCond::LastModified as i64, 3);
        assert_eq!(TimeCond::default(), TimeCond::None);
    }

    // ---- URL → path resolution -------------------------------------------

    #[test]
    fn hex_value_decodes_ascii_hex() {
        assert_eq!(hex_value(b'0'), Some(0));
        assert_eq!(hex_value(b'9'), Some(9));
        assert_eq!(hex_value(b'a'), Some(10));
        assert_eq!(hex_value(b'f'), Some(15));
        assert_eq!(hex_value(b'A'), Some(10));
        assert_eq!(hex_value(b'F'), Some(15));
        assert_eq!(hex_value(b'g'), None);
        assert_eq!(hex_value(b'/'), None);
    }

    #[test]
    fn urldecode_decodes_valid_escapes() {
        assert_eq!(urldecode_reject_zero("%41").unwrap(), b"A");
        assert_eq!(urldecode_reject_zero("a%20b").unwrap(), b"a b");
        assert_eq!(urldecode_reject_zero("%2f").unwrap(), b"/");
        assert_eq!(urldecode_reject_zero("plain").unwrap(), b"plain");
    }

    #[test]
    fn urldecode_passes_through_stray_percent() {
        // A '%' not followed by two hex digits is literal, exactly as curl.
        assert_eq!(urldecode_reject_zero("%").unwrap(), b"%");
        assert_eq!(urldecode_reject_zero("%2").unwrap(), b"%2");
        assert_eq!(urldecode_reject_zero("%gg").unwrap(), b"%gg");
        assert_eq!(urldecode_reject_zero("50%").unwrap(), b"50%");
    }

    #[test]
    fn urldecode_rejects_zero_byte() {
        let err = urldecode_reject_zero("a%00b").unwrap_err();
        assert_eq!(err.code(), CurlCode::UrlMalformat);
    }

    #[test]
    fn resolve_url_path_decodes_and_builds_path() {
        assert_eq!(
            resolve_url_path("/tmp/foo").unwrap(),
            PathBuf::from("/tmp/foo")
        );
        assert_eq!(
            resolve_url_path("/tmp/a%20b").unwrap(),
            PathBuf::from("/tmp/a b")
        );
        assert_eq!(resolve_url_path("/a%2Fb").unwrap(), PathBuf::from("/a/b"));
    }

    #[test]
    fn resolve_url_path_rejects_nul() {
        assert_eq!(
            resolve_url_path("/a%00b").unwrap_err().code(),
            CurlCode::UrlMalformat
        );
    }

    #[test]
    fn file_url_to_path_handles_authority_variants() {
        let want = PathBuf::from("/tmp/x");
        // Empty authority (`file:///path`).
        assert_eq!(file_url_to_path("file:///tmp/x").unwrap(), want);
        // `localhost` authority.
        assert_eq!(file_url_to_path("file://localhost/tmp/x").unwrap(), want);
        // Arbitrary host authority (ignored for a local file, per RFC 1738).
        assert_eq!(file_url_to_path("file://somehost/tmp/x").unwrap(), want);
        // No authority marker (`file:/path`).
        assert_eq!(file_url_to_path("file:/tmp/x").unwrap(), want);
        // Bare path, no scheme.
        assert_eq!(file_url_to_path("/tmp/x").unwrap(), want);
        // Case-insensitive scheme.
        assert_eq!(file_url_to_path("FILE:///tmp/x").unwrap(), want);
    }

    #[test]
    fn file_url_to_path_decodes_and_rejects_nul() {
        assert_eq!(
            file_url_to_path("file:///tmp/a%20b").unwrap(),
            PathBuf::from("/tmp/a b")
        );
        assert_eq!(
            file_url_to_path("file:///a%00b").unwrap_err().code(),
            CurlCode::UrlMalformat
        );
    }

    // ---- time condition ---------------------------------------------------

    #[test]
    fn meets_timecondition_zero_times_are_always_met() {
        assert!(meets_timecondition(0, 100, TimeCond::IfModifiedSince));
        assert!(meets_timecondition(100, 0, TimeCond::IfModifiedSince));
        assert!(meets_timecondition(0, 0, TimeCond::IfUnmodifiedSince));
    }

    #[test]
    fn meets_timecondition_if_modified_since() {
        // Met when the file is newer than the reference.
        assert!(meets_timecondition(200, 100, TimeCond::IfModifiedSince));
        assert!(!meets_timecondition(100, 200, TimeCond::IfModifiedSince));
        // Equal timestamps are NOT met (curl uses `<=`).
        assert!(!meets_timecondition(100, 100, TimeCond::IfModifiedSince));
        // LASTMOD folds into the same comparison as IFMODSINCE.
        assert!(meets_timecondition(200, 100, TimeCond::LastModified));
        assert!(!meets_timecondition(100, 100, TimeCond::LastModified));
    }

    #[test]
    fn meets_timecondition_if_unmodified_since() {
        // Met when the file is older than the reference.
        assert!(meets_timecondition(100, 200, TimeCond::IfUnmodifiedSince));
        assert!(!meets_timecondition(200, 100, TimeCond::IfUnmodifiedSince));
        // Equal timestamps are NOT met (curl uses `>=`).
        assert!(!meets_timecondition(100, 100, TimeCond::IfUnmodifiedSince));
    }

    // ---- gmtime / Last-Modified ------------------------------------------

    #[test]
    fn last_modified_matches_reference_dates() {
        let cases: &[(i64, &str)] = &[
            (0, "Last-Modified: Thu, 01 Jan 1970 00:00:00 GMT\r\n"),
            (
                784_903_526,
                "Last-Modified: Tue, 15 Nov 1994 12:45:26 GMT\r\n",
            ),
            (
                1_000_000_000,
                "Last-Modified: Sun, 09 Sep 2001 01:46:40 GMT\r\n",
            ),
            (
                1_700_000_000,
                "Last-Modified: Tue, 14 Nov 2023 22:13:20 GMT\r\n",
            ),
            // Leap day.
            (
                951_782_400,
                "Last-Modified: Tue, 29 Feb 2000 00:00:00 GMT\r\n",
            ),
        ];
        for (secs, want) in cases {
            assert_eq!(&format_last_modified(&gmtime(*secs)), want, "secs={secs}");
        }
    }

    #[test]
    fn gmtime_fields_are_correct_for_epoch() {
        let tm = gmtime(0);
        assert_eq!(tm.year, 1970);
        assert_eq!(tm.mon, 0); // January (zero-based)
        assert_eq!(tm.mday, 1);
        assert_eq!(tm.hour, 0);
        assert_eq!(tm.min, 0);
        assert_eq!(tm.sec, 0);
        assert_eq!(tm.wday, 4); // Thursday (Sunday = 0)
    }

    #[test]
    fn systemtime_to_unix_secs_roundtrips() {
        assert_eq!(systemtime_to_unix_secs(UNIX_EPOCH), 0);
        assert_eq!(
            systemtime_to_unix_secs(UNIX_EPOCH + Duration::from_secs(784_903_526)),
            784_903_526
        );
    }

    // ---- download ---------------------------------------------------------

    #[tokio::test]
    async fn download_reads_whole_file() {
        let dir = TmpDir::new("dl_whole");
        let path = dir.join("data.txt");
        std::fs::write(&path, b"hello world").unwrap();

        let mut sink = VecSink::default();
        let out = download(&path, &mut sink, &DownloadRequest::default())
            .await
            .unwrap();

        assert_eq!(sink.body, b"hello world");
        assert_eq!(out.body_bytes, 11);
        assert_eq!(out.size, Some(11));
        assert!(out.filetime.is_some());
        assert!(!out.timecondition_unmet);

        let headers = String::from_utf8(sink.headers).unwrap();
        assert!(headers.contains("Content-Length: 11\r\n"));
        assert!(headers.contains("Accept-ranges: bytes\r\n"));
        assert!(headers.contains("Last-Modified: "));
        assert!(headers.ends_with("\r\n\r\n"));
        // The synthesized Last-Modified reflects the file's real mtime, routed
        // through the same gmtime/format path the unit tests pin above.
        let mtime = systemtime_to_unix_secs(std::fs::metadata(&path).unwrap().modified().unwrap());
        assert!(headers.contains(&format_last_modified(&gmtime(mtime))));
    }

    #[tokio::test]
    async fn download_no_body_emits_headers_only() {
        let dir = TmpDir::new("dl_nobody");
        let path = dir.join("data.txt");
        std::fs::write(&path, b"hello world").unwrap();

        let mut sink = VecSink::default();
        let req = DownloadRequest {
            no_body: true,
            ..DownloadRequest::default()
        };
        let out = download(&path, &mut sink, &req).await.unwrap();

        assert!(sink.body.is_empty());
        assert_eq!(out.body_bytes, 0);
        assert_eq!(out.size, Some(11));
        assert!(!sink.headers.is_empty());
    }

    #[tokio::test]
    async fn download_resume_from_seeks() {
        let dir = TmpDir::new("dl_resume");
        let path = dir.join("d");
        std::fs::write(&path, b"0123456789").unwrap();

        let mut sink = VecSink::default();
        let req = DownloadRequest {
            resume_from: 3,
            ..DownloadRequest::default()
        };
        let out = download(&path, &mut sink, &req).await.unwrap();

        assert_eq!(sink.body, b"3456789");
        assert_eq!(out.body_bytes, 7);
        assert_eq!(out.size, Some(7));
    }

    #[tokio::test]
    async fn download_negative_resume_counts_from_end() {
        let dir = TmpDir::new("dl_neg");
        let path = dir.join("d");
        std::fs::write(&path, b"0123456789").unwrap();

        let mut sink = VecSink::default();
        let req = DownloadRequest {
            resume_from: -4,
            ..DownloadRequest::default()
        };
        let out = download(&path, &mut sink, &req).await.unwrap();

        assert_eq!(sink.body, b"6789");
        assert_eq!(out.size, Some(4));
    }

    #[tokio::test]
    async fn download_resume_beyond_size_is_bad_resume() {
        let dir = TmpDir::new("dl_badresume");
        let path = dir.join("d");
        std::fs::write(&path, b"01234").unwrap();

        let mut sink = VecSink::default();
        let req = DownloadRequest {
            resume_from: 10,
            ..DownloadRequest::default()
        };
        let err = download(&path, &mut sink, &req).await.unwrap_err();
        assert_eq!(err.code(), CurlCode::BadDownloadResume);
    }

    #[tokio::test]
    async fn download_maxdownload_caps_transfer() {
        let dir = TmpDir::new("dl_max");
        let path = dir.join("d");
        std::fs::write(&path, b"0123456789").unwrap();

        let mut sink = VecSink::default();
        let req = DownloadRequest {
            maxdownload: 4,
            ..DownloadRequest::default()
        };
        let out = download(&path, &mut sink, &req).await.unwrap();

        assert_eq!(sink.body, b"0123");
        assert_eq!(out.body_bytes, 4);
        assert_eq!(out.size, Some(4));
    }

    #[tokio::test]
    async fn download_missing_file_is_couldnt_read() {
        let dir = TmpDir::new("dl_missing");
        let path = dir.join("does_not_exist");
        let mut sink = VecSink::default();
        let err = download(&path, &mut sink, &DownloadRequest::default())
            .await
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::FileCouldntReadFile);
    }

    #[tokio::test]
    async fn download_timecondition_unmet_moves_no_data() {
        let dir = TmpDir::new("dl_tc_unmet");
        let path = dir.join("d");
        std::fs::write(&path, b"data").unwrap();

        let mut sink = VecSink::default();
        // Reference time far in the future → file is not newer → condition unmet.
        let req = DownloadRequest {
            timecondition: TimeCond::IfModifiedSince,
            timevalue: 9_000_000_000,
            ..DownloadRequest::default()
        };
        let out = download(&path, &mut sink, &req).await.unwrap();

        assert!(out.timecondition_unmet);
        assert_eq!(out.body_bytes, 0);
        assert_eq!(out.size, None);
        assert!(sink.body.is_empty());
        // The early-out returns before any header is synthesized.
        assert!(sink.headers.is_empty());
    }

    #[tokio::test]
    async fn download_timecondition_met_transfers() {
        let dir = TmpDir::new("dl_tc_met");
        let path = dir.join("d");
        std::fs::write(&path, b"data").unwrap();

        let mut sink = VecSink::default();
        let req = DownloadRequest {
            timecondition: TimeCond::IfModifiedSince,
            timevalue: 1,
            ..DownloadRequest::default()
        };
        let out = download(&path, &mut sink, &req).await.unwrap();

        assert!(!out.timecondition_unmet);
        assert_eq!(sink.body, b"data");
        assert_eq!(out.body_bytes, 4);
    }

    #[tokio::test]
    async fn download_directory_lists_non_dot_entries() {
        let dir = TmpDir::new("dl_dir");
        std::fs::write(dir.join("alpha"), b"x").unwrap();
        std::fs::write(dir.join("beta"), b"y").unwrap();
        std::fs::write(dir.join(".hidden"), b"z").unwrap();

        let mut sink = VecSink::default();
        let out = download(dir.path(), &mut sink, &DownloadRequest::default())
            .await
            .unwrap();

        let body = String::from_utf8(sink.body).unwrap();
        assert!(body.contains("alpha\n"));
        assert!(body.contains("beta\n"));
        assert!(!body.contains(".hidden"));
        // "alpha\n" (6) + "beta\n" (5); dot-entry skipped.
        assert_eq!(out.body_bytes, 11);
        // A directory has no Content-Length-equivalent size.
        assert_eq!(out.size, None);

        let headers = String::from_utf8(sink.headers).unwrap();
        assert!(headers.contains("Last-Modified: "));
        assert!(!headers.contains("Content-Length"));
    }

    #[tokio::test]
    async fn download_write_error_propagates() {
        let dir = TmpDir::new("dl_werr");
        let path = dir.join("d");
        std::fs::write(&path, b"data").unwrap();

        let mut sink = FailingSink;
        let err = download(&path, &mut sink, &DownloadRequest::default())
            .await
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::WriteError);
    }

    // ---- upload -----------------------------------------------------------

    #[tokio::test]
    async fn upload_creates_and_writes() {
        let dir = TmpDir::new("up_create");
        let path = dir.join("out.bin");

        let mut src: &[u8] = b"payload";
        let out = upload(&path, &mut src, &UploadRequest::default())
            .await
            .unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"payload");
        assert_eq!(out.uploaded_bytes, 7);
        assert_eq!(out.upload_size, None);
    }

    #[tokio::test]
    async fn upload_truncates_existing() {
        let dir = TmpDir::new("up_trunc");
        let path = dir.join("out.bin");
        std::fs::write(&path, b"OLDLONGCONTENT").unwrap();

        let mut src: &[u8] = b"new";
        let out = upload(&path, &mut src, &UploadRequest::default())
            .await
            .unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(out.uploaded_bytes, 3);
    }

    #[tokio::test]
    async fn upload_appends_and_skips_resume_bytes() {
        let dir = TmpDir::new("up_append");
        let path = dir.join("out.bin");
        std::fs::write(&path, b"AAAA").unwrap();

        // resume_from != 0 opens for append and skips that many input bytes.
        let mut src: &[u8] = b"XXYY";
        let req = UploadRequest {
            resume_from: 2,
            ..UploadRequest::default()
        };
        let out = upload(&path, &mut src, &req).await.unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"AAAAYY");
        assert_eq!(out.uploaded_bytes, 2);
    }

    #[tokio::test]
    async fn upload_negative_resume_resolves_to_file_size() {
        let dir = TmpDir::new("up_neg");
        let path = dir.join("out.bin");
        std::fs::write(&path, b"ABCDE").unwrap();

        // A negative resume resolves to the current file size (5), so the first
        // five input bytes are skipped and the remainder appended.
        let mut src: &[u8] = b"HELLOWORLD";
        let req = UploadRequest {
            resume_from: -1,
            ..UploadRequest::default()
        };
        let out = upload(&path, &mut src, &req).await.unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"ABCDEWORLD");
        assert_eq!(out.uploaded_bytes, 5);
    }

    #[tokio::test]
    async fn upload_reports_infilesize() {
        let dir = TmpDir::new("up_size");
        let path = dir.join("out.bin");

        let mut src: &[u8] = b"hi";
        let req = UploadRequest {
            infilesize: 42,
            ..UploadRequest::default()
        };
        let out = upload(&path, &mut src, &req).await.unwrap();

        assert_eq!(out.upload_size, Some(42));
        assert_eq!(out.uploaded_bytes, 2);
    }

    #[tokio::test]
    async fn upload_open_failure_is_write_error() {
        let dir = TmpDir::new("up_fail");
        // The parent directory does not exist → create() cannot make it.
        let path = dir.join("no_such_dir").join("out.bin");

        let mut src: &[u8] = b"x";
        let err = upload(&path, &mut src, &UploadRequest::default())
            .await
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::WriteError);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn upload_applies_new_file_perms() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TmpDir::new("up_perms");
        let path = dir.join("out.bin");

        let mut src: &[u8] = b"x";
        let req = UploadRequest {
            new_file_perms: 0o644,
            ..UploadRequest::default()
        };
        upload(&path, &mut src, &req).await.unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        // A umask can only clear bits, so no bit outside 0o644 may be set.
        assert_eq!(mode & !0o644, 0, "unexpected perm bits: {mode:o}");
    }

    // ---- protocol handler -------------------------------------------------

    #[test]
    fn handler_is_object_safe() {
        // Coercion to a trait object proves `Protocol` is object-safe and that
        // `HANDLER` is the exported singleton the scheme table references.
        let h: &dyn Protocol = &HANDLER;
        let _ = h;
    }

    #[tokio::test]
    async fn handler_phase_methods_complete() {
        // Every lifecycle phase runs against a real file so the wired DO phase
        // (← `file_do`) performs an actual transfer, not the former no-op. FILE
        // completes connect and DO in a single shot (curl's `*done = TRUE`).
        let dir = TmpDir::new("handler_phases");
        let path = dir.join("data.txt");
        std::fs::write(&path, b"body bytes").unwrap();

        let h: &dyn Protocol = &HANDLER;
        let collected = Arc::new(Mutex::new(Vec::new()));
        let mut ctx = ctx_for(&path);
        ctx.sink = Some(Box::new(RecordingSink(Arc::clone(&collected))));

        h.setup_connection(&mut ctx).await.unwrap();
        assert!(h.connect(&mut ctx).await.unwrap());
        assert!(h.do_it(&mut ctx).await.unwrap());
        h.done(&mut ctx, Ok(()), false).await.unwrap();
        h.disconnect(&mut ctx, false).await.unwrap();

        assert_eq!(
            collected.lock().unwrap().as_slice(),
            b"body bytes",
            "the wired DO phase streams the file body to the download sink"
        );
    }

    #[tokio::test]
    async fn handler_do_it_downloads_file_to_sink() {
        // The DO phase resolves the request path, opens the file, and streams
        // its bytes to the transfer's download sink (← `file_do` read loop).
        let dir = TmpDir::new("handler_dl");
        let path = dir.join("payload.bin");
        std::fs::write(&path, b"the quick brown fox").unwrap();

        let collected = Arc::new(Mutex::new(Vec::new()));
        let mut ctx = ctx_for(&path);
        ctx.sink = Some(Box::new(RecordingSink(Arc::clone(&collected))));

        let done = HANDLER.do_it(&mut ctx).await.expect("do_it downloads");
        assert!(done, "FILE do_it reports the DO phase complete in one step");
        assert_eq!(collected.lock().unwrap().as_slice(), b"the quick brown fox");
    }

    #[tokio::test]
    async fn handler_do_it_download_without_sink_still_succeeds() {
        // curl's `file_do` always drives the client-write path; with no download
        // sink installed the body is discarded but the DO phase still completes
        // successfully (the discarding-writer branch, not an early error).
        let dir = TmpDir::new("handler_dl_nosink");
        let path = dir.join("payload.bin");
        std::fs::write(&path, b"discarded").unwrap();

        let mut ctx = ctx_for(&path);
        // No sink installed.
        let done = HANDLER
            .do_it(&mut ctx)
            .await
            .expect("do_it completes with no sink");
        assert!(done);
    }

    #[tokio::test]
    async fn handler_do_it_no_body_streams_nothing() {
        // `-I`/`CURLOPT_NOBODY` (← `data->req.no_body`) emits headers only; the
        // body sink must receive zero bytes while the DO phase still completes.
        let dir = TmpDir::new("handler_nobody");
        let path = dir.join("data.txt");
        std::fs::write(&path, b"unseen body").unwrap();

        let collected = Arc::new(Mutex::new(Vec::new()));
        let mut ctx = ctx_for(&path);
        ctx.request.no_body = true;
        ctx.sink = Some(Box::new(RecordingSink(Arc::clone(&collected))));

        assert!(HANDLER.do_it(&mut ctx).await.expect("do_it ok"));
        assert!(
            collected.lock().unwrap().is_empty(),
            "no_body suppresses body delivery to the sink"
        );
    }

    #[tokio::test]
    async fn handler_do_it_uploads_body_to_file() {
        // The upload direction (← `file_upload`) writes the request body to the
        // destination path; a truncating (non-resume) write replaces contents.
        let dir = TmpDir::new("handler_up");
        let path = dir.join("dest.bin");

        let mut ctx = ctx_for(&path);
        ctx.request.upload = true;
        ctx.request.body = Some(b"uploaded payload".to_vec());

        assert!(HANDLER.do_it(&mut ctx).await.expect("do_it uploads"));
        assert_eq!(std::fs::read(&path).unwrap(), b"uploaded payload");
    }

    #[tokio::test]
    async fn handler_do_it_missing_file_surfaces_curl_code() {
        // A download of a nonexistent path surfaces curl's frozen
        // `CURLE_FILE_COULDNT_READ_FILE` rather than succeeding silently.
        let dir = TmpDir::new("handler_missing");
        let path = dir.join("nope");
        let mut ctx = ctx_for(&path);
        let err = HANDLER.do_it(&mut ctx).await.unwrap_err();
        assert_eq!(err.code(), CurlCode::FileCouldntReadFile);
    }
}
