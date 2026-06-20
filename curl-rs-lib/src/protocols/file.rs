//! FILE protocol engine — the Rust analog of `lib/file.c` (+ `lib/fileinfo.c`).
//!
//! `file://` is the **only** curl scheme that carries
//! [`PROTOPT_NONETWORK`](super::PROTOPT_NONETWORK): it moves no bytes over a
//! socket. Where every other protocol drives [`crate::conn`]'s connection /
//! filter chain, FILE reads and writes the **local filesystem** directly — here
//! via asynchronous [`tokio::fs`] I/O — so this module deliberately imports
//! none of `crate::conn`'s send/recv verbs for its data path. The transfer is
//! performed entirely in the do-phase, exactly as curl's `file_do` does (curl
//! does the whole operation up front because `select()`/`recv()` cannot be used
//! on a plain file descriptor on every platform it supports).
//!
//! The C source (`lib/file.c`) is treated strictly as a **behavioral / ABI
//! oracle** — its observable effects are reproduced (the synthetic
//! `Content-Length` / `Accept-ranges` / `Last-Modified` response headers, RANGE
//! and resume handling, the directory listing, the `--remote-time` modification
//! time, and the exact error mapping), not transliterated line by line.
//!
//! # Scheme descriptor
//!
//! [`SCHEME_FILE`] (defined centrally in [`crate::protocols`]) reproduces
//! `const struct Curl_scheme Curl_scheme_file`: protocol/family
//! [`CURLPROTO_FILE`](super::CURLPROTO_FILE), flags
//! `PROTOPT_NONETWORK | PROTOPT_NOURLQUERY`, default port `0`.
//!
//! # `Protocol` mapping (C `Curl_protocol_file`)
//!
//! The C vtable wires only `setup_connection`, `connect_it` (`file_connect`),
//! `do_it` (`file_do`), `done` (`file_done`), and `disconnect`
//! (`file_disconnect`); everything else is `ZERO_NULL`. This module mirrors that
//! exactly:
//!
//! * [`FileProtocol::setup_connection`] — no-op success (curl allocates a
//!   `FILEPROTO` here; the Rust state is built in `connect`).
//! * [`FileProtocol::connect`] — decode the URL path to a local path
//!   ([`decode_file_url_path`]) and, for a download, open the file early so a
//!   missing/unreadable file fails with [`CurlError::FileCouldntReadFile`]
//!   exactly as `file_connect` does. The decoded path is parked on the
//!   [`Connection`] as protocol state.
//! * [`FileProtocol::do_it`] — return the [`ProtocolTransfer`] descriptor
//!   (download size or upload direction).
//! * [`FileProtocol::done`] / [`FileProtocol::disconnect`] — drop the parked
//!   state (Rust `Drop` closes any handle; FILE has no real connection).
//!
//! The actual byte movement lives in the engine-facing
//! [`FileProtocol::run_download`] / [`FileProtocol::run_upload`] methods (the
//! analogs of `file_do`'s download and `file_upload`), which take the
//! [`ClientWriter`] chain and the user's [`WriteCallbacks`] just like the other
//! protocol handlers (cf. `protocols::mqtt`). Those, and the standalone helpers
//! they call, are pure async Rust with no raw pointers.
//!
//! # Memory safety
//!
//! This subtree inherits `#![forbid(unsafe_code)]` from [`crate::protocols`]; it
//! is intentionally **not** re-declared here. All file I/O is safe `tokio::fs`.

use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::conn::{BoxFuture, Connection};
use crate::easy::Easy;
use crate::error::{CurlError, Result};
use crate::escape::{urldecode, UrlReject};
use crate::protocols::{Protocol, ProtocolTransfer, Scheme, TransferDirection, SCHEME_FILE};
use crate::setopt::{HttpReq, StrId};
use crate::transfer::{
    uc_to_curlcode, ClientWriteType, ClientWriter, ReadCallback, ReadStep, UploadReader,
    WriteCallbacks,
};
use crate::url::{CurlUPart, CurlUrl, CURLU_GUESS_SCHEME};
use crate::util::parsedate::{CURL_MONTH, CURL_WKDAY};
use crate::util::sendf::{failf, infof};
use crate::util::timeval::curlx_gmtime;

use chrono::{Datelike, Timelike};

// ===========================================================================
// Time-condition constants (`curl_TimeCond`, include/curl/curl.h)
// ===========================================================================

/// `CURL_TIMECOND_NONE` — no time condition (the disabled state).
const CURL_TIMECOND_NONE: u8 = 0;
/// `CURL_TIMECOND_IFMODSINCE` — fetch only if newer than `timevalue`.
const CURL_TIMECOND_IFMODSINCE: u8 = 1;
/// `CURL_TIMECOND_IFUNMODSINCE` — fetch only if not newer than `timevalue`.
const CURL_TIMECOND_IFUNMODSINCE: u8 = 2;

/// The scratch read/write buffer size for the body loops. curl borrows a
/// multi-transfer buffer (`Curl_multi_xfer_buf_borrow`, default 256 KiB minus a
/// guard byte); the exact size is not observable in the produced bytes (it only
/// affects chunk boundaries), so a fixed 64 KiB buffer is used here.
const FILE_XFER_BUF: usize = 64 * 1024;

// ===========================================================================
// URL → local path decoding (C `file_connect` path handling)
// ===========================================================================

/// Decode a `file://` URL path component to a local filesystem [`PathBuf`],
/// reproducing curl's `file_connect` path handling.
///
/// `encoded` is the URL-encoded path as produced by the URL parser (curl's
/// `data->state.up.path`). The host is intentionally **not** consulted: per
/// RFC 1738 curl ignores the hostname for `file://`, so `file://localhost/x`,
/// `file:///x`, and `file://anything/x` all resolve to the same local path
/// `/x`. The URL layer already excludes the authority from the path component,
/// so this function only has to decode the path.
///
/// The decoding is curl's `Curl_urldecode(..., REJECT_ZERO)`
/// ([`urldecode`] with [`UrlReject::Zero`]): `%XX` escapes are decoded, a
/// decoded NUL byte is rejected as [`CurlError::UrlMalformat`] (a NUL in a path
/// "indicates foul play"), and malformed escapes are preserved verbatim. For
/// example `file:///tmp/a%20b.txt` decodes to the local path `/tmp/a b.txt`.
///
/// On Windows / DOS filesystems the extra normalization `file_connect` performs
/// is reproduced (see [`normalize_dos_path`]): a leading `/X:` or `/X|` drive
/// spec has its slash stripped and `|` mapped to `:`, and `/` separators are
/// mapped to `\`.
///
/// # Errors
///
/// [`CurlError::UrlMalformat`] if the decoded path contains a NUL byte (or, on
/// Windows, if it is not valid UTF-8 after decoding).
pub fn decode_file_url_path(encoded: &str) -> Result<PathBuf> {
    // curl: Curl_urldecode(path, 0, &real_path, &len, REJECT_ZERO).
    let decoded = urldecode(encoded.as_bytes(), UrlReject::Zero)?;

    #[cfg(windows)]
    {
        // On Windows the decoded path must be valid UTF-8 to apply the
        // drive-letter normalization and build an OS path from it.
        let text = String::from_utf8(decoded).map_err(|_| CurlError::UrlMalformat)?;
        Ok(PathBuf::from(normalize_dos_path(&text)))
    }

    #[cfg(not(windows))]
    {
        // On Unix the path is an arbitrary byte string (curl operates on raw
        // bytes), so build the OsStr directly from the decoded bytes without a
        // UTF-8 round-trip — this preserves non-UTF-8 filenames exactly.
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        Ok(PathBuf::from(OsStr::from_bytes(&decoded)))
    }
}

/// Normalize a decoded `file://` path for DOS / Windows filesystems, exactly as
/// curl's `file_connect` does under `DOS_FILESYSTEM`.
///
/// 1. A leading `/X:` or `/X|` (slash, drive letter, then `:` or `|`) has the
///    leading slash removed and `|` rewritten to `:`, so `/c:/tmp` becomes
///    `c:/tmp`. Browsers behave the same way, and dropping the slash in all
///    cases would wrongly make drive-less paths relative.
/// 2. Every `/` separator is rewritten to `\`.
///
/// This helper is always compiled (so it is unit-testable on every platform)
/// but is only *called* on Windows by [`decode_file_url_path`].
#[cfg_attr(not(windows), allow(dead_code))]
fn normalize_dos_path(path: &str) -> String {
    let bytes = path.as_bytes();
    // Step 1: strip the leading slash of a `/X:` or `/X|` drive spec.
    let start = if bytes.len() >= 3
        && bytes[0] == b'/'
        && bytes[1].is_ascii_alphabetic()
        && (bytes[2] == b':' || bytes[2] == b'|')
    {
        1
    } else {
        0
    };

    // Work byte-wise like curl (it rewrites the raw `char*` in place). Only
    // ASCII bytes are ever substituted, and ASCII↔ASCII swaps on
    // originally-valid UTF-8 keep the result valid UTF-8, so multi-byte
    // filenames are preserved exactly (a UTF-8 continuation/lead byte is never
    // `/` (0x2F) or `|` (0x7C)).
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() - start);
    for (idx, &b) in bytes.iter().enumerate().skip(start) {
        let nb = match b {
            // The drive separator `|` becomes `:` (only at the drive position).
            b'|' if idx == start + 1 => b':',
            b'/' => b'\\',
            other => other,
        };
        out.push(nb);
    }
    // The conversion cannot fail (see above); fall back losslessly if it ever
    // did rather than introduce a panic path.
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

// ===========================================================================
// RANGE parsing (C `Curl_range`, lib/curl_range.c)
// ===========================================================================

/// The outcome of parsing a `--range` specification — the resume offset and the
/// maximum number of bytes to download, mirroring the two fields
/// `Curl_range` writes (`data->state.resume_from` and `data->req.maxdownload`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeOutcome {
    /// The start offset (`resume_from`). A **negative** value means "the last
    /// `-resume_from` bytes of the file" (the `-Y` form), resolved against the
    /// real file size by the caller, exactly as `file_do` does.
    pub resume_from: i64,
    /// The download byte cap (`maxdownload`); `-1` means "no cap / to end of
    /// file".
    pub maxdownload: i64,
}

/// Parse a base-10 non-negative offset at `bytes[*i..]`, advancing `*i` past the
/// consumed digits only on success. The Rust counterpart of curl's
/// `curlx_str_number` (via `str_num_base`) with `max = CURL_OFF_T_MAX`.
///
/// Returns `(true, n)` and advances `*i` when a number is parsed. Returns
/// `(false, 0)` **without advancing `*i`** in curl's two failure modes:
///
/// * `STRE_NO_NUM` — there is no leading digit; and
/// * `STRE_OVERFLOW` — the value exceeds `CURL_OFF_T_MAX`. curl's `str_num_base`
///   leaves `*nump = 0` and does **not** advance the cursor on overflow, and
///   [`parse_range`]'s caller (`Curl_range`) treats any failure the same way —
///   so an overflowing *second* number degrades to the `X-` form, while an
///   overflowing *first* number leaves the cursor on a digit and the mandatory
///   `-` check then yields [`CurlError::RangeError`]. Reproducing the
///   "no advance" behavior is what keeps both cases byte-for-byte faithful.
fn parse_off_t(bytes: &[u8], i: &mut usize) -> (bool, i64) {
    let mut j = *i;
    // STRE_NO_NUM: not positioned on a digit (cursor unchanged).
    if j >= bytes.len() || !bytes[j].is_ascii_digit() {
        return (false, 0);
    }
    let mut num: i64 = 0;
    while j < bytes.len() && bytes[j].is_ascii_digit() {
        let d = i64::from(bytes[j] - b'0');
        // STRE_OVERFLOW mirror: `num > (CURL_OFF_T_MAX - d) / 10`. curl returns
        // failure with `*nump = 0` and the cursor un-advanced; do the same.
        if num > (i64::MAX - d) / 10 {
            return (false, 0);
        }
        num = num * 10 + d;
        j += 1;
    }
    *i = j;
    (true, num)
}

/// Parse a `--range` value into a [`RangeOutcome`], faithfully reproducing
/// `Curl_range` (`lib/curl_range.c`).
///
/// The accepted forms (and their effect) are:
///
/// * `X-`   — resume from `X` to end of file: `resume_from = X`, `maxdownload = -1`.
/// * `-Y`   — the last `Y` bytes: `maxdownload = Y`, `resume_from = -Y`. `Y == 0`
///   (`-0`) is rejected as [`CurlError::RangeError`].
/// * `X-Y`  — the closed range `[X, Y]`: `maxdownload = Y - X + 1`,
///   `resume_from = X`. `X > Y` is rejected, and a span equal to
///   `i64::MAX` is rejected (it would overflow `Y - X + 1`).
///
/// Mirroring `Curl_range`, a `-` separator is **mandatory** after the optional
/// leading number: a bare `X` (no dash) is a [`CurlError::RangeError`]. As in C,
/// trailing characters after the parsed numbers are not rejected here.
///
/// # Errors
///
/// [`CurlError::RangeError`] for a malformed specification (missing `-`, `-0`,
/// an inverted `X-Y`, an overflowing number or span).
pub fn parse_range(range: &str) -> Result<RangeOutcome> {
    let bytes = range.as_bytes();
    let mut i = 0usize;

    // Optional leading number (`curlx_str_number(&p, &from, ...)`).
    let (first_num, mut from) = parse_off_t(bytes, &mut i);

    // A single '-' must follow (`curlx_str_single(&p, '-')` errors otherwise).
    if i >= bytes.len() || bytes[i] != b'-' {
        return Err(CurlError::RangeError);
    }
    i += 1;

    // Optional trailing number.
    let (have_to, to) = parse_off_t(bytes, &mut i);

    if !have_to {
        // `X-` : from the given offset to the end of the file.
        // (`from` is `0` when no leading number was given, matching the C stack
        // default for the degenerate `-` input.)
        if !first_num {
            from = 0;
        }
        Ok(RangeOutcome {
            resume_from: from,
            maxdownload: -1,
        })
    } else if !first_num {
        // `-Y` : the last `Y` bytes.
        if to == 0 {
            // "-0" is just wrong.
            return Err(CurlError::RangeError);
        }
        Ok(RangeOutcome {
            resume_from: -to,
            maxdownload: to,
        })
    } else {
        // `X-Y` : an explicit closed range.
        if from > to {
            return Err(CurlError::RangeError);
        }
        let totalsize = to - from;
        if totalsize == i64::MAX {
            // `totalsize + 1` would overflow curl_off_t.
            return Err(CurlError::RangeError);
        }
        Ok(RangeOutcome {
            resume_from: from,
            maxdownload: totalsize + 1, // include the last byte
        })
    }
}

// ===========================================================================
// Synthetic response headers + time-condition (C `file_do` header block)
// ===========================================================================

/// Format the synthetic `Last-Modified` response header line for a file
/// modification time, reproducing `file_do`'s
/// `"Last-Modified: %s, %02d %s %4d %02d:%02d:%02d GMT\r\n"`.
///
/// `filetime` is a Unix timestamp (seconds). The result includes the trailing
/// CRLF, e.g. `Last-Modified: Tue, 15 Nov 1994 12:45:26 GMT\r\n`. The weekday
/// and month use the abbreviated [`CURL_WKDAY`] / [`CURL_MONTH`] tables (the
/// same tables curl's `file_do` indexes), so the output is locale-independent
/// and byte-for-byte identical to curl.
///
/// Returns [`None`] when `filetime` is outside the range representable by
/// [`curlx_gmtime`] (curl's `file_do` bails out of the header on a `gmtime`
/// failure); the caller then simply omits the header.
#[must_use]
pub fn format_last_modified_header(filetime: i64) -> Option<Vec<u8>> {
    let dt = curlx_gmtime(filetime)?;

    // chrono's `num_days_from_monday()` yields 0=Mon..6=Sun, which indexes
    // CURL_WKDAY (= ["Mon", .., "Sun"]) directly — the same mapping curl's
    // `Curl_wkday[tm_wday ? tm_wday - 1 : 6]` produces. `month0()` yields
    // 0=Jan..11=Dec, indexing CURL_MONTH likewise.
    let wday = CURL_WKDAY[dt.weekday().num_days_from_monday() as usize];
    let mon = CURL_MONTH[dt.month0() as usize];

    // "Last-Modified: Tue, 15 Nov 1994 12:45:26 GMT\r\n"
    let line = format!(
        "Last-Modified: {}, {:02} {} {:04} {:02}:{:02}:{:02} GMT\r\n",
        wday,
        dt.day(),
        mon,
        dt.year(),
        dt.hour(),
        dt.minute(),
        dt.second(),
    );
    Some(line.into_bytes())
}

/// Whether a transfer with document time `filetime` (a Unix timestamp) meets the
/// configured time condition — the Rust analog of `Curl_meets_timecondition`
/// (`lib/transfer.c`).
///
/// Returns `true` (proceed with the transfer) when there is no usable condition
/// (`filetime == 0` or `timevalue == 0`). For
/// [`CURL_TIMECOND_IFMODSINCE`](self) (the default) the document must be newer
/// than `timevalue` (`filetime > timevalue`); for
/// [`CURL_TIMECOND_IFUNMODSINCE`](self) it must not be newer
/// (`filetime < timevalue`). Any other condition value proceeds.
#[must_use]
pub fn meets_timecondition(filetime: i64, timecondition: u8, timevalue: i64) -> bool {
    if filetime == 0 || timevalue == 0 {
        return true;
    }
    // Mirrors curl's `switch(timecondition)`, where `CURL_TIMECOND_IFMODSINCE`
    // and the `default:` case share one body (a C fall-through), hence the two
    // structurally-identical arms.
    #[allow(clippy::match_same_arms)]
    match timecondition {
        CURL_TIMECOND_IFUNMODSINCE => filetime < timevalue,
        CURL_TIMECOND_IFMODSINCE => filetime > timevalue,
        // curl's `default:` — treat any other value as if-modified-since.
        _ => filetime > timevalue,
    }
}

// ===========================================================================
// Download engine (C `file_do`, download branch)
// ===========================================================================

/// Convert a [`SystemTime`] modification time to a Unix timestamp (seconds),
/// the value curl stores in `data->info.filetime` from `statbuf.st_mtime`.
///
/// Times at or after the epoch yield a non-negative value; times before the
/// epoch yield a negative value (curl's `time_t` is likewise signed). When the
/// platform cannot supply a modification time the function yields `0`, which —
/// like curl's behavior when `st_mtime` is unavailable — disables the
/// time-condition shortcut (see [`meets_timecondition`]) and suppresses the
/// `Last-Modified` header (see [`format_last_modified_header`], whose epoch base
/// is unaffected, but a `0` simply formats as the epoch).
fn system_time_to_unix(modified: Option<SystemTime>) -> i64 {
    match modified {
        Some(st) => match st.duration_since(UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            // Pre-epoch modification time: negate the magnitude.
            Err(e) => i64::try_from(e.duration().as_secs())
                .map(|s| -s)
                .unwrap_or(i64::MIN),
        },
        None => 0,
    }
}

/// What a successful [`read_file_to_writer`] reports back to its caller so the
/// caller can update the easy handle's post-transfer info — mirroring the
/// side effects `file_do` performs on `data->info` and the progress meter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DownloadInfo {
    /// The file modification time as a Unix timestamp, when it could be
    /// `stat`-ed (curl's `data->info.filetime`, surfaced by `--remote-time`
    /// and `CURLINFO_FILETIME`). [`None`] when the file could not be `stat`-ed.
    pub filetime: Option<i64>,
    /// The number of body bytes the transfer is expected to deliver, when known
    /// (curl's `Curl_pgrsSetDownloadSize` argument). [`None`] when the size is
    /// not known (e.g. a directory listing, or a zero-length file).
    pub download_size: Option<u64>,
    /// `true` when a configured time condition was not met and the transfer was
    /// skipped without an error (curl's `data->info.timecond`, surfaced by
    /// `CURLINFO_CONDITION_UNMET`). The body is intentionally empty in this case.
    pub timecond_unmet: bool,
}

/// Stream a local file (or a directory listing) to the client write path —
/// the Rust analog of `file_do`'s download branch (`lib/file.c`).
///
/// This is the engine-facing worker invoked by [`FileProtocol::run_download`];
/// it is also the unit the module's tests drive directly (cf. the
/// `protocols::mqtt` pattern of a public async worker over a [`ClientWriter`] +
/// [`WriteCallbacks`] sink).
///
/// The observable behavior reproduced from curl, in order:
///
/// 1. **Open + stat.** The file at `path` is opened for reading; failure maps to
///    [`CurlError::FileCouldntReadFile`] with curl's
///    `"Could not open file ..."` message (`file_connect`). A successful
///    `stat` yields the file size (for a regular file) and the modification
///    time.
/// 2. **Time condition.** When the file was `stat`-ed, no `range` is set, and a
///    `timecondition` other than [`CURL_TIMECOND_NONE`] is configured, an unmet
///    condition (see [`meets_timecondition`]) skips the transfer: the function
///    returns `Ok` with [`DownloadInfo::timecond_unmet`] set and no body.
/// 3. **Synthetic headers.** When `stat`-ed, `Content-Length` and
///    `Accept-ranges: bytes` (only if the size is known), then `Last-Modified`,
///    then the terminating CRLF are written with [`ClientWriteType::HEADER`].
///    For a `no_body` (HEAD-equivalent) request the function returns here.
/// 4. **RANGE / resume.** [`parse_range`] (when `range` is set) and
///    `set_resume_from` are resolved exactly as curl's `Curl_range` plus the
///    `resume_from` adjustments: last-N-bytes (`resume_from < 0`) requires a
///    known size, a forward resume past EOF is
///    [`CurlError::BadDownloadResume`], and `maxdownload` caps the byte count.
/// 5. **Body.** The file is `seek`-ed to the resume offset (a bad seek is
///    [`CurlError::BadDownloadResume`]) and streamed in `FILE_XFER_BUF` chunks
///    via [`ClientWriteType::BODY`]; a directory `path` instead lists its
///    entries (one name per line, dot-prefixed entries skipped) like curl's
///    `opendir`/`readdir` branch. A final empty `BODY | EOS` write finalizes the
///    chain (the analog of the transfer engine's end-of-stream signal).
///
/// `errbuf` receives curl's `failf` error text; `verbose` enables the
/// `infof` traces curl emits under `DEBUGF`.
#[allow(clippy::too_many_arguments)]
pub async fn read_file_to_writer(
    path: &Path,
    set_resume_from: i64,
    range: Option<&str>,
    no_body: bool,
    timecondition: u8,
    timevalue: i64,
    writer: &mut ClientWriter,
    sink: &mut dyn WriteCallbacks,
    errbuf: &mut Option<String>,
    verbose: bool,
) -> Result<DownloadInfo> {
    // --- 1. Open + stat -----------------------------------------------------
    // curl opens the descriptor in `file_connect`; we open here so the worker
    // is self-contained and holds the handle across no `.await` suspension
    // points other than its own reads. A failure to open is curl's
    // `CURLE_FILE_COULDNT_READ_FILE` ("Could not open file ...").
    let mut file = match fs::File::open(path).await {
        Ok(f) => f,
        Err(_) => {
            failf(errbuf, &format!("Could not open file {}", path.display()));
            return Err(CurlError::FileCouldntReadFile);
        }
    };

    // `fstat`: a directory has no meaningful size; a regular file's size feeds
    // `Content-Length`/RANGE math. The modification time feeds `--remote-time`.
    let (fstated, is_dir, stat_size, filetime): (bool, bool, i64, Option<i64>) =
        match file.metadata().await {
            Ok(meta) => {
                let is_dir = meta.is_dir();
                // Raw file size (curl's `statbuf.st_size`), used for both the
                // `Content-Length` header and the last-N-bytes resume math.
                let size = i64::try_from(meta.len()).unwrap_or(i64::MAX);
                let mtime = system_time_to_unix(meta.modified().ok());
                (true, is_dir, size, Some(mtime))
            }
            Err(_) => (false, false, -1, None),
        };

    // curl: `expected_size = statbuf.st_size` for a regular file, else stays -1.
    let mut expected_size: i64 = if fstated && !is_dir { stat_size } else { -1 };

    // --- 2. Time condition --------------------------------------------------
    // curl: `if(fstated && !range && timecondition && !meets) return CURLE_OK;`
    if fstated
        && range.is_none()
        && timecondition != CURL_TIMECOND_NONE
        && !meets_timecondition(filetime.unwrap_or(0), timecondition, timevalue)
    {
        infof(verbose, "The requested document is not new enough");
        return Ok(DownloadInfo {
            filetime,
            download_size: None,
            timecond_unmet: true,
        });
    }

    // --- 3. Synthetic response headers --------------------------------------
    if fstated {
        if expected_size >= 0 {
            let cl = format!("Content-Length: {expected_size}\r\n");
            writer.write(ClientWriteType::HEADER, cl.as_bytes(), sink)?;
            writer.write(ClientWriteType::HEADER, b"Accept-ranges: bytes\r\n", sink)?;
        }
        // curl bails the whole transfer if `gmtime` fails; an out-of-range
        // modification time is not reachable for a real file, so we simply omit
        // the header in that case rather than failing.
        if let Some(hdr) = format_last_modified_header(filetime.unwrap_or(0)) {
            writer.write(ClientWriteType::HEADER, &hdr, sink)?;
        }
        // End of headers.
        writer.write(ClientWriteType::HEADER, b"\r\n", sink)?;

        // curl: `if(data->req.no_body) return CURLE_OK;` — headers only.
        if no_body {
            return Ok(DownloadInfo {
                filetime,
                download_size: if expected_size >= 0 {
                    Some(expected_size as u64)
                } else {
                    None
                },
                timecond_unmet: false,
            });
        }
    }

    // --- 4. RANGE / resume resolution ---------------------------------------
    // curl: `Curl_range(data)` populates `resume_from`/`maxdownload` only when a
    // range string is set; otherwise `resume_from` is whatever the caller set
    // via CURLOPT_RESUME_FROM and `maxdownload` is unset (-1).
    let (mut resume_from, maxdownload) = match range {
        Some(r) => {
            let outcome = parse_range(r)?;
            (outcome.resume_from, outcome.maxdownload)
        }
        None => (set_resume_from, -1),
    };

    // Last-N-bytes: `resume_from < 0` rebases off the end of the file.
    if resume_from < 0 {
        if !fstated {
            failf(errbuf, "cannot get the size of file.");
            return Err(CurlError::ReadError);
        }
        resume_from += stat_size;
    }

    // Forward resume: shrink the expected size, or reject when past EOF.
    if resume_from > 0 {
        if resume_from <= expected_size {
            expected_size -= resume_from;
        } else {
            failf(errbuf, "failed to resume file:// transfer");
            return Err(CurlError::BadDownloadResume);
        }
    }

    // A high-water mark from the range (`X-Y` / `-Y`) caps the byte count.
    if maxdownload > 0 {
        expected_size = maxdownload;
    }

    // curl: `size_known = fstated && expected_size > 0`.
    let size_known = fstated && expected_size > 0;
    let download_size = if size_known {
        Some(expected_size as u64)
    } else {
        None
    };

    if resume_from != 0 {
        infof(
            verbose,
            &format!("file:// resume/seek to offset {resume_from}"),
        );
    }

    // --- 5. Body ------------------------------------------------------------
    if !is_dir {
        // Seek to the resume offset. curl checks `lseek` returns the requested
        // offset; a negative offset (a last-N range larger than the file) or a
        // short seek is a bad resume.
        if resume_from != 0 {
            if resume_from < 0 {
                return Err(CurlError::BadDownloadResume);
            }
            let pos = file
                .seek(SeekFrom::Start(resume_from as u64))
                .await
                .map_err(|_| CurlError::BadDownloadResume)?;
            if pos != resume_from as u64 {
                return Err(CurlError::BadDownloadResume);
            }
        }

        let mut buf = vec![0u8; FILE_XFER_BUF];
        // `remaining` mirrors curl's running `expected_size` countdown.
        let mut remaining = expected_size;
        loop {
            // curl: read at most `expected_size` bytes when the size is known,
            // else a full buffer (less the historical NUL-terminator byte).
            let bytestoread = if size_known {
                core::cmp::min(remaining.max(0) as usize, FILE_XFER_BUF - 1)
            } else {
                FILE_XFER_BUF - 1
            };

            let nread = file
                .read(&mut buf[..bytestoread])
                .await
                .map_err(|_| CurlError::ReadError)?;

            // curl: `if(nread <= 0 || (size_known && expected_size == 0)) break;`
            if nread == 0 || (size_known && remaining == 0) {
                break;
            }
            if size_known {
                remaining -= nread as i64;
            }
            writer.write(ClientWriteType::BODY, &buf[..nread], sink)?;
        }
    } else {
        // Directory listing: curl's `opendir`/`readdir` branch writes each
        // entry name (dot-prefixed names skipped) followed by '\n'.
        let mut entries = fs::read_dir(path).await.map_err(|_| CurlError::ReadError)?;
        loop {
            let entry = match entries.next_entry().await {
                Ok(Some(e)) => e,
                Ok(None) => break,
                Err(_) => return Err(CurlError::ReadError),
            };
            let name = entry.file_name();
            // Raw bytes on Unix (curl writes the raw `d_name`); lossy elsewhere.
            #[cfg(unix)]
            let name_bytes = {
                use std::os::unix::ffi::OsStrExt;
                name.as_bytes().to_vec()
            };
            #[cfg(not(unix))]
            let name_bytes = name.to_string_lossy().into_bytes();

            // curl: `if(entry->d_name[0] != '.')` — skip '.', '..', dotfiles.
            if name_bytes.first() == Some(&b'.') {
                continue;
            }
            writer.write(ClientWriteType::BODY, &name_bytes, sink)?;
            writer.write(ClientWriteType::BODY, b"\n", sink)?;
        }
    }

    // Signal end-of-stream so the client-write chain finalizes (the analog of
    // the transfer engine's terminating write; idempotent w.r.t. the writer's
    // own EOS guard).
    writer.write(ClientWriteType::BODY | ClientWriteType::EOS, &[], sink)?;

    Ok(DownloadInfo {
        filetime,
        download_size,
        timecond_unmet: false,
    })
}

// ===========================================================================
// Upload engine (C `file_upload`)
// ===========================================================================

/// Find the byte offset of the first path separator in `path`, the Rust analog
/// of curl's `strchr(file->path, DIRSEP)` in `file_upload`. On Unix the
/// separator is `/`; on Windows-style `DOS_FILESYSTEM` builds it is `\`.
///
/// Operates on the decoded path's raw bytes so a path that is not valid UTF-8
/// is handled exactly as curl's byte-oriented `strchr` would.
fn first_dir_sep(path: &Path) -> Option<usize> {
    #[cfg(windows)]
    const DIRSEP: u8 = b'\\';
    #[cfg(not(windows))]
    const DIRSEP: u8 = b'/';

    #[cfg(unix)]
    let bytes: &[u8] = {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes()
    };
    #[cfg(not(unix))]
    let owned = path.to_string_lossy().into_owned().into_bytes();
    #[cfg(not(unix))]
    let bytes: &[u8] = &owned;

    bytes.iter().position(|&b| b == DIRSEP)
}

/// Write an upload body to a local file — the Rust analog of `file_upload`
/// (`lib/file.c`).
///
/// This is the engine-facing worker invoked by [`FileProtocol::run_upload`] and
/// the unit the module's tests drive directly. It is symmetric with
/// [`read_file_to_writer`]: where the download worker pushes bytes into a
/// [`ClientWriter`], the upload worker pulls bytes from an [`UploadReader`] fed
/// by the user's [`ReadCallback`] source.
///
/// The observable behavior reproduced from curl, in order:
///
/// 1. **Target validation.** The decoded `path` must contain a path separator
///    and must not end on one (curl's `strchr(path, DIRSEP)` /
///    `!dir`/`!dir[1]` guards); otherwise [`CurlError::FileCouldntReadFile`].
/// 2. **Open.** The file is opened write-only and created if absent, with
///    [`O_APPEND`-equivalent](std::fs::OpenOptions::append) semantics when a
///    resume offset is set and truncation otherwise (curl's
///    `O_WRONLY | O_CREAT | (resume_from ? O_APPEND : O_TRUNC)`), honoring
///    `new_file_perms` on Unix. A failure is
///    [`CurlError::WriteError`] ("cannot open ... for writing").
/// 3. **Resume rebase.** A negative `resume_from` ("`-`") rebases to the current
///    size of the target file (curl `fstat`s the just-opened descriptor); a
///    `stat` failure is [`CurlError::WriteError`] ("cannot get the size of ...").
/// 4. **Pump.** Upload bytes are pulled in `FILE_XFER_BUF` chunks; the first
///    `resume_from` bytes of the *input* are skipped (curl advances `sendbuf`
///    past the resume point) and the remainder is written. A short or failed
///    write is [`CurlError::SendError`].
///
/// `errbuf` receives curl's `failf` text; `verbose` enables the `infof` trace.
#[allow(clippy::too_many_arguments)]
pub async fn write_file_from_reader(
    path: &Path,
    resume_from: i64,
    new_file_perms: u32,
    reader: &mut UploadReader,
    source: &mut dyn ReadCallback,
    errbuf: &mut Option<String>,
    verbose: bool,
) -> Result<()> {
    // --- 1. Target validation ----------------------------------------------
    // curl: `dir = strchr(path, DIRSEP); if(!dir) ...; if(!dir[1]) ...`.
    // `!dir`  -> no separator at all in the path.
    // `!dir[1]`-> the separator is the final byte (a bare directory path).
    match first_dir_sep(path) {
        None => return Err(CurlError::FileCouldntReadFile),
        Some(idx) => {
            #[cfg(unix)]
            let len = {
                use std::os::unix::ffi::OsStrExt;
                path.as_os_str().as_bytes().len()
            };
            #[cfg(not(unix))]
            let len = path.to_string_lossy().len();
            if idx + 1 >= len {
                return Err(CurlError::FileCouldntReadFile);
            }
        }
    }

    // --- 2. Open ------------------------------------------------------------
    // curl: mode = O_WRONLY | O_CREAT | (resume_from ? O_APPEND : O_TRUNC).
    let append = resume_from != 0;
    let mut open_opts = fs::OpenOptions::new();
    open_opts.write(true).create(true);
    if append {
        open_opts.append(true);
    } else {
        open_opts.truncate(true);
    }
    // curl passes `data->set.new_file_perms` as the `open()` mode; honor it on
    // Unix where file permissions exist (the umask still applies, as in curl).
    // `tokio::fs::OpenOptions::mode` is an inherent unix method (no extension
    // trait import needed).
    #[cfg(unix)]
    open_opts.mode(new_file_perms);
    #[cfg(not(unix))]
    let _ = new_file_perms;

    let mut file = match open_opts.open(path).await {
        Ok(f) => f,
        Err(_) => {
            failf(
                errbuf,
                &format!("cannot open {} for writing", path.display()),
            );
            return Err(CurlError::WriteError);
        }
    };

    // --- 3. Resume rebase ---------------------------------------------------
    // curl: "treat the negative resume offset value as the case of '-'".
    let mut resume_from = resume_from;
    if resume_from < 0 {
        match file.metadata().await {
            Ok(meta) => resume_from = i64::try_from(meta.len()).unwrap_or(i64::MAX),
            Err(_) => {
                failf(
                    errbuf,
                    &format!("cannot get the size of {}", path.display()),
                );
                return Err(CurlError::WriteError);
            }
        }
    }
    if resume_from != 0 {
        infof(
            verbose,
            &format!("file:// upload skipping {resume_from} input bytes"),
        );
    }

    // --- 4. Pump ------------------------------------------------------------
    let mut buf = vec![0u8; FILE_XFER_BUF];
    loop {
        let nread = match reader.read(&mut buf, source)? {
            ReadStep::Data(n) => n,
            // End of the upload stream.
            ReadStep::Eof => break,
            // FILE is `PROTOPT_NONETWORK` and constructs its `UploadReader` with
            // `can_pause = false`, so a pause is reported as `ReadError` by the
            // reader and never surfaces here; treat it defensively all the same.
            ReadStep::Paused => return Err(CurlError::ReadError),
        };
        if nread == 0 {
            continue;
        }

        // curl: skip bytes before the resume point, advancing `sendbuf`.
        let sendbuf: &[u8] = if resume_from > 0 {
            if (nread as i64) <= resume_from {
                // The whole block is still before the resume point: drop it.
                resume_from -= nread as i64;
                continue;
            }
            let skip = resume_from as usize;
            resume_from = 0;
            &buf[skip..nread]
        } else {
            &buf[..nread]
        };

        // curl: `write(fd, sendbuf, nread)`; a short or failed write is fatal.
        file.write_all(sendbuf)
            .await
            .map_err(|_| CurlError::SendError)?;
    }

    // Flush any buffered bytes to the OS before the handle is dropped.
    file.flush().await.map_err(|_| CurlError::SendError)?;
    Ok(())
}

// ===========================================================================
// `FileProtocol` — the `Protocol` handler (C `Curl_protocol_file`)
// ===========================================================================

/// Per-connection protocol state for a FILE transfer — the Rust analog of curl's
/// `struct FILEPROTO` (`lib/file.c`).
///
/// curl's `FILEPROTO` carries `{ path, freepath, fd }`. Here only the decoded
/// local `path` is parked on the [`Connection`]: the descriptor is opened by the
/// worker ([`read_file_to_writer`] / [`write_file_from_reader`]) at transfer
/// time rather than held open across the connect→do boundary, so there is no
/// `fd` to track and Rust's `Drop` closes the handle deterministically. The
/// owned [`PathBuf`] subsumes curl's `freepath` ownership flag.
#[derive(Debug, Clone)]
struct FileState {
    /// The decoded local filesystem path (curl's `FILEPROTO.path`).
    path: PathBuf,
}

/// The `file://` scheme handler — the Rust analog of curl's `Curl_protocol_file`
/// (`lib/file.c`).
///
/// A zero-sized, stateless singleton (like the other handlers): all per-transfer
/// state lives on the [`Easy`] handle and the parked [`FileState`], so one value
/// serves every `file` transfer. FILE is the only [`PROTOPT_NONETWORK`] scheme,
/// so this handler never touches the [`crate::conn`] send/recv path — its
/// [`connect`](Protocol::connect) merely decodes and validates the path, and the
/// byte movement happens in [`run_download`](FileProtocol::run_download) /
/// [`run_upload`](FileProtocol::run_upload) over [`tokio::fs`].
#[derive(Debug, Clone, Copy, Default)]
pub struct FileProtocol;

impl FileProtocol {
    /// Construct the FILE handler. Used by
    /// [`crate::protocols::scheme_handler`] to map the `file` scheme here.
    #[must_use]
    pub const fn new() -> Self {
        FileProtocol
    }

    /// Whether this transfer is an upload — the Rust analog of curl's
    /// `data->state.upload`. `CURLOPT_UPLOAD`/`CURLOPT_PUT` set the request
    /// method to [`HttpReq::Put`] (see `setopt.rs`), so that is the signal.
    fn is_upload(data: &Easy) -> bool {
        data.set.method == HttpReq::Put
    }

    /// Resolve the request URL for this transfer, mirroring the preflight in
    /// [`Easy::perform`]: prefer an explicitly-set `CURLOPT_CURLU` handle,
    /// otherwise parse the `CURLOPT_URL` string (guessing the scheme as curl
    /// does). Equivalent to the gopher handler's private `resolve_request_url`.
    fn resolve_request_url(data: &Easy) -> Result<CurlUrl> {
        if let Some(uh) = data.set.uh.as_ref() {
            Ok(uh.clone())
        } else if let Some(url_str) = data.url() {
            let mut url = CurlUrl::new();
            url.set(CurlUPart::Url, Some(url_str), CURLU_GUESS_SCHEME)
                .map_err(uc_to_curlcode)?;
            Ok(url)
        } else {
            Err(CurlError::UrlMalformat)
        }
    }

    /// Decode the configured URL's path component into a local filesystem path —
    /// the connect-phase work of curl's `file_connect`. The URL parser hands back
    /// a still-percent-encoded path (curl's `data->state.up.path`), which
    /// [`decode_file_url_path`] decodes and normalizes.
    fn decode_path(data: &Easy) -> Result<PathBuf> {
        let url = Self::resolve_request_url(data)?;
        let encoded = url.get(CurlUPart::Path, 0).map_err(uc_to_curlcode)?;
        decode_file_url_path(&encoded)
    }

    /// The local path for this transfer: the one parked by
    /// [`connect`](Protocol::connect) when present, otherwise decoded on demand
    /// from the handle. The fallback lets [`run_download`](Self::run_download) /
    /// [`run_upload`](Self::run_upload) be driven directly (as the tests do)
    /// without a prior `connect`.
    fn resolve_local_path(data: &Easy, conn: &Connection) -> Result<PathBuf> {
        if let Some(state) = conn.proto_state_ref::<FileState>() {
            Ok(state.path.clone())
        } else {
            Self::decode_path(data)
        }
    }

    /// Run the FILE **download** — the engine-facing entry that performs the
    /// whole read transfer (curl does the entire operation in `file_do` because
    /// `select()`/`recv()` are not usable on a plain file descriptor). It streams
    /// the file (or directory listing) to the client write path and then updates
    /// the handle's post-transfer info (`data->info.filetime`/`timecond`), just
    /// as `file_do` does.
    ///
    /// Symmetric with [`crate::protocols::mqtt::MqttProtocol::run_subscription`]:
    /// it takes the [`ClientWriter`] chain and the user's [`WriteCallbacks`] sink
    /// so the engine (and the tests) can drive it directly.
    ///
    /// # Errors
    ///
    /// Propagates the worker's error mapping — [`CurlError::FileCouldntReadFile`]
    /// for an unopenable file, [`CurlError::BadDownloadResume`] /
    /// [`CurlError::RangeError`] / [`CurlError::ReadError`] for resume/range/read
    /// failures, or a [`WriteCallbacks`]-originated [`CurlError::WriteError`].
    pub async fn run_download(
        &self,
        data: &mut Easy,
        conn: &mut Connection,
        writer: &mut ClientWriter,
        sink: &mut dyn WriteCallbacks,
    ) -> Result<()> {
        let path = Self::resolve_local_path(data, conn)?;

        // Snapshot the (Copy) option values and own the range string so no borrow
        // of `data` is held across the `await` (the worker borrows neither).
        let set_resume_from = data.set.set_resume_from;
        let no_body = data.set.opt_no_body;
        let timecondition = data.set.timecondition;
        let timevalue = data.set.timevalue;
        let verbose = data.set.verbose;
        let range = data.set.str(StrId::SetRange).map(str::to_owned);

        let info = read_file_to_writer(
            &path,
            set_resume_from,
            range.as_deref(),
            no_body,
            timecondition,
            timevalue,
            writer,
            sink,
            &mut conn.filter_data.error_buffer,
            verbose,
        )
        .await?;

        // Post-transfer info, exactly as `file_do` records it on `data->info`.
        if let Some(filetime) = info.filetime {
            data.info.filetime = filetime;
        }
        data.info.timecond = info.timecond_unmet;
        Ok(())
    }

    /// Run the FILE **upload** — the engine-facing entry that performs the whole
    /// write transfer (curl's `file_upload`). Symmetric with
    /// [`run_download`](Self::run_download): it pulls upload bytes from an
    /// [`UploadReader`] fed by the user's [`ReadCallback`] source and writes them
    /// to the target file.
    ///
    /// # Errors
    ///
    /// Propagates the worker's error mapping — [`CurlError::FileCouldntReadFile`]
    /// for an invalid target path, [`CurlError::WriteError`] for an unopenable
    /// target, or [`CurlError::SendError`] for a failed write.
    pub async fn run_upload(
        &self,
        data: &mut Easy,
        conn: &mut Connection,
        reader: &mut UploadReader,
        source: &mut dyn ReadCallback,
    ) -> Result<()> {
        let path = Self::resolve_local_path(data, conn)?;
        let set_resume_from = data.set.set_resume_from;
        let new_file_perms = data.set.new_file_perms;
        let verbose = data.set.verbose;

        write_file_from_reader(
            &path,
            set_resume_from,
            new_file_perms,
            reader,
            source,
            &mut conn.filter_data.error_buffer,
            verbose,
        )
        .await
    }
}

impl Protocol for FileProtocol {
    fn scheme(&self) -> &'static Scheme {
        &SCHEME_FILE
    }

    // curl's `file_setup_connection` only allocates the `FILEPROTO` meta; the
    // Rust state is built in `connect`, so this is a no-op success.
    // (defaulted `setup_connection` suffices.)

    /// Decode the URL path to a local path and, for a download, open the file
    /// early so a missing/unreadable file fails here with
    /// [`CurlError::FileCouldntReadFile`] — exactly as curl's `file_connect`
    /// does (it `open()`s the descriptor at connect time). The decoded path is
    /// parked on the [`Connection`] as protocol state for the do-phase. There is
    /// no socket, so this performs no network I/O.
    fn connect<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let path = Self::decode_path(data)?;

            // curl opens the file in `file_connect`; for a download a failure to
            // open is fatal here. For an upload curl defers opening to
            // `file_upload` (it may create the file), so we do not pre-open.
            if !Self::is_upload(data) && fs::File::open(&path).await.is_err() {
                failf(
                    &mut conn.filter_data.error_buffer,
                    &format!("Could not open file {}", path.display()),
                );
                return Err(CurlError::FileCouldntReadFile);
            }

            conn.set_proto_state(Box::new(FileState { path }));
            Ok(())
        })
    }

    /// Describe the transfer to the engine (curl's `file_do` up to the point it
    /// knows the direction/size). FILE moves the bytes itself in
    /// [`run_download`](Self::run_download) / [`run_upload`](Self::run_upload),
    /// so this only reports the shape: an upload carries no response, while a
    /// download emits synthetic headers and, for a regular file, a known size.
    fn do_it<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<ProtocolTransfer>> {
        Box::pin(async move {
            if Self::is_upload(data) {
                return Ok(ProtocolTransfer::new(TransferDirection::Upload));
            }

            // Download: report the size up front when the path is a regular file
            // (curl's `Curl_pgrsSetDownloadSize`); a directory or stat failure
            // leaves it unknown. FILE always emits synthetic response headers.
            let path = Self::resolve_local_path(data, conn)?;
            let mut xfer =
                ProtocolTransfer::new(TransferDirection::Download).with_response_headers(true);
            if let Ok(meta) = fs::metadata(&path).await {
                if meta.is_file() {
                    xfer = xfer.with_size(meta.len());
                }
            }
            Ok(xfer)
        })
    }

    /// Post-transfer finalization (curl's `file_done`): drop the parked path
    /// state. There is no connection to tear down.
    fn done<'a>(
        &'a self,
        _data: &'a mut Easy,
        conn: &'a mut Connection,
        _status: Result<()>,
        _premature: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Drop the FILEPROTO-equivalent state (curl frees `file->path`).
            let _ = conn.take_proto_state();
            Ok(())
        })
    }

    // curl's `file_disconnect` only frees `file->path` (already handled by
    // `done`/`Drop`); FILE has no real connection, so the defaulted no-op
    // `disconnect` is correct.
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{SchemeDescriptor, TRNSPRT_TCP};
    use crate::options::CurlOption;
    use crate::setopt::OptionValue;

    // ---- test doubles -----------------------------------------------------

    /// A [`WriteCallbacks`] sink that accumulates the body and header bytes the
    /// download worker emits (mirrors the `mqtt` test sink).
    #[derive(Debug, Default)]
    struct VecSink {
        body: Vec<u8>,
        headers: Vec<u8>,
    }

    impl WriteCallbacks for VecSink {
        fn write_body(&mut self, data: &[u8]) -> usize {
            self.body.extend_from_slice(data);
            data.len()
        }
        fn write_header(&mut self, data: &[u8]) -> Option<usize> {
            self.headers.extend_from_slice(data);
            Some(data.len())
        }
    }

    /// A [`ReadCallback`] upload source that serves bytes from an in-memory
    /// buffer, returning `0` (end-of-input) once exhausted — the analog of a
    /// `CURLOPT_READFUNCTION` reading a fixed payload.
    struct SliceReader {
        data: Vec<u8>,
        pos: usize,
    }

    impl SliceReader {
        fn new(data: impl Into<Vec<u8>>) -> Self {
            Self {
                data: data.into(),
                pos: 0,
            }
        }
    }

    impl ReadCallback for SliceReader {
        fn read(&mut self, buf: &mut [u8]) -> usize {
            let n = (self.data.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            n
        }
    }

    /// Run the download worker over `path` with the given range/resume settings,
    /// returning the collected sink and the [`DownloadInfo`]. No-body and
    /// time-condition are disabled.
    async fn download(
        path: &Path,
        set_resume_from: i64,
        range: Option<&str>,
    ) -> Result<(VecSink, DownloadInfo)> {
        let mut writer = ClientWriter::with_options(false, false);
        let mut sink = VecSink::default();
        let mut errbuf: Option<String> = None;
        let info = read_file_to_writer(
            path,
            set_resume_from,
            range,
            false,
            CURL_TIMECOND_NONE,
            0,
            &mut writer,
            &mut sink,
            &mut errbuf,
            false,
        )
        .await?;
        Ok((sink, info))
    }

    /// Build a minimal FILE [`Connection`] (no filters — FILE is NONETWORK).
    fn make_file_conn() -> Connection {
        let scheme = &SCHEME_FILE;
        let desc = SchemeDescriptor::new(
            scheme.name,
            scheme.default_port,
            scheme.flags,
            scheme.protocol,
        );
        Connection::new("file:", TRNSPRT_TCP, desc)
    }

    // ---- decode_file_url_path --------------------------------------------

    #[test]
    fn decode_url_path_percent_decodes() {
        // `file:///tmp/a%20b.txt` → local path `/tmp/a b.txt`.
        let p = decode_file_url_path("/tmp/a%20b.txt").unwrap();
        assert_eq!(p, PathBuf::from("/tmp/a b.txt"));
    }

    #[test]
    fn decode_url_path_plain_passthrough() {
        let p = decode_file_url_path("/etc/hosts").unwrap();
        assert_eq!(p, PathBuf::from("/etc/hosts"));
    }

    #[test]
    fn decode_url_path_localhost_form_path_only() {
        // The URL layer strips the authority, so the path component for
        // `file://localhost/tmp/x` is just `/tmp/x` — same as `file:///tmp/x`.
        let p = decode_file_url_path("/tmp/x").unwrap();
        assert_eq!(p, PathBuf::from("/tmp/x"));
    }

    #[test]
    fn decode_url_path_rejects_embedded_nul() {
        // A decoded NUL "indicates foul play" — curl's `REJECT_ZERO`.
        let err = decode_file_url_path("/tmp/a%00b").unwrap_err();
        assert_eq!(err, CurlError::UrlMalformat);
    }

    #[test]
    fn decode_url_path_preserves_malformed_escape() {
        // curl's `Curl_urldecode` copies a malformed `%` escape verbatim.
        let p = decode_file_url_path("/tmp/100%discount").unwrap();
        assert_eq!(p, PathBuf::from("/tmp/100%discount"));
    }

    // ---- normalize_dos_path (compiled on all platforms for testability) ---

    #[test]
    fn dos_path_strips_drive_slash_and_maps_seps() {
        // `/c:/Temp/x` → `c:\Temp\x`.
        assert_eq!(normalize_dos_path("/c:/Temp/x"), "c:\\Temp\\x");
    }

    #[test]
    fn dos_path_maps_pipe_to_colon() {
        // `/c|/x` → `c:\x`.
        assert_eq!(normalize_dos_path("/c|/x"), "c:\\x");
    }

    #[test]
    fn dos_path_no_drive_keeps_leading_sep() {
        // No drive spec: the leading slash is kept (becomes `\`).
        assert_eq!(normalize_dos_path("/foo/bar"), "\\foo\\bar");
    }

    #[test]
    fn dos_path_preserves_multibyte_utf8() {
        // ASCII↔ASCII swaps must not corrupt a multi-byte filename.
        assert_eq!(normalize_dos_path("/c:/π/x"), "c:\\π\\x");
    }

    // ---- parse_range ------------------------------------------------------

    #[test]
    fn range_from_to_end() {
        // `X-` : resume from X to end of file.
        assert_eq!(
            parse_range("100-").unwrap(),
            RangeOutcome {
                resume_from: 100,
                maxdownload: -1
            }
        );
    }

    #[test]
    fn range_last_n_bytes() {
        // `-Y` : the last Y bytes.
        assert_eq!(
            parse_range("-100").unwrap(),
            RangeOutcome {
                resume_from: -100,
                maxdownload: 100
            }
        );
    }

    #[test]
    fn range_closed_interval() {
        // `X-Y` : the closed range [X, Y], maxdownload = Y - X + 1.
        assert_eq!(
            parse_range("0-99").unwrap(),
            RangeOutcome {
                resume_from: 0,
                maxdownload: 100
            }
        );
        // Single byte.
        assert_eq!(
            parse_range("5-5").unwrap(),
            RangeOutcome {
                resume_from: 5,
                maxdownload: 1
            }
        );
    }

    #[test]
    fn range_rejects_bad_forms() {
        // Bare number (no dash), inverted interval, and `-0`.
        assert_eq!(parse_range("5").unwrap_err(), CurlError::RangeError);
        assert_eq!(parse_range("abc").unwrap_err(), CurlError::RangeError);
        assert_eq!(parse_range("10-5").unwrap_err(), CurlError::RangeError);
        assert_eq!(parse_range("-0").unwrap_err(), CurlError::RangeError);
    }

    #[test]
    fn range_second_number_overflow_degrades_to_from_end() {
        // curl's `Curl_range`: an overflowing SECOND number degrades to `X-`
        // (the cursor is not advanced, treated as "no second number").
        assert_eq!(
            parse_range("5-99999999999999999999999999").unwrap(),
            RangeOutcome {
                resume_from: 5,
                maxdownload: -1
            }
        );
    }

    #[test]
    fn range_first_number_overflow_errors() {
        // An overflowing FIRST number leaves the cursor on a digit, so the
        // mandatory `-` check fails → RangeError (matches curl).
        assert_eq!(
            parse_range("99999999999999999999999999-5").unwrap_err(),
            CurlError::RangeError
        );
    }

    // ---- format_last_modified_header -------------------------------------

    #[test]
    fn last_modified_header_epoch() {
        // 1970-01-01 00:00:00 UTC is a Thursday.
        let hdr = format_last_modified_header(0).unwrap();
        assert_eq!(
            hdr,
            b"Last-Modified: Thu, 01 Jan 1970 00:00:00 GMT\r\n".to_vec()
        );
    }

    #[test]
    fn last_modified_header_pads_and_indexes_tables() {
        // 86400 + 3661 = 1970-01-02 01:01:01 UTC (a Friday) — exercises the
        // weekday index and two-digit zero-padding of day/H/M/S.
        let hdr = format_last_modified_header(90_061).unwrap();
        assert_eq!(
            hdr,
            b"Last-Modified: Fri, 02 Jan 1970 01:01:01 GMT\r\n".to_vec()
        );
    }

    // ---- meets_timecondition ---------------------------------------------

    #[test]
    fn timecondition_disabled_when_either_is_zero() {
        assert!(meets_timecondition(0, CURL_TIMECOND_IFMODSINCE, 100));
        assert!(meets_timecondition(100, CURL_TIMECOND_IFMODSINCE, 0));
    }

    #[test]
    fn timecondition_if_modified_since() {
        // Proceed only when the document is strictly newer than `timevalue`.
        assert!(meets_timecondition(200, CURL_TIMECOND_IFMODSINCE, 100));
        assert!(!meets_timecondition(100, CURL_TIMECOND_IFMODSINCE, 200));
        assert!(!meets_timecondition(100, CURL_TIMECOND_IFMODSINCE, 100));
    }

    #[test]
    fn timecondition_if_unmodified_since() {
        // Proceed only when the document is strictly older than `timevalue`.
        assert!(meets_timecondition(100, CURL_TIMECOND_IFUNMODSINCE, 200));
        assert!(!meets_timecondition(200, CURL_TIMECOND_IFUNMODSINCE, 100));
        assert!(!meets_timecondition(100, CURL_TIMECOND_IFUNMODSINCE, 100));
    }

    // ---- system_time_to_unix ---------------------------------------------

    #[test]
    fn system_time_conversion() {
        use std::time::Duration;
        assert_eq!(system_time_to_unix(Some(UNIX_EPOCH)), 0);
        assert_eq!(
            system_time_to_unix(Some(UNIX_EPOCH + Duration::from_secs(100))),
            100
        );
        assert_eq!(
            system_time_to_unix(Some(UNIX_EPOCH - Duration::from_secs(50))),
            -50
        );
        assert_eq!(system_time_to_unix(None), 0);
    }

    // ---- first_dir_sep ----------------------------------------------------

    #[test]
    fn first_dir_sep_positions() {
        assert_eq!(first_dir_sep(Path::new("/foo/bar")), Some(0));
        assert_eq!(first_dir_sep(Path::new("foo/bar")), Some(3));
        assert_eq!(first_dir_sep(Path::new("foo")), None);
    }

    // ---- read_file_to_writer (download) ----------------------------------

    #[tokio::test]
    async fn download_full_file_and_headers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.txt");
        std::fs::write(&path, b"hello world").unwrap();

        let (sink, info) = download(&path, 0, None).await.unwrap();

        assert_eq!(sink.body, b"hello world");
        // Synthetic headers: Content-Length, Accept-ranges, Last-Modified, CRLF.
        let headers = String::from_utf8(sink.headers).unwrap();
        assert!(headers.contains("Content-Length: 11\r\n"), "{headers:?}");
        assert!(headers.contains("Accept-ranges: bytes\r\n"), "{headers:?}");
        assert!(headers.contains("Last-Modified: "), "{headers:?}");
        assert!(headers.ends_with("\r\n\r\n"), "{headers:?}");
        // The size and a (nonzero) modification time are reported back.
        assert_eq!(info.download_size, Some(11));
        assert!(info.filetime.is_some());
        assert!(!info.timecond_unmet);
    }

    #[tokio::test]
    async fn download_missing_file_maps_to_couldnt_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist");
        let err = download(&path, 0, None).await.unwrap_err();
        assert_eq!(err, CurlError::FileCouldntReadFile);
    }

    #[tokio::test]
    async fn download_closed_range() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("digits.txt");
        std::fs::write(&path, b"0123456789").unwrap();

        // `2-5` → bytes at offsets 2..=5 = "2345".
        let (sink, _) = download(&path, 0, Some("2-5")).await.unwrap();
        assert_eq!(sink.body, b"2345");
    }

    #[tokio::test]
    async fn download_resume_offset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("digits.txt");
        std::fs::write(&path, b"0123456789").unwrap();

        // CURLOPT_RESUME_FROM = 3 → skip the first three bytes.
        let (sink, _) = download(&path, 3, None).await.unwrap();
        assert_eq!(sink.body, b"3456789");
    }

    #[tokio::test]
    async fn download_last_n_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("digits.txt");
        std::fs::write(&path, b"0123456789").unwrap();

        // `-3` → the last three bytes = "789".
        let (sink, _) = download(&path, 0, Some("-3")).await.unwrap();
        assert_eq!(sink.body, b"789");
    }

    #[tokio::test]
    async fn download_no_body_emits_headers_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.txt");
        std::fs::write(&path, b"hello").unwrap();

        let mut writer = ClientWriter::with_options(false, false);
        let mut sink = VecSink::default();
        let mut errbuf: Option<String> = None;
        let info = read_file_to_writer(
            &path,
            0,
            None,
            true, // no_body
            CURL_TIMECOND_NONE,
            0,
            &mut writer,
            &mut sink,
            &mut errbuf,
            false,
        )
        .await
        .unwrap();

        assert!(
            sink.body.is_empty(),
            "no body expected for a HEAD-like read"
        );
        let headers = String::from_utf8(sink.headers).unwrap();
        assert!(headers.contains("Content-Length: 5\r\n"));
        assert_eq!(info.download_size, Some(5));
    }

    #[tokio::test]
    async fn download_bad_resume_past_eof() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("abc.txt");
        std::fs::write(&path, b"abc").unwrap();

        // Resume offset beyond EOF is a bad-download-resume.
        let err = download(&path, 10, None).await.unwrap_err();
        assert_eq!(err, CurlError::BadDownloadResume);
    }

    #[tokio::test]
    async fn download_time_condition_unmet_skips_body() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.txt");
        std::fs::write(&path, b"hello").unwrap();

        let mut writer = ClientWriter::with_options(false, false);
        let mut sink = VecSink::default();
        let mut errbuf: Option<String> = None;
        // If-Modified-Since with a far-future `timevalue` → the file is not
        // newer → the transfer is skipped without an error.
        let info = read_file_to_writer(
            &path,
            0,
            None,
            false,
            CURL_TIMECOND_IFMODSINCE,
            i64::MAX,
            &mut writer,
            &mut sink,
            &mut errbuf,
            false,
        )
        .await
        .unwrap();

        assert!(info.timecond_unmet);
        assert!(sink.body.is_empty());
        // No headers are emitted on the time-condition shortcut.
        assert!(sink.headers.is_empty());
    }

    #[tokio::test]
    async fn download_directory_listing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"a").unwrap();
        std::fs::write(dir.path().join("b.txt"), b"b").unwrap();
        // A dot-prefixed entry must be skipped (curl's `d_name[0] != '.'`).
        std::fs::write(dir.path().join(".hidden"), b"x").unwrap();

        let (sink, info) = download(dir.path(), 0, None).await.unwrap();

        let listing = String::from_utf8(sink.body).unwrap();
        let mut names: Vec<&str> = listing.lines().collect();
        names.sort_unstable();
        assert_eq!(names, vec!["a.txt", "b.txt"]);
        assert!(!listing.contains(".hidden"));
        // A directory has no known size.
        assert_eq!(info.download_size, None);
    }

    // ---- write_file_from_reader (upload) ---------------------------------

    /// Drive the upload worker, returning the resulting file contents.
    async fn upload(path: &Path, resume_from: i64, payload: &[u8]) -> Result<Vec<u8>> {
        let mut reader = UploadReader::new(Some(payload.len() as u64), false);
        let mut source = SliceReader::new(payload.to_vec());
        let mut errbuf: Option<String> = None;
        write_file_from_reader(
            path,
            resume_from,
            0o644,
            &mut reader,
            &mut source,
            &mut errbuf,
            false,
        )
        .await?;
        Ok(std::fs::read(path).unwrap())
    }

    #[tokio::test]
    async fn upload_writes_payload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        let got = upload(&path, 0, b"payload data").await.unwrap();
        assert_eq!(got, b"payload data");
    }

    #[tokio::test]
    async fn upload_truncates_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        std::fs::write(&path, b"OLD LONGER CONTENT").unwrap();

        // resume_from == 0 → O_TRUNC: the old content is replaced wholesale.
        let got = upload(&path, 0, b"new").await.unwrap();
        assert_eq!(got, b"new");
    }

    #[tokio::test]
    async fn upload_resume_appends_and_skips_input() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        std::fs::write(&path, b"PREFIX").unwrap();

        // resume_from != 0 → O_APPEND; the first 4 input bytes ("SKIP") are
        // skipped, and "keep" is appended → "PREFIXkeep".
        let got = upload(&path, 4, b"SKIPkeep").await.unwrap();
        assert_eq!(got, b"PREFIXkeep");
    }

    #[tokio::test]
    async fn upload_rejects_path_without_separator() {
        // No path separator at all → curl's `!dir` guard.
        let mut reader = UploadReader::new(Some(3), false);
        let mut source = SliceReader::new(b"abc".to_vec());
        let mut errbuf: Option<String> = None;
        let err = write_file_from_reader(
            Path::new("noslashfile"),
            0,
            0o644,
            &mut reader,
            &mut source,
            &mut errbuf,
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(err, CurlError::FileCouldntReadFile);
    }

    #[tokio::test]
    async fn upload_rejects_bare_root_path() {
        // `/` : a separator with nothing after it → curl's `!dir[1]` guard.
        let mut reader = UploadReader::new(Some(3), false);
        let mut source = SliceReader::new(b"abc".to_vec());
        let mut errbuf: Option<String> = None;
        let err = write_file_from_reader(
            Path::new("/"),
            0,
            0o644,
            &mut reader,
            &mut source,
            &mut errbuf,
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(err, CurlError::FileCouldntReadFile);
    }

    // ---- FileProtocol handler glue (connect → do_it → run_download) ------

    #[tokio::test]
    async fn handler_download_roundtrip_sets_info() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("page.txt");
        std::fs::write(&path, b"file body").unwrap();

        let mut easy = Easy::new();
        easy.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("file://{}", path.display()))),
        )
        .unwrap();

        let proto = FileProtocol::new();
        let mut conn = make_file_conn();

        // connect: decode + open-validate, park the path on the connection.
        proto.connect(&mut easy, &mut conn).await.unwrap();
        assert!(conn.proto_state_ref::<FileState>().is_some());

        // do_it: a download descriptor with response headers and a known size.
        let xfer = proto.do_it(&mut easy, &mut conn).await.unwrap();
        assert_eq!(xfer.direction, TransferDirection::Download);
        assert!(xfer.has_response_headers);
        assert_eq!(xfer.expected_size, Some(9));

        // run_download: stream the body and record post-transfer info.
        let mut writer = ClientWriter::with_options(false, false);
        let mut sink = VecSink::default();
        proto
            .run_download(&mut easy, &mut conn, &mut writer, &mut sink)
            .await
            .unwrap();
        assert_eq!(sink.body, b"file body");
        assert!(
            easy.info.filetime > 0,
            "filetime recorded for --remote-time"
        );

        // done: the parked state is dropped.
        proto
            .done(&mut easy, &mut conn, Ok(()), false)
            .await
            .unwrap();
        assert!(conn.proto_state_ref::<FileState>().is_none());
    }

    #[tokio::test]
    async fn handler_connect_missing_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.txt");

        let mut easy = Easy::new();
        easy.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("file://{}", path.display()))),
        )
        .unwrap();

        let proto = FileProtocol::new();
        let mut conn = make_file_conn();
        let err = proto.connect(&mut easy, &mut conn).await.unwrap_err();
        assert_eq!(err, CurlError::FileCouldntReadFile);
    }

    #[tokio::test]
    async fn handler_upload_roundtrip_writes_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("upload.txt");

        let mut easy = Easy::new();
        easy.setopt(
            CurlOption::CURLOPT_URL,
            OptionValue::Str(Some(format!("file://{}", path.display()))),
        )
        .unwrap();
        // CURLOPT_UPLOAD → method PUT, the upload signal.
        easy.setopt(CurlOption::CURLOPT_UPLOAD, OptionValue::Long(1))
            .unwrap();

        let proto = FileProtocol::new();
        let mut conn = make_file_conn();

        // An upload does not pre-open in connect (the target may be created).
        proto.connect(&mut easy, &mut conn).await.unwrap();
        let xfer = proto.do_it(&mut easy, &mut conn).await.unwrap();
        assert_eq!(xfer.direction, TransferDirection::Upload);

        let mut reader = UploadReader::new(Some(7), false);
        let mut source = SliceReader::new(b"uploads".to_vec());
        proto
            .run_upload(&mut easy, &mut conn, &mut reader, &mut source)
            .await
            .unwrap();

        let got = std::fs::read(&path).unwrap();
        assert_eq!(got, b"uploads");
    }
}
