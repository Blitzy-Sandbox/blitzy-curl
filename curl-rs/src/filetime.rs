// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// Rust rewrite of curl's src/tool_filetime.c + src/toolx/tool_time.c.

//! # File-time get/set and portable local-time conversion
//!
//! Faithful, memory-safe Rust port of curl 8.19.0-DEV's `src/tool_filetime.c`
//! (`getfiletime` / `setfiletime`) and the portable time helper
//! `src/toolx/tool_time.c` (`toolx_localtime`), together with the `-z` /
//! `--time-cond` argument helper that the C tool implements in
//! `src/tool_getparam.c` (`parse_time_cond`).
//!
//! ## What this module powers
//!
//! * [`getfiletime`] reads a file's modification time as a Unix timestamp. It
//!   backs `-z` / `--time-cond <file>` (curl's `OperationConfig.timecond` +
//!   `condtime`, translated by `setopt.rs` into `CURLOPT_TIMECONDITION` +
//!   `CURLOPT_TIMEVALUE`).
//! * [`setfiletime`] stamps a freshly downloaded file with a server-reported
//!   modification time. It backs `-R` / `--remote-time`
//!   (`OperationConfig.remote_time`), invoked post-transfer by `operate.rs` /
//!   `callbacks/write.rs` with the value of `CURLINFO_FILETIME`.
//! * [`toolx_localtime`] converts a Unix timestamp to broken-down *local* time,
//!   used for `--time-cond` date rendering and the write-out time fields.
//! * [`parse_time_cond`] / [`time_cond_selector`] parse a `--time-cond`
//!   argument: an optional `+`/`-`/`=` direction prefix followed by either a
//!   date string or the name of an existing file.
//!
//! ## Memory-safety and unsafe policy (AAP §0.6.2 / §0.7.2)
//!
//! This module contains **zero `unsafe`**. curl's C implementation reaches for
//! `stat(2)`, `utimes(2)`/`utime(2)`, and `localtime_r(3)` (plus a Win32
//! `CreateFile` / `GetFileTime` / `SetFileTime` branch). Every one of those is
//! expressed here with **safe** standard-library and `chrono` APIs:
//!
//! | curl C primitive       | safe Rust replacement                                    |
//! |------------------------|----------------------------------------------------------|
//! | `stat().st_mtime`      | [`std::fs::Metadata::modified`]                          |
//! | `utimes()` / `utime()` | [`std::fs::File::set_times`] + [`std::fs::FileTimes`]    |
//! | `localtime_r()`        | [`chrono::DateTime::from_timestamp`] + [`chrono::Local`] |
//!
//! `File::set_times` and `FileTimes` are stable as of Rust 1.75 — the workspace
//! MSRV — so neither `unsafe` nor a `libc` dependency is required. Consequently
//! this file is deliberately **not** one of the three `unsafe`-permitted
//! OS-integration modules (`xattr.rs`, `terminal.rs`, `getpass.rs`).
//!
//! ## Parity notes
//!
//! * The Win32 `CreateFile` / `GetFileTime` fast path of `getfiletime` is out of
//!   scope — only the four POSIX targets are supported (AAP §0.6.5).
//! * curl's Windows FILETIME overflow clamps (`910670515199` max,
//!   `-6857222400` min) are Windows-specific. They are retained here only as a
//!   *silent* defensive bound on the value fed to [`std::time::Duration`]
//!   arithmetic; on the Unix targets `utimes` receives the raw value, so — to
//!   match that behavior — the clamp emits no diagnostic (unlike the C Win32
//!   branch, which warns).
//! * Diagnostic *text* mirrors curl's `warnf` output ("Warning: Failed to get
//!   filetime: …" / "Warning: Failed to set filetime …") so downstream stderr
//!   scrapers keep working (AAP §0.7.3).

// The public entry points are consumed by CLI modules that are layered on in
// later build-order checkpoints (`setopt.rs`, `operate.rs`, `callbacks/write.rs`
// — AAP §0.7.3). Until those callers exist, some items are not yet referenced
// from within the crate; mirror the sibling CLI modules (`xattr.rs`,
// `getpass.rs`, `terminal.rs`) and allow dead code so the strict
// `-D warnings` clippy gate (AAP §0.6.4) stays green.
#![allow(dead_code)]

use std::fs::{FileTimes, OpenOptions};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Local, NaiveDate, NaiveDateTime};

// ===========================================================================
// CURL_TIMECOND_* — time-condition selector ids (include/curl/curl.h).
//
// Reproduced here as `i64` to match `OperationConfig.timecond` (args.rs) and the
// `curlabi` module's identical values, and — most importantly — to keep the
// integer values frozen for libcurl ABI parity (a consumer relying on
// `CURL_TIMECOND_IFMODSINCE == 1` must keep working, AAP §0.6.1). They are
// defined locally so the module is self-contained; the values are byte-identical
// to the canonical `curl.h` enumeration.
// ===========================================================================

/// No time condition (`CURL_TIMECOND_NONE`).
pub const CURL_TIMECOND_NONE: i64 = 0;
/// Transfer only if the resource was modified since the reference time
/// (`CURL_TIMECOND_IFMODSINCE`) — the `--time-cond` default and the effect of a
/// leading `+`.
pub const CURL_TIMECOND_IFMODSINCE: i64 = 1;
/// Transfer only if the resource was *not* modified since the reference time
/// (`CURL_TIMECOND_IFUNMODSINCE`) — selected by a leading `-`.
pub const CURL_TIMECOND_IFUNMODSINCE: i64 = 2;
/// Compare against the resource's own last-modification time
/// (`CURL_TIMECOND_LASTMOD`) — selected by a leading `=`.
pub const CURL_TIMECOND_LASTMOD: i64 = 3;

/// Maximum Unix timestamp that curl's C code maps to a Win32 `FILETIME` without
/// overflow (`30827-12-31T23:59:59`). Retained as a defensive upper bound on the
/// seconds value handed to [`Duration`] arithmetic; see the module-level parity
/// notes.
const FILETIME_MAX: i64 = 910_670_515_199;
/// Minimum Unix timestamp curl's C code accepts before the (pre-Gregorian) dates
/// become inaccurate (`1752-09-14`). Retained as a defensive lower bound.
const FILETIME_MIN: i64 = -6_857_222_400;

/// Emit a `warnf`-style diagnostic to stderr.
///
/// curl routes these through `tool_msgs.c`'s `warnf`, which is gated on
/// `--silent` and wrapped to the terminal width. The public entry points of this
/// module intentionally take no diagnostic-config handle (their signatures are
/// fixed by the plan to `&Path` / `&str`), so — like the standalone helpers they
/// replace — the message is written unconditionally with curl's `"Warning: "`
/// prefix, preserving the stderr text for downstream scrapers. The
/// `--silent`-gated arg-parse path lives in `args.rs`, which carries the `Diag`
/// handle.
fn warn(msg: &str) {
    eprintln!("Warning: {msg}");
}

/// Return the modification time of `filename` as a Unix timestamp in **seconds**,
/// or `None` (after emitting a warning) when the file cannot be stat'd.
///
/// Rust port of `getfiletime` (`src/tool_filetime.c`, POSIX branch). curl reads
/// `statbuf.st_mtime`; the memory-safe equivalent is [`std::fs::metadata`]
/// followed by [`Metadata::modified`](std::fs::Metadata::modified). The resulting
/// [`SystemTime`] is converted to whole seconds relative to [`UNIX_EPOCH`]:
///
/// * times at or after the epoch use [`SystemTime::duration_since`] directly;
/// * pre-epoch times (where `duration_since` returns [`Err`]) are returned as a
///   negative second count, mirroring curl's signed `curl_off_t st_mtime`.
///
/// On any stat / `modified` failure a `warnf`-style diagnostic
/// (`"Failed to get filetime: <error>"`) is printed and `None` is returned,
/// matching the C function's `rc != 0` path.
///
/// The Win32 `CreateFile` / `GetFileTime` fast path of the C original is out of
/// scope (only POSIX targets are supported).
pub fn getfiletime(filename: &Path) -> Option<i64> {
    match std::fs::metadata(filename).and_then(|meta| meta.modified()) {
        Ok(mtime) => match mtime.duration_since(UNIX_EPOCH) {
            // At or after the Unix epoch: whole seconds, truncated toward zero
            // exactly like the C cast to `curl_off_t`.
            Ok(delta) => Some(delta.as_secs() as i64),
            // Before the Unix epoch: `duration_since` reports how far `mtime`
            // precedes the epoch, which we return as a negative timestamp.
            Err(err) => Some(-(err.duration().as_secs() as i64)),
        },
        Err(err) => {
            warn(&format!("Failed to get filetime: {err}"));
            None
        }
    }
}

/// Convert a Unix timestamp in seconds to a [`SystemTime`].
///
/// The input is first clamped to the `[FILETIME_MIN, FILETIME_MAX]` range. That
/// clamp is *silent* and defensive: on the POSIX targets curl passes the raw
/// value to `utimes`, but bounding it here keeps the subsequent [`Duration`]
/// arithmetic far away from any overflow and matches the value range curl's Win32
/// branch would accept. `checked_add` / `checked_sub` guarantee the conversion
/// can never panic; on the (post-clamp, unreachable) overflow path we fall back
/// to [`UNIX_EPOCH`].
fn unix_seconds_to_system_time(secs: i64) -> SystemTime {
    let secs = secs.clamp(FILETIME_MIN, FILETIME_MAX);
    if secs >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(secs as u64))
            .unwrap_or(UNIX_EPOCH)
    } else {
        // `unsigned_abs` yields the magnitude as a `u64` and is correct even for
        // `i64::MIN` (which cannot occur here after the clamp, but keeps the code
        // total and panic-free).
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(secs.unsigned_abs()))
            .unwrap_or(UNIX_EPOCH)
    }
}

/// Set the modification time of `filename` to `filetime` (a Unix timestamp in
/// seconds), used to honor `-R` / `--remote-time`.
///
/// Rust port of `setfiletime` (`src/tool_filetime.c`). curl uses `utimes` /
/// `utime` to set **both** the access and modification times to `filetime`
/// (`times[0] == times[1]`); the memory-safe equivalent opens the file and calls
/// [`std::fs::File::set_times`] with a [`FileTimes`] carrying the same instant for
/// both fields. Both APIs are stable as of Rust 1.75, so no `unsafe` / `libc` is
/// involved.
///
/// Failures are non-fatal (matching curl): failing to open the file or to set its
/// times only emits a `warnf`-style diagnostic — `"Failed to set filetime <n> on
/// '<path>': <error>"` — and the function returns. The C Win32 overflow *capping
/// warnings* are Windows-specific and are intentionally not reproduced on the
/// POSIX targets; the value is clamped silently inside
/// [`unix_seconds_to_system_time`].
pub fn setfiletime(filetime: i64, filename: &Path) {
    let when = unix_seconds_to_system_time(filetime);

    // A handle is required to reach the safe `set_times` API; curl's `utimes`
    // takes a path, but opening for write is the closest safe analog and is
    // always satisfiable for the freshly written download this backs.
    let file = match OpenOptions::new().write(true).open(filename) {
        Ok(file) => file,
        Err(err) => {
            warn(&format!(
                "Failed to set filetime {filetime} on '{}': {err}",
                filename.display()
            ));
            return;
        }
    };

    // Set access and modification times together, exactly as curl's
    // `times[0] == times[1]` does.
    let times = FileTimes::new().set_accessed(when).set_modified(when);
    if let Err(err) = file.set_times(times) {
        warn(&format!(
            "Failed to set filetime {filetime} on '{}': {err}",
            filename.display()
        ));
    }
}

/// Convert a Unix timestamp (seconds) to broken-down **local** time.
///
/// Full `chrono` replacement for curl's `toolx_localtime`
/// (`src/toolx/tool_time.c`), whose sole purpose was a portable, thread-safe
/// `localtime_r`. The timestamp is resolved to UTC with
/// [`chrono::DateTime::from_timestamp`] (infallible for any in-range value) and
/// then projected onto the system local zone with
/// [`DateTime::with_timezone`](chrono::DateTime::with_timezone). Returns `None`
/// only when the timestamp is outside the representable range — the parity of
/// curl's `CURLE_BAD_FUNCTION_ARGUMENT` result. No `libc::localtime*` call is
/// made.
pub fn toolx_localtime(intime: i64) -> Option<DateTime<Local>> {
    DateTime::from_timestamp(intime, 0).map(|utc| utc.with_timezone(&Local))
}

/// Parse an absolute date string into a Unix timestamp, covering the formats
/// curl's `curl_getdate` (`lib/parsedate.c`) accepts for `-z` / `--time-cond`.
///
/// Recognized inputs include RFC 822/1123 (`Sun, 06 Nov 1994 08:49:37 GMT`),
/// RFC 850 (`Sunday, 06-Nov-94 08:49:37 GMT`), ANSI C `asctime`
/// (`Sun Nov  6 08:49:37 1994`), ISO-8601 variants (with an explicit zone/offset
/// or, when the zone is omitted, interpreted as UTC exactly as curl treats a
/// missing zone as GMT), and date-only forms (defaulted to midnight UTC). Returns
/// `None` when nothing matches, so the caller can fall back to treating the
/// argument as a filename.
fn curl_getdate(spec: &str) -> Option<i64> {
    let text = spec.trim();
    if text.is_empty() {
        return None;
    }

    // Formats carrying an explicit zone or numeric offset.
    if let Ok(dt) = DateTime::parse_from_rfc2822(text) {
        return Some(dt.timestamp());
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(text) {
        return Some(dt.timestamp());
    }
    const OFFSET_FMTS: &[&str] = &[
        "%a, %d %b %Y %H:%M:%S %z",
        "%d %b %Y %H:%M:%S %z",
        "%Y-%m-%d %H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S%z",
    ];
    for fmt in OFFSET_FMTS {
        if let Ok(dt) = DateTime::parse_from_str(text, fmt) {
            return Some(dt.timestamp());
        }
    }

    // Zone-less formats: curl treats a missing zone as GMT, so interpret as UTC.
    const NAIVE_FMTS: &[&str] = &[
        "%a, %d %b %Y %H:%M:%S GMT", // RFC 1123
        "%a, %d %b %Y %H:%M:%S",
        "%d %b %Y %H:%M:%S GMT",
        "%d %b %Y %H:%M:%S",
        "%A, %d-%b-%y %H:%M:%S GMT", // RFC 850
        "%A, %d-%b-%y %H:%M:%S",
        "%a %b %e %H:%M:%S %Y", // ANSI C asctime()
        "%b %e %H:%M:%S %Y",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y%m%dT%H%M%S",
    ];
    for fmt in NAIVE_FMTS {
        if let Ok(naive) = NaiveDateTime::parse_from_str(text, fmt) {
            return Some(naive.and_utc().timestamp());
        }
    }

    // Date-only forms default to midnight UTC.
    const DATE_FMTS: &[&str] = &["%Y-%m-%d", "%d %b %Y", "%d-%b-%Y", "%d-%b-%y"];
    for fmt in DATE_FMTS {
        if let Ok(date) = NaiveDate::parse_from_str(text, fmt) {
            if let Some(naive) = date.and_hms_opt(0, 0, 0) {
                return Some(naive.and_utc().timestamp());
            }
        }
    }

    None
}

/// Split a `--time-cond` spec into its comparison-direction selector and the
/// remaining reference text.
///
/// A leading `+` (or no prefix) selects [`CURL_TIMECOND_IFMODSINCE`], `-` selects
/// [`CURL_TIMECOND_IFUNMODSINCE`], and `=` selects [`CURL_TIMECOND_LASTMOD`],
/// exactly as curl's `parse_time_cond` interprets the first byte. The returned
/// slice is the spec with any recognized prefix removed. Because the recognized
/// prefixes are all single-byte ASCII, slicing at index 1 is always on a UTF-8
/// character boundary.
fn split_time_cond(spec: &str) -> (i64, &str) {
    match spec.as_bytes().first() {
        Some(b'+') => (CURL_TIMECOND_IFMODSINCE, &spec[1..]),
        Some(b'-') => (CURL_TIMECOND_IFUNMODSINCE, &spec[1..]),
        Some(b'=') => (CURL_TIMECOND_LASTMOD, &spec[1..]),
        _ => (CURL_TIMECOND_IFMODSINCE, spec),
    }
}

/// Return the `CURL_TIMECOND_*` comparison direction selected by a `--time-cond`
/// spec's leading `+` / `-` / `=` prefix (defaulting to
/// [`CURL_TIMECOND_IFMODSINCE`] when no prefix is present).
///
/// `setopt.rs` uses this to populate `CURLOPT_TIMECONDITION` while
/// [`parse_time_cond`] resolves the accompanying `CURLOPT_TIMEVALUE`.
pub fn time_cond_selector(spec: &str) -> i64 {
    split_time_cond(spec).0
}

/// Resolve a `-z` / `--time-cond` spec to a reference Unix timestamp (curl's
/// `condtime`), or `None` when it is neither a valid date nor an existing file.
///
/// Rust port of curl's `parse_time_cond` (`src/tool_getparam.c`). The optional
/// leading `+` / `-` / `=` direction prefix — which [`time_cond_selector`] maps
/// to a `CURL_TIMECOND_*` id — is stripped first, so the prefix is *honored*
/// rather than parsed as part of the value. The remaining text is then resolved:
///
/// 1. as an absolute date string via [`curl_getdate`]; failing that,
/// 2. as the name of an existing file, via [`getfiletime`] on its mtime.
///
/// If neither succeeds the function returns `None`; curl's caller then disables
/// the time condition (`CURL_TIMECOND_NONE`) and warns.
pub fn parse_time_cond(spec: &str) -> Option<i64> {
    let (_selector, reference) = split_time_cond(spec);
    curl_getdate(reference).or_else(|| getfiletime(Path::new(reference)))
}

// ===========================================================================
// Unit tests — behavioral parity with curl's tool_filetime / tool_time.
//
// These exercise the safe get/set round-trip, the negative (pre-epoch) branch,
// the defensive clamp, the chrono-backed localtime conversion, and the full
// `--time-cond` parse (direction prefixes, date strings, and file fallback).
// Temporary files use the mandated throwaway prefix and are always removed.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    /// Build a unique, process-scoped path in the system temp dir. The name is
    /// prefixed so it is never mistaken for a committed fixture.
    fn temp_path(tag: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "blitzy_adhoc_test_filetime_{}_{tag}",
            std::process::id()
        ));
        path
    }

    fn create_file(path: &Path) {
        let mut file = std::fs::File::create(path).expect("create temp file");
        file.write_all(b"blitzy").expect("write temp file");
    }

    #[test]
    fn set_then_get_round_trips_seconds() {
        let path = temp_path("roundtrip");
        create_file(&path);

        let stamp: i64 = 1_000_000_000; // 2001-09-09T01:46:40Z
        setfiletime(stamp, &path);
        assert_eq!(getfiletime(&path), Some(stamp));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn get_missing_file_returns_none() {
        let path = temp_path("missing_get");
        let _ = std::fs::remove_file(&path);
        assert_eq!(getfiletime(&path), None);
    }

    #[test]
    fn set_epoch_round_trips() {
        let path = temp_path("epoch");
        create_file(&path);

        setfiletime(0, &path);
        assert_eq!(getfiletime(&path), Some(0));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn set_missing_file_is_non_fatal() {
        let path = temp_path("missing_set");
        let _ = std::fs::remove_file(&path);
        // Must not panic — curl's setfiletime only warns on failure.
        setfiletime(123, &path);
    }

    #[test]
    fn conversion_clamps_and_is_panic_free() {
        // Above the max clamps down to FILETIME_MAX.
        let high = unix_seconds_to_system_time(i64::MAX);
        let high_secs = high.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        assert_eq!(high_secs, FILETIME_MAX);

        // Below the min clamps up to FILETIME_MIN (a pre-epoch instant).
        let low = unix_seconds_to_system_time(i64::MIN);
        let low_secs = UNIX_EPOCH.duration_since(low).unwrap().as_secs() as i64;
        assert_eq!(-low_secs, FILETIME_MIN);

        // The epoch maps to the epoch exactly.
        assert_eq!(unix_seconds_to_system_time(0), UNIX_EPOCH);
    }

    #[test]
    fn localtime_preserves_the_instant() {
        let ts = 1_700_000_000; // any in-range timestamp
        let local = toolx_localtime(ts).expect("timestamp in range");
        // The absolute instant is timezone-independent, so this holds in any TZ.
        assert_eq!(local.timestamp(), ts);
    }

    #[test]
    fn selector_honors_direction_prefixes() {
        assert_eq!(time_cond_selector("2020-01-01"), CURL_TIMECOND_IFMODSINCE);
        assert_eq!(time_cond_selector("+2020-01-01"), CURL_TIMECOND_IFMODSINCE);
        assert_eq!(
            time_cond_selector("-2020-01-01"),
            CURL_TIMECOND_IFUNMODSINCE
        );
        assert_eq!(time_cond_selector("=2020-01-01"), CURL_TIMECOND_LASTMOD);
    }

    #[test]
    fn parse_time_cond_parses_dates_with_every_prefix() {
        // 2020-01-01T00:00:00Z
        let expected = 1_577_836_800;
        assert_eq!(parse_time_cond("2020-01-01"), Some(expected));
        assert_eq!(parse_time_cond("+2020-01-01"), Some(expected));
        assert_eq!(parse_time_cond("-2020-01-01"), Some(expected));
        assert_eq!(parse_time_cond("=2020-01-01"), Some(expected));
    }

    #[test]
    fn parse_time_cond_parses_rfc1123() {
        // The canonical RFC 7231 example: Sun, 06 Nov 1994 08:49:37 GMT.
        assert_eq!(
            parse_time_cond("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
    }

    #[test]
    fn parse_time_cond_falls_back_to_file_mtime() {
        let path = temp_path("timecond_file");
        create_file(&path);

        let stamp = 1_234_567_890;
        setfiletime(stamp, &path);

        // Not a parseable date, but names an existing file: resolves to its mtime.
        let spec = path.to_str().expect("utf-8 temp path");
        assert_eq!(parse_time_cond(spec), Some(stamp));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn parse_time_cond_rejects_non_date_non_file() {
        assert_eq!(
            parse_time_cond("this-is-neither-a-date-nor-a-file-9be3f1"),
            None
        );
    }
}
