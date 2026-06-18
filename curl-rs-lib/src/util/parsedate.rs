// SPDX-License-Identifier: curl
//
// Memory-safe Rust port of curl's permissive date parser.
//
// This module is the idiomatic, `unsafe`-free Rust reimplementation of
// libcurl's `lib/parsedate.c` — the tolerant date-string parser that backs
// `curl_getdate()` and the internal `Curl_getdate_capped()`. The C source is
// consulted strictly as a *behavioral and value oracle*: nothing is
// transliterated pointer-for-pointer, but every observable result — the exact
// Unix timestamp produced for a given input, and the precise set of inputs
// accepted versus rejected — is reproduced byte-for-byte.

//! Permissive HTTP / cookie date parsing (`curl_getdate` and the capped form).
//!
//! This is the Rust successor to libcurl's `lib/parsedate.c`. It powers cookie
//! `expires=` handling, HSTS and alt-svc expiry, `CURLINFO_FILETIME`, and the
//! public `curl_getdate()` entry point. Because cookie / HSTS / alt-svc expiry
//! comparisons depend on it — and the curl test-suite feeds it a large matrix
//! of odd, legacy, and deliberately malformed formats — this is one of the
//! **byte-for-byte-critical** modules: it must accept *every* date format curl
//! accepts and return the *identical* Unix timestamp (or `-1` on failure).
//!
//! # The grammar (what this parser accepts)
//!
//! The parser is a *tolerant tokenizer*, not a fixed-format matcher. It splits
//! the input on any run of non-alphanumeric bytes and classifies each token
//! independently as a weekday name, a month name, a `HH:MM[:SS]` time, a named
//! time zone, an RFC 822 numeric `±HHMM` zone, or a bare number that is then
//! disambiguated (by magnitude and position) into a day-of-month, a year, or —
//! for an eight-digit run — a compact `YYYYMMDD`. As a result the same instant
//! is recognized across wildly different spellings:
//!
//! ```text
//! Sun, 06 Nov 1994 08:49:37 GMT     ; RFC 822, updated by RFC 1123
//! Sunday, 06-Nov-94 08:49:37 GMT    ; RFC 850, obsoleted by RFC 1036
//! Sun Nov  6 08:49:37 1994          ; ANSI C asctime()
//! 06 Nov 1994 08:49:37 GMT          ; no weekday
//! 06 Nov 1994 08:49:37              ; no time zone (assume GMT)
//! 1994 Nov 6 08:49:37               ; weird order
//! 06 Nov 1994                       ; time omitted (assume 00:00:00)
//! 1994.Nov.6                        ; unusual separators
//! Sun/Nov/6/94/GMT                  ; unusual separators
//! Sun, 06 Nov 1994 08:49:37 CET     ; named non-GMT zone
//! Sun, 12 Sep 2004 15:05:58 -0700   ; RFC 822 numeric zone
//! 20040912 15:05:58 -0700           ; compact YYYYMMDD
//! ```
//!
//! # `time_t` model — i64 on the 64-bit parity targets
//!
//! curl's `time_t` width is platform-dependent; the four supported build
//! targets (x86_64 / aarch64 on Linux and macOS, AAP §0.8.1) all use a **signed
//! 64-bit** `time_t`. This port therefore models `time_t` as [`i64`] and
//! compiles exactly the `SIZEOF_TIME_T >= 5`, signed code path of the C
//! original: years before 1583 are rejected, and the saturation sentinels
//! `TIME_T_MAX` / `TIME_T_MIN` are [`i64::MAX`] / [`i64::MIN`]. A bare number is
//! capped at eight digits (`99999999`) by the tokenizer, so no parseable input
//! can drive the epoch computation anywhere near the `i64` range; the overflow
//! / underflow branches are kept (with checked arithmetic) for completeness but
//! are unreachable for real input — matching real 64-bit curl, where e.g. a
//! year-9999 expiry yields its true timestamp rather than a clamp.
//!
//! # Why the calendar math is hand-rolled (and not `chrono`)
//!
//! The final broken-down-date → epoch conversion is the exact integer formula
//! from C's `time2epoch()`, **not** a `chrono` calendar constructor. This is a
//! deliberate parity decision:
//!
//! * curl validates only coarse field ranges (`mday <= 31`, `mon <= 11`, …) and
//!   then computes a *rolled-over* timestamp for impossible dates such as
//!   "Feb 31" or "Nov 31". A calendar-aware constructor like
//!   `chrono::NaiveDate::from_ymd_opt` would instead *reject* those dates,
//!   silently diverging from curl on inputs the test-suite actually exercises.
//! * curl accepts years up to `99999999`, far outside the year range a
//!   `chrono::NaiveDate` can represent.
//!
//! Reproducing `time2epoch()` directly is the only way to stay byte-for-byte
//! faithful across the whole accepted-input matrix.
//!
//! # Memory safety
//!
//! This module contains **zero `unsafe`** and compiles under the crate-wide and
//! module-level `#![forbid(unsafe_code)]` mandated for the core crate
//! (AAP §0.7.1). The cursor is a byte slice walked with bounds-checked indices,
//! never a raw pointer, and the epoch arithmetic is fully checked, so no input
//! — however malformed — can cause an out-of-bounds access, an overflow panic,
//! or any other trap, matching curl's "never crash on bad input" contract.

#![forbid(unsafe_code)]
// This module authors curl's complete `parsedate.c` surface — the public
// `curl_getdate` / `getdate_capped` entry points plus the shared `CURL_WKDAY` /
// `CURL_MONTH` name tables that the C tree exposes non-`static` for the FTP and
// FILE code. In a partially assembled workspace not every entry point yet has
// an in-crate caller (the cookie / HSTS / alt-svc / getinfo / FTP / FILE
// modules that consume this one are authored in parallel), so — exactly as in
// the sibling `util/` ports (`strparse.rs`, `timeval.rs`, `strerror.rs`) — the
// full surface is provided up front and `dead_code` is allowed to keep the
// module self-contained without tripping the workspace's `-D warnings` gate. It
// does not mask defects: every private helper is exercised by the public
// functions and the unit tests below.
#![allow(dead_code)]

use crate::util::strparse::{strcasecompare, Str};

// =============================================================================
// Static tables — exact transcription of `lib/parsedate.c`
// =============================================================================

/// Abbreviated (three-letter) weekday names, `Mon`(0) … `Sun`(6).
///
/// This is the Rust image of C's `const char * const Curl_wkday[]`, which the C
/// tree exposes non-`static` because the FTP and FILE code reuse it when
/// formatting dates. It is published here for the same reason. Index order is
/// Monday-first to match the weekday numbering used internally by the parser.
pub const CURL_WKDAY: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

/// Abbreviated (three-letter) month names, `Jan`(0) … `Dec`(11).
///
/// Rust image of C's `const char * const Curl_month[]`, likewise exposed
/// non-`static` in C for the FTP and FILE code and published here for parity.
/// Index order is zero-based (`Jan == 0`), matching the `month` field the
/// parser fills.
pub const CURL_MONTH: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Full weekday names, `Monday`(0) … `Sunday`(6).
///
/// Rust image of the `static const char * const weekday[]` table. The parser
/// consults this table for tokens longer than three letters and the
/// [`CURL_WKDAY`] table for exactly-three-letter tokens, reproducing
/// `checkday()`.
const WEEKDAY: [&str; 7] = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
];

/// Daylight-saving adjustment (in minutes) applied to several zone offsets,
/// mirroring C's `#define tDAYZONE (-60)`.
const TDAYZONE: i32 = -60;

/// A named time zone and its offset from GMT, in **minutes**.
///
/// Rust image of C's `struct tzinfo { char name[5]; int offset; }`. The stored
/// `offset` is the number of minutes that must be *added* to the local wall
/// time to obtain GMT (so US zones west of Greenwich are positive and European
/// zones east of it are negative), exactly as in the C table.
struct TzInfo {
    /// Upper-case zone name (1–4 ASCII letters); matched case-insensitively.
    name: &'static str,
    /// Offset from GMT in minutes (added to local time to reach GMT).
    offset: i32,
}

/// Frequently used time-zone names, transcribed verbatim from the `tz[]` table
/// in `lib/parsedate.c` (the set the historical `getdate` parser supported).
///
/// The list ends with the RFC 822 single-letter military zones; note the signs
/// follow *actual military usage* (corrected per RFC 1123), and `J` (Juliet) is
/// intentionally absent because it denotes the observer's local time.
//
// `identity_op` / `neg_multiply` are allowed here so the offsets stay a
// character-for-character transcription of the C `tz[]` table (`0 + tDAYZONE`,
// `1 * 60`, `-1 * 60`, …); this keeps the table trivially diff-able against
// `lib/parsedate.c` for parity auditing. The computed values are unaffected.
//
// `rustfmt::skip` preserves that hand-aligned, column-for-column layout (which
// `rustfmt` would otherwise collapse), keeping the table a faithful visual
// mirror of the C source; the rest of the file is fully `rustfmt`-clean.
#[rustfmt::skip]
#[allow(clippy::identity_op, clippy::neg_multiply)]
const TZ: &[TzInfo] = &[
    TzInfo { name: "GMT", offset: 0 },             // Greenwich Mean
    TzInfo { name: "UT", offset: 0 },              // Universal Time
    TzInfo { name: "UTC", offset: 0 },             // Universal (Coordinated)
    TzInfo { name: "WET", offset: 0 },             // Western European
    TzInfo { name: "BST", offset: 0 + TDAYZONE },  // British Summer
    TzInfo { name: "WAT", offset: 60 },            // West Africa
    TzInfo { name: "AST", offset: 240 },           // Atlantic Standard
    TzInfo { name: "ADT", offset: 240 + TDAYZONE }, // Atlantic Daylight
    TzInfo { name: "EST", offset: 300 },           // Eastern Standard
    TzInfo { name: "EDT", offset: 300 + TDAYZONE }, // Eastern Daylight
    TzInfo { name: "CST", offset: 360 },           // Central Standard
    TzInfo { name: "CDT", offset: 360 + TDAYZONE }, // Central Daylight
    TzInfo { name: "MST", offset: 420 },           // Mountain Standard
    TzInfo { name: "MDT", offset: 420 + TDAYZONE }, // Mountain Daylight
    TzInfo { name: "PST", offset: 480 },           // Pacific Standard
    TzInfo { name: "PDT", offset: 480 + TDAYZONE }, // Pacific Daylight
    TzInfo { name: "YST", offset: 540 },           // Yukon Standard
    TzInfo { name: "YDT", offset: 540 + TDAYZONE }, // Yukon Daylight
    TzInfo { name: "HST", offset: 600 },           // Hawaii Standard
    TzInfo { name: "HDT", offset: 600 + TDAYZONE }, // Hawaii Daylight
    TzInfo { name: "CAT", offset: 600 },           // Central Alaska
    TzInfo { name: "AHST", offset: 600 },          // Alaska-Hawaii Standard
    TzInfo { name: "NT", offset: 660 },            // Nome
    TzInfo { name: "IDLW", offset: 720 },          // International Date Line West
    TzInfo { name: "CET", offset: -60 },           // Central European
    TzInfo { name: "MET", offset: -60 },           // Middle European
    TzInfo { name: "MEWT", offset: -60 },          // Middle European Winter
    TzInfo { name: "MEST", offset: -60 + TDAYZONE }, // Middle European Summer
    TzInfo { name: "CEST", offset: -60 + TDAYZONE }, // Central European Summer
    TzInfo { name: "MESZ", offset: -60 + TDAYZONE }, // Middle European Summer
    TzInfo { name: "FWT", offset: -60 },           // French Winter
    TzInfo { name: "FST", offset: -60 + TDAYZONE }, // French Summer
    TzInfo { name: "EET", offset: -120 },          // Eastern Europe, USSR Zone 1
    TzInfo { name: "WAST", offset: -420 },         // West Australian Standard
    TzInfo { name: "WADT", offset: -420 + TDAYZONE }, // West Australian Daylight
    TzInfo { name: "CCT", offset: -480 },          // China Coast, USSR Zone 7
    TzInfo { name: "JST", offset: -540 },          // Japan Standard, USSR Zone 8
    TzInfo { name: "EAST", offset: -600 },         // Eastern Australian Standard
    TzInfo { name: "EADT", offset: -600 + TDAYZONE }, // Eastern Australian Daylight
    TzInfo { name: "GST", offset: -600 },          // Guam Standard, USSR Zone 9
    TzInfo { name: "NZT", offset: -720 },          // New Zealand
    TzInfo { name: "NZST", offset: -720 },         // New Zealand Standard
    TzInfo { name: "NZDT", offset: -720 + TDAYZONE }, // New Zealand Daylight
    TzInfo { name: "IDLE", offset: -720 },         // International Date Line East
    // Military single-letter zones (RFC 822, corrected signs per RFC 1123).
    TzInfo { name: "A", offset: 1 * 60 },          // Alpha
    TzInfo { name: "B", offset: 2 * 60 },          // Bravo
    TzInfo { name: "C", offset: 3 * 60 },          // Charlie
    TzInfo { name: "D", offset: 4 * 60 },          // Delta
    TzInfo { name: "E", offset: 5 * 60 },          // Echo
    TzInfo { name: "F", offset: 6 * 60 },          // Foxtrot
    TzInfo { name: "G", offset: 7 * 60 },          // Golf
    TzInfo { name: "H", offset: 8 * 60 },          // Hotel
    TzInfo { name: "I", offset: 9 * 60 },          // India
    // "J" (Juliet) is intentionally omitted — it means the observer's local time.
    TzInfo { name: "K", offset: 10 * 60 },         // Kilo
    TzInfo { name: "L", offset: 11 * 60 },         // Lima
    TzInfo { name: "M", offset: 12 * 60 },         // Mike
    TzInfo { name: "N", offset: -1 * 60 },         // November
    TzInfo { name: "O", offset: -2 * 60 },         // Oscar
    TzInfo { name: "P", offset: -3 * 60 },         // Papa
    TzInfo { name: "Q", offset: -4 * 60 },         // Quebec
    TzInfo { name: "R", offset: -5 * 60 },         // Romeo
    TzInfo { name: "S", offset: -6 * 60 },         // Sierra
    TzInfo { name: "T", offset: -7 * 60 },         // Tango
    TzInfo { name: "U", offset: -8 * 60 },         // Uniform
    TzInfo { name: "V", offset: -9 * 60 },         // Victor
    TzInfo { name: "W", offset: -10 * 60 },        // Whiskey
    TzInfo { name: "X", offset: -11 * 60 },        // X-ray
    TzInfo { name: "Y", offset: -12 * 60 },        // Yankee
    TzInfo { name: "Z", offset: 0 },               // Zulu, zero meridian (UTC)
];

/// Longest name this parser will scan as a single alphabetic token
/// (`Wednesday` is nine letters; C uses the same `#define NAME_LEN 12` cap as a
/// generous upper bound). An alphabetic run that reaches this length is treated
/// as un-classifiable and fails the parse, exactly as in C.
const NAME_LEN: usize = 12;

// =============================================================================
// Small bounds-checked byte helpers (keep the parser panic-free)
// =============================================================================

/// Returns the byte at `i`, or `None` if `i` is past the end of `bytes`.
///
/// This is the safe-Rust replacement for the C idiom of dereferencing a
/// `const char *` that may sit on the terminating NUL: out of range simply
/// yields `None` (the equivalent of reading `'\0'` and stopping).
#[inline]
fn byte_at(bytes: &[u8], i: usize) -> Option<u8> {
    bytes.get(i).copied()
}

/// Returns `true` when `bytes[i]` exists and is an ASCII decimal digit.
#[inline]
fn is_digit_at(bytes: &[u8], i: usize) -> bool {
    matches!(bytes.get(i), Some(b) if b.is_ascii_digit())
}

// =============================================================================
// Token classifiers — `checkday` / `checkmonth` / `checktz`
// =============================================================================

/// Classifies an alphabetic token as a weekday.
///
/// Mirrors C's `checkday()`: tokens longer than three letters are matched
/// against the full [`WEEKDAY`] names, exactly-three-letter tokens against the
/// abbreviated [`CURL_WKDAY`] names, and anything shorter is rejected. Matching
/// is ASCII case-insensitive and length-exact (via [`strcasecompare`], which
/// only reports equality when the lengths match).
///
/// Returns the weekday index `0..=6` (Monday … Sunday) or `-1` if the token is
/// not a weekday name.
fn checkday(check: &[u8]) -> i32 {
    let what: &[&str] = if check.len() > 3 {
        &WEEKDAY
    } else if check.len() == 3 {
        &CURL_WKDAY
    } else {
        return -1; // too short to be any weekday name
    };
    for (i, name) in what.iter().enumerate() {
        if strcasecompare(check, name.as_bytes()) {
            return i as i32;
        }
    }
    -1
}

/// Classifies an alphabetic token as a month.
///
/// Mirrors C's `checkmonth()`: only exactly-three-letter tokens are considered,
/// compared ASCII case-insensitively against [`CURL_MONTH`]. Returns the month
/// index `0..=11` (January … December) or `-1` if the token is not a month
/// name.
fn checkmonth(check: &[u8]) -> i32 {
    if check.len() != 3 {
        return -1; // not a three-letter month abbreviation
    }
    for (i, name) in CURL_MONTH.iter().enumerate() {
        if strcasecompare(check, name.as_bytes()) {
            return i as i32;
        }
    }
    -1
}

/// Classifies an alphabetic token as a named time zone.
///
/// Mirrors C's `checktz()`: tokens longer than four letters cannot be a zone
/// name and are rejected immediately; otherwise the token is compared ASCII
/// case-insensitively against the [`TZ`] table. Returns the offset between the
/// zone and GMT **in seconds** (table minutes × 60; `0` for GMT/UT/UTC/Z) or
/// `-1` when the token is not a known zone. The value is always a multiple of
/// 60, so the `-1` "not found" sentinel can never collide with a real offset.
fn checktz(check: &[u8]) -> i32 {
    if check.len() > 4 {
        return -1; // longer than any valid time-zone name
    }
    for zone in TZ {
        if strcasecompare(check, zone.name.as_bytes()) {
            return zone.offset * 60;
        }
    }
    -1
}

// =============================================================================
// Numeric / time token parsing — `oneortwodigit` / `match_time`
// =============================================================================

/// Reads a one- or two-digit decimal number starting at `start`.
///
/// Mirrors C's `oneortwodigit()`: consumes a single digit, then a second one
/// only if present, returning the value together with the index just past the
/// consumed digit(s). Callers only invoke this when `bytes[start]` is already
/// known to be a digit; the `byte_at` guards nonetheless keep the function total
/// (it never panics and never reads out of range).
fn oneortwodigit(bytes: &[u8], start: usize) -> (i32, usize) {
    let d0 = match byte_at(bytes, start) {
        Some(b) if b.is_ascii_digit() => i32::from(b - b'0'),
        // Defensive: callers guarantee a digit here, so this is unreachable.
        _ => return (0, start),
    };
    match byte_at(bytes, start + 1) {
        Some(b) if b.is_ascii_digit() => (d0 * 10 + i32::from(b - b'0'), start + 2),
        _ => (d0, start + 1),
    }
}

/// Tries to read a `HH:MM[:SS]` time starting at `start`.
///
/// Mirrors C's `match_time()`, including its use of [`oneortwodigit`] so each
/// component may be one or two digits. Validates `hour < 24`, `minute < 60`,
/// and (when present) `second <= 60` (a leap second is permitted). On success
/// returns `(hour, minute, second, end)` where `end` is the index just past the
/// matched time; on any mismatch returns `None` and consumes nothing.
fn match_time(bytes: &[u8], start: usize) -> Option<(i32, i32, i32, usize)> {
    let (hh, p) = oneortwodigit(bytes, start);
    // Need "HH:" followed by at least one minute digit.
    if hh >= 24 || byte_at(bytes, p) != Some(b':') || !is_digit_at(bytes, p + 1) {
        return None;
    }

    let (mm, p) = oneortwodigit(bytes, p + 1);
    if mm >= 60 {
        return None; // minutes out of range
    }

    if byte_at(bytes, p) == Some(b':') && is_digit_at(bytes, p + 1) {
        // "HH:MM:SS"
        let (ss, p) = oneortwodigit(bytes, p + 1);
        if ss <= 60 {
            Some((hh, mm, ss, p))
        } else {
            None // seconds out of range
        }
    } else {
        // "HH:MM" — seconds default to zero.
        Some((hh, mm, 0, p))
    }
}

// =============================================================================
// Calendar → epoch — `time2epoch`
// =============================================================================

/// Converts a broken-down GMT date to seconds since the Unix epoch.
///
/// This is the exact integer formula from C's `time2epoch()` — a GMT-only
/// `mktime` that does **no** day-of-month validity checking (so impossible
/// dates such as "Feb 31" roll over rather than being rejected, matching curl).
/// All arithmetic is checked, so the function is total: a result that would not
/// fit in [`i64`] yields `None` instead of wrapping or panicking. For any input
/// the tokenizer can actually produce (year ≤ `99999999`) the result fits
/// comfortably and `None` is never returned; the checked path exists only to
/// keep the no-panic guarantee absolute.
///
/// `mon` is the zero-based month (`0..=11`); the caller validates the range, and
/// an out-of-range `mon` is treated defensively as cumulative-days `0`.
fn time2epoch_checked(
    sec: i64,
    min: i64,
    hour: i64,
    mday: i64,
    mon: i64,
    year: i64,
) -> Option<i64> {
    // Days elapsed at the start of each month in a non-leap year.
    const MONTH_DAYS_CUMULATIVE: [i64; 12] =
        [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let cum = MONTH_DAYS_CUMULATIVE
        .get(usize::try_from(mon).unwrap_or(usize::MAX))
        .copied()
        .unwrap_or(0);

    // Leap days between 1970 and the target year (the current year's leap day
    // only counts once March has been reached). The `1969/...` constants and
    // truncating division match C exactly. The initial `year - (mon <= 1)` is
    // done with `checked_sub` so the function stays total even for an absurd
    // `year == i64::MIN` (unreachable through the tokenizer, but it keeps the
    // documented no-panic contract absolute); for every real year the checked
    // subtraction is identical to the C expression. The following combination
    // of truncating divisions is magnitude-bounded by `leap_days` itself and so
    // cannot overflow for any `i64` input.
    let mut leap_days = year.checked_sub(i64::from(mon <= 1))?;
    leap_days = (leap_days / 4) - (leap_days / 100) + (leap_days / 400) - (1969 / 4) + (1969 / 100)
        - (1969 / 400);

    // ((((year-1970)*365 + leap_days + cum + mday - 1)*24 + hour)*60 + min)*60 + sec
    let days = year
        .checked_sub(1970)?
        .checked_mul(365)?
        .checked_add(leap_days)?
        .checked_add(cum)?
        .checked_add(mday)?
        .checked_sub(1)?;
    let hours = days.checked_mul(24)?.checked_add(hour)?;
    let mins = hours.checked_mul(60)?.checked_add(min)?;
    mins.checked_mul(60)?.checked_add(sec)
}

// =============================================================================
// Core parser
// =============================================================================

/// Which kind of value the next bare number should be assumed to be.
///
/// Mirrors the relevant arms of C's `enum assume` (the unused `DATE_TIME` arm is
/// intentionally omitted — `dignext` only ever toggles between day-of-month and
/// year in the C state machine).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Assume {
    /// The next plain number should be tried as a day-of-month first.
    Mday,
    /// The next plain number should be tried as a year first.
    Year,
}

/// Outcome of the internal [`parsedate`] state machine.
///
/// These map one-to-one onto C's `PARSEDATE_OK` / `PARSEDATE_FAIL` /
/// `PARSEDATE_LATER` / `PARSEDATE_SOONER` return codes. On the 64-bit `time_t`
/// model `Later` / `Sooner` are unreachable for any parseable input (see the
/// module docs); they are retained so the saturating contract of
/// [`getdate_capped`] is complete and so the behavior matches the C source
/// arm-for-arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseResult {
    /// A successful conversion to the contained Unix timestamp.
    Ok(i64),
    /// The input could not be parsed as a date.
    Fail,
    /// The date overflowed the high end of `time_t` (saturates to [`i64::MAX`]).
    Later,
    /// The date underflowed the low end of `time_t` (saturates to [`i64::MIN`]).
    Sooner,
}

/// The tolerant date tokenizer and field assembler — the heart of the module.
///
/// This reproduces C's `parsedate()` exactly: it walks the input as a sequence
/// of up to six tokens (splitting on any non-alphanumeric run), classifies each
/// token, fills the broken-down-date fields with curl's disambiguation rules,
/// and finally converts to a Unix timestamp via [`time2epoch_checked`], applying
/// the time-zone offset. See [`ParseResult`] for the meaning of each outcome.
fn parsedate(date: &str) -> ParseResult {
    let bytes = date.as_bytes();
    let mut i = 0usize;

    // -1 means "not yet seen" for each field, matching the C sentinels.
    let mut wdaynum: i32 = -1; // weekday 0..6 (unused after parsing, as in C)
    let mut monnum: i32 = -1; // month 0..11
    let mut mdaynum: i32 = -1; // day-of-month 1..31
    let mut hournum: i32 = -1;
    let mut minnum: i32 = -1;
    let mut secnum: i32 = -1;
    let mut yearnum: i32 = -1;
    let mut tzoff: i32 = -1; // zone offset in seconds
    let mut dignext = Assume::Mday;
    let mut part: u32 = 0; // at most six parts are inspected

    while i < bytes.len() && part < 6 {
        // Skip everything that is not an ASCII letter or digit (the C `skip()`).
        while i < bytes.len() && !bytes[i].is_ascii_alphanumeric() {
            i += 1;
        }

        if i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            // ---- an alphabetic name: weekday, month, or time zone ----
            let name_start = i;
            let mut namelen = 0usize;
            while i < bytes.len() && bytes[i].is_ascii_alphabetic() && namelen < NAME_LEN {
                i += 1;
                namelen += 1;
            }
            let token = &bytes[name_start..i];
            let mut found = false;

            // A run that reached NAME_LEN is too long to be any known name.
            if namelen != NAME_LEN {
                if wdaynum == -1 {
                    let r = checkday(token);
                    if r != -1 {
                        wdaynum = r;
                        found = true;
                    }
                }
                if !found && monnum == -1 {
                    let r = checkmonth(token);
                    if r != -1 {
                        monnum = r;
                        found = true;
                    }
                }
                if !found && tzoff == -1 {
                    let r = checktz(token);
                    if r != -1 {
                        tzoff = r;
                        found = true;
                    }
                }
            }

            if !found {
                return ParseResult::Fail; // an unrecognized name => bad string
            }
            // `i` already points just past the scanned name.
        } else if i < bytes.len() && bytes[i].is_ascii_digit() {
            // ---- a digit run: time, numeric zone, YYYYMMDD, day, or year ----
            let mut handled = false;

            // Only the first time-looking token becomes the time.
            if secnum == -1 {
                if let Some((h, m, s, end)) = match_time(bytes, i) {
                    hournum = h;
                    minnum = m;
                    secnum = s;
                    i = end;
                    handled = true;
                }
            }

            if !handled {
                let digit_start = i;
                let mut cursor = Str::from_bytes(&bytes[digit_start..]);
                let mut lval: u64 = 0;
                // A number that does not fit in 8 digits is a parse failure,
                // exactly as the C `curlx_str_number(..., 99999999)` guard.
                if cursor.curlx_str_number(&mut lval, 99_999_999).is_err() {
                    return ParseResult::Fail;
                }
                let num_digits = (bytes.len() - digit_start) - cursor.curlx_strlen();
                // lval <= 99_999_999 fits losslessly in both u32 and i32.
                let val = lval as u32;
                i = digit_start + num_digits;

                let mut found = false;

                // The byte immediately before the digit run (the C `date[-1]`),
                // available only when the run does not start at offset zero.
                let prev = if digit_start > 0 {
                    byte_at(bytes, digit_start - 1)
                } else {
                    None
                };

                if tzoff == -1
                    && num_digits == 4
                    && val <= 1400
                    && (prev == Some(b'+') || prev == Some(b'-'))
                {
                    // Four digits <= 1400 (covers all real offsets, +1300/+1400
                    // included) immediately preceded by '+'/'-': an RFC 822 zone.
                    found = true;
                    let off = (((val / 100) * 60 + (val % 100)) * 60) as i32;
                    // '+'/'-' express local-vs-GMT; the stored offset is reversed
                    // so that `t += tzoff` later yields GMT.
                    tzoff = if prev == Some(b'+') { -off } else { off };
                } else if num_digits == 8 && yearnum == -1 && monnum == -1 && mdaynum == -1 {
                    // Eight digits with nothing set yet: a compact YYYYMMDD.
                    found = true;
                    yearnum = (val / 10000) as i32;
                    monnum = ((val % 10000) / 100) as i32 - 1; // month is 0..11
                    mdaynum = (val % 100) as i32;
                }

                // A plain number defaults to the day-of-month when one is still
                // wanted; note `dignext` advances to YEAR even on a miss, so a
                // value > 31 falls through to the year test below in the same
                // iteration (this is how "1994 Nov 6" is accepted).
                if !found && dignext == Assume::Mday && mdaynum == -1 {
                    // C: (val > 0) && (val < 32)
                    if (1..32).contains(&val) {
                        mdaynum = val as i32;
                        found = true;
                    }
                    dignext = Assume::Year;
                }

                if !found && dignext == Assume::Year && yearnum == -1 {
                    yearnum = val as i32;
                    found = true;
                    // Two-digit-year pivot, EXACTLY as curl: > 70 => 1900s
                    // (71..99 => 1971..1999), otherwise 2000s (0..70 => 2000..2070).
                    if yearnum < 100 {
                        if yearnum > 70 {
                            yearnum += 1900;
                        } else {
                            yearnum += 2000;
                        }
                    }
                    if mdaynum == -1 {
                        dignext = Assume::Mday;
                    }
                }

                if !found {
                    return ParseResult::Fail;
                }
            }
        }

        part += 1;
    }

    // An omitted time means midnight.
    if secnum == -1 {
        secnum = 0;
        minnum = 0;
        hournum = 0;
    }

    // Day, month and year are all mandatory.
    if mdaynum == -1 || monnum == -1 || yearnum == -1 {
        return ParseResult::Fail;
    }

    // 64-bit signed time_t path: the proleptic Gregorian calendar starts 1583.
    if yearnum < 1583 {
        return ParseResult::Fail;
    }

    // Reject clearly illegal field values (a leap second `secnum == 60` is OK).
    if mdaynum > 31 || monnum > 11 || hournum > 23 || minnum > 59 || secnum > 60 {
        return ParseResult::Fail;
    }

    let t = match time2epoch_checked(
        i64::from(secnum),
        i64::from(minnum),
        i64::from(hournum),
        i64::from(mdaynum),
        i64::from(monnum),
        i64::from(yearnum),
    ) {
        Some(v) => v,
        // Unreachable for parseable input; kept so the contract stays total.
        None => {
            return if yearnum >= 1970 {
                ParseResult::Later
            } else {
                ParseResult::Sooner
            };
        }
    };

    // Default an absent zone to GMT, then apply it.
    let tzoff = i64::from(if tzoff == -1 { 0 } else { tzoff });

    // Mirror C's single overflow guard: a positive zone push past TIME_T_MAX.
    if tzoff > 0 && t > i64::MAX - tzoff {
        return ParseResult::Later;
    }

    // `saturating_add` cannot actually saturate here (both operands are tiny
    // relative to i64) but keeps the addition panic-free unconditionally.
    ParseResult::Ok(t.saturating_add(tzoff))
}

// =============================================================================
// Public API
// =============================================================================

/// Parses a date string into a Unix timestamp, or returns `-1` on failure.
///
/// This is the Rust image of C's
/// `time_t curl_getdate(const char *p, const time_t *now)`. The legacy `now`
/// argument was unused by curl and is dropped here.
///
/// The full curl format matrix is accepted (see the module docs): RFC 822 /
/// 1123, RFC 850, ANSI C `asctime`, weekday-less and zone-less variants, weird
/// token orders, unusual separators, named and numeric time zones, and compact
/// `YYYYMMDD`. When no time is present it defaults to `00:00:00`; when no zone
/// is present GMT is assumed.
///
/// # Return value
///
/// The number of seconds since the Unix epoch (1970-01-01T00:00:00Z) for the
/// parsed instant, or `-1` if the input is not a recognizable date. As a quirk
/// preserved from curl, the single valid instant whose timestamp is exactly
/// `-1` (one second before the epoch) is reported as `0` so it cannot be
/// mistaken for the error sentinel.
///
/// # Examples
///
/// ```ignore
/// use curl_rs_lib::util::parsedate::curl_getdate;
/// assert_eq!(curl_getdate("Sun, 06 Nov 1994 08:49:37 GMT"), 784_111_777);
/// assert_eq!(curl_getdate("not a date"), -1);
/// ```
#[must_use]
pub fn curl_getdate(date: &str) -> i64 {
    match parsedate(date) {
        ParseResult::Ok(t) => {
            // Avoid returning the -1 error sentinel for a working scenario.
            if t == -1 {
                0
            } else {
                t
            }
        }
        // A failure, or an out-of-range over/underflow, is reported as -1.
        ParseResult::Fail | ParseResult::Later | ParseResult::Sooner => -1,
    }
}

/// Parses a date string, **saturating** out-of-range results instead of failing.
///
/// This is the Rust image of C's
/// `int Curl_getdate_capped(const char *date, time_t *output)`, used internally
/// by the cookie, HSTS, and alt-svc expiry logic, where a far-future expiry
/// should clamp rather than be rejected.
///
/// # Difference from [`curl_getdate`]
///
/// The two functions share the exact same parser; they differ only in how they
/// report the non-`Ok` outcomes:
///
/// * **Parse failure** — [`curl_getdate`] returns `-1`; this returns [`None`].
/// * **Overflow / underflow** of `time_t` — [`curl_getdate`] reports `-1`
///   (failure), whereas this **saturates**: [`Some`]\([`i64::MAX`]\) for an
///   overflow, [`Some`]\([`i64::MIN`]\) for an underflow. This is the whole
///   point of the "capped" form: a year-far-in-the-future expiry clamps to the
///   maximum representable time rather than being thrown away.
/// * The `-1 → 0` bump that [`curl_getdate`] applies is **not** performed here;
///   the genuine timestamp (including `-1`) is returned verbatim, matching the C
///   `Curl_getdate_capped`, which writes the raw `time_t` to its out-parameter.
///
/// On this build's 64-bit signed `time_t` model the over/underflow branches are
/// unreachable for any parseable input (a bare number is capped at eight
/// digits, so the epoch never approaches the [`i64`] range). Consequently, for
/// every real input this function returns `Some(v)` with the same `v` that
/// [`curl_getdate`] returns (apart from the `-1 → 0` bump) — which is exactly
/// how real curl behaves on a 64-bit platform, where e.g. a year-9999 expiry
/// yields its true timestamp.
///
/// # Return value
///
/// `Some(seconds_since_epoch)` on a successful (or saturated) parse, or `None`
/// if the input is not a recognizable date.
#[must_use]
pub fn getdate_capped(date: &str) -> Option<i64> {
    match parsedate(date) {
        ParseResult::Ok(t) => Some(t),
        ParseResult::Later => Some(i64::MAX),
        ParseResult::Sooner => Some(i64::MIN),
        ParseResult::Fail => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The canonical GMT instant used throughout: 1994-11-06 08:49:37 GMT.
    // (Independently confirmed with Python `calendar.timegm`.)
    const CANON: i64 = 784_111_777;
    // The same calendar day at midnight GMT (time omitted => 00:00:00).
    const MIDNIGHT: i64 = 784_080_000;

    // ---- The headline parity assertion ---------------------------------------

    #[test]
    fn canonical_rfc1123() {
        // The single most important value in the whole module.
        assert_eq!(curl_getdate("Sun, 06 Nov 1994 08:49:37 GMT"), CANON);
    }

    // ---- Every GMT-equivalent spelling yields the SAME instant ---------------

    #[test]
    fn gmt_variants_all_equal_canonical() {
        // Each of these denotes 1994-11-06 08:49:37 GMT and must map to CANON.
        let variants = [
            "Sun, 06 Nov 1994 08:49:37 GMT",  // RFC 822 / 1123
            "Sunday, 06-Nov-94 08:49:37 GMT", // RFC 850
            "Sun Nov  6 08:49:37 1994",       // ANSI C asctime (double space)
            "06 Nov 1994 08:49:37 GMT",       // no weekday
            "Nov 6 1994 08:49:37",            // no weekday, no zone (=> GMT)
            "06 Nov 1994 08:49:37",           // no zone (=> GMT)
            "06-Nov-94 08:49:37 GMT",         // RFC 850 without weekday
            "1994 Nov 6 08:49:37",            // weird order
            "Nov 1994 6 08:49:37",            // weird order
            "94 6 Nov 08:49:37",              // weird order (GNU date fails)
            "GMT 08:49:37 06-Nov-94 Sunday",  // fully reversed order
        ];
        for v in variants {
            assert_eq!(curl_getdate(v), CANON, "variant `{v}` should equal CANON");
        }
    }

    #[test]
    fn time_omitted_is_midnight() {
        // Time left out => 00:00:00; zone left out => GMT.
        let variants = [
            "06 Nov 1994",      // no time, no zone
            "1994 Nov 6",       // weird order, no time
            "1994.Nov.6",       // unusual '.' separators
            "Sun/Nov/6/94/GMT", // unusual '/' separators (2-digit year)
            "Sun Nov 6 94",     // time left out, 2-digit year
            "06-Nov-94",        // RFC 850 date only
        ];
        for v in variants {
            assert_eq!(
                curl_getdate(v),
                MIDNIGHT,
                "variant `{v}` should be midnight"
            );
        }
    }

    // ---- Named non-GMT zones shift the instant correctly ---------------------

    #[test]
    fn named_zone_offsets() {
        // CET = UTC+1  => 08:49:37 CET is 07:49:37 UTC (CANON - 3600).
        assert_eq!(curl_getdate("Sun, 06 Nov 1994 08:49:37 CET"), 784_108_177);
        assert_eq!(784_108_177, CANON - 3600);
        // EST = UTC-5  => 08:49:37 EST is 13:49:37 UTC (CANON + 5*3600).
        assert_eq!(curl_getdate("06 Nov 1994 08:49:37 EST"), 784_129_777);
        assert_eq!(784_129_777, CANON + 5 * 3600);
        // UTC / UT / Z / GMT are all zero offset and equal CANON.
        for z in ["GMT", "UTC", "UT", "Z"] {
            assert_eq!(curl_getdate(&format!("06 Nov 1994 08:49:37 {z}")), CANON);
        }
    }

    // ---- RFC 822 numeric zones (`±HHMM`) -------------------------------------

    #[test]
    fn numeric_zone_offsets() {
        // +0100 => local is 1h ahead of UTC => 07:49:37 UTC (CANON - 3600).
        assert_eq!(curl_getdate("Sun, 06 Nov 1994 08:49:37 +0100"), 784_108_177);
        // -0700 => local is 7h behind UTC => 15:49:37 UTC (CANON + 7*3600).
        assert_eq!(curl_getdate("Sun, 06 Nov 1994 08:49:37 -0700"), 784_136_977);
        assert_eq!(784_136_977, CANON + 7 * 3600);
        // The canonical curl example: 2004-09-12 15:05:58 -0700 = 22:05:58 UTC.
        assert_eq!(
            curl_getdate("Sun, 12 Sep 2004 15:05:58 -0700"),
            1_095_026_758
        );
    }

    // ---- Compact numerical date strings (YYYYMMDD) ---------------------------

    #[test]
    fn compact_yyyymmdd() {
        // Bare YYYYMMDD => that calendar day at midnight GMT.
        assert_eq!(curl_getdate("20041106"), 1_099_699_200);
        // YYYYMMDD + time + numeric zone (curl's own example).
        assert_eq!(curl_getdate("20040912 15:05:58 -0700"), 1_095_026_758);
        // YYYYMMDD + numeric zone, no time (=> midnight then shifted).
        // 2004-09-11 00:00:00 +0200 = 2004-09-10 22:00:00 UTC.
        assert_eq!(curl_getdate("20040911 +0200"), 1_094_853_600);
    }

    // ---- Case-insensitivity of names -----------------------------------------

    #[test]
    fn names_are_case_insensitive() {
        assert_eq!(curl_getdate("sun, 06 nov 1994 08:49:37 gmt"), CANON);
        assert_eq!(curl_getdate("SUN, 06 NOV 1994 08:49:37 GMT"), CANON);
        assert_eq!(curl_getdate("Sun, 06 nOv 1994 08:49:37 cEt"), 784_108_177);
    }

    // ---- The 2-digit-year pivot, EXACTLY as curl -----------------------------

    #[test]
    fn two_digit_year_pivot() {
        // With the day-of-month already fixed, the trailing number is the year.
        // Pivot: > 70 => 1900s, otherwise => 2000s (so 70 maps to 2070!).
        assert_eq!(curl_getdate("6 Jan 70"), 3_156_192_000, "70 -> 2070");
        assert_eq!(curl_getdate("6 Jan 71"), 31_968_000, "71 -> 1971");
        assert_eq!(curl_getdate("6 Jan 69"), 3_124_656_000, "69 -> 2069");
        assert_eq!(curl_getdate("6 Jan 00"), 947_116_800, "00 -> 2000");
        assert_eq!(curl_getdate("6 Jan 99"), 915_580_800, "99 -> 1999");
        // 94 -> 1994 (the value embedded in many of the variants above).
        assert_eq!(curl_getdate("6 Nov 94"), MIDNIGHT, "94 -> 1994");
    }

    // ---- Malformed / empty / garbage all fail with -1 ------------------------

    #[test]
    fn malformed_returns_minus_one() {
        let bad = [
            "",                     // empty
            "   ",                  // only separators
            "not a date",           // unrecognized words
            "garbage",              // single long word
            "Mon",                  // weekday only (no date fields)
            "06 Nov",               // missing year
            "Nov 1994",             // missing day
            "06 1994",              // missing month
            "32 Nov 1994",          // 32 is neither a valid day nor leaves a year slot
            "Sun Mon Nov 6 1994",   // two weekday names
            "123456789",            // 9-digit number exceeds the 8-digit cap
            "06 Nov 1994 25:00:00", // hour out of range is not a time, then no year slot
        ];
        for b in bad {
            assert_eq!(curl_getdate(b), -1, "`{b}` should fail with -1");
        }
    }

    // ---- curl's "Feb 31" tolerance (why chrono is NOT used) ------------------

    #[test]
    fn impossible_dates_roll_over_like_curl() {
        // curl validates only `mday <= 31`, so "Feb 31" is accepted and rolls
        // over to Mar 2 (2000 is a leap year). A calendar-aware library would
        // reject it — this test pins curl's behavior.
        assert_eq!(curl_getdate("Feb 31 2000"), 951_955_200);
        assert_eq!(curl_getdate("Feb 31 2000"), curl_getdate("Mar 2 2000"));
    }

    // ---- Only the first six tokens are inspected -----------------------------

    #[test]
    fn part_limit_ignores_trailing_tokens() {
        // The six leading tokens fully specify the date; a 7th token (which on
        // its own would be unrecognized) is never reached.
        assert_eq!(
            curl_getdate("Sun, 06 Nov 1994 08:49:37 GMT EXTRA-IGNORED"),
            CANON
        );
    }

    // ---- Far-future year: real value, NOT a clamp (64-bit parity) ------------

    #[test]
    fn far_future_year_is_not_clamped() {
        // 9999-01-01 00:00:00 GMT fits comfortably in i64, so BOTH entry points
        // return its true timestamp — matching real curl on a 64-bit platform.
        const Y9999: i64 = 253_370_764_800;
        assert_eq!(curl_getdate("Sat, 01 Jan 9999 00:00:00 GMT"), Y9999);
        assert_eq!(getdate_capped("Sat, 01 Jan 9999 00:00:00 GMT"), Some(Y9999));
    }

    // ---- The precise difference between the two public entry points ----------

    #[test]
    fn capped_vs_getdate_difference() {
        // 1969-12-31 23:59:59 GMT has timestamp exactly -1. `curl_getdate`
        // bumps that to 0 (so it is not confused with its error sentinel),
        // whereas `getdate_capped` returns the raw value verbatim.
        assert_eq!(curl_getdate("31 Dec 1969 23:59:59 GMT"), 0);
        assert_eq!(getdate_capped("31 Dec 1969 23:59:59 GMT"), Some(-1));

        // A genuine parse failure: -1 from `curl_getdate`, `None` from capped.
        assert_eq!(curl_getdate("totally bogus"), -1);
        assert_eq!(getdate_capped("totally bogus"), None);
    }

    #[test]
    fn capped_matches_getdate_for_normal_dates() {
        // For every parseable, in-range date the capped form returns exactly
        // what `curl_getdate` returns (the -1 bump aside).
        for v in [
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "06 Nov 1994 08:49:37 CET",
            "Sun, 12 Sep 2004 15:05:58 -0700",
            "20041106",
        ] {
            assert_eq!(
                getdate_capped(v),
                Some(curl_getdate(v)),
                "mismatch for `{v}`"
            );
        }
    }

    // ---- Internal `time2epoch_checked` directly ------------------------------

    #[test]
    fn time2epoch_matches_reference() {
        // The canonical broken-down date converts to CANON.
        assert_eq!(time2epoch_checked(37, 49, 8, 6, 10, 1994), Some(CANON));
        // Midnight on the same day.
        assert_eq!(time2epoch_checked(0, 0, 0, 6, 10, 1994), Some(MIDNIGHT));
        // The Unix epoch itself.
        assert_eq!(time2epoch_checked(0, 0, 0, 1, 0, 1970), Some(0));
        // One second before the epoch.
        assert_eq!(time2epoch_checked(59, 59, 23, 31, 11, 1969), Some(-1));
        // The largest year the tokenizer can ever produce still fits in i64.
        assert_eq!(
            time2epoch_checked(0, 0, 0, 1, 0, 99_999_999),
            Some(3_155_633_001_244_800)
        );
    }

    #[test]
    fn time2epoch_saturating_overflow_is_none() {
        // An absurd year (not reachable through the tokenizer's 8-digit cap)
        // overflows i64 and is reported as `None` rather than panicking — the
        // hook that lets `getdate_capped` saturate instead of trapping.
        assert!(time2epoch_checked(0, 0, 0, 1, 0, i64::MAX).is_none());
        assert!(time2epoch_checked(0, 0, 0, 1, 0, i64::MIN).is_none());
    }

    // ---- Internal `parsedate` outcome shape ----------------------------------

    #[test]
    fn parsedate_outcomes() {
        assert_eq!(
            parsedate("Sun, 06 Nov 1994 08:49:37 GMT"),
            ParseResult::Ok(CANON)
        );
        assert_eq!(parsedate("not a date"), ParseResult::Fail);
        assert_eq!(parsedate(""), ParseResult::Fail);
    }

    // ---- Classifier unit checks ----------------------------------------------

    #[test]
    fn classifiers() {
        // checkday: abbreviated and full, case-insensitive; Monday=0..Sunday=6.
        assert_eq!(checkday(b"Mon"), 0);
        assert_eq!(checkday(b"sun"), 6);
        assert_eq!(checkday(b"Wednesday"), 2);
        assert_eq!(checkday(b"Fr"), -1); // too short
        assert_eq!(checkday(b"Funday"), -1); // not a weekday
                                             // checkmonth: three letters only; Jan=0..Dec=11.
        assert_eq!(checkmonth(b"Jan"), 0);
        assert_eq!(checkmonth(b"dec"), 11);
        assert_eq!(checkmonth(b"Sept"), -1); // four letters
                                             // checktz: offset in seconds (minutes*60); not-found is -1.
        assert_eq!(checktz(b"GMT"), 0);
        assert_eq!(checktz(b"Z"), 0);
        assert_eq!(checktz(b"EST"), 300 * 60);
        assert_eq!(checktz(b"CET"), -60 * 60);
        assert_eq!(checktz(b"A"), 60 * 60);
        assert_eq!(checktz(b"N"), -60 * 60);
        assert_eq!(checktz(b"NOPE"), -1);
    }

    // ---- The published name tables -------------------------------------------

    #[test]
    fn name_tables() {
        assert_eq!(CURL_WKDAY.len(), 7);
        assert_eq!(CURL_MONTH.len(), 12);
        assert_eq!(CURL_WKDAY[0], "Mon");
        assert_eq!(CURL_WKDAY[6], "Sun");
        assert_eq!(CURL_MONTH[0], "Jan");
        assert_eq!(CURL_MONTH[11], "Dec");
    }

    // ---- No input can panic (the "never trap" contract) ----------------------

    #[test]
    fn never_panics_on_hostile_input() {
        // A spread of awkward inputs: lone separators, partial times, huge
        // alpha runs, sign-prefixed numbers, embedded control bytes, and a long
        // pseudo-random soup. None may panic; the return value is irrelevant.
        let hostile = [
            ":",
            "::::",
            "+",
            "-",
            "+-+-",
            "1:",
            "1:2:",
            "99:99:99",
            "24:00:00",
            "Wednesdayyyyyyyyyy", // alpha run beyond NAME_LEN
            "++++0100",
            "0000000000000000000000",
            "Nov Nov Nov Nov Nov Nov Nov",
            ".-,:.-,:.-,:",
            "06 Nov 1994 08:49:37 GMT \u{0}\u{1}\u{7f}",
            "\u{0}\u{0}\u{0}",
            "12345678901234567890",
            "Sun, 06 Nov 1994 08:49:37 ZZZZZ",
        ];
        for h in hostile {
            // Must simply return without panicking.
            let _ = curl_getdate(h);
            let _ = getdate_capped(h);
        }

        // A deterministic byte soup across the full 0..=255 range.
        let mut soup = String::new();
        for n in 0u32..512 {
            let b = (n.wrapping_mul(37).wrapping_add(11) & 0xff) as u8;
            // Keep it valid UTF-8 by mapping each byte to a char.
            soup.push(char::from(b));
        }
        let _ = curl_getdate(&soup);
        let _ = getdate_capped(&soup);
    }
}
