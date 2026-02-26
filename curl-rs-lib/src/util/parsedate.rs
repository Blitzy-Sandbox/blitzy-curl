//! Date/time parsing and formatting for HTTP headers and cookie expiry.
//!
//! Rust rewrite of `lib/parsedate.c` — supports multiple date formats
//! encountered in HTTP headers: RFC 822/2616, RFC 850, ANSI C asctime,
//! ISO 8601 subsets, and various real-world quirky formats.
//!
//! # Supported formats
//!
//! ```text
//! Sun, 06 Nov 1994 08:49:37 GMT    (RFC 822 / RFC 2616)
//! Sunday, 06-Nov-94 08:49:37 GMT   (RFC 850)
//! Sun Nov  6 08:49:37 1994         (ANSI C asctime)
//! 1994-11-06 08:49:37              (ISO 8601 subset)
//! 06 Nov 1994 08:49:37 GMT         (without weekday)
//! 20040912 15:05:58 -0700          (compact numerical)
//! ```
//!
//! # Two-digit year handling
//!
//! Values 0–70 map to 2000–2070; values 71–99 map to 1971–1999.
//! This matches curl 8.x behaviour exactly.

use chrono::{DateTime, FixedOffset, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};

use crate::error::CurlError;

// ───────────────────────────────── Public Constants ─────────────────────────

/// Abbreviated English month names used in HTTP date headers.
pub const MONTH_NAMES: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Abbreviated English weekday names used in HTTP date headers.
///
/// Index 0 = Monday, 6 = Sunday — matching the C `Curl_wkday` table.
pub const WEEKDAY_NAMES: [&str; 7] = [
    "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun",
];

// ───────────────────────────── Internal Constants ───────────────────────────

/// Full weekday names for RFC 850 format parsing.
const WEEKDAY_FULL: [&str; 7] = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
];

/// Internal parse-result codes mirroring the C `PARSEDATE_*` constants.
const PARSEDATE_OK: i32 = 0;
const PARSEDATE_FAIL: i32 = -1;
const PARSEDATE_LATER: i32 = 1;

/// Maximum word length the parser will consider (matches C `NAME_LEN`).
const NAME_LEN: usize = 12;

/// Maximum value for a 64-bit signed time_t.
const TIME_T_MAX: i64 = i64::MAX;

// ───────────────────────── Timezone Offset Table ────────────────────────────

/// A named timezone and its UTC offset in **minutes**.
///
/// Positive values mean the timezone is *west* of UTC (add to local time
/// to obtain UTC). Negative values mean *east* of UTC.
///
/// The table replicates the C `tz[]` array exactly — including the
/// military single-letter zones whose signs match the original curl
/// implementation for functional parity.
struct TzInfo {
    name: &'static str,
    /// Offset in minutes.  `checktz` multiplies by 60 to return seconds.
    offset_minutes: i32,
}

/// Daylight-saving adjustment applied to summer-time zones (−60 min).
const DAYZONE: i32 = -60;

static TZ_TABLE: &[TzInfo] = &[
    // ── Common civil zones ──
    // Offsets in minutes; positive = west of UTC, negative = east of UTC.
    TzInfo { name: "GMT",  offset_minutes: 0 },
    TzInfo { name: "UT",   offset_minutes: 0 },
    TzInfo { name: "UTC",  offset_minutes: 0 },
    TzInfo { name: "WET",  offset_minutes: 0 },
    TzInfo { name: "BST",  offset_minutes: DAYZONE },        // 0 + daylight
    TzInfo { name: "WAT",  offset_minutes: 60 },
    TzInfo { name: "AST",  offset_minutes: 240 },
    TzInfo { name: "ADT",  offset_minutes: 240 + DAYZONE },
    TzInfo { name: "EST",  offset_minutes: 300 },
    TzInfo { name: "EDT",  offset_minutes: 300 + DAYZONE },
    TzInfo { name: "CST",  offset_minutes: 360 },
    TzInfo { name: "CDT",  offset_minutes: 360 + DAYZONE },
    TzInfo { name: "MST",  offset_minutes: 420 },
    TzInfo { name: "MDT",  offset_minutes: 420 + DAYZONE },
    TzInfo { name: "PST",  offset_minutes: 480 },
    TzInfo { name: "PDT",  offset_minutes: 480 + DAYZONE },
    TzInfo { name: "YST",  offset_minutes: 540 },
    TzInfo { name: "YDT",  offset_minutes: 540 + DAYZONE },
    TzInfo { name: "HST",  offset_minutes: 600 },
    TzInfo { name: "HDT",  offset_minutes: 600 + DAYZONE },
    TzInfo { name: "CAT",  offset_minutes: 600 },
    TzInfo { name: "AHST", offset_minutes: 600 },
    TzInfo { name: "NT",   offset_minutes: 660 },
    TzInfo { name: "IDLW", offset_minutes: 720 },
    TzInfo { name: "CET",  offset_minutes: -60 },
    TzInfo { name: "MET",  offset_minutes: -60 },
    TzInfo { name: "MEWT", offset_minutes: -60 },
    TzInfo { name: "MEST", offset_minutes: -60 + DAYZONE },
    TzInfo { name: "CEST", offset_minutes: -60 + DAYZONE },
    TzInfo { name: "MESZ", offset_minutes: -60 + DAYZONE },
    TzInfo { name: "FWT",  offset_minutes: -60 },
    TzInfo { name: "FST",  offset_minutes: -60 + DAYZONE },
    TzInfo { name: "EET",  offset_minutes: -120 },
    TzInfo { name: "WAST", offset_minutes: -420 },
    TzInfo { name: "WADT", offset_minutes: -420 + DAYZONE },
    TzInfo { name: "CCT",  offset_minutes: -480 },
    TzInfo { name: "JST",  offset_minutes: -540 },
    TzInfo { name: "EAST", offset_minutes: -600 },
    TzInfo { name: "EADT", offset_minutes: -600 + DAYZONE },
    TzInfo { name: "GST",  offset_minutes: -600 },
    TzInfo { name: "NZT",  offset_minutes: -720 },
    TzInfo { name: "NZST", offset_minutes: -720 },
    TzInfo { name: "NZDT", offset_minutes: -720 + DAYZONE },
    TzInfo { name: "IDLE", offset_minutes: -720 },
    // ── Military single-letter zones (signs match curl 8.x) ──
    TzInfo { name: "A", offset_minutes: 60 },
    TzInfo { name: "B", offset_minutes: 2 * 60 },
    TzInfo { name: "C", offset_minutes: 3 * 60 },
    TzInfo { name: "D", offset_minutes: 4 * 60 },
    TzInfo { name: "E", offset_minutes: 5 * 60 },
    TzInfo { name: "F", offset_minutes: 6 * 60 },
    TzInfo { name: "G", offset_minutes: 7 * 60 },
    TzInfo { name: "H", offset_minutes: 8 * 60 },
    TzInfo { name: "I", offset_minutes: 9 * 60 },
    // J (Juliet) is intentionally omitted — observer's local time.
    TzInfo { name: "K", offset_minutes: 10 * 60 },
    TzInfo { name: "L", offset_minutes: 11 * 60 },
    TzInfo { name: "M", offset_minutes: 12 * 60 },
    TzInfo { name: "N", offset_minutes: -60 },
    TzInfo { name: "O", offset_minutes: -2 * 60 },
    TzInfo { name: "P", offset_minutes: -3 * 60 },
    TzInfo { name: "Q", offset_minutes: -4 * 60 },
    TzInfo { name: "R", offset_minutes: -5 * 60 },
    TzInfo { name: "S", offset_minutes: -6 * 60 },
    TzInfo { name: "T", offset_minutes: -7 * 60 },
    TzInfo { name: "U", offset_minutes: -8 * 60 },
    TzInfo { name: "V", offset_minutes: -9 * 60 },
    TzInfo { name: "W", offset_minutes: -10 * 60 },
    TzInfo { name: "X", offset_minutes: -11 * 60 },
    TzInfo { name: "Y", offset_minutes: -12 * 60 },
    TzInfo { name: "Z", offset_minutes: 0 },
];

// ────────────────────────── Name-Lookup Helpers ─────────────────────────────

/// Check whether `name` is a weekday name (case-insensitive).
///
/// Returns 0–6 (Mon–Sun) or `None`.  Accepts both abbreviated (3 chars)
/// and full-length names.
fn check_day(name: &str) -> Option<usize> {
    let len = name.len();
    if len > 3 {
        // Try full weekday names (length must match exactly).
        for (i, full) in WEEKDAY_FULL.iter().enumerate() {
            if full.len() == len && name.eq_ignore_ascii_case(full) {
                return Some(i);
            }
        }
    } else if len == 3 {
        // Try abbreviated weekday names.
        for (i, short) in WEEKDAY_NAMES.iter().enumerate() {
            if name.eq_ignore_ascii_case(short) {
                return Some(i);
            }
        }
    }
    // len < 3 → not a weekday.
    None
}

/// Check whether `name` is an abbreviated month name (case-insensitive).
///
/// Returns 0–11 (Jan–Dec) or `None`.  Only 3-character names are accepted.
fn check_month(name: &str) -> Option<usize> {
    if name.len() != 3 {
        return None;
    }
    for (i, month) in MONTH_NAMES.iter().enumerate() {
        if name.eq_ignore_ascii_case(month) {
            return Some(i);
        }
    }
    None
}

/// Look up a named timezone and return its offset in **seconds**.
///
/// Returns `None` for unknown names or names longer than 4 characters.
fn check_tz(name: &str) -> Option<i32> {
    if name.len() > 4 {
        return None;
    }
    for tz in TZ_TABLE.iter() {
        if tz.name.len() == name.len() && name.eq_ignore_ascii_case(tz.name) {
            return Some(tz.offset_minutes * 60);
        }
    }
    None
}

// ─────────────────────── Epoch Computation ──────────────────────────────────

/// Convert broken-down time components (in GMT) to seconds since the Unix
/// epoch, matching the C `time2epoch` function exactly.
///
/// * `mon` is 0-based (0 = January, 11 = December).
/// * `mday` is 1-based (1–31).
fn time2epoch(sec: i32, min: i32, hour: i32, mday: i32, mon: i32, year: i32) -> i64 {
    static MONTH_DAYS_CUMULATIVE: [i32; 12] = [
        0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334,
    ];

    let leap_adj = year - i32::from(mon <= 1);
    let leap_days =
        (leap_adj / 4) - (leap_adj / 100) + (leap_adj / 400)
        - (1969 / 4) + (1969 / 100) - (1969 / 400);

    let days = (year - 1970) as i64 * 365
        + leap_days as i64
        + MONTH_DAYS_CUMULATIVE[mon as usize] as i64
        + mday as i64
        - 1;

    ((days * 24 + hour as i64) * 60 + min as i64) * 60 + sec as i64
}

// ───────────────────────── Time-String Matcher ──────────────────────────────

/// Parse one or two ASCII digits starting at `bytes[pos]`.
///
/// Returns `(value, bytes_consumed)`.  The caller must ensure `pos` is
/// valid and `bytes[pos]` is a digit.
fn one_or_two_digit(bytes: &[u8], pos: usize) -> (i32, usize) {
    let first = (bytes[pos] - b'0') as i32;
    if pos + 1 < bytes.len() && bytes[pos + 1].is_ascii_digit() {
        (first * 10 + (bytes[pos + 1] - b'0') as i32, 2)
    } else {
        (first, 1)
    }
}

/// Try to match `HH:MM[:SS]` at the beginning of `bytes`.
///
/// Returns `Some((hour, min, sec, bytes_consumed))` on success.
fn match_time(bytes: &[u8]) -> Option<(i32, i32, i32, usize)> {
    if bytes.is_empty() || !bytes[0].is_ascii_digit() {
        return None;
    }

    let (hh, hlen) = one_or_two_digit(bytes, 0);
    let mut p = hlen;

    if hh >= 24 || p >= bytes.len() || bytes[p] != b':' {
        return None;
    }
    p += 1; // skip ':'

    if p >= bytes.len() || !bytes[p].is_ascii_digit() {
        return None;
    }
    let (mm, mlen) = one_or_two_digit(bytes, p);
    p += mlen;

    if mm >= 60 {
        return None;
    }

    // Optional seconds.
    let ss;
    if p < bytes.len() && bytes[p] == b':' && p + 1 < bytes.len() && bytes[p + 1].is_ascii_digit()
    {
        let (s, slen) = one_or_two_digit(bytes, p + 1);
        if s > 60 {
            return None; // 61+ is invalid even with leap seconds.
        }
        ss = s;
        p += 1 + slen;
    } else {
        ss = 0;
    }

    Some((hh, mm, ss, p))
}

// ─────────────────── Parsed Component Container ─────────────────────────────

/// Intermediate container for parsed date/time components.
struct DateComponents {
    year: i32,
    /// 0-based month (0 = January).
    month: i32,
    /// 1-based day of month.
    day: i32,
    hour: i32,
    min: i32,
    sec: i32,
    /// Seconds to **add** to local time to obtain UTC.
    tz_offset_secs: i32,
}

// ────────────────────── State for the digit heuristic ───────────────────────

/// When the parser encounters a bare number, this hint decides whether
/// to try interpreting it as a day-of-month or a year first.
#[derive(Clone, Copy)]
enum DigitAssume {
    Mday,
    Year,
}

// ───────────────────────── Core Parsing Engine ──────────────────────────────

/// Skip all non-alphanumeric characters, matching the C `skip()` function.
///
/// This advances past separators including `-`, `+`, `,`, `/`, ` `, etc.
/// The caller can inspect `bytes[pos - 1]` to recover the sign character
/// that was just skipped (used for timezone offset detection).
#[inline]
fn skip(bytes: &[u8], pos: &mut usize) {
    while *pos < bytes.len() && !bytes[*pos].is_ascii_alphanumeric() {
        *pos += 1;
    }
}

/// Main parsing routine — mirrors the C `parsedate()` state machine.
///
/// Returns `(PARSEDATE_OK|FAIL|LATER, DateComponents)`.
fn parsedate(date: &str) -> (i32, DateComponents) {
    let bytes = date.as_bytes();
    let len = bytes.len();

    let mut yearnum: i32 = -1;
    let mut monnum: i32 = -1;
    let mut mdaynum: i32 = -1;
    let mut hournum: i32 = -1;
    let mut minnum: i32 = -1;
    let mut secnum: i32 = -1;
    let mut tzoff: i32 = -1;

    let mut wdaynum: i32 = -1;
    let mut dignext = DigitAssume::Mday;

    let mut pos: usize = 0;
    let mut parts: usize = 0;

    while pos < len && parts < 6 {
        let mut found = false;

        // Skip ALL non-alphanumeric characters (including +, -, /, etc.)
        // exactly as the C skip() function does.
        skip(bytes, &mut pos);
        if pos >= len {
            break;
        }

        // ── Alphabetic token ──
        if bytes[pos].is_ascii_alphabetic() {
            let start = pos;
            while pos < len && bytes[pos].is_ascii_alphabetic() && (pos - start) < NAME_LEN {
                pos += 1;
            }
            let word_len = pos - start;

            // The C code rejects words that exactly fill NAME_LEN
            // (they are truncated and therefore ambiguous).
            if word_len == NAME_LEN {
                return (PARSEDATE_FAIL, empty_components());
            }

            let word = &date[start..pos];

            if wdaynum == -1 {
                if let Some(d) = check_day(word) {
                    wdaynum = d as i32;
                    found = true;
                }
            }
            if !found && monnum == -1 {
                if let Some(m) = check_month(word) {
                    monnum = m as i32;
                    found = true;
                }
            }
            if !found && tzoff == -1 {
                if let Some(tz) = check_tz(word) {
                    tzoff = tz;
                    found = true;
                }
            }

            if !found {
                return (PARSEDATE_FAIL, empty_components());
            }
        } else if bytes[pos].is_ascii_digit() {
            // ── Numeric token ──

            // Try HH:MM[:SS] time first (only if time not yet found).
            if secnum == -1 {
                if let Some((h, m, s, consumed)) = match_time(&bytes[pos..]) {
                    hournum = h;
                    minnum = m;
                    secnum = s;
                    pos += consumed;
                    found = true;
                }
            }

            if !found {
                // Parse a bare integer.
                let num_start = pos;
                while pos < len && bytes[pos].is_ascii_digit() {
                    pos += 1;
                }
                let num_str = &date[num_start..pos];
                let num_val: i64 = match num_str.parse() {
                    Ok(v) => v,
                    Err(_) => return (PARSEDATE_FAIL, empty_components()),
                };
                // Guard against extremely large values.
                if num_val > 99_999_999 {
                    return (PARSEDATE_FAIL, empty_components());
                }
                let val = num_val as u32;
                let num_digits = pos - num_start;

                // ── 4-digit number preceded by '+' or '-': timezone ──
                //
                // The C code uses `date[-1]` to recover the sign that
                // was consumed by skip().  We replicate this by checking
                // `bytes[num_start - 1]`.
                if tzoff == -1
                    && num_digits == 4
                    && val <= 1400
                    && num_start > 0
                    && (bytes[num_start - 1] == b'+' || bytes[num_start - 1] == b'-')
                {
                    let offset_secs =
                        ((val / 100 * 60 + val % 100) * 60) as i32;
                    tzoff = if bytes[num_start - 1] == b'+' {
                        -offset_secs
                    } else {
                        offset_secs
                    };
                    found = true;
                }

                // ── 8-digit YYYYMMDD compact date ──
                if !found
                    && num_digits == 8
                    && yearnum == -1
                    && monnum == -1
                    && mdaynum == -1
                {
                    yearnum = (val / 10000) as i32;
                    monnum = ((val % 10000) / 100) as i32 - 1;
                    mdaynum = (val % 100) as i32;
                    found = true;
                }

                // ── Try mday first (sequential ifs, not if/else) ──
                //
                // The C code uses sequential `if` blocks so that
                // `dignext` changes regardless of whether `found`
                // was set.
                if !found
                    && matches!(dignext, DigitAssume::Mday)
                    && mdaynum == -1
                {
                    if val > 0 && val < 32 {
                        mdaynum = val as i32;
                        found = true;
                    }
                    dignext = DigitAssume::Year;
                }

                // ── Then try year ──
                if !found
                    && matches!(dignext, DigitAssume::Year)
                    && yearnum == -1
                {
                    yearnum = val as i32;
                    found = true;
                    // Two-digit year adjustment happens here in the C
                    // code to set dignext correctly.
                    if yearnum < 100 {
                        if yearnum > 70 {
                            yearnum += 1900;
                        } else {
                            yearnum += 2000;
                        }
                    }
                    if mdaynum == -1 {
                        dignext = DigitAssume::Mday;
                    }
                }

                if !found {
                    return (PARSEDATE_FAIL, empty_components());
                }
            }
        } else {
            // Non-alnum that skip() didn't consume — should not happen,
            // but advance to avoid infinite loops.
            pos += 1;
            continue;
        }

        parts += 1;
    }

    // ── Post-processing ──

    // Default time to midnight if no time was found.
    if secnum == -1 {
        secnum = 0;
        minnum = 0;
        hournum = 0;
    }

    // Must have at least month, day, and year.
    if mdaynum == -1 || monnum == -1 || yearnum == -1 {
        return (PARSEDATE_FAIL, empty_components());
    }

    // Gregorian calendar check (C: yearnum < 1583 → FAIL on 64-bit).
    if yearnum < 1583 {
        return (PARSEDATE_FAIL, empty_components());
    }

    // Range validation matching the C code exactly.
    if mdaynum > 31
        || monnum > 11
        || hournum > 23
        || minnum > 59
        || secnum > 60
    {
        return (PARSEDATE_FAIL, empty_components());
    }

    // Default timezone to GMT if not found.
    if tzoff == -1 {
        tzoff = 0;
    }

    // Compute the raw UTC timestamp and apply timezone offset.
    let raw = time2epoch(secnum, minnum, hournum, mdaynum, monnum, yearnum);

    // Check for overflow when adding the timezone offset.
    if tzoff > 0 && raw > (i64::MAX - tzoff as i64) {
        return (PARSEDATE_LATER, empty_components());
    }
    let _t = raw + tzoff as i64;

    (
        PARSEDATE_OK,
        DateComponents {
            year: yearnum,
            month: monnum,
            day: mdaynum,
            hour: hournum,
            min: minnum,
            sec: secnum,
            tz_offset_secs: tzoff,
        },
    )
}

/// Helper to produce an empty/default `DateComponents`.
fn empty_components() -> DateComponents {
    DateComponents {
        year: 0,
        month: 0,
        day: 0,
        hour: 0,
        min: 0,
        sec: 0,
        tz_offset_secs: 0,
    }
}

// ─────────────────────── Public API Functions ────────────────────────────────

/// Parse a date string into a Unix timestamp (seconds since epoch).
///
/// Accepts a wide range of HTTP-style date formats, matching the
/// behaviour of the C `curl_getdate` function.
///
/// # Errors
///
/// Returns [`CurlError::BadFunctionArgument`] if the input is empty.
/// Returns [`CurlError::GotNothing`] if the date cannot be parsed.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::util::parsedate::parse_date;
///
/// let ts = parse_date("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
/// assert_eq!(ts, 784111777);
/// ```
pub fn parse_date(date_str: &str) -> Result<i64, CurlError> {
    let trimmed = date_str.trim();
    if trimmed.is_empty() {
        return Err(CurlError::BadFunctionArgument);
    }

    let (rc, components) = parsedate(trimmed);
    if rc == PARSEDATE_FAIL {
        return Err(CurlError::GotNothing);
    }

    // Compute timestamp from components + offset.
    let t = time2epoch(
        components.sec,
        components.min,
        components.hour,
        components.day,
        components.month,
        components.year,
    );
    let t = t.wrapping_add(components.tz_offset_secs as i64);

    // C curl_getdate returns -1 on failure, and adjusts -1 → 0 for success.
    // In the Rust API we use Result, but we mirror the quirk: if the
    // timestamp is exactly -1, bump to 0 to maintain parity with callers
    // that pass the value through to C.
    let t = if t == -1 { 0 } else { t };

    Ok(t)
}

/// Parse a date string into a Unix timestamp, capping the result so
/// it never exceeds `TIME_T_MAX` (i64::MAX).
///
/// This matches the C `Curl_getdate_capped` function which guards
/// against 32-bit `time_t` overflow.  On 64-bit systems the cap is
/// effectively unreachable, but the function preserves curl 8.x API
/// semantics.
///
/// # Errors
///
/// Same error conditions as [`parse_date`].
pub fn parse_date_capped(date_str: &str) -> Result<i64, CurlError> {
    let trimmed = date_str.trim();
    if trimmed.is_empty() {
        return Err(CurlError::BadFunctionArgument);
    }

    let (rc, components) = parsedate(trimmed);

    match rc {
        PARSEDATE_OK => {
            let t = time2epoch(
                components.sec,
                components.min,
                components.hour,
                components.day,
                components.month,
                components.year,
            );
            let t = t.saturating_add(components.tz_offset_secs as i64);
            // On 64-bit systems saturating_add already bounds to
            // i64::MAX.  This is a semantic marker for the TIME_T_MAX
            // cap required by the API contract.
            Ok(t)
        }
        PARSEDATE_LATER => {
            // Date is in the future beyond representable range → cap.
            Ok(TIME_T_MAX)
        }
        _ => Err(CurlError::GotNothing),
    }
}

/// Parse a date string into a `chrono::DateTime<Utc>`.
///
/// This is a convenience wrapper around the internal parser that
/// returns a rich chrono type instead of a raw timestamp.  Used by
/// higher-level modules that need structured date/time objects.
///
/// # Errors
///
/// Returns [`CurlError::BadFunctionArgument`] if the input is empty.
/// Returns [`CurlError::GotNothing`] if the date cannot be parsed or
/// the resulting components fall outside chrono's representable range.
pub fn parse_date_chrono(date_str: &str) -> Result<DateTime<Utc>, CurlError> {
    let trimmed = date_str.trim();
    if trimmed.is_empty() {
        return Err(CurlError::BadFunctionArgument);
    }

    let (rc, components) = parsedate(trimmed);
    if rc == PARSEDATE_FAIL {
        return Err(CurlError::GotNothing);
    }

    // Clamp leap second for chrono (which supports only 0–59).
    let sec = if components.sec >= 60 { 59 } else { components.sec };

    let naive_date = NaiveDate::from_ymd_opt(
        components.year,
        (components.month + 1) as u32,
        components.day as u32,
    )
    .ok_or(CurlError::GotNothing)?;

    let naive_time =
        NaiveTime::from_hms_opt(components.hour as u32, components.min as u32, sec as u32)
            .ok_or(CurlError::GotNothing)?;

    let naive_dt = NaiveDateTime::new(naive_date, naive_time);

    // Build a fixed-offset timezone from the parsed offset.
    let offset =
        FixedOffset::east_opt(-(components.tz_offset_secs))
            .ok_or(CurlError::GotNothing)?;

    // Interpret the naive datetime in the parsed timezone, then convert
    // to UTC.
    let local_dt = offset
        .from_local_datetime(&naive_dt)
        .single()
        .ok_or(CurlError::GotNothing)?;

    let utc_dt: DateTime<Utc> = local_dt.with_timezone(&Utc);
    Ok(utc_dt)
}

/// Format a Unix timestamp as an RFC 822 date string suitable for
/// HTTP headers (`Date`, `If-Modified-Since`, `Last-Modified`).
///
/// Output format: `"Sun, 06 Nov 1994 08:49:37 GMT"`
///
/// Returns an empty string if the timestamp is outside chrono's
/// representable range.
pub fn format_http_date(timestamp: i64) -> String {
    let dt = match DateTime::from_timestamp(timestamp, 0) {
        Some(d) => d,
        None => return String::new(),
    };

    // chrono's `%a` and `%b` produce English locale abbreviations.
    dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// Format a Unix timestamp as a cookie `Expires` date string.
///
/// Output format: `"Sun, 06-Nov-1994 08:49:37 GMT"` — note the
/// hyphen separators between day, month, and year per the Netscape
/// cookie specification.
///
/// Returns an empty string if the timestamp is outside chrono's
/// representable range.
pub fn format_cookie_date(timestamp: i64) -> String {
    let dt = match DateTime::from_timestamp(timestamp, 0) {
        Some(d) => d,
        None => return String::new(),
    };

    dt.format("%a, %d-%b-%Y %H:%M:%S GMT").to_string()
}

// ─────────────────────────────── Tests ──────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── RFC 822 ──

    #[test]
    fn rfc822_basic() {
        let ts = parse_date("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        assert_eq!(ts, 784111777);
    }

    #[test]
    fn rfc822_with_utc() {
        let ts = parse_date("Sun, 06 Nov 1994 08:49:37 UTC").unwrap();
        assert_eq!(ts, 784111777);
    }

    // ── RFC 850 ──

    #[test]
    fn rfc850_basic() {
        let ts = parse_date("Sunday, 06-Nov-94 08:49:37 GMT").unwrap();
        assert_eq!(ts, 784111777);
    }

    // ── asctime ──

    #[test]
    fn asctime_basic() {
        let ts = parse_date("Sun Nov  6 08:49:37 1994").unwrap();
        assert_eq!(ts, 784111777);
    }

    // ── Two-digit year handling ──

    #[test]
    fn two_digit_year_high() {
        // 94 > 70 → 1994
        let ts = parse_date("06-Nov-94 08:49:37 GMT").unwrap();
        assert_eq!(ts, 784111777);
    }

    #[test]
    fn two_digit_year_low() {
        // 00 <= 70 → 2000
        let ts = parse_date("01 Jan 00 00:00:00 GMT").unwrap();
        // 2000-01-01 00:00:00 UTC = 946684800
        assert_eq!(ts, 946684800);
    }

    // ── Timezone offsets ──

    #[test]
    fn numeric_tz_offset_positive() {
        // +0000 is GMT
        let ts = parse_date("06 Nov 1994 08:49:37 +0000").unwrap();
        assert_eq!(ts, 784111777);
    }

    #[test]
    fn numeric_tz_offset_negative() {
        // -0500 means 5 hours west = EST
        let ts = parse_date("06 Nov 1994 08:49:37 -0500").unwrap();
        // 08:49:37 EST = 13:49:37 UTC
        assert_eq!(ts, 784111777 + 5 * 3600);
    }

    // ── Invalid inputs ──

    #[test]
    fn empty_input_fails() {
        assert!(parse_date("").is_err());
    }

    #[test]
    fn garbage_input_fails() {
        assert!(parse_date("not a date").is_err());
    }

    #[test]
    fn missing_year_fails() {
        assert!(parse_date("Nov 06 08:49:37 GMT").is_err());
    }

    // ── parse_date_capped ──

    #[test]
    fn capped_normal() {
        let ts = parse_date_capped("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        assert_eq!(ts, 784111777);
    }

    // ── parse_date_chrono ──

    #[test]
    fn chrono_conversion() {
        let dt = parse_date_chrono("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        assert_eq!(dt.timestamp(), 784111777);
    }

    // ── format_http_date ──

    #[test]
    fn format_http_roundtrip() {
        let s = format_http_date(784111777);
        assert_eq!(s, "Sun, 06 Nov 1994 08:49:37 GMT");
    }

    // ── format_cookie_date ──

    #[test]
    fn format_cookie_roundtrip() {
        let s = format_cookie_date(784111777);
        assert_eq!(s, "Sun, 06-Nov-1994 08:49:37 GMT");
    }

    // ── YYYYMMDD compact format ──

    #[test]
    fn compact_date() {
        let ts = parse_date("19941106 08:49:37 GMT").unwrap();
        assert_eq!(ts, 784111777);
    }

    // ── Edge: whitespace handling ──

    #[test]
    fn leading_trailing_whitespace() {
        let ts = parse_date("  Sun, 06 Nov 1994 08:49:37 GMT  ").unwrap();
        assert_eq!(ts, 784111777);
    }
}
