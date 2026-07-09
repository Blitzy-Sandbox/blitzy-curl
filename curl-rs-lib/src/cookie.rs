// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! HTTP cookie engine and Netscape cookie jar — a memory-safe Rust rewrite of
//! curl's `lib/cookie.c`.
//!
//! This module implements curl's complete cookie store: it parses `Set-Cookie:`
//! response headers, matches stored cookies against outgoing requests, and reads
//! and writes the *Netscape* cookie-jar file format. It is the source-of-truth
//! port of `lib/cookie.c` (curl 8.19.0-DEV) and preserves that file's observable
//! behavior byte-for-byte.
//!
//! # Responsibilities (mirroring `lib/cookie.c`)
//!
//! * **Ingestion** — [`CookieJar::add`] reproduces `Curl_cookie_add`: it accepts
//!   either an HTTP `Set-Cookie` header line or a Netscape jar-file line, applies
//!   curl's exact tokenizer, the `__Secure-` / `__Host-` prefix rules, the TAB
//!   rejection, the domain-acceptance checks (public-suffix "supercookie"
//!   defense via [`crate::psl`]), the `max-age` / `expires` parsing, and the
//!   replace / drop rules for cookies that supersede an existing one.
//! * **Matching** — [`CookieJar::get_list`] reproduces `Curl_cookie_getlist`:
//!   domain tail-match, path prefix-match, secure-only-over-TLS filtering, and
//!   expiry filtering, returning matches ordered exactly as curl orders them
//!   (longest path first) so a generated `Cookie:` request header is byte
//!   identical.
//! * **Persistence** — [`CookieJar::save`] / [`CookieJar::load`] reproduce
//!   `cookie_output` / `cookie_load` and their **byte-compatible** on-disk
//!   format: the standard header comment block, then one line per cookie with
//!   seven TAB-separated fields (`domain`, `tailmatch`, `path`, `secure`,
//!   `expires`, `name`, `value`), with HttpOnly cookies carrying the literal
//!   `#HttpOnly_` prefix immediately before the domain field.
//!
//! # Relationship to the C code
//!
//! curl stores cookies in a fixed-size hash table (`COOKIE_HASH_SIZE` linked
//! lists keyed on the domain's top label) purely as a lookup optimization. This
//! port stores them in a single ordered [`Vec`] instead: the hash bucketing is
//! not observable, because every match applies the same domain/path predicates
//! and both the jar-output order (sorted by creation time) and the request-match
//! order (sorted by [`cookie_sort`](CookieJar::get_list)) are fully determined by
//! the sort, not by storage order. curl's `creationtime` is a monotonically
//! increasing counter (`++ci->lastct`), not a wall-clock stamp; this port
//! preserves that exactly, which is what makes the sort tie-breaker
//! deterministic.
//!
//! The whole `Curl_psl_use` / `Curl_share_lock` lifecycle collapses into Rust
//! ownership: a [`CookieJar`] is a plain owned value that is trivially wrapped in
//! [`SharedCookieJar`] (`Arc<Mutex<CookieJar>>`) to realize curl's cross-handle
//! `curl_share` cookie sharing model.
//!
//! # Public-suffix ("supercookie") defense
//!
//! curl links `libpsl` to reject cookies whose `Domain` attribute names a public
//! suffix (`com`, `co.uk`, …). This port uses [`crate::psl::Psl`]. When a list is
//! loaded ([`Psl::is_available`] is `true`) the PSL acceptance check mirrors
//! curl's `#ifdef USE_LIBPSL` path; when no list is loaded it falls back to
//! curl's `#ifndef USE_LIBPSL` heuristic (`bad_domain`: the domain must contain a
//! non-trailing dot or be exactly `localhost`).
//!
//! # Memory safety
//!
//! The module is written entirely in safe Rust (the crate applies
//! `#![forbid(unsafe_code)]`); it performs no raw-pointer, `transmute`, or FFI
//! work, in keeping with the workspace policy that confines such constructs to
//! the FFI layer. It is only compiled when the `cookies` feature is enabled
//! (default-on), mirroring curl's `CURL_DISABLE_COOKIES` guard.

use std::fmt;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};
use crate::psl::Psl;

// ---------------------------------------------------------------------------
// Limits and constants — mirror `lib/cookie.h` and `lib/cookie.c`.
// ---------------------------------------------------------------------------

/// The longest line accepted when reading a cookie from an HTTP header or a
/// cookie jar (`MAX_COOKIE_LINE` in `cookie.h`). Overly long lines are dropped.
const MAX_COOKIE_LINE: usize = 5000;

/// Maximum length of an incoming cookie name or value we deal with; longer
/// cookies are ignored (`MAX_NAME` in `cookie.h`).
const MAX_NAME: usize = 4096;

/// Maximum number of cookies sent in a single request even if more match
/// (`MAX_COOKIE_SEND_AMOUNT` in `cookie.h`).
const MAX_COOKIE_SEND_AMOUNT: usize = 150;

/// The longest string accepted for the `expires` attribute date
/// (`MAX_DATE_LENGTH` in `cookie.c`).
const MAX_DATE_LENGTH: usize = 80;

/// Number of hash buckets curl distributes cookies across (`COOKIE_HASH_SIZE`
/// in `cookie.h`). This port stores cookies in a flat [`Vec`], but the bucket
/// index is still computed to reproduce the exact traversal order of
/// [`CookieJar::list`] (`Curl_cookie_list`).
const COOKIE_HASH_SIZE: usize = 63;

/// The absolute ceiling curl places on a single string argument
/// (`CURL_MAX_INPUT_LENGTH` in `urldata.h`), used to reject an over-long inline
/// cookie line passed to [`CookieJar::command`] (`CURLOPT_COOKIELIST`).
const CURL_MAX_INPUT_LENGTH: usize = 8_000_000;

/// Number of seconds in 400 days — the RFC 6265bis cap on how far in the future
/// a cookie may expire (`COOKIES_MAXAGE` in `cookie.c`).
const COOKIES_MAXAGE: i64 = 400 * 24 * 3600;

/// curl's `CURL_OFF_T_MAX` / `TIME_T_MAX` on the 64-bit targets this port
/// supports. Used as the "no overflow / unlimited" sentinel exactly as the C
/// code uses it.
const CURL_OFF_T_MAX: i64 = i64::MAX;

/// The header comment block curl writes at the top of every cookie jar
/// (`cookie_output` in `cookie.c`). Reproduced byte-for-byte, including the
/// trailing blank line (`\n\n`).
const NETSCAPE_HEADER: &str = concat!(
    "# Netscape HTTP Cookie File\n",
    "# https://curl.se/docs/http-cookies.html\n",
    "# This file was generated by libcurl! Edit at your own risk.\n",
    "\n",
);

// ---------------------------------------------------------------------------
// Low-level string / byte helpers — faithful ports of the C primitives used by
// `cookie.c` (`curl_strnequal`, `strncmp`, `Curl_host_is_ipnum`, and the small
// static helpers `cookie_tailmatch` / `pathmatch` / `sanitize_cookie_path` /
// `invalid_octets` / `cap_expires`).
// ---------------------------------------------------------------------------

/// Returns `true` when `host` is a numeric IP literal (IPv4 or IPv6).
///
/// Mirrors curl's `Curl_host_is_ipnum`, which uses `inet_pton` for both address
/// families. Rust's `Ipv4Addr` / `Ipv6Addr` parsers are the exact equivalents
/// (strict, no brackets, no zone), so an IP host is detected identically.
fn is_ip_address(host: &str) -> bool {
    host.parse::<Ipv4Addr>().is_ok() || host.parse::<Ipv6Addr>().is_ok()
}

/// Case-insensitive comparison of a field against a literal, reproducing
/// `curl_strnequal(field, lit, field.len())`.
///
/// curl compares byte-by-byte, ASCII-case-insensitively, treating `lit` as
/// NUL-terminated: once all `field.len()` bytes have matched the loop exits with
/// "equal". If the field is longer than the literal, the literal's implicit
/// trailing NUL will differ from the field's next byte, so the comparison fails
/// — which is exactly what makes, for example, `curl_strnequal("TRUEX", "TRUE",
/// 5)` unequal. `field` never contains an interior NUL here (it is a span of a
/// jar/header line), so this faithfully matches the C loop.
fn c_strncaseeq(field: &[u8], lit: &str) -> bool {
    let lit = lit.as_bytes();
    for (i, &b) in field.iter().enumerate() {
        // Bytes past the end of the literal compare against its terminating NUL.
        let l = if i < lit.len() { lit[i] } else { 0 };
        if !b.eq_ignore_ascii_case(&l) {
            return false;
        }
    }
    true
}

/// Case-sensitive comparison equivalent to C `strncmp(lit, field, field.len())
/// == 0`.
///
/// Used only for the Netscape "does field 2 look like a boolean?" test, which
/// curl performs case-sensitively (`strncmp("TRUE", ptr, len)`), unlike the
/// case-insensitive `curl_strnequal` used for the actual TRUE/FALSE values. The
/// literal is treated as NUL-terminated, so a field longer than the literal is
/// never considered equal.
fn c_strncmp_eq(lit: &str, field: &[u8]) -> bool {
    let lit = lit.as_bytes();
    for (i, &b) in field.iter().enumerate() {
        let l = if i < lit.len() { lit[i] } else { 0 };
        if b != l {
            return false;
        }
    }
    true
}

/// Full case-insensitive equality of a token against a literal, reproducing
/// `curlx_str_casecompare` (used for cookie attribute names).
///
/// Unlike [`c_strncaseeq`] (a prefix test), this requires the lengths to be
/// equal as well, so `path` matches only the exact token `path`/`PATH`/`Path`,
/// never `pathological`.
fn c_casecompare(field: &[u8], lit: &str) -> bool {
    field.len() == lit.len() && field.eq_ignore_ascii_case(lit.as_bytes())
}

/// Tail-matches a cookie domain against a hostname (RFC 6265 §4.1.2.3).
///
/// Faithful port of `cookie_tailmatch`: `hostname` must end with
/// `cookie_domain` (compared ASCII-case-insensitively), and either the two are
/// the same length or the character in `hostname` immediately preceding the
/// matched suffix is a dot. Both arguments are raw bytes so the comparison never
/// depends on UTF-8 validity.
fn cookie_tailmatch(cookie_domain: &[u8], hostname: &[u8]) -> bool {
    let clen = cookie_domain.len();
    let hlen = hostname.len();
    if hlen < clen {
        return false;
    }
    let suffix = &hostname[hlen - clen..];
    if !suffix.eq_ignore_ascii_case(cookie_domain) {
        return false;
    }
    if hlen == clen {
        return true;
    }
    // A lead char of cookie_domain is not '.', so require a dot boundary.
    hostname[hlen - clen - 1] == b'.'
}

/// Matches a cookie path against a request URI path (RFC 6265 §5.1.4).
///
/// Faithful port of `pathmatch`. A single-character cookie path is always `/`
/// (guaranteed by [`sanitize_cookie_path`]) and matches everything. An empty or
/// non-absolute URI path defaults to `/`. The prefix comparison is
/// **case-sensitive** (curl uses `strncmp`, deliberately not `checkprefix`). The
/// paths match when they are identical or the URI path has a `/` immediately
/// after the cookie-path prefix.
fn pathmatch(cookie_path: &str, uri_path: &str) -> bool {
    let cb = cookie_path.as_bytes();
    let cplen = cb.len();
    if cplen == 1 {
        // cookie_path is "/"
        return true;
    }

    // #-fragments are already cut off by the caller; a missing or relative path
    // defaults to "/".
    let uri = if uri_path.is_empty() || !uri_path.starts_with('/') {
        "/"
    } else {
        uri_path
    };
    let ub = uri.as_bytes();
    let uplen = ub.len();

    if uplen < cplen {
        return false;
    }
    // Case-sensitive prefix match.
    if ub[..cplen] != *cb {
        return false;
    }
    if cplen == uplen {
        return true;
    }
    ub[cplen] == b'/'
}

/// Sanitizes a cookie path (RFC 6265 §5.2.4), a faithful port of
/// `sanitize_cookie_path`.
///
/// Surrounding double quotes (some sites send `path="/x"`) are stripped; an
/// empty or non-absolute path becomes the default `/`; and a single trailing
/// slash is removed from a non-root path (`/hoge/` → `/hoge`). The input is a
/// span of an already-valid-UTF-8 line taken at ASCII delimiters, so the lossy
/// conversion never actually replaces anything.
fn sanitize_cookie_path(cookie_path: &[u8]) -> String {
    let mut p = cookie_path;

    // Some sites wrap the path in double quotes.
    if !p.is_empty() && p[0] == b'"' {
        p = &p[1..];
        if !p.is_empty() && p[p.len() - 1] == b'"' {
            p = &p[..p.len() - 1];
        }
    }

    // Let cookie-path be the default-path when empty or not absolute.
    if p.is_empty() || p[0] != b'/' {
        return "/".to_string();
    }

    // Remove a single trailing slash from a non-root path.
    if p.len() > 1 && p[p.len() - 1] == b'/' {
        p = &p[..p.len() - 1];
    }

    String::from_utf8_lossy(p).into_owned()
}

/// Derives the default cookie path from a request path, a faithful port of the
/// `storecookie` default-path logic (`strrchr(path, '/')`).
///
/// The default path is everything up to and **including** the last `/`; if the
/// request path contains no slash the whole path is used. The result is later
/// run through [`sanitize_cookie_path`], so `"/a/b"` yields `"/a/"` → `"/a"`,
/// `"/"` yields `"/"`, and `"abc"` yields `"abc"` → `"/"`.
fn default_path_prefix(full: &str) -> &[u8] {
    let b = full.as_bytes();
    match b.iter().rposition(|&x| x == b'/') {
        Some(idx) => &b[..idx + 1],
        None => b,
    }
}

/// Returns `true` if the byte span contains a control octet curl rejects.
///
/// Faithful port of `invalid_octets`: bytes `0x01..=0x1f` are rejected except
/// TAB (`0x09`), and `0x7f` (DEL) is rejected. The scan stops at a NUL byte, as
/// the C loop condition (`while(len && *p)`) does.
fn invalid_octets(bytes: &[u8]) -> bool {
    for &b in bytes {
        if b == 0 {
            break;
        }
        if (b != 9 && b < 0x20) || b == 0x7f {
            return true;
        }
    }
    false
}

/// Returns `true` if a cookie `Domain` attribute is "bad" when no public-suffix
/// list is available, a faithful port of `bad_domain` (the `#ifndef USE_LIBPSL`
/// fallback).
///
/// Without a PSL curl cannot tell whether an incoming `Domain` names a TLD or
/// otherwise protected suffix, so to reduce risk it requires the domain to
/// either be exactly `localhost` (ASCII-case-insensitive) or contain a dot that
/// is not the trailing byte. Anything else is "bad" and its cookie is rejected.
fn bad_domain(domain: &[u8]) -> bool {
    if domain.len() == 9 && c_strncaseeq(domain, "localhost") {
        return false;
    }
    // There must be a dot, and it must not be the last byte.
    if let Some(dot) = domain.iter().position(|&b| b == b'.') {
        if domain.len() - dot > 1 {
            return false;
        }
    }
    true
}

/// Caps a cookie expiry no more than 400 days into the future (RFC 6265bis),
/// a faithful port of `cap_expires`.
///
/// Session cookies (`expires == 0`) and the near-`TIME_T_MAX` guard are handled
/// exactly as curl does, including the alignment of the capped value to a 60
/// second boundary after adding the 30 second slack.
fn cap_expires(now: i64, expires: i64) -> i64 {
    if expires != 0 && (CURL_OFF_T_MAX - COOKIES_MAXAGE - 30) > now {
        let cap = now + COOKIES_MAXAGE;
        if expires > cap {
            let cap = cap + 30;
            return (cap / 60) * 60;
        }
    }
    expires
}

/// Trims leading and trailing blanks (space and TAB) from a byte span,
/// reproducing `curlx_str_trimblanks`.
fn trim_blanks(mut span: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = span {
        if *first == b' ' || *first == b'\t' {
            span = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = span {
        if *last == b' ' || *last == b'\t' {
            span = rest;
        } else {
            break;
        }
    }
    span
}

/// The current wall-clock time in seconds since the Unix epoch.
///
/// Mirrors curl's `time(NULL)`. A pre-epoch clock (which cannot happen in
/// practice) is clamped to `0`.
fn system_now() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(dur) => dur.as_secs() as i64,
        Err(_) => 0,
    }
}

/// Returns whether the request origin is a "secure context" for cookie
/// purposes, a faithful port of `Curl_secure_context`.
///
/// A context is secure when the transport is TLS (`is_tls`) or the host is one
/// of the loopback names curl treats as trustworthy: `localhost` (matched
/// ASCII-case-insensitively), `127.0.0.1`, or `::1`.
#[must_use]
pub fn secure_context(is_tls: bool, host: &str) -> bool {
    is_tls || host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

/// The result of parsing an unsigned decimal number, mirroring the `STRE_*`
/// return codes of `curlx_str_number`.
enum NumResult {
    /// A number was parsed: `(value, bytes_consumed)`.
    Ok(i64, usize),
    /// The value exceeded the supplied maximum (`STRE_OVERFLOW`).
    Overflow,
    /// The span did not start with a digit (`STRE_NO_NUM`).
    NoNum,
}

/// Parses a leading unsigned decimal number capped at `max`, reproducing
/// `curlx_str_number` (base-10 `str_num_base`).
///
/// Returns [`NumResult::NoNum`] when the span does not begin with an ASCII
/// digit, [`NumResult::Overflow`] when the accumulated value would exceed `max`
/// (curl leaves the output at `0` in that case), and [`NumResult::Ok`] with the
/// value and the number of digit bytes consumed otherwise. The overflow test is
/// performed before each multiply-add exactly as curl does, so the boundary
/// behavior is identical.
fn str_number(bytes: &[u8], max: i64) -> NumResult {
    // MSRV 1.75: avoid `Option::is_none_or` (stabilized in 1.82).
    match bytes.first() {
        Some(b) if b.is_ascii_digit() => {}
        _ => return NumResult::NoNum,
    }
    let mut num: i64 = 0;
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        let n = i64::from(bytes[i] - b'0');
        if num > (max - n) / 10 {
            return NumResult::Overflow;
        }
        num = num * 10 + n;
        i += 1;
    }
    NumResult::Ok(num, i)
}

// ---------------------------------------------------------------------------
// Date parsing — a faithful port of `lib/parsedate.c` (`Curl_getdate_capped`).
//
// curl parses the wildly varied `expires` date strings with a hand-written
// tokenizer rather than a calendar library, so this port reproduces that exact
// tokenizer and its `time2epoch` integer arithmetic. It targets the 64-bit
// `time_t` configuration this workspace supports: a year before 1583 fails, an
// out-of-range far-future time is capped to `i64::MAX` (`PARSEDATE_LATER`), and
// there is no low-end underflow case.
// ---------------------------------------------------------------------------

/// Three-letter weekday abbreviations (`Curl_wkday`).
const WKDAY: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
/// Full weekday names (`weekday`).
const WEEKDAY: [&str; 7] = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
];
/// Three-letter month abbreviations (`Curl_month`).
const MONTH: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Offset applied to daylight-saving zone names (`tDAYZONE`), in minutes.
const T_DAYZONE: i32 = -60;

/// Time-zone name table (`tz`) — `(name, offset_in_minutes)`. The offsets and
/// the military single-letter zones are copied verbatim from `parsedate.c`.
const TZ: &[(&str, i32)] = &[
    ("GMT", 0),
    ("UT", 0),
    ("UTC", 0),
    ("WET", 0),
    ("BST", T_DAYZONE),
    ("WAT", 60),
    ("AST", 240),
    ("ADT", 240 + T_DAYZONE),
    ("EST", 300),
    ("EDT", 300 + T_DAYZONE),
    ("CST", 360),
    ("CDT", 360 + T_DAYZONE),
    ("MST", 420),
    ("MDT", 420 + T_DAYZONE),
    ("PST", 480),
    ("PDT", 480 + T_DAYZONE),
    ("YST", 540),
    ("YDT", 540 + T_DAYZONE),
    ("HST", 600),
    ("HDT", 600 + T_DAYZONE),
    ("CAT", 600),
    ("AHST", 600),
    ("NT", 660),
    ("IDLW", 720),
    ("CET", -60),
    ("MET", -60),
    ("MEWT", -60),
    ("MEST", -60 + T_DAYZONE),
    ("CEST", -60 + T_DAYZONE),
    ("MESZ", -60 + T_DAYZONE),
    ("FWT", -60),
    ("FST", -60 + T_DAYZONE),
    ("EET", -120),
    ("WAST", -420),
    ("WADT", -420 + T_DAYZONE),
    ("CCT", -480),
    ("JST", -540),
    ("EAST", -600),
    ("EADT", -600 + T_DAYZONE),
    ("GST", -600),
    ("NZT", -720),
    ("NZST", -720),
    ("NZDT", -720 + T_DAYZONE),
    ("IDLE", -720),
    // Military zones (RFC 822 signs corrected per RFC 1123); "J" is intentionally
    // absent (it denotes the observer's local time).
    ("A", 60),
    ("B", 120),
    ("C", 180),
    ("D", 240),
    ("E", 300),
    ("F", 360),
    ("G", 420),
    ("H", 480),
    ("I", 540),
    ("K", 600),
    ("L", 660),
    ("M", 720),
    ("N", -60),
    ("O", -120),
    ("P", -180),
    ("Q", -240),
    ("R", -300),
    ("S", -360),
    ("T", -420),
    ("U", -480),
    ("V", -540),
    ("W", -600),
    ("X", -660),
    ("Y", -720),
    ("Z", 0),
];

/// Which field an unqualified number should be assumed to be next (`enum
/// assume`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Assume {
    Mday,
    Year,
    /// Vestigial in curl too: `DATE_TIME` is declared in `enum assume` but never
    /// assigned to `dignext` (times are matched by `match_time`, not by the
    /// digit-assumption state machine). Kept for a faithful 1:1 mirror of the C
    /// enum; never constructed, exactly as in `parsedate.c`.
    #[allow(dead_code)]
    Time,
}

/// The three outcomes of [`parsedate`] relevant on 64-bit `time_t`
/// (`PARSEDATE_OK` / `PARSEDATE_FAIL` / `PARSEDATE_LATER`).
enum ParseResult {
    Ok,
    Fail,
    Later,
}

/// Returns the weekday index (0 = Monday … 6 = Sunday) for a name, or `-1`
/// (`checkday`). Names longer than three characters are matched against the full
/// weekday names, exactly-three-character names against the abbreviations.
fn checkday(name: &[u8]) -> i32 {
    use std::cmp::Ordering;
    // `checkday` compares the token length against 3 to select between the full
    // weekday names (`len > 3`) and the three-letter abbreviations (`len == 3`),
    // rejecting anything shorter. Expressed as a `match` on the ordering to keep
    // clippy's `comparison_chain` lint satisfied while preserving the exact C
    // branch semantics from `cookie.c`.
    let table: &[&str; 7] = match name.len().cmp(&3) {
        Ordering::Greater => &WEEKDAY,
        Ordering::Equal => &WKDAY,
        Ordering::Less => return -1,
    };
    for (i, cand) in table.iter().enumerate() {
        if cand.len() == name.len() && name.eq_ignore_ascii_case(cand.as_bytes()) {
            return i as i32;
        }
    }
    -1
}

/// Returns the month index (0 = January … 11 = December) for a three-letter
/// abbreviation, or `-1` (`checkmonth`).
fn checkmonth(name: &[u8]) -> i32 {
    if name.len() != 3 {
        return -1;
    }
    for (i, cand) in MONTH.iter().enumerate() {
        if name.eq_ignore_ascii_case(cand.as_bytes()) {
            return i as i32;
        }
    }
    -1
}

/// Returns a time-zone offset in **seconds**, or `-1` when the name is unknown
/// or too long (`checktz`). Names longer than four characters cannot be valid
/// zones and are rejected up front, as in curl.
fn checktz(name: &[u8]) -> i64 {
    if name.len() > 4 {
        return -1;
    }
    for (cand, off_min) in TZ {
        if cand.len() == name.len() && name.eq_ignore_ascii_case(cand.as_bytes()) {
            return i64::from(*off_min) * 60;
        }
    }
    -1
}

/// Reads a one- or two-digit decimal starting at `i`, returning
/// `(value, next_index)` (`oneortwodigit`). The caller guarantees `bytes[i]` is
/// a digit.
fn one_or_two_digit(bytes: &[u8], i: usize) -> (i32, usize) {
    let num = i32::from(bytes[i] - b'0');
    if i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
        (num * 10 + i32::from(bytes[i + 1] - b'0'), i + 2)
    } else {
        (num, i + 1)
    }
}

/// Matches an `HH:MM[:SS]` time (single digits allowed) starting at `i`,
/// returning `(hour, min, sec, next_index)` on success (`match_time`).
fn match_time(bytes: &[u8], i: usize) -> Option<(i32, i32, i32, usize)> {
    let (hh, mut p) = one_or_two_digit(bytes, i);
    if hh >= 24 || bytes.get(p) != Some(&b':') || !bytes.get(p + 1).is_some_and(u8::is_ascii_digit)
    {
        return None;
    }
    let (mm, np) = one_or_two_digit(bytes, p + 1);
    p = np;
    if mm >= 60 {
        return None;
    }
    if bytes.get(p) == Some(&b':') && bytes.get(p + 1).is_some_and(u8::is_ascii_digit) {
        let (ss, np) = one_or_two_digit(bytes, p + 1);
        if ss <= 60 {
            return Some((hh, mm, ss, np));
        }
        None
    } else {
        // Valid HH:MM with no seconds.
        Some((hh, mm, 0, p))
    }
}

/// Converts a broken-down UTC time to seconds since the Unix epoch
/// (`time2epoch`), using curl's exact leap-day arithmetic.
fn time2epoch(sec: i64, min: i64, hour: i64, mday: i64, mon: i64, year: i64) -> i64 {
    const MONTH_DAYS_CUMULATIVE: [i64; 12] =
        [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let mut leap_days = year - i64::from(mon <= 1);
    leap_days = (leap_days / 4) - (leap_days / 100) + (leap_days / 400) - (1969 / 4) + (1969 / 100)
        - (1969 / 400);
    ((((year - 1970) * 365 + leap_days + MONTH_DAYS_CUMULATIVE[mon as usize] + mday - 1) * 24
        + hour)
        * 60
        + min)
        * 60
        + sec
}

/// The core date tokenizer (`parsedate`), returning the outcome and the computed
/// timestamp. On [`ParseResult::Later`] the timestamp is `i64::MAX`.
fn parsedate(date: &[u8]) -> (ParseResult, i64) {
    let mut wdaynum: i32 = -1;
    let mut monnum: i32 = -1;
    let mut mdaynum: i32 = -1;
    let mut hournum: i32 = -1;
    let mut minnum: i32 = -1;
    let mut secnum: i32 = -1;
    let mut yearnum: i32 = -1;
    let mut tzoff: i64 = -1;
    let mut dignext = Assume::Mday;
    let mut i = 0usize;
    let mut part = 0;

    // Treat an interior NUL as end-of-string, mirroring the C `while(*date)`.
    let end = date.iter().position(|&b| b == 0).unwrap_or(date.len());
    let date = &date[..end];

    while i < date.len() && part < 6 {
        let mut found = false;

        // skip(): advance past everything that is not a letter or digit.
        while i < date.len() && !date[i].is_ascii_alphanumeric() {
            i += 1;
        }
        if i >= date.len() {
            // Nothing but separators left; count the part and let the loop end.
            part += 1;
            continue;
        }

        if date[i].is_ascii_alphabetic() {
            // A name (weekday / month / zone), at most NAME_LEN (12) letters.
            let start = i;
            let mut len = 0;
            while i < date.len() && date[i].is_ascii_alphabetic() && len < 12 {
                i += 1;
                len += 1;
            }
            let name = &date[start..start + len];

            if len != 12 {
                if wdaynum == -1 {
                    let d = checkday(name);
                    if d != -1 {
                        wdaynum = d;
                        found = true;
                    }
                }
                if !found && monnum == -1 {
                    let m = checkmonth(name);
                    if m != -1 {
                        monnum = m;
                        found = true;
                    }
                }
                if !found && tzoff == -1 {
                    let tz = checktz(name);
                    if tz != -1 {
                        tzoff = tz;
                        found = true;
                    }
                }
            }
            if !found {
                return (ParseResult::Fail, -1);
            }
        } else {
            // date[i] is a digit.
            let mut matched_time = false;
            if secnum == -1 {
                if let Some((h, m, s, np)) = match_time(date, i) {
                    hournum = h;
                    minnum = m;
                    secnum = s;
                    i = np;
                    matched_time = true;
                }
            }

            if !matched_time {
                let (val, num_digits) = match str_number(&date[i..], 99_999_999) {
                    NumResult::Ok(v, n) => (v, n),
                    // Overflow (9+ digits) or, impossibly here, no digit → fail.
                    _ => return (ParseResult::Fail, -1),
                };
                let before = if i > 0 { date[i - 1] } else { 0 };

                if tzoff == -1
                    && num_digits == 4
                    && val <= 1400
                    && i > 0
                    && (before == b'+' || before == b'-')
                {
                    // A numeric timezone such as "+0100".
                    found = true;
                    let mut off = (val / 100 * 60 + val % 100) * 60;
                    off = if before == b'+' { -off } else { off };
                    tzoff = off;
                } else if num_digits == 8 && yearnum == -1 && monnum == -1 && mdaynum == -1 {
                    // Eight digits with nothing set yet: YYYYMMDD.
                    found = true;
                    yearnum = (val / 10000) as i32;
                    monnum = ((val % 10000) / 100 - 1) as i32;
                    mdaynum = (val % 100) as i32;
                }

                if !found && dignext == Assume::Mday && mdaynum == -1 {
                    if val > 0 && val < 32 {
                        mdaynum = val as i32;
                        found = true;
                    }
                    dignext = Assume::Year;
                }

                if !found && dignext == Assume::Year && yearnum == -1 {
                    yearnum = val as i32;
                    found = true;
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
                    return (ParseResult::Fail, -1);
                }
                i += num_digits;
            }
        }

        part += 1;
    }

    if secnum == -1 {
        secnum = 0;
        minnum = 0;
        hournum = 0;
    }

    if mdaynum == -1 || monnum == -1 || yearnum == -1 {
        // Lacks vital info.
        return (ParseResult::Fail, -1);
    }

    // 64-bit time_t: the Gregorian calendar was introduced in 1582.
    if yearnum < 1583 {
        return (ParseResult::Fail, -1);
    }

    if mdaynum > 31 || monnum > 11 || hournum > 23 || minnum > 59 || secnum > 60 {
        return (ParseResult::Fail, -1);
    }

    let t = time2epoch(
        i64::from(secnum),
        i64::from(minnum),
        i64::from(hournum),
        i64::from(mdaynum),
        i64::from(monnum),
        i64::from(yearnum),
    );

    let tzoff = if tzoff == -1 { 0 } else { tzoff };

    if tzoff > 0 && t > CURL_OFF_T_MAX - tzoff {
        // time_t overflow at the far end of time.
        return (ParseResult::Later, CURL_OFF_T_MAX);
    }

    (ParseResult::Ok, t + tzoff)
}

/// Parses a date string the way curl's `Curl_getdate_capped` does.
///
/// Returns `Some(seconds_since_epoch)` on success (a far-future overflow is
/// capped to `i64::MAX`, matching `PARSEDATE_LATER`), or `None` when the date
/// cannot be parsed (`PARSEDATE_FAIL`).
fn getdate_capped(date: &str) -> Option<i64> {
    match parsedate(date.as_bytes()) {
        (ParseResult::Fail, _) => None,
        (_, t) => Some(t),
    }
}

// ---------------------------------------------------------------------------
// The `Cookie` record — a faithful port of `struct Cookie` (`lib/cookie.h`).
// ---------------------------------------------------------------------------

/// A single stored cookie, mirroring curl's `struct Cookie`.
///
/// Field semantics are preserved exactly:
///
/// * `expires` is a Unix epoch timestamp; `0` denotes a *session* cookie (one
///   that is discarded when the session ends and never written to a jar with a
///   real expiry).
/// * `creationtime` is **not** a wall-clock stamp — it is curl's monotonically
///   increasing per-jar counter (`++ci->lastct`). It exists purely to give the
///   output and match sorts a stable, insertion-ordered tie-breaker, so it is
///   reproduced as a counter rather than a time.
/// * `tailmatch` records whether the cookie's `domain` was set from an explicit
///   `Domain` attribute (and therefore also matches sub-domains); when it is
///   set, the jar writes a leading dot before the domain.
/// * `prefix_secure` / `prefix_host` capture the `__Secure-` / `__Host-` name
///   prefixes (RFC 6265bis §4.1.3), which impose extra constraints checked when
///   the cookie is added.
///
/// The type derives [`PartialEq`]/[`Eq`] so tests can assert exact round-trip
/// equality of a reloaded jar.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cookie {
    /// The cookie name (the part before the first `=` of the `Set-Cookie`).
    pub name: String,
    /// The cookie value (the part after the first `=`). Empty when absent.
    pub value: String,
    /// The `Path` attribute, sanitized (always begins with `/`). `None` when the
    /// cookie carried no `Path` and none was derived.
    pub path: Option<String>,
    /// The domain the cookie is scoped to. For a cookie with an explicit
    /// `Domain` this is stored **without** a leading dot (with `tailmatch` set);
    /// otherwise it is the exact request host.
    pub domain: Option<String>,
    /// Expiry as seconds since the Unix epoch; `0` means a session cookie.
    pub expires: i64,
    /// curl's creation-order counter (`++ci->lastct`), used only for sorting.
    pub creationtime: u32,
    /// Mirror of curl's historical `lastaccess` field; set equal to
    /// `creationtime` when the cookie is stored. Preserved for API completeness.
    pub lastaccess: u32,
    /// `true` when the cookie also matches sub-domains (came from a `Domain`
    /// attribute); controls the leading dot written to the jar.
    pub tailmatch: bool,
    /// The `Secure` attribute: the cookie is only sent over a secure transport.
    pub secure: bool,
    /// `true` for a cookie received live over the network (as opposed to loaded
    /// from a jar file); live cookies win when replacing an existing entry.
    pub livecookie: bool,
    /// The `HttpOnly` attribute: the cookie is withheld from non-HTTP(S) access
    /// and written to the jar with the `#HttpOnly_` prefix.
    pub httponly: bool,
    /// The name carried the `__Secure-` prefix (`COOKIE_PREFIX__SECURE`).
    pub prefix_secure: bool,
    /// The name carried the `__Host-` prefix (`COOKIE_PREFIX__HOST`).
    pub prefix_host: bool,
}

impl Cookie {
    /// Formats this cookie as a single Netscape cookie-jar line **without** the
    /// trailing newline, a faithful port of `get_netscape_format`.
    ///
    /// The layout is seven TAB-separated fields — `domain`, `tailmatch`, `path`,
    /// `secure`, `expires`, `name`, `value` — with two curl-exact quirks:
    ///
    /// * an HttpOnly cookie is prefixed with the literal `#HttpOnly_`
    ///   immediately before the domain (no separating space); and
    /// * a leading dot is written before the domain when the cookie tail-matches
    ///   and the stored domain does not already begin with a dot (the
    ///   Netscape/Mozilla convention for sub-domain cookies).
    ///
    /// A missing domain renders as `unknown` and a missing path as `/`, matching
    /// curl's defensive fallbacks.
    #[must_use]
    pub fn to_netscape_line(&self) -> String {
        let httponly_prefix = if self.httponly { "#HttpOnly_" } else { "" };

        let domain = self.domain.as_deref();
        let dot_prefix = match domain {
            Some(d) if self.tailmatch && !d.starts_with('.') => ".",
            _ => "",
        };
        let domain = domain.unwrap_or("unknown");
        let tailmatch = if self.tailmatch { "TRUE" } else { "FALSE" };
        let path = self.path.as_deref().unwrap_or("/");
        let secure = if self.secure { "TRUE" } else { "FALSE" };

        format!(
            "{httponly_prefix}{dot_prefix}{domain}\t{tailmatch}\t{path}\t{secure}\t{expires}\t{name}\t{value}",
            expires = self.expires,
            name = self.name,
            value = self.value,
        )
    }
}

// ---------------------------------------------------------------------------
// The `CookieJar` — a faithful port of `struct CookieInfo` (`lib/cookie.h`).
// ---------------------------------------------------------------------------

/// The cookie store, a port of curl's `struct CookieInfo`.
///
/// curl keeps cookies in a `COOKIE_HASH_SIZE`-bucketed hash table keyed on the
/// top-most domain label; this port keeps a single ordered [`Vec`] because the
/// bucketing is a non-observable lookup optimization (see the module docs).
///
/// A `CookieJar` is a plain owned value. To realize curl's cross-handle
/// `curl_share` cookie sharing it is wrapped in a [`SharedCookieJar`]
/// (`Arc<Mutex<CookieJar>>`) via [`CookieJar::into_shared`], which replaces the
/// C `Curl_share_lock` / `Curl_share_unlock` dance with ordinary Rust locking.
pub struct CookieJar {
    /// Every stored cookie, in insertion order. Output and match ordering are
    /// derived by sorting, never from this order.
    cookies: Vec<Cookie>,
    /// The soonest future expiry among stored cookies, used to short-circuit
    /// [`remove_expired`](CookieJar::remove_expired). `0` forces a full scan
    /// (matching curl's calloc-zeroed initial value / an externally authored
    /// jar).
    next_expiration: i64,
    /// The last creation-order counter handed out (`ci->lastct`).
    lastct: u32,
    /// `true` while processing live network cookies, `false` while loading a jar
    /// file. Governs the "live cookie wins" replace rule and the trust applied
    /// to `Secure`/session attributes.
    running: bool,
    /// When `true`, session cookies (no expiry) are discarded on load — curl's
    /// "new session" behavior (`CURLOPT_COOKIESESSION`).
    newsession: bool,
    /// The public-suffix list used for the "supercookie" domain-acceptance
    /// defense. An empty list ([`Psl::is_available`] is `false`) selects curl's
    /// non-`libpsl` heuristic fallback.
    psl: Psl,
    /// The jar file cookies are written to on [`save`](CookieJar::save) when no
    /// explicit path is given (`CURLOPT_COOKIEJAR`).
    filename: Option<String>,
    /// The list of files to (re)load (`CURLOPT_COOKIEFILE` entries), remembered
    /// so a `RELOAD` command can replay them.
    files: Vec<String>,
}

/// A [`CookieJar`] shared across handles, mirroring curl's `curl_share` cookie
/// sharing. Cloning the `Arc` shares one jar; the `Mutex` serializes access the
/// way `Curl_share_lock`/`Curl_share_unlock` serialize the C jar.
pub type SharedCookieJar = Arc<Mutex<CookieJar>>;

impl fmt::Debug for CookieJar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CookieJar")
            .field("cookies", &self.cookies.len())
            .field("next_expiration", &self.next_expiration)
            .field("lastct", &self.lastct)
            .field("running", &self.running)
            .field("newsession", &self.newsession)
            .field("psl_available", &self.psl.is_available())
            .field("filename", &self.filename)
            .field("files", &self.files)
            .finish()
    }
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::new()
    }
}

impl CookieJar {
    /// Creates an empty jar ready to ingest live cookies.
    ///
    /// Equivalent to `Curl_cookie_init(NULL)` followed by the `running = TRUE`
    /// that curl sets once initialization completes: a freshly built jar is in
    /// the "running" (live-network) state and carries the bundled public-suffix
    /// list, so the "supercookie" domain defense is active by default — parity
    /// with a curl built against `libpsl`. Use
    /// [`with_psl(Psl::empty())`](Self::with_psl) for the no-`libpsl` fallback.
    #[must_use]
    pub fn new() -> Self {
        CookieJar {
            cookies: Vec::new(),
            // curl's `Curl_cookie_init` seeds `next_expiration` with
            // `CURL_OFF_T_MAX` to signal "not enough information yet". This
            // sentinel is what lets `add_at`'s soonest-expiry fold
            // (`co.expires < next_expiration`) record the first real expiry;
            // seeding with 0 would wrongly leave it pinned at 0 through a bulk
            // load (only causing extra sweeps, but diverging from curl).
            next_expiration: CURL_OFF_T_MAX,
            lastct: 0,
            running: true,
            newsession: false,
            // Load the bundled Public Suffix List so the supercookie defense is
            // on by default, matching a curl built with libpsl. The list is
            // parsed once and shared via Arc, so this is cheap. Callers wanting
            // the no-libpsl behavior use `CookieJar::with_psl(Psl::empty())`.
            psl: Psl::bundled(),
            filename: None,
            files: Vec::new(),
        }
    }

    /// Creates an empty jar that uses `psl` for the supercookie domain defense.
    #[must_use]
    pub fn with_psl(psl: Psl) -> Self {
        CookieJar {
            psl,
            ..CookieJar::new()
        }
    }

    /// Installs (or replaces) the public-suffix list used for domain acceptance.
    pub fn set_psl(&mut self, psl: Psl) {
        self.psl = psl;
    }

    /// Consumes the jar and wraps it for cross-handle sharing
    /// ([`SharedCookieJar`]).
    #[must_use]
    pub fn into_shared(self) -> SharedCookieJar {
        Arc::new(Mutex::new(self))
    }

    /// The number of cookies currently stored (curl's `numcookies`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    /// Whether the jar holds no cookies.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    /// Read-only access to the stored cookies (insertion order).
    #[must_use]
    pub fn cookies(&self) -> &[Cookie] {
        &self.cookies
    }

    /// Whether the jar is in the "running" (live-network) state.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Sets the running state. Live network processing uses `true`; loading a
    /// jar file uses `false` (which is managed internally by the load routines).
    pub fn set_running(&mut self, running: bool) {
        self.running = running;
    }

    /// Sets the "new session" flag (`CURLOPT_COOKIESESSION`): when `true`,
    /// session cookies are discarded the next time a jar file is loaded.
    pub fn set_newsession(&mut self, newsession: bool) {
        self.newsession = newsession;
    }

    /// Records the default jar file used by [`save`](CookieJar::save) when no
    /// explicit path is supplied (`CURLOPT_COOKIEJAR`).
    pub fn set_jar_file(&mut self, path: impl Into<String>) {
        self.filename = Some(path.into());
    }

    /// The configured default jar file, if any.
    #[must_use]
    pub fn jar_file(&self) -> Option<&str> {
        self.filename.as_deref()
    }

    /// Appends a file to the list of cookie files to read
    /// (`CURLOPT_COOKIEFILE`), a port of curl's `cookiefile` accumulation into
    /// `data->state.cookielist`.
    ///
    /// The path is remembered but not read immediately; it is consumed by
    /// [`load_files`](CookieJar::load_files) and by the `RELOAD`
    /// [`command`](CookieJar::command). As in curl the same file may be added
    /// more than once, and the special name `"-"` denotes standard input.
    pub fn add_file(&mut self, file: impl Into<String>) {
        self.files.push(file.into());
    }

    /// The list of cookie files queued for reading (`CURLOPT_COOKIEFILE`).
    #[must_use]
    pub fn cookie_files(&self) -> &[String] {
        &self.files
    }
}

// ---------------------------------------------------------------------------
// Set-Cookie header parsing — a faithful port of `parse_cookie_header` +
// `storecookie` (`lib/cookie.c`).
// ---------------------------------------------------------------------------

/// Parses a single `Set-Cookie` header value into a [`Cookie`], reproducing
/// curl's `parse_cookie_header` tokenizer exactly.
///
/// `line` is the header value with the `Set-Cookie:` prefix already stripped.
/// `default_domain` / `default_path` are the request host and full request path
/// used to fill in a cookie that omits `Domain` / `Path` (curl's `domain` /
/// `path` arguments). `secure` is whether the request used a secure transport,
/// `running` whether the jar is processing live network cookies (vs. loading a
/// file), and `psl_available` whether a public-suffix list is loaded (which
/// selects between the PSL path and the `bad_domain` heuristic).
///
/// Returns `Some(cookie)` when a valid cookie was parsed (curl's `okay == TRUE`)
/// with its `name`, `value`, `domain`, `path`, `expires`, `secure`, `httponly`,
/// `tailmatch`, and prefix flags populated; returns `None` when the line is
/// dropped (overly long, invalid octets, oversized, a TAB in the value, a
/// non-secure `Secure`, a bad domain tail-match, or no cookie name).
fn parse_cookie_header(
    line: &[u8],
    default_domain: Option<&str>,
    default_path: Option<&str>,
    secure: bool,
    running: bool,
    psl_available: bool,
    now: i64,
) -> Option<Cookie> {
    // Discard overly long lines at once (curl: `linelength > MAX_COOKIE_LINE`).
    if line.len() > MAX_COOKIE_LINE {
        return None;
    }

    let mut co = Cookie::default();
    let mut pos = 0usize;

    // Staged pieces, mirroring curl's `cookie[COOKIE_PIECES]` array. The first
    // name/value pair is committed only once, everything else is last-wins.
    let mut have_name = false;
    let mut name_field: &[u8] = b"";
    let mut value_field: &[u8] = b"";
    let mut path_field: Option<&[u8]> = None;
    let mut domain_field: Option<&[u8]> = None;

    loop {
        // Read <name>: a non-empty span of bytes that are not in ";\t\r\n=".
        let nstart = pos;
        while pos < line.len() && !matches!(line[pos], b';' | b'\t' | b'\r' | b'\n' | b'=') {
            pos += 1;
        }
        let name_raw = &line[nstart..pos];

        // Only process when the span was non-empty (curl's `!curlx_str_cspn`).
        if !name_raw.is_empty() {
            let name = trim_blanks(name_raw);
            let mut sep = false;
            let mut val: &[u8] = b"";

            // Consume a single '=' if present, then read the value up to ";\r\n".
            if pos < line.len() && line[pos] == b'=' {
                pos += 1;
                sep = true;
                let vstart = pos;
                while pos < line.len() && !matches!(line[pos], b';' | b'\r' | b'\n') {
                    pos += 1;
                }
                let val_raw = &line[vstart..pos];
                if !val_raw.is_empty() {
                    val = trim_blanks(val_raw);
                }
            }

            if !have_name {
                // The first name/value pair is the actual cookie name/value.
                if !sep || invalid_octets(name) || invalid_octets(val) || name.is_empty() {
                    // Invalid octets in name/value (or a bare first word).
                    return None;
                }

                // Reject an over-long name, value, or name+value combination
                // (Chrome/Firefox accept ~4095/4096 bytes).
                if name.len() >= (MAX_NAME - 1)
                    || val.len() >= (MAX_NAME - 1)
                    || (name.len() + val.len() > MAX_NAME)
                {
                    return None;
                }

                // Reject a cookie whose value contains a TAB.
                if !val.is_empty() && val.contains(&b'\t') {
                    return None;
                }

                // Reserved name prefixes (compared case-sensitively, as curl does).
                if name.starts_with(b"__Secure-") {
                    co.prefix_secure = true;
                } else if name.starts_with(b"__Host-") {
                    co.prefix_host = true;
                }

                name_field = name;
                value_field = val;
                have_name = true;
            } else if !sep {
                // A stand-alone word (no '=').
                if c_casecompare(name, "secure") {
                    // Secure may be set only over a secure origin, or when the
                    // cookie is being read from a file (not "running").
                    if secure || !running {
                        co.secure = true;
                    } else {
                        return None;
                    }
                } else if c_casecompare(name, "httponly") {
                    co.httponly = true;
                }
                // Any other bare word (e.g. a valueless attribute) is ignored.
            } else if c_casecompare(name, "path") {
                path_field = Some(val);
            } else if c_casecompare(name, "domain") && !val.is_empty() {
                // Ensure our host is within the given domain, or reject it.
                let mut v = val;
                if v[0] == b'.' {
                    v = &v[1..];
                }

                // Without a PSL, require the domain to contain a non-trailing dot
                // or be exactly "localhost"; otherwise poison the host so the
                // acceptance check below fails (curl sets `domain = ":"`).
                let effective_host: Option<&str> = if !psl_available && bad_domain(v) {
                    Some(":")
                } else {
                    default_domain
                };

                // `Curl_host_is_ipnum(domain ? domain : val)`.
                let is_ip = match effective_host {
                    Some(h) => is_ip_address(h),
                    None => is_ip_address(&String::from_utf8_lossy(v)),
                };

                let accept = match effective_host {
                    // No default host: accept any domain (curl's `!domain`).
                    None => true,
                    Some(host) => {
                        if is_ip {
                            // Host is numeric: require an exact domain match.
                            v == host.as_bytes()
                        } else {
                            // Host is a name: require the host to tail-match `v`.
                            cookie_tailmatch(v, host.as_bytes())
                        }
                    }
                };

                if accept {
                    domain_field = Some(v);
                    if !is_ip {
                        // Always tail-match when a domain name was given.
                        co.tailmatch = true;
                    }
                } else {
                    // Attempted domain is not one the host belongs to.
                    return None;
                }
            } else if c_casecompare(name, "max-age") && !val.is_empty() {
                // RFC 2109 Max-Age: lifetime in seconds; 0 (or bad) expires now.
                let maxage = if val[0] == b'"' { &val[1..] } else { val };
                match str_number(maxage, CURL_OFF_T_MAX) {
                    NumResult::Overflow => co.expires = CURL_OFF_T_MAX,
                    // Negative or otherwise bad → expire immediately.
                    NumResult::NoNum => co.expires = 1,
                    NumResult::Ok(v, _) => {
                        co.expires = if v == 0 {
                            1
                        } else if CURL_OFF_T_MAX - now < v {
                            CURL_OFF_T_MAX
                        } else {
                            v + now
                        };
                    }
                }
                co.expires = cap_expires(now, co.expires);
            } else if c_casecompare(name, "expires")
                && !val.is_empty()
                && co.expires == 0
                && val.len() < MAX_DATE_LENGTH
            {
                // Max-Age has priority; an unparseable date → session cookie.
                let dstr = String::from_utf8_lossy(val);
                match getdate_capped(&dstr) {
                    Some(date) => co.expires = if date == 0 { 1 } else { date },
                    None => co.expires = 0,
                }
                co.expires = cap_expires(now, co.expires);
            }
        }

        // `while(!curlx_str_single(&ptr, ';'))`: keep going only across ';'.
        if pos < line.len() && line[pos] == b';' {
            pos += 1;
        } else {
            break;
        }
    }

    // Nothing to store unless we captured a cookie name (curl's final check).
    if !have_name {
        return None;
    }

    // --- storecookie: commit name/value and fill in default path/domain. ---
    co.name = String::from_utf8_lossy(name_field).into_owned();
    co.value = String::from_utf8_lossy(value_field).into_owned();

    // Path: an explicit non-empty Path wins; otherwise derive from the request
    // path; otherwise leave unset.
    let path_slice: Option<&[u8]> = match path_field {
        Some(p) if !p.is_empty() => Some(p),
        _ => default_path.map(default_path_prefix),
    };
    if let Some(ps) = path_slice {
        co.path = Some(sanitize_cookie_path(ps));
    }

    // Domain: an explicit non-empty Domain wins; otherwise use the request host.
    match domain_field {
        Some(d) if !d.is_empty() => {
            co.domain = Some(String::from_utf8_lossy(d).into_owned());
        }
        _ => {
            if let Some(dd) = default_domain {
                co.domain = Some(dd.to_string());
            }
        }
    }

    Some(co)
}

/// Reproduces libpsl's `psl_is_cookie_domain_acceptable(psl, hostname,
/// cookie_domain)` using [`Psl::is_public_suffix`].
///
/// A cookie domain is acceptable when it exactly equals the hostname, or when it
/// is a proper suffix of the hostname at a dot boundary **and** is not itself a
/// public suffix. Both inputs are expected already lowercased (curl lowercases
/// them before the call).
fn psl_cookie_domain_acceptable(psl: &Psl, hostname: &str, cookie_domain: &str) -> bool {
    // Strip any leading dots from the cookie domain.
    let cookie_domain = cookie_domain.trim_start_matches('.');

    // An exact match is always acceptable (even for a public suffix).
    if hostname == cookie_domain {
        return true;
    }

    // The cookie domain must be strictly shorter to be a parent of the host.
    if cookie_domain.len() >= hostname.len() {
        return false;
    }
    // It must be a suffix of the hostname...
    if !hostname.ends_with(cookie_domain) {
        return false;
    }
    // ...at a dot boundary.
    let boundary = hostname.len() - cookie_domain.len();
    if hostname.as_bytes()[boundary - 1] != b'.' {
        return false;
    }

    // And it must not itself be a public suffix (the supercookie defense).
    !psl.is_public_suffix(cookie_domain)
}

// ---------------------------------------------------------------------------
// Netscape jar-line parsing — a faithful port of `parse_netscape` (`cookie.c`).
// ---------------------------------------------------------------------------

/// Applies the Netscape `secure` field (used by both field index 2's
/// boolean-fallthrough and field index 3), returning `false` when the cookie
/// must be dropped.
///
/// A `TRUE` secure flag is honored only over a secure origin or while the jar is
/// "running"; a secure cookie read from a file into a non-running, non-secure
/// context is rejected (curl `return CURLE_OK` with `okay == FALSE`).
fn apply_netscape_secure(co: &mut Cookie, field: &[u8], secure: bool, running: bool) -> bool {
    co.secure = false;
    if c_strncaseeq(field, "TRUE") {
        if secure || running {
            co.secure = true;
        } else {
            return false;
        }
    }
    true
}

/// Parses a single Netscape cookie-jar line into a [`Cookie`], reproducing
/// curl's `parse_netscape` exactly.
///
/// The seven TAB-separated fields are `domain`, `tailmatch`, `path`, `secure`,
/// `expires`, `name`, `value`. Two curl-exact behaviors are preserved:
///
/// * a leading `#HttpOnly_` marks the cookie HttpOnly and is stripped, while any
///   other line beginning with `#` is a comment and is skipped; and
/// * if the path field "looks like" a boolean (`TRUE`/`FALSE`, matched
///   case-sensitively) the path is defaulted to `/` and that same field is
///   re-interpreted as the `secure` flag — the classic Netscape layout in which
///   the path column may be omitted.
///
/// A six-field line (missing value) is accepted with an empty value; any other
/// field count is rejected. Returns `Some(cookie)` on success or `None` when the
/// line is a comment, is malformed, has too few/many fields, carries an
/// unparseable/negative/overflowing `expires`, or is a non-honorable secure
/// cookie.
fn parse_netscape(line: &[u8], secure: bool, running: bool) -> Option<Cookie> {
    let mut co = Cookie::default();
    let mut lp = line;

    // A leading "#HttpOnly_" (case-sensitive) flags HttpOnly and is stripped.
    if lp.starts_with(b"#HttpOnly_") {
        lp = &lp[10..];
        co.httponly = true;
    }

    // Any other '#' line is a comment.
    if lp.first() == Some(&b'#') {
        return None;
    }

    let mut fields: i32 = 0;
    let mut pos = 0usize;

    loop {
        // Read the current field up to a TAB / CR / LF.
        let fstart = pos;
        while pos < lp.len() && !matches!(lp[pos], b'\t' | b'\r' | b'\n') {
            pos += 1;
        }
        let mut fptr = &lp[fstart..pos];
        let has_tab = pos < lp.len() && lp[pos] == b'\t';

        match fields {
            0 => {
                // Domain; skip a single preceding dot.
                if fptr.first() == Some(&b'.') {
                    fptr = &fptr[1..];
                }
                co.domain = Some(String::from_utf8_lossy(fptr).into_owned());
            }
            1 => {
                // Tail-match flag (case-insensitive "TRUE").
                co.tailmatch = c_strncaseeq(fptr, "TRUE");
            }
            2 => {
                // Path — unless it looks like a boolean, in which case the path
                // column was omitted: default it and re-read this field as
                // `secure` (case-sensitive boolean test).
                if !c_strncmp_eq("TRUE", fptr) && !c_strncmp_eq("FALSE", fptr) {
                    co.path = Some(sanitize_cookie_path(fptr));
                } else {
                    co.path = Some("/".to_string());
                    fields += 1; // consume an extra field and fall into `secure`
                    if !apply_netscape_secure(&mut co, fptr, secure, running) {
                        return None;
                    }
                }
            }
            3 => {
                if !apply_netscape_secure(&mut co, fptr, secure, running) {
                    return None;
                }
            }
            4 => {
                // Expires: a non-number / negative / overflow drops the cookie.
                match str_number(fptr, CURL_OFF_T_MAX) {
                    NumResult::Ok(v, _) => co.expires = v,
                    _ => return None,
                }
            }
            5 => {
                co.name = String::from_utf8_lossy(fptr).into_owned();
                // Prefix check for jar-format cookies is case-insensitive.
                let nb = co.name.as_bytes();
                if nb.len() >= 9 && nb[..9].eq_ignore_ascii_case(b"__Secure-") {
                    co.prefix_secure = true;
                } else if nb.len() >= 7 && nb[..7].eq_ignore_ascii_case(b"__Host-") {
                    co.prefix_host = true;
                }
            }
            6 => {
                co.value = String::from_utf8_lossy(fptr).into_owned();
            }
            _ => {}
        }

        // for-loop post-increment (`fields++`).
        fields += 1;

        if has_tab {
            pos += 1;
            continue;
        }
        break;
    }

    if fields == 6 {
        // A cookie with blank contents: fill in an empty value.
        co.value = String::new();
        fields += 1;
    }

    if fields != 7 {
        // Insufficient (or excessive) number of fields.
        return None;
    }

    Some(co)
}

// ---------------------------------------------------------------------------
// Cookie ingestion and expiry — a faithful port of `Curl_cookie_add`,
// `remove_expired`, `replace_existing`, and `is_public_suffix` (`cookie.c`).
// ---------------------------------------------------------------------------

/// The outcome of [`CookieJar::replace_existing`] — either the new cookie is
/// dropped, or it may proceed to be stored.
///
/// curl tracks a separate `numcookies` counter and only bumps it when the
/// newcomer did *not* replace an existing entry. This port stores cookies in a
/// [`Vec`] whose length *is* the count: [`replace_existing`](CookieJar::replace_existing)
/// removes the superseded entry in place, so a subsequent push keeps the length
/// correct whether or not a replacement occurred. The replacement bookkeeping is
/// therefore implicit and no flag is carried here.
enum ReplaceOutcome {
    /// The new cookie must not be stored (would overlay a secure cookie, or a
    /// live cookie of the same identity already exists).
    Drop,
    /// The new cookie may be stored (any superseded entry has already been
    /// removed).
    Proceed,
}

impl CookieJar {
    /// Removes expired cookies, a faithful port of `remove_expired`.
    ///
    /// If the soonest recorded expiry is safely in the future the scan is
    /// skipped; otherwise every cookie with a non-zero expiry in the past is
    /// evicted and the soonest future expiry is recomputed. Session cookies
    /// (`expires == 0`) are never expiry-evicted.
    fn remove_expired_at(&mut self, now: i64) {
        if now < self.next_expiration && self.next_expiration != CURL_OFF_T_MAX {
            return;
        }
        let mut soonest = CURL_OFF_T_MAX;
        self.cookies.retain(|co| {
            if co.expires != 0 {
                if co.expires < now {
                    return false;
                }
                if co.expires < soonest {
                    soonest = co.expires;
                }
            }
            true
        });
        self.next_expiration = soonest;
    }

    /// Removes expired cookies using the current wall-clock time.
    pub fn remove_expired(&mut self) {
        self.remove_expired_at(system_now());
    }

    /// The public-suffix "supercookie" defense, a faithful port of
    /// `is_public_suffix`.
    ///
    /// Returns `true` when the cookie must be dropped because its `Domain`
    /// names a public suffix it is not allowed to set cookies for. With no PSL
    /// loaded this is a no-op (the [`bad_domain`] heuristic in the header parser
    /// covers that configuration instead), exactly mirroring curl's
    /// `#ifdef USE_LIBPSL` split.
    fn is_public_suffix_reject(&self, co: &Cookie, request_host: Option<&str>) -> bool {
        if !self.psl.is_available() {
            return false;
        }
        let (Some(host), Some(cdom)) = (request_host, co.domain.as_deref()) else {
            return false;
        };
        // A numeric cookie domain is exempt from the PSL check.
        if is_ip_address(cdom) {
            return false;
        }
        // curl copies both names into 256-byte buffers; an over-long name is
        // treated as unacceptable and the cookie is dropped.
        if host.len() >= 256 || cdom.len() >= 256 {
            return true;
        }
        let host_lc = host.to_ascii_lowercase();
        let cdom_lc = cdom.to_ascii_lowercase();
        !psl_cookie_domain_acceptable(&self.psl, &host_lc, &cdom_lc)
    }

    /// Determines whether a new cookie supersedes (or is blocked by) an existing
    /// one, a faithful port of `replace_existing`.
    ///
    /// The scan reproduces curl's two checks verbatim:
    ///
    /// * A non-secure cookie may not overlay a same-name, same-domain **secure**
    ///   cookie whose path shares the leading path segment. curl computes that
    ///   segment as the bytes up to the *second* `/` of the existing path (or
    ///   the whole path if there is no second `/`) and drops the newcomer when
    ///   the new path shares that prefix — so an existing secure `/login` blocks
    ///   both `/login/en` **and** `/loginhelper`. The code is reproduced, not the
    ///   narrower behavior its comment suggests.
    /// * The new cookie replaces the first existing cookie with the same name,
    ///   an equal (case-insensitive) domain, the same `tailmatch`, and an equal
    ///   path (or both paths absent). If that existing cookie is "live" (from the
    ///   network) and the newcomer is not (from a file), the newcomer is dropped
    ///   instead — live cookies win.
    ///
    /// On replacement the newcomer inherits the old cookie's `creationtime` and
    /// the old cookie is removed here.
    fn replace_existing(&mut self, co: &mut Cookie, secure: bool) -> ReplaceOutcome {
        let mut replace_idx: Option<usize> = None;

        for (idx, clist) in self.cookies.iter().enumerate() {
            // --- Pass A: secure-overlay protection (checked for every match). ---
            if clist.name == co.name {
                let matching_domains = match (clist.domain.as_deref(), co.domain.as_deref()) {
                    (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                    (None, None) => true,
                    _ => false,
                };

                if matching_domains
                    && clist.path.is_some()
                    && co.path.is_some()
                    && clist.secure
                    && !co.secure
                    && !secure
                {
                    let cl_path = clist.path.as_deref().unwrap().as_bytes();
                    // Length up to (not including) the second '/', else full.
                    let cllen = if cl_path.len() > 1 {
                        match cl_path[1..].iter().position(|&b| b == b'/') {
                            Some(rel) => 1 + rel,
                            None => cl_path.len(),
                        }
                    } else {
                        cl_path.len()
                    };
                    let co_path = co.path.as_deref().unwrap().as_bytes();
                    if co_path.len() >= cllen
                        && co_path[..cllen].eq_ignore_ascii_case(&cl_path[..cllen])
                    {
                        // Would overlay an existing secure cookie.
                        return ReplaceOutcome::Drop;
                    }
                }
            }

            // --- Pass B: locate the first cookie this one replaces. ---
            if replace_idx.is_none() && clist.name == co.name {
                let mut replace_old = match (clist.domain.as_deref(), co.domain.as_deref()) {
                    (Some(a), Some(b)) => {
                        a.eq_ignore_ascii_case(b) && clist.tailmatch == co.tailmatch
                    }
                    (None, None) => true,
                    _ => false,
                };

                if replace_old {
                    let both_present_differ = match (clist.path.as_deref(), co.path.as_deref()) {
                        (Some(a), Some(b)) => !a.eq_ignore_ascii_case(b),
                        _ => false,
                    };
                    // Keep `replace_old` true only when both paths are present
                    // and compare equal, or when both are absent; drop it when
                    // the paths differ or exactly one side has a path. This
                    // collapses the two identical C branches into one condition
                    // to satisfy clippy's `if_same_then_else` without changing
                    // the semantics of `Curl_cookie_add`.
                    if both_present_differ || (clist.path.is_some() != co.path.is_some()) {
                        replace_old = false;
                    }
                }

                if replace_old && !co.livecookie && clist.livecookie {
                    // Existing live cookie is preferred; drop the newcomer.
                    return ReplaceOutcome::Drop;
                }
                if replace_old {
                    replace_idx = Some(idx);
                }
            }
        }

        if let Some(idx) = replace_idx {
            co.creationtime = self.cookies[idx].creationtime;
            self.cookies.remove(idx);
        }
        ReplaceOutcome::Proceed
    }

    /// Ingests one cookie line at a fixed `now`, a faithful port of
    /// `Curl_cookie_add`. Returns `true` when the cookie was stored.
    ///
    /// Note: curl's per-request `MAX_SET_COOKIE_AMOUNT` (50) cap lives in the
    /// request layer (`data->req.setcookies`), not in the jar; callers ingesting
    /// live `Set-Cookie` headers enforce it, so it is intentionally not applied
    /// here.
    #[allow(clippy::too_many_arguments)]
    fn add_at(
        &mut self,
        http_header: bool,
        no_expire: bool,
        line: &[u8],
        domain: Option<&str>,
        path: Option<&str>,
        secure: bool,
        now: i64,
    ) -> bool {
        let mut co = if http_header {
            match parse_cookie_header(
                line,
                domain,
                path,
                secure,
                self.running,
                self.psl.is_available(),
                now,
            ) {
                Some(c) => c,
                None => return false,
            }
        } else {
            match parse_netscape(line, secure, self.running) {
                Some(c) => c,
                None => return false,
            }
        };

        // The __Secure- prefix requires the cookie to be secure.
        if co.prefix_secure && !co.secure {
            return false;
        }

        // The __Host- prefix requires secure + path "/" + no domain (tailmatch).
        if co.prefix_host && !(co.secure && co.path.as_deref() == Some("/") && !co.tailmatch) {
            return false;
        }

        // Discard session cookies when loading a file with "new session".
        if !self.running && self.newsession && co.expires == 0 {
            return false;
        }

        co.livecookie = self.running;
        self.lastct = self.lastct.wrapping_add(1);
        co.creationtime = self.lastct;
        co.lastaccess = co.creationtime;

        // Remove expired cookies unless explicitly skipped (bulk file load).
        if !no_expire {
            self.remove_expired_at(now);
        }

        // Public-suffix supercookie defense.
        if self.is_public_suffix_reject(&co, domain) {
            return false;
        }

        // Supersede an existing cookie where applicable.
        match self.replace_existing(&mut co, secure) {
            ReplaceOutcome::Drop => return false,
            ReplaceOutcome::Proceed => {}
        }

        // Update the soonest-expiry tracker before the cookie is moved in.
        if co.expires != 0 && co.expires < self.next_expiration {
            self.next_expiration = co.expires;
        }

        self.cookies.push(co);
        true
    }

    /// Ingests one cookie line, a faithful port of `Curl_cookie_add`.
    ///
    /// `http_header` selects the `Set-Cookie`-header tokenizer (`true`) or the
    /// Netscape jar-line parser (`false`). `no_expire` skips the
    /// [`remove_expired`](CookieJar::remove_expired) sweep (used during bulk file
    /// loads). `domain` / `path` are the request host and full request path used
    /// to default a cookie that omits `Domain` / `Path`. `secure` indicates a
    /// secure transport.
    ///
    /// Returns `Ok(true)` when the cookie was stored (added or replaced) and
    /// `Ok(false)` when it was dropped for any of curl's many reasons (invalid
    /// octets, oversize, a value TAB, a bad domain tail-match, a public-suffix
    /// rejection, a failed prefix rule, a discarded session cookie, or a secure
    /// overlay).
    ///
    /// # Errors
    ///
    /// This function does not currently return an error; the [`Result`] shape is
    /// retained for API parity with the C `CURLcode` contract (`Curl_cookie_add`
    /// returns `CURLcode`).
    pub fn add(
        &mut self,
        http_header: bool,
        no_expire: bool,
        line: &str,
        domain: Option<&str>,
        path: Option<&str>,
        secure: bool,
    ) -> Result<bool> {
        Ok(self.add_at(
            http_header,
            no_expire,
            line.as_bytes(),
            domain,
            path,
            secure,
            system_now(),
        ))
    }

    /// Removes every cookie from the jar (the `CURLOPT_COOKIELIST` `ALL`
    /// command), a faithful port of `Curl_cookie_clearall`.
    ///
    /// curl only zeroes `numcookies` here; it deliberately leaves
    /// `next_expiration` and the `lastct` creation-time counter untouched.
    /// This port does the same: emptying the [`Vec`] is the `numcookies = 0`
    /// equivalent, and a now-stale `next_expiration` is harmless on an empty
    /// jar (the next [`remove_expired`](CookieJar::remove_expired) sweep resets
    /// it), while preserving `lastct` keeps creation-time ordering monotonic
    /// exactly as curl does.
    pub fn clear_all(&mut self) {
        self.cookies.clear();
    }

    /// Removes all session cookies — those with no expiry (the
    /// `CURLOPT_COOKIELIST` `SESS` command), a faithful port of
    /// `Curl_cookie_clearsess`.
    ///
    /// Only cookies with `expires == 0` are dropped; persistent cookies keep
    /// their `creationtime`, and (as in curl) neither `next_expiration` nor
    /// `lastct` is disturbed.
    pub fn clear_session(&mut self) {
        self.cookies.retain(|co| co.expires != 0);
    }
}

/// Orders two cookies for the outgoing request, a faithful port of
/// `cookie_sort`.
///
/// The keys, all in descending order, are: path length, then domain length,
/// then name length, then `creationtime` (newest first). Because
/// `creationtime` is unique per cookie the ordering is total, so the resulting
/// `Cookie:` header is deterministic (longest path first).
fn cookie_sort_cmp(a: &Cookie, b: &Cookie) -> std::cmp::Ordering {
    let pa = a.path.as_deref().map_or(0, str::len);
    let pb = b.path.as_deref().map_or(0, str::len);
    if pa != pb {
        return pb.cmp(&pa);
    }
    let da = a.domain.as_deref().map_or(0, str::len);
    let db = b.domain.as_deref().map_or(0, str::len);
    if da != db {
        return db.cmp(&da);
    }
    if a.name.len() != b.name.len() {
        return b.name.len().cmp(&a.name.len());
    }
    b.creationtime.cmp(&a.creationtime)
}

// ---------------------------------------------------------------------------
// Cookie matching — a faithful port of `Curl_cookie_getlist` (`cookie.c`).
// ---------------------------------------------------------------------------

impl CookieJar {
    /// Returns the cookies to send for a request at a fixed `now`, a faithful
    /// port of `Curl_cookie_getlist`.
    ///
    /// `host` is the request host, `path` the request URI path, and `is_tls`
    /// whether the transport is secure. Expired cookies are swept first; then a
    /// cookie is included when it passes the secure filter (a `Secure` cookie
    /// requires a secure context — see [`secure_context`]), the domain filter
    /// (tail-match for a `tailmatch` cookie over a non-IP host, else an exact
    /// case-insensitive host match), and the path filter ([`pathmatch`]). At
    /// most [`MAX_COOKIE_SEND_AMOUNT`] cookies are returned, and the result is
    /// ordered by [`cookie_sort_cmp`] (longest path first) so the generated
    /// header is byte-identical to curl's.
    pub fn get_list_at(&mut self, host: &str, path: &str, is_tls: bool, now: i64) -> Vec<&Cookie> {
        self.remove_expired_at(now);

        let secure = secure_context(is_tls, host);
        let is_ip = is_ip_address(host);
        let host_bytes = host.as_bytes();

        let mut matches: Vec<&Cookie> = Vec::new();
        for co in &self.cookies {
            // Secure cookies are only sent over a secure context.
            if co.secure && !secure {
                continue;
            }

            // Domain check.
            let domain_ok = match co.domain.as_deref() {
                None => true,
                Some(cd) => {
                    if co.tailmatch && !is_ip && cookie_tailmatch(cd.as_bytes(), host_bytes) {
                        true
                    } else {
                        (!co.tailmatch || is_ip) && host.eq_ignore_ascii_case(cd)
                    }
                }
            };
            if !domain_ok {
                continue;
            }

            // Path check.
            let path_ok = match co.path.as_deref() {
                None => true,
                Some(cp) => pathmatch(cp, path),
            };
            if !path_ok {
                continue;
            }

            matches.push(co);
            if matches.len() >= MAX_COOKIE_SEND_AMOUNT {
                break;
            }
        }

        matches.sort_by(|a, b| cookie_sort_cmp(a, b));
        matches
    }

    /// Returns the cookies to send for a request using the current wall-clock
    /// time (see [`get_list_at`](CookieJar::get_list_at)).
    pub fn get_list(&mut self, host: &str, path: &str, is_tls: bool) -> Vec<&Cookie> {
        self.get_list_at(host, path, is_tls, system_now())
    }

    /// Builds the `Cookie:` request-header value for a request at a fixed `now`,
    /// or `None` when no cookie matches.
    ///
    /// The value is the matching cookies formatted as `name=value` pairs joined
    /// by `"; "`, in [`get_list_at`](CookieJar::get_list_at) order — byte-exactly
    /// what curl assembles (`"%s%s=%s"`, separator `"; "`). The `Cookie: ` field
    /// name itself is added by the HTTP layer.
    pub fn cookie_header_at(
        &mut self,
        host: &str,
        path: &str,
        is_tls: bool,
        now: i64,
    ) -> Option<String> {
        let list = self.get_list_at(host, path, is_tls, now);
        if list.is_empty() {
            return None;
        }
        let mut header = String::new();
        for (i, co) in list.iter().enumerate() {
            if i > 0 {
                header.push_str("; ");
            }
            header.push_str(&co.name);
            header.push('=');
            header.push_str(&co.value);
        }
        Some(header)
    }

    /// Builds the `Cookie:` request-header value using the current wall-clock
    /// time (see [`cookie_header_at`](CookieJar::cookie_header_at)).
    pub fn cookie_header(&mut self, host: &str, path: &str, is_tls: bool) -> Option<String> {
        self.cookie_header_at(host, path, is_tls, system_now())
    }
}

// ---------------------------------------------------------------------------
// Netscape cookie-jar output — a faithful port of `cookie_output`,
// `cookie_list`, and their sort/hash helpers (`cookie.c`).
// ---------------------------------------------------------------------------

/// Orders two cookies for the on-disk jar, a faithful port of `cookie_sort_ct`.
///
/// The sole key is `creationtime` in descending order (newest first). curl's
/// comparator returns `1` when `c2 > c1` and `-1` otherwise — it never reports
/// equality because `creationtime` is unique per cookie (assigned from the
/// monotonic `lastct` counter in [`CookieJar::add`]). This port expresses the
/// same total order via `b.cmp(&a)`; equal keys (which do not occur for
/// real cookies) fall back to the input order under a stable sort.
fn cookie_sort_ct_cmp(a: &Cookie, b: &Cookie) -> std::cmp::Ordering {
    b.creationtime.cmp(&a.creationtime)
}

/// Returns the top-level (last two labels) of `domain`, a faithful port of
/// `get_top_domain`.
///
/// curl locates the last `.` and then the `.` before it; the substring after
/// that earlier dot is the hashing key (e.g. `www.example.com` →
/// `example.com`). When the domain has fewer than two dots the whole string is
/// returned (e.g. `example.com` → `example.com`, `localhost` → `localhost`).
/// The result is returned as a byte slice, ready for [`cookie_hash_domain`].
fn get_top_domain(domain: &str) -> &[u8] {
    let bytes = domain.as_bytes();
    // `memrchr(domain, '.', len)` — the last dot in the whole string.
    if let Some(last) = bytes.iter().rposition(|&c| c == b'.') {
        // `memrchr(domain, '.', last - domain)` — the last dot strictly before
        // `last` (searching only the prefix `bytes[..last]`).
        if let Some(first) = bytes[..last].iter().rposition(|&c| c == b'.') {
            // curl advances past this dot (`++first`) and trims the leading
            // labels: `len -= (first - domain)`.
            return &bytes[first + 1..];
        }
    }
    bytes
}

/// Computes the case-insensitive bucket hash for a cookie domain, a faithful
/// port of `cookie_hash_domain`.
///
/// This is curl's DJB2-XOR variant seeded with `5381`: for each byte the state
/// is updated as `h += h << 5; h ^= toupper(byte)`, using wrapping arithmetic
/// on a `size_t` (modeled here as [`u64`]), and the final value is reduced
/// modulo [`COOKIE_HASH_SIZE`]. [`u8::to_ascii_uppercase`] reproduces
/// `Curl_raw_toupper` exactly (only `a`–`z` are folded; every other byte,
/// including non-ASCII, is left unchanged).
fn cookie_hash_domain(domain: &[u8]) -> usize {
    let mut h: u64 = 5381;
    for &c in domain {
        let j = u64::from(c.to_ascii_uppercase());
        // `h += h << 5` — the shift can drop high bits and the add can wrap;
        // both are the defined `size_t` behavior curl relies on.
        h = h.wrapping_add(h << 5);
        h ^= j;
    }
    (h % COOKIE_HASH_SIZE as u64) as usize
}

/// Hashes a cookie domain into its bucket index, a faithful port of
/// `cookiehash`.
///
/// A missing domain or a numeric-IP domain always maps to bucket `0` (curl's
/// `!domain || Curl_host_is_ipnum(domain)` guard, using [`is_ip_address`] as
/// the `Curl_host_is_ipnum` equivalent). Otherwise the top domain
/// ([`get_top_domain`]) is hashed by [`cookie_hash_domain`]. The bucket index
/// itself is never stored; it exists purely to reproduce the traversal order
/// of [`CookieJar::list`].
fn cookiehash(domain: Option<&str>) -> usize {
    match domain {
        Some(d) if !is_ip_address(d) => cookie_hash_domain(get_top_domain(d)),
        _ => 0,
    }
}

impl CookieJar {
    /// Serializes the jar to the Netscape cookie-file format into `out` at a
    /// fixed `now`, the writer core shared by [`save`](CookieJar::save).
    ///
    /// Expired cookies are swept first (`remove_expired`), then the standard
    /// header block ([`NETSCAPE_HEADER`], written even for an empty jar) is
    /// emitted, followed by one [`Cookie::to_netscape_line`] per cookie that
    /// owns a domain (domain-less cookies are skipped, exactly as
    /// `get_netscape_format` returns nothing for them). Cookies are ordered by
    /// [`cookie_sort_ct_cmp`] (newest `creationtime` first), matching curl's
    /// `qsort(..., cookie_sort_ct)`.
    fn write_to_at<W: Write>(&mut self, out: &mut W, now: i64) -> Result<()> {
        self.remove_expired_at(now);

        out.write_all(NETSCAPE_HEADER.as_bytes())?;

        // Collect only the cookies that carry a domain, then order them by
        // creation time (newest first) just as `cookie_output` does.
        let mut refs: Vec<&Cookie> = self.cookies.iter().filter(|c| c.domain.is_some()).collect();
        refs.sort_by(|a, b| cookie_sort_ct_cmp(a, b));

        for co in refs {
            out.write_all(co.to_netscape_line().as_bytes())?;
            out.write_all(b"\n")?;
        }
        Ok(())
    }

    /// Serializes the jar to the Netscape cookie-file format into `out` using
    /// the current wall-clock time.
    ///
    /// This is the streaming entry point for callers that already hold a
    /// writer (for example an in-memory buffer or a socket); persisting to the
    /// configured jar file is [`save`](CookieJar::save). Any I/O failure is
    /// surfaced as [`Error::Io`].
    pub fn write_to<W: Write>(&mut self, out: &mut W) -> Result<()> {
        self.write_to_at(out, system_now())
    }

    /// Persists the jar to a file at a fixed `now`, the deterministic core of
    /// [`save`](CookieJar::save).
    fn save_at(&mut self, filename: Option<&str>, now: i64) -> Result<()> {
        // Resolve the target: an explicit argument wins, else the stored jar
        // file name (`CURLOPT_COOKIEJAR`).
        let target = match filename.or(self.filename.as_deref()) {
            Some(t) if !t.is_empty() => t.to_string(),
            _ => return Ok(()), // no jar file configured: nothing to write
        };

        // "-" writes the jar to standard output, exactly like curl.
        if target == "-" {
            let stdout = io::stdout();
            let mut lock = stdout.lock();
            return self.write_to_at(&mut lock, now);
        }

        // Atomic replace: serialize into a buffer, write it to a uniquely
        // named sibling file, then rename over the target. A rename failure
        // maps to curl's `CURLE_WRITE_ERROR` ([`Error::Write`]), mirroring the
        // `curlx_rename` path in `cookie_output`.
        let mut buf: Vec<u8> = Vec::new();
        self.write_to_at(&mut buf, now)?;

        let tmp = format!("{target}.tmp.{}", std::process::id());
        fs::write(&tmp, &buf)?;
        if fs::rename(&tmp, &target).is_err() {
            let _ = fs::remove_file(&tmp);
            return Err(Error::Write);
        }
        Ok(())
    }

    /// Persists the jar to the Netscape cookie file, a faithful port of
    /// `cookie_output` / `Curl_cookie_output`.
    ///
    /// The target is resolved from the explicit `filename` argument when given,
    /// otherwise from the jar file configured via
    /// [`set_jar_file`](CookieJar::set_jar_file) (curl's `CURLOPT_COOKIEJAR`).
    /// When neither yields a non-empty name the call is a no-op returning
    /// `Ok(())`. A `filename` of `"-"` writes to standard output; any other
    /// name is written atomically (write-to-temp then rename). Expired cookies
    /// are removed before writing, the header block is always emitted, and
    /// cookies are ordered newest-first by creation time — the output is
    /// byte-identical to curl's, including the `#HttpOnly_` prefix and the
    /// seven TAB-separated fields.
    ///
    /// # Errors
    ///
    /// * [`Error::Io`] if writing the temporary file (or standard output)
    ///   fails.
    /// * [`Error::Write`] if the atomic rename over the target fails
    ///   (`CURLE_WRITE_ERROR`).
    pub fn save(&mut self, filename: Option<&str>) -> Result<()> {
        self.save_at(filename, system_now())
    }

    /// Returns the jar contents as Netscape-format lines at a fixed `now`, the
    /// deterministic core of [`list`](CookieJar::list).
    fn list_at(&mut self, now: i64) -> Vec<String> {
        // curl's `cookie_list` short-circuits to an empty result before doing
        // any expiry sweep when the jar holds no cookies.
        if self.cookies.is_empty() {
            return Vec::new();
        }
        self.remove_expired_at(now);

        // Collect the domain-bearing cookies, then reproduce curl's
        // bucket-by-bucket traversal. A *stable* sort by bucket index keeps the
        // relative (insertion) order of cookies that share a bucket — which is
        // exactly how curl's per-bucket linked list preserves them (a replaced
        // cookie is unlinked and re-appended at the tail in both models).
        let mut refs: Vec<&Cookie> = self.cookies.iter().filter(|c| c.domain.is_some()).collect();
        refs.sort_by_key(|co| cookiehash(co.domain.as_deref()));
        refs.iter().map(|co| co.to_netscape_line()).collect()
    }

    /// Returns the current jar contents as Netscape-format lines, a faithful
    /// port of `Curl_cookie_list` (the `CURLINFO_COOKIELIST` accessor).
    ///
    /// Each entry is formatted by [`Cookie::to_netscape_line`] (the same
    /// seven-field representation the jar file uses, including the `#HttpOnly_`
    /// prefix); domain-less cookies are omitted. Unlike [`save`](CookieJar::save)
    /// no header block is produced, and the ordering follows curl's hash-bucket
    /// traversal rather than creation time. Expired cookies are swept first, and
    /// an empty jar yields an empty vector.
    pub fn list(&mut self) -> Vec<String> {
        self.list_at(system_now())
    }
}

// ---------------------------------------------------------------------------
// Cookie-file loading and the `CURLOPT_COOKIELIST` command dispatcher — a
// faithful port of `cookie_load`, `Curl_cookie_loadfiles`, and the setopt
// `cookielist` handler (`cookie.c` / `setopt.c`).
// ---------------------------------------------------------------------------

/// The literal HTTP header prefix curl recognizes on a jar/list line
/// (`checkprefix("Set-Cookie:", ...)`).
const SET_COOKIE_PREFIX: &[u8] = b"Set-Cookie:";

/// Strips a leading `Set-Cookie:` prefix (matched case-insensitively, like
/// curl's `checkprefix`) and any blanks that follow it (`curlx_str_passblanks`,
/// i.e. spaces and tabs), returning the remaining header value.
///
/// Returns `None` when `line` is not a `Set-Cookie:` header line, in which case
/// the caller treats it as a Netscape jar line.
fn strip_set_cookie_prefix(line: &[u8]) -> Option<&[u8]> {
    if line.len() < SET_COOKIE_PREFIX.len()
        || !line[..SET_COOKIE_PREFIX.len()].eq_ignore_ascii_case(SET_COOKIE_PREFIX)
    {
        return None;
    }
    let mut rest = &line[SET_COOKIE_PREFIX.len()..];
    while let Some(&b) = rest.first() {
        if b == b' ' || b == b'\t' {
            rest = &rest[1..];
        } else {
            break;
        }
    }
    Some(rest)
}

impl CookieJar {
    /// Ingests one raw jar/header line during a bulk load, a faithful port of
    /// the per-line body of `cookie_load`.
    ///
    /// A `Set-Cookie:` prefix (case-insensitive) selects the header tokenizer;
    /// otherwise the line is parsed as a Netscape jar line. curl always loads
    /// with `no_expire = TRUE` (the expiry sweep is deferred to the end of the
    /// file) and `secure = TRUE`, with no default domain/path — this reproduces
    /// `Curl_cookie_add(data, ci, headerline, TRUE, lineptr, NULL, NULL, TRUE)`.
    fn load_line(&mut self, raw: &[u8], now: i64) {
        let (http_header, line) = match strip_set_cookie_prefix(raw) {
            Some(rest) => (true, rest),
            None => (false, raw),
        };
        // Individual parse/add failures are intentionally ignored, exactly as
        // curl discards them ("File reading cookie failures are not propagated
        // back to the caller").
        self.add_at(http_header, true, line, None, None, true, now);
    }

    /// Reads and ingests every line from `reader`, a faithful port of
    /// `cookie_load`'s read loop over `Curl_get_line`.
    ///
    /// Lines are delimited by `\n` (a trailing `\r`/`\n` is tolerated by the
    /// parsers). A line longer than [`MAX_COOKIE_LINE`] halts the load — and is
    /// itself skipped — mirroring `Curl_get_line` returning an error that
    /// terminates curl's loop (the remainder of the source is left unread). The
    /// read is bounded per line so a newline-free source cannot exhaust memory.
    fn read_lines<R: BufRead>(&mut self, reader: &mut R, now: i64) -> Result<()> {
        let mut raw: Vec<u8> = Vec::new();
        loop {
            raw.clear();
            let read = reader
                .by_ref()
                .take(MAX_COOKIE_LINE as u64 + 1)
                .read_until(b'\n', &mut raw)?;
            if read == 0 {
                break; // EOF
            }
            if raw.len() > MAX_COOKIE_LINE {
                // Over-long line: stop reading, exactly as curl abandons the
                // rest of the file. The offending line is not added.
                break;
            }
            self.load_line(&raw, now);
        }
        Ok(())
    }

    /// Loads cookies from a single file at a fixed `now`, the deterministic
    /// core of [`load`](CookieJar::load).
    fn load_at(&mut self, file: &str, now: i64) -> Result<()> {
        // curl sets `running = FALSE` for the duration of the read (init, not
        // live traffic) and unconditionally restores `running = TRUE`
        // afterwards — even when the file cannot be opened.
        self.running = false;
        let result = self.load_source(file, now);
        self.running = true;
        result
    }

    /// Opens `file` and reads it, running the post-read expiry sweep, the inner
    /// body of [`load_at`](CookieJar::load_at).
    fn load_source(&mut self, file: &str, now: i64) -> Result<()> {
        if file.is_empty() {
            // curl guards the read with `if(file && *file)`: an empty name
            // reads nothing (but `running` is still toggled by the caller).
            return Ok(());
        }
        if file == "-" {
            // Read standard input.
            let stdin = io::stdin();
            let mut reader = stdin.lock();
            self.read_lines(&mut reader, now)?;
            self.remove_expired_at(now);
            return Ok(());
        }
        match fs::File::open(file) {
            Ok(f) => {
                let mut reader = io::BufReader::new(f);
                self.read_lines(&mut reader, now)?;
                // Sweep expired cookies once, after the whole file is read
                // (loading used `no_expire = TRUE` per line).
                self.remove_expired_at(now);
                Ok(())
            }
            // A missing or unreadable file is only a warning in curl, never an
            // error; the cookie engine still comes up running.
            Err(_) => Ok(()),
        }
    }

    /// Loads cookies from `file`, a faithful port of `cookie_load`.
    ///
    /// `file` is a jar/header file (mixed `Set-Cookie:` and Netscape lines are
    /// both accepted); the special name `"-"` reads standard input. During the
    /// read the jar is marked not-running so that session-cookie and bare-
    /// `secure` rules apply as curl's init path expects, and the current
    /// [`set_newsession`](CookieJar::set_newsession) flag governs whether
    /// session cookies are discarded. Expired cookies are swept once at the
    /// end, and the jar is left running.
    ///
    /// # Errors
    ///
    /// A file that cannot be opened is **not** an error (curl only logs a
    /// warning). [`Error::Io`] is returned only for a read failure on an opened
    /// source.
    pub fn load(&mut self, file: &str) -> Result<()> {
        self.load_at(file, system_now())
    }

    /// Loads cookies from an in-memory jar/header document at a fixed `now`,
    /// the deterministic core of [`load_str`](CookieJar::load_str).
    fn load_str_at(&mut self, contents: &str, now: i64) -> Result<()> {
        self.running = false;
        let mut reader = io::Cursor::new(contents.as_bytes());
        let result = self.read_lines(&mut reader, now);
        // The in-memory source is always "present", so the post-read sweep runs
        // (curl performs it inside the `if(fp)` block).
        if result.is_ok() {
            self.remove_expired_at(now);
        }
        self.running = true;
        result
    }

    /// Loads cookies from an in-memory jar/header document, the string
    /// counterpart of [`load`](CookieJar::load).
    ///
    /// This applies the exact `cookie_load` semantics to `contents` without any
    /// file I/O: each line is a `Set-Cookie:` header line or a Netscape jar
    /// line, the jar is not-running during the parse, and expired cookies are
    /// swept once afterwards. It underpins the `RELOAD`-style refresh in tests
    /// and any caller holding jar text directly.
    ///
    /// # Errors
    ///
    /// This never fails for in-memory input; the [`Result`] shape mirrors
    /// [`load`](CookieJar::load) for a uniform API.
    pub fn load_str(&mut self, contents: &str) -> Result<()> {
        self.load_str_at(contents, system_now())
    }

    /// Loads every queued cookie file (`CURLOPT_COOKIEFILE`), a faithful port
    /// of `Curl_cookie_loadfiles`.
    ///
    /// Each file registered with [`add_file`](CookieJar::add_file) is read in
    /// order via [`load`](CookieJar::load); reading stops at the first hard
    /// error. Because an unopenable file is not an error, missing files are
    /// silently skipped just as in curl.
    ///
    /// # Errors
    ///
    /// Propagates the first [`Error::Io`] from an opened-but-unreadable file.
    pub fn load_files(&mut self) -> Result<()> {
        // Clone the queue so the mutable per-file load does not alias the field.
        let files = self.files.clone();
        for file in &files {
            self.load(file)?;
        }
        Ok(())
    }

    /// Executes a `CURLOPT_COOKIELIST` command at a fixed `now`, the
    /// deterministic core of [`command`](CookieJar::command).
    fn command_at(&mut self, cmd: &str, now: i64) -> Result<()> {
        // The four verbs are matched case-insensitively (curl uses
        // `curl_strequal`).
        if cmd.eq_ignore_ascii_case("ALL") {
            self.clear_all();
        } else if cmd.eq_ignore_ascii_case("SESS") {
            self.clear_session();
        } else if cmd.eq_ignore_ascii_case("FLUSH") {
            // Flush the jar to the configured jar file.
            self.save_at(None, now)?;
        } else if cmd.eq_ignore_ascii_case("RELOAD") {
            // Reload from the configured cookie files.
            self.load_files()?;
        } else {
            // Any other string is an inline cookie line to add. curl guards it
            // against absurd lengths with `CURL_MAX_INPUT_LENGTH`.
            if cmd.len() > CURL_MAX_INPUT_LENGTH {
                return Err(Error::bad_argument(
                    "cookie list command exceeds CURL_MAX_INPUT_LENGTH",
                ));
            }
            let raw = cmd.as_bytes();
            let (http_header, line) = match strip_set_cookie_prefix(raw) {
                Some(rest) => (true, rest),
                None => (false, raw),
            };
            // Inline adds use `no_expire = FALSE` and `secure = TRUE`
            // (setopt.c), with no default domain/path.
            self.add_at(http_header, false, line, None, None, true, now);
        }
        Ok(())
    }

    /// Executes a `CURLOPT_COOKIELIST` command, a faithful port of the setopt
    /// `cookielist` handler.
    ///
    /// The recognized verbs (case-insensitive) are:
    ///
    /// * `ALL` — clear every cookie ([`clear_all`](CookieJar::clear_all)).
    /// * `SESS` — clear session cookies ([`clear_session`](CookieJar::clear_session)).
    /// * `FLUSH` — write the jar to the configured file ([`save`](CookieJar::save)).
    /// * `RELOAD` — reload the queued cookie files ([`load_files`](CookieJar::load_files)).
    ///
    /// Any other value is treated as an inline cookie line to ingest (a
    /// `Set-Cookie:` header line or a Netscape line), exactly as
    /// `CURLOPT_COOKIELIST` does for non-command strings.
    ///
    /// # Errors
    ///
    /// * [`Error::BadFunctionArgument`] if a non-command line exceeds
    ///   `CURL_MAX_INPUT_LENGTH` (8 000 000 bytes).
    /// * Any error surfaced by `FLUSH` ([`save`](CookieJar::save)) or `RELOAD`
    ///   ([`load_files`](CookieJar::load_files)).
    pub fn command(&mut self, cmd: &str) -> Result<()> {
        self.command_at(cmd, system_now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed wall clock for deterministic expiry arithmetic (2001-09-09).
    const NOW: i64 = 1_000_000_000;
    /// An expiry safely inside `COOKIES_MAXAGE` of [`NOW`] (never capped/swept).
    const SOON: i64 = NOW + 10_000;

    /// A minimal Public Suffix List covering the labels the tests exercise. The
    /// ICANN section markers make the labels canonical public suffixes.
    fn test_psl() -> Psl {
        let list = concat!(
            "// ===BEGIN ICANN DOMAINS===\n",
            "com\n",
            "net\n",
            "org\n",
            "uk\n",
            "co.uk\n",
            "// ===END ICANN DOMAINS===\n",
        );
        list.parse::<Psl>().expect("test PSL should parse")
    }

    /// Adds a `Set-Cookie` header line at the fixed [`NOW`] clock.
    fn add_header(
        jar: &mut CookieJar,
        line: &str,
        host: Option<&str>,
        path: Option<&str>,
        secure: bool,
    ) -> bool {
        jar.add_at(true, false, line.as_bytes(), host, path, secure, NOW)
    }

    /// Adds a Netscape jar line (bulk-load semantics: `no_expire`, `secure`).
    fn add_netscape(jar: &mut CookieJar, line: &str) -> bool {
        jar.add_at(false, true, line.as_bytes(), None, None, true, NOW)
    }

    // -----------------------------------------------------------------------
    // Type-level guarantees
    // -----------------------------------------------------------------------

    #[test]
    fn jar_is_send_sync() {
        // The `Arc<Mutex<CookieJar>>` share model requires Send + Sync.
        fn assert_traits<T: Send + Sync>() {}
        assert_traits::<CookieJar>();
        assert_traits::<SharedCookieJar>();
    }

    #[test]
    fn new_jar_is_empty_and_running() {
        let jar = CookieJar::new();
        assert!(jar.is_empty());
        assert_eq!(jar.len(), 0);
        assert!(jar.is_running());
    }

    // -----------------------------------------------------------------------
    // Date parsing (getdate_capped / parsedate)
    // -----------------------------------------------------------------------

    #[test]
    fn getdate_parses_rfc1123() {
        assert_eq!(
            getdate_capped("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
    }

    #[test]
    fn getdate_parses_asctime() {
        assert_eq!(
            getdate_capped("Sun Nov  6 08:49:37 1994"),
            Some(784_111_777)
        );
    }

    #[test]
    fn getdate_parses_future_date() {
        assert_eq!(
            getdate_capped("Wed, 18 Jan 2023 12:00:00 GMT"),
            Some(1_674_043_200)
        );
    }

    #[test]
    fn getdate_rejects_garbage() {
        assert_eq!(getdate_capped("not a date at all"), None);
        assert_eq!(getdate_capped(""), None);
    }

    // -----------------------------------------------------------------------
    // Set-Cookie parsing edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn parse_basic_name_value() {
        let mut jar = CookieJar::new();
        assert!(add_header(
            &mut jar,
            "foo=bar",
            Some("example.com"),
            Some("/"),
            false
        ));
        assert_eq!(jar.len(), 1);
        let c = &jar.cookies()[0];
        assert_eq!(c.name, "foo");
        assert_eq!(c.value, "bar");
        // No explicit Domain: host-only (tailmatch == false), host as domain.
        assert_eq!(c.domain.as_deref(), Some("example.com"));
        assert!(!c.tailmatch);
    }

    #[test]
    fn parse_full_attribute_set() {
        let mut jar = CookieJar::new();
        let line = "sess=xyz; Domain=example.com; Path=/app; Secure; HttpOnly; \
                    Expires=Wed, 18 Jan 2023 12:00:00 GMT";
        // Host tail-matches the given Domain, so it is accepted.
        assert!(add_header(
            &mut jar,
            line,
            Some("www.example.com"),
            Some("/"),
            true
        ));
        let c = &jar.cookies()[0];
        assert_eq!(c.name, "sess");
        assert_eq!(c.value, "xyz");
        assert_eq!(c.domain.as_deref(), Some("example.com"));
        assert_eq!(c.path.as_deref(), Some("/app"));
        assert!(c.secure);
        assert!(c.httponly);
        // An explicit Domain always tail-matches.
        assert!(c.tailmatch);
        // The Expires date (Jan 2023) is ~22 years beyond NOW (2001), so curl's
        // RFC 6265bis 400-day cap applies: expires = ((now + COOKIES_MAXAGE + 30)
        // / 60) * 60, aligned to a 60-second boundary (cap_expires).
        let capped = ((NOW + COOKIES_MAXAGE + 30) / 60) * 60;
        assert_eq!(c.expires, capped);
        assert_eq!(c.expires, 1_034_560_020);
    }

    #[test]
    fn parse_rejects_tab_in_value() {
        let mut jar = CookieJar::new();
        // A TAB inside the value is rejected (cookie.c ~495 memchr '\t').
        let ok = add_header(
            &mut jar,
            "foo=bar\tbaz",
            Some("example.com"),
            Some("/"),
            false,
        );
        assert!(!ok);
        assert!(jar.is_empty());
    }

    #[test]
    fn parse_rejects_oversized_name() {
        let mut jar = CookieJar::new();
        let huge = "n".repeat(MAX_NAME);
        let line = format!("{huge}=v");
        assert!(!add_header(
            &mut jar,
            &line,
            Some("example.com"),
            Some("/"),
            false
        ));
        assert!(jar.is_empty());
    }

    #[test]
    fn parse_max_age_sets_relative_expiry() {
        let mut jar = CookieJar::new();
        assert!(add_header(
            &mut jar,
            "a=b; Max-Age=1000",
            Some("example.com"),
            Some("/"),
            false,
        ));
        assert_eq!(jar.cookies()[0].expires, NOW + 1000);
    }

    #[test]
    fn parse_max_age_zero_expires_immediately() {
        let mut jar = CookieJar::new();
        // Max-Age=0 → expire "now" (curl stores expires = 1).
        assert!(add_header(
            &mut jar,
            "a=b; Max-Age=0",
            Some("example.com"),
            Some("/"),
            false,
        ));
        assert_eq!(jar.cookies()[0].expires, 1);
    }

    #[test]
    fn parse_unknown_attribute_is_ignored() {
        let mut jar = CookieJar::new();
        // SameSite is not a curl attribute; the tokenizer skips it gracefully.
        assert!(add_header(
            &mut jar,
            "a=b; SameSite=Lax; Path=/x",
            Some("example.com"),
            Some("/"),
            false,
        ));
        let c = &jar.cookies()[0];
        assert_eq!(c.value, "b");
        assert_eq!(c.path.as_deref(), Some("/x"));
    }

    #[test]
    fn parse_leading_dot_domain_is_stripped() {
        let mut jar = CookieJar::new();
        assert!(add_header(
            &mut jar,
            "a=b; Domain=.example.com",
            Some("www.example.com"),
            Some("/"),
            false,
        ));
        let c = &jar.cookies()[0];
        // The leading dot is stripped but the cookie remains a tail-match.
        assert_eq!(c.domain.as_deref(), Some("example.com"));
        assert!(c.tailmatch);
    }

    // -----------------------------------------------------------------------
    // __Secure- / __Host- prefix rules
    // -----------------------------------------------------------------------

    #[test]
    fn secure_prefix_accepted_when_secure() {
        let mut jar = CookieJar::new();
        assert!(add_header(
            &mut jar,
            "__Secure-a=1; Secure",
            Some("example.com"),
            Some("/"),
            true,
        ));
        let c = &jar.cookies()[0];
        assert!(c.prefix_secure);
        assert!(c.secure);
    }

    #[test]
    fn secure_prefix_rejected_without_secure() {
        let mut jar = CookieJar::new();
        // __Secure- requires the Secure attribute; without it the cookie drops.
        assert!(!add_header(
            &mut jar,
            "__Secure-a=1",
            Some("example.com"),
            Some("/"),
            true,
        ));
        assert!(jar.is_empty());
    }

    #[test]
    fn host_prefix_accepted_with_secure_root_and_no_domain() {
        let mut jar = CookieJar::new();
        // No Domain → host-only (tailmatch == false), Path=/ and Secure present.
        assert!(add_header(
            &mut jar,
            "__Host-a=1; Secure; Path=/",
            Some("example.com"),
            Some("/"),
            true,
        ));
        let c = &jar.cookies()[0];
        assert!(c.prefix_host);
        assert!(c.secure);
        assert_eq!(c.path.as_deref(), Some("/"));
        assert!(!c.tailmatch);
    }

    #[test]
    fn host_prefix_rejected_with_domain() {
        let mut jar = CookieJar::new();
        // An explicit Domain sets tailmatch, which the __Host- rule forbids.
        assert!(!add_header(
            &mut jar,
            "__Host-a=1; Secure; Path=/; Domain=example.com",
            Some("www.example.com"),
            Some("/"),
            true,
        ));
        assert!(jar.is_empty());
    }

    #[test]
    fn host_prefix_rejected_with_non_root_path() {
        let mut jar = CookieJar::new();
        assert!(!add_header(
            &mut jar,
            "__Host-a=1; Secure; Path=/app",
            Some("example.com"),
            Some("/"),
            true,
        ));
        assert!(jar.is_empty());
    }

    #[test]
    fn host_prefix_rejected_without_secure() {
        let mut jar = CookieJar::new();
        assert!(!add_header(
            &mut jar,
            "__Host-a=1; Path=/",
            Some("example.com"),
            Some("/"),
            true,
        ));
        assert!(jar.is_empty());
    }

    // -----------------------------------------------------------------------
    // Public-suffix "supercookie" rejection
    // -----------------------------------------------------------------------

    #[test]
    fn psl_rejects_public_suffix_domain() {
        let mut jar = CookieJar::with_psl(test_psl());
        // Domain=com is a public suffix → rejected by the PSL defense.
        assert!(!add_header(
            &mut jar,
            "x=1; Domain=com",
            Some("www.example.com"),
            Some("/"),
            false,
        ));
        assert!(jar.is_empty());
    }

    #[test]
    fn psl_accepts_registrable_domain() {
        let mut jar = CookieJar::with_psl(test_psl());
        // Domain=example.com is registrable (eTLD+1) → accepted.
        assert!(add_header(
            &mut jar,
            "y=2; Domain=example.com",
            Some("www.example.com"),
            Some("/"),
            false,
        ));
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.cookies()[0].domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn default_jar_rejects_public_suffix_supercookie() {
        // F5-PSL-001: a jar built with `new()` (the default) now carries the
        // bundled Public Suffix List, so a cookie scoped to a public suffix — a
        // "supercookie" — is rejected out of the box, matching curl built with
        // libpsl. Before the fix, `new()` carried no PSL and such cookies were
        // wrongly accepted via the weaker bad_domain heuristic.
        let mut jar = CookieJar::new();
        // Multi-label public suffix (`co.uk`).
        assert!(!add_header(
            &mut jar,
            "evil=1; Domain=co.uk",
            Some("www.bbc.co.uk"),
            Some("/"),
            false,
        ));
        // Single-label public suffix (`com`).
        assert!(!add_header(
            &mut jar,
            "evil2=1; Domain=com",
            Some("www.example.com"),
            Some("/"),
            false,
        ));
        assert!(
            jar.is_empty(),
            "supercookies must not enter the default jar"
        );
        // A registrable domain (eTLD+1) is still accepted by the same jar.
        assert!(add_header(
            &mut jar,
            "ok=1; Domain=bbc.co.uk",
            Some("www.bbc.co.uk"),
            Some("/"),
            false,
        ));
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.cookies()[0].domain.as_deref(), Some("bbc.co.uk"));
    }

    #[test]
    fn no_psl_rejects_single_label_domain() {
        // Exercise the no-libpsl fallback explicitly. A jar from `new()` now
        // carries the bundled PSL (which would reject `com` via the public-
        // suffix check); an empty PSL forces curl's bad_domain heuristic path,
        // which is what this test is meant to cover.
        let mut jar = CookieJar::with_psl(Psl::empty());
        // Without a PSL, curl's bad_domain fallback poisons a single-label
        // Domain so it cannot be accepted (the `domain = ":"` trick).
        assert!(!add_header(
            &mut jar,
            "x=1; Domain=com",
            Some("www.example.com"),
            Some("/"),
            false,
        ));
        assert!(jar.is_empty());
    }

    // -----------------------------------------------------------------------
    // Request matching: secure, domain tail-match, path prefix, expiry
    // -----------------------------------------------------------------------

    #[test]
    fn secure_cookie_only_sent_over_secure_context() {
        let mut jar = CookieJar::new();
        // Adding over a secure transport so the Secure attribute is honored.
        assert!(add_header(
            &mut jar,
            "s=1; Secure; Path=/; Max-Age=10000",
            Some("example.com"),
            Some("/"),
            true,
        ));
        // Plain HTTP: the secure cookie is withheld.
        assert!(jar.get_list_at("example.com", "/", false, NOW).is_empty());
        // HTTPS: the secure cookie is sent.
        let over_tls = jar.get_list_at("example.com", "/", true, NOW);
        assert_eq!(over_tls.len(), 1);
        assert_eq!(over_tls[0].name, "s");
    }

    #[test]
    fn host_only_cookie_matches_exact_host_only() {
        let mut jar = CookieJar::new();
        // No Domain attribute → host-only cookie (tailmatch == false).
        assert!(add_header(
            &mut jar,
            "h=1; Path=/; Max-Age=10000",
            Some("example.com"),
            Some("/"),
            false,
        ));
        assert_eq!(jar.get_list_at("example.com", "/", false, NOW).len(), 1);
        // A subdomain must NOT receive a host-only cookie.
        assert!(jar
            .get_list_at("www.example.com", "/", false, NOW)
            .is_empty());
    }

    #[test]
    fn tailmatch_cookie_matches_subdomains() {
        let mut jar = CookieJar::new();
        assert!(add_header(
            &mut jar,
            "t=1; Domain=example.com; Path=/; Max-Age=10000",
            Some("www.example.com"),
            Some("/"),
            false,
        ));
        // Both the apex and any subdomain match a tail-match cookie.
        assert_eq!(jar.get_list_at("example.com", "/", false, NOW).len(), 1);
        assert_eq!(
            jar.get_list_at("deep.www.example.com", "/", false, NOW)
                .len(),
            1
        );
        // A sibling domain does not.
        assert!(jar
            .get_list_at("notexample.com", "/", false, NOW)
            .is_empty());
    }

    #[test]
    fn path_prefix_matching() {
        let mut jar = CookieJar::new();
        assert!(add_header(
            &mut jar,
            "p=1; Path=/app; Max-Age=10000",
            Some("example.com"),
            Some("/"),
            false,
        ));
        // A request under the cookie path matches.
        assert_eq!(
            jar.get_list_at("example.com", "/app/page", false, NOW)
                .len(),
            1
        );
        // A sibling path does not.
        assert!(jar
            .get_list_at("example.com", "/other", false, NOW)
            .is_empty());
    }

    #[test]
    fn expired_cookie_is_not_sent() {
        let mut jar = CookieJar::new();
        // Max-Age=1 expires one second after NOW.
        assert!(add_header(
            &mut jar,
            "e=1; Path=/; Max-Age=1",
            Some("example.com"),
            Some("/"),
            false,
        ));
        // Ten seconds later the cookie is expired and swept.
        assert!(jar
            .get_list_at("example.com", "/", false, NOW + 10)
            .is_empty());
    }

    #[test]
    fn cookie_header_orders_longer_path_first() {
        let mut jar = CookieJar::new();
        assert!(add_header(
            &mut jar,
            "wide=1; Path=/; Max-Age=10000",
            Some("example.com"),
            Some("/"),
            false,
        ));
        assert!(add_header(
            &mut jar,
            "narrow=2; Path=/app; Max-Age=10000",
            Some("example.com"),
            Some("/"),
            false,
        ));
        // Both match /app/page; the longer path must be emitted first, joined
        // by "; " exactly as curl assembles the Cookie header.
        let header = jar
            .cookie_header_at("example.com", "/app/page", false, NOW)
            .expect("both cookies match");
        assert_eq!(header, "narrow=2; wide=1");
    }

    #[test]
    fn cookie_header_none_when_no_match() {
        let mut jar = CookieJar::new();
        assert!(add_header(
            &mut jar,
            "a=b; Path=/; Max-Age=10000",
            Some("example.com"),
            Some("/"),
            false,
        ));
        assert!(jar.cookie_header_at("other.com", "/", false, NOW).is_none());
    }

    // -----------------------------------------------------------------------
    // Netscape jar output — byte-exact format & the #HttpOnly_ prefix
    // -----------------------------------------------------------------------

    #[test]
    fn to_netscape_line_tailmatch_gets_leading_dot() {
        let c = Cookie {
            name: "foo".into(),
            value: "bar".into(),
            domain: Some("example.com".into()),
            path: Some("/".into()),
            expires: 1_674_043_200,
            tailmatch: true,
            ..Default::default()
        };
        // Mozilla-style leading dot is added for tail-match domains.
        assert_eq!(
            c.to_netscape_line(),
            ".example.com\tTRUE\t/\tFALSE\t1674043200\tfoo\tbar"
        );
    }

    #[test]
    fn to_netscape_line_host_only_no_dot() {
        let c = Cookie {
            name: "foo".into(),
            value: "bar".into(),
            domain: Some("example.com".into()),
            path: Some("/".into()),
            expires: 1_674_043_200,
            tailmatch: false,
            ..Default::default()
        };
        assert_eq!(
            c.to_netscape_line(),
            "example.com\tFALSE\t/\tFALSE\t1674043200\tfoo\tbar"
        );
    }

    #[test]
    fn to_netscape_line_httponly_prefix() {
        let c = Cookie {
            name: "sid".into(),
            value: "42".into(),
            domain: Some("example.com".into()),
            path: Some("/".into()),
            expires: 1_674_043_200,
            secure: true,
            httponly: true,
            tailmatch: false,
            ..Default::default()
        };
        // The #HttpOnly_ literal sits immediately before the domain, no space.
        assert_eq!(
            c.to_netscape_line(),
            "#HttpOnly_example.com\tFALSE\t/\tTRUE\t1674043200\tsid\t42"
        );
    }

    #[test]
    fn write_to_emits_header_and_creationtime_order() {
        let mut jar = CookieJar::new();
        // Added A (creationtime 1) then B (creationtime 2); output is newest
        // first (B, then A), preceded by the standard header block.
        assert!(add_netscape(
            &mut jar,
            "example.com\tFALSE\t/\tFALSE\t2000000000\tA\t1"
        ));
        assert!(add_netscape(
            &mut jar,
            ".sub.example.com\tTRUE\t/x\tTRUE\t2000000001\tB\t2"
        ));
        let mut buf: Vec<u8> = Vec::new();
        jar.write_to_at(&mut buf, NOW).expect("write");
        let text = String::from_utf8(buf).expect("utf8");
        let expected = concat!(
            "# Netscape HTTP Cookie File\n",
            "# https://curl.se/docs/http-cookies.html\n",
            "# This file was generated by libcurl! Edit at your own risk.\n",
            "\n",
            ".sub.example.com\tTRUE\t/x\tTRUE\t2000000001\tB\t2\n",
            "example.com\tFALSE\t/\tFALSE\t2000000000\tA\t1\n",
        );
        assert_eq!(text, expected);
    }

    #[test]
    fn write_to_empty_jar_emits_header_only() {
        let mut jar = CookieJar::new();
        let mut buf: Vec<u8> = Vec::new();
        jar.write_to_at(&mut buf, NOW).expect("write");
        assert_eq!(String::from_utf8(buf).unwrap(), NETSCAPE_HEADER);
    }

    #[test]
    fn jar_round_trips_through_netscape() {
        let mut jar1 = CookieJar::new();
        assert!(add_netscape(
            &mut jar1,
            "example.com\tFALSE\t/\tFALSE\t2000000000\tA\t1"
        ));
        assert!(add_netscape(
            &mut jar1,
            ".sub.example.com\tTRUE\t/x\tTRUE\t2000000001\tB\t2"
        ));
        assert!(add_netscape(
            &mut jar1,
            "#HttpOnly_host.example.com\tFALSE\t/\tFALSE\t2000000002\tC\t3"
        ));

        // Serialize, then reload into a fresh jar.
        let mut buf: Vec<u8> = Vec::new();
        jar1.write_to_at(&mut buf, NOW).expect("write");
        let text = String::from_utf8(buf).expect("utf8");

        let mut jar2 = CookieJar::new();
        jar2.load_str_at(&text, NOW).expect("load");

        // The set of cookies (ignoring the per-load creationtime) must match.
        let normalize = |j: &CookieJar| {
            let mut v: Vec<_> = j
                .cookies()
                .iter()
                .map(|c| {
                    (
                        c.name.clone(),
                        c.value.clone(),
                        c.domain.clone(),
                        c.path.clone(),
                        c.expires,
                        c.secure,
                        c.httponly,
                        c.tailmatch,
                    )
                })
                .collect::<Vec<_>>();
            v.sort();
            v
        };
        assert_eq!(jar2.len(), 3);
        assert_eq!(normalize(&jar1), normalize(&jar2));
    }

    #[test]
    fn comment_lines_are_ignored_on_load() {
        let mut jar = CookieJar::new();
        let doc = concat!(
            "# Netscape HTTP Cookie File\n",
            "# a comment line\n",
            "\n",
            "example.com\tFALSE\t/\tFALSE\t2000000000\tk\tv\n",
        );
        jar.load_str_at(doc, NOW).expect("load");
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.cookies()[0].name, "k");
    }

    #[test]
    fn list_returns_all_cookies_as_lines() {
        let mut jar = CookieJar::new();
        assert!(add_netscape(
            &mut jar,
            "example.com\tFALSE\t/\tFALSE\t2000000000\tA\t1"
        ));
        assert!(add_netscape(
            &mut jar,
            "other.org\tFALSE\t/\tFALSE\t2000000000\tB\t2"
        ));
        let lines = jar.list_at(NOW);
        assert_eq!(lines.len(), 2);
        assert!(lines.contains(&"example.com\tFALSE\t/\tFALSE\t2000000000\tA\t1".to_string()));
        assert!(lines.contains(&"other.org\tFALSE\t/\tFALSE\t2000000000\tB\t2".to_string()));
    }

    #[test]
    fn save_to_file_round_trip() {
        use std::fs;
        // A unique path in the system temp dir (never committed).
        let path = std::env::temp_dir().join(format!(
            "blitzy_adhoc_cookie_save_{}.txt",
            std::process::id()
        ));
        let path_str = path.to_str().expect("utf8 path");

        let mut jar = CookieJar::new();
        assert!(add_netscape(
            &mut jar,
            "example.com\tFALSE\t/\tFALSE\t2000000000\tk\tv"
        ));
        jar.save_at(Some(path_str), NOW).expect("save");

        // The file exists, starts with the header, and holds the cookie line.
        let written = fs::read_to_string(&path).expect("read back");
        assert!(written.starts_with("# Netscape HTTP Cookie File\n"));
        assert!(written.contains("example.com\tFALSE\t/\tFALSE\t2000000000\tk\tv\n"));

        // Reloading yields the same cookie.
        let mut jar2 = CookieJar::new();
        jar2.load_at(path_str, NOW).expect("load");
        assert_eq!(jar2.len(), 1);
        assert_eq!(jar2.cookies()[0].name, "k");
        assert_eq!(jar2.cookies()[0].value, "v");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn save_with_no_target_is_noop() {
        let mut jar = CookieJar::new();
        assert!(add_netscape(
            &mut jar,
            "example.com\tFALSE\t/\tFALSE\t2000000000\tk\tv"
        ));
        // No explicit file and no configured jar file: nothing to do, Ok(()).
        jar.save_at(None, NOW).expect("noop save");
    }

    // -----------------------------------------------------------------------
    // Loading (Set-Cookie: prefix) and the CURLOPT_COOKIELIST commands
    // -----------------------------------------------------------------------

    #[test]
    fn load_str_detects_set_cookie_prefix() {
        let mut jar = CookieJar::new();
        // A header-format line is recognized case-insensitively and parsed as
        // a Set-Cookie header (prefix + blanks stripped).
        jar.load_str_at("Set-Cookie: hk=hv; Domain=example.com\n", NOW)
            .expect("load");
        assert_eq!(jar.len(), 1);
        let c = &jar.cookies()[0];
        assert_eq!(c.name, "hk");
        assert_eq!(c.value, "hv");
        assert_eq!(c.domain.as_deref(), Some("example.com"));
        assert!(c.tailmatch);
    }

    #[test]
    fn load_str_mixed_formats() {
        let mut jar = CookieJar::new();
        let doc = concat!(
            "set-cookie: a=1; Domain=example.com\n", // lower-case prefix
            "example.com\tFALSE\t/\tFALSE\t2000000000\tb\t2\n",
        );
        jar.load_str_at(doc, NOW).expect("load");
        assert_eq!(jar.len(), 2);
    }

    #[test]
    fn add_public_api_returns_stored_flag() {
        let mut jar = CookieJar::new();
        // Stored → Ok(true).
        assert!(jar
            .add(true, false, "a=b; Domain=example.com", None, None, false)
            .expect("add"));
        // A TAB in the value → dropped → Ok(false).
        assert!(!jar
            .add(true, false, "c=d\te", Some("example.com"), Some("/"), false)
            .expect("add"));
    }

    #[test]
    fn add_replaces_same_identity_cookie() {
        let mut jar = CookieJar::new();
        assert!(add_header(
            &mut jar,
            "k=v1; Domain=example.com; Path=/",
            Some("www.example.com"),
            Some("/"),
            false,
        ));
        assert!(add_header(
            &mut jar,
            "k=v2; Domain=example.com; Path=/",
            Some("www.example.com"),
            Some("/"),
            false,
        ));
        // Same name + domain + path + tailmatch → replaced in place.
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.cookies()[0].value, "v2");
    }

    #[test]
    fn clear_all_empties_the_jar() {
        let mut jar = CookieJar::new();
        assert!(add_netscape(
            &mut jar,
            "example.com\tFALSE\t/\tFALSE\t2000000000\tk\tv"
        ));
        jar.clear_all();
        assert!(jar.is_empty());
    }

    #[test]
    fn command_all_clears_everything() {
        let mut jar = CookieJar::new();
        assert!(add_netscape(
            &mut jar,
            "example.com\tFALSE\t/\tFALSE\t2000000000\tA\t1"
        ));
        jar.command_at("ALL", NOW).expect("command");
        assert!(jar.is_empty());
    }

    #[test]
    fn command_sess_clears_only_session_cookies() {
        let mut jar = CookieJar::new();
        // Persistent cookie expiring at SOON, plus a session cookie (expires 0).
        assert!(add_netscape(
            &mut jar,
            &format!("example.com\tFALSE\t/\tFALSE\t{SOON}\tp\t1")
        ));
        assert!(add_netscape(
            &mut jar,
            "example.com\tFALSE\t/\tFALSE\t0\ts\t2"
        ));
        assert_eq!(jar.len(), 2);
        jar.command_at("SESS", NOW).expect("command");
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.cookies()[0].name, "p");
    }

    #[test]
    fn command_inline_adds_header_and_netscape_lines() {
        let mut jar = CookieJar::new();
        jar.command_at("Set-Cookie: inline=yes; Domain=example.com", NOW)
            .expect("command");
        jar.command_at("example.com\tFALSE\t/\tFALSE\t2000000000\tnl\tv", NOW)
            .expect("command");
        assert_eq!(jar.len(), 2);
    }

    #[test]
    fn command_case_insensitive_verbs() {
        let mut jar = CookieJar::new();
        assert!(add_netscape(
            &mut jar,
            "example.com\tFALSE\t/\tFALSE\t2000000000\tk\tv"
        ));
        // Verbs are matched case-insensitively (curl_strequal).
        jar.command_at("all", NOW).expect("command");
        assert!(jar.is_empty());
    }

    #[test]
    fn command_rejects_oversized_inline() {
        let mut jar = CookieJar::new();
        let huge = "x".repeat(CURL_MAX_INPUT_LENGTH + 1);
        assert!(jar.command_at(&huge, NOW).is_err());
    }

    #[test]
    fn load_files_reads_queued_files() {
        use std::fs;
        let path = std::env::temp_dir().join(format!(
            "blitzy_adhoc_cookie_loadfiles_{}.txt",
            std::process::id()
        ));
        fs::write(&path, "example.com\tFALSE\t/\tFALSE\t2000000000\tk\tv\n")
            .expect("write fixture");
        let mut jar = CookieJar::new();
        jar.add_file(path.to_str().unwrap());
        assert_eq!(jar.cookie_files().len(), 1);
        jar.load_files().expect("load files");
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.cookies()[0].name, "k");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn command_reload_loads_queued_files() {
        use std::fs;
        let path = std::env::temp_dir().join(format!(
            "blitzy_adhoc_cookie_reload_{}.txt",
            std::process::id()
        ));
        fs::write(&path, "example.com\tFALSE\t/\tFALSE\t2000000000\trk\trv\n")
            .expect("write fixture");
        let mut jar = CookieJar::new();
        jar.add_file(path.to_str().unwrap());
        jar.command_at("RELOAD", NOW).expect("reload");
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.cookies()[0].name, "rk");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn command_flush_writes_configured_jar_file() {
        use std::fs;
        let path = std::env::temp_dir().join(format!(
            "blitzy_adhoc_cookie_flush_{}.txt",
            std::process::id()
        ));
        let mut jar = CookieJar::new();
        jar.set_jar_file(path.to_str().unwrap());
        assert!(add_netscape(
            &mut jar,
            "example.com\tFALSE\t/\tFALSE\t2000000000\tk\tv"
        ));
        jar.command_at("FLUSH", NOW).expect("flush");
        let written = fs::read_to_string(&path).expect("read back");
        assert!(written.starts_with("# Netscape HTTP Cookie File\n"));
        assert!(written.contains("example.com\tFALSE\t/\tFALSE\t2000000000\tk\tv\n"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn load_missing_file_is_not_an_error() {
        let mut jar = CookieJar::new();
        // curl only warns on an unopenable cookie file; the engine still runs.
        jar.load_at("/nonexistent/blitzy/cookie/path.txt", NOW)
            .expect("missing file is ok");
        assert!(jar.is_empty());
        assert!(jar.is_running());
    }
}
