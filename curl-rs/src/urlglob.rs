// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// Rust rewrite of curl's src/tool_urlglob.c (curl {a,b} / [1-10] URL globbing).

//! # curl's URL globbing engine
//!
//! Faithful Rust port of curl 8.19.0-DEV's `src/tool_urlglob.c` / `src/tool_urlglob.h`.
//!
//! curl supports a small, bespoke *URL globbing* mini-language on the command line that lets
//! one invocation expand into many transfers. It is **not** filesystem/shell globbing (so the
//! `glob` crate is deliberately **not** used here) — it is curl's own syntax:
//!
//! * **Set** — `{one,two,three}`: a comma-separated list of literal alternatives.
//! * **Range** — `[1-10]` (numeric), `[a-z]` (alphabetic), each with an optional step
//!   (`[1-100:10]`, `[a-z:2]`). Leading-zero numeric ranges (`[001-100]`) preserve their
//!   field width.
//! * Any run of literal characters between patterns is a fixed segment.
//! * A backslash escapes an otherwise-special character (`\{`, `\[`, `\}`, `\]`).
//!
//! IPv6 address literals such as `http://[::1]/` are detected and passed through verbatim so
//! that the `[` … `]` are not mistaken for a range.
//!
//! ## Public surface (mirrors the C functions)
//!
//! * [`glob_url`] — parse a URL into its pattern list and report the total number of expanded
//!   URLs (curl's `glob_url`). Honors `-g`/`--globoff`.
//! * [`glob_next_url`] — produce the next expanded URL by odometer-incrementing the pattern
//!   indices, least-significant pattern first (curl's `glob_next_url`).
//! * [`glob_match_url`] — expand an output-filename template that references glob parts via
//!   `#1`, `#2`, … (curl's `glob_match_url`, used by `-o`/`--output`).
//! * [`glob_inuse`] — whether a [`URLGlob`] holds any parsed patterns (curl's `glob_inuse`).
//!
//! Cleanup is automatic: [`URLGlob`] owns all of its storage, so Rust's `Drop` replaces
//! curl's manual `glob_cleanup`.
//!
//! ## Error handling
//!
//! Malformed patterns return [`CurlCode::UrlMalformat`] (curl's `CURLE_URL_MALFORMAT`). The
//! human-readable message and the offending column are stored on the [`URLGlob`] and, exactly
//! like curl's tool, [`glob_url`] prints a `curl: (N) <message>` diagnostic (with a caret
//! pointing at the error column) to standard error before returning. curl's out-of-memory
//! paths are intentionally omitted — Rust's allocator handles allocation failure.

// This module is a language rewrite of curl's `src/tool_urlglob.c`. Its public entry points
// (`glob_url`, `glob_next_url`, `glob_match_url`, `glob_inuse`) are consumed by the
// operation-dispatch layer (`operate.rs`) and referenced from `args.rs`'s `State`
// (`urlglob`/`inglob`), which are wired up in a later checkpoint following curl's build-order
// dependency sequence (AAP §0.7.3). Until that wiring lands there is no in-crate caller, so —
// matching the established convention of the sibling CLI modules (`args.rs`, `getpass.rs`,
// `terminal.rs`, `xattr.rs`) — a crate-style `dead_code` allowance keeps the foundation build
// warning-free without weakening any other lint.
#![allow(dead_code)]

use curl_rs_lib::CurlCode;
use std::fmt::Write as _;
use std::net::Ipv6Addr;

/// Maximum length (including the enclosing brackets) that a bracketed token may have while
/// still being considered as a possible IPv6 literal. Mirrors curl's `MAX_IP6LEN`.
const MAX_IP6LEN: usize = 128;

/// Upper bound on the number of patterns a single URL may expand into before curl reports
/// `"too many {} sets"`. Mirrors the `glob->pnum < 255` guard in curl's `add_glob`.
const GLOB_PATTERN_MAX: usize = 255;

/// Upper bound on the number of elements a single `{…}` set may contain before curl reports
/// `"range overflow"`. Mirrors the `size >= 100000` guard in curl's `glob_set`.
const GLOB_SET_ELEM_MAX: usize = 100_000;

// ===========================================================================
// Data model (ports of `globtype` and `struct URLPattern` from tool_urlglob.h)
// ===========================================================================

/// The kind of a single URL glob pattern.
///
/// curl distinguishes three C `globtype`s (`GLOB_SET`, `GLOB_ASCII`, `GLOB_NUM`); the two
/// range flavors (`GLOB_ASCII` / `GLOB_NUM`) are unified here under [`GlobPatternType::Range`]
/// because they share identical iteration semantics, with the numeric-versus-alphabetic detail
/// carried in the pattern payload ([`RangeKind`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobPatternType {
    /// A `{a,b,c}` set — or a fixed literal segment, which curl models as a single-element
    /// set (`GLOB_SET`).
    Set,
    /// A `[1-10]` / `[a-z]` range (curl's `GLOB_ASCII` and `GLOB_NUM`).
    Range,
}

/// The concrete shape of a [`GlobPatternType::Range`] pattern: either an alphabetic character
/// range (curl's `GLOB_ASCII`) or a numeric range (curl's `GLOB_NUM`).
///
/// The `cur` field is the live iteration cursor (curl's `letter` / `idx`); it starts at `min`
/// and is advanced by `step` in [`glob_next_url`].
#[derive(Debug, Clone)]
enum RangeKind {
    /// Alphabetic range, e.g. `[a-z]` or `[B-Q:2]`. Values are ASCII letter codes; they are
    /// held in `i32` (matching curl's `int` fields) so that `cur + step` never overflows.
    Ascii {
        /// First letter of the range (inclusive).
        min: i32,
        /// Last letter of the range (inclusive).
        max: i32,
        /// Current letter for the active iteration.
        cur: i32,
        /// Iteration step (1–255); a step of 0 is rejected as a bad range.
        step: u8,
    },
    /// Numeric range, e.g. `[1-10]` or `[001-100:5]`.
    Num {
        /// First value of the range (inclusive).
        min: i64,
        /// Last value of the range (inclusive).
        max: i64,
        /// Current value for the active iteration.
        cur: i64,
        /// Iteration step (>= 1).
        step: i64,
        /// Zero-padding field width taken from a leading-zero minimum (e.g. `[001-100]`
        /// yields `npad = 3`); `0` means no padding.
        npad: usize,
    },
}

/// The payload of a [`UrlPattern`]: the two shapes a pattern can take.
#[derive(Debug, Clone)]
enum PatternData {
    /// A set of literal alternatives (curl's `GLOB_SET`). A fixed literal segment is a
    /// single-element set. `idx` is the live cursor into `elem`; `size` mirrors curl's
    /// `c.set.size` (always equal to `elem.len()`).
    Set {
        /// The set's literal alternatives.
        elem: Vec<String>,
        /// Current element index for the active iteration.
        idx: usize,
        /// Number of elements (curl's `c.set.size`).
        size: usize,
    },
    /// A range (curl's `GLOB_ASCII` / `GLOB_NUM`).
    Range(RangeKind),
}

/// A single URL glob pattern (port of curl's `struct URLPattern`).
#[derive(Debug, Clone)]
pub struct UrlPattern {
    /// Whether this is a set or a range (curl's `type`).
    pub ptype: GlobPatternType,
    /// The 0-based index of this pattern among the "actual" globs (`{}`/`[]`) for `#N`
    /// output-template references, or `-1` for a fixed literal segment (curl's `globindex`).
    pub globindex: i32,
    /// The pattern payload.
    data: PatternData,
}

/// A parsed URL glob (port of curl's `struct URLGlob`).
///
/// Holds the ordered list of [`UrlPattern`]s a URL expands into plus the live iteration state.
/// The total number of expanded URLs is [`URLGlob::urlnum`]. All storage is owned, so cleanup
/// is automatic via `Drop` (replacing curl's `glob_cleanup`).
#[derive(Debug, Clone, Default)]
pub struct URLGlob {
    /// The ordered pattern list (curl's `pattern[]` + `pnum`).
    patterns: Vec<UrlPattern>,
    /// Length in bytes of the URL that was globbed (curl sizes its work buffer from this).
    urllen: usize,
    /// Reusable scratch buffer that each expanded URL is assembled into (curl's `dynbuf buf`).
    glob_buffer: String,
    /// Total number of URLs this glob expands to (curl's `*urlnum`).
    urlnum: u64,
    /// Number of patterns in use (curl's `pnum`; always equal to `patterns.len()`).
    size: usize,
    /// Human-readable error message for the most recent parse failure (curl's `error`).
    error: Option<&'static str>,
    /// 1-based column of the parse error, or `0` if not applicable (curl's `pos`).
    pos: usize,
    /// Whether [`glob_next_url`] has already produced the first combination (curl's
    /// `beenhere`).
    beenhere: bool,
}

// ===========================================================================
// Low-level parsing helpers (ports of curlx string primitives + `multiply`)
// ===========================================================================

/// Multiply the running combination count `amount` by `with`, checking for overflow.
///
/// Faithful port of curl's `multiply`: if either operand is zero the product is zero, and a
/// `u64` overflow is reported by returning `true` (curl returns `1`) so the caller can raise a
/// `"range overflow"` error. Uses `checked_mul`, the idiomatic replacement for curl's
/// `__builtin_mul_overflow` intrinsic.
fn multiply(amount: &mut u64, with: u64) -> bool {
    if with == 0 || *amount == 0 {
        *amount = 0;
        false
    } else {
        match amount.checked_mul(with) {
            Some(product) => {
                *amount = product;
                false
            }
            None => true,
        }
    }
}

/// Parse an unsigned decimal number from `bytes` starting at `pos` (port of
/// `curlx_str_number`).
///
/// Returns `Some((value, new_pos))` with the cursor advanced past the digits on success, or
/// `None` when there is no leading digit (curl's `STRE_NO_NUM`) or the value would exceed
/// `max` / overflow `i64` (curl's `STRE_OVERFLOW`). Leading zeroes are accepted; there is no
/// `0x` prefix or leading-space handling — matching curl exactly. On failure the cursor is
/// **not** advanced.
fn str_number(bytes: &[u8], pos: usize, max: i64) -> Option<(i64, usize)> {
    if pos >= bytes.len() || !bytes[pos].is_ascii_digit() {
        return None;
    }
    let mut num: i64 = 0;
    let mut cursor = pos;
    while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
        let digit = i64::from(bytes[cursor] - b'0');
        // `checked_*` guards the i64 itself; the `> max` test reproduces curl's ceiling check.
        num = num.checked_mul(10).and_then(|n| n.checked_add(digit))?;
        if num > max {
            return None;
        }
        cursor += 1;
    }
    Some((num, cursor))
}

/// If `bytes[pos]` equals `byte`, return the position just past it; otherwise `None` (port of
/// `curlx_str_single`). The cursor is advanced only on a match.
fn str_single(bytes: &[u8], pos: usize, byte: u8) -> Option<usize> {
    if pos < bytes.len() && bytes[pos] == byte {
        Some(pos + 1)
    } else {
        None
    }
}

/// Advance `pos` past any run of blanks (space or tab), returning the new position (port of
/// `curlx_str_passblanks`).
fn pass_blanks(bytes: &[u8], pos: usize) -> usize {
    let mut cursor = pos;
    while cursor < bytes.len() && (bytes[cursor] == b' ' || bytes[cursor] == b'\t') {
        cursor += 1;
    }
    cursor
}

/// Detect an IPv6 address literal beginning at `bytes[start]` (which must be `[`).
///
/// Port of curl's `peek_ipv6`. curl asks its URL parser to validate the bracketed token; here
/// the bracketed content (minus any `%zone` suffix) is validated with [`Ipv6Addr`], which is
/// self-contained and accepts exactly the standard IPv6 forms (`::1`, `2001:db8::1`,
/// IPv4-mapped, …) while rejecting glob ranges such as `1-10` or `a-z`.
///
/// Returns the number of bytes to skip — the full `[` … `]` span — when the token is an IPv6
/// literal, or `0` otherwise.
fn peek_ipv6(bytes: &[u8], start: usize) -> usize {
    // Locate the closing bracket; a token with no `]` cannot be an IPv6 literal.
    let close = match bytes[start + 1..].iter().position(|&b| b == b']') {
        Some(rel) => start + 1 + rel,
        None => return 0,
    };

    let hlen = close - start + 1; // includes the enclosing '[' and ']'
    if hlen >= MAX_IP6LEN {
        return 0;
    }

    // Content between the brackets, with any zone identifier ("%eth0", "%25eth0") stripped —
    // std's parser does not accept a zone suffix, but its presence still marks an IPv6 host.
    let content = &bytes[start + 1..close];
    let host = match content.iter().position(|&b| b == b'%') {
        Some(idx) => &content[..idx],
        None => content,
    };

    match std::str::from_utf8(host) {
        Ok(text) if text.parse::<Ipv6Addr>().is_ok() => hlen,
        _ => 0,
    }
}

// ===========================================================================
// Parsing (ports of glob_fixed / glob_set / glob_range / glob_parse / add_glob)
// ===========================================================================

/// Transient parse-cursor state threaded through the pattern parsers.
///
/// Bundles curl's `pattern` cursor (`i`), the 1-based error column (`col`, curl's `*posp`),
/// the running combination count (`amount`, curl's `*amount`), the "actual glob" counter
/// (`globindex`), and the element/literal accumulation buffer (`scratch`, curl's `dynbuf buf`).
struct Cursor {
    /// 0-based byte offset into the URL (curl's advancing `pattern` pointer).
    i: usize,
    /// 1-based column used for error reporting (curl's `*posp`).
    col: usize,
    /// Running product of pattern sizes — the eventual `urlnum` (curl's `*amount`).
    amount: u64,
    /// Number of "actual" globs seen so far, assigned as each pattern's `globindex`.
    globindex: i32,
    /// Byte accumulator for the current literal/element (curl's `dynbuf buf`).
    scratch: Vec<u8>,
}

impl URLGlob {
    /// Create an empty glob sized for the URL `url`.
    fn new(url: &str) -> Self {
        let urllen = url.len();
        URLGlob {
            patterns: Vec::new(),
            urllen,
            glob_buffer: String::with_capacity(urllen),
            urlnum: 0,
            size: 0,
            error: None,
            pos: 0,
            beenhere: false,
        }
    }

    /// Record a parse error (message + 1-based column) and return the matching curl error code.
    ///
    /// Port of curl's `globerror`. Every glob parse error maps to `CURLE_URL_MALFORMAT`; curl's
    /// out-of-memory path is not reproduced.
    fn set_error(&mut self, message: &'static str, pos: usize) -> CurlCode {
        self.error = Some(message);
        self.pos = pos;
        CurlCode::UrlMalformat
    }

    /// Append a fixed literal segment as a single-element set (port of curl's `glob_fixed`).
    fn glob_fixed(&mut self, fixed: &[u8]) {
        // Splits only ever occur on ASCII delimiters, so `fixed` is always valid UTF-8; the
        // lossy conversion therefore reproduces the bytes exactly and cannot panic.
        let literal = String::from_utf8_lossy(fixed).into_owned();
        self.patterns.push(UrlPattern {
            ptype: GlobPatternType::Set,
            globindex: -1,
            data: PatternData::Set {
                elem: vec![literal],
                idx: 0,
                size: 1,
            },
        });
    }

    /// Commit the pattern just pushed, enforcing curl's pattern-count ceiling (port of curl's
    /// `add_glob`). Reports `"too many {} sets"` once the limit is exceeded.
    fn add_glob(&mut self, pos: usize) -> Result<(), CurlCode> {
        if self.patterns.len() > GLOB_PATTERN_MAX {
            return Err(self.set_error("too many {} sets", pos));
        }
        Ok(())
    }

    /// Parse a `{…}` set expression, with `cur.i` positioned just past the opening `{` (port of
    /// curl's `glob_set`). On success pushes a [`GlobPatternType::Set`] pattern.
    fn glob_set(&mut self, bytes: &[u8], cur: &mut Cursor) -> Result<(), CurlCode> {
        let start_i = cur.i; // curl's `opattern` — the first byte after '{'
        let opos = cur.col - 1; // column of the opening '{' (curl's `opos`)
        let globindex = cur.globindex;
        let mut elem: Vec<String> = Vec::new();
        cur.scratch.clear();

        loop {
            match bytes.get(cur.i).copied() {
                // URL ended while the set was still open.
                None => return Err(self.set_error("unmatched brace", opos)),

                // No nested expressions are permitted.
                Some(b'{') | Some(b'[') => return Err(self.set_error("nested brace", cur.col)),

                // Closing brace: complete the final element, then finish.
                Some(b'}') => {
                    if cur.i == start_i {
                        return Err(self.set_error("empty string within braces", cur.col));
                    }
                    // +1 counts the element about to be pushed below (curl multiplies here).
                    if multiply(&mut cur.amount, elem.len() as u64 + 1) {
                        return Err(self.set_error("range overflow", 0));
                    }
                    if elem.len() >= GLOB_SET_ELEM_MAX {
                        return Err(self.set_error("range overflow", 0));
                    }
                    elem.push(String::from_utf8_lossy(&cur.scratch).into_owned());
                    cur.scratch.clear();
                    cur.i += 1; // consume '}' (curl does not advance the column when done)
                    break;
                }

                // Element separator: complete the current element and continue.
                Some(b',') => {
                    if elem.len() >= GLOB_SET_ELEM_MAX {
                        return Err(self.set_error("range overflow", 0));
                    }
                    elem.push(String::from_utf8_lossy(&cur.scratch).into_owned());
                    cur.scratch.clear();
                    cur.i += 1;
                    cur.col += 1;
                }

                // A closing bracket here is illegal.
                Some(b']') => return Err(self.set_error("unexpected close bracket", cur.col)),

                // Backslash escapes the following byte (any byte) within a set.
                Some(b'\\') => {
                    if cur.i + 1 < bytes.len() {
                        cur.i += 1;
                        cur.col += 1;
                    }
                    cur.scratch.push(bytes[cur.i]);
                    cur.i += 1;
                    cur.col += 1;
                }

                // Ordinary byte: copy it into the current element.
                Some(byte) => {
                    cur.scratch.push(byte);
                    cur.i += 1;
                    cur.col += 1;
                }
            }
        }

        let size = elem.len();
        self.patterns.push(UrlPattern {
            ptype: GlobPatternType::Set,
            globindex,
            data: PatternData::Set { elem, idx: 0, size },
        });
        Ok(())
    }

    /// Parse a `[…]` range expression, with `cur.i` positioned just past the opening `[` (port
    /// of curl's `glob_range`). On success pushes a [`GlobPatternType::Range`] pattern.
    fn glob_range(&mut self, bytes: &[u8], cur: &mut Cursor) -> Result<(), CurlCode> {
        let start_i = cur.i;
        let globindex = cur.globindex;

        match bytes.get(cur.i).copied() {
            // ---- Alphabetic range: "a-z]", "B-Q]", "a-z:2]" ------------------------------
            Some(first) if first.is_ascii_alphabetic() => {
                let mut pmatch = false;
                let mut min_c: i32 = 0;
                let mut max_c: i32 = 0;
                let mut step: u8 = 1;

                // Requires "X-Y" followed by at least one more byte (curl's
                // `pattern[1]=='-' && pattern[2] && pattern[3]`).
                if bytes.get(cur.i + 1) == Some(&b'-') && cur.i + 3 < bytes.len() {
                    min_c = i32::from(bytes[cur.i]);
                    max_c = i32::from(bytes[cur.i + 2]);
                    let end_c = bytes[cur.i + 3];
                    pmatch = true;

                    if end_c == b':' {
                        // Optional step: "[a-z:2]".
                        let p0 = cur.i + 4;
                        match str_number(bytes, p0, 256) {
                            Some((num, np)) => match str_single(bytes, np, b']') {
                                Some(np2) => {
                                    step = num as u8; // 256 wraps to 0 → rejected below
                                    cur.i = np2;
                                }
                                None => {
                                    step = 0;
                                    cur.i = np;
                                }
                            },
                            None => {
                                step = 0;
                                cur.i = p0;
                            }
                        }
                    } else if end_c == b']' {
                        cur.i += 4; // consume "X-Y]"
                    } else {
                        pmatch = false; // malformed; cursor left unadvanced
                    }
                }

                cur.col += cur.i - start_i;

                let span = max_c - min_c;
                if !pmatch
                    || step == 0
                    || (min_c == max_c && step != 1)
                    || (min_c != max_c
                        && (min_c > max_c
                            || i32::from(step) > span
                            || span > (i32::from(b'z') - i32::from(b'a'))))
                {
                    return Err(self.set_error("bad range", cur.col));
                }

                let count = ((max_c - min_c) / i32::from(step) + 1) as u64;
                if multiply(&mut cur.amount, count) {
                    return Err(self.set_error("range overflow", cur.col));
                }

                self.patterns.push(UrlPattern {
                    ptype: GlobPatternType::Range,
                    globindex,
                    data: PatternData::Range(RangeKind::Ascii {
                        min: min_c,
                        max: max_c,
                        cur: min_c,
                        step,
                    }),
                });
            }

            // ---- Numeric range: "0-9]", "17-2000]", "001-999]", "1-100:10]" --------------
            Some(first) if first.is_ascii_digit() => {
                let mut npad = 0usize;
                let mut min_n: i64 = 0;
                let mut max_n: i64 = 0;
                let mut step_n: i64 = 0;

                // Leading zero → count the padding width across the whole minimum literal.
                if bytes[cur.i] == b'0' {
                    let mut c = cur.i;
                    while c < bytes.len() && bytes[c].is_ascii_digit() {
                        c += 1;
                        npad += 1;
                    }
                }

                if let Some((num, np)) = str_number(bytes, cur.i, i64::MAX) {
                    min_n = num;
                    cur.i = np;
                    if let Some(np) = str_single(bytes, cur.i, b'-') {
                        cur.i = pass_blanks(bytes, np);
                        if let Some((num, np)) = str_number(bytes, cur.i, i64::MAX) {
                            max_n = num;
                            cur.i = np;
                            if let Some(np) = str_single(bytes, cur.i, b']') {
                                cur.i = np;
                                step_n = 1;
                            } else if let Some(np) = str_single(bytes, cur.i, b':') {
                                cur.i = np;
                                if let Some((num, np)) = str_number(bytes, cur.i, i64::MAX) {
                                    cur.i = np;
                                    if let Some(np) = str_single(bytes, cur.i, b']') {
                                        cur.i = np;
                                        step_n = num;
                                    }
                                }
                            }
                        }
                    }
                }

                cur.col += cur.i - start_i;

                if step_n == 0
                    || (min_n == max_n && step_n != 1)
                    || (min_n != max_n && (min_n > max_n || step_n > (max_n - min_n)))
                {
                    return Err(self.set_error("bad range", cur.col));
                }

                // Compute the element count in `u64`: the validity check above guarantees
                // `max_n >= min_n` and `step_n >= 1`, so the span is non-negative, and the
                // `+ 1` cannot overflow `u64` even for a full-width `i64` span (which would
                // overflow the `i64` arithmetic curl performs).
                let count = (max_n - min_n) as u64 / step_n as u64 + 1;
                if multiply(&mut cur.amount, count) {
                    return Err(self.set_error("range overflow", cur.col));
                }

                self.patterns.push(UrlPattern {
                    ptype: GlobPatternType::Range,
                    globindex,
                    data: PatternData::Range(RangeKind::Num {
                        min: min_n,
                        max: max_n,
                        cur: min_n,
                        step: step_n,
                        npad,
                    }),
                });
            }

            // ---- Neither a letter nor a digit --------------------------------------------
            _ => return Err(self.set_error("bad range specification", cur.col)),
        }

        Ok(())
    }

    /// Parse a whole URL into its pattern list (port of curl's `glob_parse`).
    ///
    /// Returns the total number of expanded URLs on success, or the stored
    /// [`CurlCode::UrlMalformat`] on a malformed pattern.
    fn parse(&mut self, url: &str) -> Result<u64, CurlCode> {
        let bytes = url.as_bytes();
        let mut cur = Cursor {
            i: 0,
            col: 1,
            amount: 1,
            globindex: 0,
            scratch: Vec::new(),
        };

        while cur.i < bytes.len() {
            // Collect a literal run until the next '{' or a genuine range '['.
            while cur.i < bytes.len() && bytes[cur.i] != b'{' {
                if bytes[cur.i] == b'[' {
                    let mut skip = peek_ipv6(bytes, cur.i);
                    if skip == 0 && bytes.get(cur.i + 1) == Some(&b']') {
                        skip = 2; // an empty "[]" is a literal, not a range
                    }
                    if skip > 0 {
                        cur.scratch.extend_from_slice(&bytes[cur.i..cur.i + skip]);
                        cur.i += skip;
                        // curl advances `pattern` but intentionally not `*pos` here, so the
                        // error column deliberately does not count skipped IPv6/`[]` bytes.
                        continue;
                    }
                    break; // a real range — hand off to glob_range below
                }
                if bytes[cur.i] == b'}' || bytes[cur.i] == b']' {
                    return Err(self.set_error("unmatched close brace/bracket", cur.col));
                }
                // In a literal, only the four bracket characters may be backslash-escaped.
                if bytes[cur.i] == b'\\'
                    && matches!(
                        bytes.get(cur.i + 1),
                        Some(&b'{') | Some(&b'[') | Some(&b'}') | Some(&b']')
                    )
                {
                    cur.i += 1;
                    cur.col += 1;
                }
                cur.scratch.push(bytes[cur.i]);
                cur.i += 1;
                cur.col += 1;
            }

            if !cur.scratch.is_empty() {
                // Flush the collected literal as a fixed single-element set.
                let literal: Vec<u8> = std::mem::take(&mut cur.scratch);
                self.glob_fixed(&literal);
                self.add_glob(cur.col)?;
            } else if cur.i >= bytes.len() {
                break;
            } else if bytes[cur.i] == b'{' {
                cur.i += 1;
                cur.col += 1;
                self.glob_set(bytes, &mut cur)?;
                self.add_glob(cur.col)?;
                cur.globindex += 1;
            } else if bytes[cur.i] == b'[' {
                cur.i += 1;
                cur.col += 1;
                self.glob_range(bytes, &mut cur)?;
                self.add_glob(cur.col)?;
                cur.globindex += 1;
            }
        }

        Ok(cur.amount)
    }
}

// ===========================================================================
// Public entry points (ports of glob_url / glob_next_url / glob_match_url)
// ===========================================================================

impl URLGlob {
    /// Total number of URLs this glob expands to (curl's `urlnum`).
    pub fn urlnum(&self) -> u64 {
        self.urlnum
    }

    /// Number of parsed patterns (curl's `pnum`).
    pub fn pattern_count(&self) -> usize {
        self.size
    }

    /// Append the current value of a single pattern to `out` (shared by [`glob_next_url`] and
    /// [`glob_match_url`]).
    fn append_current(out: &mut Vec<u8>, pattern: &UrlPattern) {
        match &pattern.data {
            PatternData::Set { elem, idx, .. } => out.extend_from_slice(elem[*idx].as_bytes()),
            PatternData::Range(RangeKind::Ascii { cur, .. }) => out.push(*cur as u8),
            PatternData::Range(RangeKind::Num { cur, npad, .. }) => {
                let mut number = String::new();
                // Writing to a String is infallible.
                let _ = write!(number, "{:0width$}", cur, width = *npad);
                out.extend_from_slice(number.as_bytes());
            }
        }
    }
}

/// Format curl's `curl: (N) <message>` glob diagnostic, with a caret under the error column
/// when a position is known. Mirrors the text produced by curl's `glob_url` error branch.
fn format_glob_error(code: CurlCode, message: &str, pos: usize, url: &str) -> String {
    if pos > 0 {
        let indent = " ".repeat(pos.saturating_sub(1));
        format!(
            "curl: ({}) {} in URL position {}:\n{}\n{}^",
            code as i32, message, pos, url, indent
        )
    } else {
        format!("curl: ({}) {}", code as i32, message)
    }
}

/// Parse `url` into a [`URLGlob`] and report the total number of expanded URLs (port of curl's
/// `glob_url`).
///
/// When `globoff` is set (curl's `-g`/`--globoff`) the URL is treated as a single literal — no
/// pattern parsing is performed and the count is `1`. On a malformed pattern the human-readable
/// diagnostic (with a caret at the offending column) is printed to standard error, exactly as
/// curl's tool does, and [`CurlCode::UrlMalformat`] is returned.
pub fn glob_url(url: &str, globoff: bool) -> Result<(URLGlob, u64), CurlCode> {
    let mut glob = URLGlob::new(url);

    if globoff {
        // Globbing disabled: the URL passes through untouched as one literal segment.
        glob.glob_fixed(url.as_bytes());
        glob.urlnum = 1;
        glob.size = glob.patterns.len();
        return Ok((glob, 1));
    }

    match glob.parse(url) {
        Ok(amount) => {
            glob.urlnum = amount;
            glob.size = glob.patterns.len();
            Ok((glob, amount))
        }
        Err(code) => {
            if let Some(message) = glob.error {
                eprintln!("{}", format_glob_error(code, message, glob.pos, url));
            }
            Err(code)
        }
    }
}

/// Produce the next expanded URL, or `None` once every combination has been emitted (port of
/// curl's `glob_next_url`).
///
/// The pattern indices form an odometer: the least-significant (right-most) pattern advances
/// first and carries leftward, matching curl's iteration order exactly. Over its lifetime the
/// function yields exactly [`URLGlob::urlnum`] URLs.
pub fn glob_next_url(glob: &mut URLGlob) -> Option<String> {
    glob.glob_buffer.clear();

    if !glob.beenhere {
        glob.beenhere = true;
    } else {
        let mut carry = true;
        let n = glob.size;
        let mut k = 0;
        while carry && k < n {
            carry = false;
            let pattern = &mut glob.patterns[n - 1 - k];
            match &mut pattern.data {
                PatternData::Set { idx, size, .. } => {
                    *idx += 1;
                    if *idx == *size {
                        *idx = 0;
                        carry = true;
                    }
                }
                PatternData::Range(RangeKind::Ascii {
                    cur,
                    min,
                    max,
                    step,
                }) => {
                    *cur += i32::from(*step);
                    if *cur > *max {
                        *cur = *min;
                        carry = true;
                    }
                }
                PatternData::Range(RangeKind::Num {
                    cur,
                    min,
                    max,
                    step,
                    ..
                }) => match cur.checked_add(*step) {
                    Some(next) if next <= *max => *cur = next,
                    _ => {
                        *cur = *min;
                        carry = true;
                    }
                },
            }
            k += 1;
        }
        if carry {
            // The most-significant pattern overflowed: the sequence is exhausted.
            return None;
        }
    }

    let mut out: Vec<u8> = Vec::new();
    for pattern in &glob.patterns {
        URLGlob::append_current(&mut out, pattern);
    }
    // Every fragment is valid UTF-8 (whole set strings, ASCII letters, decimal digits), so the
    // lossy conversion is exact and cannot panic.
    glob.glob_buffer = String::from_utf8_lossy(&out).into_owned();
    Some(glob.glob_buffer.clone())
}

/// Expand an output-filename template, substituting `#1`, `#2`, … with the current value of the
/// corresponding glob (port of curl's `glob_match_url`, used by `-o`/`--output`).
///
/// `#N` references the N-th "actual" glob (fixed literal segments are skipped when numbering).
/// A `#N` that does not resolve to a glob is emitted literally, matching curl. curl's
/// Windows/MS-DOS filename-sanitization branch is out of scope for the supported platforms.
pub fn glob_match_url(filename: &str, glob: &URLGlob) -> Result<String, CurlCode> {
    let bytes = filename.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'#' && matches!(bytes.get(i + 1), Some(b) if b.is_ascii_digit()) {
            let start = i; // position of '#', for literal fallback
            i += 1; // consume '#'
            let mut matched: Option<&UrlPattern> = None;

            if let Some((num, np)) = str_number(bytes, i, glob.size as i64) {
                // curl advances past the digits on a successful parse regardless of value.
                i = np;
                if num != 0 {
                    let target = (num - 1) as i32;
                    for pattern in &glob.patterns {
                        if pattern.globindex == target {
                            matched = Some(pattern);
                            break;
                        }
                    }
                }
            }

            match matched {
                Some(pattern) => URLGlob::append_current(&mut out, pattern),
                // `#N` out of range: reproduce the literal `#N` text verbatim.
                None => out.extend_from_slice(&bytes[start..i]),
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }

    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Whether the glob holds any parsed patterns (port of curl's `glob_inuse`).
pub fn glob_inuse(glob: &URLGlob) -> bool {
    glob.size != 0
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Fully expand a URL (globbing enabled) into the ordered list of concrete URLs.
    fn expand(url: &str) -> Vec<String> {
        let (mut glob, urlnum) = glob_url(url, false).expect("glob_url should succeed");
        let mut urls = Vec::new();
        while let Some(next) = glob_next_url(&mut glob) {
            urls.push(next);
        }
        // The number of emitted URLs must match the reported total exactly.
        assert_eq!(urls.len() as u64, urlnum, "emitted count must equal urlnum");
        urls
    }

    /// Parse a URL and return the stored error message on failure (for error-path assertions).
    fn parse_error(url: &str) -> (CurlCode, Option<&'static str>, usize) {
        let mut glob = URLGlob::new(url);
        match glob.parse(url) {
            Ok(_) => panic!("expected parse failure for {url:?}"),
            Err(code) => (code, glob.error, glob.pos),
        }
    }

    // ---- Plain literals ------------------------------------------------------------------

    #[test]
    fn plain_url_is_single_literal() {
        let urls = expand("http://example.com/index.html");
        assert_eq!(urls, vec!["http://example.com/index.html".to_string()]);
    }

    #[test]
    fn empty_url_expands_to_single_empty_string() {
        let urls = expand("");
        assert_eq!(urls, vec![String::new()]);
    }

    // ---- Sets ----------------------------------------------------------------------------

    #[test]
    fn simple_set_expands_each_alternative() {
        let urls = expand("http://site/{one,two,three}");
        assert_eq!(
            urls,
            vec![
                "http://site/one".to_string(),
                "http://site/two".to_string(),
                "http://site/three".to_string(),
            ]
        );
    }

    #[test]
    fn single_element_set() {
        assert_eq!(expand("a{b}c"), vec!["abc".to_string()]);
    }

    #[test]
    fn trailing_comma_yields_empty_element() {
        // "{a,}" is two elements: "a" and "".
        assert_eq!(expand("x{a,}y"), vec!["xay".to_string(), "xy".to_string()]);
    }

    // ---- Numeric ranges ------------------------------------------------------------------

    #[test]
    fn numeric_range() {
        assert_eq!(
            expand("[1-3]"),
            vec!["1".to_string(), "2".to_string(), "3".to_string()]
        );
    }

    #[test]
    fn numeric_range_with_step() {
        assert_eq!(
            expand("[1-10:3]"),
            vec![
                "1".to_string(),
                "4".to_string(),
                "7".to_string(),
                "10".to_string()
            ]
        );
    }

    #[test]
    fn numeric_range_zero_padded_preserves_width() {
        assert_eq!(
            expand("img[08-11].png"),
            vec![
                "img08.png".to_string(),
                "img09.png".to_string(),
                "img10.png".to_string(),
                "img11.png".to_string(),
            ]
        );
    }

    #[test]
    fn numeric_range_wide_padding() {
        let urls = expand("[001-100]");
        assert_eq!(urls.len(), 100);
        assert_eq!(urls[0], "001");
        assert_eq!(urls[8], "009");
        assert_eq!(urls[9], "010");
        assert_eq!(urls[99], "100");
    }

    #[test]
    fn numeric_range_blanks_after_hyphen() {
        // curl accepts blanks between '-' and the upper bound.
        assert_eq!(
            expand("[1- 3]"),
            vec!["1".to_string(), "2".to_string(), "3".to_string()]
        );
    }

    // ---- Alphabetic ranges ---------------------------------------------------------------

    #[test]
    fn alpha_range() {
        assert_eq!(
            expand("[a-e]"),
            vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string(),
                "e".to_string()
            ]
        );
    }

    #[test]
    fn alpha_range_with_step() {
        assert_eq!(
            expand("[a-z:5]"),
            vec![
                "a".to_string(),
                "f".to_string(),
                "k".to_string(),
                "p".to_string(),
                "u".to_string(),
                "z".to_string()
            ]
        );
    }

    #[test]
    fn alpha_range_uppercase() {
        assert_eq!(
            expand("[B-D]"),
            vec!["B".to_string(), "C".to_string(), "D".to_string()]
        );
    }

    // ---- Combinations and odometer order -------------------------------------------------

    #[test]
    fn two_sets_odometer_rightmost_fastest() {
        // Right-most pattern varies fastest, exactly like curl.
        assert_eq!(
            expand("{a,b}{1,2}"),
            vec![
                "a1".to_string(),
                "a2".to_string(),
                "b1".to_string(),
                "b2".to_string()
            ]
        );
    }

    #[test]
    fn set_and_range_combination() {
        assert_eq!(
            expand("http://h/{x,y}/[1-2]"),
            vec![
                "http://h/x/1".to_string(),
                "http://h/x/2".to_string(),
                "http://h/y/1".to_string(),
                "http://h/y/2".to_string(),
            ]
        );
    }

    #[test]
    fn urlnum_is_product_of_pattern_sizes() {
        let (glob, urlnum) = glob_url("[1-3]{a,b}[a-c]", false).unwrap();
        assert_eq!(urlnum, 3 * 2 * 3);
        assert_eq!(glob.urlnum(), 18);
        assert_eq!(glob.pattern_count(), 3);
    }

    // ---- Escapes -------------------------------------------------------------------------

    #[test]
    fn escaped_braces_in_literal_are_literal() {
        // "\{" and "\}" collapse to literal braces and are not treated as a set.
        assert_eq!(expand(r"a\{b\}c"), vec!["a{b}c".to_string()]);
    }

    #[test]
    fn escaped_brackets_in_literal_are_literal() {
        assert_eq!(expand(r"a\[b\]c"), vec!["a[b]c".to_string()]);
    }

    #[test]
    fn escaped_comma_within_set() {
        // Inside a set, a backslash escapes the following byte, so "a\,b" is one element.
        assert_eq!(expand(r"{a\,b}"), vec!["a,b".to_string()]);
    }

    #[test]
    fn backslash_before_plain_char_in_literal_is_kept() {
        // Outside a set only the four bracket chars are escapable, so "\n" stays "\n".
        assert_eq!(expand(r"a\nb"), vec![r"a\nb".to_string()]);
    }

    // ---- IPv6 literals -------------------------------------------------------------------

    #[test]
    fn ipv6_literal_passes_through() {
        assert_eq!(
            expand("http://[::1]/path"),
            vec!["http://[::1]/path".to_string()]
        );
    }

    #[test]
    fn ipv6_literal_with_full_address() {
        assert_eq!(
            expand("http://[2001:db8::1]:8080/"),
            vec!["http://[2001:db8::1]:8080/".to_string()]
        );
    }

    #[test]
    fn ipv6_host_with_trailing_range() {
        assert_eq!(
            expand("http://[::1]/file[1-2]"),
            vec![
                "http://[::1]/file1".to_string(),
                "http://[::1]/file2".to_string(),
            ]
        );
    }

    #[test]
    fn empty_brackets_are_literal() {
        assert_eq!(expand("a[]b"), vec!["a[]b".to_string()]);
    }

    // ---- globoff -------------------------------------------------------------------------

    #[test]
    fn globoff_treats_url_as_literal() {
        let (mut glob, urlnum) = glob_url("http://h/{a,b}[1-3]", true).unwrap();
        assert_eq!(urlnum, 1);
        assert!(glob_inuse(&glob));
        let first = glob_next_url(&mut glob).unwrap();
        assert_eq!(first, "http://h/{a,b}[1-3]");
        assert!(glob_next_url(&mut glob).is_none());
    }

    // ---- Output-template (#N) substitution -----------------------------------------------

    #[test]
    fn match_url_substitutes_glob_parts() {
        let (mut glob, _) = glob_url("http://h/{a,b}/[1-2]", false).unwrap();
        // Advance to the second combination: "a" / "2".
        let _ = glob_next_url(&mut glob); // a / 1
        let _ = glob_next_url(&mut glob); // a / 2
        let out = glob_match_url("out_#1_#2.dat", &glob).unwrap();
        assert_eq!(out, "out_a_2.dat");
    }

    #[test]
    fn match_url_first_combination() {
        let (mut glob, _) = glob_url("{x,y}[5-6]", false).unwrap();
        let _ = glob_next_url(&mut glob); // first: x / 5
        assert_eq!(glob_match_url("#1-#2", &glob).unwrap(), "x-5");
    }

    #[test]
    fn match_url_out_of_range_reference_is_literal() {
        let (mut glob, _) = glob_url("{a,b}", false).unwrap();
        let _ = glob_next_url(&mut glob);
        // Only #1 exists; #2 and #0 are emitted verbatim.
        assert_eq!(glob_match_url("#1", &glob).unwrap(), "a");
        assert_eq!(glob_match_url("#2", &glob).unwrap(), "#2");
        assert_eq!(glob_match_url("#0", &glob).unwrap(), "#0");
    }

    #[test]
    fn match_url_non_reference_hash_is_kept() {
        let (mut glob, _) = glob_url("{a}", false).unwrap();
        let _ = glob_next_url(&mut glob);
        // A '#' not followed by a digit is copied literally.
        assert_eq!(glob_match_url("a#b", &glob).unwrap(), "a#b");
    }

    // ---- Error cases (verbatim messages must be preserved) -------------------------------

    #[test]
    fn error_unmatched_brace() {
        let (code, msg, _) = parse_error("http://h/{a,b");
        assert_eq!(code, CurlCode::UrlMalformat);
        assert_eq!(msg, Some("unmatched brace"));
    }

    #[test]
    fn error_nested_brace() {
        let (code, msg, _) = parse_error("{a{b}}");
        assert_eq!(code, CurlCode::UrlMalformat);
        assert_eq!(msg, Some("nested brace"));
    }

    #[test]
    fn error_nested_bracket_in_set() {
        let (_, msg, _) = parse_error("{a[1-2]}");
        assert_eq!(msg, Some("nested brace"));
    }

    #[test]
    fn error_empty_string_within_braces() {
        let (code, msg, _) = parse_error("{}");
        assert_eq!(code, CurlCode::UrlMalformat);
        assert_eq!(msg, Some("empty string within braces"));
    }

    #[test]
    fn error_unexpected_close_bracket_in_set() {
        let (_, msg, _) = parse_error("{a]b}");
        assert_eq!(msg, Some("unexpected close bracket"));
    }

    #[test]
    fn error_unmatched_close_brace() {
        let (_, msg, _) = parse_error("abc}");
        assert_eq!(msg, Some("unmatched close brace/bracket"));
    }

    #[test]
    fn error_bad_range() {
        let (code, msg, _) = parse_error("[z-a]");
        assert_eq!(code, CurlCode::UrlMalformat);
        assert_eq!(msg, Some("bad range"));
    }

    #[test]
    fn error_bad_numeric_range_reversed() {
        let (_, msg, _) = parse_error("[10-1]");
        assert_eq!(msg, Some("bad range"));
    }

    #[test]
    fn error_bad_range_specification() {
        // First char after '[' is neither a letter nor a digit.
        let (_, msg, _) = parse_error("[-abc]");
        assert_eq!(msg, Some("bad range specification"));
    }

    #[test]
    fn error_cross_case_span_too_wide() {
        // "[A-z]" spans 57 letters (> 25) and is rejected.
        let (_, msg, _) = parse_error("[A-z]");
        assert_eq!(msg, Some("bad range"));
    }

    #[test]
    fn error_alpha_step_too_large() {
        let (_, msg, _) = parse_error("[a-c:9]");
        assert_eq!(msg, Some("bad range"));
    }

    #[test]
    fn error_alpha_step_256_wraps_to_zero() {
        // A step of 256 wraps to 0 as an unsigned byte and is rejected.
        let (_, msg, _) = parse_error("[a-z:256]");
        assert_eq!(msg, Some("bad range"));
    }

    #[test]
    fn error_range_overflow_via_multiply() {
        // Two maximal numeric ranges overflow the u64 combination count.
        let big = format!("[0-{max}][0-{max}]", max = i64::MAX);
        let (code, msg, _) = parse_error(&big);
        assert_eq!(code, CurlCode::UrlMalformat);
        assert_eq!(msg, Some("range overflow"));
    }

    // ---- multiply ------------------------------------------------------------------------

    #[test]
    fn multiply_basic_and_overflow() {
        let mut amount: u64 = 3;
        assert!(!multiply(&mut amount, 4));
        assert_eq!(amount, 12);

        // Zero operand yields zero without signalling overflow.
        let mut zero: u64 = 5;
        assert!(!multiply(&mut zero, 0));
        assert_eq!(zero, 0);

        // Genuine overflow is reported.
        let mut big: u64 = u64::MAX;
        assert!(multiply(&mut big, 2));
    }

    // ---- str_number ----------------------------------------------------------------------

    #[test]
    fn str_number_parses_and_advances() {
        assert_eq!(str_number(b"123]", 0, i64::MAX), Some((123, 3)));
        // Leading zeros accepted, value unchanged.
        assert_eq!(str_number(b"007", 0, i64::MAX), Some((7, 3)));
        // No digit at the cursor.
        assert_eq!(str_number(b"-5", 0, i64::MAX), None);
        // Exceeds max -> rejected, cursor not consumed.
        assert_eq!(str_number(b"300", 0, 256), None);
        // Exactly max is accepted.
        assert_eq!(str_number(b"256", 0, 256), Some((256, 3)));
    }

    // ---- glob_inuse / peek_ipv6 ----------------------------------------------------------

    #[test]
    fn glob_inuse_reflects_patterns() {
        let (glob, _) = glob_url("plain", false).unwrap();
        assert!(glob_inuse(&glob));
    }

    #[test]
    fn peek_ipv6_detects_and_rejects() {
        // Recognised IPv6 literals return the full bracket span.
        assert_eq!(peek_ipv6(b"[::1]", 0), 5);
        assert_eq!(peek_ipv6(b"[2001:db8::1]x", 0), 13);
        // Glob ranges are not IPv6.
        assert_eq!(peek_ipv6(b"[1-10]", 0), 0);
        assert_eq!(peek_ipv6(b"[a-z]", 0), 0);
        // No closing bracket.
        assert_eq!(peek_ipv6(b"[::1", 0), 0);
    }

    // ---- pattern metadata ----------------------------------------------------------------

    #[test]
    fn pattern_types_and_globindex() {
        let (glob, _) = glob_url("lit{a,b}[1-2]", false).unwrap();
        assert_eq!(glob.patterns.len(), 3);
        // Fixed literal: Set type, globindex -1.
        assert_eq!(glob.patterns[0].ptype, GlobPatternType::Set);
        assert_eq!(glob.patterns[0].globindex, -1);
        // First actual glob (the set): globindex 0.
        assert_eq!(glob.patterns[1].ptype, GlobPatternType::Set);
        assert_eq!(glob.patterns[1].globindex, 0);
        // Second actual glob (the range): globindex 1.
        assert_eq!(glob.patterns[2].ptype, GlobPatternType::Range);
        assert_eq!(glob.patterns[2].globindex, 1);
    }
}
