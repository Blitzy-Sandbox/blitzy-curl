//! curl's own `fnmatch`-style wildcard matcher — a byte-for-byte Rust rewrite of
//! libcurl's `lib/curl_fnmatch.c` / `lib/curl_fnmatch.h`.
//!
//! # Purpose
//!
//! This matcher backs curl's **FTP wildcard transfer** feature
//! (`CURLOPT_WILDCARDMATCH`, e.g. `ftp://host/path/*.txt`). The connection /
//! protocol layer ([`crate::protocols::ftp`]) selects which remote files to
//! transfer by matching each server-listed filename against the user's glob
//! pattern with [`curl_fnmatch`].
//!
//! # Parity requirement (why this is hand-written, not a `glob` crate)
//!
//! curl ships its *own* recursive, backtracking matcher whose semantics differ
//! from POSIX `fnmatch(3)` and from general-purpose Rust glob crates
//! (`glob`, `globset`). The FTP wildcard tests in `tests/data` (and the unit
//! test `tests/unit/unit1307.c`) depend on curl's exact match / no-match
//! outcomes — including its handling of malformed bracket expressions and the
//! bounded `*` backtracking depth. This module therefore reproduces the C
//! `loop()` / `setcharset()` / `parsekeyword()` control flow exactly, rather
//! than delegating to a third-party matcher. Do **not** swap in a generic glob
//! crate: their semantics are subtly different and would break test parity.
//!
//! The behavioral oracle is the `#ifndef HAVE_FNMATCH` branch of
//! `lib/curl_fnmatch.c` — curl's portable, deterministic custom matcher (the
//! one curl controls and ships). The alternative `HAVE_FNMATCH` branch merely
//! delegates to the platform `fnmatch(3)`, whose results are *not* part of
//! curl's own contract.
//!
//! # Result of malformed patterns: `NoMatch`, not `Fail`
//!
//! A subtle but important parity point: curl's native matcher returns
//! [`FnMatch::NoMatch`] for a **malformed** bracket expression (an unterminated
//! `[`, or an unknown `[:class:]`), *not* [`FnMatch::Fail`]. The only path that
//! yields `Fail` in the C `Curl_fnmatch()` is a `NULL` `pattern` or `string`
//! pointer. This is confirmed by curl's own unit test `unit1307.c`, whose
//! `SYSTEM_CUSTOM` expectations (the custom matcher, which is what we
//! reimplement) require, for example:
//!
//! - `Curl_fnmatch("[",        "[")   == NOMATCH`   (unterminated set)
//! - `Curl_fnmatch("[]",       "[]")  == NOMATCH`   (unterminated set)
//! - `Curl_fnmatch("[[:foo:]]","bar") == NOMATCH`   (unknown class)
//! - `Curl_fnmatch("[[:foo:]]","f]")  == MATCH`     (unknown class, falls back
//!   to literal parsing)
//!
//! The `FAIL` outcomes seen in `unit1307.c` belong exclusively to the
//! `MAC_*`/BSD `fnmatch(3)` column — never to curl's custom matcher. Because
//! the safe Rust entry point takes `&[u8]` slices (which cannot be null), the
//! `NULL -> Fail` path is unreachable here; [`curl_fnmatch`] returns only
//! [`FnMatch::Match`] or [`FnMatch::NoMatch`]. The [`FnMatch::Fail`] variant is
//! retained for result-code completeness so the FFI layer can map a `NULL` C
//! pointer to it, preserving the `CURL_FNMATCH_FAIL` ABI value.
//!
//! # Bytes, not text
//!
//! curl matches *bytes*: FTP filenames are not guaranteed to be valid UTF-8, so
//! the matcher operates on `&[u8]`. The C implementation walks NUL-terminated
//! C strings; this rewrite models "end of input" as reading a `0` byte past the
//! end of a slice (see [`byte_at`]). FTP filenames are C strings in practice and
//! contain no interior NUL, so treating a `0` byte as end-of-input is faithful.
//!
//! # Safety
//!
//! This module contains **zero `unsafe`** and compiles cleanly under the
//! crate-wide `#![forbid(unsafe_code)]` mandate (AAP §0.7.1). All buffer access
//! is bounds-checked via slice indexing and the [`byte_at`] helper.

/// libcurl `CURL_FNMATCH_*` result codes (integer ABI values).
///
/// These mirror the constants in `include`-visible `lib/curl_fnmatch.h` and are
/// the exact integers the FFI layer and the `curl_fnmatch_callback` contract
/// expect. They are kept in sync with [`FnMatch`] via its `#[repr(i32)]`.
pub mod codes {
    /// The string matched the pattern.
    pub const CURL_FNMATCH_MATCH: i32 = 0;
    /// The string did not match the pattern (this also covers malformed
    /// patterns under curl's native matcher).
    pub const CURL_FNMATCH_NOMATCH: i32 = 1;
    /// An error occurred (e.g. a `NULL` argument at the C ABI boundary).
    pub const CURL_FNMATCH_FAIL: i32 = 2;
}

/// Outcome of matching a string against a pattern with [`curl_fnmatch`].
///
/// The discriminants are pinned to curl's `CURL_FNMATCH_*` integer values via
/// `#[repr(i32)]`, so `FnMatch as i32` yields the exact ABI code and the FFI
/// crate can return it directly from the C `Curl_fnmatch` shim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum FnMatch {
    /// The string matched the pattern (`CURL_FNMATCH_MATCH`, `0`).
    Match = codes::CURL_FNMATCH_MATCH,
    /// The string did not match the pattern (`CURL_FNMATCH_NOMATCH`, `1`).
    ///
    /// Under curl's native matcher this also covers malformed patterns, e.g. an
    /// unterminated `[` or an unknown `[:class:]`.
    NoMatch = codes::CURL_FNMATCH_NOMATCH,
    /// An error occurred (`CURL_FNMATCH_FAIL`, `2`).
    ///
    /// The safe `&[u8]` entry point never returns this; it exists so the FFI
    /// boundary can map a `NULL` `pattern`/`string` pointer to the correct ABI
    /// code, exactly as the C `Curl_fnmatch()` does.
    Fail = codes::CURL_FNMATCH_FAIL,
}

impl FnMatch {
    /// Returns the integer `CURL_FNMATCH_*` ABI code for this outcome.
    #[inline]
    #[must_use]
    pub const fn as_code(self) -> i32 {
        self as i32
    }

    /// Builds a [`FnMatch`] from a `CURL_FNMATCH_*` integer code.
    ///
    /// `0` -> [`FnMatch::Match`], `1` -> [`FnMatch::NoMatch`], and any other
    /// value (including `2`) -> [`FnMatch::Fail`]. Mapping unknown codes to
    /// `Fail` keeps the conversion total without inventing a spurious match.
    #[inline]
    #[must_use]
    pub const fn from_code(code: i32) -> Self {
        match code {
            codes::CURL_FNMATCH_MATCH => FnMatch::Match,
            codes::CURL_FNMATCH_NOMATCH => FnMatch::NoMatch,
            _ => FnMatch::Fail,
        }
    }
}

impl From<FnMatch> for i32 {
    #[inline]
    fn from(value: FnMatch) -> Self {
        value.as_code()
    }
}

// ===========================================================================
// Internal constants — mirror the `CURLFNM_*` macros in lib/curl_fnmatch.c.
//
// The character-set buffer is a single fixed array. Indices 0..256 record
// per-byte membership; indices 256..267 are pseudo-entries used as boolean
// flags (negation + the ten POSIX character classes). The original C buffer is
// `CURLFNM_CHSET_SIZE = 256 + 15` bytes; only the first +10 flag slots are
// used, the rest are slack carried over verbatim for fidelity.
// ===========================================================================

/// Number of distinct byte values (`CURLFNM_CHARSET_LEN`).
const CURLFNM_CHARSET_LEN: usize = 256;
/// Total size of the membership buffer (`CURLFNM_CHSET_SIZE`).
const CURLFNM_CHSET_SIZE: usize = CURLFNM_CHARSET_LEN + 15;

/// Flag slot: the set is negated (`[!...]` / `[^...]`).
const CURLFNM_NEGATE: usize = CURLFNM_CHARSET_LEN;

/// Flag slot: `[:alnum:]`.
const CURLFNM_ALNUM: usize = CURLFNM_CHARSET_LEN + 1;
/// Flag slot: `[:digit:]`.
const CURLFNM_DIGIT: usize = CURLFNM_CHARSET_LEN + 2;
/// Flag slot: `[:xdigit:]`.
const CURLFNM_XDIGIT: usize = CURLFNM_CHARSET_LEN + 3;
/// Flag slot: `[:alpha:]`.
const CURLFNM_ALPHA: usize = CURLFNM_CHARSET_LEN + 4;
/// Flag slot: `[:print:]`.
const CURLFNM_PRINT: usize = CURLFNM_CHARSET_LEN + 5;
/// Flag slot: `[:blank:]`.
const CURLFNM_BLANK: usize = CURLFNM_CHARSET_LEN + 6;
/// Flag slot: `[:lower:]`.
const CURLFNM_LOWER: usize = CURLFNM_CHARSET_LEN + 7;
/// Flag slot: `[:graph:]`.
const CURLFNM_GRAPH: usize = CURLFNM_CHARSET_LEN + 8;
/// Flag slot: `[:space:]`.
const CURLFNM_SPACE: usize = CURLFNM_CHARSET_LEN + 9;
/// Flag slot: `[:upper:]`.
const CURLFNM_UPPER: usize = CURLFNM_CHARSET_LEN + 10;

// ===========================================================================
// Byte classification — byte-for-byte equivalents of the macros in
// lib/curl_ctype.h. curl's ctype is ASCII-only and locale-independent, so the
// `u8::is_ascii_*` helpers match exactly where used; `is_print` / `is_graph` /
// `is_blank` are defined explicitly because curl's definitions differ from the
// Rust standard library (notably, curl's PRINT/GRAPH also include the low
// control range 0x09..=0x0d).
// ===========================================================================

/// `ISLOWER` — ASCII lowercase `a..=z`.
#[inline]
fn is_lower(c: u8) -> bool {
    c.is_ascii_lowercase()
}

/// `ISUPPER` — ASCII uppercase `A..=Z`.
#[inline]
fn is_upper(c: u8) -> bool {
    c.is_ascii_uppercase()
}

/// `ISDIGIT` — ASCII decimal digit `0..=9`.
#[inline]
fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

/// `ISALPHA` — ASCII letter (`a..=z` or `A..=Z`).
#[inline]
fn is_alpha(c: u8) -> bool {
    c.is_ascii_alphabetic()
}

/// `ISALNUM` — ASCII letter or digit.
#[inline]
fn is_alnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

/// `ISXDIGIT` — ASCII hexadecimal digit (`0..=9`, `a..=f`, `A..=F`).
#[inline]
fn is_xdigit(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

/// `ISLOWPRINT` — curl's low "printable" control range `0x09..=0x0d`
/// (`\t \n \v \f \r`).
#[inline]
fn is_lowprint(c: u8) -> bool {
    (0x09..=0x0d).contains(&c)
}

/// `ISPRINT` — curl's printable test: the low control range `0x09..=0x0d` or
/// the ASCII printable range `0x20..=0x7e` (space through `~`).
#[inline]
fn is_print(c: u8) -> bool {
    is_lowprint(c) || (b' '..=b'~').contains(&c)
}

/// `ISGRAPH` — curl's graph test: the low control range `0x09..=0x0d` or the
/// ASCII graphic range `0x21..=0x7e` (`!` through `~`, i.e. printable minus
/// space). `u8::is_ascii_graphic` is exactly `0x21..=0x7e`.
#[inline]
fn is_graph(c: u8) -> bool {
    is_lowprint(c) || c.is_ascii_graphic()
}

/// `ISBLANK` — space or horizontal tab only.
#[inline]
fn is_blank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// Reads the byte at `idx`, returning `0` when `idx` is at or past the end.
///
/// This models C NUL-terminated string semantics over a `&[u8]`: the original
/// matcher walks until it reads the terminating `0`, and this helper reproduces
/// that "read past the end yields `0`" behavior without any bounds-check panic.
#[inline]
fn byte_at(buf: &[u8], idx: usize) -> u8 {
    buf.get(idx).copied().unwrap_or(0)
}

/// Coarse character class used when expanding a `a-z`-style range, mirroring
/// the C `char_class` enum. A range only includes bytes whose class matches the
/// class of its start byte, which is why e.g. `[A-z]` matches only `A..=Z`
/// (the lowercase letters in the numeric span `A..z` are a different class and
/// are skipped).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CharClass {
    /// Not a letter or digit.
    Other,
    /// ASCII decimal digit.
    Digit,
    /// ASCII uppercase letter.
    Upper,
    /// ASCII lowercase letter.
    Lower,
}

/// Returns the [`CharClass`] of a byte, mirroring the C `charclass()` helper
/// (upper, then lower, then digit, else other).
#[inline]
fn charclass(c: u8) -> CharClass {
    if is_upper(c) {
        CharClass::Upper
    } else if is_lower(c) {
        CharClass::Lower
    } else if is_digit(c) {
        CharClass::Digit
    } else {
        CharClass::Other
    }
}

// `SETCHARSET_OK` / `SETCHARSET_FAIL` are represented as a `bool` (`true` ==
// OK) throughout, matching the C functions' `1`/`0` return convention.

/// Parses a POSIX character-class keyword of the form `name:]` (the caller has
/// already consumed the leading `[:`), setting the corresponding class flag in
/// `charset`.
///
/// `pidx` points just past the `[:` (at the first keyword byte) on entry; on
/// success it is advanced past the closing `]` and `true` is returned. On any
/// malformation — a non-lowercase byte, an over-long keyword (the C buffer is
/// 10 bytes), reaching end-of-input, or an unknown class name — the pattern
/// cursor is left untouched and `false` is returned. This is a faithful port of
/// the C `parsekeyword()` state machine.
fn parsekeyword(pat: &[u8], pidx: &mut usize, charset: &mut [bool; CURLFNM_CHSET_SIZE]) -> bool {
    // Mirrors `parsekey_state` in the C source.
    enum State {
        Init,
        Ddot,
    }

    let mut state = State::Init;
    // The C buffer is `char keyword[10]`; the over-long guard fires at i == 10.
    let mut keyword = [0u8; 10];
    let mut p = *pidx;
    let mut found = false;
    let mut i = 0usize;

    while !found {
        let c = byte_at(pat, p);
        p += 1;
        // The C code checks `i >= sizeof(keyword)` *after* reading the byte but
        // *before* dispatching on it, so reproduce that ordering exactly.
        if i >= keyword.len() {
            return false;
        }
        match state {
            State::Init => {
                if is_lower(c) {
                    keyword[i] = c;
                } else if c == b':' {
                    state = State::Ddot;
                } else {
                    return false;
                }
            }
            State::Ddot => {
                if c == b']' {
                    found = true;
                } else {
                    return false;
                }
            }
        }
        i += 1;
    }

    // Move the caller's pattern cursor past the closing `]`.
    *pidx = p;

    // The keyword consists of the lowercase bytes written above, terminated by
    // the first 0 (the `:`/`]` slots were never written). Compare against the
    // known class names exactly as the C `strcmp` chain does.
    let end = keyword
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(keyword.len());
    let kw = &keyword[..end];

    let flag = match kw {
        b"digit" => CURLFNM_DIGIT,
        b"alnum" => CURLFNM_ALNUM,
        b"alpha" => CURLFNM_ALPHA,
        b"xdigit" => CURLFNM_XDIGIT,
        b"print" => CURLFNM_PRINT,
        b"graph" => CURLFNM_GRAPH,
        b"space" => CURLFNM_SPACE,
        b"blank" => CURLFNM_BLANK,
        b"upper" => CURLFNM_UPPER,
        b"lower" => CURLFNM_LOWER,
        _ => return false,
    };
    charset[flag] = true;
    true
}

/// Adds a single byte — or an `a-z`-style range — to `charset`, advancing the
/// pattern cursor `pp`. Faithful port of the C `setcharorrange()`.
///
/// On entry `pp` points at the first byte of the item. The first byte is always
/// added as a literal. If that byte is alphanumeric and is immediately followed
/// by `-`, a range is attempted: the end byte is read (honoring a single
/// `\`-escape), and if it is `>=` the start byte and of the *same* class, every
/// in-class byte in the span is added. Only on a successful range is the extra
/// span consumed from `pp`; otherwise just the single literal byte is consumed,
/// exactly as the C pointer bookkeeping dictates.
fn setcharorrange(pat: &[u8], pp: &mut usize, charset: &mut [bool; CURLFNM_CHSET_SIZE]) {
    // `p = (*pp)++` then `c = *p++`: both the caller cursor and the local cursor
    // advance past the first byte, which is recorded as a literal member.
    let mut p = *pp;
    *pp += 1;
    let c = byte_at(pat, p);
    p += 1;
    charset[c as usize] = true;

    if is_alnum(c) {
        // C: `*p++ == '-'` — read the next byte and advance regardless of match
        // (the short-circuit only skips this when `c` is not alphanumeric).
        let dash = byte_at(pat, p);
        p += 1;
        if dash == b'-' {
            let cc = charclass(c);
            let mut endrange = byte_at(pat, p);
            p += 1;
            if endrange == b'\\' {
                endrange = byte_at(pat, p);
                p += 1;
            }
            if endrange >= c && charclass(endrange) == cc {
                // Reproduce `while(c++ != endrange) if(charclass(c)==cc) ...`:
                // the comparison uses the pre-increment value while the body
                // sees the post-increment value.
                let mut cur = c;
                loop {
                    let prev = cur;
                    cur = cur.wrapping_add(1);
                    if prev == endrange {
                        break;
                    }
                    if charclass(cur) == cc {
                        charset[cur as usize] = true;
                    }
                }
                // Only a successful range consumes the trailing span.
                *pp = p;
            }
        }
    }
}

/// Parses a bracket expression `[...]` into `charset`, advancing the pattern
/// cursor `p` to the closing `]`. Returns `true` (`SETCHARSET_OK`) on a
/// well-formed set and `false` (`SETCHARSET_FAIL`) on a malformed one (e.g. an
/// unterminated `[`). Faithful port of the C `setcharset()` state machine.
///
/// On entry `p` points just past the opening `[`. The buffer is fully reset
/// first (the C `memset`), then bytes are consumed honoring: a leading `]`
/// taken as a literal member; `[:class:]` keyword handling; `!`/`^` negation
/// (the first such byte negates the set, a subsequent one is literal); `\`
/// escaping; and plain bytes / ranges via [`setcharorrange`].
fn setcharset(pat: &[u8], p: &mut usize, charset: &mut [bool; CURLFNM_CHSET_SIZE]) -> bool {
    // Mirrors `setcharset_state` in the C source.
    enum State {
        Default,
        RightBr,
        RightBrLeftBr,
    }

    let mut state = State::Default;
    let mut something_found = false;

    // C: `memset(charset, 0, CURLFNM_CHSET_SIZE)`.
    charset.fill(false);

    loop {
        let c = byte_at(pat, *p);
        if c == 0 {
            // Unterminated set => SETCHARSET_FAIL.
            return false;
        }

        match state {
            State::Default => {
                if c == b']' {
                    if something_found {
                        return true;
                    }
                    // A `]` in the first position is a literal member.
                    something_found = true;
                    state = State::RightBr;
                    charset[c as usize] = true;
                    *p += 1;
                } else if c == b'[' {
                    // Possible `[:class:]`. `pp` points at the byte after `[`;
                    // the C code reads it (checking for `:`) and advances.
                    let mut pp = *p + 1;
                    let after = byte_at(pat, pp);
                    pp += 1;
                    if after == b':' && parsekeyword(pat, &mut pp, charset) {
                        *p = pp;
                    } else {
                        // Not a class: `[` is a literal member.
                        charset[c as usize] = true;
                        *p += 1;
                    }
                    something_found = true;
                } else if c == b'^' || c == b'!' {
                    if !something_found {
                        if charset[CURLFNM_NEGATE] {
                            // Already negated: this one is a literal member.
                            charset[c as usize] = true;
                            something_found = true;
                        } else {
                            charset[CURLFNM_NEGATE] = true;
                        }
                    } else {
                        charset[c as usize] = true;
                    }
                    *p += 1;
                } else if c == b'\\' {
                    // C: `c = *(++(*p))` — advance past the backslash, then read
                    // the escaped byte.
                    *p += 1;
                    let escaped = byte_at(pat, *p);
                    if escaped != 0 {
                        setcharorrange(pat, p, charset);
                    } else {
                        // Trailing backslash: record `\` literally. The next
                        // loop iteration reads the terminating 0 and fails,
                        // matching curl (a lone trailing `\` is unterminated).
                        charset[b'\\' as usize] = true;
                    }
                    something_found = true;
                } else {
                    setcharorrange(pat, p, charset);
                    something_found = true;
                }
            }
            State::RightBr => {
                if c == b'[' {
                    state = State::RightBrLeftBr;
                    charset[c as usize] = true;
                    *p += 1;
                } else if c == b']' {
                    return true;
                } else if is_print(c) {
                    charset[c as usize] = true;
                    *p += 1;
                    state = State::Default;
                } else {
                    // Non-printable after a literal `]`: malformed.
                    return false;
                }
            }
            State::RightBrLeftBr => {
                if c == b']' {
                    return true;
                }
                state = State::Default;
                charset[c as usize] = true;
                *p += 1;
            }
        }
    }
}

/// The recursive, backtracking matcher — a faithful port of the C `loop()`.
///
/// Matches `string[si..]` against `pattern[pi..]`. `maxstars` bounds the depth
/// of `*` backtracking recursion (the top-level call uses `2`, exactly as
/// curl). This bound is a genuine semantic feature, not just a guard: patterns
/// that would require deeper star recursion than `maxstars` allows yield
/// [`codes::CURL_FNMATCH_NOMATCH`] even if a "perfect" glob matcher would match.
/// Reproducing it is required for byte-for-byte parity.
///
/// Returns one of the [`codes`] integer values.
fn fnmatch_loop(pattern: &[u8], string: &[u8], pi: usize, si: usize, maxstars: i32) -> i32 {
    let mut p = pi;
    let mut s = si;
    // One reusable set buffer per invocation, matching the C stack array.
    let mut charset = [false; CURLFNM_CHSET_SIZE];

    loop {
        match byte_at(pattern, p) {
            b'*' => {
                if maxstars == 0 {
                    return codes::CURL_FNMATCH_NOMATCH;
                }
                // Regroup consecutive `*` and `?`: `*?*?*` is equivalent to
                // `??*`. Each `?` consumes one string byte; if the pattern ends
                // while regrouping, a trailing `*` matches the remainder.
                loop {
                    p += 1;
                    let pc = byte_at(pattern, p);
                    if pc == 0 {
                        return codes::CURL_FNMATCH_MATCH;
                    }
                    if pc == b'?' {
                        if byte_at(string, s) == 0 {
                            return codes::CURL_FNMATCH_NOMATCH;
                        }
                        s += 1;
                    } else if pc != b'*' {
                        break;
                    }
                }
                // Try to match the pattern suffix at each remaining string
                // position, recursing with one fewer available star.
                let next_maxstars = maxstars - 1;
                while byte_at(string, s) != 0 {
                    if fnmatch_loop(pattern, string, p, s, next_maxstars)
                        == codes::CURL_FNMATCH_MATCH
                    {
                        return codes::CURL_FNMATCH_MATCH;
                    }
                    s += 1;
                }
                return codes::CURL_FNMATCH_NOMATCH;
            }
            b'?' => {
                if byte_at(string, s) == 0 {
                    return codes::CURL_FNMATCH_NOMATCH;
                }
                s += 1;
                p += 1;
            }
            0 => {
                // End of pattern: match iff the string is also exhausted.
                return if byte_at(string, s) != 0 {
                    codes::CURL_FNMATCH_NOMATCH
                } else {
                    codes::CURL_FNMATCH_MATCH
                };
            }
            b'\\' => {
                // Escaped literal: if a byte follows the backslash, match it;
                // otherwise the backslash itself is the literal (trailing `\`).
                if byte_at(pattern, p + 1) != 0 {
                    p += 1;
                }
                let pc = byte_at(pattern, p);
                let sc = byte_at(string, s);
                s += 1;
                p += 1;
                if sc != pc {
                    return codes::CURL_FNMATCH_NOMATCH;
                }
            }
            b'[' => {
                // Parse the set from a *copy* of the cursor so a malformed set
                // leaves `p` untouched for the fallthrough (mismatch) path.
                let mut pp = p + 1;
                if setcharset(pattern, &mut pp, &mut charset) {
                    let sc = byte_at(string, s);
                    if sc == 0 {
                        return codes::CURL_FNMATCH_NOMATCH;
                    }
                    // Membership: a direct byte hit wins; otherwise the FIRST
                    // set POSIX class (in this exact priority order) is tested.
                    // NOTE the curl quirk: the SPACE class is tested with
                    // `is_blank`, identical to BLANK — not a general whitespace
                    // test. This ordering and the SPACE->blank mapping are
                    // load-bearing for parity.
                    let mut found = if charset[sc as usize] {
                        true
                    } else if charset[CURLFNM_ALNUM] {
                        is_alnum(sc)
                    } else if charset[CURLFNM_ALPHA] {
                        is_alpha(sc)
                    } else if charset[CURLFNM_DIGIT] {
                        is_digit(sc)
                    } else if charset[CURLFNM_XDIGIT] {
                        is_xdigit(sc)
                    } else if charset[CURLFNM_PRINT] {
                        is_print(sc)
                    } else if charset[CURLFNM_SPACE] {
                        is_blank(sc)
                    } else if charset[CURLFNM_UPPER] {
                        is_upper(sc)
                    } else if charset[CURLFNM_LOWER] {
                        is_lower(sc)
                    } else if charset[CURLFNM_BLANK] {
                        is_blank(sc)
                    } else if charset[CURLFNM_GRAPH] {
                        is_graph(sc)
                    } else {
                        false
                    };

                    if charset[CURLFNM_NEGATE] {
                        found = !found;
                    }

                    if !found {
                        return codes::CURL_FNMATCH_NOMATCH;
                    }
                    // Advance the real cursor past the closing `]` and consume
                    // the matched string byte.
                    p = pp + 1;
                    s += 1;
                } else {
                    // Malformed set: curl's native matcher treats this as a
                    // mismatch (NOT a failure). See the module-level docs.
                    return codes::CURL_FNMATCH_NOMATCH;
                }
            }
            _ => {
                // Ordinary literal byte: must match exactly.
                let pc = byte_at(pattern, p);
                let sc = byte_at(string, s);
                p += 1;
                s += 1;
                if pc != sc {
                    return codes::CURL_FNMATCH_NOMATCH;
                }
            }
        }
    }
}

/// Matches `string` against the wildcard `pattern`, returning curl's match
/// outcome.
///
/// This is the Rust counterpart of curl's
/// `int Curl_fnmatch(void *ptr, const char *pattern, const char *string)`. The
/// unused `ptr` context argument from the C callback prototype is dropped.
///
/// Supported pattern syntax (curl's own, *not* POSIX `fnmatch`):
///
/// - `*` — matches any run of bytes, including empty (with curl's bounded
///   backtracking; see [`fnmatch_loop`]).
/// - `?` — matches exactly one byte.
/// - `[...]` — a character set: ranges (`a-z`), negation (`[!...]` / `[^...]`),
///   literal `]`/`-` per position rules, and POSIX classes
///   (`[:alnum:]`, `[:digit:]`, `[:xdigit:]`, `[:alpha:]`, `[:print:]`,
///   `[:blank:]`, `[:lower:]`, `[:graph:]`, `[:space:]`, `[:upper:]`).
/// - `\` — escapes the following metacharacter to match it literally.
///
/// Matching is performed on raw bytes (FTP filenames are not guaranteed UTF-8).
/// A malformed pattern (e.g. an unterminated `[`) yields [`FnMatch::NoMatch`],
/// matching curl's native matcher; this entry point never returns
/// [`FnMatch::Fail`] (that code is reserved for the `NULL`-pointer case at the
/// C ABI boundary, which a `&[u8]` cannot express).
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::util::fnmatch::{curl_fnmatch, FnMatch};
/// assert_eq!(curl_fnmatch(b"*.txt", b"file.txt"), FnMatch::Match);
/// assert_eq!(curl_fnmatch(b"*.txt", b"file.dat"), FnMatch::NoMatch);
/// assert_eq!(curl_fnmatch(b"a?c", b"abc"), FnMatch::Match);
/// assert_eq!(curl_fnmatch(b"[a-c]", b"b"), FnMatch::Match);
/// assert_eq!(curl_fnmatch(b"[!a-c]", b"d"), FnMatch::Match);
/// assert_eq!(curl_fnmatch(br"\*", b"*"), FnMatch::Match);
/// ```
#[must_use]
pub fn curl_fnmatch(pattern: &[u8], string: &[u8]) -> FnMatch {
    // The C `Curl_fnmatch` returns CURL_FNMATCH_FAIL for a NULL pattern/string;
    // `&[u8]` slices are never null, so that path is unreachable here and the
    // top-level recursion is entered directly with maxstars = 2.
    FnMatch::from_code(fnmatch_loop(pattern, string, 0, 0, 2))
}

// ===========================================================================
// Tests
//
// The authoritative parity gate is `parity_unit1307_full_table`, which ports
// ALL 157 cases from curl's own unit test `tests/unit/unit1307.c` using the
// `SYSTEM_CUSTOM` expected outcomes (`tests[i].result & 0x03` — the value the
// custom matcher, which this module reimplements, must produce). The byte
// content of every pattern/string was decoded by the C compiler from the
// upstream literals, so the inputs are byte-identical to curl's.
//
// The remaining tests are explicit, human-readable checks of the headline
// behaviors (including the points the task prompt calls out) plus several
// curl-specific quirks. Every expected value below was cross-checked against a
// C reference compiled directly from `lib/curl_fnmatch.c`'s custom matcher.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[inline]
    fn run(pattern: &[u8], string: &[u8]) -> FnMatch {
        curl_fnmatch(pattern, string)
    }

    /// The `CURL_FNMATCH_*` ABI integers and the `FnMatch` <-> i32 conversions
    /// must stay pinned to curl's values.
    #[test]
    fn result_code_abi_values() {
        assert_eq!(codes::CURL_FNMATCH_MATCH, 0);
        assert_eq!(codes::CURL_FNMATCH_NOMATCH, 1);
        assert_eq!(codes::CURL_FNMATCH_FAIL, 2);

        assert_eq!(FnMatch::Match as i32, 0);
        assert_eq!(FnMatch::NoMatch as i32, 1);
        assert_eq!(FnMatch::Fail as i32, 2);

        assert_eq!(FnMatch::Match.as_code(), 0);
        assert_eq!(FnMatch::NoMatch.as_code(), 1);
        assert_eq!(FnMatch::Fail.as_code(), 2);

        assert_eq!(FnMatch::from_code(0), FnMatch::Match);
        assert_eq!(FnMatch::from_code(1), FnMatch::NoMatch);
        assert_eq!(FnMatch::from_code(2), FnMatch::Fail);
        // Any out-of-range code maps to Fail (total, never a spurious match).
        assert_eq!(FnMatch::from_code(-1), FnMatch::Fail);
        assert_eq!(FnMatch::from_code(99999), FnMatch::Fail);

        assert_eq!(i32::from(FnMatch::Match), 0);
        assert_eq!(i32::from(FnMatch::NoMatch), 1);
        assert_eq!(i32::from(FnMatch::Fail), 2);
    }

    /// Prompt PHASE 4 — basic `*` / `?`.
    #[test]
    fn basic_star_and_question() {
        assert_eq!(run(b"*.txt", b"file.txt"), FnMatch::Match);
        assert_eq!(run(b"*.txt", b"file.dat"), FnMatch::NoMatch);
        assert_eq!(run(b"a?c", b"abc"), FnMatch::Match);
        assert_eq!(run(b"a?c", b"ac"), FnMatch::NoMatch);
        assert_eq!(run(b"a?c", b"abbc"), FnMatch::NoMatch);
    }

    /// Prompt PHASE 4 — character sets, ranges, negation, POSIX classes.
    #[test]
    fn charsets_ranges_negation_classes() {
        assert_eq!(run(b"[a-c]", b"b"), FnMatch::Match);
        assert_eq!(run(b"[a-c]", b"d"), FnMatch::NoMatch);
        assert_eq!(run(b"[!a-c]", b"d"), FnMatch::Match);
        assert_eq!(run(b"[!a-c]", b"b"), FnMatch::NoMatch);
        assert_eq!(run(b"[^a-c]", b"d"), FnMatch::Match);
        assert_eq!(run(b"[^a-c]", b"b"), FnMatch::NoMatch);
        assert_eq!(run(b"[[:digit:]]", b"5"), FnMatch::Match);
        assert_eq!(run(b"[[:digit:]]", b"x"), FnMatch::NoMatch);
    }

    /// Prompt PHASE 4 — backslash escaping of metacharacters.
    #[test]
    fn escaping_metacharacters() {
        assert_eq!(run(b"\\*", b"*"), FnMatch::Match);
        assert_eq!(run(b"\\*", b"x"), FnMatch::NoMatch);
        assert_eq!(run(b"\\?", b"?"), FnMatch::Match);
        assert_eq!(run(b"\\[", b"["), FnMatch::Match);
        // An escaped backslash matches a single literal backslash.
        assert_eq!(run(b"\\\\", b"\\"), FnMatch::Match);
    }

    /// Prompt PHASE 4 — malformed patterns.
    ///
    /// IMPORTANT PARITY NOTE: the task prompt's prose states malformed patterns
    /// return `Fail`. That describes the BSD/macOS `fnmatch(3)` path, NOT curl's
    /// own custom matcher. curl's native matcher (the `#ifndef HAVE_FNMATCH`
    /// branch of `lib/curl_fnmatch.c`) and its unit test `unit1307.c` return
    /// `NOMATCH` for malformed sets — confirmed against a C reference built from
    /// the actual source. The safe `&[u8]` entry point therefore never returns
    /// `Fail` (that code is reserved for the NULL-pointer case at the FFI edge).
    #[test]
    fn malformed_returns_nomatch_not_fail() {
        assert_eq!(run(b"[abc", b"abc"), FnMatch::NoMatch); // unterminated '['
        assert_eq!(run(b"[", b"["), FnMatch::NoMatch);
        assert_eq!(run(b"[]", b"[]"), FnMatch::NoMatch);
        assert_eq!(run(b"[[:bogus:]]", b"x"), FnMatch::NoMatch); // unknown class
        assert_eq!(run(b"[[:bogus:]]", b"f]"), FnMatch::NoMatch);
        // Unknown class falls back to literal parsing: its letters become set
        // members, so a string built from them still matches.
        assert_eq!(run(b"[[:bogus:]]", b"b]"), FnMatch::Match);
        assert_ne!(run(b"[abc", b"abc"), FnMatch::Fail);
        assert_ne!(run(b"[[:bogus:]]", b"x"), FnMatch::Fail);
    }

    /// curl quirk: the `[:space:]` class is matched with `is_blank` (space/tab
    /// only), NOT a general-whitespace test, so CR/LF do not match.
    #[test]
    fn space_class_uses_blank_semantics() {
        assert_eq!(run(b"[[:space:]]", b" "), FnMatch::Match);
        assert_eq!(run(b"[[:space:]]", b"\t"), FnMatch::Match);
        assert_eq!(run(b"[[:space:]]", b"\r"), FnMatch::NoMatch);
        assert_eq!(run(b"[[:space:]]", b"\n"), FnMatch::NoMatch);
    }

    /// curl quirk: a range whose end byte is a different character class than
    /// its start is rejected wholesale, leaving the start, `-`, and end as
    /// literal members. Hence `[A-z]` is exactly the set `{ 'A', '-', 'z' }`.
    #[test]
    fn cross_class_range_collapses_to_literals() {
        for ch in [b'A', b'z', b'-'] {
            assert_eq!(run(b"[A-z]", &[ch]), FnMatch::Match, "byte {ch:#04x}");
        }
        for ch in [b'Q', b'a', b'_', b'm', b'M'] {
            assert_eq!(run(b"[A-z]", &[ch]), FnMatch::NoMatch, "byte {ch:#04x}");
        }
    }

    /// curl quirk: `*` backtracking is bounded by `maxstars = 2`. Patterns that
    /// would require deeper star recursion do NOT match, even where a "perfect"
    /// glob matcher would. Verified against the C reference.
    #[test]
    fn maxstars_bounded_backtracking() {
        // Up to two independent star-groups resolve normally.
        assert_eq!(run(b"*a*b", b"axb"), FnMatch::Match);
        assert_eq!(run(b"*curl*", b"lets use curl!!"), FnMatch::Match);
        // Three independent star-groups exceed the bound -> NOMATCH.
        assert_eq!(run(b"*a*b*c", b"axbxc"), FnMatch::NoMatch);
        assert_eq!(run(b"*a*b*c", b"aXbXc"), FnMatch::NoMatch);
        assert_eq!(run(b"*a*b*c", b"abc"), FnMatch::NoMatch);
        assert_eq!(run(b"a*b*c*d", b"abcd"), FnMatch::NoMatch);
    }

    /// The matcher operates on raw bytes; non-UTF-8 input is fine.
    #[test]
    fn matches_raw_non_utf8_bytes() {
        assert_eq!(run(b"[\xff]", b"\xff"), FnMatch::Match);
        assert_eq!(run(b"?", b"\xff"), FnMatch::Match);
        assert_eq!(run(b"\xff*", b"\xffabc"), FnMatch::Match);
        // A literal UTF-8 multibyte sequence matches itself byte-for-byte.
        assert_eq!(
            run(b"Lindm\xc3\xa4tarv", b"Lindm\xc3\xa4tarv"),
            FnMatch::Match
        );
    }

    /// Empty pattern / empty string edge cases.
    #[test]
    fn empty_pattern_and_string() {
        assert_eq!(run(b"", b""), FnMatch::Match);
        assert_eq!(run(b"", b"hello"), FnMatch::NoMatch);
        assert_eq!(run(b"*", b""), FnMatch::Match);
        assert_eq!(run(b"?", b""), FnMatch::NoMatch);
        assert_eq!(run(b"file", b""), FnMatch::NoMatch);
    }

    /// An adversarial, deeply nested but unterminated bracket run must
    /// terminate (the `maxstars` bound prevents blow-up) and report NoMatch.
    #[test]
    fn adversarial_long_unterminated_bracket_terminates() {
        let mut pattern = vec![b'*'];
        pattern.resize(401, b'['); // '*' followed by 400 '[' with no closing ']'
        let string = vec![b'a'; 64];
        assert_eq!(curl_fnmatch(&pattern, &string), FnMatch::NoMatch);
    }

    /// Full parity table ported verbatim from `tests/unit/unit1307.c`
    /// (`SYSTEM_CUSTOM` expectations). This is the primary byte-for-byte gate.
    #[rustfmt::skip]
    const UNIT1307_CASES: &[(&[u8], &[u8], FnMatch)] = &[
        (b"*[*[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[\x01\x7f[[[[[[[[[[[[[[[[[[[[[" as &[u8], b"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[" as &[u8], FnMatch::NoMatch),
        (b"\\[" as &[u8], b"[" as &[u8], FnMatch::Match),
        (b"[" as &[u8], b"[" as &[u8], FnMatch::NoMatch),
        (b"[]" as &[u8], b"[]" as &[u8], FnMatch::NoMatch),
        (b"[][]" as &[u8], b"[" as &[u8], FnMatch::Match),
        (b"[][]" as &[u8], b"]" as &[u8], FnMatch::Match),
        (b"[[]" as &[u8], b"[" as &[u8], FnMatch::Match),
        (b"[[[]" as &[u8], b"[" as &[u8], FnMatch::Match),
        (b"[[[[]" as &[u8], b"[" as &[u8], FnMatch::Match),
        (b"[[[[]" as &[u8], b"[" as &[u8], FnMatch::Match),
        (b"[][[]" as &[u8], b"]" as &[u8], FnMatch::Match),
        (b"[][[[]" as &[u8], b"[" as &[u8], FnMatch::Match),
        (b"[[]" as &[u8], b"]" as &[u8], FnMatch::NoMatch),
        (b"[a@]" as &[u8], b"a" as &[u8], FnMatch::Match),
        (b"[a-z]" as &[u8], b"a" as &[u8], FnMatch::Match),
        (b"[a-z]" as &[u8], b"A" as &[u8], FnMatch::NoMatch),
        (b"?[a-z]" as &[u8], b"?Z" as &[u8], FnMatch::NoMatch),
        (b"[A-Z]" as &[u8], b"C" as &[u8], FnMatch::Match),
        (b"[A-Z]" as &[u8], b"c" as &[u8], FnMatch::NoMatch),
        (b"[0-9]" as &[u8], b"7" as &[u8], FnMatch::Match),
        (b"[7-8]" as &[u8], b"7" as &[u8], FnMatch::Match),
        (b"[7-]" as &[u8], b"7" as &[u8], FnMatch::Match),
        (b"[7-]" as &[u8], b"-" as &[u8], FnMatch::Match),
        (b"[7-]" as &[u8], b"[" as &[u8], FnMatch::NoMatch),
        (b"[a-bA-F]" as &[u8], b"F" as &[u8], FnMatch::Match),
        (b"[a-bA-B9]" as &[u8], b"9" as &[u8], FnMatch::Match),
        (b"[a-bA-B98]" as &[u8], b"8" as &[u8], FnMatch::Match),
        (b"[a-bA-B98]" as &[u8], b"C" as &[u8], FnMatch::NoMatch),
        (b"[a-bA-Z9]" as &[u8], b"F" as &[u8], FnMatch::Match),
        (b"[a-bA-Z9]ero*" as &[u8], b"Zero chance." as &[u8], FnMatch::Match),
        (b"S[a-][x]opho*" as &[u8], b"Saxophone" as &[u8], FnMatch::Match),
        (b"S[a-][x]opho*" as &[u8], b"SaXophone" as &[u8], FnMatch::NoMatch),
        (b"S[a-][x]*.txt" as &[u8], b"S-x.txt" as &[u8], FnMatch::Match),
        (b"[\\a-\\b]" as &[u8], b"a" as &[u8], FnMatch::Match),
        (b"[\\a-\\b]" as &[u8], b"b" as &[u8], FnMatch::Match),
        (b"[?*[][?*[][?*[]" as &[u8], b"?*[" as &[u8], FnMatch::Match),
        (b"[][?*-]" as &[u8], b"]" as &[u8], FnMatch::Match),
        (b"[][?*-]" as &[u8], b"[" as &[u8], FnMatch::Match),
        (b"[][?*-]" as &[u8], b"?" as &[u8], FnMatch::Match),
        (b"[][?*-]" as &[u8], b"*" as &[u8], FnMatch::Match),
        (b"[][?*-]" as &[u8], b"-" as &[u8], FnMatch::Match),
        (b"[]?*-]" as &[u8], b"-" as &[u8], FnMatch::Match),
        (b"[\xff]" as &[u8], b"\xff" as &[u8], FnMatch::Match),
        (b"?/b/c" as &[u8], b"a/b/c" as &[u8], FnMatch::Match),
        (b"^_{}~" as &[u8], b"^_{}~" as &[u8], FnMatch::Match),
        (b"!#%+,-./01234567889" as &[u8], b"!#%+,-./01234567889" as &[u8], FnMatch::Match),
        (b"PQRSTUVWXYZ]abcdefg" as &[u8], b"PQRSTUVWXYZ]abcdefg" as &[u8], FnMatch::Match),
        (b":;=@ABCDEFGHIJKLMNO" as &[u8], b":;=@ABCDEFGHIJKLMNO" as &[u8], FnMatch::Match),
        (b"[!a]" as &[u8], b"b" as &[u8], FnMatch::Match),
        (b"[!a]" as &[u8], b"a" as &[u8], FnMatch::NoMatch),
        (b"[^a]" as &[u8], b"b" as &[u8], FnMatch::Match),
        (b"[^a]" as &[u8], b"a" as &[u8], FnMatch::NoMatch),
        (b"[^a-z0-9A-Z]" as &[u8], b"a" as &[u8], FnMatch::NoMatch),
        (b"[^a-z0-9A-Z]" as &[u8], b"-" as &[u8], FnMatch::Match),
        (b"curl[!a-z]lib" as &[u8], b"curl lib" as &[u8], FnMatch::Match),
        (b"curl[! ]lib" as &[u8], b"curl lib" as &[u8], FnMatch::NoMatch),
        (b"[! ][ ]" as &[u8], b"  " as &[u8], FnMatch::NoMatch),
        (b"[! ][ ]" as &[u8], b"a " as &[u8], FnMatch::Match),
        (b"*[^a].t?t" as &[u8], b"a.txt" as &[u8], FnMatch::NoMatch),
        (b"*[^a].t?t" as &[u8], b"ca.txt" as &[u8], FnMatch::NoMatch),
        (b"*[^a].t?t" as &[u8], b"ac.txt" as &[u8], FnMatch::Match),
        (b"*[^a]" as &[u8], b"" as &[u8], FnMatch::NoMatch),
        (b"[!\xff]" as &[u8], b"" as &[u8], FnMatch::NoMatch),
        (b"[!\xff]" as &[u8], b"\xff" as &[u8], FnMatch::NoMatch),
        (b"[!\xff]" as &[u8], b"a" as &[u8], FnMatch::Match),
        (b"[!?*[]" as &[u8], b"?" as &[u8], FnMatch::NoMatch),
        (b"[!!]" as &[u8], b"!" as &[u8], FnMatch::NoMatch),
        (b"[!!]" as &[u8], b"x" as &[u8], FnMatch::Match),
        (b"[[:alpha:]]" as &[u8], b"a" as &[u8], FnMatch::Match),
        (b"[[:alpha:]]" as &[u8], b"9" as &[u8], FnMatch::NoMatch),
        (b"[[:alnum:]]" as &[u8], b"a" as &[u8], FnMatch::Match),
        (b"[[:alnum:]]" as &[u8], b"[" as &[u8], FnMatch::NoMatch),
        (b"[[:alnum:]]" as &[u8], b"]" as &[u8], FnMatch::NoMatch),
        (b"[[:alnum:]]" as &[u8], b"9" as &[u8], FnMatch::Match),
        (b"[[:digit:]]" as &[u8], b"9" as &[u8], FnMatch::Match),
        (b"[[:xdigit:]]" as &[u8], b"9" as &[u8], FnMatch::Match),
        (b"[[:xdigit:]]" as &[u8], b"F" as &[u8], FnMatch::Match),
        (b"[[:xdigit:]]" as &[u8], b"G" as &[u8], FnMatch::NoMatch),
        (b"[[:upper:]]" as &[u8], b"U" as &[u8], FnMatch::Match),
        (b"[[:upper:]]" as &[u8], b"u" as &[u8], FnMatch::NoMatch),
        (b"[[:lower:]]" as &[u8], b"l" as &[u8], FnMatch::Match),
        (b"[[:lower:]]" as &[u8], b"L" as &[u8], FnMatch::NoMatch),
        (b"[[:print:]]" as &[u8], b"L" as &[u8], FnMatch::Match),
        (b"[[:print:]]" as &[u8], b"\x08" as &[u8], FnMatch::NoMatch),
        (b"[[:print:]]" as &[u8], b"\x08" as &[u8], FnMatch::NoMatch),
        (b"[[:space:]]" as &[u8], b" " as &[u8], FnMatch::Match),
        (b"[[:space:]]" as &[u8], b"x" as &[u8], FnMatch::NoMatch),
        (b"[[:graph:]]" as &[u8], b" " as &[u8], FnMatch::NoMatch),
        (b"[[:graph:]]" as &[u8], b"x" as &[u8], FnMatch::Match),
        (b"[[:blank:]]" as &[u8], b"\x09" as &[u8], FnMatch::Match),
        (b"[[:blank:]]" as &[u8], b" " as &[u8], FnMatch::Match),
        (b"[[:blank:]]" as &[u8], b"\x0d" as &[u8], FnMatch::NoMatch),
        (b"[^[:blank:]]" as &[u8], b"\x09" as &[u8], FnMatch::NoMatch),
        (b"[^[:print:]]" as &[u8], b"\x08" as &[u8], FnMatch::Match),
        (b"[[:lower:]][[:lower:]]" as &[u8], b"ll" as &[u8], FnMatch::Match),
        (b"[[:foo:]]" as &[u8], b"bar" as &[u8], FnMatch::NoMatch),
        (b"[[:foo:]]" as &[u8], b"f]" as &[u8], FnMatch::Match),
        (b"curl[[:blank:]];-)" as &[u8], b"curl ;-)" as &[u8], FnMatch::Match),
        (b"*[[:blank:]]*" as &[u8], b" " as &[u8], FnMatch::Match),
        (b"*[[:blank:]]*" as &[u8], b"" as &[u8], FnMatch::NoMatch),
        (b"*[[:blank:]]*" as &[u8], b"hi, im_Pavel" as &[u8], FnMatch::Match),
        (b"Filename.dat" as &[u8], b"Filename.dat" as &[u8], FnMatch::Match),
        (b"*curl*" as &[u8], b"lets use curl!!" as &[u8], FnMatch::Match),
        (b"filename.txt" as &[u8], b"filename.dat" as &[u8], FnMatch::NoMatch),
        (b"*.txt" as &[u8], b"text.txt" as &[u8], FnMatch::Match),
        (b"*.txt" as &[u8], b"a.txt" as &[u8], FnMatch::Match),
        (b"*.txt" as &[u8], b".txt" as &[u8], FnMatch::Match),
        (b"*.txt" as &[u8], b"txt" as &[u8], FnMatch::NoMatch),
        (b"??.txt" as &[u8], b"99.txt" as &[u8], FnMatch::Match),
        (b"??.txt" as &[u8], b"a99.txt" as &[u8], FnMatch::NoMatch),
        (b"?.???" as &[u8], b"a.txt" as &[u8], FnMatch::Match),
        (b"*.???" as &[u8], b"somefile.dat" as &[u8], FnMatch::Match),
        (b"*.???" as &[u8], b"photo.jpeg" as &[u8], FnMatch::NoMatch),
        (b".*" as &[u8], b".htaccess" as &[u8], FnMatch::Match),
        (b".*" as &[u8], b"." as &[u8], FnMatch::Match),
        (b".*" as &[u8], b".." as &[u8], FnMatch::Match),
        (b"**.txt" as &[u8], b"text.txt" as &[u8], FnMatch::Match),
        (b"***.txt" as &[u8], b"t.txt" as &[u8], FnMatch::Match),
        (b"****.txt" as &[u8], b".txt" as &[u8], FnMatch::Match),
        (b"" as &[u8], b"" as &[u8], FnMatch::Match),
        (b"" as &[u8], b"hello" as &[u8], FnMatch::NoMatch),
        (b"file" as &[u8], b"" as &[u8], FnMatch::NoMatch),
        (b"?" as &[u8], b"" as &[u8], FnMatch::NoMatch),
        (b"*" as &[u8], b"" as &[u8], FnMatch::Match),
        (b"x" as &[u8], b"" as &[u8], FnMatch::NoMatch),
        (b"\\" as &[u8], b"\\" as &[u8], FnMatch::Match),
        (b"\\\\" as &[u8], b"\\" as &[u8], FnMatch::Match),
        (b"\\\\" as &[u8], b"\\\\" as &[u8], FnMatch::NoMatch),
        (b"\\?" as &[u8], b"?" as &[u8], FnMatch::Match),
        (b"\\*" as &[u8], b"*" as &[u8], FnMatch::Match),
        (b"?.txt" as &[u8], b"?.txt" as &[u8], FnMatch::Match),
        (b"*.txt" as &[u8], b"*.txt" as &[u8], FnMatch::Match),
        (b"\\?.txt" as &[u8], b"?.txt" as &[u8], FnMatch::Match),
        (b"\\*.txt" as &[u8], b"*.txt" as &[u8], FnMatch::Match),
        (b"\\?.txt" as &[u8], b"x.txt" as &[u8], FnMatch::NoMatch),
        (b"\\*.txt" as &[u8], b"x.txt" as &[u8], FnMatch::NoMatch),
        (b"\\*\\\\.txt" as &[u8], b"*\\.txt" as &[u8], FnMatch::Match),
        (b"*\\**\\?*\\\\*" as &[u8], b"cc*cc?cccc" as &[u8], FnMatch::NoMatch),
        (b"*\\?*\\**" as &[u8], b"cc?cc" as &[u8], FnMatch::NoMatch),
        (b"\\\"\\$\\&\\'\\(\\)" as &[u8], b"\"$&'()" as &[u8], FnMatch::Match),
        (b"\\*\\?\\[\\\\\\`\\|" as &[u8], b"*?[\\`|" as &[u8], FnMatch::Match),
        (b"[\\a\\b]c" as &[u8], b"ac" as &[u8], FnMatch::Match),
        (b"[\\a\\b]c" as &[u8], b"bc" as &[u8], FnMatch::Match),
        (b"[\\a\\b]d" as &[u8], b"bc" as &[u8], FnMatch::NoMatch),
        (b"[a-bA-B\\?]" as &[u8], b"?" as &[u8], FnMatch::Match),
        (b"cu[a-ab-b\\r]l" as &[u8], b"curl" as &[u8], FnMatch::Match),
        (b"[\\a-z]" as &[u8], b"c" as &[u8], FnMatch::Match),
        (b"?*?*?.*?*" as &[u8], b"abc.c" as &[u8], FnMatch::Match),
        (b"?*?*?.*?*" as &[u8], b"abcc" as &[u8], FnMatch::NoMatch),
        (b"?*?*?.*?*" as &[u8], b"abc." as &[u8], FnMatch::NoMatch),
        (b"?*?*?.*?*" as &[u8], b"abc.c++" as &[u8], FnMatch::Match),
        (b"?*?*?.*?*" as &[u8], b"abcdef.c++" as &[u8], FnMatch::Match),
        (b"?*?*?.?" as &[u8], b"abcdef.c" as &[u8], FnMatch::Match),
        (b"?*?*?.?" as &[u8], b"abcdef.cd" as &[u8], FnMatch::NoMatch),
        (b"Lindm\xc3\xa4tarv" as &[u8], b"Lindm\xc3\xa4tarv" as &[u8], FnMatch::Match),
        (b"" as &[u8], b"" as &[u8], FnMatch::Match),
        (b"**]*[*[\x13]**[*\x13)]*]*[**[*\x13~r-]*]**[.*]*[\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3\xe3*[\x13]**[*\x13)]*]*[*[\x13]*[~r]*]*\xba\x13\xa6~b-]*" as &[u8], b"a" as &[u8], FnMatch::NoMatch),

    ];

    #[test]
    fn parity_unit1307_full_table() {
        for (i, &(pattern, string, expected)) in UNIT1307_CASES.iter().enumerate() {
            let got = curl_fnmatch(pattern, string);
            let pat_s = String::from_utf8_lossy(pattern);
            let str_s = String::from_utf8_lossy(string);
            assert_eq!(
                got, expected,
                "unit1307 case #{i}: pattern={pat_s:?} string={str_s:?} \
                 expected {expected:?} got {got:?}"
            );
        }
    }
}
