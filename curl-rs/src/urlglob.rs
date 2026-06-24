// curl-rs/src/urlglob.rs
//
// Rust port of curl's URL-globbing engine — `src/tool_urlglob.c` and
// `src/tool_urlglob.h` from curl 8.x.
//
// This module implements **curl's own URL-glob grammar**, which is entirely
// distinct from filesystem globbing (the `glob` crate). curl's URL-glob lets a
// single command-line URL describe many URLs through two constructs:
//
//   * **brace sets** — `{one,two,three}` expand to each comma-separated literal;
//   * **ranges** — `[1-10]`, `[a-z]`, optionally with a `:step` suffix and
//     zero-padding (`[001-100]`), expand to a sequence of numbers or letters.
//
// Several patterns combine like the wheels of an odometer: the **rightmost**
// pattern advances fastest, carrying to the left when it wraps. The same
// machinery powers `#N` back-references in `-o`/`--output` filename templates,
// where `#1` is replaced with the current value of the first glob, `#2` the
// second, and so on (out-of-range references are emitted verbatim).
//
// # Behavioral parity
//
// Per AAP §0.8.2 the generated URL set and the `#N` filename substitution must
// match curl **byte-for-byte**: identical expansion, odometer ordering,
// zero-padding width, step handling, `\` escaping, IPv6-literal handling, and
// overflow limits. The C source is the behavioral oracle; the algorithms below
// reproduce it precisely while remaining free of `unsafe`.
//
// # Error reporting
//
// curl's `glob_url()` takes a `FILE *error` and prints a multi-line diagnostic
// with a caret pointing at the offending position (see test `tests/data/test75`).
// In `curl-rs` that printing belongs to the operation driver (`operate.rs`),
// which already owns the gated error stream — mirroring `src/tool_operate.c`
// where the stream is `(!global->silent || global->showerror) ? tool_stderr
// : NULL`. This module therefore keeps [`glob_url`] **pure** (it returns a
// [`GlobError`] and never writes anywhere) and exposes
// [`GlobError::to_stderr_string`], which produces the exact bytes curl would
// emit so the caller can write them directly to the error sink. Routing the
// diagnostic through `crate::messages::errorf` is intentionally avoided: that
// path word-wraps to the terminal width and asserts the message contains no
// newlines, which would corrupt the multi-line caret output.
//
// # Safety & dependencies
//
// The module forbids `unsafe`, depends only on `curl_rs_lib` (for the canonical
// `CURLcode` integers) plus the standard library and `tracing`, and never
// references `curl-rs-ffi` or the `glob` crate.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::Ipv6Addr;

// Only `CURLE_URL_MALFORMAT` (malformed pattern) and `CURLE_TOO_LARGE`
// (output-length cap) are produced here. curl additionally returns
// `CURLE_OUT_OF_MEMORY` from failed allocations, but in safe Rust container
// growth aborts on allocation failure rather than yielding a recoverable error,
// so that code has no call site in this port.
use curl_rs_lib::error::codes::{CURLE_TOO_LARGE, CURLE_URL_MALFORMAT};
use tracing::trace;

// ===========================================================================
// Constants (mirroring the `#define`s in `src/tool_urlglob.h`/`.c`)
// ===========================================================================

/// C `GLOB_PATTERN_NUM` from `src/tool_urlglob.h`.
///
/// This constant is **vestigial** in curl 8.x: it is declared in the header but
/// never referenced by `tool_urlglob.c`, which instead grows its pattern array
/// dynamically and caps the count at [`GLOB_MAX_PATTERNS`]. It is preserved here
/// purely to document the historical header value.
#[allow(dead_code)]
const GLOB_PATTERN_NUM: usize = 30;

/// Maximum number of patterns (literals + globs) per URL.
///
/// C `tool_urlglob.c:add_glob()` rejects the pattern array once it would grow
/// to 255 entries with the error `"too many {} sets"` ("avoid ridiculous
/// amounts"). The 256th pattern is refused.
const GLOB_MAX_PATTERNS: usize = 255;

/// Maximum number of comma-separated elements inside a single `{...}` set.
///
/// C `tool_urlglob.c:glob_set()` errors with `"range overflow"` once a set
/// reaches 100000 elements.
const GLOB_MAX_SET_SIZE: usize = 100_000;

/// Maximum length of an expanded `-o`/`--output` filename template.
///
/// C `tool_urlglob.c` `#define MAX_OUTPUT_GLOB_LENGTH (1024 * 1024)`. Exceeding
/// it yields [`CURLE_TOO_LARGE`] (the dynamic-buffer "too big" error).
const MAX_OUTPUT_GLOB_LENGTH: usize = 1024 * 1024;

/// Maximum length, in bytes, of a bracketed token considered for IPv6-literal
/// detection. C `tool_urlglob.c` `#define MAX_IP6LEN 128`.
const MAX_IP6LEN: usize = 128;

/// Upper bound for numeric range parsing — C `CURL_OFF_T_MAX`, i.e. the maximum
/// value of a 64-bit signed `curl_off_t`.
const CURL_OFF_T_MAX: i64 = i64::MAX;

/// Characters permitted inside an IPv6 literal host, matching the `strspn`
/// charset used by curl's `ipv6_parse()` in `lib/urlapi.c`
/// (`"0123456789abcdefABCDEF:."`, the `.` allowing embedded IPv4 forms).
const IPV6_CHARSET: &[u8] = b"0123456789abcdefABCDEF:.";

// ===========================================================================
// GlobError — parse failure carrying curl's message, position and CURLcode
// ===========================================================================

/// A URL-glob parse failure.
///
/// Mirrors the `glob->error` / `glob->pos` pair that C's `glob_url()` fills in,
/// together with the `CURLcode` it would return. curl uses `CURLE_URL_MALFORMAT`
/// for malformed patterns and `CURLE_OUT_OF_MEMORY` for allocation failures; the
/// CLI maps a glob failure to that code as the operation's exit status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobError {
    /// Static, human-readable cause (C `glob->error`), e.g. `"bad range"`.
    msg: String,
    /// 1-based byte position within the URL where the error was detected
    /// (C `glob->pos`). `0` means "no position" — curl then prints only the
    /// message with no caret line.
    pos: usize,
    /// The `CURLcode` integer curl's `glob_url()` returns for this failure.
    code: i32,
}

impl GlobError {
    /// Constructs a new error — the analog of C `globerror()`.
    fn new(msg: &str, pos: usize, code: i32) -> Self {
        GlobError {
            msg: msg.to_string(),
            pos,
            code,
        }
    }

    /// The `CURLcode` integer associated with this failure (C return value of
    /// `glob_url`). Used by `operate.rs` to set the transfer/exit status.
    pub fn code(&self) -> i32 {
        self.code
    }

    /// The 1-based position within the URL (C `glob->pos`); `0` if unknown.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// The static cause message (C `glob->error`).
    pub fn message(&self) -> &str {
        &self.msg
    }

    /// Builds the diagnostic body exactly as curl formats it into `text[]`
    /// inside `glob_url()` — i.e. the `%s` argument to its
    /// `"curl: (%d) %s\n"` print.
    ///
    /// When a position is known (`pos > 0`) this reproduces
    /// `"%s in URL position %zu:\n%s\n%*s^"` with `glob->error`, `glob->pos`,
    /// the original `url`, and `(int)glob->pos - 1` leading spaces before the
    /// caret. When `pos == 0` it is just the bare message.
    pub fn diagnostic(&self, url: &str) -> String {
        if self.pos > 0 {
            // `%*s` with width `pos - 1` and the single-space argument " "
            // yields exactly `pos - 1` spaces, placing `^` under column `pos`.
            let spaces = " ".repeat(self.pos - 1);
            let full = format!(
                "{} in URL position {}:\n{}\n{}^",
                self.msg, self.pos, url, spaces
            );
            // C `globerror()` does not format this directly to the stream: it
            // renders into a fixed `char text[512]` via
            // `curl_msnprintf(text, sizeof(text), ...)`. `curl_msnprintf`
            // stores at most `maxlength` bytes and then NUL-terminates,
            // overwriting the final byte when the buffer fills (lib/mprintf.c
            // `addbyter`/`curl_mvsnprintf`), so the emitted C string is capped
            // at `sizeof(text) - 1 == 511` bytes. For a pathologically long URL
            // this truncates the rendered URL mid-string and can drop the
            // trailing newline + caret entirely — observable, and asserted, by
            // tests/data/test761. Reproduce that fixed-buffer cap byte-for-byte.
            truncate_to_c_text_buffer(&full)
        } else {
            // C takes the `t = glob->error` branch when `glob->pos == 0`, i.e.
            // it points `t` straight at the static message and never routes it
            // through the `text[]` buffer, so the bare message is emitted
            // untruncated.
            self.msg.clone()
        }
    }

    /// Produces the complete, byte-exact line(s) curl writes to its error
    /// stream from `glob_url()`: `curl: (<code>) <diagnostic>\n` (note the
    /// trailing newline emitted by curl's `curl_mfprintf`).
    ///
    /// `operate.rs` writes this string directly to the gated error sink to
    /// reproduce curl's output (e.g. the exact three lines asserted by
    /// `tests/data/test75`).
    pub fn to_stderr_string(&self, url: &str) -> String {
        format!("curl: ({}) {}\n", self.code, self.diagnostic(url))
    }
}

impl fmt::Display for GlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.pos > 0 {
            write!(f, "{} (URL position {})", self.msg, self.pos)
        } else {
            write!(f, "{}", self.msg)
        }
    }
}

impl std::error::Error for GlobError {}

/// Caps `s` at the capacity of C `globerror()`'s `char text[512]` diagnostic
/// buffer.
///
/// `curl_msnprintf(text, sizeof(text), ...)` writes at most `sizeof(text)`
/// bytes and then NUL-terminates; when the buffer fills, `curl_mvsnprintf`
/// overwrites the final stored byte with the terminator (lib/mprintf.c), so the
/// resulting C string holds at most `512 - 1 == 511` bytes. We reproduce that
/// exact cap.
///
/// The cut is performed on a UTF-8 character boundary so the returned `String`
/// stays valid. The glob diagnostics that can exceed 511 bytes are built from
/// the (ASCII) error label, a decimal position, and the user-supplied URL; for
/// the ASCII inputs this path handles in practice the boundary-safe cut lands
/// on the same byte C would cut at, making the output byte-for-byte identical
/// (see tests/data/test761).
fn truncate_to_c_text_buffer(s: &str) -> String {
    /// `sizeof(text)` in `globerror()` is 512; one byte is reserved for the
    /// terminating NUL, leaving 511 bytes of content.
    const C_TEXT_CAP: usize = 511;

    if s.len() <= C_TEXT_CAP {
        return s.to_string();
    }
    // Walk back to the nearest char boundary at or below the cap so slicing
    // never splits a multi-byte sequence (a no-op for ASCII content).
    let mut end = C_TEXT_CAP;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

// ===========================================================================
// Pattern types (mirroring `struct URLPattern` and `enum globtype`)
// ===========================================================================

/// One component of a parsed URL template.
///
/// curl stores every component — including fixed literal text — in its
/// `pattern[]` array. Literal runs are kept as a single-element `GLOB_SET` with
/// `globindex == -1`; here they get their own [`PatternKind::Literal`] variant
/// for clarity, while [`UrlPattern::globindex`] preserves the `-1` sentinel so
/// `#N` back-reference lookup behaves identically.
///
/// The C `globtype` enum is `{ GLOB_SET = 1, GLOB_ASCII, GLOB_NUM }`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PatternKind {
    /// Fixed literal text (C: a `GLOB_SET` of size 1 with `globindex == -1`).
    Literal(String),
    /// A brace set `{a,b,c}` (C `GLOB_SET`). `idx` is the current element.
    Set { elems: Vec<String>, idx: usize },
    /// An alphabetic range `[a-z]` / `[a-z:step]` (C `GLOB_ASCII`).
    ///
    /// `letter` is the current value of the odometer wheel, advancing from
    /// `min` to `max` in increments of `step`.
    Ascii {
        min: u8,
        max: u8,
        letter: u8,
        step: u8,
    },
    /// A numeric range `[1-10]` / `[1-10:step]` (C `GLOB_NUM`).
    ///
    /// `idx` is the current value; `npad` is the zero-padding width derived
    /// from leading zeros in the start token (`[001-100]` ⇒ `npad == 3`).
    Num {
        min: i64,
        max: i64,
        idx: i64,
        step: i64,
        npad: usize,
    },
}

/// A pattern together with its glob index.
///
/// `globindex` is curl's `URLPattern.globindex`: the 0-based ordinal among the
/// "real" globs (used to resolve `#N` references, where `#1` maps to
/// `globindex == 0`), or `-1` for literal text.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UrlPattern {
    kind: PatternKind,
    globindex: i32,
}

// ===========================================================================
// UrlGlob — the parsed template plus odometer iteration state
// ===========================================================================

/// A parsed URL-glob template and its iteration state.
///
/// This is the Rust analog of C `struct URLGlob`. It is produced by [`glob_url`]
/// and then driven with [`UrlGlob::glob_next_url`] to enumerate every expanded
/// URL in curl's odometer order. [`UrlGlob::glob_match_url`] performs the `#N`
/// substitution for output-filename templates.
///
/// The type is public and derives [`Debug`] because the CLI's transient
/// `State` (see `crate::config`) stores it as `Option<UrlGlob>` and derives
/// `Debug`/`Default`. C's explicit `glob_cleanup()` is unnecessary here: owned
/// `String`/`Vec` data is released automatically when the value is dropped.
#[derive(Debug, Clone, Default)]
pub struct UrlGlob {
    /// Literal segments and globs, in template order.
    patterns: Vec<UrlPattern>,
    /// Whether the first combination has already been emitted (C
    /// `glob->beenhere`): the odometer emits the initial state on the first
    /// `glob_next_url` call and only then begins incrementing.
    beenhere: bool,
}

impl UrlGlob {
    /// Reports whether this glob holds any pattern — the analog of C
    /// `glob_inuse()`.
    ///
    /// In curl, `glob_inuse()` returns whether the embedded `URLGlob` was
    /// initialized (`palloc != 0`). In `curl-rs` an uninitialized glob is simply
    /// `None` (the field type is `Option<UrlGlob>`), so a *present* `UrlGlob`
    /// carrying at least one pattern is the meaningful "in use" condition.
    pub fn glob_inuse(&self) -> bool {
        !self.patterns.is_empty()
    }

    /// Number of "real" globs (excluding literal segments). Equivalent to the
    /// highest `globindex + 1` curl assigned, and the count operate.rs uses to
    /// decide whether expansion produced multiple URLs.
    pub fn glob_count(&self) -> usize {
        self.patterns
            .iter()
            .filter(|p| p.globindex >= 0)
            .count()
    }

    /// Returns the next expanded URL, or `None` when the sequence is exhausted —
    /// the analog of C `glob_next_url()`.
    ///
    /// The first call emits the initial combination (all wheels at their start).
    /// Each subsequent call advances the **rightmost** pattern and carries left
    /// on overflow; when the leftmost pattern overflows, iteration is complete
    /// and `None` is returned (C returns with `*globbed = NULL`).
    ///
    /// Numeric wheels are formatted with their zero-pad width (`"%0*d"`),
    /// alphabetic wheels advance by `step`, and set wheels cycle through their
    /// elements.
    pub fn glob_next_url(&mut self) -> Option<String> {
        if !self.beenhere {
            // First call: emit the initial combination without advancing.
            self.beenhere = true;
        } else if !self.advance() {
            // The odometer wrapped past the leftmost wheel — done.
            return None;
        }
        Some(self.reconstruct())
    }

    /// Advances the odometer by one step. Returns `true` if a new combination is
    /// available, or `false` if the leftmost wheel overflowed (iteration done).
    ///
    /// Mirrors the carry loop of C `glob_next_url()`, walking patterns from the
    /// rightmost to the leftmost. Literal segments are fixed wheels that always
    /// carry (they cannot absorb an increment), exactly like C's size-1
    /// `GLOB_SET` literals.
    fn advance(&mut self) -> bool {
        let pnum = self.patterns.len();
        let mut carry = true;
        let mut i = 0;
        while carry && i < pnum {
            carry = false;
            let pat = &mut self.patterns[pnum - 1 - i];
            match &mut pat.kind {
                PatternKind::Literal(_) => {
                    // Fixed wheel: cannot advance, so the carry propagates left.
                    carry = true;
                }
                PatternKind::Set { elems, idx } => {
                    *idx += 1;
                    if *idx >= elems.len() {
                        *idx = 0;
                        carry = true;
                    }
                }
                PatternKind::Ascii {
                    min,
                    max,
                    letter,
                    step,
                } => {
                    // Use a wider intermediate so `letter + step` cannot wrap a
                    // u8 before the `> max` comparison.
                    let next = u16::from(*letter) + u16::from(*step);
                    if next > u16::from(*max) {
                        *letter = *min;
                        carry = true;
                    } else {
                        *letter = next as u8;
                    }
                }
                PatternKind::Num {
                    min,
                    max,
                    idx,
                    step,
                    ..
                } => {
                    // checked_add guards the extreme `idx + step` overflow
                    // (e.g. ranges near i64::MAX); an overflow is treated as
                    // "past max", wrapping the wheel and carrying.
                    match idx.checked_add(*step) {
                        Some(next) if next <= *max => *idx = next,
                        _ => {
                            *idx = *min;
                            carry = true;
                        }
                    }
                }
            }
            i += 1;
        }
        // If `carry` is still set, the leftmost wheel overflowed → exhausted.
        !carry
    }

    /// Rebuilds the current URL by concatenating each pattern's current value,
    /// left to right — the second loop of C `glob_next_url()`.
    fn reconstruct(&self) -> String {
        let mut out = String::new();
        for pat in &self.patterns {
            match &pat.kind {
                PatternKind::Literal(s) => out.push_str(s),
                PatternKind::Set { elems, idx } => {
                    // `idx` is always within bounds (0..elems.len()).
                    if let Some(elem) = elems.get(*idx) {
                        out.push_str(elem);
                    }
                }
                PatternKind::Ascii { letter, .. } => {
                    // Alphabetic wheels are always ASCII letters (< 128).
                    out.push(*letter as char);
                }
                PatternKind::Num { idx, npad, .. } => {
                    // `%0*d` — zero-pad to `npad`; widths smaller than the
                    // number's own length do not truncate (matches printf).
                    out.push_str(&format!("{:0width$}", idx, width = *npad));
                }
            }
        }
        out
    }

    /// Substitutes `#N` back-references in an output-filename template with the
    /// current value of the corresponding glob — the analog of C
    /// `glob_match_url()`.
    ///
    /// `#1` is replaced by the current value of the first glob (`globindex 0`),
    /// `#2` the second, and so on. A reference to a glob that does not exist is
    /// emitted **verbatim** (e.g. `#9` with only two globs stays `#9`). Only a
    /// `#` immediately followed by a digit is treated as a reference; any other
    /// `#` is copied literally.
    ///
    /// The expanded result is capped at [`MAX_OUTPUT_GLOB_LENGTH`]; exceeding it
    /// returns [`CURLE_TOO_LARGE`], matching curl's dynamic-buffer limit.
    ///
    /// # Platform note
    ///
    /// On Windows and MS-DOS, curl additionally runs the result through
    /// `sanitize_file_name()` (`SANITIZE_ALLOW_PATH | SANITIZE_ALLOW_RESERVED`).
    /// This port targets non-Windows behavior first and returns the
    /// unsanitized name, exactly like curl's non-Windows branch. A
    /// cross-platform sanitization hook can be added here later without
    /// changing this signature.
    pub fn glob_match_url(&self, filename: &str) -> Result<String, GlobError> {
        let bytes = filename.as_bytes();
        let len = bytes.len();
        // Accumulate bytes so multi-byte UTF-8 in the template survives the
        // byte-oriented walk; convert once at the end.
        let mut out: Vec<u8> = Vec::with_capacity(len);
        let pnum = self.patterns.len() as i64;
        let mut i = 0usize;

        while i < len {
            if bytes[i] == b'#' && i + 1 < len && bytes[i + 1].is_ascii_digit() {
                let start = i; // position of '#'
                i += 1; // step over '#'
                let mut matched: Option<&UrlPattern> = None;
                // Parse the reference number, bounded by the pattern count just
                // as curl bounds it by `glob->pnum`.
                if let Some((num, next)) = str_number(bytes, i, pnum) {
                    i = next;
                    if num != 0 {
                        let target = (num - 1) as i32;
                        matched =
                            self.patterns.iter().find(|p| p.globindex == target);
                    }
                }
                match matched {
                    Some(pat) => append_pattern_value(&mut out, pat)?,
                    None => {
                        // Out of range (or overflowed): emit the consumed
                        // `#`/`#digits` text verbatim, exactly as curl copies
                        // `ptr .. filename`.
                        push_checked(&mut out, &bytes[start..i])?;
                    }
                }
            } else {
                push_checked(&mut out, &bytes[i..i + 1])?;
                i += 1;
            }
        }

        // The input was valid UTF-8 and substitutions insert only valid UTF-8
        // (pattern values / ASCII), so the result is always valid UTF-8.
        Ok(String::from_utf8(out).unwrap_or_else(|e| {
            String::from_utf8_lossy(e.as_bytes()).into_owned()
        }))
    }
}

/// Appends a pattern's *current* value to `out` for `#N` substitution — the
/// per-type append in C `glob_match_url()`. Literal patterns contribute their
/// text (curl never resolves `#N` to a literal because literals carry
/// `globindex == -1`, but handling it keeps the helper total).
fn append_pattern_value(out: &mut Vec<u8>, pat: &UrlPattern) -> Result<(), GlobError> {
    match &pat.kind {
        PatternKind::Literal(s) => push_checked(out, s.as_bytes()),
        PatternKind::Set { elems, idx } => match elems.get(*idx) {
            Some(elem) => push_checked(out, elem.as_bytes()),
            None => Ok(()),
        },
        PatternKind::Ascii { letter, .. } => push_checked(out, &[*letter]),
        PatternKind::Num { idx, npad, .. } => {
            let formatted = format!("{:0width$}", idx, width = *npad);
            push_checked(out, formatted.as_bytes())
        }
    }
}

/// Appends `data` to `out`, enforcing the [`MAX_OUTPUT_GLOB_LENGTH`] cap. This
/// reproduces curl's `dynbuf` "too big" behavior: once the buffer would exceed
/// the limit, the dynamic-buffer error [`CURLE_TOO_LARGE`] is returned.
fn push_checked(out: &mut Vec<u8>, data: &[u8]) -> Result<(), GlobError> {
    if out.len() + data.len() > MAX_OUTPUT_GLOB_LENGTH {
        return Err(GlobError::new(
            "output glob length exceeded",
            0,
            CURLE_TOO_LARGE,
        ));
    }
    out.extend_from_slice(data);
    Ok(())
}

// ===========================================================================
// glob_url — top-level parse entry point
// ===========================================================================

/// Parses a URL template into a [`UrlGlob`] and computes the total number of
/// URLs it expands to — the analog of C `glob_url()`.
///
/// On success returns `(glob, urlnum)` where `urlnum` is the product of every
/// glob's element count (`1` for a URL with no globs). On failure returns a
/// [`GlobError`] carrying curl's message, position and `CURLcode`; the caller
/// (`operate.rs`) is responsible for printing it via
/// [`GlobError::to_stderr_string`] — this function performs no I/O, mirroring
/// curl where the error stream is supplied by `tool_operate.c`.
///
/// # Examples
///
/// ```ignore
/// let (mut glob, n) = glob_url("http://site/[1-3]")?;
/// assert_eq!(n, 3);
/// assert_eq!(glob.glob_next_url().as_deref(), Some("http://site/1"));
/// ```
pub fn glob_url(url: &str) -> Result<(UrlGlob, i64), GlobError> {
    let mut glob = UrlGlob::default();
    // C initialises amount to 1 inside glob_parse; the product of all pattern
    // sizes accumulates into it.
    let mut amount: i64 = 1;
    glob_parse(url.as_bytes(), &mut glob.patterns, &mut amount)?;
    trace!(
        urlnum = amount,
        patterns = glob.patterns.len(),
        globs = glob.glob_count(),
        "parsed URL glob"
    );
    Ok((glob, amount))
}

// ===========================================================================
// glob_parse — walk the template, emitting literals and globs
// ===========================================================================

/// Walks the template, copying literal text and branching to [`glob_set`] /
/// [`glob_range`] when it meets `{` / `[` — the analog of C `glob_parse()`.
///
/// `pos` starts at 1 (matching curl's `glob_parse(glob, url, 1, &amount)` call),
/// so error positions are 1-based and align with curl's caret diagnostics.
fn glob_parse(
    bytes: &[u8],
    patterns: &mut Vec<UrlPattern>,
    amount: &mut i64,
) -> Result<(), GlobError> {
    let len = bytes.len();
    let mut pos: usize = 1;
    let mut idx: usize = 0;
    let mut globindex: i32 = 0;
    // Mirror curl's pattern-array growth so the "too many {} sets" cap triggers
    // at exactly the same count (`glob->palloc` starts at 2 in `glob_url`).
    let mut palloc: usize = 2;
    // Literal accumulator — the Rust analog of `glob->buf`. Bytes are collected
    // so that multi-byte UTF-8 survives the byte-oriented scan.
    let mut lit: Vec<u8> = Vec::new();

    while idx < len {
        // Inner loop: copy literal characters until a '{' (or a real '[' range,
        // or the end of input).
        while idx < len && bytes[idx] != b'{' {
            if bytes[idx] == b'[' {
                // Distinguish an IPv6 literal / "[]" (copied verbatim) from a
                // real range expression.
                let (mut skip, ipv6) = peek_ipv6(&bytes[idx..]);
                if !ipv6 && idx + 1 < len && bytes[idx + 1] == b']' {
                    skip = 2;
                }
                if skip > 0 {
                    // Verbatim copy of the bracketed literal. curl does NOT
                    // advance `pos` across this skip — reproduced here.
                    lit.extend_from_slice(&bytes[idx..idx + skip]);
                    idx += skip;
                    continue;
                }
                break; // a genuine range starts here
            }
            if bytes[idx] == b'}' || bytes[idx] == b']' {
                return Err(GlobError::new(
                    "unmatched close brace/bracket",
                    pos,
                    CURLE_URL_MALFORMAT,
                ));
            }
            // Backslash escapes ONLY the four special characters `{ [ } ]`.
            if bytes[idx] == b'\\'
                && idx + 1 < len
                && matches!(bytes[idx + 1], b'{' | b'[' | b'}' | b']')
            {
                idx += 1; // skip the '\'
                pos += 1;
            }
            lit.push(bytes[idx]);
            idx += 1;
            pos += 1;
        }

        if !lit.is_empty() {
            // A literal string component — stored as its own pattern with
            // globindex -1 (curl's `glob_fixed` + `add_glob`).
            let s = bytes_to_string(&lit);
            add_pattern(patterns, &mut palloc, PatternKind::Literal(s), -1, pos)?;
            lit.clear();
        } else if idx >= len {
            break; // reached the end with nothing pending
        } else if bytes[idx] == b'{' {
            idx += 1; // step over '{'
            pos += 1;
            let kind = glob_set(bytes, &mut idx, &mut pos, amount, globindex)?;
            let gi = globindex;
            globindex += 1;
            add_pattern(patterns, &mut palloc, kind, gi, pos)?;
        } else if bytes[idx] == b'[' {
            idx += 1; // step over '['
            pos += 1;
            let kind = glob_range(bytes, &mut idx, &mut pos, amount, globindex)?;
            let gi = globindex;
            globindex += 1;
            add_pattern(patterns, &mut palloc, kind, gi, pos)?;
        }
    }

    Ok(())
}

/// Appends a finished pattern and enforces the [`GLOB_MAX_PATTERNS`] cap — the
/// analog of C `add_glob()`. `palloc` mirrors curl's doubling pattern-array
/// capacity so the "too many {} sets" error fires at the identical count.
fn add_pattern(
    patterns: &mut Vec<UrlPattern>,
    palloc: &mut usize,
    kind: PatternKind,
    globindex: i32,
    pos: usize,
) -> Result<(), GlobError> {
    patterns.push(UrlPattern { kind, globindex });
    let pnum = patterns.len();
    if pnum >= *palloc {
        *palloc = palloc.saturating_mul(2);
        if pnum >= GLOB_MAX_PATTERNS {
            return Err(GlobError::new(
                "too many {} sets",
                pos,
                CURLE_URL_MALFORMAT,
            ));
        }
    }
    Ok(())
}

/// Overflow-checked multiply used to accumulate the total URL count — the
/// analog of C `multiply()`. Returns `true` on overflow (the caller turns this
/// into a `"range overflow"` error). When either operand is non-positive the
/// running total is set to `0`, exactly as curl does.
fn multiply(amount: &mut i64, with: i64) -> bool {
    if with <= 0 || *amount <= 0 {
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

// ===========================================================================
// glob_set — parse a `{a,b,c}` brace set
// ===========================================================================

/// Parses a brace set, with the cursor positioned just past the opening `{` —
/// the analog of C `glob_set()`. Collects comma-separated literal elements until
/// the closing `}`, honoring `\` escapes of `{ } [ ] ,`.
fn glob_set(
    bytes: &[u8],
    idx: &mut usize,
    pos: &mut usize,
    amount: &mut i64,
    _globindex: i32,
) -> Result<PatternKind, GlobError> {
    let len = bytes.len();
    let opos = *pos - 1; // position of the opening '{'
    let start_idx = *idx; // for curl's `opattern == pattern` empty check
    let mut elems: Vec<String> = Vec::new();
    let mut buf: Vec<u8> = Vec::new(); // current element accumulator (glob->buf)
    let mut done = false;

    while !done {
        if *idx >= len {
            // case '\0' — URL ended while the set was still open
            return Err(GlobError::new(
                "unmatched brace",
                opos,
                CURLE_URL_MALFORMAT,
            ));
        }
        match bytes[*idx] {
            b'{' | b'[' => {
                // No nested expressions are supported.
                return Err(GlobError::new(
                    "nested brace",
                    *pos,
                    CURLE_URL_MALFORMAT,
                ));
            }
            b'}' => {
                // A set element completes here; `}` also closes the set.
                if *idx == start_idx {
                    return Err(GlobError::new(
                        "empty string within braces",
                        *pos,
                        CURLE_URL_MALFORMAT,
                    ));
                }
                // Account for the element about to be added (curl multiplies by
                // `size + 1` before the fall-through appends it).
                if multiply(amount, elems.len() as i64 + 1) {
                    return Err(GlobError::new(
                        "range overflow",
                        0,
                        CURLE_URL_MALFORMAT,
                    ));
                }
                done = true;
                // FALLTHROUGH to the element-finalize shared with ','.
                finalize_set_element(&mut elems, &mut buf, idx, pos, done)?;
            }
            b',' => {
                finalize_set_element(&mut elems, &mut buf, idx, pos, done)?;
            }
            b']' => {
                return Err(GlobError::new(
                    "unexpected close bracket",
                    *pos,
                    CURLE_URL_MALFORMAT,
                ));
            }
            b'\\' => {
                // Escaped character: skip the '\' if a character follows, then
                // fall through to copy the (now current) character.
                if *idx + 1 < len {
                    *idx += 1;
                    *pos += 1;
                }
                buf.push(bytes[*idx]);
                *idx += 1;
                *pos += 1;
            }
            other => {
                buf.push(other);
                *idx += 1;
                *pos += 1;
            }
        }
    }

    Ok(PatternKind::Set { elems, idx: 0 })
}

/// Finalizes the current set element — the body shared by curl's `}` (via
/// fall-through) and `,` cases. Enforces the [`GLOB_MAX_SET_SIZE`] cap, appends
/// the accumulated element (empty string if none), resets the accumulator,
/// advances past the delimiter, and advances `pos` only for a real `,`.
fn finalize_set_element(
    elems: &mut Vec<String>,
    buf: &mut Vec<u8>,
    idx: &mut usize,
    pos: &mut usize,
    done: bool,
) -> Result<(), GlobError> {
    if elems.len() >= GLOB_MAX_SET_SIZE {
        return Err(GlobError::new("range overflow", 0, CURLE_URL_MALFORMAT));
    }
    elems.push(bytes_to_string(buf));
    buf.clear();
    *idx += 1; // step over the ',' or '}'
    if !done {
        *pos += 1;
    }
    Ok(())
}

// ===========================================================================
// glob_range — parse a `[start-end]` / `[start-end:step]` range
// ===========================================================================

/// Parses a range expression, with the cursor positioned just past the opening
/// `[` — the analog of C `glob_range()`. Handles alphabetic ranges
/// (`[a-z]`, `[a-z:step]`) and numeric ranges (`[1-10]`, `[001-100:2]`),
/// validating well-formedness and computing the element count.
fn glob_range(
    bytes: &[u8],
    idx: &mut usize,
    pos: &mut usize,
    amount: &mut i64,
    _globindex: i32,
) -> Result<PatternKind, GlobError> {
    let len = bytes.len();
    let start_idx = *idx;
    let entry_pos = *pos;

    if *idx < len && bytes[*idx].is_ascii_alphabetic() {
        // ----- alphabetic range (GLOB_ASCII) -----
        let mut pmatch = false;
        let mut min_c: u8 = 0;
        let mut max_c: u8 = 0;
        let mut step: u8 = 1;

        // Requires the exact shape `X-Y?` with non-NUL X, Y and a following
        // terminator byte (curl: `pattern[1]=='-' && pattern[2] && pattern[3]`).
        if *idx + 3 < len
            && bytes[*idx + 1] == b'-'
            && bytes[*idx + 2] != 0
            && bytes[*idx + 3] != 0
        {
            min_c = bytes[*idx];
            max_c = bytes[*idx + 2];
            let end_c = bytes[*idx + 3];
            pmatch = true;

            if end_c == b':' {
                // Parse the step (max 256) then the closing ']'. The cursor
                // advances exactly as far as each sub-parse succeeds, matching
                // curl's short-circuiting `||` chain.
                let mut p = *idx + 4;
                match str_number(bytes, p, 256) {
                    None => step = 0,
                    Some((num, np)) => {
                        p = np;
                        match str_single(bytes, p, b']') {
                            None => step = 0,
                            Some(np2) => {
                                p = np2;
                                // (unsigned char) cast: 256 wraps to 0 → caught
                                // by the `step == 0` validation below.
                                step = num as u8;
                            }
                        }
                    }
                }
                *idx = p;
            } else if end_c != b']' {
                pmatch = false;
            } else {
                *idx += 4; // step over "X-Y]"
            }
        }

        *pos = entry_pos + (*idx - start_idx);

        // Validation mirrors curl exactly. The `min_c > max_c` term is checked
        // before any `max_c - min_c` subtraction, so the unsigned subtraction
        // can never underflow.
        let bad = !pmatch
            || step == 0
            || (min_c == max_c && step != 1)
            || (min_c != max_c
                && (min_c > max_c
                    || step > (max_c - min_c)
                    || (max_c - min_c) > (b'z' - b'a')));
        if bad {
            return Err(GlobError::new("bad range", *pos, CURLE_URL_MALFORMAT));
        }

        let count = ((max_c - min_c) as i64) / (step as i64) + 1;
        if multiply(amount, count) {
            return Err(GlobError::new(
                "range overflow",
                *pos,
                CURLE_URL_MALFORMAT,
            ));
        }

        Ok(PatternKind::Ascii {
            min: min_c,
            max: max_c,
            letter: min_c,
            step,
        })
    } else if *idx < len && bytes[*idx].is_ascii_digit() {
        // ----- numeric range (GLOB_NUM) -----
        let mut npad: usize = 0;
        // When the start token begins with '0', the zero-pad width is the count
        // of its leading digits (`[001-100]` ⇒ npad 3).
        if bytes[*idx] == b'0' {
            let mut c = *idx;
            while c < len && bytes[c].is_ascii_digit() {
                c += 1;
                npad += 1;
            }
        }

        let mut min_n: i64 = 0;
        let mut max_n: i64 = 0;
        let mut step_n: i64 = 0;
        let mut p = *idx;

        // Parse `min '-' max [':' step] ']'`. The cursor advances exactly as far
        // as each sub-parse succeeds, faithfully matching curl's nested
        // short-circuit chain so error positions land identically.
        if let Some((num, np)) = str_number(bytes, p, CURL_OFF_T_MAX) {
            min_n = num;
            p = np;
            if let Some(np) = str_single(bytes, p, b'-') {
                p = str_passblanks(bytes, np);
                if let Some((num, np)) = str_number(bytes, p, CURL_OFF_T_MAX) {
                    max_n = num;
                    p = np;
                    if let Some(np) = str_single(bytes, p, b']') {
                        p = np;
                        step_n = 1;
                    } else if let Some(np1) = str_single(bytes, p, b':') {
                        p = np1;
                        if let Some((num, np2)) =
                            str_number(bytes, p, CURL_OFF_T_MAX)
                        {
                            p = np2;
                            if let Some(np3) = str_single(bytes, p, b']') {
                                p = np3;
                                step_n = num;
                            } else {
                                // ']' missing after step: cursor sits past the
                                // step number, step_n stays 0 (bad syntax).
                                p = np2;
                            }
                        } else {
                            // step number parse failed: cursor sits past ':'.
                            p = np1;
                        }
                    }
                    // else: neither ']' nor ':' — step_n stays 0 (bad syntax).
                }
            }
        }

        *idx = p;
        *pos = entry_pos + (*idx - start_idx);

        let bad = step_n == 0
            || (min_n == max_n && step_n != 1)
            || (min_n != max_n && (min_n > max_n || step_n > (max_n - min_n)));
        if bad {
            return Err(GlobError::new("bad range", *pos, CURLE_URL_MALFORMAT));
        }

        // `(max - min) / step + 1`. curl relies on signed wrap for the extreme
        // `i64::MAX` span; `wrapping_add` reproduces it so the subsequent
        // `multiply` collapses to 0 exactly as curl's does.
        let count = ((max_n - min_n) / step_n).wrapping_add(1);
        if multiply(amount, count) {
            return Err(GlobError::new(
                "range overflow",
                *pos,
                CURLE_URL_MALFORMAT,
            ));
        }

        Ok(PatternKind::Num {
            min: min_n,
            max: max_n,
            idx: min_n,
            step: step_n,
            npad,
        })
    } else {
        // Neither alphabetic nor numeric — curl reports "bad range
        // specification" without advancing the cursor.
        Err(GlobError::new(
            "bad range specification",
            entry_pos,
            CURLE_URL_MALFORMAT,
        ))
    }
}

// ===========================================================================
// peek_ipv6 — distinguish an IPv6 literal host from a range expression
// ===========================================================================

/// Determines whether the bracketed token at the start of `s` (which begins
/// with `[`) is an IPv6 literal that must be copied verbatim — the analog of C
/// `peek_ipv6()`.
///
/// Returns `(skip, is_ipv6)`: when the token is a valid IPv6 literal, `skip` is
/// its full length (including both brackets) and `is_ipv6` is `true`. curl
/// validates by feeding the bracketed host to `curl_url_set` with
/// `CURLU_GUESS_SCHEME`; this port reproduces the same accept/reject decision by
/// checking the host body against the IPv6 character set
/// (`lib/urlapi.c:ipv6_parse`'s `strspn`) and then parsing it with
/// [`std::net::Ipv6Addr`] (the equivalent of `inet_pton(AF_INET6, …)`). A
/// hyphen — present in every range (`[1-10]`, `[a-z]`) but never in an IPv6
/// literal — falls outside the charset, so ranges are correctly rejected here.
fn peek_ipv6(s: &[u8]) -> (usize, bool) {
    let endbr = match s.iter().position(|&b| b == b']') {
        Some(i) => i,
        None => return (0, false),
    };
    let hlen = endbr + 1; // length including '[' and ']'
    if hlen >= MAX_IP6LEN {
        return (0, false);
    }
    // Host body between the brackets, minus any "%zoneid" suffix.
    let body = &s[1..endbr];
    let addr = match body.iter().position(|&b| b == b'%') {
        Some(i) => &body[..i],
        None => body,
    };
    if addr.is_empty() || !addr.iter().all(|b| IPV6_CHARSET.contains(b)) {
        return (0, false);
    }
    match std::str::from_utf8(addr) {
        Ok(text) if text.parse::<Ipv6Addr>().is_ok() => (hlen, true),
        _ => (0, false),
    }
}

// ===========================================================================
// String-parsing primitives (ports of lib/curlx/strparse.c)
// ===========================================================================

/// Parses a base-10 number at `pos`, bounded by `max` — the analog of
/// `curlx_str_number` / `str_num_base`.
///
/// Returns `Some((value, new_pos))` on success, advancing past the digits. On
/// no-digit or overflow it returns `None` **without** advancing (matching
/// curl, which leaves the cursor untouched on error). Two overflow regimes
/// reproduce curl's `str_num_base`: when `max < 10` the accumulated value is
/// checked against `max` after each digit; otherwise the pre-multiply guard
/// `num > (max - n) / base` is used. Both are panic-free.
fn str_number(bytes: &[u8], pos: usize, max: i64) -> Option<(i64, usize)> {
    const BASE: i64 = 10;
    let len = bytes.len();
    let mut i = pos;
    if i >= len || !bytes[i].is_ascii_digit() {
        return None; // STRE_NO_NUM
    }
    let mut num: i64 = 0;
    if max < BASE {
        // Low-max special case: check after accumulation.
        loop {
            let n = (bytes[i] - b'0') as i64;
            i += 1;
            num = num * BASE + n;
            if num > max {
                return None; // STRE_OVERFLOW
            }
            if i >= len || !bytes[i].is_ascii_digit() {
                break;
            }
        }
    } else {
        // General case: guard before accumulation so `num` never exceeds `max`
        // (and therefore never overflows i64, since `max <= i64::MAX`).
        loop {
            let n = (bytes[i] - b'0') as i64;
            if num > (max - n) / BASE {
                return None; // STRE_OVERFLOW
            }
            num = num * BASE + n;
            i += 1;
            if i >= len || !bytes[i].is_ascii_digit() {
                break;
            }
        }
    }
    Some((num, i))
}

/// Matches a single expected byte at `pos` — the analog of `curlx_str_single`.
/// Returns `Some(pos + 1)` if the byte matches (advancing over it), else `None`.
/// At end-of-input it returns `None`, matching curl where the implicit NUL
/// terminator never equals the sought byte.
fn str_single(bytes: &[u8], pos: usize, byte: u8) -> Option<usize> {
    if pos < bytes.len() && bytes[pos] == byte {
        Some(pos + 1)
    } else {
        None
    }
}

/// Skips spaces and tabs starting at `pos` — the analog of
/// `curlx_str_passblanks` (curl `ISBLANK` is space or tab only).
fn str_passblanks(bytes: &[u8], pos: usize) -> usize {
    let mut i = pos;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    i
}

/// Converts an accumulated byte run to a `String`. The runs collected by the
/// parser are split only at ASCII glob metacharacters, so a multi-byte UTF-8
/// sequence is never bisected and the bytes are always valid UTF-8; the lossy
/// conversion is therefore exact and simply guarantees the function never
/// panics.
fn bytes_to_string(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

// ===========================================================================
// Tests — parity with curl's `tool_urlglob.c` behavior
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Fully expands a URL template into `(urlnum, all_urls)`.
    fn expand(url: &str) -> (i64, Vec<String>) {
        let (mut glob, n) = glob_url(url).expect("glob_url should succeed");
        let mut urls = Vec::new();
        while let Some(u) = glob.glob_next_url() {
            urls.push(u);
        }
        (n, urls)
    }

    // ---- plain URLs ----

    #[test]
    fn plain_url_has_no_globs() {
        let (n, urls) = expand("http://example.com/path");
        assert_eq!(n, 1);
        assert_eq!(urls, vec!["http://example.com/path".to_string()]);
    }

    #[test]
    fn empty_url_yields_nothing() {
        let (glob, n) = glob_url("").unwrap();
        assert_eq!(n, 1);
        assert!(!glob.glob_inuse());
        assert_eq!(glob.glob_count(), 0);
    }

    // ---- VALIDATION: expansion parity ----

    #[test]
    fn numeric_range_expands_to_three() {
        let (n, urls) = expand("http://site/[1-3]");
        assert_eq!(n, 3);
        assert_eq!(
            urls,
            vec![
                "http://site/1".to_string(),
                "http://site/2".to_string(),
                "http://site/3".to_string(),
            ]
        );
    }

    #[test]
    fn odometer_order_rightmost_varies_fastest() {
        // {a,b} is glob #1 (left), [1-2] is glob #2 (right). The right wheel
        // advances fastest with carry to the left.
        let (n, urls) = expand("http://site/{a,b}/[1-2]");
        assert_eq!(n, 4);
        assert_eq!(
            urls,
            vec![
                "http://site/a/1".to_string(),
                "http://site/a/2".to_string(),
                "http://site/b/1".to_string(),
                "http://site/b/2".to_string(),
            ]
        );
    }

    #[test]
    fn brace_set_three_elements() {
        let (n, urls) = expand("pre-{x,y,z}-post");
        assert_eq!(n, 3);
        assert_eq!(
            urls,
            vec![
                "pre-x-post".to_string(),
                "pre-y-post".to_string(),
                "pre-z-post".to_string(),
            ]
        );
    }

    #[test]
    fn alphabetic_range_full_alphabet() {
        let (n, urls) = expand("[a-z]");
        assert_eq!(n, 26);
        assert_eq!(urls.first().map(String::as_str), Some("a"));
        assert_eq!(urls.last().map(String::as_str), Some("z"));
        assert_eq!(urls.len(), 26);
    }

    #[test]
    fn trailing_set_element_can_be_empty() {
        // `{a,}` expands to ["a", ""] (curl keeps the empty trailing element).
        let (n, urls) = expand("pre{a,}");
        assert_eq!(n, 2);
        assert_eq!(urls, vec!["prea".to_string(), "pre".to_string()]);
    }

    // ---- VALIDATION: zero-pad parity ----

    #[test]
    fn zero_padding_width_three() {
        let (n, urls) = expand("img[001-100].jpg");
        assert_eq!(n, 100);
        assert_eq!(urls.first().map(String::as_str), Some("img001.jpg"));
        assert_eq!(urls.get(9).map(String::as_str), Some("img010.jpg"));
        assert_eq!(urls.last().map(String::as_str), Some("img100.jpg"));
    }

    #[test]
    fn no_zero_padding_when_start_is_nonzero() {
        let (_n, urls) = expand("[8-11]");
        assert_eq!(
            urls,
            vec![
                "8".to_string(),
                "9".to_string(),
                "10".to_string(),
                "11".to_string()
            ]
        );
    }

    // ---- VALIDATION: step parity ----

    #[test]
    fn numeric_step_two() {
        let (n, urls) = expand("[1-10:2]");
        assert_eq!(n, 5);
        assert_eq!(
            urls,
            vec![
                "1".to_string(),
                "3".to_string(),
                "5".to_string(),
                "7".to_string(),
                "9".to_string(),
            ]
        );
    }

    #[test]
    fn alphabetic_step_two() {
        // [a-z:2] yields a,c,e,...,y (13 letters; 'z' is not reached).
        let (n, urls) = expand("[a-z:2]");
        assert_eq!(n, 13);
        assert_eq!(urls.first().map(String::as_str), Some("a"));
        assert_eq!(urls.get(1).map(String::as_str), Some("c"));
        assert_eq!(urls.last().map(String::as_str), Some("y"));
    }

    #[test]
    fn zero_pad_with_step() {
        let (n, urls) = expand("[00-10:5]");
        assert_eq!(n, 3);
        assert_eq!(
            urls,
            vec!["00".to_string(), "05".to_string(), "10".to_string()]
        );
    }

    // ---- VALIDATION: escape parity ----

    #[test]
    fn backslash_escapes_braces_and_brackets() {
        // `\{`, `\}`, `\[`, `\]` are literal; the result is a single URL.
        let (n, urls) = expand(r"http://x/\{a\}\[b\]");
        assert_eq!(n, 1);
        assert_eq!(urls, vec!["http://x/{a}[b]".to_string()]);
    }

    #[test]
    fn unterminated_brace_is_error_at_open_position() {
        // test759-style: a brace set that never closes.
        let err = glob_url("{,").unwrap_err();
        assert_eq!(err.message(), "unmatched brace");
        assert_eq!(err.pos(), 1);
        assert_eq!(err.code(), CURLE_URL_MALFORMAT);
    }

    #[test]
    fn unterminated_bracket_is_bad_range() {
        // A numeric range with no closing ']' fails (step parse fails ⇒ step 0).
        let err = glob_url("http://x/[1-2").unwrap_err();
        assert_eq!(err.message(), "bad range");
        assert_eq!(err.code(), CURLE_URL_MALFORMAT);
    }

    #[test]
    fn nested_brace_is_error() {
        let err = glob_url("{a{b}}").unwrap_err();
        assert_eq!(err.message(), "nested brace");
        assert_eq!(err.code(), CURLE_URL_MALFORMAT);
    }

    #[test]
    fn empty_braces_is_error() {
        let err = glob_url("{}").unwrap_err();
        assert_eq!(err.message(), "empty string within braces");
        assert_eq!(err.code(), CURLE_URL_MALFORMAT);
    }

    #[test]
    fn unmatched_close_brace_is_error() {
        let err = glob_url("abc}def").unwrap_err();
        assert_eq!(err.message(), "unmatched close brace/bracket");
        assert_eq!(err.code(), CURLE_URL_MALFORMAT);
    }

    // ---- VALIDATION: IPv6 parity ----

    #[test]
    fn ipv6_literal_is_not_a_glob() {
        let (n, urls) = expand("http://[::1]/");
        assert_eq!(n, 1);
        assert_eq!(urls, vec!["http://[::1]/".to_string()]);
    }

    #[test]
    fn ipv6_literal_with_following_range() {
        let (n, urls) = expand("http://[::1]:8080/[1-2]");
        assert_eq!(n, 2);
        assert_eq!(
            urls,
            vec![
                "http://[::1]:8080/1".to_string(),
                "http://[::1]:8080/2".to_string(),
            ]
        );
    }

    #[test]
    fn full_ipv6_address_is_literal() {
        let (n, urls) = expand("http://[2001:db8::1]/x");
        assert_eq!(n, 1);
        assert_eq!(urls, vec!["http://[2001:db8::1]/x".to_string()]);
    }

    #[test]
    fn empty_brackets_are_literal() {
        let (n, urls) = expand("http://x/[]y");
        assert_eq!(n, 1);
        assert_eq!(urls, vec!["http://x/[]y".to_string()]);
    }

    // ---- VALIDATION: #N substitution ----

    #[test]
    fn hash_substitution_uses_current_values() {
        let (mut glob, n) = glob_url("http://site/{a,b}/[1-2]").unwrap();
        assert_eq!(n, 4);
        assert_eq!(glob.glob_count(), 2);

        // first combination: set="a", num=1
        assert_eq!(glob.glob_next_url().as_deref(), Some("http://site/a/1"));
        assert_eq!(glob.glob_match_url("#1-#2.html").unwrap(), "a-1.html");

        // second combination: set="a", num=2
        assert_eq!(glob.glob_next_url().as_deref(), Some("http://site/a/2"));
        assert_eq!(glob.glob_match_url("#1-#2.html").unwrap(), "a-2.html");

        // third combination: set="b", num=1
        assert_eq!(glob.glob_next_url().as_deref(), Some("http://site/b/1"));
        assert_eq!(glob.glob_match_url("out/#1/#2").unwrap(), "out/b/1");
    }

    #[test]
    fn hash_out_of_range_stays_literal() {
        let (mut glob, _n) = glob_url("http://site/{a,b}/[1-2]").unwrap();
        glob.glob_next_url();
        // Only globs #1 and #2 exist; #9 is emitted verbatim.
        assert_eq!(glob.glob_match_url("file-#9.txt").unwrap(), "file-#9.txt");
        // #3 is also out of range here.
        assert_eq!(glob.glob_match_url("#3").unwrap(), "#3");
    }

    #[test]
    fn hash_zero_is_literal() {
        let (mut glob, _n) = glob_url("[1-2]").unwrap();
        glob.glob_next_url();
        // `#0` is not a valid reference; curl emits it literally.
        assert_eq!(glob.glob_match_url("#0.bin").unwrap(), "#0.bin");
    }

    #[test]
    fn hash_without_digit_is_literal() {
        let (mut glob, _n) = glob_url("[1-2]").unwrap();
        glob.glob_next_url();
        assert_eq!(glob.glob_match_url("a#b").unwrap(), "a#b");
    }

    #[test]
    fn hash_zero_padded_value_substitution() {
        let (mut glob, _n) = glob_url("[001-100]").unwrap();
        glob.glob_next_url(); // value 1 → "001"
        assert_eq!(glob.glob_match_url("#1.dump").unwrap(), "001.dump");
    }

    // ---- VALIDATION: overflow ----

    #[test]
    fn product_overflow_is_rejected() {
        // 1e10 * 1e10 = 1e20 > i64::MAX ⇒ "range overflow".
        let err = glob_url("http://x/[0-9999999999]/[0-9999999999]").unwrap_err();
        assert_eq!(err.message(), "range overflow");
        assert_eq!(err.code(), CURLE_URL_MALFORMAT);
    }

    #[test]
    fn huge_number_token_overflows_to_bad_range() {
        // A bound beyond i64::MAX makes the number parse fail ⇒ "bad range".
        let err = glob_url("[0-60000000000000000000]").unwrap_err();
        assert_eq!(err.message(), "bad range");
        assert_eq!(err.code(), CURLE_URL_MALFORMAT);
    }

    #[test]
    fn reversed_numeric_range_is_bad() {
        let err = glob_url("[5-2]").unwrap_err();
        assert_eq!(err.message(), "bad range");
    }

    // ---- VALIDATION: test75 — byte-exact diagnostic ----

    #[test]
    fn test75_bad_range_exact_position_and_diagnostic() {
        let url = "http://a-site-never-accessed.example.org/[2-1]";
        let err = glob_url(url).unwrap_err();
        assert_eq!(err.code(), 3); // CURLE_URL_MALFORMAT
        assert_eq!(err.pos(), 47);
        assert_eq!(err.message(), "bad range");

        // Reproduce the exact three-line diagnostic curl prints (test75 asserts
        // this verbatim via `--stderr -`), including the 46-space caret indent
        // and the trailing newline.
        let expected = format!(
            "curl: (3) bad range in URL position 47:\n{}\n{}^\n",
            url,
            " ".repeat(46)
        );
        assert_eq!(err.to_stderr_string(url), expected);
    }

    #[test]
    fn diagnostic_without_position_is_bare_message() {
        // "range overflow" carries pos 0 ⇒ no caret line.
        let err = GlobError::new("range overflow", 0, CURLE_URL_MALFORMAT);
        assert_eq!(err.diagnostic("anything"), "range overflow");
        assert_eq!(err.to_stderr_string("anything"), "curl: (3) range overflow\n");
    }

    // ---- misc parity ----

    #[test]
    fn single_value_range_requires_step_one() {
        // [5-5] is valid (one value); [5-5:2] is not.
        let (n, urls) = expand("[5-5]");
        assert_eq!(n, 1);
        assert_eq!(urls, vec!["5".to_string()]);
        assert!(glob_url("[5-5:2]").is_err());
    }

    #[test]
    fn bad_range_specification_for_non_alnum() {
        let err = glob_url("[-]").unwrap_err();
        assert_eq!(err.message(), "bad range specification");
    }

    #[test]
    fn glob_inuse_reflects_patterns() {
        let (glob, _n) = glob_url("http://x/[1-2]").unwrap();
        assert!(glob.glob_inuse());
        assert_eq!(glob.glob_count(), 1);
    }

    #[test]
    fn multibyte_literal_is_preserved() {
        // Non-ASCII bytes around an ASCII glob metacharacter must round-trip.
        let (n, urls) = expand("café-{1,2}");
        assert_eq!(n, 2);
        assert_eq!(
            urls,
            vec!["café-1".to_string(), "café-2".to_string()]
        );
    }

    #[test]
    fn upper_to_lower_span_too_wide_is_bad() {
        // [A-z] spans 57 > 25 ⇒ curl rejects it as a bad range.
        let err = glob_url("[A-z]").unwrap_err();
        assert_eq!(err.message(), "bad range");
    }
}
