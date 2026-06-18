// SPDX-License-Identifier: curl
//
// Memory-safe Rust port of curl's modern string-cursor parser.
//
// This module is the idiomatic, `unsafe`-free Rust reimplementation of
// libcurl's `lib/curlx/strparse.c` / `lib/curlx/strparse.h`. It provides a
// small, bounds-checked tokenizing parser built around a byte-slice cursor
// (`Str`) plus the family of `curlx_str_*` helpers that callers across the
// crate rely on to chop request lines, headers, URLs, config files, and
// numeric fields into typed pieces.
//
// # Relationship to the C oracle
//
// The C sources are consulted as a *behavioral and return-code oracle*, not
// transliterated line-by-line. Every public function below reproduces the
// exact observable behavior of its C counterpart — including the precise
// `STRE_*` integer it returns and the precise cursor advancement — while being
// expressed with safe Rust slices instead of raw `const char *` pointers.
//
// The C `struct Curl_str { const char *str; size_t len; }` (a pointer/length
// pair) and the companion `const char **linep` walking cursor are unified here
// into a single [`Str`] type that owns a `&[u8]` view of the *remaining* input.
// Capturing a token therefore means handing back a sub-slice of the original
// buffer (zero-copy), exactly mirroring how the C code points `out->str` into
// the source string.
//
// # Memory safety
//
// Per the project memory-safety mandate (AAP §0.7.1) this module contains
// **zero `unsafe`** and is compiled under `#![forbid(unsafe_code)]`. The cursor
// is a byte slice, never a raw pointer; every read is bounds-checked and the
// parser can never index past the end of its input.
//
// # The `strcase` home
//
// curl's ASCII case-insensitive comparison helpers live *here* (folded into
// this module on purpose — there is deliberately no separate `strcase.rs`).
// `util/mod.rs` re-exports them as `crate::util::strcase`, e.g.:
//
// ```ignore
// pub mod strcase {
//     pub use super::strparse::{
//         curlx_str_casecompare, curlx_str_cmp, strcasecompare, strncasecompare,
//     };
// }
// ```
//
// All case folding here is **ASCII-only** (parity with curl's `tolower`/
// `toupper`, which only fold `A`–`Z`). Non-ASCII bytes are compared literally;
// Unicode case folding is never performed.
//
// # `STRE_*` error codes
//
// The C API returns a bare `int` whose value is one of the `STRE_*` macros.
// Those integer values are observable in callers (some compare the raw `int`
// against a constant), so they are preserved exactly. Internally this module
// prefers an idiomatic [`Result<(), StrError>`]; the [`StrError`] discriminants
// are `#[repr(i32)]` and equal the C macro values 1:1, and the raw constants
// are also re-exported in the [`stre`] submodule for callers that compare
// against an `i32` directly. `Result::Ok(())` corresponds to `STRE_OK` (`0`).

#![forbid(unsafe_code)]
// This module is a foundational, dependency-free port of curl's complete
// `curlx_str_*` parsing surface (plus the `strcase` compare helpers). The full
// API is provided for parity even though, in a partially assembled workspace,
// not every entrypoint yet has an in-crate consumer (the protocol, header, and
// date-parsing modules that call into it are authored in parallel). The exact
// set of items reachable from the crate's public API also depends on how
// `util/mod.rs` re-exports this module. Allowing `dead_code` here keeps this
// module self-contained and prevents those construction-order artifacts from
// tripping the workspace's `-D warnings` gate; it does not mask defects, as the
// private helpers are all exercised by the public functions and the tests.
#![allow(dead_code)]

/// Parser result codes, mirroring curl's `STRE_*` macros from
/// `lib/curlx/strparse.h`.
///
/// The `#[repr(i32)]` discriminants are identical to the C macro integer
/// values, so converting a variant to `i32` (via [`StrError::as_i32`] or an
/// `as` cast) yields the exact value the C function would have returned. The
/// success code `STRE_OK == 0` is represented by `Result::Ok(())` in idiomatic
/// usage and by the [`StrError::Ok`] variant when an explicit code is needed.
///
/// | Variant            | C macro         | Value |
/// |--------------------|-----------------|-------|
/// | [`StrError::Ok`]       | `STRE_OK`       | 0 |
/// | [`StrError::Big`]      | `STRE_BIG`      | 1 |
/// | [`StrError::Short`]    | `STRE_SHORT`    | 2 |
/// | [`StrError::BegQuote`] | `STRE_BEGQUOTE` | 3 |
/// | [`StrError::EndQuote`] | `STRE_ENDQUOTE` | 4 |
/// | [`StrError::Byte`]     | `STRE_BYTE`     | 5 |
/// | [`StrError::Newline`]  | `STRE_NEWLINE`  | 6 |
/// | [`StrError::Overflow`] | `STRE_OVERFLOW` | 7 |
/// | [`StrError::NoNum`]    | `STRE_NO_NUM`   | 8 |
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StrError {
    /// `STRE_OK` (0): success. Idiomatically represented by `Result::Ok(())`.
    Ok = 0,
    /// `STRE_BIG` (1): a captured token exceeded the caller-provided maximum.
    Big = 1,
    /// `STRE_SHORT` (2): the captured token was empty (zero bytes long).
    Short = 2,
    /// `STRE_BEGQUOTE` (3): a quoted word did not start with `"`.
    BegQuote = 3,
    /// `STRE_ENDQUOTE` (4): a quoted word was not terminated by a closing `"`.
    EndQuote = 4,
    /// `STRE_BYTE` (5): an expected single byte was not present.
    Byte = 5,
    /// `STRE_NEWLINE` (6): a newline (CR or LF) was expected but not found.
    Newline = 6,
    /// `STRE_OVERFLOW` (7): an arithmetic or cursor overflow occurred.
    Overflow = 7,
    /// `STRE_NO_NUM` (8): no numeric digit was present where one was required.
    NoNum = 8,
}

impl StrError {
    /// Returns the raw C `STRE_*` integer value for this code.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Maps a raw C `STRE_*` integer back to a [`StrError`], or `None` if the
    /// value is not a defined code.
    #[must_use]
    pub const fn from_i32(value: i32) -> Option<StrError> {
        match value {
            0 => Some(StrError::Ok),
            1 => Some(StrError::Big),
            2 => Some(StrError::Short),
            3 => Some(StrError::BegQuote),
            4 => Some(StrError::EndQuote),
            5 => Some(StrError::Byte),
            6 => Some(StrError::Newline),
            7 => Some(StrError::Overflow),
            8 => Some(StrError::NoNum),
            _ => None,
        }
    }
}

/// Raw `STRE_*` integer constants, preserved exactly from
/// `lib/curlx/strparse.h`.
///
/// These exist for callers that mirror the C habit of comparing a returned
/// `int` against a named constant. They are identical to the discriminants of
/// [`StrError`]; prefer the typed [`Result`] API where practical.
pub mod stre {
    /// Success.
    pub const STRE_OK: i32 = 0;
    /// A captured token exceeded the caller-provided maximum length.
    pub const STRE_BIG: i32 = 1;
    /// The captured token was empty (zero bytes long).
    pub const STRE_SHORT: i32 = 2;
    /// A quoted word did not start with `"`.
    pub const STRE_BEGQUOTE: i32 = 3;
    /// A quoted word was not terminated by a closing `"`.
    pub const STRE_ENDQUOTE: i32 = 4;
    /// An expected single byte was not present.
    pub const STRE_BYTE: i32 = 5;
    /// A newline (CR or LF) was expected but not found.
    pub const STRE_NEWLINE: i32 = 6;
    /// An arithmetic or cursor overflow occurred.
    pub const STRE_OVERFLOW: i32 = 7;
    /// No numeric digit was present where one was required.
    pub const STRE_NO_NUM: i32 = 8;
}

/// The largest value a curl `curl_off_t` can hold: a 63-bit maximum
/// (`i64::MAX`, i.e. `0x7FFF_FFFF_FFFF_FFFF`).
///
/// curl's numeric parsers operate on the signed `curl_off_t` type but only
/// ever produce non-negative results, so this port uses `u64` for parsed
/// values and exposes the same upper bound. It backs [`Str::curlx_str_numblanks`],
/// matching the C `CURL_OFF_T_MAX` cap.
pub const CURL_OFF_T_MAX: u64 = i64::MAX as u64;

/// Returns `true` for the bytes curl's `ISNEWLINE` macro treats as a newline:
/// LF (`\n`) or CR (`\r`).
#[inline]
const fn is_newline(byte: u8) -> bool {
    byte == b'\n' || byte == b'\r'
}

/// Returns `true` for the bytes curl's `ISBLANK` macro treats as blank:
/// space (` `) or horizontal tab (`\t`).
#[inline]
const fn is_blank(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

/// Returns the binary value of a single hexadecimal digit byte, or `None` if
/// the byte is not a valid hex digit.
///
/// This is the safe replacement for curl's `curlx_hexval` macro (and its
/// backing `curlx_hexasciitable[]`). The C macro is documented as only valid
/// for known-good hex input; this version validates instead, returning `None`
/// for any non-hex byte. `b'0'..=b'9'` map to `0..=9`, and both `b'a'..=b'f'`
/// and `b'A'..=b'F'` map to `10..=15`.
#[must_use]
pub const fn curlx_hexval(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Returns the numeric value of `byte` interpreted as a digit in `base`
/// (which must be 8, 10, or 16), or `None` if `byte` is not a valid digit for
/// that base.
///
/// This unifies curl's `valid_digit()` check and `curlx_hexval()` lookup: a
/// byte is accepted only when its decoded value is strictly less than `base`,
/// so e.g. `'8'` and `'9'` are rejected for octal and letters are rejected for
/// decimal.
#[inline]
fn digit_value(byte: u8, base: u64) -> Option<u64> {
    let value: u64 = match byte {
        b'0'..=b'9' => u64::from(byte - b'0'),
        b'a'..=b'f' => u64::from(byte - b'a') + 10,
        b'A'..=b'F' => u64::from(byte - b'A') + 10,
        _ => return None,
    };
    if value < base {
        Some(value)
    } else {
        None
    }
}

/// A bounds-checked, zero-copy string cursor over a byte buffer.
///
/// `Str` is the Rust counterpart of curl's `struct Curl_str` *and* its
/// `const char **linep` walking pointer, unified into one type. It holds a
/// `&[u8]` view of the bytes that remain to be parsed. The parsing methods that
/// take `&mut self` advance this view in place (consuming input), and the
/// tokenizers additionally write the captured token into an output `Str` whose
/// slice borrows from the same underlying buffer.
///
/// curl operates on raw bytes (HTTP headers, URLs and config lines are not
/// guaranteed to be UTF-8), so the cursor is a `&[u8]` rather than a `&str`.
/// The slice's length *is* the extent of the string: end-of-slice is treated as
/// end-of-input, exactly as the C code treats its terminating NUL.
///
/// `Str` is `Copy`, so a cursor can be cheaply snapshotted (e.g. to attempt a
/// parse and roll back on failure) by simply copying it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Str<'a> {
    /// The not-yet-consumed bytes. For a captured token this is the token's
    /// bytes; for a walking cursor it is the remaining input.
    s: &'a [u8],
}

impl<'a> Default for Str<'a> {
    /// An empty cursor, equivalent to C's `curlx_str_init` result
    /// (`{ str = NULL, len = 0 }`).
    fn default() -> Self {
        Str { s: &[] }
    }
}

impl<'a> Str<'a> {
    /// Creates a cursor over the bytes of `input`.
    ///
    /// Equivalent to assigning `{ str = input, len = strlen(input) }` in C.
    /// The string's UTF-8 bytes are used as-is; no validation beyond `&str`'s
    /// own invariant is performed.
    #[must_use]
    pub const fn new(input: &'a str) -> Self {
        Str {
            s: input.as_bytes(),
        }
    }

    /// Creates a cursor over a raw byte slice.
    ///
    /// This is the byte-oriented constructor that most closely matches curl's
    /// `curlx_str_assign(out, str, len)`, where the pointer/length pair is a
    /// `&[u8]`.
    #[must_use]
    pub const fn from_bytes(input: &'a [u8]) -> Self {
        Str { s: input }
    }

    /// Returns an empty cursor.
    ///
    /// Safe-Rust analogue of C's `curlx_str_init(out)`, which resets a
    /// `struct Curl_str` to `{ NULL, 0 }`. Prefer [`Str::default`] in idiomatic
    /// code; this name is provided for parity with the C API surface.
    #[must_use]
    pub const fn curlx_str_init() -> Self {
        Str { s: &[] }
    }

    /// Repoints this cursor at `input`.
    ///
    /// Safe-Rust analogue of C's `curlx_str_assign(out, str, len)`: the
    /// pointer/length pair becomes a single slice.
    pub fn curlx_str_assign(&mut self, input: &'a [u8]) {
        self.s = input;
    }

    /// Returns the remaining (or, for a captured token, the whole) byte slice.
    ///
    /// Equivalent to the C `curlx_str(x)` macro, which yields `x->str`. Because
    /// a slice already carries its length, the returned value is the complete
    /// token — there is no need to separately consult [`Str::curlx_strlen`] to
    /// know where it ends.
    #[must_use]
    pub const fn curlx_str(&self) -> &'a [u8] {
        self.s
    }

    /// Returns the number of bytes remaining in (or captured by) the cursor.
    ///
    /// Equivalent to the C `curlx_strlen(x)` macro (`x->len`).
    #[must_use]
    pub const fn curlx_strlen(&self) -> usize {
        self.s.len()
    }

    /// Returns `true` when the cursor holds no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.s.is_empty()
    }

    /// Advances the cursor by `num` bytes, dropping them from the front.
    ///
    /// Mirrors C's `curlx_str_nudge`: succeeds when `num <= len`, otherwise
    /// leaves the cursor untouched and returns [`StrError::Overflow`]
    /// (`STRE_OVERFLOW`).
    ///
    /// # Errors
    ///
    /// Returns [`StrError::Overflow`] if `num` is greater than the number of
    /// bytes remaining.
    pub fn curlx_str_nudge(&mut self, num: usize) -> Result<(), StrError> {
        if num <= self.s.len() {
            self.s = &self.s[num..];
            Ok(())
        } else {
            Err(StrError::Overflow)
        }
    }

    /// Captures bytes up to (but not including) the first `delim` byte, or up
    /// to the end of the input, whichever comes first.
    ///
    /// On success `out` is set to the captured token, this cursor is advanced
    /// to point *at* the delimiter (or at end-of-input), and `Ok(())` is
    /// returned. The captured token is always at least one byte long.
    ///
    /// Mirrors C's `curlx_str_until`. Note the precise C semantics, which this
    /// reproduces exactly: the delimiter need *not* be present — reaching the
    /// end of the input yields the bytes seen so far. [`StrError::Short`] is
    /// returned only when the token would be empty (the very first byte is the
    /// delimiter, or the input is empty), never merely because the delimiter is
    /// absent.
    ///
    /// `out` is reset to empty on entry, so it is left empty on any error.
    ///
    /// # Errors
    ///
    /// - [`StrError::Big`] (`STRE_BIG`) if the token would exceed `max` bytes.
    /// - [`StrError::Short`] (`STRE_SHORT`) if the token would be empty.
    pub fn curlx_str_until(
        &mut self,
        out: &mut Str<'a>,
        max: usize,
        delim: u8,
    ) -> Result<(), StrError> {
        *out = Str::default();
        let s = self.s;
        let mut len = 0usize;
        while len < s.len() && s[len] != delim {
            len += 1;
            if len > max {
                return Err(StrError::Big);
            }
        }
        if len == 0 {
            return Err(StrError::Short);
        }
        out.s = &s[..len];
        self.s = &s[len..];
        Ok(())
    }

    /// Captures bytes up to the first space (` `) or end of input.
    ///
    /// Convenience wrapper over [`Str::curlx_str_until`] with a space
    /// delimiter, mirroring C's `curlx_str_word`. The same error and
    /// at-least-one-byte rules apply.
    ///
    /// # Errors
    ///
    /// Propagates [`StrError::Big`] / [`StrError::Short`] from
    /// [`Str::curlx_str_until`].
    pub fn curlx_str_word(&mut self, out: &mut Str<'a>, max: usize) -> Result<(), StrError> {
        self.curlx_str_until(out, max, b' ')
    }

    /// Captures bytes up to the first newline byte (CR or LF) or end of input.
    ///
    /// Mirrors C's `curlx_str_untilnl`, which stops at a byte for which
    /// `ISNEWLINE` is true. As with [`Str::curlx_str_until`], the token is at
    /// least one byte long and the cursor is left pointing at the newline (or
    /// at end-of-input).
    ///
    /// `out` is reset to empty on entry.
    ///
    /// # Errors
    ///
    /// - [`StrError::Big`] (`STRE_BIG`) if the token would exceed `max` bytes.
    /// - [`StrError::Short`] (`STRE_SHORT`) if the token would be empty.
    pub fn curlx_str_untilnl(&mut self, out: &mut Str<'a>, max: usize) -> Result<(), StrError> {
        *out = Str::default();
        let s = self.s;
        let mut len = 0usize;
        while len < s.len() && !is_newline(s[len]) {
            len += 1;
            if len > max {
                return Err(StrError::Big);
            }
        }
        if len == 0 {
            return Err(StrError::Short);
        }
        out.s = &s[..len];
        self.s = &s[len..];
        Ok(())
    }

    /// Parses a double-quoted word, honoring backslash escapes.
    ///
    /// The input must begin with `"`. Bytes are captured until the matching
    /// closing `"`. A backslash that is followed by at least one more byte
    /// escapes that byte, so an escaped quote (`\"`) does not terminate the
    /// word. On success `out` is set to the content *between* the quotes and
    /// the cursor is advanced past the closing quote.
    ///
    /// Mirrors C's `curlx_str_quotedword`. As in C, the captured token is the
    /// raw inner bytes **including** any backslash escape characters — the word
    /// is not un-escaped here; both the backslash and the byte it escapes are
    /// part of (and counted toward the `max` of) the token.
    ///
    /// `out` is reset to empty on entry.
    ///
    /// # Errors
    ///
    /// - [`StrError::BegQuote`] (`STRE_BEGQUOTE`) if the input does not start
    ///   with `"`.
    /// - [`StrError::Big`] (`STRE_BIG`) if the inner content would exceed `max`
    ///   bytes.
    /// - [`StrError::EndQuote`] (`STRE_ENDQUOTE`) if no closing `"` is found.
    pub fn curlx_str_quotedword(
        &mut self,
        out: &mut Str<'a>,
        max: usize,
    ) -> Result<(), StrError> {
        *out = Str::default();
        let s = self.s;
        if s.is_empty() || s[0] != b'"' {
            return Err(StrError::BegQuote);
        }
        // `i` walks the source bytes (starting just past the opening quote);
        // `len` counts the bytes that belong to the captured token.
        let mut i = 1usize;
        let mut len = 0usize;
        while i < s.len() && s[i] != b'"' {
            // A backslash followed by another byte escapes it: count the
            // backslash, then fall through to count the escaped byte too.
            if s[i] == b'\\' && (i + 1) < s.len() {
                i += 1;
                len += 1;
                if len > max {
                    return Err(StrError::Big);
                }
            }
            i += 1;
            len += 1;
            if len > max {
                return Err(StrError::Big);
            }
        }
        if i >= s.len() || s[i] != b'"' {
            return Err(StrError::EndQuote);
        }
        out.s = &s[1..1 + len];
        self.s = &s[i + 1..];
        Ok(())
    }

    /// Consumes exactly one byte, which must equal `byte`.
    ///
    /// Mirrors C's `curlx_str_single`. If the cursor is empty or the leading
    /// byte differs, the cursor is left untouched and [`StrError::Byte`]
    /// (`STRE_BYTE`) is returned.
    ///
    /// # Errors
    ///
    /// Returns [`StrError::Byte`] if the next byte is not `byte` (including
    /// when the cursor is empty).
    pub fn curlx_str_single(&mut self, byte: u8) -> Result<(), StrError> {
        if self.s.is_empty() || self.s[0] != byte {
            return Err(StrError::Byte);
        }
        self.s = &self.s[1..];
        Ok(())
    }

    /// Consumes exactly one space (` `) byte.
    ///
    /// Convenience wrapper over [`Str::curlx_str_single`], mirroring C's
    /// `curlx_str_singlespace`.
    ///
    /// # Errors
    ///
    /// Returns [`StrError::Byte`] if the next byte is not a space.
    pub fn curlx_str_singlespace(&mut self) -> Result<(), StrError> {
        self.curlx_str_single(b' ')
    }

    /// Consumes a single newline byte (CR or LF).
    ///
    /// Mirrors C's `curlx_str_newline`. If the leading byte is not a newline
    /// (including when the cursor is empty) the cursor is left untouched and
    /// [`StrError::Newline`] (`STRE_NEWLINE`) is returned.
    ///
    /// # Errors
    ///
    /// Returns [`StrError::Newline`] if the next byte is not CR or LF.
    pub fn curlx_str_newline(&mut self) -> Result<(), StrError> {
        if !self.s.is_empty() && is_newline(self.s[0]) {
            self.s = &self.s[1..];
            return Ok(());
        }
        Err(StrError::Newline)
    }

    /// Skips leading blank bytes (spaces and tabs), returning how many were
    /// skipped.
    ///
    /// Mirrors C's `curlx_str_passblanks`, which advances the cursor over all
    /// leading `ISBLANK` bytes. The C function returns `void`; this port also
    /// reports the count, which callers may ignore.
    pub fn curlx_str_passblanks(&mut self) -> usize {
        let mut skipped = 0usize;
        while !self.s.is_empty() && is_blank(self.s[0]) {
            self.s = &self.s[1..];
            skipped += 1;
        }
        skipped
    }

    /// Skips leading blanks, then parses a non-negative decimal number capped
    /// at [`CURL_OFF_T_MAX`].
    ///
    /// Mirrors C's `curlx_str_numblanks`: `curlx_str_passblanks` followed by
    /// `curlx_str_number(.., CURL_OFF_T_MAX)`. On success the parsed value is
    /// written to `num` and the cursor is advanced past the digits; on error
    /// `num` is set to `0`.
    ///
    /// # Errors
    ///
    /// - [`StrError::NoNum`] (`STRE_NO_NUM`) if no digit follows the blanks.
    /// - [`StrError::Overflow`] (`STRE_OVERFLOW`) if the value exceeds
    ///   [`CURL_OFF_T_MAX`].
    pub fn curlx_str_numblanks(&mut self, num: &mut u64) -> Result<(), StrError> {
        self.curlx_str_passblanks();
        self.curlx_str_number(num, CURL_OFF_T_MAX)
    }

    /// Captures the leading run of bytes that are **not** present in `reject`
    /// (the complement-span operation, like C's `strcspn`).
    ///
    /// On success `out` is set to that run and the cursor is advanced to the
    /// first rejected byte (or end-of-input). Mirrors C's `curlx_str_cspn`.
    ///
    /// `out` is left empty on error.
    ///
    /// # Errors
    ///
    /// Returns [`StrError::Short`] (`STRE_SHORT`) if the very first byte is in
    /// `reject` (i.e. the run would be empty).
    pub fn curlx_str_cspn(&mut self, out: &mut Str<'a>, reject: &[u8]) -> Result<(), StrError> {
        let s = self.s;
        let mut len = 0usize;
        while len < s.len() && !reject.contains(&s[len]) {
            len += 1;
        }
        if len != 0 {
            out.s = &s[..len];
            self.s = &s[len..];
            Ok(())
        } else {
            *out = Str::default();
            Err(StrError::Short)
        }
    }

    /// Trims leading and trailing blank bytes (spaces and tabs) from the
    /// cursor's current view.
    ///
    /// Mirrors C's `curlx_str_trimblanks`, which is applied to a captured
    /// token. Because tokens are slices of the original buffer, trimming simply
    /// re-slices the view; no data is copied.
    pub fn curlx_str_trimblanks(&mut self) {
        while !self.s.is_empty() && is_blank(self.s[0]) {
            self.s = &self.s[1..];
        }
        while !self.s.is_empty() && is_blank(self.s[self.s.len() - 1]) {
            self.s = &self.s[..self.s.len() - 1];
        }
    }
}

impl<'a> Str<'a> {
    /// Shared implementation behind the decimal/hex/octal parsers.
    ///
    /// Parses a non-negative integer in `base` (which must be 8, 10, or 16),
    /// requiring at least one digit and capping the value at `max`. There is no
    /// support for a sign, leading whitespace, or a base prefix (`0x`, `0`);
    /// leading zeroes are accepted. On success the parsed value is returned and
    /// the cursor is advanced past the digits. On error the cursor is left
    /// untouched.
    ///
    /// Overflow is detected with checked arithmetic so it can never panic or
    /// wrap. This mirrors curl's `str_num_base`, including its two-branch
    /// structure: when `max < base` the product is formed first and then
    /// compared against `max`, otherwise the canonical
    /// `num > (max - digit) / base` pre-multiplication check is used (which is
    /// well-defined because `digit < base <= max` there).
    ///
    /// # Errors
    ///
    /// - [`StrError::NoNum`] (`STRE_NO_NUM`) if the first byte is not a digit.
    /// - [`StrError::Overflow`] (`STRE_OVERFLOW`) if the value exceeds `max`.
    fn str_num_base(&mut self, base: u64, max: u64) -> Result<u64, StrError> {
        let s = self.s;
        // At least one valid digit is required up front.
        if s.is_empty() || digit_value(s[0], base).is_none() {
            return Err(StrError::NoNum);
        }

        let mut num: u64 = 0;
        let mut i = 0usize;

        if max < base {
            // Low-`max` special case: accumulate first, then range-check. The
            // running value stays tiny (bounded by `max < base <= 16` on every
            // successful step), but checked arithmetic guards the path anyway.
            loop {
                let digit = digit_value(s[i], base).unwrap_or(0);
                i += 1;
                num = num
                    .checked_mul(base)
                    .and_then(|v| v.checked_add(digit))
                    .ok_or(StrError::Overflow)?;
                if num > max {
                    return Err(StrError::Overflow);
                }
                if i >= s.len() || digit_value(s[i], base).is_none() {
                    break;
                }
            }
        } else {
            loop {
                let digit = digit_value(s[i], base).unwrap_or(0);
                i += 1;
                // `max - digit` cannot underflow: `digit < base <= max`.
                if num > (max - digit) / base {
                    return Err(StrError::Overflow);
                }
                num = num * base + digit;
                if i >= s.len() || digit_value(s[i], base).is_none() {
                    break;
                }
            }
        }

        self.s = &s[i..];
        Ok(num)
    }

    /// Parses a non-negative decimal number, capped at `max`.
    ///
    /// Mirrors C's `curlx_str_number`. No sign, no leading whitespace, no base
    /// prefix; leading zeroes are accepted. On success the value is written to
    /// `num` and the cursor advances past the digits; on error `num` is reset
    /// to `0` and the cursor is left untouched.
    ///
    /// # Errors
    ///
    /// - [`StrError::NoNum`] (`STRE_NO_NUM`) if the first byte is not a digit.
    /// - [`StrError::Overflow`] (`STRE_OVERFLOW`) if the value exceeds `max`.
    pub fn curlx_str_number(&mut self, num: &mut u64, max: u64) -> Result<(), StrError> {
        *num = 0;
        *num = self.str_num_base(10, max)?;
        Ok(())
    }

    /// Parses a non-negative hexadecimal number, capped at `max`.
    ///
    /// Mirrors C's `curlx_str_hex`. Accepts upper- and lower-case digits; no
    /// `0x` prefix, sign, or leading whitespace; leading zeroes are accepted.
    /// On success the value is written to `num`; on error `num` is reset to `0`.
    ///
    /// # Errors
    ///
    /// - [`StrError::NoNum`] (`STRE_NO_NUM`) if the first byte is not a hex
    ///   digit.
    /// - [`StrError::Overflow`] (`STRE_OVERFLOW`) if the value exceeds `max`.
    pub fn curlx_str_hex(&mut self, num: &mut u64, max: u64) -> Result<(), StrError> {
        *num = 0;
        *num = self.str_num_base(16, max)?;
        Ok(())
    }

    /// Parses a non-negative octal number, capped at `max`.
    ///
    /// Mirrors C's `curlx_str_octal`. No `0` prefix, sign, or leading
    /// whitespace; leading zeroes are accepted; `8` and `9` are not octal
    /// digits and terminate the number. On success the value is written to
    /// `num`; on error `num` is reset to `0`.
    ///
    /// # Errors
    ///
    /// - [`StrError::NoNum`] (`STRE_NO_NUM`) if the first byte is not an octal
    ///   digit.
    /// - [`StrError::Overflow`] (`STRE_OVERFLOW`) if the value exceeds `max`.
    pub fn curlx_str_octal(&mut self, num: &mut u64, max: u64) -> Result<(), StrError> {
        *num = 0;
        *num = self.str_num_base(8, max)?;
        Ok(())
    }
}

/// ASCII case-insensitive equality between a parsed token and a check string.
///
/// Returns `true` when the cursor's current bytes equal `check` ignoring ASCII
/// letter case. Mirrors C's `curlx_str_casecompare`, which checks the lengths
/// match and then performs a case-insensitive byte comparison.
///
/// Folding is ASCII-only (matching curl's `tolower`): `b'A'..=b'Z'` fold to
/// `b'a'..=b'z'` and nothing else. Bytes outside the ASCII letter range — every
/// byte `>= 0x80` included — are compared literally, so this never applies
/// Unicode case folding.
#[must_use]
pub fn curlx_str_casecompare(s: &Str<'_>, check: &str) -> bool {
    let check = check.as_bytes();
    s.curlx_strlen() == check.len() && s.curlx_str().eq_ignore_ascii_case(check)
}

/// Case-sensitive (exact) byte equality between a parsed token and a check
/// string.
///
/// Returns `true` when the cursor's current bytes equal `check` exactly.
/// Mirrors C's `curlx_str_cmp` for the (always-present in Rust) non-null
/// `check`: lengths must match and the bytes must be identical.
#[must_use]
pub fn curlx_str_cmp(s: &Str<'_>, check: &str) -> bool {
    let check = check.as_bytes();
    s.curlx_strlen() == check.len() && s.curlx_str() == check
}

/// ASCII case-insensitive equality of two byte strings.
///
/// This is the free-standing, cursor-less helper that backs the
/// `crate::util::strcase` re-export consumed by sibling modules such as
/// `headers.rs`. It mirrors curl's classic `strcasecompare` /
/// `Curl_strcasecompare`: two strings are equal when they have the same length
/// and match byte-for-byte ignoring ASCII letter case.
///
/// Folding is ASCII-only; non-ASCII bytes are compared literally.
#[must_use]
pub fn strcasecompare(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// ASCII case-insensitive equality of the first `n` bytes of two byte strings.
///
/// This is the free-standing, cursor-less helper that backs the
/// `crate::util::strcase` re-export. It mirrors curl's `Curl_strncasecompare`,
/// including its NUL-terminated edge semantics, reproduced safely for byte
/// slices: the leading `min(n, a.len(), b.len())` bytes are compared ignoring
/// ASCII case, and the result is `true` only when those bytes all match **and**
/// either a full `n` bytes were compared or the two slices have equal length
/// (so a shorter slice cannot spuriously match a longer prefix).
///
/// Folding is ASCII-only; non-ASCII bytes are compared literally. The
/// comparison is fully bounds-checked and never panics regardless of how `n`
/// relates to the slice lengths.
#[must_use]
pub fn strncasecompare(a: &[u8], b: &[u8], n: usize) -> bool {
    let compare_len = n.min(a.len()).min(b.len());
    if !a[..compare_len].eq_ignore_ascii_case(&b[..compare_len]) {
        return false;
    }
    if n <= a.len() && n <= b.len() {
        // Compared a full `n` matching bytes.
        true
    } else {
        // One slice ended before `n`; equal only if both are the same length.
        a.len() == b.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- STRE_* code parity ---------------------------------------------

    #[test]
    fn stre_constants_match_c_header_exactly() {
        // These are the exact integer values from lib/curlx/strparse.h and are
        // observable in callers; any drift breaks parity.
        assert_eq!(stre::STRE_OK, 0);
        assert_eq!(stre::STRE_BIG, 1);
        assert_eq!(stre::STRE_SHORT, 2);
        assert_eq!(stre::STRE_BEGQUOTE, 3);
        assert_eq!(stre::STRE_ENDQUOTE, 4);
        assert_eq!(stre::STRE_BYTE, 5);
        assert_eq!(stre::STRE_NEWLINE, 6);
        assert_eq!(stre::STRE_OVERFLOW, 7);
        assert_eq!(stre::STRE_NO_NUM, 8);
    }

    #[test]
    fn strerror_discriminants_match_constants() {
        assert_eq!(StrError::Ok.as_i32(), stre::STRE_OK);
        assert_eq!(StrError::Big.as_i32(), stre::STRE_BIG);
        assert_eq!(StrError::Short.as_i32(), stre::STRE_SHORT);
        assert_eq!(StrError::BegQuote.as_i32(), stre::STRE_BEGQUOTE);
        assert_eq!(StrError::EndQuote.as_i32(), stre::STRE_ENDQUOTE);
        assert_eq!(StrError::Byte.as_i32(), stre::STRE_BYTE);
        assert_eq!(StrError::Newline.as_i32(), stre::STRE_NEWLINE);
        assert_eq!(StrError::Overflow.as_i32(), stre::STRE_OVERFLOW);
        assert_eq!(StrError::NoNum.as_i32(), stre::STRE_NO_NUM);
    }

    #[test]
    fn strerror_from_i32_round_trips_and_rejects_unknown() {
        for code in 0..=8 {
            let err = StrError::from_i32(code).expect("0..=8 are defined codes");
            assert_eq!(err.as_i32(), code);
        }
        assert_eq!(StrError::from_i32(-1), None);
        assert_eq!(StrError::from_i32(9), None);
        assert_eq!(StrError::from_i32(99999), None);
    }

    // ---- Str construction / accessors -----------------------------------

    #[test]
    fn construction_and_accessors() {
        let s = Str::new("hello");
        assert_eq!(s.curlx_str(), b"hello");
        assert_eq!(s.curlx_strlen(), 5);
        assert!(!s.is_empty());

        let b = Str::from_bytes(&[0x00, 0xFF, 0x7F]);
        assert_eq!(b.curlx_strlen(), 3);
        assert_eq!(b.curlx_str(), &[0x00, 0xFF, 0x7F]);

        let empty = Str::curlx_str_init();
        assert!(empty.is_empty());
        assert_eq!(empty.curlx_strlen(), 0);
        assert_eq!(Str::default(), Str::curlx_str_init());

        let mut a = Str::new("first");
        a.curlx_str_assign(b"second");
        assert_eq!(a.curlx_str(), b"second");
    }

    // ---- nudge ----------------------------------------------------------

    #[test]
    fn nudge_advances_and_detects_overflow() {
        let mut s = Str::new("abcdef");
        assert_eq!(s.curlx_str_nudge(2), Ok(()));
        assert_eq!(s.curlx_str(), b"cdef");

        // Nudging by exactly the remaining length is allowed and empties it.
        assert_eq!(s.curlx_str_nudge(4), Ok(()));
        assert!(s.is_empty());

        // One past the end is STRE_OVERFLOW, leaving the cursor untouched.
        let mut t = Str::new("xy");
        assert_eq!(t.curlx_str_nudge(3), Err(StrError::Overflow));
        assert_eq!(t.curlx_str(), b"xy");
    }

    // ---- until / word ---------------------------------------------------

    #[test]
    fn until_basic_and_cursor_position() {
        let mut s = Str::new("abc;def");
        let mut out = Str::default();
        assert_eq!(s.curlx_str_until(&mut out, 100, b';'), Ok(()));
        assert_eq!(out.curlx_str(), b"abc");
        // Cursor is left pointing AT the delimiter, not past it.
        assert_eq!(s.curlx_str(), b";def");
        // The delimiter can then be consumed explicitly.
        assert_eq!(s.curlx_str_single(b';'), Ok(()));
        assert_eq!(s.curlx_str(), b"def");
    }

    #[test]
    fn until_without_delimiter_captures_to_end() {
        // Parity with C: a missing delimiter is NOT an error; the bytes seen so
        // far (the whole remaining input) are returned.
        let mut s = Str::new("abc");
        let mut out = Str::default();
        assert_eq!(s.curlx_str_until(&mut out, 100, b';'), Ok(()));
        assert_eq!(out.curlx_str(), b"abc");
        assert!(s.is_empty());
    }

    #[test]
    fn until_empty_token_is_short() {
        // Delimiter as the very first byte -> empty token -> STRE_SHORT.
        let mut s = Str::new(";rest");
        let mut out = Str::new("stale");
        assert_eq!(s.curlx_str_until(&mut out, 100, b';'), Err(StrError::Short));
        // `out` is reset on error.
        assert!(out.is_empty());

        // Empty input -> STRE_SHORT as well.
        let mut e = Str::new("");
        let mut o2 = Str::default();
        assert_eq!(e.curlx_str_until(&mut o2, 100, b';'), Err(StrError::Short));
    }

    #[test]
    fn until_respects_max_boundary() {
        // A token of exactly `max` bytes is accepted.
        let mut ok = Str::new("abc;");
        let mut out = Str::default();
        assert_eq!(ok.curlx_str_until(&mut out, 3, b';'), Ok(()));
        assert_eq!(out.curlx_str(), b"abc");

        // `max + 1` bytes before the delimiter is STRE_BIG.
        let mut big = Str::new("abcd;");
        let mut out2 = Str::default();
        assert_eq!(big.curlx_str_until(&mut out2, 3, b';'), Err(StrError::Big));
        assert!(out2.is_empty());
    }

    #[test]
    fn word_stops_at_space() {
        let mut s = Str::new("token rest");
        let mut out = Str::default();
        assert_eq!(s.curlx_str_word(&mut out, 100), Ok(()));
        assert_eq!(out.curlx_str(), b"token");
        assert_eq!(s.curlx_str(), b" rest");

        // Leading space -> empty word -> STRE_SHORT.
        let mut lead = Str::new(" x");
        let mut o2 = Str::default();
        assert_eq!(lead.curlx_str_word(&mut o2, 100), Err(StrError::Short));
    }

    // ---- untilnl --------------------------------------------------------

    #[test]
    fn untilnl_stops_at_cr_or_lf() {
        let mut lf = Str::new("line\nnext");
        let mut out = Str::default();
        assert_eq!(lf.curlx_str_untilnl(&mut out, 100), Ok(()));
        assert_eq!(out.curlx_str(), b"line");
        assert_eq!(lf.curlx_str(), b"\nnext");

        let mut cr = Str::new("line\r\nnext");
        let mut out2 = Str::default();
        assert_eq!(cr.curlx_str_untilnl(&mut out2, 100), Ok(()));
        assert_eq!(out2.curlx_str(), b"line");
        assert_eq!(cr.curlx_str(), b"\r\nnext");

        // A leading newline yields an empty token -> STRE_SHORT.
        let mut nl = Str::new("\nrest");
        let mut o3 = Str::default();
        assert_eq!(nl.curlx_str_untilnl(&mut o3, 100), Err(StrError::Short));
    }

    // ---- quotedword -----------------------------------------------------

    #[test]
    fn quotedword_basic() {
        let mut s = Str::new("\"hello\" trailing");
        let mut out = Str::default();
        assert_eq!(s.curlx_str_quotedword(&mut out, 100), Ok(()));
        assert_eq!(out.curlx_str(), b"hello");
        // Cursor is advanced past the closing quote.
        assert_eq!(s.curlx_str(), b" trailing");
    }

    #[test]
    fn quotedword_requires_leading_quote() {
        let mut s = Str::new("hello\"");
        let mut out = Str::new("stale");
        assert_eq!(
            s.curlx_str_quotedword(&mut out, 100),
            Err(StrError::BegQuote)
        );
        assert!(out.is_empty());
    }

    #[test]
    fn quotedword_unterminated_is_endquote() {
        let mut s = Str::new("\"hello");
        let mut out = Str::default();
        assert_eq!(
            s.curlx_str_quotedword(&mut out, 100),
            Err(StrError::EndQuote)
        );

        // A trailing backslash before EOF cannot escape a (missing) quote.
        let mut bs = Str::new("\"ab\\");
        let mut o2 = Str::default();
        assert_eq!(
            bs.curlx_str_quotedword(&mut o2, 100),
            Err(StrError::EndQuote)
        );
    }

    #[test]
    fn quotedword_keeps_backslash_escapes_literally() {
        // An escaped quote does not terminate the word, and BOTH the backslash
        // and the escaped byte remain part of the captured token (C does not
        // un-escape here).
        let mut s = Str::new("\"a\\\"b\"rest");
        let mut out = Str::default();
        assert_eq!(s.curlx_str_quotedword(&mut out, 100), Ok(()));
        assert_eq!(out.curlx_str(), b"a\\\"b");
        assert_eq!(out.curlx_strlen(), 4);
        assert_eq!(s.curlx_str(), b"rest");
    }

    #[test]
    fn quotedword_empty_content() {
        let mut s = Str::new("\"\"x");
        let mut out = Str::new("stale");
        assert_eq!(s.curlx_str_quotedword(&mut out, 100), Ok(()));
        assert!(out.is_empty());
        assert_eq!(s.curlx_str(), b"x");
    }

    #[test]
    fn quotedword_overflow_is_big() {
        let mut s = Str::new("\"abcd\"");
        let mut out = Str::default();
        assert_eq!(s.curlx_str_quotedword(&mut out, 3), Err(StrError::Big));
    }

    // ---- single / singlespace / newline ---------------------------------

    #[test]
    fn single_and_singlespace() {
        let mut s = Str::new("=value");
        assert_eq!(s.curlx_str_single(b'='), Ok(()));
        assert_eq!(s.curlx_str(), b"value");
        assert_eq!(s.curlx_str_single(b'='), Err(StrError::Byte));
        // Unchanged after a failed match.
        assert_eq!(s.curlx_str(), b"value");

        let mut sp = Str::new(" x");
        assert_eq!(sp.curlx_str_singlespace(), Ok(()));
        assert_eq!(sp.curlx_str(), b"x");
        assert_eq!(sp.curlx_str_singlespace(), Err(StrError::Byte));

        // Empty cursor -> STRE_BYTE.
        let mut e = Str::new("");
        assert_eq!(e.curlx_str_single(b'x'), Err(StrError::Byte));
    }

    #[test]
    fn newline_consumes_cr_or_lf() {
        let mut lf = Str::new("\nrest");
        assert_eq!(lf.curlx_str_newline(), Ok(()));
        assert_eq!(lf.curlx_str(), b"rest");

        let mut cr = Str::new("\rrest");
        assert_eq!(cr.curlx_str_newline(), Ok(()));
        assert_eq!(cr.curlx_str(), b"rest");

        let mut no = Str::new("xrest");
        assert_eq!(no.curlx_str_newline(), Err(StrError::Newline));
        assert_eq!(no.curlx_str(), b"xrest");

        let mut e = Str::new("");
        assert_eq!(e.curlx_str_newline(), Err(StrError::Newline));
    }

    // ---- passblanks / numblanks / trimblanks ----------------------------

    #[test]
    fn passblanks_skips_spaces_and_tabs() {
        let mut s = Str::new("  \t x");
        assert_eq!(s.curlx_str_passblanks(), 4);
        assert_eq!(s.curlx_str(), b"x");

        // Nothing to skip.
        let mut none = Str::new("y");
        assert_eq!(none.curlx_str_passblanks(), 0);
        assert_eq!(none.curlx_str(), b"y");
    }

    #[test]
    fn numblanks_skips_then_parses() {
        let mut s = Str::new("   42rest");
        let mut n = 0u64;
        assert_eq!(s.curlx_str_numblanks(&mut n), Ok(()));
        assert_eq!(n, 42);
        assert_eq!(s.curlx_str(), b"rest");

        // Blanks but no number -> STRE_NO_NUM, and the value is reset to 0.
        let mut bad = Str::new("   x");
        let mut m = 7u64;
        assert_eq!(bad.curlx_str_numblanks(&mut m), Err(StrError::NoNum));
        assert_eq!(m, 0);
    }

    #[test]
    fn trimblanks_trims_both_ends() {
        let mut s = Str::from_bytes(b" \t hello \t ");
        s.curlx_str_trimblanks();
        assert_eq!(s.curlx_str(), b"hello");

        // All-blank trims to empty.
        let mut all = Str::from_bytes(b"   ");
        all.curlx_str_trimblanks();
        assert!(all.is_empty());

        // No blanks: unchanged.
        let mut none = Str::new("word");
        none.curlx_str_trimblanks();
        assert_eq!(none.curlx_str(), b"word");
    }

    // ---- cspn -----------------------------------------------------------

    #[test]
    fn cspn_captures_until_reject_byte() {
        let mut s = Str::new("abc=def");
        let mut out = Str::default();
        assert_eq!(s.curlx_str_cspn(&mut out, b"=;"), Ok(()));
        assert_eq!(out.curlx_str(), b"abc");
        assert_eq!(s.curlx_str(), b"=def");

        // No reject byte present -> whole remaining input captured.
        let mut whole = Str::new("abcdef");
        let mut out2 = Str::default();
        assert_eq!(whole.curlx_str_cspn(&mut out2, b"=;"), Ok(()));
        assert_eq!(out2.curlx_str(), b"abcdef");
        assert!(whole.is_empty());

        // Reject byte first -> empty run -> STRE_SHORT, out reset.
        let mut lead = Str::new("=abc");
        let mut out3 = Str::new("stale");
        assert_eq!(lead.curlx_str_cspn(&mut out3, b"=;"), Err(StrError::Short));
        assert!(out3.is_empty());
    }

    // ---- decimal numbers ------------------------------------------------

    #[test]
    fn number_decimal_basic_and_leading_zeros() {
        let mut s = Str::new("12345rest");
        let mut n = 0u64;
        assert_eq!(s.curlx_str_number(&mut n, CURL_OFF_T_MAX), Ok(()));
        assert_eq!(n, 12345);
        assert_eq!(s.curlx_str(), b"rest");

        // Leading zeroes accepted.
        let mut z = Str::new("00042");
        let mut n2 = 0u64;
        assert_eq!(z.curlx_str_number(&mut n2, CURL_OFF_T_MAX), Ok(()));
        assert_eq!(n2, 42);
    }

    #[test]
    fn number_no_digit_is_no_num() {
        let mut s = Str::new("xyz");
        let mut n = 5u64;
        assert_eq!(s.curlx_str_number(&mut n, CURL_OFF_T_MAX), Err(StrError::NoNum));
        assert_eq!(n, 0);
        // Cursor untouched on error.
        assert_eq!(s.curlx_str(), b"xyz");
    }

    #[test]
    fn number_overflow_general_branch() {
        // max >= base path.
        let mut ok = Str::new("100");
        let mut n = 0u64;
        assert_eq!(ok.curlx_str_number(&mut n, 100), Ok(()));
        assert_eq!(n, 100);

        let mut over = Str::new("101");
        let mut m = 0u64;
        assert_eq!(over.curlx_str_number(&mut m, 100), Err(StrError::Overflow));
        assert_eq!(m, 0);
    }

    #[test]
    fn number_overflow_low_max_branch() {
        // max < base path (max = 5, base = 10).
        let mut ok = Str::new("5");
        let mut n = 0u64;
        assert_eq!(ok.curlx_str_number(&mut n, 5), Ok(()));
        assert_eq!(n, 5);

        let mut over = Str::new("7");
        let mut m = 0u64;
        assert_eq!(over.curlx_str_number(&mut m, 5), Err(StrError::Overflow));

        let mut over2 = Str::new("12");
        let mut k = 0u64;
        assert_eq!(over2.curlx_str_number(&mut k, 5), Err(StrError::Overflow));
    }

    #[test]
    fn number_at_63bit_max_boundary() {
        // CURL_OFF_T_MAX itself parses; one more overflows.
        let mut at = Str::new("9223372036854775807");
        let mut n = 0u64;
        assert_eq!(at.curlx_str_number(&mut n, CURL_OFF_T_MAX), Ok(()));
        assert_eq!(n, 9_223_372_036_854_775_807);

        let mut over = Str::new("9223372036854775808");
        let mut m = 0u64;
        assert_eq!(
            over.curlx_str_number(&mut m, CURL_OFF_T_MAX),
            Err(StrError::Overflow)
        );
    }

    // ---- hexadecimal numbers --------------------------------------------

    #[test]
    fn hex_basic_upper_and_lower() {
        let mut lo = Str::new("ff");
        let mut n = 0u64;
        assert_eq!(lo.curlx_str_hex(&mut n, CURL_OFF_T_MAX), Ok(()));
        assert_eq!(n, 255);

        let mut up = Str::new("DEADBEEF");
        let mut m = 0u64;
        assert_eq!(up.curlx_str_hex(&mut m, CURL_OFF_T_MAX), Ok(()));
        assert_eq!(m, 0xDEAD_BEEF);

        // No "0x" prefix support: parsing stops at 'x'.
        let mut prefixed = Str::new("0x1");
        let mut k = 0u64;
        assert_eq!(prefixed.curlx_str_hex(&mut k, CURL_OFF_T_MAX), Ok(()));
        assert_eq!(k, 0);
        assert_eq!(prefixed.curlx_str(), b"x1");
    }

    #[test]
    fn hex_no_digit_and_overflow() {
        let mut none = Str::new("ghi");
        let mut n = 0u64;
        assert_eq!(none.curlx_str_hex(&mut n, CURL_OFF_T_MAX), Err(StrError::NoNum));

        // Low-max branch (max = 15 < base = 16).
        let mut ok = Str::new("f");
        let mut m = 0u64;
        assert_eq!(ok.curlx_str_hex(&mut m, 15), Ok(()));
        assert_eq!(m, 15);

        let mut over = Str::new("10"); // hex 0x10 = 16 > 15
        let mut k = 0u64;
        assert_eq!(over.curlx_str_hex(&mut k, 15), Err(StrError::Overflow));
    }

    // ---- octal numbers --------------------------------------------------

    #[test]
    fn octal_basic_and_invalid_digits() {
        let mut s = Str::new("0755");
        let mut n = 0u64;
        assert_eq!(s.curlx_str_octal(&mut n, CURL_OFF_T_MAX), Ok(()));
        assert_eq!(n, 0o755);

        // 8 and 9 are not octal digits: parsing stops at the first one.
        let mut stop = Str::new("178");
        let mut m = 0u64;
        assert_eq!(stop.curlx_str_octal(&mut m, CURL_OFF_T_MAX), Ok(()));
        assert_eq!(m, 0o17);
        assert_eq!(stop.curlx_str(), b"8");

        // A leading 8 means no octal digit at all.
        let mut bad = Str::new("8");
        let mut k = 0u64;
        assert_eq!(bad.curlx_str_octal(&mut k, CURL_OFF_T_MAX), Err(StrError::NoNum));
    }

    #[test]
    fn octal_overflow() {
        // Low-max branch: max = 5 < base = 8.
        let mut over = Str::new("7");
        let mut n = 0u64;
        assert_eq!(over.curlx_str_octal(&mut n, 5), Err(StrError::Overflow));

        let mut ok = Str::new("5");
        let mut m = 0u64;
        assert_eq!(ok.curlx_str_octal(&mut m, 5), Ok(()));
        assert_eq!(m, 5);
    }

    // ---- hexval ---------------------------------------------------------

    #[test]
    fn hexval_maps_valid_digits_only() {
        assert_eq!(curlx_hexval(b'0'), Some(0));
        assert_eq!(curlx_hexval(b'9'), Some(9));
        assert_eq!(curlx_hexval(b'a'), Some(10));
        assert_eq!(curlx_hexval(b'f'), Some(15));
        assert_eq!(curlx_hexval(b'A'), Some(10));
        assert_eq!(curlx_hexval(b'F'), Some(15));
        assert_eq!(curlx_hexval(b'g'), None);
        assert_eq!(curlx_hexval(b'G'), None);
        assert_eq!(curlx_hexval(b' '), None);
        // Bytes adjacent to the digit/letter ranges must be rejected.
        assert_eq!(curlx_hexval(b'/'), None); // just before '0'
        assert_eq!(curlx_hexval(b':'), None); // just after '9'
        assert_eq!(curlx_hexval(b'`'), None); // just before 'a'
        assert_eq!(curlx_hexval(b'@'), None); // just before 'A'
    }

    // ---- case compares (ASCII-only folding) -----------------------------

    #[test]
    fn str_casecompare_is_ascii_case_insensitive() {
        let s = Str::new("ABC");
        assert!(curlx_str_casecompare(&s, "abc"));
        assert!(curlx_str_casecompare(&s, "ABC"));
        assert!(curlx_str_casecompare(&s, "aBc"));
        // Length mismatch never matches.
        assert!(!curlx_str_casecompare(&s, "ab"));
        assert!(!curlx_str_casecompare(&s, "abcd"));
        // Empty token matches only the empty check.
        let e = Str::new("");
        assert!(curlx_str_casecompare(&e, ""));
        assert!(!curlx_str_casecompare(&e, "x"));
    }

    #[test]
    fn str_cmp_is_case_sensitive() {
        let s = Str::new("ABC");
        assert!(curlx_str_cmp(&s, "ABC"));
        assert!(!curlx_str_cmp(&s, "abc"));
        assert!(!curlx_str_cmp(&s, "AB"));
    }

    #[test]
    fn strcasecompare_folds_only_ascii_letters() {
        assert!(strcasecompare(b"Hello", b"hELLO"));
        assert!(strcasecompare(b"", b""));
        assert!(!strcasecompare(b"abc", b"abcd"));

        // Non-letter ASCII bytes are NOT folded: '[' (0x5B) vs '{' (0x7B) and
        // '@' (0x40) vs '`' (0x60) differ by the same 0x20 bit as letters do,
        // but must remain distinct.
        assert!(!strcasecompare(b"[", b"{"));
        assert!(!strcasecompare(b"@", b"`"));

        // Non-ASCII bytes are compared literally (no Unicode folding): the
        // UTF-8 encodings of 'E-acute' (uppercase) and 'e-acute' (lowercase)
        // must not be considered equal.
        assert!(!strcasecompare(&[0xC3, 0x89], &[0xC3, 0xA9]));
        // Identical non-ASCII bytes are equal.
        assert!(strcasecompare(&[0xC3, 0x89], &[0xC3, 0x89]));
    }

    #[test]
    fn strncasecompare_prefix_semantics() {
        // Equal prefixes within n match.
        assert!(strncasecompare(b"Content-Type", b"content-LENGTH", 8));
        assert!(strncasecompare(b"abc", b"ABC", 3));
        // Differing within the compared window fails.
        assert!(!strncasecompare(b"abc", b"abd", 3));

        // Comparing fewer bytes than both lengths only inspects the prefix.
        assert!(strncasecompare(b"abcXYZ", b"abcijk", 3));

        // C NUL-edge semantics: a shorter slice cannot match a longer prefix.
        assert!(!strncasecompare(b"ab", b"abc", 5));
        assert!(!strncasecompare(b"abc", b"ab", 5));
        // When both end before n, equal length + equal content matches.
        assert!(strncasecompare(b"abc", b"ABC", 5));
        // n == 0 always matches.
        assert!(strncasecompare(b"anything", b"different", 0));
        // Both empty matches at any n.
        assert!(strncasecompare(b"", b"", 5));
    }
}

