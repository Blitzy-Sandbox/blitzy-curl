//! String parsing toolkit for the curl-rs library.
//!
//! This module is the Rust replacement for `lib/curlx/strparse.c` from the
//! curl C codebase. It provides a zero-copy, cursor-based string parser used
//! extensively throughout curl for tokenizing HTTP headers, parsing protocol
//! responses, extracting numeric values, and handling quoted strings.
//!
//! # Design
//!
//! The C implementation uses `struct Curl_str` (pointer + length) views and
//! `const char **linep` cursor pointers. In Rust, [`StrParser`] wraps a
//! `&str` slice with a position offset, and all returned tokens are borrowed
//! sub-slices of the original input — no allocations occur during parsing.
//!
//! # Error Codes
//!
//! [`StrParseError`] variants carry explicit `#[repr(u8)]` discriminants
//! matching the C `STRE_*` constants for behavioral parity.

use crate::error::CurlError;

// ---------------------------------------------------------------------------
// StrParseError — maps to C STRE_* error codes
// ---------------------------------------------------------------------------

/// Error codes for string parsing operations.
///
/// Every variant maps 1:1 to a C `STRE_*` constant defined in
/// `lib/curlx/strparse.h`. The explicit `#[repr(u8)]` discriminants preserve
/// integer parity with the C error space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StrParseError {
    /// No error — operation succeeded (`STRE_OK = 0`).
    ///
    /// Included for completeness; `Result::Ok` is the idiomatic Rust success
    /// path, so this variant is rarely constructed directly.
    Ok = 0,

    /// Number or string exceeded the maximum allowed size (`STRE_BIG = 1`).
    ///
    /// Returned by numeric parsers on `u64` overflow and by string parsers
    /// when the token length exceeds the caller-specified `max_len` /
    /// `max_digits` bound.
    BigNum = 1,

    /// Token was empty — at least one character was required (`STRE_SHORT = 2`).
    Short = 2,

    /// Expected opening quote character not found (`STRE_BEGQUOTE = 3`).
    BegQuote = 3,

    /// Closing quote character not found before end of input (`STRE_ENDQUOTE = 4`).
    EndQuote = 4,

    /// Expected a specific byte/character that was not present (`STRE_BYTE = 5`).
    Byte = 5,

    /// Unexpected newline encountered (`STRE_NEWLINE = 6`).
    NewLine = 6,

    /// General overflow condition (`STRE_OVERFLOW = 7`).
    Overflow = 7,

    /// First character is not a valid digit for the requested base (`STRE_NO_NUM = 8`).
    NoNum = 8,
}

impl std::fmt::Display for StrParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StrParseError::Ok => write!(f, "no error"),
            StrParseError::BigNum => write!(f, "number or string too large"),
            StrParseError::Short => write!(f, "string too short"),
            StrParseError::BegQuote => write!(f, "missing opening quote"),
            StrParseError::EndQuote => write!(f, "missing closing quote"),
            StrParseError::Byte => write!(f, "unexpected byte"),
            StrParseError::NewLine => write!(f, "unexpected newline"),
            StrParseError::Overflow => write!(f, "overflow"),
            StrParseError::NoNum => write!(f, "not a number"),
        }
    }
}

impl std::error::Error for StrParseError {}

/// Convert a [`StrParseError`] into the library-wide [`CurlError`] type.
///
/// Mapping rationale:
/// - **`BigNum`** / **`BegQuote`** / **`EndQuote`** / **`Byte`** / **`NoNum`**
///   → [`CurlError::BadFunctionArgument`]: the input did not conform to the
///   expected format — a caller-side issue analogous to passing a bad argument.
/// - **`Short`** / **`NewLine`** → [`CurlError::ReadError`]: insufficient or
///   malformed data, analogous to a truncated read.
/// - **`Overflow`** → [`CurlError::OutOfMemory`]: a value exceeds
///   representable bounds, broadly mapping to resource exhaustion.
/// - **`Ok`** → [`CurlError::Ok`]: success maps to success.
impl From<StrParseError> for CurlError {
    fn from(e: StrParseError) -> Self {
        match e {
            StrParseError::Ok => CurlError::Ok,
            StrParseError::BigNum => CurlError::BadFunctionArgument,
            StrParseError::Short => CurlError::ReadError,
            StrParseError::BegQuote => CurlError::BadFunctionArgument,
            StrParseError::EndQuote => CurlError::BadFunctionArgument,
            StrParseError::Byte => CurlError::BadFunctionArgument,
            StrParseError::NewLine => CurlError::ReadError,
            StrParseError::Overflow => CurlError::OutOfMemory,
            StrParseError::NoNum => CurlError::BadFunctionArgument,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helper: RFC 7230 token character predicate
// ---------------------------------------------------------------------------

/// Returns `true` if `b` is a valid HTTP token character per RFC 7230 §3.2.6.
///
/// ```text
/// token = 1*tchar
/// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*"
///       / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
///       / DIGIT / ALPHA
/// ```
#[inline]
fn is_tchar(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' |
        b'+' | b'-' | b'.' | b'^' | b'_' | b'`'  | b'|' | b'~' |
        b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
    )
}

/// Returns the numeric value of a hexadecimal ASCII digit, or `None`.
#[inline]
fn hex_digit_value(b: u8) -> Option<u64> {
    match b {
        b'0'..=b'9' => Some((b - b'0') as u64),
        b'a'..=b'f' => Some((b - b'a' + 10) as u64),
        b'A'..=b'F' => Some((b - b'A' + 10) as u64),
        _ => None,
    }
}

/// Returns the numeric value of a decimal ASCII digit, or `None`.
#[inline]
fn dec_digit_value(b: u8) -> Option<u64> {
    match b {
        b'0'..=b'9' => Some((b - b'0') as u64),
        _ => None,
    }
}

/// Returns the numeric value of an octal ASCII digit, or `None`.
#[inline]
fn oct_digit_value(b: u8) -> Option<u64> {
    match b {
        b'0'..=b'7' => Some((b - b'0') as u64),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// StrParser — zero-copy cursor over a &str
// ---------------------------------------------------------------------------

/// A zero-copy, cursor-based parser over a borrowed string slice.
///
/// `StrParser` replaces the C pattern of passing `const char **linep` through
/// a chain of `curlx_str_*` functions. The parser tracks a position offset
/// into the original `&str` and all returned tokens are sub-slices borrowing
/// from the same input — no heap allocation occurs during parsing.
///
/// # Examples
///
/// ```ignore
/// use curl_rs_lib::util::strparse::StrParser;
///
/// let mut p = StrParser::new("Content-Length: 42\r\n");
/// let name = p.parse_header_name().unwrap();
/// assert_eq!(name, "Content-Length");
/// p.skip_char(':');
/// let value = p.parse_header_value().unwrap();
/// assert_eq!(value, "42");
/// ```
#[derive(Debug, Clone)]
pub struct StrParser<'a> {
    /// The full, immutable input string.
    input: &'a str,
    /// Current byte offset into `input`. Invariant: `pos <= input.len()`.
    pos: usize,
}

impl<'a> StrParser<'a> {
    // ------------------------------------------------------------------
    // Construction and state queries
    // ------------------------------------------------------------------

    /// Create a new parser positioned at the beginning of `input`.
    #[inline]
    pub fn new(input: &'a str) -> Self {
        StrParser { input, pos: 0 }
    }

    /// Return the unconsumed portion of the input.
    #[inline]
    pub fn remaining(&self) -> &'a str {
        // SAFETY invariant: `self.pos <= self.input.len()` is maintained by
        // all mutation methods, and the input is valid UTF-8, so slicing at
        // a byte boundary that was previously validated is always safe.
        &self.input[self.pos..]
    }

    /// Return `true` if the parser has consumed all input.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.input.len()
    }

    /// Return the current byte offset from the start of the input.
    #[inline]
    pub fn position(&self) -> usize {
        self.pos
    }

    // ------------------------------------------------------------------
    // Numeric parsers
    // ------------------------------------------------------------------

    /// Parse an unsigned decimal integer, consuming up to `max_digits` digits.
    ///
    /// Matches the C `Curl_str_number` / `Curl_str_nudecimal` family. Returns
    /// [`StrParseError::NoNum`] if the first unconsumed byte is not a decimal
    /// digit, and [`StrParseError::BigNum`] on `u64` overflow.
    pub fn parse_decimal(&mut self, max_digits: usize) -> Result<u64, StrParseError> {
        self.parse_num_generic(max_digits, 10, dec_digit_value)
    }

    /// Parse an unsigned hexadecimal integer, consuming up to `max_digits`
    /// hex digits (`[0-9a-fA-F]`).
    ///
    /// Matches the C `Curl_str_hex` function. Returns
    /// [`StrParseError::NoNum`] if the first unconsumed byte is not a hex
    /// digit, and [`StrParseError::BigNum`] on `u64` overflow.
    pub fn parse_hex(&mut self, max_digits: usize) -> Result<u64, StrParseError> {
        self.parse_num_generic(max_digits, 16, hex_digit_value)
    }

    /// Parse an unsigned octal integer, consuming up to `max_digits` octal
    /// digits (`[0-7]`).
    ///
    /// Matches the C `Curl_str_octal` function. Returns
    /// [`StrParseError::NoNum`] if the first unconsumed byte is not an octal
    /// digit, and [`StrParseError::BigNum`] on `u64` overflow.
    pub fn parse_octal(&mut self, max_digits: usize) -> Result<u64, StrParseError> {
        self.parse_num_generic(max_digits, 8, oct_digit_value)
    }

    /// Generic numeric parser parameterised by base and digit-value function.
    ///
    /// Scans up to `max_digits` consecutive digits in the given `base`,
    /// accumulating into a `u64`. Uses checked arithmetic to detect overflow.
    fn parse_num_generic(
        &mut self,
        max_digits: usize,
        base: u64,
        digit_fn: fn(u8) -> Option<u64>,
    ) -> Result<u64, StrParseError> {
        let bytes = self.remaining().as_bytes();
        if bytes.is_empty() {
            return Err(StrParseError::NoNum);
        }

        // The first byte must be a valid digit for this base.
        if digit_fn(bytes[0]).is_none() {
            return Err(StrParseError::NoNum);
        }

        let mut num: u64 = 0;
        let mut count: usize = 0;

        for &b in bytes.iter().take(max_digits) {
            let digit = match digit_fn(b) {
                Some(d) => d,
                None => break,
            };
            num = num
                .checked_mul(base)
                .and_then(|n| n.checked_add(digit))
                .ok_or(StrParseError::BigNum)?;
            count += 1;
        }

        // `count` is guaranteed ≥ 1 because we pre-checked the first byte.
        self.pos += count;
        Ok(num)
    }

    // ------------------------------------------------------------------
    // String token parsers
    // ------------------------------------------------------------------

    /// Parse a whitespace-delimited word of at most `max_len` bytes.
    ///
    /// Matches the C `Curl_str_word` function. Scanning stops at the first
    /// ASCII whitespace byte (space, tab, CR, LF), end of input, or when
    /// `max_len` bytes have been consumed. At least one non-whitespace byte
    /// must be present; otherwise [`StrParseError::Short`] is returned. If
    /// the non-whitespace run exceeds `max_len`, [`StrParseError::BigNum`]
    /// is returned.
    pub fn parse_word(&mut self, max_len: usize) -> Result<&'a str, StrParseError> {
        let bytes = self.remaining().as_bytes();
        let mut count: usize = 0;

        for &b in bytes {
            if b == b' ' || b == b'\t' || b == b'\r' || b == b'\n' {
                break;
            }
            count += 1;
            if count > max_len {
                return Err(StrParseError::BigNum);
            }
        }

        if count == 0 {
            return Err(StrParseError::Short);
        }

        let start = self.pos;
        self.pos += count;
        Ok(&self.input[start..start + count])
    }

    /// Parse until the first occurrence of `delim` or end of input, returning
    /// the consumed slice. At least one byte must be consumed.
    ///
    /// Matches the C `Curl_str_until` function. Returns
    /// [`StrParseError::BigNum`] if the token exceeds `max_len` bytes, and
    /// [`StrParseError::Short`] if the token is empty (delimiter is the very
    /// first character or input is exhausted).
    pub fn parse_until_char(
        &mut self,
        delim: char,
        max_len: usize,
    ) -> Result<&'a str, StrParseError> {
        let bytes = self.remaining().as_bytes();
        let delim_byte = delim as u8; // safe for ASCII delimiters
        let mut count: usize = 0;

        for &b in bytes {
            if b == delim_byte {
                break;
            }
            count += 1;
            if count > max_len {
                return Err(StrParseError::BigNum);
            }
        }

        if count == 0 {
            return Err(StrParseError::Short);
        }

        let start = self.pos;
        self.pos += count;
        Ok(&self.input[start..start + count])
    }

    /// Parse until CR (`\r`) or LF (`\n`) or end of input.
    ///
    /// Matches the C `Curl_str_untilnl` function. At least one byte must be
    /// consumed; otherwise [`StrParseError::Short`] is returned. Returns
    /// [`StrParseError::BigNum`] if the line exceeds `max_len` bytes.
    pub fn parse_until_newline(&mut self, max_len: usize) -> Result<&'a str, StrParseError> {
        let bytes = self.remaining().as_bytes();
        let mut count: usize = 0;

        for &b in bytes {
            if b == b'\r' || b == b'\n' {
                break;
            }
            count += 1;
            if count > max_len {
                return Err(StrParseError::BigNum);
            }
        }

        if count == 0 {
            return Err(StrParseError::Short);
        }

        let start = self.pos;
        self.pos += count;
        Ok(&self.input[start..start + count])
    }

    /// Parse a quoted string, returning the content **without** surrounding
    /// quotes. Both double-quote (`"`) and single-quote (`'`) delimiters are
    /// accepted. Backslash-escaped characters within the quoted region are
    /// included verbatim in the returned slice (the caller must post-process
    /// escape sequences if needed).
    ///
    /// Matches the C `Curl_str_quotedword` function. Returns
    /// [`StrParseError::BegQuote`] if the first character is not a quote,
    /// [`StrParseError::EndQuote`] if no matching closing quote is found, and
    /// [`StrParseError::BigNum`] if the content exceeds `max_len` bytes.
    pub fn parse_quoted(&mut self, max_len: usize) -> Result<&'a str, StrParseError> {
        let bytes = self.remaining().as_bytes();

        if bytes.is_empty() {
            return Err(StrParseError::BegQuote);
        }

        let quote_char = bytes[0];
        if quote_char != b'"' && quote_char != b'\'' {
            return Err(StrParseError::BegQuote);
        }

        // `i` is the byte offset *within the remaining slice*, starting just
        // past the opening quote.
        let mut i: usize = 1;
        let mut logical_len: usize = 0;

        while i < bytes.len() && bytes[i] != quote_char {
            if bytes[i] == b'\\' && i + 1 < bytes.len() {
                // Escaped character — skip past the backslash.
                i += 1;
                logical_len += 1;
                if logical_len > max_len {
                    return Err(StrParseError::BigNum);
                }
            }
            i += 1;
            logical_len += 1;
            if logical_len > max_len {
                return Err(StrParseError::BigNum);
            }
        }

        // We must be positioned at the closing quote.
        if i >= bytes.len() || bytes[i] != quote_char {
            return Err(StrParseError::EndQuote);
        }

        // Content lies between the quotes: [pos+1 .. pos+i)
        let content_start = self.pos + 1;
        let content_end = self.pos + i;
        let result = &self.input[content_start..content_end];

        // Advance past the closing quote.
        self.pos += i + 1;
        Ok(result)
    }

    // ------------------------------------------------------------------
    // HTTP-specific parsers
    // ------------------------------------------------------------------

    /// Parse an HTTP header field-name (RFC 7230 token characters).
    ///
    /// Consumes one or more `tchar` bytes and stops at the first non-token
    /// byte (typically `:`). The colon itself is **not** consumed. Returns
    /// [`StrParseError::Short`] if no token characters are found.
    pub fn parse_header_name(&mut self) -> Result<&'a str, StrParseError> {
        let bytes = self.remaining().as_bytes();
        let mut count: usize = 0;

        for &b in bytes {
            if is_tchar(b) {
                count += 1;
            } else {
                break;
            }
        }

        if count == 0 {
            return Err(StrParseError::Short);
        }

        let start = self.pos;
        self.pos += count;
        Ok(&self.input[start..start + count])
    }

    /// Parse an HTTP header field-value.
    ///
    /// Skips optional leading whitespace (OWS: spaces and tabs), then
    /// consumes bytes until CR, LF, or end of input. Trailing spaces and
    /// tabs are trimmed from the returned slice. An empty value (e.g.
    /// immediately followed by CRLF) is valid and returns `Ok("")`.
    pub fn parse_header_value(&mut self) -> Result<&'a str, StrParseError> {
        // Skip optional leading whitespace (OWS per RFC 7230 §3.2).
        self.skip_whitespace();

        let bytes = self.remaining().as_bytes();
        let mut count: usize = 0;

        for &b in bytes {
            if b == b'\r' || b == b'\n' {
                break;
            }
            count += 1;
        }

        let start = self.pos;
        self.pos += count;

        // Trim trailing OWS (spaces and tabs) from the value.
        let raw = &self.input[start..start + count];
        let trimmed = raw.trim_end_matches([' ', '\t']);
        Ok(trimmed)
    }

    // ------------------------------------------------------------------
    // Whitespace and control
    // ------------------------------------------------------------------

    /// Skip over leading ASCII blank characters (spaces and horizontal tabs).
    ///
    /// Matches the C `Curl_str_passblanks` function which uses the
    /// `ISBLANK()` macro (SP + HTAB only).
    pub fn skip_whitespace(&mut self) {
        let bytes = self.remaining().as_bytes();
        let mut count: usize = 0;

        for &b in bytes {
            if b == b' ' || b == b'\t' {
                count += 1;
            } else {
                break;
            }
        }

        self.pos += count;
    }

    /// If the next byte equals `c`, consume it and return `true`.
    /// Otherwise leave the position unchanged and return `false`.
    ///
    /// Matches the C `Curl_str_single` function (which returns 0 on match
    /// and `STRE_BYTE` on mismatch). The Rust API uses a boolean for
    /// ergonomic use in conditional chains.
    pub fn skip_char(&mut self, c: char) -> bool {
        let bytes = self.remaining().as_bytes();
        if !bytes.is_empty() && bytes[0] == c as u8 {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// Peek at the next unconsumed character without advancing the cursor.
    ///
    /// Returns `None` if the parser is at end of input.
    pub fn peek(&self) -> Option<char> {
        self.remaining().chars().next()
    }

    /// Consume the exact string `expected` from the current position.
    ///
    /// Returns [`StrParseError::Short`] if fewer than `expected.len()` bytes
    /// remain, and [`StrParseError::Byte`] if any byte does not match.
    pub fn expect(&mut self, expected: &str) -> Result<(), StrParseError> {
        let remaining = self.remaining();
        if remaining.len() < expected.len() {
            return Err(StrParseError::Short);
        }

        let candidate = &remaining[..expected.len()];
        if candidate != expected {
            return Err(StrParseError::Byte);
        }

        self.pos += expected.len();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Free-standing case-insensitive comparison functions
// ---------------------------------------------------------------------------

/// Return `true` if `s` starts with `prefix` using ASCII case-insensitive
/// comparison.
///
/// Matches the C `Curl_str_casecompare` family for prefix matching. Only
/// ASCII letters are folded; non-ASCII bytes are compared exactly.
///
/// # Examples
///
/// ```ignore
/// assert!(starts_with_ignore_case("Content-Type: text", "content-type"));
/// assert!(!starts_with_ignore_case("Con", "content-type"));
/// ```
pub fn starts_with_ignore_case(s: &str, prefix: &str) -> bool {
    if s.len() < prefix.len() {
        return false;
    }
    let s_bytes = s.as_bytes();
    let p_bytes = prefix.as_bytes();
    for i in 0..p_bytes.len() {
        if !s_bytes[i].eq_ignore_ascii_case(&p_bytes[i]) {
            return false;
        }
    }
    true
}

/// Return `true` if `a` and `b` are equal under ASCII case-insensitive
/// comparison.
///
/// Matches the C `curl_strnequal` / `Curl_str_casecompare` semantics.
/// Only ASCII letters are folded; non-ASCII bytes must match exactly.
///
/// # Examples
///
/// ```ignore
/// assert!(eq_ignore_case("Content-Length", "content-length"));
/// assert!(!eq_ignore_case("Content-Length", "content-type"));
/// ```
pub fn eq_ignore_case(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes()
        .iter()
        .zip(b.as_bytes().iter())
        .all(|(&x, &y)| x.eq_ignore_ascii_case(&y))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- StrParseError repr values --

    #[test]
    fn error_discriminant_values() {
        assert_eq!(StrParseError::Ok as u8, 0);
        assert_eq!(StrParseError::BigNum as u8, 1);
        assert_eq!(StrParseError::Short as u8, 2);
        assert_eq!(StrParseError::BegQuote as u8, 3);
        assert_eq!(StrParseError::EndQuote as u8, 4);
        assert_eq!(StrParseError::Byte as u8, 5);
        assert_eq!(StrParseError::NewLine as u8, 6);
        assert_eq!(StrParseError::Overflow as u8, 7);
        assert_eq!(StrParseError::NoNum as u8, 8);
    }

    // -- From<StrParseError> for CurlError --

    #[test]
    fn error_conversion_uses_all_variants() {
        assert_eq!(CurlError::from(StrParseError::Ok), CurlError::Ok);
        assert_eq!(
            CurlError::from(StrParseError::BigNum),
            CurlError::BadFunctionArgument
        );
        assert_eq!(
            CurlError::from(StrParseError::Short),
            CurlError::ReadError
        );
        assert_eq!(
            CurlError::from(StrParseError::BegQuote),
            CurlError::BadFunctionArgument
        );
        assert_eq!(
            CurlError::from(StrParseError::EndQuote),
            CurlError::BadFunctionArgument
        );
        assert_eq!(
            CurlError::from(StrParseError::Byte),
            CurlError::BadFunctionArgument
        );
        assert_eq!(
            CurlError::from(StrParseError::NewLine),
            CurlError::ReadError
        );
        assert_eq!(
            CurlError::from(StrParseError::Overflow),
            CurlError::OutOfMemory
        );
        assert_eq!(
            CurlError::from(StrParseError::NoNum),
            CurlError::BadFunctionArgument
        );
    }

    // -- StrParser: construction and state --

    #[test]
    fn parser_new_and_state() {
        let p = StrParser::new("hello");
        assert_eq!(p.remaining(), "hello");
        assert!(!p.is_empty());
        assert_eq!(p.position(), 0);
    }

    #[test]
    fn parser_empty_input() {
        let p = StrParser::new("");
        assert!(p.is_empty());
        assert_eq!(p.remaining(), "");
        assert_eq!(p.position(), 0);
    }

    // -- Numeric parsers --

    #[test]
    fn parse_decimal_basic() {
        let mut p = StrParser::new("12345abc");
        assert_eq!(p.parse_decimal(10), Ok(12345));
        assert_eq!(p.remaining(), "abc");
    }

    #[test]
    fn parse_decimal_max_digits() {
        let mut p = StrParser::new("123456789");
        assert_eq!(p.parse_decimal(5), Ok(12345));
        assert_eq!(p.remaining(), "6789");
    }

    #[test]
    fn parse_decimal_overflow() {
        // u64::MAX = 18446744073709551615 (20 digits)
        let mut p = StrParser::new("99999999999999999999");
        assert_eq!(p.parse_decimal(20), Err(StrParseError::BigNum));
    }

    #[test]
    fn parse_decimal_no_digits() {
        let mut p = StrParser::new("abc");
        assert_eq!(p.parse_decimal(10), Err(StrParseError::NoNum));
        assert_eq!(p.position(), 0); // position unchanged
    }

    #[test]
    fn parse_decimal_empty() {
        let mut p = StrParser::new("");
        assert_eq!(p.parse_decimal(10), Err(StrParseError::NoNum));
    }

    #[test]
    fn parse_decimal_leading_zeros() {
        let mut p = StrParser::new("007");
        assert_eq!(p.parse_decimal(10), Ok(7));
        assert!(p.is_empty());
    }

    #[test]
    fn parse_hex_basic() {
        let mut p = StrParser::new("1a2B end");
        assert_eq!(p.parse_hex(10), Ok(0x1A2B));
        assert_eq!(p.remaining(), " end");
    }

    #[test]
    fn parse_hex_max_digits() {
        let mut p = StrParser::new("DeadBeef");
        assert_eq!(p.parse_hex(4), Ok(0xDEAD));
        assert_eq!(p.remaining(), "Beef");
    }

    #[test]
    fn parse_hex_no_hex() {
        let mut p = StrParser::new("ghij");
        assert_eq!(p.parse_hex(10), Err(StrParseError::NoNum));
    }

    #[test]
    fn parse_octal_basic() {
        let mut p = StrParser::new("755rest");
        assert_eq!(p.parse_octal(10), Ok(0o755));
        assert_eq!(p.remaining(), "rest");
    }

    #[test]
    fn parse_octal_stops_at_eight() {
        let mut p = StrParser::new("1238");
        assert_eq!(p.parse_octal(10), Ok(0o123));
        assert_eq!(p.remaining(), "8");
    }

    // -- String token parsers --

    #[test]
    fn parse_word_basic() {
        let mut p = StrParser::new("hello world");
        assert_eq!(p.parse_word(100), Ok("hello"));
        assert_eq!(p.remaining(), " world");
    }

    #[test]
    fn parse_word_tab_delimiter() {
        let mut p = StrParser::new("hello\tworld");
        assert_eq!(p.parse_word(100), Ok("hello"));
        assert_eq!(p.remaining(), "\tworld");
    }

    #[test]
    fn parse_word_end_of_input() {
        let mut p = StrParser::new("only");
        assert_eq!(p.parse_word(100), Ok("only"));
        assert!(p.is_empty());
    }

    #[test]
    fn parse_word_empty() {
        let mut p = StrParser::new(" leading");
        assert_eq!(p.parse_word(100), Err(StrParseError::Short));
    }

    #[test]
    fn parse_word_exceeds_max() {
        let mut p = StrParser::new("toolongword");
        assert_eq!(p.parse_word(5), Err(StrParseError::BigNum));
    }

    #[test]
    fn parse_until_char_basic() {
        let mut p = StrParser::new("key=value");
        assert_eq!(p.parse_until_char('=', 100), Ok("key"));
        assert_eq!(p.remaining(), "=value");
    }

    #[test]
    fn parse_until_char_at_end() {
        let mut p = StrParser::new("nodelim");
        assert_eq!(p.parse_until_char('=', 100), Ok("nodelim"));
        assert!(p.is_empty());
    }

    #[test]
    fn parse_until_char_empty_token() {
        let mut p = StrParser::new("=value");
        assert_eq!(p.parse_until_char('=', 100), Err(StrParseError::Short));
    }

    #[test]
    fn parse_until_char_exceeds_max() {
        let mut p = StrParser::new("verylongkey=val");
        assert_eq!(p.parse_until_char('=', 5), Err(StrParseError::BigNum));
    }

    #[test]
    fn parse_until_newline_crlf() {
        let mut p = StrParser::new("line content\r\nnext");
        assert_eq!(p.parse_until_newline(100), Ok("line content"));
        assert_eq!(p.remaining(), "\r\nnext");
    }

    #[test]
    fn parse_until_newline_lf() {
        let mut p = StrParser::new("line\nnext");
        assert_eq!(p.parse_until_newline(100), Ok("line"));
        assert_eq!(p.remaining(), "\nnext");
    }

    #[test]
    fn parse_until_newline_empty() {
        let mut p = StrParser::new("\r\nstuff");
        assert_eq!(p.parse_until_newline(100), Err(StrParseError::Short));
    }

    // -- Quoted string --

    #[test]
    fn parse_quoted_double() {
        let mut p = StrParser::new("\"hello world\" rest");
        assert_eq!(p.parse_quoted(100), Ok("hello world"));
        assert_eq!(p.remaining(), " rest");
    }

    #[test]
    fn parse_quoted_single() {
        let mut p = StrParser::new("'hello' rest");
        assert_eq!(p.parse_quoted(100), Ok("hello"));
        assert_eq!(p.remaining(), " rest");
    }

    #[test]
    fn parse_quoted_escaped() {
        let mut p = StrParser::new(r#""say \"hi\"" rest"#);
        assert_eq!(p.parse_quoted(100), Ok(r#"say \"hi\""#));
        assert_eq!(p.remaining(), " rest");
    }

    #[test]
    fn parse_quoted_no_opening_quote() {
        let mut p = StrParser::new("no quotes");
        assert_eq!(p.parse_quoted(100), Err(StrParseError::BegQuote));
    }

    #[test]
    fn parse_quoted_missing_closing() {
        let mut p = StrParser::new("\"unclosed");
        assert_eq!(p.parse_quoted(100), Err(StrParseError::EndQuote));
    }

    #[test]
    fn parse_quoted_exceeds_max() {
        let mut p = StrParser::new("\"toolong\"");
        assert_eq!(p.parse_quoted(3), Err(StrParseError::BigNum));
    }

    #[test]
    fn parse_quoted_empty_content() {
        let mut p = StrParser::new("\"\"rest");
        assert_eq!(p.parse_quoted(100), Ok(""));
        assert_eq!(p.remaining(), "rest");
    }

    // -- HTTP-specific parsers --

    #[test]
    fn parse_header_name_basic() {
        let mut p = StrParser::new("Content-Type: text/html");
        assert_eq!(p.parse_header_name(), Ok("Content-Type"));
        assert_eq!(p.remaining(), ": text/html");
    }

    #[test]
    fn parse_header_name_empty() {
        let mut p = StrParser::new(": value");
        assert_eq!(p.parse_header_name(), Err(StrParseError::Short));
    }

    #[test]
    fn parse_header_value_basic() {
        let mut p = StrParser::new("  text/html\r\n");
        assert_eq!(p.parse_header_value(), Ok("text/html"));
        assert_eq!(p.remaining(), "\r\n");
    }

    #[test]
    fn parse_header_value_trailing_ws() {
        let mut p = StrParser::new(" value  \t \r\n");
        assert_eq!(p.parse_header_value(), Ok("value"));
    }

    #[test]
    fn parse_header_value_empty() {
        let mut p = StrParser::new("  \r\n");
        assert_eq!(p.parse_header_value(), Ok(""));
    }

    // -- Whitespace and control --

    #[test]
    fn skip_whitespace_spaces_and_tabs() {
        let mut p = StrParser::new("  \t  hello");
        p.skip_whitespace();
        assert_eq!(p.remaining(), "hello");
    }

    #[test]
    fn skip_whitespace_no_ws() {
        let mut p = StrParser::new("hello");
        p.skip_whitespace();
        assert_eq!(p.remaining(), "hello");
    }

    #[test]
    fn skip_whitespace_does_not_skip_newlines() {
        let mut p = StrParser::new("\nhello");
        p.skip_whitespace();
        // Newlines are NOT spaces/tabs — position should remain at the newline.
        assert_eq!(p.remaining(), "\nhello");
    }

    #[test]
    fn skip_char_match() {
        let mut p = StrParser::new(":value");
        assert!(p.skip_char(':'));
        assert_eq!(p.remaining(), "value");
    }

    #[test]
    fn skip_char_no_match() {
        let mut p = StrParser::new("value");
        assert!(!p.skip_char(':'));
        assert_eq!(p.remaining(), "value");
    }

    #[test]
    fn skip_char_empty() {
        let mut p = StrParser::new("");
        assert!(!p.skip_char(':'));
    }

    #[test]
    fn peek_basic() {
        let p = StrParser::new("abc");
        assert_eq!(p.peek(), Some('a'));
    }

    #[test]
    fn peek_empty() {
        let p = StrParser::new("");
        assert_eq!(p.peek(), None);
    }

    #[test]
    fn expect_success() {
        let mut p = StrParser::new("HTTP/1.1 200");
        assert!(p.expect("HTTP/1.1").is_ok());
        assert_eq!(p.remaining(), " 200");
    }

    #[test]
    fn expect_too_short() {
        let mut p = StrParser::new("HT");
        assert_eq!(p.expect("HTTP"), Err(StrParseError::Short));
        assert_eq!(p.position(), 0); // position unchanged
    }

    #[test]
    fn expect_mismatch() {
        let mut p = StrParser::new("HTTP/2.0");
        assert_eq!(p.expect("HTTP/1.1"), Err(StrParseError::Byte));
        assert_eq!(p.position(), 0); // position unchanged
    }

    // -- Case-insensitive functions --

    #[test]
    fn starts_with_ignore_case_match() {
        assert!(starts_with_ignore_case("Content-Type: text", "content-type"));
        assert!(starts_with_ignore_case("CONTENT-TYPE", "Content-Type"));
    }

    #[test]
    fn starts_with_ignore_case_no_match() {
        assert!(!starts_with_ignore_case("Content-Length", "content-type"));
    }

    #[test]
    fn starts_with_ignore_case_too_short() {
        assert!(!starts_with_ignore_case("Con", "content-type"));
    }

    #[test]
    fn starts_with_ignore_case_exact() {
        assert!(starts_with_ignore_case("abc", "ABC"));
    }

    #[test]
    fn eq_ignore_case_equal() {
        assert!(eq_ignore_case("Content-Length", "content-length"));
        assert!(eq_ignore_case("ABC", "abc"));
        assert!(eq_ignore_case("", ""));
    }

    #[test]
    fn eq_ignore_case_not_equal() {
        assert!(!eq_ignore_case("Content-Length", "content-type"));
        assert!(!eq_ignore_case("short", "longer"));
    }

    // -- Combined workflow --

    #[test]
    fn parse_http_header_line() {
        let mut p = StrParser::new("Content-Length: 42\r\n");

        let name = p.parse_header_name().unwrap();
        assert_eq!(name, "Content-Length");

        assert!(p.skip_char(':'));

        let value = p.parse_header_value().unwrap();
        assert_eq!(value, "42");

        assert_eq!(p.remaining(), "\r\n");
    }

    #[test]
    fn parse_ftp_response_line() {
        let mut p = StrParser::new("220 Welcome to FTP\r\n");

        let code = p.parse_decimal(3).unwrap();
        assert_eq!(code, 220);

        assert!(p.skip_char(' '));

        let msg = p.parse_until_newline(1000).unwrap();
        assert_eq!(msg, "Welcome to FTP");
    }
}
