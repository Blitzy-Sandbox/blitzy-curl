//! URL percent-encoding and decoding functions.
//!
//! Rust rewrite of `lib/escape.c` — provides URL encoding/decoding functions
//! for the curl library. Implements `curl_easy_escape` and `curl_easy_unescape`
//! with behavior-for-behavior parity with curl 8.x.
//!
//! # Encoding
//!
//! All characters except RFC 3986 unreserved characters (`A-Z`, `a-z`, `0-9`,
//! `'-'`, `'.'`, `'_'`, `'~'`) are percent-encoded using uppercase hex digits
//! (e.g., `%2F` not `%2f`), matching curl 8.x output exactly.
//!
//! # Decoding
//!
//! `%XX` hex sequences are decoded to raw bytes. Invalid percent sequences
//! (e.g., `%` not followed by two valid hex digits) are passed through
//! unchanged, preserving curl 8.x behavior.
//!
//! # ABI Compatibility
//!
//! The [`curl_easy_escape`] and [`curl_easy_unescape`] functions mirror the
//! semantics of their C counterparts for consumption by the FFI layer. The
//! `data` (easy-handle) parameter is omitted because it has been ignored
//! since libcurl 7.82.0.

use std::borrow::Cow;

use percent_encoding::{percent_decode_str, percent_encode, AsciiSet, NON_ALPHANUMERIC};

use crate::error::CurlError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Custom [`AsciiSet`] for curl-compatible URL percent-encoding.
///
/// Encodes all bytes **except** RFC 3986 unreserved characters:
///
/// * `A-Z`, `a-z`, `0-9`
/// * `'-'`, `'.'`, `'_'`, `'~'`
///
/// [`NON_ALPHANUMERIC`] encodes everything except `A-Za-z0-9`. We then
/// remove the four additional characters that RFC 3986 classifies as
/// unreserved so that they pass through unencoded.
const CURL_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// URL rejection mode controlling which decoded byte values are rejected.
///
/// Mirrors the C `enum urlreject` from `lib/escape.h`. Discriminant values
/// start at 2 so that a debug assertion in the C code can detect legacy
/// invocations that passed `TRUE`/`FALSE` (0 and 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
#[allow(dead_code)] // Variants used by other crate modules (url.rs, etc.) not yet created
pub(crate) enum UrlReject {
    /// Accept all decoded byte values (`REJECT_NADA = 2`).
    Nada = 2,
    /// Reject decoded control characters (byte value < 0x20) (`REJECT_CTRL = 3`).
    Ctrl = 3,
    /// Reject decoded zero bytes (`REJECT_ZERO = 4`).
    Zero = 4,
}

// ---------------------------------------------------------------------------
// Public API — Encoding
// ---------------------------------------------------------------------------

/// Percent-encode a UTF-8 string per RFC 3986.
///
/// All characters except unreserved characters (`A-Z`, `a-z`, `0-9`, `'-'`,
/// `'.'`, `'_'`, `'~'`) are encoded as `%XX` with **uppercase** hex digits,
/// matching the output of curl 8.x `curl_easy_escape` exactly.
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::escape::url_encode;
/// assert_eq!(url_encode("hello world"), "hello%20world");
/// assert_eq!(url_encode("foo/bar"), "foo%2Fbar");
/// assert_eq!(url_encode("a-b_c.d~e"), "a-b_c.d~e"); // unreserved pass-through
/// ```
pub fn url_encode(input: &str) -> String {
    url_encode_bytes(input.as_bytes())
}

/// Percent-encode raw bytes per RFC 3986.
///
/// Operates on arbitrary byte slices — not restricted to valid UTF-8. Uses
/// the same encoding rules as [`url_encode`]: all bytes except unreserved
/// characters are encoded as `%XX` with uppercase hex digits.
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::escape::url_encode_bytes;
/// assert_eq!(url_encode_bytes(b"\x00\xff"), "%00%FF");
/// assert_eq!(url_encode_bytes(b"hello"), "hello");
/// ```
pub fn url_encode_bytes(input: &[u8]) -> String {
    percent_encode(input, CURL_ENCODE_SET).to_string()
}

// ---------------------------------------------------------------------------
// Public API — Decoding
// ---------------------------------------------------------------------------

/// Decode a percent-encoded string into raw bytes.
///
/// Handles `%XX` hex sequences and converts `+` to space for query-string
/// compatibility (`application/x-www-form-urlencoded`). Returns raw bytes
/// since decoded data may not be valid UTF-8.
///
/// Invalid percent sequences (e.g., `%` not followed by two valid hex
/// digits) are passed through unchanged, matching curl 8.x behavior.
///
/// # Errors
///
/// This function uses the accept-all rejection mode and does not produce
/// errors on any well-formed or malformed input. The `Result` return type
/// is provided for API consistency with [`url_decode_string`] and the
/// internal [`urldecode`] function.
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::escape::url_decode;
/// let decoded = url_decode("hello%20world").unwrap();
/// assert_eq!(decoded, b"hello world");
///
/// // Plus sign converted to space
/// let decoded = url_decode("a+b").unwrap();
/// assert_eq!(decoded, b"a b");
///
/// // Encoded plus (%2B) stays as literal '+'
/// let decoded = url_decode("a%2Bb").unwrap();
/// assert_eq!(decoded, b"a+b");
/// ```
pub fn url_decode(input: &str) -> Result<Vec<u8>, CurlError> {
    // Convert '+' to space for query-string compatibility *before*
    // percent-decoding. This ensures that `%2B` still decodes to '+'.
    // We use `Cow` to avoid allocation when no '+' is present.
    let processed: Cow<'_, str> = if input.contains('+') {
        Cow::Owned(input.replace('+', " "))
    } else {
        Cow::Borrowed(input)
    };
    // Use `percent_decode_str` for `%XX` handling. It passes through
    // invalid sequences (e.g., `%zz`, trailing `%`) unchanged.
    Ok(percent_decode_str(&processed).collect())
}

/// Decode a percent-encoded string into a valid UTF-8 string.
///
/// Performs the same decoding as [`url_decode`] (including `+` → space)
/// and then validates that the resulting bytes form valid UTF-8.
///
/// # Errors
///
/// * [`CurlError::UrlMalformat`] — if the percent-encoding is rejected
///   (only possible with stricter rejection modes via [`urldecode`]).
/// * [`CurlError::BadContentEncoding`] — if the decoded bytes are not
///   valid UTF-8.
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::escape::url_decode_string;
/// assert_eq!(url_decode_string("hello%20world").unwrap(), "hello world");
///
/// // Invalid UTF-8 sequence
/// assert!(url_decode_string("%FF").is_err());
/// ```
pub fn url_decode_string(input: &str) -> Result<String, CurlError> {
    let bytes = url_decode(input)?;
    String::from_utf8(bytes).map_err(|_| CurlError::BadContentEncoding)
}

// ---------------------------------------------------------------------------
// Public API — ABI Compatibility
// ---------------------------------------------------------------------------

/// Percent-encode a string, matching `curl_easy_escape` C API behavior.
///
/// The `data` (easy-handle) parameter from the C signature is omitted
/// because it has been ignored since libcurl 7.82.0.
///
/// When `length` is `0`, the entire input string is encoded. When `length`
/// is positive, only the first `length` bytes of `string` are encoded.
///
/// Returns [`None`] for invalid arguments (negative length, or length
/// exceeding the input byte length).
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::escape::curl_easy_escape;
/// assert_eq!(curl_easy_escape("hello world", 0), Some("hello%20world".into()));
/// assert_eq!(curl_easy_escape("hello", 3), Some("hel".into()));
/// assert_eq!(curl_easy_escape("", 0), Some(String::new()));
/// assert_eq!(curl_easy_escape("test", -1), None);
/// ```
pub fn curl_easy_escape(string: &str, length: i32) -> Option<String> {
    // Reject negative lengths — matches C: returns NULL for inlength < 0.
    if length < 0 {
        return None;
    }

    // Determine the effective byte slice to encode.
    let input_bytes = if length == 0 {
        // When length is zero, encode the full string (matches C: uses strlen).
        string.as_bytes()
    } else {
        let len = length as usize;
        // Validate that the requested length falls within the input.
        // In C this would be UB; in Rust we return None for safety.
        string.as_bytes().get(..len)?
    };

    // Empty input returns an empty string — matches C: strdup("").
    if input_bytes.is_empty() {
        return Some(String::new());
    }

    Some(url_encode_bytes(input_bytes))
}

/// Percent-decode a string, matching `curl_easy_unescape` C API behavior.
///
/// The `data` (easy-handle) parameter from the C signature is omitted
/// because it has been ignored since libcurl 7.82.0.
///
/// When `length` is `0`, the full input string is decoded. When `length` is
/// positive, only the first `length` bytes of `string` are decoded.
///
/// Unlike [`url_decode`], this function does **not** convert `+` to space,
/// faithfully matching curl 8.x `curl_easy_unescape` behavior.
///
/// Returns the decoded bytes and the output length as an `i32`.
///
/// # Errors
///
/// * [`CurlError::BadFunctionArgument`] — negative length, or length
///   exceeding the input byte length / not on a UTF-8 boundary.
/// * [`CurlError::UrlMalformat`] — if the output length exceeds
///   [`i32::MAX`] (matches C behavior where the function frees and returns
///   `NULL` when the output is too large).
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::escape::curl_easy_unescape;
/// let (bytes, len) = curl_easy_unescape("hello%20world", 0).unwrap();
/// assert_eq!(bytes, b"hello world");
/// assert_eq!(len, 11);
///
/// // '+' is NOT converted to space (matches curl 8.x)
/// let (bytes, _) = curl_easy_unescape("a+b", 0).unwrap();
/// assert_eq!(bytes, b"a+b");
/// ```
pub fn curl_easy_unescape(string: &str, length: i32) -> Result<(Vec<u8>, i32), CurlError> {
    // Reject negative lengths — matches C: returns NULL for length < 0.
    if length < 0 {
        return Err(CurlError::BadFunctionArgument);
    }

    // Determine the input slice to decode.
    let input = if length == 0 {
        // When length is zero, decode the full string (matches C: uses strlen).
        string
    } else {
        let len = length as usize;
        // Validate the requested length is within bounds and on a char boundary.
        string
            .get(..len)
            .ok_or(CurlError::BadFunctionArgument)?
    };

    // Decode using the internal decoder — no '+' conversion, accept all bytes
    // (REJECT_NADA). This matches `curl_easy_unescape` calling
    // `Curl_urldecode(..., REJECT_NADA)`.
    let decoded = urldecode(input, UrlReject::Nada)?;

    // Check that the output length fits in i32. The C code frees and returns
    // NULL if `outputlen > INT_MAX`.
    let output_len = i32::try_from(decoded.len()).map_err(|_| CurlError::UrlMalformat)?;

    Ok((decoded, output_len))
}

// ---------------------------------------------------------------------------
// Crate-internal functions
// ---------------------------------------------------------------------------

/// Core URL decoder with configurable byte rejection.
///
/// This is the Rust equivalent of C `Curl_urldecode()`. It decodes `%XX`
/// hex sequences and applies the specified rejection policy to each decoded
/// byte.
///
/// **Unlike** [`url_decode`], this function does **not** convert `+` to
/// space. It matches the C `Curl_urldecode` behavior exactly.
///
/// # Rejection Modes
///
/// * [`UrlReject::Nada`] — accept all decoded byte values.
/// * [`UrlReject::Ctrl`] — reject decoded bytes with value < 0x20.
/// * [`UrlReject::Zero`] — reject decoded zero bytes.
///
/// # Errors
///
/// Returns [`CurlError::UrlMalformat`] if a decoded byte is rejected by
/// the specified rejection mode.
pub(crate) fn urldecode(input: &str, reject: UrlReject) -> Result<Vec<u8>, CurlError> {
    let src = input.as_bytes();
    let mut output = Vec::with_capacity(src.len());
    let mut i = 0;

    while i < src.len() {
        let byte = src[i];

        if byte == b'%' && i + 2 < src.len() {
            // Attempt to decode the two-character hex sequence after '%'.
            if let Some(decoded) = decode_hex_pair(src[i + 1], src[i + 2]) {
                // Apply the rejection policy to the decoded byte value.
                check_reject(decoded, reject)?;
                output.push(decoded);
                i += 3;
                continue;
            }
        }

        // Not a valid percent-encoded sequence — pass through byte as-is.
        // This handles:
        //   - Normal literal characters
        //   - '%' at end of input (fewer than 2 chars remaining)
        //   - '%' followed by non-hex characters
        output.push(byte);
        i += 1;
    }

    Ok(output)
}

/// Encode binary data as lowercase hex-encoded ASCII string.
///
/// Rust equivalent of C `Curl_hexencode()`. Writes at most
/// `min(src.len(), out_buf.len() / 2)` hex pairs into `out_buf` and
/// returns the number of bytes written to the output buffer.
///
/// # Examples
///
/// ```ignore
/// let mut buf = [0u8; 8];
/// let n = hex_encode_lower(&[0xAB, 0xCD, 0xEF], &mut buf);
/// assert_eq!(n, 6);
/// assert_eq!(&buf[..6], b"abcdef");
/// ```
#[allow(dead_code)] // Used by other crate modules (auth, etc.) not yet created
pub(crate) fn hex_encode_lower(src: &[u8], out_buf: &mut [u8]) -> usize {
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    let pairs = std::cmp::min(src.len(), out_buf.len() / 2);
    for (idx, &b) in src.iter().take(pairs).enumerate() {
        out_buf[idx * 2] = HEX_LOWER[(b >> 4) as usize];
        out_buf[idx * 2 + 1] = HEX_LOWER[(b & 0x0F) as usize];
    }
    pairs * 2
}

/// Write a single byte as a two-character uppercase hex representation.
///
/// Rust equivalent of C `Curl_hexbyte()`.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(hex_byte_upper(0x2F), [b'2', b'F']);
/// ```
#[allow(dead_code)] // Used by other crate modules (escape encoding paths) not yet created
pub(crate) fn hex_byte_upper(val: u8) -> [u8; 2] {
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    [
        HEX_UPPER[(val >> 4) as usize],
        HEX_UPPER[(val & 0x0F) as usize],
    ]
}

/// Encode binary data as a lowercase hex string.
///
/// Convenience wrapper around [`hex_encode_lower`] that returns a new
/// `String` instead of writing to a pre-allocated buffer.
#[allow(dead_code)] // Used by other crate modules (auth, etc.) not yet created
pub(crate) fn hex_encode_lower_string(src: &[u8]) -> String {
    let mut buf = vec![0u8; src.len() * 2];
    let n = hex_encode_lower(src, &mut buf);
    // SAFETY-NOTE: hex_encode_lower only writes ASCII hex digits,
    // which are always valid UTF-8. No `unsafe` is needed — we just
    // convert the known-ASCII bytes.
    String::from_utf8(buf[..n].to_vec()).expect("hex digits are valid ASCII/UTF-8")
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Decode a pair of ASCII hex characters into a single byte value.
///
/// Returns [`None`] if either character is not a valid hexadecimal digit
/// (`0-9`, `a-f`, `A-F`).
#[inline]
fn decode_hex_pair(hi: u8, lo: u8) -> Option<u8> {
    Some((hex_val(hi)? << 4) | hex_val(lo)?)
}

/// Convert a single ASCII hex character to its numeric value (0–15).
///
/// Returns [`None`] if the byte is not a valid hex digit.
#[inline]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Apply the URL rejection policy to a decoded byte value.
///
/// # Errors
///
/// Returns [`CurlError::UrlMalformat`] if the byte is rejected by the
/// active policy.
#[inline]
fn check_reject(byte: u8, reject: UrlReject) -> Result<(), CurlError> {
    match reject {
        UrlReject::Ctrl if byte < 0x20 => Err(CurlError::UrlMalformat),
        UrlReject::Zero if byte == 0 => Err(CurlError::UrlMalformat),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ===== Encoding tests =====

    #[test]
    fn encode_empty_string() {
        assert_eq!(url_encode(""), "");
    }

    #[test]
    fn encode_unreserved_passthrough() {
        // RFC 3986 unreserved: A-Z, a-z, 0-9, '-', '.', '_', '~'
        let unreserved =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        assert_eq!(url_encode(unreserved), unreserved);
    }

    #[test]
    fn encode_space() {
        assert_eq!(url_encode("hello world"), "hello%20world");
    }

    #[test]
    fn encode_special_characters() {
        assert_eq!(url_encode("/"), "%2F");
        assert_eq!(url_encode("?"), "%3F");
        assert_eq!(url_encode("&"), "%26");
        assert_eq!(url_encode("="), "%3D");
        assert_eq!(url_encode("#"), "%23");
        assert_eq!(url_encode("+"), "%2B");
        assert_eq!(url_encode("@"), "%40");
        assert_eq!(url_encode(":"), "%3A");
        assert_eq!(url_encode("["), "%5B");
        assert_eq!(url_encode("]"), "%5D");
    }

    #[test]
    fn encode_uses_uppercase_hex() {
        // Must produce uppercase hex digits (matching curl 8.x)
        let encoded = url_encode("\x0a\x0b\x0c\x0d\x0e\x0f");
        assert_eq!(encoded, "%0A%0B%0C%0D%0E%0F");
    }

    #[test]
    fn encode_bytes_raw() {
        assert_eq!(url_encode_bytes(&[0x00]), "%00");
        assert_eq!(url_encode_bytes(&[0xFF]), "%FF");
        assert_eq!(url_encode_bytes(&[0x80]), "%80");
        assert_eq!(url_encode_bytes(&[0xAB, 0xCD]), "%AB%CD");
    }

    #[test]
    fn encode_bytes_mixed() {
        assert_eq!(url_encode_bytes(b"a b"), "a%20b");
        assert_eq!(url_encode_bytes(b"test"), "test");
        assert_eq!(url_encode_bytes(b""), "");
    }

    #[test]
    fn encode_complex_url() {
        assert_eq!(
            url_encode("https://example.com/path?key=value&foo=bar"),
            "https%3A%2F%2Fexample.com%2Fpath%3Fkey%3Dvalue%26foo%3Dbar"
        );
    }

    // ===== Decoding tests =====

    #[test]
    fn decode_empty_string() {
        assert_eq!(url_decode("").unwrap(), b"");
    }

    #[test]
    fn decode_no_encoding() {
        assert_eq!(url_decode("hello").unwrap(), b"hello");
    }

    #[test]
    fn decode_percent_space() {
        assert_eq!(url_decode("hello%20world").unwrap(), b"hello world");
    }

    #[test]
    fn decode_plus_to_space() {
        assert_eq!(url_decode("hello+world").unwrap(), b"hello world");
    }

    #[test]
    fn decode_encoded_plus_stays_plus() {
        // %2B should decode to literal '+'
        assert_eq!(url_decode("a%2Bb").unwrap(), b"a+b");
    }

    #[test]
    fn decode_multiple_percent() {
        assert_eq!(
            url_decode("%48%65%6C%6C%6F").unwrap(),
            b"Hello"
        );
    }

    #[test]
    fn decode_mixed_case_hex() {
        // Both upper and lower case hex digits are accepted
        assert_eq!(url_decode("%2f").unwrap(), b"/");
        assert_eq!(url_decode("%2F").unwrap(), b"/");
        assert_eq!(url_decode("%aB").unwrap(), vec![0xAB]);
    }

    #[test]
    fn decode_invalid_percent_passthrough() {
        // '%' not followed by two hex digits is passed through unchanged
        assert_eq!(url_decode("abc%zz").unwrap(), b"abc%zz");
        assert_eq!(url_decode("abc%").unwrap(), b"abc%");
        assert_eq!(url_decode("abc%2").unwrap(), b"abc%2");
        assert_eq!(url_decode("%").unwrap(), b"%");
        assert_eq!(url_decode("%%").unwrap(), b"%%");
    }

    #[test]
    fn decode_null_byte() {
        // url_decode uses NADA mode — null bytes are accepted
        assert_eq!(url_decode("%00").unwrap(), vec![0x00]);
    }

    #[test]
    fn decode_string_valid_utf8() {
        assert_eq!(
            url_decode_string("hello%20world").unwrap(),
            "hello world"
        );
    }

    #[test]
    fn decode_string_plus_to_space() {
        assert_eq!(url_decode_string("a+b").unwrap(), "a b");
    }

    #[test]
    fn decode_string_invalid_utf8() {
        // 0xFF is not valid UTF-8 by itself
        let err = url_decode_string("%FF").unwrap_err();
        assert_eq!(err, CurlError::BadContentEncoding);
    }

    #[test]
    fn decode_string_multibyte_utf8() {
        // UTF-8 encoding of '€' (U+20AC) is E2 82 AC
        assert_eq!(url_decode_string("%E2%82%AC").unwrap(), "€");
    }

    // ===== ABI compatibility tests — curl_easy_escape =====

    #[test]
    fn easy_escape_basic() {
        assert_eq!(
            curl_easy_escape("hello world", 0),
            Some("hello%20world".to_string())
        );
    }

    #[test]
    fn easy_escape_with_length() {
        // Only encode the first 5 bytes
        assert_eq!(
            curl_easy_escape("hello world", 5),
            Some("hello".to_string())
        );
    }

    #[test]
    fn easy_escape_partial_with_special() {
        // "a b c" with length 3 → takes "a b" (3 bytes) → "a%20b"
        assert_eq!(
            curl_easy_escape("a b c", 3),
            Some("a%20b".to_string())
        );
        // "a b c" with length 2 → takes "a " (2 bytes) → "a%20"
        assert_eq!(
            curl_easy_escape("a b c", 2),
            Some("a%20".to_string())
        );
    }

    #[test]
    fn easy_escape_empty_string() {
        assert_eq!(curl_easy_escape("", 0), Some(String::new()));
    }

    #[test]
    fn easy_escape_negative_length() {
        assert_eq!(curl_easy_escape("test", -1), None);
    }

    #[test]
    fn easy_escape_length_exceeds_input() {
        assert_eq!(curl_easy_escape("ab", 5), None);
    }

    #[test]
    fn easy_escape_exact_length() {
        assert_eq!(
            curl_easy_escape("ab", 2),
            Some("ab".to_string())
        );
    }

    // ===== ABI compatibility tests — curl_easy_unescape =====

    #[test]
    fn easy_unescape_basic() {
        let (bytes, len) = curl_easy_unescape("hello%20world", 0).unwrap();
        assert_eq!(bytes, b"hello world");
        assert_eq!(len, 11);
    }

    #[test]
    fn easy_unescape_no_plus_conversion() {
        // curl_easy_unescape does NOT convert '+' to space
        let (bytes, _) = curl_easy_unescape("hello+world", 0).unwrap();
        assert_eq!(bytes, b"hello+world");
    }

    #[test]
    fn easy_unescape_with_length() {
        // "hello%20" (8 bytes) decodes to "hello " (6 bytes)
        let (bytes, len) = curl_easy_unescape("hello%20world", 8).unwrap();
        assert_eq!(bytes, b"hello ");
        assert_eq!(len, 6);
    }

    #[test]
    fn easy_unescape_negative_length() {
        let err = curl_easy_unescape("test", -1).unwrap_err();
        assert_eq!(err, CurlError::BadFunctionArgument);
    }

    #[test]
    fn easy_unescape_empty() {
        let (bytes, len) = curl_easy_unescape("", 0).unwrap();
        assert_eq!(bytes, b"");
        assert_eq!(len, 0);
    }

    #[test]
    fn easy_unescape_length_exceeds_input() {
        let err = curl_easy_unescape("ab", 5).unwrap_err();
        assert_eq!(err, CurlError::BadFunctionArgument);
    }

    #[test]
    fn easy_unescape_null_byte_preserved() {
        let (bytes, len) = curl_easy_unescape("%00", 0).unwrap();
        assert_eq!(bytes, vec![0x00]);
        assert_eq!(len, 1);
    }

    // ===== Internal urldecode tests =====

    #[test]
    fn urldecode_nada_accepts_all() {
        let result = urldecode("%00%01%1F%20%7F%FF", UrlReject::Nada).unwrap();
        assert_eq!(result, vec![0x00, 0x01, 0x1F, 0x20, 0x7F, 0xFF]);
    }

    #[test]
    fn urldecode_reject_ctrl() {
        // Control characters (< 0x20) are rejected
        assert_eq!(
            urldecode("%01", UrlReject::Ctrl).unwrap_err(),
            CurlError::UrlMalformat
        );
        assert_eq!(
            urldecode("%1F", UrlReject::Ctrl).unwrap_err(),
            CurlError::UrlMalformat
        );
        // 0x20 (space) is accepted — it's not a control character
        assert_eq!(urldecode("%20", UrlReject::Ctrl).unwrap(), vec![0x20]);
        // Normal ASCII is fine
        assert_eq!(urldecode("hello", UrlReject::Ctrl).unwrap(), b"hello");
    }

    #[test]
    fn urldecode_reject_zero() {
        assert_eq!(
            urldecode("%00", UrlReject::Zero).unwrap_err(),
            CurlError::UrlMalformat
        );
        // 0x01 is accepted (only zero is rejected)
        assert_eq!(urldecode("%01", UrlReject::Zero).unwrap(), vec![0x01]);
    }

    #[test]
    fn urldecode_no_plus_conversion() {
        // Internal urldecode does NOT convert '+' to space
        assert_eq!(urldecode("a+b", UrlReject::Nada).unwrap(), b"a+b");
    }

    #[test]
    fn urldecode_invalid_sequences() {
        assert_eq!(urldecode("%zz", UrlReject::Nada).unwrap(), b"%zz");
        assert_eq!(urldecode("%", UrlReject::Nada).unwrap(), b"%");
        assert_eq!(urldecode("%2", UrlReject::Nada).unwrap(), b"%2");
    }

    // ===== Hex helper tests =====

    #[test]
    fn hex_byte_upper_values() {
        assert_eq!(hex_byte_upper(0x00), [b'0', b'0']);
        assert_eq!(hex_byte_upper(0x2F), [b'2', b'F']);
        assert_eq!(hex_byte_upper(0xFF), [b'F', b'F']);
        assert_eq!(hex_byte_upper(0xAB), [b'A', b'B']);
    }

    #[test]
    fn hex_encode_lower_basic() {
        let mut buf = [0u8; 10];
        let n = hex_encode_lower(&[0xAB, 0xCD], &mut buf);
        assert_eq!(n, 4);
        assert_eq!(&buf[..4], b"abcd");
    }

    #[test]
    fn hex_encode_lower_empty() {
        let mut buf = [0u8; 10];
        let n = hex_encode_lower(&[], &mut buf);
        assert_eq!(n, 0);
    }

    #[test]
    fn hex_encode_lower_buffer_too_small() {
        // Buffer can only hold 1 hex pair (2 bytes)
        let mut buf = [0u8; 2];
        let n = hex_encode_lower(&[0xAB, 0xCD, 0xEF], &mut buf);
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], b"ab");
    }

    #[test]
    fn hex_encode_lower_string_helper() {
        assert_eq!(hex_encode_lower_string(&[0xAB, 0xCD, 0xEF]), "abcdef");
        assert_eq!(hex_encode_lower_string(&[]), "");
    }

    // ===== Round-trip tests =====

    #[test]
    fn roundtrip_encode_decode() {
        let original = "Hello, World! /path?key=value&x=1+2";
        let encoded = url_encode(original);
        // url_decode converts '+' to space, so we use urldecode for exact roundtrip
        let decoded = urldecode(&encoded, UrlReject::Nada).unwrap();
        assert_eq!(decoded, original.as_bytes());
    }

    #[test]
    fn roundtrip_abi_compat() {
        let original = "test string with spaces & special=chars";
        let encoded = curl_easy_escape(original, 0).unwrap();
        let (decoded, _) = curl_easy_unescape(&encoded, 0).unwrap();
        assert_eq!(decoded, original.as_bytes());
    }

    #[test]
    fn roundtrip_binary_data() {
        let binary: Vec<u8> = (0..=255).collect();
        let encoded = url_encode_bytes(&binary);
        let decoded = urldecode(&encoded, UrlReject::Nada).unwrap();
        assert_eq!(decoded, binary);
    }
}
