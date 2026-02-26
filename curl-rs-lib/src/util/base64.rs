//! Base64 encoding and decoding — Rust replacement for C `lib/curlx/base64.c`.
//!
//! Supports both standard (RFC 4648 §4, with padding) and URL-safe
//! (RFC 4648 §5, no padding) alphabets. The implementation delegates to
//! the [`base64`](https://crates.io/crates/base64) crate (0.22.x) while
//! preserving the curl-compatible API surface, including whitespace-skipping
//! decode behaviour used when handling folded header values.
//!
//! # C Correspondence
//!
//! | Rust                      | C                                          |
//! |---------------------------|--------------------------------------------|
//! | `encode()`                | `Curl_base64_encode()`                     |
//! | `encode_url_safe()`       | `Curl_base64url_encode()`                  |
//! | `decode()`                | `Curl_base64_decode()`                     |
//! | `decode_url_safe()`       | URL-safe variant of decode                 |
//! | `encoded_len()`           | inline `(len + 2) / 3 * 4`                |
//! | `decoded_len_estimate()`  | inline `len * 3 / 4`                       |
//! | `encode_to_buf()`         | auth modules writing into `struct dynbuf`  |
//! | `decode_to_vec()`         | alias for `decode()`                       |

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::alphabet;
use base64::Engine;

use crate::error::CurlError;
use crate::util::dynbuf::DynBuf;

/// A decode-only engine that accepts both padded and un-padded standard
/// Base64 input, matching the behaviour of C `Curl_base64_decode`.
static STANDARD_INDIFFERENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum input length accepted for Base64 encoding.
///
/// Prevents accidental multi-gigabyte allocations. 16 MB matches the
/// practical ceiling used by auth / MIME encoders in the C implementation.
pub const MAX_BASE64_INPUT: usize = 16_000_000;

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Standard Base64-encode `input` with padding (`=`).
///
/// Returns an empty [`String`] for empty input.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::util::base64;
///
/// assert_eq!(base64::encode(b"Hello"), "SGVsbG8=");
/// assert_eq!(base64::encode(b""), "");
/// ```
pub fn encode(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }
    STANDARD.encode(input)
}

/// URL-safe Base64-encode `input` **without** padding.
///
/// Uses the alphabet `A-Z a-z 0-9 - _` ('+' → '-', '/' → '_', no '=').
///
/// # Examples
///
/// ```
/// use curl_rs_lib::util::base64;
///
/// let encoded = base64::encode_url_safe(b"Hello");
/// assert!(!encoded.contains('+'));
/// assert!(!encoded.contains('/'));
/// assert!(!encoded.contains('='));
/// ```
pub fn encode_url_safe(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }
    URL_SAFE_NO_PAD.encode(input)
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Standard Base64-decode `input`.
///
/// Accepts both padded and un-padded input. Whitespace characters
/// (CR, LF, space, tab) are silently stripped before decoding to match
/// the C `Curl_base64_decode` behaviour (necessary when decoding header
/// values that may be folded across multiple lines).
///
/// Returns [`CurlError::BadContentEncoding`] on invalid characters.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::util::base64;
///
/// let decoded = base64::decode("SGVsbG8=").unwrap();
/// assert_eq!(decoded, b"Hello");
/// ```
pub fn decode(input: &str) -> Result<Vec<u8>, CurlError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    // Strip whitespace (CR, LF, space, tab) matching C curl behaviour.
    let clean: String = input
        .chars()
        .filter(|&c| c != ' ' && c != '\t' && c != '\r' && c != '\n')
        .collect();

    STANDARD_INDIFFERENT
        .decode(&clean)
        .map_err(|_| CurlError::BadContentEncoding)
}

/// URL-safe Base64-decode `input`.
///
/// Strips whitespace and uses the URL-safe alphabet.
pub fn decode_url_safe(input: &str) -> Result<Vec<u8>, CurlError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let clean: String = input
        .chars()
        .filter(|&c| c != ' ' && c != '\t' && c != '\r' && c != '\n')
        .collect();

    URL_SAFE_NO_PAD
        .decode(&clean)
        .map_err(|_| CurlError::BadContentEncoding)
}

// ---------------------------------------------------------------------------
// Length helpers
// ---------------------------------------------------------------------------

/// Calculate the exact encoded length (standard, with padding).
///
/// Formula: `ceil(n / 3) * 4`.
#[inline]
pub fn encoded_len(input_len: usize) -> usize {
    input_len.div_ceil(3) * 4
}

/// Estimate the decoded length from an encoded length.
///
/// Formula: `n * 3 / 4`. Actual length may be 1–2 bytes shorter due to
/// padding.
#[inline]
pub fn decoded_len_estimate(encoded_len: usize) -> usize {
    encoded_len * 3 / 4
}

// ---------------------------------------------------------------------------
// Buffer operations
// ---------------------------------------------------------------------------

/// Encode `input` directly into a [`DynBuf`], avoiding an intermediate
/// [`String`] allocation for large payloads.
///
/// Used by authentication modules (Basic, NTLM, Digest, SASL) that build
/// authorisation headers containing Base64-encoded credentials.
pub fn encode_to_buf(input: &[u8], buf: &mut DynBuf) -> Result<(), CurlError> {
    if input.len() > MAX_BASE64_INPUT {
        return Err(CurlError::TooLarge);
    }
    let encoded = encode(input);
    buf.add_str(&encoded)
}

/// Decode Base64 `input` into a freshly allocated [`Vec<u8>`].
///
/// This is an explicit-naming alias for [`decode()`] used in call-sites
/// where the return-type context is ambiguous.
#[inline]
pub fn decode_to_vec(input: &str) -> Result<Vec<u8>, CurlError> {
    decode(input)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Encoding -----------------------------------------------------------

    #[test]
    fn encode_empty_input() {
        assert_eq!(encode(b""), "");
    }

    #[test]
    fn encode_hello() {
        assert_eq!(encode(b"Hello"), "SGVsbG8=");
    }

    #[test]
    fn encode_padding_one_byte() {
        // "a" → "YQ=="
        assert_eq!(encode(b"a"), "YQ==");
    }

    #[test]
    fn encode_padding_two_bytes() {
        // "ab" → "YWI="
        assert_eq!(encode(b"ab"), "YWI=");
    }

    #[test]
    fn encode_no_padding_three_bytes() {
        // "abc" → "YWJj"
        let encoded = encode(b"abc");
        assert!(!encoded.ends_with('='));
    }

    #[test]
    fn encode_binary_data() {
        let data: Vec<u8> = (0u8..=255).collect();
        let encoded = encode(&data);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    // -- URL-safe encoding --------------------------------------------------

    #[test]
    fn encode_url_safe_no_plus_slash_padding() {
        let encoded = encode_url_safe(b"\xfb\xff\xfe");
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
    }

    #[test]
    fn encode_url_safe_empty() {
        assert_eq!(encode_url_safe(b""), "");
    }

    #[test]
    fn url_safe_round_trip() {
        let data = b"Hello, World! \xff\x00\x01";
        let encoded = encode_url_safe(data);
        let decoded = decode_url_safe(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    // -- Decoding -----------------------------------------------------------

    #[test]
    fn decode_empty_input() {
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn decode_standard_padded() {
        assert_eq!(decode("SGVsbG8=").unwrap(), b"Hello");
    }

    #[test]
    fn decode_standard_unpadded() {
        // Some encoders omit padding; our decode should still handle it.
        assert_eq!(decode("SGVsbG8").unwrap(), b"Hello");
    }

    #[test]
    fn decode_whitespace_skipped() {
        // Folded header line with embedded CR LF and spaces.
        let input = "SGVs\r\n bG8=";
        assert_eq!(decode(input).unwrap(), b"Hello");
    }

    #[test]
    fn decode_tabs_skipped() {
        let input = "SGVs\tbG8=";
        assert_eq!(decode(input).unwrap(), b"Hello");
    }

    #[test]
    fn decode_invalid_character() {
        assert!(decode("!!!invalid!!!").is_err());
    }

    #[test]
    fn decode_url_safe_empty_input() {
        assert_eq!(decode_url_safe("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn decode_url_safe_invalid_character() {
        assert!(decode_url_safe("!!!").is_err());
    }

    // -- Round-trip ----------------------------------------------------------

    #[test]
    fn standard_round_trip_various_lengths() {
        for len in 0..=64 {
            let data: Vec<u8> = (0u8..).take(len).collect();
            let encoded = encode(&data);
            let decoded = decode(&encoded).unwrap();
            assert_eq!(decoded, data, "round-trip failed for length {len}");
        }
    }

    #[test]
    fn url_safe_round_trip_various_lengths() {
        for len in 0..=64 {
            let data: Vec<u8> = (0u8..).take(len).collect();
            let encoded = encode_url_safe(&data);
            let decoded = decode_url_safe(&encoded).unwrap();
            assert_eq!(decoded, data, "url-safe round-trip failed for length {len}");
        }
    }

    // -- Length helpers ------------------------------------------------------

    #[test]
    fn encoded_len_values() {
        assert_eq!(encoded_len(0), 0);
        assert_eq!(encoded_len(1), 4);
        assert_eq!(encoded_len(2), 4);
        assert_eq!(encoded_len(3), 4);
        assert_eq!(encoded_len(4), 8);
        assert_eq!(encoded_len(6), 8);
    }

    #[test]
    fn decoded_len_estimate_values() {
        assert_eq!(decoded_len_estimate(0), 0);
        assert_eq!(decoded_len_estimate(4), 3);
        assert_eq!(decoded_len_estimate(8), 6);
    }

    // -- DynBuf integration -------------------------------------------------

    #[test]
    fn encode_to_buf_basic() {
        let mut buf = DynBuf::new();
        encode_to_buf(b"test", &mut buf).unwrap();
        assert_eq!(buf.as_bytes(), b"dGVzdA==");
    }

    #[test]
    fn encode_to_buf_too_large() {
        let big = vec![0u8; MAX_BASE64_INPUT + 1];
        let mut buf = DynBuf::new();
        let err = encode_to_buf(&big, &mut buf);
        assert!(err.is_err());
    }

    // -- decode_to_vec alias ------------------------------------------------

    #[test]
    fn decode_to_vec_works() {
        let decoded = decode_to_vec("SGVsbG8=").unwrap();
        assert_eq!(decoded, b"Hello");
    }
}
