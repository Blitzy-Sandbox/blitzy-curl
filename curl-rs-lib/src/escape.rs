//! URL percent-encoding and decoding.
//!
//! This module is the Rust reimplementation of curl's `lib/escape.c`. It
//! provides the pure, allocation-returning core behind libcurl's public
//! escape/unescape surface:
//!
//! * [`curl_easy_escape`] / the deprecated `curl_escape` map to [`escape`].
//! * [`curl_easy_unescape`] / the deprecated `curl_unescape` map to
//!   [`unescape`].
//!
//! [`curl_easy_escape`]: https://curl.se/libcurl/c/curl_easy_escape.html
//! [`curl_easy_unescape`]: https://curl.se/libcurl/c/curl_easy_unescape.html
//!
//! The C functions allocate a heap string that the caller frees with
//! `curl_free`. That raw-pointer marshaling — turning a `*const c_char` plus an
//! `int` length into a slice, computing `strlen` when the length is `0`, and
//! handing back a `CString::into_raw` pointer — is the job of the FFI crate
//! (`curl-rs-ffi`). Here the functions are *pure*: they take a byte slice and
//! return an owned [`String`] / [`Vec<u8>`], so they are trivial to unit-test
//! and to reuse from [`crate::url`] and from query/option processing.
//!
//! # Parity with curl (wire-observable)
//!
//! The encoded output is URL/wire-observable and is checked by the curl test
//! suite, so it must match curl 8.x **byte-for-byte**. Two details are pinned
//! against the C oracle and exercised by the unit tests below:
//!
//! * **Unreserved set.** curl percent-encodes every byte that is *not*
//!   "unreserved". The unreserved set is curl's `ISUNRESERVED` macro
//!   (`lib/curl_ctype.h`): the ASCII alphanumerics `A-Z a-z 0-9` plus the four
//!   punctuation bytes `-` `.` `_` `~`. Every other byte — including the space,
//!   `+`, and all bytes `>= 0x80` — is encoded.
//! * **Uppercase hex.** Each encoded byte becomes `%` followed by two
//!   **uppercase** hex digits (curl's `Curl_hexbyte` uses the `Curl_udigits`
//!   table `"0123456789ABCDEF"`). The decoder, mirroring `ISXDIGIT`, accepts
//!   both upper- and lowercase hex on input.
//!
//! Note that, unlike `application/x-www-form-urlencoded` decoding, curl's URL
//! unescape does **not** turn `+` into a space — a `+` byte decodes to `+`, and
//! `%2B` decodes to `+`. That behavior is preserved here.
//!
//! # Memory safety
//!
//! This module is pure, safe Rust: it contains **zero** `unsafe` and compiles
//! cleanly under a crate-root `#![forbid(unsafe_code)]`. Deterministic `Drop`
//! and the growable [`String`]/[`Vec`] replace curl's manual `curlx_malloc` /
//! `curlx_dyn_*` buffer management. curl's `Curl_urldecode` can additionally
//! return `CURLE_OUT_OF_MEMORY` when its allocation fails; in Rust an allocation
//! failure aborts the process through the global allocator rather than surfacing
//! as a result code, so the only error these functions can return is the
//! malformed-input rejection described on [`unescape`]/[`urldecode`].

use crate::error::{CurlError, Result};

/// Uppercase hexadecimal digit table, mirroring curl's `Curl_udigits`
/// (`"0123456789ABCDEF"`). Indexed by a 4-bit nibble (`0..=15`) to render the
/// two hex digits of a percent-encoded byte.
const HEX_UPPER: [u8; 16] = *b"0123456789ABCDEF";

/// Decoding rejection policy, mirroring curl's `enum urlreject`
/// (`lib/escape.h`).
///
/// curl starts the discriminants at `2` so that a stray legacy `TRUE`/`FALSE`
/// (`0`/`1`) argument is caught by an assertion rather than being silently
/// interpreted as a policy. The same numbering is reproduced here for fidelity
/// to the oracle, even though Rust's type system already prevents that misuse.
///
/// [`unescape`] selects between [`Nada`](UrlReject::Nada) and
/// [`Ctrl`](UrlReject::Ctrl) via its `reject_ctrl` flag; [`urldecode`] exposes
/// the full policy (including [`Zero`](UrlReject::Zero)) for callers such as
/// [`crate::url`] that need it — the URL API decodes some components with
/// control-character rejection enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlReject {
    /// Accept every decoded byte (`REJECT_NADA`). This is the policy used by
    /// the public `curl_easy_unescape`.
    Nada = 2,
    /// Reject a decoded control character — any byte less than `0x20`
    /// (`REJECT_CTRL`). A rejection yields [`CurlError::UrlMalformat`].
    Ctrl = 3,
    /// Reject a decoded NUL byte (`REJECT_ZERO`). A rejection yields
    /// [`CurlError::UrlMalformat`].
    Zero = 4,
}

/// Returns `true` for bytes in curl's "unreserved" set
/// (`ISUNRESERVED` in `lib/curl_ctype.h`): ASCII alphanumerics plus `-`, `.`,
/// `_`, and `~`. These bytes are emitted verbatim by [`escape`]; every other
/// byte is percent-encoded.
#[inline]
fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// Converts a single ASCII hex digit to its `0..=15` value, returning `None`
/// for non-hex bytes.
///
/// This is the total, panic-free equivalent of curl's `ISXDIGIT` test combined
/// with its `curlx_hexval` lookup: it accepts exactly `0-9`, `a-f`, and `A-F`.
#[inline]
fn hex_decode(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Percent-encodes a byte slice for use in a URL, exactly as curl's
/// `curl_easy_escape` does.
///
/// Every byte in curl's unreserved set (`A-Z a-z 0-9 - . _ ~`) is copied
/// through unchanged; every other byte is rendered as `%` followed by two
/// **uppercase** hex digits. The result is therefore always pure ASCII, so the
/// returned [`String`] is always valid UTF-8. An empty input yields an empty
/// string (matching curl, which returns a freshly allocated `""`).
///
/// The FFI shim is responsible for the C-specific edge cases that cannot be
/// expressed against a slice: a `NULL` pointer or a negative length make
/// `curl_easy_escape` return `NULL`, and curl guards against the
/// `length * 3 + 1` buffer-size computation overflowing. Those concerns live at
/// the C boundary; here the function is total over any slice.
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::escape::escape;
/// assert_eq!(escape(b"hello world!"), "hello%20world%21");
/// // `+` is reserved and is encoded; the unreserved punctuation is preserved.
/// assert_eq!(escape(b"a+b-._~"), "a%2Bb-._~");
/// // Non-ASCII (here UTF-8 for `é`) is encoded byte-by-byte in uppercase hex.
/// assert_eq!(escape("é".as_bytes()), "%C3%A9");
/// ```
pub fn escape(input: &[u8]) -> String {
    // Most inputs are dominated by unreserved bytes, so reserve the input
    // length up front; the buffer grows automatically when escapes expand it.
    let mut out = String::with_capacity(input.len());
    for &byte in input {
        if is_unreserved(byte) {
            // `byte` is a 7-bit ASCII value here, so this pushes a single byte.
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX_UPPER[usize::from(byte >> 4)]));
            out.push(char::from(HEX_UPPER[usize::from(byte & 0x0f)]));
        }
    }
    out
}

/// Decodes a percent-encoded byte slice, applying the given rejection policy —
/// the Rust equivalent of curl's internal `Curl_urldecode`.
///
/// A `%` is decoded only when it is followed by two valid hex digits and there
/// are at least two more bytes available (curl's `alloc > 2` guard); otherwise
/// the `%` is treated as a literal byte. This means malformed sequences are
/// preserved verbatim: `"%"`, `"%2"`, and `"%zz"` all decode to themselves. A
/// `+` is left untouched (curl's URL decoder does not map `+` to space).
///
/// If `reject` is [`UrlReject::Ctrl`] and a decoded byte is a control character
/// (`< 0x20`), or if `reject` is [`UrlReject::Zero`] and a decoded byte is NUL,
/// the function returns [`CurlError::UrlMalformat`] (curl's
/// `CURLE_URL_MALFORMAT`). [`UrlReject::Nada`] accepts every byte.
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::escape::{urldecode, UrlReject};
/// # use curl_rs_lib::error::CurlError;
/// assert_eq!(urldecode(b"a%20b", UrlReject::Nada).unwrap(), b"a b");
/// // A decoded control byte is rejected under the `Ctrl` policy.
/// assert_eq!(urldecode(b"%1F", UrlReject::Ctrl), Err(CurlError::UrlMalformat));
/// // ...but accepted under `Nada`.
/// assert_eq!(urldecode(b"%1F", UrlReject::Nada).unwrap(), vec![0x1F]);
/// ```
pub fn urldecode(input: &[u8], reject: UrlReject) -> Result<Vec<u8>> {
    let len = input.len();
    let mut out = Vec::with_capacity(len);
    let mut i = 0;

    while i < len {
        let cur = input[i];
        // Decode `%XX` only when a full, well-formed escape is present. The
        // `len - i > 2` test (curl's `alloc > 2`) guarantees that `i + 1` and
        // `i + 2` are valid indices, keeping the lookahead in bounds.
        let decoded = if cur == b'%' && (len - i) > 2 {
            match (hex_decode(input[i + 1]), hex_decode(input[i + 2])) {
                (Some(hi), Some(lo)) => {
                    i += 3;
                    (hi << 4) | lo
                }
                // Not two hex digits: keep the '%' literally.
                _ => {
                    i += 1;
                    cur
                }
            }
        } else {
            i += 1;
            cur
        };

        match reject {
            UrlReject::Ctrl if decoded < 0x20 => return Err(CurlError::UrlMalformat),
            UrlReject::Zero if decoded == 0 => return Err(CurlError::UrlMalformat),
            _ => {}
        }

        out.push(decoded);
    }

    Ok(out)
}

/// Decodes a percent-encoded byte slice, as curl's `curl_easy_unescape` does.
///
/// This is a thin wrapper over [`urldecode`]: `reject_ctrl == false` selects
/// [`UrlReject::Nada`] (the policy the public `curl_easy_unescape` uses, which
/// accepts every decoded byte), while `reject_ctrl == true` selects
/// [`UrlReject::Ctrl`], causing a decoded control character (`< 0x20`) to be
/// rejected with [`CurlError::UrlMalformat`].
///
/// `%XX` escapes are decoded with both upper- and lowercase hex accepted;
/// malformed escapes are preserved verbatim; and `+` is left as `+` rather than
/// being decoded to a space.
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::escape::unescape;
/// assert_eq!(unescape(b"%2Bone%20two", false).unwrap(), b"+one two");
/// // `+` is preserved, never turned into a space.
/// assert_eq!(unescape(b"a+b", false).unwrap(), b"a+b");
/// ```
pub fn unescape(input: &[u8], reject_ctrl: bool) -> Result<Vec<u8>> {
    let reject = if reject_ctrl {
        UrlReject::Ctrl
    } else {
        UrlReject::Nada
    };
    urldecode(input, reject)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The complete unreserved set must pass through [`escape`] unchanged.
    #[test]
    fn escape_unreserved_passthrough() {
        let unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        assert_eq!(escape(unreserved.as_bytes()), unreserved);
    }

    /// A space is encoded as `%20` (a common, test-checked case).
    #[test]
    fn escape_space_is_percent_20() {
        assert_eq!(escape(b" "), "%20");
        assert_eq!(escape(b"hello world!"), "hello%20world%21");
    }

    /// Encoded hex digits are UPPERCASE for every nibble, including the
    /// `A..=F` digits and the high bytes `>= 0x80`.
    #[test]
    fn escape_hex_is_uppercase() {
        assert_eq!(escape(&[0xFF]), "%FF");
        assert_eq!(escape(&[0xAB]), "%AB");
        assert_eq!(escape(&[0x0A]), "%0A");
        assert_eq!(escape(&[0xCD]), "%CD");
        // For every byte that gets percent-encoded, the two hex digits must be
        // uppercase (`0-9 A-F`) — never lowercase. Unreserved bytes (which pass
        // through unchanged and may be lowercase ASCII letters) are skipped via
        // the `%` prefix check.
        for byte in 0u8..=255 {
            let e = escape(&[byte]);
            if let Some(hex) = e.strip_prefix('%') {
                assert_eq!(hex.len(), 2, "byte {byte:#04x} produced {e}");
                assert!(
                    hex.chars()
                        .all(|c| c.is_ascii_digit() || ('A'..='F').contains(&c)),
                    "byte {byte:#04x} produced non-uppercase hex: {e}"
                );
            }
        }
    }

    /// `+` is reserved and therefore encoded (it is NOT in the unreserved set).
    #[test]
    fn escape_plus_is_encoded() {
        assert_eq!(escape(b"+"), "%2B");
        assert_eq!(escape(b"a+b"), "a%2Bb");
    }

    /// A representative reserved/punctuation set encodes to known sequences.
    #[test]
    fn escape_reserved_set() {
        assert_eq!(escape(b"/?#[]@"), "%2F%3F%23%5B%5D%40");
        assert_eq!(
            escape(b":/?#[]@!$&'()*+,;="),
            "%3A%2F%3F%23%5B%5D%40%21%24%26%27%28%29%2A%2B%2C%3B%3D"
        );
    }

    /// Non-ASCII bytes (here the UTF-8 encoding of `é`) are encoded per byte.
    #[test]
    fn escape_utf8_bytes() {
        assert_eq!(escape("é".as_bytes()), "%C3%A9");
        assert_eq!(escape("€".as_bytes()), "%E2%82%AC");
    }

    /// An empty input yields an empty string.
    #[test]
    fn escape_empty() {
        assert_eq!(escape(b""), "");
    }

    /// Every byte of [`escape`] output is ASCII, so the [`String`] is always
    /// valid UTF-8.
    #[test]
    fn escape_output_is_ascii() {
        let all: Vec<u8> = (0u8..=255).collect();
        assert!(escape(&all).is_ascii());
    }

    /// Basic decoding of well-formed `%XX` escapes.
    #[test]
    fn unescape_basic() {
        assert_eq!(unescape(b"a%20b", false).unwrap(), b"a b");
        assert_eq!(unescape(b"%2Bone%20two", false).unwrap(), b"+one two");
        assert_eq!(unescape(b"", false).unwrap(), b"");
    }

    /// `+` is preserved on decode (curl's URL unescape does not map it to a
    /// space), and `%2B` decodes to `+`.
    #[test]
    fn unescape_plus_is_preserved() {
        assert_eq!(unescape(b"a+b", false).unwrap(), b"a+b");
        assert_eq!(unescape(b"%2B", false).unwrap(), b"+");
        assert_eq!(unescape(b"1+1=2", false).unwrap(), b"1+1=2");
    }

    /// Both upper- and lowercase hex digits decode identically.
    #[test]
    fn unescape_accepts_lowercase_hex() {
        assert_eq!(unescape(b"%2b", false).unwrap(), b"+");
        assert_eq!(unescape(b"%ab", false).unwrap(), vec![0xAB]);
        assert_eq!(unescape(b"%AB", false).unwrap(), vec![0xAB]);
        assert_eq!(unescape(b"%fF", false).unwrap(), vec![0xFF]);
    }

    /// Malformed escapes are preserved verbatim (matching curl's literal-`%`
    /// fallback): a trailing `%`, a one-digit `%2`, and a non-hex `%zz`.
    #[test]
    fn unescape_malformed_is_literal() {
        assert_eq!(unescape(b"%", false).unwrap(), b"%");
        assert_eq!(unescape(b"%2", false).unwrap(), b"%2");
        assert_eq!(unescape(b"%zz", false).unwrap(), b"%zz");
        assert_eq!(unescape(b"%g0", false).unwrap(), b"%g0");
        assert_eq!(unescape(b"100%", false).unwrap(), b"100%");
        // A '%' immediately followed by another valid escape: only the second
        // is well-formed when the first lacks two trailing hex digits.
        assert_eq!(unescape(b"%%20", false).unwrap(), b"% ");
    }

    /// With `reject_ctrl == true`, a decoded control character is rejected with
    /// `CURLE_URL_MALFORMAT`; the same input is accepted with the flag off.
    #[test]
    fn unescape_reject_ctrl() {
        // Decoded from an escape.
        assert_eq!(unescape(b"%00", true), Err(CurlError::UrlMalformat));
        assert_eq!(unescape(b"%1F", true), Err(CurlError::UrlMalformat));
        assert_eq!(unescape(b"ok%0Abad", true), Err(CurlError::UrlMalformat));
        // A raw (already-literal) control byte is rejected too.
        assert_eq!(
            unescape(&[b'a', 0x01, b'b'], true),
            Err(CurlError::UrlMalformat)
        );

        // Accepted when the flag is off.
        assert_eq!(unescape(b"%00", false).unwrap(), vec![0x00]);
        assert_eq!(unescape(b"%1F", false).unwrap(), vec![0x1F]);
    }

    /// `0x20` (space) is the boundary: it is NOT a control character, so it is
    /// accepted even under the `Ctrl` policy. Bytes `>= 0x20` (including high
    /// bytes) are likewise accepted.
    #[test]
    fn unescape_ctrl_boundary() {
        assert_eq!(unescape(b"%20", true).unwrap(), b" ");
        assert_eq!(unescape(b"%FF", true).unwrap(), vec![0xFF]);
        assert_eq!(unescape(b"%7F", true).unwrap(), vec![0x7F]);
    }

    /// [`UrlReject::Zero`] rejects a decoded NUL but allows other control
    /// characters; [`UrlReject::Nada`] allows the NUL through.
    #[test]
    fn urldecode_reject_zero() {
        assert_eq!(
            urldecode(b"%00", UrlReject::Zero),
            Err(CurlError::UrlMalformat)
        );
        assert_eq!(
            urldecode(b"a\0b", UrlReject::Zero),
            Err(CurlError::UrlMalformat)
        );
        // A non-NUL control byte is fine under the Zero policy.
        assert_eq!(urldecode(b"%01", UrlReject::Zero).unwrap(), vec![0x01]);
        // Nada accepts the NUL.
        assert_eq!(urldecode(b"%00", UrlReject::Nada).unwrap(), vec![0x00]);
    }

    /// [`unescape`]'s `reject_ctrl` flag maps to the correct [`UrlReject`]
    /// policy in terms of [`urldecode`].
    #[test]
    fn unescape_matches_urldecode_policy() {
        let input = b"x%41%42%1F";
        assert_eq!(
            unescape(input, false).unwrap(),
            urldecode(input, UrlReject::Nada).unwrap()
        );
        assert_eq!(unescape(input, true), urldecode(input, UrlReject::Ctrl));
    }

    /// `escape` followed by `unescape` is the identity over *every* byte value,
    /// which simultaneously proves the encoder and decoder agree on the full
    /// `0..=255` range.
    #[test]
    fn escape_unescape_roundtrip_all_bytes() {
        let all: Vec<u8> = (0u8..=255).collect();
        let encoded = escape(&all);
        let decoded = unescape(encoded.as_bytes(), false).unwrap();
        assert_eq!(decoded, all);
    }

    /// A mixed, human-readable corpus round-trips correctly.
    #[test]
    fn roundtrip_corpus() {
        let corpus: &[&[u8]] = &[
            b"",
            b"plain",
            b"with space",
            b"https://example.com/path?a=b&c=d",
            b"unicode-\xC3\xA9-\xE2\x82\xAC",
            b"reserved:/?#[]@!$&'()*+,;=",
            b"-._~tilde",
            b"100%",
        ];
        for &original in corpus {
            let encoded = escape(original);
            // The encoded form is always pure ASCII / unreserved-or-%XX.
            assert!(encoded.is_ascii(), "non-ascii output for {original:?}");
            let decoded = unescape(encoded.as_bytes(), false).unwrap();
            assert_eq!(decoded, original, "roundtrip failed for {original:?}");
        }
    }

    /// `UrlReject` mirrors curl's `enum urlreject` discriminants
    /// (`REJECT_NADA = 2`, then `CTRL`, `ZERO`).
    #[test]
    fn urlreject_discriminants_match_curl() {
        assert_eq!(UrlReject::Nada as i32, 2);
        assert_eq!(UrlReject::Ctrl as i32, 3);
        assert_eq!(UrlReject::Zero as i32, 4);
    }
}
