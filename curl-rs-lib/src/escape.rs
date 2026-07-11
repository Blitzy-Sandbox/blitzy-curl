// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! URL percent-encoding and decoding — a memory-safe Rust rewrite of curl's
//! `lib/escape.c`.
//!
//! This module provides the two primitives curl exposes for URL escaping:
//!
//! * [`escape`] mirrors `curl_easy_escape` (and the legacy `curl_escape`):
//!   it percent-encodes every byte that is **not** an RFC 3986 *unreserved*
//!   character.
//! * [`unescape`] mirrors `Curl_urldecode` (the engine behind
//!   `curl_easy_unescape` and the legacy `curl_unescape`): it decodes `%XX`
//!   sequences and can optionally reject decoded control characters.
//!
//! Both functions are consumed by the URL layer (`url.rs`, `urlapi.rs`) and by
//! form / query-string building, exactly as `escape.c` is used across curl 8.x.
//!
//! # Parity with curl 8.x
//!
//! Behaviour is byte-for-byte identical to curl 8.19.0-DEV:
//!
//! * **Unreserved set.** curl passes through only the RFC 3986 *unreserved*
//!   characters — `ALPHA` / `DIGIT` plus `-`, `.`, `_`, `~` — as defined by the
//!   `ISUNRESERVED` macro in `lib/curl_ctype.h`
//!   (`ISUNRESERVED(x) = ISALNUM(x) || ISURLPUNTCS(x)`). Every other byte,
//!   including all bytes `>= 0x80`, is percent-encoded.
//! * **Uppercase hex.** Encoded bytes are emitted as `%` followed by two
//!   **uppercase** hexadecimal digits, matching curl's `Curl_hexbyte`, which
//!   indexes `Curl_udigits = "0123456789ABCDEF"`.
//! * **Lenient decode.** A `%` is decoded only when it is followed by two
//!   hexadecimal digits, matching curl's
//!   `('%' == in) && (alloc > 2) && ISXDIGIT(string[1]) && ISXDIGIT(string[2])`
//!   guard in `Curl_urldecode`; otherwise the `%` is passed through literally.
//! * **`+` is not a space.** curl's URL decoder does *not* map `+` to a space
//!   (that is an `application/x-www-form-urlencoded` convention, not a
//!   URL-decoding one); this module preserves that behaviour.
//!
//! The core codec is delegated to the audited [`percent_encoding`] crate, whose
//! output has been verified to be identical to curl's for every byte value on
//! the encode path and for curl's malformed-sequence handling on the decode
//! path.
//!
//! # Safety
//!
//! This module is implemented entirely in safe Rust — it performs no
//! raw-pointer or FFI operations — and never panics on caller-supplied data:
//! the only fallible path ([`unescape`] with control rejection) returns an
//! [`Error`] instead of panicking.

use percent_encoding::{percent_decode, percent_encode, AsciiSet, NON_ALPHANUMERIC};

use crate::error::{Error, Result};

/// The set of ASCII bytes that [`escape`] percent-encodes.
///
/// This is the complement of curl's `ISUNRESERVED` set: it starts from
/// [`NON_ALPHANUMERIC`] (which marks for encoding every ASCII byte that is not
/// `ALPHA` / `DIGIT`) and then *exempts* the four unreserved punctuation
/// characters `-`, `.`, `_`, `~`. The net effect is that exactly the RFC 3986
/// unreserved characters (`A`–`Z`, `a`–`z`, `0`–`9`, `-`, `.`, `_`, `~`) pass
/// through unescaped, mirroring `ISURLPUNTCS` / `ISUNRESERVED` in
/// `lib/curl_ctype.h`.
///
/// Bytes `>= 0x80` are always percent-encoded by [`percent_encoding`],
/// regardless of this set, which matches curl (such bytes are not unreserved).
const ESCAPE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// The exclusive upper bound below which a decoded byte counts as a control
/// character for curl's `REJECT_CTRL` mode.
///
/// curl's `Curl_urldecode` (`lib/escape.c`) rejects a byte in `REJECT_CTRL`
/// mode when `in < 0x20`, i.e. for the bytes `0x00..=0x1F`. It deliberately
/// does **not** reject `0x7F` (DEL) at this site — only bytes strictly below
/// `0x20` — so this module uses the same bound to preserve byte-for-byte
/// behaviour. (curl's separate `ISCNTRL` macro *does* include `0x7F`, but that
/// macro is not what `REJECT_CTRL` tests against.)
const CTRL_THRESHOLD: u8 = 0x20;

/// Percent-encode `input`, mirroring curl's `curl_easy_escape`.
///
/// Every byte that is not an RFC 3986 *unreserved* character
/// (`A`–`Z`, `a`–`z`, `0`–`9`, `-`, `.`, `_`, `~`) is replaced by a `%`
/// followed by its two-digit **uppercase** hexadecimal value; unreserved bytes
/// pass through unchanged. An empty input yields an empty string.
///
/// This replaces curl's `char *` return value and `int inlength` parameter with
/// an owned [`String`] built from the input slice's own length. The output is
/// always pure ASCII and therefore always valid UTF-8.
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::escape::escape;
/// assert_eq!(escape(b"a b/c?d=e&f"), "a%20b%2Fc%3Fd%3De%26f");
/// assert_eq!(escape(b"unreserved-._~"), "unreserved-._~");
/// assert_eq!(escape(b""), "");
/// ```
#[must_use]
pub fn escape(input: &[u8]) -> String {
    percent_encode(input, ESCAPE_SET).to_string()
}

/// URL-decode `input`, mirroring curl's `Curl_urldecode` /
/// `curl_easy_unescape`.
///
/// Each `%XX` sequence — a `%` followed by exactly two hexadecimal digits
/// (`0`–`9`, `a`–`f`, `A`–`F`, case-insensitive) — is decoded into the
/// corresponding byte. A `%` that is *not* followed by two hexadecimal digits
/// (for example the truncated `"%A"`, a trailing `"%"`, or an invalid `"%2G"`)
/// is passed through literally, exactly as curl does. `+` is **not** treated as
/// a space.
///
/// When `reject_ctrl` is `true` (curl's `REJECT_CTRL` mode) the function
/// returns an [`Error`] mapping to `CURLE_URL_MALFORMAT` if any resulting byte
/// is a control character (`< 0x20`), matching curl's check in `lib/escape.c`.
/// When `reject_ctrl` is `false` (curl's `REJECT_NADA` mode) every decoded byte
/// is accepted.
///
/// The C `char **ostring` / `size_t *olen` out-parameters are replaced by an
/// owned [`Vec<u8>`], whose length is the decoded length.
///
/// # Errors
///
/// Returns [`Error::Url`] (which maps to `CURLE_URL_MALFORMAT`) when
/// `reject_ctrl` is `true` and the decoded data contains a byte `< 0x20`.
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::escape::unescape;
/// assert_eq!(unescape(b"a%20b%2Fc", false).unwrap(), b"a b/c");
/// assert_eq!(unescape(b"a+b", false).unwrap(), b"a+b"); // '+' stays '+'
/// assert_eq!(unescape(b"%2G", false).unwrap(), b"%2G"); // invalid: literal
/// assert!(unescape(b"%00", true).is_err()); // control byte rejected
/// ```
pub fn unescape(input: &[u8], reject_ctrl: bool) -> Result<Vec<u8>> {
    // Delegate the `%XX` decoding to the audited `percent-encoding` crate. Its
    // handling of malformed sequences — passing a bare `%` through literally
    // when it is not followed by two hex digits — is byte-for-byte identical to
    // curl's `Curl_urldecode` guard (`alloc > 2 && ISXDIGIT && ISXDIGIT`), and
    // it does not treat `+` as a space.
    let decoded: Vec<u8> = percent_decode(input).collect();

    // curl's `REJECT_CTRL` mode rejects the entire string if *any* resulting
    // byte is a control character (`< 0x20`). curl performs this test per byte
    // as it decodes and bails on the first offender; scanning the fully decoded
    // buffer here produces the identical accept/reject outcome. The check
    // covers both decoded bytes and literal (non-`%`) bytes, exactly as curl's
    // per-byte test does.
    if reject_ctrl && decoded.iter().any(|&byte| byte < CTRL_THRESHOLD) {
        return Err(Error::url("control character in URL-decoded string"));
    }

    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::{escape, unescape};
    use crate::error::CurlCode;

    /// A faithful, standalone reproduction of curl's `curl_easy_escape`
    /// (`lib/escape.c` + `ISUNRESERVED` / `Curl_udigits` from
    /// `lib/curl_ctype.h`), used as the parity oracle for [`escape`].
    fn curl_reference_escape(input: &[u8]) -> String {
        const UPPER: &[u8; 16] = b"0123456789ABCDEF";
        let mut out = String::new();
        for &b in input {
            // ISUNRESERVED(x) == ISALNUM(x) || ISURLPUNTCS(x)
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                out.push(b as char);
            } else {
                out.push('%');
                out.push(UPPER[(b >> 4) as usize] as char);
                out.push(UPPER[(b & 0x0F) as usize] as char);
            }
        }
        out
    }

    #[test]
    fn escape_matches_curl_reference_for_all_bytes() {
        // Whole-range parity: encoding every byte 0x00..=0xFF must be identical
        // to curl's reference implementation.
        let all: Vec<u8> = (0u8..=u8::MAX).collect();
        assert_eq!(escape(&all), curl_reference_escape(&all));

        // Per-byte parity to pinpoint any single-byte divergence.
        for b in 0u8..=u8::MAX {
            assert_eq!(
                escape(&[b]),
                curl_reference_escape(&[b]),
                "divergence at byte 0x{b:02X}"
            );
        }
    }

    #[test]
    fn escape_parity_target() {
        // Exact output curl 8.x produces for the documented example.
        assert_eq!(escape(b"a b/c?d=e&f"), "a%20b%2Fc%3Fd%3De%26f");
    }

    #[test]
    fn escape_uses_uppercase_hex() {
        assert_eq!(escape(b"\n"), "%0A");
        assert_eq!(escape(&[0xff]), "%FF");
        assert_eq!(escape(b" "), "%20");
        assert_eq!(escape(b"/"), "%2F");
        assert_eq!(escape(&[0x7f]), "%7F");
    }

    #[test]
    fn escape_passes_through_unreserved() {
        const UNRESERVED: &str =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        assert_eq!(escape(UNRESERVED.as_bytes()), UNRESERVED);
    }

    #[test]
    fn round_trip_preserves_bytes() {
        let cases: &[&[u8]] = &[
            b"",
            b"hello world",
            b"reserved: /?#[]@!$&'()*+,;=",
            b"unreserved-._~ABCabc012",
            // Multi-byte UTF-8 (accented, CJK, emoji) round-trips at the byte level.
            "UTF-8: \u{00e9}\u{4e2d}\u{6587}\u{1f600}".as_bytes(),
            // Control bytes and high bytes; decoded with reject_ctrl = false so
            // that the control bytes survive the round trip.
            &[0x00, 0x01, 0x1f, 0x7f, 0x80, 0xff],
        ];
        for &case in cases {
            let encoded = escape(case);
            let decoded = unescape(encoded.as_bytes(), false).expect("decode must succeed");
            assert_eq!(decoded, case.to_vec(), "round trip failed for {case:?}");
        }
    }

    #[test]
    fn unescape_passes_through_invalid_sequences() {
        // A '%' not followed by two hex digits is emitted literally, exactly as
        // curl's `Curl_urldecode` does.
        assert_eq!(unescape(b"%2G", false).unwrap(), b"%2G".to_vec()); // bad 2nd digit
        assert_eq!(unescape(b"%G2", false).unwrap(), b"%G2".to_vec()); // bad 1st digit
        assert_eq!(unescape(b"%A", false).unwrap(), b"%A".to_vec()); // truncated
        assert_eq!(unescape(b"%", false).unwrap(), b"%".to_vec()); // trailing
        assert_eq!(unescape(b"100%", false).unwrap(), b"100%".to_vec());
        // '%' then "%41" -> the first '%' is literal, "%41" decodes to 'A'.
        assert_eq!(unescape(b"%%41", false).unwrap(), b"%A".to_vec());
    }

    #[test]
    fn unescape_decodes_valid_sequences_case_insensitively() {
        assert_eq!(unescape(b"%2f", false).unwrap(), b"/".to_vec()); // lowercase hex
        assert_eq!(unescape(b"%2F", false).unwrap(), b"/".to_vec()); // uppercase hex
        assert_eq!(unescape(b"a%20b", false).unwrap(), b"a b".to_vec());
        assert_eq!(unescape(b"%00", false).unwrap(), vec![0u8]); // NUL when accepted
    }

    #[test]
    fn unescape_does_not_treat_plus_as_space() {
        // curl_easy_unescape leaves '+' untouched (it is not the '+'-as-space
        // form-encoding convention).
        assert_eq!(unescape(b"a+b+c", false).unwrap(), b"a+b+c".to_vec());
        // The literal '+' can still be produced by decoding "%2B".
        assert_eq!(unescape(b"%2B", false).unwrap(), b"+".to_vec());
    }

    #[test]
    fn unescape_reject_ctrl_rejects_low_bytes() {
        // Every decoded byte below 0x20 is rejected: NUL, newline, and 0x1F
        // (the highest rejected value).
        assert!(unescape(b"%00", true).is_err());
        assert!(unescape(b"%0A", true).is_err());
        assert!(unescape(b"%1F", true).is_err());
        // A literal (non-percent-encoded) control byte is rejected too.
        assert!(unescape(b"a\x0ab", true).is_err());
    }

    #[test]
    fn unescape_reject_ctrl_accepts_0x20_and_above() {
        // 0x20 (space) is the boundary: it is accepted.
        assert_eq!(unescape(b"%20", true).unwrap(), b" ".to_vec());
        assert_eq!(unescape(b"hello", true).unwrap(), b"hello".to_vec());
    }

    #[test]
    fn unescape_reject_ctrl_does_not_reject_0x7f_or_high_bytes() {
        // Parity with lib/escape.c: REJECT_CTRL tests `in < 0x20` ONLY, so 0x7F
        // (DEL) is accepted here even though it is conceptually a control char.
        assert_eq!(unescape(b"%7F", true).unwrap(), vec![0x7fu8]);
        // Bytes >= 0x80 are also accepted.
        assert_eq!(unescape(b"%FF", true).unwrap(), vec![0xffu8]);
    }

    #[test]
    fn unescape_reject_ctrl_maps_to_url_malformat() {
        let err = unescape(b"%00", true).unwrap_err();
        // Frozen ABI: the error must map to CURLE_URL_MALFORMAT (integer 3).
        assert_eq!(err.code(), CurlCode::UrlMalformat);
        assert_eq!(err.code_i32(), 3);
    }

    #[test]
    fn empty_inputs() {
        assert_eq!(escape(b""), "");
        assert_eq!(unescape(b"", false).unwrap(), Vec::<u8>::new());
        assert_eq!(unescape(b"", true).unwrap(), Vec::<u8>::new());
    }
}
