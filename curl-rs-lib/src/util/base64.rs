//! Base64 encoding and decoding with **byte-for-byte curl parity**.
//!
//! This module is the memory-safe Rust replacement for libcurl's
//! `lib/curlx/base64.c` / `lib/curlx/base64.h`. Base64 output is wire- and
//! format-observable — it is fed verbatim into HTTP `Authorization` headers
//! (Basic/Digest/NTLM/Negotiate via `auth/`), SASL exchanges, and MIME /
//! multipart bodies (`mime.rs`) — so the encoders and the decoder here must
//! reproduce curl's exact alphabet, padding rules, input cap, and *error
//! behavior*. The C sources are treated as a behavioral oracle.
//!
//! # Public surface (parity names in parentheses)
//!
//! * [`base64_decode`] (`curlx_base64_decode`) — decode standard base64.
//! * [`base64_encode`] (`curlx_base64_encode`) — encode with the standard
//!   alphabet and `=` padding.
//! * [`base64url_encode`] (`curlx_base64url_encode`) — encode with the URL- and
//!   filename-safe alphabet (RFC 4648 §5) and **no** padding.
//! * [`CURL_MAX_BASE64_INPUT`] — the 16,000,000-byte input cap on encoding.
//!
//! Unlike the C API (which writes into caller-managed `char *` / `uint8_t *`
//! buffers and reports a `CURLcode`), these functions return an owned
//! [`Vec<u8>`] and a [`CurlError`]. The encoders return the encoded base64
//! *text* as bytes; the decoder returns the decoded *raw* bytes.
//!
//! # Decode parity details (the subtle, must-match points)
//!
//! curl's `curlx_base64_decode` is deliberately strict in some ways and lenient
//! in others. Every one of these behaviors is reproduced exactly:
//!
//! * **Length must be a non-zero multiple of four.** Empty input, or any length
//!   not divisible by four, is rejected with
//!   [`CurlError::BadContentEncoding`]. (A naive unpadded decoder would accept
//!   e.g. `"Zg"`; curl — and therefore this function — does not.)
//! * **At most two `=` padding characters**, and only as a contiguous trailing
//!   run. Three or more, or a `=` that appears earlier than the trailing run
//!   permits, is rejected.
//! * **No whitespace tolerance.** curl does *not* skip spaces, tabs, or
//!   newlines; any byte outside the standard alphabet (including the URL-safe
//!   `-` and `_`) is an illegal symbol and is rejected.
//! * **Trailing bits are ignored, not validated.** For the final padded
//!   quantum curl shifts every symbol (treating each `=` as six zero bits) into
//!   an accumulator and then emits only the top `3 - padding` bytes; it never
//!   checks that the low bits of the last data symbol are zero. So a
//!   non-canonical encoding such as `"Zh=="` decodes to `"f"` exactly as
//!   `"Zg=="` does. (Note: the `base64` crate's *default* decoder rejects such
//!   inputs, which is why the decoder here is hand-rolled rather than delegated
//!   — see the implementation note on [`base64_decode`].)
//! * **C-string length semantics.** The C function takes a NUL-terminated
//!   `const char *` and uses `strlen`. Operating on a `&[u8]`, this function
//!   mirrors that by considering only the bytes up to the first NUL. Valid
//!   base64 text never contains a NUL, so for well-formed input this is a
//!   no-op; it exists purely so the length computation matches curl when a
//!   terminator is embedded.
//!
//! # Encode parity details
//!
//! * Empty input yields empty output and success (curl returns `CURLE_OK` with
//!   a zero-length result).
//! * Input larger than [`CURL_MAX_BASE64_INPUT`] is rejected with
//!   [`CurlError::TooLarge`] (curl's `insize > CURL_MAX_BASE64_INPUT` guard).
//! * The standard encoder uses the alphabet `A–Z a–z 0–9 + /` with `=`
//!   padding; the URL-safe encoder uses `A–Z a–z 0–9 - _` and emits no padding.
//!   These are produced by the audited [`base64`] crate, whose `STANDARD` and
//!   `URL_SAFE_NO_PAD` engines yield exactly curl's output.
//!
//! # Memory safety
//!
//! This module contains **zero `unsafe`** and compiles cleanly under the
//! `#![forbid(unsafe_code)]` declared at the `curl-rs-lib` crate root
//! (AAP §0.7.1). All buffers are owned [`Vec<u8>`]/`String` values; there is no
//! manual allocation and no raw-pointer arithmetic.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;

use crate::error::CurlError;

/// Maximum input length, in bytes, accepted by the base64 *encoders*.
///
/// Parity with the C macro `CURL_MAX_BASE64_INPUT` in `lib/curlx/base64.h`
/// (`16000000`). curl uses this as a sanity cap to catch callers that pass a
/// bogus length; inputs strictly larger than this are rejected with
/// [`CurlError::TooLarge`]. The comparison is `>` (curl's
/// `insize > CURL_MAX_BASE64_INPUT`), so an input of *exactly* this size is
/// still encoded.
pub const CURL_MAX_BASE64_INPUT: usize = 16_000_000;

/// The standard base64 alphabet (`curlx_base64encdec` in the C source):
/// `A–Z`, `a–z`, `0–9`, `+`, `/`. Value *i* of the alphabet is the symbol at
/// index *i*. Used here to build the decode lookup table so the table matches
/// curl's `decodetable` exactly.
const BASE64_STD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Sentinel stored in [`DECODE_TABLE`] for every byte that is **not** a valid
/// standard-alphabet symbol. Mirrors the `0xff` entries curl writes with
/// `memset(lookup, 0xff, sizeof(lookup))` before overlaying `decodetable`.
const INVALID: u8 = 0xFF;

/// 256-entry decode lookup table mapping each possible input byte to its 6-bit
/// value, or [`INVALID`] (`0xFF`) for non-alphabet bytes.
///
/// This reproduces curl's runtime construction
/// (`memset(lookup, 0xff, 256); memcpy(&lookup['+'], decodetable, 80);`) at
/// compile time: every standard-alphabet symbol maps to its index in
/// [`BASE64_STD_ALPHABET`] (so `'A' => 0 … '/' => 63`) and every other byte —
/// including `=`, whitespace, and the URL-safe `-`/`_` — maps to [`INVALID`].
const DECODE_TABLE: [u8; 256] = build_decode_table();

/// Build [`DECODE_TABLE`] in a `const` context.
const fn build_decode_table() -> [u8; 256] {
    let mut table = [INVALID; 256];
    let mut i = 0usize;
    // `while` (not `for`) because iterators are not available in `const fn`.
    while i < BASE64_STD_ALPHABET.len() {
        table[BASE64_STD_ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
}

/// Decode a base64 byte string, reproducing `curlx_base64_decode` exactly.
///
/// Returns the decoded raw bytes on success. On any malformed input — empty,
/// length not a multiple of four, more than two padding characters, a
/// misplaced `=`, or any illegal symbol (whitespace included) — returns
/// [`CurlError::BadContentEncoding`], the same code curl returns
/// (`CURLE_BAD_CONTENT_ENCODING`).
///
/// See the [module documentation](self) for the full list of parity rules,
/// including curl's deliberate *ignoring* of non-zero trailing bits in the
/// final quantum.
///
/// # Implementation note
///
/// The decoder is implemented directly here rather than delegated to the
/// [`base64`] crate. The crate's `GeneralPurpose` decoder, in its default
/// configuration, *rejects* inputs whose final symbol carries non-zero trailing
/// bits, whereas curl silently ignores them; matching curl therefore requires
/// either a non-default crate configuration or a direct port. For a
/// byte-for-byte-critical path, a direct port of curl's small, well-understood
/// algorithm is the most defensible choice and removes any dependence on subtle
/// decoder-configuration semantics. (The crate still backs the encoders, and is
/// used as an independent cross-check oracle in this module's tests.)
///
/// # Examples
///
/// ```ignore
/// assert_eq!(base64_decode(b"Zm9vYmFy").unwrap(), b"foobar");
/// assert!(base64_decode(b"Zg").is_err()); // length is not a multiple of four
/// ```
pub fn base64_decode(src: &[u8]) -> Result<Vec<u8>, CurlError> {
    // Mirror curl's `srclen = strlen(src)`: treat the slice as a C string and
    // consider only the bytes up to the first NUL terminator.
    let src = match src.iter().position(|&b| b == 0) {
        Some(nul) => &src[..nul],
        None => src,
    };
    let srclen = src.len();

    // The encoded length must be non-empty and an exact multiple of four.
    if srclen == 0 || srclen % 4 != 0 {
        return Err(CurlError::BadContentEncoding);
    }

    // Count the trailing '=' padding characters. curl permits at most two; the
    // bound check runs before any further indexing, so no underflow is possible
    // (srclen >= 4 and padding is capped at 2 here).
    let mut padding = 0usize;
    while src[srclen - 1 - padding] == b'=' {
        padding += 1;
        if padding > 2 {
            return Err(CurlError::BadContentEncoding);
        }
    }

    let num_quantums = srclen / 4;
    // The final quantum is decoded separately when padding is present.
    let full_quantums = num_quantums - usize::from(padding > 0);
    // Exact decoded length: three bytes per quantum, less the padding count.
    let rawlen = num_quantums * 3 - padding;

    let mut out: Vec<u8> = Vec::with_capacity(rawlen);
    let mut pos = 0usize;

    // Decode every complete four-symbol quantum into three output bytes.
    for _ in 0..full_quantums {
        let mut acc: u32 = 0;
        for _ in 0..4 {
            let val = DECODE_TABLE[src[pos] as usize];
            pos += 1;
            if val == INVALID {
                // Illegal symbol (including a stray '=' inside a full quantum).
                return Err(CurlError::BadContentEncoding);
            }
            acc = (acc << 6) | u32::from(val);
        }
        out.push(((acc >> 16) & 0xFF) as u8);
        out.push(((acc >> 8) & 0xFF) as u8);
        out.push((acc & 0xFF) as u8);
    }

    // Decode the final, padded quantum (if any). Each '=' contributes six zero
    // bits; curl emits only the top `3 - padding` bytes and never inspects the
    // remaining low bits, so non-canonical trailing bits are ignored.
    if padding > 0 {
        let mut acc: u32 = 0;
        let mut pad_seen = 0usize;
        for _ in 0..4 {
            if src[pos] == b'=' {
                acc <<= 6;
                pos += 1;
                pad_seen += 1;
                if pad_seen > padding {
                    // A '=' appeared earlier than the trailing run allows.
                    return Err(CurlError::BadContentEncoding);
                }
            } else {
                let val = DECODE_TABLE[src[pos] as usize];
                pos += 1;
                if val == INVALID {
                    return Err(CurlError::BadContentEncoding);
                }
                acc = (acc << 6) | u32::from(val);
            }
        }
        out.push(((acc >> 16) & 0xFF) as u8);
        if padding == 1 {
            out.push(((acc >> 8) & 0xFF) as u8);
        }
    }

    debug_assert_eq!(out.len(), rawlen);
    Ok(out)
}

/// Encode bytes as standard base64, reproducing `curlx_base64_encode`.
///
/// Uses the standard alphabet (`A–Z a–z 0–9 + /`) with `=` padding. Empty input
/// returns an empty `Vec` and success (curl's `CURLE_OK` with zero-length
/// output). Input longer than [`CURL_MAX_BASE64_INPUT`] returns
/// [`CurlError::TooLarge`] (curl's `CURLE_TOO_LARGE`).
///
/// The returned bytes are the ASCII base64 *text* (always valid UTF-8).
///
/// # Examples
///
/// ```ignore
/// assert_eq!(base64_encode(b"foobar").unwrap(), b"Zm9vYmFy");
/// assert!(base64_encode(b"").unwrap().is_empty());
/// ```
pub fn base64_encode(input: &[u8]) -> Result<Vec<u8>, CurlError> {
    if input.is_empty() {
        // curl: `if(!insize) return CURLE_OK;` with empty output.
        return Ok(Vec::new());
    }
    if input.len() > CURL_MAX_BASE64_INPUT {
        return Err(CurlError::TooLarge);
    }
    Ok(STANDARD.encode(input).into_bytes())
}

/// Encode bytes as URL- and filename-safe base64, reproducing
/// `curlx_base64url_encode`.
///
/// Uses the RFC 4648 §5 alphabet (`A–Z a–z 0–9 - _`) and emits **no** padding
/// (curl passes a pad byte of `0`, suppressing the `=` characters). Empty input
/// returns empty output and success; input longer than
/// [`CURL_MAX_BASE64_INPUT`] returns [`CurlError::TooLarge`].
///
/// The returned bytes are the ASCII base64url *text* (always valid UTF-8).
///
/// # Examples
///
/// ```ignore
/// // No '=' padding is ever produced.
/// assert_eq!(base64url_encode(b"f").unwrap(), b"Zg");
/// ```
pub fn base64url_encode(input: &[u8]) -> Result<Vec<u8>, CurlError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    if input.len() > CURL_MAX_BASE64_INPUT {
        return Err(CurlError::TooLarge);
    }
    Ok(URL_SAFE_NO_PAD.encode(input).into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

    /// An independent decode oracle: the `base64` crate configured to mirror
    /// curl's leniency — ignore trailing bits — while still requiring canonical
    /// padding. Used **only** to cross-check the hand-rolled [`base64_decode`]
    /// on valid inputs; it is not part of the shipped code path.
    const CURL_LIKE_DECODE: GeneralPurpose = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
    );

    /// Tiny self-contained PRNG (a linear congruential generator using the
    /// Numerical Recipes constants). Avoids pulling `rand` into the test build
    /// while still giving reproducible pseudo-random coverage.
    struct Lcg(u64);

    impl Lcg {
        fn next_u32(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) as u32
        }

        fn next_byte(&mut self) -> u8 {
            (self.next_u32() & 0xFF) as u8
        }
    }

    fn enc_std(input: &[u8]) -> String {
        String::from_utf8(base64_encode(input).unwrap()).unwrap()
    }

    fn enc_url(input: &[u8]) -> String {
        String::from_utf8(base64url_encode(input).unwrap()).unwrap()
    }

    #[test]
    fn max_input_constant_matches_curl() {
        assert_eq!(CURL_MAX_BASE64_INPUT, 16_000_000);
    }

    // ---------------------------------------------------------------------
    // Encode — known-answer vectors (RFC 4648 §10).
    // ---------------------------------------------------------------------
    #[test]
    fn encode_known_answers() {
        assert!(base64_encode(b"").unwrap().is_empty());
        assert_eq!(enc_std(b"f"), "Zg==");
        assert_eq!(enc_std(b"fo"), "Zm8=");
        assert_eq!(enc_std(b"foo"), "Zm9v");
        assert_eq!(enc_std(b"foob"), "Zm9vYg==");
        assert_eq!(enc_std(b"fooba"), "Zm9vYmE=");
        assert_eq!(enc_std(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn standard_encode_uses_plus_slash_and_padding() {
        // '+' is value 62 and '/' is value 63 in the standard alphabet.
        assert_eq!(base64_encode(&[0xFF, 0xFF, 0xFF]).unwrap(), b"////");
        assert_eq!(base64_encode(&[0xFB, 0xFF, 0xFF]).unwrap(), b"+///");
        // A one-byte input pads with two '=' characters.
        assert_eq!(base64_encode(b"f").unwrap(), b"Zg==");
    }

    // ---------------------------------------------------------------------
    // URL-safe encode — uses '-'/'_' and never emits '=' padding.
    // ---------------------------------------------------------------------
    #[test]
    fn url_safe_encode_no_padding_and_url_alphabet() {
        assert!(base64url_encode(b"").unwrap().is_empty());
        // Standard would pad these; the URL-safe form must not.
        assert_eq!(enc_url(b"f"), "Zg");
        assert_eq!(enc_url(b"fo"), "Zm8");
        assert_eq!(enc_url(b"foo"), "Zm9v");
        assert_eq!(enc_url(b"foobar"), "Zm9vYmFy");
        // '-' replaces '+' (62) and '_' replaces '/' (63).
        assert_eq!(base64url_encode(&[0xFF, 0xFF, 0xFF]).unwrap(), b"____");
        assert_eq!(base64url_encode(&[0xFB, 0xFF, 0xFF]).unwrap(), b"-___");
        // Never any '=' padding, regardless of input length.
        for input in [
            b"f".as_slice(),
            b"fo".as_slice(),
            b"foo".as_slice(),
            b"foob".as_slice(),
            b"fooba".as_slice(),
        ] {
            assert!(!base64url_encode(input).unwrap().contains(&b'='));
        }
    }

    #[test]
    fn url_safe_matches_standard_alphabet_translation() {
        // Property: url-safe output equals the standard output with '+' -> '-',
        // '/' -> '_', and the trailing '=' padding stripped.
        let mut rng = Lcg(0xFEED_FACE_CAFE_BABE);
        for _ in 0..1000 {
            let len = (rng.next_u32() % 48) as usize + 1;
            let data: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
            let std_s = enc_std(&data);
            let url_s = enc_url(&data);
            let expected: String = std_s
                .trim_end_matches('=')
                .chars()
                .map(|c| match c {
                    '+' => '-',
                    '/' => '_',
                    other => other,
                })
                .collect();
            assert_eq!(url_s, expected, "url-safe mismatch for {data:?}");
        }
    }

    // ---------------------------------------------------------------------
    // Decode — known-answer vectors.
    // ---------------------------------------------------------------------
    #[test]
    fn decode_known_answers() {
        assert_eq!(base64_decode(b"Zg==").unwrap(), b"f");
        assert_eq!(base64_decode(b"Zm8=").unwrap(), b"fo");
        assert_eq!(base64_decode(b"Zm9v").unwrap(), b"foo");
        assert_eq!(base64_decode(b"Zm9vYg==").unwrap(), b"foob");
        assert_eq!(base64_decode(b"Zm9vYmE=").unwrap(), b"fooba");
        assert_eq!(base64_decode(b"Zm9vYmFy").unwrap(), b"foobar");
        // '+' and '/' are valid standard symbols.
        assert_eq!(
            base64_decode(b"//79/A==").unwrap(),
            vec![0xFF, 0xFE, 0xFD, 0xFC]
        );
    }

    // ---------------------------------------------------------------------
    // Decode — structural rejections (must match curl's error conditions).
    // ---------------------------------------------------------------------
    #[test]
    fn decode_rejects_empty_and_bad_length() {
        assert_eq!(base64_decode(b""), Err(CurlError::BadContentEncoding));
        assert_eq!(base64_decode(b"Z"), Err(CurlError::BadContentEncoding));
        assert_eq!(base64_decode(b"Zg"), Err(CurlError::BadContentEncoding));
        assert_eq!(base64_decode(b"Zm9"), Err(CurlError::BadContentEncoding));
        assert_eq!(base64_decode(b"Zm9vYg"), Err(CurlError::BadContentEncoding));
    }

    #[test]
    fn decode_rejects_excess_padding() {
        // Three or four '=' characters exceed the two-padding maximum.
        assert_eq!(base64_decode(b"Y==="), Err(CurlError::BadContentEncoding));
        assert_eq!(base64_decode(b"===="), Err(CurlError::BadContentEncoding));
        assert_eq!(
            base64_decode(b"Zm9vY==="),
            Err(CurlError::BadContentEncoding)
        );
    }

    #[test]
    fn decode_rejects_illegal_symbols() {
        // '*' is not in the alphabet.
        assert_eq!(base64_decode(b"Zm9*"), Err(CurlError::BadContentEncoding));
        assert_eq!(base64_decode(b"****"), Err(CurlError::BadContentEncoding));
        // The URL-safe symbols '-' and '_' are NOT valid for the standard
        // decoder (curl has no URL-safe decode and rejects them).
        assert_eq!(base64_decode(b"-___"), Err(CurlError::BadContentEncoding));
        assert_eq!(base64_decode(b"ab-_"), Err(CurlError::BadContentEncoding));
    }

    #[test]
    fn decode_does_not_skip_whitespace() {
        // curl rejects embedded whitespace rather than skipping it.
        assert_eq!(base64_decode(b"Zm9 "), Err(CurlError::BadContentEncoding));
        assert_eq!(base64_decode(b"Z m9"), Err(CurlError::BadContentEncoding));
        assert_eq!(base64_decode(b"\tm9v"), Err(CurlError::BadContentEncoding));
        assert_eq!(base64_decode(b"Zm9\n"), Err(CurlError::BadContentEncoding));
    }

    #[test]
    fn decode_rejects_misplaced_padding() {
        // A '=' that appears before the permitted trailing run is illegal.
        assert_eq!(base64_decode(b"Z=g="), Err(CurlError::BadContentEncoding));
        assert_eq!(base64_decode(b"=AAA"), Err(CurlError::BadContentEncoding));
        assert_eq!(base64_decode(b"A=AA"), Err(CurlError::BadContentEncoding));
        assert_eq!(base64_decode(b"AA=A"), Err(CurlError::BadContentEncoding));
    }

    // ---------------------------------------------------------------------
    // Decode — curl's deliberate trailing-bit leniency.
    // ---------------------------------------------------------------------
    #[test]
    fn decode_ignores_trailing_bits_like_curl() {
        // "Zg==" is canonical for "f"; "Zh==" carries non-zero trailing bits in
        // the second symbol ('h' vs 'g') yet curl ignores them and yields "f".
        assert_eq!(base64_decode(b"Zh==").unwrap(), b"f");
        // "Zm8=" is canonical for "fo"; "Zm9=" has non-zero trailing bits ('9'
        // vs '8') and still decodes to "fo".
        assert_eq!(base64_decode(b"Zm9=").unwrap(), b"fo");

        // Confirm the deliberate divergence from the crate's DEFAULT decoder,
        // which rejects non-zero trailing bits: this proves our leniency is an
        // intentional curl-parity choice, not an accident of delegation.
        assert!(STANDARD.decode("Zh==").is_err());
        assert!(STANDARD.decode("Zm9=").is_err());
    }

    // ---------------------------------------------------------------------
    // Decode — inputs a naive/permissive decoder accepts but curl rejects.
    // ---------------------------------------------------------------------
    #[test]
    fn decode_rejects_inputs_a_naive_decoder_accepts() {
        // A no-padding engine decodes the unpadded "Zg" into "f", but curl
        // requires a multiple-of-four length, so we must reject it.
        assert_eq!(STANDARD_NO_PAD.decode("Zg").unwrap(), b"f");
        assert_eq!(base64_decode(b"Zg"), Err(CurlError::BadContentEncoding));

        // Likewise "Zm9vYg" (unpadded "foob") is accepted by a no-pad decoder
        // but is length 6 — rejected by curl.
        assert_eq!(STANDARD_NO_PAD.decode("Zm9vYg").unwrap(), b"foob");
        assert_eq!(base64_decode(b"Zm9vYg"), Err(CurlError::BadContentEncoding));
    }

    #[test]
    fn decode_honors_strlen_nul_truncation() {
        // curl uses strlen(), so bytes at/after a NUL are not part of the input.
        // "Zm9v\0junk" -> curl sees "Zm9v" (len 4) -> decodes "foo".
        assert_eq!(base64_decode(b"Zm9v\0junk").unwrap(), b"foo");
        // "Zm\0..." -> curl sees "Zm" (len 2) -> rejected (not a multiple of 4).
        assert_eq!(
            base64_decode(b"Zm\0vYmFy"),
            Err(CurlError::BadContentEncoding)
        );
        // A leading NUL yields an empty effective string -> rejected.
        assert_eq!(base64_decode(b"\0Zm9v"), Err(CurlError::BadContentEncoding));
    }

    // ---------------------------------------------------------------------
    // Encode — the 16,000,000-byte input cap.
    // ---------------------------------------------------------------------
    #[test]
    fn encode_rejects_oversize_input() {
        // One byte past the cap is rejected by both encoders (the guard returns
        // before doing any encoding, so this allocation is cheap).
        let too_big = vec![0u8; CURL_MAX_BASE64_INPUT + 1];
        assert_eq!(base64_encode(&too_big), Err(CurlError::TooLarge));
        assert_eq!(base64url_encode(&too_big), Err(CurlError::TooLarge));
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn encode_allows_input_exactly_at_cap() {
        // curl uses a strict `>` comparison, so an input of exactly the cap is
        // still encoded. Verify the boundary using zero-filled data and check
        // the output length matches the base64 size formula.
        let at_cap = vec![0u8; CURL_MAX_BASE64_INPUT];
        let encoded = base64_encode(&at_cap).expect("input at the cap must encode");
        // 16_000_000 bytes -> ceil(16_000_000 / 3) = 5_333_334 quantums * 4.
        assert_eq!(encoded.len(), 5_333_334 * 4);
        assert_eq!(encoded.len(), 21_333_336);
    }

    // ---------------------------------------------------------------------
    // Round-trip and independent cross-check over pseudo-random buffers.
    // ---------------------------------------------------------------------
    #[cfg_attr(miri, ignore)]
    #[test]
    fn round_trip_random_buffers() {
        let mut rng = Lcg(0x1234_5678_9ABC_DEF0);
        for _ in 0..3000 {
            // Non-empty buffers (empty encodes to empty, which is not a valid
            // decoder input — that boundary is covered separately).
            let len = (rng.next_u32() % 96) as usize + 1;
            let data: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();

            // Standard: encode then decode must reproduce the original bytes.
            let encoded = base64_encode(&data).unwrap();
            let decoded = base64_decode(&encoded).unwrap();
            assert_eq!(decoded, data, "std round-trip failed for {data:?}");

            // The independent crate oracle must agree on the same encoded text.
            let oracle = CURL_LIKE_DECODE.decode(&encoded).unwrap();
            assert_eq!(oracle, data, "oracle disagreed for {data:?}");

            // URL-safe form must round-trip too, after translating the alphabet
            // back to standard and restoring the dropped padding.
            let url = enc_url(&data);
            assert!(!url.contains('='));
            let mut restored: String = url
                .chars()
                .map(|c| match c {
                    '-' => '+',
                    '_' => '/',
                    other => other,
                })
                .collect();
            while restored.len() % 4 != 0 {
                restored.push('=');
            }
            assert_eq!(
                base64_decode(restored.as_bytes()).unwrap(),
                data,
                "url round-trip failed for {data:?}"
            );
        }
    }

    #[test]
    fn decode_output_length_is_exact() {
        // rawlen = numQuantums*3 - padding for every padding case.
        assert_eq!(base64_decode(b"Zm9v").unwrap().len(), 3); // no padding
        assert_eq!(base64_decode(b"Zm8=").unwrap().len(), 2); // one '='
        assert_eq!(base64_decode(b"Zg==").unwrap().len(), 1); // two '='
        assert_eq!(base64_decode(b"Zm9vYmFy").unwrap().len(), 6); // two quantums
        assert_eq!(base64_decode(b"Zm9vYg==").unwrap().len(), 4);
    }
}
