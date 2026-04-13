//! MD5 hash computation module.
//!
//! Pure-Rust replacement for `lib/md5.c` (609 lines). The C code maintained
//! seven separate backend implementations (OpenSSL, GnuTLS/Nettle, wolfSSL,
//! mbedTLS, Apple CommonCrypto, Windows CNG, and a built-in RFC 1321
//! implementation), each selected via `#ifdef` at compile time. This module
//! replaces **all seven** with a single delegation to the `md-5` crate, which
//! provides a portable, pure-Rust MD5 implementation.
//!
//! # Security Note
//!
//! MD5 is cryptographically broken and **must not** be used for new security
//! constructs. It is retained here solely for backward compatibility with:
//!
//! - **HTTP Digest authentication** — RFC 7616 permits the `MD5` algorithm
//!   variant, and many deployed servers still require it.
//! - **NTLM authentication** — NTLMv2 computes the NTProofStr via HMAC-MD5.
//! - **CRAM-MD5 SASL** — the challenge-response mechanism uses HMAC-MD5.
//!
//! # C API Correspondence
//!
//! | Rust API                  | C API                          |
//! |---------------------------|--------------------------------|
//! | [`md5`]                   | `Curl_md5it()`                 |
//! | [`Md5Context::new`]       | `Curl_MD5_init()`              |
//! | [`Md5Context::update`]    | `Curl_MD5_update()`            |
//! | [`Md5Context::finish`]    | `Curl_MD5_final()`             |
//! | [`hmac_md5`]              | `Curl_hmac()` with `Curl_HMAC_MD5` params |
//! | [`MD5_DIGEST_LENGTH`]     | `MD5_DIGEST_LEN` (16)          |

use md5::{Digest, Md5};
use hmac::{Hmac, Mac};

use crate::error::CurlError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Length of an MD5 digest in bytes (128 bits = 16 bytes).
///
/// Corresponds to `MD5_DIGEST_LEN` (16) defined in `lib/curl_md5.h`.
pub const MD5_DIGEST_LENGTH: usize = 16;

/// Length of a hex-encoded MD5 digest string (32 characters).
///
/// Each of the 16 digest bytes is represented as two lowercase hexadecimal
/// characters.
pub const MD5_HEX_LENGTH: usize = 32;

// ---------------------------------------------------------------------------
// Type aliases (internal)
// ---------------------------------------------------------------------------

/// Type alias for HMAC-MD5 as used by NTLM and CRAM-MD5.
type HmacMd5 = Hmac<Md5>;

// ---------------------------------------------------------------------------
// One-shot hashing API
// ---------------------------------------------------------------------------

/// Computes the MD5 hash of `data` and returns the 16-byte digest.
///
/// This is a one-shot convenience function equivalent to the C `Curl_md5it()`
/// function. It creates an internal context, feeds all data, and finalizes in
/// a single call.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::util::md5;
/// let digest = md5::md5(b"abc");
/// assert_eq!(digest.len(), 16);
/// ```
pub fn md5(data: &[u8]) -> [u8; MD5_DIGEST_LENGTH] {
    let result = Md5::digest(data);
    let mut output = [0u8; MD5_DIGEST_LENGTH];
    output.copy_from_slice(&result);
    output
}

/// Computes the MD5 hash of `data` and returns it as a lowercase hex string.
///
/// Returns a 32-character lowercase hexadecimal string. This is the primary
/// format consumed by HTTP Digest authentication (MD5 algorithm variant per
/// RFC 7616).
///
/// # Examples
///
/// ```
/// use curl_rs_lib::util::md5;
/// assert_eq!(md5::md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
/// assert_eq!(md5::md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
/// ```
pub fn md5_hex(data: &[u8]) -> String {
    bytes_to_hex(&md5(data))
}

// ---------------------------------------------------------------------------
// Incremental / Streaming API
// ---------------------------------------------------------------------------

/// Streaming (incremental) MD5 hash context.
///
/// Wraps the `md5::Md5` hasher to provide an API that mirrors the C
/// `struct MD5_context` lifecycle:
///
/// 1. **`new()`** — initialise (C: `Curl_MD5_init(&Curl_DIGEST_MD5)`)
/// 2. **`update()`** — feed data in one or more chunks (C: `Curl_MD5_update()`)
/// 3. **`finish()`** — finalise and retrieve the digest (C: `Curl_MD5_final()`)
///
/// The `finish()` and `finish_hex()` methods consume `self` by value to
/// enforce single finalisation at the type level. This is a safety
/// improvement over the C API where double-finalisation was a latent bug
/// risk due to manual memory management of the context.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::util::md5::Md5Context;
///
/// let mut ctx = Md5Context::new();
/// ctx.update(b"Hello, ");
/// ctx.update(b"world!");
/// let digest = ctx.finish();
/// assert_eq!(digest.len(), 16);
/// ```
pub struct Md5Context {
    hasher: Md5,
}

impl Md5Context {
    /// Creates a new MD5 hashing context, ready to accept data via
    /// [`update`](Self::update).
    ///
    /// Equivalent to `Curl_MD5_init(&Curl_DIGEST_MD5)` in C.
    #[inline]
    pub fn new() -> Self {
        Self {
            hasher: Md5::new(),
        }
    }

    /// Feeds `data` into the MD5 context.
    ///
    /// Can be called any number of times to incrementally hash data.
    /// Equivalent to `Curl_MD5_update(context, data, len)` in C.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.hasher, data);
    }

    /// Finalises the MD5 computation and returns the 16-byte digest.
    ///
    /// Consumes `self` to enforce single finalisation. Equivalent to
    /// `Curl_MD5_final(context, result)` in C, which also freed the context.
    pub fn finish(self) -> [u8; MD5_DIGEST_LENGTH] {
        let result = self.hasher.finalize();
        let mut output = [0u8; MD5_DIGEST_LENGTH];
        output.copy_from_slice(&result);
        output
    }

    /// Finalises the MD5 computation and returns the digest as a lowercase
    /// hex string of [`MD5_HEX_LENGTH`] (32) characters.
    ///
    /// Convenience method combining [`finish`](Self::finish) with hex
    /// encoding.
    pub fn finish_hex(self) -> String {
        bytes_to_hex(&self.finish())
    }
}

impl Default for Md5Context {
    /// Creates a default (freshly initialised) MD5 context.
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// HMAC-MD5 integration
// ---------------------------------------------------------------------------

/// Computes HMAC-MD5 of `data` keyed with `key`, returning the 16-byte MAC.
///
/// Uses the `hmac` crate's `Hmac<Md5>` implementation per RFC 2104.
///
/// # Required By
///
/// - **NTLM authentication** — NTLMv2 computes the NTProofStr as
///   `HMAC_MD5(nt_hash, concat(server_challenge, blob))`.
/// - **CRAM-MD5 SASL** — the response is `HMAC_MD5(password, challenge)`.
///
/// The C equivalent uses the generic `Curl_hmac()` function from
/// `lib/curl_hmac.c` parameterised with the `Curl_HMAC_MD5` descriptor.
///
/// # Errors
///
/// Returns [`CurlError::OutOfMemory`] if the HMAC context cannot be
/// initialised. In practice this should never occur because HMAC-MD5
/// accepts keys of any length (short keys are zero-padded, long keys
/// are hashed first), but the underlying crate API returns `Result` so
/// we propagate the error for correctness.
pub fn hmac_md5(key: &[u8], data: &[u8]) -> Result<[u8; MD5_DIGEST_LENGTH], CurlError> {
    let mut mac =
        HmacMd5::new_from_slice(key).map_err(|_| CurlError::OutOfMemory)?;
    Mac::update(&mut mac, data);
    let result = mac.finalize().into_bytes();
    let mut output = [0u8; MD5_DIGEST_LENGTH];
    output.copy_from_slice(&result);
    Ok(output)
}

// ---------------------------------------------------------------------------
// Multi-part concatenation helpers
// ---------------------------------------------------------------------------

/// Computes the MD5 hash of the concatenation of multiple byte slices.
///
/// Creates an incremental context, feeds each part sequentially, and
/// finalises. This avoids a separate allocation for the concatenated
/// buffer.
///
/// Used extensively in HTTP Digest authentication for computing composite
/// hashes such as `MD5(username:realm:password)` where `username`, `:`,
/// `realm`, `:`, and `password` are passed as separate parts.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::util::md5::{md5, md5_concat};
///
/// // Concatenating parts is equivalent to hashing the joined bytes.
/// let parts_digest = md5_concat(&[b"abc", b"def"]);
/// let joined_digest = md5(b"abcdef");
/// assert_eq!(parts_digest, joined_digest);
/// ```
pub fn md5_concat(parts: &[&[u8]]) -> [u8; MD5_DIGEST_LENGTH] {
    let mut ctx = Md5Context::new();
    for part in parts {
        ctx.update(part);
    }
    ctx.finish()
}

/// Computes the MD5 hash of the concatenation of multiple byte slices and
/// returns it as a lowercase hex string of [`MD5_HEX_LENGTH`] (32)
/// characters.
///
/// Equivalent to [`md5_concat`] followed by hex encoding.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::util::md5::{md5_hex, md5_concat_hex};
///
/// let hex = md5_concat_hex(&[b"abc", b"def"]);
/// let expected = md5_hex(b"abcdef");
/// assert_eq!(hex, expected);
/// ```
pub fn md5_concat_hex(parts: &[&[u8]]) -> String {
    bytes_to_hex(&md5_concat(parts))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Converts a byte slice to a lowercase hexadecimal string.
///
/// Used internally by [`md5_hex`], [`Md5Context::finish_hex`], and
/// [`md5_concat_hex`].
fn bytes_to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // `write!` on a `String` is infallible; the expect is a safety net.
        write!(hex, "{:02x}", byte).expect("hex formatting cannot fail on String");
    }
    hex
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // RFC 1321 — MD5 test vectors (Appendix A.5)
    // ------------------------------------------------------------------

    #[test]
    fn md5_empty_string() {
        assert_eq!(
            md5_hex(b""),
            "d41d8cd98f00b204e9800998ecf8427e",
            "MD5 of empty string must match RFC 1321 test vector"
        );
    }

    #[test]
    fn md5_abc() {
        assert_eq!(
            md5_hex(b"abc"),
            "900150983cd24fb0d6963f7d28e17f72",
            "MD5 of 'abc' must match RFC 1321 test vector"
        );
    }

    #[test]
    fn md5_message_digest() {
        assert_eq!(
            md5_hex(b"message digest"),
            "f96b697d7cb7938d525a2f31aaf161d0",
        );
    }

    #[test]
    fn md5_alphabet_lower() {
        assert_eq!(
            md5_hex(b"abcdefghijklmnopqrstuvwxyz"),
            "c3fcd3d76192e4007dfb496cca67e13b",
        );
    }

    #[test]
    fn md5_alphanumeric() {
        assert_eq!(
            md5_hex(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
            "d174ab98d277d9f5a5611c2c9f419d9f",
        );
    }

    #[test]
    fn md5_numeric_sequence() {
        assert_eq!(
            md5_hex(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
            "57edf4a22be3c955ac49da2e2107b67a",
        );
    }

    // ------------------------------------------------------------------
    // One-shot API — digest length
    // ------------------------------------------------------------------

    #[test]
    fn md5_returns_16_bytes() {
        let digest = md5(b"test data");
        assert_eq!(digest.len(), MD5_DIGEST_LENGTH);
    }

    #[test]
    fn md5_hex_returns_32_chars() {
        let hex = md5_hex(b"test data");
        assert_eq!(hex.len(), MD5_HEX_LENGTH);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ------------------------------------------------------------------
    // Incremental / streaming API
    // ------------------------------------------------------------------

    #[test]
    fn incremental_matches_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";

        let oneshot = md5(data);

        let mut ctx = Md5Context::new();
        ctx.update(&data[..10]);
        ctx.update(&data[10..20]);
        ctx.update(&data[20..]);
        let incremental = ctx.finish();

        assert_eq!(
            oneshot, incremental,
            "Incremental and one-shot hashing must produce identical digests"
        );
    }

    #[test]
    fn incremental_single_byte_at_a_time() {
        let data = b"Hello";
        let oneshot = md5(data);

        let mut ctx = Md5Context::new();
        for byte in data.iter() {
            ctx.update(std::slice::from_ref(byte));
        }
        let incremental = ctx.finish();

        assert_eq!(oneshot, incremental);
    }

    #[test]
    fn context_finish_hex() {
        let mut ctx = Md5Context::new();
        ctx.update(b"abc");
        assert_eq!(ctx.finish_hex(), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn context_default_is_new() {
        let default_ctx = Md5Context::default();
        let new_ctx = Md5Context::new();
        // Both should produce the same digest for empty input.
        assert_eq!(default_ctx.finish(), new_ctx.finish());
    }

    #[test]
    fn context_no_update_is_empty_hash() {
        let ctx = Md5Context::new();
        let hex = bytes_to_hex(&ctx.finish());
        assert_eq!(hex, "d41d8cd98f00b204e9800998ecf8427e");
    }

    // ------------------------------------------------------------------
    // Concatenation helpers
    // ------------------------------------------------------------------

    #[test]
    fn concat_equals_manual_join() {
        let concat_digest = md5_concat(&[b"a", b"b", b"c"]);
        let manual_digest = md5(b"abc");
        assert_eq!(concat_digest, manual_digest);
    }

    #[test]
    fn concat_hex_equals_hex_of_concat() {
        let hex = md5_concat_hex(&[b"abc", b"def"]);
        let expected = md5_hex(b"abcdef");
        assert_eq!(hex, expected);
    }

    #[test]
    fn concat_empty_parts_is_empty_hash() {
        let empty_concat = md5_concat(&[]);
        let empty_hash = md5(b"");
        assert_eq!(empty_concat, empty_hash);
    }

    #[test]
    fn concat_single_part_equals_oneshot() {
        let data = b"single part";
        let concat_digest = md5_concat(&[data]);
        let oneshot_digest = md5(data);
        assert_eq!(concat_digest, oneshot_digest);
    }

    #[test]
    fn concat_with_empty_parts_in_middle() {
        // Empty parts should not affect the result.
        let with_empties = md5_concat(&[b"abc", b"", b"def", b""]);
        let without_empties = md5_concat(&[b"abc", b"def"]);
        assert_eq!(with_empties, without_empties);
    }

    // ------------------------------------------------------------------
    // HMAC-MD5 — RFC 2202 test vectors
    // ------------------------------------------------------------------

    #[test]
    fn hmac_md5_rfc2202_case1() {
        // Key  = 0x0b repeated 16 times
        // Data = "Hi There"
        // HMAC = 9294727a3638bb1c13f48ef8158bfc9d
        let key = [0x0bu8; 16];
        let result = hmac_md5(&key, b"Hi There").expect("hmac_md5 must succeed");
        assert_eq!(bytes_to_hex(&result), "9294727a3638bb1c13f48ef8158bfc9d");
    }

    #[test]
    fn hmac_md5_rfc2202_case2() {
        // Key  = "Jefe"
        // Data = "what do ya want for nothing?"
        // HMAC = 750c783e6ab0b503eaa86e310a5db738
        let result = hmac_md5(b"Jefe", b"what do ya want for nothing?")
            .expect("hmac_md5 must succeed");
        assert_eq!(bytes_to_hex(&result), "750c783e6ab0b503eaa86e310a5db738");
    }

    #[test]
    fn hmac_md5_rfc2202_case3() {
        // Key  = 0xAA repeated 16 times
        // Data = 0xDD repeated 50 times
        // HMAC = 56be34521d144c88dbb8c733f0e8b3f6
        let key = [0xAAu8; 16];
        let data = [0xDDu8; 50];
        let result = hmac_md5(&key, &data).expect("hmac_md5 must succeed");
        assert_eq!(bytes_to_hex(&result), "56be34521d144c88dbb8c733f0e8b3f6");
    }

    #[test]
    fn hmac_md5_empty_data() {
        // HMAC-MD5 with empty data should still produce a valid 16-byte MAC.
        let result = hmac_md5(b"key", b"").expect("hmac_md5 must succeed");
        assert_eq!(result.len(), MD5_DIGEST_LENGTH);
    }

    #[test]
    fn hmac_md5_empty_key() {
        // HMAC-MD5 with an empty key is valid per RFC 2104.
        let result = hmac_md5(b"", b"data").expect("hmac_md5 must succeed");
        assert_eq!(result.len(), MD5_DIGEST_LENGTH);
    }

    #[test]
    fn hmac_md5_long_key() {
        // Keys longer than the block size (64 bytes) are hashed first.
        let long_key = [0x42u8; 128];
        let result = hmac_md5(&long_key, b"test").expect("hmac_md5 must succeed");
        assert_eq!(result.len(), MD5_DIGEST_LENGTH);
    }

    // ------------------------------------------------------------------
    // Constants
    // ------------------------------------------------------------------

    #[test]
    fn digest_length_is_16() {
        assert_eq!(MD5_DIGEST_LENGTH, 16);
    }

    #[test]
    fn hex_length_is_32() {
        assert_eq!(MD5_HEX_LENGTH, 32);
        // Every MD5 hex output must be exactly this length.
        assert_eq!(md5_hex(b"any data").len(), MD5_HEX_LENGTH);
    }

    // ------------------------------------------------------------------
    // Internal helper
    // ------------------------------------------------------------------

    #[test]
    fn bytes_to_hex_empty() {
        assert_eq!(bytes_to_hex(&[]), "");
    }

    #[test]
    fn bytes_to_hex_basic() {
        assert_eq!(bytes_to_hex(&[0x00]), "00");
        assert_eq!(bytes_to_hex(&[0xFF]), "ff");
        assert_eq!(bytes_to_hex(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
    }

    #[test]
    fn bytes_to_hex_all_values() {
        // Ensure all 256 byte values produce correct 2-char hex.
        for i in 0u16..=255 {
            let hex = bytes_to_hex(&[i as u8]);
            assert_eq!(hex.len(), 2);
            assert_eq!(
                u8::from_str_radix(&hex, 16).unwrap(),
                i as u8,
                "Round-trip failed for byte {i:#04x}"
            );
        }
    }
}
