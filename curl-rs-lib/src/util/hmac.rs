//! HMAC (Hash-based Message Authentication Code) computation — RFC 2104.
//!
//! Rust rewrite of `lib/hmac.c` (164 lines). Provides generic HMAC digests
//! used by NTLM authentication (without SSPI), AWS SigV4 request signing,
//! and HTTP Digest authentication.
//!
//! # Architecture
//!
//! The original C implementation (`lib/hmac.c`) manually managed HMAC
//! contexts with `malloc`/`free` and dispatched hash operations through a
//! `struct HMAC_params` function-pointer table (`hinit`, `hupdate`,
//! `hfinal`). This Rust module delegates entirely to the [`hmac`] crate,
//! which provides a type-safe generic [`Hmac<D>`] implementing the [`Mac`]
//! trait. All manual memory management is replaced by Rust ownership
//! semantics — no `unsafe` blocks are needed.
//!
//! # Exports
//!
//! | Symbol | Kind | Description |
//! |--------|------|-------------|
//! | [`hmac_sha256`] | function | One-shot HMAC-SHA-256 → `[u8; 32]` |
//! | [`hmac_md5`] | function | One-shot HMAC-MD5 → `[u8; 16]` |
//! | [`HmacContext`] | enum | Streaming HMAC context (replaces C `HMAC_context`) |
//! | [`HmacAlgorithm`] | enum | Algorithm selector (`Sha256`, `Md5`) |
//! | [`hmacit`] | function | One-shot helper matching C `Curl_hmacit` |
//!
//! # Examples
//!
//! ```
//! use curl_rs_lib::util::hmac::{hmac_sha256, hmac_md5, HmacContext, HmacAlgorithm, hmacit};
//!
//! // One-shot HMAC-SHA-256
//! let digest = hmac_sha256(b"key", b"message");
//! assert_eq!(digest.len(), 32);
//!
//! // One-shot HMAC-MD5
//! let digest = hmac_md5(b"key", b"message");
//! assert_eq!(digest.len(), 16);
//!
//! // Streaming context
//! let mut ctx = HmacContext::new(HmacAlgorithm::Sha256, b"key").unwrap();
//! ctx.update(b"part1");
//! ctx.update(b"part2");
//! let digest = ctx.finalize();
//! assert_eq!(digest.len(), 32);
//!
//! // One-shot helper (matches C Curl_hmacit)
//! let digest = hmacit(HmacAlgorithm::Md5, b"key", b"data").unwrap();
//! assert_eq!(digest.len(), 16);
//! ```

use hmac::{Hmac, Mac};
use md5::Md5;
use sha2::Sha256;

use crate::error::CurlError;

// ---------------------------------------------------------------------------
// HmacAlgorithm — algorithm selector enum
// ---------------------------------------------------------------------------

/// Supported HMAC hash algorithms.
///
/// Replaces the C `struct HMAC_params` dispatch table. Instead of
/// function-pointer indirection, Rust uses generics via the [`hmac::Mac`]
/// trait parameterised by the digest type.
///
/// # Variants
///
/// * `Sha256` — HMAC-SHA-256 producing a 32-byte digest. Used by AWS SigV4
///   signing and HTTP Digest auth (SHA-256 variant).
/// * `Md5` — HMAC-MD5 producing a 16-byte digest. Used by NTLMv2
///   authentication and the CRAM-MD5 SASL mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HmacAlgorithm {
    /// HMAC-SHA-256 (32-byte digest).
    Sha256,
    /// HMAC-MD5 (16-byte digest).
    Md5,
}

impl HmacAlgorithm {
    /// Returns the output digest length in bytes for this algorithm.
    ///
    /// * `Sha256` → 32
    /// * `Md5` → 16
    #[inline]
    pub fn digest_len(self) -> usize {
        match self {
            HmacAlgorithm::Sha256 => 32,
            HmacAlgorithm::Md5 => 16,
        }
    }
}

// ---------------------------------------------------------------------------
// HmacContext — streaming HMAC computation context
// ---------------------------------------------------------------------------

/// Streaming HMAC computation context.
///
/// Replaces the C `struct HMAC_context` which held two opaque hash context
/// pointers (`hashctxt1`, `hashctxt2`) and a pointer to the `HMAC_params`
/// function-pointer table. The Rust enum directly carries a fully-typed
/// [`Hmac<D>`] instance for each supported algorithm variant.
///
/// The context is created with [`HmacContext::new`], fed data via
/// [`HmacContext::update`] (may be called multiple times), and consumed by
/// [`HmacContext::finalize`] to produce the final digest.
///
/// # Lifetime
///
/// Consuming `self` in [`finalize`](HmacContext::finalize) mirrors the C
/// behaviour where `Curl_HMAC_final` frees the context — Rust's ownership
/// model enforces this at compile time.
pub enum HmacContext {
    /// HMAC-SHA-256 context wrapping `Hmac<Sha256>`.
    Sha256(Hmac<Sha256>),
    /// HMAC-MD5 context wrapping `Hmac<Md5>`.
    Md5(Hmac<Md5>),
}

impl HmacContext {
    /// Create a new HMAC context for the given algorithm and key.
    ///
    /// Corresponds to C `Curl_HMAC_init`. If the key exceeds the hash
    /// block size the [`hmac`] crate automatically hashes it first per
    /// RFC 2104 §2, so callers need not pre-process oversized keys.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::OutOfMemory`] if key initialisation fails.
    /// This preserves the C API error contract where `Curl_HMAC_init`
    /// returns `NULL` on allocation failure. In practice, the Rust
    /// [`Hmac`] implementation via [`Mac::new_from_slice`] only returns
    /// `Err(InvalidLength)` for algorithms with a fixed-size key
    /// requirement — neither SHA-256 nor MD5 impose one, so this path
    /// is effectively unreachable but is kept for API compatibility.
    pub fn new(algorithm: HmacAlgorithm, key: &[u8]) -> Result<Self, CurlError> {
        match algorithm {
            HmacAlgorithm::Sha256 => {
                let mac = Hmac::<Sha256>::new_from_slice(key)
                    .map_err(|_| CurlError::OutOfMemory)?;
                Ok(HmacContext::Sha256(mac))
            }
            HmacAlgorithm::Md5 => {
                let mac = Hmac::<Md5>::new_from_slice(key)
                    .map_err(|_| CurlError::OutOfMemory)?;
                Ok(HmacContext::Md5(mac))
            }
        }
    }

    /// Feed data into the HMAC computation.
    ///
    /// Corresponds to C `Curl_HMAC_update`. May be called zero or more
    /// times to incrementally process data chunks before finalisation.
    /// The order and boundaries of chunks do not affect the result — only
    /// the concatenation of all data matters.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        match self {
            HmacContext::Sha256(ref mut mac) => Mac::update(mac, data),
            HmacContext::Md5(ref mut mac) => Mac::update(mac, data),
        }
    }

    /// Consume the context and return the final HMAC digest.
    ///
    /// Corresponds to C `Curl_HMAC_final`. The returned [`Vec<u8>`] has
    /// length 32 for SHA-256 or 16 for MD5.
    ///
    /// Consuming `self` mirrors the C behaviour where `Curl_HMAC_final`
    /// frees the HMAC context after extracting the digest.
    pub fn finalize(self) -> Vec<u8> {
        match self {
            HmacContext::Sha256(mac) => mac.finalize().into_bytes().to_vec(),
            HmacContext::Md5(mac) => mac.finalize().into_bytes().to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// One-shot convenience functions
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA-256 in one shot, returning a fixed-size 32-byte array.
///
/// This is a convenience wrapper around [`Hmac<Sha256>`] for callers that
/// have all data available at once. The key may be of any length — keys
/// longer than the SHA-256 block size (64 bytes) are automatically hashed
/// first per RFC 2104.
///
/// # Panics
///
/// This function will never panic — [`Hmac<Sha256>`] accepts any key length.
///
/// # Use Cases
///
/// * AWS Signature V4 signing (iterative key derivation).
/// * HTTP Digest authentication (SHA-256 algorithm variant).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // Hmac<Sha256>::new_from_slice accepts any key length, so expect() is
    // safe here. This avoids returning Result for a path that cannot fail.
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .expect("HMAC-SHA-256 accepts any key length");
    Mac::update(&mut mac, data);
    let result = mac.finalize();
    result.into_bytes().into()
}

/// Compute HMAC-MD5 in one shot, returning a fixed-size 16-byte array.
///
/// This is a convenience wrapper around [`Hmac<Md5>`] for callers that
/// have all data available at once. The key may be of any length — keys
/// longer than the MD5 block size (64 bytes) are automatically hashed
/// first per RFC 2104.
///
/// # Panics
///
/// This function will never panic — [`Hmac<Md5>`] accepts any key length.
///
/// # Use Cases
///
/// * NTLMv2 authentication (HMAC-MD5 of the NT hash and challenge).
/// * CRAM-MD5 SASL mechanism.
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    // Hmac<Md5>::new_from_slice accepts any key length, so expect() is
    // safe here. This avoids returning Result for a path that cannot fail.
    let mut mac = Hmac::<Md5>::new_from_slice(key)
        .expect("HMAC-MD5 accepts any key length");
    Mac::update(&mut mac, data);
    let result = mac.finalize();
    result.into_bytes().into()
}

// ---------------------------------------------------------------------------
// hmacit — one-shot helper matching C Curl_hmacit
// ---------------------------------------------------------------------------

/// One-shot HMAC computation — initialise, update, and finalise in a single
/// call.
///
/// Corresponds to C `Curl_hmacit`. Returns the digest as a [`Vec<u8>`]
/// whose length depends on the algorithm (32 for SHA-256, 16 for MD5).
///
/// # Errors
///
/// Returns [`CurlError::OutOfMemory`] if context creation fails, preserving
/// the C error contract where `Curl_hmacit` returns `CURLE_OUT_OF_MEMORY`
/// when `Curl_HMAC_init` returns `NULL`.
///
/// # Parameters
///
/// * `algorithm` — The hash algorithm to use ([`HmacAlgorithm::Sha256`] or
///   [`HmacAlgorithm::Md5`]).
/// * `key` — The HMAC key (arbitrary length; hashed if longer than the
///   algorithm's block size per RFC 2104).
/// * `data` — The message data to authenticate.
pub fn hmacit(
    algorithm: HmacAlgorithm,
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, CurlError> {
    let mut ctx = HmacContext::new(algorithm, key)?;
    ctx.update(data);
    Ok(ctx.finalize())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4231 Test Case 1 — HMAC-SHA-256
    // Key  = 0x0b repeated 20 times
    // Data = "Hi There"
    // Expected HMAC-SHA-256 = b0344c61d8db38535ca8afceaf0bf12b
    //                         881dc200c9833da726e9376c2e32cff7
    #[test]
    fn test_hmac_sha256_rfc4231_case1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let expected: [u8; 32] = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
            0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
            0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
            0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(hmac_sha256(&key, data), expected);
    }

    // RFC 4231 Test Case 2 — HMAC-SHA-256
    // Key  = "Jefe"
    // Data = "what do ya want for nothing?"
    #[test]
    fn test_hmac_sha256_rfc4231_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected: [u8; 32] = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
            0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
            0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
            0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
        ];
        assert_eq!(hmac_sha256(key, data), expected);
    }

    // RFC 2202 Test Case 1 — HMAC-MD5
    // Key  = 0x0b repeated 16 times
    // Data = "Hi There"
    // Expected HMAC-MD5 = 9294727a3638bb1c13f48ef8158bfc9d
    #[test]
    fn test_hmac_md5_rfc2202_case1() {
        let key = [0x0bu8; 16];
        let data = b"Hi There";
        let expected: [u8; 16] = [
            0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c,
            0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d,
        ];
        assert_eq!(hmac_md5(&key, data), expected);
    }

    // RFC 2202 Test Case 2 — HMAC-MD5
    // Key  = "Jefe"
    // Data = "what do ya want for nothing?"
    // Expected HMAC-MD5 = 750c783e6ab0b503eaa86e310a5db738
    #[test]
    fn test_hmac_md5_rfc2202_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected: [u8; 16] = [
            0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
            0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38,
        ];
        assert_eq!(hmac_md5(key, data), expected);
    }

    // Streaming context — verify identical output to one-shot
    #[test]
    fn test_hmac_context_sha256_streaming() {
        let key = b"streaming-key";
        let data_full = b"hello world streaming test";
        let one_shot = hmac_sha256(key, data_full);

        let mut ctx = HmacContext::new(HmacAlgorithm::Sha256, key).unwrap();
        ctx.update(b"hello ");
        ctx.update(b"world ");
        ctx.update(b"streaming test");
        let streamed = ctx.finalize();

        assert_eq!(streamed.as_slice(), one_shot.as_slice());
    }

    // Streaming context — MD5 variant
    #[test]
    fn test_hmac_context_md5_streaming() {
        let key = b"streaming-key-md5";
        let data_full = b"incremental md5 test data";
        let one_shot = hmac_md5(key, data_full);

        let mut ctx = HmacContext::new(HmacAlgorithm::Md5, key).unwrap();
        ctx.update(b"incremental ");
        ctx.update(b"md5 test ");
        ctx.update(b"data");
        let streamed = ctx.finalize();

        assert_eq!(streamed.as_slice(), one_shot.as_slice());
    }

    // hmacit one-shot helper — SHA-256
    #[test]
    fn test_hmacit_sha256() {
        let key = b"hmacit-key";
        let data = b"hmacit-data";
        let result = hmacit(HmacAlgorithm::Sha256, key, data).unwrap();
        let expected = hmac_sha256(key, data);
        assert_eq!(result.as_slice(), expected.as_slice());
        assert_eq!(result.len(), 32);
    }

    // hmacit one-shot helper — MD5
    #[test]
    fn test_hmacit_md5() {
        let key = b"hmacit-key";
        let data = b"hmacit-data";
        let result = hmacit(HmacAlgorithm::Md5, key, data).unwrap();
        let expected = hmac_md5(key, data);
        assert_eq!(result.as_slice(), expected.as_slice());
        assert_eq!(result.len(), 16);
    }

    // Empty data should still produce a valid HMAC
    #[test]
    fn test_hmac_empty_data() {
        let key = b"key";
        let sha_result = hmac_sha256(key, b"");
        assert_eq!(sha_result.len(), 32);

        let md5_result = hmac_md5(key, b"");
        assert_eq!(md5_result.len(), 16);
    }

    // Empty key should still work (RFC 2104 allows zero-length keys)
    #[test]
    fn test_hmac_empty_key() {
        let sha_result = hmac_sha256(b"", b"data");
        assert_eq!(sha_result.len(), 32);

        let md5_result = hmac_md5(b"", b"data");
        assert_eq!(md5_result.len(), 16);
    }

    // Large key (> block size of 64 bytes) — triggers internal key hashing
    #[test]
    fn test_hmac_large_key() {
        let key = [0xAAu8; 131]; // > 64-byte block size for both SHA-256 and MD5
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";

        // RFC 4231 Test Case 6 for SHA-256
        let expected_sha256: [u8; 32] = [
            0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f,
            0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f,
            0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14,
            0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54,
        ];
        assert_eq!(hmac_sha256(&key, data), expected_sha256);
    }

    // HmacAlgorithm::digest_len
    #[test]
    fn test_algorithm_digest_len() {
        assert_eq!(HmacAlgorithm::Sha256.digest_len(), 32);
        assert_eq!(HmacAlgorithm::Md5.digest_len(), 16);
    }

    // Verify HmacAlgorithm derives
    #[test]
    fn test_algorithm_derives() {
        let a = HmacAlgorithm::Sha256;
        let b = a;
        assert_eq!(a, b);

        let c = HmacAlgorithm::Md5;
        assert_ne!(a, c);

        // Debug formatting should not panic
        let _ = format!("{:?}", a);
    }

    // Single-byte updates produce same result as bulk update
    #[test]
    fn test_hmac_context_byte_by_byte() {
        let key = b"byte-key";
        let data = b"abcdefgh";
        let expected = hmac_sha256(key, data);

        let mut ctx = HmacContext::new(HmacAlgorithm::Sha256, key).unwrap();
        for &b in data.iter() {
            ctx.update(&[b]);
        }
        let result = ctx.finalize();
        assert_eq!(result.as_slice(), expected.as_slice());
    }
}
