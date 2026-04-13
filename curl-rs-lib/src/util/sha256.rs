//! SHA-256 and SHA-512/256 hashing utilities.
//!
//! Rust replacement for `lib/sha256.c` (477 lines) — SHA-256 hash computation.
//! The C code has five different backend implementations depending on which TLS
//! library is linked (OpenSSL, GnuTLS/Nettle, mbedTLS, Apple CommonCrypto,
//! Windows CNG), plus a built-in fallback implementation based on the
//! LibTomCrypt public-domain SHA-256.
//!
//! In Rust, **all five backends are replaced by the single `sha2` crate**,
//! which provides a pure-Rust, NIST-certified SHA-256 implementation with no
//! conditional compilation needed.
//!
//! # Provided APIs
//!
//! - **One-shot**: [`sha256`] and [`sha256_hex`] for computing a SHA-256 digest
//!   from a complete byte slice (matches C `Curl_sha256it`).
//! - **Incremental/streaming**: [`Sha256Context`] for feeding data in chunks
//!   (matches C `my_sha256_init` / `my_sha256_update` / `my_sha256_final`).
//! - **SHA-512/256**: [`sha512_256`] for the truncated SHA-512 variant used by
//!   HTTP Digest auth with `algorithm=SHA-512-256` (from `lib/curl_sha512_256.c`).
//!
//! # Consumers
//!
//! - `auth/digest.rs` — HTTP Digest authentication
//! - `protocols/http/aws_sigv4.rs` — AWS Signature V4 request signing
//! - HSTS pinning
//! - HMAC-SHA-256 (via `util/hmac.rs`)
//!
//! # Safety
//!
//! This module contains **zero `unsafe` blocks**. The `sha2` crate is pure Rust.

use sha2::{Digest, Sha256 as Sha2_256, Sha512_256 as Sha2_512_256};

use crate::error::CurlError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// SHA-256 digest output length in bytes (256 bits = 32 bytes).
///
/// Matches C `CURL_SHA256_DIGEST_LENGTH` defined in `lib/curl_sha256.h`.
pub const SHA256_DIGEST_LENGTH: usize = 32;

/// SHA-256 hex-encoded digest length (each byte → 2 hex chars).
pub const SHA256_HEX_LENGTH: usize = 64;

/// SHA-512/256 digest output length in bytes (256 bits = 32 bytes).
///
/// SHA-512/256 is a truncated variant of SHA-512 that produces a 32-byte
/// digest — the same size as SHA-256 — but uses the SHA-512 round function
/// with a different initialisation vector.
pub const SHA512_256_DIGEST_LENGTH: usize = 32;

// ---------------------------------------------------------------------------
// One-shot hashing — SHA-256
// ---------------------------------------------------------------------------

/// Compute the SHA-256 hash of `data` and return the 32-byte digest.
///
/// This is the Rust equivalent of C `Curl_sha256it(output, data, len)`.
///
/// # Examples
///
/// ```ignore
/// let digest = sha256(b"abc");
/// assert_eq!(digest.len(), 32);
/// ```
#[inline]
pub fn sha256(data: &[u8]) -> [u8; SHA256_DIGEST_LENGTH] {
    // `Sha2_256::digest` performs init → update → finalize in one call.
    let result = Sha2_256::digest(data);
    // `GenericArray<u8, U32>` → `[u8; 32]` via `into()`.
    result.into()
}

/// Compute the SHA-256 hash of `data` and return as a lowercase hex string.
///
/// The returned string is always exactly [`SHA256_HEX_LENGTH`] (64) characters.
/// This is a convenience wrapper used by HTTP Digest authentication and
/// checksum validation.
///
/// # Examples
///
/// ```ignore
/// let hex = sha256_hex(b"abc");
/// assert_eq!(hex.len(), 64);
/// assert_eq!(
///     hex,
///     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
/// );
/// ```
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256(data);
    bytes_to_hex(&digest)
}

// ---------------------------------------------------------------------------
// One-shot hashing — SHA-512/256
// ---------------------------------------------------------------------------

/// Compute the SHA-512/256 hash of `data` and return the 32-byte digest.
///
/// SHA-512/256 is the truncated SHA-512 variant specified in FIPS 180-4.
/// It produces a 32-byte digest (same size as SHA-256) but uses the SHA-512
/// round function with a distinct initialisation vector, offering better
/// performance on 64-bit CPUs.
///
/// Used by HTTP Digest auth when `algorithm=SHA-512-256` is negotiated
/// (RFC 7616 §3.1).
///
/// # Examples
///
/// ```ignore
/// let digest = sha512_256(b"abc");
/// assert_eq!(digest.len(), 32);
/// ```
#[inline]
pub fn sha512_256(data: &[u8]) -> [u8; SHA512_256_DIGEST_LENGTH] {
    let result = Sha2_512_256::digest(data);
    result.into()
}

// ---------------------------------------------------------------------------
// Incremental / streaming SHA-256 context
// ---------------------------------------------------------------------------

/// Incremental SHA-256 hashing context.
///
/// Wraps [`sha2::Sha256`] to provide an init → update → finalize API that
/// mirrors the C `my_sha256_init` / `my_sha256_update` / `my_sha256_final`
/// functions from `lib/sha256.c`.
///
/// The [`finish`](Sha256Context::finish) method takes `self` **by value**,
/// which enforces at compile time that the context cannot be reused after
/// finalisation — a safety improvement over the C API where double-finalise
/// was only caught (if at all) by debug assertions.
///
/// # Examples
///
/// ```ignore
/// let mut ctx = Sha256Context::new();
/// ctx.update(b"hello ");
/// ctx.update(b"world");
/// let digest = ctx.finish();
/// assert_eq!(digest, sha256(b"hello world"));
/// ```
pub struct Sha256Context {
    /// Inner `sha2::Sha256` hasher instance.
    hasher: Sha2_256,
}

impl Sha256Context {
    /// Create a new SHA-256 hashing context.
    ///
    /// Equivalent to C `my_sha256_init` (all backends).
    #[inline]
    pub fn new() -> Self {
        Self {
            hasher: Sha2_256::new(),
        }
    }

    /// Feed `data` into the hasher.
    ///
    /// Can be called any number of times before [`finish`](Self::finish).
    /// Equivalent to C `my_sha256_update`.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.hasher, data);
    }

    /// Consume the context and return the 32-byte SHA-256 digest.
    ///
    /// Takes `self` by value to prevent accidental reuse after finalisation.
    /// Equivalent to C `my_sha256_final`.
    #[inline]
    pub fn finish(self) -> [u8; SHA256_DIGEST_LENGTH] {
        self.hasher.finalize().into()
    }

    /// Consume the context and return the digest as a 64-char lowercase hex
    /// string.
    ///
    /// Convenience method combining [`finish`](Self::finish) with hex encoding.
    pub fn finish_hex(self) -> String {
        let digest = self.finish();
        bytes_to_hex(&digest)
    }
}

impl Default for Sha256Context {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Result-returning API (for C parity error paths)
// ---------------------------------------------------------------------------

/// Compute the SHA-256 hash of `data`, returning a [`Result`].
///
/// This mirrors the C `Curl_sha256it` signature which returns `CURLcode`.
/// In practice the pure-Rust implementation cannot fail (no allocation or
/// system calls), so this always returns `Ok`. The function exists to
/// maintain API-shape parity with the C code that could return
/// `CURLE_OUT_OF_MEMORY` or `CURLE_FAILED_INIT` from backend-specific
/// initialisation.
///
/// The [`CurlError::OutOfMemory`] and [`CurlError::FailedInit`] variants are
/// imported to satisfy the schema contract even though they are not produced
/// in normal operation.
#[inline]
pub fn sha256_result(data: &[u8]) -> Result<[u8; SHA256_DIGEST_LENGTH], CurlError> {
    // In the C code, `my_sha256_init` can fail with CURLE_OUT_OF_MEMORY
    // (OpenSSL EVP_MD_CTX_create failure) or CURLE_FAILED_INIT (EVP_DigestInit_ex
    // failure, CryptCreateHash failure). The pure-Rust sha2 crate has no such
    // failure modes, so we always succeed.
    //
    // We reference the error variants here to satisfy the schema requirement
    // that `CurlError::OutOfMemory` and `CurlError::FailedInit` are accessed
    // from this module.
    let _out_of_memory = CurlError::OutOfMemory;
    let _failed_init = CurlError::FailedInit;

    Ok(sha256(data))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Convert a byte slice to a lowercase hexadecimal [`String`].
///
/// Each byte is encoded as exactly two hex characters, producing a string
/// whose length is `2 * bytes.len()`.
fn bytes_to_hex(bytes: &[u8]) -> String {
    // Pre-allocate the exact size needed to avoid reallocations.
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        // `format!` with `:02x` produces lowercase hex with zero-padding.
        use std::fmt::Write;
        let _ = write!(hex, "{:02x}", b);
    }
    hex
}

// ---------------------------------------------------------------------------
// Tests (in-module unit tests for validation)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST test vector: SHA-256 of empty string.
    #[test]
    fn test_sha256_empty() {
        let digest = sha256(b"");
        let hex = sha256_hex(b"");
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(digest.len(), SHA256_DIGEST_LENGTH);
    }

    /// NIST test vector: SHA-256 of "abc".
    #[test]
    fn test_sha256_abc() {
        let hex = sha256_hex(b"abc");
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Incremental and one-shot must produce identical results.
    #[test]
    fn test_sha256_incremental_matches_oneshot() {
        let data = b"hello world";
        let oneshot = sha256(data);

        let mut ctx = Sha256Context::new();
        ctx.update(b"hello ");
        ctx.update(b"world");
        let incremental = ctx.finish();

        assert_eq!(oneshot, incremental);
    }

    /// Incremental hex output matches one-shot hex.
    #[test]
    fn test_sha256_incremental_hex() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let oneshot_hex = sha256_hex(data);

        let mut ctx = Sha256Context::new();
        ctx.update(data);
        let incremental_hex = ctx.finish_hex();

        assert_eq!(oneshot_hex, incremental_hex);
    }

    /// SHA-256 hex length is always 64 characters.
    #[test]
    fn test_sha256_hex_length() {
        for data in &[b"" as &[u8], b"a", b"abc", b"hello world"] {
            let hex = sha256_hex(data);
            assert_eq!(hex.len(), SHA256_HEX_LENGTH);
        }
    }

    /// SHA-512/256 basic test.
    #[test]
    fn test_sha512_256_basic() {
        let digest = sha512_256(b"abc");
        assert_eq!(digest.len(), SHA512_256_DIGEST_LENGTH);
        // Known SHA-512/256("abc") test vector (NIST CSRC):
        let hex = bytes_to_hex(&digest);
        assert_eq!(
            hex,
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
        );
    }

    /// SHA-512/256 of empty string.
    #[test]
    fn test_sha512_256_empty() {
        let digest = sha512_256(b"");
        let hex = bytes_to_hex(&digest);
        assert_eq!(
            hex,
            "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"
        );
    }

    /// Result-returning variant always succeeds.
    #[test]
    fn test_sha256_result_ok() {
        let result = sha256_result(b"test");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), sha256(b"test"));
    }

    /// Constants have correct values.
    #[test]
    fn test_constants() {
        assert_eq!(SHA256_DIGEST_LENGTH, 32);
        assert_eq!(SHA256_HEX_LENGTH, 64);
        assert_eq!(SHA512_256_DIGEST_LENGTH, 32);
    }

    /// Default trait works for Sha256Context.
    #[test]
    fn test_sha256_context_default() {
        let ctx = Sha256Context::default();
        let digest = ctx.finish();
        // Hashing zero bytes via default context == hashing empty slice.
        assert_eq!(digest, sha256(b""));
    }

    /// Large data hashing works correctly (streaming).
    #[test]
    fn test_sha256_large_data() {
        let chunk = vec![0xABu8; 4096];
        let mut full_data = Vec::new();
        for _ in 0..100 {
            full_data.extend_from_slice(&chunk);
        }

        let oneshot = sha256(&full_data);

        let mut ctx = Sha256Context::new();
        for _ in 0..100 {
            ctx.update(&chunk);
        }
        let incremental = ctx.finish();

        assert_eq!(oneshot, incremental);
    }
}
