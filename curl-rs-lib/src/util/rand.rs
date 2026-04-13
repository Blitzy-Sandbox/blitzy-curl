//! Cryptographically secure random number generation.
//!
//! This module is the Rust replacement for `lib/rand.c` (284 lines in the C
//! codebase). The C implementation maintained a complex multi-platform
//! fallback chain:
//!
//! 1. TLS-backend random (`Curl_ssl_random`) when built with SSL
//! 2. Windows `BCryptGenRandom` / `CryptGenRandom`
//! 3. `arc4random()` on BSD-family systems
//! 4. `/dev/urandom` on POSIX
//! 5. Weak LCG-seeded `srand()` as last resort
//!
//! In Rust, all of these paths collapse into a single call to the `rand`
//! crate, which provides cryptographically secure randomness cross-platform
//! via the operating system's entropy source (getrandom). There is no "weak"
//! fallback — Rust always gets proper entropy.
//!
//! # Exported Functions
//!
//! | Function | C Equivalent | Purpose |
//! |---|---|---|
//! | [`random_bytes`] | `Curl_rand_bytes` / `Curl_rand` | Fill buffer with secure random bytes |
//! | [`random_hex_string`] | `Curl_rand_hex` | Hex-encoded random string |
//! | [`random_alphanumeric`] | `Curl_rand_alnum` | Alphanumeric random string |
//! | [`generate_nonce`] | — (inline callers) | 32-char hex nonce for auth protocols |
//! | [`generate_boundary`] | — (inline callers) | MIME multipart boundary string |
//! | [`seeded_rng`] | debug `CURL_ENTROPY` | Deterministic RNG for tests |
//! | [`random_u32`] | `randit` cast to u32 | Random 32-bit unsigned integer |
//! | [`random_range`] | — | Random integer in a half-open range |

use std::fmt::Write;

use rand::distributions::{Alphanumeric, DistString};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

use crate::error::CurlError;

// ---------------------------------------------------------------------------
// Phase 1 — Core Random API
// ---------------------------------------------------------------------------

/// Fill `buf` with cryptographically secure random bytes.
///
/// This is the Rust equivalent of the C `Curl_rand_bytes` / `Curl_rand`
/// function. It delegates to [`rand::thread_rng()`] which is backed by the
/// operating system's secure entropy source on every supported platform.
///
/// # Arguments
///
/// * `buf` — mutable byte slice to fill with random data. An empty slice is
///   a no-op that returns `Ok(())`.
///
/// # Errors
///
/// Returns [`CurlError::FailedInit`] if the entropy source is unavailable.
/// In practice, the `rand` crate panics on catastrophic entropy failure, so
/// this function will not return an error under normal operating conditions.
///
/// # Examples
///
/// ```rust
/// # use curl_rs_lib::util::rand::random_bytes;
/// let mut buf = [0u8; 16];
/// random_bytes(&mut buf).unwrap();
/// // buf now contains 16 random bytes
/// ```
pub fn random_bytes(buf: &mut [u8]) -> Result<(), CurlError> {
    if buf.is_empty() {
        return Ok(());
    }
    // rand::thread_rng() is cryptographically secure on all platforms.
    // We use RngCore::fill_bytes directly for zero-overhead random byte
    // generation. It will panic only on catastrophic OS entropy failure,
    // which indicates an unrecoverable system state.
    let mut rng = rand::thread_rng();
    RngCore::fill_bytes(&mut rng, buf);
    Ok(())
}

/// Generate a hex-encoded random string of exactly `len` characters.
///
/// This is the Rust equivalent of the C `Curl_rand_hex` function. The C
/// version required `len` to be an odd number (to account for a
/// null-terminator byte); in Rust we simply produce a `String` of exactly
/// the requested length with no null terminator concerns.
///
/// Internally, `len / 2` random bytes are generated and each byte is
/// formatted as two lowercase hex digits. If `len` is odd, one extra byte
/// is generated and only the first hex digit of that byte is used so that
/// the resulting string has exactly `len` characters.
///
/// # Arguments
///
/// * `len` — desired length of the hex string. A value of 0 returns an
///   empty `String`.
///
/// # Errors
///
/// Returns [`CurlError::BadFunctionArgument`] only if the underlying
/// entropy source fails, which is practically impossible.
///
/// # Examples
///
/// ```rust
/// # use curl_rs_lib::util::rand::random_hex_string;
/// let hex = random_hex_string(32).unwrap();
/// assert_eq!(hex.len(), 32);
/// assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
/// ```
pub fn random_hex_string(len: usize) -> Result<String, CurlError> {
    if len == 0 {
        return Ok(String::new());
    }

    // Number of random bytes needed: each byte produces 2 hex chars.
    // If len is odd we need one extra byte (only the first hex digit is used).
    let num_bytes = len.div_ceil(2);
    let mut bytes = vec![0u8; num_bytes];
    random_bytes(&mut bytes)?;

    // Pre-allocate the exact output capacity.
    let mut hex = String::with_capacity(len);
    for &b in &bytes {
        // write! on a String is infallible; the Result is always Ok.
        let _ = write!(hex, "{:02x}", b);
    }

    // If len is odd, we generated one extra hex digit. Truncate.
    hex.truncate(len);
    Ok(hex)
}

/// Generate a random alphanumeric string of exactly `len` characters.
///
/// This is the Rust equivalent of the C `Curl_rand_alnum` function. The
/// character set is `[A-Za-z0-9]` (62 symbols), matching the C
/// implementation's `alnum[]` lookup table.
///
/// # Arguments
///
/// * `len` — desired string length. A value of 0 returns an empty `String`.
///
/// # Examples
///
/// ```rust
/// # use curl_rs_lib::util::rand::random_alphanumeric;
/// let s = random_alphanumeric(24);
/// assert_eq!(s.len(), 24);
/// assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
/// ```
pub fn random_alphanumeric(len: usize) -> String {
    if len == 0 {
        return String::new();
    }
    let mut rng = rand::thread_rng();
    Alphanumeric.sample_string(&mut rng, len)
}

// ---------------------------------------------------------------------------
// Phase 2 — Nonce and Boundary Generation
// ---------------------------------------------------------------------------

/// Generate a 32-character lowercase hexadecimal nonce.
///
/// This is a convenience wrapper around [`random_hex_string`] that produces
/// a nonce suitable for HTTP Digest authentication, NTLM challenges, and
/// other protocols requiring a client nonce (`cnonce`).
///
/// # Returns
///
/// A 32-character `String` containing only lowercase hexadecimal digits
/// (`[0-9a-f]`). The 128 bits of entropy are sufficient for all
/// authentication nonce requirements.
///
/// # Examples
///
/// ```rust
/// # use curl_rs_lib::util::rand::generate_nonce;
/// let nonce = generate_nonce();
/// assert_eq!(nonce.len(), 32);
/// assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
/// ```
pub fn generate_nonce() -> String {
    // 32 hex chars = 16 random bytes = 128 bits of entropy.
    // unwrap is safe: random_hex_string only fails on entropy exhaustion
    // which causes a panic before reaching the Err path.
    random_hex_string(32).unwrap_or_else(|_| {
        // Defensive fallback: should never be reached in practice.
        // If we somehow got here, produce a zero-filled nonce rather than
        // propagating an error in a convenience function.
        "0".repeat(32)
    })
}

/// Generate a MIME multipart boundary string.
///
/// Produces a boundary string in the format `------------------------<24 hex>`,
/// matching the curl C convention of prefixing random hex digits with a
/// series of dashes. The 24 hex characters (12 random bytes = 96 bits)
/// provide more than sufficient uniqueness for multipart boundaries.
///
/// # Returns
///
/// A `String` of the form `"------------------------"` followed by 24
/// lowercase hex digits, totaling 48 characters.
///
/// # Examples
///
/// ```rust
/// # use curl_rs_lib::util::rand::generate_boundary;
/// let boundary = generate_boundary();
/// assert!(boundary.starts_with("------------------------"));
/// assert_eq!(boundary.len(), 48);
/// ```
pub fn generate_boundary() -> String {
    let hex_part = random_hex_string(24).unwrap_or_else(|_| "0".repeat(24));
    // Curl uses a prefix of 24 dashes followed by 24 random hex chars.
    let mut boundary = String::with_capacity(48);
    boundary.push_str("------------------------");
    boundary.push_str(&hex_part);
    boundary
}

// ---------------------------------------------------------------------------
// Phase 3 — Seed Support (for testing)
// ---------------------------------------------------------------------------

/// Create a deterministic (seeded) random number generator.
///
/// This function is the Rust equivalent of the C `CURL_ENTROPY` environment
/// variable override used in debug builds. It returns a [`StdRng`] seeded
/// with the given value, producing a fully reproducible sequence of random
/// numbers. This is intended **exclusively** for test reproducibility and
/// **must not** be used in production code paths.
///
/// # Arguments
///
/// * `seed` — 64-bit seed value. The same seed always produces the same
///   sequence of random outputs.
///
/// # Returns
///
/// A [`StdRng`] implementing [`rand::Rng`] and [`rand::RngCore`].
///
/// # Examples
///
/// ```rust
/// # use curl_rs_lib::util::rand::seeded_rng;
/// # use rand::Rng;
/// let mut rng1 = seeded_rng(42);
/// let mut rng2 = seeded_rng(42);
/// let val1: u32 = rng1.gen();
/// let val2: u32 = rng2.gen();
/// assert_eq!(val1, val2); // deterministic
/// ```
pub fn seeded_rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

// ---------------------------------------------------------------------------
// Phase 4 — Integer Random
// ---------------------------------------------------------------------------

/// Generate a random 32-bit unsigned integer.
///
/// This replaces the common C pattern of calling `Curl_rand` with a 4-byte
/// buffer and casting the result to `unsigned int`. In Rust we simply ask
/// the RNG for a `u32` directly.
///
/// # Returns
///
/// A uniformly distributed random `u32` in the full range `[0, u32::MAX]`.
///
/// # Examples
///
/// ```rust
/// # use curl_rs_lib::util::rand::random_u32;
/// let val = random_u32();
/// // val is a random u32
/// ```
pub fn random_u32() -> u32 {
    let mut rng = rand::thread_rng();
    rng.gen::<u32>()
}

/// Generate a random `u32` in the half-open range `[min, max)`.
///
/// Used for jitter in retry delays, ephemeral port selection, and other
/// scenarios requiring a bounded random integer.
///
/// # Arguments
///
/// * `min` — inclusive lower bound.
/// * `max` — exclusive upper bound. Must be strictly greater than `min`.
///
/// # Panics
///
/// Panics if `min >= max` (matches the `rand` crate's behaviour for empty
/// ranges).
///
/// # Examples
///
/// ```rust
/// # use curl_rs_lib::util::rand::random_range;
/// let val = random_range(100, 200);
/// assert!((100..200).contains(&val));
/// ```
pub fn random_range(min: u32, max: u32) -> u32 {
    assert!(
        min < max,
        "random_range requires min ({}) < max ({})",
        min,
        max
    );
    let mut rng = rand::thread_rng();
    rng.gen_range(min..max)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_random_bytes_fills_buffer() {
        let mut buf = [0u8; 64];
        random_bytes(&mut buf).unwrap();
        // Statistical check: extremely unlikely that all 64 bytes are zero.
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_random_bytes_empty_buffer() {
        let mut buf: [u8; 0] = [];
        assert!(random_bytes(&mut buf).is_ok());
    }

    #[test]
    fn test_random_hex_string_even_length() {
        let hex = random_hex_string(32).unwrap();
        assert_eq!(hex.len(), 32);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_random_hex_string_odd_length() {
        let hex = random_hex_string(33).unwrap();
        assert_eq!(hex.len(), 33);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_random_hex_string_zero() {
        let hex = random_hex_string(0).unwrap();
        assert!(hex.is_empty());
    }

    #[test]
    fn test_random_hex_string_one() {
        let hex = random_hex_string(1).unwrap();
        assert_eq!(hex.len(), 1);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_random_alphanumeric_length() {
        let s = random_alphanumeric(48);
        assert_eq!(s.len(), 48);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_random_alphanumeric_zero() {
        let s = random_alphanumeric(0);
        assert!(s.is_empty());
    }

    #[test]
    fn test_generate_nonce_format() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 32);
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_boundary_format() {
        let boundary = generate_boundary();
        assert_eq!(boundary.len(), 48);
        assert!(boundary.starts_with("------------------------"));
        let hex_part = &boundary[24..];
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_seeded_rng_deterministic() {
        let mut rng1 = seeded_rng(12345);
        let mut rng2 = seeded_rng(12345);

        let v1: [u8; 16] = rng1.gen();
        let v2: [u8; 16] = rng2.gen();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_seeded_rng_different_seeds() {
        let mut rng1 = seeded_rng(1);
        let mut rng2 = seeded_rng(2);

        let v1: u64 = rng1.gen();
        let v2: u64 = rng2.gen();
        assert_ne!(v1, v2);
    }

    #[test]
    fn test_random_u32_returns_value() {
        // Just verify it doesn't panic.
        let _ = random_u32();
    }

    #[test]
    fn test_random_range_bounds() {
        for _ in 0..1000 {
            let val = random_range(10, 20);
            assert!(val >= 10);
            assert!(val < 20);
        }
    }

    #[test]
    fn test_random_range_single_value() {
        // When range has single element: [5, 6)
        for _ in 0..100 {
            let val = random_range(5, 6);
            assert_eq!(val, 5);
        }
    }

    #[test]
    #[should_panic(expected = "random_range requires min")]
    fn test_random_range_panics_on_equal() {
        random_range(10, 10);
    }

    #[test]
    #[should_panic(expected = "random_range requires min")]
    fn test_random_range_panics_on_inverted() {
        random_range(20, 10);
    }

    #[test]
    fn test_random_bytes_large_buffer() {
        // Test with a large buffer to verify no issues with chunked generation.
        let mut buf = vec![0u8; 4096];
        random_bytes(&mut buf).unwrap();
        // Check that we have reasonable distribution — at least some non-zero bytes.
        let nonzero_count = buf.iter().filter(|&&b| b != 0).count();
        // Statistically, ~4080 of 4096 bytes should be non-zero (1 - 1/256 per byte).
        assert!(nonzero_count > 3900);
    }

    #[test]
    fn test_generate_nonce_uniqueness() {
        // Two consecutive nonces should be different (probabilistically guaranteed).
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_seeded_rng_rngcore_fill_bytes() {
        // Verify that the seeded RNG works with RngCore::fill_bytes.
        let mut rng = seeded_rng(999);
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }
}
