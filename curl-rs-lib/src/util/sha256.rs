//! SHA-256 message digest.
//!
//! Rust rewrite of curl's `lib/sha256.c` / `lib/curl_sha256.h`, providing both a
//! one-shot and an incremental SHA-256 interface. This module is the behavioral
//! successor to curl's `Curl_sha256it()` helper and the `Curl_HMAC_SHA256`
//! descriptor; it is consumed by the authentication layer (`auth::digest` for
//! Digest-SHA-256, `auth::scram` for SCRAM-SHA-256) and by AWS Signature
//! Version 4 signing (`protocols::http::aws_sigv4`), which hashes a canonical
//! request incrementally.
//!
//! # Behavioral parity (digest output, not line-by-line)
//!
//! curl's `lib/sha256.c` selects a SHA-256 implementation from whichever TLS
//! backend is compiled in (OpenSSL, GnuTLS/nettle, mbedTLS, Common Crypto,
//! Win32 Crypto) and otherwise falls back to a vendored LibTomCrypt routine.
//! Every one of those backends — and the fallback, which uses the standard
//! FIPS 180-4 initialization vectors (`0x6A09E667`, …) and compression function
//! — produces the identical, standard SHA-256 digest. In this Rust rewrite the
//! single implementation is the pure-Rust RustCrypto [`sha2`] crate, which
//! likewise produces standard SHA-256 output. The digests are therefore
//! byte-for-byte identical to those of curl 8.x (validated against the
//! published FIPS 180-2 known-answer vectors for `""` and `"abc"` in the unit
//! tests below).
//!
//! Note: this revision of curl contains **no** `sha512_256` variant, so none is
//! provided here.
//!
//! # `Curl_HMAC_SHA256`
//!
//! In C, HMAC-SHA-256 is driven through the `Curl_HMAC_SHA256` "params" vtable
//! — a struct of init/update/final function pointers plus the context size, the
//! maximum key length (the 64-byte input block size), and the 32-byte result
//! size. In Rust that descriptor collapses entirely: the [`hmac`] crate is
//! generic over any [`digest`]-compatible hash, so HMAC-SHA-256 is expressed
//! simply as `Hmac<Sha256>`. The block size and output size that the C struct
//! enumerated by hand are carried by `Sha256`'s associated types
//! (`BlockSizeUser` / `OutputSizeUser`). To support that usage this module
//! re-exports [`Sha256`] so `auth::hmac` can write `Hmac::<Sha256>::…` without
//! taking its own direct dependency on `sha2`.
//!
//! # Memory safety
//!
//! This module contains **zero** `unsafe` code and compiles cleanly under the
//! crate-wide `#![forbid(unsafe_code)]` declared at the `curl-rs-lib` crate root
//! (AAP §0.7.1). The RustCrypto `sha2` crate is itself pure-safe Rust, so no
//! raw-pointer handling — the source of curl's historical defect classes — is
//! reintroduced.
//!
//! # Feature gating
//!
//! Although SHA-256 is logically tied to the `aws-sigv4`, `digest-auth`, and
//! `scram` features, the helper is small, pure, and has no heavy transitive
//! cost, so it is compiled **unconditionally**. This keeps it available to any
//! consumer and guarantees the crate still builds under `--no-default-features`
//! without conditional-compilation bookkeeping.

use sha2::Digest;

/// The SHA-256 hash type, re-exported from the RustCrypto [`sha2`] crate.
///
/// Re-exported so that sibling modules (notably `auth::hmac`) can construct
/// `Hmac<Sha256>` and other [`digest`]-generic constructions without declaring
/// their own dependency on `sha2`. This is the Rust replacement for curl's
/// `Curl_HMAC_SHA256` parameter table (see the module-level documentation).
pub use sha2::Sha256;

/// Length, in bytes, of a SHA-256 digest.
///
/// Direct parity with the C macro `CURL_SHA256_DIGEST_LENGTH` defined in
/// `lib/curl_sha256.h`. SHA-256 always produces a 256-bit (32-byte) digest.
pub const CURL_SHA256_DIGEST_LENGTH: usize = 32;

/// Compute the SHA-256 digest of `input` in a single call.
///
/// This is the parity replacement for curl's
/// `Curl_sha256it(unsigned char *output, const unsigned char *input, size_t len)`.
/// The C function writes the digest into a caller-supplied 32-byte buffer and
/// returns a `CURLcode` (always `CURLE_OK` for the backends that cannot fail to
/// initialize). Because the `sha2` backend has no fallible initialization step,
/// the Rust API is infallible and returns the digest by value.
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::util::sha256::{sha256it, CURL_SHA256_DIGEST_LENGTH};
/// let digest = sha256it(b"abc");
/// assert_eq!(digest.len(), CURL_SHA256_DIGEST_LENGTH);
/// assert_eq!(
///     digest,
///     [
///         0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
///         0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
///         0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
///         0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
///     ]
/// );
/// ```
#[must_use]
pub fn sha256it(input: &[u8]) -> [u8; CURL_SHA256_DIGEST_LENGTH] {
    // `Sha256::digest` performs init + update(input) + finalize in one shot,
    // exactly mirroring the body of `Curl_sha256it`.
    let digest = Sha256::digest(input);

    // Copy the fixed-size `GenericArray` result into a plain `[u8; 32]`. Using
    // `copy_from_slice` (rather than a `From`/`Into` conversion on the generic
    // array type) keeps this robust across `sha2`/`generic-array` versions and
    // requires no `unsafe`. The lengths are guaranteed equal: SHA-256 always
    // emits `CURL_SHA256_DIGEST_LENGTH` bytes.
    let mut output = [0u8; CURL_SHA256_DIGEST_LENGTH];
    output.copy_from_slice(digest.as_slice());
    output
}

/// Incremental SHA-256 hashing context.
///
/// Parity replacement for curl's streaming `my_sha256_init` /
/// `my_sha256_update` / `my_sha256_final` sequence. Data is fed in arbitrarily
/// sized chunks via [`update`](Sha256Context::update) and the digest is produced
/// by [`finalize`](Sha256Context::finalize), which consumes the context. This is
/// the form used by AWS Signature Version 4 signing, which hashes a canonical
/// request assembled from several pieces.
///
/// The context is [`Clone`], mirroring the trivially copyable C `sha256_state`
/// struct; cloning captures the exact intermediate hash state, which is useful
/// when a common prefix must be finalized in more than one way.
#[derive(Clone)]
pub struct Sha256Context {
    inner: Sha256,
}

impl Sha256Context {
    /// Create a fresh, empty SHA-256 context.
    ///
    /// Parity with `my_sha256_init`, which seeds the standard SHA-256
    /// initialization vectors.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    /// Feed an additional chunk of `data` into the running digest.
    ///
    /// May be called any number of times before [`finalize`](Self::finalize).
    /// Parity with `my_sha256_update`.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Consume the context and return the final 32-byte SHA-256 digest.
    ///
    /// Parity with `my_sha256_final`. After finalization the context cannot be
    /// reused — start a new transfer with [`Sha256Context::new`] — which the
    /// type system enforces by taking `self` by value.
    #[must_use]
    pub fn finalize(self) -> [u8; CURL_SHA256_DIGEST_LENGTH] {
        let digest = self.inner.finalize();
        let mut output = [0u8; CURL_SHA256_DIGEST_LENGTH];
        output.copy_from_slice(digest.as_slice());
        output
    }
}

impl Default for Sha256Context {
    /// Equivalent to [`Sha256Context::new`].
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Sha256Context {
    /// Debug output deliberately omits the intermediate hash state, both
    /// because it carries no useful diagnostic value and to avoid leaking
    /// partially hashed data into logs.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sha256Context").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Render a byte slice as a lowercase hex string for readable comparison
    /// against the published known-answer vectors.
    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn digest_length_constant_is_32() {
        assert_eq!(CURL_SHA256_DIGEST_LENGTH, 32);
        assert_eq!(sha256it(b"abc").len(), CURL_SHA256_DIGEST_LENGTH);
    }

    #[test]
    fn one_shot_empty_input_matches_known_answer() {
        // FIPS 180-2 / curl known-answer vector for the empty input.
        assert_eq!(
            to_hex(&sha256it(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn one_shot_abc_matches_known_answer() {
        // FIPS 180-2 / curl known-answer vector for "abc".
        assert_eq!(
            to_hex(&sha256it(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn incremental_context_matches_one_shot() {
        // Hashing "a" then "bc" incrementally must equal the one-shot "abc".
        let mut ctx = Sha256Context::new();
        ctx.update(b"a");
        ctx.update(b"bc");
        assert_eq!(ctx.finalize(), sha256it(b"abc"));
    }

    #[test]
    fn incremental_empty_matches_one_shot_empty() {
        // A context that is finalized without any updates equals SHA-256("").
        assert_eq!(Sha256Context::new().finalize(), sha256it(b""));
    }

    #[test]
    fn default_equals_new() {
        let mut a = Sha256Context::new();
        a.update(b"hello world");
        let mut b = Sha256Context::default();
        b.update(b"hello world");
        assert_eq!(a.finalize(), b.finalize());
    }

    #[test]
    fn clone_captures_intermediate_state() {
        // Cloning mid-stream must yield two contexts that, fed identical
        // remaining input, produce identical digests.
        let mut base = Sha256Context::new();
        base.update(b"shared-prefix-");
        let mut branch = base.clone();
        base.update(b"tail");
        branch.update(b"tail");
        assert_eq!(base.finalize(), branch.finalize());
    }

    #[test]
    fn reexported_sha256_works_with_digest_traits() {
        // Verify the re-exported `Sha256` type is usable exactly as `auth::hmac`
        // will use it (constructing hashers via the `digest` traits). This is
        // the Rust stand-in for curl's `Curl_HMAC_SHA256` descriptor.
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        let out = hasher.finalize();
        assert_eq!(out.len(), CURL_SHA256_DIGEST_LENGTH);
        assert_eq!(out.as_slice(), &sha256it(b"abc"));
    }
}
