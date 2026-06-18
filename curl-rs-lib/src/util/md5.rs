//! MD5 (and, for NTLM, MD4) message-digest primitives.
//!
//! This module is the memory-safe Rust replacement for libcurl's
//! `lib/md5.c` / `lib/curl_md5.h` **and** `lib/md4.c` / `lib/curl_md4.h`.
//! Per the target workspace layout there is no separate `md4.rs`; MD4 is
//! folded into this module because it is only ever needed by the NTLM
//! authentication path.
//!
//! # Scope and consumers
//!
//! * **MD5** is used broadly — by NTLM, HTTP Digest authentication,
//!   CRAM-MD5 (SASL) and POP3 APOP — so it is compiled **unconditionally**.
//!   It is exposed both as a one-shot helper ([`md5it`]) and as an
//!   incremental hasher ([`Md5Context`]); the incremental form mirrors the C
//!   `Curl_MD5_init` / `Curl_MD5_update` / `Curl_MD5_final` lifecycle because
//!   Digest authentication feeds the hash in several pieces.
//! * **MD4** is used **only** by the NTLM core (`lib/curl_ntlm_core.c` in the
//!   C tree, gated there by `USE_CURL_NTLM_CORE`). It is therefore gated here
//!   behind the `ntlm` Cargo feature and exposes only the one-shot
//!   [`md4it`] helper (NTLM never hashes incrementally).
//!
//! # Behavioral parity
//!
//! The C sources are treated as a **behavioral oracle**: the goal is
//! byte-for-byte identical digest output, not a line-by-line transliteration
//! of the public-domain reference implementation. Both algorithms are backed
//! by the audited, pure-Rust [RustCrypto] crates `md-5` (imported as `md5`)
//! and `md4`, which produce exactly the RFC 1321 (MD5) and RFC 1320 (MD4)
//! digests that curl produces.
//!
//! # HMAC / Digest descriptors
//!
//! The C code exposes two function-pointer vtables — `Curl_HMAC_MD5`
//! (`struct HMAC_params`) and `Curl_DIGEST_MD5` (`struct MD5_params`) — so
//! that generic HMAC and Digest code can drive MD5 indirectly. In Rust those
//! vtables collapse to using the [`Md5`] hasher type together with the
//! `digest` / `hmac` traits (e.g. `Hmac<Md5>`). This module therefore
//! re-exports [`Md5`] so that the HMAC implementation can construct
//! `Hmac<Md5>` without redefining a parallel descriptor type.
//!
//! # Memory safety
//!
//! This module contains **zero `unsafe`** and compiles cleanly under the
//! crate-wide `#![forbid(unsafe_code)]`. All buffers are owned Rust arrays;
//! there is no manual allocation, no raw pointers, and no explicit `free`
//! (the C `Curl_MD5_final` freed the heap context — here the equivalent state
//! is dropped automatically).
//!
//! [RustCrypto]: https://github.com/RustCrypto/hashes

// Re-export the MD5 hasher so dependents (notably the HMAC module) can build
// `Hmac<Md5>` directly. The `md-5` crate is published under the name `md-5`
// but its library name is `md5`, hence the `md5::` path.
pub use md5::Md5;

// The `Digest` trait provides `new`, `update` and `finalize`. It is the same
// `digest::Digest` trait that both the `md5` and `md4` crates re-export, so a
// single import here covers the MD5 helpers below (MD4 imports it locally to
// stay self-contained behind the feature gate).
use md5::Digest;

/// Length, in bytes, of an MD5 digest.
///
/// Parity with the C macro `MD5_DIGEST_LEN` from `lib/curl_md5.h`.
pub const MD5_DIGEST_LEN: usize = 16;

/// Compute the MD5 digest of `input` in a single call.
///
/// This is the parity equivalent of the C one-shot `Curl_md5it`. Where the C
/// function wrote into a caller-provided `unsigned char *output` and signalled
/// failure with a `CURLcode`, the Rust version simply returns the 16-byte
/// digest by value: the pure-Rust backend is infallible (it performs no
/// allocation that can fail and engages no external crypto provider), so there
/// is no error path to propagate.
///
/// # Examples
///
/// ```ignore
/// let digest = md5it(b"abc");
/// assert_eq!(digest.len(), MD5_DIGEST_LEN);
/// ```
pub fn md5it(input: &[u8]) -> [u8; MD5_DIGEST_LEN] {
    let mut hasher = Md5::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Incremental MD5 hashing context.
///
/// Mirrors the C `struct MD5_context` and its
/// `Curl_MD5_init` / `Curl_MD5_update` / `Curl_MD5_final` lifecycle:
///
/// | C function          | Rust equivalent          |
/// |---------------------|--------------------------|
/// | `Curl_MD5_init`     | [`Md5Context::new`]      |
/// | `Curl_MD5_update`   | [`Md5Context::update`]   |
/// | `Curl_MD5_final`    | [`Md5Context::finalize`] |
///
/// Digest authentication hashes several discrete pieces (method, URI, nonce,
/// …) and therefore relies on this incremental API rather than [`md5it`].
///
/// Unlike the C version, the context cannot leak: its backing state is owned
/// and dropped automatically, so there is no separate free step and
/// [`finalize`](Md5Context::finalize) consumes `self` to make the
/// "one digest per context" contract explicit at compile time.
#[derive(Clone)]
pub struct Md5Context {
    /// The underlying RustCrypto MD5 hasher accumulating the message.
    inner: Md5,
}

impl Md5Context {
    /// Create a fresh MD5 hashing context.
    ///
    /// Parity with `Curl_MD5_init` (minus the fallible heap allocation, which
    /// has no analog in the safe Rust core).
    #[must_use]
    pub fn new() -> Self {
        Self { inner: Md5::new() }
    }

    /// Feed another chunk of `data` into the running digest.
    ///
    /// Parity with `Curl_MD5_update`. May be called any number of times; the
    /// resulting digest is identical to hashing the concatenation of all
    /// chunks in one call.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Consume the context and return the final 16-byte MD5 digest.
    ///
    /// Parity with `Curl_MD5_final`. Taking `self` by value mirrors the C
    /// contract where the context is no longer usable (it was freed) after the
    /// final call.
    #[must_use]
    pub fn finalize(self) -> [u8; MD5_DIGEST_LEN] {
        self.inner.finalize().into()
    }
}

impl Default for Md5Context {
    /// Equivalent to [`Md5Context::new`].
    fn default() -> Self {
        Self::new()
    }
}

/// Length, in bytes, of an MD4 digest.
///
/// Parity with the C macro `MD4_DIGEST_LENGTH` from `lib/curl_md4.h`.
///
/// MD4 is required **only** by NTLM, so this constant is gated behind the
/// `ntlm` feature to match the C `USE_CURL_NTLM_CORE` build gate.
#[cfg(feature = "ntlm")]
pub const MD4_DIGEST_LENGTH: usize = 16;

/// Compute the MD4 digest of `input` in a single call.
///
/// This is the parity equivalent of the C one-shot `Curl_md4it`. As verified
/// against the C tree, `Curl_md4it` is referenced solely by
/// `lib/curl_ntlm_core.c`; MD4 has no other consumer and is never hashed
/// incrementally, so only this one-shot helper is provided. The whole helper
/// is gated behind the `ntlm` feature (the `md4` crate is an optional
/// dependency enabled by that feature), matching the C `USE_CURL_NTLM_CORE`
/// gate. Under `--no-default-features` this function — and the `md4`
/// dependency — are absent, while the MD5 surface above remains available.
///
/// MD4 is cryptographically broken and retained purely for NTLM wire
/// compatibility; it must not be used for any new security purpose.
#[cfg(feature = "ntlm")]
pub fn md4it(input: &[u8]) -> [u8; MD4_DIGEST_LENGTH] {
    // Import the `Md4` hasher and bring its `Digest` trait into scope
    // anonymously (`as _`). The anonymous import avoids clashing with the
    // module-level `md5::Digest` binding while still enabling the trait
    // methods — both crates re-export the very same `digest::Digest` trait.
    use md4::{Digest as _, Md4};

    let mut hasher = Md4::new();
    hasher.update(input);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lower-case hex encoding helper for comparing against published vectors.
    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    #[test]
    fn md5_digest_len_constant() {
        assert_eq!(MD5_DIGEST_LEN, 16);
        assert_eq!(md5it(b"").len(), MD5_DIGEST_LEN);
    }

    #[test]
    fn md5_known_answer_empty() {
        // RFC 1321 / curl output for the empty input.
        assert_eq!(hex(&md5it(b"")), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn md5_known_answer_abc() {
        // RFC 1321 / curl output for "abc".
        assert_eq!(hex(&md5it(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn md5_incremental_matches_one_shot() {
        // Feeding "a" then "bc" must equal the one-shot digest of "abc",
        // exercising the Curl_MD5_update lifecycle used by Digest auth.
        let mut ctx = Md5Context::new();
        ctx.update(b"a");
        ctx.update(b"bc");
        assert_eq!(ctx.finalize(), md5it(b"abc"));
    }

    #[test]
    fn md5_context_default_equals_new() {
        let mut from_new = Md5Context::new();
        let mut from_default = Md5Context::default();
        from_new.update(b"abc");
        from_default.update(b"abc");
        assert_eq!(from_new.finalize(), from_default.finalize());
    }

    #[test]
    fn md5_context_clone_is_independent() {
        // Cloning mid-stream must capture the accumulated state, and the two
        // contexts must then evolve independently.
        let mut base = Md5Context::new();
        base.update(b"a");
        let mut forked = base.clone();
        base.update(b"bc");
        forked.update(b"bc");
        assert_eq!(base.finalize(), forked.finalize());
        assert_eq!(Md5Context::new().finalize(), md5it(b""));
    }

    #[cfg(feature = "ntlm")]
    #[test]
    fn md4_digest_length_constant() {
        assert_eq!(MD4_DIGEST_LENGTH, 16);
        assert_eq!(md4it(b"").len(), MD4_DIGEST_LENGTH);
    }

    #[cfg(feature = "ntlm")]
    #[test]
    fn md4_known_answer_empty() {
        // RFC 1320 test vector for the empty input (used by NTLM).
        assert_eq!(hex(&md4it(b"")), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[cfg(feature = "ntlm")]
    #[test]
    fn md4_known_answer_abc() {
        // RFC 1320 test vector for "abc".
        assert_eq!(hex(&md4it(b"abc")), "a448017aaf21d8525fc10ae87aa6729d");
    }
}
