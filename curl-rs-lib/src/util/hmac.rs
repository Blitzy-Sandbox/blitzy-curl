//! HMAC (keyed-hash message authentication code).
//!
//! Rust rewrite of curl's `lib/hmac.c` / `lib/curl_hmac.h`, which provide a
//! single generic HMAC engine driven by a pluggable digest descriptor. This
//! module is the behavioral successor to curl's `Curl_hmacit()` one-shot helper
//! and the `Curl_HMAC_init` / `Curl_HMAC_update` / `Curl_HMAC_final` streaming
//! lifecycle. It is consumed by the authentication layer:
//!
//! * `auth::digest` — HTTP Digest with `qop` (the `H(A1)`/`H(A2)` response uses
//!   HMAC for the SHA variants),
//! * `auth::ntlm` — NTLMv2 response computation (`HMAC-MD5`),
//! * `auth::scram` — SASL SCRAM-SHA-256 (`HMAC-SHA-256`),
//! * `protocols::http::aws_sigv4` — AWS Signature Version 4 signing
//!   (`HMAC-SHA-256`, fed incrementally).
//!
//! # The HMAC construction (delegated, not hand-rolled)
//!
//! C's `lib/hmac.c` implements the classic RFC 2104 construction by hand:
//! `H((key ⊕ opad) || H((key ⊕ ipad) || message))`, where `ipad`/`opad` are the
//! `0x36`/`0x5C` block-fill bytes, keys longer than the hash block size are
//! first reduced by hashing, and shorter keys are zero-padded to the block size.
//! It expresses the pluggable digest as a `struct HMAC_params` vtable of
//! init/update/final function pointers plus the context size, the maximum key
//! length (the input block size) and the result length.
//!
//! This rewrite does **not** transliterate that math. The audited, pure-Rust
//! RustCrypto [`hmac`] crate already implements RFC 2104 correctly and is
//! generic over any [`digest`](hmac::digest)-compatible hash, so the entire
//! `HMAC_params` descriptor collapses to the type parameter of `Hmac<D>`. The
//! ipad/opad fill, the long-key reduction and the short-key padding are all
//! handled inside the crate; the block size and output size that the C struct
//! enumerated by hand are carried by the hash's associated types
//! (`BlockSizeUser` / `OutputSizeUser`). The two digests curl actually uses for
//! HMAC are MD5 and SHA-256, so this module exposes the two concrete
//! instantiations `Hmac<Md5>` and `Hmac<Sha256>` — the [`Md5`] and [`Sha256`]
//! hashers re-exported by the sibling [`crate::util::md5`] and
//! [`crate::util::sha256`] modules.
//!
//! Output parity with curl is therefore guaranteed by the standard: both curl
//! and this module compute RFC 2104 HMAC over RFC 1321 MD5 / FIPS 180-4
//! SHA-256, so the tags are byte-for-byte identical. The unit tests below pin
//! this against the RFC 2202 (HMAC-MD5) and RFC 4231 (HMAC-SHA-256)
//! known-answer vectors.
//!
//! # Surface
//!
//! Both a one-shot and an incremental form are provided for each digest,
//! mirroring the two C entry points:
//!
//! | C entry point                       | Rust equivalent                               |
//! |-------------------------------------|-----------------------------------------------|
//! | `Curl_hmacit` + `Curl_HMAC_MD5`     | [`hmac_md5`]                                   |
//! | `Curl_hmacit` + `Curl_HMAC_SHA256`  | [`hmac_sha256`]                               |
//! | `Curl_HMAC_init` (`Curl_HMAC_MD5`)  | [`HmacMd5Context::new`]                        |
//! | `Curl_HMAC_update`                  | [`HmacMd5Context::update`] / SHA-256 analog   |
//! | `Curl_HMAC_final`                   | [`HmacMd5Context::finalize`] / SHA-256 analog |
//!
//! The incremental contexts are required because Digest authentication and
//! SCRAM feed the MAC several discrete pieces rather than one contiguous buffer.
//!
//! No generic `hmacit<D>` helper is exposed. A digest-generic wrapper around
//! `Hmac<D>` would require threading a deep stack of `digest`/`crypto-common`
//! trait bounds (for example `D: CoreProxy` whose associated `D::Core` is in
//! turn `HashMarker`, `BlockSizeUser`, `FixedOutputCore`, `Default` and
//! `Clone`) through every call site for no practical benefit: curl uses HMAC
//! with exactly MD5 and SHA-256, both covered by the two concrete helpers
//! above. Keeping the surface concrete is the minimal-change choice and avoids
//! leaking RustCrypto's generic machinery into this crate's API.
//!
//! # Memory safety
//!
//! This module contains **zero** `unsafe` code and compiles cleanly under the
//! crate-wide `#![forbid(unsafe_code)]` declared at the `curl-rs-lib` crate root
//! (AAP §0.7.1). The `hmac` crate is itself pure-safe Rust, so none of curl's
//! historical raw-pointer defect classes are reintroduced. The heap context
//! that C's `Curl_HMAC_final` had to `free` is, here, owned state dropped
//! automatically; `finalize` consumes the context by value so the "one tag per
//! context" contract is enforced at compile time.
//!
//! [RustCrypto]: https://github.com/RustCrypto/MACs

// A module named `hmac` can still resolve the extern crate `hmac` here: within
// this module its own name is reachable only via `self`/`crate::util::hmac`, so
// a leading `hmac::` path segment binds to the external crate (verified to
// compile). `Mac` is the trait carrying `new_from_slice`/`update`/`finalize`.
use hmac::{Hmac, Mac};
// `InvalidLength` is re-exported by the `hmac` crate through its `digest`
// re-export, so importing it requires no additional direct dependency (the
// import whitelist for this file is the `hmac` crate plus the two sibling digest
// modules). It is the error type of `new_from_slice`; for HMAC it is never
// actually produced (HMAC imposes no key-length restriction), but the fallible
// signature is surfaced honestly by the incremental constructors below.
use hmac::digest::InvalidLength;

// Digest hashers re-exported by the sibling crypto modules. These are the only
// internal dependencies of this file (`depends_on_files`), and supplying the
// hashers this way means this module needs no direct dependency on `md-5` or
// `sha2`.
use crate::util::md5::Md5;
use crate::util::sha256::Sha256;

/// Length, in bytes, of an HMAC-MD5 tag.
///
/// Direct parity with the C macro `HMAC_MD5_LENGTH` from `lib/curl_hmac.h`.
/// HMAC's output length equals the underlying digest length, so this is the
/// 16-byte MD5 digest size.
pub const HMAC_MD5_LENGTH: usize = 16;

/// Length, in bytes, of an HMAC-SHA-256 tag.
///
/// The C header defined only `HMAC_MD5_LENGTH`; this is the SHA-256 analog,
/// equal to the 32-byte SHA-256 digest size. It is the result length carried by
/// the C `Curl_HMAC_SHA256` params table.
pub const HMAC_SHA256_LENGTH: usize = 32;

/// HMAC-MD5 instantiation: the RFC 2104 construction over MD5.
///
/// Replaces curl's `Curl_HMAC_MD5` `struct HMAC_params` descriptor — the digest
/// vtable collapses to this concrete type alias.
type HmacMd5 = Hmac<Md5>;

/// HMAC-SHA-256 instantiation: the RFC 2104 construction over SHA-256.
///
/// Replaces curl's `Curl_HMAC_SHA256` `struct HMAC_params` descriptor.
type HmacSha256 = Hmac<Sha256>;

/// Compute the HMAC-MD5 of `data` under `key` in a single call.
///
/// Parity replacement for C's `Curl_hmacit(&Curl_HMAC_MD5, key, keylen, data,
/// datalen, output)`. The C function wrote into a caller-supplied 16-byte buffer
/// and returned a `CURLcode`; the Rust API returns the tag by value.
///
/// `key` may be **any** length: HMAC reduces over-long keys by hashing and
/// zero-pads short keys to the block size, all inside the [`hmac`] crate. The
/// construction is consequently infallible — the only error the underlying
/// `new_from_slice` can name is [`InvalidLength`], which HMAC never produces (it
/// imposes no key-length limit). That impossibility is asserted with a single
/// [`expect`](Result::expect) carrying an explanatory message; it is provably
/// unreachable and is exercised across empty, short, block-sized and over-long
/// keys by the test suite, so this helper never panics in practice.
///
/// # Examples
///
/// ```ignore
/// // RFC 2202 HMAC-MD5 test case 1.
/// let key = [0x0b_u8; 16];
/// let tag = hmac_md5(&key, b"Hi There");
/// assert_eq!(tag.len(), HMAC_MD5_LENGTH);
/// ```
#[must_use]
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; HMAC_MD5_LENGTH] {
    // `new_from_slice` is infallible for HMAC (it accepts a key of any length);
    // the `Result` exists only because the `Mac::new_from_slice` signature is
    // shared with fixed-key MACs. See the function docs for why `expect` here
    // cannot fire.
    let mut mac = HmacMd5::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(data);
    finalize_md5(mac)
}

/// Compute the HMAC-SHA-256 of `data` under `key` in a single call.
///
/// Parity replacement for C's `Curl_hmacit(&Curl_HMAC_SHA256, …)`. As with
/// [`hmac_md5`], `key` may be any length and the construction is infallible; the
/// single [`expect`](Result::expect) guards a path HMAC never takes.
///
/// # Examples
///
/// ```ignore
/// // RFC 4231 HMAC-SHA-256 test case 1.
/// let key = [0x0b_u8; 20];
/// let tag = hmac_sha256(&key, b"Hi There");
/// assert_eq!(tag.len(), HMAC_SHA256_LENGTH);
/// ```
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; HMAC_SHA256_LENGTH] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(data);
    finalize_sha256(mac)
}

/// Finalize an HMAC-MD5 instance into a fixed-size array.
///
/// Copies the crate's `GenericArray` tag into a plain `[u8; 16]` via
/// `copy_from_slice` rather than a `From`/`Into` conversion on the generic-array
/// type; this keeps the code robust across `hmac`/`generic-array` versions and
/// requires no `unsafe`. The lengths are guaranteed equal — HMAC-MD5 always
/// emits [`HMAC_MD5_LENGTH`] bytes.
fn finalize_md5(mac: HmacMd5) -> [u8; HMAC_MD5_LENGTH] {
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; HMAC_MD5_LENGTH];
    out.copy_from_slice(&tag);
    out
}

/// Finalize an HMAC-SHA-256 instance into a fixed-size `[u8; 32]`.
///
/// See [`finalize_md5`] for the rationale behind the `copy_from_slice` pattern.
fn finalize_sha256(mac: HmacSha256) -> [u8; HMAC_SHA256_LENGTH] {
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; HMAC_SHA256_LENGTH];
    out.copy_from_slice(&tag);
    out
}

/// Incremental HMAC-MD5 context.
///
/// Parity replacement for curl's `struct HMAC_context` driven by the
/// `Curl_HMAC_MD5` params: [`new`](Self::new) primes the inner/outer pads with
/// the key, [`update`](Self::update) feeds the inner hash, and
/// [`finalize`](Self::finalize) completes both hashes and returns the tag. This
/// streaming form is what Digest authentication and SCRAM use, since they
/// authenticate several discrete pieces (method, URI, nonce, …) rather than one
/// contiguous buffer.
///
/// The context is [`Clone`] — cloning captures the exact intermediate MAC state,
/// which is useful when a common prefix must be finalized in more than one way.
/// Unlike the keyless [`crate::util::md5::Md5Context`], it has **no** `Default`
/// impl: an HMAC context is meaningless without a key.
#[derive(Clone)]
pub struct HmacMd5Context {
    /// The underlying RustCrypto HMAC-MD5 state (keyed pads + running inner hash).
    inner: HmacMd5,
}

impl HmacMd5Context {
    /// Create a fresh HMAC-MD5 context keyed with `key`.
    ///
    /// Parity with `Curl_HMAC_init(&Curl_HMAC_MD5, key, keylen)`. `key` may be
    /// any length. The return type is [`Result`] purely to honor the fallible
    /// `Mac::new_from_slice` signature *without* resorting to a panic: HMAC
    /// never actually rejects a key, so [`Ok`] is always returned, but exposing
    /// the [`Result`] lets callers use `?` and keeps this constructor free of
    /// any `unwrap`/`expect`.
    pub fn new(key: &[u8]) -> Result<Self, InvalidLength> {
        Ok(Self {
            inner: HmacMd5::new_from_slice(key)?,
        })
    }

    /// Feed another chunk of `data` into the running MAC.
    ///
    /// Parity with `Curl_HMAC_update`. May be called any number of times; the
    /// resulting tag is identical to authenticating the concatenation of all
    /// chunks in a single call.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Consume the context and return the final 16-byte HMAC-MD5 tag.
    ///
    /// Parity with `Curl_HMAC_final`. Taking `self` by value mirrors the C
    /// contract where the heap context was freed after the final call, making
    /// the "one tag per context" rule a compile-time guarantee.
    #[must_use]
    pub fn finalize(self) -> [u8; HMAC_MD5_LENGTH] {
        finalize_md5(self.inner)
    }
}

/// Incremental HMAC-SHA-256 context.
///
/// Parity replacement for curl's `struct HMAC_context` driven by the
/// `Curl_HMAC_SHA256` params. This is the form used by SASL SCRAM-SHA-256 and by
/// AWS Signature Version 4 signing, which authenticate a value assembled from
/// several pieces. See [`HmacMd5Context`] for the shared design notes (cloning,
/// the absence of `Default`, and the by-value [`finalize`](Self::finalize)).
#[derive(Clone)]
pub struct HmacSha256Context {
    /// The underlying RustCrypto HMAC-SHA-256 state.
    inner: HmacSha256,
}

impl HmacSha256Context {
    /// Create a fresh HMAC-SHA-256 context keyed with `key`.
    ///
    /// Parity with `Curl_HMAC_init(&Curl_HMAC_SHA256, key, keylen)`. See
    /// [`HmacMd5Context::new`] for why this returns [`Result`] yet never errors.
    pub fn new(key: &[u8]) -> Result<Self, InvalidLength> {
        Ok(Self {
            inner: HmacSha256::new_from_slice(key)?,
        })
    }

    /// Feed another chunk of `data` into the running MAC.
    ///
    /// Parity with `Curl_HMAC_update`.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Consume the context and return the final 32-byte HMAC-SHA-256 tag.
    ///
    /// Parity with `Curl_HMAC_final`.
    #[must_use]
    pub fn finalize(self) -> [u8; HMAC_SHA256_LENGTH] {
        finalize_sha256(self.inner)
    }
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
    fn length_constants() {
        assert_eq!(HMAC_MD5_LENGTH, 16);
        assert_eq!(HMAC_SHA256_LENGTH, 32);
        assert_eq!(hmac_md5(b"k", b"d").len(), HMAC_MD5_LENGTH);
        assert_eq!(hmac_sha256(b"k", b"d").len(), HMAC_SHA256_LENGTH);
    }

    #[test]
    fn rfc2202_hmac_md5_case1() {
        // RFC 2202 section 2, test case 1: key = 0x0b x16, data = "Hi There".
        // This is also exactly what curl's Curl_hmacit(&Curl_HMAC_MD5, …) emits.
        let key = [0x0b_u8; 16];
        assert_eq!(
            hex(&hmac_md5(&key, b"Hi There")),
            "9294727a3638bb1c13f48ef8158bfc9d"
        );
    }

    #[test]
    fn rfc2202_hmac_md5_case2_jefe() {
        // RFC 2202 section 2, test case 2: key = "Jefe" (shorter than the block,
        // so it is zero-padded by the construction).
        assert_eq!(
            hex(&hmac_md5(b"Jefe", b"what do ya want for nothing?")),
            "750c783e6ab0b503eaa86e310a5db738"
        );
    }

    #[test]
    fn rfc2202_hmac_md5_case6_long_key() {
        // RFC 2202 section 2, test case 6: key = 0xaa x80 (longer than the
        // 64-byte block, so it is first reduced by hashing).
        let key = [0xaa_u8; 80];
        assert_eq!(
            hex(&hmac_md5(
                &key,
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"
        );
    }

    #[test]
    fn rfc4231_hmac_sha256_case1() {
        // RFC 4231 section 4.2, test case 1: key = 0x0b x20, data = "Hi There".
        let key = [0x0b_u8; 20];
        assert_eq!(
            hex(&hmac_sha256(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn rfc4231_hmac_sha256_case2_jefe() {
        // RFC 4231 section 4.3, test case 2: key = "Jefe".
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn rfc4231_hmac_sha256_case6_long_key() {
        // RFC 4231 section 4.7, test case 6: key = 0xaa x131 (longer than the
        // 64-byte block, reduced by hashing first).
        let key = [0xaa_u8; 131];
        assert_eq!(
            hex(&hmac_sha256(
                &key,
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn incremental_md5_matches_one_shot() {
        // Feeding the message in pieces via the streaming context must equal the
        // one-shot tag, exercising the Curl_HMAC_update lifecycle used by Digest.
        let key = b"Jefe";
        let mut ctx = HmacMd5Context::new(key).expect("HMAC accepts any key length");
        ctx.update(b"what do ya want ");
        ctx.update(b"for nothing?");
        assert_eq!(
            ctx.finalize(),
            hmac_md5(key, b"what do ya want for nothing?")
        );
    }

    #[test]
    fn incremental_sha256_matches_one_shot() {
        let key = [0x0b_u8; 20];
        let mut ctx = HmacSha256Context::new(&key).expect("HMAC accepts any key length");
        ctx.update(b"Hi ");
        ctx.update(b"There");
        assert_eq!(ctx.finalize(), hmac_sha256(&key, b"Hi There"));
    }

    #[test]
    fn new_from_slice_is_infallible_for_all_key_lengths() {
        // HMAC imposes no key-length restriction: the constructors must return
        // Ok for empty, single-byte, block-sized (64 bytes for both MD5 and
        // SHA-256), and over-long keys. This proves the `expect` in the one-shot
        // helpers is unreachable.
        for len in [0_usize, 1, 16, 20, 32, 63, 64, 65, 128, 200] {
            let key = vec![0xab_u8; len];
            assert!(HmacMd5Context::new(&key).is_ok(), "MD5 key len {len}");
            assert!(
                HmacSha256Context::new(&key).is_ok(),
                "SHA-256 key len {len}"
            );
        }
    }

    #[test]
    fn context_clone_is_independent() {
        // Cloning mid-stream captures the accumulated MAC state; the two
        // contexts then evolve independently and converge on the same tag when
        // fed identical remaining input.
        let key = [0x0b_u8; 16];
        let mut base = HmacMd5Context::new(&key).expect("HMAC accepts any key length");
        base.update(b"Hi ");
        let mut forked = base.clone();
        base.update(b"There");
        forked.update(b"There");

        // `finalize` consumes the context, so capture the `Copy` tag arrays
        // first, then compare.
        let base_tag = base.finalize();
        let forked_tag = forked.finalize();
        assert_eq!(base_tag, forked_tag);

        // Both must also match the one-shot tag over the full message.
        assert_eq!(base_tag, hmac_md5(&key, b"Hi There"));
    }
}
