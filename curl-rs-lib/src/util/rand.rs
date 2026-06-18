//! Random byte / hex / alphanumeric generation.
//!
//! This module is the memory-safe Rust replacement for libcurl's
//! `lib/rand.c` / `lib/rand.h`. It provides curl's internal randomness API,
//! used for MIME multipart boundaries (`lib/mime.c`), HTTP Digest and NTLM
//! `cnonce` values (`lib/vauth/*`), the WebSocket `Sec-WebSocket-Key`
//! (`lib/ws.c`), and other "unpredictable but not necessarily cryptographic"
//! needs throughout the transfer engine.
//!
//! # Public API and parity
//!
//! The C surface is reproduced with one deliberate simplification: the leading
//! `struct Curl_easy *data` parameter is **dropped**. In curl that pointer is
//! used only for trace logging and to dispatch to a TLS backend's RNG; in this
//! workspace randomness always comes from a single source (the OS CSPRNG via
//! the `rand` crate), so the parameter carries no information and is omitted.
//!
//! | C function           | Rust equivalent                              |
//! |----------------------|----------------------------------------------|
//! | `Curl_rand`          | [`rand_bytes`]                               |
//! | `Curl_rand_bytes`    | [`rand_bytes_env_override`]                  |
//! | `Curl_rand_hex`      | [`rand_hex`]                                 |
//! | `Curl_rand_alnum`    | [`rand_alnum`]                               |
//! | `Curl_win32_random`  | *out of scope* (Windows / Schannel only)     |
//!
//! Each function returns [`crate::error::Result<()>`], mirroring curl's
//! `CURLcode` return (success is `CURLE_OK`, i.e. `Ok(())`); the failure codes
//! reproduced here are `CURLE_BAD_FUNCTION_ARGUMENT` for misuse and
//! `CURLE_FAILED_INIT` if the OS entropy source cannot be read.
//!
//! # The `CURL_ENTROPY` deterministic test hook (test-suite parity, AAP G7)
//!
//! curl's regression suite must produce byte-identical MIME boundaries and
//! auth nonces across runs. To make that possible, curl ships a deterministic
//! generator gated on a *debug build* (`DEBUGBUILD`): when the `CURL_ENTROPY`
//! environment variable is set, the RNG becomes a fixed, repeatable sequence.
//! Many `tests/data` definitions set `CURL_ENTROPY=12345678` and assert exact
//! output, so reproducing this generator **bit-for-bit** is mandatory.
//!
//! This hook is mapped to Rust's `debug_assertions` cfg (the moral equivalent
//! of `DEBUGBUILD`): the entire deterministic path is compiled **only** in
//! debug builds and is completely absent from release artifacts — exactly as
//! the C code compiles it out of non-debug builds.
//!
//! ## Exact algorithm (matches the C source, *not* a paraphrase)
//!
//! The deterministic generator in `lib/rand.c` (`randit`, the
//! `getenv("CURL_ENTROPY")` branch) is an **incrementing counter**, not a
//! linear-congruential generator:
//!
//! 1. **Seed.** On the first draw, `seed` is a zero-initialized `unsigned int`;
//!    up to `sizeof(int)` (4) bytes of the env-var string are `memcpy`-ed into
//!    it, then `randseed = ntohl(seed)`. The combination of a host-order
//!    `memcpy` followed by `ntohl` is, on every host endianness, exactly
//!    [`u32::from_be_bytes`] of the first four env bytes (missing trailing
//!    bytes are zero). So `randseed = from_be_bytes([b0, b1, b2, b3])`.
//! 2. **Advance.** Every subsequent draw does `randseed++`. The produced
//!    sequence of 32-bit values is therefore `S, S+1, S+2, …` (wrapping).
//! 3. **Byte emission.** `Curl_rand_bytes` slices the buffer into chunks of up
//!    to four bytes; for each chunk it takes one 32-bit value and writes its
//!    bytes **least-significant-first** (`v & 0xFF`, `v >> 8`, …). That is the
//!    little-endian encoding of each value, applied front-to-back.
//!
//! This was empirically verified against two immutable test definitions with
//! `CURL_ENTROPY=12345678` (so `S = 0x3132_3334`):
//!
//! * `tests/data/test2301` expects `Sec-WebSocket-Key: NDMyMTUzMjE2MzIxNzMyMQ==`,
//!   whose base64 decodes to the 16 bytes `b"4321532163217321"` — exactly
//!   `S, S+1, S+2, S+3` little-endian (see the unit tests below).
//! * `tests/data/test1972` expects the multipart boundary random suffix
//!   `qrstuvwxyz0123456789AB` — exactly `alnum[(S+i) % 62]` for `i = 0..22`.
//!
//! The single static counter is process-global (as in C), so all of
//! [`rand_bytes`], [`rand_hex`] and [`rand_alnum`] draw from one shared
//! sequence within a run; the C test harness gives each curl invocation a fresh
//! process, re-seeding from `S` each time.
//!
//! # Memory safety
//!
//! This module contains **zero `unsafe`** and compiles cleanly under the
//! crate-wide `#![forbid(unsafe_code)]` (declared below as well, matching the
//! sibling `util` modules). The default randomness comes from the audited
//! pure-Rust `rand` crate (`rand::rngs::OsRng`); there is no `libc`/OS FFI,
//! no raw pointers, and no manual allocation.

#![forbid(unsafe_code)]

use crate::error::{CurlError, Result};
use rand::rngs::OsRng;
use rand::RngCore;

/// The alphabet used by [`rand_alnum`], in the **exact order** of curl's
/// `static const char alnum[]` in `lib/rand.c`.
///
/// The order (`A–Z`, then `a–z`, then `0–9`) is load-bearing: under the
/// `CURL_ENTROPY` deterministic hook the emitted character for a given draw is
/// `ALNUM[value % 62]`, so any reordering would change the bytes the test
/// suite observes.
const ALNUM: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Number of distinct alphanumeric symbols (`sizeof(alnum) - 1` in C).
const ALNUM_SPACE: u32 = ALNUM.len() as u32;

/// Lowercase hexadecimal digits, matching curl's `Curl_ldigits` table used by
/// `Curl_hexencode` (`lib/escape.c`). [`rand_hex`] therefore emits **lowercase**
/// hex, byte-for-byte identical to curl.
const LDIGITS: &[u8; 16] = b"0123456789abcdef";

// ---------------------------------------------------------------------------
// Deterministic `CURL_ENTROPY` generator — debug builds only.
//
// Mirrors the `getenv("CURL_ENTROPY")` branch of `randit` in `lib/rand.c`,
// which is itself gated on `DEBUGBUILD`. Mapping `DEBUGBUILD -> debug build`
// means this whole region is absent from release artifacts, exactly like the
// C `#ifdef DEBUGBUILD`.
// ---------------------------------------------------------------------------

/// Reads the `CURL_ENTROPY` environment variable, returning its bytes if set.
///
/// curl uses `getenv`, treating the value as raw bytes; for the ASCII values
/// the regression suite uses (e.g. `12345678`) this is equivalent to reading
/// the UTF-8 string and taking its bytes. Only the first four bytes ever
/// influence the seed.
#[cfg(debug_assertions)]
fn entropy_env() -> Option<Vec<u8>> {
    std::env::var("CURL_ENTROPY").ok().map(String::into_bytes)
}

/// Process-global state for the deterministic generator.
///
/// This is the Rust analogue of the function-local `static unsigned int
/// randseed; static bool seeded;` inside C's `randit`: a single counter shared
/// by every randomness draw in the process. `None` encodes "not yet seeded".
#[cfg(debug_assertions)]
mod env_state {
    use std::sync::Mutex;

    /// `None` until the first draw seeds it from `CURL_ENTROPY`.
    static SEED: Mutex<Option<u32>> = Mutex::new(None);

    /// Returns the next 32-bit value in the deterministic sequence.
    ///
    /// On the first call it seeds `randseed = from_be_bytes(first 4 env bytes,
    /// zero-padded)` and returns it; on every later call it returns
    /// `randseed = randseed.wrapping_add(1)` (C's `randseed++` on an
    /// `unsigned int`). See the module docs for the parity rationale.
    pub(super) fn next(force_entropy: &[u8]) -> u32 {
        // Recover from a poisoned lock rather than panicking: the protected
        // datum is a plain integer with no broken invariant.
        let mut guard = SEED.lock().unwrap_or_else(|e| e.into_inner());
        let value = match *guard {
            None => {
                let mut seed = [0u8; 4];
                let n = force_entropy.len().min(4);
                seed[..n].copy_from_slice(&force_entropy[..n]);
                u32::from_be_bytes(seed)
            }
            Some(prev) => prev.wrapping_add(1),
        };
        *guard = Some(value);
        value
    }

    /// Test-only: clear the seed so the next draw re-seeds from `S`.
    ///
    /// This emulates a fresh curl process (the C harness runs each test case in
    /// its own process, re-seeding from `S` every time), letting independent
    /// known-answer assertions each start from the documented sequence.
    #[cfg(test)]
    pub(super) fn reset() {
        *SEED.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

// ---------------------------------------------------------------------------
// Randomness primitives.
// ---------------------------------------------------------------------------

/// Fills `out` from the operating system's CSPRNG (`rand::rngs::OsRng`).
///
/// This is the default randomness source — the parity equivalent of curl's
/// `Curl_ssl_random` path (a build *with* a TLS backend, which this workspace
/// always is). A failure to read OS entropy is mapped to
/// [`CurlError::FailedInit`], matching the `CURLE_FAILED_INIT` that curl's
/// platform RNG helpers return on acquisition failure.
fn fill_os_random(out: &mut [u8]) -> Result<()> {
    OsRng.try_fill_bytes(out).map_err(|_| CurlError::FailedInit)
}

/// Produces a single 32-bit random value, honoring the `CURL_ENTROPY` hook in
/// debug builds.
///
/// Used by [`rand_alnum`], which (like C's `Curl_rand_alnum`) draws a full
/// 32-bit value per character for modulo-rejection sampling. In release builds
/// the deterministic branch is compiled out and this is always OS randomness.
fn next_random_u32(allow_env_override: bool) -> Result<u32> {
    #[cfg(debug_assertions)]
    {
        if allow_env_override {
            if let Some(force_entropy) = entropy_env() {
                return Ok(env_state::next(&force_entropy));
            }
        }
    }
    #[cfg(not(debug_assertions))]
    {
        // The override never exists in release; consume the argument so the
        // signature stays identical across build profiles.
        let _ = allow_env_override;
    }

    let mut buf = [0u8; 4];
    fill_os_random(&mut buf)?;
    // Native-endian reinterpretation mirrors C casting `&unsigned int` to
    // `unsigned char *`; for uniform random bytes the endianness is immaterial.
    Ok(u32::from_ne_bytes(buf))
}

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

/// Fills the entire `out` buffer with random bytes.
///
/// Parity with curl's `Curl_rand` macro (`Curl_rand_bytes(data, TRUE, …)` in
/// debug builds): the `CURL_ENTROPY` deterministic override is *enabled*, so in
/// a debug build with `CURL_ENTROPY` set this yields the fixed, repeatable byte
/// stream the regression suite depends on. In release builds it is always the
/// OS CSPRNG.
///
/// Returns [`CurlError::BadFunctionArgument`] for an empty buffer (matching
/// curl, where `Curl_rand_bytes` with `num == 0` returns
/// `CURLE_BAD_FUNCTION_ARGUMENT`), or [`CurlError::FailedInit`] if OS entropy
/// cannot be read.
///
/// # Examples
///
/// ```ignore
/// let mut key = [0u8; 16];
/// rand_bytes(&mut key)?;
/// ```
pub fn rand_bytes(out: &mut [u8]) -> Result<()> {
    rand_bytes_env_override(out, true)
}

/// Fills the entire `out` buffer with random bytes, explicitly choosing whether
/// the `CURL_ENTROPY` debug override is permitted.
///
/// This mirrors the full C signature `Curl_rand_bytes(data, allow_env_override,
/// rnd, num)` (with `data` dropped), for the rare caller that must force OS
/// randomness even in a debug build (`allow_env_override = false`). Most callers
/// want [`rand_bytes`], which passes `true`.
///
/// `allow_env_override` has no effect in release builds: the deterministic path
/// is compiled out entirely, so the OS CSPRNG is always used.
pub fn rand_bytes_env_override(out: &mut [u8], allow_env_override: bool) -> Result<()> {
    // C: `DEBUGASSERT(num);` followed by a `while(num)` loop whose `result`
    // starts as CURLE_BAD_FUNCTION_ARGUMENT — so a zero-length request returns
    // that code. Reproduce both the debug assert and the runtime error.
    debug_assert!(!out.is_empty(), "rand_bytes requires a non-empty buffer");
    if out.is_empty() {
        return Err(CurlError::BadFunctionArgument);
    }

    #[cfg(debug_assertions)]
    {
        if allow_env_override {
            if let Some(force_entropy) = entropy_env() {
                // Deterministic path. C's `Curl_rand_bytes` consumes one 32-bit
                // value per chunk of up to four bytes, writing each value
                // least-significant-byte-first, front-to-back. `chunks_mut(4)`
                // reproduces that chunking exactly (the final chunk may be < 4).
                for chunk in out.chunks_mut(4) {
                    let value = env_state::next(&force_entropy);
                    let bytes = value.to_le_bytes();
                    let take = chunk.len();
                    chunk.copy_from_slice(&bytes[..take]);
                }
                return Ok(());
            }
        }
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = allow_env_override;
    }

    fill_os_random(out)
}

/// Hex-encodes `src` into `out` as lowercase ASCII, NUL-terminated, exactly like
/// curl's `Curl_hexencode` (`lib/escape.c`).
///
/// Each input byte becomes two lowercase hex digits; encoding stops early if the
/// output buffer lacks room for another digit pair plus the terminator (the C
/// `olen >= 3` guard). A terminating NUL is always written when there is room.
fn hexencode(src: &[u8], out: &mut [u8]) {
    let olen = out.len();
    if !src.is_empty() && olen >= 3 {
        let mut oi = 0usize;
        for &byte in src {
            // Need two hex digits plus the trailing NUL (C: `olen >= 3`).
            if out.len() - oi < 3 {
                break;
            }
            out[oi] = LDIGITS[(byte >> 4) as usize];
            out[oi + 1] = LDIGITS[(byte & 0x0F) as usize];
            oi += 2;
        }
        out[oi] = 0;
    } else if olen > 0 {
        out[0] = 0;
    }
}

/// Fills `out` with `num - 1` random lowercase hex digits followed by a
/// terminating NUL; `num` must be **odd**.
///
/// Parity with curl's `Curl_rand_hex`. `num` is the total buffer size including
/// the NUL (as in C), so the caller must provide at least `num` bytes. The
/// number of random bytes consumed is `(num - 1) / 2`.
///
/// Returns [`CurlError::BadFunctionArgument`] if `num` is even or too large
/// (curl caps the work at a 128-byte internal buffer, i.e. `num / 2 >= 128`),
/// or if `out` is shorter than `num`.
///
/// # Examples
///
/// ```ignore
/// let mut buf = [0u8; 9];      // 8 hex digits + NUL
/// rand_hex(&mut buf, 9)?;
/// assert_eq!(buf[8], 0);
/// ```
pub fn rand_hex(out: &mut [u8], num: usize) -> Result<()> {
    // C uses `unsigned char buffer[128]` for the raw random bytes.
    const BUFFER: usize = 128;

    // C: `DEBUGASSERT(num > 1);`
    debug_assert!(num > 1, "rand_hex requires num > 1");

    // C: `if((num / 2 >= sizeof(buffer)) || !(num & 1)) return
    // CURLE_BAD_FUNCTION_ARGUMENT;` — must fit the buffer and be odd.
    if num / 2 >= BUFFER || (num & 1) == 0 {
        return Err(CurlError::BadFunctionArgument);
    }
    if out.len() < num {
        return Err(CurlError::BadFunctionArgument);
    }

    // C: `num--; Curl_rand(data, buffer, num / 2);` — number of raw bytes is
    // `(num - 1) / 2`. When `num == 1` this is zero, so the underlying fill
    // sees a zero-length request and returns CURLE_BAD_FUNCTION_ARGUMENT,
    // exactly as curl's `Curl_rand(buffer, 0)` does.
    let nbytes = (num - 1) / 2;
    let mut buffer = [0u8; BUFFER];
    rand_bytes(&mut buffer[..nbytes])?;

    // C: `Curl_hexencode(buffer, num / 2, rnd, num + 1);` where `num` is the
    // post-decrement value, i.e. the output window is the original `num` bytes.
    hexencode(&buffer[..nbytes], &mut out[..num]);
    Ok(())
}

/// Fills `out` with `num - 1` random alphanumeric characters (`[A-Za-z0-9]`)
/// followed by a terminating NUL.
///
/// Parity with curl's `Curl_rand_alnum`. As in C, each character is produced by
/// drawing a full 32-bit value and applying modulo-rejection sampling to avoid
/// modulo bias: values in `[UINT_MAX - (UINT_MAX % 62), UINT_MAX]` (the top four
/// values, `>= 0xFFFF_FFFC`) are rejected and redrawn, and the accepted value is
/// mapped through [`ALNUM`] as `ALNUM[value % 62]`. `num` is the total buffer
/// size including the NUL, so `out` must hold at least `num` bytes.
///
/// Returns [`CurlError::BadFunctionArgument`] for `num == 0` or if `out` is
/// shorter than `num`, or [`CurlError::FailedInit`] if OS entropy cannot be read.
///
/// # Examples
///
/// ```ignore
/// let mut boundary = [0u8; 23];  // 22 random chars + NUL (curl MIME boundary)
/// rand_alnum(&mut boundary, 23)?;
/// ```
pub fn rand_alnum(out: &mut [u8], num: usize) -> Result<()> {
    // Reject the top `UINT_MAX % 62` (== 3) values so that `% 62` is unbiased.
    // C: `while(r >= (UINT_MAX - UINT_MAX % alnumspace))`.
    const REJECT_AT: u32 = u32::MAX - (u32::MAX % ALNUM_SPACE);

    // C: `DEBUGASSERT(num > 1);`
    debug_assert!(num > 1, "rand_alnum requires num > 1");

    // `num == 0` would underflow C's `num--` into a near-infinite loop; reject
    // it. `num >= 1` then yields `count == num - 1` characters plus the NUL.
    if num == 0 {
        return Err(CurlError::BadFunctionArgument);
    }
    if out.len() < num {
        return Err(CurlError::BadFunctionArgument);
    }

    let count = num - 1;
    for slot in out.iter_mut().take(count) {
        // Modulo-rejection draw: redraw until the value is in the unbiased range.
        let value = loop {
            let candidate = next_random_u32(true)?;
            if candidate < REJECT_AT {
                break candidate;
            }
        };
        *slot = ALNUM[(value % ALNUM_SPACE) as usize];
    }
    out[count] = 0; // trailing NUL (C: `*rnd = 0;`)
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes all tests in this module. The `CURL_ENTROPY` environment
    /// variable and the deterministic counter are process-global, and Cargo
    /// runs tests on multiple threads by default; this lock keeps each test's
    /// view of that shared state isolated.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ---- default (OS CSPRNG) path -------------------------------------------

    #[test]
    fn rand_bytes_fills_whole_buffer_and_varies() {
        let _g = lock();
        std::env::remove_var("CURL_ENTROPY");

        // Two independent 32-byte draws must differ (collision probability is
        // ~2^-256), which also proves the whole buffer is written.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        rand_bytes(&mut a).expect("rand_bytes a");
        rand_bytes(&mut b).expect("rand_bytes b");
        assert_ne!(a, b, "two CSPRNG draws should differ");
    }

    #[test]
    fn rand_hex_is_lowercase_hex_with_nul() {
        let _g = lock();
        std::env::remove_var("CURL_ENTROPY");

        let num = 21; // 20 hex digits + NUL
        let mut buf = [0xFFu8; 21];
        rand_hex(&mut buf, num).expect("rand_hex");
        assert_eq!(buf[num - 1], 0, "must be NUL-terminated");
        for &c in &buf[..num - 1] {
            assert!(
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
                "non-lowercase-hex byte: {c:#x}"
            );
        }
    }

    #[test]
    fn rand_alnum_is_alnum_with_nul() {
        let _g = lock();
        std::env::remove_var("CURL_ENTROPY");

        let num = 23; // 22 alnum chars + NUL (curl MIME boundary length)
        let mut buf = [0xFFu8; 23];
        rand_alnum(&mut buf, num).expect("rand_alnum");
        assert_eq!(buf[num - 1], 0, "must be NUL-terminated");
        for &c in &buf[..num - 1] {
            assert!(c.is_ascii_alphanumeric(), "non-alphanumeric byte: {c:#x}");
            assert!(ALNUM.contains(&c), "byte not in ALNUM table: {c:#x}");
        }
    }

    // ---- error contracts (parity with curl's CURLcode returns) --------------

    // An empty buffer (curl's `num == 0`) trips `DEBUGASSERT(num)` in debug
    // builds — so this panics, matching curl's debug abort. In release the
    // runtime guard instead returns CURLE_BAD_FUNCTION_ARGUMENT (verified by the
    // release-gated test below). No shared state is touched before the assert,
    // so this test needs no serialization lock.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "rand_bytes requires a non-empty buffer")]
    fn rand_bytes_empty_debug_asserts() {
        let _ = rand_bytes(&mut []);
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn rand_bytes_empty_is_bad_argument() {
        let _g = lock();
        assert_eq!(rand_bytes(&mut []), Err(CurlError::BadFunctionArgument));
    }

    #[test]
    fn rand_hex_even_size_is_bad_argument() {
        let _g = lock();
        std::env::remove_var("CURL_ENTROPY");
        let mut buf = [0u8; 8];
        assert_eq!(rand_hex(&mut buf, 8), Err(CurlError::BadFunctionArgument));
    }

    #[test]
    fn rand_hex_too_large_is_bad_argument() {
        let _g = lock();
        std::env::remove_var("CURL_ENTROPY");
        // 257 is odd but 257 / 2 == 128 >= the 128-byte internal buffer.
        let mut buf = [0u8; 257];
        assert_eq!(rand_hex(&mut buf, 257), Err(CurlError::BadFunctionArgument));
    }

    // `num == 1` is odd and fits, but trips `DEBUGASSERT(num > 1)` in debug
    // builds. In release it consumes zero random bytes, so the underlying
    // zero-length fill returns CURLE_BAD_FUNCTION_ARGUMENT (curl's
    // `Curl_rand(buffer, 0)`).
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "rand_hex requires num > 1")]
    fn rand_hex_one_debug_asserts() {
        let mut buf = [0u8; 1];
        let _ = rand_hex(&mut buf, 1);
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn rand_hex_one_is_bad_argument() {
        let _g = lock();
        let mut buf = [0u8; 1];
        assert_eq!(rand_hex(&mut buf, 1), Err(CurlError::BadFunctionArgument));
    }

    // `num == 0` trips `DEBUGASSERT(num > 1)` in debug builds. In release the
    // explicit guard returns CURLE_BAD_FUNCTION_ARGUMENT (curl would underflow
    // `num--` into a near-infinite loop, which this rewrite refuses to do).
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "rand_alnum requires num > 1")]
    fn rand_alnum_zero_debug_asserts() {
        let mut buf = [0u8; 4];
        let _ = rand_alnum(&mut buf, 0);
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn rand_alnum_zero_is_bad_argument() {
        let _g = lock();
        let mut buf = [0u8; 4];
        assert_eq!(rand_alnum(&mut buf, 0), Err(CurlError::BadFunctionArgument));
    }

    // `num == 1` trips `DEBUGASSERT(num > 1)` in debug builds. In release it
    // writes only the terminating NUL (curl: `num--; while(0){} *rnd = 0;`).
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "rand_alnum requires num > 1")]
    fn rand_alnum_one_debug_asserts() {
        let mut buf = [0xFFu8; 1];
        let _ = rand_alnum(&mut buf, 1);
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn rand_alnum_one_writes_only_nul() {
        let _g = lock();
        let mut buf = [0xFFu8; 1];
        rand_alnum(&mut buf, 1).expect("rand_alnum(1)");
        assert_eq!(buf[0], 0);
    }

    // ---- hexencode helper ----------------------------------------------------

    #[test]
    fn hexencode_known_answer_lowercase() {
        let mut out = [0xFFu8; 5];
        hexencode(&[0xAB, 0xCD], &mut out);
        assert_eq!(&out, b"abcd\0");
    }

    #[test]
    fn hexencode_stops_when_output_too_small() {
        // Only room for one digit pair plus NUL: the second byte is dropped.
        let mut out = [0xFFu8; 3];
        hexencode(&[0x0F, 0xF0], &mut out);
        assert_eq!(&out, b"0f\0");
    }

    // ---- CURL_ENTROPY deterministic hook (debug builds only) ----------------
    //
    // These assert byte-for-byte parity with real curl, anchored to immutable
    // `tests/data` definitions. They exist only in debug builds, mirroring
    // curl's `#ifdef DEBUGBUILD` gate (and `cargo test` builds in debug).

    /// `tests/data/test2301`: with `CURL_ENTROPY=12345678`, curl's WebSocket
    /// handshake emits `Sec-WebSocket-Key: NDMyMTUzMjE2MzIxNzMyMQ==`, which
    /// base64-decodes to these 16 bytes. This is the canonical parity anchor
    /// for [`rand_bytes`].
    #[cfg(debug_assertions)]
    #[test]
    fn entropy_rand_bytes_matches_test2301() {
        let _g = lock();
        std::env::set_var("CURL_ENTROPY", "12345678");
        env_state::reset();

        let mut buf = [0u8; 16];
        rand_bytes(&mut buf).expect("deterministic rand_bytes");
        assert_eq!(&buf, b"4321532163217321");

        // Repeatable: a fresh "process" (reset) reproduces the identical stream.
        env_state::reset();
        let mut buf2 = [0u8; 16];
        rand_bytes(&mut buf2).expect("deterministic rand_bytes repeat");
        assert_eq!(buf, buf2);

        std::env::remove_var("CURL_ENTROPY");
    }

    /// `tests/data/test1972`: with `CURL_ENTROPY=12345678`, curl's multipart
    /// boundary random suffix is `qrstuvwxyz0123456789AB`. This is the parity
    /// anchor for [`rand_alnum`] (and confirms the full-`u32` draw and the
    /// exact [`ALNUM`] table order).
    #[cfg(debug_assertions)]
    #[test]
    fn entropy_rand_alnum_matches_test1972() {
        let _g = lock();
        std::env::set_var("CURL_ENTROPY", "12345678");
        env_state::reset();

        let mut buf = [0u8; 23]; // MIME_RAND_BOUNDARY_CHARS (22) + NUL
        rand_alnum(&mut buf, 23).expect("deterministic rand_alnum");
        assert_eq!(&buf[..22], b"qrstuvwxyz0123456789AB");
        assert_eq!(buf[22], 0);

        std::env::remove_var("CURL_ENTROPY");
    }

    /// Derived known-answer for [`rand_hex`] under the same seed: it consumes
    /// the first four bytes of the deterministic stream (`34 33 32 31`) and
    /// lowercase-hex-encodes them.
    #[cfg(debug_assertions)]
    #[test]
    fn entropy_rand_hex_known_answer() {
        let _g = lock();
        std::env::set_var("CURL_ENTROPY", "12345678");
        env_state::reset();

        let mut buf = [0u8; 9]; // 8 hex digits + NUL
        rand_hex(&mut buf, 9).expect("deterministic rand_hex");
        assert_eq!(&buf, b"34333231\0");

        std::env::remove_var("CURL_ENTROPY");
    }

    /// The shared counter advances across mixed calls within one "process":
    /// after consuming the first value via `rand_bytes`, the next `rand_bytes`
    /// continues the `S, S+1, …` sequence rather than restarting.
    #[cfg(debug_assertions)]
    #[test]
    fn entropy_counter_is_shared_and_monotonic() {
        let _g = lock();
        std::env::set_var("CURL_ENTROPY", "12345678");
        env_state::reset();

        // First 4-byte draw -> S = 0x31323334 little-endian.
        let mut first = [0u8; 4];
        rand_bytes(&mut first).expect("draw 1");
        assert_eq!(first, 0x3132_3334u32.to_le_bytes());

        // Next 4-byte draw -> S + 1.
        let mut second = [0u8; 4];
        rand_bytes(&mut second).expect("draw 2");
        assert_eq!(second, 0x3132_3335u32.to_le_bytes());

        std::env::remove_var("CURL_ENTROPY");
    }

    /// `allow_env_override = false` bypasses the deterministic hook even when
    /// `CURL_ENTROPY` is set, falling back to OS randomness.
    #[cfg(debug_assertions)]
    #[test]
    fn entropy_override_can_be_disabled() {
        let _g = lock();
        std::env::set_var("CURL_ENTROPY", "12345678");
        env_state::reset();

        let mut buf = [0u8; 16];
        rand_bytes_env_override(&mut buf, false).expect("forced OS randomness");
        // Overwhelmingly unlikely to equal the deterministic stream.
        assert_ne!(&buf, b"4321532163217321");

        std::env::remove_var("CURL_ENTROPY");
    }

    /// In release builds the `CURL_ENTROPY` hook is compiled out entirely
    /// (mirroring curl's non-`DEBUGBUILD` behavior), so even with the variable
    /// set the output is OS randomness rather than the deterministic stream a
    /// debug build would produce. This validates the compile-out at runtime.
    #[cfg(not(debug_assertions))]
    #[test]
    fn entropy_hook_is_compiled_out_in_release() {
        let _g = lock();
        std::env::set_var("CURL_ENTROPY", "12345678");

        let mut buf = [0u8; 16];
        rand_bytes(&mut buf).expect("rand_bytes");
        assert_ne!(&buf, b"4321532163217321");

        std::env::remove_var("CURL_ENTROPY");
    }
}
