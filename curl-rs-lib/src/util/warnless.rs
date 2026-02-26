//! Safe numeric type conversions replacing C `lib/curlx/warnless.c`.
//!
//! In C, the `curlx_*` functions in `warnless.c` suppress compiler warnings
//! when narrowing integers (e.g., `unsigned long` → `unsigned char`). Each
//! function casts the value and adds a `DEBUGASSERT` that fires in debug
//! builds if the value would be truncated.
//!
//! In Rust this module is **largely unnecessary** because the type system
//! already handles integer conversions safely via `as` (truncating), `TryFrom`
//! (checked), and the `From`/`Into` traits (widening). We provide these
//! convenience helpers for three reasons:
//!
//! 1. **Drop-in migration** — callers ported from C can use the same
//!    function-call pattern without sprinkling bare `as` casts everywhere.
//! 2. **Debug-build assertions** — the truncating variants include
//!    `debug_assert!` checks that mirror C's `DEBUGASSERT`, catching
//!    unexpected out-of-range values during testing.
//! 3. **Semantic clarity** — `usize_to_u8(len)` communicates intent more
//!    clearly than `len as u8` at the call site.
//!
//! # Function Categories
//!
//! | Category   | Behaviour                                     | Example             |
//! |------------|-----------------------------------------------|---------------------|
//! | Truncating | `debug_assert!` + `as` cast (mirrors C)       | [`usize_to_u8`]     |
//! | Checked    | returns `Option<T>` via `TryFrom`              | [`try_usize_to_u8`] |
//! | Clamping   | saturates to target range                      | [`clamp_to_u8`]     |
//! | Socket     | platform-specific fd/socket conversions         | [`fd_to_i32`]       |
//!
//! All functions are marked `#[inline]` so they compile to the same machine
//! code as a bare `as` cast in release builds.

// ---------------------------------------------------------------------------
// Phase 1 — Truncating conversions
// ---------------------------------------------------------------------------
// These match the C `curlx_*` functions: assert-in-debug, truncate-in-release.

/// Convert `usize` to `u8`, asserting the value fits in debug builds.
///
/// Matches C `curlx_ultouc(unsigned long) -> unsigned char`.
#[inline]
pub fn usize_to_u8(val: usize) -> u8 {
    debug_assert!(
        val <= u8::MAX as usize,
        "usize_to_u8: value {val} exceeds u8::MAX ({})",
        u8::MAX
    );
    val as u8
}

/// Convert `usize` to `u16`, asserting the value fits in debug builds.
///
/// Matches C `curlx_ultous(unsigned long) -> unsigned short` and
/// `curlx_sltous(long) -> unsigned short`.
#[inline]
pub fn usize_to_u16(val: usize) -> u16 {
    debug_assert!(
        val <= u16::MAX as usize,
        "usize_to_u16: value {val} exceeds u16::MAX ({})",
        u16::MAX
    );
    val as u16
}

/// Convert `usize` to `u32`, asserting the value fits in debug builds.
///
/// Matches C `curlx_uztoui(size_t) -> unsigned int`.
#[inline]
pub fn usize_to_u32(val: usize) -> u32 {
    debug_assert!(
        val <= u32::MAX as usize,
        "usize_to_u32: value {val} exceeds u32::MAX ({})",
        u32::MAX
    );
    val as u32
}

/// Convert `i64` to `i32`, asserting the value fits in debug builds.
///
/// Matches C `curlx_sltosi(long) -> int`.
#[inline]
pub fn i64_to_i32(val: i64) -> i32 {
    debug_assert!(
        val >= i32::MIN as i64 && val <= i32::MAX as i64,
        "i64_to_i32: value {val} outside i32 range [{}, {}]",
        i32::MIN,
        i32::MAX
    );
    val as i32
}

/// Convert `u64` to `usize`, asserting the value fits in debug builds.
///
/// On 64-bit platforms this is always a no-op; on 32-bit platforms the
/// assertion guards against truncation.
///
/// Matches C `curlx_uztoui(size_t) -> unsigned int` on 64-bit systems.
#[inline]
pub fn u64_to_usize(val: u64) -> usize {
    debug_assert!(
        val <= usize::MAX as u64,
        "u64_to_usize: value {val} exceeds usize::MAX ({})",
        usize::MAX
    );
    val as usize
}

/// Convert `usize` to `i32`, asserting the value fits in debug builds.
///
/// Matches C `curlx_uztosi(size_t) -> int`.
#[inline]
pub fn usize_to_i32(val: usize) -> i32 {
    debug_assert!(
        val <= i32::MAX as usize,
        "usize_to_i32: value {val} exceeds i32::MAX ({})",
        i32::MAX
    );
    val as i32
}

/// Convert `i64` to `usize`, asserting the value is non-negative in debug
/// builds.
///
/// Matches C `curlx_sotouz(curl_off_t) -> size_t`. In the C version
/// `curl_off_t` is a signed 64-bit integer, and the `DEBUGASSERT` checks
/// that the value is >= 0.
#[inline]
pub fn i64_to_usize(val: i64) -> usize {
    debug_assert!(
        val >= 0,
        "i64_to_usize: value {val} is negative"
    );
    // On 32-bit targets, also guard against exceeding usize::MAX.
    debug_assert!(
        (val as u64) <= usize::MAX as u64,
        "i64_to_usize: value {val} exceeds usize::MAX ({})",
        usize::MAX
    );
    val as usize
}

// ---------------------------------------------------------------------------
// Phase 2 — Checked (safe) conversions
// ---------------------------------------------------------------------------
// These use `TryFrom` internally and return `None` when the value is out of
// range, rather than truncating or panicking.

/// Checked conversion from `usize` to `u8`.
///
/// Returns `None` if `val > 255`.
#[inline]
pub fn try_usize_to_u8(val: usize) -> Option<u8> {
    u8::try_from(val).ok()
}

/// Checked conversion from `usize` to `u16`.
///
/// Returns `None` if `val > 65535`.
#[inline]
pub fn try_usize_to_u16(val: usize) -> Option<u16> {
    u16::try_from(val).ok()
}

/// Checked conversion from `usize` to `u32`.
///
/// Returns `None` if `val > u32::MAX` (possible on 64-bit platforms).
#[inline]
pub fn try_usize_to_u32(val: usize) -> Option<u32> {
    u32::try_from(val).ok()
}

/// Checked conversion from `i64` to `i32`.
///
/// Returns `None` if `val` is outside the `i32` range.
#[inline]
pub fn try_i64_to_i32(val: i64) -> Option<i32> {
    i32::try_from(val).ok()
}

// ---------------------------------------------------------------------------
// Phase 3 — Clamping conversions
// ---------------------------------------------------------------------------
// These saturate the value to the target type's range, guaranteeing a valid
// result without assertions or `Option` wrappers.

/// Clamp a `usize` into the `u8` range `[0, 255]`.
///
/// Values larger than 255 are clamped to 255.
#[inline]
pub fn clamp_to_u8(val: usize) -> u8 {
    if val > u8::MAX as usize {
        u8::MAX
    } else {
        val as u8
    }
}

/// Clamp a `usize` into the `u16` range `[0, 65535]`.
///
/// Values larger than 65535 are clamped to 65535.
#[inline]
pub fn clamp_to_u16(val: usize) -> u16 {
    if val > u16::MAX as usize {
        u16::MAX
    } else {
        val as u16
    }
}

/// Clamp an `i64` into the `i32` range `[i32::MIN, i32::MAX]`.
///
/// Matches the clamping variant of C's `curlx_sltosi` for cases where
/// silent saturation is preferred over assertion.
#[inline]
pub fn clamp_to_i32(val: i64) -> i32 {
    if val < i32::MIN as i64 {
        i32::MIN
    } else if val > i32::MAX as i64 {
        i32::MAX
    } else {
        val as i32
    }
}

/// Clamp an `i64` to a non-negative `usize`.
///
/// Negative values are clamped to `0`. On 32-bit targets, values exceeding
/// `usize::MAX` are clamped to `usize::MAX`.
#[inline]
pub fn clamp_to_usize(val: i64) -> usize {
    if val < 0 {
        0
    } else {
        let unsigned = val as u64;
        if unsigned > usize::MAX as u64 {
            usize::MAX
        } else {
            unsigned as usize
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 4 — Platform-specific socket / file-descriptor conversions
// ---------------------------------------------------------------------------
// On Unix, `RawFd` is `i32`, so both functions are effectively identity
// operations. On Windows, `RawSocket` is `usize` (SOCKET), which may need
// truncation or widening depending on pointer width.

/// Convert a Unix raw file descriptor to `i32`.
///
/// On Unix this is a no-op since `RawFd` is already `i32`.
/// Matches C `curlx_sktosi(curl_socket_t) -> int`.
#[cfg(unix)]
#[inline]
pub fn fd_to_i32(fd: std::os::unix::io::RawFd) -> i32 {
    // RawFd is i32 on all Unix-like platforms, so this is a direct pass-through.
    fd
}

/// Convert an `i32` back to a Unix raw file descriptor.
///
/// Matches C `curlx_sitosk(int) -> curl_socket_t`.
#[cfg(unix)]
#[inline]
pub fn i32_to_fd(val: i32) -> std::os::unix::io::RawFd {
    val
}

/// Convert a Windows `RawSocket` (SOCKET, which is `usize`) to `i32`.
///
/// On Windows, `SOCKET` is defined as `UINT_PTR` (pointer-sized unsigned).
/// The assertion catches 64-bit socket handles that don't fit in `i32`,
/// though in practice Windows socket values are small non-negative integers.
///
/// Matches C `curlx_sktosi(curl_socket_t) -> int`.
#[cfg(windows)]
#[inline]
pub fn fd_to_i32(fd: std::os::windows::io::RawSocket) -> i32 {
    debug_assert!(
        fd <= i32::MAX as std::os::windows::io::RawSocket,
        "fd_to_i32: RawSocket value {fd} exceeds i32::MAX"
    );
    fd as i32
}

/// Convert an `i32` to a Windows `RawSocket`.
///
/// Matches C `curlx_sitosk(int) -> curl_socket_t`.
#[cfg(windows)]
#[inline]
pub fn i32_to_fd(val: i32) -> std::os::windows::io::RawSocket {
    debug_assert!(
        val >= 0,
        "i32_to_fd: value {val} is negative, invalid for RawSocket"
    );
    val as std::os::windows::io::RawSocket
}

// Fallback for platforms that are neither Unix nor Windows (e.g., WASI, bare
// metal). Treats the "file descriptor" as a plain `i32`.
#[cfg(not(any(unix, windows)))]
#[inline]
pub fn fd_to_i32(fd: i32) -> i32 {
    fd
}

#[cfg(not(any(unix, windows)))]
#[inline]
pub fn i32_to_fd(val: i32) -> i32 {
    val
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Truncating conversions — in-range values
    // -----------------------------------------------------------------------

    #[test]
    fn test_usize_to_u8_in_range() {
        assert_eq!(usize_to_u8(0), 0u8);
        assert_eq!(usize_to_u8(127), 127u8);
        assert_eq!(usize_to_u8(255), 255u8);
    }

    #[test]
    fn test_usize_to_u16_in_range() {
        assert_eq!(usize_to_u16(0), 0u16);
        assert_eq!(usize_to_u16(65535), 65535u16);
    }

    #[test]
    fn test_usize_to_u32_in_range() {
        assert_eq!(usize_to_u32(0), 0u32);
        assert_eq!(usize_to_u32(u32::MAX as usize), u32::MAX);
    }

    #[test]
    fn test_i64_to_i32_in_range() {
        assert_eq!(i64_to_i32(0), 0i32);
        assert_eq!(i64_to_i32(-1), -1i32);
        assert_eq!(i64_to_i32(i32::MAX as i64), i32::MAX);
        assert_eq!(i64_to_i32(i32::MIN as i64), i32::MIN);
    }

    #[test]
    fn test_u64_to_usize_in_range() {
        assert_eq!(u64_to_usize(0), 0usize);
        assert_eq!(u64_to_usize(42), 42usize);
    }

    #[test]
    fn test_usize_to_i32_in_range() {
        assert_eq!(usize_to_i32(0), 0i32);
        assert_eq!(usize_to_i32(i32::MAX as usize), i32::MAX);
    }

    #[test]
    fn test_i64_to_usize_in_range() {
        assert_eq!(i64_to_usize(0), 0usize);
        assert_eq!(i64_to_usize(1000), 1000usize);
    }

    // -----------------------------------------------------------------------
    // Truncating conversions — debug_assert panics (debug builds only)
    // -----------------------------------------------------------------------

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "usize_to_u8")]
    fn test_usize_to_u8_overflow_debug() {
        let _ = usize_to_u8(256);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "usize_to_u16")]
    fn test_usize_to_u16_overflow_debug() {
        let _ = usize_to_u16(65536);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "usize_to_i32")]
    fn test_usize_to_i32_overflow_debug() {
        let _ = usize_to_i32((i32::MAX as usize) + 1);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "i64_to_i32")]
    fn test_i64_to_i32_overflow_debug() {
        let _ = i64_to_i32(i64::from(i32::MAX) + 1);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "i64_to_usize")]
    fn test_i64_to_usize_negative_debug() {
        let _ = i64_to_usize(-1);
    }

    // -----------------------------------------------------------------------
    // Checked (safe) conversions
    // -----------------------------------------------------------------------

    #[test]
    fn test_try_usize_to_u8() {
        assert_eq!(try_usize_to_u8(0), Some(0u8));
        assert_eq!(try_usize_to_u8(255), Some(255u8));
        assert_eq!(try_usize_to_u8(256), None);
        assert_eq!(try_usize_to_u8(usize::MAX), None);
    }

    #[test]
    fn test_try_usize_to_u16() {
        assert_eq!(try_usize_to_u16(0), Some(0u16));
        assert_eq!(try_usize_to_u16(65535), Some(65535u16));
        assert_eq!(try_usize_to_u16(65536), None);
    }

    #[test]
    fn test_try_usize_to_u32() {
        assert_eq!(try_usize_to_u32(0), Some(0u32));
        assert_eq!(try_usize_to_u32(u32::MAX as usize), Some(u32::MAX));
        // On 64-bit, values beyond u32::MAX should return None.
        #[cfg(target_pointer_width = "64")]
        assert_eq!(try_usize_to_u32(u32::MAX as usize + 1), None);
    }

    #[test]
    fn test_try_i64_to_i32() {
        assert_eq!(try_i64_to_i32(0), Some(0i32));
        assert_eq!(try_i64_to_i32(i32::MAX as i64), Some(i32::MAX));
        assert_eq!(try_i64_to_i32(i32::MIN as i64), Some(i32::MIN));
        assert_eq!(try_i64_to_i32(i64::from(i32::MAX) + 1), None);
        assert_eq!(try_i64_to_i32(i64::from(i32::MIN) - 1), None);
    }

    // -----------------------------------------------------------------------
    // Clamping conversions
    // -----------------------------------------------------------------------

    #[test]
    fn test_clamp_to_u8() {
        assert_eq!(clamp_to_u8(0), 0u8);
        assert_eq!(clamp_to_u8(200), 200u8);
        assert_eq!(clamp_to_u8(255), 255u8);
        assert_eq!(clamp_to_u8(256), 255u8);
        assert_eq!(clamp_to_u8(100_000), 255u8);
    }

    #[test]
    fn test_clamp_to_u16() {
        assert_eq!(clamp_to_u16(0), 0u16);
        assert_eq!(clamp_to_u16(65535), 65535u16);
        assert_eq!(clamp_to_u16(65536), 65535u16);
        assert_eq!(clamp_to_u16(1_000_000), 65535u16);
    }

    #[test]
    fn test_clamp_to_i32() {
        assert_eq!(clamp_to_i32(0), 0i32);
        assert_eq!(clamp_to_i32(100), 100i32);
        assert_eq!(clamp_to_i32(-100), -100i32);
        assert_eq!(clamp_to_i32(i32::MAX as i64), i32::MAX);
        assert_eq!(clamp_to_i32(i32::MIN as i64), i32::MIN);
        assert_eq!(clamp_to_i32(i64::from(i32::MAX) + 1), i32::MAX);
        assert_eq!(clamp_to_i32(i64::from(i32::MIN) - 1), i32::MIN);
        assert_eq!(clamp_to_i32(i64::MAX), i32::MAX);
        assert_eq!(clamp_to_i32(i64::MIN), i32::MIN);
    }

    #[test]
    fn test_clamp_to_usize() {
        assert_eq!(clamp_to_usize(0), 0usize);
        assert_eq!(clamp_to_usize(42), 42usize);
        assert_eq!(clamp_to_usize(-1), 0usize);
        assert_eq!(clamp_to_usize(-1_000_000), 0usize);
        assert_eq!(clamp_to_usize(i64::MIN), 0usize);
        assert_eq!(clamp_to_usize(1_000_000), 1_000_000usize);
    }

    // -----------------------------------------------------------------------
    // Socket conversions (Unix)
    // -----------------------------------------------------------------------

    #[test]
    #[cfg(unix)]
    fn test_fd_to_i32_and_back() {
        let fd: std::os::unix::io::RawFd = 42;
        let as_i32 = fd_to_i32(fd);
        assert_eq!(as_i32, 42i32);
        let back = i32_to_fd(as_i32);
        assert_eq!(back, 42);
    }

    #[test]
    #[cfg(unix)]
    fn test_fd_to_i32_negative() {
        // -1 is the conventional "invalid fd" sentinel.
        let fd: std::os::unix::io::RawFd = -1;
        assert_eq!(fd_to_i32(fd), -1i32);
        assert_eq!(i32_to_fd(-1), -1);
    }
}
