// SPDX-License-Identifier: curl
//
// Safe-Rust port of curl's `lib/curlx/warnless.c` / `lib/curlx/warnless.h`.
// The upstream C is consumed only as a behavioral oracle; this file is an
// idiomatic, memory-safe reimplementation rather than a line-by-line
// transliteration.

//! Warningless integer cast helpers — a memory-safe port of libcurl's
//! `lib/curlx/warnless.c` / `warnless.h`.
//!
//! In the C codebase these helpers exist to convert between integer widths
//! *without tripping compiler narrowing/conversion warnings*, while bounding
//! any out-of-range source value to the destination type's representable range
//! (the C code masks the value, guarded by `DEBUGASSERT`). In Rust the same
//! conversions are expressed safely and explicitly through [`TryFrom`] combined
//! with saturation (`unwrap_or(<MAX>)`) and [`Ord::clamp`]: there is no
//! `unsafe`, no raw-pointer arithmetic, and no possibility of undefined
//! behavior. This module therefore compiles cleanly under the crate-wide
//! `#![forbid(unsafe_code)]` declared in `curl-rs-lib/src/lib.rs`.
//!
//! The functions are retained as **parity shims**: ported call sites across the
//! crate (connection handling, DNS, buffer management, ...) reference them by
//! their exact upstream `curlx_*` names, so the names and the *observable*
//! saturating/clamping behavior are preserved verbatim even though every body
//! is now a safe one-liner. None of them can panic — out-of-range inputs
//! saturate (or, for the fallible predicates, return [`None`]) rather than
//! aborting the process.
//!
//! # C ↔ Rust type modeling
//!
//! The shims model curl's C integer types with the following Rust types, which
//! match the workspace's 64-bit LP64 targets (Linux `x86_64`/`aarch64`, macOS):
//!
//! | C type          | Rust type | Notes                          |
//! |-----------------|-----------|--------------------------------|
//! | `size_t`        | `usize`   | pointer-width unsigned         |
//! | `ssize_t`       | `isize`   | pointer-width signed           |
//! | `curl_off_t`    | `i64`     | curl's 64-bit file offset      |
//! | `int`           | `i32`     |                                |
//! | `unsigned int`  | `u32`     |                                |
//! | `long`          | `i64`     | LP64; see the caveat below     |
//! | `unsigned long` | `u64`     | LP64; see the caveat below     |
//!
//! On Windows (LLP64) and on ILP32 platforms, C `long` / `unsigned long` are
//! 32-bit. Those platforms are not part of the current build matrix; a caller
//! that requires an exact 32-bit `unsigned long` there should use
//! [`curlx_uztoui`] instead of [`curlx_uztoul`]. The [`TryFrom`]-based bodies
//! stay correct on any pointer width because they saturate rather than wrap.
//!
//! The three C predicates that returned `bool` while writing through a
//! `size_t *` out-parameter ([`curlx_sztouz`], [`curlx_sotouz_fits`],
//! [`curlx_sltouz`]) are mapped to the idiomatic `-> Option<usize>` form:
//! `Some(value)` replaces the C `true` (with the out-parameter written) and
//! [`None`] replaces the C `false` (which also set `*puznum = 0`). A caller that
//! needs the C "zero on failure" behavior can simply write `.unwrap_or(0)`.

// These helpers form a complete parity surface mirroring the upstream C cast
// inventory. During the staged C→Rust migration not every cast is exercised by
// a caller yet (and a few only fire on non-default target widths), so
// `dead_code` is allowed here to keep `clippy -D warnings` green regardless of
// how the surrounding `util` module is wired up. The set is intentionally
// complete so any ported call site can reference an upstream name without
// having to re-add a shim.
#![allow(dead_code)]

/// C `unsigned long` → `unsigned char`, saturating at [`u8::MAX`] (`0xff`).
///
/// Parity shim for C `curlx_ultouc`. Values larger than `0xff` clamp to `0xff`
/// rather than wrapping.
#[inline]
#[must_use]
pub fn curlx_ultouc(ulnum: u64) -> u8 {
    u8::try_from(ulnum).unwrap_or(u8::MAX)
}

/// C `size_t` → `int`, saturating at [`i32::MAX`] (the C `CURL_MASK_SINT`).
///
/// Parity shim for C `curlx_uztosi`.
#[inline]
#[must_use]
pub fn curlx_uztosi(uznum: usize) -> i32 {
    i32::try_from(uznum).unwrap_or(i32::MAX)
}

/// C `size_t` → `unsigned long` (modeled as [`u64`] on the LP64 targets).
///
/// Parity shim for C `curlx_uztoul`. On the workspace's 64-bit targets this is
/// a width-preserving widening that never loses data; the saturating fallback
/// exists only for completeness. See the module docs for the Windows / ILP32
/// 32-bit `unsigned long` caveat.
#[inline]
#[must_use]
pub fn curlx_uztoul(uznum: usize) -> u64 {
    u64::try_from(uznum).unwrap_or(u64::MAX)
}

/// C `size_t` → `unsigned int`, saturating at [`u32::MAX`] (C `CURL_MASK_UINT`).
///
/// Parity shim for C `curlx_uztoui`.
#[inline]
#[must_use]
pub fn curlx_uztoui(uznum: usize) -> u32 {
    u32::try_from(uznum).unwrap_or(u32::MAX)
}

/// C `long` → `int`, a saturating signed conversion (parity shim for
/// C `curlx_sltosi`).
///
/// In-range values — including negatives such as `-5` — are preserved exactly;
/// magnitudes beyond `i32` saturate to [`i32::MAX`] or [`i32::MIN`].
#[inline]
#[must_use]
pub fn curlx_sltosi(slnum: i64) -> i32 {
    i32::try_from(slnum).unwrap_or(if slnum < 0 { i32::MIN } else { i32::MAX })
}

/// C `long` → `unsigned int` (parity shim for C `curlx_sltoui`).
///
/// Negative inputs clamp to `0`; values above [`u32::MAX`] saturate to it.
#[inline]
#[must_use]
pub fn curlx_sltoui(slnum: i64) -> u32 {
    if slnum < 0 {
        0
    } else {
        u32::try_from(slnum).unwrap_or(u32::MAX)
    }
}

/// C `long` → `unsigned short` (parity shim for C `curlx_sltous`).
///
/// Negative inputs clamp to `0`; values above [`u16::MAX`] saturate to it.
#[inline]
#[must_use]
pub fn curlx_sltous(slnum: i64) -> u16 {
    if slnum < 0 {
        0
    } else {
        u16::try_from(slnum).unwrap_or(u16::MAX)
    }
}

/// C `size_t` → `ssize_t`, saturating at [`isize::MAX`] (C `CURL_MASK_SSIZE_T`).
///
/// Parity shim for C `curlx_uztosz`.
#[inline]
#[must_use]
pub fn curlx_uztosz(uznum: usize) -> isize {
    isize::try_from(uznum).unwrap_or(isize::MAX)
}

/// C `curl_off_t` → `size_t` (parity shim for C `curlx_sotouz`).
///
/// Negative inputs clamp to `0`; values that exceed `usize::MAX` (possible only
/// where `usize` is narrower than `i64`) saturate to [`usize::MAX`].
#[inline]
#[must_use]
pub fn curlx_sotouz(sonum: i64) -> usize {
    if sonum < 0 {
        0
    } else {
        usize::try_from(sonum).unwrap_or(usize::MAX)
    }
}

/// C `ssize_t` → `int`, a saturating signed conversion (parity shim for
/// C `curlx_sztosi`).
///
/// In-range values — including negatives — are preserved exactly; magnitudes
/// beyond `i32` saturate to [`i32::MAX`] or [`i32::MIN`].
#[inline]
#[must_use]
pub fn curlx_sztosi(sznum: isize) -> i32 {
    i32::try_from(sznum).unwrap_or(if sznum < 0 { i32::MIN } else { i32::MAX })
}

/// C `unsigned int` → `unsigned short`, saturating at [`u16::MAX`]
/// (C `CURL_MASK_USHORT`). Parity shim for C `curlx_uitous`.
#[inline]
#[must_use]
pub fn curlx_uitous(uinum: u32) -> u16 {
    u16::try_from(uinum).unwrap_or(u16::MAX)
}

/// C `int` → `size_t` (parity shim for C `curlx_sitouz`).
///
/// Negative inputs clamp to `0`. Non-negative inputs always fit a `usize` on
/// the supported targets.
#[inline]
#[must_use]
pub fn curlx_sitouz(sinum: i32) -> usize {
    if sinum < 0 {
        0
    } else {
        usize::try_from(sinum).unwrap_or(usize::MAX)
    }
}

/// C `unsigned int` → `size_t`, an always-fits widening (parity shim for
/// C `curlx_uitouz`).
#[inline]
#[must_use]
pub fn curlx_uitouz(uinum: u32) -> usize {
    usize::try_from(uinum).unwrap_or(usize::MAX)
}

/// C `curl_off_t` → `size_t`, clamped into the inclusive interval
/// `[uzmin, uzmax]` (parity shim for C `curlx_sotouz_range`).
///
/// Mirrors curl's `CURLMIN(CURLMAX((size_t)sonum, uzmin), uzmax)`:
/// * a negative `sonum` yields `uzmin` (the lower bound);
/// * a `sonum` that does not fit in `usize` (only possible on targets where
///   `usize` is narrower than `i64`) yields `uzmax` (the upper bound);
/// * otherwise the value is clamped into `[uzmin, uzmax]`.
#[inline]
#[must_use]
pub fn curlx_sotouz_range(sonum: i64, uzmin: usize, uzmax: usize) -> usize {
    // Negative offsets map to the lower bound, matching C's `if(sonum < 0)`.
    if sonum < 0 {
        return uzmin;
    }
    // On targets where `usize` is narrower than `curl_off_t`, a value that is
    // in range for C can still exceed `usize::MAX`; saturating to `usize::MAX`
    // makes the clamp below resolve to `uzmax`, matching C's `sonum > SIZE_MAX`.
    let value = usize::try_from(sonum).unwrap_or(usize::MAX);
    // `usize::clamp` panics when `uzmin > uzmax`. curl's nested min/max instead
    // yields `uzmax` in that degenerate case, so handle it explicitly here to
    // keep this shim panic-free for every input.
    if uzmin > uzmax {
        return uzmax;
    }
    value.clamp(uzmin, uzmax)
}

/// C `size_t` → `curl_off_t`, returning [`i64::MAX`] (C `CURL_OFF_T_MAX`) when
/// the value exceeds it. Parity shim for C `curlx_uztoso`.
#[inline]
#[must_use]
pub fn curlx_uztoso(uznum: usize) -> i64 {
    i64::try_from(uznum).unwrap_or(i64::MAX)
}

/// C `ssize_t` → `size_t` (parity shim for C `curlx_sztouz`).
///
/// Returns `Some(value)` when `sznum` is non-negative (the C `true` case that
/// wrote `*puznum`), or [`None`] when it is negative (the C `false` case that
/// set `*puznum = 0`).
#[inline]
#[must_use]
pub fn curlx_sztouz(sznum: isize) -> Option<usize> {
    usize::try_from(sznum).ok()
}

/// C `curl_off_t` → `size_t` (parity shim for C `curlx_sotouz_fits`).
///
/// Returns `Some(value)` when `sonum` is non-negative and fits a `usize`, or
/// [`None`] when it is negative or too large (the C `false` / `*puznum = 0`
/// case).
#[inline]
#[must_use]
pub fn curlx_sotouz_fits(sonum: i64) -> Option<usize> {
    usize::try_from(sonum).ok()
}

/// C `long` → `size_t` (parity shim for C `curlx_sltouz`).
///
/// Returns `Some(value)` when `slnum` is non-negative and fits a `usize`, or
/// [`None`] otherwise (the C `false` / `*puznum = 0` case).
#[inline]
#[must_use]
pub fn curlx_sltouz(slnum: i64) -> Option<usize> {
    usize::try_from(slnum).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ultouc_saturates_at_0xff() {
        assert_eq!(curlx_ultouc(0), 0);
        assert_eq!(curlx_ultouc(0xfe), 0xfe);
        assert_eq!(curlx_ultouc(0xff), 0xff);
        assert_eq!(curlx_ultouc(0x100), u8::MAX); // 256 saturates to 255
        assert_eq!(curlx_ultouc(u64::MAX), u8::MAX);
    }

    #[test]
    fn uztosi_saturates_at_i32_max() {
        assert_eq!(curlx_uztosi(0), 0);
        assert_eq!(curlx_uztosi(123), 123);
        let i32_max_as_usize = usize::try_from(i32::MAX).unwrap();
        assert_eq!(curlx_uztosi(i32_max_as_usize), i32::MAX);
        assert_eq!(curlx_uztosi(usize::MAX), i32::MAX);
    }

    #[test]
    fn uztoul_widens() {
        assert_eq!(curlx_uztoul(0), 0_u64);
        assert_eq!(curlx_uztoul(42), 42_u64);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(curlx_uztoul(usize::MAX), u64::MAX);
    }

    #[test]
    fn uztoui_saturates_at_u32_max() {
        assert_eq!(curlx_uztoui(0), 0);
        assert_eq!(curlx_uztoui(123), 123);
        assert_eq!(curlx_uztoui(usize::MAX), u32::MAX);
    }

    #[test]
    fn sltosi_is_a_saturating_signed_cast() {
        assert_eq!(curlx_sltosi(0), 0);
        assert_eq!(curlx_sltosi(-5), -5); // in-range negatives preserved
        assert_eq!(curlx_sltosi(123), 123);
        assert_eq!(curlx_sltosi(i64::from(i32::MAX)), i32::MAX);
        assert_eq!(curlx_sltosi(i64::from(i32::MAX) + 1), i32::MAX);
        assert_eq!(curlx_sltosi(i64::from(i32::MIN)), i32::MIN);
        assert_eq!(curlx_sltosi(i64::from(i32::MIN) - 1), i32::MIN);
    }

    #[test]
    fn sltoui_clamps_negatives_and_overflow() {
        assert_eq!(curlx_sltoui(-1), 0);
        assert_eq!(curlx_sltoui(i64::MIN), 0);
        assert_eq!(curlx_sltoui(0), 0);
        assert_eq!(curlx_sltoui(123), 123);
        assert_eq!(curlx_sltoui(i64::from(u32::MAX)), u32::MAX);
        assert_eq!(curlx_sltoui(i64::from(u32::MAX) + 1), u32::MAX);
    }

    #[test]
    fn sltous_clamps_negatives_and_overflow() {
        assert_eq!(curlx_sltous(-1), 0);
        assert_eq!(curlx_sltous(0), 0);
        assert_eq!(curlx_sltous(65_534), 65_534);
        assert_eq!(curlx_sltous(65_535), u16::MAX);
        assert_eq!(curlx_sltous(65_536), u16::MAX);
        assert_eq!(curlx_sltous(1_000_000), u16::MAX);
    }

    #[test]
    fn uztosz_saturates_at_isize_max() {
        assert_eq!(curlx_uztosz(0), 0);
        assert_eq!(curlx_uztosz(123), 123);
        assert_eq!(curlx_uztosz(usize::MAX), isize::MAX);
    }

    #[test]
    fn sotouz_clamps_negatives_to_zero() {
        assert_eq!(curlx_sotouz(-5), 0);
        assert_eq!(curlx_sotouz(i64::MIN), 0);
        assert_eq!(curlx_sotouz(0), 0);
        assert_eq!(curlx_sotouz(123), 123);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(curlx_sotouz(i64::MAX), usize::try_from(i64::MAX).unwrap());
    }

    #[test]
    fn sztosi_is_a_saturating_signed_cast() {
        assert_eq!(curlx_sztosi(0), 0);
        assert_eq!(curlx_sztosi(-5), -5);
        assert_eq!(curlx_sztosi(123), 123);
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(curlx_sztosi(isize::MAX), i32::MAX);
            assert_eq!(curlx_sztosi(isize::MIN), i32::MIN);
        }
    }

    #[test]
    fn uitous_saturates_at_u16_max() {
        assert_eq!(curlx_uitous(0), 0);
        assert_eq!(curlx_uitous(65_535), u16::MAX);
        assert_eq!(curlx_uitous(65_536), u16::MAX);
        assert_eq!(curlx_uitous(u32::MAX), u16::MAX);
    }

    #[test]
    fn sitouz_clamps_negatives_to_zero() {
        assert_eq!(curlx_sitouz(-1), 0);
        assert_eq!(curlx_sitouz(i32::MIN), 0);
        assert_eq!(curlx_sitouz(0), 0);
        assert_eq!(curlx_sitouz(12_345), 12_345);
        assert_eq!(curlx_sitouz(i32::MAX), usize::try_from(i32::MAX).unwrap());
    }

    #[test]
    fn uitouz_widens() {
        assert_eq!(curlx_uitouz(0), 0);
        assert_eq!(curlx_uitouz(42), 42);
        assert_eq!(curlx_uitouz(u32::MAX), usize::try_from(u32::MAX).unwrap());
    }

    #[test]
    fn sotouz_range_clamps_into_interval() {
        // Negative input -> lower bound.
        assert_eq!(curlx_sotouz_range(-5, 10, 20), 10);
        // Below the interval -> lower bound.
        assert_eq!(curlx_sotouz_range(5, 10, 20), 10);
        // Inside the interval -> unchanged.
        assert_eq!(curlx_sotouz_range(15, 10, 20), 15);
        // Exactly on the bounds.
        assert_eq!(curlx_sotouz_range(10, 10, 20), 10);
        assert_eq!(curlx_sotouz_range(20, 10, 20), 20);
        // Above the interval -> upper bound.
        assert_eq!(curlx_sotouz_range(25, 10, 20), 20);
        // Degenerate uzmin > uzmax must NOT panic and yields uzmax (curl parity).
        assert_eq!(curlx_sotouz_range(15, 20, 10), 10);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(curlx_sotouz_range(i64::MAX, 0, 100), 100);
    }

    #[test]
    fn uztoso_saturates_at_i64_max() {
        assert_eq!(curlx_uztoso(0), 0);
        assert_eq!(curlx_uztoso(123), 123);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(curlx_uztoso(usize::MAX), i64::MAX);
    }

    #[test]
    fn sztouz_maps_negative_to_none() {
        assert_eq!(curlx_sztouz(-1), None);
        assert_eq!(curlx_sztouz(isize::MIN), None);
        assert_eq!(curlx_sztouz(0), Some(0));
        assert_eq!(curlx_sztouz(50), Some(50));
        assert_eq!(
            curlx_sztouz(isize::MAX),
            Some(usize::try_from(isize::MAX).unwrap())
        );
    }

    #[test]
    fn sotouz_fits_maps_out_of_range_to_none() {
        assert_eq!(curlx_sotouz_fits(-1), None);
        assert_eq!(curlx_sotouz_fits(i64::MIN), None);
        assert_eq!(curlx_sotouz_fits(0), Some(0));
        assert_eq!(curlx_sotouz_fits(100), Some(100));
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            curlx_sotouz_fits(i64::MAX),
            Some(usize::try_from(i64::MAX).unwrap())
        );
        // On a 32-bit `usize`, i64::MAX does not fit and must yield None.
        #[cfg(target_pointer_width = "32")]
        assert_eq!(curlx_sotouz_fits(i64::MAX), None);
    }

    #[test]
    fn sltouz_maps_negative_to_none() {
        assert_eq!(curlx_sltouz(-1), None);
        assert_eq!(curlx_sltouz(i64::MIN), None);
        assert_eq!(curlx_sltouz(0), Some(0));
        assert_eq!(curlx_sltouz(123), Some(123));
    }
}
