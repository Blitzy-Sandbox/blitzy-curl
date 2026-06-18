// curl-rs — a memory-safe Rust rewrite of curl / libcurl.
//
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// This software is licensed as described in the file COPYING, which you should
// have received as part of this distribution. The terms are also available at
// https://curl.se/docs/copyright.html.
//
// You may opt to use, copy, modify, merge, publish, distribute and/or sell
// copies of the Software, and permit persons to whom the Software is furnished
// to do so, under the terms of the COPYING file.
//
// This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
// KIND, either express or implied.
//
// SPDX-License-Identifier: curl

//! Millisecond ⇄ `timeval` time-difference conversions.
//!
//! This module is the Rust replacement for libcurl's `lib/curlx/timediff.c`
//! and `lib/curlx/timediff.h`. It provides the small, pure-arithmetic helpers
//! that translate between curl's millisecond *time-difference* representation
//! and a `struct timeval`-style seconds/microseconds pair ([`Timeval`]), plus
//! ergonomic bridges to [`std::time::Duration`] used throughout the
//! asynchronous core. It is a foundational leaf with no dependencies, consumed
//! by `crate::util::timeval`, the multi/transfer timeout logic, and the
//! connection code.
//!
//! # Relationship to the C original
//!
//! In curl, the time-difference type is `typedef curl_off_t timediff_t;` — a
//! signed 64-bit integer — so it is modeled here as [`i64`], with
//! [`TIMEDIFF_T_MAX`] / [`TIMEDIFF_T_MIN`] mirroring C's `TIMEDIFF_T_MAX` /
//! `TIMEDIFF_T_MIN` (`CURL_OFF_T_MAX` / `CURL_OFF_T_MIN`).
//!
//! The C `curlx_mstotv` converts a millisecond count into a `struct timeval`
//! whose `tv_sec` / `tv_usec` widths depend on the platform (`time_t` /
//! `suseconds_t`, `long` on Windows, or `int` elsewhere) and clamps `tv_sec`
//! to that platform maximum to avoid signed overflow. To sidestep
//! platform-specific `time_t` widths entirely, [`Timeval`] stores both fields
//! as [`i64`]. Because the seconds value is always `ms / 1000`, it can never
//! exceed [`i64::MAX`] for any [`i64`] input, so the platform `tv_sec` clamp
//! from the C original is a structural no-op in this representation.
//!
//! # No panics
//!
//! Every arithmetic operation here is exact, checked, or saturating, so — in
//! contrast to a naive translation that would panic on debug-mode integer
//! overflow — these helpers never panic for any input. This matches curl's
//! "never trap" behavior: a pathologically large input clamps (saturates)
//! rather than aborting.
//!
//! # Memory safety
//!
//! This module contains no `unsafe` code and compiles cleanly under the
//! crate-wide `#![forbid(unsafe_code)]` attribute mandated for the core crate.

use std::time::Duration;

/// Maximum value of curl's millisecond time-difference type.
///
/// Mirrors C's `TIMEDIFF_T_MAX` (`CURL_OFF_T_MAX`). curl defines the type as
/// `curl_off_t` (a signed 64-bit integer), so the maximum is [`i64::MAX`].
pub const TIMEDIFF_T_MAX: i64 = i64::MAX;

/// Minimum value of curl's millisecond time-difference type.
///
/// Mirrors C's `TIMEDIFF_T_MIN` (`CURL_OFF_T_MIN`), i.e. [`i64::MIN`].
pub const TIMEDIFF_T_MIN: i64 = i64::MIN;

/// Number of milliseconds in one second.
const MS_PER_SEC: i64 = 1_000;

/// Number of microseconds in one millisecond.
const US_PER_MS: i64 = 1_000;

/// A plain seconds + microseconds pair, mirroring C's `struct timeval`.
///
/// The C `struct timeval` uses `time_t tv_sec` and `suseconds_t tv_usec` (or
/// `long` / `int` depending on the platform). To avoid depending on the
/// platform width of `time_t`, both fields here are [`i64`]; this keeps
/// microsecond accuracy on every target and removes the signed-overflow
/// hazards the C code guards against with `#ifdef` clamps.
///
/// This is intentionally the *plain* timeval pair consumed by the millisecond
/// conversions in this module. The richer, monotonic clock type used for
/// elapsed-time measurement lives in `crate::util::timeval` (`CurlTime`); the
/// two types are complementary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Timeval {
    /// Whole seconds (C: `time_t tv_sec`).
    pub tv_sec: i64,
    /// Microseconds within the current second (C: `suseconds_t tv_usec`).
    ///
    /// For values produced by [`curlx_mstotv`] this is always in the range
    /// `0..=999_000` (millisecond granularity), but the field can hold any
    /// microsecond value a caller supplies.
    pub tv_usec: i64,
}

impl Timeval {
    /// Construct a [`Timeval`] from explicit seconds and microseconds.
    ///
    /// No normalization is performed; the values are stored verbatim, matching
    /// the C code's direct field assignment.
    #[must_use]
    pub const fn new(tv_sec: i64, tv_usec: i64) -> Self {
        Self { tv_sec, tv_usec }
    }
}

/// Convert a millisecond count into a [`Timeval`], writing into `tv`.
///
/// This mirrors the C `curlx_mstotv(struct timeval *tv, timediff_t ms)` pointer
/// idiom: the caller supplies the destination and receives a success flag.
///
/// # Returns
///
/// * `false` if `ms < 0` (the C "no timeout → blocking select" case, where the
///   original returns `NULL`); `tv` is left unmodified.
/// * `true` otherwise, with `tv` populated as:
///   * `ms == 0` → `tv_sec = 0, tv_usec = 0` (the "0ms timeout → polling"
///     case).
///   * `ms > 0`  → `tv_sec = ms / 1000`, `tv_usec = (ms % 1000) * 1000`
///     (so `tv_usec` is at most `999_000`).
///
/// # Overflow
///
/// All arithmetic is exact or saturating, so no input can cause a panic. In
/// the C original `tv_sec` is additionally clamped to the platform `time_t` /
/// `long` / `int` maximum; because [`Timeval`] models `tv_sec` as [`i64`]
/// (equal to [`TIMEDIFF_T_MAX`]) and the value is always `ms / 1000`, that
/// clamp can never trigger here and is therefore unnecessary.
pub fn curlx_mstotv_into(tv: &mut Timeval, ms: i64) -> bool {
    // ms < 0: matches the C `return NULL` branch (no timeout). Leave `tv`
    // untouched, exactly like the C function which never writes through the
    // pointer in this case.
    if ms < 0 {
        return false;
    }

    if ms > 0 {
        // Seconds: a non-negative dividend over a positive divisor can never
        // overflow, so this is exact and matches the C `ms / 1000`.
        tv.tv_sec = ms / MS_PER_SEC;
        // Microseconds: `ms % 1000` is in `0..=999` for `ms > 0`, so the
        // product is at most 999_000 and cannot overflow. `saturating_mul`
        // upholds the no-panic contract regardless of the operands.
        tv.tv_usec = (ms % MS_PER_SEC).saturating_mul(US_PER_MS);
    } else {
        // ms == 0: a 0ms timeout maps to an all-zero timeval (polling select).
        tv.tv_sec = 0;
        tv.tv_usec = 0;
    }

    true
}

/// Convert a millisecond count into a [`Timeval`], returning it by value.
///
/// This is the idiomatic Rust form of the C `curlx_mstotv`. Because the result
/// is returned by value, the C "`tv` pointer is `NULL`" failure mode does not
/// apply; only `ms < 0` yields [`None`]:
///
/// * `ms < 0`  → [`None`]
/// * `ms == 0` → `Some(Timeval { tv_sec: 0, tv_usec: 0 })`
/// * `ms > 0`  → `Some(Timeval { tv_sec: ms / 1000, tv_usec: (ms % 1000) * 1000 })`
///
/// For example, `1500` ms becomes `Timeval { tv_sec: 1, tv_usec: 500_000 }`.
#[must_use]
pub fn curlx_mstotv(ms: i64) -> Option<Timeval> {
    let mut tv = Timeval::default();
    if curlx_mstotv_into(&mut tv, ms) {
        Some(tv)
    } else {
        None
    }
}

/// Convert a [`Timeval`] into a millisecond count.
///
/// Mirrors the C `curlx_tvtoms`:
/// `return (tv->tv_sec * 1000) + (timediff_t)(tv->tv_usec / 1000);`
///
/// Unlike [`curlx_mstotv`], the seconds-to-milliseconds multiplication *can*
/// overflow [`i64`] for a very large `tv_sec`, so `saturating_mul` and
/// `saturating_add` are used: the result clamps at [`TIMEDIFF_T_MAX`] /
/// [`TIMEDIFF_T_MIN`] instead of panicking or wrapping. Sub-millisecond
/// microseconds are truncated by the integer division, exactly as in C.
#[must_use]
pub fn curlx_tvtoms(tv: &Timeval) -> i64 {
    tv.tv_sec
        .saturating_mul(MS_PER_SEC)
        .saturating_add(tv.tv_usec / US_PER_MS)
}

/// Convert a millisecond count into a [`std::time::Duration`].
///
/// Negative or zero inputs map to [`Duration::ZERO`] (a non-positive timeout),
/// consistent with [`curlx_mstotv`] treating `ms < 0` as "no wait" and
/// `ms == 0` as an immediately-elapsed interval. The multi/transfer timeout
/// code prefers this bridge over constructing an intermediate [`Timeval`].
#[must_use]
pub fn ms_to_duration(ms: i64) -> Duration {
    // `u64::try_from` rejects negatives (→ `ZERO`) and accepts the full
    // positive i64 range losslessly; `ms == 0` yields a zero `Duration` too.
    match u64::try_from(ms) {
        Ok(millis) => Duration::from_millis(millis),
        Err(_) => Duration::ZERO,
    }
}

/// Convert a [`std::time::Duration`] into a millisecond count, saturating.
///
/// The whole-millisecond component of `d` is returned. Durations longer than
/// [`i64::MAX`] milliseconds (roughly 292 million years) saturate to
/// [`TIMEDIFF_T_MAX`] rather than wrapping. This is the inverse of
/// [`ms_to_duration`] and is likewise preferred by the multi/transfer timeout
/// code.
#[must_use]
pub fn duration_to_ms(d: Duration) -> i64 {
    // `Duration::as_millis` returns a u128; clamp anything beyond i64::MAX.
    i64::try_from(d.as_millis()).unwrap_or(TIMEDIFF_T_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- curlx_mstotv -----------------------------------------------------

    #[test]
    fn mstotv_negative_returns_none() {
        // The C function returns NULL for ms < 0 ("no timeout → blocking").
        assert_eq!(curlx_mstotv(-1), None);
        assert_eq!(curlx_mstotv(-1_000), None);
        assert_eq!(curlx_mstotv(TIMEDIFF_T_MIN), None);
    }

    #[test]
    fn mstotv_zero_is_all_zero() {
        // ms == 0 → both fields zero ("0ms timeout → polling select").
        assert_eq!(
            curlx_mstotv(0),
            Some(Timeval {
                tv_sec: 0,
                tv_usec: 0
            })
        );
    }

    #[test]
    fn mstotv_basic_conversions() {
        // The canonical example from the specification.
        assert_eq!(
            curlx_mstotv(1500),
            Some(Timeval {
                tv_sec: 1,
                tv_usec: 500_000
            })
        );
        // 1 ms → 1000 us, no whole seconds.
        assert_eq!(
            curlx_mstotv(1),
            Some(Timeval {
                tv_sec: 0,
                tv_usec: 1_000
            })
        );
        // Exactly one second.
        assert_eq!(
            curlx_mstotv(1_000),
            Some(Timeval {
                tv_sec: 1,
                tv_usec: 0
            })
        );
        // Largest sub-second microsecond value (999 ms → 999_000 us).
        assert_eq!(
            curlx_mstotv(999),
            Some(Timeval {
                tv_sec: 0,
                tv_usec: 999_000
            })
        );
        // Multi-second with a fractional remainder.
        assert_eq!(
            curlx_mstotv(2_500),
            Some(Timeval {
                tv_sec: 2,
                tv_usec: 500_000
            })
        );
    }

    #[test]
    fn mstotv_usec_is_bounded_by_999000() {
        // tv_usec == (ms % 1000) * 1000, so it is always within [0, 999_000].
        for ms in [1_i64, 7, 13, 250, 999, 1_001, 123_456, 999_999_999] {
            let tv = curlx_mstotv(ms).expect("non-negative ms yields Some");
            assert!(tv.tv_usec >= 0, "ms={ms} produced negative usec");
            assert!(
                tv.tv_usec <= 999_000,
                "ms={ms} usec={} > 999_000",
                tv.tv_usec
            );
        }
    }

    #[test]
    fn mstotv_overflow_saturates_without_panic() {
        // i64::MAX must not panic. With the i64 model the split is exact:
        // tv_sec = MAX/1000, tv_usec = (MAX%1000)*1000, both well in range.
        let tv = curlx_mstotv(TIMEDIFF_T_MAX).expect("MAX is non-negative");
        assert_eq!(tv.tv_sec, TIMEDIFF_T_MAX / 1_000);
        assert_eq!(tv.tv_usec, (TIMEDIFF_T_MAX % 1_000) * 1_000);
        assert!(tv.tv_usec <= 999_000);
    }

    // ---- curlx_mstotv_into ------------------------------------------------

    #[test]
    fn mstotv_into_mirrors_pointer_idiom() {
        let mut tv = Timeval::new(42, 42);

        // Negative input: returns false and leaves `tv` untouched (like the C
        // function never writing through the pointer when it returns NULL).
        assert!(!curlx_mstotv_into(&mut tv, -5));
        assert_eq!(tv, Timeval::new(42, 42));

        // Zero input: returns true and zeroes both fields.
        assert!(curlx_mstotv_into(&mut tv, 0));
        assert_eq!(tv, Timeval::new(0, 0));

        // Positive input: returns true and populates the fields.
        assert!(curlx_mstotv_into(&mut tv, 3_210));
        assert_eq!(tv, Timeval::new(3, 210_000));
    }

    #[test]
    fn mstotv_into_agrees_with_by_value_form() {
        for ms in [-10_i64, -1, 0, 1, 999, 1_000, 1_500, 86_400_000] {
            let mut tv = Timeval::default();
            let ok = curlx_mstotv_into(&mut tv, ms);
            match curlx_mstotv(ms) {
                Some(expected) => {
                    assert!(ok, "ms={ms} should succeed");
                    assert_eq!(tv, expected, "ms={ms} field mismatch");
                }
                None => assert!(!ok, "ms={ms} should fail"),
            }
        }
    }

    // ---- curlx_tvtoms -----------------------------------------------------

    #[test]
    fn tvtoms_basic_conversions() {
        // The canonical example from the specification.
        assert_eq!(curlx_tvtoms(&Timeval::new(2, 500_000)), 2_500);
        assert_eq!(curlx_tvtoms(&Timeval::new(0, 0)), 0);
        assert_eq!(curlx_tvtoms(&Timeval::new(1, 0)), 1_000);
        // Sub-millisecond microseconds are truncated (matching C integer div).
        assert_eq!(curlx_tvtoms(&Timeval::new(0, 999)), 0);
        assert_eq!(curlx_tvtoms(&Timeval::new(0, 1_000)), 1);
        assert_eq!(curlx_tvtoms(&Timeval::new(0, 1_999)), 1);
    }

    #[test]
    fn tvtoms_saturates_without_panic() {
        // tv_sec * 1000 would overflow i64; saturating_mul clamps at MAX.
        assert_eq!(
            curlx_tvtoms(&Timeval::new(TIMEDIFF_T_MAX, 0)),
            TIMEDIFF_T_MAX
        );
        // The added microsecond term cannot push the result past MAX.
        assert_eq!(
            curlx_tvtoms(&Timeval::new(TIMEDIFF_T_MAX, 999_000)),
            TIMEDIFF_T_MAX
        );
        // Negative seconds saturate toward MIN.
        assert_eq!(
            curlx_tvtoms(&Timeval::new(TIMEDIFF_T_MIN, 0)),
            TIMEDIFF_T_MIN
        );
    }

    #[test]
    fn mstotv_tvtoms_round_trip_is_exact_for_whole_ms() {
        // Whole-millisecond inputs round-trip exactly through a Timeval.
        for ms in [0_i64, 1, 2, 500, 999, 1_000, 1_500, 1_234_567, 86_400_000] {
            let tv = curlx_mstotv(ms).expect("non-negative ms yields Some");
            assert_eq!(curlx_tvtoms(&tv), ms, "round trip failed for ms={ms}");
        }
    }

    // ---- Duration bridges -------------------------------------------------

    #[test]
    fn ms_to_duration_non_positive_is_zero() {
        assert_eq!(ms_to_duration(-1), Duration::ZERO);
        assert_eq!(ms_to_duration(TIMEDIFF_T_MIN), Duration::ZERO);
        assert_eq!(ms_to_duration(0), Duration::ZERO);
    }

    #[test]
    fn ms_to_duration_positive() {
        assert_eq!(ms_to_duration(1), Duration::from_millis(1));
        assert_eq!(ms_to_duration(1_500), Duration::from_millis(1_500));
        // The full positive i64 range converts losslessly.
        let max_u64 = u64::try_from(TIMEDIFF_T_MAX).expect("MAX fits in u64");
        assert_eq!(
            ms_to_duration(TIMEDIFF_T_MAX),
            Duration::from_millis(max_u64)
        );
    }

    #[test]
    fn duration_to_ms_basic_and_saturating() {
        assert_eq!(duration_to_ms(Duration::ZERO), 0);
        assert_eq!(duration_to_ms(Duration::from_millis(1_500)), 1_500);
        // Sub-millisecond is truncated to the whole-millisecond component.
        assert_eq!(duration_to_ms(Duration::from_micros(1_999)), 1);
        // Enormous durations saturate to MAX rather than wrapping or panicking.
        assert_eq!(
            duration_to_ms(Duration::from_secs(u64::MAX)),
            TIMEDIFF_T_MAX
        );
        assert_eq!(
            duration_to_ms(Duration::new(u64::MAX, 999_999_999)),
            TIMEDIFF_T_MAX
        );
    }

    #[test]
    fn duration_round_trip_is_exact_for_whole_ms() {
        for ms in [0_i64, 1, 250, 1_000, 1_500, 60_000, 3_600_000] {
            assert_eq!(
                duration_to_ms(ms_to_duration(ms)),
                ms,
                "duration round trip failed for ms={ms}"
            );
        }
    }

    // ---- Constants and the Timeval type -----------------------------------

    #[test]
    fn constants_match_curl_off_t_bounds() {
        assert_eq!(TIMEDIFF_T_MAX, i64::MAX);
        assert_eq!(TIMEDIFF_T_MIN, i64::MIN);
    }

    #[test]
    fn timeval_new_default_and_copy() {
        assert_eq!(
            Timeval::new(3, 4),
            Timeval {
                tv_sec: 3,
                tv_usec: 4
            }
        );
        assert_eq!(
            Timeval::default(),
            Timeval {
                tv_sec: 0,
                tv_usec: 0
            }
        );

        // `Timeval` is `Copy`: the original remains usable after a bind-copy.
        let a = Timeval::new(7, 8);
        let b = a;
        assert_eq!(a, b);
        assert_eq!(a.tv_sec, 7);
    }
}
