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

//! Monotonic clock ([`CurlTime`]) and time-difference helpers.
//!
//! This module is the Rust replacement for libcurl's `lib/curlx/timeval.c` and
//! `lib/curlx/timeval.h` — curl's portable *monotonic-clock* abstraction
//! (`struct curltime`) together with the time-difference helpers used for
//! timeouts, progress timing, and the splay-tree timer keys in the async core.
//!
//! # Relationship to the C original
//!
//! curl models a point in time as
//!
//! ```c
//! struct curltime {
//!   time_t tv_sec;  /* seconds */
//!   int    tv_usec; /* microseconds */
//! };
//! ```
//!
//! and obtains "now" from a **monotonic** clock source —
//! `clock_gettime(CLOCK_MONOTONIC[_RAW])` on Linux, `QueryPerformanceCounter`
//! on Windows, `mach_absolute_time()` on older macOS. The Rust port mirrors the
//! field shape in [`CurlTime`] (with `tv_sec` widened to [`i64`] so the type is
//! identical on every target, and `tv_usec` kept as [`i32`] to match the C
//! `int` width) and obtains "now" from [`std::time::Instant`], the standard
//! library's monotonic clock — so there is **no `clock_gettime` FFI** and the
//! module compiles cleanly under `#![forbid(unsafe_code)]`.
//!
//! ## Monotonic, not wall-clock
//!
//! [`curlx_now`] returns a value that only ever moves **forward**; it is
//! suitable for measuring *elapsed* time but **not** for display or for
//! deriving a calendar date. The origin is an arbitrary, process-stable point
//! (the first time the clock is observed), exactly like the unspecified epoch of
//! `CLOCK_MONOTONIC`. Wall-clock breakdown — turning a Unix timestamp into a
//! broken-down UTC date — is a *separate* concern provided by [`curlx_gmtime`]
//! (backed by `chrono`); for the current wall-clock instant, callers elsewhere
//! use `chrono::Utc::now()`, never [`curlx_now`].
//!
//! # Difference helpers
//!
//! [`curlx_timediff`] (milliseconds), [`curlx_timediff_us`] (microseconds), and
//! [`curlx_timediff_ceil_ms`] (milliseconds, rounded up) reproduce the exact
//! arithmetic and overflow-clamping of their C counterparts
//! (`curlx_timediff_ms`, `curlx_timediff_us`, `curlx_timediff_ceil_ms`),
//! including the "for too large diffs return the max/min value" behavior. The
//! C-named aliases ([`curlx_timediff_ms`]) and the pointer-style forms
//! ([`curlx_ptimediff_ms`] / [`curlx_ptimediff_us`]) are provided as thin
//! wrappers so call sites translated directly from the C tree keep working.
//!
//! All time-difference results use the signed 64-bit [`i64`] type — the Rust
//! image of curl's `timediff_t` (`curl_off_t`) — and reuse the
//! [`TIMEDIFF_T_MAX`] / [`TIMEDIFF_T_MIN`] saturation bounds defined by the
//! sibling [`crate::util::timediff`] module.
//!
//! # No panics
//!
//! Every operation here is checked or saturating: `curlx_now` uses
//! [`Instant::saturating_duration_since`] (never panics, never goes backward),
//! and the difference helpers use `saturating_*` arithmetic and the same
//! overflow guards as the C original. No input can cause a panic, matching
//! curl's "never trap" contract.
//!
//! # Memory safety
//!
//! This module contains no `unsafe` code and compiles under the crate-wide and
//! module-level `#![forbid(unsafe_code)]` mandated for the core crate.

// The monotonic clock and the full C-header surface (the `_ms` aliases and the
// pointer-style `curlx_ptimediff_*` forms) are part of this leaf utility's
// public API, consumed by the multi/transfer/connection layers and `splay.rs`.
// As in the sibling `curlx/` ports (`strerror.rs`, `strparse.rs`,
// `warnless.rs`), the surface is authored in full here even before every call
// site lands, so `dead_code` is allowed for this foundational module.
#![allow(dead_code)]
#![forbid(unsafe_code)]

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use crate::util::timediff::{TIMEDIFF_T_MAX, TIMEDIFF_T_MIN};

/// Milliseconds per second.
const MS_PER_SEC: i64 = 1_000;

/// Microseconds per second.
const US_PER_SEC: i64 = 1_000_000;

/// Microseconds per millisecond.
const US_PER_MS: i64 = 1_000;

/// A monotonic point in time, mirroring C's `struct curltime`.
///
/// This is the Rust image of
///
/// ```c
/// struct curltime { time_t tv_sec; int tv_usec; };
/// ```
///
/// `tv_sec` is widened to [`i64`] (so the type has the same layout on every
/// target regardless of the platform `time_t` width) while `tv_usec` keeps the
/// C `int` width as [`i32`]. For values produced by [`curlx_now`], `tv_usec` is
/// always normalized to the range `0..=999_999`.
///
/// # Ordering
///
/// [`CurlTime`] derives [`Ord`] (and therefore [`PartialOrd`]) with the field
/// order `tv_sec` **then** `tv_usec`, so two timestamps compare exactly as the
/// instants they represent. This total order is **required**: the multi
/// handle's timer machinery (`splay.rs`) keys an ordered map on [`CurlTime`],
/// and the timeout logic compares deadlines directly. The type is also [`Copy`]
/// and 16 bytes wide, so it is cheap to pass and store by value.
///
/// # Monotonic only
///
/// A [`CurlTime`] obtained from [`curlx_now`] is monotonic and has an arbitrary
/// origin; it is meaningful only relative to another [`CurlTime`] (via the
/// difference helpers), never as an absolute calendar time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct CurlTime {
    /// Whole seconds since the monotonic origin (C: `time_t tv_sec`).
    pub tv_sec: i64,
    /// Microseconds within the current second (C: `int tv_usec`), normally in
    /// the range `0..=999_999` for values produced by [`curlx_now`].
    pub tv_usec: i32,
}

impl CurlTime {
    /// Construct a [`CurlTime`] from explicit seconds and microseconds.
    ///
    /// The values are stored verbatim with no normalization, matching the C
    /// code's direct field assignment. Callers that build a [`CurlTime`] by
    /// hand are responsible for keeping `tv_usec` within `0..=999_999` if the
    /// value is to be compared against clock readings.
    #[must_use]
    pub const fn new(tv_sec: i64, tv_usec: i32) -> Self {
        Self { tv_sec, tv_usec }
    }

    /// The all-zero [`CurlTime`] (`{ tv_sec: 0, tv_usec: 0 }`).
    ///
    /// curl uses an all-zero `struct curltime` as the "unset" / "not yet
    /// recorded" sentinel for many stored timestamps; this `const` constructor
    /// provides that value in `const` contexts (where [`Default::default`] is
    /// not usable).
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            tv_sec: 0,
            tv_usec: 0,
        }
    }

    /// Return `true` if this is the all-zero [`CurlTime`] sentinel.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_usec == 0
    }

    /// Build a [`CurlTime`] from a [`std::time::Duration`] measured from the
    /// monotonic origin.
    ///
    /// This is the split used by [`curlx_now`]: the duration's whole seconds
    /// become `tv_sec` and its sub-second microseconds become `tv_usec`
    /// (`0..=999_999`). A duration whose seconds exceed [`i64::MAX`] (about 292
    /// billion years) saturates `tv_sec` to [`i64::MAX`] rather than wrapping.
    #[must_use]
    pub fn from_duration(d: Duration) -> Self {
        // `as_secs()` is u64; clamp to i64::MAX for absurd durations so the
        // conversion can never wrap or panic.
        let tv_sec = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
        // `subsec_micros()` is always in `0..1_000_000`, which fits in i32, so
        // this conversion never fails; `unwrap_or(0)` upholds the no-panic
        // contract regardless.
        let tv_usec = i32::try_from(d.subsec_micros()).unwrap_or(0);
        Self { tv_sec, tv_usec }
    }

    /// Convert this [`CurlTime`] into a [`std::time::Duration`] measured from
    /// the monotonic origin.
    ///
    /// This is the inverse of [`from_duration`](CurlTime::from_duration) for
    /// normalized values and is used at the async timeout sites that take a
    /// [`Duration`]. A negative `tv_sec` or `tv_usec` (which a clock reading
    /// never produces) clamps to zero, since [`Duration`] is unsigned.
    #[must_use]
    pub fn as_duration(&self) -> Duration {
        let secs = u64::try_from(self.tv_sec).unwrap_or(0);
        let micros = u32::try_from(self.tv_usec).unwrap_or(0);
        // micros <= 999_999, so micros * 1000 <= 999_999_000 < 1e9 — well
        // within u32 and below one second, so `Duration::new` cannot carry or
        // panic. `saturating_mul` keeps the no-panic guarantee unconditional.
        Duration::new(secs, micros.saturating_mul(1_000))
    }
}

// =============================================================================
// Monotonic clock — `curlx_now` / `curlx_now_init`
// =============================================================================

/// Process-stable monotonic origin for [`curlx_now`].
///
/// curl's `curlx_now()` returns a value from a monotonic clock whose epoch is
/// unspecified but fixed for the lifetime of the process. We reproduce that by
/// capturing a single [`Instant`] the first time the clock is observed and
/// expressing every later reading as the elapsed time since that baseline. A
/// [`OnceLock`] makes the capture happen exactly once, lazily, and in a
/// thread-safe way without any `unsafe`.
static CLOCK_BASE: OnceLock<Instant> = OnceLock::new();

/// Return the monotonic origin, initializing it on first use.
#[inline]
fn clock_base() -> Instant {
    // `get_or_init` runs `Instant::now` exactly once across all threads; every
    // subsequent call returns the stored baseline. `Instant` is `Copy`, so the
    // dereference yields an owned value.
    *CLOCK_BASE.get_or_init(Instant::now)
}

/// Prime the monotonic clock baseline.
///
/// This mirrors C's `curlx_now_init()`. In C the function only does work on
/// Windows (recording `QueryPerformanceFrequency`), and the tool/tests must call
/// it before the first `curlx_now()`. Here it simply forces the lazy
/// [`CLOCK_BASE`] to initialize so that the very first [`curlx_now`] reading is
/// taken relative to a baseline established at this call.
///
/// It is **idempotent**: calling it zero, one, or many times is safe and has the
/// same effect (the baseline is captured at most once).
pub fn curlx_now_init() {
    // Force initialization; the returned baseline is intentionally discarded.
    let _ = clock_base();
}

/// Return the current monotonic time as a [`CurlTime`].
///
/// This is the Rust image of C's `struct curltime curlx_now(void)`. The result
/// is monotonic — successive calls never go backward — and is expressed as the
/// elapsed time since the process-stable origin established by the first call
/// (or by [`curlx_now_init`]).
///
/// The reading uses [`Instant::saturating_duration_since`], so it never panics
/// even on the (std-guaranteed-impossible, but defensively handled) chance that
/// the clock appears to move backward; in that case it yields the origin
/// (`{ 0, 0 }`) rather than trapping.
///
/// # Not wall-clock
///
/// The returned value is meaningful only relative to another [`CurlTime`] (via
/// [`curlx_timediff`] and friends). It is **not** a Unix timestamp and must not
/// be passed to [`curlx_gmtime`] or used for display.
#[must_use]
pub fn curlx_now() -> CurlTime {
    let elapsed = Instant::now().saturating_duration_since(clock_base());
    CurlTime::from_duration(elapsed)
}

// =============================================================================
// Difference helpers — milliseconds / microseconds / ceil-milliseconds
// =============================================================================

/// Time difference, in **milliseconds**, between two [`CurlTime`] values.
///
/// Computes `newer - older` in milliseconds, the Rust image of C's
/// `curlx_timediff_ms` (the agent specification names this `curlx_timediff`):
///
/// ```text
/// (newer.tv_sec - older.tv_sec) * 1000 + (newer.tv_usec - older.tv_usec) / 1000
/// ```
///
/// As in C, pass the more recent time as `newer`; a reversed pair yields a
/// negative result. For differences too large to express in [`i64`]
/// milliseconds the result saturates to [`TIMEDIFF_T_MAX`] / [`TIMEDIFF_T_MIN`],
/// matching the C "for too large diffs it returns max value" guard. The
/// sub-millisecond microsecond remainder is truncated toward zero by the
/// integer division, exactly as in C.
///
/// All arithmetic is saturating, so no input can panic.
#[must_use]
pub fn curlx_timediff(newer: CurlTime, older: CurlTime) -> i64 {
    // Second-level difference (the C `timediff_t diff = newer.tv_sec -
    // older.tv_sec`). `saturating_sub` avoids overflow for pathological inputs.
    let diff = newer.tv_sec.saturating_sub(older.tv_sec);
    // Overflow guards, identical to the C original: if the whole-second
    // difference alone would overflow a millisecond `timediff_t`, clamp.
    if diff >= TIMEDIFF_T_MAX / MS_PER_SEC {
        return TIMEDIFF_T_MAX;
    }
    if diff <= TIMEDIFF_T_MIN / MS_PER_SEC {
        return TIMEDIFF_T_MIN;
    }
    // Microsecond difference promoted to i64 (the C `int` subtraction widened
    // before the divide). The `/ 1000` truncates toward zero, as in C.
    let usec = i64::from(newer.tv_usec) - i64::from(older.tv_usec);
    diff.saturating_mul(MS_PER_SEC)
        .saturating_add(usec / US_PER_MS)
}

/// Time difference in milliseconds — the C-symbol-named alias of
/// [`curlx_timediff`].
///
/// curl's header spells this `curlx_timediff_ms`; it is provided so call sites
/// translated verbatim from the C tree resolve without renaming. It is exactly
/// [`curlx_timediff`].
#[must_use]
pub fn curlx_timediff_ms(newer: CurlTime, older: CurlTime) -> i64 {
    curlx_timediff(newer, older)
}

/// Pointer-style millisecond difference — the Rust image of C's
/// `curlx_ptimediff_ms(const struct curltime *, const struct curltime *)`.
///
/// [`CurlTime`] is [`Copy`], so the idiomatic Rust form is the by-value
/// [`curlx_timediff`]; this borrowing wrapper exists only to match the C
/// header's pointer signature for directly translated call sites.
#[allow(clippy::trivially_copy_pass_by_ref)] // C-parity: C takes `const curltime *`.
#[must_use]
pub fn curlx_ptimediff_ms(newer: &CurlTime, older: &CurlTime) -> i64 {
    curlx_timediff(*newer, *older)
}

/// Time difference, in **microseconds**, between two [`CurlTime`] values.
///
/// The Rust image of C's `curlx_timediff_us`:
///
/// ```text
/// (newer.tv_sec - older.tv_sec) * 1_000_000 + (newer.tv_usec - older.tv_usec)
/// ```
///
/// For differences too large to express in [`i64`] microseconds the result
/// saturates to [`TIMEDIFF_T_MAX`] / [`TIMEDIFF_T_MIN`], matching the C guard
/// (which compares against `TIMEDIFF_T_MAX / 1_000_000`). All arithmetic is
/// saturating, so no input can panic.
#[must_use]
pub fn curlx_timediff_us(newer: CurlTime, older: CurlTime) -> i64 {
    let diff = newer.tv_sec.saturating_sub(older.tv_sec);
    if diff >= TIMEDIFF_T_MAX / US_PER_SEC {
        return TIMEDIFF_T_MAX;
    }
    if diff <= TIMEDIFF_T_MIN / US_PER_SEC {
        return TIMEDIFF_T_MIN;
    }
    let usec = i64::from(newer.tv_usec) - i64::from(older.tv_usec);
    diff.saturating_mul(US_PER_SEC).saturating_add(usec)
}

/// Pointer-style microsecond difference — the Rust image of C's
/// `curlx_ptimediff_us(const struct curltime *, const struct curltime *)`.
///
/// As with [`curlx_ptimediff_ms`], the idiomatic form is the by-value
/// [`curlx_timediff_us`]; this wrapper matches the C pointer signature.
#[allow(clippy::trivially_copy_pass_by_ref)] // C-parity: C takes `const curltime *`.
#[must_use]
pub fn curlx_ptimediff_us(newer: &CurlTime, older: &CurlTime) -> i64 {
    curlx_timediff_us(*newer, *older)
}

/// Time difference, in **milliseconds rounded up**, between two [`CurlTime`]
/// values.
///
/// The Rust image of C's `curlx_timediff_ceil_ms`. curl rounds a partial
/// millisecond *up* so that a sub-millisecond remaining timeout still waits at
/// least 1 ms:
///
/// ```text
/// (newer.tv_sec - older.tv_sec) * 1000 + (newer.tv_usec - older.tv_usec + 999) / 1000
/// ```
///
/// For example a gap of 1500 µs rounds up to 2 ms (whereas [`curlx_timediff`]
/// truncates it to 1 ms). The same [`TIMEDIFF_T_MAX`] / [`TIMEDIFF_T_MIN`]
/// saturation guards apply, and all arithmetic is saturating.
#[must_use]
pub fn curlx_timediff_ceil_ms(newer: CurlTime, older: CurlTime) -> i64 {
    let diff = newer.tv_sec.saturating_sub(older.tv_sec);
    if diff >= TIMEDIFF_T_MAX / MS_PER_SEC {
        return TIMEDIFF_T_MAX;
    }
    if diff <= TIMEDIFF_T_MIN / MS_PER_SEC {
        return TIMEDIFF_T_MIN;
    }
    let usec = i64::from(newer.tv_usec) - i64::from(older.tv_usec);
    // The `+ 999` before the divide-by-1000 is the C ceil idiom. `saturating_*`
    // keeps the no-panic contract for any field values.
    diff.saturating_mul(MS_PER_SEC)
        .saturating_add(usec.saturating_add(999) / US_PER_MS)
}

// =============================================================================
// Duration bridges — for the async timeout sites
// =============================================================================

/// Monotonic time elapsed since `t`, as a [`std::time::Duration`].
///
/// Equivalent to `curlx_now() - t` measured at microsecond resolution. This is
/// the [`CurlTime`] analog of the `timediff` → [`Duration`] bridges in
/// [`crate::util::timediff`], used by the multi/transfer timeout code that
/// drives Tokio timers with a [`Duration`].
///
/// If `t` is in the future (so the elapsed time would be negative), the result
/// is [`Duration::ZERO`], since a [`Duration`] cannot be negative.
#[must_use]
pub fn elapsed_since(t: CurlTime) -> Duration {
    let now = curlx_now();
    let micros = curlx_timediff_us(now, t);
    if micros <= 0 {
        Duration::ZERO
    } else {
        // `micros > 0` here, so the conversion to u64 always succeeds;
        // `unwrap_or(0)` upholds the no-panic contract unconditionally.
        Duration::from_micros(u64::try_from(micros).unwrap_or(0))
    }
}

// =============================================================================
// UTC breakdown — `curlx_gmtime`
// =============================================================================

/// Convert a Unix timestamp (seconds since 1970-01-01T00:00:00Z) into a
/// broken-down UTC date/time.
///
/// This is the Rust replacement for C's
/// `CURLcode curlx_gmtime(time_t intime, struct tm *store)` — curl's
/// thread-safe `gmtime_r`/`gmtime_s` wrapper used by date formatting
/// (`parsedate.rs`) and `getinfo`. It is **wall-clock**: unlike [`curlx_now`],
/// the input here is an absolute calendar timestamp.
///
/// The conversion is delegated to [`chrono::DateTime::from_timestamp`], which
/// returns [`None`] for out-of-range timestamps — the Rust equivalent of the C
/// function returning `CURLE_BAD_FUNCTION_ARGUMENT` (and `gmtime_r` returning
/// `NULL`). On success the returned [`DateTime<Utc>`] exposes the same
/// broken-down fields (`year`, `month`, `day`, `hour`, `minute`, `second`,
/// weekday, ordinal day) that the C `struct tm` carries.
#[must_use]
pub fn curlx_gmtime(intime: i64) -> Option<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp(intime, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, Timelike};

    // ---- CurlTime construction / derives ----------------------------------

    #[test]
    fn curltime_new_zero_default_and_is_zero() {
        assert_eq!(
            CurlTime::new(3, 4),
            CurlTime {
                tv_sec: 3,
                tv_usec: 4
            }
        );
        assert_eq!(
            CurlTime::zero(),
            CurlTime {
                tv_sec: 0,
                tv_usec: 0
            }
        );
        // The derived `Default` agrees with the explicit `zero()` constructor.
        assert_eq!(CurlTime::default(), CurlTime::zero());

        assert!(CurlTime::zero().is_zero());
        assert!(!CurlTime::new(0, 1).is_zero());
        assert!(!CurlTime::new(1, 0).is_zero());
    }

    #[test]
    fn curltime_is_copy() {
        // `CurlTime` is `Copy`: the original remains usable after a bind-copy.
        let a = CurlTime::new(7, 8);
        let b = a;
        assert_eq!(a, b);
        assert_eq!(a.tv_sec, 7);
        assert_eq!(a.tv_usec, 8);
    }

    // ---- Ordering (splay-key usability) -----------------------------------

    #[test]
    fn curltime_ordering_is_sec_then_usec() {
        // The canonical example from the specification: {1,0} < {1,500} < {2,0}.
        let a = CurlTime::new(1, 0);
        let b = CurlTime::new(1, 500);
        let c = CurlTime::new(2, 0);

        assert!(a < b, "equal seconds compare by usec");
        assert!(b < c, "smaller seconds always sort first");
        assert!(a < c);

        // A larger second value outranks any usec of a smaller second.
        assert!(CurlTime::new(1, 999_999) < CurlTime::new(2, 0));
    }

    #[test]
    fn curltime_sorts_as_an_ordered_key() {
        // Exercises the total order `splay.rs` relies on for its timer map.
        let a = CurlTime::new(1, 0);
        let b = CurlTime::new(1, 500);
        let c = CurlTime::new(2, 0);
        let mut v = vec![c, a, b];
        v.sort();
        assert_eq!(v, vec![a, b, c]);
    }

    // ---- Duration conversions ---------------------------------------------

    #[test]
    fn from_duration_splits_secs_and_micros() {
        let d = Duration::new(5, 250_000_000); // 5 s + 250 ms
        let t = CurlTime::from_duration(d);
        assert_eq!(t.tv_sec, 5);
        assert_eq!(t.tv_usec, 250_000);
    }

    #[test]
    fn from_duration_truncates_sub_microsecond_nanos() {
        // 1_999 ns is 1 whole microsecond (the remaining 999 ns is dropped).
        let t = CurlTime::from_duration(Duration::new(1, 1_999));
        assert_eq!(t.tv_sec, 1);
        assert_eq!(t.tv_usec, 1);
    }

    #[test]
    fn from_duration_saturates_huge_seconds() {
        // A duration beyond i64::MAX seconds clamps tv_sec instead of wrapping.
        let t = CurlTime::from_duration(Duration::new(u64::MAX, 0));
        assert_eq!(t.tv_sec, i64::MAX);
        assert_eq!(t.tv_usec, 0);
    }

    #[test]
    fn as_duration_round_trips_with_from_duration() {
        let d = Duration::new(5, 250_000_000);
        let t = CurlTime::from_duration(d);
        assert_eq!(t.as_duration(), d);
    }

    #[test]
    fn as_duration_clamps_negative_fields_to_zero() {
        // Clock readings never produce negatives, but the conversion is defined
        // and panic-free for hand-built values.
        assert_eq!(CurlTime::new(-1, -5).as_duration(), Duration::ZERO);
    }

    // ---- Monotonic clock --------------------------------------------------

    #[test]
    fn curlx_now_is_monotonic() {
        // Two successive readings: the second is never earlier than the first.
        let a = curlx_now();
        let b = curlx_now();
        assert!(b >= a, "curlx_now must be monotonic: {a:?} then {b:?}");
    }

    #[test]
    fn curlx_now_init_is_idempotent() {
        // Safe to call any number of times; the clock still works afterward.
        curlx_now_init();
        curlx_now_init();
        let a = curlx_now();
        let b = curlx_now();
        assert!(b >= a);
    }

    #[test]
    fn curlx_now_fields_are_normalized() {
        let t = curlx_now();
        assert!(t.tv_sec >= 0, "monotonic seconds are non-negative");
        assert!(
            (0..=999_999).contains(&t.tv_usec),
            "tv_usec must be normalized, got {}",
            t.tv_usec
        );
    }

    // ---- Difference helpers: milliseconds ---------------------------------

    #[test]
    fn timediff_ms_known_pair() {
        let older = CurlTime::new(1, 250_000);
        let newer = CurlTime::new(2, 500_000);
        // (2-1)*1000 + (500_000-250_000)/1000 = 1000 + 250 = 1250 ms.
        assert_eq!(curlx_timediff(newer, older), 1_250);
        // The C-named alias and the pointer form agree exactly.
        assert_eq!(curlx_timediff_ms(newer, older), 1_250);
        assert_eq!(curlx_ptimediff_ms(&newer, &older), 1_250);
    }

    #[test]
    fn timediff_ms_reversed_pair_is_negative() {
        let older = CurlTime::new(1, 250_000);
        let newer = CurlTime::new(2, 500_000);
        assert_eq!(curlx_timediff(older, newer), -1_250);
    }

    #[test]
    fn timediff_ms_truncates_sub_millisecond() {
        let z = CurlTime::zero();
        // 1500 µs truncates to 1 ms (vs. the ceil form below).
        assert_eq!(curlx_timediff(CurlTime::new(0, 1_500), z), 1);
        // Sub-millisecond truncates to 0.
        assert_eq!(curlx_timediff(CurlTime::new(0, 1), z), 0);
        assert_eq!(curlx_timediff(z, z), 0);
    }

    // ---- Difference helpers: microseconds ---------------------------------

    #[test]
    fn timediff_us_known_pair() {
        let older = CurlTime::new(1, 250_000);
        let newer = CurlTime::new(2, 500_000);
        // (2-1)*1_000_000 + (500_000-250_000) = 1_250_000 µs.
        assert_eq!(curlx_timediff_us(newer, older), 1_250_000);
        assert_eq!(curlx_ptimediff_us(&newer, &older), 1_250_000);
    }

    // ---- Difference helpers: ceil-milliseconds ----------------------------

    #[test]
    fn timediff_ceil_ms_rounds_partial_up() {
        let z = CurlTime::zero();
        // The canonical example: a 1500 µs gap rounds UP to 2 ms.
        assert_eq!(curlx_timediff_ceil_ms(CurlTime::new(0, 1_500), z), 2);
        // Exactly one millisecond stays 1 ms (no spurious round-up).
        assert_eq!(curlx_timediff_ceil_ms(CurlTime::new(0, 1_000), z), 1);
        // Just over one millisecond rounds up to 2 ms.
        assert_eq!(curlx_timediff_ceil_ms(CurlTime::new(0, 1_001), z), 2);
        // Any sub-millisecond positive remainder becomes at least 1 ms.
        assert_eq!(curlx_timediff_ceil_ms(CurlTime::new(0, 1), z), 1);
        // A zero gap is still zero.
        assert_eq!(curlx_timediff_ceil_ms(z, z), 0);
    }

    // ---- Overflow saturation ----------------------------------------------

    #[test]
    fn timediff_saturates_for_huge_diffs() {
        let big = CurlTime::new(i64::MAX, 0);
        let z = CurlTime::zero();

        assert_eq!(curlx_timediff(big, z), TIMEDIFF_T_MAX);
        assert_eq!(curlx_timediff(z, big), TIMEDIFF_T_MIN);

        assert_eq!(curlx_timediff_us(big, z), TIMEDIFF_T_MAX);
        assert_eq!(curlx_timediff_us(z, big), TIMEDIFF_T_MIN);

        assert_eq!(curlx_timediff_ceil_ms(big, z), TIMEDIFF_T_MAX);
        assert_eq!(curlx_timediff_ceil_ms(z, big), TIMEDIFF_T_MIN);
    }

    // ---- elapsed_since ----------------------------------------------------

    #[test]
    fn elapsed_since_is_small_and_non_negative() {
        let start = curlx_now();
        let elapsed = elapsed_since(start);
        // A reading taken immediately after `start` elapses well under a minute.
        assert!(elapsed < Duration::from_secs(60));
    }

    #[test]
    fn elapsed_since_future_is_zero() {
        let start = curlx_now();
        // A point comfortably in the future yields a zero (never negative) span.
        let future = CurlTime::new(start.tv_sec.saturating_add(10_000), 0);
        assert_eq!(elapsed_since(future), Duration::ZERO);
    }

    // ---- curlx_gmtime -----------------------------------------------------

    #[test]
    fn gmtime_epoch_is_1970_01_01() {
        let dt = curlx_gmtime(0).expect("the Unix epoch is in range");
        assert_eq!(dt.timestamp(), 0);
        assert_eq!((dt.year(), dt.month(), dt.day()), (1970, 1, 1));
        assert_eq!((dt.hour(), dt.minute(), dt.second()), (0, 0, 0));
    }

    #[test]
    fn gmtime_known_timestamp() {
        // 1_431_648_000 == 2015-05-15T00:00:00Z (chrono's own doc example).
        let dt = curlx_gmtime(1_431_648_000).expect("in range");
        assert_eq!((dt.year(), dt.month(), dt.day()), (2015, 5, 15));
        assert_eq!((dt.hour(), dt.minute(), dt.second()), (0, 0, 0));
    }

    #[test]
    fn gmtime_out_of_range_is_none() {
        // Mirrors the C function returning CURLE_BAD_FUNCTION_ARGUMENT / NULL.
        assert_eq!(curlx_gmtime(i64::MAX), None);
        assert_eq!(curlx_gmtime(i64::MIN), None);
    }
}
