//! Millisecond ↔ Duration/Timeval conversion — Rust replacement for
//! `lib/curlx/timediff.c`.
//!
//! Provides overflow-safe conversions between millisecond counts and
//! [`Duration`] / [`CurlTimeval`] values. Negative millisecond inputs are
//! clamped to zero, and excessively large values are clamped rather than
//! wrapped or allowed to panic, matching the C implementation's behaviour.
//!
//! # C Correspondence
//!
//! | Rust                   | C                                        |
//! |------------------------|------------------------------------------|
//! | `ms_to_duration()`     | `curlx_mstotv(timediff_t, struct timeval *)` |
//! | `duration_to_ms()`     | `curlx_tvtoms(struct timeval)`           |
//! | `timeout_ms_clamp()`   | clamped timeout helpers throughout curl   |
//! | `remaining_ms()`       | `Curl_timeleft()` pattern                |
//! | `CurlTimeval`          | `struct timeval`                         |
//! | `ms_to_timeval()`      | `curlx_mstotv()` with `struct timeval`   |
//! | `timeval_to_ms()`      | `curlx_tvtoms()`                         |
//!
//! # Design Notes
//!
//! Internally all Rust code should use [`std::time::Duration`] for time spans.
//! [`CurlTimeval`] and the `ms_to_timeval` / `timeval_to_ms` helpers exist
//! solely for the FFI boundary so that C consumers receive a `struct timeval`–
//! shaped value.

use std::time::{Duration, Instant};

use crate::util::timeval::CurlTime;

// ---------------------------------------------------------------------------
// Type alias
// ---------------------------------------------------------------------------

/// Millisecond‐resolution time difference (matches C `timediff_t`).
pub type TimeDiff = i64;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum representable millisecond value.
///
/// Equivalent to C `TIMEDIFF_T_MAX`. Using `i64::MAX` here aligns with the
/// 64-bit `timediff_t` typedef on all supported platforms.
pub const TIMEDIFF_T_MAX: i64 = i64::MAX;

/// Sentinel value meaning "no timeout" (blocking operation).
///
/// Matches the C convention where `-1` signals that no timeout is set.
pub const TIMEOUT_NONE: i64 = -1;

/// Maximum practical timeout for socket operations (24 hours in ms).
///
/// Used by [`timeout_ms_clamp`] to prevent excessively large poll timeouts.
const MAX_TIMEOUT_MS: i64 = 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Duration conversions
// ---------------------------------------------------------------------------

/// Convert milliseconds to a [`Duration`].
///
/// * `ms <= 0` → [`Duration::ZERO`]
/// * `ms > 0`  → `Duration::from_millis(ms as u64)` (clamped for overflow)
///
/// Matches the semantics of C `curlx_mstotv`.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::util::timediff::ms_to_duration;
/// use std::time::Duration;
///
/// assert_eq!(ms_to_duration(1000), Duration::from_secs(1));
/// assert_eq!(ms_to_duration(0), Duration::ZERO);
/// assert_eq!(ms_to_duration(-42), Duration::ZERO);
/// ```
pub fn ms_to_duration(ms: i64) -> Duration {
    if ms <= 0 {
        Duration::ZERO
    } else {
        // i64::MAX (≈ 9.2e18) fits inside u64::MAX (≈ 1.8e19).
        Duration::from_millis(ms as u64)
    }
}

/// Convert a [`Duration`] to a millisecond count.
///
/// Clamps to [`i64::MAX`] if the duration overflows. Returns `0` for a
/// zero-length duration.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::util::timediff::duration_to_ms;
/// use std::time::Duration;
///
/// assert_eq!(duration_to_ms(Duration::from_secs(1)), 1000);
/// assert_eq!(duration_to_ms(Duration::ZERO), 0);
/// ```
pub fn duration_to_ms(d: Duration) -> i64 {
    let millis = d.as_millis();
    if millis > i64::MAX as u128 {
        i64::MAX
    } else {
        millis as i64
    }
}

// ---------------------------------------------------------------------------
// Timeout helpers
// ---------------------------------------------------------------------------

/// Clamp a millisecond timeout to a safe [`Duration`] for socket operations.
///
/// * Negative values → [`Duration::ZERO`] (non-blocking poll)
/// * Values > 24 hours → capped to 24 hours
///
/// Prevents accidentally blocking forever or handing an unreasonably large
/// timeout to `poll` / `select`.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::util::timediff::timeout_ms_clamp;
/// use std::time::Duration;
///
/// assert_eq!(timeout_ms_clamp(-1), Duration::ZERO);
/// assert_eq!(timeout_ms_clamp(500), Duration::from_millis(500));
/// ```
pub fn timeout_ms_clamp(ms: i64) -> Duration {
    if ms <= 0 {
        Duration::ZERO
    } else if ms > MAX_TIMEOUT_MS {
        Duration::from_millis(MAX_TIMEOUT_MS as u64)
    } else {
        Duration::from_millis(ms as u64)
    }
}

/// Calculate the remaining milliseconds until `deadline`.
///
/// Returns `0` if the deadline has already passed (never returns a negative
/// value), matching the `Curl_timeleft` pattern.
///
/// # Examples
///
/// ```no_run
/// use curl_rs_lib::util::timediff::remaining_ms;
/// use std::time::Instant;
///
/// let deadline = Instant::now() + std::time::Duration::from_millis(500);
/// let remaining = remaining_ms(deadline, Instant::now());
/// assert!(remaining > 0);
/// ```
pub fn remaining_ms(deadline: Instant, now: Instant) -> i64 {
    if now >= deadline {
        0
    } else {
        duration_to_ms(deadline.duration_since(now))
    }
}

/// Calculate the remaining milliseconds using [`CurlTime`] instances.
///
/// Uses [`CurlTime::to_duration_since`] to compute the gap between `deadline`
/// and `now`. When the deadline has already passed (`now >= deadline`),
/// `to_duration_since` returns [`Duration::ZERO`] and this function returns
/// `0`.
pub fn remaining_ms_curl(deadline: CurlTime, now: CurlTime) -> i64 {
    duration_to_ms(deadline.to_duration_since(now))
}

/// Compute how many milliseconds have elapsed since `start`.
///
/// Convenience wrapper around [`CurlTime::elapsed`] that converts the
/// resulting [`Duration`] to an `i64` millisecond count. Clamped to
/// [`i64::MAX`] on overflow (should never occur in practice given that
/// monotonic clocks start at process launch).
///
/// # Examples
///
/// ```no_run
/// use curl_rs_lib::util::timeval::CurlTime;
/// use curl_rs_lib::util::timediff::elapsed_ms;
///
/// let start = CurlTime::now();
/// // … perform some work …
/// let ms = elapsed_ms(start);
/// assert!(ms >= 0);
/// ```
pub fn elapsed_ms(start: CurlTime) -> i64 {
    duration_to_ms(start.elapsed())
}

/// Convenience: remaining milliseconds from [`Instant::now`] until `deadline`.
///
/// Equivalent to `remaining_ms(deadline, Instant::now())`.
#[inline]
pub fn remaining_ms_now(deadline: Instant) -> i64 {
    remaining_ms(deadline, Instant::now())
}

// ---------------------------------------------------------------------------
// CurlTimeval — FFI-oriented struct timeval equivalent
// ---------------------------------------------------------------------------

/// A `struct timeval`–shaped value for the FFI boundary.
///
/// Internal Rust code should use [`Duration`] directly; this type exists so
/// that the `curl-rs-ffi` crate can expose timeout values to C consumers in
/// the expected `struct timeval` layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CurlTimeval {
    /// Seconds component.
    pub tv_sec: i64,
    /// Microseconds component (0 ..= 999_999).
    pub tv_usec: i64,
}

impl CurlTimeval {
    /// Convert this timeval into a [`Duration`] with full microsecond
    /// precision.
    ///
    /// Negative field values are treated as zero. This mirrors converting a
    /// C `struct timeval` into a Rust-native time span.
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::util::timediff::CurlTimeval;
    /// use std::time::Duration;
    ///
    /// let tv = CurlTimeval { tv_sec: 2, tv_usec: 500_000 };
    /// assert_eq!(tv.to_duration(), Duration::from_millis(2500));
    /// ```
    pub fn to_duration(&self) -> Duration {
        let sec_part = if self.tv_sec > 0 {
            Duration::from_secs(self.tv_sec as u64)
        } else {
            Duration::ZERO
        };
        let usec_part = if self.tv_usec > 0 {
            Duration::from_micros(self.tv_usec as u64)
        } else {
            Duration::ZERO
        };
        sec_part + usec_part
    }

    /// Create a new [`CurlTimeval`] from separate seconds and microseconds.
    ///
    /// No validation is performed; callers are expected to keep `tv_usec` in
    /// the `0 ..= 999_999` range.
    #[inline]
    pub fn new(tv_sec: i64, tv_usec: i64) -> Self {
        Self { tv_sec, tv_usec }
    }
}

/// Convert milliseconds to a [`CurlTimeval`].
///
/// Negative values produce a zero-valued timeval, matching C semantics where
/// `curlx_mstotv` zeros the fields for `ms <= 0`.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::util::timediff::ms_to_timeval;
///
/// let tv = ms_to_timeval(1500);
/// assert_eq!(tv.tv_sec, 1);
/// assert_eq!(tv.tv_usec, 500_000);
/// ```
pub fn ms_to_timeval(ms: i64) -> CurlTimeval {
    if ms <= 0 {
        CurlTimeval {
            tv_sec: 0,
            tv_usec: 0,
        }
    } else {
        CurlTimeval {
            tv_sec: ms / 1000,
            tv_usec: (ms % 1000) * 1000,
        }
    }
}

/// Convert a [`CurlTimeval`] back to milliseconds.
///
/// Overflow is clamped to [`i64::MAX`].
///
/// # Examples
///
/// ```
/// use curl_rs_lib::util::timediff::{CurlTimeval, timeval_to_ms};
///
/// let tv = CurlTimeval { tv_sec: 1, tv_usec: 500_000 };
/// assert_eq!(timeval_to_ms(&tv), 1500);
/// ```
pub fn timeval_to_ms(tv: &CurlTimeval) -> i64 {
    let sec_ms = tv.tv_sec.saturating_mul(1000);
    let usec_ms = tv.tv_usec / 1000;
    sec_ms.saturating_add(usec_ms)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- ms_to_duration -----------------------------------------------------

    #[test]
    fn ms_to_duration_positive() {
        assert_eq!(ms_to_duration(1000), Duration::from_secs(1));
    }

    #[test]
    fn ms_to_duration_zero() {
        assert_eq!(ms_to_duration(0), Duration::ZERO);
    }

    #[test]
    fn ms_to_duration_negative() {
        assert_eq!(ms_to_duration(-42), Duration::ZERO);
    }

    #[test]
    fn ms_to_duration_one() {
        assert_eq!(ms_to_duration(1), Duration::from_millis(1));
    }

    #[test]
    fn ms_to_duration_large() {
        let ms = 86_400_000i64; // 24 hours
        assert_eq!(ms_to_duration(ms), Duration::from_millis(ms as u64));
    }

    #[test]
    fn ms_to_duration_max() {
        let d = ms_to_duration(i64::MAX);
        assert_eq!(d, Duration::from_millis(i64::MAX as u64));
    }

    // -- duration_to_ms -----------------------------------------------------

    #[test]
    fn duration_to_ms_one_second() {
        assert_eq!(duration_to_ms(Duration::from_secs(1)), 1000);
    }

    #[test]
    fn duration_to_ms_zero() {
        assert_eq!(duration_to_ms(Duration::ZERO), 0);
    }

    #[test]
    fn duration_to_ms_subsecond() {
        assert_eq!(duration_to_ms(Duration::from_millis(500)), 500);
    }

    #[test]
    fn duration_to_ms_overflow_clamps() {
        // Duration::MAX.as_millis() > i64::MAX
        assert_eq!(duration_to_ms(Duration::MAX), i64::MAX);
    }

    // -- Round-trip ----------------------------------------------------------

    #[test]
    fn round_trip_ms_duration() {
        for ms in [0, 1, 999, 1000, 60_000, 3_600_000i64] {
            assert_eq!(duration_to_ms(ms_to_duration(ms)), ms);
        }
    }

    // -- timeout_ms_clamp ---------------------------------------------------

    #[test]
    fn timeout_clamp_negative() {
        assert_eq!(timeout_ms_clamp(-1), Duration::ZERO);
    }

    #[test]
    fn timeout_clamp_normal() {
        assert_eq!(timeout_ms_clamp(500), Duration::from_millis(500));
    }

    #[test]
    fn timeout_clamp_too_large() {
        let clamped = timeout_ms_clamp(MAX_TIMEOUT_MS + 1);
        assert_eq!(clamped, Duration::from_millis(MAX_TIMEOUT_MS as u64));
    }

    #[test]
    fn timeout_clamp_zero() {
        assert_eq!(timeout_ms_clamp(0), Duration::ZERO);
    }

    // -- remaining_ms -------------------------------------------------------

    #[test]
    fn remaining_ms_deadline_passed() {
        let now = Instant::now();
        // Deadline is in the "past" relative to `now`.
        assert_eq!(remaining_ms(now, now), 0);
    }

    #[test]
    fn remaining_ms_future_deadline() {
        let now = Instant::now();
        let deadline = now + Duration::from_millis(500);
        let rem = remaining_ms(deadline, now);
        // Should be approximately 500, allow some jitter.
        assert!(rem >= 499 && rem <= 501, "remaining was {rem}");
    }

    // -- CurlTimeval --------------------------------------------------------

    #[test]
    fn ms_to_timeval_positive() {
        let tv = ms_to_timeval(1500);
        assert_eq!(tv.tv_sec, 1);
        assert_eq!(tv.tv_usec, 500_000);
    }

    #[test]
    fn ms_to_timeval_zero() {
        let tv = ms_to_timeval(0);
        assert_eq!(tv.tv_sec, 0);
        assert_eq!(tv.tv_usec, 0);
    }

    #[test]
    fn ms_to_timeval_negative() {
        let tv = ms_to_timeval(-100);
        assert_eq!(tv.tv_sec, 0);
        assert_eq!(tv.tv_usec, 0);
    }

    #[test]
    fn ms_to_timeval_exact_second() {
        let tv = ms_to_timeval(3000);
        assert_eq!(tv.tv_sec, 3);
        assert_eq!(tv.tv_usec, 0);
    }

    #[test]
    fn timeval_to_ms_basic() {
        let tv = CurlTimeval {
            tv_sec: 1,
            tv_usec: 500_000,
        };
        assert_eq!(timeval_to_ms(&tv), 1500);
    }

    #[test]
    fn timeval_to_ms_zero() {
        let tv = CurlTimeval::default();
        assert_eq!(timeval_to_ms(&tv), 0);
    }

    #[test]
    fn timeval_round_trip() {
        for ms in [0, 1, 999, 1000, 1500, 60_000, 3_600_000i64] {
            let tv = ms_to_timeval(ms);
            assert_eq!(timeval_to_ms(&tv), ms, "round-trip failed for {ms}ms");
        }
    }

    #[test]
    fn timeval_to_ms_overflow_clamps() {
        let tv = CurlTimeval {
            tv_sec: i64::MAX,
            tv_usec: 999_999,
        };
        assert_eq!(timeval_to_ms(&tv), i64::MAX);
    }

    // -- remaining_ms_curl (CurlTime) ---------------------------------------

    #[test]
    fn remaining_ms_curl_deadline_in_future() {
        let now = CurlTime::now();
        let deadline = now.add_ms(200);
        let rem = remaining_ms_curl(deadline, now);
        // Should be approximately 200; allow jitter.
        assert!(rem >= 150 && rem <= 300, "remaining was {rem}");
    }

    #[test]
    fn remaining_ms_curl_deadline_passed() {
        let deadline = CurlTime::now();
        std::thread::sleep(Duration::from_millis(10));
        let now = CurlTime::now();
        assert_eq!(remaining_ms_curl(deadline, now), 0);
    }

    // -- elapsed_ms ---------------------------------------------------------

    #[test]
    fn elapsed_ms_non_negative() {
        let start = CurlTime::now();
        std::thread::sleep(Duration::from_millis(10));
        let ms = elapsed_ms(start);
        assert!(ms >= 5, "elapsed should be >= 5 ms, got {ms}");
    }

    // -- remaining_ms_now ---------------------------------------------------

    #[test]
    fn remaining_ms_now_future_deadline() {
        let deadline = Instant::now() + Duration::from_millis(300);
        let rem = remaining_ms_now(deadline);
        assert!(rem > 0, "remaining should be > 0, got {rem}");
    }

    // -- CurlTimeval::to_duration -------------------------------------------

    #[test]
    fn timeval_to_duration_basic() {
        let tv = CurlTimeval { tv_sec: 2, tv_usec: 500_000 };
        assert_eq!(tv.to_duration(), Duration::from_millis(2500));
    }

    #[test]
    fn timeval_to_duration_zero() {
        let tv = CurlTimeval::default();
        assert_eq!(tv.to_duration(), Duration::ZERO);
    }

    #[test]
    fn timeval_to_duration_negative_clamped() {
        let tv = CurlTimeval { tv_sec: -1, tv_usec: -500 };
        assert_eq!(tv.to_duration(), Duration::ZERO);
    }

    #[test]
    fn timeval_new_constructor() {
        let tv = CurlTimeval::new(3, 250_000);
        assert_eq!(tv.tv_sec, 3);
        assert_eq!(tv.tv_usec, 250_000);
    }

    // -- Constants ----------------------------------------------------------

    #[test]
    fn timeout_none_is_negative_one() {
        assert_eq!(TIMEOUT_NONE, -1);
    }

    #[test]
    fn timediff_t_max_is_i64_max() {
        assert_eq!(TIMEDIFF_T_MAX, i64::MAX);
    }
}
