//! Cross-platform monotonic time source.
//!
//! Rust replacement for `lib/curlx/timeval.c`. The C code provides
//! platform-specific monotonic clocks using `QueryPerformanceCounter` (Windows),
//! `clock_gettime` (POSIX), `mach_absolute_time` (macOS), or `gettimeofday`
//! fallback. In Rust, [`std::time::Instant`] provides a portable, guaranteed
//! monotonic clock on all supported platforms, eliminating every
//! platform-specific code path.
//!
//! This module also exposes wall-clock time helpers via [`SystemTime`] for
//! absolute timestamps needed in cookies, HTTP date headers, and X.509
//! certificate validation.
//!
//! # Exported Types
//!
//! * [`CurlTime`] — Newtype wrapper around [`Instant`] replacing the C
//!   `struct curltime { time_t tv_sec; int tv_usec; }`.
//!
//! # Exported Functions
//!
//! * [`system_now`] — Current wall-clock Unix timestamp (seconds since epoch).
//! * [`from_unix_timestamp`] — Convert a Unix timestamp into [`SystemTime`].
//!
//! # Design Notes
//!
//! * **No `unsafe` blocks.** `Instant` abstracts away all OS-level clock
//!   syscalls behind a safe API.
//! * **Signed differences.** [`CurlTime::diff_ms`] and [`CurlTime::diff_us`]
//!   return `i64`, matching the C `timediff_t` type. When `newer < older` the
//!   result is negative, and overflow is clamped to `i64::MIN` / `i64::MAX`.
//! * **Thread-safe program-start sentinel.** [`CurlTime::zero`] lazily captures
//!   a program-start [`Instant`] via [`OnceLock`], providing a stable epoch for
//!   logging timestamps and uninitialised field defaults.
//! * **MSRV 1.75.** All standard-library APIs used here are stable since well
//!   before Rust 1.75 (`OnceLock` stabilised in 1.70).

use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::CurlError;

// ---------------------------------------------------------------------------
// Program-start sentinel (lazy, thread-safe)
// ---------------------------------------------------------------------------

/// Thread-safe, lazily-initialised program-start [`Instant`].
///
/// Captured on the **first** access — either via [`CurlTime::zero`] or
/// [`CurlTime::as_ms_since_epoch`] — and remains constant for the entire
/// process lifetime.
static PROGRAM_START: OnceLock<Instant> = OnceLock::new();

/// Returns (or lazily initialises) the program-start instant.
#[inline]
fn program_start() -> Instant {
    *PROGRAM_START.get_or_init(Instant::now)
}

// ---------------------------------------------------------------------------
// CurlTime — monotonic time newtype
// ---------------------------------------------------------------------------

/// Monotonic time type replacing C `struct curltime`.
///
/// Wraps [`std::time::Instant`], which is guaranteed monotonic on all
/// Rust-supported platforms. All platform-specific clocks from the C
/// implementation (QPC, `clock_gettime(CLOCK_MONOTONIC)`,
/// `mach_absolute_time`, `gettimeofday`) are replaced by this single type.
///
/// `CurlTime` is [`Copy`], [`Ord`], and supports **signed** time differences
/// (newer − older may be negative) via [`diff_ms`](Self::diff_ms) and
/// [`diff_us`](Self::diff_us), matching the C `timediff_t` return semantics.
///
/// # Examples
///
/// ```rust,no_run
/// use curl_rs_lib::util::timeval::CurlTime;
///
/// let t1 = CurlTime::now();
/// // … perform some work …
/// let t2 = CurlTime::now();
/// let elapsed_ms = CurlTime::diff_ms(t2, t1);
/// assert!(elapsed_ms >= 0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CurlTime(Instant);

impl CurlTime {
    // -----------------------------------------------------------------------
    // Time acquisition
    // -----------------------------------------------------------------------

    /// Returns the current monotonic timestamp.
    ///
    /// Equivalent to C `curlx_now()`. Wraps [`Instant::now`].
    #[inline]
    pub fn now() -> Self {
        CurlTime(Instant::now())
    }

    /// Returns a sentinel "zero" time representing program start.
    ///
    /// Used for fields that have not yet been explicitly set. It is the
    /// earliest [`CurlTime`] that any module will observe, guaranteeing
    /// `CurlTime::now() >= CurlTime::zero()` always holds (monotonicity).
    ///
    /// The underlying [`Instant`] is lazily captured on the first call via
    /// [`OnceLock`] and remains constant for the entire process lifetime.
    #[inline]
    pub fn zero() -> Self {
        CurlTime(program_start())
    }

    // -----------------------------------------------------------------------
    // Time difference helpers
    // -----------------------------------------------------------------------

    /// Signed difference in **milliseconds** (`newer − older`).
    ///
    /// Equivalent to C `curlx_timediff_ms` / `curlx_ptimediff_ms`.
    ///
    /// * Positive when `newer > older`.
    /// * Negative when `newer < older`.
    /// * Clamped to [`i64::MIN`]..=[`i64::MAX`] to prevent overflow (matching
    ///   the C `TIMEDIFF_T_MAX` / `TIMEDIFF_T_MIN` clamping).
    #[inline]
    pub fn diff_ms(newer: CurlTime, older: CurlTime) -> i64 {
        if newer.0 >= older.0 {
            let ms = newer.0.duration_since(older.0).as_millis();
            // Clamp: Duration::as_millis() returns u128 which may exceed i64::MAX.
            if ms > i64::MAX as u128 {
                i64::MAX
            } else {
                ms as i64
            }
        } else {
            let ms = older.0.duration_since(newer.0).as_millis();
            if ms > i64::MAX as u128 {
                // The magnitude exceeds i64::MAX; clamp to i64::MIN.
                // Note: |i64::MIN| = i64::MAX + 1, but i64::MIN is the
                // closest representable negative value.
                i64::MIN
            } else {
                -(ms as i64)
            }
        }
    }

    /// Signed difference in **microseconds** (`newer − older`).
    ///
    /// Equivalent to C `curlx_timediff_us` / `curlx_ptimediff_us`.
    /// Higher precision than [`diff_ms`](Self::diff_ms) for fine-grained
    /// timing. Clamped to [`i64::MIN`]..=[`i64::MAX`].
    #[inline]
    pub fn diff_us(newer: CurlTime, older: CurlTime) -> i64 {
        if newer.0 >= older.0 {
            let us = newer.0.duration_since(older.0).as_micros();
            if us > i64::MAX as u128 {
                i64::MAX
            } else {
                us as i64
            }
        } else {
            let us = older.0.duration_since(newer.0).as_micros();
            if us > i64::MAX as u128 {
                i64::MIN
            } else {
                -(us as i64)
            }
        }
    }

    /// Signed difference as **floating-point seconds** (`newer − older`).
    ///
    /// Convenience helper for progress display and rate calculations where
    /// sub-second precision is useful but an integer representation is not
    /// required.
    #[inline]
    pub fn diff_secs(newer: CurlTime, older: CurlTime) -> f64 {
        if newer.0 >= older.0 {
            newer.0.duration_since(older.0).as_secs_f64()
        } else {
            -older.0.duration_since(newer.0).as_secs_f64()
        }
    }

    // -----------------------------------------------------------------------
    // Conversion helpers
    // -----------------------------------------------------------------------

    /// Duration from `earlier` to `self`.
    ///
    /// Returns [`Duration::ZERO`] when `self` precedes `earlier`, preventing
    /// panics that [`Instant::duration_since`] would otherwise produce on some
    /// platforms.
    #[inline]
    pub fn to_duration_since(self, earlier: CurlTime) -> Duration {
        if self.0 >= earlier.0 {
            self.0.duration_since(earlier.0)
        } else {
            Duration::ZERO
        }
    }

    /// Duration elapsed since this timestamp was captured.
    ///
    /// Wraps [`Instant::elapsed`]. Always returns a non-negative value
    /// because [`Instant`] is monotonic.
    #[inline]
    pub fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }

    /// Add (or subtract) milliseconds to produce a new timestamp.
    ///
    /// Used for computing timeout deadlines. When `ms` is negative the
    /// timestamp moves backward. Overflow and underflow are handled
    /// defensively:
    ///
    /// * **Positive overflow** — returns `self` unchanged (matching curl's
    ///   defensive clamping).
    /// * **Negative underflow** — clamps to [`CurlTime::zero`] (the
    ///   program-start epoch). A `CurlTime` is never allowed to precede
    ///   program start, matching the semantic range of the type.
    #[inline]
    pub fn add_ms(&self, ms: i64) -> CurlTime {
        if ms >= 0 {
            // Positive offset — add duration; checked_add returns None on
            // Instant overflow (extremely unlikely).
            match self.0.checked_add(Duration::from_millis(ms as u64)) {
                Some(inst) => CurlTime(inst),
                None => *self,
            }
        } else {
            // Negative offset — subtract and clamp to program start.
            let abs_ms = ms.unsigned_abs();
            let subtract_dur = Duration::from_millis(abs_ms);
            let start = program_start();

            if self.0 >= start {
                // Compute how far self is past program start.
                let offset = self.0.duration_since(start);
                if offset >= subtract_dur {
                    // Result stays at or after program start.
                    CurlTime(start + (offset - subtract_dur))
                } else {
                    // Subtraction would cross below program start — clamp.
                    CurlTime::zero()
                }
            } else {
                // Already before program start (shouldn't happen normally).
                CurlTime::zero()
            }
        }
    }

    /// Milliseconds since program start (the [`zero`](Self::zero) epoch).
    ///
    /// Useful for logging and trace output where a monotonic but
    /// human-readable reference is preferred over wall-clock time.
    #[inline]
    pub fn as_ms_since_epoch(&self) -> u64 {
        let ms = self.to_duration_since(CurlTime::zero()).as_millis();
        // Clamp to u64::MAX — astronomically unlikely to overflow but we
        // match the defensive style of the C codebase.
        if ms > u64::MAX as u128 {
            u64::MAX
        } else {
            ms as u64
        }
    }

    /// Human-readable timestamp for debug / verbose output.
    ///
    /// Formats as `SSSSS.mmm` where `SSSSS` is total seconds since program
    /// start and `mmm` is the sub-second millisecond remainder. This mirrors
    /// curl's `--trace-time` diagnostic timestamp granularity.
    pub fn format_timestamp(&self) -> String {
        let dur = self.to_duration_since(CurlTime::zero());
        let total_secs = dur.as_secs();
        let millis = dur.subsec_millis();
        format!("{total_secs}.{millis:03}")
    }
}

// ---------------------------------------------------------------------------
// System (wall-clock) time helpers
// ---------------------------------------------------------------------------

/// Current wall-clock time as a Unix timestamp (seconds since the epoch).
///
/// Equivalent to C `time(NULL)`. This **must not** be used for interval
/// measurement — it is subject to NTP adjustments, leap seconds, and manual
/// clock changes. Use [`CurlTime::now`] for durations and timeouts.
///
/// Returns the current time as `i64` (matching C `time_t`). On the
/// astronomically unlikely failure of [`SystemTime::now`] being before
/// [`UNIX_EPOCH`] (system clock set to before 1970), returns `0`.
#[inline]
pub fn system_now() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(dur) => {
            let secs = dur.as_secs();
            // Clamp to i64::MAX to match C time_t range.
            if secs > i64::MAX as u64 {
                i64::MAX
            } else {
                secs as i64
            }
        }
        // System clock before UNIX_EPOCH — return 0 defensively.
        Err(_) => 0,
    }
}

/// Convert a Unix timestamp (seconds since the epoch) to [`SystemTime`].
///
/// Matches C patterns that convert `time_t` values — from cookies, HTTP date
/// headers, and X.509 certificates — into time representations for
/// comparison and formatting.
///
/// # Errors
///
/// Returns [`CurlError::BadFunctionArgument`] if `secs` is negative, since
/// pre-1970 timestamps are not meaningful for curl's use cases (cookie
/// expiry, certificate validity, etc.). This mirrors the C `curlx_gmtime`
/// function which returns `CURLE_BAD_FUNCTION_ARGUMENT` on invalid input.
pub fn from_unix_timestamp(secs: i64) -> Result<SystemTime, CurlError> {
    if secs < 0 {
        return Err(CurlError::BadFunctionArgument);
    }
    Ok(UNIX_EPOCH + Duration::from_secs(secs as u64))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn now_returns_incrementing_values() {
        let t1 = CurlTime::now();
        // Tiny sleep to ensure monotonic progression.
        thread::sleep(Duration::from_millis(1));
        let t2 = CurlTime::now();
        assert!(t2 > t1, "CurlTime::now() must be monotonically increasing");
    }

    #[test]
    fn zero_is_consistent() {
        let z1 = CurlTime::zero();
        let z2 = CurlTime::zero();
        assert_eq!(z1, z2, "CurlTime::zero() must return the same value");
    }

    #[test]
    fn zero_is_before_now() {
        let z = CurlTime::zero();
        // Tiny sleep to guarantee separation.
        thread::sleep(Duration::from_millis(1));
        let n = CurlTime::now();
        assert!(n >= z, "CurlTime::now() must be >= CurlTime::zero()");
    }

    #[test]
    fn diff_ms_positive() {
        let older = CurlTime::now();
        thread::sleep(Duration::from_millis(50));
        let newer = CurlTime::now();
        let diff = CurlTime::diff_ms(newer, older);
        // Allow some scheduling jitter — at least 30 ms, at most 500 ms.
        assert!(diff >= 30, "diff_ms should be >= 30, got {diff}");
        assert!(diff < 500, "diff_ms should be < 500, got {diff}");
    }

    #[test]
    fn diff_ms_negative() {
        let older = CurlTime::now();
        thread::sleep(Duration::from_millis(50));
        let newer = CurlTime::now();
        // Swapped arguments → negative result.
        let diff = CurlTime::diff_ms(older, newer);
        assert!(diff < 0, "swapped diff_ms should be negative, got {diff}");
    }

    #[test]
    fn diff_ms_same_instant() {
        let t = CurlTime::now();
        assert_eq!(CurlTime::diff_ms(t, t), 0);
    }

    #[test]
    fn diff_us_positive() {
        let older = CurlTime::now();
        thread::sleep(Duration::from_millis(10));
        let newer = CurlTime::now();
        let diff = CurlTime::diff_us(newer, older);
        // At least ~5000 µs (5 ms), accounting for jitter.
        assert!(diff >= 5_000, "diff_us should be >= 5000, got {diff}");
        assert!(diff < 500_000, "diff_us should be < 500000, got {diff}");
    }

    #[test]
    fn diff_us_negative() {
        let older = CurlTime::now();
        thread::sleep(Duration::from_millis(10));
        let newer = CurlTime::now();
        let diff = CurlTime::diff_us(older, newer);
        assert!(diff < 0, "swapped diff_us should be negative, got {diff}");
    }

    #[test]
    fn diff_secs_positive() {
        let older = CurlTime::now();
        thread::sleep(Duration::from_millis(100));
        let newer = CurlTime::now();
        let diff = CurlTime::diff_secs(newer, older);
        assert!(diff >= 0.05, "diff_secs should be >= 0.05, got {diff}");
        assert!(diff < 1.0, "diff_secs should be < 1.0, got {diff}");
    }

    #[test]
    fn diff_secs_negative() {
        let older = CurlTime::now();
        thread::sleep(Duration::from_millis(50));
        let newer = CurlTime::now();
        let diff = CurlTime::diff_secs(older, newer);
        assert!(diff < 0.0, "swapped diff_secs should be negative");
    }

    #[test]
    fn to_duration_since_normal() {
        let earlier = CurlTime::now();
        thread::sleep(Duration::from_millis(10));
        let later = CurlTime::now();
        let dur = later.to_duration_since(earlier);
        assert!(dur >= Duration::from_millis(5));
    }

    #[test]
    fn to_duration_since_reversed_returns_zero() {
        let earlier = CurlTime::now();
        thread::sleep(Duration::from_millis(10));
        let later = CurlTime::now();
        let dur = earlier.to_duration_since(later);
        assert_eq!(dur, Duration::ZERO);
    }

    #[test]
    fn elapsed_is_non_negative() {
        let t = CurlTime::now();
        let e = t.elapsed();
        // Elapsed must be >= 0 (Duration is unsigned).
        assert!(e >= Duration::ZERO);
    }

    #[test]
    fn add_ms_positive() {
        let t = CurlTime::now();
        let t_plus = t.add_ms(100);
        let diff = CurlTime::diff_ms(t_plus, t);
        assert_eq!(diff, 100, "add_ms(100) should advance by 100 ms");
    }

    #[test]
    fn add_ms_zero() {
        let t = CurlTime::now();
        let t_same = t.add_ms(0);
        assert_eq!(t, t_same, "add_ms(0) should return the same time");
    }

    #[test]
    fn add_ms_negative_within_range() {
        let _base = CurlTime::now();
        thread::sleep(Duration::from_millis(100));
        let later = CurlTime::now();
        let moved_back = later.add_ms(-50);
        // moved_back should be between base and later.
        let diff_from_later = CurlTime::diff_ms(later, moved_back);
        assert_eq!(diff_from_later, 50);
    }

    #[test]
    fn add_ms_negative_underflow_clamps_to_zero() {
        let t = CurlTime::zero();
        // Subtracting an astronomically large value should force an
        // `Instant` underflow (`checked_sub` → None) and clamp to zero.
        let result = t.add_ms(i64::MIN);
        assert_eq!(result, CurlTime::zero());
    }

    #[test]
    fn as_ms_since_epoch_for_zero() {
        let z = CurlTime::zero();
        assert_eq!(z.as_ms_since_epoch(), 0);
    }

    #[test]
    fn as_ms_since_epoch_increases() {
        // Allow the program-start sentinel to initialise.
        let _ = CurlTime::zero();
        thread::sleep(Duration::from_millis(10));
        let t = CurlTime::now();
        let ms = t.as_ms_since_epoch();
        assert!(ms >= 5, "as_ms_since_epoch should be >= 5, got {ms}");
    }

    #[test]
    fn format_timestamp_for_zero() {
        let z = CurlTime::zero();
        assert_eq!(z.format_timestamp(), "0.000");
    }

    #[test]
    fn format_timestamp_format() {
        let _ = CurlTime::zero();
        thread::sleep(Duration::from_millis(50));
        let t = CurlTime::now();
        let s = t.format_timestamp();
        // Should look like "N.NNN" — contains a dot, ends with 3 digits.
        assert!(s.contains('.'), "format_timestamp should contain a dot: {s}");
        let parts: Vec<&str> = s.split('.').collect();
        assert_eq!(parts.len(), 2, "format_timestamp should have two parts: {s}");
        assert_eq!(parts[1].len(), 3, "millisecond part should be 3 digits: {s}");
    }

    // -----------------------------------------------------------------------
    // System time helpers
    // -----------------------------------------------------------------------

    #[test]
    fn system_now_returns_positive() {
        let ts = system_now();
        // Any modern system should return a timestamp after 2020-01-01
        // (1_577_836_800).
        assert!(ts > 1_577_836_800, "system_now() looks too small: {ts}");
    }

    #[test]
    fn from_unix_timestamp_valid() {
        let st = from_unix_timestamp(1_000_000_000).expect("valid timestamp");
        let dur = st.duration_since(UNIX_EPOCH).expect("after epoch");
        assert_eq!(dur.as_secs(), 1_000_000_000);
    }

    #[test]
    fn from_unix_timestamp_zero() {
        let st = from_unix_timestamp(0).expect("zero is valid");
        assert_eq!(st, UNIX_EPOCH);
    }

    #[test]
    fn from_unix_timestamp_negative_errors() {
        let result = from_unix_timestamp(-1);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::BadFunctionArgument);
    }

    #[test]
    fn from_unix_timestamp_large() {
        // Year ~3000 — should succeed.
        let st = from_unix_timestamp(32_503_680_000).expect("far future");
        let dur = st.duration_since(UNIX_EPOCH).expect("after epoch");
        assert_eq!(dur.as_secs(), 32_503_680_000);
    }
}
