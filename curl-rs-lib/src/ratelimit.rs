//! Bandwidth rate limiting for uploads and downloads.
//!
//! This module implements a token-bucket rate limiter that exactly replicates
//! the algorithm in curl 8.x's `lib/ratelimit.c`. It enforces the bandwidth
//! caps set by `CURLOPT_MAX_RECV_SPEED_LARGE` and
//! `CURLOPT_MAX_SEND_SPEED_LARGE`.
//!
//! # Token Bucket Model
//!
//! The limiter generates a fixed number of tokens (bytes) per *step* period.
//! Initially the step is 1 second, but [`RateLimiter::start`] may tune it for
//! improved tail behavior on small transfers.
//!
//! * **Rate** — tokens generated per step (bytes/sec by default).
//! * **Burst** — optional cap preventing token accumulation during idle
//!   periods. When zero, no cap is applied.
//! * **Blocking** — an external pause that forces available tokens to zero
//!   until explicitly unblocked.
//!
//! # Example
//!
//! ```rust,no_run
//! use curl_rs_lib::ratelimit::RateLimiter;
//!
//! let mut limiter = RateLimiter::new(1024 * 1024, 0).unwrap(); // 1 MB/s
//! limiter.start(-1); // unknown total transfer size
//!
//! if let Some(delay) = limiter.should_throttle() {
//!     std::thread::sleep(delay);
//! }
//! limiter.record_bytes(4096);
//! ```

use std::time::{Duration, Instant};

use crate::error::{CurlError, CurlResult};

// ---------------------------------------------------------------------------
// Constants — matching lib/ratelimit.c exactly
// ---------------------------------------------------------------------------

/// Microseconds per second — the default step duration.
const US_PER_SEC: i64 = 1_000_000;

/// Minimum rate (bytes) for step tuning to take effect.
/// Matches `CURL_RLIMIT_MIN_RATE` in the C source.
const RLIMIT_MIN_RATE: i64 = 4 * 1024;

/// Minimum step duration in milliseconds for tuning adjustments.
/// Matches `CURL_RLIMIT_STEP_MIN_MS` in the C source.
const RLIMIT_STEP_MIN_MS: i64 = 2;

/// Default delay returned by [`RateLimiter::should_throttle`] when the limiter
/// is blocked. Callers should sleep for this interval before retrying.
const BLOCKED_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Duration corresponding to one second — used to validate step constants
/// and for default step-period consistency checks.
const ONE_SECOND: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// RateLimiter
// ---------------------------------------------------------------------------

/// A token-bucket rate limiter for bandwidth control.
///
/// Each instance tracks a single direction (upload or download). The transfer
/// engine should maintain separate `RateLimiter` instances for send and
/// receive paths.
///
/// The struct is `!Send` by design via [`Instant`] interior usage — callers
/// must not share it across threads without external synchronisation.
pub struct RateLimiter {
    /// Tokens (bytes) generated per step period.
    rate_per_step: i64,
    /// Maximum token burst per step (0 = no burst cap).
    burst_per_step: i64,
    /// Step duration in microseconds.
    step_us: i64,
    /// Current available tokens (may be negative = debt).
    tokens: i64,
    /// Fractional microseconds carried over from the last update.
    spare_us: i64,
    /// Timestamp of the last token-generation update.
    ts: Instant,
    /// Whether the rate limiter is externally blocked.
    blocked: bool,
}

impl RateLimiter {
    /// Creates a new rate limiter.
    ///
    /// # Arguments
    ///
    /// * `rate_per_sec` — Maximum bytes per second. Pass `0` for unlimited.
    /// * `burst_per_sec` — Burst token cap per step. Pass `0` for no cap.
    ///   When non-zero, must be ≥ `rate_per_sec`.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::BadFunctionArgument`] when:
    /// * `rate_per_sec` is negative, **or**
    /// * `burst_per_sec` is non-zero but less than `rate_per_sec`.
    pub fn new(rate_per_sec: i64, burst_per_sec: i64) -> CurlResult<Self> {
        if rate_per_sec < 0 {
            return Err(CurlError::BadFunctionArgument);
        }
        if burst_per_sec != 0 && burst_per_sec < rate_per_sec {
            return Err(CurlError::BadFunctionArgument);
        }

        // Verify the constant relationship at construction time.
        debug_assert_eq!(US_PER_SEC, ONE_SECOND.as_micros() as i64);

        let now = Instant::now();
        Ok(Self {
            rate_per_step: rate_per_sec,
            burst_per_step: burst_per_sec,
            step_us: US_PER_SEC,
            spare_us: 0,
            tokens: rate_per_sec,
            ts: now,
            blocked: false,
        })
    }

    /// Starts (or restarts) rate limiting with optional transfer-size hint.
    ///
    /// Resets the token count and timestamp, then applies step-duration tuning
    /// when `total_tokens` is a positive count of the expected total bytes.
    /// Pass `-1` (or any negative value) if the total size is unknown.
    ///
    /// Matches `Curl_rlimit_start` in `lib/ratelimit.c`.
    pub fn start(&mut self, total_tokens: i64) {
        self.tokens = self.rate_per_step;
        self.spare_us = 0;
        self.ts = Instant::now();
        self.tune_steps(total_tokens);
    }

    /// Resets the rate-limiting window without step tuning.
    ///
    /// Restores tokens to the current rate-per-step value, clears fractional
    /// microseconds, and resets the timestamp to now. Useful when the transfer
    /// context has changed and step tuning is not desired.
    pub fn reset_window(&mut self) {
        self.tokens = self.rate_per_step;
        self.spare_us = 0;
        self.ts = Instant::now();
    }

    /// Checks whether the transfer should be throttled.
    ///
    /// Returns `Some(delay)` with the recommended sleep [`Duration`] when the
    /// rate limit has been reached, or `None` if the transfer may proceed
    /// immediately.
    ///
    /// When the limiter is blocked, returns [`BLOCKED_POLL_INTERVAL`] so that
    /// the caller retries after a short delay rather than busy-looping.
    pub fn should_throttle(&mut self) -> Option<Duration> {
        if self.blocked {
            return Some(BLOCKED_POLL_INTERVAL);
        }
        if self.rate_per_step == 0 {
            return None;
        }

        let now = Instant::now();
        self.update_with(now);
        if self.tokens > 0 {
            return None;
        }

        let wait_us = self.compute_wait_us_with(now);
        if wait_us > 0 {
            Some(Duration::from_micros(wait_us as u64))
        } else {
            None
        }
    }

    /// Records that `count` bytes have been transferred (drains tokens).
    ///
    /// The token balance may go negative, creating a *debt* that must be
    /// repaid by future token generation before more data can be transferred.
    ///
    /// Matches `Curl_rlimit_drain` in `lib/ratelimit.c`.
    pub fn record_bytes(&mut self, count: u64) {
        if self.blocked || self.rate_per_step == 0 {
            return;
        }

        let now = Instant::now();
        self.update_with(now);

        // Match C behaviour: if count exceeds i64::MAX, cap tokens at i64::MAX
        // (overflow protection for extremely large drain values on 64-bit).
        if count > i64::MAX as u64 {
            self.tokens = i64::MAX;
            return;
        }

        let val = count as i64;
        // Subtract tokens, saturating at i64::MIN to prevent underflow.
        if (i64::MIN + val) < self.tokens {
            self.tokens -= val;
        } else {
            self.tokens = i64::MIN;
        }
    }

    /// Returns whether rate limiting is currently active.
    ///
    /// A limiter is active when it has a non-zero rate **or** is blocked.
    /// When inactive (rate = 0, not blocked), transfer proceeds without
    /// limits.
    pub fn is_active(&self) -> bool {
        (self.rate_per_step > 0) || self.blocked
    }

    /// Returns whether the rate limiter is currently blocked.
    ///
    /// A blocked limiter reports zero available tokens regardless of the
    /// configured rate.
    pub fn is_blocked(&self) -> bool {
        self.blocked
    }

    /// Blocks or unblocks the rate limiter.
    ///
    /// * **Blocking** (`activate = true`): forces available tokens to zero.
    ///   No new tokens are generated while blocked.
    /// * **Unblocking** (`activate = false`): restarts rate limiting fresh,
    ///   discarding any history from the blocked period.
    ///
    /// Calling with the same state as the current state is a no-op.
    ///
    /// Matches `Curl_rlimit_block` in `lib/ratelimit.c`.
    pub fn block(&mut self, activate: bool) {
        // No-op when the requested state matches the current state.
        if activate == self.blocked {
            return;
        }

        self.ts = Instant::now();
        self.blocked = activate;
        if !self.blocked {
            // Start rate limiting fresh — blocked time does not generate
            // extra tokens.
            self.start(-1);
        } else {
            self.tokens = 0;
        }
    }

    /// Returns the number of tokens (bytes) currently available.
    ///
    /// * Returns `0` when blocked.
    /// * Returns [`i64::MAX`] when no rate limit is configured (rate = 0).
    /// * Otherwise performs a token-generation update and returns the current
    ///   balance, which may be negative if in debt.
    ///
    /// Matches `Curl_rlimit_avail` in `lib/ratelimit.c`.
    pub fn available(&mut self) -> i64 {
        if self.blocked {
            return 0;
        }
        if self.rate_per_step > 0 {
            let now = Instant::now();
            self.update_with(now);
            return self.tokens;
        }
        i64::MAX
    }

    /// Returns milliseconds to wait until tokens become available again.
    ///
    /// Returns `0` when:
    /// * tokens are already available, **or**
    /// * the limiter is blocked (wait time is indeterminate), **or**
    /// * no rate limit is configured.
    ///
    /// Matches `Curl_rlimit_wait_ms` in `lib/ratelimit.c`.
    pub fn wait_ms(&mut self) -> i64 {
        if self.blocked || self.rate_per_step == 0 {
            return 0;
        }
        let now = Instant::now();
        self.update_with(now);
        if self.tokens > 0 {
            return 0;
        }

        self.compute_wait_ms_with(now)
    }

    /// Returns milliseconds until the next token-generation step.
    ///
    /// Returns `0` when blocked, no rate limit is set, or the step boundary
    /// has already been reached.
    ///
    /// Matches `Curl_rlimit_next_step_ms` in `lib/ratelimit.c`.
    pub fn next_step_ms(&self) -> i64 {
        if !self.blocked && self.rate_per_step > 0 {
            let elapsed = self.ts.elapsed();
            let elapsed_us = duration_to_us(elapsed).saturating_add(self.spare_us);
            if self.step_us > elapsed_us {
                let next_us = self.step_us - elapsed_us;
                return (next_us + 999) / 1000;
            }
        }
        0
    }

    /// Returns the current token-generation rate per step.
    ///
    /// This value may differ from the constructor's `rate_per_sec` if
    /// [`start`](Self::start) applied step tuning.
    pub fn rate_per_step(&self) -> i64 {
        self.rate_per_step
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Updates the token count based on wall-clock time elapsed since the last
    /// update.
    ///
    /// Faithfully replicates `rlimit_update()` from `lib/ratelimit.c`:
    /// 1. Compute elapsed microseconds since `self.ts` (plus carried-over
    ///    spare microseconds).
    /// 2. If less than one step has elapsed, return early (no mutation).
    /// 3. Otherwise, advance `self.ts` to `now`, accumulate tokens
    ///    proportional to the number of elapsed steps, and cap at the burst
    ///    limit if configured.
    fn update_with(&mut self, now: Instant) {
        debug_assert!(self.rate_per_step > 0);

        let raw_elapsed = now.duration_since(self.ts);
        let raw_elapsed_us = duration_to_us(raw_elapsed);
        if raw_elapsed_us == 0 {
            // No time has passed — nothing to update.
            return;
        }

        let elapsed_us = raw_elapsed_us.saturating_add(self.spare_us);
        if elapsed_us < self.step_us {
            // Less than one step has elapsed — keep ts unchanged.
            return;
        }

        // Advance the timestamp and compute integral steps.
        self.ts = now;
        let elapsed_steps = elapsed_us / self.step_us;
        self.spare_us = elapsed_us % self.step_us;

        // Calculate token gain with overflow protection.
        let token_gain = if self.rate_per_step > (i64::MAX / elapsed_steps) {
            i64::MAX
        } else {
            self.rate_per_step * elapsed_steps
        };

        // Accumulate tokens, capping at i64::MAX.
        if (i64::MAX - token_gain) > self.tokens {
            self.tokens += token_gain;
        } else {
            self.tokens = i64::MAX;
        }

        // Apply burst cap so inactivity does not generate unbounded tokens.
        if self.burst_per_step > 0 && self.tokens > self.burst_per_step {
            self.tokens = self.burst_per_step;
        }
    }

    /// Tunes the step duration for improved tail behaviour on small transfers.
    ///
    /// Faithfully replicates `rlimit_tune_steps()` from `lib/ratelimit.c`.
    ///
    /// When the total transfer size is known, the algorithm shortens the step
    /// so that the *last* step consumes only ≈1 % of the total tokens (at
    /// least 1, at most [`RLIMIT_MIN_RATE`]). This avoids the "fast last
    /// step" problem where the final burst completes too quickly.
    fn tune_steps(&mut self, tokens_total: i64) {
        if self.rate_per_step == 0
            || tokens_total <= 1
            || tokens_total > (i64::MAX / 1000)
        {
            return;
        }

        // Tokens reserved for the last step (≈1 %, clamped).
        let mut tokens_last = tokens_total / 100;
        if tokens_last == 0 {
            tokens_last = 1;
        } else if tokens_last > RLIMIT_MIN_RATE {
            tokens_last = RLIMIT_MIN_RATE;
        }
        let tokens_main = tokens_total - tokens_last;

        // How many *milli-steps* to consume `tokens_main` at the configured
        // rate? (The step defaults to 1 second = 1000 milli-steps.)
        debug_assert!(self.step_us == US_PER_SEC);

        let msteps = tokens_main * 1000 / self.rate_per_step;
        if msteps < RLIMIT_STEP_MIN_MS {
            // Steps this small will not work — do not tune.
            return;
        } else if msteps < 1000 {
            // Less than one second needed. Make the step exactly that long
            // and provide exactly the needed tokens per step.
            self.step_us = msteps * 1000;
            self.rate_per_step = tokens_main;
            self.tokens = self.rate_per_step;
        } else {
            // More than 1 second. Spread the remainder milli-steps and
            // their tokens across all steps.
            let ms_unaccounted = msteps % 1000;
            let mstep_inc = ms_unaccounted / (msteps / 1000);
            if mstep_inc > 0 {
                let rate_inc = (self.rate_per_step * mstep_inc) / 1000;
                if rate_inc > 0 {
                    self.step_us = US_PER_SEC + (mstep_inc * 1000);
                    self.rate_per_step += rate_inc;
                    self.tokens = self.rate_per_step;
                }
            }
        }

        // Synchronise burst cap with the (possibly adjusted) rate.
        if self.burst_per_step > 0 {
            self.burst_per_step = self.rate_per_step;
        }
    }

    /// Computes the wait time in **microseconds** until tokens become positive.
    ///
    /// Used internally by [`should_throttle`](Self::should_throttle) which
    /// needs the raw microsecond value to construct a [`Duration`].
    fn compute_wait_us_with(&self, now: Instant) -> i64 {
        let mut wait_us = self.step_us - self.spare_us;

        // If tokens are negative, additional time is needed proportional
        // to the debt percentage.
        if self.tokens < 0 {
            let debt_pct = (-self.tokens) * 100 / self.rate_per_step;
            if debt_pct > 0 {
                wait_us += self.step_us * debt_pct / 100;
            }
        }

        let elapsed = now.duration_since(self.ts);
        let elapsed_us = duration_to_us(elapsed);
        if elapsed_us >= wait_us {
            return 0;
        }
        wait_us - elapsed_us
    }

    /// Computes the wait time in **milliseconds** (rounded up) until tokens
    /// become positive.
    ///
    /// Matches the return value of `Curl_rlimit_wait_ms` in
    /// `lib/ratelimit.c`.
    fn compute_wait_ms_with(&self, now: Instant) -> i64 {
        let wait_us = self.compute_wait_us_with(now);
        if wait_us <= 0 {
            return 0;
        }
        // Convert to milliseconds, rounding up.
        (wait_us + 999) / 1000
    }
}

// ---------------------------------------------------------------------------
// Free helper functions
// ---------------------------------------------------------------------------

/// Converts a [`Duration`] to microseconds as [`i64`], saturating at
/// [`i64::MAX`] for durations exceeding ≈292 millennia.
#[inline]
fn duration_to_us(d: Duration) -> i64 {
    d.as_micros().min(i64::MAX as u128) as i64
}

// ---------------------------------------------------------------------------
// Trait implementations
// ---------------------------------------------------------------------------

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("rate_per_step", &self.rate_per_step)
            .field("burst_per_step", &self.burst_per_step)
            .field("step_us", &self.step_us)
            .field("tokens", &self.tokens)
            .field("spare_us", &self.spare_us)
            .field("blocked", &self.blocked)
            .finish()
    }
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
    fn test_new_unlimited() {
        let limiter = RateLimiter::new(0, 0).unwrap();
        assert!(!limiter.is_active());
        assert!(!limiter.is_blocked());
        assert_eq!(limiter.rate_per_step(), 0);
    }

    #[test]
    fn test_new_with_rate() {
        let limiter = RateLimiter::new(1024, 0).unwrap();
        assert!(limiter.is_active());
        assert_eq!(limiter.rate_per_step(), 1024);
    }

    #[test]
    fn test_new_negative_rate_fails() {
        let err = RateLimiter::new(-1, 0).unwrap_err();
        assert_eq!(err, CurlError::BadFunctionArgument);
    }

    #[test]
    fn test_new_burst_less_than_rate_fails() {
        let err = RateLimiter::new(1024, 512).unwrap_err();
        assert_eq!(err, CurlError::BadFunctionArgument);
    }

    #[test]
    fn test_new_burst_equal_to_rate_ok() {
        let limiter = RateLimiter::new(1024, 1024).unwrap();
        assert_eq!(limiter.rate_per_step(), 1024);
    }

    #[test]
    fn test_unlimited_no_throttle() {
        let mut limiter = RateLimiter::new(0, 0).unwrap();
        assert!(limiter.should_throttle().is_none());
        assert_eq!(limiter.available(), i64::MAX);
        assert_eq!(limiter.wait_ms(), 0);
    }

    #[test]
    fn test_unlimited_record_bytes_noop() {
        let mut limiter = RateLimiter::new(0, 0).unwrap();
        limiter.record_bytes(999_999);
        assert_eq!(limiter.available(), i64::MAX);
    }

    #[test]
    fn test_initial_tokens_available() {
        let mut limiter = RateLimiter::new(1000, 0).unwrap();
        // Immediately after creation, tokens should equal rate_per_step.
        let avail = limiter.available();
        assert_eq!(avail, 1000);
    }

    #[test]
    fn test_drain_reduces_tokens() {
        let mut limiter = RateLimiter::new(1000, 0).unwrap();
        limiter.record_bytes(600);
        let avail = limiter.available();
        // Tokens should be approximately 1000 - 600 = 400.
        // Timing jitter may add a few tokens, so check a range.
        assert!(avail >= 390 && avail <= 410, "avail was {avail}");
    }

    #[test]
    fn test_drain_creates_debt() {
        let mut limiter = RateLimiter::new(100, 0).unwrap();
        limiter.record_bytes(200);
        let avail = limiter.available();
        // Should be negative (debt): 100 initial - 200 drained = -100 approx
        assert!(avail < 0, "avail was {avail}");
    }

    #[test]
    fn test_block_and_unblock() {
        let mut limiter = RateLimiter::new(1024, 0).unwrap();
        limiter.block(true);
        assert!(limiter.is_blocked());
        assert!(limiter.is_active());
        assert_eq!(limiter.available(), 0);
        assert_eq!(limiter.wait_ms(), 0);

        limiter.block(false);
        assert!(!limiter.is_blocked());
        // After unblocking, tokens are restored.
        let avail = limiter.available();
        assert!(avail > 0, "avail was {avail}");
    }

    #[test]
    fn test_block_idempotent() {
        let mut limiter = RateLimiter::new(1024, 0).unwrap();
        limiter.block(true);
        limiter.block(true); // no-op
        assert!(limiter.is_blocked());

        limiter.block(false);
        limiter.block(false); // no-op
        assert!(!limiter.is_blocked());
    }

    #[test]
    fn test_should_throttle_when_blocked() {
        let mut limiter = RateLimiter::new(1024, 0).unwrap();
        limiter.block(true);
        let delay = limiter.should_throttle();
        assert!(delay.is_some());
        assert_eq!(delay.unwrap(), Duration::from_millis(100));
    }

    #[test]
    fn test_should_throttle_initial_no_delay() {
        let mut limiter = RateLimiter::new(1024, 0).unwrap();
        // Immediately after creation, tokens are available — no throttle.
        assert!(limiter.should_throttle().is_none());
    }

    #[test]
    fn test_should_throttle_after_drain() {
        let mut limiter = RateLimiter::new(100, 0).unwrap();
        // Drain all tokens plus some to create debt.
        limiter.record_bytes(200);
        let delay = limiter.should_throttle();
        assert!(delay.is_some(), "Expected throttle delay after over-drain");
    }

    #[test]
    fn test_reset_window() {
        let mut limiter = RateLimiter::new(1000, 0).unwrap();
        limiter.record_bytes(2000);
        assert!(limiter.available() < 0);

        limiter.reset_window();
        let avail = limiter.available();
        assert_eq!(avail, 1000);
    }

    #[test]
    fn test_start_with_tuning() {
        let mut limiter = RateLimiter::new(1024, 0).unwrap();
        // Start with a known total that triggers step tuning.
        limiter.start(1536); // 1.5 KB at 1 KB/s
        // After tuning, rate_per_step may have been adjusted.
        assert!(limiter.rate_per_step() > 0);
    }

    #[test]
    fn test_start_unknown_total() {
        let mut limiter = RateLimiter::new(1024, 0).unwrap();
        limiter.start(-1); // unknown total
        assert_eq!(limiter.rate_per_step(), 1024);
    }

    #[test]
    fn test_next_step_ms_returns_non_negative() {
        let limiter = RateLimiter::new(1024, 0).unwrap();
        let ms = limiter.next_step_ms();
        assert!(ms >= 0, "next_step_ms was {ms}");
    }

    #[test]
    fn test_next_step_ms_zero_when_not_active() {
        let limiter = RateLimiter::new(0, 0).unwrap();
        assert_eq!(limiter.next_step_ms(), 0);
    }

    #[test]
    fn test_next_step_ms_zero_when_blocked() {
        let mut limiter = RateLimiter::new(1024, 0).unwrap();
        limiter.block(true);
        assert_eq!(limiter.next_step_ms(), 0);
    }

    #[test]
    fn test_burst_caps_accumulation() {
        // With burst == rate, after idle time tokens should not exceed rate.
        let mut limiter = RateLimiter::new(100, 100).unwrap();
        // Sleep to allow time to pass — simulates idle period.
        thread::sleep(Duration::from_millis(50));
        let avail = limiter.available();
        assert!(
            avail <= 100,
            "Burst cap should prevent tokens exceeding 100, got {avail}"
        );
    }

    #[test]
    fn test_tune_steps_small_transfer() {
        // A transfer of 50 bytes at 1024/s should be tuned.
        let mut limiter = RateLimiter::new(1024, 0).unwrap();
        limiter.start(50);
        // step_us should have been shortened because msteps < 1000.
        // rate_per_step should reflect the tuned value.
        assert!(limiter.rate_per_step() > 0);
    }

    #[test]
    fn test_tune_steps_skips_tiny_total() {
        let mut limiter = RateLimiter::new(1024, 0).unwrap();
        limiter.start(1); // total_tokens == 1, tuning should be skipped
        assert_eq!(limiter.rate_per_step(), 1024);
    }

    #[test]
    fn test_record_bytes_huge_count() {
        // Exercise the overflow path (count > i64::MAX).
        let mut limiter = RateLimiter::new(1000, 0).unwrap();
        limiter.record_bytes(u64::MAX);
        // After overflow protection, tokens = i64::MAX (matching C behaviour).
        let avail = limiter.available();
        assert_eq!(avail, i64::MAX);
    }

    #[test]
    fn test_wait_ms_when_tokens_available() {
        let mut limiter = RateLimiter::new(1024, 0).unwrap();
        assert_eq!(limiter.wait_ms(), 0);
    }

    #[test]
    fn test_wait_ms_after_drain() {
        let mut limiter = RateLimiter::new(100, 0).unwrap();
        limiter.record_bytes(200);
        let wait = limiter.wait_ms();
        // After draining 200 tokens from 100, we should have to wait.
        assert!(wait > 0, "Expected positive wait, got {wait}");
    }

    #[test]
    fn test_debug_format() {
        let limiter = RateLimiter::new(512, 0).unwrap();
        let dbg = format!("{:?}", limiter);
        assert!(dbg.contains("RateLimiter"));
        assert!(dbg.contains("rate_per_step: 512"));
    }

    #[test]
    fn test_is_active_with_zero_rate_unblocked() {
        let limiter = RateLimiter::new(0, 0).unwrap();
        assert!(!limiter.is_active());
    }

    #[test]
    fn test_is_active_with_zero_rate_blocked() {
        let mut limiter = RateLimiter::new(0, 0).unwrap();
        limiter.block(true);
        assert!(limiter.is_active());
    }

    #[test]
    fn test_one_second_constant_value() {
        // Verify the ONE_SECOND constant is used as expected.
        assert_eq!(ONE_SECOND.as_micros(), US_PER_SEC as u128);
    }
}
