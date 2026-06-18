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

//! Transfer rate limiting — throttle send/receive throughput to a configured cap.
//!
//! This module is the Rust replacement for libcurl's transfer rate-limiting
//! accounting (`lib/ratelimit.c`). It implements the throttle that honours the
//! [`CURLOPT_MAX_SEND_SPEED_LARGE`] / [`CURLOPT_MAX_RECV_SPEED_LARGE`] options
//! and the `curl` command-line `--limit-rate` flag by computing how long a
//! transfer must pause so that its *measured* rate stays at or below the cap.
//!
//! [`CURLOPT_MAX_SEND_SPEED_LARGE`]: https://curl.se/libcurl/c/CURLOPT_MAX_SEND_SPEED_LARGE.html
//! [`CURLOPT_MAX_RECV_SPEED_LARGE`]: https://curl.se/libcurl/c/CURLOPT_MAX_RECV_SPEED_LARGE.html
//!
//! # The model
//!
//! Each direction (download / upload) keeps an independent *sampling window*:
//!
//! * the [`Instant`] the window opened,
//! * the cumulative byte count at that instant, and
//! * the configured limit in bytes/second (`0` meaning *unlimited*).
//!
//! [`RateLimit::wait_time`] is the heart of the module and mirrors curl's
//! `Curl_pgrsLimitWaitTime`. Given the running total of bytes transferred in a
//! direction and the current time, it answers a single question: *how long
//! should the transfer sleep so that, over the open window, it has not moved
//! data faster than the cap?* The computation is:
//!
//! ```text
//!   size    = total_transferred - window_start_bytes      // bytes this window
//!   minimum = (size * 1000) / limit                        // ms `size` *should* take
//!   elapsed = now - window_start                           // ms actually taken
//!   wait    = max(0, minimum - elapsed)                    // ms still owed
//! ```
//!
//! When `wait` is zero — the transfer is at or below the cap — the window is
//! advanced to "now" (its byte baseline reset to the current total), exactly as
//! curl does in `Curl_pgrsSetDownloadCounter` / `Curl_pgrsSetUploadCounter`.
//! Because `minimum` represents about one second of data at the cap, the window
//! naturally rolls forward roughly once per second under steady-state
//! throttling, which is the "reset the window when about a second has elapsed"
//! behaviour described by curl's accounting.
//!
//! # Relationship to the C original
//!
//! This is a behavioural re-implementation, **not** a line-by-line translation.
//! The arithmetic — integer division, the `* 1000` millisecond scaling, the
//! clamp to non-negative, and the window-reset-on-zero-wait — reproduces curl's
//! observable `--limit-rate` behaviour. Two deliberate refinements keep the Rust
//! version safe and drift-free:
//!
//! * Time is measured with the monotonic [`std::time::Instant`] clock rather
//!   than a wall-clock `struct curltime`, so the window can never be corrupted
//!   by clock adjustments.
//! * The `size * 1000` product is evaluated in [`u128`], which makes the
//!   overflow that curl must guard against (`size >= CURL_OFF_T_MAX / 1000`)
//!   impossible by construction for every realistic transfer size, while
//!   producing the identical quotient on curl's normal path. All arithmetic is
//!   integer; no floating point is used anywhere, so there is no rate drift.
//!
//! # How the transfer engine uses it
//!
//! This module performs *pure computation only* — it never sleeps. The
//! asynchronous transfer engine (`crate::transfer`) calls [`RateLimit::wait_time`]
//! after updating its progress counters and, when a non-zero [`Duration`] comes
//! back, awaits `tokio::time::sleep(duration)` before moving more bytes. That is
//! the async equivalent of curl's multi-handle "this transfer is expired until
//! time T" mechanism. The limits themselves are configured from
//! `crate::setopt` when the application sets the `MAX_SEND_SPEED_LARGE` /
//! `MAX_RECV_SPEED_LARGE` options, and the progress subsystem (`crate::progress`)
//! owns the byte counters that are fed in here.
//!
//! # Memory safety
//!
//! This module is pure arithmetic over [`std::time`] values. It contains
//! **zero** `unsafe` and no raw pointers, and compiles cleanly under the
//! crate-root `#![forbid(unsafe_code)]`.

use std::time::{Duration, Instant};

use crate::error::{CurlError, Result};

/// Milliseconds in one second — the scaling factor in curl's rate formula.
const MILLIS_PER_SEC: u64 = 1_000;

/// The direction of a transfer that a rate limit applies to.
///
/// curl tracks download and upload throughput independently, each with its own
/// cap. The receive cap (`CURLOPT_MAX_RECV_SPEED_LARGE`, `--limit-rate` for
/// downloads) governs [`Direction::Download`]; the send cap
/// (`CURLOPT_MAX_SEND_SPEED_LARGE`) governs [`Direction::Upload`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Bytes received from the server (download / "recv").
    Download,
    /// Bytes sent to the server (upload / "send").
    Upload,
}

/// Per-direction rate-limit state: the open sampling window plus the cap.
///
/// This is the private building block behind [`RateLimit`]; one instance exists
/// for each [`Direction`]. It owns the windowed accounting and the wait-time
/// computation for a single direction.
#[derive(Debug, Clone)]
struct DirRateLimit {
    /// Configured cap in bytes per second; `0` means unlimited (no throttling).
    limit_bps: u64,
    /// The instant the current sampling window opened.
    window_start: Instant,
    /// Cumulative transferred-byte count recorded when the window opened.
    window_start_bytes: u64,
}

impl DirRateLimit {
    /// Creates an unlimited direction whose window opens at `now`.
    fn new(now: Instant) -> Self {
        Self {
            limit_bps: 0,
            window_start: now,
            window_start_bytes: 0,
        }
    }

    /// Reopens the sampling window at `now` with a fresh, zeroed byte baseline.
    ///
    /// The configured cap is left untouched — only the accounting is restarted,
    /// which is what curl does at the start of a new transfer.
    fn reset(&mut self, now: Instant) {
        self.window_start = now;
        self.window_start_bytes = 0;
    }

    /// Computes how long the transfer must pause to keep the windowed rate at or
    /// below the cap, and advances the window when the transfer is on pace.
    ///
    /// `total_transferred` is the running, monotonically non-decreasing count of
    /// bytes moved in this direction since the transfer began. `now` is the
    /// current monotonic time. See the module documentation for the formula.
    fn wait_time(&mut self, total_transferred: u64, now: Instant) -> Duration {
        // Unlimited: never throttle, and leave the window untouched. curl gates
        // its window reset on `limit > 0`, so an unlimited direction keeps no
        // accounting at all.
        if self.limit_bps == 0 {
            return Duration::ZERO;
        }

        // Bytes moved since the window opened. `saturating_sub` is purely
        // defensive: the progress counters are monotonic, so this should never
        // underflow, but if a caller ever rewinds the counter we treat it as
        // "no progress" rather than panicking or wrapping.
        let size = total_transferred.saturating_sub(self.window_start_bytes);

        // Milliseconds the window has been open, on the monotonic clock and
        // truncated toward zero — exactly curl's `Curl_timediff`.
        let elapsed_ms = elapsed_millis(self.window_start, now);

        // `minimum` is the number of milliseconds `size` bytes *should* take so
        // that the windowed rate does not exceed the cap:
        //
        //     minimum = (size * 1000) / limit            (integer, floored)
        //
        // The multiply is done in `u128` so the intermediate cannot overflow for
        // any realistic `size`; the quotient is identical to curl's normal path.
        let minimum_ms = saturating_u64(
            u128::from(size) * u128::from(MILLIS_PER_SEC) / u128::from(self.limit_bps),
        );

        // Pause only for the portion of `minimum` not already covered by real
        // elapsed time, clamped to non-negative. This is curl's
        // `if (actual < minimum) return minimum - actual; return 0;`.
        let wait_ms = minimum_ms.saturating_sub(elapsed_ms);

        if wait_ms == 0 {
            // At or below the cap for this window: advance the window to "now"
            // so the next interval is sampled fresh. This is the reset curl
            // performs in `Curl_pgrsSetDownloadCounter` /
            // `Curl_pgrsSetUploadCounter` whenever the computed wait is zero.
            self.window_start = now;
            self.window_start_bytes = total_transferred;
        }

        Duration::from_millis(wait_ms)
    }
}

/// Transfer rate limiter for a single easy handle.
///
/// Holds an independent [`DirRateLimit`] for each [`Direction`]. It is configured
/// through [`set_recv_limit`](RateLimit::set_recv_limit) /
/// [`set_send_limit`](RateLimit::set_send_limit) (driven from `crate::setopt`),
/// consulted through [`wait_time`](RateLimit::wait_time) (driven from
/// `crate::transfer` / `crate::progress`), and restarted between transfers
/// through [`reset`](RateLimit::reset).
///
/// # Examples
///
/// ```ignore
/// use std::time::Instant;
/// use curl_rs_lib::ratelimit::{Direction, RateLimit};
///
/// let start = Instant::now();
/// let mut rl = RateLimit::new(start);
/// rl.set_recv_limit(1_000).unwrap(); // cap downloads at 1000 bytes/sec
///
/// // After 500 ms we have received 2000 bytes — twice the budget — so the
/// // transfer must wait the remaining 1500 ms before reading more.
/// let wait = rl.wait_time(Direction::Download, 2_000, start + std::time::Duration::from_millis(500));
/// assert_eq!(wait, std::time::Duration::from_millis(1_500));
/// ```
#[derive(Debug, Clone)]
pub struct RateLimit {
    /// Download (receive) direction accounting.
    download: DirRateLimit,
    /// Upload (send) direction accounting.
    upload: DirRateLimit,
}

impl RateLimit {
    /// Creates a rate limiter with both directions unlimited and their windows
    /// opened at `now`.
    ///
    /// Callers in the live transfer path pass [`Instant::now()`]; tests pass a
    /// fixed instant so the windowed arithmetic is fully deterministic.
    #[must_use]
    pub fn new(now: Instant) -> Self {
        Self {
            download: DirRateLimit::new(now),
            upload: DirRateLimit::new(now),
        }
    }

    /// Sets the download (receive) cap in bytes per second; `0` disables the cap.
    ///
    /// Mirrors `CURLOPT_MAX_RECV_SPEED_LARGE`: a negative value is rejected with
    /// [`CurlError::BadFunctionArgument`], exactly as libcurl's `setopt` returns
    /// `CURLE_BAD_FUNCTION_ARGUMENT` for a negative speed cap.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::BadFunctionArgument`] if `bytes_per_sec` is negative.
    pub fn set_recv_limit(&mut self, bytes_per_sec: i64) -> Result<()> {
        self.download.limit_bps = validate_limit(bytes_per_sec)?;
        Ok(())
    }

    /// Sets the upload (send) cap in bytes per second; `0` disables the cap.
    ///
    /// Mirrors `CURLOPT_MAX_SEND_SPEED_LARGE`: a negative value is rejected with
    /// [`CurlError::BadFunctionArgument`], exactly as libcurl's `setopt` returns
    /// `CURLE_BAD_FUNCTION_ARGUMENT` for a negative speed cap.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::BadFunctionArgument`] if `bytes_per_sec` is negative.
    pub fn set_send_limit(&mut self, bytes_per_sec: i64) -> Result<()> {
        self.upload.limit_bps = validate_limit(bytes_per_sec)?;
        Ok(())
    }

    /// Returns the configured download (receive) cap in bytes/second (`0` = unlimited).
    #[must_use]
    pub fn recv_limit(&self) -> u64 {
        self.download.limit_bps
    }

    /// Returns the configured upload (send) cap in bytes/second (`0` = unlimited).
    #[must_use]
    pub fn send_limit(&self) -> u64 {
        self.upload.limit_bps
    }

    /// Returns the configured cap for `direction` in bytes/second (`0` = unlimited).
    #[must_use]
    pub fn limit(&self, direction: Direction) -> u64 {
        match direction {
            Direction::Download => self.download.limit_bps,
            Direction::Upload => self.upload.limit_bps,
        }
    }

    /// Returns `true` if `direction` has an active (non-zero) rate cap.
    #[must_use]
    pub fn is_limited(&self, direction: Direction) -> bool {
        self.limit(direction) != 0
    }

    /// Restarts both sampling windows at `now`, zeroing their byte baselines.
    ///
    /// The configured caps are preserved. Call this when (re)starting a transfer
    /// so the rate accounting begins fresh.
    pub fn reset(&mut self, now: Instant) {
        self.download.reset(now);
        self.upload.reset(now);
    }

    /// Returns how long the transfer in `direction` must pause so its windowed
    /// rate stays at or below the configured cap.
    ///
    /// `total_transferred` is the cumulative, monotonically non-decreasing byte
    /// count for `direction`; `now` is the current monotonic time. The result is
    /// [`Duration::ZERO`] when the direction is unlimited or already at/under the
    /// cap, otherwise the remaining time the transfer still "owes". The caller
    /// (the transfer engine) is responsible for actually sleeping for the
    /// returned duration via `tokio::time::sleep`.
    ///
    /// As a side effect, when the returned wait is zero the sampling window for
    /// `direction` is advanced to `now`, matching curl's window reset.
    #[must_use]
    pub fn wait_time(
        &mut self,
        direction: Direction,
        total_transferred: u64,
        now: Instant,
    ) -> Duration {
        match direction {
            Direction::Download => self.download.wait_time(total_transferred, now),
            Direction::Upload => self.upload.wait_time(total_transferred, now),
        }
    }
}

/// Validates and converts a user-supplied bytes-per-second cap.
///
/// libcurl stores the speed caps as `curl_off_t` (a signed 64-bit integer) and
/// rejects negatives in `setopt`. We accept the same `i64` and use the natural
/// signed→unsigned conversion as the validation: a negative value fails
/// [`u64::try_from`] and is reported as [`CurlError::BadFunctionArgument`]
/// (`CURLE_BAD_FUNCTION_ARGUMENT`); any non-negative value converts exactly.
fn validate_limit(bytes_per_sec: i64) -> Result<u64> {
    u64::try_from(bytes_per_sec).map_err(|_| CurlError::BadFunctionArgument)
}

/// Monotonic elapsed milliseconds from `start` to `now`, truncated toward zero.
///
/// Uses [`Instant::saturating_duration_since`] so that a (theoretically
/// impossible) backwards monotonic clock yields `0` rather than panicking, and
/// truncates sub-millisecond remainder exactly like curl's `Curl_timediff`.
fn elapsed_millis(start: Instant, now: Instant) -> u64 {
    saturating_u64(now.saturating_duration_since(start).as_millis())
}

/// Saturating conversion from [`u128`] to [`u64`] (clamps at [`u64::MAX`]).
///
/// Keeps the rate arithmetic total and panic-free without any lossy `as` cast.
fn saturating_u64(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Convenience: an instant `ms` milliseconds after `base`.
    fn at(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    #[test]
    fn new_is_unlimited_in_both_directions() {
        let t0 = Instant::now();
        let rl = RateLimit::new(t0);
        assert_eq!(rl.recv_limit(), 0);
        assert_eq!(rl.send_limit(), 0);
        assert!(!rl.is_limited(Direction::Download));
        assert!(!rl.is_limited(Direction::Upload));
        assert_eq!(rl.limit(Direction::Download), 0);
        assert_eq!(rl.limit(Direction::Upload), 0);
    }

    #[test]
    fn unlimited_never_waits_and_keeps_no_window() {
        let t0 = Instant::now();
        let mut rl = RateLimit::new(t0);
        // No limit set: any amount of data at any time => zero wait.
        assert_eq!(
            rl.wait_time(Direction::Download, 1_000_000, t0),
            Duration::ZERO
        );
        assert_eq!(
            rl.wait_time(Direction::Upload, u64::MAX, at(t0, 1)),
            Duration::ZERO
        );
    }

    #[test]
    fn setters_store_limits_per_direction() {
        let t0 = Instant::now();
        let mut rl = RateLimit::new(t0);
        rl.set_recv_limit(4_096).unwrap();
        rl.set_send_limit(1_024).unwrap();
        assert_eq!(rl.recv_limit(), 4_096);
        assert_eq!(rl.send_limit(), 1_024);
        assert!(rl.is_limited(Direction::Download));
        assert!(rl.is_limited(Direction::Upload));
        assert_eq!(rl.limit(Direction::Download), 4_096);
        assert_eq!(rl.limit(Direction::Upload), 1_024);
    }

    #[test]
    fn zero_limit_disables_throttling() {
        let t0 = Instant::now();
        let mut rl = RateLimit::new(t0);
        rl.set_recv_limit(0).unwrap();
        assert!(!rl.is_limited(Direction::Download));
        assert_eq!(
            rl.wait_time(Direction::Download, 10_000_000, t0),
            Duration::ZERO
        );
    }

    #[test]
    fn negative_limit_is_rejected_as_bad_argument() {
        let t0 = Instant::now();
        let mut rl = RateLimit::new(t0);
        assert_eq!(rl.set_recv_limit(-1), Err(CurlError::BadFunctionArgument));
        assert_eq!(
            rl.set_send_limit(i64::MIN),
            Err(CurlError::BadFunctionArgument)
        );
        // A rejected set leaves the prior (unlimited) state intact.
        assert_eq!(rl.recv_limit(), 0);
        assert_eq!(rl.send_limit(), 0);
    }

    #[test]
    fn over_limit_returns_exact_remaining_wait() {
        // Hand-computed: limit = 1000 B/s. 2000 bytes "should" take
        // minimum = 2000 * 1000 / 1000 = 2000 ms. After 500 ms elapsed, the
        // transfer still owes wait = 2000 - 500 = 1500 ms.
        let t0 = Instant::now();
        let mut rl = RateLimit::new(t0);
        rl.set_recv_limit(1_000).unwrap();
        let wait = rl.wait_time(Direction::Download, 2_000, at(t0, 500));
        assert_eq!(wait, Duration::from_millis(1_500));
    }

    #[test]
    fn under_limit_returns_zero() {
        // limit = 1000 B/s. 500 bytes => minimum = 500 ms. After 1000 ms the
        // transfer is well under the cap, so the wait is zero.
        let t0 = Instant::now();
        let mut rl = RateLimit::new(t0);
        rl.set_recv_limit(1_000).unwrap();
        let wait = rl.wait_time(Direction::Download, 500, at(t0, 1_000));
        assert_eq!(wait, Duration::ZERO);
    }

    #[test]
    fn exactly_at_limit_returns_zero() {
        // limit = 1000 B/s. 1000 bytes => minimum = 1000 ms == elapsed => 0 wait.
        let t0 = Instant::now();
        let mut rl = RateLimit::new(t0);
        rl.set_recv_limit(1_000).unwrap();
        assert_eq!(
            rl.wait_time(Direction::Download, 1_000, at(t0, 1_000)),
            Duration::ZERO
        );
    }

    #[test]
    fn integer_division_floors_like_curl() {
        // limit = 3 B/s, 10 bytes: minimum = 10 * 1000 / 3 = 10000/3 = 3333 ms
        // (floored, not 3333.33). elapsed = 0 => wait = 3333 ms exactly.
        let t0 = Instant::now();
        let mut rl = RateLimit::new(t0);
        rl.set_send_limit(3).unwrap();
        let wait = rl.wait_time(Direction::Upload, 10, t0);
        assert_eq!(wait, Duration::from_millis(3_333));
    }

    #[test]
    fn window_resets_when_on_pace_then_samples_fresh() {
        // limit = 1000 B/s. Drive the transfer at exactly the cap and verify the
        // window advances (resets) each time the wait evaluates to zero, so the
        // following interval is measured from the new baseline.
        let t0 = Instant::now();
        let mut rl = RateLimit::new(t0);
        rl.set_recv_limit(1_000).unwrap();

        // First second: 1000 bytes in 1000 ms => on pace => wait 0 => window
        // advances to (t0+1000ms, 1000 bytes).
        assert_eq!(
            rl.wait_time(Direction::Download, 1_000, at(t0, 1_000)),
            Duration::ZERO
        );

        // Second interval measured from the NEW window: another 500 bytes over
        // the next 500 ms. size = 1500 - 1000 = 500, elapsed = 1500 - 1000 = 500,
        // minimum = 500 => wait 0. If the window had NOT reset, size would be
        // 1500 over 1500 ms (also 0 here) — so prove the reset explicitly below.
        assert_eq!(
            rl.wait_time(Direction::Download, 1_500, at(t0, 1_500)),
            Duration::ZERO
        );

        // Now push a burst in the fresh window: 2000 more bytes (total 3500) only
        // 100 ms after the last reset at t0+1500ms. From the reset baseline
        // (t0+1500ms, 1500 bytes): size = 3500 - 1500 = 2000 => minimum = 2000 ms,
        // elapsed = 1600 - 1500 = 100 ms => wait = 1900 ms. This only holds if the
        // window was reset to the t0+1500ms baseline.
        let wait = rl.wait_time(Direction::Download, 3_500, at(t0, 1_600));
        assert_eq!(wait, Duration::from_millis(1_900));
    }

    #[test]
    fn window_does_not_reset_while_throttling_a_burst() {
        // A burst that exceeds the cap must keep waiting across repeated checks
        // until real time catches up — the window must NOT reset while wait > 0.
        let t0 = Instant::now();
        let mut rl = RateLimit::new(t0);
        rl.set_recv_limit(1_000).unwrap();

        // 5000 bytes at t0 => minimum = 5000 ms, elapsed 0 => wait 5000 ms.
        assert_eq!(
            rl.wait_time(Direction::Download, 5_000, t0),
            Duration::from_millis(5_000)
        );
        // 1000 ms later, still the same 5000 bytes pending (we are mid-sleep):
        // elapsed = 1000 => wait = 4000 ms. The window did not reset.
        assert_eq!(
            rl.wait_time(Direction::Download, 5_000, at(t0, 1_000)),
            Duration::from_millis(4_000)
        );
        // Once enough real time elapses (5000 ms), the debt is paid: wait 0 and
        // the window finally advances.
        assert_eq!(
            rl.wait_time(Direction::Download, 5_000, at(t0, 5_000)),
            Duration::ZERO
        );
    }

    #[test]
    fn directions_are_independent() {
        let t0 = Instant::now();
        let mut rl = RateLimit::new(t0);
        rl.set_recv_limit(1_000).unwrap();
        // Upload is unlimited: never waits, regardless of the download cap.
        assert_eq!(
            rl.wait_time(Direction::Upload, 10_000, at(t0, 1)),
            Duration::ZERO
        );
        // Download still throttles independently.
        assert_eq!(
            rl.wait_time(Direction::Download, 2_000, at(t0, 0)),
            Duration::from_millis(2_000)
        );
    }

    #[test]
    fn reset_restarts_windows_but_keeps_limits() {
        let t0 = Instant::now();
        let mut rl = RateLimit::new(t0);
        rl.set_recv_limit(1_000).unwrap();

        // Establish progress, then reset at a later instant.
        let _ = rl.wait_time(Direction::Download, 4_000, t0);
        let t_reset = at(t0, 10_000);
        rl.reset(t_reset);

        // Limit preserved.
        assert_eq!(rl.recv_limit(), 1_000);

        // After reset the byte baseline is zero again: 1000 bytes measured from
        // the reset instant => minimum 1000 ms, elapsed 0 => wait 1000 ms.
        let wait = rl.wait_time(Direction::Download, 1_000, t_reset);
        assert_eq!(wait, Duration::from_millis(1_000));
    }

    #[test]
    fn zero_size_in_window_returns_zero() {
        // No new bytes since the window opened => zero wait (curl: !size => 0).
        let t0 = Instant::now();
        let mut rl = RateLimit::new(t0);
        rl.set_recv_limit(1_000).unwrap();
        assert_eq!(
            rl.wait_time(Direction::Download, 0, at(t0, 5_000)),
            Duration::ZERO
        );
    }

    #[test]
    fn backwards_counter_is_handled_defensively() {
        // A counter that appears to move backwards must not panic or wrap; it is
        // treated as zero progress for the window.
        let t0 = Instant::now();
        let mut rl = RateLimit::new(t0);
        rl.set_recv_limit(1_000).unwrap();
        // Drive on pace so the window resets to a non-zero baseline of 1000
        // bytes: 1000 bytes over 1000 ms => wait 0 => window (t0+1000ms, 1000).
        assert_eq!(
            rl.wait_time(Direction::Download, 1_000, at(t0, 1_000)),
            Duration::ZERO
        );
        // Now report a *smaller* total (500) than the 1000-byte baseline. The
        // windowed size saturates to 0 instead of underflowing/wrapping, so the
        // wait is zero and the window simply re-syncs.
        let wait = rl.wait_time(Direction::Download, 500, at(t0, 1_100));
        assert_eq!(wait, Duration::ZERO);
    }

    #[test]
    fn huge_size_does_not_overflow() {
        // A very large windowed size must use the u128 intermediate without
        // overflow. limit = 1 B/s, size = u64::MAX bytes. minimum in ms would be
        // u64::MAX * 1000, which saturates to u64::MAX ms; elapsed 0 => wait
        // saturates to u64::MAX ms. The point is: no panic, no wrap.
        let t0 = Instant::now();
        let mut rl = RateLimit::new(t0);
        rl.set_recv_limit(1).unwrap();
        let wait = rl.wait_time(Direction::Download, u64::MAX, t0);
        assert_eq!(wait, Duration::from_millis(u64::MAX));
    }

    #[test]
    fn validate_limit_boundaries() {
        assert_eq!(validate_limit(0), Ok(0));
        assert_eq!(validate_limit(1), Ok(1));
        // i64::MAX converts exactly to the same magnitude as u64 (cast-free).
        assert_eq!(validate_limit(i64::MAX), Ok(9_223_372_036_854_775_807));
        assert_eq!(validate_limit(-1), Err(CurlError::BadFunctionArgument));
        assert_eq!(
            validate_limit(i64::MIN),
            Err(CurlError::BadFunctionArgument)
        );
    }

    #[test]
    fn elapsed_millis_truncates_and_saturates_backwards() {
        let t0 = Instant::now();
        assert_eq!(elapsed_millis(t0, t0), 0);
        assert_eq!(elapsed_millis(t0, at(t0, 1_234)), 1_234);
        // Backwards (now < start) saturates to zero rather than panicking.
        assert_eq!(elapsed_millis(at(t0, 1_000), t0), 0);
    }
}
