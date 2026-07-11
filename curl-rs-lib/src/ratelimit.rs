//! Transfer rate limiting — a language rewrite of curl 8.x `lib/ratelimit.c`.
//!
//! This module implements curl's `--limit-rate` pacing for both the send
//! (`CURLOPT_MAX_SEND_SPEED_LARGE`) and receive
//! (`CURLOPT_MAX_RECV_SPEED_LARGE`) directions. It is a byte-for-byte
//! behavioral port of curl 8.19.0-DEV's [token-bucket] rate limiter: the token
//! accounting, the step tuning, the overflow guards, and the millisecond
//! wait computation are reproduced exactly so that a transfer paces
//! identically to curl 8.x.
//!
//! [token-bucket]: https://en.wikipedia.org/wiki/Token_bucket
//!
//! # The token-bucket model (from `lib/ratelimit.h`)
//!
//! A [`RateLimit`] provides "tokens" (bytes) to be consumed per second:
//!
//! * A rate limit of one megabyte per second starts with one million tokens.
//! * They are drained as bytes flow; checking availability before the second
//!   elapses returns `0` once the budget is spent.
//! * At/after the next second, the tokens are replenished.
//! * A `burst` cap prevents an idle transfer from accumulating an unbounded
//!   token surplus. curl always sets `burst == rate` (see `lib/setopt.c`), so a
//!   transfer stays *at or below* the configured rate and slow periods do not
//!   generate extra credit.
//! * A limiter with rate `0` is *inactive* and always reports [`i64::MAX`]
//!   tokens available (unless explicitly blocked).
//!
//! # Relationship to sibling modules
//!
//! * [`crate::progress`] owns the transfer byte counters and speeds; it
//!   deliberately does **not** own the rate-limit pacing state. This module
//!   owns that state and *consumes* the progress measurements
//!   ([`RateLimiter::drain_from_progress`]).
//! * The multi-handle state machine (`multi.rs`) drives the
//!   `MSTATE_RATELIMITING` state from [`RateLimiter::check`], which reproduces
//!   curl's `mspeed_check` (`lib/multi.c`).
//! * The transfer loop (`transfer.rs`) consults [`RateLimiter::recv_avail`] /
//!   [`RateLimiter::send_avail`] to decide how many bytes it may move this
//!   iteration, exactly as curl does in `lib/transfer.c`.
//!
//! # No busy-waiting
//!
//! The limiter never sleeps. It computes a [`Duration`] that the caller passes
//! to `tokio::time::sleep` (or arms as a multi-handle timer), matching curl's
//! event-driven `EXPIRE_TOOFAST` wait. This keeps the async runtime in charge
//! of scheduling and keeps this module pure, synchronous math.
//!
//! # Safety
//!
//! This module is written entirely in safe Rust, as mandated for
//! `curl-rs-lib`; it contains no `unsafe`, no raw pointers, and no `panic!`.
//! All arithmetic uses `i64` (curl's `curl_off_t`/`timediff_t`) with saturating
//! operations so that pathological inputs can never panic in a debug build
//! while remaining bit-identical to curl for realistic transfer magnitudes.
//! curl's exact overflow and time-condition guards are preserved verbatim.
//!
//! # Time source and testability
//!
//! curl stamps every operation with a shared `struct curltime` sampled once per
//! event-loop turn (`Curl_pgrs_now`). Here that timestamp is a
//! [`std::time::Instant`], matching [`crate::progress`]. Every method that
//! needs "now" takes it as an explicit `Instant` argument, so the token math is
//! fully deterministic and unit-testable; production callers pass
//! [`crate::progress::Progress::now`].

use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::progress::Progress;

/// Microseconds per second — curl's `CURL_US_PER_SEC` (`lib/ratelimit.c`).
///
/// This is the initial step duration: tokens replenish once per second until
/// [`RateLimit::start`] tunes the step for a known total transfer size.
const CURL_US_PER_SEC: i64 = 1_000_000;

/// Minimum per-step token rate used when tuning — curl's `CURL_RLIMIT_MIN_RATE`
/// (`4 * 1024`, `lib/ratelimit.c`).
///
/// The reserved "last step" is capped at this many tokens so the final step of
/// a transfer stays small without becoming vanishingly so.
const CURL_RLIMIT_MIN_RATE: i64 = 4 * 1024;

/// Minimum viable step duration in milliseconds — curl's
/// `CURL_RLIMIT_STEP_MIN_MS` (`lib/ratelimit.c`).
///
/// If tuning computes a step shorter than this, the limiter is left untuned
/// (steps this small do not pace usefully).
const CURL_RLIMIT_STEP_MIN_MS: i64 = 2;

/// Signed microsecond difference `newer - older`, mirroring curl's
/// `curlx_ptimediff_us` (`lib/curlx/timeval.c`).
///
/// Returns a negative value when `newer` precedes `older` (curl's callers guard
/// on `< 0`), and saturates to [`i64::MAX`] / [`i64::MIN`] for differences that
/// exceed the `i64` microsecond range — the same saturation curl applies at
/// `TIMEDIFF_T_MAX` / `TIMEDIFF_T_MIN`. Because [`Instant`] is monotonic the
/// negative branch is unreachable in practice, but it is preserved for exact
/// behavioral parity with the C guards.
fn ptimediff_us(newer: Instant, older: Instant) -> i64 {
    match newer.checked_duration_since(older) {
        Some(delta) => {
            let us = delta.as_micros();
            if us > i64::MAX as u128 {
                i64::MAX
            } else {
                us as i64
            }
        }
        None => {
            // `newer` precedes `older`: report a negative difference.
            let back = older.saturating_duration_since(newer).as_micros();
            match i64::try_from(back) {
                Ok(v) => -v,
                Err(_) => i64::MIN,
            }
        }
    }
}

/// A single-direction transfer rate limiter — a faithful port of curl's
/// `struct Curl_rlimit` and the `Curl_rlimit_*` function family
/// (`lib/ratelimit.c`, `lib/ratelimit.h`).
///
/// One instance paces a single direction (download *or* upload). The
/// higher-level [`RateLimiter`] bundles the two independent caps that a
/// transfer uses together.
///
/// The type is [`Copy`] (it is a small bag of integers plus a timestamp), so it
/// can be freely embedded and moved with a transfer between Tokio worker
/// threads.
#[derive(Debug, Clone, Copy)]
pub struct RateLimit {
    /// Tokens generated per step (`rate_per_step`). `0` means the limiter is
    /// inactive and reports unlimited availability.
    rate_per_step: i64,
    /// Burst cap of tokens per step (`burst_per_step`). `0` disables the cap.
    burst_per_step: i64,
    /// Microseconds between token replenishments (`step_us`). Starts at one
    /// second and may be shortened/lengthened by [`RateLimit::start`] tuning.
    step_us: i64,
    /// Tokens currently available; may go negative when over-drained
    /// (`tokens`).
    tokens: i64,
    /// Leftover microseconds carried into the next step (`spare_us`).
    spare_us: i64,
    /// Timestamp of the last token update (`ts`).
    ts: Instant,
    /// When set, availability is forced to `0` until unblocked (`blocked`).
    blocked: bool,
}

impl RateLimit {
    /// Initializes a limiter, mirroring `Curl_rlimit_init`.
    ///
    /// `rate_per_sec` is the token (byte) budget per second; `burst_per_sec` is
    /// the burst cap (`0` disables it). curl invariants (asserted in debug C
    /// builds) are `rate_per_sec >= 0` and `burst_per_sec >= rate_per_sec ||
    /// burst_per_sec == 0`; the library does not panic on violation — callers
    /// that surface these as `CURLE_BAD_FUNCTION_ARGUMENT` validate through
    /// [`RateLimiter::set_max_recv_speed`] / [`RateLimiter::set_max_send_speed`].
    /// A `rate_per_sec` of `0` yields an inactive limiter.
    #[must_use]
    pub fn init(rate_per_sec: i64, burst_per_sec: i64, now: Instant) -> Self {
        RateLimit {
            rate_per_step: rate_per_sec,
            burst_per_step: burst_per_sec,
            step_us: CURL_US_PER_SEC,
            spare_us: 0,
            tokens: rate_per_sec,
            ts: now,
            blocked: false,
        }
    }

    /// (Re)starts rate limiting at `now`, resetting the available tokens —
    /// mirrors `Curl_rlimit_start`.
    ///
    /// `total_tokens` is the number of tokens (bytes) expected to be consumed in
    /// total, or `-1` when unknown. When known, it is used to tune the step so
    /// the *last* step is small and the transfer's average rate stays in line
    /// (see [`RateLimit::tune_steps`]).
    pub fn start(&mut self, now: Instant, total_tokens: i64) {
        self.tokens = self.rate_per_step;
        self.spare_us = 0;
        self.ts = now;
        self.tune_steps(total_tokens);
    }

    /// Returns the per-step token rate, mirroring `Curl_rlimit_per_step`.
    ///
    /// Consumers such as the HTTP/2 flow-control window sizing
    /// (`lib/http2.c`) read this to align their buffering with the limit.
    #[must_use]
    pub fn per_step(&self) -> i64 {
        self.rate_per_step
    }

    /// Returns whether token rate limiting is active, mirroring
    /// `Curl_rlimit_active` (`rate_per_step > 0 || blocked`).
    #[must_use]
    pub fn active(&self) -> bool {
        self.rate_per_step > 0 || self.blocked
    }

    /// Returns whether the limiter is currently blocked, mirroring
    /// `Curl_rlimit_is_blocked`.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        self.blocked
    }

    /// Replenishes tokens for the time elapsed since the last update — the
    /// private `rlimit_update` (`lib/ratelimit.c`).
    ///
    /// Preconditions match curl: `rate_per_step != 0` (callers
    /// [`avail`](Self::avail) / [`drain`](Self::drain) / [`wait_ms`](Self::wait_ms)
    /// only invoke this when the limiter is active). No update occurs until at
    /// least one full step has elapsed; the leftover time is carried in
    /// `spare_us`. Token gain and accumulation use curl's exact overflow guards.
    fn update(&mut self, now: Instant) {
        // Fast path: nothing to do if no time has passed (curl compares the
        // stored `tv_sec`/`tv_usec` against `now`).
        if self.ts == now {
            return;
        }

        let mut elapsed_us = ptimediff_us(now, self.ts);
        if elapsed_us < 0 {
            // Time went backwards; curl asserts and bails. Unreachable with a
            // monotonic `Instant`, but the guard is preserved.
            return;
        }

        elapsed_us = elapsed_us.saturating_add(self.spare_us);
        if elapsed_us < self.step_us {
            // Less than a full step has elapsed; keep accumulating.
            return;
        }

        // Perform the update.
        self.ts = now;
        // `step_us` is always > 0, and `elapsed_us >= step_us` here, so
        // `elapsed_steps >= 1` and the divisions below are safe.
        let elapsed_steps = elapsed_us / self.step_us;
        self.spare_us = elapsed_us % self.step_us;

        // Tokens gained since the last update, guarded against `i64` overflow
        // exactly as curl does.
        let token_gain = if self.rate_per_step > i64::MAX / elapsed_steps {
            i64::MAX
        } else {
            self.rate_per_step.saturating_mul(elapsed_steps)
        };

        // Add the gained tokens, capping at `i64::MAX` (curl's overflow guard).
        self.tokens = if i64::MAX - token_gain > self.tokens {
            self.tokens.saturating_add(token_gain)
        } else {
            i64::MAX
        };

        // Re-cap by the burst rate (if set) so a long idle period cannot leave
        // a huge token surplus.
        if self.burst_per_step != 0 && self.tokens > self.burst_per_step {
            self.tokens = self.burst_per_step;
        }
    }

    /// Tunes the step duration and per-step rate when the total transfer size
    /// is known — the private `rlimit_tune_steps` (`lib/ratelimit.c`).
    ///
    /// rlimit delivers tokens per "step" (initially one second). Because tokens
    /// may be consumed in full at the start of a step, the remainder of that
    /// step blocks consumption, keeping the step average in line. That works up
    /// to the *last* step, where — with no more tokens needed — no wait occurs
    /// and the last step would run too fast (very noticeable for small
    /// transfers). Tuning makes the last step small (1% of the total, at least
    /// `1`, at most [`CURL_RLIMIT_MIN_RATE`]) and spreads the remaining tokens
    /// across the earlier steps by adjusting the step duration and per-step
    /// rate, when integer arithmetic permits.
    fn tune_steps(&mut self, tokens_total: i64) {
        // Only tune when active, the total is known and > 1, and the token math
        // cannot overflow (curl's guards, verbatim).
        if self.rate_per_step == 0 || tokens_total <= 1 || tokens_total > i64::MAX / 1000 {
            return;
        }

        // Reserve tokens for a small last step.
        let mut tokens_last = tokens_total / 100;
        if tokens_last == 0 {
            // Fewer than 100 tokens total: just use 1.
            tokens_last = 1;
        } else if tokens_last > CURL_RLIMIT_MIN_RATE {
            tokens_last = CURL_RLIMIT_MIN_RATE;
        }
        let tokens_main = tokens_total - tokens_last;

        // curl asserts `step_us == CURL_US_PER_SEC` here (freshly started).
        // How many milli-steps to consume `tokens_main` at the per-second rate?
        let msteps = tokens_main.saturating_mul(1000) / self.rate_per_step;
        if msteps < CURL_RLIMIT_STEP_MIN_MS {
            // Steps this small will not work; leave the limiter untuned.
            return;
        }
        if msteps < 1000 {
            // Less than one full step provides the needed tokens: make the step
            // exactly that long and provide exactly those tokens.
            self.step_us = msteps * 1000;
            self.rate_per_step = tokens_main;
            self.tokens = self.rate_per_step;
        } else {
            // More than one step: spread the remainder milli-steps (and the
            // tokens they must provide) across all steps, when integer
            // arithmetic can express it.
            let ms_unaccounted = msteps % 1000;
            let mstep_inc = ms_unaccounted / (msteps / 1000);
            if mstep_inc != 0 {
                let rate_inc = self.rate_per_step.saturating_mul(mstep_inc) / 1000;
                if rate_inc != 0 {
                    self.step_us = CURL_US_PER_SEC + mstep_inc * 1000;
                    self.rate_per_step = self.rate_per_step.saturating_add(rate_inc);
                    self.tokens = self.rate_per_step;
                }
            }
        }

        // Keep the burst cap aligned with the (possibly tuned) rate.
        if self.burst_per_step != 0 {
            self.burst_per_step = self.rate_per_step;
        }
    }

    /// Returns the tokens available to spend right now (may be negative),
    /// mirroring `Curl_rlimit_avail`.
    ///
    /// A blocked limiter reports `0`; an inactive limiter (rate `0`) reports
    /// [`i64::MAX`]; otherwise the token bucket is first updated for elapsed
    /// time, then the current token count is returned. The transfer loop treats
    /// a value `<= 0` as "cannot move data now" and enters rate limiting.
    pub fn avail(&mut self, now: Instant) -> i64 {
        if self.blocked {
            0
        } else if self.rate_per_step != 0 {
            self.update(now);
            self.tokens
        } else {
            i64::MAX
        }
    }

    /// Drains `tokens` (bytes) from the bucket, mirroring `Curl_rlimit_drain`.
    ///
    /// No-op when blocked or inactive. The bucket is first updated for elapsed
    /// time, then the drained amount is subtracted, guarding against `i64`
    /// underflow exactly as curl does. On 64-bit platforms a `usize` can exceed
    /// [`i64::MAX`]; curl clamps that degenerate case to `i64::MAX`, reproduced
    /// here verbatim.
    pub fn drain(&mut self, tokens: usize, now: Instant) {
        if self.blocked || self.rate_per_step == 0 {
            return;
        }
        self.update(now);

        if tokens as u128 > i64::MAX as u128 {
            // Matches curl's `#if 8 <= SIZEOF_SIZE_T` clamp. On 32-bit targets
            // `usize` cannot reach this range, so this branch is never taken —
            // exactly as the C preprocessor guard arranges.
            self.tokens = i64::MAX;
        } else {
            let val = tokens as i64;
            // curl uses a strict `<`; when `i64::MIN + val == tokens` it falls
            // through to the clamp, which yields the same `i64::MIN` result.
            if i64::MIN + val < self.tokens {
                self.tokens -= val;
            } else {
                self.tokens = i64::MIN;
            }
        }
    }

    /// Returns how many milliseconds to wait until tokens are available again,
    /// mirroring `Curl_rlimit_wait_ms`.
    ///
    /// Returns `0` when blocked, inactive, or tokens are already positive.
    /// Otherwise the wait is the remainder of the current step plus, when in
    /// token debt, a proportional repayment; the time already elapsed since the
    /// last update is then deducted. The result is rounded up to whole
    /// milliseconds (curl's `(wait_us + 999) / 1000`).
    pub fn wait_ms(&mut self, now: Instant) -> i64 {
        if self.blocked || self.rate_per_step == 0 {
            return 0;
        }
        self.update(now);
        if self.tokens > 0 {
            return 0;
        }

        // Base wait: the remainder of the current step.
        let mut wait_us = self.step_us - self.spare_us;

        // In debt: add proportional extra time to repay it.
        if self.tokens < 0 {
            let debt_pct = self.tokens.saturating_neg().saturating_mul(100) / self.rate_per_step;
            if debt_pct != 0 {
                wait_us = wait_us.saturating_add(self.step_us.saturating_mul(debt_pct) / 100);
            }
        }

        // Deduct time already elapsed since the last token update.
        let elapsed_us = ptimediff_us(now, self.ts);
        if elapsed_us >= wait_us {
            return 0;
        }
        wait_us -= elapsed_us;
        wait_us.saturating_add(999) / 1000
    }

    /// Returns how many milliseconds until the limiter next replenishes tokens,
    /// mirroring `Curl_rlimit_next_step_ms`.
    ///
    /// A transfer that is *not* currently waiting still needs to run again when
    /// the next step's tokens arrive, or it could stall. Returns `0` when
    /// blocked, inactive, or a step boundary has already been reached. Unlike
    /// [`avail`](Self::avail) / [`wait_ms`](Self::wait_ms) this is a read-only
    /// query and does not replenish tokens.
    #[must_use]
    pub fn next_step_ms(&self, now: Instant) -> i64 {
        if !self.blocked && self.rate_per_step != 0 {
            let elapsed_us = ptimediff_us(now, self.ts).saturating_add(self.spare_us);
            if self.step_us > elapsed_us {
                let next_us = self.step_us - elapsed_us;
                return next_us.saturating_add(999) / 1000;
            }
        }
        0
    }

    /// Blocks or unblocks the limiter, mirroring `Curl_rlimit_block`.
    ///
    /// A blocked limiter reports `0` available tokens until unblocked. This is a
    /// no-op if the requested state already matches. Unblocking restarts rate
    /// limiting fresh (the blocked interval does not accrue tokens); blocking
    /// zeroes the available tokens.
    pub fn block(&mut self, activate: bool, now: Instant) {
        // curl: `if(!activate == !blocked) return;`
        if activate == self.blocked {
            return;
        }
        self.ts = now;
        self.blocked = activate;
        if !self.blocked {
            // Restart with no history of the blocked period; total unknown.
            self.start(now, -1);
        } else {
            self.tokens = 0;
        }
    }
}

/// Converts a non-negative millisecond count to a [`Duration`], clamping any
/// non-positive value to [`Duration::ZERO`].
///
/// The limiter's millisecond helpers never return a negative value, but this
/// keeps the conversion total and panic-free.
fn ms_to_duration(ms: i64) -> Duration {
    if ms <= 0 {
        Duration::ZERO
    } else {
        Duration::from_millis(ms as u64)
    }
}

/// Clamps a non-negative `i64` byte delta into the `usize` domain expected by
/// [`RateLimit::drain`].
///
/// On 64-bit targets an `i64` byte count always fits in `usize`; on 32-bit
/// targets an improbably large delta is clamped to [`usize::MAX`]. Negative
/// inputs (which the callers never pass) clamp to `0`.
fn clamp_i64_to_usize(v: i64) -> usize {
    // `v.max(0)` guards the (never-passed) negative case; `try_from` clamps a
    // value that overflows `usize` on 32-bit targets. Total and panic-free.
    usize::try_from(v.max(0)).unwrap_or(usize::MAX)
}

/// The outcome of a rate-limit check for the multi-handle state machine — the
/// decision curl makes in `mspeed_check` (`lib/multi.c`) that drives the
/// `MSTATE_RATELIMITING` state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MSpeedCheck {
    /// The transfer is **not** rate limited and may proceed. `next_update` is
    /// how long until the token buckets next replenish; the caller arms a timer
    /// for that instant so the transfer resumes promptly rather than stalling.
    /// [`Duration::ZERO`] means there is no pending replenishment to schedule
    /// (no active cap, or a step boundary is already due).
    Proceed {
        /// Time until the next token replenishment (`0` if none to schedule).
        next_update: Duration,
    },
    /// The transfer **is** rate limited: it must enter `MSTATE_RATELIMITING`
    /// and idle for `wait` before retrying (curl's `CURLE_AGAIN` +
    /// `EXPIRE_TOOFAST` path). The caller passes `wait` to `tokio::time::sleep`
    /// (or arms it as a multi-handle expiry timer) — never a busy loop.
    RateLimited {
        /// How long to wait before the transfer should be retried.
        wait: Duration,
    },
}

/// A bidirectional transfer rate limiter bundling the two independent caps a
/// transfer uses together: the receive (download) cap
/// (`CURLOPT_MAX_RECV_SPEED_LARGE`) and the send (upload) cap
/// (`CURLOPT_MAX_SEND_SPEED_LARGE`).
///
/// This mirrors how curl stores one [`RateLimit`] per direction inside the
/// per-transfer progress state (`data->progress.dl.rlimit` and
/// `data->progress.ul.rlimit`) and always consults them together in the multi
/// handle. It is the primary API that `transfer.rs` and `multi.rs` call to pace
/// a transfer and to decide when to enter or leave `MSTATE_RATELIMITING`.
///
/// # Progress coupling
///
/// [`drain_from_progress`](Self::drain_from_progress) reads the cumulative byte
/// counters owned by [`crate::progress::Progress`] and drains the per-direction
/// delta transferred since the previous observation, reproducing curl's
/// `Curl_pgrs_download_inc` / `Curl_pgrs_upload_inc` → `Curl_rlimit_drain` data
/// flow (`lib/progress.c`). Callers that already know the freshly transferred
/// byte count can instead use [`drain_recv`](Self::drain_recv) /
/// [`drain_send`](Self::drain_send) directly.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// Receive-direction (download) cap.
    recv: RateLimit,
    /// Send-direction (upload) cap.
    send: RateLimit,
    /// Cumulative downloaded bytes observed at the last
    /// [`drain_from_progress`](Self::drain_from_progress).
    last_dl: i64,
    /// Cumulative uploaded bytes observed at the last
    /// [`drain_from_progress`](Self::drain_from_progress).
    last_ul: i64,
}

impl RateLimiter {
    /// Creates a limiter with both directions inactive (no cap).
    ///
    /// `now` seeds each direction's internal timestamp; while inactive (rate
    /// `0`) both directions report unlimited availability, matching a
    /// zero-initialized curl handle before any `CURLOPT_MAX_*_SPEED_LARGE` is
    /// set.
    #[must_use]
    pub fn new(now: Instant) -> Self {
        RateLimiter {
            recv: RateLimit::init(0, 0, now),
            send: RateLimit::init(0, 0, now),
            last_dl: 0,
            last_ul: 0,
        }
    }

    /// Sets the maximum receive speed in bytes per second
    /// (`CURLOPT_MAX_RECV_SPEED_LARGE`), mirroring `lib/setopt.c`.
    ///
    /// curl sets `burst == rate`, so the transfer stays at or below the cap and
    /// slow periods do not build up extra credit. A value of `0` disables the
    /// receive cap.
    ///
    /// # Errors
    ///
    /// Returns [`Error::bad_argument`] ([`CURLE_BAD_FUNCTION_ARGUMENT`]) when
    /// `bytes_per_sec` is negative, exactly as `curl_easy_setopt` does.
    ///
    /// [`CURLE_BAD_FUNCTION_ARGUMENT`]: crate::error::CurlCode::BadFunctionArgument
    pub fn set_max_recv_speed(&mut self, bytes_per_sec: i64, now: Instant) -> Result<()> {
        if bytes_per_sec < 0 {
            return Err(Error::bad_argument(
                "CURLOPT_MAX_RECV_SPEED_LARGE must not be negative",
            ));
        }
        self.recv = RateLimit::init(bytes_per_sec, bytes_per_sec, now);
        Ok(())
    }

    /// Sets the maximum send speed in bytes per second
    /// (`CURLOPT_MAX_SEND_SPEED_LARGE`), mirroring `lib/setopt.c`.
    ///
    /// curl sets `burst == rate`. A value of `0` disables the send cap.
    ///
    /// # Errors
    ///
    /// Returns [`Error::bad_argument`] ([`CURLE_BAD_FUNCTION_ARGUMENT`]) when
    /// `bytes_per_sec` is negative.
    ///
    /// [`CURLE_BAD_FUNCTION_ARGUMENT`]: crate::error::CurlCode::BadFunctionArgument
    pub fn set_max_send_speed(&mut self, bytes_per_sec: i64, now: Instant) -> Result<()> {
        if bytes_per_sec < 0 {
            return Err(Error::bad_argument(
                "CURLOPT_MAX_SEND_SPEED_LARGE must not be negative",
            ));
        }
        self.send = RateLimit::init(bytes_per_sec, bytes_per_sec, now);
        Ok(())
    }

    /// (Re)starts receive-direction rate limiting, mirroring the download-side
    /// `Curl_rlimit_start` call in `lib/sendf.c`.
    ///
    /// `total_bytes` is the expected total download size (or `-1` if unknown),
    /// used to tune the step so the average download rate stays in line. Also
    /// resets the progress-delta baseline used by
    /// [`drain_from_progress`](Self::drain_from_progress).
    pub fn start_recv(&mut self, now: Instant, total_bytes: i64) {
        self.last_dl = 0;
        self.recv.start(now, total_bytes);
    }

    /// (Re)starts send-direction rate limiting, mirroring the upload-side
    /// `Curl_rlimit_start` call in `lib/sendf.c` (which passes `-1`, as the
    /// upload total is not tuned).
    pub fn start_send(&mut self, now: Instant) {
        self.last_ul = 0;
        self.send.start(now, -1);
    }

    /// Drains `bytes` freshly received from the receive bucket
    /// (`Curl_rlimit_drain` on the download direction).
    pub fn drain_recv(&mut self, bytes: usize, now: Instant) {
        self.recv.drain(bytes, now);
    }

    /// Drains `bytes` freshly sent from the send bucket
    /// (`Curl_rlimit_drain` on the upload direction).
    pub fn drain_send(&mut self, bytes: usize, now: Instant) {
        self.send.drain(bytes, now);
    }

    /// Drains both buckets by the bytes transferred since the last call, using
    /// the cumulative counters owned by [`Progress`].
    ///
    /// This reproduces curl's `Curl_pgrs_download_inc` / `Curl_pgrs_upload_inc`
    /// → `Curl_rlimit_drain` flow (`lib/progress.c`): [`Progress`] owns the
    /// byte measurement, and the limiter owns the pacing. Call it once per
    /// progress update (with the shared [`Progress::now`] timestamp) and it will
    /// drain exactly the delta transferred in each direction since the previous
    /// call.
    pub fn drain_from_progress(&mut self, progress: &Progress, now: Instant) {
        let dl = progress.downloaded();
        let dl_delta = dl.saturating_sub(self.last_dl);
        if dl_delta > 0 {
            self.last_dl = dl;
            self.recv.drain(clamp_i64_to_usize(dl_delta), now);
        }

        let ul = progress.uploaded();
        let ul_delta = ul.saturating_sub(self.last_ul);
        if ul_delta > 0 {
            self.last_ul = ul;
            self.send.drain(clamp_i64_to_usize(ul_delta), now);
        }
    }

    /// Returns the tokens (bytes) the receive direction may consume now
    /// (`Curl_rlimit_avail`). A value `<= 0` means the transfer must stop
    /// receiving and enter rate limiting.
    pub fn recv_avail(&mut self, now: Instant) -> i64 {
        self.recv.avail(now)
    }

    /// Returns the tokens (bytes) the send direction may consume now
    /// (`Curl_rlimit_avail`).
    pub fn send_avail(&mut self, now: Instant) -> i64 {
        self.send.avail(now)
    }

    /// Returns whether the receive direction is rate limiting
    /// (`Curl_rlimit_active`).
    #[must_use]
    pub fn recv_active(&self) -> bool {
        self.recv.active()
    }

    /// Returns whether the send direction is rate limiting
    /// (`Curl_rlimit_active`).
    #[must_use]
    pub fn send_active(&self) -> bool {
        self.send.active()
    }

    /// Returns whether either direction is rate limiting. The multi handle uses
    /// this to decide whether to run the speed check at all (`lib/multi.c`).
    #[must_use]
    pub fn any_active(&self) -> bool {
        self.recv.active() || self.send.active()
    }

    /// Returns whether the receive direction is currently blocked
    /// (`Curl_rlimit_is_blocked`).
    #[must_use]
    pub fn recv_is_blocked(&self) -> bool {
        self.recv.is_blocked()
    }

    /// Returns whether the send direction is currently blocked
    /// (`Curl_rlimit_is_blocked`).
    #[must_use]
    pub fn send_is_blocked(&self) -> bool {
        self.send.is_blocked()
    }

    /// Blocks or unblocks the receive direction (`Curl_rlimit_block`).
    pub fn block_recv(&mut self, activate: bool, now: Instant) {
        self.recv.block(activate, now);
    }

    /// Blocks or unblocks the send direction (`Curl_rlimit_block`).
    pub fn block_send(&mut self, activate: bool, now: Instant) {
        self.send.block(activate, now);
    }

    /// Borrows the receive-direction limiter, for consumers that call the
    /// single-direction API directly (e.g. HTTP/2 window sizing in
    /// `lib/http2.c` reads [`RateLimit::per_step`]).
    #[must_use]
    pub fn recv(&self) -> &RateLimit {
        &self.recv
    }

    /// Borrows the send-direction limiter.
    #[must_use]
    pub fn send(&self) -> &RateLimit {
        &self.send
    }

    /// Mutably borrows the receive-direction limiter.
    pub fn recv_mut(&mut self) -> &mut RateLimit {
        &mut self.recv
    }

    /// Mutably borrows the send-direction limiter.
    pub fn send_mut(&mut self) -> &mut RateLimit {
        &mut self.send
    }

    /// Returns how long the transfer should wait to satisfy both caps — the
    /// larger of the two per-direction waits (curl's `CURLMAX(send_ms,
    /// recv_ms)` in `mspeed_check`).
    ///
    /// The returned [`Duration`] is intended for `tokio::time::sleep`; a
    /// zero duration means no wait is required.
    pub fn wait_duration(&mut self, now: Instant) -> Duration {
        let send_ms = self.send.wait_ms(now);
        let recv_ms = self.recv.wait_ms(now);
        ms_to_duration(send_ms.max(recv_ms))
    }

    /// Performs the combined rate-limit check that drives `MSTATE_RATELIMITING`,
    /// reproducing curl's `mspeed_check` (`lib/multi.c`).
    ///
    /// * If neither direction is active, the transfer proceeds with nothing to
    ///   schedule.
    /// * If either direction must wait, returns [`MSpeedCheck::RateLimited`]
    ///   with the larger wait — the transfer enters `MSTATE_RATELIMITING` and
    ///   idles for that duration.
    /// * Otherwise returns [`MSpeedCheck::Proceed`] carrying the time until the
    ///   next token replenishment, computed as `CURLMIN` of the per-direction
    ///   next-step times, falling back to `CURLMAX` when the minimum is zero
    ///   (so an inactive direction's `0` does not mask the active one).
    pub fn check(&mut self, now: Instant) -> MSpeedCheck {
        if !self.recv.active() && !self.send.active() {
            return MSpeedCheck::Proceed {
                next_update: Duration::ZERO,
            };
        }

        let send_ms = self.send.wait_ms(now);
        let recv_ms = self.recv.wait_ms(now);
        if send_ms != 0 || recv_ms != 0 {
            return MSpeedCheck::RateLimited {
                wait: ms_to_duration(send_ms.max(recv_ms)),
            };
        }

        // Not waiting now: schedule the next token replenishment.
        let send_next = self.send.next_step_ms(now);
        let recv_next = self.recv.next_step_ms(now);
        let mut next_ms = send_next.min(recv_next);
        if next_ms == 0 {
            next_ms = send_next.max(recv_next);
        }
        MSpeedCheck::Proceed {
            next_update: ms_to_duration(next_ms),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CurlCode;

    /// A fixed anchor plus microsecond-precise offsets make the token math
    /// exactly reproducible and directly comparable to curl's integer results.
    fn base() -> Instant {
        Instant::now()
    }

    fn after_us(t: Instant, us: u64) -> Instant {
        t + Duration::from_micros(us)
    }

    fn after_ms(t: Instant, ms: u64) -> Instant {
        t + Duration::from_millis(ms)
    }

    // ---- ptimediff_us helper ------------------------------------------------

    #[test]
    fn ptimediff_us_positive_zero_negative() {
        let t0 = base();
        assert_eq!(ptimediff_us(after_us(t0, 1_000_000), t0), 1_000_000);
        assert_eq!(ptimediff_us(t0, t0), 0);
        // `newer` precedes `older` -> negative, as curl's callers expect.
        assert_eq!(ptimediff_us(t0, after_us(t0, 1_000_000)), -1_000_000);
    }

    // ---- RateLimit: inactive (rate 0) --------------------------------------

    #[test]
    fn inactive_limiter_reports_unlimited_and_never_waits() {
        let t0 = base();
        let mut r = RateLimit::init(0, 0, t0);
        assert!(!r.active());
        assert!(!r.is_blocked());
        assert_eq!(r.per_step(), 0);
        assert_eq!(r.avail(t0), i64::MAX);
        assert_eq!(r.wait_ms(t0), 0);
        assert_eq!(r.next_step_ms(t0), 0);
        // Draining an inactive limiter is a no-op.
        r.drain(1_000, t0);
        assert_eq!(r.avail(t0), i64::MAX);
    }

    // ---- RateLimit: core token-bucket parity -------------------------------

    #[test]
    fn full_drain_waits_exactly_one_step() {
        let t0 = base();
        let mut r = RateLimit::init(1_000_000, 1_000_000, t0);
        assert!(r.active());
        assert_eq!(r.avail(t0), 1_000_000);

        r.drain(1_000_000, t0);
        assert_eq!(r.avail(t0), 0);
        // Spent the whole second's budget instantly -> wait ~1s.
        assert_eq!(r.wait_ms(t0), 1000);
        // A full step is also when the next replenishment is due.
        assert_eq!(r.next_step_ms(t0), 1000);
    }

    #[test]
    fn tokens_replenish_after_one_second() {
        let t0 = base();
        let mut r = RateLimit::init(1_000_000, 1_000_000, t0);
        r.drain(1_000_000, t0);
        assert_eq!(r.avail(t0), 0);

        let t1 = after_us(t0, 1_000_000);
        assert_eq!(r.avail(t1), 1_000_000);
        assert_eq!(r.wait_ms(t1), 0);
    }

    #[test]
    fn partial_drain_leaves_tokens_and_no_wait() {
        let t0 = base();
        let mut r = RateLimit::init(1_000_000, 1_000_000, t0);
        r.drain(400_000, t0);
        assert_eq!(r.avail(t0), 600_000);
        assert_eq!(r.wait_ms(t0), 0);
    }

    #[test]
    fn over_drain_incurs_proportional_debt_wait() {
        let t0 = base();
        let mut r = RateLimit::init(1_000_000, 1_000_000, t0);
        // Drain 1.5x the per-second budget -> tokens = -500_000.
        r.drain(1_500_000, t0);
        assert_eq!(r.avail(t0), -500_000);
        // wait_us = step_us(1e6) + step_us * debt_pct(50) / 100 = 1.5e6 us
        // -> (1_500_000 + 999) / 1000 = 1500 ms. Matches curl exactly.
        assert_eq!(r.wait_ms(t0), 1500);
    }

    #[test]
    fn next_step_ms_counts_down_within_a_step() {
        let t0 = base();
        let r = RateLimit::init(1_000_000, 1_000_000, t0);
        assert_eq!(r.next_step_ms(t0), 1000);
        // 400 ms into the step, 600 ms remain until replenishment.
        assert_eq!(r.next_step_ms(after_ms(t0, 400)), 600);
    }

    #[test]
    fn elapsed_time_reduces_the_wait() {
        let t0 = base();
        let mut r = RateLimit::init(1_000_000, 1_000_000, t0);
        r.drain(1_000_000, t0);
        assert_eq!(r.wait_ms(t0), 1000);
        // 600 ms later, only ~400 ms of the step remains.
        assert_eq!(r.wait_ms(after_ms(t0, 600)), 400);
    }

    #[test]
    fn burst_equal_rate_caps_accumulated_tokens() {
        let t0 = base();
        // burst == rate (curl's setopt behavior): idle time does NOT build up
        // a surplus beyond one step's worth.
        let mut r = RateLimit::init(1_000_000, 1_000_000, t0);
        r.drain(1_000_000, t0);
        assert_eq!(r.avail(t0), 0);
        // Idle 3 seconds: gained 3e6, but capped at burst (1e6).
        assert_eq!(r.avail(after_us(t0, 3_000_000)), 1_000_000);
    }

    #[test]
    fn burst_zero_allows_lifetime_averaging() {
        let t0 = base();
        // burst == 0 disables the cap -> tokens accumulate (curl's
        // "average over the whole transfer" behavior).
        let mut r = RateLimit::init(1_000_000, 0, t0);
        r.drain(1_000_000, t0);
        assert_eq!(r.avail(t0), 0);
        assert_eq!(r.avail(after_us(t0, 3_000_000)), 3_000_000);
    }

    #[test]
    fn spare_time_carries_across_sub_step_updates() {
        let t0 = base();
        let mut r = RateLimit::init(1_000_000, 1_000_000, t0);
        r.drain(1_000_000, t0);
        // Half a step elapses: less than a full step, so no replenishment yet.
        assert_eq!(r.avail(after_us(t0, 500_000)), 0);
        // Another 600_000us -> total 1_100_000us since t0 crosses one full
        // step (1e6), replenishing exactly one step of tokens; 100_000us spare.
        assert_eq!(r.avail(after_us(t0, 1_100_000)), 1_000_000);
    }

    // ---- RateLimit: block / unblock ----------------------------------------

    #[test]
    fn block_forces_zero_then_unblock_restarts() {
        let t0 = base();
        let mut r = RateLimit::init(1_000_000, 1_000_000, t0);

        r.block(true, t0);
        assert!(r.is_blocked());
        assert!(r.active());
        assert_eq!(r.avail(t0), 0);
        assert_eq!(r.wait_ms(t0), 0);
        assert_eq!(r.next_step_ms(t0), 0);

        // Re-blocking is a no-op.
        r.block(true, t0);
        assert!(r.is_blocked());

        // Unblocking restarts fresh with a full token budget.
        r.block(false, t0);
        assert!(!r.is_blocked());
        assert_eq!(r.avail(t0), 1_000_000);
    }

    // ---- RateLimit: tune_steps (Curl_rlimit_start tuning) ------------------

    #[test]
    fn tune_steps_spreads_remainder_for_multi_step_transfer() {
        let t0 = base();
        let mut r = RateLimit::init(1_000, 1_000, t0);
        // total=1500: tokens_last=15, tokens_main=1485, msteps=1485 (>=1000)
        // ms_unaccounted=485, mstep_inc=485, rate_inc=485
        // -> rate_per_step=1485, step_us=1_485_000, burst=1485.
        r.start(t0, 1_500);
        assert_eq!(r.per_step(), 1_485);
        assert_eq!(r.avail(t0), 1_485);
    }

    #[test]
    fn tune_steps_shrinks_step_for_sub_second_transfer() {
        let t0 = base();
        let mut r = RateLimit::init(1_000, 1_000, t0);
        // total=500: tokens_last=5, tokens_main=495, msteps=495 (<1000)
        // -> step_us=495_000, rate_per_step=495.
        r.start(t0, 500);
        assert_eq!(r.per_step(), 495);
        assert_eq!(r.avail(t0), 495);
    }

    #[test]
    fn tune_steps_skips_when_step_would_be_too_small() {
        let t0 = base();
        let mut r = RateLimit::init(1_000_000_000, 1_000_000_000, t0);
        // total=1000 vs a 1e9/s rate: msteps == 0 (< CURL_RLIMIT_STEP_MIN_MS)
        // -> no tuning; rate/step unchanged.
        r.start(t0, 1_000);
        assert_eq!(r.per_step(), 1_000_000_000);
        // One full (untuned) second still replenishes the full rate.
        assert_eq!(r.next_step_ms(t0), 1000);
    }

    #[test]
    fn tune_steps_ignores_unknown_total() {
        let t0 = base();
        let mut r = RateLimit::init(1_000, 1_000, t0);
        r.start(t0, -1);
        assert_eq!(r.per_step(), 1_000);
        assert_eq!(r.avail(t0), 1_000);
    }

    // ---- RateLimiter: two independent caps ---------------------------------

    #[test]
    fn limiter_new_is_inactive() {
        let t0 = base();
        let mut lim = RateLimiter::new(t0);
        assert!(!lim.any_active());
        assert!(!lim.recv_active());
        assert!(!lim.send_active());
        assert_eq!(lim.recv_avail(t0), i64::MAX);
        assert_eq!(lim.send_avail(t0), i64::MAX);
        assert_eq!(lim.wait_duration(t0), Duration::ZERO);
        assert_eq!(
            lim.check(t0),
            MSpeedCheck::Proceed {
                next_update: Duration::ZERO
            }
        );
    }

    #[test]
    fn limiter_rejects_negative_speed_with_bad_argument() {
        let t0 = base();
        let mut lim = RateLimiter::new(t0);

        let err = lim.set_max_recv_speed(-1, t0).unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
        let err = lim.set_max_send_speed(-5, t0).unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);

        // Zero and positive are accepted.
        assert!(lim.set_max_recv_speed(0, t0).is_ok());
        assert!(lim.set_max_send_speed(1_000, t0).is_ok());
    }

    #[test]
    fn limiter_recv_cap_enters_rate_limiting_when_spent() {
        let t0 = base();
        let mut lim = RateLimiter::new(t0);
        lim.set_max_recv_speed(1_000_000, t0).unwrap();
        assert!(lim.recv_active());
        assert!(lim.any_active());

        // Fresh budget -> proceed; next replenishment scheduled at one step.
        assert_eq!(
            lim.check(t0),
            MSpeedCheck::Proceed {
                next_update: Duration::from_millis(1000)
            }
        );

        // Spend the whole receive budget -> must rate-limit for one step.
        lim.drain_recv(1_000_000, t0);
        assert_eq!(
            lim.check(t0),
            MSpeedCheck::RateLimited {
                wait: Duration::from_millis(1000)
            }
        );
    }

    #[test]
    fn limiter_caps_are_independent() {
        let t0 = base();
        let mut lim = RateLimiter::new(t0);
        lim.set_max_recv_speed(1_000_000, t0).unwrap();
        // Send is uncapped: unlimited availability, no wait contribution.
        assert_eq!(lim.send_avail(t0), i64::MAX);

        lim.drain_recv(1_000_000, t0);
        assert_eq!(lim.recv_avail(t0), 0);
        assert_eq!(lim.send_avail(t0), i64::MAX);
        // Only the receive cap paces; wait is driven by it alone.
        assert_eq!(lim.wait_duration(t0), Duration::from_millis(1000));
    }

    #[test]
    fn limiter_wait_duration_takes_the_larger_of_both() {
        let t0 = base();
        let mut lim = RateLimiter::new(t0);
        lim.set_max_recv_speed(1_000_000, t0).unwrap();
        lim.set_max_send_speed(1_000_000, t0).unwrap();

        lim.drain_recv(1_000_000, t0); // recv wait == 1000 ms
        lim.drain_send(1_500_000, t0); // send wait == 1500 ms (debt)
        assert_eq!(lim.wait_duration(t0), Duration::from_millis(1500));
    }

    #[test]
    fn limiter_drain_from_progress_uses_cumulative_counters() {
        let t0 = base();
        let mut lim = RateLimiter::new(t0);
        lim.set_max_recv_speed(1_000_000, t0).unwrap();
        lim.set_max_send_speed(1_000_000, t0).unwrap();

        let mut p = Progress::new();

        // First observation: 400_000 downloaded, 300_000 uploaded.
        p.pgrs_download_inc(400_000);
        p.pgrs_upload_inc(300_000);
        lim.drain_from_progress(&p, t0);
        assert_eq!(lim.recv_avail(t0), 600_000);
        assert_eq!(lim.send_avail(t0), 700_000);

        // Second observation drains only the DELTA since last time.
        p.pgrs_download_inc(200_000); // cumulative dl = 600_000
        lim.drain_from_progress(&p, t0);
        assert_eq!(lim.recv_avail(t0), 400_000);
        // Upload counter unchanged -> send bucket untouched.
        assert_eq!(lim.send_avail(t0), 700_000);
    }

    #[test]
    fn limiter_block_helpers_zero_then_restore() {
        let t0 = base();
        let mut lim = RateLimiter::new(t0);
        lim.set_max_recv_speed(1_000_000, t0).unwrap();

        lim.block_recv(true, t0);
        assert!(lim.recv_is_blocked());
        assert_eq!(lim.recv_avail(t0), 0);

        lim.block_recv(false, t0);
        assert!(!lim.recv_is_blocked());
        assert_eq!(lim.recv_avail(t0), 1_000_000);

        // Send side was never blocked.
        assert!(!lim.send_is_blocked());
    }

    #[test]
    fn limiter_direct_accessors_expose_single_direction_api() {
        let t0 = base();
        let mut lim = RateLimiter::new(t0);
        lim.set_max_recv_speed(1_000_000, t0).unwrap();

        // Immutable borrow reads the per-step rate (as HTTP/2 sizing does).
        assert_eq!(lim.recv().per_step(), 1_000_000);
        assert_eq!(lim.send().per_step(), 0);

        // Mutable borrow drives the single-direction bucket directly.
        lim.recv_mut().drain(1_000_000, t0);
        assert!(lim.recv().active());
        assert_eq!(lim.recv_avail(t0), 0);
        lim.send_mut().block(true, t0);
        assert!(lim.send_is_blocked());
    }
}
