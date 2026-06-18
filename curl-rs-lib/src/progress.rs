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

//! Transfer progress metering — byte counters, timing milestones, speeds.
//!
//! This module is the Rust replacement for libcurl's progress subsystem
//! (`lib/progress.c` + `lib/progress.h`, the `struct Progress` fields in
//! `urldata.h`). It tracks, for a single easy handle:
//!
//! * the bytes transferred and the (optionally known) totals, in each
//!   direction (download / upload);
//! * the elapsed-time milestones curl exposes — name-lookup, connect,
//!   app-connect (TLS), pre-transfer, start-transfer, post-transfer, redirect,
//!   and the overall total time;
//! * the *current* (rolling-window) speed and the *average* per-direction
//!   speeds; and
//! * the user progress callbacks ([`CURLOPT_XFERINFOFUNCTION`] and the
//!   deprecated [`CURLOPT_PROGRESSFUNCTION`]).
//!
//! [`CURLOPT_XFERINFOFUNCTION`]: https://curl.se/libcurl/c/CURLOPT_XFERINFOFUNCTION.html
//! [`CURLOPT_PROGRESSFUNCTION`]: https://curl.se/libcurl/c/CURLOPT_PROGRESSFUNCTION.html
//!
//! # Who consumes this
//!
//! * `crate::transfer` drives the metering: it feeds byte deltas in, captures
//!   milestones with [`Progress::time`], and calls [`Progress::update`] /
//!   [`Progress::check`] at intervals.
//! * `crate::getinfo` reads the numbers back to answer the `CURLINFO_*`
//!   timing/size/speed queries — both the floating-point-seconds form
//!   (`CURLINFO_TOTAL_TIME`, `CURLINFO_SPEED_DOWNLOAD`, …) and the integer
//!   form (`CURLINFO_TOTAL_TIME_T`, `CURLINFO_SIZE_DOWNLOAD_T`, …). Every
//!   timing getter therefore returns a [`TimerData`], which exposes both
//!   representations.
//! * `crate::ratelimit` is consulted through [`Progress::limit_wait_time`]: the
//!   progress subsystem owns the byte counters, so the hand-off to the rate
//!   limiter happens here (`CURLOPT_MAX_RECV_SPEED_LARGE` /
//!   `CURLOPT_MAX_SEND_SPEED_LARGE`).
//! * `crate::setopt` configures the speed caps ([`Progress::set_max_recv_speed`]
//!   / [`Progress::set_max_send_speed`]), the `NOPROGRESS` flag
//!   ([`Progress::set_hide`]), and records that a progress callback is in use
//!   ([`Progress::set_callback_used`]).
//!
//! # Relationship to the C original
//!
//! This is a behavioural re-implementation, **not** a line-by-line translation.
//! The milestone-capture rules, the rolling speed window, the average-speed
//! formula, the once-per-second meter throttle, and the
//! `LOW_SPEED_LIMIT`/`LOW_SPEED_TIME` abort all reproduce curl's observable
//! behaviour (verified against curl's own unit tests 1606 and 1636 — see the
//! tests at the bottom of this file). Two deliberate refinements keep the Rust
//! version safe:
//!
//! * Time is measured with the monotonic [`std::time::Instant`] clock rather
//!   than a wall-clock `struct curltime`, matching curl's use of a monotonic
//!   clock for elapsed/speed and making the timers immune to clock changes.
//! * All arithmetic uses checked/saturating integer operations (no raw `as`
//!   truncation on the hot path, no overflow panics), so the `uint8_t`
//!   speed-record counter wraps exactly as the C `uint8_t` does without
//!   panicking in debug builds.
//!
//! # Memory safety
//!
//! This module is pure computation over owned values. It contains **zero**
//! `unsafe` and no raw pointers; the crate-root `#![forbid(unsafe_code)]` is
//! reinforced locally by the module-level attribute below.

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use crate::error::{CurlError, Result};
use crate::ratelimit::{Direction, RateLimit};

/// Number of slots in the rolling speed-sample ring buffer.
///
/// curl uses `#define CURL_SPEED_RECORDS (5 + 1)` — six entries holding five
/// seconds of history plus the in-progress slot. The "current speed" is derived
/// from the oldest and newest samples in this window.
pub const CURL_SPEED_RECORDS: usize = 6;

/// Progress-callback return value that asks libcurl to keep running the default
/// progress meter after the callback returns.
///
/// Mirrors curl's `#define CURL_PROGRESSFUNC_CONTINUE 0x10000001`. A callback
/// that returns this value is treated as "continue, and still draw the built-in
/// meter"; returning `0` means "continue, but suppress the meter"; any other
/// non-zero value aborts the transfer with
/// [`CurlError::AbortedByCallback`](crate::error::CurlError::AbortedByCallback).
pub const CURL_PROGRESSFUNC_CONTINUE: i32 = 0x1000_0001;

/// One million — microseconds per second, the scaling factor in the speed and
/// timing arithmetic. Kept as a named constant so the intent is explicit at
/// every use site.
const MICROS_PER_SEC: i64 = 1_000_000;

/// The timing milestones a transfer records, mirroring curl's `timerid` enum
/// (`lib/progress.h`).
///
/// Each value names a point in a transfer's lifecycle at which
/// [`Progress::time`] captures "now". The semantics of each label are
/// reproduced exactly from `Curl_pgrsTimeWas`:
///
/// * [`StartOp`](Timer::StartOp) — the very start of an operation (resets the
///   queue accounting).
/// * [`StartSingle`](Timer::StartSingle) — the start of one single transfer
///   (each redirect begins a new "single"); the per-single reference point for
///   the name-lookup/connect/… deltas.
/// * [`PostQueue`](Timer::PostQueue) — immediately after a queued transfer is
///   dequeued; accumulates queue time across redirects.
/// * [`NameLookup`](Timer::NameLookup), [`Connect`](Timer::Connect),
///   [`AppConnect`](Timer::AppConnect), [`PreTransfer`](Timer::PreTransfer),
///   [`StartTransfer`](Timer::StartTransfer),
///   [`PostTransfer`](Timer::PostTransfer) — the cumulative phase timers,
///   measured from the current single transfer's start.
/// * [`StartAccept`](Timer::StartAccept) — when an inbound connection is
///   accepted (FTP active mode).
/// * [`Redirect`](Timer::Redirect) — total time spent in redirects so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Timer {
    /// No-op label (`TIMER_NONE`); capturing it records nothing.
    None,
    /// Start of the whole operation (`TIMER_STARTOP`).
    StartOp,
    /// Start of one single transfer, which may be queued (`TIMER_STARTSINGLE`).
    StartSingle,
    /// Immediately after dequeue (`TIMER_POSTQUEUE`); queue time is cumulative.
    PostQueue,
    /// DNS name resolution completed (`TIMER_NAMELOOKUP`).
    NameLookup,
    /// TCP (or equivalent) connection established (`TIMER_CONNECT`).
    Connect,
    /// Application-layer connection — e.g. the TLS handshake — completed
    /// (`TIMER_APPCONNECT`).
    AppConnect,
    /// All pre-transfer setup completed; about to issue the request
    /// (`TIMER_PRETRANSFER`).
    PreTransfer,
    /// First byte of the response received (`TIMER_STARTTRANSFER`).
    StartTransfer,
    /// Transfer body completed (`TIMER_POSTRANSFER`).
    PostTransfer,
    /// Inbound connection accepted (`TIMER_STARTACCEPT`).
    StartAccept,
    /// Cumulative time spent following redirects (`TIMER_REDIRECT`).
    Redirect,
}

/// A captured timing value, stored as a number of microseconds and exposing the
/// two representations the `CURLINFO_*` queries need.
///
/// curl exposes each timing both as a `double` number of seconds (e.g.
/// `CURLINFO_TOTAL_TIME`) and as a `curl_off_t` number of microseconds (e.g.
/// `CURLINFO_TOTAL_TIME_T`). Storing microseconds and converting on demand keeps
/// the integer form exact (it is the stored value) and reproduces curl's
/// `double` form (`micros / 1e6`).
///
/// The contained value is always non-negative for the deltas curl records.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimerData {
    /// The timing in microseconds.
    micros: i64,
}

impl TimerData {
    /// A zero timing — the value a milestone has before it is captured.
    #[must_use]
    pub const fn zero() -> Self {
        Self { micros: 0 }
    }

    /// Builds a timing from a microsecond count.
    #[must_use]
    pub const fn from_micros(micros: i64) -> Self {
        Self { micros }
    }

    /// The timing in microseconds — the value behind the `CURLINFO_*_TIME_T`
    /// (and `CURLINFO_SIZE_*_T`-adjacent) integer queries.
    #[must_use]
    pub const fn as_micros(self) -> i64 {
        self.micros
    }

    /// The timing in seconds as an `f64` — the value behind the legacy
    /// floating-point `CURLINFO_*_TIME` queries.
    #[must_use]
    pub fn as_seconds(self) -> f64 {
        self.micros as f64 / MICROS_PER_SEC as f64
    }

    /// Returns `true` if a non-zero timing has been recorded.
    #[must_use]
    pub const fn is_set(self) -> bool {
        self.micros > 0
    }

    /// Adds a (clamped non-negative) microsecond delta to this timing.
    ///
    /// Mirrors curl's `*delta += us` accumulation in `Curl_pgrsTimeWas`. The
    /// addition saturates rather than overflowing, which cannot happen for any
    /// realistic transfer duration but keeps the operation total and panic-free.
    fn add_micros(&mut self, us: i64) {
        self.micros = self.micros.saturating_add(us);
    }
}

/// A progress callback supplied by the application, borrowed for the duration of
/// a single [`Progress::update`] call.
///
/// curl offers two callback shapes; this enum models both. The transfer engine
/// (or the FFI layer, when a C function pointer is in play) adapts the
/// application's callback into one of these variants and hands it to
/// [`Progress::update`]. The callback is **borrowed**, never stored, which keeps
/// [`Progress`] free of trait objects and trivially [`Send`]/[`Clone`].
///
/// The four arguments are always passed in curl's order: download total,
/// download now, upload total, upload now.
pub enum ProgressCallbackRef<'a> {
    /// `CURLOPT_XFERINFOFUNCTION` — the preferred form, taking `curl_off_t`
    /// (`i64`) byte counts and avoiding floating point.
    Xferinfo(&'a mut dyn FnMut(i64, i64, i64, i64) -> i32),
    /// `CURLOPT_PROGRESSFUNCTION` — the deprecated form, taking `double` byte
    /// counts. Retained for parity with applications that still set it.
    Progress(&'a mut dyn FnMut(f64, f64, f64, f64) -> i32),
}

impl std::fmt::Debug for ProgressCallbackRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Xferinfo(_) => f.write_str("ProgressCallbackRef::Xferinfo(..)"),
            Self::Progress(_) => f.write_str("ProgressCallbackRef::Progress(..)"),
        }
    }
}

/// Per-direction accounting: the expected total, the running counter, and the
/// most recently computed average speed.
///
/// Mirrors curl's `struct pgrs_dir` (minus the embedded rate limiter, which the
/// Rust design hoists to a single [`RateLimit`] owned by [`Progress`]). The
/// `total_size` is only meaningful when the matching `*_size_known` flag on the
/// owning [`Progress`] is set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PgrsDir {
    /// Total expected bytes for this direction (valid only when known).
    total_size: i64,
    /// Bytes transferred so far in this direction.
    cur_size: i64,
    /// Most recent average speed in bytes/second (`cur_size` over elapsed time).
    speed: i64,
}

/// Transfer progress meter for a single easy handle.
///
/// This is the Rust analogue of curl's `struct Progress`. It owns the byte
/// counters, the timing milestones, the rolling speed window, and the rate
/// limiter, and drives the application progress callbacks. It is configured
/// from `crate::setopt`, fed and polled from `crate::transfer`, and read from
/// `crate::getinfo`.
///
/// All time is taken from the monotonic [`Instant`] clock. Methods that need
/// "now" accept it as a parameter so the live transfer path can pass
/// [`Instant::now()`] while tests pass a fixed instant for fully deterministic
/// arithmetic.
///
/// # Examples
///
/// ```ignore
/// use std::time::{Duration, Instant};
/// use curl_rs_lib::progress::{Progress, Timer};
///
/// let t0 = Instant::now();
/// let mut p = Progress::new(t0);
/// p.start_now(t0);
/// p.set_download_size(1_000);
/// p.download_inc(500);
/// p.time(Timer::NameLookup, t0 + Duration::from_millis(10));
/// let _show = p.calc(t0 + Duration::from_millis(1_000), false);
/// assert_eq!(p.download_size(), 500);
/// ```
#[derive(Debug, Clone)]
pub struct Progress {
    /// Upload (send) direction accounting.
    ul: PgrsDir,
    /// Download (receive) direction accounting.
    dl: PgrsDir,

    /// The currently fastest measured speed (bytes/second), over the rolling
    /// window. Negative is never produced by this module, but the field is a
    /// signed `i64` to mirror curl's `curl_off_t current_speed` (and so the
    /// low-speed check's `current_speed >= 0` guard is meaningful).
    current_speed: i64,
    /// Bytes of TLS early-data sent (`CURLINFO`-adjacent bookkeeping).
    earlydata_sent: i64,

    /// Total time spent so far, in microseconds (`CURLINFO_TOTAL_TIME[_T]`).
    timespent: i64,

    /// Cumulative queue time across redirects, in microseconds.
    t_postqueue: TimerData,
    /// Cumulative name-lookup time, in microseconds.
    t_nslookup: TimerData,
    /// Cumulative connect time, in microseconds.
    t_connect: TimerData,
    /// Cumulative app-connect (TLS) time, in microseconds.
    t_appconnect: TimerData,
    /// Cumulative pre-transfer time, in microseconds.
    t_pretransfer: TimerData,
    /// Cumulative post-transfer time, in microseconds.
    t_posttransfer: TimerData,
    /// Cumulative start-transfer (time-to-first-byte) time, in microseconds.
    t_starttransfer: TimerData,
    /// Cumulative redirect time, in microseconds.
    t_redirect: TimerData,

    /// Start of the overall operation; the reference for `timespent` and the
    /// redirect timer.
    start: Instant,
    /// Start of the current single transfer; the reference for the phase
    /// deltas (name-lookup/connect/…).
    t_startsingle: Option<Instant>,
    /// Start of the operation as captured by [`Timer::StartOp`].
    t_startop: Option<Instant>,
    /// Start of the current queue interval (advanced at op start and redirect).
    t_startqueue: Option<Instant>,
    /// Timestamp at which inbound data was accepted (FTP active mode).
    t_acceptdata: Option<Instant>,

    /// Cumulative transferred amount (dl + ul) sampled at each ring-buffer slot.
    speed_amount: [i64; CURL_SPEED_RECORDS],
    /// The instant each ring-buffer slot was sampled (`None` until first used).
    speed_time: [Option<Instant>; CURL_SPEED_RECORDS],
    /// Monotonic count of speed samples recorded; indexes the ring buffer
    /// modulo [`CURL_SPEED_RECORDS`]. A `u8` that wraps exactly like curl's
    /// `uint8_t speeder_c`.
    speeder_c: u8,

    /// Whole-second mark of the last meter draw, measured from `start`. Used to
    /// throttle the meter to at most once per second. `None` forces a redraw.
    lastshow: Option<u64>,
    /// Instant at which the transfer first dropped below the low-speed limit
    /// (`None` while at/above the limit). Mirrors curl's `state.keeps_speed`.
    keeps_speed: Option<Instant>,

    /// `CURLOPT_NOPROGRESS` — when `true`, neither the meter nor the callbacks
    /// run.
    hide: bool,
    /// Whether the upload total size is known (vs. an open-ended upload).
    ul_size_known: bool,
    /// Whether the download total size is known (vs. an open-ended download).
    dl_size_known: bool,
    /// Whether the meter header line has already been emitted.
    headers_out: bool,
    /// Whether an application progress/xferinfo callback is configured. Used to
    /// decide whether [`Progress`] should print a trailing newline when done.
    callback: bool,
    /// Whether the start-transfer milestone has been captured for the current
    /// single transfer (prevents repeated `TIMER_STARTTRANSFER` updates).
    is_t_startransfer_set: bool,

    /// The transfer rate limiter, fed this handle's byte counters. Owning it
    /// here mirrors curl's per-direction `pgrs_dir.rlimit`.
    ratelimit: RateLimit,
}

impl Progress {
    /// Creates a fresh progress meter whose clocks start at `now`.
    ///
    /// All counters, sizes, timers, and speeds begin at zero/unknown, the meter
    /// is visible (not hidden), and both rate-limit directions are unlimited.
    /// This corresponds to a zero-initialised `struct Progress` on a brand-new
    /// easy handle.
    #[must_use]
    pub fn new(now: Instant) -> Self {
        Self {
            ul: PgrsDir::default(),
            dl: PgrsDir::default(),
            current_speed: 0,
            earlydata_sent: 0,
            timespent: 0,
            t_postqueue: TimerData::zero(),
            t_nslookup: TimerData::zero(),
            t_connect: TimerData::zero(),
            t_appconnect: TimerData::zero(),
            t_pretransfer: TimerData::zero(),
            t_posttransfer: TimerData::zero(),
            t_starttransfer: TimerData::zero(),
            t_redirect: TimerData::zero(),
            start: now,
            t_startsingle: None,
            t_startop: None,
            t_startqueue: None,
            t_acceptdata: None,
            speed_amount: [0; CURL_SPEED_RECORDS],
            speed_time: [None; CURL_SPEED_RECORDS],
            speeder_c: 0,
            lastshow: None,
            keeps_speed: None,
            hide: false,
            ul_size_known: false,
            dl_size_known: false,
            headers_out: false,
            callback: false,
            is_t_startransfer_set: false,
            ratelimit: RateLimit::new(now),
        }
    }

    /// Marks the start of a transfer at `now` (`Curl_pgrsStartNow`).
    ///
    /// Resets the speed-meter display state, the per-direction counters, and the
    /// size-known flags, and re-bases the rate-limit windows — but, exactly like
    /// curl, leaves the cumulative milestone timers (name-lookup, connect, …)
    /// untouched so they continue to accumulate across redirects within one
    /// operation. (A full reset of those timers happens only via [`Progress::new`]
    /// on handle (re)initialisation.)
    pub fn start_now(&mut self, now: Instant) {
        self.speeder_c = 0;
        self.speed_amount = [0; CURL_SPEED_RECORDS];
        self.speed_time = [None; CURL_SPEED_RECORDS];
        self.start = now;
        self.is_t_startransfer_set = false;
        self.dl.cur_size = 0;
        self.ul.cur_size = 0;
        self.dl_size_known = false;
        self.ul_size_known = false;
        self.lastshow = None;
        self.current_speed = 0;
        self.ratelimit.reset(now);
    }

    /// Resets the counters, sizes, and speed records for reuse
    /// (`Curl_pgrsReset`), re-basing the rate-limit windows at `now`.
    ///
    /// Clears the upload counter and download counter, marks both totals
    /// unknown, drops the speed history, and clears the low-speed timer. The
    /// configured rate caps are preserved.
    pub fn reset(&mut self, now: Instant) {
        self.ul.cur_size = 0;
        self.dl.cur_size = 0;
        self.set_upload_size(-1);
        self.set_download_size(-1);
        self.speeder_c = 0;
        self.speed_amount = [0; CURL_SPEED_RECORDS];
        self.speed_time = [None; CURL_SPEED_RECORDS];
        self.keeps_speed = None;
        self.ratelimit.reset(now);
    }

    /// Resets only the known transfer sizes (`Curl_pgrsResetTransferSizes`),
    /// marking both the download and upload totals unknown.
    pub fn reset_transfer_sizes(&mut self) {
        self.set_download_size(-1);
        self.set_upload_size(-1);
    }

    /// Informs the meter that receiving was paused/unpaused
    /// (`Curl_pgrsRecvPause`).
    ///
    /// On *unpause* (`enable == false`) the speed history and low-speed timer
    /// are reset so the pause does not count as a slow stretch — matching curl.
    pub fn recv_pause(&mut self, enable: bool) {
        if !enable {
            self.speeder_c = 0;
            self.speed_amount = [0; CURL_SPEED_RECORDS];
            self.speed_time = [None; CURL_SPEED_RECORDS];
            self.keeps_speed = None;
        }
    }

    /// Informs the meter that sending was paused/unpaused
    /// (`Curl_pgrsSendPause`); see [`Progress::recv_pause`] for the semantics.
    pub fn send_pause(&mut self, enable: bool) {
        if !enable {
            self.speeder_c = 0;
            self.speed_amount = [0; CURL_SPEED_RECORDS];
            self.speed_time = [None; CURL_SPEED_RECORDS];
            self.keeps_speed = None;
        }
    }
}

// ---------------------------------------------------------------------------
// Counters and known sizes
// ---------------------------------------------------------------------------
impl Progress {
    /// Sets the absolute number of bytes downloaded so far.
    ///
    /// curl 8.x increments the download counter (see [`Progress::download_inc`])
    /// rather than setting it absolutely, but an absolute setter is provided for
    /// callers (and tests) that track the running total themselves. A negative
    /// value is clamped to zero, since byte counts are non-negative.
    pub fn set_download_counter(&mut self, bytes: i64) {
        self.dl.cur_size = bytes.max(0);
    }

    /// Sets the absolute number of bytes uploaded so far
    /// (`Curl_pgrsSetUploadCounter`). A negative value is clamped to zero.
    pub fn set_upload_counter(&mut self, bytes: i64) {
        self.ul.cur_size = bytes.max(0);
    }

    /// Adds `delta` bytes to the download counter (`Curl_pgrs_download_inc`).
    ///
    /// The running total is what the rate limiter and the speed window observe;
    /// unlike the C original there is no separate token "drain" here, because
    /// [`RateLimit`] derives its wait time from the running total directly.
    pub fn download_inc(&mut self, delta: u64) {
        if delta != 0 {
            self.dl.cur_size = self
                .dl
                .cur_size
                .saturating_add(i64::try_from(delta).unwrap_or(i64::MAX));
        }
    }

    /// Adds `delta` bytes to the upload counter (`Curl_pgrs_upload_inc`); see
    /// [`Progress::download_inc`].
    pub fn upload_inc(&mut self, delta: u64) {
        if delta != 0 {
            self.ul.cur_size = self
                .ul
                .cur_size
                .saturating_add(i64::try_from(delta).unwrap_or(i64::MAX));
        }
    }

    /// Sets the expected download size (`Curl_pgrsSetDownloadSize`).
    ///
    /// A value `>= 0` records the total and marks it known; a negative value
    /// (curl uses `-1`) zeroes the total and marks it unknown.
    pub fn set_download_size(&mut self, size: i64) {
        if size >= 0 {
            self.dl.total_size = size;
            self.dl_size_known = true;
        } else {
            self.dl.total_size = 0;
            self.dl_size_known = false;
        }
    }

    /// Sets the expected upload size (`Curl_pgrsSetUploadSize`); see
    /// [`Progress::set_download_size`] for the sign convention.
    pub fn set_upload_size(&mut self, size: i64) {
        if size >= 0 {
            self.ul.total_size = size;
            self.ul_size_known = true;
        } else {
            self.ul.total_size = 0;
            self.ul_size_known = false;
        }
    }

    /// Records the number of TLS early-data bytes sent (`Curl_pgrsEarlyData`).
    pub fn early_data(&mut self, sent: i64) {
        self.earlydata_sent = sent;
    }
}

// ---------------------------------------------------------------------------
// Timing milestones
// ---------------------------------------------------------------------------

/// Which cumulative phase-delta timer a [`Timer`] label updates, if any.
///
/// The phase deltas all share the same "accumulate (now − single-start)"
/// arithmetic, so the milestone dispatch picks the target with this tag and the
/// shared accumulation runs once afterwards — the safe-Rust equivalent of curl's
/// `timediff_t *delta` pointer.
#[derive(Clone, Copy)]
enum DeltaTarget {
    NameLookup,
    Connect,
    AppConnect,
    PreTransfer,
    PostTransfer,
    StartTransfer,
}

impl Progress {
    /// Captures the current monotonic time `now` at the milestone `timer`
    /// (`Curl_pgrsTime`).
    pub fn time(&mut self, timer: Timer, now: Instant) {
        self.time_was(timer, now);
    }

    /// Records `timestamp` as the time of the milestone `timer`
    /// (`Curl_pgrsTimeWas`).
    ///
    /// This is the lower-level entry point used when a timer must be recorded
    /// after the fact — for example happy-eyeballs only logs the winning
    /// connection's timestamps. The labelled rules mirror the C original
    /// exactly:
    ///
    /// * the phase deltas accumulate `(timestamp − single-start)`, clamped to at
    ///   least one microsecond, so cumulative timing across redirects matches
    ///   curl;
    /// * start-transfer is recorded at most once per single transfer; and
    /// * redirect time is the elapsed time from the operation start (overwriting,
    ///   not accumulating), and also re-bases the queue clock.
    pub fn time_was(&mut self, timer: Timer, timestamp: Instant) {
        let mut target: Option<DeltaTarget> = None;

        match timer {
            Timer::None => {}
            Timer::StartOp => {
                // Start of a transfer: anchor the op and queue clocks, and
                // clear the cumulative queue time.
                self.t_startop = Some(timestamp);
                self.t_startqueue = Some(timestamp);
                self.t_postqueue = TimerData::zero();
            }
            Timer::StartSingle => {
                // Start of each single transfer (re-set at every redirect).
                self.t_startsingle = Some(timestamp);
                self.is_t_startransfer_set = false;
            }
            Timer::PostQueue => {
                // Queue time is cumulative across all involved redirects.
                if let Some(startqueue) = self.t_startqueue {
                    self.t_postqueue
                        .add_micros(ptimediff_us(timestamp, startqueue));
                }
            }
            Timer::StartAccept => {
                self.t_acceptdata = Some(timestamp);
            }
            Timer::NameLookup => target = Some(DeltaTarget::NameLookup),
            Timer::Connect => target = Some(DeltaTarget::Connect),
            Timer::AppConnect => target = Some(DeltaTarget::AppConnect),
            Timer::PreTransfer => target = Some(DeltaTarget::PreTransfer),
            Timer::StartTransfer => {
                // Only the first capture per single transfer counts; a redirect
                // re-arms it by clearing the flag in `TIMER_STARTSINGLE`.
                if self.is_t_startransfer_set {
                    return;
                }
                self.is_t_startransfer_set = true;
                target = Some(DeltaTarget::StartTransfer);
            }
            Timer::PostTransfer => target = Some(DeltaTarget::PostTransfer),
            Timer::Redirect => {
                // Redirect time is measured from the operation start and the
                // queue clock is re-based to this moment.
                self.t_redirect = TimerData::from_micros(ptimediff_us(timestamp, self.start));
                self.t_startqueue = Some(timestamp);
            }
        }

        if let Some(target) = target {
            // All phase deltas accumulate (timestamp − current single-start),
            // forced to at least one microsecond, exactly as curl does.
            let mut us = match self.t_startsingle {
                Some(startsingle) => ptimediff_us(timestamp, startsingle),
                // Defensive: if the single-start was never recorded, treat the
                // delta as the minimal one microsecond rather than reading an
                // unset reference (curl would read a zeroed timeval here).
                None => 0,
            };
            if us < 1 {
                us = 1;
            }
            match target {
                DeltaTarget::NameLookup => self.t_nslookup.add_micros(us),
                DeltaTarget::Connect => self.t_connect.add_micros(us),
                DeltaTarget::AppConnect => self.t_appconnect.add_micros(us),
                DeltaTarget::PreTransfer => self.t_pretransfer.add_micros(us),
                DeltaTarget::PostTransfer => self.t_posttransfer.add_micros(us),
                DeltaTarget::StartTransfer => self.t_starttransfer.add_micros(us),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Speed calculation, callback dispatch, and abort checks
// ---------------------------------------------------------------------------
impl Progress {
    /// Recomputes the elapsed time, the per-direction average speeds, and the
    /// rolling current speed at `now`, returning whether the meter is due for a
    /// redraw (`progress_calc`; also the body of `Curl_pgrsUpdate_nometer`).
    ///
    /// `req_done` indicates the transfer's request has completed, which (a)
    /// forces a final speed sample when no speed was established yet and (b)
    /// overrides the once-per-second redraw throttle. This never invokes a
    /// callback or draws anything; it only updates the numbers and reports the
    /// redraw decision.
    pub fn calc(&mut self, now: Instant, req_done: bool) -> bool {
        // Total elapsed time so far, in microseconds.
        self.timespent = ptimediff_us(now, self.start);
        // Per-direction *average* speeds: total bytes over total elapsed time.
        self.dl.speed = trspeed(self.dl.cur_size, self.timespent);
        self.ul.speed = trspeed(self.ul.cur_size, self.timespent);

        let now_secs = self.secs_since_start(now);

        if self.speeder_c == 0 {
            // No previous record: seed the window and use the overall average as
            // the current speed.
            self.speed_amount[0] = self.dl.cur_size.saturating_add(self.ul.cur_size);
            self.speed_time[0] = Some(now);
            self.speeder_c = self.speeder_c.wrapping_add(1);
            self.current_speed = self.ul.speed.saturating_add(self.dl.speed);
            self.lastshow = Some(now_secs);
            return true;
        }

        // Where the next sample would go, and where the latest one is.
        let i_next = usize::from(self.speeder_c) % CURL_SPEED_RECORDS;
        let mut i_latest = if i_next > 0 {
            i_next - 1
        } else {
            CURL_SPEED_RECORDS - 1
        };

        // Only record a new sample once roughly a second has passed; sampling
        // too often would ruin the history.
        let latest_age_ms = self.speed_time[i_latest]
            .map_or(i64::MAX, |t| dur_ms(now.saturating_duration_since(t)));
        if latest_age_ms >= 1000 {
            self.speeder_c = self.speeder_c.wrapping_add(1);
            i_latest = i_next;
            self.speed_amount[i_latest] = self.dl.cur_size.saturating_add(self.ul.cur_size);
            self.speed_time[i_latest] = Some(now);
        } else if req_done {
            // On completion, if no current speed is established yet, refresh the
            // last record; otherwise keep the speed we have (the final partial
            // chunk would otherwise inflate the reported speed under rate
            // limiting).
            if self.current_speed == 0 {
                self.speed_amount[i_latest] = self.dl.cur_size.saturating_add(self.ul.cur_size);
                self.speed_time[i_latest] = Some(now);
            }
        } else {
            // Transfer ongoing and less than a second since the last sample:
            // nothing new to show.
            return false;
        }

        // The oldest sample still in the window.
        let i_oldest = if usize::from(self.speeder_c) < CURL_SPEED_RECORDS {
            0
        } else {
            (i_latest + 1) % CURL_SPEED_RECORDS
        };

        // Bytes transferred and time elapsed between the oldest and latest
        // samples define the current speed.
        let amount = self.speed_amount[i_latest].saturating_sub(self.speed_amount[i_oldest]);
        let mut duration_us = match (self.speed_time[i_latest], self.speed_time[i_oldest]) {
            (Some(latest), Some(oldest)) => ptimediff_us(latest, oldest),
            _ => 0,
        };
        if duration_us <= 0 {
            duration_us = 1;
        }

        // current_speed = amount * 1e6 / duration_us. Evaluated in i128 so the
        // `* 1_000_000` intermediate cannot overflow even for the huge-amount
        // case curl guards with floating point; the quotient is identical to
        // curl's normal integer path and saturates rather than panicking.
        self.current_speed = saturating_i64(
            i128::from(amount) * i128::from(MICROS_PER_SEC) / i128::from(duration_us),
        );

        // Throttle the meter to at most once per whole second, unless done.
        if self.lastshow == Some(now_secs) && !req_done {
            return false;
        }
        self.lastshow = Some(now_secs);
        true
    }

    /// Performs a progress update at `now` and invokes the application callback,
    /// returning whether the caller should now draw the built-in meter
    /// (`Curl_pgrsUpdate` / `pgrsupdate`).
    ///
    /// The callback (if any) is invoked with the current totals/counters in
    /// curl's argument order. Its return value is interpreted exactly as curl
    /// does:
    ///
    /// * [`CURL_PROGRESSFUNC_CONTINUE`] — continue and let the built-in meter
    ///   draw (subject to the redraw decision and the hidden flag);
    /// * `0` — continue but suppress the meter for this update;
    /// * any other value — abort with
    ///   [`CurlError::AbortedByCallback`](crate::error::CurlError::AbortedByCallback).
    ///
    /// When `CURLOPT_NOPROGRESS` is set ([`Progress::set_hide`]), neither the
    /// callback nor the meter runs and `Ok(false)` is returned.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::AbortedByCallback`](crate::error::CurlError::AbortedByCallback)
    /// when the application callback returns a non-zero, non-continue value.
    pub fn update(
        &mut self,
        now: Instant,
        req_done: bool,
        callback: Option<ProgressCallbackRef<'_>>,
    ) -> Result<bool> {
        let showprogress = self.calc(now, req_done);
        self.dispatch(showprogress, callback)
    }

    /// Invokes the callback (if any) and decides whether the meter should draw.
    /// Factored out of [`Progress::update`] so [`Progress::check`] can share it.
    fn dispatch(
        &mut self,
        showprogress: bool,
        callback: Option<ProgressCallbackRef<'_>>,
    ) -> Result<bool> {
        if self.hide {
            // NOPROGRESS: no callback, no meter.
            return Ok(false);
        }

        if let Some(callback) = callback {
            let result = match callback {
                ProgressCallbackRef::Xferinfo(f) => f(
                    self.dl.total_size,
                    self.dl.cur_size,
                    self.ul.total_size,
                    self.ul.cur_size,
                ),
                ProgressCallbackRef::Progress(f) => f(
                    self.dl.total_size as f64,
                    self.dl.cur_size as f64,
                    self.ul.total_size as f64,
                    self.ul.cur_size as f64,
                ),
            };
            if result != CURL_PROGRESSFUNC_CONTINUE {
                if result != 0 {
                    return Err(CurlError::AbortedByCallback);
                }
                // Callback asked to continue without drawing the meter.
                return Ok(false);
            }
            // CURL_PROGRESSFUNC_CONTINUE: fall through to the meter decision.
        }

        Ok(showprogress)
    }

    /// Updates progress and, when the request is not yet done, runs the
    /// low-speed abort check (`Curl_pgrsCheck`).
    ///
    /// Equivalent to calling [`Progress::update`] followed by
    /// [`Progress::speed_check`] (the latter only while `!req_done`). Returns
    /// whether the caller should draw the meter.
    ///
    /// # Errors
    ///
    /// Propagates [`CurlError::AbortedByCallback`](crate::error::CurlError::AbortedByCallback)
    /// from the callback, or returns
    /// [`CurlError::OperationTimedout`](crate::error::CurlError::OperationTimedout)
    /// when the low-speed limit has been violated for too long.
    #[allow(clippy::too_many_arguments)]
    pub fn check(
        &mut self,
        now: Instant,
        req_done: bool,
        paused: bool,
        low_speed_limit: i64,
        low_speed_time: u32,
        callback: Option<ProgressCallbackRef<'_>>,
    ) -> Result<bool> {
        let show = self.update(now, req_done, callback)?;
        if !req_done {
            self.speed_check(low_speed_limit, low_speed_time, paused, now)?;
        }
        Ok(show)
    }

    /// Enforces `CURLOPT_LOW_SPEED_LIMIT` / `CURLOPT_LOW_SPEED_TIME`
    /// (`pgrs_speedcheck`).
    ///
    /// While the current speed stays below `low_speed_limit` bytes/second for at
    /// least `low_speed_time` seconds, the transfer is aborted with
    /// [`CurlError::OperationTimedout`](crate::error::CurlError::OperationTimedout).
    /// The check is skipped entirely when either option is zero or the transfer
    /// is `paused`. The clock starts the first time the speed drops below the
    /// limit and is cleared whenever the speed recovers — matching curl's
    /// `state.keeps_speed` accounting.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::OperationTimedout`](crate::error::CurlError::OperationTimedout)
    /// when the speed has been below the limit for at least `low_speed_time`
    /// seconds.
    pub fn speed_check(
        &mut self,
        low_speed_limit: i64,
        low_speed_time: u32,
        paused: bool,
        now: Instant,
    ) -> Result<()> {
        if low_speed_time == 0 || low_speed_limit == 0 || paused {
            // Not qualified for a speed check.
            return Ok(());
        }

        if self.current_speed >= 0 {
            if self.current_speed < low_speed_limit {
                match self.keeps_speed {
                    // First moment under the limit: start the clock.
                    None => self.keeps_speed = Some(now),
                    Some(since) => {
                        let howlong = now.saturating_duration_since(since);
                        if howlong >= Duration::from_secs(u64::from(low_speed_time)) {
                            return Err(CurlError::OperationTimedout);
                        }
                    }
                }
            } else {
                // Fast enough right now: clear the under-limit clock.
                self.keeps_speed = None;
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Rate-limit hand-off and configuration
// ---------------------------------------------------------------------------
impl Progress {
    /// Sets the download (receive) rate cap in bytes/second
    /// (`CURLOPT_MAX_RECV_SPEED_LARGE`); `0` disables it.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::BadFunctionArgument`](crate::error::CurlError::BadFunctionArgument)
    /// when `bytes_per_sec` is negative, exactly as libcurl's `setopt` does.
    pub fn set_max_recv_speed(&mut self, bytes_per_sec: i64) -> Result<()> {
        self.ratelimit.set_recv_limit(bytes_per_sec)
    }

    /// Sets the upload (send) rate cap in bytes/second
    /// (`CURLOPT_MAX_SEND_SPEED_LARGE`); `0` disables it.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::BadFunctionArgument`](crate::error::CurlError::BadFunctionArgument)
    /// when `bytes_per_sec` is negative.
    pub fn set_max_send_speed(&mut self, bytes_per_sec: i64) -> Result<()> {
        self.ratelimit.set_send_limit(bytes_per_sec)
    }

    /// Returns the configured download (receive) cap in bytes/second
    /// (`0` = unlimited).
    #[must_use]
    pub fn max_recv_speed(&self) -> u64 {
        self.ratelimit.recv_limit()
    }

    /// Returns the configured upload (send) cap in bytes/second
    /// (`0` = unlimited).
    #[must_use]
    pub fn max_send_speed(&self) -> u64 {
        self.ratelimit.send_limit()
    }

    /// Computes how long the transfer in `direction` must pause to keep its
    /// rate at or below the configured cap, feeding the running byte counter to
    /// the rate limiter (the `Curl_pgrsLimitWaitTime` hand-off).
    ///
    /// Returns [`Duration::ZERO`] when the direction is unlimited or already on
    /// pace. The caller (the async transfer engine) is responsible for actually
    /// awaiting the returned duration.
    #[must_use]
    pub fn limit_wait_time(&mut self, direction: Direction, now: Instant) -> Duration {
        let total = match direction {
            Direction::Download => self.dl.cur_size,
            Direction::Upload => self.ul.cur_size,
        };
        // Counters are non-negative; clamp defensively for the conversion.
        let total = u64::try_from(total).unwrap_or(0);
        self.ratelimit.wait_time(direction, total, now)
    }
}

// ---------------------------------------------------------------------------
// Flags and meter lifecycle
// ---------------------------------------------------------------------------
impl Progress {
    /// Sets the hidden (`CURLOPT_NOPROGRESS`) flag. When hidden, neither the
    /// meter nor the callbacks run.
    pub fn set_hide(&mut self, hide: bool) {
        self.hide = hide;
    }

    /// Returns whether the meter is hidden (`CURLOPT_NOPROGRESS`).
    #[must_use]
    pub fn is_hidden(&self) -> bool {
        self.hide
    }

    /// Records whether an application progress/xferinfo callback is configured.
    ///
    /// Mirrors curl's `progress.callback` flag, set when
    /// `CURLOPT_PROGRESSFUNCTION`/`CURLOPT_XFERINFOFUNCTION` is given a non-NULL
    /// function. It only affects whether a trailing newline is printed when the
    /// transfer finishes (see [`Progress::should_print_final_newline`]).
    pub fn set_callback_used(&mut self, used: bool) {
        self.callback = used;
    }

    /// Returns whether an application progress callback is configured.
    #[must_use]
    pub fn callback_used(&self) -> bool {
        self.callback
    }

    /// Forces the next meter update to redraw, regardless of the once-per-second
    /// throttle (the `lastshow = 0` reset performed by `Curl_pgrsDone`).
    pub fn force_redraw(&mut self) {
        self.lastshow = None;
    }

    /// Returns whether a trailing newline should be printed when the transfer
    /// finishes: only when the meter is visible *and* no callback is in use,
    /// matching `Curl_pgrsDone`.
    #[must_use]
    pub fn should_print_final_newline(&self) -> bool {
        !self.hide && !self.callback
    }

    /// Returns whether the meter header line has already been emitted.
    #[must_use]
    pub fn headers_out(&self) -> bool {
        self.headers_out
    }
}

// ---------------------------------------------------------------------------
// getinfo accessors — back the CURLINFO_* timing/size/speed queries
// ---------------------------------------------------------------------------
impl Progress {
    /// Bytes downloaded so far (`CURLINFO_SIZE_DOWNLOAD_T`).
    #[must_use]
    pub fn download_size(&self) -> i64 {
        self.dl.cur_size
    }

    /// Bytes downloaded so far as `f64` (`CURLINFO_SIZE_DOWNLOAD`).
    #[must_use]
    pub fn download_size_f64(&self) -> f64 {
        self.dl.cur_size as f64
    }

    /// Bytes uploaded so far (`CURLINFO_SIZE_UPLOAD_T`).
    #[must_use]
    pub fn upload_size(&self) -> i64 {
        self.ul.cur_size
    }

    /// Bytes uploaded so far as `f64` (`CURLINFO_SIZE_UPLOAD`).
    #[must_use]
    pub fn upload_size_f64(&self) -> f64 {
        self.ul.cur_size as f64
    }

    /// Expected download size, or `None` when unknown
    /// (`CURLINFO_CONTENT_LENGTH_DOWNLOAD_T`; callers map `None` to `-1`).
    #[must_use]
    pub fn download_total(&self) -> Option<i64> {
        if self.dl_size_known {
            Some(self.dl.total_size)
        } else {
            None
        }
    }

    /// Expected upload size, or `None` when unknown
    /// (`CURLINFO_CONTENT_LENGTH_UPLOAD_T`).
    #[must_use]
    pub fn upload_total(&self) -> Option<i64> {
        if self.ul_size_known {
            Some(self.ul.total_size)
        } else {
            None
        }
    }

    /// Average download speed in bytes/second (`CURLINFO_SPEED_DOWNLOAD_T`).
    #[must_use]
    pub fn download_speed(&self) -> i64 {
        self.dl.speed
    }

    /// Average download speed in bytes/second as `f64`
    /// (`CURLINFO_SPEED_DOWNLOAD`).
    #[must_use]
    pub fn download_speed_f64(&self) -> f64 {
        self.dl.speed as f64
    }

    /// Average upload speed in bytes/second (`CURLINFO_SPEED_UPLOAD_T`).
    #[must_use]
    pub fn upload_speed(&self) -> i64 {
        self.ul.speed
    }

    /// Average upload speed in bytes/second as `f64` (`CURLINFO_SPEED_UPLOAD`).
    #[must_use]
    pub fn upload_speed_f64(&self) -> f64 {
        self.ul.speed as f64
    }

    /// The currently fastest measured speed in bytes/second (the rolling-window
    /// "current speed").
    #[must_use]
    pub fn current_speed(&self) -> i64 {
        self.current_speed
    }

    /// TLS early-data bytes sent.
    #[must_use]
    pub fn early_data_sent(&self) -> i64 {
        self.earlydata_sent
    }

    /// Total time spent so far (`CURLINFO_TOTAL_TIME[_T]`).
    #[must_use]
    pub fn total_time(&self) -> TimerData {
        TimerData::from_micros(self.timespent)
    }

    /// Time until name resolution completed (`CURLINFO_NAMELOOKUP_TIME[_T]`).
    #[must_use]
    pub fn namelookup_time(&self) -> TimerData {
        self.t_nslookup
    }

    /// Time until the connection completed (`CURLINFO_CONNECT_TIME[_T]`).
    #[must_use]
    pub fn connect_time(&self) -> TimerData {
        self.t_connect
    }

    /// Time until the TLS handshake completed (`CURLINFO_APPCONNECT_TIME[_T]`).
    #[must_use]
    pub fn appconnect_time(&self) -> TimerData {
        self.t_appconnect
    }

    /// Time until pre-transfer setup completed (`CURLINFO_PRETRANSFER_TIME[_T]`).
    #[must_use]
    pub fn pretransfer_time(&self) -> TimerData {
        self.t_pretransfer
    }

    /// Time until the first response byte (`CURLINFO_STARTTRANSFER_TIME[_T]`).
    #[must_use]
    pub fn starttransfer_time(&self) -> TimerData {
        self.t_starttransfer
    }

    /// Time recorded at post-transfer (`CURLINFO_POSTTRANSFER_TIME_T`).
    #[must_use]
    pub fn posttransfer_time(&self) -> TimerData {
        self.t_posttransfer
    }

    /// Cumulative time spent in redirects (`CURLINFO_REDIRECT_TIME[_T]`).
    #[must_use]
    pub fn redirect_time(&self) -> TimerData {
        self.t_redirect
    }

    /// Cumulative time spent queued (`CURLINFO_QUEUE_TIME_T`).
    #[must_use]
    pub fn postqueue_time(&self) -> TimerData {
        self.t_postqueue
    }

    /// Whole-second mark of the operation elapsed time, used internally by the
    /// once-per-second meter throttle.
    fn secs_since_start(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.start).as_secs()
    }
}

// ---------------------------------------------------------------------------
// Internal time / arithmetic helpers
// ---------------------------------------------------------------------------

/// Microseconds in `d`, saturating at [`i64::MAX`] (no lossy `as` truncation).
fn dur_us(d: Duration) -> i64 {
    i64::try_from(d.as_micros()).unwrap_or(i64::MAX)
}

/// Milliseconds in `d`, saturating at [`i64::MAX`].
fn dur_ms(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

/// Monotonic microseconds from `older` to `newer` (`newer − older`), clamped to
/// be non-negative — the non-negative case of curl's `curlx_ptimediff_us` that
/// the progress arithmetic relies on.
fn ptimediff_us(newer: Instant, older: Instant) -> i64 {
    dur_us(newer.saturating_duration_since(older))
}

/// Saturating conversion from [`i128`] to [`i64`] (clamps at the `i64` bounds).
fn saturating_i64(value: i128) -> i64 {
    if value > i128::from(i64::MAX) {
        i64::MAX
    } else if value < i128::from(i64::MIN) {
        i64::MIN
    } else {
        value as i64
    }
}

/// Average speed in bytes/second for `size` bytes over `us` microseconds,
/// reproducing curl's `trspeed` exactly (including its overflow guards).
///
/// * `us < 1` → treat as an instantaneous transfer: `size * 1e6` (saturating).
/// * the common case multiplies in `i64` after confirming it cannot overflow.
/// * the large-`size` cases fall back to dividing first, then capping at
///   [`i64::MAX`], matching curl.
fn trspeed(size: i64, us: i64) -> i64 {
    if us < 1 {
        size.saturating_mul(MICROS_PER_SEC)
    } else if size < i64::MAX / MICROS_PER_SEC {
        size * MICROS_PER_SEC / us
    } else if us >= MICROS_PER_SEC {
        size / (us / MICROS_PER_SEC)
    } else {
        i64::MAX
    }
}

/// Percentage of `cur` against `total`, reproducing curl's `pgrs_est_percent`.
///
/// The two branches avoid overflow the way curl does (dividing the larger
/// operand first when `total` is big); the small-`total` branch is widened to
/// [`i128`] so `cur * 100` cannot overflow for any byte count.
fn pgrs_est_percent(total: i64, cur: i64) -> i64 {
    if total > 10000 {
        cur / (total / 100)
    } else if total > 0 {
        saturating_i64(i128::from(cur) * 100 / i128::from(total))
    } else {
        0
    }
}

/// Estimated remaining seconds and percent-complete for one direction,
/// reproducing curl's `pgrs_estimates`.
///
/// Yields `(0, 0)` unless the total size is known and a positive speed has been
/// measured.
fn pgrs_estimates(total_size: i64, cur_size: i64, speed: i64, total_known: bool) -> (i64, i64) {
    if total_known && speed > 0 {
        (total_size / speed, pgrs_est_percent(total_size, cur_size))
    } else {
        (0, 0)
    }
}

// ---------------------------------------------------------------------------
// Human-readable formatting (curl's time2str / max6out — unit test 1636)
// ---------------------------------------------------------------------------

/// Formats `seconds` as a fixed-width 7-character human-readable duration,
/// reproducing curl's `time2str` byte-for-byte.
///
/// The output is always exactly seven characters: blank for non-positive input,
/// `MM:SS` / `H:MM:SS` for short durations, `Hh MMm` / `Dd HHh` for longer ones,
/// and finally a single `Nd` / `Nm` / `Ny` magnitude (capped at `>99999y`). This
/// matches the columns drawn by the progress meter and is validated against
/// curl's unit test 1636.
#[must_use]
pub fn time2str(seconds: i64) -> String {
    if seconds <= 0 {
        return "       ".to_string(); // seven spaces
    }
    let h = seconds / 3600;
    if h <= 99 {
        let m = (seconds - (h * 3600)) / 60;
        if h <= 9 {
            let s = (seconds - (h * 3600)) - (m * 60);
            if h != 0 {
                format!("{h}:{m:02}:{s:02}")
            } else {
                format!("  {m:02}:{s:02}")
            }
        } else {
            format!("{h}h {m:02}m")
        }
    } else {
        let d = seconds / 86400;
        let h = (seconds - (d * 86400)) / 3600;
        if d <= 99 {
            format!("{d:2}d {h:02}h")
        } else if d <= 999 {
            format!("{d:6}d")
        } else {
            let m = d / 30;
            if m <= 999 {
                format!("{m:6}m")
            } else {
                let y = d / 365;
                if y <= 99999 {
                    format!("{y:6}y")
                } else {
                    ">99999y".to_string()
                }
            }
        }
    }
}

/// Formats `bytes` as a fixed-width 6-character human-readable size,
/// reproducing curl's `max6out` byte-for-byte.
///
/// Values below 100000 are printed right-aligned as-is; larger values are scaled
/// to the largest fitting unit (`k`, `M`, `G`, `T`, `P`, `E`) with two or one
/// fractional digits so the field never exceeds six characters. Validated
/// against curl's unit test 1636.
#[must_use]
pub fn max6out(bytes: i64) -> String {
    if bytes < 100_000 {
        return format!("{bytes:6}");
    }

    /// Unit suffixes, ascending; curl's `{ 'k','M','G','T','P','E', 0 }`.
    const UNIT: [char; 6] = ['k', 'M', 'G', 'T', 'P', 'E'];

    let mut b = bytes;
    let mut k = 0usize;
    let mut nbytes = b / 1024;
    while nbytes >= 1000 {
        b = nbytes;
        k += 1;
        if k >= UNIT.len() {
            // Unreachable for i64 inputs (i64::MAX is below 1000 * 1024^6); cap
            // at the largest unit rather than indexing out of bounds.
            k = UNIT.len() - 1;
            break;
        }
        nbytes = b / 1024;
    }

    let rest = b % 1024;
    let unit = UNIT[k];
    if nbytes <= 99 {
        // "xx.yyU"
        format!("{nbytes:2}.{:02}{unit}", rest * 100 / 1024)
    } else {
        // "xxx.yU"
        format!("{nbytes:3}.{}{unit}", rest * 10 / 1024)
    }
}

/// The two header lines the progress meter prints once, before the first data
/// line. Exact bytes from `lib/progress.c` (`%%` resolved to `%`).
const METER_HEADER: &str = concat!(
    "  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current\n",
    "                                 Dload  Upload  Total   Spent   Left   Speed\n",
);

// ---------------------------------------------------------------------------
// Built-in progress meter rendering (curl's progress_meter)
// ---------------------------------------------------------------------------
impl Progress {
    /// Renders the built-in progress meter, reproducing curl's `progress_meter`,
    /// and returns it as a string the caller writes to the error stream.
    ///
    /// On the first call (per [`Progress::headers_out`]) the two-line column
    /// header is prepended and the header flag is set, exactly as curl emits the
    /// header once. Each call then appends the carriage-return-prefixed status
    /// line: the overall / received / transferred percentages and sizes, the
    /// average download and upload speeds, the total / spent / left times, and
    /// the current speed. Sizes and times are formatted with [`max6out`] and
    /// [`time2str`], so the field widths match curl's columns.
    ///
    /// This performs no I/O itself — keeping the module testable and free of any
    /// stream dependency. libcurl-side callers write the returned string to the
    /// configured error stream; the CLI uses it for the default meter.
    pub fn render_meter(&mut self) -> String {
        let mut out = String::new();
        if !self.headers_out {
            out.push_str(METER_HEADER);
            self.headers_out = true;
        }

        // Elapsed whole seconds.
        let cur_secs = self.timespent / MICROS_PER_SEC;

        // Per-direction ETA / percent estimates.
        let (ul_secs, ul_percent) = pgrs_estimates(
            self.ul.total_size,
            self.ul.cur_size,
            self.ul.speed,
            self.ul_size_known,
        );
        let (dl_secs, dl_percent) = pgrs_estimates(
            self.dl.total_size,
            self.dl.cur_size,
            self.dl.speed,
            self.dl_size_known,
        );

        // Upload and download happen concurrently, so the combined ETA is the
        // larger of the two.
        let total_secs = ul_secs.max(dl_secs);
        let time_left = if total_secs > 0 {
            (total_secs - cur_secs).max(0)
        } else {
            0
        };

        // Total expected = known totals (else current) for each direction,
        // capped to avoid overflow exactly as curl does.
        let ul_expected = if self.ul_size_known {
            self.ul.total_size
        } else {
            self.ul.cur_size
        };
        let dl_expected = if self.dl_size_known {
            self.dl.total_size
        } else {
            self.dl.cur_size
        };
        let total_expected_size = if i64::MAX - ul_expected < dl_expected {
            i64::MAX
        } else {
            ul_expected + dl_expected
        };

        let total_cur_size = self.dl.cur_size.saturating_add(self.ul.cur_size);
        let total_percent = pgrs_est_percent(total_expected_size, total_cur_size);

        out.push_str(&format!(
            "\r{:3} {} {:3} {} {:3} {} {} {} {} {} {} {}",
            total_percent,                // total %
            max6out(total_expected_size), // total size
            dl_percent,                   // received %
            max6out(self.dl.cur_size),    // received size
            ul_percent,                   // transferred %
            max6out(self.ul.cur_size),    // transferred size
            max6out(self.dl.speed),       // average download speed
            max6out(self.ul.speed),       // average upload speed
            time2str(total_secs),         // total time
            time2str(cur_secs),           // time spent
            time2str(time_left),          // time left
            max6out(self.current_speed),  // current speed
        ));

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An instant `secs` seconds after `base`.
    fn at_secs(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    /// An instant `ms` milliseconds after `base`.
    fn at_ms(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    // -- TimerData ---------------------------------------------------------

    #[test]
    fn timerdata_dual_representation() {
        let t = TimerData::from_micros(1_500_000);
        assert_eq!(t.as_micros(), 1_500_000);
        assert!((t.as_seconds() - 1.5).abs() < 1e-9);
        assert!(t.is_set());
        assert!(!TimerData::zero().is_set());
        assert_eq!(TimerData::zero().as_micros(), 0);
        assert_eq!(TimerData::zero().as_seconds(), 0.0);
    }

    #[test]
    fn timerdata_add_micros_saturates() {
        let mut t = TimerData::from_micros(10);
        t.add_micros(5);
        assert_eq!(t.as_micros(), 15);
        t.add_micros(i64::MAX);
        assert_eq!(t.as_micros(), i64::MAX); // saturates, no panic
    }

    // -- construction / lifecycle -----------------------------------------

    #[test]
    fn new_is_zeroed_and_visible() {
        let t0 = Instant::now();
        let p = Progress::new(t0);
        assert_eq!(p.download_size(), 0);
        assert_eq!(p.upload_size(), 0);
        assert_eq!(p.download_total(), None);
        assert_eq!(p.upload_total(), None);
        assert_eq!(p.current_speed(), 0);
        assert_eq!(p.total_time(), TimerData::zero());
        assert_eq!(p.namelookup_time(), TimerData::zero());
        assert!(!p.is_hidden());
        assert!(!p.callback_used());
        assert!(!p.headers_out());
        assert!(p.should_print_final_newline());
        assert_eq!(p.max_recv_speed(), 0);
        assert_eq!(p.max_send_speed(), 0);
    }

    #[test]
    fn start_now_resets_counters_but_keeps_milestone_timers() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        // Record a milestone and some progress on the first single transfer.
        p.time(Timer::StartSingle, t0);
        p.time(Timer::NameLookup, at_ms(t0, 5));
        p.download_inc(1234);
        p.set_download_size(9999);
        assert!(p.namelookup_time().is_set());

        // Starting a new transfer clears counters/sizes but NOT the cumulative
        // milestone timers (they accumulate across redirects).
        p.start_now(at_secs(t0, 1));
        assert_eq!(p.download_size(), 0);
        assert_eq!(p.upload_size(), 0);
        assert_eq!(p.download_total(), None);
        assert!(
            p.namelookup_time().is_set(),
            "milestone must survive start_now"
        );
    }

    #[test]
    fn reset_clears_sizes_and_speed_history() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.set_download_size(1000);
        p.set_upload_size(2000);
        p.download_inc(500);
        p.reset(t0);
        assert_eq!(p.download_size(), 0);
        assert_eq!(p.download_total(), None);
        assert_eq!(p.upload_total(), None);
        assert_eq!(p.speeder_c, 0);
    }

    #[test]
    fn reset_transfer_sizes_only_marks_unknown() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.set_download_size(1000);
        p.set_upload_size(2000);
        p.download_inc(7);
        p.reset_transfer_sizes();
        assert_eq!(p.download_total(), None);
        assert_eq!(p.upload_total(), None);
        // Counters are untouched by a sizes-only reset.
        assert_eq!(p.download_size(), 7);
    }

    // -- counters & sizes --------------------------------------------------

    #[test]
    fn counters_increment_and_set() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.download_inc(100);
        p.download_inc(50);
        assert_eq!(p.download_size(), 150);
        p.upload_inc(10);
        assert_eq!(p.upload_size(), 10);
        p.set_upload_counter(999);
        assert_eq!(p.upload_size(), 999);
        p.set_download_counter(42);
        assert_eq!(p.download_size(), 42);
        // Negative absolute counters clamp to zero.
        p.set_download_counter(-5);
        assert_eq!(p.download_size(), 0);
        // A zero increment is a no-op.
        p.download_inc(0);
        assert_eq!(p.download_size(), 0);
    }

    #[test]
    fn size_setters_follow_sign_convention() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.set_download_size(2048);
        assert_eq!(p.download_total(), Some(2048));
        p.set_download_size(-1);
        assert_eq!(p.download_total(), None);
        p.set_upload_size(0);
        assert_eq!(p.upload_total(), Some(0)); // zero is "known and empty"
        p.set_upload_size(-7);
        assert_eq!(p.upload_total(), None);
    }

    #[test]
    fn early_data_is_recorded() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.early_data(4096);
        assert_eq!(p.early_data_sent(), 4096);
    }

    // -- milestone capture -------------------------------------------------

    #[test]
    fn phase_deltas_accumulate_from_single_start() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.time(Timer::StartSingle, t0);
        p.time(Timer::NameLookup, at_ms(t0, 10)); // +10ms = 10_000us
        p.time(Timer::Connect, at_ms(t0, 30)); // +30ms = 30_000us
        p.time(Timer::AppConnect, at_ms(t0, 80));
        assert_eq!(p.namelookup_time().as_micros(), 10_000);
        assert_eq!(p.connect_time().as_micros(), 30_000);
        assert_eq!(p.appconnect_time().as_micros(), 80_000);

        // A second single transfer (a redirect) re-bases t_startsingle, and the
        // delta accumulates onto the previous value.
        p.time(Timer::StartSingle, at_secs(t0, 1));
        p.time(Timer::NameLookup, at_ms(t0, 1_005)); // +5ms onto 10ms
        assert_eq!(p.namelookup_time().as_micros(), 10_000 + 5_000);
    }

    #[test]
    fn min_one_microsecond_for_zero_delta() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.time(Timer::StartSingle, t0);
        // Captured at the exact same instant: curl forces at least 1us.
        p.time(Timer::Connect, t0);
        assert_eq!(p.connect_time().as_micros(), 1);
    }

    #[test]
    fn starttransfer_recorded_once_per_single() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.time(Timer::StartSingle, t0);
        // The first capture records 100_000us; a second capture in the SAME
        // single transfer is ignored.
        p.time(Timer::StartTransfer, at_ms(t0, 100));
        p.time(Timer::StartTransfer, at_ms(t0, 500));
        assert_eq!(p.starttransfer_time().as_micros(), 100_000);

        // After a new single transfer it can be recorded again (accumulating).
        p.time(Timer::StartSingle, at_secs(t0, 1));
        p.time(Timer::StartTransfer, at_ms(t0, 1_050)); // +50ms
        assert_eq!(p.starttransfer_time().as_micros(), 100_000 + 50_000);
    }

    #[test]
    fn redirect_time_is_from_op_start_and_rebases_queue() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.start_now(t0); // start = t0
        p.time(Timer::Redirect, at_ms(t0, 250)); // 250ms from start
        assert_eq!(p.redirect_time().as_micros(), 250_000);
        // Redirect rebases the queue clock; PostQueue then measures from there.
        p.time(Timer::PostQueue, at_ms(t0, 300)); // +50ms onto the rebased queue
        assert_eq!(p.postqueue_time().as_micros(), 50_000);
    }

    #[test]
    fn startop_resets_postqueue_and_anchors_queue() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.time(Timer::StartOp, t0);
        p.time(Timer::PostQueue, at_ms(t0, 40)); // +40ms
        assert_eq!(p.postqueue_time().as_micros(), 40_000);
        // A fresh StartOp zeroes the cumulative queue time.
        p.time(Timer::StartOp, at_secs(t0, 1));
        assert_eq!(p.postqueue_time().as_micros(), 0);
    }

    #[test]
    fn timer_none_is_noop() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.time(Timer::None, at_ms(t0, 100));
        assert_eq!(p.namelookup_time(), TimerData::zero());
        assert_eq!(p.total_time(), TimerData::zero());
    }

    // -- speed calculation -------------------------------------------------

    #[test]
    fn calc_seeds_speed_on_first_call() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.start_now(t0);
        p.download_inc(1000);
        let show = p.calc(at_secs(t0, 1), false);
        assert!(show, "first calc always shows");
        // Average download speed = 1000 bytes / 1s = 1000 B/s.
        assert_eq!(p.download_speed(), 1000);
        assert_eq!(p.upload_speed(), 0);
        // Seeded current speed is the sum of the average speeds.
        assert_eq!(p.current_speed(), 1000);
        // Total time is exactly one second.
        assert_eq!(p.total_time().as_micros(), 1_000_000);
        assert!((p.total_time().as_seconds() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn calc_ongoing_within_one_second_does_not_show() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.start_now(t0);
        p.download_inc(1000);
        assert!(p.calc(at_secs(t0, 1), false));
        // Less than a second since the last sample, transfer ongoing: no show.
        p.download_inc(10);
        assert!(!p.calc(at_ms(t0, 1_500), false));
    }

    #[test]
    fn calc_windowed_current_speed_steady_rate() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.start_now(t0);
        // 1000 B/s sustained over several one-second samples.
        for sec in 1..=5u64 {
            p.set_download_counter(1000 * i64::try_from(sec).unwrap());
            p.calc(at_secs(t0, sec), false);
        }
        assert_eq!(p.current_speed(), 1000);
    }

    #[test]
    fn calc_done_forces_show_even_within_second() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.start_now(t0);
        p.download_inc(500);
        assert!(p.calc(at_secs(t0, 1), false));
        p.download_inc(500);
        // Same second, but req_done overrides the once-per-second throttle.
        assert!(p.calc(at_ms(t0, 1_200), true));
    }

    // -- low-speed abort (parity with curl unit test 1606) -----------------

    /// Faithful port of curl's `unit1606.c` `runawhile`: drives a constant or
    /// decaying speed one second at a time and returns the final second at which
    /// the low-speed check aborts (or 99 if it never does).
    fn runawhile(time_limit: u32, speed_limit: i64, mut speed: i64, dec: i64) -> i64 {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.reset(t0);
        let mut counter: i64 = 1;
        loop {
            let now = at_secs(t0, u64::try_from(counter).unwrap());
            p.current_speed = speed;
            if p.speed_check(speed_limit, time_limit, false, now).is_err() {
                return counter - 1;
            }
            counter += 1;
            speed -= dec;
            if counter >= 100 {
                return counter - 1;
            }
        }
    }

    #[test]
    fn low_speed_timeouts_match_curl_unit1606() {
        assert_eq!(runawhile(41, 41, 40, 0), 41, "wrong low speed timeout");
        assert_eq!(runawhile(21, 21, 20, 0), 21, "wrong low speed timeout");
        assert_eq!(runawhile(60, 60, 40, 0), 60, "wrong low speed timeout");
        assert_eq!(runawhile(50, 50, 40, 0), 50, "wrong low speed timeout");
        assert_eq!(runawhile(40, 40, 40, 0), 99, "should not time out");
        assert_eq!(runawhile(10, 50, 100, 2), 36, "bad timeout");
    }

    #[test]
    fn speed_check_skipped_when_disabled_or_paused() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.current_speed = 1; // very slow
                             // Zero time disables the check.
        assert!(p.speed_check(1000, 0, false, t0).is_ok());
        // Zero limit disables the check.
        assert!(p.speed_check(0, 10, false, t0).is_ok());
        // Paused transfers are never checked.
        assert!(p.speed_check(1000, 1, true, at_secs(t0, 100)).is_ok());
    }

    #[test]
    fn speed_check_clears_clock_when_recovering() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        // Drop below the limit: clock starts.
        p.current_speed = 10;
        assert!(p.speed_check(100, 5, false, at_secs(t0, 1)).is_ok());
        assert!(p.keeps_speed.is_some());
        // Recover above the limit: clock clears.
        p.current_speed = 200;
        assert!(p.speed_check(100, 5, false, at_secs(t0, 2)).is_ok());
        assert!(p.keeps_speed.is_none());
    }

    // -- callback dispatch -------------------------------------------------

    #[test]
    fn xferinfo_callback_receives_counters_in_order() {
        use std::cell::Cell;
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.start_now(t0);
        p.set_download_size(1000);
        p.download_inc(500);

        let seen: Cell<(i64, i64, i64, i64)> = Cell::new((0, 0, 0, 0));
        let mut cb = |dt: i64, dn: i64, ut: i64, un: i64| {
            seen.set((dt, dn, ut, un));
            CURL_PROGRESSFUNC_CONTINUE
        };
        let show = p
            .update(
                at_secs(t0, 1),
                false,
                Some(ProgressCallbackRef::Xferinfo(&mut cb)),
            )
            .unwrap();
        // CONTINUE → meter draw decision returned (first calc shows).
        assert!(show);
        // Args are (dl total, dl now, ul total, ul now).
        assert_eq!(seen.get(), (1000, 500, 0, 0));
    }

    #[test]
    fn progress_callback_receives_doubles() {
        use std::cell::Cell;
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.start_now(t0);
        p.set_upload_size(200);
        p.upload_inc(50);

        let seen: Cell<(f64, f64, f64, f64)> = Cell::new((0.0, 0.0, 0.0, 0.0));
        let mut cb = |dt: f64, dn: f64, ut: f64, un: f64| {
            seen.set((dt, dn, ut, un));
            0 // not CONTINUE → suppress meter, no abort
        };
        let show = p
            .update(
                at_secs(t0, 1),
                false,
                Some(ProgressCallbackRef::Progress(&mut cb)),
            )
            .unwrap();
        assert!(!show, "returning 0 suppresses the meter");
        assert_eq!(seen.get(), (0.0, 0.0, 200.0, 50.0));
    }

    #[test]
    fn nonzero_callback_return_aborts() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.start_now(t0);
        let mut cb = |_: i64, _: i64, _: i64, _: i64| 1; // abort
        let r = p.update(
            at_secs(t0, 1),
            false,
            Some(ProgressCallbackRef::Xferinfo(&mut cb)),
        );
        assert_eq!(r, Err(CurlError::AbortedByCallback));
    }

    #[test]
    fn noprogress_suppresses_callback_and_meter() {
        use std::cell::Cell;
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.start_now(t0);
        p.set_hide(true);
        let calls = Cell::new(0u32);
        let mut cb = |_: i64, _: i64, _: i64, _: i64| {
            calls.set(calls.get() + 1);
            1
        };
        let show = p
            .update(
                at_secs(t0, 1),
                false,
                Some(ProgressCallbackRef::Xferinfo(&mut cb)),
            )
            .unwrap();
        assert!(!show);
        assert_eq!(calls.get(), 0, "hidden meter must not call the callback");
    }

    #[test]
    fn update_without_callback_returns_show_decision() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.start_now(t0);
        let show = p.update(at_secs(t0, 1), false, None).unwrap();
        assert!(show);
    }

    #[test]
    fn check_combines_update_and_speedcheck() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.reset(t0);
        // Establish a slow current speed via repeated checks below the limit.
        let mut counter: i64 = 1;
        loop {
            let now = at_secs(t0, u64::try_from(counter).unwrap());
            p.current_speed = 10; // below the 100 B/s limit
            match p.check(now, false, false, 100, 5, None) {
                Ok(_) => {}
                Err(e) => {
                    assert_eq!(e, CurlError::OperationTimedout);
                    // Started the clock at counter==1, aborts when 5s elapsed.
                    assert_eq!(counter - 1, 5);
                    break;
                }
            }
            counter += 1;
            assert!(counter < 50, "should have aborted by now");
        }
    }

    #[test]
    fn check_skips_speedcheck_when_done() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.reset(t0);
        p.current_speed = 0; // would otherwise be "too slow"
                             // req_done == true → speed check skipped, no timeout.
        let r = p.check(at_secs(t0, 100), true, false, 100, 1, None);
        assert!(r.is_ok());
    }

    // -- rate-limit hand-off ----------------------------------------------

    #[test]
    fn rate_limit_configuration_and_handoff() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        // Negative caps are rejected exactly like libcurl setopt.
        assert_eq!(
            p.set_max_recv_speed(-1),
            Err(CurlError::BadFunctionArgument)
        );
        p.set_max_recv_speed(1_000).unwrap();
        assert_eq!(p.max_recv_speed(), 1_000);

        // 2000 bytes downloaded should owe ~2s at 1000 B/s; after 500ms elapsed,
        // 1500ms of wait remains.
        p.set_download_counter(2_000);
        let wait = p.limit_wait_time(Direction::Download, at_ms(t0, 500));
        assert_eq!(wait, Duration::from_millis(1_500));

        // Upload is unlimited → never waits.
        p.set_upload_counter(10_000);
        assert_eq!(
            p.limit_wait_time(Direction::Upload, at_ms(t0, 1)),
            Duration::ZERO
        );
    }

    #[test]
    fn start_now_rebaselines_rate_limit_window() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.set_max_send_speed(1_000).unwrap();
        assert_eq!(p.max_send_speed(), 1_000);
        // start_now resets the window; a fresh transfer at t0 then owes time from
        // its own baseline.
        p.start_now(t0);
        p.set_upload_counter(3_000);
        let wait = p.limit_wait_time(Direction::Upload, t0);
        assert_eq!(wait, Duration::from_millis(3_000));
    }

    // -- pause handling ----------------------------------------------------

    #[test]
    fn unpause_resets_speed_records() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.start_now(t0);
        p.download_inc(1000);
        p.calc(at_secs(t0, 1), false); // speeder_c becomes 1
        assert_eq!(p.speeder_c, 1);
        p.recv_pause(false); // unpause → reset
        assert_eq!(p.speeder_c, 0);

        p.calc(at_secs(t0, 2), false);
        assert_eq!(p.speeder_c, 1);
        p.send_pause(false);
        assert_eq!(p.speeder_c, 0);
    }

    // -- meter lifecycle ---------------------------------------------------

    #[test]
    fn meter_header_emitted_once() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.start_now(t0);
        p.set_download_size(1000);
        p.download_inc(500);
        p.calc(at_secs(t0, 1), false);

        let first = p.render_meter();
        assert!(p.headers_out());
        assert!(first.starts_with(METER_HEADER));
        assert!(first.contains('\r'));

        // The second render omits the header.
        let second = p.render_meter();
        assert!(!second.contains("% Total"));
        assert!(second.starts_with('\r'));
    }

    #[test]
    fn force_redraw_and_final_newline_flags() {
        let t0 = Instant::now();
        let mut p = Progress::new(t0);
        p.start_now(t0);
        p.calc(at_secs(t0, 1), false);
        assert!(p.lastshow.is_some());
        p.force_redraw();
        assert!(p.lastshow.is_none());

        assert!(p.should_print_final_newline());
        p.set_callback_used(true);
        assert!(
            !p.should_print_final_newline(),
            "callback suppresses newline"
        );
        p.set_callback_used(false);
        p.set_hide(true);
        assert!(!p.should_print_final_newline(), "hidden suppresses newline");
    }

    // -- trspeed / helpers -------------------------------------------------

    #[test]
    fn trspeed_matches_curl_branches() {
        // us < 1 → size * 1e6.
        assert_eq!(trspeed(5, 0), 5_000_000);
        // Common case: 1000 bytes over 1s = 1000 B/s.
        assert_eq!(trspeed(1000, 1_000_000), 1000);
        // 1000 bytes over 0.5s = 2000 B/s.
        assert_eq!(trspeed(1000, 500_000), 2000);
        // Huge size path stays finite and non-panicking.
        assert_eq!(trspeed(i64::MAX, 2_000_000), i64::MAX / 2);
    }

    #[test]
    fn ptimediff_and_dur_helpers() {
        let t0 = Instant::now();
        assert_eq!(ptimediff_us(at_ms(t0, 1), t0), 1_000);
        // Backwards saturates to zero (monotonic clock should never go back).
        assert_eq!(ptimediff_us(t0, at_ms(t0, 1)), 0);
        assert_eq!(dur_ms(Duration::from_millis(1234)), 1234);
        assert_eq!(dur_us(Duration::from_micros(99)), 99);
    }

    #[test]
    fn saturating_i64_clamps() {
        assert_eq!(saturating_i64(0), 0);
        assert_eq!(saturating_i64(i128::from(i64::MAX) + 1), i64::MAX);
        assert_eq!(saturating_i64(i128::from(i64::MIN) - 1), i64::MIN);
    }

    // -- time2str / max6out parity (curl unit test 1636) -------------------

    #[test]
    fn time2str_exact_values_from_unit1636() {
        let cases: &[(i64, &str)] = &[
            (0, "       "),
            (1, "  00:01"),
            (3, "  00:03"),
            (63, "  01:03"),
            (4095, "1:08:15"),
            (8191, "2:16:31"),
            (32767, "9:06:07"),
            (65535, "18h 12m"),
            (131071, "36h 24m"),
            (524287, " 6d 01h"),
            (8388607, "97d 02h"),
            (16777215, "   194d"),
            (67108863, "   776d"),
            (134217727, "    51m"),
            (2147483647, "   828m"),
            (4294967295, "   136y"),
            (34359738367, "  1089y"),
            (2199023255551, " 69730y"),
            (4398046511103, ">99999y"),
        ];
        for &(secs, expected) in cases {
            assert_eq!(time2str(secs), expected, "time2str({secs})");
        }
    }

    #[test]
    fn max6out_exact_values_from_unit1636() {
        let cases: &[(i64, &str)] = &[
            (0, "     0"),
            (1, "     1"),
            (65535, " 65535"),
            (131071, "127.9k"),
            (262143, "255.9k"),
            (524287, "511.9k"),
            (1048575, " 0.99M"),
            (2097151, " 1.99M"),
            (1073741823, " 0.99G"),
            (131072, "128.0k"),
            (12645826, "12.05M"),
            (1073741824, " 1.00G"),
            (12938588979, "12.04G"),
            (1099445657078333, "999.9T"),
        ];
        for &(bytes, expected) in cases {
            assert_eq!(max6out(bytes), expected, "max6out({bytes})");
        }
    }

    #[test]
    fn time2str_always_seven_chars_doubling_sequence() {
        // Mirror unit1636: secs starts at 0 and follows secs = secs*2 + 1 for
        // 63 iterations; the output must always be exactly seven characters.
        let mut secs: i64 = 0;
        for _ in 0..63 {
            let s = time2str(secs);
            assert_eq!(s.chars().count(), 7, "time2str({secs}) = {s:?} not 7 chars");
            secs = secs.wrapping_mul(2).wrapping_add(1);
        }
    }

    #[test]
    fn max6out_always_six_chars_doubling_sequence() {
        // Mirror unit1636 for max6out: always exactly six characters.
        let mut v: i64 = 0;
        for _ in 0..63 {
            let s = max6out(v);
            assert_eq!(s.chars().count(), 6, "max6out({v}) = {s:?} not 6 chars");
            v = v.wrapping_mul(2).wrapping_add(1);
        }
    }
}
