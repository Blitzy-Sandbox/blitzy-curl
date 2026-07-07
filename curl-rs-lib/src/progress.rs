//! Transfer progress metering — a language rewrite of curl 8.x `lib/progress.c`.
//!
//! This module tracks the number of bytes transferred up and down, computes
//! instantaneous and averaged transfer speeds, records the canonical transfer
//! time points, and drives the application progress callback. It is a
//! byte-for-byte behavioral port of curl's progress subsystem: the speed
//! sliding-window math, the timer accumulation rules, and the low-speed abort
//! logic are reproduced exactly so that `--limit-rate`, `--speed-limit` /
//! `--speed-time`, the reported speeds, and the `curl_easy_getinfo` timing
//! values all match curl 8.x.
//!
//! # Scope boundaries (Minimal Change Mandate)
//!
//! This module *supplies the measurements*; it deliberately does **not** do two
//! things that live in sibling modules:
//!
//! * **Rate-limit waiting** — the pacing/sleeping that implements
//!   `--limit-rate` lives in `ratelimit.rs`. Here we only maintain the byte
//!   counters and speeds it consumes (via [`Progress::pgrs_download_inc`],
//!   [`Progress::downloaded`], [`Progress::download_speed`], …).
//! * **Progress-bar rendering** — the textual meter / progress bar is rendered
//!   by the CLI crate (`curl-rs/src/progress_display.rs`). This module exposes
//!   the raw numbers and the callback plumbing and returns *whether* it is time
//!   to render, but never writes to a terminal.
//!
//! Two further curl responsibilities that are not local to progress metering
//! are intentionally left to their owning modules: the `EXPIRE_SPEEDCHECK`
//! multi-handle timer scheduling (owned by `multi.rs`) and the per-connection
//! rate-limit draining (owned by `ratelimit.rs`).
//!
//! # Safety
//!
//! This module is written entirely in safe Rust, as mandated for
//! `curl-rs-lib`; it never uses raw pointers or the escape-hatch keyword. All
//! timing uses [`std::time::Instant`]; all speed and timer arithmetic is
//! performed on `i64` (curl's `curl_off_t`) using saturating operations so that
//! pathological inputs can never panic in debug builds while remaining
//! bit-identical to curl for realistic transfer magnitudes.
//!
//! # Time source and testability
//!
//! Public methods that need "now" read [`std::time::Instant::now`]. Every such
//! method has a sibling `*_at(now: Instant)` form that accepts an explicit
//! timestamp. This mirrors curl, where the internal helpers receive a
//! pre-sampled `pnow` (shared across a multi handle), and it makes the speed
//! and timer math fully deterministic for unit testing.

use std::fmt;
use std::time::Instant;

use crate::error::{CurlCode, Error, Result};

/// Number of samples retained in the speed sliding window.
///
/// Mirrors curl's `CURL_SPEED_RECORDS` (`urldata.h`): `5 + 1` — six slots that
/// together cover a five-second averaging window (`CURR_TIME`). The extra slot
/// lets the oldest and newest samples span a full five seconds.
const CURL_SPEED_RECORDS: usize = 5 + 1;

/// Return value a progress/xferinfo callback yields to request that libcurl
/// continue *and* still render its built-in meter.
///
/// Transcribed verbatim from `CURL_PROGRESSFUNC_CONTINUE` in
/// `include/curl/curl.h`. Any other non-zero return aborts the transfer
/// (mapped to [`CurlCode::AbortedByCallback`]); a zero return means the
/// callback handled reporting and the built-in meter must be suppressed.
pub const CURL_PROGRESSFUNC_CONTINUE: i32 = 0x0100_0001;

/// The application transfer-info callback.
///
/// This is the idiomatic-Rust form of curl's `curl_xferinfo_callback`
/// (`CURLOPT_XFERINFOFUNCTION`). The four arguments are, in order,
/// `dltotal`, `dlnow`, `ultotal`, `ulnow`, all expressed as `i64` (curl's
/// `curl_off_t`). The return value follows curl's convention: `0` to continue
/// with the meter suppressed, [`CURL_PROGRESSFUNC_CONTINUE`] to continue and
/// keep the built-in meter, or any other non-zero value to abort the transfer.
///
/// The deprecated `double`-typed `curl_progress_callback`
/// (`CURLOPT_PROGRESSFUNCTION`) is bridged at the FFI boundary
/// (`curl-rs-ffi`); at the library level a single typed callback is sufficient.
pub type XferInfoCallback = Box<dyn FnMut(i64, i64, i64, i64) -> i32 + Send>;

/// Canonical transfer time points, equivalent to curl's `timerid`
/// (`lib/progress.h`).
///
/// The discriminants are frozen to match curl's enum ordering so the values
/// remain stable diagnostic symbols and can be bridged 1:1 to the C `timerid`
/// at the FFI boundary. The `TIMER_LAST` sentinel is intentionally not
/// represented. These points feed `curl_easy_getinfo` timing
/// (`CURLINFO_NAMELOOKUP_TIME_T`, `CURLINFO_CONNECT_TIME_T`, …) and must keep
/// identical semantics.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Timer {
    /// `TIMER_NONE` — sentinel / mistake filter; recording it is a no-op.
    None = 0,
    /// `TIMER_STARTOP` — start of the whole operation (all redirects). Also
    /// (re)initializes the queue-time bookkeeping.
    StartOp = 1,
    /// `TIMER_STARTSINGLE` — start of a single transfer (each redirect leg).
    /// Resets the "start transfer recorded" latch. All cumulative point timers
    /// are measured relative to this instant.
    StartSingle = 2,
    /// `TIMER_POSTQUEUE` — recorded immediately after dequeue; accumulates the
    /// time spent queued across redirects.
    PostQueue = 3,
    /// `TIMER_NAMELOOKUP` — name resolution completed.
    NameLookup = 4,
    /// `TIMER_CONNECT` — TCP (or equivalent) connection established.
    Connect = 5,
    /// `TIMER_APPCONNECT` — application-layer (e.g. TLS) handshake completed.
    AppConnect = 6,
    /// `TIMER_PRETRANSFER` — all pre-transfer negotiation completed; the
    /// transfer is about to begin.
    PreTransfer = 7,
    /// `TIMER_STARTTRANSFER` — the first byte of the response was received.
    /// Recorded at most once per transfer leg (see [`Timer::StartSingle`]).
    StartTransfer = 8,
    /// `TIMER_POSTRANSFER` — the transfer body finished.
    PostTransfer = 9,
    /// `TIMER_STARTACCEPT` — FTP: started waiting for the server to connect
    /// back (active mode).
    StartAccept = 10,
    /// `TIMER_REDIRECT` — a redirect was followed; records cumulative redirect
    /// time relative to the operation start.
    Redirect = 11,
}

/// Per-direction progress state, mirroring curl's `struct pgrs_dir`
/// (`urldata.h`).
///
/// One instance tracks the download direction and another the upload
/// direction. curl's `struct pgrs_dir` additionally embeds a `Curl_rlimit`
/// used for `--limit-rate` pacing; that pacing state and logic live in
/// `ratelimit.rs`, so it is intentionally absent here.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct PgrsDir {
    /// Total expected bytes for this direction (`total_size`). Meaningful only
    /// when the corresponding `*_size_known` flag is set.
    total_size: i64,
    /// Bytes transferred so far in this direction (`cur_size`).
    cur_size: i64,
    /// Most recently computed average speed for this direction, in bytes per
    /// second (`speed`).
    speed: i64,
}

/// Transfer progress meter.
///
/// A faithful reimplementation of curl's `struct Progress` and the
/// `Curl_pgrs*` function family from `lib/progress.c`. A `Progress` value is
/// owned by an easy handle and is driven through the transfer lifecycle:
/// [`pgrs_start_now`](Progress::pgrs_start_now) at the beginning, repeated
/// [`pgrs_update`](Progress::pgrs_update) / [`pgrs_check`](Progress::pgrs_check)
/// calls during the transfer, and [`pgrs_done`](Progress::pgrs_done) at the
/// end. Timer points are stamped with [`pgrs_time`](Progress::pgrs_time).
///
/// The type is [`Send`] (so it can move with a transfer between Tokio worker
/// threads) but is intentionally not `Clone` because it may own a callback
/// closure.
#[derive(Default)]
pub struct Progress {
    /// Download-direction counters and speed.
    dl: PgrsDir,
    /// Upload-direction counters and speed.
    ul: PgrsDir,

    /// The currently fastest transfer speed in bytes/sec, computed over the
    /// sliding window (`current_speed`). This is the value reported as the
    /// "Current Speed" and consulted by the low-speed check.
    current_speed: i64,
    /// Bytes sent as TLS early data (`earlydata_sent`), reported informally.
    earlydata_sent: i64,

    /// Microseconds elapsed since [`start`](Progress::start_instant) as of the
    /// last [`progress_calc`](Progress::progress_calc) (`timespent`).
    timespent: i64,

    /// Accumulated queue time in microseconds (`t_postqueue`).
    t_postqueue: i64,
    /// Cumulative name-lookup time in microseconds (`t_nslookup`).
    t_nslookup: i64,
    /// Cumulative connect time in microseconds (`t_connect`).
    t_connect: i64,
    /// Cumulative app-connect (TLS) time in microseconds (`t_appconnect`).
    t_appconnect: i64,
    /// Cumulative pre-transfer time in microseconds (`t_pretransfer`).
    t_pretransfer: i64,
    /// Cumulative post-transfer time in microseconds (`t_posttransfer`).
    t_posttransfer: i64,
    /// Time to first byte in microseconds (`t_starttransfer`).
    t_starttransfer: i64,
    /// Cumulative redirect time in microseconds (`t_redirect`).
    t_redirect: i64,

    /// Operation start timestamp (`start`), set by
    /// [`pgrs_start_now`](Progress::pgrs_start_now).
    start: Option<Instant>,
    /// Start of the current single transfer leg (`t_startsingle`); the
    /// reference for all cumulative point timers.
    t_startsingle: Option<Instant>,
    /// Start of the whole operation (`t_startop`).
    t_startop: Option<Instant>,
    /// Start of the current queue interval (`t_startqueue`).
    t_startqueue: Option<Instant>,
    /// Time an FTP active-mode accept began (`t_acceptdata`).
    t_acceptdata: Option<Instant>,

    /// Cumulative transferred amounts sampled into the sliding window
    /// (`speed_amount`; historically `speeder[]`). Slot `i` holds the total
    /// (download + upload) byte count at `speed_time[i]`.
    speed_amount: [i64; CURL_SPEED_RECORDS],
    /// Timestamps paired with [`speed_amount`](Progress::speed_amount)
    /// (`speed_time`; historically `speeder_time[]`).
    speed_time: [Option<Instant>; CURL_SPEED_RECORDS],
    /// Number of speed samples taken (`speeder_c`). A `u8` that wraps exactly
    /// as curl's `uint8_t` does, driving the ring-buffer index math.
    speeder_c: u8,
    /// Whole seconds since [`start`](Progress::start_instant) at which the
    /// meter was last flagged for display (`lastshow`). `None` forces the next
    /// update to report "show" (used for the final forced update).
    lastshow: Option<i64>,

    /// Low-speed abort threshold in bytes/sec (`set.low_speed_limit`); `0`
    /// disables the check.
    low_speed_limit: i64,
    /// Low-speed abort window in whole seconds (`set.low_speed_time`); `0`
    /// disables the check.
    low_speed_time: u32,
    /// Instant since which the transfer has continuously been below
    /// [`low_speed_limit`](Progress::low_speed_limit) (curl's
    /// `state.keeps_speed`); `None` means "not currently below".
    keeps_speed: Option<Instant>,

    /// Whether the receive side is currently paused (informs the low-speed
    /// check, which ignores paused transfers).
    recv_paused: bool,
    /// Whether the send side is currently paused.
    send_paused: bool,
    /// Whether the current request has completed (`req.done`); influences the
    /// final sliding-window sample and the show-throttle.
    req_done: bool,

    /// `hide` — when set, neither the callback nor the meter run (curl's
    /// `CURLOPT_NOPROGRESS`). Defaults to `false` (visible), matching the
    /// zero-initialized C struct; the owning handle sets it during setup.
    hide: bool,
    /// `ul_size_known` — the total upload size is known.
    ul_size_known: bool,
    /// `dl_size_known` — the total download size is known.
    dl_size_known: bool,
    /// `headers_out` — the meter header row has already been emitted (consulted
    /// by the CLI renderer; tracked here for parity).
    headers_out: bool,
    /// `callback` — a progress/xferinfo callback is in use.
    callback: bool,
    /// `is_t_startransfer_set` — the start-transfer time point has been latched
    /// for the current transfer leg.
    is_t_startransfer_set: bool,

    /// The application transfer-info callback, if registered.
    xferinfo: Option<XferInfoCallback>,
}

impl fmt::Debug for Progress {
    /// Formats the meter without attempting to format the callback closure
    /// (which is not [`Debug`]); the callback is shown only as present/absent.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Progress")
            .field("dl", &self.dl)
            .field("ul", &self.ul)
            .field("current_speed", &self.current_speed)
            .field("earlydata_sent", &self.earlydata_sent)
            .field("timespent", &self.timespent)
            .field("t_nslookup", &self.t_nslookup)
            .field("t_connect", &self.t_connect)
            .field("t_appconnect", &self.t_appconnect)
            .field("t_pretransfer", &self.t_pretransfer)
            .field("t_starttransfer", &self.t_starttransfer)
            .field("t_posttransfer", &self.t_posttransfer)
            .field("t_redirect", &self.t_redirect)
            .field("t_postqueue", &self.t_postqueue)
            .field("speeder_c", &self.speeder_c)
            .field("low_speed_limit", &self.low_speed_limit)
            .field("low_speed_time", &self.low_speed_time)
            .field("hide", &self.hide)
            .field("dl_size_known", &self.dl_size_known)
            .field("ul_size_known", &self.ul_size_known)
            .field("callback", &self.callback)
            .field("is_t_startransfer_set", &self.is_t_startransfer_set)
            .field("req_done", &self.req_done)
            .field(
                "xferinfo",
                &self
                    .xferinfo
                    .as_ref()
                    .map_or("None", |_| "Some(<callback>)"),
            )
            .finish_non_exhaustive()
    }
}

impl Progress {
    /// Creates a fresh, zero-initialized progress meter.
    ///
    /// Equivalent to curl's zero-initialized `struct Progress`. No timestamps
    /// are recorded yet; call [`pgrs_start_now`](Progress::pgrs_start_now)
    /// before driving updates.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ---------------------------------------------------------------------
    // Size / counter mutators — mirror the `Curl_pgrsSet*` C API.
    // ---------------------------------------------------------------------

    /// Sets the known expected download size (`Curl_pgrsSetDownloadSize`).
    ///
    /// A negative `size` marks the download size as *unknown* (clearing the
    /// total to `0`), exactly as curl does; a non-negative `size` records the
    /// total and marks it known.
    pub fn pgrs_set_download_size(&mut self, size: i64) {
        if size >= 0 {
            self.dl.total_size = size;
            self.dl_size_known = true;
        } else {
            self.dl.total_size = 0;
            self.dl_size_known = false;
        }
    }

    /// Sets the known expected upload size (`Curl_pgrsSetUploadSize`).
    ///
    /// A negative `size` marks the upload size as *unknown*; a non-negative
    /// `size` records the total and marks it known.
    pub fn pgrs_set_upload_size(&mut self, size: i64) {
        if size >= 0 {
            self.ul.total_size = size;
            self.ul_size_known = true;
        } else {
            self.ul.total_size = 0;
            self.ul_size_known = false;
        }
    }

    /// Sets the absolute number of bytes downloaded so far.
    ///
    /// The download counterpart of `Curl_pgrsSetUploadCounter`. Prefer
    /// [`pgrs_download_inc`](Progress::pgrs_download_inc) on the hot path; this
    /// absolute setter is provided for symmetry and for callers that track the
    /// running total themselves.
    pub fn pgrs_set_download_counter(&mut self, size: i64) {
        self.dl.cur_size = size;
    }

    /// Sets the absolute number of bytes uploaded so far
    /// (`Curl_pgrsSetUploadCounter`).
    pub fn pgrs_set_upload_counter(&mut self, size: i64) {
        self.ul.cur_size = size;
    }

    /// Adds `delta` freshly received bytes to the download counter
    /// (`Curl_pgrs_download_inc`).
    ///
    /// curl additionally drains its `--limit-rate` bucket here; that pacing is
    /// owned by `ratelimit.rs`, which consumes these counters, so this method
    /// only advances the measurement.
    pub fn pgrs_download_inc(&mut self, delta: u64) {
        if delta != 0 {
            self.dl.cur_size = self.dl.cur_size.saturating_add(delta as i64);
        }
    }

    /// Adds `delta` freshly sent bytes to the upload counter
    /// (`Curl_pgrs_upload_inc`).
    pub fn pgrs_upload_inc(&mut self, delta: u64) {
        if delta != 0 {
            self.ul.cur_size = self.ul.cur_size.saturating_add(delta as i64);
        }
    }

    /// Records the number of bytes accepted as TLS early data
    /// (`Curl_pgrsEarlyData`).
    pub fn pgrs_early_data(&mut self, sent: i64) {
        self.earlydata_sent = sent;
    }

    // ---------------------------------------------------------------------
    // Read accessors — expose the measured numbers to dependents
    // (transfer/multi/getinfo, the rate limiter, and the CLI renderer).
    // ---------------------------------------------------------------------

    /// Total expected download size in bytes (meaningful when
    /// [`is_download_size_known`](Progress::is_download_size_known)).
    #[must_use]
    pub fn download_size(&self) -> i64 {
        self.dl.total_size
    }

    /// Total expected upload size in bytes (meaningful when
    /// [`is_upload_size_known`](Progress::is_upload_size_known)).
    #[must_use]
    pub fn upload_size(&self) -> i64 {
        self.ul.total_size
    }

    /// Bytes downloaded so far.
    #[must_use]
    pub fn downloaded(&self) -> i64 {
        self.dl.cur_size
    }

    /// Bytes uploaded so far.
    #[must_use]
    pub fn uploaded(&self) -> i64 {
        self.ul.cur_size
    }

    /// Most recent average download speed in bytes/sec.
    #[must_use]
    pub fn download_speed(&self) -> i64 {
        self.dl.speed
    }

    /// Most recent average upload speed in bytes/sec.
    #[must_use]
    pub fn upload_speed(&self) -> i64 {
        self.ul.speed
    }

    /// The current sliding-window speed in bytes/sec (the "Current Speed").
    #[must_use]
    pub fn current_speed(&self) -> i64 {
        self.current_speed
    }

    /// Bytes reported as TLS early data.
    #[must_use]
    pub fn early_data_sent(&self) -> i64 {
        self.earlydata_sent
    }

    /// Microseconds elapsed since the operation start as of the last update.
    #[must_use]
    pub fn timespent_us(&self) -> i64 {
        self.timespent
    }

    /// Whether the expected download size is known.
    #[must_use]
    pub fn is_download_size_known(&self) -> bool {
        self.dl_size_known
    }

    /// Whether the expected upload size is known.
    #[must_use]
    pub fn is_upload_size_known(&self) -> bool {
        self.ul_size_known
    }

    // ---------------------------------------------------------------------
    // Transfer lifecycle
    // ---------------------------------------------------------------------

    /// Returns the module's notion of "now".
    ///
    /// The single time source used throughout the meter (curl's
    /// `Curl_pgrs_now`). Callers that need to drive several progress methods
    /// against one shared instant (as the multi handle does) can sample here
    /// once and pass the value to the `*_at` methods.
    #[must_use]
    pub fn now() -> Instant {
        Instant::now()
    }

    /// The operation start timestamp, if [`pgrs_start_now`](Progress::pgrs_start_now)
    /// has run.
    #[must_use]
    pub fn start_instant(&self) -> Option<Instant> {
        self.start
    }

    /// Begins timing the operation as of *now* (`Curl_pgrsStartNow`).
    pub fn pgrs_start_now(&mut self) {
        self.pgrs_start_now_at(Instant::now());
    }

    /// Begins timing the operation as of the supplied instant.
    ///
    /// Resets the speed sampler, records the start time, clears the
    /// start-transfer latch, and zeroes the current byte counters while marking
    /// both transfer sizes unknown — matching `Curl_pgrsStartNow`.
    pub fn pgrs_start_now_at(&mut self, now: Instant) {
        self.speeder_c = 0;
        self.start = Some(now);
        self.is_t_startransfer_set = false;
        self.dl.cur_size = 0;
        self.ul.cur_size = 0;
        self.dl_size_known = false;
        self.ul_size_known = false;
    }

    /// Stamps the given time point with the current instant
    /// (`Curl_pgrsTime`).
    pub fn pgrs_time(&mut self, timer: Timer) {
        self.pgrs_time_was(timer, Instant::now());
    }

    /// Stamps the given time point with an explicit `timestamp`
    /// (`Curl_pgrsTimeWas`).
    ///
    /// This is the workhorse used both for live stamping and for retroactive
    /// recording (e.g. Happy Eyeballs records only the winning connection's
    /// times). The cumulative point timers ([`Timer::NameLookup`] through
    /// [`Timer::PostTransfer`]) accumulate microseconds measured from
    /// [`Timer::StartSingle`], with a one-microsecond floor so a point can
    /// never register as zero elapsed. [`Timer::StartTransfer`] is latched so
    /// repeated calls within a transfer leg do not move time-to-first-byte.
    pub fn pgrs_time_was(&mut self, timer: Timer, timestamp: Instant) {
        // Microseconds from the start of this single transfer, with curl's
        // one-microsecond floor. Computed up front; only the cumulative point
        // timers consume it.
        let us_since_single = self
            .t_startsingle
            .map_or(1, |ts| diff_us(timestamp, ts))
            .max(1);

        match timer {
            Timer::None => {}
            Timer::StartOp => {
                // Start of the whole operation; (re)initialize queue tracking.
                self.t_startop = Some(timestamp);
                self.t_startqueue = Some(timestamp);
                self.t_postqueue = 0;
            }
            Timer::StartSingle => {
                self.t_startsingle = Some(timestamp);
                self.is_t_startransfer_set = false;
            }
            Timer::PostQueue => {
                // Queue time is accumulative across redirects.
                if let Some(startqueue) = self.t_startqueue {
                    self.t_postqueue = self
                        .t_postqueue
                        .saturating_add(diff_us(timestamp, startqueue));
                }
            }
            Timer::StartAccept => {
                self.t_acceptdata = Some(timestamp);
            }
            Timer::NameLookup => {
                self.t_nslookup = self.t_nslookup.saturating_add(us_since_single);
            }
            Timer::Connect => {
                self.t_connect = self.t_connect.saturating_add(us_since_single);
            }
            Timer::AppConnect => {
                self.t_appconnect = self.t_appconnect.saturating_add(us_since_single);
            }
            Timer::PreTransfer => {
                self.t_pretransfer = self.t_pretransfer.saturating_add(us_since_single);
            }
            Timer::StartTransfer => {
                // Only record the first byte once per transfer leg; a redirect
                // clears the latch via TIMER_STARTSINGLE.
                if self.is_t_startransfer_set {
                    return;
                }
                self.is_t_startransfer_set = true;
                self.t_starttransfer = self.t_starttransfer.saturating_add(us_since_single);
            }
            Timer::PostTransfer => {
                self.t_posttransfer = self.t_posttransfer.saturating_add(us_since_single);
            }
            Timer::Redirect => {
                // Redirect time is cumulative from the operation start; a new
                // queue interval begins at the redirect.
                if let Some(start) = self.start {
                    self.t_redirect = diff_us(timestamp, start);
                }
                self.t_startqueue = Some(timestamp);
            }
        }
    }

    /// Resets sizes and counters for both directions (`Curl_pgrsReset`).
    ///
    /// Clears the byte counters, marks both sizes unknown, and discards the
    /// speed history and low-speed measurement.
    pub fn pgrs_reset(&mut self) {
        self.pgrs_set_upload_counter(0);
        self.dl.cur_size = 0;
        self.pgrs_set_upload_size(-1);
        self.pgrs_set_download_size(-1);
        self.speeder_c = 0;
        self.keeps_speed = None;
    }

    /// Resets only the known transfer sizes (`Curl_pgrsResetTransferSizes`),
    /// marking both directions' totals unknown.
    pub fn pgrs_reset_transfer_sizes(&mut self) {
        self.pgrs_set_download_size(-1);
        self.pgrs_set_upload_size(-1);
    }

    /// Informs the meter that the receive side paused or resumed
    /// (`Curl_pgrsRecvPause`).
    ///
    /// On resume (`enable == false`) the speed history and low-speed
    /// measurement are discarded so the pause interval does not distort the
    /// reported speed or trip the low-speed abort.
    pub fn pgrs_recv_pause(&mut self, enable: bool) {
        self.recv_paused = enable;
        if !enable {
            self.speeder_c = 0;
            self.keeps_speed = None;
        }
    }

    /// Informs the meter that the send side paused or resumed
    /// (`Curl_pgrsSendPause`).
    pub fn pgrs_send_pause(&mut self, enable: bool) {
        self.send_paused = enable;
        if !enable {
            self.speeder_c = 0;
            self.keeps_speed = None;
        }
    }

    // ---------------------------------------------------------------------
    // Configuration flags and low-speed thresholds
    // ---------------------------------------------------------------------

    /// Sets the `hide` flag (curl's `CURLOPT_NOPROGRESS`). When hidden, neither
    /// the callback nor the built-in meter run.
    pub fn set_hide(&mut self, hide: bool) {
        self.hide = hide;
    }

    /// Whether progress reporting is hidden.
    #[must_use]
    pub fn is_hidden(&self) -> bool {
        self.hide
    }

    /// Sets the meter-header-emitted flag consulted by the CLI renderer.
    pub fn set_headers_out(&mut self, out: bool) {
        self.headers_out = out;
    }

    /// Whether the meter header row has already been emitted.
    #[must_use]
    pub fn headers_out(&self) -> bool {
        self.headers_out
    }

    /// Sets the low-speed abort threshold in bytes/sec
    /// (`CURLOPT_LOW_SPEED_LIMIT`); `0` disables the check.
    pub fn set_low_speed_limit(&mut self, limit: i64) {
        self.low_speed_limit = limit;
    }

    /// Sets the low-speed abort window in whole seconds
    /// (`CURLOPT_LOW_SPEED_TIME`); `0` disables the check.
    pub fn set_low_speed_time(&mut self, seconds: u32) {
        self.low_speed_time = seconds;
    }

    /// Marks whether the current request has completed (curl's `req.done`),
    /// which influences the final sliding-window sample and show-throttle.
    pub fn set_req_done(&mut self, done: bool) {
        self.req_done = done;
    }

    /// Whether the current request is marked done.
    #[must_use]
    pub fn is_req_done(&self) -> bool {
        self.req_done
    }

    /// Whether a progress/xferinfo callback is registered.
    #[must_use]
    pub fn has_callback(&self) -> bool {
        self.callback
    }

    /// Registers the application transfer-info callback and marks the meter as
    /// callback-driven (curl's `callback` flag).
    pub fn set_xferinfo(&mut self, callback: XferInfoCallback) {
        self.xferinfo = Some(callback);
        self.callback = true;
    }

    /// Removes any registered callback.
    pub fn clear_xferinfo(&mut self) {
        self.xferinfo = None;
        self.callback = false;
    }

    // ---------------------------------------------------------------------
    // Timing accessors — feed `curl_easy_getinfo` (all in microseconds, the
    // unit of the `CURLINFO_*_TIME_T` family).
    // ---------------------------------------------------------------------

    /// `CURLINFO_NAMELOOKUP_TIME_T` — cumulative name-lookup time (µs).
    #[must_use]
    pub fn namelookup_time_us(&self) -> i64 {
        self.t_nslookup
    }

    /// `CURLINFO_CONNECT_TIME_T` — cumulative connect time (µs).
    #[must_use]
    pub fn connect_time_us(&self) -> i64 {
        self.t_connect
    }

    /// `CURLINFO_APPCONNECT_TIME_T` — cumulative app-connect (TLS) time (µs).
    #[must_use]
    pub fn appconnect_time_us(&self) -> i64 {
        self.t_appconnect
    }

    /// `CURLINFO_PRETRANSFER_TIME_T` — cumulative pre-transfer time (µs).
    #[must_use]
    pub fn pretransfer_time_us(&self) -> i64 {
        self.t_pretransfer
    }

    /// `CURLINFO_STARTTRANSFER_TIME_T` — time to first byte (µs).
    #[must_use]
    pub fn starttransfer_time_us(&self) -> i64 {
        self.t_starttransfer
    }

    /// Cumulative post-transfer time (µs).
    #[must_use]
    pub fn posttransfer_time_us(&self) -> i64 {
        self.t_posttransfer
    }

    /// `CURLINFO_REDIRECT_TIME_T` — cumulative redirect time (µs).
    #[must_use]
    pub fn redirect_time_us(&self) -> i64 {
        self.t_redirect
    }

    /// `CURLINFO_QUEUE_TIME_T` — accumulated queue time (µs).
    #[must_use]
    pub fn queue_time_us(&self) -> i64 {
        self.t_postqueue
    }
}

impl Progress {
    // ---------------------------------------------------------------------
    // Speed calculation and update loop
    // ---------------------------------------------------------------------

    /// Recomputes speeds and advances the sliding window, returning whether it
    /// is time to render the meter.
    ///
    /// A direct port of curl's `progress_calc`. It refreshes the per-direction
    /// average speeds from the elapsed time, then maintains the six-slot ring
    /// buffer of `(cumulative bytes, timestamp)` samples: a new sample is taken
    /// at most once per second (or once at the very end of a zero-speed
    /// transfer), and the "current speed" is the amount transferred between the
    /// oldest and newest retained samples divided by their time span. The
    /// return value additionally honors curl's once-per-second display
    /// throttle.
    fn progress_calc(&mut self, now: Instant) -> bool {
        // Time spent so far, in microseconds, and whole seconds — both measured
        // from the operation start.
        self.timespent = self
            .start
            .map_or(0, |s| duration_us(now.saturating_duration_since(s)));
        let now_sec = self
            .start
            .map_or(0, |s| now.saturating_duration_since(s).as_secs() as i64);

        self.dl.speed = trspeed(self.dl.cur_size, self.timespent);
        self.ul.speed = trspeed(self.ul.cur_size, self.timespent);

        if self.speeder_c == 0 {
            // No previous record exists: seed the window and use the overall
            // average as the initial current speed.
            self.speed_amount[0] = self.dl.cur_size.saturating_add(self.ul.cur_size);
            self.speed_time[0] = Some(now);
            self.speeder_c = self.speeder_c.wrapping_add(1);
            self.current_speed = self.ul.speed.saturating_add(self.dl.speed);
            self.lastshow = Some(now_sec);
            return true;
        }

        // At least one record exists. Locate the next write slot and the most
        // recent slot.
        let records = CURL_SPEED_RECORDS as u8;
        let i_next = (self.speeder_c % records) as usize;
        let mut i_latest = if i_next > 0 {
            i_next - 1
        } else {
            CURL_SPEED_RECORDS - 1
        };

        // Take a new sample only when at least a second has elapsed since the
        // latest one; too-frequent samples would ruin the history.
        let ms_since_latest = self.speed_time[i_latest]
            .map_or(i64::MAX, |t| duration_ms(now.saturating_duration_since(t)));
        if ms_since_latest >= 1000 {
            self.speeder_c = self.speeder_c.wrapping_add(1);
            i_latest = i_next;
            self.speed_amount[i_latest] = self.dl.cur_size.saturating_add(self.ul.cur_size);
            self.speed_time[i_latest] = Some(now);
        } else if self.req_done {
            // On completion, if no current speed was established yet, refresh
            // the last record. Otherwise stay at the measured speed: the final
            // (rate-limited) chunk no longer spans a full second and would
            // otherwise inflate the reported speed.
            if self.current_speed == 0 {
                self.speed_amount[i_latest] = self.dl.cur_size.saturating_add(self.ul.cur_size);
                self.speed_time[i_latest] = Some(now);
            }
        } else {
            // Transfer ongoing; wait for more time to pass.
            return false;
        }

        let i_oldest = if (self.speeder_c as usize) < CURL_SPEED_RECORDS {
            0
        } else {
            (i_latest + 1) % CURL_SPEED_RECORDS
        };

        // Bytes transferred between the oldest and newest retained samples and
        // the time that took.
        let amount = self.speed_amount[i_latest] - self.speed_amount[i_oldest];
        let duration_us = match (self.speed_time[i_latest], self.speed_time[i_oldest]) {
            (Some(latest), Some(oldest)) => {
                duration_us(latest.saturating_duration_since(oldest)).max(1)
            }
            _ => 1,
        };

        if amount > (i64::MAX / 1_000_000) {
            // `amount * 1_000_000` would overflow 64 bits; fall back to double
            // precision, exactly as curl does.
            self.current_speed = ((amount as f64 * 1_000_000.0) / duration_us as f64) as i64;
        } else {
            self.current_speed = amount.saturating_mul(1_000_000) / duration_us;
        }

        // Honor curl's once-per-second display throttle unless the request just
        // completed (in which case the final state is always shown).
        if self.lastshow == Some(now_sec) && !self.req_done {
            return false;
        }
        self.lastshow = Some(now_sec);
        true
    }

    /// Invokes the callback (if any) and decides whether the meter should be
    /// rendered — the port of curl's `pgrsupdate`.
    ///
    /// Returns `Ok(true)` when the caller should render the built-in meter,
    /// `Ok(false)` when it should not (hidden, or the callback suppressed it),
    /// and `Err(`[`CurlCode::AbortedByCallback`]`)` when the callback requested
    /// an abort.
    fn pgrsupdate(&mut self, showprogress: bool) -> Result<bool> {
        if self.hide {
            return Ok(false);
        }

        // Snapshot the sizes so the callback borrow does not overlap the reads.
        let (dltotal, dlnow, ultotal, ulnow) = (
            self.dl.total_size,
            self.dl.cur_size,
            self.ul.total_size,
            self.ul.cur_size,
        );

        if let Some(callback) = self.xferinfo.as_mut() {
            let result = callback(dltotal, dlnow, ultotal, ulnow);
            if result != CURL_PROGRESSFUNC_CONTINUE {
                if result != 0 {
                    return Err(Error::with_context(
                        CurlCode::AbortedByCallback,
                        "Callback aborted",
                    ));
                }
                // The callback handled reporting; suppress the built-in meter.
                return Ok(false);
            }
            // CURL_PROGRESSFUNC_CONTINUE: fall through and render if due.
        }

        Ok(showprogress)
    }

    /// Performs a progress update as of *now*, invoking the callback and
    /// reporting whether to render the meter (`Curl_pgrsUpdate`).
    ///
    /// # Errors
    ///
    /// Returns [`CurlCode::AbortedByCallback`] if the application callback
    /// requested that the transfer abort.
    pub fn pgrs_update(&mut self) -> Result<bool> {
        self.pgrs_update_at(Instant::now())
    }

    /// Performs a progress update as of the supplied instant.
    ///
    /// # Errors
    ///
    /// Returns [`CurlCode::AbortedByCallback`] if the application callback
    /// requested that the transfer abort.
    pub fn pgrs_update_at(&mut self, now: Instant) -> Result<bool> {
        let showprogress = self.progress_calc(now);
        self.pgrsupdate(showprogress)
    }

    /// Advances the speed/window state without invoking the callback or meter
    /// (`Curl_pgrsUpdate_nometer`), using *now*.
    pub fn pgrs_update_nometer(&mut self) {
        self.pgrs_update_nometer_at(Instant::now());
    }

    /// Advances the speed/window state without callback or meter, using an
    /// explicit instant.
    pub fn pgrs_update_nometer_at(&mut self, now: Instant) {
        let _ = self.progress_calc(now);
    }

    /// Updates progress and then, unless the request is done, runs the
    /// low-speed check (`Curl_pgrsCheck`), using *now*.
    ///
    /// # Errors
    ///
    /// Returns [`CurlCode::AbortedByCallback`] if the callback aborted, or
    /// [`CurlCode::OperationTimedout`] if the low-speed threshold was breached.
    pub fn pgrs_check(&mut self) -> Result<bool> {
        self.pgrs_check_at(Instant::now())
    }

    /// [`pgrs_check`](Progress::pgrs_check) against an explicit instant.
    ///
    /// # Errors
    ///
    /// Returns [`CurlCode::AbortedByCallback`] if the callback aborted, or
    /// [`CurlCode::OperationTimedout`] if the low-speed threshold was breached.
    pub fn pgrs_check_at(&mut self, now: Instant) -> Result<bool> {
        let showprogress = self.pgrs_update_at(now)?;
        if !self.req_done {
            self.pgrs_speedcheck_at(now)?;
        }
        Ok(showprogress)
    }

    /// Performs the final, forced progress update (`Curl_pgrsDone`), using
    /// *now*.
    ///
    /// Clears the display throttle so the terminal state is always reported,
    /// then updates. The trailing newline curl prints on the terminal is a
    /// rendering concern handled by the CLI crate, not here.
    ///
    /// # Errors
    ///
    /// Returns [`CurlCode::AbortedByCallback`] if the callback aborted.
    pub fn pgrs_done(&mut self) -> Result<bool> {
        self.pgrs_done_at(Instant::now())
    }

    /// [`pgrs_done`](Progress::pgrs_done) against an explicit instant.
    ///
    /// # Errors
    ///
    /// Returns [`CurlCode::AbortedByCallback`] if the callback aborted.
    pub fn pgrs_done_at(&mut self, now: Instant) -> Result<bool> {
        self.lastshow = None; // force the final update to report "show"
        self.pgrs_update_at(now)
    }

    /// Enforces the low-speed abort threshold (`pgrs_speedcheck`), using *now*.
    ///
    /// # Errors
    ///
    /// Returns [`CurlCode::OperationTimedout`] when the transfer has stayed
    /// below [`set_low_speed_limit`](Progress::set_low_speed_limit) for at
    /// least [`set_low_speed_time`](Progress::set_low_speed_time) seconds.
    pub fn pgrs_speedcheck(&mut self) -> Result<()> {
        self.pgrs_speedcheck_at(Instant::now())
    }

    /// [`pgrs_speedcheck`](Progress::pgrs_speedcheck) against an explicit
    /// instant.
    ///
    /// # Errors
    ///
    /// Returns [`CurlCode::OperationTimedout`] when the low-speed threshold has
    /// been breached for the configured duration.
    pub fn pgrs_speedcheck_at(&mut self, now: Instant) -> Result<()> {
        // A disabled check, or a paused transfer, is never a candidate.
        if self.low_speed_time == 0
            || self.low_speed_limit == 0
            || self.recv_paused
            || self.send_paused
        {
            return Ok(());
        }

        if self.current_speed >= 0 {
            if self.current_speed < self.low_speed_limit {
                match self.keeps_speed {
                    None => {
                        // First moment under the limit.
                        self.keeps_speed = Some(now);
                    }
                    Some(since) => {
                        let howlong = duration_ms(now.saturating_duration_since(since));
                        if howlong >= i64::from(self.low_speed_time) * 1000 {
                            return Err(Error::with_context(
                                CurlCode::OperationTimedout,
                                format!(
                                    "Operation too slow. Less than {} bytes/sec \
                                     transferred the last {} seconds",
                                    self.low_speed_limit, self.low_speed_time
                                ),
                            ));
                        }
                    }
                }
            } else {
                // Fast enough right now; clear the under-limit timer.
                self.keeps_speed = None;
            }
        }

        // curl also arms an `EXPIRE_SPEEDCHECK` multi-handle timer here so the
        // speed is re-checked in a second; that scheduling belongs to `multi.rs`.
        Ok(())
    }
}

// =========================================================================
// Free helper functions — the exact scalar math from `lib/progress.c`.
// =========================================================================

/// Returns the average speed in bytes/second (curl's `trspeed`).
///
/// `size` is a byte count and `us` a microsecond duration. The branch
/// structure and overflow guards mirror curl exactly: sub-microsecond
/// durations report `size * 1_000_000`; otherwise the product is scaled while
/// avoiding 64-bit overflow, capping at [`i64::MAX`] when it cannot be
/// represented.
fn trspeed(size: i64, us: i64) -> i64 {
    if us < 1 {
        size.saturating_mul(1_000_000)
    } else if size < i64::MAX / 1_000_000 {
        // `size * 1_000_000` cannot overflow given the guard above.
        (size * 1_000_000) / us
    } else if us >= 1_000_000 {
        size / (us / 1_000_000)
    } else {
        i64::MAX
    }
}

/// Converts a [`std::time::Duration`] to microseconds, saturating at
/// [`i64::MAX`].
///
/// curl stores durations in a signed 64-bit `timediff_t`; all durations in this
/// module are non-negative (they come from `Instant::saturating_duration_since`),
/// so a saturating conversion is exact for every realistic transfer.
fn duration_us(d: std::time::Duration) -> i64 {
    i64::try_from(d.as_micros()).unwrap_or(i64::MAX)
}

/// Converts a [`std::time::Duration`] to milliseconds, saturating at
/// [`i64::MAX`].
fn duration_ms(d: std::time::Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

/// Signed microsecond difference `newer - older` (curl's `curlx_ptimediff_us`).
///
/// Non-negative when `newer >= older`; negative otherwise. Matches curl's
/// signed convention for the (rare) out-of-order case.
fn diff_us(newer: Instant, older: Instant) -> i64 {
    if newer >= older {
        duration_us(newer.saturating_duration_since(older))
    } else {
        -duration_us(older.saturating_duration_since(newer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Drives a steady 1000 bytes/second download and asserts the sliding
    /// window reports exactly 1000 B/s at every step — including after the ring
    /// buffer has wrapped past its six slots.
    #[test]
    fn steady_speed_is_reported_exactly() {
        let base = Instant::now();
        let mut p = Progress::new();
        p.pgrs_start_now_at(base);

        // First update seeds the window; it always reports "show".
        p.pgrs_set_download_counter(0);
        assert!(p.pgrs_update_at(base).unwrap());
        assert_eq!(p.current_speed(), 0);

        // Feed 1000 bytes per second for eight seconds (past the 6-slot ring).
        for sec in 1..=8u64 {
            p.pgrs_set_download_counter(1000 * sec as i64);
            let _ = p.pgrs_update_at(base + Duration::from_secs(sec)).unwrap();
            assert_eq!(
                p.current_speed(),
                1000,
                "steady speed wrong at second {sec}"
            );
        }
    }

    /// After five seconds at 1000 B/s, a one-second burst is averaged over the
    /// five-second window: 10 000 bytes across the retained span => 2000 B/s,
    /// not the 6000 B/s instantaneous rate.
    #[test]
    fn burst_is_averaged_over_five_second_window() {
        let base = Instant::now();
        let mut p = Progress::new();
        p.pgrs_start_now_at(base);
        p.pgrs_set_download_counter(0);
        let _ = p.pgrs_update_at(base).unwrap();

        for sec in 1..=5u64 {
            p.pgrs_set_download_counter(1000 * sec as i64);
            let _ = p.pgrs_update_at(base + Duration::from_secs(sec)).unwrap();
        }
        assert_eq!(p.current_speed(), 1000);

        // Burst: jump from 5000 to 11 000 bytes in the sixth second.
        p.pgrs_set_download_counter(11_000);
        let _ = p.pgrs_update_at(base + Duration::from_secs(6)).unwrap();
        // Window spans seconds 1..6 => (11000 - 1000) bytes over 5 s = 2000 B/s.
        assert_eq!(p.current_speed(), 2000);
    }

    /// An ongoing transfer that is polled more often than once per second does
    /// not create spurious samples and reports "do not show yet".
    #[test]
    fn sub_second_polls_do_not_resample() {
        let base = Instant::now();
        let mut p = Progress::new();
        p.pgrs_start_now_at(base);
        p.pgrs_set_download_counter(0);
        let _ = p.pgrs_update_at(base).unwrap();
        assert_eq!(p.speeder_c, 1);

        // 100 ms later: below the 1 s resample threshold and not done.
        p.pgrs_set_download_counter(100);
        let show = p.pgrs_update_at(base + Duration::from_millis(100)).unwrap();
        assert!(
            !show,
            "an ongoing sub-second poll must not request a redraw"
        );
        assert_eq!(p.speeder_c, 1, "no new sample should be recorded");
    }

    /// Timer points accumulate microseconds from the single-transfer start,
    /// remain monotonic for increasing timestamps, and time-to-first-byte is
    /// latched against repeated recording.
    #[test]
    fn timer_points_record_monotonically_and_latch() {
        let base = Instant::now();
        let mut p = Progress::new();
        p.pgrs_start_now_at(base);
        p.pgrs_time_was(Timer::StartSingle, base);

        p.pgrs_time_was(Timer::NameLookup, base + Duration::from_millis(10));
        p.pgrs_time_was(Timer::Connect, base + Duration::from_millis(30));
        p.pgrs_time_was(Timer::AppConnect, base + Duration::from_millis(50));
        p.pgrs_time_was(Timer::PreTransfer, base + Duration::from_millis(60));
        p.pgrs_time_was(Timer::StartTransfer, base + Duration::from_millis(100));

        assert_eq!(p.namelookup_time_us(), 10_000);
        assert_eq!(p.connect_time_us(), 30_000);
        assert_eq!(p.appconnect_time_us(), 50_000);
        assert_eq!(p.pretransfer_time_us(), 60_000);
        assert_eq!(p.starttransfer_time_us(), 100_000);

        // Monotonic non-decreasing across the connection phases.
        assert!(p.namelookup_time_us() <= p.connect_time_us());
        assert!(p.connect_time_us() <= p.appconnect_time_us());
        assert!(p.appconnect_time_us() <= p.pretransfer_time_us());
        assert!(p.pretransfer_time_us() <= p.starttransfer_time_us());

        // A second STARTTRANSFER must not move time-to-first-byte (latched).
        p.pgrs_time_was(Timer::StartTransfer, base + Duration::from_millis(500));
        assert_eq!(p.starttransfer_time_us(), 100_000);
    }

    /// The one-microsecond floor applies when a timer is stamped at the exact
    /// single-transfer start instant.
    #[test]
    fn timer_has_one_microsecond_floor() {
        let base = Instant::now();
        let mut p = Progress::new();
        p.pgrs_start_now_at(base);
        p.pgrs_time_was(Timer::StartSingle, base);
        p.pgrs_time_was(Timer::NameLookup, base);
        assert_eq!(p.namelookup_time_us(), 1);
    }

    /// Queue time accumulates and redirect time is measured from the operation
    /// start.
    #[test]
    fn queue_and_redirect_timers() {
        let base = Instant::now();
        let mut p = Progress::new();
        p.pgrs_start_now_at(base);

        p.pgrs_time_was(Timer::StartOp, base);
        p.pgrs_time_was(Timer::PostQueue, base + Duration::from_millis(20));
        assert_eq!(p.queue_time_us(), 20_000);
        // A second dequeue accumulates onto the first.
        p.pgrs_time_was(Timer::StartOp, base + Duration::from_millis(100));
        p.pgrs_time_was(Timer::PostQueue, base + Duration::from_millis(130));
        assert_eq!(p.queue_time_us(), 30_000);

        p.pgrs_time_was(Timer::Redirect, base + Duration::from_millis(200));
        assert_eq!(p.redirect_time_us(), 200_000);
    }

    /// A callback returning a non-zero, non-CONTINUE value aborts the transfer
    /// and maps to `CURLE_ABORTED_BY_CALLBACK` with curl's message text.
    #[test]
    fn callback_abort_maps_to_aborted_by_callback() {
        let base = Instant::now();
        let mut p = Progress::new();
        p.pgrs_start_now_at(base);
        p.set_xferinfo(Box::new(|_, _, _, _| 1));
        assert!(p.has_callback());

        let err = p.pgrs_update_at(base).unwrap_err();
        assert_eq!(err.code(), CurlCode::AbortedByCallback);
        assert_eq!(err.to_string(), "Callback aborted");
    }

    /// A callback returning `CURL_PROGRESSFUNC_CONTINUE` lets the built-in meter
    /// run, while returning `0` suppresses it — neither aborts.
    #[test]
    fn callback_continue_and_zero_control_the_meter() {
        let base = Instant::now();

        let mut cont = Progress::new();
        cont.pgrs_start_now_at(base);
        cont.set_xferinfo(Box::new(|_, _, _, _| CURL_PROGRESSFUNC_CONTINUE));
        assert!(cont.pgrs_update_at(base).unwrap());

        let mut zero = Progress::new();
        zero.pgrs_start_now_at(base);
        zero.set_xferinfo(Box::new(|_, _, _, _| 0));
        assert!(!zero.pgrs_update_at(base).unwrap());
    }

    /// The callback receives curl's argument order: dltotal, dlnow, ultotal,
    /// ulnow.
    #[test]
    fn callback_receives_sizes_in_curl_order() {
        use std::sync::{Arc, Mutex};
        let base = Instant::now();
        let mut p = Progress::new();
        p.pgrs_start_now_at(base);
        p.pgrs_set_download_size(1000);
        p.pgrs_set_download_counter(400);
        p.pgrs_set_upload_size(2000);
        p.pgrs_set_upload_counter(500);

        let seen = Arc::new(Mutex::new((0i64, 0i64, 0i64, 0i64)));
        let sink = Arc::clone(&seen);
        p.set_xferinfo(Box::new(move |dt, dn, ut, un| {
            *sink.lock().unwrap() = (dt, dn, ut, un);
            CURL_PROGRESSFUNC_CONTINUE
        }));
        let _ = p.pgrs_update_at(base).unwrap();
        assert_eq!(*seen.lock().unwrap(), (1000, 400, 2000, 500));
    }

    /// When hidden, neither the callback nor the meter runs (an aborting
    /// callback is never consulted).
    #[test]
    fn hidden_suppresses_callback_and_meter() {
        let base = Instant::now();
        let mut p = Progress::new();
        p.set_hide(true);
        p.pgrs_start_now_at(base);
        // This callback would abort if it were ever invoked.
        p.set_xferinfo(Box::new(|_, _, _, _| 1));
        let show = p.pgrs_update_at(base).unwrap();
        assert!(!show);
    }

    /// A sustained sub-threshold speed for longer than the configured window
    /// aborts with `CURLE_OPERATION_TIMEDOUT`.
    #[test]
    fn low_speed_check_times_out() {
        let base = Instant::now();
        let mut p = Progress::new();
        p.pgrs_start_now_at(base);
        p.set_low_speed_limit(1000);
        p.set_low_speed_time(1);

        // Establish a current speed of 0 (below the 1000 B/s limit).
        p.pgrs_set_download_counter(0);
        let _ = p.pgrs_update_at(base).unwrap();

        // First check: records the moment we dropped below the limit.
        p.pgrs_speedcheck_at(base + Duration::from_secs(1)).unwrap();
        assert!(p.keeps_speed.is_some());

        // Still slow one second later; keep the window sample fresh.
        p.pgrs_set_download_counter(0);
        let _ = p.pgrs_update_at(base + Duration::from_secs(2)).unwrap();

        // Two seconds under the limit exceeds the one-second window => timeout.
        let err = p
            .pgrs_speedcheck_at(base + Duration::from_secs(3))
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::OperationTimedout);
        assert!(err.to_string().starts_with("Operation too slow."));
    }

    /// The low-speed check is a no-op when disabled or when the transfer is
    /// paused, and it clears its timer once the speed recovers.
    #[test]
    fn low_speed_check_disabled_paused_and_recovery() {
        let base = Instant::now();

        // Disabled (time == 0): never trips even at zero speed.
        let mut disabled = Progress::new();
        disabled.pgrs_start_now_at(base);
        disabled.set_low_speed_limit(1000);
        disabled.pgrs_set_download_counter(0);
        let _ = disabled.pgrs_update_at(base).unwrap();
        disabled
            .pgrs_speedcheck_at(base + Duration::from_secs(100))
            .unwrap();

        // Paused transfers are exempt.
        let mut paused = Progress::new();
        paused.pgrs_start_now_at(base);
        paused.set_low_speed_limit(1000);
        paused.set_low_speed_time(1);
        paused.pgrs_set_download_counter(0);
        let _ = paused.pgrs_update_at(base).unwrap();
        paused.pgrs_recv_pause(true);
        paused
            .pgrs_speedcheck_at(base + Duration::from_secs(100))
            .unwrap();

        // Recovery: once fast again, the under-limit timer is cleared.
        let mut recover = Progress::new();
        recover.pgrs_start_now_at(base);
        recover.set_low_speed_limit(1000);
        recover.set_low_speed_time(10);
        recover.pgrs_set_download_counter(0);
        let _ = recover.pgrs_update_at(base).unwrap();
        recover
            .pgrs_speedcheck_at(base + Duration::from_secs(1))
            .unwrap();
        assert!(recover.keeps_speed.is_some());

        recover.pgrs_set_download_counter(100_000);
        let _ = recover
            .pgrs_update_at(base + Duration::from_secs(2))
            .unwrap();
        assert!(recover.current_speed() >= 1000);
        recover
            .pgrs_speedcheck_at(base + Duration::from_secs(2))
            .unwrap();
        assert!(recover.keeps_speed.is_none());
    }

    /// Size/counter setters and their "known" flags behave like the C API,
    /// including the negative-size "unknown" convention.
    #[test]
    fn size_and_counter_setters() {
        let mut p = Progress::new();

        p.pgrs_set_download_size(1000);
        assert_eq!(p.download_size(), 1000);
        assert!(p.is_download_size_known());
        p.pgrs_set_download_size(-1);
        assert_eq!(p.download_size(), 0);
        assert!(!p.is_download_size_known());

        p.pgrs_set_upload_size(2000);
        assert_eq!(p.upload_size(), 2000);
        assert!(p.is_upload_size_known());

        p.pgrs_set_download_counter(123);
        assert_eq!(p.downloaded(), 123);
        p.pgrs_download_inc(77);
        assert_eq!(p.downloaded(), 200);
        p.pgrs_download_inc(0); // no-op
        assert_eq!(p.downloaded(), 200);

        p.pgrs_set_upload_counter(50);
        p.pgrs_upload_inc(50);
        assert_eq!(p.uploaded(), 100);

        p.pgrs_early_data(42);
        assert_eq!(p.early_data_sent(), 42);
    }

    /// `pgrs_reset` clears counters, sizes, speed history, and the low-speed
    /// timer; `pgrs_reset_transfer_sizes` clears only the totals.
    #[test]
    fn reset_clears_state() {
        let base = Instant::now();
        let mut p = Progress::new();
        p.pgrs_start_now_at(base);
        p.pgrs_set_download_counter(500);
        p.pgrs_set_upload_counter(300);
        p.pgrs_set_download_size(1000);
        p.pgrs_set_upload_size(2000);
        let _ = p.pgrs_update_at(base + Duration::from_secs(1)).unwrap();

        p.pgrs_reset();
        assert_eq!(p.downloaded(), 0);
        assert_eq!(p.uploaded(), 0);
        assert!(!p.is_download_size_known());
        assert!(!p.is_upload_size_known());
        assert_eq!(p.speeder_c, 0);
        assert!(p.keeps_speed.is_none());

        p.pgrs_set_download_size(1234);
        p.pgrs_set_upload_size(5678);
        p.pgrs_reset_transfer_sizes();
        assert!(!p.is_download_size_known());
        assert!(!p.is_upload_size_known());
        assert_eq!(p.download_size(), 0);
        assert_eq!(p.upload_size(), 0);
    }

    /// The forced final update reports "show" even within the same wall-second
    /// as the previous update, because `pgrs_done` clears the display throttle.
    #[test]
    fn done_forces_a_final_show() {
        let base = Instant::now();
        let mut p = Progress::new();
        p.pgrs_start_now_at(base);
        p.pgrs_set_download_counter(0);
        let _ = p.pgrs_update_at(base).unwrap();

        p.set_req_done(true);
        p.pgrs_set_download_counter(1000);
        assert!(p.pgrs_done_at(base + Duration::from_secs(1)).unwrap());
    }

    /// `pgrs_update_nometer` advances the speed state without a callback: an
    /// aborting callback is never consulted, and speeds still update.
    #[test]
    fn update_nometer_skips_callback() {
        let base = Instant::now();
        let mut p = Progress::new();
        p.pgrs_start_now_at(base);
        p.set_xferinfo(Box::new(|_, _, _, _| 1)); // would abort if consulted
        p.pgrs_set_download_counter(0);
        p.pgrs_update_nometer_at(base);
        p.pgrs_set_download_counter(1000);
        p.pgrs_update_nometer_at(base + Duration::from_secs(1));
        assert_eq!(p.current_speed(), 1000);
    }

    /// Pause/resume discards the speed history so paused intervals do not skew
    /// the reported speed.
    #[test]
    fn resume_resets_speed_history() {
        let base = Instant::now();
        let mut p = Progress::new();
        p.pgrs_start_now_at(base);
        p.pgrs_set_download_counter(0);
        let _ = p.pgrs_update_at(base).unwrap();
        assert_eq!(p.speeder_c, 1);

        p.pgrs_recv_pause(true);
        assert!(p.recv_paused);
        p.pgrs_recv_pause(false);
        assert!(!p.recv_paused);
        assert_eq!(p.speeder_c, 0, "resume must clear the speed history");

        p.pgrs_send_pause(true);
        p.pgrs_send_pause(false);
        assert!(!p.send_paused);
    }

    /// Direct checks of the scalar helpers against curl's `trspeed` branches.
    #[test]
    fn trspeed_matches_curl_branches() {
        assert_eq!(trspeed(1000, 1_000_000), 1000);
        assert_eq!(trspeed(2000, 2_000_000), 1000);
        // us < 1: reports size * 1_000_000.
        assert_eq!(trspeed(500, 0), 500_000_000);
        // Large size path: scale down by whole seconds.
        assert_eq!(trspeed(i64::MAX, 2_000_000), i64::MAX / 2);
        // Large size with sub-second duration caps at i64::MAX.
        assert_eq!(trspeed(i64::MAX, 500_000), i64::MAX);
    }

    /// The signed microsecond difference helper matches curl's convention.
    #[test]
    fn diff_us_is_signed() {
        let base = Instant::now();
        assert_eq!(diff_us(base + Duration::from_micros(100), base), 100);
        assert_eq!(diff_us(base, base + Duration::from_micros(100)), -100);
        assert_eq!(diff_us(base, base), 0);
    }

    /// Debug formatting succeeds and does not attempt to print the callback.
    #[test]
    fn debug_format_is_safe_with_callback() {
        let mut p = Progress::new();
        p.set_xferinfo(Box::new(|_, _, _, _| 0));
        let text = format!("{p:?}");
        assert!(text.contains("Progress"));
        assert!(text.contains("<callback>"));
    }
}
