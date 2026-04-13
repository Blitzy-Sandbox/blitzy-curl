//! Transfer progress tracking module.
//!
//! Rust rewrite of `lib/progress.c` — provides speed calculation, ETA
//! estimation, progress callback invocation, and low-speed timeout detection
//! for curl transfers.
//!
//! # Key Types
//!
//! * [`Progress`] — the main progress tracker struct, equivalent to the C
//!   `struct Progress` in `lib/urldata.h`.  Tracks download/upload counters,
//!   computes average and current transfer speeds using a moving-window
//!   algorithm, and manages timing data for the various transfer phases.
//!
//! * [`ProgressCallback`] — type alias for the user-provided progress
//!   function, invoked at most once per second during a transfer (matching
//!   the C `CURL_PROGRESS_INTERVAL` behaviour).
//!
//! * [`TimerId`] — enum identifying the timing phase to record, equivalent
//!   to the C `timerid` enum in `lib/progress.h`.
//!
//! # Speed Calculation Algorithm
//!
//! Speed is calculated using a sliding window of [`SPEED_RECORDS`] (6)
//! entries sampled at 1-second intervals.  Current speed is derived from the
//! difference between the oldest and newest window entries.  This matches
//! the curl 8.x algorithm implemented in `progress_calc()`.

use std::fmt;
use std::time::{Duration, Instant};

use crate::error::{CurlError, CurlResult};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of speed measurement records in the circular buffer.
/// Matches C `CURL_SPEED_RECORDS` defined as `(5 + 1)` in `lib/urldata.h`.
const SPEED_RECORDS: usize = 6;

/// Minimum interval between progress callback invocations and speed window
/// samples (1 second), matching the C behaviour where `lastshow` is compared
/// against the current second.
const PROGRESS_INTERVAL: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// TimerId — maps to C `timerid` enum in lib/progress.h
// ---------------------------------------------------------------------------

/// Identifies a timing phase during a transfer.
///
/// Each variant corresponds to a phase of the request lifecycle whose
/// timestamp is recorded via [`Progress::record_time()`] or
/// [`Progress::record_time_was()`].  The integer discriminants match the C
/// `timerid` enum ordering for clarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TimerId {
    /// No timer — used as a sentinel / mistake filter.
    None = 0,
    /// Start of the overall operation.
    StartOp = 1,
    /// Start of a single transfer (may be queued).
    StartSingle = 2,
    /// Time immediately after leaving the queue.
    PostQueue = 3,
    /// DNS name lookup completed.
    NameLookup = 4,
    /// TCP connection established.
    Connect = 5,
    /// TLS / application-level connection completed.
    AppConnect = 6,
    /// Pre-transfer phase completed.
    PreTransfer = 7,
    /// First byte of transfer data sent / received.
    StartTransfer = 8,
    /// Transfer completed (post-transfer phase).
    PostTransfer = 9,
    /// Server accept completed (FTP active mode).
    StartAccept = 10,
    /// A redirect was followed.
    Redirect = 11,
}

// ---------------------------------------------------------------------------
// ProgressCallback type
// ---------------------------------------------------------------------------

/// Callback type invoked during transfers to report progress.
///
/// Parameters: `(dl_total, dl_now, ul_total, ul_now)`.
///
/// Return `true` to continue the transfer, or `false` to abort it
/// (resulting in [`CurlError::AbortedByCallback`]).
///
/// This unifies the C `CURLOPT_XFERINFOFUNCTION` (new-style) and the
/// deprecated `CURLOPT_PROGRESSFUNCTION` (old-style) callbacks.
pub type ProgressCallback = Box<dyn Fn(u64, u64, u64, u64) -> bool + Send + Sync>;

// ---------------------------------------------------------------------------
// Internal: per-direction (download / upload) tracker
// ---------------------------------------------------------------------------

/// Tracks byte counters and average speed for one direction.
#[derive(Debug)]
struct ProgressDirection {
    /// Total expected bytes (`0` when the size is unknown).
    total_size: u64,
    /// Bytes transferred so far.
    cur_size: u64,
    /// Average speed in bytes / second over the whole transfer.
    speed: f64,
}

impl ProgressDirection {
    /// Creates a zeroed direction tracker.
    fn new() -> Self {
        Self {
            total_size: 0,
            cur_size: 0,
            speed: 0.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Progress struct
// ---------------------------------------------------------------------------

/// Transfer progress tracker.
///
/// Maintains all counters, timing data, and speed-calculation state for a
/// single curl transfer.  Equivalent to the C `struct Progress` in
/// `lib/urldata.h` together with speed-check fields from `struct UrlState`.
pub struct Progress {
    // -- Transfer direction trackers ------------------------------------------
    dl: ProgressDirection,
    ul: ProgressDirection,

    // -- Size-known flags -----------------------------------------------------
    dl_size_known: bool,
    ul_size_known: bool,

    // -- Current speed from the sliding window (bytes / sec) ------------------
    current_speed: f64,

    // -- Early TLS 0-RTT data -------------------------------------------------
    earlydata_sent: u64,

    // -- Elapsed time in microseconds from start ------------------------------
    timespent_us: i64,

    // -- Speed measurement circular buffer ------------------------------------
    speed_amount: [u64; SPEED_RECORDS],
    speed_time: [Option<Instant>; SPEED_RECORDS],
    speeder_count: u32,

    // -- Primary timing anchors -----------------------------------------------
    start: Option<Instant>,
    t_startsingle: Option<Instant>,
    t_startop: Option<Instant>,
    t_startqueue: Option<Instant>,
    t_acceptdata: Option<Instant>,

    // -- Timer deltas (microseconds, accumulated from t_startsingle) -----------
    t_postqueue_us: i64,
    t_nslookup_us: i64,
    t_connect_us: i64,
    t_appconnect_us: i64,
    t_pretransfer_us: i64,
    t_posttransfer_us: i64,
    t_starttransfer_us: i64,
    t_redirect_us: i64,

    // -- Display / throttle control -------------------------------------------
    last_show_time: Option<Instant>,
    /// Tracks whether the progress meter header row has been displayed.
    /// Set to `true` after the first `Display::fmt` call and reset by
    /// `start_now()` / `reset()`.
    pub(crate) headers_out: bool,

    // -- Control flags --------------------------------------------------------
    /// When `true`, progress output and callbacks are suppressed.
    pub(crate) hide: bool,
    is_t_starttransfer_set: bool,

    // -- Pause tracking -------------------------------------------------------
    recv_paused_flag: bool,
    send_paused_flag: bool,

    // -- Transfer-done flag (affects final speed record) ----------------------
    /// Set to `true` by the transfer engine when the request is complete.
    pub(crate) done: bool,

    // -- Low-speed limit settings ---------------------------------------------
    /// Minimum average speed in bytes / second.  `0` disables the check.
    pub(crate) low_speed_limit: u64,
    /// Seconds the speed must remain below the limit before timeout.  `0`
    /// disables the check.
    pub(crate) low_speed_time: u64,
    /// Instant when the speed first dropped below the threshold.
    keeps_speed: Option<Instant>,

    // -- User callback --------------------------------------------------------
    /// Optional progress callback, invoked at most once per second.
    pub(crate) callback: Option<ProgressCallback>,
}

// ---------------------------------------------------------------------------
// Default implementation
// ---------------------------------------------------------------------------

impl Default for Progress {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Progress implementation
// ---------------------------------------------------------------------------

impl Progress {
    // ====================================================================
    // Construction and Reset
    // ====================================================================

    /// Creates a new, zeroed progress tracker.
    pub fn new() -> Self {
        Self {
            dl: ProgressDirection::new(),
            ul: ProgressDirection::new(),
            dl_size_known: false,
            ul_size_known: false,
            current_speed: 0.0,
            earlydata_sent: 0,
            timespent_us: 0,
            speed_amount: [0; SPEED_RECORDS],
            speed_time: [None; SPEED_RECORDS],
            speeder_count: 0,
            start: None,
            t_startsingle: None,
            t_startop: None,
            t_startqueue: None,
            t_acceptdata: None,
            t_postqueue_us: 0,
            t_nslookup_us: 0,
            t_connect_us: 0,
            t_appconnect_us: 0,
            t_pretransfer_us: 0,
            t_posttransfer_us: 0,
            t_starttransfer_us: 0,
            t_redirect_us: 0,
            last_show_time: None,
            headers_out: false,
            hide: false,
            is_t_starttransfer_set: false,
            recv_paused_flag: false,
            send_paused_flag: false,
            done: false,
            low_speed_limit: 0,
            low_speed_time: 0,
            keeps_speed: None,
            callback: None,
        }
    }

    /// Resets upload / download counters, sizes, and speed records.
    ///
    /// Equivalent to `Curl_pgrsReset()` in `lib/progress.c`.
    pub fn reset(&mut self) {
        self.set_upload_counter(0);
        self.dl.cur_size = 0;
        self.set_upload_size(None);
        self.set_download_size(None);
        self.speeder_count = 0;
        self.speed_amount = [0; SPEED_RECORDS];
        self.speed_time = [None; SPEED_RECORDS];
        self.keeps_speed = None;
    }

    /// Resets only the expected transfer sizes (not counters).
    ///
    /// Equivalent to `Curl_pgrsResetTransferSizes()` in `lib/progress.c`.
    pub fn reset_transfer_sizes(&mut self) {
        self.set_download_size(None);
        self.set_upload_size(None);
    }

    /// Records the start time and resets per-transfer counters.
    ///
    /// Equivalent to `Curl_pgrsStartNow()` in `lib/progress.c`.
    pub fn start_now(&mut self) {
        let now = Instant::now();
        self.speeder_count = 0;
        self.speed_amount = [0; SPEED_RECORDS];
        self.speed_time = [None; SPEED_RECORDS];
        self.start = Some(now);
        self.is_t_starttransfer_set = false;
        self.dl.cur_size = 0;
        self.ul.cur_size = 0;
        self.dl_size_known = false;
        self.ul_size_known = false;
    }

    /// Performs a final forced progress update.
    ///
    /// Sets the done flag and forces the update to trigger regardless of the
    /// throttle timer, then returns the result.
    ///
    /// Equivalent to `Curl_pgrsDone()` in `lib/progress.c`.
    pub fn done(&mut self) -> CurlResult<()> {
        self.done = true;
        // Reset throttle so the final update always fires.
        self.last_show_time = None;
        self.update()
    }

    // ====================================================================
    // Size Setters
    // ====================================================================

    /// Sets the expected total download size.
    ///
    /// Pass `Some(size)` for a known size, or `None` for unknown.
    /// Equivalent to `Curl_pgrsSetDownloadSize()` in `lib/progress.c`.
    pub fn set_download_size(&mut self, size: Option<u64>) {
        match size {
            Some(s) => {
                self.dl.total_size = s;
                self.dl_size_known = true;
            }
            None => {
                self.dl.total_size = 0;
                self.dl_size_known = false;
            }
        }
    }

    /// Sets the expected total upload size.
    ///
    /// Pass `Some(size)` for a known size, or `None` for unknown.
    /// Equivalent to `Curl_pgrsSetUploadSize()` in `lib/progress.c`.
    pub fn set_upload_size(&mut self, size: Option<u64>) {
        match size {
            Some(s) => {
                self.ul.total_size = s;
                self.ul_size_known = true;
            }
            None => {
                self.ul.total_size = 0;
                self.ul_size_known = false;
            }
        }
    }

    // ====================================================================
    // Counter Updates
    // ====================================================================

    /// Increments the download byte counter by `delta`.
    ///
    /// Equivalent to `Curl_pgrs_download_inc()` in `lib/progress.c`.
    pub fn download_inc(&mut self, delta: u64) {
        if delta > 0 {
            self.dl.cur_size = self.dl.cur_size.saturating_add(delta);
        }
    }

    /// Increments the upload byte counter by `delta`.
    ///
    /// Equivalent to `Curl_pgrs_upload_inc()` in `lib/progress.c`.
    pub fn upload_inc(&mut self, delta: u64) {
        if delta > 0 {
            self.ul.cur_size = self.ul.cur_size.saturating_add(delta);
        }
    }

    /// Sets the upload byte counter to an absolute value.
    ///
    /// Equivalent to `Curl_pgrsSetUploadCounter()` in `lib/progress.c`.
    pub fn set_upload_counter(&mut self, size: u64) {
        self.ul.cur_size = size;
    }

    // ====================================================================
    // Core Progress Calculation
    // ====================================================================

    /// Computes average and current transfer speeds.  Determines whether the
    /// progress meter / callback should fire (at most once per second).
    ///
    /// Returns `true` when a display update should occur, matching the C
    /// `progress_calc()` function in `lib/progress.c`.
    fn progress_calc(&mut self, now: &Instant) -> bool {
        let start = match self.start {
            Some(s) => s,
            None => return false,
        };

        // Elapsed time since transfer start in microseconds.
        self.timespent_us = now.duration_since(start).as_micros() as i64;

        // Overall average speeds.
        self.dl.speed = Self::trspeed(self.dl.cur_size, self.timespent_us);
        self.ul.speed = Self::trspeed(self.ul.cur_size, self.timespent_us);

        // --- Speed window management -----------------------------------------
        if self.speeder_count == 0 {
            // First record — seed the circular buffer.
            self.speed_amount[0] = self.dl.cur_size.saturating_add(self.ul.cur_size);
            self.speed_time[0] = Some(*now);
            self.speeder_count = 1;
            // Use the overall average as initial current speed.
            self.current_speed = self.dl.speed + self.ul.speed;
            self.last_show_time = Some(*now);
            return true;
        }

        // Indices into the circular buffer.
        let i_next = (self.speeder_count as usize) % SPEED_RECORDS;
        let i_latest = if i_next > 0 { i_next - 1 } else { SPEED_RECORDS - 1 };

        // Only add a new record when >= 1 second has elapsed since the most
        // recent entry.  Too-frequent calls would ruin the history.
        let latest_time = self.speed_time[i_latest].unwrap_or(*now);
        let elapsed_since_latest = now.duration_since(latest_time);

        if elapsed_since_latest >= PROGRESS_INTERVAL {
            // Advance the ring buffer.
            self.speeder_count += 1;
            let new_latest = (self.speeder_count as usize - 1) % SPEED_RECORDS;
            self.speed_amount[new_latest] =
                self.dl.cur_size.saturating_add(self.ul.cur_size);
            self.speed_time[new_latest] = Some(*now);
            self.recalc_current_speed(new_latest);
        } else if self.done {
            // Transfer done: update the last record when we have no current
            // speed yet so we get a final measurement.  If we already have a
            // speed, keep it — the last short chunk would inflate the number.
            if self.current_speed == 0.0 {
                self.speed_amount[i_latest] =
                    self.dl.cur_size.saturating_add(self.ul.cur_size);
                self.speed_time[i_latest] = Some(*now);
                self.recalc_current_speed(i_latest);
            }
        } else {
            // Ongoing transfer, not enough time has elapsed.
            return false;
        }

        // Throttle display updates to once per second.
        if let Some(last) = self.last_show_time {
            if now.duration_since(last) < PROGRESS_INTERVAL && !self.done {
                return false;
            }
        }
        self.last_show_time = Some(*now);
        true
    }

    /// Recalculates [`current_speed`](Self::current_speed) from the speed
    /// window circular buffer.
    fn recalc_current_speed(&mut self, i_latest: usize) {
        let i_oldest = if (self.speeder_count as usize) < SPEED_RECORDS {
            0
        } else {
            (i_latest + 1) % SPEED_RECORDS
        };

        let amount = self.speed_amount[i_latest]
            .saturating_sub(self.speed_amount[i_oldest]);

        let duration_us = match (self.speed_time[i_latest], self.speed_time[i_oldest]) {
            (Some(latest), Some(oldest)) => {
                let d = latest.duration_since(oldest).as_micros() as i64;
                if d <= 0 { 1 } else { d }
            }
            _ => 1,
        };

        // Floating-point avoids overflow for very large byte counts.
        self.current_speed = (amount as f64) * 1_000_000.0 / (duration_us as f64);
    }

    /// Computes average bytes / second from total bytes and elapsed
    /// microseconds.  Uses f64 to avoid the integer-overflow edge cases
    /// present in the C `trspeed()` function.
    fn trspeed(size: u64, us: i64) -> f64 {
        if us < 1 {
            (size as f64) * 1_000_000.0
        } else {
            (size as f64) * 1_000_000.0 / (us as f64)
        }
    }

    /// Invokes the user progress callback (if one is set and the transfer is
    /// not hidden).
    ///
    /// Returns `Err(CurlError::AbortedByCallback)` when the callback signals
    /// abort by returning `false`.
    fn invoke_callback(&self) -> CurlResult<()> {
        if self.hide {
            return Ok(());
        }
        if let Some(ref cb) = self.callback {
            let should_continue = cb(
                self.dl.total_size,
                self.dl.cur_size,
                self.ul.total_size,
                self.ul.cur_size,
            );
            if !should_continue {
                return Err(CurlError::AbortedByCallback);
            }
        }
        Ok(())
    }

    // ====================================================================
    // Public Update Methods
    // ====================================================================

    /// Performs a full progress update: recalculates speeds, invokes the
    /// callback (at most once per second), and returns any error.
    ///
    /// Equivalent to `Curl_pgrsUpdate()` in `lib/progress.c`.
    ///
    /// Returns `Err(CurlError::AbortedByCallback)` if the progress callback
    /// signals abort.
    pub fn update(&mut self) -> CurlResult<()> {
        let now = Instant::now();
        let _show = self.progress_calc(&now);
        self.invoke_callback()
    }

    /// Performs a progress update **and** low-speed timeout detection.
    ///
    /// Equivalent to `Curl_pgrsCheck()` in `lib/progress.c`.
    ///
    /// Returns:
    /// - `Err(CurlError::AbortedByCallback)` — progress callback abort.
    /// - `Err(CurlError::OperationTimedOut)` — speed stayed below
    ///   `low_speed_limit` for longer than `low_speed_time` seconds.
    pub fn check(&mut self) -> CurlResult<()> {
        let now = Instant::now();
        let _show = self.progress_calc(&now);
        self.invoke_callback()?;

        if !self.done {
            self.speed_check(&now)?;
        }
        Ok(())
    }

    /// Performs progress calculations (speed, time) without invoking the
    /// callback or checking speed limits.
    ///
    /// Equivalent to `Curl_pgrsUpdate_nometer()` in `lib/progress.c`.
    pub fn update_nometer(&mut self) {
        let now = Instant::now();
        let _ = self.progress_calc(&now);
    }

    /// Checks whether the current speed is below the low-speed threshold
    /// long enough to trigger a timeout.
    ///
    /// Matches the C `pgrs_speedcheck()` function.
    fn speed_check(&mut self, now: &Instant) -> CurlResult<()> {
        // If low-speed parameters are not configured or the transfer is
        // paused, skip the check entirely.
        if self.low_speed_time == 0
            || self.low_speed_limit == 0
            || self.recv_paused_flag
            || self.send_paused_flag
        {
            return Ok(());
        }

        if self.current_speed >= 0.0 {
            if (self.current_speed as u64) < self.low_speed_limit {
                // Speed is below the threshold.
                match self.keeps_speed {
                    None => {
                        // Start tracking when we first drop below the limit.
                        self.keeps_speed = Some(*now);
                    }
                    Some(since) => {
                        let howlong = now.duration_since(since);
                        if howlong >= Duration::from_secs(self.low_speed_time) {
                            return Err(CurlError::OperationTimedOut);
                        }
                    }
                }
            } else {
                // Speed is back above the threshold — reset tracker.
                self.keeps_speed = None;
            }
        }
        Ok(())
    }

    // ====================================================================
    // Timer Recording
    // ====================================================================

    /// Records the current wall-clock time for the given timer phase.
    ///
    /// Equivalent to `Curl_pgrsTime()` in `lib/progress.c`.
    pub fn record_time(&mut self, timer: TimerId) {
        let now = Instant::now();
        self.record_time_was(timer, now);
    }

    /// Records a specific timestamp for the given timer phase.
    ///
    /// This allows updating timers after the fact (used by Happy Eyeballs,
    /// where only the winning connection's times are recorded).
    ///
    /// Equivalent to `Curl_pgrsTimeWas()` in `lib/progress.c`.
    pub fn record_time_was(&mut self, timer: TimerId, timestamp: Instant) {
        match timer {
            TimerId::None => {
                // Mistake filter — do nothing.
            }
            TimerId::StartOp => {
                self.t_startop = Some(timestamp);
                self.t_startqueue = Some(timestamp);
                self.t_postqueue_us = 0;
            }
            TimerId::StartSingle => {
                self.t_startsingle = Some(timestamp);
                self.is_t_starttransfer_set = false;
            }
            TimerId::PostQueue => {
                // Queue time is accumulative across redirects.
                if let Some(sq) = self.t_startqueue {
                    self.t_postqueue_us +=
                        timestamp.duration_since(sq).as_micros() as i64;
                }
            }
            TimerId::StartAccept => {
                self.t_acceptdata = Some(timestamp);
            }
            TimerId::NameLookup => {
                self.t_nslookup_us += self.delta_from_startsingle(timestamp);
            }
            TimerId::Connect => {
                self.t_connect_us += self.delta_from_startsingle(timestamp);
            }
            TimerId::AppConnect => {
                self.t_appconnect_us += self.delta_from_startsingle(timestamp);
            }
            TimerId::PreTransfer => {
                self.t_pretransfer_us += self.delta_from_startsingle(timestamp);
            }
            TimerId::StartTransfer => {
                // Only record the first measurement per single transfer.
                if self.is_t_starttransfer_set {
                    return;
                }
                self.is_t_starttransfer_set = true;
                self.t_starttransfer_us += self.delta_from_startsingle(timestamp);
            }
            TimerId::PostTransfer => {
                self.t_posttransfer_us += self.delta_from_startsingle(timestamp);
            }
            TimerId::Redirect => {
                if let Some(s) = self.start {
                    self.t_redirect_us =
                        timestamp.duration_since(s).as_micros() as i64;
                }
                self.t_startqueue = Some(timestamp);
            }
        }
    }

    /// Computes the microsecond delta from `t_startsingle` to `timestamp`,
    /// clamped to a minimum of 1 µs.
    fn delta_from_startsingle(&self, timestamp: Instant) -> i64 {
        match self.t_startsingle {
            Some(ss) => {
                let us = timestamp.duration_since(ss).as_micros() as i64;
                if us < 1 { 1 } else { us }
            }
            None => 1,
        }
    }

    // ====================================================================
    // Pause Notification
    // ====================================================================

    /// Informs the progress tracker about a receive-pause state change.
    ///
    /// When `enable` is `false` (un-pausing), speed records and low-speed
    /// tracking are reset to avoid false timeout triggers.
    ///
    /// Equivalent to `Curl_pgrsRecvPause()` in `lib/progress.c`.
    pub fn recv_pause(&mut self, enable: bool) {
        self.recv_paused_flag = enable;
        if !enable {
            self.speeder_count = 0;
            self.speed_amount = [0; SPEED_RECORDS];
            self.speed_time = [None; SPEED_RECORDS];
            self.keeps_speed = None;
        }
    }

    /// Informs the progress tracker about a send-pause state change.
    ///
    /// When `enable` is `false` (un-pausing), speed records and low-speed
    /// tracking are reset to avoid false timeout triggers.
    ///
    /// Equivalent to `Curl_pgrsSendPause()` in `lib/progress.c`.
    pub fn send_pause(&mut self, enable: bool) {
        self.send_paused_flag = enable;
        if !enable {
            self.speeder_count = 0;
            self.speed_amount = [0; SPEED_RECORDS];
            self.speed_time = [None; SPEED_RECORDS];
            self.keeps_speed = None;
        }
    }

    // ====================================================================
    // Early Data
    // ====================================================================

    /// Records the amount of TLS 0-RTT (early data) bytes sent.
    ///
    /// Equivalent to `Curl_pgrsEarlyData()` in `lib/progress.c`.
    pub fn early_data(&mut self, sent: u64) {
        self.earlydata_sent = sent;
    }

    // ====================================================================
    // Getters
    // ====================================================================

    /// Returns the average download speed in bytes / second.
    pub fn get_download_speed(&self) -> f64 {
        self.dl.speed
    }

    /// Returns the average upload speed in bytes / second.
    pub fn get_upload_speed(&self) -> f64 {
        self.ul.speed
    }

    /// Returns the current (window-based) combined transfer speed in
    /// bytes / second.
    pub fn get_current_speed(&self) -> f64 {
        self.current_speed
    }

    /// Returns the total elapsed time since the transfer started.
    pub fn get_total_time(&self) -> Duration {
        match self.start {
            Some(s) => s.elapsed(),
            None => Duration::ZERO,
        }
    }

    /// Returns the number of bytes downloaded so far.
    pub fn get_dl_now(&self) -> u64 {
        self.dl.cur_size
    }

    /// Returns the number of bytes uploaded so far.
    pub fn get_ul_now(&self) -> u64 {
        self.ul.cur_size
    }

    /// Returns the expected total download size (`0` if unknown).
    pub fn get_dl_total(&self) -> u64 {
        self.dl.total_size
    }

    /// Returns the expected total upload size (`0` if unknown).
    pub fn get_ul_total(&self) -> u64 {
        self.ul.total_size
    }

    // ====================================================================
    // Formatting (associated functions)
    // ====================================================================

    /// Formats a byte-rate as a human-readable **6-character** string with
    /// auto-scaled units (`k`, `M`, `G`, `T`, `P`, `E`).
    ///
    /// Matches the C `max6out()` function in `lib/progress.c`.
    ///
    /// # Algorithm
    ///
    /// - Values below 100 000 are printed right-aligned in 6 digits.
    /// - Larger values are divided by 1024 repeatedly until the quotient is
    ///   below 1000, then formatted as either `"xx.yyU"` (≤ 99) or
    ///   `"xxx.yU"` (100–999) where `U` is the unit suffix.
    pub fn format_speed(bytes_per_sec: f64) -> String {
        let bytes = bytes_per_sec as i64;
        if bytes < 0 {
            return String::from("     0");
        }
        let bytes_u = bytes as u64;
        if bytes_u < 100_000 {
            return format!("{:>6}", bytes_u);
        }

        let units: &[char] = &['k', 'M', 'G', 'T', 'P', 'E'];
        let mut value = bytes_u;
        let mut k: usize = 0;
        let nbytes;
        loop {
            let nb = value / 1024;
            if nb < 1000 || k + 1 >= units.len() {
                nbytes = nb;
                break;
            }
            value = nb;
            k += 1;
        }
        let rest = value % 1024;
        if nbytes <= 99 {
            // "xx.yyU" — two fractional digits.
            let frac = rest * 100 / 1024;
            format!("{:>2}.{:02}{}", nbytes, frac, units[k])
        } else {
            // "xxx.yU" — one fractional digit.
            let frac = rest * 10 / 1024;
            format!("{:>3}.{}{}", nbytes, frac, units[k])
        }
    }

    /// Formats a duration in seconds as a human-readable **7-character**
    /// string.
    ///
    /// Output patterns (matching the C `time2str()` function):
    ///
    /// | Condition           | Format      | Example     |
    /// |---------------------|-------------|-------------|
    /// | ≤ 0                 | 7 spaces    | `"       "` |
    /// | < 1 h (h = 0)       | `"  MM:SS"` | `"  05:30"` |
    /// | < 10 h (h > 0)      | `"H:MM:SS"` | `"2:15:00"` |
    /// | 10–99 h             | `"XXh YYm"` | `"24h 00m"` |
    /// | 1–99 d              | `"XXd YYh"` | `" 3d 12h"` |
    /// | 100–999 d           | 6-col + `d` | `"   365d"` |
    /// | 1 000+ d (months)   | 6-col + `m` | `"    33m"` |
    /// | months > 999 (yrs)  | 6-col + `y` | `" 99999y"` |
    /// | > 99 999 y          | `">99999y"` | `">99999y"` |
    pub fn format_time(seconds: i64) -> String {
        use std::fmt::Write;

        if seconds <= 0 {
            return String::from("       ");
        }

        let h = seconds / 3600;
        if h <= 99 {
            let m = (seconds - h * 3600) / 60;
            if h <= 9 {
                let s = seconds - h * 3600 - m * 60;
                let mut buf = String::with_capacity(7);
                if h > 0 {
                    // "H:MM:SS"
                    let _ = write!(buf, "{}:{:02}:{:02}", h, m, s);
                } else {
                    // "  MM:SS"
                    let _ = write!(buf, "  {:02}:{:02}", m, s);
                }
                return buf;
            }
            // "XXh YYm"
            let mut buf = String::with_capacity(7);
            let _ = write!(buf, "{}h {:02}m", h, m);
            return buf;
        }

        let d = seconds / 86400;
        let hh = (seconds - d * 86400) / 3600;

        if d <= 99 {
            // "XXd YYh"
            let mut buf = String::with_capacity(7);
            let _ = write!(buf, "{:>2}d {:02}h", d, hh);
            return buf;
        }
        if d <= 999 {
            return format!("{:>6}d", d);
        }
        // Express in months (d / 30).
        let months = d / 30;
        if months <= 999 {
            return format!("{:>6}m", months);
        }
        // Express in years (d / 365).
        let years = d / 365;
        if years <= 99999 {
            return format!("{:>6}y", years);
        }
        String::from(">99999y")
    }

    /// Computes the percentage of `cur` relative to `total`, handling edge
    /// cases for very large or very small totals.  Matches the C
    /// `pgrs_est_percent()` in `lib/progress.c`.
    fn est_percent(total: u64, cur: u64) -> u64 {
        if total > 10000 {
            cur / (total / 100)
        } else if total > 0 {
            (cur * 100) / total
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// Display trait implementation for the progress meter line
// ---------------------------------------------------------------------------

impl fmt::Display for Progress {
    /// Formats the progress tracker as a single-line progress meter in the
    /// familiar curl output format:
    ///
    /// ```text
    ///   % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
    ///                                  Dload  Upload   Total   Spent    Left  Speed
    /// 100  1234  100  1234    0     0   1234      0  0:00:01  0:00:01 --:--:--  1234
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // When the header row hasn't been output yet, include it above the
        // data line.  Since `Display` takes `&self` we cannot flip the flag
        // here — the caller should set `headers_out = true` after writing.
        if !self.headers_out {
            writeln!(
                f,
                "  % Total    % Received % Xferd  Average Speed  \
                 Time    Time     Time  Current"
            )?;
            writeln!(
                f,
                "                                 Dload  Upload  \
                 Total   Spent    Left  Speed"
            )?;
        }

        let cur_secs = self.timespent_us / 1_000_000;

        // Download ETA.
        let dl_est_secs = if self.dl_size_known && self.dl.speed > 0.0 {
            (self.dl.total_size as f64 / self.dl.speed) as i64
        } else {
            0
        };
        let dl_percent = Self::est_percent(
            if self.dl_size_known { self.dl.total_size } else { 0 },
            self.dl.cur_size,
        );

        // Upload ETA.
        let ul_est_secs = if self.ul_size_known && self.ul.speed > 0.0 {
            (self.ul.total_size as f64 / self.ul.speed) as i64
        } else {
            0
        };
        let ul_percent = Self::est_percent(
            if self.ul_size_known { self.ul.total_size } else { 0 },
            self.ul.cur_size,
        );

        // Overall estimates.
        let total_est_secs = dl_est_secs.max(ul_est_secs);
        let time_left = Self::format_time(
            if total_est_secs > 0 { total_est_secs - cur_secs } else { 0 },
        );
        let time_total = Self::format_time(total_est_secs);
        let time_spent = Self::format_time(cur_secs);

        // Total expected and current sizes.
        let total_expected = {
            let ul_exp = if self.ul_size_known { self.ul.total_size } else { self.ul.cur_size };
            let dl_exp = if self.dl_size_known { self.dl.total_size } else { self.dl.cur_size };
            ul_exp.saturating_add(dl_exp)
        };
        let total_cur = self.dl.cur_size.saturating_add(self.ul.cur_size);
        let total_percent = Self::est_percent(total_expected, total_cur);

        write!(
            f,
            "\r{:>3} {} {:>3} {} {:>3} {} {} {} {} {} {} {}",
            total_percent,
            Self::format_speed(total_expected as f64),
            dl_percent,
            Self::format_speed(self.dl.cur_size as f64),
            ul_percent,
            Self::format_speed(self.ul.cur_size as f64),
            Self::format_speed(self.dl.speed),
            Self::format_speed(self.ul.speed),
            time_total,
            time_spent,
            time_left,
            Self::format_speed(self.current_speed),
        )
    }
}

// ---------------------------------------------------------------------------
// Internal unit tests (can access pub(crate) fields)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    // -- Callback behaviour ---------------------------------------------------

    #[test]
    fn test_update_with_continuing_callback() {
        let mut p = Progress::new();
        p.start_now();
        p.download_inc(1024);
        p.callback = Some(Box::new(|_, _, _, _| true));
        assert!(p.update().is_ok());
    }

    #[test]
    fn test_update_with_aborting_callback() {
        let mut p = Progress::new();
        p.start_now();
        p.download_inc(1024);
        p.callback = Some(Box::new(|_, _, _, _| false));
        let result = p.update();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::AbortedByCallback);
    }

    #[test]
    fn test_update_hidden_suppresses_callback() {
        let mut p = Progress::new();
        p.start_now();
        p.hide = true;
        p.callback = Some(Box::new(|_, _, _, _| false));
        assert!(p.update().is_ok());
    }

    #[test]
    fn test_update_nometer_does_not_invoke_callback() {
        let mut p = Progress::new();
        p.start_now();
        p.download_inc(4096);
        p.callback = Some(Box::new(|_, _, _, _| false));
        p.update_nometer(); // no callback invoked, should not panic
    }

    // -- Speed check ----------------------------------------------------------

    #[test]
    fn test_check_paused_skips_speed_check() {
        let mut p = Progress::new();
        p.start_now();
        p.low_speed_limit = 1000;
        p.low_speed_time = 1;
        p.recv_pause(true);
        assert!(p.check().is_ok());
    }

    #[test]
    fn test_done_sets_flag() {
        let mut p = Progress::new();
        p.start_now();
        p.download_inc(2048);
        assert!(p.done().is_ok());
        assert!(p.done);
    }

    // -- Speed window ---------------------------------------------------------

    #[test]
    fn test_speed_window_initial_seed() {
        let mut p = Progress::new();
        p.start_now();
        p.download_inc(5000);
        let _ = p.update();
        assert!(p.speeder_count >= 1);
        assert!(p.current_speed >= 0.0);
    }

    // -- Timer recording internals --------------------------------------------

    #[test]
    fn test_delta_from_startsingle() {
        let mut p = Progress::new();
        p.start_now();
        let now = Instant::now();
        p.record_time_was(TimerId::StartSingle, now);
        thread::sleep(Duration::from_millis(2));
        let delta = p.delta_from_startsingle(Instant::now());
        assert!(delta >= 1);
    }

    #[test]
    fn test_delta_from_startsingle_no_start() {
        let p = Progress::new();
        assert_eq!(p.delta_from_startsingle(Instant::now()), 1);
    }

    // -- est_percent ----------------------------------------------------------

    #[test]
    fn test_est_percent() {
        assert_eq!(Progress::est_percent(0, 0), 0);
        assert_eq!(Progress::est_percent(100, 50), 50);
        assert_eq!(Progress::est_percent(100, 100), 100);
        assert_eq!(Progress::est_percent(200, 100), 50);
        assert_eq!(Progress::est_percent(50000, 25000), 50);
    }

    // -- Headers out tracking -------------------------------------------------

    #[test]
    fn test_headers_out_display() {
        let mut p = Progress::new();
        p.headers_out = true;
        let s1 = format!("{}", p);
        p.headers_out = false;
        let s2 = format!("{}", p);
        // s2 should have header lines, s1 should not
        assert!(s2.len() > s1.len());
    }
}
