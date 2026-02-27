// -----------------------------------------------------------------------
// curl-rs/src/progress_display.rs — Progress Bar/Meter Rendering
//
// Rust rewrite of src/tool_progress.c and src/tool_progress.h from
// curl 8.19.0-DEV. Implements the CLI progress meter that displays
// DL%/UL%, transfer sizes, transfer speeds, elapsed time, estimated
// remaining time, and current speed to stderr.
//
// The C implementation uses static (file-scope) variables for accumulated
// totals and a ring buffer for speed sampling. This Rust version replaces
// those statics with the `ProgressState` struct, enabling clean lifecycle
// management, testability, and thread-safety without global mutable state.
//
// Zero `unsafe` blocks — all I/O uses safe Rust abstractions.
//
// SPDX-License-Identifier: curl
// -----------------------------------------------------------------------

use std::fmt::Write as FmtWrite;
use std::io::Write as IoWrite;
use std::time::{Duration, Instant};

use crate::config::{GlobalConfig, OperationConfig};
use crate::stderr::{tool_stderr, tool_stderr_write};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of speed samples kept in the ring buffer.
/// Matches the C constant `SPEEDCNT` (10).
const SPEED_CNT: usize = 10;

/// Minimum interval between progress meter updates (milliseconds).
/// Matches the C throttle of 500 ms.
const UPDATE_INTERVAL: Duration = Duration::from_millis(500);

// ---------------------------------------------------------------------------
// PerTransfer — per-transfer progress counters
//
// This struct holds the per-transfer counters that libcurl's
// XFERINFOFUNCTION callback populates. In the C code these live inside
// `struct per_transfer` (tool_operate.h). We define them here because
// the `operate` module is not yet in scope as a dependency.
// ---------------------------------------------------------------------------

/// Per-transfer progress counters, updated by `xferinfo_cb`.
///
/// Maps to the progress-related fields of the C `struct per_transfer`
/// in `src/tool_operate.h`: `dltotal`, `dlnow`, `ultotal`, `ulnow`,
/// `dltotal_added`, `ultotal_added`, `abort`, `noprogress`.
#[derive(Debug, Clone)]
pub struct PerTransfer {
    /// Expected total download size (bytes), or 0 if unknown.
    pub dltotal: i64,
    /// Bytes downloaded so far for this transfer.
    pub dlnow: i64,
    /// Expected total upload size (bytes), or 0 if unknown.
    pub ultotal: i64,
    /// Bytes uploaded so far for this transfer.
    pub ulnow: i64,
    /// Whether this transfer's `dltotal` has already been registered
    /// with the global total (prevents double-counting).
    pub dltotal_added: bool,
    /// Whether this transfer's `ultotal` has already been registered
    /// with the global total.
    pub ultotal_added: bool,
    /// When true, the progress callback should signal cancellation.
    pub abort: bool,
    /// Per-transfer progress suppression flag.
    pub noprogress: bool,
}

impl PerTransfer {
    /// Creates a new, zeroed per-transfer progress tracker.
    pub fn new() -> Self {
        Self {
            dltotal: 0,
            dlnow: 0,
            ultotal: 0,
            ulnow: 0,
            dltotal_added: false,
            ultotal_added: false,
            abort: false,
            noprogress: false,
        }
    }
}

impl Default for PerTransfer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SpeedSample — one entry in the speed ring buffer
// ---------------------------------------------------------------------------

/// A single speed-measurement sample recording cumulative download and
/// upload byte counts at a specific point in time.
///
/// Maps to the C `struct speedcount` in `src/tool_progress.c`.
#[derive(Debug, Clone)]
struct SpeedSample {
    /// Cumulative bytes downloaded at sample time.
    dl: i64,
    /// Cumulative bytes uploaded at sample time.
    ul: i64,
    /// Monotonic timestamp of this sample.
    stamp: Instant,
}

impl SpeedSample {
    /// Creates a zeroed sample anchored at the given instant.
    fn new(now: Instant) -> Self {
        Self {
            dl: 0,
            ul: 0,
            stamp: now,
        }
    }
}

// ---------------------------------------------------------------------------
// ProgressState — accumulated progress tracking state
// ---------------------------------------------------------------------------

/// Accumulated progress tracking state for the progress meter.
///
/// Replaces the C file-scope static variables (`all_dltotal`, `all_ultotal`,
/// `all_dlalready`, `all_ulalready`, `speedstore[]`, `speedindex`,
/// `indexwrapped`, `header`, `stamp`) in `src/tool_progress.c`.
///
/// Collecting this state into a struct instead of using statics enables:
/// - Clean initialization and teardown in the binary's main loop.
/// - Unit-testable progress logic without global state pollution.
/// - Future thread-safety if parallel transfer display is needed.
pub struct ProgressState {
    /// Accumulated bytes already downloaded by finished transfers.
    pub all_dl_already: i64,
    /// Accumulated bytes already uploaded by finished transfers.
    pub all_ul_already: i64,
    /// Grand total expected download size across all transfers.
    pub all_dl_total: i64,
    /// Grand total expected upload size across all transfers.
    pub all_ul_total: i64,

    /// Ring buffer of speed samples (fixed size SPEED_CNT = 10).
    speed_store: [SpeedSample; SPEED_CNT],
    /// Current write index into `speed_store`.
    speed_index: usize,
    /// Whether `speed_index` has wrapped around at least once.
    index_wrapped: bool,

    /// Whether the column header line has been printed.
    header_printed: bool,
    /// Timestamp of the last progress meter update (for throttling).
    last_update: Instant,

    /// Transfer start time — used as the baseline for elapsed time
    /// and as the initial speed reference before the ring buffer wraps.
    start_time: Instant,
}

impl ProgressState {
    /// Creates a new, zeroed progress state anchored at the current time.
    pub fn new() -> Self {
        let now = Instant::now();
        let sample = SpeedSample::new(now);
        Self {
            all_dl_already: 0,
            all_ul_already: 0,
            all_dl_total: 0,
            all_ul_total: 0,
            speed_store: [
                sample.clone(),
                sample.clone(),
                sample.clone(),
                sample.clone(),
                sample.clone(),
                sample.clone(),
                sample.clone(),
                sample.clone(),
                sample.clone(),
                sample,
            ],
            speed_index: 0,
            index_wrapped: false,
            header_printed: false,
            last_update: now,
            start_time: now,
        }
    }

    /// Updates the progress state with newly sampled data.
    ///
    /// Call this after walking the transfer list to record a new
    /// speed sample. This drives the ring-buffer-based speed
    /// calculation in [`progress_meter`].
    ///
    /// # Arguments
    ///
    /// * `all_dl_now` — Cumulative bytes downloaded (finished + active).
    /// * `all_ul_now` — Cumulative bytes uploaded (finished + active).
    /// * `now`        — The current monotonic timestamp.
    pub fn update(&mut self, all_dl_now: i64, all_ul_now: i64, now: Instant) {
        let i = self.speed_index;
        self.speed_store[i] = SpeedSample {
            dl: all_dl_now,
            ul: all_ul_now,
            stamp: now,
        };
        self.speed_index += 1;
        if self.speed_index >= SPEED_CNT {
            self.index_wrapped = true;
            self.speed_index = 0;
        }
    }

    /// Resets all accumulated state, preparing for a fresh set of transfers.
    ///
    /// This is useful when the CLI starts a new batch of URLs — all counters,
    /// the speed ring buffer, and the header-printed flag are cleared.
    pub fn reset(&mut self) {
        let now = Instant::now();
        self.all_dl_already = 0;
        self.all_ul_already = 0;
        self.all_dl_total = 0;
        self.all_ul_total = 0;
        let sample = SpeedSample::new(now);
        self.speed_store = [
            sample.clone(),
            sample.clone(),
            sample.clone(),
            sample.clone(),
            sample.clone(),
            sample.clone(),
            sample.clone(),
            sample.clone(),
            sample.clone(),
            sample,
        ];
        self.speed_index = 0;
        self.index_wrapped = false;
        self.header_printed = false;
        self.last_update = now;
        self.start_time = now;
    }
}

impl Default for ProgressState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Saturating arithmetic
// ---------------------------------------------------------------------------

/// Saturating addition for `i64` values.
///
/// Returns `a + b` capped at `i64::MAX` instead of overflowing.
/// Mirrors the C helper `add_offt()` in `src/tool_progress.c`.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(add_offt(100, 200), 300);
/// assert_eq!(add_offt(i64::MAX - 10, 20), i64::MAX);
/// ```
pub fn add_offt(a: i64, b: i64) -> i64 {
    a.saturating_add(b)
}

// ---------------------------------------------------------------------------
// Fixed-width formatters
// ---------------------------------------------------------------------------

/// Formats a byte count into a right-justified string of at most 5 characters.
///
/// For values below 100,000 the raw number is right-justified in 5 columns.
/// For larger values the number is scaled with binary (1024-based) suffixes:
///
/// | Range               | Format   | Example  |
/// |---------------------|----------|----------|
/// | 0 – 99,999          | `%5d`    | `"99999"`|
/// | 100,000 – 102,399   | `"XX.Xk"`| `" 97.6k"`|
/// | 102,400 – 10,239,999| `"XXXXk"`| `"9999k"`|
/// | (scaled up)         | M, G, T… | `" 1.0M"`|
///
/// Matches the C function `max5data()` byte-for-byte.
pub fn max5data(bytes: i64) -> String {
    // Suffix units: k, M, G, T, P, E  (1024-based)
    const UNITS: [char; 6] = ['k', 'M', 'G', 'T', 'P', 'E'];

    if bytes < 100_000 {
        return format!("{:>5}", bytes);
    }

    let mut value = bytes;
    let mut k: usize = 0;

    loop {
        let next = value / 1024;
        if next < 100 {
            // Display with one decimal place: "XX.Xk"
            let whole = value / 1024;
            let frac = (value % 1024) * 10 / 1024;
            let mut buf = String::with_capacity(5);
            let _ = write!(buf, "{:>2}.{}{}", whole, frac, UNITS[k]);
            return buf;
        } else if next < 10_000 {
            // No decimal: "XXXXk"
            let mut buf = String::with_capacity(5);
            let _ = write!(buf, "{:>4}{}", next, UNITS[k]);
            return buf;
        }
        value = next;
        k += 1;
        // Guard: if we've exhausted all units, break to prevent index OOB.
        if k >= UNITS.len() {
            // Extremely large value — format as best we can.
            let mut buf = String::with_capacity(5);
            let _ = write!(buf, "{:>4}{}", value, UNITS[UNITS.len() - 1]);
            return buf;
        }
    }
}

/// Formats a duration (in seconds) into an exactly 8-character string.
///
/// | Range                  | Format          | Example      |
/// |------------------------|-----------------|--------------|
/// | ≤ 0                    | 8 spaces        | `"        "` |
/// | 1 – 359,999 s (≤99h)  | `"HH:MM:SS"`    | `"01:02:03"` |
/// | ≤ 999 days             | `"DDDd HHh"`    | `"123d 04h"` |
/// | ≤ 999 months (30d/mo)  | `"MMMm DDd"`    | `"123m 04d"` |
/// | ≤ 99,999 years         | `"YYYYYYYy"`    | `"  12345y"` |
/// | > 99,999 years         | `" >99999y"`    |              |
///
/// Matches the C function `time2str()` byte-for-byte.
pub fn time2str(seconds: i64) -> String {
    if seconds <= 0 {
        return "        ".to_string();
    }

    let h = seconds / 3600;
    if h <= 99 {
        let m = (seconds - h * 3600) / 60;
        let s = (seconds - h * 3600) - m * 60;
        return format!("{:02}:{:02}:{:02}", h, m, s);
    }

    let d = seconds / 86400;
    let hour = (seconds - d * 86400) / 3600;

    if d <= 999 {
        return format!("{:>3}d {:02}h", d, hour);
    }

    // More than 999 days — switch to months (30 days/month).
    let months = d / 30;
    if months <= 999 {
        return format!("{:>3}m {:02}d", months, d % 30);
    }

    // More than 999 months — switch to years (365 days/year).
    let years = d / 365;
    if years <= 99_999 {
        return format!("{:>7}y", years);
    }

    " >99999y".to_string()
}

// ---------------------------------------------------------------------------
// Transfer info callback
// ---------------------------------------------------------------------------

/// Progress callback invoked by libcurl's XFERINFOFUNCTION mechanism.
///
/// Updates per-transfer counters and checks for abort/pause conditions.
/// Returns `true` to cancel the transfer, `false` to continue.
///
/// Matches the C function `xferinfo_cb()` in `src/tool_progress.c`.
///
/// # Arguments
///
/// * `per`      — Per-transfer progress state (mutable for counter updates).
/// * `config`   — Per-operation configuration (for readbusy handling).
/// * `dl_total` — Expected total download size (from libcurl).
/// * `dl_now`   — Bytes downloaded so far (from libcurl).
/// * `ul_total` — Expected total upload size (from libcurl).
/// * `ul_now`   — Bytes uploaded so far (from libcurl).
pub fn xferinfo_cb(
    per: &mut PerTransfer,
    config: &mut OperationConfig,
    dl_total: i64,
    dl_now: i64,
    ul_total: i64,
    ul_now: i64,
) -> bool {
    per.dltotal = dl_total;
    per.dlnow = dl_now;
    per.ultotal = ul_total;
    per.ulnow = ul_now;

    // If the transfer has been flagged for abort (e.g., --fail-early
    // triggered by another parallel transfer), signal cancellation.
    if per.abort {
        return true;
    }

    // If the read callback previously returned CURL_READFUNC_PAUSE,
    // unpause the transfer now that the progress callback has fired.
    // In Rust we clear the flag; the actual unpause is performed by
    // the caller which holds the easy handle.
    if config.readbusy {
        config.readbusy = false;
        // In the C code this calls curl_easy_pause(per->curl, CURLPAUSE_CONT).
        // The Rust caller is responsible for issuing the unpause on the
        // easy handle after this callback returns.
    }

    false
}

// ---------------------------------------------------------------------------
// Progress meter display
// ---------------------------------------------------------------------------

/// Renders the progress meter to stderr.
///
/// Outputs a single-line status update showing download/upload percentages,
/// transferred sizes, transfer count, elapsed/estimated/remaining time,
/// and current speed. Updates are throttled to a minimum 500 ms interval
/// unless `is_final` is true (which forces immediate output with a
/// trailing newline).
///
/// Returns `true` if a line was actually printed, `false` if output was
/// suppressed (silent mode, no-progress mode, or throttle interval not
/// yet elapsed).
///
/// Matches the C function `progress_meter()` in `src/tool_progress.c`.
///
/// # Column Header
///
/// On the first call, a column header is printed:
/// ```text
/// DL% UL%  Dled  Uled  Xfers  Live Total     Current  Left    Speed
/// ```
///
/// # Arguments
///
/// * `state`     — Accumulated progress state (ring buffer, totals, flags).
/// * `global`    — Global configuration (noprogress, silent flags).
/// * `transfers` — Slice of active per-transfer trackers.
/// * `is_final`  — If true, force output and append a newline.
pub fn progress_meter(
    state: &mut ProgressState,
    global: &GlobalConfig,
    transfers: &mut [PerTransfer],
    is_final: bool,
) -> bool {
    // Suppress output if the user requested --no-progress-meter or --silent.
    if global.noprogress || global.silent {
        return false;
    }

    let now = Instant::now();
    let diff = now.duration_since(state.last_update);

    // Print column header once on the first invocation.
    if !state.header_printed {
        state.header_printed = true;
        tool_stderr_write(
            "DL% UL%  Dled  Uled  Xfers  Live \
             Total     Current  Left    Speed\n",
        );
    }

    // Throttle updates to at most once every 500 ms, unless this is the
    // final update after all transfers have completed.
    if !is_final && diff < UPDATE_INTERVAL {
        return false;
    }

    // Mark the update timestamp.
    state.last_update = now;

    // Compute elapsed seconds since transfer start.
    let elapsed_ms = now.duration_since(state.start_time).as_millis() as i64;
    let spent_seconds = elapsed_ms / 1000;

    // Accumulate live transfer counters.
    let mut all_dl_now: i64 = 0;
    let mut all_ul_now: i64 = 0;
    let mut dl_known = true;
    let mut ul_known = true;
    let xfers_added = transfers.len() as i64;
    let mut xfers_running: i64 = 0;

    // Start with bytes already accumulated from finished transfers.
    all_dl_now = add_offt(all_dl_now, state.all_dl_already);
    all_ul_now = add_offt(all_ul_now, state.all_ul_already);

    for per in transfers.iter_mut() {
        all_dl_now = add_offt(all_dl_now, per.dlnow);
        all_ul_now = add_offt(all_ul_now, per.ulnow);

        if per.dltotal == 0 {
            dl_known = false;
        } else if !per.dltotal_added {
            // Register this transfer's total exactly once.
            state.all_dl_total = add_offt(state.all_dl_total, per.dltotal);
            per.dltotal_added = true;
        }

        if per.ultotal == 0 {
            ul_known = false;
        } else if !per.ultotal_added {
            state.all_ul_total = add_offt(state.all_ul_total, per.ultotal);
            per.ultotal_added = true;
        }

        // Count non-finished transfers as "running".
        if !per.noprogress {
            xfers_running += 1;
        }
    }

    // Compute download percentage.
    let dl_percent: String = if dl_known && state.all_dl_total > 0 {
        let pct = if all_dl_now < (i64::MAX / 100) {
            all_dl_now * 100 / state.all_dl_total
        } else {
            all_dl_now / (state.all_dl_total / 100)
        };
        format!("{:>3}", pct)
    } else {
        " --".to_string()
    };

    // Compute upload percentage.
    let ul_percent: String = if ul_known && state.all_ul_total > 0 {
        let pct = if all_ul_now < (i64::MAX / 100) {
            all_ul_now * 100 / state.all_ul_total
        } else {
            all_ul_now / (state.all_ul_total / 100)
        };
        format!("{:>3}", pct)
    } else {
        " --".to_string()
    };

    // Record speed sample in ring buffer.
    state.update(all_dl_now, all_ul_now, now);

    // Calculate current speed from the ring buffer.
    let speed: i64 = {
        let (delta_ms, dl_delta, ul_delta) = if state.index_wrapped {
            // `speed_index` now points to the oldest stored sample.
            let oldest = &state.speed_store[state.speed_index];
            let delta = now.duration_since(oldest.stamp).as_millis() as i64;
            (delta, all_dl_now - oldest.dl, all_ul_now - oldest.ul)
        } else {
            // Not enough samples yet — measure from transfer start.
            (elapsed_ms, all_dl_now, all_ul_now)
        };

        let delta_ms_safe = if delta_ms == 0 { 1 } else { delta_ms };
        let dl_speed = (dl_delta as f64) / (delta_ms_safe as f64 / 1000.0);
        let ul_speed = (ul_delta as f64) / (delta_ms_safe as f64 / 1000.0);
        let s = if dl_speed > ul_speed {
            dl_speed
        } else {
            ul_speed
        };
        s as i64
    };

    // Estimate remaining and total time.
    let (time_left, time_total) = if dl_known && speed > 0 && state.all_dl_total > 0 {
        let est = state.all_dl_total / speed;
        let left = (state.all_dl_total - all_dl_now) / speed;
        (time2str(left), time2str(est))
    } else {
        (time2str(0), time2str(0))
    };

    let time_spent = time2str(spent_seconds);

    // Format the progress line.
    //
    // C format string reference:
    //   "\r%-3s %-3s %s %s %5lld %5lld  %s %s %s %s %5s"
    //
    // Layout:
    //   DL% UL%  Dled  Uled  Xfers  Live  Total     Current  Left    Speed
    let trailing = if is_final { "\n" } else { "" };

    let line = format!(
        "\r{} {} {} {} {:>5} {:>5}  {} {} {} {} {}",
        dl_percent,
        ul_percent,
        max5data(all_dl_now),
        max5data(all_ul_now),
        xfers_added,
        xfers_running,
        time_total,
        time_spent,
        time_left,
        max5data(speed),
        trailing,
    );

    // Write the line to stderr.
    if let Ok(mut guard) = tool_stderr().lock() {
        let _ = guard.stream.write_all(line.as_bytes());
        let _ = guard.stream.flush();
    }

    true
}

// ---------------------------------------------------------------------------
// Transfer finalization
// ---------------------------------------------------------------------------

/// Accumulates a finished transfer's byte counts into the global totals.
///
/// Called when a transfer completes (successfully or not) to move its
/// `dlnow`/`ulnow` into `all_dl_already`/`all_ul_already`, and to register
/// its `dltotal`/`ultotal` if not already counted.
///
/// Matches the C function `progress_finalize()` in `src/tool_progress.c`.
pub fn progress_finalize(state: &mut ProgressState, per: &mut PerTransfer) {
    // Move downloaded/uploaded bytes into already-accumulated totals.
    state.all_dl_already = add_offt(state.all_dl_already, per.dlnow);
    state.all_ul_already = add_offt(state.all_ul_already, per.ulnow);

    // Register the transfer's expected totals if not already done.
    if !per.dltotal_added {
        state.all_dl_total = add_offt(state.all_dl_total, per.dltotal);
        per.dltotal_added = true;
    }
    if !per.ultotal_added {
        state.all_ul_total = add_offt(state.all_ul_total, per.ultotal);
        per.ultotal_added = true;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- max5data tests --

    #[test]
    fn test_max5data_zero() {
        assert_eq!(max5data(0), "    0");
    }

    #[test]
    fn test_max5data_small() {
        assert_eq!(max5data(42), "   42");
    }

    #[test]
    fn test_max5data_boundary_99999() {
        assert_eq!(max5data(99999), "99999");
    }

    #[test]
    fn test_max5data_boundary_100000() {
        // 100000 / 1024 = 97 (< 100), so format is "XX.Xk"
        // 100000 / 1024 = 97, (100000 % 1024) * 10 / 1024 = (672 * 10) / 1024 = 6
        assert_eq!(max5data(100_000), "97.6k");
    }

    #[test]
    fn test_max5data_1mb() {
        // 1024 * 1024 = 1048576
        // 1048576 / 1024 = 1024 (>= 100, < 10000) -> "1024k"
        assert_eq!(max5data(1_048_576), "1024k");
    }

    #[test]
    fn test_max5data_large_megabytes() {
        // 10 * 1024 * 1024 = 10485760
        // / 1024 = 10240 (>= 10000)
        // / 1024 again = 10 (< 100) -> "10.0M"
        assert_eq!(max5data(10_485_760), "10.0M");
    }

    #[test]
    fn test_max5data_gigabyte() {
        // 1 GiB = 1073741824
        // /1024 = 1048576 (>= 10000)
        // /1024 = 1024 (>= 100, < 10000) -> "1024M"
        assert_eq!(max5data(1_073_741_824), "1024M");
    }

    #[test]
    fn test_max5data_exact_5_char() {
        // All outputs should be at most 5 characters
        let vals: &[i64] = &[0, 1, 999, 99999, 100_000, 1_048_576, 1_073_741_824];
        for &v in vals {
            let s = max5data(v);
            assert!(
                s.len() <= 5,
                "max5data({}) = {:?} (len={}), expected <=5",
                v,
                s,
                s.len()
            );
        }
    }

    // -- time2str tests --

    #[test]
    fn test_time2str_zero() {
        assert_eq!(time2str(0), "        ");
        assert_eq!(time2str(0).len(), 8);
    }

    #[test]
    fn test_time2str_negative() {
        assert_eq!(time2str(-5), "        ");
    }

    #[test]
    fn test_time2str_one_second() {
        assert_eq!(time2str(1), "00:00:01");
    }

    #[test]
    fn test_time2str_one_hour() {
        assert_eq!(time2str(3600), "01:00:00");
    }

    #[test]
    fn test_time2str_99_hours() {
        // 99 * 3600 = 356400
        assert_eq!(time2str(356_400), "99:00:00");
    }

    #[test]
    fn test_time2str_24_hours() {
        // 86400 seconds = 24 hours. h = 86400/3600 = 24 (≤ 99 → HH:MM:SS).
        assert_eq!(time2str(86_400), "24:00:00");
    }

    #[test]
    fn test_time2str_100_hours_to_days() {
        // 100 hours = 360000 seconds. h = 100 (> 99 → days format).
        // d = 360000/86400 = 4, h = (360000 - 4*86400)/3600 = 4
        assert_eq!(time2str(360_000), "  4d 04h");
    }

    #[test]
    fn test_time2str_999_days() {
        // 999 * 86400 = 86313600, + 3600 = 86317200 -> "999d 01h"
        assert_eq!(time2str(86_317_200), "999d 01h");
    }

    #[test]
    fn test_time2str_months() {
        // 1000 days -> months = 1000/30 = 33, days remainder = 1000%30 = 10
        let seconds = 1000 * 86400;
        assert_eq!(time2str(seconds), " 33m 10d");
    }

    #[test]
    fn test_time2str_years() {
        // 365 * 100 = 36500 days -> months = 36500/30 = 1216 > 999
        // years = 36500/365 = 100
        let seconds = 36500_i64 * 86400;
        assert_eq!(time2str(seconds), "    100y");
    }

    #[test]
    fn test_time2str_max_years() {
        // 99999 years: 99999 * 365 = 36499635 days
        let seconds = 36_499_635_i64 * 86400;
        assert_eq!(time2str(seconds), "  99999y");
    }

    #[test]
    fn test_time2str_overflow() {
        // > 99999 years
        let seconds = 40_000_000_i64 * 86400;
        assert_eq!(time2str(seconds), " >99999y");
    }

    #[test]
    fn test_time2str_always_8_chars() {
        let vals: &[i64] = &[0, 1, 3600, 86400, 86_400_000, 3_153_600_000];
        for &v in vals {
            let s = time2str(v);
            assert_eq!(
                s.len(),
                8,
                "time2str({}) = {:?} (len={}), expected 8",
                v,
                s,
                s.len()
            );
        }
    }

    // -- add_offt tests --

    #[test]
    fn test_add_offt_normal() {
        assert_eq!(add_offt(100, 200), 300);
    }

    #[test]
    fn test_add_offt_saturation() {
        assert_eq!(add_offt(i64::MAX - 10, 20), i64::MAX);
    }

    #[test]
    fn test_add_offt_zero() {
        assert_eq!(add_offt(0, 0), 0);
    }

    #[test]
    fn test_add_offt_max_plus_zero() {
        assert_eq!(add_offt(i64::MAX, 0), i64::MAX);
    }

    // -- ProgressState tests --

    #[test]
    fn test_progress_state_new() {
        let state = ProgressState::new();
        assert_eq!(state.all_dl_already, 0);
        assert_eq!(state.all_ul_already, 0);
        assert_eq!(state.all_dl_total, 0);
        assert_eq!(state.all_ul_total, 0);
        assert_eq!(state.speed_index, 0);
        assert!(!state.index_wrapped);
        assert!(!state.header_printed);
    }

    #[test]
    fn test_progress_state_update() {
        let mut state = ProgressState::new();
        let now = Instant::now();
        state.update(1000, 500, now);
        assert_eq!(state.speed_index, 1);
        assert!(!state.index_wrapped);
        assert_eq!(state.speed_store[0].dl, 1000);
        assert_eq!(state.speed_store[0].ul, 500);
    }

    #[test]
    fn test_progress_state_update_wraps() {
        let mut state = ProgressState::new();
        let now = Instant::now();
        for i in 0..SPEED_CNT {
            state.update(i as i64 * 100, i as i64 * 50, now);
        }
        assert!(state.index_wrapped);
        assert_eq!(state.speed_index, 0);
    }

    #[test]
    fn test_progress_state_reset() {
        let mut state = ProgressState::new();
        state.all_dl_already = 999;
        state.all_ul_already = 888;
        state.all_dl_total = 777;
        state.all_ul_total = 666;
        state.header_printed = true;
        state.speed_index = 5;
        state.index_wrapped = true;

        state.reset();

        assert_eq!(state.all_dl_already, 0);
        assert_eq!(state.all_ul_already, 0);
        assert_eq!(state.all_dl_total, 0);
        assert_eq!(state.all_ul_total, 0);
        assert_eq!(state.speed_index, 0);
        assert!(!state.index_wrapped);
        assert!(!state.header_printed);
    }

    // -- PerTransfer tests --

    #[test]
    fn test_per_transfer_new() {
        let pt = PerTransfer::new();
        assert_eq!(pt.dltotal, 0);
        assert_eq!(pt.dlnow, 0);
        assert_eq!(pt.ultotal, 0);
        assert_eq!(pt.ulnow, 0);
        assert!(!pt.dltotal_added);
        assert!(!pt.ultotal_added);
        assert!(!pt.abort);
        assert!(!pt.noprogress);
    }

    // -- xferinfo_cb tests --

    #[test]
    fn test_xferinfo_cb_normal() {
        let mut per = PerTransfer::new();
        let mut config = OperationConfig::new();
        let cancel = xferinfo_cb(&mut per, &mut config, 1000, 500, 2000, 100);
        assert!(!cancel);
        assert_eq!(per.dltotal, 1000);
        assert_eq!(per.dlnow, 500);
        assert_eq!(per.ultotal, 2000);
        assert_eq!(per.ulnow, 100);
    }

    #[test]
    fn test_xferinfo_cb_abort() {
        let mut per = PerTransfer::new();
        per.abort = true;
        let mut config = OperationConfig::new();
        let cancel = xferinfo_cb(&mut per, &mut config, 1000, 500, 2000, 100);
        assert!(cancel);
    }

    #[test]
    fn test_xferinfo_cb_readbusy() {
        let mut per = PerTransfer::new();
        let mut config = OperationConfig::new();
        config.readbusy = true;
        let cancel = xferinfo_cb(&mut per, &mut config, 0, 0, 0, 0);
        assert!(!cancel);
        assert!(!config.readbusy);
    }

    // -- progress_finalize tests --

    #[test]
    fn test_progress_finalize_accumulates() {
        let mut state = ProgressState::new();
        let mut per = PerTransfer::new();
        per.dlnow = 500;
        per.ulnow = 300;
        per.dltotal = 1000;
        per.ultotal = 600;

        progress_finalize(&mut state, &mut per);

        assert_eq!(state.all_dl_already, 500);
        assert_eq!(state.all_ul_already, 300);
        assert_eq!(state.all_dl_total, 1000);
        assert_eq!(state.all_ul_total, 600);
        assert!(per.dltotal_added);
        assert!(per.ultotal_added);
    }

    #[test]
    fn test_progress_finalize_no_double_count() {
        let mut state = ProgressState::new();
        let mut per = PerTransfer::new();
        per.dlnow = 500;
        per.ulnow = 300;
        per.dltotal = 1000;
        per.ultotal = 600;
        per.dltotal_added = true;
        per.ultotal_added = true;

        progress_finalize(&mut state, &mut per);

        // dlnow/ulnow still accumulate
        assert_eq!(state.all_dl_already, 500);
        assert_eq!(state.all_ul_already, 300);
        // But totals are NOT double-added since flags were already true
        assert_eq!(state.all_dl_total, 0);
        assert_eq!(state.all_ul_total, 0);
    }

    // -- progress_meter tests --

    /// Helper to create a minimal GlobalConfig for unit tests without
    /// calling globalconf_init() (which requires library initialization).
    fn make_test_global(noprogress: bool, silent: bool) -> GlobalConfig {
        use crate::config::*;
        use crate::libinfo::LibCurlInfo;

        GlobalConfig {
            state: TransferState::new(),
            trace_dump: None,
            trace_stream: None,
            libcurl: None,
            ssl_sessions: None,
            variables: Vec::new(),
            configs: vec![OperationConfig::new()],
            current: 0,
            ms_per_transfer: 0,
            tracetype: TraceType::None,
            progressmode: 0,
            parallel_host: 0,
            parallel_max: PARALLEL_DEFAULT,
            verbosity: 0,
            parallel: false,
            parallel_connect: false,
            fail_early: false,
            styled_output: true,
            trace_fopened: false,
            tracetime: false,
            traceids: false,
            showerror: false,
            silent,
            noprogress,
            isatty: false,
            trace_set: false,
            libcurl_info: LibCurlInfo::default(),
            term: TerminalState::new(),
            libcurl_version: None,
        }
    }

    #[test]
    fn test_progress_meter_suppressed_noprogress() {
        let mut state = ProgressState::new();
        let global = make_test_global(true, false);
        let mut transfers: Vec<PerTransfer> = Vec::new();
        let result = progress_meter(&mut state, &global, &mut transfers, false);
        assert!(!result);
    }

    #[test]
    fn test_progress_meter_suppressed_silent() {
        let mut state = ProgressState::new();
        let global = make_test_global(false, true);
        let mut transfers: Vec<PerTransfer> = Vec::new();
        let result = progress_meter(&mut state, &global, &mut transfers, false);
        assert!(!result);
    }
}
