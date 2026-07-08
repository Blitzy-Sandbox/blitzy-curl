// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// Rust rewrite of curl's src/tool_progress.c (parallel progress meter / max5data).

//! # `progress_display` — the `--parallel` aggregate progress meter
//!
//! A faithful, idiomatic-Rust rewrite of curl 8.19.0-DEV's `src/tool_progress.c`
//! (`src/tool_progress.h`). This module renders the **`-Z` / `--parallel` aggregate
//! progress meter** — the single stderr status line that summarizes *all* in-flight
//! transfers at once:
//!
//! ```text
//! DL% UL%  Dled  Uled  Xfers  Live Total     Current  Left    Speed
//!   6 --   9.9G     0     2     2   0:00:40  0:00:02  0:00:37 4087M
//! ```
//!
//! ## Scope (what this module is *not*)
//!
//! This is strictly the **parallel aggregate** meter. The *single-transfer* progress
//! bar / meter — the `CURLOPT_XFERINFOFUNCTION` callback ported from `src/tool_cb_prg.c`
//! — lives in `callbacks/progress.rs`, authored by the callbacks sub-agent, and is **not**
//! duplicated here. In parallel mode curl overrides each easy handle's xferinfo callback
//! with [`xferinfo_cb`] (see `src/tool_operate.c`), so the per-transfer bar is not used and
//! the aggregate stats layout below is shown regardless of
//! [`GlobalConfig::progressmode`](crate::args::GlobalConfig).
//!
//! ## Parity contract (byte-for-byte with curl 8.x — AAP §0.7.1 / §0.7.3)
//!
//! The observable stderr text is preserved exactly so downstream log scrapers keep working:
//!
//! * [`max5data`] reproduces curl's five-column byte formatter *character-for-character*,
//!   including the `k`/`M`/`G`/`T`/`P`/`E` suffix ladder and the `< 100 → one-decimal`
//!   vs. `< 10000 → no-decimal` thresholds.
//! * [`time2str`] reproduces curl's eight-character elapsed/remaining time formatter.
//! * The header line and the per-refresh column layout, ordering, and inter-field spacing
//!   are emitted verbatim (see [`ProgressMeter::progress_meter`]).
//! * Refresh throttling matches curl: the line is redrawn on the final call or at most
//!   roughly twice per second (a new line only when ≥ 500 ms have elapsed).
//!
//! ## State ownership — no global mutable state, no `unsafe`
//!
//! curl keeps the meter's running totals and its speed ring buffer in file-level `static`
//! variables. Reproducing that with Rust `static mut` would require `unsafe`, which is
//! forbidden outside the FFI crate (AAP §0.7.2). Instead all of that state is encapsulated
//! in the [`ProgressMeter`] value that `operate.rs` owns for the lifetime of a parallel run.
//! The whole module is `#![forbid]`-clean safe Rust: it contains **zero** `unsafe` blocks.
//!
//! ## Decoupling from `operate.rs` (no cyclic dependency)
//!
//! curl's meter walks the intrusive `struct per_transfer` list directly. To avoid a cyclic
//! dependency (this module must not reach into `operate.rs`'s transfer type), the per-transfer
//! progress counters are modeled by the small, self-contained [`TransferProgress`] value.
//! `operate.rs` owns those values (one per live transfer), feeds them from libcurl's xferinfo
//! callback via [`xferinfo_cb`], and hands a slice of references to
//! [`ProgressMeter::progress_meter`] on each poll iteration. The cumulative "already
//! finished" totals are folded in through [`ProgressMeter::progress_finalize`] just before a
//! completed transfer is dropped.

// The consumer of this module — the parallel dispatch loop in `operate.rs` — lands in a
// later checkpoint (AAP §0.7.3), mirroring the same allowance already present in the sibling
// `args.rs` and `terminal.rs` modules. Until that call site exists the crate-level
// `dead_code` lint would otherwise fire on this module's public API during intermediate
// builds; the items become live once `operate.rs` is wired.
#![allow(dead_code)]

use std::cell::Cell;
use std::io::Write;
use std::time::Instant;

use crate::args::GlobalConfig;
use crate::terminal::get_terminal_columns;

/// The meter's column header, emitted once to stderr before the first data line.
///
/// Reproduced byte-for-byte from `src/tool_progress.c` (the two adjacent C string literals
/// concatenated). It is 66 bytes including the trailing newline; changing a single space
/// would break downstream scrapers, so this constant must not be edited.
const PROGRESS_HEADER: &str = "DL% UL%  Dled  Uled  Xfers  Live Total     Current  Left    Speed\n";

/// Size of the rolling speed-sample ring buffer (curl's `SPEEDCNT`).
///
/// The instantaneous transfer speed shown by the meter is computed over the window between
/// the oldest and newest of the last `SPEEDCNT` samples, smoothing out short-term jitter.
const SPEEDCNT: usize = 10;

/// curl's refresh throttle: a fresh data line is drawn at most once per this many
/// milliseconds (unless it is the final line). Mirrors the `diff > 500` gate in
/// `src/tool_progress.c`, i.e. roughly two updates per second.
const REFRESH_INTERVAL_MS: i64 = 500;

/// Saturating add of `add` into `*val`, clamped at [`i64::MAX`].
///
/// Faithful port of curl's `add_offt()` (`src/tool_progress.c`): the running byte totals are
/// `curl_off_t` (a signed 64-bit value), and rather than wrapping on overflow curl pins the
/// total at `CURL_OFF_T_MAX`. All callers only ever add non-negative byte counts, so the
/// intermediate `i64::MAX - *val` never underflows (`*val` starts at `0` and only grows).
#[inline]
fn add_offt(val: &mut i64, add: i64) {
    if i64::MAX - *val < add {
        // Adding `add` would exceed the representable maximum — saturate, exactly as curl does.
        *val = i64::MAX;
    } else {
        *val += add;
    }
}

/// Format a byte count into a string that is **at most five columns wide**, appending a
/// binary unit suffix (`k`, `M`, `G`, `T`, `P`, `E`) once the value no longer fits in five
/// plain digits.
///
/// This is a character-for-character port of curl's `max5data()` (`src/tool_progress.c`,
/// marked `UNITTEST`). The exact thresholds and field widths are user-visible and are relied
/// upon by log scrapers, so they are reproduced precisely:
///
/// * `bytes < 100000` → the raw value right-justified in five columns (`"%5d"`), e.g.
///   `42` → `"   42"`, `99999` → `"99999"`.
/// * otherwise the value is repeatedly divided by 1024, advancing the unit suffix each step,
///   until the divided value `nbytes` fits:
///   * `nbytes < 100` → one decimal place: `"%2d.%1d%c"` where the integer part is
///     `bytes / 1024`, the single fraction digit is `(bytes % 1024) * 10 / 1024`, and `%c`
///     is the current unit — e.g. `100000` → `"97.6k"`.
///   * `nbytes < 10000` → no decimals: `"%4d%c"` — e.g. `i64::MAX`, which divides down to
///     `8191` petabytes-worth, renders as `"8191P"`.
///
/// Every produced string is exactly five characters wide.
///
/// ## API note
///
/// curl's C signature writes into a caller-supplied `char max5[6]` buffer and returns that
/// pointer. The idiomatic Rust equivalent is to return an owned [`String`]; the meter is
/// redrawn at most twice per second, so the few tiny allocations per refresh are negligible.
pub fn max5data(bytes: i64) -> String {
    // curl: `const char unit[] = { 'k', 'M', 'G', 'T', 'P', 'E', 0 };` — the trailing NUL is
    // only the C loop sentinel; the Rust loop bound (below) plays that role instead.
    const UNIT: [char; 6] = ['k', 'M', 'G', 'T', 'P', 'E'];

    // curl: `if(bytes < 100000) { snprintf("%5" ...); return; }`
    if bytes < 100_000 {
        return format!("{bytes:5}");
    }

    let mut bytes = bytes;
    let mut k = 0usize;
    loop {
        let nbytes = bytes / 1024;
        let unit = UNIT[k];
        if nbytes < 100 {
            // One decimal place. The integer part uses the *current* `bytes` (`bytes / 1024`
            // == `nbytes`), and the single fraction digit is `(bytes % 1024) * 10 / 1024`,
            // which is always in `0..=9`. Matches `"%2" FMT ".%" FMT "%c"`.
            return format!("{:2}.{}{unit}", bytes / 1024, (bytes % 1024) * 10 / 1024);
        }
        if nbytes < 10_000 {
            // No decimals. Matches `"%4" FMT "%c"`.
            return format!("{nbytes:4}{unit}");
        }
        bytes = nbytes;
        k += 1;
        // curl: `DEBUGASSERT(unit[k]);` — for any non-negative `i64` the value drops below
        // 10000 by `k == 4` (`i64::MAX` renders as `"8191P"`), so `k` never reaches the
        // sentinel; this assertion documents and guards that invariant in debug builds.
        debug_assert!(k < UNIT.len(), "max5data unit index overflow");
    }
}

/// Format a duration in seconds into an **eight-character** time string.
///
/// A character-for-character port of curl's `time2str()` (`src/tool_progress.c`, marked
/// `UNITTEST`). The layout escalates as the magnitude grows, always yielding exactly eight
/// columns so the meter's columns stay aligned:
///
/// * `seconds <= 0` → eight spaces (`"        "`).
/// * up to 99 hours → `"HH:MM:SS"` (`"%02d:%02d:%02d"`).
/// * otherwise, in whole days `d`:
///   * `d <= 999` → `"%3dd %02dh"` (days + leftover hours), e.g. `"  5d 03h"`.
///   * else, in whole months `m = d / 30`:
///     * `m <= 999` → `"%3dm %02dd"` (months + leftover days-mod-30).
///     * else, in whole years `y = d / 365`:
///       * `y <= 99999` → `"%7dy"`.
///       * else → `" >99999y"`.
pub fn time2str(seconds: i64) -> String {
    // curl: `if(seconds <= 0) { copy 8 spaces; return; }`
    if seconds <= 0 {
        return String::from("        ");
    }

    let h = seconds / 3600;
    if h <= 99 {
        let m = (seconds - h * 3600) / 60;
        let s = (seconds - h * 3600) - m * 60;
        return format!("{h:02}:{m:02}:{s:02}");
    }

    let d = seconds / 86400;
    let h = (seconds - d * 86400) / 3600;
    if d <= 999 {
        return format!("{d:3}d {h:02}h");
    }

    let m = d / 30;
    if m <= 999 {
        return format!("{m:3}m {:02}d", d % 30);
    }

    let y = d / 365;
    if y <= 99999 {
        format!("{y:7}y")
    } else {
        String::from(" >99999y")
    }
}

/// Per-transfer progress state consumed by the aggregate meter.
///
/// This is the decoupled stand-in for the progress-relevant fields of curl's
/// `struct per_transfer` (`src/tool_operate.h`): the four `curl_off_t` progress counters,
/// the two "already folded into the running total" flags, and the abort flag. It is owned by
/// `operate.rs` (one instance per live transfer) — this module only borrows it — which keeps
/// the dependency edge one-directional (`operate.rs → progress_display`, never the reverse).
///
/// Every field uses [`Cell`] interior mutability so the meter can update the "already added"
/// bookkeeping and the xferinfo hook can record fresh counters through a shared `&` reference,
/// exactly matching the borrow shape [`ProgressMeter::progress_meter`] expects (a slice of
/// shared references). `Cell` — rather than a lock — is correct here because the curl CLI runs
/// on a single-threaded Tokio runtime (`flavor = "current_thread"`), so the meter, the
/// callback, and the dispatch loop never touch a [`TransferProgress`] concurrently.
///
/// No `unsafe` is involved: `Cell` is entirely safe, checked interior mutability.
#[derive(Debug, Default)]
pub struct TransferProgress {
    /// Total bytes expected to download (`curl_off_t dltotal`), or `0` when still unknown.
    dltotal: Cell<i64>,
    /// Bytes downloaded so far (`curl_off_t dlnow`).
    dlnow: Cell<i64>,
    /// Total bytes expected to upload (`curl_off_t ultotal`), or `0` when still unknown.
    ultotal: Cell<i64>,
    /// Bytes uploaded so far (`curl_off_t ulnow`).
    ulnow: Cell<i64>,
    /// Whether this transfer's `dltotal` has already been folded into the meter's running
    /// grand total (curl's `BIT(dltotal_added)`), so it is only counted once.
    dltotal_added: Cell<bool>,
    /// Whether this transfer's `ultotal` has already been folded in (curl's
    /// `BIT(ultotal_added)`).
    ultotal_added: Cell<bool>,
    /// Set by `operate.rs` when a critical error elsewhere (e.g. `--fail-early`) means this
    /// transfer must be aborted at its next progress callback (curl's `BIT(abort)`).
    abort: Cell<bool>,
    /// Set by the read/write callbacks when a non-blocking stdin read paused the transfer
    /// (curl's `config->readbusy`); [`xferinfo_cb`] clears it and requests a resume.
    readbusy: Cell<bool>,
    /// Raised by [`xferinfo_cb`] to ask `operate.rs` to un-pause this transfer's easy handle
    /// (`curl_easy_pause(CURLPAUSE_CONT)`). Decoupling this into a flag lets the actual pause
    /// call stay in `operate.rs`, which owns the handle, instead of coupling this module to it.
    resume_requested: Cell<bool>,
}

impl TransferProgress {
    /// Create a zero-initialized transfer-progress record (all counters `0`, all flags clear).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the latest progress counters, as delivered by libcurl's xferinfo callback.
    /// Mirrors the four assignments at the top of curl's `xferinfo_cb`.
    pub fn record(&self, dltotal: i64, dlnow: i64, ultotal: i64, ulnow: i64) {
        self.dltotal.set(dltotal);
        self.dlnow.set(dlnow);
        self.ultotal.set(ultotal);
        self.ulnow.set(ulnow);
    }

    /// Flag (or clear) the abort request for this transfer (curl's `per->abort`). Set by
    /// `operate.rs` when another transfer's failure must tear this one down.
    pub fn set_abort(&self, abort: bool) {
        self.abort.set(abort);
    }

    /// Whether this transfer has been marked for abort.
    #[must_use]
    pub fn is_aborting(&self) -> bool {
        self.abort.get()
    }

    /// Mark this transfer as read-paused (curl's `config->readbusy = TRUE`), so the next
    /// [`xferinfo_cb`] call requests a resume.
    pub fn set_readbusy(&self) {
        self.readbusy.set(true);
    }

    /// Consume the pending resume request, returning `true` exactly once after
    /// [`xferinfo_cb`] observed a read-paused transfer. `operate.rs` calls this after the
    /// callback returns and, when `true`, issues `curl_easy_pause(CURLPAUSE_CONT)`.
    pub fn take_resume_requested(&self) -> bool {
        let requested = self.resume_requested.get();
        self.resume_requested.set(false);
        requested
    }

    /// Expected download total, or `0` when unknown (`per->dltotal`).
    #[must_use]
    pub fn dltotal(&self) -> i64 {
        self.dltotal.get()
    }

    /// Bytes downloaded so far (`per->dlnow`).
    #[must_use]
    pub fn dlnow(&self) -> i64 {
        self.dlnow.get()
    }

    /// Expected upload total, or `0` when unknown (`per->ultotal`).
    #[must_use]
    pub fn ultotal(&self) -> i64 {
        self.ultotal.get()
    }

    /// Bytes uploaded so far (`per->ulnow`).
    #[must_use]
    pub fn ulnow(&self) -> i64 {
        self.ulnow.get()
    }
}

/// libcurl `CURLOPT_XFERINFOFUNCTION` hook used for **parallel** transfers.
///
/// A faithful port of curl's `xferinfo_cb()` (`src/tool_progress.c`). In parallel mode curl
/// installs this on every easy handle (`src/tool_operate.c`); it records the freshest progress
/// counters into the transfer's [`TransferProgress`] so [`ProgressMeter::progress_meter`] can
/// aggregate across all live transfers.
///
/// Returns `1` to tell libcurl to abort the transfer when [`TransferProgress::set_abort`] has
/// been raised (a critical error occurred elsewhere), and `0` to continue — matching the C
/// callback's `int` contract (`curl_off_t` arguments map to `i64`).
///
/// Side effect (decoupled from the easy handle): when the transfer was read-paused
/// (`config->readbusy` in curl), this clears that flag and raises
/// [`TransferProgress::take_resume_requested`] so `operate.rs` — which owns the handle — can
/// call `curl_easy_pause(CURLPAUSE_CONT)`. curl performs that pause inline here; splitting it
/// out keeps this module free of any handle dependency.
#[must_use]
pub fn xferinfo_cb(
    per: &TransferProgress,
    dltotal: i64,
    dlnow: i64,
    ultotal: i64,
    ulnow: i64,
) -> i32 {
    // curl: record the four counters unconditionally.
    per.dltotal.set(dltotal);
    per.dlnow.set(dlnow);
    per.ultotal.set(ultotal);
    per.ulnow.set(ulnow);

    // curl: `if(per->abort) return 1;`
    if per.abort.get() {
        return 1;
    }

    // curl: `if(config->readbusy) { config->readbusy = FALSE; curl_easy_pause(CONT); }`
    // The unpause needs the easy handle, which lives in `operate.rs`; signal it via a flag.
    if per.readbusy.get() {
        per.readbusy.set(false);
        per.resume_requested.set(true);
    }

    0
}

/// One rolling speed sample: the cumulative byte totals captured at a point in time.
///
/// Port of curl's `struct speedcount` (`src/tool_progress.c`). [`ProgressMeter`] keeps a ring
/// of [`SPEEDCNT`] of these and derives the displayed transfer speed from the delta between
/// the oldest and newest samples. `stamp` is [`None`] for a slot that has not been written
/// yet; such a slot is never read, because the meter only consults the oldest sample once the
/// ring has wrapped (i.e. once every slot holds a real sample).
#[derive(Debug, Default, Clone, Copy)]
struct SpeedCount {
    /// Cumulative downloaded-bytes total at `stamp`.
    dl: i64,
    /// Cumulative uploaded-bytes total at `stamp`.
    ul: i64,
    /// When this sample was taken (`None` until the slot is first written).
    stamp: Option<Instant>,
}

/// The parallel aggregate progress meter's running state.
///
/// This value encapsulates everything curl keeps in file-level `static`s across successive
/// `progress_meter()` / `progress_finalize()` calls: the grand totals, the "already finished"
/// carry-over, the speed ring buffer, the last-drawn timestamp, and whether the header has
/// been emitted. `operate.rs` constructs one [`ProgressMeter`] per parallel run and threads a
/// `&mut` reference through the poll loop. Keeping this state in a value (rather than in
/// `static mut`) is what lets the whole module stay free of `unsafe` (AAP §0.7.2).
#[derive(Debug, Default)]
pub struct ProgressMeter {
    /// Sum of every transfer's known download total, each added exactly once
    /// (curl's `all_dltotal`).
    all_dltotal: i64,
    /// Sum of every transfer's known upload total, each added exactly once
    /// (curl's `all_ultotal`).
    all_ultotal: i64,
    /// Downloaded bytes carried over from transfers that have already finished
    /// (curl's `all_dlalready`).
    all_dlalready: i64,
    /// Uploaded bytes carried over from transfers that have already finished
    /// (curl's `all_ulalready`).
    all_ulalready: i64,
    /// Rolling window of recent cumulative samples used to compute the displayed speed
    /// (curl's `speedstore[SPEEDCNT]`).
    speedstore: [SpeedCount; SPEEDCNT],
    /// Index of the next slot to write in [`Self::speedstore`] (curl's `speedindex`).
    speedindex: usize,
    /// Whether [`Self::speedstore`] has filled at least once, so the oldest sample is valid
    /// (curl's `indexwrapped`).
    indexwrapped: bool,
    /// Timestamp of the last drawn data line, used for the ≥ 500 ms refresh throttle
    /// (curl's function-local `static struct curltime stamp`). [`None`] until the first draw,
    /// reproducing curl's zero-initialized stamp that forces an immediate first render.
    stamp: Option<Instant>,
    /// Whether the column header has been printed yet (curl's function-local
    /// `static bool header`).
    header: bool,
}

impl ProgressMeter {
    /// Create a fresh meter with all totals zeroed, an empty speed ring, and the header
    /// not-yet-printed — equivalent to curl's zero-initialized file-level statics.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Draw (or skip) one refresh of the aggregate parallel progress meter, returning `true`
    /// when a data line was actually emitted.
    ///
    /// Faithful port of curl's `progress_meter()` (`src/tool_progress.c`). Behavior preserved
    /// exactly:
    ///
    /// * **Suppression.** Emits nothing and returns `false` when
    ///   [`GlobalConfig::noprogress`](crate::args::GlobalConfig) or
    ///   [`GlobalConfig::silent`](crate::args::GlobalConfig) is set. In curl the `--output`-to-a-tty
    ///   case is folded into `noprogress` upstream in `operate.rs`, so honoring `noprogress`
    ///   here also honors the terminal-detection (`isatty`) decision. `progressmode` does not
    ///   gate this meter: in parallel mode curl overrides the per-transfer bar callback, so the
    ///   aggregate stats layout is shown for both `--progress-bar` and the default stats mode.
    /// * **Header.** The column header is printed to stderr exactly once, on the first call.
    /// * **Throttle.** A data line is drawn only when `show_final` is set or at least
    ///   [`REFRESH_INTERVAL_MS`] have elapsed since the previous draw (curl's `diff > 500`),
    ///   capping the refresh rate at roughly twice per second.
    /// * **Aggregation.** Sums `dlnow`/`ulnow` across `transfers` plus the finished carry-over,
    ///   folds each transfer's known totals into the grand totals exactly once, computes the
    ///   download/upload percentages, derives the speed over the rolling sample window, and
    ///   formats the total/elapsed/remaining times.
    /// * **Layout.** The `\r`-prefixed line uses curl's exact column order, field widths, and
    ///   spacing; each byte field is rendered by [`max5data`] and each time field by
    ///   [`time2str`], so the visible columns are byte-identical to curl 8.x.
    ///
    /// `xfers_added` and `xfers_running` are the values curl reads from the multi handle via
    /// `curl_multi_get_offt(CURLMINFO_XFERS_ADDED / CURLMINFO_XFERS_RUNNING)`. Because
    /// `operate.rs` owns the multi handle, it reads them and passes them in, keeping this
    /// module decoupled from the handle. `transfers` is the set of currently-live transfers'
    /// progress records (see [`TransferProgress`]); the finished ones have already been folded
    /// in via [`Self::progress_finalize`].
    ///
    /// ## Terminal-width line sizing
    ///
    /// The transient (non-final) line is padded with trailing spaces out to the current
    /// terminal width — queried via [`get_terminal_columns`] — so that a redraw fully clears
    /// whatever the previous, possibly longer, line left behind, keeping the meter on a single
    /// tidy line (the "sized to the terminal width" behavior). Only trailing padding is added;
    /// the meaningful columns are emitted in curl's exact layout, so field-parsing scrapers see
    /// identical content (AAP §0.7.3). The line is never truncated below its content — a
    /// terminal narrower than the fixed layout falls back to curl's natural wrapping.
    pub fn progress_meter(
        &mut self,
        global: &GlobalConfig,
        start: Instant,
        transfers: &[&TransferProgress],
        xfers_added: i64,
        xfers_running: i64,
        show_final: bool,
    ) -> bool {
        // curl: `if(global->noprogress || global->silent) return FALSE;`
        if global.noprogress || global.silent {
            return false;
        }

        let now = Instant::now();
        // curl: `diff = curlx_timediff_ms(now, stamp);` — with `stamp` zero-initialized the
        // first call sees an effectively infinite delta and always draws. `None` models that.
        let diff: i64 = match self.stamp {
            Some(last) => elapsed_ms(now, last),
            None => i64::MAX,
        };

        // curl: header printed once, before the throttle gate.
        if !self.header {
            self.header = true;
            let _ = std::io::stderr().write_all(PROGRESS_HEADER.as_bytes());
        }

        // curl: `if(final || (diff > 500)) { ... } return FALSE;`
        if !show_final && diff <= REFRESH_INTERVAL_MS {
            return false;
        }

        // curl: `stamp = now;`
        self.stamp = Some(now);

        // curl: `spent = curlx_timediff_ms(now, *start) / 1000;`
        let spent = elapsed_ms(now, start) / 1000;

        // curl: dlpercen/ulpercen default to "--" and are overwritten only when known.
        let mut dlpercen = String::from("--");
        let mut ulpercen = String::from("--");

        let mut all_dlnow: i64 = 0;
        let mut all_ulnow: i64 = 0;
        let mut dlknown = true;
        let mut ulknown = true;

        // curl: first fold in the amounts from already-completed transfers.
        add_offt(&mut all_dlnow, self.all_dlalready);
        add_offt(&mut all_ulnow, self.all_ulalready);

        // curl: `for(per = transfers; per; per = per->next) { ... }`
        for per in transfers {
            add_offt(&mut all_dlnow, per.dlnow.get());
            add_offt(&mut all_ulnow, per.ulnow.get());
            if per.dltotal.get() == 0 {
                dlknown = false;
            } else if !per.dltotal_added.get() {
                // Only add each transfer's total once.
                add_offt(&mut self.all_dltotal, per.dltotal.get());
                per.dltotal_added.set(true);
            }
            if per.ultotal.get() == 0 {
                ulknown = false;
            } else if !per.ultotal_added.get() {
                add_offt(&mut self.all_ultotal, per.ultotal.get());
                per.ultotal_added.set(true);
            }
        }

        // curl: `if(dlknown && all_dltotal) snprintf(dlpercen, 4, "%3lld", ...);`
        // The percentage uses a scaled division when `all_dlnow` is large enough that
        // `all_dlnow * 100` could overflow, exactly as curl does.
        if dlknown && self.all_dltotal != 0 {
            dlpercen = format_percent(all_dlnow, self.all_dltotal);
        }
        if ulknown && self.all_ultotal != 0 {
            ulpercen = format_percent(all_ulnow, self.all_ultotal);
        }

        // curl: store the current cumulative totals into the speed ring buffer, then advance.
        let i = self.speedindex;
        self.speedstore[i] = SpeedCount {
            dl: all_dlnow,
            ul: all_ulnow,
            stamp: Some(now),
        };
        self.speedindex += 1;
        if self.speedindex >= SPEEDCNT {
            self.indexwrapped = true;
            self.speedindex = 0;
        }

        // curl: derive the speed as the higher of the download/upload rates over the window.
        let speed = self.window_speed(now, start, all_dlnow, all_ulnow);

        // curl: total/remaining times need a non-zero, known-download speed to be meaningful.
        let (time_left, time_total) = if dlknown && speed != 0 {
            let est = self.all_dltotal / speed;
            let left = (self.all_dltotal - all_dlnow) / speed;
            (time2str(left), time2str(est))
        } else {
            (time2str(0), time2str(0))
        };
        let time_spent = time2str(spent);

        // curl: `curl_mfprintf(tool_stderr, "\r%-3s %-3s %s %s %5lld %5lld  %s %s %s %s %5s", ...)`
        // Everything up to (but excluding) the final "%5s" tail is the fixed column body, in
        // curl's exact order/widths/spacing. `max5data` fields are already five columns wide
        // and `time2str` fields eight, so they use `{}` (no extra width), matching C's `%s`.
        let dled = max5data(all_dlnow);
        let uled = max5data(all_ulnow);
        let speed_str = max5data(speed);
        let body = format!(
            "\r{dlpercen:<3} {ulpercen:<3} {dled} {uled} {xfers_added:5} {xfers_running:5}  \
             {time_total} {time_spent} {time_left} {speed_str} "
        );

        // Size the transient line to the terminal width by extending the trailing spaces so a
        // redraw clears any residue; never truncate the fixed layout. The final line ends with
        // a newline so the summary is left intact on its own line.
        let visible = body.len().saturating_sub(1); // exclude the leading '\r' (all ASCII).
        let cols = get_terminal_columns() as usize;
        let pad = cols.saturating_sub(visible);
        let mut line = body;
        line.extend(std::iter::repeat(' ').take(pad));
        if show_final {
            line.push('\n');
        }

        let _ = std::io::stderr().write_all(line.as_bytes());
        let _ = std::io::stderr().flush();
        true
    }

    /// Fold a finished transfer's final numbers into the meter's carry-over totals, just
    /// before that transfer is dropped.
    ///
    /// Faithful port of curl's `progress_finalize()` (`src/tool_progress.c`): the transfer's
    /// last `dlnow`/`ulnow` are accumulated into the "already finished" carry-over so they keep
    /// counting toward the aggregate after the live record goes away, and its declared totals
    /// are folded into the grand totals if they were not already added during a
    /// [`Self::progress_meter`] pass.
    pub fn progress_finalize(&mut self, per: &TransferProgress) {
        // curl: capture the numbers before this transfer goes away.
        add_offt(&mut self.all_dlalready, per.dlnow.get());
        add_offt(&mut self.all_ulalready, per.ulnow.get());
        if !per.dltotal_added.get() {
            add_offt(&mut self.all_dltotal, per.dltotal.get());
            per.dltotal_added.set(true);
        }
        if !per.ultotal_added.get() {
            add_offt(&mut self.all_ultotal, per.ultotal.get());
            per.ultotal_added.set(true);
        }
    }

    /// Compute the displayed speed (bytes/second) as the higher of the download and upload
    /// rates measured over the rolling sample window, mirroring curl's speed block.
    ///
    /// When the ring has wrapped the window spans from the oldest retained sample to `now`;
    /// otherwise it spans from the transfer `start`. A zero-length window is bumped to 1 ms to
    /// avoid a divide-by-zero, exactly as curl's `if(!deltams) deltams++;` does.
    fn window_speed(&self, now: Instant, start: Instant, all_dlnow: i64, all_ulnow: i64) -> i64 {
        let (deltams_raw, dl, ul) = if self.indexwrapped {
            // `speedindex` now points at the oldest (about-to-be-overwritten) sample.
            let oldest = self.speedstore[self.speedindex];
            let stamp = oldest.stamp.unwrap_or(start);
            (
                elapsed_ms(now, stamp),
                all_dlnow - oldest.dl,
                all_ulnow - oldest.ul,
            )
        } else {
            (elapsed_ms(now, start), all_dlnow, all_ulnow)
        };
        // curl: `if(!deltams) deltams++;`
        let deltams = if deltams_raw == 0 { 1 } else { deltams_raw };
        let seconds = deltams as f64 / 1000.0;
        let dls = (dl as f64 / seconds) as i64;
        let uls = (ul as f64 / seconds) as i64;
        // curl: `speed = dls > uls ? dls : uls;`
        dls.max(uls)
    }
}

/// Milliseconds elapsed from `earlier` to `now`, clamped at `0` if `now` precedes `earlier`.
///
/// The Rust analogue of curl's `curlx_timediff_ms(now, earlier)` for the monotonic
/// [`Instant`] clock. [`Instant::saturating_duration_since`] guarantees a non-negative result,
/// and the millisecond count comfortably fits in `i64` for any realistic transfer duration.
#[inline]
fn elapsed_ms(now: Instant, earlier: Instant) -> i64 {
    now.saturating_duration_since(earlier).as_millis() as i64
}

/// Format a completion percentage into curl's three-column `"%3lld"` field.
///
/// Reproduces the exact percentage arithmetic from `progress_meter()`: when `now` is small
/// enough that `now * 100` cannot overflow it uses `now * 100 / total`; otherwise it scales
/// down first with `now / (total / 100)`. curl writes this through `snprintf` into a
/// four-byte buffer, so at most three characters survive — reproduced here by truncating to
/// three characters (only reachable for the pathological `>= 1000%` case).
fn format_percent(now: i64, total: i64) -> String {
    let pct = if now < i64::MAX / 100 {
        now * 100 / total
    } else {
        now / (total / 100)
    };
    let mut s = format!("{pct:3}");
    if s.len() > 3 {
        s.truncate(3);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`max5data`] must reproduce curl's `max5data()` byte-for-byte. The expected strings were
    /// produced by an oracle mirroring the C integer arithmetic; this is the `UNITTEST`-marked
    /// parity check from `src/tool_progress.c`.
    #[test]
    fn max5data_matches_curl() {
        // Raw branch: `bytes < 100000` → right-justified in five columns ("%5d").
        assert_eq!(max5data(0), "    0");
        assert_eq!(max5data(1), "    1");
        assert_eq!(max5data(42), "   42");
        assert_eq!(max5data(999), "  999");
        assert_eq!(max5data(1000), " 1000");
        assert_eq!(max5data(99999), "99999");

        // One-decimal branch (nbytes < 100): "%2d.%d%c".
        assert_eq!(max5data(100_000), "97.6k");
        assert_eq!(max5data(102_300), "99.9k");
        assert_eq!(max5data(10_485_760), "10.0M");

        // No-decimal branch (nbytes < 10000): "%4d%c".
        assert_eq!(max5data(102_400), " 100k");
        assert_eq!(max5data(1_048_576), "1024k");
        assert_eq!(max5data(1_073_741_824), "1024M");
        assert_eq!(max5data(1_099_511_627_776), "1024G");

        // The suffix ladder walks all the way to 'P' for the largest 64-bit value.
        assert_eq!(max5data(i64::MAX), "8191P");
    }

    /// Every [`max5data`] result is exactly five characters wide, across each branch and unit.
    #[test]
    fn max5data_is_five_columns() {
        let samples = [
            0i64,
            1,
            12_345,
            99_999,
            100_000,
            102_400,
            999_999,
            1_048_576,
            1_073_741_824,
            1_099_511_627_776,
            1_125_899_906_842_624,
            i64::MAX,
        ];
        for b in samples {
            let s = max5data(b);
            assert_eq!(
                s.chars().count(),
                5,
                "max5data({b}) = {s:?} is not 5 columns"
            );
        }
    }

    /// [`time2str`] must reproduce curl's `time2str()` byte-for-byte (the second `UNITTEST`
    /// parity check from `src/tool_progress.c`).
    #[test]
    fn time2str_matches_curl() {
        // Non-positive → eight spaces.
        assert_eq!(time2str(0), "        ");
        assert_eq!(time2str(-5), "        ");

        // HH:MM:SS while hours ≤ 99.
        assert_eq!(time2str(1), "00:00:01");
        assert_eq!(time2str(59), "00:00:59");
        assert_eq!(time2str(60), "00:01:00");
        assert_eq!(time2str(61), "00:01:01");
        assert_eq!(time2str(3599), "00:59:59");
        assert_eq!(time2str(3600), "01:00:00");
        assert_eq!(time2str(3661), "01:01:01");
        assert_eq!(time2str(86_399), "23:59:59");
        assert_eq!(time2str(86_400), "24:00:00");
        assert_eq!(time2str(90_000), "25:00:00");
        assert_eq!(time2str(359_999), "99:59:59");

        // Days: "%3dd %02dh".
        assert_eq!(time2str(360_000), "  4d 04h");
        assert_eq!(time2str(86_331_600), "999d 05h");

        // Months: "%3dm %02dd".
        assert_eq!(time2str(86_400_000), " 33m 10d");
        assert_eq!(time2str(103_680_000), " 40m 00d");

        // Years: "%7dy", then the clamp.
        assert_eq!(time2str(86_400_000_000), "   2739y");
        assert_eq!(time2str(3_153_600_000_000), " >99999y");
    }

    /// Every [`time2str`] result is exactly eight characters wide, across each layout branch.
    #[test]
    fn time2str_is_eight_columns() {
        let samples = [
            0i64,
            -1,
            1,
            3661,
            359_999,
            360_000,
            86_331_600,
            86_400_000,
            86_400_000_000,
            3_153_600_000_000,
            i64::MAX,
        ];
        for s in samples {
            let out = time2str(s);
            assert_eq!(
                out.chars().count(),
                8,
                "time2str({s}) = {out:?} is not 8 columns"
            );
        }
    }

    /// [`add_offt`] adds normally and saturates at [`i64::MAX`] rather than overflowing.
    #[test]
    fn add_offt_saturates() {
        let mut v = 0i64;
        add_offt(&mut v, 10);
        add_offt(&mut v, 5);
        assert_eq!(v, 15);

        // Saturation: MAX-1 plus 10 pins at MAX (never wraps).
        let mut v = i64::MAX - 1;
        add_offt(&mut v, 10);
        assert_eq!(v, i64::MAX);

        // Exact boundary: MAX + 0 stays MAX.
        let mut v = i64::MAX;
        add_offt(&mut v, 0);
        assert_eq!(v, i64::MAX);
    }

    /// [`format_percent`] reproduces curl's `"%3lld"` percentage field.
    #[test]
    fn format_percent_matches_curl() {
        assert_eq!(format_percent(0, 100), "  0");
        assert_eq!(format_percent(6, 100), "  6");
        assert_eq!(format_percent(50, 200), " 25");
        assert_eq!(format_percent(100, 100), "100");
        assert_eq!(format_percent(999, 1000), " 99");
        // The large-`now` scaled path stays within three columns and never divides by zero
        // (the grand total always dominates `now`).
        let s = format_percent(i64::MAX, i64::MAX);
        assert_eq!(s.chars().count(), 3);
    }

    /// [`xferinfo_cb`] records the four counters and reports "continue" (0) in the common case.
    #[test]
    fn xferinfo_cb_records_and_continues() {
        let per = TransferProgress::new();
        let rc = xferinfo_cb(&per, 1000, 250, 500, 100);
        assert_eq!(rc, 0);
        assert_eq!(per.dltotal(), 1000);
        assert_eq!(per.dlnow(), 250);
        assert_eq!(per.ultotal(), 500);
        assert_eq!(per.ulnow(), 100);
        // No resume was requested because the transfer was not read-paused.
        assert!(!per.take_resume_requested());
    }

    /// [`xferinfo_cb`] returns 1 (abort) when the transfer has been flagged for abort, while
    /// still recording the freshest counters.
    #[test]
    fn xferinfo_cb_aborts() {
        let per = TransferProgress::new();
        per.set_abort(true);
        assert!(per.is_aborting());
        let rc = xferinfo_cb(&per, 10, 5, 0, 0);
        assert_eq!(rc, 1);
        assert_eq!(per.dlnow(), 5);
    }

    /// [`xferinfo_cb`] clears a read-paused flag and requests exactly one resume.
    #[test]
    fn xferinfo_cb_resume_on_readbusy() {
        let per = TransferProgress::new();
        per.set_readbusy();
        let rc = xferinfo_cb(&per, 0, 0, 0, 0);
        assert_eq!(rc, 0);
        // The resume request is raised once and then consumed.
        assert!(per.take_resume_requested());
        assert!(!per.take_resume_requested());
    }

    /// [`ProgressMeter::progress_finalize`] folds a finished transfer's numbers into the
    /// carry-over and grand totals, marking its totals as added.
    #[test]
    fn progress_finalize_accumulates() {
        let mut meter = ProgressMeter::new();
        let per = TransferProgress::new();
        per.record(1000, 100, 500, 50); // dltotal, dlnow, ultotal, ulnow

        meter.progress_finalize(&per);

        assert_eq!(meter.all_dlalready, 100);
        assert_eq!(meter.all_ulalready, 50);
        assert_eq!(meter.all_dltotal, 1000);
        assert_eq!(meter.all_ultotal, 500);
        assert!(per.dltotal_added.get());
        assert!(per.ultotal_added.get());

        // A second finalize of the same record adds the now-current bytes again to the
        // carry-over but does not double-count the (already-added) totals.
        meter.progress_finalize(&per);
        assert_eq!(meter.all_dlalready, 200);
        assert_eq!(meter.all_dltotal, 1000);
    }

    /// The meter emits nothing and returns `false` whenever progress output is suppressed via
    /// `--no-progress-meter` (`noprogress`) or `--silent` (`silent`), even for the final line.
    #[test]
    fn progress_meter_suppressed_when_silent_or_noprogress() {
        let mut meter = ProgressMeter::new();
        let start = Instant::now();

        let mut g = GlobalConfig::new();
        g.noprogress = true;
        assert!(!meter.progress_meter(&g, start, &[], 0, 0, true));

        let mut g = GlobalConfig::new();
        g.silent = true;
        assert!(!meter.progress_meter(&g, start, &[], 0, 0, true));
    }

    /// The refresh throttle draws on the first call and on the final call, but skips an
    /// immediate intermediate call (< 500 ms elapsed). Output goes to stderr; here we assert
    /// only the return value that signals whether a line was drawn.
    #[test]
    fn progress_meter_throttles_and_finalizes() {
        let mut meter = ProgressMeter::new();
        let g = GlobalConfig::new();
        let start = Instant::now();
        let a = TransferProgress::new();
        a.record(2000, 500, 0, 0);
        let transfers: [&TransferProgress; 1] = [&a];

        // First call always draws (curl's stamp starts at zero → effectively infinite delta).
        assert!(meter.progress_meter(&g, start, &transfers, 1, 1, false));
        // An immediate, non-final follow-up is throttled out.
        assert!(!meter.progress_meter(&g, start, &transfers, 1, 1, false));
        // The final call always draws the summary line.
        assert!(meter.progress_meter(&g, start, &transfers, 1, 1, true));
    }
}
