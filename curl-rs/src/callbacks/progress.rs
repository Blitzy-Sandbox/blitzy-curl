// curl-rs — CLI progress-bar callback (`-#` / `--progress-bar`).
//
// SPDX-License-Identifier: curl
//
// This module is the memory-safe Rust port of curl's `src/tool_cb_prg.c`
// (238 LoC). The original C source is
//   Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// and is licensed under the curl license (https://curl.se/docs/copyright.html).
//
// It implements ONLY the `--progress-bar` (`-#`) variant of curl's progress
// reporting: the `CURLOPT_XFERINFOFUNCTION` callback `tool_progress_cb`, the
// `progressbarinit` initializer, the private `fly` knight-rider animation and
// `update_width` helpers, and the static `sinus[]` table that drives the
// animation. It OWNS the [`ProgressData`] struct (the Rust analog of
// `struct ProgressData` from `src/tool_cb_prg.h`), which is re-exported by the
// `callbacks` module and embedded as the `progressbar` field of
// `crate::operate::PerTransfer`.
//
// Division of labor (AAP §0.5.1): the *default* (non-`-#`) progress meter and
// the parallel-transfer aggregate meter live in curl's `tool_progress.c`, which
// maps to `crate::operate` — NOT here. This module is strictly the
// `tool_cb_prg.c` `-#` bar.
//
// The C source is consumed as a behavioral oracle, not transliterated: the
// fixed-size C `char buf[]` scratch becomes a stack array sliced to the visible
// width, `struct curltime` becomes [`std::time::Instant`], `FILE *out` becomes
// the [`ProgressOut`] sink, and the manual `memset`/`memcpy` byte twiddling
// becomes safe slice operations. No `unsafe` is used. The animation is pure
// `i32` arithmetic over the fixed `SINUS` table; the integer divisions and the
// `width - 6` / `width - 7` offsets are reproduced exactly so the `-#` frames
// stay byte-for-byte identical to curl 8.x (AAP §0.8.2 wire/behavioral parity).

//! The `-#` / `--progress-bar` transfer callback.
//!
//! curl's `-#` flag swaps the default percentage/speed meter for a compact
//! progress *bar*. This module is the parity-faithful port of
//! `src/tool_cb_prg.c`:
//!
//! * [`ProgressData`] — the per-transfer bar state (`struct ProgressData`).
//! * [`tool_progress_cb`] — the `CURLOPT_XFERINFOFUNCTION` callback that renders
//!   a frame on each progress tick (throttled to 10 Hz).
//! * [`progressbarinit`] — resets the bar state at the start of a transfer,
//!   threading `--continue-at`/resume through so the bar reflects progress
//!   toward the *whole* file.
//!
//! When the total transfer size is known the bar is *determinate* — a row of
//! `#` characters plus a right-hand percentage. When the size is unknown the bar
//! is *indeterminate* — a "knight-rider" `-=O=-` glider with four bouncing `#`
//! markers, animated from the precomputed [`SINUS`] table.
//!
//! # Output
//!
//! The bar is always written to **stderr** (curl's `tool_stderr`), modeled by
//! [`ProgressOut`]. Frames are emitted as raw bytes and flushed immediately so
//! the carriage-return (`\r`) overwrites work; no line buffering is applied.
//!
//! # Dependencies
//!
//! This module depends only on [`std`] and `curl_rs_lib` (for
//! [`curl_rs_lib::easy::CURLPAUSE_CONT`], used to unpause a read-busy transfer),
//! plus the sibling [`crate::config`] and [`crate::operate`] types it is handed.
//! It links no C library and contains no `unsafe` (AAP §0.7.1 / §0.8.2).

use std::io::Write;
use std::time::Instant;

use curl_rs_lib::easy::CURLPAUSE_CONT;

use crate::config::OperationConfig;
use crate::operate::PerTransfer;

// ===========================================================================
// Constants
// ===========================================================================

/// Maximum bar width in columns (`#define MAX_BARLENGTH 400`,
/// `src/tool_cb_prg.c:31`). `update_width` clamps the terminal width to this.
const MAX_BARLENGTH: i32 = 400;

/// Minimum bar width in columns (`#define MIN_BARLENGTH 20`,
/// `src/tool_cb_prg.c:32`).
const MIN_BARLENGTH: i32 = 20;

/// Size of the scratch frame buffer, mirroring C's `char buf[MAX_BARLENGTH + 2]`
/// (`src/tool_cb_prg.c:69`): one byte for the leading `\r`, up to
/// `MAX_BARLENGTH` content columns, and one byte for C's terminating NUL. Only
/// the first `width + 1` bytes are ever emitted, but allocating the full size
/// (exactly as C does) means a glider/marker that lands in the tail — possible
/// when the terminal shrank since the previous frame — is a harmless scratch
/// write rather than an out-of-bounds panic, reproducing C's behavior where
/// `fputs` simply stops at the NUL.
const BAR_BUF_LEN: usize = MAX_BARLENGTH as usize + 2;

// --- terminal-width detection (mirrors `src/terminal.c get_terminal_columns`) -

/// Smallest `COLUMNS` value curl honors: `get_terminal_columns` keeps the parsed
/// value only when `num > 20` (`src/terminal.c`). Values at or below this fall
/// back to [`DEFAULT_TERMINAL_COLUMNS`].
const MIN_COLUMNS: i32 = 20;

/// Largest `COLUMNS` value curl accepts, the `max` passed to
/// `curlx_str_number(&p, &num, 10000)` in `get_terminal_columns`
/// (`src/terminal.c`); larger values are rejected as overflow.
const MAX_COLUMNS: i32 = 10_000;

/// Width curl returns when the terminal size is unknown — `get_terminal_columns`
/// returns `79` on failure (`src/terminal.c`). curl's `ioctl(TIOCGWINSZ)`
/// auto-detection is intentionally not reproduced here: it requires `unsafe`,
/// which this crate forbids, and in the (non-tty) environment the test harness
/// runs in curl's own detection also fails and returns `79`, so the determinate
/// bar's cosmetic width stays identical where parity is observable. This matches
/// the existing `crate::messages` terminal-width fallback (also `79`).
const DEFAULT_TERMINAL_COLUMNS: i32 = 79;

// ===========================================================================
// The `sinus[]` table (transcribed verbatim from `src/tool_cb_prg.c:41-65`).
//
// 200 values generated by curl's perl one-liner:
//   foreach my $i (1 .. 200) { sin($i / 200 * 2 * $pi) * 500000 + 500000 }
// The `fly` animation indexes this table modulo 200; any deviation in a single
// value desynchronizes the `-#` knight-rider animation, so it MUST stay
// byte-for-byte identical to the C source.
// ===========================================================================

/// Precomputed half-sine lookup table driving the [`fly`] knight-rider
/// animation. Transcribed verbatim from `src/tool_cb_prg.c`.
///
/// The 9-values-per-row layout is preserved with `#[rustfmt::skip]` so it mirrors
/// the grouping in the C source (`src/tool_cb_prg.c:42-64`), keeping the table
/// easy to re-verify line-by-line against the oracle. Line wrapping is cosmetic:
/// the 200 values — and therefore the animation — are identical regardless.
#[rustfmt::skip]
static SINUS: [i32; 200] = [
    515704, 531394, 547052, 562664, 578214, 593687, 609068, 624341, 639491,
    654504, 669364, 684057, 698568, 712883, 726989, 740870, 754513, 767906,
    781034, 793885, 806445, 818704, 830647, 842265, 853545, 864476, 875047,
    885248, 895069, 904500, 913532, 922156, 930363, 938145, 945495, 952406,
    958870, 964881, 970434, 975522, 980141, 984286, 987954, 991139, 993840,
    996054, 997778, 999011, 999752, 999999, 999754, 999014, 997783, 996060,
    993848, 991148, 987964, 984298, 980154, 975536, 970449, 964898, 958888,
    952426, 945516, 938168, 930386, 922180, 913558, 904527, 895097, 885277,
    875077, 864507, 853577, 842299, 830682, 818739, 806482, 793922, 781072,
    767945, 754553, 740910, 727030, 712925, 698610, 684100, 669407, 654548,
    639536, 624386, 609113, 593733, 578260, 562710, 547098, 531440, 515751,
    500046, 484341, 468651, 452993, 437381, 421830, 406357, 390976, 375703,
    360552, 345539, 330679, 315985, 301474, 287158, 273052, 259170, 245525,
    232132, 219003, 206152, 193590, 181331, 169386, 157768, 146487, 135555,
    124983, 114781, 104959, 95526,  86493,  77868,  69660,  61876,  54525,
    47613,  41147,  35135,  29581,  24491,  19871,  15724,  12056,  8868,
    6166,   3951,   2225,   990,    248,    0,      244,    982,    2212,
    3933,   6144,   8842,   12025,  15690,  19832,  24448,  29534,  35084,
    41092,  47554,  54462,  61809,  69589,  77794,  86415,  95445,  104873,
    114692, 124891, 135460, 146389, 157667, 169282, 181224, 193480, 206039,
    218888, 232015, 245406, 259048, 272928, 287032, 301346, 315856, 330548,
    345407, 360419, 375568, 390841, 406221, 421693, 437243, 452854, 468513,
    484202, 499907,
];

// ===========================================================================
// ProgressOut — the bar's output sink (curl's `FILE *out`, always `tool_stderr`)
// ===========================================================================

/// Where the progress bar writes its frames.
///
/// curl's `struct ProgressData` holds a `FILE *out` that `progressbarinit`
/// always sets to `tool_stderr`. Modeling it as an enum keeps the production
/// path (stderr) while letting tests capture frames into an in-memory buffer for
/// byte-exact parity assertions. Frames are written as raw bytes and flushed
/// immediately so the carriage-return overwrite behaves like curl's
/// `fputs`/`fflush` (no line buffering).
#[derive(Debug, Default)]
pub enum ProgressOut {
    /// Write frames to the process's standard error stream (curl `tool_stderr`).
    #[default]
    Stderr,
    /// Capture frames in memory — used by this module's tests to assert the
    /// exact bytes a frame produces. Compiled only under `cfg(test)` so the
    /// shipped binary's sink is honestly stderr-only.
    #[cfg(test)]
    Buffer(Vec<u8>),
}

impl ProgressOut {
    /// Writes a complete frame (raw bytes) to the sink. Errors are ignored, as
    /// curl ignores the return of `fputs`/`curl_mfprintf` when drawing the bar.
    fn write_all(&mut self, buf: &[u8]) {
        match self {
            ProgressOut::Stderr => {
                let _ = std::io::stderr().write_all(buf);
            }
            #[cfg(test)]
            ProgressOut::Buffer(v) => v.extend_from_slice(buf),
        }
    }

    /// Flushes the sink, mirroring C's `fflush(bar->out)` so each `\r`-prefixed
    /// frame is visible immediately. The in-memory buffer needs no flush.
    fn flush(&mut self) {
        match self {
            ProgressOut::Stderr => {
                let _ = std::io::stderr().flush();
            }
            #[cfg(test)]
            ProgressOut::Buffer(_) => {}
        }
    }
}

// ===========================================================================
// ProgressData — the per-transfer `-#` bar state (C `struct ProgressData`)
// ===========================================================================

/// Per-transfer state for the `-#` / `--progress-bar` meter — the Rust analog of
/// `struct ProgressData` (`src/tool_cb_prg.h`).
///
/// Fields map one-to-one onto the C struct (with C's `FILE *out` modeled by
/// [`ProgressOut`] and `struct curltime prevtime` by [`Instant`]). It is
/// embedded unchanged as the `progressbar` field of `crate::operate::PerTransfer`
/// and reset by [`progressbarinit`] at the start of each transfer.
#[derive(Debug)]
pub struct ProgressData {
    /// Number of times the callback has fired (`bar->calls`). Zero means the bar
    /// has not drawn yet; the driver checks `calls > 0` to decide whether a
    /// closing newline is needed after the transfer.
    pub calls: i32,
    /// Previous absolute progress point used to render the last frame
    /// (`bar->prev`).
    pub prev: i64,
    /// Timestamp of the last drawn frame (`bar->prevtime`), used for the 10 Hz
    /// update throttle.
    pub prevtime: Instant,
    /// Current bar width in columns (`bar->width`), set by [`update_width`] and
    /// clamped to `[MIN_BARLENGTH, MAX_BARLENGTH]`.
    pub width: i32,
    /// The output sink (`bar->out`), always stderr in production.
    pub out: ProgressOut,
    /// Resume offset for `--continue-at` transfers (`bar->initial_size`); lets
    /// the bar show progress toward the whole file. Negative means "size to be
    /// learned from the remote".
    pub initial_size: i64,
    /// Animation phase for the indeterminate knight-rider (`bar->tick`), an index
    /// into [`SINUS`] advanced by 2 each frame.
    pub tick: u32,
    /// Current position of the `-=O=-` glider (`bar->bar`) within the bar.
    pub bar: i32,
    /// Glider travel direction (`bar->barmove`): `+1` rightward, `-1` leftward.
    pub barmove: i32,
}

impl Default for ProgressData {
    /// Zero-initializes every counter (mirroring C's `memset(bar, 0, ...)` in
    /// `progressbarinit`) and seeds `prevtime` with [`Instant::now`]. The real
    /// per-transfer initialization is done by [`progressbarinit`].
    fn default() -> Self {
        ProgressData {
            calls: 0,
            prev: 0,
            prevtime: Instant::now(),
            width: 0,
            out: ProgressOut::Stderr,
            initial_size: 0,
            tick: 0,
            bar: 0,
            barmove: 0,
        }
    }
}

// ===========================================================================
// Terminal-width detection (port of `src/terminal.c get_terminal_columns`)
// ===========================================================================

/// Returns the terminal width in columns, mirroring curl's
/// `get_terminal_columns()` (`src/terminal.c`).
///
/// curl reads the `COLUMNS` environment variable and, when it parses to a number
/// greater than 20 (and not larger than 10000), uses it. Otherwise it consults
/// `ioctl(TIOCGWINSZ)` and finally falls back to 79. The `ioctl` step is
/// deliberately omitted here — it requires `unsafe`, which this crate forbids,
/// and `curl_rs_lib` exposes no safe terminal-size helper — so an unset/invalid
/// `COLUMNS` falls straight through to [`DEFAULT_TERMINAL_COLUMNS`] (`79`),
/// exactly as curl's own detection does in the non-tty environment the parity
/// test harness runs in.
fn get_terminal_columns() -> i32 {
    if let Ok(columns) = std::env::var("COLUMNS") {
        if let Some(num) = parse_columns(&columns) {
            // curl honors the value only when it exceeds 20.
            if num > MIN_COLUMNS {
                return num;
            }
        }
    }
    DEFAULT_TERMINAL_COLUMNS
}

/// Parses a `COLUMNS` value the way curl's `curlx_str_number(&p, &num, 10000)`
/// does (`src/terminal.c` → `lib/curlx/strparse.c`): read a leading run of
/// base-10 digits, stopping at the first non-digit. Returns [`None`] (so the
/// caller falls back to the default) when there is no leading digit or when the
/// value would exceed [`MAX_COLUMNS`] (curl's overflow rejection against
/// `max == 10000`). The `> 20` acceptance check is applied by the caller, to
/// match curl's two-step `(!error) && (num > 20)` logic. This mirrors the
/// existing `crate::messages` COLUMNS parser.
fn parse_columns(s: &str) -> Option<i32> {
    let bytes = s.as_bytes();
    // curl requires the first character to be a digit (`STRE_NO_NUM` otherwise).
    if bytes.is_empty() || !bytes[0].is_ascii_digit() {
        return None;
    }

    let mut num: i32 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            break; // stop at the first non-digit, like curl
        }
        num = num * 10 + i32::from(b - b'0');
        if num > MAX_COLUMNS {
            return None; // curl rejects values past `max`
        }
    }
    Some(num)
}

/// Recomputes [`ProgressData::width`] from the current terminal width, clamped to
/// `[MIN_BARLENGTH, MAX_BARLENGTH]` (port of `update_width`,
/// `src/tool_cb_prg.c:110-119`).
fn update_width(bar: &mut ProgressData) {
    let cols = get_terminal_columns();
    bar.width = if cols > MAX_BARLENGTH {
        MAX_BARLENGTH
    } else if cols > MIN_BARLENGTH {
        cols
    } else {
        MIN_BARLENGTH
    };
}

// ===========================================================================
// Small arithmetic helpers
// ===========================================================================

/// Milliseconds elapsed from `earlier` to `now` (port of `curlx_timediff_ms`).
///
/// Uses [`Instant::saturating_duration_since`] so a non-monotonic reading can
/// never panic; the result is clamped at zero in that case, which the 10 Hz
/// throttle treats as "no time has passed" (a frame is then allowed).
fn timediff_ms(now: Instant, earlier: Instant) -> i64 {
    // `as_millis()` is u128; transfer durations are tiny relative to i64::MAX.
    now.saturating_duration_since(earlier).as_millis() as i64
}

/// Computes a saturating `value_a + value_b (+ initial_size)`, reproducing the
/// total/point arithmetic in `tool_progress_cb` (`src/tool_cb_prg.c:132-156`).
///
/// `initial_size < 0` means the size is to be learned from the remote: the sum
/// of `value_a + value_b` is reported only once the corresponding *totals*
/// (`cond_a`/`cond_b`) are known, otherwise the result is `i64::MAX`
/// (C's `CURL_OFF_T_MAX`, the "unknown/unbounded" sentinel). When `initial_size`
/// is known (`>= 0`) the resume offset is added, saturating to `i64::MAX` on
/// overflow exactly as C's explicit overflow guard does — `saturating_add` keeps
/// the C intent while avoiding Rust's debug-mode overflow panic.
///
/// Note the deliberate split between the *condition* operands and the *value*
/// operands: for `point`, C gates on `dltotal || ultotal` (the totals) but sums
/// `dlnow + ulnow` (the current counts), so the two operand pairs differ.
fn accumulate(initial_size: i64, cond_a: i64, cond_b: i64, value_a: i64, value_b: i64) -> i64 {
    if initial_size < 0 {
        if cond_a != 0 || cond_b != 0 {
            value_a.saturating_add(value_b)
        } else {
            i64::MAX
        }
    } else {
        let sum = value_a.saturating_add(value_b);
        // `i64::MAX - initial_size` cannot underflow here (initial_size >= 0).
        if (i64::MAX - initial_size) < sum {
            i64::MAX
        } else {
            sum.saturating_add(initial_size)
        }
    }
}

// ===========================================================================
// Frame builders (pure — separated from I/O so they can be parity-tested)
// ===========================================================================

/// Builds one indeterminate "knight-rider" frame into a fixed-size scratch
/// buffer, reproducing the byte layout of `fly` (`src/tool_cb_prg.c:67-90`).
///
/// The returned array is [`BAR_BUF_LEN`] bytes (matching C's
/// `char buf[MAX_BARLENGTH + 2]`); the caller emits only the first `width + 1`
/// bytes. Index 0 is the carriage return; indices `1..=width` are the visible
/// columns (spaces by default). The five-byte `-=O=-` glider is placed at
/// `bar_pos + 1`, then four `#` markers are placed at positions derived from the
/// [`SINUS`] table — using the exact same `i32` integer division as C
/// (`sinus[(tick + k) % 200] / (1_000_000 / (width - 2)) + 1`) so rounding
/// matches bit-for-bit.
fn fly_frame(width: i32, bar_pos: i32, tick: u32) -> [u8; BAR_BUF_LEN] {
    // `check` is the usable inner span; `width >= MIN_BARLENGTH` (20) is an
    // invariant guaranteed by `update_width` running before every `fly`, so
    // `check >= 18 > 0` and the division below can never divide by zero.
    let check = width - 2;
    debug_assert!(
        width <= MAX_BARLENGTH,
        "width is range-checked by update_width"
    );
    debug_assert!(
        check > 0,
        "width >= MIN_BARLENGTH guarantees a positive divisor"
    );

    let mut buf = [b' '; BAR_BUF_LEN];
    buf[0] = b'\r';

    // The glider: 5 bytes at offset bar_pos + 1 (C `memcpy(&buf[bar+1], "-=O=-", 5)`).
    let start = (bar_pos + 1) as usize;
    buf[start..start + 5].copy_from_slice(b"-=O=-");

    // Four `#` markers, sampled from the sine table 5 ticks apart. The markers
    // are written AFTER the glider, so a marker may overwrite a glider byte —
    // identical to C's ordering.
    for k in [0u32, 5, 10, 15] {
        let idx = ((tick + k) % 200) as usize;
        let pos = (SINUS[idx] / (1_000_000 / check) + 1) as usize;
        buf[pos] = b'#';
    }

    buf
}

/// Builds the determinate bar line, reproducing the formatting of
/// `tool_progress_cb` (`src/tool_cb_prg.c:183-210`).
///
/// C composes a format string `"\r%-{barwidth}s %5.1f%%"` and prints a row of
/// `#` characters left-justified in a `barwidth = width - 7` field, a space, the
/// percentage with `%5.1f` (width 5, one decimal), and a literal `%`. The Rust
/// equivalent `"\r{line:<barwidth} {percent:5.1}%"` produces the identical byte
/// sequence. When `point` exceeds `total` (more than expected was received) the
/// total is bumped to `point` so the fraction caps at `1.0`, exactly as C does.
fn determinate_line(width: i32, point: i64, total: i64) -> String {
    // C: if(point > total) total = point;  — cap the fraction at 100%.
    let total = if point > total { point } else { total };

    let frac = point as f64 / total as f64;
    let percent = frac * 100.0;
    let barwidth = width - 7;

    // C: num = (size_t)((double)barwidth * frac); if(num > MAX_BARLENGTH) num = MAX_BARLENGTH;
    let mut num = (barwidth as f64 * frac) as i64;
    if num > MAX_BARLENGTH as i64 {
        num = MAX_BARLENGTH as i64;
    }
    let num = num.max(0) as usize;

    let line = "#".repeat(num);
    let bw = barwidth.max(0) as usize;
    // `\r` + `line` left-justified in `bw` columns + ` ` + `%5.1f` percent + `%`.
    format!("\r{line:<bw$} {percent:5.1}%")
}

// ===========================================================================
// fly — render + advance one knight-rider frame (C `fly`, src/tool_cb_prg.c:67)
// ===========================================================================

/// Emits one indeterminate animation frame and advances the animation state.
///
/// `moved` is true when real progress occurred since the previous frame; only
/// then does the glider move. After drawing, the tick advances by 2 (wrapping at
/// 200) and the glider position is stepped by `barmove` and bounced off the
/// `[0, width - 6]` bounds, flipping `barmove` at each end — all exactly as
/// `src/tool_cb_prg.c:90-103`.
fn fly(bar: &mut ProgressData, moved: bool) {
    let frame = fly_frame(bar.width, bar.bar, bar.tick);
    // Emit `\r` + the `width` visible columns (indices 0..=width).
    let visible = bar.width as usize + 1;
    bar.out.write_all(&frame[..visible]);

    // Advance the animation phase (C: bar->tick += 2; wrap at 200).
    bar.tick += 2;
    if bar.tick >= 200 {
        bar.tick -= 200;
    }

    // Step and bounce the glider (C: bar->bar += moved ? barmove : 0; clamp).
    bar.bar += if moved { bar.barmove } else { 0 };
    if bar.bar >= bar.width - 6 {
        bar.barmove = -1;
        bar.bar = bar.width - 6;
    } else if bar.bar < 0 {
        bar.barmove = 1;
        bar.bar = 0;
    }
}

// ===========================================================================
// Core update logic (the body of C `tool_progress_cb`, minus the readbusy tail)
// ===========================================================================

/// Runs one progress update against `bar`, returning `true` when the bar was
/// fully refreshed and `false` when the 10 Hz throttle skipped this tick.
///
/// This is the body of C's `tool_progress_cb` (`src/tool_cb_prg.c:120-214`) with
/// the trailing `readbusy`/`curl_easy_pause` handling factored out into
/// [`tool_progress_cb`]. The boolean return reproduces C's control flow exactly:
/// the early `return 0;` throttle exits (which also skip the unpause tail) map to
/// `false`, while reaching the end of the function maps to `true`.
///
/// Splitting the I/O-free logic out this way keeps it unit-testable without
/// constructing a full `PerTransfer`/`Easy`.
fn progress_update(
    bar: &mut ProgressData,
    dltotal: i64,
    dlnow: i64,
    ultotal: i64,
    ulnow: i64,
) -> bool {
    let now = Instant::now();
    let initial_size = bar.initial_size;

    // Expected total size and current progress point (C lines 132-156). For the
    // point, the "size known?" guard intentionally tests the TOTALS, not the
    // current counts (see `accumulate`).
    let total = accumulate(initial_size, dltotal, ultotal, dltotal, ultotal);
    let point = accumulate(initial_size, dltotal, ultotal, dlnow, ulnow);

    if bar.calls != 0 {
        // After the first call, apply the update throttle (C lines 158-177).
        if total != 0 {
            // Total known: skip when nothing changed, and cap to 10 Hz unless at
            // 100% (so the final frame is never dropped). C (lines 161-166) uses
            // two sequential `return 0` guards; they collapse to a single `||`
            // condition — semantically identical, since `timediff_ms` is
            // side-effect-free and `||` short-circuits exactly as the original
            // `if`/`else if` did. (clippy `if_same_then_else`.)
            if bar.prev == point || (timediff_ms(now, bar.prevtime) < 100 && point < total) {
                return false;
            }
        } else {
            // Total unknown: cap to 10 Hz, then draw the knight-rider frame.
            if timediff_ms(now, bar.prevtime) < 100 {
                return false;
            }
            update_width(bar);
            fly(bar, point != bar.prev);
        }
    }

    // Count this invocation (C line 180).
    bar.calls += 1;

    update_width(bar);

    // Determinate bar: only when the total is known and progress advanced
    // (C lines 183-211).
    if total > 0 && point != bar.prev {
        let frame = determinate_line(bar.width, point, total);
        bar.out.write_all(frame.as_bytes());
    }

    bar.out.flush();
    bar.prev = point;
    bar.prevtime = now;
    true
}

// ===========================================================================
// Public API
// ===========================================================================

/// The `CURLOPT_XFERINFOFUNCTION` progress callback for the `-#` bar — the port
/// of `tool_progress_cb` (`src/tool_cb_prg.c:120-222`).
///
/// On each progress tick `curl_rs_lib` delivers the four `curl_off_t` byte
/// counters as safe `i64` values. This renders (at most 10 frames per second) a
/// determinate bar when the size is known or the knight-rider animation when it
/// is not, then — if a read-busy pause is in effect — clears it and resumes the
/// transfer (C lines 215-219). Always returns `0` to continue the transfer; a
/// non-zero return would abort it.
///
/// `config` is passed alongside `per` because `PerTransfer` references its
/// owning `OperationConfig` by index rather than by pointer (the C
/// `per->config`); the integration layer resolves it from
/// `global.operations[per.config_idx]` and hands both in. The `readbusy`/unpause
/// tail runs only when the bar was actually refreshed (not throttled), matching
/// C, where the early throttle `return`s skip that tail.
pub fn tool_progress_cb(
    per: &mut PerTransfer,
    config: &mut OperationConfig,
    dltotal: i64,
    dlnow: i64,
    ultotal: i64,
    ulnow: i64,
) -> i32 {
    let completed = progress_update(&mut per.progressbar, dltotal, dlnow, ultotal, ulnow);

    // C lines 215-219: once a full update has been drawn, resume a transfer that
    // was paused because the read callback reported "busy".
    if completed && config.readbusy {
        config.readbusy = false;
        // curl ignores curl_easy_pause()'s return when unpausing here; so do we.
        // Pausing requires an active connection (Easy::pause otherwise returns
        // BadFunctionArgument), which always holds inside an in-flight transfer.
        let _ = per.easy.pause(CURLPAUSE_CONT);
    }

    // curl's tool_progress_cb always returns 0 (continue).
    0
}

/// Resets `bar` for a new transfer — the port of `progressbarinit`
/// (`src/tool_cb_prg.c:224-238`).
///
/// Every counter is zeroed (C's `memset`), the resume offset is threaded through
/// from `--continue-at` so the bar tracks progress toward the *whole* file, the
/// width is computed from the terminal, the output is bound to stderr, and the
/// animation seed (`tick = 150`) and initial glider direction (`barmove = 1`)
/// are set.
pub fn progressbarinit(bar: &mut ProgressData, config: &OperationConfig) {
    // C: memset(bar, 0, sizeof(*bar)). A fresh Default zeroes every field and
    // (re)seeds prevtime; the assignments below mirror C's explicit tail.
    *bar = ProgressData::default();

    // C lines 228-231: pass the resume-from offset to the bar so it shows
    // progress toward the whole file rather than just the remaining part.
    if config.use_resume {
        bar.initial_size = config.resume_from;
    }

    update_width(bar);

    bar.out = ProgressOut::Stderr;
    bar.tick = 150;
    bar.barmove = 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // -- helpers -------------------------------------------------------------

    /// Builds a fresh bar with an in-memory sink for byte-exact assertions.
    fn bar_with_buffer() -> ProgressData {
        ProgressData {
            out: ProgressOut::Buffer(Vec::new()),
            ..ProgressData::default()
        }
    }

    /// Extracts the bytes captured by a buffer-backed bar.
    fn captured(bar: &ProgressData) -> Vec<u8> {
        match &bar.out {
            ProgressOut::Buffer(v) => v.clone(),
            ProgressOut::Stderr => panic!("expected an in-memory buffer sink"),
        }
    }

    // -- SINUS table integrity ----------------------------------------------

    #[test]
    fn sinus_table_has_exactly_200_values() {
        assert_eq!(SINUS.len(), 200);
    }

    #[test]
    fn sinus_table_anchor_values_match_source() {
        // Anchors transcribed from src/tool_cb_prg.c: first value, the peak at
        // index 49, the single zero at index 149, and the last value.
        assert_eq!(SINUS[0], 515704);
        assert_eq!(SINUS[49], 999999);
        assert_eq!(SINUS[149], 0);
        assert_eq!(SINUS[199], 499907);
    }

    // -- Default state -------------------------------------------------------

    #[test]
    fn default_is_fully_zeroed() {
        let d = ProgressData::default();
        assert_eq!(d.calls, 0);
        assert_eq!(d.prev, 0);
        assert_eq!(d.width, 0);
        assert_eq!(d.initial_size, 0);
        assert_eq!(d.tick, 0);
        assert_eq!(d.bar, 0);
        assert_eq!(d.barmove, 0);
        assert!(matches!(d.out, ProgressOut::Stderr));
    }

    // -- accumulate (total/point arithmetic) --------------------------------

    #[test]
    fn accumulate_unknown_size_without_totals_is_max() {
        // initial_size < 0 and totals both zero => "unknown" sentinel.
        assert_eq!(accumulate(-1, 0, 0, 0, 0), i64::MAX);
    }

    #[test]
    fn accumulate_unknown_size_with_totals_sums_values() {
        // initial_size < 0 but totals known => report value sum.
        assert_eq!(accumulate(-1, 100, 0, 50, 0), 50);
        assert_eq!(accumulate(-1, 0, 100, 0, 30), 30);
    }

    #[test]
    fn accumulate_known_size_adds_initial_offset() {
        assert_eq!(accumulate(0, 100, 0, 50, 0), 50);
        assert_eq!(accumulate(10, 100, 0, 50, 0), 60);
        assert_eq!(accumulate(4096, 0, 0, 7, 0), 4103);
    }

    #[test]
    fn accumulate_saturates_on_overflow() {
        // (i64::MAX - initial_size) < sum => clamp to i64::MAX, never panic.
        assert_eq!(accumulate(i64::MAX, 1, 0, 1, 0), i64::MAX);
        assert_eq!(accumulate(i64::MAX - 5, 0, 0, 10, 0), i64::MAX);
    }

    // -- parse_columns (COLUMNS parsing) ------------------------------------

    #[test]
    fn parse_columns_accepts_leading_digits() {
        assert_eq!(parse_columns("80"), Some(80));
        assert_eq!(parse_columns("100"), Some(100));
        assert_eq!(parse_columns("10000"), Some(10000));
        // curl stops at the first non-digit.
        assert_eq!(parse_columns("80abc"), Some(80));
        // Returned even though the caller's `> 20` check would reject it.
        assert_eq!(parse_columns("20"), Some(20));
    }

    #[test]
    fn parse_columns_rejects_overflow_and_non_numbers() {
        assert_eq!(parse_columns("10001"), None); // past max 10000
        assert_eq!(parse_columns(""), None);
        assert_eq!(parse_columns("x80"), None); // no leading digit
    }

    // -- update_width --------------------------------------------------------

    #[test]
    fn update_width_stays_within_bounds() {
        let mut bar = ProgressData::default();
        update_width(&mut bar);
        assert!(bar.width >= MIN_BARLENGTH);
        assert!(bar.width <= MAX_BARLENGTH);
    }

    // -- fly_frame (knight-rider byte layout) -------------------------------

    #[test]
    fn fly_frame_layout_for_known_tick() {
        // width=80 => check=78, divisor = 1_000_000 / 78 = 12820.
        // tick=50 samples SINUS[50,55,60,65] = 999754,991148,970449,938168,
        // giving marker positions 78,78,76,74 (well clear of the glider at 1..6).
        let frame = fly_frame(80, 0, 50);
        assert_eq!(frame[0], b'\r');
        assert_eq!(&frame[1..6], b"-=O=-");
        assert_eq!(frame[74], b'#');
        assert_eq!(frame[76], b'#');
        assert_eq!(frame[78], b'#');
        assert_eq!(frame[75], b' ');
        assert_eq!(frame[77], b' ');
        // Exactly three distinct '#' columns are drawn (78 is sampled twice).
        let visible = &frame[..81];
        assert_eq!(visible.iter().filter(|&&b| b == b'#').count(), 3);
    }

    #[test]
    fn fly_frame_buffer_is_full_size() {
        let frame = fly_frame(MAX_BARLENGTH, 0, 0);
        assert_eq!(frame.len(), BAR_BUF_LEN);
        assert_eq!(BAR_BUF_LEN, 402);
    }

    // -- fly (state advance + emission) -------------------------------------

    #[test]
    fn fly_emits_width_plus_one_bytes_starting_with_cr() {
        let mut bar = bar_with_buffer();
        bar.width = 80;
        bar.bar = 0;
        bar.tick = 50;
        bar.barmove = 1;
        fly(&mut bar, true);
        let out = captured(&bar);
        assert_eq!(out.len(), 81); // '\r' + 80 columns
        assert_eq!(out[0], b'\r');
    }

    #[test]
    fn fly_tick_wraps_at_200() {
        let mut bar = bar_with_buffer();
        bar.width = 80;
        bar.tick = 198;
        bar.barmove = 1;
        fly(&mut bar, false);
        // 198 + 2 = 200 -> wraps to 0.
        assert_eq!(bar.tick, 0);
    }

    #[test]
    fn fly_glider_bounces_off_right_edge() {
        let mut bar = bar_with_buffer();
        bar.width = 80; // right bound = width - 6 = 74
        bar.bar = 73;
        bar.barmove = 1;
        fly(&mut bar, true);
        // 73 + 1 = 74 >= 74 -> clamp and reverse.
        assert_eq!(bar.bar, 74);
        assert_eq!(bar.barmove, -1);
    }

    #[test]
    fn fly_glider_bounces_off_left_edge() {
        let mut bar = bar_with_buffer();
        bar.width = 80;
        bar.bar = 0;
        bar.barmove = -1;
        fly(&mut bar, true);
        // 0 + (-1) = -1 < 0 -> clamp to 0 and reverse.
        assert_eq!(bar.bar, 0);
        assert_eq!(bar.barmove, 1);
    }

    #[test]
    fn fly_does_not_move_when_not_moved() {
        let mut bar = bar_with_buffer();
        bar.width = 80;
        bar.bar = 10;
        bar.barmove = 1;
        fly(&mut bar, false);
        // moved == false -> position unchanged.
        assert_eq!(bar.bar, 10);
    }

    // -- determinate_line (byte-exact parity with curl's format) ------------

    #[test]
    fn determinate_line_half_progress_exact_bytes() {
        // width=27 => barwidth=20; frac=0.5 => 10 '#' and percent " 50.0".
        // C: "\r%-20s %5.1f%%" => '\r' + 10# + 12 spaces + "50.0%".
        let expected = format!("\r{}{}50.0%", "#".repeat(10), " ".repeat(12));
        assert_eq!(determinate_line(27, 1, 2), expected);
    }

    #[test]
    fn determinate_line_full_progress_exact_bytes() {
        // frac=1.0 => barwidth '#' and percent "100.0" (exactly 5 wide).
        let expected = format!("\r{} 100.0%", "#".repeat(20));
        assert_eq!(determinate_line(27, 2, 2), expected);
    }

    #[test]
    fn determinate_line_caps_when_point_exceeds_total() {
        // point > total => total bumped to point, fraction capped at 100%.
        let line = determinate_line(27, 3, 2);
        assert!(line.ends_with("100.0%"));
        assert!(line.starts_with('\r'));
    }

    #[test]
    fn determinate_line_zero_progress_has_no_hashes() {
        let line = determinate_line(27, 0, 2);
        assert!(line.starts_with('\r'));
        assert!(line.ends_with("0.0%"));
        assert_eq!(line.bytes().filter(|&b| b == b'#').count(), 0);
    }

    // -- progress_update (throttle + render control flow) -------------------

    #[test]
    fn progress_update_first_call_renders_determinate() {
        let mut bar = bar_with_buffer();
        let completed = progress_update(&mut bar, 100, 50, 0, 0);
        assert!(completed);
        assert_eq!(bar.calls, 1);
        assert_eq!(bar.prev, 50);
        let out = captured(&bar);
        assert!(!out.is_empty());
        assert_eq!(out[0], b'\r');
        assert_eq!(*out.last().unwrap(), b'%');
    }

    #[test]
    fn progress_update_throttles_unchanged_point() {
        let mut bar = bar_with_buffer();
        assert!(progress_update(&mut bar, 100, 50, 0, 0)); // first frame
        let before = captured(&bar).len();
        // Same point => prev == point => skip (return false), no extra output.
        let completed = progress_update(&mut bar, 100, 50, 0, 0);
        assert!(!completed);
        assert_eq!(bar.calls, 1);
        assert_eq!(captured(&bar).len(), before);
    }

    #[test]
    fn progress_update_throttles_within_10hz_window() {
        let mut bar = bar_with_buffer();
        assert!(progress_update(&mut bar, 100, 50, 0, 0)); // first frame, prev=50
                                                           // Different point but within 100 ms and below total => throttled.
        let completed = progress_update(&mut bar, 100, 60, 0, 0);
        assert!(!completed);
        assert_eq!(bar.calls, 1);
    }

    #[test]
    fn progress_update_first_call_unknown_total_draws_nothing() {
        // initial_size 0, no totals => total == 0; first call only counts.
        let mut bar = bar_with_buffer();
        let completed = progress_update(&mut bar, 0, 5, 0, 0);
        assert!(completed);
        assert_eq!(bar.calls, 1);
        assert_eq!(bar.prev, 5);
        assert!(captured(&bar).is_empty()); // no determinate bar, no fly yet
    }

    #[test]
    fn progress_update_unknown_total_animates_after_throttle() {
        let mut bar = bar_with_buffer();
        assert!(progress_update(&mut bar, 0, 5, 0, 0)); // first call, prev=5
                                                        // Force the 10 Hz window open by backdating the last-frame time.
        if let Some(earlier) = Instant::now().checked_sub(Duration::from_millis(300)) {
            bar.prevtime = earlier;
            let completed = progress_update(&mut bar, 0, 7, 0, 0);
            assert!(completed);
            // The knight-rider frame was drawn (CR-prefixed, no trailing '%').
            let out = captured(&bar);
            assert!(!out.is_empty());
            assert_eq!(out[0], b'\r');
            assert_ne!(*out.last().unwrap(), b'%');
            // tick advanced by 2 from the default seed of 0.
            assert_eq!(bar.tick, 2);
            assert_eq!(bar.prev, 7);
        }
    }

    // -- progressbarinit -----------------------------------------------------

    #[test]
    fn progressbarinit_resets_and_seeds_state() {
        let mut bar = ProgressData {
            calls: 99,
            prev: 12345,
            tick: 7,
            bar: 3,
            barmove: -1,
            initial_size: 999,
            ..ProgressData::default()
        };
        let config = OperationConfig::default(); // use_resume defaults false
        progressbarinit(&mut bar, &config);
        assert_eq!(bar.calls, 0);
        assert_eq!(bar.prev, 0);
        assert_eq!(bar.bar, 0);
        assert_eq!(bar.initial_size, 0); // no resume
        assert_eq!(bar.tick, 150);
        assert_eq!(bar.barmove, 1);
        assert!(bar.width >= MIN_BARLENGTH && bar.width <= MAX_BARLENGTH);
        assert!(matches!(bar.out, ProgressOut::Stderr));
    }

    #[test]
    fn progressbarinit_threads_resume_offset() {
        let mut bar = ProgressData::default();
        // Struct-update syntax (rather than default-then-reassign) keeps clippy's
        // `field_reassign_with_default` happy; `..Default::default()` fills the
        // remaining `OperationConfig` fields.
        let config = OperationConfig {
            use_resume: true,
            resume_from: 4096,
            ..Default::default()
        };
        progressbarinit(&mut bar, &config);
        assert_eq!(bar.initial_size, 4096);
    }
}
