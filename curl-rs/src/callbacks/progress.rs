// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

//! Single-transfer `-#`/--progress-bar renderer (CURLOPT_XFERINFOFUNCTION). Rust rewrite of
//! curl 8.19.0-DEV `src/tool_cb_prg.c`. The parallel aggregate meter lives in
//! progress_display.rs.
//!
//! # Division of labor (do not duplicate)
//!
//! curl ships two distinct progress renderers, both driven by `CURLOPT_XFERINFOFUNCTION`:
//!
//! * The **single-transfer** flying/percentage bar — curl's `src/tool_cb_prg.c` — installed on
//!   the one easy handle of a serial `-#` transfer. **That is this module.**
//! * The **parallel aggregate** meter — curl's `src/tool_progress.c` — installed on every easy
//!   handle of a `--parallel` run to fold each transfer's counters into one status line. That
//!   lives in the sibling [`crate::progress_display`] module and owns its own xferinfo hook
//!   ([`crate::progress_display::xferinfo_cb`]); nothing aggregate is reimplemented here.
//!
//! # FFI userdata contract
//!
//! curl registers this callback with `CURLOPT_XFERINFODATA` pointing at the transfer's
//! [`ProgressData`] record. The [`tool_progress_cb`] entry point recovers that pointer through
//! the module's [`crate::callbacks::userdata_mut`] boundary helper — the single `unsafe`
//! deref, documented there. (curl points `XFERINFODATA` at the whole `per_transfer` and reads
//! `per->progressbar`; because `per_transfer`'s fields are private to `operate.rs` and its
//! progress state is modeled by the parallel-meter [`crate::progress_display::TransferProgress`],
//! the single-transfer bar is handed its own [`ProgressData`] directly — the same narrow-value
//! shape the sibling parallel hook already uses.)
//!
//! # Read-pause / resume coordination
//!
//! curl's `tool_progress_cb` also clears `config->readbusy` and calls
//! `curl_easy_pause(per->curl, CURLPAUSE_CONT)` to wake a transfer that a non-blocking stdin
//! read had paused. That un-pause needs the easy handle, which `operate.rs` owns. Exactly as
//! the sibling [`crate::progress_display::xferinfo_cb`] does (it "keeps this module free of any
//! handle dependency" by signalling a resume through a flag that `operate.rs` acts on), the
//! resume is **not** performed inside this render callback; it is coordinated by the
//! operation-dispatch layer that holds both the handle and the `readbusy` state. The resume
//! opcode is libcurl's `CURLPAUSE_CONT` (== 0).

// The single-transfer bar is a leaf renderer whose public surface (`progressbarinit`, the
// `CURL_PROGRESS_*` mode selectors, and `ProgressData`) is consumed by the operation-dispatch
// and option-application layers once the serial `-#` path is wired through them. Until that
// wiring lands this module has no in-crate caller, so — matching the sibling
// `progress_display.rs` — dead-code analysis is relaxed here rather than sprinkled per item.
#![allow(dead_code)]

use std::io::Write;
use std::time::Instant;

use curl_rs_ffi::easy::curl_xferinfo_callback;

use crate::args::OperationConfig;
use crate::callbacks::userdata_mut;

/// Widest bar curl will ever draw (curl's `MAX_BARLENGTH`). Also the hard cap on the number of
/// `#` hash cells emitted by the known-total renderer.
pub const MAX_BARLENGTH: i32 = 400;

/// Narrowest bar curl will draw (curl's `MIN_BARLENGTH`); used to clamp a very small or
/// undetectable terminal width up to a usable floor.
const MIN_BARLENGTH: i32 = 20;

/// curl's `CURL_PROGRESS_STATS` — the classic multi-column stats meter (the default progress
/// display). Retained as the mode selector paired with [`CURL_PROGRESS_BAR`].
pub const CURL_PROGRESS_STATS: i32 = 0;

/// curl's `CURL_PROGRESS_BAR` — the single-line progress bar selected by `-#` /
/// `--progress-bar`, i.e. the renderer implemented by this module.
pub const CURL_PROGRESS_BAR: i32 = 1;

/// Per-transfer state backing the single-transfer progress bar.
///
/// A field-for-field port of curl's `struct ProgressData` (`src/tool_cb_prg.h`). curl's
/// `FILE *out` sink is omitted: it is unconditionally set to `tool_stderr` in
/// [`progressbarinit`], so this renderer writes straight to [`std::io::stderr`] instead of
/// storing a constant handle. Every other field maps one-to-one; [`Default`] reproduces
/// curl's zero-initialization (`memset(bar, 0, …)`), with `prevtime` as [`None`] standing in
/// for the zeroed `struct curltime`.
#[derive(Debug, Default)]
pub struct ProgressData {
    /// Number of times the callback has been invoked (curl's `int calls`). The first call
    /// bypasses rate limiting; subsequent calls are throttled to 10 Hz.
    pub calls: i32,
    /// The previous progress point in bytes (curl's `curl_off_t prev`), used to suppress
    /// redraws when nothing changed.
    pub prev: i64,
    /// When the bar was last drawn (curl's `struct curltime prevtime`). [`None`] until the
    /// first draw, mirroring the zeroed timestamp produced by curl's `memset`.
    pub prevtime: Option<Instant>,
    /// Current bar width in columns (curl's `int width`), range-checked in [`update_width`].
    pub width: i32,
    /// Bytes already present before the transfer began — the `-C`/`--continue-at` resume
    /// offset (curl's `curl_off_t initial_size`). Negative means "expecting the size from the
    /// remote", which switches the total/point maths to the unknown-size branch.
    pub initial_size: i64,
    /// Animation phase for the unknown-total "flying" marker (curl's `unsigned int tick`),
    /// advanced by two each frame and wrapped modulo 200.
    pub tick: u32,
    /// Column of the `-=O=-` flying marker (curl's `int bar`).
    pub bar: i32,
    /// Direction the flying marker is travelling: `+1` right, `-1` left (curl's `int barmove`).
    pub barmove: i32,
}

// 200 values generated by this perl code:
//   my $pi = 3.1415;
//   foreach my $i (1 .. 200) {
//     printf "%d, ", sin($i / 200 * 2 * $pi) * 500000 + 500000;
//   }
//
// curl declares this `static const int sinus[]`; the Rust analog for a purely value-indexed
// lookup table is a `const` (never address-taken), which additionally lets the length be
// checked in the `const` assertion below. The `[i32; 200]` type itself already fixes the count
// at compile time — the assertion documents that invariant explicitly.
//
// `#[rustfmt::skip]` keeps this table nine samples per row, mirroring the curl source layout so
// it diffs line-for-line against `src/tool_cb_prg.c` (same rationale as `ffi/src/options.rs`).
#[rustfmt::skip]
const SINUS: [i32; 200] = [
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

// The `sinus` lookup table must contain exactly 200 samples: the animation indexes it modulo
// 200 (`tick`, `tick + 5`, `tick + 10`, `tick + 15`), so any other length would silently
// desynchronize the flying marker. Verified at compile time (mirrors curl's fixed-size array).
const _: () = assert!(SINUS.len() == 200);

/// Draw one frame of the unknown-total "flying" bar and advance its animation.
///
/// A byte-exact port of curl's `fly()` (`src/tool_cb_prg.c`). It renders a line of the form
/// `\r` + a `width`-wide field of spaces, over-stamped with the `-=O=-` marker at column
/// `bar + 1` and four `#` cells whose positions are sampled from the [`SINUS`] table at the
/// current `tick` (and `tick + 5/10/15`). The marker then bounces between the left edge and
/// `width - 6`, and `tick` advances by two, wrapping modulo 200.
///
/// `moved` is curl's flag for "progress actually advanced since the last frame"; when `false`
/// the marker holds its column so a stalled transfer's bar stops sliding.
fn fly(bar: &mut ProgressData, moved: bool) {
    // curl: `DEBUGASSERT(bar->width <= MAX_BARLENGTH);` — width is range-checked on assignment
    // in `update_width`, which every caller runs first.
    debug_assert!(bar.width <= MAX_BARLENGTH);

    // curl divides `1000000` by this to scale a sinus sample (0..=999999) onto a bar column.
    // `width >= MIN_BARLENGTH` (20) guarantees `check >= 18`, so the division is never by zero.
    let check = bar.width - 2;

    // curl builds `char buf[MAX_BARLENGTH + 2]` but only ever emits `buf[0..=width]` (index 0
    // is `\r`, indices `1..=width` start as spaces, and a trailing NUL bounds `fputs`). The
    // Rust buffer is exactly the emitted `width + 1` bytes and is written by length, so no NUL
    // terminator is needed.
    let mut buf = vec![b' '; (bar.width + 1) as usize];
    buf[0] = b'\r';

    // curl: `memcpy(&buf[bar->bar + 1], "-=O=-", 5);` — `bar` is bounded to `0..=width-6`, so
    // the five marker bytes always land inside `buf`.
    let marker_at = bar.bar as usize + 1;
    buf[marker_at..marker_at + 5].copy_from_slice(b"-=O=-");

    // curl stamps four `#` cells over the line at sinus-sampled columns. Integer arithmetic is
    // reproduced exactly: the divisor `1000000 / check` is truncated first, then the sample is
    // divided by it and offset by one. `pos` lands in `1..=width-1`, always inside `buf`.
    let mut pos = SINUS[(bar.tick as usize) % 200] / (1_000_000 / check) + 1;
    buf[pos as usize] = b'#';
    pos = SINUS[((bar.tick + 5) as usize) % 200] / (1_000_000 / check) + 1;
    buf[pos as usize] = b'#';
    pos = SINUS[((bar.tick + 10) as usize) % 200] / (1_000_000 / check) + 1;
    buf[pos as usize] = b'#';
    pos = SINUS[((bar.tick + 15) as usize) % 200] / (1_000_000 / check) + 1;
    buf[pos as usize] = b'#';

    // curl: `fputs(buf, bar->out);` — `bar->out` is always `tool_stderr`. Errors are ignored,
    // exactly as curl ignores the `fputs` return value.
    let _ = std::io::stderr().write_all(&buf);

    // curl: advance the animation phase by two, wrapping at 200.
    bar.tick += 2;
    if bar.tick >= 200 {
        bar.tick -= 200;
    }

    // curl: move the marker when progress advanced, then bounce it off either boundary.
    bar.bar += if moved { bar.barmove } else { 0 };
    if bar.bar >= bar.width - 6 {
        bar.barmove = -1;
        bar.bar = bar.width - 6;
    } else if bar.bar < 0 {
        bar.barmove = 1;
        bar.bar = 0;
    }
}

/// Recompute the bar width from the current terminal size.
///
/// A byte-exact port of curl's `update_width()` (`src/tool_cb_prg.c`): query the terminal
/// column count (curl's `get_terminal_columns()`, whose Rust port falls back to 79 when the
/// width cannot be determined) and clamp it into `[MIN_BARLENGTH, MAX_BARLENGTH]`.
fn update_width(bar: &mut ProgressData) {
    let cols = crate::terminal::get_terminal_columns() as i32;
    bar.width = if cols > MAX_BARLENGTH {
        MAX_BARLENGTH
    } else if cols > MIN_BARLENGTH {
        cols
    } else {
        MIN_BARLENGTH
    };
}

/// Milliseconds elapsed from `prev` to `now`, or [`i64::MAX`] when there is no previous frame.
///
/// Port of curl's `curlx_timediff_ms(now, bar->prevtime)`. Whenever the throttle actually
/// consults this value the callback has already drawn at least once (`calls != 0`), so
/// `prevtime` is [`Some`]; the [`None`] arm returns "infinitely long ago" so a first,
/// unthrottled draw is never suppressed. [`Instant::saturating_duration_since`] is the
/// panic-free equivalent of curl's subtraction — `now` is captured at entry and can only be
/// at or after `prev`, so the saturating and plain forms are identical here.
fn timediff_ms(now: Instant, prev: Option<Instant>) -> i64 {
    prev.map_or(i64::MAX, |t| {
        now.saturating_duration_since(t).as_millis() as i64
    })
}

/// libcurl `CURLOPT_XFERINFOFUNCTION` hook for the single-transfer `-#` bar.
///
/// A byte-exact port of curl's `tool_progress_cb()` (`src/tool_cb_prg.c`). It computes the
/// expected `total` and current `point` in bytes (folding in any resume `initial_size` and
/// clamping to [`i64::MAX`] on overflow or unknown size), rate-limits redraws to 10 Hz except
/// at completion, and then either animates the flying marker (unknown total) or paints a
/// hash-filled percentage bar (known total). Always returns `0` to continue the transfer,
/// matching the C callback's `int` contract (`curl_off_t` arguments map to `i64`).
///
/// # Safety
///
/// `clientp` must be the `*mut ProgressData` supplied to libcurl via `CURLOPT_XFERINFODATA`
/// for this transfer: a valid, aligned, live pointer, uniquely borrowed for the duration of
/// the call (the CLI runs on a single-threaded runtime, so no other alias is active). A null
/// pointer is tolerated defensively — the callback returns `0` (continue) without dereferencing
/// it — but any non-null pointer must satisfy the contract of [`crate::callbacks::userdata_mut`].
pub unsafe extern "C" fn tool_progress_cb(
    clientp: *mut core::ffi::c_void,
    dltotal: i64,
    dlnow: i64,
    ultotal: i64,
    ulnow: i64,
) -> core::ffi::c_int {
    // curl: `struct curltime now = curlx_now();`
    let now = Instant::now();

    // curl: `struct per_transfer *per = clientp; bar = &per->progressbar;`. Here
    // `CURLOPT_XFERINFODATA` points directly at the `ProgressData`. Recovering it is the sole
    // `unsafe` deref in this module, funnelled through the documented boundary helper.
    // SAFETY: by this callback's registration contract (see the fn-level `# Safety` note),
    // `clientp` is the transfer's `*mut ProgressData` — valid, aligned, live, and uniquely
    // borrowed for this call. `userdata_mut` returns `None` for a null pointer, which is
    // handled without any dereference.
    let bar = match unsafe { userdata_mut::<ProgressData>(clientp) } {
        Some(bar) => bar,
        None => return 0,
    };

    // curl: expected transfer size. `initial_size < 0` means "size still expected from the
    // remote"; otherwise the resume offset is folded in, clamping to CURL_OFF_T_MAX (i64::MAX)
    // on overflow.
    let mut total: i64 = if bar.initial_size < 0 {
        if dltotal != 0 || ultotal != 0 {
            dltotal + ultotal
        } else {
            i64::MAX
        }
    } else if i64::MAX - bar.initial_size < dltotal + ultotal {
        i64::MAX
    } else {
        dltotal + ultotal + bar.initial_size
    };

    // curl: current progress, with the identical initial_size / overflow handling as `total`.
    let point: i64 = if bar.initial_size < 0 {
        if dltotal != 0 || ultotal != 0 {
            dlnow + ulnow
        } else {
            i64::MAX
        }
    } else if i64::MAX - bar.initial_size < dlnow + ulnow {
        i64::MAX
    } else {
        dlnow + ulnow + bar.initial_size
    };

    // curl: after the first invocation, throttle redraws.
    if bar.calls != 0 {
        if total != 0 {
            // Total known: skip the redraw when nothing changed, or when under the 10 Hz
            // interval and not yet at 100% (completion always redraws). curl writes these as
            // two `if`/`else if` arms that both `return`; they are OR-combined here (identical
            // short-circuit order — `timediff_ms` is side-effect-free) so the single skip path
            // stays clippy-clean while preserving curl's exact throttle logic.
            if bar.prev == point || (timediff_ms(now, bar.prevtime) < 100 && point < total) {
                return 0;
            }
        } else {
            // Total unknown: throttle to 10 Hz, then animate the flying marker.
            if timediff_ms(now, bar.prevtime) < 100 {
                return 0;
            }
            update_width(bar);
            fly(bar, point != bar.prev);
        }
    }

    // curl: `bar->calls++;`
    bar.calls += 1;

    // curl: recompute the width, then paint the known-total percentage bar when the point has
    // advanced.
    update_width(bar);
    if total > 0 && point != bar.prev {
        // curl: got more than the advertised total — treat the total as the point.
        if point > total {
            total = point;
        }
        let frac = point as f64 / total as f64;
        let percent = frac * 100.0;
        let barwidth = bar.width - 7;
        let mut num = (barwidth as f64 * frac) as usize;
        if num > MAX_BARLENGTH as usize {
            num = MAX_BARLENGTH as usize;
        }
        // curl fills `line` with `num` `#` then formats `"\r%-<barwidth>ds %5.1f%%"`: a
        // carriage return, the hashes left-justified in a `barwidth` field, a space, the
        // percentage as `%5.1f`, and a literal `%`.
        let hashes: String = "#".repeat(num);
        eprint!(
            "\r{:<width$} {:5.1}%",
            hashes,
            percent,
            width = barwidth as usize
        );
    }

    // curl: `fflush(bar->out);`
    let _ = std::io::stderr().flush();

    // curl: `bar->prev = point; bar->prevtime = now;`
    bar.prev = point;
    bar.prevtime = Some(now);

    // curl here clears `config->readbusy` and issues `curl_easy_pause(per->curl, CURLPAUSE_CONT)`
    // to wake a transfer paused by a would-block stdin read. That un-pause needs the easy
    // handle (owned by `operate.rs`) and the per-transfer `readbusy` state (kept out of this
    // narrow `ProgressData`), so — as the sibling `progress_display::xferinfo_cb` does — the
    // resume is coordinated by the operation-dispatch layer rather than performed here.

    // curl: `return 0;`
    0
}

/// Initialize a [`ProgressData`] for a fresh transfer.
///
/// A byte-exact port of curl's `progressbarinit()` (`src/tool_cb_prg.c`): zero the record,
/// seed `initial_size` from the resume offset (so the bar tracks progress toward the whole
/// file rather than just the remaining part), size the bar to the terminal, and prime the
/// flying-marker animation (`tick = 150`, moving right). curl's `bar->out = tool_stderr` has
/// no analog here — the renderer writes straight to stderr.
pub fn progressbarinit(bar: &mut ProgressData, config: &OperationConfig) {
    // curl: `memset(bar, 0, sizeof(struct ProgressData));`
    *bar = ProgressData::default();

    // curl: pass the resume offset through so the meter shows progress toward the full file.
    if config.use_resume {
        bar.initial_size = config.resume_from;
    }

    update_width(bar);

    // curl: `bar->out = tool_stderr;` — modeled by writing directly to stderr (no stored sink).
    bar.tick = 150;
    bar.barmove = 1;
}

/// Compile-time proof that [`tool_progress_cb`] is ABI-identical to libcurl's
/// `CURLOPT_XFERINFOFUNCTION` callback type ([`curl_xferinfo_callback`]). If the signature ever
/// drifts from the FFI contract (argument types, calling convention, or return type) this
/// coercion fails to type-check, turning a latent ABI break into a build error.
const _: curl_xferinfo_callback = Some(tool_progress_cb);

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A default [`OperationConfig`] with resume disabled, for exercising [`progressbarinit`].
    fn config_no_resume() -> OperationConfig {
        OperationConfig::default()
    }

    /// The `sinus` table is parity-critical: it must hold exactly 200 samples (indexed modulo
    /// 200) and reproduce curl's generated values verbatim.
    #[test]
    fn sinus_table_is_verbatim_and_200_long() {
        assert_eq!(SINUS.len(), 200);
        // Endpoints and the mid-table zero crossing pin the table to curl's values.
        assert_eq!(SINUS[0], 515_704);
        assert_eq!(SINUS[49], 999_999);
        assert_eq!(SINUS[149], 0);
        assert_eq!(SINUS[199], 499_907);
    }

    /// [`ProgressData::default`] must reproduce curl's `memset(bar, 0, …)`: every counter zero
    /// and `prevtime` absent.
    #[test]
    fn default_is_zeroed() {
        let bar = ProgressData::default();
        assert_eq!(bar.calls, 0);
        assert_eq!(bar.prev, 0);
        assert!(bar.prevtime.is_none());
        assert_eq!(bar.width, 0);
        assert_eq!(bar.initial_size, 0);
        assert_eq!(bar.tick, 0);
        assert_eq!(bar.bar, 0);
        assert_eq!(bar.barmove, 0);
    }

    /// The `CURL_PROGRESS_*` mode selectors keep curl's integer identities.
    #[test]
    fn progress_mode_constants_match_curl() {
        assert_eq!(CURL_PROGRESS_STATS, 0);
        assert_eq!(CURL_PROGRESS_BAR, 1);
        assert_eq!(MAX_BARLENGTH, 400);
        assert_eq!(MIN_BARLENGTH, 20);
    }

    /// Without resume, [`progressbarinit`] zeroes the record, primes the animation
    /// (`tick = 150`, `barmove = 1`), leaves `initial_size` at zero, and clamps the width into
    /// the valid range.
    #[test]
    fn progressbarinit_zeros_and_primes() {
        let mut bar = ProgressData {
            calls: 7,
            prev: 999,
            tick: 42,
            bar: 5,
            barmove: -1,
            ..ProgressData::default()
        };
        progressbarinit(&mut bar, &config_no_resume());
        assert_eq!(bar.calls, 0);
        assert_eq!(bar.prev, 0);
        assert_eq!(bar.initial_size, 0);
        assert_eq!(bar.tick, 150);
        assert_eq!(bar.barmove, 1);
        assert!(bar.prevtime.is_none());
        assert!(bar.width >= MIN_BARLENGTH && bar.width <= MAX_BARLENGTH);
    }

    /// With `-C`/`--continue-at` active, the resume offset flows into `initial_size` so the bar
    /// tracks progress toward the whole file.
    #[test]
    fn progressbarinit_seeds_initial_size_from_resume() {
        let mut config = config_no_resume();
        config.use_resume = true;
        config.resume_from = 4096;
        let mut bar = ProgressData::default();
        progressbarinit(&mut bar, &config);
        assert_eq!(bar.initial_size, 4096);
        assert_eq!(bar.tick, 150);
        assert_eq!(bar.barmove, 1);
    }

    /// [`fly`] advances the animation phase by two each frame.
    #[test]
    fn fly_advances_tick_by_two() {
        let mut bar = ProgressData {
            width: 50,
            tick: 0,
            bar: 0,
            barmove: 1,
            ..ProgressData::default()
        };
        fly(&mut bar, true);
        assert_eq!(bar.tick, 2);
    }

    /// The animation phase wraps back into `0..200` once it reaches 200.
    #[test]
    fn fly_tick_wraps_at_200() {
        let mut bar = ProgressData {
            width: 50,
            tick: 198,
            bar: 0,
            barmove: 1,
            ..ProgressData::default()
        };
        fly(&mut bar, true);
        assert_eq!(bar.tick, 0);
    }

    /// The flying marker bounces off the right boundary (`width - 6`), reversing direction and
    /// clamping its column.
    #[test]
    fn fly_marker_bounces_at_right_edge() {
        let mut bar = ProgressData {
            width: 50,
            tick: 0,
            bar: 50 - 6, // exactly at the right limit
            barmove: 1,
            ..ProgressData::default()
        };
        fly(&mut bar, true);
        assert_eq!(bar.barmove, -1);
        assert_eq!(bar.bar, 50 - 6);
    }

    /// The flying marker bounces off the left edge (column 0), reversing direction.
    #[test]
    fn fly_marker_bounces_at_left_edge() {
        let mut bar = ProgressData {
            width: 50,
            tick: 0,
            bar: 0,
            barmove: -1,
            ..ProgressData::default()
        };
        fly(&mut bar, true);
        assert_eq!(bar.barmove, 1);
        assert_eq!(bar.bar, 0);
    }

    /// When progress has not moved, the marker holds its column even though `tick` still ticks.
    #[test]
    fn fly_holds_marker_when_not_moved() {
        let mut bar = ProgressData {
            width: 50,
            tick: 0,
            bar: 10,
            barmove: 1,
            ..ProgressData::default()
        };
        fly(&mut bar, false);
        assert_eq!(bar.bar, 10);
        assert_eq!(bar.barmove, 1);
        assert_eq!(bar.tick, 2);
    }

    /// [`update_width`] always clamps the reported terminal width into
    /// `[MIN_BARLENGTH, MAX_BARLENGTH]`, whatever the environment reports.
    #[test]
    fn update_width_clamps_into_range() {
        let mut bar = ProgressData::default();
        update_width(&mut bar);
        assert!(bar.width >= MIN_BARLENGTH && bar.width <= MAX_BARLENGTH);
    }

    /// A null `clientp` is tolerated: the callback returns `0` (continue) without dereferencing.
    #[test]
    fn tool_progress_cb_null_clientp_returns_zero() {
        // SAFETY: a null `clientp` is explicitly part of the callback's contract — it is
        // handled without any dereference, so calling with null is sound.
        let rc = unsafe { tool_progress_cb(std::ptr::null_mut(), 0, 0, 0, 0) };
        assert_eq!(rc, 0);
    }

    /// The first invocation is unthrottled: it records the point, stamps the timestamp, bumps
    /// the call counter, and returns "continue".
    #[test]
    fn tool_progress_cb_first_call_records_state() {
        let mut bar = ProgressData::default();
        let clientp = (&mut bar as *mut ProgressData).cast::<core::ffi::c_void>();
        // SAFETY: `clientp` is a valid, uniquely-borrowed pointer to the live `bar` for the
        // duration of the call; no other alias exists in this single-threaded test.
        let rc = unsafe { tool_progress_cb(clientp, 1000, 500, 0, 0) };
        assert_eq!(rc, 0);
        assert_eq!(bar.calls, 1);
        assert_eq!(bar.prev, 500);
        assert!(bar.prevtime.is_some());
    }

    /// After the first call, an identical `point` is throttled away: the callback returns `0`
    /// immediately and leaves the record untouched.
    #[test]
    fn tool_progress_cb_throttles_unchanged_point() {
        let mut bar = ProgressData {
            calls: 1,
            prev: 500,
            prevtime: Some(Instant::now()),
            ..ProgressData::default()
        };
        let clientp = (&mut bar as *mut ProgressData).cast::<core::ffi::c_void>();
        // SAFETY: `clientp` uniquely borrows the live `bar` for the call (single-threaded test).
        let rc = unsafe { tool_progress_cb(clientp, 1000, 500, 0, 0) };
        assert_eq!(rc, 0);
        assert_eq!(bar.calls, 1);
        assert_eq!(bar.prev, 500);
    }

    /// With an unknown total after the first call and the throttle window elapsed, the callback
    /// takes the "flying marker" branch: it animates (advancing `tick`) and counts the call.
    #[test]
    fn tool_progress_cb_unknown_total_animates() {
        let mut bar = ProgressData {
            calls: 1,
            prev: 0,
            // 200 ms ago so the 10 Hz throttle allows a redraw.
            prevtime: Some(
                Instant::now()
                    .checked_sub(Duration::from_millis(200))
                    .unwrap_or_else(Instant::now),
            ),
            tick: 0,
            barmove: 1,
            ..ProgressData::default()
        };
        let clientp = (&mut bar as *mut ProgressData).cast::<core::ffi::c_void>();
        // SAFETY: `clientp` uniquely borrows the live `bar` for the call (single-threaded test).
        let rc = unsafe { tool_progress_cb(clientp, 0, 0, 0, 0) };
        assert_eq!(rc, 0);
        assert_eq!(bar.calls, 2);
        // `fly` ran once and advanced the animation phase by two.
        assert_eq!(bar.tick, 2);
    }
}
