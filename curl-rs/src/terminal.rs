// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// Rust rewrite of curl's src/terminal.c (terminal width/columns query).

//! # Terminal-width query
//!
//! Faithful Rust port of curl 8.19.0-DEV's `src/terminal.c` (`src/terminal.h`). The single
//! public entry point, [`get_terminal_columns`], answers the question *"how many columns wide
//! is the controlling terminal?"* and is consumed by the CLI's progress-meter/progress-bar
//! renderer (`progress_display.rs`) and by help-text wrapping.
//!
//! ## Behavior (byte-for-byte parity with `src/terminal.c`)
//!
//! The width is resolved in three ordered steps, exactly mirroring the C implementation:
//!
//! 1. **`COLUMNS` environment variable.** If set and it parses (via curl's
//!    [`curlx_str_number`]-equivalent — see [`parse_columns_env`]) as a number that is
//!    **greater than 20** and does not exceed the parser cap of 10000, that value is used.
//! 2. **`ioctl(STDIN_FILENO, TIOCGWINSZ, …)`.** Otherwise the kernel is asked for the window
//!    size and `ws_col` is used, clamped to the half-open range `[0, 10000)`.
//! 3. **Fallback `79`.** If neither source yields a usable, non-zero width, the function
//!    returns exactly **79** — curl's historical default. This constant must not change:
//!    downstream progress-bar and help-column layout depend on it.
//!
//! The returned value can legitimately be tiny or very large (up to 9999 from `ioctl`, up to
//! 10000 from `COLUMNS`); callers are responsible for their own layout decisions, precisely as
//! in curl.
//!
//! ## Platform scope
//!
//! The four supported build targets (`x86_64`/`aarch64` × `unknown-linux-gnu`/`apple-darwin`)
//! all provide `TIOCGWINSZ`, so — unlike the multi-branch C source — only that single ioctl
//! path is implemented. curl's BSD-only `TIOCGSIZE`/`ttysize` branch is unnecessary on these
//! targets, and its `_WIN32` `GetConsoleScreenBufferInfo` branch is out of scope (Windows is
//! not a supported target; see AAP §0.6.5).
//!
//! ## Unsafe policy (AAP §0.6.2 / §0.7.2)
//!
//! `unsafe` appears exactly once, in [`query_ioctl_columns`], wrapping only the `libc::ioctl`
//! FFI call — the narrow OS-integration primitive that genuinely requires it — and it carries
//! a mandatory `// SAFETY:` comment. The environment parsing, range clamping, and fallback
//! logic are entirely safe Rust.

// This module is wired into the binary crate ahead of its consumer: the progress-display
// renderer that calls `get_terminal_columns` lands as a sibling module in the same build
// order. Until that call site is present, the crate-level `dead_code` lint would otherwise
// fire on these items during intermediate builds, so it is allowed at module scope. The
// allowance is harmless once the consumer is wired (the items become live).
#![allow(dead_code)]

/// curl's exact terminal-width fallback, returned when neither `COLUMNS` nor `TIOCGWINSZ`
/// yields a usable width.
///
/// This value is a hard behavioral contract: progress-bar rendering and `--help` column
/// wrapping are laid out against it, so it must remain `79` (mirrors `width = 79;` in
/// `src/terminal.c`).
const FALLBACK_COLUMNS: u32 = 79;

/// Numeric limit shared by both width sources, matching the literal `10000` in
/// `src/terminal.c`.
///
/// * For the `COLUMNS` environment variable it is the **inclusive** cap passed to curl's
///   `curlx_str_number(&p, &num, 10000)` — a parsed value may equal 10000 but a larger value
///   makes the parse fail (see [`parse_columns_env`]).
/// * For the `ioctl` result it is the **exclusive** upper bound of the accepted range
///   (`cols < 10000`).
const COLUMNS_LIMIT: i64 = 10_000;

/// The `COLUMNS` value must be strictly greater than this to be honored, mirroring the
/// `(num > 20)` guard in `src/terminal.c`. Values of 20 or below are ignored and the query
/// falls through to `ioctl`.
const COLUMNS_MIN: i64 = 20;

/// Parse an unsigned base-10 number from the **start** of `value`, faithfully reproducing
/// curl's `curlx_str_number(&p, &num, max)` (`lib/curlx/strparse.c`) as used by
/// `src/terminal.c` for the `COLUMNS` variable.
///
/// Semantics preserved exactly from the C helper:
///
/// * The first byte **must** be an ASCII digit — there is no support for a leading sign,
///   surrounding whitespace, or a `0x`/`0` prefix. A non-digit first byte (or an empty
///   string) is the C `STRE_NO_NUM` error, reported here as [`None`].
/// * Only the leading run of digits is consumed; the first non-digit ends the scan and any
///   trailing characters are ignored (so `"80x"` parses as `80`), just as the C caller does
///   not require the whole string to be numeric.
/// * Leading zeroes are accepted (`"0080"` → `80`).
/// * `max` is an **inclusive** cap. The overflow guard is the C expression
///   `num > (max - n) / base` evaluated *before* each shift-and-add, so `"10000"` succeeds
///   (equals the cap) while `"10001"` overflows — the C `STRE_OVERFLOW` error, reported here
///   as [`None`].
///
/// The returned value is the parsed magnitude; the caller applies the separate `> 20` gate.
fn parse_columns_env(value: &str, max: i64) -> Option<i64> {
    let bytes = value.as_bytes();

    // curl: `if(!valid_digit(*p, m)) return STRE_NO_NUM;` — the first character must be a
    // digit (no leading blanks, sign, or prefix). An empty value yields `None` here.
    let first = *bytes.first()?;
    if !first.is_ascii_digit() {
        return None;
    }

    let base: i64 = 10;
    let mut num: i64 = 0;
    for &b in bytes {
        // Stop at the first non-digit: only the leading digit run is consumed, matching the
        // `while(valid_digit(*p, m))` loop condition in the C source.
        if !b.is_ascii_digit() {
            break;
        }
        let n = i64::from(b - b'0');
        // curl's overflow guard for the `max >= base` case: reject if the next shift-and-add
        // would exceed the inclusive cap. Keeping the exact form makes the accepted boundary
        // (value may equal `max`) identical to the C code.
        if num > (max - n) / base {
            return None;
        }
        num = num * base + n;
    }

    Some(num)
}

/// Resolve the terminal width from the two already-gathered inputs — the raw `COLUMNS`
/// environment value and the `ioctl` result — applying curl's exact precedence and clamping.
///
/// Splitting this pure decision logic out of [`get_terminal_columns`] keeps the environment
/// parse, the `> 20` gate, the `[0, 10000)` clamp, and the `79` fallback fully testable
/// without touching process state or issuing a real `ioctl`; the only behavior
/// [`get_terminal_columns`] layers on top is the thin `unsafe` ioctl call.
///
/// This mirrors the control flow of `src/terminal.c`:
///
/// * `env_columns` is `Some` iff `COLUMNS` was set; a value that parses, exceeds 20, and is
///   within the cap wins outright.
/// * `ioctl_cols` is `Some(ws_col)` on ioctl success and `None` on failure. A value in
///   `[0, 10000)` is used, but a resulting width of `0` (e.g. `ws_col == 0` when stdin is not
///   a terminal) is treated as "unknown" — exactly as the C code's trailing `if(!width)`
///   check does — and falls through to the fallback.
/// * When nothing usable is found the result is [`FALLBACK_COLUMNS`] (79).
fn columns_from(env_columns: Option<&str>, ioctl_cols: Option<i64>) -> u32 {
    // Step 1 — `COLUMNS` environment variable (curl: parse with cap 10000, then require > 20).
    if let Some(value) = env_columns {
        if let Some(num) = parse_columns_env(value, COLUMNS_LIMIT) {
            if num > COLUMNS_MIN {
                return num as u32;
            }
        }
    }

    // Step 2 — `ioctl` window size, clamped to the half-open range `[0, 10000)`. A zero width
    // is not usable and deliberately falls through to the fallback below (parity with the C
    // code, where `width` would be set to 0 and then re-checked by `if(!width)`).
    if let Some(cols) = ioctl_cols {
        if (0..COLUMNS_LIMIT).contains(&cols) {
            let width = cols as u32;
            if width != 0 {
                return width;
            }
        }
    }

    // Step 3 — curl's exact fallback for an unknown terminal width.
    FALLBACK_COLUMNS
}

/// Query the terminal width via `ioctl(STDIN_FILENO, TIOCGWINSZ, …)`.
///
/// Returns `Some(ws_col)` on success and `None` when the ioctl fails — most commonly because
/// standard input is not a terminal (a pipe, file, or closed descriptor). The `ws_col` field
/// is an unsigned 16-bit value, so the widened `i64` result is always non-negative; it is
/// returned as `i64` to match the `curl_off_t`/`int` width arithmetic in
/// [`columns_from`].
///
/// This is the sole `unsafe` site in the crate outside the FFI layer. Per AAP §0.6.2 it is
/// permitted only because a raw `ioctl` is a narrow OS-integration primitive with no safe
/// equivalent in the standard library, and the `unsafe` block is kept as tight as possible.
fn query_ioctl_columns() -> Option<i64> {
    // Build a fully-initialized `winsize` in safe Rust (all fields are public and zeroable),
    // avoiding `mem::zeroed()` so the *only* `unsafe` in this function is the ioctl call
    // itself.
    let mut ws = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    // SAFETY: `ws` is a valid, fully-initialized (zeroed) `winsize` — exactly the struct and
    // size `libc::ioctl` expects for the `TIOCGWINSZ` request — and `&mut ws` is a valid,
    // unique, properly aligned pointer to it. `libc::STDIN_FILENO` is a valid file descriptor.
    // On success `ioctl` writes only within `ws`; on failure it returns non-zero and leaves
    // `ws` unmodified (we ignore it in that case). No pointer escapes this call.
    let rc = unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) };

    if rc == 0 {
        Some(i64::from(ws.ws_col))
    } else {
        None
    }
}

/// Return the width, in columns, of the controlling terminal.
///
/// This is the Rust equivalent of curl's `unsigned int get_terminal_columns(void)`
/// (`src/terminal.c`). It consults the `COLUMNS` environment variable first, then falls back
/// to `ioctl(TIOCGWINSZ)`, and finally returns curl's fixed default of **79** when the width
/// cannot be determined. The returned value is never zero and may be small or large; it is up
/// to the caller (progress rendering, help wrapping) to decide how to use it.
///
/// See the [module documentation](self) for the precise resolution order and parity notes.
pub fn get_terminal_columns() -> u32 {
    // `curl_getenv("COLUMNS")` — a missing variable is `None` and skips step 1.
    let env_columns = std::env::var("COLUMNS").ok();
    // `ioctl(STDIN_FILENO, TIOCGWINSZ, …)` — `None` on failure (e.g. stdin is not a tty).
    let ioctl_cols = query_ioctl_columns();
    columns_from(env_columns.as_deref(), ioctl_cols)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The numeric parser must reproduce curl's `curlx_str_number` boundary behavior exactly.
    #[test]
    fn parse_columns_env_matches_curl_semantics() {
        // Plain values.
        assert_eq!(parse_columns_env("80", COLUMNS_LIMIT), Some(80));
        assert_eq!(parse_columns_env("21", COLUMNS_LIMIT), Some(21));
        assert_eq!(parse_columns_env("9999", COLUMNS_LIMIT), Some(9999));

        // The cap is inclusive: exactly 10000 parses, 10001 (and larger) overflow to `None`.
        assert_eq!(parse_columns_env("10000", COLUMNS_LIMIT), Some(10_000));
        assert_eq!(parse_columns_env("10001", COLUMNS_LIMIT), None);
        assert_eq!(parse_columns_env("15000", COLUMNS_LIMIT), None);
        assert_eq!(parse_columns_env("99999", COLUMNS_LIMIT), None);

        // Leading zeroes accepted; only the leading digit run is consumed.
        assert_eq!(parse_columns_env("0080", COLUMNS_LIMIT), Some(80));
        assert_eq!(parse_columns_env("80x", COLUMNS_LIMIT), Some(80));
        assert_eq!(parse_columns_env("120 ", COLUMNS_LIMIT), Some(120));

        // First byte must be a digit: leading space/sign, non-numeric, and empty all fail.
        assert_eq!(parse_columns_env(" 80", COLUMNS_LIMIT), None);
        assert_eq!(parse_columns_env("+80", COLUMNS_LIMIT), None);
        assert_eq!(parse_columns_env("-80", COLUMNS_LIMIT), None);
        assert_eq!(parse_columns_env("abc", COLUMNS_LIMIT), None);
        assert_eq!(parse_columns_env("", COLUMNS_LIMIT), None);

        // Values are parsed regardless of the `> 20` gate (which the caller applies).
        assert_eq!(parse_columns_env("0", COLUMNS_LIMIT), Some(0));
        assert_eq!(parse_columns_env("20", COLUMNS_LIMIT), Some(20));
    }

    /// The full precedence/clamp/fallback decision must match `src/terminal.c`.
    #[test]
    fn columns_from_applies_curl_precedence() {
        // A valid `COLUMNS` (> 20, within cap) wins outright and bypasses ioctl.
        assert_eq!(columns_from(Some("133"), Some(200)), 133);
        assert_eq!(columns_from(Some("10000"), None), 10_000);
        assert_eq!(columns_from(Some("21"), None), 21);

        // `COLUMNS` of 20-or-below, over-cap, or non-numeric is ignored; ioctl is consulted.
        assert_eq!(columns_from(Some("20"), Some(200)), 200);
        assert_eq!(columns_from(Some("10001"), Some(200)), 200);
        assert_eq!(columns_from(Some("abc"), Some(200)), 200);

        // ioctl value used when within `[0, 10000)`; out-of-range or zero → fallback.
        assert_eq!(columns_from(None, Some(120)), 120);
        assert_eq!(columns_from(None, Some(9999)), 9999);
        assert_eq!(columns_from(None, Some(10_000)), FALLBACK_COLUMNS);
        assert_eq!(columns_from(None, Some(0)), FALLBACK_COLUMNS);

        // Nothing usable (no COLUMNS, ioctl failed) → curl's fixed 79.
        assert_eq!(columns_from(None, None), FALLBACK_COLUMNS);
        assert_eq!(FALLBACK_COLUMNS, 79);
    }

    /// The public entry point must always yield a positive width, whatever the environment.
    #[test]
    fn get_terminal_columns_is_positive() {
        assert!(get_terminal_columns() > 0);
    }
}
