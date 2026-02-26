// -----------------------------------------------------------------------
// curl-rs/src/terminal.rs — Terminal width/capabilities detection
//
// Rust rewrite of src/terminal.c and src/terminal.h from the curl 8.x
// C codebase.  Provides:
//
//   - `get_terminal_columns()` — returns the current terminal width in
//     columns, checking the COLUMNS environment variable first, falling
//     back to OS-level terminal size detection, and defaulting to 79.
//
//   - `terminal_binary_ok()` — returns whether binary data may safely
//     be written to stdout (true when stdout is NOT a terminal).
//
//   - `is_terminal()` — generic wrapper around `std::io::IsTerminal`
//     for any stream that implements the trait.
//
// Design choices:
//   - Zero `unsafe` blocks — all terminal queries go through the
//     `terminal_size` crate (which uses rustix on Unix, windows-sys
//     on Windows internally).
//   - COLUMNS env-var semantics match the C implementation exactly:
//     parsed as an integer, must be > 20 and <= 10_000.
//   - Default width 79 matches curl 8.x `tool_terminal.c`.
//   - Maximum width 10_000 matches C guard.
//   - Cross-platform: Linux x86_64/aarch64, macOS x86_64/arm64.
//
// SPDX-License-Identifier: curl
// -----------------------------------------------------------------------

use std::env;
use std::io::{self, IsTerminal};
use terminal_size::{terminal_size, Width};

/// Default terminal width when detection is unavailable.
///
/// Matches curl 8.x `tool_terminal.c` fallback value exactly.
const DEFAULT_TERMINAL_WIDTH: u32 = 79;

/// Minimum accepted width from the COLUMNS environment variable.
///
/// Values <= 20 are rejected to prevent severely broken output
/// formatting.  This matches the C implementation's guard:
///
/// ```c
/// if(!curlx_str_number(&num, &env[0], 10000) && (num > 20))
///   cols = (unsigned int)num;
/// ```
const MIN_COLUMNS_ENV: u32 = 20;

/// Maximum accepted terminal width (both from COLUMNS env var and
/// OS-level detection).
///
/// Any width exceeding this value is capped.  Matches the C
/// implementation guard of 10 000.
const MAX_TERMINAL_WIDTH: u32 = 10_000;

/// Returns the current terminal width in columns.
///
/// Detection order (matching curl 8.x `get_terminal_columns()` in
/// `src/terminal.c`):
///
/// 1. **COLUMNS environment variable** — If set, parsed as an integer.
///    Accepted only when the parsed value is strictly greater than
///    [`MIN_COLUMNS_ENV`] (20) and at most [`MAX_TERMINAL_WIDTH`]
///    (10 000).  Takes precedence over OS detection so that the user
///    (or the test harness) can override terminal width portably.
///
/// 2. **OS-level terminal size** — Uses the `terminal_size` crate to
///    query the actual terminal width.  On Unix this corresponds to
///    `ioctl(fd, TIOCGWINSZ, ...)`, on Windows to
///    `GetConsoleScreenBufferInfo`.  The result is capped at
///    [`MAX_TERMINAL_WIDTH`].
///
/// 3. **Fallback** — If both of the above fail (e.g. stdout is
///    redirected to a pipe/file), returns [`DEFAULT_TERMINAL_WIDTH`]
///    (79).
///
/// # Examples
///
/// ```rust
/// // In a typical interactive terminal:
/// let cols = curl_rs::terminal::get_terminal_columns();
/// assert!(cols > 0);
/// ```
pub fn get_terminal_columns() -> u32 {
    // ---- Step 1: Check COLUMNS env var (highest priority) ----
    if let Ok(val) = env::var("COLUMNS") {
        if let Ok(num) = val.trim().parse::<u32>() {
            // C semantics: must be > 20 AND <= 10_000
            if num > MIN_COLUMNS_ENV && num <= MAX_TERMINAL_WIDTH {
                return num;
            }
        }
        // If COLUMNS is set but invalid/out-of-range, fall through
        // to OS detection (same as C behaviour — the env var is
        // simply ignored when unparseable or out of bounds).
    }

    // ---- Step 2: OS-level terminal size detection ----
    if let Some((Width(w), _height)) = terminal_size() {
        let width = u32::from(w);
        if width > 0 {
            // Cap at maximum, matching C guard
            return width.min(MAX_TERMINAL_WIDTH);
        }
    }

    // ---- Step 3: Fallback ----
    DEFAULT_TERMINAL_WIDTH
}

/// Returns `true` when binary data may safely be written to stdout.
///
/// When stdout is connected to a real terminal, writing raw binary
/// output can corrupt the display.  curl 8.x prints a warning and
/// refuses to write binary to a TTY unless `--output -` is explicitly
/// given.
///
/// This function returns:
///   - `false` — stdout **is** a terminal (binary output would be
///     visible and potentially harmful).
///   - `true`  — stdout is redirected to a file or pipe, so binary
///     output is fine.
///
/// The check uses `std::io::IsTerminal` (stable since Rust 1.70,
/// within MSRV 1.75) on `std::io::stdout()`.
///
/// # Examples
///
/// ```rust,no_run
/// if !curl_rs::terminal::terminal_binary_ok() {
///     eprintln!("Warning: Binary output to terminal.");
/// }
/// ```
pub fn terminal_binary_ok() -> bool {
    // Binary output is acceptable only when stdout is NOT a terminal.
    !io::stdout().is_terminal()
}

/// Returns whether the given stream is connected to a terminal (TTY).
///
/// This is a thin, generic wrapper around the `std::io::IsTerminal`
/// trait method `is_terminal()`.  It exists to provide a single
/// call-site for TTY detection that the progress meter, binary output
/// check, and help formatter can all share.
///
/// # Type Parameter
///
/// - `T` — Any type implementing `std::io::IsTerminal`.  Common
///   concrete types: `std::io::Stdout`, `std::io::Stderr`,
///   `std::fs::File`.
///
/// # Examples
///
/// ```rust,no_run
/// use std::io;
/// let stdout = io::stdout();
/// if curl_rs::terminal::is_terminal(&stdout) {
///     println!("stdout is a terminal");
/// }
/// ```
pub fn is_terminal<T: IsTerminal>(stream: &T) -> bool {
    stream.is_terminal()
}

// -----------------------------------------------------------------------
// Unit tests
// -----------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// The default terminal width must be 79, matching curl 8.x.
    #[test]
    fn default_width_constant() {
        assert_eq!(DEFAULT_TERMINAL_WIDTH, 79);
    }

    /// `get_terminal_columns` must always return a value > 0.
    #[test]
    fn columns_always_positive() {
        let cols = get_terminal_columns();
        assert!(cols > 0, "terminal columns must be > 0, got {cols}");
    }

    /// `get_terminal_columns` must never exceed MAX_TERMINAL_WIDTH.
    #[test]
    fn columns_within_max() {
        let cols = get_terminal_columns();
        assert!(
            cols <= MAX_TERMINAL_WIDTH,
            "terminal columns must be <= {MAX_TERMINAL_WIDTH}, got {cols}"
        );
    }

    /// When COLUMNS env var is set to a valid value > 20 and <= 10000,
    /// `get_terminal_columns` must return that value.
    #[test]
    fn columns_env_var_respected() {
        // We cannot safely set env vars in multi-threaded tests, but
        // for a single-threaded test runner this is fine.
        // Save and restore the original value.
        let original = env::var("COLUMNS").ok();

        env::set_var("COLUMNS", "120");
        let cols = get_terminal_columns();
        assert_eq!(cols, 120);

        // Restore
        match original {
            Some(v) => env::set_var("COLUMNS", v),
            None => env::remove_var("COLUMNS"),
        }
    }

    /// COLUMNS values <= 20 must be ignored.
    #[test]
    fn columns_env_var_too_small() {
        let original = env::var("COLUMNS").ok();

        env::set_var("COLUMNS", "20");
        let cols = get_terminal_columns();
        // Should NOT be 20 — must fall through to OS or default
        assert_ne!(cols, 20, "COLUMNS=20 must be rejected (> 20 required)");

        match original {
            Some(v) => env::set_var("COLUMNS", v),
            None => env::remove_var("COLUMNS"),
        }
    }

    /// COLUMNS values > 10000 must be ignored.
    #[test]
    fn columns_env_var_too_large() {
        let original = env::var("COLUMNS").ok();

        env::set_var("COLUMNS", "20000");
        let cols = get_terminal_columns();
        assert_ne!(cols, 20000, "COLUMNS=20000 must be rejected");

        match original {
            Some(v) => env::set_var("COLUMNS", v),
            None => env::remove_var("COLUMNS"),
        }
    }

    /// Non-numeric COLUMNS values must be ignored.
    #[test]
    fn columns_env_var_non_numeric() {
        let original = env::var("COLUMNS").ok();

        env::set_var("COLUMNS", "abc");
        let cols = get_terminal_columns();
        // Must fall through to OS detection or default
        assert!(
            cols > 0 && cols <= MAX_TERMINAL_WIDTH,
            "non-numeric COLUMNS must be ignored, got {cols}"
        );

        match original {
            Some(v) => env::set_var("COLUMNS", v),
            None => env::remove_var("COLUMNS"),
        }
    }

    /// COLUMNS boundary: exactly 21 should be accepted.
    #[test]
    fn columns_env_var_boundary_21() {
        let original = env::var("COLUMNS").ok();

        env::set_var("COLUMNS", "21");
        let cols = get_terminal_columns();
        assert_eq!(cols, 21, "COLUMNS=21 should be accepted");

        match original {
            Some(v) => env::set_var("COLUMNS", v),
            None => env::remove_var("COLUMNS"),
        }
    }

    /// COLUMNS boundary: exactly 10000 should be accepted.
    #[test]
    fn columns_env_var_boundary_10000() {
        let original = env::var("COLUMNS").ok();

        env::set_var("COLUMNS", "10000");
        let cols = get_terminal_columns();
        assert_eq!(cols, 10000, "COLUMNS=10000 should be accepted");

        match original {
            Some(v) => env::set_var("COLUMNS", v),
            None => env::remove_var("COLUMNS"),
        }
    }

    /// `terminal_binary_ok` returns a bool without panicking.
    #[test]
    fn binary_ok_does_not_panic() {
        let _ok = terminal_binary_ok();
    }

    /// `is_terminal` accepts stdout without panicking.
    #[test]
    fn is_terminal_stdout() {
        let stdout = io::stdout();
        let _result = is_terminal(&stdout);
    }

    /// `is_terminal` accepts stderr without panicking.
    #[test]
    fn is_terminal_stderr() {
        let stderr = io::stderr();
        let _result = is_terminal(&stderr);
    }

    /// In CI / test-runner context, stdout is usually NOT a terminal.
    /// This is a soft check — it documents expected behaviour in
    /// automated environments.
    #[test]
    fn binary_ok_in_ci() {
        // In CI, stdout is typically redirected, so terminal_binary_ok()
        // should return true (binary output is safe).
        // This is a documentation test — we don't hard-assert because
        // some CI runners allocate a pseudo-terminal.
        let ok = terminal_binary_ok();
        // Just verify it returns a bool value (compiler enforces this).
        let _: bool = ok;
    }
}
