// -----------------------------------------------------------------------
// curl-rs/src/msgs.rs — Message/Warning Output
//
// Rust rewrite of src/tool_msgs.c and src/tool_msgs.h from curl 8.19.0-DEV.
//
// Provides four diagnostic output functions used throughout the CLI
// binary for user-facing messages:
//
//   - `warnf`  — warnings suppressed by `--silent` (`-s`)
//   - `notef`  — notes emitted only in verbose/trace modes
//   - `errorf` — errors shown unless `--silent` without `--show-error`
//   - `helpf`  — command-line usage errors with "try --help" hint
//
// All output is routed through `tool_stderr_write()` so that
// `--stderr` redirection is respected.  Terminal-width-aware word
// wrapping is applied by the internal `voutf` helper, matching the C
// implementation's wrapping algorithm byte-for-byte.
//
// Additionally, convenience macros `warnf!`, `notef!`, `errorf!`, and
// `helpf!` are provided for ergonomic `format!`-style argument usage.
//
// Zero `unsafe` blocks.
//
// SPDX-License-Identifier: curl
// -----------------------------------------------------------------------

use crate::config::{GlobalConfig, TraceType};
use crate::stderr::tool_stderr_write;
use crate::terminal::get_terminal_columns;

// ---------------------------------------------------------------------------
// Prefix constants — exact byte-for-byte match with curl 8.x tool_msgs.c
//
// These constants correspond to the C preprocessor macros:
//   #define WARN_PREFIX  "Warning: "
//   #define NOTE_PREFIX  "Note: "
//   #define ERROR_PREFIX "curl: "
// ---------------------------------------------------------------------------

/// Warning message prefix.
///
/// Matches the C `#define WARN_PREFIX "Warning: "` in `src/tool_msgs.c`.
/// Prepended to every line of output from [`warnf`].
const WARN_PREFIX: &str = "Warning: ";

/// Note message prefix.
///
/// Matches the C `#define NOTE_PREFIX "Note: "` in `src/tool_msgs.c`.
/// Prepended to every line of output from [`notef`].
const NOTE_PREFIX: &str = "Note: ";

/// Error message prefix.
///
/// Matches the C `#define ERROR_PREFIX "curl: "` in `src/tool_msgs.c`.
/// Prepended to every line of output from [`errorf`].
const ERROR_PREFIX: &str = "curl: ";

/// Help hint line printed by [`helpf`] after any error context.
///
/// `USE_MANUAL` is always defined in the Rust build (per AAP Section
/// 0.7.3), so the hint always includes `or 'curl --manual'`.
///
/// Matches the C:
/// ```c
/// curl_mfprintf(tool_stderr, "curl: try 'curl --help' "
///               "or 'curl --manual' "
///               "for more information\n");
/// ```
const HELP_HINT: &str = "curl: try 'curl --help' or 'curl --manual' for more information\n";

// ---------------------------------------------------------------------------
// Internal helper: is_blank
// ---------------------------------------------------------------------------

/// Returns `true` if the byte is a blank character (space or horizontal
/// tab), matching the C `ISBLANK()` macro semantics used in `voutf`.
///
/// The C `isblank()` / `ISBLANK()` function recognises exactly two
/// characters as "blank": space (0x20) and horizontal tab (0x09).
#[inline]
fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

// ---------------------------------------------------------------------------
// Internal helper: voutf (word-wrapping diagnostic output)
// ---------------------------------------------------------------------------

/// Formats and outputs a diagnostic message with the given prefix,
/// performing terminal-width-aware line wrapping at word boundaries.
///
/// This is the Rust equivalent of the C static function `voutf()` in
/// `src/tool_msgs.c`.  The wrapping algorithm matches the C
/// implementation exactly:
///
/// 1. Get terminal width via [`get_terminal_columns()`].
/// 2. Compute available text width = terminal_width − prefix_width.
///    If the terminal is narrower than the prefix, disable wrapping
///    (effectively infinite width), matching the C `SIZE_MAX` fallback.
/// 3. For each iteration:
///    - Print the prefix.
///    - If the remaining text exceeds the available width:
///      start at position `width − 1` and search backward for a
///      blank character (space or tab).
///      If found at position `cut`, write `cut + 1` bytes (the text
///      up to and including the blank) followed by a newline.
///      If no blank is found (`cut` reaches 0), hard-cut at
///      `width − 1` bytes.
///      Advance the read position past the written portion.
///    - Otherwise, print the remaining text plus a newline and finish.
///
/// All output goes through [`tool_stderr_write()`] so that `--stderr`
/// redirection is respected.
///
/// # Panics (debug builds only)
///
/// Panics via `debug_assert!` if `msg` contains an embedded newline
/// character, matching the C `DEBUGASSERT(!strchr(fmt, '\n'))`.
fn voutf(prefix: &str, msg: &str) {
    let termw = get_terminal_columns() as usize;
    let prefw = prefix.len();

    // If the terminal is wider than the prefix, the available text area
    // is the difference.  Otherwise, set to usize::MAX to effectively
    // disable wrapping — matching the C `SIZE_MAX` semantic:
    //   size_t width = termw > prefw ? termw - prefw : SIZE_MAX;
    let width: usize = if termw > prefw {
        termw - prefw
    } else {
        usize::MAX
    };

    // Debug-mode assertion: the message must not contain embedded
    // newlines.  Matches C: `DEBUGASSERT(!strchr(fmt, '\n'));`
    debug_assert!(
        !msg.contains('\n'),
        "diagnostic message must not contain embedded newlines"
    );

    let msg_bytes = msg.as_bytes();
    let total_len = msg_bytes.len();
    let mut pos: usize = 0;

    // Main wrapping loop — matches C: `while(len > 0) { ... }`
    while pos < total_len {
        // Always emit the prefix at the start of each output line.
        tool_stderr_write(prefix);

        let remaining = total_len - pos;

        if remaining > width {
            // --- Line wrapping needed ---
            //
            // The C code:
            //   size_t cut = width - 1;
            //   while(!ISBLANK(ptr[cut]) && cut) { cut--; }
            //   if(cut == 0) cut = width - 1;
            let mut cut = width - 1;

            // Search backward for a blank character to wrap at a word
            // boundary.
            while cut > 0 && !is_blank(msg_bytes[pos + cut]) {
                cut -= 1;
            }

            if cut == 0 {
                // No suitable blank found in the search range — hard-cut
                // at the maximum text width.
                // C: `if(cut == 0) cut = width - 1;`
                cut = width - 1;
            }

            // Write `cut + 1` bytes (up to and including the blank or
            // the hard-cut boundary character) followed by a newline.
            //
            // Slice safety: `pos + cut + 1 <= total_len` holds because
            // `remaining > width` guarantees `remaining >= width`, and
            // `cut + 1 <= width` (since `cut <= width - 1`).
            tool_stderr_write(&msg[pos..pos + cut + 1]);
            tool_stderr_write("\n");

            // Advance past the written bytes.  When we wrapped at a
            // blank, this also consumes the blank character itself —
            // matching the C comment "skip the space too":
            //   ptr += cut + 1;
            //   len -= cut + 1;
            pos += cut + 1;
        } else {
            // --- Remaining text fits on one line ---
            //
            // C: `fputs(ptr, tool_stderr); fputs("\n", tool_stderr); len = 0;`
            tool_stderr_write(&msg[pos..]);
            tool_stderr_write("\n");
            // All text consumed — exit the loop.
            pos = total_len;
        }
    }
}

// ---------------------------------------------------------------------------
// Public diagnostic functions
// ---------------------------------------------------------------------------

/// Emit a warning message to the tool's stderr stream unless `--silent`
/// (`-s`) mode is active.
///
/// Rust equivalent of `warnf()` in `src/tool_msgs.c`:
/// ```c
/// void warnf(const char *fmt, ...)
/// {
///     if(!global->silent) {
///         voutf(WARN_PREFIX, fmt, ap);
///     }
/// }
/// ```
///
/// The message is pre-formatted before calling this function.  Use the
/// [`warnf!`] macro for ergonomic `format_args!`-style usage.
///
/// # Arguments
///
/// * `global` — Global configuration; if `global.silent` is `true`, the
///   warning is suppressed.
/// * `msg` — Pre-formatted warning message text (must not contain `\n`).
///
/// # Output Format
///
/// Each (possibly wrapped) line is prefixed with `"Warning: "`:
/// ```text
/// Warning: some message here
/// ```
pub fn warnf(global: &GlobalConfig, msg: &str) {
    if !global.silent {
        voutf(WARN_PREFIX, msg);
    }
}

/// Emit a note message to the tool's stderr stream when verbose or
/// trace output is enabled.
///
/// Rust equivalent of `notef()` in `src/tool_msgs.c`:
/// ```c
/// void notef(const char *fmt, ...)
/// {
///     if(global->tracetype) {
///         voutf(NOTE_PREFIX, fmt, ap);
///     }
/// }
/// ```
///
/// In the C implementation, `global->tracetype` is treated as a boolean:
/// any non-zero trace type (`Ascii`, `Plain`, or `Verbose`) enables note
/// output.  [`TraceType::None`] (value 0) suppresses notes.
///
/// # Arguments
///
/// * `global` — Global configuration; notes are emitted only when
///   `global.tracetype` is not [`TraceType::None`].
/// * `msg` — Pre-formatted note message text (must not contain `\n`).
///
/// # Output Format
///
/// Each (possibly wrapped) line is prefixed with `"Note: "`:
/// ```text
/// Note: some informational note
/// ```
pub fn notef(global: &GlobalConfig, msg: &str) {
    // C treats `global->tracetype` as boolean: 0 = none = suppress.
    if global.tracetype != TraceType::None {
        voutf(NOTE_PREFIX, msg);
    }
}

/// Emit an error message to the tool's stderr stream unless stderr is
/// muted without `--show-error` (`-S`).
///
/// Rust equivalent of `errorf()` in `src/tool_msgs.c`:
/// ```c
/// void errorf(const char *fmt, ...)
/// {
///     if(!global->silent || global->showerror) {
///         voutf(ERROR_PREFIX, fmt, ap);
///     }
/// }
/// ```
///
/// Error output is suppressed only when `global.silent` is `true`
/// **and** `global.showerror` is `false`.  If either condition allows
/// output, the error is printed.
///
/// # Arguments
///
/// * `global` — Global configuration controlling silent/show-error.
/// * `msg` — Pre-formatted error message text (must not contain `\n`).
///
/// # Output Format
///
/// Each (possibly wrapped) line is prefixed with `"curl: "`:
/// ```text
/// curl: (7) Failed to connect to host port 80
/// ```
pub fn errorf(global: &GlobalConfig, msg: &str) {
    if !global.silent || global.showerror {
        voutf(ERROR_PREFIX, msg);
    }
}

/// Emit a help message followed by the "try 'curl --help'" hint.
///
/// Rust equivalent of `helpf()` in `src/tool_msgs.c`:
/// ```c
/// void helpf(const char *fmt, ...)
/// {
///     if(fmt) {
///         fputs("curl: ", tool_stderr);
///         curl_mvfprintf(tool_stderr, fmt, ap);
///         fputs("\n", tool_stderr);
///     }
///     curl_mfprintf(tool_stderr,
///         "curl: try 'curl --help' or 'curl --manual' "
///         "for more information\n");
/// }
/// ```
///
/// Unlike [`warnf`]/[`notef`]/[`errorf`], `helpf` does **not** use
/// `voutf` and therefore does **not** perform terminal-width line
/// wrapping.  It also does not check `global.silent` — help hints
/// are always printed regardless of silent mode.
///
/// `USE_MANUAL` is always defined in the Rust build (per AAP Section
/// 0.7.3), so the hint line always includes `or 'curl --manual'`.
///
/// # Arguments
///
/// * `msg` — Optional pre-formatted message.  When `Some`, it is
///   printed as `curl: {msg}\n`.  When `None`, only the hint line is
///   printed.
///
/// # Output Format
///
/// ```text
/// curl: unknown option '--foo'
/// curl: try 'curl --help' or 'curl --manual' for more information
/// ```
pub fn helpf(msg: Option<&str>) {
    if let Some(text) = msg {
        tool_stderr_write("curl: ");
        tool_stderr_write(text);
        tool_stderr_write("\n");
    }
    tool_stderr_write(HELP_HINT);
}

// ---------------------------------------------------------------------------
// Convenience macros
//
// These macros wrap the public functions above with `format!`-style
// argument support, replacing the C variadic `(const char *fmt, ...)`
// pattern.  `#[macro_export]` places them at the crate root so they
// can be used from any module via `crate::warnf!(...)`.
// ---------------------------------------------------------------------------

/// Convenience macro for [`warnf`] with `format!`-style arguments.
///
/// # Examples
///
/// ```ignore
/// warnf!(global, "option {} is deprecated", opt_name);
/// warnf!(global, "simple warning without parameters");
/// ```
#[macro_export]
macro_rules! warnf {
    ($global:expr, $($arg:tt)*) => {
        $crate::msgs::warnf($global, &format!($($arg)*))
    };
}

/// Convenience macro for [`notef`] with `format!`-style arguments.
///
/// # Examples
///
/// ```ignore
/// notef!(global, "using HTTP/2 for {}", url);
/// ```
#[macro_export]
macro_rules! notef {
    ($global:expr, $($arg:tt)*) => {
        $crate::msgs::notef($global, &format!($($arg)*))
    };
}

/// Convenience macro for [`errorf`] with `format!`-style arguments.
///
/// # Examples
///
/// ```ignore
/// errorf!(global, "(7) Failed to connect to {} port {}", host, port);
/// ```
#[macro_export]
macro_rules! errorf {
    ($global:expr, $($arg:tt)*) => {
        $crate::msgs::errorf($global, &format!($($arg)*))
    };
}

/// Convenience macro for [`helpf`] with optional `format!`-style
/// arguments.
///
/// When invoked with no arguments, only the "try --help" hint line is
/// printed.  When invoked with a format string and arguments, the
/// formatted message is printed first.
///
/// # Examples
///
/// ```ignore
/// // With message:
/// helpf!("unknown option '{}'", opt);
/// // Without message (hint line only):
/// helpf!();
/// ```
#[macro_export]
macro_rules! helpf {
    () => {
        $crate::msgs::helpf(None)
    };
    ($($arg:tt)*) => {
        $crate::msgs::helpf(Some(&format!($($arg)*)))
    };
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        OperationConfig, TerminalState, TransferState, PARALLEL_DEFAULT,
    };
    use crate::libinfo::LibCurlInfo;
    use crate::stderr::{tool_init_stderr, tool_set_stderr, tool_stderr_close};
    use std::fs;

    /// Construct a `GlobalConfig` for testing without calling
    /// `globalconf_init()` (which depends on the library being
    /// properly initialised).  All fields use safe defaults; callers
    /// adjust `silent`, `showerror`, `tracetype` as needed.
    fn make_test_global() -> GlobalConfig {
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
            silent: false,
            noprogress: false,
            isatty: false,
            trace_set: false,
            libcurl_info: LibCurlInfo::default(),
            term: TerminalState::new(),
            libcurl_version: None,
        }
    }

    // ---------------------------------------------------------------
    // Constant verification
    // ---------------------------------------------------------------

    /// Prefix constants must match curl 8.x tool_msgs.c exactly.
    #[test]
    fn prefix_constants_match_c() {
        assert_eq!(WARN_PREFIX, "Warning: ");
        assert_eq!(NOTE_PREFIX, "Note: ");
        assert_eq!(ERROR_PREFIX, "curl: ");
    }

    /// The help hint line must include both --help and --manual.
    #[test]
    fn help_hint_content() {
        assert!(HELP_HINT.contains("curl --help"));
        assert!(HELP_HINT.contains("curl --manual"));
        assert!(HELP_HINT.ends_with('\n'));
        assert_eq!(
            HELP_HINT,
            "curl: try 'curl --help' or 'curl --manual' for more information\n"
        );
    }

    // ---------------------------------------------------------------
    // is_blank tests
    // ---------------------------------------------------------------

    #[test]
    fn is_blank_space() {
        assert!(is_blank(b' '));
    }

    #[test]
    fn is_blank_tab() {
        assert!(is_blank(b'\t'));
    }

    #[test]
    fn is_blank_non_blank() {
        assert!(!is_blank(b'a'));
        assert!(!is_blank(b'Z'));
        assert!(!is_blank(b'0'));
        assert!(!is_blank(b'-'));
        assert!(!is_blank(b'\n'));
        assert!(!is_blank(b'\r'));
        assert!(!is_blank(b'\0'));
    }

    // ---------------------------------------------------------------
    // Prefix length verification
    // ---------------------------------------------------------------

    #[test]
    fn prefix_lengths() {
        assert_eq!(WARN_PREFIX.len(), 9);  // W-a-r-n-i-n-g-:-space
        assert_eq!(NOTE_PREFIX.len(), 6);  // N-o-t-e-:-space
        assert_eq!(ERROR_PREFIX.len(), 6); // c-u-r-l-:-space
    }

    // ---------------------------------------------------------------
    // Control-flow logic tests (no output capture needed)
    // ---------------------------------------------------------------

    /// warnf with silent=false should not panic.
    #[test]
    fn warnf_not_silent_does_not_panic() {
        tool_init_stderr();
        let global = make_test_global();
        warnf(&global, "test warning");
    }

    /// warnf with silent=true should silently do nothing.
    #[test]
    fn warnf_silent_suppresses() {
        tool_init_stderr();
        let mut global = make_test_global();
        global.silent = true;
        warnf(&global, "suppressed warning");
    }

    /// notef with TraceType::None should suppress output.
    #[test]
    fn notef_none_suppresses() {
        tool_init_stderr();
        let global = make_test_global(); // tracetype defaults to None
        notef(&global, "suppressed note");
    }

    /// notef with any non-None TraceType should output.
    #[test]
    fn notef_verbose_outputs() {
        tool_init_stderr();
        let mut global = make_test_global();
        global.tracetype = TraceType::Verbose;
        notef(&global, "verbose note");
    }

    /// notef with TraceType::Ascii should output.
    #[test]
    fn notef_ascii_outputs() {
        tool_init_stderr();
        let mut global = make_test_global();
        global.tracetype = TraceType::Ascii;
        notef(&global, "ascii note");
    }

    /// notef with TraceType::Plain should output.
    #[test]
    fn notef_plain_outputs() {
        tool_init_stderr();
        let mut global = make_test_global();
        global.tracetype = TraceType::Plain;
        notef(&global, "plain note");
    }

    /// errorf with !silent should output.
    #[test]
    fn errorf_not_silent_outputs() {
        tool_init_stderr();
        let global = make_test_global();
        errorf(&global, "error msg");
    }

    /// errorf with silent=true and showerror=false should suppress.
    #[test]
    fn errorf_silent_no_showerror_suppresses() {
        tool_init_stderr();
        let mut global = make_test_global();
        global.silent = true;
        global.showerror = false;
        errorf(&global, "suppressed error");
    }

    /// errorf with silent=true and showerror=true should still output.
    #[test]
    fn errorf_silent_with_showerror_outputs() {
        tool_init_stderr();
        let mut global = make_test_global();
        global.silent = true;
        global.showerror = true;
        errorf(&global, "error despite silent");
    }

    /// helpf with Some message should not panic.
    #[test]
    fn helpf_with_message() {
        tool_init_stderr();
        helpf(Some("unknown option"));
    }

    /// helpf with None should not panic.
    #[test]
    fn helpf_without_message() {
        tool_init_stderr();
        helpf(None);
    }

    /// Empty messages must not crash any function.
    #[test]
    fn empty_messages_are_safe() {
        tool_init_stderr();
        let global = make_test_global();
        warnf(&global, "");
        errorf(&global, "");
        helpf(Some(""));
        helpf(None);
    }

    // ---------------------------------------------------------------
    // Output capture tests via stderr redirection to temp file
    // ---------------------------------------------------------------

    /// Helper: redirect stderr to a temp file, run a closure, then
    /// read the file content.  Restores stderr after capture.
    fn capture_stderr<F: FnOnce()>(f: F) -> String {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capture.txt");
        let path_str = path.to_str().unwrap();

        tool_init_stderr();
        tool_set_stderr(path_str).unwrap();

        f();

        tool_stderr_close();
        tool_init_stderr();

        fs::read_to_string(&path).unwrap()
    }

    #[test]
    fn warnf_output_format() {
        let output = capture_stderr(|| {
            let global = make_test_global();
            warnf(&global, "test warning");
        });
        assert_eq!(output, "Warning: test warning\n");
    }

    #[test]
    fn errorf_output_format() {
        let output = capture_stderr(|| {
            let global = make_test_global();
            errorf(&global, "(7) Failed to connect");
        });
        assert_eq!(output, "curl: (7) Failed to connect\n");
    }

    #[test]
    fn notef_output_format() {
        let output = capture_stderr(|| {
            let mut global = make_test_global();
            global.tracetype = TraceType::Verbose;
            notef(&global, "using HTTP/2");
        });
        assert_eq!(output, "Note: using HTTP/2\n");
    }

    #[test]
    fn helpf_output_with_message() {
        let output = capture_stderr(|| {
            helpf(Some("unknown option '--foo'"));
        });
        assert_eq!(
            output,
            "curl: unknown option '--foo'\n\
             curl: try 'curl --help' or 'curl --manual' for more information\n"
        );
    }

    #[test]
    fn helpf_output_without_message() {
        let output = capture_stderr(|| {
            helpf(None);
        });
        assert_eq!(
            output,
            "curl: try 'curl --help' or 'curl --manual' for more information\n"
        );
    }

    #[test]
    fn warnf_silent_no_output() {
        let output = capture_stderr(|| {
            let mut global = make_test_global();
            global.silent = true;
            warnf(&global, "should not appear");
        });
        assert_eq!(output, "");
    }

    #[test]
    fn notef_none_no_output() {
        let output = capture_stderr(|| {
            let global = make_test_global(); // tracetype = None
            notef(&global, "should not appear");
        });
        assert_eq!(output, "");
    }

    #[test]
    fn errorf_silent_no_showerror_no_output() {
        let output = capture_stderr(|| {
            let mut global = make_test_global();
            global.silent = true;
            global.showerror = false;
            errorf(&global, "should not appear");
        });
        assert_eq!(output, "");
    }

    #[test]
    fn errorf_silent_with_showerror_produces_output() {
        let output = capture_stderr(|| {
            let mut global = make_test_global();
            global.silent = true;
            global.showerror = true;
            errorf(&global, "(6) Could not resolve host");
        });
        assert_eq!(output, "curl: (6) Could not resolve host\n");
    }

    /// Verify that voutf wraps long lines at word boundaries.
    /// We set COLUMNS=40 so that the available width for "Warning: "
    /// (9 chars prefix) is 31 characters.
    #[test]
    fn voutf_wraps_at_word_boundary() {
        // Save original env
        let orig = std::env::var("COLUMNS").ok();

        // Set terminal width to 40.  Prefix "Warning: " is 9 chars,
        // so available text width is 31.
        std::env::set_var("COLUMNS", "40");

        let output = capture_stderr(|| {
            let global = make_test_global();
            // 41 chars total = "This is a long warning message that wrap"
            // but with available width 31, it should wrap.
            warnf(&global, "This is a long warning message that wraps around");
        });

        // Restore env
        match orig {
            Some(v) => std::env::set_var("COLUMNS", v),
            None => std::env::remove_var("COLUMNS"),
        }

        // The output should contain multiple "Warning: " prefixed lines.
        let lines: Vec<&str> = output.lines().collect();
        assert!(
            lines.len() >= 2,
            "expected wrapped output to have >= 2 lines, got {}: {:?}",
            lines.len(),
            lines
        );
        // Every line should start with "Warning: "
        for line in &lines {
            assert!(
                line.starts_with("Warning: "),
                "line should start with 'Warning: ': {:?}",
                line
            );
        }
    }

    /// Verify that short messages are NOT wrapped.
    #[test]
    fn voutf_no_wrap_for_short_message() {
        let orig = std::env::var("COLUMNS").ok();
        std::env::set_var("COLUMNS", "80");

        let output = capture_stderr(|| {
            let global = make_test_global();
            warnf(&global, "short");
        });

        match orig {
            Some(v) => std::env::set_var("COLUMNS", v),
            None => std::env::remove_var("COLUMNS"),
        }

        assert_eq!(output, "Warning: short\n");
    }

    /// Empty message should produce no output at all (no prefix, no
    /// newline), matching the C while(len > 0) which skips the loop.
    #[test]
    fn voutf_empty_message_no_output() {
        let output = capture_stderr(|| {
            let global = make_test_global();
            warnf(&global, "");
        });
        assert_eq!(output, "");
    }
}
