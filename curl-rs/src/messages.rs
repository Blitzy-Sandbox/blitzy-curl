// curl-rs — CLI diagnostic message + stderr facility.
//
// SPDX-License-Identifier: curl
//
// This module is the Rust reimplementation of curl's command-line diagnostics
// facility. The original C sources are
//   Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// and are licensed under the curl license (https://curl.se/docs/copyright.html).
//
// It is the behavioral port of two C translation units of the `src/` CLI tree:
//   * `src/tool_msgs.c` / `src/tool_msgs.h` — the `warnf` / `notef` / `helpf` /
//     `errorf` diagnostic family and the shared `voutf` word-wrapping writer.
//   * `src/tool_stderr.c` / `src/tool_stderr.h` — the `tool_stderr` diagnostic
//     stream plus its `tool_init_stderr` initializer and `tool_set_stderr_file`
//     (`--stderr`) redirector.
//
// The folder requirements (AAP §0.4.1 narrative) explicitly permit this as "a
// tiny helper module the implementer may add" so the diagnostics are
// centralized rather than duplicated. It is REQUIRED for the mandatory
// `--insecure` stderr warning (AAP §0.7.3, §0.8.1) and for every other CLI
// diagnostic. The C constructs are consumed as a behavioral oracle, not
// transliterated: C varargs become Rust `&str` + `format!` (exposed through the
// `warnf!` / `notef!` / `errorf!` / `helpf!` macros), the file-scope
// `FILE *tool_stderr` global becomes a safe process-global
// `OnceLock<Mutex<ErrorStream>>`, and the gating `global` pointer becomes a
// borrowed [`GlobalConfig`]. No prefix, gating condition, wrap behavior, or exit
// path is altered (the observable-I/O-parity mandate, AAP §0.7.3 / §0.8.2).

//! Diagnostic message and `stderr` facility for `curl-rs`.
//!
//! This module centralizes every command-line diagnostic so the byte-for-byte
//! output of `curl` is reproduced exactly. It mirrors curl's `src/tool_msgs.c`
//! and `src/tool_stderr.c`.
//!
//! # The four diagnostic functions
//!
//! Each corresponds 1:1 to a curl entry point and applies curl's exact emit
//! gating against the borrowed [`GlobalConfig`]:
//!
//! | Function          | curl origin | Prefix       | Emitted when                         |
//! |-------------------|-------------|--------------|--------------------------------------|
//! | [`warnf`]         | `warnf`     | `"Warning: "`| `!cfg.silent`                        |
//! | [`notef`]         | `notef`     | `"Note: "`   | `cfg.tracetype != TraceType::None`   |
//! | [`errorf`]        | `errorf`    | `"curl: "`   | `!cfg.silent || cfg.showerror`       |
//! | [`helpf`]         | `helpf`     | `"curl: "`   | always (message part only if present)|
//!
//! Because Rust has no C `printf`-style varargs, callers either pass an
//! already-formatted `&str` to the functions or — more ergonomically — use the
//! [`warnf!`], [`notef!`], [`errorf!`], and [`helpf!`] macros, which accept
//! [`format!`](std::format)-style arguments and forward to the functions. The
//! emit gating lives in the functions (not the macros) so it stays unit-testable.
//!
//! # The diagnostic stream (`--stderr`)
//!
//! curl writes diagnostics to a file-scope `FILE *tool_stderr` that defaults to
//! the process `stderr` and may be redirected by `--stderr`. This module models
//! the same single shared sink as a process-global [`ErrorStream`] guarded by a
//! [`Mutex`](std::sync::Mutex) inside a [`OnceLock`](std::sync::OnceLock):
//!
//! * [`init_stderr`] resets the sink to `stderr` (mirrors `tool_init_stderr`).
//! * [`set_stderr_file`] implements `--stderr` (mirrors `tool_set_stderr_file`):
//!   `"-"` routes diagnostics to `stdout`; any other name opens that file; an
//!   open failure warns and keeps `stderr`.
//!
//! A process-global sink (rather than a field on [`GlobalConfig`]) is the design
//! the AAP sanctions as the safe alternative: it keeps the dependency
//! `config.rs` unmodified, requires no `unsafe` (both `OnceLock` and `Mutex` are
//! safe), and reproduces curl's actual file-scope-global structure. The sink is
//! `Send`-safe so diagnostics emitted from runtime worker threads (parallel
//! transfers) serialize correctly behind the mutex, even though the CLI's own
//! path is single-threaded (`#[tokio::main(flavor = "current_thread")]`).
//!
//! # Word wrapping
//!
//! [`warnf`], [`notef`], and [`errorf`] route through curl's `voutf` word-wrap
//! ([`wrap_message`]), which folds long messages to the terminal width minus the
//! prefix width. [`helpf`] does **not** wrap (matching curl). See
//! [`wrap_message`] and [`terminal_columns`] for the exact, parity-faithful
//! algorithm.

use std::fs::File;
use std::io::{self, Write};
use std::sync::{Mutex, OnceLock};

use crate::config::{GlobalConfig, TraceType};

// ===========================================================================
// Diagnostic prefixes and limits (mirrored verbatim from `src/tool_msgs.c`).
// The trailing space in each prefix is significant and part of the parity
// contract — do not trim it.
// ===========================================================================

/// Prefix for [`warnf`] output (`WARN_PREFIX`, `src/tool_msgs.c`).
const WARN_PREFIX: &str = "Warning: ";

/// Prefix for [`notef`] output (`NOTE_PREFIX`, `src/tool_msgs.c`).
const NOTE_PREFIX: &str = "Note: ";

/// Prefix for [`errorf`] output (`ERROR_PREFIX`, `src/tool_msgs.c`).
const ERROR_PREFIX: &str = "curl: ";

/// Prefix curl prepends to the optional message line of [`helpf`]
/// (the literal `"curl: "` in `helpf`, `src/tool_msgs.c`).
const HELP_PREFIX: &str = "curl: ";

/// The fixed trailer [`helpf`] always emits.
///
/// curl conditionally inserts `"or 'curl --manual' "` only when the built-in
/// manual is compiled in (`#ifdef USE_MANUAL`, `src/tool_msgs.c`). For the
/// initial Rust port the manual is not built in (matching `#ifndef USE_MANUAL`),
/// so the `--manual` clause is intentionally omitted; the remaining text is
/// reproduced byte-for-byte.
const HELP_TRAILER: &str = "curl: try 'curl --help' for more information\n";

/// Maximum number of message bytes considered, reproducing curl's fixed
/// `char buffer[1024]` in `voutf`: `curl_mvsnprintf` stores at most
/// `sizeof(buffer) - 1` content bytes and returns that capped length
/// (`lib/mprintf.c`), so any message of 1024 bytes or more is truncated to
/// 1023 before wrapping.
const MAX_MSG_LEN: usize = 1023;

/// Fallback terminal width used when the width cannot be determined, matching
/// curl's `get_terminal_columns()` default of `79` (`src/terminal.c`).
const DEFAULT_TERMINAL_COLUMNS: usize = 79;

/// Upper bound curl accepts for a `COLUMNS` value, mirroring the `max` argument
/// curl passes to `curlx_str_number(&p, &num, 10000)` in `get_terminal_columns`
/// (`src/terminal.c`). A parsed value greater than this is rejected.
const MAX_COLUMNS: usize = 10000;

/// Smallest `COLUMNS` value curl will honor; `get_terminal_columns` requires
/// `num > 20` (`src/terminal.c`).
const MIN_COLUMNS: usize = 20;

// ===========================================================================
// Diagnostic stream — the Rust analog of the file-scope `FILE *tool_stderr`.
// ===========================================================================

/// The destination for diagnostic output — the Rust analog of curl's
/// `FILE *tool_stderr` (`src/tool_stderr.c`).
///
/// curl points `tool_stderr` at the process `stderr` by default, at `stdout`
/// for `--stderr -`, or at an opened file for `--stderr <file>`. This enum
/// captures those three states. It is `Send` (the [`File`] handle is `Send`),
/// so it can live behind a process-global mutex and be written from any thread.
#[derive(Debug)]
enum ErrorStream {
    /// Diagnostics go to the process standard error (curl's default and the
    /// state after a successful `tool_init_stderr`).
    Stderr,
    /// Diagnostics go to the process standard output (`--stderr -`).
    Stdout,
    /// Diagnostics go to the opened file (`--stderr <file>`).
    File(File),
}

impl ErrorStream {
    /// Writes the complete diagnostic byte sequence and flushes it.
    ///
    /// The bytes are pre-rendered by [`wrap_message`] / [`format_help`], so this
    /// performs a single `write_all` against the active destination. The handle
    /// is flushed because C `stderr` is unbuffered: diagnostics must appear in
    /// the correct order relative to transfer output rather than linger in a
    /// buffer.
    fn write_diagnostic(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            // `stderr()`/`stdout()` return locked, shared handles; locking once
            // here keeps the whole diagnostic atomic with respect to other
            // writers using the same standard stream.
            ErrorStream::Stderr => {
                let mut handle = io::stderr().lock();
                handle.write_all(bytes)?;
                handle.flush()
            }
            ErrorStream::Stdout => {
                let mut handle = io::stdout().lock();
                handle.write_all(bytes)?;
                handle.flush()
            }
            ErrorStream::File(file) => {
                file.write_all(bytes)?;
                file.flush()
            }
        }
    }
}

/// Returns the process-global diagnostic sink, initializing it to
/// [`ErrorStream::Stderr`] on first access.
///
/// Lazy initialization to `stderr` means a diagnostic emitted before an explicit
/// [`init_stderr`] still goes somewhere sensible (curl's equivalent would
/// dereference a `NULL` `tool_stderr`); `init_stderr` and [`set_stderr_file`]
/// then overwrite the state as needed.
fn sink() -> &'static Mutex<ErrorStream> {
    static SINK: OnceLock<Mutex<ErrorStream>> = OnceLock::new();
    SINK.get_or_init(|| Mutex::new(ErrorStream::Stderr))
}

/// Acquires the diagnostic sink, recovering from a poisoned mutex.
///
/// A panic while another thread held the lock must not silence every subsequent
/// diagnostic, so a poisoned lock is recovered via
/// [`PoisonError::into_inner`](std::sync::PoisonError::into_inner); the
/// [`ErrorStream`] state itself is never left inconsistent by a write.
fn lock_sink() -> std::sync::MutexGuard<'static, ErrorStream> {
    sink()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Writes a fully-rendered diagnostic to the active sink, ignoring I/O errors.
///
/// curl ignores the return value of its `fputs`/`fwrite` diagnostic writes, so a
/// failed write here is likewise swallowed: a broken diagnostic stream must not
/// change the program's result.
fn write_to_sink(bytes: &[u8]) {
    let _ = lock_sink().write_diagnostic(bytes);
}

/// Writes raw, pre-rendered bytes to the active diagnostic stream (the one
/// `--stderr` controls), without adding any `curl: `/`Warning: ` prefix.
///
/// This is the analog of curl's direct `curl_mfprintf(tool_stderr, …)` writes
/// (e.g. the "Cannot comply. This curl was built without built-in manual"
/// message in `tool_help.c`'s option-help branch). Like the other sink writers
/// it swallows I/O errors, matching curl's unchecked diagnostic writes.
pub(crate) fn emit_raw(bytes: &[u8]) {
    write_to_sink(bytes);
}

/// Initializes the diagnostic stream to the process `stderr`.
///
/// Mirrors `tool_init_stderr()` (`src/tool_stderr.c`), called once near process
/// start (curl invokes it from `main`, `src/tool_main.c`). It is idempotent and
/// also resets the sink if a prior [`set_stderr_file`] had redirected it.
pub fn init_stderr() {
    *lock_sink() = ErrorStream::Stderr;
}

/// Redirects the diagnostic stream per the `--stderr` option.
///
/// Mirrors `tool_set_stderr_file()` (`src/tool_stderr.c`):
///
/// * `filename == "-"` routes diagnostics to `stdout`.
/// * any other name opens (creating/truncating) that file for writing and
///   routes diagnostics there. curl uses `freopen` with `FOPEN_WRITETEXT`; on
///   Unix that is a plain truncating text-mode open, which
///   [`File::create`](std::fs::File::create) reproduces. (On Windows curl would
///   additionally translate `\n` to `\r\n`; the Rust port writes LF unchanged,
///   matching the Unix/Linux behavior the test suite exercises.)
/// * if the file cannot be opened, curl emits
///   `warnf("Warning: Failed to open %s", filename)` and keeps `stderr`. Note
///   that [`warnf`] itself prepends `"Warning: "`, so the emitted line is
///   `"Warning: Warning: Failed to open <file>"` — this doubled prefix is
///   curl's actual behavior and is reproduced verbatim for byte-for-byte parity.
///
/// `cfg` supplies the gating state for that failure warning (so `--silent`
/// suppresses it exactly as in curl, where `warnf` consults the global config).
pub fn set_stderr_file(cfg: &GlobalConfig, filename: &str) {
    if filename == "-" {
        *lock_sink() = ErrorStream::Stdout;
        return;
    }

    // Open (create/truncate) the target. The sink lock is deliberately NOT held
    // across the open, because the failure path calls `warnf`, which acquires
    // the same lock — holding it here would deadlock.
    match File::create(filename) {
        Ok(file) => *lock_sink() = ErrorStream::File(file),
        Err(_) => warnf(cfg, &format!("Warning: Failed to open {filename}")),
    }
}

// ===========================================================================
// The four diagnostic functions. Each reproduces the emit gating of its curl
// counterpart in `src/tool_msgs.c` exactly; the gating lives here (not in the
// convenience macros) so it can be unit-tested.
// ===========================================================================

/// Emits a `Warning:` diagnostic unless `--silent` was given.
///
/// Mirrors `warnf()` in `src/tool_msgs.c`: emitted with the `"Warning: "`
/// prefix and word-wrapped to the terminal width (see [`wrap_message`]), but
/// only when `!cfg.silent`.
///
/// Prefer the [`warnf!`] macro at call sites so the message can be composed with
/// [`format!`](std::format)-style arguments.
pub fn warnf(cfg: &GlobalConfig, msg: &str) {
    if !cfg.silent {
        emit(WARN_PREFIX, msg);
    }
}

/// Emits a `Note:` diagnostic when verbose/trace output is enabled.
///
/// Mirrors `notef()` in `src/tool_msgs.c`: emitted with the `"Note: "` prefix
/// and word-wrapped, but only when tracing is active. curl tests
/// `if(global->tracetype)`; the Rust equivalent is
/// `cfg.tracetype != TraceType::None`, since [`TraceType::None`] is the zero
/// discriminant.
///
/// Prefer the [`notef!`] macro at call sites.
pub fn notef(cfg: &GlobalConfig, msg: &str) {
    if cfg.tracetype != TraceType::None {
        emit(NOTE_PREFIX, msg);
    }
}

/// Emits a `curl:` error diagnostic unless muted.
///
/// Mirrors `errorf()` in `src/tool_msgs.c`: emitted with the `"curl: "` prefix
/// and word-wrapped, when `!cfg.silent || cfg.showerror` (i.e. unless silent,
/// but always when `--show-error` forced errors on). Errors tied to command-line
/// arguments use [`helpf`] instead.
///
/// Prefer the [`errorf!`] macro at call sites.
pub fn errorf(cfg: &GlobalConfig, msg: &str) {
    if !cfg.silent || cfg.showerror {
        emit(ERROR_PREFIX, msg);
    }
}

/// Emits a command-line usage diagnostic with the fixed help trailer.
///
/// Mirrors `helpf()` in `src/tool_msgs.c`. When `msg` is [`Some`], the message
/// is printed first as `"curl: " + msg + "\n"` (single line, **not**
/// word-wrapped, exactly like curl's direct `fputs`/`curl_mvfprintf`). The fixed
/// trailer ([`HELP_TRAILER`]) is then **always** printed regardless of `msg`.
///
/// Unlike the other three functions, `helpf` is **not** gated on `--silent`
/// (curl's `helpf` consults no global state and always writes), so it takes no
/// [`GlobalConfig`]. The message must be a single line; in debug builds an
/// embedded newline trips a `debug_assert!` mirroring curl's `DEBUGASSERT`.
///
/// Prefer the [`helpf!`] macro at call sites: `helpf!()` for the trailer alone,
/// or `helpf!("bad option: {}", opt)` to include a message.
pub fn helpf(msg: Option<&str>) {
    write_to_sink(&format_help(msg));
}

// ===========================================================================
// Convenience macros bridging C's `printf`-style varargs to Rust `format!`.
// They accept `format!`-style arguments and forward to the gating functions
// above, keeping call sites terse (e.g. `warnf!(global, "Failed to open {}",
// path);`). `#[macro_export]` places them at the crate root and exempts them
// from the `unused_macros` lint until call sites are wired in later steps.
// ===========================================================================

/// Formats its arguments with [`format!`](std::format) and forwards to
/// [`warnf`]. See [`warnf`] for the emit gating.
///
/// `$cfg` must be a `&GlobalConfig` expression; the remaining arguments are a
/// [`format!`](std::format) format string and its arguments.
#[macro_export]
macro_rules! warnf {
    ($cfg:expr, $($arg:tt)*) => {
        $crate::messages::warnf($cfg, &::std::format!($($arg)*))
    };
}

/// Formats its arguments with [`format!`](std::format) and forwards to
/// [`notef`]. See [`notef`] for the emit gating.
#[macro_export]
macro_rules! notef {
    ($cfg:expr, $($arg:tt)*) => {
        $crate::messages::notef($cfg, &::std::format!($($arg)*))
    };
}

/// Formats its arguments with [`format!`](std::format) and forwards to
/// [`errorf`]. See [`errorf`] for the emit gating.
#[macro_export]
macro_rules! errorf {
    ($cfg:expr, $($arg:tt)*) => {
        $crate::messages::errorf($cfg, &::std::format!($($arg)*))
    };
}

/// Forwards to [`helpf`]. `helpf!()` prints the trailer alone; `helpf!(fmt,
/// ...)` formats a message with [`format!`](std::format) and prints it before
/// the trailer.
#[macro_export]
macro_rules! helpf {
    () => {
        $crate::messages::helpf(None)
    };
    ($($arg:tt)*) => {
        $crate::messages::helpf(Some(&::std::format!($($arg)*)))
    };
}

// ===========================================================================
// Internal rendering helpers (curl `voutf` + `get_terminal_columns`).
// ===========================================================================

/// Renders `prefix` + `msg` through curl's word-wrap and writes it to the sink.
///
/// This is the shared body of [`warnf`], [`notef`], and [`errorf`] — the analog
/// of curl's `voutf` once gating has passed (`src/tool_msgs.c`).
fn emit(prefix: &str, msg: &str) {
    write_to_sink(&wrap_message(prefix, msg, terminal_columns()));
}

/// Word-wraps `msg` under `prefix` to `termw` columns, returning the exact bytes
/// curl's `voutf` would write (`src/tool_msgs.c`).
///
/// The algorithm is reproduced byte-for-byte:
///
/// * The effective wrap `width` is `termw - prefix.len()` when the terminal is
///   wider than the prefix, otherwise [`usize::MAX`] (curl's `SIZE_MAX`),
///   meaning "never wrap".
/// * `msg` is first capped at [`MAX_MSG_LEN`] bytes, reproducing curl's fixed
///   1024-byte format buffer.
/// * Each output line is `prefix` followed by a chunk and a `\n`. While the
///   remaining length exceeds `width`, the chunk is cut at the last blank
///   (space or tab, curl's `ISBLANK`) at or before `width - 1`; if no blank is
///   found the chunk is hard-cut at `width - 1`. The cut byte (the blank, when
///   one was found) is included in the emitted chunk and then skipped, exactly
///   as curl advances `ptr += cut + 1`. The final chunk (length `<= width`) is
///   emitted whole.
///
/// Operating on bytes (not `char`s) matches curl's `char`-buffer handling and
/// keeps a hard cut from being skewed by multi-byte UTF-8 (the output is raw
/// bytes, so a split sequence is written exactly as curl would write it).
///
/// `msg` must contain no embedded newline; in debug builds this trips a
/// `debug_assert!` mirroring curl's `DEBUGASSERT(!strchr(fmt, '\n'))`.
fn wrap_message(prefix: &str, msg: &str, termw: usize) -> Vec<u8> {
    debug_assert!(
        !msg.contains('\n'),
        "diagnostic message must not contain a newline (mirrors curl's \
         DEBUGASSERT in voutf)"
    );

    let prefw = prefix.len();
    // curl: width = termw > prefw ? termw - prefw : SIZE_MAX.
    let width = if termw > prefw {
        termw - prefw
    } else {
        usize::MAX
    };

    let bytes = msg.as_bytes();
    // curl's `curl_mvsnprintf` caps stored content at sizeof(buffer)-1 == 1023.
    let total = bytes.len().min(MAX_MSG_LEN);

    let mut out = Vec::with_capacity(total + prefw + 2);
    let mut ptr = 0usize; // index of the first unconsumed byte
    let mut len = total; // bytes remaining to emit

    while len > 0 {
        out.extend_from_slice(prefix.as_bytes());

        if len > width {
            // Look for a blank to break on, scanning back from `width - 1`.
            // (Because `len > width`, `width` is the finite terminal-derived
            // value, so `width >= 1` and `width - 1` cannot underflow.)
            let mut cut = width - 1;
            while cut > 0 && !is_blank(bytes[ptr + cut]) {
                cut -= 1;
            }
            if cut == 0 {
                // No blank found anywhere in range: hard-cut at the max width.
                cut = width - 1;
            }

            // Emit bytes [0..=cut] (cut + 1 bytes); the trailing blank, when one
            // was found, is part of this slice and is then skipped.
            out.extend_from_slice(&bytes[ptr..ptr + cut + 1]);
            out.push(b'\n');
            ptr += cut + 1;
            len -= cut + 1;
        } else {
            // Remainder fits on one line.
            out.extend_from_slice(&bytes[ptr..ptr + len]);
            out.push(b'\n');
            len = 0;
        }
    }

    out
}

/// Renders the bytes [`helpf`] writes for the given optional message.
///
/// Returns `"curl: " + msg + "\n"` (when `msg` is [`Some`]) followed by the
/// fixed [`HELP_TRAILER`]; with [`None`], only the trailer. This is the
/// non-wrapping counterpart of [`wrap_message`], factored out so it is
/// unit-testable without touching the process-global sink.
fn format_help(msg: Option<&str>) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(m) = msg {
        debug_assert!(
            !m.contains('\n'),
            "helpf message must not contain a newline (mirrors curl's \
             DEBUGASSERT in helpf)"
        );
        out.extend_from_slice(HELP_PREFIX.as_bytes());
        out.extend_from_slice(m.as_bytes());
        out.push(b'\n');
    }
    out.extend_from_slice(HELP_TRAILER.as_bytes());
    out
}

/// Returns the terminal width to wrap diagnostics at.
///
/// Mirrors `get_terminal_columns()` (`src/terminal.c`) within the constraint
/// that no terminal-size dependency may be added (AAP): the `COLUMNS`
/// environment variable is honored when present and valid, otherwise the width
/// falls back to [`DEFAULT_TERMINAL_COLUMNS`] (`79`). curl's `ioctl`-based
/// auto-detection is intentionally not reproduced; in the test harness `stdin`
/// is not a terminal, so curl's own detection also fails and returns `79`,
/// keeping wrap output identical in the environment that matters for parity.
pub(crate) fn terminal_columns() -> usize {
    if let Ok(columns) = std::env::var("COLUMNS") {
        if let Some(num) = parse_columns(&columns) {
            // curl: honored only when num > 20.
            if num > MIN_COLUMNS {
                return num;
            }
        }
    }
    DEFAULT_TERMINAL_COLUMNS
}

/// Parses a `COLUMNS` value the way curl's `curlx_str_number(&p, &num, 10000)`
/// does (`src/terminal.c` → `lib/curlx/strparse.c`).
///
/// A leading run of base-10 digits is read and the rest of the string is
/// ignored (curl stops at the first non-digit). Parsing fails — returning
/// [`None`], so the caller falls back to the default — when there is no leading
/// digit or when the value would exceed [`MAX_COLUMNS`] (curl's `STRE_OVERFLOW`
/// against `max == 10000`). A successfully parsed value (`<= 10000`) is returned
/// even if it is small; the `> 20` acceptance check is applied by the caller, to
/// match curl's two-step `(!error) && (num > 20)` logic.
fn parse_columns(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    // curl requires the first character to be a digit (`STRE_NO_NUM` otherwise).
    if bytes.is_empty() || !bytes[0].is_ascii_digit() {
        return None;
    }

    let mut num: usize = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            break; // stop at the first non-digit, like curl
        }
        num = num * 10 + usize::from(b - b'0');
        if num > MAX_COLUMNS {
            return None; // curl returns STRE_OVERFLOW for values past max
        }
    }
    Some(num)
}

/// Returns whether `b` is a blank byte, matching curl's `ISBLANK`
/// (`lib/curl_ctype.h`): an ASCII space or horizontal tab.
fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    // -- test helpers --------------------------------------------------------

    /// Decodes rendered diagnostic bytes to a `String` for readable assertions.
    fn s(bytes: Vec<u8>) -> String {
        String::from_utf8(bytes).expect("diagnostic bytes are valid UTF-8 in tests")
    }

    /// Builds a [`GlobalConfig`] carrying the three gating fields this module
    /// reads. Construction is via [`Default`] + field assignment (never a struct
    /// literal) so the same test code compiles against both the real
    /// many-field `GlobalConfig` and any minimal stand-in.
    fn cfg_with(silent: bool, showerror: bool, tracetype: TraceType) -> GlobalConfig {
        GlobalConfig {
            silent,
            showerror,
            tracetype,
            ..Default::default()
        }
    }

    /// Serializes tests that mutate the process-global diagnostic sink so they
    /// do not interfere when the test runner executes them in parallel.
    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A unique temporary file path for sink-redirection tests.
    fn unique_temp_path() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "curl_rs_messages_test_{}_{}.tmp",
            std::process::id(),
            n
        ));
        p
    }

    /// Test-only inspector for the active sink variant.
    fn sink_label() -> &'static str {
        match &*lock_sink() {
            ErrorStream::Stderr => "stderr",
            ErrorStream::Stdout => "stdout",
            ErrorStream::File(_) => "file",
        }
    }

    /// Redirects the diagnostic sink to a fresh temp file, runs `f`, restores
    /// the sink to `stderr`, and returns everything written during `f`.
    /// Serialized via [`test_lock`].
    fn capture<F: FnOnce()>(f: F) -> String {
        let _guard = test_lock();
        let path = unique_temp_path();
        {
            let file = File::create(&path).expect("create temp capture file");
            *lock_sink() = ErrorStream::File(file);
        }
        f();
        // Restore stderr, dropping (closing) the capture file handle.
        init_stderr();
        let captured = std::fs::read_to_string(&path).expect("read capture file");
        let _ = std::fs::remove_file(&path);
        captured
    }

    // -- prefix / constant audit (must match src/tool_msgs.c verbatim) -------

    #[test]
    fn prefixes_match_curl_exactly() {
        assert_eq!(WARN_PREFIX, "Warning: ");
        assert_eq!(NOTE_PREFIX, "Note: ");
        assert_eq!(ERROR_PREFIX, "curl: ");
        assert_eq!(HELP_PREFIX, "curl: ");
        // The trailing space is part of the parity contract.
        assert!(WARN_PREFIX.ends_with(' '));
        assert!(NOTE_PREFIX.ends_with(' '));
        assert!(ERROR_PREFIX.ends_with(' '));
        // No `or 'curl --manual'` clause for the initial port (#ifndef USE_MANUAL).
        assert_eq!(
            HELP_TRAILER,
            "curl: try 'curl --help' for more information\n"
        );
        assert!(!HELP_TRAILER.contains("--manual"));
    }

    // -- is_blank (curl ISBLANK) ---------------------------------------------

    #[test]
    fn is_blank_matches_isblank() {
        assert!(is_blank(b' '));
        assert!(is_blank(b'\t'));
        assert!(!is_blank(b'a'));
        assert!(!is_blank(b'\n'));
        assert!(!is_blank(b'\r'));
        assert!(!is_blank(0));
    }

    // -- wrap_message (curl voutf) byte-for-byte -----------------------------

    #[test]
    fn wrap_short_message_is_single_line() {
        assert_eq!(
            s(wrap_message("Warning: ", "hello", 79)),
            "Warning: hello\n"
        );
    }

    #[test]
    fn wrap_empty_message_emits_nothing() {
        // curl's `while(len > 0)` never runs for an empty message — not even the
        // prefix is written.
        assert_eq!(s(wrap_message("Warning: ", "", 79)), "");
    }

    #[test]
    fn wrap_hard_cut_when_no_blank() {
        // prefix "> " (2), termw 5 => width 3; "abcdef" has no blank.
        assert_eq!(s(wrap_message("> ", "abcdef", 5)), "> abc\n> def\n");
    }

    #[test]
    fn wrap_breaks_on_blank_and_keeps_trailing_blank() {
        // width 4; cut falls on the spaces, which are emitted then skipped.
        assert_eq!(s(wrap_message("", "ab cd ef", 4)), "ab \ncd \nef\n");
    }

    #[test]
    fn wrap_multiline_with_prefix_on_each_line() {
        // prefix "ab: " (4), termw 8 => width 4.
        assert_eq!(
            s(wrap_message("ab: ", "12345 67890", 8)),
            "ab: 1234\nab: 5 \nab: 6789\nab: 0\n"
        );
    }

    #[test]
    fn wrap_never_wraps_when_prefix_at_least_terminal_width() {
        // termw (5) <= prefix width (9) => width = usize::MAX (curl SIZE_MAX).
        let msg = "hello world this is a long line";
        assert_eq!(
            s(wrap_message("Warning: ", msg, 5)),
            format!("Warning: {msg}\n")
        );
    }

    #[test]
    fn wrap_width_boundary_exact_and_plus_one() {
        // len == width: no wrap.
        assert_eq!(s(wrap_message("", "abcd", 4)), "abcd\n");
        // len == width + 1: wraps (hard cut, no blank).
        assert_eq!(s(wrap_message("", "abcde", 4)), "abcd\ne\n");
    }

    #[test]
    fn wrap_caps_message_at_1023_bytes() {
        // curl's fixed 1024-byte buffer stores at most 1023 content bytes.
        let big = "a".repeat(2000);
        let out = wrap_message("", &big, MAX_COLUMNS);
        assert_eq!(out.len(), MAX_MSG_LEN + 1); // 1023 'a' + '\n'
        assert!(out[..MAX_MSG_LEN].iter().all(|&b| b == b'a'));
        assert_eq!(out[MAX_MSG_LEN], b'\n');

        // Exactly 1023 bytes is NOT truncated.
        let exact = "b".repeat(MAX_MSG_LEN);
        assert_eq!(wrap_message("", &exact, MAX_COLUMNS).len(), MAX_MSG_LEN + 1);
        // 1024 bytes is truncated to 1023.
        let over = "c".repeat(MAX_MSG_LEN + 1);
        assert_eq!(wrap_message("", &over, MAX_COLUMNS).len(), MAX_MSG_LEN + 1);
    }

    // -- format_help (curl helpf body) ---------------------------------------

    #[test]
    fn format_help_none_is_trailer_only() {
        assert_eq!(
            s(format_help(None)),
            "curl: try 'curl --help' for more information\n"
        );
    }

    #[test]
    fn format_help_some_prepends_message_line() {
        assert_eq!(
            s(format_help(Some("option --foo: is unknown"))),
            "curl: option --foo: is unknown\n\
             curl: try 'curl --help' for more information\n"
        );
    }

    // -- parse_columns / terminal_columns (curl get_terminal_columns) --------

    #[test]
    fn parse_columns_matches_curlx_str_number() {
        assert_eq!(parse_columns("80"), Some(80));
        assert_eq!(parse_columns("21"), Some(21));
        assert_eq!(parse_columns("20"), Some(20)); // parses; the > 20 gate is the caller's
        assert_eq!(parse_columns("10000"), Some(10000)); // exactly max is accepted
        assert_eq!(parse_columns("10001"), None); // overflow past max => rejected
        assert_eq!(parse_columns("99999"), None);
        assert_eq!(parse_columns("007"), Some(7)); // leading zeroes accepted
        assert_eq!(parse_columns("100abc"), Some(100)); // stops at first non-digit
        assert_eq!(parse_columns(""), None); // no digit
        assert_eq!(parse_columns("abc"), None); // non-digit start
        assert_eq!(parse_columns("x80"), None); // non-digit start
    }

    #[test]
    fn terminal_columns_is_always_above_min() {
        // Honored COLUMNS values are > 20 by construction, and the fallback is
        // 79; the function must therefore never return a width <= 20 that would
        // make the wrap math degenerate.
        assert!(terminal_columns() > MIN_COLUMNS);
    }

    // -- gating: warnf (=> !silent) ------------------------------------------

    #[test]
    fn warnf_emits_unless_silent() {
        let cfg = cfg_with(false, false, TraceType::None);
        let out = capture(|| warnf(&cfg, "hi"));
        assert_eq!(out, s(wrap_message(WARN_PREFIX, "hi", terminal_columns())));
        assert_eq!(out, "Warning: hi\n");

        let silent = cfg_with(true, false, TraceType::None);
        assert_eq!(capture(|| warnf(&silent, "hi")), "");
    }

    // -- gating: notef (=> tracetype != None) --------------------------------

    #[test]
    fn notef_emits_only_when_tracing() {
        let none = cfg_with(false, false, TraceType::None);
        assert_eq!(capture(|| notef(&none, "x")), "");

        for tt in [TraceType::Bin, TraceType::Ascii, TraceType::Plain] {
            let cfg = cfg_with(false, false, tt);
            assert_eq!(capture(|| notef(&cfg, "x")), "Note: x\n");
        }

        // notef ignores --silent; tracetype alone gates it.
        let silent_trace = cfg_with(true, false, TraceType::Plain);
        assert_eq!(capture(|| notef(&silent_trace, "x")), "Note: x\n");
    }

    // -- gating: errorf (=> !silent || showerror) ----------------------------

    #[test]
    fn errorf_emits_unless_silent_without_showerror() {
        // !silent, !showerror => emit
        let a = cfg_with(false, false, TraceType::None);
        assert_eq!(capture(|| errorf(&a, "e")), "curl: e\n");
        // silent, !showerror => suppressed
        let b = cfg_with(true, false, TraceType::None);
        assert_eq!(capture(|| errorf(&b, "e")), "");
        // silent, showerror => emit
        let c = cfg_with(true, true, TraceType::None);
        assert_eq!(capture(|| errorf(&c, "e")), "curl: e\n");
        // !silent, showerror => emit
        let d = cfg_with(false, true, TraceType::None);
        assert_eq!(capture(|| errorf(&d, "e")), "curl: e\n");
    }

    // -- helpf is never gated ------------------------------------------------

    #[test]
    fn helpf_always_emits_trailer() {
        assert_eq!(
            capture(|| helpf(None)),
            "curl: try 'curl --help' for more information\n"
        );
        assert_eq!(
            capture(|| helpf(Some("bad"))),
            "curl: bad\ncurl: try 'curl --help' for more information\n"
        );
        // Even when silent would be set elsewhere, helpf consults no config and
        // still prints (it takes no GlobalConfig at all).
    }

    // -- --stderr redirection (curl tool_set_stderr_file) --------------------

    #[test]
    fn set_stderr_file_dash_routes_to_stdout() {
        let _guard = test_lock();
        let cfg = cfg_with(false, false, TraceType::None);
        init_stderr();
        assert_eq!(sink_label(), "stderr");
        set_stderr_file(&cfg, "-");
        assert_eq!(sink_label(), "stdout");
        init_stderr();
        assert_eq!(sink_label(), "stderr");
    }

    #[test]
    fn set_stderr_file_opens_and_routes_to_file() {
        let _guard = test_lock();
        let cfg = cfg_with(false, false, TraceType::None);
        let path = unique_temp_path();
        init_stderr();
        set_stderr_file(&cfg, path.to_str().unwrap());
        assert_eq!(sink_label(), "file");
        warnf(&cfg, "hi");
        init_stderr(); // close the file
        let captured = std::fs::read_to_string(&path).expect("read sink file");
        let _ = std::fs::remove_file(&path);
        assert_eq!(captured, "Warning: hi\n");
    }

    #[test]
    fn set_stderr_file_open_failure_warns_and_keeps_sink() {
        let _guard = test_lock();
        let cfg = cfg_with(false, false, TraceType::None);

        // Redirect the sink to a file we control so we can capture the warning.
        let cap_path = unique_temp_path();
        *lock_sink() = ErrorStream::File(File::create(&cap_path).unwrap());

        // A path whose parent directory does not exist => File::create fails.
        let mut bad = std::env::temp_dir();
        bad.push(format!("curl_rs_no_such_dir_{}", std::process::id()));
        bad.push("x");
        let bad_str = bad.to_str().unwrap();

        set_stderr_file(&cfg, bad_str);
        // On failure the sink is unchanged (still our capture file).
        assert_eq!(sink_label(), "file");

        init_stderr(); // close the capture file
        let captured = std::fs::read_to_string(&cap_path).expect("read capture file");
        let _ = std::fs::remove_file(&cap_path);

        // warnf prepends "Warning: " to the already-"Warning: "-prefixed text,
        // so the doubled prefix is curl's actual, reproduced behavior.
        let expected = s(wrap_message(
            WARN_PREFIX,
            &format!("Warning: Failed to open {bad_str}"),
            terminal_columns(),
        ));
        assert_eq!(captured, expected);
        assert!(captured.contains("Warning: Warning: "));
        assert!(captured.contains("Failed to open"));
    }

    #[test]
    fn set_stderr_file_open_failure_is_muted_when_silent() {
        let _guard = test_lock();
        let cfg = cfg_with(true, false, TraceType::None); // --silent

        let cap_path = unique_temp_path();
        *lock_sink() = ErrorStream::File(File::create(&cap_path).unwrap());

        let mut bad = std::env::temp_dir();
        bad.push(format!("curl_rs_no_such_dir_silent_{}", std::process::id()));
        bad.push("x");

        set_stderr_file(&cfg, bad.to_str().unwrap());
        assert_eq!(sink_label(), "file"); // unchanged

        init_stderr();
        let captured = std::fs::read_to_string(&cap_path).expect("read capture file");
        let _ = std::fs::remove_file(&cap_path);
        // warnf is suppressed under --silent, so nothing is written.
        assert_eq!(captured, "");
    }

    // -- macros forward to the gating functions ------------------------------

    #[test]
    fn macros_forward_with_formatting() {
        let _guard = test_lock();
        let cfg = cfg_with(false, false, TraceType::Plain); // notef enabled

        let path = unique_temp_path();
        *lock_sink() = ErrorStream::File(File::create(&path).unwrap());

        crate::warnf!(&cfg, "n={}", 7);
        crate::notef!(&cfg, "trace {}", "on");
        crate::errorf!(&cfg, "e");
        crate::helpf!();
        crate::helpf!("h={}", 1);

        init_stderr();
        let captured = std::fs::read_to_string(&path).expect("read capture file");
        let _ = std::fs::remove_file(&path);

        let tc = terminal_columns();
        let expected = format!(
            "{}{}{}{}{}",
            s(wrap_message(WARN_PREFIX, "n=7", tc)),
            s(wrap_message(NOTE_PREFIX, "trace on", tc)),
            s(wrap_message(ERROR_PREFIX, "e", tc)),
            s(format_help(None)),
            s(format_help(Some("h=1"))),
        );
        assert_eq!(captured, expected);
    }
}
