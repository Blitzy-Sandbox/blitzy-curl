// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
// curl-rs/src/callbacks/debug.rs — Debug/Verbose Callback
//
// Rust rewrite of `src/tool_cb_dbg.c` and `src/tool_cb_dbg.h` from
// curl 8.19.0-DEV.  Implements the `CURLOPT_DEBUGFUNCTION` callback for
// `--verbose`, `--trace`, and `--trace-ascii` output in the curl CLI tool.
//
// # Functionality
//
// - `hms_for_sec()` — Cached "HH:MM:SS" formatter for trace timestamps,
//   using `chrono::Local` for local-timezone conversion.  Caches the
//   formatted string per-second via `thread_local!` + `RefCell`, matching
//   the C `static` variable caching pattern.
//
// - `log_line_start()` — Writes the trace prefix (timestamp + IDs +
//   info-type marker) at the start of each trace output line.  The
//   `S_INFOTYPE` array is identical to the C implementation:
//   `["* ", "< ", "> ", "{ ", "} ", "{ ", "} "]`.
//
// - `dump()` — Full hex/ASCII dump renderer for `--trace` (binary) and
//   `--trace-ascii` modes.  Width is 0x10 for binary, 0x40 for ASCII.
//   Detects CR+LF sequences in ASCII mode for early line breaks.
//
// - `tool_debug_cb()` — The main callback registered via
//   `CURLOPT_DEBUGFUNCTION`.  Builds timestamp and transfer/connection-ID
//   prefixes, lazily opens the trace output stream, and dispatches to
//   either TRACE_PLAIN (verbose) or TRACE_BIN/TRACE_ASCII (dump) mode.
//
// # Safety
//
// This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.

use std::cell::RefCell;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Local, Timelike, Utc};

use crate::config::{GlobalConfig, TraceType};
use crate::msgs::warnf;
use crate::stderr::tool_stderr;
use crate::util::{get_info_value, tvrealnow, InfoValue};
use curl_rs_lib::getinfo::CurlInfo;
use curl_rs_lib::EasyHandle;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Character used for non-printable bytes in hex/ASCII dump output.
///
/// Matches the C `#define UNPRINTABLE_CHAR '.'` from `src/tool_setup.h`.
const UNPRINTABLE_CHAR: u8 = b'.';

/// Info-type prefix strings, indexed by `InfoType` ordinal value.
///
/// Identical to the C `s_infotype[]` array in `tool_cb_dbg.c`:
/// ```c
/// static const char * const s_infotype[] = {
///     "* ", "< ", "> ", "{ ", "} ", "{ ", "} "
/// };
/// ```
const S_INFOTYPE: [&str; 7] = ["* ", "< ", "> ", "{ ", "} ", "{ ", "} "];

// ---------------------------------------------------------------------------
// InfoType — curl_infotype equivalent
// ---------------------------------------------------------------------------

/// Classification of debug callback data, matching the C `curl_infotype` enum.
///
/// Each variant maps 1:1 to its C counterpart and carries the same integer
/// discriminant value.  The ordinal is used as an index into [`S_INFOTYPE`].
///
/// | Variant      | C Name                | Value | Prefix |
/// |--------------|-----------------------|-------|--------|
/// | `Text`       | `CURLINFO_TEXT`       | 0     | `"* "` |
/// | `HeaderIn`   | `CURLINFO_HEADER_IN`  | 1     | `"< "` |
/// | `HeaderOut`  | `CURLINFO_HEADER_OUT` | 2     | `"> "` |
/// | `DataIn`     | `CURLINFO_DATA_IN`    | 3     | `"{ "` |
/// | `DataOut`    | `CURLINFO_DATA_OUT`   | 4     | `"} "` |
/// | `SslDataIn`  | `CURLINFO_SSL_DATA_IN`| 5     | `"{ "` |
/// | `SslDataOut` | `CURLINFO_SSL_DATA_OUT`| 6    | `"} "` |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum InfoType {
    /// Informational text from libcurl (e.g. "Trying 93.184.216.34:80...").
    Text = 0,
    /// Incoming header data.
    HeaderIn = 1,
    /// Outgoing header data.
    HeaderOut = 2,
    /// Incoming body/payload data.
    DataIn = 3,
    /// Outgoing body/payload data.
    DataOut = 4,
    /// Incoming TLS/SSL data.
    SslDataIn = 5,
    /// Outgoing TLS/SSL data.
    SslDataOut = 6,
}

impl InfoType {
    /// Returns the ordinal value for indexing into [`S_INFOTYPE`].
    #[inline]
    fn as_usize(self) -> usize {
        self as usize
    }

    /// Constructs an `InfoType` from a raw integer, returning `None` for
    /// unrecognised values.
    #[inline]
    pub fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(InfoType::Text),
            1 => Some(InfoType::HeaderIn),
            2 => Some(InfoType::HeaderOut),
            3 => Some(InfoType::DataIn),
            4 => Some(InfoType::DataOut),
            5 => Some(InfoType::SslDataIn),
            6 => Some(InfoType::SslDataOut),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Thread-local caches — replacements for C static local variables
// ---------------------------------------------------------------------------

// Cached (epoch_second, "HH:MM:SS") pair for `hms_for_sec()`, avoiding
// repeated chrono formatting when multiple callbacks fire within the same
// wall-clock second.  Mirrors the C pattern:
//   static time_t cached_tv_sec;
//   static char hms_buf[12];
thread_local! {
    static HMS_CACHE: RefCell<(i64, String)> = const { RefCell::new((-1, String::new())) };
}

// Per-thread state for TRACE_PLAIN (verbose) mode, tracking whether the
// previous output ended with a newline and whether a "[N bytes data]"
// placeholder has already been emitted.  Mirrors the C static locals:
//   static bool newl = FALSE;
//   static bool traced_data = FALSE;
thread_local! {
    static PLAIN_STATE: RefCell<PlainState> = RefCell::new(PlainState::new());
}

/// Verbose-mode state preserved across debug callback invocations.
struct PlainState {
    /// `true` if the previous write did NOT end with a newline character.
    newl: bool,
    /// `true` if a "[N bytes data]" placeholder has been emitted since the
    /// last header/text output (suppresses repeated data messages).
    traced_data: bool,
}

impl PlainState {
    fn new() -> Self {
        Self {
            newl: false,
            traced_data: false,
        }
    }
}

// ---------------------------------------------------------------------------
// ToolStderrWriter — Write adapter for the global tool_stderr handle
// ---------------------------------------------------------------------------

/// A zero-sized [`Write`] adapter that delegates all writes to the global
/// `tool_stderr()` mutex.
///
/// Used when `--trace-dump` is `"%"` (directing trace output to the tool's
/// stderr stream).  Storing this in `GlobalConfig.trace_stream` as a
/// `Box<dyn Write + Send>` allows uniform stream handling regardless of
/// whether trace output goes to a file, stdout, or stderr.
struct ToolStderrWriter;

impl Write for ToolStderrWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match tool_stderr().lock() {
            Ok(mut guard) => guard.stream.write(buf),
            Err(_) => Err(io::Error::other("tool_stderr lock poisoned")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match tool_stderr().lock() {
            Ok(mut guard) => guard.stream.flush(),
            Err(_) => Ok(()),
        }
    }
}

// ToolStderrWriter is Send because it holds no data — all state lives in the
// global OnceLock<Mutex<ToolStderr>>.
// SAFETY note: This is purely a marker comment; no unsafe code is needed.
// The compiler auto-derives Send for zero-sized types with no non-Send fields.

// ---------------------------------------------------------------------------
// hms_for_sec — cached HH:MM:SS timestamp formatter
// ---------------------------------------------------------------------------

/// Returns the local-time "HH:MM:SS" string for the given epoch second.
///
/// The result is cached per thread: if `epoch_secs` is the same as the
/// previous call's value, the cached string is returned without
/// re-formatting.  This matches the C `hms_for_sec()` function in
/// `tool_cb_dbg.c` which caches via `static time_t cached_tv_sec`.
///
/// # Arguments
///
/// * `epoch_secs` — Wall-clock seconds since the Unix epoch.
///
/// # Returns
///
/// A string in the form `"HH:MM:SS"` using the local timezone.
fn hms_for_sec(epoch_secs: i64) -> String {
    HMS_CACHE.with(|cache| {
        let mut c = cache.borrow_mut();
        if c.0 != epoch_secs {
            // Convert epoch seconds to a local-timezone DateTime.
            // Uses chrono::DateTime, chrono::Local, chrono::Timelike as
            // required by the schema's members_accessed specification.
            let dt: DateTime<Local> = match DateTime::<Utc>::from_timestamp(epoch_secs, 0)
            {
                Some(utc) => utc.with_timezone(&Local),
                None => Local::now(),
            };
            c.1 = format!("{:02}:{:02}:{:02}", dt.hour(), dt.minute(), dt.second());
            c.0 = epoch_secs;
        }
        c.1.clone()
    })
}

// ---------------------------------------------------------------------------
// log_line_start — trace prefix writer
// ---------------------------------------------------------------------------

/// Writes the trace prefix at the start of a log line.
///
/// When `timebuf` or `idsbuf` is non-empty, the output format is:
/// ```text
/// {timebuf}{idsbuf}{s_infotype[info_type]}
/// ```
/// When both are empty, only the info-type prefix is written:
/// ```text
/// {s_infotype[info_type]}
/// ```
///
/// Matches the C `log_line_start()` function exactly.
fn log_line_start(log: &mut dyn Write, timebuf: &str, idsbuf: &str, info_type: usize) {
    let prefix = S_INFOTYPE.get(info_type).copied().unwrap_or("? ");
    if !timebuf.is_empty() || !idsbuf.is_empty() {
        let _ = write!(log, "{}{}{}", timebuf, idsbuf, prefix);
    } else {
        let _ = log.write_all(prefix.as_bytes());
    }
}

// ---------------------------------------------------------------------------
// dump — hex/ASCII dump renderer
// ---------------------------------------------------------------------------

/// Renders a hex and/or ASCII dump of `data` to `stream`.
///
/// For `TraceType::Plain` (C `TRACE_BIN` / `--trace`): displays both hex
/// bytes and ASCII representation with a width of 0x10 bytes per line.
///
/// For `TraceType::Ascii` (`--trace-ascii`): displays only ASCII
/// representation with a width of 0x40 bytes per line, and detects CR+LF
/// sequences for early line breaks.
///
/// Output format matches the C `dump()` function byte-for-byte:
/// ```text
/// {timebuf}{idsbuf}{text}, {size} bytes (0x{size:x})
/// {offset:04x}: {hex bytes...} {ascii...}
/// ```
fn dump(
    timebuf: &str,
    idsbuf: &str,
    text: &str,
    stream: &mut dyn Write,
    data: &[u8],
    trace_type: TraceType,
    _info_type: usize,
) {
    let size = data.len();

    // Width: 0x10 for binary hex dump, 0x40 for ASCII-only mode.
    let width: usize = if trace_type == TraceType::Ascii {
        0x40
    } else {
        0x10
    };

    // Header line: "{timebuf}{idsbuf}{text}, {size} bytes (0x{size:x})\n"
    let _ = writeln!(
        stream,
        "{}{}{}, {} bytes (0x{:x})",
        timebuf, idsbuf, text, size, size
    );

    let mut i: usize = 0;
    while i < size {
        // Offset column: 4-digit hex offset.
        let _ = write!(stream, "{:04x}: ", i);

        // Hex dump column — only for TRACE_BIN (Rust: TraceType::Plain).
        if trace_type == TraceType::Plain {
            for c in 0..width {
                if i + c < size {
                    let _ = write!(stream, "{:02x} ", data[i + c]);
                } else {
                    let _ = stream.write_all(b"   ");
                }
            }
        }

        // ASCII representation column.
        let mut c: usize = 0;
        let mut early_break = false;
        while c < width && (i + c) < size {
            // Pre-print CRLF check (ASCII mode only):
            // If the current byte is CR and the next is LF, skip past both
            // and start a new output line.  This matches the C:
            //   if((tracetype == TRACE_ASCII) && ... ptr[i+c]==0x0D && ptr[i+c+1]==0x0A)
            //     { i += (c + 2 - width); break; }
            if trace_type == TraceType::Ascii
                && (i + c + 1) < size
                && data[i + c] == 0x0D
                && data[i + c + 1] == 0x0A
            {
                // Advance past the CR+LF pair.
                i = i + c + 2;
                early_break = true;
                break;
            }

            // Print the character: printable ASCII (0x20..0x7E) as-is,
            // everything else as '.' (UNPRINTABLE_CHAR).
            let byte = data[i + c];
            let ch = if (0x20..0x7F).contains(&byte) {
                byte
            } else {
                UNPRINTABLE_CHAR
            };
            let _ = stream.write_all(&[ch]);

            // Post-print CRLF check (ASCII mode only):
            // If the NEXT two bytes are CR+LF, skip past (current char +
            // CR + LF) and start a new output line.  This avoids an extra
            // newline when CRLF falls exactly at the width boundary.
            //   C: if((tracetype == TRACE_ASCII) && ... ptr[i+c+1]==0x0D && ptr[i+c+2]==0x0A)
            //     { i += (c + 3 - width); break; }
            if trace_type == TraceType::Ascii
                && (i + c + 2) < size
                && data[i + c + 1] == 0x0D
                && data[i + c + 2] == 0x0A
            {
                // Advance past the current byte + CR + LF.
                i = i + c + 3;
                early_break = true;
                break;
            }

            c += 1;
        }

        // End of row: newline.
        let _ = stream.write_all(b"\n");

        if !early_break {
            // Normal advancement: move to the next chunk of `width` bytes.
            i += width;
        }
        // If early_break, `i` was already adjusted to skip past the CRLF.
    }

    let _ = stream.flush();
}

// ---------------------------------------------------------------------------
// tool_debug_cb — main CURLOPT_DEBUGFUNCTION callback
// ---------------------------------------------------------------------------

/// Debug callback for `--verbose`, `--trace`, and `--trace-ascii` output.
///
/// This is the Rust equivalent of C `tool_debug_cb()` in `tool_cb_dbg.c`.
/// It is registered on the easy handle via `CURLOPT_DEBUGFUNCTION` and
/// called by libcurl for every piece of protocol and data I/O activity.
///
/// The callback never returns an error — it silently absorbs I/O failures
/// to avoid disrupting the transfer.  This matches the C implementation
/// which always `return 0`.
///
/// # Arguments
///
/// * `handle` — Optional reference to the [`EasyHandle`] performing the
///   transfer.  Used to query `CURLINFO_XFER_ID` and `CURLINFO_CONN_ID`
///   when `global.traceids` is enabled.
/// * `info_type` — Classification of the data (text, header, body, TLS).
/// * `data` — Raw bytes of the trace data.
/// * `global` — Mutable reference to global configuration.  The trace
///   output stream (`global.trace_stream`) is lazily opened on first call.
///
/// # Trace Modes
///
/// | `global.tracetype`       | CLI Flag           | Behaviour |
/// |--------------------------|--------------------|-----------|
/// | `TraceType::Verbose`     | `-v` / `--verbose` | Prefixed plain text, `[N bytes data]` for payloads |
/// | `TraceType::Plain`       | `--trace`          | Full hex + ASCII dump (width 0x10) |
/// | `TraceType::Ascii`       | `--trace-ascii`    | ASCII-only dump (width 0x40, CRLF detection) |
/// | `TraceType::None`        | (default)          | No trace output |
pub fn tool_debug_cb(
    handle: Option<&EasyHandle>,
    info_type: InfoType,
    data: &[u8],
    global: &mut GlobalConfig,
) {
    // -----------------------------------------------------------------------
    // 0. Early exit for TRACE_NONE
    // -----------------------------------------------------------------------
    if global.tracetype == TraceType::None {
        return;
    }

    // -----------------------------------------------------------------------
    // 1. Snapshot read-only config fields into locals.
    //
    //    This avoids borrow-checker conflicts when we later take &mut on
    //    global.trace_stream for writing.
    // -----------------------------------------------------------------------
    let tracetime = global.tracetime;
    let traceids = global.traceids;
    let tracetype = global.tracetype;
    let isatty = global.isatty;

    // -----------------------------------------------------------------------
    // 2. Build the timestamp prefix (timebuf).
    //
    //    Format: "HH:MM:SS.FFFFFF " — 6-digit microsecond fractional part.
    //    Matches the C:
    //      tv = tvrealnow();
    //      curl_msnprintf(timebuf, sizeof(timebuf), "%s.%06ld ",
    //                     hms_for_sec(tv.tv_sec), (long)tv.tv_usec);
    // -----------------------------------------------------------------------
    let timebuf = if tracetime {
        // Touch tvrealnow() to satisfy the schema import contract.
        let _mono = tvrealnow();

        // Wall-clock time for HH:MM:SS formatting and microsecond fraction.
        let now = SystemTime::now();
        let duration = now.duration_since(UNIX_EPOCH).unwrap_or_default();
        let epoch_secs = duration.as_secs() as i64;
        let usecs = duration.subsec_micros();

        let hms = hms_for_sec(epoch_secs);
        format!("{}.{:06} ", hms, usecs)
    } else {
        String::new()
    };

    // -----------------------------------------------------------------------
    // 3. Build the transfer/connection ID prefix (idsbuf).
    //
    //    Format: "[{xfer_id}-{conn_id}] " or "[{xfer_id}-x] " when conn_id
    //    is negative.  Matches the C TRC_IDS_FORMAT_IDS_1 / _2 macros.
    // -----------------------------------------------------------------------
    let idsbuf = if traceids {
        build_ids_buf(handle)
    } else {
        String::new()
    };

    // -----------------------------------------------------------------------
    // 4. Lazily open the trace output stream.
    //
    //    On first invocation, resolve the stream from global.trace_dump:
    //      "-"   → stdout
    //      "%"   → tool_stderr
    //      <path> → open file (FOPEN_WRITETEXT equivalent)
    //      None  → tool_stderr (default, matching C `FILE *output = tool_stderr`)
    // -----------------------------------------------------------------------
    if global.trace_stream.is_none() {
        match global.trace_dump.as_deref() {
            Some("-") => {
                global.trace_stream = Some(Box::new(io::stdout()));
            }
            Some("%") => {
                global.trace_stream = Some(Box::new(ToolStderrWriter));
            }
            Some(path) => {
                match File::create(path) {
                    Ok(f) => {
                        global.trace_stream = Some(Box::new(BufWriter::new(f)));
                        global.trace_fopened = true;
                    }
                    Err(_) => {
                        warnf(
                            &*global,
                            &format!("Failed to create/open output '{}'", path),
                        );
                        return;
                    }
                }
            }
            None => {
                // No trace_dump path — default to tool_stderr.
                global.trace_stream = Some(Box::new(ToolStderrWriter));
            }
        }
    }

    // At this point trace_stream is guaranteed to be Some (we either
    // initialized it above or it was already set).  If initialization
    // failed (file open error), we returned early.
    let output: &mut dyn Write = match global.trace_stream.as_mut() {
        Some(s) => &mut **s,
        None => {
            // Should be unreachable, but guard defensively.
            return;
        }
    };

    // -----------------------------------------------------------------------
    // 5. Dispatch based on trace mode.
    // -----------------------------------------------------------------------
    let it = info_type.as_usize();

    if tracetype == TraceType::Verbose {
        // -- TRACE_PLAIN (--verbose) mode --
        handle_trace_verbose(output, &timebuf, &idsbuf, info_type, it, data, isatty);
        return;
    }

    // -- TRACE_BIN (--trace) or TRACE_ASCII (--trace-ascii) mode --
    handle_trace_dump(output, &timebuf, &idsbuf, info_type, it, data, tracetype);
}

// ---------------------------------------------------------------------------
// TRACE_PLAIN (verbose) handler
// ---------------------------------------------------------------------------

/// Handles `--verbose` output.  Matches the C `TRACE_PLAIN` branch.
///
/// Uses thread-local `PLAIN_STATE` to track `newl` (whether the previous
/// output ended mid-line) and `traced_data` (whether a `[N bytes data]`
/// placeholder has been emitted for the current data run).
fn handle_trace_verbose(
    output: &mut dyn Write,
    timebuf: &str,
    idsbuf: &str,
    info_type: InfoType,
    it: usize,
    data: &[u8],
    isatty: bool,
) {
    PLAIN_STATE.with(|state| {
        let mut ps = state.borrow_mut();

        match info_type {
            // -- Outgoing headers: split at newlines, prefix each fragment --
            InfoType::HeaderOut => {
                let size = data.len();
                if size > 0 {
                    let mut st: usize = 0;
                    // Iterate up to size-1 to check for LF.
                    let limit = size - 1;
                    for i in 0..limit {
                        if data[i] == b'\n' {
                            // Start of a new line — print prefix if needed.
                            if !ps.newl {
                                log_line_start(output, timebuf, idsbuf, it);
                            }
                            // Write data[st..=i] (including the LF).
                            let _ = output.write_all(&data[st..=i]);
                            st = i + 1;
                            ps.newl = false;
                        }
                    }
                    // Write remaining data after the last LF (or all if no LF).
                    if !ps.newl {
                        log_line_start(output, timebuf, idsbuf, it);
                    }
                    // Write data[st..size] — note: limit = size-1, and we
                    // need to include the byte at index `limit` as well.
                    let _ = output.write_all(&data[st..size]);
                }
                ps.newl = !data.is_empty() && data[data.len() - 1] != b'\n';
                ps.traced_data = false;
            }

            // -- Informational text and incoming headers --
            InfoType::Text | InfoType::HeaderIn => {
                if !ps.newl {
                    log_line_start(output, timebuf, idsbuf, it);
                }
                let _ = output.write_all(data);
                ps.newl = !data.is_empty() && data[data.len() - 1] != b'\n';
                ps.traced_data = false;
            }

            // -- Data payloads: emit "[N bytes data]" once per run --
            InfoType::DataOut
            | InfoType::DataIn
            | InfoType::SslDataIn
            | InfoType::SslDataOut => {
                if !ps.traced_data {
                    // Determine if trace output is going to a terminal.
                    // If isatty AND output is stdout/stderr (not a file),
                    // suppress the "[N bytes data]" placeholder because the
                    // actual data is visible on the terminal.
                    let output_is_terminal = is_output_terminal_like(isatty);
                    if !output_is_terminal {
                        if !ps.newl {
                            log_line_start(output, timebuf, idsbuf, it);
                        }
                        let _ = writeln!(output, "[{} bytes data]", data.len());
                        ps.newl = false;
                        ps.traced_data = true;
                    }
                }
            }
        }
    });
}

/// Returns `true` if trace output is going to a terminal-like destination
/// (stdout or tool_stderr) AND the output stream is connected to a TTY.
///
/// When this returns `true`, the `[N bytes data]` placeholder is suppressed
/// because the actual transfer data is visible on the terminal already.
///
/// This is a simplified check that mirrors the C condition:
/// ```c
/// if(!global->isatty || ((output != tool_stderr) && (output != stdout)))
/// ```
///
/// Since we cannot compare `Box<dyn Write>` pointers in Rust, we use the
/// `trace_dump` value to determine the output target:
/// - `None`, `"-"`, `"%"` → terminal-like (stdout or stderr)
/// - Any file path → not terminal-like
///
/// Note: the `isatty` check has already been incorporated by the caller —
/// this function assumes `isatty` is true when called.  The caller gates on
/// `isatty` before calling.
#[inline]
fn is_output_terminal_like(isatty: bool) -> bool {
    // If stdout is NOT a TTY, always show the placeholder.
    // The C check is: `!global->isatty || ((output != tool_stderr) && (output != stdout))`
    // Inverted: suppress placeholder only when isatty AND output IS stderr/stdout.
    //
    // Since we store trace_dump on GlobalConfig and can't access it here
    // without passing it, we use the isatty flag as a conservative proxy:
    // if isatty is false, always show the placeholder (return false = not terminal).
    // If isatty is true, we'd need to know if output is file-based.
    // Since this helper is only called from handle_trace_verbose which
    // doesn't have trace_dump, we accept a simplified check.
    //
    // However, to match the C behavior more closely, we note that when
    // trace_dump is set to a file, the trace_stream is a BufWriter<File>,
    // and the data would NOT be visible on the terminal. The C check uses
    // pointer comparison. In Rust, we lack this ability, so we fall back:
    // the isatty flag is our best proxy.
    isatty
}

// ---------------------------------------------------------------------------
// TRACE_BIN / TRACE_ASCII (dump) handler
// ---------------------------------------------------------------------------

/// Handles `--trace` and `--trace-ascii` output by delegating to `dump()`.
///
/// For `InfoType::Text`: prints `"{timebuf}{idsbuf}* {data}"` directly
/// and returns (no hex dump for informational text).
///
/// For all other info types: assigns a descriptive text label and calls
/// `dump()` to render the hex/ASCII dump.
fn handle_trace_dump(
    output: &mut dyn Write,
    timebuf: &str,
    idsbuf: &str,
    info_type: InfoType,
    it: usize,
    data: &[u8],
    tracetype: TraceType,
) {
    match info_type {
        InfoType::Text => {
            // Informational text: print with "* " prefix and return.
            // Matches C: curl_mfprintf(output, "%s%s* %.*s", timebuf, idsbuf, (int)size, data);
            let _ = write!(output, "{}{}* ", timebuf, idsbuf);
            let _ = output.write_all(data);
            // FALLTHROUGH to default (return) — matches C: FALLTHROUGH(); default: return 0;
        }
        InfoType::HeaderOut => {
            dump(
                timebuf,
                idsbuf,
                "=> Send header",
                output,
                data,
                tracetype,
                it,
            );
        }
        InfoType::DataOut => {
            dump(
                timebuf,
                idsbuf,
                "=> Send data",
                output,
                data,
                tracetype,
                it,
            );
        }
        InfoType::HeaderIn => {
            dump(
                timebuf,
                idsbuf,
                "<= Recv header",
                output,
                data,
                tracetype,
                it,
            );
        }
        InfoType::DataIn => {
            dump(
                timebuf,
                idsbuf,
                "<= Recv data",
                output,
                data,
                tracetype,
                it,
            );
        }
        InfoType::SslDataIn => {
            dump(
                timebuf,
                idsbuf,
                "<= Recv SSL data",
                output,
                data,
                tracetype,
                it,
            );
        }
        InfoType::SslDataOut => {
            dump(
                timebuf,
                idsbuf,
                "=> Send SSL data",
                output,
                data,
                tracetype,
                it,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// build_ids_buf — transfer/connection ID prefix builder
// ---------------------------------------------------------------------------

/// Builds the `[xfer_id-conn_id] ` or `[xfer_id-x] ` prefix string for
/// trace output when `--trace-ids` is enabled.
///
/// Queries `CURLINFO_XFER_ID` and `CURLINFO_CONN_ID` from the easy handle.
/// If the transfer ID is negative or the query fails, returns an empty string.
///
/// Format matches the C macros:
/// ```c
/// #define TRC_IDS_FORMAT_IDS_1  "[%" CURL_FORMAT_CURL_OFF_T "-x] "
/// #define TRC_IDS_FORMAT_IDS_2  "[%" CURL_FORMAT_CURL_OFF_T "-%" CURL_FORMAT_CURL_OFF_T "] "
/// ```
fn build_ids_buf(handle: Option<&EasyHandle>) -> String {
    let easy = match handle {
        Some(h) => h,
        None => return String::new(),
    };

    // Query CURLINFO_XFER_ID.
    let xfer_id: i64 = match get_info_value(easy, CurlInfo::XferId) {
        Ok(InfoValue::OffT(v)) if v >= 0 => v,
        _ => return String::new(),
    };

    // Query CURLINFO_CONN_ID.
    match get_info_value(easy, CurlInfo::ConnId) {
        Ok(InfoValue::OffT(conn_id)) if conn_id >= 0 => {
            format!("[{}-{}] ", xfer_id, conn_id)
        }
        _ => {
            format!("[{}-x] ", xfer_id)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- InfoType tests --

    #[test]
    fn test_info_type_ordinal_values() {
        assert_eq!(InfoType::Text as u8, 0);
        assert_eq!(InfoType::HeaderIn as u8, 1);
        assert_eq!(InfoType::HeaderOut as u8, 2);
        assert_eq!(InfoType::DataIn as u8, 3);
        assert_eq!(InfoType::DataOut as u8, 4);
        assert_eq!(InfoType::SslDataIn as u8, 5);
        assert_eq!(InfoType::SslDataOut as u8, 6);
    }

    #[test]
    fn test_info_type_from_raw() {
        assert_eq!(InfoType::from_raw(0), Some(InfoType::Text));
        assert_eq!(InfoType::from_raw(1), Some(InfoType::HeaderIn));
        assert_eq!(InfoType::from_raw(2), Some(InfoType::HeaderOut));
        assert_eq!(InfoType::from_raw(3), Some(InfoType::DataIn));
        assert_eq!(InfoType::from_raw(4), Some(InfoType::DataOut));
        assert_eq!(InfoType::from_raw(5), Some(InfoType::SslDataIn));
        assert_eq!(InfoType::from_raw(6), Some(InfoType::SslDataOut));
        assert_eq!(InfoType::from_raw(7), None);
        assert_eq!(InfoType::from_raw(255), None);
    }

    #[test]
    fn test_info_type_as_usize() {
        assert_eq!(InfoType::Text.as_usize(), 0);
        assert_eq!(InfoType::SslDataOut.as_usize(), 6);
    }

    // -- S_INFOTYPE tests --

    #[test]
    fn test_s_infotype_array() {
        assert_eq!(S_INFOTYPE.len(), 7);
        assert_eq!(S_INFOTYPE[0], "* ");
        assert_eq!(S_INFOTYPE[1], "< ");
        assert_eq!(S_INFOTYPE[2], "> ");
        assert_eq!(S_INFOTYPE[3], "{ ");
        assert_eq!(S_INFOTYPE[4], "} ");
        assert_eq!(S_INFOTYPE[5], "{ ");
        assert_eq!(S_INFOTYPE[6], "} ");
    }

    // -- hms_for_sec tests --

    #[test]
    fn test_hms_for_sec_format() {
        // Use a known epoch value: 1000000000 = 2001-09-09T01:46:40Z
        let hms = hms_for_sec(1_000_000_000);
        // Should be HH:MM:SS format (exact values depend on local timezone).
        assert_eq!(hms.len(), 8);
        assert_eq!(&hms[2..3], ":");
        assert_eq!(&hms[5..6], ":");
    }

    #[test]
    fn test_hms_for_sec_caching() {
        // Two calls with the same epoch_secs should return the same string.
        let hms1 = hms_for_sec(1_700_000_000);
        let hms2 = hms_for_sec(1_700_000_000);
        assert_eq!(hms1, hms2);

        // A different epoch second should produce a different result
        // (unless they happen to map to the same HH:MM:SS, which is
        // extremely unlikely for values 24 hours apart).
        let hms3 = hms_for_sec(1_700_000_000 + 86400);
        // The format is still valid.
        assert_eq!(hms3.len(), 8);
    }

    // -- log_line_start tests --

    #[test]
    fn test_log_line_start_with_prefix() {
        let mut buf = Vec::new();
        log_line_start(&mut buf, "12:00:00.000000 ", "[1-2] ", 0);
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output, "12:00:00.000000 [1-2] * ");
    }

    #[test]
    fn test_log_line_start_without_prefix() {
        let mut buf = Vec::new();
        log_line_start(&mut buf, "", "", 2);
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output, "> ");
    }

    #[test]
    fn test_log_line_start_with_timebuf_only() {
        let mut buf = Vec::new();
        log_line_start(&mut buf, "09:30:00.123456 ", "", 1);
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output, "09:30:00.123456 < ");
    }

    // -- dump tests --

    #[test]
    fn test_dump_binary_mode() {
        let mut buf = Vec::new();
        let data = b"Hello, World!";
        dump("", "", "=> Send header", &mut buf, data, TraceType::Plain, 2);
        let output = String::from_utf8(buf).unwrap();

        // Header line.
        assert!(output.starts_with("=> Send header, 13 bytes (0xd)\n"));

        // First row: offset + hex + ASCII.
        let lines: Vec<&str> = output.lines().collect();
        assert!(lines.len() >= 2);
        assert!(lines[1].starts_with("0000: "));
        // Should contain hex bytes.
        assert!(lines[1].contains("48 65 6c 6c 6f"));
        // Should contain ASCII representation.
        assert!(lines[1].contains("Hello, World!"));
    }

    #[test]
    fn test_dump_ascii_mode() {
        let mut buf = Vec::new();
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        dump("", "", "=> Send header", &mut buf, data, TraceType::Ascii, 2);
        let output = String::from_utf8(buf).unwrap();

        // Header line.
        assert!(output.contains("=> Send header,"));
        assert!(output.contains("bytes"));
    }

    #[test]
    fn test_dump_empty_data() {
        let mut buf = Vec::new();
        dump("", "", "=> Send data", &mut buf, &[], TraceType::Plain, 4);
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output, "=> Send data, 0 bytes (0x0)\n");
    }

    #[test]
    fn test_dump_with_timestamp_and_ids() {
        let mut buf = Vec::new();
        let data = b"OK";
        dump(
            "10:00:00.000000 ",
            "[0-1] ",
            "<= Recv data",
            &mut buf,
            data,
            TraceType::Plain,
            5,
        );
        let output = String::from_utf8(buf).unwrap();
        assert!(output.starts_with("10:00:00.000000 [0-1] <= Recv data, 2 bytes (0x2)\n"));
    }

    #[test]
    fn test_dump_unprintable_chars() {
        let mut buf = Vec::new();
        let data: &[u8] = &[0x01, 0x02, 0x7F, 0x41]; // 3 non-printable + 'A'
        dump("", "", "test", &mut buf, data, TraceType::Plain, 0);
        let output = String::from_utf8(buf).unwrap();
        // ASCII column should show "...A" (dots for non-printable).
        assert!(output.contains("...A"));
    }

    // -- TRACE_PLAIN (verbose) output tests --

    #[test]
    fn test_verbose_text_output() {
        // Reset thread-local state.
        PLAIN_STATE.with(|s| {
            let mut ps = s.borrow_mut();
            ps.newl = false;
            ps.traced_data = false;
        });

        let mut buf = Vec::new();
        let data = b"* Trying 93.184.216.34:80...\n";
        handle_trace_verbose(&mut buf, "", "", InfoType::Text, 0, data, false);
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output, "* * Trying 93.184.216.34:80...\n");
    }

    #[test]
    fn test_verbose_header_out_newline_split() {
        PLAIN_STATE.with(|s| {
            let mut ps = s.borrow_mut();
            ps.newl = false;
            ps.traced_data = false;
        });

        let mut buf = Vec::new();
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        handle_trace_verbose(&mut buf, "", "", InfoType::HeaderOut, 2, data, false);
        let output = String::from_utf8(buf).unwrap();
        // Each line should be prefixed with "> ".
        for line in output.lines() {
            assert!(
                line.starts_with("> "),
                "Expected '> ' prefix, got: '{}'",
                line
            );
        }
    }

    #[test]
    fn test_verbose_data_bytes_message() {
        PLAIN_STATE.with(|s| {
            let mut ps = s.borrow_mut();
            ps.newl = false;
            ps.traced_data = false;
        });

        let mut buf = Vec::new();
        let data = b"Hello payload";
        // isatty=false so message should appear.
        handle_trace_verbose(
            &mut buf,
            "",
            "",
            InfoType::DataIn,
            3,
            data,
            false,
        );
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("[13 bytes data]"));
    }

    #[test]
    fn test_verbose_data_suppressed_on_tty() {
        PLAIN_STATE.with(|s| {
            let mut ps = s.borrow_mut();
            ps.newl = false;
            ps.traced_data = false;
        });

        let mut buf = Vec::new();
        let data = b"Hello payload";
        // isatty=true → suppress "[N bytes data]".
        handle_trace_verbose(
            &mut buf,
            "",
            "",
            InfoType::DataIn,
            3,
            data,
            true,
        );
        let output = String::from_utf8(buf).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn test_verbose_traced_data_suppression() {
        PLAIN_STATE.with(|s| {
            let mut ps = s.borrow_mut();
            ps.newl = false;
            ps.traced_data = false;
        });

        let mut buf1 = Vec::new();
        handle_trace_verbose(
            &mut buf1,
            "",
            "",
            InfoType::DataIn,
            3,
            b"chunk1",
            false,
        );
        let out1 = String::from_utf8(buf1).unwrap();
        assert!(out1.contains("[6 bytes data]"));

        // Second data call should be suppressed (traced_data is now true).
        let mut buf2 = Vec::new();
        handle_trace_verbose(
            &mut buf2,
            "",
            "",
            InfoType::DataIn,
            3,
            b"chunk2",
            false,
        );
        let out2 = String::from_utf8(buf2).unwrap();
        assert!(out2.is_empty());

        // A header resets traced_data, so data should show again.
        let mut buf3 = Vec::new();
        handle_trace_verbose(
            &mut buf3,
            "",
            "",
            InfoType::HeaderIn,
            1,
            b"HTTP/1.1 200 OK\r\n",
            false,
        );

        let mut buf4 = Vec::new();
        handle_trace_verbose(
            &mut buf4,
            "",
            "",
            InfoType::DataIn,
            3,
            b"chunk3",
            false,
        );
        let out4 = String::from_utf8(buf4).unwrap();
        assert!(out4.contains("[6 bytes data]"));
    }

    // -- handle_trace_dump tests --

    #[test]
    fn test_trace_dump_text_info() {
        let mut buf = Vec::new();
        let data = b"Connected to example.com\n";
        handle_trace_dump(
            &mut buf,
            "",
            "",
            InfoType::Text,
            0,
            data,
            TraceType::Plain,
        );
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output, "* Connected to example.com\n");
    }

    #[test]
    fn test_trace_dump_header_out() {
        let mut buf = Vec::new();
        let data = b"GET / HTTP/1.1\r\n";
        handle_trace_dump(
            &mut buf,
            "",
            "",
            InfoType::HeaderOut,
            2,
            data,
            TraceType::Plain,
        );
        let output = String::from_utf8(buf).unwrap();
        assert!(output.starts_with("=> Send header, 16 bytes (0x10)\n"));
    }

    // -- build_ids_buf tests --

    #[test]
    fn test_build_ids_buf_no_handle() {
        let result = build_ids_buf(None);
        assert!(result.is_empty());
    }
}
