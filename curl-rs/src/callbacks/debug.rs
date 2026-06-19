// curl-rs — the `CURLOPT_DEBUGFUNCTION` trace callback (`-v` / `--trace*`).
//
// SPDX-License-Identifier: curl
//
// This module is the memory-safe Rust reimplementation of curl's command-line
// debug/trace callback. The original C source is
//   Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// and is licensed under the curl license (https://curl.se/docs/copyright.html).
//
// It is the behavioral port of one C translation unit of the `src/` CLI tree:
//   * `src/tool_cb_dbg.c` — the `tool_debug_cb` callback installed as
//     `CURLOPT_DEBUGFUNCTION`, plus its private helpers `hms_for_sec`,
//     `log_line_start`, and `dump`.
//
// The C source is consumed as a *behavioral oracle*, not transliterated
// line-by-line: the function-static caches (`cached_tv_sec`/`hms_buf`, `newl`,
// `traced_data`) become thread-locals (never `static mut`, which is `unsafe`),
// the raw `char *` payload becomes a safe `&[u8]` slice, the `FILE *` target
// becomes a resolved [`std::io::Write`] sink, and the manual `va`-free C
// formatting becomes Rust `write!`/`writeln!`. No label, offset format, hex
// column, ASCII column, CRLF handling, or summary line is altered: this output
// is diffed byte-for-byte by curl's regression suite, so parity is paramount
// (AAP §0.8.2 — behavioral preservation; §0.7.3 — test-harness compatibility).

//! `CURLOPT_DEBUGFUNCTION` rendering for `curl-rs` — the `-v` / `--verbose`
//! plain trace and the `--trace` / `--trace-ascii` hex/ASCII dumps.
//!
//! This module mirrors curl's `src/tool_cb_dbg.c`. Its single public entry
//! point, [`tool_debug_cb`], is the callback curl installs as
//! `CURLOPT_DEBUGFUNCTION`. It renders, in curl's exact wire-visible format:
//!
//! * **`-v` / `--verbose`** — plain trace: outgoing headers prefixed `"> "`,
//!   incoming headers `"< "`, informational text `"* "`, and a one-line
//!   `[N bytes data]` summary in place of dumping body payloads.
//! * **`--trace <file>`** — a tcpdump-style hex **and** ASCII dump, 16 bytes per
//!   row, with a `0xNNNN:` offset, the hex columns, and the printable-ASCII
//!   column.
//! * **`--trace-ascii <file>`** — the ASCII-only dump, 64 bytes per row, with
//!   CRLF-aware line wrapping (a `\r\n` pair ends the current row).
//! * **`--trace-ids`** — an optional `"[xfer-conn] "` transfer/connection id
//!   prefix on every line.
//! * **`--trace-time`** — an optional `"HH:MM:SS.usec "` timestamp prefix.
//!
//! # Relationship to the `tracing` facade (parity reconciliation)
//!
//! The crate-wide design emits verbose diagnostics through the `tracing`
//! facade, whose subscriber is initialized in `main.rs`. **This module
//! deliberately does not route the user-visible trace bytes through `tracing`.**
//! The curl 8.x regression suite diffs `-v` / `--trace` / `--trace-ascii`
//! output byte-for-byte; `tracing`'s own formatting (levels, spans, ISO
//! timestamps) would wrap and corrupt those bytes and break the suite. As the
//! file brief states, *parity wins over stylistic use of `tracing`*. Therefore
//! the formatted trace bytes are written **directly** to the resolved output
//! stream — exactly as the C `tool_debug_cb` writes to its `FILE *` — and the
//! `tracing` facade is reserved for *internal library* diagnostics elsewhere in
//! the workspace, never for this user-facing trace. This is the documented,
//! chosen mechanism.
//!
//! # Output-stream resolution
//!
//! curl resolves the trace target once from `global->trace_dump`: `"-"` selects
//! stdout, `"%"` selects stderr (used by plain `-v`), and any other value names
//! a file opened for writing. Because [`GlobalConfig::trace_stream`] can hold
//! only an [`std::fs::File`] (not the process stdout/stderr handles), this port
//! models the resolved destination as a small [`TraceTarget`] enum recomputed
//! per call; a file is opened exactly once and cached on
//! [`GlobalConfig::trace_stream`] (with [`GlobalConfig::trace_fopened`] set so
//! cleanup can close it), while stdout/stderr are re-selected each call (a
//! no-op that yields identical bytes).
//!
//! # Memory safety
//!
//! The module is `#![forbid(unsafe_code)]`: there are no raw pointers, no
//! `static mut`, and no FFI. The payload is a borrowed `&[u8]`, the handle is a
//! typed [`Easy`] reference used only for `getinfo`, and the persisted
//! cross-call state lives in thread-locals.

#![forbid(unsafe_code)]

use std::cell::{Cell, RefCell};
use std::fs::File;
use std::io::{self, Write};

use chrono::{Local, TimeZone};
use curl_rs_lib::{CurlInfo, Easy, InfoValue};

use crate::config::{GlobalConfig, TraceType};
use crate::warnf;

// ===========================================================================
// curl_infotype — the trace classification passed to the debug callback.
// ===========================================================================

/// The kind of trace datum delivered to [`tool_debug_cb`], mirroring libcurl's
/// public `curl_infotype` enum (`include/curl/curl.h`) one-to-one, including the
/// exact integer discriminants.
///
/// The discriminants are load-bearing: they index the [`S_INFOTYPE`] prefix
/// table (`self as usize`), exactly as the C code indexes `s_infotype[type]`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum CurlInfoType {
    /// `CURLINFO_TEXT` (0): informational text from libcurl (printed `"* "`).
    Text = 0,
    /// `CURLINFO_HEADER_IN` (1): an incoming protocol header (`"< "`).
    HeaderIn = 1,
    /// `CURLINFO_HEADER_OUT` (2): an outgoing protocol header (`"> "`).
    HeaderOut = 2,
    /// `CURLINFO_DATA_IN` (3): incoming body data (`"{ "`).
    DataIn = 3,
    /// `CURLINFO_DATA_OUT` (4): outgoing body data (`"} "`).
    DataOut = 4,
    /// `CURLINFO_SSL_DATA_IN` (5): incoming raw TLS bytes (`"{ "`).
    SslDataIn = 5,
    /// `CURLINFO_SSL_DATA_OUT` (6): outgoing raw TLS bytes (`"} "`).
    SslDataOut = 6,
}

impl CurlInfoType {
    /// Converts a raw libcurl `curl_infotype` integer into a [`CurlInfoType`],
    /// returning [`None`] for any value outside the documented `0..=6` range.
    ///
    /// This mirrors the defensive `default:` arm of the C callback, which
    /// ignores unknown info types ("in case a new one is introduced to shock
    /// us"): a caller bridging from the C ABI converts the raw `int` here and
    /// simply skips the call when this returns [`None`].
    #[must_use]
    pub fn from_raw(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::Text),
            1 => Some(Self::HeaderIn),
            2 => Some(Self::HeaderOut),
            3 => Some(Self::DataIn),
            4 => Some(Self::DataOut),
            5 => Some(Self::SslDataIn),
            6 => Some(Self::SslDataOut),
            _ => None,
        }
    }

    /// The raw libcurl integer value of this info type (its `curl_infotype`
    /// discriminant).
    #[must_use]
    pub fn as_raw(self) -> i32 {
        self as i32
    }
}

// ===========================================================================
// Constants transcribed verbatim from `src/tool_cb_dbg.c`.
// ===========================================================================

/// Per-info-type line prefix, indexed by the `curl_infotype` discriminant —
/// the exact `s_infotype[]` table from `log_line_start` (`tool_cb_dbg.c:59-61`).
///
/// Note the deliberate duplication: `DATA_IN`/`SSL_DATA_IN` both render `"{ "`
/// and `DATA_OUT`/`SSL_DATA_OUT` both render `"} "`. The trailing space is part
/// of each entry and must be preserved.
const S_INFOTYPE: [&str; 7] = ["* ", "< ", "> ", "{ ", "} ", "{ ", "} "];

/// Bytes per row for `--trace` (`TRACE_BIN`): 16, leaving room for the hex
/// columns (`tool_cb_dbg.c:75`).
const WIDTH_BIN: usize = 0x10;

/// Bytes per row for `--trace-ascii` (`TRACE_ASCII`): 64. Without the hex
/// columns more bytes fit on screen (`tool_cb_dbg.c:79`).
const WIDTH_ASCII: usize = 0x40;

/// Placeholder rendered for any non-printable byte in the ASCII column —
/// curl's `UNPRINTABLE_CHAR` (`src/tool_setup.h:63`).
const UNPRINTABLE_CHAR: u8 = b'.';

// ===========================================================================
// Cross-call state — the safe replacements for C's function-`static`s.
//
// The CLI runs on a single-threaded Tokio runtime
// (`#[tokio::main(flavor = "current_thread")]`), so a thread-local behaves
// exactly like C's process-wide function-`static` while remaining safe (no
// `static mut`).
// ===========================================================================

thread_local! {
    /// Mirrors C's `static bool newl` in the plain (`-v`) renderer: `true` when
    /// the previous write left a partial line open (no trailing newline), so
    /// the next datum continues that line rather than emitting a fresh prefix.
    static NEWL: Cell<bool> = const { Cell::new(false) };

    /// Mirrors C's `static bool traced_data`: `true` once the `[N bytes data]`
    /// summary has been emitted for the current logical line, so consecutive
    /// body chunks are summarized only once.
    static TRACED_DATA: Cell<bool> = const { Cell::new(false) };

    /// Mirrors C's `static time_t cached_tv_sec` + `static char hms_buf[12]`:
    /// the last whole second and its `"HH:MM:SS"` rendering, so a burst of trace
    /// lines within one second formats the time string only once.
    static HMS_CACHE: RefCell<Option<(i64, String)>> = const { RefCell::new(None) };
}

/// The resolved destination of a single trace write.
///
/// curl keeps a `FILE *` in `global->trace_stream`; this port cannot store the
/// process stdout/stderr in [`GlobalConfig::trace_stream`] (typed
/// `Option<File>`), so the destination is classified per call. The `File`
/// variant is backed by the cached [`GlobalConfig::trace_stream`]; `Stdout` and
/// `Stderr` lock the process streams for the duration of the write.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TraceTarget {
    /// curl's `global->trace_stream == stdout` (`--trace -` / `--trace-ascii -`).
    Stdout,
    /// curl's `global->trace_stream == tool_stderr` (plain `-v`, whose
    /// `trace_dump` is `"%"`, and the default fallback).
    Stderr,
    /// A file opened by the tool, cached on [`GlobalConfig::trace_stream`].
    File,
}

// ===========================================================================
// hms_for_sec — cached "HH:MM:SS" of localtime(tv_sec). (tool_cb_dbg.c:35-50)
// ===========================================================================

/// Returns the local-time `"HH:MM:SS"` (zero-padded) for the given Unix
/// timestamp `tv_sec`, caching the last second's rendering in a thread-local.
///
/// This is the port of C's `hms_for_sec`. The C `"%02d:%02d:%02d"` of
/// `localtime(tv_sec)` becomes `chrono::Local` formatted as `"%H:%M:%S"` (both
/// zero-pad to two digits). On the (practically unreachable) failure to resolve
/// the local time, C zeroes the `struct tm`, yielding `"00:00:00"`; this port
/// reproduces that fallback exactly.
fn hms_for_sec(tv_sec: i64) -> String {
    // Fast path: reuse the cached rendering when the whole second is unchanged.
    if let Some(hit) = HMS_CACHE.with(|cache| {
        cache
            .borrow()
            .as_ref()
            .filter(|(sec, _)| *sec == tv_sec)
            .map(|(_, buf)| buf.clone())
    }) {
        return hit;
    }

    // Render localtime(tv_sec) as zero-padded HH:MM:SS. `single()` yields `None`
    // only for an impossible/ambiguous local instant; C's analog memsets the
    // `struct tm` to zero, i.e. "00:00:00".
    let formatted = match Local.timestamp_opt(tv_sec, 0).single() {
        Some(dt) => dt.format("%H:%M:%S").to_string(),
        None => String::from("00:00:00"),
    };

    HMS_CACHE.with(|cache| {
        *cache.borrow_mut() = Some((tv_sec, formatted.clone()));
    });
    formatted
}

// ===========================================================================
// log_line_start — the per-line prefix. (tool_cb_dbg.c:52-66)
// ===========================================================================

/// Writes the start-of-line marker for `infotype`, optionally preceded by the
/// time and id prefixes — the port of C's `log_line_start`.
///
/// When either `timebuf` or `idsbuf` is non-empty the three pieces are written
/// together (`"%s%s%s"`); otherwise just the bare `s_infotype` marker is
/// written (C's `fputs` fast path). The marker already carries its trailing
/// space.
fn log_line_start(
    out: &mut dyn Write,
    timebuf: &str,
    idsbuf: &str,
    infotype: CurlInfoType,
) -> io::Result<()> {
    let marker = S_INFOTYPE[infotype as usize];
    if !timebuf.is_empty() || !idsbuf.is_empty() {
        write!(out, "{timebuf}{idsbuf}{marker}")
    } else {
        out.write_all(marker.as_bytes())
    }
}

// ===========================================================================
// dump — the tcpdump-style hex/ASCII block. (tool_cb_dbg.c:68-120)
// ===========================================================================

/// Writes a labeled hex/ASCII dump of `ptr` — the port of C's `dump`, used by
/// the `--trace` (`TRACE_BIN`) and `--trace-ascii` (`TRACE_ASCII`) modes.
///
/// The output is:
/// 1. a header line `"<time><ids><label>, <N> bytes (0x<N>)\n"` (decimal then
///    `0x`-prefixed hex length); then
/// 2. one row per `width` bytes: a 4-hex-digit offset and `": "`, the hex
///    columns (BIN mode only, with 3-space padding for past-the-end slots so
///    the ASCII column aligns), and the printable-ASCII column
///    (`0x20..0x7F`, else [`UNPRINTABLE_CHAR`]).
///
/// In the ASCII modes a `\r\n` pair ends the current row early and is skipped,
/// reproducing curl's two CRLF look-ahead checks faithfully. `_infotype` is
/// accepted to match curl's `dump` signature but is unused (C casts it to
/// `(void)`).
///
/// The stream is flushed at the end, mirroring C's `fflush`.
fn dump(
    timebuf: &str,
    idsbuf: &str,
    text: &str,
    out: &mut dyn Write,
    ptr: &[u8],
    tracetype: TraceType,
    _infotype: CurlInfoType,
) -> io::Result<()> {
    let size = ptr.len();
    // `--trace` (BIN) packs 16 bytes/row; `--trace-ascii` fits 64 by dropping
    // the hex columns. Any other `tracetype` defaults to the 16-wide form,
    // matching C's `width = 0x10` initializer.
    let width = if tracetype == TraceType::Ascii {
        WIDTH_ASCII
    } else {
        WIDTH_BIN
    };

    // Header line: "<time><ids><label>, <N> bytes (0x<N>)\n".
    writeln!(out, "{timebuf}{idsbuf}{text}, {size} bytes (0x{size:x})")?;

    let mut i = 0usize;
    while i < size {
        // Row offset: 4-digit lowercase hex followed by ": ".
        write!(out, "{i:04x}: ")?;

        // BIN mode prints the hex columns; past-the-end slots are padded with
        // three spaces so the trailing ASCII column lines up across rows.
        if tracetype == TraceType::Bin {
            for c in 0..width {
                if i + c < size {
                    let byte = ptr[i + c];
                    write!(out, "{byte:02x} ")?;
                } else {
                    out.write_all(b"   ")?;
                }
            }
        }

        // ASCII column, with CRLF-aware early row breaks in the ASCII modes.
        //
        // C mutates the outer index `i` on a `\r\n` boundary and `break`s; the
        // net effect, after the unconditional trailing `i += width`, is:
        //   * normal row completion            -> `i += width`
        //   * CRLF at the current byte          -> `i += c + 2` (CR not printed)
        //   * CRLF beginning at the next byte   -> `i += c + 3` (current printed)
        // `advance` captures that net step so the single `i += advance` below
        // mirrors C's single `i += width` increment site.
        let mut c = 0usize;
        let advance: usize;
        loop {
            // C `for(...)` guard: stop at the row width or the data end.
            if !(c < width && i + c < size) {
                advance = width;
                break;
            }
            // First CRLF check (ASCII modes only): break *before* printing, so
            // the CR and the LF are both skipped.
            if tracetype == TraceType::Ascii
                && i + c + 1 < size
                && ptr[i + c] == 0x0D
                && ptr[i + c + 1] == 0x0A
            {
                advance = c + 2;
                break;
            }
            let byte = ptr[i + c];
            let shown = if (0x20..0x7F).contains(&byte) {
                byte
            } else {
                UNPRINTABLE_CHAR
            };
            out.write_all(&[shown])?;
            // Second CRLF check (ASCII modes only): the CRLF begins at the next
            // byte; break *after* printing the current one. This avoids an
            // extra blank row when a CRLF lands exactly on the row boundary.
            if tracetype == TraceType::Ascii
                && i + c + 2 < size
                && ptr[i + c + 1] == 0x0D
                && ptr[i + c + 2] == 0x0A
            {
                advance = c + 3;
                break;
            }
            c += 1;
        }

        out.write_all(b"\n")?;
        i += advance;
    }

    out.flush()
}

// ===========================================================================
// render_trace — the body of the C mode switch. (tool_cb_dbg.c:190-281)
// ===========================================================================

/// Renders one trace datum to the already-resolved `out` stream — the port of
/// the two-mode body of C's `tool_debug_cb`: the plain (`-v`) renderer
/// (`tool_cb_dbg.c:190-250`) and the hex/ASCII renderer
/// (`tool_cb_dbg.c:252-281`).
///
/// `show_data_alert` is the precomputed C predicate `!isatty || (output is
/// neither stderr nor stdout)`. When it is `false`, the `[N bytes data]`
/// summary is suppressed because the body is already visible on the terminal
/// (curl: "the data _is_ shown then just not via this function").
fn render_trace(
    out: &mut dyn Write,
    timebuf: &str,
    idsbuf: &str,
    tracetype: TraceType,
    infotype: CurlInfoType,
    data: &[u8],
    show_data_alert: bool,
) -> io::Result<()> {
    let size = data.len();

    // ---- plain (`-v` / `TRACE_PLAIN`) mode --------------------------------
    if tracetype == TraceType::Plain {
        match infotype {
            // Outgoing headers: split on '\n' so each header line gets its own
            // "> " prefix; a trailing partial line leaves `newl` set so the
            // next datum continues it.
            CurlInfoType::HeaderOut => {
                if size > 0 {
                    let mut st = 0usize;
                    let mut i = 0usize;
                    // C iterates `for(i = 0; i < size - 1; i++)`.
                    while i < size - 1 {
                        if data[i] == b'\n' {
                            if !NEWL.with(Cell::get) {
                                log_line_start(out, timebuf, idsbuf, infotype)?;
                            }
                            out.write_all(&data[st..=i])?;
                            st = i + 1;
                            NEWL.with(|n| n.set(false));
                        }
                        i += 1;
                    }
                    // Loop exits with `i == size - 1`; write the final segment
                    // `data[st..size]` (C's `fwrite(data + st, i - st + 1, ...)`).
                    if !NEWL.with(Cell::get) {
                        log_line_start(out, timebuf, idsbuf, infotype)?;
                    }
                    out.write_all(&data[st..=i])?;
                }
                NEWL.with(|n| n.set(size > 0 && data[size - 1] != b'\n'));
                TRACED_DATA.with(|t| t.set(false));
            }
            // Informational text and incoming headers: written verbatim,
            // prefixed only when starting a fresh line.
            CurlInfoType::Text | CurlInfoType::HeaderIn => {
                if !NEWL.with(Cell::get) {
                    log_line_start(out, timebuf, idsbuf, infotype)?;
                }
                out.write_all(data)?;
                NEWL.with(|n| n.set(size > 0 && data[size - 1] != b'\n'));
                TRACED_DATA.with(|t| t.set(false));
            }
            // Body / TLS payloads: summarized once as "[N bytes data]" rather
            // than dumped, unless suppressed because the body is on the tty.
            CurlInfoType::DataOut
            | CurlInfoType::DataIn
            | CurlInfoType::SslDataIn
            | CurlInfoType::SslDataOut => {
                if !TRACED_DATA.with(Cell::get) && show_data_alert {
                    if !NEWL.with(Cell::get) {
                        log_line_start(out, timebuf, idsbuf, infotype)?;
                    }
                    writeln!(out, "[{size} bytes data]")?;
                    NEWL.with(|n| n.set(false));
                    TRACED_DATA.with(|t| t.set(true));
                }
            }
        }
        return Ok(());
    }

    // ---- hex/ASCII (`--trace` / `--trace-ascii`) mode ---------------------
    let text = match infotype {
        // Informational text is printed inline with a "* " marker, never dumped
        // (C prints "%s%s* %.*s" then falls through to `return`).
        CurlInfoType::Text => {
            write!(out, "{timebuf}{idsbuf}* ")?;
            return out.write_all(data);
        }
        CurlInfoType::HeaderOut => "=> Send header",
        CurlInfoType::DataOut => "=> Send data",
        CurlInfoType::HeaderIn => "<= Recv header",
        CurlInfoType::DataIn => "<= Recv data",
        CurlInfoType::SslDataIn => "<= Recv SSL data",
        CurlInfoType::SslDataOut => "=> Send SSL data",
    };
    dump(timebuf, idsbuf, text, out, data, tracetype, infotype)
}

// ===========================================================================
// ids_prefix — the "--trace-ids" prefix. (tool_cb_dbg.c:122-167)
// ===========================================================================

/// Formats the `--trace-ids` body for a known transfer id and a possibly-known
/// connection id — the port of C's `TRC_IDS_FORMAT_IDS_2` / `TRC_IDS_FORMAT_IDS_1`.
///
/// A non-negative `conn_id` yields `"[xfer-conn] "`; a negative `conn_id` (the
/// connection is not yet assigned) yields `"[xfer-x] "`. The trailing space is
/// part of the format.
fn format_ids(xfer_id: i64, conn_id: i64) -> String {
    if conn_id >= 0 {
        format!("[{xfer_id}-{conn_id}] ")
    } else {
        format!("[{xfer_id}-x] ")
    }
}

/// Builds the `--trace-ids` prefix from the handle's transfer/connection ids —
/// the port of C's `TRC_IDS_FORMAT_IDS_*` block.
///
/// Returns `"[xfer-conn] "` when both ids are known, `"[xfer-x] "` when only the
/// transfer id is known, and an empty string when ids are disabled, the handle
/// is absent, or the transfer id is unavailable/negative.
fn ids_prefix(handle: Option<&Easy>, traceids: bool) -> String {
    if !traceids {
        return String::new();
    }
    let Some(handle) = handle else {
        return String::new();
    };

    // A `getinfo` error or a non-`OFF_T` value is treated as "unavailable"
    // (negative), mirroring C's `!curl_easy_getinfo(...) && id >= 0` guard.
    let xfer_id = match handle.getinfo(CurlInfo::XferId) {
        Ok(InfoValue::OffT(v)) => v,
        _ => -1,
    };
    if xfer_id < 0 {
        return String::new();
    }

    let conn_id = match handle.getinfo(CurlInfo::ConnId) {
        Ok(InfoValue::OffT(v)) => v,
        _ => -1,
    };
    format_ids(xfer_id, conn_id)
}

// ===========================================================================
// tool_debug_cb — CURLOPT_DEBUGFUNCTION. (tool_cb_dbg.c:128-282)
// ===========================================================================

/// The `CURLOPT_DEBUGFUNCTION` callback — the public entry point and the port
/// of C's `tool_debug_cb`.
///
/// It renders the trace datum (`data`, classified by `infotype`) for the active
/// mode (`global.tracetype`), prefixed by the optional `--trace-time` timestamp
/// and `--trace-ids` ids, to the resolved trace stream (stderr by default,
/// stdout for `--trace -`, or the file named by `--trace`/`--trace-ascii`).
///
/// `handle` is the easy handle owning the transfer (curl's `CURL *`); it is used
/// only to read `CURLINFO_XFER_ID`/`CURLINFO_CONN_ID` for the `--trace-ids`
/// prefix and may be [`None`]. `global` is the process configuration (curl's
/// `per->config->global`); it is taken by `&mut` because the trace file is
/// opened lazily on first use and cached on [`GlobalConfig::trace_stream`].
///
/// Always returns `0`: curl's debug callback never aborts a transfer, and any
/// write error on the trace stream is intentionally ignored (the C code ignores
/// its `fwrite`/`fprintf`/`fflush` return values).
pub fn tool_debug_cb(
    handle: Option<&Easy>,
    infotype: CurlInfoType,
    data: &[u8],
    global: &mut GlobalConfig,
) -> i32 {
    // --- "--trace-time" prefix: "HH:MM:SS.usec " (trailing space), or "". ---
    let timebuf = if global.tracetime {
        let now = Local::now();
        format!(
            "{}.{:06} ",
            hms_for_sec(now.timestamp()),
            now.timestamp_subsec_micros()
        )
    } else {
        String::new()
    };

    // --- "--trace-ids" prefix: "[xfer-conn] " / "[xfer-x] ", or "". --------
    let idsbuf = ids_prefix(handle, global.traceids);

    // --- Resolve (and lazily open) the trace destination. ------------------
    // A real filename is opened once and cached on `global.trace_stream`;
    // "-"/"%" select stdout/stderr; absence defaults to stderr. The dump spec
    // is cloned so no borrow of `global.trace_dump` is held across the
    // `global.trace_stream` mutation.
    let target = if global.trace_stream.is_some() {
        TraceTarget::File
    } else {
        let dump_spec = global.trace_dump.clone();
        match dump_spec.as_deref() {
            Some("-") => TraceTarget::Stdout,
            Some("%") => TraceTarget::Stderr,
            Some(path) => match File::create(path) {
                Ok(file) => {
                    global.trace_stream = Some(file);
                    global.trace_fopened = true;
                    TraceTarget::File
                }
                Err(_) => {
                    warnf!(global, "Failed to create/open output");
                    return 0;
                }
            },
            None => TraceTarget::Stderr,
        }
    };

    // Copy the scalar flags out before borrowing the (possibly file) stream and
    // precompute C's `!isatty || (output is not a std stream)` predicate.
    let tracetype = global.tracetype;
    let is_std_stream = matches!(target, TraceTarget::Stdout | TraceTarget::Stderr);
    let show_data_alert = !global.isatty || !is_std_stream;

    // Acquire the resolved writer. stdout/stderr are locked for the duration of
    // the write; the file is the cached `global.trace_stream`. The lock guards
    // are declared here so they outlive the `&mut dyn Write` borrow below.
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut stdout_lock;
    let mut stderr_lock;
    let out: &mut dyn Write = match target {
        TraceTarget::Stdout => {
            stdout_lock = stdout.lock();
            &mut stdout_lock
        }
        TraceTarget::Stderr => {
            stderr_lock = stderr.lock();
            &mut stderr_lock
        }
        TraceTarget::File => match global.trace_stream.as_mut() {
            Some(file) => file,
            // Unreachable: a `File` target implies the stream is open. Skip the
            // write rather than panic inside a trace callback.
            None => return 0,
        },
    };

    // Render and flush. Write/flush errors are ignored: a trace-stream failure
    // must never abort the transfer (curl ignores these returns too).
    let _ = render_trace(
        out,
        &timebuf,
        &idsbuf,
        tracetype,
        infotype,
        data,
        show_data_alert,
    );
    let _ = out.flush();
    0
}

// ===========================================================================
// Tests — byte-for-byte parity guards for every trace path.
//
// These exercise the private helpers directly (capturing into a `Vec<u8>`
// sink) and the public `tool_debug_cb` end-to-end (capturing into a temp file).
// The expected bytes are transcribed from the behavior of `src/tool_cb_dbg.c`:
// any drift here is a parity regression the curl 8.x suite would catch.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Local, TimeZone};

    /// Resets the plain-mode cross-call thread-locals so a test starts from the
    /// same state as a fresh process (C's zero-initialized function-`static`s).
    fn reset_plain_state() {
        NEWL.with(|n| n.set(false));
        TRACED_DATA.with(|t| t.set(false));
    }

    /// Renders via the private `dump` into a fresh buffer and returns the bytes
    /// as a `String` (all dump output is printable ASCII + spaces + newlines).
    fn dump_to_string(text: &str, ptr: &[u8], tracetype: TraceType) -> String {
        let mut buf: Vec<u8> = Vec::new();
        dump(
            "",
            "",
            text,
            &mut buf,
            ptr,
            tracetype,
            CurlInfoType::HeaderOut,
        )
        .unwrap();
        String::from_utf8(buf).expect("dump output is valid UTF-8")
    }

    // ---- constants & enum transcription guards ----------------------------

    #[test]
    fn s_infotype_table_is_transcribed_exactly() {
        // The deliberate duplication (DATA_IN/SSL_DATA_IN -> "{ ",
        // DATA_OUT/SSL_DATA_OUT -> "} ") and the trailing spaces are load-bearing.
        assert_eq!(S_INFOTYPE, ["* ", "< ", "> ", "{ ", "} ", "{ ", "} "]);
    }

    #[test]
    fn dump_widths_and_unprintable_are_exact() {
        assert_eq!(WIDTH_BIN, 0x10);
        assert_eq!(WIDTH_ASCII, 0x40);
        assert_eq!(UNPRINTABLE_CHAR, b'.');
    }

    #[test]
    fn curl_info_type_round_trips_and_rejects_out_of_range() {
        for raw in 0..=6 {
            let t = CurlInfoType::from_raw(raw).expect("0..=6 are valid");
            assert_eq!(t.as_raw(), raw);
            // The discriminant must index `S_INFOTYPE` (no panic, in range).
            assert!((t as usize) < S_INFOTYPE.len());
        }
        assert_eq!(CurlInfoType::from_raw(7), None);
        assert_eq!(CurlInfoType::from_raw(-1), None);
        assert_eq!(CurlInfoType::from_raw(i32::MAX), None);
    }

    // ---- log_line_start ----------------------------------------------------

    #[test]
    fn log_line_start_bare_marker_when_no_prefixes() {
        // Each info type maps to its exact `s_infotype` marker, no extra bytes.
        let cases = [
            (CurlInfoType::Text, "* "),
            (CurlInfoType::HeaderIn, "< "),
            (CurlInfoType::HeaderOut, "> "),
            (CurlInfoType::DataIn, "{ "),
            (CurlInfoType::DataOut, "} "),
            (CurlInfoType::SslDataIn, "{ "),
            (CurlInfoType::SslDataOut, "} "),
        ];
        for (info, marker) in cases {
            let mut buf: Vec<u8> = Vec::new();
            log_line_start(&mut buf, "", "", info).unwrap();
            assert_eq!(String::from_utf8(buf).unwrap(), marker);
        }
    }

    #[test]
    fn log_line_start_prepends_time_and_ids() {
        let mut buf: Vec<u8> = Vec::new();
        log_line_start(
            &mut buf,
            "12:00:00.000000 ",
            "[1-2] ",
            CurlInfoType::HeaderIn,
        )
        .unwrap();
        // C: curl_mfprintf(log, "%s%s%s", timebuf, idsbuf, s_infotype[type]).
        assert_eq!(String::from_utf8(buf).unwrap(), "12:00:00.000000 [1-2] < ");
    }

    #[test]
    fn log_line_start_uses_prefix_path_when_only_ids_present() {
        // Non-empty idsbuf alone must still take the "%s%s%s" path.
        let mut buf: Vec<u8> = Vec::new();
        log_line_start(&mut buf, "", "[7-x] ", CurlInfoType::HeaderOut).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "[7-x] > ");
    }

    // ---- dump: BIN (--trace) ----------------------------------------------

    #[test]
    fn dump_bin_full_16_byte_row() {
        // A complete 16-byte row: hex columns + ASCII column; CR/LF render as
        // '.' in the ASCII column (BIN never line-wraps on CRLF).
        let out = dump_to_string("=> Send header", b"GET / HTTP/1.1\r\n", TraceType::Bin);
        let expected = "=> Send header, 16 bytes (0x10)\n\
             0000: 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a GET / HTTP/1.1..\n";
        assert_eq!(out, expected);
    }

    #[test]
    fn dump_bin_partial_row_is_space_padded() {
        // 3 of 16 slots used: the remaining 13 slots are 3-space pads so the
        // ASCII column still aligns.
        let out = dump_to_string("test", b"abc", TraceType::Bin);
        let mut expected = String::from("test, 3 bytes (0x3)\n0000: 61 62 63 ");
        expected.push_str(&" ".repeat(3 * (WIDTH_BIN - 3)));
        expected.push_str("abc\n");
        assert_eq!(out, expected);
    }

    #[test]
    fn dump_bin_ignores_crlf_no_line_wrap() {
        // BIN mode must NOT honor the ASCII CRLF early-break: "A\r\nB" stays on
        // one row with '.' for the CR and LF.
        let out = dump_to_string("test", b"A\r\nB", TraceType::Bin);
        let mut expected = String::from("test, 4 bytes (0x4)\n0000: 41 0d 0a 42 ");
        expected.push_str(&" ".repeat(3 * (WIDTH_BIN - 4)));
        expected.push_str("A..B\n");
        assert_eq!(out, expected);
    }

    #[test]
    fn dump_header_line_hex_length_is_lowercase_0x() {
        // 26 bytes -> "26 bytes (0x1a)"; verify the exact header line form.
        let out = dump_to_string("lbl", &[0u8; 26], TraceType::Bin);
        assert!(
            out.starts_with("lbl, 26 bytes (0x1a)\n"),
            "header line mismatch: {out:?}"
        );
    }

    // ---- dump: ASCII (--trace-ascii) --------------------------------------

    #[test]
    fn dump_ascii_has_no_hex_columns_and_64_wide() {
        // ASCII mode prints only the offset + ASCII column (no hex), width 64.
        let out = dump_to_string("test", b"abc", TraceType::Ascii);
        assert_eq!(out, "test, 3 bytes (0x3)\n0000: abc\n");
    }

    #[test]
    fn dump_ascii_wraps_each_line_at_crlf() {
        // The two-line payload wraps into two rows; the CRLF pairs are consumed
        // (second look-ahead check), and the offset advances past them.
        let out = dump_to_string("test", b"Line1\r\nLine2\r\n", TraceType::Ascii);
        assert_eq!(out, "test, 14 bytes (0xe)\n0000: Line1\n0007: Line2\n");
    }

    #[test]
    fn dump_ascii_leading_crlf_triggers_first_check() {
        // A CRLF at the very start exercises the FIRST look-ahead check: the row
        // is emitted empty (just the offset) and the index skips the CRLF.
        let out = dump_to_string("test", b"\r\nA", TraceType::Ascii);
        assert_eq!(out, "test, 3 bytes (0x3)\n0000: \n0002: A\n");
    }

    #[test]
    fn dump_ascii_unprintable_becomes_dot() {
        // A NUL and a 0x7F (DEL) are both non-printable -> '.'; 0x7E ('~') prints.
        let out = dump_to_string("t", &[0x00, 0x7E, 0x7F], TraceType::Ascii);
        assert_eq!(out, "t, 3 bytes (0x3)\n0000: .~.\n");
    }

    // ---- render_trace: plain (-v) -----------------------------------------

    #[test]
    fn render_plain_header_out_splits_and_prefixes_each_line() {
        reset_plain_state();
        let mut buf: Vec<u8> = Vec::new();
        render_trace(
            &mut buf,
            "",
            "",
            TraceType::Plain,
            CurlInfoType::HeaderOut,
            b"GET / HTTP/1.1\r\nHost: x\r\n",
            true,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "> GET / HTTP/1.1\r\n> Host: x\r\n"
        );
    }

    #[test]
    fn render_plain_text_gets_star_prefix() {
        reset_plain_state();
        let mut buf: Vec<u8> = Vec::new();
        render_trace(
            &mut buf,
            "",
            "",
            TraceType::Plain,
            CurlInfoType::Text,
            b"Trying 1.2.3.4...\n",
            true,
        )
        .unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "* Trying 1.2.3.4...\n");
    }

    #[test]
    fn render_plain_header_in_gets_lt_prefix() {
        reset_plain_state();
        let mut buf: Vec<u8> = Vec::new();
        render_trace(
            &mut buf,
            "",
            "",
            TraceType::Plain,
            CurlInfoType::HeaderIn,
            b"HTTP/1.1 200 OK\r\n",
            true,
        )
        .unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "< HTTP/1.1 200 OK\r\n");
    }

    #[test]
    fn render_plain_continues_partial_line_without_new_prefix() {
        // A first datum with no trailing newline sets `newl`; the next datum
        // must continue the same line (no fresh "* " marker).
        reset_plain_state();
        let mut buf: Vec<u8> = Vec::new();
        render_trace(
            &mut buf,
            "",
            "",
            TraceType::Plain,
            CurlInfoType::Text,
            b"abc",
            true,
        )
        .unwrap();
        render_trace(
            &mut buf,
            "",
            "",
            TraceType::Plain,
            CurlInfoType::Text,
            b"def\n",
            true,
        )
        .unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "* abcdef\n");
    }

    #[test]
    fn render_plain_data_emits_summary_once() {
        // The body is summarized as "[N bytes data]" exactly once per logical
        // line; a second body chunk is silent until a non-data datum resets it.
        reset_plain_state();
        let mut buf: Vec<u8> = Vec::new();
        let body = vec![0u8; 100];
        render_trace(
            &mut buf,
            "",
            "",
            TraceType::Plain,
            CurlInfoType::DataOut,
            &body,
            true,
        )
        .unwrap();
        render_trace(
            &mut buf,
            "",
            "",
            TraceType::Plain,
            CurlInfoType::DataOut,
            &body,
            true,
        )
        .unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "} [100 bytes data]\n");
    }

    #[test]
    fn render_plain_data_suppressed_when_not_alerting() {
        // When the body is already visible on the tty (`show_data_alert==false`),
        // no summary line is emitted at all.
        reset_plain_state();
        let mut buf: Vec<u8> = Vec::new();
        render_trace(
            &mut buf,
            "",
            "",
            TraceType::Plain,
            CurlInfoType::DataIn,
            &[0u8; 50],
            false,
        )
        .unwrap();
        assert!(buf.is_empty(), "expected no output, got {buf:?}");
    }

    #[test]
    fn render_plain_prefixes_include_time_and_ids() {
        // The resolved time/ids prefixes precede the marker on a fresh line.
        reset_plain_state();
        let mut buf: Vec<u8> = Vec::new();
        render_trace(
            &mut buf,
            "12:00:00.000000 ",
            "[3-4] ",
            TraceType::Plain,
            CurlInfoType::HeaderIn,
            b"X\r\n",
            true,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "12:00:00.000000 [3-4] < X\r\n"
        );
    }

    // ---- render_trace: hex/ASCII modes ------------------------------------

    #[test]
    fn render_bin_text_is_inline_with_star_not_dumped() {
        // CURLINFO_TEXT in BIN/ASCII mode is printed inline ("* %.*s"), never
        // hex-dumped, and has no trailing newline of its own.
        let mut buf: Vec<u8> = Vec::new();
        render_trace(
            &mut buf,
            "",
            "",
            TraceType::Bin,
            CurlInfoType::Text,
            b"hello",
            true,
        )
        .unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "* hello");
    }

    #[test]
    fn render_bin_text_inline_includes_prefixes() {
        let mut buf: Vec<u8> = Vec::new();
        render_trace(
            &mut buf,
            "00:00:01.000000 ",
            "[1-x] ",
            TraceType::Ascii,
            CurlInfoType::Text,
            b"hi",
            true,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "00:00:01.000000 [1-x] * hi"
        );
    }

    #[test]
    fn render_dump_labels_match_curl_exactly() {
        // Each non-text info type maps to its exact dump label; verify via the
        // header line `dump` emits ("<label>, 1 bytes (0x1)\n").
        let cases = [
            (CurlInfoType::HeaderOut, "=> Send header"),
            (CurlInfoType::DataOut, "=> Send data"),
            (CurlInfoType::HeaderIn, "<= Recv header"),
            (CurlInfoType::DataIn, "<= Recv data"),
            (CurlInfoType::SslDataIn, "<= Recv SSL data"),
            (CurlInfoType::SslDataOut, "=> Send SSL data"),
        ];
        for (info, label) in cases {
            let mut buf: Vec<u8> = Vec::new();
            render_trace(&mut buf, "", "", TraceType::Bin, info, b"x", true).unwrap();
            let out = String::from_utf8(buf).unwrap();
            let want = format!("{label}, 1 bytes (0x1)\n");
            assert!(
                out.starts_with(&want),
                "info {info:?}: expected label line {want:?}, got {out:?}"
            );
        }
    }

    // ---- format_ids / ids_prefix ------------------------------------------

    #[test]
    fn format_ids_renders_both_curl_id_formats() {
        // TRC_IDS_FORMAT_IDS_2 ("[%-%] ") and IDS_1 ("[%-x] "), trailing space.
        assert_eq!(format_ids(1, 2), "[1-2] ");
        assert_eq!(format_ids(0, 0), "[0-0] ");
        assert_eq!(format_ids(42, 0), "[42-0] ");
        assert_eq!(format_ids(5, -1), "[5-x] ");
        assert_eq!(format_ids(123, -7), "[123-x] ");
    }

    #[test]
    fn ids_prefix_empty_when_disabled_or_no_handle() {
        assert_eq!(ids_prefix(None, true), "");
        assert_eq!(ids_prefix(None, false), "");
    }

    // ---- hms_for_sec -------------------------------------------------------

    #[test]
    fn hms_for_sec_matches_localtime_and_caches() {
        let t = 1_700_000_000_i64;
        let expected = Local
            .timestamp_opt(t, 0)
            .single()
            .unwrap()
            .format("%H:%M:%S")
            .to_string();
        // First call populates the cache; second hits it; both must agree.
        assert_eq!(hms_for_sec(t), expected);
        assert_eq!(hms_for_sec(t), expected);
        // Exactly "HH:MM:SS" — 8 chars with colons at the fixed positions.
        let s = hms_for_sec(t);
        assert_eq!(s.len(), 8);
        assert_eq!(&s[2..3], ":");
        assert_eq!(&s[5..6], ":");
        // A different second invalidates the cache and recomputes.
        let t2 = t + 3661; // +1h 1m 1s -> a guaranteed different rendering
        let expected2 = Local
            .timestamp_opt(t2, 0)
            .single()
            .unwrap()
            .format("%H:%M:%S")
            .to_string();
        assert_eq!(hms_for_sec(t2), expected2);
    }

    // ---- tool_debug_cb: end-to-end to a file ------------------------------

    #[test]
    fn tool_debug_cb_opens_file_once_and_appends_bin_dump() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trace.bin");
        let path_str = path.to_str().unwrap().to_string();

        // tracetime/traceids/isatty all default to false.
        let mut g = GlobalConfig {
            tracetype: TraceType::Bin,
            trace_dump: Some(path_str),
            ..Default::default()
        };

        // First write: the file is created lazily and the flag is set.
        let rc = tool_debug_cb(None, CurlInfoType::HeaderOut, b"GET / HTTP/1.1\r\n", &mut g);
        assert_eq!(rc, 0);
        assert!(g.trace_stream.is_some(), "file should be opened");
        assert!(g.trace_fopened, "trace_fopened must be set for cleanup");

        // Second write reuses the cached handle (no truncate) and appends.
        let rc = tool_debug_cb(None, CurlInfoType::HeaderIn, b"OK", &mut g);
        assert_eq!(rc, 0);

        let contents = std::fs::read(&path).unwrap();
        let contents = String::from_utf8(contents).unwrap();

        let mut expected = String::from(
            "=> Send header, 16 bytes (0x10)\n\
             0000: 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a GET / HTTP/1.1..\n",
        );
        expected.push_str("<= Recv header, 2 bytes (0x2)\n0000: 4f 4b ");
        expected.push_str(&" ".repeat(3 * (WIDTH_BIN - 2)));
        expected.push_str("OK\n");
        assert_eq!(contents, expected);

        // Keep the temp dir alive until after the read.
        drop(g);
        drop(dir);
    }

    #[test]
    fn tool_debug_cb_std_stream_targets_open_no_file() {
        // "-" selects stdout and "%" selects stderr; neither must open a file.
        // Using a body datum with `isatty` set makes the plain renderer suppress
        // the "[N bytes data]" summary (show_data_alert == false), so this test
        // verifies the lazy-open path without writing to the process streams.
        for spec in ["-", "%"] {
            let mut g = GlobalConfig {
                tracetype: TraceType::Plain,
                trace_dump: Some(spec.to_string()),
                isatty: true, // body already on the tty -> summary suppressed
                ..Default::default()
            };
            reset_plain_state();
            let rc = tool_debug_cb(None, CurlInfoType::DataIn, b"body", &mut g);
            assert_eq!(rc, 0);
            assert!(
                g.trace_stream.is_none(),
                "spec {spec:?} must not open a file"
            );
            assert!(!g.trace_fopened, "spec {spec:?} must not set trace_fopened");
        }
    }

    #[test]
    fn tool_debug_cb_always_returns_zero() {
        // The debug callback never aborts a transfer. The suppressed-data path
        // (isatty + std stream) keeps this assertion free of stream output.
        let mut g = GlobalConfig {
            tracetype: TraceType::Plain,
            trace_dump: Some("%".to_string()),
            isatty: true,
            ..Default::default()
        };
        reset_plain_state();
        assert_eq!(
            tool_debug_cb(None, CurlInfoType::DataIn, b"data", &mut g),
            0
        );
    }
}
