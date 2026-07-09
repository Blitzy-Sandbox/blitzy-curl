// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

//! CURLOPT_DEBUGFUNCTION — `-v`/`--trace`/`--trace-ascii`/`--trace-time` hex+ascii dump.
//! Rust rewrite of curl 8.19.0-DEV `src/tool_cb_dbg.c`. Output is byte-for-byte identical to
//! curl 8.x.
//!
//! The C original reaches its configuration through the file-scope
//! `extern struct GlobalConfig *global` (`tool_cfgable.h`). curl-rs has no mutable process
//! global, so the CLI threads the [`GlobalConfig`] through `CURLOPT_DEBUGDATA`
//! (`operate.rs`), and the callback recovers it from its `userdata` argument. The callback
//! still needs `&mut GlobalConfig` because it lazily opens the trace output stream on first
//! use, exactly as curl does.
//!
//! Everything the callback emits for a single invocation is assembled into an in-memory buffer
//! and then written to the resolved sink in one shot. Because a C `FILE *` is buffered too, and
//! curl flushes at the end of each dump, the resulting bytes are identical; buffering merely
//! keeps the mutable borrow used for sink resolution disjoint from the write step.

use std::cell::Cell;
use std::io::{stderr, stdout, Write};

use chrono::Local;
use libc::{c_char, c_int, c_void, size_t};

use crate::args::{GlobalConfig, TraceType};
use crate::callbacks::userdata_mut;
use crate::operate::warnf;
use curl_rs_ffi::easy::{crs_easy_getinfo, curl_infotype, curl_off_t, CURLINFO};

/// Byte substituted for any non-printable octet in the ASCII column (curl `UNPRINTABLE_CHAR`,
/// `tool_setup.h`).
const UNPRINTABLE_CHAR: u8 = b'.';

/// Per-`curl_infotype` line-start markers, indexed by the info type's discriminant. A verbatim
/// transcription of curl's `s_infotype[]` (`tool_cb_dbg.c`): `CURLINFO_TEXT` → `"* "`,
/// header in/out → `"< "`/`"> "`, and the (SSL) data in/out pairs → `"{ "`/`"} "`. Only the
/// seven real info types (discriminants 0..=6) are ever passed to [`log_line_start`].
static S_INFOTYPE: [&str; 7] = ["* ", "< ", "> ", "{ ", "} ", "{ ", "} "];

// curl's trace-id line prefixes (`TRC_IDS_FORMAT_IDS_1` / `TRC_IDS_FORMAT_IDS_2`,
// `tool_cb_dbg.c`) expand `CURL_FORMAT_CURL_OFF_T` to a signed 64-bit decimal. They are applied
// inline below as `format!("[{xfer_id}-x] ")` (xfer only) and
// `format!("[{xfer_id}-{conn_id}] ")` (xfer + conn).

thread_local! {
    // curl declares these as function-local `static bool`s inside `tool_debug_cb`; they persist
    // across every invocation and gate the line-start prefix and the "[N bytes data]" note in
    // TRACE_PLAIN mode. The CLI trace/verbose callback runs on curl 8.x's single-threaded model
    // (Tokio current-thread), so a thread-local reproduces the process-global lifetime exactly.
    /// `true` while the previous plain-trace write did not end on a newline (curl `newl`).
    static NEWL: Cell<bool> = const { Cell::new(false) };
    /// `true` once the "[N bytes data]" note has been emitted for the current run of data
    /// records, suppressing duplicates (curl `traced_data`).
    static TRACED_DATA: Cell<bool> = const { Cell::new(false) };
}

/// The resolved destination for a trace record.
///
/// curl caches `stdout`/`tool_stderr`/an `fopen`'d `FILE *` in `global->trace_stream`. curl-rs's
/// [`GlobalConfig::trace_stream`] can only own a real file (`Option<fs::File>`), so the standard
/// streams — which carry no per-open state — are represented by these variants and re-resolved
/// from `trace_dump` each call, yielding the same target every time.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TraceTarget {
    /// `--trace -` writes to standard output.
    Stdout,
    /// `-v`/`--trace %` (and the defensive no-dump-target fallback) write to standard error.
    Stderr,
    /// `--trace <file>` writes to an owned file held in [`GlobalConfig::trace_stream`].
    File,
}

/// Emit the per-line prefix (curl's `log_line_start`, `tool_cb_dbg.c`).
///
/// When a timestamp and/or id column is present the prefix is `"<time><ids><marker>"`; otherwise
/// only the bare info-type marker is written. Writes target an in-memory buffer, so the I/O
/// results cannot fail and are intentionally discarded.
fn log_line_start(out: &mut Vec<u8>, timebuf: &str, idsbuf: &str, type_: curl_infotype) {
    let marker = S_INFOTYPE[type_ as usize];
    if !timebuf.is_empty() || !idsbuf.is_empty() {
        let _ = write!(out, "{timebuf}{idsbuf}{marker}");
    } else {
        let _ = out.write_all(marker.as_bytes());
    }
}

/// Render a hex/ascii dump of `ptr` (curl's `dump`, `tool_cb_dbg.c`), byte-for-byte.
///
/// `width` is 16 bytes per row for a full `--trace` (hex + ascii) dump and 64 for the ASCII-only
/// `--trace-ascii` dump. The ASCII column splits protocol lines on `0D 0A` (CR-LF) so each line
/// begins on a fresh dump row. `ptr` is the exact slice libcurl handed us, so its length is the
/// authoritative byte count and every index is in bounds. (curl's `dump` also received an unused
/// `infotype` argument — `(void)infotype;` — which is therefore not reproduced here.)
fn dump(
    out: &mut Vec<u8>,
    timebuf: &str,
    idsbuf: &str,
    text: &str,
    ptr: &[u8],
    tracetype: TraceType,
) {
    let size = ptr.len();
    let width: usize = if tracetype == TraceType::Ascii {
        0x40
    } else {
        0x10
    };

    // Header: "<time><ids><text>, <n> bytes (0x<n>)\n"  (curl "%s%s%s, %zu bytes (0x%zx)\n").
    let _ = writeln!(out, "{timebuf}{idsbuf}{text}, {size} bytes (0x{size:x})");

    let mut i = 0usize;
    while i < size {
        // Offset column, curl "%04zx: ".
        let _ = write!(out, "{i:04x}: ");

        if tracetype == TraceType::Bin {
            // Hex column (full dump only); short final rows are padded with three spaces per
            // missing byte so the ASCII column always starts at the same position.
            for c in 0..width {
                if i + c < size {
                    let _ = write!(out, "{:02x} ", ptr[i + c]);
                } else {
                    let _ = out.write_all(b"   ");
                }
            }
        }

        // ASCII column. `inc` is the outer-index advance for this row: `width` normally, but
        // shortened to end the row right after a CR-LF pair. This mirrors curl's
        // `i += (c + N - width)` inside the loop plus the enclosing `for`'s `i += width`
        // (net `i += c + N`), computed here without any unsigned underflow.
        let mut inc = width;
        let mut c = 0usize;
        while c < width && i + c < size {
            // Check for 0D0A before emitting: a CR-LF starting here ends the row immediately.
            if tracetype == TraceType::Ascii
                && i + c + 1 < size
                && ptr[i + c] == 0x0D
                && ptr[i + c + 1] == 0x0A
            {
                inc = c + 2;
                break;
            }
            let byte = ptr[i + c];
            let printable = if (0x20..0x7F).contains(&byte) {
                byte
            } else {
                UNPRINTABLE_CHAR
            };
            let _ = out.write_all(&[printable]);
            // Check again after emitting to avoid an extra newline when the CR-LF sits exactly
            // on the row (width) boundary.
            if tracetype == TraceType::Ascii
                && i + c + 2 < size
                && ptr[i + c + 1] == 0x0D
                && ptr[i + c + 2] == 0x0A
            {
                inc = c + 3;
                break;
            }
            c += 1;
        }
        let _ = out.write_all(b"\n");
        i += inc;
    }
}

/// libcurl `CURLOPT_DEBUGFUNCTION` callback — renders `-v`/`--trace`/`--trace-ascii`/
/// `--trace-time` diagnostics identically to curl 8.x.
///
/// This is the byte-exact port of curl 8.19.0-DEV `int tool_debug_cb(...)`
/// (`src/tool_cb_dbg.c`). It is registered on the easy handle by `operate.rs` together with a
/// `CURLOPT_DEBUGDATA` pointer to the CLI's [`GlobalConfig`]. `#[no_mangle]` keeps the callback
/// (and its byte-exact helper chain) a reachable symbol — matching curl's linkable
/// `tool_debug_cb` — so the dump logic is retained even before the registration is wired.
///
/// # Safety
/// * `data` must point to `size` readable bytes, or be null when `size == 0`.
/// * `userdata` must be the [`GlobalConfig`]-bearing context installed via `CURLOPT_DEBUGDATA`:
///   a live, uniquely-borrowed `*mut GlobalConfig` that outlives this call (the CLI trace
///   callback runs single-threaded), or null.
/// * `handle` is the `CURL *` for this transfer and may be null.
#[no_mangle]
pub unsafe extern "C" fn tool_debug_cb(
    handle: *mut c_void,
    type_: curl_infotype,
    data: *mut c_char,
    size: size_t,
    userdata: *mut c_void,
) -> c_int {
    // Recover the CLI configuration the C original read from its file-scope `global`. A null or
    // foreign pointer means "nothing to trace", so return success with no output — the same
    // observable result as a disabled trace.
    // SAFETY: per the contract above, `userdata` is a live, uniquely-borrowed `*mut GlobalConfig`
    // for the duration of this call, or null (which `userdata_mut` reports as `None`).
    let global = match unsafe { userdata_mut::<GlobalConfig>(userdata) } {
        Some(g) => g,
        None => return 0,
    };

    // Snapshot the Copy scalar fields up front so the mutable borrow taken below to lazily open
    // the trace file does not conflict with reading them.
    let tracetime = global.tracetime;
    let traceids = global.traceids;
    let tracetype = global.tracetype;
    let isatty = global.isatty;

    // View the payload as bytes. libcurl passes `size` readable bytes at `data`; a null pointer
    // or zero length yields an empty slice, and `size` is re-derived from the slice so every
    // later index is in bounds.
    // SAFETY: per the contract above, `data` covers `size` initialized bytes for this call.
    let data_slice: &[u8] = if data.is_null() || size == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(data as *const u8, size) }
    };
    let size = data_slice.len();

    // --- timestamp column (`--trace-time`) -------------------------------------------------
    // curl: hms_for_sec() + "%s.%06ld " over gettimeofday(); chrono::Local reproduces the same
    // local "HH:MM:SS.uuuuuu " string, trailing space included.
    let timebuf: String = if tracetime {
        let now = Local::now();
        format!(
            "{}.{:06} ",
            now.format("%H:%M:%S"),
            now.timestamp_subsec_micros()
        )
    } else {
        String::new()
    };

    // --- xfer/conn id column (`--trace-ids`) -----------------------------------------------
    // Emitted only with a live handle, when ids are requested, the getinfo call succeeds, and
    // the value is non-negative — matching curl's guards exactly. `CURLINFO_XFER_ID` and
    // `CURLINFO_CONN_ID` are `CURLINFO_OFF_T` infos read through a `curl_off_t *` out-pointer.
    let idsbuf: String = if !handle.is_null() && traceids {
        let mut xfer_id: curl_off_t = 0;
        // SAFETY: `handle` is the live `CURL *` libcurl passed to this callback; `&mut xfer_id`
        // is a valid `curl_off_t *` for the duration of the call.
        let xfer_ok = unsafe {
            crs_easy_getinfo(
                handle,
                CURLINFO::CURLINFO_XFER_ID as c_int,
                &mut xfer_id as *mut curl_off_t as usize,
            )
        } == 0;
        if xfer_ok && xfer_id >= 0 {
            let mut conn_id: curl_off_t = 0;
            // SAFETY: as above; `&mut conn_id` is a valid `curl_off_t *` for the call.
            let conn_ok = unsafe {
                crs_easy_getinfo(
                    handle,
                    CURLINFO::CURLINFO_CONN_ID as c_int,
                    &mut conn_id as *mut curl_off_t as usize,
                )
            } == 0;
            if conn_ok && conn_id >= 0 {
                format!("[{xfer_id}-{conn_id}] ")
            } else {
                format!("[{xfer_id}-x] ")
            }
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    // --- resolve the output sink -----------------------------------------------------------
    // curl's default is tool_stderr; on first use `trace_stream` is opened from `trace_dump`:
    // "-" => stdout, "%" => stderr, else a freshly created file (`trace_fopened = TRUE`).
    let target: TraceTarget = if global.trace_stream.is_some() {
        // An already-open trace_stream is always a file we own.
        TraceTarget::File
    } else {
        match global.trace_dump.as_deref() {
            Some("-") => TraceTarget::Stdout,
            // "%" is curl's undocumented stderr alias; a missing dump target also defaults to
            // stderr, matching curl's initial `output = tool_stderr`.
            Some("%") | None => TraceTarget::Stderr,
            Some(path) => {
                // Truncate/create the trace file. On the supported Unix targets curl's "wt"
                // text mode performs no CR-LF translation, so File::create is byte-identical.
                match std::fs::File::create(path) {
                    Ok(file) => {
                        global.trace_stream = Some(file);
                        global.trace_fopened = true;
                        TraceTarget::File
                    }
                    Err(_) => {
                        // curl: warnf("Failed to create/open output") then skip this record.
                        warnf(global.diag(), "Failed to create/open output");
                        return 0;
                    }
                }
            }
        }
    };
    let output_is_std = matches!(target, TraceTarget::Stdout | TraceTarget::Stderr);

    // Assemble this call's trace bytes, then flush them to the sink once (below).
    let mut buf: Vec<u8> = Vec::new();

    if tracetype == TraceType::Plain {
        // curl's function-local `static bool newl, traced_data;` — see the thread_local note.
        let mut newl = NEWL.with(Cell::get);
        let mut traced_data = TRACED_DATA.with(Cell::get);

        match type_ {
            curl_infotype::CURLINFO_HEADER_OUT => {
                if size > 0 {
                    // Print each LF-terminated line with its own line-start prefix. The scan
                    // covers indices 0..size-1 (curl `for(i = 0; i < size - 1; i++)`), leaving a
                    // trailing byte for the tail write below.
                    let mut st = 0usize;
                    let mut i = 0usize;
                    while i < size - 1 {
                        if data_slice[i] == b'\n' {
                            if !newl {
                                log_line_start(&mut buf, &timebuf, &idsbuf, type_);
                            }
                            let _ = buf.write_all(&data_slice[st..=i]);
                            st = i + 1;
                            newl = false;
                        }
                        i += 1;
                    }
                    // Tail from the last LF to the end (curl writes data+st, i-st+1 with
                    // i == size-1 here).
                    if !newl {
                        log_line_start(&mut buf, &timebuf, &idsbuf, type_);
                    }
                    let _ = buf.write_all(&data_slice[st..size]);
                }
                newl = size > 0 && data_slice[size - 1] != b'\n';
                traced_data = false;
            }
            curl_infotype::CURLINFO_TEXT | curl_infotype::CURLINFO_HEADER_IN => {
                if !newl {
                    log_line_start(&mut buf, &timebuf, &idsbuf, type_);
                }
                let _ = buf.write_all(data_slice);
                newl = size > 0 && data_slice[size - 1] != b'\n';
                traced_data = false;
            }
            curl_infotype::CURLINFO_DATA_OUT
            | curl_infotype::CURLINFO_DATA_IN
            | curl_infotype::CURLINFO_SSL_DATA_IN
            | curl_infotype::CURLINFO_SSL_DATA_OUT => {
                if !traced_data {
                    // Skip the note only when the data is already visible on the same tty: it is
                    // shown iff the output is NOT a std stream, or std but not a terminal.
                    if !isatty || !output_is_std {
                        if !newl {
                            log_line_start(&mut buf, &timebuf, &idsbuf, type_);
                        }
                        let _ = writeln!(buf, "[{size} bytes data]");
                        newl = false;
                        traced_data = true;
                    }
                }
            }
            _ => {
                newl = false;
                traced_data = false;
            }
        }

        NEWL.with(|c| c.set(newl));
        TRACED_DATA.with(|c| c.set(traced_data));
        write_sink(global, target, &buf);
        return 0;
    }

    // --- non-plain (`--trace` / `--trace-ascii`) -------------------------------------------
    match type_ {
        curl_infotype::CURLINFO_TEXT => {
            // curl: "%s%s* %.*s" then FALLTHROUGH to default (no hex/ascii dump). The payload is
            // written verbatim — it already carries its own newline.
            let _ = write!(buf, "{timebuf}{idsbuf}* ");
            let _ = buf.write_all(data_slice);
        }
        curl_infotype::CURLINFO_HEADER_OUT => {
            dump(
                &mut buf,
                &timebuf,
                &idsbuf,
                "=> Send header",
                data_slice,
                tracetype,
            );
        }
        curl_infotype::CURLINFO_DATA_OUT => {
            dump(
                &mut buf,
                &timebuf,
                &idsbuf,
                "=> Send data",
                data_slice,
                tracetype,
            );
        }
        curl_infotype::CURLINFO_HEADER_IN => {
            dump(
                &mut buf,
                &timebuf,
                &idsbuf,
                "<= Recv header",
                data_slice,
                tracetype,
            );
        }
        curl_infotype::CURLINFO_DATA_IN => {
            dump(
                &mut buf,
                &timebuf,
                &idsbuf,
                "<= Recv data",
                data_slice,
                tracetype,
            );
        }
        curl_infotype::CURLINFO_SSL_DATA_IN => {
            dump(
                &mut buf,
                &timebuf,
                &idsbuf,
                "<= Recv SSL data",
                data_slice,
                tracetype,
            );
        }
        curl_infotype::CURLINFO_SSL_DATA_OUT => {
            dump(
                &mut buf,
                &timebuf,
                &idsbuf,
                "=> Send SSL data",
                data_slice,
                tracetype,
            );
        }
        _ => {}
    }

    write_sink(global, target, &buf);
    0
}

/// Write the assembled trace bytes to the resolved sink and flush (curl's `fflush(stream)`).
fn write_sink(global: &mut GlobalConfig, target: TraceTarget, buf: &[u8]) {
    match target {
        TraceTarget::File => {
            if let Some(file) = global.trace_stream.as_mut() {
                let _ = file.write_all(buf);
                let _ = file.flush();
            }
        }
        TraceTarget::Stdout => {
            let mut out = stdout();
            let _ = out.write_all(buf);
            let _ = out.flush();
        }
        TraceTarget::Stderr => {
            let mut err = stderr();
            let _ = err.write_all(buf);
            let _ = err.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    //! Byte-exact tests for the pure formatting helpers ([`log_line_start`] and [`dump`]) — the
    //! parts on which the `--trace`/`--trace-ascii` output parity depends. The full
    //! `tool_debug_cb` state machine (sink resolution, `GlobalConfig`, FFI getinfo) is exercised
    //! separately through the CLI integration harness.
    use super::*;

    #[test]
    fn log_line_start_bare_marker_when_no_columns() {
        // No time/id columns: just the "> " header-out marker (curl fputs(s_infotype[type])).
        let mut out = Vec::new();
        log_line_start(&mut out, "", "", curl_infotype::CURLINFO_HEADER_OUT);
        assert_eq!(out, b"> ");
    }

    #[test]
    fn log_line_start_prefixes_time_and_ids() {
        // With columns present: "<time><ids><marker>" (curl "%s%s%s"). "< " is header-in.
        let mut out = Vec::new();
        log_line_start(
            &mut out,
            "12:00:00.000000 ",
            "[1-0] ",
            curl_infotype::CURLINFO_HEADER_IN,
        );
        assert_eq!(out, b"12:00:00.000000 [1-0] < ");
    }

    #[test]
    fn log_line_start_marker_table_matches_curl() {
        // Verbatim check of every s_infotype[] entry.
        let cases = [
            (curl_infotype::CURLINFO_TEXT, "* "),
            (curl_infotype::CURLINFO_HEADER_IN, "< "),
            (curl_infotype::CURLINFO_HEADER_OUT, "> "),
            (curl_infotype::CURLINFO_DATA_IN, "{ "),
            (curl_infotype::CURLINFO_DATA_OUT, "} "),
            (curl_infotype::CURLINFO_SSL_DATA_IN, "{ "),
            (curl_infotype::CURLINFO_SSL_DATA_OUT, "} "),
        ];
        for (info, marker) in cases {
            let mut out = Vec::new();
            log_line_start(&mut out, "", "", info);
            assert_eq!(out, marker.as_bytes());
        }
    }

    #[test]
    fn dump_bin_short_row_pads_hex_column() {
        // Full (hex+ascii) dump of two bytes: one hex pair each, then 14 three-space pads, then
        // the ascii "Hi", then the row newline.
        let mut out = Vec::new();
        dump(&mut out, "", "", "X", b"Hi", TraceType::Bin);

        let mut expected = Vec::new();
        expected.extend_from_slice(b"X, 2 bytes (0x2)\n");
        expected.extend_from_slice(b"0000: ");
        expected.extend_from_slice(b"48 69 ");
        for _ in 0..14 {
            expected.extend_from_slice(b"   ");
        }
        expected.extend_from_slice(b"Hi\n");
        assert_eq!(out, expected);
    }

    #[test]
    fn dump_bin_wraps_rows_every_sixteen_bytes() {
        // 17 bytes → a full first row (offset 0000) and a one-byte second row (offset 0010).
        let data = b"0123456789abcdef!";
        let mut out = Vec::new();
        dump(&mut out, "", "", "W", data, TraceType::Bin);

        let mut expected = Vec::new();
        expected.extend_from_slice(b"W, 17 bytes (0x11)\n");
        expected.extend_from_slice(
            b"0000: 30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66 0123456789abcdef\n",
        );
        expected.extend_from_slice(b"0010: 21 ");
        for _ in 0..15 {
            expected.extend_from_slice(b"   ");
        }
        expected.extend_from_slice(b"!\n");
        assert_eq!(out, expected);
    }

    #[test]
    fn dump_ascii_splits_on_crlf() {
        // ASCII-only dump splits protocol lines on CR-LF; the CR-LF bytes are consumed and the
        // offset column advances accordingly (0000 then 0004).
        let mut out = Vec::new();
        dump(&mut out, "", "", "Y", b"AB\r\nCD", TraceType::Ascii);
        assert_eq!(out, b"Y, 6 bytes (0x6)\n0000: AB\n0004: CD\n".to_vec());
    }

    #[test]
    fn dump_ascii_substitutes_unprintable_byte() {
        // Bytes outside 0x20..0x7F render as '.' (UNPRINTABLE_CHAR).
        let mut out = Vec::new();
        dump(&mut out, "", "", "Z", b"a\x01b", TraceType::Ascii);
        assert_eq!(out, b"Z, 3 bytes (0x3)\n0000: a.b\n".to_vec());
    }

    #[test]
    fn dump_prepends_time_and_id_columns_to_header() {
        // The header line carries the time/id columns ahead of the descriptive text.
        let mut out = Vec::new();
        dump(
            &mut out,
            "09:00:00.000000 ",
            "[2-1] ",
            "=> Send header",
            b"Hi",
            TraceType::Ascii,
        );
        assert_eq!(
            out,
            b"09:00:00.000000 [2-1] => Send header, 2 bytes (0x2)\n0000: Hi\n".to_vec()
        );
    }
}
