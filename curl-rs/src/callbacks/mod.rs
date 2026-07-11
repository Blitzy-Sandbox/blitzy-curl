// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

//! libcurl-parity CLI callback support for curl-rs easy/multi handles. Rust rewrite of
//! curl 8.19.0-DEV `src/tool_cb_*.c`.
//!
//! This module owns the shared per-transfer output context [`OutStruct`] — a port of curl's
//! `struct OutStruct` from `src/tool_sdecls.h` — together with the two safe boundary
//! primitives (`userdata_mut` and `callback_slice`) that a callback uses to cross the C ABI.
//!
//! The `OutStruct` model mirrors curl's data structure field-for-field, minus the
//! Windows-only console `utf8seq` staging buffer (the supported targets are the Linux and
//! macOS tuples only, per AAP §0.2.2 / §0.6.5). Its C `char *filename` / `FILE *stream`
//! pair — hand-managed in curl — is expressed here through Rust ownership: an
//! `Option<String>` filename and an [`OutSink`] enum that unifies a buffered regular file
//! with the standard streams and the discard ("/dev/null") sink.

// Callback submodules — language rewrites of curl's `src/tool_cb_*.c`, each installing one
// libcurl transfer callback. Declared here as they land; the operation layer wires the live
// function pointers onto the easy handle. `seek` ports `src/tool_cb_see.c`
// (`CURLOPT_SEEKFUNCTION`).
pub mod seek;

use core::ffi::c_void;
use std::fs::File;
use std::io::{self, BufWriter, Write};

/// `CURLOPT_DEBUGFUNCTION` — `-v`/`--trace`/`--trace-ascii`/`--trace-time` diagnostic dump
/// (Rust rewrite of `src/tool_cb_dbg.c`).
pub mod debug;

/// Body-write callback plus output-file and directory-hierarchy helpers — the
/// `CURLOPT_WRITEFUNCTION` path (curl's `src/tool_cb_wrt.c`, absorbing `src/tool_dirhie.c`
/// and `src/tool_dirhie.h`).
pub mod write;

/// Single-transfer `-#`/`--progress-bar` renderer (curl's `src/tool_cb_prg.c`). Owns the
/// `CURLOPT_XFERINFOFUNCTION` callback and [`ProgressData`] state for a serial `-#` transfer;
/// the parallel aggregate meter is the separate [`crate::progress_display`] module.
pub mod progress;

// Re-export the single-transfer progress-bar surface at the `callbacks` root, so the
// operation-dispatch and option-application layers refer to `callbacks::ProgressData` /
// `callbacks::CURL_PROGRESS_*` without reaching into the submodule (mirrors how curl's
// `tool_cb_prg.h` publishes these). The bar path is not yet wired into `operate.rs`, so these
// names have no in-crate consumer at this stage — same not-yet-wired status the boundary
// helpers below carry — hence the targeted `unused_imports` relaxation on the re-export.
#[allow(unused_imports)]
pub use progress::{ProgressData, CURL_PROGRESS_BAR, CURL_PROGRESS_STATS};
// Callback submodules — language rewrites of curl's `src/tool_cb_*.c` (and the socket-option
// handler lifted from `src/config2setopts.c`), wired in as they are added. `socket` implements
// the `CURLOPT_OPENSOCKETFUNCTION` (Linux MPTCP) and `CURLOPT_SOCKOPTFUNCTION`
// (`--ip-tos` / `--vlan-priority`) callbacks and is the only submodule that reaches OS socket
// primitives directly (its `unsafe` is the narrow OS-integration exception of AAP §0.6.2).
/// `CURLOPT_READFUNCTION` upload-source read + `CURLOPT_XFERINFOFUNCTION` busy-read unpauser
/// (Rust rewrite of curl's `src/tool_cb_rea.c`).
pub mod read;
pub mod socket;

/// `CURLOPT_HEADERFUNCTION` — `-D`/`--dump-header`, `--etag-save`, `-O` from
/// `Content-Disposition`, `--write-out` header counting, and bold/OSC 8 header display
/// (Rust rewrite of curl's `src/tool_cb_hdr.c`).
pub mod header;

// Re-export the header-callback per-transfer state at the `callbacks` root, mirroring how
// curl's `tool_cb_hdr.h` publishes `struct HdrCbData`. It is embedded in `PerTransfer`
// (`operate.rs`); the header callback is not yet wired into the transfer engine, but the type
// is consumed by `operate.rs` so no `unused_imports` relaxation is required here.
pub use header::HdrCbData;

/// Output destination for a transfer.
///
/// This replaces curl's raw `FILE *stream` member of `struct OutStruct`. Modelling the sink
/// as an enum lets a regular file and the process standard streams be represented uniformly
/// while keeping ownership of an opened file inside the value itself (so it is closed on drop,
/// removing curl's manual `fclose` bookkeeping).
#[derive(Debug, Default)]
pub enum OutSink {
    /// No stream opened yet.
    #[default]
    None,
    /// Buffered write to a regular file (the `fopen` `"wb"` equivalent).
    File(BufWriter<File>),
    /// Standard output.
    Stdout,
    /// Discard (matches `out_null` / redirect to the bit-bucket).
    ///
    /// Constructed by the write-callback submodule (`callbacks/write.rs`, curl's
    /// `tool_cb_wrt.c`) when a transfer's output is routed to the bit-bucket. The
    /// operation-dispatch layer (`operate.rs`) instead tracks discards via the
    /// [`OutStruct::out_null`] flag (curl's `outs->out_null`), so it never constructs this
    /// variant — hence `allow(dead_code)` until the write-callback submodule lands.
    #[allow(dead_code)]
    Null,
}

impl OutSink {
    /// Returns `true` when a stream is present, i.e. any variant other than
    /// [`OutSink::None`]. Mirrors curl testing `outs->stream` for non-`NULL`.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !matches!(self, OutSink::None)
    }

    /// Writes the whole of `buf` to the active sink and returns the number of bytes
    /// consumed.
    ///
    /// The [`OutSink::Null`] sink discards the data but still reports the full length, exactly
    /// as curl's `out_null` path returns the byte count without writing — libcurl treats a
    /// short count as an error, so a discard must claim all bytes. Writing to
    /// [`OutSink::None`] is a misuse (no stream has been opened) and yields an error rather
    /// than silently succeeding.
    ///
    /// Called by the write-callback submodule (`callbacks/write.rs`, curl's `tool_cb_wrt.c`),
    /// which owns the body-streaming path; the operation-dispatch layer only opens and closes
    /// sinks, so `allow(dead_code)` holds until that submodule lands.
    #[allow(dead_code)]
    pub fn write_all(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            OutSink::File(file) => {
                file.write_all(buf)?;
                Ok(buf.len())
            }
            OutSink::Stdout => {
                io::stdout().write_all(buf)?;
                Ok(buf.len())
            }
            // Discard sink: count the bytes as consumed but write nothing.
            OutSink::Null => Ok(buf.len()),
            OutSink::None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "output stream not open",
            )),
        }
    }

    /// Flushes any buffered output to the underlying destination. A no-op for the discard and
    /// not-yet-open sinks. Mirrors curl's `fflush(outs->stream)`.
    pub fn flush(&mut self) -> io::Result<()> {
        match self {
            OutSink::File(file) => file.flush(),
            OutSink::Stdout => io::stdout().flush(),
            OutSink::None | OutSink::Null => Ok(()),
        }
    }
}

/// Per-transfer output-writing context.
///
/// A field-for-field port of curl's `struct OutStruct` (`src/tool_sdecls.h`), tracking where a
/// single transfer's body (or its response headers, when used for `heads`/`etag_save`) is
/// written and how much has been written so far. Instances are embedded in `PerTransfer`
/// (owned by `operate.rs`); the callback submodules read and update these fields.
#[derive(Debug, Default)]
pub struct OutStruct {
    /// Output filename, or `None` for a standard stream (curl's `NULL` filename).
    pub filename: Option<String>,
    /// The active output destination (a buffered file or a standard stream).
    pub stream: OutSink,
    /// Amount written so far.
    pub bytes: i64,
    /// Original file size, or the offset at which truncation takes place. Zero unless
    /// appending to a non-empty regular file.
    pub init: i64,
    /// `true` when `filename` was dynamically allocated and belongs to this struct. Retained
    /// from curl's `alloc_filename` bit so header-callback logic can distinguish a
    /// server-supplied name from a statically configured one.
    pub alloc_filename: bool,
    /// `true` when `filename` was set from a server-specified Content-Disposition or Location
    /// header.
    pub is_cd_filename: bool,
    /// `true` when output goes to a regular file, which also implies the stream is seekable
    /// and appendable. `false` for any standard stream.
    pub regular_file: bool,
    /// `true` when the output file was opened by us (`fopen`'ed) and therefore must be closed
    /// later.
    pub fopened: bool,
    /// `true` when output is discarded (the `/dev/null` bit-bucket): writes are counted but
    /// not stored.
    pub out_null: bool,
}

/// Reconstitutes a `&mut T` from a libcurl userdata pointer.
///
/// # Safety
/// `ptr` must be a valid, non-null, properly-aligned pointer to a live `T` that libcurl was
/// handed via `CURLOPT_*DATA` and that outlives this borrow; no other alias exists for the
/// duration (single-threaded CLI runtime).
///
/// Used by the callback submodules (`callbacks/{write,read,header,progress,seek,socket,debug}.rs`,
/// curl's `tool_cb_*.c`) to cross the C ABI; the operation-dispatch layer registers callbacks but
/// does not implement their bodies, so `allow(dead_code)` holds until those submodules land.
#[allow(dead_code)]
pub(crate) unsafe fn userdata_mut<'a, T>(ptr: *mut c_void) -> Option<&'a mut T> {
    // SAFETY: caller guarantees ptr is a valid, uniquely-borrowed *mut T for 'a.
    unsafe { (ptr as *mut T).as_mut() }
}

/// Views a libcurl callback buffer as a byte slice of `size * nitems` bytes.
///
/// # Safety
/// `buffer` must point to at least `size * nitems` initialized bytes for `'a`.
///
/// Used by the callback submodules (`callbacks/{write,read,header,progress,seek,socket,debug}.rs`,
/// curl's `tool_cb_*.c`) to view libcurl's callback buffer; the operation-dispatch layer does not
/// implement callback bodies, so `allow(dead_code)` holds until those submodules land.
#[allow(dead_code)]
pub(crate) unsafe fn callback_slice<'a>(buffer: *const u8, size: usize, nitems: usize) -> &'a [u8] {
    let len = size.saturating_mul(nitems);
    if buffer.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: caller guarantees buffer covers len initialized bytes.
    unsafe { core::slice::from_raw_parts(buffer, len) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn outsink_default_is_none_and_not_open() {
        let s = OutSink::default();
        assert!(matches!(s, OutSink::None));
        assert!(!s.is_open(), "the default (unopened) sink must not be open");
    }

    #[test]
    fn outsink_null_counts_bytes_but_writes_nothing() {
        // The discard sink reports the full length so libcurl never sees a short write,
        // yet stores nothing (curl's `out_null` path).
        let mut s = OutSink::Null;
        assert!(s.is_open(), "Null is an open sink");
        assert_eq!(s.write_all(b"abcdef").unwrap(), 6);
        assert_eq!(s.write_all(&[]).unwrap(), 0);
        s.flush().unwrap();
    }

    #[test]
    fn outsink_none_write_is_notconnected_error() {
        let mut s = OutSink::None;
        let err = s.write_all(b"x").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
        // flush on an unopened sink is a no-op success.
        s.flush().unwrap();
    }

    #[test]
    fn outsink_file_writes_through_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("body.out");
        let f = File::create(&path).unwrap();
        let mut s = OutSink::File(BufWriter::new(f));
        assert!(s.is_open());
        assert_eq!(s.write_all(b"hello world").unwrap(), 11);
        s.flush().unwrap();
        drop(s); // close the BufWriter/File so the bytes are durable

        let mut got = String::new();
        File::open(&path).unwrap().read_to_string(&mut got).unwrap();
        assert_eq!(got, "hello world");
    }

    #[test]
    fn outsink_stdout_is_open_and_flushes() {
        // Exercise the Stdout arm without emitting visible noise (empty write).
        let mut s = OutSink::Stdout;
        assert!(s.is_open());
        assert_eq!(s.write_all(&[]).unwrap(), 0);
        s.flush().unwrap();
    }

    #[test]
    fn outstruct_default_is_empty_stream_none() {
        let o = OutStruct::default();
        assert!(o.filename.is_none());
        assert!(!o.stream.is_open());
        assert_eq!(o.bytes, 0);
        assert_eq!(o.init, 0);
        assert!(!o.alloc_filename);
        assert!(!o.is_cd_filename);
        assert!(!o.regular_file);
        assert!(!o.fopened);
        assert!(!o.out_null);
    }

    #[test]
    fn callback_slice_handles_null_zero_and_valid() {
        // null buffer -> empty slice regardless of the claimed length.
        // SAFETY: a null pointer with any size must yield the empty-slice fast path.
        let empty = unsafe { callback_slice(std::ptr::null(), 4, 8) };
        assert!(empty.is_empty());

        let data = [1u8, 2, 3, 4, 5, 6];
        // zero element count -> empty slice even with a valid pointer.
        // SAFETY: len == 0 takes the empty-slice fast path; the pointer is not dereferenced.
        let zero = unsafe { callback_slice(data.as_ptr(), 0, 3) };
        assert!(zero.is_empty());

        // size * nitems == 6 -> the whole backing array is viewed.
        // SAFETY: `data` owns 6 initialized bytes and outlives the borrow.
        let full = unsafe { callback_slice(data.as_ptr(), 2, 3) };
        assert_eq!(full, &data[..]);
    }

    #[test]
    fn userdata_mut_round_trips_and_rejects_null() {
        let mut value: u64 = 40;
        let ptr = std::ptr::addr_of_mut!(value).cast::<c_void>();
        // SAFETY: `ptr` is the live, uniquely-borrowed `*mut u64` of `value`.
        let borrowed = unsafe { userdata_mut::<u64>(ptr) }.expect("non-null must reconstitute");
        *borrowed += 2;
        assert_eq!(
            value, 42,
            "mutation through the reconstituted &mut must be visible"
        );

        // SAFETY: a null userdata pointer must yield None, never a dangling reference.
        let none = unsafe { userdata_mut::<u64>(std::ptr::null_mut()) };
        assert!(none.is_none());
    }
}
