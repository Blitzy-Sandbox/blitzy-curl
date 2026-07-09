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

use core::ffi::c_void;
use std::fs::File;
use std::io::{self, BufWriter, Write};

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
