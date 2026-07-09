// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

//! `CURLOPT_SEEKFUNCTION` callback — repositions the upload source on redirect/resume.
//! Rust rewrite of curl 8.19.0-DEV `src/tool_cb_see.c`.
//!
//! libcurl invokes this callback when it must rewind or fast-forward the data it is
//! uploading — for example to replay a request body after an HTTP redirect or an
//! authentication round-trip, or to resume an interrupted upload. The callback repositions
//! the transfer's upload descriptor and reports only a `CURL_SEEKFUNC_*` status; it never
//! returns the resulting offset (libcurl reads the offset back through other means).
//!
//! curl keeps the upload source as a raw descriptor `per->infd` and seeks it with
//! `curl_lseek` (a thin [`lseek(2)`] wrapper). The Rust port instead owns the upload source
//! as [`PerTransfer::infile`](crate::operate::PerTransfer) — an `Option<File>` closed by
//! RAII — so this callback borrows that descriptor through [`AsRawFd`] and performs the
//! identical `lseek` syscall. Because the seek happens at the kernel-descriptor level with
//! the `whence` value forwarded verbatim, the observable behavior is byte-for-byte that of
//! curl 8.x.
//!
//! The 32-bit `off_t` large-seek workaround from the C source (guarded by
//! `#if (SIZEOF_CURL_OFF_T > SIZEOF_OFF_T) && !defined(_WIN32)`) is intentionally omitted:
//! on every supported target (`{x86_64,aarch64}-unknown-linux-gnu` and
//! `{x86_64,aarch64}-apple-darwin`) `curl_off_t` and `off_t` are both 64-bit, so that branch
//! compiles out and the fallback chunked-rewind loop is unreachable (AAP §0.2.2).
//!
//! [`lseek(2)`]: https://man7.org/linux/man-pages/man2/lseek.2.html

use core::ffi::{c_int, c_void};
use std::os::fd::AsRawFd;

use curl_rs_ffi::easy::{CURL_SEEKFUNC_CANTSEEK, CURL_SEEKFUNC_OK};

use crate::callbacks::userdata_mut;
use crate::operate::PerTransfer;

/// `CURLOPT_SEEKFUNCTION` callback — reposition the upload source (curl's `tool_seek_cb`).
///
/// The operation layer installs this function pointer together with `CURLOPT_SEEKDATA`, which
/// carries the `*mut PerTransfer` for the transfer being driven. libcurl calls it when it
/// needs to seek the upload data (redirect replay, auth retry, resume). Per the libcurl
/// contract the callback returns only a `CURL_SEEKFUNC_*` code and never the resulting offset.
///
/// Behavior — identical to curl 8.19.0-DEV `src/tool_cb_see.c`:
/// * a null/invalid `userdata`, or a transfer whose upload has no seekable backing file
///   (e.g. a stdin/pipe source), cannot be repositioned and yields [`CURL_SEEKFUNC_CANTSEEK`],
///   letting libcurl fall back to other means;
/// * otherwise `lseek(fd, offset, whence)` is performed on the upload descriptor and its
///   result mapped: failure (`-1`, curl's `LSEEK_ERROR`) → [`CURL_SEEKFUNC_CANTSEEK`],
///   success → [`CURL_SEEKFUNC_OK`].
///
/// `whence` is forwarded unchanged: libc's `SEEK_SET`/`SEEK_CUR`/`SEEK_END` are exactly the
/// `0`/`1`/`2` values libcurl supplies, so no translation is performed.
///
/// # Safety
/// `userdata` must be the `*mut PerTransfer` that libcurl was handed via `CURLOPT_SEEKDATA`
/// (or null); when non-null it must point to a live [`PerTransfer`] that outlives this call
/// and is not aliased elsewhere for its duration (guaranteed by curl's single-threaded CLI
/// transfer model).
// Installed as a C function pointer by the operation layer once callback registration lands;
// like the shared `callbacks` helpers in `mod.rs` it has no Rust call site before then, so it
// carries `allow(dead_code)` to keep the strict `-D warnings` lint gate green in the interim.
#[allow(dead_code)]
pub unsafe extern "C" fn tool_seek_cb(userdata: *mut c_void, offset: i64, whence: c_int) -> c_int {
    // Recover the per-transfer context from the userdata pointer. A null or otherwise
    // unusable pointer cannot identify an upload to seek, so report CANTSEEK.
    // SAFETY: by the `CURLOPT_SEEKDATA` contract documented above, `userdata` is either null
    // or the unique `*mut PerTransfer` for this transfer, valid for the duration of the call;
    // `userdata_mut` returns `None` for a null pointer rather than dereferencing it.
    let per = match unsafe { userdata_mut::<PerTransfer>(userdata) } {
        Some(per) => per,
        None => return CURL_SEEKFUNC_CANTSEEK,
    };

    // Borrow the upload source's descriptor (curl's `per->infd`). It is absent when the upload
    // is not backed by an opened file (a stdin/pipe source); such a source is not seekable, so
    // report CANTSEEK exactly as an `lseek` on such a descriptor would have failed in curl.
    let fd = match per.infile.as_ref() {
        Some(file) => file.as_raw_fd(),
        None => return CURL_SEEKFUNC_CANTSEEK,
    };

    // Reposition the kernel file offset. `whence` is forwarded verbatim (see the item docs).
    // SAFETY: `fd` is owned by `per.infile` and stays open for the duration of this call;
    // `lseek` only moves the descriptor's file offset and dereferences no user-supplied memory.
    let rc = unsafe { libc::lseek(fd, offset, whence) };
    if rc == -1 {
        // curl's `LSEEK_ERROR` is `(curl_off_t)-1`, and `lseek` yields `-1` on failure. The
        // errno is deliberately ignored (as curl does): libcurl only needs to learn that the
        // seek did not happen so it may try other means.
        return CURL_SEEKFUNC_CANTSEEK;
    }

    CURL_SEEKFUNC_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// curl forwards libc's `SEEK_*` values straight through as `whence`; guard the mapping
    /// the callback relies on (`SEEK_SET` = 0, `SEEK_CUR` = 1, `SEEK_END` = 2).
    #[test]
    fn seek_whence_values_match_libcurl() {
        assert_eq!(libc::SEEK_SET, 0);
        assert_eq!(libc::SEEK_CUR, 1);
        assert_eq!(libc::SEEK_END, 2);
    }

    /// Guard the FFI return codes against ABI drift (`curl.h`: `OK` = 0, `CANTSEEK` = 2).
    #[test]
    fn seekfunc_return_codes_are_stable() {
        assert_eq!(CURL_SEEKFUNC_OK, 0);
        assert_eq!(CURL_SEEKFUNC_CANTSEEK, 2);
    }

    /// A null `userdata` cannot identify an upload to seek, so the callback must report
    /// `CANTSEEK` (never `OK`, never a panic or dereference).
    #[test]
    fn null_userdata_reports_cantseek() {
        // SAFETY: the callback tolerates a null userdata by design (curl's SEEKDATA may be
        // unset); the null path returns before any dereference occurs.
        let rc = unsafe { tool_seek_cb(core::ptr::null_mut(), 0, libc::SEEK_SET) };
        assert_eq!(rc, CURL_SEEKFUNC_CANTSEEK);
    }

    /// The descriptor-level behavior the callback maps: a real file seeks successfully for
    /// every `whence`, while an invalid descriptor fails — mirroring `OK` vs `CANTSEEK`.
    #[test]
    fn lseek_maps_success_and_failure() {
        let mut file = tempfile::tempfile().expect("create temp file");
        file.write_all(b"0123456789").expect("write temp file");
        let fd = file.as_raw_fd();

        // Valid seeks around the 10-byte file never yield LSEEK_ERROR (-1), so the callback
        // would map each to CURL_SEEKFUNC_OK.
        for (offset, whence) in [
            (0_i64, libc::SEEK_SET),
            (4, libc::SEEK_SET),
            (0, libc::SEEK_CUR),
            (0, libc::SEEK_END),
        ] {
            // SAFETY: `fd` is the live descriptor of `file`, open for the whole loop; `lseek`
            // performs no memory access.
            let rc = unsafe { libc::lseek(fd, offset, whence) };
            assert_ne!(rc, -1, "lseek(fd, {offset}, {whence}) unexpectedly failed");
        }

        // An invalid descriptor yields -1 (curl's LSEEK_ERROR), which the callback maps to
        // CURL_SEEKFUNC_CANTSEEK.
        // SAFETY: `lseek` merely reports EBADF for a bad descriptor; it performs no memory
        // access.
        let rc = unsafe { libc::lseek(-1, 0, libc::SEEK_SET) };
        assert_eq!(rc, -1);
    }
}
