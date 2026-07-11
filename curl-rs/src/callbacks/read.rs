// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

//! CURLOPT_READFUNCTION upload-source read + CURLOPT_XFERINFOFUNCTION busy-read unpauser.
//! Rust rewrite of curl 8.19.0-DEV `src/tool_cb_rea.c`.
//!
//! Two libcurl callbacks live here, both crossing the C ABI exactly as their curl
//! counterparts do:
//!
//! * [`tool_read_cb`] — the `CURLOPT_READFUNCTION` handler (matches the
//!   `curl_read_callback` typedef). It pulls upload-body bytes from the transfer's input
//!   descriptor, honours the `--max-time` wait, pauses the transfer on a non-blocking
//!   `EAGAIN`, and refuses to deliver more than the size declared at start.
//! * [`tool_readbusy_cb`] — the `CURLOPT_XFERINFOFUNCTION` handler installed on the
//!   *non-progress-bar* path (matches the `curl_xferinfo_callback` typedef). It un-pauses a
//!   transfer that a previous [`tool_read_cb`] paused because its input was momentarily dry.
//!
//! Both callbacks receive a [`crate::operate::PerTransfer`] pointer through libcurl's
//! opaque userdata slot (`CURLOPT_READDATA` / `CURLOPT_XFERINFODATA`), reconstituted with
//! the shared [`crate::callbacks::userdata_mut`] boundary primitive.
//!
//! # Platform scope
//! curl's `waitfd` selects `poll()` when `HAVE_POLL` is set and falls back to `select()`
//! otherwise, with a separate `#ifdef _WIN32` recv() path. All four supported targets
//! (`{x86_64,aarch64}-unknown-linux-gnu` and `{x86_64,aarch64}-apple-darwin`) have `poll`,
//! and Windows is out of scope (AAP §0.2.2 / §0.6.5), so only the `poll` branch is ported.
//!
//! # Wiring status
//! These callbacks are registered on an easy handle by the transfer-dispatch layer
//! (`operate.rs`, curl's `single_transfer`) once the `curl-rs-lib` transfer engine drives
//! uploads. Until that engine is wired, nothing in the CLI binary calls them, so — exactly
//! as [`crate::callbacks::userdata_mut`] and its siblings are marked in `callbacks/mod.rs`
//! — the items in this module carry `#[allow(dead_code)]`. This is an integration boundary,
//! not a stub: every code path is fully implemented.

use core::cell::Cell;
use core::ffi::{c_char, c_int, c_void};
use std::os::fd::RawFd;

use curl_rs_ffi::easy::{curl_easy_pause, CURLPAUSE_CONT, CURL_READFUNC_PAUSE};

use crate::callbacks::userdata_mut;
use crate::operate::{warnf, PerTransfer};

/// `CURL_PROGRESSFUNC_CONTINUE` — the progress/xferinfo-callback return value that tells
/// libcurl to keep driving its own built-in progress meter while the callback signals
/// "continue" (`include/curl/curl.h`). It is not (yet) re-exported by `curl-rs-ffi`, so it
/// is defined here with the exact `curl.h` value (`0x10000001`), per the file plan's
/// constant-fallback guidance. Numerically identical to [`CURL_READFUNC_PAUSE`], but kept
/// separate because the two constants belong to different callback contracts.
#[allow(dead_code)]
const CURL_PROGRESSFUNC_CONTINUE: c_int = 0x1000_0001;

/// Wait up to `waitms` milliseconds for read activity on a (possibly non-socket) `fd`.
///
/// Faithful port of curl's `waitfd` (`src/tool_cb_rea.c`), `HAVE_POLL` branch only. curl
/// deliberately uses `poll` here because the descriptor can be a plain file/pipe rather than
/// a socket, which `select` on Windows cannot handle — but on the supported Unix targets
/// `poll` is always available, so the `select` fallback and the `#ifdef _WIN32` path are
/// dropped.
///
/// The boolean result is advisory and mirrors curl's `if(poll(...)) return TRUE;`: `true`
/// when `poll` reports a non-zero result (readiness *or* error), `false` on a `0` timeout.
/// Callers use it only to bound how long the read blocks, so an error is treated the same as
/// readiness (proceed to attempt the read), exactly as in curl.
#[allow(dead_code)]
fn waitfd(waitms: i32, fd: RawFd) -> bool {
    let mut set = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `poll` reads/writes only the single `pollfd` we own by mutable reference for
    // the duration of the call (`nfds == 1`); it touches no other user memory.
    let r = unsafe { libc::poll(&mut set as *mut libc::pollfd, 1, waitms) };
    // C: `if(poll(&set, 1, waitms)) return TRUE; return FALSE;`
    r != 0
}

/// `CURLOPT_READFUNCTION` callback — reads the next chunk of the upload body.
///
/// Matches the `curl_read_callback` typedef (`include/curl/curl.h`):
/// `size_t (*)(char *buffer, size_t size, size_t nitems, void *instream)`. libcurl calls it
/// with `instream` set to the `CURLOPT_READDATA` value, which the CLI configures to the
/// owning [`PerTransfer`].
///
/// Behaviour is a line-for-line port of curl's `tool_read_cb` (C lines 79-158), minus the
/// `#ifdef _WIN32` stdin-socket `recv()` branch (Windows is out of scope):
///
/// 1. Report end-of-input (`0`) once the declared upload size has been delivered.
/// 2. When `--max-time` is set, either time out (`0`) or block up to the remaining budget on
///    [`waitfd`] before reading.
/// 3. `read(2)` up to `size * nitems` bytes into `buffer`. A non-blocking `EAGAIN` pauses the
///    transfer ([`CURL_READFUNC_PAUSE`]) and records the busy state; any other error yields
///    `0` (a negative count cannot be represented in the unsigned return).
/// 4. Never deliver more than the size declared at start: clamp and warn once with curl's
///    verbatim message.
///
/// # Safety
/// `buffer` must point to `sz * nmemb` writable bytes (the libcurl `CURLOPT_READFUNCTION`
/// contract), and `userdata` must be the `*mut PerTransfer` handed to libcurl via
/// `CURLOPT_READDATA`, valid and uniquely borrowed for the duration of the call.
#[allow(dead_code)]
pub unsafe extern "C" fn tool_read_cb(
    buffer: *mut c_char,
    sz: usize,
    nmemb: usize,
    userdata: *mut c_void,
) -> usize {
    // SAFETY: the caller guarantees `userdata` is the live, uniquely-borrowed
    // `*mut PerTransfer` registered via `CURLOPT_READDATA`.
    let per = match unsafe { userdata_mut::<PerTransfer>(userdata) } {
        Some(p) => p,
        None => return 0,
    };

    // C: `if((per->uploadfilesize != -1) && (per->uploadedsofar == per->uploadfilesize))`
    // — the upload is already complete (`-1` is the "size unknown" sentinel).
    if per.uploadfilesize != -1 && per.uploadedsofar() == per.uploadfilesize {
        // done
        return 0;
    }

    // C: `if(config->timeout_ms) { ... }` — honour `--max-time` by either timing out or
    // blocking (up to the remaining budget) for read activity before attempting the read.
    if per.timeout_ms != 0 {
        // C: `long msdelta = (long)curlx_timediff_ms(curlx_now(), per->start);`
        let msdelta = per.start.elapsed().as_millis() as i64;
        if msdelta > per.timeout_ms {
            // timeout
            return 0;
        }
        // C: `long w = config->timeout_ms - msdelta; if(w > INT_MAX) w = INT_MAX;`
        let mut w = per.timeout_ms - msdelta;
        if w > i64::from(i32::MAX) {
            w = i64::from(i32::MAX);
        }
        waitfd(w as i32, per.infd());
    }

    // C: `rc = read(per->infd, buffer, sz * nmemb);`
    let want = sz.saturating_mul(nmemb);
    let fd = per.infd();
    // SAFETY: `buffer` covers `sz * nmemb` writable bytes per the libcurl
    // `CURLOPT_READFUNCTION` contract; `fd` is a valid open descriptor for the upload source
    // (or `STDIN_FILENO` for a stdin upload); `read` writes only into `buffer`, at most
    // `want` bytes.
    let rc_raw = unsafe { libc::read(fd, buffer.cast::<c_void>(), want) };
    let mut rc: i64 = if rc_raw < 0 {
        // C: `if(errno == EAGAIN) { errno = 0; config->readbusy = TRUE;
        //                          return CURL_READFUNC_PAUSE; }`
        // (`EAGAIN == EWOULDBLOCK` on every supported target.)
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN) {
            per.readbusy = true;
            return CURL_READFUNC_PAUSE;
        }
        // C: "since size_t is unsigned we cannot return negative values fine" — collapse to 0.
        0
    } else {
        rc_raw as i64
    };

    // C: `if((per->uploadfilesize != -1) &&
    //        (per->uploadedsofar + rc > per->uploadfilesize)) { ... }`
    // — never upload more than originally declared.
    if per.uploadfilesize != -1 && per.uploadedsofar() + rc > per.uploadfilesize {
        let delta = per.uploadedsofar() + rc - per.uploadfilesize;
        // Message preserved verbatim from curl (the two C string literals concatenate to
        // this exact text); `delta` is a `curl_off_t` (i64).
        warnf(
            per.diag,
            &format!(
                "File size larger in the end than when started. Dropping at least {delta} bytes"
            ),
        );
        rc = per.uploadfilesize - per.uploadedsofar();
    }
    // C: `config->readbusy = FALSE;`
    per.readbusy = false;

    // C: `return (size_t)rc;`
    rc as usize
}

// curl keeps the previous upload-progress reading in a function-local `static curl_off_t
// ulprev`. The CLI runs the easy interface on a single (current-thread) runtime, so a
// `thread_local` preserves that static's single-threaded semantics without a global `mut`.
thread_local! {
    static ULPREV: Cell<i64> = const { Cell::new(0) };
}

/// `CURLOPT_XFERINFOFUNCTION` callback used to un-pause busy reads (non-progress-bar path).
///
/// Matches the `curl_xferinfo_callback` typedef (`include/curl/curl.h`):
/// `int (*)(void *clientp, curl_off_t dltotal, dlnow, ultotal, ulnow)`. libcurl calls it with
/// `clientp` set to the `CURLOPT_XFERINFODATA` value (the owning [`PerTransfer`]).
///
/// Line-for-line port of curl's `tool_readbusy_cb` (C lines 164-193): when a previous
/// [`tool_read_cb`] paused the transfer on `EAGAIN`, and upload progress has not advanced
/// since the last tick (`ulprev == ulnow`), briefly wait on the input descriptor, then clear
/// the busy state and resume the transfer via `curl_easy_pause(CURLPAUSE_CONT)`. The
/// `dltotal`/`dlnow`/`ultotal` arguments are unused (curl casts them to `void`).
///
/// Returns `0` when the transfer's progress meter is suppressed (`--no-progress-meter`),
/// otherwise [`CURL_PROGRESSFUNC_CONTINUE`] to let libcurl keep drawing its built-in meter.
///
/// # Safety
/// `clientp` must be the `*mut PerTransfer` handed to libcurl via `CURLOPT_XFERINFODATA`,
/// valid and uniquely borrowed for the duration of the call.
#[allow(dead_code)]
pub unsafe extern "C" fn tool_readbusy_cb(
    clientp: *mut c_void,
    _dltotal: i64,
    _dlnow: i64,
    _ultotal: i64,
    ulnow: i64,
) -> c_int {
    // SAFETY: the caller guarantees `clientp` is the live, uniquely-borrowed
    // `*mut PerTransfer` registered via `CURLOPT_XFERINFODATA`.
    let per = match unsafe { userdata_mut::<PerTransfer>(clientp) } {
        Some(p) => p,
        None => return 0,
    };

    // C: `if(config->readbusy) { ... }`
    if per.readbusy {
        // C: `if(ulprev == ulnow) waitfd(1, per->infd);` — sleep ~1ms worth of read-wait
        // while the upload has made no progress since the last callback.
        if ULPREV.with(Cell::get) == ulnow {
            waitfd(1, per.infd());
        }

        // C: `config->readbusy = FALSE; curl_easy_pause(per->curl, CURLPAUSE_CONT);`
        per.readbusy = false;
        // curl passes `per->curl` (the opaque `CURL*`) to `curl_easy_pause`. In this port the
        // `CURL*` is a `*mut Easy` (that is exactly what `curl-rs-ffi` boxes and hands back
        // from `curl_easy_init` and interprets in `curl_easy_pause`), so this transfer's own
        // `Easy` is that handle.
        let handle = std::ptr::addr_of_mut!(per.easy).cast::<c_void>();
        // SAFETY: `handle` is a non-null pointer to this transfer's live `Easy`, valid for the
        // duration of the call; `curl_easy_pause` only borrows it (through a null-checked
        // `as_ref`) to clear the transfer's pause bits and never frees or takes ownership.
        let _ = unsafe { curl_easy_pause(handle, CURLPAUSE_CONT) };
    }

    // C: `ulprev = ulnow;`
    ULPREV.with(|u| u.set(ulnow));

    // C: `return per->noprogress ? 0 : CURL_PROGRESSFUNC_CONTINUE;`
    if per.noprogress {
        0
    } else {
        CURL_PROGRESSFUNC_CONTINUE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waitfd_reports_readiness_on_a_real_pipe() {
        // A pipe is a non-socket descriptor — exactly the case curl uses `poll` for.
        let mut fds = [0 as RawFd; 2];
        // SAFETY: `pipe` writes two fds into the 2-element array we own.
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "pipe() must succeed");
        let (rd, wr) = (fds[0], fds[1]);

        // Empty pipe with a 0ms budget -> poll times out (0) -> not ready.
        assert!(!waitfd(0, rd), "an empty pipe must not report readiness");

        // Make the read end readable, then poll must report it ready.
        // SAFETY: `wr` is a valid open descriptor; we write exactly one byte from a valid ptr.
        let n = unsafe { libc::write(wr, b"x".as_ptr().cast::<c_void>(), 1) };
        assert_eq!(n, 1);
        assert!(
            waitfd(0, rd),
            "a pipe with pending data must report readiness"
        );

        // SAFETY: both descriptors are valid and owned by this test; close once each.
        unsafe {
            libc::close(rd);
            libc::close(wr);
        }
    }
}
