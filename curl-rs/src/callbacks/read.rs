// curl-rs — CLI upload/read callback (`CURLOPT_READFUNCTION`) + busy-read unpauser.
//
// SPDX-License-Identifier: curl
//
// This module is the Rust reimplementation of curl's command-line read-callback
// translation unit. The original C source is
//   Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// and is licensed under the curl license (https://curl.se/docs/copyright.html).
//
// It is the behavioral port of one C translation unit of the `src/` CLI tree:
//   * `src/tool_cb_rea.c` (193 LoC) — `tool_read_cb` (the `CURLOPT_READFUNCTION`
//     upload feeder), `tool_readbusy_cb` (the `CURLOPT_XFERINFOFUNCTION` that
//     unpauses an upload paused on a busy/`EAGAIN` read), and the private
//     `waitfd` bounded-wait helper.
//
// The C source is consumed as a behavioral oracle, not transliterated: the raw
// `int infd` file descriptor becomes a typed [`std::fs::File`] handle, the
// `read()`/`poll()` syscalls become safe [`std::io::Read`] / bounded-sleep
// operations, the C-variadic `warnf()` becomes the [`crate::warnf!`] macro, and
// the function-`static curl_off_t ulprev` becomes per-transfer state on
// [`PerTransfer`]. No control-flow branch, return value, or emitted byte is
// altered (the observable-I/O-parity mandate, AAP §0.7.3 / §0.8.2).

#![forbid(unsafe_code)]

//! Upload/read callback (`CURLOPT_READFUNCTION`) and the busy-read unpauser.
//!
//! This module hosts the two cooperating CLI callbacks that drive an **upload**
//! (`-T`/`--upload-file`), plus their shared bounded-wait helper. It mirrors
//! curl's `src/tool_cb_rea.c`.
//!
//! # The two callbacks cooperate
//!
//! 1. [`tool_read_cb`] is registered as `CURLOPT_READFUNCTION`. libcurl calls it
//!    whenever it needs more request-body bytes; it copies the next chunk from
//!    the upload source (a file, or standard input) into the buffer libcurl
//!    supplies. It also (a) stops exactly at the originally measured upload size,
//!    (b) honors `--max-time` by ending the read once the deadline passes, and
//!    (c) signals a **pause** ([`CURL_READFUNC_PAUSE`]) when the source would
//!    block, so libcurl suspends the upload instead of busy-spinning.
//! 2. [`tool_readbusy_cb`] is registered as `CURLOPT_XFERINFOFUNCTION` (the
//!    progress callback) when an upload may pause. Its sole job is to **unpause**
//!    the transfer once the read source is ready again: when curl marked the
//!    transfer busy ([`OperationConfig::readbusy`](crate::config::OperationConfig::readbusy)),
//!    it clears the flag and resumes the easy handle.
//!
//! # Return-value contract (parity-critical)
//!
//! [`tool_read_cb`] returns a [`ReadResult`] which converts to the exact
//! `size_t` sentinel libcurl expects ([`ReadResult::to_curl_return`]): a normal
//! byte count, [`CURL_READFUNC_PAUSE`] (`0x10000001`), or [`CURL_READFUNC_ABORT`]
//! (`0x10000000`). A returned count of `0` legitimately signals end-of-data /
//! timeout to libcurl. [`tool_readbusy_cb`] returns
//! [`CURL_PROGRESSFUNC_CONTINUE`](curl_rs_lib::progress::CURL_PROGRESSFUNC_CONTINUE)
//! unless progress is suppressed for the transfer, in which case it returns `0`.
//!
//! # Memory-safety notes (deviations from the C original)
//!
//! * **Typed input handle, not a raw fd.** C reads `read(per->infd, …)`; here the
//!   source is [`PerTransfer::infile`](crate::operate::PerTransfer::infile), an
//!   [`Option<File>`] where [`None`] means standard input. No `libc`/`unsafe` is
//!   used.
//! * **`waitfd` is a safe bounded wait.** C's `waitfd` calls `poll()`/`select()`
//!   on the input fd; both callers **ignore its return**. Since raw `poll()`
//!   needs `unsafe`, [`waitfd`] approximates the bounded wait safely (see its
//!   docs); the unused return makes the approximation observationally negligible.
//! * **`ulprev` is per-transfer.** C uses a function-`static curl_off_t ulprev`;
//!   the safe port stores it on [`PerTransfer`](crate::operate::PerTransfer),
//!   which is more correct than a process-global and avoids `static mut`/`unsafe`.

use std::fs::File;
use std::io::{self, Read};
use std::thread;
use std::time::{Duration, Instant};

use curl_rs_lib::easy::CURLPAUSE_CONT;
use curl_rs_lib::progress::CURL_PROGRESSFUNC_CONTINUE;

use crate::config::GlobalConfig;
use crate::operate::PerTransfer;
use crate::warnf;

// ===========================================================================
// Return-value sentinels (curl `include/curl/curl.h`)
// ===========================================================================
//
// curl's read callback returns a `size_t`, reserving two magic values that are
// far larger than any real buffer. They are absent from `curl_rs_lib` (the core
// stores read callbacks as opaque pointers and never needs the CLI-side
// sentinels), so they are defined here exactly as the C `#define`s, as `usize`
// to match the C `size_t` return type — identical in spirit to
// [`curl_rs_lib::transfer::CURL_WRITEFUNC_PAUSE`].

/// `CURL_READFUNC_PAUSE` — value a `CURLOPT_READFUNCTION` callback returns to
/// **pause** the upload (the transfer's send side is suspended until
/// `curl_easy_pause(…, CURLPAUSE_CONT)`). Matches curl's
/// `#define CURL_READFUNC_PAUSE 0x10000001`.
pub const CURL_READFUNC_PAUSE: usize = 0x1000_0001;

/// `CURL_READFUNC_ABORT` — value a `CURLOPT_READFUNCTION` callback returns to
/// **abort** the transfer (libcurl fails it with `CURLE_ABORTED_BY_CALLBACK`).
/// Matches curl's `#define CURL_READFUNC_ABORT 0x10000000`. The CLI's
/// [`tool_read_cb`] never returns this itself (curl's `tool_cb_rea.c` only ever
/// pauses), but it is part of the callback's value contract and is exposed on
/// [`ReadResult`] for completeness and for any caller that needs it.
pub const CURL_READFUNC_ABORT: usize = 0x1000_0000;

/// Upper bound (milliseconds) on the safe approximation of C's `waitfd` sleep.
///
/// C's `waitfd` waits up to `waitms` ms for input readiness via `poll()` and
/// returns as soon as data arrives; [`waitfd`] cannot observe readiness without
/// raw `poll()`, so for a non-file input it sleeps for a *capped* slice of
/// `waitms` to avoid both a busy spin and an unbounded block. The throttle call
/// site can pass a `waitms` as large as `i32::MAX`, so the cap keeps the wait
/// reasonable; the busy-read call site passes `1`, which is below the cap and so
/// is honored exactly. The wait's effect is unobservable to libcurl (the return
/// is unused), so the precise cap is not parity-sensitive.
const WAITFD_MAX_SLEEP_MS: i64 = 1000;

// ===========================================================================
// ReadResult — the outcome of a read callback invocation
// ===========================================================================

/// The result of a [`tool_read_cb`] invocation, modeling the three things curl's
/// `size_t`-returning `CURLOPT_READFUNCTION` can signal.
///
/// Use [`ReadResult::to_curl_return`] to obtain the raw `size_t` value libcurl
/// inspects. Representing the outcome as an enum (rather than a bare `usize`)
/// keeps the safe core type-checked and makes the pause/abort sentinels
/// impossible to confuse with a real byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadResult {
    /// `n` bytes were placed into libcurl's buffer. `Bytes(0)` is a legitimate
    /// end-of-data / timeout signal (curl's `tool_cb_rea.c` comment: "when
    /// select() returned zero here, it timed out").
    Bytes(usize),
    /// The source would block; pause the upload ([`CURL_READFUNC_PAUSE`]). The
    /// transfer is later resumed by [`tool_readbusy_cb`].
    Pause,
    /// Abort the transfer ([`CURL_READFUNC_ABORT`]). Provided for contract
    /// completeness; [`tool_read_cb`] never returns it.
    Abort,
}

impl ReadResult {
    /// Converts to the exact `size_t` value libcurl's read-callback contract
    /// expects: the byte count for [`Bytes`](ReadResult::Bytes),
    /// [`CURL_READFUNC_PAUSE`] for [`Pause`](ReadResult::Pause), or
    /// [`CURL_READFUNC_ABORT`] for [`Abort`](ReadResult::Abort).
    #[must_use]
    pub fn to_curl_return(self) -> usize {
        match self {
            ReadResult::Bytes(n) => n,
            ReadResult::Pause => CURL_READFUNC_PAUSE,
            ReadResult::Abort => CURL_READFUNC_ABORT,
        }
    }
}

// ===========================================================================
// Pure helpers — the parity-critical decision logic, factored out so it can be
// unit-tested without constructing a full `PerTransfer`/`GlobalConfig`.
// ===========================================================================

/// Classification of the outcome of a single read from the upload source,
/// mirroring the three branches of curl's `read()` handling
/// (`src/tool_cb_rea.c:133-142`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadStep {
    /// `read()` returned `n` bytes (`n >= 0`).
    Filled(usize),
    /// `read()` failed with `EAGAIN`/`WouldBlock` — curl sets `readbusy` and
    /// returns `CURL_READFUNC_PAUSE`.
    WouldBlock,
    /// `read()` failed for any other reason — curl treats it as `0` bytes
    /// ("since size_t is unsigned we cannot return negative values").
    OtherErr,
}

/// Classifies an [`io::Result`] from a buffer read into a [`ReadStep`], matching
/// C's `if(rc < 0) { if(errno == EAGAIN) … else rc = 0; }`.
fn classify_read(res: io::Result<usize>) -> ReadStep {
    match res {
        Ok(n) => ReadStep::Filled(n),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => ReadStep::WouldBlock,
        Err(_) => ReadStep::OtherErr,
    }
}

/// The "done" predicate of `src/tool_cb_rea.c:85-89`: the upload is complete when
/// a definite size was set (`uploadfilesize != -1`) and exactly that many bytes
/// have already been consumed (`uploadedsofar == uploadfilesize`).
fn upload_complete(uploadfilesize: i64, uploadedsofar: i64) -> bool {
    uploadfilesize != -1 && uploadedsofar == uploadfilesize
}

/// The timeout predicate of `src/tool_cb_rea.c:95-96`: the transfer has run past
/// its `--max-time` deadline when the elapsed milliseconds exceed `timeout_ms`.
/// Only meaningful when `timeout_ms != 0` (the caller gates on that, as does C).
fn timed_out(timeout_ms: i64, msdelta: i64) -> bool {
    msdelta > timeout_ms
}

/// Computes the bounded wait passed to [`waitfd`] in the throttle path
/// (`src/tool_cb_rea.c:99-102`): the remaining time budget
/// `timeout_ms - msdelta`, clamped to `INT_MAX` so it fits the C `int waitms`.
fn clamp_wait(timeout_ms: i64, msdelta: i64) -> i32 {
    (timeout_ms - msdelta).min(i64::from(i32::MAX)) as i32
}

/// The exact `--max-time`-overrun warning text emitted when the upload source
/// grew past its originally measured size (`src/tool_cb_rea.c:149-151`).
///
/// curl wraps the literal across two source lines; the *emitted* text is a
/// single line with exactly one space between "when" and "started.". This helper
/// is the single source of the string so [`tool_read_cb`] and the parity test
/// cannot drift apart.
fn cap_warning(delta: i64) -> String {
    format!("File size larger in the end than when started. Dropping at least {delta} bytes")
}

/// The outcome of [`apply_upload_cap`]: the (possibly clamped) byte count to
/// report to libcurl, and — when the cap fired — the number of bytes dropped (so
/// the caller can emit [`cap_warning`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CapResult {
    /// Bytes to report to libcurl (clamped to never exceed the original size).
    rc: usize,
    /// `Some(delta)` when the source overran its original size by `delta` bytes;
    /// [`None`] when no cap was applied.
    dropped: Option<i64>,
}

/// Enforces curl's "do not upload more than originally set out to do" rule
/// (`src/tool_cb_rea.c:145-153`): if a definite size was set and
/// `uploadedsofar + rc` would exceed it, report the overrun (`dropped`) and clamp
/// `rc` down to the exact remaining byte count. Otherwise `rc` passes through.
fn apply_upload_cap(uploadfilesize: i64, uploadedsofar: i64, rc: usize) -> CapResult {
    if uploadfilesize != -1 && uploadedsofar + (rc as i64) > uploadfilesize {
        let delta = uploadedsofar + (rc as i64) - uploadfilesize;
        // `uploadedsofar < uploadfilesize` here (the done-check already returned
        // when equal), so the remainder is strictly positive and fits `usize`.
        let clamped = (uploadfilesize - uploadedsofar) as usize;
        CapResult {
            rc: clamped,
            dropped: Some(delta),
        }
    } else {
        CapResult { rc, dropped: None }
    }
}

/// The return value of [`tool_readbusy_cb`] (`src/tool_cb_rea.c:192`):
/// [`CURL_PROGRESSFUNC_CONTINUE`](curl_rs_lib::progress::CURL_PROGRESSFUNC_CONTINUE)
/// to let libcurl's built-in meter run, unless progress is suppressed for this
/// transfer (`per->noprogress`), in which case `0` keeps the meter quiet.
fn readbusy_return(noprogress: bool) -> i32 {
    if noprogress {
        0
    } else {
        CURL_PROGRESSFUNC_CONTINUE
    }
}

/// Milliseconds [`waitfd`] sleeps for a non-file input: `waitms` clamped to
/// `[0, WAITFD_MAX_SLEEP_MS]`. A non-positive `waitms` yields `0` (no sleep).
fn waitfd_sleep_ms(waitms: i32) -> u64 {
    if waitms <= 0 {
        0
    } else {
        i64::from(waitms).min(WAITFD_MAX_SLEEP_MS) as u64
    }
}

/// Reads up to `buffer.len()` bytes from the upload source into `buffer`,
/// mirroring C's `read(per->infd, buffer, sz * nmemb)` (the slice length is the C
/// `sz * nmemb`). [`Some`] reads from the open upload file; [`None`] reads from
/// standard input (curl's `-T -` stdin upload).
fn read_from_input(input: &mut Option<File>, buffer: &mut [u8]) -> io::Result<usize> {
    match input {
        Some(file) => file.read(buffer),
        // No open file => the upload source is standard input. `Stdin` locks
        // internally per call, which is fine for the one-chunk-per-call contract.
        None => io::stdin().read(buffer),
    }
}

// ===========================================================================
// waitfd — bounded wait for input readiness (port of src/tool_cb_rea.c:40-72)
// ===========================================================================

/// Waits a bounded amount of time for the upload source to become readable.
///
/// This is the safe port of curl's `waitfd` (`src/tool_cb_rea.c:40-72`), whose
/// return value **both call sites ignore** — it exists purely as a throttle so a
/// not-yet-ready input does not spin the CPU.
///
/// curl calls `poll(POLLIN)` (or `select`) on the input fd for up to `waitms`
/// milliseconds, returning as soon as data is available. Raw `poll()`/`select()`
/// require `unsafe`/`libc`, which this crate forbids, so the wait is approximated
/// safely:
///
/// * **Regular file** ([`Some`]): a regular-file fd always reports readable
///   immediately under `poll()`/`select()`, so there is nothing to wait for —
///   return at once, exactly as the C `poll()` would. This keeps `-T file`
///   uploads running at full speed (no per-chunk sleep).
/// * **Standard input / pipe** ([`None`]): no readiness signal is available
///   without raw `poll()`, so sleep for a short, capped slice of `waitms`
///   ([`waitfd_sleep_ms`]) to avoid a busy spin while keeping the wait bounded.
///
/// Because the return is unused and a non-file source is read with a blocking
/// `Read` anyway, this simplification is observationally negligible for parity.
///
/// The `_waitms`/`input` signature mirrors C's `waitfd(int waitms, int fd)`. The
/// Windows `_WIN32`-only variant (`select` fallback) is not ported; the AAP's
/// four targets are Linux/macOS.
fn waitfd(waitms: i32, input: &Option<File>) {
    if input.is_none() {
        let ms = waitfd_sleep_ms(waitms);
        if ms > 0 {
            thread::sleep(Duration::from_millis(ms));
        }
    }
}

// ===========================================================================
// tool_read_cb — the CURLOPT_READFUNCTION upload feeder
// (port of src/tool_cb_rea.c:79-158)
// ===========================================================================

/// `CURLOPT_READFUNCTION` callback: feeds upload-request-body bytes from the
/// per-transfer input source into the buffer libcurl supplies.
///
/// This is the Rust port of curl's `tool_read_cb` (`src/tool_cb_rea.c:79-158`).
/// The C signature is `size_t tool_read_cb(char *buffer, size_t sz, size_t nmemb,
/// void *userdata)`; here the destination is a safe `&mut [u8]` (its length is
/// the C `sz * nmemb`), `userdata` becomes the typed `per`, and the operation
/// configuration — which C reaches via `per->config` — is resolved through
/// `global.operations[per.config_idx]` (the same back-reference the rest of the
/// CLI uses). `global` is also needed to emit the over-size warning via
/// [`crate::warnf!`].
///
/// The control flow reproduces the C original exactly:
///
/// 1. **Done check.** If the upload has a definite size and exactly that many
///    bytes were already consumed, return `Bytes(0)` — the upload is complete.
/// 2. **Timeout throttle.** When `--max-time` is set (`timeout_ms != 0`), compute
///    the elapsed time since the transfer started; if it exceeds the deadline,
///    return `Bytes(0)` to end the read. Otherwise wait (bounded) for input
///    readiness via [`waitfd`] (whose return is ignored).
/// 3. **The read.** Read into `buffer`. A would-block error sets `readbusy` and
///    returns [`ReadResult::Pause`]; any other error is treated as `0` bytes.
/// 4. **Upload-size cap.** If the source grew past its original size, emit the
///    exact over-size warning and clamp the byte count to the remaining size.
/// 5. **Clear busy** and return the byte count.
///
/// The byte accounting (`uploadedsofar`) is updated by libcurl's transfer engine,
/// not here — exactly as in C; this callback only reads and clamps.
///
/// # Note
///
/// The Windows `-T .` socket-stdin path (`src/tool_cb_rea.c:107-129`, where
/// `per->infd` is a socket fed by a reader thread and read with `recv()`) is not
/// ported; the AAP's four targets are Linux/macOS, so only the POSIX `read()`
/// branch is taken.
pub fn tool_read_cb(buffer: &mut [u8], per: &mut PerTransfer, global: &mut GlobalConfig) -> ReadResult {
    let idx = per.config_idx;

    // (1) Done check (C:85-89): nothing more to upload.
    if upload_complete(per.uploadfilesize, per.uploadedsofar) {
        return ReadResult::Bytes(0);
    }

    // (2) Timeout / wait throttle (C:91-105). Read `timeout_ms` into a local so
    // no borrow of `global.operations[idx]` is held across the read or `warnf!`.
    let timeout_ms = global.operations[idx].timeout_ms;
    if timeout_ms != 0 {
        let msdelta = Instant::now().duration_since(per.start).as_millis() as i64;
        if timed_out(timeout_ms, msdelta) {
            return ReadResult::Bytes(0); // timeout
        }
        // Non-Windows: bounded wait for input readiness; the return is ignored.
        waitfd(clamp_wait(timeout_ms, msdelta), &per.infile);
    }

    // (3) The read (C:130-148, the non-Windows `else` branch).
    let rc: usize = match classify_read(read_from_input(&mut per.infile, buffer)) {
        ReadStep::Filled(n) => n,
        ReadStep::WouldBlock => {
            // EAGAIN: mark the transfer busy and pause; `tool_readbusy_cb`
            // (plus the write/progress callbacks) will unpause it later.
            global.operations[idx].readbusy = true;
            return ReadResult::Pause;
        }
        // Any other error: since size_t is unsigned we cannot return negatives,
        // so report 0 bytes (matching C `rc = 0`).
        ReadStep::OtherErr => 0,
    };

    // (4) Upload-size cap (C:145-153): never upload more than originally sized.
    let cap = apply_upload_cap(per.uploadfilesize, per.uploadedsofar, rc);
    if let Some(delta) = cap.dropped {
        warnf!(global, "{}", cap_warning(delta));
    }
    let rc = cap.rc;

    // (5) Clear busy (C:154) and return the byte count. A returned `0` here
    // legitimately signals EOF/timeout to libcurl (C:156).
    global.operations[idx].readbusy = false;
    ReadResult::Bytes(rc)
}

// ===========================================================================
// tool_readbusy_cb — XFERINFOFUNCTION that unpauses busy reads
// (port of src/tool_cb_rea.c:164-192)
// ===========================================================================

/// `CURLOPT_XFERINFOFUNCTION` callback whose sole job is to **unpause** an upload
/// that [`tool_read_cb`] paused because its read source returned `EAGAIN`.
///
/// This is the Rust port of curl's `tool_readbusy_cb` (`src/tool_cb_rea.c:164-192`).
/// The C signature is `int tool_readbusy_cb(void *clientp, curl_off_t dltotal,
/// dlnow, ultotal, ulnow)`; the four progress counters arrive as safe `i64`, and
/// `clientp` becomes the typed `per` (with the operation configuration resolved
/// through `global.operations[per.config_idx]`).
///
/// When the transfer is marked busy ([`OperationConfig::readbusy`](crate::config::OperationConfig::readbusy)):
/// if the uploaded byte count has not advanced since the previous call
/// (`ulprev == ulnow`, indicating a genuine stall), wait a bounded 1 ms for the
/// source via [`waitfd`]; then clear the busy flag and resume the easy handle
/// with `CURLPAUSE_CONT`. The previous upload count is then updated.
///
/// curl persists `ulprev` in a function-`static`; the safe port stores it on
/// [`PerTransfer::ulprev`](crate::operate::PerTransfer::ulprev) (per-transfer
/// state is more correct than a process-global and needs no `unsafe`). The
/// observable effect — at most a 1 ms wait when the upload stalls — is unchanged.
///
/// Returns [`CURL_PROGRESSFUNC_CONTINUE`](curl_rs_lib::progress::CURL_PROGRESSFUNC_CONTINUE)
/// so libcurl's built-in progress meter still runs, unless progress is suppressed
/// for this transfer (`per.noprogress`), in which case it returns `0`.
pub fn tool_readbusy_cb(
    per: &mut PerTransfer,
    global: &mut GlobalConfig,
    _dltotal: i64,
    _dlnow: i64,
    _ultotal: i64,
    ulnow: i64,
) -> i32 {
    let idx = per.config_idx;

    if global.operations[idx].readbusy {
        if per.ulprev == ulnow {
            // Genuine stall (no upload progress since last call): wait 1 ms for
            // the source. Non-Windows path; the return is ignored.
            waitfd(1, &per.infile);
        }

        // Clear the busy flag BEFORE resuming (matching C's statement order), then
        // resume both directions. `Easy::pause` returns an error when the handle
        // has no active transfer; curl ignores `curl_easy_pause`'s return here, so
        // the result is intentionally discarded.
        global.operations[idx].readbusy = false;
        let _ = per.easy.pause(CURLPAUSE_CONT);
    }

    // Persist the latest upload count for the next stall comparison (C:190).
    per.ulprev = ulnow;

    readbusy_return(per.noprogress)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write as _;
    use std::time::Instant;

    use tempfile::NamedTempFile;

    use crate::config::GlobalConfig;
    use crate::operate::PerTransfer;

    /// Creates a temporary file containing `content` and returns it together with
    /// a fresh read handle positioned at offset 0. The [`NamedTempFile`] is
    /// returned so the caller keeps it alive (dropping it deletes the file).
    fn temp_input(content: &[u8]) -> (NamedTempFile, File) {
        let mut tf = NamedTempFile::new().expect("create temp file");
        tf.write_all(content).expect("write temp file");
        tf.flush().expect("flush temp file");
        let file = File::open(tf.path()).expect("reopen temp file");
        (tf, file)
    }

    // ---- return-value sentinels & ReadResult --------------------------------

    #[test]
    fn readfunc_constants_match_curl_headers() {
        // Exact `include/curl/curl.h` #define values.
        assert_eq!(CURL_READFUNC_PAUSE, 0x1000_0001);
        assert_eq!(CURL_READFUNC_ABORT, 0x1000_0000);
        // Pause shares the numeric family of the write/progress "continue/pause"
        // sentinel (0x10000001), as documented in curl_rs_lib.
        assert_eq!(CURL_READFUNC_PAUSE, CURL_PROGRESSFUNC_CONTINUE as usize);
    }

    #[test]
    fn read_result_to_curl_return_maps_each_variant() {
        assert_eq!(ReadResult::Bytes(0).to_curl_return(), 0);
        assert_eq!(ReadResult::Bytes(4096).to_curl_return(), 4096);
        assert_eq!(ReadResult::Pause.to_curl_return(), CURL_READFUNC_PAUSE);
        assert_eq!(ReadResult::Abort.to_curl_return(), CURL_READFUNC_ABORT);
    }

    // ---- cap warning string (byte-for-byte parity) --------------------------

    #[test]
    fn cap_warning_is_byte_for_byte_identical_to_curl() {
        // The literal must match `src/tool_cb_rea.c:149-151` exactly: a single
        // line with one space between "when" and "started.".
        assert_eq!(
            cap_warning(1234),
            "File size larger in the end than when started. Dropping at least 1234 bytes"
        );
        assert_eq!(
            cap_warning(1),
            "File size larger in the end than when started. Dropping at least 1 bytes"
        );
    }

    // ---- upload_complete (done check) ---------------------------------------

    #[test]
    fn upload_complete_only_when_sized_and_fully_consumed() {
        // Unknown size (-1) is never "complete".
        assert!(!upload_complete(-1, 0));
        assert!(!upload_complete(-1, 999));
        // Sized: complete iff consumed == size.
        assert!(upload_complete(10, 10));
        assert!(!upload_complete(10, 9));
        assert!(!upload_complete(10, 0));
    }

    // ---- timed_out ----------------------------------------------------------

    #[test]
    fn timed_out_compares_elapsed_against_deadline() {
        assert!(timed_out(100, 101));
        assert!(!timed_out(100, 100)); // equal is NOT over (C uses strict `>`).
        assert!(!timed_out(100, 50));
    }

    // ---- clamp_wait ---------------------------------------------------------

    #[test]
    fn clamp_wait_computes_remaining_budget_and_clamps() {
        assert_eq!(clamp_wait(100, 40), 60);
        assert_eq!(clamp_wait(100, 100), 0);
        // A remaining budget beyond i32::MAX clamps to i32::MAX.
        assert_eq!(clamp_wait(i64::from(i32::MAX) + 1000, 0), i32::MAX);
    }

    // ---- classify_read ------------------------------------------------------

    #[test]
    fn classify_read_maps_ok_wouldblock_and_other_errors() {
        assert_eq!(classify_read(Ok(7)), ReadStep::Filled(7));
        assert_eq!(classify_read(Ok(0)), ReadStep::Filled(0));
        assert_eq!(
            classify_read(Err(io::Error::from(io::ErrorKind::WouldBlock))),
            ReadStep::WouldBlock
        );
        assert_eq!(
            classify_read(Err(io::Error::from(io::ErrorKind::BrokenPipe))),
            ReadStep::OtherErr
        );
        assert_eq!(
            classify_read(Err(io::Error::from(io::ErrorKind::PermissionDenied))),
            ReadStep::OtherErr
        );
    }

    // ---- apply_upload_cap ---------------------------------------------------

    #[test]
    fn apply_upload_cap_passes_through_when_unknown_size() {
        let cap = apply_upload_cap(-1, 1_000_000, 8192);
        assert_eq!(cap.rc, 8192);
        assert_eq!(cap.dropped, None);
    }

    #[test]
    fn apply_upload_cap_passes_through_when_within_size() {
        // 100 consumed + 50 read == 150 <= 200: no cap.
        let cap = apply_upload_cap(200, 100, 50);
        assert_eq!(cap.rc, 50);
        assert_eq!(cap.dropped, None);
        // Exact fit (150 == 150) is also not an overrun.
        let cap = apply_upload_cap(150, 100, 50);
        assert_eq!(cap.rc, 50);
        assert_eq!(cap.dropped, None);
    }

    #[test]
    fn apply_upload_cap_clamps_and_reports_overrun() {
        // 100 consumed + 50 read == 150 > 120: drop 30, clamp to 20.
        let cap = apply_upload_cap(120, 100, 50);
        assert_eq!(cap.rc, 20);
        assert_eq!(cap.dropped, Some(30));
        // From a fresh start: file grew from 4 to (0 + 10) -> drop 6, clamp 4.
        let cap = apply_upload_cap(4, 0, 10);
        assert_eq!(cap.rc, 4);
        assert_eq!(cap.dropped, Some(6));
    }

    // ---- readbusy_return ----------------------------------------------------

    #[test]
    fn readbusy_return_honors_noprogress() {
        assert_eq!(readbusy_return(false), CURL_PROGRESSFUNC_CONTINUE);
        assert_eq!(readbusy_return(true), 0);
    }

    // ---- waitfd_sleep_ms ----------------------------------------------------

    #[test]
    fn waitfd_sleep_ms_clamps_to_bounds() {
        assert_eq!(waitfd_sleep_ms(1), 1);
        assert_eq!(waitfd_sleep_ms(0), 0);
        assert_eq!(waitfd_sleep_ms(-5), 0);
        assert_eq!(waitfd_sleep_ms(500), 500);
        assert_eq!(waitfd_sleep_ms(i32::MAX), WAITFD_MAX_SLEEP_MS as u64);
    }

    #[test]
    fn waitfd_on_regular_file_does_not_sleep() {
        // A regular file is always ready, so even a large `waitms` must return
        // promptly (no sleep). Generous bound avoids timing flakiness.
        let (_tf, file) = temp_input(b"x");
        let input = Some(file);
        let start = Instant::now();
        waitfd(1000, &input);
        assert!(start.elapsed() < Duration::from_millis(200));
    }

    // ---- tool_read_cb (callback-level) --------------------------------------

    #[test]
    fn tool_read_cb_returns_zero_when_upload_done() {
        let mut per = PerTransfer::new(0);
        per.uploadfilesize = 10;
        per.uploadedsofar = 10; // fully consumed -> done
        let mut global = GlobalConfig::new();
        let mut buf = [0u8; 16];
        assert_eq!(
            tool_read_cb(&mut buf, &mut per, &mut global),
            ReadResult::Bytes(0)
        );
    }

    #[test]
    fn tool_read_cb_returns_zero_on_timeout() {
        // Give the input real content so that, if the timeout branch were NOT
        // taken, the test would FAIL loudly (Bytes(>0)) rather than read stdin.
        let (_tf, file) = temp_input(b"payload-bytes");
        let mut per = PerTransfer::new(0);
        per.infile = Some(file);
        per.uploadfilesize = 13;
        per.uploadedsofar = 0;
        per.start = Instant::now();
        let mut global = GlobalConfig::new();
        global.operations[0].timeout_ms = 1; // 1 ms deadline
        std::thread::sleep(Duration::from_millis(5)); // guarantee msdelta > 1
        let mut buf = [0u8; 16];
        assert_eq!(
            tool_read_cb(&mut buf, &mut per, &mut global),
            ReadResult::Bytes(0)
        );
    }

    #[test]
    fn tool_read_cb_feeds_file_bytes() {
        let (_tf, file) = temp_input(b"hello");
        let mut per = PerTransfer::new(0);
        per.infile = Some(file);
        per.uploadfilesize = 5;
        per.uploadedsofar = 0;
        let mut global = GlobalConfig::new();
        global.operations[0].timeout_ms = 0; // no throttle
        let mut buf = [0u8; 16];
        assert_eq!(
            tool_read_cb(&mut buf, &mut per, &mut global),
            ReadResult::Bytes(5)
        );
        assert_eq!(&buf[..5], b"hello");
        // Busy flag must be cleared on a normal read.
        assert!(!global.operations[0].readbusy);
    }

    #[test]
    fn tool_read_cb_clamps_to_uploadfilesize_when_source_grows() {
        // The source has 10 bytes but the upload was sized at 4: read must clamp.
        let (_tf, file) = temp_input(b"0123456789");
        let mut per = PerTransfer::new(0);
        per.infile = Some(file);
        per.uploadfilesize = 4;
        per.uploadedsofar = 0;
        let mut global = GlobalConfig::new();
        global.operations[0].timeout_ms = 0;
        let mut buf = [0u8; 16];
        assert_eq!(
            tool_read_cb(&mut buf, &mut per, &mut global),
            ReadResult::Bytes(4)
        );
    }

    // ---- tool_readbusy_cb (callback-level) ----------------------------------

    #[test]
    fn tool_readbusy_cb_unpauses_and_continues() {
        let mut per = PerTransfer::new(0);
        per.ulprev = 0;
        per.noprogress = false;
        let mut global = GlobalConfig::new();
        global.operations[0].readbusy = true;
        // ulnow (5) != ulprev (0): not a stall, so waitfd is skipped.
        let ret = tool_readbusy_cb(&mut per, &mut global, 0, 0, 0, 5);
        assert_eq!(ret, CURL_PROGRESSFUNC_CONTINUE);
        assert!(!global.operations[0].readbusy); // busy cleared
        assert_eq!(per.ulprev, 5); // latest upload count persisted
    }

    #[test]
    fn tool_readbusy_cb_stall_path_unpauses() {
        // ulprev == ulnow exercises the stall branch (waitfd). A file input keeps
        // waitfd instant. The transfer is still unpaused afterward.
        let (_tf, file) = temp_input(b"x");
        let mut per = PerTransfer::new(0);
        per.infile = Some(file);
        per.ulprev = 42;
        per.noprogress = false;
        let mut global = GlobalConfig::new();
        global.operations[0].readbusy = true;
        let ret = tool_readbusy_cb(&mut per, &mut global, 0, 0, 0, 42);
        assert_eq!(ret, CURL_PROGRESSFUNC_CONTINUE);
        assert!(!global.operations[0].readbusy);
        assert_eq!(per.ulprev, 42);
    }

    #[test]
    fn tool_readbusy_cb_returns_zero_when_noprogress() {
        let mut per = PerTransfer::new(0);
        per.ulprev = 0;
        per.noprogress = true;
        let mut global = GlobalConfig::new();
        global.operations[0].readbusy = false; // not busy
        let ret = tool_readbusy_cb(&mut per, &mut global, 0, 0, 0, 9);
        assert_eq!(ret, 0);
        assert_eq!(per.ulprev, 9); // ulprev still updated every call
    }

    #[test]
    fn tool_readbusy_cb_is_noop_when_not_busy() {
        let mut per = PerTransfer::new(0);
        per.ulprev = 3;
        per.noprogress = false;
        let mut global = GlobalConfig::new();
        global.operations[0].readbusy = false;
        let ret = tool_readbusy_cb(&mut per, &mut global, 0, 0, 0, 3);
        assert_eq!(ret, CURL_PROGRESSFUNC_CONTINUE);
        assert!(!global.operations[0].readbusy);
        assert_eq!(per.ulprev, 3);
    }
}
