// -----------------------------------------------------------------------
// curl-rs/src/callbacks/read.rs — Read Callback for Upload Data
//
// Rust rewrite of `src/tool_cb_rea.c` and `src/tool_cb_rea.h` from
// curl 8.19.0-DEV.  Implements the CURLOPT_READFUNCTION callback for
// reading upload data from files/stdin, with:
//
//   - Upload completion detection (returns EOF when declared size met)
//   - Timeout enforcement (returns EOF when `--max-time` expires)
//   - WouldBlock/EAGAIN → Pause/readbusy protocol
//   - Upload-size clamping with file-grew-unexpectedly warning
//   - Readbusy recovery callback with 1 ms anti-spin sleep
//
// ## Key Differences from C
//
// | C Behavior                               | Rust Equivalent                        |
// |------------------------------------------|----------------------------------------|
// | `read(infd, buf, sz*nmemb)` on POSIX     | `reader.read(buffer)` via `dyn Read`   |
// | `sread()` / SOCKEWOULDBLOCK (Windows)    | `ErrorKind::WouldBlock` (portable)     |
// | `waitfd()` via poll/select               | No pre-wait; read blocks naturally     |
// | `CURL_READFUNC_PAUSE` (0x10000001)       | `ReadResult::Pause` enum variant       |
// | `static curl_off_t ulprev`               | Per-transfer `ulprev` field            |
// | `curl_easy_pause(per->curl, CONT)`       | `data.needs_unpause = true` flag       |
//
// ## Safety
//
// This module contains **zero** `unsafe` blocks.
//
// SPDX-License-Identifier: curl
// -----------------------------------------------------------------------

use std::io::{ErrorKind, Read};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::{GlobalConfig, OperationConfig};
use crate::msgs;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// libcurl's `CURL_PROGRESSFUNC_CONTINUE` value (`0x10000001`).
///
/// When returned from an `XFERINFOFUNCTION` callback, tells the transfer
/// engine to update its internal progress meter but otherwise continue the
/// transfer as normal.  Returning `0` instead suppresses the internal
/// progress callback behavior.
///
/// Matches the C `#define CURL_PROGRESSFUNC_CONTINUE 0x10000001`.
pub const CURL_PROGRESSFUNC_CONTINUE: i32 = 0x1000_0001_u32 as i32;

// ---------------------------------------------------------------------------
// ReadResult — typed replacement for CURL_READFUNC_* return codes
// ---------------------------------------------------------------------------

/// Result type returned by the read callback, replacing the C-style
/// `size_t` return value with explicit, type-safe semantics.
///
/// In the C API the read callback returns:
///
/// | C Return Value               | Meaning                           |
/// |------------------------------|-----------------------------------|
/// | positive `size_t`            | Bytes read into the buffer        |
/// | `0`                          | End of file / upload complete     |
/// | `CURL_READFUNC_ABORT` (0x10000000) | Hard abort                 |
/// | `CURL_READFUNC_PAUSE` (0x10000001) | Pause (WouldBlock)         |
///
/// This enum makes those semantics explicit and prevents integer
/// misinterpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadResult {
    /// Successfully read `n` bytes into the buffer.
    ///
    /// The engine should transmit exactly `n` bytes from the front of
    /// the buffer.  A value of `0` is distinct from [`Eof`] only at the
    /// type level — both signal end-of-data in the C ABI.
    Bytes(usize),

    /// Temporarily blocked — the read source returned `WouldBlock`.
    ///
    /// Signals the transfer engine to pause the upload until the
    /// readbusy callback ([`tool_readbusy_cb`]) clears the condition
    /// and the transfer is unpaused via `curl_easy_pause(CURLPAUSE_CONT)`.
    ///
    /// Maps to `CURL_READFUNC_PAUSE` (`0x10000001`) in the C ABI.
    Pause,

    /// Hard, unrecoverable failure — the upload should be aborted.
    ///
    /// Maps to `CURL_READFUNC_ABORT` (`0x10000000`) in the C ABI.
    Abort,

    /// End of file — no more data to upload.
    ///
    /// Returned when:
    /// - The declared `uploadfilesize` has been fully delivered.
    /// - The input stream returns zero bytes (true EOF).
    /// - The upload timeout has expired.
    /// - A non-WouldBlock I/O error occurred (matching C's `rc = 0`
    ///   fallback behavior).
    ///
    /// Maps to a return value of `0` in the C ABI.
    Eof,
}

impl ReadResult {
    /// Convert to the C-compatible `size_t` return value.
    ///
    /// This is used when bridging back to the C ABI in the FFI layer.
    ///
    /// | Variant        | C Value                                |
    /// |----------------|----------------------------------------|
    /// | `Bytes(n)`     | `n`                                    |
    /// | `Pause`        | `CURL_READFUNC_PAUSE`  (`0x10000001`)  |
    /// | `Abort`        | `CURL_READFUNC_ABORT`  (`0x10000000`)  |
    /// | `Eof`          | `0`                                    |
    #[inline]
    pub fn as_usize(self) -> usize {
        match self {
            ReadResult::Bytes(n) => n,
            ReadResult::Pause => 0x1000_0001,
            ReadResult::Abort => 0x1000_0000,
            ReadResult::Eof => 0,
        }
    }

    /// Attempt to create a `ReadResult` from a C-style `size_t` return
    /// value.
    ///
    /// Returns `None` for values that do not match any known constant.
    #[inline]
    pub fn from_usize(value: usize) -> Option<Self> {
        match value {
            0 => Some(ReadResult::Eof),
            0x1000_0001 => Some(ReadResult::Pause),
            0x1000_0000 => Some(ReadResult::Abort),
            n => Some(ReadResult::Bytes(n)),
        }
    }
}

impl std::fmt::Display for ReadResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadResult::Bytes(n) => write!(f, "Bytes({})", n),
            ReadResult::Pause => write!(f, "CURL_READFUNC_PAUSE"),
            ReadResult::Abort => write!(f, "CURL_READFUNC_ABORT"),
            ReadResult::Eof => write!(f, "EOF(0)"),
        }
    }
}

// ---------------------------------------------------------------------------
// ReadCallbackData — per-transfer state for read/readbusy callbacks
// ---------------------------------------------------------------------------

/// Per-transfer state consumed by [`tool_read_cb`] and
/// [`tool_readbusy_cb`].
///
/// This struct holds the subset of `per_transfer` fields (from the C
/// `struct per_transfer` in `tool_operate.h`) that the read and readbusy
/// callbacks require.  The operate module populates this struct when
/// setting up each transfer.
///
/// ## Design vs. C
///
/// In C, `per_transfer` is a monolithic struct accessed by all callbacks.
/// In Rust, each callback module defines its own per-transfer data struct
/// containing only the fields it needs, promoting encapsulation and
/// preventing unrelated state from leaking across callback boundaries.
///
/// The C `static curl_off_t ulprev` in `tool_readbusy_cb` is replaced by
/// the [`ulprev`](Self::ulprev) instance field, eliminating global mutable
/// state and enabling safe parallel transfers.
pub struct ReadCallbackData {
    /// Expected total upload file size in bytes, or `-1` if unknown.
    ///
    /// Corresponds to `per->uploadfilesize` in the C source.  When set
    /// to a non-negative value, [`tool_read_cb`] will:
    /// 1. Return [`ReadResult::Eof`] once `uploadedsofar` reaches this
    ///    value.
    /// 2. Clamp excess reads and emit a "file grew unexpectedly" warning
    ///    via [`msgs::warnf`].
    pub uploadfilesize: i64,

    /// Number of bytes delivered from this callback so far.
    ///
    /// Corresponds to `per->uploadedsofar` in the C source.  Updated
    /// after each successful (possibly clamped) read, and compared
    /// against [`uploadfilesize`](Self::uploadfilesize) for the "done"
    /// check and clamping logic.
    pub uploadedsofar: i64,

    /// Monotonic timestamp of when this transfer started.
    ///
    /// Corresponds to `per->start` in the C source.  Used to calculate
    /// elapsed time for the upload timeout check when
    /// `config.timeout > 0`.
    pub start: Instant,

    /// Previous upload position for readbusy tracking.
    ///
    /// Replaces the C `static curl_off_t ulprev` in `tool_readbusy_cb`.
    /// Stored per-transfer instead of as a process-global static to
    /// avoid data races during parallel transfers.
    pub ulprev: i64,

    /// Whether progress display is suppressed for this transfer.
    ///
    /// Corresponds to `per->noprogress` in the C source.  When `true`,
    /// [`tool_readbusy_cb`] returns `0` instead of
    /// [`CURL_PROGRESSFUNC_CONTINUE`].
    pub noprogress: bool,

    /// Set to `true` by [`tool_readbusy_cb`] when the transfer should
    /// be unpaused.
    ///
    /// The caller (operate module) checks this flag after the readbusy
    /// callback returns and calls the equivalent of
    /// `curl_easy_pause(handle, CURLPAUSE_CONT)` when set.  The flag
    /// is reset by the caller after performing the unpause.
    pub needs_unpause: bool,
}

impl ReadCallbackData {
    /// Creates a new `ReadCallbackData` with default values.
    ///
    /// | Field            | Default     | Meaning                         |
    /// |------------------|-------------|---------------------------------|
    /// | `uploadfilesize` | `-1`        | Unknown size                    |
    /// | `uploadedsofar`  | `0`         | Nothing uploaded yet            |
    /// | `start`          | `now()`     | Transfer starts immediately     |
    /// | `ulprev`         | `0`         | No previous upload position     |
    /// | `noprogress`     | `false`     | Progress display enabled        |
    /// | `needs_unpause`  | `false`     | No unpause needed               |
    pub fn new() -> Self {
        Self {
            uploadfilesize: -1,
            uploadedsofar: 0,
            start: Instant::now(),
            ulprev: 0,
            noprogress: false,
            needs_unpause: false,
        }
    }

    /// Creates a `ReadCallbackData` with a specific upload file size and
    /// start time.
    ///
    /// This is the typical constructor used by the operate module when
    /// setting up a file upload.
    ///
    /// # Arguments
    ///
    /// * `uploadfilesize` — Expected total bytes, or `-1` if unknown.
    /// * `start` — Monotonic time marking the start of this transfer.
    /// * `noprogress` — Whether to suppress progress output.
    pub fn with_size(uploadfilesize: i64, start: Instant, noprogress: bool) -> Self {
        Self {
            uploadfilesize,
            uploadedsofar: 0,
            start,
            ulprev: 0,
            noprogress,
            needs_unpause: false,
        }
    }
}

impl Default for ReadCallbackData {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// tool_read_cb — CURLOPT_READFUNCTION callback
// ---------------------------------------------------------------------------

/// Read callback for upload data streams.
///
/// This is the Rust equivalent of `tool_read_cb()` from
/// `src/tool_cb_rea.c`.  It reads upload data from the provided input
/// stream (file or stdin) into the supplied buffer, with the following
/// curl 8.x-compatible behaviors:
///
/// 1. **Upload completion** — Returns [`ReadResult::Eof`] when the known
///    `uploadfilesize` has been fully delivered.
///
/// 2. **Timeout enforcement** — If `config.timeout > 0`, checks elapsed
///    time against the transfer start.  Returns [`ReadResult::Eof`] when
///    the timeout expires (matching the C `return 0` on timeout).
///
/// 3. **WouldBlock handling** — Maps `ErrorKind::WouldBlock` to
///    [`ReadResult::Pause`] and sets `config.readbusy = true`, triggering
///    the pause/resume protocol via [`tool_readbusy_cb`].
///
/// 4. **Upload size clamping** — If the read would push `uploadedsofar`
///    beyond `uploadfilesize`, the returned byte count is clamped and a
///    "file grew unexpectedly" warning is emitted via [`msgs::warnf`].
///
/// 5. **Error fallback** — Any I/O error other than `WouldBlock` maps to
///    [`ReadResult::Eof`], matching the C behavior of setting `rc = 0`.
///
/// # Arguments
///
/// * `buffer`  — Destination buffer to fill with upload data.  Its length
///   determines the maximum bytes to read (equivalent to C's `sz * nmemb`).
/// * `reader`  — Input stream implementing [`Read`] (file, stdin, pipe).
/// * `data`    — Per-transfer state (upload progress, timing).
/// * `config`  — Per-operation configuration (timeout, readbusy flag).
/// * `global`  — Global configuration (for warning output suppression).
///
/// # Returns
///
/// * [`ReadResult::Bytes(n)`] — `n` bytes were read into `buffer[..n]`.
/// * [`ReadResult::Pause`]    — Read blocked (`WouldBlock`); upload paused.
/// * [`ReadResult::Eof`]      — End of input data, timeout, or I/O error.
///
/// # Panics
///
/// This function **never panics**.  All error paths are handled gracefully
/// through the [`ReadResult`] return value.
pub fn tool_read_cb(
    buffer: &mut [u8],
    reader: &mut dyn Read,
    data: &mut ReadCallbackData,
    config: &mut OperationConfig,
    global: &GlobalConfig,
) -> ReadResult {
    // ------------------------------------------------------------------
    // 1. Upload completion check.
    //
    // C: if((per->uploadfilesize != -1) &&
    //       (per->uploadedsofar == per->uploadfilesize)) {
    //        return 0; /* done */
    //    }
    //
    // When the declared upload size is known and has been fully
    // delivered, immediately return EOF without attempting a read.
    // ------------------------------------------------------------------
    if data.uploadfilesize != -1 && data.uploadedsofar >= data.uploadfilesize {
        return ReadResult::Eof;
    }

    // ------------------------------------------------------------------
    // 2. Timeout enforcement.
    //
    // C: if(config->timeout_ms) {
    //        struct curltime now = curlx_now();
    //        long msdelta = (long)curlx_timediff_ms(now, per->start);
    //        if(msdelta > config->timeout_ms)
    //            return 0; /* timeout */
    //        else { waitfd((int)w, per->infd); }
    //    }
    //
    // The Rust `config.timeout` field holds the timeout in milliseconds,
    // matching the C `config->timeout_ms`.
    //
    // The C non-Windows path uses `waitfd()` (poll/select on the fd)
    // to wait for readability.  In Rust, `Read::read()` on regular
    // files blocks naturally, and for stdin the WouldBlock path
    // handles non-blocking returns — so no explicit pre-wait is needed.
    // ------------------------------------------------------------------
    if config.timeout > 0 {
        let elapsed_ms = data.start.elapsed().as_millis() as i64;

        if elapsed_ms > config.timeout {
            // Timeout expired — signal EOF, matching C `return 0`.
            return ReadResult::Eof;
        }
    }

    // ------------------------------------------------------------------
    // 3. Read data from the input stream.
    //
    // C (non-Windows): rc = read(per->infd, buffer, sz * nmemb);
    //
    // Rust's `Read::read()` handles all platforms portably — no need
    // for the Windows-specific `sread()` / socket-stdin path from C.
    // Regular files, stdin, pipes, and sockets all work through the
    // unified `Read` trait.
    // ------------------------------------------------------------------
    let read_result = reader.read(buffer);

    match read_result {
        // -- True EOF from the input stream --
        //
        // C: rc == 0 after read()  →  falls through to `return (size_t)rc;`
        //    which returns 0 (EOF).
        Ok(0) => {
            config.readbusy = false;
            ReadResult::Eof
        }

        // -- Successful read of N bytes --
        Ok(bytes_read) => {
            let mut clamped = bytes_read;

            // ----------------------------------------------------------
            // 4. Upload size clamping.
            //
            // C: if((per->uploadfilesize != -1) &&
            //       (per->uploadedsofar + rc > per->uploadfilesize)) {
            //     curl_off_t delta = per->uploadedsofar + rc
            //                        - per->uploadfilesize;
            //     warnf("File size larger in the end than when "
            //           "started. Dropping at least %"
            //           CURL_FORMAT_CURL_OFF_T " bytes", delta);
            //     rc = (ssize_t)(per->uploadfilesize
            //                    - per->uploadedsofar);
            // }
            //
            // Prevents uploading more data than originally declared,
            // which would confuse servers expecting Content-Length
            // bytes exactly.
            // ----------------------------------------------------------
            if data.uploadfilesize != -1 {
                let total_after = data.uploadedsofar + clamped as i64;
                if total_after > data.uploadfilesize {
                    let delta = total_after - data.uploadfilesize;
                    msgs::warnf(
                        global,
                        &format!(
                            "File size larger in the end than when \
                             started. Dropping at least {} bytes",
                            delta
                        ),
                    );
                    // Clamp to exactly the remaining expected bytes.
                    let remaining = data.uploadfilesize - data.uploadedsofar;
                    clamped = if remaining > 0 {
                        remaining as usize
                    } else {
                        0
                    };
                }
            }

            // Update the upload progress counter.
            data.uploadedsofar += clamped as i64;

            // Clear the readbusy flag on successful read.
            //
            // C: config->readbusy = FALSE;
            config.readbusy = false;

            if clamped == 0 {
                // After clamping, zero bytes remain — signal EOF.
                ReadResult::Eof
            } else {
                ReadResult::Bytes(clamped)
            }
        }

        // -- WouldBlock / EAGAIN — pause protocol --
        //
        // C: if(errno == EAGAIN) {
        //        errno = 0;
        //        config->readbusy = TRUE;
        //        return CURL_READFUNC_PAUSE;
        //    }
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
            config.readbusy = true;
            ReadResult::Pause
        }

        // -- Other I/O errors — treated as EOF --
        //
        // C: rc = 0;  (falls through to `config->readbusy = FALSE;
        //              return (size_t)rc;`)
        //
        // The C implementation silently treats non-EAGAIN read errors
        // as zero-byte reads (EOF).  We match this exactly: clear
        // readbusy and return Eof.
        Err(_) => {
            config.readbusy = false;
            ReadResult::Eof
        }
    }
}

// ---------------------------------------------------------------------------
// tool_readbusy_cb — CURLOPT_XFERINFOFUNCTION for upload pause recovery
// ---------------------------------------------------------------------------

/// Progress/transfer-info callback for unpausing busy reads.
///
/// This is the Rust equivalent of `tool_readbusy_cb()` from
/// `src/tool_cb_rea.c`.  It is used as the `XFERINFOFUNCTION` callback
/// when the read callback has entered the "readbusy" pause state, and
/// its purpose is to:
///
/// 1. Detect when the upload source is ready to produce data again.
/// 2. Apply a 1 ms anti-spin sleep when no upload progress is detected.
/// 3. Clear the readbusy flag and signal that the transfer should be
///    unpaused.
///
/// ## Pause/Resume Protocol
///
/// ```text
///   tool_read_cb returns Pause  →  config.readbusy = true
///        ↓
///   engine calls tool_readbusy_cb periodically
///        ↓
///   readbusy_cb checks ulnow vs ulprev
///        ↓ (no progress)
///   sleep 1 ms to prevent busy-spinning
///        ↓
///   clear config.readbusy = false
///        ↓
///   set data.needs_unpause = true
///        ↓
///   caller calls curl_easy_pause(CURLPAUSE_CONT)
///        ↓
///   engine resumes → calls tool_read_cb again
/// ```
///
/// ## Side Effects
///
/// - Sleeps for 1 ms when the upload is stalled and readbusy is active.
///   This critical sleep prevents CPU-bound busy-spinning.
/// - Clears `config.readbusy`.
/// - Sets `data.needs_unpause` when the caller should invoke the
///   unpause operation.
///
/// # Arguments
///
/// * `data`      — Per-transfer read state (ulprev, noprogress, unpause).
/// * `config`    — Per-operation config (readbusy flag).
/// * `_dltotal`  — Total download bytes expected (unused).
/// * `_dlnow`    — Current download bytes (unused).
/// * `_ultotal`  — Total upload bytes expected (unused).
/// * `ulnow`     — Current upload bytes transferred by the engine.
///
/// # Returns
///
/// * `0` — When progress display is suppressed (`noprogress` is `true`).
/// * [`CURL_PROGRESSFUNC_CONTINUE`] — Otherwise (continue internal
///   progress meter).
///
/// # Panics
///
/// This function **never panics**.
pub fn tool_readbusy_cb(
    data: &mut ReadCallbackData,
    config: &mut OperationConfig,
    _dltotal: i64,
    _dlnow: i64,
    _ultotal: i64,
    ulnow: i64,
) -> i32 {
    // ------------------------------------------------------------------
    // 1. Check if the read callback is in the busy/paused state.
    //
    // C: if(config->readbusy) { ... }
    // ------------------------------------------------------------------
    if config.readbusy {
        // Compare current upload position against the previous value
        // to detect whether the upload has made any forward progress
        // since the last invocation of this callback.
        //
        // C: if(ulprev == ulnow) { waitfd(1, per->infd); }
        if data.ulprev == ulnow {
            // Upload has NOT advanced — sleep 1 ms to give the read
            // source time to produce data.  This single-millisecond
            // sleep is critical: without it, the engine would
            // busy-spin calling this callback thousands of times per
            // second while waiting for a slow/blocked read source.
            //
            // C (POSIX):   waitfd(1, per->infd);
            // C (Windows): curlx_wait_ms(1);
            thread::sleep(Duration::from_millis(1));
        }

        // Clear the readbusy flag and signal that the caller should
        // unpause the transfer.
        //
        // C: config->readbusy = FALSE;
        //    curl_easy_pause(per->curl, CURLPAUSE_CONT);
        //
        // In the Rust design, the `curl_easy_pause` call is delegated
        // to the caller via the `needs_unpause` flag, because the
        // callback does not hold a reference to the easy handle.
        config.readbusy = false;
        data.needs_unpause = true;
    }

    // ------------------------------------------------------------------
    // 2. Update the previous upload position tracker.
    //
    // C: ulprev = ulnow;
    // ------------------------------------------------------------------
    data.ulprev = ulnow;

    // ------------------------------------------------------------------
    // 3. Return the appropriate progress callback code.
    //
    // C: return per->noprogress ? 0 : CURL_PROGRESSFUNC_CONTINUE;
    //
    // When `noprogress` is true, returning 0 tells the engine to skip
    // its internal progress meter update.  Otherwise, CONTINUE tells
    // it to proceed with its normal progress display logic.
    // ------------------------------------------------------------------
    if data.noprogress {
        0
    } else {
        CURL_PROGRESSFUNC_CONTINUE
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // -- Helper: create a minimal GlobalConfig for testing --
    //
    // The warnf function checks `global.silent`; for most tests we want
    // it to be non-silent so warnings are actually emitted (to stderr).

    fn test_global_config(silent: bool) -> GlobalConfig {
        GlobalConfig {
            state: crate::config::TransferState::new(),
            trace_dump: None,
            trace_stream: None,
            libcurl: None,
            ssl_sessions: None,
            variables: Vec::new(),
            configs: vec![OperationConfig::new()],
            current: 0,
            ms_per_transfer: 0,
            tracetype: crate::config::TraceType::None,
            progressmode: 0,
            parallel_host: 0,
            parallel_max: crate::config::PARALLEL_DEFAULT,
            verbosity: 0,
            parallel: false,
            parallel_connect: false,
            fail_early: false,
            styled_output: false,
            trace_fopened: false,
            tracetime: false,
            traceids: false,
            showerror: false,
            silent,
            noprogress: false,
            isatty: false,
            trace_set: false,
            libcurl_info: crate::libinfo::LibCurlInfo::default(),
            term: crate::config::TerminalState::new(),
            libcurl_version: None,
        }
    }

    // -- ReadResult tests -------------------------------------------------

    #[test]
    fn read_result_as_usize_matches_curl_constants() {
        assert_eq!(ReadResult::Eof.as_usize(), 0);
        assert_eq!(ReadResult::Bytes(42).as_usize(), 42);
        assert_eq!(ReadResult::Pause.as_usize(), 0x1000_0001);
        assert_eq!(ReadResult::Abort.as_usize(), 0x1000_0000);
    }

    #[test]
    fn read_result_from_usize_roundtrip() {
        assert_eq!(ReadResult::from_usize(0), Some(ReadResult::Eof));
        assert_eq!(
            ReadResult::from_usize(0x1000_0001),
            Some(ReadResult::Pause)
        );
        assert_eq!(
            ReadResult::from_usize(0x1000_0000),
            Some(ReadResult::Abort)
        );
        assert_eq!(ReadResult::from_usize(100), Some(ReadResult::Bytes(100)));
    }

    #[test]
    fn read_result_display() {
        assert_eq!(format!("{}", ReadResult::Bytes(10)), "Bytes(10)");
        assert_eq!(format!("{}", ReadResult::Pause), "CURL_READFUNC_PAUSE");
        assert_eq!(format!("{}", ReadResult::Abort), "CURL_READFUNC_ABORT");
        assert_eq!(format!("{}", ReadResult::Eof), "EOF(0)");
    }

    // -- ReadCallbackData tests -------------------------------------------

    #[test]
    fn read_callback_data_default() {
        let data = ReadCallbackData::new();
        assert_eq!(data.uploadfilesize, -1);
        assert_eq!(data.uploadedsofar, 0);
        assert_eq!(data.ulprev, 0);
        assert!(!data.noprogress);
        assert!(!data.needs_unpause);
    }

    #[test]
    fn read_callback_data_with_size() {
        let now = Instant::now();
        let data = ReadCallbackData::with_size(1024, now, true);
        assert_eq!(data.uploadfilesize, 1024);
        assert_eq!(data.uploadedsofar, 0);
        assert!(data.noprogress);
        assert!(!data.needs_unpause);
    }

    // -- tool_read_cb tests -----------------------------------------------

    #[test]
    fn read_cb_returns_eof_when_upload_complete() {
        let global = test_global_config(true);
        let mut config = OperationConfig::new();
        let mut data = ReadCallbackData::new();
        data.uploadfilesize = 100;
        data.uploadedsofar = 100;

        let mut reader = Cursor::new(vec![0u8; 64]);
        let mut buffer = [0u8; 64];

        let result = tool_read_cb(&mut buffer, &mut reader, &mut data, &mut config, &global);
        assert_eq!(result, ReadResult::Eof);
    }

    #[test]
    fn read_cb_reads_bytes_from_cursor() {
        let global = test_global_config(true);
        let mut config = OperationConfig::new();
        let mut data = ReadCallbackData::new();
        // Unknown upload size (-1) — no clamping.

        let content = b"Hello, World!";
        let mut reader = Cursor::new(content.to_vec());
        let mut buffer = [0u8; 64];

        let result = tool_read_cb(&mut buffer, &mut reader, &mut data, &mut config, &global);
        assert_eq!(result, ReadResult::Bytes(13));
        assert_eq!(&buffer[..13], content.as_slice());
        assert_eq!(data.uploadedsofar, 13);
    }

    #[test]
    fn read_cb_returns_eof_on_empty_stream() {
        let global = test_global_config(true);
        let mut config = OperationConfig::new();
        let mut data = ReadCallbackData::new();

        let mut reader = Cursor::new(Vec::<u8>::new());
        let mut buffer = [0u8; 64];

        let result = tool_read_cb(&mut buffer, &mut reader, &mut data, &mut config, &global);
        assert_eq!(result, ReadResult::Eof);
    }

    #[test]
    fn read_cb_clamps_to_upload_filesize() {
        // Suppress warning output during test.
        let global = test_global_config(true);
        let mut config = OperationConfig::new();
        let mut data = ReadCallbackData::new();
        data.uploadfilesize = 5;
        data.uploadedsofar = 0;

        // The reader has 20 bytes, but upload is declared as 5.
        let mut reader = Cursor::new(vec![0xAA; 20]);
        let mut buffer = [0u8; 20];

        let result = tool_read_cb(&mut buffer, &mut reader, &mut data, &mut config, &global);
        // Should clamp to 5 bytes and warn.
        assert_eq!(result, ReadResult::Bytes(5));
        assert_eq!(data.uploadedsofar, 5);

        // Second read: uploadedsofar == uploadfilesize → EOF.
        let result2 = tool_read_cb(&mut buffer, &mut reader, &mut data, &mut config, &global);
        assert_eq!(result2, ReadResult::Eof);
    }

    #[test]
    fn read_cb_timeout_returns_eof() {
        let global = test_global_config(true);
        let mut config = OperationConfig::new();
        config.timeout = 1; // 1 ms timeout

        let mut data = ReadCallbackData::new();
        // Set start to a past time so elapsed > 1 ms.
        data.start = Instant::now() - Duration::from_millis(100);

        let mut reader = Cursor::new(vec![0u8; 64]);
        let mut buffer = [0u8; 64];

        let result = tool_read_cb(&mut buffer, &mut reader, &mut data, &mut config, &global);
        assert_eq!(result, ReadResult::Eof);
    }

    #[test]
    fn read_cb_clears_readbusy_on_success() {
        let global = test_global_config(true);
        let mut config = OperationConfig::new();
        config.readbusy = true; // simulate prior busy state

        let mut data = ReadCallbackData::new();
        let mut reader = Cursor::new(b"data".to_vec());
        let mut buffer = [0u8; 64];

        let result = tool_read_cb(&mut buffer, &mut reader, &mut data, &mut config, &global);
        assert_eq!(result, ReadResult::Bytes(4));
        assert!(!config.readbusy);
    }

    #[test]
    fn read_cb_unknown_size_no_clamping() {
        let global = test_global_config(true);
        let mut config = OperationConfig::new();
        let mut data = ReadCallbackData::new();
        data.uploadfilesize = -1; // unknown size

        let content = vec![0xBB; 1000];
        let mut reader = Cursor::new(content);
        let mut buffer = [0u8; 512];

        let result = tool_read_cb(&mut buffer, &mut reader, &mut data, &mut config, &global);
        assert_eq!(result, ReadResult::Bytes(512));
        assert_eq!(data.uploadedsofar, 512);
    }

    // -- tool_readbusy_cb tests -------------------------------------------

    #[test]
    fn readbusy_cb_clears_busy_and_signals_unpause() {
        let mut data = ReadCallbackData::new();
        data.noprogress = false;
        let mut config = OperationConfig::new();
        config.readbusy = true;

        // ulnow > ulprev → no sleep needed.
        let result = tool_readbusy_cb(&mut data, &mut config, 0, 0, 100, 50);

        assert!(!config.readbusy);
        assert!(data.needs_unpause);
        assert_eq!(data.ulprev, 50);
        assert_eq!(result, CURL_PROGRESSFUNC_CONTINUE);
    }

    #[test]
    fn readbusy_cb_sleeps_when_no_progress() {
        let mut data = ReadCallbackData::new();
        data.ulprev = 42;
        let mut config = OperationConfig::new();
        config.readbusy = true;

        let before = Instant::now();
        // ulnow == ulprev → triggers 1ms sleep.
        let _result = tool_readbusy_cb(&mut data, &mut config, 0, 0, 100, 42);
        let elapsed = before.elapsed();

        assert!(!config.readbusy);
        assert!(data.needs_unpause);
        // Should have slept at least 1ms (allow some OS scheduling slack).
        assert!(elapsed >= Duration::from_micros(500));
    }

    #[test]
    fn readbusy_cb_returns_zero_when_noprogress() {
        let mut data = ReadCallbackData::new();
        data.noprogress = true;
        let mut config = OperationConfig::new();
        config.readbusy = false;

        let result = tool_readbusy_cb(&mut data, &mut config, 0, 0, 0, 0);
        assert_eq!(result, 0);
    }

    #[test]
    fn readbusy_cb_returns_continue_when_progress_enabled() {
        let mut data = ReadCallbackData::new();
        data.noprogress = false;
        let mut config = OperationConfig::new();
        config.readbusy = false;

        let result = tool_readbusy_cb(&mut data, &mut config, 0, 0, 0, 10);
        assert_eq!(result, CURL_PROGRESSFUNC_CONTINUE);
        assert_eq!(data.ulprev, 10);
    }

    #[test]
    fn readbusy_cb_no_unpause_when_not_busy() {
        let mut data = ReadCallbackData::new();
        let mut config = OperationConfig::new();
        config.readbusy = false;

        let _result = tool_readbusy_cb(&mut data, &mut config, 0, 0, 0, 0);
        assert!(!data.needs_unpause);
    }

    #[test]
    fn readbusy_cb_updates_ulprev() {
        let mut data = ReadCallbackData::new();
        data.ulprev = 0;
        let mut config = OperationConfig::new();

        let _result = tool_readbusy_cb(&mut data, &mut config, 0, 0, 100, 75);
        assert_eq!(data.ulprev, 75);
    }

    // -- CURL_PROGRESSFUNC_CONTINUE constant test -------------------------

    #[test]
    fn progressfunc_continue_matches_c_value() {
        // C: #define CURL_PROGRESSFUNC_CONTINUE 0x10000001
        assert_eq!(CURL_PROGRESSFUNC_CONTINUE, 0x1000_0001_i32);
    }
}
