// curl-rs/src/callbacks/write.rs — Write Callback for Download Data
//
// Rust rewrite of src/tool_cb_wrt.c and src/tool_cb_wrt.h from curl 8.19.0-DEV.
//
// Implements the CURLOPT_WRITEFUNCTION callback that handles downloaded data,
// writing to output files or stdout with configurable CLOBBER policies,
// binary output detection on terminals, and transfer size limit enforcement.
//
// Key responsibilities:
// - Creating output files with clobber-mode-dependent overwrite policies
// - Exclusive file creation (O_CREAT|O_EXCL equivalent via create_new)
//   to prevent TOCTOU race conditions
// - Numbered filename alternatives (.1, .2, ...) for CLOBBER_NEVER mode
// - Binary output detection on terminal stdout with user warning
// - Flushing buffered Content-Disposition headers before first data write
// - Enforcing --no-buffer immediate flush semantics
// - Handling readbusy/pause continuation signalling
//
// Zero `unsafe` blocks — all I/O uses safe Rust abstractions.
//
// SPDX-License-Identifier: curl

use std::fs::{File, OpenOptions};
use std::io::{self, Write};

use crate::callbacks::header::{HdrCbData, OutStruct, OutputStream, tool_write_headers};
use crate::config::{ClobberMode, GlobalConfig, OperationConfig};
use crate::msgs;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Sentinel return value signalling a fatal write callback error to libcurl.
///
/// Equivalent to the C `CURL_WRITEFUNC_ERROR` constant (0xFFFFFFFF on 32-bit,
/// `(size_t)-1` on all platforms). Returning this value from the write
/// callback causes libcurl to abort the transfer with `CURLE_WRITE_ERROR`.
const CURL_WRITEFUNC_ERROR: usize = usize::MAX;

/// Maximum number of numbered filename suffix attempts when operating in
/// `ClobberPolicy::Never` mode.
///
/// The C implementation uses `next_num < 100` with `next_num` starting at 1,
/// resulting in suffix attempts `.1` through `.99` (99 alternatives total).
/// This constant controls the upper bound of the loop.
const MAX_CLOBBER_NUM: u32 = 100;

// ---------------------------------------------------------------------------
// ClobberPolicy — File overwrite policy
// ---------------------------------------------------------------------------

/// File overwrite policy for output file creation.
///
/// Maps 1:1 to the C CLOBBER_* constants defined for `file_clobber_mode`:
/// - `CLOBBER_DEFAULT`  (0) — overwrite unless filename came from Content-Disposition
/// - `CLOBBER_NEVER`    (1) — exclusive create; on conflict try numbered alternatives
/// - `CLOBBER_RENAME`   (2) — exclusive create; fail on conflict
/// - `CLOBBER_ALWAYS`   (3) — unconditionally overwrite existing files
///
/// The [`Default`] variant preserves curl 8.x default behaviour where `-o` and
/// `-O` overwrite files but `-J` (Content-Disposition) uses exclusive creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClobberPolicy {
    /// Overwrite unless the filename was derived from a Content-Disposition
    /// header (in which case exclusive creation is used).
    ///
    /// This is the default policy matching C `CLOBBER_DEFAULT` (0).
    Default = 0,

    /// Never overwrite existing files. When the target filename exists, try
    /// numbered alternatives `.1`, `.2`, … `.99` using exclusive creation.
    ///
    /// Matches C `CLOBBER_NEVER` (1), set by `--no-clobber`.
    Never = 1,

    /// Use exclusive file creation. If the file already exists, the creation
    /// fails immediately without attempting numbered alternatives.
    ///
    /// Matches C `CLOBBER_RENAME` (2).
    Rename = 2,

    /// Unconditionally overwrite any existing file.
    ///
    /// Matches C `CLOBBER_ALWAYS` (3).
    Always = 3,
}

impl From<ClobberMode> for ClobberPolicy {
    /// Converts the CLI-level [`ClobberMode`] (from config.rs) into the
    /// more granular [`ClobberPolicy`] used by the write callback.
    ///
    /// Note: `ClobberMode` does not have a `Default` variant — the CLI
    /// default is represented as `ClobberMode::Always` (matching the C
    /// constant `CLOBBER_DEFAULT` which is aliased to always-overwrite
    /// behaviour for non-Content-Disposition filenames).
    fn from(mode: ClobberMode) -> Self {
        match mode {
            ClobberMode::Always => ClobberPolicy::Always,
            ClobberMode::Never => ClobberPolicy::Never,
            ClobberMode::Rename => ClobberPolicy::Rename,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helper: error classification for clobber retry logic
// ---------------------------------------------------------------------------

/// Returns `true` when the I/O error indicates the path already exists as a
/// file or directory — matching the C check `errno == EEXIST || errno == EISDIR`.
///
/// `ErrorKind::AlreadyExists` maps to `EEXIST`. For `EISDIR`, which is only
/// available as `ErrorKind::IsADirectory` starting in Rust 1.83 (above MSRV
/// 1.75), we fall back to checking the raw OS error code (21 on Unix).
#[inline]
fn is_exists_or_isdir(e: &io::Error) -> bool {
    if e.kind() == io::ErrorKind::AlreadyExists {
        return true;
    }
    // EISDIR = 21 on all POSIX platforms. ErrorKind::IsADirectory is not
    // available until Rust 1.83, but MSRV is 1.75 — check raw OS error.
    #[cfg(unix)]
    if e.raw_os_error() == Some(21) {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// tool_create_output_file — Create/open a local file for writing
// ---------------------------------------------------------------------------

/// Creates or opens a local file for download output, applying the configured
/// clobber policy.
///
/// This is the Rust equivalent of the C `tool_create_output_file()` function
/// from `src/tool_cb_wrt.c`. It is called lazily on the first write to a
/// transfer's output stream when the stream has not yet been opened.
///
/// # Clobber Policy Logic (matching C behaviour exactly)
///
/// 1. **`ClobberMode::Always` with non-Content-Disposition filename:**
///    Standard overwrite via `File::create()` (equivalent to C `fopen("wb")`).
///    This is the default behaviour for `-o` and `-O`.
///
/// 2. **`ClobberMode::Always` with Content-Disposition filename (`-J`):**
///    Exclusive creation via `OpenOptions::create_new(true)` (equivalent to
///    C `O_CREAT|O_EXCL`). Prevents overwriting files whose names were
///    server-provided, matching the defensive C default.
///
/// 3. **`ClobberMode::Never` (`--no-clobber`):**
///    Exclusive creation on the original filename. On `AlreadyExists` failure,
///    tries numbered alternatives `filename.1`, `filename.2`, … `filename.99`
///    using exclusive creation for each. If all attempts fail, reports an error.
///
/// 4. **`ClobberMode::Rename`:**
///    Exclusive creation. On conflict, fails immediately without retries.
///
/// # Returns
///
/// `true` if the output file was successfully created/opened (stream is now
/// ready for writing), `false` on any failure. On failure, a warning is
/// emitted via [`msgs::warnf`].
///
/// # File Safety
///
/// All non-overwrite paths use `OpenOptions::create_new(true)` which maps to
/// `O_CREAT|O_EXCL` on POSIX — this prevents TOCTOU race conditions between
/// checking file existence and creating the file.
pub fn tool_create_output_file(
    outs: &mut OutStruct,
    config: &OperationConfig,
    global: &GlobalConfig,
) -> bool {
    // Extract the filename — must be present and non-empty.
    // In C: DEBUGASSERT(fname && *fname);
    let fname = match outs.filename {
        Some(ref f) if !f.is_empty() => f.clone(),
        _ => {
            // This should not happen if the caller validated state correctly.
            // Return false defensively, matching the C assertion failure path.
            return false;
        }
    };

    // -----------------------------------------------------------------------
    // Determine whether to use simple overwrite (fopen "wb") or exclusive
    // creation (O_CREAT|O_EXCL).
    //
    // C logic (lines 47-52):
    //   if(config->file_clobber_mode == CLOBBER_ALWAYS ||
    //      (config->file_clobber_mode == CLOBBER_DEFAULT &&
    //       !outs->is_cd_filename))
    //     file = curlx_fopen(fname, "wb");
    //
    // Since config.rs maps CLOBBER_DEFAULT to ClobberMode::Always, the
    // check becomes: ClobberMode::Always AND NOT cd_filename → overwrite.
    // When is_cd_filename is true (even with ClobberMode::Always), we fall
    // through to exclusive creation, matching the C CLOBBER_DEFAULT+cd path.
    // -----------------------------------------------------------------------
    let do_simple_overwrite = config.clobber == ClobberMode::Always && !outs.is_cd_filename;

    if do_simple_overwrite {
        // Simple overwrite: File::create ≡ fopen(fname, "wb")
        match File::create(&fname) {
            Ok(file) => {
                outs.stream = OutputStream::File(file);
                outs.s_isreg = true;
                outs.fopened = true;
                outs.bytes = 0;
                outs.init = false;
                return true;
            }
            Err(e) => {
                msgs::warnf(
                    global,
                    &format!("Failed to open the file {}: {}", fname, e),
                );
                return false;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Exclusive creation path: O_CREAT|O_EXCL|O_WRONLY
    //
    // C (lines 55-60):
    //   do {
    //     fd = curlx_open(fname, O_CREAT|O_WRONLY|O_EXCL|CURL_O_BINARY, OPENMODE);
    //   } while(fd == -1 && errno == EINTR);
    //
    // Rust's OpenOptions::create_new(true) provides the same atomicity
    // guarantee as O_CREAT|O_EXCL. Interrupt retry is handled internally
    // by the Rust standard library.
    // -----------------------------------------------------------------------
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&fname)
    {
        Ok(file) => {
            outs.stream = OutputStream::File(file);
            outs.s_isreg = true;
            outs.fopened = true;
            outs.bytes = 0;
            outs.init = false;
            true
        }
        Err(ref e)
            if e.kind() == io::ErrorKind::AlreadyExists
                && config.clobber == ClobberMode::Never =>
        {
            // ---------------------------------------------------------------
            // CLOBBER_NEVER: try numbered alternatives .1 through .99
            //
            // C (lines 62-82):
            //   int next_num = 1;
            //   while(fd == -1 &&
            //         (errno == EEXIST || errno == EISDIR) &&
            //         next_num < 100) {
            //       // try filename.next_num
            //       next_num++;
            //   }
            // ---------------------------------------------------------------
            let mut next_num: u32 = 1;
            while next_num < MAX_CLOBBER_NUM {
                let alt_name = format!("{}.{}", fname, next_num);
                next_num += 1;

                match OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&alt_name)
                {
                    Ok(file) => {
                        // Success: update the filename to the numbered
                        // alternative (matches C: outs->filename = dyn_ptr)
                        outs.filename = Some(alt_name);
                        outs.alloc_filename = true;
                        outs.stream = OutputStream::File(file);
                        outs.s_isreg = true;
                        outs.fopened = true;
                        outs.bytes = 0;
                        outs.init = false;
                        return true;
                    }
                    Err(ref e2) if is_exists_or_isdir(e2) => {
                        // File/directory exists at this numbered path — try
                        // the next suffix. Matches C: errno == EEXIST || errno == EISDIR
                        continue;
                    }
                    Err(_) => {
                        // Other I/O error on this alternative — try the next
                        // suffix anyway (best-effort, matches C retry loop
                        // which only checks EEXIST/EISDIR but continues the
                        // outer while loop for other errors too since the
                        // fd remains -1).
                        continue;
                    }
                }
            }

            // All numbered alternatives exhausted.
            msgs::warnf(
                global,
                &format!("Failed to open the file {}: File exists", fname),
            );
            false
        }
        Err(e) => {
            // Exclusive creation failed for a reason other than EEXIST with
            // CLOBBER_NEVER, or the clobber mode is CLOBBER_RENAME /
            // CLOBBER_DEFAULT+cd which does not retry.
            msgs::warnf(
                global,
                &format!("Failed to open the file {}: {}", fname, e),
            );
            false
        }
    }
}

// ---------------------------------------------------------------------------
// tool_write_cb — CURLOPT_WRITEFUNCTION callback
// ---------------------------------------------------------------------------

/// Write callback for downloaded transfer data.
///
/// This is the Rust equivalent of the C `tool_write_cb()` function registered
/// via `CURLOPT_WRITEFUNCTION` in `src/tool_cb_wrt.c`. It is invoked by the
/// transfer engine for each chunk of downloaded body data.
///
/// # Processing Pipeline (matching C order exactly)
///
/// 1. If output is null (`out_null`), discard all data and return success.
/// 2. If the output stream has not been opened yet, create the output file
///    via [`tool_create_output_file`].
/// 3. Binary output detection: if stdout is a terminal and the buffer
///    contains a null byte (binary data indicator), emit a warning and abort
///    the transfer (matching the C `terminal_binary_ok` check).
/// 4. Flush any buffered Content-Disposition headers via
///    [`tool_write_headers`] before writing body data.
/// 5. Write the buffer contents to the output stream.
/// 6. Handle `readbusy` flag reset (signals pause continuation to caller).
/// 7. If `nobuffer` is set (`--no-buffer`), flush the stream immediately.
///
/// # Return Value
///
/// - `buffer.len()` — all bytes successfully written (success).
/// - `0` — write I/O error (causes libcurl `CURLE_WRITE_ERROR`).
/// - `usize::MAX` (`CURL_WRITEFUNC_ERROR`) — fatal callback error (file
///   creation failure, binary-to-terminal abort, flush failure).
///
/// # Panics
///
/// This function is designed to never panic. All error conditions are handled
/// by returning an appropriate error code.
pub fn tool_write_cb(
    buffer: &[u8],
    outs: &mut OutStruct,
    config: &mut OperationConfig,
    global: &GlobalConfig,
    hdrcbdata: &mut HdrCbData,
) -> usize {
    let bytes = buffer.len();

    // (1) Null output — discard everything.
    // C (line 253): if(outs->out_null) return bytes;
    if outs.out_null {
        return bytes;
    }

    // (2) Lazy output file creation.
    // C (lines 308-309):
    //   if(!outs->stream && !tool_create_output_file(outs, per->config))
    //       return CURL_WRITEFUNC_ERROR;
    //
    // In Rust, OutputStream::Null with a filename indicates the stream has
    // not yet been opened.  OutputStream::Stdout or OutputStream::File means
    // the stream is already active.
    if outs.stream.is_null()
        && outs.filename.is_some()
        && !tool_create_output_file(outs, config, global)
    {
        return CURL_WRITEFUNC_ERROR;
    }

    // (3) Binary output detection on terminals.
    // C (lines 311-319):
    //   if(is_tty && (outs->bytes < 2000) && !config->terminal_binary_ok) {
    //     if(memchr(buffer, 0, bytes)) {
    //       warnf("Binary output can mess up your terminal...");
    //       config->synthetic_error = TRUE;
    //       return CURL_WRITEFUNC_ERROR;
    //     }
    //   }
    //
    // The check uses global->isatty which indicates stdout is a terminal.
    // Only check the first 2000 bytes of output (early detection).
    let is_tty = global.isatty;
    if is_tty
        && (outs.bytes < 2000)
        && !config.terminal_binary_ok
        && buffer.contains(&0u8)
    {
        msgs::warnf(
            global,
            "Binary output can mess up your terminal. Use \"--output -\" to \
             tell curl to output it to your terminal anyway, or consider \
             \"--output <FILE>\" to save to a file.",
        );
        config.synthetic_error = true;
        return CURL_WRITEFUNC_ERROR;
    }

    // (4) Flush buffered Content-Disposition headers.
    // C (lines 334-337):
    //   if(per->hdrcbdata.headlist) {
    //     if(tool_write_headers(&per->hdrcbdata, outs->stream))
    //       return CURL_WRITEFUNC_ERROR;
    //   }
    //
    // When -J is active, headers may be buffered waiting for the
    // Content-Disposition filename to be resolved. Before writing body data,
    // flush those buffered headers to the output stream.
    if !hdrcbdata.headlist.is_empty()
        && tool_write_headers(hdrcbdata, &mut outs.stream).is_err()
    {
        return CURL_WRITEFUNC_ERROR;
    }

    // (5) Write the download data to the output stream.
    // C (line 338): rc = fwrite(buffer, sz, nmemb, outs->stream);
    //
    // Rust's write_all either writes everything or returns an error — there
    // is no partial write. This matches the C semantics where fwrite returning
    // less than nmemb signals an error.
    let rc = match outs.stream.write_all(buffer) {
        Ok(()) => {
            // C (lines 341-343):
            //   if(bytes == rc) outs->bytes += bytes;
            outs.bytes += bytes as u64;
            bytes
        }
        Err(_) => {
            // Write failed — return 0 to signal error to libcurl.
            // In C, fwrite returning < nmemb causes the outer return of rc < bytes.
            0
        }
    };

    // If the write itself failed, skip readbusy/nobuffer handling and return
    // the error indicator immediately — matching C where rc < bytes means the
    // nobuffer flush path still runs but the return value is already rc.
    // For safety, we short-circuit on write failure.
    if rc == 0 {
        return rc;
    }

    // (6) Handle readbusy flag reset.
    // C (lines 345-348):
    //   if(config->readbusy) {
    //     config->readbusy = FALSE;
    //     curl_easy_pause(per->curl, CURLPAUSE_CONT);
    //   }
    //
    // In Rust, the actual unpause call is the caller's responsibility (since
    // we don't have access to the easy handle here). We clear the flag to
    // signal that the caller should issue the unpause.
    if config.readbusy {
        config.readbusy = false;
        // Caller (operate.rs) is responsible for calling
        // curl_easy_pause(handle, CURLPAUSE_CONT) after this callback returns.
    }

    // (7) Handle --no-buffer immediate flush.
    // C (lines 350-359):
    //   if(config->nobuffer) {
    //     int res;
    //     do { res = fflush(outs->stream); } while(res && errno == EINTR);
    //     if(res) return CURL_WRITEFUNC_ERROR;
    //   }
    if config.nobuffer && outs.stream.flush().is_err() {
        return CURL_WRITEFUNC_ERROR;
    }

    rc
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClobberMode;

    /// Verifies that ClobberPolicy has the expected integer discriminant values
    /// matching the C CLOBBER_* constants.
    #[test]
    fn clobber_policy_discriminants() {
        assert_eq!(ClobberPolicy::Default as u32, 0);
        assert_eq!(ClobberPolicy::Never as u32, 1);
        assert_eq!(ClobberPolicy::Rename as u32, 2);
        assert_eq!(ClobberPolicy::Always as u32, 3);
    }

    /// Verifies the ClobberMode → ClobberPolicy conversion.
    #[test]
    fn clobber_mode_to_policy_conversion() {
        assert_eq!(ClobberPolicy::from(ClobberMode::Always), ClobberPolicy::Always);
        assert_eq!(ClobberPolicy::from(ClobberMode::Never), ClobberPolicy::Never);
        assert_eq!(ClobberPolicy::from(ClobberMode::Rename), ClobberPolicy::Rename);
    }

    /// Verifies that CURL_WRITEFUNC_ERROR is usize::MAX.
    #[test]
    fn writefunc_error_constant() {
        assert_eq!(CURL_WRITEFUNC_ERROR, usize::MAX);
    }

    /// Verifies the is_exists_or_isdir helper correctly classifies errors.
    #[test]
    fn test_is_exists_or_isdir_already_exists() {
        let err = io::Error::new(io::ErrorKind::AlreadyExists, "test");
        assert!(is_exists_or_isdir(&err));
    }

    /// Verifies that non-exists errors are not classified as exists.
    #[test]
    fn test_is_exists_or_isdir_other_error() {
        let err = io::Error::new(io::ErrorKind::PermissionDenied, "test");
        assert!(!is_exists_or_isdir(&err));
    }

    /// Verifies ClobberPolicy equality and debug formatting.
    #[test]
    fn clobber_policy_clone_eq_debug() {
        let p = ClobberPolicy::Never;
        let p2 = p;
        assert_eq!(p, p2);
        assert_eq!(format!("{:?}", p), "Never");
    }
}
