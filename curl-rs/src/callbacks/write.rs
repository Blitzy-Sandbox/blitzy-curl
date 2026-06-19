//! `CURLOPT_WRITEFUNCTION` body-write callback and output-file creation for the
//! `curl-rs` CLI.
//!
//! This module is the memory-safe Rust reimplementation of curl's
//! `src/tool_cb_wrt.c` (the body-data write callback `tool_write_cb` and the
//! output-file opener `tool_create_output_file`). It is read against — but never
//! modifies — that C file and `src/tool_sdecls.h`, which serve strictly as the
//! behavioral oracle.
//!
//! # Role in the crate
//!
//! It implements the callback registered for `CURLOPT_WRITEFUNCTION`: the
//! function libcurl invokes for every chunk of received response **body**, plus
//! the lazy creator of the on-disk output file. The header-write path
//! (`-D`/`--dump-header` and the in-memory header buffer) lives in the sibling
//! `callbacks/header.rs`; this file only *flushes* any buffered headers ahead of
//! the first body byte, reproducing curl's ordering.
//!
//! # `OutStruct`
//!
//! curl's `struct OutStruct` (the per-sink output state) is defined canonically
//! in [`crate::operate`] — the operation driver owns the three sinks (`outs`,
//! `heads`, `etag_save`) embedded in each `PerTransfer`. To keep a single source
//! of truth and let this callback operate on the driver's own state, the type is
//! **re-exported** here (see [`OutStruct`]) rather than redefined; the crate's
//! `callbacks/mod.rs` re-exports it in turn. Compared with the C struct, Rust
//! ownership removes the manual bookkeeping: `Option<String>` owns the filename
//! (no `alloc_filename` flag) and `Drop` on the held `File` closes it
//! deterministically (no explicit `fclose`).
//!
//! # Behavioral parity (AAP §0.7.3, §0.8.2)
//!
//! Every observable artifact of `tool_cb_wrt.c` is reproduced exactly: the
//! `out_null` short-circuit, the binary-output-to-terminal refusal (with its
//! precise warning string and synthetic-error flag), the lazy file open with its
//! clobber/no-clobber/numbered-fallback policy, the header-before-body flush, the
//! byte accounting, the `readbusy` unpause, and the `--no-buffer` per-write
//! flush. The `CURL_WRITEFUNC_ERROR` sentinel is taken from
//! [`curl_rs_lib::transfer`] so the transfer/FFI layer maps it faithfully.
//!
//! # Out of scope (initial POSIX/macOS port)
//!
//! The Windows-console UTF-8→UTF-16 conversion path (`win_console`,
//! `tool_cb_wrt.c:108-235`, guarded by `#ifdef _WIN32` and only entered on a
//! Windows console) is intentionally omitted; on the Linux/macOS targets in the
//! AAP four-target matrix curl takes the plain `fwrite` branch, which is what
//! this port implements. The Windows-only `utf8seq` field is likewise not added.
//! The path can be reintroduced behind `#[cfg(windows)]` without changing this
//! module's public API.

#![forbid(unsafe_code)]
// The CLI is assembled file-by-file; this callback's public entry points
// (`create_output_file`, `write_cb`) are wired in by `operate`/`setopt` in a
// later migration step (AAP §0.8.4 step 11/12). `allow(dead_code)` keeps the
// not-yet-driven public functions from tripping the workspace `-D warnings`
// gate, mirroring the construction-order staging already used by sibling CLI
// modules (`formparse.rs`, `parsecfg.rs`); it is removed once they are called.
#![allow(dead_code)]

use std::fs::{File, OpenOptions};
use std::io::{self, Write};

use curl_rs_lib::easy::CURLPAUSE_CONT;
use curl_rs_lib::transfer::CURL_WRITEFUNC_ERROR;

use crate::config::{FileClobberMode, GlobalConfig, OperationConfig};
use crate::operate::{HdrCbData, PerTransfer};

// Re-export curl's `struct OutStruct` from the operation driver, which defines
// it canonically and embeds it in `PerTransfer`. Re-exporting (rather than
// redefining) keeps one source of truth and lets `write_cb` operate directly on
// `per.outs`; `callbacks/mod.rs` re-exports this in turn so the type is reachable
// as `crate::callbacks::OutStruct` and `crate::callbacks::write::OutStruct`.
pub use crate::operate::OutStruct;

/// Largest body chunk libcurl hands a single write-callback call
/// (`CURL_MAX_WRITE_SIZE`); only used by the debug-build size guard below.
/// Imported from the core to avoid drift; gated to debug builds so release
/// builds carry no unused import.
#[cfg(debug_assertions)]
use curl_rs_lib::transfer::CURL_MAX_WRITE_SIZE;

/// Largest header block libcurl will deliver (`CURL_MAX_HTTP_HEADER`,
/// `100 * 1024`, from `include/curl/curl.h`). The core library does not export
/// this constant, so it is defined locally; it is only consulted by the
/// debug-build header-size guard, hence the `#[cfg(debug_assertions)]` gate
/// (release builds must not carry an unused constant under `-D warnings`).
#[cfg(debug_assertions)]
const CURL_MAX_HTTP_HEADER: usize = 100 * 1024;

// ===========================================================================
// Output-file creation — port of `tool_create_output_file`
// (`src/tool_cb_wrt.c:38-108`).
// ===========================================================================

/// Creates (opens) the local output file named in `outs.filename`, applying
/// curl's clobber policy. Returns `true` on success (with `outs` updated to hold
/// the open file), or `false` after emitting curl's exact failure warning.
///
/// This is the Rust port of `tool_create_output_file`. The decision tree matches
/// C precisely:
///
/// * **Clobber allowed** — `CLOBBER_ALWAYS`, or `CLOBBER_DEFAULT` while the name
///   did *not* come from a `Content-Disposition` header: the file is opened for
///   writing, truncating any existing content (curl's `fopen(fname, "wb")`).
/// * **No clobber** — `CLOBBER_NEVER`, or `CLOBBER_DEFAULT` with a
///   `Content-Disposition` name: the file is created *exclusively* (curl's
///   `open(..., O_CREAT|O_WRONLY|O_EXCL)`), so an existing file is never
///   overwritten.
/// * **Numbered fallback** — only under `CLOBBER_NEVER`: when the exclusive
///   create fails because the file already exists, `"{fname}.1"`, `"{fname}.2"`,
///   … up to `"{fname}.99"` are tried until one is created (see
///   [`open_numbered_fallback`]).
///
/// On success `outs` is left exactly as C leaves it: `regular_file` and
/// `fopened` set, the open `File` stored in `stream`, and `bytes`/`init` reset to
/// zero. The `global` reference is required only to gate the failure warning on
/// `--silent` (C used a file-scope `global`; Rust passes it explicitly).
///
/// `outs.filename` must be `Some` and non-empty (C `DEBUGASSERT`); a violation is
/// a programming error that trips a `debug_assert!` and returns `false` in
/// release rather than panicking.
pub fn create_output_file(
    outs: &mut OutStruct,
    config: &OperationConfig,
    global: &GlobalConfig,
) -> bool {
    // C: `const char *fname = outs->filename; DEBUGASSERT(fname && *fname);`.
    // Capture the *original* name up front — the numbered fallback may reassign
    // `outs.filename`, but the failure warning must still report the original
    // (C keeps `fname` in a separate local for exactly this reason).
    let fname = match outs.filename.as_deref() {
        Some(name) if !name.is_empty() => name.to_owned(),
        _ => {
            debug_assert!(false, "create_output_file called with no/empty filename");
            return false;
        }
    };

    // C: clobber is allowed for CLOBBER_ALWAYS, or for CLOBBER_DEFAULT unless the
    // filename came from a Content-Disposition header.
    let clobber_allowed = config.file_clobber_mode == FileClobberMode::Always
        || (config.file_clobber_mode == FileClobberMode::Default && !outs.is_cd_filename);

    let opened: io::Result<File> = if clobber_allowed {
        // C: curlx_fopen(fname, "wb") — create/truncate/overwrite.
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&fname)
    } else {
        // C: curlx_open(fname, O_CREAT | O_WRONLY | O_EXCL, OPENMODE) — exclusive
        // create. Rust's default create mode is 0666 before umask, matching C's
        // POSIX OPENMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH); no
        // custom permissions are set. (EINTR is retried inside `open` by std, so
        // no manual retry loop is needed.)
        match OpenOptions::new().write(true).create_new(true).open(&fname) {
            Ok(file) => Ok(file),
            // CLOBBER_NEVER: retry with numbered suffixes while the target keeps
            // already existing (C's `errno == EEXIST || errno == EISDIR` guard).
            Err(err)
                if config.file_clobber_mode == FileClobberMode::Never
                    && err.kind() == io::ErrorKind::AlreadyExists =>
            {
                open_numbered_fallback(outs, &fname, err)
            }
            // CLOBBER_DEFAULT with a Content-Disposition name (or any other
            // error): C does not retry — `fd` stays -1 and the open fails.
            Err(err) => Err(err),
        }
    };

    match opened {
        Ok(file) => {
            // C:102-107 — record the freshly opened regular file.
            outs.regular_file = true;
            outs.fopened = true;
            outs.stream = Some(file);
            outs.bytes = 0;
            outs.init = 0;
            true
        }
        Err(err) => {
            // C:96-100 — `warnf("Failed to open the file %s: %s", fname,
            // strerror(errno))`. The OS message is `io::Error`'s `Display`.
            crate::warnf!(global, "Failed to open the file {fname}: {err}");
            false
        }
    }
}

/// `CLOBBER_NEVER` numbered fallback — port of `tool_cb_wrt.c:61-93`.
///
/// Tries `"{fname}.{n}"` for `n` in `1..100`, returning the first file that can
/// be created *exclusively*. On success, `outs.filename` is updated to the chosen
/// name — the `Option<String>` taking ownership is the Rust equivalent of C's
/// `outs->filename = <new>; outs->alloc_filename = TRUE;`.
///
/// Retrying continues only while a candidate already exists, mirroring C's
/// `errno == EEXIST` loop guard; any other error stops the search immediately.
/// (C also tests `EISDIR`, but `create_new` maps an existing path of *any* kind —
/// including a directory — to [`io::ErrorKind::AlreadyExists`], so that case is
/// already covered.) If all 99 names exist, the last "already exists" error is
/// returned so the caller emits curl's open-failure warning.
fn open_numbered_fallback(
    outs: &mut OutStruct,
    fname: &str,
    first_err: io::Error,
) -> io::Result<File> {
    let mut last_err = first_err;
    // C: `int next_num = 1; while(... next_num < 100) { ... next_num++; ... }`.
    let mut next_num = 1;
    while next_num < 100 {
        // C dynbuf `curlx_dyn_addf(&fbuffer, "%s.%d", fname, next_num)`.
        let candidate = format!("{fname}.{next_num}");
        next_num += 1;
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                outs.filename = Some(candidate);
                return Ok(file);
            }
            // Keep trying the next number while the candidate already exists.
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                last_err = err;
            }
            // Any other error aborts the search (matches C breaking the loop).
            Err(err) => return Err(err),
        }
    }
    Err(last_err)
}

// ===========================================================================
// Output-sink helpers — resolve `OutStruct` to its concrete writer.
//
// curl carries a single `FILE *stream`; `operate`'s Rust `OutStruct` models the
// same destination with an `Option<File>` plus a `to_stderr` flag: a held `File`
// is a regular file; otherwise `to_stderr` selects the process stderr; otherwise
// the destination is the process stdout (curl's default `outs->stream = stdout`).
// ===========================================================================

/// Writes the whole `buffer` to the sink described by `outs`, returning the
/// number of bytes accepted — the Rust analogue of `fwrite(buffer, 1, bytes,
/// stream)`.
///
/// curl's `fwrite` returns the item count, which `tool_write_cb` compares against
/// the byte count to detect a short write: on a full write it equals the input
/// length; on any failure it is smaller, which makes libcurl abort the transfer
/// with `CURLE_WRITE_ERROR`. This port preserves that *observable* contract: a
/// fully successful [`Write::write_all`] returns `buffer.len()`, and any error
/// returns `0` (`!= buffer.len()`), triggering the same abort. The exact partial
/// count on error is irrelevant — only equality with the input length is
/// observed by the caller.
fn write_to_sink(outs: &mut OutStruct, buffer: &[u8]) -> usize {
    let result = if let Some(file) = outs.stream.as_mut() {
        file.write_all(buffer)
    } else if outs.to_stderr {
        io::stderr().write_all(buffer)
    } else {
        io::stdout().write_all(buffer)
    };
    match result {
        Ok(()) => buffer.len(),
        Err(_) => 0,
    }
}

/// Flushes the sink described by `outs`, used for the `--no-buffer` path.
///
/// Mirrors C's `fflush(outs->stream)`; std retries the underlying `EINTR`
/// internally, so a single flush matches C's `do { } while(errno == EINTR)`
/// loop.
fn flush_sink(outs: &mut OutStruct) -> io::Result<()> {
    if let Some(file) = outs.stream.as_mut() {
        file.flush()
    } else if outs.to_stderr {
        io::stderr().flush()
    } else {
        io::stdout().flush()
    }
}

/// Flushes any buffered response headers to the body sink ahead of the first
/// body byte — port of `tool_write_headers` (`src/tool_cb_hdr.c:233`).
///
/// Returns `true` on a write failure (curl's `rc = 1`), which the caller maps to
/// `CURL_WRITEFUNC_ERROR`; `false` on success (curl's `rc = 0`). As in C, the
/// buffered header list is **always** consumed/cleared afterward, regardless of
/// outcome (curl's `curl_slist_free_all(headlist); headlist = NULL;`). On the
/// first short write the remaining lines are skipped (curl's `goto fail`).
///
/// The logic is inlined here — rather than calling into `callbacks/header.rs` —
/// because the header module is not among this file's permitted dependencies and
/// the documented dependency direction is header→write (header consumes this
/// module's exports), so calling back the other way would invert it.
fn write_buffered_headers(hdrcbdata: &mut HdrCbData, outs: &mut OutStruct) -> bool {
    let mut failed = false;
    for line in &hdrcbdata.headlist {
        // C compares `strlen(h->data)` against the `fwrite` return; the stored
        // bytes carry no trailing NUL, so the line length is the expectation.
        if write_to_sink(outs, line) != line.len() {
            failed = true; // C: `goto fail` (rc stays 1)
            break;
        }
    }
    // C always frees the list and nulls the pointer (the `fail:` label is reached
    // on both the success and failure paths).
    hdrcbdata.headlist.clear();
    failed
}

// ===========================================================================
// Body write callback — port of `tool_write_cb` (`src/tool_cb_wrt.c:240-363`).
// ===========================================================================

/// The `CURLOPT_WRITEFUNCTION` callback: consumes one chunk of received response
/// **body** for `per`, returning the number of bytes handled (or
/// [`CURL_WRITEFUNC_ERROR`] to abort the transfer).
///
/// This is the public entry point a future transfer integrator registers against
/// `curl_rs_lib`'s safe write-callback surface (which delivers body bytes as a
/// `&[u8]`). It is a thin shim that splits the disjoint pieces of `per` it needs
/// and forwards to [`write_body_impl`], which carries the full control flow and
/// is unit-testable without constructing an entire `PerTransfer`.
///
/// Unlike C's `tool_write_cb`, no `size`/`nmemb` pair is taken: the safe core
/// hands over the already-sized slice, so `buffer.len()` is curl's `sz * nmemb`.
/// As in curl, this never returns the *pause* sentinel — `tool_write_cb` does not
/// pause from the body path.
pub fn write_cb(buffer: &[u8], per: &mut PerTransfer, global: &mut GlobalConfig) -> usize {
    // Borrow the disjoint fields `write_body_impl` needs. `config_idx` is `Copy`;
    // `global` (a distinct argument) carries the owning `OperationConfig` at
    // `global.operations[config_idx]`, matching `operate`'s config-by-index model.
    write_body_impl(
        buffer,
        &mut per.outs,
        &mut per.hdrcbdata,
        &mut per.easy,
        per.config_idx,
        global,
    )
}

/// Core of the body write callback, operating on the individual pieces of state
/// rather than a whole `PerTransfer` so it can be exercised directly in tests.
///
/// The control-flow order mirrors `tool_write_cb` step for step; see the inline
/// comments tying each block to the C source lines.
fn write_body_impl(
    buffer: &[u8],
    outs: &mut OutStruct,
    hdrcbdata: &mut HdrCbData,
    easy: &mut curl_rs_lib::Easy,
    config_idx: usize,
    global: &mut GlobalConfig,
) -> usize {
    // C:246 — `size_t bytes = sz * nmemb;`. The safe slice is already sized.
    let bytes = buffer.len();

    // C:253-254 — discard everything when the sink is the null sink. MUST be the
    // first check so no other side effect (lazy open, guards) ever runs for it.
    if outs.out_null {
        return bytes;
    }

    // C:247 — `bool is_tty = global->isatty;`. Declared `mut` because the
    // debug-only `CURL_ISATTY` override below may force it on; the attribute
    // suppresses the unused-mut warning in release builds where that block is
    // compiled out.
    #[allow(unused_mut)]
    let mut is_tty = global.isatty;

    // C:256-306 — `#ifdef DEBUGBUILD` diagnostics. Gated to debug builds so the
    // release callback is byte-identical to curl's release build.
    #[cfg(debug_assertions)]
    {
        // C:257-263 — `CURL_ISATTY` forces tty treatment for tests.
        if std::env::var_os("CURL_ISATTY").is_some() {
            is_tty = true;
        }

        // C:265-276 — refuse oversized chunks. With `show_headers` the limit is
        // the header cap; otherwise the per-write cap.
        if global.operations[config_idx].show_headers {
            if bytes > CURL_MAX_HTTP_HEADER {
                crate::warnf!(&*global, "Header data size exceeds write limit");
                return CURL_WRITEFUNC_ERROR;
            }
        } else if bytes > CURL_MAX_WRITE_SIZE {
            crate::warnf!(&*global, "Data size exceeds write limit");
            return CURL_WRITEFUNC_ERROR;
        }

        // C:278-304 — internal congruency checks on the received `OutStruct`.
        let mut check_fails = false;
        match outs.filename.as_deref() {
            Some(name) => {
                // C:281-292 — a regular-file sink.
                if name.is_empty() {
                    check_fails = true;
                }
                if !outs.regular_file {
                    check_fails = true;
                }
                if outs.fopened && outs.stream.is_none() {
                    check_fails = true;
                }
                if !outs.fopened && outs.stream.is_some() {
                    check_fails = true;
                }
                if !outs.fopened && outs.bytes != 0 {
                    check_fails = true;
                }
            }
            None => {
                // C:294-300 — a standard stream (stdout/stderr). C also asserts
                // `outs->stream` is non-NULL, but in this model stdout/stderr are
                // represented by `stream == None` (no owned `File`), so that one
                // sub-check is intentionally dropped; the rest port verbatim.
                if outs.regular_file || outs.fopened {
                    check_fails = true;
                }
                if outs.alloc_filename || outs.is_cd_filename || outs.init != 0 {
                    check_fails = true;
                }
            }
        }
        if check_fails {
            crate::warnf!(&*global, "Invalid output struct data for write callback");
            return CURL_WRITEFUNC_ERROR;
        }
    }

    // C:308-309 — lazily create the output file on first write. C tests
    // `!outs->stream`; here a regular-file sink is "not yet open" when it has a
    // filename but no held `File` (stdout/stderr keep `filename == None`, so this
    // never fires for them — matching C, where stdout is a non-NULL stream).
    if outs.stream.is_none() && outs.filename.is_some() {
        // `outs` is disjoint from `global`; `&global.operations[config_idx]` and
        // `&*global` are two shared reborrows of `*global`, which may coexist.
        if !create_output_file(outs, &global.operations[config_idx], &*global) {
            return CURL_WRITEFUNC_ERROR;
        }
    }

    // C:311-320 — refuse binary output to a terminal early in a transfer, unless
    // the user opted in. `buffer.contains(&0)` is the safe analogue of
    // `memchr(buffer, 0, bytes)`.
    if is_tty
        && outs.bytes < 2000
        && !global.operations[config_idx].terminal_binary_ok
        && buffer.contains(&0)
    {
        // The wording, punctuation, and embedded quotes must match curl exactly.
        crate::warnf!(
            &*global,
            "Binary output can mess up your terminal. Use \"--output -\" to tell \
             curl to output it to your terminal anyway, or consider \"--output \
             <FILE>\" to save to a file."
        );
        global.operations[config_idx].synthetic_error = true;
        return CURL_WRITEFUNC_ERROR;
    }

    // C:333-337 — flush any buffered response headers before the first body byte.
    if !hdrcbdata.headlist.is_empty() && write_buffered_headers(hdrcbdata, outs) {
        return CURL_WRITEFUNC_ERROR;
    }

    // C:338 — `rc = fwrite(buffer, sz, nmemb, outs->stream);`.
    let rc = write_to_sink(outs, buffer);

    // C:341-343 — account only a fully successful write.
    if bytes == rc {
        outs.bytes += bytes as u64;
    }

    // C:345-348 — a successful write clears a prior "read busy" pause. curl
    // ignores `curl_easy_pause`'s return here; so do we (and with no connection
    // attached the core returns an error we deliberately drop).
    if global.operations[config_idx].readbusy {
        global.operations[config_idx].readbusy = false;
        let _ = easy.pause(CURLPAUSE_CONT);
    }

    // C:350-360 — with output buffering disabled, flush after every write.
    if global.operations[config_idx].nobuffer && flush_sink(outs).is_err() {
        return CURL_WRITEFUNC_ERROR;
    }

    // C:362 — report the bytes consumed.
    rc
}

// ===========================================================================
// Tests — exercise the control flow of the write callback and the output-file
// creation policy against curl's observable behavior. They use temp files for
// every sink that is actually written, so no test pollutes the process stdout
// (the only stdout-bound case, binary-output-to-terminal, refuses *before* any
// write).
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// Builds a fresh `GlobalConfig` with one operation block (index 0) — the
    /// shape `write_body_impl` expects (`global.operations[config_idx]`).
    fn global_with_one_op() -> GlobalConfig {
        GlobalConfig::new()
    }

    /// A disposable easy handle for the callback's `pause` argument. With no
    /// connection attached, `pause` returns an error the callback ignores.
    fn dummy_easy() -> curl_rs_lib::Easy {
        curl_rs_lib::Easy::new()
    }

    // ---- create_output_file ------------------------------------------------

    #[test]
    fn create_output_file_clobber_default_truncates() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("body.out");
        // Pre-seed with content that must be truncated away.
        fs::write(&path, b"stale contents").unwrap();

        let mut outs = OutStruct {
            filename: Some(path.to_str().unwrap().to_owned()),
            ..OutStruct::default()
        };
        // `global` is only read here (CLOBBER_DEFAULT is the derived default), so
        // it needs no `mut`.
        let global = global_with_one_op();
        // CLOBBER_DEFAULT (the derived default) + not a Content-Disposition name
        // => clobber allowed => truncate.
        assert_eq!(
            global.operations[0].file_clobber_mode,
            FileClobberMode::Default
        );

        let ok = create_output_file(&mut outs, &global.operations[0], &global);
        assert!(ok);
        assert!(outs.fopened);
        assert!(outs.regular_file);
        assert!(outs.stream.is_some());
        assert_eq!(outs.bytes, 0);
        assert_eq!(outs.init, 0);

        // Drop the handle to ensure the (truncated) file is closed, then verify
        // it is now empty.
        outs.stream = None;
        assert_eq!(fs::read(&path).unwrap(), b"");
    }

    #[test]
    fn create_output_file_clobber_never_uses_numbered_fallback() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("dl");
        let base_str = base.to_str().unwrap().to_owned();
        // The base name already exists, forcing the numbered fallback.
        fs::write(&base, b"existing").unwrap();

        let mut global = global_with_one_op();
        global.operations[0].file_clobber_mode = FileClobberMode::Never;

        // First no-clobber create -> "dl.1".
        let mut outs1 = OutStruct {
            filename: Some(base_str.clone()),
            ..OutStruct::default()
        };
        assert!(create_output_file(
            &mut outs1,
            &global.operations[0],
            &global
        ));
        assert_eq!(
            outs1.filename.as_deref(),
            Some(format!("{base_str}.1").as_str())
        );
        assert!(base.with_extension("1").exists() || dir.path().join("dl.1").exists());

        // Second no-clobber create with "dl" and "dl.1" present -> "dl.2".
        let mut outs2 = OutStruct {
            filename: Some(base_str.clone()),
            ..OutStruct::default()
        };
        assert!(create_output_file(
            &mut outs2,
            &global.operations[0],
            &global
        ));
        assert_eq!(
            outs2.filename.as_deref(),
            Some(format!("{base_str}.2").as_str())
        );
    }

    #[test]
    fn create_output_file_cd_name_no_clobber_fails_without_fallback() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cd.bin");
        fs::write(&path, b"keep me").unwrap();

        let mut outs = OutStruct {
            filename: Some(path.to_str().unwrap().to_owned()),
            // Content-Disposition-derived name under CLOBBER_DEFAULT => no clobber
            // AND no numbered fallback (fallback is CLOBBER_NEVER only).
            is_cd_filename: true,
            ..OutStruct::default()
        };
        let mut global = global_with_one_op();
        global.silent = true; // suppress the (expected) failure warning in tests

        let ok = create_output_file(&mut outs, &global.operations[0], &global);
        assert!(!ok);
        assert!(!outs.fopened);
        assert!(outs.stream.is_none());
        // The existing file is untouched, and no "cd.bin.1" was created.
        assert_eq!(fs::read(&path).unwrap(), b"keep me");
        assert!(!dir.path().join("cd.bin.1").exists());
    }

    #[test]
    fn create_output_file_open_failure_warns_and_returns_false() {
        // A path inside a non-existent directory cannot be created.
        let dir = tempdir().unwrap();
        let bad = dir.path().join("missing-subdir").join("file.out");

        let mut outs = OutStruct {
            filename: Some(bad.to_str().unwrap().to_owned()),
            ..OutStruct::default()
        };
        let mut global = global_with_one_op();
        global.silent = true; // suppress the (expected) failure warning

        assert!(!create_output_file(
            &mut outs,
            &global.operations[0],
            &global
        ));
        assert!(!outs.fopened);
        assert!(outs.stream.is_none());
    }

    // ---- write_buffered_headers -------------------------------------------

    #[test]
    fn write_buffered_headers_flushes_and_clears() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("withheaders.out");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();

        let mut outs = OutStruct {
            filename: Some(path.to_str().unwrap().to_owned()),
            stream: Some(file),
            regular_file: true,
            fopened: true,
            ..OutStruct::default()
        };
        let mut hdr = HdrCbData {
            headlist: vec![b"HTTP/1.1 200 OK\r\n".to_vec(), b"X-A: 1\r\n".to_vec()],
            ..HdrCbData::default()
        };

        let failed = write_buffered_headers(&mut hdr, &mut outs);
        assert!(!failed);
        // The list is always consumed, matching curl's free+null.
        assert!(hdr.headlist.is_empty());

        outs.stream = None; // close before reading back
        assert_eq!(fs::read(&path).unwrap(), b"HTTP/1.1 200 OK\r\nX-A: 1\r\n");
    }

    // ---- write_body_impl ---------------------------------------------------

    #[test]
    fn write_body_out_null_discards_without_opening() {
        let mut outs = OutStruct {
            out_null: true,
            ..OutStruct::default()
        };
        let mut hdr = HdrCbData::default();
        let mut easy = dummy_easy();
        let mut global = global_with_one_op();

        let payload = b"discard me";
        let rc = write_body_impl(payload, &mut outs, &mut hdr, &mut easy, 0, &mut global);
        // All bytes "consumed", but nothing opened or written.
        assert_eq!(rc, payload.len());
        assert!(outs.stream.is_none());
        assert!(!outs.fopened);
        assert_eq!(outs.bytes, 0);
    }

    #[test]
    fn write_body_writes_to_open_file_and_accounts_bytes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("body.dat");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();

        let mut outs = OutStruct {
            filename: Some(path.to_str().unwrap().to_owned()),
            stream: Some(file),
            regular_file: true,
            fopened: true,
            ..OutStruct::default()
        };
        let mut hdr = HdrCbData::default();
        let mut easy = dummy_easy();
        let mut global = global_with_one_op();

        let payload = b"hello body bytes";
        let rc = write_body_impl(payload, &mut outs, &mut hdr, &mut easy, 0, &mut global);
        assert_eq!(rc, payload.len());
        assert_eq!(outs.bytes, payload.len() as u64);

        outs.stream = None;
        assert_eq!(fs::read(&path).unwrap(), payload);
    }

    #[test]
    fn write_body_lazily_opens_named_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("lazy.out");
        let path_str = path.to_str().unwrap().to_owned();

        // A regular-file sink that has not been opened yet (stream == None) —
        // exactly the state `operate` sets up before the first write.
        let mut outs = OutStruct {
            filename: Some(path_str),
            regular_file: true,
            ..OutStruct::default()
        };
        let mut hdr = HdrCbData::default();
        let mut easy = dummy_easy();
        let mut global = global_with_one_op();

        assert!(!path.exists());
        let payload = b"lazily opened content";
        let rc = write_body_impl(payload, &mut outs, &mut hdr, &mut easy, 0, &mut global);
        assert_eq!(rc, payload.len());
        assert!(outs.fopened);
        assert!(outs.stream.is_some());

        outs.stream = None;
        assert_eq!(fs::read(&path).unwrap(), payload);
    }

    #[test]
    fn write_body_binary_to_terminal_is_refused() {
        // stdout sink (filename None, stream None) treated as a TTY.
        let mut outs = OutStruct::default();
        let mut hdr = HdrCbData::default();
        let mut easy = dummy_easy();
        let mut global = global_with_one_op();
        global.isatty = true;
        global.silent = true; // suppress the (expected) warning during tests
        global.operations[0].terminal_binary_ok = false;

        // Contains a NUL byte and we are early in the transfer (bytes < 2000) =>
        // the guard fires *before* any write reaches stdout.
        let payload = b"text\0binary";
        let rc = write_body_impl(payload, &mut outs, &mut hdr, &mut easy, 0, &mut global);
        assert_eq!(rc, CURL_WRITEFUNC_ERROR);
        assert!(global.operations[0].synthetic_error);
        // Nothing was opened; stdout was never written.
        assert!(outs.stream.is_none());
        assert_eq!(outs.bytes, 0);
    }

    #[test]
    fn write_body_binary_allowed_when_opted_in() {
        // With --output - style opt-in, binary to the terminal is permitted; to
        // avoid touching the real stdout we direct the sink at a temp file
        // instead (the guard is keyed on the flag, not the sink kind).
        let dir = tempdir().unwrap();
        let path = dir.path().join("bin.out");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();

        let mut outs = OutStruct {
            filename: Some(path.to_str().unwrap().to_owned()),
            stream: Some(file),
            regular_file: true,
            fopened: true,
            ..OutStruct::default()
        };
        let mut hdr = HdrCbData::default();
        let mut easy = dummy_easy();
        let mut global = global_with_one_op();
        global.isatty = true;
        global.operations[0].terminal_binary_ok = true;

        let payload = b"\0\x01\x02binary-ok";
        let rc = write_body_impl(payload, &mut outs, &mut hdr, &mut easy, 0, &mut global);
        assert_eq!(rc, payload.len());
        assert!(!global.operations[0].synthetic_error);

        outs.stream = None;
        assert_eq!(fs::read(&path).unwrap(), payload);
    }

    #[test]
    fn write_body_clears_readbusy_after_write() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("rb.out");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();

        let mut outs = OutStruct {
            filename: Some(path.to_str().unwrap().to_owned()),
            stream: Some(file),
            regular_file: true,
            fopened: true,
            ..OutStruct::default()
        };
        let mut hdr = HdrCbData::default();
        let mut easy = dummy_easy();
        let mut global = global_with_one_op();
        global.operations[0].readbusy = true;

        let payload = b"unpause please";
        let rc = write_body_impl(payload, &mut outs, &mut hdr, &mut easy, 0, &mut global);
        assert_eq!(rc, payload.len());
        // The successful write resets the busy-read flag (the pause call itself
        // is best-effort and its error is ignored).
        assert!(!global.operations[0].readbusy);
    }

    #[test]
    fn write_body_nobuffer_flushes_each_write() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nb.out");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();

        let mut outs = OutStruct {
            filename: Some(path.to_str().unwrap().to_owned()),
            stream: Some(file),
            regular_file: true,
            fopened: true,
            ..OutStruct::default()
        };
        let mut hdr = HdrCbData::default();
        let mut easy = dummy_easy();
        let mut global = global_with_one_op();
        global.operations[0].nobuffer = true;

        let payload = b"flushed";
        let rc = write_body_impl(payload, &mut outs, &mut hdr, &mut easy, 0, &mut global);
        // A valid file flushes cleanly; the bytes are visible immediately.
        assert_eq!(rc, payload.len());
        assert_eq!(fs::read(&path).unwrap(), payload);
    }

    #[test]
    fn write_body_flushes_headers_before_first_body_byte() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ordered.out");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();

        let mut outs = OutStruct {
            filename: Some(path.to_str().unwrap().to_owned()),
            stream: Some(file),
            regular_file: true,
            fopened: true,
            ..OutStruct::default()
        };
        let mut hdr = HdrCbData {
            headlist: vec![b"X-First: yes\r\n".to_vec()],
            ..HdrCbData::default()
        };
        let mut easy = dummy_easy();
        let mut global = global_with_one_op();

        let payload = b"the body";
        let rc = write_body_impl(payload, &mut outs, &mut hdr, &mut easy, 0, &mut global);
        assert_eq!(rc, payload.len());
        assert!(hdr.headlist.is_empty());

        outs.stream = None;
        // Header bytes precede the body bytes in the output.
        assert_eq!(fs::read(&path).unwrap(), b"X-First: yes\r\nthe body");
    }
}
