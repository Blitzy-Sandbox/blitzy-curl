// SPDX-License-Identifier: curl
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

//! CURLOPT_WRITEFUNCTION body writer + output-dir/create-dirs + clobber policy.
//!
//! Rust rewrite of curl 8.19.0-DEV `src/tool_cb_wrt.c`, absorbing `src/tool_dirhie.c` and
//! `src/tool_dirhie.h` (the header declared only `create_dir_hierarchy`, folded in here).
//!
//! This module owns the CLI's body-output path:
//!
//! * [`tool_write_cb`] — the `CURLOPT_WRITEFUNCTION` callback that streams received body
//!   bytes to a transfer's output sink, opening the destination file lazily on first write,
//!   refusing to splatter binary data onto a terminal, honoring `--no-buffer`, and unpausing
//!   a parked reader.
//! * [`tool_create_output_file`] — create/open the configured output file honoring the
//!   `--clobber` / `--no-clobber` policy (truncate, exclusive-create, or numbered `.N`).
//! * [`create_dir_hierarchy`] — create the directory hierarchy leading to an output file
//!   (`--create-dirs` / `--output-dir`), with curl's exact per-errno diagnostics.
//!
//! Behavioral parity is binding (AAP §0.7): the clobber and directory-hierarchy semantics,
//! and every `warnf`/`errorf` message, are byte-for-byte identical to curl 8.x.
//!
//! Windows (`_WIN32`), MS-DOS/DJGPP, and `DEBUGBUILD`-only code paths from the C sources are
//! intentionally dropped: the supported targets are the Linux and macOS tuples only
//! (AAP §0.2.2 / §0.6.5), and debug hooks are not carried forward (§0.7.3). Consequently the
//! only path separator is `/` and the file/dir open modes use the POSIX bit sets directly.

use core::ffi::{c_char, c_void};
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, BufWriter, ErrorKind};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use super::{userdata_mut, OutSink, OutStruct};
use crate::args::{ClobberMode, Diag, OperationConfig};
use crate::operate::{errorf, warnf};

use curl_rs_ffi::easy::{curl_easy_pause, CURLPAUSE_CONT, CURL_WRITEFUNC_ERROR};
use curl_rs_lib::CurlCode;

/// Creation mode for output files — curl's non-Windows `OPENMODE`
/// (`S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH`). The `_WIN32`
/// `_S_IREAD | _S_IWRITE` variant is dropped. The mode is subject to the process umask,
/// exactly as curl's `open`/`fopen` calls are.
const OPENMODE: u32 = 0o666;

/// Creation mode for directories created by [`create_dir_hierarchy`] — curl's `(mode_t)0000750`.
const DIRMODE: u32 = 0o750;

// ===========================================================================
// Output-file creation — port of `tool_create_output_file` (tool_cb_wrt.c:37-108).
// ===========================================================================

/// Create/open the configured local output file for writing, returning `true` on success.
///
/// A 1:1 port of curl's `tool_create_output_file` (`src/tool_cb_wrt.c:37-108`):
///
/// * `CLOBBER_ALWAYS`, and `CLOBBER_DEFAULT` for a name that did not come from a server
///   `Content-Disposition`/`Location` header, open the file truncating (curl's
///   `fopen(fname, "wb")`).
/// * Otherwise the file is created exclusively (curl's `O_CREAT | O_WRONLY | O_EXCL`),
///   retrying while the open is interrupted (`EINTR`).
/// * `CLOBBER_NEVER` additionally tries the numbered names `fname.1` … `fname.99` while the
///   collision keeps reporting `EEXIST`/`EISDIR`, remembering the last name tried.
///
/// On failure it emits curl's exact `"Failed to open the file %s: %s"` warning and returns
/// `false`; on success it records the opened stream and resets the byte/offset accounting.
///
/// The `diag` parameter carries the `--silent`/`--show-error` gating that curl's `warnf`
/// reads from the global config (this crate's emitters take it explicitly).
pub fn tool_create_output_file(diag: Diag, outs: &mut OutStruct, config: &OperationConfig) -> bool {
    // Delegate to the clobber-mode-parameterized opener so callers that hold only the clobber
    // policy — notably the live body sink in `operate.rs`, which streams to `per->outs` without
    // a back-reference to the whole `OperationConfig` — can open the lazily-created output file
    // through the identical code path.
    open_output_file(diag, outs, config.file_clobber_mode)
}

/// Create/open the configured output file honoring an explicit `--clobber`/`--no-clobber`
/// policy, returning `true` on success. This is the body of curl's `tool_create_output_file`
/// parameterized by [`ClobberMode`] instead of `&OperationConfig`, so the live transfer sink
/// (`operate.rs`, curl's `per->outs` open-on-first-write) can open a lazily-created output file
/// while holding only the clobber policy. [`tool_create_output_file`] is the thin
/// `&OperationConfig` wrapper retained for the existing callback callers; both share this
/// single implementation so the clobber and error-message semantics stay byte-identical.
pub(crate) fn open_output_file(
    diag: Diag,
    outs: &mut OutStruct,
    clobber_mode: ClobberMode,
) -> bool {
    // curl `DEBUGASSERT`s a present, non-empty filename; without one there is nothing to open.
    let fname = match outs.filename.clone() {
        Some(f) if !f.is_empty() => f,
        _ => return false,
    };

    let opened: io::Result<File> = if clobber_mode == ClobberMode::Always
        || (clobber_mode == ClobberMode::Default && !outs.is_cd_filename)
    {
        // Truncating overwrite (curl's `fopen(fname, "wb")`).
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(OPENMODE)
            .open(&fname)
    } else {
        // Exclusive create (curl's `O_CREAT | O_WRONLY | O_EXCL`), EINTR-retried.
        let mut file = open_exclusive(&fname);

        // CLOBBER_NEVER: on collision, retry with numbered suffixes `fname.1` … `fname.99`,
        // continuing only while the failure is `EEXIST`/`EISDIR` and the limit is not reached
        // (curl's numbered-retry `while` loop).
        if clobber_mode == ClobberMode::Never && file.is_err() {
            let mut next_num = 1;
            while file.is_err() && is_errno(&file, &[libc::EEXIST, libc::EISDIR]) && next_num < 100
            {
                let candidate = format!("{fname}.{next_num}");
                next_num += 1;
                file = open_exclusive(&candidate);
                // curl remembers the last-tried numbered name (whether or not it opened).
                outs.filename = Some(candidate);
                outs.alloc_filename = true;
            }
        }
        file
    };

    match opened {
        Ok(file) => {
            outs.regular_file = true;
            outs.fopened = true;
            outs.stream = OutSink::File(BufWriter::new(file));
            outs.bytes = 0;
            outs.init = 0;
            true
        }
        Err(e) => {
            // Message byte-exact with curl: "Failed to open the file %s: %s" (the second
            // `%s` is the OS error text, curl's `curlx_strerror(errno, …)`).
            warnf(diag, &format!("Failed to open the file {fname}: {e}"));
            false
        }
    }
}

/// Exclusive-create open (`O_CREAT | O_WRONLY | O_EXCL`, curl's `curlx_open`), retrying while
/// the syscall is interrupted (curl's `do { … } while(fd == -1 && errno == EINTR)`).
fn open_exclusive(path: &str) -> io::Result<File> {
    loop {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(OPENMODE)
            .open(path)
        {
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}

/// Whether the error carried by `result` is one of the given raw OS error numbers. Used to
/// reproduce curl's `errno == EEXIST || errno == EISDIR` numbered-retry guard against the
/// exact platform errno values (correct on both linux-gnu and apple-darwin).
fn is_errno(result: &io::Result<File>, wanted: &[i32]) -> bool {
    match result {
        Err(e) => match e.raw_os_error() {
            Some(code) => wanted.contains(&code),
            None => false,
        },
        Ok(_) => false,
    }
}

// ===========================================================================
// Directory hierarchy — port of `tool_dirhie.c` (create_dir_hierarchy + show_dir_errno).
// ===========================================================================

/// Emit curl's exact per-errno directory-creation diagnostic (`show_dir_errno`,
/// `src/tool_dirhie.c:36-71`). The wording is a user-visible parity surface, so each branch
/// matches curl byte-for-byte.
///
/// curl reads the global `errno` left by the failed `mkdir`; the equivalent here is the
/// thread-local OS error read via [`io::Error::last_os_error`]. It is invoked immediately
/// after the failing `mkdir` with no intervening syscall, so the error number is still the
/// one `mkdir` set.
fn show_dir_errno(diag: Diag, name: &str) {
    let msg = match io::Error::last_os_error().raw_os_error() {
        Some(libc::EACCES) => format!("You do not have permission to create {name}"),
        Some(libc::ENAMETOOLONG) => format!("The directory name {name} is too long"),
        Some(libc::EROFS) => format!("{name} resides on a read-only file system"),
        Some(libc::ENOSPC) => {
            format!("No space left on the file system that will contain the directory {name}")
        }
        Some(libc::EDQUOT) => {
            format!("Cannot create directory {name} because you exceeded your quota")
        }
        _ => format!("Error creating directory {name}"),
    };
    errorf(diag, &msg);
}

/// Create the directory hierarchy leading up to (but not including) the file component of
/// `outfile`, so that a multi-GET write such as
/// `curl "http://example.org/dir[1-5]/file[1-5].txt" -o "dir#1/file#2.txt"` creates every
/// `dir*` automatically. A 1:1 port of curl's `create_dir_hierarchy` (`src/tool_dirhie.c`).
///
/// Each iteration spans a run of leading separators (`strspn`) followed by a component
/// (`strcspn`); the trailing component is the file itself (nothing follows it) and is not
/// created. Each cumulative directory prefix is created with mode `0000750`. An already
/// existing directory (`EEXIST`) or a permission-denied component (`EACCES`) is tolerated so
/// traversal into a pre-existing tree can continue; any other errno prints curl's specific
/// per-errno message and yields [`CurlCode::WriteError`].
///
/// The only path separator on the supported targets is `/` (curl's `DIR_CHAR`); the
/// Windows/DJGPP `"\\/"` separator set and the `_WIN32`/`MSDOS` drive-letter skip are dropped.
pub fn create_dir_hierarchy(diag: Diag, outfile: &str) -> CurlCode {
    let bytes = outfile.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        // `strspn`: run of leading separators at the cursor.
        let seplen = bytes[i..].iter().take_while(|&&b| b == b'/').count();
        // `strcspn`: the following run of non-separators (the directory/file name).
        let complen = bytes[i + seplen..]
            .iter()
            .take_while(|&&b| b != b'/')
            .count();

        // curl: `if(!outfile[len + seplen]) break;` — when nothing follows this component it
        // is the file itself and must not be created as a directory.
        let end = i + seplen + complen;
        if end >= bytes.len() {
            break;
        }

        // The cumulative directory path so far. curl grows a `dynbuf` by appending the
        // "separators + name" slice each iteration; because those separators are part of
        // `outfile`, the accumulated buffer is exactly `outfile[..end]`.
        let dir = &outfile[..end];

        // Create this level with curl's mode 0000750. Tolerate EEXIST/EACCES (allow traversal
        // into an existing/unreadable-but-present tree); any other errno is fatal.
        if let Err(e) = DirBuilder::new().mode(DIRMODE).create(dir) {
            let errno = e.raw_os_error();
            if errno != Some(libc::EACCES) && errno != Some(libc::EEXIST) {
                show_dir_errno(diag, dir);
                return CurlCode::WriteError;
            }
        }

        i = end;
    }

    CurlCode::Ok
}

// ===========================================================================
// CURLOPT_WRITEFUNCTION callback — port of `tool_write_cb` (tool_cb_wrt.c:240-363).
// ===========================================================================

/// `CURLOPT_WRITEDATA` payload for [`tool_write_cb`].
///
/// In curl 8.x the write callback receives the whole `struct per_transfer` as its userdata
/// and reaches `per->outs`, `per->config`, `global->isatty`, `per->curl`, and
/// `per->hdrcbdata` through it. This crate's per-transfer record (`operate.rs`) references
/// its [`OperationConfig`] by index into `GlobalConfig.operations` and keeps no back-pointer
/// to the global config, so the exact inputs the write path needs are surfaced here as an
/// explicit payload assembled by the operation layer when it installs the callback (curl's
/// `curl_easy_setopt(curl, CURLOPT_WRITEDATA, per)`).
///
/// The pointers are non-owning: for the duration of a single callback invocation they alias
/// state owned by the live per-transfer/global config, exactly as curl's raw `per`/`global`
/// do. The payload therefore must outlive every write callback of its transfer.
#[allow(dead_code)] // constructed by the operation layer once the live write callback is wired
pub struct WriteData {
    /// The transfer's output sink and byte accounting (curl's `per->outs`).
    pub outs: *mut OutStruct,
    /// The driving operation's config (curl's `per->config`); mutated to raise
    /// `synthetic_error` and to clear `readbusy`.
    pub config: *mut OperationConfig,
    /// Whether the output is a terminal (curl's `global->isatty`).
    pub isatty: bool,
    /// Diagnostic gating captured from the global config, for the `warnf` emitter.
    pub diag: Diag,
    /// The easy handle, passed to `curl_easy_pause` on the `readbusy` unpause
    /// (curl's `per->curl`).
    pub curl: *mut c_void,
}

/// Callback for `CURLOPT_WRITEFUNCTION`: write received body bytes to the transfer's output
/// sink. A 1:1 port of curl's `tool_write_cb` (`src/tool_cb_wrt.c:240-363`), matching the
/// [`curl_write_callback`](curl_rs_ffi::easy::curl_write_callback) ABI so it can be installed
/// as a libcurl write function.
///
/// Sequence (mirroring curl): discard when the output is the bit-bucket (`out_null`); open the
/// output file lazily on the first write; refuse binary output to a terminal; write the body;
/// update the byte counter on a full write; unpause a reader parked on `readbusy`; and flush
/// after every write under `--no-buffer`.
///
/// The Windows console UTF-16 branch (`win_console`) and the entire `DEBUGBUILD` block
/// (the `CURL_ISATTY` override, the `CURL_MAX_HTTP_HEADER`/`CURL_MAX_WRITE_SIZE` limit checks,
/// and the `OutStruct` congruency checks) are dropped per AAP §0.2.2 (Linux/macOS only) and
/// §0.7.3 (debug hooks not carried forward).
///
/// # Safety
/// `buffer` must point to `sz * nmemb` readable bytes, and `userdata` must be a valid, live
/// [`WriteData`] previously handed to libcurl via `CURLOPT_WRITEDATA`, per the libcurl
/// write-callback contract.
#[allow(dead_code)] // installed by the operation layer once the live transfer loop is wired
pub unsafe extern "C" fn tool_write_cb(
    buffer: *mut c_char,
    sz: usize,
    nmemb: usize,
    userdata: *mut c_void,
) -> usize {
    // SAFETY: per the CURLOPT_WRITEDATA contract, `userdata` is a valid, uniquely-borrowed
    // `WriteData` for the duration of this call (single-threaded CLI runtime).
    let data = match unsafe { userdata_mut::<WriteData>(userdata) } {
        Some(d) => d,
        None => return CURL_WRITEFUNC_ERROR,
    };
    // SAFETY: `data.outs` aliases the live per-transfer output struct, valid and uniquely
    // borrowed for this call (the payload outlives the callback, per its contract).
    let outs = unsafe { &mut *data.outs };
    // SAFETY: `data.config` aliases the live OperationConfig, valid and uniquely borrowed for
    // this call.
    let config = unsafe { &mut *data.config };
    let diag = data.diag;
    let is_tty = data.isatty;
    let bytes = sz * nmemb;

    // Discard sink (`out_null`): count the bytes as consumed but write nothing.
    if outs.out_null {
        return bytes;
    }

    // Open the output file lazily on the first write (curl opens it here when `stream` is
    // still NULL). A failure to open aborts the transfer.
    if !outs.stream.is_open() && !tool_create_output_file(diag, outs, config) {
        return CURL_WRITEFUNC_ERROR;
    }

    // SAFETY: the write-callback contract guarantees `buffer` covers `bytes` readable bytes.
    let buf = unsafe { core::slice::from_raw_parts(buffer as *const u8, bytes) };

    // Refuse to splatter binary data onto a terminal (curl's guard). The message is a single
    // concatenated string, byte-exact with curl.
    if is_tty && outs.bytes < 2000 && !config.terminal_binary_ok && buf.contains(&0u8) {
        warnf(diag, "Binary output can mess up your terminal. Use \"--output -\" to tell curl to output it to your terminal anyway, or consider \"--output <FILE>\" to save to a file.");
        config.synthetic_error = true;
        return CURL_WRITEFUNC_ERROR;
    }

    // NOTE(parity): curl flushes `per->hdrcbdata.headlist` through `tool_write_headers` here,
    // emitting any pending response headers to the same sink before the body (the `-i` /
    // `--include` interleave). The header-callback module (`callbacks/header.rs`, curl's
    // `src/tool_cb_hdr.c`) is authored after this file and is not yet present, so that flush
    // is wired when that module and its `HdrCbData` land. The body output below is unaffected.

    // Write the body. curl's `fwrite` returns the item count; for CURLOPT_WRITEFUNCTION
    // `sz == 1`, so a full write yields `nmemb`. A write error yields a short count (0) so
    // libcurl detects the failure via `rc != bytes`.
    let rc = match outs.stream.write_all(buf) {
        Ok(_) => nmemb,
        Err(_) => 0,
    };

    if bytes == rc {
        // We added this amount of data to the output.
        outs.bytes += bytes as i64;
    }

    // Unpause a reader that was parked because input returned EAGAIN (curl's `readbusy`).
    if config.readbusy {
        config.readbusy = false;
        // SAFETY: `data.curl` is the easy handle for this transfer, valid for the call; the
        // return value is advisory and ignored exactly as curl ignores it here.
        let _ = unsafe { curl_easy_pause(data.curl, CURLPAUSE_CONT) };
    }

    // `--no-buffer`: flush after every write, retrying while interrupted (curl's fflush loop).
    if config.nobuffer {
        loop {
            match outs.stream.flush() {
                Ok(()) => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return CURL_WRITEFUNC_ERROR,
            }
        }
    }

    rc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::{ClobberMode, Diag, OperationConfig};
    use std::io::Read;
    use std::path::Path;

    fn qdiag() -> Diag {
        // Silent so the parity `warnf`/`errorf` messages do not pollute test output; the
        // logic under test is independent of whether the diagnostic is printed.
        Diag {
            silent: true,
            showerror: false,
            tracing: false,
        }
    }

    #[test]
    fn create_output_file_truncating_opens_and_streams() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.bin");
        let mut outs = OutStruct {
            filename: Some(path.to_string_lossy().into_owned()),
            ..OutStruct::default()
        };
        let mut config = OperationConfig::new();
        config.file_clobber_mode = ClobberMode::Always;

        assert!(tool_create_output_file(qdiag(), &mut outs, &config));
        assert!(
            outs.regular_file,
            "a real file must be flagged regular_file"
        );
        assert!(outs.fopened, "we opened it, so fopened must be set");
        assert!(outs.stream.is_open());
        assert_eq!(outs.bytes, 0);

        // The returned sink must actually write to the created path.
        outs.stream.write_all(b"payload").unwrap();
        outs.stream.flush().unwrap();
        drop(outs.stream);
        let mut got = String::new();
        File::open(&path).unwrap().read_to_string(&mut got).unwrap();
        assert_eq!(got, "payload");
    }

    #[test]
    fn create_output_file_empty_or_missing_name_fails() {
        let config = OperationConfig::new();
        // Absent filename.
        let mut none = OutStruct::default();
        assert!(!tool_create_output_file(qdiag(), &mut none, &config));
        // Present-but-empty filename (curl DEBUGASSERTs a non-empty name).
        let mut empty = OutStruct {
            filename: Some(String::new()),
            ..OutStruct::default()
        };
        assert!(!tool_create_output_file(qdiag(), &mut empty, &config));
    }

    #[test]
    fn create_output_file_open_failure_returns_false() {
        // A path inside a directory that does not exist cannot be created -> Err -> false.
        let dir = tempfile::tempdir().unwrap();
        let bogus = dir.path().join("no_such_subdir").join("file.out");
        let mut outs = OutStruct {
            filename: Some(bogus.to_string_lossy().into_owned()),
            ..OutStruct::default()
        };
        let mut config = OperationConfig::new();
        config.file_clobber_mode = ClobberMode::Always;
        assert!(!tool_create_output_file(qdiag(), &mut outs, &config));
        assert!(!outs.stream.is_open());
    }

    #[test]
    fn create_output_file_never_mode_uses_numbered_suffix_on_collision() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("dl");
        // Pre-create the target so exclusive-create collides and the numbered retry kicks in.
        File::create(&target).unwrap();
        let base = target.to_string_lossy().into_owned();

        let mut outs = OutStruct {
            filename: Some(base.clone()),
            ..OutStruct::default()
        };
        let mut config = OperationConfig::new();
        config.file_clobber_mode = ClobberMode::Never;

        assert!(tool_create_output_file(qdiag(), &mut outs, &config));
        // curl records the numbered name it actually opened; first free is `dl.1`.
        let used = outs.filename.clone().unwrap();
        assert_eq!(
            used,
            format!("{base}.1"),
            "must fall back to the `.1` suffix"
        );
        assert!(
            outs.alloc_filename,
            "a generated name is owned/alloc_filename"
        );
        assert!(
            Path::new(&used).exists(),
            "the numbered file must exist on disk"
        );
        assert!(outs.fopened);
    }

    #[test]
    fn is_errno_matches_only_requested_codes() {
        let eexist: io::Result<File> = Err(io::Error::from_raw_os_error(libc::EEXIST));
        assert!(is_errno(&eexist, &[libc::EEXIST, libc::EISDIR]));
        assert!(!is_errno(&eexist, &[libc::ENOENT]));
        // A success carries no errno.
        let dir = tempfile::tempdir().unwrap();
        let ok: io::Result<File> = File::create(dir.path().join("x"));
        assert!(!is_errno(&ok, &[libc::EEXIST]));
    }

    #[test]
    fn create_dir_hierarchy_builds_nested_dirs_but_not_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_string_lossy().into_owned();
        let outfile = format!("{root}/a/b/c/file.txt");

        assert!(matches!(
            create_dir_hierarchy(qdiag(), &outfile),
            CurlCode::Ok
        ));
        assert!(Path::new(&format!("{root}/a")).is_dir());
        assert!(Path::new(&format!("{root}/a/b")).is_dir());
        assert!(Path::new(&format!("{root}/a/b/c")).is_dir());
        // The trailing component is the file itself and must NOT be created.
        assert!(!Path::new(&outfile).exists());
    }

    #[test]
    fn create_dir_hierarchy_with_no_directory_component_is_noop_ok() {
        // A bare filename (no `/`) has only a trailing file component -> nothing to create.
        assert!(matches!(
            create_dir_hierarchy(qdiag(), "just_a_file.txt"),
            CurlCode::Ok
        ));
        assert!(!Path::new("just_a_file.txt").exists());
    }

    #[test]
    fn create_dir_hierarchy_tolerates_preexisting_dirs() {
        // The tempdir root already exists; every prefix up to it is EEXIST-tolerated.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_string_lossy().into_owned();
        let outfile = format!("{root}/only.txt");
        assert!(matches!(
            create_dir_hierarchy(qdiag(), &outfile),
            CurlCode::Ok
        ));
    }

    // -----------------------------------------------------------------------
    // tool_write_cb — the CURLOPT_WRITEFUNCTION body sink. These drive the raw
    // C-ABI callback directly (a `WriteData` behind a `*mut c_void`, exactly as
    // libcurl invokes it) to cover the body-output path wired for QA F8 Issue 1.
    // sz == 1 per the CURLOPT_WRITEFUNCTION contract, so bytes == nmemb.
    // -----------------------------------------------------------------------

    /// Invoke `tool_write_cb` with a byte payload and a mutable `WriteData` context.
    fn call_write_cb(buf: &mut [u8], wd: &mut WriteData) -> usize {
        // SAFETY: `buf` is a live slice for the call; `wd` is a valid, uniquely-borrowed
        // WriteData whose `outs`/`config` pointers outlive this invocation — the exact
        // contract libcurl upholds when it calls the write callback.
        unsafe {
            tool_write_cb(
                buf.as_mut_ptr() as *mut c_char,
                1,
                buf.len(),
                wd as *mut WriteData as *mut c_void,
            )
        }
    }

    #[test]
    fn write_cb_null_userdata_signals_error() {
        // A null CURLOPT_WRITEDATA must fail the callback without dereferencing the buffer.
        let rc = unsafe { tool_write_cb(core::ptr::null_mut(), 1, 4, core::ptr::null_mut()) };
        assert_eq!(rc, CURL_WRITEFUNC_ERROR);
    }

    #[test]
    fn write_cb_out_null_counts_but_discards() {
        // The discard sink (`--output /dev/null` bit-bucket) consumes the bytes and writes
        // nothing: it returns the full count yet never opens a stream or advances `bytes`.
        let mut outs = OutStruct {
            out_null: true,
            ..OutStruct::default()
        };
        let mut config = OperationConfig::new();
        let mut wd = WriteData {
            outs: &mut outs,
            config: &mut config,
            isatty: false,
            diag: qdiag(),
            curl: core::ptr::null_mut(),
        };
        let mut buf = b"discarded".to_vec();
        let rc = call_write_cb(&mut buf, &mut wd);
        assert_eq!(rc, buf.len(), "out_null must report all bytes consumed");
        assert!(!outs.stream.is_open(), "out_null must not open a stream");
        assert_eq!(outs.bytes, 0, "out_null must not accumulate bytes");
    }

    #[test]
    fn write_cb_lazily_opens_file_and_streams_body() {
        // The normal path: the destination is opened on first write, the payload lands in the
        // file, and `bytes` advances by the write count (curl returns `nmemb`).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("body.out");
        let mut outs = OutStruct {
            filename: Some(path.to_string_lossy().into_owned()),
            ..OutStruct::default()
        };
        let mut config = OperationConfig::new();
        config.file_clobber_mode = ClobberMode::Always;

        let mut buf = b"hello body".to_vec();
        let expected = buf.len();
        {
            let mut wd = WriteData {
                outs: &mut outs,
                config: &mut config,
                isatty: false,
                diag: qdiag(),
                curl: core::ptr::null_mut(),
            };
            let rc = call_write_cb(&mut buf, &mut wd);
            assert_eq!(rc, expected, "a full write returns nmemb");
        }
        assert!(outs.stream.is_open(), "the file must have been opened");
        assert_eq!(outs.bytes, expected as i64, "bytes must track the write");
        // Flush the BufWriter and confirm the payload actually reached disk.
        outs.stream.flush().unwrap();
        let mut got = String::new();
        File::open(&path).unwrap().read_to_string(&mut got).unwrap();
        assert_eq!(got, "hello body");
    }

    #[test]
    fn write_cb_refuses_binary_on_terminal() {
        // curl's guard: binary bytes (a NUL) to a terminal, before 2000 bytes, without
        // --output-binary, are refused with a synthetic error rather than splattered.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("term.out");
        let mut outs = OutStruct {
            filename: Some(path.to_string_lossy().into_owned()),
            ..OutStruct::default()
        };
        let mut config = OperationConfig::new();
        config.file_clobber_mode = ClobberMode::Always;
        // Pre-open the sink so the lazy-open is skipped and the binary guard is what fires.
        assert!(tool_create_output_file(qdiag(), &mut outs, &config));

        let mut buf = vec![b'A', 0u8, b'B'];
        {
            let mut wd = WriteData {
                outs: &mut outs,
                config: &mut config,
                isatty: true,
                diag: qdiag(),
                curl: core::ptr::null_mut(),
            };
            let rc = call_write_cb(&mut buf, &mut wd);
            assert_eq!(rc, CURL_WRITEFUNC_ERROR, "binary-to-tty must error");
        }
        assert!(
            config.synthetic_error,
            "the guard must raise the synthetic-error marker"
        );
        assert_eq!(outs.bytes, 0, "no bytes are written when the guard fires");
    }

    #[test]
    fn write_cb_allows_binary_on_terminal_when_opted_in() {
        // With `--output-binary` (terminal_binary_ok) the same NUL-bearing payload is written.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("term_ok.out");
        let mut outs = OutStruct {
            filename: Some(path.to_string_lossy().into_owned()),
            ..OutStruct::default()
        };
        let mut config = OperationConfig::new();
        config.file_clobber_mode = ClobberMode::Always;
        config.terminal_binary_ok = true;

        let mut buf = vec![b'A', 0u8, b'B'];
        let expected = buf.len();
        {
            let mut wd = WriteData {
                outs: &mut outs,
                config: &mut config,
                isatty: true,
                diag: qdiag(),
                curl: core::ptr::null_mut(),
            };
            let rc = call_write_cb(&mut buf, &mut wd);
            assert_eq!(rc, expected, "opted-in binary write returns nmemb");
        }
        assert!(!config.synthetic_error, "no synthetic error when opted in");
        assert_eq!(outs.bytes, expected as i64);
    }
}
