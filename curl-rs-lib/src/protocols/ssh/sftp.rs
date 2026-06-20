//! SFTP protocol engine.
//!
//! This module implements the SFTP "DO" phase of a transfer — file download
//! and upload, directory listing, RANGE / resume, the `--ftp-create-dirs`
//! equivalent (recursive remote directory creation on upload), and the SFTP
//! QUOTE / POSTQUOTE pseudo-commands. It is the safe-Rust replacement for the
//! SFTP code paths in the C oracle `lib/vssh/libssh2.c` (and corroborated by
//! `lib/vssh/libssh.c`); the C is consumed strictly as a behavioral oracle and
//! is never transliterated line-by-line (AAP §0.3.2).
//!
//! # Architecture
//!
//! `sftp.rs` is a child module of [`super`] (`ssh/mod.rs`). The SSH transport,
//! host-key verification, user authentication and the connection lifecycle all
//! live in `mod.rs`; the [`SftpHandler`](super::SftpHandler) delegates the SFTP
//! subsystem start to [`init_subsystem`] and each request to [`do_it`] /
//! [`done`]. This module consumes the live [`russh_sftp::client::SftpSession`]
//! (built on `russh-sftp`) stored on the per-connection [`super::SshConn`], plus
//! the shared path/range helpers [`super::get_working_path`],
//! [`super::get_pathname`] and [`super::ssh_range`].
//!
//! # Data plane (important)
//!
//! Every libssh2 `EAGAIN` / non-blocking state re-entry in the C oracle
//! collapses here into a straight `.await`: we model the *sequence* and the
//! *decisions*, not the runtime state machine. SFTP file bytes flow over the
//! `russh-sftp` file handle (which rides the encrypted SSH transport owned by
//! `russh`), **not** over the raw connection socket — mirroring the C handler
//! overriding `conn->recv`/`conn->send` with `sftp_recv`/`sftp_send`. Because
//! the end-to-end transfer engine (`easy::perform`) is not yet wired, the DO
//! phase is performed inline here, delivering downloaded bytes through a
//! [`WriteCallbacks`] sink and pulling upload bytes from a [`ReadCallback`]
//! source — the same staging used by the sibling `telnet` engine, where the
//! default seam reads/writes the process standard streams until the FFI
//! write/read-callback bridge is plumbed. The byte pumps are factored as
//! standalone async helpers taking `&mut dyn WriteCallbacks` / `&mut dyn
//! ReadCallback` so they are unit-testable with in-memory sinks.
//!
//! # Memory safety
//!
//! This module contains zero `unsafe`. The crate-wide `#![forbid(unsafe_code)]`
//! is inherited from `lib.rs` / `protocols/mod.rs`; it is intentionally NOT
//! re-declared here (AAP §0.7.1). `russh-sftp` is a safe async API.

use std::io::SeekFrom;

use russh_sftp::client::error::Error as SftpError;
use russh_sftp::client::SftpSession;
use russh_sftp::extensions::Statvfs;
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

use super::{get_pathname, get_working_path, ssh_range, SshConn};
use crate::conn::Connection;
use crate::easy::Easy;
use crate::error::{CurlError, Result};
use crate::protocols::{ProtocolTransfer, TransferDirection};
use crate::setopt::{HttpReq, StrId};
use crate::slist::SList;
use crate::transfer::{ReadCallback, ReadStep, UploadReader, WriteCallbacks};
use crate::util::parsedate::getdate_capped;
use crate::util::sendf;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Chunk size for the download read loop (bytes pulled from the SFTP file
/// handle per `.await`). A 16 KiB window mirrors curl's default transfer buffer
/// granularity closely enough for parity while keeping per-call overhead low.
const SFTP_RECV_CHUNK: usize = 16 * 1024;

/// Chunk size for the upload read loop (bytes pulled from the read callback per
/// iteration before being written to the SFTP file handle).
const SFTP_SEND_CHUNK: usize = 16 * 1024;

/// Scratch buffer size for the resume read-and-discard fallback, matching the C
/// `char scratch[4 * 1024]` in `sftp_upload_init`.
const RESUME_SCRATCH: usize = 4 * 1024;

/// POSIX `S_IFMT` — the bit mask that isolates the file-type field of a Unix
/// mode word. Used to detect symlinks in a directory listing exactly as the C
/// oracle does (`(permissions & S_IFMT) == S_IFLNK`).
const S_IFMT: u32 = 0o170_000;
/// POSIX `S_IFLNK` — symbolic link file type.
const S_IFLNK: u32 = 0o120_000;
/// POSIX `S_IFDIR` — directory file type.
const S_IFDIR: u32 = 0o040_000;
/// POSIX `S_IFREG` — regular file type.
const S_IFREG: u32 = 0o100_000;
/// POSIX `S_IFCHR` — character device.
const S_IFCHR: u32 = 0o020_000;
/// POSIX `S_IFBLK` — block device.
const S_IFBLK: u32 = 0o060_000;
/// POSIX `S_IFIFO` — FIFO / named pipe.
const S_IFIFO: u32 = 0o010_000;
/// POSIX `S_IFSOCK` — socket.
const S_IFSOCK: u32 = 0o140_000;

// ---------------------------------------------------------------------------
// Error mapping (mirrors `sftp_libssh2_strerror` + `sftp_libssh2_error_to_CURLE`)
// ---------------------------------------------------------------------------

/// Extract the SFTP protocol status code from a `russh-sftp` error, if the error
/// originated from a server status packet. Non-status errors (I/O, timeout,
/// unexpected packet, …) return [`None`] — the C analog being a non-SFTP-protocol
/// libssh2 error, for which `sftperr` is `LIBSSH2_FX_OK`.
fn sftp_status_code(err: &SftpError) -> Option<StatusCode> {
    match err {
        SftpError::Status(status) => Some(status.status_code),
        _ => None,
    }
}

/// Human-readable SFTP error string, byte-for-byte identical to the C
/// `sftp_libssh2_strerror` table. Embedded verbatim into the `failf` diagnostics
/// so error output matches curl. Codes that `russh-sftp`'s [`StatusCode`] does
/// not model (the SFTP v4+ extended codes 9–21) cannot occur on this v3 client
/// and therefore need no entry; anything unmodeled falls through to the C
/// default string.
fn sftp_strerror(code: Option<StatusCode>) -> &'static str {
    match code {
        Some(StatusCode::NoSuchFile) => "No such file or directory",
        Some(StatusCode::PermissionDenied) => "Permission denied",
        Some(StatusCode::Failure) => "Operation failed",
        Some(StatusCode::BadMessage) => "Bad message from SFTP server",
        Some(StatusCode::NoConnection) => "Not connected to SFTP server",
        Some(StatusCode::ConnectionLost) => "Connection to SFTP server lost",
        Some(StatusCode::OpUnsupported) => "Operation not supported by SFTP server",
        // LIBSSH2_FX_OK and SSH_FX_EOF have no strerror case in the C table and
        // fall through to the default, as do all non-status errors.
        _ => "Unknown error in libssh2",
    }
}

/// Map a `russh-sftp` error to the matching [`CurlError`], mirroring
/// `sftp_libssh2_error_to_CURLE`. This is intentionally richer than
/// [`super::map_sftp_err`] so the upload create-dirs path can distinguish the
/// "missing path" status codes that trigger remote directory creation.
///
/// `russh-sftp`'s [`StatusCode`] models only SFTP v3 (codes 0–8), so the C
/// branches for `NO_SPACE_ON_FILESYSTEM`/`QUOTA_EXCEEDED` (→ disk full),
/// `FILE_ALREADY_EXISTS` (→ file exists) and `DIR_NOT_EMPTY` (→ quote error)
/// are not reachable as distinct codes — a v3 server reports them as
/// `Failure`, which maps to [`CurlError::Ssh`] just like the C default branch.
fn map_sftp_status(err: &SftpError) -> CurlError {
    match sftp_status_code(err) {
        Some(StatusCode::NoSuchFile) => CurlError::RemoteFileNotFound,
        Some(StatusCode::PermissionDenied) => CurlError::RemoteAccessDenied,
        // Ok/Eof/Failure/BadMessage/NoConnection/ConnectionLost/OpUnsupported and
        // all non-status errors collapse to the SSH-layer error (C default).
        _ => CurlError::Ssh,
    }
}

/// `true` when an open failure denotes a missing path that should trigger the
/// `--ftp-create-dirs` remote-directory-creation retry. The C condition is
/// `sftperr ∈ {NO_SUCH_FILE, FAILURE, NO_SUCH_PATH}`; on a v3 `russh-sftp`
/// client the reachable subset is `{NoSuchFile, Failure}` (NO_SUCH_PATH, code
/// 10, is reported as `Failure`).
fn is_missing_path_error(err: &SftpError) -> bool {
    matches!(
        sftp_status_code(err),
        Some(StatusCode::NoSuchFile) | Some(StatusCode::Failure)
    )
}

// ---------------------------------------------------------------------------
// Pure helper: upload open-flag selection (mirrors `sftp_upload_init`)
// ---------------------------------------------------------------------------

/// Choose the SFTP open flags for an upload, reproducing the exact precedence in
/// the C `sftp_upload_init`:
///
/// * remote append (`CURLOPT_APPEND`) → `WRITE | CREATE | APPEND`;
/// * else a positive resume offset → `WRITE` only — deliberately **without**
///   `APPEND`, because some servers force writes to EOF when `APPEND` is set,
///   ignoring a prior seek;
/// * else (the normal case) → `WRITE | CREATE | TRUNCATE` (clear before write).
///
/// `resume_from` is the effective resume offset (a negative value has already
/// been resolved to a concrete offset by the caller before the open).
fn select_upload_flags(remote_append: bool, resume_from: i64) -> OpenFlags {
    if remote_append {
        OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::APPEND
    } else if resume_from > 0 {
        OpenFlags::WRITE
    } else {
        OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE
    }
}

// ---------------------------------------------------------------------------
// Pure helper: download size / seek / resume plan (mirrors `sftp_download_stat`)
// ---------------------------------------------------------------------------

/// The computed layout of a download: where to seek the remote handle, how many
/// bytes to transfer, and whether the request is already satisfied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DownloadPlan {
    /// Absolute offset to seek the SFTP file handle to before reading.
    seek_from: u64,
    /// Maximum number of bytes to download: `-1` when the size is unknown
    /// (transfer until EOF), `0` when nothing remains ("already downloaded"),
    /// or a positive exact byte count.
    maxdownload: i64,
    /// `true` when [`Self::maxdownload`] is `0` — the C "no data to transfer"
    /// short-circuit that emits "File already completely downloaded".
    already_done: bool,
}

/// Compute the download layout from the server-reported size, the optional
/// RANGE specification and the resume offset, faithfully reproducing the
/// branching of `sftp_download_stat`.
///
/// `stat_size` is `None` when the stat failed, the server omitted the size
/// attribute, or the size was reported as `0` — in all three cases the C treats
/// the size as unknown (`req.size = -1`) and zeroes `attrs.filesize` for the
/// resume arithmetic below.
///
/// Errors:
/// * [`CurlError::RangeError`] — a malformed RANGE (propagated from
///   [`super::ssh_range`]);
/// * [`CurlError::BadDownloadResume`] — a resume offset beyond the file size.
///
/// The function is deliberately free of `failf`/network effects so it is
/// unit-testable; the caller emits the matching diagnostic on error.
fn compute_download_plan(
    stat_size: Option<u64>,
    use_range: bool,
    range: Option<&str>,
    resume_from: i64,
) -> Result<DownloadPlan> {
    // `attrs.filesize` in C: the real size when known, else 0.
    let attrs_filesize: i64 = stat_size
        .map(|s| i64::try_from(s).unwrap_or(i64::MAX))
        .unwrap_or(0);

    let mut seek_from: i64 = 0;
    let mut maxdownload: i64;

    if let Some(sz) = stat_size {
        let mut size = i64::try_from(sz).unwrap_or(i64::MAX);
        if use_range {
            if let Some(r) = range {
                let (from, rsize) = ssh_range(r, sz)?;
                seek_from = i64::try_from(from).unwrap_or(i64::MAX);
                size = i64::try_from(rsize).unwrap_or(i64::MAX);
            }
        }
        maxdownload = size;
    } else {
        // Unknown size: download until EOF.
        maxdownload = -1;
    }

    // Resume handling uses `attrs_filesize` (0 when the size is unknown, which
    // makes any resume offset "beyond file size" → error, exactly as in C).
    if resume_from != 0 {
        let mut rf = resume_from;
        if rf < 0 {
            // Download the last abs(rf) bytes.
            if attrs_filesize < -rf {
                return Err(CurlError::BadDownloadResume);
            }
            rf += attrs_filesize;
        } else if attrs_filesize < rf {
            return Err(CurlError::BadDownloadResume);
        }
        maxdownload = attrs_filesize - rf;
        seek_from = rf;
    }

    let already_done = maxdownload == 0;
    Ok(DownloadPlan {
        seek_from: u64::try_from(seek_from).unwrap_or(0),
        maxdownload,
        already_done,
    })
}

// ---------------------------------------------------------------------------
// Pure helper: `ls -l`-style long-entry synthesis (directory listing)
// ---------------------------------------------------------------------------

// NOTE (russh-sftp API limitation): the high-level `ReadDir` iterator discards
// the server-provided `longname` (the pre-formatted `ls -l` line that the C
// libssh2 backend forwards verbatim). We therefore reconstruct an equivalent
// long-format line from the SFTP attributes. This is a documented divergence
// from the C oracle: the synthesized line is faithful in structure to the
// common OpenSSH `sftp-server` format but cannot be byte-identical to an
// arbitrary server's `longname`. The list-only (names) path is exact.

/// The single file-type character that opens an `ls -l` mode field.
fn type_char(mode: u32) -> char {
    match mode & S_IFMT {
        S_IFDIR => 'd',
        S_IFLNK => 'l',
        S_IFREG => '-',
        S_IFCHR => 'c',
        S_IFBLK => 'b',
        S_IFIFO => 'p',
        S_IFSOCK => 's',
        _ => '-',
    }
}

/// Render the nine-character `rwxrwxrwx` permission triplet of an `ls -l` line,
/// honoring the setuid/setgid (`s`/`S`) and sticky (`t`/`T`) bits exactly as
/// `ls` does.
fn perm_rwx(mode: u32) -> String {
    let mut s = String::with_capacity(9);
    let bit = |mask: u32| (mode & mask) != 0;
    let special = |exec: bool, sp: bool, set: char, unset: char| match (exec, sp) {
        (true, true) => set.to_ascii_lowercase(),
        (false, true) => set.to_ascii_uppercase(),
        (true, false) => unset,
        (false, false) => '-',
    };
    s.push(if bit(0o400) { 'r' } else { '-' });
    s.push(if bit(0o200) { 'w' } else { '-' });
    s.push(special(bit(0o100), bit(0o4000), 's', 'x'));
    s.push(if bit(0o040) { 'r' } else { '-' });
    s.push(if bit(0o020) { 'w' } else { '-' });
    s.push(special(bit(0o010), bit(0o2000), 's', 'x'));
    s.push(if bit(0o004) { 'r' } else { '-' });
    s.push(if bit(0o002) { 'w' } else { '-' });
    s.push(special(bit(0o001), bit(0o1000), 't', 'x'));
    s
}

/// Format an SFTP `mtime` (seconds since the Unix epoch) as an `ls -l`-style
/// `"%b %e %H:%M"` timestamp in UTC. A deterministic format is used (no
/// "older-than-six-months → year" switch) to keep the output reproducible.
fn format_ls_date(mtime: u32) -> String {
    use chrono::{TimeZone, Utc};
    match Utc.timestamp_opt(i64::from(mtime), 0).single() {
        Some(dt) => dt.format("%b %e %H:%M").to_string(),
        None => "Jan  1 00:00".to_string(),
    }
}

/// Synthesize a complete `ls -l`-style long-format line for a directory entry
/// from its SFTP [`FileAttributes`]. Owner/group are rendered from the symbolic
/// names when the server supplied them, otherwise from the numeric uid/gid.
fn format_long_entry(name: &str, attrs: &FileAttributes) -> String {
    let mode = attrs.permissions.unwrap_or(0);
    let owner = attrs
        .user
        .clone()
        .unwrap_or_else(|| attrs.uid.unwrap_or(0).to_string());
    let group = attrs
        .group
        .clone()
        .unwrap_or_else(|| attrs.gid.unwrap_or(0).to_string());
    format!(
        "{}{} {:>3} {:<8} {:<8} {:>8} {} {}",
        type_char(mode),
        perm_rwx(mode),
        1, // link count is not carried by SFTP attributes; libssh2 reports 1
        owner,
        group,
        attrs.size.unwrap_or(0),
        format_ls_date(attrs.mtime.unwrap_or(0)),
        name,
    )
}

// NOTE on wildcard matching: curl's wildcard feature (`CURLOPT_WILDCARDMATCH`,
// the `curl_fnmatch` matcher) is gated behind the `PROTOPT_WILDCARD` handler
// flag, which the C oracle sets ONLY for FTP (`lib/ftp.c`); `lib/url.c` clears
// the effective wildcard state for any scheme lacking that flag, and
// `lib/vssh/libssh2.c` contains no wildcard references whatsoever. SFTP listings
// are therefore always a plain single-directory enumeration (see `do_listing`).
// Wiring a wildcard matcher here would introduce behavior absent from curl 8.x
// and violate the minimal-change mandate (AAP §0.8.2), so it is intentionally
// omitted rather than stubbed.

// ---------------------------------------------------------------------------
// Data-plane seams (default: process standard streams; see module docs)
// ---------------------------------------------------------------------------

/// Header-line sink for QUOTE/`statvfs` *command output* (the `pwd` "257" line
/// and the `statvfs` block) — the SFTP analog of curl writing these via
/// `Curl_client_write(CLIENTWRITE_HEADER)`. The file-transfer data plane
/// (`do_download`/`do_upload`/`do_listing`) no longer uses this: it threads the
/// caller-supplied [`WriteCallbacks`]/[`ReadCallback`] (the real `-o`/`-T` /
/// `CURLOPT_*FUNCTION` targets) down from [`run_do`]. This staging seam remains
/// only for the QUOTE-command informational lines, which curl emits on the
/// header stream (default `stdout`) and which are outside the F4 transfer scope.
struct StdoutSink;

impl WriteCallbacks for StdoutSink {
    fn write_body(&mut self, data: &[u8]) -> usize {
        use std::io::Write;
        let mut out = std::io::stdout();
        match out.write_all(data) {
            Ok(()) => {
                let _ = out.flush();
                data.len()
            }
            // A short write signals failure; `ClientWriter` maps it to
            // `CurlError::WriteError`, matching curl's write-callback contract.
            Err(_) => 0,
        }
    }

    fn write_header(&mut self, data: &[u8]) -> Option<usize> {
        use std::io::Write;
        let mut out = std::io::stdout();
        match out.write_all(data) {
            Ok(()) => {
                let _ = out.flush();
                Some(data.len())
            }
            Err(_) => None,
        }
    }
}

// ---------------------------------------------------------------------------
// QUOTE / POSTQUOTE pseudo-command model (mirrors `sftp_quote` + `sftp_quote_stat`)
// ---------------------------------------------------------------------------

/// The single attribute change requested by a `chmod`/`chown`/`chgrp`/`atime`/
/// `mtime` QUOTE command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttrChange {
    /// `chmod` — set the permission bits (independent; no prior stat).
    Chmod(u32),
    /// `chown` — set the owner uid (paired with the current gid).
    Chown(u32),
    /// `chgrp` — set the group gid (paired with the current uid).
    Chgrp(u32),
    /// `atime` — set the access time (paired with the current mtime).
    Atime(u32),
    /// `mtime` — set the modification time (paired with the current atime).
    Mtime(u32),
    /// The numeric uid/gid failed to parse but the command carried a leading
    /// `*` (acceptfail): the C proceeds to SETSTAT without adding the attribute.
    /// chmod/atime/mtime parse failures are always fatal and never produce this.
    None,
}

/// The attribute-change verb of a setstat QUOTE command. Carried (rather than a
/// pre-parsed [`AttrChange`]) so the executor can reproduce the C ordering: for
/// every verb except `chmod`, `sftp_quote_stat` issues the `stat` round-trip
/// *before* parsing the value, so a missing target surfaces "Attempt to get SFTP
/// stats failed" rather than a value-syntax error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetstatVerb {
    /// `chmod` — set permission bits; never stats first.
    Chmod,
    /// `chown` — set the owner uid (stats first to preserve the gid).
    Chown,
    /// `chgrp` — set the group gid (stats first to preserve the uid).
    Chgrp,
    /// `atime` — set the access time (stats first to preserve the mtime).
    Atime,
    /// `mtime` — set the modification time (stats first to preserve the atime).
    Mtime,
}

impl SetstatVerb {
    /// `true` for every verb except `chmod` — the verbs whose SFTP attribute is
    /// one half of a serialized pair and therefore require a prior `stat`.
    fn stats_first(self) -> bool {
        !matches!(self, SetstatVerb::Chmod)
    }

    /// The five-byte verb label used verbatim in the C `atime`/`mtime`
    /// "incorrect date format for %.*s" diagnostic.
    fn label(self) -> &'static str {
        match self {
            SetstatVerb::Chmod => "chmod",
            SetstatVerb::Chown => "chown",
            SetstatVerb::Chgrp => "chgrp",
            SetstatVerb::Atime => "atime",
            SetstatVerb::Mtime => "mtime",
        }
    }
}

/// A fully parsed QUOTE pseudo-command, ready to execute against the SFTP
/// session.
#[derive(Debug, Clone, PartialEq, Eq)]
enum QuoteAction {
    /// `pwd` — emit the current working directory as an FTP-style `257` header.
    Pwd,
    /// `chmod`/`chown`/`chgrp`/`atime`/`mtime` — set file attributes. The value
    /// is kept raw and parsed by the executor (after the `stat`, for non-chmod
    /// verbs) so the C diagnostic ordering is preserved.
    Setstat {
        /// The target path whose attributes are changed (C `quote_path2`).
        target: String,
        /// Which attribute the command changes.
        verb: SetstatVerb,
        /// The unparsed value argument (C `quote_path1`): an octal mode, a
        /// decimal uid/gid, or a date string.
        value: String,
    },
    /// `ln`/`symlink <src> <dst>` — create a symbolic link.
    Symlink { src: String, dst: String },
    /// `mkdir <path>` — create a directory.
    Mkdir { path: String },
    /// `rename <from> <to>` — rename a file or directory.
    Rename { from: String, to: String },
    /// `rmdir <path>` — remove a directory.
    Rmdir { path: String },
    /// `rm <path>` — remove a file.
    Unlink { path: String },
    /// `statvfs <path>` — query filesystem statistics (emitted as a header block).
    Statvfs { path: String },
}

/// A successfully parsed QUOTE command: the action plus whether the command
/// carried a leading `*` (acceptfail — a *server* failure of this command is
/// ignored, the transfer continues as if it succeeded).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedQuote {
    action: QuoteAction,
    acceptfail: bool,
}

/// A QUOTE parse error: the diagnostic to emit via `failf` (`None` when the
/// underlying error is out-of-memory, for which the C emits no message) and the
/// [`CurlError`] to surface.
#[derive(Debug, Clone, PartialEq, Eq)]
struct QuoteParseError {
    msg: Option<String>,
    err: CurlError,
}

/// The C `return_quote_error` diagnostic + code. In the C oracle the return
/// value of `return_quote_error` is discarded and execution falls through to
/// operate on freed (NULL) paths — a latent defect that would crash and that
/// the test suite never exercises. The memory-safe behavior (AAP §0.7.1) is to
/// surface the intended [`CurlError::QuoteError`] here.
fn suspicious_data() -> QuoteParseError {
    QuoteParseError {
        msg: Some("Suspicious data after the command line".to_string()),
        err: CurlError::QuoteError,
    }
}

/// Parse a base-8 value bounded by `max` (inclusive), mirroring C
/// `curlx_str_octal(&p, &perms, 07777)`: at least one octal digit is required,
/// parsing stops at the first non-octal byte (trailing bytes are ignored, as in
/// the C), and a value exceeding `max` is a syntax error (`None`).
fn parse_octal(s: &str, max: u32) -> Option<u32> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || !(b'0'..=b'7').contains(&bytes[0]) {
        return None;
    }
    let mut num: u64 = 0;
    let mut i = 0;
    while i < bytes.len() && (b'0'..=b'7').contains(&bytes[i]) {
        num = num * 8 + u64::from(bytes[i] - b'0');
        if num > u64::from(max) {
            return None;
        }
        i += 1;
    }
    Some(num as u32)
}

/// Parse a base-10 uid/gid, mirroring C `curlx_str_number(&p, &val, ULONG_MAX)`:
/// at least one digit is required, parsing stops at the first non-digit, and a
/// value overflowing `u64` is an error (`None`). The parsed value is narrowed to
/// the 32-bit SFTP wire field — the same truncating store the C performs.
fn parse_decimal_u32(s: &str) -> Option<u32> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_digit() {
        return None;
    }
    let mut num: u64 = 0;
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        let d = u64::from(bytes[i] - b'0');
        if num > (u64::MAX - d) / 10 {
            return None;
        }
        num = num * 10 + d;
        i += 1;
    }
    Some(num as u32)
}

/// Parse the value argument of an attribute-change QUOTE command into an
/// [`AttrChange`], reproducing the per-verb arithmetic of `sftp_quote_stat`.
///
/// This is invoked by the executor (not by [`parse_quote_command`]) so that, for
/// every verb except `chmod`, it runs *after* the prerequisite `stat` round-trip
/// — preserving the C ordering in which a missing target reports "Attempt to get
/// SFTP stats failed" before any value-syntax check. The error rules match the C
/// exactly:
/// * `chmod` octal parse failure is **always** fatal (no acceptfail guard);
/// * `chgrp`/`chown` numeric parse failure is fatal **unless** `acceptfail`
///   (then it degrades to [`AttrChange::None`] and SETSTAT still proceeds);
/// * `atime`/`mtime` date parse failure is **always** fatal.
fn parse_attr_value(
    verb: SetstatVerb,
    value: &str,
    acceptfail: bool,
) -> std::result::Result<AttrChange, QuoteParseError> {
    match verb {
        SetstatVerb::Chmod => match parse_octal(value, 0o7777) {
            Some(perms) => Ok(AttrChange::Chmod(perms)),
            None => Err(QuoteParseError {
                msg: Some("Syntax error: chmod permissions not a number".to_string()),
                err: CurlError::QuoteError,
            }),
        },
        SetstatVerb::Chgrp => match parse_decimal_u32(value) {
            Some(gid) => Ok(AttrChange::Chgrp(gid)),
            None if acceptfail => Ok(AttrChange::None),
            None => Err(QuoteParseError {
                msg: Some("Syntax error: chgrp gid not a number".to_string()),
                err: CurlError::QuoteError,
            }),
        },
        SetstatVerb::Chown => match parse_decimal_u32(value) {
            Some(uid) => Ok(AttrChange::Chown(uid)),
            None if acceptfail => Ok(AttrChange::None),
            None => Err(QuoteParseError {
                msg: Some("Syntax error: chown uid not a number".to_string()),
                err: CurlError::QuoteError,
            }),
        },
        SetstatVerb::Atime | SetstatVerb::Mtime => match getdate_capped(value) {
            None => Err(QuoteParseError {
                msg: Some(format!("incorrect date format for {}", verb.label())),
                err: CurlError::QuoteError,
            }),
            // The C date-overflow guard (`date > 0xffffffff`) is compiled out on
            // LP64 targets (SIZEOF_TIME_T == SIZEOF_LONG); the value is stored
            // into the 32-bit SFTP wire field, matching this narrowing cast.
            Some(date) => {
                let secs = date as u32;
                if matches!(verb, SetstatVerb::Atime) {
                    Ok(AttrChange::Atime(secs))
                } else {
                    Ok(AttrChange::Mtime(secs))
                }
            }
        },
    }
}

/// Parse a single QUOTE command string into a [`ParsedQuote`], faithfully
/// reproducing `sftp_quote` (verb detection, `*` acceptfail, argument parsing
/// via [`super::get_pathname`]) and `sftp_quote_stat` (value parsing). This is a
/// pure function (no network, no `failf`) so it is unit-testable; the live
/// executor emits the diagnostics carried by [`QuoteParseError::msg`].
fn parse_quote_command(
    cmd: &str,
    homedir: &str,
) -> std::result::Result<ParsedQuote, QuoteParseError> {
    // A leading '*' — never legal in a real SFTP command — marks the command as
    // "acceptfail": a server failure is ignored. Strip it.
    let (cmd, acceptfail) = match cmd.strip_prefix('*') {
        Some(rest) => (rest, true),
        None => (cmd, false),
    };

    // `pwd` is matched case-insensitively in full (C `curl_strequal`).
    if cmd.eq_ignore_ascii_case("pwd") {
        return Ok(ParsedQuote {
            action: QuoteAction::Pwd,
            acceptfail,
        });
    }

    // Every other command needs a space separating the verb from its argument.
    let space = match cmd.find(' ') {
        Some(i) => i,
        None => {
            return Err(QuoteParseError {
                msg: Some(format!("Syntax error command '{cmd}', missing parameter")),
                err: CurlError::QuoteError,
            });
        }
    };

    // Parse the first argument. `get_pathname` skips leading blanks, so we feed
    // it the slice starting at the separating space (mirroring the C `cp`).
    let args = &cmd[space..];
    let (path1, consumed1) = get_pathname(args, homedir).map_err(|e| QuoteParseError {
        msg: (e != CurlError::OutOfMemory)
            .then(|| format!("Syntax error: Bad first parameter to '{cmd}'")),
        err: e,
    })?;
    let rest1 = &args[consumed1..];

    // Two-argument attribute-change commands: path1 is the value, path2 the
    // target file. The value is NOT parsed here — it is carried raw so the
    // executor can parse it in the C order (after the prerequisite `stat`).
    let setstat_verb = if cmd.starts_with("chmod ") {
        Some(SetstatVerb::Chmod)
    } else if cmd.starts_with("chgrp ") {
        Some(SetstatVerb::Chgrp)
    } else if cmd.starts_with("chown ") {
        Some(SetstatVerb::Chown)
    } else if cmd.starts_with("atime ") {
        Some(SetstatVerb::Atime)
    } else if cmd.starts_with("mtime ") {
        Some(SetstatVerb::Mtime)
    } else {
        None
    };
    if let Some(verb) = setstat_verb {
        let (path2, consumed2) = get_pathname(rest1, homedir).map_err(|e| QuoteParseError {
            msg: (e != CurlError::OutOfMemory)
                .then(|| format!("Syntax error in {cmd}: Bad second parameter")),
            err: e,
        })?;
        if !rest1[consumed2..].is_empty() {
            return Err(suspicious_data());
        }
        return Ok(ParsedQuote {
            action: QuoteAction::Setstat {
                target: path2,
                verb,
                value: path1,
            },
            acceptfail,
        });
    }

    // `ln`/`symlink <src> <dst>`.
    if cmd.starts_with("ln ") || cmd.starts_with("symlink ") {
        let (path2, consumed2) = get_pathname(rest1, homedir).map_err(|e| QuoteParseError {
            msg: (e != CurlError::OutOfMemory)
                .then(|| "Syntax error in ln/symlink: Bad second parameter".to_string()),
            err: e,
        })?;
        if !rest1[consumed2..].is_empty() {
            return Err(suspicious_data());
        }
        return Ok(ParsedQuote {
            action: QuoteAction::Symlink {
                src: path1,
                dst: path2,
            },
            acceptfail,
        });
    }

    // `rename <from> <to>`.
    if cmd.starts_with("rename ") {
        let (path2, consumed2) = get_pathname(rest1, homedir).map_err(|e| QuoteParseError {
            msg: (e != CurlError::OutOfMemory)
                .then(|| "Syntax error in rename: Bad second parameter".to_string()),
            err: e,
        })?;
        if !rest1[consumed2..].is_empty() {
            return Err(suspicious_data());
        }
        return Ok(ParsedQuote {
            action: QuoteAction::Rename {
                from: path1,
                to: path2,
            },
            acceptfail,
        });
    }

    // Single-argument commands: path1 is the target. Any trailing data is
    // "suspicious".
    if cmd.starts_with("mkdir ") {
        if !rest1.is_empty() {
            return Err(suspicious_data());
        }
        return Ok(ParsedQuote {
            action: QuoteAction::Mkdir { path: path1 },
            acceptfail,
        });
    }
    if cmd.starts_with("rmdir ") {
        if !rest1.is_empty() {
            return Err(suspicious_data());
        }
        return Ok(ParsedQuote {
            action: QuoteAction::Rmdir { path: path1 },
            acceptfail,
        });
    }
    if cmd.starts_with("rm ") {
        if !rest1.is_empty() {
            return Err(suspicious_data());
        }
        return Ok(ParsedQuote {
            action: QuoteAction::Unlink { path: path1 },
            acceptfail,
        });
    }
    if cmd.starts_with("statvfs ") {
        if !rest1.is_empty() {
            return Err(suspicious_data());
        }
        return Ok(ParsedQuote {
            action: QuoteAction::Statvfs { path: path1 },
            acceptfail,
        });
    }

    Err(QuoteParseError {
        msg: Some("Unknown SFTP command".to_string()),
        err: CurlError::QuoteError,
    })
}

// ---------------------------------------------------------------------------
// Data plane byte pumps (mirror `sftp_recv` / `sftp_send`)
// ---------------------------------------------------------------------------

/// Drive a download: read bytes from the SFTP file `reader` and deliver them to
/// `sink`, until either `maxdownload` bytes have been transferred or the reader
/// reaches EOF. `maxdownload < 0` means the size is unknown and the transfer
/// runs until EOF.
///
/// SFTP carries no content encoding, so bytes are handed straight to the write
/// callback (`sink.write_body`) rather than through a [`crate::transfer::
/// ClientWriter`] decoder chain — the same direct-to-output approach the sibling
/// `telnet` engine uses for the inline data plane. A short write (callback
/// consuming fewer bytes than offered) is the curl write-error contract and maps
/// to [`CurlError::WriteError`].
///
/// Returns the number of bytes delivered. A premature EOF (or read error) when a
/// definite size was expected maps to [`CurlError::PartialFile`], matching curl.
/// The pump is generic over the file reader so it can be unit-tested with an
/// in-memory source; the sink is the caller-supplied client write-callback chain
/// ([`WriteCallbacks`]) — the real `-o file` / `CURLOPT_WRITEFUNCTION` target
/// threaded down from [`run_do`], not a hardcoded stdout stub. `dyn
/// WriteCallbacks` is `Send` (the trait's supertrait), so the resulting future
/// is `Send` as the protocol `BoxFuture` requires.
async fn pump_download<R>(
    reader: &mut R,
    maxdownload: i64,
    sink: &mut dyn WriteCallbacks,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
{
    let bounded = maxdownload >= 0;
    let limit = if bounded {
        maxdownload as u64
    } else {
        u64::MAX
    };
    let mut total: u64 = 0;
    let mut buf = vec![0u8; SFTP_RECV_CHUNK];

    while total < limit {
        let want = if bounded {
            ((limit - total) as usize).min(SFTP_RECV_CHUNK)
        } else {
            SFTP_RECV_CHUNK
        };
        let n = match reader.read(&mut buf[..want]).await {
            Ok(n) => n,
            // A hard read error mid-transfer is a partial file when a size was
            // promised, otherwise an SSH-layer error.
            Err(_) => {
                return Err(if bounded {
                    CurlError::PartialFile
                } else {
                    CurlError::Ssh
                })
            }
        };
        if n == 0 {
            break; // EOF
        }
        // curl write-callback contract: a return value below the offered length
        // (other than a pause, which the inline seam never issues) is an error.
        if sink.write_body(&buf[..n]) != n {
            return Err(CurlError::WriteError);
        }
        total += n as u64;
    }

    // Server delivered fewer bytes than the promised size → partial file.
    if bounded && total < limit {
        return Err(CurlError::PartialFile);
    }

    Ok(total)
}

/// Drive an upload: pull bytes from the read-callback `src` via `reader` and
/// write them to the SFTP file `file`, until the source is exhausted. Returns
/// the number of bytes written. The buffered writer is flushed before returning;
/// the caller is responsible for the final close (shutdown).
///
/// Generic over the file writer so it can be unit-tested with an in-memory
/// endpoint; the source is the caller-supplied client read-callback
/// ([`ReadCallback`]) — the real `-T file` / `CURLOPT_READFUNCTION` source
/// threaded down from [`run_do`], not a hardcoded stdin stub. `dyn ReadCallback`
/// is `Send` (the trait's supertrait), so the future is `Send`.
async fn pump_upload<W>(
    file: &mut W,
    reader: &mut UploadReader,
    src: &mut dyn ReadCallback,
) -> Result<u64>
where
    W: AsyncWrite + Unpin,
{
    let mut total: u64 = 0;
    let mut buf = vec![0u8; SFTP_SEND_CHUNK];

    // Loop while the read-callback yields data. End of input — or a pause request
    // that the inline default seam cannot honor (no event loop to resume it) —
    // ends the upload.
    while let ReadStep::Data(n) = reader.read(&mut buf, src)? {
        file.write_all(&buf[..n])
            .await
            .map_err(|_| CurlError::UploadFailed)?;
        total += n as u64;
    }

    file.flush().await.map_err(|_| CurlError::UploadFailed)?;
    Ok(total)
}

// ---------------------------------------------------------------------------
// Diagnostics seam
// ---------------------------------------------------------------------------

/// Emit a `failf`-style diagnostic, mirroring the C `failf`: record it into the
/// error buffer (first-write-wins, the `CURLOPT_ERRORBUFFER` contract) and echo
/// it to the info stream when `verbose` (the `CURLINFO_TEXT` debug write that
/// `failf` performs under `--verbose`).
///
/// Until the transfer engine plumbs an error buffer through the inline SSH data
/// plane, the buffer is the caller's local `Option<String>` — the same seam the
/// sibling inline protocol (`telnet`) uses (`crate::util::sendf`).
fn diag(errbuf: &mut Option<String>, verbose: bool, msg: &str) {
    sendf::failf(errbuf, msg);
    sendf::infof(verbose, msg);
}

// ---------------------------------------------------------------------------
// Entry points (called by `SftpHandler` in `ssh/mod.rs`)
// ---------------------------------------------------------------------------

/// Start the SFTP subsystem on the authenticated SSH session and capture the
/// remote home directory — the Rust analog of the C `SSH_SFTP_INIT` →
/// `SSH_SFTP_REALPATH` transition (`lib/vssh/libssh2.c`).
///
/// Called by `SftpHandler::connect` *after* [`super::connect_ssh_session`] has
/// completed the transport handshake and authentication. It opens a fresh SSH
/// session channel, requests the `sftp` subsystem on it, wraps the channel
/// stream in a [`SftpSession`], then resolves `realpath(".")` to learn the home
/// directory (stored on [`SshConn`] for the per-request `/~` substitution in
/// [`do_it`]).
///
/// The non-`Clone` [`russh::client::Handle`] is moved out of [`SshConn`] for the
/// duration of the channel setup so that no `&Connection` borrow is held across
/// an `.await`, then moved back — the engine's futures are `Send` and this keeps
/// the borrow checker satisfied without copying the handle.
pub(super) async fn init_subsystem(data: &mut Easy, conn: &mut Connection) -> Result<()> {
    let verbose = data.set.verbose;

    // Move the authenticated session handle out of the per-connection state.
    let handle = {
        let sshc = conn
            .proto_state_mut::<SshConn>()
            .ok_or(CurlError::FailedInit)?;
        sshc.handle.take().ok_or(CurlError::FailedInit)?
    };

    // Open a channel, request the SFTP subsystem, and realpath the home dir.
    // Any failure here mirrors the C `Failure initializing sftp session` →
    // `CURLE_FAILED_INIT`.
    let mut errbuf: Option<String> = None;
    let setup = async {
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|_| CurlError::FailedInit)?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|_| CurlError::FailedInit)?;
        let session = SftpSession::new(channel.into_stream())
            .await
            .map_err(|_| CurlError::FailedInit)?;
        // C `SSH_SFTP_REALPATH`: canonicalize(".") yields the absolute home dir.
        // A server that does not support realpath leaves the home dir empty, in
        // which case later `/~` substitution simply does not occur.
        let homedir = session.canonicalize(".").await.ok();
        Ok::<_, CurlError>((session, homedir))
    }
    .await;

    match setup {
        Ok((session, homedir)) => {
            let sshc = conn
                .proto_state_mut::<SshConn>()
                .ok_or(CurlError::FailedInit)?;
            sshc.handle = Some(handle);
            sshc.sftp_session = Some(session);
            sshc.homedir = homedir;
            Ok(())
        }
        Err(e) => {
            // Return the handle so the disconnect hook can tear it down cleanly.
            if let Some(sshc) = conn.proto_state_mut::<SshConn>() {
                sshc.handle = Some(handle);
            }
            diag(
                &mut errbuf,
                verbose,
                "Failure initializing sftp session: subsystem start failed",
            );
            Err(e)
        }
    }
}

/// Classify the SFTP DO phase — the Rust analog of the C `sftp_doing` entry that
/// resolves the working path and records it on the per-request state.
///
/// Because the SFTP data plane is the `russh-sftp` file handle (not the raw
/// socket), the byte movement is performed by [`run_do`] (which threads the
/// caller's [`WriteCallbacks`]/[`ReadCallback`] through `do_download` /
/// `do_upload` / `do_listing`), not by the transfer engine. This classifier
/// therefore reports [`TransferDirection::None`]: there are no socket bytes for
/// the engine to pump afterwards (the same inline model the `telnet` engine
/// uses). It is retained as the [`crate::protocols::Protocol::do_it`] hook for
/// API symmetry with the other handlers; the runtime transfer is driven by
/// [`run_do`] from [`perform_sftp`](super::perform_sftp).
pub(super) async fn do_it(data: &mut Easy, conn: &mut Connection) -> Result<ProtocolTransfer> {
    // Resolve the working path now that the home directory is known
    // (C `Curl_getworkingpath` with the SFTP `/~` → home substitution) and
    // record it on the per-request state (C `sshp->path`), so `done`'s
    // POSTQUOTE/path handling sees the resolved path.
    let homedir = conn
        .proto_state_ref::<SshConn>()
        .and_then(|s| s.homedir.clone())
        .unwrap_or_default();
    let working_path = get_working_path(data, conn, Some(&homedir))?;
    if let Some(sshc) = conn.proto_state_mut::<SshConn>() {
        sshc.request.path = working_path;
    }

    Ok(ProtocolTransfer::new(TransferDirection::None))
}

/// Drive the SFTP DO phase end-to-end with the caller-supplied client `sink`
/// (download / directory listing) and `source` (upload) — the genuine SFTP
/// transfer entry point invoked by [`perform_sftp`](super::perform_sftp).
///
/// This is the data-plane analog of FTP's `run_do_phase`: it resolves the
/// working path, records it on the per-request state, moves the owned
/// [`SftpSession`] out of [`SshConn`] (so no `&Connection` borrow is held across
/// an `.await`), runs the [`do_sequence`] exchange (QUOTE → FILETIME →
/// upload/listing/download) with the real `sink`/`source`, then moves the
/// session back regardless of outcome for [`done`]/`disconnect`.
pub(super) async fn run_do(
    data: &mut Easy,
    conn: &mut Connection,
    sink: &mut dyn WriteCallbacks,
    source: &mut dyn ReadCallback,
) -> Result<()> {
    let verbose = data.set.verbose;

    // Resolve the working path now that the home directory is known
    // (C `Curl_getworkingpath` with the SFTP `/~` → home substitution).
    let homedir = conn
        .proto_state_ref::<SshConn>()
        .and_then(|s| s.homedir.clone())
        .unwrap_or_default();
    let working_path = get_working_path(data, conn, Some(&homedir))?;

    // Record it on the per-request state (C `sshp->path`).
    if let Some(sshc) = conn.proto_state_mut::<SshConn>() {
        sshc.request.path = working_path.clone();
    }

    // Move the live SFTP session out for the inline exchange.
    let session = conn
        .proto_state_mut::<SshConn>()
        .and_then(|s| s.sftp_session.take())
        .ok_or(CurlError::Ssh)?;

    // Drive the DO sequence; capture the outcome WITHOUT early-returning so the
    // session is always returned to `SshConn`.
    let mut errbuf: Option<String> = None;
    let outcome = do_sequence(
        &session,
        data,
        &working_path,
        &homedir,
        verbose,
        &mut errbuf,
        sink,
        source,
    )
    .await;

    if let Some(sshc) = conn.proto_state_mut::<SshConn>() {
        sshc.sftp_session = Some(session);
    }

    outcome
}

/// The body of [`do_it`], operating on the moved-out [`SftpSession`]: run the
/// pre-transfer QUOTE list, fetch the file time when requested, then branch to
/// upload / directory-listing / download exactly as the C `SSH_SFTP_TRANS_INIT`
/// does.
#[allow(clippy::too_many_arguments)]
async fn do_sequence(
    session: &SftpSession,
    data: &mut Easy,
    working_path: &str,
    homedir: &str,
    verbose: bool,
    errbuf: &mut Option<String>,
    sink: &mut dyn WriteCallbacks,
    source: &mut dyn ReadCallback,
) -> Result<()> {
    // 1. Pre-transfer QUOTE commands (C `ssh_state_sftp_quote_init`). The SFTP
    //    backend does NOT process `prequote` (verified: zero references in
    //    `lib/vssh/libssh2.c`); POSTQUOTE runs in `done`.
    let quote_items = collect_quote_items(data.set.quote.as_ref());
    if !quote_items.is_empty() {
        sendf::infof(verbose, "Sending quote commands");
        run_quote_list(
            session,
            &quote_items,
            working_path,
            homedir,
            verbose,
            errbuf,
        )
        .await?;
    }

    // 2. GETINFO → FILETIME (C `SSH_SFTP_GETINFO`/`SSH_SFTP_FILETIME`): when
    //    `CURLOPT_FILETIME` is set, stat the path and publish the mtime. A stat
    //    failure is non-fatal — the file time simply stays unset.
    if data.set.get_filetime {
        if let Ok(meta) = session.metadata(working_path.to_string()).await {
            if let Some(mtime) = meta.mtime {
                data.info.filetime = i64::from(mtime);
            }
        }
    }

    // 3. TRANS_INIT branch: upload (PUT), else directory listing (trailing '/'),
    //    else single-file download. The client `sink`/`source` (the real
    //    `-o`/`-T` / `CURLOPT_*FUNCTION` targets) are threaded straight through
    //    so the bytes reach the configured output/input rather than a stub.
    if data.set.method == HttpReq::Put {
        do_upload(session, data, working_path, verbose, errbuf, source).await?;
    } else if working_path.ends_with('/') {
        do_listing(session, data, working_path, verbose, errbuf, sink).await?;
    } else {
        do_download(session, data, working_path, verbose, errbuf, sink).await?;
    }

    // The bytes have already been delivered inline through the client callbacks;
    // the transfer engine has nothing to pump over the socket.
    Ok(())
}

/// Finalize an SFTP transfer — the Rust analog of `sftp_done` →
/// `ssh_state_sftp_close`. Runs the pending POSTQUOTE commands when the transfer
/// succeeded and was not aborted (the C `nextstate = SSH_SFTP_POSTQUOTE_INIT`
/// chain), then clears the per-request path. The SFTP subsystem itself is NOT
/// shut down here — that is the connection `disconnect` hook's job
/// (`SSH_SFTP_SHUTDOWN`) in `ssh/mod.rs`.
pub(super) async fn done(
    data: &mut Easy,
    conn: &mut Connection,
    status: Result<()>,
    premature: bool,
) -> Result<()> {
    let verbose = data.set.verbose;

    // POSTQUOTE only runs on a clean, complete transfer (C `sftp_done`:
    // `!status && !premature && postquote`).
    let run_postquote = status.is_ok() && !premature;
    let postquote_items = if run_postquote {
        collect_quote_items(data.set.postquote.as_ref())
    } else {
        Vec::new()
    };

    let homedir = conn
        .proto_state_ref::<SshConn>()
        .and_then(|s| s.homedir.clone())
        .unwrap_or_default();
    let working_path = conn
        .proto_state_ref::<SshConn>()
        .map(|s| s.request.path.clone())
        .unwrap_or_default();

    let mut result = status;

    if !postquote_items.is_empty() {
        // Move the session out for the inline POSTQUOTE round-trips.
        let session = conn
            .proto_state_mut::<SshConn>()
            .and_then(|s| s.sftp_session.take());
        if let Some(session) = session {
            let mut errbuf: Option<String> = None;
            sendf::infof(verbose, "Sending quote commands");
            let pq = run_quote_list(
                &session,
                &postquote_items,
                &working_path,
                &homedir,
                verbose,
                &mut errbuf,
            )
            .await;
            // A POSTQUOTE failure becomes the transfer result only if the
            // transfer itself had succeeded (curl surfaces the quote error).
            if result.is_ok() {
                result = pq;
            }
            if let Some(sshc) = conn.proto_state_mut::<SshConn>() {
                sshc.sftp_session = Some(session);
            }
        }
    }

    // Clear the per-request path (C `Curl_safefree(sshp->path)`).
    if let Some(sshc) = conn.proto_state_mut::<SshConn>() {
        sshc.request.path.clear();
    }

    result
}

// ---------------------------------------------------------------------------
// QUOTE / POSTQUOTE engine (mirrors `sftp_quote` + the `SSH_SFTP_QUOTE_*` states)
// ---------------------------------------------------------------------------

/// Snapshot a QUOTE/POSTQUOTE command list into owned strings. Decouples the
/// borrow of the [`Easy`] option list from the `async` execution that follows
/// (the live engine moves the session out of the connection and must not hold an
/// `Easy` slist borrow across `.await`). Lossy UTF-8 is acceptable: QUOTE
/// commands are ASCII verbs with path operands.
fn collect_quote_items(list: Option<&SList>) -> Vec<String> {
    match list {
        Some(sl) => sl
            .iter()
            .map(|c| c.to_string_lossy().into_owned())
            .collect(),
        None => Vec::new(),
    }
}

/// Format the `statvfs` header block byte-for-byte as the C
/// `ssh_state_sftp_quote_statvfs` does (the `f_*` field names and order are part
/// of the observable output). The `russh-sftp` [`Statvfs`] fields map onto the
/// POSIX `statvfs` members the C prints.
fn format_statvfs(st: &Statvfs) -> String {
    format!(
        "statvfs:\n\
         f_bsize: {}\n\
         f_frsize: {}\n\
         f_blocks: {}\n\
         f_bfree: {}\n\
         f_bavail: {}\n\
         f_files: {}\n\
         f_ffree: {}\n\
         f_favail: {}\n\
         f_fsid: {}\n\
         f_flag: {}\n\
         f_namemax: {}\n",
        st.block_size,
        st.fragment_size,
        st.blocks,
        st.blocks_free,
        st.blocks_avail,
        st.inodes,
        st.inodes_free,
        st.inodes_avail,
        st.fs_id,
        st.flags,
        st.name_max,
    )
}

/// Execute an ordered QUOTE/POSTQUOTE command list, stopping at the first
/// command that fails without the `*` acceptfail prefix (C `sftp_quote` loop).
async fn run_quote_list(
    session: &SftpSession,
    items: &[String],
    working_path: &str,
    homedir: &str,
    verbose: bool,
    errbuf: &mut Option<String>,
) -> Result<()> {
    for cmd in items {
        execute_quote(session, cmd, working_path, homedir, verbose, errbuf).await?;
    }
    Ok(())
}

/// Parse and execute a single QUOTE pseudo-command against the live session,
/// reproducing the exact dispatch and `failf` text of `sftp_quote` and the
/// `SSH_SFTP_QUOTE_*` action states. A command that fails the server round-trip
/// is fatal (`CURLE_QUOTE_ERROR`) unless it carried the `*` acceptfail prefix.
async fn execute_quote(
    session: &SftpSession,
    cmd: &str,
    working_path: &str,
    homedir: &str,
    verbose: bool,
    errbuf: &mut Option<String>,
) -> Result<()> {
    // Pure parse: argument extraction, `*` acceptfail, and the syntax checks all
    // happen here, carrying the exact C diagnostic for any parse failure.
    let parsed = match parse_quote_command(cmd, homedir) {
        Ok(p) => p,
        Err(qpe) => {
            if let Some(msg) = &qpe.msg {
                diag(errbuf, verbose, msg);
            }
            return Err(qpe.err);
        }
    };
    let acceptfail = parsed.acceptfail;

    match parsed.action {
        QuoteAction::Pwd => {
            // FTP-like "257" line to the header callback (C `CLIENTWRITE_HEADER`),
            // so the working directory is readable as with ordinary FTP. SFTP has
            // no content encoding, so the line is handed straight to the header
            // callback (`write_header`) without a `ClientWriter` decoder chain.
            let line = format!("257 \"{working_path}\" is current directory.\n");
            let mut sink = StdoutSink;
            if sink.write_header(line.as_bytes()) != Some(line.len()) {
                return Err(CurlError::WriteError);
            }
        }
        QuoteAction::Setstat {
            target,
            verb,
            value,
        } => {
            execute_setstat(session, &target, verb, &value, acceptfail, verbose, errbuf).await?;
        }
        QuoteAction::Symlink { src, dst } => {
            if let Err(e) = session.symlink(src.as_str(), dst.as_str()).await {
                if !acceptfail {
                    diag(
                        errbuf,
                        verbose,
                        &format!(
                            "symlink \"{src}\" to \"{dst}\" failed: {}",
                            sftp_strerror(sftp_status_code(&e))
                        ),
                    );
                    return Err(CurlError::QuoteError);
                }
            }
        }
        QuoteAction::Mkdir { path } => {
            if let Err(e) = session.create_dir(path.as_str()).await {
                if !acceptfail {
                    diag(
                        errbuf,
                        verbose,
                        &format!(
                            "mkdir \"{path}\" failed: {}",
                            sftp_strerror(sftp_status_code(&e))
                        ),
                    );
                    return Err(CurlError::QuoteError);
                }
            }
        }
        QuoteAction::Rename { from, to } => {
            if let Err(e) = session.rename(from.as_str(), to.as_str()).await {
                if !acceptfail {
                    diag(
                        errbuf,
                        verbose,
                        &format!(
                            "rename \"{from}\" to \"{to}\" failed: {}",
                            sftp_strerror(sftp_status_code(&e))
                        ),
                    );
                    return Err(CurlError::QuoteError);
                }
            }
        }
        QuoteAction::Rmdir { path } => {
            if let Err(e) = session.remove_dir(path.as_str()).await {
                if !acceptfail {
                    diag(
                        errbuf,
                        verbose,
                        &format!(
                            "rmdir \"{path}\" failed: {}",
                            sftp_strerror(sftp_status_code(&e))
                        ),
                    );
                    return Err(CurlError::QuoteError);
                }
            }
        }
        QuoteAction::Unlink { path } => {
            if let Err(e) = session.remove_file(path.as_str()).await {
                if !acceptfail {
                    diag(
                        errbuf,
                        verbose,
                        &format!(
                            "rm \"{path}\" failed: {}",
                            sftp_strerror(sftp_status_code(&e))
                        ),
                    );
                    return Err(CurlError::QuoteError);
                }
            }
        }
        QuoteAction::Statvfs { path } => {
            execute_statvfs(session, &path, acceptfail, verbose, errbuf).await?;
        }
    }
    Ok(())
}

/// Apply a `chmod`/`chown`/`chgrp`/`atime`/`mtime` QUOTE command. Mirrors
/// `sftp_quote_stat` (the prerequisite `stat` for the paired-field verbs, in the
/// C ordering) followed by `ssh_state_sftp_quote_setstat`.
async fn execute_setstat(
    session: &SftpSession,
    target: &str,
    verb: SetstatVerb,
    value: &str,
    acceptfail: bool,
    verbose: bool,
    errbuf: &mut Option<String>,
) -> Result<()> {
    // For every verb but chmod, stat the target FIRST so the unchanged half of a
    // serialized attribute pair (uid+gid, atime+mtime) is preserved — and so a
    // missing target reports the stat error before any value-syntax check.
    let current = if verb.stats_first() {
        match session.metadata(target.to_string()).await {
            Ok(m) => Some(m),
            Err(e) => {
                if !acceptfail {
                    diag(
                        errbuf,
                        verbose,
                        &format!(
                            "Attempt to get SFTP stats failed: {}",
                            sftp_strerror(sftp_status_code(&e))
                        ),
                    );
                    return Err(CurlError::QuoteError);
                }
                None
            }
        }
    } else {
        None
    };

    // Parse the value in the C order (after the stat, for non-chmod verbs).
    let change = match parse_attr_value(verb, value, acceptfail) {
        Ok(c) => c,
        Err(qpe) => {
            if let Some(msg) = &qpe.msg {
                diag(errbuf, verbose, msg);
            }
            return Err(qpe.err);
        }
    };

    // Build the attribute set. russh-sftp serializes uid+gid together and
    // atime+mtime together, so the paired field is filled from the stat above.
    let mut attrs = FileAttributes::default();
    match change {
        AttrChange::Chmod(perms) => attrs.permissions = Some(perms),
        AttrChange::Chown(uid) => {
            attrs.uid = Some(uid);
            attrs.gid = Some(current.as_ref().and_then(|m| m.gid).unwrap_or(0));
        }
        AttrChange::Chgrp(gid) => {
            attrs.gid = Some(gid);
            attrs.uid = Some(current.as_ref().and_then(|m| m.uid).unwrap_or(0));
        }
        AttrChange::Atime(secs) => {
            attrs.atime = Some(secs);
            attrs.mtime = Some(current.as_ref().and_then(|m| m.mtime).unwrap_or(0));
        }
        AttrChange::Mtime(secs) => {
            attrs.mtime = Some(secs);
            attrs.atime = Some(current.as_ref().and_then(|m| m.atime).unwrap_or(0));
        }
        AttrChange::None => {
            // acceptfail + non-numeric uid/gid: the C leaves the stat'd
            // attributes in place and re-applies them (an effectively no-op
            // SETSTAT). Re-apply the current pair when it is known.
            if let Some(m) = &current {
                attrs.uid = m.uid;
                attrs.gid = m.gid;
            }
        }
    }

    // Apply (C `ssh_state_sftp_quote_setstat`); the error path names the target.
    if let Err(e) = session.set_metadata(target.to_string(), attrs).await {
        if !acceptfail {
            diag(
                errbuf,
                verbose,
                &format!(
                    "Attempt to set SFTP stats for \"{target}\" failed: {}",
                    sftp_strerror(sftp_status_code(&e))
                ),
            );
            return Err(CurlError::QuoteError);
        }
    }
    Ok(())
}

/// Apply a `statvfs <path>` QUOTE command, emitting the C-formatted header block
/// (C `ssh_state_sftp_quote_statvfs`). A server without the `statvfs@openssh.com`
/// extension yields `None`, which the C code path never reaches; treat it as a
/// benign no-op.
async fn execute_statvfs(
    session: &SftpSession,
    path: &str,
    acceptfail: bool,
    verbose: bool,
    errbuf: &mut Option<String>,
) -> Result<()> {
    match session.fs_info(path.to_string()).await {
        Ok(Some(st)) => {
            let block = format_statvfs(&st);
            let mut sink = StdoutSink;
            if sink.write_header(block.as_bytes()) != Some(block.len()) {
                return Err(CurlError::WriteError);
            }
        }
        Ok(None) => {}
        Err(e) => {
            if !acceptfail {
                diag(
                    errbuf,
                    verbose,
                    &format!(
                        "statvfs \"{path}\" failed: {}",
                        sftp_strerror(sftp_status_code(&e))
                    ),
                );
                return Err(CurlError::QuoteError);
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DIRECTORY LISTING (mirrors `ssh_state_sftp_readdir_init` + `sftp_readdir` +
// the `SSH_SFTP_READDIR*` chain)
// ---------------------------------------------------------------------------

/// SFTP directory listing for a URL path that ends in `/`. With `--list-only`
/// (NLST semantics) the bare entry names are emitted; otherwise an `ls -l`-style
/// long line per entry, with a ` -> target` suffix appended for symlinks (C
/// `SSH_SFTP_READDIR_LINK`).
///
/// curl's wildcard feature (`CURLOPT_WILDCARDMATCH`) is intentionally NOT applied
/// here: only the FTP handler sets `PROTOPT_WILDCARD`, and `url.c` clears the
/// effective wildcard state for any scheme that lacks that flag, so an SFTP URL
/// always performs a plain, single-directory listing — matching the C oracle,
/// which contains no wildcard handling in its SFTP path.
async fn do_listing(
    session: &SftpSession,
    data: &Easy,
    path: &str,
    verbose: bool,
    errbuf: &mut Option<String>,
    sink: &mut dyn WriteCallbacks,
) -> Result<()> {
    // C `ssh_state_sftp_readdir_init`: a no-body request (`--head`/`-I`) lists
    // nothing — the download size is set to "unknown" and the state stops.
    if data.set.opt_no_body {
        return Ok(());
    }

    // `russh-sftp`'s `read_dir` performs the opendir + readdir loop + closedir
    // atomically, so both the C `opendir` failure (readdir_init) and a mid-scan
    // `readdir` failure surface here. The opendir failure is the common, tested
    // case, so its diagnostic ("Could not open directory for reading") is used.
    let read_dir = match session.read_dir(path.to_string()).await {
        Ok(rd) => rd,
        Err(e) => {
            diag(
                errbuf,
                verbose,
                &format!(
                    "Could not open directory for reading: {}",
                    sftp_strerror(sftp_status_code(&e))
                ),
            );
            return Err(map_sftp_status(&e));
        }
    };

    let list_only = data.set.list_only;

    // `ReadDir` is a fully-buffered iterator that already filters `.`/`..`, so
    // it is iterated synchronously while `read_link` is awaited per symlink. SFTP
    // has no content encoding, so each line goes straight to `write_body` on the
    // caller-supplied client sink (the real `-o file`/`stdout` target).
    for entry in read_dir {
        let name = entry.file_name();
        if list_only {
            // C: write the filename, then a newline (CLIENTWRITE_BODY x2).
            write_body_all(sink, name.as_bytes())?;
            write_body_all(sink, b"\n")?;
        } else {
            let attrs = entry.metadata();
            let mut line = format_long_entry(&name, &attrs);
            // C: only when the PERMISSIONS attr is present and marks a symlink.
            let is_symlink = attrs
                .permissions
                .map(|p| (p & S_IFMT) == S_IFLNK)
                .unwrap_or(false);
            if is_symlink {
                // C `SSH_SFTP_READDIR_LINK`: readlink(path + filename); a failure
                // aborts the whole listing exactly as the C does (it maps a
                // negative readlink result to `CURLE_OUT_OF_MEMORY`).
                let link_path = format!("{path}{name}");
                match session.read_link(link_path).await {
                    Ok(target) => {
                        line.push_str(" -> ");
                        line.push_str(&target);
                    }
                    Err(_) => return Err(CurlError::OutOfMemory),
                }
            }
            // C `SSH_SFTP_READDIR_BOTTOM`: append "\n" and write the whole line.
            line.push('\n');
            write_body_all(sink, line.as_bytes())?;
        }
    }

    Ok(())
}

/// Hand a complete buffer to a write callback's body stream, enforcing curl's
/// write-callback contract: a return value below the offered length (other than
/// a pause, which the inline seam never issues) is a [`CurlError::WriteError`].
fn write_body_all(sink: &mut dyn WriteCallbacks, data: &[u8]) -> Result<()> {
    if sink.write_body(data) != data.len() {
        return Err(CurlError::WriteError);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DOWNLOAD (mirrors `ssh_state_sftp_download_init` + `sftp_download_stat`)
// ---------------------------------------------------------------------------

/// SFTP file download. Opens the remote file read-only, stats it for the size,
/// applies RANGE/resume seeking via [`compute_download_plan`], then streams the
/// bytes to the write sink. Faithfully reproduces the C download init/stat
/// branching, including the "File already completely downloaded" short-circuit.
async fn do_download(
    session: &SftpSession,
    data: &Easy,
    path: &str,
    verbose: bool,
    errbuf: &mut Option<String>,
    sink: &mut dyn WriteCallbacks,
) -> Result<()> {
    // C `ssh_state_sftp_download_init`: open read-only.
    let mut file = match session
        .open_with_flags(path.to_string(), OpenFlags::READ)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            diag(
                errbuf,
                verbose,
                &format!(
                    "Could not open remote file for reading: {}",
                    sftp_strerror(sftp_status_code(&e))
                ),
            );
            return Err(map_sftp_status(&e));
        }
    };

    // C `sftp_download_stat`: a stat failure, a missing SIZE attribute, or a
    // reported size of 0 all mean "unknown size" → download until EOF.
    let stat_size = match file.metadata().await {
        Ok(m) => match m.size {
            Some(sz) if sz > 0 => Some(sz),
            _ => None,
        },
        Err(_) => None,
    };

    let resume_from = data.set.set_resume_from;
    // EasyState is minimal (no `use_range`/`range`): the presence of the RANGE
    // option string is the effective `use_range`, read directly from options.
    let range_opt: Option<String> = data.set.str(StrId::SetRange).map(|s| s.to_string());
    let use_range = range_opt.is_some();

    let plan = match compute_download_plan(stat_size, use_range, range_opt.as_deref(), resume_from)
    {
        Ok(p) => p,
        Err(e) => {
            // The resume-beyond-size case carries the C diagnostic verbatim; a
            // malformed RANGE is surfaced by code only (the helper validated it,
            // and `ssh_range` owns that message in the C — see its Rust port).
            if e == CurlError::BadDownloadResume {
                let filesize = stat_size
                    .map(|s| i64::try_from(s).unwrap_or(i64::MAX))
                    .unwrap_or(0);
                diag(
                    errbuf,
                    verbose,
                    &format!("Offset ({resume_from}) was beyond file size ({filesize})"),
                );
            }
            let _ = file.shutdown().await;
            return Err(e);
        }
    };

    if plan.already_done {
        // C: `Curl_xfer_setup_nop` + "File already completely downloaded" + STOP.
        let _ = file.shutdown().await;
        sendf::infof(verbose, "File already completely downloaded");
        return Ok(());
    }

    if plan.seek_from != 0 {
        file.seek(SeekFrom::Start(plan.seek_from))
            .await
            .map_err(|_| CurlError::Ssh)?;
    }

    let result = pump_download(&mut file, plan.maxdownload, sink).await;

    // C `ssh_state_sftp_close`: close the handle regardless of transfer outcome.
    if file.shutdown().await.is_err() {
        sendf::infof(verbose, "Failed to close SFTP file");
    }
    result.map(|_| ())
}

// ---------------------------------------------------------------------------
// UPLOAD (mirrors `sftp_upload_init` + the `SSH_SFTP_CREATE_DIRS*` states)
// ---------------------------------------------------------------------------

/// The SFTP protocol status number (`LIBSSH2_FX_*` value) for the C
/// "Upload failed: %s (%lu/%d)" diagnostic. `russh-sftp`'s [`StatusCode`]
/// discriminants coincide with the `LIBSSH2_FX_*` constants for the SFTP v3
/// range (0–8), so this reproduces the C number exactly.
fn sftp_status_num(code: Option<StatusCode>) -> u32 {
    match code {
        Some(StatusCode::Ok) => 0,
        Some(StatusCode::Eof) => 1,
        Some(StatusCode::NoSuchFile) => 2,
        Some(StatusCode::PermissionDenied) => 3,
        Some(StatusCode::Failure) => 4,
        Some(StatusCode::BadMessage) => 5,
        Some(StatusCode::NoConnection) => 6,
        Some(StatusCode::ConnectionLost) => 7,
        Some(StatusCode::OpUnsupported) => 8,
        _ => 0,
    }
}

/// Walk a remote path's `/`-separated prefixes and create each missing directory
/// best-effort, reproducing the C `SSH_SFTP_CREATE_DIRS_INIT` → `CREATE_DIRS` →
/// `CREATE_DIRS_MKDIR` chain. The walk starts after the first character (C
/// `slash_pos = path + 1`) so a leading `/` is not a spurious empty component.
///
/// A `mkdir` failure is ignored when the status is benign — the C set is
/// `{FILE_ALREADY_EXISTS, FAILURE, PERMISSION_DENIED}`; on an SFTP v3 server an
/// existing directory is reported as `Failure` (FILE_ALREADY_EXISTS is v4+), so
/// the reachable benign set is `{Failure, PermissionDenied}`. Any other status
/// aborts the walk with the mapped error (the C routes to `SSH_SFTP_CLOSE`).
///
/// Note (documented divergence, AAP §0.7.1): `russh-sftp`'s `create_dir` issues
/// `SSH_FXP_MKDIR` with empty attributes, so `CURLOPT_NEW_DIRECTORY_PERMS` cannot
/// be carried on the wire; the server's umask applies to created directories.
async fn create_missing_dirs(session: &SftpSession, path: &str, verbose: bool) -> Result<()> {
    if path.len() <= 1 {
        return Ok(());
    }
    let mut search = 1usize;
    while let Some(rel) = path[search..].find('/') {
        let slash = search + rel;
        let prefix = &path[..slash];
        sendf::infof(verbose, &format!("Creating directory '{prefix}'"));
        if let Err(e) = session.create_dir(prefix).await {
            match sftp_status_code(&e) {
                Some(StatusCode::Failure) | Some(StatusCode::PermissionDenied) => {}
                _ => return Err(map_sftp_status(&e)),
            }
        }
        search = slash + 1;
    }
    Ok(())
}

/// SFTP file upload. Resolves a negative resume offset against the remote size,
/// selects the open flags ([`select_upload_flags`]), opens the file (retrying
/// once after creating missing parent directories when `--ftp-create-dirs` is
/// set), advances past the resume offset, then streams the input to the file.
async fn do_upload(
    session: &SftpSession,
    data: &Easy,
    path: &str,
    verbose: bool,
    errbuf: &mut Option<String>,
    source: &mut dyn ReadCallback,
) -> Result<()> {
    let remote_append = data.set.remote_append;

    // C `sftp_upload_init`: a negative resume offset ("append after the current
    // size") is resolved by stat'ing the remote file first. A stat failure (or a
    // missing size) resets the offset to 0, matching the C `rc` branch.
    let mut resume_from = data.set.set_resume_from;
    if resume_from < 0 {
        resume_from = match session.metadata(path.to_string()).await {
            Ok(m) => m
                .size
                .map(|sz| i64::try_from(sz).unwrap_or(i64::MAX))
                .unwrap_or(0),
            Err(_) => 0,
        };
    }

    let flags = select_upload_flags(remote_append, resume_from);
    // C passes `data->set.new_file_perms` to `libssh2_sftp_open_ex`; carry it as
    // the create-time permission attribute (ignored by the server when the file
    // already exists, i.e. the resume/append cases).
    let attrs = FileAttributes {
        permissions: Some(data.set.new_file_perms),
        ..FileAttributes::default()
    };

    // Open, retrying once after remote directory creation (C `secondCreateDirs`).
    let mut second_create_dirs = false;
    let mut file = loop {
        match session
            .open_with_flags_and_attributes(path.to_string(), flags, attrs.clone())
            .await
        {
            Ok(f) => break f,
            Err(e) => {
                if second_create_dirs {
                    // The retry after creating dirs still failed (C secondCreateDirs).
                    diag(
                        errbuf,
                        verbose,
                        &format!(
                            "Creating the dir/file failed: {}",
                            sftp_strerror(sftp_status_code(&e))
                        ),
                    );
                    return Err(map_sftp_status(&e));
                }
                if is_missing_path_error(&e)
                    && data.set.ftp_create_missing_dirs != 0
                    && path.len() > 1
                {
                    // C: create the missing path remotely, then retry the open.
                    second_create_dirs = true;
                    create_missing_dirs(session, path, verbose).await?;
                    continue;
                }
                // Generic open failure (C "Upload failed: %s (%lu/%d)").
                let code = sftp_status_code(&e);
                let strerr = if code.is_some() {
                    sftp_strerror(code)
                } else {
                    "ssh error"
                };
                // `rc` is the libssh2 session errno; when the failure carried an
                // SFTP status the C `rc` was `LIBSSH2_ERROR_SFTP_PROTOCOL` (-31).
                let rc = if code.is_some() { -31 } else { 0 };
                diag(
                    errbuf,
                    verbose,
                    &format!(
                        "Upload failed: {} ({}/{})",
                        strerr,
                        sftp_status_num(code),
                        rc
                    ),
                );
                return Err(map_sftp_status(&e));
            }
        }
    };

    let infilesize = data.set.filesize;

    // C: a positive resume (non-append) advances the *input* past `resume_from`
    // bytes, then seeks the remote handle. The client read source carries no seek
    // hook here, so always read-and-discard from the source (the C fallback path).
    if resume_from > 0 && !remote_append {
        let mut scratch = vec![0u8; RESUME_SCRATCH];
        let mut passed: i64 = 0;
        while passed < resume_from {
            let want = ((resume_from - passed) as usize).min(RESUME_SCRATCH);
            let n = source.read(&mut scratch[..want]);
            // C: a zero read (or an over-read / READFUNC_ABORT) is fatal.
            if n == 0 || n > want {
                diag(errbuf, verbose, "Failed to read data");
                let _ = file.shutdown().await;
                return Err(CurlError::FtpCouldntUseRest);
            }
            passed += n as i64;
        }
        file.seek(SeekFrom::Start(resume_from as u64))
            .await
            .map_err(|_| CurlError::Ssh)?;
    }

    // Effective upload length: the known infile size (decremented by the resume
    // offset for a non-append resume), or unknown (stream to EOF) when negative.
    let remaining: Option<u64> = if infilesize >= 0 {
        let eff = if resume_from > 0 && !remote_append {
            (infilesize - resume_from).max(0)
        } else {
            infilesize
        };
        Some(eff as u64)
    } else {
        None
    };

    let mut reader = UploadReader::new(remaining, false);
    let result = pump_upload(&mut file, &mut reader, source).await;

    // C `ssh_state_sftp_close`: close the handle regardless of transfer outcome.
    if file.shutdown().await.is_err() {
        sendf::infof(verbose, "Failed to close SFTP file");
    }
    result.map(|_| ())
}

// ===========================================================================
// Unit tests — pure decision logic (no live SFTP server required)
//
// These exercise the standalone, side-effect-free helpers that encode the C
// oracle's SFTP decisions: QUOTE command parsing, attribute-value parsing,
// open-flag selection, the download size/seek/resume plan, `ls -l` long-entry
// synthesis, and the `russh-sftp`→`CurlError` error mapping. The live engines
// (`do_listing`/`do_download`/`do_upload`) are integration-tested by the curl
// 8.x suite against a real SFTP server; here we lock down the branching logic
// that determines parity.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use russh_sftp::protocol::Status;

    // -- fixtures -----------------------------------------------------------

    /// Build a `russh-sftp` server-status error carrying `code` (the analog of
    /// a libssh2 `LIBSSH2_FX_*` status).
    fn status_err(code: StatusCode) -> SftpError {
        SftpError::Status(Status {
            id: 0,
            status_code: code,
            error_message: String::new(),
            language_tag: String::new(),
        })
    }

    /// A non-status (I/O) error — the analog of a non-SFTP-protocol libssh2
    /// error, for which the C `sftperr` is `LIBSSH2_FX_OK`.
    fn io_err() -> SftpError {
        SftpError::IO("connection reset".to_string())
    }

    /// Construct `FileAttributes` with the given mode/size/mtime; everything
    /// else defaulted (absent).
    fn fa(mode: u32, size: u64, mtime: u32) -> FileAttributes {
        FileAttributes {
            permissions: Some(mode),
            size: Some(size),
            mtime: Some(mtime),
            ..FileAttributes::default()
        }
    }

    // -- parse_octal --------------------------------------------------------

    #[test]
    fn parse_octal_valid_and_bounds() {
        assert_eq!(parse_octal("0755", 0o7777), Some(0o755));
        assert_eq!(parse_octal("755", 0o7777), Some(0o755));
        assert_eq!(parse_octal("0", 0o7777), Some(0));
        assert_eq!(parse_octal("7777", 0o7777), Some(0o7777));
        // Trailing non-octal bytes stop the scan (C `curlx_str_octal`).
        assert_eq!(parse_octal("755z", 0o7777), Some(0o755));
    }

    #[test]
    fn parse_octal_rejects() {
        assert_eq!(parse_octal("", 0o7777), None); // empty
        assert_eq!(parse_octal("8", 0o7777), None); // 8 is not an octal digit
        assert_eq!(parse_octal("9abc", 0o7777), None); // leading non-octal
                                                       // Exceeding the inclusive maximum is a syntax error.
        assert_eq!(parse_octal("10000", 0o7777), None);
    }

    // -- parse_decimal_u32 --------------------------------------------------

    #[test]
    fn parse_decimal_valid() {
        assert_eq!(parse_decimal_u32("0"), Some(0));
        assert_eq!(parse_decimal_u32("1000"), Some(1000));
        assert_eq!(parse_decimal_u32("4294967295"), Some(u32::MAX));
        // Parsing stops at the first non-digit.
        assert_eq!(parse_decimal_u32("123abc"), Some(123));
    }

    #[test]
    fn parse_decimal_rejects() {
        assert_eq!(parse_decimal_u32(""), None);
        assert_eq!(parse_decimal_u32("x"), None);
        // A value overflowing u64 is rejected.
        assert_eq!(parse_decimal_u32("99999999999999999999999"), None);
    }

    // -- parse_attr_value ---------------------------------------------------

    #[test]
    fn attr_chmod_octal() {
        assert_eq!(
            parse_attr_value(SetstatVerb::Chmod, "0755", false),
            Ok(AttrChange::Chmod(0o755))
        );
        // chmod parse failure is ALWAYS fatal — even with acceptfail set.
        for acceptfail in [false, true] {
            let e = parse_attr_value(SetstatVerb::Chmod, "abc", acceptfail).unwrap_err();
            assert_eq!(e.err, CurlError::QuoteError);
            assert_eq!(
                e.msg.as_deref(),
                Some("Syntax error: chmod permissions not a number")
            );
        }
    }

    #[test]
    fn attr_chgrp_number_and_acceptfail() {
        assert_eq!(
            parse_attr_value(SetstatVerb::Chgrp, "1000", false),
            Ok(AttrChange::Chgrp(1000))
        );
        // Bad gid without acceptfail → fatal with the exact C message.
        let e = parse_attr_value(SetstatVerb::Chgrp, "x", false).unwrap_err();
        assert_eq!(e.err, CurlError::QuoteError);
        assert_eq!(
            e.msg.as_deref(),
            Some("Syntax error: chgrp gid not a number")
        );
        // Bad gid WITH acceptfail → degrades to a no-op (SETSTAT still proceeds).
        assert_eq!(
            parse_attr_value(SetstatVerb::Chgrp, "x", true),
            Ok(AttrChange::None)
        );
    }

    #[test]
    fn attr_chown_number_and_acceptfail() {
        assert_eq!(
            parse_attr_value(SetstatVerb::Chown, "0", false),
            Ok(AttrChange::Chown(0))
        );
        let e = parse_attr_value(SetstatVerb::Chown, "nope", false).unwrap_err();
        assert_eq!(
            e.msg.as_deref(),
            Some("Syntax error: chown uid not a number")
        );
        assert_eq!(
            parse_attr_value(SetstatVerb::Chown, "nope", true),
            Ok(AttrChange::None)
        );
    }

    #[test]
    fn attr_atime_mtime_dates() {
        // The canonical RFC1123 instant the parsedate module pins: 784111777.
        // (parse_attr_value forwards the raw value to getdate_capped; the live
        // flow supplies a single space-free token, but the forwarding semantics
        // are identical for a unit test.)
        let canon: u32 = 784_111_777;
        assert_eq!(
            parse_attr_value(SetstatVerb::Atime, "Sun, 06 Nov 1994 08:49:37 GMT", false),
            Ok(AttrChange::Atime(canon))
        );
        assert_eq!(
            parse_attr_value(SetstatVerb::Mtime, "Sun, 06 Nov 1994 08:49:37 GMT", false),
            Ok(AttrChange::Mtime(canon))
        );
        // A bad date is ALWAYS fatal, with the verb-labeled C message.
        let e = parse_attr_value(SetstatVerb::Atime, "not-a-date", false).unwrap_err();
        assert_eq!(e.err, CurlError::QuoteError);
        assert_eq!(e.msg.as_deref(), Some("incorrect date format for atime"));
        let e = parse_attr_value(SetstatVerb::Mtime, "not-a-date", true).unwrap_err();
        assert_eq!(e.msg.as_deref(), Some("incorrect date format for mtime"));
    }

    // -- parse_quote_command ------------------------------------------------

    const HOME: &str = "/home/user";

    #[test]
    fn quote_pwd_variants() {
        for (input, accept) in [("pwd", false), ("PWD", false), ("*pwd", true)] {
            let p = parse_quote_command(input, HOME).unwrap();
            assert_eq!(p.action, QuoteAction::Pwd);
            assert_eq!(p.acceptfail, accept);
        }
    }

    #[test]
    fn quote_setstat_commands() {
        let p = parse_quote_command("chmod 0755 /file", HOME).unwrap();
        assert!(!p.acceptfail);
        assert_eq!(
            p.action,
            QuoteAction::Setstat {
                target: "/file".to_string(),
                verb: SetstatVerb::Chmod,
                value: "0755".to_string(),
            }
        );
        // Leading '*' strips and sets acceptfail.
        let p = parse_quote_command("*chown 1000 /file", HOME).unwrap();
        assert!(p.acceptfail);
        assert_eq!(
            p.action,
            QuoteAction::Setstat {
                target: "/file".to_string(),
                verb: SetstatVerb::Chown,
                value: "1000".to_string(),
            }
        );
        // chgrp / atime / mtime carry the verb and the raw value.
        assert!(matches!(
            parse_quote_command("chgrp 1000 /f", HOME).unwrap().action,
            QuoteAction::Setstat {
                verb: SetstatVerb::Chgrp,
                ..
            }
        ));
        assert!(matches!(
            parse_quote_command("atime 20140101 /f", HOME)
                .unwrap()
                .action,
            QuoteAction::Setstat {
                verb: SetstatVerb::Atime,
                ..
            }
        ));
        assert!(matches!(
            parse_quote_command("mtime 20140101 /f", HOME)
                .unwrap()
                .action,
            QuoteAction::Setstat {
                verb: SetstatVerb::Mtime,
                ..
            }
        ));
    }

    #[test]
    fn quote_link_and_rename_two_arg() {
        for verb in ["ln", "symlink"] {
            let p = parse_quote_command(&format!("{verb} /src /dst"), HOME).unwrap();
            assert_eq!(
                p.action,
                QuoteAction::Symlink {
                    src: "/src".to_string(),
                    dst: "/dst".to_string(),
                }
            );
        }
        let p = parse_quote_command("rename /a /b", HOME).unwrap();
        assert_eq!(
            p.action,
            QuoteAction::Rename {
                from: "/a".to_string(),
                to: "/b".to_string(),
            }
        );
    }

    #[test]
    fn quote_single_arg_commands() {
        assert_eq!(
            parse_quote_command("mkdir /newdir", HOME).unwrap().action,
            QuoteAction::Mkdir {
                path: "/newdir".to_string()
            }
        );
        assert_eq!(
            parse_quote_command("rmdir /d", HOME).unwrap().action,
            QuoteAction::Rmdir {
                path: "/d".to_string()
            }
        );
        assert_eq!(
            parse_quote_command("rm /f", HOME).unwrap().action,
            QuoteAction::Unlink {
                path: "/f".to_string()
            }
        );
        let p = parse_quote_command("*rm /f", HOME).unwrap();
        assert!(p.acceptfail);
        assert_eq!(
            p.action,
            QuoteAction::Unlink {
                path: "/f".to_string()
            }
        );
        assert_eq!(
            parse_quote_command("statvfs /", HOME).unwrap().action,
            QuoteAction::Statvfs {
                path: "/".to_string()
            }
        );
    }

    #[test]
    fn quote_home_substitution() {
        // The `/~/` prefix is replaced by the home directory (C `get_pathname`).
        let p = parse_quote_command("mkdir /~/sub", HOME).unwrap();
        assert_eq!(
            p.action,
            QuoteAction::Mkdir {
                path: "/home/user/sub".to_string()
            }
        );
    }

    #[test]
    fn quote_errors() {
        // Missing parameter (no space at all).
        let e = parse_quote_command("chmod", HOME).unwrap_err();
        assert_eq!(e.err, CurlError::QuoteError);
        assert_eq!(
            e.msg.as_deref(),
            Some("Syntax error command 'chmod', missing parameter")
        );
        // Trailing data after a single-argument command is "suspicious".
        let e = parse_quote_command("mkdir /a /b", HOME).unwrap_err();
        assert_eq!(e.err, CurlError::QuoteError);
        assert_eq!(
            e.msg.as_deref(),
            Some("Suspicious data after the command line")
        );
        // Trailing data after a two-argument command is "suspicious" too.
        let e = parse_quote_command("rename /a /b /c", HOME).unwrap_err();
        assert_eq!(
            e.msg.as_deref(),
            Some("Suspicious data after the command line")
        );
        // An unrecognized verb.
        let e = parse_quote_command("frobnicate /x", HOME).unwrap_err();
        assert_eq!(e.err, CurlError::QuoteError);
        assert_eq!(e.msg.as_deref(), Some("Unknown SFTP command"));
    }

    // -- select_upload_flags ------------------------------------------------

    #[test]
    fn upload_flags_selection() {
        // `OpenFlags` is a `bitflags` type without `PartialEq`; compare the
        // underlying bit pattern via `.bits()`.
        // Append → WRITE|CREATE|APPEND, regardless of resume offset.
        let want_append = (OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::APPEND).bits();
        assert_eq!(select_upload_flags(true, 0).bits(), want_append);
        assert_eq!(select_upload_flags(true, 500).bits(), want_append);
        // Positive resume (non-append) → WRITE only (deliberately no APPEND).
        assert_eq!(
            select_upload_flags(false, 500).bits(),
            OpenFlags::WRITE.bits()
        );
        // Fresh upload → WRITE|CREATE|TRUNCATE.
        let want_fresh = (OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE).bits();
        assert_eq!(select_upload_flags(false, 0).bits(), want_fresh);
    }

    // -- compute_download_plan ----------------------------------------------

    #[test]
    fn download_unknown_size_streams_to_eof() {
        let p = compute_download_plan(None, false, None, 0).unwrap();
        assert_eq!(
            p,
            DownloadPlan {
                seek_from: 0,
                maxdownload: -1,
                already_done: false
            }
        );
    }

    #[test]
    fn download_known_size_plain() {
        let p = compute_download_plan(Some(100), false, None, 0).unwrap();
        assert_eq!(
            p,
            DownloadPlan {
                seek_from: 0,
                maxdownload: 100,
                already_done: false
            }
        );
    }

    #[test]
    fn download_resume_positive() {
        let p = compute_download_plan(Some(100), false, None, 30).unwrap();
        assert_eq!(
            p,
            DownloadPlan {
                seek_from: 30,
                maxdownload: 70,
                already_done: false
            }
        );
    }

    #[test]
    fn download_resume_equals_size_is_already_done() {
        let p = compute_download_plan(Some(100), false, None, 100).unwrap();
        assert_eq!(
            p,
            DownloadPlan {
                seek_from: 100,
                maxdownload: 0,
                already_done: true
            }
        );
    }

    #[test]
    fn download_resume_negative_last_n_bytes() {
        // Resume of -30 with a 100-byte file → last 30 bytes from offset 70.
        let p = compute_download_plan(Some(100), false, None, -30).unwrap();
        assert_eq!(
            p,
            DownloadPlan {
                seek_from: 70,
                maxdownload: 30,
                already_done: false
            }
        );
    }

    #[test]
    fn download_resume_beyond_file_errors() {
        assert_eq!(
            compute_download_plan(Some(100), false, None, 150),
            Err(CurlError::BadDownloadResume)
        );
        assert_eq!(
            compute_download_plan(Some(100), false, None, -150),
            Err(CurlError::BadDownloadResume)
        );
        // Resume against an unknown size always fails (attrs_filesize == 0).
        assert_eq!(
            compute_download_plan(None, false, None, 30),
            Err(CurlError::BadDownloadResume)
        );
    }

    #[test]
    fn download_range_via_ssh_range() {
        // ssh_range("10-19", 100) → (from=10, size=10).
        let p = compute_download_plan(Some(100), true, Some("10-19"), 0).unwrap();
        assert_eq!(
            p,
            DownloadPlan {
                seek_from: 10,
                maxdownload: 10,
                already_done: false
            }
        );
    }

    #[test]
    fn download_range_malformed_errors() {
        assert_eq!(
            compute_download_plan(Some(100), true, Some("not-a-range"), 0),
            Err(CurlError::RangeError)
        );
    }

    // -- type_char / perm_rwx / format_ls_date ------------------------------

    #[test]
    fn type_char_all_kinds() {
        assert_eq!(type_char(S_IFDIR), 'd');
        assert_eq!(type_char(S_IFLNK), 'l');
        assert_eq!(type_char(S_IFREG), '-');
        assert_eq!(type_char(S_IFCHR), 'c');
        assert_eq!(type_char(S_IFBLK), 'b');
        assert_eq!(type_char(S_IFIFO), 'p');
        assert_eq!(type_char(S_IFSOCK), 's');
        assert_eq!(type_char(0), '-'); // unknown type
    }

    #[test]
    fn perm_rwx_rendering() {
        assert_eq!(perm_rwx(0o755), "rwxr-xr-x");
        assert_eq!(perm_rwx(0o644), "rw-r--r--");
        assert_eq!(perm_rwx(0o000), "---------");
        // setuid + user-exec → lowercase 's'.
        assert_eq!(perm_rwx(0o4755), "rwsr-xr-x");
        // setgid without group-exec → uppercase 'S'.
        assert_eq!(perm_rwx(0o2645), "rw-r-Sr-x");
        // sticky + other-exec → lowercase 't'.
        assert_eq!(perm_rwx(0o1777), "rwxrwxrwt");
        // sticky without other-exec → uppercase 'T'.
        assert_eq!(perm_rwx(0o1776), "rwxrwxrwT");
    }

    #[test]
    fn format_ls_date_deterministic_utc() {
        assert_eq!(format_ls_date(0), "Jan  1 00:00");
        // 784_111_777 = 1994-11-06 08:49:37 UTC.
        assert_eq!(format_ls_date(784_111_777), "Nov  6 08:49");
    }

    // -- format_long_entry --------------------------------------------------

    #[test]
    fn long_entry_regular_file() {
        let line = format_long_entry("file.txt", &fa(S_IFREG | 0o644, 1234, 0));
        assert!(line.starts_with("-rw-r--r--"), "line: {line}");
        assert!(line.contains("1234"), "line: {line}");
        assert!(line.ends_with("file.txt"), "line: {line}");
    }

    #[test]
    fn long_entry_directory_and_symlink() {
        assert!(format_long_entry("d", &fa(S_IFDIR | 0o755, 4096, 0)).starts_with("drwxr-xr-x"));
        assert!(format_long_entry("l", &fa(S_IFLNK | 0o777, 0, 0)).starts_with("lrwxrwxrwx"));
    }

    #[test]
    fn long_entry_named_owner_group() {
        let attrs = FileAttributes {
            permissions: Some(S_IFREG | 0o600),
            size: Some(7),
            uid: Some(1000),
            gid: Some(1000),
            user: Some("alice".to_string()),
            group: Some("staff".to_string()),
            mtime: Some(0),
            ..FileAttributes::default()
        };
        let line = format_long_entry("x", &attrs);
        assert!(line.contains("alice"), "line: {line}");
        assert!(line.contains("staff"), "line: {line}");
    }

    #[test]
    fn long_entry_numeric_owner_group_fallback() {
        let attrs = FileAttributes {
            permissions: Some(S_IFREG | 0o600),
            size: Some(7),
            uid: Some(1001),
            gid: Some(2002),
            mtime: Some(0),
            ..FileAttributes::default()
        };
        let line = format_long_entry("x", &attrs);
        // No symbolic names → numeric uid/gid are rendered.
        assert!(line.contains("1001"), "line: {line}");
        assert!(line.contains("2002"), "line: {line}");
    }

    // -- error mapping ------------------------------------------------------

    #[test]
    fn map_sftp_status_codes() {
        assert_eq!(
            map_sftp_status(&status_err(StatusCode::NoSuchFile)),
            CurlError::RemoteFileNotFound
        );
        assert_eq!(
            map_sftp_status(&status_err(StatusCode::PermissionDenied)),
            CurlError::RemoteAccessDenied
        );
        // Failure and all other status codes collapse to the SSH-layer error.
        assert_eq!(
            map_sftp_status(&status_err(StatusCode::Failure)),
            CurlError::Ssh
        );
        assert_eq!(map_sftp_status(&io_err()), CurlError::Ssh);
    }

    #[test]
    fn is_missing_path_error_set() {
        assert!(is_missing_path_error(&status_err(StatusCode::NoSuchFile)));
        assert!(is_missing_path_error(&status_err(StatusCode::Failure)));
        assert!(!is_missing_path_error(&status_err(
            StatusCode::PermissionDenied
        )));
        assert!(!is_missing_path_error(&io_err()));
    }

    #[test]
    fn sftp_strerror_table() {
        assert_eq!(
            sftp_strerror(Some(StatusCode::NoSuchFile)),
            "No such file or directory"
        );
        assert_eq!(
            sftp_strerror(Some(StatusCode::PermissionDenied)),
            "Permission denied"
        );
        assert_eq!(sftp_strerror(Some(StatusCode::Failure)), "Operation failed");
        assert_eq!(
            sftp_strerror(Some(StatusCode::OpUnsupported)),
            "Operation not supported by SFTP server"
        );
        assert_eq!(sftp_strerror(None), "Unknown error in libssh2");
    }

    #[test]
    fn sftp_status_num_mapping() {
        assert_eq!(sftp_status_num(Some(StatusCode::Ok)), 0);
        assert_eq!(sftp_status_num(Some(StatusCode::NoSuchFile)), 2);
        assert_eq!(sftp_status_num(Some(StatusCode::Failure)), 4);
        assert_eq!(sftp_status_num(Some(StatusCode::OpUnsupported)), 8);
        assert_eq!(sftp_status_num(None), 0);
    }

    #[test]
    fn sftp_status_code_extraction() {
        assert_eq!(
            sftp_status_code(&status_err(StatusCode::NoSuchFile)),
            Some(StatusCode::NoSuchFile)
        );
        // A non-status error yields no SFTP status code.
        assert_eq!(sftp_status_code(&io_err()), None);
    }
}
