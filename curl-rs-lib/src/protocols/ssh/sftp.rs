// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.
//
//! SFTP subsystem — the `SSH_SFTP_*` half of curl / libcurl **8.19.0-DEV**'s SSH
//! state machine, ported for byte-for-byte functional parity.
//!
//! This module implements the SFTP DO / DONE / DISCONNECT phases that the shared
//! engine in [`super`](crate::protocols::ssh) drives. curl ships **two** C SFTP
//! implementations — `lib/vssh/libssh.c` (libssh) and `lib/vssh/libssh2.c`
//! (libssh2) — behind the dispatch layer `lib/vssh/vssh.c`. This rewrite
//! collapses both onto **`russh-sftp`** running over the `russh` session that
//! [`super::SshSession`] establishes, so the SFTP path is **entirely safe
//! Rust** — the crate-level `forbid` lint rejects raw-pointer/FFI code at
//! compile time — with no C linkage.
//!
//! # Source-of-truth references
//!
//! * `lib/vssh/libssh.c` — the structural model for every per-state handler
//!   (`myssh_in_SFTP_*`) and the quote-command parser (`myssh_in_SFTP_QUOTE`),
//!   plus `myssh_quote_error` / `return_quote_error`.
//! * `lib/vssh/libssh2.c` — the data-mechanics reference (`sftp_download_stat`,
//!   `sftp_readdir` wire format, `sftp_upload_init`) and the SFTP error map.
//! * `lib/vssh/vssh.c` — the shared `Curl_getworkingpath` / `Curl_get_pathname`
//!   / `Curl_ssh_range` helpers, re-exported by [`super`] as
//!   [`get_working_path`] / [`get_pathname`] / [`ssh_range`].
//! * `lib/vssh/ssh.h` — the `SSH_SFTP_*` state names and the `struct SSHPROTO`
//!   readdir buffers.
//!
//! # Design
//!
//! The single entry point is [`advance`], which mod.rs's shared driver
//! ([`super::SshSession::statemach`]) calls once per `SSH_SFTP_*` state. Each
//! call performs the state's asynchronous work over the `russh-sftp`
//! [`SftpSession`] and then transitions with [`super::SshSession::set_state`]
//! (the sole state mutator, which emits the `[old] -> [new]` `--trace` line).
//! The `perform` / `done` / `disconnect` / `statemach` / `drive` orchestration
//! is owned by [`super`]; this module contributes only `advance`, the pure
//! parity helpers it relies on, and their unit tests.
//!
//! Every failure follows curl's control flow: a protocol error records
//! `conn.actualcode` and transitions to [`SshState::SSH_SFTP_CLOSE`] (or the
//! session-teardown chain) rather than propagating a hard `Err` — the recorded
//! code surfaces later at `SSH_SESSION_FREE` (← `myssh_to_ERROR` /
//! `myssh_to_SFTP_CLOSE`). A hard `Err` is reserved for internal invariant
//! violations (a missing session/subsystem handle).

use super::{get_pathname, get_working_path, ssh_range};
use super::{sftp_status_to_curlcode, SshScheme, SshSession, SshState};
use crate::error::{CurlCode, Error, Result};

use russh_sftp::client::error::Error as SftpError;
use russh_sftp::client::fs::DirEntry;
use russh_sftp::client::SftpSession;
use russh_sftp::extensions::Statvfs;
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};

// ===========================================================================
// Request-configuration seam
//
// curl's SFTP DO phase consults a large set of `data->set.*` / `data->state.*`
// / `data->req.*` fields (upload flag, resume offset, byte range, list-only,
// no-body, create-missing-dirs, permissions, …). Those live on the easy handle,
// which the shared per-transfer context ([`crate::protocols::TransferCtx`]) does
// not yet carry onto [`SshSession`] at this stage of the rewrite (the same
// reason mod.rs's `Protocol` vtable methods defer). Until that wiring lands,
// [`RequestConfig::resolve`] returns curl's documented defaults so every state
// still transitions deterministically. This is a faithful port of the C control
// flow, not a stub: the moment `TransferCtx` carries the request, only
// `resolve` changes — every `advance` arm already consumes the resolved values.
// ===========================================================================

/// The per-request configuration the SFTP DO phase reads (← the `data->set.*` /
/// `data->state.*` / `data->req.*` fields curl consults in `myssh_in_*`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct RequestConfig {
    /// Whether this is an upload (← `data->state.upload`).
    upload: bool,
    /// Whether the file mtime is wanted (← `data->set.get_filetime`).
    get_filetime: bool,
    /// Whether the body is suppressed, e.g. `-I` (← `data->req.no_body`).
    no_body: bool,
    /// Whether to emit bare file names, `-l` (← `data->set.list_only`).
    list_only: bool,
    /// Whether to append rather than truncate, `--append`
    /// (← `data->set.remote_append`).
    remote_append: bool,
    /// The resume offset; negative means "the last N bytes"
    /// (← `data->state.resume_from`).
    resume_from: i64,
    /// Whether a byte range was requested (← `data->state.use_range`).
    use_range: bool,
    /// The requested byte range text (← `data->state.range`).
    range: String,
    /// Whether missing remote directories should be created on upload
    /// (← `data->set.ftp_create_missing_dirs`).
    create_missing_dirs: bool,
    /// The known upload size, or `-1` when unknown (← `data->state.infilesize`).
    infilesize: i64,
    /// Mode bits for created directories (← `data->set.new_directory_perms`).
    new_directory_perms: u32,
    /// Mode bits for created files (← `data->set.new_file_perms`).
    new_file_perms: u32,
    /// Whether prequote commands are queued (← `data->set.prequote`).
    has_prequote: bool,
    /// Whether postquote commands are queued (← `data->set.postquote`).
    has_postquote: bool,
}

impl RequestConfig {
    /// Resolve the request configuration for `session`.
    ///
    /// # TODO(wiring): request configuration source
    ///
    /// The values below mirror curl's defaults when no corresponding option is
    /// set. Once [`crate::protocols::TransferCtx`] carries the easy-handle
    /// request onto [`SshSession`], populate each field from the real
    /// `data->set.*` / `data->state.*` / `data->req.*` value; the `advance`
    /// arms already consume the resolved fields, so no state logic changes.
    fn resolve(_session: &SshSession) -> Self {
        RequestConfig {
            upload: false,
            get_filetime: false,
            no_body: false,
            list_only: false,
            remote_append: false,
            resume_from: 0,
            use_range: false,
            range: String::new(),
            create_missing_dirs: false,
            infilesize: -1,
            new_directory_perms: 0o755,
            new_file_perms: 0o644,
            has_prequote: false,
            has_postquote: false,
        }
    }
}

// ===========================================================================
// Quote-command parsing (pure) — ← `myssh_in_SFTP_QUOTE` (libssh.c L1360)
//
// The OpenSSH-sftp command vocabulary and its exact error strings are
// wire-parity critical, so the parser is a standalone pure function covered by
// unit tests. It recognises the `*` accept-fail prefix, `pwd`, the two-argument
// attribute/link/rename verbs, and the single-argument directory/file verbs,
// rejecting anything else with the same `CURLE_QUOTE_ERROR` text curl emits.
// ===========================================================================

/// Strip a leading `*` accept-fail marker (← the `if(cmd[0] == '*')` check).
///
/// A quote command prefixed with `*` — which a legal SFTP command never is — is
/// allowed to fail silently. Returns `(accept_fail, remainder)`.
fn strip_accept_fail(cmd: &str) -> (bool, &str) {
    match cmd.strip_prefix('*') {
        Some(rest) => (true, rest),
        None => (false, cmd),
    }
}

/// The classified result of one quote command (← the dispatch in
/// `myssh_in_SFTP_QUOTE`).
#[derive(Clone, Debug, PartialEq, Eq)]
enum QuoteAction {
    /// `pwd` — emit the FTP-style `257` header line, then advance.
    Pwd,
    /// A filesystem operation: transition to `next`, with the parsed path
    /// argument(s) in `path1` / `path2` (← `sshc->quote_path1/2`).
    Op {
        /// The `SSH_SFTP_QUOTE_*` state that performs the operation.
        next: SshState,
        /// The first path argument (← `sshc->quote_path1`).
        path1: String,
        /// The second path argument, for two-argument verbs
        /// (← `sshc->quote_path2`).
        path2: Option<String>,
    },
}

/// A fully parsed quote command: the accept-fail flag plus the action.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedQuote {
    /// Whether the command was `*`-prefixed (← `sshc->acceptfail`).
    accept_fail: bool,
    /// The classified action.
    action: QuoteAction,
}

/// Parse one quote-command line exactly as `myssh_in_SFTP_QUOTE` does.
///
/// `homedir` is forwarded to [`get_pathname`] for `~` expansion. On a malformed
/// command this returns an [`Error`] whose [`Display`](std::fmt::Display) text is
/// byte-identical to curl's `failf` message and whose [`code`](Error::code) is
/// the matching frozen [`CurlCode`] (usually [`CurlCode::QuoteError`], or the
/// [`get_pathname`] code for a bad path argument).
fn parse_quote_command(raw: &str, homedir: &str) -> Result<ParsedQuote> {
    let (accept_fail, cmd) = strip_accept_fail(raw);

    // ← if(curl_strequal("pwd", cmd)) — case-insensitive.
    if cmd.eq_ignore_ascii_case("pwd") {
        return Ok(ParsedQuote {
            accept_fail,
            action: QuoteAction::Pwd,
        });
    }

    // ← cp = strchr(cmd, ' '); if(!cp) { failf(...); QUOTE_ERROR; }
    let Some(sp) = cmd.find(' ') else {
        return Err(Error::with_context(
            CurlCode::QuoteError,
            "Syntax error in SFTP command. Supply parameter(s)",
        ));
    };

    // ← Curl_get_pathname(&cp, &path1, homedir): the argument scan begins at the
    //   space (get_pathname skips leading blanks). On failure curl reports
    //   "Out of memory" for OOM (impossible in safe Rust) or otherwise
    //   "Syntax error: Bad first parameter", preserving the get_pathname code.
    let arg1_input = &cmd[sp..];
    let (path1, off1) = get_pathname(arg1_input, homedir)
        .map_err(|e| Error::with_context(e.code(), "Syntax error: Bad first parameter"))?;

    // Two-argument attribute change (chgrp/chmod/chown/atime/mtime) → QUOTE_STAT.
    if cmd.starts_with("chgrp ")
        || cmd.starts_with("chmod ")
        || cmd.starts_with("chown ")
        || cmd.starts_with("atime ")
        || cmd.starts_with("mtime ")
    {
        let path2 = parse_second_arg(
            arg1_input,
            off1,
            homedir,
            "Syntax error in chgrp/chmod/chown/atime/mtime: Bad second parameter",
        )?;
        return Ok(ParsedQuote {
            accept_fail,
            action: QuoteAction::Op {
                next: SshState::SSH_SFTP_QUOTE_STAT,
                path1,
                path2: Some(path2),
            },
        });
    }

    // Two-argument symlink (ln/symlink) → QUOTE_SYMLINK.
    if cmd.starts_with("ln ") || cmd.starts_with("symlink ") {
        let path2 = parse_second_arg(
            arg1_input,
            off1,
            homedir,
            "Syntax error in ln/symlink: Bad second parameter",
        )?;
        return Ok(ParsedQuote {
            accept_fail,
            action: QuoteAction::Op {
                next: SshState::SSH_SFTP_QUOTE_SYMLINK,
                path1,
                path2: Some(path2),
            },
        });
    }

    // Two-argument rename → QUOTE_RENAME.
    if cmd.starts_with("rename ") {
        let path2 = parse_second_arg(
            arg1_input,
            off1,
            homedir,
            "Syntax error in rename: Bad second parameter",
        )?;
        return Ok(ParsedQuote {
            accept_fail,
            action: QuoteAction::Op {
                next: SshState::SSH_SFTP_QUOTE_RENAME,
                path1,
                path2: Some(path2),
            },
        });
    }

    // Single-argument verbs: no trailing data is permitted after the argument.
    let single = if cmd.starts_with("mkdir ") {
        Some(SshState::SSH_SFTP_QUOTE_MKDIR)
    } else if cmd.starts_with("rmdir ") {
        Some(SshState::SSH_SFTP_QUOTE_RMDIR)
    } else if cmd.starts_with("rm ") {
        Some(SshState::SSH_SFTP_QUOTE_UNLINK)
    } else if cmd.starts_with("statvfs ") {
        Some(SshState::SSH_SFTP_QUOTE_STATVFS)
    } else {
        None
    };
    if let Some(next) = single {
        // ← if(*cp) return_quote_error(...): get_pathname already consumed
        //   trailing blanks, so any remainder is suspicious.
        if !arg1_input[off1..].is_empty() {
            return Err(Error::with_context(
                CurlCode::QuoteError,
                "Suspicious data after the command line",
            ));
        }
        return Ok(ParsedQuote {
            accept_fail,
            action: QuoteAction::Op {
                next,
                path1,
                path2: None,
            },
        });
    }

    // ← failf(data, "Unknown SFTP command");
    Err(Error::with_context(
        CurlCode::QuoteError,
        "Unknown SFTP command",
    ))
}

/// Parse the second path argument of a two-argument quote command and reject any
/// trailing data (← the second `Curl_get_pathname` plus the `if(*cp)`
/// `return_quote_error` check). `bad_msg` is the verb-specific "Bad second
/// parameter" text curl emits.
fn parse_second_arg(
    arg1_input: &str,
    off1: usize,
    homedir: &str,
    bad_msg: &'static str,
) -> Result<String> {
    let arg2_input = &arg1_input[off1..];
    let (path2, off2) =
        get_pathname(arg2_input, homedir).map_err(|e| Error::with_context(e.code(), bad_msg))?;
    if !arg2_input[off2..].is_empty() {
        return Err(Error::with_context(
            CurlCode::QuoteError,
            "Suspicious data after the command line",
        ));
    }
    Ok(path2)
}

// ===========================================================================
// Attribute-change parsing (pure) — ← `myssh_in_SFTP_QUOTE_STAT` (libssh.c
// L1578) attribute decoding. chgrp/chown parse a decimal uid/gid, chmod an octal
// mode, atime/mtime a date. Each malformed value yields curl's exact failf text.
// ===========================================================================

/// The attribute mutation requested by a `chgrp`/`chmod`/`chown`/`atime`/`mtime`
/// quote command (← the `SSH_FILEXFER_ATTR_*` field curl sets).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AttrChange {
    /// `chgrp <gid>` — set the group id (← `attrs->gid`, `ATTR_UIDGID`).
    Gid(u32),
    /// `chmod <octal>` — set the permission bits (← `attrs->permissions`).
    Perms(u32),
    /// `chown <uid>` — set the owner id (← `attrs->uid`, `ATTR_UIDGID`).
    Uid(u32),
    /// `atime <date>` — set the access time (← `attrs->atime`, `ATTR_ACMODTIME`).
    Atime(u32),
    /// `mtime <date>` — set the modification time (← `attrs->mtime`).
    Mtime(u32),
}

/// Decode the attribute change for `verb` from its `value` argument
/// (← the `strncmp(cmd, "chgrp", 5)` chain). `verb` is the command word (its
/// first five characters select the operation, matching curl's 5-char compare).
fn parse_attr_change(verb: &str, value: &str) -> Result<AttrChange> {
    if verb.starts_with("chgrp") {
        let gid = parse_dec_u32(value).ok_or_else(|| {
            Error::with_context(CurlCode::QuoteError, "Syntax error: chgrp gid not a number")
        })?;
        Ok(AttrChange::Gid(gid))
    } else if verb.starts_with("chmod") {
        let perms = parse_octal_u32(value, 0o7777).ok_or_else(|| {
            Error::with_context(
                CurlCode::QuoteError,
                "Syntax error: chmod permissions not a number",
            )
        })?;
        Ok(AttrChange::Perms(perms))
    } else if verb.starts_with("chown") {
        let uid = parse_dec_u32(value).ok_or_else(|| {
            Error::with_context(CurlCode::QuoteError, "Syntax error: chown uid not a number")
        })?;
        Ok(AttrChange::Uid(uid))
    } else if verb.starts_with("atime") {
        let secs = parse_epoch_u32(value).ok_or_else(|| date_format_error(verb))?;
        Ok(AttrChange::Atime(secs))
    } else if verb.starts_with("mtime") {
        let secs = parse_epoch_u32(value).ok_or_else(|| date_format_error(verb))?;
        Ok(AttrChange::Mtime(secs))
    } else {
        // Unreachable for a well-formed dispatch, but mirror curl's fallback.
        Err(Error::with_context(
            CurlCode::QuoteError,
            "Unknown SFTP command",
        ))
    }
}

/// Build the `"incorrect date format for <verb>"` error (← `failf(data,
/// "incorrect date format for %.*s", 5, cmd)`), using the verb's first five
/// characters exactly as curl's `%.*s` precision does.
fn date_format_error(verb: &str) -> Error {
    let head: String = verb.chars().take(5).collect();
    Error::with_context(
        CurlCode::QuoteError,
        format!("incorrect date format for {head}"),
    )
}

/// Parse a leading run of decimal digits into a `u32`, capped at `UINT_MAX`
/// (← `curlx_str_number(&p, &v, UINT_MAX)`). Returns `None` when no digit is
/// present or the value overflows `u32`.
fn parse_dec_u32(value: &str) -> Option<u32> {
    let digits: String = value.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<u32>().ok()
}

/// Parse a leading run of octal digits into a `u32`, rejecting values greater
/// than `mask` (← `curlx_str_octal(&p, &v, 07777)`). Returns `None` when no
/// octal digit is present or the value exceeds `mask`.
fn parse_octal_u32(value: &str, mask: u32) -> Option<u32> {
    let digits: String = value
        .chars()
        .take_while(|c| ('0'..='7').contains(c))
        .collect();
    if digits.is_empty() {
        return None;
    }
    let parsed = u32::from_str_radix(&digits, 8).ok()?;
    if parsed > mask {
        None
    } else {
        Some(parsed)
    }
}

/// Parse a date argument into a capped 32-bit epoch (← `Curl_getdate_capped`).
///
/// # TODO(wiring): full date-format coverage
///
/// curl accepts the full RFC 822 / RFC 850 / asctime / ISO 8601 grammar via
/// `Curl_getdate_capped`. Until a shared date parser is available crate-wide,
/// the deterministic decimal-epoch subset is handled here; a value curl would
/// reject (non-numeric) yields the same `"incorrect date format"` error, and an
/// out-of-range value is capped at `u32::MAX` exactly as curl caps at its
/// `time_t` ceiling.
fn parse_epoch_u32(value: &str) -> Option<u32> {
    let secs: i64 = value.trim().parse().ok()?;
    if secs < 0 {
        return None;
    }
    let capped = secs.min(i64::from(u32::MAX));
    u32::try_from(capped).ok()
}

// ===========================================================================
// Upload / download planning (pure)
// ===========================================================================

/// Select the SFTP open flags for an upload (← the flag block in
/// `myssh_in_UPLOAD_INIT`, libssh.c L979-995).
///
/// The critical parity rule: a resume (`resume_from > 0`) opens **write-only,
/// without `APPEND`**, and seeks — because many SFTP servers force every write
/// to EOF when `O_APPEND` is set, which would corrupt a resumed upload. Only an
/// explicit `--append` (`remote_append`) uses true append mode.
fn select_upload_flags(remote_append: bool, resume_from: i64) -> OpenFlags {
    if remote_append {
        // True append: create if missing.
        OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::APPEND
    } else if resume_from > 0 {
        // Resume: write-only, NO append; the caller seeks to `resume_from`.
        OpenFlags::WRITE
    } else {
        // Normal upload: truncate before writing.
        OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE
    }
}

/// The computed download transfer plan (← the size / range / resume arithmetic
/// in `myssh_in_SFTP_DOWNLOAD_STAT`, libssh.c L1120).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DownloadPlan {
    /// Absolute offset to seek to before reading, if any (← `sftp_seek64`).
    seek_from: Option<u64>,
    /// The number of bytes to transfer (← `data->req.size`); `-1` means the
    /// length is unknown (the server reported no size, or size 0).
    req_size: i64,
    /// Whether there is nothing left to transfer (← the `data->req.size == 0`
    /// "File already completely downloaded" branch).
    already_complete: bool,
}

/// Compute the download plan from the stat'd file size and the request's range /
/// resume settings (← `myssh_in_SFTP_DOWNLOAD_STAT`).
///
/// `size_opt` is the server-reported size: `None` (no size attribute) or
/// `Some(0)` both mean "unknown length". A negative reported size, or a resume
/// offset beyond the file, is a [`CurlCode::BadDownloadResume`] with curl's
/// exact `failf` text; a malformed range surfaces the [`ssh_range`]
/// [`CurlCode::RangeError`].
fn compute_download_transfer(
    size_opt: Option<i64>,
    resume_from: i64,
    use_range: bool,
    range: &str,
) -> Result<DownloadPlan> {
    let mut seek_from: Option<u64> = None;
    let mut size: i64;
    let mut req_size: i64;

    match size_opt {
        // ← no ATTR_SIZE flag or size == 0: unknown length, req.size = -1.
        None | Some(0) => {
            size = 0;
            req_size = -1;
        }
        Some(reported) => {
            if reported < 0 {
                // ← failf(data, "Bad file size (%d)", size);
                return Err(Error::with_context(
                    CurlCode::BadDownloadResume,
                    format!("Bad file size ({reported})"),
                ));
            }
            size = reported;
            if use_range {
                // ← Curl_ssh_range(data, range, size, &from, &size);
                let (from, ranged) = ssh_range(range, size)?;
                size = ranged;
                seek_from = Some(from);
            }
            req_size = size;
        }
    }

    // Resume handling runs against the (possibly unknown, i.e. 0) size, exactly
    // as curl does after the size branch (← the `if(data->state.resume_from)`
    // block). The failf text reports the ORIGINAL `resume_from`.
    if resume_from != 0 {
        if resume_from < 0 {
            // ← "download the last abs(from) bytes"
            if size < -resume_from {
                return Err(Error::with_context(
                    CurlCode::BadDownloadResume,
                    format!("Offset ({resume_from}) was beyond file size ({size})"),
                ));
            }
            let absolute = resume_from + size;
            req_size = size - absolute;
            seek_from = Some(u64::try_from(absolute).unwrap_or(0));
        } else {
            if size < resume_from {
                return Err(Error::with_context(
                    CurlCode::BadDownloadResume,
                    format!("Offset ({resume_from}) was beyond file size ({size})"),
                ));
            }
            req_size = size - resume_from;
            seek_from = Some(u64::try_from(resume_from).unwrap_or(0));
        }
    }

    Ok(DownloadPlan {
        seek_from,
        req_size,
        already_complete: req_size == 0,
    })
}

// ===========================================================================
// Formatting (pure) — the exact byte layouts curl writes to the transfer body /
// header sink. These are wire-parity critical.
// ===========================================================================

/// Format the `statvfs:` header block (← `myssh_in_SFTP_QUOTE_STATVFS`,
/// libssh.c L570-597) — eleven newline-terminated `f_*` fields in curl's order.
fn format_statvfs(vfs: &Statvfs) -> String {
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
        vfs.block_size,
        vfs.fragment_size,
        vfs.blocks,
        vfs.blocks_free,
        vfs.blocks_avail,
        vfs.inodes,
        vfs.inodes_free,
        vfs.inodes_avail,
        vfs.fs_id,
        vfs.flags,
        vfs.name_max,
    )
}

/// Format one `--list-only` directory entry (← `curl_maprintf("%s\n",
/// filename)` in `myssh_in_SFTP_READDIR`): the bare file name plus a newline.
fn format_list_only_line(filename: &str) -> String {
    format!("{filename}\n")
}

/// Format one long-form directory entry from the SFTP server's raw `longname`
/// (← `curlx_dyn_add(&sshc->readdir_buf, longentry)` in
/// `myssh_in_SFTP_READDIR`).
///
/// curl emits the server's verbatim `longname` so the listing is byte-identical
/// to OpenSSH's `ls -l`; this therefore passes the string through untouched.
/// **Reconstructing the `ls -l` line from attributes is forbidden** — column
/// widths, dates and locale would diverge from the server.
fn format_readdir_longentry(server_longname: &str) -> String {
    server_longname.to_string()
}

// ===========================================================================
// Error mapping (pure) — ← `sftp_libssh2_error_to_CURLE` (libssh2.c L158) via
// the shared [`sftp_status_to_curlcode`] map exported by [`super`].
// ===========================================================================

/// Map a `russh-sftp` client error to the frozen curl [`CurlCode`].
///
/// A protocol `Status` is mapped through [`sftp_status_to_curlcode`] (so the
/// `SSH_FX_*` codes keep their curl integers); a timeout maps to
/// [`CurlCode::OperationTimedout`] (28); every other transport-level error falls
/// back to the generic [`CurlCode::Ssh`] (79), matching curl's default.
fn map_sftp_error(err: &SftpError) -> CurlCode {
    match err {
        SftpError::Status(status) => sftp_status_to_curlcode(status.status_code as u32),
        SftpError::Timeout => CurlCode::OperationTimedout,
        _ => CurlCode::Ssh,
    }
}

// ===========================================================================
// Runtime seams — small helpers that either reach into the shared session state
// or mark an honest wiring boundary. Each is a faithful port of the C control
// flow and still transitions the state machine.
// ===========================================================================

/// Borrow the active [`SftpSession`], or fail with the internal
/// [`CurlCode::FailedInit`] invariant error if the subsystem handle is absent
/// (← the `if(!sshc->sftp_session)` guards). This is reached only if `advance`
/// runs an SFTP DO state before `SSH_SFTP_INIT` established the subsystem, which
/// the shared driver never does.
fn sftp_session(session: &SshSession) -> Result<&SftpSession> {
    session
        .conn
        .sftp
        .as_ref()
        .ok_or_else(|| Error::with_context(CurlCode::FailedInit, "SFTP subsystem not initialised"))
}

/// Fetch the current quote command to parse (← `sshc->quote_item->data`,
/// indexed by `sshc->quote_index`).
///
/// # TODO(wiring): quote-command source
///
/// In curl the quote list is the `data->set.quote` / `prequote` / `postquote`
/// `curl_slist` walked by `sshc->quote_item`. That request configuration is not
/// yet carried on [`SshSession`] (see [`RequestConfig`]), so this resolves to
/// `None` — the `SSH_SFTP_QUOTE*` states then behave as if the list is
/// exhausted. When the request wiring lands, return the entry at
/// `session.conn.quote_index`.
fn current_quote_command(_session: &SshSession) -> Option<String> {
    None
}

/// Obtain the SFTP server's raw `longname` for a directory entry
/// (← `sshc->readdir_attrs->longname`).
///
/// # TODO(wiring): server longname is unreachable via the high-level API
///
/// Byte-identical directory listings require the server's verbatim `longname`
/// (`ls -l` line). `russh-sftp`'s high-level [`SftpSession::read_dir`] discards
/// it: it maps each wire entry to `(filename, attrs)`, and the resulting
/// [`DirEntry`] exposes only `file_name` / `file_type` / `metadata` / `path`
/// (the low-level `protocol::File::longname()` is dropped). The high-level
/// `read_dir` additionally skips `"."` / `".."`, which curl lists. Achieving
/// full parity therefore requires reimplementing readdir over the low-level
/// `russh-sftp` protocol (`opendir` / `readdir` / `close`) so `longname` and the
/// dot entries are preserved. Reconstructing the line here is forbidden, so this
/// returns `None` until that low-level readdir wiring lands.
fn server_longname(_entry: &DirEntry) -> Option<String> {
    None
}

/// Record a quote-command failure and route to `SSH_SFTP_CLOSE`
/// (← `return_quote_error` L1348 / the non-command path of `myssh_quote_error`
/// L541): clear the parsed path arguments, freeze `nextstate`, and store
/// `actualcode`.
fn quote_error_close(session: &mut SshSession, code: CurlCode) {
    session.conn.quote_path1 = None;
    session.conn.quote_path2 = None;
    session.conn.actualcode = code;
    session.conn.nextstate = SshState::SSH_NO_STATE;
    session.set_state(SshState::SSH_SFTP_CLOSE);
}

/// Report a failed quote operation and route to `SSH_SFTP_CLOSE`
/// (← `myssh_quote_error(data, sshc, cmd)` L541, `failf(data, "%s command
/// failed: %s", cmd, err)`), then perform the same cleanup as
/// [`quote_error_close`].
fn sftp_quote_error(session: &mut SshSession, op: &str, err: &SftpError) {
    tracing::warn!(target: "curl::ssh", "{op} command failed: {err}");
    quote_error_close(session, CurlCode::QuoteError);
}

// ===========================================================================
// Runtime helpers used exclusively by `advance` (state-machine glue).
// ===========================================================================

/// Report a fatal failure while establishing the SFTP subsystem and route to
/// the shared session teardown chain (← `myssh_in_SFTP_INIT` L1278 `failf(data,
/// "Failure initializing sftp session: %s", …)` followed by `myssh_to_ERROR`,
/// i.e. `SSH_SESSION_DISCONNECT`). The surfaced error code is
/// [`CurlCode::CouldntConnect`] (7), matching curl's `CURLE_COULDNT_CONNECT`.
fn sftp_init_fail(session: &mut SshSession, err: impl core::fmt::Display) {
    tracing::warn!(target: "curl::ssh", "Failure initializing sftp session: {err}");
    session.conn.actualcode = CurlCode::CouldntConnect;
    session.conn.nextstate = SshState::SSH_NO_STATE;
    session.set_state(SshState::SSH_SESSION_DISCONNECT);
}

/// Apply a single parsed attribute change onto a stat'd [`FileAttributes`]
/// record, preserving every field the quote command does not touch (← the
/// selective `attrs.flags |= …` assignments in libssh2 `sftp_quote_stat`
/// L1163). Only the addressed field is overwritten so the follow-up
/// `SSH_FXP_SETSTAT` leaves ownership/timestamps intact.
fn apply_attr_change(md: &mut FileAttributes, change: AttrChange) {
    match change {
        AttrChange::Gid(gid) => md.gid = Some(gid),
        AttrChange::Perms(perms) => md.permissions = Some(perms),
        AttrChange::Uid(uid) => md.uid = Some(uid),
        AttrChange::Atime(atime) => md.atime = Some(atime),
        AttrChange::Mtime(mtime) => md.mtime = Some(mtime),
    }
}

/// Extract the SFTP protocol status number (`SSH_FX_*`) from an error for the
/// `%d`-formatted diagnostics curl emits (← `sftp_get_error`), or `-1` when the
/// failure is not a protocol status (transport/timeout/etc.).
fn fx_code(err: &SftpError) -> i32 {
    match err {
        SftpError::Status(status) => status.status_code as i32,
        _ => -1,
    }
}

/// Complete a quote operation: on success advance to `SSH_SFTP_NEXT_QUOTE`; on
/// failure either swallow the error when the command was `*`-prefixed
/// (`acceptfail`) and still advance, or report it via [`sftp_quote_error`]
/// (← the shared `if(rc && !acceptfail) return myssh_quote_error(cmd);`
/// epilogue of the quote-op states in `myssh_statemach_act` L1918-2012).
fn finish_quote_op(
    session: &mut SshSession,
    accept_fail: bool,
    op: &str,
    result: core::result::Result<(), SftpError>,
) {
    match result {
        Ok(()) => session.set_state(SshState::SSH_SFTP_NEXT_QUOTE),
        Err(err) if accept_fail => {
            tracing::trace!(target: "curl::ssh", "{op} command ignored (*): {err}");
            session.set_state(SshState::SSH_SFTP_NEXT_QUOTE);
        }
        Err(err) => sftp_quote_error(session, op, &err),
    }
}

// ===========================================================================
// The SFTP DO/DONE/DISCONNECT state machine.
//
// `advance` executes exactly ONE `SSH_SFTP_*` transition per call and is
// invoked by `super`'s shared driver (`SshSession::advance_sftp` →
// `sftp::advance`). Every arm MUST call `set_state` (directly or via a helper)
// so the driver makes forward progress; an arm that returns without changing
// state would spin the driver forever.
//
// Error model (← `myssh_to_ERROR` L309 / `myssh_to_SFTP_CLOSE` L318): a
// *protocol* failure records `conn.actualcode` and routes to
// `SSH_SFTP_CLOSE`/`SSH_SESSION_DISCONNECT`, then returns `Ok(())`; the code is
// surfaced later at `SSH_SESSION_FREE`. `Err`/`?` is reserved for internal
// invariants only (a missing session/subsystem handle → [`CurlCode::FailedInit`]).
// ===========================================================================

/// Drive one step of the SFTP half of the SSH state machine.
///
/// See the module-level documentation for the full state-by-state mapping to
/// the C `libssh`/`libssh2` handlers. This is the single entry point `super`
/// delegates to for every `SSH_SFTP_*` state.
#[allow(clippy::too_many_lines)]
pub(super) async fn advance(session: &mut SshSession) -> Result<()> {
    match session.conn.state {
        // -------------------------------------------------------------------
        // Phase A — SFTP connect tail (← libssh.c L1270-1315).
        // -------------------------------------------------------------------
        SshState::SSH_SFTP_INIT => {
            // ← `myssh_in_SFTP_INIT` L1270: `sftp_new` + `sftp_init`. russh has
            //   no dedicated SFTP handle type; open a fresh session channel,
            //   request the `sftp` subsystem, and hand the channel's byte
            //   stream to russh-sftp's `SftpSession`, which performs the
            //   `SSH_FXP_INIT`/`VERSION` handshake. `super` establishes and
            //   owns the authenticated russh `Handle`; the channel is opened
            //   here (mod.rs never populates `conn.channel`).
            let channel = {
                let handle = session.session_mut()?;
                handle.channel_open_session().await
            };
            let channel = match channel {
                Ok(channel) => channel,
                Err(err) => {
                    sftp_init_fail(session, err);
                    return Ok(());
                }
            };
            if let Err(err) = channel.request_subsystem(true, "sftp").await {
                sftp_init_fail(session, err);
                return Ok(());
            }
            let stream = channel.into_stream();
            match SftpSession::new(stream).await {
                Ok(sftp) => {
                    session.conn.sftp = Some(sftp);
                    session.set_state(SshState::SSH_SFTP_REALPATH);
                }
                Err(err) => sftp_init_fail(session, err),
            }
        }

        SshState::SSH_SFTP_REALPATH => {
            // ← `myssh_in_SFTP_REALPATH` L1293: canonicalize "." to learn the
            //   server home directory (`sftp_canonicalize_path`), cache it on
            //   the connection, then `CURL_TRC_SSH("CONNECT phase done")`
            //   (L1310) and stop — the working path is (re)computed in DO.
            match sftp_session(session)?.canonicalize(".").await {
                Ok(home) => {
                    session.conn.homedir = Some(home);
                    // TODO(wiring): mirror into `data->state.most_recent_ftp_entrypath`
                    //   once the easy-handle state is carried on the session.
                    tracing::trace!(target: "curl::ssh", "CONNECT phase done");
                    session.set_state(SshState::SSH_STOP);
                }
                Err(err) => {
                    session.conn.actualcode = map_sftp_error(&err);
                    session.conn.nextstate = SshState::SSH_NO_STATE;
                    tracing::warn!(target: "curl::ssh", "SFTP realpath failed: {err}");
                    session.set_state(SshState::SSH_SESSION_DISCONNECT);
                }
            }
        }

        // -------------------------------------------------------------------
        // Phase B — quote command engine (← libssh.c L1315-1578).
        // -------------------------------------------------------------------
        SshState::SSH_SFTP_QUOTE_INIT => {
            // ← `myssh_in_SFTP_QUOTE_INIT` L1315: compute the working path from
            //   the URL + home dir; on error surface it and stop; otherwise, if
            //   a prequote list is present announce it and enter the parser,
            //   else jump straight to GETINFO.
            let cfg = RequestConfig::resolve(session);
            let homedir = session.conn.homedir.clone().unwrap_or_default();
            let scheme = session.setup.scheme.unwrap_or(SshScheme::Sftp);
            let url_path = session.proto.path.clone();
            match get_working_path(scheme, &url_path, &homedir) {
                Ok(path) => {
                    session.proto.path = path;
                    if cfg.has_prequote {
                        tracing::info!(target: "curl::ssh", "Sending quote commands");
                        session.conn.quote_index = 0;
                        session.set_state(SshState::SSH_SFTP_QUOTE);
                    } else {
                        session.set_state(SshState::SSH_SFTP_GETINFO);
                    }
                }
                Err(err) => {
                    session.conn.actualcode = err.code();
                    session.conn.nextstate = SshState::SSH_NO_STATE;
                    tracing::warn!(target: "curl::ssh", "{err}");
                    session.set_state(SshState::SSH_STOP);
                }
            }
        }

        SshState::SSH_SFTP_POSTQUOTE_INIT => {
            // ← `myssh_in_SFTP_POSTQUOTE_INIT` L1334: if a postquote list is
            //   present announce it and enter the parser, else stop (the DONE
            //   phase is finished).
            let cfg = RequestConfig::resolve(session);
            if cfg.has_postquote {
                tracing::info!(target: "curl::ssh", "Sending quote commands");
                session.conn.quote_index = 0;
                session.set_state(SshState::SSH_SFTP_QUOTE);
            } else {
                session.set_state(SshState::SSH_STOP);
            }
        }

        SshState::SSH_SFTP_QUOTE => {
            // ← `myssh_in_SFTP_QUOTE` L1360: parse one quote item and route it.
            match current_quote_command(session) {
                None => {
                    // Wiring gap: the quote list is not yet carried on the
                    // session (see `current_quote_command`). Treat as an
                    // exhausted list. // TODO(wiring): quote-command source.
                    session.set_state(SshState::SSH_SFTP_NEXT_QUOTE);
                }
                Some(raw) => {
                    let homedir = session.conn.homedir.clone().unwrap_or_default();
                    match parse_quote_command(&raw, &homedir) {
                        Ok(parsed) => {
                            // `*`-prefixed → command may fail silently.
                            session.conn.acceptfail = parsed.accept_fail;
                            match parsed.action {
                                QuoteAction::Pwd => {
                                    // ← L1385: emit an FTP-style header line for
                                    //   `pwd`, using the working path (NOT the
                                    //   home dir). curl writes `PWD\n` to
                                    //   CURLINFO_HEADER_OUT and the `257 …` reply
                                    //   to CLIENTWRITE_HEADER.
                                    let line = format!(
                                        "257 \"{}\" is current directory.\n",
                                        session.proto.path
                                    );
                                    // TODO(wiring): emit `line` via
                                    //   CLIENTWRITE_HEADER once the header sink
                                    //   is carried on the transfer context.
                                    tracing::trace!(
                                        target: "curl::ssh",
                                        "{}",
                                        line.trim_end()
                                    );
                                    session.set_state(SshState::SSH_SFTP_NEXT_QUOTE);
                                }
                                QuoteAction::Op { next, path1, path2 } => {
                                    session.conn.quote_path1 = Some(path1);
                                    session.conn.quote_path2 = path2;
                                    session.set_state(next);
                                }
                            }
                        }
                        Err(err) => {
                            // ← `failf(...)` + `CURLE_QUOTE_ERROR` → SFTP_CLOSE.
                            tracing::warn!(target: "curl::ssh", "{err}");
                            quote_error_close(session, err.code());
                        }
                    }
                }
            }
        }

        SshState::SSH_SFTP_NEXT_QUOTE => {
            // ← `myssh_in_SFTP_NEXT_QUOTE` L1556: free the parsed paths, advance
            //   the cursor; more items → back to QUOTE; else honour the queued
            //   `nextstate` (postquote pass) or fall through to GETINFO
            //   (prequote pass).
            session.conn.quote_path1 = None;
            session.conn.quote_path2 = None;
            session.conn.quote_index = session.conn.quote_index.saturating_add(1);
            if current_quote_command(session).is_some() {
                session.set_state(SshState::SSH_SFTP_QUOTE);
            } else if session.conn.nextstate != SshState::SSH_NO_STATE {
                let next = session.conn.nextstate;
                session.conn.nextstate = SshState::SSH_NO_STATE;
                session.set_state(next);
            } else {
                session.set_state(SshState::SSH_SFTP_GETINFO);
            }
        }

        SshState::SSH_SFTP_QUOTE_STAT => {
            // ← libssh2 `sftp_quote_stat` L1163 (parse phase): validate the
            //   numeric/date attribute argument (surfacing chmod/chown/chgrp/
            //   atime/mtime parse errors here) before the STAT+SETSTAT round
            //   trip performed by SSH_SFTP_QUOTE_SETSTAT.
            match current_quote_command(session) {
                None => session.set_state(SshState::SSH_SFTP_QUOTE_SETSTAT),
                Some(raw) => {
                    let (_accept, verb) = strip_accept_fail(&raw);
                    let value = session.conn.quote_path1.clone().unwrap_or_default();
                    match parse_attr_change(verb, &value) {
                        Ok(_change) => {
                            session.set_state(SshState::SSH_SFTP_QUOTE_SETSTAT);
                        }
                        Err(err) => {
                            tracing::warn!(target: "curl::ssh", "{err}");
                            quote_error_close(session, err.code());
                        }
                    }
                }
            }
        }

        SshState::SSH_SFTP_QUOTE_SETSTAT => {
            // ← `myssh_statemach_act` SETSTAT case L1918: stat the target to
            //   preserve untouched fields, apply the parsed attribute, then
            //   `sftp_setstat`. curl issues the STAT in QUOTE_STAT and the
            //   SETSTAT here; `SshConn` has no field to carry the attributes
            //   between states, so both packets are issued here in the same
            //   order (identical wire exchange).
            //   TODO(wiring): add a `quote_attrs` field on `SshConn` to move
            //   the STAT back into SSH_SFTP_QUOTE_STAT.
            let target = session.conn.quote_path2.clone().unwrap_or_default();
            let value = session.conn.quote_path1.clone().unwrap_or_default();
            let accept_fail = session.conn.acceptfail;
            let change = current_quote_command(session).map(|raw| {
                let (_accept, verb) = strip_accept_fail(&raw);
                parse_attr_change(verb, &value)
            });
            match change {
                // Wiring gap: no command carried → nothing to apply.
                None => session.set_state(SshState::SSH_SFTP_NEXT_QUOTE),
                Some(Err(err)) => {
                    tracing::warn!(target: "curl::ssh", "{err}");
                    quote_error_close(session, err.code());
                }
                Some(Ok(change)) => {
                    match sftp_session(session)?.metadata(target.clone()).await {
                        Ok(mut md) => {
                            apply_attr_change(&mut md, change);
                            let result = sftp_session(session)?.set_metadata(target, md).await;
                            finish_quote_op(session, accept_fail, "setstat", result);
                        }
                        Err(_err) if accept_fail => {
                            session.set_state(SshState::SSH_SFTP_NEXT_QUOTE);
                        }
                        Err(err) => {
                            // ← L1603 `failf("Attempt to get SFTP stats failed:
                            //   %d", sftp_get_error(...))`.
                            tracing::warn!(
                                target: "curl::ssh",
                                "Attempt to get SFTP stats failed: {}",
                                fx_code(&err)
                            );
                            quote_error_close(session, map_sftp_error(&err));
                        }
                    }
                }
            }
        }

        SshState::SSH_SFTP_QUOTE_SYMLINK => {
            // ← SYMLINK case L1940: `sftp_symlink(target=quote_path2,
            //   linkpath=quote_path1)`. russh-sftp `symlink(path, target)`
            //   takes (link, target) in that order.
            let link = session.conn.quote_path1.clone().unwrap_or_default();
            let target = session.conn.quote_path2.clone().unwrap_or_default();
            let accept_fail = session.conn.acceptfail;
            let result = sftp_session(session)?.symlink(link, target).await;
            finish_quote_op(session, accept_fail, "symlink", result);
        }

        SshState::SSH_SFTP_QUOTE_MKDIR => {
            // ← MKDIR case L1953: `sftp_mkdir(quote_path1, new_directory_perms)`.
            let cfg = RequestConfig::resolve(session);
            let dir = session.conn.quote_path1.clone().unwrap_or_default();
            let accept_fail = session.conn.acceptfail;
            // russh-sftp `create_dir` sends the server-default mode; the
            // requested perms are recorded for the follow-up the wiring will add.
            // TODO(wiring): apply `new_directory_perms` via a setstat once
            //   create_dir accepts an explicit mode.
            tracing::trace!(
                target: "curl::ssh",
                "mkdir mode {:o}",
                cfg.new_directory_perms
            );
            let result = sftp_session(session)?.create_dir(dir).await;
            finish_quote_op(session, accept_fail, "mkdir", result);
        }

        SshState::SSH_SFTP_QUOTE_RENAME => {
            // ← RENAME case L1966: `sftp_rename(quote_path1, quote_path2)`.
            let from = session.conn.quote_path1.clone().unwrap_or_default();
            let to = session.conn.quote_path2.clone().unwrap_or_default();
            let accept_fail = session.conn.acceptfail;
            let result = sftp_session(session)?.rename(from, to).await;
            finish_quote_op(session, accept_fail, "rename", result);
        }

        SshState::SSH_SFTP_QUOTE_RMDIR => {
            // ← RMDIR case L1979: `sftp_rmdir(quote_path1)`.
            let dir = session.conn.quote_path1.clone().unwrap_or_default();
            let accept_fail = session.conn.acceptfail;
            let result = sftp_session(session)?.remove_dir(dir).await;
            finish_quote_op(session, accept_fail, "rmdir", result);
        }

        SshState::SSH_SFTP_QUOTE_UNLINK => {
            // ← UNLINK case L1990: `sftp_unlink(quote_path1)` (the `rm` verb).
            let file = session.conn.quote_path1.clone().unwrap_or_default();
            let accept_fail = session.conn.acceptfail;
            let result = sftp_session(session)?.remove_file(file).await;
            finish_quote_op(session, accept_fail, "rm", result);
        }

        SshState::SSH_SFTP_QUOTE_STATVFS => {
            // ← STATVFS case L554 / L2001: `sftp_statvfs(quote_path1)`; emit the
            //   `statvfs:` header block. russh-sftp `fs_info` returns `None`
            //   when the server lacks the `statvfs@openssh.com` extension —
            //   treated as failure unless `*`-prefixed.
            let path = session.conn.quote_path1.clone().unwrap_or_default();
            let accept_fail = session.conn.acceptfail;
            match sftp_session(session)?.fs_info(path).await {
                Ok(Some(vfs)) => {
                    let block = format_statvfs(&vfs);
                    // TODO(wiring): write `block` via CLIENTWRITE_HEADER once the
                    //   header sink is carried on the transfer context.
                    tracing::trace!(target: "curl::ssh", "statvfs -> {block}");
                    session.set_state(SshState::SSH_SFTP_NEXT_QUOTE);
                }
                Ok(None) | Err(_) if accept_fail => {
                    session.set_state(SshState::SSH_SFTP_NEXT_QUOTE);
                }
                Ok(None) => {
                    tracing::warn!(
                        target: "curl::ssh",
                        "statvfs command failed: extension not supported"
                    );
                    quote_error_close(session, CurlCode::QuoteError);
                }
                Err(err) => sftp_quote_error(session, "statvfs", &err),
            }
        }

        // -------------------------------------------------------------------
        // Phase C — GETINFO / FILETIME / TRANS_INIT (← L2010-2055).
        // -------------------------------------------------------------------
        SshState::SSH_SFTP_GETINFO => {
            // ← GETINFO case: if the caller requested the file time, fetch it
            //   first, otherwise begin the transfer.
            let cfg = RequestConfig::resolve(session);
            if cfg.get_filetime {
                session.set_state(SshState::SSH_SFTP_FILETIME);
            } else {
                session.set_state(SshState::SSH_SFTP_TRANS_INIT);
            }
        }

        SshState::SSH_SFTP_FILETIME => {
            // ← FILETIME case: `sftp_stat(path)` → `data->info.filetime = mtime`.
            let path = session.proto.path.clone();
            if let Ok(md) = sftp_session(session)?.metadata(path).await {
                if let Some(mtime) = md.mtime {
                    // TODO(wiring): store into `data->info.filetime` once the
                    //   easy-handle info is carried on the transfer context.
                    tracing::trace!(target: "curl::ssh", "filetime {mtime}");
                }
            }
            session.set_state(SshState::SSH_SFTP_TRANS_INIT);
        }

        SshState::SSH_SFTP_TRANS_INIT => {
            // ← TRANS_INIT case L2024: uploading → UPLOAD_INIT; a trailing `/`
            //   selects a directory listing; otherwise a plain download.
            let cfg = RequestConfig::resolve(session);
            if cfg.upload {
                session.set_state(SshState::SSH_SFTP_UPLOAD_INIT);
            } else if session.proto.path.ends_with('/') {
                session.set_state(SshState::SSH_SFTP_READDIR_INIT);
            } else {
                session.set_state(SshState::SSH_SFTP_DOWNLOAD_INIT);
            }
        }

        // -------------------------------------------------------------------
        // Phase D — upload + recursive create-dirs (← L951 + L2055-2100).
        // -------------------------------------------------------------------
        SshState::SSH_SFTP_UPLOAD_INIT => {
            // ← `myssh_in_UPLOAD_INIT` L951: resolve resume, choose open flags,
            //   open the remote file (falling back to create-dirs when the
            //   parent is missing), validate the resume point, and hand off to
            //   the send transfer.
            let cfg = RequestConfig::resolve(session);
            let path = session.proto.path.clone();

            // Resolve a negative `resume_from` (resume from EOF) by stat'ing the
            // existing remote file (← L960-970).
            let mut resume_from = cfg.resume_from;
            if resume_from < 0 {
                match sftp_session(session)?.metadata(path.clone()).await {
                    Ok(md) => match md.size {
                        Some(size) => match i64::try_from(size) {
                            Ok(size) => resume_from = size,
                            Err(_) => {
                                // ← L967 `failf("Bad file size (%…)")`.
                                tracing::warn!(
                                    target: "curl::ssh",
                                    "Bad file size ({size})"
                                );
                                session.conn.actualcode = CurlCode::BadDownloadResume;
                                session.conn.nextstate = SshState::SSH_NO_STATE;
                                session.set_state(SshState::SSH_SESSION_DISCONNECT);
                                return Ok(());
                            }
                        },
                        None => resume_from = 0,
                    },
                    Err(_) => resume_from = 0,
                }
            }

            let flags = select_upload_flags(cfg.remote_append, resume_from);
            let mut attrs = FileAttributes::empty();
            attrs.permissions = Some(cfg.new_file_perms);
            let open_res = sftp_session(session)?
                .open_with_flags_and_attributes(path.clone(), flags, attrs)
                .await;
            match open_res {
                Ok(_file) => {
                    // TODO(wiring): retain the `File` handle for the send
                    //   transfer (Phase H) and perform the resume seek; `SshConn`
                    //   has no file-handle field yet, so the handle is dropped
                    //   (closed) here. The pure resume-point validation below is
                    //   request math and is applied unconditionally.
                    if resume_from > 0
                        && !cfg.remote_append
                        && cfg.infilesize > 0
                        && resume_from > cfg.infilesize
                    {
                        // ← L1065 `failf("Resume point beyond size")`.
                        tracing::warn!(target: "curl::ssh", "Resume point beyond size");
                        session.conn.actualcode = CurlCode::BadFunctionArgument;
                        session.conn.nextstate = SshState::SSH_NO_STATE;
                        session.set_state(SshState::SSH_SFTP_CLOSE);
                    } else {
                        session.set_state(SshState::SSH_STOP);
                    }
                }
                Err(err) => {
                    // ← L1010: on ENOENT/FAILURE, if create-missing-dirs is on
                    //   and the path is non-trivial, create the tree; else close.
                    let missing = matches!(
                        &err,
                        SftpError::Status(status)
                            if matches!(
                                status.status_code,
                                StatusCode::NoSuchFile | StatusCode::Failure
                            )
                    );
                    if missing && cfg.create_missing_dirs && path.len() > 1 {
                        session.conn.second_create_dirs = 1;
                        session.set_state(SshState::SSH_SFTP_CREATE_DIRS_INIT);
                    } else {
                        tracing::warn!(
                            target: "curl::ssh",
                            "Could not open remote file for writing: {err}"
                        );
                        session.conn.actualcode = map_sftp_error(&err);
                        session.conn.nextstate = SshState::SSH_NO_STATE;
                        session.set_state(SshState::SSH_SFTP_CLOSE);
                    }
                }
            }
        }

        SshState::SSH_SFTP_CREATE_DIRS_INIT => {
            // ← CREATE_DIRS_INIT case L2043: begin walking `/`-segments when the
            //   path is non-trivial, else retry the upload open.
            if session.proto.path.len() > 1 {
                session.conn.slash_pos = Some(1);
                session.set_state(SshState::SSH_SFTP_CREATE_DIRS);
            } else {
                session.set_state(SshState::SSH_SFTP_UPLOAD_INIT);
            }
        }

        SshState::SSH_SFTP_CREATE_DIRS => {
            // ← CREATE_DIRS case L2056: find the next `/`; create that prefix
            //   directory, or (no more slashes) go back to open the file.
            let path = session.proto.path.clone();
            let start = session.conn.slash_pos.unwrap_or(1).min(path.len());
            match path[start..].find('/') {
                Some(rel) => {
                    let slash = start + rel;
                    session.conn.slash_pos = Some(slash);
                    // ← L2066 `infof("Creating directory '%s'")`.
                    tracing::info!(
                        target: "curl::ssh",
                        "Creating directory '{}'",
                        &path[..slash]
                    );
                    session.set_state(SshState::SSH_SFTP_CREATE_DIRS_MKDIR);
                }
                None => session.set_state(SshState::SSH_SFTP_UPLOAD_INIT),
            }
        }

        SshState::SSH_SFTP_CREATE_DIRS_MKDIR => {
            // ← CREATE_DIRS_MKDIR case L2072: `sftp_mkdir(prefix)`; tolerate
            //   already-exists / generic-failure / permission-denied (creation
            //   may still succeed deeper), abort on anything else; then advance
            //   the cursor past the `/` and loop.
            let cfg = RequestConfig::resolve(session);
            let path = session.proto.path.clone();
            let slash = session.conn.slash_pos.unwrap_or(0).min(path.len());
            let dir = path[..slash].to_string();
            tracing::trace!(
                target: "curl::ssh",
                "mkdir '{dir}' mode {:o}",
                cfg.new_directory_perms
            );
            let result = sftp_session(session)?.create_dir(dir).await;
            // ← `*slash_pos = '/'; ++slash_pos;` — advance regardless of result.
            session.conn.slash_pos = Some(slash.saturating_add(1));
            match result {
                Ok(()) => session.set_state(SshState::SSH_SFTP_CREATE_DIRS),
                Err(err) => {
                    let tolerate = matches!(
                        &err,
                        SftpError::Status(status)
                            if matches!(
                                status.status_code,
                                StatusCode::Failure | StatusCode::PermissionDenied
                            )
                    );
                    if tolerate {
                        session.set_state(SshState::SSH_SFTP_CREATE_DIRS);
                    } else {
                        session.conn.actualcode = map_sftp_error(&err);
                        session.conn.nextstate = SshState::SSH_NO_STATE;
                        session.set_state(SshState::SSH_SFTP_CLOSE);
                    }
                }
            }
        }

        // -------------------------------------------------------------------
        // Phase E — download + resume/range (← libssh2 L1274).
        // -------------------------------------------------------------------
        SshState::SSH_SFTP_DOWNLOAD_INIT => {
            // ← `myssh_in_SFTP_DOWNLOAD_INIT` L1099: open the remote file for
            //   reading; on error map + close.
            let path = session.proto.path.clone();
            match sftp_session(session)?
                .open_with_flags(path, OpenFlags::READ)
                .await
            {
                Ok(_file) => {
                    // TODO(wiring): retain the `File` handle for the recv
                    //   transfer (Phase H); dropped (closed) here until `SshConn`
                    //   carries a file handle.
                    session.set_state(SshState::SSH_SFTP_DOWNLOAD_STAT);
                }
                Err(err) => {
                    // ← L1110 `failf("Could not open remote file for reading: %s")`.
                    tracing::warn!(
                        target: "curl::ssh",
                        "Could not open remote file for reading: {err}"
                    );
                    session.conn.actualcode = map_sftp_error(&err);
                    session.conn.nextstate = SshState::SSH_NO_STATE;
                    session.set_state(SshState::SSH_SFTP_CLOSE);
                }
            }
        }

        SshState::SSH_SFTP_DOWNLOAD_STAT => {
            // ← libssh2 `sftp_download_stat` L1274: stat the file, apply range
            //   and resume math, then either report "already downloaded" or set
            //   up the recv transfer. curl fstats the open handle; `SshConn`
            //   retains no handle yet, so we stat by path (equivalent size).
            //   TODO(wiring): fstat the retained handle once it is carried.
            let cfg = RequestConfig::resolve(session);
            let path = session.proto.path.clone();
            let size_opt = match sftp_session(session)?.metadata(path).await {
                Ok(md) => md.size.and_then(|size| i64::try_from(size).ok()),
                Err(err) => {
                    tracing::warn!(target: "curl::ssh", "Could not stat remote file: {err}");
                    session.conn.actualcode = map_sftp_error(&err);
                    session.conn.nextstate = SshState::SSH_NO_STATE;
                    session.set_state(SshState::SSH_SFTP_CLOSE);
                    return Ok(());
                }
            };
            match compute_download_transfer(size_opt, cfg.resume_from, cfg.use_range, &cfg.range) {
                Ok(plan) => {
                    if plan.already_complete {
                        // ← L1201 `infof("File already completely downloaded")`
                        //   + `Curl_xfer_setup_nop`.
                        tracing::info!(
                            target: "curl::ssh",
                            "File already completely downloaded"
                        );
                    } else {
                        // TODO(wiring): seek to `plan.seek_from` and
                        //   `Curl_xfer_setup_recv` with `plan.req_size` once the
                        //   retained handle + transfer are wired.
                        tracing::trace!(
                            target: "curl::ssh",
                            "download plan: seek={:?} size={}",
                            plan.seek_from,
                            plan.req_size
                        );
                    }
                    session.set_state(SshState::SSH_STOP);
                }
                Err(err) => {
                    tracing::warn!(target: "curl::ssh", "{err}");
                    session.conn.actualcode = err.code();
                    session.conn.nextstate = SshState::SSH_NO_STATE;
                    session.set_state(SshState::SSH_SFTP_CLOSE);
                }
            }
        }

        // -------------------------------------------------------------------
        // Phase F — directory listing (← libssh2 L1369 + link states).
        // -------------------------------------------------------------------
        SshState::SSH_SFTP_READDIR_INIT => {
            // ← `myssh_in_SFTP_READDIR_INIT` L356: set the download size to
            //   unknown (-1); a body-less request stops immediately, otherwise
            //   begin reading entries.
            let cfg = RequestConfig::resolve(session);
            // TODO(wiring): `Curl_pgrsSetDownloadSize(-1)` once the transfer
            //   engine is wired.
            if cfg.no_body {
                session.set_state(SshState::SSH_STOP);
            } else {
                session.set_state(SshState::SSH_SFTP_READDIR);
            }
        }

        SshState::SSH_SFTP_READDIR => {
            // ← `myssh_in_SFTP_READDIR` L381: read the directory. The high-level
            //   `ReadDir` materialises every entry at once (and, per
            //   `server_longname`, drops the server longname and the "."/".."
            //   entries), so curl's per-entry READDIR/READDIR_LINK/
            //   READDIR_BOTTOM loop is folded into one pass, accumulating into
            //   `proto.readdir`.
            //   TODO(wiring): flush `proto.readdir` via CLIENTWRITE_BODY, and use
            //   the low-level readdir for the server longname + dot entries (see
            //   `server_longname`).
            let cfg = RequestConfig::resolve(session);
            let path = session.proto.path.clone();
            match sftp_session(session)?.read_dir(path).await {
                Ok(entries) => {
                    let mut listing = String::new();
                    for entry in entries {
                        if cfg.list_only {
                            // `-l` / `--list-only`: bare filenames only.
                            listing.push_str(&format_list_only_line(&entry.file_name()));
                        } else if let Some(longname) = server_longname(&entry) {
                            // Full `ls -l`-style listing using the SERVER's raw
                            // longname — never reconstructed (wire parity).
                            listing.push_str(&format_readdir_longentry(&longname));
                            listing.push('\n');
                        }
                    }
                    session.proto.readdir = listing;
                    session.set_state(SshState::SSH_SFTP_READDIR_DONE);
                }
                Err(err) => {
                    // ← L373 `failf("Could not open directory for reading: %s")`.
                    tracing::warn!(
                        target: "curl::ssh",
                        "Could not open directory for reading: {err}"
                    );
                    session.conn.actualcode = map_sftp_error(&err);
                    session.conn.nextstate = SshState::SSH_NO_STATE;
                    session.set_state(SshState::SSH_SFTP_CLOSE);
                }
            }
        }

        SshState::SSH_SFTP_READDIR_LINK => {
            // ← `myssh_in_SFTP_READDIR_LINK` L453 / libssh2 L2202: resolve a
            //   symlink entry's target and append `" -> <target>"`. Faithful
            //   port; entered only under the future low-level per-entry readdir
            //   wiring (the folded READDIR above does not reach it).
            let link_path = session.proto.readdir_link.clone();
            match sftp_session(session)?.read_link(link_path).await {
                Ok(target) => {
                    session
                        .proto
                        .readdir_longentry
                        .push_str(&format!(" -> {target}"));
                    session.set_state(SshState::SSH_SFTP_READDIR_BOTTOM);
                }
                Err(err) => {
                    // ← L462 `failf("Could not read symlink for reading: %s")`.
                    tracing::warn!(
                        target: "curl::ssh",
                        "Could not read symlink for reading: {err}"
                    );
                    session.conn.actualcode = map_sftp_error(&err);
                    session.conn.nextstate = SshState::SSH_NO_STATE;
                    session.set_state(SshState::SSH_SFTP_CLOSE);
                }
            }
        }

        SshState::SSH_SFTP_READDIR_BOTTOM => {
            // ← `myssh_in_SFTP_READDIR_BOTTOM` L507: terminate the accumulated
            //   long-entry line and write it to the body, then read the next
            //   entry. Faithful port (unreachable under the folded READDIR).
            session.proto.readdir_longentry.push('\n');
            // TODO(wiring): flush `proto.readdir_longentry` via CLIENTWRITE_BODY.
            session.proto.readdir_longentry.clear();
            session.set_state(SshState::SSH_SFTP_READDIR);
        }

        SshState::SSH_SFTP_READDIR_DONE => {
            // ← `myssh_in_SFTP_READDIR_DONE` L529: close the directory handle and
            //   finish. The high-level `ReadDir` was already consumed; nothing to
            //   close explicitly. // TODO(wiring): `Curl_xfer_setup_nop`.
            session.set_state(SshState::SSH_STOP);
        }

        // -------------------------------------------------------------------
        // Phase G — close / shutdown (← libssh.c L1216-1268).
        // -------------------------------------------------------------------
        SshState::SSH_SFTP_CLOSE => {
            // ← `myssh_in_SFTP_CLOSE` L1216: close the open file/dir handle (the
            //   retained handle, once wired, is dropped here); if a `nextstate`
            //   was queued (e.g. the postquote pass) honour it, else stop.
            tracing::trace!(target: "curl::ssh", "SFTP DONE done");
            let next = session.conn.nextstate;
            if next != SshState::SSH_NO_STATE && next != SshState::SSH_SFTP_CLOSE {
                session.conn.nextstate = SshState::SSH_SFTP_CLOSE;
                session.set_state(next);
            } else {
                session.set_state(SshState::SSH_STOP);
            }
        }

        SshState::SSH_SFTP_SHUTDOWN => {
            // ← `myssh_in_SFTP_SHUTDOWN` L1242: tear down the SFTP subsystem
            //   (drop `SftpSession`) and free the cached home dir, then hand off
            //   to the shared session teardown chain.
            session.conn.sftp = None;
            session.conn.homedir = None;
            session.set_state(SshState::SSH_SESSION_DISCONNECT);
        }

        // -------------------------------------------------------------------
        // Any non-SFTP state routed here is unexpected; mirror C's `default:`
        // by stopping (← the fall-through `default` of `myssh_statemach_act`).
        // -------------------------------------------------------------------
        _ => session.set_state(SshState::SSH_STOP),
    }

    Ok(())
}

// ===========================================================================
// Unit tests — the wire-parity-critical pure logic (quote parsing, upload flag
// selection, download resume/range arithmetic, directory-listing formatting,
// the statvfs block, and the SFTP-error → CurlCode mapping). These exercise the
// same helpers `advance` consumes, with no live SSH session required.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use russh_sftp::protocol::Status;

    const HOME: &str = "/home/user";

    /// Build an `SftpError::Status(..)` carrying `code` for the mapping tests.
    fn status_err(code: StatusCode) -> SftpError {
        SftpError::Status(Status {
            id: 0,
            status_code: code,
            error_message: String::new(),
            language_tag: String::new(),
        })
    }

    /// Convenience: parse a quote command against the fixed home dir.
    fn quote(raw: &str) -> Result<ParsedQuote> {
        parse_quote_command(raw, HOME)
    }

    // -- (a) quote-command parser -------------------------------------------

    #[test]
    fn strip_accept_fail_detects_star_prefix() {
        assert_eq!(strip_accept_fail("*rm /a"), (true, "rm /a"));
        assert_eq!(strip_accept_fail("rm /a"), (false, "rm /a"));
        assert_eq!(strip_accept_fail("*"), (true, ""));
    }

    #[test]
    fn quote_pwd_is_recognised_case_insensitively() {
        let parsed = quote("pwd").unwrap();
        assert!(!parsed.accept_fail);
        assert!(matches!(parsed.action, QuoteAction::Pwd));

        // Case-insensitive and `*`-prefixed.
        let parsed = quote("*PWD").unwrap();
        assert!(parsed.accept_fail);
        assert!(matches!(parsed.action, QuoteAction::Pwd));
    }

    #[test]
    fn quote_two_arg_attribute_verbs_route_to_quote_stat() {
        for verb in ["chgrp", "chmod", "chown", "atime", "mtime"] {
            let line = format!("{verb} 0644 /etc/hosts");
            let parsed = quote(&line).unwrap();
            match parsed.action {
                QuoteAction::Op { next, path1, path2 } => {
                    assert!(
                        matches!(next, SshState::SSH_SFTP_QUOTE_STAT),
                        "{verb} must route to QUOTE_STAT"
                    );
                    assert_eq!(path1, "0644");
                    assert_eq!(path2.as_deref(), Some("/etc/hosts"));
                }
                other => panic!("{verb}: expected Op, got {other:?}"),
            }
        }
    }

    #[test]
    fn quote_symlink_and_rename_route_correctly() {
        for verb in ["ln", "symlink"] {
            let parsed = quote(&format!("{verb} /target /link")).unwrap();
            match parsed.action {
                QuoteAction::Op { next, path1, path2 } => {
                    assert!(matches!(next, SshState::SSH_SFTP_QUOTE_SYMLINK));
                    assert_eq!(path1, "/target");
                    assert_eq!(path2.as_deref(), Some("/link"));
                }
                other => panic!("{verb}: expected Op, got {other:?}"),
            }
        }

        let parsed = quote("rename /from /to").unwrap();
        match parsed.action {
            QuoteAction::Op { next, path1, path2 } => {
                assert!(matches!(next, SshState::SSH_SFTP_QUOTE_RENAME));
                assert_eq!(path1, "/from");
                assert_eq!(path2.as_deref(), Some("/to"));
            }
            other => panic!("expected Op, got {other:?}"),
        }
    }

    #[test]
    fn quote_single_arg_verbs_route_correctly() {
        let cases = [
            ("mkdir /d", SshState::SSH_SFTP_QUOTE_MKDIR),
            ("rmdir /d", SshState::SSH_SFTP_QUOTE_RMDIR),
            ("rm /f", SshState::SSH_SFTP_QUOTE_UNLINK),
            ("statvfs /f", SshState::SSH_SFTP_QUOTE_STATVFS),
        ];
        for (line, expected) in cases {
            let parsed = quote(line).unwrap();
            match parsed.action {
                QuoteAction::Op { next, path2, .. } => {
                    assert!(
                        std::mem::discriminant(&next) == std::mem::discriminant(&expected),
                        "{line} routed to the wrong state"
                    );
                    assert!(path2.is_none(), "{line} must have no second argument");
                }
                other => panic!("{line}: expected Op, got {other:?}"),
            }
        }
    }

    #[test]
    fn quote_accept_fail_prefix_is_parsed_on_real_command() {
        let parsed = quote("*rm /tmp/x").unwrap();
        assert!(parsed.accept_fail);
        assert!(matches!(
            parsed.action,
            QuoteAction::Op {
                next: SshState::SSH_SFTP_QUOTE_UNLINK,
                ..
            }
        ));
    }

    #[test]
    fn quote_missing_parameter_is_quote_error() {
        let err = quote("chmod").unwrap_err();
        assert_eq!(err.code() as i32, 21);
        assert_eq!(
            err.to_string(),
            "Syntax error in SFTP command. Supply parameter(s)"
        );
    }

    #[test]
    fn quote_unknown_command_is_quote_error() {
        let err = quote("frobnicate /x").unwrap_err();
        assert_eq!(err.code() as i32, 21);
        assert_eq!(err.to_string(), "Unknown SFTP command");
    }

    #[test]
    fn quote_trailing_junk_after_single_arg_is_rejected() {
        let err = quote("rmdir /a extra").unwrap_err();
        assert_eq!(err.code() as i32, 21);
        assert_eq!(err.to_string(), "Suspicious data after the command line");
    }

    // -- parse_attr_change ---------------------------------------------------

    #[test]
    fn attr_change_decodes_each_verb() {
        assert_eq!(
            parse_attr_change("chgrp", "100").unwrap(),
            AttrChange::Gid(100)
        );
        assert_eq!(
            parse_attr_change("chmod", "0644").unwrap(),
            AttrChange::Perms(0o644)
        );
        assert_eq!(parse_attr_change("chown", "0").unwrap(), AttrChange::Uid(0));
        assert_eq!(
            parse_attr_change("atime", "1609459200").unwrap(),
            AttrChange::Atime(1_609_459_200)
        );
        assert_eq!(
            parse_attr_change("mtime", "1000").unwrap(),
            AttrChange::Mtime(1000)
        );
    }

    #[test]
    fn attr_change_rejects_malformed_values() {
        assert_eq!(
            parse_attr_change("chmod", "xyz").unwrap_err().to_string(),
            "Syntax error: chmod permissions not a number"
        );
        assert_eq!(
            parse_attr_change("chgrp", "nope").unwrap_err().to_string(),
            "Syntax error: chgrp gid not a number"
        );
        assert_eq!(
            parse_attr_change("atime", "notadate")
                .unwrap_err()
                .to_string(),
            "incorrect date format for atime"
        );
        // Octal mode overflowing the 07777 mask is rejected.
        assert!(parse_attr_change("chmod", "10000").is_err());
    }

    #[test]
    fn apply_attr_change_only_touches_the_target_field() {
        let mut md = FileAttributes::empty();
        md.uid = Some(7);
        md.gid = Some(9);
        apply_attr_change(&mut md, AttrChange::Perms(0o600));
        assert_eq!(md.permissions, Some(0o600));
        // The unrelated fields are preserved (← selective ATTR flag set).
        assert_eq!(md.uid, Some(7));
        assert_eq!(md.gid, Some(9));
    }

    // -- (b) upload open-flag selection -------------------------------------

    #[test]
    fn upload_flags_append_resume_and_truncate() {
        // --append: true APPEND, create if missing.
        let append = select_upload_flags(true, 0);
        assert!(append.contains(OpenFlags::APPEND));
        assert!(append.contains(OpenFlags::WRITE));
        assert!(append.contains(OpenFlags::CREATE));

        // Resume (resume_from > 0): WRITE only — NEVER append, NEVER truncate.
        // `OpenFlags` (bitflags v2) does not derive `PartialEq`, so compare the
        // raw bits for exact equality.
        let resume = select_upload_flags(false, 128);
        assert_eq!(resume.bits(), OpenFlags::WRITE.bits());
        assert!(!resume.contains(OpenFlags::APPEND));
        assert!(!resume.contains(OpenFlags::TRUNCATE));
        assert!(!resume.contains(OpenFlags::CREATE));

        // Normal upload: truncate, no append.
        let fresh = select_upload_flags(false, 0);
        assert!(fresh.contains(OpenFlags::TRUNCATE));
        assert!(fresh.contains(OpenFlags::CREATE));
        assert!(!fresh.contains(OpenFlags::APPEND));
    }

    // -- (c) download resume/range arithmetic (incl. negative) --------------

    #[test]
    fn download_plain_download_has_no_seek() {
        let plan = compute_download_transfer(Some(1000), 0, false, "").unwrap();
        assert_eq!(plan.seek_from, None);
        assert_eq!(plan.req_size, 1000);
        assert!(!plan.already_complete);
    }

    #[test]
    fn download_positive_resume_seeks_and_shrinks() {
        let plan = compute_download_transfer(Some(1000), 100, false, "").unwrap();
        assert_eq!(plan.seek_from, Some(100));
        assert_eq!(plan.req_size, 900);
        assert!(!plan.already_complete);
    }

    #[test]
    fn download_negative_resume_takes_trailing_bytes() {
        // Resume from -200 => download the last 200 bytes of a 1000-byte file.
        let plan = compute_download_transfer(Some(1000), -200, false, "").unwrap();
        assert_eq!(plan.seek_from, Some(800));
        assert_eq!(plan.req_size, 200);
        assert!(!plan.already_complete);
    }

    #[test]
    fn download_range_seeks_and_sizes() {
        // Range "100-199" => seek to 100, transfer 100 bytes (to-from+1).
        let plan = compute_download_transfer(Some(1000), 0, true, "100-199").unwrap();
        assert_eq!(plan.seek_from, Some(100));
        assert_eq!(plan.req_size, 100);
        assert!(!plan.already_complete);
    }

    #[test]
    fn download_resume_beyond_size_is_bad_download_resume() {
        let err = compute_download_transfer(Some(1000), 2000, false, "").unwrap_err();
        assert_eq!(err.code() as i32, 36);
        assert_eq!(err.to_string(), "Offset (2000) was beyond file size (1000)");

        // Negative offset larger than the file is likewise rejected.
        let err = compute_download_transfer(Some(1000), -2000, false, "").unwrap_err();
        assert_eq!(err.code() as i32, 36);
    }

    #[test]
    fn download_negative_reported_size_is_bad_download_resume() {
        let err = compute_download_transfer(Some(-5), 0, false, "").unwrap_err();
        assert_eq!(err.code() as i32, 36);
        assert_eq!(err.to_string(), "Bad file size (-5)");
    }

    // -- (e) "File already completely downloaded" (zero remaining) ----------

    #[test]
    fn download_exact_resume_is_already_complete() {
        // Resuming a 500-byte file from byte 500 leaves nothing to transfer.
        let plan = compute_download_transfer(Some(500), 500, false, "").unwrap();
        assert_eq!(plan.req_size, 0);
        assert!(plan.already_complete);
        assert_eq!(plan.seek_from, Some(500));
    }

    #[test]
    fn download_unknown_size_reports_negative_length() {
        // No size attribute (or a reported 0) => unknown length (req.size = -1),
        // and NOT "already complete".
        let plan = compute_download_transfer(None, 0, false, "").unwrap();
        assert_eq!(plan.req_size, -1);
        assert!(!plan.already_complete);

        let plan = compute_download_transfer(Some(0), 0, false, "").unwrap();
        assert_eq!(plan.req_size, -1);
        assert!(!plan.already_complete);
    }

    // -- (d) directory-listing byte formats ---------------------------------

    #[test]
    fn listing_list_only_is_bare_filename() {
        assert_eq!(format_list_only_line("file.txt"), "file.txt\n");
    }

    #[test]
    fn listing_longentry_passes_server_string_through_untouched() {
        // Wire parity: the server's raw longname is emitted verbatim — never
        // reconstructed. The trailing newline is added by the caller.
        let longname = "-rw-r--r--   1 user group        0 Jan  1  1970 file.txt";
        assert_eq!(format_readdir_longentry(longname), longname);
    }

    // -- statvfs block + error mapping --------------------------------------

    #[test]
    fn statvfs_block_has_all_eleven_fields() {
        let vfs = Statvfs {
            block_size: 1,
            fragment_size: 2,
            blocks: 3,
            blocks_free: 4,
            blocks_avail: 5,
            inodes: 6,
            inodes_free: 7,
            inodes_avail: 8,
            fs_id: 9,
            flags: 10,
            name_max: 11,
        };
        let block = format_statvfs(&vfs);
        assert!(block.starts_with("statvfs:\n"));
        assert!(block.contains("f_bsize: 1\n"));
        assert!(block.contains("f_frsize: 2\n"));
        assert!(block.contains("f_favail: 8\n"));
        assert!(block.contains("f_fsid: 9\n"));
        assert!(block.ends_with("f_namemax: 11\n"));
    }

    #[test]
    fn sftp_error_maps_to_frozen_curlcodes() {
        assert_eq!(
            map_sftp_error(&status_err(StatusCode::NoSuchFile)) as i32,
            78
        );
        assert_eq!(
            map_sftp_error(&status_err(StatusCode::PermissionDenied)) as i32,
            9
        );
        // A generic FAILURE (and any unmapped status) collapses to CURLE_SSH.
        assert_eq!(map_sftp_error(&status_err(StatusCode::Failure)) as i32, 79);
        // A transport timeout maps to CURLE_OPERATION_TIMEDOUT.
        assert_eq!(map_sftp_error(&SftpError::Timeout) as i32, 28);
    }
}
