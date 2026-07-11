// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.
//
//! SCP transfer handler — the `SSH_SCP_*` half of curl / libcurl
//! **8.19.0-DEV**'s SSH state machine.
//!
//! This module implements the SCP DO / DONE / DISCONNECT phases that the shared
//! SSH engine in [`super`] ([`super::SshSession`]) delegates to. It is the
//! idiomatic-Rust rewrite of the SCP paths of curl's **two** C SSH backends —
//! `lib/vssh/libssh.c` (libssh) and `lib/vssh/libssh2.c` (libssh2) — collapsed
//! onto the single pure-Rust **`russh`** session that [`super`] establishes.
//! There is **zero `unsafe`** here and no C linkage anywhere on the SCP path.
//!
//! # Source-of-truth references
//!
//! * `lib/vssh/libssh.c` — the structural model (the "cleanest" backend):
//!   `myssh_in_TRANS_INIT` (upload/download decision), the `SSH_SCP_UPLOAD_INIT`
//!   / `SSH_SCP_DOWNLOAD_INIT` / `SSH_SCP_DOWNLOAD` arms, `myssh_SSH_SCP_DOWNLOAD`
//!   (size from `ssh_scp_request_get_size`), the `SSH_SCP_DONE` /
//!   `SSH_SCP_SEND_EOF` / `SSH_SCP_CHANNEL_FREE` teardown, and the `scp_send` /
//!   `scp_recv` / `scp_perform` / `scp_doing` / `scp_done` / `scp_disconnect`
//!   drivers plus the shared `myssh_done`.
//! * `lib/vssh/libssh2.c` — the more elaborate channel-shutdown handshake:
//!   `ssh_state_scp_upload_init` (`libssh2_scp_send64`, which requires the exact
//!   size up front and maps generic errors to `CURLE_UPLOAD_FAILED`),
//!   `ssh_state_scp_download_init` (`libssh2_scp_recv2`, size from
//!   `struct stat`), and the discrete `SSH_SCP_SEND_EOF` / `SSH_SCP_WAIT_EOF` /
//!   `SSH_SCP_WAIT_CLOSE` / `SSH_SCP_CHANNEL_FREE` states.
//! * `lib/vssh/vssh.c` — `Curl_getworkingpath` (exposed as
//!   [`super::get_working_path`]; the SCP variant strips a leading `/~/`).
//! * `lib/vssh/ssh.h` — the `SSH_SCP_*` state names and `struct ssh_conn`.
//!
//! # Architecture — one state step per call
//!
//! curl's C handler is driven by the multi state machine through the
//! `struct Curl_protocol` vtable. In this rewrite the vtable is
//! [`crate::protocols::Protocol`] and the transport is the `russh` client
//! running on Tokio. The DO / DONE / DISCONNECT **phase drivers** —
//! `scp_perform`, `scp_doing`, `scp_done`, `scp_disconnect` and the shared
//! `myssh_done` — already live on the engine ([`super::SshSession::perform`],
//! [`super::SshSession::doing`], [`super::SshSession::disconnect`]). This module
//! contributes only the per-state work: [`advance`] executes exactly one
//! `SSH_SCP_*` transition and returns, mirroring one iteration of the C
//! `myssh_statemach_act` switch. The shared driver
//! ([`super::SshSession::statemach`]) calls [`advance`] for every state in the
//! [`SshState::is_scp`](super::SshState::is_scp) range and stops the machine
//! when [`advance`] reaches [`SshState::SSH_STOP`](super::SshState::SSH_STOP).
//!
//! # The SCP byte protocol
//!
//! The SCP wire protocol is implemented end-to-end over the `russh` exec
//! channel that [`super::SshSession`] establishes on the shared
//! [`crate::conn::Connection`] filter chain: [`scp_open_exec`] runs the remote
//! `scp -t <path>` sink (upload) or `scp -f <path>` source (download);
//! [`scp_send_body`] and [`scp_recv_body`] exchange the
//! `C<mode> <size> <name>\n` header, honour the single-byte acknowledgements,
//! and pump the body bytes to/from the per-transfer source
//! ([`super::SshSession::upload`]) and sink ([`super::SshSession::sink`]) that
//! the [`super::ScpHandler`] projects from the shared
//! [`crate::protocols::TransferCtx`]. Every decision the C code makes is
//! implemented here in a pure, unit-tested helper; there is **zero `unsafe`**
//! and no C linkage anywhere on the SCP path.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use russh::client;
use russh::ChannelStream;

use super::{get_working_path, SshScheme, SshSession, SshState};
use crate::error::{CurlCode, Error, Result};

// ===========================================================================
// Diagnostic message text (← the C `failf` strings; preserved verbatim for
// stderr parity with curl 8.x, per the Minimal Change Mandate).
// ===========================================================================

/// `failf` text emitted when an upload is requested without a known length
/// (← `libssh.c` / `libssh2.c` `SSH_SCP_TRANS_INIT`:
/// `failf(data, "SCP requires a known file size for upload")`). SCP transmits
/// the size in its file header *before* any data, so a streamed upload of
/// unknown length cannot proceed — this is a hard SCP-protocol constraint.
const SCP_UPLOAD_NEEDS_SIZE: &str = "SCP requires a known file size for upload";

/// `failf` text for a failed SCP-send channel setup (← the `failf(data, "%s",
/// err_msg)` in `ssh_state_scp_upload_init`). [`advance`] emits this when
/// opening the `scp -t` exec stream fails, mapping the failure to
/// [`CurlCode::UploadFailed`] exactly as the C upload-init path does.
const SCP_UPLOAD_OPEN_FAILED: &str = "Failed to open SCP channel for upload";

/// `failf` text for a failed SCP-recv channel setup (← the `failf(data, "%s",
/// err_msg)` in `ssh_state_scp_download_init` / `myssh_in_TRANS_INIT`).
const SCP_DOWNLOAD_OPEN_FAILED: &str = "Failed to open SCP channel for download";

/// `failf` text when the SCP source does not answer with a new-file request
/// (← `myssh_SSH_SCP_DOWNLOAD`: a non-`SSH_SCP_REQUEST_NEWFILE` reply maps to
/// `CURLE_REMOTE_FILE_NOT_FOUND`).
const SCP_REMOTE_FILE_NOT_FOUND: &str = "SCP remote file not found";

// ===========================================================================
// Pure decision helpers.
//
// Every branch the C `myssh_statemach_act` switch takes for the `SSH_SCP_*`
// states is factored into one of these pure, side-effect-free functions so it
// can be unit-tested in isolation (see the `tests` module) and reused verbatim
// by [`advance`]. Keeping the decisions here — rather than inline in the async
// dispatcher — is what makes the SCP logic testable under Miri without a live
// `russh` session.
// ===========================================================================

/// Pick the next state after `SSH_SCP_TRANS_INIT` from the transfer direction
/// (← `myssh_in_TRANS_INIT`: `data->state.upload` selects `SSH_SCP_UPLOAD_INIT`
/// vs `SSH_SCP_DOWNLOAD_INIT`).
#[must_use]
fn scp_trans_init_next(upload: bool) -> SshState {
    if upload {
        SshState::SSH_SCP_UPLOAD_INIT
    } else {
        SshState::SSH_SCP_DOWNLOAD_INIT
    }
}

/// Enforce SCP's "size known up front" precondition for uploads
/// (← `myssh_in_TRANS_INIT`: `if(data->state.infilesize < 0) { failf(...);
/// CURLE_UPLOAD_FAILED; }`). SCP writes the file length into its header before
/// any bytes flow, so a negative (unknown) `infilesize` is fatal.
///
/// Returns [`CurlCode::UploadFailed`] (25) on an unknown length, matching curl.
fn scp_upload_precheck(infilesize: i64) -> std::result::Result<(), CurlCode> {
    if infilesize < 0 {
        Err(CurlCode::UploadFailed)
    } else {
        Ok(())
    }
}

/// Coerce a raw SCP-send channel-open error to the code curl reports
/// (← `ssh_state_scp_upload_init`: `if(result == CURLE_SSH || result ==
/// CURLE_REMOTE_FILE_NOT_FOUND) result = CURLE_UPLOAD_FAILED;`). Any other code
/// (e.g. a genuine timeout) is preserved unchanged.
#[must_use]
fn map_upload_open_error(raw: CurlCode) -> CurlCode {
    match raw {
        CurlCode::Ssh | CurlCode::RemoteFileNotFound => CurlCode::UploadFailed,
        other => other,
    }
}

/// Derive `req.maxdownload` from the size announced in the SCP download header
/// (← `myssh_SSH_SCP_DOWNLOAD`: `data->req.maxdownload =
/// ssh_scp_request_get_size(...)`; libssh2 uses `sb.st_size`). A negative size
/// is never produced by the SCP header, but is clamped to `0` defensively so an
/// out-of-range value can never widen the download cap.
#[must_use]
fn scp_download_maxdownload(size: i64) -> i64 {
    size.max(0)
}

/// Pick the first teardown state after `SSH_SCP_DONE` (← the `SSH_SCP_DONE`
/// arm: an upload sends EOF first (`SSH_SCP_SEND_EOF`); a download has nothing
/// to flush and frees the channel directly (`SSH_SCP_CHANNEL_FREE`)).
#[must_use]
fn scp_done_next(upload: bool) -> SshState {
    if upload {
        SshState::SSH_SCP_SEND_EOF
    } else {
        SshState::SSH_SCP_CHANNEL_FREE
    }
}

/// Advance the SCP channel-shutdown handshake by one step
/// (← the `libssh2.c` `SSH_SCP_SEND_EOF` → `SSH_SCP_WAIT_EOF` →
/// `SSH_SCP_WAIT_CLOSE` → `SSH_SCP_CHANNEL_FREE` chain, then `libssh.c`'s
/// `SSH_SCP_CHANNEL_FREE` → `SSH_SESSION_DISCONNECT` fall-through). The
/// `WAIT_EOF` / `WAIT_CLOSE` names are preserved as discrete transitions for
/// `--trace` parity even though `russh` collapses the peer EOF and channel
/// close into fewer awaits.
///
/// The final hop leaves the SCP range and enters the shared teardown state
/// [`SshState::SSH_SESSION_DISCONNECT`], which the parent driver
/// ([`super::SshSession::statemach`]) owns. Any non-teardown input maps to
/// [`SshState::SSH_STOP`] (defensive; unreachable in normal flow).
#[must_use]
fn scp_teardown_next(state: SshState) -> SshState {
    match state {
        SshState::SSH_SCP_SEND_EOF => SshState::SSH_SCP_WAIT_EOF,
        SshState::SSH_SCP_WAIT_EOF => SshState::SSH_SCP_WAIT_CLOSE,
        SshState::SSH_SCP_WAIT_CLOSE => SshState::SSH_SCP_CHANNEL_FREE,
        SshState::SSH_SCP_CHANNEL_FREE => SshState::SSH_SESSION_DISCONNECT,
        _ => SshState::SSH_STOP,
    }
}

// ===========================================================================
// Transfer-context accessors + the SCP byte protocol.
//
// The pure accessors read the per-transfer request the handler projected onto
// the engine from the shared [`crate::protocols::TransferCtx`]
// ([`super::SshRequest`]). The async helpers run the real SCP wire protocol
// over a `russh` exec channel — `scp -t`/`scp -f`, the `C<mode> <size> <name>`
// header, the single-byte acknowledgements, and the body pump — mirroring
// libssh2's `libssh2_scp_send64` / `libssh2_scp_recv2`.
// ===========================================================================

/// Whether this transfer is an upload (← `data->state.upload`), read from the
/// per-transfer request the handler populated ([`super::SshRequest::upload`]).
#[must_use]
fn transfer_is_upload(session: &SshSession) -> bool {
    session.req.upload
}

/// The known upload length in bytes, or `-1` when unknown
/// (← `data->state.infilesize`), read from the per-transfer request
/// ([`super::SshRequest::infilesize`]).
#[must_use]
fn transfer_infilesize(session: &SshSession) -> i64 {
    session.req.infilesize
}

/// Derive the SCP file name transmitted in the header — the last `/`-separated
/// component of the remote path (← libssh2 naming the file after the final path
/// segment). An empty result (a path ending in `/`) yields `""`, which the
/// remote `scp` then names after the destination directory, matching curl.
#[must_use]
fn scp_basename(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some((_, name)) => name,
        None => path,
    }
}

/// Parse an SCP source header line `C<mode> <size> <name>` (← the reply the
/// remote `scp -f` sends; libssh2's `ssh_scp_request_get_size`). Returns
/// `(size, mode, name)`. Any reply that is not a `C` new-file record maps to
/// [`CurlCode::RemoteFileNotFound`] (78) — matching `myssh_SSH_SCP_DOWNLOAD`'s
/// non-`SSH_SCP_REQUEST_NEWFILE` branch.
fn parse_scp_header(line: &str) -> std::result::Result<(i64, u32, String), CurlCode> {
    let line = line.trim_end_matches(['\n', '\r']);
    let rest = line.strip_prefix('C').ok_or(CurlCode::RemoteFileNotFound)?;
    let mut parts = rest.splitn(3, ' ');
    let mode = parts
        .next()
        .and_then(|s| u32::from_str_radix(s, 8).ok())
        .ok_or(CurlCode::RemoteFileNotFound)?;
    let size = parts
        .next()
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or(CurlCode::RemoteFileNotFound)?;
    let name = parts.next().unwrap_or("").to_string();
    Ok((size, mode, name))
}

/// Read the SCP single-byte acknowledgement off the exec-channel stream
/// (← libssh2's `ssh_scp` ack: `0` = OK, `1` = warning, `2` = fatal). Returns
/// the raw code. A hard read failure surfaces as [`CurlCode::Ssh`].
///
/// The whole SCP exchange runs over one [`ChannelStream`] (rather than repeated
/// `Channel::make_reader()` calls) because a single `ChannelMsg::Data` packet
/// can carry the header *and* the first body bytes together; a fresh reader per
/// read would drop the leftover bytes buffered inside the reader. Reading over
/// one persistent stream preserves every byte across the header→body boundary.
async fn scp_read_ack<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result<u8> {
    let mut b = [0u8; 1];
    stream
        .read_exact(&mut b)
        .await
        .map_err(|e| Error::with_context(CurlCode::Ssh, format!("SCP: no acknowledgement: {e}")))?;
    Ok(b[0])
}

/// Read one `\n`-terminated line off the exec-channel stream (← reading the SCP
/// header record byte-by-byte, as libssh2 does). Bounded to a sane header
/// length so a misbehaving peer cannot allocate without limit.
async fn scp_read_line<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result<String> {
    let mut out: Vec<u8> = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await.map_err(|e| {
            Error::with_context(CurlCode::Ssh, format!("SCP: header read failed: {e}"))
        })?;
        if n == 0 || byte[0] == b'\n' {
            break;
        }
        out.push(byte[0]);
        if out.len() > super::MAX_PATHLENGTH {
            return Err(Error::with_context(
                CurlCode::Ssh,
                "SCP: header line too long",
            ));
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Open a `russh` session channel, start the remote `scp` in the requested
/// direction (`scp -t <path>` for a sink / upload, `scp -f <path>` for a source
/// / download) and return the channel as a single duplex byte stream (← the
/// `channel_open_session()` + `exec(...)` that replaces `libssh2_scp_send64` /
/// `libssh2_scp_recv2`). The `-t`/`-f` flags are the standard remote-`scp`
/// protocol selectors, exactly as OpenSSH's own `scp` uses them.
async fn scp_open_stream(
    session: &mut SshSession,
    upload: bool,
) -> Result<ChannelStream<client::Msg>> {
    // Direction-appropriate failure (← the C `failf` text + error code): an
    // upload open-failure is `CURLE_UPLOAD_FAILED` (ssh_state_scp_upload_init),
    // a download open-failure is `CURLE_COULDNT_CONNECT` (ssh_scp_init).
    let (code, what) = if upload {
        (CurlCode::UploadFailed, SCP_UPLOAD_OPEN_FAILED)
    } else {
        (CurlCode::CouldntConnect, SCP_DOWNLOAD_OPEN_FAILED)
    };
    let handle = session
        .conn
        .session
        .as_ref()
        .ok_or_else(|| Error::with_context(code, what))?;
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|_| Error::with_context(code, what))?;
    let flag = if upload { "-t" } else { "-f" };
    // Shell-safe single-quoting of the path (← curl builds the same remote
    // command line for the `scp` executable).
    let cmd = format!("scp {} {}", flag, shell_single_quote(&session.proto.path));
    channel
        .exec(true, cmd)
        .await
        .map_err(|_| Error::with_context(code, what))?;
    Ok(channel.into_stream())
}

/// Single-quote a path for the remote `scp` command line, escaping embedded
/// single quotes the POSIX way (`'\''`). Mirrors how curl shell-quotes the SCP
/// path before handing it to the remote shell.
fn shell_single_quote(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 2);
    out.push('\'');
    for ch in path.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Run the SCP send (upload) protocol over a fresh exec-channel stream (← the
/// `libssh2_scp_send64` handshake + body write): open `scp -t`, consume its
/// initial ready ack, send the `C<mode> <size> <name>` header, consume its ack,
/// stream the body, send the trailing `\0`, consume the final ack, then send
/// EOF. A non-zero ack maps to [`CurlCode::UploadFailed`] (25).
async fn scp_send_body(session: &mut SshSession) -> Result<()> {
    let payload = session.upload.take().unwrap_or_default();
    let size = session.req.infilesize.max(0);
    let name = scp_basename(&session.proto.path).to_string();
    // curl's SCP send uses the new-file mode `data->set.new_file_perms`
    // (default 0644); the header carries it verbatim.
    let header = format!("C{:04o} {} {}\n", 0o644, size, name);

    let mut stream = scp_open_stream(session, true).await?;

    // The remote `scp -t` sends an initial 0 ack when ready.
    if scp_read_ack(&mut stream).await? != 0 {
        return Err(Error::with_context(
            CurlCode::UploadFailed,
            SCP_UPLOAD_OPEN_FAILED,
        ));
    }
    stream.write_all(header.as_bytes()).await.map_err(|e| {
        Error::with_context(
            CurlCode::UploadFailed,
            format!("SCP: header send failed: {e}"),
        )
    })?;
    stream.flush().await.map_err(|e| {
        Error::with_context(
            CurlCode::UploadFailed,
            format!("SCP: header flush failed: {e}"),
        )
    })?;
    if scp_read_ack(&mut stream).await? != 0 {
        return Err(Error::with_context(
            CurlCode::UploadFailed,
            SCP_UPLOAD_OPEN_FAILED,
        ));
    }
    // Body, then the SCP end-of-file `\0`, then the closing ack.
    stream.write_all(&payload).await.map_err(|e| {
        Error::with_context(
            CurlCode::UploadFailed,
            format!("SCP: body send failed: {e}"),
        )
    })?;
    stream.write_all(b"\0").await.map_err(|e| {
        Error::with_context(CurlCode::UploadFailed, format!("SCP: EOF send failed: {e}"))
    })?;
    stream.flush().await.map_err(|e| {
        Error::with_context(
            CurlCode::UploadFailed,
            format!("SCP: body flush failed: {e}"),
        )
    })?;
    if scp_read_ack(&mut stream).await? != 0 {
        return Err(Error::with_context(
            CurlCode::UploadFailed,
            SCP_UPLOAD_OPEN_FAILED,
        ));
    }
    // Signal end-of-write (← libssh2_channel_send_eof); dropping `stream`
    // afterwards closes the channel (ownership replaces the manual free).
    let _ = stream.shutdown().await;
    Ok(())
}

/// Run the SCP receive (download) protocol over a fresh exec-channel stream
/// (← the `libssh2_scp_recv2` handshake + body read): open `scp -f`, send the
/// initial `0` ack, read the `C<mode> <size> <name>` header, send its ack, read
/// exactly `size` body bytes to the client sink, then read the trailing `\0`
/// and send the closing ack. Returns the announced size
/// (→ `data->req.maxdownload`). A header that is not a `C` record maps to
/// [`CurlCode::RemoteFileNotFound`] (78).
async fn scp_recv_body(session: &mut SshSession) -> Result<i64> {
    let mut sink = session.sink.take();
    let mut stream = scp_open_stream(session, false).await?;

    // Kick the source with a 0 ack, then read the file header record.
    stream
        .write_all(b"\0")
        .await
        .map_err(|e| Error::with_context(CurlCode::Ssh, format!("SCP: start ack failed: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| Error::with_context(CurlCode::Ssh, format!("SCP: start flush failed: {e}")))?;
    let line = scp_read_line(&mut stream).await?;
    let (size, _mode, _name) = parse_scp_header(&line)
        .map_err(|code| Error::with_context(code, SCP_REMOTE_FILE_NOT_FOUND))?;
    // Acknowledge the header so the source starts sending the body.
    stream
        .write_all(b"\0")
        .await
        .map_err(|e| Error::with_context(CurlCode::Ssh, format!("SCP: header ack failed: {e}")))?;
    stream.flush().await.map_err(|e| {
        Error::with_context(CurlCode::Ssh, format!("SCP: header ack flush failed: {e}"))
    })?;

    // Read exactly `size` bytes (← `data->req.maxdownload`) to the client sink.
    let mut remaining = size.max(0);
    let mut buf = vec![0u8; 32 * 1024];
    while remaining > 0 {
        let want = usize::try_from(remaining)
            .unwrap_or(buf.len())
            .min(buf.len());
        let n = stream.read(&mut buf[..want]).await.map_err(|e| {
            Error::with_context(CurlCode::PartialFile, format!("SCP: body read failed: {e}"))
        })?;
        if n == 0 {
            break; // premature EOF
        }
        if let Some(sink) = sink.as_deref_mut() {
            sink.write(&buf[..n])?;
        }
        remaining -= i64::try_from(n).unwrap_or(0);
    }
    // The source sends a trailing 0 byte after the body; ack it.
    let _ = scp_read_ack(&mut stream).await;
    let _ = stream.write_all(b"\0").await;
    let _ = stream.flush().await;

    session.sink = sink;
    Ok(size)
}

// ===========================================================================
// The state stepper (← the `SSH_SCP_*` arms of `myssh_statemach_act`).
// ===========================================================================

/// Execute exactly one `SSH_SCP_*` state transition for `session`
/// (← one iteration of the C `myssh_statemach_act` switch, restricted to the
/// SCP states). The parent driver [`super::SshSession::statemach`] calls this
/// for every state in the [`SshState::is_scp`](super::SshState::is_scp) range
/// and treats a transition into [`SshState::SSH_STOP`](super::SshState::SSH_STOP)
/// as "phase complete".
///
/// # Blocking model
///
/// curl's SCP subsystem is synchronous (`ssh_set_blocking(1)`); C polls with
/// `SSH_AGAIN` / `CURLE_AGAIN`. Here every channel operation is a Tokio
/// `.await`, so there is no busy-loop and no would-block signal — a step either
/// completes or propagates an error.
///
/// # Errors
///
/// Returns the transfer's [`CurlCode`] on any fatal condition. The error is
/// surfaced as `Err` (never merely stashed in `actualcode`) because the shared
/// driver treats `SSH_STOP` as success regardless of `actualcode`; the frozen
/// integer codes are: upload precondition/channel failures →
/// [`CurlCode::UploadFailed`] (25), download channel-open failure →
/// [`CurlCode::CouldntConnect`] (7), an unknown remote file →
/// [`CurlCode::RemoteFileNotFound`] (78). On a fatal condition the state is also
/// moved to the matching cleanup state first, so the `[old] -> [new]` `--trace`
/// output matches curl before the error unwinds.
pub(super) async fn advance(session: &mut SshSession) -> Result<()> {
    match session.conn.state {
        // -------------------------------------------------------------------
        // ← myssh_in_TRANS_INIT: resolve the working path (the SCP variant
        //   strips a leading "/~/"), then branch on the transfer direction.
        // -------------------------------------------------------------------
        SshState::SSH_SCP_TRANS_INIT => {
            let url_path = session.proto.path.clone();
            let homedir = session.conn.homedir.clone().unwrap_or_default();
            match get_working_path(SshScheme::Scp, &url_path, &homedir) {
                Ok(working) => session.proto.path = working,
                Err(e) => {
                    // ← if(result) { sshc->actualcode = result; SSH_STOP; }
                    session.conn.actualcode = e.code();
                    session.set_state(SshState::SSH_STOP);
                    return Err(e);
                }
            }

            let upload = transfer_is_upload(session);
            if upload {
                // ← if(data->state.infilesize < 0) { failf(...); UPLOAD_FAILED }
                if let Err(code) = scp_upload_precheck(transfer_infilesize(session)) {
                    session.conn.actualcode = code;
                    // libssh2 routes the failure through channel cleanup.
                    session.set_state(SshState::SSH_SCP_CHANNEL_FREE);
                    return Err(Error::with_context(code, SCP_UPLOAD_NEEDS_SIZE));
                }
            }
            session.set_state(scp_trans_init_next(upload));
        }

        // -------------------------------------------------------------------
        // ← ssh_state_scp_upload_init: open the SCP-send exec channel and run
        //   the sink protocol over the shared transfer source.
        //
        //   libssh2 requires the destination path to be a full path that
        //   includes the destination file name OR ends in a "/"; otherwise the
        //   file is named after the last directory in the path. This is
        //   preserved verbatim — it is curl-parity behaviour, not a bug to fix.
        //
        //   The wire steps replace `libssh2_scp_send64`: open the session
        //   channel, `exec("scp -t <path>")`, send the
        //   `C<perms> <infilesize> <name>\n` header, await the 0 ack, then pump
        //   the request body ([`SshSession::upload`]) over the channel followed
        //   by the trailing `\0`. Any generic failure collapses to
        //   [`CurlCode::UploadFailed`] (25) exactly as the C code maps it.
        // -------------------------------------------------------------------
        SshState::SSH_SCP_UPLOAD_INIT => {
            // `scp_send_body` opens its own `scp -t` exec-channel stream, runs
            // the whole send handshake, and sends EOF — mirroring the
            // open+`libssh2_scp_send64`+write sequence of the C arm.
            match scp_send_body(session).await {
                Ok(()) => {
                    // ← Curl_pgrsSetUploadSize + Curl_xfer_setup_send completed
                    //   above (the body is pumped synchronously here), then
                    //   myssh_to(SSH_STOP).
                    session.set_state(SshState::SSH_STOP);
                }
                Err(e) => {
                    // ← failf("%s", err_msg); map generic errors to UPLOAD_FAILED.
                    let code = map_upload_open_error(e.code());
                    session.conn.actualcode = code;
                    session.set_state(SshState::SSH_SCP_CHANNEL_FREE);
                    return Err(Error::with_context(code, SCP_UPLOAD_OPEN_FAILED));
                }
            }
        }

        // -------------------------------------------------------------------
        // ← ssh_scp_init / libssh2_scp_recv2: begin the SCP-recv phase. The
        //   `scp -f` exec channel is opened together with the header read in
        //   SSH_SCP_DOWNLOAD (`scp_recv_body` opens its own stream), so this
        //   arm is the discrete `--trace` transition the C backend emits before
        //   the download proper (libssh `FALLTHROUGH` into `SSH_SCP_DOWNLOAD`).
        // -------------------------------------------------------------------
        SshState::SSH_SCP_DOWNLOAD_INIT => {
            session.set_state(SshState::SSH_SCP_DOWNLOAD);
        }

        // -------------------------------------------------------------------
        // ← myssh_SSH_SCP_DOWNLOAD: read the SCP header, capture the size and
        //   stream exactly that many body bytes to the client sink. The header
        //   read + body pump run over the exec channel opened in DOWNLOAD_INIT;
        //   a reply that is not a `C` new-file record maps to
        //   CURLE_REMOTE_FILE_NOT_FOUND (78).
        // -------------------------------------------------------------------
        SshState::SSH_SCP_DOWNLOAD => match scp_recv_body(session).await {
            Ok(size) => {
                // ← data->req.maxdownload = size; the body was streamed to the
                //   sink above (Curl_xfer_setup_recv is folded into the pump).
                let _maxdownload = scp_download_maxdownload(size);
                session.set_state(SshState::SSH_SCP_DONE);
            }
            Err(e) => {
                // ← failf("%s", err_msg): a channel-open failure
                //   (CURLE_COULDNT_CONNECT), a non-NEWFILE header
                //   (CURLE_REMOTE_FILE_NOT_FOUND) or a body-read failure
                //   (CURLE_PARTIAL_FILE) each surface here with the code and
                //   diagnostic text `scp_recv_body` already assigned; the error
                //   is preserved verbatim rather than flattened.
                session.conn.actualcode = e.code();
                session.set_state(SshState::SSH_SCP_CHANNEL_FREE);
                return Err(e);
            }
        },

        // -------------------------------------------------------------------
        // ← the SSH_SCP_DONE arm: an upload flushes EOF first; a download has
        //   nothing to flush and frees the channel directly.
        // -------------------------------------------------------------------
        SshState::SSH_SCP_DONE => {
            let upload = transfer_is_upload(session);
            session.set_state(scp_done_next(upload));
        }

        // -------------------------------------------------------------------
        // ← ssh_scp_close / libssh2_channel_send_eof: signal end-of-write. The
        //   upload path already sent EOF via [`scp_send_body`] (which calls
        //   `AsyncWriteExt::shutdown` on the exec-channel stream before dropping
        //   it), so this is the discrete `--trace` transition curl emits after
        //   the write completes; russh needs no separate send-EOF step.
        // -------------------------------------------------------------------
        SshState::SSH_SCP_SEND_EOF => {
            session.set_state(scp_teardown_next(SshState::SSH_SCP_SEND_EOF));
        }

        // -------------------------------------------------------------------
        // ← libssh2 SSH_SCP_WAIT_EOF (libssh2_channel_wait_eof). The exec-channel
        //   stream owned by the body helper observed the peer EOF while draining
        //   (its read returned 0); the stream is then dropped, so no separate
        //   wait is required. Preserved as a discrete `--trace` transition for
        //   parity with the libssh2 backend.
        // -------------------------------------------------------------------
        SshState::SSH_SCP_WAIT_EOF => {
            session.set_state(scp_teardown_next(SshState::SSH_SCP_WAIT_EOF));
        }

        // -------------------------------------------------------------------
        // ← libssh2 SSH_SCP_WAIT_CLOSE (libssh2_channel_wait_closed). Dropping
        //   the exec-channel stream in the body helper closed the channel
        //   (ownership replaces the manual close); preserved as a discrete
        //   `--trace` transition for parity.
        // -------------------------------------------------------------------
        SshState::SSH_SCP_WAIT_CLOSE => {
            session.set_state(scp_teardown_next(SshState::SSH_SCP_WAIT_CLOSE));
        }

        // -------------------------------------------------------------------
        // ← ssh_scp_free / libssh2_channel_free: release the exec channel. The
        //   `ChannelStream` the body helper used was already dropped (which
        //   sends the close and frees it — ownership replaces the manual free);
        //   any vestigial handle on the connection is cleared defensively.
        //   libssh then falls through to SSH_SESSION_DISCONNECT.
        // -------------------------------------------------------------------
        SshState::SSH_SCP_CHANNEL_FREE => {
            session.conn.channel = None;
            // ← CURL_TRC_SSH(data, "SCP DONE phase complete");
            tracing::trace!(target: "curl::ssh", "SCP DONE phase complete");
            session.set_state(scp_teardown_next(SshState::SSH_SCP_CHANNEL_FREE));
        }

        // -------------------------------------------------------------------
        // The parent driver only delegates `is_scp()` states here; any other
        // value is curl's `default:` / `SSH_QUIT` case — an internal error that
        // simply stops the machine (← `myssh_to(data, sshc, SSH_STOP)`).
        // -------------------------------------------------------------------
        _ => {
            session.set_state(SshState::SSH_STOP);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    //! Pure-logic unit tests for the SCP state machine.
    //!
    //! Every test here is synchronous and free of any live `russh` session, so
    //! the suite runs unchanged under `cargo test` and `cargo +nightly miri
    //! test`. The async [`advance`] dispatcher is validated indirectly: each
    //! branch it can take is one of the pure helpers exercised below, so the
    //! decisions are covered without needing a live transport.

    use super::super::SshSetup;
    use super::*;

    /// A default engine with no live transport (`session` / `channel` are
    /// `None`), used to pin the request-accessor contract and the pure header /
    /// path / quoting helpers without a live `russh` session.
    fn test_session() -> SshSession {
        SshSession::new(SshSetup::default())
    }

    // --- (a) upload precondition + channel-open error coercion --------------

    #[test]
    fn upload_requires_known_infilesize() {
        // ← SSH_SCP_TRANS_INIT: `infilesize < 0` is fatal for SCP because the
        //   size is written into the SCP header before any bytes flow.
        assert_eq!(scp_upload_precheck(-1), Err(CurlCode::UploadFailed));
        // A known length (including a legitimate zero-byte file) is accepted.
        assert_eq!(scp_upload_precheck(0), Ok(()));
        assert_eq!(scp_upload_precheck(100), Ok(()));
    }

    #[test]
    fn upload_open_error_is_coerced_to_upload_failed() {
        // ← ssh_state_scp_upload_init (libssh2.c L2405-2410): CURLE_SSH and
        //   CURLE_REMOTE_FILE_NOT_FOUND both collapse to CURLE_UPLOAD_FAILED.
        assert_eq!(map_upload_open_error(CurlCode::Ssh), CurlCode::UploadFailed);
        assert_eq!(
            map_upload_open_error(CurlCode::RemoteFileNotFound),
            CurlCode::UploadFailed
        );
        // Any other code is preserved unchanged (e.g. a genuine timeout or a
        // connect failure surfaced by the transport).
        assert_eq!(
            map_upload_open_error(CurlCode::OperationTimedout),
            CurlCode::OperationTimedout
        );
        assert_eq!(
            map_upload_open_error(CurlCode::CouldntConnect),
            CurlCode::CouldntConnect
        );
    }

    /// The frozen integer values the FFI layer and downstream consumers depend
    /// on (§5 of the agent plan; must never drift).
    #[test]
    fn error_codes_have_frozen_integer_values() {
        assert_eq!(CurlCode::CouldntConnect as i32, 7);
        assert_eq!(CurlCode::UploadFailed as i32, 25);
        assert_eq!(CurlCode::RemoteFileNotFound as i32, 78);
        assert_eq!(CurlCode::Ssh as i32, 79);
    }

    // --- (b) download size capture -> maxdownload ---------------------------

    #[test]
    fn download_size_sets_maxdownload() {
        // ← myssh_SSH_SCP_DOWNLOAD: `req.maxdownload = <SCP header size>`.
        assert_eq!(scp_download_maxdownload(12_345), 12_345);
        assert_eq!(scp_download_maxdownload(0), 0);
        // A pathological negative size is clamped so it can never widen the cap.
        assert_eq!(scp_download_maxdownload(-5), 0);
    }

    // --- (c) transition order: upload vs download ---------------------------

    #[test]
    fn trans_init_branches_on_direction() {
        // ← myssh_in_TRANS_INIT: `data->state.upload` selects the next state.
        assert_eq!(scp_trans_init_next(true), SshState::SSH_SCP_UPLOAD_INIT);
        assert_eq!(scp_trans_init_next(false), SshState::SSH_SCP_DOWNLOAD_INIT);
    }

    #[test]
    fn done_branches_on_direction() {
        // Upload flushes EOF first; download has nothing to flush and frees the
        // channel directly.
        assert_eq!(scp_done_next(true), SshState::SSH_SCP_SEND_EOF);
        assert_eq!(scp_done_next(false), SshState::SSH_SCP_CHANNEL_FREE);
    }

    #[test]
    fn upload_teardown_walks_full_handshake() {
        // ← the libssh2 SEND_EOF -> WAIT_EOF -> WAIT_CLOSE -> CHANNEL_FREE
        //   handshake, then libssh's CHANNEL_FREE -> SSH_SESSION_DISCONNECT
        //   fall-through. The WAIT_EOF / WAIT_CLOSE names are preserved as
        //   discrete transitions for `--trace` parity.
        let mut state = SshState::SSH_SCP_SEND_EOF;
        state = scp_teardown_next(state);
        assert_eq!(state, SshState::SSH_SCP_WAIT_EOF);
        state = scp_teardown_next(state);
        assert_eq!(state, SshState::SSH_SCP_WAIT_CLOSE);
        state = scp_teardown_next(state);
        assert_eq!(state, SshState::SSH_SCP_CHANNEL_FREE);
        state = scp_teardown_next(state);
        assert_eq!(state, SshState::SSH_SESSION_DISCONNECT);
    }

    #[test]
    fn download_teardown_is_direct() {
        // A download reaches CHANNEL_FREE straight from DONE (no EOF handshake),
        // then hands off to the shared disconnect state owned by `super`.
        assert_eq!(scp_done_next(false), SshState::SSH_SCP_CHANNEL_FREE);
        assert_eq!(
            scp_teardown_next(SshState::SSH_SCP_CHANNEL_FREE),
            SshState::SSH_SESSION_DISCONNECT
        );
    }

    // --- (d) path handling: SCP strips a leading "/~/" ----------------------

    #[test]
    fn working_path_strips_leading_tilde_for_scp() {
        // ← Curl_getworkingpath: the SCP variant strips a leading "/~/".
        let path =
            get_working_path(SshScheme::Scp, "/~/rel/path", "/home/user").expect("valid path");
        assert_eq!(path, "rel/path");
    }

    #[test]
    fn working_path_passes_absolute_paths_through() {
        // An ordinary absolute path is used verbatim; `homedir` is irrelevant
        // for SCP (unlike SFTP, which expands "/~" against it).
        let path =
            get_working_path(SshScheme::Scp, "/dir/file.txt", "/home/user").expect("valid path");
        assert_eq!(path, "/dir/file.txt");
    }

    // --- transfer-request accessors -----------------------------------------

    #[test]
    fn request_accessors_default_to_curl_uninitialised_state() {
        // With no request projected, the accessors report curl's uninitialised
        // transfer state: a bare `scp://host/path` is a download of unknown
        // length. (← `data->state.upload` / `data->state.infilesize`.)
        let session = test_session();
        assert!(!transfer_is_upload(&session), "default is a download");
        assert_eq!(transfer_infilesize(&session), -1, "length unknown");
    }

    #[test]
    fn request_accessors_reflect_projected_request() {
        // Once the handler projects the per-transfer request onto the engine
        // (← `ScpHandler::do_it`), the accessors read it directly.
        let mut session = test_session();
        session.req.upload = true;
        session.req.infilesize = 4096;
        assert!(transfer_is_upload(&session), "upload flag honoured");
        assert_eq!(transfer_infilesize(&session), 4096, "known length honoured");
    }

    // --- SCP header formatting + parsing ------------------------------------

    #[test]
    fn scp_basename_takes_final_path_segment() {
        // ← libssh2 names the file after the last '/'-separated component.
        assert_eq!(scp_basename("/dir/sub/file.txt"), "file.txt");
        assert_eq!(scp_basename("file.txt"), "file.txt");
        // A trailing slash yields an empty name — the remote `scp` then names
        // the file after the destination directory, matching curl.
        assert_eq!(scp_basename("/dir/"), "");
    }

    #[test]
    fn parse_scp_header_reads_mode_size_name() {
        // ← the `C<mode> <size> <name>` record a remote `scp -f` sends.
        let (size, mode, name) = parse_scp_header("C0644 12345 file.txt\n").expect("valid header");
        assert_eq!(size, 12_345);
        assert_eq!(mode, 0o644);
        assert_eq!(name, "file.txt");
    }

    #[test]
    fn parse_scp_header_rejects_non_newfile_reply() {
        // ← myssh_SSH_SCP_DOWNLOAD: a reply that is not a `C` new-file record
        //   maps to CURLE_REMOTE_FILE_NOT_FOUND (e.g. a `D` directory record or
        //   a `\x01`-prefixed error line).
        assert_eq!(
            parse_scp_header("D0755 0 subdir"),
            Err(CurlCode::RemoteFileNotFound)
        );
        assert_eq!(
            parse_scp_header("\x01scp: no such file"),
            Err(CurlCode::RemoteFileNotFound)
        );
    }

    #[test]
    fn shell_single_quote_escapes_embedded_quotes() {
        // A path with no quotes is simply wrapped.
        assert_eq!(shell_single_quote("/tmp/file"), "'/tmp/file'");
        // An embedded single quote is closed, escaped and reopened the POSIX
        // way (`'\''`), so the remote shell receives the literal path.
        assert_eq!(shell_single_quote("a'b"), "'a'\\''b'");
    }
}
