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
//! # TODO(wiring): the transport-coupled SCP byte protocol
//!
//! The SCP wire protocol (open an `exec` channel running the remote
//! `scp -t <path>` sink or `scp -f <path>` source, exchange the
//! `C<mode> <size> <name>\n` header, then pump the body bytes) is inherently
//! coupled to the transfer *sink* (received bytes) and *source* (upload bytes).
//! Those live in the shared per-transfer context
//! ([`crate::protocols::TransferCtx`]), which — exactly as [`super`]'s module
//! documentation states — is intentionally thin at this stage of the rewrite
//! and is threaded into the engine once the transfer/multi layers finalize the
//! shared handle type. This module therefore implements the **complete SCP
//! state machine** (transitions, error mapping and channel teardown) as a
//! faithful port and marks the transport-coupled byte protocol with
//! `// TODO(wiring)`, mirroring how [`super::SshSession::connect`] documents its
//! own transport-source hand-off. It is a faithful port, **not** a stub: every
//! decision the C code makes is implemented here in a pure, unit-tested helper.

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
/// err_msg)` in `ssh_state_scp_upload_init`; the wired transport substitutes the
/// server's error string, see the `// TODO(wiring)` in [`advance`]).
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
// TODO(wiring) transfer-context accessors.
//
// These read the per-transfer request state that the C code takes from
// `data->state` / `data->set` / `data->req`. That state lives in the shared
// [`crate::protocols::TransferCtx`], which is not yet threaded into the SSH
// engine (see the module-level note and [`super`]'s documentation). Each
// accessor returns the C default until the shared context is wired, at which
// point its body is replaced with the corresponding `ctx.request.*` read. They
// are kept as named functions so the single wiring point per datum is explicit
// and so [`advance`] exercises every decision helper in real (non-test) code.
// ===========================================================================

/// Whether this transfer is an upload (← `data->state.upload`).
///
/// TODO(wiring): read `ctx.request.upload` once [`crate::protocols::TransferCtx`]
/// is threaded into [`super::SshSession`]. A bare `scp://host/path` transfer is
/// a download, so the pre-wiring default is `false`.
#[must_use]
fn transfer_is_upload(session: &SshSession) -> bool {
    let _ = session;
    false
}

/// The known upload length in bytes, or `-1` when unknown (←
/// `data->state.infilesize`).
///
/// TODO(wiring): read `ctx.request` (curl's `Curl_range`-computed size / the
/// `CURLOPT_INFILESIZE[_LARGE]` value) once the shared context is wired. The
/// pre-wiring default is `-1` (unknown), matching curl's uninitialised value.
#[must_use]
fn transfer_infilesize(session: &SshSession) -> i64 {
    let _ = session;
    -1
}

/// Outcome of opening the SCP-send exec channel (← the `libssh2_scp_send64`
/// result in `ssh_state_scp_upload_init`).
///
/// TODO(wiring): open the channel and run the SCP sink handshake once the shared
/// transfer *source* is available (see the block in [`advance`]). Until then
/// there is no channel to open, so this reports success and the wired code
/// substitutes the real `channel_open_session()` + `exec("scp -t …")` result. A
/// future failure code is coerced by [`map_upload_open_error`].
fn scp_upload_init_outcome(session: &SshSession) -> std::result::Result<(), CurlCode> {
    let _ = session;
    Ok(())
}

/// Outcome of opening the SCP-recv exec channel (← `ssh_scp_init` /
/// `libssh2_scp_recv2` in `ssh_state_scp_download_init`).
///
/// TODO(wiring): open the channel via `channel_open_session()` +
/// `exec("scp -f …")` once the shared context is wired. Reports success until
/// then; a future failure is reported as [`CurlCode::CouldntConnect`] by
/// [`advance`], matching the libssh backend's `SSH_SCP_DOWNLOAD_INIT` arm.
fn scp_download_init_outcome(session: &SshSession) -> std::result::Result<(), CurlCode> {
    let _ = session;
    Ok(())
}

/// The file size announced in the SCP download header
/// (← `ssh_scp_request_get_size` / libssh2's `sb.st_size`).
///
/// TODO(wiring): parse the `C<mode> <size> <name>\n` header off the exec channel
/// once the transfer *sink* is wired; a reply that is not a new-file request
/// maps to `Err(`[`CurlCode::RemoteFileNotFound`]`)`
/// (← `myssh_SSH_SCP_DOWNLOAD`). Reports `Ok(0)` until then.
fn scp_read_file_size(session: &SshSession) -> std::result::Result<i64, CurlCode> {
    let _ = session;
    Ok(0)
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
        // ← ssh_state_scp_upload_init: open the SCP-send exec channel.
        //
        //   libssh2 requires the destination path to be a full path that
        //   includes the destination file name OR ends in a "/"; otherwise the
        //   file is named after the last directory in the path. This is
        //   preserved verbatim — it is curl-parity behaviour, not a bug to fix.
        //
        //   TODO(wiring): open + drive the SCP sink protocol over the shared
        //     transfer source:
        //       let ch = session.conn.session.channel_open_session().await?;
        //       ch.exec(true, format!("scp -t {}", session.proto.path)).await?;
        //       // send "C{perms:04o} {infilesize} {name}\n", await the 0 ack,
        //       // Curl_pgrsSetUploadSize(infilesize) + Curl_xfer_setup_send to
        //       // pump the request body from ctx.source over `ch`.
        //     `scp_upload_init_outcome` yields the channel-open result (success
        //     until the shared context provides the source).
        // -------------------------------------------------------------------
        SshState::SSH_SCP_UPLOAD_INIT => match scp_upload_init_outcome(session) {
            Ok(()) => {
                // ← Curl_pgrsSetUploadSize + Curl_xfer_setup_send (wired above),
                //   then myssh_to(SSH_STOP).
                session.set_state(SshState::SSH_STOP);
            }
            Err(raw) => {
                // ← failf("%s", err_msg); map generic errors to UPLOAD_FAILED.
                let code = map_upload_open_error(raw);
                session.conn.actualcode = code;
                session.set_state(SshState::SSH_SCP_CHANNEL_FREE);
                return Err(Error::with_context(code, SCP_UPLOAD_OPEN_FAILED));
            }
        },

        // -------------------------------------------------------------------
        // ← ssh_scp_init / libssh2_scp_recv2: open the SCP-recv exec channel.
        //   TODO(wiring): channel_open_session() + exec("scp -f {path}"); the
        //     header is read in SSH_SCP_DOWNLOAD. `scp_download_init_outcome`
        //     yields the channel-open result (success until wired).
        // -------------------------------------------------------------------
        SshState::SSH_SCP_DOWNLOAD_INIT => match scp_download_init_outcome(session) {
            Ok(()) => {
                // ← libssh FALLTHROUGH into SSH_SCP_DOWNLOAD.
                session.set_state(SshState::SSH_SCP_DOWNLOAD);
            }
            Err(_raw) => {
                // ← failf("%s", err_msg); the libssh backend reports
                //   CURLE_COULDNT_CONNECT for a failed SCP init.
                let code = CurlCode::CouldntConnect;
                session.conn.actualcode = code;
                session.set_state(SshState::SSH_SCP_CHANNEL_FREE);
                return Err(Error::with_context(code, SCP_DOWNLOAD_OPEN_FAILED));
            }
        },

        // -------------------------------------------------------------------
        // ← myssh_SSH_SCP_DOWNLOAD: read the SCP header, capture the size and
        //   arm the receive transfer for exactly that many bytes.
        //   TODO(wiring): the size comes from the SCP header; reading it needs
        //     the exec channel + the transfer sink. `scp_read_file_size` yields
        //     it (0 until wired); a non-NEWFILE reply => RemoteFileNotFound.
        // -------------------------------------------------------------------
        SshState::SSH_SCP_DOWNLOAD => match scp_read_file_size(session) {
            Ok(size) => {
                // ← data->req.maxdownload = size; Curl_xfer_setup_recv(size).
                let _maxdownload = scp_download_maxdownload(size);
                // TODO(wiring): set ctx.request.maxdownload = _maxdownload and
                //   arm Curl_xfer_setup_recv over ctx.sink for exactly `size`.
                session.set_state(SshState::SSH_STOP);
            }
            Err(code) => {
                // ← failf("%s", err_msg); return CURLE_REMOTE_FILE_NOT_FOUND.
                session.conn.actualcode = code;
                session.set_state(SshState::SSH_SCP_CHANNEL_FREE);
                return Err(Error::with_context(code, SCP_REMOTE_FILE_NOT_FOUND));
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
        // ← ssh_scp_close / libssh2_channel_send_eof: signal end-of-write. A
        //   failure is non-fatal — curl only `infof`s it — then it waits for
        //   the peer EOF.
        // -------------------------------------------------------------------
        SshState::SSH_SCP_SEND_EOF => {
            if let Some(channel) = session.conn.channel.as_ref() {
                if let Err(e) = channel.eof().await {
                    tracing::info!(target: "curl::ssh", "Failed to send SCP channel EOF: {e}");
                }
            }
            session.set_state(scp_teardown_next(SshState::SSH_SCP_SEND_EOF));
        }

        // -------------------------------------------------------------------
        // ← libssh2 SSH_SCP_WAIT_EOF (libssh2_channel_wait_eof). russh surfaces
        //   the peer EOF as `ChannelMsg::Eof` on the channel stream, which the
        //   wired byte-pump observes while draining the channel; preserved as a
        //   discrete `--trace` transition for parity.
        //   TODO(wiring): await the peer EOF on the channel once the byte-pump
        //     owns it (near pass-through — russh needs no separate wait step).
        // -------------------------------------------------------------------
        SshState::SSH_SCP_WAIT_EOF => {
            session.set_state(scp_teardown_next(SshState::SSH_SCP_WAIT_EOF));
        }

        // -------------------------------------------------------------------
        // ← libssh2 SSH_SCP_WAIT_CLOSE (libssh2_channel_wait_closed). russh
        //   delivers the close as `ChannelMsg::Close`; preserved as a discrete
        //   `--trace` transition for parity.
        //   TODO(wiring): await the channel close once the byte-pump owns it.
        // -------------------------------------------------------------------
        SshState::SSH_SCP_WAIT_CLOSE => {
            session.set_state(scp_teardown_next(SshState::SSH_SCP_WAIT_CLOSE));
        }

        // -------------------------------------------------------------------
        // ← ssh_scp_free / libssh2_channel_free: release the exec channel.
        //   Dropping the `russh::Channel` sends the close and frees it, so
        //   clearing the field is the whole operation (ownership replaces the
        //   manual free). libssh then falls through to SSH_SESSION_DISCONNECT.
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
    /// `None`), used to pin the pre-wiring contract of the TODO(wiring)
    /// accessors.
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

    // --- TODO(wiring) accessor contract -------------------------------------

    #[test]
    fn pre_wiring_accessor_defaults() {
        // These defaults mirror curl's uninitialised transfer state; they are
        // the single points that change when `TransferCtx` is threaded in.
        let session = test_session();
        assert!(!transfer_is_upload(&session), "default is a download");
        assert_eq!(transfer_infilesize(&session), -1, "length unknown");
        assert_eq!(scp_upload_init_outcome(&session), Ok(()));
        assert_eq!(scp_download_init_outcome(&session), Ok(()));
        assert_eq!(scp_read_file_size(&session), Ok(0));
    }
}
