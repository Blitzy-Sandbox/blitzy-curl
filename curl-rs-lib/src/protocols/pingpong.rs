//! The shared "ping-pong" command/response engine (`lib/pingpong.c` +
//! `lib/pingpong.h`).
//!
//! This is the line-oriented, back-and-forth command/response state-machine
//! engine that the text protocols — **FTP, IMAP, POP3 and SMTP** — all build
//! on. It owns three things on behalf of those protocols:
//!
//! * the **send buffer** for the command currently being written to the server
//!   (including non-blocking partial-send bookkeeping),
//! * the **receive buffer** that accumulates server response bytes until one or
//!   more complete response lines are available, and
//! * the **response timeout** clock that bounds how long a single server
//!   response may take to arrive.
//!
//! On top of those it provides the generic loop: *send a command, read the
//! (possibly multi-line) response, hand the final numeric status code back to
//! the protocol.*
//!
//! # Compilation gate
//!
//! In C this engine is gated by
//! `USE_PINGPONG = !CURL_DISABLE_IMAP || !CURL_DISABLE_FTP ||
//! !CURL_DISABLE_POP3 || !CURL_DISABLE_SMTP`. In this crate the equivalent gate
//! lives at the `pub mod pingpong;` declaration in
//! [`crate::protocols`](crate::protocols), spelled
//! `#[cfg(any(feature = "ftp", feature = "imap", feature = "pop3", feature = "smtp"))]`.
//! Inside this file we simply assume the module is being compiled.
//!
//! # The two-function-pointer design becomes a trait
//!
//! The C `struct pingpong` carries two function pointers that each protocol
//! wires up with the `PINGPONG_SETUP(pp, statemachine, endofresp)` macro:
//!
//! * `statemachine` — run one iteration of the protocol's own command/response
//!   state machine, and
//! * `endofresp` — decide whether a freshly received response line is the
//!   *final* line of a (multi-line) response and, if so, extract its numeric
//!   code.
//!
//! Those are exactly the points where FTP, IMAP, POP3 and SMTP differ (FTP and
//! SMTP use `NNN-`…`NNN ` continuation, IMAP uses tagged / `+` continuation,
//! POP3 uses `+OK` / `-ERR`), so in Rust they become the
//! [`PingPongProtocol`] trait that each protocol module implements. The engine
//! takes a `&mut impl PingPongProtocol` on its drive calls — the idiomatic
//! replacement for the C function-pointer pair.
//!
//! # Async, not "call me repeatedly"
//!
//! C's `Curl_pp_statemach` is documented as "called repeatedly until done",
//! driven by the protocol's multi-state handler with a `*done` out-parameter.
//! Under Tokio that polling contract disappears: a blocking read simply
//! `.await`s readiness. Each `Curl_pp_*` entry point that the C code wrote as a
//! resumable, partial-progress function collapses into one `async fn` here.
//!
//! # Safety / I/O discipline
//!
//! This module contains **zero `unsafe`** (the crate root applies
//! `#![forbid(unsafe_code)]`). All socket I/O is performed through the
//! [`crate::conn`] verbs ([`Curl_conn_recv`] / [`Curl_conn_send`]); the engine
//! never touches a raw socket. All diagnostics go through
//! [`crate::util::sendf`] (`infof` for verbose traces, `failf` for fatal
//! errors). Buffers are plain `Vec<u8>`, never raw pointers. SASL is layered
//! *on top* by the mail protocols (they call `crate::auth::sasl` from inside
//! their own `statemachine`); this engine is SASL-agnostic — it only ferries
//! command lines and response codes.

use std::fmt;

use crate::conn::{
    BoxFuture, Connection, Curl_conn_data_pending, Curl_conn_recv, Curl_conn_send, FIRSTSOCKET,
};
use crate::easy::Easy;
use crate::error::{CurlError, Result};
use crate::util::dynbuf::DYN_PINGPPONG_CMD;
use crate::util::sendf;
use crate::util::timeval::{self, CurlTime};

// ===========================================================================
// Constants
// ===========================================================================

/// The default per-response timeout, in milliseconds, used when
/// `CURLOPT_SERVER_RESPONSE_TIMEOUT` is unset (C `RESP_TIMEOUT`,
/// `lib/urldata.h` — `60 * 1000`). This bounds the time a *single* server
/// response may take to arrive, independent of any overall transfer timeout.
const RESP_TIMEOUT: i64 = 60 * 1000;

/// The size of the stack read buffer used by [`PingPong::readresp`] for each
/// `recv` (C `char buffer[900]`). When a read fills the whole buffer the engine
/// keeps reading in the same call (more response is likely pending); a short
/// read ends the call and the caller resumes later.
const PINGPONG_READ_CHUNK: usize = 900;

// ===========================================================================
// Transfer mode — C `curl_pp_transfer`
// ===========================================================================

/// What a ping-pong transfer should fetch, mirroring C `curl_pp_transfer`.
///
/// Stored by the line-based protocols on their connection state to remember
/// what the in-flight command is expected to produce.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PpTransfer {
    /// Transfer a body (C `PPTRANSFER_BODY`).
    Body,
    /// Do not transfer a body, but still go through to get info / headers
    /// (C `PPTRANSFER_INFO`).
    Info,
    /// Get nothing at all — neither body nor info (C `PPTRANSFER_NONE`).
    None,
}

// ===========================================================================
// The protocol hook trait — replaces the two C function pointers
// ===========================================================================

/// The per-protocol hooks the ping-pong engine drives, replacing the C
/// `struct pingpong` function pointers `statemachine` and `endofresp` (wired in
/// C by the `PINGPONG_SETUP` macro).
///
/// FTP, IMAP, POP3 and SMTP each implement this trait on their own
/// connection-state type. The engine ([`PingPong`]) takes a
/// `&mut impl PingPongProtocol` on its drive calls and invokes these hooks; the
/// engine itself stays protocol-agnostic.
///
/// The async [`statemachine`](PingPongProtocol::statemachine) hook returns a
/// [`BoxFuture`] rather than using `async fn` in the trait directly: that keeps
/// the trait object-safe and avoids the `async_fn_in_trait` lint, matching the
/// established convention of [`crate::conn`]'s filter trait and
/// [`crate::protocols`]'s `Protocol` trait.
pub trait PingPongProtocol {
    /// Run one iteration of the protocol's command/response state machine
    /// (C `pp->statemachine(data, conn)`).
    ///
    /// The implementation typically sends the next command (via
    /// [`PingPong::sendf`]) and/or consumes a response (via
    /// [`PingPong::readresp`]) and advances its own protocol state, awaiting
    /// I/O as needed. It resolves when the protocol reaches a state where the
    /// engine should hand control back to its caller.
    fn statemachine<'a>(
        &'a mut self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>>;

    /// Detect the end of a (possibly multi-line) server response
    /// (C `pp->endofresp(data, conn, ptr, len, code)`).
    ///
    /// `line` is one complete response line, terminated by `\n` (the trailing
    /// CRLF is included). Returns `Some(code)` when `line` is the *final* line
    /// of the response — `code` being the protocol's numeric status — and
    /// `None` when more response lines are still to come (a continuation line).
    ///
    /// This is the hook that differs per protocol: FTP/SMTP key off the
    /// `NNN-` (continuation) versus `NNN ` (final) fourth byte, IMAP off its
    /// tagged / `+` responses, POP3 off `+OK` / `-ERR`.
    fn endofresp(&mut self, data: &mut Easy, conn: &mut Connection, line: &[u8]) -> Option<i32>;
}

// ===========================================================================
// The engine state — C `struct pingpong`
// ===========================================================================

/// The generic command/response engine state, the Rust image of C
/// `struct pingpong`.
///
/// Protocols embed one of these in their per-connection state (the analog of C
/// `struct ftp_conn { struct pingpong pp; … }`) and drive it through the
/// methods below, passing themselves (as a [`PingPongProtocol`]) into
/// [`readresp`](PingPong::readresp) and [`statemach`](PingPong::statemach).
#[derive(Debug, Default)]
pub struct PingPong {
    /// Pending outgoing command bytes (C `struct dynbuf sendbuf`). Holds the
    /// formatted command plus its terminating CRLF while it is being written;
    /// for a non-blocking partial send the un-sent remainder stays here.
    sendbuf: Vec<u8>,

    /// Accumulated server response bytes (C `struct dynbuf recvbuf`). Complete
    /// lines are scanned out of the front of this buffer; after a final
    /// response line is matched the final line is kept at the front (see
    /// [`nfinal`](PingPong::nfinal)) for the protocol parser to read.
    recvbuf: Vec<u8>,

    /// Number of bytes of the current command still to be sent (C `sendleft`).
    /// Non-zero only after a partial send; the un-sent slice is
    /// `sendbuf[sendsize - sendleft ..]`.
    sendleft: usize,

    /// Total size of the command being sent (C `sendsize`). Together with
    /// `sendleft` this locates the un-sent tail inside `sendbuf` — the
    /// idiomatic replacement for C's separate `sendthis` pointer.
    sendsize: usize,

    /// Bytes of the current server response already read (C `nread_resp`). Reset
    /// to zero each time a final response line is matched.
    nread_resp: usize,

    /// Length, in bytes, of the final response line — the line that, after a
    /// match, sits first in `recvbuf` (C `nfinal`). Trimmed from the front on
    /// the next [`readresp`](PingPong::readresp) call.
    nfinal: usize,

    /// Number of bytes left in `recvbuf` *after* a final response line
    /// (C `overflow`) — i.e. already-received data belonging to the *next*
    /// (pipelined) response. While non-zero the next read is served from the
    /// buffer rather than the socket.
    overflow: usize,

    /// Timestamp set when a command finished being sent (C `response`), used as
    /// the zero point for the response read timeout.
    response: CurlTime,

    /// Whether the engine has been initialised (C `BIT(initialised)`). Set by
    /// [`init`](PingPong::init); cleared by [`disconnect`](PingPong::disconnect).
    initialised: bool,

    /// Whether a server response is pending or in progress (C
    /// `BIT(pending_resp)`). Set when a command is sent; cleared once the last
    /// response line has been read.
    pending_resp: bool,
}

impl PingPong {
    /// Create a fresh, un-initialised engine. Call [`init`](PingPong::init)
    /// before driving a response.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Prepare to read a fresh new response (C `Curl_pp_init`).
    ///
    /// Resets the response byte counter, stamps `response` with `now` to start
    /// the response timeout, marks a response pending, and marks the engine
    /// initialised. `now` should be the current monotonic time
    /// ([`timeval::curlx_now`]).
    pub fn init(&mut self, now: CurlTime) {
        debug_assert!(!self.initialised, "Curl_pp_init on an initialised engine");
        self.nread_resp = 0;
        self.response = now; // start response time-out
        self.pending_resp = true;
        // C initialises the dynbufs here with the DYN_PINGPPONG_CMD cap; with a
        // `Vec` we just clear them and enforce the cap on append.
        self.sendbuf.clear();
        self.recvbuf.clear();
        self.sendleft = 0;
        self.sendsize = 0;
        self.nfinal = 0;
        self.overflow = 0;
        self.initialised = true;
    }

    /// Milliseconds until the response read times out (C
    /// `Curl_pp_state_timeout`). Zero or a negative number means the timeout has
    /// already triggered.
    ///
    /// Uses `CURLOPT_SERVER_RESPONSE_TIMEOUT` when set, otherwise
    /// [`RESP_TIMEOUT`]; the remaining time is measured from the `response`
    /// timestamp (set when the last command was sent), so the budget governs a
    /// single server response rather than the whole connect-to-response span.
    ///
    /// Note: C additionally clamps this against the overall transfer timeout via
    /// `Curl_timeleft_ms` (which needs the transfer's start timestamp from the
    /// progress subsystem). That progress plumbing is not yet wired into the
    /// Rust [`Easy`] handle, so only the per-response budget is applied here;
    /// the clamp is reinstated once `Curl_timeleft_ms` exists.
    #[must_use]
    pub fn state_timeout(&self, data: &Easy) -> i64 {
        let response_time = if data.set.server_response_timeout != 0 {
            data.set.server_response_timeout
        } else {
            RESP_TIMEOUT
        };
        let elapsed = timeval::curlx_ptimediff_ms(&timeval::curlx_now(), &self.response);
        response_time - elapsed
    }
}

// ===========================================================================
// Sending commands — C `Curl_pp_sendf` / `Curl_pp_vsendf` / `Curl_pp_flushsend`
// ===========================================================================

impl PingPong {
    /// Format and send a command to a ping-pong server (C `Curl_pp_sendf` and
    /// `Curl_pp_vsendf` — both collapse here, since `fmt::Arguments` already
    /// captures what C threaded through `va_list`).
    ///
    /// Callers pass the **bare** command with no line terminator; this method
    /// appends the protocol CRLF itself. Build the argument with
    /// [`format_args!`], e.g. `pp.sendf(data, conn, format_args!("USER {user}"))`.
    ///
    /// The send is made never to block: the underlying [`Curl_conn_send`] is
    /// awaited, and a `CURLE_AGAIN`-equivalent (would-block) result is treated
    /// as "zero bytes written", leaving the whole command buffered for a later
    /// [`flushsend`](PingPong::flushsend). A partial write is likewise retained.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::TooLarge`] if the formatted command plus CRLF would
    /// exceed [`DYN_PINGPPONG_CMD`] (the C dynbuf cap), or any transport error
    /// surfaced by [`Curl_conn_send`].
    pub async fn sendf(
        &mut self,
        data: &Easy,
        conn: &mut Connection,
        args: fmt::Arguments<'_>,
    ) -> Result<()> {
        // Format the bare command eagerly into an owned `String`, *consuming*
        // `args` before any `.await`, then delegate to [`send_command`]. This
        // keeps the convenient `format_args!` API while ensuring the actual
        // awaited future never holds the non-`Send` `fmt::Arguments` (nor the
        // hidden `[core::fmt::rt::Argument; N]` array it borrows) across an
        // await — a requirement for any caller whose future must be `Send`
        // (e.g. a `Protocol` implementation returning a `BoxFuture<… + Send>`).
        let cmd = fmt::format(args);
        self.send_command(data, conn, &cmd).await
    }

    /// Stage and send a complete command line, taking the already-formatted
    /// command **by value** (without the trailing CRLF, which the engine
    /// appends). This is the `Send`-compatible counterpart to [`sendf`]:
    /// because the command is an owned [`String`] (which is `Send`), the
    /// returned future is `Send` and can therefore be awaited inside a
    /// [`crate::conn::filters::BoxFuture`] (e.g. a protocol's `connect`/`do_it`
    /// future). `sendf`'s `fmt::Arguments<'_>` parameter is `!Send` and cannot
    /// cross an `.await` in such a context, so protocol engines must use this
    /// method instead.
    ///
    /// Mirrors C `Curl_pp_sendf`/`Curl_pp_vsendf`: stages the command in the
    /// send buffer with a `CRLF` terminator, performs one non-blocking send, and
    /// records any un-sent tail for a later [`flushsend`](Self::flushsend).
    pub async fn send_cmd(
        &mut self,
        data: &Easy,
        conn: &mut Connection,
        cmd: String,
    ) -> Result<()> {
        // `send_cmd` keeps its owned-`String` signature for callers that already
        // hold an owned command (e.g. the IMAP engine); the staging/send logic
        // lives in the `&str` core `send_command`, to which it delegates.
        self.send_command(data, conn, &cmd).await
    }

    /// Send an already-formatted, **bare** command (no line terminator) to a
    /// ping-pong server. This is the `Send`-safe core of [`sendf`].
    ///
    /// Callers pass the bare command with no line terminator; this method
    /// appends the protocol CRLF itself.
    ///
    /// The send is made never to block: the underlying [`Curl_conn_send`] is
    /// awaited, and a `CURLE_AGAIN`-equivalent (would-block) result is treated
    /// as "zero bytes written", leaving the whole command buffered for a later
    /// [`flushsend`](PingPong::flushsend). A partial write is likewise retained.
    ///
    /// Unlike [`sendf`], this takes a `&str` rather than [`fmt::Arguments`], so
    /// the returned future is `Send` and may be awaited from within a `Send`
    /// future (the protocol engines' `BoxFuture<… + Send>` flows).
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::TooLarge`] if the command plus CRLF would exceed
    /// [`DYN_PINGPPONG_CMD`] (the C dynbuf cap), or any transport error
    /// surfaced by [`Curl_conn_send`].
    pub async fn send_command(
        &mut self,
        data: &Easy,
        conn: &mut Connection,
        cmd_str: &str,
    ) -> Result<()> {
        debug_assert_eq!(self.sendleft, 0, "Curl_pp_sendf with a pending send");
        debug_assert_eq!(self.sendsize, 0, "Curl_pp_sendf with a pending send");

        // The bare command (no terminator yet).
        let mut cmd = cmd_str.as_bytes().to_vec();

        // Enforce the command-buffer cap on the full command + CRLF, mirroring
        // the C dynbuf which fails such an over-long append with CURLE_TOO_LARGE.
        if cmd.len().saturating_add(2) > DYN_PINGPPONG_CMD {
            return Err(CurlError::TooLarge);
        }

        // Append CRLF — the engine owns the terminator, callers must not.
        cmd.extend_from_slice(b"\r\n");

        // Stage it as the pending send buffer and mark a response expected.
        self.sendbuf = cmd;
        self.pending_resp = true;
        let write_len = self.sendbuf.len();

        // Non-blocking send. A would-block result means nothing went out yet.
        let bytes_written = match Curl_conn_send(conn, FIRSTSOCKET, &self.sendbuf, false).await {
            Ok(n) => n,
            Err(CurlError::Again) => 0,
            Err(e) => return Err(e),
        };

        // Verbose ">" trace of what was actually written (C `Curl_debug` with
        // CURLINFO_HEADER_OUT). Built only when verbose, to avoid allocating on
        // the common path.
        if data.set.verbose && bytes_written > 0 {
            let shown = String::from_utf8_lossy(&self.sendbuf[..bytes_written]);
            sendf::infof(true, shown.trim_end_matches(['\r', '\n']));
        }

        if bytes_written != write_len {
            // The whole chunk did not go out; keep the remainder and record how
            // much is left (the un-sent tail is `sendbuf[sendsize - sendleft..]`).
            self.sendsize = write_len;
            self.sendleft = write_len - bytes_written;
        } else {
            // Fully sent: clear the pending-send bookkeeping and (re)start the
            // response timeout from now.
            self.sendsize = 0;
            self.sendleft = 0;
            self.response = timeval::curlx_now();
        }

        Ok(())
    }

    /// Whether a partially-sent command still has bytes to flush
    /// (C `Curl_pp_needs_flush`).
    #[must_use]
    pub fn needs_flush(&self) -> bool {
        self.sendleft > 0
    }

    /// Push out any buffered command bytes still pending from a previous partial
    /// send (C `Curl_pp_flushsend`).
    ///
    /// A no-op when nothing is pending. A would-block result is swallowed
    /// (nothing more goes out this round); a further partial write simply
    /// shrinks the pending remainder.
    ///
    /// # Errors
    ///
    /// Any transport error surfaced by [`Curl_conn_send`].
    pub async fn flushsend(&mut self, data: &Easy, conn: &mut Connection) -> Result<()> {
        if !self.needs_flush() {
            return Ok(());
        }

        // The un-sent tail: C `pp->sendthis + pp->sendsize - pp->sendleft`.
        let offset = self.sendsize - self.sendleft;

        let written = match Curl_conn_send(conn, FIRSTSOCKET, &self.sendbuf[offset..], false).await
        {
            Ok(n) => n,
            Err(CurlError::Again) => 0,
            Err(e) => return Err(e),
        };

        if data.set.verbose && written > 0 {
            let shown = String::from_utf8_lossy(&self.sendbuf[offset..offset + written]);
            sendf::infof(true, shown.trim_end_matches(['\r', '\n']));
        }

        if written != self.sendleft {
            // Only a fraction went out; keep shrinking the remainder.
            self.sendleft -= written;
        } else {
            // Remainder fully sent: clear bookkeeping and restart the timeout.
            self.sendsize = 0;
            self.sendleft = 0;
            self.response = timeval::curlx_now();
        }

        Ok(())
    }
}

// ===========================================================================
// Reading responses — C `Curl_pp_readresp`
// ===========================================================================

impl PingPong {
    /// Append `data` to the receive buffer, enforcing the [`DYN_PINGPPONG_CMD`]
    /// cap (the C dynbuf cap on `recvbuf`).
    fn recvbuf_append(&mut self, data: &[u8]) -> Result<()> {
        if self.recvbuf.len().saturating_add(data.len()) > DYN_PINGPPONG_CMD {
            return Err(CurlError::TooLarge);
        }
        self.recvbuf.extend_from_slice(data);
        Ok(())
    }

    /// Read a piece of server response (C `Curl_pp_readresp`).
    ///
    /// Reads from the connection via [`Curl_conn_recv`], appends to the receive
    /// buffer, and scans complete lines, asking the protocol's
    /// [`endofresp`](PingPongProtocol::endofresp) hook about each. Returns
    /// `(code, size)`:
    ///
    /// * `code` is the protocol's numeric status from the final line, or `0`
    ///   when the response is **not yet complete** (more data is needed — call
    ///   again later) — mirroring C leaving `*code == 0`.
    /// * `size` is the number of response bytes read (C `*size`,
    ///   `pp->nread_resp` at the point of the match).
    ///
    /// When a final line is matched it is kept first in the receive buffer (so a
    /// protocol parser can read it), and [`overflow`](PingPong) records any
    /// trailing pipelined bytes belonging to the next response — those are
    /// served from the buffer on the following call without blocking.
    ///
    /// # Errors
    ///
    /// [`CurlError::RecvError`] on a closed connection (zero-length read),
    /// [`CurlError::TooLarge`] if the buffered response exceeds the cap, or any
    /// transport error from [`Curl_conn_recv`]. A would-block read is **not** an
    /// error: it returns `Ok((0, 0))` ("not done yet"), exactly as C maps
    /// `CURLE_AGAIN` to `CURLE_OK`.
    pub async fn readresp(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        sockindex: usize,
        proto: &mut impl PingPongProtocol,
    ) -> Result<(i32, usize)> {
        let mut read_buf = [0u8; PINGPONG_READ_CHUNK];

        // Outer loop == C `do { … } while(gotbytes == sizeof(buffer))`: keep
        // reading while each read fills the whole buffer (more is pending).
        loop {
            let mut gotbytes = 0usize;

            // A previous call left the final line at the front of the buffer;
            // drop it now (C trims `pp->nfinal` leading bytes).
            if self.nfinal > 0 {
                let drop = self.nfinal.min(self.recvbuf.len());
                self.recvbuf.drain(0..drop);
                self.nfinal = 0;
            }

            // Only read from the socket when there is no buffered overflow from
            // a prior (pipelined) response to process first.
            if self.overflow == 0 {
                match Curl_conn_recv(conn, sockindex, &mut read_buf).await {
                    // Would-block: no data available yet — not an error, not done.
                    Err(CurlError::Again) => return Ok((0, 0)),
                    Err(e) => return Err(e),
                    // Zero bytes == the peer closed the connection.
                    Ok(0) => {
                        sendf::failf(
                            &mut conn.filter_data.error_buffer,
                            "response reading failed",
                        );
                        return Err(CurlError::RecvError);
                    }
                    Ok(n) => {
                        gotbytes = n;
                        self.recvbuf_append(&read_buf[..n])?;
                        self.nread_resp += n;
                    }
                }
            }

            // Inner loop: scan complete lines out of the front of the buffer.
            loop {
                let Some(pos) = self.recvbuf.iter().position(|&b| b == b'\n') else {
                    // No newline yet — a partial line. There is, by definition,
                    // no overflow, and we need more bytes to make progress.
                    self.overflow = 0;
                    break;
                };
                // A pp-talk line ends at LF; the CR (if any) is part of the line.
                let length = pos + 1;

                // Verbose "<" trace of the response line (C `Curl_debug` with
                // CURLINFO_HEADER_IN). C also forwards each line to the header
                // ("INFO") client-write callback; that routing belongs to the
                // transfer/header layer and is applied there, not in the engine.
                if data.set.verbose {
                    let shown = String::from_utf8_lossy(&self.recvbuf[..length]).into_owned();
                    sendf::infof(true, shown.trim_end_matches(['\r', '\n']));
                }

                // Ask the protocol whether this is the final line. The borrow of
                // `recvbuf` for the slice ends with this call (NLL), freeing us
                // to mutate the buffer afterwards.
                if let Some(code) = proto.endofresp(data, conn, &self.recvbuf[..length]) {
                    // End of response: keep the final line first in the buffer
                    // and record any trailing pipelined bytes as overflow.
                    self.nfinal = length;
                    let cur = self.recvbuf.len();
                    self.overflow = cur.saturating_sub(length);
                    let size = self.nread_resp;
                    self.nread_resp = 0; // restart for the next response
                    self.pending_resp = false;
                    return Ok((code, size));
                }

                // Not final: consume this line and keep scanning the rest.
                let cur = self.recvbuf.len();
                if cur > length {
                    self.recvbuf.drain(0..length);
                } else {
                    self.recvbuf.clear();
                }
            }

            // C `while(gotbytes == sizeof(buffer))`: a short read (or a buffered
            // overflow pass, where `gotbytes == 0`) ends the call; resume later.
            if gotbytes != read_buf.len() {
                break;
            }
        }

        // Reached the end without a complete response: not done. (C clears
        // pending_resp and returns CURLE_OK with `*code == 0`.)
        self.pending_resp = false;
        Ok((0, 0))
    }
}

// ===========================================================================
// The drive loop and lifecycle — C `Curl_pp_statemach`, `Curl_pp_moredata`,
// `Curl_pp_disconnect`
// ===========================================================================

impl PingPong {
    /// Whether there is still buffered response data, so a following
    /// [`readresp`](PingPong::readresp) will not block (C `Curl_pp_moredata`).
    ///
    /// True when no send is pending and the receive buffer holds more than just
    /// the kept final line.
    #[must_use]
    pub fn moredata(&self) -> bool {
        self.sendleft == 0 && self.recvbuf.len() > self.nfinal
    }

    /// Drive one iteration of the protocol's command/response exchange
    /// (C `Curl_pp_statemach`).
    ///
    /// This performs the single round C does per call: it first checks the
    /// response timeout and fails with [`CurlError::OperationTimedout`] if it
    /// has elapsed; it flushes any partially-sent command; then, if there is
    /// work to do this round, it invokes the protocol's
    /// [`statemachine`](PingPongProtocol::statemachine) hook. The *outer* "until
    /// the protocol reaches its stop state" loop lives in the protocol's own
    /// driver (in C, e.g. `ftp_multi_statemach`), which calls this repeatedly —
    /// the engine deliberately does not own that loop.
    ///
    /// `block` selects waiting versus polling behavior: when `true` the engine
    /// always engages the protocol hook (which `.await`s I/O readiness); when
    /// `false` it engages only if there is already buffered or pending traffic,
    /// otherwise this round is a no-op. `disconnecting` relaxes handling for the
    /// teardown path (QUIT / LOGOUT): an idle non-blocking poll then reports the
    /// timeout rather than silently doing nothing, matching C.
    ///
    /// # Errors
    ///
    /// [`CurlError::OperationTimedout`] when the response timeout has elapsed
    /// (or, while disconnecting, when there is nothing to do), plus any error
    /// surfaced by [`flushsend`](PingPong::flushsend) or the protocol's
    /// `statemachine`.
    pub async fn statemach(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        proto: &mut impl PingPongProtocol,
        block: bool,
        disconnecting: bool,
    ) -> Result<()> {
        // C: bail immediately if the response timeout has already triggered.
        if self.state_timeout(data) <= 0 {
            sendf::failf(
                &mut conn.filter_data.error_buffer,
                "server response timeout",
            );
            return Err(CurlError::OperationTimedout);
        }

        // C decides via `Curl_socket_check` whether there is readable/writable
        // traffic this round (`rc`). Under Tokio readiness is awaited inside the
        // protocol hook, so we only need to know whether to engage it now: when
        // blocking we always do; otherwise only when there is buffered overflow,
        // a pending send, or data already waiting on the socket.
        let has_work = block
            || self.sendleft > 0
            || self.overflow > 0
            || Curl_conn_data_pending(conn, FIRSTSOCKET);

        if !has_work {
            // C `rc == 0`: nothing to do. While disconnecting that is treated as
            // a timeout (give up on the polite teardown); otherwise it is a
            // successful no-op round.
            if disconnecting {
                return Err(CurlError::OperationTimedout);
            }
            return Ok(());
        }

        // Drain any partially-sent command before engaging the protocol, so the
        // hook sees a clean send state (C reaches the same outcome through the
        // protocol's SENDING states calling `Curl_pp_flushsend`).
        if self.sendleft > 0 {
            self.flushsend(data, conn).await?;
        }

        // C: `result = pp->statemachine(data, data->conn)`.
        proto.statemachine(data, conn).await
    }

    /// Reset the engine when its connection is torn down (C
    /// `Curl_pp_disconnect`).
    ///
    /// Frees the buffers and zeroes all state (the C `memset` after
    /// `curlx_dyn_free`), leaving the engine un-initialised. Safe to call on an
    /// engine that was never initialised (a no-op then, as in C).
    pub fn disconnect(&mut self) {
        if self.initialised {
            *self = Self::default();
        }
    }

    // NOTE: C `Curl_pp_pollset` is intentionally omitted. It existed only to
    // register the connection's socket and its read/write interest with C's
    // hand-rolled `select`/`poll` multi machinery. Under the Tokio runtime that
    // readiness tracking is the runtime's job — the async `Curl_conn_recv` /
    // `Curl_conn_send` awaits resolve exactly when the socket is ready — so
    // there is no pollset for this engine to populate.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::{CfState, ConnectionFilter, FilterChain};
    use crate::conn::SchemeDescriptor;
    use crate::conn::TRNSPRT_TCP;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// Drive a future to completion on a fresh current-thread runtime (the
    /// helper shape used across the `conn` filter tests).
    fn run<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build test runtime")
            .block_on(fut)
    }

    /// A leaf transport mock: serves scripted `recv` chunks (one queue entry per
    /// `recv` call, returning `CURLE_AGAIN` when the queue is empty) and records
    /// every byte sent. It reports itself already connected so a
    /// [`FilterChain`] will route I/O straight to it.
    struct MockIo {
        state: CfState,
        chunks: VecDeque<Vec<u8>>,
        sent: Arc<Mutex<Vec<u8>>>,
    }

    impl MockIo {
        fn new(chunks: Vec<Vec<u8>>) -> Self {
            let mut state = CfState::new();
            state.connected = true;
            Self {
                state,
                chunks: chunks.into_iter().collect(),
                sent: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn sent_handle(&self) -> Arc<Mutex<Vec<u8>>> {
            Arc::clone(&self.sent)
        }
    }

    impl ConnectionFilter for MockIo {
        fn name(&self) -> &'static str {
            "MOCK-IO"
        }
        fn cf_state(&self) -> &CfState {
            &self.state
        }
        fn cf_state_mut(&mut self) -> &mut CfState {
            &mut self.state
        }
        fn send<'a>(&'a mut self, buf: &'a [u8], _eos: bool) -> BoxFuture<'a, Result<usize>> {
            Box::pin(async move {
                self.sent.lock().expect("sent lock").extend_from_slice(buf);
                Ok(buf.len())
            })
        }
        fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize>> {
            Box::pin(async move {
                match self.chunks.pop_front() {
                    Some(chunk) => {
                        let n = chunk.len().min(buf.len());
                        buf[..n].copy_from_slice(&chunk[..n]);
                        if n < chunk.len() {
                            // Partial consumption: keep the tail for next time.
                            self.chunks.push_front(chunk[n..].to_vec());
                        }
                        Ok(n)
                    }
                    None => Err(CurlError::Again),
                }
            })
        }
    }

    /// An FTP/SMTP-style protocol hook: a line `"NNN "` (space after the code)
    /// is final and yields the code; `"NNN-"` is a continuation; anything else
    /// is treated as not-final.
    struct FtpStyle;

    impl PingPongProtocol for FtpStyle {
        fn statemachine<'a>(
            &'a mut self,
            _data: &'a mut Easy,
            _conn: &'a mut Connection,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move { Ok(()) })
        }
        fn endofresp(
            &mut self,
            _data: &mut Easy,
            _conn: &mut Connection,
            line: &[u8],
        ) -> Option<i32> {
            if line.len() < 4 {
                return None;
            }
            let code: i32 = std::str::from_utf8(&line[..3]).ok()?.parse().ok()?;
            match line[3] {
                b' ' => Some(code), // final line
                _ => None,          // '-' continuation (or non-status line)
            }
        }
    }

    /// Build a `Connection` whose primary socket is the given [`MockIo`],
    /// returning the connection plus a handle to the captured sent bytes.
    fn conn_with(chunks: Vec<Vec<u8>>) -> (Connection, Arc<Mutex<Vec<u8>>>) {
        let mock = MockIo::new(chunks);
        let sent = mock.sent_handle();
        let scheme = SchemeDescriptor::new("ftp", 21, 0, 0);
        let mut conn = Connection::new("ftp.example.com:21", TRNSPRT_TCP, scheme);
        conn.cfilter[FIRSTSOCKET] = FilterChain::from_head(Box::new(mock));
        (conn, sent)
    }

    #[test]
    fn readresp_complete_multiline_returns_code_and_size() {
        run(async {
            let mut data = Easy::new();
            // 12 bytes + 11 bytes = 23 bytes, the second line being final.
            let (mut conn, _sent) = conn_with(vec![b"220-banner\r\n220 ready\r\n".to_vec()]);
            let mut pp = PingPong::new();
            pp.init(timeval::curlx_now());
            let mut proto = FtpStyle;

            let (code, size) = pp
                .readresp(&mut data, &mut conn, FIRSTSOCKET, &mut proto)
                .await
                .expect("readresp");

            assert_eq!(code, 220, "final FTP code");
            assert_eq!(size, 23, "all response bytes counted");
            assert_eq!(pp.overflow, 0, "no pipelined data");
            assert_eq!(pp.nfinal, 11, "final line kept at front");
            assert_eq!(&pp.recvbuf[..pp.nfinal], b"220 ready\r\n");
            assert!(!pp.pending_resp, "response fully read");
        });
    }

    #[test]
    fn readresp_handles_pipelined_overflow() {
        run(async {
            let mut data = Easy::new();
            // Three lines in one read: a continuation, a final, then a pipelined
            // next-response line (the "overflow"). 12 + 11 + 10 = 33 bytes.
            let (mut conn, _sent) =
                conn_with(vec![b"220-banner\r\n220 ready\r\n226 done\r\n".to_vec()]);
            let mut pp = PingPong::new();
            pp.init(timeval::curlx_now());
            let mut proto = FtpStyle;

            let (code1, size1) = pp
                .readresp(&mut data, &mut conn, FIRSTSOCKET, &mut proto)
                .await
                .expect("first readresp");
            assert_eq!(code1, 220);
            assert_eq!(size1, 33, "nread_resp counts the whole read (C parity)");
            assert_eq!(pp.overflow, 10, "trailing pipelined line is overflow");
            assert_eq!(&pp.recvbuf[..pp.nfinal], b"220 ready\r\n");

            // Second call: served from the buffered overflow without blocking.
            let (code2, _size2) = pp
                .readresp(&mut data, &mut conn, FIRSTSOCKET, &mut proto)
                .await
                .expect("second readresp");
            assert_eq!(code2, 226, "pipelined response parsed from overflow");
            assert_eq!(pp.overflow, 0, "overflow consumed");
        });
    }

    #[test]
    fn readresp_partial_line_requests_more_then_completes() {
        run(async {
            let mut data = Easy::new();
            // First chunk has no newline (partial line); second completes it.
            let (mut conn, _sent) = conn_with(vec![b"220 read".to_vec(), b"y\r\n".to_vec()]);
            let mut pp = PingPong::new();
            pp.init(timeval::curlx_now());
            let mut proto = FtpStyle;

            // Partial: not done — code 0, size 0, bytes retained.
            let (code, size) = pp
                .readresp(&mut data, &mut conn, FIRSTSOCKET, &mut proto)
                .await
                .expect("partial readresp");
            assert_eq!(code, 0, "incomplete response");
            assert_eq!(size, 0);
            assert_eq!(pp.recvbuf, b"220 read", "partial line buffered");

            // Completion: the line finishes and the final code is returned.
            let (code, size) = pp
                .readresp(&mut data, &mut conn, FIRSTSOCKET, &mut proto)
                .await
                .expect("completing readresp");
            assert_eq!(code, 220);
            assert_eq!(size, 11, "8 buffered + 3 newly read");
        });
    }

    #[test]
    fn readresp_closed_connection_is_recv_error() {
        run(async {
            let mut data = Easy::new();
            // Empty script: the mock returns CURLE_AGAIN, not EOF; to exercise
            // the closed-connection path we script a single zero-length read by
            // queueing an empty chunk.
            let (mut conn, _sent) = conn_with(vec![Vec::new()]);
            let mut pp = PingPong::new();
            pp.init(timeval::curlx_now());
            let mut proto = FtpStyle;

            let err = pp
                .readresp(&mut data, &mut conn, FIRSTSOCKET, &mut proto)
                .await
                .expect_err("zero-length read must be an error");
            assert!(matches!(err, CurlError::RecvError));
        });
    }

    #[test]
    fn readresp_would_block_is_not_done() {
        run(async {
            let mut data = Easy::new();
            // No chunks at all -> recv yields CURLE_AGAIN -> Ok((0, 0)).
            let (mut conn, _sent) = conn_with(vec![]);
            let mut pp = PingPong::new();
            pp.init(timeval::curlx_now());
            let mut proto = FtpStyle;

            let (code, size) = pp
                .readresp(&mut data, &mut conn, FIRSTSOCKET, &mut proto)
                .await
                .expect("would-block maps to Ok");
            assert_eq!((code, size), (0, 0));
        });
    }

    #[test]
    fn sendf_appends_crlf_once() {
        run(async {
            let data = Easy::new();
            let (mut conn, sent) = conn_with(vec![]);
            let mut pp = PingPong::new();
            pp.init(timeval::curlx_now());

            pp.sendf(&data, &mut conn, format_args!("USER {}", "anonymous"))
                .await
                .expect("sendf");

            assert_eq!(
                &*sent.lock().expect("sent lock"),
                b"USER anonymous\r\n",
                "exactly one CRLF appended"
            );
            assert_eq!(pp.sendleft, 0, "full send leaves nothing pending");
            assert!(!pp.needs_flush());
        });
    }

    #[test]
    fn sendf_rejects_oversized_command() {
        run(async {
            let data = Easy::new();
            let (mut conn, _sent) = conn_with(vec![]);
            let mut pp = PingPong::new();
            pp.init(timeval::curlx_now());

            // One byte over the cap once CRLF is added.
            let huge = "X".repeat(DYN_PINGPPONG_CMD);
            let err = pp
                .sendf(&data, &mut conn, format_args!("{huge}"))
                .await
                .expect_err("oversized command must be rejected");
            assert!(matches!(err, CurlError::TooLarge));
            assert_eq!(err.code(), CurlError::TooLarge.code());
        });
    }

    #[test]
    fn state_timeout_positive_then_expires() {
        let data = Easy::new();
        let mut pp = PingPong::new();

        // Fresh response stamp: a healthy budget remains.
        pp.init(timeval::curlx_now());
        assert!(pp.state_timeout(&data) > 0, "fresh response has time left");

        // Stamp the response well beyond the default 60s budget in the past.
        let now = timeval::curlx_now();
        pp.disconnect(); // reset so we may re-init
        pp.init(CurlTime::new(now.tv_sec - 61, now.tv_usec));
        assert!(
            pp.state_timeout(&data) <= 0,
            "elapsed budget yields a non-positive timeout"
        );
    }

    #[test]
    fn statemach_times_out_when_budget_elapsed() {
        run(async {
            let mut data = Easy::new();
            let (mut conn, _sent) = conn_with(vec![]);
            let mut pp = PingPong::new();
            let now = timeval::curlx_now();
            pp.init(CurlTime::new(now.tv_sec - 61, now.tv_usec));
            let mut proto = FtpStyle;

            let err = pp
                .statemach(&mut data, &mut conn, &mut proto, true, false)
                .await
                .expect_err("an elapsed budget must time out");
            assert!(matches!(err, CurlError::OperationTimedout));
            assert_eq!(
                conn.filter_data.error_buffer.as_deref(),
                Some("server response timeout"),
                "diagnostic recorded via failf"
            );
        });
    }

    #[test]
    fn moredata_reflects_buffer_state() {
        let mut pp = PingPong::new();
        pp.init(timeval::curlx_now());
        assert!(!pp.moredata(), "empty buffer has no more data");

        // Simulate a kept final line plus trailing pipelined bytes.
        pp.recvbuf.extend_from_slice(b"220 ok\r\nextra");
        pp.nfinal = 8; // "220 ok\r\n"
        assert!(pp.moredata(), "trailing bytes beyond the final line");

        pp.nfinal = pp.recvbuf.len();
        assert!(!pp.moredata(), "nothing beyond the final line");
    }

    #[test]
    fn disconnect_resets_state() {
        let mut pp = PingPong::new();
        pp.init(timeval::curlx_now());
        pp.recvbuf.extend_from_slice(b"junk");
        pp.sendbuf.extend_from_slice(b"cmd");
        pp.disconnect();
        assert!(!pp.initialised, "disconnect un-initialises");
        assert!(pp.recvbuf.is_empty());
        assert!(pp.sendbuf.is_empty());
    }

    #[test]
    fn pp_transfer_is_comparable() {
        assert_eq!(PpTransfer::Body, PpTransfer::Body);
        assert_ne!(PpTransfer::Body, PpTransfer::None);
    }
}
