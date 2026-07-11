// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! Generic line-based command/response ("ping-pong") engine shared by curl's
//! four text protocols — FTP, IMAP, POP3 and SMTP. This is the memory-safe Rust
//! port of curl / libcurl **8.19.0-DEV**'s `lib/pingpong.c` (+ `lib/pingpong.h`),
//! guarded in C by `USE_PINGPONG` (defined whenever any of FTP/IMAP/POP3/SMTP is
//! enabled). The whole module is feature-gated by its declaration in
//! [`crate::protocols`] (`#[cfg(any(feature = "ftp", "imap", "pop3", "smtp"))]`),
//! so nothing here compiles unless at least one of those protocols is built.
//!
//! # What a "ping-pong" protocol is
//!
//! FTP/IMAP/POP3/SMTP all speak a back-and-forth dialogue: the client sends a
//! text command terminated by CRLF, the server answers with one or more text
//! response lines, and only then does the client send the next command. curl
//! factors the common send/receive/parse machinery into `struct pingpong`; each
//! protocol supplies just two behaviours — a **state-machine driver** and an
//! **end-of-response detector** — and shares everything else.
//!
//! Here those two C function pointers become the [`PingPongProtocol`] trait, and
//! `struct pingpong` becomes [`PingPong`]. The engine is deliberately kept
//! **protocol-agnostic**: every protocol-specific rule (FTP's `NNN-`/`NNN `
//! continuation convention, IMAP's tagged/untagged lines, POP3's `+OK`/`-ERR`
//! with `.`-terminated multiline, SMTP's `NNN-`/`NNN ` like FTP) lives entirely
//! inside the owning module's [`PingPongProtocol::endofresp`] implementation.
//! `ftp.rs`, `imap.rs`, `pop3.rs` and `smtp.rs` each own a [`PingPong`] instance
//! and implement [`PingPongProtocol`]; this module never imports them (they
//! depend on it, not the other way around).
//!
//! # Buffering & multi-line parsing (preserved byte-for-byte)
//!
//! [`PingPong::readresp`] keeps appending received bytes to an internal receive
//! buffer until [`PingPongProtocol::endofresp`] reports that a (possibly
//! multi-line) response is complete. It then records the length of the final
//! line in [`PingPong::nread_resp`]'s sibling bookkeeping and exposes any bytes
//! that arrived *after* the final line as `overflow`, so a protocol can pipeline
//! (see [`PingPong::moredata`]). This mirrors `Curl_pp_readresp` exactly.
//!
//! # Async model & the `sendf` note
//!
//! All socket I/O flows through the [`crate::conn`] connection/filter chain, so
//! TLS-upgraded FTPS/IMAPS/etc. is transparent at this layer. Reads and writes
//! are Tokio-async.
//!
//! One intentional shape difference from the C prototype: [`PingPong::sendf`] is
//! **synchronous**. curl's `Curl_pp_sendf` does one non-blocking `send` as part
//! of formatting a command, but the mandate for this engine is "never block —
//! just queue the bytes; the write path flushes them" (the actual network write
//! is the async [`PingPong::flushsend`]). Because `sendf` accepts
//! [`std::fmt::Arguments`], which is **not** `Send`, keeping it `async` would
//! make its future `!Send` and poison the `Send` futures of the protocol state
//! machines that call it — so a synchronous, allocation-then-buffer `sendf` is
//! both the correct and the mandated design. It formats the command, appends
//! CRLF itself, and buffers it; [`PingPong::flushsend`] performs the write.
//!
//! # Diagnostics
//!
//! Response and command lines are emitted via [`tracing`] at `trace` level
//! (curl's `Curl_debug`/`CURLINFO_HEADER_IN`/`CURLINFO_HEADER_OUT`). Forwarding
//! response lines to the application as `CLIENTWRITE_INFO` "headers" is a
//! transfer-layer concern that operates on the easy handle; it is applied by the
//! transfer layer once the ping-pong based protocols are wired into transfer
//! dispatch. The per-transfer [`crate::protocols::TransferCtx`] already carries
//! the response sink (curl's `Curl_client_write` path), exactly as curl routes
//! `Curl_client_write` through `data` rather than through the protocol vtable.
//!
//! # Safety
//!
//! This module honours the crate-wide `#![forbid(...)]` safe-code lint: it uses
//! only safe `std`/`bytes` operations — no raw pointers, no manual allocation,
//! and no FFI — so it introduces no memory-safety obligations of its own.

use std::fmt;
use std::os::fd::RawFd;
use std::time::{Duration, Instant};

use bytes::{Buf, BytesMut};

use crate::conn::{Connection, FIRSTSOCKET};
use crate::error::{CurlCode, Error, Result};

use super::{Pollset, ProtoFuture, CURL_POLL_IN, CURL_POLL_OUT};

// ===========================================================================
// Constants ported verbatim from the C sources.
// ===========================================================================

/// Default per-response timeout window, in milliseconds
/// (← `RESP_TIMEOUT`, `lib/urldata.h`: `#define RESP_TIMEOUT (60 * 1000)`).
///
/// Used by [`PingPong::init`] as the default [`PingPong::response_time`] when the
/// owning protocol has no `CURLOPT_SERVER_RESPONSE_TIMEOUT` to impose.
const RESP_TIMEOUT_MS: u64 = 60 * 1000;

/// Hard upper bound on the size of either command buffer
/// (← `DYN_PINGPPONG_CMD`, `lib/curlx/dynbuf.h`: `#define DYN_PINGPPONG_CMD
/// (64 * 1024)`).
///
/// curl's dynamic buffer refuses to grow past its configured maximum and returns
/// `CURLE_TOO_LARGE`; the same limit and the same error ([`Error::TooLarge`]) are
/// reproduced here for both the send and receive buffers.
const DYN_PINGPONG_CMD: usize = 64 * 1024;

/// Size of the fixed buffer a single [`PingPong::readresp`] socket read draws
/// into (← the `char buffer[900]` local in `Curl_pp_readresp`).
///
/// A read that fills it exactly makes the outer loop read again (there may be
/// more data immediately available), so this value doubles as the "keep
/// draining" watermark, matching the C `while(gotbytes == sizeof(buffer))`.
const PINGPONG_READ_BUFSIZE: usize = 900;

// ===========================================================================
// PpTransfer — whether/what to transfer (← `enum curl_pp_transfer`).
// ===========================================================================

/// Whether the transfer should download the body, only informational
/// headers/metadata, or nothing at all (← `enum curl_pp_transfer`,
/// `lib/pingpong.h`).
///
/// The owning protocol (FTP in particular) stores one of these to decide how
/// much of a response to actually stream to the caller.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PpTransfer {
    /// Yes, do transfer a body (← `PPTRANSFER_BODY`).
    Body,
    /// Do not transfer a body, but still go through to get info/headers
    /// (← `PPTRANSFER_INFO`).
    Info,
    /// Do not get anything and do not get info (← `PPTRANSFER_NONE`).
    None,
}

// ===========================================================================
// PingPong — the shared command/response state (← `struct pingpong`).
// ===========================================================================

/// The generic state used by protocols doing a server↔client back-and-forth
/// dialogue in the FTP/IMAP/POP3/SMTP style (← `struct pingpong`,
/// `lib/pingpong.h`).
///
/// It holds the outgoing-command buffer (for non-blocking sending) and the
/// received-response cache (for multi-line parsing), plus the response-timeout
/// bookkeeping. The two protocol behaviours it drives are supplied out-of-band
/// through the [`PingPongProtocol`] trait rather than being stored as function
/// pointers, so a `PingPong` is not generic over the protocol; the engine
/// methods that need the callbacks take `&mut impl PingPongProtocol` explicitly
/// (exactly as curl passes `data`/`conn` separately from `pp`).
///
/// Field names and roles are preserved from the C struct so that `--trace`
/// diagnostics and the `Curl_pp_*` semantics remain identical.
pub struct PingPong {
    /// Number of bytes read so far for the response currently being parsed
    /// (← `nread_resp`). Reset to `0` each time a full response completes.
    pub nread_resp: usize,

    /// The instant the current response's timeout window started — stamped when
    /// a command has finished being sent and a reply is awaited (← `response`, a
    /// `struct curltime` taken from `Curl_pgrs_now`).
    pub response: Instant,

    /// The response-timeout window applied by [`PingPong::state_timeout`]
    /// (← the `CURLOPT_SERVER_RESPONSE_TIMEOUT`, else [`RESP_TIMEOUT_MS`], that
    /// `Curl_pp_state_timeout` computes from `data->set`). Stored on the struct
    /// so the engine needs no easy-handle reference; the owning protocol may
    /// overwrite it after [`PingPong::init`].
    pub response_time: Duration,

    /// Outgoing command buffer (← `sendbuf`, a `dynbuf`). Holds the fully
    /// formatted command — including its trailing CRLF — that
    /// [`PingPong::sendf`] queued, until [`PingPong::flushsend`] drains it. Not
    /// exposed as a raw buffer.
    sendbuf: BytesMut,

    /// Number of bytes still to send from [`sendbuf`](Self::sendbuf)
    /// (← `sendleft`). The unsent tail is `sendbuf[sendsize - sendleft..]`.
    sendleft: usize,

    /// Total size of the queued command in [`sendbuf`](Self::sendbuf)
    /// (← `sendsize`).
    sendsize: usize,

    /// Accumulated received bytes being parsed into responses (← `recvbuf`, a
    /// `dynbuf`). The final response line is kept first in this buffer after a
    /// match so protocol parsers can read it via [`PingPong::response_line`].
    recvbuf: BytesMut,

    /// Number of bytes buffered *after* the final response line (← `overflow`).
    /// These belong to the next response (or to the data stream) and are what
    /// let a protocol pipeline; see [`PingPong::moredata`].
    overflow: usize,

    /// Length in bytes of the final response line, kept first in
    /// [`recvbuf`](Self::recvbuf) after a match (← `nfinal`).
    nfinal: usize,

    /// Whether the buffers/timers have been initialised (← `initialised`).
    initialised: bool,

    /// Whether a server response is pending or in progress (← `pending_resp`);
    /// set when a command is queued and cleared once the last response line has
    /// been read.
    pending_resp: bool,
}

impl PingPong {
    /// Create a fresh, un-initialised ping-pong state.
    ///
    /// This is the analogue of the zeroed embedded `struct pingpong` a protocol
    /// starts with: buffers are empty, all counters are `0`, and `initialised`
    /// is `false`. Call [`PingPong::init`] with the current instant before
    /// driving any exchange. [`response_time`](Self::response_time) is seeded
    /// with the [`RESP_TIMEOUT_MS`] default so `state_timeout` is meaningful even
    /// before a protocol overrides it.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nread_resp: 0,
            response: Instant::now(),
            response_time: Duration::from_millis(RESP_TIMEOUT_MS),
            sendbuf: BytesMut::new(),
            sendleft: 0,
            sendsize: 0,
            recvbuf: BytesMut::new(),
            overflow: 0,
            nfinal: 0,
            initialised: false,
            pending_resp: false,
        }
    }

    /// Initialise the buffers and timers to prepare for reading a fresh response
    /// (← `Curl_pp_init`).
    ///
    /// Mirrors the C routine: clears the read counter, starts the response
    /// timeout at `now`, marks a response pending, resets both buffers, and sets
    /// `initialised`. curl asserts the struct was not already initialised; the
    /// same debug assertion is reproduced. `now` is supplied by the caller (the
    /// cached `Curl_pgrs_now` in curl) rather than read from the clock here, so
    /// the timing is deterministic and testable.
    ///
    /// The remaining fields are reset defensively (curl relies on the struct
    /// being zeroed) so a `PingPong` reused after [`PingPong::disconnect`] starts
    /// clean.
    pub fn init(&mut self, now: Instant) {
        debug_assert!(
            !self.initialised,
            "Curl_pp_init on an already-initialised pingpong"
        );
        self.nread_resp = 0;
        self.response = now; // start response time-out
        self.response_time = Duration::from_millis(RESP_TIMEOUT_MS);
        self.pending_resp = true;
        self.sendbuf.clear();
        self.recvbuf.clear();
        self.sendleft = 0;
        self.sendsize = 0;
        self.overflow = 0;
        self.nfinal = 0;
        self.initialised = true;
    }

    /// Remaining time before the response timeout triggers, in milliseconds
    /// (← `Curl_pp_state_timeout`).
    ///
    /// A result `<= 0` means the timeout has already fired — the exact "0 or
    /// negative" convention of curl's `timediff_t`, which is why an `i64`
    /// (rather than a non-negative [`Duration`]) is returned.
    ///
    /// The value is `response_time - elapsed_since(response)`. If a transfer-wide
    /// timeout is also in force it is honoured: `xfer_timeleft_ms` is curl's
    /// `Curl_timeleft_ms(data)` — `0` means "no transfer timeout applies", and
    /// any smaller positive transfer deadline wins over the per-response window
    /// (matching `if(xfer_timeout_ms && (xfer_timeout_ms < timeout_ms))`).
    #[must_use]
    pub fn state_timeout(&self, now: Instant, xfer_timeleft_ms: i64) -> i64 {
        let response_time_ms = self.response_time.as_millis() as i64;
        // Elapsed since the response timer started; saturating so a clock that
        // appears to move backwards yields 0 elapsed rather than underflowing.
        let elapsed_ms = now.saturating_duration_since(self.response).as_millis() as i64;
        let timeout_ms = response_time_ms - elapsed_ms;

        // A transfer timeout of 0 means "no timeout applies".
        if xfer_timeleft_ms != 0 && xfer_timeleft_ms < timeout_ms {
            return xfer_timeleft_ms;
        }
        timeout_ms
    }

    /// Whether there are unsent buffered command bytes (← `Curl_pp_needs_flush`).
    ///
    /// True exactly when [`PingPong::flushsend`] still has work to do.
    #[must_use]
    pub fn needs_flush(&self) -> bool {
        self.sendleft > 0
    }

    /// Whether the receive buffer still holds an already-received response beyond
    /// what the last [`PingPong::readresp`] consumed (← `Curl_pp_moredata`).
    ///
    /// When true, a follow-up `readresp` can make progress without blocking on
    /// the socket — this is the pipelining hook. Reproduces curl's exact test
    /// `!pp->sendleft && curlx_dyn_len(&pp->recvbuf) > pp->nfinal`.
    #[must_use]
    pub fn moredata(&self) -> bool {
        self.sendleft == 0 && self.recvbuf.len() > self.nfinal
    }

    /// Whether a server response is pending or in progress (← `pending_resp`).
    ///
    /// Set when a command is queued by [`PingPong::sendf`] (and by
    /// [`PingPong::init`]); cleared by [`PingPong::readresp`] once the last
    /// response line of an exchange has been read.
    #[must_use]
    pub fn pending_resp(&self) -> bool {
        self.pending_resp
    }

    /// The final response line, kept first in the receive buffer after a match
    /// (`recvbuf[..nfinal]`).
    ///
    /// This is the memory-safe accessor protocol parsers use in place of curl's
    /// `curlx_dyn_ptr(&pp->recvbuf)` + `pp->nfinal`: after
    /// [`PingPong::readresp`] reports a completed response, the numeric status is
    /// returned via its `code` out-parameter while the textual final line (for
    /// any protocol-specific parsing, e.g. an FTP reply message or an SMTP
    /// enhanced status) is read here. It is an empty slice when no response has
    /// completed yet.
    #[must_use]
    pub fn response_line(&self) -> &[u8] {
        &self.recvbuf[..self.nfinal]
    }

    /// Reset the buffers and flags when a ping-pong connection is disconnected
    /// (← `Curl_pp_disconnect`).
    ///
    /// curl frees both dynbufs and `memset`s the struct to zero; the equivalent
    /// here drops the buffer storage and returns every counter/flag to its
    /// initial state. It is a no-op when the state was never initialised, so
    /// calling it twice is harmless. [`response`](Self::response) and
    /// [`response_time`](Self::response_time) are left as-is because they are
    /// meaningless while `initialised` is `false` and are overwritten by the next
    /// [`PingPong::init`].
    pub fn disconnect(&mut self) {
        if self.initialised {
            // Release the buffer allocations (curl's `curlx_dyn_free`).
            self.sendbuf = BytesMut::new();
            self.recvbuf = BytesMut::new();
            self.nread_resp = 0;
            self.sendleft = 0;
            self.sendsize = 0;
            self.overflow = 0;
            self.nfinal = 0;
            self.pending_resp = false;
            self.initialised = false;
        }
    }

    /// Contribute this exchange's desired socket readiness to `ps`
    /// (← `Curl_pp_pollset`).
    ///
    /// Requests **write** interest while there are buffered command bytes to
    /// flush ([`needs_flush`](Self::needs_flush)), otherwise **read** interest
    /// while awaiting a response — exactly curl's
    /// `flags = pp->sendleft ? CURL_POLL_OUT : CURL_POLL_IN` on the primary
    /// socket. If the transport has not yet exposed a socket (e.g. before the IP
    /// filter connects), nothing is added.
    pub fn pollset(&self, conn: &Connection, ps: &mut Pollset) {
        if let Some(fd) = conn.get_first_socket() {
            let action = if self.sendleft > 0 {
                CURL_POLL_OUT
            } else {
                CURL_POLL_IN
            };
            ps.set(fd as RawFd, action);
        }
    }
}

impl Default for PingPong {
    /// Same as [`PingPong::new`] — a fresh, un-initialised ping-pong state.
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// PingPongProtocol — the two behaviours a protocol MUST provide (← the
// `statemachine` + `endofresp` function pointers set by `PINGPONG_SETUP`).
// ===========================================================================

/// The two protocol-specific behaviours the ping-pong engine drives, supplied by
/// the owning protocol (FTP/IMAP/POP3/SMTP).
///
/// In C these are two function pointers embedded in `struct pingpong` and wired
/// up by the `PINGPONG_SETUP` macro. Here they are trait methods the protocol
/// implements on its own connection-state type. Keeping them on a separate trait
/// (rather than storing closures on [`PingPong`]) means the engine can hold a
/// `&mut PingPong` and a `&mut impl PingPongProtocol` as **distinct** borrows —
/// mirroring curl, where `pp` and `data`/`conn` are always separate arguments —
/// so no self-referential aliasing ever arises.
///
/// # Object safety / async shape
///
/// [`statemachine`](PingPongProtocol::statemachine) returns a boxed
/// [`ProtoFuture`] instead of being an `async fn`. This is the same idiom the
/// sibling [`crate::protocols::Protocol`] trait uses: it keeps the returned
/// future nameable and `Send` (so protocol state machines compose on Tokio's
/// multi-threaded runtime) and avoids the `async_fn_in_trait` lint under the
/// crate's `-D warnings` gate on the MSRV (Rust 1.75).
pub trait PingPongProtocol {
    /// Advance the protocol's own state machine one step (← the `statemachine`
    /// function pointer, `CURLcode (*)(struct Curl_easy *, struct connectdata
    /// *)`).
    ///
    /// The engine ([`PingPong::statemach`]) invokes this when the socket is (or,
    /// in blocking mode, becomes) ready. A typical implementation flushes any
    /// pending command via [`PingPong::flushsend`], reads the next response via
    /// [`PingPong::readresp`], acts on the returned status code, and queues the
    /// following command via [`PingPong::sendf`]. It receives the engine state
    /// (`pp`) and the [`Connection`] as separate borrows.
    fn statemachine<'a>(
        &'a mut self,
        pp: &'a mut PingPong,
        conn: &'a mut Connection,
    ) -> ProtoFuture<'a, ()>;

    /// Decide whether `line` completes a (possibly multi-line) response, and if
    /// so parse its numeric status into `code` (← the `endofresp` function
    /// pointer, `bool (*)(..., const char *ptr, size_t len, int *code)`).
    ///
    /// `line` is the latest complete response line (including its trailing CRLF),
    /// taken directly from the receive buffer. Return `true` at the **end** of a
    /// response and set `*code` to the parsed status (e.g. FTP `226`, SMTP `250`,
    /// or an IMAP tagged-`OK`-derived code); return `false` for an intermediate
    /// continuation line, in which case the engine consumes the line and keeps
    /// scanning. Each protocol's multi-line rule (FTP/SMTP `NNN-` vs `NNN `,
    /// POP3 `+OK`/`-ERR` with `.`-terminated multiline, IMAP tagged/untagged
    /// `*`) is encapsulated entirely here.
    fn endofresp(&mut self, line: &[u8], code: &mut i32) -> bool;
}

impl PingPong {
    /// Format a command, append CRLF, and buffer it for a non-blocking send
    /// (← `Curl_pp_sendf` / `Curl_pp_vsendf`, folded together since Rust has no
    /// `va_list`).
    ///
    /// The command text must **not** carry a trailing CRLF; this method appends
    /// the `"\r\n"` itself, exactly as the C prototype documents. The formatted
    /// bytes are queued into the send buffer and the send bookkeeping
    /// ([`sendsize`](Self::sendsize)/[`sendleft`](Self::sendleft)) is set so the
    /// whole command is pending; [`pending_resp`](Self::pending_resp) is marked.
    ///
    /// # Non-blocking
    ///
    /// This is synchronous and performs **no** network I/O — it only queues. The
    /// actual write is [`PingPong::flushsend`] (driven by the write path /
    /// [`PingPong::statemach`]), which starts the response timer once the command
    /// is fully on the wire. See the module docs for why buffering here is
    /// synchronous (in short: it accepts [`fmt::Arguments`], which is not `Send`,
    /// so an `async` shape would poison the caller's `Send` future — and the
    /// engine's contract is "never block, just queue").
    ///
    /// The [`pp_sendf!`](crate::pp_sendf) macro provides `println!`-style
    /// ergonomics over this method.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooLarge`] (curl's `CURLE_TOO_LARGE`) if the command plus
    /// its CRLF would exceed [`DYN_PINGPONG_CMD`] (64 KiB), matching the dynamic
    /// buffer's hard ceiling.
    pub fn sendf(&mut self, args: fmt::Arguments<'_>) -> Result<()> {
        // curl asserts no partial send is still outstanding when a new command is
        // formatted; reproduce those invariants in debug builds.
        debug_assert_eq!(self.sendleft, 0, "Curl_pp_sendf with a send still pending");
        debug_assert_eq!(self.sendsize, 0, "Curl_pp_sendf with a send still pending");

        // curlx_dyn_reset(&pp->sendbuf): start from empty.
        self.sendbuf.clear();

        // Render the caller's format arguments once, then enforce the same 64 KiB
        // ceiling curl's dynbuf imposes (command text + the 2-byte CRLF).
        let command = args.to_string();
        if command.len() + 2 > DYN_PINGPONG_CMD {
            return Err(Error::TooLarge);
        }

        self.sendbuf.extend_from_slice(command.as_bytes());
        // Append CRLF — the caller passes the bare command text.
        self.sendbuf.extend_from_slice(b"\r\n");

        // Diagnostic parity with curl's `Curl_debug(CURLINFO_HEADER_OUT, ...)`.
        tracing::trace!(
            target: "curl::pingpong",
            direction = "out",
            "{}",
            command
        );

        self.pending_resp = true;
        self.sendsize = self.sendbuf.len();
        self.sendleft = self.sendbuf.len();
        Ok(())
    }
}

/// `println!`-style helper over [`PingPong::sendf`] (← the variadic
/// `Curl_pp_sendf(data, pp, fmt, ...)` call sites).
///
/// Expands to `pp.sendf(format_args!(...))`, so it queues a CRLF-terminated
/// command without blocking and yields the same [`Result`](crate::error::Result)
/// `sendf` returns. Because `sendf` is synchronous, the result is used directly
/// (no `.await`):
///
/// ```ignore
/// use curl_rs_lib::pp_sendf;
/// pp_sendf!(pp, "USER {}", user)?;
/// pp_sendf!(pp, "PASS {}", pass)?;
/// ```
#[macro_export]
macro_rules! pp_sendf {
    ($pp:expr, $($arg:tt)*) => {
        $pp.sendf(::std::format_args!($($arg)*))
    };
}

// ===========================================================================
// Receive path — reading and parsing (possibly multi-line) responses
// (← `Curl_pp_readresp` and its two private helpers).
// ===========================================================================

impl PingPong {
    /// Read whatever response bytes are currently available and, if a complete
    /// (possibly multi-line) response has arrived, parse its status
    /// (← `Curl_pp_readresp`).
    ///
    /// This is the receive counterpart of [`PingPong::sendf`]. It draws bytes
    /// from the [`Connection`]'s filter chain at `sockindex` into the receive
    /// buffer, then scans that buffer line-by-line, deferring the decision of
    /// "is this the end of the response?" to the protocol's
    /// [`PingPongProtocol::endofresp`]. On completion it writes the parsed
    /// numeric status to `*code`, the accumulated response byte count to
    /// `*size`, records the final line's length in [`nfinal`](Self::nfinal), and
    /// exposes any bytes received *after* the final line as
    /// [`overflow`](Self::overflow) for pipelining (see [`PingPong::moredata`]).
    ///
    /// Both out-parameters are cleared to `0` on entry; if no complete response
    /// is available yet they remain `0` and the method returns `Ok(())` so the
    /// caller ([`PingPong::statemach`]) can poll again later. This mirrors
    /// `Curl_pp_readresp` down to the counting quirks: bytes served from a prior
    /// `overflow` are *not* re-counted, so a response satisfied entirely from
    /// overflow reports `*size == 0` exactly as curl does — a faithful behaviour,
    /// not a bug, and deliberately preserved.
    ///
    /// # Non-blocking
    ///
    /// A socket read that would block surfaces as [`CurlCode::Again`] from the
    /// filter chain and is translated to `Ok(())` (curl maps `CURLE_AGAIN` to
    /// `CURLE_OK` here), so this never blocks and never treats "no data yet" as
    /// an error.
    ///
    /// # Errors
    ///
    /// * [`Error::TooLarge`] — the receive buffer would exceed
    ///   [`DYN_PINGPONG_CMD`] (64 KiB).
    /// * [`CurlCode::RecvError`] — the peer closed the connection (0 bytes read
    ///   without an "again"), matching curl's `failf` + `CURLE_RECV_ERROR`.
    /// * Any transport error propagated from the filter chain.
    pub async fn readresp<P: PingPongProtocol>(
        &mut self,
        proto: &mut P,
        conn: &mut Connection,
        sockindex: usize,
        code: &mut i32,
        size: &mut usize,
    ) -> Result<()> {
        // `*code = 0` / `*size = 0`: cleared for the "error or not done" cases.
        *code = 0;
        *size = 0;

        // The fixed read buffer (← `char buffer[900]`).
        let mut buffer = [0u8; PINGPONG_READ_BUFSIZE];

        // Outer loop: `do { ... } while(gotbytes == sizeof(buffer))`. It always
        // runs at least once and repeats only while a read completely fills the
        // buffer (there may be more data immediately available).
        loop {
            let mut gotbytes = 0usize;

            // A previous call may have left the just-parsed final line at the
            // front of the buffer (kept so parsers could read it); drop it now
            // (← `if(pp->nfinal) { Curl_dyn_tail(&recvbuf, len - nfinal); ... }`).
            if self.nfinal > 0 {
                let keep = self.recvbuf.len() - self.nfinal;
                self.buf_tail(keep);
                self.nfinal = 0;
            }

            // Only read from the socket when there is no already-buffered
            // overflow to consume first (← `if(!pp->overflow)`).
            if self.overflow == 0 {
                // `pingpong_read(...)` via the connection filter chain. An empty
                // chain cannot yield data — surface it as a receive failure.
                let recv_result = match conn
                    .cfilter
                    .get_mut(sockindex)
                    .and_then(|slot| slot.as_mut())
                {
                    Some(chain) => chain.recv(&mut buffer).await,
                    None => Err(Error::Recv),
                };

                let n = match recv_result {
                    Ok(n) => n,
                    // CURLE_AGAIN → CURLE_OK: nothing to read right now.
                    Err(e) if e.code() == CurlCode::Again => return Ok(()),
                    Err(e) => return Err(e),
                };

                // Zero bytes without an "again" means the peer closed the
                // connection (← `failf(...); return CURLE_RECV_ERROR;`).
                if n == 0 {
                    return Err(Error::with_context(
                        CurlCode::RecvError,
                        "response reading failed",
                    ));
                }

                // `Curl_dyn_addn(&recvbuf, buffer, gotbytes)` + `nread_resp +=`.
                // (curl also bumps `data->req.headerbytecount` here; that is
                // transfer-layer bookkeeping applied once the easy-handle context
                // is threaded — see the module docs.)
                self.ingest(&buffer[..n])?;
                gotbytes = n;
            }

            // Inner loop: scan the accumulated buffer for a complete response.
            // Returns `true` once `endofresp` fires, in which case curl forces
            // the outer loop to stop by zeroing `gotbytes`.
            if self.scan(proto, code, size)? {
                gotbytes = 0;
            }

            // `while(gotbytes == sizeof(buffer))`.
            if gotbytes != PINGPONG_READ_BUFSIZE {
                break;
            }
        }

        // The command's response is no longer pending once a read pass completes
        // (← `pp->pending_resp = FALSE;`).
        self.pending_resp = false;
        Ok(())
    }

    /// Scan the accumulated receive buffer line-by-line, driving the protocol's
    /// [`PingPongProtocol::endofresp`] until a response completes or the buffer
    /// runs out of newline-terminated lines (← the inner `do { ... } while(1)`
    /// of `Curl_pp_readresp`).
    ///
    /// Returns `Ok(true)` when `endofresp` reports the end of a response — with
    /// [`nfinal`](Self::nfinal)/[`overflow`](Self::overflow) updated, `*size` set
    /// to the response byte count and [`nread_resp`](Self::nread_resp) reset for
    /// the next response — or `Ok(false)` when no complete line remains (the
    /// partial line is retained in the buffer for a later read to complete).
    ///
    /// Factored out of [`PingPong::readresp`] so it operates purely on the
    /// buffer: unit tests can feed canned byte streams to a stub
    /// [`PingPongProtocol`] and exercise the multi-line/overflow/`nfinal` logic
    /// without a live [`Connection`].
    fn scan<P: PingPongProtocol>(
        &mut self,
        proto: &mut P,
        code: &mut i32,
        size: &mut usize,
    ) -> Result<bool> {
        loop {
            // `memchr(line, '\n', len)`: a line ends at LF; the CR of a CRLF is
            // part of the line and left for the protocol parser to trim.
            let Some(pos) = self.recvbuf.iter().position(|&b| b == b'\n') else {
                // No newline: the response is incomplete, so there is nothing
                // buffered beyond it (← `pp->overflow = 0; break;`). The partial
                // line stays in `recvbuf` for the next read to extend.
                self.overflow = 0;
                return Ok(false);
            };
            let length = pos + 1; // include the trailing LF

            // Diagnostic parity with `Curl_debug(data, CURLINFO_HEADER_IN, ...)`.
            // Application-level `CLIENTWRITE_INFO` forwarding is applied by the
            // transfer layer (see the module docs), not here.
            tracing::trace!(
                target: "curl::pingpong",
                direction = "in",
                "{}",
                String::from_utf8_lossy(&self.recvbuf[..length])
                    .trim_end_matches(['\r', '\n'])
            );

            // Ask the protocol whether this line ends the (multi-line) response.
            if proto.endofresp(&self.recvbuf[..length], code) {
                // End of response. The final line is deliberately left at the
                // front of the buffer (parsers read it via
                // [`PingPong::response_line`]); it is trimmed at the start of the
                // next `readresp`. Any bytes past it become `overflow`.
                let len = self.recvbuf.len();
                self.nfinal = length;
                self.overflow = len.saturating_sub(length);
                *size = self.nread_resp; // size of the response
                self.nread_resp = 0; // restart for the next response
                return Ok(true);
            }

            // Intermediate continuation line: drop it and keep scanning
            // (← `if(len > length) Curl_dyn_tail(...); else Curl_dyn_reset(...)`).
            let len = self.recvbuf.len();
            if len > length {
                self.buf_tail(len - length);
            } else {
                self.recvbuf.clear();
            }
        }
    }

    /// Append freshly received bytes to the receive buffer, enforcing the 64 KiB
    /// ceiling and advancing the response byte counter
    /// (← `Curl_dyn_addn(&pp->recvbuf, ...)` + `pp->nread_resp += gotbytes`).
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] if the buffer would grow past [`DYN_PINGPONG_CMD`],
    /// mirroring the dynamic buffer's `CURLE_TOO_LARGE`.
    fn ingest(&mut self, data: &[u8]) -> Result<()> {
        if self.recvbuf.len() + data.len() > DYN_PINGPONG_CMD {
            return Err(Error::TooLarge);
        }
        self.recvbuf.extend_from_slice(data);
        self.nread_resp += data.len();
        Ok(())
    }

    /// Keep only the last `trail` bytes of the receive buffer, discarding the
    /// prefix (← `Curl_dyn_tail`, which memmoves the trailing `trail` bytes to
    /// the front and truncates).
    ///
    /// `trail` is always `<= recvbuf.len()` by construction at every call site.
    fn buf_tail(&mut self, trail: usize) {
        let len = self.recvbuf.len();
        debug_assert!(trail <= len, "buf_tail trail exceeds buffer length");
        let drop = len - trail;
        if drop > 0 {
            // `BytesMut::advance` drops the leading `drop` bytes, leaving the
            // last `trail` bytes — exactly the semantics of `Curl_dyn_tail`.
            self.recvbuf.advance(drop);
        }
    }
}

// ===========================================================================
// Send/flush and the drive loop (← `Curl_pp_flushsend` and `Curl_pp_statemach`).
// ===========================================================================

impl PingPong {
    /// Write any buffered-but-unsent command bytes to the connection
    /// (← `Curl_pp_flushsend`).
    ///
    /// [`PingPong::sendf`] only *queues* a command; this method performs the
    /// actual non-blocking write of the still-pending tail
    /// (`sendbuf[sendsize - sendleft ..]`) through the [`Connection`]'s primary
    /// filter chain. A short write leaves the remainder queued
    /// ([`sendleft`](Self::sendleft) is decremented); a complete write clears the
    /// send bookkeeping and (re)starts the response timer to `now` — exactly as
    /// curl stamps `pp->response = *Curl_pgrs_now(data)` once a command is fully
    /// on the wire, so the per-response timeout is measured from that instant.
    ///
    /// # Non-blocking
    ///
    /// A write that would block surfaces as [`CurlCode::Again`] and is treated as
    /// "zero bytes written" (curl maps `CURLE_AGAIN` to `CURLE_OK` with
    /// `written = 0`), so this never blocks; the caller flushes again later.
    ///
    /// # Errors
    ///
    /// Any transport error from the filter chain (other than "again"), or
    /// [`Error::Send`] if the primary filter chain is absent.
    pub async fn flushsend(&mut self, conn: &mut Connection, now: Instant) -> Result<()> {
        // Nothing queued → nothing to do (← `if(!Curl_pp_needs_flush(...))`).
        if !self.needs_flush() {
            return Ok(());
        }

        // The unsent tail is `sendbuf[sendsize - sendleft ..]`, `sendleft` bytes
        // long (← `pp->sendthis + pp->sendsize - pp->sendleft`, len `sendleft`).
        let start = self.sendsize - self.sendleft;
        let written = {
            let chunk = &self.sendbuf[start..];
            match conn
                .cfilter
                .get_mut(FIRSTSOCKET)
                .and_then(|slot| slot.as_mut())
            {
                // `Curl_conn_send(..., eos = FALSE, &written)`.
                Some(chain) => match chain.send(chunk, false).await {
                    Ok(n) => n,
                    // CURLE_AGAIN → CURLE_OK with `written = 0`.
                    Err(e) if e.code() == CurlCode::Again => 0,
                    Err(e) => return Err(e),
                },
                None => return Err(Error::Send),
            }
        };

        if written != self.sendleft {
            // Only a fraction was sent; keep the remainder queued.
            self.sendleft -= written;
        } else {
            // Fully flushed: clear the send state and start the response timer
            // (← `pp->sendthis = NULL; pp->sendleft = pp->sendsize = 0;
            // pp->response = *Curl_pgrs_now(data);`). The send buffer's bytes are
            // left in place and reset lazily by the next `sendf`, matching curl's
            // deferred `Curl_dyn_reset`.
            self.sendleft = 0;
            self.sendsize = 0;
            self.response = now;
        }
        Ok(())
    }

    /// Drive the protocol's state machine one step, honouring the response
    /// timeout and socket readiness (← `Curl_pp_statemach`).
    ///
    /// Higher layers call this repeatedly (it is the "ping-pong" pump): each call
    /// first enforces the per-response timeout via [`PingPong::state_timeout`]
    /// (with `now`/`xfer_timeleft_ms` supplying the values curl reads from the
    /// easy handle), then decides whether the socket is ready and, if so, invokes
    /// [`PingPongProtocol::statemachine`] exactly once.
    ///
    /// Readiness mirrors curl's `rc` computation: bytes already pending in the
    /// transport/TLS layer or buffered [`overflow`](Self::overflow) to parse make
    /// it immediately ready to read, and a queued command
    /// ([`sendleft`](Self::sendleft) `> 0`) makes it ready to write. When nothing
    /// is ready and `block` is set, the step is awaited but bounded by curl's
    /// 1-second interval (capped to the remaining response window); the caller
    /// re-enters and the cumulative response timeout is re-checked. When nothing
    /// is ready and `block` is clear, no step is taken (progress has stalled) and
    /// the caller polls again — unless `disconnecting`, in which case the socket
    /// is abandoned with [`CurlCode::OperationTimedout`], reproducing curl's
    /// `else if(disconnecting) return CURLE_OPERATION_TIMEDOUT;`.
    ///
    /// # Cancellation
    ///
    /// In `block` mode the awaited step may be cancelled when the interval
    /// elapses. Implementations of [`PingPongProtocol::statemachine`] must be
    /// cancel-safe up to any completed read: [`PingPong::readresp`] commits bytes
    /// to the receive buffer only after a `recv` fully returns, and a protocol
    /// advances its own state only after a complete response is parsed, so a
    /// cancelled step never leaves the engine buffers inconsistent — the step is
    /// simply retried on the next call.
    ///
    /// # Deferred
    ///
    /// curl additionally runs `Curl_pgrsCheck` (progress/abort and speed-limit
    /// checks) in blocking mode; that operates on the easy handle and is applied
    /// by the transfer layer, mirroring how `CLIENTWRITE_INFO` forwarding is
    /// deferred (see the module docs) rather than reached through the protocol
    /// vtable.
    ///
    /// # Errors
    ///
    /// * [`CurlCode::OperationTimedout`] — the response window is exhausted, or
    ///   the socket did not become ready while disconnecting.
    /// * Any error propagated from [`PingPongProtocol::statemachine`].
    pub async fn statemach<P: PingPongProtocol>(
        &mut self,
        proto: &mut P,
        conn: &mut Connection,
        block: bool,
        disconnecting: bool,
        now: Instant,
        xfer_timeleft_ms: i64,
    ) -> Result<()> {
        // Curl_pp_state_timeout: bail immediately if the window is already spent.
        let timeout_ms = self.state_timeout(now, xfer_timeleft_ms);
        if timeout_ms <= 0 {
            return Err(Error::with_context(
                CurlCode::OperationTimedout,
                "server response timeout",
            ));
        }

        // Fast-ready conditions matching curl's `rc = 1` branches: bytes pending
        // in the transport/TLS layer, or buffered overflow to parse. A queued
        // command (`sendleft > 0`) means we want to *write*, which curl drives by
        // polling for writability — effectively always ready — so it is included.
        let ready = conn.data_pending(FIRSTSOCKET) || self.overflow > 0 || self.sendleft > 0;

        if ready {
            // rc == 1: run one protocol step now.
            return proto.statemachine(self, conn).await;
        }

        if block {
            // curl's blocking path waits up to `interval_ms` (1 s, capped to the
            // remaining response window) for readability before running the state
            // machine. Bound the awaited step by that same interval; if it makes
            // no progress in time the caller re-enters and the response timeout
            // above is re-checked cumulatively.
            let interval_ms = timeout_ms.clamp(1, 1000) as u64;
            match tokio::time::timeout(
                Duration::from_millis(interval_ms),
                proto.statemachine(self, conn),
            )
            .await
            {
                Ok(result) => result, // became ready and ran (rc > 0)
                Err(_elapsed) => {
                    // rc == 0: not ready within the interval.
                    if disconnecting {
                        Err(Error::with_context(
                            CurlCode::OperationTimedout,
                            "server response timeout",
                        ))
                    } else {
                        Ok(())
                    }
                }
            }
        } else if disconnecting {
            // Non-blocking, nothing ready, shutting down (← `else if(disconnecting)
            // return CURLE_OPERATION_TIMEDOUT;`).
            Err(Error::with_context(
                CurlCode::OperationTimedout,
                "server response timeout",
            ))
        } else {
            // Non-blocking and nothing to do yet: rc == 0, statemachine not
            // invoked, caller polls again (← `return CURLE_OK;`).
            Ok(())
        }
    }
}

// ===========================================================================
// Tests — canned FTP/SMTP/POP3/IMAP byte streams driven through stub protocols,
// plus end-to-end read/flush/drive coverage over an in-memory mock filter.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};

    use crate::conn::filters::{CfFuture, FilterCtx, QueryCtx, QueryOut};
    use crate::conn::{CfQuery, CfType, ConnectionFilter, FilterChain, Scheme, Transport};

    // ----- Stub protocols: each encapsulates one protocol's `endofresp` rule --

    /// FTP/SMTP style: a line `NNN-...` continues the response, a line `NNN ...`
    /// (space after three digits) terminates it. `statemachine` just counts how
    /// many times the engine drove it.
    #[derive(Default)]
    struct NnnProto {
        calls: usize,
    }

    impl PingPongProtocol for NnnProto {
        fn statemachine<'a>(
            &'a mut self,
            _pp: &'a mut PingPong,
            _conn: &'a mut Connection,
        ) -> ProtoFuture<'a, ()> {
            self.calls += 1;
            Box::pin(async { Ok(()) })
        }

        fn endofresp(&mut self, line: &[u8], code: &mut i32) -> bool {
            if line.len() < 4 || !line[..3].iter().all(|b| b.is_ascii_digit()) {
                return false;
            }
            // A dash after the status number marks a continuation line.
            if line[3] == b'-' {
                return false;
            }
            *code = std::str::from_utf8(&line[..3]).unwrap().parse().unwrap();
            true
        }
    }

    /// Trim a single trailing CRLF (or bare LF) from a line.
    fn strip_eol(line: &[u8]) -> &[u8] {
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        line.strip_suffix(b"\r").unwrap_or(line)
    }

    /// POP3 style: in single-line mode `+OK`/`-ERR` terminates immediately; in
    /// multi-line mode the response ends at a line that is exactly `.`.
    #[derive(Default)]
    struct Pop3Proto {
        multiline: bool,
        calls: usize,
    }

    impl PingPongProtocol for Pop3Proto {
        fn statemachine<'a>(
            &'a mut self,
            _pp: &'a mut PingPong,
            _conn: &'a mut Connection,
        ) -> ProtoFuture<'a, ()> {
            self.calls += 1;
            Box::pin(async { Ok(()) })
        }

        fn endofresp(&mut self, line: &[u8], code: &mut i32) -> bool {
            if line.starts_with(b"+OK") {
                *code = 0;
            } else if line.starts_with(b"-ERR") {
                *code = 1;
            }
            if self.multiline {
                // Only a lone "." ends a multi-line response.
                strip_eol(line) == b"."
            } else {
                line.starts_with(b"+OK") || line.starts_with(b"-ERR")
            }
        }
    }

    /// IMAP style: untagged (`*`) and continuation (`+`) lines do not end a
    /// response; the tagged line does, mapping `OK` → 0 and anything else → 1.
    #[derive(Default)]
    struct ImapProto {
        calls: usize,
    }

    impl PingPongProtocol for ImapProto {
        fn statemachine<'a>(
            &'a mut self,
            _pp: &'a mut PingPong,
            _conn: &'a mut Connection,
        ) -> ProtoFuture<'a, ()> {
            self.calls += 1;
            Box::pin(async { Ok(()) })
        }

        fn endofresp(&mut self, line: &[u8], code: &mut i32) -> bool {
            if line.starts_with(b"*") || line.starts_with(b"+") {
                return false;
            }
            *code = if line.windows(4).any(|w| w == b" OK ") {
                0
            } else {
                1
            };
            true
        }
    }

    // ----- In-memory mock connection filter (leaf; overrides send/recv) -------

    /// Shared, inspectable I/O state for [`MockFilter`].
    #[derive(Default)]
    struct MockIo {
        /// Bytes handed to `recv`, consumed from the front.
        to_deliver: Vec<u8>,
        /// Bytes accepted by `send`, for assertion.
        captured: Vec<u8>,
        /// If set, each `send` accepts at most this many bytes (partial-write).
        accept_limit: Option<usize>,
        /// If set, `recv` reports [`CurlCode::Again`] instead of delivering.
        again: bool,
    }

    /// A leaf filter terminating the chain: it never delegates, instead
    /// delivering canned bytes on `recv` and capturing written bytes on `send`.
    struct MockFilter {
        io: Arc<Mutex<MockIo>>,
        fd: i32,
    }

    impl ConnectionFilter for MockFilter {
        fn name(&self) -> &'static str {
            "MOCK"
        }

        fn cf_type(&self) -> CfType {
            CfType::IP_CONNECT
        }

        fn send<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            buf: &'a [u8],
            _eos: bool,
        ) -> CfFuture<'a, Result<usize>> {
            let io = Arc::clone(&self.io);
            let data = buf.to_vec();
            Box::pin(async move {
                let mut g = io.lock().unwrap();
                let take = g.accept_limit.map_or(data.len(), |lim| lim.min(data.len()));
                g.captured.extend_from_slice(&data[..take]);
                Ok(take)
            })
        }

        fn recv<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            buf: &'a mut [u8],
        ) -> CfFuture<'a, Result<usize>> {
            let io = Arc::clone(&self.io);
            Box::pin(async move {
                let mut g = io.lock().unwrap();
                if g.again {
                    return Err(Error::Again);
                }
                let n = g.to_deliver.len().min(buf.len());
                buf[..n].copy_from_slice(&g.to_deliver[..n]);
                g.to_deliver.drain(..n);
                Ok(n)
            })
        }

        fn data_pending(&self, _cx: &QueryCtx<'_>) -> bool {
            !self.io.lock().unwrap().to_deliver.is_empty()
        }

        fn query(&self, _cx: &QueryCtx<'_>, query: CfQuery, out: &mut QueryOut) -> Result<()> {
            match query {
                CfQuery::Socket => {
                    *out = QueryOut::Socket(self.fd);
                    Ok(())
                }
                CfQuery::Transport => {
                    *out = QueryOut::Transport(Transport::Tcp);
                    Ok(())
                }
                _ => Err(Error::Code(CurlCode::UnknownOption)),
            }
        }
    }

    // ----- Helpers ------------------------------------------------------------

    /// A freshly initialised engine with the default response window.
    fn init_pp() -> PingPong {
        let mut pp = PingPong::new();
        pp.init(Instant::now());
        pp
    }

    /// A network connection whose primary chain is the given mock filter.
    fn conn_with(io: Arc<Mutex<MockIo>>, fd: i32) -> Connection {
        let mut conn = Connection::new(Scheme::new("ftp", 21), "example.com", 21);
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(MockFilter { io, fd }));
        conn.cfilter[FIRSTSOCKET] = Some(chain);
        conn
    }

    // ----- PpTransfer ---------------------------------------------------------

    #[test]
    fn pp_transfer_variants_are_distinct() {
        assert_ne!(PpTransfer::Body, PpTransfer::Info);
        assert_ne!(PpTransfer::Info, PpTransfer::None);
        let t = PpTransfer::Body;
        assert_eq!(t, PpTransfer::Body); // Copy + Eq
    }

    // ----- scan(): multi-line / overflow / nfinal / code ----------------------

    #[test]
    fn scan_ftp_multiline_terminates_and_sets_code() {
        let mut pp = init_pp();
        let mut proto = NnnProto::default();
        pp.ingest(b"220-hello\r\n220 ready\r\n").unwrap();
        let mut code = -1;
        let mut size = 0;
        assert!(pp.scan(&mut proto, &mut code, &mut size).unwrap());
        assert_eq!(code, 220);
        assert_eq!(size, 22); // all ingested bytes counted for the response
        assert_eq!(pp.nfinal, 11); // "220 ready\r\n"
        assert_eq!(pp.overflow, 0);
        assert!(!pp.moredata());
        assert_eq!(pp.response_line(), b"220 ready\r\n");
    }

    #[test]
    fn scan_ftp_overflow_is_tracked() {
        let mut pp = init_pp();
        let mut proto = NnnProto::default();
        pp.ingest(b"226 done\r\n200 next\r\n").unwrap();
        let mut code = 0;
        let mut size = 0;
        assert!(pp.scan(&mut proto, &mut code, &mut size).unwrap());
        assert_eq!(code, 226);
        assert_eq!(pp.nfinal, 10); // "226 done\r\n"
        assert_eq!(pp.overflow, 10); // "200 next\r\n" arrived after the final line
        assert!(pp.moredata());
        assert_eq!(pp.response_line(), b"226 done\r\n");
    }

    #[test]
    fn scan_smtp_multiline_like_ftp() {
        let mut pp = init_pp();
        let mut proto = NnnProto::default();
        pp.ingest(b"250-SIZE 100\r\n250 OK\r\n").unwrap();
        let mut code = 0;
        let mut size = 0;
        assert!(pp.scan(&mut proto, &mut code, &mut size).unwrap());
        assert_eq!(code, 250);
        assert_eq!(pp.response_line(), b"250 OK\r\n");
        assert_eq!(pp.overflow, 0);
    }

    #[test]
    fn scan_pop3_single_line() {
        let mut pp = init_pp();
        let mut proto = Pop3Proto::default();
        pp.ingest(b"+OK logged in\r\n").unwrap();
        let mut code = -1;
        let mut size = 0;
        assert!(pp.scan(&mut proto, &mut code, &mut size).unwrap());
        assert_eq!(code, 0);
        assert_eq!(pp.overflow, 0);
        assert_eq!(pp.response_line(), b"+OK logged in\r\n");
    }

    #[test]
    fn scan_pop3_error_line_maps_code() {
        let mut pp = init_pp();
        let mut proto = Pop3Proto::default();
        pp.ingest(b"-ERR nope\r\n").unwrap();
        let mut code = -1;
        let mut size = 0;
        assert!(pp.scan(&mut proto, &mut code, &mut size).unwrap());
        assert_eq!(code, 1);
    }

    #[test]
    fn scan_pop3_multiline_dot_terminated() {
        let mut pp = init_pp();
        let mut proto = Pop3Proto {
            multiline: true,
            calls: 0,
        };
        pp.ingest(b"+OK 2 messages\r\nfirst\r\nsecond\r\n.\r\n")
            .unwrap();
        let mut code = -1;
        let mut size = 0;
        assert!(pp.scan(&mut proto, &mut code, &mut size).unwrap());
        assert_eq!(code, 0); // set from the "+OK" status line
        assert_eq!(pp.response_line(), b".\r\n"); // final line is the lone dot
        assert_eq!(pp.overflow, 0);
    }

    #[test]
    fn scan_imap_tagged_ends_response() {
        let mut pp = init_pp();
        let mut proto = ImapProto::default();
        pp.ingest(b"* OK preamble\r\nA1 OK LOGIN done\r\n").unwrap();
        let mut code = -1;
        let mut size = 0;
        assert!(pp.scan(&mut proto, &mut code, &mut size).unwrap());
        assert_eq!(code, 0); // tagged OK
        assert_eq!(pp.response_line(), b"A1 OK LOGIN done\r\n");
        assert_eq!(pp.overflow, 0);
    }

    #[test]
    fn scan_incomplete_line_keeps_partial() {
        let mut pp = init_pp();
        let mut proto = NnnProto::default();
        pp.ingest(b"220 par").unwrap(); // no newline yet
        let mut code = 0;
        let mut size = 0;
        assert!(!pp.scan(&mut proto, &mut code, &mut size).unwrap());
        assert_eq!(pp.overflow, 0);
        assert_eq!(pp.recvbuf.len(), 7); // partial line retained for the next read
    }

    // ----- sendf() / pp_sendf! ------------------------------------------------

    #[test]
    fn sendf_appends_crlf_and_queues() {
        let mut pp = init_pp();
        pp.sendf(format_args!("USER {}", "alice")).unwrap();
        assert!(pp.needs_flush());
        assert_eq!(pp.sendleft, "USER alice\r\n".len());
        assert_eq!(pp.sendsize, "USER alice\r\n".len());
        assert_eq!(&pp.sendbuf[..], b"USER alice\r\n");
        assert!(pp.pending_resp());
    }

    #[test]
    fn pp_sendf_macro_matches_sendf() {
        let mut pp = init_pp();
        crate::pp_sendf!(pp, "PASS {}", "secret").unwrap();
        assert_eq!(&pp.sendbuf[..], b"PASS secret\r\n");
    }

    #[test]
    fn sendf_rejects_oversized_command() {
        let mut pp = init_pp();
        let big = "x".repeat(DYN_PINGPONG_CMD); // + CRLF would exceed the cap
        let err = pp.sendf(format_args!("{big}")).unwrap_err();
        assert_eq!(err.code(), CurlCode::TooLarge);
    }

    // ----- ingest() cap -------------------------------------------------------

    #[test]
    fn ingest_enforces_64k_cap() {
        let mut pp = init_pp();
        let fill = vec![b'a'; DYN_PINGPONG_CMD];
        assert!(pp.ingest(&fill).is_ok()); // exactly at the cap is allowed
        assert_eq!(pp.ingest(b"x").unwrap_err().code(), CurlCode::TooLarge);
    }

    // ----- state_timeout() ----------------------------------------------------

    #[test]
    fn state_timeout_counts_down_and_respects_xfer_cap() {
        let mut pp = PingPong::new();
        let now = Instant::now();
        pp.init(now);
        // Full window remaining when no time has elapsed and no transfer cap.
        let full = pp.state_timeout(now, 0);
        assert!(full > 0 && full <= RESP_TIMEOUT_MS as i64);
        // A tighter transfer deadline caps the result.
        assert_eq!(pp.state_timeout(now, 5_000), 5_000);
        // A looser transfer deadline does not.
        assert_eq!(pp.state_timeout(now, RESP_TIMEOUT_MS as i64 + 10_000), full);
        // Elapsing past the window yields a non-positive timeout.
        let later = now + Duration::from_millis(RESP_TIMEOUT_MS + 10);
        assert!(pp.state_timeout(later, 0) <= 0);
    }

    // ----- init() / disconnect() / accessors ---------------------------------

    #[test]
    fn init_then_disconnect_resets_state() {
        let mut pp = PingPong::new();
        pp.init(Instant::now());
        assert!(pp.pending_resp());
        assert!(!pp.needs_flush());
        assert!(!pp.moredata());

        pp.sendf(format_args!("NOOP")).unwrap();
        pp.ingest(b"junk").unwrap();
        assert!(pp.needs_flush());

        pp.disconnect();
        assert!(!pp.needs_flush());
        assert!(!pp.moredata());
        assert_eq!(pp.sendleft, 0);
        assert_eq!(pp.sendbuf.len(), 0);
        assert_eq!(pp.recvbuf.len(), 0);
    }

    // ----- readresp(): end-to-end over the mock filter ------------------------

    #[tokio::test]
    async fn readresp_reads_a_complete_response() {
        let io = Arc::new(Mutex::new(MockIo {
            to_deliver: b"220-hi\r\n220 ok\r\n".to_vec(),
            ..MockIo::default()
        }));
        let mut conn = conn_with(Arc::clone(&io), 42);
        let mut pp = init_pp();
        let mut proto = NnnProto::default();
        let mut code = 0;
        let mut size = 0;
        pp.readresp(&mut proto, &mut conn, FIRSTSOCKET, &mut code, &mut size)
            .await
            .unwrap();
        assert_eq!(code, 220);
        assert_eq!(size, 16);
        assert_eq!(pp.response_line(), b"220 ok\r\n");
        assert!(!pp.pending_resp());
    }

    #[tokio::test]
    async fn readresp_pipelines_second_response_from_overflow() {
        let io = Arc::new(Mutex::new(MockIo {
            to_deliver: b"226 done\r\n200 next\r\n".to_vec(),
            ..MockIo::default()
        }));
        let mut conn = conn_with(Arc::clone(&io), 42);
        let mut pp = init_pp();
        let mut proto = NnnProto::default();

        // First call reads the socket and returns the first response, leaving
        // the second buffered as overflow.
        let mut code = 0;
        let mut size = 0;
        pp.readresp(&mut proto, &mut conn, FIRSTSOCKET, &mut code, &mut size)
            .await
            .unwrap();
        assert_eq!(code, 226);
        assert!(pp.moredata());

        // Second call performs no socket read; it parses the overflow. curl
        // reports size == 0 for a response served entirely from overflow — a
        // faithful quirk, deliberately preserved.
        let mut code2 = 0;
        let mut size2 = 0;
        pp.readresp(&mut proto, &mut conn, FIRSTSOCKET, &mut code2, &mut size2)
            .await
            .unwrap();
        assert_eq!(code2, 200);
        assert_eq!(size2, 0);
        assert_eq!(pp.overflow, 0);
        assert!(!pp.moredata());
    }

    #[tokio::test]
    async fn readresp_again_maps_to_ok() {
        let io = Arc::new(Mutex::new(MockIo {
            again: true,
            ..MockIo::default()
        }));
        let mut conn = conn_with(Arc::clone(&io), 42);
        let mut pp = init_pp();
        let mut proto = NnnProto::default();
        let mut code = 9;
        let mut size = 9;
        pp.readresp(&mut proto, &mut conn, FIRSTSOCKET, &mut code, &mut size)
            .await
            .unwrap();
        // CURLE_AGAIN → CURLE_OK, with nothing parsed.
        assert_eq!(code, 0);
        assert_eq!(size, 0);
    }

    #[tokio::test]
    async fn readresp_zero_bytes_is_recv_error() {
        let io = Arc::new(Mutex::new(MockIo::default())); // empty → recv returns 0
        let mut conn = conn_with(Arc::clone(&io), 42);
        let mut pp = init_pp();
        let mut proto = NnnProto::default();
        let mut code = 0;
        let mut size = 0;
        let err = pp
            .readresp(&mut proto, &mut conn, FIRSTSOCKET, &mut code, &mut size)
            .await
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::RecvError);
    }

    // ----- flushsend(): end-to-end over the mock filter -----------------------

    #[tokio::test]
    async fn flushsend_handles_partial_then_full_write() {
        let io = Arc::new(Mutex::new(MockIo {
            accept_limit: Some(4),
            ..MockIo::default()
        }));
        let mut conn = conn_with(Arc::clone(&io), 42);
        let mut pp = init_pp();
        pp.sendf(format_args!("NOOP")).unwrap(); // "NOOP\r\n" = 6 bytes
        assert_eq!(pp.sendleft, 6);

        // First flush: only 4 of 6 bytes accepted.
        pp.flushsend(&mut conn, Instant::now()).await.unwrap();
        assert_eq!(pp.sendleft, 2);
        assert!(pp.needs_flush());

        // Allow the remainder; the send completes and the response timer resets.
        io.lock().unwrap().accept_limit = None;
        let stamp = Instant::now();
        pp.flushsend(&mut conn, stamp).await.unwrap();
        assert_eq!(pp.sendleft, 0);
        assert_eq!(pp.sendsize, 0);
        assert!(!pp.needs_flush());
        assert_eq!(pp.response, stamp);
        assert_eq!(&io.lock().unwrap().captured[..], b"NOOP\r\n");
    }

    #[tokio::test]
    async fn flushsend_is_noop_when_nothing_queued() {
        let io = Arc::new(Mutex::new(MockIo::default()));
        let mut conn = conn_with(Arc::clone(&io), 42);
        let mut pp = init_pp();
        pp.flushsend(&mut conn, Instant::now()).await.unwrap();
        assert!(io.lock().unwrap().captured.is_empty());
    }

    // ----- statemach(): timeout / readiness / disconnect ----------------------

    #[tokio::test]
    async fn statemach_times_out_when_window_spent() {
        let io = Arc::new(Mutex::new(MockIo::default()));
        let mut conn = conn_with(Arc::clone(&io), 42);
        let mut pp = PingPong::new();
        let start = Instant::now();
        pp.init(start);
        let mut proto = NnnProto::default();
        let later = start + Duration::from_millis(RESP_TIMEOUT_MS + 100);
        let err = pp
            .statemach(&mut proto, &mut conn, false, false, later, 0)
            .await
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::OperationTimedout);
        assert_eq!(proto.calls, 0);
    }

    #[tokio::test]
    async fn statemach_idle_when_not_ready_and_nonblocking() {
        let io = Arc::new(Mutex::new(MockIo::default())); // nothing pending
        let mut conn = conn_with(Arc::clone(&io), 42);
        let mut pp = init_pp();
        let mut proto = NnnProto::default();
        pp.statemach(&mut proto, &mut conn, false, false, Instant::now(), 0)
            .await
            .unwrap();
        assert_eq!(proto.calls, 0); // stalled: state machine not driven
    }

    #[tokio::test]
    async fn statemach_times_out_when_disconnecting_and_idle() {
        let io = Arc::new(Mutex::new(MockIo::default()));
        let mut conn = conn_with(Arc::clone(&io), 42);
        let mut pp = init_pp();
        let mut proto = NnnProto::default();
        let err = pp
            .statemach(&mut proto, &mut conn, false, true, Instant::now(), 0)
            .await
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::OperationTimedout);
        assert_eq!(proto.calls, 0);
    }

    #[tokio::test]
    async fn statemach_drives_state_machine_when_ready() {
        let io = Arc::new(Mutex::new(MockIo::default()));
        let mut conn = conn_with(Arc::clone(&io), 42);
        let mut pp = init_pp();
        let mut proto = NnnProto::default();
        // A queued command makes the engine "ready to write".
        pp.sendf(format_args!("NOOP")).unwrap();
        pp.statemach(&mut proto, &mut conn, false, false, Instant::now(), 0)
            .await
            .unwrap();
        assert_eq!(proto.calls, 1);
    }

    // ----- pollset() ----------------------------------------------------------

    #[test]
    fn pollset_wants_write_when_sending_else_read() {
        let io = Arc::new(Mutex::new(MockIo::default()));
        let conn = conn_with(Arc::clone(&io), 77);
        let mut pp = init_pp();

        // Awaiting a response with nothing queued → interested in reading.
        let mut ps = Pollset::new();
        pp.pollset(&conn, &mut ps);
        assert_eq!(ps.action_of(77), CURL_POLL_IN);

        // With a command queued → interested in writing.
        pp.sendf(format_args!("NOOP")).unwrap();
        let mut ps2 = Pollset::new();
        pp.pollset(&conn, &mut ps2);
        assert_eq!(ps2.action_of(77), CURL_POLL_OUT);
    }
}
