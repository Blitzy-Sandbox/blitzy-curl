//! POP3 / POP3S protocol engine — the Rust analog of `lib/pop3.c` (+ `lib/pop3.h`).
//!
//! This module implements the `pop3://` and `pop3s://` scheme handlers, the
//! Rust successor to curl's monolithic `pop3.c` (≈49 KB). It builds on the
//! generic command/response engine ([`crate::protocols::pingpong`]) and the
//! SASL state machine ([`crate::auth::sasl`]), exactly as the C code layered
//! `pop3_conn` on top of `struct pingpong` and `struct SASL`.
//!
//! # Architecture
//!
//! * **State machine.** curl's repeat-call `pop3_statemachine` (driven by the
//!   hand-rolled `select`/`poll` multi loop) collapses here into a single
//!   `async fn` that `.await`s each server response. The [`Pop3State`] enum
//!   mirrors C's `pop3state` one-for-one, and the per-state response handlers
//!   reproduce `pop3_state_*_resp` byte-for-byte.
//! * **Per-connection state** lives in [`Pop3Conn`] (the analog of C
//!   `struct pop3_conn`), boxed into [`crate::conn::Connection::set_proto_state`]
//!   so it survives connection reuse — the [`Protocol`] trait handler is
//!   stateless (`&self`), matching the established convention of this crate.
//! * **Three authentication paths**, exactly as curl: cleartext `USER`/`PASS`,
//!   the POP3-specific `APOP` MD5 challenge (implemented here with
//!   [`crate::util::md5`]), and SASL `AUTH` (delegated to
//!   [`crate::auth::sasl`]).
//! * **`STLS` upgrade** (RFC 2595) wraps the live connection with a TLS filter
//!   via [`crate::conn`], then re-issues `CAPA`. `pop3s://` is implicit TLS.
//! * **Multi-line responses** (`RETR`/`LIST`/`TOP`/…) terminate with a lone
//!   `.` line and use dot-stuffing: a body line that begins with `.` is doubled
//!   by the server. [`DotState`] un-stuffs this byte-exactly and detects the
//!   `\r\n.\r\n` end-of-body marker, reproducing C's `pop3_write`.
//!
//! # Safety
//!
//! This module contains zero `unsafe` code; the crate-root
//! `#![forbid(unsafe_code)]` (declared on `crate::protocols`) is inherited and
//! deliberately not re-declared here.

use crate::auth::sasl::{
    decode_mech, Sasl, SaslParams, SaslProgress, SaslProto, SASL_AUTH_DEFAULT, SASL_AUTH_NONE,
    SASL_FLAG_BASE64,
};
use crate::conn::connect::tls_factory;
use crate::conn::{BoxFuture, Connection, Curl_conn_connect, Curl_conn_is_ssl, FIRSTSOCKET};
use crate::easy::Easy;
use crate::error::{CurlError, Result};
use crate::protocols::pingpong::{tls_config_from_easy, PingPong, PingPongProtocol};
use crate::protocols::{
    Protocol, ProtocolTransfer, Scheme, TransferDirection, SCHEME_POP3, SCHEME_POP3S,
};
use crate::setopt::StrId;
use crate::url::{CurlUPart, CurlUrl, CURLU_GUESS_SCHEME, CURLU_NON_SUPPORT_SCHEME};
use crate::util::md5;
use crate::util::sendf;

// ===========================================================================
// Constants (C `lib/pop3.c` / `lib/pop3.h`)
// ===========================================================================

/// POP3 authentication type: none selected (C `POP3_TYPE_NONE`).
const POP3_TYPE_NONE: u8 = 0;
/// POP3 authentication type: cleartext `USER`/`PASS` (C `POP3_TYPE_CLEARTEXT`).
const POP3_TYPE_CLEARTEXT: u8 = 1 << 0;
/// POP3 authentication type: `APOP` MD5 challenge (C `POP3_TYPE_APOP`).
const POP3_TYPE_APOP: u8 = 1 << 1;
/// POP3 authentication type: SASL `AUTH` (C `POP3_TYPE_SASL`).
const POP3_TYPE_SASL: u8 = 1 << 2;
/// All POP3 authentication types (C `POP3_TYPE_ANY`).
const POP3_TYPE_ANY: u8 = POP3_TYPE_CLEARTEXT | POP3_TYPE_APOP | POP3_TYPE_SASL;

/// The POP3 end-of-body marker `\r\n.\r\n` (C `POP3_EOB`, 5 bytes).
const POP3_EOB: &[u8] = b"\r\n.\r\n";
/// Length of [`POP3_EOB`] (C `POP3_EOB_LEN`).
const POP3_EOB_LEN: usize = 5;

// `CURLUSESSL_*` wire values (`include/curl/curl.h`). Defined locally as plain
// ABI constants (not imported) so this module stays within its dependency
// whitelist; the values are fixed by the public API and never change.
/// `CURLUSESSL_NONE` — do not attempt to use SSL.
const CURLUSESSL_NONE: u8 = 0;
/// `CURLUSESSL_TRY` — try using SSL, proceed anyway otherwise.
const CURLUSESSL_TRY: u8 = 1;

// ===========================================================================
// State machine (C `pop3state`)
// ===========================================================================

/// The POP3 connection state, a one-for-one image of C's `pop3state` enum
/// (`lib/pop3.c`). Drives [`Pop3Conn`]'s command/response sequencing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pop3State {
    /// No connect/transfer in progress (C `POP3_STOP`). Terminal.
    Stop,
    /// Awaiting the server greeting (C `POP3_SERVERGREET`).
    ServerGreet,
    /// Awaiting the `CAPA` capability listing (C `POP3_CAPA`).
    Capa,
    /// Awaiting the `STLS` response (C `POP3_STARTTLS`).
    StartTls,
    /// Performing the TLS handshake after `STLS` (C `POP3_UPGRADETLS`).
    UpgradeTls,
    /// Awaiting a SASL `AUTH` exchange response (C `POP3_AUTH`).
    Auth,
    /// Awaiting the `APOP` response (C `POP3_APOP`).
    Apop,
    /// Awaiting the `USER` response (C `POP3_USER`).
    User,
    /// Awaiting the `PASS` response (C `POP3_PASS`).
    Pass,
    /// Awaiting a command (`RETR`/`LIST`/…) response (C `POP3_COMMAND`).
    Command,
    /// Awaiting the `QUIT` response (C `POP3_QUIT`).
    Quit,
    /// Sentinel marking the count of states (C `POP3_LAST`). Never a live state.
    Last,
}

// ===========================================================================
// Per-easy request state (C `struct POP3`)
// ===========================================================================

/// Per-transfer POP3 request state, the Rust image of C `struct POP3`.
///
/// In curl this hangs off the easy handle (`CURL_META_POP3_EASY`); here it is
/// carried inside [`Pop3Conn`] for the duration of a transfer, since the
/// connection serves one transfer at a time in this model.
#[derive(Debug, Clone, Default)]
pub struct Pop3 {
    /// What to transfer for the active command (C `POP3.transfer`).
    pub transfer: Pop3Transfer,
    /// The message id parsed from the URL path (C `POP3.id`); empty for a
    /// mailbox-level `LIST`.
    pub id: String,
    /// A custom request overriding the default command (C `POP3.custom`,
    /// `CURLOPT_CUSTOMREQUEST`), if any.
    pub custom: Option<String>,
}

/// What a POP3 command transfers — the Rust mirror of C's `curl_pp_transfer`
/// (`PPTRANSFER_*`) as used by POP3, kept as its own small enum so [`Pop3`] does
/// not depend on the ping-pong engine's internal naming.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Pop3Transfer {
    /// Transfer the response body (C `PPTRANSFER_BODY`). The default.
    #[default]
    Body,
    /// Get info only, no body (C `PPTRANSFER_INFO`) — a message-specific `LIST`.
    Info,
    /// Transfer nothing (C `PPTRANSFER_NONE`).
    None,
}

// ===========================================================================
// SASL I/O shim (C `struct SASLproto saslpop3`)
// ===========================================================================

/// The POP3 SASL command staging shim — the Rust successor to C's `saslpop3`
/// vtable.
///
/// The [`SaslProto`] I/O methods have no connection handle (the SASL engine is
/// transport-agnostic), so they *stage* the command bytes here; the POP3 state
/// machine flushes the staged command through the ping-pong layer afterwards.
/// `get_message` returns the server payload captured from the latest `+ …`
/// continuation line (the raw bytes; the SASL layer performs any base64
/// decode), mirroring C's `pop3_get_message`.
#[derive(Debug, Default)]
struct Pop3SaslIo {
    /// The command staged by the last [`SaslProto`] I/O call (without the CRLF,
    /// which the ping-pong layer appends), consumed by the state machine.
    cmd: Option<String>,
    /// The server SASL payload extracted from the latest continuation line,
    /// handed back by [`SaslProto::get_message`].
    msg: Vec<u8>,
}

impl SaslProto for Pop3SaslIo {
    fn service(&self) -> &str {
        // C-oracle parity: `saslpop3.service` is "pop" (NOT "pop3"). This is
        // wire-significant for GSSAPI service-principal names, so we follow the
        // C source over the implementation brief.
        "pop"
    }

    fn maxirlen(&self) -> usize {
        // C-oracle parity: `saslpop3` sets `255 - 8` ("Max line len -
        // strlen('AUTH ') - 1 space - crlf"), NOT 0. An initial response longer
        // than this forces a separate continuation round.
        255 - 8
    }

    fn cont_code(&self) -> i32 {
        // C `saslpop3`: continuation expected on '+'.
        i32::from(b'+')
    }

    fn final_code(&self) -> i32 {
        // C `saslpop3`: success indicated by '+'.
        i32::from(b'+')
    }

    fn def_mechs(&self) -> u16 {
        SASL_AUTH_DEFAULT
    }

    fn flags(&self) -> u16 {
        SASL_FLAG_BASE64
    }

    fn send_auth(&mut self, mech: &str, initial_resp: Option<&[u8]>) -> Result<()> {
        // C `pop3_perform_auth`: "AUTH <mech> <ir>" when an initial response is
        // present, otherwise "AUTH <mech>". The bytes are already wire-ready
        // (base64) because `flags()` advertises `SASL_FLAG_BASE64`.
        self.cmd = Some(match initial_resp {
            Some(ir) => format!("AUTH {mech} {}", String::from_utf8_lossy(ir)),
            None => format!("AUTH {mech}"),
        });
        Ok(())
    }

    fn cont_auth(&mut self, _mech: &str, resp: &[u8]) -> Result<()> {
        // C `pop3_continue_auth`: send the (base64) continuation verbatim.
        self.cmd = Some(String::from_utf8_lossy(resp).into_owned());
        Ok(())
    }

    fn cancel_auth(&mut self, _mech: &str) -> Result<()> {
        // C `pop3_cancel_auth`: a single '*' aborts the exchange.
        self.cmd = Some("*".to_string());
        Ok(())
    }

    fn get_message(&mut self) -> Result<Vec<u8>> {
        Ok(core::mem::take(&mut self.msg))
    }
}

// ===========================================================================
// Multi-line body un-stuffing / EOB detection (C `pop3_write`)
// ===========================================================================

/// The stateful dot-stuffing / end-of-body scanner, the Rust image of the
/// `pop3c->eob` / `pop3c->strip` machinery driven by C's `pop3_write`.
///
/// POP3 multi-line responses (`RETR`/`TOP`/…) terminate with the 5-byte marker
/// `\r\n.\r\n` ([`POP3_EOB`]); a body line that itself begins with `.` is
/// doubled by the server (dot-stuffing) and must be un-stuffed on receipt. The
/// marker (and any partial match) may be split across arbitrarily many network
/// chunks, so the match position [`eob`](Self::eob) persists between calls.
#[derive(Debug, Default)]
struct DotState {
    /// How many bytes of [`POP3_EOB`] have matched so far (`0..=5`); C
    /// `pop3c->eob`.
    eob: usize,
    /// How many leading bytes of the current match to suppress from output
    /// (the `+OK`-line CRLF that opens the body); C `pop3c->strip`.
    strip: usize,
}

impl DotState {
    /// Initialise for a fresh `RETR`/multi-line download.
    ///
    /// C `pop3_state_command_resp` seeds `eob = 2` and `strip = 2`: the `+OK`
    /// line's terminating CRLF is the first two bytes of [`POP3_EOB`], so it
    /// pre-counts as a partial match, but those two bytes are *not* part of the
    /// body and are stripped.
    fn for_download() -> Self {
        Self { eob: 2, strip: 2 }
    }

    /// Process `input` body bytes, appending the un-stuffed, EOB-trimmed output
    /// to `out`. Returns `true` once the full end-of-body marker has been seen
    /// (the transfer is complete and the receiver should stop reading).
    ///
    /// This is a faithful port of C `pop3_write`: it walks each byte, advancing
    /// or resetting the [`POP3_EOB`] match, emits the body portion preceding a
    /// match start, replays the matched prefix of a *failed* partial match
    /// (because those bytes were genuine body content), strips the doubled dot,
    /// and on a full match emits the leading CRLF (RFC-1939 §3 considers it part
    /// of the message) before signalling completion.
    fn process(&mut self, input: &[u8], out: &mut Vec<u8>) -> bool {
        let nread = input.len();
        let mut strip_dot = false;
        let mut last = 0usize;

        let mut i = 0usize;
        while i < nread {
            let prev = self.eob;

            match input[i] {
                0x0d => {
                    if self.eob == 0 {
                        self.eob += 1;
                        if i != 0 {
                            // Body bytes that did not match the marker.
                            out.extend_from_slice(&input[last..i]);
                            last = i;
                        }
                    } else if self.eob == 3 {
                        self.eob += 1;
                    } else {
                        // Match not at position 0 or 3 → restart the pattern.
                        self.eob = 1;
                    }
                }
                0x0a => {
                    if self.eob == 1 || self.eob == 4 {
                        self.eob += 1;
                    } else {
                        self.eob = 0;
                    }
                }
                0x2e => {
                    if self.eob == 2 {
                        self.eob += 1;
                    } else if self.eob == 3 {
                        // An extra dot after CRLF — the stuffed dot to strip.
                        strip_dot = true;
                        self.eob = 0;
                    } else {
                        self.eob = 0;
                    }
                }
                _ => {
                    self.eob = 0;
                }
            }

            // Did we have a partial match which has now failed?
            if prev != 0 && prev >= self.eob {
                // `strip` can only be non-zero for the first mismatch after the
                // opening CRLF; then `prev == strip` and nothing is emitted.
                let mut prev = prev;
                while prev != 0 && self.strip != 0 {
                    prev -= 1;
                    self.strip -= 1;
                }

                if prev != 0 {
                    if strip_dot && prev - 1 > 0 {
                        // Partial match was CRLF + dot: emit only the CRLF, the
                        // server inserted the dot.
                        out.extend_from_slice(&POP3_EOB[..prev - 1]);
                    } else if !strip_dot {
                        out.extend_from_slice(&POP3_EOB[..prev]);
                    }
                    last = i;
                    strip_dot = false;
                }
            }

            i += 1;
        }

        if self.eob == POP3_EOB_LEN {
            // Full match: the leading CRLF of the marker is delivered as part of
            // the message (RFC-1939 §3); the transfer is then complete.
            out.extend_from_slice(&POP3_EOB[..2]);
            self.eob = 0;
            return true;
        }

        if self.eob != 0 {
            // Mid-match: emit nothing until we know whether it completes.
            return false;
        }

        if nread - last != 0 {
            out.extend_from_slice(&input[last..nread]);
        }

        false
    }
}

/// Per-transfer body-delivery state, held by the [`Pop3Protocol`] handler behind
/// a mutex (the handler is created fresh per transfer, like
/// [`crate::protocols::rtsp`]'s session).
#[derive(Debug, Default)]
struct Pop3WriteState {
    /// The dot-stuffing / EOB scanner for the active multi-line download.
    dot: DotState,
    /// Un-stuffed body bytes awaiting delivery to the client writer (drained by
    /// the transfer engine via [`Pop3Protocol::take_pending_body`]).
    pending_body: Vec<u8>,
    /// Set once the end-of-body marker has been consumed.
    recv_done: bool,
}

// ===========================================================================
// Per-connection state (C `struct pop3_conn`)
// ===========================================================================

/// The per-connection POP3 state, the Rust image of C `struct pop3_conn`.
///
/// Boxed into [`Connection::set_proto_state`] for the life of the connection
/// and reclaimed on `done`/`disconnect`. Implements [`PingPongProtocol`] so the
/// ping-pong engine can drive its [`statemachine`](PingPongProtocol::statemachine)
/// and [`endofresp`](PingPongProtocol::endofresp) hooks.
pub struct Pop3Conn {
    /// The generic command/response engine (C `pop3_conn.pp`).
    pp: PingPong,
    /// The SASL negotiation state (C `pop3_conn.sasl`).
    sasl: Sasl,
    /// The SASL command-staging shim (the Rust face of the `saslpop3` vtable's
    /// per-exchange scratch).
    sasl_io: Pop3SaslIo,
    /// The current protocol state (C `pop3_conn.state`).
    state: Pop3State,
    /// The APOP timestamp captured from the greeting, including the angle
    /// brackets (C `pop3_conn.apoptimestamp`); `None` if the server offered no
    /// RFC-822-conformant timestamp.
    apoptimestamp: Option<Vec<u8>>,
    /// The authentication types the server supports (C `pop3_conn.authtypes`).
    authtypes: u8,
    /// The preferred authentication type, from the URL `;AUTH=` option
    /// (C `pop3_conn.preftype`).
    preftype: u8,
    /// Whether the server advertised `STLS` (C `pop3_conn.tls_supported`).
    tls_supported: bool,
    /// Whether the TLS handshake after `STLS` has completed
    /// (C `pop3_conn.ssldone`).
    ssldone: bool,
    /// The latest final response line captured during
    /// [`endofresp`](PingPongProtocol::endofresp) (the ping-pong `recvbuf` is
    /// private, so the protocol stashes what it needs here). Includes the
    /// trailing CRLF.
    last_line: Vec<u8>,
    /// The connection user name (the Rust analog of `conn->user`), sourced from
    /// the URL during connect.
    user: String,
    /// The connection password (the Rust analog of `conn->passwd`), sourced
    /// from the URL during connect.
    passwd: String,
    /// The per-transfer request state (C `struct POP3`).
    req: Pop3,
}

impl Pop3Conn {
    /// Build fresh per-connection state (the analog of allocating
    /// `struct pop3_conn` in C `pop3_connect`).
    #[must_use]
    fn new() -> Self {
        Self {
            pp: PingPong::new(),
            sasl: Sasl::new(),
            sasl_io: Pop3SaslIo::default(),
            state: Pop3State::Stop,
            apoptimestamp: None,
            authtypes: POP3_TYPE_NONE,
            preftype: POP3_TYPE_ANY,
            tls_supported: false,
            ssldone: false,
            last_line: Vec::new(),
            user: String::new(),
            passwd: String::new(),
            req: Pop3::default(),
        }
    }
}

// ===========================================================================
// The stateless scheme handler (C `Curl_handler_pop3` / `_pop3s`)
// ===========================================================================

/// The POP3 / POP3S [`Protocol`] handler — the Rust successor to curl's
/// `Curl_handler_pop3` and `Curl_handler_pop3s` dispatch tables.
///
/// One instance is created per transfer (see
/// [`crate::protocols::scheme_handler`]); the per-connection machinery lives on
/// the [`Connection`] (via [`Pop3Conn`]), while the short-lived body-delivery
/// scratch lives here behind a mutex.
pub struct Pop3Protocol {
    /// The bound scheme — [`SCHEME_POP3`] or [`SCHEME_POP3S`].
    scheme: &'static Scheme,
    /// Per-transfer body-delivery state (dot-unstuffing + pending body).
    write_state: std::sync::Mutex<Pop3WriteState>,
}

impl Pop3Protocol {
    /// Build a handler bound to `scheme` ([`SCHEME_POP3`] or [`SCHEME_POP3S`]).
    #[must_use]
    pub fn new(scheme: &'static Scheme) -> Self {
        Self {
            scheme,
            write_state: std::sync::Mutex::new(Pop3WriteState::default()),
        }
    }

    /// Drain the un-stuffed body bytes accumulated by
    /// [`write_resp`](Protocol::write_resp), for delivery to the client writer
    /// by the transfer engine (mirrors
    /// [`crate::protocols::rtsp`]'s `take_pending_body`).
    #[must_use]
    pub fn take_pending_body(&self) -> Vec<u8> {
        std::mem::take(&mut self.write_state.lock().unwrap().pending_body)
    }

    /// Whether the end-of-body marker has been consumed (the download is done).
    #[must_use]
    pub fn body_complete(&self) -> bool {
        self.write_state.lock().unwrap().recv_done
    }
}

/// Construct a `pop3://` handler (C `Curl_handler_pop3`).
#[must_use]
pub fn pop3_handler() -> Box<dyn Protocol> {
    Box::new(Pop3Protocol::new(&SCHEME_POP3))
}

/// Construct a `pop3s://` handler (C `Curl_handler_pop3s`).
#[must_use]
pub fn pop3s_handler() -> Box<dyn Protocol> {
    Box::new(Pop3Protocol::new(&SCHEME_POP3S))
}

// ===========================================================================
// Free helpers (byte-exact ports of the C oracle's small static functions)
// ===========================================================================

/// The POP3 command table — a one-for-one image of C's `pop3cmds[]`
/// (`lib/pop3.c`). Each entry is `(name, multiline, multiline_with_args)`:
/// `multiline` is whether the bare command yields a multi-line response, and
/// `multiline_with_args` whether it does so when given arguments. Used by
/// [`pop3_is_multiline`] to decide whether a `do_it` command has a body.
const POP3CMDS: &[(&[u8], bool, bool)] = &[
    (b"APOP", false, false),
    (b"AUTH", false, false),
    (b"CAPA", true, true),
    (b"DELE", false, false),
    (b"LIST", true, false),
    (b"MSG", true, true),
    (b"NOOP", false, false),
    (b"PASS", false, false),
    (b"QUIT", false, false),
    (b"RETR", true, true),
    (b"RSET", false, false),
    (b"STAT", false, false),
    (b"STLS", false, false),
    (b"TOP", true, true),
    (b"UIDL", true, false),
    (b"USER", false, false),
    (b"UTF8", false, false),
    (b"XTND", true, true),
];

/// Is `b` a horizontal whitespace byte (C `ISBLANK`: space or tab)?
#[inline]
fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Is `b` an end-of-line byte (C `ISNEWLINE`: CR or LF)?
#[inline]
fn is_newline(b: u8) -> bool {
    b == b'\r' || b == b'\n'
}

/// The numeric value of a single hex digit, or `None` if `b` is not one.
#[inline]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Lower-case hex encoding of `digest` (C `curl_msnprintf("%02x")` per byte).
/// Produces exactly `2 * digest.len()` ASCII characters.
fn hex_lower(digest: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(digest.len() * 2);
    for &b in digest {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Extract the SASL message payload from a `+ …` continuation line — a byte-for-
/// byte port of C `pop3_get_message`.
///
/// `line` is the captured final response line including its trailing CRLF. The
/// leading two bytes (`"+ "`) and any further leading blanks are skipped, then
/// trailing blanks and newlines are trimmed; the remaining bytes are the raw
/// (still base64-encoded) server challenge. A line of two bytes or fewer yields
/// an empty payload (C's "junk input => zero length output").
fn extract_sasl_message(line: &[u8]) -> Vec<u8> {
    let len = line.len();
    if len <= 2 {
        return Vec::new();
    }
    // Skip the "+ " prefix, then any further leading blanks.
    let mut start = 2;
    while start < len && is_blank(line[start]) {
        start += 1;
    }
    // Trim trailing blanks and newlines back to `start`.
    let mut end = len;
    while end > start && (is_blank(line[end - 1]) || is_newline(line[end - 1])) {
        end -= 1;
    }
    line[start..end].to_vec()
}

/// Scan a server greeting line for an APOP timestamp — a byte-for-byte port of
/// the `<…@…>` search in C `pop3_state_servergreet_resp`.
///
/// Returns the timestamp *including* its angle brackets when the line contains a
/// `<…>` span that also holds an `@` (the RFC-822 message-id syntax RFC-1939
/// requires for APOP); otherwise `None`.
fn scan_apop_timestamp(line: &[u8]) -> Option<Vec<u8>> {
    let lt = line.iter().position(|&b| b == b'<')?;
    // Search the remainder (from '<') for the closing '>'.
    let gt = lt + line[lt..].iter().position(|&b| b == b'>')?;
    let timestamp = &line[lt..=gt];
    if timestamp.contains(&b'@') {
        Some(timestamp.to_vec())
    } else {
        None
    }
}

/// Whether a POP3 command word yields a multi-line response — a byte-for-byte
/// port of C `pop3_is_multiline`.
///
/// `cmdline` is the command as it will be sent (the bare verb here, e.g.
/// `b"RETR"`). Matching is case-insensitive against [`POP3CMDS`]; an exact match
/// uses the `multiline` flag, a match followed by a space uses
/// `multiline_with_args`, and an unknown command defaults to multi-line (C's
/// backward-compatibility fallback).
fn pop3_is_multiline(cmdline: &[u8]) -> bool {
    for &(name, multiline, multiline_with_args) in POP3CMDS {
        let nlen = name.len();
        if cmdline.len() >= nlen && cmdline[..nlen].eq_ignore_ascii_case(name) {
            if cmdline.len() == nlen {
                return multiline;
            } else if cmdline[nlen] == b' ' {
                return multiline_with_args;
            }
        }
    }
    // Unknown command: assume multi-line for backward compatibility.
    true
}

/// Percent-decode a URL component (the Rust stand-in for C `Curl_urldecode` over
/// the POP3 message-id path / credentials). Invalid `%XX` escapes are left
/// verbatim; the result is interpreted as UTF-8 (lossily), matching how the
/// surrounding engine treats POP3 identifiers as text.
fn percent_decode(input: &[u8]) -> String {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            if let (Some(h), Some(l)) = (hex_val(input[i + 1]), hex_val(input[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse the transfer URL into `(user, password, options, message_id)` using the
/// crate URL engine ([`CurlUrl`]).
///
/// Mirrors C `pop3_connect` (credentials and `;options` from the URL) and
/// `pop3_parse_url_path` (the message id is the path with its leading `/`
/// stripped, URL-decoded). Credentials are URL-decoded to match curl's
/// `conn->user` / `conn->passwd`. Any parse failure yields all-empty values,
/// leaving the connect phase to stop gracefully when no username is present.
fn parse_url_info(data: &Easy) -> (String, String, Option<String>, String) {
    let Some(url) = data.url() else {
        return (String::new(), String::new(), None, String::new());
    };
    let mut handle = CurlUrl::new();
    if handle
        .set(
            CurlUPart::Url,
            Some(url),
            CURLU_GUESS_SCHEME | CURLU_NON_SUPPORT_SCHEME,
        )
        .is_err()
    {
        return (String::new(), String::new(), None, String::new());
    }
    match handle.to_request_parts() {
        Ok(parts) => {
            // C `pop3_parse_url_path`: path with the leading '/' removed, decoded.
            let id = if parts.path.len() > 1 {
                percent_decode(&parts.path.as_bytes()[1..])
            } else {
                String::new()
            };
            let user = parts
                .user
                .map(|u| percent_decode(u.as_bytes()))
                .unwrap_or_default();
            let passwd = parts
                .password
                .map(|p| percent_decode(p.as_bytes()))
                .unwrap_or_default();
            (user, passwd, parts.options, id)
        }
        Err(_) => (String::new(), String::new(), None, String::new()),
    }
}

// ===========================================================================
// Pop3Conn — URL options, SASL helpers, the `perform_*` senders, the per-state
// response handlers, the dispatch switch, and the async drive loop.
// ===========================================================================

impl Pop3Conn {
    /// Parse the URL `;options` string (C `pop3_parse_url_options`).
    ///
    /// Iterates `key=value` pairs separated by `;`. The only recognised key is
    /// `AUTH=`, handed to the SASL engine; the special value `+APOP` selects
    /// APOP preference. After parsing, the preferred auth *type* is derived from
    /// the resulting SASL `prefmech`, exactly as C does. An unrecognised key is
    /// a [`CurlError::UrlMalformat`].
    fn parse_url_options(&mut self, options: &[u8]) -> Result<()> {
        let mut result: Result<()> = Ok(());
        let n = options.len();
        let mut ptr = 0usize;

        while result.is_ok() && ptr < n {
            let key_start = ptr;
            while ptr < n && options[ptr] != b'=' {
                ptr += 1;
            }
            // Value begins just after '=' (or at end if there is no '=').
            let value_start = (ptr + 1).min(n);
            while ptr < n && options[ptr] != b';' {
                ptr += 1;
            }
            let value = &options[value_start..ptr];
            let key = &options[key_start..];

            if key.len() >= 5 && key[..5].eq_ignore_ascii_case(b"AUTH=") {
                match self.sasl.parse_url_auth_option(value) {
                    Ok(()) => {}
                    Err(_) => {
                        // C: a `+APOP` value (any prefix of it, per the C
                        // `curl_strnequal(value, "+APOP", len)` semantics)
                        // selects APOP and clears the SASL preference.
                        let apop = value.len() <= 5
                            && b"+APOP"[..value.len()].eq_ignore_ascii_case(value);
                        if apop {
                            self.preftype = POP3_TYPE_APOP;
                            self.sasl.prefmech = SASL_AUTH_NONE;
                        } else {
                            result = Err(CurlError::UrlMalformat);
                        }
                    }
                }
            } else {
                result = Err(CurlError::UrlMalformat);
            }

            if ptr < n && options[ptr] == b';' {
                ptr += 1;
            }
        }

        // Derive the preferred auth type from the SASL preference (unless APOP
        // was explicitly selected above). C's post-loop switch.
        if self.preftype != POP3_TYPE_APOP {
            self.preftype = if self.sasl.prefmech == SASL_AUTH_NONE {
                POP3_TYPE_NONE
            } else if self.sasl.prefmech == SASL_AUTH_DEFAULT {
                POP3_TYPE_ANY
            } else {
                POP3_TYPE_SASL
            };
        }

        result
    }

    /// Snapshot the owned SASL input strings/flags so a [`SaslParams`] can be
    /// built from locals (avoiding aliasing `self` while
    /// [`Sasl::start`]/[`Sasl::cont`] mutably borrow `self.sasl`/`self.sasl_io`).
    fn sasl_inputs(&self, data: &Easy, conn: &Connection) -> (String, String, String, u16, bool, bool) {
        (
            self.user.clone(),
            self.passwd.clone(),
            conn.remote_host.clone(),
            conn.remote_port,
            data.set.sasl_ir,
            data.set.allow_auth_to_other_hosts,
        )
    }

    /// Emit the SASL "no mechanism could be selected" diagnostics (C
    /// `Curl_sasl_is_blocked`, which always resolves to
    /// [`CurlError::LoginDenied`]). Only the verbose `infof` lines are
    /// reproduced; the caller returns the error code.
    fn sasl_is_blocked(&self, data: &Easy) {
        let enabled = self.sasl.authmechs & self.sasl.prefmech;
        if self.sasl.authmechs == 0 {
            sendf::infof(data.set.verbose, "SASL: no auth mechanism was offered or recognized");
        } else if enabled == 0 {
            sendf::infof(
                data.set.verbose,
                "SASL: no overlap between offered and configured auth mechanisms",
            );
        } else {
            sendf::infof(data.set.verbose, "SASL: no auth mechanism offered could be selected");
        }
    }

    /// Send `CAPA` and enter [`Pop3State::Capa`] (C `pop3_perform_capa`). Resets
    /// the discovered SASL mechanisms and TLS capability first.
    async fn perform_capa(
        &mut self,
        pp: &mut PingPong,
        data: &Easy,
        conn: &mut Connection,
    ) -> Result<()> {
        self.sasl.authmechs = SASL_AUTH_NONE;
        self.sasl.authused = SASL_AUTH_NONE;
        self.tls_supported = false;
        pp.send_command(data, conn, "CAPA").await?;
        self.state = Pop3State::Capa;
        Ok(())
    }

    /// Send `STLS` and enter [`Pop3State::StartTls`] (C `pop3_perform_starttls`).
    async fn perform_starttls(
        &mut self,
        pp: &mut PingPong,
        data: &Easy,
        conn: &mut Connection,
    ) -> Result<()> {
        pp.send_command(data, conn, "STLS").await?;
        self.state = Pop3State::StartTls;
        Ok(())
    }

    /// Send `USER <name>` and enter [`Pop3State::User`] (C `pop3_perform_user`).
    /// With no username configured the connect phase stops (C's
    /// `!data->state.aptr.user` guard).
    async fn perform_user(
        &mut self,
        pp: &mut PingPong,
        data: &Easy,
        conn: &mut Connection,
    ) -> Result<()> {
        if self.user.is_empty() {
            self.state = Pop3State::Stop;
            return Ok(());
        }
        let cmd = format!("USER {}", self.user);
        pp.send_command(data, conn, &cmd).await?;
        self.state = Pop3State::User;
        Ok(())
    }

    /// Send `APOP <user> <digest>` and enter [`Pop3State::Apop`] (C
    /// `pop3_perform_apop`). The digest is the lower-case hex MD5 of the APOP
    /// timestamp concatenated with the password. With no username the connect
    /// phase stops; a missing timestamp likewise stops (APOP is only selected
    /// when a timestamp was captured, so this is defensive).
    async fn perform_apop(
        &mut self,
        pp: &mut PingPong,
        data: &Easy,
        conn: &mut Connection,
    ) -> Result<()> {
        if self.user.is_empty() {
            self.state = Pop3State::Stop;
            return Ok(());
        }
        let Some(timestamp) = self.apoptimestamp.clone() else {
            self.state = Pop3State::Stop;
            return Ok(());
        };
        // digest = MD5(timestamp ++ passwd); MD5 is update-order agnostic, so a
        // single hash over the concatenation equals C's two `Curl_MD5_update`s.
        let mut buf = timestamp;
        buf.extend_from_slice(self.passwd.as_bytes());
        let digest = md5::md5it(&buf);
        let secret = hex_lower(&digest);
        let cmd = format!("APOP {} {secret}", self.user);
        pp.send_command(data, conn, &cmd).await?;
        self.state = Pop3State::Apop;
        Ok(())
    }

    /// Send `QUIT` and enter [`Pop3State::Quit`] (C `pop3_perform_quit`).
    async fn perform_quit(
        &mut self,
        pp: &mut PingPong,
        data: &Easy,
        conn: &mut Connection,
    ) -> Result<()> {
        pp.send_command(data, conn, "QUIT").await?;
        self.state = Pop3State::Quit;
        Ok(())
    }

    /// Issue the DO-phase command (`RETR`/`LIST`/custom) and enter
    /// [`Pop3State::Command`] (C `pop3_perform_command`).
    ///
    /// `LIST` is used for a mailbox listing or when `list_only` is set;
    /// a message-specific `LIST` switches the transfer to [`Pop3Transfer::Info`]
    /// (no body). Otherwise `RETR` downloads the message. A non-multi-line
    /// command (C `data->req.no_body`) carries no body, so the transfer is set
    /// to [`Pop3Transfer::None`].
    async fn perform_command(
        &mut self,
        pp: &mut PingPong,
        data: &Easy,
        conn: &mut Connection,
    ) -> Result<()> {
        let list_only = data.set.list_only;
        let id = self.req.id.clone();

        let mut command: String = if id.is_empty() || list_only {
            if !id.is_empty() {
                // Message-specific LIST: skip the body transfer.
                self.req.transfer = Pop3Transfer::Info;
            }
            "LIST".to_string()
        } else {
            "RETR".to_string()
        };

        if let Some(custom) = self.req.custom.clone() {
            if !custom.is_empty() {
                command = custom;
            }
        }

        let wire = if id.is_empty() {
            command.clone()
        } else {
            format!("{command} {id}")
        };
        pp.send_command(data, conn, &wire).await?;

        self.state = Pop3State::Command;

        // C `data->req.no_body = !pop3_is_multiline(command)`: a single-line
        // command has no body to download.
        if self.req.transfer == Pop3Transfer::Body && !pop3_is_multiline(command.as_bytes()) {
            self.req.transfer = Pop3Transfer::None;
        }
        Ok(())
    }

    /// Choose and begin the authentication path (C
    /// `pop3_perform_authentication`): SASL when offered and preferred, else
    /// APOP, else clear-text `USER`/`PASS`, else fail with a SASL diagnostic.
    async fn perform_authentication(
        &mut self,
        pp: &mut PingPong,
        data: &Easy,
        conn: &mut Connection,
    ) -> Result<()> {
        if !self.sasl.can_authenticate(&self.user) {
            self.state = Pop3State::Stop;
            return Ok(());
        }

        let mut progress = SaslProgress::Idle;
        if self.authtypes & self.preftype & POP3_TYPE_SASL != 0 {
            let (user, passwd, host, port, sasl_ir, allow) = self.sasl_inputs(data, conn);
            let params = SaslParams {
                user: &user,
                passwd: &passwd,
                authzid: "",
                host: &host,
                port,
                service_name: None,
                bearer: None,
                sasl_ir,
                allow_auth_to_other_hosts: allow,
                this_is_a_follow: false,
            };
            progress = self.sasl.start(&mut self.sasl_io, &params, false)?;
            // Flush the AUTH command the SASL engine staged (if any).
            if let Some(cmd) = self.sasl_io.cmd.take() {
                pp.send_command(data, conn, &cmd).await?;
            }
            if progress == SaslProgress::InProgress {
                self.state = Pop3State::Auth;
            }
        }

        if progress == SaslProgress::Idle {
            if self.authtypes & self.preftype & POP3_TYPE_APOP != 0 {
                self.perform_apop(pp, data, conn).await
            } else if self.authtypes & self.preftype & POP3_TYPE_CLEARTEXT != 0 {
                self.perform_user(pp, data, conn).await
            } else {
                self.sasl_is_blocked(data);
                Err(CurlError::LoginDenied)
            }
        } else {
            Ok(())
        }
    }

    // ---- per-state response handlers (C `pop3_state_*_resp`) --------------

    /// C `pop3_state_servergreet_resp`: validate the greeting, capture any APOP
    /// timestamp, then request capabilities.
    async fn servergreet_resp(
        &mut self,
        pp: &mut PingPong,
        code: i32,
        data: &Easy,
        conn: &mut Connection,
    ) -> Result<()> {
        if code != i32::from(b'+') {
            sendf::failf(
                &mut conn.filter_data.error_buffer,
                "Got unexpected pop3-server response",
            );
            return Err(CurlError::WeirdServerReply);
        }
        if self.last_line.len() > 3 {
            if let Some(timestamp) = scan_apop_timestamp(&self.last_line) {
                self.apoptimestamp = Some(timestamp);
                self.authtypes |= POP3_TYPE_APOP;
            }
            self.perform_capa(pp, data, conn).await?;
        }
        Ok(())
    }

    /// C `pop3_state_capa_resp`: accumulate one capability line on a `*`
    /// continuation, or on the terminating line decide between authentication,
    /// `STLS`, or failure.
    async fn capa_resp(
        &mut self,
        pp: &mut PingPong,
        code: i32,
        data: &Easy,
        conn: &mut Connection,
    ) -> Result<()> {
        if code == i32::from(b'*') {
            self.parse_capa_line();
            return Ok(());
        }

        // Terminating line. Clear text is supported when CAPA is unrecognised.
        if code != i32::from(b'+') {
            self.authtypes |= POP3_TYPE_CLEARTEXT;
        }

        let use_ssl = data.set.use_ssl;
        if use_ssl == CURLUSESSL_NONE || Curl_conn_is_ssl(conn, FIRSTSOCKET) {
            self.perform_authentication(pp, data, conn).await
        } else if code == i32::from(b'+') && self.tls_supported {
            self.perform_starttls(pp, data, conn).await
        } else if use_ssl <= CURLUSESSL_TRY {
            self.perform_authentication(pp, data, conn).await
        } else {
            sendf::failf(&mut conn.filter_data.error_buffer, "STLS not supported.");
            Err(CurlError::UseSslFailed)
        }
    }

    /// Parse one `*` CAPA capability line (C `pop3_state_capa_resp`'s `'*'`
    /// branch): detect `STLS`, clear-text `USER`, and the `SASL` mechanism list.
    fn parse_capa_line(&mut self) {
        // Clone the captured line so we may freely mutate `self`'s other fields.
        let line = self.last_line.clone();
        let len = line.len();

        if len >= 4 && line[..4].eq_ignore_ascii_case(b"STLS") {
            self.tls_supported = true;
        } else if len >= 4 && line[..4].eq_ignore_ascii_case(b"USER") {
            self.authtypes |= POP3_TYPE_CLEARTEXT;
        } else if len >= 5 && line[..5].eq_ignore_ascii_case(b"SASL ") {
            self.authtypes |= POP3_TYPE_SASL;
            // Walk the space-separated mechanism list after "SASL ".
            let mut p = 5usize;
            loop {
                while p < len && (is_blank(line[p]) || is_newline(line[p])) {
                    p += 1;
                }
                if p >= len {
                    break;
                }
                let start = p;
                while p < len && !is_blank(line[p]) && !is_newline(line[p]) {
                    p += 1;
                }
                let wordlen = p - start;
                if wordlen == 0 {
                    break;
                }
                let (mechbit, llen) = decode_mech(&line[start..p], wordlen);
                if mechbit != 0 && llen == wordlen {
                    self.sasl.authmechs |= mechbit;
                }
            }
        }
    }

    /// C `pop3_state_starttls_resp`: on `+OK` advance to the TLS handshake; on
    /// failure either fall back to authentication (`CURLUSESSL_TRY`) or fail.
    /// Pipelined data after the `STLS` response is rejected.
    async fn starttls_resp(
        &mut self,
        pp: &mut PingPong,
        code: i32,
        data: &Easy,
        conn: &mut Connection,
    ) -> Result<()> {
        // C: `if(pop3c->pp.overflow) return CURLE_WEIRD_SERVER_REPLY;`. The
        // engine's overflow buffer is private; `moredata()` (no pending send,
        // buffered bytes beyond the final line) is the equivalent public signal
        // that the server pipelined data ahead of the TLS handshake.
        if pp.moredata() {
            return Err(CurlError::WeirdServerReply);
        }

        if code != i32::from(b'+') {
            if data.set.use_ssl != CURLUSESSL_TRY {
                sendf::failf(&mut conn.filter_data.error_buffer, "STARTTLS denied");
                return Err(CurlError::UseSslFailed);
            }
            return self.perform_authentication(pp, data, conn).await;
        }
        self.state = Pop3State::UpgradeTls;
        Ok(())
    }

    /// C `pop3_state_auth_resp`: feed the response code to the SASL engine,
    /// flush any staged continuation/cancel, and either complete, fall back to
    /// APOP/USER (on cancellation), or stay mid-exchange.
    async fn auth_resp(
        &mut self,
        pp: &mut PingPong,
        code: i32,
        data: &Easy,
        conn: &mut Connection,
    ) -> Result<()> {
        // Stage the server challenge for `SaslProto::get_message`.
        self.sasl_io.msg = extract_sasl_message(&self.last_line);

        let (user, passwd, host, port, sasl_ir, allow) = self.sasl_inputs(data, conn);
        let params = SaslParams {
            user: &user,
            passwd: &passwd,
            authzid: "",
            host: &host,
            port,
            service_name: None,
            bearer: None,
            sasl_ir,
            allow_auth_to_other_hosts: allow,
            this_is_a_follow: false,
        };
        let progress = self.sasl.cont(&mut self.sasl_io, &params, code)?;

        // Flush whatever the SASL engine staged this round (continuation or `*`).
        if let Some(cmd) = self.sasl_io.cmd.take() {
            pp.send_command(data, conn, &cmd).await?;
        }

        match progress {
            SaslProgress::Done => {
                self.state = Pop3State::Stop;
                Ok(())
            }
            SaslProgress::Idle => {
                // No mechanism left after cancellation: fall back.
                if self.authtypes & self.preftype & POP3_TYPE_APOP != 0 {
                    self.perform_apop(pp, data, conn).await
                } else if self.authtypes & self.preftype & POP3_TYPE_CLEARTEXT != 0 {
                    self.perform_user(pp, data, conn).await
                } else {
                    sendf::failf(&mut conn.filter_data.error_buffer, "Authentication cancelled");
                    Err(CurlError::LoginDenied)
                }
            }
            SaslProgress::InProgress => Ok(()),
        }
    }

    /// C `pop3_state_apop_resp`: `+OK` ends the connect phase, anything else is
    /// a login failure.
    fn apop_resp(&mut self, code: i32, conn: &mut Connection) -> Result<()> {
        if code != i32::from(b'+') {
            let msg = format!("Authentication failed: {code}");
            sendf::failf(&mut conn.filter_data.error_buffer, &msg);
            Err(CurlError::LoginDenied)
        } else {
            self.state = Pop3State::Stop;
            Ok(())
        }
    }

    /// C `pop3_state_user_resp`: `+OK` sends `PASS`, anything else is access
    /// denied.
    async fn user_resp(
        &mut self,
        pp: &mut PingPong,
        code: i32,
        data: &Easy,
        conn: &mut Connection,
    ) -> Result<()> {
        if code != i32::from(b'+') {
            let msg = format!("Access denied. {}", (code as u8) as char);
            sendf::failf(&mut conn.filter_data.error_buffer, &msg);
            return Err(CurlError::LoginDenied);
        }
        let cmd = format!("PASS {}", self.passwd);
        pp.send_command(data, conn, &cmd).await?;
        self.state = Pop3State::Pass;
        Ok(())
    }

    /// C `pop3_state_pass_resp`: `+OK` ends the connect phase, anything else is
    /// access denied.
    fn pass_resp(&mut self, code: i32, conn: &mut Connection) -> Result<()> {
        if code != i32::from(b'+') {
            let msg = format!("Access denied. {}", (code as u8) as char);
            sendf::failf(&mut conn.filter_data.error_buffer, &msg);
            Err(CurlError::LoginDenied)
        } else {
            self.state = Pop3State::Stop;
            Ok(())
        }
    }

    /// C `pop3_state_command_resp`: a `+OK` opens the body stream (the body
    /// itself is delivered to the client writer via
    /// [`Pop3Protocol::write_resp`] with dot-unstuffing); any other code is a
    /// weird server reply.
    ///
    /// The dot-state seeding (`eob = 2`, `strip = 2`) C performs here is applied
    /// to the handler's write state in [`Pop3Protocol::do_it`] once the download
    /// direction is known. The C overflow-as-body replay (pipelined body bytes
    /// arriving in the same segment as the `+OK`) is handled by the transfer
    /// engine delivering those bytes to `write_resp`; the engine's overflow
    /// buffer is private to the ping-pong layer.
    fn command_resp(&mut self, code: i32, _conn: &mut Connection) -> Result<()> {
        if code != i32::from(b'+') {
            self.state = Pop3State::Stop;
            return Err(CurlError::WeirdServerReply);
        }
        self.state = Pop3State::Stop;
        Ok(())
    }

    /// Perform the post-`STLS` TLS handshake (C `pop3_perform_upgrade_tls`):
    /// insert a `rustls` filter at the top of the socket's filter chain (unless
    /// the connection is already TLS), drive the handshake to completion, then
    /// re-issue `CAPA` over the secured channel.
    async fn perform_upgrade_tls(
        &mut self,
        pp: &mut PingPong,
        data: &Easy,
        conn: &mut Connection,
    ) -> Result<()> {
        if !Curl_conn_is_ssl(conn, FIRSTSOCKET) {
            let host = conn.remote_host.clone();
            let port = conn.remote_port;

            // Translate the handle's full TLS settings (validation on by
            // default) via the shared ping-pong mapping, so `STLS` honours the
            // same handle options as SMTP/IMAP/FTP explicit-TLS upgrades and as
            // an implicit `pop3s://` connection: `--insecure`, `--cacert`,
            // `--pinnedpubkey`, client certificates, cipher and TLS-version
            // selection all take effect (previously only the verify flags and
            // version window were propagated).
            let tls_config = tls_config_from_easy(data);
            // The public-key pin (`CURLOPT_PINNEDPUBLICKEY`) is enforced by the
            // TLS filter via this explicit argument (the pin check runs in
            // `tls::connect`), exactly as SMTP/IMAP/FTP thread it — this is what
            // makes `--pinnedpubkey` take effect on the `STLS` upgrade.
            let pinned = data.set.str(StrId::SslPinnedPublicKey).map(String::from);

            // POP3-over-TLS uses no ALPN. Add the filter at the chain top so it
            // wraps the existing TCP transport (C `Curl_ssl_cfilter_add`).
            let factory = tls_factory(tls_config, host, port, pinned, Vec::new());
            conn.cfilter[FIRSTSOCKET].add_filter(factory());
        }

        // Drive the handshake to completion (the await resolves once connected).
        Curl_conn_connect(conn, FIRSTSOCKET, false).await?;
        self.ssldone = true;

        // Capabilities may differ post-TLS; re-issue CAPA (moves out of
        // UPGRADETLS).
        self.perform_capa(pp, data, conn).await
    }

    /// Dispatch a complete server response to the handler for the current state
    /// (C `pop3_statemachine`'s `switch(pop3c->state)`).
    async fn dispatch(
        &mut self,
        pp: &mut PingPong,
        code: i32,
        data: &Easy,
        conn: &mut Connection,
    ) -> Result<()> {
        match self.state {
            Pop3State::ServerGreet => self.servergreet_resp(pp, code, data, conn).await,
            Pop3State::Capa => self.capa_resp(pp, code, data, conn).await,
            Pop3State::StartTls => self.starttls_resp(pp, code, data, conn).await,
            Pop3State::Auth => self.auth_resp(pp, code, data, conn).await,
            Pop3State::Apop => self.apop_resp(code, conn),
            Pop3State::User => self.user_resp(pp, code, data, conn).await,
            Pop3State::Pass => self.pass_resp(code, conn),
            Pop3State::Command => self.command_resp(code, conn),
            // QUIT response, or any unexpected state, ends the machine.
            Pop3State::Quit
            | Pop3State::Stop
            | Pop3State::UpgradeTls
            | Pop3State::Last => {
                self.state = Pop3State::Stop;
                Ok(())
            }
        }
    }

    /// Drive the command/response state machine to a terminal state (the Rust
    /// fusion of C `pop3_statemachine` and the `*_statemach` outer loops).
    ///
    /// Each round borrows the ping-pong engine out of `self` (via
    /// [`core::mem::take`]) so it can be passed alongside `&mut self` as the
    /// `endofresp` provider — the borrow split that lets the engine and this
    /// protocol object cooperate without aliasing. The loop honours the response
    /// timeout, flushes partial sends, reads one response, dispatches it, and
    /// drains any pipelined (buffered) responses before awaiting the socket
    /// again; it returns when the state reaches [`Pop3State::Stop`]. A closed
    /// connection surfaces as an error from the read.
    async fn drive(&mut self, data: &mut Easy, conn: &mut Connection) -> Result<()> {
        loop {
            // Busy upgrading: all I/O is the TLS handshake, not POP3 (C's
            // `upgrade_tls:` label at the top of the state machine).
            if self.state == Pop3State::UpgradeTls {
                let mut pp = core::mem::take(&mut self.pp);
                let result = self.perform_upgrade_tls(&mut pp, data, conn).await;
                self.pp = pp;
                result?;
                if self.state == Pop3State::UpgradeTls {
                    // The handshake did not complete and did not error — should
                    // not happen with a driven-to-completion connect; treat as a
                    // failed upgrade rather than spin.
                    return Err(CurlError::UseSslFailed);
                }
                continue;
            }

            if self.state == Pop3State::Stop {
                return Ok(());
            }

            let mut pp = core::mem::take(&mut self.pp);

            // Response timeout (C `Curl_pp_statemach`'s `state_timeout` guard).
            if pp.state_timeout(data) <= 0 {
                self.pp = pp;
                sendf::failf(&mut conn.filter_data.error_buffer, "server response timeout");
                return Err(CurlError::OperationTimedout);
            }

            // Flush any partially-sent command before reading.
            if pp.needs_flush() {
                if let Err(e) = pp.flushsend(data, conn).await {
                    self.pp = pp;
                    return Err(e);
                }
            }

            // C `do { readresp; dispatch } while(state != STOP && moredata)`.
            loop {
                let (code, _size) = match pp.readresp(data, conn, FIRSTSOCKET, self).await {
                    Ok(v) => v,
                    Err(e) => {
                        self.pp = pp;
                        return Err(e);
                    }
                };
                if code == 0 {
                    // No complete response yet (would-block); resume next round.
                    break;
                }
                if let Err(e) = self.dispatch(&mut pp, code, data, conn).await {
                    self.pp = pp;
                    return Err(e);
                }
                if self.state == Pop3State::Stop || self.state == Pop3State::UpgradeTls {
                    break;
                }
                if !pp.moredata() {
                    break;
                }
            }

            self.pp = pp;
            // Loop: STOP returns at the top, UPGRADETLS is handled at the top,
            // otherwise the next round awaits the response to the command just
            // sent.
        }
    }
}

// ===========================================================================
// PingPongProtocol — the engine hooks (C `PINGPONG_SETUP` callbacks)
// ===========================================================================

impl PingPongProtocol for Pop3Conn {
    /// Required by the [`PingPongProtocol`] bound that
    /// [`PingPong::readresp`](crate::protocols::pingpong::PingPong::readresp)
    /// places on its `proto` argument, but intentionally a no-op: `readresp`
    /// invokes only [`endofresp`](PingPongProtocol::endofresp), never this hook.
    ///
    /// The POP3 drive loop lives in [`Pop3Conn::drive`], which owns the borrow
    /// split between the ping-pong engine and this protocol object — the engine
    /// cannot both be the `statemach` receiver and be reachable as `self.pp`
    /// inside this method, so POP3 does not route through `PingPong::statemach`.
    fn statemachine<'a>(
        &'a mut self,
        _data: &'a mut Easy,
        _conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { Ok(()) })
    }

    /// Classify a response line and capture it for the dispatcher (C
    /// `pop3_endofresp`).
    ///
    /// Returns `Some(code)` for a complete response — `'-'` for `-ERR`, `'+'`
    /// for `+OK` (and the CAPA terminating dot line), `'*'` for a continuation
    /// (and each non-terminating CAPA line) — or `None` when the line is not yet
    /// a complete response. `line` includes its trailing CRLF. The final line is
    /// stashed in [`last_line`](Pop3Conn::last_line) because the engine's
    /// receive buffer is private to it.
    fn endofresp(
        &mut self,
        _data: &mut Easy,
        _conn: &mut Connection,
        line: &[u8],
    ) -> Option<i32> {
        let len = line.len();

        // Error response (exact, case-sensitive — C `memcmp`).
        if len >= 4 && &line[..4] == b"-ERR" {
            self.last_line = line.to_vec();
            return Some(i32::from(b'-'));
        }

        // CAPA responses: every line is "complete"; a lone dot terminates.
        if self.state == Pop3State::Capa {
            let terminator = (len == 3 && line[0] == b'.' && line[1] == b'\r')
                || (len == 2 && line[0] == b'.' && line[1] == b'\n');
            self.last_line = line.to_vec();
            return Some(i32::from(if terminator { b'+' } else { b'*' }));
        }

        // Success response (exact, case-sensitive — C `memcmp`).
        if len >= 3 && &line[..3] == b"+OK" {
            self.last_line = line.to_vec();
            return Some(i32::from(b'+'));
        }

        // Continuation response.
        if len >= 1 && line[0] == b'+' {
            self.last_line = line.to_vec();
            return Some(i32::from(b'*'));
        }

        None
    }
}

// ===========================================================================
// Protocol — the scheme handler lifecycle (C `Curl_handler_pop3{,s}` vtable)
// ===========================================================================

impl Protocol for Pop3Protocol {
    fn scheme(&self) -> &'static Scheme {
        self.scheme
    }

    /// Establish the POP3 session (C `pop3_connect` + the `connecting` loop):
    /// initialise per-connection state, parse URL credentials and `;options`,
    /// then drive the greeting → `CAPA` → optional `STLS` → authentication
    /// sequence to completion before storing the state on the connection.
    fn connect<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut pop3c = Box::new(Pop3Conn::new());

            // Initialise the ping-pong engine (C `Curl_pp_init`).
            pop3c.pp.init(conn.created);

            // Credentials and options come from the URL (C `pop3_connect` uses
            // `conn->user`/`conn->passwd`/`conn->options`).
            let (user, passwd, options, _id) = parse_url_info(data);
            pop3c.user = user;
            pop3c.passwd = passwd;

            // Default preferred auth, then SASL init (C order).
            pop3c.preftype = POP3_TYPE_ANY;
            // `def_mechs`/`flags` are constant, so a throwaway shim gives the
            // same initialisation as borrowing `pop3c.sasl_io`.
            pop3c.sasl.init(&Pop3SaslIo::default(), 0);

            if let Some(opts) = options {
                pop3c.parse_url_options(opts.as_bytes())?;
            }

            // Wait for the server greeting, then drive to STOP.
            pop3c.state = Pop3State::ServerGreet;
            pop3c.drive(data, conn).await?;

            // Hand the established state to the connection for reuse.
            conn.set_proto_state(pop3c);
            Ok(())
        })
    }

    /// Issue the request and describe the transfer (C `pop3_do` /
    /// `pop3_perform_command` + the `doing` loop). Parses the message id from
    /// the URL, sends the command, drives to completion, and returns a
    /// [`ProtocolTransfer`] describing whether a body download follows.
    fn do_it<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<ProtocolTransfer>> {
        Box::pin(async move {
            // The message id is the URL path (C `pop3_parse_url_path`). A custom
            // request (`CURLOPT_CUSTOMREQUEST`) is not reachable through the
            // dependency whitelist, so it is left unset (standard RETR/LIST and
            // `--list-only` still work).
            let (_user, _passwd, _options, id) = parse_url_info(data);

            // Borrow the per-connection state out so its methods can take `conn`.
            let mut pop3c = match conn.take_proto_state() {
                Some(state) => state
                    .downcast::<Pop3Conn>()
                    .map_err(|_| CurlError::FailedInit)?,
                None => return Err(CurlError::FailedInit),
            };

            pop3c.req.id = id;
            pop3c.req.custom = None;
            pop3c.req.transfer = Pop3Transfer::Body;

            // Send the command (borrow the engine out, as the drive loop does).
            {
                let mut pp = core::mem::take(&mut pop3c.pp);
                let result = pop3c.perform_command(&mut pp, data, conn).await;
                pop3c.pp = pp;
                if let Err(e) = result {
                    conn.set_proto_state(pop3c);
                    return Err(e);
                }
            }

            // Drive the command response to STOP.
            if let Err(e) = pop3c.drive(data, conn).await {
                conn.set_proto_state(pop3c);
                return Err(e);
            }

            let transfer = pop3c.req.transfer;

            // Seed the dot-unstuffing state for a body download (the `eob = 2`,
            // `strip = 2` seeding C does in `pop3_state_command_resp`).
            if transfer == Pop3Transfer::Body {
                let mut ws = self.write_state.lock().expect("pop3 write_state poisoned");
                ws.dot = DotState::for_download();
                ws.pending_body.clear();
                ws.recv_done = false;
            }

            // Return the per-connection state for reuse.
            conn.set_proto_state(pop3c);

            let direction = if transfer == Pop3Transfer::Body {
                TransferDirection::Download
            } else {
                TransferDirection::None
            };
            Ok(ProtocolTransfer::new(direction))
        })
    }

    /// Finalise the request (C `pop3_done`): clear per-request state and
    /// propagate the transfer status.
    fn done<'a>(
        &'a self,
        _data: &'a mut Easy,
        conn: &'a mut Connection,
        status: Result<()>,
        _premature: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if let Some(pop3c) = conn.proto_state_mut::<Pop3Conn>() {
                // C clears `pop3->id`/`pop3->custom` and resets transfer to BODY.
                pop3c.req = Pop3::default();
            }
            status
        })
    }

    /// Tear down the session (C `pop3_disconnect`): when the connection is alive
    /// and idle, politely `QUIT`; then drop the per-connection state (freeing
    /// the APOP timestamp and the ping-pong buffers).
    ///
    /// The engine carries this on the [`Connection`] as a boxed-async hook, but
    /// POP3 needs the connection handle to send `QUIT`, so the work is performed
    /// here where `conn` is available rather than in the handle-less
    /// `disconnect_hook`.
    fn disconnect<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
        dead: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let Some(state) = conn.take_proto_state() else {
                return Ok(());
            };
            let Ok(mut pop3c) = state.downcast::<Pop3Conn>() else {
                return Ok(());
            };

            // C: only QUIT a live connection with no half-sent command. The
            // presence of stored state stands in for `conn->bits.protoconnstart`.
            if !dead && !pop3c.pp.needs_flush() {
                let mut pp = core::mem::take(&mut pop3c.pp);
                let sent = pop3c.perform_quit(&mut pp, data, conn).await;
                pop3c.pp = pp;
                if sent.is_ok() {
                    // Drive the QUIT response, ignoring errors (C ignores them).
                    let _ = pop3c.drive(data, conn).await;
                }
            }

            // Reset the ping-pong engine (C `Curl_pp_disconnect`); `pop3c` and
            // its `apoptimestamp` are freed as it drops here.
            pop3c.pp.disconnect();
            Ok(())
        })
    }

    /// Intercept response body bytes for dot-unstuffing (C `pop3_write` via
    /// `write_resp`). Un-stuffs doubled leading dots and detects the
    /// `CRLF.CRLF` end-of-body marker, buffering the cleaned body for delivery
    /// through [`take_pending_body`](Pop3Protocol::take_pending_body). Always
    /// reports the bytes as fully handled.
    fn write_resp(&self, _data: &mut Easy, buf: &[u8], _is_eos: bool) -> Result<bool> {
        let mut ws = self.write_state.lock().expect("pop3 write_state poisoned");
        if ws.recv_done {
            // End-of-body already seen; trailing bytes are not part of the body.
            return Ok(true);
        }
        let Pop3WriteState {
            dot,
            pending_body,
            recv_done,
        } = &mut *ws;
        if dot.process(buf, pending_body) {
            *recv_done = true;
        }
        Ok(true)
    }
}

// ===========================================================================
// Unit tests — parity-critical pure logic (the wire-facing pieces that can be
// validated without a live server: response classification, CAPA parsing, the
// APOP digest, dot-unstuffing, the SASL vtable, and URL-option parsing).
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{SchemeDescriptor, TRNSPRT_TCP};

    /// A throwaway `Connection` for the `endofresp` tests (which ignore it).
    fn test_conn() -> Connection {
        let scheme = SchemeDescriptor::new("pop3", 110, 0, 0);
        Connection::new("pop3.example.com:110", TRNSPRT_TCP, scheme)
    }

    // ---- SASL vtable (the C `saslpop3` constants and staging) ------------

    #[test]
    fn saslproto_constants_match_c_oracle() {
        let io = Pop3SaslIo::default();
        // C-oracle parity: service "pop" (not "pop3"), maxirlen 255 - 8.
        assert_eq!(io.service(), "pop");
        assert_eq!(io.maxirlen(), 247);
        assert_eq!(io.cont_code(), i32::from(b'+'));
        assert_eq!(io.final_code(), i32::from(b'+'));
        assert_eq!(io.def_mechs(), SASL_AUTH_DEFAULT);
        assert_eq!(io.flags(), SASL_FLAG_BASE64);
    }

    #[test]
    fn saslproto_stages_auth_commands() {
        let mut io = Pop3SaslIo::default();

        io.send_auth("PLAIN", None).expect("send_auth");
        assert_eq!(io.cmd.as_deref(), Some("AUTH PLAIN"));

        io.send_auth("PLAIN", Some(b"dGVzdA==")).expect("send_auth ir");
        assert_eq!(io.cmd.as_deref(), Some("AUTH PLAIN dGVzdA=="));

        io.cont_auth("PLAIN", b"Zm9v").expect("cont_auth");
        assert_eq!(io.cmd.as_deref(), Some("Zm9v"));

        io.cancel_auth("PLAIN").expect("cancel_auth");
        assert_eq!(io.cmd.as_deref(), Some("*"));
    }

    #[test]
    fn saslproto_get_message_takes_payload() {
        let mut io = Pop3SaslIo {
            msg: b"challenge".to_vec(),
            ..Default::default()
        };
        assert_eq!(io.get_message().expect("get_message"), b"challenge");
        // Taken: a second call yields nothing.
        assert!(io.get_message().expect("get_message").is_empty());
    }

    // ---- endofresp (C `pop3_endofresp`) ----------------------------------

    #[test]
    fn endofresp_classifies_status_lines() {
        let mut data = Easy::new();
        let mut conn = test_conn();
        let mut c = Pop3Conn::new();
        c.state = Pop3State::ServerGreet;

        assert_eq!(
            c.endofresp(&mut data, &mut conn, b"+OK ready\r\n"),
            Some(i32::from(b'+'))
        );
        assert_eq!(c.last_line, b"+OK ready\r\n");

        assert_eq!(
            c.endofresp(&mut data, &mut conn, b"-ERR nope\r\n"),
            Some(i32::from(b'-'))
        );

        // A SASL continuation ("+ <base64>") is an untagged continuation.
        assert_eq!(
            c.endofresp(&mut data, &mut conn, b"+ Y2hhbGxlbmdl\r\n"),
            Some(i32::from(b'*'))
        );

        // Not a recognised complete response.
        assert_eq!(c.endofresp(&mut data, &mut conn, b"garbage\r\n"), None);
    }

    #[test]
    fn endofresp_capa_continuation_and_terminator() {
        let mut data = Easy::new();
        let mut conn = test_conn();
        let mut c = Pop3Conn::new();
        c.state = Pop3State::Capa;

        // Each capability line is an untagged continuation.
        assert_eq!(
            c.endofresp(&mut data, &mut conn, b"TOP\r\n"),
            Some(i32::from(b'*'))
        );
        // A lone dot terminates (treated as success). CRLF form.
        assert_eq!(
            c.endofresp(&mut data, &mut conn, b".\r\n"),
            Some(i32::from(b'+'))
        );
        // Bare-LF dot form also terminates.
        assert_eq!(
            c.endofresp(&mut data, &mut conn, b".\n"),
            Some(i32::from(b'+'))
        );
        // An error during CAPA is still an error response.
        assert_eq!(
            c.endofresp(&mut data, &mut conn, b"-ERR no capa\r\n"),
            Some(i32::from(b'-'))
        );
    }

    // ---- greeting APOP-timestamp scan (C `pop3_state_servergreet_resp`) --

    #[test]
    fn scan_apop_timestamp_requires_bracketed_at() {
        assert_eq!(
            scan_apop_timestamp(b"+OK POP3 <1896.697@dbc.us> ready").as_deref(),
            Some(&b"<1896.697@dbc.us>"[..])
        );
        // No '@' inside the brackets => not an RFC-822 message id => ignored.
        assert!(scan_apop_timestamp(b"+OK <no-at-here> ready").is_none());
        // No timestamp at all.
        assert!(scan_apop_timestamp(b"+OK plain greeting").is_none());
    }

    // ---- CAPA line parsing (C `pop3_state_capa_resp` '*' branch) ---------

    #[test]
    fn parse_capa_detects_stls() {
        let mut c = Pop3Conn::new();
        c.state = Pop3State::Capa;
        c.last_line = b"STLS\r\n".to_vec();
        c.parse_capa_line();
        assert!(c.tls_supported);
    }

    #[test]
    fn parse_capa_detects_user_cleartext() {
        let mut c = Pop3Conn::new();
        c.last_line = b"USER\r\n".to_vec();
        c.parse_capa_line();
        assert_eq!(c.authtypes & POP3_TYPE_CLEARTEXT, POP3_TYPE_CLEARTEXT);
    }

    #[test]
    fn parse_capa_detects_sasl_mechs() {
        let mut c = Pop3Conn::new();
        c.last_line = b"SASL PLAIN LOGIN\r\n".to_vec();
        c.parse_capa_line();
        assert_eq!(c.authtypes & POP3_TYPE_SASL, POP3_TYPE_SASL);
        // At least one offered mechanism was recognised and recorded.
        assert_ne!(c.sasl.authmechs, 0);
    }

    // ---- SASL message extraction (C `pop3_get_message`) ------------------

    #[test]
    fn extract_sasl_message_trims_prefix_and_whitespace() {
        assert_eq!(extract_sasl_message(b"+ dGVzdA==\r\n"), b"dGVzdA==");
        assert_eq!(extract_sasl_message(b"+   spaced  \r\n"), b"spaced");
        // Two bytes or fewer => empty (C "junk input => zero length output").
        assert!(extract_sasl_message(b"ab").is_empty());
        // "+ " with only a newline payload => empty.
        assert!(extract_sasl_message(b"+\r\n").is_empty());
    }

    // ---- APOP digest (RFC-1939 §7 worked example) ------------------------

    #[test]
    fn apop_digest_matches_rfc1939_example() {
        // RFC-1939: timestamp "<1896.697170952@dbc.mtview.ca.us>" + password
        // "tanstaaf" => MD5 "c4c9334bac560ecc979e58001b3e22fb".
        let timestamp = b"<1896.697170952@dbc.mtview.ca.us>";
        let password = b"tanstaaf";
        let mut buf = timestamp.to_vec();
        buf.extend_from_slice(password);
        let digest = md5::md5it(&buf);
        assert_eq!(hex_lower(&digest), "c4c9334bac560ecc979e58001b3e22fb");
    }

    #[test]
    fn hex_lower_is_lowercase_and_fixed_width() {
        assert_eq!(hex_lower(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        assert_eq!(hex_lower(&[]), "");
    }

    // ---- multi-line command classification (C `pop3_is_multiline`) -------

    #[test]
    fn is_multiline_matches_command_table() {
        assert!(pop3_is_multiline(b"RETR"));
        assert!(pop3_is_multiline(b"LIST"));
        assert!(pop3_is_multiline(b"TOP"));
        assert!(!pop3_is_multiline(b"USER"));
        assert!(!pop3_is_multiline(b"QUIT"));
        assert!(!pop3_is_multiline(b"DELE"));
        // "LIST <id>" uses the with-args column (false for LIST).
        assert!(!pop3_is_multiline(b"LIST 1"));
        // "RETR <id>" stays multi-line (true with args).
        assert!(pop3_is_multiline(b"RETR 1"));
        // Unknown commands default to multi-line.
        assert!(pop3_is_multiline(b"WHATEVER"));
    }

    // ---- dot-unstuffing / EOB detection (C `pop3_write`) -----------------

    #[test]
    fn dotstate_emits_body_and_detects_eob() {
        let mut dot = DotState::default();
        let mut out = Vec::new();
        // "hello" + CRLF + terminating "." line.
        let done = dot.process(b"hello\r\n.\r\n", &mut out);
        assert!(done, "end-of-body marker consumed");
        // The CRLF before the dot is part of the message (RFC-1939 §3).
        assert_eq!(out, b"hello\r\n");
    }

    #[test]
    fn dotstate_unstuffs_leading_dot() {
        // Mid-stream right after a CRLF (eob pre-counted to 2, no strip): the
        // server doubled the leading dot of a line (".data" -> "..data").
        let mut dot = DotState { eob: 2, strip: 0 };
        let mut out = Vec::new();
        let done = dot.process(b"..data\r\n.\r\n", &mut out);
        assert!(done);
        // Un-stuffed back to a single leading dot.
        assert_eq!(out, b"\r\n.data\r\n");
    }

    #[test]
    fn dotstate_strips_opening_crlf_for_download() {
        // `for_download` seeds eob = strip = 2 so the "+OK" line's own CRLF
        // (the first two EOB bytes) is not delivered as body.
        let mut dot = DotState::for_download();
        let mut out = Vec::new();
        // The body proper is "X"; then the terminating dot line.
        let done = dot.process(b"X\r\n.\r\n", &mut out);
        assert!(done);
        // The leading CRLF that opened the stream is stripped; the body "X" and
        // its trailing CRLF (part of the message) are delivered.
        assert_eq!(out, b"X\r\n");
    }

    // ---- percent-decoding (C `Curl_urldecode` stand-in) ------------------

    #[test]
    fn percent_decode_handles_escapes_and_invalids() {
        assert_eq!(percent_decode(b"plain"), "plain");
        assert_eq!(percent_decode(b"a%20b"), "a b");
        assert_eq!(percent_decode(b"%2e"), ".");
        // Invalid escape is left verbatim.
        assert_eq!(percent_decode(b"bad%zz"), "bad%zz");
    }

    // ---- URL ;options parsing (C `pop3_parse_url_options`) ---------------

    #[test]
    fn parse_url_options_empty_yields_any_after_init() {
        let mut c = Pop3Conn::new();
        // Mirror connect(): SASL init sets prefmech to the default set.
        c.sasl.init(&Pop3SaslIo::default(), 0);
        c.parse_url_options(b"").expect("empty options");
        assert_eq!(c.preftype, POP3_TYPE_ANY);
    }

    #[test]
    fn parse_url_options_plus_apop_selects_apop() {
        let mut c = Pop3Conn::new();
        c.parse_url_options(b"AUTH=+APOP").expect("+APOP option");
        assert_eq!(c.preftype, POP3_TYPE_APOP);
        assert_eq!(c.sasl.prefmech, SASL_AUTH_NONE);
    }

    #[test]
    fn parse_url_options_unknown_key_is_malformat() {
        let mut c = Pop3Conn::new();
        assert!(matches!(
            c.parse_url_options(b"FOO=bar"),
            Err(CurlError::UrlMalformat)
        ));
    }

    // ---- handler/scheme wiring -------------------------------------------

    #[test]
    fn handlers_bind_expected_schemes() {
        assert_eq!(pop3_handler().scheme().name, "pop3");
        assert_eq!(pop3_handler().scheme().default_port, 110);
        assert_eq!(pop3s_handler().scheme().name, "pop3s");
        assert_eq!(pop3s_handler().scheme().default_port, 995);
        // pop3s is implicit TLS; pop3 is not.
        assert!(pop3s_handler().scheme().is_ssl());
        assert!(!pop3_handler().scheme().is_ssl());
    }

    #[test]
    fn write_resp_unstuffs_into_pending_body() {
        let handler = Pop3Protocol::new(&SCHEME_POP3);
        {
            // Seed for a download, as do_it would.
            let mut ws = handler.write_state.lock().expect("lock");
            ws.dot = DotState::for_download();
        }
        let mut data = Easy::new();
        let handled = handler
            .write_resp(&mut data, b"line\r\n.\r\n", false)
            .expect("write_resp");
        assert!(handled, "POP3 fully handles body bytes");
        assert!(handler.body_complete(), "EOB detected");
        assert_eq!(handler.take_pending_body(), b"line\r\n");
        // Drained.
        assert!(handler.take_pending_body().is_empty());
    }
}
