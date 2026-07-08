//! POP3 and POP3S protocol handler (← `lib/pop3.c`, `lib/pop3.h`).
//!
//! This is the idiomatic-Rust port of curl 8.19.0-DEV's Post Office Protocol
//! version 3 client, targeting byte-for-byte functional parity. POP3 is a
//! line-based *ping-pong* protocol (single command, single — possibly
//! multi-line — response), so it is driven by the shared engine in
//! [`crate::protocols::pingpong`], exactly as FTP/IMAP/SMTP are. It supports
//! three authentication paths, selected precisely as curl does:
//!
//! 1. **SASL** (`AUTH <mech>` with optional initial response / continuations),
//!    shared with the other mail protocols via [`crate::auth::sasl`];
//! 2. **APOP** (`APOP <user> <md5(timestamp+password)>`), using the pure-Rust
//!    `md-5` crate — the MD5 primitive is never reimplemented here; and
//! 3. **USER/PASS** clear-text (`USER <name>` then `PASS <secret>`).
//!
//! It further reproduces the STLS upgrade (`STLS`, RFC 2595) to negotiate TLS
//! over a clear-text connection, the implicit-TLS `pop3s` scheme, capability
//! discovery (`CAPA`, RFC 2449), and the message-retrieval commands
//! (`RETR`/`LIST`/`UIDL`/`TOP`/`DELE`/`STAT`/…) with the RFC 1939 multi-line
//! body framing: a body is terminated by a line containing only `.`, and any
//! data line whose first byte is `.` is *dot-stuffed* with a leading `.` that
//! must be stripped on receive.
//!
//! # Wire and diagnostic parity
//!
//! * The [`Pop3State`] variants carry the **verbatim** curl state names
//!   (`POP3_STOP`, `POP3_SERVERGREET`, …) so `--trace`/`--verbose` output is
//!   identical (see [`Pop3State::name`]).
//! * Response classification in [`Pop3Conn::classify_response`] mirrors
//!   `pop3_endofresp`: `+OK` → `'+'`, `-ERR` → `'-'`, an untagged/continuation
//!   line → `'*'`, and — while awaiting `CAPA` output — a lone `.` terminator →
//!   `'+'`. These `char`-valued codes match curl's `int *resp` convention.
//! * The end-of-body scanner in [`Pop3Conn::write_body`] reproduces
//!   `pop3_write` byte-for-byte, including the five-byte `\r\n.\r\n` marker
//!   match spread across chunk boundaries and the dot-unstuffing of `..`.
//!
//! # Structure (and its relationship to the C `struct`s)
//!
//! curl keeps two structs: `struct POP3` (per-transfer, on the easy handle) and
//! `struct pop3_conn` (per-connection, holding the `pingpong` engine and the
//! `SASL` engine). This module preserves that split as [`Pop3`] and
//! [`Pop3Conn`]. Because the shared [`PingPong`] engine's methods
//! ([`PingPong::readresp`], [`PingPong::statemach`]) take the ping-pong buffer
//! and the protocol object as *separate* borrows — exactly as curl passes `pp`
//! and `conn`/`data` as separate arguments — the [`PingPong`] instance is held
//! by the connection layer and threaded into [`Pop3Conn`]'s methods rather than
//! stored as a field of [`Pop3Conn`]. Likewise, the `SASL` engine
//! ([`crate::auth::sasl::Sasl`]) requires the SASL protocol callbacks to be a
//! borrow distinct from the engine itself; the callbacks are therefore
//! implemented by the small [`Pop3SaslAdapter`] view over the borrowed
//! [`PingPong`], and [`Pop3Conn`] owns the [`Sasl`] engine as its `sasl` field.
//! This is the same decomposition the ping-pong contract documents and that
//! `pingpong.rs`'s own tests use, and it is what lets the whole module compile
//! in safe Rust with **zero `unsafe`** while driving both engines coherently.

use std::fmt::Write as _;
use std::mem;
use std::time::Instant;

use md5::{Digest as _, Md5};

use crate::auth::sasl::{
    decode_mech, Sasl, SaslCredentials, SaslProgress, SaslProto, SASL_AUTH_DEFAULT, SASL_AUTH_NONE,
    SASL_FLAG_BASE64,
};
use crate::auth::CURLAUTH_NONE;
use crate::conn::{Connection, FIRSTSOCKET};
use crate::error::{CurlCode, Error, Result};
use crate::protocols::pingpong::{PingPong, PingPongProtocol, PpTransfer};
use crate::protocols::{ProtoFuture, Protocol, TransferCtx};

// ===========================================================================
// Authentication-type bitmask (← the `POP3_TYPE_*` macros in `lib/pop3.c`).
//
// These describe which *kinds* of authentication the connection may use. They
// are ANDed together from two sources: the server's advertised capabilities
// (`Pop3Conn::authtypes`, populated while parsing the `CAPA` response) and the
// user's preference (`Pop3Conn::preftype`, derived from the URL `;AUTH=` option
// in `Pop3Conn::parse_url_options`). The intersection selects the auth path in
// `Pop3Conn::perform_authentication`.
// ===========================================================================

/// No authentication type (← `POP3_TYPE_NONE`).
pub const POP3_TYPE_NONE: u8 = 0;
/// Clear-text `USER`/`PASS` authentication is available (← `POP3_TYPE_CLEARTEXT`).
pub const POP3_TYPE_CLEARTEXT: u8 = 1 << 0;
/// `APOP` challenge-response authentication is available (← `POP3_TYPE_APOP`).
pub const POP3_TYPE_APOP: u8 = 1 << 1;
/// SASL (`AUTH <mech>`) authentication is available (← `POP3_TYPE_SASL`).
pub const POP3_TYPE_SASL: u8 = 1 << 2;
/// Any of the three authentication types (← `POP3_TYPE_ANY`); the default
/// preference before any URL `;AUTH=` option narrows it.
pub const POP3_TYPE_ANY: u8 = POP3_TYPE_CLEARTEXT | POP3_TYPE_APOP | POP3_TYPE_SASL;

// ===========================================================================
// End-of-body marker (← the `POP3_EOB` / `POP3_EOB_LEN` macros in `lib/pop3.c`).
// ===========================================================================

/// The RFC 1939 end-of-body byte sequence, `CRLF . CRLF` (← `POP3_EOB`).
///
/// A multi-line POP3 body is terminated by a line containing only `.`; on the
/// wire that is the five bytes `\r\n.\r\n`. The leading `\r\n` belongs to the
/// message per RFC 1939 §3 and is delivered; the trailing `.\r\n` is the
/// terminator and is not.
const POP3_EOB: &[u8] = b"\r\n.\r\n";
/// Length in bytes of [`POP3_EOB`] (← `POP3_EOB_LEN`).
const POP3_EOB_LEN: usize = 5;

// ===========================================================================
// SASL protocol descriptor constants (← the `saslpop3` `struct SASLproto`
// initializer in `lib/pop3.c`). These are surfaced through the [`SaslProto`]
// implementation on [`Pop3SaslAdapter`].
// ===========================================================================

/// The SASL service name for POP3 (← `saslpop3.service` = `"pop"`). Used to
/// build the GSSAPI/`DIGEST-MD5` service principal and the OAUTHBEARER string.
const POP3_SASL_SERVICE: &str = "pop";
/// Maximum SASL initial-response line length (← `saslpop3.maxirlen` = `255 - 8`):
/// the POP3 command-line limit of 255 minus `strlen("AUTH ")`, one space and the
/// trailing CRLF. Beyond this the initial response is sent in a continuation.
const POP3_SASL_MAX_IR_LEN: usize = 255 - 8;
/// The status code received when a SASL continuation is expected
/// (← `saslpop3.contcode` = `'*'`).
const POP3_SASL_CONT_CODE: i32 = b'*' as i32;
/// The status code received on SASL authentication success
/// (← `saslpop3.finalcode` = `'+'`).
const POP3_SASL_FINAL_CODE: i32 = b'+' as i32;

// ===========================================================================
// Pop3UseSsl — the requested TLS level (← curl's `curl_usessl`, `data->set.use_ssl`).
//
// curl models the `--ssl`/`--ssl-reqd` family with the `curl_usessl` enum. POP3
// consults it in three places: to decide whether to attempt `STLS`, whether a
// failed `STLS` is fatal, and whether to fall back to clear-text. There is no
// crate-wide model for this yet, so the enum is reproduced locally with the
// same integer identities and the same ordering the C comparisons rely on
// (`use_ssl <= CURLUSESSL_TRY`).
// ===========================================================================

/// The requested transport-security level for a POP3 transfer (← `curl_usessl`).
///
/// The discriminants match curl's `CURLUSESSL_*` integer values so that the
/// ordering comparisons (`<= CURLUSESSL_TRY`) behave identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Pop3UseSsl {
    /// Do not attempt TLS (← `CURLUSESSL_NONE`). The default.
    #[default]
    None = 0,
    /// Try TLS, but continue in clear text if it is unavailable
    /// (← `CURLUSESSL_TRY`).
    Try = 1,
    /// Require TLS for the control channel (← `CURLUSESSL_CONTROL`).
    Control = 2,
    /// Require TLS for the whole connection (← `CURLUSESSL_ALL`).
    All = 3,
}

// ===========================================================================
// Pop3State — the connect/transfer state machine (← `pop3state`, `lib/pop3.h`).
// ===========================================================================

/// The POP3 protocol state (← the `pop3state` enum in `lib/pop3.h`).
///
/// The variant *names* and their *order* are preserved verbatim from curl so
/// that the diagnostic strings emitted by [`Pop3Conn::set_state`] match curl's
/// `--trace` output exactly. [`Pop3State::Last`] is curl's `POP3_LAST` sentinel
/// (the count of real states); it is never a live state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pop3State {
    /// No connect/transfer in progress (← `POP3_STOP`). Also the terminal state.
    Stop,
    /// Awaiting the server's opening greeting (← `POP3_SERVERGREET`).
    ServerGreet,
    /// Awaiting the `CAPA` capability listing (← `POP3_CAPA`).
    Capa,
    /// Awaiting the `STLS` (STARTTLS) response (← `POP3_STARTTLS`).
    StartTls,
    /// Performing the TLS handshake after a successful `STLS` (← `POP3_UPGRADETLS`).
    UpgradeTls,
    /// Awaiting a SASL `AUTH` exchange response (← `POP3_AUTH`).
    Auth,
    /// Awaiting the `APOP` response (← `POP3_APOP`).
    Apop,
    /// Awaiting the `USER` response (← `POP3_USER`).
    User,
    /// Awaiting the `PASS` response (← `POP3_PASS`).
    Pass,
    /// Awaiting a request command's response (← `POP3_COMMAND`).
    Command,
    /// Awaiting the `QUIT` response (← `POP3_QUIT`).
    Quit,
    /// Sentinel: the number of real states (← `POP3_LAST`). Never a live state.
    Last,
}

impl Pop3State {
    /// The diagnostic name of the state, matching curl's `names[]` array in
    /// `pop3_state` (`lib/pop3.c`) verbatim so `--trace` output is identical.
    ///
    /// curl's array has no entry for the `POP3_LAST` sentinel (it is only a
    /// count); `"LAST"` is returned defensively for it but is never emitted for
    /// a live transition.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Pop3State::Stop => "STOP",
            Pop3State::ServerGreet => "SERVERGREET",
            Pop3State::Capa => "CAPA",
            Pop3State::StartTls => "STARTTLS",
            Pop3State::UpgradeTls => "UPGRADETLS",
            Pop3State::Auth => "AUTH",
            Pop3State::Apop => "APOP",
            Pop3State::User => "USER",
            Pop3State::Pass => "PASS",
            Pop3State::Command => "COMMAND",
            Pop3State::Quit => "QUIT",
            Pop3State::Last => "LAST",
        }
    }
}

// ===========================================================================
// POP3 command table (← `struct pop3_cmd` + `pop3cmds[]`, `lib/pop3.c`).
// ===========================================================================

/// One row of the POP3 command table (← `struct pop3_cmd`).
///
/// `name` is the command keyword; `multiline` is `true` when the command's
/// response is a `.`-terminated multi-line body when issued with no argument;
/// `multiline_with_args` is `true` when it is multi-line only when issued *with*
/// an argument. (curl stores an explicit `nlen`; here it is `name.len()`.)
struct Pop3Cmd {
    /// The command keyword (compared case-insensitively).
    name: &'static str,
    /// Response is multi-line when the command has no argument.
    multiline: bool,
    /// Response is multi-line when the command has an argument.
    multiline_with_args: bool,
}

/// The POP3 command table (← `pop3cmds[]`), kept in the same order as curl.
///
/// It is consulted by [`pop3_is_multiline`] to decide whether a command yields
/// a `.`-terminated multi-line body (and therefore whether the request has a
/// body to download).
static POP3CMDS: &[Pop3Cmd] = &[
    Pop3Cmd {
        name: "APOP",
        multiline: false,
        multiline_with_args: false,
    },
    Pop3Cmd {
        name: "AUTH",
        multiline: false,
        multiline_with_args: false,
    },
    Pop3Cmd {
        name: "CAPA",
        multiline: true,
        multiline_with_args: true,
    },
    Pop3Cmd {
        name: "DELE",
        multiline: false,
        multiline_with_args: false,
    },
    Pop3Cmd {
        name: "LIST",
        multiline: true,
        multiline_with_args: false,
    },
    Pop3Cmd {
        name: "MSG",
        multiline: true,
        multiline_with_args: true,
    },
    Pop3Cmd {
        name: "NOOP",
        multiline: false,
        multiline_with_args: false,
    },
    Pop3Cmd {
        name: "PASS",
        multiline: false,
        multiline_with_args: false,
    },
    Pop3Cmd {
        name: "QUIT",
        multiline: false,
        multiline_with_args: false,
    },
    Pop3Cmd {
        name: "RETR",
        multiline: true,
        multiline_with_args: true,
    },
    Pop3Cmd {
        name: "RSET",
        multiline: false,
        multiline_with_args: false,
    },
    Pop3Cmd {
        name: "STAT",
        multiline: false,
        multiline_with_args: false,
    },
    Pop3Cmd {
        name: "STLS",
        multiline: false,
        multiline_with_args: false,
    },
    Pop3Cmd {
        name: "TOP",
        multiline: true,
        multiline_with_args: true,
    },
    Pop3Cmd {
        name: "UIDL",
        multiline: true,
        multiline_with_args: false,
    },
    Pop3Cmd {
        name: "USER",
        multiline: false,
        multiline_with_args: false,
    },
    Pop3Cmd {
        name: "UTF8",
        multiline: false,
        multiline_with_args: false,
    },
    Pop3Cmd {
        name: "XTND",
        multiline: true,
        multiline_with_args: true,
    },
];

/// Decide whether the response to `cmdline` is a `.`-terminated multi-line body
/// (← `pop3_is_multiline`, `lib/pop3.c`).
///
/// The first table entry whose keyword is a case-insensitive prefix of
/// `cmdline` and is immediately followed by end-of-string or a space decides
/// the answer: [`Pop3Cmd::multiline`] for the no-argument form,
/// [`Pop3Cmd::multiline_with_args`] for the argument form. An unrecognized
/// command is assumed multi-line, for backward compatibility with earlier curl
/// versions that could only do multi-line responses.
#[must_use]
fn pop3_is_multiline(cmdline: &str) -> bool {
    let bytes = cmdline.as_bytes();
    for cmd in POP3CMDS {
        let nlen = cmd.name.len();
        if bytes.len() >= nlen && bytes[..nlen].eq_ignore_ascii_case(cmd.name.as_bytes()) {
            match bytes.get(nlen) {
                // End of the command: the no-argument multi-line flag applies.
                None => return cmd.multiline,
                // A space introduces an argument: the with-args flag applies.
                Some(b' ') => return cmd.multiline_with_args,
                // A longer keyword (e.g. "RETRX"): not a match, keep scanning.
                Some(_) => {}
            }
        }
    }
    // Unknown command → assume multi-line (curl's backward-compatible default).
    true
}

// ===========================================================================
// Pop3 — the per-transfer state (← `struct POP3`, `lib/pop3.c`).
// ===========================================================================

/// Per-transfer POP3 state (← `struct POP3`).
///
/// curl allocates one of these per easy handle for the duration of a single
/// request. It records the transfer mode and the two request parameters parsed
/// from the URL / `CURLOPT_CUSTOMREQUEST`.
#[derive(Debug, Clone)]
pub struct Pop3 {
    /// How much of the response to stream to the caller (← `POP3.transfer`).
    /// Defaults to [`PpTransfer::Body`]; downgraded to [`PpTransfer::Info`] for
    /// message-specific `LIST` and for no-body commands.
    pub transfer: PpTransfer,
    /// The message identifier from the URL path (← `POP3.id`), URL-decoded. Empty
    /// when the URL has no message number (a mailbox-level command such as
    /// `LIST`).
    pub id: String,
    /// The custom request from `CURLOPT_CUSTOMREQUEST` (← `POP3.custom`),
    /// URL-decoded; `None` when unset.
    pub custom: Option<String>,
}

impl Default for Pop3 {
    fn default() -> Self {
        // curl zero-initializes `struct POP3`; `transfer` is set to
        // `PPTRANSFER_BODY` (its zero value) — reproduced explicitly here.
        Pop3 {
            transfer: PpTransfer::Body,
            id: String::new(),
            custom: None,
        }
    }
}

// ===========================================================================
// Pop3Request — the per-transfer configuration bundle read from `data->set` /
// `data->state` (analogous to `MqttRequest` in `mqtt.rs`).
//
// curl's `pop3_*` functions read these directly from `struct Curl_easy`.
// Grouping them lets the (future) transfer-layer wiring populate one struct and
// call [`Pop3Conn`]'s connect/do helpers, while documenting each field's C
// provenance. It borrows its string inputs for the lifetime of the call.
// ===========================================================================

/// The per-transfer configuration a POP3 connect/do needs from the easy handle.
#[derive(Debug, Clone, Copy)]
pub struct Pop3Request<'a> {
    /// The URL path *including* its leading `/` (← `data->state.up.path`); the
    /// message id is everything after the `/`, URL-decoded (see
    /// [`Pop3Conn::parse_url_path`]).
    pub path: &'a str,
    /// The custom request string (← `data->set.str[STRING_CUSTOMREQUEST]`), if
    /// any; URL-decoded by [`Pop3Conn::parse_custom_request`].
    pub custom_request: Option<&'a str>,
    /// The URL login options string (← `conn->options`), e.g. `AUTH=+APOP`;
    /// parsed by [`Pop3Conn::parse_url_options`].
    pub options: Option<&'a str>,
    /// The requested TLS level (← `data->set.use_ssl`).
    pub use_ssl: Pop3UseSsl,
    /// Whether `-l`/`CURLOPT_DIRLISTONLY` forces a `LIST` (← `data->set.list_only`).
    pub list_only: bool,
    /// Whether an initial SASL response is permitted (← `data->set.sasl_ir`).
    pub sasl_ir: bool,
    /// The application's `CURLAUTH_*` selection (← `data->set.httpauth`), used
    /// to seed the SASL preferred-mechanism set.
    pub httpauth: u32,
}

impl Default for Pop3Request<'_> {
    fn default() -> Self {
        Pop3Request {
            path: "/",
            custom_request: None,
            options: None,
            use_ssl: Pop3UseSsl::None,
            list_only: false,
            sasl_ir: false,
            httpauth: CURLAUTH_NONE,
        }
    }
}

// ===========================================================================
// Pop3Conn — the per-connection state (← `struct pop3_conn`, `lib/pop3.c`).
// ===========================================================================

/// Per-connection POP3 state (← `struct pop3_conn`).
///
/// This owns the [`Sasl`] engine and all the connect-time bookkeeping the C
/// struct holds. It does **not** own the [`PingPong`] engine: the ping-pong
/// contract (see [`PingPongProtocol`]) requires the buffer and the protocol
/// object to be *separate* borrows, so the [`PingPong`] is threaded into the
/// methods here by the connection layer, exactly as curl passes `pp` and `conn`
/// separately. The per-transfer parameters ([`pop3`](Self::pop3),
/// [`use_ssl`](Self::use_ssl), …) are co-located here — curl keeps them on the
/// easy handle — so the fixed-signature [`PingPongProtocol::statemachine`] can
/// reach them without extra out-of-band arguments.
///
/// Does not derive [`Debug`]: it owns a [`PingPong`] (whose I/O buffers are not
/// `Debug`), exactly like its sibling engine
/// [`crate::protocols::smtp::SmtpConn`].
pub struct Pop3Conn {
    /// The shared SASL engine (← `pop3_conn.sasl`). [`Pop3Conn`] drives it via
    /// [`Sasl::sasl_start`] / [`Sasl::sasl_continue`], supplying the POP3
    /// protocol callbacks through [`Pop3SaslAdapter`].
    pub sasl: Sasl,
    /// The current protocol state (← `pop3_conn.state`).
    pub state: Pop3State,
    /// The server's APOP timestamp `<...>` captured from the greeting
    /// (← `pop3_conn.apoptimestamp`), or `None` if the server offered no
    /// RFC-822-conformant timestamp.
    pub apoptimestamp: Option<String>,
    /// Bitmask of server-advertised authentication types (← `pop3_conn.authtypes`),
    /// built from [`POP3_TYPE_CLEARTEXT`] / [`POP3_TYPE_APOP`] / [`POP3_TYPE_SASL`].
    pub authtypes: u8,
    /// The user's preferred authentication type (← `pop3_conn.preftype`);
    /// [`POP3_TYPE_ANY`] unless narrowed by a URL `;AUTH=` option.
    pub preftype: u8,
    /// End-of-body match progress for the `\r\n.\r\n` scanner (← `pop3_conn.eob`).
    pub eob: usize,
    /// Number of leading bytes still to strip from the body — the dot-stuffing /
    /// initial-CRLF strip counter (← `pop3_conn.strip`).
    pub strip: usize,
    /// Whether the TLS handshake after `STLS` has completed (← `pop3_conn.ssldone`).
    pub ssldone: bool,
    /// Whether the server advertised the `STLS` capability (← `pop3_conn.tls_supported`).
    pub tls_supported: bool,

    // --- Per-transfer parameters (curl keeps these on `struct Curl_easy`;
    //     co-located here for the trait-driven state machine). ---
    /// The active transfer's [`Pop3`] request state.
    pub pop3: Pop3,
    /// The requested TLS level for this transfer (← `data->set.use_ssl`).
    pub use_ssl: Pop3UseSsl,
    /// Whether a bare `LIST` is forced (← `data->set.list_only`).
    pub list_only: bool,
    /// Whether the last issued command has no response body (← `data->req.no_body`);
    /// set by [`Pop3Conn::perform_command`] from [`pop3_is_multiline`].
    pub no_body: bool,
    /// Whether an initial SASL response is permitted (← `data->set.sasl_ir`).
    pub sasl_ir: bool,

    /// The owned ping-pong command/response buffer for this connection
    /// (← the pingpong embedded in curl's `struct pop3_conn`). Mirrors
    /// [`crate::protocols::smtp::SmtpConn`]'s owned `pp`: the lifecycle wrappers
    /// ([`perform`](Self::perform) / [`doing`](Self::doing)) swap it out via
    /// [`mem::replace`] so the state machine can borrow the engine and the
    /// buffer disjointly, then swap it back. The lower-level
    /// [`perform_command`](Self::perform_command) / [`run_statemachine`] still
    /// accept an external `pp` for unit tests that drive a single step.
    pub pp: PingPong,
}

impl Pop3Conn {
    /// Create the per-connection state at the start of a connect
    /// (← the initialization block of `pop3_connect`).
    ///
    /// Mirrors curl: the preferred auth type starts as [`POP3_TYPE_ANY`], the
    /// SASL engine is initialized with the POP3 default mechanisms and the
    /// application's `httpauth` selection, and the state starts at
    /// [`Pop3State::Stop`] (the caller moves it to [`Pop3State::ServerGreet`]
    /// once the ping-pong layer is initialized).
    #[must_use]
    pub fn new(req: &Pop3Request) -> Self {
        Pop3Conn {
            sasl: Sasl::init(SASL_AUTH_DEFAULT, req.httpauth),
            state: Pop3State::Stop,
            apoptimestamp: None,
            authtypes: POP3_TYPE_NONE,
            preftype: POP3_TYPE_ANY,
            eob: 0,
            strip: 0,
            ssldone: false,
            tls_supported: false,
            pop3: Pop3::default(),
            use_ssl: req.use_ssl,
            list_only: req.list_only,
            no_body: false,
            sasl_ir: req.sasl_ir,
            pp: PingPong::new(),
        }
    }

    /// The single, canonical state-transition point (← `pop3_state`, the "ONLY
    /// way to change POP3 state").
    ///
    /// Emits curl's `POP3 state change from %s to %s` diagnostic via
    /// [`tracing`] (so `--trace`/`--verbose` output matches) whenever the state
    /// actually changes, then records the new state.
    pub fn set_state(&mut self, newstate: Pop3State) {
        if self.state != newstate {
            tracing::trace!(
                target: "curl::pop3",
                "POP3 state change from {} to {}",
                self.state.name(),
                newstate.name()
            );
        }
        self.state = newstate;
    }
}

// ===========================================================================
// Response classification and SASL message extraction.
// ===========================================================================

/// Extract the human-readable message from a POP3 response line
/// (← `pop3_get_message`, `lib/pop3.c`).
///
/// curl skips the two-byte status prefix (`+OK`/`-ERR` are followed by the
/// message after position 2), trims leading blanks, then trims trailing blanks
/// and newlines, yielding the SASL challenge / diagnostic text. A line of two
/// bytes or fewer yields an empty message (curl: "junk input => zero length
/// output"). `line` is the final response line, including its trailing CRLF —
/// i.e. [`PingPong::response_line`].
#[must_use]
fn pop3_get_message(line: &[u8]) -> Vec<u8> {
    if line.len() <= 2 {
        return Vec::new();
    }
    // Skip the 2-byte status prefix (← `message += 2; len -= 2`).
    let after = &line[2..];
    // Trim leading blanks (space/tab) (← the `for(; ISBLANK(*message); …)` loop).
    let start = after
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(after.len());
    let trimmed = &after[start..];
    // Trim trailing blanks and newlines (← the `while(len--)` scan).
    let mut end = trimmed.len();
    while end > 0 {
        let c = trimmed[end - 1];
        if c == b' ' || c == b'\t' || c == b'\r' || c == b'\n' {
            end -= 1;
        } else {
            break;
        }
    }
    trimmed[..end].to_vec()
}

impl Pop3Conn {
    /// Classify a response line and, if it completes a response, set `code`
    /// (← `pop3_endofresp`, `lib/pop3.c`).
    ///
    /// Returns `true` when `line` ends a (possibly multi-line) response. The
    /// `code` follows curl's `char`-valued convention: `'+'` for `+OK` (and the
    /// `CAPA` terminator), `'-'` for `-ERR`, and `'*'` for an untagged
    /// continuation line (including every intermediate `CAPA` capability line
    /// and a SASL `+ <base64>` challenge). While in [`Pop3State::Capa`] every
    /// line completes a response (returning `true`) so the state machine can
    /// process the capability listing one line at a time.
    #[must_use]
    pub fn classify_response(&self, line: &[u8], code: &mut i32) -> bool {
        // Error response: `-ERR ...`.
        if line.len() >= 4 && &line[..4] == b"-ERR" {
            *code = i32::from(b'-');
            return true;
        }

        // While reading `CAPA` output, a line containing only `.` (per RFC 2449)
        // terminates the listing; anything else is an untagged continuation.
        if self.state == Pop3State::Capa {
            if (line.len() == 3 && line[0] == b'.' && line[1] == b'\r')
                || (line.len() == 2 && line[0] == b'.' && line[1] == b'\n')
            {
                *code = i32::from(b'+');
            } else {
                *code = i32::from(b'*');
            }
            return true;
        }

        // Success response: `+OK ...`.
        if line.len() >= 3 && &line[..3] == b"+OK" {
            *code = i32::from(b'+');
            return true;
        }

        // Continuation response: any line beginning with `+`.
        if !line.is_empty() && line[0] == b'+' {
            *code = i32::from(b'*');
            return true;
        }

        // Nothing for us — the engine keeps scanning.
        false
    }
}

// ===========================================================================
// Pop3SaslAdapter — the SASL protocol-callback view (← the `saslpop3`
// `struct SASLproto` function pointers, `lib/pop3.c`).
//
// The [`Sasl`] engine invokes these callbacks with a borrow (`&mut self`) that
// must be *distinct* from the engine itself. Bundling only the borrowed
// [`PingPong`] here lets [`Pop3Conn`] call `self.sasl.sasl_start(&mut adapter,
// …)` with the engine (`self.sasl`, a field) and the callbacks (`adapter`, over
// the `pp` parameter) as disjoint borrows — the same split curl expresses by
// passing `data`/`conn` (which reach `pp`) separately from `&pop3c->sasl`.
// ===========================================================================

/// The SASL protocol-callback adapter for POP3 (← `saslpop3`).
///
/// Holds the borrowed ping-pong buffer so the callbacks can send commands and
/// read the last response while the [`Sasl`] engine drives the exchange.
struct Pop3SaslAdapter<'a> {
    /// The connection's ping-pong buffer, borrowed for the duration of a single
    /// SASL step.
    pp: &'a mut PingPong,
}

impl SaslProto for Pop3SaslAdapter<'_> {
    fn service(&self) -> &str {
        POP3_SASL_SERVICE
    }

    fn max_ir_len(&self) -> usize {
        POP3_SASL_MAX_IR_LEN
    }

    fn cont_code(&self) -> i32 {
        POP3_SASL_CONT_CODE
    }

    fn final_code(&self) -> i32 {
        POP3_SASL_FINAL_CODE
    }

    fn def_mechs(&self) -> u32 {
        SASL_AUTH_DEFAULT
    }

    fn flags(&self) -> u16 {
        SASL_FLAG_BASE64
    }

    /// Send the `AUTH` command, with an optional base64 initial response
    /// (← `pop3_perform_auth`). With an initial response: `AUTH <mech> <ir>`;
    /// without: `AUTH <mech>`.
    fn send_auth(&mut self, mech: &str, initial_resp: Option<&[u8]>) -> Result<()> {
        match initial_resp {
            Some(ir) => {
                // The initial response is base64 (SASL_FLAG_BASE64), hence ASCII.
                let ir = String::from_utf8_lossy(ir);
                self.pp.sendf(format_args!("AUTH {mech} {ir}"))
            }
            None => self.pp.sendf(format_args!("AUTH {mech}")),
        }
    }

    /// Send a SASL continuation response verbatim (← `pop3_continue_auth`, which
    /// sends `Curl_pp_sendf(pp, "%s", resp)`).
    fn cont_auth(&mut self, _mech: &str, resp: &[u8]) -> Result<()> {
        let resp = String::from_utf8_lossy(resp);
        self.pp.sendf(format_args!("{resp}"))
    }

    /// Cancel the in-progress SASL exchange by sending a lone `*`
    /// (← `pop3_cancel_auth`).
    fn cancel_auth(&mut self, _mech: &str) -> Result<()> {
        self.pp.sendf(format_args!("*"))
    }

    /// Return the decoded challenge from the last server response
    /// (← `pop3_get_message`).
    fn get_message(&mut self) -> Result<Vec<u8>> {
        Ok(pop3_get_message(self.pp.response_line()))
    }
}

// ===========================================================================
// PingPongProtocol — the engine callbacks (← the `statemachine` / `endofresp`
// function pointers installed by `PINGPONG_SETUP` in `pop3_connect`).
// ===========================================================================

impl PingPongProtocol for Pop3Conn {
    /// Advance the POP3 state machine one step (← `pop3_statemachine`).
    fn statemachine<'a>(
        &'a mut self,
        pp: &'a mut PingPong,
        conn: &'a mut Connection,
    ) -> ProtoFuture<'a, ()> {
        Box::pin(async move { self.run_statemachine(pp, conn).await })
    }

    /// Decide whether `line` completes a response and parse its status code
    /// (← `pop3_endofresp`). Delegates to [`Pop3Conn::classify_response`].
    fn endofresp(&mut self, line: &[u8], code: &mut i32) -> bool {
        self.classify_response(line, code)
    }
}

impl Pop3Conn {
    /// The POP3 state-machine step, driven by the ping-pong engine
    /// (← `pop3_statemachine`, `lib/pop3.c`).
    ///
    /// Because [`Pop3Conn`] does not own the [`PingPong`] buffer, the call
    /// `pp.readresp(self, conn, …)` borrows the buffer (`pp`), the protocol
    /// object (`self`) and the connection (`conn`) as three disjoint mutable
    /// references — the ping-pong contract that this decomposition exists to
    /// satisfy. The `'outer` label reproduces curl's `upgrade_tls:` goto: after
    /// a successful `STLS` the machine re-enters at the TLS-handshake check.
    async fn run_statemachine(&mut self, pp: &mut PingPong, conn: &mut Connection) -> Result<()> {
        'outer: loop {
            // upgrade_tls: — while upgrading, all I/O is TLS, not POP3.
            if self.state == Pop3State::UpgradeTls {
                self.perform_upgrade_tls(pp, conn).await?;
                // Still handshaking → yield until the socket is ready again.
                if self.state == Pop3State::UpgradeTls {
                    return Ok(());
                }
            }

            // Flush any data that still needs to be sent (← `if(pp->sendleft)`).
            if pp.needs_flush() {
                return pp.flushsend(conn, Instant::now()).await;
            }

            // Read and dispatch responses while the server has more buffered
            // (← the `do { … } while(!result && state != STOP && moredata)` loop).
            loop {
                let mut code: i32 = 0;
                let mut nread: usize = 0;
                pp.readresp(&mut *self, conn, FIRSTSOCKET, &mut code, &mut nread)
                    .await?;

                // No complete response yet (← `if(!pop3code) break;`).
                if code == 0 {
                    return Ok(());
                }

                match self.state {
                    Pop3State::ServerGreet => self.state_servergreet_resp(pp, code)?,
                    Pop3State::Capa => self.state_capa_resp(pp, conn, code)?,
                    Pop3State::StartTls => {
                        self.state_starttls_resp(pp, conn, code)?;
                        // During UPGRADETLS, re-enter at the TLS-handshake check
                        // before doing any more POP3 I/O (← `goto upgrade_tls`).
                        if self.state == Pop3State::UpgradeTls {
                            continue 'outer;
                        }
                    }
                    Pop3State::Auth => self.state_auth_resp(pp, conn, code)?,
                    Pop3State::Apop => self.state_apop_resp(code)?,
                    Pop3State::User => self.state_user_resp(pp, conn, code)?,
                    Pop3State::Pass => self.state_pass_resp(code)?,
                    Pop3State::Command => self.state_command_resp(code)?,
                    Pop3State::Quit => self.set_state(Pop3State::Stop),
                    // Internal error / unexpected state (← the `default:` arm).
                    _ => self.set_state(Pop3State::Stop),
                }

                // Loop only while there is more buffered data and we are not done.
                if self.state == Pop3State::Stop || !pp.moredata() {
                    return Ok(());
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Public DO/DONE lifecycle wrappers driven by [`Pop3Handler`] over the
    // owned [`pp`](Self::pp) — the borrow-safe equivalent of curl passing `pp`
    // and `conn`/`data` as separate arguments. Each wrapper swaps `pp` out of
    // `self` (via `mem::replace`) so the state machine can borrow the engine
    // and the buffer disjointly, then swaps it back (mirrors
    // [`crate::protocols::smtp::SmtpConn`]).
    // -----------------------------------------------------------------------

    /// Begin the DO phase (← `pop3_perform` inside `pop3_do`): issue the first
    /// command ([`perform_command`](Self::perform_command) — `RETR`/`LIST`/`TOP`
    /// or a custom command) and pump the ping-pong state machine once. Returns
    /// `true` once the DO phase has reached [`Pop3State::Stop`] (the `+OK`
    /// status line has been consumed and the body, if any, is left for the
    /// [`write_resp`](Protocol::write_resp)→[`write_body`](Self::write_body)
    /// path); otherwise the transfer layer continues via [`doing`](Self::doing).
    ///
    /// # Errors
    /// Any protocol or I/O error surfaced while issuing the command or pumping
    /// the state machine.
    pub async fn perform(&mut self, conn: &mut Connection) -> Result<bool> {
        // Swap the buffer out so `perform_command`/`run_statemachine` can borrow
        // `self` and `pp` disjointly (← curl's separate `pp`/`conn` arguments).
        let mut pp = mem::replace(&mut self.pp, PingPong::new());
        let result = match self.perform_command(&mut pp) {
            Ok(()) => self.run_statemachine(&mut pp, conn).await,
            Err(e) => Err(e),
        };
        self.pp = pp;
        result?;
        Ok(self.state == Pop3State::Stop)
    }

    /// Continue a non-blocking DO phase (← `pop3_doing` → `pop3_multi_statemach`):
    /// pump the state machine one step and report whether it reached
    /// [`Pop3State::Stop`].
    ///
    /// # Errors
    /// Any error surfaced while pumping the state machine.
    pub async fn doing(&mut self, conn: &mut Connection) -> Result<bool> {
        let mut pp = mem::replace(&mut self.pp, PingPong::new());
        let result = self.run_statemachine(&mut pp, conn).await;
        self.pp = pp;
        result?;
        Ok(self.state == Pop3State::Stop)
    }

    /// Complete a single DO (← `pop3_done`): reset the transfer mode to
    /// [`PpTransfer::Body`] for the next request, and on a bad `status` mark the
    /// connection for closure and propagate the error. `premature` is accepted
    /// for signature parity (`(void)premature` in curl).
    ///
    /// # Errors
    /// The propagated bad `status`.
    pub async fn done(
        &mut self,
        conn: &mut Connection,
        status: Result<()>,
        premature: bool,
    ) -> Result<()> {
        // `(void)premature` in curl — accepted for signature parity.
        let _ = premature;
        // Reset the transfer mode for the next request (← `pop3->transfer =
        // PPTRANSFER_BODY`).
        self.pop3.transfer = PpTransfer::Body;
        match status {
            Err(e) => {
                // Marked for closure on failure (← `connclose(conn, ...)`).
                conn.bits.close = true;
                Err(e)
            }
            Ok(()) => Ok(()),
        }
    }
}

// ===========================================================================
// URL / option parsing helpers.
// ===========================================================================

/// Decode a single hex digit, or `None` if `b` is not `[0-9A-Fa-f]`.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// URL-decode `input` rejecting control bytes (← `Curl_urldecode(..., REJECT_CTRL)`,
/// `lib/escape.c`), which POP3 uses for both the message id and the custom
/// request.
///
/// Reproduces curl's byte loop: `%XX` is decoded only when two hex digits
/// follow the `%` (otherwise the `%` is literal); any decoded byte below `0x20`
/// (a control character, which includes a decoded NUL) is rejected with
/// [`Error::url`] (curl's `CURLE_URL_MALFORMAT`). Because `escape.c` is not a
/// dependency of this module, the loop is reimplemented here rather than
/// imported (the same approach `gopher.rs` takes).
///
/// The decoded bytes are returned as a [`String`]. All accepted bytes are
/// `>= 0x20`; the (rare, non-standard) case of a decoded byte `>= 0x80` that is
/// not valid UTF-8 is rendered losslessly for ASCII and via
/// [`String::from_utf8_lossy`] otherwise — a faithful choice given that the
/// ping-pong command layer is text-based and POP3 message ids are ASCII.
fn urldecode_reject_ctrl(input: &[u8]) -> Result<String> {
    // `length == 0` in curl means "use strlen": stop at the first literal NUL.
    let end = input.iter().position(|&b| b == 0).unwrap_or(input.len());
    let s = &input[..end];

    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let mut i = 0usize;
    while i < s.len() {
        let decoded = if s[i] == b'%' && (s.len() - i) > 2 {
            match (hex_val(s[i + 1]), hex_val(s[i + 2])) {
                (Some(hi), Some(lo)) => {
                    i += 3;
                    (hi << 4) | lo
                }
                // A `%` not followed by two hex digits is a literal `%`.
                _ => {
                    i += 1;
                    b'%'
                }
            }
        } else {
            let b = s[i];
            i += 1;
            b
        };

        // REJECT_CTRL: reject any decoded control byte (< 0x20); this subsumes a
        // decoded NUL (← `(ctrl == REJECT_CTRL) && (in < 0x20)`).
        if decoded < 0x20 {
            return Err(Error::url("POP3 URL contains a rejected control byte"));
        }
        out.push(decoded);
    }

    Ok(String::from_utf8_lossy(&out).into_owned())
}

impl Pop3Conn {
    /// Build the SASL credential set from the connection (← the several
    /// `conn->user` / `conn->passwd` / `conn->sasl_authzid` / `data->set` reads
    /// that `Curl_sasl_start` / `Curl_sasl_continue` perform via the easy handle).
    fn build_credentials(&self, conn: &Connection) -> SaslCredentials {
        SaslCredentials {
            user: conn.user.clone().unwrap_or_default(),
            passwd: conn.passwd.clone().unwrap_or_default(),
            authzid: conn.sasl_authzid.clone(),
            bearer: conn.oauth_bearer.clone(),
            // POP3 supplies no service-name override; the SASL layer falls back
            // to `SaslProto::service` ("pop").
            service_name: None,
            host: conn.host.name.clone(),
            port: i64::from(conn.remote_port),
            sasl_ir: self.sasl_ir,
        }
    }

    /// Parse the URL login options string (← `pop3_parse_url_options`).
    ///
    /// Only `AUTH=<mech>` is recognized; anything else is
    /// [`Error::url`] (`CURLE_URL_MALFORMAT`). The special `AUTH=+APOP` value
    /// forces [`POP3_TYPE_APOP`] (its unrecognized-mechanism error is caught and
    /// mapped, exactly as curl does). Finally the SASL preferred-mechanism set
    /// is projected onto [`Self::preftype`]: none → [`POP3_TYPE_NONE`], the
    /// default set → [`POP3_TYPE_ANY`], any explicit set → [`POP3_TYPE_SASL`].
    pub fn parse_url_options(&mut self, options: Option<&str>) -> Result<()> {
        let bytes = options.unwrap_or("").as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            let key_start = i;
            while i < bytes.len() && bytes[i] != b'=' {
                i += 1;
            }
            // The value begins just after the `=` (← `value = ptr + 1`).
            let value_start = (i + 1).min(bytes.len());
            while i < bytes.len() && bytes[i] != b';' {
                i += 1;
            }
            let value_end = i;
            let key = &bytes[key_start..];
            let value = if value_start <= value_end {
                &bytes[value_start..value_end]
            } else {
                &[][..]
            };

            if key.len() >= 5 && key[..5].eq_ignore_ascii_case(b"AUTH=") {
                let value_str = std::str::from_utf8(value)
                    .map_err(|_| Error::url("invalid POP3 AUTH option"))?;
                match self.sasl.set_url_auth_option(value_str) {
                    Ok(()) => {}
                    Err(e) => {
                        // `+APOP` is not a SASL mechanism; curl special-cases it.
                        if value.eq_ignore_ascii_case(b"+APOP") {
                            self.preftype = POP3_TYPE_APOP;
                            // `set_url_auth_option` already reset the preferred
                            // mechanism set to none via its one-shot latch.
                        } else {
                            return Err(e);
                        }
                    }
                }
            } else {
                return Err(Error::url("malformed POP3 URL option"));
            }

            if i < bytes.len() && bytes[i] == b';' {
                i += 1;
            }
        }

        // Project the SASL preference onto the POP3 preferred auth type, unless
        // `+APOP` already forced it (← the trailing `switch` in
        // `pop3_parse_url_options`).
        if self.preftype != POP3_TYPE_APOP {
            self.preftype = match self.sasl.prefmech() {
                SASL_AUTH_NONE => POP3_TYPE_NONE,
                SASL_AUTH_DEFAULT => POP3_TYPE_ANY,
                _ => POP3_TYPE_SASL,
            };
        }

        Ok(())
    }

    /// Parse the message id from the URL path (← `pop3_parse_url_path`).
    ///
    /// The id is the path with its single leading `/` removed, URL-decoded with
    /// [`urldecode_reject_ctrl`]. An empty id denotes a mailbox-level command.
    pub fn parse_url_path(&mut self, path: &str) -> Result<()> {
        // Skip the leading path separator (← `&data->state.up.path[1]`).
        let raw = path.strip_prefix('/').unwrap_or(path);
        self.pop3.id = urldecode_reject_ctrl(raw.as_bytes())?;
        Ok(())
    }

    /// Parse the custom request (← `pop3_parse_custom_request`), URL-decoding it
    /// with [`urldecode_reject_ctrl`] when present.
    pub fn parse_custom_request(&mut self, custom: Option<&str>) -> Result<()> {
        if let Some(c) = custom {
            self.pop3.custom = Some(urldecode_reject_ctrl(c.as_bytes())?);
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Command builders (← the `pop3_perform_*` functions). Each queues a single
    // command on the ping-pong buffer and advances the state.
    // -----------------------------------------------------------------------

    /// Send `CAPA` and enter [`Pop3State::Capa`] (← `pop3_perform_capa`).
    ///
    /// Clears the SASL advertised-mechanism set and the STLS capability first,
    /// so a re-issue after `STLS` starts from a clean slate (curl also clears
    /// `sasl.authused`; there is no public setter for it, and it is overwritten
    /// by [`Sasl::sasl_start`] when a mechanism is chosen, so POP3 wire behavior
    /// is unaffected).
    fn perform_capa(&mut self, pp: &mut PingPong) -> Result<()> {
        self.sasl.set_authmechs(SASL_AUTH_NONE);
        self.tls_supported = false;
        pp.sendf(format_args!("CAPA"))?;
        self.set_state(Pop3State::Capa);
        Ok(())
    }

    /// Send `STLS` and enter [`Pop3State::StartTls`] (← `pop3_perform_starttls`).
    fn perform_starttls(&mut self, pp: &mut PingPong) -> Result<()> {
        pp.sendf(format_args!("STLS"))?;
        self.set_state(Pop3State::StartTls);
        Ok(())
    }

    /// Drive the post-`STLS` TLS handshake, then re-run `CAPA`
    /// (← `pop3_perform_upgrade_tls`).
    ///
    /// The TLS connection filter is inserted into the connection's filter chain
    /// by the connection layer (curl's `Curl_ssl_cfilter_add`); here the
    /// handshake is progressed via [`Connection::connect`] and, once it
    /// completes, [`Self::perform_capa`] is issued — which moves the state out of
    /// [`Pop3State::UpgradeTls`]. Unlike curl (whose non-TLS build returns
    /// `CURLE_NOT_BUILT_IN`), the `rustls` backend is always present, so there
    /// is no not-built-in path.
    async fn perform_upgrade_tls(
        &mut self,
        pp: &mut PingPong,
        conn: &mut Connection,
    ) -> Result<()> {
        let ssldone = conn.connect(FIRSTSOCKET, false).await?;
        if ssldone {
            self.ssldone = true;
            // Re-run CAPA over the now-encrypted channel.
            self.perform_capa(pp)?;
        }
        Ok(())
    }

    /// Send `USER <name>` and enter [`Pop3State::User`] (← `pop3_perform_user`).
    ///
    /// With no username the connect phase ends without authenticating (curl
    /// moves to `POP3_STOP`).
    fn perform_user(&mut self, pp: &mut PingPong, conn: &Connection) -> Result<()> {
        if conn.user.is_none() {
            self.set_state(Pop3State::Stop);
            return Ok(());
        }
        let user = conn.user.as_deref().unwrap_or("");
        pp.sendf(format_args!("USER {user}"))?;
        self.set_state(Pop3State::User);
        Ok(())
    }

    /// Send `APOP <user> <digest>` and enter [`Pop3State::Apop`]
    /// (← `pop3_perform_apop`).
    ///
    /// The digest is the lowercase hex MD5 of the server's APOP timestamp
    /// concatenated with the password (RFC 1939 §7). MD5 comes from the
    /// pure-Rust `md-5` crate — it is never reimplemented here. With no username
    /// the connect phase ends (curl moves to `POP3_STOP`).
    fn perform_apop(&mut self, pp: &mut PingPong, conn: &Connection) -> Result<()> {
        if conn.user.is_none() {
            self.set_state(Pop3State::Stop);
            return Ok(());
        }

        let timestamp = self.apoptimestamp.as_deref().unwrap_or("");
        let passwd = conn.passwd.as_deref().unwrap_or("");
        let secret = apop_secret(timestamp, passwd);

        let user = conn.user.as_deref().unwrap_or("");
        pp.sendf(format_args!("APOP {user} {secret}"))?;
        self.set_state(Pop3State::Apop);
        Ok(())
    }

    /// Choose and begin the authentication path (← `pop3_perform_authentication`).
    ///
    /// The path is `authtypes & preftype`, in curl's exact priority order:
    /// SASL (via [`Sasl::sasl_start`]) first, then APOP, then clear-text
    /// `USER`/`PASS`; if none is possible the SASL "blocked" error is returned.
    /// With insufficient credentials the connect phase ends (curl moves to
    /// `POP3_STOP`).
    fn perform_authentication(&mut self, pp: &mut PingPong, conn: &Connection) -> Result<()> {
        let creds = self.build_credentials(conn);
        if !self.sasl.can_authenticate(&creds) {
            self.set_state(Pop3State::Stop);
            return Ok(());
        }

        let mut progress = SaslProgress::Idle;
        if self.authtypes & self.preftype & POP3_TYPE_SASL != 0 {
            // `self.sasl` (a field) and the adapter over `pp` (a parameter) are
            // disjoint borrows, so the engine can drive its POP3 callbacks.
            let mut adapter = Pop3SaslAdapter { pp: &mut *pp };
            progress = self.sasl.sasl_start(&mut adapter, &creds, false)?;
            if progress == SaslProgress::InProgress {
                self.set_state(Pop3State::Auth);
            }
        }

        if progress == SaslProgress::Idle {
            if self.authtypes & self.preftype & POP3_TYPE_APOP != 0 {
                self.perform_apop(pp, conn)?;
            } else if self.authtypes & self.preftype & POP3_TYPE_CLEARTEXT != 0 {
                self.perform_user(pp, conn)?;
            } else {
                return Err(self.sasl.is_blocked(&creds));
            }
        }

        Ok(())
    }

    /// Send `QUIT` and enter [`Pop3State::Quit`] (← `pop3_perform_quit`).
    ///
    /// Public because the disconnect path (curl's `Curl_protocol_pop3.disconnect`
    /// = `pop3_disconnect`) drives it from the connection layer once the
    /// ping-pong buffer is threaded through [`TransferCtx`].
    pub fn perform_quit(&mut self, pp: &mut PingPong) -> Result<()> {
        pp.sendf(format_args!("QUIT"))?;
        self.set_state(Pop3State::Quit);
        Ok(())
    }
}

// ===========================================================================
// Small character-class helpers (← curl's `ISBLANK` / `ISNEWLINE` macros and
// the `%c` status-code formatting in `failf`).
// ===========================================================================

/// `true` for a POP3 in-line whitespace byte (← `ISBLANK`): space or TAB.
#[inline]
fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// `true` for a POP3 line-ending byte (← `ISNEWLINE`): CR or LF.
#[inline]
fn is_newline(b: u8) -> bool {
    b == b'\r' || b == b'\n'
}

/// Render a status-code byte as a `char` for diagnostics (← the `%c` in curl's
/// `failf(data, "Access denied. %c", pop3code)`). The code is always one of
/// `'+'`, `'-'` or `'*'`; the `'?'` fallback is unreachable in practice.
fn code_char(code: i32) -> char {
    u8::try_from(code).map_or('?', char::from)
}

/// Compute the APOP shared-secret digest (← the MD5 block in `pop3_perform_apop`).
///
/// The secret is the lowercase hex encoding of `MD5(timestamp || passwd)`, where
/// `timestamp` is the server's greeting `<...>` (brackets included) and `passwd`
/// is the account password (RFC 1939 §7). The MD5 primitive is the pure-Rust
/// `md-5` crate — never reimplemented here. Extracted as a free function so the
/// digest can be validated directly against the RFC 1939 test vector.
fn apop_secret(timestamp: &str, passwd: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(timestamp.as_bytes());
    hasher.update(passwd.as_bytes());
    let digest = hasher.finalize();

    let mut secret = String::with_capacity(2 * digest.len());
    for &byte in digest.iter() {
        // Writing formatted hex into a `String` is infallible.
        let _ = write!(secret, "{byte:02x}");
    }
    secret
}

// ===========================================================================
// State-response handlers (← the `pop3_state_*_resp` functions) and the
// command / body machinery (← `pop3_perform_command` and `pop3_write`).
// ===========================================================================

impl Pop3Conn {
    /// Handle the server greeting (← `pop3_state_servergreet_resp`).
    ///
    /// A non-`+OK` greeting is a fatal `CURLE_WEIRD_SERVER_REPLY`. Otherwise, if
    /// the greeting is long enough, the RFC-822 message-id-shaped APOP timestamp
    /// `<...@...>` is captured (brackets included) and [`POP3_TYPE_APOP`] is
    /// recorded, then `CAPA` is issued via [`Self::perform_capa`]. A timestamp
    /// without an `@` is *not* RFC-1939 conformant and is ignored, exactly as
    /// curl does.
    fn state_servergreet_resp(&mut self, pp: &mut PingPong, code: i32) -> Result<()> {
        if code != i32::from(b'+') {
            return Err(Error::with_context(
                CurlCode::WeirdServerReply,
                "Got unexpected pop3-server response",
            ));
        }

        let line = pp.response_line();
        let len = line.len();

        if len > 3 {
            // Look for the APOP timestamp `<...>`; capture it as an owned string
            // (with brackets) so the borrow of `pp` ends before `perform_capa`.
            let mut timestamp: Option<String> = None;
            if let Some(lt) = line.iter().position(|&b| b == b'<') {
                // Search the remainder (from `<`) for the closing `>`.
                if let Some(gt_rel) = line[lt..].iter().position(|&b| b == b'>') {
                    // Length of the timestamp including the brackets (`gt - lt + 1`).
                    let timestamplen = gt_rel + 1;
                    let ts = &line[lt..lt + timestamplen];
                    // The timestamp must contain `@` to be RFC-822 conformant.
                    if ts.contains(&b'@') {
                        timestamp = Some(String::from_utf8_lossy(ts).into_owned());
                    }
                }
            }

            if let Some(ts) = timestamp {
                self.apoptimestamp = Some(ts);
                self.authtypes |= POP3_TYPE_APOP;
            }

            self.perform_capa(pp)?;
        }

        Ok(())
    }

    /// Handle a `CAPA` response line (← `pop3_state_capa_resp`).
    ///
    /// Untagged continuation lines (`'*'`) advertise capabilities: `STLS`
    /// (records [`Self::tls_supported`]), `USER` (records
    /// [`POP3_TYPE_CLEARTEXT`]) and `SASL <mechs>` (records [`POP3_TYPE_SASL`]
    /// and each decoded mechanism bit). The final tagged line decides the next
    /// step: authenticate immediately if TLS is not wanted or already active;
    /// otherwise `STLS`-upgrade if the server supports it; otherwise fall back to
    /// clear authentication when TLS is merely *tried*; otherwise fail with
    /// `CURLE_USE_SSL_FAILED`.
    fn state_capa_resp(&mut self, pp: &mut PingPong, conn: &Connection, code: i32) -> Result<()> {
        let star = i32::from(b'*');
        let plus = i32::from(b'+');

        if code == star {
            let line = pp.response_line();
            let len = line.len();

            if len >= 4 && line[..4].eq_ignore_ascii_case(b"STLS") {
                // Server supports the STLS (STARTTLS) capability.
                self.tls_supported = true;
            } else if len >= 4 && line[..4].eq_ignore_ascii_case(b"USER") {
                // Server supports clear-text USER/PASS authentication.
                self.authtypes |= POP3_TYPE_CLEARTEXT;
            } else if len >= 5 && line[..5].eq_ignore_ascii_case(b"SASL ") {
                // Server supports SASL; parse the space/newline-separated list of
                // mechanism tokens that follows the "SASL " keyword.
                self.authtypes |= POP3_TYPE_SASL;
                let mut rest = &line[5..];
                loop {
                    // Skip leading blanks and newlines (← the ISBLANK/ISNEWLINE loop).
                    while !rest.is_empty() && (is_blank(rest[0]) || is_newline(rest[0])) {
                        rest = &rest[1..];
                    }
                    if rest.is_empty() {
                        break;
                    }

                    // Extract one whitespace-delimited word.
                    let mut wordlen = 0usize;
                    while wordlen < rest.len()
                        && !is_blank(rest[wordlen])
                        && !is_newline(rest[wordlen])
                    {
                        wordlen += 1;
                    }

                    // Decode the word to a mechanism bit; require that the whole
                    // word be consumed (← `mechbit && llen == wordlen`).
                    let word = &rest[..wordlen];
                    let decoded = std::str::from_utf8(word).ok().and_then(decode_mech);
                    if let Some((mechbit, llen)) = decoded {
                        if mechbit != 0 && llen == wordlen {
                            self.sasl.add_authmech(mechbit);
                        }
                    }

                    rest = &rest[wordlen..];
                }
            }
        } else {
            // Final CAPA line. Clear text is assumed when CAPA is unrecognized.
            if code != plus {
                self.authtypes |= POP3_TYPE_CLEARTEXT;
            }

            if self.use_ssl == Pop3UseSsl::None || conn.is_ssl(FIRSTSOCKET) {
                // No TLS wanted, or the connection is already encrypted.
                self.perform_authentication(pp, conn)?;
            } else if code == plus && self.tls_supported {
                // Upgrade to TLS now.
                self.perform_starttls(pp)?;
            } else if self.use_ssl <= Pop3UseSsl::Try {
                // TLS was only requested opportunistically; carry on in the clear.
                self.perform_authentication(pp, conn)?;
            } else {
                return Err(Error::with_context(
                    CurlCode::UseSslFailed,
                    "STLS not supported.",
                ));
            }
        }

        Ok(())
    }

    /// Handle the `STLS` response (← `pop3_state_starttls_resp`).
    ///
    /// A `+OK` moves to [`Pop3State::UpgradeTls`] to drive the handshake; a
    /// denial fails with `CURLE_USE_SSL_FAILED` unless TLS was only *tried*, in
    /// which case authentication proceeds in the clear. (curl also rejects a
    /// pipelined response via `pp->overflow`; that buffer is private to the
    /// ping-pong engine here, so the check is not reproduced.)
    fn state_starttls_resp(
        &mut self,
        pp: &mut PingPong,
        conn: &Connection,
        code: i32,
    ) -> Result<()> {
        if code != i32::from(b'+') {
            if self.use_ssl != Pop3UseSsl::Try {
                return Err(Error::with_context(
                    CurlCode::UseSslFailed,
                    "STARTTLS denied",
                ));
            }
            // Fall back and carry on with authentication.
            self.perform_authentication(pp, conn)?;
        } else {
            self.set_state(Pop3State::UpgradeTls);
        }

        Ok(())
    }

    /// Handle a SASL authentication response (← `pop3_state_auth_resp`).
    ///
    /// Delegates to [`Sasl::sasl_continue`] via a [`Pop3SaslAdapter`]. On
    /// completion the connect phase ends; if the SASL engine goes idle (every
    /// mechanism was cancelled) the handler falls back to APOP, then to clear
    /// `USER`/`PASS`, and finally fails with `CURLE_LOGIN_DENIED`.
    fn state_auth_resp(&mut self, pp: &mut PingPong, conn: &Connection, code: i32) -> Result<()> {
        let creds = self.build_credentials(conn);

        // `self.sasl` (a field) and the adapter over `pp` (a parameter) are
        // disjoint borrows, so the engine can drive its POP3 callbacks.
        let progress = {
            let mut adapter = Pop3SaslAdapter { pp: &mut *pp };
            self.sasl.sasl_continue(&mut adapter, &creds, code)?
        };

        match progress {
            SaslProgress::Done => self.set_state(Pop3State::Stop),
            SaslProgress::Idle => {
                if self.authtypes & self.preftype & POP3_TYPE_APOP != 0 {
                    self.perform_apop(pp, conn)?;
                } else if self.authtypes & self.preftype & POP3_TYPE_CLEARTEXT != 0 {
                    self.perform_user(pp, conn)?;
                } else {
                    return Err(Error::with_context(
                        CurlCode::LoginDenied,
                        "Authentication cancelled",
                    ));
                }
            }
            SaslProgress::InProgress => {}
        }

        Ok(())
    }

    /// Handle the `APOP` response (← `pop3_state_apop_resp`). Non-`+OK` fails with
    /// `CURLE_LOGIN_DENIED`; success ends the connect phase.
    fn state_apop_resp(&mut self, code: i32) -> Result<()> {
        if code != i32::from(b'+') {
            return Err(Error::with_context(
                CurlCode::LoginDenied,
                format!("Authentication failed: {code}"),
            ));
        }
        self.set_state(Pop3State::Stop);
        Ok(())
    }

    /// Handle the `USER` response (← `pop3_state_user_resp`). On `+OK` the `PASS`
    /// command is sent and the state advances to [`Pop3State::Pass`]; otherwise
    /// `CURLE_LOGIN_DENIED`.
    fn state_user_resp(&mut self, pp: &mut PingPong, conn: &Connection, code: i32) -> Result<()> {
        if code != i32::from(b'+') {
            return Err(Error::with_context(
                CurlCode::LoginDenied,
                format!("Access denied. {}", code_char(code)),
            ));
        }

        // Send the PASS command with the connection password (empty if unset).
        let passwd = conn.passwd.as_deref().unwrap_or("");
        pp.sendf(format_args!("PASS {passwd}"))?;
        self.set_state(Pop3State::Pass);
        Ok(())
    }

    /// Handle the `PASS` response (← `pop3_state_pass_resp`). Non-`+OK` fails with
    /// `CURLE_LOGIN_DENIED`; success ends the connect phase.
    fn state_pass_resp(&mut self, code: i32) -> Result<()> {
        if code != i32::from(b'+') {
            return Err(Error::with_context(
                CurlCode::LoginDenied,
                format!("Access denied. {}", code_char(code)),
            ));
        }
        self.set_state(Pop3State::Stop);
        Ok(())
    }

    /// Handle the command response (← `pop3_state_command_resp`).
    ///
    /// A non-`+OK` reply ends the DO phase with `CURLE_WEIRD_SERVER_REPLY`.
    /// Otherwise the end-of-body scanner is primed: the `+OK` line's trailing
    /// CRLF is the first two bytes of the `\r\n.\r\n` marker, so [`Self::eob`] is
    /// seeded to `2`, and because that CRLF is not part of the body,
    /// [`Self::strip`] is set to `2` so those bytes are not delivered. Body bytes
    /// that follow are streamed by [`Self::write_body`]; the DO phase ends here.
    fn state_command_resp(&mut self, code: i32) -> Result<()> {
        if code != i32::from(b'+') {
            self.set_state(Pop3State::Stop);
            return Err(Error::from(CurlCode::WeirdServerReply));
        }

        // The '+OK' line ends with CRLF — the first two bytes of the EOB marker.
        // Seed the match so a body of exactly ".\r\n" (i.e. no content) is still
        // detected as the end-of-body (← `pop3c->eob = 2`).
        self.eob = 2;
        // Those two bytes are not part of the actual body, so schedule them to be
        // stripped rather than delivered (← `pop3c->strip = 2`).
        self.strip = 2;

        // curl may have body bytes already buffered as `pp->overflow`; that
        // buffer is private to the ping-pong engine here, so body delivery is
        // driven by the transfer layer invoking `write_body` on later reads. The
        // DO phase ends regardless of `pop3->transfer`.
        self.set_state(Pop3State::Stop);
        Ok(())
    }

    /// Issue the message-retrieval command for the DO phase
    /// (← `pop3_perform_command`).
    ///
    /// The default command is `RETR <id>` when a message id is present, else a
    /// mailbox-level `LIST`; a message-specific `LIST` streams only info (no
    /// body). A non-empty `CURLOPT_CUSTOMREQUEST` overrides the command verb.
    /// The command is sent (with the id argument when present), the state
    /// advances to [`Pop3State::Command`], and [`Self::no_body`] records whether
    /// the chosen command yields a multi-line body.
    ///
    /// Public because the DO phase (curl's `Curl_protocol_pop3.do_it` =
    /// `pop3_do` → `pop3_perform`) drives it from the transfer layer once the
    /// request handles are threaded through [`TransferCtx`].
    pub fn perform_command(&mut self, pp: &mut PingPong) -> Result<()> {
        // Calculate the default command. `command` is owned so the immutable
        // borrow of `self.pop3` ends before the later `&mut self` calls.
        let mut command: String = if self.pop3.id.is_empty() || self.list_only {
            if !self.pop3.id.is_empty() {
                // Message-specific LIST, so skip the BODY transfer.
                self.pop3.transfer = PpTransfer::Info;
            }
            String::from("LIST")
        } else {
            String::from("RETR")
        };

        if let Some(custom) = self.pop3.custom.as_deref() {
            if !custom.is_empty() {
                command = String::from(custom);
            }
        }

        // Send the command, with the message id argument when we have one.
        if self.pop3.id.is_empty() {
            pp.sendf(format_args!("{command}"))?;
        } else {
            pp.sendf(format_args!("{} {}", command, self.pop3.id))?;
        }

        self.set_state(Pop3State::Command);
        self.no_body = !pop3_is_multiline(&command);
        Ok(())
    }

    /// Scan a received chunk for the end-of-body marker and return the body bytes
    /// to deliver (← `pop3_write`, `lib/pop3.c`).
    ///
    /// A multi-line POP3 body is terminated by the five-byte marker `\r\n.\r\n`
    /// ([`POP3_EOB`]); the marker may straddle chunk boundaries, so the match
    /// progress lives in [`Self::eob`] across calls. A data line beginning with
    /// `.` is dot-stuffed by the server (`..`); the extra leading dot is
    /// stripped on receive. The leading CRLF of the marker belongs to the message
    /// (RFC 1939 §3) and is delivered; the trailing `.\r\n` is not.
    ///
    /// Returns `(body, done)`: `body` is the (possibly empty) slice of bytes to
    /// hand to the client-write sink, and `done` is `true` once the full marker
    /// has matched (curl clears `KEEP_RECV` and finishes the transfer). This
    /// mirrors `pop3_write`'s `Curl_client_write` calls without owning the sink,
    /// which lives in the transfer layer.
    ///
    /// Public because the response-write path (curl's
    /// `Curl_protocol_pop3.write_resp` = `pop3_write`) drives it from the
    /// transfer layer for each received body chunk.
    pub fn write_body(&mut self, data: &[u8]) -> (Vec<u8>, bool) {
        let mut out: Vec<u8> = Vec::new();
        let mut strip_dot = false;
        let mut last: usize = 0;
        let nread = data.len();

        // Search for the 5-byte end-of-body marker (0d 0a 2e 0d 0a). A line that
        // starts with a dot matches the marker, so the server prefixes it with an
        // extra dot which is stripped here; the marker may span several chunks.
        for i in 0..nread {
            let mut prev = self.eob;

            match data[i] {
                0x0d => {
                    if self.eob == 0 {
                        self.eob += 1;
                        if i != 0 {
                            // Flush the body part that did not match the marker.
                            out.extend_from_slice(&data[last..i]);
                            last = i;
                        }
                    } else if self.eob == 3 {
                        self.eob += 1;
                    } else {
                        // A match at neither position 0 nor 3 restarts matching.
                        self.eob = 1;
                    }
                }
                0x0a => {
                    if self.eob == 1 || self.eob == 4 {
                        self.eob += 1;
                    } else {
                        // A match at neither position 1 nor 4 restarts the search.
                        self.eob = 0;
                    }
                }
                0x2e => {
                    if self.eob == 2 {
                        self.eob += 1;
                    } else if self.eob == 3 {
                        // Extra dot after CRLF (dot-stuffing) — strip it.
                        strip_dot = true;
                        self.eob = 0;
                    } else {
                        // A match at a position other than 2 restarts the search.
                        self.eob = 0;
                    }
                }
                _ => {
                    self.eob = 0;
                }
            }

            // Did a partial match subsequently fail? `strip` is only non-zero for
            // the first mismatch after the seeded CRLF, and there `prev == strip`
            // so nothing is emitted below.
            if prev != 0 && prev >= self.eob {
                while prev != 0 && self.strip != 0 {
                    prev -= 1;
                    self.strip -= 1;
                }

                if prev != 0 {
                    if strip_dot && prev - 1 > 0 {
                        // Partial match was CRLF + dot: emit only the CRLF, since
                        // the server inserted the dot.
                        out.extend_from_slice(&POP3_EOB[..prev - 1]);
                    } else if !strip_dot {
                        out.extend_from_slice(&POP3_EOB[..prev]);
                    }
                    // else: strip_dot with prev-1 == 0 emits nothing.

                    last = i;
                    strip_dot = false;
                }
            }
        }

        if self.eob == POP3_EOB_LEN {
            // Full marker matched: transfer done. The leading CRLF of the marker
            // is part of the message per RFC 1939 §3, so deliver those two bytes.
            out.extend_from_slice(&POP3_EOB[..2]);
            self.eob = 0;
            return (out, true);
        }

        if self.eob != 0 {
            // A partial match is in progress; emit nothing until it resolves.
            return (out, false);
        }

        if nread - last != 0 {
            out.extend_from_slice(&data[last..nread]);
        }

        (out, false)
    }
}

// ===========================================================================
// Pop3Handler — the scheme's `Protocol` vtable (← `Curl_protocol_pop3`,
// shared by the `pop3` and `pop3s` schemes exactly as curl points both
// `Curl_scheme_pop3` and `Curl_scheme_pop3s` at `&Curl_protocol_pop3`).
// ===========================================================================

/// The POP3/POP3S protocol handler singleton (← `Curl_protocol_pop3`).
///
/// The complete POP3 logic lives in [`Pop3Conn`] (the port of `struct
/// pop3_conn` and the `pop3_*` machine) and its per-transfer [`Pop3`] (the port
/// of `struct POP3`); the vtable methods below map one-to-one onto curl's
/// `Curl_protocol_pop3` function pointers and drive that engine over the
/// connection, ping-pong buffer, and request state carried by the shared
/// [`TransferCtx`] (the engine lives in [`TransferCtx::proto_state`], the
/// connection in [`TransferCtx::conn`], ← `conn->proto.pop3c`). curl's
/// `Curl_protocol_pop3` sets these pointers:
///
/// | curl pointer         | value                 | mapped to                                   |
/// |----------------------|-----------------------|---------------------------------------------|
/// | `setup_connection`   | `pop3_setup_connection` | [`Pop3Conn::new`] + URL-option parse (default hook) |
/// | `do_it`              | `pop3_do`             | [`Pop3Handler::do_it`] → [`Pop3Conn::perform`] |
/// | `doing`              | `pop3_doing`          | [`Pop3Handler::doing`] → [`Pop3Conn::doing`] |
/// | `done`               | `pop3_done`           | [`Pop3Handler::done`] → [`Pop3Conn::done`]  |
/// | `write_resp`         | `pop3_write`          | [`Pop3Handler::write_resp`] → [`Pop3Conn::write_body`] |
/// | `connect_it`         | `pop3_connect`        | [`Pop3Conn::run_statemachine`] from `ServerGreet` (default hook) |
/// | `connecting`         | `pop3_multi_statemach`| [`Pop3Conn::run_statemachine`] (default hook) |
/// | `proto_pollset` / `doing_pollset` | `pop3_pollset` | the ping-pong socket set (default hook) |
/// | `disconnect`         | `pop3_disconnect`     | [`Pop3Conn::perform_quit`] (default hook)   |
/// | `do_more` / `perform_pollset` / `write_resp_hd` / `connection_check` / `attach` / `follow` | `ZERO_NULL` | faithful no-op defaults |
///
/// The DO-phase pointers (`do_it`, `doing`), the mandatory `done`, and the body
/// writer (`write_resp`) are overridden here to drive [`Pop3Conn`] over the
/// [`TransferCtx`]; every other hook keeps the [`Protocol`] trait's faithful
/// default, mirroring curl's `ZERO_NULL` entries and the generic connect/
/// disconnect machinery. This matches the sibling ping-pong handlers.
#[derive(Debug, Clone, Copy, Default)]
pub struct Pop3Handler;

/// The shared POP3/POP3S handler singleton referenced by the `pop3` and `pop3s`
/// schemes (← the `&Curl_protocol_pop3` pointer in `Curl_scheme_pop3` and
/// `Curl_scheme_pop3s`).
pub static HANDLER: Pop3Handler = Pop3Handler;

/// Borrow the transfer's [`Connection`] and its [`Pop3Conn`] engine disjointly
/// from the [`TransferCtx`]: the connection lives in [`TransferCtx::conn`] and
/// the engine — established by the connect phase (← `conn->proto.pop3c`) — in
/// [`TransferCtx::proto_state`]. Because `conn` and `proto_state` are distinct
/// fields, the two mutable borrows coexist (the disjoint-field-borrow pattern
/// documented on [`TransferCtx`]).
///
/// # Errors
/// [`CurlCode::BadFunctionArgument`] when either handle is absent — a caller
/// precondition mirroring curl requiring both `data->conn` and
/// `conn->proto.pop3c` to be established before the DO phase runs.
fn pop3_conn_and_engine(ctx: &mut TransferCtx) -> Result<(&mut Connection, &mut Pop3Conn)> {
    let engine = ctx
        .proto_state
        .as_deref_mut()
        .and_then(|s| s.downcast_mut::<Pop3Conn>())
        .ok_or_else(|| {
            Error::with_context(
                CurlCode::BadFunctionArgument,
                "[POP3] no POP3 engine assigned to transfer",
            )
        })?;
    let conn = ctx.conn.as_deref_mut().ok_or_else(|| {
        Error::with_context(
            CurlCode::BadFunctionArgument,
            "[POP3] no connection assigned to transfer",
        )
    })?;
    Ok((conn, engine))
}

impl Protocol for Pop3Handler {
    /// The required "DO" phase (← `pop3_do` → `pop3_perform`).
    ///
    /// Drives the transfer's [`Pop3Conn`] engine (held in
    /// [`TransferCtx::proto_state`], its URL path / custom request already
    /// decoded into the engine by the connect phase, ← `conn->proto.pop3c`) and
    /// its [`Connection`] (in [`TransferCtx::conn`]): issues the first command
    /// (`RETR`/`LIST`/`TOP` or a custom command) and pumps the ping-pong state
    /// machine. Returns `true` if the DO phase has already reached
    /// [`Pop3State::Stop`] in this step; otherwise the transfer layer continues
    /// it via [`doing`](Protocol::doing) (← `pop3_multi_statemach`). The
    /// multi-line response body is delivered separately through
    /// [`write_resp`](Protocol::write_resp).
    ///
    /// # Errors
    /// [`CurlCode::BadFunctionArgument`] if the transfer carries no connection
    /// or no POP3 engine, or any protocol/I/O error surfaced while issuing the
    /// command.
    fn do_it<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        Box::pin(async move {
            let (conn, engine) = pop3_conn_and_engine(ctx)?;
            engine.perform(conn).await
        })
    }

    /// Continue a non-blocking POP3 DO phase (← `pop3_doing`).
    ///
    /// Pumps the engine's ping-pong state machine one step and reports whether
    /// the DO phase reached [`Pop3State::Stop`].
    ///
    /// # Errors
    /// As [`do_it`](Self::do_it): a missing connection/engine, or an engine
    /// error surfaced while pumping the state machine.
    fn doing<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        Box::pin(async move {
            let (conn, engine) = pop3_conn_and_engine(ctx)?;
            engine.doing(conn).await
        })
    }

    /// The required teardown (← `pop3_done`).
    ///
    /// Resets `POP3.transfer` to [`PpTransfer::Body`] for the next request and,
    /// on a bad `status`, marks the connection for closure and propagates the
    /// error. (`POP3.id`/`POP3.custom` are owned `String`s released
    /// deterministically by ownership when the transfer ends.)
    ///
    /// # Errors
    /// The propagated bad `status`, or [`CurlCode::BadFunctionArgument`] for a
    /// missing connection/engine.
    fn done<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        status: Result<()>,
        premature: bool,
    ) -> ProtoFuture<'a, ()> {
        Box::pin(async move {
            let (conn, engine) = pop3_conn_and_engine(ctx)?;
            engine.done(conn, status, premature).await
        })
    }

    /// Post-process and deliver a chunk of response *body* bytes (← `pop3_write`).
    ///
    /// The multi-line message body is dot-unstuffed and scanned for the
    /// `\r\n.\r\n` end-of-body marker by [`Pop3Conn::write_body`]; the resulting
    /// client bytes (the marker and stuffing removed) are written to the
    /// transfer's [`sink`](TransferCtx::sink), exactly as curl's `pop3_write`
    /// funnels body bytes into `Curl_client_write`. `is_eos` needs no
    /// POP3-specific finalisation (the EOB marker already delimits the body).
    fn write_resp<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        buf: &'a [u8],
        is_eos: bool,
    ) -> ProtoFuture<'a, ()> {
        Box::pin(async move {
            let _ = is_eos;
            // De-stuff via the engine's EOB scanner (disjoint `proto_state`
            // borrow ends when `out` is produced), then deliver to the sink.
            let out = match ctx
                .proto_state
                .as_deref_mut()
                .and_then(|s| s.downcast_mut::<Pop3Conn>())
            {
                Some(engine) => engine.write_body(buf).0,
                // No engine assigned (a caller precondition normally satisfied
                // by the connect phase): pass the chunk through unchanged rather
                // than aborting the write.
                None => buf.to_vec(),
            };
            if !out.is_empty() {
                if let Some(sink) = ctx.sink.as_deref_mut() {
                    sink.write(&out)?;
                }
            }
            Ok(())
        })
    }
}

// ===========================================================================
// Unit tests. These validate the byte-for-byte parity of the pure algorithms
// (response classification, the end-of-body / dot-unstuffing scanner, the
// command-multiline table, URL decoding/parsing, and the APOP digest) and the
// observable state effects of the command builders. They exercise only safe
// Rust and need no network — matching the sibling protocol test modules.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::Scheme;

    use std::sync::{Arc, Mutex};

    use crate::conn::filters::{CfFuture, FilterCtx, QueryCtx, QueryOut};
    use crate::conn::{CfQuery, CfType, ConnectionFilter, FilterChain, Transport};
    use crate::protocols::TransferSink;

    /// A fresh connection state with default options.
    fn mk_pop3() -> Pop3Conn {
        Pop3Conn::new(&Pop3Request::default())
    }

    /// A minimal POP3 [`Connection`] for handlers that read connection fields.
    fn mk_conn() -> Connection {
        Connection::new(Scheme::new("pop3", 110), "mail.example.com", 110)
    }

    // ----- In-memory mock connection filter (leaf; overrides send/recv) -----
    //
    // Mirrors the harness in `smtp.rs`/`pingpong.rs`: it delivers canned bytes
    // on `recv` and captures written bytes on `send`, so command framing and
    // response handling can be exercised without a live socket.

    /// Shared, inspectable I/O state for [`MockFilter`].
    #[derive(Default)]
    struct MockIo {
        /// Bytes handed to `recv`, consumed from the front.
        to_deliver: Vec<u8>,
        /// Bytes accepted by `send`, for assertion.
        captured: Vec<u8>,
    }

    /// A leaf filter terminating the chain: it never delegates.
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
                g.captured.extend_from_slice(&data);
                Ok(data.len())
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

    /// A network connection whose primary chain is the given mock filter.
    fn conn_with(io: Arc<Mutex<MockIo>>) -> Connection {
        let mut conn = Connection::new(Scheme::new("pop3", 110), "mail.example.com", 110);
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(MockFilter { io, fd: 7 }));
        conn.cfilter[FIRSTSOCKET] = Some(chain);
        conn
    }

    /// A [`TransferSink`] that records every delivered body chunk for assertion.
    struct RecordingSink(Arc<Mutex<Vec<u8>>>);
    impl TransferSink for RecordingSink {
        fn write(&mut self, data: &[u8]) -> Result<()> {
            self.0.lock().expect("sink lock").extend_from_slice(data);
            Ok(())
        }
    }

    // ----- Pop3State diagnostic vocabulary (← the `names[]` in `pop3_state`) --

    #[test]
    fn state_names_match_curl_verbatim() {
        // These are the exact strings curl emits in its `POP3 %p state change
        // from %s to %s` trace (the `names[]` array in `pop3_state`), not the
        // `POP3_*` C enum-constant identifiers. `--trace` parity depends on them.
        assert_eq!(Pop3State::Stop.name(), "STOP");
        assert_eq!(Pop3State::ServerGreet.name(), "SERVERGREET");
        assert_eq!(Pop3State::Capa.name(), "CAPA");
        assert_eq!(Pop3State::StartTls.name(), "STARTTLS");
        assert_eq!(Pop3State::UpgradeTls.name(), "UPGRADETLS");
        assert_eq!(Pop3State::Auth.name(), "AUTH");
        assert_eq!(Pop3State::Apop.name(), "APOP");
        assert_eq!(Pop3State::User.name(), "USER");
        assert_eq!(Pop3State::Pass.name(), "PASS");
        assert_eq!(Pop3State::Command.name(), "COMMAND");
        assert_eq!(Pop3State::Quit.name(), "QUIT");
        // curl's `names[]` has no entry for the LAST sentinel; we return "LAST"
        // defensively and it is never emitted for a live transition.
        assert_eq!(Pop3State::Last.name(), "LAST");
    }

    // ----- classify_response (← pop3_endofresp) -----------------------------

    #[test]
    fn classify_success_error_and_continuation() {
        let conn = mk_pop3();
        let mut code = 0;

        // `+OK` success.
        assert!(conn.classify_response(b"+OK logged in\r\n", &mut code));
        assert_eq!(code, i32::from(b'+'));

        // `-ERR` failure.
        assert!(conn.classify_response(b"-ERR bad\r\n", &mut code));
        assert_eq!(code, i32::from(b'-'));

        // A bare leading `+` (SASL continuation) is untagged.
        assert!(conn.classify_response(b"+ aGVsbG8=\r\n", &mut code));
        assert_eq!(code, i32::from(b'*'));

        // A line that is neither is not a complete response.
        assert!(!conn.classify_response(b"random\r\n", &mut code));
    }

    #[test]
    fn classify_capa_terminator_and_lines() {
        let mut conn = mk_pop3();
        conn.state = Pop3State::Capa;
        let mut code = 0;

        // Lone-dot terminator (CRLF form) is a success.
        assert!(conn.classify_response(b".\r\n", &mut code));
        assert_eq!(code, i32::from(b'+'));

        // Lone-dot terminator (bare-LF form) is a success too.
        assert!(conn.classify_response(b".\n", &mut code));
        assert_eq!(code, i32::from(b'+'));

        // Any other CAPA line is an untagged continuation.
        assert!(conn.classify_response(b"STLS\r\n", &mut code));
        assert_eq!(code, i32::from(b'*'));

        // `-ERR` still wins even in CAPA state (checked before the CAPA branch).
        assert!(conn.classify_response(b"-ERR no capa\r\n", &mut code));
        assert_eq!(code, i32::from(b'-'));
    }

    // ----- pop3_get_message -------------------------------------------------

    #[test]
    fn get_message_strips_prefix_and_trims() {
        // The 2-byte status prefix is skipped, leading blanks removed, trailing
        // whitespace/newlines trimmed.
        assert_eq!(pop3_get_message(b"+ challenge\r\n"), b"challenge");
        // No content after the prefix -> empty.
        assert_eq!(pop3_get_message(b"+\r\n"), b"");
        // Too short (<= 2 bytes) -> empty.
        assert_eq!(pop3_get_message(b"+"), b"");
    }

    // ----- pop3_is_multiline (← the POP3CMDS table) -------------------------

    #[test]
    fn is_multiline_table_matches_curl() {
        // Bare multi-line commands.
        assert!(pop3_is_multiline("RETR"));
        assert!(pop3_is_multiline("LIST"));
        assert!(pop3_is_multiline("UIDL"));
        assert!(pop3_is_multiline("CAPA"));
        assert!(pop3_is_multiline("TOP"));

        // Single-line commands.
        assert!(!pop3_is_multiline("USER"));
        assert!(!pop3_is_multiline("PASS"));
        assert!(!pop3_is_multiline("DELE"));
        assert!(!pop3_is_multiline("STAT"));
        assert!(!pop3_is_multiline("QUIT"));
        assert!(!pop3_is_multiline("NOOP"));

        // With arguments: LIST/UIDL become single-line (multiline_with_args=false);
        // RETR/TOP stay multi-line (multiline_with_args=true).
        assert!(!pop3_is_multiline("LIST 1"));
        assert!(!pop3_is_multiline("UIDL 3"));
        assert!(pop3_is_multiline("RETR 1"));
        assert!(pop3_is_multiline("TOP 1 0"));

        // Case-insensitive matching.
        assert!(pop3_is_multiline("retr 1"));

        // Unknown commands default to multi-line.
        assert!(pop3_is_multiline("FOOBAR"));
    }

    // ----- write_body (← pop3_write) ----------------------------------------

    #[test]
    fn write_body_delivers_body_then_detects_eob() {
        let mut conn = mk_pop3();
        // A complete body followed by the end-of-body marker in one chunk.
        let (body, done) = conn.write_body(b"hello world\r\n.\r\n");
        assert!(done, "the full EOB marker must end the transfer");
        // The message content plus the leading CRLF of the marker (RFC 1939 §3),
        // but not the terminating `.\r\n`.
        assert_eq!(body, b"hello world\r\n");
    }

    #[test]
    fn write_body_unstuffs_leading_dot() {
        let mut conn = mk_pop3();
        // Dot-unstuffing only applies to a `.` at the start of a line (i.e. right
        // after a CRLF). `state_command_resp` seeds eob=2/strip=2 so the body's
        // first line is treated as line-start; reproduce that here. The server
        // dot-stuffs a leading `.` as `..`; the extra dot is stripped on receive.
        conn.eob = 2;
        conn.strip = 2;
        let (body, done) = conn.write_body(b"..dotted\r\n.\r\n");
        assert!(done);
        assert_eq!(body, b".dotted\r\n");
    }

    #[test]
    fn write_body_eob_split_across_chunks() {
        let mut conn = mk_pop3();
        // First chunk ends mid-marker (after "\r\n.").
        let (b1, d1) = conn.write_body(b"data\r\n.");
        assert!(!d1, "partial marker must not end the transfer");
        // The body up to (but not including) the partial marker is delivered.
        assert_eq!(b1, b"data");
        // Second chunk supplies the rest of the marker ("\r\n").
        let (b2, d2) = conn.write_body(b"\r\n");
        assert!(d2, "the completed marker ends the transfer");
        // The marker's leading CRLF belongs to the message and is delivered now.
        assert_eq!(b2, b"\r\n");
    }

    #[test]
    fn write_body_command_seed_strips_initial_crlf() {
        // state_command_resp seeds eob=2, strip=2 so the `+OK` line's trailing
        // CRLF is treated as the marker's first two bytes. When the body does NOT
        // begin with a dot, that partial match fails on the first body byte and
        // the strip counter consumes the seeded CRLF so it is not prepended to
        // the delivered body (← the `while(prev && pop3c->strip)` block).
        let mut conn = mk_pop3();
        conn.eob = 2;
        conn.strip = 2;
        let (body, done) = conn.write_body(b"Hello\r\n.\r\n");
        assert!(done);
        // "Hello" plus the marker's leading CRLF; the seeded CRLF was stripped.
        assert_eq!(body, b"Hello\r\n");
    }

    #[test]
    fn write_body_empty_body_emits_marker_crlf() {
        // With the seed and a body of exactly `.\r\n`, the marker completes with
        // no intervening body byte, so the match never fails and the strip
        // counter is never consumed: curl emits the marker's leading CRLF
        // (POP3_EOB[..2]) as part of the message per RFC 1939 §3.
        let mut conn = mk_pop3();
        conn.eob = 2;
        conn.strip = 2;
        let (body, done) = conn.write_body(b".\r\n");
        assert!(done);
        assert_eq!(body, b"\r\n");
    }

    // ----- URL / option parsing ---------------------------------------------

    #[test]
    fn parse_url_path_decodes_message_id() {
        let mut conn = mk_pop3();
        conn.parse_url_path("/123").expect("valid path");
        assert_eq!(conn.pop3.id, "123");

        // Percent-decoding is applied (REJECT_CTRL permits printable bytes).
        let mut conn2 = mk_pop3();
        conn2.parse_url_path("/%41%42").expect("valid path");
        assert_eq!(conn2.pop3.id, "AB");

        // An empty path yields an empty (mailbox-level) id.
        let mut conn3 = mk_pop3();
        conn3.parse_url_path("/").expect("valid path");
        assert_eq!(conn3.pop3.id, "");
    }

    #[test]
    fn parse_url_path_rejects_control_bytes() {
        let mut conn = mk_pop3();
        // A decoded control byte (NUL) is rejected as CURLE_URL_MALFORMAT.
        let err = conn
            .parse_url_path("/%00")
            .expect_err("control byte rejected");
        assert_eq!(err.code(), CurlCode::UrlMalformat);
    }

    #[test]
    fn parse_custom_request_decodes() {
        let mut conn = mk_pop3();
        conn.parse_custom_request(Some("UIDL")).expect("valid");
        assert_eq!(conn.pop3.custom.as_deref(), Some("UIDL"));

        // None leaves it unset.
        let mut conn2 = mk_pop3();
        conn2.parse_custom_request(None).expect("valid");
        assert_eq!(conn2.pop3.custom, None);
    }

    #[test]
    fn parse_url_options_plus_apop_forces_apop() {
        let mut conn = mk_pop3();
        conn.parse_url_options(Some("AUTH=+APOP"))
            .expect("valid option");
        assert_eq!(conn.preftype, POP3_TYPE_APOP);
    }

    #[test]
    fn parse_url_options_star_is_any() {
        let mut conn = mk_pop3();
        // `AUTH=*` selects the default SASL set, which maps to POP3_TYPE_ANY.
        conn.parse_url_options(Some("AUTH=*"))
            .expect("valid option");
        assert_eq!(conn.preftype, POP3_TYPE_ANY);
    }

    #[test]
    fn parse_url_options_malformed_is_url_error() {
        let mut conn = mk_pop3();
        let err = conn
            .parse_url_options(Some("FOO=bar"))
            .expect_err("unknown option rejected");
        assert_eq!(err.code(), CurlCode::UrlMalformat);
    }

    #[test]
    fn parse_url_options_empty_is_ok() {
        let mut conn = mk_pop3();
        // No options: preftype stays at its default (ANY) via the prefmech map.
        conn.parse_url_options(None).expect("no options is fine");
        assert_eq!(conn.preftype, POP3_TYPE_ANY);
    }

    // ----- APOP digest (← the MD5 block of pop3_perform_apop) ----------------

    #[test]
    fn apop_secret_matches_rfc1939_vector() {
        // RFC 1939 §7 worked example: timestamp + shared secret "tanstaaf".
        let secret = apop_secret("<1896.697170952@dbc.mtview.ca.us>", "tanstaaf");
        assert_eq!(secret, "c4c9334bac560ecc979e58001b3e22fb");
    }

    // ----- urldecode_reject_ctrl / hex_val ----------------------------------

    #[test]
    fn urldecode_decodes_and_rejects() {
        assert_eq!(urldecode_reject_ctrl(b"%41bc").unwrap(), "Abc");
        // A lone `%` without two hex digits is literal.
        assert_eq!(urldecode_reject_ctrl(b"50%").unwrap(), "50%");
        assert_eq!(urldecode_reject_ctrl(b"a%2").unwrap(), "a%2");
        // A decoded control byte is rejected.
        assert!(urldecode_reject_ctrl(b"%1f").is_err());
        // Decoding stops at a literal NUL (C `length == 0` => strlen).
        assert_eq!(urldecode_reject_ctrl(b"ab\0cd").unwrap(), "ab");
    }

    #[test]
    fn hex_val_maps_digits() {
        assert_eq!(hex_val(b'0'), Some(0));
        assert_eq!(hex_val(b'9'), Some(9));
        assert_eq!(hex_val(b'a'), Some(10));
        assert_eq!(hex_val(b'F'), Some(15));
        assert_eq!(hex_val(b'g'), None);
    }

    // ----- perform_command (← pop3_perform_command) -------------------------

    #[test]
    fn perform_command_defaults_to_retr_with_id() {
        let mut conn = mk_pop3();
        conn.pop3.id = String::from("1");
        let mut pp = PingPong::new();

        conn.perform_command(&mut pp).expect("command queued");
        assert_eq!(conn.state, Pop3State::Command);
        // RETR is multi-line, so a body IS expected.
        assert!(!conn.no_body);
        assert_eq!(conn.pop3.transfer, PpTransfer::Body);
        assert!(pp.needs_flush(), "a command must have been queued");
    }

    #[test]
    fn perform_command_lists_when_no_id() {
        let mut conn = mk_pop3();
        // id is empty by default.
        let mut pp = PingPong::new();

        conn.perform_command(&mut pp).expect("command queued");
        assert_eq!(conn.state, Pop3State::Command);
        // LIST is multi-line -> body expected.
        assert!(!conn.no_body);
    }

    #[test]
    fn perform_command_message_specific_list_is_info() {
        let mut conn = mk_pop3();
        conn.pop3.id = String::from("2");
        conn.list_only = true;
        let mut pp = PingPong::new();

        conn.perform_command(&mut pp).expect("command queued");
        // A message-specific LIST downgrades the transfer to INFO (no body).
        assert_eq!(conn.pop3.transfer, PpTransfer::Info);
        assert_eq!(conn.state, Pop3State::Command);
    }

    #[test]
    fn perform_command_custom_request_single_line() {
        let mut conn = mk_pop3();
        conn.pop3.id = String::from("1");
        conn.pop3.custom = Some(String::from("DELE"));
        let mut pp = PingPong::new();

        conn.perform_command(&mut pp).expect("command queued");
        // DELE is single-line -> no body.
        assert!(conn.no_body);
        assert_eq!(conn.state, Pop3State::Command);
    }

    // ----- perform_capa (← pop3_perform_capa) -------------------------------

    #[test]
    fn perform_capa_resets_state_and_queues() {
        let mut conn = mk_pop3();
        conn.tls_supported = true;
        conn.sasl.set_authmechs(0xFF);
        let mut pp = PingPong::new();

        conn.perform_capa(&mut pp).expect("CAPA queued");
        assert_eq!(conn.state, Pop3State::Capa);
        assert!(!conn.tls_supported, "STLS capability is re-probed");
        assert_eq!(conn.sasl.authmechs(), SASL_AUTH_NONE);
        assert!(pp.needs_flush());
    }

    // ----- perform_authentication (← pop3_perform_authentication) -----------

    #[test]
    fn authentication_falls_back_to_cleartext_user() {
        let mut conn = mk_pop3();
        // Server offers only clear text; user prefers anything.
        conn.authtypes = POP3_TYPE_CLEARTEXT;
        conn.preftype = POP3_TYPE_ANY;
        let mut c = mk_conn();
        c.user = Some(String::from("bob"));
        c.passwd = Some(String::from("secret"));
        let mut pp = PingPong::new();

        conn.perform_authentication(&mut pp, &c)
            .expect("auth started");
        // With no SASL mechanism and clear text available, USER is sent.
        assert_eq!(conn.state, Pop3State::User);
    }

    #[test]
    fn authentication_selects_apop_when_preferred() {
        let mut conn = mk_pop3();
        conn.authtypes = POP3_TYPE_APOP;
        conn.preftype = POP3_TYPE_APOP;
        conn.apoptimestamp = Some(String::from("<1896.697170952@dbc.mtview.ca.us>"));
        let mut c = mk_conn();
        c.user = Some(String::from("mrose"));
        c.passwd = Some(String::from("tanstaaf"));
        let mut pp = PingPong::new();

        conn.perform_authentication(&mut pp, &c)
            .expect("auth started");
        assert_eq!(conn.state, Pop3State::Apop);
    }

    #[test]
    fn authentication_ends_without_credentials() {
        let mut conn = mk_pop3();
        conn.authtypes = POP3_TYPE_CLEARTEXT;
        conn.preftype = POP3_TYPE_ANY;
        // No user set on the connection -> cannot authenticate.
        let c = mk_conn();
        let mut pp = PingPong::new();

        conn.perform_authentication(&mut pp, &c)
            .expect("connect ends");
        assert_eq!(conn.state, Pop3State::Stop);
    }

    // ----- Pop3Handler end-to-end (← pop3_do/pop3_doing/pop3_done/pop3_write) -

    /// The [`Pop3Handler`] trait hooks drive the DO phase over the [`Pop3Conn`]
    /// engine held in [`TransferCtx::proto_state`] and the [`Connection`] in
    /// [`TransferCtx::conn`]: `do_it` flushes the `RETR` command and `doing`
    /// consumes the `+OK` status line, completing the DO phase. `done` resets
    /// the transfer mode, and a transfer with no connection/engine is a
    /// caller-precondition error. This exercises the handler wiring the review
    /// flagged (the previous `do_it` discarded `TransferCtx` and returned
    /// `Ok(false)`).
    #[tokio::test]
    async fn handler_drives_retr_command_over_transfer_ctx() {
        // The server returns just the RETR status line; the message body is
        // delivered separately by the transfer layer via `write_resp`.
        let io = Arc::new(Mutex::new(MockIo {
            to_deliver: b"+OK 11 octets\r\n".to_vec(),
            ..MockIo::default()
        }));
        let mut conn = conn_with(Arc::clone(&io));
        conn.connect(FIRSTSOCKET, false).await.unwrap();

        // The engine the connect phase would have installed, primed to RETR #1.
        let mut engine = mk_pop3();
        engine.pop3.id = String::from("1");
        engine.pp.init(Instant::now());

        let mut ctx = TransferCtx::new();
        ctx.conn = Some(Box::new(conn));
        ctx.proto_state = Some(Box::new(engine));

        // Drive the DO phase through the handler: do_it flushes RETR, then doing
        // reads the +OK status line and completes the DO phase.
        let mut done = HANDLER.do_it(&mut ctx).await.unwrap();
        let mut guard = 0;
        while !done && guard < 40 {
            done = HANDLER.doing(&mut ctx).await.unwrap();
            guard += 1;
        }
        assert!(done, "handler DO phase did not reach completion");
        assert_eq!(io.lock().unwrap().captured.as_slice(), b"RETR 1\r\n");

        // DONE resets the transfer mode to Body for the next request.
        HANDLER.done(&mut ctx, Ok(()), false).await.unwrap();
        let engine = ctx
            .proto_state
            .as_deref()
            .unwrap()
            .downcast_ref::<Pop3Conn>()
            .unwrap();
        assert_eq!(engine.pop3.transfer, PpTransfer::Body);

        // A transfer with no connection/engine is a caller-precondition error.
        let mut empty = TransferCtx::new();
        let err = HANDLER.do_it(&mut empty).await.unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
    }

    /// [`Pop3Handler::write_resp`] (← `pop3_write`) dot-unstuffs the multi-line
    /// body via [`Pop3Conn::write_body`] and delivers the client bytes to the
    /// transfer's [`sink`](TransferCtx::sink); the terminating `.\r\n` marker is
    /// consumed, not delivered. This covers the "body bytes reach client
    /// callbacks" wiring the review flagged as deferred.
    #[tokio::test]
    async fn handler_write_resp_destuffs_body_to_sink() {
        let sink = Arc::new(Mutex::new(Vec::new()));
        let mut ctx = TransferCtx::new();
        ctx.proto_state = Some(Box::new(mk_pop3()));
        ctx.sink = Some(Box::new(RecordingSink(Arc::clone(&sink))));

        // A complete message body followed by the end-of-body marker in one
        // chunk (the known-good pair from `write_body_delivers_body_then_detects_eob`).
        HANDLER
            .write_resp(&mut ctx, b"hello world\r\n.\r\n", true)
            .await
            .unwrap();

        // The message content plus the marker's leading CRLF reached the sink;
        // the terminating `.\r\n` did not.
        assert_eq!(sink.lock().unwrap().as_slice(), b"hello world\r\n");
    }
}
