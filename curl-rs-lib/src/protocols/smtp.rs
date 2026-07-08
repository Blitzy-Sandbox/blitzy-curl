// SPDX-License-Identifier: curl
//
// curl-rs-lib — SMTP / SMTPS protocol handler.
//
//! SMTP / SMTPS protocol handler — the memory-safe Rust port of curl's
//! `lib/smtp.c` (+ `lib/smtp.h`) for the byte-for-byte functional-parity
//! rewrite of curl / libcurl **8.19.0-DEV**.
//!
//! SMTP is an RFC 5321 line-oriented "ping-pong" protocol: the client and
//! server exchange CRLF-terminated command/response pairs, where each response
//! is a three-digit status code optionally followed by text, and a multi-line
//! reply repeats the code with a `-` separator (`250-`) on every line but the
//! last (`250 `). This handler drives that exchange through the shared
//! [`crate::protocols::pingpong`] engine, exactly as curl layers `smtp.c` on
//! top of `pingpong.c`.
//!
//! # Conversation shape (preserved verbatim from curl)
//!
//! 1. **Greeting** — wait for the server's `220` banner.
//! 2. **EHLO / HELO** — send `EHLO <domain>`; on any non-2xx (and where TLS is
//!    not mandatory) fall back to the older `HELO <domain>`. The multi-line
//!    EHLO reply advertises the server's capabilities (`STARTTLS`, `SIZE`,
//!    `SMTPUTF8`, `AUTH <mechs>`), which are parsed here.
//! 3. **STARTTLS** — when TLS is requested over a plain connection and the
//!    server advertises `STARTTLS`, send `STARTTLS`, upgrade the connection to
//!    TLS, then re-issue `EHLO`. `smtps://` uses *implicit* TLS instead (the
//!    transport is already encrypted before the greeting).
//! 4. **AUTH** — negotiate SASL through the shared [`crate::auth::sasl`] engine
//!    (`AUTH <mech> [ir]`, continuation lines, `*` to cancel).
//! 5. **Send** — `MAIL FROM:<from> [AUTH=..] [SIZE=..] [SMTPUTF8]`, one
//!    `RCPT TO:<rcpt>` per recipient, then `DATA`; upon the `354` go-ahead the
//!    message body is streamed with SMTP **dot-stuffing** and the `\r\n.\r\n`
//!    end-of-body terminator; the final `250` is read in the DONE phase.
//! 6. **Command** — a custom recipient/verb request (`VRFY`, `EXPN`, `NOOP`,
//!    `RSET`, `HELP`) when no message body is being uploaded.
//! 7. **QUIT** — sent on graceful disconnect.
//!
//! # State-name preservation
//!
//! The [`SmtpState`] variants map one-to-one to curl's `smtpstate` enum and
//! [`SmtpState::name`] returns curl's exact trace spellings (`SERVERGREET`,
//! `EHLO`, …) so `--trace` diagnostics remain identical (AAP §0.6.3).
//!
//! # Memory safety
//!
//! This module contains **zero** `unsafe` (the crate is `#![forbid(unsafe_code)]`).
//! All buffers are owned `Vec`/`String`; TLS is layered by the
//! [`crate::conn`] filter chain (backed by [`crate::tls`]) rather than by any C
//! library.
//!
//! # Relationship to the transfer/multi driver
//!
//! curl reaches the pingpong buffer and the download sink directly through the
//! easy handle (`Curl_pp_sendf`, `Curl_client_write`). The Rust
//! [`PingPongProtocol`] contract instead hands the engine (`pp`) and
//! [`Connection`] to the protocol as *separate* borrows, and the
//! [`SaslProto`] hooks receive only `&mut self`. To bridge that boundary
//! without any aliasing, out-of-band I/O is *staged* on [`SmtpConn`]:
//! [`SmtpConn::take_recv_body`] carries `CLIENTWRITE_BODY` bytes, and the SASL
//! send/receive is staged internally and flushed to `pp` by the response
//! handlers. The forthcoming [`crate::transfer`]/[`crate::multi`] driver drains
//! these, exactly as curl's generic transfer loop does.

use std::mem;
use std::time::Instant;

use crate::auth::sasl::{
    decode_mech, Sasl, SaslCredentials, SaslProgress, SaslProto, SASL_AUTH_DEFAULT, SASL_AUTH_NONE,
    SASL_FLAG_BASE64,
};
use crate::conn::{Connection, FIRSTSOCKET};
use crate::error::{CurlCode, Error, Result};
use crate::pp_sendf;
use crate::protocols::pingpong::{PingPong, PingPongProtocol, PpTransfer};
use crate::protocols::{Pollset, ProtoFuture, Protocol, TransferCtx};

// ===========================================================================
// Constants (← the `#define`s and the `saslsmtp` table in `lib/smtp.c`).
// ===========================================================================

/// The 5-byte SMTP End-Of-Body marker (← `#define SMTP_EOB "\r\n.\r\n"`).
///
/// A message body is terminated on the wire by a line containing a single dot;
/// combined with the CRLF framing this is the five bytes `\r\n.\r\n`.
const SMTP_EOB: &[u8] = b"\r\n.\r\n";

/// Length of the EOB *prefix* (`"\r\n."`) whose match arms dot-stuffing
/// (← `#define SMTP_EOB_FIND_LEN 3`).
const SMTP_EOB_FIND_LEN: usize = 3;

/// Maximum SASL initial-response length for SMTP
/// (← `512 - 8` in `saslsmtp`: the max line length minus `strlen("AUTH ")`,
/// the separating space and the trailing CRLF).
const SMTP_SASL_MAX_IR_LEN: usize = 512 - 8;

/// The status code that signals a SASL continuation is expected
/// (← `334` in `saslsmtp`).
const SMTP_SASL_CONT_CODE: i32 = 334;

/// The status code received upon SASL authentication success
/// (← `235` in `saslsmtp`).
const SMTP_SASL_FINAL_CODE: i32 = 235;

// ===========================================================================
// UseSsl — the requested TLS level (← `curl_usessl` / `CURLUSESSL_*`).
// ===========================================================================

/// How aggressively TLS should be negotiated for a plaintext SMTP connection
/// (← `curl_usessl`, `include/curl/curl.h`).
///
/// This mirrors curl's `data->set.use_ssl` and drives the STARTTLS decision in
/// [`SmtpConn::ehlo_resp`] / [`SmtpConn::starttls_resp`]: `Try` downgrades
/// gracefully to a plaintext session when STARTTLS is unavailable, while
/// `Control`/`All` fail with [`CurlCode::UseSslFailed`].
///
/// The variant order matches the `CURLUSESSL_*` integer values (`NONE` = 0,
/// `TRY` = 1, `CONTROL` = 2, `ALL` = 3), so the derived [`Ord`] reproduces
/// curl's `data->set.use_ssl <= CURLUSESSL_TRY` comparison exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum UseSsl {
    /// Do not attempt TLS (← `CURLUSESSL_NONE`).
    #[default]
    None,
    /// Try TLS, but continue in plaintext if it is unavailable
    /// (← `CURLUSESSL_TRY`).
    Try,
    /// Require TLS for the control channel (← `CURLUSESSL_CONTROL`).
    Control,
    /// Require TLS for all communication (← `CURLUSESSL_ALL`).
    All,
}

// ===========================================================================
// SmtpState — the SMTP state machine (← `smtpstate`, verbatim names).
// ===========================================================================

/// The SMTP connection's state-machine position (← `smtpstate`, `lib/smtp.c`).
///
/// The variants and [`name`](SmtpState::name) spellings are preserved
/// one-to-one from curl so that `--trace` output ("state change from … to …")
/// is byte-identical. [`Last`](SmtpState::Last) is the never-used sentinel
/// (← `SMTP_LAST`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SmtpState {
    /// Do-nothing state; stops the state machine (← `SMTP_STOP`).
    #[default]
    Stop,
    /// Waiting for the initial greeting right after connecting
    /// (← `SMTP_SERVERGREET`).
    ServerGreet,
    /// `EHLO` sent, awaiting the ESMTP capability reply (← `SMTP_EHLO`).
    Ehlo,
    /// `HELO` sent (EHLO fallback), awaiting the reply (← `SMTP_HELO`).
    Helo,
    /// `STARTTLS` sent, awaiting the go-ahead (← `SMTP_STARTTLS`).
    StartTls,
    /// Asynchronously upgrading the connection to TLS (← `SMTP_UPGRADETLS`).
    UpgradeTls,
    /// SASL `AUTH` exchange in progress (← `SMTP_AUTH`).
    Auth,
    /// A custom command (`VRFY`/`EXPN`/`NOOP`/`RSET`/`HELP`) is in flight
    /// (← `SMTP_COMMAND`).
    Command,
    /// `MAIL FROM` sent (← `SMTP_MAIL`).
    Mail,
    /// `RCPT TO` sent (← `SMTP_RCPT`).
    Rcpt,
    /// `DATA` sent, awaiting the `354` go-ahead (← `SMTP_DATA`).
    Data,
    /// Body sent; awaiting the final `250` after the end-of-body dot
    /// (← `SMTP_POSTDATA`).
    Postdata,
    /// `QUIT` sent (← `SMTP_QUIT`).
    Quit,
    /// Never-used sentinel (← `SMTP_LAST`).
    Last,
}

impl SmtpState {
    /// curl's exact trace spelling for this state (← the `names[]` table in
    /// `smtp_state`, `lib/smtp.c`).
    ///
    /// [`Last`](SmtpState::Last) has no C spelling (the table stops before it);
    /// it maps to `"LAST"` here purely for completeness and never appears in
    /// trace output.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            SmtpState::Stop => "STOP",
            SmtpState::ServerGreet => "SERVERGREET",
            SmtpState::Ehlo => "EHLO",
            SmtpState::Helo => "HELO",
            SmtpState::StartTls => "STARTTLS",
            SmtpState::UpgradeTls => "UPGRADETLS",
            SmtpState::Auth => "AUTH",
            SmtpState::Command => "COMMAND",
            SmtpState::Mail => "MAIL",
            SmtpState::Rcpt => "RCPT",
            SmtpState::Data => "DATA",
            SmtpState::Postdata => "POSTDATA",
            SmtpState::Quit => "QUIT",
            SmtpState::Last => "LAST",
        }
    }
}

// ===========================================================================
// Pure helpers (← `Curl_is_ASCII_name`, `smtp_parse_address`, `cr_eob_read`).
// ===========================================================================

/// Whether every byte of `name` is 7-bit ASCII (← `Curl_is_ASCII_name`).
///
/// Used to decide whether the `SMTPUTF8` envelope flag must be advertised for
/// a mailbox (RFC 6531 §3.1): a non-ASCII local part or hostname requires it.
#[must_use]
fn is_ascii_name(name: &str) -> bool {
    name.bytes().all(|b| b < 0x80)
}

/// A mailbox address parsed into its local part, optional hostname and any
/// trailing suffix (← the out-parameters of `smtp_parse_address`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct MailAddress {
    /// The local address part (everything before `@`, or the whole mailbox
    /// when there is no `@`).
    address: String,
    /// The hostname (everything after `@`), or `None` for a local mailbox
    /// with no `@` separator.
    host: Option<String>,
    /// Text following the closing `>` of an angle-bracketed mailbox
    /// (e.g. RFC 3461 `NOTIFY=` parameters), or empty.
    suffix: String,
}

/// Parse a fully-qualified mailbox address (← `smtp_parse_address`).
///
/// Reproduces curl's stripping of the optional `<`…`>` delimiters, extraction
/// of the `suffix` that follows a closing `>`, and the split of the local part
/// from the hostname at the first `@`.
///
/// Unlike curl this does **not** perform IDN ACE conversion of the hostname:
/// the IDN converter (`Curl_idnconvert_hostname`) is not part of this module's
/// dependency surface, and curl itself treats ACE conversion as best-effort —
/// on failure it "shall attempt to continue and send the hostname using UTF-8"
/// as a U-label (RFC 6531 §3.2). Emitting the hostname unchanged is therefore
/// the documented fallback path and preserves the wire bytes for the common
/// ASCII case exactly.
fn parse_address(fqma: &str) -> MailAddress {
    // Duplicate without a leading '<' (← `curlx_strdup(fqma[0]=='<' ? fqma+1 : fqma)`).
    let angled = fqma.starts_with('<');
    let mut dup = if angled { &fqma[1..] } else { fqma };
    let mut suffix = String::new();

    if !angled {
        // Not angle-bracketed: drop a single trailing '>' if present.
        if let Some(stripped) = dup.strip_suffix('>') {
            dup = stripped;
        }
    } else if let Some(pos) = dup.rfind('>') {
        // Angle-bracketed: split at the last '>'; everything after is suffix.
        suffix = dup[pos + 1..].to_string();
        dup = &dup[..pos];
    }

    // Extract the hostname after the first '@' (← `strpbrk(dup, "@")`).
    if let Some(at) = dup.find('@') {
        MailAddress {
            address: dup[..at].to_string(),
            host: Some(dup[at + 1..].to_string()),
            suffix,
        }
    } else {
        MailAddress {
            address: dup.to_string(),
            host: None,
            suffix,
        }
    }
}

/// Apply SMTP dot-stuffing to a message body and append the end-of-body
/// terminator (← the whole of `cr_eob_read`, `lib/smtp.c`).
///
/// This is wire-critical and reproduces curl's `cr_eob` client-reader byte for
/// byte:
///
/// * A dot at the *start of a line* is escaped by doubling it (`.` → `..`).
///   The scan starts with `n_eob = 2` — as if a `\r\n` had just been read — so
///   a leading dot on the very first line is escaped as well.
/// * The body is terminated with `\r\n.\r\n`. When the body already ends in
///   `\r\n` only `.\r\n` is appended; when it ends in `\r\n.` the trailing dot
///   is escaped (`.` + `\r\n.\r\n`); an empty body yields `.\r\n`.
///
/// The one-shot form here is byte-identical to curl's streaming reader because
/// the transformation is a deterministic function of the byte sequence.
#[must_use]
fn eob_encode(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + SMTP_EOB.len());
    // "The first char we read is the first on a line, as if we had read CRLF
    // just before" (← `cr_eob_init`: `ctx->n_eob = 2`).
    let mut n_eob: usize = 2;
    let mut start: usize = 0;
    let mut i: usize = 0;

    while i < body.len() {
        if n_eob >= SMTP_EOB_FIND_LEN {
            // Matched the EOB prefix ("\r\n.") and see another char: escape by
            // writing the pending run plus an extra '.'.
            out.extend_from_slice(&body[start..i]);
            out.push(b'.');
            n_eob = 0;
            start = i;
        }

        if body[i] != SMTP_EOB[n_eob] {
            n_eob = 0;
        }
        if body[i] == SMTP_EOB[n_eob] {
            n_eob += 1;
        }
        i += 1;
    }

    // Any remainder after the last escape point.
    if start < body.len() {
        out.extend_from_slice(&body[start..]);
    }

    // Auto-terminate the body (← the `switch(ctx->n_eob)` at EOS).
    match n_eob {
        2 => out.extend_from_slice(&SMTP_EOB[2..]), // ends in "\r\n": add ".\r\n"
        3 => {
            // ended with "\r\n.": escape the last '.' (`"." SMTP_EOB`).
            out.push(b'.');
            out.extend_from_slice(SMTP_EOB);
        }
        _ => out.extend_from_slice(SMTP_EOB), // add full "\r\n.\r\n"
    }

    out
}

/// Extract the SASL data line from a raw SMTP response line
/// (← `smtp_get_message`).
///
/// `line` is the final response line (with its trailing CRLF), i.e. exactly
/// what [`PingPong::response_line`] returns. curl skips the four-byte status
/// prefix (`NNN` + separator), trims leading blanks, then trims trailing
/// newline/blank characters. A line of four bytes or fewer yields an empty
/// message.
#[must_use]
fn extract_sasl_message(line: &[u8]) -> Vec<u8> {
    if line.len() > 4 {
        // Skip the "NNN<sep>" prefix (← `message += 4; len -= 4;`).
        let mut msg = &line[4..];
        // Trim leading blanks (space/tab) (← the `for(; ISBLANK(*message); …)`).
        while let Some((&first, rest)) = msg.split_first() {
            if first == b' ' || first == b'\t' {
                msg = rest;
            } else {
                break;
            }
        }
        // Trim trailing newline/blank (← the `while(len--) if(!ISNEWLINE && !ISBLANK)`).
        let mut end = msg.len();
        while end > 0 {
            let c = msg[end - 1];
            if c == b'\r' || c == b'\n' || c == b' ' || c == b'\t' {
                end -= 1;
            } else {
                break;
            }
        }
        msg[..end].to_vec()
    } else {
        Vec::new()
    }
}

// ===========================================================================
// SmtpOptions — the per-transfer settings SMTP reads from the easy handle.
// ===========================================================================

/// The subset of easy-handle settings the SMTP handler consumes, gathered into
/// an owned bundle (analogous to [`crate::auth::sasl::SaslCredentials`]).
///
/// curl reads these straight off `data->set` / `data->state`; because the
/// owning transfer/easy layer (`crate::multi`) is not yet wired to this module,
/// the driver populates this struct and hands it to [`SmtpConn`]. Every field
/// maps to a specific curl setting, annotated below.
#[derive(Debug, Clone, Default)]
pub struct SmtpOptions {
    /// Envelope sender for `MAIL FROM` (← `data->set.str[STRING_MAIL_FROM]`);
    /// `None` sends the null reverse-path `<>`.
    pub mail_from: Option<String>,
    /// Optional `AUTH=` mailbox for `MAIL FROM`
    /// (← `data->set.str[STRING_MAIL_AUTH]`).
    pub mail_auth: Option<String>,
    /// Custom request verb (← `data->set.str[STRING_CUSTOMREQUEST]`), e.g.
    /// `VRFY`, `EXPN`, `NOOP`, `RSET`, `HELP`.
    pub custom_request: Option<String>,
    /// Recipient mailboxes for `RCPT TO` / a recipient-bearing command
    /// (← `data->set.mail_rcpt`).
    pub mail_rcpt: Vec<String>,
    /// Requested TLS level (← `data->set.use_ssl`).
    pub use_ssl: UseSsl,
    /// Whether individual failed `RCPT TO` recipients may be ignored
    /// (← `data->set.mail_rcpt_allowfails`).
    pub mail_rcpt_allowfails: bool,
    /// Size of the upload body in bytes, or `-1` when unknown
    /// (← `data->state.infilesize`).
    pub infilesize: i64,
    /// Whether the request wants no body (← `data->req.no_body`).
    pub no_body: bool,
    /// Whether an upload is in progress (← `data->state.upload`).
    pub upload: bool,
    /// Whether this is a MIME post (← `IS_MIME_POST(data)`).
    pub mime_post: bool,
    /// Whether the handle is in connect-only mode (← `data->set.connect_only`).
    pub connect_only: bool,
    /// SASL login user (← `conn->user`).
    pub user: String,
    /// SASL login password (← `conn->passwd`).
    pub passwd: String,
    /// SASL authorization identity (← `conn->sasl_authzid`).
    pub authzid: Option<String>,
    /// OAuth 2.0 bearer token (← `data->set.str[STRING_BEARER]`).
    pub bearer: Option<String>,
    /// SASL service-name override (← `data->set.str[STRING_SERVICE_NAME]`).
    pub service_name: Option<String>,
    /// Connection host name, for SASL host binding (← `conn->host.name`).
    pub host: String,
    /// Connection port, for SASL binding (← `conn->port`).
    pub port: i64,
    /// Whether an initial SASL response is permitted (← `data->set.sasl_ir`).
    pub sasl_ir: bool,
}

// ===========================================================================
// Smtp — the per-transfer state (← `struct SMTP`, `lib/smtp.c`).
// ===========================================================================

/// Per-transfer SMTP state (← `struct SMTP`).
///
/// curl keeps this on the easy handle (separate from the per-connection
/// [`smtp_conn`](SmtpConn)) so a reused connection can serve different
/// transfers. Field roles are preserved verbatim; the recipient *cursor* is a
/// [`Vec`] index ([`rcpt_index`](Smtp::rcpt_index)) rather than curl's
/// advancing `struct curl_slist *` pointer, which is the idiomatic Rust
/// equivalent of `smtp->rcpt = smtp->rcpt->next`.
#[derive(Debug, Clone)]
pub struct Smtp {
    /// Whether/what to transfer for this request (← `transfer`).
    pub transfer: PpTransfer,
    /// The decoded custom request, if any (← `custom`).
    pub custom: Option<String>,
    /// The recipient mailbox list (← `rcpt`, a `curl_slist`).
    pub rcpt: Vec<String>,
    /// The cursor into [`rcpt`](Smtp::rcpt) (← curl's advancing `rcpt` pointer).
    pub rcpt_index: usize,
    /// The last error code received for a `RCPT TO` (← `rcpt_last_error`).
    pub rcpt_last_error: i32,
    /// Number of end-of-body bytes seen so far (← `eob`). Set to `2` at the
    /// start of a transfer (an implicit leading CRLF); preserved for parity
    /// with curl, where it is likewise vestigial in the current reader.
    pub eob: usize,
    /// Whether at least one `RCPT TO` has succeeded (← `rcpt_had_ok`).
    pub rcpt_had_ok: bool,
    /// Whether the message ends with a trailing CRLF (← `trailing_crlf`).
    pub trailing_crlf: bool,
}

impl Default for Smtp {
    fn default() -> Self {
        // Mirrors a zero-initialised `struct SMTP` with `transfer` defaulting to
        // the "transfer a body" mode curl resets it to.
        Smtp {
            transfer: PpTransfer::Body,
            custom: None,
            rcpt: Vec::new(),
            rcpt_index: 0,
            rcpt_last_error: 0,
            eob: 0,
            rcpt_had_ok: false,
            trailing_crlf: false,
        }
    }
}

impl Smtp {
    /// The recipient the cursor currently points at, or `None` past the end
    /// (← dereferencing `smtp->rcpt`).
    #[must_use]
    fn current_rcpt(&self) -> Option<&str> {
        self.rcpt.get(self.rcpt_index).map(String::as_str)
    }

    /// Advance the recipient cursor (← `smtp->rcpt = smtp->rcpt->next`).
    fn advance_rcpt(&mut self) {
        self.rcpt_index += 1;
    }

    /// Whether there is a recipient at (or after) the cursor
    /// (← the truthiness of `smtp->rcpt`).
    #[must_use]
    fn has_rcpt(&self) -> bool {
        self.rcpt_index < self.rcpt.len()
    }
}

// ===========================================================================
// SmtpConn — the per-connection state and driver (← `struct smtp_conn`).
// ===========================================================================

/// Per-connection SMTP state and the state-machine driver (← `struct smtp_conn`).
///
/// Owns the shared [`PingPong`] engine and the [`Sasl`] engine, the current
/// [`SmtpState`], the EHLO-derived capability flags, and the client `domain`
/// sent in EHLO/HELO. It also embeds the per-transfer [`Smtp`] state and the
/// [`SmtpOptions`] the driver supplies, so a single value can drive the whole
/// exchange through the [`PingPongProtocol`] contract (whose `statemachine`
/// receives `pp`/`conn` as borrows separate from the protocol object).
///
/// # Staging fields
///
/// [`sasl_outgoing`](Self::sasl_outgoing) and [`sasl_message`](Self::sasl_message)
/// bridge the [`SaslProto`] hooks (which see only `&mut self`, never `pp`) to
/// the engine: send/continuation/cancel commands are queued into
/// `sasl_outgoing` and flushed to `pp` by the response handlers, and the
/// server's SASL data line is staged into `sasl_message` for
/// [`SaslProto::get_message`]. [`recv_body`](Self::recv_body) captures
/// `CLIENTWRITE_BODY` bytes for the transfer layer to drain.
pub struct SmtpConn {
    /// The shared command/response engine (← `smtp_conn.pp`).
    pp: PingPong,
    /// The SASL engine, held in an [`Option`] so it can be moved out while it
    /// borrows `self` as the [`SaslProto`] during `sasl_start`/`sasl_continue`
    /// (← `smtp_conn.sasl`). It is `Some` at all other times.
    sasl: Option<Sasl>,
    /// Current state-machine position (← `smtp_conn.state`).
    state: SmtpState,
    /// Client address/name sent in EHLO/HELO (← `smtp_conn.domain`).
    domain: String,
    /// Whether the TLS handshake has completed (← `smtp_conn.ssldone`).
    ssldone: bool,
    /// Whether the server advertised STARTTLS (← `smtp_conn.tls_supported`).
    tls_supported: bool,
    /// Whether the server advertised SIZE (← `smtp_conn.size_supported`).
    size_supported: bool,
    /// Whether the server advertised SMTPUTF8 (← `smtp_conn.utf8_supported`).
    utf8_supported: bool,
    /// Whether the server advertised AUTH (← `smtp_conn.auth_supported`).
    auth_supported: bool,
    /// The per-transfer state (curl keeps this on the easy handle; co-located
    /// here for the single-value driver — see the type-level docs).
    smtp: Smtp,
    /// The per-transfer settings supplied by the driver.
    options: SmtpOptions,
    /// SASL commands queued by the [`SaslProto`] hooks, flushed to `pp` by the
    /// response handlers (staging — see the type-level docs).
    sasl_outgoing: Vec<String>,
    /// The server's SASL data line, staged for [`SaslProto::get_message`].
    sasl_message: Vec<u8>,
    /// `CLIENTWRITE_BODY` bytes captured from command responses, for the
    /// transfer layer to drain (← `Curl_client_write(…, CLIENTWRITE_BODY, …)`).
    recv_body: Vec<u8>,
    /// Latest server status code, stored for the transfer layer to expose as
    /// `response_code` (← `data->info.httpcode = smtpcode`). Updated in the
    /// state machine for every response except while quitting and for SASL
    /// continuation lines (`code == 1`).
    response_code: i32,
}

impl SmtpConn {
    /// Create a fresh SMTP connection driver for `domain` with the given
    /// per-transfer `options` (← the state set up across `smtp_setup_connection`
    /// and `smtp_connect`).
    ///
    /// The [`Sasl`] engine is initialised with SMTP's default mechanisms. The
    /// [`PingPong`] engine is left in its freshly-constructed state (its
    /// response window is already meaningful); [`connect`](SmtpConn::connect)
    /// performs the single `Curl_pp_init` — mirroring curl, where the zeroed
    /// `struct smtp_conn` is set up in `smtp_setup_connection` and the pingpong
    /// buffers are initialised later in `smtp_connect`. The initial state is
    /// [`SmtpState::Stop`]; `connect` moves it to [`SmtpState::ServerGreet`].
    #[must_use]
    pub fn new(domain: impl Into<String>, options: SmtpOptions) -> Self {
        let pp = PingPong::new();
        SmtpConn {
            pp,
            // SMTP passes `SASL_AUTH_DEFAULT` for the default mechanisms; the
            // HTTP-auth mask is unused by SMTP (there is no HTTP negotiation).
            sasl: Some(Sasl::init(SASL_AUTH_DEFAULT, 0)),
            state: SmtpState::Stop,
            domain: domain.into(),
            ssldone: false,
            tls_supported: false,
            size_supported: false,
            utf8_supported: false,
            auth_supported: false,
            smtp: Smtp::default(),
            options,
            sasl_outgoing: Vec::new(),
            sasl_message: Vec::new(),
            recv_body: Vec::new(),
            response_code: 0,
        }
    }

    /// Change state (← `smtp_state`, the *only* way to change state).
    ///
    /// Logs curl's exact trace string on a real transition so `--trace` output
    /// is preserved verbatim.
    fn set_state(&mut self, newstate: SmtpState) {
        if self.state != newstate {
            tracing::trace!(
                "state change from {} to {}",
                self.state.name(),
                newstate.name()
            );
        }
        self.state = newstate;
    }

    /// The current state-machine position.
    #[must_use]
    pub fn state(&self) -> SmtpState {
        self.state
    }

    /// Whether the state machine has stopped (← `state == SMTP_STOP`), i.e. the
    /// current connect/DO/DONE phase is complete.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.state == SmtpState::Stop
    }

    /// The transfer mode selected for this request (← `smtp->transfer`).
    #[must_use]
    pub fn transfer(&self) -> PpTransfer {
        self.smtp.transfer
    }

    /// The latest server status code, for the transfer layer to surface as
    /// `response_code` (← `data->info.httpcode`).
    #[must_use]
    pub fn response_code(&self) -> i32 {
        self.response_code
    }

    /// The number of end-of-body bytes tracked for this transfer
    /// (← `smtp->eob`); preserved for parity (see [`Smtp::eob`]).
    #[must_use]
    pub fn eob(&self) -> usize {
        self.smtp.eob
    }

    /// Whether the transfer's trailing CRLF is present (← `smtp->trailing_crlf`).
    #[must_use]
    pub fn trailing_crlf(&self) -> bool {
        self.smtp.trailing_crlf
    }

    /// Take the buffered `CLIENTWRITE_BODY` bytes captured from command
    /// responses, leaving the buffer empty (drained by the transfer layer).
    #[must_use]
    pub fn take_recv_body(&mut self) -> Vec<u8> {
        mem::take(&mut self.recv_body)
    }

    /// Encode a message body for the `DATA` phase with dot-stuffing and the
    /// end-of-body terminator (← the `cr_eob` client reader). Exposed so the
    /// transfer layer can stream the upload exactly as curl does.
    #[must_use]
    pub fn encode_body(&self, body: &[u8]) -> Vec<u8> {
        eob_encode(body)
    }

    // -----------------------------------------------------------------------
    // Command builders (← the `smtp_perform_*` functions). Each formats and
    // queues one command through `pp` and advances `state`.
    // -----------------------------------------------------------------------

    /// Send `EHLO <domain>` and reset the ESMTP capability flags
    /// (← `smtp_perform_ehlo`).
    fn perform_ehlo(&mut self, pp: &mut PingPong) -> Result<()> {
        // Clear known auth mechanisms and capabilities before the fresh EHLO.
        if let Some(sasl) = self.sasl.as_mut() {
            sasl.set_authmechs(SASL_AUTH_NONE);
        }
        self.tls_supported = false;
        self.auth_supported = false;

        pp_sendf!(pp, "EHLO {}", self.domain)?;
        self.set_state(SmtpState::Ehlo);
        Ok(())
    }

    /// Send `HELO <domain>` (the EHLO fallback) (← `smtp_perform_helo`).
    fn perform_helo(&mut self, pp: &mut PingPong) -> Result<()> {
        pp_sendf!(pp, "HELO {}", self.domain)?;
        self.set_state(SmtpState::Helo);
        Ok(())
    }

    /// Send `STARTTLS` to begin the TLS upgrade (← `smtp_perform_starttls`).
    fn perform_starttls(&mut self, pp: &mut PingPong) -> Result<()> {
        pp_sendf!(pp, "STARTTLS")?;
        self.set_state(SmtpState::StartTls);
        Ok(())
    }

    /// Send `QUIT` (← `smtp_perform_quit`).
    fn perform_quit(&mut self, pp: &mut PingPong) -> Result<()> {
        pp_sendf!(pp, "QUIT")?;
        self.set_state(SmtpState::Quit);
        Ok(())
    }

    /// Build the owned [`SaslCredentials`] for the SASL engine from
    /// [`options`](Self::options) (← the `conn`/`data` fields curl reads).
    fn sasl_credentials(&self) -> SaslCredentials {
        SaslCredentials {
            user: self.options.user.clone(),
            passwd: self.options.passwd.clone(),
            authzid: self.options.authzid.clone(),
            bearer: self.options.bearer.clone(),
            service_name: self.options.service_name.clone(),
            host: self.options.host.clone(),
            port: self.options.port,
            sasl_ir: self.options.sasl_ir,
        }
    }

    /// Flush any SASL commands the [`SaslProto`] hooks queued into `pp`
    /// (CRLF is appended by [`PingPong::sendf`]). SASL payloads are base64
    /// (7-bit ASCII), so the staged `String`s reproduce the wire bytes exactly.
    fn flush_sasl_outgoing(&mut self, pp: &mut PingPong) -> Result<()> {
        for cmd in self.sasl_outgoing.drain(..) {
            pp_sendf!(pp, "{}", cmd)?;
        }
        Ok(())
    }

    /// Begin SASL authentication with the best mutually-supported mechanism
    /// (← `smtp_perform_authentication`).
    ///
    /// Ends the connect phase (state → [`SmtpState::Stop`]) when the server
    /// advertised no AUTH capability or there are no usable credentials.
    /// Otherwise it starts the SASL exchange: on progress it moves to
    /// [`SmtpState::Auth`] and flushes the initial `AUTH` command; if the
    /// engine cannot proceed it returns the engine's blocking error
    /// (typically [`CurlCode::LoginDenied`]).
    fn perform_authentication(&mut self, pp: &mut PingPong) -> Result<()> {
        let creds = self.sasl_credentials();

        // Not enough to authenticate, or the server has no AUTH: end connect.
        let can = self
            .sasl
            .as_ref()
            .is_some_and(|s| s.can_authenticate(&creds));
        if !self.auth_supported || !can {
            self.set_state(SmtpState::Stop);
            return Ok(());
        }

        // Drive `sasl_start` with `self` as the `SaslProto`: move the engine out
        // so it does not alias the `&mut self` it is handed (restored after).
        let mut sasl = self.sasl.take().ok_or(Error::Code(CurlCode::FailedInit))?;
        let progress = sasl.sasl_start(self, &creds, false);
        self.sasl = Some(sasl);
        let progress = progress?;

        match progress {
            SaslProgress::InProgress => {
                self.flush_sasl_outgoing(pp)?;
                self.set_state(SmtpState::Auth);
                Ok(())
            }
            // Idle/Done without progress: the engine is blocked (no mechanism).
            _ => Err(self
                .sasl
                .as_ref()
                .map_or(Error::Code(CurlCode::LoginDenied), |s| s.is_blocked(&creds))),
        }
    }

    /// Send a custom command — recipient-bearing (`VRFY`/`EXPN`) or bare
    /// (`NOOP`/`RSET`/`HELP`) (← `smtp_perform_command`).
    fn perform_command(&mut self, pp: &mut PingPong) -> Result<()> {
        if let Some(rcpt) = self.smtp.current_rcpt() {
            let rcpt = rcpt.to_string();
            let custom_empty = self.smtp.custom.as_deref().map_or(true, |c| c.is_empty());

            if custom_empty {
                // Default recipient command is VRFY, on the parsed mailbox.
                let parsed = parse_address(&rcpt);
                // SMTPUTF8 iff the server supports it and the mailbox is UTF-8.
                let utf8 = self.utf8_supported
                    && (!is_ascii_name(&parsed.address)
                        || parsed.host.as_deref().is_some_and(|h| !is_ascii_name(h)));
                let host_part = match parsed.host.as_deref() {
                    Some(h) => format!("@{h}"),
                    None => String::new(),
                };
                pp_sendf!(
                    pp,
                    "VRFY {}{}{}{}",
                    parsed.address,
                    host_part,
                    parsed.suffix,
                    if utf8 { " SMTPUTF8" } else { "" }
                )?;
            } else {
                let custom = self.smtp.custom.clone().unwrap_or_default();
                // SMTPUTF8 for EXPN only (curl reports it just for EXPN here),
                // and only when the server supports it.
                let utf8 = self.utf8_supported && custom == "EXPN";
                pp_sendf!(
                    pp,
                    "{} {}{}",
                    custom,
                    rcpt,
                    if utf8 { " SMTPUTF8" } else { "" }
                )?;
            }
        } else {
            // Non-recipient command such as HELP.
            let cmd = match self.smtp.custom.as_deref() {
                Some(c) if !c.is_empty() => c.to_string(),
                _ => "HELP".to_string(),
            };
            pp_sendf!(pp, "{}", cmd)?;
        }

        self.set_state(SmtpState::Command);
        Ok(())
    }

    /// Send `MAIL FROM:<from> [AUTH=..] [SIZE=..] [SMTPUTF8]`
    /// (← `smtp_perform_mail`).
    ///
    /// Reproduces curl's construction exactly: the reverse-path (or `<>` when
    /// no sender is set), an optional `AUTH=` mailbox (only when `MAIL_AUTH` is
    /// set *and* a mechanism was used), an optional `SIZE=` (only when the
    /// server supports SIZE and the upload size is known and positive), and the
    /// `SMTPUTF8` envelope flag when any of FROM/AUTH/recipients is non-ASCII.
    fn perform_mail(&mut self, pp: &mut PingPong) -> Result<()> {
        let mut utf8 = false;

        // --- FROM (mandatory) -------------------------------------------------
        let from = if let Some(mf) = self.options.mail_from.clone() {
            let p = parse_address(&mf);
            utf8 = self.utf8_supported
                && (!is_ascii_name(&p.address)
                    || p.host.as_deref().is_some_and(|h| !is_ascii_name(h)));
            match p.host.as_deref() {
                Some(h) => format!("<{}@{}>{}", p.address, h, p.suffix),
                // Invalid mailbox: let the server reply 501, as curl does.
                None => format!("<{}>{}", p.address, p.suffix),
            }
        } else {
            // Null reverse-path (RFC 5321 §3.6.3).
            "<>".to_string()
        };

        // --- optional AUTH= ---------------------------------------------------
        let auth_used = self.sasl.as_ref().is_some_and(|s| s.authused() != 0);
        let auth = match (&self.options.mail_auth, auth_used) {
            (Some(ma), true) => Some(if ma.is_empty() {
                // Empty AUTH (RFC 2554 §5).
                "<>".to_string()
            } else {
                let p = parse_address(ma);
                if !utf8
                    && self.utf8_supported
                    && (!is_ascii_name(&p.address)
                        || p.host.as_deref().is_some_and(|h| !is_ascii_name(h)))
                {
                    utf8 = true;
                }
                match p.host.as_deref() {
                    Some(h) => format!("<{}@{}>{}", p.address, h, p.suffix),
                    None => format!("<{}>{}", p.address, p.suffix),
                }
            }),
            _ => None,
        };

        // --- optional SIZE= ---------------------------------------------------
        let size = if self.size_supported && self.options.infilesize > 0 {
            Some(self.options.infilesize)
        } else {
            None
        };

        // If FROM/AUTH were ASCII, scan the recipients for a UTF-8 mailbox so
        // the envelope's SMTPUTF8 flag is correct (RFC 6531 §3.4).
        if self.utf8_supported && !utf8 {
            utf8 = self.smtp.rcpt.iter().any(|r| !is_ascii_name(r));
        }

        // curl records the initial EOB state here (implicit leading CRLF); the
        // dot-stuffing itself is applied by [`eob_encode`] on the body stream.
        self.smtp.eob = 2;
        self.smtp.trailing_crlf = true;

        pp_sendf!(
            pp,
            "MAIL FROM:{}{}{}{}{}{}",
            from,
            if auth.is_some() { " AUTH=" } else { "" },
            auth.as_deref().unwrap_or(""),
            if size.is_some() { " SIZE=" } else { "" },
            size.map(|s| s.to_string()).unwrap_or_default(),
            if utf8 { " SMTPUTF8" } else { "" }
        )?;
        self.set_state(SmtpState::Mail);
        Ok(())
    }

    /// Send `RCPT TO:<rcpt>` for the recipient at the cursor
    /// (← `smtp_perform_rcpt_to`).
    fn perform_rcpt_to(&mut self, pp: &mut PingPong) -> Result<()> {
        let rcpt = self
            .smtp
            .current_rcpt()
            .ok_or(Error::Code(CurlCode::FailedInit))?
            .to_string();
        let p = parse_address(&rcpt);
        match p.host.as_deref() {
            Some(h) => pp_sendf!(pp, "RCPT TO:<{}@{}>{}", p.address, h, p.suffix)?,
            // Invalid mailbox: let the server reply 501, as curl does.
            None => pp_sendf!(pp, "RCPT TO:<{}>{}", p.address, p.suffix)?,
        }
        self.set_state(SmtpState::Rcpt);
        Ok(())
    }

    /// Perform the asynchronous TLS upgrade after a `220` STARTTLS reply
    /// (← `smtp_perform_upgrade_tls`).
    ///
    /// The actual insertion of the TLS filter into the connection's filter
    /// chain is a connection-layer concern — in curl it is `Curl_ssl_cfilter_add`
    /// from the vtls subsystem, *not* SMTP code. Here that delegation is
    /// expressed by flagging [`upgrade_in_progress`](crate::conn) and driving
    /// [`Connection::connect`], which composes the TLS filter and performs the
    /// handshake. Once the handshake completes, `ssldone` is recorded and a
    /// fresh `EHLO` is issued (moving the state out of
    /// [`SmtpState::UpgradeTls`]); until then the state is left unchanged so the
    /// engine re-enters here on the next poll.
    async fn perform_upgrade_tls(
        &mut self,
        pp: &mut PingPong,
        conn: &mut Connection,
    ) -> Result<()> {
        debug_assert_eq!(self.state, SmtpState::UpgradeTls);

        // Not yet secured: request the TLS upgrade (← `Curl_ssl_cfilter_add`
        // plus `conn->scheme = &Curl_scheme_smtps`). The connection layer owns
        // filter composition; this flag is the SMTP-side signal for it.
        if !conn.is_ssl(FIRSTSOCKET) {
            conn.bits.upgrade_in_progress = true;
        }

        // Drive the (non-blocking) connect; `true` means the handshake finished.
        let ssldone = conn.connect(FIRSTSOCKET, false).await?;
        if ssldone {
            self.ssldone = true;
            conn.bits.upgrade_in_progress = false;
            // Re-EHLO over the secured channel; this leaves SMTP_UPGRADETLS.
            self.perform_ehlo(pp)?;
        }
        Ok(())
    }

    /// Parse one EHLO capability line (already past the `NNN-`/`NNN ` prefix)
    /// and record the advertised extension (← the capability tests in
    /// `smtp_state_ehlo_resp`).
    ///
    /// Recognises `STARTTLS`, `SIZE`, `SMTPUTF8`, and `AUTH <mechlist>`; for the
    /// last it decodes each whitespace-separated mechanism token via
    /// [`decode_mech`] and folds the recognised bits into the SASL engine's
    /// advertised-mechanism mask.
    fn scan_ehlo_capability(&mut self, cap: &[u8]) {
        if cap.len() >= 8 && cap[..8].eq_ignore_ascii_case(b"STARTTLS") {
            self.tls_supported = true;
        } else if cap.len() >= 4 && cap[..4].eq_ignore_ascii_case(b"SIZE") {
            self.size_supported = true;
        } else if cap.len() >= 8 && cap[..8].eq_ignore_ascii_case(b"SMTPUTF8") {
            self.utf8_supported = true;
        } else if cap.len() >= 5 && cap[..5].eq_ignore_ascii_case(b"AUTH ") {
            self.auth_supported = true;

            // Walk the space/newline-separated mechanism tokens after "AUTH ".
            // `split` yields empty slices for runs of delimiters (curl's
            // `while(ISBLANK||ISNEWLINE)` skip), which are ignored.
            for word in cap[5..].split(|&b| matches!(b, b' ' | b'\t' | b'\r' | b'\n')) {
                if word.is_empty() {
                    continue;
                }
                // A token counts only if it matches a known mechanism in full
                // (← `mechbit && llen == wordlen`).
                if let Some((bit, llen)) = std::str::from_utf8(word).ok().and_then(decode_mech) {
                    if llen == word.len() {
                        if let Some(sasl) = self.sasl.as_mut() {
                            sasl.add_authmech(bit);
                        }
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Per-state response handlers (← the `smtp_state_*_resp` functions). Each
    // consumes the freshly parsed `smtpcode`, may queue the next command via
    // `pp`, and advances `state`.
    // -----------------------------------------------------------------------

    /// Handle the initial server greeting (← `smtp_state_servergreet_resp`).
    fn servergreet_resp(&mut self, pp: &mut PingPong, smtpcode: i32) -> Result<()> {
        if smtpcode / 100 != 2 {
            return Err(Error::with_context(
                CurlCode::WeirdServerReply,
                format!("Got unexpected smtp-server response: {smtpcode}"),
            ));
        }
        self.perform_ehlo(pp)
    }

    /// Handle the `STARTTLS` reply (← `smtp_state_starttls_resp`).
    ///
    /// On `220` the state moves to [`SmtpState::UpgradeTls`] and the caller
    /// re-enters the TLS-upgrade path; otherwise the behaviour depends on
    /// whether TLS was merely *tried* (`CURLUSESSL_TRY` continues in plaintext)
    /// or *required* (fail with [`CurlCode::UseSslFailed`]).
    fn starttls_resp(&mut self, pp: &mut PingPong, smtpcode: i32) -> Result<()> {
        // Pipelining a response after STARTTLS is forbidden (← `pp.overflow`);
        // `moredata()` is the equivalent "bytes buffered past the final line"
        // check when no command is queued.
        if pp.moredata() {
            return Err(Error::Code(CurlCode::WeirdServerReply));
        }

        if smtpcode != 220 {
            if self.options.use_ssl != UseSsl::Try {
                return Err(Error::with_context(
                    CurlCode::UseSslFailed,
                    format!("STARTTLS denied, code {smtpcode}"),
                ));
            }
            // Fallback: carry on with authentication in plaintext.
            self.perform_authentication(pp)
        } else {
            self.set_state(SmtpState::UpgradeTls);
            Ok(())
        }
    }

    /// Handle an EHLO reply line — capability accumulation and the post-EHLO
    /// decision (STARTTLS / auth / HELO fallback) (← `smtp_state_ehlo_resp`).
    ///
    /// `is_ssl` is the connection's current TLS state
    /// (← `Curl_conn_is_ssl(conn, FIRSTSOCKET)`).
    fn ehlo_resp(&mut self, pp: &mut PingPong, is_ssl: bool, smtpcode: i32) -> Result<()> {
        // Copy the response line out so `pp` is free for the command builders
        // below (EHLO lines are short).
        let line = pp.response_line().to_vec();
        let len = line.len();

        if smtpcode / 100 != 2 && smtpcode != 1 {
            // EHLO rejected: fall back to HELO if TLS is not required (or is
            // already up), else deny.
            if self.options.use_ssl <= UseSsl::Try || is_ssl {
                self.perform_helo(pp)
            } else {
                Err(Error::with_context(
                    CurlCode::RemoteAccessDenied,
                    format!("Remote access denied: {smtpcode}"),
                ))
            }
        } else if len >= 4 {
            // Record this capability line (skip the "NNN-"/"NNN " prefix).
            self.scan_ehlo_capability(&line[4..]);

            // Only decide the next step on the *final* EHLO line (`code != 1`).
            if smtpcode != 1 {
                if self.options.use_ssl != UseSsl::None && !is_ssl {
                    // TLS wanted but not yet up.
                    if self.tls_supported {
                        self.perform_starttls(pp)
                    } else if self.options.use_ssl == UseSsl::Try {
                        self.perform_authentication(pp)
                    } else {
                        Err(Error::with_context(
                            CurlCode::UseSslFailed,
                            "STARTTLS not supported.",
                        ))
                    }
                } else {
                    self.perform_authentication(pp)
                }
            } else {
                Ok(())
            }
        } else {
            Err(Error::with_context(
                CurlCode::WeirdServerReply,
                "Unexpectedly short EHLO response",
            ))
        }
    }

    /// Handle a HELO reply (← `smtp_state_helo_resp`).
    fn helo_resp(&mut self, smtpcode: i32) -> Result<()> {
        if smtpcode / 100 != 2 {
            return Err(Error::with_context(
                CurlCode::RemoteAccessDenied,
                format!("Remote access denied: {smtpcode}"),
            ));
        }
        // End of connect phase.
        self.set_state(SmtpState::Stop);
        Ok(())
    }

    /// Handle a SASL authentication reply, driving the SASL engine forward
    /// (← `smtp_state_auth_resp`).
    ///
    /// The server's SASL data line is staged into
    /// [`sasl_message`](Self::sasl_message) for [`SaslProto::get_message`], the
    /// engine is moved out of `self` for the borrow-disjoint continuation, and
    /// any command the engine queued is flushed to `pp` afterwards.
    fn auth_resp(&mut self, pp: &mut PingPong, smtpcode: i32) -> Result<()> {
        // Stage the server's SASL payload for `get_message` (← `smtp_get_message`
        // reading `pp.recvbuf`/`nfinal` during `Curl_sasl_continue`).
        self.sasl_message = extract_sasl_message(pp.response_line());

        let creds = self.sasl_credentials();
        let mut sasl = self.sasl.take().ok_or(Error::Code(CurlCode::FailedInit))?;
        let progress = sasl.sasl_continue(self, &creds, smtpcode);
        self.sasl = Some(sasl);
        let progress = progress?;

        // Flush whatever the continuation/cancel hooks queued (may be nothing).
        self.flush_sasl_outgoing(pp)?;

        match progress {
            SaslProgress::Done => {
                // Authenticated: end of connect phase.
                self.set_state(SmtpState::Stop);
                Ok(())
            }
            SaslProgress::Idle => Err(Error::with_context(
                CurlCode::LoginDenied,
                "Authentication cancelled",
            )),
            SaslProgress::InProgress => Ok(()),
        }
    }

    /// Handle a custom-command reply (`VRFY`/`EXPN`/`NOOP`/…) — write any body,
    /// then advance to the next recipient or stop (← `smtp_state_command_resp`).
    fn command_resp(&mut self, pp: &mut PingPong, smtpcode: i32) -> Result<()> {
        let has_rcpt = self.smtp.has_rcpt();

        // A recipient command tolerates 553 (mailbox name not allowed) besides
        // any 2xx / continuation; a non-recipient command tolerates only those.
        let failed = if has_rcpt {
            smtpcode / 100 != 2 && smtpcode != 553 && smtpcode != 1
        } else {
            smtpcode / 100 != 2 && smtpcode != 1
        };
        if failed {
            return Err(Error::with_context(
                CurlCode::WeirdServerReply,
                format!("Command failed: {smtpcode}"),
            ));
        }

        // Forward the reply text to the client as body (unless suppressed).
        if !self.options.no_body {
            self.recv_body.extend_from_slice(pp.response_line());
        }

        if smtpcode != 1 {
            if has_rcpt {
                self.smtp.advance_rcpt();
                if self.smtp.has_rcpt() {
                    // Send the command for the next recipient.
                    return self.perform_command(pp);
                }
            }
            // End of DO phase.
            self.set_state(SmtpState::Stop);
        }
        Ok(())
    }

    /// Handle a `MAIL FROM` reply — proceed to the first `RCPT TO`
    /// (← `smtp_state_mail_resp`).
    fn mail_resp(&mut self, pp: &mut PingPong, smtpcode: i32) -> Result<()> {
        if smtpcode / 100 != 2 {
            return Err(Error::with_context(
                CurlCode::SendError,
                format!("MAIL failed: {smtpcode}"),
            ));
        }
        self.perform_rcpt_to(pp)
    }

    /// Handle a `RCPT TO` reply — iterate recipients, honouring
    /// `--mail-rcpt-allowfails`, then issue `DATA` (← `smtp_state_rcpt_resp`).
    fn rcpt_resp(&mut self, pp: &mut PingPong, smtpcode: i32) -> Result<()> {
        let is_err = smtpcode / 100 != 2;
        // With allowfails, a failed recipient is non-blocking: skip it and
        // continue with the remaining addresses.
        let is_blocking = is_err && !self.options.mail_rcpt_allowfails;

        if is_err {
            // Remember the last failure to report if *every* RCPT fails.
            self.smtp.rcpt_last_error = smtpcode;
            if is_blocking {
                return Err(Error::with_context(
                    CurlCode::SendError,
                    format!("RCPT failed: {smtpcode}"),
                ));
            }
        } else {
            self.smtp.rcpt_had_ok = true;
        }

        if !is_blocking {
            self.smtp.advance_rcpt();
            if self.smtp.has_rcpt() {
                // Next recipient.
                return self.perform_rcpt_to(pp);
            }
            // All recipients processed.
            if !self.smtp.rcpt_had_ok {
                return Err(Error::with_context(
                    CurlCode::SendError,
                    format!("RCPT failed: {} (last error)", self.smtp.rcpt_last_error),
                ));
            }
            // At least one recipient accepted: send the message body.
            pp_sendf!(pp, "DATA")?;
            self.set_state(SmtpState::Data);
        }
        Ok(())
    }

    /// Handle a `DATA` reply — a `354` go-ahead starts the upload
    /// (← `smtp_state_data_resp`).
    ///
    /// The transfer layer performs the actual send setup (`Curl_xfer_setup_send`
    /// / progress upload size); here the state simply ends the DO phase so the
    /// transfer loop streams the dot-stuffed body (see [`SmtpConn::encode_body`]).
    fn data_resp(&mut self, smtpcode: i32) -> Result<()> {
        if smtpcode != 354 {
            return Err(Error::with_context(
                CurlCode::SendError,
                format!("DATA failed: {smtpcode}"),
            ));
        }
        // End of DO phase; the upload proceeds in the transfer layer.
        self.set_state(SmtpState::Stop);
        Ok(())
    }

    /// Handle the final reply after the message body (← `smtp_state_postdata_resp`).
    fn postdata_resp(&mut self, smtpcode: i32) -> Result<()> {
        let result = if smtpcode != 250 {
            Err(Error::Code(CurlCode::WeirdServerReply))
        } else {
            Ok(())
        };
        // End of DONE phase, regardless of the code (← curl sets STOP either way).
        self.set_state(SmtpState::Stop);
        result
    }

    /// Dispatch a freshly parsed response to the handler for the current state
    /// (← the `switch(smtpc->state)` in `smtp_pp_statemachine`).
    ///
    /// `is_ssl` is threaded through for [`ehlo_resp`](Self::ehlo_resp). The
    /// [`SmtpState::UpgradeTls`] transition itself is *not* handled here — like
    /// curl, the state machine detects it after [`starttls_resp`](Self::starttls_resp)
    /// and re-enters the TLS-upgrade path (see [`PingPongProtocol::statemachine`]).
    fn handle_response(&mut self, pp: &mut PingPong, is_ssl: bool, smtpcode: i32) -> Result<()> {
        match self.state {
            SmtpState::ServerGreet => self.servergreet_resp(pp, smtpcode),
            SmtpState::Ehlo => self.ehlo_resp(pp, is_ssl, smtpcode),
            SmtpState::Helo => self.helo_resp(smtpcode),
            SmtpState::StartTls => self.starttls_resp(pp, smtpcode),
            SmtpState::Auth => self.auth_resp(pp, smtpcode),
            SmtpState::Command => self.command_resp(pp, smtpcode),
            SmtpState::Mail => self.mail_resp(pp, smtpcode),
            SmtpState::Rcpt => self.rcpt_resp(pp, smtpcode),
            SmtpState::Data => self.data_resp(smtpcode),
            SmtpState::Postdata => self.postdata_resp(smtpcode),
            // SMTP_QUIT and any unexpected state: internal error, just stop
            // (← the `default` arm of the C switch).
            _ => {
                self.set_state(SmtpState::Stop);
                Ok(())
            }
        }
    }
}

// ===========================================================================
// PingPongProtocol — response framing and the readresp loop (← smtp_endofresp
// and smtp_pp_statemachine).
// ===========================================================================

impl PingPongProtocol for SmtpConn {
    /// Decide whether `line` ends an SMTP response and, if so, parse its status
    /// code (← `smtp_endofresp`).
    ///
    /// SMTP shares FTP's convention: a three-digit code followed by a space
    /// (`NNN `), or a bare `NNN\r\n` five-byte line, is the final line; a code
    /// followed by `-` (`NNN-`) is a continuation, but only while awaiting a
    /// multi-line reply (EHLO or a custom COMMAND). The internal sentinel `1`
    /// is used for continuation lines, so a genuine `001` from the server is
    /// remapped to `0` exactly as curl does.
    fn endofresp(&mut self, line: &[u8], code: &mut i32) -> bool {
        // Need at least "NNN" and three leading digits, else it is not ours.
        if line.len() < 4
            || !line[0].is_ascii_digit()
            || !line[1].is_ascii_digit()
            || !line[2].is_ascii_digit()
        {
            return false;
        }

        let len = line.len();
        if line[3] == b' ' || len == 5 {
            // Final line. Only three digits ever precede the space/CRLF, so the
            // status is exactly the leading three-digit number (← the
            // `curlx_str_number` parse of the copied prefix).
            let parsed = i32::from(line[0] - b'0') * 100
                + i32::from(line[1] - b'0') * 10
                + i32::from(line[2] - b'0');
            // A real server never sends the internal sentinel value.
            *code = if parsed == 1 { 0 } else { parsed };
            true
        } else if line[3] == b'-'
            && (self.state == SmtpState::Ehlo || self.state == SmtpState::Command)
        {
            // Continuation line of a multi-line EHLO/COMMAND reply.
            *code = 1;
            true
        } else {
            false
        }
    }

    /// Drive the SMTP state machine one engine step (← `smtp_pp_statemachine`).
    ///
    /// Mirrors curl's structure precisely: an `upgrade_tls` re-entry point that
    /// performs the asynchronous TLS handshake while the state is
    /// [`SmtpState::UpgradeTls`]; a pending-command flush; then a
    /// read-response/dispatch loop that continues while the state is live and
    /// more buffered data is available. The STARTTLS → UPGRADETLS transition
    /// re-enters the upgrade point via `continue`, reproducing curl's
    /// `goto upgrade_tls`.
    fn statemachine<'a>(
        &'a mut self,
        pp: &'a mut PingPong,
        conn: &'a mut Connection,
    ) -> ProtoFuture<'a, ()> {
        Box::pin(async move {
            // `upgrade_tls:` label — re-entered after STARTTLS succeeds.
            loop {
                // Busy upgrading: all I/O is the TLS handshake, not SMTP.
                if self.state == SmtpState::UpgradeTls {
                    self.perform_upgrade_tls(pp, conn).await?;
                    // Still upgrading (handshake not done) → yield; the engine
                    // re-enters on the next poll (← `if(result || state==
                    // UPGRADETLS) return result;`).
                    if self.state == SmtpState::UpgradeTls {
                        return Ok(());
                    }
                }

                // Flush any queued command before reading (← `if(pp.sendleft)
                // return Curl_pp_flushsend(...)`). `Instant::now()` stamps the
                // response timer exactly when the write completes.
                if pp.needs_flush() {
                    return pp.flushsend(conn, Instant::now()).await;
                }

                // do { readresp; dispatch } while (live && moredata()).
                loop {
                    let mut smtpcode: i32 = 0;
                    let mut nread: usize = 0;
                    pp.readresp(self, conn, FIRSTSOCKET, &mut smtpcode, &mut nread)
                        .await?;

                    // Record the latest status for `response_code`, except while
                    // quitting and for continuation lines (← `if(state != QUIT
                    // && smtpcode != 1) data->info.httpcode = smtpcode;`).
                    if self.state != SmtpState::Quit && smtpcode != 1 {
                        self.response_code = smtpcode;
                    }

                    // No complete response yet: wait for more socket data.
                    if smtpcode == 0 {
                        break;
                    }

                    let prev = self.state;
                    let is_ssl = conn.is_ssl(FIRSTSOCKET);
                    self.handle_response(pp, is_ssl, smtpcode)?;

                    // STARTTLS accepted → re-enter the TLS upgrade path so the
                    // handshake runs before any further SMTP I/O
                    // (← `goto upgrade_tls`).
                    if prev == SmtpState::StartTls && self.state == SmtpState::UpgradeTls {
                        break;
                    }

                    // Loop only while still live and more is already buffered.
                    if self.state == SmtpState::Stop || !pp.moredata() {
                        return Ok(());
                    }
                }

                // Reached here only via the STARTTLS→UPGRADETLS break: re-enter
                // the upgrade point. Any other break returned above.
                if self.state != SmtpState::UpgradeTls {
                    return Ok(());
                }
            }
        })
    }
}

// ===========================================================================
// SaslProto — the SMTP SASL descriptor (← the `saslsmtp` SASLproto table).
// ===========================================================================

impl SaslProto for SmtpConn {
    /// The SASL service name (← `saslsmtp.service`).
    fn service(&self) -> &str {
        "smtp"
    }

    /// Maximum initial-response length — `512 - strlen("AUTH ") - CRLF`
    /// (← `saslsmtp.maxirlen`).
    fn max_ir_len(&self) -> usize {
        SMTP_SASL_MAX_IR_LEN
    }

    /// The `334` continuation code (← `saslsmtp.contcode`).
    fn cont_code(&self) -> i32 {
        SMTP_SASL_CONT_CODE
    }

    /// The `235` success code (← `saslsmtp.finalcode`).
    fn final_code(&self) -> i32 {
        SMTP_SASL_FINAL_CODE
    }

    /// The default mechanism set (← `saslsmtp.defmechs`).
    fn def_mechs(&self) -> u32 {
        SASL_AUTH_DEFAULT
    }

    /// Configuration flags — base64-encoded payloads (← `saslsmtp.flags`).
    fn flags(&self) -> u16 {
        SASL_FLAG_BASE64
    }

    /// Queue `AUTH <mech>` or `AUTH <mech> <ir>` (← `smtp_perform_auth`).
    ///
    /// The command is staged (not sent) because the SASL engine borrows `self`
    /// exclusively during `sasl_start`/`sasl_continue`; the response handler
    /// flushes the staged command to the engine afterwards (see the type-level
    /// docs). The initial response is base64 (7-bit ASCII), so the byte→text
    /// conversion is lossless.
    fn send_auth(&mut self, mech: &str, initial_resp: Option<&[u8]>) -> Result<()> {
        let cmd = match initial_resp {
            Some(ir) => {
                let ir = String::from_utf8_lossy(ir);
                format!("AUTH {mech} {ir}")
            }
            None => format!("AUTH {mech}"),
        };
        self.sasl_outgoing.push(cmd);
        Ok(())
    }

    /// Queue a SASL continuation line carrying the client response
    /// (← `smtp_continue_auth`, which sends `"%s"` of the response). The `mech`
    /// is unused, exactly as in curl (`(void)mech`).
    fn cont_auth(&mut self, _mech: &str, resp: &[u8]) -> Result<()> {
        self.sasl_outgoing
            .push(String::from_utf8_lossy(resp).into_owned());
        Ok(())
    }

    /// Queue the `*` SASL-cancellation line (← `smtp_cancel_auth`). The `mech`
    /// is unused, exactly as in curl (`(void)mech`).
    fn cancel_auth(&mut self, _mech: &str) -> Result<()> {
        self.sasl_outgoing.push("*".to_string());
        Ok(())
    }

    /// Return the server's staged SASL message token (← `smtp_get_message`).
    ///
    /// The token was extracted from the response line into
    /// [`sasl_message`](Self::sasl_message) by [`auth_resp`](Self::auth_resp)
    /// before the engine was driven; it is still base64-encoded (the engine
    /// decodes it). A clone is returned so the accessor is idempotent, matching
    /// curl's non-consuming buffer read.
    fn get_message(&mut self) -> Result<Vec<u8>> {
        Ok(self.sasl_message.clone())
    }
}

// ===========================================================================
// SmtpConn — the public lifecycle driver (← smtp_connect / smtp_do /
// smtp_done / smtp_disconnect and the *_statemach pumps).
//
// These methods are what a transfer/multi layer calls to run an SMTP exchange.
// Each engine step swaps the owned `pp` out of `self` (via `mem::replace`) so
// the [`PingPong::statemach`] call can borrow the engine and the protocol
// object disjointly, then swaps it back — the borrow-safe equivalent of curl
// passing `pp` and `conn`/`data` as separate arguments.
// ===========================================================================

impl SmtpConn {
    /// Run the ping-pong pump exactly once (← one `Curl_pp_statemach` call).
    ///
    /// `xfer_timeleft_ms` is the remaining transfer time the engine uses to
    /// enforce the per-response timeout (curl reads it from the easy handle);
    /// the caller threads the live value in.
    async fn run_statemach(
        &mut self,
        conn: &mut Connection,
        block: bool,
        disconnecting: bool,
        xfer_timeleft_ms: i64,
    ) -> Result<()> {
        let now = Instant::now();
        // Swap the engine out so `statemach` can borrow `pp` and `self`
        // (as the `PingPongProtocol`) without aliasing.
        let mut pp = mem::replace(&mut self.pp, PingPong::new());
        let result = pp
            .statemach(self, conn, block, disconnecting, now, xfer_timeleft_ms)
            .await;
        self.pp = pp;
        result
    }

    /// Pump once, non-blocking, and report whether the phase is complete
    /// (← `smtp_multi_statemach`; `*done = (state == SMTP_STOP)`).
    async fn multi_statemach(
        &mut self,
        conn: &mut Connection,
        xfer_timeleft_ms: i64,
    ) -> Result<bool> {
        self.run_statemach(conn, false, false, xfer_timeleft_ms)
            .await?;
        Ok(self.state == SmtpState::Stop)
    }

    /// Pump, blocking, until the state machine stops (← `smtp_block_statemach`).
    async fn block_statemach(
        &mut self,
        conn: &mut Connection,
        disconnecting: bool,
        xfer_timeleft_ms: i64,
    ) -> Result<()> {
        while self.state != SmtpState::Stop {
            self.run_statemach(conn, true, disconnecting, xfer_timeleft_ms)
                .await?;
        }
        Ok(())
    }

    /// Begin the connect phase: wait for the greeting, then EHLO/HELO,
    /// STARTTLS, and authentication (← `smtp_connect`).
    ///
    /// URL-option/URL-path parsing (`smtp_parse_url_options` /
    /// `smtp_parse_url_path`) is performed by the driver and reflected into
    /// [`SmtpOptions`] and `domain` before this call. Returns `true` once the
    /// connect phase is complete.
    ///
    /// # Errors
    /// Any protocol, TLS, or I/O error surfaced while establishing the session.
    pub async fn connect(&mut self, conn: &mut Connection, xfer_timeleft_ms: i64) -> Result<bool> {
        // (Re)initialise the ping-pong timers (← `Curl_pp_init`); the state
        // machine/end-of-response hooks are this type's trait impls.
        self.pp.init(Instant::now());
        // Start off waiting for the server greeting.
        self.set_state(SmtpState::ServerGreet);
        self.multi_statemach(conn, xfer_timeleft_ms).await
    }

    /// Continue a non-blocking connect started by [`connect`](Self::connect)
    /// (← the `connecting` vtable entry, `smtp_multi_statemach`).
    ///
    /// # Errors
    /// Propagates any error from the underlying engine step.
    pub async fn connecting(
        &mut self,
        conn: &mut Connection,
        xfer_timeleft_ms: i64,
    ) -> Result<bool> {
        self.multi_statemach(conn, xfer_timeleft_ms).await
    }

    /// Run the DO phase: send a mail (`MAIL`/`RCPT`/`DATA`) or a custom command
    /// (← `smtp_do` → `smtp_regular_transfer` → `smtp_perform`).
    ///
    /// Returns `true` once the DO phase is complete. When a body is to be
    /// uploaded, completion of this phase leaves the connection ready for the
    /// transfer layer to stream the dot-stuffed body (see
    /// [`encode_body`](Self::encode_body)); the terminating `250` is collected
    /// later in [`done`](Self::done).
    ///
    /// # Errors
    /// Any protocol or I/O error surfaced while issuing the DO-phase commands.
    pub async fn perform(&mut self, conn: &mut Connection, xfer_timeleft_ms: i64) -> Result<bool> {
        // Requested no body means no transfer (← `data->req.no_body`).
        if self.options.no_body {
            self.smtp.transfer = PpTransfer::Info;
        }

        // Reset the per-request recipient iteration and body bookkeeping.
        self.smtp.rcpt = self.options.mail_rcpt.clone();
        self.smtp.rcpt_index = 0;
        self.smtp.rcpt_had_ok = false;
        self.smtp.rcpt_last_error = 0;
        // The initial data character is implicitly preceded by a virtual CRLF.
        self.smtp.trailing_crlf = true;
        self.smtp.eob = 2;
        // The decoded custom request (← `smtp_parse_custom_request`).
        self.smtp.custom = self.options.custom_request.clone();

        // Issue the first DO-phase command. Swap `pp` out so the builder can
        // borrow it disjointly from `self`.
        let mut pp = mem::replace(&mut self.pp, PingPong::new());
        let queued = if (self.options.upload || self.options.mime_post)
            && !self.options.mail_rcpt.is_empty()
        {
            // MAIL transfer.
            self.perform_mail(&mut pp)
        } else {
            // SMTP command (VRFY/EXPN/NOOP/RSET/HELP).
            self.perform_command(&mut pp)
        };
        self.pp = pp;
        queued?;

        self.multi_statemach(conn, xfer_timeleft_ms).await
    }

    /// Continue a non-blocking DO phase (← the `doing` vtable entry,
    /// `smtp_doing`). The post-DO `Curl_xfer_setup_nop` for the no-body case is
    /// a transfer-layer concern.
    ///
    /// # Errors
    /// Propagates any error from the underlying engine step.
    pub async fn doing(&mut self, conn: &mut Connection, xfer_timeleft_ms: i64) -> Result<bool> {
        self.multi_statemach(conn, xfer_timeleft_ms).await
    }

    /// Complete a single DO (← `smtp_done`).
    ///
    /// On a bad `status` the connection is marked for closure and the status is
    /// propagated. Otherwise, for a completed upload (`mail_rcpt` present and a
    /// body was sent, and not `connect_only`), the state machine is driven
    /// through [`SmtpState::Postdata`] to collect the final `250` after the
    /// dot-terminated body. The transfer mode is reset to `Body` for the next
    /// request either way.
    ///
    /// # Errors
    /// The propagated bad `status`, or any error from the POSTDATA exchange.
    pub async fn done(
        &mut self,
        conn: &mut Connection,
        status: Result<()>,
        premature: bool,
        xfer_timeleft_ms: i64,
    ) -> Result<()> {
        // `(void)premature` in curl — accepted for signature parity.
        let _ = premature;

        // Clean up the per-request custom command (← `Curl_safefree`).
        self.smtp.custom = None;

        let result = match status {
            Err(e) => {
                // Marked for closure (← `connclose(conn, ...)`); reuse the code.
                conn.bits.close = true;
                Err(e)
            }
            Ok(()) => {
                if !self.options.connect_only
                    && !self.options.mail_rcpt.is_empty()
                    && (self.options.upload || self.options.mime_post)
                {
                    self.set_state(SmtpState::Postdata);
                    self.block_statemach(conn, false, xfer_timeleft_ms).await
                } else {
                    Ok(())
                }
            }
        };

        // Clear the transfer mode for the next request.
        self.smtp.transfer = PpTransfer::Body;
        result
    }

    /// Disconnect from the server, sending `QUIT` when it is safe to do so
    /// (← `smtp_disconnect`). Blocking.
    ///
    /// `QUIT` is skipped for a dead connection, before the protocol handshake
    /// has started, or when a command is still queued (sending and waiting
    /// would stall the teardown). Errors from the `QUIT` exchange are ignored,
    /// exactly as curl does.
    ///
    /// # Errors
    /// Never returns an error for the QUIT exchange itself (ignored); the
    /// signature is fallible for parity with the other lifecycle methods.
    pub async fn disconnect(
        &mut self,
        conn: &mut Connection,
        dead_connection: bool,
        xfer_timeleft_ms: i64,
    ) -> Result<()> {
        if !dead_connection && conn.bits.protoconnstart && !self.pp.needs_flush() {
            // Queue QUIT (swap `pp` out for the disjoint builder borrow).
            let mut pp = mem::replace(&mut self.pp, PingPong::new());
            let queued = self.perform_quit(&mut pp);
            self.pp = pp;
            if queued.is_ok() {
                // Ignore any error on QUIT.
                let _ = self.block_statemach(conn, true, xfer_timeleft_ms).await;
            }
        }
        Ok(())
    }
}

// ===========================================================================
// SmtpHandler — the stateless protocol singleton (← Curl_handler_smtp /
// Curl_handler_smtps) and its pollset delegate.
// ===========================================================================

impl SmtpConn {
    /// Contribute the socket this connection wants watched during the connect
    /// and DO phases (← `smtp_pollset`, which delegates to `Curl_pp_pollset`).
    ///
    /// Watches for writability while a command is queued and readability while
    /// awaiting a response — exactly the ping-pong engine's pollset.
    pub fn pollset(&self, conn: &Connection, ps: &mut Pollset) {
        self.pp.pollset(conn, ps);
    }
}

/// The stateless SMTP/SMTPS protocol handler singleton
/// (← `Curl_handler_smtp` / `Curl_handler_smtps`).
///
/// A zero-sized type shared as `&'static dyn Protocol` and referenced by the
/// `SCHEME_SMTP`/`SCHEME_SMTPS` scheme descriptors. All per-connection and
/// per-transfer state lives in [`SmtpConn`]; the transfer/multi layer owns a
/// [`SmtpConn`] and drives it through the public lifecycle methods
/// ([`SmtpConn::connect`], [`SmtpConn::perform`], [`SmtpConn::done`],
/// [`SmtpConn::disconnect`], …). SMTPS differs only in that its transport is
/// TLS from the outset (implicit TLS); the SMTP conversation is identical.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SmtpHandler;

/// The SMTP/SMTPS handler singleton referenced by the scheme descriptors
/// (← `Curl_handler_smtp` / `Curl_handler_smtps`).
pub static HANDLER: SmtpHandler = SmtpHandler;

/// The remaining whole-transfer time budget in milliseconds for the SMTP
/// engine (← curl's `Curl_timeleft_ms(data)`): the configured
/// `CURLOPT_TIMEOUT[_MS]` when set, or `0` — the sentinel the ping-pong pump
/// reads as "no transfer timeout applies", falling back to its per-response
/// default (see [`PingPong::state_timeout`]). Threading the configured budget
/// here mirrors curl reading the live remaining time from the easy handle on
/// each engine step.
fn smtp_do_timeleft(ctx: &TransferCtx) -> i64 {
    ctx.request
        .timeout
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Borrow the transfer's [`Connection`] and its [`SmtpConn`] engine disjointly
/// from the [`TransferCtx`]: the connection lives in [`TransferCtx::conn`] and
/// the engine — established by the connect phase (← `conn->proto.smtpc`) — in
/// [`TransferCtx::proto_state`]. Because `conn` and `proto_state` are distinct
/// fields, the two mutable borrows coexist (the disjoint-field-borrow pattern
/// documented on [`TransferCtx`]), which is exactly how curl passes
/// `conn`/`data` and the SMTP struct to the engine as separate arguments.
///
/// # Errors
/// [`CurlCode::BadFunctionArgument`] when either handle is absent — a caller
/// precondition mirroring curl requiring both `data->conn` and
/// `conn->proto.smtpc` to be set before the DO phase runs.
fn smtp_conn_and_engine(ctx: &mut TransferCtx) -> Result<(&mut Connection, &mut SmtpConn)> {
    // Borrow the engine out of `proto_state` first; this borrows only that
    // field, leaving `conn` free to borrow below.
    let engine = ctx
        .proto_state
        .as_deref_mut()
        .and_then(|s| s.downcast_mut::<SmtpConn>())
        .ok_or_else(|| {
            Error::with_context(
                CurlCode::BadFunctionArgument,
                "[SMTP] no SMTP engine assigned to transfer",
            )
        })?;
    let conn = ctx.conn.as_deref_mut().ok_or_else(|| {
        Error::with_context(
            CurlCode::BadFunctionArgument,
            "[SMTP] no connection assigned to transfer",
        )
    })?;
    Ok((conn, engine))
}

impl Protocol for SmtpHandler {
    /// The SMTP "DO" phase entry point (← `smtp_do`).
    ///
    /// Drives the first step of the DO-phase state machine over the transfer's
    /// [`SmtpConn`] engine (held in [`TransferCtx::proto_state`], set up by the
    /// connect phase) and its [`Connection`] (in [`TransferCtx::conn`]),
    /// issuing `MAIL`/`RCPT`/`DATA` for an upload or a custom command
    /// (`VRFY`/`EXPN`/`NOOP`/`RSET`/`HELP`) otherwise. Returns `true` when the
    /// DO phase reaches `SMTP_STOP` in this single non-blocking step; otherwise
    /// the transfer layer continues it via [`doing`](Self::doing) (← the
    /// `*done` out-parameter of `smtp_do`).
    ///
    /// # Errors
    /// [`CurlCode::BadFunctionArgument`] if the transfer carries no connection
    /// or no SMTP engine (a caller precondition, ← curl's `data->conn` /
    /// `conn->proto.smtpc` always being established by the connect phase), or
    /// any protocol/I/O error surfaced while issuing the DO-phase commands.
    fn do_it<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        Box::pin(async move {
            let timeleft = smtp_do_timeleft(ctx);
            let (conn, engine) = smtp_conn_and_engine(ctx)?;
            engine.perform(conn, timeleft).await
        })
    }

    /// Continue a non-blocking SMTP DO phase (← `smtp_doing`).
    ///
    /// Pumps the engine's ping-pong state machine one non-blocking step and
    /// reports whether the DO phase has reached `SMTP_STOP`
    /// (← `*done = (smtpc->state == SMTP_STOP)`).
    ///
    /// # Errors
    /// As [`do_it`](Self::do_it): a missing connection/engine, or an engine
    /// error surfaced while pumping the state machine.
    fn doing<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        Box::pin(async move {
            let timeleft = smtp_do_timeleft(ctx);
            let (conn, engine) = smtp_conn_and_engine(ctx)?;
            engine.doing(conn, timeleft).await
        })
    }

    /// The SMTP "DONE" phase entry point (← `smtp_done`).
    ///
    /// Completes the transfer over the engine: on a good `status` for a body
    /// upload it drives [`SmtpState::Postdata`] to collect the dot-terminated
    /// message's trailing `250`; on a bad `status` it marks the connection for
    /// closure and propagates the error (← `smtp_done`).
    ///
    /// # Errors
    /// The propagated bad `status`, [`CurlCode::BadFunctionArgument`] for a
    /// missing connection/engine, or any error from the POSTDATA exchange.
    fn done<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        status: Result<()>,
        premature: bool,
    ) -> ProtoFuture<'a, ()> {
        Box::pin(async move {
            let timeleft = smtp_do_timeleft(ctx);
            let (conn, engine) = smtp_conn_and_engine(ctx)?;
            engine.done(conn, status, premature, timeleft).await
        })
    }
}

// ===========================================================================
// Tests — canned SMTP byte streams and command framing driven through an
// in-memory mock connection filter. Every assertion reflects curl 8.x's exact
// behaviour (state names, wire bytes, dot-stuffing, error codes).
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};

    use crate::auth::sasl::{SASL_MECH_LOGIN, SASL_MECH_PLAIN};
    use crate::conn::filters::{CfFuture, FilterCtx, QueryCtx, QueryOut};
    use crate::conn::{CfQuery, CfType, ConnectionFilter, FilterChain, Scheme, Transport};

    // ----- In-memory mock connection filter (leaf; overrides send/recv) -----
    //
    // Mirrors the harness in `pingpong.rs`: it delivers canned bytes on `recv`
    // and captures written bytes on `send`, so command framing and response
    // handling can be exercised without a live socket.

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

    // ----- Helpers ----------------------------------------------------------

    /// A network connection whose primary chain is the given mock filter.
    fn conn_with(io: Arc<Mutex<MockIo>>) -> Connection {
        let mut conn = Connection::new(Scheme::new("smtp", 25), "example.com", 25);
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(MockFilter { io, fd: 7 }));
        conn.cfilter[FIRSTSOCKET] = Some(chain);
        conn
    }

    /// A freshly initialised, standalone ping-pong engine.
    fn new_pp() -> PingPong {
        let mut pp = PingPong::new();
        pp.init(Instant::now());
        pp
    }

    /// A fresh SMTP driver for `domain` with default options.
    fn smtpc(domain: &str) -> SmtpConn {
        SmtpConn::new(domain, SmtpOptions::default())
    }

    // =======================================================================
    // 1. SmtpState — verbatim curl trace spellings.
    // =======================================================================

    #[test]
    fn smtpstate_names_match_curl_verbatim() {
        assert_eq!(SmtpState::Stop.name(), "STOP");
        assert_eq!(SmtpState::ServerGreet.name(), "SERVERGREET");
        assert_eq!(SmtpState::Ehlo.name(), "EHLO");
        assert_eq!(SmtpState::Helo.name(), "HELO");
        assert_eq!(SmtpState::StartTls.name(), "STARTTLS");
        assert_eq!(SmtpState::UpgradeTls.name(), "UPGRADETLS");
        assert_eq!(SmtpState::Auth.name(), "AUTH");
        assert_eq!(SmtpState::Command.name(), "COMMAND");
        assert_eq!(SmtpState::Mail.name(), "MAIL");
        assert_eq!(SmtpState::Rcpt.name(), "RCPT");
        assert_eq!(SmtpState::Data.name(), "DATA");
        assert_eq!(SmtpState::Postdata.name(), "POSTDATA");
        assert_eq!(SmtpState::Quit.name(), "QUIT");
        assert_eq!(SmtpState::Last.name(), "LAST");
    }

    #[test]
    fn smtpstate_default_is_stop() {
        assert_eq!(SmtpState::default(), SmtpState::Stop);
    }

    // =======================================================================
    // 2. endofresp — final vs continuation framing (← smtp_endofresp).
    // =======================================================================

    #[test]
    fn endofresp_final_line_parses_code() {
        let mut c = smtpc("localhost");
        let mut code = -1;
        assert!(c.endofresp(b"250 OK\r\n", &mut code));
        assert_eq!(code, 250);
    }

    #[test]
    fn endofresp_five_byte_bare_line_is_final() {
        // A bare "NNN\r\n" (len == 5) is a final line even without a space.
        let mut c = smtpc("localhost");
        let mut code = -1;
        assert!(c.endofresp(b"250\r\n", &mut code));
        assert_eq!(code, 250);
    }

    #[test]
    fn endofresp_continuation_only_in_ehlo_or_command() {
        let mut c = smtpc("localhost");
        let mut code = -1;

        // In EHLO: "NNN-" is a continuation, mapped to the internal sentinel 1.
        c.state = SmtpState::Ehlo;
        assert!(c.endofresp(b"250-STARTTLS\r\n", &mut code));
        assert_eq!(code, 1);

        // In COMMAND: likewise a continuation.
        c.state = SmtpState::Command;
        code = -1;
        assert!(c.endofresp(b"250-first\r\n", &mut code));
        assert_eq!(code, 1);

        // In any other state a "NNN-" line is not a valid response terminator.
        c.state = SmtpState::Mail;
        code = -1;
        assert!(!c.endofresp(b"250-nope\r\n", &mut code));
    }

    #[test]
    fn endofresp_sentinel_001_remaps_to_zero() {
        // A genuine "001" collides with the internal continuation sentinel, so
        // curl remaps it to 0 (← `if(code == 1) code = 0;`).
        let mut c = smtpc("localhost");
        let mut code = -1;
        assert!(c.endofresp(b"001 hi\r\n", &mut code));
        assert_eq!(code, 0);
    }

    #[test]
    fn endofresp_rejects_short_and_nondigit() {
        let mut c = smtpc("localhost");
        let mut code = 0;
        // Fewer than four bytes.
        assert!(!c.endofresp(b"25\r", &mut code));
        // Non-digit status.
        assert!(!c.endofresp(b"XYZ ok\r\n", &mut code));
    }

    // =======================================================================
    // 3. eob_encode / encode_body — dot-stuffing + terminator (← cr_eob).
    // =======================================================================

    #[test]
    fn eob_encode_appends_terminator_to_plain_body() {
        assert_eq!(eob_encode(b"hello"), b"hello\r\n.\r\n");
    }

    #[test]
    fn eob_encode_body_already_crlf_terminated() {
        // Body ends in "\r\n": only ".\r\n" is appended.
        assert_eq!(eob_encode(b"abc\r\n"), b"abc\r\n.\r\n");
    }

    #[test]
    fn eob_encode_empty_body_is_bare_terminator() {
        assert_eq!(eob_encode(b""), b".\r\n");
    }

    #[test]
    fn eob_encode_dot_stuffs_leading_dot_on_first_line() {
        // n_eob starts at 2 (virtual leading CRLF), so a dot at the very start
        // of the body is escaped as "..".
        assert_eq!(eob_encode(b".dotline"), b"..dotline\r\n.\r\n");
    }

    #[test]
    fn eob_encode_dot_stuffs_dot_after_crlf() {
        // The ".b" line begins with a dot after "\r\n" → doubled.
        assert_eq!(eob_encode(b"a\r\n.b"), b"a\r\n..b\r\n.\r\n");
    }

    #[test]
    fn eob_encode_multiline_without_leading_dots() {
        assert_eq!(eob_encode(b"line1\r\nline2"), b"line1\r\nline2\r\n.\r\n");
    }

    #[test]
    fn encode_body_public_api_matches_eob_encode() {
        let c = smtpc("localhost");
        assert_eq!(c.encode_body(b".x"), b"..x\r\n.\r\n");
    }

    // =======================================================================
    // 4. parse_address — angle-bracket stripping, suffix, host split.
    // =======================================================================

    #[test]
    fn parse_address_angled_with_host() {
        let a = parse_address("<user@example.com>");
        assert_eq!(a.address, "user");
        assert_eq!(a.host.as_deref(), Some("example.com"));
        assert_eq!(a.suffix, "");
    }

    #[test]
    fn parse_address_unangled_with_host() {
        let a = parse_address("user@example.com");
        assert_eq!(a.address, "user");
        assert_eq!(a.host.as_deref(), Some("example.com"));
        assert_eq!(a.suffix, "");
    }

    #[test]
    fn parse_address_angled_with_suffix() {
        // Text after the closing '>' is preserved verbatim as the suffix
        // (e.g. RFC 3461 NOTIFY parameters).
        let a = parse_address("<user@example.com> NOTIFY=SUCCESS");
        assert_eq!(a.address, "user");
        assert_eq!(a.host.as_deref(), Some("example.com"));
        assert_eq!(a.suffix, " NOTIFY=SUCCESS");
    }

    #[test]
    fn parse_address_local_only_has_no_host() {
        let a = parse_address("postmaster");
        assert_eq!(a.address, "postmaster");
        assert_eq!(a.host, None);
        assert_eq!(a.suffix, "");

        let b = parse_address("<postmaster>");
        assert_eq!(b.address, "postmaster");
        assert_eq!(b.host, None);
        assert_eq!(b.suffix, "");
    }

    #[test]
    fn parse_address_unangled_trailing_bracket_dropped() {
        // A single trailing '>' on an unangled address is dropped.
        let a = parse_address("user@example.com>");
        assert_eq!(a.address, "user");
        assert_eq!(a.host.as_deref(), Some("example.com"));
        assert_eq!(a.suffix, "");
    }

    // =======================================================================
    // 5. extract_sasl_message — SASL data-line extraction (← smtp_get_message).
    // =======================================================================

    #[test]
    fn extract_sasl_message_skips_prefix_and_trims() {
        assert_eq!(extract_sasl_message(b"334 dGVzdA==\r\n"), b"dGVzdA==");
    }

    #[test]
    fn extract_sasl_message_trims_leading_blanks() {
        assert_eq!(extract_sasl_message(b"334\t token \r\n"), b"token");
    }

    #[test]
    fn extract_sasl_message_empty_when_only_prefix() {
        // "334 \r\n" → after the 4-byte prefix only blanks/newline remain.
        assert_eq!(extract_sasl_message(b"334 \r\n"), b"");
        // A four-byte-or-shorter line yields nothing.
        assert_eq!(extract_sasl_message(b"334\r"), b"");
    }

    // =======================================================================
    // 6. scan_ehlo_capability — EHLO extension parsing.
    // =======================================================================

    #[test]
    fn scan_ehlo_capability_flags() {
        let mut c = smtpc("localhost");
        assert!(!c.tls_supported);
        c.scan_ehlo_capability(b"STARTTLS");
        assert!(c.tls_supported);

        c.scan_ehlo_capability(b"SIZE 10485760");
        assert!(c.size_supported);

        c.scan_ehlo_capability(b"SMTPUTF8");
        assert!(c.utf8_supported);
    }

    #[test]
    fn scan_ehlo_capability_is_case_insensitive() {
        let mut c = smtpc("localhost");
        c.scan_ehlo_capability(b"starttls");
        assert!(c.tls_supported);
    }

    #[test]
    fn scan_ehlo_capability_partial_keyword_ignored() {
        let mut c = smtpc("localhost");
        c.scan_ehlo_capability(b"SIZ");
        assert!(!c.size_supported);
        // "AUTH" without the trailing space + mechs is not an AUTH line.
        c.scan_ehlo_capability(b"AUTH");
        assert!(!c.auth_supported);
    }

    #[test]
    fn scan_ehlo_capability_decodes_auth_mechs() {
        let mut c = smtpc("localhost");
        // Start from a clean advertised-mechanism mask (as perform_ehlo does).
        c.sasl.as_mut().unwrap().set_authmechs(SASL_AUTH_NONE);

        c.scan_ehlo_capability(b"AUTH PLAIN LOGIN");
        assert!(c.auth_supported);
        assert_eq!(
            c.sasl.as_ref().unwrap().authmechs(),
            SASL_MECH_PLAIN | SASL_MECH_LOGIN
        );
    }

    #[test]
    fn scan_ehlo_capability_unknown_mech_ignored() {
        let mut c = smtpc("localhost");
        c.sasl.as_mut().unwrap().set_authmechs(SASL_AUTH_NONE);
        c.scan_ehlo_capability(b"AUTH NOSUCHMECH");
        assert!(c.auth_supported);
        assert_eq!(c.sasl.as_ref().unwrap().authmechs(), SASL_AUTH_NONE);
    }

    // =======================================================================
    // 7. SaslProto — the saslsmtp descriptor and the staging hooks.
    // =======================================================================

    #[test]
    fn sasl_descriptor_matches_saslsmtp() {
        let c = smtpc("localhost");
        assert_eq!(c.service(), "smtp");
        assert_eq!(c.cont_code(), 334);
        assert_eq!(c.final_code(), 235);
        assert_eq!(c.max_ir_len(), 512 - 8);
        assert_eq!(c.def_mechs(), SASL_AUTH_DEFAULT);
        assert_eq!(c.flags(), SASL_FLAG_BASE64);
    }

    #[test]
    fn sasl_send_auth_stages_command_without_ir() {
        let mut c = smtpc("localhost");
        c.send_auth("PLAIN", None).unwrap();
        assert_eq!(c.sasl_outgoing, vec!["AUTH PLAIN".to_string()]);
    }

    #[test]
    fn sasl_send_auth_stages_command_with_ir() {
        let mut c = smtpc("localhost");
        c.send_auth("PLAIN", Some(b"dGVzdA==")).unwrap();
        assert_eq!(c.sasl_outgoing, vec!["AUTH PLAIN dGVzdA==".to_string()]);
    }

    #[test]
    fn sasl_cont_and_cancel_stage_lines() {
        let mut c = smtpc("localhost");
        c.cont_auth("PLAIN", b"cmVzcG9uc2U=").unwrap();
        assert_eq!(c.sasl_outgoing, vec!["cmVzcG9uc2U=".to_string()]);

        let mut c2 = smtpc("localhost");
        c2.cancel_auth("PLAIN").unwrap();
        assert_eq!(c2.sasl_outgoing, vec!["*".to_string()]);
    }

    #[test]
    fn sasl_get_message_returns_staged_token() {
        let mut c = smtpc("localhost");
        c.sasl_message = b"Zm9vYmFy".to_vec();
        assert_eq!(c.get_message().unwrap(), b"Zm9vYmFy");
    }

    // =======================================================================
    // 8. Response-handler state transitions (← smtp_state_*_resp), the
    //    branches that do not require a populated response line.
    // =======================================================================

    #[test]
    fn servergreet_resp_ok_sends_ehlo() {
        let mut c = smtpc("localhost");
        c.state = SmtpState::ServerGreet;
        let mut pp = new_pp();
        c.servergreet_resp(&mut pp, 220).unwrap();
        assert_eq!(c.state(), SmtpState::Ehlo);
    }

    #[test]
    fn servergreet_resp_rejects_non_2xx() {
        let mut c = smtpc("localhost");
        c.state = SmtpState::ServerGreet;
        let mut pp = new_pp();
        let err = c.servergreet_resp(&mut pp, 421).unwrap_err();
        assert_eq!(err.code(), CurlCode::WeirdServerReply);
    }

    #[test]
    fn starttls_resp_220_moves_to_upgrade() {
        let mut c = smtpc("localhost");
        c.state = SmtpState::StartTls;
        let mut pp = new_pp();
        c.starttls_resp(&mut pp, 220).unwrap();
        assert_eq!(c.state(), SmtpState::UpgradeTls);
    }

    #[test]
    fn starttls_resp_denied_when_required_fails() {
        let mut c = smtpc("localhost");
        c.options.use_ssl = UseSsl::All;
        c.state = SmtpState::StartTls;
        let mut pp = new_pp();
        let err = c.starttls_resp(&mut pp, 454).unwrap_err();
        assert_eq!(err.code(), CurlCode::UseSslFailed);
    }

    #[test]
    fn starttls_resp_denied_when_try_falls_back_to_plaintext() {
        // With CURLUSESSL_TRY a STARTTLS refusal continues in plaintext; with no
        // credentials the connect phase simply ends (STOP).
        let mut c = smtpc("localhost");
        c.options.use_ssl = UseSsl::Try;
        c.auth_supported = false;
        c.state = SmtpState::StartTls;
        let mut pp = new_pp();
        c.starttls_resp(&mut pp, 454).unwrap();
        assert_eq!(c.state(), SmtpState::Stop);
    }

    #[test]
    fn helo_resp_ok_stops_and_error_denies() {
        let mut c = smtpc("localhost");
        c.state = SmtpState::Helo;
        c.helo_resp(250).unwrap();
        assert_eq!(c.state(), SmtpState::Stop);

        let mut c2 = smtpc("localhost");
        c2.state = SmtpState::Helo;
        let err = c2.helo_resp(521).unwrap_err();
        assert_eq!(err.code(), CurlCode::RemoteAccessDenied);
    }

    #[test]
    fn perform_authentication_without_support_stops() {
        let mut c = smtpc("localhost");
        c.auth_supported = false;
        let mut pp = new_pp();
        c.perform_authentication(&mut pp).unwrap();
        assert_eq!(c.state(), SmtpState::Stop);
    }

    #[test]
    fn perform_authentication_without_credentials_stops() {
        let mut c = smtpc("localhost");
        // Server offers AUTH, but the default options carry no usable creds.
        c.auth_supported = true;
        let mut pp = new_pp();
        c.perform_authentication(&mut pp).unwrap();
        assert_eq!(c.state(), SmtpState::Stop);
    }

    #[test]
    fn mail_resp_ok_sends_first_rcpt() {
        let mut c = smtpc("localhost");
        c.smtp.rcpt = vec!["rcpt@example.com".to_string()];
        c.state = SmtpState::Mail;
        let mut pp = new_pp();
        c.mail_resp(&mut pp, 250).unwrap();
        assert_eq!(c.state(), SmtpState::Rcpt);
    }

    #[test]
    fn mail_resp_rejects_non_2xx() {
        let mut c = smtpc("localhost");
        c.state = SmtpState::Mail;
        let mut pp = new_pp();
        let err = c.mail_resp(&mut pp, 550).unwrap_err();
        assert_eq!(err.code(), CurlCode::SendError);
    }

    #[test]
    fn rcpt_resp_single_ok_issues_data() {
        let mut c = smtpc("localhost");
        c.smtp.rcpt = vec!["rcpt@example.com".to_string()];
        c.state = SmtpState::Rcpt;
        let mut pp = new_pp();
        c.rcpt_resp(&mut pp, 250).unwrap();
        assert_eq!(c.state(), SmtpState::Data);
        assert!(c.smtp.rcpt_had_ok);
    }

    #[test]
    fn rcpt_resp_failure_without_allowfails_is_fatal() {
        let mut c = smtpc("localhost");
        c.smtp.rcpt = vec!["rcpt@example.com".to_string()];
        c.state = SmtpState::Rcpt;
        let mut pp = new_pp();
        let err = c.rcpt_resp(&mut pp, 550).unwrap_err();
        assert_eq!(err.code(), CurlCode::SendError);
        assert_eq!(c.smtp.rcpt_last_error, 550);
    }

    #[test]
    fn rcpt_resp_all_fail_with_allowfails_reports_last_error() {
        let mut c = smtpc("localhost");
        c.options.mail_rcpt_allowfails = true;
        c.smtp.rcpt = vec!["rcpt@example.com".to_string()];
        c.state = SmtpState::Rcpt;
        let mut pp = new_pp();
        let err = c.rcpt_resp(&mut pp, 550).unwrap_err();
        assert_eq!(err.code(), CurlCode::SendError);
        assert_eq!(c.smtp.rcpt_last_error, 550);
    }

    #[tokio::test]
    async fn rcpt_resp_allowfails_iterates_to_next_recipient() {
        let io = Arc::new(Mutex::new(MockIo::default()));
        let mut conn = conn_with(Arc::clone(&io));
        let mut c = smtpc("localhost");
        c.options.mail_rcpt_allowfails = true;
        c.smtp.rcpt = vec![
            "bad@example.com".to_string(),
            "good@example.com".to_string(),
        ];
        c.state = SmtpState::Rcpt;
        let mut pp = new_pp();

        // First recipient fails but is skipped; the cursor advances and the
        // next RCPT TO is issued.
        c.rcpt_resp(&mut pp, 550).unwrap();
        assert_eq!(c.state(), SmtpState::Rcpt);
        assert_eq!(c.smtp.rcpt_index, 1);
        assert_eq!(c.smtp.rcpt_last_error, 550);

        // The engine always flushes the queued command before reading the next
        // reply (Curl_pp_sendf asserts no send is still pending), so drain it.
        pp.flushsend(&mut conn, Instant::now()).await.unwrap();
        assert_eq!(
            io.lock().unwrap().captured.as_slice(),
            b"RCPT TO:<good@example.com>\r\n"
        );

        // Second recipient succeeds → DATA.
        c.rcpt_resp(&mut pp, 250).unwrap();
        assert_eq!(c.state(), SmtpState::Data);
        assert!(c.smtp.rcpt_had_ok);
    }

    #[test]
    fn data_resp_354_stops_and_other_fails() {
        let mut c = smtpc("localhost");
        c.state = SmtpState::Data;
        c.data_resp(354).unwrap();
        assert_eq!(c.state(), SmtpState::Stop);

        let mut c2 = smtpc("localhost");
        c2.state = SmtpState::Data;
        let err = c2.data_resp(451).unwrap_err();
        assert_eq!(err.code(), CurlCode::SendError);
    }

    #[test]
    fn postdata_resp_stops_either_way() {
        let mut c = smtpc("localhost");
        c.state = SmtpState::Postdata;
        c.postdata_resp(250).unwrap();
        assert_eq!(c.state(), SmtpState::Stop);

        let mut c2 = smtpc("localhost");
        c2.state = SmtpState::Postdata;
        let err = c2.postdata_resp(500).unwrap_err();
        assert_eq!(err.code(), CurlCode::WeirdServerReply);
        // curl sets STOP regardless of the code.
        assert_eq!(c2.state(), SmtpState::Stop);
    }

    #[test]
    fn command_resp_non_recipient_failure_is_weird_reply() {
        let mut c = smtpc("localhost");
        c.state = SmtpState::Command;
        let mut pp = new_pp();
        let err = c.command_resp(&mut pp, 500).unwrap_err();
        assert_eq!(err.code(), CurlCode::WeirdServerReply);
    }

    #[test]
    fn command_resp_recipient_tolerates_553() {
        // A recipient-bearing command (VRFY/EXPN) tolerates 553 besides 2xx.
        let mut c = smtpc("localhost");
        c.options.no_body = true;
        c.smtp.rcpt = vec!["user@example.com".to_string()];
        c.state = SmtpState::Command;
        let mut pp = new_pp();
        c.command_resp(&mut pp, 553).unwrap();
        // Single recipient consumed → STOP.
        assert_eq!(c.state(), SmtpState::Stop);
    }

    #[test]
    fn command_resp_non_recipient_ok_stops() {
        let mut c = smtpc("localhost");
        c.options.no_body = true;
        c.state = SmtpState::Command;
        let mut pp = new_pp();
        c.command_resp(&mut pp, 250).unwrap();
        assert_eq!(c.state(), SmtpState::Stop);
    }

    // =======================================================================
    // 9. Command builders — exact wire bytes (← smtp_perform_*). Each queues a
    //    command into a standalone engine which is then flushed through the
    //    mock filter so the bytes on the wire can be asserted.
    // =======================================================================

    /// Flush a fully-built engine through a mock filter and return the bytes
    /// that reached the wire.
    async fn flush_captured(mut pp: PingPong) -> Vec<u8> {
        let io = Arc::new(Mutex::new(MockIo::default()));
        let mut conn = conn_with(Arc::clone(&io));
        pp.flushsend(&mut conn, Instant::now()).await.unwrap();
        let out = io.lock().unwrap().captured.clone();
        out
    }

    #[tokio::test]
    async fn perform_ehlo_wire_bytes() {
        let mut c = smtpc("localhost");
        let mut pp = new_pp();
        c.perform_ehlo(&mut pp).unwrap();
        assert_eq!(c.state(), SmtpState::Ehlo);
        assert_eq!(flush_captured(pp).await.as_slice(), b"EHLO localhost\r\n");
    }

    #[tokio::test]
    async fn perform_helo_wire_bytes() {
        let mut c = smtpc("localhost");
        let mut pp = new_pp();
        c.perform_helo(&mut pp).unwrap();
        assert_eq!(c.state(), SmtpState::Helo);
        assert_eq!(flush_captured(pp).await.as_slice(), b"HELO localhost\r\n");
    }

    #[tokio::test]
    async fn perform_starttls_wire_bytes() {
        let mut c = smtpc("localhost");
        let mut pp = new_pp();
        c.perform_starttls(&mut pp).unwrap();
        assert_eq!(c.state(), SmtpState::StartTls);
        assert_eq!(flush_captured(pp).await.as_slice(), b"STARTTLS\r\n");
    }

    #[tokio::test]
    async fn perform_quit_wire_bytes() {
        let mut c = smtpc("localhost");
        let mut pp = new_pp();
        c.perform_quit(&mut pp).unwrap();
        assert_eq!(c.state(), SmtpState::Quit);
        assert_eq!(flush_captured(pp).await.as_slice(), b"QUIT\r\n");
    }

    #[tokio::test]
    async fn perform_mail_null_reverse_path() {
        // No sender configured → null reverse-path "<>".
        let mut c = smtpc("localhost");
        let mut pp = new_pp();
        c.perform_mail(&mut pp).unwrap();
        assert_eq!(c.state(), SmtpState::Mail);
        assert_eq!(flush_captured(pp).await.as_slice(), b"MAIL FROM:<>\r\n");
    }

    #[tokio::test]
    async fn perform_mail_with_sender() {
        let mut c = smtpc("localhost");
        c.options.mail_from = Some("user@example.com".to_string());
        let mut pp = new_pp();
        c.perform_mail(&mut pp).unwrap();
        assert_eq!(
            flush_captured(pp).await.as_slice(),
            b"MAIL FROM:<user@example.com>\r\n"
        );
    }

    #[tokio::test]
    async fn perform_mail_with_size_when_supported() {
        let mut c = smtpc("localhost");
        c.options.mail_from = Some("user@example.com".to_string());
        c.size_supported = true;
        c.options.infilesize = 42;
        let mut pp = new_pp();
        c.perform_mail(&mut pp).unwrap();
        assert_eq!(
            flush_captured(pp).await.as_slice(),
            b"MAIL FROM:<user@example.com> SIZE=42\r\n"
        );
    }

    #[tokio::test]
    async fn perform_mail_omits_size_when_unknown() {
        // SIZE is only emitted for a known positive upload size.
        let mut c = smtpc("localhost");
        c.options.mail_from = Some("user@example.com".to_string());
        c.size_supported = true;
        c.options.infilesize = 0;
        let mut pp = new_pp();
        c.perform_mail(&mut pp).unwrap();
        assert_eq!(
            flush_captured(pp).await.as_slice(),
            b"MAIL FROM:<user@example.com>\r\n"
        );
    }

    #[tokio::test]
    async fn perform_mail_omits_auth_when_not_authenticated() {
        // AUTH= is only appended when a mechanism was actually used; with no
        // SASL exchange the parameter must not appear even if MAIL_AUTH is set.
        let mut c = smtpc("localhost");
        c.options.mail_from = Some("user@example.com".to_string());
        c.options.mail_auth = Some("auth@example.com".to_string());
        let mut pp = new_pp();
        c.perform_mail(&mut pp).unwrap();
        assert_eq!(
            flush_captured(pp).await.as_slice(),
            b"MAIL FROM:<user@example.com>\r\n"
        );
    }

    #[tokio::test]
    async fn perform_mail_smtputf8_for_non_ascii_sender() {
        let mut c = smtpc("localhost");
        c.options.mail_from = Some("üser@example.com".to_string());
        c.utf8_supported = true;
        let mut pp = new_pp();
        c.perform_mail(&mut pp).unwrap();
        assert_eq!(
            flush_captured(pp).await.as_slice(),
            "MAIL FROM:<üser@example.com> SMTPUTF8\r\n".as_bytes()
        );
    }

    #[tokio::test]
    async fn perform_rcpt_to_wire_bytes() {
        let mut c = smtpc("localhost");
        c.smtp.rcpt = vec!["rcpt@example.com".to_string()];
        let mut pp = new_pp();
        c.perform_rcpt_to(&mut pp).unwrap();
        assert_eq!(c.state(), SmtpState::Rcpt);
        assert_eq!(
            flush_captured(pp).await.as_slice(),
            b"RCPT TO:<rcpt@example.com>\r\n"
        );
    }

    #[tokio::test]
    async fn perform_rcpt_to_local_mailbox() {
        let mut c = smtpc("localhost");
        c.smtp.rcpt = vec!["postmaster".to_string()];
        let mut pp = new_pp();
        c.perform_rcpt_to(&mut pp).unwrap();
        assert_eq!(
            flush_captured(pp).await.as_slice(),
            b"RCPT TO:<postmaster>\r\n"
        );
    }

    #[tokio::test]
    async fn perform_command_default_vrfy_on_recipient() {
        let mut c = smtpc("localhost");
        c.smtp.rcpt = vec!["user@host".to_string()];
        let mut pp = new_pp();
        c.perform_command(&mut pp).unwrap();
        assert_eq!(c.state(), SmtpState::Command);
        assert_eq!(flush_captured(pp).await.as_slice(), b"VRFY user@host\r\n");
    }

    #[tokio::test]
    async fn perform_command_custom_expn_on_recipient() {
        let mut c = smtpc("localhost");
        c.smtp.rcpt = vec!["mailing-list".to_string()];
        c.smtp.custom = Some("EXPN".to_string());
        let mut pp = new_pp();
        c.perform_command(&mut pp).unwrap();
        assert_eq!(
            flush_captured(pp).await.as_slice(),
            b"EXPN mailing-list\r\n"
        );
    }

    #[tokio::test]
    async fn perform_command_custom_without_recipient() {
        let mut c = smtpc("localhost");
        c.smtp.custom = Some("NOOP".to_string());
        let mut pp = new_pp();
        c.perform_command(&mut pp).unwrap();
        assert_eq!(flush_captured(pp).await.as_slice(), b"NOOP\r\n");
    }

    #[tokio::test]
    async fn perform_command_defaults_to_help() {
        // No recipient and no custom verb → bare HELP.
        let mut c = smtpc("localhost");
        let mut pp = new_pp();
        c.perform_command(&mut pp).unwrap();
        assert_eq!(flush_captured(pp).await.as_slice(), b"HELP\r\n");
    }

    #[tokio::test]
    async fn rcpt_resp_data_command_wire_bytes() {
        // After a single accepted recipient the engine issues DATA.
        let mut c = smtpc("localhost");
        c.smtp.rcpt = vec!["rcpt@example.com".to_string()];
        c.state = SmtpState::Rcpt;
        let mut pp = new_pp();
        c.rcpt_resp(&mut pp, 250).unwrap();
        assert_eq!(c.state(), SmtpState::Data);
        assert_eq!(flush_captured(pp).await.as_slice(), b"DATA\r\n");
    }

    #[tokio::test]
    async fn sasl_outgoing_flushes_as_auth_command() {
        // The staged AUTH command reaches the wire verbatim (CRLF appended).
        let mut c = smtpc("localhost");
        c.send_auth("PLAIN", None).unwrap();
        let mut pp = new_pp();
        c.flush_sasl_outgoing(&mut pp).unwrap();
        assert!(c.sasl_outgoing.is_empty());
        assert_eq!(flush_captured(pp).await.as_slice(), b"AUTH PLAIN\r\n");
    }

    // =======================================================================
    // 10. EHLO reply decisions (← smtp_state_ehlo_resp) driven over a real
    //     response line read through the engine.
    // =======================================================================

    #[tokio::test]
    async fn ehlo_rejected_falls_back_to_helo() {
        // EHLO refused and TLS not required → HELO fallback.
        let mut c = smtpc("localhost");
        c.options.use_ssl = UseSsl::None;
        c.state = SmtpState::Ehlo;
        let mut pp = new_pp();
        c.ehlo_resp(&mut pp, false, 500).unwrap();
        assert_eq!(c.state(), SmtpState::Helo);
        assert_eq!(flush_captured(pp).await.as_slice(), b"HELO localhost\r\n");
    }

    #[tokio::test]
    async fn ehlo_with_starttls_starts_upgrade() {
        let io = Arc::new(Mutex::new(MockIo {
            to_deliver: b"250 STARTTLS\r\n".to_vec(),
            ..MockIo::default()
        }));
        let mut conn = conn_with(Arc::clone(&io));
        let mut c = smtpc("localhost");
        c.options.use_ssl = UseSsl::Try;
        c.state = SmtpState::Ehlo;
        let mut pp = new_pp();
        let mut code = 0;
        let mut size = 0;
        pp.readresp(&mut c, &mut conn, FIRSTSOCKET, &mut code, &mut size)
            .await
            .unwrap();
        assert_eq!(code, 250);
        c.ehlo_resp(&mut pp, false, code).unwrap();
        assert!(c.tls_supported);
        assert_eq!(c.state(), SmtpState::StartTls);
        // The queued STARTTLS command reaches the wire.
        pp.flushsend(&mut conn, Instant::now()).await.unwrap();
        assert_eq!(io.lock().unwrap().captured.as_slice(), b"STARTTLS\r\n");
    }

    #[tokio::test]
    async fn ehlo_without_tls_proceeds_to_auth() {
        let io = Arc::new(Mutex::new(MockIo {
            to_deliver: b"250 AUTH PLAIN LOGIN\r\n".to_vec(),
            ..MockIo::default()
        }));
        let mut conn = conn_with(Arc::clone(&io));
        let mut c = smtpc("localhost");
        c.options.use_ssl = UseSsl::None;
        c.state = SmtpState::Ehlo;
        c.sasl.as_mut().unwrap().set_authmechs(SASL_AUTH_NONE);
        let mut pp = new_pp();
        let mut code = 0;
        let mut size = 0;
        pp.readresp(&mut c, &mut conn, FIRSTSOCKET, &mut code, &mut size)
            .await
            .unwrap();
        c.ehlo_resp(&mut pp, false, code).unwrap();
        assert!(c.auth_supported);
        assert_eq!(
            c.sasl.as_ref().unwrap().authmechs(),
            SASL_MECH_PLAIN | SASL_MECH_LOGIN
        );
        // No usable credentials → the connect phase ends.
        assert_eq!(c.state(), SmtpState::Stop);
    }

    #[tokio::test]
    async fn ehlo_requires_tls_but_unavailable_fails() {
        let io = Arc::new(Mutex::new(MockIo {
            to_deliver: b"250 SIZE 100\r\n".to_vec(),
            ..MockIo::default()
        }));
        let mut conn = conn_with(Arc::clone(&io));
        let mut c = smtpc("localhost");
        c.options.use_ssl = UseSsl::All;
        c.state = SmtpState::Ehlo;
        let mut pp = new_pp();
        let mut code = 0;
        let mut size = 0;
        pp.readresp(&mut c, &mut conn, FIRSTSOCKET, &mut code, &mut size)
            .await
            .unwrap();
        let err = c.ehlo_resp(&mut pp, false, code).unwrap_err();
        assert_eq!(err.code(), CurlCode::UseSslFailed);
    }

    // =======================================================================
    // 11. End-to-end connect (← smtp_connect): greeting → multi-line EHLO → the
    //     no-auth completion path, driven to completion over the mock socket.
    // =======================================================================

    #[tokio::test]
    async fn connect_greeting_then_multiline_ehlo_completes() {
        let io = Arc::new(Mutex::new(MockIo {
            to_deliver: b"220 smtp.example.com ESMTP\r\n250-smtp.example.com\r\n250 SIZE 1000\r\n"
                .to_vec(),
            ..MockIo::default()
        }));
        let mut conn = conn_with(Arc::clone(&io));
        // The transport (TCP/TLS) is established before smtp_connect runs; mark
        // the mock filter connected so the engine's readiness check sees pending
        // bytes.
        conn.connect(FIRSTSOCKET, false).await.unwrap();
        let mut c = smtpc("localhost");

        let mut done = c.connect(&mut conn, 30_000).await.unwrap();
        let mut guard = 0;
        while !done && guard < 40 {
            done = c.connecting(&mut conn, 30_000).await.unwrap();
            guard += 1;
        }

        assert!(done, "connect did not reach completion");
        assert_eq!(c.state(), SmtpState::Stop);
        // The multi-line EHLO capabilities were parsed.
        assert!(c.size_supported);
        // Exactly one EHLO was sent (no auth attempted without credentials).
        assert_eq!(
            io.lock().unwrap().captured.as_slice(),
            b"EHLO localhost\r\n"
        );
    }

    // =======================================================================
    // 12. End-to-end DO phase (← smtp_perform): MAIL FROM → RCPT TO → DATA,
    //     issued in sequence as each reply arrives.
    // =======================================================================

    #[tokio::test]
    async fn perform_mail_rcpt_data_sequence() {
        let io = Arc::new(Mutex::new(MockIo {
            to_deliver: b"250 2.1.0 Ok\r\n250 2.1.5 Ok\r\n354 End data\r\n".to_vec(),
            ..MockIo::default()
        }));
        let mut conn = conn_with(Arc::clone(&io));
        // Simulate an already-connected session (transport up + pingpong init'd
        // by the connect phase) before running the DO phase.
        conn.connect(FIRSTSOCKET, false).await.unwrap();
        let mut c = smtpc("localhost");
        c.pp.init(Instant::now());
        c.options.mail_from = Some("from@example.com".to_string());
        c.options.mail_rcpt = vec!["rcpt@example.com".to_string()];
        c.options.upload = true;

        let mut done = c.perform(&mut conn, 30_000).await.unwrap();
        let mut guard = 0;
        while !done && guard < 40 {
            done = c.doing(&mut conn, 30_000).await.unwrap();
            guard += 1;
        }

        assert!(done, "DO phase did not reach completion");
        assert_eq!(c.state(), SmtpState::Stop);
        // A body upload was selected (not the no-body/info transfer).
        assert_eq!(c.transfer(), PpTransfer::Body);
        // The three commands were issued in order with exact framing.
        assert_eq!(
            io.lock().unwrap().captured.as_slice(),
            b"MAIL FROM:<from@example.com>\r\nRCPT TO:<rcpt@example.com>\r\nDATA\r\n"
        );
    }

    /// The [`SmtpHandler`] trait hooks (← `smtp_do`/`smtp_doing`/`smtp_done`)
    /// drive the DO and DONE phases over the [`SmtpConn`] engine held in
    /// [`TransferCtx::proto_state`] and the [`Connection`] in
    /// [`TransferCtx::conn`], with a missing engine/connection reported as a
    /// caller-precondition error. This exercises the handler wiring the review
    /// flagged (the previous `do_it`/`done` were no-op placeholders).
    #[tokio::test]
    async fn handler_drives_do_doing_done_over_transfer_ctx() {
        // Greeting-completed session; server returns 250 (MAIL), 250 (RCPT),
        // 354 (DATA), then the final 250 collected by the DONE/POSTDATA step.
        let io = Arc::new(Mutex::new(MockIo {
            to_deliver: b"250 2.1.0 Ok\r\n250 2.1.5 Ok\r\n354 End data\r\n250 2.0.0 Ok\r\n"
                .to_vec(),
            ..MockIo::default()
        }));
        let mut conn = conn_with(Arc::clone(&io));
        conn.connect(FIRSTSOCKET, false).await.unwrap();

        // The engine the connect phase would have installed, primed for upload.
        let mut engine = smtpc("localhost");
        engine.pp.init(Instant::now());
        engine.options.mail_from = Some("from@example.com".to_string());
        engine.options.mail_rcpt = vec!["rcpt@example.com".to_string()];
        engine.options.upload = true;

        // Assemble the transfer context exactly as the driver would: the
        // connection in `conn`, the SMTP engine in `proto_state`.
        let mut ctx = TransferCtx::new();
        ctx.conn = Some(Box::new(conn));
        ctx.proto_state = Some(Box::new(engine));

        // Drive the DO phase through the handler vtable (do_it, then doing).
        let mut done = HANDLER.do_it(&mut ctx).await.unwrap();
        let mut guard = 0;
        while !done && guard < 40 {
            done = HANDLER.doing(&mut ctx).await.unwrap();
            guard += 1;
        }
        assert!(done, "handler DO phase did not reach completion");

        // The three DO-phase commands were issued in order with exact framing.
        assert_eq!(
            io.lock().unwrap().captured.as_slice(),
            b"MAIL FROM:<from@example.com>\r\nRCPT TO:<rcpt@example.com>\r\nDATA\r\n"
        );

        // DONE completes cleanly, collecting the trailing 250 via POSTDATA and
        // resetting the engine to the idle Body transfer mode for reuse.
        HANDLER.done(&mut ctx, Ok(()), false).await.unwrap();
        let engine = ctx
            .proto_state
            .as_deref()
            .unwrap()
            .downcast_ref::<SmtpConn>()
            .unwrap();
        assert_eq!(engine.state(), SmtpState::Stop);
        assert_eq!(engine.transfer(), PpTransfer::Body);

        // A transfer with no connection/engine is a caller-precondition error
        // (← curl requiring `data->conn` / `conn->proto.smtpc`).
        let mut empty = TransferCtx::new();
        let err = HANDLER.do_it(&mut empty).await.unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
    }
}
