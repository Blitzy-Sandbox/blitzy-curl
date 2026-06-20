//! SMTP / SMTPS protocol engine — the Rust analog of curl's `lib/smtp.c`
//! (`lib/smtp.h`), built on [`crate::protocols::pingpong`] and integrating
//! [`crate::auth::sasl`].
//!
//! # Overview
//!
//! This module implements the `smtp://` and `smtps://` scheme handlers used to
//! submit mail (the `MAIL FROM` / `RCPT TO` / `DATA` envelope) and to run the
//! non-transfer service commands (`VRFY`, `EXPN`, `NOOP`, `RSET`, `HELP`). It is
//! a faithful behavioral port of curl 8.x: the wire formatting, the multi-line
//! response framing, the `STARTTLS` upgrade, the SASL authentication exchange,
//! and the body **dot-stuffing** are reproduced byte-for-byte where the C
//! implementation is deterministic.
//!
//! # Async collapse of the C state loop
//!
//! curl drives SMTP through a re-entrant state machine (`smtp_statemachine`)
//! pumped by the multi loop. Here the equivalent control flow is expressed as a
//! **straight-line `async` sequence** inside the [`Protocol`] methods
//! ([`SmtpProtocol::connect`], [`SmtpProtocol::do_it`],
//! [`SmtpProtocol::disconnect`]): each command is sent with
//! [`PingPong::sendf`] and each response awaited with [`PingPong::readresp`],
//! so the C `switch(state)` becomes ordinary `.await` points. The
//! [`PingPongProtocol::statemachine`] hook is therefore a no-op; the only
//! per-line work that still lives in a callback is [`PingPongProtocol::endofresp`]
//! (response framing **and** capability/SASL capture, since the ping-pong engine
//! discards continuation lines after the hook returns).
//!
//! # Memory safety
//!
//! This crate sets `#![forbid(unsafe_code)]` at its root; this module contains
//! **zero** `unsafe`. All buffers are owned `Vec<u8>`/`String`; the connection
//! state ([`SmtpConn`]) lives in the connection's `proto_state` and is taken out
//! at the top of each [`Protocol`] method so the borrow of `conn` is released
//! for the duration of the exchange.
//!
//! C ORACLE (read-only reference): `lib/smtp.c`, `lib/smtp.h`,
//! `lib/curl_sasl.h`.

use std::path::PathBuf;

use crate::auth::sasl::{
    decode_mech, Sasl, SaslParams, SaslProgress, SaslProto, SASL_AUTH_DEFAULT, SASL_AUTH_NONE,
    SASL_FLAG_BASE64,
};
use crate::conn::https_connect::create_tls_filter;
use crate::conn::{
    BoxFuture, Connection, Curl_conn_cf_add, Curl_conn_connect, Curl_conn_is_ssl, Curl_conn_send,
    FIRSTSOCKET,
};
use crate::easy::Easy;
use crate::error::{CurlError, Result};
use crate::protocols::pingpong::{PingPong, PingPongProtocol};
use crate::protocols::{Protocol, ProtocolTransfer, Scheme, TransferDirection};
use crate::setopt::StrId;
use crate::tls::TlsConfig;
use crate::url::{CurlUPart, CurlUrl, CURLU_DEFAULT_PORT, CURLU_URLDECODE};

// ===========================================================================
// Protocol constants
// ===========================================================================

/// The 5-byte SMTP End-Of-Body marker (`SMTP_EOB` in `smtp.c`): a line
/// containing a single dot, framed by CRLFs.
const SMTP_EOB: &[u8] = b"\r\n.\r\n";

/// How many leading bytes of [`SMTP_EOB`] (`"\r\n."`) the dot-stuffing scanner
/// must match before it starts doubling a literal leading dot
/// (`SMTP_EOB_FIND_LEN` in `smtp.c`).
const SMTP_EOB_FIND_LEN: usize = 3;

/// SASL maximum initial-response length for SMTP (`saslsmtp.maxirlen` in
/// `smtp.c`, `512 - 8`).
///
/// Unlike IMAP/POP3 (whose `maxirlen` is `0`, i.e. unbounded), SMTP **does**
/// bound the combined mechanism-plus-initial-response length: the `AUTH`
/// command line must fit within the 512-octet SMTP command limit, leaving room
/// for the `"AUTH "` keyword and CRLF. When an initial response would overflow
/// this, the SASL layer defers it to a continuation round.
const SMTP_AUTH_MAXIRLEN: usize = 512 - 8;

// SMTP response codes referenced by the state handlers (RFC 5321 / RFC 4954).
/// `220` — service ready (greeting / post-`STARTTLS`).
const SMTP_RESP_SERVICE_READY: i32 = 220;
/// `235` — authentication successful (RFC 4954 final code).
const SMTP_RESP_AUTH_OK: i32 = 235;
/// `250` — requested action OK / completed.
const SMTP_RESP_OK: i32 = 250;
/// `334` — server SASL challenge / continuation (RFC 4954 continuation code).
const SMTP_RESP_CONTINUE: i32 = 334;
/// `354` — start mail input; end with `<CRLF>.<CRLF>`.
const SMTP_RESP_DATA: i32 = 354;
/// `553` — mailbox name not allowed (a per-recipient soft failure tolerated
/// under `CURLOPT_MAIL_RCPT_ALLOWFAILS`).
const SMTP_RESP_MBOX_NOT_ALLOWED: i32 = 553;

// `CURLUSESSL_*` values (`include/curl/curl.h`), used to gate the `STARTTLS`
// upgrade exactly as `data->set.use_ssl` does in `smtp.c`.
/// Do not attempt TLS at all.
const CURLUSESSL_NONE: u8 = 0;
/// Try TLS, but continue without it on failure.
const CURLUSESSL_TRY: u8 = 1;

// ===========================================================================
// State machine
// ===========================================================================

/// The SMTP connection state (`smtpstate` in `smtp.c`).
///
/// In curl these are the discrete steps of the re-entrant `smtp_statemachine`;
/// here they tag the *current* command awaiting a response so [`endofresp`]
/// (the only surviving per-line callback) can apply the right multi-line rules
/// and capture the right data. The straight-line `async` driver sets the state
/// immediately before sending each command.
///
/// [`endofresp`]: PingPongProtocol::endofresp
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SmtpState {
    /// No command in flight / sequence complete (`SMTP_STOP`).
    #[default]
    Stop,
    /// Awaiting the server greeting (`SMTP_SERVERGREET`).
    ServerGreet,
    /// Awaiting the `EHLO` response (multi-line; `SMTP_EHLO`).
    Ehlo,
    /// Awaiting the `HELO` response (the non-ESMTP fallback; `SMTP_HELO`).
    Helo,
    /// Awaiting the `STARTTLS` response (`SMTP_STARTTLS`).
    StartTls,
    /// Performing the TLS handshake after a `220` (`SMTP_UPGRADETLS`).
    UpgradeTls,
    /// Awaiting an `AUTH` exchange response (`SMTP_AUTH`).
    Auth,
    /// Awaiting a custom service-command response (multi-line; `SMTP_COMMAND`).
    Command,
    /// Awaiting the `MAIL FROM` response (`SMTP_MAIL`).
    Mail,
    /// Awaiting a `RCPT TO` response (`SMTP_RCPT`).
    Rcpt,
    /// Awaiting the `DATA` response (`SMTP_DATA`).
    Data,
    /// Awaiting the post-body acceptance after `<CRLF>.<CRLF>` (`SMTP_POSTDATA`).
    PostData,
    /// Awaiting the `QUIT` response (`SMTP_QUIT`).
    Quit,
    /// Sentinel upper bound (`SMTP_LAST`); never an active state.
    Last,
}

// ===========================================================================
// Connection / request state
// ===========================================================================

/// Per-connection SMTP state (`struct smtp_conn` in `smtp.c`).
///
/// Embeds the [`PingPong`] command/response engine and the [`Sasl`]
/// authentication state, and records the capabilities advertised by the
/// server's `EHLO` response. It is stored in the connection's `proto_state` and
/// also serves as the [`PingPongProtocol`] and [`SaslProto`] implementor: the
/// straight-line driver moves `pp` out (via [`std::mem::take`]) for the
/// duration of an exchange so `self` (as the protocol/SASL callback target)
/// and the ping-pong engine are disjoint mutable borrows.
#[derive(Debug, Default)]
pub struct SmtpConn {
    /// The command/response ("ping-pong") engine.
    pp: PingPong,
    /// The SASL authentication state machine.
    sasl: Sasl,
    /// The current protocol state (which command is awaiting a response).
    state: SmtpState,
    /// The domain name presented in `EHLO`/`HELO` (from the URL path, else the
    /// local host name).
    domain: String,
    /// `STARTTLS` advertised in the `EHLO` response.
    tls_supported: bool,
    /// `SIZE` advertised in the `EHLO` response.
    size_supported: bool,
    /// `SMTPUTF8` advertised in the `EHLO` response.
    utf8_supported: bool,
    /// `AUTH` advertised in the `EHLO` response.
    auth_supported: bool,
    /// The full bytes of the most recent *final* response line, captured by
    /// [`endofresp`](PingPongProtocol::endofresp) for [`SaslProto::get_message`]
    /// (the ping-pong engine exposes no public accessor for its receive
    /// buffer).
    last_final_line: Vec<u8>,
    /// A wire-ready SASL command line queued by the synchronous
    /// [`SaslProto`] hooks, to be flushed by the async driver via
    /// [`PingPong::sendf`].
    pending_auth: Option<Vec<u8>>,
    /// Whether the connect-phase handshake (greeting → `EHLO` → optional
    /// `STARTTLS` → `AUTH`) has completed on this connection.
    ///
    /// The transfer engine does not yet drive [`Protocol::connect`] separately
    /// from [`Protocol::do_it`], so `do_it` performs the handshake itself when
    /// this flag is unset; the flag makes that idempotent, so a future engine
    /// that *does* call `connect` first will not trigger a second handshake.
    session_established: bool,
}

/// Per-request SMTP state (`struct SMTP` in `smtp.c`).
///
/// curl stores this on the easy handle's request; here it is assembled inside
/// [`SmtpProtocol::do_it`] from the easy handle's options for the duration of
/// the send. The C struct's `eob`/`trailing_crlf` book-keeping is internal to
/// the dot-stuffing reader and is reproduced by the pure [`dot_stuff`] function,
/// so it is not mirrored as fields here.
#[derive(Debug, Default, Clone)]
struct Smtp {
    /// The reverse-path for `MAIL FROM:` already rendered to its wire form
    /// (`"<addr@host>suffix"`, `"<addr>suffix"`, or `"<>"`).
    from: String,
    /// The recipient mailboxes for `RCPT TO:` (the `CURLOPT_MAIL_RCPT` list).
    rcpt: Vec<String>,
    /// A custom service command (`CURLOPT_CUSTOMREQUEST`): `VRFY`, `EXPN`,
    /// `NOOP`, `RSET`, `HELP`, …
    custom: Option<String>,
    /// The optional `AUTH=` override for `MAIL FROM` (`CURLOPT_MAIL_AUTH`),
    /// already rendered to its wire mailbox form (`"<addr@host>suffix"` or
    /// `"<>"`), or `None` when no `AUTH=` parameter should be sent.
    auth: Option<String>,
    /// The optional `SIZE=` value (the body length), when the server advertised
    /// `SIZE` and the body is non-empty.
    size: Option<u64>,
}

// ===========================================================================
// The handler
// ===========================================================================

/// The `smtp`/`smtps` [`Protocol`] handler.
///
/// A stateless singleton (the per-connection state lives in [`SmtpConn`] inside
/// the connection's `proto_state`); the only field is the static [`Scheme`]
/// descriptor it serves, which distinguishes `smtp` (port 25, opportunistic
/// `STARTTLS`) from `smtps` (port 465, implicit TLS).
#[derive(Debug)]
pub struct SmtpProtocol {
    /// The scheme descriptor (`SCHEME_SMTP` or `SCHEME_SMTPS`) this instance
    /// serves.
    scheme: &'static Scheme,
}

impl SmtpProtocol {
    /// Construct a handler for the given scheme descriptor.
    ///
    /// `scheme` must be `SCHEME_SMTP` or `SCHEME_SMTPS`; the registry in
    /// [`crate::protocols::scheme_handler`] passes the correct one.
    #[must_use]
    pub(crate) const fn new(scheme: &'static Scheme) -> Self {
        Self { scheme }
    }
}

// ===========================================================================
// Pure helpers (unit-testable, no I/O)
// ===========================================================================

/// Apply SMTP body **dot-stuffing** and append the end-of-body marker, exactly
/// reproducing curl's `cr_eob_read` (`smtp.c`).
///
/// Per RFC 5321 §4.5.2 the body is "transparency"-encoded: any line that begins
/// with a `.` has an extra `.` prepended, and the message is terminated with
/// `<CRLF>.<CRLF>`. This function processes the whole body at once and returns
/// the on-the-wire bytes.
///
/// The scanner mirrors the C state exactly: `n_eob` (how many leading bytes of
/// [`SMTP_EOB`] have matched) starts at `2`, as if a CRLF had just been read, so
/// a body that *starts* with `.` is stuffed. The terminator chosen at the end
/// depends on how much of the trailing CRLF was already present:
///
/// * `n_eob == 2` (body ended with `\r\n`, or was empty): append `".\r\n"`.
/// * `n_eob == 3` (body ended with `\r\n.`): the trailing dot is itself a line
///   start, so append `".\r\n.\r\n"` (escape it, then close the body).
/// * otherwise: append the full `"\r\n.\r\n"`.
///
/// # Examples
///
/// ```
/// # use curl_rs_lib::protocols::smtp::dot_stuff;
/// assert_eq!(dot_stuff(b".foo\r\n"), b"..foo\r\n.\r\n");
/// assert_eq!(dot_stuff(b"foo"), b"foo\r\n.\r\n");
/// assert_eq!(dot_stuff(b""), b".\r\n");
/// ```
#[must_use]
pub fn dot_stuff(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + SMTP_EOB.len());
    // `n_eob == 2` => treat the first byte as the start of a line (as if a CRLF
    // preceded it), matching `cr_eob_init`.
    let mut n_eob: usize = 2;
    let mut start = 0usize;

    for i in 0..body.len() {
        if n_eob >= SMTP_EOB_FIND_LEN {
            // We matched the `"\r\n."` prefix and another byte follows: the line
            // begins with a dot, so emit what we have plus an extra '.'.
            out.extend_from_slice(&body[start..i]);
            out.push(b'.');
            n_eob = 0;
            start = i;
        }

        // `n_eob` is always < SMTP_EOB_FIND_LEN here (the block above reset any
        // value that reached it), so indexing SMTP_EOB is in bounds.
        if body[i] != SMTP_EOB[n_eob] {
            n_eob = 0;
        }
        if body[i] == SMTP_EOB[n_eob] {
            n_eob += 1;
        }
    }

    if start < body.len() {
        out.extend_from_slice(&body[start..]);
    }

    // Auto-end the body (`cr_eob_read`'s read_eos branch).
    match n_eob {
        2 => out.extend_from_slice(&SMTP_EOB[2..]),
        3 => {
            out.push(b'.');
            out.extend_from_slice(SMTP_EOB);
        }
        _ => out.extend_from_slice(SMTP_EOB),
    }

    out
}

/// Split a fully-qualified mailbox into `(local_address, host, suffix)`,
/// reproducing curl's `smtp_parse_address` (`smtp.c`).
///
/// The grammar curl accepts is permissive: an optional angle-bracketed address
/// with a trailing suffix, e.g. `"<user@host>extra"`, `"user@host"`,
/// `"<user>"`, or a bare local part `"Postmaster"`. The rules are:
///
/// * If the string starts with `<`, the leading `<` is dropped and everything
///   from the *last* `>` is split off: the text before it is the address, the
///   text after it is the `suffix`.
/// * Otherwise a single trailing `>` (if present) is dropped and the `suffix`
///   is empty.
/// * The (remaining) address is then split at the first `@` into the local part
///   and the host; with no `@`, the host is `None` and the whole string is the
///   local part.
///
/// IDN A-label conversion of the host (a *best-effort*, failure-tolerant step
/// in curl) is intentionally not performed; the host is used verbatim.
fn parse_address(fqma: &str) -> (String, Option<String>, String) {
    let mut suffix = String::new();

    // Strip the optional angle brackets, capturing any suffix after `>`.
    let core: String = if let Some(stripped) = fqma.strip_prefix('<') {
        if let Some(pos) = stripped.rfind('>') {
            suffix = stripped[pos + 1..].to_string();
            stripped[..pos].to_string()
        } else {
            stripped.to_string()
        }
    } else if let Some(without) = fqma.strip_suffix('>') {
        without.to_string()
    } else {
        fqma.to_string()
    };

    // Split the address into local part and host at the first `@`.
    match core.find('@') {
        Some(at) => {
            let address = core[..at].to_string();
            let host = core[at + 1..].to_string();
            (address, Some(host), suffix)
        }
        None => (core, None, suffix),
    }
}

/// Render a parsed mailbox back to its angle-bracketed wire form, the shared
/// tail of both `MAIL FROM:` and `RCPT TO:`.
///
/// Produces `"<address@host>suffix"` when a host is present, else
/// `"<address>suffix"` — matching `smtp_perform_mail` / `smtp_perform_rcpt_to`.
fn format_mailbox(address: &str, host: Option<&str>, suffix: &str) -> String {
    match host {
        Some(h) => format!("<{address}@{h}>{suffix}"),
        None => format!("<{address}>{suffix}"),
    }
}

/// Whether a string contains any non-ASCII byte (curl's `!Curl_is_ASCII_name`),
/// used to decide whether to advertise `SMTPUTF8` for a mailbox.
fn has_non_ascii(s: &str) -> bool {
    !s.is_ascii()
}

/// Determine the domain to present in `EHLO`/`HELO` from the URL path,
/// reproducing `smtp_parse_url_path` (`smtp.c`).
///
/// The path (minus its leading `/`) is URL-decoded and used as the domain. When
/// the path is empty, curl falls back to the local host name and, failing that,
/// to `"localhost"`; [`local_domain`] provides the same fallback without
/// `unsafe`.
fn domain_from_url(url: &CurlUrl) -> String {
    let path = url.get(CurlUPart::Path, CURLU_URLDECODE).unwrap_or_default();
    // The URL path includes the leading '/'; skip it (curl uses `&path[1]`).
    let trimmed = path.strip_prefix('/').unwrap_or(&path);
    if trimmed.is_empty() {
        local_domain()
    } else {
        trimmed.to_string()
    }
}

/// Best-effort local host name for the `EHLO`/`HELO` domain, with curl's
/// `"localhost"` fallback (the safe analog of `Curl_gethostname`).
///
/// Reads the kernel-exposed host name on Linux without `unsafe`; any failure
/// (or an empty result) yields `"localhost"`, matching curl's fallback when
/// `Curl_gethostname` fails.
fn local_domain() -> String {
    for path in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(contents) = std::fs::read_to_string(path) {
            let name = contents.trim();
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    "localhost".to_string()
}

/// Build a [`TlsConfig`] from the easy handle's SSL options, for the
/// `STARTTLS` upgrade.
///
/// Mirrors curl's mapping of `data->set.ssl` onto the TLS backend: the verify
/// flags (`CURLOPT_SSL_VERIFYPEER`/`VERIFYHOST`/`VERIFYSTATUS`), the version
/// window, the raw `CURLSSLOPT_*` bits, and the certificate/CA/cipher string
/// options. Certificate validation stays **on by default** (the [`TlsConfig`]
/// defaults), so `STARTTLS` is secure unless the user explicitly disabled it.
fn tls_config_from_easy(data: &Easy) -> TlsConfig {
    let mut cfg = TlsConfig::default();
    let p = &data.set.ssl.primary;

    cfg.verify_peer = p.verifypeer;
    cfg.verify_host = p.verifyhost;
    cfg.verify_status = p.verifystatus;
    cfg.version = u32::from(p.version);
    cfg.version_max = p.version_max;
    cfg.sessionid = p.cache_session;
    cfg.set_ssl_options(u32::from(p.ssl_options));

    cfg.ca_file = data.set.str(StrId::SslCafile).map(PathBuf::from);
    cfg.ca_path = data.set.str(StrId::SslCapath).map(PathBuf::from);
    cfg.crl_file = data.set.str(StrId::SslCrlfile).map(PathBuf::from);
    cfg.issuer_cert = data.set.str(StrId::SslIssuercert).map(PathBuf::from);
    cfg.cipher_list = data.set.str(StrId::SslCipherList).map(String::from);
    cfg.cipher_list13 = data.set.str(StrId::SslCipher13List).map(String::from);
    cfg.client_cert = data.set.str(StrId::Cert).map(PathBuf::from);
    cfg.client_key = data.set.str(StrId::Key).map(PathBuf::from);
    cfg.key_passwd = data.set.str(StrId::KeyPasswd).map(String::from);
    cfg.cert_type = data.set.str(StrId::CertType).map(String::from);
    cfg.key_type = data.set.str(StrId::KeyType).map(String::from);
    cfg.pinned_pubkey = data.set.str(StrId::SslPinnedPublicKey).map(String::from);

    cfg
}

/// Drive [`PingPong::readresp`] to a complete response, returning the numeric
/// status code (the blocking analog of curl's `Curl_pp_statemach` with
/// `block = TRUE`).
///
/// `readresp` returns a code of `0` when the response is not yet complete (a
/// would-block, or a partial read). Because the underlying transport read
/// awaits readiness, the retry simply suspends until more bytes arrive; the
/// cooperative yield guards against a busy spin if the transport ever reports a
/// would-block without parking. A closed connection surfaces as
/// [`CurlError::RecvError`] from `readresp` and propagates here.
async fn read_response(
    pp: &mut PingPong,
    smtpc: &mut SmtpConn,
    data: &mut Easy,
    conn: &mut Connection,
) -> Result<i32> {
    loop {
        let (code, _size) = pp.readresp(data, conn, FIRSTSOCKET, smtpc).await?;
        if code != 0 {
            return Ok(code);
        }
        tokio::task::yield_now().await;
    }
}

/// Send a fully-buffered byte slice over the connection, looping until every
/// byte is written (the raw-send path used for the dot-stuffed message body,
/// which — unlike [`PingPong::sendf`] — must not have a CRLF appended).
async fn send_all(conn: &mut Connection, mut buf: &[u8]) -> Result<()> {
    while !buf.is_empty() {
        match Curl_conn_send(conn, FIRSTSOCKET, buf, false).await {
            Ok(0) => return Err(CurlError::SendError),
            Ok(n) => buf = &buf[n..],
            Err(CurlError::Again) => tokio::task::yield_now().await,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Send a single SMTP command line, appending the CRLF terminator.
///
/// SMTP commands are written as raw bytes through [`send_all`] rather than via
/// [`PingPong::sendf`]. `sendf` takes `core::fmt::Arguments`, whose backing
/// temporary is **not `Send`** and would be kept alive across the inner
/// `.await`, making the enclosing protocol future non-`Send` — but the
/// [`Protocol`] trait requires `Send` futures. Formatting the command into an
/// owned `String` *before* the await sidesteps that entirely. Responses are
/// still read through [`PingPong::readresp`], whose receive-side bookkeeping is
/// independent of how the command was sent. The verbose `>` trace mirrors
/// curl's `CURLINFO_HEADER_OUT` logging for ping-pong commands.
async fn send_line(data: &Easy, conn: &mut Connection, cmd: &str) -> Result<()> {
    if data.set.verbose {
        crate::infof!(true, "{cmd}");
    }
    let mut line = Vec::with_capacity(cmd.len() + 2);
    line.extend_from_slice(cmd.as_bytes());
    line.extend_from_slice(b"\r\n");
    send_all(conn, &line).await
}

// ===========================================================================
// Connection-state handle + URL/credential helpers
// ===========================================================================

/// Take the per-connection [`SmtpConn`] out of `conn.proto_state`, or create a
/// fresh default one if none has been stored yet.
///
/// Moving the state *out* (leaving `proto_state` empty) releases the borrow of
/// `conn` for the duration of an exchange; the caller restores it with
/// [`Connection::set_proto_state`] when done. Returning a default when absent
/// makes each [`Protocol`] entry point self-sufficient even if
/// [`SmtpProtocol::setup_connection`] was not invoked first.
fn take_smtp_conn(conn: &mut Connection) -> Box<SmtpConn> {
    conn.take_proto_state()
        .and_then(|state| state.downcast::<SmtpConn>().ok())
        .unwrap_or_default()
}

/// Parse the easy handle's URL into a [`CurlUrl`] (with the default port
/// applied), mirroring the URL handling curl performs before `smtp_connect`.
fn parse_url(data: &Easy) -> Result<CurlUrl> {
    let url_str = data.url().ok_or(CurlError::UrlMalformat)?.to_string();
    let mut url = CurlUrl::new();
    url.set(CurlUPart::Url, Some(&url_str), CURLU_DEFAULT_PORT)
        .map_err(|_| CurlError::UrlMalformat)?;
    Ok(url)
}

/// Resolve the `EHLO`/`HELO` domain from the easy handle's URL, falling back to
/// the local host name (`local_domain`) when the URL cannot be parsed.
fn ehlo_domain(data: &Easy) -> String {
    parse_url(data).map_or_else(|_| local_domain(), |url| domain_from_url(&url))
}

/// Resolve the effective username/password, applying curl's precedence: the
/// `CURLOPT_USERNAME`/`CURLOPT_PASSWORD` options override the URL userinfo.
fn resolve_credentials(data: &Easy, url: &CurlUrl) -> (String, String) {
    let user = match data.set.str(StrId::Username) {
        Some(u) => u.to_string(),
        None => url.get(CurlUPart::User, CURLU_URLDECODE).unwrap_or_default(),
    };
    let passwd = match data.set.str(StrId::Password) {
        Some(p) => p.to_string(),
        None => url.get(CurlUPart::Password, CURLU_URLDECODE).unwrap_or_default(),
    };
    (user, passwd)
}

// ===========================================================================
// Connect-phase driver — greeting → EHLO/HELO → STARTTLS → AUTH
// (oracle: smtp_connect + the SMTP_SERVERGREET..SMTP_AUTH state handlers)
// ===========================================================================

/// Send `EHLO <domain>` and read its (possibly multi-line) response, returning
/// the final numeric code.
///
/// Mirrors `smtp_perform_ehlo`: the discovered capabilities and offered SASL
/// mechanisms are reset first (so a re-`EHLO` after `STARTTLS` re-learns them),
/// then the command is sent. Each response line's capabilities are captured by
/// [`PingPongProtocol::endofresp`] as the response streams in.
async fn perform_ehlo(
    pp: &mut PingPong,
    smtpc: &mut SmtpConn,
    data: &mut Easy,
    conn: &mut Connection,
) -> Result<i32> {
    smtpc.sasl.authmechs = SASL_AUTH_NONE;
    smtpc.sasl.authused = SASL_AUTH_NONE;
    smtpc.tls_supported = false;
    smtpc.auth_supported = false;
    smtpc.state = SmtpState::Ehlo;
    let cmd = format!("EHLO {}", smtpc.domain);
    send_line(data, conn, &cmd).await?;
    read_response(pp, smtpc, data, conn).await
}

/// Send `HELO <domain>` (the non-ESMTP fallback) and validate its response.
///
/// Mirrors `smtp_state_helo_resp`: a non-2xx reply is a fatal
/// [`CurlError::RemoteAccessDenied`]; success ends the connect phase (there is
/// no capability discovery or authentication after `HELO`).
async fn perform_helo(
    pp: &mut PingPong,
    smtpc: &mut SmtpConn,
    data: &mut Easy,
    conn: &mut Connection,
) -> Result<()> {
    smtpc.state = SmtpState::Helo;
    let cmd = format!("HELO {}", smtpc.domain);
    send_line(data, conn, &cmd).await?;
    let code = read_response(pp, smtpc, data, conn).await?;
    if code / 100 != 2 {
        crate::failf!(
            &mut conn.filter_data.error_buffer,
            "Remote access denied: {code}"
        );
        return Err(CurlError::RemoteAccessDenied);
    }
    smtpc.state = SmtpState::Stop;
    Ok(())
}

/// Perform the `STARTTLS` upgrade: add the TLS connection filter on top of the
/// already-connected transport (unless TLS is already active) and drive the
/// handshake, mirroring `smtp_perform_upgrade_tls`.
///
/// The TLS configuration is derived from the easy handle's SSL options
/// ([`tls_config_from_easy`]); certificate validation stays on by default. The
/// caller re-issues `EHLO` afterwards.
async fn upgrade_tls(data: &mut Easy, conn: &mut Connection) -> Result<()> {
    if !Curl_conn_is_ssl(conn, FIRSTSOCKET) {
        let config = tls_config_from_easy(data);
        let hostname = conn.remote_host.clone();
        let port = conn.remote_port;
        let pinned = data.set.str(StrId::SslPinnedPublicKey).map(String::from);
        let tls = create_tls_filter(config, hostname, port, pinned, Vec::new());
        Curl_conn_cf_add(conn, FIRSTSOCKET, tls);
    }
    Curl_conn_connect(conn, FIRSTSOCKET, true).await
}

/// Flush any SASL command line queued by the synchronous [`SaslProto`] hooks
/// (`send_auth`/`cont_auth`/`cancel_auth`) through [`PingPong::sendf`].
///
/// The queued bytes are a complete, wire-ready line (mechanism names plus
/// base64 — pure ASCII), so the lossy UTF-8 decode is exact and `sendf` appends
/// the CRLF.
async fn flush_pending(
    smtpc: &mut SmtpConn,
    data: &mut Easy,
    conn: &mut Connection,
) -> Result<()> {
    if let Some(line) = smtpc.pending_auth.take() {
        let line = String::from_utf8_lossy(&line).into_owned();
        send_line(data, conn, &line).await?;
    }
    Ok(())
}

/// Run the SASL exchange to completion against an already-extracted [`Sasl`].
///
/// Mirrors `smtp_perform_authentication` (the `Curl_sasl_start` kickoff) and the
/// `smtp_state_auth_resp` loop (`Curl_sasl_continue`). `sasl` is threaded as a
/// separate `&mut` so it is disjoint from `smtpc` (which serves as the
/// [`SaslProto`] callback target). Each round flushes the command the SASL
/// layer queued, then reads and feeds back the next response code.
async fn perform_auth_inner(
    sasl: &mut Sasl,
    pp: &mut PingPong,
    smtpc: &mut SmtpConn,
    data: &mut Easy,
    conn: &mut Connection,
    params: &SaslParams<'_>,
) -> Result<()> {
    let progress = sasl.start(&mut *smtpc, params, false)?;
    if progress != SaslProgress::InProgress {
        // No usable mechanism could be selected (`Curl_sasl_is_blocked`).
        return sasl.is_blocked();
    }
    flush_pending(smtpc, data, conn).await?;
    smtpc.state = SmtpState::Auth;

    loop {
        let code = read_response(pp, smtpc, data, conn).await?;
        let progress = sasl.cont(&mut *smtpc, params, code)?;
        flush_pending(smtpc, data, conn).await?;
        match progress {
            SaslProgress::Done => return Ok(()),
            SaslProgress::Idle => {
                crate::failf!(
                    &mut conn.filter_data.error_buffer,
                    "Authentication cancelled"
                );
                return Err(CurlError::LoginDenied);
            }
            SaslProgress::InProgress => {}
        }
    }
}

/// The complete connect-phase exchange: greeting, `EHLO` (with `HELO` fallback),
/// the optional `STARTTLS` upgrade with a re-`EHLO`, and SASL authentication.
async fn connect_session(
    pp: &mut PingPong,
    smtpc: &mut SmtpConn,
    data: &mut Easy,
    conn: &mut Connection,
    user: &str,
    passwd: &str,
) -> Result<()> {
    // Set the default preferred authentication mechanism set up front
    // (`Curl_sasl_init` in `smtp_connect`). This populates `prefmech` from
    // `def_mechs()` and the `CURLOPT_HTTPAUTH` bits; it also clears
    // `authmechs`, which is why it must run *before* EHLO learns the
    // server-offered mechanisms. `init` only reads `def_mechs()` from the
    // proto, so taking `sasl` out momentarily is safe.
    {
        let mut sasl = std::mem::take(&mut smtpc.sasl);
        sasl.init(&*smtpc, data.set.httpauth);
        smtpc.sasl = sasl;
    }

    // --- Server greeting (smtp_state_servergreet_resp). ---
    smtpc.state = SmtpState::ServerGreet;
    let code = read_response(pp, smtpc, data, conn).await?;
    if code / 100 != 2 {
        crate::failf!(
            &mut conn.filter_data.error_buffer,
            "Got unexpected smtp-server response: {code}"
        );
        return Err(CurlError::WeirdServerReply);
    }

    let use_ssl = data.set.use_ssl;

    // --- EHLO (smtp_state_ehlo_resp), with HELO fallback. ---
    let ehlo_code = perform_ehlo(pp, smtpc, data, conn).await?;
    if ehlo_code / 100 != 2 {
        if use_ssl <= CURLUSESSL_TRY || Curl_conn_is_ssl(conn, FIRSTSOCKET) {
            return perform_helo(pp, smtpc, data, conn).await;
        }
        crate::failf!(
            &mut conn.filter_data.error_buffer,
            "Remote access denied: {ehlo_code}"
        );
        return Err(CurlError::RemoteAccessDenied);
    }

    // EHLO succeeded; capabilities are captured in `smtpc`. Decide on STARTTLS.
    if use_ssl != CURLUSESSL_NONE && !Curl_conn_is_ssl(conn, FIRSTSOCKET) {
        if smtpc.tls_supported {
            // STARTTLS (smtp_perform_starttls / smtp_state_starttls_resp).
            smtpc.state = SmtpState::StartTls;
            send_line(data, conn, "STARTTLS").await?;
            let code = read_response(pp, smtpc, data, conn).await?;
            if code != SMTP_RESP_SERVICE_READY {
                if use_ssl != CURLUSESSL_TRY {
                    crate::failf!(
                        &mut conn.filter_data.error_buffer,
                        "STARTTLS denied, code {code}"
                    );
                    return Err(CurlError::UseSslFailed);
                }
                // CURLUSESSL_TRY: carry on without TLS.
            } else {
                // Upgrade then re-EHLO (smtp_perform_upgrade_tls).
                smtpc.state = SmtpState::UpgradeTls;
                upgrade_tls(data, conn).await?;
                let ehlo_code = perform_ehlo(pp, smtpc, data, conn).await?;
                if ehlo_code / 100 != 2 {
                    if use_ssl <= CURLUSESSL_TRY || Curl_conn_is_ssl(conn, FIRSTSOCKET) {
                        return perform_helo(pp, smtpc, data, conn).await;
                    }
                    crate::failf!(
                        &mut conn.filter_data.error_buffer,
                        "Remote access denied: {ehlo_code}"
                    );
                    return Err(CurlError::RemoteAccessDenied);
                }
            }
        } else if use_ssl == CURLUSESSL_TRY {
            // No STARTTLS but only requested: continue unencrypted.
        } else {
            crate::failf!(&mut conn.filter_data.error_buffer, "STARTTLS not supported.");
            return Err(CurlError::UseSslFailed);
        }
    }

    // --- Authentication (smtp_perform_authentication). ---
    if !smtpc.auth_supported || !smtpc.sasl.can_authenticate(user) {
        smtpc.state = SmtpState::Stop;
        return Ok(());
    }
    // Build owned credential locals so the SASL params borrow *them*, not
    // `data` — leaving `data` free as `&mut` for the response reads.
    let host = conn.remote_host.clone();
    let port = conn.remote_port;
    let authzid = data
        .set
        .str(StrId::SaslAuthzid)
        .unwrap_or_default()
        .to_string();
    let service_name = data.set.str(StrId::ServiceName).map(String::from);
    let bearer = data.set.str(StrId::Bearer).map(String::from);
    let sasl_ir = data.set.sasl_ir;
    let allow_auth_to_other_hosts = data.set.allow_auth_to_other_hosts;
    let params = SaslParams {
        user,
        passwd,
        authzid: &authzid,
        host: &host,
        port,
        service_name: service_name.as_deref(),
        bearer: bearer.as_deref(),
        sasl_ir,
        allow_auth_to_other_hosts,
        this_is_a_follow: false,
    };
    let mut sasl = std::mem::take(&mut smtpc.sasl);
    let result = perform_auth_inner(&mut sasl, pp, smtpc, data, conn, &params).await;
    smtpc.sasl = sasl;
    result?;

    smtpc.state = SmtpState::Stop;
    Ok(())
}

/// Ensure the connect-phase session is established exactly once on this
/// connection.
///
/// Drives the transport connect (which performs implicit TLS for `smtps`), then
/// runs [`connect_session`] (greeting → `EHLO`/`HELO` → optional `STARTTLS` →
/// `AUTH`) the first time, and records [`SmtpConn::session_established`] so a
/// subsequent [`Protocol::do_it`] (or a future engine that calls
/// [`Protocol::connect`] first) does not repeat the handshake.
async fn ensure_session(
    pp: &mut PingPong,
    smtpc: &mut SmtpConn,
    data: &mut Easy,
    conn: &mut Connection,
) -> Result<()> {
    if smtpc.session_established {
        return Ok(());
    }
    if smtpc.domain.is_empty() {
        smtpc.domain = ehlo_domain(data);
    }
    // Make sure the transport (and, for `smtps`, the implicit TLS filter) is
    // connected before any SMTP chatter (`Curl_conn_connect`, idempotent).
    Curl_conn_connect(conn, FIRSTSOCKET, true).await?;

    // Resolve credentials before borrowing `data` mutably for the exchange.
    let (user, passwd) = match parse_url(data) {
        Ok(url) => resolve_credentials(data, &url),
        Err(_) => (
            data.set.str(StrId::Username).unwrap_or_default().to_string(),
            data.set.str(StrId::Password).unwrap_or_default().to_string(),
        ),
    };

    connect_session(pp, smtpc, data, conn, &user, &passwd).await?;
    smtpc.session_established = true;
    Ok(())
}

// ===========================================================================
// DO-phase driver — the mail-send sequence and the custom-command path
// (oracle: smtp_perform + smtp_state_{mail,rcpt,data,postdata,command}_resp)
// ===========================================================================

/// Run the full mail-send transaction over an established session: `MAIL FROM`
/// → one `RCPT TO` per recipient → `DATA` → the dot-stuffed body → the final
/// `250` acceptance.
///
/// Mirrors `smtp_perform_mail`, `smtp_state_rcpt_resp` (including the
/// `CURLOPT_MAIL_RCPT_ALLOWFAILS` tolerance), `smtp_state_data_resp`, the
/// `cr_eob_read` body escaping, and `smtp_state_postdata_resp`.
#[allow(clippy::too_many_arguments)]
async fn run_mail_transaction(
    pp: &mut PingPong,
    smtpc: &mut SmtpConn,
    data: &mut Easy,
    conn: &mut Connection,
    smtp: &Smtp,
    body: &[u8],
    utf8: bool,
    allowfails: bool,
    verbose: bool,
) -> Result<()> {
    use std::fmt::Write as _;

    // --- MAIL FROM (smtp_perform_mail / smtp_state_mail_resp). ---
    let mut cmd = format!("MAIL FROM:{}", smtp.from);
    if let Some(auth) = &smtp.auth {
        cmd.push_str(" AUTH=");
        cmd.push_str(auth);
    }
    if let Some(size) = smtp.size {
        // Infallible write into a String.
        let _ = write!(cmd, " SIZE={size}");
    }
    if utf8 {
        cmd.push_str(" SMTPUTF8");
    }
    smtpc.state = SmtpState::Mail;
    send_line(data, conn, &cmd).await?;
    let code = read_response(pp, smtpc, data, conn).await?;
    if code / 100 != 2 {
        crate::failf!(&mut conn.filter_data.error_buffer, "MAIL failed: {code}");
        return Err(CurlError::SendError);
    }

    // --- RCPT TO, one command per recipient (smtp_state_rcpt_resp). ---
    let mut rcpt_had_ok = false;
    let mut rcpt_last_error: i32 = 0;
    for rcpt in &smtp.rcpt {
        let (address, host, suffix) = parse_address(rcpt);
        let cmd = match host {
            Some(ref h) => format!("RCPT TO:<{address}@{h}>{suffix}"),
            None => format!("RCPT TO:<{address}>{suffix}"),
        };
        smtpc.state = SmtpState::Rcpt;
        send_line(data, conn, &cmd).await?;
        let code = read_response(pp, smtpc, data, conn).await?;
        if code / 100 != 2 {
            // A recipient was rejected. Remember it so we can report the last
            // failure if every recipient fails.
            rcpt_last_error = code;
            if !allowfails {
                crate::failf!(&mut conn.filter_data.error_buffer, "RCPT failed: {code}");
                return Err(CurlError::SendError);
            }
        } else {
            rcpt_had_ok = true;
        }
    }
    if !rcpt_had_ok {
        crate::failf!(
            &mut conn.filter_data.error_buffer,
            "RCPT failed: {rcpt_last_error} (last error)"
        );
        return Err(CurlError::SendError);
    }

    // --- DATA (smtp_state_data_resp). ---
    smtpc.state = SmtpState::Data;
    send_line(data, conn, "DATA").await?;
    let code = read_response(pp, smtpc, data, conn).await?;
    if code != SMTP_RESP_DATA {
        crate::failf!(&mut conn.filter_data.error_buffer, "DATA failed: {code}");
        return Err(CurlError::SendError);
    }

    // --- Stream the body with EOB escaping, then the terminator. ---
    // `dot_stuff` produces the on-the-wire bytes including the trailing
    // `<CRLF>.<CRLF>` (cr_eob_read). The body is sent outside the ping-pong
    // command framing.
    let wire = dot_stuff(body);
    send_all(conn, &wire).await?;

    // --- Final acceptance (smtp_state_postdata_resp expects 250). ---
    smtpc.state = SmtpState::PostData;
    let code = read_response(pp, smtpc, data, conn).await?;
    if code != SMTP_RESP_OK {
        crate::failf!(
            &mut conn.filter_data.error_buffer,
            "Mail not accepted: {code}"
        );
        return Err(CurlError::WeirdServerReply);
    }
    crate::infof!(verbose, "SMTP mail accepted ({code})");
    smtpc.state = SmtpState::Stop;
    Ok(())
}

/// Build a `VRFY` command line for one recipient (`smtp_perform_command`, the
/// no-custom branch). `VRFY` takes a bare address (no angle brackets), with the
/// host appended after `@` and an optional ` SMTPUTF8` for non-ASCII mailboxes.
fn build_vrfy(smtpc: &SmtpConn, rcpt: &str) -> String {
    let (address, host, _suffix) = parse_address(rcpt);
    let utf8 = smtpc.utf8_supported
        && (has_non_ascii(&address) || host.as_deref().is_some_and(has_non_ascii));
    let utf8_suffix = if utf8 { " SMTPUTF8" } else { "" };
    match host {
        Some(h) => format!("VRFY {address}@{h}{utf8_suffix}"),
        None => format!("VRFY {address}{utf8_suffix}"),
    }
}

/// Run the non-send command path (`VRFY`/`EXPN`/`NOOP`/`RSET`/`HELP`).
///
/// Mirrors `smtp_perform_command` and `smtp_state_command_resp`: with a
/// recipient list, one command is issued per recipient (`VRFY <addr>`, or
/// `<custom> <rcpt>` for an explicit request such as `EXPN`); with no recipient,
/// a single bare command (the custom verb, or `HELP`) is sent. A `2xx` reply is
/// required (with `553` additionally tolerated for the per-recipient path).
async fn run_command(
    pp: &mut PingPong,
    smtpc: &mut SmtpConn,
    data: &mut Easy,
    conn: &mut Connection,
    smtp: &Smtp,
    verbose: bool,
) -> Result<()> {
    if smtp.rcpt.is_empty() {
        // Non-recipient command such as NOOP/RSET/HELP (smtp_perform_command,
        // else branch). An empty/absent custom verb defaults to HELP.
        let cmd = match &smtp.custom {
            Some(c) if !c.is_empty() => c.clone(),
            _ => "HELP".to_string(),
        };
        smtpc.state = SmtpState::Command;
        send_line(data, conn, &cmd).await?;
        let code = read_response(pp, smtpc, data, conn).await?;
        if code / 100 != 2 {
            crate::failf!(&mut conn.filter_data.error_buffer, "Command failed: {code}");
            return Err(CurlError::WeirdServerReply);
        }
        crate::infof!(verbose, "SMTP command response ({code})");
    } else {
        // One command per recipient (smtp_state_command_resp advances the
        // recipient list after each reply).
        for rcpt in &smtp.rcpt {
            let cmd = match &smtp.custom {
                // No custom verb (or empty) → VRFY the recipient.
                None => build_vrfy(smtpc, rcpt),
                Some(c) if c.is_empty() => build_vrfy(smtpc, rcpt),
                // Explicit recipient command (e.g. EXPN) → "<custom> <rcpt>".
                Some(c) => {
                    let utf8 = smtpc.utf8_supported && c == "EXPN";
                    let utf8_suffix = if utf8 { " SMTPUTF8" } else { "" };
                    format!("{c} {rcpt}{utf8_suffix}")
                }
            };
            smtpc.state = SmtpState::Command;
            send_line(data, conn, &cmd).await?;
            let code = read_response(pp, smtpc, data, conn).await?;
            // A 2xx reply is required; 553 (mailbox not allowed) is tolerated
            // for recipient-verification commands, matching the C predicate.
            if code / 100 != 2 && code != SMTP_RESP_MBOX_NOT_ALLOWED {
                crate::failf!(&mut conn.filter_data.error_buffer, "Command failed: {code}");
                return Err(CurlError::WeirdServerReply);
            }
        }
        crate::infof!(verbose, "SMTP command(s) complete");
    }
    smtpc.state = SmtpState::Stop;
    Ok(())
}

/// Send `QUIT` and read the `221` closing reply on a best-effort basis
/// (`smtp_perform_quit`).
async fn perform_quit(
    pp: &mut PingPong,
    smtpc: &mut SmtpConn,
    data: &mut Easy,
    conn: &mut Connection,
) -> Result<()> {
    smtpc.state = SmtpState::Quit;
    send_line(data, conn, "QUIT").await?;
    // The closing `221` is informational; read it but tolerate the server
    // simply dropping the connection.
    let _ = read_response(pp, smtpc, data, conn).await?;
    Ok(())
}

// ===========================================================================
// `Protocol` implementation
// ===========================================================================

impl Protocol for SmtpProtocol {
    fn scheme(&self) -> &'static Scheme {
        self.scheme
    }

    fn setup_connection<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Allocate per-connection SMTP state and pre-compute the EHLO domain
            // (C `smtp_setup_connection` / the meta allocation in `smtp_connect`).
            let mut smtpc = take_smtp_conn(conn);
            if smtpc.domain.is_empty() {
                smtpc.domain = ehlo_domain(data);
            }
            conn.set_proto_state(smtpc);
            Ok(())
        })
    }

    fn connect<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut smtpc = take_smtp_conn(conn);
            let mut pp = std::mem::take(&mut smtpc.pp);
            let result = ensure_session(&mut pp, &mut smtpc, data, conn).await;
            smtpc.pp = pp;
            conn.set_proto_state(smtpc);
            result
        })
    }

    fn do_it<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<ProtocolTransfer>> {
        Box::pin(async move {
            // Extract the per-request configuration up front so the mutable
            // borrows of `data` are released before the connection is borrowed
            // for I/O (the same discipline the MQTT handler uses).
            let verbose = data.set.verbose;
            let allowfails = data.set.mail_rcpt_allowfails;
            let custom = data.set.str(StrId::Customrequest).map(String::from);
            let mail_from_raw = data.set.str(StrId::MailFrom).map(String::from);
            let mail_auth_raw = data.set.str(StrId::MailAuth).map(String::from);
            let rcpt_raw: Vec<String> = data
                .set
                .mail_rcpt
                .as_ref()
                .map(|list| {
                    list.as_slice()
                        .iter()
                        .map(|c| c.to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default();
            // The message body is taken from the safe `copypostfields` buffer;
            // raw `postfields` pointers are an FFI concern and are not
            // dereferenced in the safe core.
            let body = data.set.copypostfields.clone().unwrap_or_default();
            let has_body = data.set.copypostfields.is_some() || data.set.postfields.is_some();

            // A mail transfer requires upload data and at least one recipient
            // (C: `(upload || MIME) && mail_rcpt`); otherwise this is a
            // command-only exchange (VRFY/EXPN/NOOP/RSET/HELP).
            let do_mail = has_body && !rcpt_raw.is_empty();

            // Acquire the connection state and detach the ping-pong engine so it
            // is disjoint from `smtpc` (the response/SASL callback target).
            let mut smtpc = take_smtp_conn(conn);
            let mut pp = std::mem::take(&mut smtpc.pp);

            // Run the exchange in a sub-scope so we always restore state below.
            let outcome: Result<TransferDirection> = async {
                ensure_session(&mut pp, &mut smtpc, data, conn).await?;

                if do_mail {
                    // Render the envelope now that EHLO capabilities are known
                    // (SMTPUTF8 / SIZE availability live on `smtpc`).
                    let mut utf8 = false;
                    let from = if let Some(mf) = &mail_from_raw {
                        let (address, host, suffix) = parse_address(mf);
                        utf8 = smtpc.utf8_supported
                            && (has_non_ascii(&address)
                                || host.as_deref().is_some_and(has_non_ascii));
                        format_mailbox(&address, host.as_deref(), &suffix)
                    } else {
                        // Null reverse-path, RFC 5321 §3.6.3.
                        "<>".to_string()
                    };

                    let auth = if mail_auth_raw.is_some()
                        && smtpc.sasl.authused != SASL_AUTH_NONE
                    {
                        let raw = mail_auth_raw.as_deref().unwrap_or("");
                        if raw.is_empty() {
                            // Empty AUTH, RFC 2554 §5.
                            Some("<>".to_string())
                        } else {
                            let (address, host, suffix) = parse_address(raw);
                            if !utf8
                                && smtpc.utf8_supported
                                && (has_non_ascii(&address)
                                    || host.as_deref().is_some_and(has_non_ascii))
                            {
                                utf8 = true;
                            }
                            Some(format_mailbox(&address, host.as_deref(), &suffix))
                        }
                    } else {
                        None
                    };

                    let size = if smtpc.size_supported && !body.is_empty() {
                        Some(body.len() as u64)
                    } else {
                        None
                    };

                    // If neither the FROM nor AUTH mailbox forced SMTPUTF8, scan
                    // the recipients for non-ASCII (RFC 6531 §3.4).
                    if smtpc.utf8_supported && !utf8 {
                        utf8 = rcpt_raw.iter().any(|r| has_non_ascii(r));
                    }

                    let smtp = Smtp {
                        from,
                        rcpt: rcpt_raw,
                        custom,
                        auth,
                        size,
                    };
                    run_mail_transaction(
                        &mut pp, &mut smtpc, data, conn, &smtp, &body, utf8, allowfails, verbose,
                    )
                    .await?;
                    Ok(TransferDirection::Upload)
                } else {
                    let smtp = Smtp {
                        from: String::new(),
                        rcpt: rcpt_raw,
                        custom,
                        auth: None,
                        size: None,
                    };
                    run_command(&mut pp, &mut smtpc, data, conn, &smtp, verbose).await?;
                    Ok(TransferDirection::Download)
                }
            }
            .await;

            // Restore the connection state regardless of success or failure.
            smtpc.pp = pp;
            conn.set_proto_state(smtpc);

            outcome.map(ProtocolTransfer::new)
        })
    }

    fn done<'a>(
        &'a self,
        _data: &'a mut Easy,
        _conn: &'a mut Connection,
        status: Result<()>,
        _premature: bool,
    ) -> BoxFuture<'a, Result<()>> {
        // The full transaction (including the post-data `250`) completes within
        // `do_it`, so finalization only needs to propagate the transfer status.
        Box::pin(async move { status })
    }

    fn disconnect<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
        dead: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut smtpc = take_smtp_conn(conn);
            // Only attempt a graceful QUIT on a live connection that actually
            // negotiated a session (C `smtp_disconnect`: skip on a dead or
            // never-started connection). Errors are swallowed — the connection
            // is going away regardless.
            if !dead && smtpc.session_established {
                let mut pp = std::mem::take(&mut smtpc.pp);
                let _ = perform_quit(&mut pp, &mut smtpc, data, conn).await;
                smtpc.pp = pp;
            }
            conn.set_proto_state(smtpc);
            Ok(())
        })
    }
}


// ===========================================================================
// Response parsing — free helpers for the `PingPongProtocol` impl
// ===========================================================================

/// Parse the leading run of ASCII digits of a response line into its numeric
/// status code (curl's `curlx_str_number` over the response prefix).
///
/// The caller has already verified that at least the first three bytes are
/// digits, so this always yields a value. SMTP status codes are three digits;
/// parsing the leading digit run reproduces curl's behavior for both the
/// `"NNN "`-prefixed lines and the bare `"NNN\r\n"` (`len == 5`) form.
fn parse_code(line: &[u8]) -> Option<i32> {
    let mut code: i32 = 0;
    let mut seen = false;
    for &b in line {
        if b.is_ascii_digit() {
            code = code.checked_mul(10)?.checked_add(i32::from(b - b'0'))?;
            seen = true;
        } else {
            break;
        }
    }
    seen.then_some(code)
}

/// Parse one `EHLO` response line for an advertised capability and record it on
/// `smtpc`, reproducing the capability scan of `smtp_state_ehlo_resp`.
///
/// The 4-byte `"NNN-"`/`"NNN "` response prefix is skipped, then the remainder
/// is matched (case-insensitively) against `STARTTLS`, `SIZE`, `SMTPUTF8`, and
/// `AUTH `. For `AUTH `, the space-separated mechanism tokens that follow are
/// decoded via [`decode_mech`] and OR-ed into the offered-mechanism set, exactly
/// as curl does (a token contributes only when it decodes to a known mechanism
/// *and* the decoded length equals the whole token, i.e. an exact match).
fn parse_ehlo_line(smtpc: &mut SmtpConn, line: &[u8]) {
    if line.len() < 4 {
        return;
    }
    // Skip the "NNN-" / "NNN " response-code prefix (C `line += 4; len -= 4`).
    let rest = &line[4..];

    if rest.len() >= 8 && rest[..8].eq_ignore_ascii_case(b"STARTTLS") {
        smtpc.tls_supported = true;
    } else if rest.len() >= 4 && rest[..4].eq_ignore_ascii_case(b"SIZE") {
        smtpc.size_supported = true;
    } else if rest.len() >= 8 && rest[..8].eq_ignore_ascii_case(b"SMTPUTF8") {
        smtpc.utf8_supported = true;
    } else if rest.len() >= 5 && rest[..5].eq_ignore_ascii_case(b"AUTH ") {
        smtpc.auth_supported = true;

        // Advance past the "AUTH " keyword and tokenize the mechanism list.
        let mut p = &rest[5..];
        loop {
            // Skip blanks/newlines between mechanisms (ISBLANK || ISNEWLINE).
            while let Some(&b) = p.first() {
                if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
                    p = &p[1..];
                } else {
                    break;
                }
            }
            if p.is_empty() {
                break;
            }
            // Extract the next word (up to the next blank/newline).
            let mut wordlen = 0;
            while wordlen < p.len() && !matches!(p[wordlen], b' ' | b'\t' | b'\r' | b'\n') {
                wordlen += 1;
            }
            // Decode against the known mechanisms. Pass the full remaining slice
            // with `maxlen == wordlen` so the word-boundary check matches curl.
            let (mechbit, decoded) = decode_mech(p, wordlen);
            if mechbit != 0 && decoded == wordlen {
                smtpc.sasl.authmechs |= mechbit;
            }
            p = &p[wordlen..];
        }
    }
}

// ===========================================================================
// `PingPongProtocol` implementation — the surviving per-line callbacks
// ===========================================================================

impl PingPongProtocol for SmtpConn {
    /// One iteration of the command/response loop.
    ///
    /// The SMTP engine drives its exchanges with a straight-line async
    /// sequence (see [`connect_session`] and [`run_mail_transaction`]) that owns
    /// the detached [`PingPong`], rather than re-entering through this hook, so
    /// there is no work to do here. Returning `Ok(())` keeps the engine's
    /// generic drive loop satisfied if it is ever invoked.
    fn statemachine<'a>(
        &'a mut self,
        _data: &'a mut Easy,
        _conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { Ok(()) })
    }

    /// Decide whether `line` is the final line of an SMTP response, returning
    /// its numeric code, and capture any `EHLO` capabilities along the way.
    ///
    /// This is a byte-exact port of `smtp_endofresp`. SMTP frames multi-line
    /// responses by the **fourth byte** after the three-digit code: a space
    /// (`"250 OK"`) marks the *final* line, a hyphen (`"250-PIPELINING"`) marks
    /// a *continuation*. A bare `"NNN\r\n"` line (`len == 5`, no text) is also
    /// final, as some servers omit the trailing text. Continuation framing is
    /// only honored in the [`Ehlo`](SmtpState::Ehlo) and
    /// [`Command`](SmtpState::Command) states, matching curl.
    ///
    /// Because the ping-pong engine discards continuation lines (it returns only
    /// on the final line), this hook is also where `EHLO` capabilities are
    /// harvested — from every line, continuation and final alike — and where the
    /// final line is stashed in [`SmtpConn::last_final_line`] for
    /// [`SaslProto::get_message`].
    fn endofresp(&mut self, _data: &mut Easy, _conn: &mut Connection, line: &[u8]) -> Option<i32> {
        self.classify_response(line)
    }
}

impl SmtpConn {
    /// The pure, I/O-free core of [`PingPongProtocol::endofresp`] — a byte-exact
    /// port of `smtp_endofresp` that also harvests `EHLO` capabilities and
    /// stashes the final line. Split out so it is directly unit-testable without
    /// constructing an [`Easy`]/[`Connection`].
    fn classify_response(&mut self, line: &[u8]) -> Option<i32> {
        // Need three leading digits plus the discriminating fourth byte.
        if line.len() < 4
            || !line[0].is_ascii_digit()
            || !line[1].is_ascii_digit()
            || !line[2].is_ascii_digit()
        {
            return None;
        }

        // Final line: a space after the code, or a bare "NNN\r\n".
        if line[3] == b' ' || line.len() == 5 {
            let code = parse_code(line)?;
            if self.state == SmtpState::Ehlo {
                parse_ehlo_line(self, line);
            }
            // Stash the final line for the SASL challenge accessor.
            self.last_final_line.clear();
            self.last_final_line.extend_from_slice(line);
            return Some(code);
        }

        // Continuation line ("NNN-…"), only meaningful in EHLO/COMMAND.
        if line[3] == b'-' && (self.state == SmtpState::Ehlo || self.state == SmtpState::Command) {
            if self.state == SmtpState::Ehlo {
                parse_ehlo_line(self, line);
            }
            return None;
        }

        // Anything else is not a recognized end-of-response.
        None
    }
}

// ===========================================================================
// `SaslProto` implementation — the C `saslsmtp` vtable
// ===========================================================================

impl SaslProto for SmtpConn {
    fn service(&self) -> &str {
        "smtp"
    }

    fn maxirlen(&self) -> usize {
        // SMTP bounds the initial-response length (unlike IMAP/POP3): the AUTH
        // command line must fit the 512-octet limit (`512 - strlen("AUTH ") - …`).
        SMTP_AUTH_MAXIRLEN
    }

    fn cont_code(&self) -> i32 {
        SMTP_RESP_CONTINUE
    }

    fn final_code(&self) -> i32 {
        SMTP_RESP_AUTH_OK
    }

    fn def_mechs(&self) -> u16 {
        SASL_AUTH_DEFAULT
    }

    fn flags(&self) -> u16 {
        SASL_FLAG_BASE64
    }

    /// Queue `AUTH <mech>` (or `AUTH <mech> <ir>` with an inline initial
    /// response), mirroring `smtp_perform_auth`.
    ///
    /// The bytes are queued for the async driver to flush; the SASL layer has
    /// already base64-encoded `initial_resp` (so it is pure ASCII).
    fn send_auth(&mut self, mech: &str, initial_resp: Option<&[u8]>) -> Result<()> {
        let line = match initial_resp {
            Some(ir) => {
                let ir = String::from_utf8_lossy(ir);
                format!("AUTH {mech} {ir}")
            }
            None => format!("AUTH {mech}"),
        };
        self.pending_auth = Some(line.into_bytes());
        Ok(())
    }

    /// Queue a continuation line carrying the (already base64-encoded) `resp`,
    /// mirroring `smtp_continue_auth`. An empty `resp` queues an empty line.
    fn cont_auth(&mut self, _mech: &str, resp: &[u8]) -> Result<()> {
        self.pending_auth = Some(resp.to_vec());
        Ok(())
    }

    /// Queue the cancellation token `*`, mirroring `smtp_cancel_auth`.
    fn cancel_auth(&mut self, _mech: &str) -> Result<()> {
        self.pending_auth = Some(b"*".to_vec());
        Ok(())
    }

    /// Extract the server's SASL challenge from the most recent final response
    /// line, reproducing `smtp_get_message`.
    ///
    /// The 4-byte response prefix is dropped, leading blanks are skipped, and
    /// trailing blanks/newlines are trimmed; a line of four bytes or fewer
    /// yields an empty message.
    fn get_message(&mut self) -> Result<Vec<u8>> {
        let line = &self.last_final_line;
        if line.len() > 4 {
            // Skip the 4-char "NNN " prefix, then leading blanks (ISBLANK).
            let mut msg = &line[4..];
            while let Some(&b) = msg.first() {
                if matches!(b, b' ' | b'\t') {
                    msg = &msg[1..];
                } else {
                    break;
                }
            }
            // Trim trailing newlines and blanks (ISNEWLINE || ISBLANK).
            let mut end = msg.len();
            while end > 0 && matches!(msg[end - 1], b' ' | b'\t' | b'\r' | b'\n') {
                end -= 1;
            }
            Ok(msg[..end].to_vec())
        } else {
            Ok(Vec::new())
        }
    }
}

// ===========================================================================
// Unit tests — pure parsing/formatting logic (no network I/O)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::sasl::{SASL_MECH_LOGIN, SASL_MECH_PLAIN};

    /// Construct a default [`SmtpConn`] pinned to a particular response-parsing
    /// state. Used by the parser tests so the `state`-dependent `NNN-`/`NNN `
    /// continuation logic and EHLO capability capture can be exercised without
    /// standing up a real connection.
    fn conn_in(state: SmtpState) -> SmtpConn {
        SmtpConn {
            state,
            ..Default::default()
        }
    }

    // ----- dot-stuffing (cr_eob_read parity) -------------------------------

    #[test]
    fn dot_stuff_doubles_leading_dot_and_terminates() {
        // A line starting with '.' is doubled; body already ending in CRLF only
        // needs the bare ".\r\n" appended.
        assert_eq!(dot_stuff(b".foo\r\n"), b"..foo\r\n.\r\n");
    }

    #[test]
    fn dot_stuff_appends_full_terminator_when_no_trailing_crlf() {
        assert_eq!(dot_stuff(b"foo"), b"foo\r\n.\r\n");
    }

    #[test]
    fn dot_stuff_empty_body_is_just_terminator() {
        assert_eq!(dot_stuff(b""), b".\r\n");
    }

    #[test]
    fn dot_stuff_interior_dot_line_is_stuffed() {
        // "a\r\n.b\r\n": the '.' after the interior CRLF starts a line and is
        // doubled; the body already ends with CRLF so just ".\r\n" follows.
        assert_eq!(dot_stuff(b"a\r\n.b\r\n"), b"a\r\n..b\r\n.\r\n");
    }

    #[test]
    fn dot_stuff_body_ending_in_crlf_dot_escapes_trailing_dot() {
        // n_eob reaches 3 ("\r\n."): the terminator escapes the dot, yielding
        // ".\r\n.\r\n" appended (the C `case 3` branch).
        assert_eq!(dot_stuff(b"x\r\n."), b"x\r\n..\r\n.\r\n");
    }

    #[test]
    fn dot_stuff_does_not_double_interior_non_line_start_dot() {
        // The '.' in "a.b" is not at a line start, so it is left untouched.
        assert_eq!(dot_stuff(b"a.b\r\n"), b"a.b\r\n.\r\n");
    }

    // ----- mailbox parsing / formatting (smtp_parse_address) ---------------

    #[test]
    fn parse_address_bracketed_with_host() {
        let (addr, host, suffix) = parse_address("<user@example.com>");
        assert_eq!(addr, "user");
        assert_eq!(host.as_deref(), Some("example.com"));
        assert_eq!(suffix, "");
    }

    #[test]
    fn parse_address_bracketed_with_suffix() {
        let (addr, host, suffix) = parse_address("<user@example.com> SIZE=10");
        assert_eq!(addr, "user");
        assert_eq!(host.as_deref(), Some("example.com"));
        assert_eq!(suffix, " SIZE=10");
    }

    #[test]
    fn parse_address_unbracketed_no_host() {
        let (addr, host, suffix) = parse_address("Postmaster");
        assert_eq!(addr, "Postmaster");
        assert_eq!(host, None);
        assert_eq!(suffix, "");
    }

    #[test]
    fn parse_address_unbracketed_trailing_angle_stripped() {
        // No leading '<' but a trailing '>' is dropped (C's `dup[length-1]`).
        let (addr, host, _suffix) = parse_address("user@host>");
        assert_eq!(addr, "user");
        assert_eq!(host.as_deref(), Some("host"));
    }

    #[test]
    fn format_mailbox_with_and_without_host() {
        assert_eq!(format_mailbox("user", Some("h.com"), ""), "<user@h.com>");
        assert_eq!(format_mailbox("user", None, ""), "<user>");
        assert_eq!(
            format_mailbox("u", Some("h"), " SMTPUTF8"),
            "<u@h> SMTPUTF8"
        );
    }

    #[test]
    fn has_non_ascii_detects_utf8() {
        assert!(!has_non_ascii("plain.ascii@host"));
        assert!(has_non_ascii("nø[email protected]"));
    }

    // ----- response code parsing -------------------------------------------

    #[test]
    fn parse_code_reads_three_digit_code() {
        assert_eq!(parse_code(b"250 OK\r\n"), Some(250));
        assert_eq!(parse_code(b"220\r\n"), Some(220));
        assert_eq!(parse_code(b"334 challenge\r\n"), Some(334));
        assert_eq!(parse_code(b"not-a-code"), None);
    }

    // ----- endofresp NNN- / NNN<space> discrimination ----------------------

    #[test]
    fn endofresp_final_line_with_space_returns_code() {
        let mut c = conn_in(SmtpState::ServerGreet);
        // "220 ready\r\n" — fourth byte is a space → final line, code 220.
        assert_eq!(c.classify_response(b"220 ready\r\n"), Some(220));
    }

    #[test]
    fn endofresp_continuation_line_returns_none_in_ehlo() {
        let mut c = conn_in(SmtpState::Ehlo);
        // "250-PIPELINING\r\n" — fourth byte is '-' → continuation (None).
        assert_eq!(c.classify_response(b"250-PIPELINING\r\n"), None);
    }

    #[test]
    fn endofresp_continuation_dash_ignored_outside_ehlo_command() {
        let mut c = conn_in(SmtpState::Mail); // not EHLO/COMMAND
        // A '-' fourth byte is not a recognized continuation here.
        assert_eq!(c.classify_response(b"250-text\r\n"), None);
        // And a final-form line is still recognized.
        assert_eq!(c.classify_response(b"250 ok\r\n"), Some(250));
    }

    #[test]
    fn endofresp_bare_code_line_len5_is_final() {
        let mut c = conn_in(SmtpState::ServerGreet);
        // "250\r\n" has length 5, no space at [3] (it is '\r') → final via len==5.
        assert_eq!(c.classify_response(b"250\r\n"), Some(250));
    }

    #[test]
    fn endofresp_rejects_short_or_non_numeric() {
        let mut c = conn_in(SmtpState::Ehlo);
        assert_eq!(c.classify_response(b"25\r\n"), None);
        assert_eq!(c.classify_response(b"2x0 hi\r\n"), None);
    }

    #[test]
    fn endofresp_stashes_final_line_for_sasl() {
        let mut c = conn_in(SmtpState::Auth);
        assert_eq!(c.classify_response(b"334 Zm9v\r\n"), Some(334));
        assert_eq!(c.last_final_line, b"334 Zm9v\r\n");
    }

    // ----- EHLO multi-line capability parse --------------------------------

    #[test]
    fn ehlo_multiline_capabilities_parsed() {
        let mut c = conn_in(SmtpState::Ehlo);

        // Greeting line (continuation) — no capability keyword.
        assert_eq!(c.classify_response(b"250-mail.example.com\r\n"), None);
        // PIPELINING — not a tracked capability, must be ignored gracefully.
        assert_eq!(c.classify_response(b"250-PIPELINING\r\n"), None);
        // SIZE with a value.
        assert_eq!(c.classify_response(b"250-SIZE 10240\r\n"), None);
        // AUTH mechanisms.
        assert_eq!(c.classify_response(b"250-AUTH PLAIN LOGIN\r\n"), None);
        // STARTTLS as the final line.
        assert_eq!(c.classify_response(b"250 STARTTLS\r\n"), Some(250));

        assert!(c.size_supported, "SIZE must be detected");
        assert!(c.auth_supported, "AUTH must be detected");
        assert!(c.tls_supported, "STARTTLS must be detected");
        assert!(!c.utf8_supported, "SMTPUTF8 was not advertised");
        assert_eq!(
            c.sasl.authmechs & (SASL_MECH_PLAIN | SASL_MECH_LOGIN),
            SASL_MECH_PLAIN | SASL_MECH_LOGIN,
            "PLAIN and LOGIN must be decoded from the AUTH line"
        );
    }

    #[test]
    fn ehlo_smtputf8_capability_parsed() {
        let mut c = conn_in(SmtpState::Ehlo);
        assert_eq!(c.classify_response(b"250 SMTPUTF8\r\n"), Some(250));
        assert!(c.utf8_supported);
    }

    // ----- SASL proto vtable (saslsmtp) ------------------------------------

    #[test]
    fn sasl_proto_constants_match_saslsmtp() {
        let c = SmtpConn::default();
        assert_eq!(c.service(), "smtp");
        assert_eq!(c.maxirlen(), 512 - 8);
        assert_eq!(c.cont_code(), 334);
        assert_eq!(c.final_code(), 235);
        assert_eq!(c.def_mechs(), SASL_AUTH_DEFAULT);
        assert_eq!(c.flags(), SASL_FLAG_BASE64);
    }

    #[test]
    fn sasl_send_auth_queues_command() {
        let mut c = SmtpConn::default();
        // Without an initial response.
        c.send_auth("LOGIN", None).expect("send_auth");
        assert_eq!(c.pending_auth.as_deref(), Some(b"AUTH LOGIN".as_slice()));
        // With an inline (base64) initial response.
        c.send_auth("PLAIN", Some(b"AGZvbwBiYXI=".as_slice()))
            .expect("send_auth");
        assert_eq!(
            c.pending_auth.as_deref(),
            Some(b"AUTH PLAIN AGZvbwBiYXI=".as_slice())
        );
    }

    #[test]
    fn sasl_continue_and_cancel_queue_lines() {
        let mut c = SmtpConn::default();
        c.cont_auth("LOGIN", b"dXNlcg==").expect("cont_auth");
        assert_eq!(c.pending_auth.as_deref(), Some(b"dXNlcg==".as_slice()));
        // An empty continuation queues an empty line (just CRLF on the wire).
        c.cont_auth("DIGEST-MD5", b"").expect("cont_auth");
        assert_eq!(c.pending_auth.as_deref(), Some(b"".as_slice()));
        c.cancel_auth("LOGIN").expect("cancel_auth");
        assert_eq!(c.pending_auth.as_deref(), Some(b"*".as_slice()));
    }

    #[test]
    fn sasl_get_message_extracts_334_challenge() {
        let mut c = conn_in(SmtpState::Auth);
        // A 334 continuation challenge carrying a base64 token.
        assert_eq!(c.classify_response(b"334 VXNlcm5hbWU6\r\n"), Some(334));
        let msg = c.get_message().expect("get_message");
        assert_eq!(msg, b"VXNlcm5hbWU6");
    }

    #[test]
    fn sasl_get_message_empty_for_short_line() {
        // "334\r\n" has only the bare code → empty challenge.
        let mut c = SmtpConn {
            last_final_line: b"334\r\n".to_vec(),
            ..Default::default()
        };
        assert_eq!(c.get_message().expect("get_message"), b"");
    }
}
