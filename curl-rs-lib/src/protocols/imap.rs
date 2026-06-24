//! IMAP / IMAPS protocol engine — the Rust analog of curl's `lib/imap.c`
//! (~2,360 lines) and `lib/imap.h`.
//!
//! curl speaks the subset of [RFC 3501] IMAP4rev1 needed to *log in*, *select*
//! a mailbox, *fetch* a message (or a section/part of one), *append* (upload) a
//! message, *list* mailboxes, *search*, run a *custom* command, and *log out*.
//! It layers on top of the shared command/response engine
//! ([`crate::protocols::pingpong`]) and delegates all authentication-mechanism
//! cryptography to the shared SASL core ([`crate::auth::sasl`]). This module
//! reproduces that behavior faithfully as idiomatic async Rust.
//!
//! ## Wire shape
//!
//! Unlike FTP/SMTP/POP3 (which key responses off a leading numeric code), IMAP
//! is **command-tagged**: the client prefixes every command with a unique tag
//! (`A001`, `A002`, …) and the server terminates the matching response with a
//! line that repeats that tag followed by a completion status —
//! `A001 OK …` / `A001 NO …` / `A001 BAD …`. Lines beginning with `*` are
//! *untagged* (intermediate data such as `CAPABILITY`/`FETCH`/`LIST`/`SEARCH`
//! results), and a line beginning with `+ ` is a *continuation request* (used
//! during `AUTHENTICATE` and the `APPEND` literal). See [`Imapc::classify_response`].
//!
//! ## Architecture
//!
//! * [`ImapHandler`] is the stateless [`Protocol`] handler (one instance per
//!   `imap`/`imaps` scheme), fused from curl's `imap_connect` + `imap_connecting`
//!   + `imap_do` + `imap_done` + `imap_disconnect`.
//! * [`ImapConn`] is the per-connection state stored in the connection's
//!   protocol-state slot. It bundles the [`PingPong`] command/response engine,
//!   the [`Sasl`] negotiation state, the protocol state machine [`Imapc`], and
//!   the per-transfer request shape [`Imap`].
//! * [`Imapc`] implements **both** [`PingPongProtocol`] (its
//!   [`endofresp`](PingPongProtocol::endofresp) detects end-of-response and
//!   captures the final line) **and** [`SaslProto`] (the Rust successor to the C
//!   `static const struct SASLproto saslimap` vtable).
//!
//! ## The state machine and the borrow design
//!
//! curl's `imap_statemach_act` is a re-entrant function repeatedly polled by the
//! multi loop; each call sends the next command and/or consumes a response and
//! advances `imapc->state`. Here that collapses into an `async` driver
//! ([`ImapHandler::drive`]) that owns the loop directly.
//!
//! The one subtlety is borrowing: [`PingPong::readresp`] needs `&mut PingPong`
//! *and* `&mut impl PingPongProtocol` simultaneously, so the engine and the
//! protocol state cannot be the same object. The driver therefore *takes*
//! [`ImapConn`] out of the connection's protocol-state slot for the duration of
//! an operation and drives its fields by **disjoint mutable borrow**:
//! `pp.readresp(data, conn, FIRSTSOCKET, &mut proto)`. The SASL methods are
//! synchronous and merely *stage* wire-ready command bytes into
//! [`Imapc::staged`]; the async driver then flushes each via
//! [`PingPong::sendf`]. This mirrors the C code, where `imap_statemach_act`
//! calls `Curl_pp_sendf` directly.
//!
//! ## Scope note
//!
//! The control plane (greeting → `CAPABILITY` → optional `STARTTLS` →
//! authentication via SASL or `LOGIN`, and the `SELECT`/`FETCH`/`APPEND`/`LIST`/
//! `SEARCH`/custom command dispatch) is implemented in full. Streaming the raw
//! `FETCH` *literal body* bytes off the live socket is handed to the transfer
//! engine (curl's `Curl_xfer_setup_recv`); here `do_it` parses the literal size
//! and returns the [`ProtocolTransfer`] descriptor the engine consumes.
//!
//! `unsafe` is forbidden crate-wide (the attribute is inherited from the crate
//! root); none is used or re-declared here. All buffers are owned `Vec<u8>` /
//! `String`.
//!
//! [RFC 3501]: https://www.rfc-editor.org/rfc/rfc3501

use crate::auth::sasl::{
    decode_mech, Sasl, SaslParams, SaslProgress, SaslProto, SASL_AUTH_DEFAULT, SASL_AUTH_NONE,
    SASL_FLAG_BASE64,
};
use crate::conn::https_connect::create_tls_filter;
use crate::conn::{
    BoxFuture, Connection, Curl_conn_cf_add, Curl_conn_connect, Curl_conn_is_alive,
    Curl_conn_is_ssl, Curl_conn_send, FIRSTSOCKET, PROTOPT_SSL,
};
use crate::easy::Easy;
use crate::error::{CurlError, Result};
use crate::protocols::pingpong::{tls_config_from_easy, PingPong, PingPongProtocol, PpTransfer};
use crate::protocols::{
    connect_network_scheme, stream_body_to_sink, Protocol, ProtocolTransfer, Scheme,
    TransferDirection, CURLPROTO_IMAPS, DEFAULT_PORT_IMAPS, SCHEME_IMAP, SCHEME_IMAPS,
};
use crate::setopt::{HttpReq, StrId};
use crate::transfer::{ReadCallback, ReadStep, UploadReader, WriteCallbacks};
use crate::url::{CurlUPart, CurlUrl, CURLU_DEFAULT_PORT, CURLU_URLDECODE};
use crate::util::dynbuf::DYN_IMAP_CMD;
use crate::util::timeval::curlx_now;

// ===========================================================================
// Response codes and sentinels (C `imap.c` `#define IMAP_RESP_*` and the
// `endofresp` return contract).
// ===========================================================================

/// Tagged `OK` completion — authentication/command success (C `IMAP_RESP_OK`).
const IMAP_RESP_OK: i32 = 1;
/// Tagged `NO`/`BAD` completion — command failure (C `IMAP_RESP_NOT_OK`).
const IMAP_RESP_NOT_OK: i32 = 2;
/// Tagged `PREAUTH` greeting — the session is pre-authenticated
/// (C `IMAP_RESP_PREAUTH`).
const IMAP_RESP_PREAUTH: i32 = 3;
/// Untagged-response sentinel returned by `endofresp` for a `* …` data line
/// that the current state treats as terminal (C returns `'*'`).
const IMAP_RESP_UNTAGGED: i32 = b'*' as i32;
/// Continuation-request sentinel returned by `endofresp` for a `+ …` line
/// (C returns `'+'`). This is also the SASL `cont_code` for IMAP.
const IMAP_RESP_CONTINUATION: i32 = b'+' as i32;

// ===========================================================================
// Authentication-type preference flags (C `imap.h` `IMAP_TYPE_*`).
// ===========================================================================

/// No acceptable authentication style (C `IMAP_TYPE_NONE`). Set when the URL
/// `;AUTH=` option selected a SASL preference that resolved to no mechanism.
const IMAP_TYPE_NONE: u8 = 0;
/// The server/user permits cleartext `LOGIN` (C `IMAP_TYPE_CLEARTEXT`).
const IMAP_TYPE_CLEARTEXT: u8 = 1 << 0;
/// The server/user permits SASL `AUTHENTICATE` (C `IMAP_TYPE_SASL`).
const IMAP_TYPE_SASL: u8 = 1 << 1;
/// Either authentication style is acceptable (C `IMAP_TYPE_ANY`).
const IMAP_TYPE_ANY: u8 = IMAP_TYPE_CLEARTEXT | IMAP_TYPE_SASL;

// ===========================================================================
// `CURLUSESSL` levels (C `curl/curl.h` `enum CURL_USESSL`), used to decide
// whether a missing `STARTTLS` is fatal. Stored in `data.set.use_ssl`.
// ===========================================================================

/// Do not attempt to use SSL (`CURLUSESSL_NONE`).
const CURLUSESSL_NONE: u8 = 0;
/// Try using SSL, proceed anyway otherwise (`CURLUSESSL_TRY`).
const CURLUSESSL_TRY: u8 = 1;

// ===========================================================================
// The IMAP connection state machine (C `imap.c` `enum imapstate`). The order
// is significant and reproduced exactly.
// ===========================================================================

/// The IMAP per-connection state, mirroring C `enum imapstate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImapState {
    /// Idle / no command in flight (C `IMAP_STOP`).
    Stop,
    /// Awaiting the server greeting (C `IMAP_SERVERGREET`).
    ServerGreet,
    /// Awaiting the `CAPABILITY` response (C `IMAP_CAPABILITY`).
    Capability,
    /// Awaiting the `STARTTLS` response (C `IMAP_STARTTLS`).
    StartTls,
    /// Performing the TLS handshake after `STARTTLS` (C `IMAP_UPGRADETLS`).
    UpgradeTls,
    /// Driving the SASL `AUTHENTICATE` exchange (C `IMAP_AUTHENTICATE`).
    Authenticate,
    /// Awaiting the cleartext `LOGIN` response (C `IMAP_LOGIN`).
    Login,
    /// Awaiting the `LIST` response (C `IMAP_LIST`).
    List,
    /// Awaiting the `SELECT` response (C `IMAP_SELECT`).
    Select,
    /// Awaiting the `FETCH` literal header (C `IMAP_FETCH`).
    Fetch,
    /// Awaiting the tagged completion after a `FETCH` body (C `IMAP_FETCH_FINAL`).
    FetchFinal,
    /// Awaiting the `APPEND` continuation request (C `IMAP_APPEND`).
    Append,
    /// Awaiting the tagged completion after an `APPEND` body (C `IMAP_APPEND_FINAL`).
    AppendFinal,
    /// Awaiting the `SEARCH` response (C `IMAP_SEARCH`).
    Search,
    /// Awaiting the `LOGOUT` response (C `IMAP_LOGOUT`).
    Logout,
}

// ===========================================================================
// Per-connection and per-transfer state structs.
// ===========================================================================

/// Per-connection IMAP protocol state — the part of curl's `struct imap_conn`
/// that drives the command/response state machine and carries the negotiated
/// capabilities. It implements both [`PingPongProtocol`] and [`SaslProto`].
///
/// It deliberately does **not** embed the [`PingPong`] engine or the [`Sasl`]
/// state; those live as sibling fields of [`ImapConn`] so the driver can borrow
/// them disjointly from this one (see the module-level borrow note).
pub struct Imapc {
    /// The current state-machine position (C `imapc->state`).
    state: ImapState,
    /// The per-connection command-tag letter, `b'A' + (connection_id % 26)`
    /// (C `imapc->cmdid` seed via the connection id).
    conn_letter: u8,
    /// The monotonically increasing command counter (C `imapc->cmdid`, an
    /// `unsigned char` that deliberately wraps `255 → 0`).
    cmdid: u8,
    /// The tag the *current* in-flight command expects in its tagged completion
    /// line, e.g. `"A001"` (C `imapc->resptag`). Starts as `"*"` so the initial
    /// greeting (an untagged/`*`/`PREAUTH` line) is matched.
    resptag: String,
    /// Whether the server advertised `STARTTLS` (C `imapc->tls_supported`).
    tls_supported: bool,
    /// Whether the server advertised `LOGINDISABLED` (C `imapc->login_disabled`).
    login_disabled: bool,
    /// Whether the server advertised `SASL-IR` — initial-response support
    /// (C `imapc->ir_supported`).
    ir_supported: bool,
    /// Whether the greeting was `PREAUTH` (already authenticated; C `imapc->preauth`).
    preauth: bool,
    /// Whether TLS is already established on this connection (mirrors the live
    /// filter chain; set once `STARTTLS`/implicit TLS completes).
    ssldone: bool,
    /// The acceptable authentication styles (C `imapc->preftype`, `IMAP_TYPE_*`).
    preftype: u8,
    /// Whether the in-flight request is a *custom* command, which suppresses the
    /// continuation handling in `endofresp` (C tests `imap->custom`).
    custom_request: bool,
    /// The custom command verb (e.g. `"STORE"`), copied from the per-transfer
    /// [`Imap::custom`] when a custom request is dispatched. `endofresp` needs it
    /// to reproduce the `LIST`-state untagged-response matching in `imap.c`.
    custom_name: Option<String>,
    /// The connection username (resolved from the URL or `CURLOPT_USERNAME`),
    /// kept here so per-round [`SaslParams`] can borrow an owned copy.
    user: String,
    /// The connection password (resolved from the URL or `CURLOPT_PASSWORD`).
    passwd: String,
    /// The SASL authorization identity (`;AUTH=` / login options), empty if none.
    sasl_authzid: String,
    /// The connection host name (for SASL service-principal construction).
    host: String,
    /// The connection port (for SASL service-principal construction).
    port: u16,
    /// The mailbox currently `SELECT`ed on this connection, if any
    /// (C `imapc->mailbox`). Set after a successful `SELECT` and compared on the
    /// next request to decide whether a re-`SELECT` is needed.
    mailbox: Option<String>,
    /// The `UIDVALIDITY` reported by the server for the selected mailbox
    /// (`Some(n)` mirrors C `mb_uidvalidity == n` with `mb_uidvalidity_set`).
    mb_uidvalidity: Option<u32>,
    /// The literal byte count parsed from a `FETCH` data line, captured so the
    /// `do` phase can size the resulting download [`ProtocolTransfer`]
    /// (C threads this through `Curl_pgrsSetDownloadSize`/`maxdownload`).
    download_size: Option<u64>,
    /// The most recently received complete response line, including its
    /// trailing CRLF, captured by [`endofresp`](PingPongProtocol::endofresp)
    /// (the engine's own receive buffer is private). [`get_message`] reads its
    /// `+ ` continuation payload from here.
    resp_line: Vec<u8>,
    /// Accumulated untagged data lines for a `LIST`/`SEARCH` transfer, captured
    /// verbatim (including their trailing CRLF) as each `* …` data line is
    /// matched in the `List`/`Search` state.
    ///
    /// Unlike a `FETCH` body — which arrives as a sized literal streamed off the
    /// socket — a `LIST`/`SEARCH` listing has no up-front size: its body *is* the
    /// set of untagged response lines, which the ping-pong engine consumes as
    /// protocol lines during the DO dialogue. C `imap.c` writes each such line to
    /// the client with `Curl_client_write(CLIENTWRITE_BODY, …)` as it is parsed;
    /// this buffer is the Rust equivalent, drained to the client writer by
    /// [`ImapHandler::transfer`] once the dialogue completes. Cleared at the
    /// start of every `LIST`/`SEARCH` so a reused connection starts clean.
    data_resp: Vec<u8>,
    /// Wire-ready command lines staged by the synchronous [`SaslProto`] methods,
    /// drained and sent by the async driver via [`PingPong::sendf`].
    staged: Vec<Vec<u8>>,
}

/// Per-transfer IMAP request shape — the Rust analog of curl's `struct IMAP`
/// (`data->req.p.imap`). It is parsed from the URL path + query and the
/// `CURLOPT_CUSTOMREQUEST` option, and consumed by the `do`/`done` phases.
///
/// It is stored as a field of [`ImapConn`] because [`Easy`] exposes no public
/// per-request protocol-state slot; the connection is dedicated to the transfer
/// for its lifetime, and [`ImapHandler::done`] resets it (C `imap_easy_reset`).
#[derive(Debug, Clone)]
pub struct Imap {
    /// The direction/role of the body transfer (C `imap->transfer`).
    transfer: PpTransfer,
    /// The mailbox name from the URL path (C `imap->mailbox`).
    mailbox: Option<String>,
    /// The `;UIDVALIDITY=` URL parameter, parsed as a number. `None` mirrors C
    /// `uidvalidity_set == FALSE`; `Some(n)` mirrors `uidvalidity == n`
    /// (C `imap->uidvalidity` is an `unsigned int` with a separate set flag).
    uidvalidity: Option<u32>,
    /// The `;UID=` URL parameter (C `imap->uid`).
    uid: Option<String>,
    /// The `;MAILINDEX=` URL parameter (C `imap->mindex`).
    mindex: Option<String>,
    /// The `;SECTION=` URL parameter (C `imap->section`).
    section: Option<String>,
    /// The `;PARTIAL=` URL parameter (C `imap->partial`).
    partial: Option<String>,
    /// The `?`-query search criteria (C `imap->query`).
    query: Option<String>,
    /// The `CURLOPT_CUSTOMREQUEST` verb, if any (C `imap->custom`).
    custom: Option<String>,
    /// The trailing parameters of a custom request (C `imap->custom_params`).
    custom_params: Option<String>,
}

impl Default for Imap {
    fn default() -> Self {
        // C zeroes `struct IMAP`; `PPTRANSFER_BODY` is the zero variant, so a
        // fresh request defaults to a body transfer with no parsed parts.
        Self {
            transfer: PpTransfer::Body,
            mailbox: None,
            uidvalidity: None,
            uid: None,
            mindex: None,
            section: None,
            partial: None,
            query: None,
            custom: None,
            custom_params: None,
        }
    }
}

impl Imap {
    /// Parse the leading run of ASCII digits of `bytes` as a `u32`, returning
    /// `None` if there is no digit or the value exceeds `u32::MAX`.
    ///
    /// Mirrors the success contract of C `curlx_str_number(&p, &num, UINT_MAX)`
    /// for the `;UIDVALIDITY=` parameter and the `[UIDVALIDITY n]` response.
    fn parse_leading_u32(bytes: &[u8]) -> Option<u32> {
        let mut i = 0;
        let mut num: u64 = 0;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            num = num * 10 + u64::from(bytes[i] - b'0');
            if num > u64::from(u32::MAX) {
                return None;
            }
            i += 1;
        }
        if i == 0 {
            None
        } else {
            Some(num as u32)
        }
    }

    /// Parse an IMAP URL `path` (and optional already-decoded `query`) into the
    /// hierarchical request parts.
    ///
    /// Mirrors C `imap_parse_url_path`: the mailbox is the leading run of
    /// `bchar`s (trailing `/` removed, then percent-decoded), followed by any
    /// number of `;NAME=VALUE` parameters (`UIDVALIDITY`, `UID`, `MAILINDEX`,
    /// `SECTION`, `PARTIAL`). The `query` is honored only when a mailbox is
    /// present and neither `UID` nor `MAILINDEX` was given (RFC 5092). An
    /// unknown parameter or any trailing junk is a [`CurlError::UrlMalformat`].
    fn parse_url_path(path: &str, query: Option<String>) -> Result<Imap> {
        let mut imap = Imap::default();
        let bytes = path.as_bytes();
        // Skip the single leading slash, exactly as C indexes `path[1]`.
        let begin = usize::from(bytes.first() == Some(&b'/'));
        let mut ptr = begin;

        // The mailbox: the leading run of bchars.
        while ptr < bytes.len() && imap_is_bchar(bytes[ptr]) {
            ptr += 1;
        }
        if ptr != begin {
            let mut end = ptr;
            if end > begin && bytes[end - 1] == b'/' {
                end -= 1;
            }
            imap.mailbox = Some(imap_urldecode(&bytes[begin..end])?);
        }

        // Any number of ";NAME=VALUE" parameters.
        while ptr < bytes.len() && bytes[ptr] == b';' {
            ptr += 1;
            let nbegin = ptr;
            while ptr < bytes.len() && bytes[ptr] != b'=' {
                ptr += 1;
            }
            if ptr >= bytes.len() {
                return Err(CurlError::UrlMalformat);
            }
            let name = imap_urldecode(&bytes[nbegin..ptr])?;
            ptr += 1; // skip '='

            let vbegin = ptr;
            while ptr < bytes.len() && imap_is_bchar(bytes[ptr]) {
                ptr += 1;
            }
            let mut value = imap_urldecode(&bytes[vbegin..ptr])?;
            // C uses the pre-strip decoded length as the "is this blank?" gate,
            // then strips a single trailing '/' from the stored value.
            let valuelen = value.len();
            if value.ends_with('/') {
                value.pop();
            }
            if valuelen > 0 {
                if name.eq_ignore_ascii_case("UIDVALIDITY") && imap.uidvalidity.is_none() {
                    // A non-numeric value leaves uidvalidity unset (as in C),
                    // but is not itself an error.
                    if let Some(n) = Imap::parse_leading_u32(value.as_bytes()) {
                        imap.uidvalidity = Some(n);
                    }
                } else if name.eq_ignore_ascii_case("UID") && imap.uid.is_none() {
                    imap.uid = Some(value);
                } else if name.eq_ignore_ascii_case("MAILINDEX") && imap.mindex.is_none() {
                    imap.mindex = Some(value);
                } else if name.eq_ignore_ascii_case("SECTION") && imap.section.is_none() {
                    imap.section = Some(value);
                } else if name.eq_ignore_ascii_case("PARTIAL") && imap.partial.is_none() {
                    imap.partial = Some(value);
                } else {
                    return Err(CurlError::UrlMalformat);
                }
            }
        }

        // The query is valid only with a mailbox and without UID/MAILINDEX.
        if imap.mailbox.is_some() && imap.uid.is_none() && imap.mindex.is_none() {
            imap.query = query;
        }

        // Any leftover (a non-';' character) is malformed.
        if ptr < bytes.len() {
            return Err(CurlError::UrlMalformat);
        }
        Ok(imap)
    }

    /// Split a percent-encoded `CURLOPT_CUSTOMREQUEST` value into the verb and
    /// its trailing parameters.
    ///
    /// Mirrors C `imap_parse_custom_request`: the value is percent-decoded, then
    /// split at the first space — `custom` is the verb, `custom_params` is the
    /// remainder **including the leading space** (or `None` when there is none).
    fn parse_custom_request(custom: Option<&str>) -> Result<(Option<String>, Option<String>)> {
        match custom {
            None => Ok((None, None)),
            Some(raw) => {
                let decoded = imap_urldecode(raw.as_bytes())?;
                if let Some(pos) = decoded.find(' ') {
                    let verb = decoded[..pos].to_string();
                    let params = decoded[pos..].to_string();
                    Ok((Some(verb), Some(params)))
                } else {
                    Ok((Some(decoded), None))
                }
            }
        }
    }
}

/// Assemble the `APPEND` message-flags suffix from a `CURLOPT_UPLOAD_FLAGS`
/// bitset.
///
/// Mirrors C `imap_perform_append`'s flag loop: an empty set yields `""`; any
/// set bit yields ` (\Flag …)` with the named system flags space-separated and
/// in canonical order (`\Answered \Deleted \Draft \Flagged \Seen`).
fn append_flags(upload_flags: u8) -> String {
    if upload_flags == 0 {
        return String::new();
    }
    let mut parts: Vec<&str> = Vec::new();
    if upload_flags & CURLULFLAG_ANSWERED != 0 {
        parts.push("\\Answered");
    }
    if upload_flags & CURLULFLAG_DELETED != 0 {
        parts.push("\\Deleted");
    }
    if upload_flags & CURLULFLAG_DRAFT != 0 {
        parts.push("\\Draft");
    }
    if upload_flags & CURLULFLAG_FLAGGED != 0 {
        parts.push("\\Flagged");
    }
    if upload_flags & CURLULFLAG_SEEN != 0 {
        parts.push("\\Seen");
    }
    format!(" ({})", parts.join(" "))
}

impl Imapc {
    /// Construct fresh per-connection state for a connection with the given id.
    ///
    /// The state starts at [`ImapState::Stop`]; [`ImapHandler::connect`] moves
    /// it to [`ImapState::ServerGreet`]. The command-tag letter is
    /// `b'A' + (connection_id mod 26)` (C seeds the tag from the connection id).
    fn new(connection_id: i64) -> Self {
        let letter = b'A' + (connection_id.rem_euclid(26) as u8);
        Self {
            state: ImapState::Stop,
            conn_letter: letter,
            cmdid: 0,
            resptag: "*".to_string(),
            tls_supported: false,
            login_disabled: false,
            ir_supported: false,
            preauth: false,
            ssldone: false,
            preftype: IMAP_TYPE_ANY,
            custom_request: false,
            custom_name: None,
            user: String::new(),
            passwd: String::new(),
            sasl_authzid: String::new(),
            host: String::new(),
            port: 0,
            mailbox: None,
            mb_uidvalidity: None,
            download_size: None,
            resp_line: Vec::new(),
            data_resp: Vec::new(),
            staged: Vec::new(),
        }
    }

    /// Advance the command counter and format the next command tag (C
    /// `imap_sendf`'s `"%c%03d"`), recording it as the tag the upcoming tagged
    /// completion line must echo.
    fn next_tag(&mut self) -> String {
        self.cmdid = self.cmdid.wrapping_add(1);
        let tag = format!("{}{:03}", self.conn_letter as char, self.cmdid);
        self.resptag = tag.clone();
        tag
    }

    /// Build a fully-tagged command wire line, `"<tag> <body>"` (the engine
    /// appends the terminating CRLF).
    fn tagged(&mut self, body: &str) -> String {
        let tag = self.next_tag();
        format!("{tag} {body}")
    }

    /// `CAPABILITY` — discover server capabilities (C `imap_perform_capability`
    /// sends this; the caller clears the cached capability/auth state first).
    fn cmd_capability(&mut self) -> String {
        self.tagged("CAPABILITY")
    }

    /// `STARTTLS` — request the cleartext→TLS upgrade (C `imap_perform_starttls`).
    fn cmd_starttls(&mut self) -> String {
        self.tagged("STARTTLS")
    }

    /// `LOGIN <user> <passwd>` — cleartext authentication
    /// (C `imap_perform_login`), with both arguments in IMAP atom form.
    fn cmd_login(&mut self) -> String {
        let user = imap_atom(&self.user, false);
        let passwd = imap_atom(&self.passwd, false);
        self.tagged(&format!("LOGIN {user} {passwd}"))
    }

    /// `SELECT <mailbox>` — open a mailbox (C `imap_perform_select`).
    fn cmd_select(&mut self, mailbox: &str) -> String {
        self.tagged(&format!("SELECT {}", imap_atom(mailbox, false)))
    }

    /// `SEARCH <query>` — search the selected mailbox (C `imap_perform_search`).
    fn cmd_search(&mut self, query: &str) -> String {
        self.tagged(&format!("SEARCH {query}"))
    }

    /// `LIST "<mailbox>" *` or a custom request (C `imap_perform_list`). A
    /// custom verb is sent verbatim with its trailing parameters; otherwise the
    /// mailbox is escaped (atom, `escape_only`) and wrapped in literal quotes.
    fn cmd_list(
        &mut self,
        custom: Option<&str>,
        custom_params: Option<&str>,
        mailbox: Option<&str>,
    ) -> String {
        match custom {
            Some(verb) => {
                let params = custom_params.unwrap_or("");
                self.tagged(&format!("{verb}{params}"))
            }
            None => {
                let mb = mailbox.map(|m| imap_atom(m, true)).unwrap_or_default();
                self.tagged(&format!("LIST \"{mb}\" *"))
            }
        }
    }

    /// `UID FETCH`/`FETCH <ident> BODY[<section>]<<partial>>?`
    /// (C `imap_perform_fetch`). `verb` is `"UID FETCH"` (for a UID) or `"FETCH"`
    /// (for a message index).
    fn cmd_fetch(&mut self, verb: &str, ident: &str, section: &str, partial: Option<&str>) -> String {
        let body = match partial {
            Some(p) => format!("{verb} {ident} BODY[{section}]<{p}>"),
            None => format!("{verb} {ident} BODY[{section}]"),
        };
        self.tagged(&body)
    }

    /// `APPEND <mailbox><flags> {<size>}` — begin a message upload
    /// (C `imap_perform_append`).
    fn cmd_append(&mut self, mailbox: &str, flags: &str, infilesize: i64) -> String {
        let mb = imap_atom(mailbox, false);
        self.tagged(&format!("APPEND {mb}{flags} {{{infilesize}}}"))
    }

    /// `LOGOUT` — end the session (C `imap_perform_logout`).
    fn cmd_logout(&mut self) -> String {
        self.tagged("LOGOUT")
    }

    /// Parse a `* CAPABILITY …` data line (held in [`Self::resp_line`]) and
    /// record the advertised capabilities, OR-ing recognized SASL mechanisms
    /// into `sasl.authmechs`.
    ///
    /// Mirrors C `imap_state_capability_resp`'s untagged branch: tokens are
    /// split on whitespace and matched against `STARTTLS`, `LOGINDISABLED`,
    /// `SASL-IR`, and `AUTH=<mech>` (the mechanism name must match a known
    /// mechanism in full).
    fn parse_capability(&mut self, sasl: &mut Sasl) {
        // Copy the line out first so the field reads do not alias the field
        // writes below (the line is small — a single CAPABILITY response).
        let line = self.resp_line.clone();
        let body = line.get(2..).unwrap_or(&[]); // skip "* "
        for word in body.split(|&b| b == b' ' || b == b'\r' || b == b'\n') {
            if word.is_empty() {
                continue;
            }
            if word.len() == 8 && word.eq_ignore_ascii_case(b"STARTTLS") {
                self.tls_supported = true;
            } else if word.len() == 13 && word.eq_ignore_ascii_case(b"LOGINDISABLED") {
                self.login_disabled = true;
            } else if word.len() == 7 && word.eq_ignore_ascii_case(b"SASL-IR") {
                self.ir_supported = true;
            } else if word.len() > 5 && word[..5].eq_ignore_ascii_case(b"AUTH=") {
                let mech = &word[5..];
                let (bit, llen) = decode_mech(mech, mech.len());
                if bit != 0 && llen == mech.len() {
                    sasl.authmechs |= bit;
                }
            }
        }
    }

    /// Parse the URL/login `;options` string (C `imap_parse_url_options`).
    ///
    /// Iterates `key=value` pairs separated by `;`. The only recognized key is
    /// `AUTH`: `AUTH=+LOGIN` forces cleartext `LOGIN` over any SASL (clearing
    /// the SASL preference), while `AUTH=<mech>` (or `AUTH=*`) sets the SASL
    /// `prefmech` via [`Sasl::parse_url_auth_option`]. After parsing, the
    /// preferred auth *type* ([`Self::preftype`]) is derived from the resulting
    /// preference exactly as C does. An unrecognized key is a
    /// [`CurlError::UrlMalformat`].
    ///
    /// Without this step the URL's `;AUTH=EXTERNAL` (and `--login-options`)
    /// never reach `prefmech`, so the engine would silently fall back to
    /// cleartext `LOGIN` for any explicitly-requested mechanism.
    fn parse_url_options(&mut self, sasl: &mut Sasl, options: &[u8]) -> Result<()> {
        let mut result: Result<()> = Ok(());
        let mut prefer_login = false;
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

            // C `curl_strnequal(key, "AUTH=+LOGIN", 11)`: prefer plaintext LOGIN
            // over any SASL (including SASL LOGIN). Checked before the generic
            // `AUTH=` so it is not consumed as a mechanism name.
            if key.len() >= 11 && key[..11].eq_ignore_ascii_case(b"AUTH=+LOGIN") {
                prefer_login = true;
                sasl.prefmech = SASL_AUTH_NONE;
            } else if key.len() >= 5 && key[..5].eq_ignore_ascii_case(b"AUTH=") {
                prefer_login = false;
                result = sasl.parse_url_auth_option(value);
            } else {
                prefer_login = false;
                result = Err(CurlError::UrlMalformat);
            }

            if ptr < n && options[ptr] == b';' {
                ptr += 1;
            }
        }

        // C post-loop switch: derive the preferred auth type.
        if prefer_login {
            self.preftype = IMAP_TYPE_CLEARTEXT;
        } else {
            self.preftype = match sasl.prefmech {
                SASL_AUTH_NONE => IMAP_TYPE_NONE,
                SASL_AUTH_DEFAULT => IMAP_TYPE_ANY,
                _ => IMAP_TYPE_SASL,
            };
        }

        result
    }

    /// Whether an untagged `line` matches what the `LIST` state expects.
    ///
    /// Mirrors the `IMAP_LIST` arm of C `imap_endofresp`: a plain `LIST` for the
    /// built-in listing, or — for a custom verb — the verb itself, the
    /// `STORE → FETCH` echo, or any of the recognized response-bearing verbs.
    fn match_list_untagged(&self, line: &[u8]) -> bool {
        match &self.custom_name {
            None => imap_matchresp(line, b"LIST"),
            Some(custom) => {
                imap_matchresp(line, custom.as_bytes())
                    || (custom.eq_ignore_ascii_case("STORE") && imap_matchresp(line, b"FETCH"))
                    || custom.eq_ignore_ascii_case("SELECT")
                    || custom.eq_ignore_ascii_case("EXAMINE")
                    || custom.eq_ignore_ascii_case("SEARCH")
                    || custom.eq_ignore_ascii_case("EXPUNGE")
                    || custom.eq_ignore_ascii_case("LSUB")
                    || custom.eq_ignore_ascii_case("UID")
                    || custom.eq_ignore_ascii_case("GETQUOTAROOT")
                    || custom.eq_ignore_ascii_case("NOOP")
            }
        }
    }

    /// Classify one complete response `line` against the current state, mapping
    /// it to the IMAP response sentinel.
    ///
    /// This is the pure core of [`endofresp`](PingPongProtocol::endofresp),
    /// mirroring C `imap_endofresp`:
    /// * a **tagged** line (`<resptag> …`) yields [`IMAP_RESP_OK`],
    ///   [`IMAP_RESP_PREAUTH`], or [`IMAP_RESP_NOT_OK`] (`OK`/`PREAUTH` are
    ///   matched case-sensitively, as the spec mandates uppercase);
    /// * an **untagged** `* …` data line yields `Some(`[`IMAP_RESP_UNTAGGED`]`)`
    ///   when the state cares about it, else `None` (consume and keep reading);
    /// * a **continuation** `+ …` line yields `Some(`[`IMAP_RESP_CONTINUATION`]`)`
    ///   in the `AUTHENTICATE`/`APPEND` states, or `Some(-1)` (a hard error) in
    ///   any other state;
    /// * anything else yields `None`.
    fn classify_response(&self, line: &[u8]) -> Option<i32> {
        let id = self.resptag.as_bytes();
        let id_len = id.len();

        // Tagged command completion?
        if line.len() > id_len && &line[..id_len] == id && line[id_len] == b' ' {
            let rest = &line[id_len + 1..];
            if rest.len() >= 2 && &rest[..2] == b"OK" {
                return Some(IMAP_RESP_OK);
            }
            if rest.len() >= 7 && &rest[..7] == b"PREAUTH" {
                return Some(IMAP_RESP_PREAUTH);
            }
            return Some(IMAP_RESP_NOT_OK);
        }

        // Untagged data line?
        if line.len() >= 2 && &line[..2] == b"* " {
            let matched = match self.state {
                ImapState::Capability => imap_matchresp(line, b"CAPABILITY"),
                ImapState::List => self.match_list_untagged(line),
                ImapState::Select => true, // SELECT untagged data has no common prefix
                ImapState::Fetch => imap_matchresp(line, b"FETCH"),
                ImapState::Search => imap_matchresp(line, b"SEARCH"),
                _ => false,
            };
            return matched.then_some(IMAP_RESP_UNTAGGED);
        }

        // Continuation request?
        if !self.custom_request
            && ((line.len() == 3 && line[0] == b'+')
                || (line.len() >= 2 && &line[..2] == b"+ "))
        {
            return match self.state {
                ImapState::Authenticate | ImapState::Append => Some(IMAP_RESP_CONTINUATION),
                _ => Some(-1),
            };
        }

        None
    }
}

/// The complete per-connection IMAP state stored in the connection's
/// protocol-state slot (`conn.set_proto_state`). Its four fields are driven by
/// disjoint mutable borrow (see the module-level borrow note).
pub struct ImapConn {
    /// The shared command/response engine (C `imap_conn.pp`).
    pp: PingPong,
    /// The shared SASL negotiation state (C `imap_conn.sasl`).
    sasl: Sasl,
    /// The IMAP state machine + capabilities, also the [`SaslProto`] impl.
    proto: Imapc,
    /// The current per-transfer request shape.
    req: Imap,
}

/// The stateless IMAP/IMAPS [`Protocol`] handler (curl's `Curl_handler_imap` /
/// `Curl_handler_imaps`). One instance is created per scheme by
/// [`crate::protocols::scheme_handler`]; all mutable state lives on the
/// connection in [`ImapConn`].
pub struct ImapHandler {
    /// The static scheme descriptor this instance serves (`imap` or `imaps`).
    scheme: &'static Scheme,
}

impl ImapHandler {
    /// Construct a handler bound to the given scheme descriptor.
    #[must_use]
    pub(crate) const fn new(scheme: &'static Scheme) -> Self {
        Self { scheme }
    }
}

// ===========================================================================
// `APPEND` flag bits.
// ===========================================================================
//
// Note on `CURLUSESSL` levels: the connect-time STARTTLS decision below only
// needs to distinguish "no TLS wanted" (`CURLUSESSL_NONE`) from "TLS optional"
// (`CURLUSESSL_TRY`). Any stronger level — `CURLUSESSL_CONTROL` (2) or
// `CURLUSESSL_ALL` (3) — is handled implicitly by the `use_ssl > CURLUSESSL_TRY`
// branch, which fails with `CURLE_USE_SSL_FAILED` when STARTTLS is unavailable,
// exactly mirroring C `imap_state_capability_resp`. Those higher levels are
// therefore never named explicitly here.

/// `APPEND` message flag `\Answered` (C `CURLULFLAG_ANSWERED`).
const CURLULFLAG_ANSWERED: u8 = 1 << 0;
/// `APPEND` message flag `\Deleted` (C `CURLULFLAG_DELETED`).
const CURLULFLAG_DELETED: u8 = 1 << 1;
/// `APPEND` message flag `\Draft` (C `CURLULFLAG_DRAFT`).
const CURLULFLAG_DRAFT: u8 = 1 << 2;
/// `APPEND` message flag `\Flagged` (C `CURLULFLAG_FLAGGED`).
const CURLULFLAG_FLAGGED: u8 = 1 << 3;
/// `APPEND` message flag `\Seen` (C `CURLULFLAG_SEEN`).
const CURLULFLAG_SEEN: u8 = 1 << 4;

// ===========================================================================
// Stateless wire helpers (the Rust analogs of the file-private helpers in
// `imap.c`). These are pure functions so they can be unit-tested directly.
// ===========================================================================

/// Whether `ch` is a valid IMAP `bchar` (the URL-path character class).
///
/// Mirrors C `imap_is_bchar`: ASCII alphanumeric, or one of the listed
/// sub-delimiters / unreserved punctuation (`%` is included because the raw
/// path is still percent-encoded at this point).
#[inline]
fn imap_is_bchar(ch: u8) -> bool {
    ch.is_ascii_alphanumeric()
        || matches!(
            ch,
            b':' | b'@'
                | b'/'
                | b'&'
                | b'='
                | b'-'
                | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b'%'
        )
}

/// Decode one hex digit, or `None` if `b` is not `[0-9A-Fa-f]`.
#[inline]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode `input`, rejecting decoded control characters.
///
/// Mirrors curl's `Curl_urldecode(..., REJECT_CTRL)` as used by the IMAP URL
/// parser: a `%XX` triplet with two valid hex digits decodes to one byte; any
/// other `%` is taken literally; a decoded byte below `0x20` is rejected with
/// [`CurlError::UrlMalformat`]. The result must be valid UTF-8.
fn imap_urldecode(input: &[u8]) -> Result<String> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let decoded = if input[i] == b'%' && i + 3 <= input.len() {
            match (hex_val(input[i + 1]), hex_val(input[i + 2])) {
                (Some(hi), Some(lo)) => {
                    i += 3;
                    (hi << 4) | lo
                }
                _ => {
                    i += 1;
                    b'%'
                }
            }
        } else {
            let b = input[i];
            i += 1;
            b
        };
        // REJECT_CTRL: control bytes are not permitted in a decoded path part.
        if decoded < 0x20 {
            return Err(CurlError::UrlMalformat);
        }
        out.push(decoded);
    }
    String::from_utf8(out).map_err(|_| CurlError::UrlMalformat)
}

/// Quote/escape a string for safe inclusion in an IMAP command argument.
///
/// Mirrors C `imap_atom`. If `s` contains none of the IMAP special characters
/// (`( ) <space> { % * ] \ "`) it is emitted verbatim. Otherwise every `\` and
/// `"` is backslash-escaped, and — unless `escape_only` is set — the whole atom
/// is wrapped in double quotes (a *quoted string*).
fn imap_atom(s: &str, escape_only: bool) -> String {
    let needs_escaping = s.bytes().any(|b| {
        matches!(
            b,
            b'(' | b')' | b' ' | b'{' | b'%' | b'*' | b']' | b'\\' | b'"'
        )
    });
    if !needs_escaping {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    if !escape_only {
        out.push('"');
    }
    for ch in s.chars() {
        if ch == '\\' || ch == '"' {
            out.push('\\');
        }
        out.push(ch);
    }
    if !escape_only {
        out.push('"');
    }
    out
}

/// Find the byte offset of the literal-length introducer `{` in `line`,
/// skipping any double-quoted run (in which `\` escapes the next byte).
///
/// Mirrors C `imap_find_literal` and is used to locate the `{NNN}` in a `FETCH`
/// or `LIST` data line.
fn imap_find_literal(line: &[u8]) -> Option<usize> {
    let mut in_quote = false;
    let mut i = 0;
    while i < line.len() {
        let c = line[i];
        if in_quote {
            if c == b'\\' && i + 1 < line.len() {
                i += 2;
                continue;
            }
            if c == b'"' {
                in_quote = false;
            }
        } else if c == b'"' {
            in_quote = true;
        } else if c == b'{' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Whether an untagged (`* …`) `line` is a data response for command `cmd`.
///
/// Mirrors C `imap_matchresp`: the leading `"* "` is skipped, an optional
/// numeric prefix (e.g. the message number in `* 1 FETCH …`) is consumed along
/// with its trailing space, then `cmd` must match case-insensitively and be
/// followed by either a space or the end-of-line CRLF.
fn imap_matchresp(line: &[u8], cmd: &[u8]) -> bool {
    let end = line.len();
    // Require the untagged "* " prefix.
    if end < 2 || &line[..2] != b"* " {
        return false;
    }
    let mut i = 2;
    // Skip an optional leading number followed by a space.
    if i < end && line[i].is_ascii_digit() {
        while i < end && line[i].is_ascii_digit() {
            i += 1;
        }
        if i >= end || line[i] != b' ' {
            return false;
        }
        i += 1;
    }
    let cmd_len = cmd.len();
    if i + cmd_len <= end && line[i..i + cmd_len].eq_ignore_ascii_case(cmd) {
        // The command word must end at a space or immediately precede the CRLF
        // (C: `line[cmd_len] == ' ' || line + cmd_len + 2 == end`).
        let after = i + cmd_len;
        if (after < end && line[after] == b' ') || after + 2 == end {
            return true;
        }
    }
    false
}

/// Parse a `FETCH` literal length: a run of ASCII digits immediately followed
/// by `}`. Returns the size (clamped to a valid `curl_off_t`) on success.
///
/// Mirrors C `fetch_resp`'s `curlx_str_number(&ptr, &size, CURL_OFF_T_MAX)`
/// followed by `curlx_str_single(&ptr, '}')`: at least one digit is required
/// and the byte after the number must be `}`.
fn parse_literal_size(bytes: &[u8]) -> Option<u64> {
    let mut i = 0;
    let mut num: u64 = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        num = num.checked_mul(10)?.checked_add(u64::from(bytes[i] - b'0'))?;
        // CURL_OFF_T_MAX is `i64::MAX`; anything larger is rejected.
        if num > i64::MAX as u64 {
            return None;
        }
        i += 1;
    }
    if i == 0 {
        return None; // no digits
    }
    if i < bytes.len() && bytes[i] == b'}' {
        Some(num)
    } else {
        None
    }
}

/// Whether a custom-request parameter string denotes a *listing*-style
/// message-set query — `" 1:* (FLAGS …"` or `" 1,2,3 (FLAGS …"` — rather than a
/// single-message body fetch.
///
/// Mirrors C `is_custom_fetch_listing_match` (lib/imap.c L1180): the parameter
/// run must start with a space, followed by one or more digits, then a `:`
/// (range) or `,` (enumeration). `custom_params` carries its leading space (see
/// [`Imap::parse_custom_request`], matching C `imap_parse_custom_request`), so
/// the leading-space check applies directly. A trailing digit run with no `:`
/// / `,` (e.g. `" 123 BODY[1]"`) is *not* a listing — its untagged responses
/// carry a `{size}` literal body that must be streamed.
fn is_custom_fetch_listing_match(params: &[u8]) -> bool {
    // First byte must be the separating space.
    if params.first() != Some(&b' ') {
        return false;
    }
    let mut i = 1;
    while i < params.len() && params[i].is_ascii_digit() {
        i += 1;
    }
    matches!(params.get(i), Some(&b':') | Some(&b','))
}

/// Whether the in-flight custom request is a `FETCH`/`UID FETCH` *listing*
/// query whose untagged `*` responses must NOT be treated as literal bodies.
///
/// Mirrors C `is_custom_fetch_listing` (lib/imap.c L1198): only `FETCH` (with
/// params matched directly) and `UID` (with a `" FETCH "` prefix, matched from
/// the embedded params) can be listings; every other verb returns `false`,
/// leaving the normal literal-detection path to run. `custom`/`custom_params`
/// come straight off the per-request [`Imap`] state.
fn is_custom_fetch_listing(custom: Option<&str>, custom_params: Option<&str>) -> bool {
    let Some(custom) = custom else {
        return false;
    };
    if custom.eq_ignore_ascii_case("FETCH") {
        custom_params.is_some_and(|p| is_custom_fetch_listing_match(p.as_bytes()))
    } else if custom.eq_ignore_ascii_case("UID") {
        // C: `curl_strnequal(custom_params, " FETCH ", 7)`, then match from
        // `custom_params + 6` (i.e. the space before the message set).
        custom_params.is_some_and(|p| {
            let b = p.as_bytes();
            b.len() >= 7
                && b[..7].eq_ignore_ascii_case(b" FETCH ")
                && is_custom_fetch_listing_match(&b[6..])
        })
    } else {
        false
    }
}

// ===========================================================================
// Command performers + the response-dispatch state machine. These are async
// because they send via `PingPong::sendf`. Each `perform_*` mirrors the C
// `imap_perform_*` of the same name, and `handle_response` mirrors the big
// `switch(imapc->state)` in C `imap_pp_statemachine`.
// ===========================================================================

impl Imapc {
    /// Send a fully-assembled IMAP command line, enforcing the IMAP command
    /// buffer cap (`DYN_IMAP_CMD`, 64 KiB) before handing the line to the shared
    /// pingpong engine.
    ///
    /// Mirrors C `imap.c`, where every command is built into the per-connection
    /// `imapc->dyn` dynamic buffer initialised with `DYN_IMAP_CMD`
    /// (`curlx_dyn_init(&imapc->dyn, DYN_IMAP_CMD)`) and then handed to
    /// `Curl_pp_sendf`. Keeping the bound here preserves the IMAP-layer command
    /// cap independent of the engine's own (numerically identical) limit, so an
    /// over-long command (for example a pathological mailbox name or `APPEND`
    /// flag set) is rejected with `CURLE_TOO_LARGE` exactly as in C.
    async fn send_command(
        &self,
        data: &Easy,
        conn: &mut Connection,
        pp: &mut PingPong,
        cmd: String,
    ) -> Result<()> {
        // The trailing CRLF the engine appends counts against the command cap,
        // matching the `"\r\n"` that C appends inside the `imapc->dyn` buffer.
        if cmd.len().saturating_add(2) > DYN_IMAP_CMD {
            return Err(CurlError::TooLarge);
        }
        pp.send_cmd(data, conn, cmd).await
    }

    /// Flush every command line staged by the synchronous [`SaslProto`] methods,
    /// sending each through the engine (which appends the terminating CRLF).
    async fn flush_staged(
        &mut self,
        data: &Easy,
        conn: &mut Connection,
        pp: &mut PingPong,
    ) -> Result<()> {
        let staged = core::mem::take(&mut self.staged);
        for line in staged {
            let text = String::from_utf8_lossy(&line).into_owned();
            self.send_command(data, conn, pp, text).await?;
        }
        Ok(())
    }

    /// C `imap_perform_capability`: reset the cached capabilities/mechanisms and
    /// send `CAPABILITY`.
    async fn perform_capability(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        pp: &mut PingPong,
        sasl: &mut Sasl,
    ) -> Result<()> {
        sasl.authmechs = 0; // SASL_AUTH_NONE — no known mechanisms yet
        sasl.authused = 0; // clear the mechanism used
        self.tls_supported = false; // clear the TLS capability
        let cmd = self.cmd_capability();
        self.send_command(data, conn, pp, cmd).await?;
        self.state = ImapState::Capability;
        Ok(())
    }

    /// C `imap_perform_starttls`: send `STARTTLS`.
    async fn perform_starttls(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        pp: &mut PingPong,
    ) -> Result<()> {
        let cmd = self.cmd_starttls();
        self.send_command(data, conn, pp, cmd).await?;
        self.state = ImapState::StartTls;
        Ok(())
    }

    /// C `imap_perform_login`: send the cleartext `LOGIN`, or end the connect
    /// phase if there is no username to authenticate with.
    async fn perform_login(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        pp: &mut PingPong,
    ) -> Result<()> {
        if self.user.is_empty() {
            // No credentials (C `!data->state.aptr.user`) — nothing to do.
            self.state = ImapState::Stop;
            return Ok(());
        }
        let cmd = self.cmd_login();
        self.send_command(data, conn, pp, cmd).await?;
        self.state = ImapState::Login;
        Ok(())
    }

    /// Build the per-round [`SaslParams`] material (cloned into the supplied
    /// owned locals so they do not alias the `&mut self` proto reference) and
    /// begin the SASL exchange. Mirrors C `imap_perform_authentication`'s
    /// `Curl_sasl_start` path.
    async fn perform_authentication(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        pp: &mut PingPong,
        sasl: &mut Sasl,
    ) -> Result<()> {
        // Already authenticated, or not enough to authenticate with → done.
        if self.preauth || !sasl.can_authenticate(&self.user) {
            self.state = ImapState::Stop;
            return Ok(());
        }

        let force_ir = self.ir_supported;
        // Clone the credential material so `SaslParams` borrows locals, leaving
        // `self` free to pass to `sasl.start` as the proto.
        let user = self.user.clone();
        let passwd = self.passwd.clone();
        let host = self.host.clone();
        let authzid = self.sasl_authzid.clone();
        let port = self.port;
        let bearer = data.set.str(StrId::Bearer).map(str::to_string);
        let service_name = data.set.str(StrId::ServiceName).map(str::to_string);
        let sasl_ir = data.set.sasl_ir;

        let progress = {
            let params = SaslParams {
                user: &user,
                passwd: &passwd,
                authzid: &authzid,
                host: &host,
                port,
                service_name: service_name.as_deref(),
                bearer: bearer.as_deref(),
                sasl_ir,
                allow_auth_to_other_hosts: false,
                this_is_a_follow: false,
            };
            sasl.start(self, &params, force_ir)?
        };

        // Send whatever the SASL layer staged (the `AUTHENTICATE` command).
        self.flush_staged(data, conn, pp).await?;

        if progress == SaslProgress::InProgress {
            self.state = ImapState::Authenticate;
        } else if !self.login_disabled && (self.preftype & IMAP_TYPE_CLEARTEXT) != 0 {
            // No usable SASL mechanism — fall back to cleartext LOGIN.
            self.perform_login(data, conn, pp).await?;
        } else {
            sasl.is_blocked()?;
            self.state = ImapState::Stop;
        }
        Ok(())
    }

    /// Drive one SASL continuation round in response to `code`. Mirrors C
    /// `imap_state_auth_resp`'s `Curl_sasl_continue` handling.
    async fn auth_continue(
        &mut self,
        code: i32,
        data: &mut Easy,
        conn: &mut Connection,
        pp: &mut PingPong,
        sasl: &mut Sasl,
    ) -> Result<()> {
        let user = self.user.clone();
        let passwd = self.passwd.clone();
        let host = self.host.clone();
        let authzid = self.sasl_authzid.clone();
        let port = self.port;
        let bearer = data.set.str(StrId::Bearer).map(str::to_string);
        let service_name = data.set.str(StrId::ServiceName).map(str::to_string);
        let sasl_ir = data.set.sasl_ir;

        let progress = {
            let params = SaslParams {
                user: &user,
                passwd: &passwd,
                authzid: &authzid,
                host: &host,
                port,
                service_name: service_name.as_deref(),
                bearer: bearer.as_deref(),
                sasl_ir,
                allow_auth_to_other_hosts: false,
                this_is_a_follow: false,
            };
            sasl.cont(self, &params, code)?
        };

        // Send whatever the SASL layer staged (a continuation line, or a "*"
        // cancellation), then react to the new progress state.
        self.flush_staged(data, conn, pp).await?;

        match progress {
            SaslProgress::Done => {
                self.state = ImapState::Stop; // authenticated
                Ok(())
            }
            SaslProgress::Idle => {
                // No mechanism left after cancellation.
                if !self.login_disabled && (self.preftype & IMAP_TYPE_CLEARTEXT) != 0 {
                    self.perform_login(data, conn, pp).await
                } else {
                    crate::failf!(&mut conn.filter_data.error_buffer, "Authentication cancelled");
                    Err(CurlError::LoginDenied)
                }
            }
            // More rounds to come; the staged continuation was just flushed.
            SaslProgress::InProgress => Ok(()),
        }
    }

    /// C `imap_perform_list`: `LIST` or a custom request.
    async fn perform_list(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        pp: &mut PingPong,
        req: &Imap,
    ) -> Result<()> {
        let cmd = self.cmd_list(
            req.custom.as_deref(),
            req.custom_params.as_deref(),
            req.mailbox.as_deref(),
        );
        // Start a fresh listing body (a reused connection may carry data from a
        // prior LIST/SEARCH on this handle).
        self.data_resp.clear();
        self.send_command(data, conn, pp, cmd).await?;
        self.state = ImapState::List;
        Ok(())
    }

    /// C `imap_perform_select`: invalidate the cached mailbox and send `SELECT`.
    async fn perform_select(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        pp: &mut PingPong,
        req: &Imap,
    ) -> Result<()> {
        self.mailbox = None; // switching mailboxes invalidates the old one
        let mailbox = match &req.mailbox {
            Some(m) => m.clone(),
            None => {
                crate::failf!(&mut conn.filter_data.error_buffer, "Cannot SELECT without a mailbox.");
                return Err(CurlError::UrlMalformat);
            }
        };
        let cmd = self.cmd_select(&mailbox);
        self.send_command(data, conn, pp, cmd).await?;
        self.state = ImapState::Select;
        Ok(())
    }

    /// C `imap_perform_fetch`: `UID FETCH`/`FETCH` of the configured part.
    async fn perform_fetch(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        pp: &mut PingPong,
        req: &Imap,
    ) -> Result<()> {
        let section = req.section.as_deref().unwrap_or("");
        let cmd = if let Some(uid) = req.uid.as_deref() {
            self.cmd_fetch("UID FETCH", uid, section, req.partial.as_deref())
        } else if let Some(mindex) = req.mindex.as_deref() {
            self.cmd_fetch("FETCH", mindex, section, req.partial.as_deref())
        } else {
            crate::failf!(&mut conn.filter_data.error_buffer, "Cannot FETCH without a UID.");
            return Err(CurlError::UrlMalformat);
        };
        self.send_command(data, conn, pp, cmd).await?;
        self.state = ImapState::Fetch;
        Ok(())
    }

    /// C `imap_perform_search`: `SEARCH` the selected mailbox.
    async fn perform_search(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        pp: &mut PingPong,
        req: &Imap,
    ) -> Result<()> {
        let query = match &req.query {
            Some(q) => q.clone(),
            None => {
                crate::failf!(&mut conn.filter_data.error_buffer, "Cannot SEARCH without a query string.");
                return Err(CurlError::UrlMalformat);
            }
        };
        let cmd = self.cmd_search(&query);
        // Start a fresh search body (clear any prior LIST/SEARCH listing).
        self.data_resp.clear();
        self.send_command(data, conn, pp, cmd).await?;
        self.state = ImapState::Search;
        Ok(())
    }

    /// C `imap_perform_append`: begin a message upload with the `APPEND` literal
    /// header. The upload size must be known up front.
    async fn perform_append(
        &mut self,
        data: &mut Easy,
        conn: &mut Connection,
        pp: &mut PingPong,
        req: &Imap,
    ) -> Result<()> {
        let mailbox = match &req.mailbox {
            Some(m) => m.clone(),
            None => {
                crate::failf!(&mut conn.filter_data.error_buffer, "Cannot APPEND without a mailbox.");
                return Err(CurlError::UrlMalformat);
            }
        };
        // The APPEND literal size: for a `-F` MIME post the body was assembled
        // eagerly into `mime_body`, so its byte length is the known size; for a
        // `-T` upload it is `CURLOPT_INFILESIZE` (`data.set.filesize`). C derives
        // the same value from `data->state.infilesize`, which libcurl sets to the
        // serialized MIME size for a MIME post (`Curl_mime_size`). Oracle:
        // tests/data/test647 expects `APPEND 647 (\Seen) {940}` — 940 being the
        // assembled multipart body length.
        let infilesize = match &data.set.mime_body {
            Some(body) => body.len() as i64,
            None => data.set.filesize,
        };
        if infilesize < 0 {
            crate::failf!(&mut conn.filter_data.error_buffer, "Cannot APPEND with unknown input file size");
            return Err(CurlError::UploadFailed);
        }
        let flags = append_flags(data.set.upload_flags);
        let cmd = self.cmd_append(&mailbox, &flags, infilesize);
        self.send_command(data, conn, pp, cmd).await?;
        self.state = ImapState::Append;
        Ok(())
    }

    /// Dispatch a single received response `code` to the handler for the current
    /// state, sending the next command and advancing the state as needed.
    ///
    /// Mirrors the `switch(imapc->state)` block of C `imap_pp_statemachine`.
    async fn handle_response(
        &mut self,
        code: i32,
        data: &mut Easy,
        conn: &mut Connection,
        pp: &mut PingPong,
        sasl: &mut Sasl,
        req: &mut Imap,
    ) -> Result<()> {
        let verbose = data.set.verbose;
        match self.state {
            // --- Connect phase -------------------------------------------------
            ImapState::ServerGreet => {
                if code == IMAP_RESP_PREAUTH {
                    self.preauth = true;
                    crate::infof!(verbose, "PREAUTH connection, already authenticated");
                } else if code != IMAP_RESP_OK {
                    crate::failf!(&mut conn.filter_data.error_buffer, "Got unexpected imap-server response");
                    return Err(CurlError::WeirdServerReply);
                }
                self.perform_capability(data, conn, pp, sasl).await
            }
            ImapState::Capability => {
                if code == IMAP_RESP_UNTAGGED {
                    self.parse_capability(sasl);
                    Ok(())
                } else {
                    let use_ssl = data.set.use_ssl;
                    let is_ssl = Curl_conn_is_ssl(conn, FIRSTSOCKET);
                    if use_ssl != CURLUSESSL_NONE && !is_ssl {
                        if code == IMAP_RESP_OK && self.tls_supported && !self.preauth {
                            self.perform_starttls(data, conn, pp).await
                        } else if use_ssl <= CURLUSESSL_TRY {
                            self.perform_authentication(data, conn, pp, sasl).await
                        } else {
                            crate::failf!(&mut conn.filter_data.error_buffer, "STARTTLS not available.");
                            Err(CurlError::UseSslFailed)
                        }
                    } else {
                        self.perform_authentication(data, conn, pp, sasl).await
                    }
                }
            }
            ImapState::StartTls => {
                // Pipelining in the STARTTLS response is forbidden: the server
                // must not send any bytes after the response line and before the
                // TLS handshake, or those plaintext bytes could be a command
                // injection by a network attacker (the STARTTLS "plaintext
                // command injection" class). Mirrors `imap_state_starttls_resp`
                // (`imap.c` L1109-1110): `if(imapc->pp.overflow) return
                // CURLE_WEIRD_SERVER_REPLY;`, checked *before* the response code
                // so a pipelined reply is rejected regardless of OK/BAD status.
                // Without this guard the buffered extra lines desynchronise the
                // tagged command/response exchange and the transfer hangs
                // (tests/data/test981).
                if pp.has_overflow() {
                    crate::failf!(
                        &mut conn.filter_data.error_buffer,
                        "Reply to STARTTLS contained pipelined data"
                    );
                    return Err(CurlError::WeirdServerReply);
                }
                if code != IMAP_RESP_OK {
                    if data.set.use_ssl != CURLUSESSL_TRY {
                        crate::failf!(&mut conn.filter_data.error_buffer, "STARTTLS denied");
                        Err(CurlError::UseSslFailed)
                    } else {
                        self.perform_authentication(data, conn, pp, sasl).await
                    }
                } else {
                    // The handshake itself runs in the driver's UpgradeTls step.
                    self.state = ImapState::UpgradeTls;
                    Ok(())
                }
            }
            ImapState::Authenticate => self.auth_continue(code, data, conn, pp, sasl).await,
            ImapState::Login => {
                if code != IMAP_RESP_OK {
                    crate::failf!(
                        &mut conn.filter_data.error_buffer,
                        "Access denied. {}",
                        code as u8 as char
                    );
                    Err(CurlError::LoginDenied)
                } else {
                    self.state = ImapState::Stop; // end of connect phase
                    Ok(())
                }
            }

            // --- Do phase ------------------------------------------------------
            ImapState::List | ImapState::Search => {
                if code == IMAP_RESP_UNTAGGED {
                    // An untagged `* …` data line in a LIST/SEARCH/custom response.
                    // Mirrors C `imap_state_listsearch_resp` (lib/imap.c L1217).
                    //
                    // A custom `FETCH`/`UID FETCH` body request (e.g.
                    // `-X 'FETCH 123 BODY[1]'`) returns a `{size}` literal
                    // introducer on this line: `* 123 FETCH (BODY[1] {70}`. The
                    // header line itself IS part of the body, and exactly `size`
                    // raw bytes of literal follow — bytes that may *look* like
                    // protocol (`+ …`, `--`, blank lines) but are opaque data and
                    // must not be parsed. We therefore (a) keep the header line as
                    // the body prefix, (b) record `size` as the download length so
                    // the transfer loop streams precisely the literal, and (c) end
                    // the DO phase, leaving the closing `)` + tagged completion for
                    // `done`. A *listing* message-set query (C `is_custom_fetch_
                    // listing`, e.g. `FETCH 1:* (FLAGS …`) is excluded: its untagged
                    // lines are plain protocol and are captured verbatim, as before.
                    let literal = if is_custom_fetch_listing(
                        req.custom.as_deref(),
                        req.custom_params.as_deref(),
                    ) {
                        None
                    } else {
                        // Search for `{NNN}` only within the line proper (before the
                        // trailing CRLF), exactly as C bounds it with the first
                        // `\r` (`memchr(line, '\r', len)`).
                        let line = &self.resp_line;
                        let cr = line
                            .iter()
                            .position(|&b| b == b'\r')
                            .unwrap_or(line.len());
                        imap_find_literal(&line[..cr])
                            .and_then(|idx| parse_literal_size(&line[idx + 1..cr]))
                    };
                    match literal {
                        Some(size) => {
                            // Header line is body; the literal is streamed next.
                            self.data_resp.extend_from_slice(&self.resp_line);
                            self.download_size = Some(size);
                            crate::infof!(verbose, "Found {size} bytes to download");
                            self.state = ImapState::Stop; // end of DO phase
                            Ok(())
                        }
                        None => {
                            // No literal: the untagged `* …` data lines ARE the
                            // listing/search body. These are consumed here as
                            // protocol lines (not streamed off the socket); capture
                            // each verbatim (with its trailing CRLF, exactly as
                            // received in `resp_line`) so `transfer` can hand them
                            // to the client writer once the dialogue completes.
                            // Mirrors C writing each line with
                            // `Curl_client_write(CLIENTWRITE_BODY, …)` as parsed.
                            self.data_resp.extend_from_slice(&self.resp_line);
                            Ok(())
                        }
                    }
                } else if code != IMAP_RESP_OK {
                    Err(CurlError::QuoteError)
                } else {
                    self.state = ImapState::Stop; // end of DO phase
                    Ok(())
                }
            }
            ImapState::Select => {
                if code == IMAP_RESP_UNTAGGED {
                    // Capture "* OK [UIDVALIDITY n] …" if present.
                    const PFX: &[u8] = b"OK [UIDVALIDITY ";
                    let line = &self.resp_line;
                    if line.len() >= 2 + PFX.len() {
                        let after_star = &line[2..];
                        if after_star[..PFX.len()].eq_ignore_ascii_case(PFX) {
                            if let Some(n) = Imap::parse_leading_u32(&after_star[PFX.len()..]) {
                                self.mb_uidvalidity = Some(n);
                            }
                        }
                    }
                    Ok(())
                } else if code == IMAP_RESP_OK {
                    // Reject a UIDVALIDITY change if the caller pinned one.
                    if let (Some(want), Some(got)) = (req.uidvalidity, self.mb_uidvalidity) {
                        if want != got {
                            crate::failf!(&mut conn.filter_data.error_buffer, "Mailbox UIDVALIDITY has changed");
                            return Err(CurlError::RemoteFileNotFound);
                        }
                    }
                    self.mailbox = req.mailbox.clone();
                    if req.custom.is_some() {
                        self.perform_list(data, conn, pp, req).await
                    } else if req.query.is_some() {
                        self.perform_search(data, conn, pp, req).await
                    } else {
                        self.perform_fetch(data, conn, pp, req).await
                    }
                } else {
                    crate::failf!(&mut conn.filter_data.error_buffer, "Select failed");
                    Err(CurlError::LoginDenied)
                }
            }
            ImapState::Fetch => {
                if code != IMAP_RESP_UNTAGGED {
                    self.state = ImapState::Stop;
                    return Err(CurlError::RemoteFileNotFound);
                }
                // Parse the "{size}" literal introducer from the FETCH line.
                let line = self.resp_line.clone();
                let parsed = imap_find_literal(&line)
                    .and_then(|idx| parse_literal_size(&line[idx + 1..]));
                match parsed {
                    Some(size) => {
                        self.download_size = Some(size);
                        crate::infof!(verbose, "Found {size} bytes to download");
                    }
                    None => {
                        crate::failf!(&mut conn.filter_data.error_buffer, "Failed to parse FETCH response.");
                        self.state = ImapState::Stop;
                        return Err(CurlError::WeirdServerReply);
                    }
                }
                self.state = ImapState::Stop; // end of DO phase
                Ok(())
            }
            ImapState::FetchFinal => {
                if code != IMAP_RESP_OK {
                    Err(CurlError::WeirdServerReply)
                } else {
                    self.state = ImapState::Stop;
                    Ok(())
                }
            }
            ImapState::Append => {
                if code != IMAP_RESP_CONTINUATION {
                    Err(CurlError::UploadFailed)
                } else {
                    // The upload body is streamed by the transfer engine once
                    // `do_it` returns an upload descriptor.
                    self.state = ImapState::Stop;
                    Ok(())
                }
            }
            ImapState::AppendFinal => {
                if code != IMAP_RESP_OK {
                    Err(CurlError::UploadFailed)
                } else {
                    self.state = ImapState::Stop;
                    Ok(())
                }
            }

            // UpgradeTls is handled before `readresp` in the driver; Logout and
            // Stop are terminal here.
            ImapState::UpgradeTls | ImapState::Logout | ImapState::Stop => {
                self.state = ImapState::Stop;
                Ok(())
            }
        }
    }
}

// ===========================================================================
// `PingPongProtocol` — the engine's per-line end-of-response hook.
// ===========================================================================

impl PingPongProtocol for Imapc {
    fn endofresp(&mut self, _data: &mut Easy, conn: &mut Connection, line: &[u8]) -> Option<i32> {
        // Capture the full line so the state handlers, the capability parser,
        // and the SASL `get_message` hook can read it once `readresp` returns
        // (the engine's own receive buffer is private to `PingPong`).
        self.resp_line.clear();
        self.resp_line.extend_from_slice(line);

        let code = self.classify_response(line);
        if code == Some(-1) {
            // A continuation in a state that does not expect one is fatal
            // (C `imap_endofresp` emits this `failf` before returning `-1`).
            crate::failf!(
                &mut conn.filter_data.error_buffer,
                "Unexpected continuation response"
            );
        }
        code
    }

    fn statemachine<'a>(
        &'a mut self,
        _data: &'a mut Easy,
        _conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        // IMAP does not use the pingpong engine's own statemachine hook: the
        // `ImapHandler` async driver owns the command/response loop and calls
        // `PingPong::readresp` directly (see the module-level borrow note), so
        // this is intentionally inert.
        Box::pin(async move { Ok(()) })
    }
}

// ===========================================================================
// `SaslProto` — the Rust successor to the C `static const struct SASLproto
// saslimap` vtable. The send/continue/cancel methods are synchronous and stage
// wire-ready bytes into `self.staged`; the async driver flushes them.
// ===========================================================================

impl SaslProto for Imapc {
    fn service(&self) -> &str {
        "imap"
    }

    fn maxirlen(&self) -> usize {
        0
    }

    fn cont_code(&self) -> i32 {
        IMAP_RESP_CONTINUATION
    }

    fn final_code(&self) -> i32 {
        IMAP_RESP_OK
    }

    fn def_mechs(&self) -> u16 {
        SASL_AUTH_DEFAULT
    }

    fn flags(&self) -> u16 {
        SASL_FLAG_BASE64
    }

    fn send_auth(&mut self, mech: &str, initial_resp: Option<&[u8]>) -> Result<()> {
        // C `imap_perform_authenticate`: "AUTHENTICATE <mech> [<ir>]". The
        // initial response is already base64 (so ASCII) when present.
        let body = match initial_resp {
            Some(ir) => {
                let ir = String::from_utf8_lossy(ir);
                format!("AUTHENTICATE {mech} {ir}")
            }
            None => format!("AUTHENTICATE {mech}"),
        };
        let cmd = self.tagged(&body);
        self.staged.push(cmd.into_bytes());
        Ok(())
    }

    fn cont_auth(&mut self, _mech: &str, resp: &[u8]) -> Result<()> {
        // C `imap_continue_authenticate`: a bare (untagged) base64 line.
        self.staged.push(resp.to_vec());
        Ok(())
    }

    fn cancel_auth(&mut self, _mech: &str) -> Result<()> {
        // C `imap_cancel_authenticate`: a bare "*".
        self.staged.push(b"*".to_vec());
        Ok(())
    }

    fn get_message(&mut self) -> Result<Vec<u8>> {
        // C `imap_get_message`: skip the "+ " prefix, trim surrounding blanks
        // and the trailing CRLF, and hand back the raw (still-base64) payload.
        let line = &self.resp_line;
        if line.len() > 2 {
            let mut start = 2;
            while start < line.len() && (line[start] == b' ' || line[start] == b'\t') {
                start += 1;
            }
            let mut end = line.len();
            while end > start && matches!(line[end - 1], b'\r' | b'\n' | b' ' | b'\t') {
                end -= 1;
            }
            Ok(line[start..end].to_vec())
        } else {
            Ok(Vec::new())
        }
    }
}

// ===========================================================================
// Per-connection state construction, free helpers, and the async
// command/response driver that ties them to the `Protocol` impl.
// ===========================================================================

impl ImapConn {
    /// Build fresh per-connection IMAP state for a new connection.
    ///
    /// Mirrors C `imap_setup_connection`'s allocation plus the
    /// `Curl_pp_setup`/`Curl_pp_init` and `Curl_sasl_init` calls in
    /// `imap_connect`: the pingpong engine is initialised with the current
    /// monotonic time, and the SASL layer's preferred-mechanism set is seeded
    /// from `CURLOPT_HTTPAUTH` via the [`SaslProto::def_mechs`] default.
    fn new(httpauth: u32, connection_id: i64) -> Self {
        let mut pp = PingPong::new();
        pp.init(curlx_now());
        let proto = Imapc::new(connection_id);
        let mut sasl = Sasl::new();
        sasl.init(&proto, httpauth);
        Self {
            pp,
            sasl,
            proto,
            req: Imap::default(),
        }
    }
}

/// Take the per-connection [`ImapConn`] out of `conn`'s protocol-state slot,
/// downcasting from the type-erased `Box<dyn Any>`.
///
/// Returns [`CurlError::FailedInit`] (C `CURLE_FAILED_INIT`) when no IMAP state
/// is present, matching the `!imapc` guard in C `imap_perform`/`imap_done`.
fn take_imap_conn(conn: &mut Connection) -> Result<Box<ImapConn>> {
    conn.take_proto_state()
        .and_then(|boxed| boxed.downcast::<ImapConn>().ok())
        .ok_or(CurlError::FailedInit)
}

/// Resolve the IMAP login credentials. The URL userinfo takes precedence; an
/// empty field falls back to `CURLOPT_USERNAME`/`CURLOPT_PASSWORD`, mirroring
/// curl's credential resolution (URL `user:password@` over `data->set.str`).
fn resolve_credentials(data: &Easy) -> Result<(String, String)> {
    let url_str = data.url().ok_or(CurlError::UrlMalformat)?.to_string();
    let mut url = CurlUrl::new();
    url.set(CurlUPart::Url, Some(&url_str), CURLU_DEFAULT_PORT)
        .map_err(|_| CurlError::UrlMalformat)?;
    let mut user = url.get(CurlUPart::User, CURLU_URLDECODE).unwrap_or_default();
    let mut passwd = url
        .get(CurlUPart::Password, CURLU_URLDECODE)
        .unwrap_or_default();
    if user.is_empty() {
        if let Some(u) = data.set.str(StrId::Username) {
            user = u.to_string();
        }
    }
    if passwd.is_empty() {
        if let Some(p) = data.set.str(StrId::Password) {
            passwd = p.to_string();
        }
    }
    Ok((user, passwd))
}

/// Resolve the effective IMAP login `;options` string (C `conn->options`).
///
/// `CURLOPT_LOGIN_OPTIONS` (`--login-options`, stored in [`StrId::Options`])
/// overrides the URL userinfo `;options` when set, mirroring C `override_login`
/// (lib/url.c L2581-2586). Returns `None` when neither source supplies options.
fn resolve_login_options(data: &Easy) -> Option<String> {
    // `--login-options` takes precedence over the URL options when present.
    if let Some(opts) = data.set.str(StrId::Options) {
        return Some(opts.to_string());
    }
    // Otherwise fall back to the URL's `;options` component (only schemes that
    // carry URL options populate this; for `imap`/`imaps` it is the userinfo
    // `user;AUTH=…` suffix).
    let url_str = data.url()?.to_string();
    let mut url = CurlUrl::new();
    url.set(CurlUPart::Url, Some(&url_str), CURLU_DEFAULT_PORT)
        .ok()?;
    url.get(CurlUPart::Options, CURLU_URLDECODE)
        .ok()
        .filter(|o| !o.is_empty())
}

/// Extract the **raw** URL path and the **URL-decoded** query for the `do`
/// phase.
///
/// C reads `data->state.up.path` raw ([`Imap::parse_url_path`] does its own
/// bchar-run decoding) and fetches the query with `CURLU_URLDECODE`
/// (`imap.c` `curl_url_get(uh, CURLUPART_QUERY, …, CURLU_URLDECODE)`).
fn url_path_and_query(data: &Easy) -> Result<(String, Option<String>)> {
    let url_str = data.url().ok_or(CurlError::UrlMalformat)?.to_string();
    let mut url = CurlUrl::new();
    url.set(CurlUPart::Url, Some(&url_str), CURLU_DEFAULT_PORT)
        .map_err(|_| CurlError::UrlMalformat)?;
    let path = url.get(CurlUPart::Path, 0).unwrap_or_default();
    let query = url.get(CurlUPart::Query, CURLU_URLDECODE).ok();
    Ok((path, query))
}

/// Perform the post-`STARTTLS` TLS upgrade (C `imap_perform_upgrade_tls`).
///
/// Installs a TLS connection filter on top of the existing transport (when the
/// channel is not already secured), drives the handshake to completion, marks
/// the channel upgraded, and re-issues `CAPABILITY` — which moves the state
/// machine out of [`ImapState::UpgradeTls`].
async fn perform_upgrade_tls(
    proto: &mut Imapc,
    pp: &mut PingPong,
    sasl: &mut Sasl,
    data: &mut Easy,
    conn: &mut Connection,
) -> Result<()> {
    if !Curl_conn_is_ssl(conn, FIRSTSOCKET) {
        // Build the upgrade's TLS config from the easy handle's SSL options —
        // the same shared mapping SMTP/POP3/FTP use for their explicit-TLS
        // upgrades (C derives the connection `ssl_config` from `data->set.ssl`
        // before calling `Curl_ssl_cfilter_add`). This propagates `--insecure`
        // (`verifypeer`), a custom CA (`--cacert`/`--capath`), a pinned key
        // (`--pinnedpubkey`), client certificates and the TLS version window to
        // the STARTTLS handshake. Certificate validation stays ON by default
        // (the helper starts from `TlsConfig::default`), satisfying the security
        // mandate. IMAP advertises no ALPN protocol, so the list is empty.
        let host = conn.remote_host.clone();
        let port = conn.remote_port;
        // The public-key pin (`CURLOPT_PINNEDPUBLICKEY`) is enforced by the TLS
        // filter through this explicit argument (the pin check runs in
        // `tls::connect`), exactly as SMTP/FTP thread it; passing it here is what
        // makes `--pinnedpubkey` actually take effect on the STARTTLS handshake.
        let pinned = data.set.str(StrId::SslPinnedPublicKey).map(String::from);
        let cf = create_tls_filter(tls_config_from_easy(data), host, port, pinned, Vec::new());
        Curl_conn_cf_add(conn, FIRSTSOCKET, cf);
        // C: `conn->scheme = &Curl_scheme_imaps`. The freshly-added filter
        // already makes `Curl_conn_is_ssl` report true; update the descriptor so
        // scheme-level queries and `CURLINFO_SCHEME` also reflect the upgrade.
        conn.scheme.name = "imaps".to_string();
        conn.scheme.default_port = DEFAULT_PORT_IMAPS;
        conn.scheme.flags |= PROTOPT_SSL;
        conn.scheme.protocol = CURLPROTO_IMAPS;
    }
    debug_assert!(!proto.ssldone, "TLS upgrade attempted after ssldone");
    // Drive the handshake; the await resolves only once TLS is established.
    Curl_conn_connect(conn, FIRSTSOCKET, false).await?;
    proto.ssldone = true;
    // Re-issue CAPABILITY now that the channel is secured (this moves the state
    // out of `UpgradeTls`).
    proto.perform_capability(data, conn, pp, sasl).await
}

/// Drive the IMAP command/response state machine until it reaches
/// [`ImapState::Stop`].
///
/// This is the async successor to C's repeat-call `imap_pp_statemachine` +
/// `imap_block_statemach`: each iteration optionally performs a pending TLS
/// upgrade (C's `goto upgrade_tls`), flushes a half-sent command
/// (`Curl_pp_flushsend`), reads exactly one complete response line
/// (`Curl_pp_readresp`), and dispatches it through [`Imapc::handle_response`].
/// The borrows of the four [`ImapConn`] fields are kept disjoint by passing
/// them as separate `&mut` parameters (see the module-level borrow note).
async fn run_imap_statemachine(
    proto: &mut Imapc,
    pp: &mut PingPong,
    sasl: &mut Sasl,
    req: &mut Imap,
    data: &mut Easy,
    conn: &mut Connection,
) -> Result<()> {
    loop {
        // C's `goto upgrade_tls`: the handshake step runs before any read.
        if proto.state == ImapState::UpgradeTls {
            perform_upgrade_tls(proto, pp, sasl, data, conn).await?;
        }
        if proto.state == ImapState::Stop {
            return Ok(());
        }

        // Flush any partially-sent command (C `Curl_pp_flushsend` at the top of
        // the statemachine). If it cannot fully flush yet, yield and retry.
        if pp.needs_flush() {
            pp.flushsend(data, conn).await?;
            if pp.needs_flush() {
                tokio::task::yield_now().await;
                continue;
            }
        }

        // Read one complete response line. `code == 0` means no complete
        // response is available yet (would-block / partial line); yield to the
        // runtime and retry, mirroring the sibling protocols' recv loops.
        let (code, _size) = pp.readresp(data, conn, FIRSTSOCKET, proto).await?;
        if code == 0 {
            tokio::task::yield_now().await;
            continue;
        }
        if code < 0 {
            // `endofresp` already emitted the diagnostic for an unexpected
            // continuation; surface it as a protocol error.
            return Err(CurlError::WeirdServerReply);
        }

        proto
            .handle_response(code, data, conn, pp, sasl, req)
            .await?;
    }
}

// ===========================================================================
// `Protocol` — the IMAP engine vtable (C `Curl_handler_imap` / `_imaps`).
// ===========================================================================

impl Protocol for ImapHandler {
    fn scheme(&self) -> &'static Scheme {
        self.scheme
    }

    fn connect<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Establish the transport. For `imaps` the engine auto-installs the
            // implicit-TLS filter (the scheme carries `PROTOPT_SSL`), so the
            // channel is already secured when this returns.
            Curl_conn_connect(conn, FIRSTSOCKET, true).await?;

            // A reused connection already carries an authenticated IMAP session
            // (C `conn->bits.protoconnstart`); skip the greeting/login dialogue.
            if conn.proto_state_ref::<ImapConn>().is_some() {
                return Ok(());
            }

            // Resolve the connection-level inputs before building the state.
            let (user, passwd) = resolve_credentials(data)?;
            // `--sasl-authzid` (`CURLOPT_SASL_AUTHZID`) supplies the SASL
            // authorization identity used by PLAIN (and others); without this
            // the `AUTHENTICATE PLAIN` payload would omit the requested
            // alternative authorization identity (C reads
            // `data->set.sasl_authzid` inside the SASL engine).
            let sasl_authzid = data
                .set
                .str(StrId::SaslAuthzid)
                .map(str::to_string)
                .unwrap_or_default();
            // The effective login `;options` (URL `;AUTH=…` or
            // `--login-options`), parsed below into the SASL `prefmech`.
            let login_options = resolve_login_options(data);
            let httpauth = data.set.httpauth;
            let connection_id = conn.connection_id;
            let host = conn.remote_host.clone();
            let port = conn.remote_port;

            let mut state = ImapConn::new(httpauth, connection_id);
            state.proto.user = user;
            state.proto.passwd = passwd;
            state.proto.sasl_authzid = sasl_authzid;
            state.proto.host = host;
            state.proto.port = port;
            // Reflect an already-secured channel (implicit `imaps`).
            state.proto.ssldone = Curl_conn_is_ssl(conn, FIRSTSOCKET);
            // C `imap_connect`: begin at the server greeting with the wildcard
            // response tag so the untagged/`PREAUTH` greeting line is matched.
            state.proto.state = ImapState::ServerGreet;
            state.proto.resptag = "*".to_string();

            let ImapConn {
                mut pp,
                mut sasl,
                mut proto,
                mut req,
            } = state;
            // Apply the URL/login `;options` to the SASL preference before the
            // dialogue starts (C `imap_parse_url_options`, called from
            // `imap_connect`). A malformed option aborts the connect.
            //
            // C calls `imap_parse_url_options` UNCONDITIONALLY (lib/imap.c
            // `imap_connect` L1971), even when `conn->options` is NULL/empty:
            // its post-loop switch re-derives `preftype` from the SASL
            // `prefmech` (seeded from `CURLOPT_HTTPAUTH` in `Curl_sasl_init`).
            // Skipping the call when there are no options would wrongly leave
            // `preftype` at its `IMAP_TYPE_ANY` default. That matters whenever
            // `prefmech` is a *specific* mechanism set — e.g. `--oauth2-bearer`
            // makes `prefmech = OAUTHBEARER|XOAUTH2`, which must yield
            // `preftype = IMAP_TYPE_SASL` (no cleartext `LOGIN` fallback). With
            // the bearer unusable (cleared across a cross-protocol redirect),
            // no SASL mechanism is selectable and the engine must reach
            // `Curl_sasl_is_blocked` → `CURLE_LOGIN_DENIED` (exit 67) rather
            // than silently downgrading to `LOGIN`. Pass an empty option
            // string when none was supplied so the switch still runs.
            let opt_bytes = login_options.as_deref().unwrap_or("");
            proto.parse_url_options(&mut sasl, opt_bytes.as_bytes())?;
            // "Response lines as headers" capture (C `Curl_pp_readresp`'s
            // unconditional `Curl_client_write(CLIENTWRITE_INFO, line)`,
            // lib/pingpong.c L304-310): opt in BEFORE the greeting read so the
            // server greeting and every subsequent control-response line
            // (`CAPABILITY`/`LOGIN`/`SELECT`/`FETCH`/…) is accumulated for a
            // `-D`/`--dump-header` dump. `perform_imap` drains it to the header
            // sink after the FETCH/APPEND completion is read but before LOGOUT.
            // Idempotent (a reused connection keeps capture enabled) and
            // wire-neutral without `-D` (the header sink discards IMAP-scheme
            // INFO). Oracle: tests/data/test897.
            pp.enable_info_capture();
            let result =
                run_imap_statemachine(&mut proto, &mut pp, &mut sasl, &mut req, data, conn).await;

            // Persist the state regardless of outcome so `do_it`/`disconnect`
            // can find it (e.g. to send `LOGOUT`).
            conn.set_proto_state(Box::new(ImapConn {
                pp,
                sasl,
                proto,
                req,
            }));
            result
        })
    }

    fn do_it<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<ProtocolTransfer>> {
        Box::pin(async move {
            // Per-transfer inputs (read before borrowing the connection state).
            let no_body = data.set.opt_no_body;
            // C `imap_perform`: APPEND (upload) is selected by `data->state.upload`
            // (`-T`/`CURLOPT_UPLOAD`) OR `IS_MIME_POST(data)` (a `-F` MIME post).
            // For the mail protocols the CLI assembles the `-F` tree eagerly with
            // curl's mail strategy and parks the finished bytes via
            // `Easy::set_mime_body` (it does NOT populate `mimepost`), so the Rust
            // analog of `IS_MIME_POST` here is a configured `mime_body` — exactly
            // as SMTP's `do_it` detects a mail send (`mime_body.is_some()`). Oracle:
            // tests/data/test647 (IMAP APPEND of a multipart MIME message).
            let upload = data.set.method == HttpReq::Put
                || !data.set.mimepost.is_null()
                || data.set.mime_body.is_some();
            let infilesize = data.set.filesize;

            // Build the request shape from the URL path/query + CUSTOMREQUEST.
            let (path, query) = url_path_and_query(data)?;
            let mut req = Imap::parse_url_path(&path, query)?;
            let custom = data.set.str(StrId::Customrequest).map(str::to_string);
            let (custom, custom_params) = Imap::parse_custom_request(custom.as_deref())?;
            req.custom = custom;
            req.custom_params = custom_params;
            if no_body {
                // C: `data->req.no_body` ⇒ no body transfer.
                req.transfer = PpTransfer::Info;
            }

            // Take the per-connection state to drive the DO dialogue.
            let state = take_imap_conn(conn)?;
            let ImapConn {
                mut pp,
                mut sasl,
                mut proto,
                ..
            } = *state;
            // `endofresp`'s LIST-state matching depends on these (C `imap->custom`).
            proto.custom_request = req.custom.is_some();
            proto.custom_name = req.custom.clone();
            proto.download_size = None;
            // Start each DO phase with an empty body-accumulation buffer. The
            // LIST/SEARCH performers also clear it, but a plain `FETCH` performer
            // does not, and on a reused connection a prior custom-FETCH transfer
            // could otherwise leave its header-line prefix behind — clearing here
            // guarantees the FETCH-literal Download path sees an empty prefix.
            proto.data_resp.clear();

            // C `imap_perform`: is the requested mailbox already selected (with a
            // matching UIDVALIDITY when one was pinned)?
            let selected = match (&req.mailbox, &proto.mailbox) {
                (Some(want), Some(sel)) => {
                    want.eq_ignore_ascii_case(sel)
                        && (req.uidvalidity.is_none()
                            || proto.mb_uidvalidity.is_none()
                            || req.uidvalidity == proto.mb_uidvalidity)
                }
                _ => false,
            };

            // C `imap_perform` DO dispatch — the exact branch order from imap.c.
            let dispatch = if upload {
                proto.perform_append(data, conn, &mut pp, &req).await
            } else if req.custom.is_some() && (selected || req.mailbox.is_none()) {
                proto.perform_list(data, conn, &mut pp, &req).await
            } else if req.custom.is_none() && selected && (req.uid.is_some() || req.mindex.is_some())
            {
                proto.perform_fetch(data, conn, &mut pp, &req).await
            } else if req.custom.is_none() && selected && req.query.is_some() {
                proto.perform_search(data, conn, &mut pp, &req).await
            } else if req.mailbox.is_some()
                && !selected
                && (req.custom.is_some()
                    || req.uid.is_some()
                    || req.mindex.is_some()
                    || req.query.is_some())
            {
                proto.perform_select(data, conn, &mut pp, &req).await
            } else {
                proto.perform_list(data, conn, &mut pp, &req).await
            };

            let drive = match dispatch {
                Ok(()) => {
                    run_imap_statemachine(&mut proto, &mut pp, &mut sasl, &mut req, data, conn).await
                }
                Err(e) => Err(e),
            };

            // Capture descriptor inputs before moving the state back.
            let download_size = proto.download_size;
            let is_body = matches!(req.transfer, PpTransfer::Body);

            conn.set_proto_state(Box::new(ImapConn {
                pp,
                sasl,
                proto,
                req,
            }));
            drive?;

            // C `imap_dophase_done`: a non-body transfer sets up no byte loop.
            let descriptor = if !is_body {
                ProtocolTransfer::new(TransferDirection::None)
            } else if upload {
                match u64::try_from(infilesize) {
                    Ok(size) => ProtocolTransfer::new(TransferDirection::Upload).with_size(size),
                    Err(_) => ProtocolTransfer::new(TransferDirection::Upload),
                }
            } else if let Some(size) = download_size {
                ProtocolTransfer::new(TransferDirection::Download).with_size(size)
            } else {
                ProtocolTransfer::new(TransferDirection::Download)
            };
            Ok(descriptor)
        })
    }

    fn done<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
        status: Result<()>,
        _premature: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // C `imap_done` ignores `premature`; only `status` triggers closure.
            let state = match take_imap_conn(conn) {
                Ok(state) => state,
                // No IMAP state ⇒ nothing to finalize; preserve the result.
                Err(_) => return status,
            };
            let connect_only = data.set.connect_only;
            // Same APPEND/upload predicate as `do_it` (C `IS_MIME_POST` ∨
            // `state.upload`): a `-F` mail MIME body is parked in `mime_body`.
            let upload = data.set.method == HttpReq::Put
                || !data.set.mimepost.is_null()
                || data.set.mime_body.is_some();

            let ImapConn {
                mut pp,
                mut sasl,
                mut proto,
                mut req,
            } = *state;

            // C: handle responses after a FETCH or APPEND body has transferred.
            let needs_final = !connect_only
                && ((req.custom.is_none() && (req.uid.is_some() || req.mindex.is_some()))
                    || (req.custom.is_some() && proto.download_size.unwrap_or(0) > 0)
                    || upload);

            let result: Result<()> = if status.is_err() {
                // C `connclose(conn, "IMAP done with bad status")`.
                conn.bits.no_reuse = true;
                status
            } else if needs_final {
                if !upload {
                    // FETCH: read the tagged completion that follows the body.
                    proto.state = ImapState::FetchFinal;
                    run_imap_statemachine(&mut proto, &mut pp, &mut sasl, &mut req, data, conn).await
                } else {
                    // APPEND: terminate the literal with an empty line, then read
                    // the tagged completion (C sends `Curl_pp_sendf(pp, "%s", "")`).
                    match proto.send_command(data, conn, &mut pp, String::new()).await {
                        Ok(()) => {
                            proto.state = ImapState::AppendFinal;
                            run_imap_statemachine(
                                &mut proto, &mut pp, &mut sasl, &mut req, data, conn,
                            )
                            .await
                        }
                        Err(e) => Err(e),
                    }
                }
            } else {
                Ok(())
            };

            // C `imap_easy_reset`: clear the per-transfer request and the cached
            // download size so the next transfer on this connection starts clean.
            req = Imap::default();
            proto.download_size = None;

            conn.set_proto_state(Box::new(ImapConn {
                pp,
                sasl,
                proto,
                req,
            }));
            result
        })
    }

    fn disconnect<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
        dead: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // C `imap_disconnect`: never errors. Send `LOGOUT` only on a live
            // connection that has an established session and nothing half-sent.
            // (C also gates on `conn->bits.protoconnstart`, which has no Rust
            // analog; the presence of `ImapConn` state stands in for it.)
            let Ok(state) = take_imap_conn(conn) else {
                return Ok(());
            };
            let ImapConn {
                mut pp,
                mut sasl,
                mut proto,
                mut req,
            } = *state;

            if !dead && !pp.needs_flush() {
                let cmd = proto.cmd_logout();
                if proto.send_command(data, conn, &mut pp, cmd).await.is_ok() {
                    proto.state = ImapState::Logout;
                    // Best-effort teardown: ignore errors (as C does).
                    let _ =
                        run_imap_statemachine(&mut proto, &mut pp, &mut sasl, &mut req, data, conn)
                            .await;
                }
            }

            conn.set_proto_state(Box::new(ImapConn {
                pp,
                sasl,
                proto,
                req,
            }));
            Ok(())
        })
    }
}

// ===========================================================================
// `perform_imap` — the IMAP/IMAPS transfer-engine seam
// ===========================================================================

/// Drive an `imap://` / `imaps://` transfer end-to-end, the IMAP analog of
/// [`ftp::perform_ftp`](crate::protocols::ftp::perform_ftp): establish the
/// (optionally implicit-TLS) connection, run the greeting → `CAPABILITY` →
/// optional `STARTTLS` → authentication session, then the DO phase
/// (`SELECT`/`FETCH`/`APPEND`/`LIST`/`SEARCH`/custom), move the body, and read
/// the trailing tagged completion in `done`, followed by a `LOGOUT` teardown.
///
/// # Body delivery
///
/// * **`FETCH`** returns a `{size}` literal of known length:
///   [`ImapHandler::do_it`] parses the size and leaves `Stop` right after the
///   untagged `* … FETCH (… {size}` line; the literal's leading bytes may
///   already sit in the ping-pong overflow ([`PingPong::take_buffered_body`]),
///   the remainder is read off the socket — exactly `size` bytes, never the
///   trailing `)` + tagged status — and delivered to `sink`. `done` then reads
///   the tagged completion (`ImapState::FetchFinal`).
/// * **`APPEND`** is an upload: after `do_it`'s `{size}` continuation, the
///   message body is streamed from `source` to the server, then `done`
///   terminates the literal and reads the tagged completion.
/// * A non-body command (`SELECT`-only, `--head`, etc.) moves no body.
///
/// # Errors
///
/// Any connection-establishment, session, authentication, command, body, or
/// transport error surfaced by the IMAP handler or the body loop.
/// Compute the IMAP connection-reuse key — the bundle key under which an
/// authenticated, mailbox-stateful control connection is parked in (and
/// recovered from) the shared pool. Keyed by `scheme | host:port | user` so that
/// two transfers with different credentials never share a session and
/// `imap`/`imaps` never collide. Returns the key plus the bare host (for the
/// `-v` reuse trace). The bracket-stripping mirrors [`connect_network_scheme`]'s
/// host normalization so a literal-IPv6 origin keys identically on dial and
/// check-in.
fn imap_reuse_key(data: &Easy, scheme: &Scheme) -> Result<(String, String)> {
    let url_str = data.url().ok_or(CurlError::UrlMalformat)?.to_string();
    let mut url = CurlUrl::new();
    url.set(CurlUPart::Url, Some(&url_str), CURLU_DEFAULT_PORT)
        .map_err(|_| CurlError::UrlMalformat)?;
    let host_bracketed = url.get(CurlUPart::Host, CURLU_URLDECODE).unwrap_or_default();
    let host = host_bracketed
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(&host_bracketed)
        .to_string();
    let port = url
        .get(CurlUPart::Port, 0)
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(scheme.default_port);
    let (user, _passwd) = resolve_credentials(data)?;
    let key = format!("{}|{}:{}|{}", scheme.name, host, port, user);
    Ok((key, host))
}

pub(crate) async fn perform_imap(
    data: &mut Easy,
    sink: &mut dyn WriteCallbacks,
    source: &mut dyn ReadCallback,
) -> Result<()> {
    // Resolve the concrete scheme descriptor (`imaps` adds `PROTOPT_SSL`).
    let is_imaps = data
        .info
        .scheme
        .as_ref()
        .and_then(|s| s.to_str().ok())
        .is_some_and(|s| s.eq_ignore_ascii_case("imaps"));
    let scheme: &'static Scheme = if is_imaps { &SCHEME_IMAPS } else { &SCHEME_IMAP };
    let handler = ImapHandler::new(scheme);

    // (1)/(2) Obtain the control connection. Connection reuse (curl's IMAP
    //     connection cache): on the CLI path — the only path with a guaranteed
    //     end-of-run pool drain (`external_pool_drain`, set solely by
    //     `set_conn_pool`) — try to reuse a pooled, already-authenticated
    //     control connection for this origin+login. A pool hit skips the TCP/TLS
    //     dial AND the greeting/CAPABILITY/STARTTLS/authentication session,
    //     resuming the live IMAP session exactly as curl does: the cached
    //     `ImapConn` carries the SASL state, the monotonic command-tag counter
    //     (`Imapc.cmdid`/`conn_letter` ⇒ continuous `A001…A006` tags across
    //     transfers), and the currently-`SELECT`ed mailbox (so `do_it`'s
    //     `selected` check elides a redundant re-`SELECT`).
    //     `CURLOPT_FRESH_CONNECT`/`CURLOPT_FORBID_REUSE` opt out (identical to
    //     the HTTP/FTP reuse gate). On the FFI easy-perform and multi-interface
    //     paths `external_pool_drain` is false, so the pool is never populated,
    //     checkout never hits, and this is byte-identical to a fresh dial +
    //     inline LOGOUT. Oracle: tests/data/test804 (no re-`SELECT` on reuse),
    //     test815/test816 (one connection, continuous tags, single trailing
    //     LOGOUT).
    let (reuse_key, host) = imap_reuse_key(data, scheme)?;
    let mut conn = {
        let mut reused: Option<Connection> = None;
        if data.external_pool_drain && !data.set.reuse_fresh && !data.set.reuse_forbid {
            let pool = data.conn_pool_handle();
            if let Some(mut candidate) = crate::conn::pool_checkout(&pool, &reuse_key) {
                // Liveness probe (curl's `Curl_conn_is_alive`): reuse only a
                // control channel still open AND carrying no unexpected pending
                // bytes — a server-side `* BYE`/close or stray data makes a
                // supposedly-idle session unsafe to reuse.
                let (alive, pending) = Curl_conn_is_alive(&mut candidate);
                if alive && !pending {
                    // Mark pool-reused (curl's `conn->bits.reuse`).
                    candidate.bits.reuse = true;
                    crate::infof!(
                        data.set.verbose,
                        "Re-using existing connection with host {host}"
                    );
                    reused = Some(candidate);
                }
                // Dead / unexpected pending data: `candidate` drops here (closing
                // its socket) and we fall through to a fresh dial.
            }
        }
        match reused {
            Some(c) => c,
            None => {
                // Fresh dial: establish the (optionally TLS) connection, stamp it
                // with the reuse key (the pool bundle key used at check-in), then
                // run the connect-phase session (greeting / CAPABILITY /
                // STARTTLS / authentication).
                let mut c = connect_network_scheme(data, scheme).await?;
                c.destination = reuse_key.clone();
                handler.connect(data, &mut c).await?;
                c
            }
        }
    };

    // (3) DO phase + body movement.
    let result: Result<()> = async {
        let xfer = handler.do_it(data, &mut conn).await?;
        match xfer.direction {
            TransferDirection::Download => {
                if let Some(size) = xfer.expected_size {
                    // FETCH literal: pull any leading literal bytes the ping-pong
                    // engine already buffered behind the untagged FETCH line, then
                    // stream exactly `size` bytes (prefix + bounded socket reads)
                    // to the client, leaving the closing `)` + tagged status for
                    // `done`.
                    //
                    // For a *custom* FETCH (`-X 'FETCH n BODY[..]'`, C
                    // `imap_state_listsearch_resp`) the untagged header line
                    // `* n FETCH (… {size}` is itself part of the body and was
                    // captured in `data_resp`; it precedes the literal. For a
                    // *plain* FETCH (C `imap_state_fetch_resp`) the header line is
                    // NOT body and `data_resp` is empty. Prepending `data_resp`
                    // therefore handles both: `header_len` is 0 for a plain FETCH,
                    // and the total delivered is `header_len + size`.
                    let (header, buffered) = {
                        let mut state = take_imap_conn(&mut conn)?;
                        let header = std::mem::take(&mut state.proto.data_resp);
                        let body = state.pp.take_buffered_body(size as usize);
                        conn.set_proto_state(state);
                        (header, body)
                    };
                    let header_len = header.len() as u64;
                    let mut prefix = header;
                    prefix.extend_from_slice(&buffered);
                    stream_body_to_sink(data, &mut conn, sink, &prefix, Some(header_len + size))
                        .await?;
                } else {
                    // A LIST/SEARCH listing has no up-front literal size: its body
                    // is the set of untagged `* …` data lines captured verbatim
                    // during the DO dialogue (`Imapc::data_resp`). Hand exactly
                    // those bytes to the client writer — passing the listing as the
                    // `prefix` with a matching `expected` size makes
                    // `stream_body_to_sink` deliver them (with end-of-stream) and
                    // perform NO socket read (the trailing tagged status is read by
                    // `done`). An empty listing still flushes a zero-length
                    // end-of-stream, preserving the prior finalize behavior.
                    let listing = {
                        let mut state = take_imap_conn(&mut conn)?;
                        let body = std::mem::take(&mut state.proto.data_resp);
                        conn.set_proto_state(state);
                        body
                    };
                    let n = listing.len() as u64;
                    stream_body_to_sink(data, &mut conn, sink, &listing, Some(n)).await?;
                }
            }
            TransferDirection::Upload => {
                // APPEND: stream the message body (the literal whose size `do_it`
                // already announced) to the server.
                //
                // A deferred MIME body content-transfer-encoder error (the
                // `7bit` encoder rejecting a high-bit byte) is replayed here:
                // curl streams the body lazily and reports `CURLE_READ_ERROR`
                // only during the literal transfer. The CLI assembles the body
                // eagerly and parked the error as `mime_body_read_error` (with
                // an empty body), so reproduce it now rather than silently
                // sending an empty literal. Mark the connection non-reusable, as
                // the literal transfer was left incomplete (C `connclose`).
                if data.set.mime_body_read_error {
                    conn.bits.no_reuse = true;
                    crate::failf!(
                        &mut conn.filter_data.error_buffer,
                        "Failed to read data from the application"
                    );
                    return Err(CurlError::ReadError);
                }
                if let Some(body) = data.set.mime_body.clone() {
                    // `-F` MIME post: the body was assembled eagerly by the CLI
                    // (curl's mail strategy) and parked in `mime_body`; send those
                    // exact bytes, exactly as SMTP streams its `mime_body`. There
                    // is no client read source for a MIME post (`-F` does not wire
                    // one), so it must come from here rather than from `source`.
                    // Oracle: tests/data/test647.
                    let mut off = 0usize;
                    while off < body.len() {
                        let wrote =
                            Curl_conn_send(&mut conn, FIRSTSOCKET, &body[off..], false).await?;
                        if wrote == 0 {
                            return Err(CurlError::UploadFailed);
                        }
                        off += wrote;
                    }
                    data.info.size_upload = body.len() as i64;
                } else {
                    // `-T` upload: stream from the client read source.
                    let total_len = if data.set.filesize >= 0 {
                        Some(data.set.filesize as u64)
                    } else {
                        None
                    };
                    let mut reader = UploadReader::new(total_len, false);
                    let mut buf = vec![0u8; 64 * 1024];
                    let mut total: i64 = 0;
                    // `read` yields `Data` until EOF (and never `Paused`, since
                    // `can_pause = false`), so the loop ends on the first non-`Data`.
                    while let ReadStep::Data(n) = reader.read(&mut buf, source)? {
                        let mut off = 0usize;
                        while off < n {
                            let wrote =
                                Curl_conn_send(&mut conn, FIRSTSOCKET, &buf[off..n], false).await?;
                            if wrote == 0 {
                                return Err(CurlError::UploadFailed);
                            }
                            off += wrote;
                        }
                        total += n as i64;
                    }
                    data.info.size_upload = total;
                }
            }
            TransferDirection::None | TransferDirection::Bidirectional => {}
        }
        Ok(())
    }
    .await;

    // (4) Finalize (reads the tagged completion for FETCH/APPEND), then either
    //     park the live session in the pool for a subsequent same-origin
    //     transfer to reuse (deferring LOGOUT to the end-of-run drain) or send
    //     LOGOUT inline.
    let premature = result.is_err();
    let done = handler.done(data, &mut conn, result, premature).await;

    // Drain the "response lines as headers" capture (the greeting + every
    // control-response line read for this transfer — including the untagged
    // `* … FETCH (… {N}` header line, the trailing envelope that follows a
    // `{N}` literal body, and the tagged completion) to the header sink as
    // `ClientWriteType::INFO`. This runs AFTER `done` has read the FETCH/APPEND
    // completion but BEFORE LOGOUT (deferred to the pool drain on reuse, or sent
    // inline by `disconnect`), so the `-D` dump excludes the LOGOUT exchange —
    // mirroring FTP's drain-before-`QUIT` and C `Curl_pp_readresp`'s per-line
    // `CLIENTWRITE_INFO` (lib/pingpong.c L304-310). Wire-neutral without `-D`
    // (the CLI header sink discards IMAP-scheme INFO). Best-effort: a header-
    // sink write failure must not mask the transfer outcome (`done`), and a
    // missing state (which cannot occur — `done` re-parks it) just skips the
    // dump. Oracle: tests/data/test897.
    if let Ok(mut state) = take_imap_conn(&mut conn) {
        if let Some(captured) = state.pp.drain_info_capture() {
            if !captured.is_empty() {
                let mut writer =
                    crate::transfer::ClientWriter::with_options(data.set.include_header, false);
                let _ = writer.write(crate::transfer::ClientWriteType::INFO, &captured, sink);
            }
        }
        conn.set_proto_state(state);
    }

    let reusable =
        data.external_pool_drain && done.is_ok() && !conn.bits.no_reuse && !conn.is_closed();
    if reusable {
        // Defer LOGOUT: check the authenticated session back in so the next
        // same-origin transfer reuses it. The single trailing LOGOUT is issued
        // by the end-of-run pool drain ([`ftp_drain_pool`], which dispatches a
        // pooled `ImapConn` to [`ImapHandler::disconnect`]). Oracle:
        // tests/data/test815, test816 — exactly one LOGOUT, after both transfers.
        let pool = data.conn_pool_handle();
        let maxconnects = data.set.maxconnects;
        crate::conn::pool_checkin(&pool, conn, maxconnects);
    } else {
        // Inline teardown. Pass `dead = conn.is_closed()` (NOT `done.is_err()`):
        // a transfer-level error that leaves the socket alive — e.g. a
        // UIDVALIDITY mismatch (`CURLE_REMOTE_FILE_NOT_FOUND`) — must still send
        // LOGOUT, matching curl's `imap_disconnect`, which gates LOGOUT on the
        // connection being live, not on the transfer outcome. Only a genuinely
        // dead socket suppresses LOGOUT. Oracle: tests/data/test803 (SELECT
        // UIDVALIDITY failure still emits A004 LOGOUT, errorcode 78).
        let dead = conn.is_closed();
        let _ = handler.disconnect(data, &mut conn, dead).await;
    }
    done
}

// ===========================================================================
// Unit tests — exercise the pure parsing / formatting / classification logic
// against the C oracle's exact behavior (`lib/imap.c`). These compile only with
// the `imap` feature (the module itself is feature-gated in `mod.rs`) and touch
// no I/O, so they need neither a runtime nor a live connection.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    // The SASL mechanism bits are not used by the production code (which routes
    // through `decode_mech`), so import them explicitly for the capability test.
    use crate::auth::sasl::{
        Sasl, SASL_AUTH_DEFAULT, SASL_FLAG_BASE64, SASL_MECH_LOGIN, SASL_MECH_PLAIN,
    };

    /// Decode a staged/owned wire buffer to `&str` for readable assertions.
    fn as_str(bytes: &[u8]) -> &str {
        std::str::from_utf8(bytes).expect("wire bytes must be valid UTF-8")
    }

    // ---- imap_is_bchar (C `imap_is_bchar`) -----------------------------

    #[test]
    fn bchar_accepts_alnum_and_subdelims() {
        for ch in b"abcXYZ0189".iter().copied() {
            assert!(imap_is_bchar(ch), "{:?} should be a bchar", ch as char);
        }
        for ch in b":@/&=-._~!$'()*+,%".iter().copied() {
            assert!(imap_is_bchar(ch), "{:?} should be a bchar", ch as char);
        }
    }

    #[test]
    fn bchar_rejects_separators_and_controls() {
        for ch in [b' ', b';', b'<', b'>', b'"', b'#', b'\0', b'\r', b'\n', 0x7f] {
            assert!(!imap_is_bchar(ch), "{ch:#x} should not be a bchar");
        }
    }

    // ---- imap_atom (C `imap_atom`; escapes the set "() {%*]\\\"") -------

    #[test]
    fn atom_passes_through_plain_text() {
        assert_eq!(imap_atom("INBOX", false), "INBOX");
        assert_eq!(imap_atom("INBOX", true), "INBOX");
    }

    #[test]
    fn atom_quotes_when_special_and_escapes_only_when_asked() {
        // A space forces the quoted-string form.
        assert_eq!(imap_atom("Sent Items", false), r#""Sent Items""#);
        // `escape_only` suppresses the surrounding quotes (used for LIST).
        assert_eq!(imap_atom("Sent Items", true), "Sent Items");
    }

    #[test]
    fn atom_backslash_escapes_quote_and_backslash() {
        // An embedded `"` is backslash-escaped, and the atom is quoted.
        assert_eq!(imap_atom(r#"a"b"#, false), r#""a\"b""#);
        // A literal backslash is likewise escaped.
        assert_eq!(imap_atom(r"a\b", false), r#""a\\b""#);
    }

    // ---- imap_urldecode (C `Curl_urldecode` with REJECT_CTRL) -----------

    #[test]
    fn urldecode_decodes_valid_triplets() {
        assert_eq!(imap_urldecode(b"a%20b").unwrap(), "a b");
        assert_eq!(imap_urldecode(b"%41%42%43").unwrap(), "ABC");
        assert_eq!(imap_urldecode(b"plain").unwrap(), "plain");
    }

    #[test]
    fn urldecode_keeps_invalid_percent_literal() {
        // Not a valid %XX triplet -> the '%' is taken literally.
        assert_eq!(imap_urldecode(b"a%zzb").unwrap(), "a%zzb");
        assert_eq!(imap_urldecode(b"trail%").unwrap(), "trail%");
    }

    #[test]
    fn urldecode_rejects_decoded_control_bytes() {
        // A decoded byte below 0x20 is rejected (REJECT_CTRL).
        assert!(imap_urldecode(b"%1f").is_err());
        assert!(imap_urldecode(b"%00").is_err());
    }

    // ---- hex_val -------------------------------------------------------

    #[test]
    fn hex_val_maps_hex_digits_only() {
        assert_eq!(hex_val(b'0'), Some(0));
        assert_eq!(hex_val(b'9'), Some(9));
        assert_eq!(hex_val(b'a'), Some(10));
        assert_eq!(hex_val(b'F'), Some(15));
        assert_eq!(hex_val(b'g'), None);
        assert_eq!(hex_val(b' '), None);
    }

    // ---- imap_matchresp (C `imap_matchresp`) ---------------------------

    #[test]
    fn matchresp_matches_command_after_optional_number() {
        assert!(imap_matchresp(b"* CAPABILITY IMAP4rev1\r\n", b"CAPABILITY"));
        assert!(imap_matchresp(b"* 1 FETCH (FLAGS ())\r\n", b"FETCH"));
        // The command word may sit immediately before the CRLF.
        assert!(imap_matchresp(b"* SEARCH\r\n", b"SEARCH"));
        // Matching is case-insensitive.
        assert!(imap_matchresp(b"* capability x\r\n", b"CAPABILITY"));
    }

    #[test]
    fn matchresp_rejects_mismatch_missing_prefix_and_partial_word() {
        assert!(!imap_matchresp(b"* OK ready\r\n", b"FETCH"));
        assert!(!imap_matchresp(b"A001 OK\r\n", b"CAPABILITY")); // not an untagged line
        assert!(!imap_matchresp(b"* FETCHED x\r\n", b"FETCH")); // not a word boundary
    }

    // ---- imap_find_literal / parse_literal_size ------------------------

    #[test]
    fn find_literal_locates_brace_skipping_quoted_run() {
        let line = b"* 1 FETCH (BODY[] {42}\r\n";
        let idx = imap_find_literal(line).unwrap();
        assert_eq!(line[idx], b'{');
        // A `{` inside a quoted string is skipped; the real literal is at 13.
        let q = br#"* LIST "a{b" {5}"#;
        assert_eq!(imap_find_literal(q), Some(13));
    }

    #[test]
    fn parse_literal_size_requires_digits_then_brace() {
        assert_eq!(parse_literal_size(b"42}"), Some(42));
        assert_eq!(parse_literal_size(b"0}"), Some(0));
        assert_eq!(parse_literal_size(b"}"), None); // no digits
        assert_eq!(parse_literal_size(b"42"), None); // no closing brace
        assert_eq!(parse_literal_size(b"4x}"), None); // junk before brace
    }

    // ---- Imap::parse_url_path (C `imap_parse_url_path`) ----------------

    #[test]
    fn url_path_bare_mailbox() {
        let imap = Imap::parse_url_path("/INBOX", None).unwrap();
        assert_eq!(imap.mailbox.as_deref(), Some("INBOX"));
        assert!(imap.uid.is_none());
        assert!(imap.query.is_none());
    }

    #[test]
    fn url_path_uid_blocks_query() {
        let imap =
            Imap::parse_url_path("/INBOX;UID=1", Some("SUBJECT x".to_string())).unwrap();
        assert_eq!(imap.mailbox.as_deref(), Some("INBOX"));
        assert_eq!(imap.uid.as_deref(), Some("1"));
        // RFC 5092: a UID suppresses the search query.
        assert!(imap.query.is_none());
    }

    #[test]
    fn url_path_section_and_partial() {
        let imap =
            Imap::parse_url_path("/INBOX;UID=3;SECTION=1.2;PARTIAL=0.1024", None).unwrap();
        assert_eq!(imap.uid.as_deref(), Some("3"));
        assert_eq!(imap.section.as_deref(), Some("1.2"));
        assert_eq!(imap.partial.as_deref(), Some("0.1024"));
    }

    #[test]
    fn url_path_uidvalidity_is_numeric() {
        let imap = Imap::parse_url_path("/INBOX;UIDVALIDITY=271828", None).unwrap();
        assert_eq!(imap.uidvalidity, Some(271_828));
    }

    #[test]
    fn url_path_query_applies_with_mailbox_and_no_uid() {
        let imap = Imap::parse_url_path("/INBOX", Some("FROM bob".to_string())).unwrap();
        assert_eq!(imap.query.as_deref(), Some("FROM bob"));
    }

    #[test]
    fn url_path_query_dropped_without_mailbox() {
        let imap = Imap::parse_url_path("/", Some("ignored".to_string())).unwrap();
        assert!(imap.mailbox.is_none());
        assert!(imap.query.is_none());
    }

    #[test]
    fn url_path_strips_trailing_slash_and_percent_decodes() {
        let imap = Imap::parse_url_path("/IN%20BOX/", None).unwrap();
        assert_eq!(imap.mailbox.as_deref(), Some("IN BOX"));
    }

    #[test]
    fn url_path_unknown_param_is_malformed() {
        assert!(matches!(
            Imap::parse_url_path("/INBOX;BOGUS=1", None),
            Err(CurlError::UrlMalformat)
        ));
    }

    #[test]
    fn url_path_param_without_equals_is_malformed() {
        assert!(matches!(
            Imap::parse_url_path("/INBOX;UID", None),
            Err(CurlError::UrlMalformat)
        ));
    }

    // ---- Imap::parse_custom_request (C `imap_parse_custom_request`) -----

    #[test]
    fn custom_request_splits_verb_and_params() {
        let (verb, params) = Imap::parse_custom_request(Some("STORE 1 +FLAGS")).unwrap();
        assert_eq!(verb.as_deref(), Some("STORE"));
        // The parameter tail keeps its leading space, as in C.
        assert_eq!(params.as_deref(), Some(" 1 +FLAGS"));
    }

    #[test]
    fn custom_request_verb_only_and_none() {
        let (verb, params) = Imap::parse_custom_request(Some("EXPUNGE")).unwrap();
        assert_eq!(verb.as_deref(), Some("EXPUNGE"));
        assert!(params.is_none());

        let (verb, params) = Imap::parse_custom_request(None).unwrap();
        assert!(verb.is_none());
        assert!(params.is_none());
    }

    #[test]
    fn custom_request_is_url_decoded() {
        let (verb, params) = Imap::parse_custom_request(Some("STORE%201")).unwrap();
        assert_eq!(verb.as_deref(), Some("STORE"));
        assert_eq!(params.as_deref(), Some(" 1"));
    }

    // ---- append_flags (C `imap_perform_append` flag loop) --------------

    #[test]
    fn append_flags_empty_is_blank() {
        assert_eq!(append_flags(0), "");
    }

    #[test]
    fn append_flags_single_and_full_in_canonical_order() {
        assert_eq!(append_flags(CURLULFLAG_SEEN), r" (\Seen)");
        assert_eq!(
            append_flags(CURLULFLAG_ANSWERED | CURLULFLAG_SEEN),
            r" (\Answered \Seen)"
        );
        assert_eq!(
            append_flags(
                CURLULFLAG_ANSWERED
                    | CURLULFLAG_DELETED
                    | CURLULFLAG_DRAFT
                    | CURLULFLAG_FLAGGED
                    | CURLULFLAG_SEEN
            ),
            r" (\Answered \Deleted \Draft \Flagged \Seen)"
        );
    }

    // ---- tag generation + command builders -----------------------------

    #[test]
    fn tag_letter_and_counter_progression() {
        let mut a = Imapc::new(0); // connection 0 -> 'A'
        assert_eq!(a.next_tag(), "A001");
        assert_eq!(a.next_tag(), "A002");
        assert_eq!(a.resptag, "A002"); // resptag tracks the most recent tag
        let mut b = Imapc::new(1); // connection 1 -> 'B'
        assert_eq!(b.next_tag(), "B001");
        let mut wrap = Imapc::new(26); // 26 % 26 -> 'A'
        assert_eq!(wrap.next_tag(), "A001");
    }

    #[test]
    fn cmd_simple_verbs() {
        let mut c = Imapc::new(0);
        assert_eq!(c.cmd_capability(), "A001 CAPABILITY");
        assert_eq!(c.cmd_starttls(), "A002 STARTTLS");
        assert_eq!(c.cmd_logout(), "A003 LOGOUT");
    }

    #[test]
    fn cmd_login_uses_atoms() {
        let mut c = Imapc::new(0);
        c.user = "alice".to_string();
        c.passwd = "s3cret".to_string();
        assert_eq!(c.cmd_login(), "A001 LOGIN alice s3cret");
        // A password containing a space is quoted.
        let mut c2 = Imapc::new(0);
        c2.user = "bob".to_string();
        c2.passwd = "pa ss".to_string();
        assert_eq!(c2.cmd_login(), r#"A001 LOGIN bob "pa ss""#);
    }

    #[test]
    fn cmd_select_quotes_spaces() {
        let mut c = Imapc::new(0);
        assert_eq!(c.cmd_select("INBOX"), "A001 SELECT INBOX");
        let mut c2 = Imapc::new(0);
        assert_eq!(c2.cmd_select("Sent Items"), r#"A001 SELECT "Sent Items""#);
    }

    #[test]
    fn cmd_fetch_uid_and_mindex_forms() {
        // UID present -> "UID FETCH", empty section -> "BODY[]".
        let mut c = Imapc::new(0);
        assert_eq!(c.cmd_fetch("UID FETCH", "1", "", None), "A001 UID FETCH 1 BODY[]");
        // Section + partial render as "BODY[<section>]<<partial>>".
        let mut c2 = Imapc::new(0);
        assert_eq!(
            c2.cmd_fetch("UID FETCH", "7", "1.2", Some("0.512")),
            "A001 UID FETCH 7 BODY[1.2]<0.512>"
        );
        // A message index uses the bare "FETCH" verb.
        let mut c3 = Imapc::new(0);
        assert_eq!(c3.cmd_fetch("FETCH", "4", "", None), "A001 FETCH 4 BODY[]");
    }

    #[test]
    fn cmd_append_includes_size_and_flags() {
        let mut c = Imapc::new(0);
        assert_eq!(c.cmd_append("INBOX", "", 42), "A001 APPEND INBOX {42}");
        let mut c2 = Imapc::new(0);
        assert_eq!(
            c2.cmd_append("INBOX", r" (\Seen)", 10),
            r"A001 APPEND INBOX (\Seen) {10}"
        );
    }

    #[test]
    fn cmd_search_and_list_forms() {
        let mut c = Imapc::new(0);
        assert_eq!(c.cmd_search("SUBJECT hello"), "A001 SEARCH SUBJECT hello");
        // The built-in listing wraps the mailbox atom in literal quotes.
        let mut c2 = Imapc::new(0);
        assert_eq!(c2.cmd_list(None, None, Some("INBOX")), r#"A001 LIST "INBOX" *"#);
        // A custom verb is sent verbatim with its (space-leading) parameters.
        let mut c3 = Imapc::new(0);
        assert_eq!(
            c3.cmd_list(Some("XLIST"), Some(r#" "" *"#), None),
            r#"A001 XLIST "" *"#
        );
    }

    // ---- parse_capability (C `imap_state_capability_resp`) -------------

    #[test]
    fn capability_detects_flags_and_mechanisms() {
        let mut c = Imapc::new(0);
        let mut sasl = Sasl::new();
        c.resp_line =
            b"* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED AUTH=PLAIN AUTH=LOGIN SASL-IR\r\n"
                .to_vec();
        c.parse_capability(&mut sasl);
        assert!(c.tls_supported, "STARTTLS not detected");
        assert!(c.login_disabled, "LOGINDISABLED not detected");
        assert!(c.ir_supported, "SASL-IR not detected");
        assert_eq!(sasl.authmechs & SASL_MECH_PLAIN, SASL_MECH_PLAIN);
        assert_eq!(sasl.authmechs & SASL_MECH_LOGIN, SASL_MECH_LOGIN);
    }

    #[test]
    fn capability_minimal_sets_nothing() {
        let mut c = Imapc::new(0);
        let mut sasl = Sasl::new();
        c.resp_line = b"* CAPABILITY IMAP4rev1 IDLE\r\n".to_vec();
        c.parse_capability(&mut sasl);
        assert!(!c.tls_supported);
        assert!(!c.login_disabled);
        assert!(!c.ir_supported);
        assert_eq!(sasl.authmechs, 0);
    }

    #[test]
    fn capability_ignores_auth_substring_prefix() {
        // "AUTH=PLAINX" must NOT match PLAIN (the mechanism name must be exact).
        let mut c = Imapc::new(0);
        let mut sasl = Sasl::new();
        c.resp_line = b"* CAPABILITY AUTH=PLAINX\r\n".to_vec();
        c.parse_capability(&mut sasl);
        assert_eq!(sasl.authmechs & SASL_MECH_PLAIN, 0);
    }

    // ---- classify_response (the pure core of `endofresp`) --------------

    fn classifier(state: ImapState, tag: &str) -> Imapc {
        let mut c = Imapc::new(0);
        c.state = state;
        c.resptag = tag.to_string();
        c
    }

    #[test]
    fn classify_tagged_ok_no_bad_preauth() {
        let c = classifier(ImapState::Fetch, "A001");
        assert_eq!(c.classify_response(b"A001 OK done\r\n"), Some(IMAP_RESP_OK));
        assert_eq!(c.classify_response(b"A001 NO denied\r\n"), Some(IMAP_RESP_NOT_OK));
        assert_eq!(c.classify_response(b"A001 BAD syntax\r\n"), Some(IMAP_RESP_NOT_OK));
        assert_eq!(c.classify_response(b"A001 PREAUTH hi\r\n"), Some(IMAP_RESP_PREAUTH));
        // A line carrying a *different* tag is not our completion.
        assert_eq!(c.classify_response(b"A002 OK other\r\n"), None);
    }

    #[test]
    fn classify_untagged_is_state_dependent() {
        let cap = classifier(ImapState::Capability, "A001");
        assert_eq!(
            cap.classify_response(b"* CAPABILITY IMAP4rev1\r\n"),
            Some(IMAP_RESP_UNTAGGED)
        );
        // An untagged line that is not the awaited data response is consumed.
        assert_eq!(cap.classify_response(b"* OK noted\r\n"), None);

        let fetch = classifier(ImapState::Fetch, "A001");
        assert_eq!(
            fetch.classify_response(b"* 1 FETCH (BODY[] {3}\r\n"),
            Some(IMAP_RESP_UNTAGGED)
        );
    }

    #[test]
    fn classify_continuation_only_in_auth_or_append() {
        let auth = classifier(ImapState::Authenticate, "A001");
        assert_eq!(
            auth.classify_response(b"+ Y2hhbGxlbmdl\r\n"),
            Some(IMAP_RESP_CONTINUATION)
        );
        // The bare "+\r\n" continuation form is also accepted.
        assert_eq!(auth.classify_response(b"+\r\n"), Some(IMAP_RESP_CONTINUATION));

        let append = classifier(ImapState::Append, "A001");
        assert_eq!(append.classify_response(b"+ go\r\n"), Some(IMAP_RESP_CONTINUATION));

        // A continuation in any other state is a hard protocol error (-1).
        let cap = classifier(ImapState::Capability, "A001");
        assert_eq!(cap.classify_response(b"+ x\r\n"), Some(-1));
    }

    #[test]
    fn classify_continuation_suppressed_for_custom_request() {
        let mut c = classifier(ImapState::Authenticate, "A001");
        c.custom_request = true;
        // C disables continuation handling while a custom request is in flight.
        assert_eq!(c.classify_response(b"+ x\r\n"), None);
    }

    // ---- SaslProto impl (the C `saslimap` vtable) ----------------------

    #[test]
    fn sasl_vtable_constants_match_c() {
        let c = Imapc::new(0);
        assert_eq!(c.service(), "imap");
        assert_eq!(c.maxirlen(), 0);
        assert_eq!(c.cont_code(), IMAP_RESP_CONTINUATION);
        assert_eq!(c.final_code(), IMAP_RESP_OK);
        assert_eq!(c.def_mechs(), SASL_AUTH_DEFAULT);
        assert_eq!(c.flags(), SASL_FLAG_BASE64);
    }

    #[test]
    fn sasl_send_auth_formats_authenticate_command() {
        // No initial response -> "<tag> AUTHENTICATE <mech>".
        let mut c = Imapc::new(0);
        c.send_auth("PLAIN", None).unwrap();
        assert_eq!(c.staged.len(), 1);
        assert_eq!(as_str(&c.staged[0]), "A001 AUTHENTICATE PLAIN");

        // With an initial response (SASL-IR) -> "<tag> AUTHENTICATE <mech> <ir>".
        let mut c2 = Imapc::new(0);
        c2.send_auth("PLAIN", Some(b"dGVzdA==")).unwrap();
        assert_eq!(as_str(&c2.staged[0]), "A001 AUTHENTICATE PLAIN dGVzdA==");
    }

    #[test]
    fn sasl_cont_and_cancel_stage_lines() {
        // A continuation stages the bare base64 line.
        let mut c = Imapc::new(0);
        c.cont_auth("PLAIN", b"cmVzcG9uc2U=").unwrap();
        assert_eq!(as_str(&c.staged[0]), "cmVzcG9uc2U=");
        // Cancelling stages a bare "*".
        let mut c2 = Imapc::new(0);
        c2.cancel_auth("PLAIN").unwrap();
        assert_eq!(as_str(&c2.staged[0]), "*");
    }

    #[test]
    fn sasl_get_message_strips_continuation_prefix() {
        let mut c = Imapc::new(0);
        c.resp_line = b"+ Y2hhbGxlbmdl\r\n".to_vec();
        assert_eq!(as_str(&c.get_message().unwrap()), "Y2hhbGxlbmdl");
        // An empty continuation ("+ ") yields an empty challenge.
        let mut c2 = Imapc::new(0);
        c2.resp_line = b"+ \r\n".to_vec();
        assert!(c2.get_message().unwrap().is_empty());
    }

    // ---- end-to-end session flow over a mock control connection ----------
    //
    // These drive the real tagged-command state machine (`connect` → greeting
    // → `CAPABILITY` → `LOGIN`, then `do_it` → `LIST`) against an in-memory
    // filter pre-loaded with scripted server replies. Connection id 0 makes the
    // command-tag letter `A`, so the tags are the deterministic `A001`, `A002`,
    // `A003` sequence asserted below.
    mod flow {
        use super::super::*;
        use crate::conn::filters::{CfState, ConnectionFilter};
        use crate::conn::{Connection, SchemeDescriptor, FIRSTSOCKET};
        use crate::options::CurlOption;
        use crate::setopt::OptionValue;
        use std::sync::{Arc, Mutex};

        const TRNSPRT_TCP: u8 = 3;

        struct MockFilter {
            state: CfState,
            sent: Arc<Mutex<Vec<u8>>>,
            recv_data: Arc<Mutex<Vec<u8>>>,
        }

        impl MockFilter {
            fn new(recv_data: Arc<Mutex<Vec<u8>>>, sent: Arc<Mutex<Vec<u8>>>) -> Self {
                Self {
                    state: CfState {
                        connected: true,
                        ..Default::default()
                    },
                    sent,
                    recv_data,
                }
            }
        }

        impl ConnectionFilter for MockFilter {
            fn name(&self) -> &'static str {
                "MOCK-IMAP"
            }
            fn cf_state(&self) -> &CfState {
                &self.state
            }
            fn cf_state_mut(&mut self) -> &mut CfState {
                &mut self.state
            }
            fn send<'a>(&'a mut self, buf: &'a [u8], _eos: bool) -> BoxFuture<'a, Result<usize>> {
                let sent = self.sent.clone();
                let chunk = buf.to_vec();
                Box::pin(async move {
                    sent.lock().unwrap().extend_from_slice(&chunk);
                    Ok(chunk.len())
                })
            }
            fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize>> {
                let queue = self.recv_data.clone();
                Box::pin(async move {
                    let mut guard = queue.lock().unwrap();
                    let n = buf.len().min(guard.len());
                    buf[..n].copy_from_slice(&guard[..n]);
                    guard.drain(..n);
                    Ok(n)
                })
            }
        }

        /// Build a mock IMAP control connection (connection id 0 ⇒ tag letter
        /// `A`) pre-loaded with the scripted replies. No proto-state is
        /// installed — `connect` creates the `ImapConn`.
        fn make_imap_conn(server: &[u8]) -> (Connection, Arc<Mutex<Vec<u8>>>) {
            let scheme = &SCHEME_IMAP;
            let desc = SchemeDescriptor::new(
                scheme.name,
                scheme.default_port,
                scheme.flags,
                scheme.protocol,
            );
            let mut conn = Connection::new(
                format!("{}:{}", scheme.name, scheme.default_port),
                TRNSPRT_TCP,
                desc,
            );
            conn.remote_host = "127.0.0.1".to_string();
            conn.connection_id = 0; // ⇒ command-tag letter 'A'
            let recv = Arc::new(Mutex::new(server.to_vec()));
            let sent = Arc::new(Mutex::new(Vec::new()));
            conn.cfilter[FIRSTSOCKET].add_filter(Box::new(MockFilter::new(recv, sent.clone())));
            (conn, sent)
        }

        fn with_url(url: &str) -> Easy {
            let mut data = Easy::new();
            data.setopt(
                CurlOption::CURLOPT_URL,
                OptionValue::Str(Some(url.to_string())),
            )
            .expect("set url");
            data
        }

        fn sent_string(sent: &Arc<Mutex<Vec<u8>>>) -> String {
            String::from_utf8(sent.lock().unwrap().clone()).unwrap()
        }

        #[tokio::test]
        async fn connect_runs_capability_then_cleartext_login() {
            // Greeting → CAPABILITY (no AUTH= mechs, LOGIN not disabled) ⇒
            // cleartext LOGIN. Tags are the deterministic A001/A002 sequence.
            let server = b"* OK [CAPABILITY IMAP4rev1] server ready\r\n\
                * CAPABILITY IMAP4rev1\r\n\
                A001 OK CAPABILITY completed\r\n\
                A002 OK LOGIN completed\r\n";
            let (mut conn, sent) = make_imap_conn(server);
            let mut data = with_url("imap://bob:secret@127.0.0.1/");

            let handler = ImapHandler::new(&SCHEME_IMAP);
            handler.connect(&mut data, &mut conn).await.expect("connect");

            let wire = sent_string(&sent);
            assert!(wire.contains("A001 CAPABILITY\r\n"), "CAPABILITY wrong: {wire:?}");
            // LOGIN with plain-atom credentials (no quoting needed).
            assert!(
                wire.contains("A002 LOGIN bob secret\r\n"),
                "LOGIN wrong: {wire:?}"
            );
        }

        #[tokio::test]
        async fn connect_then_do_it_root_list_sends_list_command() {
            // After LOGIN, a root URL (no mailbox, no custom request) drives the
            // default `LIST "" *` and consumes the untagged listing line.
            let server = b"* OK [CAPABILITY IMAP4rev1] ready\r\n\
                * CAPABILITY IMAP4rev1\r\n\
                A001 OK done\r\n\
                A002 OK LOGIN ok\r\n\
                * LIST (\\HasNoChildren) \"/\" INBOX\r\n\
                A003 OK LIST completed\r\n";
            let (mut conn, sent) = make_imap_conn(server);
            let mut data = with_url("imap://bob:secret@127.0.0.1/");

            let handler = ImapHandler::new(&SCHEME_IMAP);
            handler.connect(&mut data, &mut conn).await.expect("connect");
            handler.do_it(&mut data, &mut conn).await.expect("do_it");

            let wire = sent_string(&sent);
            assert!(
                wire.contains("A003 LIST \"\" *\r\n"),
                "LIST command wrong: {wire:?}"
            );
        }

        #[tokio::test]
        async fn connect_login_rejected_is_login_denied() {
            // A tagged `NO` to the LOGIN command ⇒ CURLE_LOGIN_DENIED
            // (C `imap_state_login_resp`).
            let server = b"* OK ready\r\n\
                * CAPABILITY IMAP4rev1\r\n\
                A001 OK done\r\n\
                A002 NO [AUTHENTICATIONFAILED] invalid credentials\r\n";
            let (mut conn, _sent) = make_imap_conn(server);
            let mut data = with_url("imap://bob:wrongpass@127.0.0.1/");

            let handler = ImapHandler::new(&SCHEME_IMAP);
            let err = handler.connect(&mut data, &mut conn).await.unwrap_err();
            assert_eq!(err, CurlError::LoginDenied);
        }
    }

}

