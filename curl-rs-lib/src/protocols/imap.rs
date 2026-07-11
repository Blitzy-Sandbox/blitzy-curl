// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! IMAP / IMAPS protocol handler (RFC 3501, RFC 4959, RFC 5092) — the
//! memory-safe Rust port of curl's `lib/imap.c` (+ `lib/imap.h`) for the
//! byte-for-byte functional-parity rewrite of curl / libcurl **8.19.0-DEV**.
//!
//! IMAP is a *ping-pong* protocol: the client sends a tagged command and reads
//! the server's tagged/untagged/continuation responses before sending the next
//! one. The exchange runs over the shared [`PingPong`](crate::protocols::pingpong::PingPong)
//! engine, and authentication is driven by the shared SASL engine
//! ([`crate::auth::sasl`]); this module supplies the IMAP glue by implementing
//! both [`PingPongProtocol`](crate::protocols::pingpong::PingPongProtocol) and
//! [`SaslProto`](crate::auth::sasl::SaslProto). There is **no data channel**
//! (unlike FTP): a `FETCH` body is read inline from the control stream after the
//! `{size}` literal header, and an `APPEND` body is streamed out on the same
//! connection.
//!
//! # What this module reproduces (source-of-truth `lib/imap.c`, ~2361 lines)
//!
//! * **The `IMAP_*` state machine** ([`ImapState`], ← `imapstate`). Every state
//!   name is preserved **verbatim** (`STOP`, `SERVERGREET`, `CAPABILITY`,
//!   `STARTTLS`, `UPGRADETLS`, `AUTHENTICATE`, `LOGIN`, `LIST`, `SELECT`,
//!   `FETCH`, `FETCH_FINAL`, `APPEND`, `APPEND_FINAL`, `SEARCH`, `LOGOUT`) so the
//!   `SASL %p state change from X to Y` / `IMAP %p state change …` diagnostics on
//!   `--trace` are identical to curl's.
//! * **Command tagging** (`imap_sendf`). Each command is prefixed with a tag of
//!   the form `A001`, `A002`, … computed as `"%c%03d"` from the connection id
//!   (`'A' + connection_id % 26`) and an incrementing command counter. The
//!   greeting phase begins with the tag set to `"*"`.
//! * **Response classification** (`imap_endofresp`). A line is *tagged* when it
//!   begins with the current tag + space (mapping the following `OK` / `PREAUTH`
//!   / anything-else to [`IMAP_RESP_OK`] / [`IMAP_RESP_PREAUTH`] /
//!   [`IMAP_RESP_NOT_OK`]); *untagged* when it begins with `"* "` (accepted only
//!   in the states that expect it, gated by [`imap_matchresp`]); or a
//!   *continuation* when it is `+`/`+ …` (only in `AUTHENTICATE` / `APPEND`,
//!   needed for SASL and literals).
//! * **CAPABILITY parsing** (`imap_state_capability_resp`): `STARTTLS`,
//!   `LOGINDISABLED`, `SASL-IR`, and `AUTH=<mech>` tokens (decoded via
//!   [`decode_mech`](crate::auth::sasl::decode_mech)).
//! * **STARTTLS upgrade** and **implicit IMAPS**: `STARTTLS` → `UPGRADETLS`
//!   (perform the TLS handshake via the connection filter chain, then re-issue
//!   `CAPABILITY`); IMAPS negotiates TLS at connect time.
//! * **Authentication**: SASL via `AUTHENTICATE <mech>` (driving the shared
//!   [`Sasl`](crate::auth::sasl::Sasl) engine, reflecting the `SASL-IR` initial
//!   response capability) or clear-text `LOGIN user pass` when SASL is
//!   unavailable and `LOGINDISABLED` is not set.
//! * **Actions**: `SELECT`/`EXAMINE` (parsing `UIDVALIDITY`), `FETCH` / `UID
//!   FETCH` (parsing the `{size}` literal to download a body) + a final
//!   post-download tagged read, `APPEND` (with a `{size}` literal upload) + a
//!   final post-upload read, `SEARCH`, `LIST`/`LSUB`, custom
//!   `CURLOPT_CUSTOMREQUEST` commands, and `LOGOUT`.
//! * **URL parsing** (`imap_parse_url_path` / `imap_parse_url_options` /
//!   `imap_parse_custom_request`): the mailbox plus the hierarchical options
//!   `;UIDVALIDITY=`, `;UID=`, `;MAILINDEX=`, `;SECTION=`, `;PARTIAL=`, the
//!   `;AUTH=` login options, and the `word[ params]` split of a custom request.
//! * **Exact error mapping**: [`CurlCode::WeirdServerReply`](crate::error::CurlCode::WeirdServerReply),
//!   [`UrlMalformat`](crate::error::CurlCode::UrlMalformat),
//!   [`UseSslFailed`](crate::error::CurlCode::UseSslFailed),
//!   [`LoginDenied`](crate::error::CurlCode::LoginDenied),
//!   [`RemoteFileNotFound`](crate::error::CurlCode::RemoteFileNotFound),
//!   [`QuoteError`](crate::error::CurlCode::QuoteError),
//!   [`UploadFailed`](crate::error::CurlCode::UploadFailed), and
//!   [`NotBuiltIn`](crate::error::CurlCode::NotBuiltIn) are produced at the same
//!   points curl produces them, with the same frozen integer values.
//!
//! # Architecture notes (fidelity + the borrow model)
//!
//! curl embeds `struct pingpong` and `struct SASL` directly in `struct
//! imap_conn`, and the SASL/ping-pong callbacks reach them through the same
//! `imapc`. The Rust ping-pong engine instead hands the protocol its
//! [`PingPong`](crate::protocols::pingpong::PingPong) as a **separate** borrow
//! (`pp.statemach(proto, conn)`), and the [`SaslProto`] trait methods carry no
//! `pp` argument. [`ImapConn`] reconciles this exactly as curl behaves on the
//! wire:
//!
//! * The [`PingPong`] is stored in an `Option` and *taken out* for the duration
//!   of an engine drive, so `pp` and the `proto` (this [`ImapConn`]) are
//!   disjoint borrows. Every method that queues a command therefore receives the
//!   live `pp` as an explicit parameter.
//! * The owned [`Sasl`](crate::auth::sasl::Sasl) engine is likewise taken out
//!   while it drives, because it borrows `self` (the [`SaslProto`]) mutably.
//! * The [`SaslProto`] hooks record the exact wire bytes they would transmit
//!   into an internal queue ([`ImapConn`]'s `sasl_out`); the state machine —
//!   which holds the live `pp` — flushes that queue with
//!   [`PingPong::sendf`](crate::protocols::pingpong::PingPong::sendf) in the same
//!   synchronous step, so the bytes on the wire are identical to curl's, just
//!   produced one call later.
//!
//! Body delivery and transfer setup are **deferred to the transfer layer**, in
//! line with the ping-pong module's contract (the engine buffers are drained by
//! [`crate::transfer`]). Where curl calls `Curl_client_write` / `Curl_xfer_setup_*`
//! this module records the intent — the download/upload size and a
//! [`XferSetup`] marker — and appends any inline header/body bytes to
//! `client_body`, leaving the actual streaming to the transfer driver.
//!
//! The memory-safety cornerstone is inherited from the crate root
//! (`#![forbid(unsafe_code)]`): there is no `unsafe`, no raw pointer, and no FFI
//! anywhere in this module.

use std::mem;
use std::time::Instant;

use crate::auth::sasl::{
    decode_mech, Sasl, SaslCredentials, SaslProgress, SaslProto, SASL_AUTH_DEFAULT, SASL_AUTH_NONE,
    SASL_FLAG_BASE64,
};
use crate::conn::{ConnControl, Connection, FIRSTSOCKET};
use crate::error::{CurlCode, Error, Result};
use crate::protocols::pingpong::{PingPong, PingPongProtocol, PpTransfer};
use crate::protocols::{Pollset, ProtoFuture, Protocol, TransferCtx};

// ===========================================================================
// Authentication-type flags (← `lib/imap.h` `IMAP_TYPE_*`).
//
// The preferred-authentication classification derived from the `;AUTH=` URL
// options and consulted when deciding between SASL and clear-text `LOGIN`.
// ===========================================================================

/// `IMAP_TYPE_CLEARTEXT` — clear-text `LOGIN` authentication is preferred.
const IMAP_TYPE_CLEARTEXT: u8 = 1 << 0;
/// `IMAP_TYPE_SASL` — SASL `AUTHENTICATE` is preferred.
const IMAP_TYPE_SASL: u8 = 1 << 1;
/// `IMAP_TYPE_NONE` — no authentication type preference.
const IMAP_TYPE_NONE: u8 = 0;
/// `IMAP_TYPE_ANY` — either clear-text or SASL is acceptable.
const IMAP_TYPE_ANY: u8 = IMAP_TYPE_CLEARTEXT | IMAP_TYPE_SASL;

// ===========================================================================
// Response status codes (← `lib/imap.c` `IMAP_RESP_*` and the `endofresp`
// sentinels).
//
// `endofresp` classifies a completed response line into one of these codes,
// which the state machine then dispatches on. The tagged codes are the small
// positive integers curl uses internally; the untagged and continuation
// sentinels reuse the literal marker byte (`'*'` / `'+'`) exactly as curl's
// `*resp = '*'` / `*resp = '+'`, and a malformed continuation is `-1`.
// ===========================================================================

/// `IMAP_RESP_OK` — a tagged `OK` completion.
const IMAP_RESP_OK: i32 = 1;
/// `IMAP_RESP_NOT_OK` — a tagged `NO` / `BAD` (or unknown) completion.
const IMAP_RESP_NOT_OK: i32 = 2;
/// `IMAP_RESP_PREAUTH` — a tagged `PREAUTH` greeting (already authenticated).
const IMAP_RESP_PREAUTH: i32 = 3;
/// Untagged-response sentinel (`'*'`), returned by [`ImapConn::endofresp`] for a
/// `"* …"` line accepted in the current state.
const IMAP_RESP_UNTAGGED: i32 = b'*' as i32;
/// Continuation-response sentinel (`'+'`), returned for a `+`/`+ …` line in the
/// `AUTHENTICATE` / `APPEND` states.
const IMAP_RESP_CONTINUE: i32 = b'+' as i32;
/// Malformed-continuation sentinel (`-1`), returned for a continuation seen in
/// an unexpected state (curl's "Unexpected continuation response").
const IMAP_RESP_BAD: i32 = -1;

// ===========================================================================
// `CURLUSESSL_*` levels (← `include/curl/curl.h`, `data->set.use_ssl`).
//
// The requested transport-security level, consulted by the CAPABILITY and
// STARTTLS response handlers to decide whether to upgrade, proceed in the clear,
// or fail. Frozen ABI integers, so the literals match curl's public enum.
//
// curl's IMAP handler only ever tests `!= CURLUSESSL_NONE` and `<= CURLUSESSL_TRY`
// (`lib/imap.c` L1085/L1113); the two higher levels `CURLUSESSL_CONTROL == 2` and
// `CURLUSESSL_ALL == 3` are never named by IMAP (they only distinguish control vs
// data channels, and IMAP has a single channel), so they are documented here but
// not defined as local constants — `use_ssl` is a `u8` holding the level and the
// `<= CURLUSESSL_TRY` comparison orders them correctly regardless.
// ===========================================================================

/// `CURLUSESSL_NONE` — do not attempt TLS.
const CURLUSESSL_NONE: u8 = 0;
/// `CURLUSESSL_TRY` — try TLS, but continue in the clear if it is unavailable.
/// (Levels `CURLUSESSL_CONTROL == 2` and `CURLUSESSL_ALL == 3` sort above this
/// and are treated as "TLS required" by the `use_ssl <= CURLUSESSL_TRY` test.)
const CURLUSESSL_TRY: u8 = 1;

/// The application's default HTTP-auth selection (`CURLAUTH_BASIC`,
/// `include/curl/curl.h`), passed to [`Sasl::init`](crate::auth::sasl::Sasl::init)
/// so the protocol's default mechanism set is kept unless the config layer
/// requests otherwise. Frozen ABI integer (`1 << 0`).
const CURLAUTH_BASIC: u32 = 1 << 0;

// ===========================================================================
// ImapState — the IMAP state machine (← `imapstate`, `lib/imap.c` L82-101).
//
// (CRITICAL) The variant *names* are preserved verbatim so the `--trace`
// state-change diagnostics are byte-identical to curl's; see [`ImapState::name`].
// ===========================================================================

/// The IMAP protocol state (← `imapstate`).
///
/// One-to-one with curl's `imapstate` enum, in the same order, so a discriminant
/// cast matches curl's `names[]` index. [`ImapState::Last`] is the trailing
/// sentinel (`IMAP_LAST`) and is never a live state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImapState {
    /// `IMAP_STOP` — no requests are running; the phase is complete.
    Stop = 0,
    /// `IMAP_SERVERGREET` — waiting for the initial server greeting.
    ServerGreet,
    /// `IMAP_CAPABILITY` — a `CAPABILITY` command is in flight.
    Capability,
    /// `IMAP_STARTTLS` — a `STARTTLS` command is in flight.
    StartTls,
    /// `IMAP_UPGRADETLS` — performing the TLS handshake after `STARTTLS`.
    UpgradeTls,
    /// `IMAP_AUTHENTICATE` — a SASL `AUTHENTICATE` exchange is in progress.
    Authenticate,
    /// `IMAP_LOGIN` — a clear-text `LOGIN` command is in flight.
    Login,
    /// `IMAP_LIST` — a `LIST`/`LSUB` (or listing custom request) is in flight.
    List,
    /// `IMAP_SELECT` — a `SELECT`/`EXAMINE` command is in flight.
    Select,
    /// `IMAP_FETCH` — a `FETCH`/`UID FETCH` command is in flight (first line).
    Fetch,
    /// `IMAP_FETCH_FINAL` — reading the tagged completion after a `FETCH` body.
    FetchFinal,
    /// `IMAP_APPEND` — an `APPEND` command is in flight (awaiting continuation).
    Append,
    /// `IMAP_APPEND_FINAL` — reading the tagged completion after an `APPEND`
    /// upload.
    AppendFinal,
    /// `IMAP_SEARCH` — a `SEARCH` command is in flight.
    Search,
    /// `IMAP_LOGOUT` — a `LOGOUT` command is in flight (during disconnect).
    Logout,
    /// `IMAP_LAST` — the trailing sentinel; never a live state.
    Last,
}

impl ImapState {
    /// The `--trace` state name (← the `names[]` table in `imap_state`).
    ///
    /// Returns exactly the string curl logs for each state so the
    /// `IMAP %p state change from %s to %s` diagnostic is byte-identical.
    /// [`ImapState::Last`] has no curl name (the C table stops before it) and
    /// maps to the empty string.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            ImapState::Stop => "STOP",
            ImapState::ServerGreet => "SERVERGREET",
            ImapState::Capability => "CAPABILITY",
            ImapState::StartTls => "STARTTLS",
            ImapState::UpgradeTls => "UPGRADETLS",
            ImapState::Authenticate => "AUTHENTICATE",
            ImapState::Login => "LOGIN",
            ImapState::List => "LIST",
            ImapState::Select => "SELECT",
            ImapState::Fetch => "FETCH",
            ImapState::FetchFinal => "FETCH_FINAL",
            ImapState::Append => "APPEND",
            ImapState::AppendFinal => "APPEND_FINAL",
            ImapState::Search => "SEARCH",
            ImapState::Logout => "LOGOUT",
            ImapState::Last => "",
        }
    }
}

/// The deferred transfer setup an IMAP response handler records for the transfer
/// layer to act on (the memory-safe stand-in for curl's `Curl_xfer_setup_*`
/// calls, which reach into `struct Curl_easy` this module does not own).
///
/// The state machine cannot drive the real body stream (the ping-pong receive
/// buffer is owned by [`PingPong`](crate::protocols::pingpong::PingPong) and
/// drained by [`crate::transfer`]); it therefore records which setup curl would
/// have performed, and the transfer driver applies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum XferSetup {
    /// No transfer setup was requested yet (the initial value).
    #[default]
    None,
    /// `Curl_xfer_setup_nop` — everything is already transferred; no body I/O.
    Nop,
    /// `Curl_xfer_setup_recv` — receive a body of the given total size (header
    /// line + literal) on the primary socket (← `FETCH`).
    Recv(i64),
    /// `Curl_xfer_setup_send` — send the upload body on the primary socket
    /// (← `APPEND`).
    Send,
}

// ===========================================================================
// Imap — per-transfer request state (← `struct IMAP`, `lib/imap.c` L126-138).
// ===========================================================================

/// Per-transfer IMAP request state (← `struct IMAP`), one per easy handle.
///
/// Populated from the URL by [`ImapConn::parse_url_path`] and from
/// `CURLOPT_CUSTOMREQUEST` by [`ImapConn::parse_custom_request`], then consumed
/// by the DO-phase dispatch to choose and build the command. Reset between
/// requests by [`Imap::easy_reset`] (← `imap_easy_reset`).
#[derive(Clone, Debug)]
pub struct Imap {
    /// The transfer mode for this request (← `transfer`), defaulting to
    /// [`PpTransfer::Body`].
    transfer: PpTransfer,
    /// The mailbox to select (← `mailbox`), URL-decoded.
    mailbox: Option<String>,
    /// The message `UID` to fetch (← `uid`).
    uid: Option<String>,
    /// The mailbox index of the mail to fetch (← `mindex`, `;MAILINDEX=`).
    mindex: Option<String>,
    /// The message `SECTION` to fetch (← `section`, `;SECTION=`).
    section: Option<String>,
    /// The `PARTIAL` byte range to fetch (← `partial`, `;PARTIAL=`).
    partial: Option<String>,
    /// The `SEARCH` query (← `query`), taken from the URL query component.
    query: Option<String>,
    /// The custom request verb (← `custom`), from `CURLOPT_CUSTOMREQUEST`.
    custom: Option<String>,
    /// The custom request parameters, including the leading space (← `custom_params`).
    custom_params: Option<String>,
    /// The `UIDVALIDITY` value parsed from the URL (← `uidvalidity`).
    uidvalidity: u32,
    /// Whether [`uidvalidity`](Self::uidvalidity) was specified (← `uidvalidity_set`).
    uidvalidity_set: bool,
}

impl Default for Imap {
    /// A fresh per-request state with the body transfer mode
    /// ([`PpTransfer::Body`]) and no URL-derived fields set (←
    /// zero-initialisation of `struct IMAP`, whose `transfer` field is
    /// `PPTRANSFER_BODY == 0`). Implemented by hand because [`PpTransfer`] has no
    /// `Default`.
    fn default() -> Self {
        Imap {
            transfer: PpTransfer::Body,
            mailbox: None,
            uid: None,
            mindex: None,
            section: None,
            partial: None,
            query: None,
            custom: None,
            custom_params: None,
            uidvalidity: 0,
            uidvalidity_set: false,
        }
    }
}

impl Imap {
    /// The current transfer mode selected for this request.
    #[must_use]
    pub fn transfer(&self) -> PpTransfer {
        self.transfer
    }

    /// Reset the per-request fields for the next request on the same handle
    /// (← `imap_easy_reset`): clears every URL-derived field and restores the
    /// transfer mode to [`PpTransfer::Body`].
    pub fn easy_reset(&mut self) {
        self.mailbox = None;
        self.uid = None;
        self.mindex = None;
        self.section = None;
        self.partial = None;
        self.query = None;
        self.custom = None;
        self.custom_params = None;
        self.uidvalidity = 0;
        self.uidvalidity_set = false;
        self.transfer = PpTransfer::Body;
    }
}

// ===========================================================================
// ImapConn — per-connection state (← `struct imap_conn`, `lib/imap.c` L104-120).
// ===========================================================================

/// Per-connection IMAP state (← `struct imap_conn`), owned for the lifetime of a
/// pooled connection.
///
/// It holds the ping-pong engine, the SASL engine, the state-machine position,
/// the command tag bookkeeping, the CAPABILITY-derived server flags, and the
/// currently-selected mailbox — mirroring curl's `struct imap_conn`. It also
/// carries the active per-transfer [`Imap`] (curl keeps it on the easy handle;
/// here it is bound to the connection for the single in-flight request, which is
/// how these ping-pong protocols operate), the SASL-glue buffers that decouple
/// the [`SaslProto`] hooks from the live [`PingPong`] (see the module docs), and
/// the deferred transfer-setup outcome for [`crate::transfer`] to apply.
///
/// See the module-level *Architecture notes* for why [`pp`](Self::pp_present)
/// and [`sasl`](Self::sasl) are held in `Option`s and taken out during a drive.
pub struct ImapConn {
    /// The ping-pong control-channel engine (← `pp`). Held in an `Option` so it
    /// can be taken out for the duration of an engine drive, keeping `pp` and
    /// the `proto` (`self`) disjoint borrows.
    pp: Option<PingPong>,
    /// The SASL negotiation engine (← `sasl`). Held in an `Option` for the same
    /// take-out-during-drive reason (it borrows `self` — the [`SaslProto`] — as
    /// it runs).
    sasl: Option<Sasl>,
    /// The active per-transfer request state (curl's easy-handle `struct IMAP`).
    imap: Imap,
    /// The last selected mailbox on this connection (← `mailbox`).
    mailbox: Option<String>,
    /// The current state-machine position (← `state`). Changed only through
    /// [`ImapConn::set_state`].
    state: ImapState,
    /// The server-reported `UIDVALIDITY` of the selected mailbox (← `mb_uidvalidity`).
    mb_uidvalidity: u32,
    /// The current response tag to match, e.g. `"A001"`, or `"*"` during the
    /// greeting (← `resptag`).
    resptag: String,
    /// The preferred authentication type bitmask (← `preftype`), one of the
    /// `IMAP_TYPE_*` values.
    preftype: u8,
    /// The last used command id, incremented to form each tag (← `cmdid`,
    /// curl's `unsigned int`).
    cmdid: u32,
    /// The connection id, used to derive the tag letter (← `data->conn->connection_id`).
    connection_id: i64,
    /// Whether the SSL/TLS handshake has completed (← `ssldone`).
    ssldone: bool,
    /// Whether the connection is `PREAUTH` (already authenticated) (← `preauth`).
    preauth: bool,
    /// Whether the server advertised `STARTTLS` (← `tls_supported`).
    tls_supported: bool,
    /// Whether the server advertised `LOGINDISABLED` (← `login_disabled`).
    login_disabled: bool,
    /// Whether the server advertised `SASL-IR` (← `ir_supported`).
    ir_supported: bool,
    /// Whether [`mb_uidvalidity`](Self::mb_uidvalidity) has been set (← `mb_uidvalidity_set`).
    mb_uidvalidity_set: bool,
    /// Queued outgoing SASL command lines recorded by the [`SaslProto`] hooks
    /// (each a complete, CRLF-free command); flushed to [`PingPong`] by the
    /// state machine (see the module docs).
    sasl_out: Vec<String>,
    /// A snapshot of the latest response line, taken before driving SASL so
    /// [`SaslProto::get_message`] can parse the server's challenge without
    /// touching the live [`PingPong`].
    last_response: Vec<u8>,
    /// Accumulated body bytes destined for the client (← the `Curl_client_write`
    /// calls); drained by the transfer layer.
    client_body: Vec<u8>,
    /// The deferred transfer setup recorded for the transfer layer.
    xfer: XferSetup,
    /// The download size recorded for progress/transfer setup (← `Curl_pgrsSetDownloadSize`).
    download_size: Option<i64>,
    /// The upload size recorded for progress (← `Curl_pgrsSetUploadSize`).
    upload_size: Option<i64>,

    // --- Inputs curl reads from `struct Curl_easy`; supplied by the config layer.
    /// The requested transport-security level (← `data->set.use_ssl`).
    use_ssl: u8,
    /// Whether the application permits an initial SASL response (← `data->set.sasl_ir`).
    sasl_ir: bool,
    /// The application HTTP-auth selection used to seed SASL (← `data->set.httpauth`).
    httpauth: u32,
    /// The known upload size for `APPEND` (← `data->state.infilesize`); negative
    /// means unknown.
    infilesize: i64,
    /// Whether this is an upload (← `data->state.upload`).
    upload: bool,
    /// Whether this is a MIME POST (← `IS_MIME_POST`).
    mime_post: bool,
    /// Whether the request wants no body (← `data->req.no_body`).
    no_body: bool,
    /// Whether the handle is in connect-only mode (← `data->set.connect_only`).
    connect_only: bool,
    /// The `APPEND` message flags bitmask (← `data->set.upload_flags`).
    upload_flags: u32,
    /// The raw custom request from `CURLOPT_CUSTOMREQUEST` (← `data->set.str[STRING_CUSTOMREQUEST]`).
    custom_request: Option<String>,
    /// The bytes already counted as transferred (← `data->req.bytecount`), used
    /// by the literal handlers to detect an already-complete transfer.
    bytecount: i64,
}

impl ImapConn {
    /// Create the per-connection state for a new IMAP connection
    /// (← `imap_setup_connection`).
    ///
    /// Initializes the ping-pong engine, seeds the SASL engine with the
    /// protocol default mechanisms, sets the preferred authentication type to
    /// [`IMAP_TYPE_ANY`], and starts the response tag at `"*"` (the greeting
    /// tag). `connection_id` is curl's `data->conn->connection_id`, used to form
    /// the command tag letter.
    #[must_use]
    pub fn new(connection_id: i64) -> Self {
        let mut pp = PingPong::new();
        pp.init(Instant::now());
        ImapConn {
            pp: Some(pp),
            sasl: Some(Sasl::init(SASL_AUTH_DEFAULT, CURLAUTH_BASIC)),
            imap: Imap::default(),
            mailbox: None,
            state: ImapState::Stop,
            mb_uidvalidity: 0,
            resptag: String::from("*"),
            preftype: IMAP_TYPE_ANY,
            cmdid: 0,
            connection_id,
            ssldone: false,
            preauth: false,
            tls_supported: false,
            login_disabled: false,
            ir_supported: false,
            mb_uidvalidity_set: false,
            sasl_out: Vec::new(),
            last_response: Vec::new(),
            client_body: Vec::new(),
            xfer: XferSetup::None,
            download_size: None,
            upload_size: None,
            use_ssl: CURLUSESSL_NONE,
            sasl_ir: false,
            httpauth: CURLAUTH_BASIC,
            infilesize: -1,
            upload: false,
            mime_post: false,
            no_body: false,
            connect_only: false,
            upload_flags: 0,
            custom_request: None,
            bytecount: 0,
        }
    }

    /// The single, canonical state-transition point (← `imap_state`).
    ///
    /// Emits curl's `IMAP %p state change from %s to %s` diagnostic (via
    /// `tracing`, so `--trace`/`--verbose` output matches) whenever the state
    /// actually changes, then records the new state.
    fn set_state(&mut self, newstate: ImapState) {
        if self.state != newstate {
            tracing::trace!(
                target: "curl::imap",
                "IMAP state change from {} to {}",
                self.state.name(),
                newstate.name()
            );
        }
        self.state = newstate;
    }

    /// The current state-machine position.
    #[must_use]
    pub fn state(&self) -> ImapState {
        self.state
    }

    /// The current response tag (`"A001"`, or `"*"` during the greeting).
    #[must_use]
    pub fn resptag(&self) -> &str {
        &self.resptag
    }

    /// Whether the connection was greeted `PREAUTH`.
    #[must_use]
    pub fn is_preauth(&self) -> bool {
        self.preauth
    }

    /// Whether the server advertised `STARTTLS`.
    #[must_use]
    pub fn tls_supported(&self) -> bool {
        self.tls_supported
    }

    /// Whether the server advertised `LOGINDISABLED`.
    #[must_use]
    pub fn login_disabled(&self) -> bool {
        self.login_disabled
    }

    /// Whether the server advertised `SASL-IR`.
    #[must_use]
    pub fn ir_supported(&self) -> bool {
        self.ir_supported
    }

    /// The server-reported `UIDVALIDITY`, if one was parsed.
    #[must_use]
    pub fn mb_uidvalidity(&self) -> Option<u32> {
        self.mb_uidvalidity_set.then_some(self.mb_uidvalidity)
    }

    /// The preferred authentication type bitmask (one of the `IMAP_TYPE_*` values).
    #[must_use]
    pub fn preftype(&self) -> u8 {
        self.preftype
    }

    /// The active per-transfer request state.
    #[must_use]
    pub fn imap(&self) -> &Imap {
        &self.imap
    }

    /// The body bytes accumulated for the client so far (drained by the transfer
    /// layer).
    #[must_use]
    pub fn client_body(&self) -> &[u8] {
        &self.client_body
    }

    /// Take (drain) the body bytes accumulated for the client so far, clearing
    /// the internal buffer. Used by [`ImapHandler`] — acting as the transfer
    /// driver — to deliver each newly-buffered chunk (the untagged response
    /// lines and any header/literal bytes the DO-phase response handlers
    /// captured into [`client_body`](Self::client_body)) to the client sink,
    /// then continue accumulating from empty. The engine only ever appends to
    /// this buffer, so draining it is side-effect free.
    #[must_use]
    pub fn take_client_body(&mut self) -> Vec<u8> {
        mem::take(&mut self.client_body)
    }

    /// The deferred transfer setup recorded by the last DO-phase response.
    #[must_use]
    pub fn xfer(&self) -> XferSetup {
        self.xfer
    }

    /// The recorded download size, if any (← `Curl_pgrsSetDownloadSize`).
    #[must_use]
    pub fn download_size(&self) -> Option<i64> {
        self.download_size
    }

    /// The recorded upload size, if any (← `Curl_pgrsSetUploadSize`).
    #[must_use]
    pub fn upload_size(&self) -> Option<i64> {
        self.upload_size
    }

    /// Whether the ping-pong engine is currently present (i.e. not taken out for
    /// a drive). Primarily a test/inspection aid.
    #[must_use]
    pub fn pp_present(&self) -> bool {
        self.pp.is_some()
    }

    // --- Configuration inputs (← the corresponding `struct Curl_easy` fields).
    // These are set by the config/CLI layer before a connect/DO drive; the live
    // binding to a running easy handle is deferred to the transfer/multi driver.

    /// Set the requested transport-security level (← `data->set.use_ssl`).
    pub fn set_use_ssl(&mut self, level: u8) {
        self.use_ssl = level;
    }

    /// Set whether an initial SASL response is permitted (← `data->set.sasl_ir`).
    pub fn set_sasl_ir(&mut self, enabled: bool) {
        self.sasl_ir = enabled;
    }

    /// Re-seed the SASL engine from an application `CURLAUTH_*` selection
    /// (← `data->set.httpauth`, applied by `Curl_sasl_init`).
    pub fn set_httpauth(&mut self, httpauth: u32) {
        self.httpauth = httpauth;
        self.sasl = Some(Sasl::init(SASL_AUTH_DEFAULT, httpauth));
    }

    /// The application `CURLAUTH_*` selection currently seeding SASL.
    #[must_use]
    pub fn httpauth(&self) -> u32 {
        self.httpauth
    }

    /// Set the known upload size for `APPEND` (← `data->state.infilesize`).
    pub fn set_infilesize(&mut self, size: i64) {
        self.infilesize = size;
    }

    /// Mark this transfer as an upload (← `data->state.upload`).
    pub fn set_upload(&mut self, upload: bool) {
        self.upload = upload;
    }

    /// Mark this transfer as a MIME POST (← `IS_MIME_POST`).
    pub fn set_mime_post(&mut self, mime_post: bool) {
        self.mime_post = mime_post;
    }

    /// Mark that the request wants no body (← `data->req.no_body`).
    pub fn set_no_body(&mut self, no_body: bool) {
        self.no_body = no_body;
    }

    /// Mark the handle as connect-only (← `data->set.connect_only`).
    pub fn set_connect_only(&mut self, connect_only: bool) {
        self.connect_only = connect_only;
    }

    /// Set the `APPEND` message flags bitmask (← `data->set.upload_flags`).
    pub fn set_upload_flags(&mut self, flags: u32) {
        self.upload_flags = flags;
    }

    /// Set the raw custom request (← `data->set.str[STRING_CUSTOMREQUEST]`).
    pub fn set_custom_request(&mut self, custom: Option<String>) {
        self.custom_request = custom;
    }

    /// Set the bytes already counted as transferred (← `data->req.bytecount`).
    pub fn set_bytecount(&mut self, bytecount: i64) {
        self.bytecount = bytecount;
    }
}

// ===========================================================================
// Pure helper functions (← the file-scope `imap_*` helpers in `lib/imap.c`).
// ===========================================================================

/// Compute a command tag of the form `A001`, `A002`, … (← the `"%c%03d"` format
/// in `imap_sendf`).
///
/// The letter is `'A' + connection_id % 26` and the number is the (already
/// incremented) command id, zero-padded to three digits. The result is at most
/// four ASCII characters, matching curl's `char resptag[5]` (four bytes + NUL).
fn calc_tag(connection_id: i64, cmdid: u32) -> String {
    let letter = b'A' + u8::try_from(connection_id.rem_euclid(26)).unwrap_or(0);
    format!("{}{:03}", letter as char, cmdid)
}

/// Escape a string into an IMAP atom ready for sending (← `imap_atom`).
///
/// If the input contains none of the characters that need escaping
/// (`(`, `)`, space, `{`, `%`, `*`, `]`, `\`, `"`), it is returned unchanged.
/// Otherwise every `\` and `"` is backslash-escaped and, unless `escape_only` is
/// set, the whole atom is wrapped in double quotes. Escaping is byte-preserving
/// (a backslash is only ever inserted before the ASCII bytes `"`/`\`, which
/// never occur inside a UTF-8 multi-byte sequence), so a valid UTF-8 mailbox
/// name stays valid.
fn imap_atom(s: &str, escape_only: bool) -> String {
    const SPECIAL: &[u8] = b"() {%*]\\\"";
    let bytes = s.as_bytes();
    if !bytes.iter().any(|b| SPECIAL.contains(b)) {
        // Nothing to escape (← `len == nclean`): return a copy verbatim.
        return s.to_string();
    }

    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() + 2);
    if !escape_only {
        out.push(b'"');
    }
    for &b in bytes {
        if b == b'\\' || b == b'"' {
            out.push(b'\\');
        }
        out.push(b);
    }
    if !escape_only {
        out.push(b'"');
    }

    // Safe: insertions only added ASCII `\` before ASCII `"`/`\`, preserving the
    // original UTF-8 structure of `s`.
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

/// Find the start of a `{size}` literal in a line, skipping quoted strings
/// (← `imap_find_literal`).
///
/// Returns the index of the first unquoted `{`, honouring `\`-escapes inside a
/// double-quoted run, or `None` if there is no literal.
fn imap_find_literal(line: &[u8]) -> Option<usize> {
    let mut in_quote = false;
    let mut i = 0;
    while i < line.len() {
        if in_quote {
            if line[i] == b'\\' && i + 1 < line.len() {
                i += 2;
                continue;
            }
            if line[i] == b'"' {
                in_quote = false;
            }
        } else if line[i] == b'"' {
            in_quote = true;
        } else if line[i] == b'{' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Whether an untagged response line relates to `cmd` (← `imap_matchresp`).
///
/// The `"* "` marker is assumed already checked by the caller. Accepts both
/// `"* <cmd> …"` and `"* <number> <cmd> …"`, requiring the command (matched
/// ASCII-case-insensitively, like curl's `curl_strnequal`) to be followed by a
/// space or to sit exactly two bytes (the trailing CRLF) from the end.
fn imap_matchresp(line: &[u8], cmd: &[u8]) -> bool {
    let end = line.len();
    let cmd_len = cmd.len();
    // Skip the untagged response marker "* ".
    let mut p = 2usize;

    // Skip an optional leading number followed by a space.
    if p < end && line[p].is_ascii_digit() {
        while p < end && line[p].is_ascii_digit() {
            p += 1;
        }
        if p == end || line[p] != b' ' {
            return false;
        }
        p += 1;
    }

    // The command name must match and be followed by a space or the CRLF at the
    // end of the line.
    if p + cmd_len <= end && line[p..p + cmd_len].eq_ignore_ascii_case(cmd) {
        let after = p + cmd_len;
        (after < end && line[after] == b' ') || (after + 2 == end)
    } else {
        false
    }
}

/// Portable test of whether `ch` is a "bchar" per the RFC 5092 grammar
/// (← `imap_is_bchar`).
fn imap_is_bchar(ch: u8) -> bool {
    if ch == 0 {
        return false;
    }
    ch.is_ascii_alphanumeric() || b":@/&=-._~!$'()*+,%".contains(&ch)
}

/// Whether a custom-request parameter string looks like a listing FETCH range
/// such as `" 1:* (FLAGS …"` or `" 1,2,3 (FLAGS …"` (← `is_custom_fetch_listing_match`).
fn is_custom_fetch_listing_match(params: &[u8]) -> bool {
    if params.first() != Some(&b' ') {
        return false;
    }
    let mut i = 1;
    while i < params.len() && params[i].is_ascii_digit() {
        i += 1;
        if i >= params.len() {
            // Reached the end while consuming digits (curl's `*params == 0`).
            return false;
        }
    }
    matches!(params.get(i), Some(&b':') | Some(&b','))
}

/// Whether the active custom request is a listing FETCH (`FETCH`/`UID FETCH`
/// with a range) rather than a single-message download (← `is_custom_fetch_listing`).
fn is_custom_fetch_listing(imap: &Imap) -> bool {
    let Some(custom) = imap.custom.as_deref() else {
        return false;
    };
    if custom.eq_ignore_ascii_case("FETCH") {
        if let Some(params) = imap.custom_params.as_deref() {
            return is_custom_fetch_listing_match(params.as_bytes());
        }
        false
    } else if custom.eq_ignore_ascii_case("UID") {
        if let Some(params) = imap.custom_params.as_deref() {
            let b = params.as_bytes();
            if b.len() >= 7 && b[..7].eq_ignore_ascii_case(b" FETCH ") {
                return is_custom_fetch_listing_match(&b[6..]);
            }
        }
        false
    } else {
        false
    }
}

/// Percent-decode `input`, rejecting decoded control bytes (← `Curl_urldecode`
/// in `REJECT_CTRL` mode, `lib/escape.c`).
///
/// A `%` is decoded only when at least two hex digits follow it; otherwise it is
/// passed through literally. Any resulting byte `< 0x20` aborts the decode with
/// [`CurlCode::UrlMalformat`]. `crate::escape` is not part of this module's
/// dependency set, so this mirrors curl's decoder locally (the same approach the
/// sibling DICT handler takes).
///
/// # Errors
///
/// [`CurlCode::UrlMalformat`] if a decoded byte is a control character.
fn urldecode_reject_ctrl(input: &[u8], what: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let (byte, step) = decode_one(input, i);
        if byte < 0x20 {
            return Err(Error::url(format!(
                "IMAP {what} contains a control character"
            )));
        }
        out.push(byte);
        i += step;
    }
    Ok(out)
}

/// Decode the byte at `input[i]`, returning the decoded value and how many input
/// bytes it consumed (`3` for a `%XX` escape, `1` otherwise).
fn decode_one(input: &[u8], i: usize) -> (u8, usize) {
    if input[i] == b'%' && i + 2 < input.len() {
        if let (Some(hi), Some(lo)) = (hex_val(input[i + 1]), hex_val(input[i + 2])) {
            return ((hi << 4) | lo, 3);
        }
    }
    (input[i], 1)
}

/// Parse an IMAP literal size `{<digits>}` given the bytes immediately after the
/// opening brace (← `curlx_str_number` + `curlx_str_single('}')` in the FETCH /
/// LIST handlers).
///
/// Returns the decoded size when at least one decimal digit is present and is
/// immediately followed by `}`; `None` otherwise (including on `curl_off_t`
/// overflow, which curl also treats as an unparsable literal).
fn parse_literal_size(after_brace: &[u8]) -> Option<i64> {
    let mut i = 0;
    let mut value: i64 = 0;
    let mut any = false;
    while i < after_brace.len() && after_brace[i].is_ascii_digit() {
        any = true;
        value = value.checked_mul(10)?;
        value = value.checked_add(i64::from(after_brace[i] - b'0'))?;
        i += 1;
    }
    if any && i < after_brace.len() && after_brace[i] == b'}' {
        Some(value)
    } else {
        None
    }
}

/// Parse a leading unsigned decimal number capped at [`u32::MAX`] (←
/// `curlx_str_number(&p, &value, UINT_MAX)` for the `UIDVALIDITY` value).
///
/// Returns `None` when no digit is present or the value exceeds [`u32::MAX`].
fn parse_u32_prefix(bytes: &[u8]) -> Option<u32> {
    let mut i = 0;
    let mut value: u64 = 0;
    let mut any = false;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        any = true;
        value = value * 10 + u64::from(bytes[i] - b'0');
        if value > u64::from(u32::MAX) {
            return None;
        }
        i += 1;
    }
    if any {
        // The cast is lossless: the loop guarantees `value <= u32::MAX`.
        Some(u32::try_from(value).unwrap_or(u32::MAX))
    } else {
        None
    }
}

/// Value of a single ASCII hex digit, or `None` for a non-hex byte.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ===========================================================================
// APPEND upload-flag bits (← `include/curl/curl.h` `CURLULFLAG_*`, frozen ABI).
// Rendered, in this fixed order, into the `APPEND` flags parenthesis.
// ===========================================================================

/// `(bit, "\\Flag-name")` table, in curl's `ulflag[]` order.
const APPEND_ULFLAGS: [(u32, &str); 5] = [
    (1 << 0, "Answered"),
    (1 << 1, "Deleted"),
    (1 << 2, "Draft"),
    (1 << 3, "Flagged"),
    (1 << 4, "Seen"),
];

// ===========================================================================
// Command construction and the `imap_perform_*` builders (← `lib/imap.c`).
//
// Every builder receives the live [`PingPong`] explicitly (see the module docs)
// and queues one command via [`ImapConn::sendf`], then advances the state.
// ===========================================================================

impl ImapConn {
    /// Format and queue a tagged IMAP command (← `imap_sendf`).
    ///
    /// Computes the next tag (`++cmdid`, then `A001`-style formatting), records
    /// it as [`resptag`](Self::resptag), and queues `"<tag> <command>"` through
    /// [`PingPong::sendf`], which appends the CRLF. The command text must not
    /// carry a trailing CRLF.
    fn sendf(&mut self, pp: &mut PingPong, command: &str) -> Result<()> {
        // ++imapc->cmdid, then "%c%03d" tag.
        self.cmdid = self.cmdid.wrapping_add(1);
        self.resptag = calc_tag(self.connection_id, self.cmdid);
        pp.sendf(format_args!("{} {}", self.resptag, command))
    }

    /// Build the SASL credential bundle from the connection (← the fields
    /// `Curl_sasl_start`/`Curl_sasl_continue` read from `data`/`conn`).
    fn make_creds(&self, conn: &Connection) -> SaslCredentials {
        SaslCredentials {
            user: conn.user.clone().unwrap_or_default(),
            passwd: conn.passwd.clone().unwrap_or_default(),
            authzid: conn.sasl_authzid.clone(),
            bearer: conn.oauth_bearer.clone(),
            service_name: None,
            host: conn.host.name.clone(),
            port: i64::from(conn.port),
            sasl_ir: self.sasl_ir,
        }
    }

    /// Flush the SASL-hook output queue to the ping-pong engine (see the module
    /// docs). Each recorded line is a complete, CRLF-free command.
    fn flush_sasl_out(&mut self, pp: &mut PingPong) -> Result<()> {
        let out = std::mem::take(&mut self.sasl_out);
        for line in out {
            pp.sendf(format_args!("{line}"))?;
        }
        Ok(())
    }

    /// Send `CAPABILITY` to obtain the server's supported capabilities
    /// (← `imap_perform_capability`).
    fn perform_capability(&mut self, pp: &mut PingPong) -> Result<()> {
        // No known auth. mechanisms yet; clear the TLS capability.
        if let Some(sasl) = self.sasl.as_mut() {
            sasl.set_authmechs(SASL_AUTH_NONE);
        }
        self.tls_supported = false;
        self.sendf(pp, "CAPABILITY")?;
        self.set_state(ImapState::Capability);
        Ok(())
    }

    /// Send `STARTTLS` to begin the upgrade to TLS (← `imap_perform_starttls`).
    fn perform_starttls(&mut self, pp: &mut PingPong) -> Result<()> {
        self.sendf(pp, "STARTTLS")?;
        self.set_state(ImapState::StartTls);
        Ok(())
    }

    /// Perform the TLS handshake after a `STARTTLS` acceptance
    /// (← `imap_perform_upgrade_tls`).
    ///
    /// Inserting the TLS filter into the connection chain and rebinding the
    /// `imaps` handler is a connection-layer concern (curl's
    /// `Curl_ssl_cfilter_add` + `conn->scheme = &Curl_scheme_imaps`); that wiring
    /// is owned by [`crate::conn`] / [`crate::tls`] and deferred here. Once the
    /// handshake reports complete, `CAPABILITY` is re-issued, moving the state
    /// out of [`ImapState::UpgradeTls`], exactly as curl does.
    async fn perform_upgrade_tls(
        &mut self,
        pp: &mut PingPong,
        conn: &mut Connection,
    ) -> Result<()> {
        // Drive the (TLS-layered) connect. When the filter chain has a TLS filter
        // this performs the handshake; without one it is an idempotent no-op that
        // still reports readiness, so the re-CAPABILITY sequencing is preserved.
        let ssldone = conn.connect(FIRSTSOCKET, false).await?;
        if ssldone {
            self.ssldone = true;
            // Perform CAPABILITY now; this changes state out of UPGRADETLS.
            self.perform_capability(pp)?;
        }
        Ok(())
    }

    /// Send a clear-text `LOGIN user pass` (← `imap_perform_login`).
    ///
    /// With no username configured the connect phase simply ends (curl's
    /// `!data->state.aptr.user` guard). The username and password are rendered
    /// as quoted atoms.
    fn perform_login(&mut self, pp: &mut PingPong, conn: &Connection) -> Result<()> {
        let user = conn.user.as_deref().unwrap_or("");
        if user.is_empty() {
            self.set_state(ImapState::Stop);
            return Ok(());
        }
        let passwd = conn.passwd.as_deref().unwrap_or("");
        let user_atom = imap_atom(user, false);
        let pass_atom = imap_atom(passwd, false);
        self.sendf(pp, &format!("LOGIN {user_atom} {pass_atom}"))?;
        self.set_state(ImapState::Login);
        Ok(())
    }

    /// Initiate authentication, choosing SASL when possible and falling back to
    /// clear-text `LOGIN` otherwise (← `imap_perform_authentication`).
    fn perform_authentication(&mut self, pp: &mut PingPong, conn: &Connection) -> Result<()> {
        let creds = self.make_creds(conn);

        // Check if already authenticated OR there is not enough data to
        // authenticate with, and end the connect phase if we do not.
        let can_auth = self
            .sasl
            .as_ref()
            .is_some_and(|s| s.can_authenticate(&creds));
        if self.preauth || !can_auth {
            self.set_state(ImapState::Stop);
            return Ok(());
        }

        // Calculate the SASL login details (force_ir = server SASL-IR support).
        // `prefmech` (seeded from the URL `;AUTH=` options) governs which
        // mechanism — if any — is chosen; a `;AUTH=+LOGIN` request leaves it
        // empty so no SASL mechanism is selected and the clear-text fall-through
        // below runs, exactly as curl does.
        let mut sasl = self.sasl.take().expect("sasl present");
        let progress = sasl.sasl_start(self, &creds, self.ir_supported);
        self.sasl = Some(sasl);
        let progress = progress?;
        self.flush_sasl_out(pp)?;

        if progress == SaslProgress::InProgress {
            self.set_state(ImapState::Authenticate);
            Ok(())
        } else if !self.login_disabled && (self.preftype & IMAP_TYPE_CLEARTEXT) != 0 {
            // Perform clear text authentication.
            self.perform_login(pp, conn)
        } else {
            Err(self.sasl.as_ref().map_or_else(
                || Error::with_context(CurlCode::LoginDenied, "Authentication cannot continue"),
                |s| s.is_blocked(&creds),
            ))
        }
    }

    /// Send a `LIST`/`LSUB` command or a custom request (← `imap_perform_list`).
    fn perform_list(&mut self, pp: &mut PingPong) -> Result<()> {
        let command = if let Some(custom) = self.imap.custom.clone() {
            let params = self.imap.custom_params.clone().unwrap_or_default();
            format!("{custom}{params}")
        } else {
            let mailbox = self
                .imap
                .mailbox
                .as_deref()
                .map_or_else(String::new, |m| imap_atom(m, true));
            format!("LIST \"{mailbox}\" *")
        };
        self.sendf(pp, &command)?;
        self.set_state(ImapState::List);
        Ok(())
    }

    /// Send a `SELECT` command for the requested mailbox (← `imap_perform_select`).
    fn perform_select(&mut self, pp: &mut PingPong) -> Result<()> {
        // Invalidate old information as we are switching mailboxes.
        self.mailbox = None;

        let Some(mb) = self.imap.mailbox.clone() else {
            return Err(Error::url("Cannot SELECT without a mailbox."));
        };
        let atom = imap_atom(&mb, false);
        self.sendf(pp, &format!("SELECT {atom}"))?;
        self.set_state(ImapState::Select);
        Ok(())
    }

    /// Send a `FETCH`/`UID FETCH` command to download a message
    /// (← `imap_perform_fetch`).
    fn perform_fetch(&mut self, pp: &mut PingPong) -> Result<()> {
        let section = self.imap.section.clone().unwrap_or_default();
        let partial = self.imap.partial.clone();
        let command = if let Some(uid) = self.imap.uid.clone() {
            partial.map_or_else(
                || format!("UID FETCH {uid} BODY[{section}]"),
                |p| format!("UID FETCH {uid} BODY[{section}]<{p}>"),
            )
        } else if let Some(mindex) = self.imap.mindex.clone() {
            partial.map_or_else(
                || format!("FETCH {mindex} BODY[{section}]"),
                |p| format!("FETCH {mindex} BODY[{section}]<{p}>"),
            )
        } else {
            return Err(Error::url("Cannot FETCH without a UID."));
        };
        self.sendf(pp, &command)?;
        self.set_state(ImapState::Fetch);
        Ok(())
    }

    /// Render the `APPEND` message-flags parenthesis (← the `ulflag[]` loop).
    ///
    /// Empty when no flags are set; otherwise `" (\\Flag …)"` in curl's fixed
    /// order, e.g. `" (\\Answered \\Seen)"`.
    fn build_append_flags(&self) -> String {
        if self.upload_flags == 0 {
            return String::new();
        }
        let mut flags = String::from(" (");
        for (bit, name) in APPEND_ULFLAGS {
            if self.upload_flags & bit != 0 {
                if flags.len() > 2 {
                    flags.push(' ');
                }
                flags.push('\\');
                flags.push_str(name);
            }
        }
        flags.push(')');
        flags
    }

    /// Send an `APPEND` command to begin a message upload (← `imap_perform_append`).
    ///
    /// The MIME/creader preparation curl performs is owned by the transfer layer;
    /// here the upload size is taken from [`infilesize`](Self::set_infilesize),
    /// and an unknown (`< 0`) size is the same [`CurlCode::UploadFailed`] curl
    /// raises.
    fn perform_append(&mut self, pp: &mut PingPong) -> Result<()> {
        let Some(mb) = self.imap.mailbox.clone() else {
            return Err(Error::url("Cannot APPEND without a mailbox."));
        };
        if self.infilesize < 0 {
            return Err(Error::with_context(
                CurlCode::UploadFailed,
                "Cannot APPEND with unknown input file size",
            ));
        }
        let mailbox = imap_atom(&mb, false);
        let flags = self.build_append_flags();
        // "APPEND %s%s {%FMT_OFF_T}" → "APPEND <mailbox><flags> {<size>}".
        self.sendf(
            pp,
            &format!("APPEND {mailbox}{flags} {{{}}}", self.infilesize),
        )?;
        self.set_state(ImapState::Append);
        Ok(())
    }

    /// Send a `SEARCH` command (← `imap_perform_search`).
    fn perform_search(&mut self, pp: &mut PingPong) -> Result<()> {
        let Some(query) = self.imap.query.clone() else {
            return Err(Error::url("Cannot SEARCH without a query string."));
        };
        self.sendf(pp, &format!("SEARCH {query}"))?;
        self.set_state(ImapState::Search);
        Ok(())
    }

    /// Send `LOGOUT` prior to closing the connection (← `imap_perform_logout`).
    fn perform_logout(&mut self, pp: &mut PingPong) -> Result<()> {
        self.sendf(pp, "LOGOUT")?;
        self.set_state(ImapState::Logout);
        Ok(())
    }
}

// ===========================================================================
// SASL glue (← the `saslimap` vtable + its four callback functions).
//
// The shared [`Sasl`] engine drives IMAP through this trait. Because the engine
// borrows `(pp, proto)` as *distinct* mutable references (`pp.statemach(proto,
// …)`) and `proto` here is the same `ImapConn`, these hooks must not touch the
// ping-pong engine directly. Instead each "send" hook records the exact,
// already-formatted command line into [`sasl_out`](ImapConn::sasl_out); the
// caller ([`perform_authentication`](ImapConn::perform_authentication) /
// [`state_auth_resp`](ImapConn::state_auth_resp)) drains that queue to the
// engine via [`flush_sasl_out`](ImapConn::flush_sasl_out) immediately after the
// SASL step returns. The bytes placed on the wire — and their ordering relative
// to the response read — are byte-identical to curl; only the mechanical point
// of the `send` call is deferred by one synchronous step. `get_message` reads
// the response snapshot captured in [`last_response`](ImapConn::last_response)
// before the SASL step was invoked.
// ===========================================================================

// ===========================================================================
// Response handlers (← the `imap_state_*_resp` functions).
//
// Each is invoked by [`run_statemachine`](ImapConn::run_statemachine) once a
// full server response has been read; `imapcode` is the classification produced
// by [`endofresp`](PingPongProtocol::endofresp). Handlers that need the raw
// response line read it from [`last_response`](ImapConn::last_response), the
// snapshot captured just before dispatch.
// ===========================================================================

impl ImapConn {
    /// Handle the server greeting (← `imap_state_servergreet_resp`).
    ///
    /// A `PREAUTH` greeting flags the session as already authenticated; any
    /// non-`OK` greeting is a fatal [`CurlCode::WeirdServerReply`]. Either way
    /// the connect phase continues by requesting `CAPABILITY`.
    fn state_servergreet_resp(&mut self, pp: &mut PingPong, imapcode: i32) -> Result<()> {
        if imapcode == IMAP_RESP_PREAUTH {
            self.preauth = true;
            tracing::info!(target: "curl::imap", "PREAUTH connection, already authenticated");
        } else if imapcode != IMAP_RESP_OK {
            return Err(Error::with_context(
                CurlCode::WeirdServerReply,
                "Got unexpected imap-server response",
            ));
        }
        self.perform_capability(pp)
    }

    /// Parse the words of an untagged `* CAPABILITY …` line, updating the
    /// capability flags (← the untagged branch of `imap_state_capability_resp`).
    fn parse_capabilities(&mut self, line: &[u8]) {
        // Skip the "* " untagged marker.
        let bytes = if line.len() >= 2 { &line[2..] } else { line };
        let n = bytes.len();
        let mut i = 0;
        loop {
            // Skip inter-word whitespace (ISBLANK | ISNEWLINE).
            while i < n && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
                i += 1;
            }
            if i >= n {
                break;
            }
            let start = i;
            while i < n && !matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
                i += 1;
            }
            let word = &bytes[start..i];

            if word.eq_ignore_ascii_case(b"STARTTLS") {
                // Server supports the STARTTLS capability.
                self.tls_supported = true;
            } else if word.eq_ignore_ascii_case(b"LOGINDISABLED") {
                // Server explicitly disabled clear-text authentication.
                self.login_disabled = true;
            } else if word.eq_ignore_ascii_case(b"SASL-IR") {
                // Server supports the SASL-IR (initial response) capability.
                self.ir_supported = true;
            } else if word.len() > 5 && word[..5].eq_ignore_ascii_case(b"AUTH=") {
                // A SASL-based authentication mechanism, e.g. "AUTH=PLAIN".
                let mech = &word[5..];
                if let Ok(mech_str) = std::str::from_utf8(mech) {
                    if let Some((mechbit, llen)) = decode_mech(mech_str) {
                        if llen == mech.len() {
                            if let Some(sasl) = self.sasl.as_mut() {
                                sasl.add_authmech(mechbit);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Handle a `CAPABILITY` response (← `imap_state_capability_resp`).
    ///
    /// Untagged lines feed [`parse_capabilities`](Self::parse_capabilities). On
    /// the tagged completion the STARTTLS-vs-clear decision is made: upgrade when
    /// TLS is wanted, supported and not `PREAUTH`; fall through to authentication
    /// when TLS is only *tried*; otherwise fail with
    /// [`CurlCode::UseSslFailed`].
    fn state_capability_resp(
        &mut self,
        pp: &mut PingPong,
        conn: &mut Connection,
        imapcode: i32,
    ) -> Result<()> {
        if imapcode == IMAP_RESP_UNTAGGED {
            let line = self.last_response.clone();
            self.parse_capabilities(&line);
            return Ok(());
        }

        if self.use_ssl != CURLUSESSL_NONE && !conn.is_ssl(FIRSTSOCKET) {
            // PREAUTH is not compatible with STARTTLS.
            if imapcode == IMAP_RESP_OK && self.tls_supported && !self.preauth {
                // Switch to a TLS connection now.
                self.perform_starttls(pp)
            } else if self.use_ssl <= CURLUSESSL_TRY {
                self.perform_authentication(pp, conn)
            } else {
                Err(Error::with_context(
                    CurlCode::UseSslFailed,
                    "STARTTLS not available.",
                ))
            }
        } else {
            self.perform_authentication(pp, conn)
        }
    }

    /// Handle a `STARTTLS` response (← `imap_state_starttls_resp`).
    ///
    /// Pipelined data after the response is forbidden (curl's `pp->overflow`
    /// check, mirrored here with [`PingPong::moredata`]). On acceptance the state
    /// advances to [`ImapState::UpgradeTls`]; on refusal it either fails (when
    /// TLS is required) or falls through to authentication (when only tried).
    fn state_starttls_resp(
        &mut self,
        pp: &mut PingPong,
        conn: &mut Connection,
        imapcode: i32,
    ) -> Result<()> {
        // Pipelining in response is forbidden.
        if pp.moredata() {
            return Err(Error::with_context(
                CurlCode::WeirdServerReply,
                "STARTTLS response contained pipelined data",
            ));
        }

        if imapcode != IMAP_RESP_OK {
            if self.use_ssl != CURLUSESSL_TRY {
                Err(Error::with_context(
                    CurlCode::UseSslFailed,
                    "STARTTLS denied",
                ))
            } else {
                self.perform_authentication(pp, conn)
            }
        } else {
            self.set_state(ImapState::UpgradeTls);
            Ok(())
        }
    }

    /// Handle a SASL authentication response (← `imap_state_auth_resp`).
    ///
    /// Drives one step of the shared [`Sasl`] engine, then flushes any command it
    /// queued. On `Done` the connect phase ends; on `Idle` (no mechanism left
    /// after a cancellation) it falls back to clear-text `LOGIN` when permitted,
    /// else fails with [`CurlCode::LoginDenied`].
    fn state_auth_resp(
        &mut self,
        pp: &mut PingPong,
        conn: &mut Connection,
        imapcode: i32,
    ) -> Result<()> {
        let creds = self.make_creds(conn);
        let mut sasl = self.sasl.take().expect("sasl present");
        let progress = sasl.sasl_continue(self, &creds, imapcode);
        self.sasl = Some(sasl);
        let progress = progress?;
        self.flush_sasl_out(pp)?;

        match progress {
            SaslProgress::Done => {
                // Authenticated.
                self.set_state(ImapState::Stop);
                Ok(())
            }
            SaslProgress::Idle => {
                // No mechanism left after cancellation.
                if !self.login_disabled && (self.preftype & IMAP_TYPE_CLEARTEXT) != 0 {
                    self.perform_login(pp, conn)
                } else {
                    Err(Error::with_context(
                        CurlCode::LoginDenied,
                        "Authentication cancelled",
                    ))
                }
            }
            SaslProgress::InProgress => Ok(()),
        }
    }

    /// Handle a clear-text `LOGIN` response (← `imap_state_login_resp`).
    ///
    /// Any non-`OK` completion denies access with [`CurlCode::LoginDenied`];
    /// otherwise the connect phase ends.
    fn state_login_resp(&mut self, imapcode: i32) -> Result<()> {
        if imapcode != IMAP_RESP_OK {
            Err(Error::with_context(CurlCode::LoginDenied, "Access denied"))
        } else {
            // End of connect phase.
            self.set_state(ImapState::Stop);
            Ok(())
        }
    }
}

impl SaslProto for ImapConn {
    /// The SASL service name (← `"imap"`).
    fn service(&self) -> &str {
        "imap"
    }

    /// No maximum initial-response length (← `0`); the server's `SASL-IR`
    /// capability governs whether the IR is sent, applied by the caller.
    fn max_ir_len(&self) -> usize {
        0
    }

    /// Status code that signals "continuation expected" (← `'+'`).
    fn cont_code(&self) -> i32 {
        IMAP_RESP_CONTINUE
    }

    /// Status code that signals authentication success (← `IMAP_RESP_OK`).
    fn final_code(&self) -> i32 {
        IMAP_RESP_OK
    }

    /// Default mechanism set (← `SASL_AUTH_DEFAULT`).
    fn def_mechs(&self) -> u32 {
        SASL_AUTH_DEFAULT
    }

    /// Configuration flags — IMAP always base64-encodes SASL messages
    /// (← `SASL_FLAG_BASE64`).
    fn flags(&self) -> u16 {
        SASL_FLAG_BASE64
    }

    /// Queue the initial `AUTHENTICATE <mech> [<ir>]` command
    /// (← `imap_perform_authenticate`).
    ///
    /// This uses [`imap_sendf`](ImapConn::sendf) semantics — a fresh tag is
    /// computed and stored in [`resptag`](ImapConn::resptag) so the tagged
    /// completion is recognised by [`endofresp`](PingPongProtocol::endofresp).
    /// The formatted line is buffered (see the impl-level docs).
    fn send_auth(&mut self, mech: &str, ir: Option<&[u8]>) -> Result<()> {
        // Reproduce imap_sendf's tag computation (++cmdid, "%c%03d").
        self.cmdid = self.cmdid.wrapping_add(1);
        self.resptag = calc_tag(self.connection_id, self.cmdid);
        let command = match ir {
            Some(ir) => {
                let ir = String::from_utf8_lossy(ir);
                format!("{} AUTHENTICATE {mech} {ir}", self.resptag)
            }
            None => format!("{} AUTHENTICATE {mech}", self.resptag),
        };
        self.sasl_out.push(command);
        Ok(())
    }

    /// Queue a bare continuation response (← `imap_continue_authenticate`,
    /// which sends `"%s"` with no tag).
    fn cont_auth(&mut self, _mech: &str, resp: &[u8]) -> Result<()> {
        self.sasl_out
            .push(String::from_utf8_lossy(resp).into_owned());
        Ok(())
    }

    /// Queue the cancellation token `*` (← `imap_cancel_authenticate`).
    fn cancel_auth(&mut self, _mech: &str) -> Result<()> {
        self.sasl_out.push(String::from('*'));
        Ok(())
    }

    /// Extract the SASL message from the latest response (← `imap_get_message`).
    ///
    /// The continuation marker (`+`/`+ `) and the surrounding whitespace are
    /// stripped: the first two bytes are dropped, then leading blanks and
    /// trailing newline/blank bytes are trimmed. A response of two bytes or
    /// fewer yields an empty message, exactly as curl's `else` branch does.
    fn get_message(&mut self) -> Result<Vec<u8>> {
        let full = &self.last_response;
        if full.len() > 2 {
            // Drop the 2-byte continuation marker, then trim.
            let mut s = &full[2..];
            // Skip leading blanks (SP/HT) — ISBLANK.
            while let [first, rest @ ..] = s {
                if *first == b' ' || *first == b'\t' {
                    s = rest;
                } else {
                    break;
                }
            }
            // Trim trailing newline (CR/LF) or blank (SP/HT).
            while let [rest @ .., last] = s {
                if matches!(*last, b'\r' | b'\n' | b' ' | b'\t') {
                    s = rest;
                } else {
                    break;
                }
            }
            Ok(s.to_vec())
        } else {
            // Junk input => zero-length output.
            Ok(Vec::new())
        }
    }
}

// ===========================================================================
// DO-phase response handlers (← the remaining `imap_state_*_resp` functions).
//
// Literal-body reinjection in curl mutates the private ping-pong receive buffer
// (`pp->recvbuf`/`pp->nfinal`/`pp->overflow`); that buffer is owned by the
// engine here, so the body drain is deferred to the transfer layer. These
// handlers therefore capture the download intent — the header bytes written to
// [`client_body`](ImapConn::client_body), the total [`download_size`], and the
// [`xfer`](ImapConn::xfer) setup — exactly as curl computes it, and the transfer
// layer performs the actual buffered-body flush and socket receive setup.
// ===========================================================================

impl ImapConn {
    /// Handle a `LIST`/`LSUB`/`SEARCH` (or custom) response
    /// (← `imap_state_listsearch_resp`).
    ///
    /// Untagged lines are written to the client body. A line carrying a
    /// `{size}` literal additionally records the download intent (the total
    /// spans the header line plus the literal body) and ends the DO phase. A
    /// custom `FETCH`/`UID FETCH` used purely for listing is passed through
    /// untouched. A tagged non-`OK` completion is a [`CurlCode::QuoteError`].
    fn state_listsearch_resp(&mut self, imapcode: i32) -> Result<()> {
        let line = self.last_response.clone();
        let len = line.len();

        if imapcode == IMAP_RESP_UNTAGGED && is_custom_fetch_listing(&self.imap) {
            // Custom FETCH or UID FETCH for listing is not handled here.
        } else if imapcode == IMAP_RESP_UNTAGGED {
            // A literal is written as `{size}` and only meaningful up to the CR.
            let line_len = line.iter().position(|&b| b == b'\r').unwrap_or(len);
            let literal = imap_find_literal(&line[..line_len])
                .and_then(|pos| parse_literal_size(&line[pos + 1..line_len]));

            match literal {
                Some(size) => {
                    // First write the header line as body content.
                    self.client_body.extend_from_slice(&line);
                    // Buffered literal-body drain is deferred to the transfer layer.
                    // Progress size includes both the header line and literal body.
                    let total = size.saturating_add(i64::try_from(len).unwrap_or(i64::MAX));
                    self.download_size = Some(total);
                    self.xfer = if self.bytecount == total {
                        XferSetup::Nop
                    } else {
                        XferSetup::Recv(total)
                    };
                    self.set_state(ImapState::Stop);
                }
                None => {
                    // No literal (or unparsable): just write the line as-is.
                    self.client_body.extend_from_slice(&line);
                }
            }
        } else if imapcode != IMAP_RESP_OK {
            return Err(Error::with_context(
                CurlCode::QuoteError,
                "IMAP command failed",
            ));
        } else {
            // End of DO phase.
            self.set_state(ImapState::Stop);
        }
        Ok(())
    }

    /// Handle a `SELECT`/`EXAMINE` response (← `imap_state_select_resp`).
    ///
    /// Untagged `OK [UIDVALIDITY n]` responses capture the mailbox's
    /// `UIDVALIDITY`. On the tagged `OK`, a mismatched requested `UIDVALIDITY`
    /// aborts with [`CurlCode::RemoteFileNotFound`]; otherwise the opened mailbox
    /// is recorded and the requested action (`LIST`/`SEARCH`/`FETCH`) is issued.
    /// A tagged non-`OK` is a [`CurlCode::LoginDenied`] "Select failed".
    fn state_select_resp(&mut self, pp: &mut PingPong, imapcode: i32) -> Result<()> {
        if imapcode == IMAP_RESP_UNTAGGED {
            let line = self.last_response.clone();
            // See if this is a UIDVALIDITY response: "* OK [UIDVALIDITY <n>...".
            const PREFIX: &[u8] = b"OK [UIDVALIDITY ";
            if line.len() >= 18 && line.len() >= 2 + PREFIX.len() {
                let after_marker = &line[2..];
                if after_marker.len() >= PREFIX.len()
                    && after_marker[..PREFIX.len()].eq_ignore_ascii_case(PREFIX)
                {
                    if let Some(value) = parse_u32_prefix(&after_marker[PREFIX.len()..]) {
                        self.mb_uidvalidity = value;
                        self.mb_uidvalidity_set = true;
                    }
                }
            }
            return Ok(());
        }

        if imapcode == IMAP_RESP_OK {
            // Check if the requested UIDVALIDITY has been specified and matches.
            if self.imap.uidvalidity_set
                && self.mb_uidvalidity_set
                && self.imap.uidvalidity != self.mb_uidvalidity
            {
                return Err(Error::with_context(
                    CurlCode::RemoteFileNotFound,
                    "Mailbox UIDVALIDITY has changed",
                ));
            }
            // Note the currently opened mailbox on this connection.
            self.mailbox = self.imap.mailbox.clone();

            if self.imap.custom.is_some() {
                self.perform_list(pp)
            } else if self.imap.query.is_some() {
                self.perform_search(pp)
            } else {
                self.perform_fetch(pp)
            }
        } else {
            Err(Error::with_context(CurlCode::LoginDenied, "Select failed"))
        }
    }

    /// Handle the first line of a `FETCH` response (← `imap_state_fetch_resp`).
    ///
    /// A non-untagged response means the message was not found
    /// ([`CurlCode::RemoteFileNotFound`]). Otherwise the `{size}` literal is
    /// parsed to establish the download size; an unparsable line is a
    /// [`CurlCode::WeirdServerReply`]. The DO phase always ends here — the body
    /// itself is streamed by the transfer layer.
    fn state_fetch_resp(&mut self, imapcode: i32) -> Result<()> {
        if imapcode != IMAP_RESP_UNTAGGED {
            self.download_size = Some(-1);
            self.set_state(ImapState::Stop);
            return Err(Error::with_context(
                CurlCode::RemoteFileNotFound,
                "no such message",
            ));
        }

        let line = self.last_response.clone();
        // Parse the continuation size within the curly brackets, e.g.
        // "* 1 FETCH (BODY[TEXT] {2021}\r".
        let parsed = imap_find_literal(&line).and_then(|pos| parse_literal_size(&line[pos + 1..]));

        let result = match parsed {
            Some(size) => {
                // Buffered overflow-body drain is deferred to the transfer layer.
                self.download_size = Some(size);
                self.xfer = if self.bytecount == size {
                    // The entire data has already been transferred.
                    XferSetup::Nop
                } else {
                    // IMAP download of the remaining literal body.
                    XferSetup::Recv(size)
                };
                Ok(())
            }
            None => {
                // We do not know how to parse this line.
                Err(Error::with_context(
                    CurlCode::WeirdServerReply,
                    "Failed to parse FETCH response.",
                ))
            }
        };

        // End of DO phase.
        self.set_state(ImapState::Stop);
        result
    }

    /// Handle the final `FETCH` response after the download
    /// (← `imap_state_fetch_final_resp`).
    fn state_fetch_final_resp(&mut self, imapcode: i32) -> Result<()> {
        if imapcode != IMAP_RESP_OK {
            Err(Error::with_context(
                CurlCode::WeirdServerReply,
                "unexpected FETCH completion",
            ))
        } else {
            // End of DONE phase.
            self.set_state(ImapState::Stop);
            Ok(())
        }
    }

    /// Handle an `APPEND` response (← `imap_state_append_resp`).
    ///
    /// The server must return a continuation (`+`) to accept the upload; any
    /// other code is a [`CurlCode::UploadFailed`]. On acceptance the upload size
    /// is recorded and the send transfer is armed for the transfer layer.
    fn state_append_resp(&mut self, imapcode: i32) -> Result<()> {
        if imapcode != IMAP_RESP_CONTINUE {
            Err(Error::with_context(
                CurlCode::UploadFailed,
                "APPEND not accepted",
            ))
        } else {
            // Set the progress upload size and arm the IMAP upload.
            self.upload_size = Some(self.infilesize);
            self.xfer = XferSetup::Send;
            // End of DO phase.
            self.set_state(ImapState::Stop);
            Ok(())
        }
    }

    /// Handle the final `APPEND` response after the upload
    /// (← `imap_state_append_final_resp`).
    fn state_append_final_resp(&mut self, imapcode: i32) -> Result<()> {
        if imapcode != IMAP_RESP_OK {
            Err(Error::with_context(
                CurlCode::UploadFailed,
                "APPEND upload failed",
            ))
        } else {
            // End of DONE phase.
            self.set_state(ImapState::Stop);
            Ok(())
        }
    }
}

/// Decide whether an untagged `* …` line seen in [`ImapState::List`] belongs to
/// us (← the `case IMAP_LIST` accept/reject expression in `imap_endofresp`).
///
/// With no custom request only `LIST` responses are ours. With a custom request
/// the response matches the custom command, `STORE`'s `FETCH` echo, or one of
/// the recognised passthrough commands (`SELECT`, `EXAMINE`, `SEARCH`,
/// `EXPUNGE`, `LSUB`, `UID`, `GETQUOTAROOT`, `NOOP`). This is the exact logical
/// negation of curl's `return FALSE` condition.
fn list_untagged_is_ours(line: &[u8], custom: Option<&str>) -> bool {
    match custom {
        None => imap_matchresp(line, b"LIST"),
        Some(c) => {
            imap_matchresp(line, c.as_bytes())
                || (c.eq_ignore_ascii_case("STORE") && imap_matchresp(line, b"FETCH"))
                || c.eq_ignore_ascii_case("SELECT")
                || c.eq_ignore_ascii_case("EXAMINE")
                || c.eq_ignore_ascii_case("SEARCH")
                || c.eq_ignore_ascii_case("EXPUNGE")
                || c.eq_ignore_ascii_case("LSUB")
                || c.eq_ignore_ascii_case("UID")
                || c.eq_ignore_ascii_case("GETQUOTAROOT")
                || c.eq_ignore_ascii_case("NOOP")
        }
    }
}

// ===========================================================================
// Ping-pong protocol integration (← the `endofresp`/`statemachine` vtable
// entries wired by `PINGPONG_SETUP(pp, imap_pp_statemachine, imap_endofresp)`).
// ===========================================================================

impl PingPongProtocol for ImapConn {
    /// Drive the IMAP state machine one step (← `imap_pp_statemachine`).
    ///
    /// Delegated to the inherent [`run_statemachine`](ImapConn::run_statemachine)
    /// async method; boxed to satisfy the object-safe, `Send` future contract of
    /// the trait.
    fn statemachine<'a>(
        &'a mut self,
        pp: &'a mut PingPong,
        conn: &'a mut Connection,
    ) -> ProtoFuture<'a, ()> {
        Box::pin(self.run_statemachine(pp, conn))
    }

    /// Classify a response line as tagged / untagged / continuation
    /// (← `imap_endofresp`).
    ///
    /// * A **tagged** line begins with the current [`resptag`](ImapConn::resptag)
    ///   followed by a space; the word after it maps to [`IMAP_RESP_OK`],
    ///   [`IMAP_RESP_PREAUTH`], or [`IMAP_RESP_NOT_OK`].
    /// * An **untagged** `"* "` line is accepted only in the states that expect
    ///   one (and, for most, only when the command keyword matches), yielding
    ///   [`IMAP_RESP_UNTAGGED`].
    /// * A **continuation** `"+"`/`"+ "` line is accepted only in
    ///   [`ImapState::Authenticate`]/[`ImapState::Append`] (and only without a
    ///   custom request), yielding [`IMAP_RESP_CONTINUE`]; an unexpected
    ///   continuation yields [`IMAP_RESP_BAD`].
    ///
    /// Returns `true` when the line completes a response (i.e. `code` was set).
    fn endofresp(&mut self, line: &[u8], code: &mut i32) -> bool {
        let id = self.resptag.as_bytes();
        let id_len = id.len();

        // Tagged command response?
        if line.len() > id_len && &line[..id_len] == id && line[id_len] == b' ' {
            let rest = &line[id_len + 1..];
            *code = if rest.len() >= 2 && &rest[..2] == b"OK" {
                IMAP_RESP_OK
            } else if rest.len() >= 7 && &rest[..7] == b"PREAUTH" {
                IMAP_RESP_PREAUTH
            } else {
                IMAP_RESP_NOT_OK
            };
            return true;
        }

        // Untagged command response?
        if line.len() >= 2 && &line[..2] == b"* " {
            let accept = match self.state {
                ImapState::Capability => imap_matchresp(line, b"CAPABILITY"),
                ImapState::List => list_untagged_is_ours(line, self.imap.custom.as_deref()),
                // SELECT untagged responses have no common prefix: accept anything.
                ImapState::Select => true,
                ImapState::Fetch => imap_matchresp(line, b"FETCH"),
                ImapState::Search => imap_matchresp(line, b"SEARCH"),
                // Ignore other untagged responses.
                _ => false,
            };
            if !accept {
                return false;
            }
            *code = IMAP_RESP_UNTAGGED;
            return true;
        }

        // Continuation response? A `+` (optionally `+ <text>`) for AUTHENTICATE
        // and APPEND, per RFC-3501 §4 and RFC-4959. Some servers send a bare `+`.
        if self.imap.custom.is_none()
            && ((line.len() == 3 && line[0] == b'+') || (line.len() >= 2 && &line[..2] == b"+ "))
        {
            match self.state {
                ImapState::Authenticate | ImapState::Append => {
                    *code = IMAP_RESP_CONTINUE;
                }
                _ => {
                    // Unexpected continuation response.
                    *code = IMAP_RESP_BAD;
                }
            }
            return true;
        }

        false // Nothing for us.
    }
}

// ===========================================================================
// State-machine driver and DO-phase dispatch (← `imap_pp_statemachine` body
// and `imap_perform`).
// ===========================================================================

impl ImapConn {
    /// Read and dispatch server responses until the machine stops or blocks
    /// (← the body of `imap_pp_statemachine`).
    ///
    /// The outer loop reproduces curl's `goto upgrade_tls`: while the state is
    /// [`ImapState::UpgradeTls`] the TLS handshake is driven to completion before
    /// any IMAP I/O; a queued command is flushed before reading; then a full
    /// response is read, its line snapshotted into
    /// [`last_response`](Self::last_response), and dispatched to the matching
    /// `state_*_resp` handler. The read loop continues while the machine has not
    /// stopped and more buffered data remains ([`PingPong::moredata`]).
    async fn run_statemachine(&mut self, pp: &mut PingPong, conn: &mut Connection) -> Result<()> {
        let mut code: i32 = 0;
        let mut nread: usize = 0;

        // Outer loop emulates the `upgrade_tls:` label + `goto`.
        loop {
            // Busy upgrading the connection: all I/O is TLS, not IMAP.
            if self.state == ImapState::UpgradeTls {
                self.perform_upgrade_tls(pp, conn).await?;
                if self.state == ImapState::UpgradeTls {
                    // Still handshaking; re-enter later once the socket is ready.
                    return Ok(());
                }
            }

            // Flush any data that needs to be sent.
            if pp.needs_flush() {
                return pp.flushsend(conn, Instant::now()).await;
            }

            let mut goto_upgrade = false;
            loop {
                // Read the response from the server.
                pp.readresp(self, conn, FIRSTSOCKET, &mut code, &mut nread)
                    .await?;

                // Was there an error parsing the response line?
                if code == IMAP_RESP_BAD {
                    return Err(Error::with_context(
                        CurlCode::WeirdServerReply,
                        "Unexpected continuation response",
                    ));
                }

                // No complete response yet.
                if code == 0 {
                    break;
                }

                // Snapshot the completed response line for the handlers and the
                // SASL `get_message` hook.
                self.last_response = pp.response_line().to_vec();

                // We have now received a full IMAP server response.
                match self.state {
                    ImapState::ServerGreet => self.state_servergreet_resp(pp, code)?,
                    ImapState::Capability => self.state_capability_resp(pp, conn, code)?,
                    ImapState::StartTls => {
                        self.state_starttls_resp(pp, conn, code)?;
                        // During UPGRADETLS, leave the read loop as we need to
                        // connect (TLS handshake) before continuing.
                        if self.state == ImapState::UpgradeTls {
                            goto_upgrade = true;
                        }
                    }
                    ImapState::Authenticate => self.state_auth_resp(pp, conn, code)?,
                    ImapState::Login => self.state_login_resp(code)?,
                    ImapState::List | ImapState::Search => self.state_listsearch_resp(code)?,
                    ImapState::Select => self.state_select_resp(pp, code)?,
                    ImapState::Fetch => self.state_fetch_resp(code)?,
                    ImapState::FetchFinal => self.state_fetch_final_resp(code)?,
                    ImapState::Append => self.state_append_resp(code)?,
                    ImapState::AppendFinal => self.state_append_final_resp(code)?,
                    // IMAP_LOGOUT and any other state: internal — just stop.
                    _ => self.set_state(ImapState::Stop),
                }

                if goto_upgrade {
                    break;
                }

                // do { … } while(!result && state != STOP && moredata).
                if self.state == ImapState::Stop || !pp.moredata() {
                    break;
                }
            }

            if goto_upgrade {
                // `goto upgrade_tls;`
                continue;
            }
            return Ok(());
        }
    }

    /// Issue the first command of the DO phase (← `imap_perform`).
    ///
    /// Chooses `APPEND` (upload/MIME), a custom `LIST`, `FETCH`, `SEARCH`,
    /// `SELECT`, or a plain `LIST` based on the URL/options and whether the
    /// requested mailbox is already selected on this connection. `no_body`
    /// downgrades the transfer to header-only ([`PpTransfer::Info`]).
    fn do_perform(&mut self, pp: &mut PingPong) -> Result<()> {
        // Requested no body means no transfer.
        if self.no_body {
            self.imap.transfer = PpTransfer::Info;
        }

        // Determine if the requested mailbox (with the same UIDVALIDITY if set)
        // has already been selected on this connection.
        let selected = match (self.imap.mailbox.as_deref(), self.mailbox.as_deref()) {
            (Some(want), Some(have)) => {
                want.eq_ignore_ascii_case(have)
                    && (!self.imap.uidvalidity_set
                        || !self.mb_uidvalidity_set
                        || self.imap.uidvalidity == self.mb_uidvalidity)
            }
            _ => false,
        };

        let has_mailbox = self.imap.mailbox.is_some();
        let has_custom = self.imap.custom.is_some();
        let has_uid = self.imap.uid.is_some();
        let has_mindex = self.imap.mindex.is_some();
        let has_query = self.imap.query.is_some();

        // Start the first command in the DO phase.
        if self.upload || self.mime_post {
            // APPEND can be executed directly.
            self.perform_append(pp)
        } else if has_custom && (selected || !has_mailbox) {
            // Custom command using the same mailbox or no mailbox.
            self.perform_list(pp)
        } else if !has_custom && selected && (has_uid || has_mindex) {
            // FETCH from the same mailbox.
            self.perform_fetch(pp)
        } else if !has_custom && selected && has_query {
            // SEARCH the current mailbox.
            self.perform_search(pp)
        } else if has_mailbox && !selected && (has_custom || has_uid || has_mindex || has_query) {
            // SELECT the mailbox.
            self.perform_select(pp)
        } else {
            // LIST.
            self.perform_list(pp)
        }
    }
}

// ===========================================================================
// URL and option parsing (← `imap_parse_url_options`, `imap_parse_url_path`,
// `imap_parse_custom_request`).
// ===========================================================================

impl ImapConn {
    /// Parse the login `;options` string (← `imap_parse_url_options`).
    ///
    /// Recognises `;AUTH=<mech>` (seeding the SASL preferred-mechanism set) and
    /// the special `;AUTH=+LOGIN` (prefer clear-text `LOGIN` over any SASL). The
    /// resulting [`preftype`](Self::preftype) is derived exactly as curl does
    /// from the `prefer_login` flag and the engine's preferred-mechanism set.
    /// Any other option is a [`CurlCode::UrlMalformat`].
    ///
    /// curl encodes `+LOGIN` by zeroing `sasl.prefmech`; the shared engine has no
    /// `prefmech` setter, so the engine is re-seeded via
    /// [`Sasl::init`](crate::auth::sasl::Sasl::init) with an empty default set,
    /// which yields the same empty `prefmech` (and, at connect time, the same
    /// empty advertised set) — reproducing the identical mechanism-selection
    /// outcome on the wire.
    fn parse_url_options(&mut self, conn: &Connection) -> Result<()> {
        let options = conn.options.clone().unwrap_or_default();
        let raw = options.as_bytes();
        let mut ptr = 0;
        let mut prefer_login = false;

        while ptr < raw.len() {
            let key_start = ptr;
            // Find the '=' (skipping ';' too, exactly as curl's first loop does).
            while ptr < raw.len() && raw[ptr] != b'=' {
                ptr += 1;
            }
            let value_start = if ptr < raw.len() { ptr + 1 } else { ptr };
            // Find the end of this option at ';'.
            while ptr < raw.len() && raw[ptr] != b';' {
                ptr += 1;
            }
            let key = &raw[key_start..ptr];
            let value = &raw[value_start.min(ptr)..ptr];

            if key.len() >= 11 && key[..11].eq_ignore_ascii_case(b"AUTH=+LOGIN") {
                // Prefer plaintext LOGIN over any SASL, including SASL LOGIN.
                prefer_login = true;
                self.sasl = Some(Sasl::init(SASL_AUTH_NONE, self.httpauth));
            } else if key.len() >= 5 && key[..5].eq_ignore_ascii_case(b"AUTH=") {
                prefer_login = false;
                let value_str = std::str::from_utf8(value).map_err(|_| {
                    Error::with_context(CurlCode::UrlMalformat, "invalid IMAP AUTH option")
                })?;
                if let Some(sasl) = self.sasl.as_mut() {
                    sasl.set_url_auth_option(value_str)?;
                }
            } else {
                return Err(Error::with_context(
                    CurlCode::UrlMalformat,
                    "invalid IMAP URL option",
                ));
            }

            if ptr < raw.len() && raw[ptr] == b';' {
                ptr += 1;
            }
        }

        if prefer_login {
            self.preftype = IMAP_TYPE_CLEARTEXT;
        } else {
            let prefmech = self.sasl.as_ref().map_or(SASL_AUTH_NONE, Sasl::prefmech);
            self.preftype = if prefmech == SASL_AUTH_NONE {
                IMAP_TYPE_NONE
            } else if prefmech == SASL_AUTH_DEFAULT {
                IMAP_TYPE_ANY
            } else {
                IMAP_TYPE_SASL
            };
        }
        Ok(())
    }

    /// Parse the URL path into the mailbox and hierarchical parameters
    /// (← `imap_parse_url_path`).
    ///
    /// `path` is the URL path (with its leading `/`); `query` is the already
    /// URL-decoded query component, present only when the URL carries one. The
    /// mailbox is the leading run of `bchar`s (trailing `/` removed), followed by
    /// any number of `;NAME=VALUE` parameters (`UIDVALIDITY`, `UID`, `MAILINDEX`,
    /// `SECTION`, `PARTIAL`). A `SEARCH` query is accepted only with a mailbox
    /// and no `UID`/`MAILINDEX` (RFC-5092). Unknown parameters or trailing junk
    /// are a [`CurlCode::UrlMalformat`].
    fn parse_url_path(&mut self, path: &str, query: Option<&str>) -> Result<()> {
        let raw = path.as_bytes();
        // Skip the leading slash (`&data->state.up.path[1]`).
        let mut ptr = usize::from(!raw.is_empty());
        let begin = ptr;

        // How much of the URL is a valid path.
        while ptr < raw.len() && imap_is_bchar(raw[ptr]) {
            ptr += 1;
        }

        if ptr != begin {
            // Remove the trailing slash if present.
            let mut end = ptr;
            if end > begin && raw[end - 1] == b'/' {
                end -= 1;
            }
            let decoded = urldecode_reject_ctrl(&raw[begin..end], "mailbox")?;
            self.imap.mailbox = Some(String::from_utf8_lossy(&decoded).into_owned());
        } else {
            self.imap.mailbox = None;
        }

        // Any number of ";NAME=VALUE" parameters.
        while ptr < raw.len() && raw[ptr] == b';' {
            ptr += 1;
            let name_begin = ptr;
            while ptr < raw.len() && raw[ptr] != b'=' {
                ptr += 1;
            }
            if ptr >= raw.len() {
                return Err(Error::with_context(
                    CurlCode::UrlMalformat,
                    "IMAP URL parameter missing '='",
                ));
            }
            let name_bytes = urldecode_reject_ctrl(&raw[name_begin..ptr], "parameter name")?;
            let name = String::from_utf8_lossy(&name_bytes).into_owned();
            ptr += 1; // Skip '='.

            let value_begin = ptr;
            while ptr < raw.len() && imap_is_bchar(raw[ptr]) {
                ptr += 1;
            }
            let decoded = urldecode_reject_ctrl(&raw[value_begin..ptr], "parameter value")?;
            let valuelen = decoded.len();
            // Strip a single trailing '/' (curl truncates in place but keeps the
            // pre-strip length for the "is it blank?" gate below).
            let value_bytes = if valuelen > 0 && decoded[valuelen - 1] == b'/' {
                &decoded[..valuelen - 1]
            } else {
                &decoded[..]
            };
            let value = String::from_utf8_lossy(value_bytes).into_owned();

            if valuelen > 0 {
                if name.eq_ignore_ascii_case("UIDVALIDITY") && !self.imap.uidvalidity_set {
                    if let Some(num) = parse_u32_prefix(value.as_bytes()) {
                        self.imap.uidvalidity = num;
                        self.imap.uidvalidity_set = true;
                    }
                } else if name.eq_ignore_ascii_case("UID") && self.imap.uid.is_none() {
                    self.imap.uid = Some(value);
                } else if name.eq_ignore_ascii_case("MAILINDEX") && self.imap.mindex.is_none() {
                    self.imap.mindex = Some(value);
                } else if name.eq_ignore_ascii_case("SECTION") && self.imap.section.is_none() {
                    self.imap.section = Some(value);
                } else if name.eq_ignore_ascii_case("PARTIAL") && self.imap.partial.is_none() {
                    self.imap.partial = Some(value);
                } else {
                    return Err(Error::with_context(
                        CurlCode::UrlMalformat,
                        "unknown IMAP URL parameter",
                    ));
                }
            }
        }

        // A query parameter is valid only with a mailbox and no UID (RFC-5092).
        if self.imap.mailbox.is_some() && self.imap.uid.is_none() && self.imap.mindex.is_none() {
            if let Some(q) = query {
                self.imap.query = Some(q.to_string());
            }
        }

        // Any extra stuff at the end of the URL is an error.
        if ptr < raw.len() {
            return Err(Error::with_context(
                CurlCode::UrlMalformat,
                "trailing characters in IMAP URL",
            ));
        }
        Ok(())
    }

    /// Parse `CURLOPT_CUSTOMREQUEST` into the custom verb and its parameters
    /// (← `imap_parse_custom_request`).
    ///
    /// The decoded request is split at the first space: the verb becomes
    /// [`custom`](Imap::custom) and the remainder (including the leading space)
    /// becomes [`custom_params`](Imap::custom_params).
    fn parse_custom_request(&mut self, custom: Option<&str>) -> Result<()> {
        if let Some(custom) = custom {
            let decoded = urldecode_reject_ctrl(custom.as_bytes(), "custom request")?;
            let decoded = String::from_utf8_lossy(&decoded).into_owned();
            if let Some(sp) = decoded.find(' ') {
                self.imap.custom = Some(decoded[..sp].to_string());
                self.imap.custom_params = Some(decoded[sp..].to_string());
            } else {
                self.imap.custom = Some(decoded);
                self.imap.custom_params = None;
            }
        }
        Ok(())
    }
}

// ===========================================================================
// Phase drivers (← `imap_connect`, `imap_do`/`imap_perform`, `imap_doing`,
// `imap_done`, `imap_disconnect`, and the `*_statemach` pumps).
//
// These inherent async methods carry the real per-connection logic. They take
// the owning [`Connection`] plus the timing values the transfer layer supplies
// (`now` and the remaining transfer time, in ms), and honour the borrow model
// described in the module docs: the [`PingPong`] engine is moved out of `self`
// for the duration of each `statemach` pump so the engine can borrow the
// connection and this handler as distinct references. The object-safe
// [`Protocol`] vtable ([`ImapHandler`]) forwards to these once the transfer
// context binds a live connection.
// ===========================================================================

impl ImapConn {
    /// Run one non-blocking step of the ping-pong engine (← one
    /// `Curl_pp_statemach(data, pp, FALSE, FALSE)` call inside
    /// `imap_multi_statemach`).
    async fn statemach_step(
        &mut self,
        conn: &mut Connection,
        block: bool,
        disconnecting: bool,
        now: Instant,
        xfer_timeleft_ms: i64,
    ) -> Result<()> {
        let mut pp = self.pp.take().expect("ping-pong engine present");
        let result = pp
            .statemach(self, conn, block, disconnecting, now, xfer_timeleft_ms)
            .await;
        self.pp = Some(pp);
        result
    }

    /// Pump the engine in blocking mode until the machine stops
    /// (← `imap_block_statemach`). `now` is re-sampled each iteration so the
    /// per-response timeout advances.
    async fn block_statemach(
        &mut self,
        conn: &mut Connection,
        disconnecting: bool,
        xfer_timeleft_ms: i64,
    ) -> Result<()> {
        while self.state != ImapState::Stop {
            self.statemach_step(conn, true, disconnecting, Instant::now(), xfer_timeleft_ms)
                .await?;
        }
        Ok(())
    }

    /// Perform post-DO-phase cleanup (← `imap_dophase_done`): when the transfer
    /// is not a body transfer there is nothing to stream, so the transfer is set
    /// up as a no-op.
    fn dophase_done(&mut self) {
        if self.imap.transfer != PpTransfer::Body {
            self.xfer = XferSetup::Nop;
        }
    }

    /// The protocol connect phase (← `imap_connect`).
    ///
    /// Parses the URL options, arms the greeting state with the `*` response
    /// tag, and runs one non-blocking engine step. Returns `true` once the
    /// connect phase has reached [`ImapState::Stop`] (curl's `*done`); the caller
    /// re-invokes [`run_connecting`](Self::run_connecting) while it is `false`.
    pub async fn run_connect(
        &mut self,
        conn: &mut Connection,
        now: Instant,
        xfer_timeleft_ms: i64,
    ) -> Result<bool> {
        // Parse the URL options.
        self.parse_url_options(conn)?;

        // Start off waiting for the server greeting response, with a `*` tag.
        self.set_state(ImapState::ServerGreet);
        self.resptag = String::from("*");

        self.statemach_step(conn, false, false, now, xfer_timeleft_ms)
            .await?;
        Ok(self.state == ImapState::Stop)
    }

    /// Continue the connect phase (← `imap_multi_statemach` used as
    /// `connecting`). Returns `true` once connected.
    pub async fn run_connecting(
        &mut self,
        conn: &mut Connection,
        now: Instant,
        xfer_timeleft_ms: i64,
    ) -> Result<bool> {
        self.statemach_step(conn, false, false, now, xfer_timeleft_ms)
            .await?;
        Ok(self.state == ImapState::Stop)
    }

    /// The DO phase (← `imap_do` → `imap_regular_transfer` → `imap_perform`).
    ///
    /// Parses the URL path/custom request, issues the first command chosen by
    /// [`do_perform`](Self::do_perform), and pumps one engine step. Returns
    /// `true` once the DO phase completes. `path` is the URL path (with leading
    /// `/`); `query` the decoded query component (if any).
    pub async fn run_do(
        &mut self,
        conn: &mut Connection,
        path: &str,
        query: Option<&str>,
        now: Instant,
        xfer_timeleft_ms: i64,
    ) -> Result<bool> {
        // Parse the URL path and the custom request.
        self.parse_url_path(path, query)?;
        let custom = self.custom_request.clone();
        self.parse_custom_request(custom.as_deref())?;

        // regular_transfer: make sure the size is unknown at this point.
        self.download_size = None;

        // Carry out the perform: issue the first command.
        {
            let mut pp = self.pp.take().expect("ping-pong engine present");
            let perform = self.do_perform(&mut pp);
            self.pp = Some(pp);
            perform?;
        }

        // Run the state machine.
        self.statemach_step(conn, false, false, now, xfer_timeleft_ms)
            .await?;
        let done = self.state == ImapState::Stop;
        if done {
            self.dophase_done();
        }
        Ok(done)
    }

    /// Continue the DO phase (← `imap_doing`). Returns `true` once complete.
    pub async fn run_doing(
        &mut self,
        conn: &mut Connection,
        now: Instant,
        xfer_timeleft_ms: i64,
    ) -> Result<bool> {
        self.statemach_step(conn, false, false, now, xfer_timeleft_ms)
            .await?;
        let done = self.state == ImapState::Stop;
        if done {
            self.dophase_done();
        }
        Ok(done)
    }

    /// The DONE phase run after a single DO completes (← `imap_done`).
    ///
    /// On a failed transfer the connection is marked for closure and the error
    /// is propagated. Otherwise, when a FETCH/APPEND (or a custom command that
    /// set up a download) needs its tagged completion read, the final state
    /// (`FETCH_FINAL`, or `APPEND_FINAL` after an empty terminating line) is
    /// entered and the machine pumped to completion. The per-request state is
    /// then reset.
    pub async fn run_done(
        &mut self,
        conn: &mut Connection,
        status: Result<()>,
        premature: bool,
        xfer_timeleft_ms: i64,
    ) -> Result<()> {
        let _ = premature;

        if let Err(err) = status {
            // Marked for closure; use the already set error code.
            conn.conn_control(ConnControl::Connection);
            self.imap.easy_reset();
            return Err(err);
        }

        let needs_final = !self.connect_only
            && ((self.imap.custom.is_none()
                && (self.imap.uid.is_some() || self.imap.mindex.is_some()))
                || (self.imap.custom.is_some() && self.download_size.is_some_and(|d| d > 0))
                || self.upload
                || self.mime_post);

        if needs_final {
            if !self.upload && !self.mime_post {
                self.set_state(ImapState::FetchFinal);
            } else {
                // End the APPEND command first by sending an empty line.
                let mut pp = self.pp.take().expect("ping-pong engine present");
                let sent = pp.sendf(format_args!(""));
                self.pp = Some(pp);
                sent?;
                self.set_state(ImapState::AppendFinal);
            }

            // Run the state machine (blocking).
            self.block_statemach(conn, false, xfer_timeleft_ms).await?;
        }

        self.imap.easy_reset();
        Ok(())
    }

    /// The disconnect phase (← `imap_disconnect`), which is BLOCKING.
    ///
    /// A graceful `LOGOUT` is attempted only when the connection is not already
    /// dead, the protocol handshake had started, and nothing is still queued to
    /// send; any errors during the ensuing block pump are ignored, exactly as
    /// curl discards them.
    pub async fn run_disconnect(
        &mut self,
        conn: &mut Connection,
        dead_connection: bool,
        xfer_timeleft_ms: i64,
    ) -> Result<()> {
        let needs_flush = self.pp.as_ref().map_or(true, PingPong::needs_flush);
        if !dead_connection && conn.bits.protoconnstart && !needs_flush {
            let logout = {
                let mut pp = self.pp.take().expect("ping-pong engine present");
                let r = self.perform_logout(&mut pp);
                self.pp = Some(pp);
                r
            };
            if logout.is_ok() {
                // Ignore errors, exactly as curl casts the result to void.
                let _ = self.block_statemach(conn, true, xfer_timeleft_ms).await;
            }
        }
        Ok(())
    }

    /// Contribute this connection's socket readiness interest to `ps`
    /// (← `imap_pollset`, which is a thin wrapper over `Curl_pp_pollset`).
    ///
    /// IMAP has no data channel of its own — everything rides the single
    /// ping-pong control connection — so the poll interest is entirely whatever
    /// the [`PingPong`] engine wants on [`FIRSTSOCKET`]: it asks for writability
    /// while a command is still being flushed and readability otherwise. This
    /// simply forwards to [`PingPong::pollset`], exactly as the C hook forwards
    /// to `Curl_pp_pollset(&imapc->pp, ps)`.
    pub fn contribute_pollset(&self, conn: &Connection, ps: &mut Pollset) {
        if let Some(pp) = self.pp.as_ref() {
            pp.pollset(conn, ps);
        }
    }
}

// ===========================================================================
// ImapHandler — the IMAP/IMAPS protocol handler singleton
// (← `Curl_protocol_imap`, `lib/imap.c`).
//
// curl exposes IMAP behavior through one `struct Curl_protocol` instance whose
// function pointers are wired to the `imap_*` entry points. The pointer map is:
//
//     .setup_connection = imap_setup_connection
//     .do_it            = imap_do
//     .done             = imap_done
//     .do_more          = ZERO_NULL
//     .connect_it       = imap_connect
//     .connecting       = imap_multi_statemach
//     .doing            = imap_doing
//     .proto_getsock    = imap_pollset          (proto_pollset)
//     .doing_getsock    = imap_pollset          (doing_pollset)
//     .domore_getsock   = ZERO_NULL
//     .perform_getsock  = ZERO_NULL
//     .disconnect       = imap_disconnect
//     .write_resp       = ZERO_NULL
//     .write_resp_hd    = ZERO_NULL
//     .connection_check = ZERO_NULL
//     .attach           = ZERO_NULL
//
// The concrete, byte-for-byte port of each of those entry points lives in the
// inherent async driver methods on [`ImapConn`] — `run_connect` (← imap_connect),
// `run_connecting` (← imap_multi_statemach), `run_do` (← imap_do), `run_doing`
// (← imap_doing), `run_done` (← imap_done), `run_disconnect` (← imap_disconnect),
// and `contribute_pollset` (← imap_pollset) — because those are where the live
// `(ImapConn, Connection)` pair is manipulated. This handler is the thin vtable
// shim that the scheme registration (`SCHEME_IMAP`/`SCHEME_IMAPS`) points at; it
// mirrors the house pattern established by the DICT handler, overriding only the
// two pointers curl marks mandatory ("These two functions MUST be set"), namely
// `do_it` and `done`. Every other trait method keeps its faithful no-op default,
// which is exactly how curl leaves the `ZERO_NULL` slots and lets generic
// behavior take over; the driver methods above supply the real work once the
// transfer layer binds a context to its connection state.
// ===========================================================================

/// The IMAP/IMAPS protocol handler (← `struct Curl_protocol Curl_protocol_imap`).
///
/// A zero-sized, `'static` singleton — IMAP keeps all mutable state on the
/// per-connection [`ImapConn`], never on the handler — so it can be shared as
/// `&'static dyn Protocol` across the multi handle's worker threads, exactly as
/// curl shares its single `Curl_protocol_imap` record.
pub struct ImapHandler;

/// The IMAP handler singleton referenced by
/// [`SCHEME_IMAP`](crate::protocols::SCHEME_IMAP) and
/// [`SCHEME_IMAPS`](crate::protocols::SCHEME_IMAPS) (← `Curl_protocol_imap`).
///
/// Both the cleartext (`imap://`, STARTTLS-capable) and implicit-TLS
/// (`imaps://`) schemes share this one record, mirroring how curl registers the
/// same `&Curl_protocol_imap` for `Curl_scheme_imap` and `Curl_scheme_imaps`
/// (TLS is layered by the connection filter chain, not by a distinct handler).
pub static HANDLER: ImapHandler = ImapHandler;

/// The remaining whole-transfer time budget in milliseconds for the IMAP engine
/// (← curl's `Curl_timeleft_ms(data)`): the configured `CURLOPT_TIMEOUT[_MS]`
/// when set, or `0` — the sentinel the ping-pong pump reads as "no transfer
/// timeout applies". Mirrors the SMTP/POP3 handlers.
fn imap_do_timeleft(ctx: &TransferCtx) -> i64 {
    ctx.request
        .timeout
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Borrow the transfer's [`Connection`] and its [`ImapConn`] engine disjointly
/// from the [`TransferCtx`]: the connection lives in [`TransferCtx::conn`] and
/// the engine — established by the connect phase (← `conn->proto.imapc`) — in
/// [`TransferCtx::proto_state`]. Because `conn` and `proto_state` are distinct
/// fields, the two mutable borrows coexist (the disjoint-field-borrow pattern
/// documented on [`TransferCtx`]).
///
/// # Errors
/// [`CurlCode::BadFunctionArgument`] when either handle is absent — a caller
/// precondition mirroring curl requiring both `data->conn` and
/// `conn->proto.imapc` to be established before the DO phase runs.
fn imap_conn_and_engine(ctx: &mut TransferCtx) -> Result<(&mut Connection, &mut ImapConn)> {
    let engine = ctx
        .proto_state
        .as_deref_mut()
        .and_then(|s| s.downcast_mut::<ImapConn>())
        .ok_or_else(|| {
            Error::with_context(
                CurlCode::BadFunctionArgument,
                "[IMAP] no IMAP engine assigned to transfer",
            )
        })?;
    let conn = ctx.conn.as_deref_mut().ok_or_else(|| {
        Error::with_context(
            CurlCode::BadFunctionArgument,
            "[IMAP] no connection assigned to transfer",
        )
    })?;
    Ok((conn, engine))
}

/// Drain the engine's accumulated client body (the untagged response lines and
/// literal-header bytes the DO-phase response handlers captured, ← curl's
/// buffered-literal reinjection) and deliver it to the transfer's
/// [`sink`](TransferCtx::sink). The engine `proto_state` borrow ends when the
/// owned bytes are taken, before the disjoint `sink` borrow.
fn imap_flush_body(ctx: &mut TransferCtx) -> Result<()> {
    let body = match ctx
        .proto_state
        .as_deref_mut()
        .and_then(|s| s.downcast_mut::<ImapConn>())
    {
        Some(engine) => engine.take_client_body(),
        None => Vec::new(),
    };
    if !body.is_empty() {
        if let Some(sink) = ctx.sink.as_deref_mut() {
            sink.write(&body)?;
        }
    }
    Ok(())
}

impl Protocol for ImapHandler {
    /// The IMAP "DO" phase (← `imap_do`).
    ///
    /// Drives the transfer's [`ImapConn`] engine (held in
    /// [`TransferCtx::proto_state`], ← `conn->proto.imapc`) and its
    /// [`Connection`] (in [`TransferCtx::conn`]) through
    /// [`ImapConn::run_do`], which issues the tagged command sequence
    /// (`SELECT`/`FETCH`/`APPEND`/`SEARCH`/`LIST`, …) derived from the request's
    /// URL path/query. Any body bytes buffered by the DO-phase response handlers
    /// (untagged lines and literal headers) are then delivered to the client
    /// [`sink`](TransferCtx::sink) via [`imap_flush_body`]. Returns `true` once
    /// the DO phase reaches [`ImapState::Stop`]; otherwise the transfer layer
    /// continues via [`doing`](Protocol::doing).
    ///
    /// # Errors
    /// [`CurlCode::BadFunctionArgument`] if the transfer carries no connection
    /// or no IMAP engine, or any protocol/I/O error surfaced while driving the
    /// command sequence.
    fn do_it<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        Box::pin(async move {
            let now = Instant::now();
            let timeleft = imap_do_timeleft(ctx);
            // Own the URL path/query so the request borrow ends before the
            // connection/engine borrows below (← `imap_do` parsing the URL).
            let path = ctx.request.path.clone();
            let query = ctx.request.query.clone();
            let done = {
                let (conn, engine) = imap_conn_and_engine(ctx)?;
                engine
                    .run_do(conn, &path, query.as_deref(), now, timeleft)
                    .await?
            };
            // Deliver the buffered untagged/literal-header bytes to the sink.
            imap_flush_body(ctx)?;
            Ok(done)
        })
    }

    /// Continue a non-blocking IMAP DO phase (← `imap_doing`).
    ///
    /// Pumps the engine's state machine one step via [`ImapConn::run_doing`],
    /// then delivers any newly buffered body bytes to the sink. Returns `true`
    /// once the DO phase reaches [`ImapState::Stop`].
    ///
    /// # Errors
    /// As [`do_it`](Self::do_it): a missing connection/engine, or an engine
    /// error surfaced while pumping the state machine.
    fn doing<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        Box::pin(async move {
            let now = Instant::now();
            let timeleft = imap_do_timeleft(ctx);
            let done = {
                let (conn, engine) = imap_conn_and_engine(ctx)?;
                engine.run_doing(conn, now, timeleft).await?
            };
            imap_flush_body(ctx)?;
            Ok(done)
        })
    }

    /// The IMAP "DONE" phase (← `imap_done`).
    ///
    /// Finalizes the transfer over the engine via [`ImapConn::run_done`]: on
    /// error it flags the connection for closure and propagates the status,
    /// otherwise it issues the trailing `FETCH`/`APPEND` completion
    /// (`IMAP_FETCH_FINAL` / `IMAP_APPEND_FINAL`) and resets the per-request
    /// state, honoring the incoming `status`/`premature`. Any residual buffered
    /// body is delivered to the sink.
    ///
    /// # Errors
    /// The propagated bad `status`, [`CurlCode::BadFunctionArgument`] for a
    /// missing connection/engine, or any error from the completion exchange.
    fn done<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        status: Result<()>,
        premature: bool,
    ) -> ProtoFuture<'a, ()> {
        Box::pin(async move {
            let timeleft = imap_do_timeleft(ctx);
            {
                let (conn, engine) = imap_conn_and_engine(ctx)?;
                engine.run_done(conn, status, premature, timeleft).await?;
            }
            imap_flush_body(ctx)?;
            Ok(())
        })
    }

    /// Deliver a chunk of response *body* bytes (← `imap_write`).
    ///
    /// IMAP literal bodies are raw, byte-counted content (no dot-stuffing), so
    /// the transfer layer's received body bytes pass straight through to the
    /// transfer's [`sink`](TransferCtx::sink) — the "subsequent body bytes"
    /// following the buffered literal header, funneled exactly as curl's
    /// `imap_write` calls `Curl_client_write`. `is_eos` needs no IMAP-specific
    /// finalisation (the recorded literal size delimits the body).
    fn write_resp<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        buf: &'a [u8],
        is_eos: bool,
    ) -> ProtoFuture<'a, ()> {
        Box::pin(async move {
            let _ = is_eos;
            if !buf.is_empty() {
                if let Some(sink) = ctx.sink.as_deref_mut() {
                    sink.write(buf)?;
                }
            }
            Ok(())
        })
    }
}

// ===========================================================================
// Unit tests — behavioral parity with `lib/imap.c`.
//
// These cover the pure, deterministic pieces of the IMAP port that can be
// exercised without a live network: the state-name trace table, command
// tagging, the `endofresp` line classifier (tagged / untagged / continuation),
// the SASL glue (`SaslProto`), CAPABILITY parsing, the URL-path / URL-option /
// custom-request parsers, and the byte-level helpers (`imap_atom`,
// `imap_matchresp`, `imap_find_literal`, literal-size parsing, bchar tests).
// The wire formats asserted here are the ones curl 8.19.0-DEV produces and
// accepts, so a regression in any of them is a parity break.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    use crate::conn::Scheme;

    /// A fresh IMAP connection state on connection id `0` (tag letter `'A'`),
    /// matching curl's freshly-`calloc`'d `imap_conn` with `resptag = "*"`.
    fn conn() -> ImapConn {
        ImapConn::new(0)
    }

    /// A bare [`Connection`] carrying the given `;`-separated login `options`
    /// (curl's `conn->options`, the `URLOPTIONS` string), for the URL-option
    /// parser.
    fn conn_opts(opts: &str) -> Connection {
        let mut c = Connection::new(Scheme::new("imap", 143), "example.com", 143);
        if !opts.is_empty() {
            c.options = Some(opts.to_string());
        }
        c
    }

    // ----- In-memory mock connection filter (leaf; overrides send/recv) -----
    //
    // Mirrors the harness in `smtp.rs`/`pop3.rs`: it delivers canned bytes on
    // `recv` and captures written bytes on `send`, so command framing and
    // response handling can be exercised without a live socket.
    use std::sync::{Arc, Mutex};

    use crate::conn::filters::{CfFuture, FilterCtx, QueryCtx, QueryOut};
    use crate::conn::{CfQuery, CfType, ConnectionFilter, FilterChain, Transport};
    use crate::protocols::TransferSink;

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
        let mut conn = Connection::new(Scheme::new("imap", 143), "example.com", 143);
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

    // ----- State-name trace table (← `names[]`) -------------------------------

    #[test]
    fn state_names_match_curl_verbatim() {
        // Byte-for-byte with the C `names[]` table; a mismatch changes --trace.
        assert_eq!(ImapState::Stop.name(), "STOP");
        assert_eq!(ImapState::ServerGreet.name(), "SERVERGREET");
        assert_eq!(ImapState::Capability.name(), "CAPABILITY");
        assert_eq!(ImapState::StartTls.name(), "STARTTLS");
        assert_eq!(ImapState::UpgradeTls.name(), "UPGRADETLS");
        assert_eq!(ImapState::Authenticate.name(), "AUTHENTICATE");
        assert_eq!(ImapState::Login.name(), "LOGIN");
        assert_eq!(ImapState::List.name(), "LIST");
        assert_eq!(ImapState::Select.name(), "SELECT");
        assert_eq!(ImapState::Fetch.name(), "FETCH");
        assert_eq!(ImapState::FetchFinal.name(), "FETCH_FINAL");
        assert_eq!(ImapState::Append.name(), "APPEND");
        assert_eq!(ImapState::AppendFinal.name(), "APPEND_FINAL");
        assert_eq!(ImapState::Search.name(), "SEARCH");
        assert_eq!(ImapState::Logout.name(), "LOGOUT");
        // The trailing sentinel has no curl name (the table stops before it).
        assert_eq!(ImapState::Last.name(), "");
    }

    #[test]
    fn state_discriminants_start_at_zero() {
        // `IMAP_STOP == 0` so a discriminant cast indexes `names[]` directly.
        assert_eq!(ImapState::Stop as usize, 0);
        assert_eq!(ImapState::ServerGreet as usize, 1);
        assert_eq!(ImapState::Capability as usize, 2);
    }

    // ----- calc_tag (← "%c%03d", 'A' + connection_id % 26) --------------------

    #[test]
    fn calc_tag_letter_and_zero_padded_number() {
        assert_eq!(calc_tag(0, 1), "A001");
        assert_eq!(calc_tag(1, 2), "B002");
        assert_eq!(calc_tag(25, 999), "Z999");
        // connection_id wraps modulo 26 back to 'A'.
        assert_eq!(calc_tag(26, 5), "A005");
        // Numbers above 999 are not truncated (curl's %03d is a minimum width).
        assert_eq!(calc_tag(0, 1234), "A1234");
    }

    // ----- imap_atom (← imap_atom) --------------------------------------------

    #[test]
    fn imap_atom_leaves_clean_strings_untouched() {
        assert_eq!(imap_atom("INBOX", false), "INBOX");
        assert_eq!(imap_atom("Sent.2024", false), "Sent.2024");
    }

    #[test]
    fn imap_atom_quotes_when_special_present() {
        // A space forces quoting.
        assert_eq!(imap_atom("Sent Items", false), "\"Sent Items\"");
        // `"` and `\` are backslash-escaped inside the quotes.
        assert_eq!(imap_atom("a\"b", false), "\"a\\\"b\"");
        assert_eq!(imap_atom("a\\b", false), "\"a\\\\b\"");
    }

    #[test]
    fn imap_atom_escape_only_skips_the_wrapping_quotes() {
        assert_eq!(imap_atom("a\"b", true), "a\\\"b");
    }

    // ----- imap_matchresp (← imap_matchresp) ----------------------------------

    #[test]
    fn matchresp_accepts_plain_and_numbered_untagged() {
        assert!(imap_matchresp(b"* CAPABILITY IMAP4rev1\r\n", b"CAPABILITY"));
        assert!(imap_matchresp(b"* 5 FETCH (BODY[])\r\n", b"FETCH"));
        // Command name followed only by CRLF (no argument) still matches.
        assert!(imap_matchresp(b"* SEARCH\r\n", b"SEARCH"));
    }

    #[test]
    fn matchresp_rejects_other_commands() {
        assert!(!imap_matchresp(b"* OK [UIDNEXT 2]\r\n", b"CAPABILITY"));
        assert!(!imap_matchresp(b"* 5 EXPUNGE\r\n", b"FETCH"));
    }

    // ----- imap_find_literal + parse_literal_size -----------------------------

    #[test]
    fn find_literal_locates_unquoted_brace() {
        assert_eq!(imap_find_literal(b"foo {12}"), Some(4));
        // A brace inside a quoted string is skipped; the second one is found.
        assert_eq!(imap_find_literal(b"\"{5}\" {7}"), Some(6));
        assert_eq!(imap_find_literal(b"no literal here"), None);
    }

    #[test]
    fn parse_literal_size_requires_digits_and_closing_brace() {
        assert_eq!(parse_literal_size(b"12}"), Some(12));
        assert_eq!(parse_literal_size(b"0}"), Some(0));
        assert_eq!(parse_literal_size(b"12"), None); // no closing brace
        assert_eq!(parse_literal_size(b"}"), None); // no digits
    }

    #[test]
    fn find_and_parse_literal_together() {
        let line = b"* 1 FETCH (BODY[] {42}\r\n";
        let idx = imap_find_literal(line).expect("has literal");
        assert_eq!(parse_literal_size(&line[idx + 1..]), Some(42));
    }

    // ----- parse_u32_prefix (← curlx_str_number, UINT_MAX) --------------------

    #[test]
    fn parse_u32_prefix_stops_at_non_digit_and_caps() {
        assert_eq!(parse_u32_prefix(b"12345"), Some(12345));
        assert_eq!(parse_u32_prefix(b"12345/rest"), Some(12345));
        assert_eq!(parse_u32_prefix(b"abc"), None);
        assert_eq!(parse_u32_prefix(b"4294967295"), Some(u32::MAX));
        assert_eq!(parse_u32_prefix(b"4294967296"), None); // overflow
    }

    // ----- imap_is_bchar ------------------------------------------------------

    #[test]
    fn bchar_grammar_matches_rfc5092() {
        for &c in b"aZ0:@/&=-._~!$'()*+,%" {
            assert!(imap_is_bchar(c), "expected bchar: {}", c as char);
        }
        for &c in b" \t\r\n;<>\0" {
            assert!(!imap_is_bchar(c), "unexpected bchar: {}", c as char);
        }
    }

    // ----- is_custom_fetch_listing --------------------------------------------

    #[test]
    fn custom_fetch_listing_detects_ranges() {
        let mut c = conn();
        c.imap.custom = Some("FETCH".into());
        c.imap.custom_params = Some(" 1:* (FLAGS)".into());
        assert!(is_custom_fetch_listing(&c.imap));

        // A single-message FETCH (no ':' or ',') is a download, not a listing.
        c.imap.custom_params = Some(" 1 (BODY[])".into());
        assert!(!is_custom_fetch_listing(&c.imap));

        // "UID FETCH 1,2,3" is a listing.
        c.imap.custom = Some("UID".into());
        c.imap.custom_params = Some(" FETCH 1,2,3 (FLAGS)".into());
        assert!(is_custom_fetch_listing(&c.imap));
    }

    // ----- endofresp: tagged completion (← imap_endofresp) --------------------

    #[test]
    fn endofresp_tagged_ok_no_preauth() {
        let mut c = conn();
        c.resptag = "A001".into();
        c.state = ImapState::Login;
        let mut code = 0;

        assert!(c.endofresp(b"A001 OK LOGIN completed\r\n", &mut code));
        assert_eq!(code, IMAP_RESP_OK);

        assert!(c.endofresp(b"A001 NO LOGIN failed\r\n", &mut code));
        assert_eq!(code, IMAP_RESP_NOT_OK);

        assert!(c.endofresp(b"A001 BAD command\r\n", &mut code));
        assert_eq!(code, IMAP_RESP_NOT_OK);

        assert!(c.endofresp(b"A001 PREAUTH ready\r\n", &mut code));
        assert_eq!(code, IMAP_RESP_PREAUTH);
    }

    #[test]
    fn endofresp_greeting_uses_star_tag() {
        // During SERVERGREET the tag is "*", so "* OK ..." is a tagged OK — this
        // is exactly how curl recognises the banner.
        let mut c = conn();
        assert_eq!(c.resptag, "*");
        c.state = ImapState::ServerGreet;
        let mut code = 0;
        assert!(c.endofresp(b"* OK IMAP4rev1 Service Ready\r\n", &mut code));
        assert_eq!(code, IMAP_RESP_OK);
    }

    // ----- endofresp: untagged, state-gated -----------------------------------

    #[test]
    fn endofresp_untagged_accepted_only_in_matching_state() {
        let mut c = conn();
        c.resptag = "A002".into();
        let mut code = 0;

        c.state = ImapState::Capability;
        assert!(c.endofresp(b"* CAPABILITY IMAP4rev1 STARTTLS\r\n", &mut code));
        assert_eq!(code, IMAP_RESP_UNTAGGED);

        c.state = ImapState::Fetch;
        assert!(c.endofresp(b"* 1 FETCH (BODY[] {3}\r\n", &mut code));
        assert_eq!(code, IMAP_RESP_UNTAGGED);

        // SELECT accepts any untagged line (no common prefix).
        c.state = ImapState::Select;
        assert!(c.endofresp(b"* 23 EXISTS\r\n", &mut code));
        assert_eq!(code, IMAP_RESP_UNTAGGED);

        // An untagged line with no expecting state is ignored (not a completion).
        c.state = ImapState::Stop;
        assert!(!c.endofresp(b"* 1 EXPUNGE\r\n", &mut code));
    }

    // ----- endofresp: continuation (`+`) --------------------------------------

    #[test]
    fn endofresp_continuation_only_for_auth_and_append() {
        let mut c = conn();
        c.resptag = "A003".into();
        let mut code = 0;

        c.state = ImapState::Authenticate;
        assert!(c.endofresp(b"+ VGVzdA==\r\n", &mut code));
        assert_eq!(code, IMAP_RESP_CONTINUE);

        // A bare "+" (three bytes with CRLF) is also a continuation.
        c.state = ImapState::Append;
        assert!(c.endofresp(b"+\r\n", &mut code));
        assert_eq!(code, IMAP_RESP_CONTINUE);

        // A continuation in any other state is a protocol error (BAD == -1).
        c.state = ImapState::Login;
        assert!(c.endofresp(b"+ unexpected\r\n", &mut code));
        assert_eq!(code, IMAP_RESP_BAD);
    }

    #[test]
    fn endofresp_continuation_suppressed_by_custom_request() {
        // With a custom request active, `+` is never treated as a continuation.
        let mut c = conn();
        c.resptag = "A004".into();
        c.state = ImapState::Authenticate;
        c.imap.custom = Some("NOOP".into());
        let mut code = 0;
        assert!(!c.endofresp(b"+ data\r\n", &mut code));
    }

    // ----- SaslProto glue (← saslimap + imap_get_message) ---------------------

    #[test]
    fn sasl_associated_items_match_curl() {
        let c = conn();
        assert_eq!(c.service(), "imap");
        assert_eq!(c.max_ir_len(), 0);
        assert_eq!(c.cont_code(), IMAP_RESP_CONTINUE);
        assert_eq!(c.final_code(), IMAP_RESP_OK);
        assert_eq!(c.def_mechs(), SASL_AUTH_DEFAULT);
        assert_eq!(c.flags(), SASL_FLAG_BASE64);
    }

    #[test]
    fn sasl_send_auth_tags_and_appends_initial_response() {
        let mut c = conn();
        // With an initial response (SASL-IR).
        c.send_auth("PLAIN", Some(b"AGFsaWNlAHB3")).unwrap();
        assert_eq!(c.resptag, "A001");
        assert_eq!(
            c.sasl_out.last().unwrap(),
            "A001 AUTHENTICATE PLAIN AGFsaWNlAHB3"
        );

        // Without an initial response.
        c.send_auth("LOGIN", None).unwrap();
        assert_eq!(c.resptag, "A002");
        assert_eq!(c.sasl_out.last().unwrap(), "A002 AUTHENTICATE LOGIN");
    }

    #[test]
    fn sasl_cont_and_cancel_are_untagged() {
        let mut c = conn();
        c.cont_auth("PLAIN", b"cmVzcG9uc2U=").unwrap();
        assert_eq!(c.sasl_out.last().unwrap(), "cmVzcG9uc2U=");
        c.cancel_auth("PLAIN").unwrap();
        assert_eq!(c.sasl_out.last().unwrap(), "*");
    }

    #[test]
    fn sasl_get_message_strips_marker_and_whitespace() {
        let mut c = conn();
        c.last_response = b"+ VGVzdA==\r\n".to_vec();
        assert_eq!(c.get_message().unwrap(), b"VGVzdA==");

        // A bare "+\r\n" yields an empty message.
        c.last_response = b"+\r\n".to_vec();
        assert!(c.get_message().unwrap().is_empty());

        // Two bytes or fewer => empty (curl's else branch).
        c.last_response = b"+".to_vec();
        assert!(c.get_message().unwrap().is_empty());
    }

    // ----- CAPABILITY parsing (← imap_state_capability_resp word loop) --------

    #[test]
    fn parse_capabilities_sets_flags_and_mechs() {
        let mut c = conn();
        // Nothing advertised before parsing.
        assert_eq!(c.sasl.as_ref().unwrap().authmechs(), 0);

        c.parse_capabilities(
            b"* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED AUTH=PLAIN SASL-IR\r\n",
        );

        assert!(c.tls_supported);
        assert!(c.login_disabled);
        assert!(c.ir_supported);
        // At least one SASL mechanism (AUTH=PLAIN) was recorded.
        assert_ne!(c.sasl.as_ref().unwrap().authmechs(), 0);
    }

    #[test]
    fn parse_capabilities_ignores_unrelated_tokens() {
        let mut c = conn();
        c.parse_capabilities(b"* CAPABILITY IMAP4rev1 LITERAL+ IDLE\r\n");
        assert!(!c.tls_supported);
        assert!(!c.login_disabled);
        assert!(!c.ir_supported);
        assert_eq!(c.sasl.as_ref().unwrap().authmechs(), 0);
    }

    // ----- parse_url_path (← imap_parse_url_path) -----------------------------

    #[test]
    fn url_path_extracts_mailbox_and_strips_trailing_slash() {
        let mut c = conn();
        c.parse_url_path("/INBOX", None).unwrap();
        assert_eq!(c.imap.mailbox.as_deref(), Some("INBOX"));

        let mut c = conn();
        c.parse_url_path("/INBOX/", None).unwrap();
        assert_eq!(c.imap.mailbox.as_deref(), Some("INBOX"));

        // A path that is just "/" leaves the mailbox unset.
        let mut c = conn();
        c.parse_url_path("/", None).unwrap();
        assert_eq!(c.imap.mailbox, None);
    }

    #[test]
    fn url_path_parses_hierarchical_parameters() {
        let mut c = conn();
        c.parse_url_path("/INBOX;UID=42", None).unwrap();
        assert_eq!(c.imap.mailbox.as_deref(), Some("INBOX"));
        assert_eq!(c.imap.uid.as_deref(), Some("42"));

        let mut c = conn();
        c.parse_url_path("/INBOX;UIDVALIDITY=12345", None).unwrap();
        assert!(c.imap.uidvalidity_set);
        assert_eq!(c.imap.uidvalidity, 12345);

        let mut c = conn();
        c.parse_url_path("/INBOX;MAILINDEX=7", None).unwrap();
        assert_eq!(c.imap.mindex.as_deref(), Some("7"));

        let mut c = conn();
        c.parse_url_path("/INBOX;SECTION=1.2", None).unwrap();
        assert_eq!(c.imap.section.as_deref(), Some("1.2"));

        let mut c = conn();
        c.parse_url_path("/INBOX;PARTIAL=0.1024", None).unwrap();
        assert_eq!(c.imap.partial.as_deref(), Some("0.1024"));
    }

    #[test]
    fn url_path_query_gated_by_mailbox_and_no_uid() {
        // A SEARCH query is kept with a mailbox and no UID.
        let mut c = conn();
        c.parse_url_path("/INBOX", Some("FROM boss")).unwrap();
        assert_eq!(c.imap.query.as_deref(), Some("FROM boss"));

        // With a UID present the query is discarded (RFC-5092).
        let mut c = conn();
        c.parse_url_path("/INBOX;UID=9", Some("FROM boss")).unwrap();
        assert_eq!(c.imap.query, None);
    }

    #[test]
    fn url_path_rejects_unknown_param_and_trailing_junk() {
        let mut c = conn();
        assert_eq!(
            c.parse_url_path("/INBOX;BOGUS=1", None).unwrap_err().code(),
            CurlCode::UrlMalformat
        );

        let mut c = conn();
        assert_eq!(
            c.parse_url_path("/INBOX extra", None).unwrap_err().code(),
            CurlCode::UrlMalformat
        );
    }

    #[test]
    fn url_path_rejects_decoded_control_character() {
        // "%00" decodes to NUL (< 0x20) and must be rejected.
        let mut c = conn();
        assert_eq!(
            c.parse_url_path("/IN%00BOX", None).unwrap_err().code(),
            CurlCode::UrlMalformat
        );
    }

    // ----- parse_custom_request (← imap_parse_custom_request) -----------------

    #[test]
    fn custom_request_splits_verb_and_params() {
        let mut c = conn();
        c.parse_custom_request(Some("FETCH 1:* (FLAGS)")).unwrap();
        assert_eq!(c.imap.custom.as_deref(), Some("FETCH"));
        // The parameters retain their leading space.
        assert_eq!(c.imap.custom_params.as_deref(), Some(" 1:* (FLAGS)"));

        // A verb with no arguments has no parameters.
        let mut c = conn();
        c.parse_custom_request(Some("NOOP")).unwrap();
        assert_eq!(c.imap.custom.as_deref(), Some("NOOP"));
        assert_eq!(c.imap.custom_params, None);
    }

    #[test]
    fn custom_request_rejects_control_character() {
        let mut c = conn();
        assert_eq!(
            c.parse_custom_request(Some("A%00B")).unwrap_err().code(),
            CurlCode::UrlMalformat
        );
    }

    // ----- parse_url_options (← imap_parse_url_options) -----------------------

    #[test]
    fn url_options_auth_plus_login_prefers_cleartext() {
        let mut c = conn();
        c.parse_url_options(&conn_opts("AUTH=+LOGIN")).unwrap();
        assert_eq!(c.preftype, IMAP_TYPE_CLEARTEXT);
    }

    #[test]
    fn url_options_default_is_any() {
        // No options => the default SASL preference (ANY) is kept.
        let mut c = conn();
        c.parse_url_options(&conn_opts("")).unwrap();
        assert_eq!(c.preftype, IMAP_TYPE_ANY);
    }

    #[test]
    fn url_options_specific_mech_selects_sasl() {
        let mut c = conn();
        c.parse_url_options(&conn_opts("AUTH=PLAIN")).unwrap();
        assert_eq!(c.preftype, IMAP_TYPE_SASL);
    }

    #[test]
    fn url_options_rejects_unknown_option() {
        let mut c = conn();
        assert_eq!(
            c.parse_url_options(&conn_opts("BOGUS=1"))
                .unwrap_err()
                .code(),
            CurlCode::UrlMalformat
        );
    }

    // ----- Per-request reset and defaults -------------------------------------

    #[test]
    fn imap_default_uses_body_transfer() {
        assert_eq!(conn().imap.transfer, PpTransfer::Body);
    }

    #[test]
    fn easy_reset_clears_request_fields() {
        let mut c = conn();
        c.parse_url_path("/INBOX;UID=1", None).unwrap();
        c.imap.custom = Some("FETCH".into());
        c.imap.easy_reset();
        assert_eq!(c.imap.mailbox, None);
        assert_eq!(c.imap.uid, None);
        assert_eq!(c.imap.custom, None);
        assert_eq!(c.imap.transfer, PpTransfer::Body);
    }

    // ----- Protocol vtable shim (← Curl_protocol_imap) ------------------------

    #[tokio::test]
    async fn handler_drives_list_body_to_sink() {
        // A directory listing (LIST) is the DO command chosen for a bare `/`
        // path with no mailbox/custom/upload. The server returns one untagged
        // listing line followed by the tagged completion; the handler must issue
        // the command over the connection and deliver the untagged line's bytes
        // to the client sink (the "buffered literals/body bytes reach client
        // callbacks" wiring the review flagged as deferred).
        let io = Arc::new(Mutex::new(MockIo {
            to_deliver: b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\nA001 OK LIST completed\r\n"
                .to_vec(),
            ..MockIo::default()
        }));
        let mut conn = conn_with(Arc::clone(&io));
        conn.connect(FIRSTSOCKET, false).await.unwrap();

        // The engine the connect phase would have installed (connection id 0 =>
        // tag letter 'A'), matching curl's `conn->proto.imapc`.
        let engine = ImapConn::new(0);

        let sink = Arc::new(Mutex::new(Vec::new()));
        let mut ctx = TransferCtx::new();
        ctx.request.path = String::from("/");
        ctx.conn = Some(Box::new(conn));
        ctx.proto_state = Some(Box::new(engine));
        ctx.sink = Some(Box::new(RecordingSink(Arc::clone(&sink))));

        // do_it issues `A001 LIST "" *` and flushes it; doing reads the
        // untagged listing line and the tagged completion, ending the DO phase.
        let mut done = HANDLER.do_it(&mut ctx).await.unwrap();
        let mut guard = 0;
        while !done && guard < 40 {
            done = HANDLER.doing(&mut ctx).await.unwrap();
            guard += 1;
        }
        assert!(done, "handler DO phase did not reach completion");

        // The tagged LIST command reached the wire.
        assert!(
            io.lock().unwrap().captured.windows(4).any(|w| w == b"LIST"),
            "LIST command was not sent"
        );
        // The untagged listing line reached the client sink.
        let body = sink.lock().unwrap().clone();
        assert!(
            body.windows(5).any(|w| w == b"INBOX"),
            "listing body did not reach the sink: {body:?}"
        );

        // A transfer with no connection/engine is a caller-precondition error.
        let mut empty = TransferCtx::new();
        let err = HANDLER.do_it(&mut empty).await.unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
    }

    #[tokio::test]
    async fn handler_done_reports_missing_precondition() {
        // done (← imap_done) requires the connection and engine established by
        // the connect phase; an empty transfer is a caller-precondition error
        // (mirrors the SMTP/POP3 handlers).
        let mut ctx = TransferCtx::new();
        let err = HANDLER.done(&mut ctx, Ok(()), false).await.unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
    }

    #[tokio::test]
    async fn handler_write_resp_passes_literal_body_to_sink() {
        // IMAP literal bodies are raw, byte-counted content (no dot-stuffing):
        // write_resp (← imap_write) funnels the "subsequent body bytes" that
        // follow a buffered literal header straight to the client sink.
        let sink = Arc::new(Mutex::new(Vec::new()));
        let mut ctx = TransferCtx::new();
        ctx.sink = Some(Box::new(RecordingSink(Arc::clone(&sink))));

        HANDLER
            .write_resp(&mut ctx, b"Subject: hi\r\n\r\nbody bytes", true)
            .await
            .unwrap();

        assert_eq!(
            sink.lock().unwrap().as_slice(),
            b"Subject: hi\r\n\r\nbody bytes"
        );
    }

    #[test]
    fn handler_is_zero_sized_singleton() {
        // Curl_protocol_imap is a shared static; the handler must be ZST so the
        // `&'static dyn Protocol` in the scheme table costs nothing.
        assert_eq!(std::mem::size_of::<ImapHandler>(), 0);
    }
}
