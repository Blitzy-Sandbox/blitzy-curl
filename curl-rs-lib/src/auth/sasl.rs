// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! SASL authentication framing + state engine (RFC 4422), plus CRAM-MD5 (RFC 2195).
//!
//! Language rewrite of curl `lib/curl_sasl.c` (the SASL state machine and mechanism
//! selection), `lib/vauth/cram.c` (CRAM-MD5), and the SASL-related behavior of
//! `lib/vauth/gsasl.c`. SASL is the shared authentication framework used by the mail
//! protocols (IMAP/POP3/SMTP); this module is the **orchestrator** that drives the
//! per-mechanism helpers living in the sibling `crate::auth` modules:
//!
//! | Mechanism(s)                     | Delegated to                       |
//! |----------------------------------|------------------------------------|
//! | PLAIN / LOGIN / EXTERNAL         | [`crate::auth::basic`]             |
//! | CRAM-MD5                         | this module ([`create_cram_md5_message`]) |
//! | DIGEST-MD5                       | [`crate::auth::digest`]            |
//! | SCRAM-SHA-1 / SCRAM-SHA-256      | [`crate::auth::scram`]             |
//! | NTLM (type-1 / type-3)           | [`crate::auth::ntlm`]              |
//! | OAUTHBEARER / XOAUTH2            | [`crate::auth::bearer`]            |
//! | GSSAPI (Kerberos V5)             | [`crate::auth::kerberos`] (feature-gated) |
//!
//! ## Purity & safety
//!
//! Pure Rust, **zero `unsafe`** (the crate root applies `#![forbid(unsafe_code)]`). curl's
//! optional external `gsasl` C library is intentionally NOT used: SCRAM is implemented in
//! pure Rust in [`crate::auth::scram`]. The C `SASL_GSASL` state is nonetheless retained as
//! a diagnostic state **name** (see [`SaslState::Gsasl`]) so that `--trace` output stays
//! byte-identical to curl; it is simply routed to the pure-Rust SCRAM engine.
//!
//! ## Wire & diagnostic parity (AAP §0.6, §0.7 — Minimal Change Mandate)
//!
//! Three tables in this module are frozen wire/diagnostic contracts reproduced verbatim
//! from curl and must never drift:
//!
//! * the [`SASL_MECH_LOGIN`]..[`SASL_MECH_SCRAM_SHA_256`] bitmask,
//! * the mechanism-name table (the tokens sent on the wire), and
//! * the [`SaslState`] names emitted in `SASL %p state change from %s to %s` traces.
//!
//! No mechanisms or states are added beyond curl's set.

use crate::auth::kerberos::Kerberos5Data;
use crate::auth::ntlm::NtlmData;
use crate::auth::scram::{ScramClient, ScramHash};
use crate::auth::{basic, bearer, digest, kerberos, ntlm};
use crate::auth::{
    user_contains_domain, CURLAUTH_BASIC, CURLAUTH_BEARER, CURLAUTH_DIGEST, CURLAUTH_GSSAPI,
    CURLAUTH_NTLM,
};
use crate::error::{Error, Result};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use md5::Md5;

// ===========================================================================
// Phase A — mechanism bitmask, aggregate values, flags, name strings, table
// (← lib/curl_sasl.h L32-63 and the `mechtable` in lib/curl_sasl.c L49-66)
// ===========================================================================
//
// These bits are the on-the-wire mechanism identifiers. They are represented as
// `u32` (curl stores the mask in `unsigned short` fields; `u32` is a strict
// superset and avoids repeated casts) — every defined bit fits well within 16
// bits, so the wire and mask semantics are unchanged.

/// LOGIN mechanism (draft-murchison-sasl-login) — `SASL_MECH_LOGIN`.
pub const SASL_MECH_LOGIN: u32 = 1 << 0;
/// PLAIN mechanism (RFC 4616) — `SASL_MECH_PLAIN`.
pub const SASL_MECH_PLAIN: u32 = 1 << 1;
/// CRAM-MD5 mechanism (RFC 2195) — `SASL_MECH_CRAM_MD5`.
pub const SASL_MECH_CRAM_MD5: u32 = 1 << 2;
/// DIGEST-MD5 mechanism (RFC 2831) — `SASL_MECH_DIGEST_MD5`.
pub const SASL_MECH_DIGEST_MD5: u32 = 1 << 3;
/// GSSAPI (Kerberos V5) mechanism (RFC 4752) — `SASL_MECH_GSSAPI`.
pub const SASL_MECH_GSSAPI: u32 = 1 << 4;
/// EXTERNAL mechanism (RFC 4422 §A) — `SASL_MECH_EXTERNAL`.
pub const SASL_MECH_EXTERNAL: u32 = 1 << 5;
/// NTLM mechanism — `SASL_MECH_NTLM`.
pub const SASL_MECH_NTLM: u32 = 1 << 6;
/// XOAUTH2 mechanism (Google) — `SASL_MECH_XOAUTH2`.
pub const SASL_MECH_XOAUTH2: u32 = 1 << 7;
/// OAUTHBEARER mechanism (RFC 7628) — `SASL_MECH_OAUTHBEARER`.
pub const SASL_MECH_OAUTHBEARER: u32 = 1 << 8;
/// SCRAM-SHA-1 mechanism (RFC 5802) — `SASL_MECH_SCRAM_SHA_1`.
pub const SASL_MECH_SCRAM_SHA_1: u32 = 1 << 9;
/// SCRAM-SHA-256 mechanism (RFC 7677) — `SASL_MECH_SCRAM_SHA_256`.
pub const SASL_MECH_SCRAM_SHA_256: u32 = 1 << 10;

/// No mechanism (`SASL_AUTH_NONE`).
pub const SASL_AUTH_NONE: u32 = 0;
/// Every mechanism (`SASL_AUTH_ANY`) — the low 16 bits, matching curl's
/// `unsigned short` mask width.
pub const SASL_AUTH_ANY: u32 = 0xffff;
/// The default preference set (`SASL_AUTH_DEFAULT`): everything except EXTERNAL,
/// which is only chosen when explicitly requested (it authenticates with no
/// password).
pub const SASL_AUTH_DEFAULT: u32 = SASL_AUTH_ANY & !SASL_MECH_EXTERNAL;

/// Configuration flag: the protocol's SASL messages are base64-encoded on the
/// wire (`SASL_FLAG_BASE64`). Stored in [`SaslProto::flags`].
pub const SASL_FLAG_BASE64: u16 = 0x0001;

/// Wire token for the LOGIN mechanism (`SASL_MECH_STRING_LOGIN`).
pub const SASL_MECH_STRING_LOGIN: &str = "LOGIN";
/// Wire token for the PLAIN mechanism (`SASL_MECH_STRING_PLAIN`).
pub const SASL_MECH_STRING_PLAIN: &str = "PLAIN";
/// Wire token for the CRAM-MD5 mechanism (`SASL_MECH_STRING_CRAM_MD5`).
pub const SASL_MECH_STRING_CRAM_MD5: &str = "CRAM-MD5";
/// Wire token for the DIGEST-MD5 mechanism (`SASL_MECH_STRING_DIGEST_MD5`).
pub const SASL_MECH_STRING_DIGEST_MD5: &str = "DIGEST-MD5";
/// Wire token for the GSSAPI mechanism (`SASL_MECH_STRING_GSSAPI`).
pub const SASL_MECH_STRING_GSSAPI: &str = "GSSAPI";
/// Wire token for the EXTERNAL mechanism (`SASL_MECH_STRING_EXTERNAL`).
pub const SASL_MECH_STRING_EXTERNAL: &str = "EXTERNAL";
/// Wire token for the NTLM mechanism (`SASL_MECH_STRING_NTLM`).
pub const SASL_MECH_STRING_NTLM: &str = "NTLM";
/// Wire token for the XOAUTH2 mechanism (`SASL_MECH_STRING_XOAUTH2`).
pub const SASL_MECH_STRING_XOAUTH2: &str = "XOAUTH2";
/// Wire token for the OAUTHBEARER mechanism (`SASL_MECH_STRING_OAUTHBEARER`).
pub const SASL_MECH_STRING_OAUTHBEARER: &str = "OAUTHBEARER";
/// Wire token for the SCRAM-SHA-1 mechanism (`SASL_MECH_STRING_SCRAM_SHA_1`).
pub const SASL_MECH_STRING_SCRAM_SHA_1: &str = "SCRAM-SHA-1";
/// Wire token for the SCRAM-SHA-256 mechanism (`SASL_MECH_STRING_SCRAM_SHA_256`).
pub const SASL_MECH_STRING_SCRAM_SHA_256: &str = "SCRAM-SHA-256";

/// The supported-mechanism table (`mechtable` in `lib/curl_sasl.c` L49-66).
///
/// Each entry is `(name, name_len, bit)`. **Order is significant** and matches
/// curl exactly: [`decode_mech`] walks this table top-to-bottom, so a token is
/// matched against the entries in this precise sequence. The `name_len` is the
/// byte length of `name`, kept explicit to mirror the C struct and to make the
/// exact-length match in [`decode_mech`] self-documenting.
static MECHTABLE: &[(&str, usize, u32)] = &[
    (SASL_MECH_STRING_LOGIN, 5, SASL_MECH_LOGIN),
    (SASL_MECH_STRING_PLAIN, 5, SASL_MECH_PLAIN),
    (SASL_MECH_STRING_CRAM_MD5, 8, SASL_MECH_CRAM_MD5),
    (SASL_MECH_STRING_DIGEST_MD5, 10, SASL_MECH_DIGEST_MD5),
    (SASL_MECH_STRING_GSSAPI, 6, SASL_MECH_GSSAPI),
    (SASL_MECH_STRING_EXTERNAL, 8, SASL_MECH_EXTERNAL),
    (SASL_MECH_STRING_NTLM, 4, SASL_MECH_NTLM),
    (SASL_MECH_STRING_XOAUTH2, 7, SASL_MECH_XOAUTH2),
    (SASL_MECH_STRING_OAUTHBEARER, 11, SASL_MECH_OAUTHBEARER),
    (SASL_MECH_STRING_SCRAM_SHA_1, 11, SASL_MECH_SCRAM_SHA_1),
    (SASL_MECH_STRING_SCRAM_SHA_256, 13, SASL_MECH_SCRAM_SHA_256),
];

// ===========================================================================
// Phase B — mechanism decoding & URL `;AUTH=` option parsing
// (← Curl_sasl_decode_mech L81, Curl_sasl_parse_url_auth_option L110)
// ===========================================================================

/// Convert a SASL mechanism name into its bit and matched length.
///
/// Port of `Curl_sasl_decode_mech` (`lib/curl_sasl.c` L81-103). The `name` slice
/// may contain trailing bytes after the mechanism token (as happens when parsing
/// a capability line); the returned length is the number of bytes that belong to
/// the matched mechanism. A token matches when either:
///
/// * `name` is exactly the mechanism string (case-insensitively), or
/// * the mechanism string is a prefix of `name` **and** the following byte is not
///   part of a longer mechanism token — i.e. it is not an uppercase letter, a
///   digit, `-`, or `_` (mirroring the C `!ISUPPER && !ISDIGIT && c != '-' &&
///   c != '_'` guard). This is what prevents `"LOGIN"` from spuriously matching a
///   prefix of some hypothetical longer name.
///
/// Returns `Some((bit, matched_len))` on a match, or `None` if no mechanism
/// matches. Matching is ASCII-case-insensitive, exactly like curl's
/// `curl_strnequal`.
#[must_use]
pub fn decode_mech(name: &str) -> Option<(u32, usize)> {
    let bytes = name.as_bytes();
    let maxlen = bytes.len();

    for &(mech_name, mech_len, bit) in MECHTABLE {
        // C: `maxlen >= mechtable[i].len && curl_strnequal(ptr, name, len)`.
        if maxlen >= mech_len && bytes[..mech_len].eq_ignore_ascii_case(mech_name.as_bytes()) {
            // Exact-length match: unambiguously this mechanism.
            if maxlen == mech_len {
                return Some((bit, mech_len));
            }

            // A longer input matches only if the next byte cannot extend the
            // token (i.e. it is a delimiter, not another mechanism-name byte).
            let c = bytes[mech_len];
            if !c.is_ascii_uppercase() && !c.is_ascii_digit() && c != b'-' && c != b'_' {
                return Some((bit, mech_len));
            }
        }
    }

    None
}

/// Parse a single `;AUTH=<mech>` URL login option into a mechanism bitmask.
///
/// Port of the value-classification core of `Curl_sasl_parse_url_auth_option`
/// (`lib/curl_sasl.c` L110-135). The wildcard `"*"` selects [`SASL_AUTH_DEFAULT`];
/// a recognized mechanism name (that consumes the whole `value`) selects its bit;
/// anything else yields `None` (curl reports `CURLE_URL_MALFORMAT`).
///
/// This is the pure, side-effect-free classifier. The stateful application of the
/// result to a [`Sasl`] handle — including curl's one-shot `resetprefs` clearing
/// of the preferred set on the first `;AUTH=` seen — lives in
/// [`Sasl::set_url_auth_option`].
#[must_use]
pub fn parse_url_auth_option(value: &str) -> Option<u32> {
    if value.is_empty() {
        return None;
    }
    if value == "*" {
        return Some(SASL_AUTH_DEFAULT);
    }
    // The mechanism name must consume the ENTIRE value (C: `mechlen == len`),
    // otherwise it is malformed rather than a prefix match.
    match decode_mech(value) {
        Some((bit, matched)) if matched == value.len() => Some(bit),
        _ => None,
    }
}

// ===========================================================================
// Phase C — SASL state machine states & progress
// (← `saslstate` / `saslprogress` in lib/curl_sasl.h L65-92; the diagnostic
//    `names[]` array in lib/curl_sasl.c L188-208)
// ===========================================================================

/// The SASL negotiation state machine states.
///
/// The variants reproduce curl's `saslstate` enum (`lib/curl_sasl.h` L65-85) in
/// the exact same order. The names emitted by [`SaslState::name`] are the frozen
/// diagnostic contract from curl's `names[]` array (`lib/curl_sasl.c` L188-208):
/// curl logs `SASL %p state change from %s to %s` and `--trace` output depends on
/// these exact strings, so they must never change.
///
/// # The `Gsasl` state
///
/// In curl, `SASL_GSASL` drove SCRAM through the optional external `libgsasl` C
/// library. This rewrite implements SCRAM in pure Rust ([`crate::auth::scram`]),
/// but the state is kept under its original name purely so the trace vocabulary
/// stays identical to curl. See the module-level documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaslState {
    /// Idle — no authentication in progress (`SASL_STOP`).
    Stop,
    /// Sending the PLAIN mechanism response (`SASL_PLAIN`).
    Plain,
    /// Sending the LOGIN username (`SASL_LOGIN`).
    Login,
    /// Sending the LOGIN password (`SASL_LOGIN_PASSWD`).
    LoginPasswd,
    /// Sending the EXTERNAL mechanism response (`SASL_EXTERNAL`).
    External,
    /// Awaiting the CRAM-MD5 challenge (`SASL_CRAMMD5`).
    CramMd5,
    /// Awaiting the DIGEST-MD5 challenge (`SASL_DIGESTMD5`).
    DigestMd5,
    /// Sending the (empty) DIGEST-MD5 acknowledgement (`SASL_DIGESTMD5_RESP`).
    DigestMd5Resp,
    /// Sending the NTLM type-1 message (`SASL_NTLM`).
    Ntlm,
    /// Awaiting and answering the NTLM type-2 message (`SASL_NTLM_TYPE2MSG`).
    NtlmType2Msg,
    /// Sending the initial GSSAPI (Kerberos V5) token (`SASL_GSSAPI`).
    Gssapi,
    /// Exchanging GSSAPI security tokens (`SASL_GSSAPI_TOKEN`).
    GssapiToken,
    /// GSSAPI security-layer negotiation with no further token
    /// (`SASL_GSSAPI_NO_DATA`).
    GssapiNoData,
    /// Sending the OAuth 2.0 bearer authorization message (`SASL_OAUTH2`).
    OAuth2,
    /// Awaiting the optional OAuth 2.0 failure continuation (`SASL_OAUTH2_RESP`).
    OAuth2Resp,
    /// Running the SCRAM exchange (`SASL_GSASL`; routed to [`crate::auth::scram`]).
    Gsasl,
    /// Cancelling the current mechanism to try an alternative (`SASL_CANCEL`).
    Cancel,
    /// Awaiting the final server status for the mechanism (`SASL_FINAL`).
    Final,
}

impl SaslState {
    /// The diagnostic name of the state, exactly matching curl's `names[]` array
    /// (`lib/curl_sasl.c` L188-208).
    ///
    /// These strings appear verbatim in `--trace` output
    /// (`SASL %p state change from %s to %s`) and are therefore a frozen
    /// wire-adjacent contract.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            SaslState::Stop => "STOP",
            SaslState::Plain => "PLAIN",
            SaslState::Login => "LOGIN",
            SaslState::LoginPasswd => "LOGIN_PASSWD",
            SaslState::External => "EXTERNAL",
            SaslState::CramMd5 => "CRAMMD5",
            SaslState::DigestMd5 => "DIGESTMD5",
            SaslState::DigestMd5Resp => "DIGESTMD5_RESP",
            SaslState::Ntlm => "NTLM",
            SaslState::NtlmType2Msg => "NTLM_TYPE2MSG",
            SaslState::Gssapi => "GSSAPI",
            SaslState::GssapiToken => "GSSAPI_TOKEN",
            SaslState::GssapiNoData => "GSSAPI_NO_DATA",
            SaslState::OAuth2 => "OAUTH2",
            SaslState::OAuth2Resp => "OAUTH2_RESP",
            SaslState::Gsasl => "GSASL",
            SaslState::Cancel => "CANCEL",
            SaslState::Final => "FINAL",
        }
    }
}

/// The progress of a SASL exchange, returned by [`Sasl::sasl_start`] and
/// [`Sasl::sasl_continue`].
///
/// Port of curl's `saslprogress` enum (`lib/curl_sasl.h` L88-92):
///
/// * [`SaslProgress::Idle`] (`SASL_IDLE`) — no mechanism could be selected/started
///   (the caller should fall back, e.g. to `LOGIN`/`USER`+`PASS`);
/// * [`SaslProgress::InProgress`] (`SASL_INPROGRESS`) — a mechanism is mid-exchange
///   and more round trips are required;
/// * [`SaslProgress::Done`] (`SASL_DONE`) — the exchange finished successfully.
///
/// A **failed** authentication is reported as `Err(`[`Error::LoginDenied`]`)`
/// rather than an `Ok` variant (curl returns `CURLE_LOGIN_DENIED` while also
/// setting progress to `SASL_DONE`; in Rust the `Err` already conveys the
/// terminal-failure outcome).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaslProgress {
    /// No mechanism was started (`SASL_IDLE`).
    Idle,
    /// A mechanism is mid-exchange (`SASL_INPROGRESS`).
    InProgress,
    /// The exchange completed successfully (`SASL_DONE`).
    Done,
}

// ===========================================================================
// Phase D — the per-protocol hook trait, the credential bundle, and the engine
// (← `struct SASLproto` / `struct SASL` in lib/curl_sasl.h L94-128)
// ===========================================================================

/// Per-protocol SASL hooks, implemented by IMAP / POP3 / SMTP.
///
/// Port of the C `struct SASLproto` (`lib/curl_sasl.h` L94-115), whose function
/// pointers and data fields become trait methods here. The concrete protocol
/// handlers (in `crate::protocols`) implement this trait; **this module only
/// defines and drives it** — it never implements it. The SASL engine calls
/// [`send_auth`](SaslProto::send_auth) / [`cont_auth`](SaslProto::cont_auth) /
/// [`cancel_auth`](SaslProto::cancel_auth) to transmit, and
/// [`get_message`](SaslProto::get_message) to read the server's SASL data line.
///
/// The data-field accessors ([`service`](SaslProto::service) ..
/// [`flags`](SaslProto::flags)) correspond one-to-one to the trailing fields of
/// the C struct.
pub trait SaslProto {
    /// The service name, e.g. `"imap"`, `"pop3"`, `"smtp"` (C `service`). Used to
    /// build the GSSAPI/DIGEST-MD5 service principal name.
    fn service(&self) -> &str;

    /// Maximum initial-response + mechanism length, or `0` for "no maximum"
    /// (C `maxirlen`). This is `0` for non-base64 protocols; when non-zero, an
    /// initial response that would push `mech.len() + resp.len()` past this limit
    /// is dropped and sent in a follow-up round instead.
    fn max_ir_len(&self) -> usize;

    /// The protocol status code that signals "continuation expected"
    /// (C `contcode`).
    fn cont_code(&self) -> i32;

    /// The protocol status code that signals "authentication succeeded"
    /// (C `finalcode`).
    fn final_code(&self) -> i32;

    /// Mechanisms enabled by default for this protocol (C `defmechs`).
    fn def_mechs(&self) -> u32;

    /// Configuration flags (C `flags`); currently only [`SASL_FLAG_BASE64`].
    fn flags(&self) -> u16;

    /// Send the `AUTH <mech>` command, optionally with a base64 initial response
    /// (C `sendauth`). `initial_resp` is `None` when no IR is included and
    /// `Some(bytes)` for the already-encoded IR to append.
    fn send_auth(&mut self, mech: &str, initial_resp: Option<&[u8]>) -> Result<()>;

    /// Send a continuation response line (C `contauth`). `resp` is the
    /// already-built message bytes (base64 / `"="` / empty as appropriate).
    fn cont_auth(&mut self, mech: &str, resp: &[u8]) -> Result<()>;

    /// Cancel the in-flight authentication (C `cancelauth`), typically by sending
    /// a `"*"` line so the server aborts the mechanism.
    fn cancel_auth(&mut self, mech: &str) -> Result<()>;

    /// Fetch the server's SASL message line (C `getmessage`). For base64
    /// protocols this returns the still-encoded token bytes; the engine performs
    /// the base64 decode (with the `"="`/empty special-case) itself.
    fn get_message(&mut self) -> Result<Vec<u8>>;
}

/// The credentials and per-transfer configuration the SASL engine reads.
///
/// In curl these values are scattered across `struct connectdata`
/// (`conn->user`, `conn->passwd`, `conn->sasl_authzid`, current host/port) and
/// `struct Curl_easy` (`data->set.str[STRING_BEARER]`,
/// `data->set.str[STRING_SERVICE_NAME]`, `data->set.sasl_ir`). Modeling them as a
/// single owned bundle keeps the SASL engine self-contained and unit-testable and
/// avoids a dependency on the (not-yet-ported) connection layer. The consuming
/// protocol handler populates this from the live transfer state before each call.
#[derive(Debug, Clone, Default)]
pub struct SaslCredentials {
    /// The login user name (`conn->user`).
    pub user: String,
    /// The login password (`conn->passwd`).
    pub passwd: String,
    /// The SASL authorization identity, if any (`conn->sasl_authzid`).
    pub authzid: Option<String>,
    /// The OAuth 2.0 bearer token, if any (`data->set.str[STRING_BEARER]`).
    pub bearer: Option<String>,
    /// A service-name override, if any (`data->set.str[STRING_SERVICE_NAME]`);
    /// when `None`, [`SaslProto::service`] is used.
    pub service_name: Option<String>,
    /// The current connection host name (used for OAUTHBEARER `host=` and the
    /// GSSAPI/DIGEST service principal).
    pub host: String,
    /// The current connection port (used for the OAUTHBEARER `port=` field).
    pub port: i64,
    /// Whether the application allows an initial SASL response
    /// (`data->set.sasl_ir`).
    pub sasl_ir: bool,
}

/// The internal representation of an outgoing SASL response before it is written.
///
/// This captures the three-way distinction curl draws inside `build_message`
/// (`lib/curl_sasl.c` L247-269) between an absent response, an empty response,
/// and real bytes — plus a fourth case for the pre-encoded NTLM path.
enum Response {
    /// No response at all (C: a NULL `bufref`). Under [`SASL_FLAG_BASE64`] curl
    /// still emits an empty line; either way the transmitted bytes are empty.
    Absent,
    /// Raw response bytes that the engine base64-encodes when
    /// [`SASL_FLAG_BASE64`] is set. An **empty** `Raw` is curl's "explicit empty
    /// response", transmitted as `"="`.
    Raw(Vec<u8>),
    /// A response that is already in its final wire form and must pass through
    /// [`build_message`] unchanged. Used for NTLM, whose helpers in
    /// [`crate::auth::ntlm`] perform their own base64 encoding.
    Encoded(Vec<u8>),
}

impl Response {
    /// Whether a response is present (C's `Curl_bufref_ptr(&resp) != NULL`
    /// check). [`Response::Absent`] is the only "not present" case; an empty
    /// [`Response::Raw`] IS present (it becomes `"="`).
    fn is_present(&self) -> bool {
        !matches!(self, Response::Absent)
    }
}

/// The SASL negotiation engine (port of C `struct SASL`, `lib/curl_sasl.h`
/// L117-128).
///
/// One instance drives a single SASL exchange for a mail-protocol connection. It
/// owns the current [`SaslState`], the negotiated/preferred mechanism masks, and
/// the per-mechanism scratch state (NTLM handshake data, the SCRAM client, and —
/// when the `gssapi` feature is enabled — the Kerberos context). curl kept the
/// NTLM/Kerberos scratch on `struct connectdata`; here it lives inside the engine
/// so a `Sasl` value is fully self-contained.
#[derive(Debug)]
pub struct Sasl {
    /// Current machine state (C `state`).
    state: SaslState,
    /// Mechanisms the server advertised as supported (C `authmechs`).
    authmechs: u32,
    /// Mechanisms preferred/permitted by the application (C `prefmech`).
    prefmech: u32,
    /// The mechanism actually chosen for this exchange (C `authused`).
    authused: u32,
    /// One-shot flag: clear `prefmech` on the first `;AUTH=` URL option seen
    /// (C `resetprefs`).
    resetprefs: bool,
    /// Whether GSSAPI mutual authentication is enabled (C `mutual_auth`).
    mutual_auth: bool,
    /// Whether the protocol always supports an initial response (C `force_ir`).
    force_ir: bool,
    /// The current mechanism's wire token (C `curmech`), or `None` before
    /// selection.
    curmech: Option<&'static str>,
    /// NTLM handshake scratch state (curl's `conn`-held `ntlmdata`).
    ntlm: NtlmData,
    /// The SCRAM client, created lazily when a SCRAM mechanism is selected.
    scram: Option<ScramClient>,
    /// Kerberos V5 context scratch state (curl's `conn`-held `kerberos5data`);
    /// an empty marker in the default (non-`gssapi`) build.
    krb5: Kerberos5Data,
}

// ===========================================================================
// Phase E — initialization, accessors, capability check, mechanism selection
// (← Curl_sasl_init L142, Curl_sasl_can_authenticate L276, sasl_choose_* L300-518)
// ===========================================================================

/// The result of the mechanism-selection pass — the local counterpart of curl's
/// stack-allocated `struct sasl_ctx` (`lib/curl_sasl.c` L289-298).
///
/// `mech`/`state1`/`state2`/`resp` describe the selected mechanism and its
/// initial response; `result` carries a deferred error from building the initial
/// response (curl stashes this in `sctx.result`).
struct Choice {
    mech: Option<&'static str>,
    state1: SaslState,
    state2: SaslState,
    resp: Response,
    result: Result<()>,
}

impl Default for Choice {
    fn default() -> Self {
        // Mirrors the C initialization: state1 = SASL_STOP, state2 = SASL_FINAL.
        Choice {
            mech: None,
            state1: SaslState::Stop,
            state2: SaslState::Final,
            resp: Response::Absent,
            result: Ok(()),
        }
    }
}

impl Sasl {
    /// Initialize a SASL engine for a protocol (port of `Curl_sasl_init`,
    /// `lib/curl_sasl.c` L142-176).
    ///
    /// `def_mechs` is the protocol's default mechanism set ([`SaslProto::def_mechs`],
    /// curl's `params->defmechs`) and `httpauth` is the application's
    /// `CURLAUTH_*` selection (curl's `data->set.httpauth`). When `httpauth` names
    /// anything other than exactly [`CURLAUTH_BASIC`], the preferred SASL set is
    /// derived from it using curl's exact `CURLAUTH_* -> SASL_MECH_*` mapping;
    /// otherwise the protocol default is kept.
    #[must_use]
    pub fn init(def_mechs: u32, httpauth: u32) -> Self {
        let mut prefmech = def_mechs;

        // C: `if(auth != CURLAUTH_BASIC)` — only remap when the app requested a
        // specific, non-default auth set.
        if httpauth != CURLAUTH_BASIC {
            let mut mechs = SASL_AUTH_NONE;
            if httpauth & CURLAUTH_BASIC != 0 {
                mechs |= SASL_MECH_PLAIN | SASL_MECH_LOGIN;
            }
            if httpauth & CURLAUTH_DIGEST != 0 {
                mechs |= SASL_MECH_DIGEST_MD5;
            }
            if httpauth & CURLAUTH_NTLM != 0 {
                mechs |= SASL_MECH_NTLM;
            }
            if httpauth & CURLAUTH_BEARER != 0 {
                mechs |= SASL_MECH_OAUTHBEARER | SASL_MECH_XOAUTH2;
            }
            // CURLAUTH_GSSAPI aliases CURLAUTH_NEGOTIATE.
            if httpauth & CURLAUTH_GSSAPI != 0 {
                mechs |= SASL_MECH_GSSAPI;
            }
            if mechs != SASL_AUTH_NONE {
                prefmech = mechs;
            }
        }

        Sasl {
            state: SaslState::Stop,
            authmechs: SASL_AUTH_NONE,
            prefmech,
            authused: SASL_AUTH_NONE,
            resetprefs: true,
            mutual_auth: false,
            force_ir: false,
            curmech: None,
            ntlm: NtlmData::default(),
            scram: None,
            krb5: Kerberos5Data::default(),
        }
    }

    /// The current machine state.
    #[must_use]
    pub fn state(&self) -> SaslState {
        self.state
    }

    /// The mechanism actually chosen for this exchange (a `SASL_MECH_*` bit), or
    /// [`SASL_AUTH_NONE`] before selection (C `authused`).
    #[must_use]
    pub fn authused(&self) -> u32 {
        self.authused
    }

    /// The mechanisms the server advertised (C `authmechs`).
    #[must_use]
    pub fn authmechs(&self) -> u32 {
        self.authmechs
    }

    /// The mechanisms the application prefers/permits (C `prefmech`).
    #[must_use]
    pub fn prefmech(&self) -> u32 {
        self.prefmech
    }

    /// The current mechanism's wire token, or `None` before selection
    /// (C `curmech`).
    #[must_use]
    pub fn curmech(&self) -> Option<&'static str> {
        self.curmech
    }

    /// Replace the set of server-advertised mechanisms (C `authmechs`).
    pub fn set_authmechs(&mut self, mechs: u32) {
        self.authmechs = mechs;
    }

    /// OR an additional server-advertised mechanism bit into [`authmechs`](Self::authmechs).
    ///
    /// The protocol capability parser calls this for each mechanism token the
    /// server lists (after decoding it with [`decode_mech`]).
    pub fn add_authmech(&mut self, bit: u32) {
        self.authmechs |= bit;
    }

    /// Enable or disable GSSAPI mutual authentication (C `mutual_auth`).
    pub fn set_mutual_auth(&mut self, enabled: bool) {
        self.mutual_auth = enabled;
    }

    /// Apply a single `;AUTH=<mech>` URL login option to this engine.
    ///
    /// Port of `Curl_sasl_parse_url_auth_option` (`lib/curl_sasl.c` L110-135)
    /// including its stateful behavior: the first option seen after
    /// initialization clears the preferred set (the one-shot `resetprefs` latch),
    /// so subsequent options build the set from scratch. `"*"` resets the set to
    /// [`SASL_AUTH_DEFAULT`]; a recognized mechanism ORs in its bit.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Url`] (curl's `CURLE_URL_MALFORMAT`) for an empty value or
    /// an unrecognized mechanism token — matching curl.
    pub fn set_url_auth_option(&mut self, value: &str) -> Result<()> {
        if value.is_empty() {
            return Err(Error::Url("empty SASL AUTH option".into()));
        }

        // One-shot: the first `;AUTH=` clears the inherited preferences.
        if self.resetprefs {
            self.resetprefs = false;
            self.prefmech = SASL_AUTH_NONE;
        }

        match parse_url_auth_option(value) {
            Some(bits) if value == "*" => {
                // "*" assigns the default set outright (C sets, not ORs).
                self.prefmech = bits;
                Ok(())
            }
            Some(bit) => {
                self.prefmech |= bit;
                Ok(())
            }
            None => Err(Error::Url(format!("unknown SASL AUTH mechanism: {value}"))),
        }
    }

    /// Check whether authentication is possible with the current credentials and
    /// negotiated mechanisms (port of `Curl_sasl_can_authenticate`,
    /// `lib/curl_sasl.c` L276-287).
    ///
    /// Returns `true` when a username is present, or when EXTERNAL is both offered
    /// and preferred (EXTERNAL can authenticate with no username/password).
    #[must_use]
    pub fn can_authenticate(&self, creds: &SaslCredentials) -> bool {
        if !creds.user.is_empty() {
            return true;
        }
        (self.authmechs & self.prefmech & SASL_MECH_EXTERNAL) != 0
    }

    /// The single, canonical state-transition point (port of `sasl_state`,
    /// `lib/curl_sasl.c` L183-218).
    ///
    /// Emits curl's `SASL %p state change from %s to %s` diagnostic (via
    /// `tracing`, so `--trace`/`--verbose` output matches) whenever the state
    /// actually changes, then records the new state.
    fn set_state(&mut self, new: SaslState) {
        if self.state != new {
            tracing::trace!(
                target: "curl::sasl",
                "SASL state change from {} to {}",
                self.state.name(),
                new.name()
            );
        }
        self.state = new;
    }
}

// ---------------------------------------------------------------------------
// Mechanism-selection helpers (← sasl_choose_*, lib/curl_sasl.c L300-518).
//
// Each returns `true` once it has claimed the exchange (setting `ch.mech` and the
// target states, and `self.authused`), or `false` to let the next candidate try.
// They are invoked from `sasl_start` in strict decreasing-security order, exactly
// matching curl's `||` chain, so the same mechanism is chosen on the wire.
//
// `want_ir` is curl's `sasl->force_ir || data->set.sasl_ir`: only then is an
// initial response produced here.
// ---------------------------------------------------------------------------

impl Sasl {
    /// EXTERNAL: chosen when enabled and no password is set (← `sasl_choose_external`).
    fn choose_external(
        &mut self,
        ch: &mut Choice,
        creds: &SaslCredentials,
        enabledmechs: u32,
        want_ir: bool,
    ) -> bool {
        if (enabledmechs & SASL_MECH_EXTERNAL) != 0 && creds.passwd.is_empty() {
            ch.mech = Some(SASL_MECH_STRING_EXTERNAL);
            ch.state1 = SaslState::External;
            self.authused = SASL_MECH_EXTERNAL;
            if want_ir {
                ch.resp = Response::Raw(basic::create_external_message(&creds.user));
            }
            return true;
        }
        false
    }

    /// GSSAPI (Kerberos V5): chosen when enabled, GSSAPI is built in, and the
    /// username carries a domain (← `sasl_choose_krb5`, gated on `USE_KERBEROS5`).
    ///
    /// Selection is skipped in the default build because
    /// [`kerberos::is_gssapi_supported`] is `false` there; the mechanism is thus
    /// simply never offered (matching curl's `#ifdef USE_KERBEROS5`).
    fn choose_krb5(
        &mut self,
        ch: &mut Choice,
        creds: &SaslCredentials,
        enabledmechs: u32,
        want_ir: bool,
        service: &str,
    ) -> bool {
        if (enabledmechs & SASL_MECH_GSSAPI) != 0
            && kerberos::is_gssapi_supported()
            && user_contains_domain(Some(&creds.user))
        {
            self.mutual_auth = false;
            ch.mech = Some(SASL_MECH_STRING_GSSAPI);
            ch.state1 = SaslState::Gssapi;
            ch.state2 = SaslState::GssapiToken;
            self.authused = SASL_MECH_GSSAPI;

            if want_ir {
                match kerberos::create_gssapi_user_message(
                    &mut self.krb5,
                    service,
                    &creds.host,
                    self.mutual_auth,
                    None,
                ) {
                    Ok(Some(token)) => ch.resp = Response::Raw(token),
                    Ok(None) => {}
                    Err(e) => ch.result = Err(e),
                }
            }
            return true;
        }
        false
    }

    /// SCRAM-SHA-256 / SCRAM-SHA-1: chosen when either is enabled, preferring
    /// SHA-256 (← `sasl_choose_gsasl`, L346-384). The C `SASL_GSASL` state is
    /// kept as a diagnostic name but the exchange is driven by the pure-Rust
    /// [`ScramClient`].
    fn choose_scram(
        &mut self,
        ch: &mut Choice,
        creds: &SaslCredentials,
        enabledmechs: u32,
        want_ir: bool,
    ) -> bool {
        if (enabledmechs & (SASL_MECH_SCRAM_SHA_256 | SASL_MECH_SCRAM_SHA_1)) != 0 {
            // Prefer SHA-256 over SHA-1 (C L359-369).
            let (mech, hash, bit) = if (enabledmechs & SASL_MECH_SCRAM_SHA_256) != 0 {
                (
                    SASL_MECH_STRING_SCRAM_SHA_256,
                    ScramHash::Sha256,
                    SASL_MECH_SCRAM_SHA_256,
                )
            } else {
                (
                    SASL_MECH_STRING_SCRAM_SHA_1,
                    ScramHash::Sha1,
                    SASL_MECH_SCRAM_SHA_1,
                )
            };

            ch.mech = Some(mech);
            self.authused = bit;
            // Both target states are GSASL: the exchange loops in GSASL until the
            // SCRAM client emits an empty response (C L375-376).
            ch.state1 = SaslState::Gsasl;
            ch.state2 = SaslState::Gsasl;

            let mut client = ScramClient::new(hash, creds.user.clone(), creds.passwd.clone());
            if want_ir {
                // curl produces the client-first message via a step over an empty
                // "null" challenge (C L379-380).
                match client.step(&[]) {
                    Ok(resp) => ch.resp = Response::Raw(resp),
                    Err(e) => ch.result = Err(e),
                }
            }
            self.scram = Some(client);
            return true;
        }
        false
    }

    /// DIGEST-MD5 (preferred) then CRAM-MD5 (← `sasl_choose_digest`, L389-406).
    /// Neither produces an initial response: both require the server challenge
    /// first. DIGEST-MD5 is always available (pure-Rust crypto).
    fn choose_digest(&mut self, ch: &mut Choice, enabledmechs: u32) -> bool {
        if (enabledmechs & SASL_MECH_DIGEST_MD5) != 0 {
            ch.mech = Some(SASL_MECH_STRING_DIGEST_MD5);
            ch.state1 = SaslState::DigestMd5;
            self.authused = SASL_MECH_DIGEST_MD5;
            return true;
        }
        if (enabledmechs & SASL_MECH_CRAM_MD5) != 0 {
            ch.mech = Some(SASL_MECH_STRING_CRAM_MD5);
            ch.state1 = SaslState::CramMd5;
            self.authused = SASL_MECH_CRAM_MD5;
            return true;
        }
        false
    }

    /// NTLM: chosen when enabled and supported (← `sasl_choose_ntlm`, gated on
    /// `USE_NTLM`; always supported in the pure-Rust build).
    ///
    /// The type-1 message is produced by [`ntlm::create_type1_message`], which
    /// returns an already-base64 string; it is wrapped as [`Response::Encoded`]
    /// so the engine does not double-encode it.
    fn choose_ntlm(&mut self, ch: &mut Choice, enabledmechs: u32, want_ir: bool) -> bool {
        if (enabledmechs & SASL_MECH_NTLM) != 0 && ntlm::is_ntlm_supported() {
            ch.mech = Some(SASL_MECH_STRING_NTLM);
            ch.state1 = SaslState::Ntlm;
            ch.state2 = SaslState::NtlmType2Msg;
            self.authused = SASL_MECH_NTLM;

            if want_ir {
                match ntlm::create_type1_message(&mut self.ntlm) {
                    Ok(b64) => ch.resp = Response::Encoded(b64.into_bytes()),
                    Err(e) => ch.result = Err(e),
                }
            }
            return true;
        }
        false
    }

    /// OAUTHBEARER: chosen when a bearer token is present and the mechanism is
    /// enabled (← `sasl_choose_oauth`, L442-466).
    fn choose_oauth(
        &mut self,
        ch: &mut Choice,
        creds: &SaslCredentials,
        enabledmechs: u32,
        want_ir: bool,
    ) -> bool {
        if let Some(bearer) = creds.bearer.as_deref() {
            if (enabledmechs & SASL_MECH_OAUTHBEARER) != 0 {
                ch.mech = Some(SASL_MECH_STRING_OAUTHBEARER);
                ch.state1 = SaslState::OAuth2;
                ch.state2 = SaslState::OAuth2Resp;
                self.authused = SASL_MECH_OAUTHBEARER;
                if want_ir {
                    ch.resp = Response::Raw(bearer::create_oauth_bearer_message(
                        &creds.user,
                        &creds.host,
                        creds.port,
                        bearer,
                    ));
                }
                return true;
            }
        }
        false
    }

    /// XOAUTH2: chosen when a bearer token is present and the mechanism is enabled
    /// (← `sasl_choose_oauth2`, L468-486).
    fn choose_oauth2(
        &mut self,
        ch: &mut Choice,
        creds: &SaslCredentials,
        enabledmechs: u32,
        want_ir: bool,
    ) -> bool {
        if let Some(bearer) = creds.bearer.as_deref() {
            if (enabledmechs & SASL_MECH_XOAUTH2) != 0 {
                ch.mech = Some(SASL_MECH_STRING_XOAUTH2);
                ch.state1 = SaslState::OAuth2;
                self.authused = SASL_MECH_XOAUTH2;
                if want_ir {
                    ch.resp =
                        Response::Raw(bearer::create_xoauth_bearer_message(&creds.user, bearer));
                }
                return true;
            }
        }
        false
    }

    /// PLAIN (← `sasl_choose_plain`, L488-503).
    fn choose_plain(
        &mut self,
        ch: &mut Choice,
        creds: &SaslCredentials,
        enabledmechs: u32,
        want_ir: bool,
    ) -> bool {
        if (enabledmechs & SASL_MECH_PLAIN) != 0 {
            ch.mech = Some(SASL_MECH_STRING_PLAIN);
            ch.state1 = SaslState::Plain;
            self.authused = SASL_MECH_PLAIN;
            if want_ir {
                match basic::create_plain_message(
                    creds.authzid.as_deref(),
                    &creds.user,
                    &creds.passwd,
                ) {
                    Ok(resp) => ch.resp = Response::Raw(resp),
                    Err(e) => ch.result = Err(e),
                }
            }
            return true;
        }
        false
    }

    /// LOGIN (← `sasl_choose_login`, L505-518). The username is the initial
    /// response; the password follows in the `LOGIN_PASSWD` state.
    fn choose_login(
        &mut self,
        ch: &mut Choice,
        creds: &SaslCredentials,
        enabledmechs: u32,
        want_ir: bool,
    ) -> bool {
        if (enabledmechs & SASL_MECH_LOGIN) != 0 {
            ch.mech = Some(SASL_MECH_STRING_LOGIN);
            ch.state1 = SaslState::Login;
            ch.state2 = SaslState::LoginPasswd;
            self.authused = SASL_MECH_LOGIN;
            if want_ir {
                ch.resp = Response::Raw(basic::create_login_message(&creds.user));
            }
            return true;
        }
        false
    }
}

// ===========================================================================
// Phase F / H — the outgoing/ incoming message codecs, start, and continue
// (← build_message L247-269, get_server_message L221-244,
//    Curl_sasl_start L525-587, Curl_sasl_continue L594-836)
// ===========================================================================

/// Encode an outgoing SASL response to its final wire bytes (port of
/// `build_message`, `lib/curl_sasl.c` L247-269).
///
/// When [`SASL_FLAG_BASE64`] is set: an [`Response::Absent`] message becomes an
/// empty line, an empty [`Response::Raw`] becomes the explicit-empty marker
/// `"="`, and any other [`Response::Raw`] is base64-encoded. A
/// [`Response::Encoded`] value (NTLM, which base64-encodes in its own helper) is
/// always passed through verbatim so it is never double-encoded. Without the flag,
/// raw bytes are emitted as-is.
fn build_message(flags: u16, resp: &Response) -> Vec<u8> {
    match resp {
        // C: NULL bufref → "" under base64; nothing otherwise. Either way, the
        // transmitted bytes are empty.
        Response::Absent => Vec::new(),
        // Already in final form (NTLM helpers do their own base64).
        Response::Encoded(v) => v.clone(),
        Response::Raw(v) => {
            if flags & SASL_FLAG_BASE64 != 0 {
                if v.is_empty() {
                    // Explicit empty response (C L255-256).
                    b"=".to_vec()
                } else {
                    BASE64.encode(v).into_bytes()
                }
            } else {
                v.clone()
            }
        }
    }
}

/// Fetch and decode the server's SASL message (port of `get_server_message`,
/// `lib/curl_sasl.c` L221-244).
///
/// The protocol's [`SaslProto::get_message`] hook returns the raw response line.
/// Under [`SASL_FLAG_BASE64`], an empty line or one that begins with `'='` is
/// treated as an **empty** message (curl's `!*serverdata || *serverdata == '='`
/// special-case), and any other line is base64-decoded. A decode failure maps to
/// [`Error::BadContentEncoding`] (curl's `CURLE_BAD_CONTENT_ENCODING`).
fn get_server_message<P: SaslProto>(proto: &mut P, flags: u16) -> Result<Vec<u8>> {
    let raw = proto.get_message()?;
    if flags & SASL_FLAG_BASE64 != 0 {
        // Empty, or begins with '=' → empty message (C L232-233).
        if raw.is_empty() || raw[0] == b'=' {
            Ok(Vec::new())
        } else {
            BASE64
                .decode(&raw)
                .map_err(|_| Error::bad_content_encoding("SASL: invalid base64 in server message"))
        }
    } else {
        Ok(raw)
    }
}

impl Sasl {
    /// Select a mechanism and begin the SASL exchange (port of `Curl_sasl_start`,
    /// `lib/curl_sasl.c` L525-587).
    ///
    /// The strongest mechanism that is both server-offered and app-permitted is
    /// chosen (see the `choose_*` chain). When the protocol supports an initial
    /// response (`force_ir` or [`SaslCredentials::sasl_ir`]) and one fits within
    /// [`SaslProto::max_ir_len`], it is produced and sent with the `AUTH` command;
    /// otherwise the command is sent without an IR and the first server
    /// continuation drives the next step.
    ///
    /// # Returns
    ///
    /// * [`SaslProgress::Idle`] — no mechanism could be selected (fall back to
    ///   non-SASL login);
    /// * [`SaslProgress::InProgress`] — a mechanism was started.
    ///
    /// # Errors
    ///
    /// Propagates an error from building the initial response or from the
    /// protocol's [`SaslProto::send_auth`] hook.
    pub fn sasl_start<P: SaslProto>(
        &mut self,
        proto: &mut P,
        creds: &SaslCredentials,
        force_ir: bool,
    ) -> Result<SaslProgress> {
        self.force_ir = force_ir; // Latch for future use (C L530).
        self.authused = SASL_AUTH_NONE; // No mechanism used yet (C L531).

        let enabledmechs = self.authmechs & self.prefmech;
        let want_ir = self.force_ir || creds.sasl_ir;
        // Resolve the service name once (owned), releasing the borrow of `proto`
        // before the mutable `choose_*` / `send_auth` calls below.
        let service = creds
            .service_name
            .as_deref()
            .unwrap_or_else(|| proto.service())
            .to_string();

        let mut ch = Choice::default();

        // Decreasing-security precedence, exactly matching curl's `||` chain
        // (C L544-560). `choose_krb5` is only effective when GSSAPI is built in.
        let _selected = self.choose_external(&mut ch, creds, enabledmechs, want_ir)
            || self.choose_krb5(&mut ch, creds, enabledmechs, want_ir, &service)
            || self.choose_scram(&mut ch, creds, enabledmechs, want_ir)
            || self.choose_digest(&mut ch, enabledmechs)
            || self.choose_ntlm(&mut ch, enabledmechs, want_ir)
            || self.choose_oauth(&mut ch, creds, enabledmechs, want_ir)
            || self.choose_oauth2(&mut ch, creds, enabledmechs, want_ir)
            || self.choose_plain(&mut ch, creds, enabledmechs, want_ir)
            || self.choose_login(&mut ch, creds, enabledmechs, want_ir);

        // Surface a deferred initial-response build error (C `sctx.result`).
        ch.result?;

        // No mechanism selected: remain idle so the caller can fall back.
        let Some(mech) = ch.mech else {
            return Ok(SaslProgress::Idle);
        };

        self.curmech = Some(mech);

        // Build and size-check the initial response (C L565-582).
        let mut ir_to_send: Option<Vec<u8>> = None;
        let mut go_state2 = false;
        if ch.resp.is_present() {
            let built = build_message(proto.flags(), &ch.resp);
            let maxirlen = proto.max_ir_len();
            // Drop the IR if `mech + resp` would exceed the protocol's max
            // (C L570-573): send without it and start from state1.
            if maxirlen != 0 && mech.len() + built.len() > maxirlen {
                ir_to_send = None;
                go_state2 = false;
            } else {
                ir_to_send = Some(built);
                go_state2 = true;
            }
        }

        proto.send_auth(mech, ir_to_send.as_deref())?;

        // With an IR we jump straight to state2; without one we await the first
        // continuation in state1 (C L580-581).
        let next = if go_state2 { ch.state2 } else { ch.state1 };
        self.set_state(next);
        Ok(SaslProgress::InProgress)
    }

    /// Report why authentication is blocked, emitting curl's diagnostics (port of
    /// `Curl_sasl_is_blocked`, `lib/curl_sasl.c` L871-932).
    ///
    /// Always returns [`Error::LoginDenied`] (curl's `CURLE_LOGIN_DENIED`). The
    /// diagnostic messages are emitted via `tracing` so `--verbose`/`--trace`
    /// output matches curl's `infof` lines.
    #[must_use]
    pub fn is_blocked(&self, creds: &SaslCredentials) -> Error {
        let enabledmechs = self.authmechs & self.prefmech;

        if self.authmechs == 0 {
            tracing::info!(
                target: "curl::sasl",
                "SASL: no auth mechanism was offered or recognized"
            );
        } else if enabledmechs == 0 {
            tracing::info!(
                target: "curl::sasl",
                "SASL: no overlap between offered and configured auth mechanisms"
            );
        } else {
            tracing::info!(
                target: "curl::sasl",
                "SASL: no auth mechanism offered could be selected"
            );
            if (enabledmechs & SASL_MECH_EXTERNAL) != 0 && !creds.passwd.is_empty() {
                tracing::info!(
                    target: "curl::sasl",
                    "SASL: auth EXTERNAL not chosen with password"
                );
            }
        }

        Error::LoginDenied
    }
}

impl Sasl {
    /// Advance the SASL exchange by one server round trip (port of
    /// `Curl_sasl_continue`, `lib/curl_sasl.c` L594-836).
    ///
    /// `code` is the protocol status code of the server's latest response. The
    /// method reads the server's SASL data via [`SaslProto::get_message`],
    /// computes the next client response for the current [`SaslState`], and sends
    /// it via [`SaslProto::cont_auth`] (or cancels via
    /// [`SaslProto::cancel_auth`]). The state transitions reproduce curl exactly.
    ///
    /// # Returns
    ///
    /// * [`SaslProgress::InProgress`] — more round trips are required;
    /// * [`SaslProgress::Done`] — authentication completed successfully.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LoginDenied`] when the server rejects the credentials (a
    /// non-continuation status where a continuation was required, or a failed
    /// final status), and propagates mechanism/transport errors otherwise. Any
    /// `Err` is terminal: the engine has returned to [`SaslState::Stop`].
    #[allow(clippy::too_many_lines)] // Faithful 1:1 port of curl's state switch.
    pub fn sasl_continue<P: SaslProto>(
        &mut self,
        proto: &mut P,
        creds: &SaslCredentials,
        code: i32,
    ) -> Result<SaslProgress> {
        let flags = proto.flags();
        let cont_code = proto.cont_code();
        let final_code = proto.final_code();
        // Owned so the borrow of `proto` is released before the mutable hooks.
        let service = creds
            .service_name
            .as_deref()
            .unwrap_or_else(|| proto.service())
            .to_string();

        // FINAL: the server's final status decides success/failure (C L617-623).
        if self.state == SaslState::Final {
            self.set_state(SaslState::Stop);
            if code != final_code {
                return Err(Error::LoginDenied);
            }
            return Ok(SaslProgress::Done);
        }

        // A non-continuation code outside CANCEL / OAUTH2_RESP means the exchange
        // failed (C L625-630). OAUTH2_RESP inspects the code itself below.
        if self.state != SaslState::Cancel
            && self.state != SaslState::OAuth2Resp
            && code != cont_code
        {
            self.set_state(SaslState::Stop);
            return Err(Error::LoginDenied);
        }

        // Per-state response and target state (C `newstate = SASL_FINAL` default).
        let mut newstate = SaslState::Final;
        let mut resp = Response::Absent;
        let mut result: Result<()> = Ok(());

        match self.state {
            SaslState::Stop => {
                // Nothing to do; already done (C L633-635).
                return Ok(SaslProgress::Done);
            }
            SaslState::Plain => {
                match basic::create_plain_message(
                    creds.authzid.as_deref(),
                    &creds.user,
                    &creds.passwd,
                ) {
                    Ok(v) => resp = Response::Raw(v),
                    Err(e) => result = Err(e),
                }
            }
            SaslState::Login => {
                resp = Response::Raw(basic::create_login_message(&creds.user));
                newstate = SaslState::LoginPasswd;
            }
            SaslState::LoginPasswd => {
                resp = Response::Raw(basic::create_login_message(&creds.passwd));
            }
            SaslState::External => {
                resp = Response::Raw(basic::create_external_message(&creds.user));
            }
            SaslState::Gsasl => {
                // SCRAM step (C SASL_GSASL, L651-660): feed the server message to
                // the pure-Rust SCRAM client; a non-empty reply loops in GSASL.
                match get_server_message(proto, flags) {
                    Ok(serverdata) => match self.scram.as_mut() {
                        Some(client) => match client.step(&serverdata) {
                            Ok(v) => {
                                let empty = v.is_empty();
                                resp = Response::Raw(v);
                                if !empty {
                                    newstate = SaslState::Gsasl;
                                }
                            }
                            Err(e) => result = Err(e),
                        },
                        // curl: `!gsasl ? CURLE_OUT_OF_MEMORY`. Reaching GSASL
                        // without a SCRAM client is an internal invariant break.
                        None => result = Err(Error::OutOfMemory),
                    },
                    Err(e) => result = Err(e),
                }
            }
            SaslState::CramMd5 => {
                // C L663-668: HMAC-MD5 over the server challenge.
                match get_server_message(proto, flags) {
                    Ok(serverdata) => {
                        resp = Response::Raw(create_cram_md5_message(
                            &serverdata,
                            &creds.user,
                            &creds.passwd,
                        ));
                    }
                    Err(e) => result = Err(e),
                }
            }
            SaslState::DigestMd5 => {
                // C L669-677.
                match get_server_message(proto, flags) {
                    Ok(serverdata) => {
                        match digest::create_digest_md5_message(
                            &serverdata,
                            &creds.user,
                            &creds.passwd,
                            &service,
                            &creds.host,
                        ) {
                            Ok(v) => {
                                resp = Response::Raw(v);
                                // Under base64 protocols, an extra empty response
                                // round follows (C L675-676).
                                if flags & SASL_FLAG_BASE64 != 0 {
                                    newstate = SaslState::DigestMd5Resp;
                                }
                            }
                            Err(e) => result = Err(e),
                        }
                    }
                    Err(e) => result = Err(e),
                }
            }
            SaslState::DigestMd5Resp => {
                // Keep the response absent to emit an empty line (C L678-680).
            }
            SaslState::Ntlm => {
                // Type-1 (C L684-694). ntlm.rs returns already-base64 text, so wrap
                // as Encoded to bypass the engine's base64 step.
                match ntlm::create_type1_message(&mut self.ntlm) {
                    Ok(b64) => resp = Response::Encoded(b64.into_bytes()),
                    Err(e) => result = Err(e),
                }
                newstate = SaslState::NtlmType2Msg;
            }
            SaslState::NtlmType2Msg => {
                // Type-2 decode + type-3 (C L695-707). The Rust ntlm helpers work in
                // base64, so pass the raw (still-base64) server line straight to
                // `decode_type2_message` and emit the type-3 output as Encoded.
                match proto.get_message() {
                    Ok(raw_line) => match std::str::from_utf8(&raw_line) {
                        Ok(b64) => match ntlm::decode_type2_message(b64, &mut self.ntlm) {
                            Ok(()) => match ntlm::create_type3_message(
                                &creds.user,
                                &creds.passwd,
                                &mut self.ntlm,
                            ) {
                                Ok(t3) => resp = Response::Encoded(t3.into_bytes()),
                                Err(e) => result = Err(e),
                            },
                            Err(e) => result = Err(e),
                        },
                        Err(_) => {
                            result = Err(Error::bad_content_encoding(
                                "NTLM: type-2 message is not valid base64 text",
                            ));
                        }
                    },
                    Err(e) => result = Err(e),
                }
            }
            SaslState::Gssapi => {
                // C L711-720. Kerberos helpers exist in both feature builds; in the
                // default build this state is never reached (GSSAPI is never
                // selected), and the stub simply reports "not built in".
                match kerberos::create_gssapi_user_message(
                    &mut self.krb5,
                    &service,
                    &creds.host,
                    self.mutual_auth,
                    None,
                ) {
                    Ok(Some(token)) => resp = Response::Raw(token),
                    Ok(None) => {}
                    Err(e) => result = Err(e),
                }
                newstate = SaslState::GssapiToken;
            }
            SaslState::GssapiToken => {
                // C L721-744.
                match get_server_message(proto, flags) {
                    Ok(serverdata) => {
                        if self.mutual_auth {
                            // C sets `newstate = SASL_GSSAPI_NO_DATA`
                            // unconditionally in this branch (an error is
                            // overwritten to STOP/CANCEL by the disposition below).
                            newstate = SaslState::GssapiNoData;
                            match kerberos::create_gssapi_user_message(
                                &mut self.krb5,
                                &service,
                                &creds.host,
                                self.mutual_auth,
                                Some(&serverdata),
                            ) {
                                Ok(Some(token)) => resp = Response::Raw(token),
                                // No token: leave the response Absent so an empty
                                // line is emitted (curl's NULL bufref → "").
                                Ok(None) => {}
                                Err(e) => result = Err(e),
                            }
                        } else {
                            match kerberos::create_gssapi_security_message(
                                &mut self.krb5,
                                creds.authzid.as_deref(),
                                &serverdata,
                            ) {
                                Ok(v) => resp = Response::Raw(v),
                                Err(e) => result = Err(e),
                            }
                        }
                    }
                    Err(e) => result = Err(e),
                }
            }
            SaslState::GssapiNoData => {
                // C L745-758.
                match get_server_message(proto, flags) {
                    Ok(serverdata) => {
                        match kerberos::create_gssapi_security_message(
                            &mut self.krb5,
                            creds.authzid.as_deref(),
                            &serverdata,
                        ) {
                            Ok(v) => resp = Response::Raw(v),
                            Err(e) => result = Err(e),
                        }
                    }
                    Err(e) => result = Err(e),
                }
            }
            SaslState::OAuth2 => {
                // C L761-777.
                let bearer = creds.bearer.as_deref().unwrap_or("");
                if self.authused == SASL_MECH_OAUTHBEARER {
                    resp = Response::Raw(bearer::create_oauth_bearer_message(
                        &creds.user,
                        &creds.host,
                        creds.port,
                        bearer,
                    ));
                    // The server may send a failure as a continuation for
                    // OAUTHBEARER (C L770-771).
                    newstate = SaslState::OAuth2Resp;
                } else {
                    resp = Response::Raw(bearer::create_xoauth_bearer_message(&creds.user, bearer));
                }
            }
            SaslState::OAuth2Resp => {
                // The continuation is optional; inspect the code (C L779-796).
                if code == final_code {
                    self.set_state(SaslState::Stop);
                    return Ok(SaslProgress::Done);
                } else if code == cont_code {
                    // Acknowledge the continuation with a 0x01 response (C L788-789).
                    resp = Response::Raw(vec![0x01]);
                } else {
                    self.set_state(SaslState::Stop);
                    return Err(Error::LoginDenied);
                }
            }
            SaslState::Cancel => {
                // Remove the offending mechanism and restart with an alternative
                // (C L798-805).
                self.authmechs &= !self.authused;
                self.authused = SASL_AUTH_NONE;
                self.curmech = None;
                let force_ir = self.force_ir;
                return self.sasl_start(proto, creds, force_ir);
            }
            SaslState::Final => {
                // Handled by the FINAL fast-path above; unreachable here.
                return Ok(SaslProgress::Done);
            }
        }

        // Post-switch disposition (C L814-835).
        match result {
            // A bad server message cancels the mechanism (C L815-819); the CANCEL
            // state then restarts with the next candidate on the following call.
            Err(Error::BadContentEncoding(_)) => {
                let mech = self.curmech.unwrap_or("");
                let cancel_result = proto.cancel_auth(mech);
                self.set_state(SaslState::Cancel);
                cancel_result?;
                Ok(SaslProgress::InProgress)
            }
            // Success: encode and transmit the response, then advance (C L820-824).
            Ok(()) => {
                let built = build_message(flags, &resp);
                let mech = self.curmech.unwrap_or("");
                let cont_result = proto.cont_auth(mech, &built);
                self.set_state(newstate);
                cont_result?;
                Ok(SaslProgress::InProgress)
            }
            // Any other error stops the exchange (C L825-828).
            Err(e) => {
                self.set_state(SaslState::Stop);
                Err(e)
            }
        }
    }
}

// ===========================================================================
// Phase G — CRAM-MD5 (RFC 2195)  (← lib/vauth/cram.c)
// ===========================================================================

/// The MD5 digest length in bytes (curl's `MD5_DIGEST_LEN`).
const MD5_DIGEST_LEN: usize = 16;

/// HMAC-MD5, the CRAM-MD5 keyed hash (curl's `Curl_HMAC_MD5`).
type HmacMd5 = Hmac<Md5>;

/// Build a CRAM-MD5 response message (port of `Curl_auth_create_cram_md5_message`,
/// `lib/vauth/cram.c` L49-84; RFC 2195).
///
/// The response is `HMAC-MD5(key = password, message = challenge)` rendered as the
/// literal text `"<username> <32-lowercase-hex-digits>"`. When `chlg` is empty the
/// HMAC is taken over an empty message (curl only calls `Curl_HMAC_update` when the
/// challenge is non-empty, which is equivalent). The returned bytes are **raw**:
/// the SASL engine applies base64 when [`SASL_FLAG_BASE64`] is set, exactly as curl
/// hands the string to `Curl_bufref_set` and lets the engine encode it.
///
/// This function is infallible: unlike the C version (which can return
/// `CURLE_OUT_OF_MEMORY` on allocation failure), the Rust HMAC and formatting never
/// fail — `HMAC` accepts a key of any length, so `new_from_slice` cannot error.
///
/// # Parameters
///
/// * `chlg`   — the server's challenge (may be empty);
/// * `user`   — the username;
/// * `passwd` — the user's password, used as the HMAC key.
#[must_use]
pub fn create_cram_md5_message(chlg: &[u8], user: &str, passwd: &str) -> Vec<u8> {
    // Compute the digest using the password as the key (C L59-61). HMAC keys may be
    // any length, so `new_from_slice` is infallible here — hence `expect`.
    let mut ctxt = <HmacMd5 as Mac>::new_from_slice(passwd.as_bytes())
        .expect("HMAC accepts a key of any length");

    // Update the digest with the given challenge (C L66-68). Feeding an empty slice
    // is a no-op, matching curl's `if(Curl_bufref_len(chlg))` guard.
    ctxt.update(chlg);

    // Finalise the digest — 16 bytes (C L71).
    let digest = ctxt.finalize().into_bytes();
    debug_assert_eq!(digest.len(), MD5_DIGEST_LEN);

    // Generate the response: "<user> " followed by the digest as 32 lowercase hex
    // characters, matching curl's `"%s %02x..%02x"` format (C L74-78).
    let mut response = Vec::with_capacity(user.len() + 1 + MD5_DIGEST_LEN * 2);
    response.extend_from_slice(user.as_bytes());
    response.push(b' ');
    for byte in digest.iter() {
        // `%02x` — two lowercase hex digits per byte, no separator.
        response.push(hex_lower_nibble(byte >> 4));
        response.push(hex_lower_nibble(byte & 0x0f));
    }
    response
}

/// Map a 4-bit nibble (0..=15) to its lowercase ASCII hex digit, reproducing C's
/// `%02x` conversion.
#[inline]
fn hex_lower_nibble(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => b'a' + (nibble - 10),
    }
}

// ===========================================================================
// Phase I — unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    // `super::*` re-exports the module-level `BASE64` engine alias and the
    // `base64::Engine` trait (imported there as `_`), so both are available here.
    use super::*;
    use std::collections::VecDeque;

    // -----------------------------------------------------------------------
    // A minimal in-memory `SaslProto` for driving the engine end to end.
    // -----------------------------------------------------------------------

    /// A message the engine transmitted, captured for assertions.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Sent {
        Auth { mech: String, ir: Option<Vec<u8>> },
        Cont { mech: String, resp: Vec<u8> },
        Cancel { mech: String },
    }

    /// A configurable mock protocol hook (stands in for IMAP/POP3/SMTP).
    struct MockProto {
        service: String,
        flags: u16,
        cont_code: i32,
        final_code: i32,
        def_mechs: u32,
        max_ir_len: usize,
        /// Server SASL lines handed out, in order, by `get_message`.
        server: VecDeque<Vec<u8>>,
        /// Everything the engine sent, in order.
        sent: Vec<Sent>,
    }

    impl MockProto {
        /// A base64 protocol (like IMAP/POP3/SMTP) with the given default mechs.
        fn base64(def_mechs: u32) -> Self {
            MockProto {
                service: "imap".to_string(),
                flags: SASL_FLAG_BASE64,
                cont_code: 1,
                final_code: 2,
                def_mechs,
                max_ir_len: 0,
                server: VecDeque::new(),
                sent: Vec::new(),
            }
        }

        /// Queue a raw server line (already in wire form, e.g. base64 text).
        fn push_server(&mut self, line: &[u8]) {
            self.server.push_back(line.to_vec());
        }
    }

    impl SaslProto for MockProto {
        fn service(&self) -> &str {
            &self.service
        }
        fn max_ir_len(&self) -> usize {
            self.max_ir_len
        }
        fn cont_code(&self) -> i32 {
            self.cont_code
        }
        fn final_code(&self) -> i32 {
            self.final_code
        }
        fn def_mechs(&self) -> u32 {
            self.def_mechs
        }
        fn flags(&self) -> u16 {
            self.flags
        }
        fn send_auth(&mut self, mech: &str, initial_resp: Option<&[u8]>) -> Result<()> {
            self.sent.push(Sent::Auth {
                mech: mech.to_string(),
                ir: initial_resp.map(<[u8]>::to_vec),
            });
            Ok(())
        }
        fn cont_auth(&mut self, mech: &str, resp: &[u8]) -> Result<()> {
            self.sent.push(Sent::Cont {
                mech: mech.to_string(),
                resp: resp.to_vec(),
            });
            Ok(())
        }
        fn cancel_auth(&mut self, mech: &str) -> Result<()> {
            self.sent.push(Sent::Cancel {
                mech: mech.to_string(),
            });
            Ok(())
        }
        fn get_message(&mut self) -> Result<Vec<u8>> {
            // A well-formed test always queues enough lines; an empty queue is a
            // test bug rather than a protocol condition.
            self.server
                .pop_front()
                .ok_or_else(|| Error::Auth("mock: no server message queued".into()))
        }
    }

    fn creds(user: &str, passwd: &str) -> SaslCredentials {
        SaslCredentials {
            user: user.to_string(),
            passwd: passwd.to_string(),
            host: "mail.example.com".to_string(),
            port: 143,
            ..SaslCredentials::default()
        }
    }

    // -----------------------------------------------------------------------
    // Phase A — bitmask, aggregates, flag, mechtable
    // -----------------------------------------------------------------------

    #[test]
    fn mech_bit_values_match_curl() {
        assert_eq!(SASL_MECH_LOGIN, 1 << 0);
        assert_eq!(SASL_MECH_PLAIN, 1 << 1);
        assert_eq!(SASL_MECH_CRAM_MD5, 1 << 2);
        assert_eq!(SASL_MECH_DIGEST_MD5, 1 << 3);
        assert_eq!(SASL_MECH_GSSAPI, 1 << 4);
        assert_eq!(SASL_MECH_EXTERNAL, 1 << 5);
        assert_eq!(SASL_MECH_NTLM, 1 << 6);
        assert_eq!(SASL_MECH_XOAUTH2, 1 << 7);
        assert_eq!(SASL_MECH_OAUTHBEARER, 1 << 8);
        assert_eq!(SASL_MECH_SCRAM_SHA_1, 1 << 9);
        assert_eq!(SASL_MECH_SCRAM_SHA_256, 1 << 10);
    }

    #[test]
    fn mech_aggregates_and_flag_match_curl() {
        assert_eq!(SASL_AUTH_NONE, 0);
        assert_eq!(SASL_AUTH_ANY, 0xffff);
        assert_eq!(SASL_AUTH_DEFAULT, 0xffff & !SASL_MECH_EXTERNAL);
        // EXTERNAL is the one bit excluded from the default preference set.
        assert_eq!(SASL_AUTH_DEFAULT & SASL_MECH_EXTERNAL, 0);
        assert_eq!(SASL_FLAG_BASE64, 0x0001);
    }

    #[test]
    fn mechtable_matches_curl_verbatim() {
        // (name, len, bit) in curl's exact order — the wire tokens and parse order.
        let expected: &[(&str, usize, u32)] = &[
            ("LOGIN", 5, SASL_MECH_LOGIN),
            ("PLAIN", 5, SASL_MECH_PLAIN),
            ("CRAM-MD5", 8, SASL_MECH_CRAM_MD5),
            ("DIGEST-MD5", 10, SASL_MECH_DIGEST_MD5),
            ("GSSAPI", 6, SASL_MECH_GSSAPI),
            ("EXTERNAL", 8, SASL_MECH_EXTERNAL),
            ("NTLM", 4, SASL_MECH_NTLM),
            ("XOAUTH2", 7, SASL_MECH_XOAUTH2),
            ("OAUTHBEARER", 11, SASL_MECH_OAUTHBEARER),
            ("SCRAM-SHA-1", 11, SASL_MECH_SCRAM_SHA_1),
            ("SCRAM-SHA-256", 13, SASL_MECH_SCRAM_SHA_256),
        ];
        assert_eq!(MECHTABLE, expected);
        // The declared length must equal the actual byte length of each token.
        for &(name, len, _) in MECHTABLE {
            assert_eq!(name.len(), len, "declared length wrong for {name}");
        }
    }

    // -----------------------------------------------------------------------
    // Phase B — decode_mech / parse_url_auth_option
    // -----------------------------------------------------------------------

    #[test]
    fn decode_mech_exact_tokens() {
        assert_eq!(decode_mech("LOGIN"), Some((SASL_MECH_LOGIN, 5)));
        assert_eq!(decode_mech("PLAIN"), Some((SASL_MECH_PLAIN, 5)));
        assert_eq!(decode_mech("CRAM-MD5"), Some((SASL_MECH_CRAM_MD5, 8)));
        assert_eq!(decode_mech("DIGEST-MD5"), Some((SASL_MECH_DIGEST_MD5, 10)));
        assert_eq!(decode_mech("GSSAPI"), Some((SASL_MECH_GSSAPI, 6)));
        assert_eq!(decode_mech("EXTERNAL"), Some((SASL_MECH_EXTERNAL, 8)));
        assert_eq!(decode_mech("NTLM"), Some((SASL_MECH_NTLM, 4)));
        assert_eq!(decode_mech("XOAUTH2"), Some((SASL_MECH_XOAUTH2, 7)));
        assert_eq!(
            decode_mech("OAUTHBEARER"),
            Some((SASL_MECH_OAUTHBEARER, 11))
        );
        assert_eq!(
            decode_mech("SCRAM-SHA-1"),
            Some((SASL_MECH_SCRAM_SHA_1, 11))
        );
        assert_eq!(
            decode_mech("SCRAM-SHA-256"),
            Some((SASL_MECH_SCRAM_SHA_256, 13))
        );
    }

    #[test]
    fn decode_mech_is_case_insensitive() {
        assert_eq!(decode_mech("cram-md5"), Some((SASL_MECH_CRAM_MD5, 8)));
        assert_eq!(decode_mech("Plain"), Some((SASL_MECH_PLAIN, 5)));
    }

    #[test]
    fn decode_mech_delimiter_and_prefix_rules() {
        // A trailing delimiter (space) ends the token and is not consumed.
        assert_eq!(decode_mech("LOGIN "), Some((SASL_MECH_LOGIN, 5)));
        // A trailing token-continuation byte (uppercase/digit/-/_) blocks the match.
        assert_eq!(decode_mech("LOGINX"), None);
        assert_eq!(decode_mech("PLAIN2"), None);
        assert_eq!(decode_mech("NTLM-"), None);
        // SCRAM-SHA-1 must NOT be matched for a SHA-256 token (prefix guard).
        assert_eq!(
            decode_mech("SCRAM-SHA-256"),
            Some((SASL_MECH_SCRAM_SHA_256, 13))
        );
    }

    #[test]
    fn decode_mech_unknown_is_none() {
        assert_eq!(decode_mech("BOGUS"), None);
        assert_eq!(decode_mech(""), None);
    }

    #[test]
    fn parse_url_auth_option_cases() {
        assert_eq!(parse_url_auth_option("*"), Some(SASL_AUTH_DEFAULT));
        assert_eq!(parse_url_auth_option("PLAIN"), Some(SASL_MECH_PLAIN));
        assert_eq!(
            parse_url_auth_option("SCRAM-SHA-256"),
            Some(SASL_MECH_SCRAM_SHA_256)
        );
        // Must consume the whole value: trailing bytes make it malformed.
        assert_eq!(parse_url_auth_option("PLAIN "), None);
        assert_eq!(parse_url_auth_option("PLAINX"), None);
        assert_eq!(parse_url_auth_option("BOGUS"), None);
        assert_eq!(parse_url_auth_option(""), None);
    }

    #[test]
    fn set_url_auth_option_is_stateful() {
        let mut sasl = Sasl::init(SASL_AUTH_DEFAULT, CURLAUTH_BASIC);
        // First option clears the inherited preferences (one-shot resetprefs).
        sasl.set_url_auth_option("PLAIN").unwrap();
        assert_eq!(sasl.prefmech(), SASL_MECH_PLAIN);
        // Subsequent options OR in.
        sasl.set_url_auth_option("LOGIN").unwrap();
        assert_eq!(sasl.prefmech(), SASL_MECH_PLAIN | SASL_MECH_LOGIN);
        // "*" assigns the full default set outright.
        sasl.set_url_auth_option("*").unwrap();
        assert_eq!(sasl.prefmech(), SASL_AUTH_DEFAULT);
        // Empty and unknown values are rejected.
        assert!(sasl.set_url_auth_option("").is_err());
        assert!(sasl.set_url_auth_option("BOGUS").is_err());
    }

    // -----------------------------------------------------------------------
    // Phase C — state-name diagnostic contract (must equal curl's names[])
    // -----------------------------------------------------------------------

    #[test]
    fn state_names_match_curl_verbatim() {
        assert_eq!(SaslState::Stop.name(), "STOP");
        assert_eq!(SaslState::Plain.name(), "PLAIN");
        assert_eq!(SaslState::Login.name(), "LOGIN");
        assert_eq!(SaslState::LoginPasswd.name(), "LOGIN_PASSWD");
        assert_eq!(SaslState::External.name(), "EXTERNAL");
        assert_eq!(SaslState::CramMd5.name(), "CRAMMD5");
        assert_eq!(SaslState::DigestMd5.name(), "DIGESTMD5");
        assert_eq!(SaslState::DigestMd5Resp.name(), "DIGESTMD5_RESP");
        assert_eq!(SaslState::Ntlm.name(), "NTLM");
        assert_eq!(SaslState::NtlmType2Msg.name(), "NTLM_TYPE2MSG");
        assert_eq!(SaslState::Gssapi.name(), "GSSAPI");
        assert_eq!(SaslState::GssapiToken.name(), "GSSAPI_TOKEN");
        assert_eq!(SaslState::GssapiNoData.name(), "GSSAPI_NO_DATA");
        assert_eq!(SaslState::OAuth2.name(), "OAUTH2");
        assert_eq!(SaslState::OAuth2Resp.name(), "OAUTH2_RESP");
        assert_eq!(SaslState::Gsasl.name(), "GSASL");
        assert_eq!(SaslState::Cancel.name(), "CANCEL");
        assert_eq!(SaslState::Final.name(), "FINAL");
    }

    // -----------------------------------------------------------------------
    // Phase F/H — outgoing/incoming codecs (base64 special-casing)
    // -----------------------------------------------------------------------

    #[test]
    fn build_message_base64_semantics() {
        // Absent → empty line; empty Raw → "="; real Raw → base64; Encoded → verbatim.
        assert_eq!(build_message(SASL_FLAG_BASE64, &Response::Absent), b"");
        assert_eq!(
            build_message(SASL_FLAG_BASE64, &Response::Raw(vec![])),
            b"="
        );
        assert_eq!(
            build_message(SASL_FLAG_BASE64, &Response::Raw(b"hi".to_vec())),
            BASE64.encode("hi").into_bytes()
        );
        assert_eq!(
            build_message(SASL_FLAG_BASE64, &Response::Encoded(b"already".to_vec())),
            b"already"
        );
    }

    #[test]
    fn build_message_without_base64_is_raw() {
        assert_eq!(
            build_message(0, &Response::Raw(b"hi".to_vec())),
            b"hi".to_vec()
        );
        assert_eq!(build_message(0, &Response::Absent), b"");
    }

    #[test]
    fn get_server_message_empty_and_equals_are_empty() {
        // Both an empty line and a bare "=" decode to an empty message.
        let mut p = MockProto::base64(SASL_AUTH_DEFAULT);
        p.push_server(b"");
        p.push_server(b"=");
        p.push_server(BASE64.encode("hello").as_bytes());
        assert_eq!(get_server_message(&mut p, SASL_FLAG_BASE64).unwrap(), b"");
        assert_eq!(get_server_message(&mut p, SASL_FLAG_BASE64).unwrap(), b"");
        assert_eq!(
            get_server_message(&mut p, SASL_FLAG_BASE64).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn get_server_message_invalid_base64_errors() {
        let mut p = MockProto::base64(SASL_AUTH_DEFAULT);
        p.push_server(b"@@@not-base64@@@");
        let err = get_server_message(&mut p, SASL_FLAG_BASE64).unwrap_err();
        assert!(matches!(err, Error::BadContentEncoding(_)));
    }

    #[test]
    fn get_server_message_without_base64_passthrough() {
        let mut p = MockProto::base64(SASL_AUTH_DEFAULT);
        p.push_server(b"raw-bytes");
        assert_eq!(get_server_message(&mut p, 0).unwrap(), b"raw-bytes");
    }

    // -----------------------------------------------------------------------
    // Phase G — CRAM-MD5 (RFC 2195 test vector)
    // -----------------------------------------------------------------------

    #[test]
    fn cram_md5_rfc2195_vector() {
        // RFC 2195 §2 worked example.
        let challenge = b"<1896.697170952@postoffice.reston.mci.net>";
        let out = create_cram_md5_message(challenge, "tim", "tanstaaftanstaaf");
        assert_eq!(out, b"tim b913a602c7eda7a495b4e6e7334d3890".to_vec());
    }

    #[test]
    fn cram_md5_empty_challenge_does_not_panic() {
        // An empty challenge HMACs the empty message; the output is still
        // "<user> <32 hex>" and 32 hex digits long after the "user ".
        let out = create_cram_md5_message(b"", "user", "secret");
        assert!(out.starts_with(b"user "));
        assert_eq!(out.len(), "user ".len() + 32);
        assert!(out[5..].iter().all(u8::is_ascii_hexdigit));
    }

    // -----------------------------------------------------------------------
    // Phase E — init mapping / can_authenticate
    // -----------------------------------------------------------------------

    #[test]
    fn sasl_init_maps_curlauth_to_mechs() {
        // CURLAUTH_BASIC exactly → keep the protocol default (no remap).
        let s = Sasl::init(SASL_AUTH_DEFAULT, CURLAUTH_BASIC);
        assert_eq!(s.prefmech(), SASL_AUTH_DEFAULT);
        assert_eq!(s.state(), SaslState::Stop);

        // Specific CURLAUTH_* bits remap to their SASL mechanism bits.
        assert_eq!(
            Sasl::init(SASL_AUTH_DEFAULT, CURLAUTH_DIGEST).prefmech(),
            SASL_MECH_DIGEST_MD5
        );
        assert_eq!(
            Sasl::init(SASL_AUTH_DEFAULT, CURLAUTH_NTLM).prefmech(),
            SASL_MECH_NTLM
        );
        assert_eq!(
            Sasl::init(SASL_AUTH_DEFAULT, CURLAUTH_BEARER).prefmech(),
            SASL_MECH_OAUTHBEARER | SASL_MECH_XOAUTH2
        );
        assert_eq!(
            Sasl::init(SASL_AUTH_DEFAULT, CURLAUTH_GSSAPI).prefmech(),
            SASL_MECH_GSSAPI
        );
        // A combined selection ORs the mapped bits together.
        assert_eq!(
            Sasl::init(SASL_AUTH_DEFAULT, CURLAUTH_BASIC | CURLAUTH_DIGEST).prefmech(),
            SASL_MECH_PLAIN | SASL_MECH_LOGIN | SASL_MECH_DIGEST_MD5
        );
    }

    #[test]
    fn can_authenticate_rules() {
        // A username present → always authenticable.
        let s = Sasl::init(SASL_AUTH_DEFAULT, CURLAUTH_BASIC);
        assert!(s.can_authenticate(&creds("bob", "pw")));

        // No username: only EXTERNAL (offered AND preferred) permits auth.
        let anon = creds("", "");
        assert!(!s.can_authenticate(&anon));
        // Offer + prefer EXTERNAL.
        let mut s_ext = Sasl::init(SASL_MECH_EXTERNAL, CURLAUTH_BASIC);
        s_ext.set_authmechs(SASL_MECH_EXTERNAL);
        assert!(s_ext.can_authenticate(&anon));
    }

    // -----------------------------------------------------------------------
    // Phase E/F — end-to-end flows through the state machine
    // -----------------------------------------------------------------------

    #[test]
    fn sasl_start_idle_when_no_mech_selectable() {
        // Server offers nothing → no mechanism can be chosen.
        let mut proto = MockProto::base64(SASL_AUTH_DEFAULT);
        let mut sasl = Sasl::init(SASL_AUTH_DEFAULT, CURLAUTH_BASIC);
        // authmechs stays 0 (no capabilities parsed).
        let progress = sasl
            .sasl_start(&mut proto, &creds("bob", "pw"), false)
            .unwrap();
        assert_eq!(progress, SaslProgress::Idle);
        assert_eq!(sasl.state(), SaslState::Stop);
        assert!(proto.sent.is_empty());
    }

    #[test]
    fn end_to_end_plain_with_initial_response() {
        let mut proto = MockProto::base64(SASL_MECH_PLAIN | SASL_MECH_LOGIN);
        let mut sasl = Sasl::init(proto.def_mechs(), CURLAUTH_BASIC);
        sasl.set_authmechs(SASL_MECH_PLAIN);

        let c = creds("tim", "tanstaaf");

        // Start with an initial response (force_ir = true).
        let progress = sasl.sasl_start(&mut proto, &c, true).unwrap();
        assert_eq!(progress, SaslProgress::InProgress);
        assert_eq!(sasl.state(), SaslState::Final);
        assert_eq!(sasl.authused(), SASL_MECH_PLAIN);
        assert_eq!(sasl.curmech(), Some("PLAIN"));

        // The AUTH command carries the base64 of the PLAIN message.
        let expected_plain = basic::create_plain_message(None, "tim", "tanstaaf").unwrap();
        match &proto.sent[0] {
            Sent::Auth { mech, ir } => {
                assert_eq!(mech, "PLAIN");
                let ir = ir.as_ref().expect("PLAIN sends an initial response");
                assert_eq!(BASE64.decode(ir).unwrap(), expected_plain);
            }
            other => panic!("expected AUTH, got {other:?}"),
        }

        // Server accepts → FINAL round completes.
        let final_code = proto.final_code;
        let done = sasl.sasl_continue(&mut proto, &c, final_code).unwrap();
        assert_eq!(done, SaslProgress::Done);
        assert_eq!(sasl.state(), SaslState::Stop);
    }

    #[test]
    fn end_to_end_cram_md5() {
        let mut proto = MockProto::base64(SASL_AUTH_DEFAULT);
        let mut sasl = Sasl::init(proto.def_mechs(), CURLAUTH_BASIC);
        // Server offers only CRAM-MD5.
        sasl.set_authmechs(SASL_MECH_CRAM_MD5);

        let c = creds("tim", "tanstaaftanstaaf");

        // Start: CRAM-MD5 has no initial response (needs the challenge first).
        let progress = sasl.sasl_start(&mut proto, &c, false).unwrap();
        assert_eq!(progress, SaslProgress::InProgress);
        assert_eq!(sasl.state(), SaslState::CramMd5);
        assert_eq!(sasl.curmech(), Some("CRAM-MD5"));
        assert_eq!(
            proto.sent[0],
            Sent::Auth {
                mech: "CRAM-MD5".to_string(),
                ir: None
            }
        );

        // Server sends the RFC 2195 challenge (base64-encoded on the wire).
        let challenge = b"<1896.697170952@postoffice.reston.mci.net>";
        proto.push_server(BASE64.encode(challenge).as_bytes());
        let cont_code = proto.cont_code;
        let progress = sasl.sasl_continue(&mut proto, &c, cont_code).unwrap();
        assert_eq!(progress, SaslProgress::InProgress);
        assert_eq!(sasl.state(), SaslState::Final);

        // The continuation carries base64 of the exact RFC response digest.
        match &proto.sent[1] {
            Sent::Cont { mech, resp } => {
                assert_eq!(mech, "CRAM-MD5");
                assert_eq!(
                    BASE64.decode(resp).unwrap(),
                    b"tim b913a602c7eda7a495b4e6e7334d3890".to_vec()
                );
            }
            other => panic!("expected CONT, got {other:?}"),
        }

        // Server accepts → done.
        let final_code = proto.final_code;
        let done = sasl.sasl_continue(&mut proto, &c, final_code).unwrap();
        assert_eq!(done, SaslProgress::Done);
        assert_eq!(sasl.state(), SaslState::Stop);
    }

    #[test]
    fn sasl_continue_wrong_code_is_login_denied() {
        let mut proto = MockProto::base64(SASL_AUTH_DEFAULT);
        let mut sasl = Sasl::init(proto.def_mechs(), CURLAUTH_BASIC);
        sasl.set_authmechs(SASL_MECH_CRAM_MD5);
        let c = creds("tim", "tanstaaftanstaaf");
        sasl.sasl_start(&mut proto, &c, false).unwrap();
        assert_eq!(sasl.state(), SaslState::CramMd5);

        // A non-continuation status where a continuation was required → denied.
        let bad = proto.final_code + 99;
        let err = sasl.sasl_continue(&mut proto, &c, bad).unwrap_err();
        assert!(matches!(err, Error::LoginDenied));
        assert_eq!(sasl.state(), SaslState::Stop);
    }

    #[test]
    fn sasl_continue_bad_base64_triggers_cancel() {
        let mut proto = MockProto::base64(SASL_AUTH_DEFAULT);
        let mut sasl = Sasl::init(proto.def_mechs(), CURLAUTH_BASIC);
        sasl.set_authmechs(SASL_MECH_CRAM_MD5);
        let c = creds("tim", "tanstaaftanstaaf");
        sasl.sasl_start(&mut proto, &c, false).unwrap();

        // Server sends an undecodable challenge → BAD_CONTENT_ENCODING → cancel.
        proto.push_server(b"@@@not-base64@@@");
        let cont_code = proto.cont_code;
        let progress = sasl.sasl_continue(&mut proto, &c, cont_code).unwrap();
        assert_eq!(progress, SaslProgress::InProgress);
        assert_eq!(sasl.state(), SaslState::Cancel);
        assert_eq!(
            proto.sent.last(),
            Some(&Sent::Cancel {
                mech: "CRAM-MD5".to_string()
            })
        );
    }
}
