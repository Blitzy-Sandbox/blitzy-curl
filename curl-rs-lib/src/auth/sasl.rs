//! Shared **SASL** authentication state machine and **CRAM-MD5** mechanism.
//!
//! This module is the Rust successor to curl's `lib/curl_sasl.c` /
//! `lib/curl_sasl.h` and `lib/vauth/cram.c`. It is the *orchestrator* of SASL
//! authentication for the mail-style protocols (`IMAP`, `POP3`, `SMTP`, and
//! `OpenLDAP`): it negotiates a mechanism from the set offered by the server,
//! drives the `AUTH` command exchange, and runs the per-mechanism continuation
//! loop, delegating the actual message construction to the sibling
//! [`crate::auth`] modules ([`basic`], [`bearer`], [`digest`], and the
//! feature-gated [`ntlm`](crate::auth::ntlm),
//! [`kerberos`](crate::auth::kerberos), [`scram`](crate::auth::scram)). The
//! **CRAM-MD5** mechanism (RFC 2195) is implemented directly here, co-located
//! with the state machine that drives it (mirroring how `cram.c` maps onto the
//! SASL surface).
//!
//! # Mechanism dispatch is a trait, not a vtable
//!
//! curl models the protocol-specific behaviour with a `struct SASLproto` of C
//! function pointers. This port replaces it with the [`SaslProto`] **trait**,
//! implemented by each mail protocol module: it supplies the service name, the
//! continuation/final response codes, the maximum initial-response length, the
//! configuration flags (notably [`SASL_FLAG_BASE64`]), and the four I/O
//! operations ([`send_auth`](SaslProto::send_auth),
//! [`cont_auth`](SaslProto::cont_auth), [`cancel_auth`](SaslProto::cancel_auth),
//! [`get_message`](SaslProto::get_message)). The per-connection state held in
//! curl's `struct SASL` becomes the [`Sasl`] struct.
//!
//! # Credentials are passed explicitly
//!
//! curl reads the username, password, authorization identity, host, and the
//! various `data->set` options straight off the easy/connection handles. To
//! keep this module decoupled from those (not-yet-built) engine types, the same
//! inputs are passed in a [`SaslParams`] borrow on every
//! [`start`](Sasl::start) / [`cont`](Sasl::cont) call — exactly the values
//! curl reads from `data->conn` and `data->set` at the corresponding points.
//!
//! # Selection priority is wire-significant
//!
//! [`Sasl::start`] selects a mechanism in curl's exact decreasing-security
//! order: EXTERNAL → GSSAPI(krb5) → SCRAM(gsasl) → DIGEST-MD5/CRAM-MD5 → NTLM →
//! OAUTHBEARER → XOAUTH2 → PLAIN → LOGIN. This is **distinct** from the HTTP
//! `pickoneauth` order in [`crate::auth`]; the two are implemented separately
//! and exactly. Mechanisms whose backend is compiled out (via the `ntlm`,
//! `gssapi`, `gsasl` Cargo features) are never selected, keeping the
//! offered/enabled overlap arithmetic correct.
//!
//! # Memory safety
//!
//! Pure-safe Rust; this module compiles under the crate-wide and module-local
//! `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

use crate::error::{CurlError, Result};
use crate::util::base64::{base64_decode, base64_encode};
use crate::util::hmac::hmac_md5;
use crate::util::strparse::strncasecompare;

use crate::auth::{basic, bearer, digest};
use crate::auth::{
    CURLAUTH_BASIC, CURLAUTH_BEARER, CURLAUTH_DIGEST, CURLAUTH_GSSAPI, CURLAUTH_NTLM,
};

#[cfg(feature = "ntlm")]
use crate::auth::ntlm;
#[cfg(feature = "gsasl")]
use crate::auth::scram;
#[cfg(feature = "gssapi")]
use crate::auth::{kerberos, user_contains_domain};

// ===========================================================================
// Phase A — Authentication-mechanism flags (curl `SASL_MECH_*`)
// ===========================================================================
//
// Each mechanism owns one bit. The values and bit positions are ABI-significant
// for `Curl_sasl_decode_mech` callers and for the offered/enabled overlap math,
// so they must match `lib/curl_sasl.h` exactly.

/// `LOGIN` SASL mechanism (`SASL_MECH_LOGIN`).
pub const SASL_MECH_LOGIN: u16 = 1 << 0;
/// `PLAIN` SASL mechanism (`SASL_MECH_PLAIN`).
pub const SASL_MECH_PLAIN: u16 = 1 << 1;
/// `CRAM-MD5` SASL mechanism (`SASL_MECH_CRAM_MD5`).
pub const SASL_MECH_CRAM_MD5: u16 = 1 << 2;
/// `DIGEST-MD5` SASL mechanism (`SASL_MECH_DIGEST_MD5`).
pub const SASL_MECH_DIGEST_MD5: u16 = 1 << 3;
/// `GSSAPI` SASL mechanism (`SASL_MECH_GSSAPI`).
pub const SASL_MECH_GSSAPI: u16 = 1 << 4;
/// `EXTERNAL` SASL mechanism (`SASL_MECH_EXTERNAL`).
pub const SASL_MECH_EXTERNAL: u16 = 1 << 5;
/// `NTLM` SASL mechanism (`SASL_MECH_NTLM`).
pub const SASL_MECH_NTLM: u16 = 1 << 6;
/// `XOAUTH2` SASL mechanism (`SASL_MECH_XOAUTH2`).
pub const SASL_MECH_XOAUTH2: u16 = 1 << 7;
/// `OAUTHBEARER` SASL mechanism (`SASL_MECH_OAUTHBEARER`).
pub const SASL_MECH_OAUTHBEARER: u16 = 1 << 8;
/// `SCRAM-SHA-1` SASL mechanism (`SASL_MECH_SCRAM_SHA_1`).
pub const SASL_MECH_SCRAM_SHA_1: u16 = 1 << 9;
/// `SCRAM-SHA-256` SASL mechanism (`SASL_MECH_SCRAM_SHA_256`).
pub const SASL_MECH_SCRAM_SHA_256: u16 = 1 << 10;

/// No authentication mechanism (`SASL_AUTH_NONE`).
pub const SASL_AUTH_NONE: u16 = 0;
/// Every authentication mechanism (`SASL_AUTH_ANY`).
pub const SASL_AUTH_ANY: u16 = 0xffff;
/// The default mechanism set: everything except EXTERNAL (`SASL_AUTH_DEFAULT`).
///
/// EXTERNAL is excluded from the default because it authenticates from the TLS
/// client certificate rather than a username/password, so it must be requested
/// explicitly.
pub const SASL_AUTH_DEFAULT: u16 = SASL_AUTH_ANY & !SASL_MECH_EXTERNAL;

/// Configuration flag: SASL messages are base64-encoded on the wire
/// (`SASL_FLAG_BASE64`). This is set by the mail protocols (IMAP/POP3/SMTP) and
/// drives the [`build_message`]/[`get_server_message`] framing.
pub const SASL_FLAG_BASE64: u16 = 0x0001;

/// The mechanism name → bit table, mirroring curl's `mechtable`.
///
/// The order is significant for [`decode_mech`]: `SCRAM-SHA-1` must precede
/// `SCRAM-SHA-256` only insofar as each entry's own length bounds the match, and
/// the case-insensitive comparison plus boundary check disambiguate the two.
/// The exact spellings are wire-significant.
const MECHTABLE: [(&str, u16); 11] = [
    ("LOGIN", SASL_MECH_LOGIN),
    ("PLAIN", SASL_MECH_PLAIN),
    ("CRAM-MD5", SASL_MECH_CRAM_MD5),
    ("DIGEST-MD5", SASL_MECH_DIGEST_MD5),
    ("GSSAPI", SASL_MECH_GSSAPI),
    ("EXTERNAL", SASL_MECH_EXTERNAL),
    ("NTLM", SASL_MECH_NTLM),
    ("XOAUTH2", SASL_MECH_XOAUTH2),
    ("OAUTHBEARER", SASL_MECH_OAUTHBEARER),
    ("SCRAM-SHA-1", SASL_MECH_SCRAM_SHA_1),
    ("SCRAM-SHA-256", SASL_MECH_SCRAM_SHA_256),
];

// ===========================================================================
// Phase A — SASL machine states (curl `saslstate`)
// ===========================================================================

/// The SASL state machine states, mirroring curl's `saslstate` enum exactly
/// (18 states, in the same order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaslState {
    /// Not running (`SASL_STOP`).
    Stop,
    /// Awaiting the PLAIN response (`SASL_PLAIN`).
    Plain,
    /// Awaiting the LOGIN username step (`SASL_LOGIN`).
    Login,
    /// Awaiting the LOGIN password step (`SASL_LOGIN_PASSWD`).
    LoginPasswd,
    /// Awaiting the EXTERNAL response (`SASL_EXTERNAL`).
    External,
    /// Awaiting the CRAM-MD5 challenge (`SASL_CRAMMD5`).
    CramMd5,
    /// Awaiting the DIGEST-MD5 challenge (`SASL_DIGESTMD5`).
    DigestMd5,
    /// Sending the DIGEST-MD5 trailing empty response (`SASL_DIGESTMD5_RESP`).
    DigestMd5Resp,
    /// Sending the NTLM type-1 message (`SASL_NTLM`).
    Ntlm,
    /// Awaiting the NTLM type-2 message (`SASL_NTLM_TYPE2MSG`).
    NtlmType2Msg,
    /// Sending the GSSAPI initial token (`SASL_GSSAPI`).
    Gssapi,
    /// Awaiting the GSSAPI token challenge (`SASL_GSSAPI_TOKEN`).
    GssapiToken,
    /// Awaiting the GSSAPI security challenge with no further data
    /// (`SASL_GSSAPI_NO_DATA`).
    GssapiNoData,
    /// Sending the OAuth 2.0 authorization message (`SASL_OAUTH2`).
    OAuth2,
    /// Awaiting the optional OAuth 2.0 continuation (`SASL_OAUTH2_RESP`).
    OAuth2Resp,
    /// Running a GSASL (SCRAM) token exchange (`SASL_GSASL`).
    Gsasl,
    /// Cancelling the current mechanism (`SASL_CANCEL`).
    Cancel,
    /// Awaiting the final success/failure code (`SASL_FINAL`).
    Final,
}

/// Progress indicator returned by [`Sasl::start`] / [`Sasl::cont`], mirroring
/// curl's `saslprogress`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaslProgress {
    /// No SASL authentication is taking place (`SASL_IDLE`).
    Idle,
    /// An exchange is in progress (`SASL_INPROGRESS`).
    InProgress,
    /// The exchange has finished (`SASL_DONE`).
    Done,
}

// ===========================================================================
// Phase A — Protocol-dependent SASL parameters (curl `struct SASLproto`)
// ===========================================================================

/// Protocol-dependent SASL behaviour, the Rust successor to curl's
/// `struct SASLproto` function-pointer vtable.
///
/// Implemented by the mail protocol modules (`imap`, `pop3`, `smtp`). The four
/// I/O methods queue/extract protocol commands and responses; the rest are
/// pure descriptors. The message bytes handed to [`send_auth`](Self::send_auth)
/// / [`cont_auth`](Self::cont_auth) are already **wire-ready** (base64-framed
/// when [`SASL_FLAG_BASE64`] is set); [`get_message`](Self::get_message)
/// returns the raw server payload exactly as received (the SASL layer performs
/// any base64 decode).
pub trait SaslProto {
    /// The service name (for example `"imap"`, `"pop"`, `"smtp"`), used when
    /// building GSSAPI/Kerberos service principal names.
    fn service(&self) -> &str;

    /// Maximum initial-response + mechanism length, or `0` if there is no
    /// limit. Must be `0` for non-base64 protocols.
    fn maxirlen(&self) -> usize;

    /// The protocol response code that signals "continuation expected".
    fn cont_code(&self) -> i32;

    /// The protocol response code that signals authentication success.
    fn final_code(&self) -> i32;

    /// The mechanisms enabled by default for this protocol.
    fn def_mechs(&self) -> u16;

    /// Configuration flags; the carrier for [`SASL_FLAG_BASE64`].
    fn flags(&self) -> u16;

    /// Send the `AUTH` command selecting `mech`, with an optional, already
    /// wire-ready `initial_resp`.
    fn send_auth(&mut self, mech: &str, initial_resp: Option<&[u8]>) -> Result<()>;

    /// Send an authentication continuation carrying the already wire-ready
    /// `resp` (an empty slice means "send an empty line").
    fn cont_auth(&mut self, mech: &str, resp: &[u8]) -> Result<()>;

    /// Cancel the in-flight authentication exchange for `mech`.
    fn cancel_auth(&mut self, mech: &str) -> Result<()>;

    /// Return the most recently received server SASL message, raw (the SASL
    /// layer applies any base64 decoding).
    fn get_message(&mut self) -> Result<Vec<u8>>;
}

/// Per-call connection/configuration inputs for the SASL exchange.
///
/// These are exactly the values curl reads from `data->conn` and `data->set`
/// inside `Curl_sasl_start` / `Curl_sasl_continue`. They are supplied fresh on
/// each [`Sasl::start`] / [`Sasl::cont`] call so this module needs no reference
/// to the easy/connection handles.
#[derive(Debug, Clone, Copy)]
pub struct SaslParams<'a> {
    /// The connection username (`conn->user`); empty if none.
    pub user: &'a str,
    /// The connection password (`conn->passwd`); empty if none.
    pub passwd: &'a str,
    /// The SASL authorization identity (`conn->sasl_authzid`); empty if none.
    pub authzid: &'a str,
    /// The current connection host name.
    pub host: &'a str,
    /// The current connection port.
    pub port: u16,
    /// Optional service-name override (`data->set.str[STRING_SERVICE_NAME]`).
    pub service_name: Option<&'a str>,
    /// The OAuth 2.0 bearer token (`data->set.str[STRING_BEARER]`), if set.
    pub bearer: Option<&'a str>,
    /// Whether the protocol/option allows sending an initial response inline
    /// (`data->set.sasl_ir`).
    pub sasl_ir: bool,
    /// Whether credentials may be sent to a redirected host
    /// (`data->set.allow_auth_to_other_hosts`).
    pub allow_auth_to_other_hosts: bool,
    /// Whether this request is the result of following a redirect
    /// (`data->state.this_is_a_follow`).
    pub this_is_a_follow: bool,
}

/// Per-connection SASL state, the Rust successor to curl's `struct SASL`.
///
/// The protocol-dependent parameters live behind the [`SaslProto`] trait passed
/// to each method (rather than being stored here), so this struct holds only the
/// negotiation state. The feature-gated mechanism handles
/// ([`ntlm`](crate::auth::ntlm) / [`kerberos`](crate::auth::kerberos) /
/// [`scram`](crate::auth::scram)) persist across the continuation rounds of
/// their respective mechanisms.
///
/// `Debug` is implemented manually (rather than derived) so the credential-
/// bearing mechanism handles are never rendered into debug output.
pub struct Sasl {
    /// Current machine state (curl `state`).
    pub state: SaslState,
    /// Current mechanism, as its [`SASL_MECH_*`](SASL_MECH_PLAIN) bit, or `0`
    /// for none (curl stores the name in `curmech`; the bit round-trips to the
    /// name through [`MECHTABLE`]).
    pub curmech: u16,
    /// Mechanisms offered by the server (curl `authmechs`).
    pub authmechs: u16,
    /// Mechanisms preferred/configured by us (curl `prefmech`).
    pub prefmech: u16,
    /// The mechanism actually used for this connection (curl `authused`).
    pub authused: u16,
    /// Whether `prefmech` should be reset on the next URL-auth parse
    /// (curl `resetprefs`).
    pub resetprefs: bool,
    /// Whether mutual authentication is enabled (GSSAPI only; curl
    /// `mutual_auth`).
    pub mutual_auth: bool,
    /// Whether the protocol always supports an initial response (curl
    /// `force_ir`).
    pub force_ir: bool,

    /// Persistent NTLM crypto state across the type-1/type-2/type-3 rounds.
    #[cfg(feature = "ntlm")]
    ntlm: ntlm::NtlmData,
    /// Persistent Kerberos V5 (GSSAPI) state across the token rounds.
    #[cfg(feature = "gssapi")]
    krb5: kerberos::Krb5Data,
    /// Persistent SCRAM (GSASL) client across the token rounds.
    #[cfg(feature = "gsasl")]
    scram: Option<scram::ScramClient>,
}

impl core::fmt::Debug for Sasl {
    /// Render the negotiation state while deliberately omitting the
    /// credential-bearing mechanism handles (NTLM/Kerberos/SCRAM), which may
    /// hold secrets.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sasl")
            .field("state", &self.state)
            .field("curmech", &self.curmech)
            .field("authmechs", &self.authmechs)
            .field("prefmech", &self.prefmech)
            .field("authused", &self.authused)
            .field("resetprefs", &self.resetprefs)
            .field("mutual_auth", &self.mutual_auth)
            .field("force_ir", &self.force_ir)
            .finish_non_exhaustive()
    }
}

// ===========================================================================
// Phase B — Mechanism-name decode and URL login-option parsing
// ===========================================================================

/// Map a single mechanism bit back to its canonical wire name.
///
/// Used to recover the mechanism string from [`Sasl::curmech`] when calling
/// back into the [`SaslProto`] continuation/cancel hooks. Returns `None` for
/// `0` or any non-single-mechanism value.
fn mech_name_from_bit(bit: u16) -> Option<&'static str> {
    MECHTABLE
        .iter()
        .find_map(|&(name, b)| if b == bit { Some(name) } else { None })
}

/// Decode a SASL mechanism name into its [`SASL_MECH_*`](SASL_MECH_PLAIN) bit.
///
/// This is the Rust successor to curl's `Curl_sasl_decode_mech`. `name` is the
/// candidate buffer and `maxlen` bounds how many of its bytes are valid (it is
/// clamped to `name.len()` so the scan never reads out of bounds). The match is
/// ASCII case-insensitive (matching curl's `curl_strnequal`). A table entry
/// matches when:
///
/// * `maxlen` is at least the entry's length and the leading bytes compare
///   equal, **and**
/// * either `maxlen` equals the entry length exactly, **or** the byte
///   immediately after the matched name is *not* a continuation character
///   (i.e. not `[A-Z0-9-_]`) — so `"PLAIN"` matches but `"PLAINX"` does not,
///   while `"PLAIN "` (trailing space) does.
///
/// Returns `(bit, effective_len)`, or `(0, 0)` when no entry matches. The
/// returned length lets callers (notably [`Sasl::parse_url_auth_option`])
/// require a *full* match.
#[must_use]
pub fn decode_mech(name: &[u8], maxlen: usize) -> (u16, usize) {
    // Never consider more bytes than the slice actually holds; curl bounds this
    // with the separate `maxlen` argument against a longer buffer.
    let maxlen = maxlen.min(name.len());

    for &(mech_name, bit) in MECHTABLE.iter() {
        let mech_bytes = mech_name.as_bytes();
        let len = mech_bytes.len();

        if maxlen >= len && strncasecompare(name, mech_bytes, len) {
            // Exact-length match: accept unconditionally.
            if maxlen == len {
                return (bit, len);
            }

            // There is at least one more byte (maxlen > len and maxlen <=
            // name.len()), so this index is always present; the guard keeps the
            // access panic-free regardless.
            if let Some(&c) = name.get(len) {
                if !c.is_ascii_uppercase() && !c.is_ascii_digit() && c != b'-' && c != b'_' {
                    return (bit, len);
                }
            }
        }
    }

    (0, 0)
}

// ===========================================================================
// Phase G — CRAM-MD5 (RFC 2195), ported from `lib/vauth/cram.c`
// ===========================================================================

/// Lowercase hexadecimal rendering of a byte slice.
///
/// curl formats the CRAM-MD5 digest with `"%02x"` per byte; this reproduces
/// that exactly (lowercase, zero-padded, two characters per input byte). It is
/// a local helper because [`crate::util::md5`] exposes no public hex routine.
fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Build a **CRAM-MD5** (RFC 2195) client response, ported from
/// `Curl_auth_create_cram_md5_message`.
///
/// The HMAC-MD5 of the server `challenge` is computed using the user's
/// `passwd` as the key, and the 16-byte digest is rendered as 32 lowercase hex
/// characters. The response is the username, a single space, and that hex
/// digest:
///
/// ```text
/// <user> <32-hex-lowercase-digest>
/// ```
///
/// An empty `challenge` is valid and still HMACs over an empty message (the
/// HMAC construction is well-defined for zero-length data, exactly as curl's
/// "update only when the challenge is non-empty" produces). The returned bytes
/// are the **raw** response; the SASL layer applies any base64 framing.
#[must_use]
pub fn create_cram_md5_message(challenge: &[u8], user: &str, passwd: &str) -> Vec<u8> {
    // HMAC-MD5 with the password as the key over the (possibly empty) challenge.
    let digest = hmac_md5(passwd.as_bytes(), challenge);

    // "<user> <hex>" — note the single ASCII space separator.
    let mut response = String::with_capacity(user.len() + 1 + digest.len() * 2);
    response.push_str(user);
    response.push(' ');
    response.push_str(&lowercase_hex(&digest));

    response.into_bytes()
}

// ===========================================================================
// Phase D — Server-message decode and outgoing-message framing
// ===========================================================================

/// Fetch the latest server SASL message and convert it to its binary form,
/// mirroring curl's `get_server_message`.
///
/// When the protocol uses base64 framing ([`SASL_FLAG_BASE64`] set in
/// `flags`), an empty payload or a lone `"="` decodes to an empty message (the
/// SASL "no data" convention), and anything else is base64-decoded. Otherwise
/// the raw payload is returned unchanged.
fn get_server_message<P: SaslProto>(proto: &mut P, flags: u16) -> Result<Vec<u8>> {
    let raw = proto.get_message()?;

    if flags & SASL_FLAG_BASE64 != 0 {
        // Empty, or the explicit "no data" marker "=".
        if raw.is_empty() || raw[0] == b'=' {
            return Ok(Vec::new());
        }
        return base64_decode(&raw);
    }

    Ok(raw)
}

/// Fetch the latest server SASL message *without* base64 decoding.
///
/// The GSSAPI/Kerberos path needs the message in its on-the-wire (still
/// base64-encoded) form because [`crate::auth::kerberos`] performs its own
/// base64 decode/encode internally (a contract it shares with the HTTP
/// Negotiate path). All other mechanisms use [`get_server_message`].
#[cfg(feature = "gssapi")]
fn get_raw_server_message<P: SaslProto>(proto: &mut P) -> Result<Vec<u8>> {
    proto.get_message()
}

/// Frame an outgoing SASL message for the wire, mirroring curl's
/// `build_message`.
///
/// With base64 framing ([`SASL_FLAG_BASE64`]):
///
/// * `None` (no response buffer) becomes an empty string `""` — an empty
///   continuation line.
/// * `Some(&[])` (an explicit empty response) becomes `"="` — the wire-critical
///   "present but empty" marker.
/// * `Some(data)` is base64-encoded.
///
/// Without base64 framing, the bytes are passed through unchanged (`None`
/// yields an empty buffer).
fn build_message(flags: u16, resp: Option<&[u8]>) -> Result<Vec<u8>> {
    if flags & SASL_FLAG_BASE64 != 0 {
        return match resp {
            None => Ok(Vec::new()), // Empty message -> "".
            Some(r) => {
                if r.is_empty() {
                    Ok(b"=".to_vec()) // Explicit empty response -> "=".
                } else {
                    base64_encode(r)
                }
            }
        };
    }

    // Non-base64 protocols send the bytes verbatim.
    Ok(resp.map(<[u8]>::to_vec).unwrap_or_default())
}

impl Default for Sasl {
    fn default() -> Self {
        Self::new()
    }
}

impl Sasl {
    /// Create a fresh, idle SASL state block (curl initializes these fields in
    /// `Curl_sasl_init`; [`init`](Self::init) then applies the protocol
    /// defaults and the configured HTTP-auth mapping).
    ///
    /// The mechanism sets start empty; [`resetprefs`](Self::resetprefs) is
    /// `true` so the first parsed `AUTH=` URL option clears the (not-yet-set)
    /// preferences before accumulating.
    #[must_use]
    pub fn new() -> Self {
        Sasl {
            state: SaslState::Stop,
            curmech: 0,
            authmechs: SASL_AUTH_NONE,
            prefmech: SASL_AUTH_NONE,
            authused: SASL_AUTH_NONE,
            resetprefs: true,
            mutual_auth: false,
            force_ir: false,
            #[cfg(feature = "ntlm")]
            ntlm: ntlm::NtlmData::default(),
            #[cfg(feature = "gssapi")]
            krb5: kerberos::Krb5Data::new(),
            #[cfg(feature = "gsasl")]
            scram: None,
        }
    }

    /// Initialize the SASL block for an exchange, mirroring `Curl_sasl_init`.
    ///
    /// `proto` supplies the protocol's default mechanism set; `httpauth` is the
    /// `CURLOPT_HTTPAUTH` bitmask. When `httpauth` is anything other than the
    /// lone [`CURLAUTH_BASIC`], its set bits are translated into the
    /// corresponding SASL mechanisms and *override* the protocol defaults:
    ///
    /// | `CURLAUTH_*` bit | SASL mechanisms |
    /// |------------------|-----------------|
    /// | `BASIC`          | `PLAIN`, `LOGIN` |
    /// | `DIGEST`         | `DIGEST-MD5` |
    /// | `NTLM`           | `NTLM` |
    /// | `BEARER`         | `OAUTHBEARER`, `XOAUTH2` |
    /// | `GSSAPI`         | `GSSAPI` |
    pub fn init<P: SaslProto>(&mut self, proto: &P, httpauth: u32) {
        self.state = SaslState::Stop;
        self.curmech = 0;
        self.authmechs = SASL_AUTH_NONE;
        self.prefmech = proto.def_mechs();
        self.authused = SASL_AUTH_NONE;
        self.resetprefs = true;
        self.mutual_auth = false;
        self.force_ir = false;

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
            if httpauth & CURLAUTH_GSSAPI != 0 {
                mechs |= SASL_MECH_GSSAPI;
            }

            if mechs != SASL_AUTH_NONE {
                self.prefmech = mechs;
            }
        }
    }

    /// Whether enough credentials/capabilities exist to attempt authentication,
    /// mirroring `Curl_sasl_can_authenticate`.
    ///
    /// True when a username is configured, or when the server offers and we
    /// prefer the EXTERNAL mechanism (which authenticates from the TLS client
    /// certificate and needs no username/password).
    #[must_use]
    pub fn can_authenticate(&self, user: &str) -> bool {
        if !user.is_empty() {
            return true;
        }
        (self.authmechs & self.prefmech & SASL_MECH_EXTERNAL) != 0
    }

    /// Parse a single URL `AUTH=` login option, mirroring
    /// `Curl_sasl_parse_url_auth_option`.
    ///
    /// `value` is the option token (for example `b"PLAIN"` or `b"*"`). The
    /// special token `"*"` selects [`SASL_AUTH_DEFAULT`]. Any other token must
    /// match a mechanism name *exactly* (full-length match); the corresponding
    /// bit is OR-ed into [`prefmech`](Self::prefmech). The first option parsed
    /// after [`resetprefs`](Self::resetprefs) was set clears the preference set
    /// first (so a sequence of options accumulates from empty).
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::UrlMalformat`] for an empty token or one that does
    /// not fully match any known mechanism.
    pub fn parse_url_auth_option(&mut self, value: &[u8]) -> Result<()> {
        if value.is_empty() {
            return Err(CurlError::UrlMalformat);
        }

        if self.resetprefs {
            self.resetprefs = false;
            self.prefmech = SASL_AUTH_NONE;
        }

        if value == b"*" {
            self.prefmech = SASL_AUTH_DEFAULT;
            return Ok(());
        }

        let (bit, mechlen) = decode_mech(value, value.len());
        if bit != 0 && mechlen == value.len() {
            self.prefmech |= bit;
            Ok(())
        } else {
            Err(CurlError::UrlMalformat)
        }
    }

    /// Report that no SASL mechanism could be selected, mirroring
    /// `Curl_sasl_is_blocked`.
    ///
    /// curl emits verbose diagnostics here (which offered mechanisms went
    /// unselected and why) and then always fails with `CURLE_LOGIN_DENIED`; the
    /// diagnostics are observability-only, so this faithfully returns the same
    /// terminal error.
    ///
    /// # Errors
    ///
    /// Always returns [`CurlError::LoginDenied`].
    pub fn is_blocked(&self) -> Result<()> {
        Err(CurlError::LoginDenied)
    }

    /// The currently selected mechanism's wire name, or `""` if none.
    fn curmech_name(&self) -> &'static str {
        mech_name_from_bit(self.curmech).unwrap_or("")
    }
}

// ===========================================================================
// Phase E — Mechanism selection and AUTH initiation (`Curl_sasl_start`)
// ===========================================================================

impl Sasl {
    /// Begin SASL authentication: select a mechanism and send the `AUTH`
    /// command, mirroring `Curl_sasl_start`.
    ///
    /// The mechanism is chosen from `authmechs & prefmech` in curl's exact
    /// **decreasing-security** order — EXTERNAL, GSSAPI(krb5), SCRAM(gsasl),
    /// DIGEST-MD5/CRAM-MD5, NTLM, OAUTHBEARER, XOAUTH2, PLAIN, LOGIN — with each
    /// branch gated identically to curl (feature-compiled mechanisms that are
    /// absent are simply skipped). When `force_ir` is set (or the protocol
    /// enabled `sasl_ir`), an initial response is computed and, unless it would
    /// exceed the protocol's [`maxirlen`](SaslProto::maxirlen), sent inline with
    /// the `AUTH` command.
    ///
    /// Returns the resulting [`SaslProgress`]: [`Idle`](SaslProgress::Idle) if
    /// no mechanism could be selected, otherwise
    /// [`InProgress`](SaslProgress::InProgress).
    ///
    /// # Errors
    ///
    /// Propagates any error from building the initial response or from the
    /// protocol's [`send_auth`](SaslProto::send_auth) hook.
    pub fn start<P: SaslProto>(
        &mut self,
        proto: &mut P,
        params: &SaslParams,
        force_ir: bool,
    ) -> Result<SaslProgress> {
        // Latch options for later continuation rounds.
        self.force_ir = force_ir;
        self.authused = SASL_AUTH_NONE;

        let want_ir = force_ir || params.sasl_ir;
        let enabled = self.authmechs & self.prefmech;
        let flags = proto.flags();

        // Selection scratch state. `state1` is the state after sending the bare
        // mechanism (await challenge); `state2` is the state after sending an
        // inline initial response. Defaults mirror curl's `SASL_STOP`/
        // `SASL_FINAL`.
        let mut mech: Option<u16> = None;
        let mut state1 = SaslState::Stop;
        let mut state2 = SaslState::Final;
        let mut resp: Option<Vec<u8>> = None;

        // --- 1. EXTERNAL (no password) -------------------------------------
        if mech.is_none() && (enabled & SASL_MECH_EXTERNAL) != 0 && params.passwd.is_empty() {
            mech = Some(SASL_MECH_EXTERNAL);
            state1 = SaslState::External;
            self.authused = SASL_MECH_EXTERNAL;
            if want_ir {
                resp = Some(basic::sasl_external_message(params.user));
            }
        }

        // --- 2. GSSAPI / Kerberos V5 ---------------------------------------
        #[cfg(feature = "gssapi")]
        if mech.is_none()
            && (enabled & SASL_MECH_GSSAPI) != 0
            && kerberos::is_gssapi_supported()
            && user_contains_domain(params.user)
        {
            let service = params.service_name.unwrap_or_else(|| proto.service());
            self.mutual_auth = false;
            if want_ir {
                // Kerberos messages are produced already base64-framed.
                resp = Some(kerberos::create_gssapi_user_message(
                    &mut self.krb5,
                    service,
                    params.host,
                    self.mutual_auth,
                    None,
                )?);
            }
            mech = Some(SASL_MECH_GSSAPI);
            state1 = SaslState::Gssapi;
            state2 = SaslState::GssapiToken;
            self.authused = SASL_MECH_GSSAPI;
        }

        // --- 3. SCRAM via GSASL (SHA-256 before SHA-1) ---------------------
        #[cfg(feature = "gsasl")]
        if mech.is_none() && (enabled & (SASL_MECH_SCRAM_SHA_256 | SASL_MECH_SCRAM_SHA_1)) != 0 {
            // Prefer SCRAM-SHA-256; fall back to SCRAM-SHA-1 only if offered and
            // supported by the backend.
            let chosen = if (enabled & SASL_MECH_SCRAM_SHA_256) != 0
                && scram::ScramMechanism::from_name("SCRAM-SHA-256").is_some()
            {
                Some((SASL_MECH_SCRAM_SHA_256, "SCRAM-SHA-256"))
            } else if (enabled & SASL_MECH_SCRAM_SHA_1) != 0
                && scram::ScramMechanism::from_name("SCRAM-SHA-1").is_some()
            {
                Some((SASL_MECH_SCRAM_SHA_1, "SCRAM-SHA-1"))
            } else {
                None
            };

            if let Some((bit, mech_str)) = chosen {
                // `from_name` already validated the spelling above.
                let mechanism = scram::ScramMechanism::from_name(mech_str)
                    .ok_or(CurlError::UnsupportedProtocol)?;
                let mut client = scram::ScramClient::new(mechanism);
                client.start(params.user, params.passwd)?;
                if want_ir {
                    resp = Some(client.token(&[])?);
                }
                self.scram = Some(client);
                mech = Some(bit);
                state1 = SaslState::Gsasl;
                state2 = SaslState::Gsasl;
                self.authused = bit;
            }
        }

        // --- 4. DIGEST-MD5, else CRAM-MD5 ----------------------------------
        // Both require a server challenge, so neither carries an initial
        // response. DIGEST is always compiled in (curl's
        // `!CURL_DISABLE_DIGEST_AUTH` default).
        if mech.is_none() && (enabled & SASL_MECH_DIGEST_MD5) != 0 && digest::is_digest_supported()
        {
            mech = Some(SASL_MECH_DIGEST_MD5);
            state1 = SaslState::DigestMd5;
            self.authused = SASL_MECH_DIGEST_MD5;
        } else if mech.is_none() && (enabled & SASL_MECH_CRAM_MD5) != 0 {
            mech = Some(SASL_MECH_CRAM_MD5);
            state1 = SaslState::CramMd5;
            self.authused = SASL_MECH_CRAM_MD5;
        }

        // --- 5. NTLM -------------------------------------------------------
        #[cfg(feature = "ntlm")]
        if mech.is_none() && (enabled & SASL_MECH_NTLM) != 0 && ntlm::is_ntlm_supported() {
            if want_ir {
                resp = Some(ntlm::create_type1_message(&mut self.ntlm)?);
            }
            mech = Some(SASL_MECH_NTLM);
            state1 = SaslState::Ntlm;
            state2 = SaslState::NtlmType2Msg;
            self.authused = SASL_MECH_NTLM;
        }

        // The bearer token is only usable on the original host unless the user
        // explicitly allows sending it across a redirect.
        let oauth_bearer = if !params.this_is_a_follow || params.allow_auth_to_other_hosts {
            params.bearer
        } else {
            None
        };

        // --- 6. OAUTHBEARER ------------------------------------------------
        if mech.is_none() && oauth_bearer.is_some() && (enabled & SASL_MECH_OAUTHBEARER) != 0 {
            if want_ir {
                resp = Some(bearer::sasl_oauth_bearer_message(
                    params.user,
                    params.host,
                    params.port,
                    oauth_bearer.unwrap_or_default(),
                )?);
            }
            mech = Some(SASL_MECH_OAUTHBEARER);
            state1 = SaslState::OAuth2;
            state2 = SaslState::OAuth2Resp;
            self.authused = SASL_MECH_OAUTHBEARER;
        }

        // --- 7. XOAUTH2 ----------------------------------------------------
        if mech.is_none() && oauth_bearer.is_some() && (enabled & SASL_MECH_XOAUTH2) != 0 {
            if want_ir {
                resp = Some(bearer::sasl_xoauth_bearer_message(
                    params.user,
                    oauth_bearer.unwrap_or_default(),
                )?);
            }
            mech = Some(SASL_MECH_XOAUTH2);
            state1 = SaslState::OAuth2;
            self.authused = SASL_MECH_XOAUTH2;
        }

        // --- 8. PLAIN ------------------------------------------------------
        if mech.is_none() && (enabled & SASL_MECH_PLAIN) != 0 {
            if want_ir {
                resp = Some(basic::sasl_plain_message(
                    params.authzid,
                    params.user,
                    params.passwd,
                )?);
            }
            mech = Some(SASL_MECH_PLAIN);
            state1 = SaslState::Plain;
            self.authused = SASL_MECH_PLAIN;
        }

        // --- 9. LOGIN ------------------------------------------------------
        if mech.is_none() && (enabled & SASL_MECH_LOGIN) != 0 {
            mech = Some(SASL_MECH_LOGIN);
            state1 = SaslState::Login;
            state2 = SaslState::LoginPasswd;
            self.authused = SASL_MECH_LOGIN;
            if want_ir {
                resp = Some(basic::sasl_login_message(params.user));
            }
        }

        // No mechanism selected: stay idle (the caller may then call
        // `is_blocked` for diagnostics).
        let Some(bit) = mech else {
            return Ok(SaslProgress::Idle);
        };

        self.curmech = bit;
        let mech_name = mech_name_from_bit(bit).unwrap_or("");

        // Kerberos is the only mechanism whose response is already base64-framed.
        let already_framed = bit == SASL_MECH_GSSAPI;

        // Frame the initial response (when present). curl only frames a buffer
        // that actually exists, so a `None` IR stays absent.
        let mut wire: Option<Vec<u8>> = match resp {
            Some(raw) if already_framed => Some(raw),
            Some(raw) => Some(build_message(flags, Some(&raw))?),
            None => None,
        };

        // Drop an over-long initial response so it is sent in a later round.
        let maxirlen = proto.maxirlen();
        if let Some(w) = &wire {
            if maxirlen != 0 && mech_name.len() + w.len() > maxirlen {
                wire = None;
            }
        }

        proto.send_auth(mech_name, wire.as_deref())?;

        // With an inline IR sent we await the continuation (`state2`); otherwise
        // we await the first challenge (`state1`).
        self.state = if wire.is_some() { state2 } else { state1 };
        Ok(SaslProgress::InProgress)
    }
}

// ===========================================================================
// Phase F — Continuation state machine (`Curl_sasl_continue`)
// ===========================================================================

impl Sasl {
    /// Advance the SASL exchange by one server response, mirroring
    /// `Curl_sasl_continue`.
    ///
    /// `code` is the protocol response code just received. The method validates
    /// it against the protocol's continuation/final codes, runs the
    /// per-mechanism step for the current [`state`](Self::state) (delegating to
    /// the appropriate sibling auth module), frames and sends the response via
    /// the [`SaslProto`] hooks, and advances the state.
    ///
    /// Returns [`SaslProgress::Done`] once the exchange has concluded
    /// successfully, otherwise [`SaslProgress::InProgress`].
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::LoginDenied`] when the server rejects the exchange
    /// (an unexpected response code or a failed final code). A mechanism that
    /// reports [`CurlError::BadContentEncoding`] triggers a cancel-and-restart
    /// rather than an immediate error. Other errors from the mechanism modules
    /// or the protocol hooks propagate unchanged.
    pub fn cont<P: SaslProto>(
        &mut self,
        proto: &mut P,
        params: &SaslParams,
        code: i32,
    ) -> Result<SaslProgress> {
        let flags = proto.flags();
        let cont_code = proto.cont_code();
        let final_code = proto.final_code();
        let progress = SaslProgress::InProgress;
        let state = self.state;

        // ---- Terminal state: validate the final response code. ------------
        if state == SaslState::Final {
            self.state = SaslState::Stop;
            return if code != final_code {
                Err(CurlError::LoginDenied)
            } else {
                Ok(SaslProgress::Done)
            };
        }

        // ---- A non-continuation code where one was required is fatal. -----
        // CANCEL and OAUTH2_RESP intentionally tolerate other codes.
        if state != SaslState::Cancel && state != SaslState::OAuth2Resp && code != cont_code {
            self.state = SaslState::Stop;
            return Err(CurlError::LoginDenied);
        }

        // ---- States with bespoke control flow. ----------------------------
        match state {
            SaslState::Stop => {
                // Nothing to do; the exchange is finished.
                return Ok(SaslProgress::Done);
            }
            SaslState::OAuth2Resp => {
                // The OAUTHBEARER continuation is optional.
                if code == final_code {
                    self.state = SaslState::Stop;
                    return Ok(SaslProgress::Done);
                } else if code == cont_code {
                    // Acknowledge a failure continuation with a single SOH byte.
                    let mech = self.curmech_name();
                    let wire = build_message(flags, Some(&[0x01]))?;
                    self.state = SaslState::Final;
                    proto.cont_auth(mech, &wire)?;
                    return Ok(progress);
                }
                self.state = SaslState::Stop;
                return Err(CurlError::LoginDenied);
            }
            SaslState::Cancel => {
                // Drop the failed mechanism and re-select the next-best one.
                self.authmechs &= !self.authused;
                self.authused = SASL_AUTH_NONE;
                self.curmech = 0;
                let force_ir = self.force_ir;
                return self.start(proto, params, force_ir);
            }
            _ => {}
        }

        // ---- Per-state response production. -------------------------------
        // `newstate` defaults to FINAL (await the success code); arms override
        // it where a further round is required. `already_framed` is true only
        // for the Kerberos messages, which are produced base64-encoded.
        let mut newstate = SaslState::Final;
        let already_framed;

        // Authorization identity as an optional borrow (Kerberos security msg).
        #[cfg(feature = "gssapi")]
        let authzid: Option<&str> = if params.authzid.is_empty() {
            None
        } else {
            Some(params.authzid)
        };
        // Cached so the GSSAPI mutual branch can read it without re-borrowing.
        #[cfg(feature = "gssapi")]
        let mutual_auth = self.mutual_auth;
        let oauthbearer_selected = self.authused == SASL_MECH_OAUTHBEARER;

        let step: Result<Option<Vec<u8>>> = match state {
            // --- Cleartext mechanisms (RAW responses). ---------------------
            SaslState::Plain => {
                already_framed = false;
                basic::sasl_plain_message(params.authzid, params.user, params.passwd).map(Some)
            }
            SaslState::Login => {
                already_framed = false;
                newstate = SaslState::LoginPasswd;
                Ok(Some(basic::sasl_login_message(params.user)))
            }
            SaslState::LoginPasswd => {
                already_framed = false;
                Ok(Some(basic::sasl_login_message(params.passwd)))
            }
            SaslState::External => {
                already_framed = false;
                Ok(Some(basic::sasl_external_message(params.user)))
            }

            // --- CRAM-MD5 (challenge -> HMAC response). --------------------
            SaslState::CramMd5 => {
                already_framed = false;
                match get_server_message(proto, flags) {
                    Ok(server) => Ok(Some(create_cram_md5_message(
                        &server,
                        params.user,
                        params.passwd,
                    ))),
                    Err(e) => Err(e),
                }
            }

            // --- DIGEST-MD5 (challenge -> digest response). ----------------
            SaslState::DigestMd5 => {
                already_framed = false;
                let service = params
                    .service_name
                    .unwrap_or_else(|| proto.service())
                    .to_owned();
                let r = (|| -> Result<Option<Vec<u8>>> {
                    let server = get_server_message(proto, flags)?;
                    let out = digest::create_digest_md5_message(
                        &server,
                        params.user.as_bytes(),
                        params.passwd.as_bytes(),
                        service.as_bytes(),
                        params.host.as_bytes(),
                    )?;
                    Ok(Some(out))
                })();
                // A base64 protocol expects a trailing empty acknowledgement.
                if r.is_ok() && (flags & SASL_FLAG_BASE64) != 0 {
                    newstate = SaslState::DigestMd5Resp;
                }
                r
            }
            SaslState::DigestMd5Resp => {
                already_framed = false;
                // No payload: emit an empty continuation line.
                Ok(None)
            }

            // --- SCRAM via GSASL (RAW token step). -------------------------
            #[cfg(feature = "gsasl")]
            SaslState::Gsasl => {
                already_framed = false;
                let r = (|| -> Result<Option<Vec<u8>>> {
                    let server = get_server_message(proto, flags)?;
                    let client = self.scram.as_mut().ok_or(CurlError::OutOfMemory)?;
                    Ok(Some(client.token(&server)?))
                })();
                // A non-empty token means another round follows.
                if let Ok(Some(token)) = &r {
                    if !token.is_empty() {
                        newstate = SaslState::Gsasl;
                    }
                }
                r
            }

            // --- NTLM (type-1 / type-2 / type-3). --------------------------
            #[cfg(feature = "ntlm")]
            SaslState::Ntlm => {
                already_framed = false;
                newstate = SaslState::NtlmType2Msg;
                ntlm::create_type1_message(&mut self.ntlm).map(Some)
            }
            #[cfg(feature = "ntlm")]
            SaslState::NtlmType2Msg => {
                already_framed = false;
                (|| -> Result<Option<Vec<u8>>> {
                    let server = get_server_message(proto, flags)?;
                    ntlm::decode_type2_message(&server, &mut self.ntlm)?;
                    let t3 =
                        ntlm::create_type3_message(&mut self.ntlm, params.user, params.passwd)?;
                    Ok(Some(t3))
                })()
            }

            // --- GSSAPI / Kerberos V5 (already base64-framed). -------------
            #[cfg(feature = "gssapi")]
            SaslState::Gssapi => {
                already_framed = true;
                newstate = SaslState::GssapiToken;
                let service = params
                    .service_name
                    .unwrap_or_else(|| proto.service())
                    .to_owned();
                kerberos::create_gssapi_user_message(
                    &mut self.krb5,
                    &service,
                    params.host,
                    mutual_auth,
                    None,
                )
                .map(Some)
            }
            #[cfg(feature = "gssapi")]
            SaslState::GssapiToken => {
                already_framed = true;
                if mutual_auth {
                    newstate = SaslState::GssapiNoData;
                }
                (|| -> Result<Option<Vec<u8>>> {
                    // Kerberos decodes the still-base64 challenge internally.
                    let server = get_raw_server_message(proto)?;
                    let out = if mutual_auth {
                        kerberos::create_gssapi_user_message(
                            &mut self.krb5,
                            "",
                            "",
                            mutual_auth,
                            Some(&server),
                        )?
                    } else {
                        kerberos::create_gssapi_security_message(&mut self.krb5, authzid, &server)?
                    };
                    Ok(Some(out))
                })()
            }
            #[cfg(feature = "gssapi")]
            SaslState::GssapiNoData => {
                already_framed = true;
                (|| -> Result<Option<Vec<u8>>> {
                    let server = get_raw_server_message(proto)?;
                    let out =
                        kerberos::create_gssapi_security_message(&mut self.krb5, authzid, &server)?;
                    Ok(Some(out))
                })()
            }

            // --- OAuth 2.0 authorization message. --------------------------
            SaslState::OAuth2 => {
                already_framed = false;
                if oauthbearer_selected {
                    // Failures may arrive as a continuation for OAUTHBEARER.
                    newstate = SaslState::OAuth2Resp;
                    bearer::sasl_oauth_bearer_message(
                        params.user,
                        params.host,
                        params.port,
                        params.bearer.unwrap_or_default(),
                    )
                    .map(Some)
                } else {
                    bearer::sasl_xoauth_bearer_message(
                        params.user,
                        params.bearer.unwrap_or_default(),
                    )
                    .map(Some)
                }
            }

            // Any state not handled above (including mechanisms whose feature
            // is compiled out, which can never be selected) is a logic error.
            _ => {
                already_framed = false;
                Err(CurlError::UnsupportedProtocol)
            }
        };

        // ---- Post-step handling (mirrors curl's `switch(result)`). --------
        match step {
            // A mechanism asked to cancel: tell the protocol, then re-select.
            Err(CurlError::BadContentEncoding) => {
                let mech = self.curmech_name();
                let r = proto.cancel_auth(mech);
                self.state = SaslState::Cancel;
                r.map(|()| progress)
            }
            // Success: advance state, frame the response, and send it.
            Ok(resp) => {
                self.state = newstate;
                let mech = self.curmech_name();
                let wire = if already_framed {
                    resp.unwrap_or_default()
                } else {
                    build_message(flags, resp.as_deref())?
                };
                proto.cont_auth(mech, &wire)?;
                Ok(progress)
            }
            // Any other error stops the exchange.
            Err(e) => {
                self.state = SaslState::Stop;
                Err(e)
            }
        }
    }
}

// ===========================================================================
// Phase I — Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::CURLAUTH_NONE;
    use std::collections::VecDeque;

    /// Typical IMAP/SMTP-style continuation/final codes used by the tests.
    const CONT: i32 = 334;
    const FINAL: i32 = 235;

    /// A controllable [`SaslProto`] for driving exchanges in isolation. It
    /// records every outgoing message and replays a queue of server messages.
    struct MockProto {
        service: String,
        maxirlen: usize,
        cont_code: i32,
        final_code: i32,
        def_mechs: u16,
        flags: u16,
        /// `send_auth` calls: `(mechanism, optional initial response)`.
        sent: Vec<(String, Option<Vec<u8>>)>,
        /// `cont_auth` calls: `(mechanism, wire bytes)`.
        cont: Vec<(String, Vec<u8>)>,
        /// `cancel_auth` calls: the mechanism name.
        cancelled: Vec<String>,
        /// FIFO of raw server messages returned by `get_message`.
        server: VecDeque<Vec<u8>>,
    }

    impl MockProto {
        /// A base64-framed protocol (IMAP/SMTP/POP3-like) with the default
        /// mechanism set, no IR-length limit.
        fn base64(def_mechs: u16) -> Self {
            MockProto {
                service: "imap".to_string(),
                maxirlen: 0,
                cont_code: CONT,
                final_code: FINAL,
                def_mechs,
                flags: SASL_FLAG_BASE64,
                sent: Vec::new(),
                cont: Vec::new(),
                cancelled: Vec::new(),
                server: VecDeque::new(),
            }
        }

        /// Queue a raw server message (already in its on-the-wire form).
        fn push_server(&mut self, msg: &[u8]) {
            self.server.push_back(msg.to_vec());
        }
    }

    impl SaslProto for MockProto {
        fn service(&self) -> &str {
            &self.service
        }
        fn maxirlen(&self) -> usize {
            self.maxirlen
        }
        fn cont_code(&self) -> i32 {
            self.cont_code
        }
        fn final_code(&self) -> i32 {
            self.final_code
        }
        fn def_mechs(&self) -> u16 {
            self.def_mechs
        }
        fn flags(&self) -> u16 {
            self.flags
        }
        fn send_auth(&mut self, mech: &str, initial_resp: Option<&[u8]>) -> Result<()> {
            self.sent
                .push((mech.to_string(), initial_resp.map(<[u8]>::to_vec)));
            Ok(())
        }
        fn cont_auth(&mut self, mech: &str, resp: &[u8]) -> Result<()> {
            self.cont.push((mech.to_string(), resp.to_vec()));
            Ok(())
        }
        fn cancel_auth(&mut self, mech: &str) -> Result<()> {
            self.cancelled.push(mech.to_string());
            Ok(())
        }
        fn get_message(&mut self) -> Result<Vec<u8>> {
            Ok(self.server.pop_front().unwrap_or_default())
        }
    }

    /// Default parameters for a credentialed user with no follow/redirect.
    fn params<'a>(user: &'a str, passwd: &'a str) -> SaslParams<'a> {
        SaslParams {
            user,
            passwd,
            authzid: "",
            host: "mail.example.com",
            port: 143,
            service_name: None,
            bearer: None,
            sasl_ir: false,
            allow_auth_to_other_hosts: false,
            this_is_a_follow: false,
        }
    }

    // ---- Phase A: constant parity -----------------------------------------

    #[test]
    fn mech_bits_match_c_header() {
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
        assert_eq!(SASL_AUTH_NONE, 0);
        assert_eq!(SASL_AUTH_ANY, 0xffff);
        assert_eq!(SASL_AUTH_DEFAULT, SASL_AUTH_ANY & !SASL_MECH_EXTERNAL);
        // EXTERNAL is the one mechanism excluded from the default set.
        assert_eq!(SASL_AUTH_DEFAULT & SASL_MECH_EXTERNAL, 0);
        assert_eq!(SASL_FLAG_BASE64, 0x0001);
    }

    #[test]
    fn mech_name_round_trips_through_bit() {
        for &(name, bit) in MECHTABLE.iter() {
            assert_eq!(mech_name_from_bit(bit), Some(name));
        }
        assert_eq!(mech_name_from_bit(0), None);
    }

    // ---- Phase B: decode_mech boundary cases ------------------------------

    #[test]
    fn decode_mech_exact_match() {
        assert_eq!(decode_mech(b"PLAIN", 5), (SASL_MECH_PLAIN, 5));
        assert_eq!(decode_mech(b"LOGIN", 5), (SASL_MECH_LOGIN, 5));
        assert_eq!(decode_mech(b"CRAM-MD5", 8), (SASL_MECH_CRAM_MD5, 8));
        assert_eq!(decode_mech(b"DIGEST-MD5", 10), (SASL_MECH_DIGEST_MD5, 10));
        assert_eq!(decode_mech(b"EXTERNAL", 8), (SASL_MECH_EXTERNAL, 8));
        assert_eq!(decode_mech(b"OAUTHBEARER", 11), (SASL_MECH_OAUTHBEARER, 11));
        assert_eq!(decode_mech(b"SCRAM-SHA-1", 11), (SASL_MECH_SCRAM_SHA_1, 11));
        assert_eq!(
            decode_mech(b"SCRAM-SHA-256", 13),
            (SASL_MECH_SCRAM_SHA_256, 13)
        );
    }

    #[test]
    fn decode_mech_is_case_insensitive() {
        assert_eq!(decode_mech(b"plain", 5), (SASL_MECH_PLAIN, 5));
        assert_eq!(decode_mech(b"cram-md5", 8), (SASL_MECH_CRAM_MD5, 8));
    }

    #[test]
    fn decode_mech_rejects_continuation_char() {
        // "PLAINX" — the trailing 'X' is an uppercase continuation char, so the
        // "PLAIN" prefix must NOT match.
        assert_eq!(decode_mech(b"PLAINX", 6), (0, 0));
        // A trailing digit is also a continuation char.
        assert_eq!(decode_mech(b"PLAIN1", 6), (0, 0));
        // '-' and '_' are continuation chars too.
        assert_eq!(decode_mech(b"PLAIN-", 6), (0, 0));
        assert_eq!(decode_mech(b"PLAIN_", 6), (0, 0));
    }

    #[test]
    fn decode_mech_accepts_non_continuation_boundary() {
        // A trailing space is NOT a continuation char, so "PLAIN " matches with
        // an effective length of 5 (curl uses this when scanning a mech list).
        assert_eq!(decode_mech(b"PLAIN ", 6), (SASL_MECH_PLAIN, 5));
        assert_eq!(decode_mech(b"PLAIN,LOGIN", 11), (SASL_MECH_PLAIN, 5));
    }

    #[test]
    fn decode_mech_unknown_and_partial() {
        assert_eq!(decode_mech(b"BOGUS", 5), (0, 0));
        assert_eq!(decode_mech(b"", 0), (0, 0));
        // maxlen is clamped to the slice; a too-short window matches nothing.
        assert_eq!(decode_mech(b"PLA", 5), (0, 0));
        // SCRAM-SHA-256 must not be mis-decoded as SCRAM-SHA-1.
        assert_eq!(
            decode_mech(b"SCRAM-SHA-256", 13),
            (SASL_MECH_SCRAM_SHA_256, 13)
        );
    }

    // ---- Phase B: parse_url_auth_option -----------------------------------

    #[test]
    fn parse_url_auth_option_accumulates_and_resets() {
        let mut sasl = Sasl::new();
        // First parse clears the (reset) preferences, then sets PLAIN.
        sasl.parse_url_auth_option(b"PLAIN").unwrap();
        assert_eq!(sasl.prefmech, SASL_MECH_PLAIN);
        assert!(!sasl.resetprefs);
        // Subsequent parses accumulate.
        sasl.parse_url_auth_option(b"LOGIN").unwrap();
        assert_eq!(sasl.prefmech, SASL_MECH_PLAIN | SASL_MECH_LOGIN);
    }

    #[test]
    fn parse_url_auth_option_star_is_default() {
        let mut sasl = Sasl::new();
        sasl.parse_url_auth_option(b"*").unwrap();
        assert_eq!(sasl.prefmech, SASL_AUTH_DEFAULT);
    }

    #[test]
    fn parse_url_auth_option_errors() {
        let mut sasl = Sasl::new();
        assert!(matches!(
            sasl.parse_url_auth_option(b""),
            Err(CurlError::UrlMalformat)
        ));
        assert!(matches!(
            sasl.parse_url_auth_option(b"BOGUS"),
            Err(CurlError::UrlMalformat)
        ));
        // A partial / non-full match (boundary char) is rejected.
        assert!(matches!(
            sasl.parse_url_auth_option(b"PLAINX"),
            Err(CurlError::UrlMalformat)
        ));
    }

    // ---- Phase C: init + can_authenticate ---------------------------------

    #[test]
    fn init_uses_protocol_defaults_for_basic() {
        let proto = MockProto::base64(SASL_MECH_PLAIN | SASL_MECH_LOGIN);
        let mut sasl = Sasl::new();
        // CURLAUTH_BASIC alone keeps the protocol defaults.
        sasl.init(&proto, CURLAUTH_BASIC);
        assert_eq!(sasl.prefmech, SASL_MECH_PLAIN | SASL_MECH_LOGIN);
        assert_eq!(sasl.state, SaslState::Stop);
        assert!(sasl.resetprefs);
    }

    #[test]
    fn init_maps_httpauth_bits() {
        let proto = MockProto::base64(SASL_AUTH_DEFAULT);

        let mut digest = Sasl::new();
        digest.init(&proto, CURLAUTH_DIGEST);
        assert_eq!(digest.prefmech, SASL_MECH_DIGEST_MD5);

        let mut bearer = Sasl::new();
        bearer.init(&proto, CURLAUTH_BEARER);
        assert_eq!(bearer.prefmech, SASL_MECH_OAUTHBEARER | SASL_MECH_XOAUTH2);

        let mut combo = Sasl::new();
        combo.init(&proto, CURLAUTH_BASIC | CURLAUTH_DIGEST);
        assert_eq!(
            combo.prefmech,
            SASL_MECH_PLAIN | SASL_MECH_LOGIN | SASL_MECH_DIGEST_MD5
        );

        // CURLAUTH_NONE maps to no mechanisms, so the defaults are retained.
        let mut none = Sasl::new();
        none.init(&proto, CURLAUTH_NONE);
        assert_eq!(none.prefmech, SASL_AUTH_DEFAULT);
    }

    #[test]
    fn can_authenticate_rules() {
        let mut sasl = Sasl::new();
        sasl.prefmech = SASL_AUTH_ANY;
        sasl.authmechs = SASL_MECH_PLAIN;
        // With a username, always true.
        assert!(sasl.can_authenticate("user"));
        // Without a username and without EXTERNAL overlap, false.
        assert!(!sasl.can_authenticate(""));
        // EXTERNAL overlap allows authentication without a username.
        sasl.authmechs = SASL_MECH_EXTERNAL;
        assert!(sasl.can_authenticate(""));
    }

    // ---- Phase D: message framing -----------------------------------------

    #[test]
    fn build_message_base64_conventions() {
        // None -> "" (empty continuation line).
        assert_eq!(build_message(SASL_FLAG_BASE64, None).unwrap(), b"");
        // Explicit empty -> "=" (wire-critical "present but empty" marker).
        assert_eq!(build_message(SASL_FLAG_BASE64, Some(b"")).unwrap(), b"=");
        // Data -> base64.
        assert_eq!(
            build_message(SASL_FLAG_BASE64, Some(b"hello")).unwrap(),
            b"aGVsbG8="
        );
    }

    #[test]
    fn build_message_non_base64_passthrough() {
        assert_eq!(build_message(0, Some(b"hello")).unwrap(), b"hello");
        assert_eq!(build_message(0, Some(b"")).unwrap(), b"");
        assert_eq!(build_message(0, None).unwrap(), b"");
    }

    #[test]
    fn get_server_message_decodes_and_handles_empty() {
        let mut proto = MockProto::base64(SASL_MECH_PLAIN);
        // base64 "aGVsbG8=" decodes to "hello".
        proto.push_server(b"aGVsbG8=");
        assert_eq!(
            get_server_message(&mut proto, SASL_FLAG_BASE64).unwrap(),
            b"hello"
        );
        // A lone "=" is the empty-data marker.
        proto.push_server(b"=");
        assert_eq!(
            get_server_message(&mut proto, SASL_FLAG_BASE64).unwrap(),
            b""
        );
        // An empty payload is also empty.
        proto.push_server(b"");
        assert_eq!(
            get_server_message(&mut proto, SASL_FLAG_BASE64).unwrap(),
            b""
        );
        // Without the base64 flag, the payload is returned verbatim.
        proto.push_server(b"raw-bytes");
        assert_eq!(get_server_message(&mut proto, 0).unwrap(), b"raw-bytes");
    }

    // ---- Phase G: CRAM-MD5 (RFC 2195) -------------------------------------

    #[test]
    fn cram_md5_rfc2195_vector() {
        // RFC 2195 §2 worked example.
        let challenge = b"<1896.697170952@postoffice.reston.mci.net>";
        let msg = create_cram_md5_message(challenge, "tim", "tanstaaftanstaaf");
        assert_eq!(msg, b"tim b913a602c7eda7a495b4e6e7334d3890".to_vec());
    }

    #[test]
    fn cram_md5_empty_challenge_still_hmacs() {
        // An empty challenge HMACs over empty data and still produces 32 hex
        // chars after "<user> ".
        let msg = create_cram_md5_message(b"", "bob", "secret");
        let text = String::from_utf8(msg).unwrap();
        assert!(text.starts_with("bob "));
        let hex = &text[4..];
        assert_eq!(hex.len(), 32);
        assert!(hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    // ---- Phase E: mechanism selection priority ----------------------------

    #[test]
    fn selection_prefers_digest_over_plain_and_login() {
        let mut proto = MockProto::base64(SASL_AUTH_DEFAULT);
        let mut sasl = Sasl::new();
        sasl.prefmech = SASL_AUTH_ANY;
        sasl.authmechs = SASL_MECH_PLAIN | SASL_MECH_LOGIN | SASL_MECH_DIGEST_MD5;

        let progress = sasl
            .start(&mut proto, &params("user", "pass"), false)
            .unwrap();

        assert_eq!(progress, SaslProgress::InProgress);
        assert_eq!(sasl.authused, SASL_MECH_DIGEST_MD5);
        assert_eq!(sasl.state, SaslState::DigestMd5);
        assert_eq!(sasl.curmech, SASL_MECH_DIGEST_MD5);
        // DIGEST-MD5 sends no initial response (it needs the challenge first).
        assert_eq!(proto.sent, vec![("DIGEST-MD5".to_string(), None)]);
    }

    #[test]
    fn selection_prefers_external_when_no_password() {
        let mut proto = MockProto::base64(SASL_AUTH_DEFAULT);
        let mut sasl = Sasl::new();
        sasl.prefmech = SASL_AUTH_ANY;
        sasl.authmechs = SASL_MECH_EXTERNAL | SASL_MECH_PLAIN;

        // No password -> EXTERNAL wins over PLAIN.
        sasl.start(&mut proto, &params("user", ""), false).unwrap();
        assert_eq!(sasl.authused, SASL_MECH_EXTERNAL);
        assert_eq!(sasl.state, SaslState::External);
    }

    #[test]
    fn selection_skips_external_with_password() {
        let mut proto = MockProto::base64(SASL_AUTH_DEFAULT);
        let mut sasl = Sasl::new();
        sasl.prefmech = SASL_AUTH_ANY;
        sasl.authmechs = SASL_MECH_EXTERNAL | SASL_MECH_PLAIN;

        // With a password, EXTERNAL is skipped and PLAIN is chosen.
        sasl.start(&mut proto, &params("user", "pass"), false)
            .unwrap();
        assert_eq!(sasl.authused, SASL_MECH_PLAIN);
        assert_eq!(sasl.state, SaslState::Plain);
    }

    #[test]
    fn selection_login_last_resort() {
        let mut proto = MockProto::base64(SASL_AUTH_DEFAULT);
        let mut sasl = Sasl::new();
        sasl.prefmech = SASL_AUTH_ANY;
        sasl.authmechs = SASL_MECH_LOGIN;

        sasl.start(&mut proto, &params("user", "pass"), false)
            .unwrap();
        assert_eq!(sasl.authused, SASL_MECH_LOGIN);
        assert_eq!(sasl.state, SaslState::Login);
    }

    #[test]
    fn selection_none_when_no_overlap() {
        let mut proto = MockProto::base64(SASL_AUTH_DEFAULT);
        let mut sasl = Sasl::new();
        sasl.prefmech = SASL_MECH_PLAIN;
        sasl.authmechs = SASL_MECH_NTLM; // no overlap with prefmech

        let progress = sasl
            .start(&mut proto, &params("user", "pass"), false)
            .unwrap();
        assert_eq!(progress, SaslProgress::Idle);
        assert_eq!(sasl.authused, SASL_AUTH_NONE);
        assert!(proto.sent.is_empty());
        // is_blocked always reports login denied.
        assert!(matches!(sasl.is_blocked(), Err(CurlError::LoginDenied)));
    }

    #[cfg(feature = "gsasl")]
    #[test]
    fn selection_prefers_scram_over_digest() {
        let mut proto = MockProto::base64(SASL_AUTH_DEFAULT);
        let mut sasl = Sasl::new();
        sasl.prefmech = SASL_AUTH_ANY;
        // SCRAM-SHA-256 must be chosen ahead of DIGEST-MD5/PLAIN/LOGIN.
        sasl.authmechs =
            SASL_MECH_PLAIN | SASL_MECH_LOGIN | SASL_MECH_DIGEST_MD5 | SASL_MECH_SCRAM_SHA_256;

        sasl.start(&mut proto, &params("user", "pass"), false)
            .unwrap();
        assert_eq!(sasl.authused, SASL_MECH_SCRAM_SHA_256);
        assert_eq!(sasl.state, SaslState::Gsasl);
    }

    // ---- Phase F: full exchanges ------------------------------------------

    #[test]
    fn plain_exchange_state_transitions() {
        let mut proto = MockProto::base64(SASL_MECH_PLAIN);
        let mut sasl = Sasl::new();
        sasl.init(&proto, CURLAUTH_BASIC);
        sasl.authmechs = SASL_MECH_PLAIN;

        // start: PLAIN selected, no IR -> state PLAIN.
        let p = sasl
            .start(&mut proto, &params("user", "pass"), false)
            .unwrap();
        assert_eq!(p, SaslProgress::InProgress);
        assert_eq!(sasl.state, SaslState::Plain);
        assert_eq!(proto.sent, vec![("PLAIN".to_string(), None)]);

        // Server sends a continuation prompt -> we send the PLAIN response and
        // advance to FINAL.
        let p = sasl
            .cont(&mut proto, &params("user", "pass"), CONT)
            .unwrap();
        assert_eq!(p, SaslProgress::InProgress);
        assert_eq!(sasl.state, SaslState::Final);
        assert_eq!(proto.cont.len(), 1);
        assert_eq!(proto.cont[0].0, "PLAIN");
        // The wire response is base64 of "\0user\0pass".
        let decoded = base64_decode(&proto.cont[0].1).unwrap();
        assert_eq!(decoded, b"\0user\0pass");

        // Server accepts -> DONE, state STOP.
        let p = sasl
            .cont(&mut proto, &params("user", "pass"), FINAL)
            .unwrap();
        assert_eq!(p, SaslProgress::Done);
        assert_eq!(sasl.state, SaslState::Stop);
    }

    #[test]
    fn plain_exchange_with_initial_response() {
        // With sasl_ir, the initial response is sent inline and the state jumps
        // straight to FINAL (state2).
        let mut proto = MockProto::base64(SASL_MECH_PLAIN);
        let mut sasl = Sasl::new();
        sasl.authmechs = SASL_MECH_PLAIN;
        sasl.prefmech = SASL_MECH_PLAIN;

        let mut p = params("user", "pass");
        p.sasl_ir = true;
        sasl.start(&mut proto, &p, false).unwrap();
        assert_eq!(sasl.state, SaslState::Final);
        assert_eq!(proto.sent.len(), 1);
        assert_eq!(proto.sent[0].0, "PLAIN");
        let ir = proto.sent[0].1.as_ref().expect("IR present");
        assert_eq!(base64_decode(ir).unwrap(), b"\0user\0pass");
    }

    #[test]
    fn cram_md5_exchange_produces_rfc_vector() {
        let mut proto = MockProto::base64(SASL_MECH_CRAM_MD5);
        let mut sasl = Sasl::new();
        sasl.authmechs = SASL_MECH_CRAM_MD5;
        sasl.prefmech = SASL_MECH_CRAM_MD5;

        // start: CRAM-MD5 selected, no IR.
        sasl.start(&mut proto, &params("tim", "tanstaaftanstaaf"), false)
            .unwrap();
        assert_eq!(sasl.state, SaslState::CramMd5);

        // Server sends the RFC 2195 challenge (base64-encoded on the wire).
        let challenge = b"<1896.697170952@postoffice.reston.mci.net>";
        let encoded = base64_encode(challenge).unwrap();
        proto.push_server(&encoded);

        sasl.cont(&mut proto, &params("tim", "tanstaaftanstaaf"), CONT)
            .unwrap();
        assert_eq!(sasl.state, SaslState::Final);
        // The response decodes to the RFC 2195 expected value.
        let decoded = base64_decode(&proto.cont[0].1).unwrap();
        assert_eq!(decoded, b"tim b913a602c7eda7a495b4e6e7334d3890".to_vec());
    }

    #[test]
    fn login_exchange_sends_username_then_password() {
        let mut proto = MockProto::base64(SASL_MECH_LOGIN);
        let mut sasl = Sasl::new();
        sasl.authmechs = SASL_MECH_LOGIN;
        sasl.prefmech = SASL_MECH_LOGIN;

        sasl.start(&mut proto, &params("bob", "s3cret"), false)
            .unwrap();
        assert_eq!(sasl.state, SaslState::Login);

        // First continuation -> username, advance to LOGIN_PASSWD.
        sasl.cont(&mut proto, &params("bob", "s3cret"), CONT)
            .unwrap();
        assert_eq!(sasl.state, SaslState::LoginPasswd);
        assert_eq!(base64_decode(&proto.cont[0].1).unwrap(), b"bob");

        // Second continuation -> password, advance to FINAL.
        sasl.cont(&mut proto, &params("bob", "s3cret"), CONT)
            .unwrap();
        assert_eq!(sasl.state, SaslState::Final);
        assert_eq!(base64_decode(&proto.cont[1].1).unwrap(), b"s3cret");

        // Final code completes the exchange.
        let p = sasl
            .cont(&mut proto, &params("bob", "s3cret"), FINAL)
            .unwrap();
        assert_eq!(p, SaslProgress::Done);
        assert_eq!(sasl.state, SaslState::Stop);
    }

    #[test]
    fn unexpected_code_denies_login() {
        let mut proto = MockProto::base64(SASL_MECH_PLAIN);
        let mut sasl = Sasl::new();
        sasl.authmechs = SASL_MECH_PLAIN;
        sasl.prefmech = SASL_MECH_PLAIN;
        sasl.start(&mut proto, &params("user", "pass"), false)
            .unwrap();

        // A non-continuation, non-final code while awaiting the PLAIN challenge
        // is rejected.
        let r = sasl.cont(&mut proto, &params("user", "pass"), 500);
        assert!(matches!(r, Err(CurlError::LoginDenied)));
        assert_eq!(sasl.state, SaslState::Stop);
    }

    #[test]
    fn final_state_wrong_code_denies_login() {
        let mut proto = MockProto::base64(SASL_MECH_PLAIN);
        let mut sasl = Sasl::new();
        sasl.state = SaslState::Final;
        // At FINAL, anything other than the final code is a denial.
        let r = sasl.cont(&mut proto, &params("user", "pass"), 500);
        assert!(matches!(r, Err(CurlError::LoginDenied)));
        assert_eq!(sasl.state, SaslState::Stop);
    }

    #[test]
    fn maxirlen_drops_overlong_initial_response() {
        let mut proto = MockProto::base64(SASL_MECH_PLAIN);
        // Force a tiny IR budget so the PLAIN IR is dropped.
        proto.maxirlen = 4;
        let mut sasl = Sasl::new();
        sasl.authmechs = SASL_MECH_PLAIN;
        sasl.prefmech = SASL_MECH_PLAIN;

        let mut p = params("averylongusername", "pass");
        p.sasl_ir = true;
        sasl.start(&mut proto, &p, false).unwrap();
        // IR dropped -> sent without an initial response, state stays PLAIN.
        assert_eq!(sasl.state, SaslState::Plain);
        assert_eq!(proto.sent[0].1, None);
    }
}
