//! SASL authentication framework + CRAM-MD5 mechanism (RFC 2195, RFC 4422).
//!
//! Pure-Rust rewrite of `lib/curl_sasl.c` (934 lines) and `lib/vauth/cram.c`
//! (87 lines). Implements the protocol-agnostic SASL authentication state
//! machine used by IMAP, POP3, SMTP, and LDAP protocols, plus the CRAM-MD5
//! mechanism.
//!
//! # Architecture
//!
//! The SASL framework is protocol-agnostic: protocol-specific details (SMTP
//! AUTH, IMAP AUTHENTICATE, POP3 AUTH) are supplied through the [`SaslProto`]
//! trait. The framework drives a state machine ([`SaslState`]) that walks
//! through challenge-response rounds for the negotiated mechanism.
//!
//! # Mechanism Negotiation
//!
//! Mechanisms are tried in decreasing order of security:
//!
//! 1. EXTERNAL (if no password)
//! 2. GSSAPI (Kerberos V5)
//! 3. SCRAM-SHA-256 / SCRAM-SHA-1
//! 4. DIGEST-MD5 / CRAM-MD5
//! 5. NTLM
//! 6. OAUTHBEARER
//! 7. XOAUTH2
//! 8. PLAIN
//! 9. LOGIN
//!
//! # References
//!
//! - RFC 2195 — CRAM-MD5 authentication
//! - RFC 2831 — DIGEST-MD5 authentication
//! - RFC 4422 — Simple Authentication and Security Layer (SASL)
//! - RFC 4616 — PLAIN authentication
//! - RFC 5802 — SCRAM-SHA-1 authentication
//! - RFC 7628 — OAuth SASL mechanisms
//! - RFC 7677 — SCRAM-SHA-256 authentication

use crate::auth::basic;
use crate::auth::bearer;
use crate::auth::digest;
use crate::auth::kerberos::{self, Kerberos5Data};
use crate::auth::ntlm::{self, NtlmData};
use crate::auth::scram::{self, ScramData};
use crate::error::CurlError;
use crate::util::base64;
use crate::util::hmac::hmac_md5;

// ===========================================================================
// Mechanism Flag Constants — match C `curl_sasl.h` lines 32–42 exactly
// ===========================================================================

/// LOGIN SASL mechanism (bit 0).
pub const SASL_MECH_LOGIN: u16 = 1 << 0;
/// PLAIN SASL mechanism (bit 1).
pub const SASL_MECH_PLAIN: u16 = 1 << 1;
/// CRAM-MD5 SASL mechanism (bit 2).
pub const SASL_MECH_CRAM_MD5: u16 = 1 << 2;
/// DIGEST-MD5 SASL mechanism (bit 3).
pub const SASL_MECH_DIGEST_MD5: u16 = 1 << 3;
/// GSSAPI (Kerberos V5) SASL mechanism (bit 4).
pub const SASL_MECH_GSSAPI: u16 = 1 << 4;
/// EXTERNAL SASL mechanism (bit 5).
pub const SASL_MECH_EXTERNAL: u16 = 1 << 5;
/// NTLM SASL mechanism (bit 6).
pub const SASL_MECH_NTLM: u16 = 1 << 6;
/// XOAUTH2 SASL mechanism (bit 7).
pub const SASL_MECH_XOAUTH2: u16 = 1 << 7;
/// OAUTHBEARER SASL mechanism (bit 8).
pub const SASL_MECH_OAUTHBEARER: u16 = 1 << 8;
/// SCRAM-SHA-1 SASL mechanism (bit 9).
pub const SASL_MECH_SCRAM_SHA_1: u16 = 1 << 9;
/// SCRAM-SHA-256 SASL mechanism (bit 10).
pub const SASL_MECH_SCRAM_SHA_256: u16 = 1 << 10;

// ===========================================================================
// Composite Auth Constants
// ===========================================================================

/// No authentication mechanism selected or available.
pub const SASL_AUTH_NONE: u16 = 0;
/// Any authentication mechanism is acceptable.
pub const SASL_AUTH_ANY: u16 = 0xFFFF;
/// Default authentication mechanism set — all except EXTERNAL.
pub const SASL_AUTH_DEFAULT: u16 = SASL_AUTH_ANY & !SASL_MECH_EXTERNAL;

// ===========================================================================
// Mechanism Name Strings
// ===========================================================================

/// LOGIN mechanism wire name.
pub const SASL_MECH_STRING_LOGIN: &str = "LOGIN";
/// PLAIN mechanism wire name.
pub const SASL_MECH_STRING_PLAIN: &str = "PLAIN";
/// CRAM-MD5 mechanism wire name.
pub const SASL_MECH_STRING_CRAM_MD5: &str = "CRAM-MD5";
/// DIGEST-MD5 mechanism wire name.
pub const SASL_MECH_STRING_DIGEST_MD5: &str = "DIGEST-MD5";
/// GSSAPI mechanism wire name.
pub const SASL_MECH_STRING_GSSAPI: &str = "GSSAPI";
/// EXTERNAL mechanism wire name.
pub const SASL_MECH_STRING_EXTERNAL: &str = "EXTERNAL";
/// NTLM mechanism wire name.
pub const SASL_MECH_STRING_NTLM: &str = "NTLM";
/// XOAUTH2 mechanism wire name.
pub const SASL_MECH_STRING_XOAUTH2: &str = "XOAUTH2";
/// OAUTHBEARER mechanism wire name.
pub const SASL_MECH_STRING_OAUTHBEARER: &str = "OAUTHBEARER";
/// SCRAM-SHA-1 mechanism wire name.
pub const SASL_MECH_STRING_SCRAM_SHA_1: &str = "SCRAM-SHA-1";
/// SCRAM-SHA-256 mechanism wire name.
pub const SASL_MECH_STRING_SCRAM_SHA_256: &str = "SCRAM-SHA-256";

// ===========================================================================
// SASL Flags
// ===========================================================================

/// Flag indicating that messages are base64-encoded on the wire.
pub const SASL_FLAG_BASE64: u16 = 0x0001;

// ===========================================================================
// HTTP Auth Flag Constants (match C CURLAUTH_* for Sasl::init mapping)
// ===========================================================================

const CURLAUTH_BASIC: u64 = 1 << 0;
const CURLAUTH_DIGEST: u64 = 1 << 1;
const CURLAUTH_GSSAPI: u64 = 1 << 2;
const CURLAUTH_NTLM: u64 = 1 << 3;
const CURLAUTH_BEARER: u64 = 1 << 6;

// ===========================================================================
// Mechanism Table — matching C mechtable[] (curl_sasl.c lines 49–66)
// ===========================================================================

struct MechEntry {
    name: &'static str,
    bit: u16,
}

const MECH_TABLE: &[MechEntry] = &[
    MechEntry { name: "LOGIN", bit: SASL_MECH_LOGIN },
    MechEntry { name: "PLAIN", bit: SASL_MECH_PLAIN },
    MechEntry { name: "CRAM-MD5", bit: SASL_MECH_CRAM_MD5 },
    MechEntry { name: "DIGEST-MD5", bit: SASL_MECH_DIGEST_MD5 },
    MechEntry { name: "GSSAPI", bit: SASL_MECH_GSSAPI },
    MechEntry { name: "EXTERNAL", bit: SASL_MECH_EXTERNAL },
    MechEntry { name: "NTLM", bit: SASL_MECH_NTLM },
    MechEntry { name: "XOAUTH2", bit: SASL_MECH_XOAUTH2 },
    MechEntry { name: "OAUTHBEARER", bit: SASL_MECH_OAUTHBEARER },
    MechEntry { name: "SCRAM-SHA-1", bit: SASL_MECH_SCRAM_SHA_1 },
    MechEntry { name: "SCRAM-SHA-256", bit: SASL_MECH_SCRAM_SHA_256 },
];

// ===========================================================================
// decode_mech — match C Curl_sasl_decode_mech (curl_sasl.c lines 81–103)
// ===========================================================================

/// Convert a SASL mechanism name at the start of `ptr` into a bitflag token.
///
/// Performs case-insensitive prefix matching against the mechanism table.
/// Returns `(bit, consumed_len)` on match, or `(0, 0)` on no match.
pub fn decode_mech(ptr: &str, maxlen: usize) -> (u16, usize) {
    let ptr_bytes = ptr.as_bytes();
    let actual_len = ptr_bytes.len().min(maxlen);

    for entry in MECH_TABLE {
        let elen = entry.name.len();
        if actual_len >= elen {
            let candidate = &ptr_bytes[..elen];
            if candidate.eq_ignore_ascii_case(entry.name.as_bytes()) {
                if actual_len == elen {
                    return (entry.bit, elen);
                }
                // Delimiter check: next char must NOT be uppercase/digit/'-'/'_'.
                let c = ptr_bytes[elen];
                if !c.is_ascii_uppercase()
                    && !c.is_ascii_digit()
                    && c != b'-'
                    && c != b'_'
                {
                    return (entry.bit, elen);
                }
            }
        }
    }

    (0, 0)
}

// ===========================================================================
// SaslState — SASL machine states (match C saslstate)
// ===========================================================================

/// SASL authentication state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaslState {
    /// Authentication stopped or not started.
    Stop,
    /// Sending PLAIN credentials.
    Plain,
    /// Sending LOGIN username.
    Login,
    /// Sending LOGIN password.
    LoginPasswd,
    /// Sending EXTERNAL identity.
    External,
    /// Processing CRAM-MD5 challenge.
    CramMd5,
    /// Processing DIGEST-MD5 challenge.
    DigestMd5,
    /// Sending DIGEST-MD5 empty acknowledgement.
    DigestMd5Resp,
    /// Sending NTLM Type-1 message.
    Ntlm,
    /// Processing NTLM Type-2 and sending Type-3.
    NtlmType2Msg,
    /// Sending GSSAPI initial token.
    Gssapi,
    /// Processing GSSAPI token exchange.
    GssapiToken,
    /// GSSAPI no-data security negotiation.
    GssapiNoData,
    /// Sending OAuth2 token.
    OAuth2,
    /// Processing OAuth2 continuation response.
    OAuth2Resp,
    /// GSASL (SCRAM) authentication round.
    Gsasl,
    /// Cancelling current mechanism and retrying.
    Cancel,
    /// Waiting for final server response code.
    Final,
}

impl std::fmt::Display for SaslState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
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
        };
        f.write_str(name)
    }
}

// ===========================================================================
// SaslProgress — progress indicator (match C saslprogress)
// ===========================================================================

/// Progress indicator for SASL authentication exchanges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaslProgress {
    /// No authentication in progress.
    Idle,
    /// Authentication is in progress; more rounds expected.
    InProgress,
    /// Authentication is complete (success or failure).
    Done,
}

// ===========================================================================
// SaslProto — protocol-dependent parameters (match C struct SASLproto)
// ===========================================================================

/// Protocol-dependent SASL parameters.
///
/// Each protocol (IMAP, SMTP, POP3, LDAP) implements this trait to provide
/// protocol-specific auth command sending and response retrieval.
pub trait SaslProto {
    /// Returns the service name (e.g. `"imap"`, `"smtp"`, `"pop"`).
    fn service(&self) -> &str;
    /// Send the initial authentication command.
    fn send_auth(&self, mech: &str, initial_response: Option<&[u8]>) -> Result<(), CurlError>;
    /// Send a continuation authentication response.
    fn cont_auth(&self, mech: &str, response: &[u8]) -> Result<(), CurlError>;
    /// Send an authentication cancellation command.
    fn cancel_auth(&self, mech: &str) -> Result<(), CurlError>;
    /// Retrieve the server's SASL response message (raw bytes).
    fn get_message(&self) -> Result<Vec<u8>, CurlError>;
    /// Maximum allowed initial response length. 0 = no maximum.
    fn max_ir_len(&self) -> usize;
    /// The response code indicating the server expects a continuation.
    fn cont_code(&self) -> i32;
    /// The response code indicating authentication succeeded.
    fn final_code(&self) -> i32;
    /// The default mechanism set for this protocol.
    fn default_mechs(&self) -> u16;
    /// Configuration flags (e.g. [`SASL_FLAG_BASE64`]).
    fn flags(&self) -> u16;
}

// ===========================================================================
// SaslAuthContext — parameters passed through start/continue methods
// ===========================================================================

/// Authentication context data needed by the SASL state machine.
pub struct SaslAuthContext<'a> {
    /// The authentication username.
    pub user: &'a str,
    /// The authentication password.
    pub passwd: &'a str,
    /// The SASL authorization identity (authzid), if any.
    pub authzid: Option<&'a str>,
    /// The server hostname for SPN construction.
    pub host: &'a str,
    /// The server port number.
    pub port: u16,
    /// The OAuth2 bearer token, if available.
    pub bearer: Option<&'a str>,
    /// The override service name, if set via CURLOPT_SERVICE_NAME.
    pub service_name: Option<&'a str>,
    /// Whether the protocol supports initial response (`sasl_ir` option).
    pub sasl_ir: bool,
    /// Whether to allow auth to hosts other than the original (redirect).
    pub allow_auth_to_other_hosts: bool,
    /// Whether this is a redirect follow.
    pub is_follow: bool,
    /// Mutable NTLM state data for the connection.
    pub ntlm: &'a mut NtlmData,
    /// Mutable Kerberos5 state data for the connection.
    pub krb5: &'a mut Kerberos5Data,
    /// Mutable SCRAM state data for the connection.
    pub scram: &'a mut ScramData,
}

// ===========================================================================
// Internal selection result
// ===========================================================================

struct SaslSelection {
    mech: &'static str,
    state1: SaslState,
    state2: SaslState,
    authused: u16,
    initial_response: Option<Vec<u8>>,
    result: Result<(), CurlError>,
}

// ===========================================================================
// Sasl — per-connection SASL state (match C struct SASL)
// ===========================================================================

/// Per-connection SASL authentication state.
pub struct Sasl {
    /// Current state machine state.
    pub state: SaslState,
    /// Name of the currently negotiated mechanism.
    pub curmech: Option<String>,
    /// Bitmask of mechanisms offered by the server.
    pub authmechs: u16,
    /// Bitmask of mechanisms preferred by the client configuration.
    pub prefmech: u16,
    /// Bitmask indicating which mechanism was used.
    pub authused: u16,
    /// Resets `prefmech` on next [`parse_url_auth_option`] call.
    pub resetprefs: bool,
    /// Whether GSSAPI mutual authentication is enabled.
    pub mutual_auth: bool,
    /// Whether the protocol always supports initial response.
    pub force_ir: bool,
}

impl Sasl {
    /// Create a new `Sasl` instance with the given default mechanism set.
    pub fn new(default_mechs: u16) -> Self {
        Self {
            state: SaslState::Stop,
            curmech: None,
            authmechs: SASL_AUTH_NONE,
            prefmech: default_mechs,
            authused: SASL_AUTH_NONE,
            resetprefs: true,
            mutual_auth: false,
            force_ir: false,
        }
    }

    /// Initialize the SASL structure based on HTTP auth flags.
    ///
    /// Matches C `Curl_sasl_init` in `curl_sasl.c` lines 142–176.
    pub fn init(&mut self, auth_flags: u64, default_mechs: u16) {
        self.state = SaslState::Stop;
        self.curmech = None;
        self.authmechs = SASL_AUTH_NONE;
        self.prefmech = default_mechs;
        self.authused = SASL_AUTH_NONE;
        self.resetprefs = true;
        self.mutual_auth = false;
        self.force_ir = false;

        if auth_flags != CURLAUTH_BASIC {
            let mut mechs: u16 = SASL_AUTH_NONE;
            if auth_flags & CURLAUTH_BASIC != 0 {
                mechs |= SASL_MECH_PLAIN | SASL_MECH_LOGIN;
            }
            if auth_flags & CURLAUTH_DIGEST != 0 {
                mechs |= SASL_MECH_DIGEST_MD5;
            }
            if auth_flags & CURLAUTH_NTLM != 0 {
                mechs |= SASL_MECH_NTLM;
            }
            if auth_flags & CURLAUTH_BEARER != 0 {
                mechs |= SASL_MECH_OAUTHBEARER | SASL_MECH_XOAUTH2;
            }
            if auth_flags & CURLAUTH_GSSAPI != 0 {
                mechs |= SASL_MECH_GSSAPI;
            }
            if mechs != SASL_AUTH_NONE {
                self.prefmech = mechs;
            }
        }
    }

    /// Parse a URL login auth option value (e.g. from `;AUTH=PLAIN`).
    ///
    /// Matches C `Curl_sasl_parse_url_auth_option` lines 110–135.
    pub fn parse_url_auth_option(&mut self, value: &str) -> Result<(), CurlError> {
        if value.is_empty() {
            return Err(CurlError::UrlMalformat);
        }
        if self.resetprefs {
            self.resetprefs = false;
            self.prefmech = SASL_AUTH_NONE;
        }
        if value == "*" {
            self.prefmech = SASL_AUTH_DEFAULT;
        } else {
            let (mechbit, mechlen) = decode_mech(value, value.len());
            if mechbit != 0 && mechlen == value.len() {
                self.prefmech |= mechbit;
            } else {
                return Err(CurlError::UrlMalformat);
            }
        }
        Ok(())
    }

    /// Check if we have enough auth data and capabilities to authenticate.
    ///
    /// Matches C `Curl_sasl_can_authenticate` lines 276–287.
    pub fn can_authenticate(&self, has_user: bool, _has_passwd: bool) -> bool {
        if has_user {
            return true;
        }
        if self.authmechs & self.prefmech & SASL_MECH_EXTERNAL != 0 {
            return true;
        }
        false
    }

    /// Transition to a new SASL state with tracing.
    fn set_state(&mut self, new_state: SaslState) {
        if self.state != new_state {
            tracing::trace!(from = %self.state, to = %new_state, "SASL state change");
        }
        self.state = new_state;
    }

    // -----------------------------------------------------------------------
    // Mechanism selection helpers — one per mechanism family
    // -----------------------------------------------------------------------

    fn choose_external(
        &self,
        enabled: u16,
        passwd: &str,
        user: &str,
        force_ir: bool,
        sasl_ir: bool,
    ) -> Option<SaslSelection> {
        if (enabled & SASL_MECH_EXTERNAL) != 0 && passwd.is_empty() {
            let initial = if force_ir || sasl_ir {
                Some(basic::create_external_message(user))
            } else {
                None
            };
            Some(SaslSelection {
                mech: SASL_MECH_STRING_EXTERNAL,
                state1: SaslState::External,
                state2: SaslState::Final,
                authused: SASL_MECH_EXTERNAL,
                initial_response: initial,
                result: Ok(()),
            })
        } else {
            None
        }
    }

    fn choose_krb5(
        &self,
        enabled: u16,
        ctx: &mut SaslAuthContext<'_>,
        service: &str,
        force_ir: bool,
        sasl_ir: bool,
    ) -> Option<SaslSelection> {
        if (enabled & SASL_MECH_GSSAPI) == 0
            || !kerberos::is_gssapi_supported()
            || !user_contains_domain(ctx.user)
        {
            return None;
        }
        let mut sel = SaslSelection {
            mech: SASL_MECH_STRING_GSSAPI,
            state1: SaslState::Gssapi,
            state2: SaslState::GssapiToken,
            authused: SASL_MECH_GSSAPI,
            initial_response: None,
            result: Ok(()),
        };
        if force_ir || sasl_ir {
            match kerberos::create_gssapi_user_message(service, ctx.host, None, ctx.krb5) {
                Ok(token) => sel.initial_response = Some(token),
                Err(e) => sel.result = Err(e),
            }
        }
        Some(sel)
    }

    fn choose_gsasl(
        &self,
        enabled: u16,
        ctx: &mut SaslAuthContext<'_>,
        force_ir: bool,
        sasl_ir: bool,
    ) -> Option<SaslSelection> {
        if (enabled & (SASL_MECH_SCRAM_SHA_256 | SASL_MECH_SCRAM_SHA_1)) == 0 {
            return None;
        }
        let (mech_str, mech_bit) =
            if (enabled & SASL_MECH_SCRAM_SHA_256) != 0
                && scram::is_scram_supported(SASL_MECH_STRING_SCRAM_SHA_256)
            {
                (SASL_MECH_STRING_SCRAM_SHA_256, SASL_MECH_SCRAM_SHA_256)
            } else if (enabled & SASL_MECH_SCRAM_SHA_1) != 0
                && scram::is_scram_supported(SASL_MECH_STRING_SCRAM_SHA_1)
            {
                (SASL_MECH_STRING_SCRAM_SHA_1, SASL_MECH_SCRAM_SHA_1)
            } else {
                return None;
            };

        let mut sel = SaslSelection {
            mech: mech_str,
            state1: SaslState::Gsasl,
            state2: SaslState::Gsasl,
            authused: mech_bit,
            initial_response: None,
            result: Ok(()),
        };

        match scram::start(ctx.user, ctx.passwd, ctx.scram) {
            Ok(_) => {
                if force_ir || sasl_ir {
                    match scram::token(&[], ctx.scram) {
                        Ok(token) => sel.initial_response = Some(token),
                        Err(e) => sel.result = Err(e),
                    }
                }
            }
            Err(e) => sel.result = Err(e),
        }
        Some(sel)
    }

    fn choose_digest(enabled: u16) -> Option<SaslSelection> {
        if (enabled & SASL_MECH_DIGEST_MD5) != 0 {
            Some(SaslSelection {
                mech: SASL_MECH_STRING_DIGEST_MD5,
                state1: SaslState::DigestMd5,
                state2: SaslState::Final,
                authused: SASL_MECH_DIGEST_MD5,
                initial_response: None,
                result: Ok(()),
            })
        } else if (enabled & SASL_MECH_CRAM_MD5) != 0 {
            Some(SaslSelection {
                mech: SASL_MECH_STRING_CRAM_MD5,
                state1: SaslState::CramMd5,
                state2: SaslState::Final,
                authused: SASL_MECH_CRAM_MD5,
                initial_response: None,
                result: Ok(()),
            })
        } else {
            None
        }
    }

    fn choose_ntlm(
        &self,
        enabled: u16,
        ctx: &mut SaslAuthContext<'_>,
        _service: &str,
        force_ir: bool,
        sasl_ir: bool,
    ) -> Option<SaslSelection> {
        if (enabled & SASL_MECH_NTLM) == 0 {
            return None;
        }
        let mut sel = SaslSelection {
            mech: SASL_MECH_STRING_NTLM,
            state1: SaslState::Ntlm,
            state2: SaslState::NtlmType2Msg,
            authused: SASL_MECH_NTLM,
            initial_response: None,
            result: Ok(()),
        };
        if force_ir || sasl_ir {
            match ntlm::create_type1_message(ctx.ntlm) {
                Ok(msg) => sel.initial_response = Some(msg),
                Err(e) => sel.result = Err(e),
            }
        }
        Some(sel)
    }

    fn choose_oauth(
        &self,
        enabled: u16,
        ctx: &SaslAuthContext<'_>,
        force_ir: bool,
        sasl_ir: bool,
    ) -> Option<SaslSelection> {
        let bearer = effective_bearer(ctx)?;
        if (enabled & SASL_MECH_OAUTHBEARER) == 0 {
            return None;
        }
        let mut sel = SaslSelection {
            mech: SASL_MECH_STRING_OAUTHBEARER,
            state1: SaslState::OAuth2,
            state2: SaslState::OAuth2Resp,
            authused: SASL_MECH_OAUTHBEARER,
            initial_response: None,
            result: Ok(()),
        };
        if force_ir || sasl_ir {
            match bearer::create_oauth_bearer_message(ctx.user, ctx.host, ctx.port, bearer) {
                Ok(msg) => sel.initial_response = Some(msg.into_bytes()),
                Err(e) => sel.result = Err(e),
            }
        }
        Some(sel)
    }

    fn choose_xoauth2(
        &self,
        enabled: u16,
        ctx: &SaslAuthContext<'_>,
        force_ir: bool,
        sasl_ir: bool,
    ) -> Option<SaslSelection> {
        let bearer = effective_bearer(ctx)?;
        if (enabled & SASL_MECH_XOAUTH2) == 0 {
            return None;
        }
        let mut sel = SaslSelection {
            mech: SASL_MECH_STRING_XOAUTH2,
            state1: SaslState::OAuth2,
            state2: SaslState::Final,
            authused: SASL_MECH_XOAUTH2,
            initial_response: None,
            result: Ok(()),
        };
        if force_ir || sasl_ir {
            match bearer::create_xoauth_bearer_message(ctx.user, bearer) {
                Ok(msg) => sel.initial_response = Some(msg.into_bytes()),
                Err(e) => sel.result = Err(e),
            }
        }
        Some(sel)
    }

    fn choose_plain(
        enabled: u16,
        ctx: &SaslAuthContext<'_>,
        force_ir: bool,
        sasl_ir: bool,
    ) -> Option<SaslSelection> {
        if (enabled & SASL_MECH_PLAIN) == 0 {
            return None;
        }
        let mut sel = SaslSelection {
            mech: SASL_MECH_STRING_PLAIN,
            state1: SaslState::Plain,
            state2: SaslState::Final,
            authused: SASL_MECH_PLAIN,
            initial_response: None,
            result: Ok(()),
        };
        if force_ir || sasl_ir {
            match basic::create_plain_message(ctx.authzid, ctx.user, ctx.passwd) {
                Ok(msg) => sel.initial_response = Some(msg),
                Err(e) => sel.result = Err(e),
            }
        }
        Some(sel)
    }

    fn choose_login(
        enabled: u16,
        ctx: &SaslAuthContext<'_>,
        force_ir: bool,
        sasl_ir: bool,
    ) -> Option<SaslSelection> {
        if (enabled & SASL_MECH_LOGIN) == 0 {
            return None;
        }
        let initial = if force_ir || sasl_ir {
            Some(basic::create_login_message(ctx.user))
        } else {
            None
        };
        Some(SaslSelection {
            mech: SASL_MECH_STRING_LOGIN,
            state1: SaslState::Login,
            state2: SaslState::LoginPasswd,
            authused: SASL_MECH_LOGIN,
            initial_response: initial,
            result: Ok(()),
        })
    }

    // -----------------------------------------------------------------------
    // start — begin SASL authentication
    // -----------------------------------------------------------------------

    /// Begin SASL authentication by selecting a mechanism and optionally
    /// sending an initial response.
    ///
    /// Matches C `Curl_sasl_start` in `curl_sasl.c` lines 525–587.
    pub fn start(
        &mut self,
        proto: &dyn SaslProto,
        ctx: &mut SaslAuthContext<'_>,
        force_ir: bool,
    ) -> Result<SaslProgress, CurlError> {
        self.force_ir = force_ir;
        self.authused = 0;

        let enabled = self.authmechs & self.prefmech;
        let service = ctx.service_name.unwrap_or_else(|| proto.service());
        let flags = proto.flags();

        tracing::debug!(
            authmechs = self.authmechs,
            prefmech = self.prefmech,
            enabled = enabled,
            "SASL: starting mechanism selection"
        );

        // Try mechanisms in decreasing order of security (C lines 544–560).
        let selection = self
            .choose_external(enabled, ctx.passwd, ctx.user, force_ir, ctx.sasl_ir)
            .or_else(|| self.choose_krb5(enabled, ctx, service, force_ir, ctx.sasl_ir))
            .or_else(|| self.choose_gsasl(enabled, ctx, force_ir, ctx.sasl_ir))
            .or_else(|| Self::choose_digest(enabled))
            .or_else(|| self.choose_ntlm(enabled, ctx, service, force_ir, ctx.sasl_ir))
            .or_else(|| self.choose_oauth(enabled, ctx, force_ir, ctx.sasl_ir))
            .or_else(|| self.choose_xoauth2(enabled, ctx, force_ir, ctx.sasl_ir))
            .or_else(|| Self::choose_plain(enabled, ctx, force_ir, ctx.sasl_ir))
            .or_else(|| Self::choose_login(enabled, ctx, force_ir, ctx.sasl_ir));

        let sel = match selection {
            Some(s) => s,
            None => return Ok(SaslProgress::Idle),
        };

        sel.result?;

        self.authused = sel.authused;
        self.curmech = Some(sel.mech.to_owned());
        tracing::info!(mechanism = sel.mech, "SASL: selected mechanism");

        // Build the initial response (base64-encode if needed).
        let ir_bytes = sel.initial_response.as_ref().map(|data| build_message(flags, Some(data)));

        // Check maxirlen limit — suppress IR if over the limit.
        let send_ir = match ir_bytes {
            Some(ref ir) => {
                let max = proto.max_ir_len();
                if max > 0 && sel.mech.len() + ir.len() > max {
                    tracing::debug!("SASL: initial response exceeds maxirlen, suppressing");
                    false
                } else {
                    true
                }
            }
            None => false,
        };

        let ir_to_send = if send_ir {
            ir_bytes.as_deref()
        } else {
            None
        };
        proto.send_auth(sel.mech, ir_to_send)?;

        let new_state = if send_ir { sel.state2 } else { sel.state1 };
        self.set_state(new_state);

        Ok(SaslProgress::InProgress)
    }

    // -----------------------------------------------------------------------
    // continue_auth — process server response and advance state machine
    // -----------------------------------------------------------------------

    /// Continue SASL authentication by processing the server's response.
    ///
    /// Matches C `Curl_sasl_continue` in `curl_sasl.c` lines 594–836.
    pub fn continue_auth(
        &mut self,
        code: i32,
        proto: &dyn SaslProto,
        ctx: &mut SaslAuthContext<'_>,
    ) -> Result<SaslProgress, CurlError> {
        let flags = proto.flags();
        let service = ctx.service_name.unwrap_or_else(|| proto.service());
        let mut newstate = SaslState::Final;

        // Handle SASL_FINAL state: check if final code matches.
        if self.state == SaslState::Final {
            let result = if code != proto.final_code() {
                Err(CurlError::LoginDenied)
            } else {
                Ok(())
            };
            self.set_state(SaslState::Stop);
            return match result {
                Ok(()) => Ok(SaslProgress::Done),
                Err(e) => Err(e),
            };
        }

        // For non-CANCEL, non-OAUTH2_RESP states, verify continuation code.
        if self.state != SaslState::Cancel
            && self.state != SaslState::OAuth2Resp
            && code != proto.cont_code()
        {
            self.set_state(SaslState::Stop);
            return Err(CurlError::LoginDenied);
        }

        // Main state dispatch.
        let resp_result: Result<Option<Vec<u8>>, CurlError> = match self.state {
            SaslState::Stop => return Ok(SaslProgress::Done),

            SaslState::Plain => {
                let msg = basic::create_plain_message(ctx.authzid, ctx.user, ctx.passwd)?;
                Ok(Some(msg))
            }

            SaslState::Login => {
                newstate = SaslState::LoginPasswd;
                Ok(Some(basic::create_login_message(ctx.user)))
            }

            SaslState::LoginPasswd => Ok(Some(basic::create_login_message(ctx.passwd))),

            SaslState::External => Ok(Some(basic::create_external_message(ctx.user))),

            SaslState::Gsasl => {
                let server_msg = get_server_message(flags, proto)?;
                match scram::token(&server_msg, ctx.scram) {
                    Ok(resp) => {
                        if !resp.is_empty() {
                            newstate = SaslState::Gsasl;
                        }
                        Ok(Some(resp))
                    }
                    Err(e) => Err(e),
                }
            }

            SaslState::CramMd5 => {
                let server_msg = get_server_message(flags, proto)?;
                let msg = create_cram_md5_message(&server_msg, ctx.user, ctx.passwd)?;
                Ok(Some(msg))
            }

            SaslState::DigestMd5 => {
                let server_msg = get_server_message(flags, proto)?;
                let msg = digest::create_digest_md5_message(
                    ctx.user, ctx.passwd, service, ctx.host, &server_msg,
                )?;
                if (flags & SASL_FLAG_BASE64) != 0 {
                    newstate = SaslState::DigestMd5Resp;
                }
                Ok(Some(msg))
            }

            SaslState::DigestMd5Resp => Ok(None),

            SaslState::Ntlm => {
                let msg = ntlm::create_type1_message(ctx.ntlm)?;
                newstate = SaslState::NtlmType2Msg;
                Ok(Some(msg))
            }

            SaslState::NtlmType2Msg => {
                let server_msg = get_server_message(flags, proto)?;
                ntlm::decode_type2_message(&server_msg, ctx.ntlm)?;
                let msg = ntlm::create_type3_message(ctx.user, ctx.passwd, ctx.ntlm)?;
                Ok(Some(msg))
            }

            SaslState::Gssapi => {
                let msg =
                    kerberos::create_gssapi_user_message(service, ctx.host, None, ctx.krb5)?;
                newstate = SaslState::GssapiToken;
                Ok(Some(msg))
            }

            SaslState::GssapiToken => {
                let server_msg = get_server_message(flags, proto)?;
                if self.mutual_auth {
                    let msg = kerberos::create_gssapi_user_message(
                        service, ctx.host, Some(&server_msg), ctx.krb5,
                    )?;
                    newstate = SaslState::GssapiNoData;
                    Ok(Some(msg))
                } else {
                    let msg = kerberos::create_gssapi_security_message(&server_msg, ctx.krb5)?;
                    Ok(Some(msg))
                }
            }

            SaslState::GssapiNoData => {
                let server_msg = get_server_message(flags, proto)?;
                let msg = kerberos::create_gssapi_security_message(&server_msg, ctx.krb5)?;
                Ok(Some(msg))
            }

            SaslState::OAuth2 => {
                if self.authused == SASL_MECH_OAUTHBEARER {
                    let bearer_token = ctx.bearer.unwrap_or("");
                    let msg =
                        bearer::create_oauth_bearer_message(ctx.user, ctx.host, ctx.port, bearer_token)?;
                    newstate = SaslState::OAuth2Resp;
                    Ok(Some(msg.into_bytes()))
                } else {
                    let bearer_token = ctx.bearer.unwrap_or("");
                    let msg = bearer::create_xoauth_bearer_message(ctx.user, bearer_token)?;
                    Ok(Some(msg.into_bytes()))
                }
            }

            SaslState::OAuth2Resp => {
                if code == proto.final_code() {
                    self.set_state(SaslState::Stop);
                    return Ok(SaslProgress::Done);
                } else if code == proto.cont_code() {
                    // Acknowledge continuation by sending 0x01.
                    let resp = vec![0x01u8];
                    let encoded = build_message(flags, Some(&resp));
                    let mech = self.curmech.clone().unwrap_or_default();
                    proto.cont_auth(&mech, &encoded)?;
                    self.set_state(newstate);
                    return Ok(SaslProgress::InProgress);
                } else {
                    self.set_state(SaslState::Stop);
                    return Err(CurlError::LoginDenied);
                }
            }

            SaslState::Cancel => {
                self.authmechs &= !self.authused;
                self.authused = SASL_AUTH_NONE;
                self.curmech = None;
                return self.start(proto, ctx, self.force_ir);
            }

            _ => {
                tracing::warn!(state = %self.state, "Unsupported SASL authentication state");
                Err(CurlError::UnsupportedProtocol)
            }
        };

        // Post-dispatch error handling.
        match resp_result {
            Err(CurlError::BadContentEncoding) => {
                let mech = self.curmech.clone().unwrap_or_default();
                let cancel_result = proto.cancel_auth(&mech);
                newstate = SaslState::Cancel;
                self.set_state(newstate);
                cancel_result?;
                Ok(SaslProgress::InProgress)
            }
            Ok(resp_opt) => {
                let encoded = build_message(flags, resp_opt.as_deref());
                let mech = self.curmech.clone().unwrap_or_default();
                proto.cont_auth(&mech, &encoded)?;
                self.set_state(newstate);
                Ok(SaslProgress::InProgress)
            }
            Err(e) => {
                newstate = SaslState::Stop;
                self.set_state(newstate);
                Err(e)
            }
        }
    }

    // -----------------------------------------------------------------------
    // is_blocked — diagnostic for failed mechanism selection
    // -----------------------------------------------------------------------

    /// Report diagnostic information and return [`CurlError::LoginDenied`].
    ///
    /// Matches C `Curl_sasl_is_blocked` in `curl_sasl.c` lines 871–932.
    pub fn is_blocked(&self) -> CurlError {
        let enabled = self.authmechs & self.prefmech;

        if self.authmechs == 0 {
            tracing::info!("SASL: no auth mechanism was offered or recognized");
        } else if enabled == 0 {
            tracing::info!("SASL: no overlap between offered and configured auth mechanisms");
        } else {
            tracing::info!("SASL: no auth mechanism offered could be selected");
            if (enabled & SASL_MECH_EXTERNAL) != 0 {
                tracing::info!("SASL: auth EXTERNAL not chosen (password was set)");
            }
            if (enabled & SASL_MECH_GSSAPI) != 0 {
                if !kerberos::is_gssapi_supported() {
                    tracing::info!("SASL: GSSAPI not supported by the platform/libraries");
                } else {
                    tracing::info!("SASL: GSSAPI requires a domain in the username");
                }
            }
            if (enabled & SASL_MECH_SCRAM_SHA_256) != 0
                && !scram::is_scram_supported(SASL_MECH_STRING_SCRAM_SHA_256)
            {
                tracing::info!("SASL: SCRAM-SHA-256 not supported");
            }
            if (enabled & SASL_MECH_SCRAM_SHA_1) != 0
                && !scram::is_scram_supported(SASL_MECH_STRING_SCRAM_SHA_1)
            {
                tracing::info!("SASL: SCRAM-SHA-1 not supported");
            }
            if (enabled & SASL_MECH_NTLM) != 0 {
                tracing::info!("SASL: NTLM is available but was not selected");
            }
            if (enabled & SASL_MECH_OAUTHBEARER) != 0 {
                tracing::info!("SASL: OAUTHBEARER requires CURLOPT_XOAUTH2_BEARER");
            }
            if (enabled & SASL_MECH_XOAUTH2) != 0 {
                tracing::info!("SASL: XOAUTH2 requires CURLOPT_XOAUTH2_BEARER");
            }
        }

        CurlError::LoginDenied
    }
}

// ===========================================================================
// CRAM-MD5 Implementation (from lib/vauth/cram.c)
// ===========================================================================

/// Create a CRAM-MD5 authentication response message (RFC 2195).
///
/// Computes `HMAC-MD5(passwd, challenge)` and formats the response as
/// `"<user> <32-char-lowercase-hex-digest>"`.
///
/// Matches C `Curl_auth_create_cram_md5_message` in `vauth/cram.c`.
pub fn create_cram_md5_message(
    challenge: &[u8],
    user: &str,
    passwd: &str,
) -> Result<Vec<u8>, CurlError> {
    let digest: [u8; 16] = hmac_md5(passwd.as_bytes(), challenge);

    let mut response = String::with_capacity(user.len() + 1 + 32);
    response.push_str(user);
    response.push(' ');
    for byte in &digest {
        use std::fmt::Write;
        write!(response, "{:02x}", byte).map_err(|_| CurlError::OutOfMemory)?;
    }

    Ok(response.into_bytes())
}

// ===========================================================================
// Utility Functions
// ===========================================================================

/// Decode the server's SASL message, base64-decoding if required.
///
/// Matches C `get_server_message` in `curl_sasl.c` lines 222–244.
fn get_server_message(flags: u16, proto: &dyn SaslProto) -> Result<Vec<u8>, CurlError> {
    let raw = proto.get_message()?;
    if (flags & SASL_FLAG_BASE64) != 0 {
        if raw.is_empty() || raw[0] == b'=' {
            return Ok(Vec::new());
        }
        let as_str = std::str::from_utf8(&raw).map_err(|_| CurlError::BadContentEncoding)?;
        base64::decode(as_str)
    } else {
        Ok(raw)
    }
}

/// Encode an outgoing SASL response for transmission.
///
/// Matches C `build_message` in `curl_sasl.c` lines 248–269.
fn build_message(flags: u16, msg: Option<&[u8]>) -> Vec<u8> {
    if (flags & SASL_FLAG_BASE64) != 0 {
        match msg {
            None => Vec::new(),
            Some([]) => vec![b'='],
            Some(data) => base64::encode(data).into_bytes(),
        }
    } else {
        msg.unwrap_or(&[]).to_vec()
    }
}

/// Check if a username contains a domain component.
fn user_contains_domain(user: &str) -> bool {
    user.contains('\\') || user.contains('/') || user.contains('@')
}

/// Extract the effective bearer token from the auth context.
fn effective_bearer<'a>(ctx: &'a SaslAuthContext<'_>) -> Option<&'a str> {
    let bearer = ctx.bearer?;
    if ctx.is_follow && !ctx.allow_auth_to_other_hosts {
        return None;
    }
    Some(bearer)
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mechanism_flags_match_c_values() {
        assert_eq!(SASL_MECH_LOGIN, 0x0001);
        assert_eq!(SASL_MECH_PLAIN, 0x0002);
        assert_eq!(SASL_MECH_CRAM_MD5, 0x0004);
        assert_eq!(SASL_MECH_DIGEST_MD5, 0x0008);
        assert_eq!(SASL_MECH_GSSAPI, 0x0010);
        assert_eq!(SASL_MECH_EXTERNAL, 0x0020);
        assert_eq!(SASL_MECH_NTLM, 0x0040);
        assert_eq!(SASL_MECH_XOAUTH2, 0x0080);
        assert_eq!(SASL_MECH_OAUTHBEARER, 0x0100);
        assert_eq!(SASL_MECH_SCRAM_SHA_1, 0x0200);
        assert_eq!(SASL_MECH_SCRAM_SHA_256, 0x0400);
    }

    #[test]
    fn auth_composite_constants() {
        assert_eq!(SASL_AUTH_NONE, 0);
        assert_eq!(SASL_AUTH_ANY, 0xFFFF);
        assert_eq!(SASL_AUTH_DEFAULT, 0xFFFF & !SASL_MECH_EXTERNAL);
        assert_ne!(SASL_AUTH_DEFAULT & SASL_MECH_EXTERNAL, SASL_MECH_EXTERNAL);
    }

    #[test]
    fn decode_mech_exact_match() {
        let (bit, len) = decode_mech("PLAIN", 5);
        assert_eq!(bit, SASL_MECH_PLAIN);
        assert_eq!(len, 5);
    }

    #[test]
    fn decode_mech_case_insensitive() {
        let (bit, len) = decode_mech("plain", 5);
        assert_eq!(bit, SASL_MECH_PLAIN);
        assert_eq!(len, 5);
    }

    #[test]
    fn decode_mech_with_space_delimiter() {
        let (bit, len) = decode_mech("PLAIN AUTH", 10);
        assert_eq!(bit, SASL_MECH_PLAIN);
        assert_eq!(len, 5);
    }

    #[test]
    fn decode_mech_no_match_dash_continuation() {
        let (bit, _) = decode_mech("PLAIN-EXT", 9);
        assert_eq!(bit, 0);
    }

    #[test]
    fn decode_mech_no_match_uppercase_continuation() {
        let (bit, _) = decode_mech("PLAINX", 6);
        assert_eq!(bit, 0);
    }

    #[test]
    fn decode_mech_unknown() {
        let (bit, len) = decode_mech("UNKNOWN", 7);
        assert_eq!(bit, 0);
        assert_eq!(len, 0);
    }

    #[test]
    fn decode_mech_cram_md5() {
        let (bit, len) = decode_mech("CRAM-MD5 ", 9);
        assert_eq!(bit, SASL_MECH_CRAM_MD5);
        assert_eq!(len, 8);
    }

    #[test]
    fn decode_mech_scram_sha_256() {
        let (bit, len) = decode_mech("SCRAM-SHA-256", 13);
        assert_eq!(bit, SASL_MECH_SCRAM_SHA_256);
        assert_eq!(len, 13);
    }

    #[test]
    fn sasl_state_display() {
        assert_eq!(format!("{}", SaslState::Stop), "STOP");
        assert_eq!(format!("{}", SaslState::Plain), "PLAIN");
        assert_eq!(format!("{}", SaslState::DigestMd5Resp), "DIGESTMD5_RESP");
        assert_eq!(format!("{}", SaslState::Cancel), "CANCEL");
        assert_eq!(format!("{}", SaslState::Final), "FINAL");
    }

    #[test]
    fn sasl_new_default() {
        let sasl = Sasl::new(SASL_AUTH_DEFAULT);
        assert_eq!(sasl.state, SaslState::Stop);
        assert!(sasl.curmech.is_none());
        assert_eq!(sasl.authmechs, SASL_AUTH_NONE);
        assert_eq!(sasl.prefmech, SASL_AUTH_DEFAULT);
        assert_eq!(sasl.authused, SASL_AUTH_NONE);
        assert!(sasl.resetprefs);
        assert!(!sasl.mutual_auth);
        assert!(!sasl.force_ir);
    }

    #[test]
    fn parse_url_auth_option_wildcard() {
        let mut sasl = Sasl::new(SASL_AUTH_NONE);
        sasl.parse_url_auth_option("*").unwrap();
        assert_eq!(sasl.prefmech, SASL_AUTH_DEFAULT);
    }

    #[test]
    fn parse_url_auth_option_specific() {
        let mut sasl = Sasl::new(SASL_AUTH_NONE);
        sasl.parse_url_auth_option("PLAIN").unwrap();
        assert_eq!(sasl.prefmech, SASL_MECH_PLAIN);
    }

    #[test]
    fn parse_url_auth_option_multiple() {
        let mut sasl = Sasl::new(SASL_AUTH_NONE);
        sasl.parse_url_auth_option("PLAIN").unwrap();
        sasl.parse_url_auth_option("LOGIN").unwrap();
        assert_eq!(sasl.prefmech, SASL_MECH_PLAIN | SASL_MECH_LOGIN);
    }

    #[test]
    fn parse_url_auth_option_empty_error() {
        let mut sasl = Sasl::new(SASL_AUTH_NONE);
        assert_eq!(sasl.parse_url_auth_option("").unwrap_err(), CurlError::UrlMalformat);
    }

    #[test]
    fn parse_url_auth_option_invalid_error() {
        let mut sasl = Sasl::new(SASL_AUTH_NONE);
        assert_eq!(sasl.parse_url_auth_option("BOGUS").unwrap_err(), CurlError::UrlMalformat);
    }

    #[test]
    fn can_authenticate_with_user() {
        let sasl = Sasl::new(SASL_AUTH_DEFAULT);
        assert!(sasl.can_authenticate(true, true));
    }

    #[test]
    fn can_authenticate_external() {
        let mut sasl = Sasl::new(SASL_AUTH_ANY);
        sasl.authmechs = SASL_MECH_EXTERNAL;
        assert!(sasl.can_authenticate(false, false));
    }

    #[test]
    fn cannot_authenticate_no_user_no_external() {
        let sasl = Sasl::new(SASL_AUTH_DEFAULT);
        assert!(!sasl.can_authenticate(false, false));
    }

    #[test]
    fn init_basic_auth() {
        let mut sasl = Sasl::new(SASL_AUTH_DEFAULT);
        sasl.init(CURLAUTH_BASIC, SASL_AUTH_DEFAULT);
        assert_eq!(sasl.prefmech, SASL_AUTH_DEFAULT);
    }

    #[test]
    fn init_digest_auth() {
        let mut sasl = Sasl::new(SASL_AUTH_DEFAULT);
        sasl.init(CURLAUTH_DIGEST, SASL_AUTH_DEFAULT);
        assert_eq!(sasl.prefmech, SASL_MECH_DIGEST_MD5);
    }

    #[test]
    fn init_bearer_auth() {
        let mut sasl = Sasl::new(SASL_AUTH_DEFAULT);
        sasl.init(CURLAUTH_BEARER, SASL_AUTH_DEFAULT);
        assert_eq!(sasl.prefmech, SASL_MECH_OAUTHBEARER | SASL_MECH_XOAUTH2);
    }

    #[test]
    fn cram_md5_basic() {
        let challenge = b"<1896.697170952@postoffice.example.net>";
        let user = "tim";
        let passwd = "tanstraafl";
        let result = create_cram_md5_message(challenge, user, passwd).unwrap();
        let result_str = std::str::from_utf8(&result).unwrap();
        assert!(result_str.starts_with("tim "));
        let hex_part = &result_str[4..];
        assert_eq!(hex_part.len(), 32);
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn cram_md5_empty_challenge() {
        let result = create_cram_md5_message(b"", "user", "pass").unwrap();
        let result_str = std::str::from_utf8(&result).unwrap();
        assert!(result_str.starts_with("user "));
        assert_eq!(result_str.len(), 5 + 32);
    }

    #[test]
    fn build_message_base64_none() {
        let result = build_message(SASL_FLAG_BASE64, None);
        assert!(result.is_empty());
    }

    #[test]
    fn build_message_base64_empty() {
        let result = build_message(SASL_FLAG_BASE64, Some(&[]));
        assert_eq!(result, b"=");
    }

    #[test]
    fn build_message_base64_data() {
        let result = build_message(SASL_FLAG_BASE64, Some(b"Hello"));
        let decoded = base64::decode(std::str::from_utf8(&result).unwrap()).unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn build_message_no_base64() {
        let result = build_message(0, Some(b"raw data"));
        assert_eq!(result, b"raw data");
    }

    #[test]
    fn user_domain_backslash() {
        assert!(user_contains_domain("DOMAIN\\user"));
    }

    #[test]
    fn user_domain_at() {
        assert!(user_contains_domain("user@domain"));
    }

    #[test]
    fn user_no_domain() {
        assert!(!user_contains_domain("simpleuser"));
    }

    #[test]
    fn is_blocked_returns_login_denied() {
        let sasl = Sasl::new(SASL_AUTH_DEFAULT);
        assert_eq!(sasl.is_blocked(), CurlError::LoginDenied);
    }
}
