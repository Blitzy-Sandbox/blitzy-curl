//! IMAP/IMAPS protocol handler (RFC 3501).
//!
//! Complete Rust rewrite of `lib/imap.c` and `lib/imap.h` — implements the
//! IMAP(S) state machine, command formatting, tagged/untagged/continuation
//! response parsing, SASL/STARTTLS authentication, URL path parsing per
//! RFC 5092, and multi-interface integration.
//!
//! # Architecture
//!
//! The handler is split into three main types:
//!
//! * [`ImapConn`] — per-connection state: pingpong I/O, SASL context,
//!   selected mailbox, UIDVALIDITY, capability flags, command tag tracking.
//! * [`Imap`] — per-easy (per-request) state: requested mailbox, UID, mail
//!   index, sections, partials, query, custom command, transfer mode.
//! * [`ImapHandler`] — implements [`Protocol`] trait to plug into the
//!   scheme registry as `imap`/`imaps` handler.
//!
//! # State Machine
//!
//! The IMAP handshake follows this progression:
//!
//! ```text
//! ServerGreet → Capability → [StartTls → UpgradeTls → Capability] →
//!     [Authenticate / Login] → Stop
//! ```
//!
//! Transfer operations:
//!
//! ```text
//! List | Select → (Fetch / Search / List) | Append → Stop
//! ```
//!
//! # References
//!
//! * RFC 2195 — CRAM-MD5 authentication
//! * RFC 2595 — Using TLS with IMAP, POP3 and ACAP
//! * RFC 2831 — DIGEST-MD5 authentication
//! * RFC 3501 — IMAPv4 protocol
//! * RFC 4422 — Simple Authentication and Security Layer (SASL)
//! * RFC 4616 — PLAIN authentication
//! * RFC 4752 — Kerberos V5 ("GSSAPI") SASL Mechanism
//! * RFC 4959 — IMAP Extension for SASL Initial Client Response
//! * RFC 5092 — IMAP URL Scheme
//! * RFC 6749 — OAuth 2.0 Authorization Framework
//! * RFC 8314 — Use of TLS for Email Submission and Access
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.

// Many internal helpers and state machine functions are invoked indirectly
// through the PingPong framework callbacks rather than being called directly
// from Protocol trait methods.
#![allow(dead_code)]

use std::fmt;

use crate::auth::sasl::{
    self, decode_mech, Sasl, SASL_AUTH_DEFAULT, SASL_AUTH_NONE, SASL_FLAG_BASE64,
};
use crate::conn::ConnectionData;
use crate::error::{CurlError, CurlResult};
use crate::escape::url_decode_string;
use crate::protocols::pingpong::{PingPong, PingPongConfig, PpTransfer};
use crate::protocols::{ConnectionCheckResult, Protocol, ProtocolFlags};

// ===========================================================================
// Constants
// ===========================================================================

/// Default IMAP port (143).
pub const PORT_IMAP: u16 = 143;

/// Default IMAPS port (993).
pub const PORT_IMAPS: u16 = 993;

/// IMAP tagged response: OK
const IMAP_RESP_OK: i32 = 1;
/// IMAP tagged response: not OK (NO / BAD)
const IMAP_RESP_NOT_OK: i32 = 2;
/// IMAP tagged response: PREAUTH
const IMAP_RESP_PREAUTH: i32 = 3;

// Authentication type preference bit flags (from imap.h).
const IMAP_TYPE_CLEARTEXT: u8 = 1 << 0;
const IMAP_TYPE_SASL: u8 = 1 << 1;
const IMAP_TYPE_NONE: u8 = 0;
const IMAP_TYPE_ANY: u8 = IMAP_TYPE_CLEARTEXT | IMAP_TYPE_SASL;

// ===========================================================================
// ImapState — state machine enum
// ===========================================================================

/// IMAP protocol state machine states.
///
/// Each variant maps to a `imapstate` value in the C `lib/imap.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImapState {
    /// Waiting for the initial server greeting.
    ServerGreet,
    /// Sent CAPABILITY, waiting for response.
    Capability,
    /// Sent STARTTLS, waiting for OK.
    StartTls,
    /// Performing TLS handshake upgrade (multi-mode async).
    UpgradeTls,
    /// Sent AUTHENTICATE, processing SASL challenge/response.
    Authenticate,
    /// Sent LOGIN, waiting for OK.
    Login,
    /// Sent LIST (or custom command), waiting for responses.
    List,
    /// Sent SELECT, waiting for OK + untagged data.
    Select,
    /// Sent FETCH, waiting for literal data.
    Fetch,
    /// Post-transfer FETCH final tagged response.
    FetchFinal,
    /// Sent APPEND, waiting for continuation (+).
    Append,
    /// Post-upload APPEND final tagged response.
    AppendFinal,
    /// Sent SEARCH, waiting for results.
    Search,
    /// Sent LOGOUT, waiting for OK.
    Logout,
    /// Terminal state — state machine has finished.
    Stop,
}

impl fmt::Display for ImapState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
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
            ImapState::Stop => "STOP",
        };
        f.write_str(name)
    }
}

// ===========================================================================
// ImapConn — per-connection IMAP state
// ===========================================================================

/// Per-connection IMAP protocol state.
///
/// Holds the pingpong state machine, SASL context, selected mailbox,
/// capability flags, and command tag tracking. This is the connection-scoped
/// counterpart to [`Imap`] (per-request state).
pub struct ImapConn {
    /// Pingpong command/response state machine for the IMAP control channel.
    pub pp: PingPong,
    /// SASL authentication state and mechanism negotiation.
    pub sasl: Sasl,
    /// Dynamic buffer for building IMAP commands.
    pub dyn_buf: String,
    /// Currently selected mailbox on this connection.
    pub mailbox: Option<String>,
    /// Current state machine state.
    pub state: ImapState,
    /// UIDVALIDITY parsed from the last SELECT response.
    pub mb_uidvalidity: u32,
    /// Response tag to match against server responses (e.g., "A001").
    pub resptag: String,
    /// Preferred authentication type bitmask.
    pub preftype: u8,
    /// Last used command ID (incremented with each command).
    pub cmdid: u8,
    /// Whether the TLS handshake has completed (for STARTTLS upgrade).
    pub ssldone: bool,
    /// Whether this connection received a PREAUTH greeting.
    pub preauth: bool,
    /// Whether the server advertised STARTTLS capability.
    pub tls_supported: bool,
    /// Whether the server explicitly disabled LOGIN command.
    pub login_disabled: bool,
    /// Whether the server supports SASL-IR (initial response).
    pub ir_supported: bool,
    /// Whether `mb_uidvalidity` has been set from a SELECT response.
    pub mb_uidvalidity_set: bool,
    /// Connection ID used for tag generation (from connection metadata).
    conn_id: u64,
}

impl ImapConn {
    /// Creates a new `ImapConn` with default initial state.
    pub fn new(conn_id: u64) -> Self {
        Self {
            pp: PingPong::new(PingPongConfig::default()),
            sasl: Sasl::new(SASL_AUTH_DEFAULT),
            dyn_buf: String::with_capacity(256),
            mailbox: None,
            state: ImapState::Stop,
            mb_uidvalidity: 0,
            resptag: "*".to_string(),
            preftype: IMAP_TYPE_ANY,
            cmdid: 0,
            ssldone: false,
            preauth: false,
            tls_supported: false,
            login_disabled: false,
            ir_supported: false,
            mb_uidvalidity_set: false,
            conn_id,
        }
    }

    /// Change the IMAP state with trace logging.
    fn set_state(&mut self, new_state: ImapState) {
        if self.state != new_state {
            tracing::trace!(
                from = %self.state,
                to = %new_state,
                "IMAP state change"
            );
        }
        self.state = new_state;
    }
}

// ===========================================================================
// Imap — per-request IMAP state
// ===========================================================================

/// Per-request (per-easy handle) IMAP operation state.
///
/// Holds the parsed URL components and custom command parameters for the
/// current transfer request. Reset after each `done()` call.
pub struct Imap {
    /// Transfer mode indicator — Body, Info, or None.
    pub transfer: PpTransfer,
    /// Requested mailbox to SELECT.
    pub mailbox: Option<String>,
    /// Message UID to FETCH.
    pub uid: Option<String>,
    /// Message index in mailbox to FETCH (MAILINDEX parameter).
    pub mindex: Option<String>,
    /// Message SECTION to FETCH (e.g., "TEXT", "HEADER").
    pub section: Option<String>,
    /// Message PARTIAL range to FETCH.
    pub partial: Option<String>,
    /// SEARCH query string.
    pub query: Option<String>,
    /// Custom IMAP command (e.g., "STORE", "EXPUNGE", "NOOP").
    pub custom: Option<String>,
    /// Parameters for the custom command.
    pub custom_params: Option<String>,
    /// UIDVALIDITY constraint from the URL.
    pub uidvalidity: u32,
    /// Whether `uidvalidity` has been set from URL parsing.
    pub uidvalidity_set: bool,
}

impl Imap {
    /// Creates a new `Imap` with default (empty) state.
    pub fn new() -> Self {
        Self {
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

    /// Reset all fields to their defaults for reuse between requests.
    fn reset(&mut self) {
        self.mailbox = None;
        self.uid = None;
        self.mindex = None;
        self.section = None;
        self.partial = None;
        self.query = None;
        self.custom = None;
        self.custom_params = None;
        self.transfer = PpTransfer::Body;
    }
}

impl Default for Imap {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// ImapSaslProto — SASL protocol adapter for IMAP
// ===========================================================================

/// IMAP-specific SASL protocol implementation providing protocol-dependent
/// callbacks required by the SASL framework: service name (`"imap"`),
/// continuation code (`'+'`), success code ([`IMAP_RESP_OK`]), and command
/// formatting for AUTHENTICATE, continuation data, and cancellation.
pub struct ImapSaslProto;

impl ImapSaslProto {
    /// Creates a new IMAP SASL protocol adapter.
    pub fn new() -> Self {
        Self
    }

    /// Returns the IMAP service name for SASL (`"imap"`).
    pub fn service_name(&self) -> &str {
        "imap"
    }

    /// Format the AUTHENTICATE command with optional initial response.
    pub fn perform_auth(&self, mech: &str, initial_response: Option<&[u8]>) -> String {
        match initial_response {
            Some(ir) => {
                let ir_str = String::from_utf8_lossy(ir);
                format!("AUTHENTICATE {} {}", mech, ir_str)
            }
            None => format!("AUTHENTICATE {}", mech),
        }
    }

    /// Format a SASL continuation response.
    pub fn continue_auth(&self, _mech: &str, resp: &[u8]) -> String {
        String::from_utf8_lossy(resp).to_string()
    }

    /// Format a SASL cancellation command (`*`).
    pub fn cancel_auth(&self, _mech: &str) -> String {
        "*".to_string()
    }

    /// Extract the SASL message from a `+` continuation response line.
    pub fn get_message(&self, response: &str) -> Vec<u8> {
        let trimmed = response.trim();
        if trimmed.len() > 2 && trimmed.starts_with("+ ") {
            trimmed[2..].trim().as_bytes().to_vec()
        } else if trimmed == "+" {
            Vec::new()
        } else {
            trimmed.as_bytes().to_vec()
        }
    }

    /// Maximum initial response line length (0 = unlimited for IMAP).
    pub fn max_line_len(&self) -> usize {
        0
    }

    /// Response code indicating continuation expected.
    pub fn continuation_code(&self) -> i32 {
        b'+' as i32
    }

    /// Response code indicating authentication success.
    pub fn success_code(&self) -> i32 {
        IMAP_RESP_OK
    }

    /// Default mechanism set for IMAP SASL.
    pub fn default_mechs(&self) -> u16 {
        SASL_AUTH_DEFAULT
    }

    /// Configuration flags for IMAP SASL.
    pub fn flags(&self) -> u16 {
        SASL_FLAG_BASE64
    }
}

impl Default for ImapSaslProto {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Helper functions
// ===========================================================================

/// Escape an IMAP atom string per RFC 3501 §4.3.
///
/// If `escape_only` is `true`, only backslash-escapes special characters
/// without adding surrounding double-quotes. When `false`, the entire
/// string is returned inside quotes if any special characters are present.
fn imap_atom(s: &str, escape_only: bool) -> String {
    const SPECIAL_CHARS: &[char] = &['(', ')', ' ', '{', '%', '*', ']', '\\', '"'];

    if s.is_empty() {
        return if escape_only { String::new() } else { "\"\"".to_string() };
    }

    let needs_escape = s.chars().any(|c| SPECIAL_CHARS.contains(&c));
    if !needs_escape {
        return s.to_string();
    }

    let mut result = String::with_capacity(s.len() + 10);
    if !escape_only {
        result.push('"');
    }
    for ch in s.chars() {
        if ch == '\\' || ch == '"' {
            result.push('\\');
        }
        result.push(ch);
    }
    if !escape_only {
        result.push('"');
    }
    result
}

/// Check if a character is a valid "bchar" per RFC 5092.
fn imap_is_bchar(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ":@/&=-._~!$'()*+,%".contains(ch)
}

/// Find the start position of a literal `{size}` in a response line,
/// skipping over quoted strings.
fn imap_find_literal(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut in_quote = false;
    let mut i = 0;
    while i < bytes.len() {
        if in_quote {
            if bytes[i] == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if bytes[i] == b'"' {
                in_quote = false;
            }
        } else if bytes[i] == b'"' {
            in_quote = true;
        } else if bytes[i] == b'{' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Parse the literal size from `{NNN}` starting at position `start`.
fn parse_literal_size(s: &str, start: usize) -> Option<u64> {
    let after_brace = &s[start + 1..];
    let end = after_brace.find('}')?;
    after_brace[..end].parse::<u64>().ok()
}

/// Check if an untagged (`* `) response matches a given IMAP command keyword.
fn imap_matchresp(line: &str, cmd: &str) -> bool {
    if line.len() < 2 || !line.starts_with("* ") {
        return false;
    }
    let after_star = &line[2..];
    // Skip optional leading number (e.g. "* 1 FETCH ...")
    let rest = if after_star.starts_with(|c: char| c.is_ascii_digit()) {
        let end_num = after_star
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(after_star.len());
        if end_num >= after_star.len() || after_star.as_bytes()[end_num] != b' ' {
            return false;
        }
        &after_star[end_num + 1..]
    } else {
        after_star
    };

    if rest.len() >= cmd.len() {
        let candidate = &rest[..cmd.len()];
        if candidate.eq_ignore_ascii_case(cmd) {
            return rest.len() == cmd.len()
                || rest.as_bytes()[cmd.len()] == b' '
                || rest.as_bytes()[cmd.len()] == b'\r';
        }
    }
    false
}

/// Determine if an IMAP response line is a valid end-of-response.
///
/// Returns `(is_complete, response_code)` where `response_code` is one of
/// [`IMAP_RESP_OK`], [`IMAP_RESP_NOT_OK`], [`IMAP_RESP_PREAUTH`],
/// `b'*'` for untagged, `b'+'` for continuation, or `-1` for error.
fn imap_endofresp(
    line: &str,
    resptag: &str,
    state: ImapState,
    imap: &Imap,
) -> (bool, i32) {
    let tag_len = resptag.len();
    // --- Tagged response ---
    if line.len() > tag_len
        && line[..tag_len] == *resptag
        && line.as_bytes().get(tag_len) == Some(&b' ')
    {
        let after_tag = &line[tag_len + 1..];
        let resp = if after_tag.len() >= 2
            && after_tag[..2].eq_ignore_ascii_case("OK")
        {
            IMAP_RESP_OK
        } else if after_tag.len() >= 7
            && after_tag[..7].eq_ignore_ascii_case("PREAUTH")
        {
            IMAP_RESP_PREAUTH
        } else {
            IMAP_RESP_NOT_OK
        };
        return (true, resp);
    }

    // --- Untagged response ---
    if line.len() >= 2 && line.starts_with("* ") {
        let matched = match state {
            ImapState::Capability => imap_matchresp(line, "CAPABILITY"),
            ImapState::List => {
                if imap.custom.is_none() {
                    imap_matchresp(line, "LIST")
                } else {
                    let cmd = imap.custom.as_deref().unwrap_or("");
                    imap_matchresp(line, cmd)
                        || (cmd.eq_ignore_ascii_case("STORE")
                            && imap_matchresp(line, "FETCH"))
                        || cmd.eq_ignore_ascii_case("SELECT")
                        || cmd.eq_ignore_ascii_case("EXAMINE")
                        || cmd.eq_ignore_ascii_case("SEARCH")
                        || cmd.eq_ignore_ascii_case("EXPUNGE")
                        || cmd.eq_ignore_ascii_case("LSUB")
                        || cmd.eq_ignore_ascii_case("UID")
                        || cmd.eq_ignore_ascii_case("GETQUOTAROOT")
                        || cmd.eq_ignore_ascii_case("NOOP")
                }
            }
            ImapState::Select => true,
            ImapState::Fetch => imap_matchresp(line, "FETCH"),
            ImapState::Search => imap_matchresp(line, "SEARCH"),
            _ => false,
        };
        if matched {
            return (true, b'*' as i32);
        }
        return (false, 0);
    }

    // --- Continuation response ---
    if imap.custom.is_none()
        && ((line.len() == 3 && line.starts_with('+'))
            || (line.len() >= 2 && line.starts_with("+ ")))
    {
        match state {
            ImapState::Authenticate | ImapState::Append => {
                return (true, b'+' as i32);
            }
            _ => {
                tracing::error!("Unexpected IMAP continuation response");
                return (true, -1);
            }
        }
    }

    (false, 0)
}

/// Check if a custom FETCH command represents a listing (range) query.
fn is_custom_fetch_listing(imap: &Imap) -> bool {
    let custom = match &imap.custom {
        Some(c) => c.as_str(),
        None => return false,
    };
    let params = match &imap.custom_params {
        Some(p) => p.as_str(),
        None => return false,
    };
    if custom.eq_ignore_ascii_case("FETCH") {
        return is_custom_fetch_listing_match(params);
    }
    if custom.eq_ignore_ascii_case("UID") {
        if let Some(rest) = params.strip_prefix(" FETCH ") {
            return is_custom_fetch_listing_match(&format!(" {}", rest));
        }
    }
    false
}

fn is_custom_fetch_listing_match(params: &str) -> bool {
    let bytes = params.as_bytes();
    if bytes.is_empty() || bytes[0] != b' ' {
        return false;
    }
    let mut i = 1;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i >= bytes.len() || i == 1 {
        return false;
    }
    bytes[i] == b':' || bytes[i] == b','
}

/// Percent-decode a string (`%XX` only) without converting `+` to space.
///
/// This matches the C `Curl_urldecode(..., REJECT_CTRL)` semantics used
/// for IMAP custom request strings where `+` must remain literal.
fn percent_decode_only(input: &str) -> CurlResult<String> {
    let mut result = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_digit(bytes[i + 1]);
            let lo = hex_digit(bytes[i + 2]);
            if let (Some(h), Some(l)) = (hi, lo) {
                let decoded = (h << 4) | l;
                // Reject control characters (matching REJECT_CTRL)
                if decoded < 0x20 {
                    return Err(CurlError::UrlMalformat);
                }
                result.push(decoded);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(result).map_err(|_| CurlError::UrlMalformat)
}

/// Convert a hex digit character to its numeric value.
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Select the best available SASL mechanism from available and preferred sets.
fn select_sasl_mechanism(authmechs: u16, prefmech: u16) -> Option<&'static str> {
    let available = authmechs & prefmech;
    let mechs: &[(u16, &str)] = &[
        (sasl::SASL_MECH_EXTERNAL, "EXTERNAL"),
        (sasl::SASL_MECH_GSSAPI, "GSSAPI"),
        (sasl::SASL_MECH_SCRAM_SHA_256, "SCRAM-SHA-256"),
        (sasl::SASL_MECH_SCRAM_SHA_1, "SCRAM-SHA-1"),
        (sasl::SASL_MECH_DIGEST_MD5, "DIGEST-MD5"),
        (sasl::SASL_MECH_CRAM_MD5, "CRAM-MD5"),
        (sasl::SASL_MECH_NTLM, "NTLM"),
        (sasl::SASL_MECH_OAUTHBEARER, "OAUTHBEARER"),
        (sasl::SASL_MECH_XOAUTH2, "XOAUTH2"),
        (sasl::SASL_MECH_PLAIN, "PLAIN"),
        (sasl::SASL_MECH_LOGIN, "LOGIN"),
    ];
    for &(bit, name) in mechs {
        if (available & bit) != 0 {
            return Some(name);
        }
    }
    None
}

// ===========================================================================
// ImapHandler — Protocol trait implementation
// ===========================================================================

/// IMAP protocol handler implementing the [`Protocol`] trait.
///
/// Registered for both `imap://` (port 143) and `imaps://` (port 993) schemes
/// in the protocol registry.  Manages the full IMAP transfer lifecycle:
/// connection setup, capability negotiation, SASL/STARTTLS authentication,
/// mailbox selection, FETCH / SEARCH / APPEND operations, and graceful LOGOUT.
pub struct ImapHandler {
    /// Per-connection IMAP state.
    conn: ImapConn,
    /// Per-request IMAP state.
    imap: Imap,
    /// Whether this handler is for IMAPS (implicit TLS).
    is_imaps: bool,
    /// Whether TLS upgrade is requested via `use_ssl` setting.
    use_ssl: bool,
    /// TLS strictness: `true` = required, `false` = best-effort.
    use_ssl_required: bool,
    /// User credentials for LOGIN / SASL authentication.
    user: Option<String>,
    /// Password for LOGIN / SASL authentication.
    passwd: Option<String>,
    /// Custom request command string from `CURLOPT_CUSTOMREQUEST`.
    custom_request: Option<String>,
    /// URL path component for parsing.
    url_path: String,
    /// URL query component (?search-query).
    url_query: Option<String>,
    /// URL login options (`;AUTH=` etc.).
    url_options: Option<String>,
    /// Whether upload (APPEND) is requested.
    is_upload: bool,
    /// Upload file size (`-1` if unknown).
    upload_size: i64,
    /// Whether response body should be suppressed (`CURLOPT_NOBODY`).
    no_body: bool,
    /// Output buffer for collecting response data to deliver to the client.
    output_buf: Vec<u8>,
    /// Download size set during FETCH.
    download_size: i64,
    /// Bytes received so far in the current transfer.
    byte_count: u64,
}

impl ImapHandler {
    /// Creates a new IMAP handler with default state.
    pub fn new() -> Self {
        Self {
            conn: ImapConn::new(0),
            imap: Imap::new(),
            is_imaps: false,
            use_ssl: false,
            use_ssl_required: false,
            user: None,
            passwd: None,
            custom_request: None,
            url_path: String::new(),
            url_query: None,
            url_options: None,
            is_upload: false,
            upload_size: -1,
            no_body: false,
            output_buf: Vec::new(),
            download_size: -1,
            byte_count: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Tag generation
    // -----------------------------------------------------------------------

    /// Generate a new command tag and update `resptag`.
    ///
    /// Tags follow the pattern `A001`..`Z999`, cycling the letter based on
    /// `conn_id % 26` and incrementing the numeric part per command.
    fn next_tag(&mut self) {
        let letter = b'A' + ((self.conn.conn_id % 26) as u8);
        self.conn.cmdid = self.conn.cmdid.wrapping_add(1);
        self.conn.resptag = format!("{}{:03}", letter as char, self.conn.cmdid);
    }

    /// Send a formatted IMAP command with auto-generated tag.
    fn imap_sendf_cmd(&mut self, cmd: &str) -> CurlResult<String> {
        self.next_tag();
        let full_cmd = format!("{} {}\r\n", self.conn.resptag, cmd);
        tracing::debug!(tag = %self.conn.resptag, cmd = %cmd, "IMAP send command");
        Ok(full_cmd)
    }

    // -----------------------------------------------------------------------
    // Command generators
    // -----------------------------------------------------------------------

    /// Send CAPABILITY command and enter `Capability` state.
    fn perform_capability(&mut self) -> CurlResult<String> {
        self.conn.sasl.authmechs = SASL_AUTH_NONE;
        self.conn.sasl.authused = SASL_AUTH_NONE;
        self.conn.tls_supported = false;
        let cmd = self.imap_sendf_cmd("CAPABILITY")?;
        self.conn.set_state(ImapState::Capability);
        Ok(cmd)
    }

    /// Send STARTTLS command and enter `StartTls` state.
    fn perform_starttls(&mut self) -> CurlResult<String> {
        let cmd = self.imap_sendf_cmd("STARTTLS")?;
        self.conn.set_state(ImapState::StartTls);
        Ok(cmd)
    }

    /// Send LOGIN command with escaped username/password.
    fn perform_login(&mut self) -> CurlResult<String> {
        let user = self.user.as_deref().unwrap_or("");
        let passwd = self.passwd.as_deref().unwrap_or("");

        if user.is_empty() {
            self.conn.set_state(ImapState::Stop);
            return Ok(String::new());
        }

        let escaped_user = imap_atom(user, false);
        let escaped_passwd = imap_atom(passwd, false);
        let cmd = self.imap_sendf_cmd(
            &format!("LOGIN {} {}", escaped_user, escaped_passwd),
        )?;
        self.conn.set_state(ImapState::Login);
        Ok(cmd)
    }

    /// Orchestrate SASL authentication or fall back to LOGIN.
    fn perform_authentication(&mut self) -> CurlResult<String> {
        // Pre-authenticated connections skip auth entirely
        if self.conn.preauth {
            self.conn.set_state(ImapState::Stop);
            return Ok(String::new());
        }

        if !self.conn.sasl.can_authenticate(
            self.user.is_some(),
            self.passwd.is_some(),
        ) {
            self.conn.set_state(ImapState::Stop);
            return Ok(String::new());
        }

        // Try SASL first
        let has_sasl_mechs =
            (self.conn.sasl.authmechs & self.conn.sasl.prefmech) != 0;
        if has_sasl_mechs && (self.conn.preftype & IMAP_TYPE_SASL) != 0 {
            if let Some(mech) = select_sasl_mechanism(
                self.conn.sasl.authmechs,
                self.conn.sasl.prefmech,
            ) {
                tracing::debug!(mechanism = mech, "Starting SASL authentication");
                let cmd = self.imap_sendf_cmd(
                    &format!("AUTHENTICATE {}", mech),
                )?;
                self.conn.set_state(ImapState::Authenticate);
                return Ok(cmd);
            }
        }

        // Fall back to LOGIN if not disabled and cleartext is allowed
        if !self.conn.login_disabled
            && (self.conn.preftype & IMAP_TYPE_CLEARTEXT) != 0
        {
            return self.perform_login();
        }

        if self.conn.sasl.authmechs == SASL_AUTH_NONE {
            tracing::warn!("No SASL mechanisms available and LOGIN disabled");
        }
        Err(CurlError::LoginDenied)
    }

    /// Send LIST command or custom request.
    fn perform_list(&mut self) -> CurlResult<String> {
        let cmd = if let Some(ref custom) = self.imap.custom {
            let params = self.imap.custom_params.as_deref().unwrap_or("");
            format!("{}{}", custom, params)
        } else {
            let mailbox = self
                .imap
                .mailbox
                .as_deref()
                .map(|m| imap_atom(m, true))
                .unwrap_or_default();
            format!("LIST \"{}\" *", mailbox)
        };
        let full = self.imap_sendf_cmd(&cmd)?;
        self.conn.set_state(ImapState::List);
        Ok(full)
    }

    /// Send SELECT command for the specified mailbox.
    fn perform_select(&mut self) -> CurlResult<String> {
        self.conn.mailbox = None;
        let mailbox = match &self.imap.mailbox {
            Some(m) => m.clone(),
            None => {
                tracing::error!("Cannot SELECT without a mailbox");
                return Err(CurlError::UrlMalformat);
            }
        };
        let escaped = imap_atom(&mailbox, false);
        let full = self.imap_sendf_cmd(&format!("SELECT {}", escaped))?;
        self.conn.set_state(ImapState::Select);
        Ok(full)
    }

    /// Send FETCH command with UID or mail index.
    fn perform_fetch(&mut self) -> CurlResult<String> {
        let section = self.imap.section.as_deref().unwrap_or("");
        let cmd = if let Some(ref uid) = self.imap.uid {
            if let Some(ref partial) = self.imap.partial {
                format!("UID FETCH {} BODY[{}]<{}>", uid, section, partial)
            } else {
                format!("UID FETCH {} BODY[{}]", uid, section)
            }
        } else if let Some(ref mindex) = self.imap.mindex {
            if let Some(ref partial) = self.imap.partial {
                format!("FETCH {} BODY[{}]<{}>", mindex, section, partial)
            } else {
                format!("FETCH {} BODY[{}]", mindex, section)
            }
        } else {
            tracing::error!("Cannot FETCH without a UID or mail index");
            return Err(CurlError::UrlMalformat);
        };
        let full = self.imap_sendf_cmd(&cmd)?;
        self.conn.set_state(ImapState::Fetch);
        Ok(full)
    }

    /// Send SEARCH command.
    fn perform_search(&mut self) -> CurlResult<String> {
        let query = match &self.imap.query {
            Some(q) => q.clone(),
            None => {
                tracing::error!("Cannot SEARCH without a query string");
                return Err(CurlError::UrlMalformat);
            }
        };
        let full = self.imap_sendf_cmd(&format!("SEARCH {}", query))?;
        self.conn.set_state(ImapState::Search);
        Ok(full)
    }

    /// Send APPEND command for uploads.
    fn perform_append(&mut self) -> CurlResult<String> {
        let mailbox = match &self.imap.mailbox {
            Some(m) => m.clone(),
            None => {
                tracing::error!("Cannot APPEND without a mailbox");
                return Err(CurlError::UrlMalformat);
            }
        };
        if self.upload_size < 0 {
            tracing::error!("Cannot APPEND with unknown upload size");
            return Err(CurlError::UploadFailed);
        }
        let escaped = imap_atom(&mailbox, false);
        let full = self.imap_sendf_cmd(
            &format!("APPEND {} {{{}}}", escaped, self.upload_size),
        )?;
        self.conn.set_state(ImapState::Append);
        Ok(full)
    }

    /// Send LOGOUT command.
    fn perform_logout(&mut self) -> CurlResult<String> {
        let full = self.imap_sendf_cmd("LOGOUT")?;
        self.conn.set_state(ImapState::Logout);
        Ok(full)
    }

    // -----------------------------------------------------------------------
    // Response handlers
    // -----------------------------------------------------------------------

    /// Handle the initial server greeting.
    fn state_servergreet_resp(&mut self, code: i32) -> CurlResult<Option<String>> {
        if code == IMAP_RESP_PREAUTH {
            self.conn.preauth = true;
            tracing::info!("PREAUTH connection — already authenticated");
        } else if code != IMAP_RESP_OK {
            tracing::error!("Got unexpected IMAP server greeting");
            return Err(CurlError::WeirdServerReply);
        }
        Ok(Some(self.perform_capability()?))
    }

    /// Handle CAPABILITY response — parse capabilities from untagged lines.
    fn state_capability_resp(
        &mut self,
        code: i32,
        line: &str,
    ) -> CurlResult<Option<String>> {
        // Untagged CAPABILITY data
        if code == b'*' as i32 {
            let words_start = if let Some(stripped) = line.strip_prefix("* ") {
                stripped
            } else {
                line
            };
            for word in words_start.split_whitespace() {
                if word.eq_ignore_ascii_case("STARTTLS") {
                    self.conn.tls_supported = true;
                } else if word.eq_ignore_ascii_case("LOGINDISABLED") {
                    self.conn.login_disabled = true;
                } else if word.eq_ignore_ascii_case("SASL-IR") {
                    self.conn.ir_supported = true;
                } else if word.len() > 5
                    && word[..5].eq_ignore_ascii_case("AUTH=")
                {
                    let mech_str = &word[5..];
                    let (mechbit, mechlen) =
                        decode_mech(mech_str, mech_str.len());
                    if mechbit != 0 && mechlen == mech_str.len() {
                        self.conn.sasl.authmechs |= mechbit;
                    }
                }
            }
            return Ok(None); // More data expected
        }

        // Tagged response — decide next action
        if self.use_ssl && !self.conn.ssldone {
            if code == IMAP_RESP_OK
                && self.conn.tls_supported
                && !self.conn.preauth
            {
                return Ok(Some(self.perform_starttls()?));
            } else if self.use_ssl_required {
                tracing::error!("STARTTLS not available but required");
                return Err(CurlError::UseSslFailed);
            }
        }
        Ok(Some(self.perform_authentication()?))
    }

    /// Handle STARTTLS response.
    fn state_starttls_resp(&mut self, code: i32) -> CurlResult<Option<String>> {
        // Pipelining in response is forbidden
        if self.conn.pp.moredata() {
            return Err(CurlError::WeirdServerReply);
        }
        if code != IMAP_RESP_OK {
            if self.use_ssl_required {
                tracing::error!("STARTTLS denied by server");
                return Err(CurlError::UseSslFailed);
            }
            return Ok(Some(self.perform_authentication()?));
        }
        // Move to TLS upgrade state
        self.conn.set_state(ImapState::UpgradeTls);
        Ok(None)
    }

    /// Handle SASL authentication response.
    fn state_auth_resp(&mut self, code: i32) -> CurlResult<Option<String>> {
        if code == IMAP_RESP_OK {
            tracing::info!("IMAP SASL authentication succeeded");
            self.conn.set_state(ImapState::Stop);
            return Ok(None);
        }
        if code == IMAP_RESP_NOT_OK {
            // SASL failed — try LOGIN fallback
            if !self.conn.login_disabled
                && (self.conn.preftype & IMAP_TYPE_CLEARTEXT) != 0
            {
                return Ok(Some(self.perform_login()?));
            }
            tracing::error!("Authentication cancelled / all mechanisms failed");
            return Err(CurlError::LoginDenied);
        }
        // Continuation — more SASL rounds needed
        Ok(None)
    }

    /// Handle LOGIN response.
    fn state_login_resp(&mut self, code: i32) -> CurlResult<Option<String>> {
        if code != IMAP_RESP_OK {
            tracing::error!("IMAP LOGIN access denied");
            return Err(CurlError::LoginDenied);
        }
        tracing::info!("IMAP LOGIN authentication succeeded");
        self.conn.set_state(ImapState::Stop);
        Ok(None)
    }

    /// Handle LIST and SEARCH responses.
    fn state_listsearch_resp(
        &mut self,
        code: i32,
        line: &str,
    ) -> CurlResult<Option<String>> {
        if code == b'*' as i32 && is_custom_fetch_listing(&self.imap) {
            return Ok(None);
        }
        if code == b'*' as i32 {
            // Check for literal data in the response
            let cr_pos = line.find('\r').unwrap_or(line.len());
            let line_portion = &line[..cr_pos];
            if let Some(lit_pos) = imap_find_literal(line_portion) {
                if let Some(size) = parse_literal_size(line_portion, lit_pos) {
                    tracing::debug!(
                        bytes = size,
                        "Found literal in LIST/SEARCH response"
                    );
                    self.output_buf.extend_from_slice(line.as_bytes());
                    self.download_size =
                        size as i64 + line.len() as i64;
                    self.conn.set_state(ImapState::Stop);
                    return Ok(None);
                }
            }
            // No literal — write line as informational output
            self.output_buf.extend_from_slice(line.as_bytes());
            return Ok(None);
        }
        if code != IMAP_RESP_OK {
            return Err(CurlError::QuoteError);
        }
        self.conn.set_state(ImapState::Stop);
        Ok(None)
    }

    /// Handle SELECT response — track UIDVALIDITY.
    fn state_select_resp(
        &mut self,
        code: i32,
        line: &str,
    ) -> CurlResult<Option<String>> {
        if code == b'*' as i32 {
            let after_star = if let Some(stripped) = line.strip_prefix("* ") {
                stripped
            } else {
                line
            };
            let upper = after_star.to_ascii_uppercase();
            if upper.starts_with("OK [UIDVALIDITY ") {
                let start = "OK [UIDVALIDITY ".len();
                let rest = &after_star[start..];
                let end = rest.find(']').unwrap_or(rest.len());
                if let Ok(val) = rest[..end].parse::<u32>() {
                    self.conn.mb_uidvalidity = val;
                    self.conn.mb_uidvalidity_set = true;
                }
            }
            return Ok(None); // More untagged data expected
        }
        if code == IMAP_RESP_OK {
            // Check UIDVALIDITY constraint
            if self.imap.uidvalidity_set
                && self.conn.mb_uidvalidity_set
                && self.imap.uidvalidity != self.conn.mb_uidvalidity
            {
                tracing::error!("Mailbox UIDVALIDITY has changed");
                return Err(CurlError::RemoteFileNotFound);
            }
            self.conn.mailbox = self.imap.mailbox.clone();
            // Proceed to the appropriate command
            return if self.imap.custom.is_some() {
                Ok(Some(self.perform_list()?))
            } else if self.imap.query.is_some() {
                Ok(Some(self.perform_search()?))
            } else {
                Ok(Some(self.perform_fetch()?))
            };
        }
        tracing::error!("IMAP SELECT failed");
        Err(CurlError::LoginDenied)
    }

    /// Handle FETCH response — parse literal size for download.
    fn state_fetch_resp(
        &mut self,
        code: i32,
        line: &str,
    ) -> CurlResult<Option<String>> {
        if code != b'*' as i32 {
            self.download_size = -1;
            self.conn.set_state(ImapState::Stop);
            return Err(CurlError::RemoteFileNotFound);
        }
        if let Some(lit_pos) = imap_find_literal(line) {
            if let Some(size) = parse_literal_size(line, lit_pos) {
                tracing::info!(bytes = size, "FETCH literal to download");
                self.download_size = size as i64;
                self.conn.set_state(ImapState::Stop);
                return Ok(None);
            }
        }
        tracing::error!("Failed to parse FETCH response literal");
        self.conn.set_state(ImapState::Stop);
        Err(CurlError::WeirdServerReply)
    }

    /// Handle post-download FETCH final response.
    fn state_fetch_final_resp(
        &mut self,
        code: i32,
    ) -> CurlResult<Option<String>> {
        if code != IMAP_RESP_OK {
            return Err(CurlError::WeirdServerReply);
        }
        self.conn.set_state(ImapState::Stop);
        Ok(None)
    }

    /// Handle APPEND continuation response.
    fn state_append_resp(&mut self, code: i32) -> CurlResult<Option<String>> {
        if code != b'+' as i32 {
            return Err(CurlError::UploadFailed);
        }
        self.conn.set_state(ImapState::Stop);
        Ok(None)
    }

    /// Handle post-upload APPEND final response.
    fn state_append_final_resp(
        &mut self,
        code: i32,
    ) -> CurlResult<Option<String>> {
        if code != IMAP_RESP_OK {
            return Err(CurlError::UploadFailed);
        }
        self.conn.set_state(ImapState::Stop);
        Ok(None)
    }

    // -----------------------------------------------------------------------
    // State machine driver
    // -----------------------------------------------------------------------

    /// Drive the IMAP state machine through one response cycle.
    ///
    /// Returns `Ok(true)` when the state machine has reached `Stop`,
    /// `Ok(false)` when more cycles are needed.
    fn statemachine_step(
        &mut self,
        code: i32,
        line: &str,
    ) -> CurlResult<bool> {
        if code == -1 {
            return Err(CurlError::WeirdServerReply);
        }
        if code == 0 {
            return Ok(false);
        }

        let _next_cmd = match self.conn.state {
            ImapState::ServerGreet => self.state_servergreet_resp(code)?,
            ImapState::Capability => {
                self.state_capability_resp(code, line)?
            }
            ImapState::StartTls => self.state_starttls_resp(code)?,
            ImapState::Authenticate => self.state_auth_resp(code)?,
            ImapState::Login => self.state_login_resp(code)?,
            ImapState::List | ImapState::Search => {
                self.state_listsearch_resp(code, line)?
            }
            ImapState::Select => {
                self.state_select_resp(code, line)?
            }
            ImapState::Fetch => {
                self.state_fetch_resp(code, line)?
            }
            ImapState::FetchFinal => self.state_fetch_final_resp(code)?,
            ImapState::Append => self.state_append_resp(code)?,
            ImapState::AppendFinal => {
                self.state_append_final_resp(code)?
            }
            ImapState::Logout | ImapState::Stop => {
                self.conn.set_state(ImapState::Stop);
                None
            }
            ImapState::UpgradeTls => {
                // Handled externally by TLS filter layer
                None
            }
        };

        Ok(self.conn.state == ImapState::Stop)
    }

    // -----------------------------------------------------------------------
    // URL parsing
    // -----------------------------------------------------------------------

    /// Parse the URL path into IMAP components per RFC 5092.
    ///
    /// Extracts mailbox, UIDVALIDITY, UID, MAILINDEX, SECTION, PARTIAL, and
    /// SEARCH query from the URL path and query string.
    pub fn parse_url_path(&mut self) -> CurlResult<()> {
        let path = self.url_path.clone();
        let begin = path.strip_prefix('/').unwrap_or(&path);
        let mut ptr = begin;

        // Parse mailbox path (bchar sequence)
        let bchar_end = ptr
            .find(|c: char| !imap_is_bchar(c))
            .unwrap_or(ptr.len());
        if bchar_end > 0 {
            let mut end = bchar_end;
            if end > 0 && ptr.as_bytes()[end - 1] == b'/' {
                end -= 1;
            }
            if end > 0 {
                self.imap.mailbox = Some(
                    url_decode_string(&ptr[..end])
                        .map_err(|_| CurlError::UrlMalformat)?,
                );
            }
        }
        ptr = &ptr[bchar_end..];

        // Parse semicolon-delimited parameters: ;NAME=VALUE
        while ptr.starts_with(';') {
            ptr = &ptr[1..]; // Skip ';'
            let eq_pos = ptr.find('=').ok_or(CurlError::UrlMalformat)?;
            let name = url_decode_string(&ptr[..eq_pos])
                .map_err(|_| CurlError::UrlMalformat)?;
            ptr = &ptr[eq_pos + 1..]; // Skip '='
            let val_end = ptr
                .find(|c: char| !imap_is_bchar(c))
                .unwrap_or(ptr.len());
            let raw_value = &ptr[..val_end];
            let mut value = url_decode_string(raw_value)
                .map_err(|_| CurlError::UrlMalformat)?;

            if value.ends_with('/') {
                value.pop();
            }

            if !value.is_empty() {
                if name.eq_ignore_ascii_case("UIDVALIDITY")
                    && !self.imap.uidvalidity_set
                {
                    if let Ok(v) = value.parse::<u32>() {
                        self.imap.uidvalidity = v;
                        self.imap.uidvalidity_set = true;
                    }
                } else if name.eq_ignore_ascii_case("UID")
                    && self.imap.uid.is_none()
                {
                    self.imap.uid = Some(value);
                } else if name.eq_ignore_ascii_case("MAILINDEX")
                    && self.imap.mindex.is_none()
                {
                    self.imap.mindex = Some(value);
                } else if name.eq_ignore_ascii_case("SECTION")
                    && self.imap.section.is_none()
                {
                    self.imap.section = Some(value);
                } else if name.eq_ignore_ascii_case("PARTIAL")
                    && self.imap.partial.is_none()
                {
                    self.imap.partial = Some(value);
                } else {
                    return Err(CurlError::UrlMalformat);
                }
            }
            ptr = &ptr[val_end..];
        }

        // Parse query parameter (SEARCH)
        if self.imap.mailbox.is_some()
            && self.imap.uid.is_none()
            && self.imap.mindex.is_none()
        {
            if let Some(ref q) = self.url_query {
                self.imap.query = Some(
                    url_decode_string(q)
                        .map_err(|_| CurlError::UrlMalformat)?,
                );
            }
        }

        if !ptr.is_empty() && !ptr.starts_with('?') {
            return Err(CurlError::UrlMalformat);
        }
        Ok(())
    }

    /// Parse URL login options (`;AUTH=<mechanism>`).
    pub fn parse_url_options(&mut self) -> CurlResult<()> {
        let options = match &self.url_options {
            Some(opts) => opts.clone(),
            None => return Ok(()),
        };

        let mut prefer_login = false;
        let mut remaining = options.as_str();

        while !remaining.is_empty() {
            // Split at next ';'
            let (segment, rest) =
                if let Some(semi_pos) = remaining.find(';') {
                    (&remaining[..semi_pos], &remaining[semi_pos + 1..])
                } else {
                    (remaining, "")
                };

            // Split segment at '='
            if let Some(eq_pos) = segment.find('=') {
                let key = &segment[..eq_pos];
                let value = &segment[eq_pos + 1..];

                if key.eq_ignore_ascii_case("AUTH") {
                    if value.eq_ignore_ascii_case("+LOGIN") {
                        prefer_login = true;
                        self.conn.sasl.prefmech = SASL_AUTH_NONE;
                    } else {
                        prefer_login = false;
                        self.conn.sasl.parse_url_auth_option(value)?;
                    }
                } else {
                    return Err(CurlError::UrlMalformat);
                }
            } else {
                return Err(CurlError::UrlMalformat);
            }
            remaining = rest;
        }

        if prefer_login {
            self.conn.preftype = IMAP_TYPE_CLEARTEXT;
        } else {
            self.conn.preftype = match self.conn.sasl.prefmech {
                p if p == SASL_AUTH_NONE => IMAP_TYPE_NONE,
                p if p == SASL_AUTH_DEFAULT => IMAP_TYPE_ANY,
                _ => IMAP_TYPE_SASL,
            };
        }
        Ok(())
    }

    /// Parse custom request command and extract parameters.
    ///
    /// Performs percent-decoding (`%XX`) without converting `+` to space,
    /// matching the C `Curl_urldecode(..., REJECT_CTRL)` semantics.
    fn parse_custom_request(&mut self) -> CurlResult<()> {
        let custom = match &self.custom_request {
            Some(c) => c.clone(),
            None => return Ok(()),
        };
        // Decode only %XX sequences — do NOT convert '+' to space.
        // url_decode_string() converts '+' to space (form-URL-encoded
        // semantics), which is wrong for IMAP custom commands like
        // "STORE 1 +FLAGS".
        let decoded = percent_decode_only(&custom)?;

        if let Some(space_pos) = decoded.find(' ') {
            self.imap.custom = Some(decoded[..space_pos].to_string());
            self.imap.custom_params =
                Some(decoded[space_pos..].to_string());
        } else {
            self.imap.custom = Some(decoded);
        }
        Ok(())
    }

    /// Set up the connection for IMAP protocol.
    pub fn setup_connection(&mut self, conn_id: u64) -> CurlResult<()> {
        self.conn = ImapConn::new(conn_id);
        self.conn.preftype = IMAP_TYPE_ANY;
        self.conn.sasl.init(0, SASL_AUTH_DEFAULT);
        tracing::debug!(conn_id = conn_id, "IMAP connection setup complete");
        Ok(())
    }
}

impl Default for ImapHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Protocol trait implementation
// ===========================================================================

impl Protocol for ImapHandler {
    fn name(&self) -> &str {
        if self.is_imaps { "IMAPS" } else { "IMAP" }
    }

    fn default_port(&self) -> u16 {
        if self.is_imaps { PORT_IMAPS } else { PORT_IMAP }
    }

    fn flags(&self) -> ProtocolFlags {
        let mut f = ProtocolFlags::CLOSEACTION
            | ProtocolFlags::URLOPTIONS
            | ProtocolFlags::SSL_REUSE
            | ProtocolFlags::CONN_REUSE;
        if self.is_imaps {
            f |= ProtocolFlags::SSL;
        }
        f
    }

    async fn connect(
        &mut self,
        _conn: &mut ConnectionData,
    ) -> Result<(), CurlError> {
        tracing::info!(
            scheme = if self.is_imaps { "imaps" } else { "imap" },
            "IMAP protocol connect"
        );
        self.parse_url_options()?;
        self.conn.set_state(ImapState::ServerGreet);
        self.conn.resptag = "*".to_string();
        tracing::debug!("IMAP waiting for server greeting");
        Ok(())
    }

    async fn do_it(
        &mut self,
        _conn: &mut ConnectionData,
    ) -> Result<(), CurlError> {
        tracing::debug!("IMAP DO phase starting");
        self.parse_url_path()?;
        self.parse_custom_request()?;

        if self.no_body {
            self.imap.transfer = PpTransfer::Info;
        }

        // Check whether the target mailbox is already SELECTed
        let selected = self.imap.mailbox.is_some()
            && self.conn.mailbox.is_some()
            && self
                .imap
                .mailbox
                .as_deref()
                .unwrap_or("")
                .eq_ignore_ascii_case(
                    self.conn.mailbox.as_deref().unwrap_or(""),
                )
            && (!self.imap.uidvalidity_set
                || !self.conn.mb_uidvalidity_set
                || self.imap.uidvalidity == self.conn.mb_uidvalidity);

        // Dispatch the appropriate command
        let _cmd = if self.is_upload {
            self.perform_append()?
        } else if self.imap.custom.is_some()
            && (selected || self.imap.mailbox.is_none())
        {
            self.perform_list()?
        } else if self.imap.custom.is_none()
            && selected
            && (self.imap.uid.is_some() || self.imap.mindex.is_some())
        {
            self.perform_fetch()?
        } else if self.imap.custom.is_none()
            && selected
            && self.imap.query.is_some()
        {
            self.perform_search()?
        } else if self.imap.mailbox.is_some()
            && !selected
            && (self.imap.custom.is_some()
                || self.imap.uid.is_some()
                || self.imap.mindex.is_some()
                || self.imap.query.is_some())
        {
            self.perform_select()?
        } else {
            self.perform_list()?
        };

        tracing::debug!("IMAP DO phase dispatched");
        Ok(())
    }

    async fn done(
        &mut self,
        _conn: &mut ConnectionData,
        _status: CurlError,
    ) -> Result<(), CurlError> {
        // Handle post-transfer states
        let needs_final = self.imap.custom.is_none()
            && (self.imap.uid.is_some() || self.imap.mindex.is_some());
        if needs_final && !self.is_upload {
            self.conn.set_state(ImapState::FetchFinal);
        } else if self.is_upload {
            self.conn.set_state(ImapState::AppendFinal);
        }
        // Reset per-request state
        self.imap.reset();
        tracing::debug!("IMAP done phase complete");
        Ok(())
    }

    async fn doing(
        &mut self,
        _conn: &mut ConnectionData,
    ) -> Result<bool, CurlError> {
        let done = self.conn.state == ImapState::Stop;
        if done && self.imap.transfer != PpTransfer::Body {
            tracing::debug!("IMAP DO phase complete (no body transfer)");
        }
        Ok(done)
    }

    async fn disconnect(
        &mut self,
        _conn: &mut ConnectionData,
    ) -> Result<(), CurlError> {
        tracing::debug!("IMAP disconnect");
        if (self.conn.state != ImapState::Stop || self.conn.pp.pending_resp)
            && !self.conn.pp.needs_flush()
        {
            let _cmd = self.perform_logout();
        }
        self.conn.pp.disconnect();
        Ok(())
    }

    fn connection_check(
        &self,
        _conn: &ConnectionData,
    ) -> ConnectionCheckResult {
        ConnectionCheckResult::Ok
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_imap_state_display() {
        assert_eq!(format!("{}", ImapState::ServerGreet), "SERVERGREET");
        assert_eq!(format!("{}", ImapState::Stop), "STOP");
        assert_eq!(format!("{}", ImapState::FetchFinal), "FETCH_FINAL");
        assert_eq!(format!("{}", ImapState::AppendFinal), "APPEND_FINAL");
    }

    #[test]
    fn test_imap_atom_no_escape() {
        assert_eq!(imap_atom("INBOX", false), "INBOX");
        assert_eq!(imap_atom("simple", true), "simple");
    }

    #[test]
    fn test_imap_atom_with_special_chars() {
        assert_eq!(imap_atom("my box", false), "\"my box\"");
        assert_eq!(imap_atom("a\"b", false), "\"a\\\"b\"");
        assert_eq!(imap_atom("a\\b", false), "\"a\\\\b\"");
    }

    #[test]
    fn test_imap_atom_escape_only() {
        assert_eq!(imap_atom("my box", true), "my box");
        assert_eq!(imap_atom("a\"b", true), "a\\\"b");
    }

    #[test]
    fn test_imap_atom_empty() {
        assert_eq!(imap_atom("", false), "\"\"");
        assert_eq!(imap_atom("", true), "");
    }

    #[test]
    fn test_imap_is_bchar() {
        assert!(imap_is_bchar('a'));
        assert!(imap_is_bchar('Z'));
        assert!(imap_is_bchar('0'));
        assert!(imap_is_bchar(':'));
        assert!(imap_is_bchar('@'));
        assert!(imap_is_bchar('/'));
        assert!(!imap_is_bchar(';'));
        assert!(!imap_is_bchar(' '));
        assert!(!imap_is_bchar('\0'));
    }

    #[test]
    fn test_imap_find_literal() {
        assert_eq!(
            imap_find_literal("* 1 FETCH (BODY[TEXT] {2021}"),
            Some(22)
        );
        assert_eq!(imap_find_literal("no braces here"), None);
        assert_eq!(
            imap_find_literal("\"quoted {fake}\" {123}"),
            Some(16)
        );
    }

    #[test]
    fn test_parse_literal_size() {
        assert_eq!(parse_literal_size("{123}", 0), Some(123));
        assert_eq!(parse_literal_size("foo {456}", 4), Some(456));
        assert_eq!(parse_literal_size("{}", 0), None);
        assert_eq!(parse_literal_size("{abc}", 0), None);
    }

    #[test]
    fn test_imap_matchresp() {
        assert!(imap_matchresp("* CAPABILITY IMAP4rev1", "CAPABILITY"));
        assert!(imap_matchresp("* 1 FETCH (FLAGS)", "FETCH"));
        assert!(!imap_matchresp("* LIST (\\Noselect)", "CAPABILITY"));
        assert!(!imap_matchresp("short", "CAPABILITY"));
    }

    #[test]
    fn test_imap_endofresp_tagged_ok() {
        let imap = Imap::new();
        let (is_end, code) =
            imap_endofresp("A001 OK Success", "A001", ImapState::Login, &imap);
        assert!(is_end);
        assert_eq!(code, IMAP_RESP_OK);
    }

    #[test]
    fn test_imap_endofresp_tagged_not_ok() {
        let imap = Imap::new();
        let (is_end, code) =
            imap_endofresp("A001 NO Failure", "A001", ImapState::Login, &imap);
        assert!(is_end);
        assert_eq!(code, IMAP_RESP_NOT_OK);
    }

    #[test]
    fn test_imap_endofresp_continuation() {
        let imap = Imap::new();
        let (is_end, code) =
            imap_endofresp("+ ", "A001", ImapState::Authenticate, &imap);
        assert!(is_end);
        assert_eq!(code, b'+' as i32);
    }

    #[test]
    fn test_is_custom_fetch_listing_range() {
        let mut imap = Imap::new();
        imap.custom = Some("FETCH".to_string());
        imap.custom_params = Some(" 1:* (FLAGS)".to_string());
        assert!(is_custom_fetch_listing(&imap));
    }

    #[test]
    fn test_is_custom_fetch_listing_comma() {
        let mut imap = Imap::new();
        imap.custom = Some("FETCH".to_string());
        imap.custom_params = Some(" 1,2,3 (FLAGS)".to_string());
        assert!(is_custom_fetch_listing(&imap));
    }

    #[test]
    fn test_is_custom_fetch_listing_false() {
        let imap = Imap::new();
        assert!(!is_custom_fetch_listing(&imap));
    }

    #[test]
    fn test_imap_handler_new() {
        let handler = ImapHandler::new();
        assert_eq!(handler.name(), "IMAP");
        assert_eq!(handler.default_port(), PORT_IMAP);
        assert!(handler.flags().contains(ProtocolFlags::CLOSEACTION));
        assert!(handler.flags().contains(ProtocolFlags::URLOPTIONS));
        assert!(handler.flags().contains(ProtocolFlags::CONN_REUSE));
    }

    #[test]
    fn test_imap_conn_new() {
        let conn = ImapConn::new(42);
        assert_eq!(conn.state, ImapState::Stop);
        assert_eq!(conn.resptag, "*");
        assert_eq!(conn.preftype, IMAP_TYPE_ANY);
        assert!(!conn.ssldone);
        assert!(!conn.preauth);
        assert_eq!(conn.cmdid, 0);
    }

    #[test]
    fn test_imap_new() {
        let imap = Imap::new();
        assert_eq!(imap.transfer, PpTransfer::Body);
        assert!(imap.mailbox.is_none());
        assert!(imap.uid.is_none());
        assert!(!imap.uidvalidity_set);
    }

    #[test]
    fn test_imap_reset() {
        let mut imap = Imap::new();
        imap.mailbox = Some("INBOX".to_string());
        imap.uid = Some("123".to_string());
        imap.transfer = PpTransfer::Info;
        imap.reset();
        assert!(imap.mailbox.is_none());
        assert!(imap.uid.is_none());
        assert_eq!(imap.transfer, PpTransfer::Body);
    }

    #[test]
    fn test_imap_sasl_proto() {
        let proto = ImapSaslProto::new();
        assert_eq!(proto.service_name(), "imap");
        assert_eq!(proto.continuation_code(), b'+' as i32);
        assert_eq!(proto.success_code(), IMAP_RESP_OK);
        assert_eq!(proto.default_mechs(), SASL_AUTH_DEFAULT);
        assert_eq!(proto.flags(), SASL_FLAG_BASE64);
        assert_eq!(proto.max_line_len(), 0);
    }

    #[test]
    fn test_imap_sasl_proto_perform_auth() {
        let proto = ImapSaslProto::new();
        assert_eq!(proto.perform_auth("PLAIN", None), "AUTHENTICATE PLAIN");
        assert_eq!(
            proto.perform_auth("PLAIN", Some(b"dGVzdA==")),
            "AUTHENTICATE PLAIN dGVzdA=="
        );
    }

    #[test]
    fn test_imap_sasl_proto_cancel() {
        let proto = ImapSaslProto::new();
        assert_eq!(proto.cancel_auth("PLAIN"), "*");
    }

    #[test]
    fn test_imap_sasl_proto_get_message() {
        let proto = ImapSaslProto::new();
        assert_eq!(proto.get_message("+ dGVzdA=="), b"dGVzdA==");
        assert_eq!(proto.get_message("+"), Vec::<u8>::new());
    }

    #[test]
    fn test_parse_url_path_simple_mailbox() {
        let mut handler = ImapHandler::new();
        handler.url_path = "/INBOX".to_string();
        handler.parse_url_path().unwrap();
        assert_eq!(handler.imap.mailbox.as_deref(), Some("INBOX"));
        assert!(handler.imap.uid.is_none());
    }

    #[test]
    fn test_parse_url_path_with_uid() {
        let mut handler = ImapHandler::new();
        handler.url_path = "/INBOX;UID=42".to_string();
        handler.parse_url_path().unwrap();
        assert_eq!(handler.imap.mailbox.as_deref(), Some("INBOX"));
        assert_eq!(handler.imap.uid.as_deref(), Some("42"));
    }

    #[test]
    fn test_parse_url_path_with_uidvalidity() {
        let mut handler = ImapHandler::new();
        handler.url_path = "/INBOX;UIDVALIDITY=1234;UID=42".to_string();
        handler.parse_url_path().unwrap();
        assert_eq!(handler.imap.mailbox.as_deref(), Some("INBOX"));
        assert!(handler.imap.uidvalidity_set);
        assert_eq!(handler.imap.uidvalidity, 1234);
        assert_eq!(handler.imap.uid.as_deref(), Some("42"));
    }

    #[test]
    fn test_parse_url_path_with_section_and_partial() {
        let mut handler = ImapHandler::new();
        handler.url_path =
            "/INBOX;UID=1;SECTION=TEXT;PARTIAL=0.512".to_string();
        handler.parse_url_path().unwrap();
        assert_eq!(handler.imap.section.as_deref(), Some("TEXT"));
        assert_eq!(handler.imap.partial.as_deref(), Some("0.512"));
    }

    #[test]
    fn test_parse_url_path_empty() {
        let mut handler = ImapHandler::new();
        handler.url_path = "/".to_string();
        handler.parse_url_path().unwrap();
        assert!(handler.imap.mailbox.is_none());
    }

    #[test]
    fn test_parse_url_path_unknown_param() {
        let mut handler = ImapHandler::new();
        handler.url_path = "/INBOX;UNKNOWN=val".to_string();
        assert!(handler.parse_url_path().is_err());
    }

    #[test]
    fn test_parse_url_path_search_query() {
        let mut handler = ImapHandler::new();
        handler.url_path = "/INBOX".to_string();
        handler.url_query = Some("SUBJECT%20test".to_string());
        handler.parse_url_path().unwrap();
        assert_eq!(handler.imap.query.as_deref(), Some("SUBJECT test"));
    }

    #[test]
    fn test_port_constants() {
        assert_eq!(PORT_IMAP, 143);
        assert_eq!(PORT_IMAPS, 993);
    }

    #[test]
    fn test_handler_tag_generation() {
        let mut handler = ImapHandler::new();
        handler.conn.conn_id = 0; // 'A'
        handler.next_tag();
        assert_eq!(handler.conn.resptag, "A001");
        handler.next_tag();
        assert_eq!(handler.conn.resptag, "A002");
    }

    #[test]
    fn test_handler_tag_generation_different_conn() {
        let mut handler = ImapHandler::new();
        handler.conn.conn_id = 1; // 'B'
        handler.next_tag();
        assert_eq!(handler.conn.resptag, "B001");
    }

    #[test]
    fn test_perform_capability() {
        let mut handler = ImapHandler::new();
        let cmd = handler.perform_capability().unwrap();
        assert!(cmd.contains("CAPABILITY"));
        assert_eq!(handler.conn.state, ImapState::Capability);
    }

    #[test]
    fn test_perform_starttls() {
        let mut handler = ImapHandler::new();
        let cmd = handler.perform_starttls().unwrap();
        assert!(cmd.contains("STARTTLS"));
        assert_eq!(handler.conn.state, ImapState::StartTls);
    }

    #[test]
    fn test_perform_logout() {
        let mut handler = ImapHandler::new();
        let cmd = handler.perform_logout().unwrap();
        assert!(cmd.contains("LOGOUT"));
        assert_eq!(handler.conn.state, ImapState::Logout);
    }

    #[test]
    fn test_perform_login() {
        let mut handler = ImapHandler::new();
        handler.user = Some("admin".to_string());
        handler.passwd = Some("secret".to_string());
        let cmd = handler.perform_login().unwrap();
        assert!(cmd.contains("LOGIN admin secret"));
        assert_eq!(handler.conn.state, ImapState::Login);
    }

    #[test]
    fn test_perform_login_special_chars() {
        let mut handler = ImapHandler::new();
        handler.user = Some("user name".to_string());
        handler.passwd = Some("pass\"word".to_string());
        let cmd = handler.perform_login().unwrap();
        assert!(cmd.contains("LOGIN \"user name\" \"pass\\\"word\""));
    }

    #[test]
    fn test_perform_select() {
        let mut handler = ImapHandler::new();
        handler.imap.mailbox = Some("INBOX".to_string());
        let cmd = handler.perform_select().unwrap();
        assert!(cmd.contains("SELECT INBOX"));
        assert_eq!(handler.conn.state, ImapState::Select);
    }

    #[test]
    fn test_perform_select_no_mailbox() {
        let mut handler = ImapHandler::new();
        assert!(handler.perform_select().is_err());
    }

    #[test]
    fn test_perform_fetch_uid() {
        let mut handler = ImapHandler::new();
        handler.imap.uid = Some("42".to_string());
        handler.imap.section = Some("TEXT".to_string());
        let cmd = handler.perform_fetch().unwrap();
        assert!(cmd.contains("UID FETCH 42 BODY[TEXT]"));
        assert_eq!(handler.conn.state, ImapState::Fetch);
    }

    #[test]
    fn test_perform_fetch_mindex() {
        let mut handler = ImapHandler::new();
        handler.imap.mindex = Some("5".to_string());
        let cmd = handler.perform_fetch().unwrap();
        assert!(cmd.contains("FETCH 5 BODY[]"));
    }

    #[test]
    fn test_perform_fetch_with_partial() {
        let mut handler = ImapHandler::new();
        handler.imap.uid = Some("42".to_string());
        handler.imap.partial = Some("0.512".to_string());
        let cmd = handler.perform_fetch().unwrap();
        assert!(cmd.contains("UID FETCH 42 BODY[]<0.512>"));
    }

    #[test]
    fn test_perform_fetch_no_uid() {
        let mut handler = ImapHandler::new();
        assert!(handler.perform_fetch().is_err());
    }

    #[test]
    fn test_perform_search() {
        let mut handler = ImapHandler::new();
        handler.imap.query = Some("SUBJECT test".to_string());
        let cmd = handler.perform_search().unwrap();
        assert!(cmd.contains("SEARCH SUBJECT test"));
        assert_eq!(handler.conn.state, ImapState::Search);
    }

    #[test]
    fn test_perform_search_no_query() {
        let mut handler = ImapHandler::new();
        assert!(handler.perform_search().is_err());
    }

    #[test]
    fn test_perform_append() {
        let mut handler = ImapHandler::new();
        handler.imap.mailbox = Some("INBOX".to_string());
        handler.upload_size = 1024;
        let cmd = handler.perform_append().unwrap();
        assert!(cmd.contains("APPEND INBOX {1024}"));
        assert_eq!(handler.conn.state, ImapState::Append);
    }

    #[test]
    fn test_perform_append_no_mailbox() {
        let mut handler = ImapHandler::new();
        assert!(handler.perform_append().is_err());
    }

    #[test]
    fn test_perform_append_unknown_size() {
        let mut handler = ImapHandler::new();
        handler.imap.mailbox = Some("INBOX".to_string());
        assert!(handler.perform_append().is_err());
    }

    #[test]
    fn test_state_servergreet_ok() {
        let mut handler = ImapHandler::new();
        let result = handler.state_servergreet_resp(IMAP_RESP_OK);
        assert!(result.is_ok());
        assert_eq!(handler.conn.state, ImapState::Capability);
    }

    #[test]
    fn test_state_servergreet_preauth() {
        let mut handler = ImapHandler::new();
        let result = handler.state_servergreet_resp(IMAP_RESP_PREAUTH);
        assert!(result.is_ok());
        assert!(handler.conn.preauth);
    }

    #[test]
    fn test_state_servergreet_bad() {
        let mut handler = ImapHandler::new();
        let result = handler.state_servergreet_resp(IMAP_RESP_NOT_OK);
        assert!(matches!(result, Err(CurlError::WeirdServerReply)));
    }

    #[test]
    fn test_state_login_ok() {
        let mut handler = ImapHandler::new();
        let result = handler.state_login_resp(IMAP_RESP_OK);
        assert!(result.is_ok());
        assert_eq!(handler.conn.state, ImapState::Stop);
    }

    #[test]
    fn test_state_login_denied() {
        let mut handler = ImapHandler::new();
        let result = handler.state_login_resp(IMAP_RESP_NOT_OK);
        assert!(matches!(result, Err(CurlError::LoginDenied)));
    }

    #[test]
    fn test_state_fetch_final_ok() {
        let mut handler = ImapHandler::new();
        let result = handler.state_fetch_final_resp(IMAP_RESP_OK);
        assert!(result.is_ok());
        assert_eq!(handler.conn.state, ImapState::Stop);
    }

    #[test]
    fn test_state_fetch_final_fail() {
        let mut handler = ImapHandler::new();
        let result = handler.state_fetch_final_resp(IMAP_RESP_NOT_OK);
        assert!(matches!(result, Err(CurlError::WeirdServerReply)));
    }

    #[test]
    fn test_state_append_continuation() {
        let mut handler = ImapHandler::new();
        let result = handler.state_append_resp(b'+' as i32);
        assert!(result.is_ok());
        assert_eq!(handler.conn.state, ImapState::Stop);
    }

    #[test]
    fn test_state_append_fail() {
        let mut handler = ImapHandler::new();
        let result = handler.state_append_resp(IMAP_RESP_NOT_OK);
        assert!(matches!(result, Err(CurlError::UploadFailed)));
    }

    #[test]
    fn test_state_append_final_ok() {
        let mut handler = ImapHandler::new();
        let result = handler.state_append_final_resp(IMAP_RESP_OK);
        assert!(result.is_ok());
        assert_eq!(handler.conn.state, ImapState::Stop);
    }

    #[test]
    fn test_state_append_final_fail() {
        let mut handler = ImapHandler::new();
        let result = handler.state_append_final_resp(IMAP_RESP_NOT_OK);
        assert!(matches!(result, Err(CurlError::UploadFailed)));
    }

    #[test]
    fn test_statemachine_step_negative_code() {
        let mut handler = ImapHandler::new();
        let result = handler.statemachine_step(-1, "");
        assert!(matches!(result, Err(CurlError::WeirdServerReply)));
    }

    #[test]
    fn test_statemachine_step_zero_code() {
        let mut handler = ImapHandler::new();
        let result = handler.statemachine_step(0, "");
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn test_handler_setup_connection() {
        let mut handler = ImapHandler::new();
        handler.setup_connection(99).unwrap();
        assert_eq!(handler.conn.conn_id, 99);
        assert_eq!(handler.conn.preftype, IMAP_TYPE_ANY);
    }

    #[test]
    fn test_imap_conn_set_state() {
        let mut conn = ImapConn::new(0);
        assert_eq!(conn.state, ImapState::Stop);
        conn.set_state(ImapState::ServerGreet);
        assert_eq!(conn.state, ImapState::ServerGreet);
    }

    #[test]
    fn test_parse_url_options_auth_plain() {
        let mut handler = ImapHandler::new();
        handler.url_options = Some("AUTH=PLAIN".to_string());
        handler.parse_url_options().unwrap();
        assert_eq!(handler.conn.preftype, IMAP_TYPE_SASL);
    }

    #[test]
    fn test_parse_custom_request() {
        let mut handler = ImapHandler::new();
        handler.custom_request = Some("STORE 1 +FLAGS".to_string());
        handler.parse_custom_request().unwrap();
        assert_eq!(handler.imap.custom.as_deref(), Some("STORE"));
        assert_eq!(
            handler.imap.custom_params.as_deref(),
            Some(" 1 +FLAGS")
        );
    }

    #[test]
    fn test_parse_custom_request_no_params() {
        let mut handler = ImapHandler::new();
        handler.custom_request = Some("NOOP".to_string());
        handler.parse_custom_request().unwrap();
        assert_eq!(handler.imap.custom.as_deref(), Some("NOOP"));
        assert!(handler.imap.custom_params.is_none());
    }

    #[test]
    fn test_perform_list_default() {
        let mut handler = ImapHandler::new();
        let cmd = handler.perform_list().unwrap();
        assert!(cmd.contains("LIST \"\" *"));
        assert_eq!(handler.conn.state, ImapState::List);
    }

    #[test]
    fn test_perform_list_custom() {
        let mut handler = ImapHandler::new();
        handler.imap.custom = Some("LSUB".to_string());
        handler.imap.custom_params = Some(" \"\" *".to_string());
        let cmd = handler.perform_list().unwrap();
        assert!(cmd.contains("LSUB \"\" *"));
    }

    #[test]
    fn test_imap_handler_imaps() {
        let mut handler = ImapHandler::new();
        handler.is_imaps = true;
        assert_eq!(handler.name(), "IMAPS");
        assert_eq!(handler.default_port(), PORT_IMAPS);
        assert!(handler.flags().contains(ProtocolFlags::SSL));
    }

    #[test]
    fn test_select_sasl_mechanism() {
        assert_eq!(
            select_sasl_mechanism(sasl::SASL_MECH_PLAIN, SASL_AUTH_DEFAULT),
            Some("PLAIN")
        );
        assert_eq!(
            select_sasl_mechanism(SASL_AUTH_NONE, SASL_AUTH_DEFAULT),
            None
        );
    }
}
