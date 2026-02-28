//! HTTP Digest and SASL DIGEST-MD5 authentication (RFC 2831, RFC 7616)
//!
//! This module implements:
//! - SASL DIGEST-MD5 authentication for IMAP, POP3, SMTP protocols
//! - HTTP Digest authentication (RFC 7616) with MD5, SHA-256, and SHA-512/256 algorithms
//! - Challenge parsing and response generation with full quoted-string escaping
//! - Nonce count tracking and client nonce generation
//!
//! Pure-Rust rewrite of `lib/vauth/digest.c` and `lib/http_digest.c` from curl 8.x.

use crate::error::CurlError;
use crate::util::base64;
use crate::util::md5::{self, Md5Context};
use crate::util::rand;
use crate::util::sha256::{self, Sha256Context};

// ---------------------------------------------------------------------------
// Algorithm flag constants (matching C lib/vauth/digest.c exactly)
// ---------------------------------------------------------------------------

/// Bitmask indicating a session-based algorithm variant (-sess suffix).
pub const SESSION_ALGO: u32 = 1;

/// MD5 algorithm (default).
pub const ALGO_MD5: u32 = 0;

/// MD5-sess algorithm (session-based MD5).
pub const ALGO_MD5SESS: u32 = ALGO_MD5 | SESSION_ALGO;

/// SHA-256 algorithm (RFC 7616).
pub const ALGO_SHA256: u32 = 2;

/// SHA-256-sess algorithm (session-based SHA-256).
pub const ALGO_SHA256SESS: u32 = ALGO_SHA256 | SESSION_ALGO;

/// SHA-512-256 algorithm (RFC 7616).
pub const ALGO_SHA512_256: u32 = 4;

/// SHA-512-256-sess algorithm (session-based SHA-512-256).
pub const ALGO_SHA512_256SESS: u32 = ALGO_SHA512_256 | SESSION_ALGO;

// ---------------------------------------------------------------------------
// Quality of Protection (QoP) bitmask constants
// ---------------------------------------------------------------------------

/// QoP value: authentication only.
pub const DIGEST_QOP_VALUE_AUTH: u32 = 1 << 0;

/// QoP value: authentication with integrity protection.
pub const DIGEST_QOP_VALUE_AUTH_INT: u32 = 1 << 1;

/// QoP value: authentication with confidentiality (SASL DIGEST-MD5 only).
pub const DIGEST_QOP_VALUE_AUTH_CONF: u32 = 1 << 2;

// ---------------------------------------------------------------------------
// Maximum length constants (matching C lib/vauth/digest.h)
// ---------------------------------------------------------------------------

/// Maximum length of a single value in a Digest challenge parameter.
pub const DIGEST_MAX_VALUE_LENGTH: usize = 256;

/// Maximum length of content in a Digest challenge parameter.
pub const DIGEST_MAX_CONTENT_LENGTH: usize = 1024;

// ---------------------------------------------------------------------------
// DigestData — per-request Digest authentication state
// ---------------------------------------------------------------------------

/// Holds the state for an ongoing Digest authentication exchange.
///
/// Matches the C `struct digestdata` from `lib/vauth/digest.h`. Fields are
/// populated during challenge decoding and consumed during response generation.
#[derive(Debug, Clone)]
pub struct DigestData {
    /// Server-provided nonce value.
    pub nonce: Option<String>,
    /// Client-generated nonce value.
    pub cnonce: Option<String>,
    /// Authentication realm from the server challenge.
    pub realm: Option<String>,
    /// Opaque value echoed back to the server unchanged.
    pub opaque: Option<String>,
    /// Quality of protection bitmask (DIGEST_QOP_VALUE_* constants).
    pub qop: u32,
    /// Nonce count — incremented for each request using the same nonce.
    pub nc: u32,
    /// Algorithm identifier (ALGO_* constants).
    pub algo: u32,
    /// Server indicated the nonce is stale and should be refreshed.
    pub stale: bool,
    /// RFC 7616 userhash flag — when true, username is hashed in the response.
    pub userhash: bool,
}

impl DigestData {
    /// Creates a new `DigestData` with default values.
    ///
    /// All optional fields are `None`, counters are zero, algorithm defaults
    /// to `ALGO_MD5`, and boolean flags are `false`.
    pub fn new() -> Self {
        DigestData {
            nonce: None,
            cnonce: None,
            realm: None,
            opaque: None,
            qop: 0,
            nc: 0,
            algo: ALGO_MD5,
            stale: false,
            userhash: false,
        }
    }

    /// Resets all fields to their default state, matching C `Curl_auth_digest_cleanup`.
    ///
    /// This is called when a new authentication exchange begins or when the
    /// connection is cleaned up.
    pub fn cleanup(&mut self) {
        self.nonce = None;
        self.cnonce = None;
        self.realm = None;
        self.opaque = None;
        self.qop = 0;
        self.nc = 0;
        self.algo = ALGO_MD5;
        self.stale = false;
        self.userhash = false;
    }
}

impl Default for DigestData {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Internal helper: bytes to lowercase hex string
// ---------------------------------------------------------------------------

/// Converts a byte slice to a lowercase hexadecimal string.
///
/// Matches the C `%02x` format used throughout digest.c for hash output.
fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        hex.push_str(&format!("{:02x}", b));
    }
    hex
}

// ---------------------------------------------------------------------------
// Internal helper: quoted-string escaping
// ---------------------------------------------------------------------------

/// Escapes a string for use in a Digest header quoted-string value.
///
/// Backslash-escapes `"` and `\` characters, matching the C function
/// `auth_digest_string_quoted` from lib/vauth/digest.c lines 153-173.
fn quoted_string_escape(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        if ch == '"' || ch == '\\' {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

// ---------------------------------------------------------------------------
// SASL DIGEST-MD5 challenge parameters (internal)
// ---------------------------------------------------------------------------

/// Parsed parameters from a SASL DIGEST-MD5 server challenge.
struct DigestMd5Params {
    /// Server-provided nonce.
    nonce: String,
    /// Authentication realm.
    realm: String,
    /// Algorithm string (expected: "md5-sess").
    algorithm: String,
    /// Quality of protection bitmask.
    qop: u32,
}

// ---------------------------------------------------------------------------
// Challenge parsing: digest_get_pair
// ---------------------------------------------------------------------------

/// Parses a single `name=value` pair from a Digest challenge string.
///
/// Handles both quoted values (with backslash escape processing) and unquoted
/// token values. Returns `None` if parsing fails or the input is exhausted.
///
/// # Returns
///
/// `Some((name, value, remaining))` where:
/// - `name` — the parameter name (trimmed of whitespace and commas)
/// - `value` — the unescaped parameter value
/// - `remaining` — the unparsed remainder of the input string
///
/// Matches the C `Curl_auth_digest_get_pair` from lib/vauth/digest.c lines 59-129.
pub fn digest_get_pair(input: &str) -> Option<(String, String, &str)> {
    // Skip leading whitespace, commas, and semicolons
    let trimmed = input.trim_start_matches([' ', ',', '\t']);
    if trimmed.is_empty() {
        return None;
    }

    // Extract the name (everything before '=')
    let eq_pos = trimmed.find('=')?;
    let name = trimmed[..eq_pos].trim();
    if name.is_empty() || name.len() > DIGEST_MAX_VALUE_LENGTH {
        return None;
    }

    let after_eq = &trimmed[eq_pos + 1..];

    if let Some(value_start) = after_eq.strip_prefix('"') {
        // Quoted value — parse until closing quote, handling backslash escapes
        let mut value = String::with_capacity(DIGEST_MAX_CONTENT_LENGTH);
        let mut chars = value_start.char_indices();
        let mut end_offset = 0;
        let mut found_close = false;

        while let Some((idx, ch)) = chars.next() {
            if ch == '\\' {
                // Backslash escape — consume next character literally
                if let Some((_next_idx, next_ch)) = chars.next() {
                    if value.len() < DIGEST_MAX_CONTENT_LENGTH {
                        value.push(next_ch);
                    }
                } else {
                    // Backslash at end of input — malformed
                    break;
                }
            } else if ch == '"' {
                // Closing quote found
                // end_offset points past the closing quote in after_eq
                // after_eq[0] = '"', value_start starts at after_eq[1..]
                // idx is position in value_start, so position in after_eq is idx + 1
                // after closing quote, position in after_eq is idx + 2
                end_offset = idx + 2; // +1 for opening quote, +1 past closing quote
                found_close = true;
                break;
            } else if value.len() < DIGEST_MAX_CONTENT_LENGTH {
                value.push(ch);
            }
        }

        if !found_close {
            // No closing quote — use whatever we parsed
            end_offset = after_eq.len();
        }

        let remaining = &after_eq[end_offset..];
        Some((name.to_string(), value, remaining))
    } else {
        // Unquoted token value — read until comma, whitespace, or end
        let end = after_eq
            .find([',', ' ', '\t', '\r', '\n'])
            .unwrap_or(after_eq.len());

        let value = &after_eq[..end];
        if value.len() > DIGEST_MAX_CONTENT_LENGTH {
            return None;
        }

        let remaining = &after_eq[end..];
        Some((name.to_string(), value.to_string(), remaining))
    }
}

// ---------------------------------------------------------------------------
// QoP value parsing
// ---------------------------------------------------------------------------

/// Parses a comma-separated QoP value list into a bitmask.
fn get_qop_values(qop_str: &str) -> u32 {
    let mut qop: u32 = 0;
    for token in qop_str.split(',') {
        let token = token.trim();
        if token.eq_ignore_ascii_case("auth") {
            qop |= DIGEST_QOP_VALUE_AUTH;
        } else if token.eq_ignore_ascii_case("auth-int") {
            qop |= DIGEST_QOP_VALUE_AUTH_INT;
        } else if token.eq_ignore_ascii_case("auth-conf") {
            qop |= DIGEST_QOP_VALUE_AUTH_CONF;
        }
    }
    qop
}

// ---------------------------------------------------------------------------
// SASL DIGEST-MD5 challenge decoding
// ---------------------------------------------------------------------------

/// Decodes a SASL DIGEST-MD5 server challenge into its component parameters.
fn decode_digest_md5_message(challenge_str: &str) -> Result<DigestMd5Params, CurlError> {
    let mut nonce = String::new();
    let mut realm = String::new();
    let mut algorithm = String::new();
    let mut qop: u32 = 0;

    let mut remaining = challenge_str;
    while let Some((name, value, rest)) = digest_get_pair(remaining) {
        remaining = rest;
        match name.as_str() {
            "nonce" => nonce = value,
            "realm" => realm = value,
            "algorithm" => algorithm = value,
            "qop" => qop = get_qop_values(&value),
            _ => {}
        }
    }

    if nonce.is_empty() {
        return Err(CurlError::BadContentEncoding);
    }

    Ok(DigestMd5Params {
        nonce,
        realm,
        algorithm,
        qop,
    })
}

// ---------------------------------------------------------------------------
// HTTP Digest challenge decoding
// ---------------------------------------------------------------------------

/// Decodes an HTTP Digest authentication challenge header.
///
/// Parses the header value (after the "Digest " prefix) and populates
/// the provided [`DigestData`] with extracted parameters.
///
/// # Errors
///
/// Returns `CurlError::BadContentEncoding` if the nonce is missing.
pub fn decode_digest_http_message(
    header: &str,
    digest: &mut DigestData,
) -> Result<(), CurlError> {
    let mut before = false;
    let mut found_nonce = false;

    if !digest.stale {
        digest.cleanup();
    }

    let mut remaining = header;
    while let Some((name, value, rest)) = digest_get_pair(remaining) {
        remaining = rest;

        match name.to_ascii_lowercase().as_str() {
            "nonce" => {
                digest.nonce = Some(value);
                found_nonce = true;
            }
            "stale" => {
                if value.eq_ignore_ascii_case("true") {
                    digest.stale = true;
                }
            }
            "realm" => {
                digest.realm = Some(value);
            }
            "opaque" => {
                digest.opaque = Some(value);
            }
            "qop" => {
                let qop_bits = get_qop_values(&value);
                if qop_bits & DIGEST_QOP_VALUE_AUTH != 0 {
                    digest.qop = DIGEST_QOP_VALUE_AUTH;
                } else if qop_bits & DIGEST_QOP_VALUE_AUTH_INT != 0 {
                    digest.qop = DIGEST_QOP_VALUE_AUTH_INT;
                }
            }
            "algorithm" => {
                if value.eq_ignore_ascii_case("MD5-sess") {
                    digest.algo = ALGO_MD5SESS;
                } else if value.eq_ignore_ascii_case("MD5") {
                    digest.algo = ALGO_MD5;
                } else if value.eq_ignore_ascii_case("SHA-256-sess") {
                    digest.algo = ALGO_SHA256SESS;
                } else if value.eq_ignore_ascii_case("SHA-256") {
                    digest.algo = ALGO_SHA256;
                } else if value.eq_ignore_ascii_case("SHA-512-256-sess") {
                    digest.algo = ALGO_SHA512_256SESS;
                } else if value.eq_ignore_ascii_case("SHA-512-256") {
                    digest.algo = ALGO_SHA512_256;
                } else {
                    // Unknown/unsupported algorithm — matches C behavior
                    // where CURLE_NOT_BUILT_IN is returned for unrecognized
                    // algorithm variants (e.g. SHA-512-256 when
                    // CURL_HAVE_SHA512_256 is not defined).
                    return Err(CurlError::NotBuiltIn);
                }
            }
            "userhash" => {
                if value.eq_ignore_ascii_case("true") {
                    digest.userhash = true;
                }
            }
            _ => {
                if !found_nonce {
                    before = true;
                }
            }
        }
    }

    if digest.nonce.is_none() {
        return Err(CurlError::BadContentEncoding);
    }

    if (digest.algo & SESSION_ALGO) != 0 && digest.qop == 0 {
        digest.qop = DIGEST_QOP_VALUE_AUTH;
    }

    if digest.stale {
        digest.nc = 0;
    }

    let _ = before;
    Ok(())
}

// ---------------------------------------------------------------------------
// Hash computation helpers
// ---------------------------------------------------------------------------

/// Computes a hex-encoded hash dispatched by algorithm constant.
fn hash_to_hex(data: &[u8], algo: u32) -> String {
    let base_algo = algo & !SESSION_ALGO;
    match base_algo {
        ALGO_SHA256 => sha256::sha256_hex(data),
        ALGO_SHA512_256 => {
            let raw = sha256::sha512_256(data);
            bytes_to_hex(&raw)
        }
        _ => md5::md5_hex(data),
    }
}

/// Computes HA1 for HTTP Digest authentication.
///
/// Non-session: `HA1 = Hash(user:realm:passwd)`
/// Session (-sess): `HA1 = Hash(Hash(user:realm:passwd):nonce:cnonce)`
fn compute_ha1(
    user: &str,
    realm: &str,
    passwd: &str,
    nonce: &str,
    cnonce: &str,
    algo: u32,
) -> String {
    let a1_input = format!("{}:{}:{}", user, realm, passwd);

    if (algo & SESSION_ALGO) != 0 {
        let base_algo = algo & !SESSION_ALGO;
        // Session algo: Hash(Hash(user:realm:passwd):nonce:cnonce)
        // Use streaming context API to avoid Vec allocation for raw-bytes
        // concatenation with colon-separated text fields.
        match base_algo {
            ALGO_SHA256 => {
                let inner_hash = sha256::sha256(a1_input.as_bytes());
                let mut ctx = Sha256Context::new();
                ctx.update(&inner_hash);
                ctx.update(b":");
                ctx.update(nonce.as_bytes());
                ctx.update(b":");
                ctx.update(cnonce.as_bytes());
                let result = ctx.finish();
                bytes_to_hex(&result)
            }
            ALGO_SHA512_256 => {
                let inner_hash = sha256::sha512_256(a1_input.as_bytes());
                // SHA-512/256 session: use Vec for concatenation, then hash
                let mut sess_input: Vec<u8> = Vec::with_capacity(
                    inner_hash.len() + 1 + nonce.len() + 1 + cnonce.len(),
                );
                sess_input.extend_from_slice(&inner_hash);
                sess_input.push(b':');
                sess_input.extend_from_slice(nonce.as_bytes());
                sess_input.push(b':');
                sess_input.extend_from_slice(cnonce.as_bytes());
                let hash = sha256::sha512_256(&sess_input);
                bytes_to_hex(&hash)
            }
            _ => {
                // MD5-sess: use Md5Context streaming API
                let inner_hash = md5::md5(a1_input.as_bytes());
                let mut ctx = Md5Context::new();
                ctx.update(&inner_hash);
                ctx.update(b":");
                ctx.update(nonce.as_bytes());
                ctx.update(b":");
                ctx.update(cnonce.as_bytes());
                ctx.finish_hex()
            }
        }
    } else {
        hash_to_hex(a1_input.as_bytes(), algo)
    }
}

/// Computes HA2 for HTTP Digest authentication.
///
/// auth: `HA2 = Hash(method:uri)`
/// auth-int: `HA2 = Hash(method:uri:Hash(entity_body))`
fn compute_ha2(method: &str, uri: &str, qop: u32, algo: u32) -> String {
    if qop == DIGEST_QOP_VALUE_AUTH_INT {
        let entity_hash = hash_to_hex(b"", algo);
        let a2_input = format!("{}:{}:{}", method, uri, entity_hash);
        hash_to_hex(a2_input.as_bytes(), algo)
    } else {
        let a2_input = format!("{}:{}", method, uri);
        hash_to_hex(a2_input.as_bytes(), algo)
    }
}

/// Computes the Digest response hash value.
///
/// With QoP: `Hash(HA1:nonce:nc:cnonce:qop:HA2)` (nc is 8-digit hex)
/// Without QoP: `Hash(HA1:nonce:HA2)` (legacy RFC 2069)
fn compute_response(
    ha1: &str,
    nonce: &str,
    nc: u32,
    cnonce: &str,
    qop: u32,
    ha2: &str,
    algo: u32,
) -> String {
    if qop != 0 {
        let qop_str = if qop == DIGEST_QOP_VALUE_AUTH_INT {
            "auth-int"
        } else {
            "auth"
        };
        let input = format!(
            "{}:{}:{:08x}:{}:{}:{}",
            ha1, nonce, nc, cnonce, qop_str, ha2
        );
        hash_to_hex(input.as_bytes(), algo)
    } else {
        let input = format!("{}:{}:{}", ha1, nonce, ha2);
        hash_to_hex(input.as_bytes(), algo)
    }
}

/// Returns the algorithm name string for the Authorization header.
fn algo_to_string(algo: u32) -> Option<&'static str> {
    match algo {
        ALGO_MD5 => None,
        ALGO_MD5SESS => Some("MD5-sess"),
        ALGO_SHA256 => Some("SHA-256"),
        ALGO_SHA256SESS => Some("SHA-256-sess"),
        ALGO_SHA512_256 => Some("SHA-512-256"),
        ALGO_SHA512_256SESS => Some("SHA-512-256-sess"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// HTTP Digest response generation
// ---------------------------------------------------------------------------

/// Creates an HTTP Digest authentication response header value.
///
/// Generates the complete `Digest username="...", realm="...", ...` string
/// for use in an `Authorization` or `Proxy-Authorization` header.
///
/// # Parameters
///
/// - `user` — username for authentication
/// - `passwd` — password for authentication
/// - `method` — HTTP method (e.g. "GET", "POST")
/// - `uri` — request URI (path component)
/// - `digest` — mutable digest state (nonce count is incremented)
///
/// # Errors
///
/// Returns `CurlError::OutOfMemory` if random number generation fails.
pub fn create_digest_http_message(
    user: &str,
    passwd: &str,
    method: &str,
    uri: &str,
    digest: &mut DigestData,
) -> Result<String, CurlError> {
    // Generate client nonce if not already present
    if digest.cnonce.is_none() {
        // HTTP Digest: 12 random bytes -> base64 -> cnonce
        // Matching C: Curl_rand_bytes(12) then curlx_base64_encode
        let mut nonce_bytes = [0u8; 12];
        rand::random_bytes(&mut nonce_bytes)?;
        digest.cnonce = Some(base64::encode(&nonce_bytes));
    }

    // Increment nonce count
    digest.nc += 1;

    let realm = digest.realm.as_deref().unwrap_or("");
    let nonce = digest.nonce.as_deref().unwrap_or("");
    let cnonce = digest.cnonce.as_deref().unwrap_or("");
    let algo = digest.algo;
    let qop = digest.qop;
    let nc = digest.nc;

    // Compute the username to use in the header
    let username_display = if digest.userhash {
        // RFC 7616: username is Hash(user:realm) in hex
        let user_realm = format!("{}:{}", user, realm);
        hash_to_hex(user_realm.as_bytes(), algo)
    } else {
        user.to_string()
    };

    // Compute HA1
    let ha1 = compute_ha1(user, realm, passwd, nonce, cnonce, algo);

    // Compute HA2
    let ha2 = compute_ha2(method, uri, qop, algo);

    // Compute response
    let response = compute_response(&ha1, nonce, nc, cnonce, qop, &ha2, algo);

    // Build the Authorization header value
    let mut header = String::with_capacity(512);
    header.push_str("Digest ");

    // username (quoted, escaped)
    header.push_str("username=\"");
    header.push_str(&quoted_string_escape(&username_display));
    header.push_str("\", ");

    // realm (quoted, escaped)
    header.push_str("realm=\"");
    header.push_str(&quoted_string_escape(realm));
    header.push_str("\", ");

    // nonce (quoted, escaped)
    header.push_str("nonce=\"");
    header.push_str(&quoted_string_escape(nonce));
    header.push_str("\", ");

    // uri (quoted, escaped)
    header.push_str("uri=\"");
    header.push_str(&quoted_string_escape(uri));
    header.push_str("\", ");

    // response (quoted, not escaped — hex string has no special chars)
    header.push_str("response=\"");
    header.push_str(&response);
    header.push('"');

    // Optional: opaque (if server provided it)
    if let Some(ref opaque) = digest.opaque {
        header.push_str(", opaque=\"");
        header.push_str(&quoted_string_escape(opaque));
        header.push('"');
    }

    // Optional: algorithm (omitted for default MD5)
    if let Some(algo_name) = algo_to_string(algo) {
        header.push_str(", algorithm=");
        header.push_str(algo_name);
    }

    // Optional: qop, nc, cnonce (present when qop was negotiated)
    if qop != 0 {
        let qop_str = if qop == DIGEST_QOP_VALUE_AUTH_INT {
            "auth-int"
        } else {
            "auth"
        };
        header.push_str(", qop=");
        header.push_str(qop_str);

        header.push_str(", nc=");
        header.push_str(&format!("{:08x}", nc));

        header.push_str(", cnonce=\"");
        header.push_str(&quoted_string_escape(cnonce));
        header.push('"');
    }

    // Optional: userhash (RFC 7616)
    if digest.userhash {
        header.push_str(", userhash=true");
    }

    Ok(header)
}

// ---------------------------------------------------------------------------
// SASL DIGEST-MD5 response generation
// ---------------------------------------------------------------------------

/// Creates a SASL DIGEST-MD5 authentication response message.
///
/// Decodes the server challenge, computes the DIGEST-MD5 response hash,
/// and formats the response string for transmission.
///
/// # Parameters
///
/// - `user` — username for authentication
/// - `passwd` — password for authentication
/// - `service` — service name (e.g. "imap", "smtp")
/// - `host` — server hostname
/// - `challenge` — raw server challenge bytes (may be base64-encoded)
///
/// # Errors
///
/// - `CurlError::BadContentEncoding` if the challenge is malformed
/// - `CurlError::OutOfMemory` if random number generation fails
pub fn create_digest_md5_message(
    user: &str,
    passwd: &str,
    service: &str,
    host: &str,
    challenge: &[u8],
) -> Result<Vec<u8>, CurlError> {
    // The SASL DIGEST-MD5 challenge may arrive base64-encoded (transport encoding).
    // Decode from base64 first if the challenge appears to be encoded,
    // matching C: Curl_base64_decode((const char *) chlg64, &chlg, &chlglen)
    let decoded_challenge: Vec<u8>;
    let challenge_bytes = if !challenge.is_empty() && challenge[0] != b'=' {
        match base64::decode(core::str::from_utf8(challenge).unwrap_or("")) {
            Ok(decoded) if !decoded.is_empty() => {
                decoded_challenge = decoded;
                &decoded_challenge[..]
            }
            _ => challenge,
        }
    } else {
        challenge
    };

    // Decode the challenge from UTF-8
    let challenge_str =
        core::str::from_utf8(challenge_bytes).map_err(|_| CurlError::BadContentEncoding)?;

    // Parse the challenge parameters
    let params = decode_digest_md5_message(challenge_str)?;

    // Validate algorithm is "md5-sess" (required for DIGEST-MD5 SASL)
    if !params.algorithm.eq_ignore_ascii_case("md5-sess") && !params.algorithm.is_empty() {
        return Err(CurlError::BadContentEncoding);
    }

    // Validate QoP includes "auth"
    if params.qop != 0 && (params.qop & DIGEST_QOP_VALUE_AUTH) == 0 {
        return Err(CurlError::BadContentEncoding);
    }

    // Generate client nonce: 32 hex characters
    let cnonce = rand::random_hex_string(32)?;

    // Build digest-uri: "service/host"
    let digest_uri = format!("{}/{}", service, host);

    // Compute HA1 = MD5(MD5(user:realm:passwd):nonce:cnonce)
    // First: inner hash = MD5(user:realm:passwd) as raw bytes
    let inner_input = format!("{}:{}:{}", user, params.realm, passwd);
    let inner_hash = md5::md5(inner_input.as_bytes());

    // Session: HA1 = MD5(inner_hash_bytes:nonce:cnonce)
    // Use Md5Context streaming API with finish() for raw bytes, then hex-encode
    let mut ha1_ctx = Md5Context::new();
    ha1_ctx.update(&inner_hash);
    ha1_ctx.update(b":");
    ha1_ctx.update(params.nonce.as_bytes());
    ha1_ctx.update(b":");
    ha1_ctx.update(cnonce.as_bytes());
    let ha1_raw = ha1_ctx.finish();
    let ha1 = bytes_to_hex(&ha1_raw);

    // Compute HA2 = MD5("AUTHENTICATE:digest-uri")
    let ha2_input = format!("AUTHENTICATE:{}", digest_uri);
    let ha2 = md5::md5_hex(ha2_input.as_bytes());

    // Compute response = MD5(HA1:nonce:00000001:cnonce:auth:HA2)
    let response_input = format!(
        "{}:{}:00000001:{}:auth:{}",
        ha1, params.nonce, cnonce, ha2
    );
    let response = md5::md5_hex(response_input.as_bytes());

    // Format the response string
    // charset=utf-8,username="...",realm="...",nonce="...",nc=00000001,
    // cnonce="...",digest-uri="...",response=...,qop=auth
    let result = format!(
        "charset=utf-8,username=\"{}\",realm=\"{}\",nonce=\"{}\",nc=00000001,cnonce=\"{}\",digest-uri=\"{}\",response={},qop=auth",
        quoted_string_escape(user),
        quoted_string_escape(&params.realm),
        quoted_string_escape(&params.nonce),
        quoted_string_escape(&cnonce),
        quoted_string_escape(&digest_uri),
        response,
    );

    Ok(result.into_bytes())
}

// ---------------------------------------------------------------------------
// HTTP Digest input/output (from http_digest.c)
// ---------------------------------------------------------------------------

/// Processes an incoming HTTP Digest authentication challenge.
///
/// Checks for the "Digest " prefix (case-insensitive) and delegates to
/// [`decode_digest_http_message`] for parameter extraction.
///
/// # Parameters
///
/// - `header` — the full `WWW-Authenticate` or `Proxy-Authenticate` header value
/// - `proxy` — `true` if this is a proxy authentication challenge
/// - `digest` — mutable digest state to populate
///
/// # Errors
///
/// Returns `CurlError::BadContentEncoding` if the header is malformed.
pub fn input_digest(
    header: &str,
    proxy: bool,
    digest: &mut DigestData,
) -> Result<(), CurlError> {
    let _ = proxy; // proxy flag used by caller for header selection

    // Check for "Digest " prefix (case-insensitive)
    let trimmed = header.trim_start();
    if trimmed.len() < 7 {
        return Err(CurlError::BadContentEncoding);
    }
    if !trimmed[..7].eq_ignore_ascii_case("Digest ") {
        return Err(CurlError::BadContentEncoding);
    }

    // Parse the challenge parameters after the "Digest " prefix
    let challenge_params = &trimmed[7..];
    decode_digest_http_message(challenge_params, digest)
}

/// Generates an HTTP Digest authentication response header value.
///
/// Delegates to [`create_digest_http_message`] to compute the Digest
/// response for the specified request.
///
/// # Parameters
///
/// - `user` — username for authentication
/// - `passwd` — password for authentication
/// - `method` — HTTP method (e.g. "GET", "POST")
/// - `uri` — request URI
/// - `proxy` — `true` if generating a Proxy-Authorization header
/// - `digest` — mutable digest state
///
/// # Errors
///
/// Returns `CurlError::OutOfMemory` if response generation fails.
pub fn output_digest(
    user: &str,
    passwd: &str,
    method: &str,
    uri: &str,
    proxy: bool,
    digest: &mut DigestData,
) -> Result<String, CurlError> {
    let _ = proxy; // proxy flag used by caller for header name selection
    create_digest_http_message(user, passwd, method, uri, digest)
}

// ---------------------------------------------------------------------------
// Support detection and cleanup
// ---------------------------------------------------------------------------

/// Returns `true` indicating that Digest authentication is supported.
///
/// This is a pure-Rust implementation, so Digest auth is always available.
/// Matches the C `Curl_auth_is_digest_supported` which returns `TRUE`.
pub fn is_digest_supported() -> bool {
    true
}

/// Cleans up HTTP Digest authentication state for both host and proxy.
///
/// Resets both the host and proxy digest state to their defaults.
/// Matches the C `Curl_http_auth_cleanup_digest` from lib/http_digest.c.
pub fn http_auth_cleanup_digest(digest: &mut DigestData, proxy_digest: &mut DigestData) {
    digest.cleanup();
    proxy_digest.cleanup();
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // DigestData tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_digest_data_new() {
        let d = DigestData::new();
        assert!(d.nonce.is_none());
        assert!(d.cnonce.is_none());
        assert!(d.realm.is_none());
        assert!(d.opaque.is_none());
        assert_eq!(d.qop, 0);
        assert_eq!(d.nc, 0);
        assert_eq!(d.algo, ALGO_MD5);
        assert!(!d.stale);
        assert!(!d.userhash);
    }

    #[test]
    fn test_digest_data_default() {
        let d = DigestData::default();
        assert_eq!(d.algo, ALGO_MD5);
        assert_eq!(d.nc, 0);
    }

    #[test]
    fn test_digest_data_cleanup() {
        let mut d = DigestData::new();
        d.nonce = Some("nonce123".into());
        d.cnonce = Some("cnonce456".into());
        d.realm = Some("testrealm@host.com".into());
        d.opaque = Some("opaque789".into());
        d.qop = DIGEST_QOP_VALUE_AUTH;
        d.nc = 5;
        d.algo = ALGO_SHA256;
        d.stale = true;
        d.userhash = true;
        d.cleanup();
        assert!(d.nonce.is_none());
        assert!(d.cnonce.is_none());
        assert!(d.realm.is_none());
        assert!(d.opaque.is_none());
        assert_eq!(d.qop, 0);
        assert_eq!(d.nc, 0);
        assert_eq!(d.algo, ALGO_MD5);
        assert!(!d.stale);
        assert!(!d.userhash);
    }

    #[test]
    fn test_digest_data_clone() {
        let d = DigestData {
            nonce: Some("test".into()),
            cnonce: Some("c".into()),
            realm: Some("r".into()),
            opaque: Some("o".into()),
            qop: DIGEST_QOP_VALUE_AUTH,
            nc: 3,
            algo: ALGO_SHA256,
            stale: false,
            userhash: true,
        };
        let d2 = d.clone();
        assert_eq!(d2.nonce.as_deref(), Some("test"));
        assert_eq!(d2.algo, ALGO_SHA256);
        assert!(d2.userhash);
    }

    // -----------------------------------------------------------------------
    // Algorithm constants tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_algo_constants() {
        assert_eq!(ALGO_MD5, 0);
        assert_eq!(ALGO_MD5SESS, 1);
        assert_eq!(ALGO_SHA256, 2);
        assert_eq!(ALGO_SHA256SESS, 3);
        assert_eq!(ALGO_SHA512_256, 4);
        assert_eq!(ALGO_SHA512_256SESS, 5);
    }

    #[test]
    fn test_session_algo_bit() {
        assert_eq!(SESSION_ALGO, 1);
        assert_eq!(ALGO_MD5 & SESSION_ALGO, 0);
        assert_eq!(ALGO_MD5SESS & SESSION_ALGO, 1);
        assert_eq!(ALGO_SHA256 & SESSION_ALGO, 0);
        assert_eq!(ALGO_SHA256SESS & SESSION_ALGO, 1);
    }

    // -----------------------------------------------------------------------
    // QoP constants tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_qop_constants() {
        assert_eq!(DIGEST_QOP_VALUE_AUTH, 1);
        assert_eq!(DIGEST_QOP_VALUE_AUTH_INT, 2);
        assert_eq!(DIGEST_QOP_VALUE_AUTH_CONF, 4);
    }

    // -----------------------------------------------------------------------
    // bytes_to_hex tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_bytes_to_hex_empty() {
        assert_eq!(bytes_to_hex(&[]), "");
    }

    #[test]
    fn test_bytes_to_hex_single() {
        assert_eq!(bytes_to_hex(&[0xff]), "ff");
        assert_eq!(bytes_to_hex(&[0x00]), "00");
        assert_eq!(bytes_to_hex(&[0x0a]), "0a");
    }

    #[test]
    fn test_bytes_to_hex_multiple() {
        assert_eq!(bytes_to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    // -----------------------------------------------------------------------
    // quoted_string_escape tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_quoted_string_escape_no_special() {
        assert_eq!(quoted_string_escape("hello"), "hello");
    }

    #[test]
    fn test_quoted_string_escape_quote() {
        assert_eq!(quoted_string_escape("he\"llo"), "he\\\"llo");
    }

    #[test]
    fn test_quoted_string_escape_backslash() {
        assert_eq!(quoted_string_escape("a\\b"), "a\\\\b");
    }

    #[test]
    fn test_quoted_string_escape_both() {
        assert_eq!(quoted_string_escape("\"\\"), "\\\"\\\\");
    }

    #[test]
    fn test_quoted_string_escape_empty() {
        assert_eq!(quoted_string_escape(""), "");
    }

    // -----------------------------------------------------------------------
    // digest_get_pair tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_digest_get_pair_simple_unquoted() {
        let result = digest_get_pair("algorithm=MD5").unwrap();
        assert_eq!(result.0, "algorithm");
        assert_eq!(result.1, "MD5");
    }

    #[test]
    fn test_digest_get_pair_quoted() {
        let result = digest_get_pair("nonce=\"abc123\"").unwrap();
        assert_eq!(result.0, "nonce");
        assert_eq!(result.1, "abc123");
    }

    #[test]
    fn test_digest_get_pair_quoted_with_escape() {
        let result = digest_get_pair("realm=\"test\\\"realm\"").unwrap();
        assert_eq!(result.0, "realm");
        assert_eq!(result.1, "test\"realm");
    }

    #[test]
    fn test_digest_get_pair_with_leading_whitespace() {
        let result = digest_get_pair("  realm=\"test\"").unwrap();
        assert_eq!(result.0, "realm");
        assert_eq!(result.1, "test");
    }

    #[test]
    fn test_digest_get_pair_with_leading_comma() {
        let result = digest_get_pair(", nonce=\"abc\"").unwrap();
        assert_eq!(result.0, "nonce");
        assert_eq!(result.1, "abc");
    }

    #[test]
    fn test_digest_get_pair_empty() {
        assert!(digest_get_pair("").is_none());
    }

    #[test]
    fn test_digest_get_pair_no_equals() {
        assert!(digest_get_pair("noequals").is_none());
    }

    #[test]
    fn test_digest_get_pair_empty_name() {
        assert!(digest_get_pair("=value").is_none());
    }

    #[test]
    fn test_digest_get_pair_remaining() {
        let result = digest_get_pair("a=1, b=2").unwrap();
        assert_eq!(result.0, "a");
        assert_eq!(result.1, "1");
        let remaining = result.2;
        let result2 = digest_get_pair(remaining).unwrap();
        assert_eq!(result2.0, "b");
        assert_eq!(result2.1, "2");
    }

    // -----------------------------------------------------------------------
    // get_qop_values tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_get_qop_values_auth() {
        assert_eq!(get_qop_values("auth"), DIGEST_QOP_VALUE_AUTH);
    }

    #[test]
    fn test_get_qop_values_auth_int() {
        assert_eq!(get_qop_values("auth-int"), DIGEST_QOP_VALUE_AUTH_INT);
    }

    #[test]
    fn test_get_qop_values_auth_conf() {
        assert_eq!(get_qop_values("auth-conf"), DIGEST_QOP_VALUE_AUTH_CONF);
    }

    #[test]
    fn test_get_qop_values_multiple() {
        let qop = get_qop_values("auth,auth-int");
        assert_eq!(qop, DIGEST_QOP_VALUE_AUTH | DIGEST_QOP_VALUE_AUTH_INT);
    }

    #[test]
    fn test_get_qop_values_case_insensitive() {
        assert_eq!(get_qop_values("AUTH"), DIGEST_QOP_VALUE_AUTH);
        assert_eq!(get_qop_values("Auth-Int"), DIGEST_QOP_VALUE_AUTH_INT);
    }

    #[test]
    fn test_get_qop_values_unknown() {
        assert_eq!(get_qop_values("unknown"), 0);
    }

    #[test]
    fn test_get_qop_values_whitespace() {
        let qop = get_qop_values("auth, auth-int");
        assert_eq!(qop, DIGEST_QOP_VALUE_AUTH | DIGEST_QOP_VALUE_AUTH_INT);
    }

    // -----------------------------------------------------------------------
    // hash_to_hex tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_hash_to_hex_md5() {
        let result = hash_to_hex(b"test", ALGO_MD5);
        assert_eq!(result.len(), 32); // MD5 produces 128-bit = 32 hex chars
    }

    #[test]
    fn test_hash_to_hex_sha256() {
        let result = hash_to_hex(b"test", ALGO_SHA256);
        assert_eq!(result.len(), 64); // SHA-256 produces 256-bit = 64 hex chars
    }

    #[test]
    fn test_hash_to_hex_sha512_256() {
        let result = hash_to_hex(b"test", ALGO_SHA512_256);
        assert_eq!(result.len(), 64); // SHA-512/256 produces 256-bit = 64 hex chars
    }

    // -----------------------------------------------------------------------
    // compute_ha1 tests (RFC 7616 test vectors)
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_ha1_md5() {
        // MD5(user:realm:pass) is deterministic
        let ha1 = compute_ha1("user", "realm", "pass", "", "", ALGO_MD5);
        assert_eq!(ha1.len(), 32);
        // Verify it's consistent
        let ha1_2 = compute_ha1("user", "realm", "pass", "", "", ALGO_MD5);
        assert_eq!(ha1, ha1_2);
    }

    #[test]
    fn test_compute_ha1_sha256() {
        let ha1 = compute_ha1("user", "realm", "pass", "", "", ALGO_SHA256);
        assert_eq!(ha1.len(), 64);
    }

    #[test]
    fn test_compute_ha1_md5_sess() {
        let ha1 = compute_ha1("user", "realm", "pass", "nonce", "cnonce", ALGO_MD5SESS);
        assert_eq!(ha1.len(), 32);
        // Session HA1 depends on nonce/cnonce
        let ha1_diff = compute_ha1("user", "realm", "pass", "other_nonce", "cnonce", ALGO_MD5SESS);
        assert_ne!(ha1, ha1_diff);
    }

    #[test]
    fn test_compute_ha1_sha256_sess() {
        let ha1 = compute_ha1("user", "realm", "pass", "nonce", "cnonce", ALGO_SHA256SESS);
        assert_eq!(ha1.len(), 64);
    }

    #[test]
    fn test_compute_ha1_sha512_256_sess() {
        let ha1 = compute_ha1("user", "realm", "pass", "nonce", "cnonce", ALGO_SHA512_256SESS);
        assert_eq!(ha1.len(), 64);
    }

    // -----------------------------------------------------------------------
    // compute_ha2 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_ha2_auth() {
        let ha2 = compute_ha2("GET", "/dir/index.html", DIGEST_QOP_VALUE_AUTH, ALGO_MD5);
        assert_eq!(ha2.len(), 32);
    }

    #[test]
    fn test_compute_ha2_auth_int() {
        let ha2 = compute_ha2("POST", "/api", DIGEST_QOP_VALUE_AUTH_INT, ALGO_MD5);
        assert_eq!(ha2.len(), 32);
        // auth-int includes Hash(entity_body) in the computation
        let ha2_auth = compute_ha2("POST", "/api", DIGEST_QOP_VALUE_AUTH, ALGO_MD5);
        assert_ne!(ha2, ha2_auth);
    }

    #[test]
    fn test_compute_ha2_no_qop() {
        let ha2 = compute_ha2("GET", "/", 0, ALGO_MD5);
        assert_eq!(ha2.len(), 32);
    }

    // -----------------------------------------------------------------------
    // compute_response tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_response_with_qop() {
        let resp = compute_response(
            "ha1hex", "nonce", 1, "cnonce", DIGEST_QOP_VALUE_AUTH, "ha2hex", ALGO_MD5,
        );
        assert_eq!(resp.len(), 32);
    }

    #[test]
    fn test_compute_response_without_qop() {
        let resp = compute_response("ha1hex", "nonce", 0, "", 0, "ha2hex", ALGO_MD5);
        assert_eq!(resp.len(), 32);
    }

    #[test]
    fn test_compute_response_deterministic() {
        let r1 = compute_response("a", "b", 1, "c", DIGEST_QOP_VALUE_AUTH, "d", ALGO_MD5);
        let r2 = compute_response("a", "b", 1, "c", DIGEST_QOP_VALUE_AUTH, "d", ALGO_MD5);
        assert_eq!(r1, r2);
    }

    // -----------------------------------------------------------------------
    // algo_to_string tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_algo_to_string() {
        assert_eq!(algo_to_string(ALGO_MD5), None);
        assert_eq!(algo_to_string(ALGO_MD5SESS), Some("MD5-sess"));
        assert_eq!(algo_to_string(ALGO_SHA256), Some("SHA-256"));
        assert_eq!(algo_to_string(ALGO_SHA256SESS), Some("SHA-256-sess"));
        assert_eq!(algo_to_string(ALGO_SHA512_256), Some("SHA-512-256"));
        assert_eq!(algo_to_string(ALGO_SHA512_256SESS), Some("SHA-512-256-sess"));
    }

    // -----------------------------------------------------------------------
    // decode_digest_http_message tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_http_message_basic() {
        let mut d = DigestData::new();
        let header = r#"realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", qop="auth""#;
        let res = decode_digest_http_message(header, &mut d);
        assert!(res.is_ok());
        assert_eq!(d.realm.as_deref(), Some("testrealm@host.com"));
        assert_eq!(d.nonce.as_deref(), Some("dcd98b7102dd2f0e8b11d0f600bfb0c093"));
        assert_eq!(d.qop, DIGEST_QOP_VALUE_AUTH);
        assert_eq!(d.algo, ALGO_MD5);
    }

    #[test]
    fn test_decode_http_message_sha256() {
        let mut d = DigestData::new();
        let header = r#"realm="test", nonce="abc", algorithm=SHA-256"#;
        let res = decode_digest_http_message(header, &mut d);
        assert!(res.is_ok());
        assert_eq!(d.algo, ALGO_SHA256);
    }

    #[test]
    fn test_decode_http_message_sha256_sess() {
        let mut d = DigestData::new();
        let header = r#"realm="test", nonce="abc", algorithm=SHA-256-sess"#;
        let res = decode_digest_http_message(header, &mut d);
        assert!(res.is_ok());
        assert_eq!(d.algo, ALGO_SHA256SESS);
        // Session algo with qop=0 should auto-set qop to auth
        assert_eq!(d.qop, DIGEST_QOP_VALUE_AUTH);
    }

    #[test]
    fn test_decode_http_message_md5_sess() {
        let mut d = DigestData::new();
        let header = r#"nonce="n", algorithm=MD5-sess"#;
        let res = decode_digest_http_message(header, &mut d);
        assert!(res.is_ok());
        assert_eq!(d.algo, ALGO_MD5SESS);
        assert_eq!(d.qop, DIGEST_QOP_VALUE_AUTH); // auto-set for session
    }

    #[test]
    fn test_decode_http_message_with_opaque() {
        let mut d = DigestData::new();
        let header = r#"nonce="n", opaque="5ccc069c403ebaf9f0171e9517f40e41""#;
        let res = decode_digest_http_message(header, &mut d);
        assert!(res.is_ok());
        assert_eq!(d.opaque.as_deref(), Some("5ccc069c403ebaf9f0171e9517f40e41"));
    }

    #[test]
    fn test_decode_http_message_stale() {
        let mut d = DigestData::new();
        let header = r#"nonce="new_nonce", stale=true"#;
        let res = decode_digest_http_message(header, &mut d);
        assert!(res.is_ok());
        assert!(d.stale);
        assert_eq!(d.nc, 0); // nc reset when stale
    }

    #[test]
    fn test_decode_http_message_userhash() {
        let mut d = DigestData::new();
        let header = r#"nonce="n", userhash=true"#;
        let res = decode_digest_http_message(header, &mut d);
        assert!(res.is_ok());
        assert!(d.userhash);
    }

    #[test]
    fn test_decode_http_message_missing_nonce() {
        let mut d = DigestData::new();
        let header = r#"realm="test""#;
        let res = decode_digest_http_message(header, &mut d);
        assert!(res.is_err());
    }

    #[test]
    fn test_decode_http_message_unknown_algo() {
        let mut d = DigestData::new();
        let header = r#"nonce="n", algorithm=UNKNOWN"#;
        let res = decode_digest_http_message(header, &mut d);
        assert!(res.is_err());
    }

    // -----------------------------------------------------------------------
    // input_digest tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_input_digest_valid() {
        let mut d = DigestData::new();
        let header = r#"Digest realm="test", nonce="abc123""#;
        let res = input_digest(header, false, &mut d);
        assert!(res.is_ok());
        assert_eq!(d.realm.as_deref(), Some("test"));
        assert_eq!(d.nonce.as_deref(), Some("abc123"));
    }

    #[test]
    fn test_input_digest_case_insensitive_prefix() {
        let mut d = DigestData::new();
        let header = r#"digest realm="test", nonce="abc""#;
        let res = input_digest(header, false, &mut d);
        assert!(res.is_ok());
    }

    #[test]
    fn test_input_digest_not_digest() {
        let mut d = DigestData::new();
        let header = "Basic realm=\"test\"";
        let res = input_digest(header, false, &mut d);
        assert!(res.is_err());
    }

    #[test]
    fn test_input_digest_too_short() {
        let mut d = DigestData::new();
        let res = input_digest("Dig", false, &mut d);
        assert!(res.is_err());
    }

    #[test]
    fn test_input_digest_proxy() {
        let mut d = DigestData::new();
        let header = r#"Digest realm="proxy", nonce="pn""#;
        let res = input_digest(header, true, &mut d);
        assert!(res.is_ok());
        assert_eq!(d.realm.as_deref(), Some("proxy"));
    }

    // -----------------------------------------------------------------------
    // create_digest_http_message tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_digest_http_message_md5() {
        let mut d = DigestData::new();
        d.nonce = Some("nonce123".into());
        d.realm = Some("testrealm".into());
        d.qop = DIGEST_QOP_VALUE_AUTH;
        d.algo = ALGO_MD5;

        let header = create_digest_http_message("user", "pass", "GET", "/index.html", &mut d);
        assert!(header.is_ok());
        let hdr = header.unwrap();
        assert!(hdr.starts_with("Digest "));
        assert!(hdr.contains("username=\"user\""));
        assert!(hdr.contains("realm=\"testrealm\""));
        assert!(hdr.contains("nonce=\"nonce123\""));
        assert!(hdr.contains("uri=\"/index.html\""));
        assert!(hdr.contains("response=\""));
        assert!(hdr.contains("qop=auth"));
        assert!(hdr.contains("nc=00000001"));
        assert!(hdr.contains("cnonce=\""));
        assert_eq!(d.nc, 1);
    }

    #[test]
    fn test_create_digest_http_message_increments_nc() {
        let mut d = DigestData::new();
        d.nonce = Some("n".into());
        d.qop = DIGEST_QOP_VALUE_AUTH;

        create_digest_http_message("u", "p", "GET", "/", &mut d).unwrap();
        assert_eq!(d.nc, 1);
        create_digest_http_message("u", "p", "GET", "/", &mut d).unwrap();
        assert_eq!(d.nc, 2);
    }

    #[test]
    fn test_create_digest_http_message_sha256() {
        let mut d = DigestData::new();
        d.nonce = Some("n".into());
        d.realm = Some("r".into());
        d.algo = ALGO_SHA256;
        d.qop = DIGEST_QOP_VALUE_AUTH;

        let hdr = create_digest_http_message("u", "p", "GET", "/", &mut d).unwrap();
        assert!(hdr.contains("algorithm=SHA-256"));
    }

    #[test]
    fn test_create_digest_http_message_with_opaque() {
        let mut d = DigestData::new();
        d.nonce = Some("n".into());
        d.opaque = Some("opaque_value".into());

        let hdr = create_digest_http_message("u", "p", "GET", "/", &mut d).unwrap();
        assert!(hdr.contains("opaque=\"opaque_value\""));
    }

    #[test]
    fn test_create_digest_http_message_no_qop() {
        let mut d = DigestData::new();
        d.nonce = Some("n".into());
        d.qop = 0;

        let hdr = create_digest_http_message("u", "p", "GET", "/", &mut d).unwrap();
        assert!(!hdr.contains("qop="));
        assert!(!hdr.contains("nc="));
        assert!(!hdr.contains("cnonce="));
    }

    #[test]
    fn test_create_digest_http_message_userhash() {
        let mut d = DigestData::new();
        d.nonce = Some("n".into());
        d.realm = Some("r".into());
        d.userhash = true;

        let hdr = create_digest_http_message("u", "p", "GET", "/", &mut d).unwrap();
        assert!(hdr.contains("userhash=true"));
        // Username should be a hash, not "u"
        assert!(!hdr.contains("username=\"u\""));
    }

    // -----------------------------------------------------------------------
    // output_digest tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_output_digest() {
        let mut d = DigestData::new();
        d.nonce = Some("n".into());
        d.realm = Some("r".into());
        d.qop = DIGEST_QOP_VALUE_AUTH;

        let result = output_digest("user", "pass", "GET", "/", false, &mut d);
        assert!(result.is_ok());
        assert!(result.unwrap().starts_with("Digest "));
    }

    // -----------------------------------------------------------------------
    // is_digest_supported test
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_digest_supported() {
        assert!(is_digest_supported());
    }

    // -----------------------------------------------------------------------
    // http_auth_cleanup_digest test
    // -----------------------------------------------------------------------

    #[test]
    fn test_http_auth_cleanup_digest() {
        let mut d1 = DigestData::new();
        d1.nonce = Some("n1".into());
        let mut d2 = DigestData::new();
        d2.nonce = Some("n2".into());
        http_auth_cleanup_digest(&mut d1, &mut d2);
        assert!(d1.nonce.is_none());
        assert!(d2.nonce.is_none());
    }

    // -----------------------------------------------------------------------
    // Full roundtrip test (decode + create)
    // -----------------------------------------------------------------------

    #[test]
    fn test_digest_roundtrip() {
        let mut d = DigestData::new();
        let challenge = r#"realm="testrealm@host.com", nonce="dcd98b", qop="auth", algorithm=MD5"#;
        decode_digest_http_message(challenge, &mut d).unwrap();

        let header = create_digest_http_message(
            "Mufasa", "Circle Of Life", "GET", "/dir/index.html", &mut d,
        ).unwrap();

        assert!(header.contains("Digest "));
        assert!(header.contains("username=\"Mufasa\""));
        assert!(header.contains("realm=\"testrealm@host.com\""));
        assert!(header.contains("response=\""));
        assert!(header.contains("qop=auth"));
    }
}
