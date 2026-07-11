//! HTTP Digest (RFC 2617 / RFC 7616) and SASL DIGEST-MD5 (RFC 2831) authentication.
//!
//! This module is a faithful, memory-safe Rust rewrite of the curl 8.19.0-DEV
//! Digest implementation, derived byte-for-byte from three source-of-truth C
//! files:
//!
//! * `lib/vauth/digest.c` — the crypto, challenge parsing, and message building
//!   (both the HTTP `Authorization: Digest` value and the SASL DIGEST-MD5
//!   response);
//! * `lib/http_digest.c` — the HTTP input/output glue (`Curl_input_digest` /
//!   `Curl_output_digest`);
//! * `lib/vauth/digest.h` — the `DIGEST_MAX_*` size caps and the
//!   `Curl_auth_digest_get_pair` contract.
//!
//! # Parity mandate
//!
//! Every byte of the emitted header and SASL response must match curl 8.x for
//! identical inputs (the client nonce aside, which is random). To that end the
//! challenge parser [`get_pair`] transcribes curl's exact quirks — the "sloppy
//! comma" unquoted terminator and the escaped-quote handling — because real
//! servers depend on that lenient behavior. The IE-style URI truncation, the
//! `-sess` "qop is mandatory" rule, and curl's deliberate lack of `auth-int`
//! body hashing for PUT/POST are all preserved rather than "fixed" (Minimal
//! Change Mandate).
//!
//! # Safety
//!
//! This module is written in safe Rust end to end: every hash is computed by the
//! pure-Rust `md-5` and `sha2` crates, so none of Rust's memory-safety escape
//! hatches are needed here. The crate root forbids them outright and a CI grep
//! audit keeps the whole library free of them.
//!
//! # Cryptographic algorithms
//!
//! Digest supports the MD5, MD5-sess, SHA-256, SHA-256-sess, SHA-512-256 and
//! SHA-512-256-sess algorithms. Both `Sha256` and `Sha512_256` live in the
//! single `sha2` crate; MD5 comes from `md-5` (whose crate name is `md5`).

use crate::auth::build_spn;
use crate::error::{Error, Result};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use md5::{Digest as _, Md5};
use rand::RngCore as _;
use sha2::{Sha256, Sha512_256};

// ---------------------------------------------------------------------------
// Phase A — constants (← digest.h L30-31, digest.c L41-56)
// ---------------------------------------------------------------------------

/// Maximum length of a challenge key (the `value` side of a `key=content`
/// pair). Transcribed from `DIGEST_MAX_VALUE_LENGTH` (`lib/vauth/digest.h` L30).
pub const DIGEST_MAX_VALUE_LENGTH: usize = 256;

/// Maximum length of a challenge value (the `content` side of a `key=content`
/// pair). Transcribed from `DIGEST_MAX_CONTENT_LENGTH` (`lib/vauth/digest.h`
/// L31).
pub const DIGEST_MAX_CONTENT_LENGTH: usize = 1024;

/// The bit that, when set in an algorithm code, denotes a `-sess` variant.
/// Transcribed from `SESSION_ALGO` (`lib/vauth/digest.c` L41). A `-sess`
/// algorithm folds the nonce and client nonce into A1.
pub const SESSION_ALGO: u8 = 1;

/// The `qop=auth` capability bit (`DIGEST_QOP_VALUE_AUTH`, digest.c L50).
pub const DIGEST_QOP_VALUE_AUTH: u32 = 1 << 0;
/// The `qop=auth-int` capability bit (`DIGEST_QOP_VALUE_AUTH_INT`, digest.c
/// L51).
pub const DIGEST_QOP_VALUE_AUTH_INT: u32 = 1 << 1;
/// The `qop=auth-conf` capability bit (`DIGEST_QOP_VALUE_AUTH_CONF`, digest.c
/// L52). curl recognizes the token but does not implement confidentiality.
pub const DIGEST_QOP_VALUE_AUTH_CONF: u32 = 1 << 2;

/// The `"auth"` quality-of-protection token (digest.c L54).
pub const DIGEST_QOP_VALUE_STRING_AUTH: &str = "auth";
/// The `"auth-int"` quality-of-protection token (digest.c L55).
pub const DIGEST_QOP_VALUE_STRING_AUTH_INT: &str = "auth-int";
/// The `"auth-conf"` quality-of-protection token (digest.c L56).
pub const DIGEST_QOP_VALUE_STRING_AUTH_CONF: &str = "auth-conf";

/// The Digest algorithm code.
///
/// The discriminants reproduce curl's `ALGO_*` `#define`s (`lib/vauth/digest.c`
/// L43-48) **exactly**, including the property that the low bit
/// ([`SESSION_ALGO`]) distinguishes a `-sess` variant from its base algorithm:
///
/// | Variant           | Value | curl macro            |
/// |-------------------|-------|-----------------------|
/// | `Md5`             | 0     | `ALGO_MD5`            |
/// | `Md5Sess`         | 1     | `ALGO_MD5SESS`        |
/// | `Sha256`          | 2     | `ALGO_SHA256`         |
/// | `Sha256Sess`      | 3     | `ALGO_SHA256SESS`     |
/// | `Sha512_256`      | 4     | `ALGO_SHA512_256`     |
/// | `Sha512_256Sess`  | 5     | `ALGO_SHA512_256SESS` |
///
/// The numeric identity is load-bearing: the C dispatcher selects the hash by
/// range comparison (`algo <= ALGO_MD5SESS`, etc.), which [`DigestAlgo::hash_kind`]
/// reproduces.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DigestAlgo {
    /// `ALGO_MD5` — MD5, the default when no algorithm is specified.
    #[default]
    Md5 = 0,
    /// `ALGO_MD5SESS` — MD5-sess.
    Md5Sess = 1,
    /// `ALGO_SHA256` — SHA-256.
    Sha256 = 2,
    /// `ALGO_SHA256SESS` — SHA-256-sess.
    Sha256Sess = 3,
    /// `ALGO_SHA512_256` — SHA-512/256.
    Sha512_256 = 4,
    /// `ALGO_SHA512_256SESS` — SHA-512/256-sess.
    Sha512_256Sess = 5,
}

impl DigestAlgo {
    /// Returns `true` for a `-sess` variant, mirroring the C predicate
    /// `digest->algo & SESSION_ALGO`.
    #[must_use]
    pub fn is_sess(self) -> bool {
        (self as u8) & SESSION_ALGO != 0
    }

    /// Selects the hash family used to compute the digest, reproducing the
    /// dispatch ladder of `Curl_auth_create_digest_http_message`
    /// (`lib/vauth/digest.c` L983-1015): `algo <= ALGO_MD5SESS` → MD5,
    /// `algo <= ALGO_SHA256SESS` → SHA-256, otherwise SHA-512/256.
    fn hash_kind(self) -> HashKind {
        match self {
            DigestAlgo::Md5 | DigestAlgo::Md5Sess => HashKind::Md5,
            DigestAlgo::Sha256 | DigestAlgo::Sha256Sess => HashKind::Sha256,
            DigestAlgo::Sha512_256 | DigestAlgo::Sha512_256Sess => HashKind::Sha512_256,
        }
    }
}

// ---------------------------------------------------------------------------
// Hashing + string helpers (← digest.c L132-173)
// ---------------------------------------------------------------------------

/// Which one-shot hash to apply. The digest string length differs: MD5 yields
/// 16 bytes (32 hex chars), SHA-256 and SHA-512/256 both yield 32 bytes (64 hex
/// chars).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashKind {
    Md5,
    Sha256,
    Sha512_256,
}

/// Lowercase-hex encode a byte slice, the Rust equivalent of curl's
/// `auth_digest_md5_to_ascii` / `auth_digest_sha256_to_ascii` (`%02x` per byte,
/// digest.c L133-150).
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Hash `input` with the selected algorithm and return the lowercase-hex digest.
fn hash_hex(kind: HashKind, input: &[u8]) -> String {
    match kind {
        HashKind::Md5 => hex_encode(Md5::digest(input).as_slice()),
        HashKind::Sha256 => hex_encode(Sha256::digest(input).as_slice()),
        HashKind::Sha512_256 => hex_encode(Sha512_256::digest(input).as_slice()),
    }
}

/// Perform quoted-string escaping as described in RFC 2616 and its errata,
/// mirroring `auth_digest_string_quoted` (`lib/vauth/digest.c` L152-173): a
/// literal `"` or `\` is prefixed with a backslash; all other bytes pass
/// through. An empty input yields an empty string.
fn string_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch == '"' || ch == '\\' {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

// ---------------------------------------------------------------------------
// Phase B — DigestData state (← C `struct digestdata` in urldata.h)
// ---------------------------------------------------------------------------

/// The parsed challenge plus the response state for one authentication target.
///
/// The C code keeps one `struct digestdata` per host (`data->state.digest`) and
/// one per proxy (`data->state.proxydigest`); the caller here owns the two
/// instances and passes the relevant one to [`input_digest`] / [`output_digest`]
/// alongside the `proxy` flag. The C `char *` fields become owned
/// [`Option<String>`] (a present `Some` mirrors a non-`NULL` pointer), and the
/// `unsigned char algo` becomes the typed [`DigestAlgo`].
///
/// `nonce.is_some()` is the "have challenge" predicate (curl's
/// `have_chlg = !!digest->nonce`, `lib/http_digest.c` L120).
#[derive(Debug, Default, Clone)]
pub struct DigestData {
    /// The server-supplied `nonce`. Its presence means a challenge was decoded.
    pub nonce: Option<String>,
    /// The client nonce (`cnonce`). Generated on first response if absent;
    /// preserved across requests so the same value is reused (matching curl,
    /// which only regenerates when `digest->cnonce` is `NULL`).
    pub cnonce: Option<String>,
    /// The authentication `realm`.
    pub realm: Option<String>,
    /// The decoded algorithm code (defaults to [`DigestAlgo::Md5`]).
    pub algo: DigestAlgo,
    /// The server-supplied `opaque` value, echoed back verbatim if present.
    pub opaque: Option<String>,
    /// The chosen quality of protection (`"auth"` or `"auth-int"`), or `None`
    /// for legacy RFC 2069 mode.
    pub qop: Option<String>,
    /// The raw `algorithm` token exactly as received (case preserved), echoed
    /// back in the response's `algorithm=` field.
    pub algorithm: Option<String>,
    /// The nonce count. Formatted as eight lowercase hex digits on the wire and
    /// incremented after each response.
    pub nc: u32,
    /// `true` when the server marked the previous nonce `stale=true`, allowing a
    /// silent retry with a fresh nonce rather than a credential-rejection error.
    pub stale: bool,
    /// `true` when the server requested RFC 7616 username hashing
    /// (`userhash=true`).
    pub userhash: bool,
}

impl DigestData {
    /// Reset all challenge/response state to defaults.
    ///
    /// This is the ownership-based equivalent of `Curl_auth_digest_cleanup`
    /// (`lib/vauth/digest.c` L1027-1040): every owned string is dropped and the
    /// scalar fields return to their defaults (`nc = 0`, `algo = Md5`,
    /// `stale = false`, `userhash = false`). No manual free is needed — dropping
    /// the old value releases its heap storage.
    pub fn reset(&mut self) {
        *self = DigestData::default();
    }

    /// `true` once a challenge has been decoded (a nonce is present), the Rust
    /// form of curl's `have_chlg = !!digest->nonce` (`lib/http_digest.c` L120).
    #[must_use]
    pub fn have_challenge(&self) -> bool {
        self.nonce.is_some()
    }
}

// ---------------------------------------------------------------------------
// Phase C — challenge pair parser (← digest.c L59-129) — transcribed exactly
// ---------------------------------------------------------------------------

/// Extract a single `key=content` pair from the front of a Digest challenge
/// string.
///
/// This is the direct Rust transcription of `Curl_auth_digest_get_pair`
/// (`lib/vauth/digest.c` L59-129). On success it returns
/// `Some((key, content, rest))`, where `rest` is the unparsed remainder of the
/// input (the C `endptr`); on any of the C `FALSE` cases it returns `None`.
///
/// The C control flow is preserved to the byte, including the two subtle,
/// load-bearing quirks that real servers rely on:
///
/// * **Sloppy comma.** For an *unquoted* value, a `,` terminates the content
///   (and is itself consumed). This is curl's lenient parsing of headers like
///   `qop=auth,algorithm=MD5`.
/// * **Escaped quote.** Inside a quoted value, `\<char>` yields `<char>`
///   verbatim (the backslash is dropped), so `realm="a\"b"` decodes to `a"b`.
///
/// Other preserved behaviors: the key is capped at
/// [`DIGEST_MAX_VALUE_LENGTH`]` - 1` bytes and the content at
/// [`DIGEST_MAX_CONTENT_LENGTH`]` - 1` bytes; a missing `=` returns `None`; a
/// quoted value that meets a CR/LF or end-of-input before its closing quote
/// returns `None`; an unescaped `"` in an unquoted value returns `None`; and a
/// trailing backslash (an escape with no following character) returns `None`.
///
/// Parsing is performed on bytes to match the C pointer arithmetic exactly; the
/// only bytes ever dropped are ASCII (`=`, quotes, the escape backslash, and the
/// unquoted terminators), so the retained runs always remain valid UTF-8.
#[must_use]
pub fn get_pair(input: &str) -> Option<(String, String, &str)> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;

    // Read the key: copy bytes until '=' or end, capped at MAX_VALUE_LENGTH-1.
    // Mirrors `for(c = DIGEST_MAX_VALUE_LENGTH - 1; *str && *str != '=' && c--;)`.
    let mut key: Vec<u8> = Vec::new();
    let mut c = DIGEST_MAX_VALUE_LENGTH - 1;
    while i < len && bytes[i] != b'=' && c != 0 {
        key.push(bytes[i]);
        i += 1;
        c -= 1;
    }

    // The next byte must be '='. Mirrors `if('=' != *str++) return FALSE;`.
    if i >= len || bytes[i] != b'=' {
        return None;
    }
    i += 1; // consume '='

    // An opening quote means the value must end with a matching quote.
    let mut starts_with_quote = false;
    if i < len && bytes[i] == b'"' {
        i += 1;
        starts_with_quote = true;
    }

    // Read the content. Mirrors `for(c = DIGEST_MAX_CONTENT_LENGTH - 1;
    // *str && c--; str++)` with its inner switch. `escape` tracks a pending
    // backslash escape inside a quoted value.
    let mut content: Vec<u8> = Vec::new();
    let mut c2 = DIGEST_MAX_CONTENT_LENGTH - 1;
    let mut escape = false;
    while i < len && c2 != 0 {
        c2 -= 1;
        let ch = bytes[i];
        if !escape {
            match ch {
                b'\\' => {
                    if starts_with_quote {
                        // Start of an escaped char: drop the backslash and mark
                        // the next byte as literal (C `escape = TRUE; continue;`).
                        escape = true;
                        i += 1;
                        continue;
                    }
                    // Unquoted backslash: treated as a literal (falls through).
                }
                b',' => {
                    if !starts_with_quote {
                        // Sloppy comma: ends unquoted content; the comma is
                        // consumed (C `c = 0; continue;`).
                        i += 1;
                        break;
                    }
                }
                b'\r' | b'\n' => {
                    if starts_with_quote {
                        return None; // no closing quote
                    }
                    i += 1;
                    break;
                }
                b'"' => {
                    if starts_with_quote {
                        i += 1; // consume the closing quote
                        break;
                    }
                    return None; // bare quote in an unquoted value
                }
                _ => {}
            }
        }
        escape = false;
        content.push(ch);
        i += 1;
    }

    // A dangling escape (trailing backslash) is invalid.
    if escape {
        return None;
    }

    let key = String::from_utf8(key).ok()?;
    let content = String::from_utf8(content).ok()?;
    let rest = input.get(i..)?;
    Some((key, content, rest))
}

// ---------------------------------------------------------------------------
// Phase D — decode an HTTP Digest challenge (← digest.c L508-655)
// ---------------------------------------------------------------------------

/// Advance past a run of leading blanks (`ISBLANK` = space or tab).
fn skip_blanks(s: &str) -> &str {
    s.trim_start_matches([' ', '\t'])
}

/// Map an `algorithm` token to a [`DigestAlgo`], case-insensitively
/// (`curl_strequal`, digest.c L594-617). Returns `None` for an unrecognized
/// token. SHA-512/256 is always available here because the `sha2` crate always
/// provides it (curl gates it behind `CURL_HAVE_SHA512_256`).
fn match_algorithm(s: &str) -> Option<DigestAlgo> {
    if s.eq_ignore_ascii_case("MD5-sess") {
        Some(DigestAlgo::Md5Sess)
    } else if s.eq_ignore_ascii_case("MD5") {
        Some(DigestAlgo::Md5)
    } else if s.eq_ignore_ascii_case("SHA-256") {
        Some(DigestAlgo::Sha256)
    } else if s.eq_ignore_ascii_case("SHA-256-SESS") {
        Some(DigestAlgo::Sha256Sess)
    } else if s.eq_ignore_ascii_case("SHA-512-256") {
        Some(DigestAlgo::Sha512_256)
    } else if s.eq_ignore_ascii_case("SHA-512-256-SESS") {
        Some(DigestAlgo::Sha512_256Sess)
    } else {
        None
    }
}

/// Select the quality of protection from a `qop` challenge value, a faithful
/// port of the qop scanner in `Curl_auth_decode_digest_http_message`
/// (`lib/vauth/digest.c` L554-586).
///
/// The C code strips leading blanks, then repeatedly reads a token up to the
/// next `,` (capped at 32 bytes via `curlx_str_until`) and compares it for an
/// **exact-length, case-insensitive** match (`curlx_str_casecompare`) against
/// `"auth"` / `"auth-int"`, OR-ing the discovery flags; a comma separates
/// tokens and a missing comma (or an empty/oversized token) ends the scan. This
/// exact-length comparison is load-bearing: a token such as `"auth "` (trailing
/// blank, no closing comma) does **not** match `auth`. Finally `"auth"` is
/// preferred over `"auth-int"`, and unrecognized tokens are ignored (leaving the
/// result `None`).
fn select_http_qop(content: &str) -> Option<String> {
    let bytes = content.as_bytes();
    let mut pos = 0usize;
    let mut found_auth = false;
    let mut found_auth_int = false;

    let is_blank = |b: u8| b == b' ' || b == b'\t';

    // Pass leading spaces (C: before the loop).
    while pos < bytes.len() && is_blank(bytes[pos]) {
        pos += 1;
    }

    loop {
        // curlx_str_until(out, 32, ',')
        let start = pos;
        while pos < bytes.len() && bytes[pos] != b',' {
            pos += 1;
        }
        let token = &bytes[start..pos];
        // STRE_SHORT (empty) or STRE_BIG (> 32) ends the scan.
        if token.is_empty() || token.len() > 32 {
            break;
        }
        if token.eq_ignore_ascii_case(DIGEST_QOP_VALUE_STRING_AUTH.as_bytes()) {
            found_auth = true;
        } else if token.eq_ignore_ascii_case(DIGEST_QOP_VALUE_STRING_AUTH_INT.as_bytes()) {
            found_auth_int = true;
        }
        // curlx_str_single(','): stop if the next byte is not a comma.
        if pos >= bytes.len() || bytes[pos] != b',' {
            break;
        }
        pos += 1;
        // Pass spaces before the next token (C: at loop end).
        while pos < bytes.len() && is_blank(bytes[pos]) {
            pos += 1;
        }
    }

    if found_auth {
        Some(DIGEST_QOP_VALUE_STRING_AUTH.to_string())
    } else if found_auth_int {
        Some(DIGEST_QOP_VALUE_STRING_AUTH_INT.to_string())
    } else {
        None
    }
}

/// Decode an HTTP Digest `WWW-Authenticate` / `Proxy-Authenticate` challenge
/// into `digest`.
///
/// Direct port of `Curl_auth_decode_digest_http_message` (`lib/vauth/digest.c`
/// L508-655). The `chlg` is the challenge parameters *after* the `Digest`
/// scheme word (the caller — [`input_digest`] — strips that).
///
/// The recognized keys are matched case-insensitively (`curl_strequal`):
/// `nonce`, `stale`, `realm`, `opaque`, `qop`, `algorithm`, and `userhash`;
/// unknown keys are ignored. Before parsing, any prior state is cleared (curl
/// calls `Curl_auth_digest_cleanup` first), but whether a nonce existed
/// beforehand is remembered to detect a repeated challenge.
///
/// # Errors
///
/// Returns [`Error::BadContentEncoding`] (curl's `CURLE_BAD_CONTENT_ENCODING`)
/// when: the algorithm token is unrecognized; a nonce already existed and the
/// new challenge is not marked `stale=true` (previous credentials were
/// rejected); no nonce is present; or a `-sess` algorithm is offered without a
/// `qop`.
pub fn decode_digest_http_message(chlg: &str, digest: &mut DigestData) -> Result<()> {
    // If we already received a nonce, keep that in mind (C `before`).
    let before = digest.nonce.is_some();

    // Clean up any former leftovers and initialise to defaults.
    digest.reset();

    let mut rest = chlg;
    loop {
        // Pass all additional spaces.
        rest = skip_blanks(rest);

        // Extract a value=content pair; a parse failure means we are done.
        let Some((value, content, next)) = get_pair(rest) else {
            break;
        };
        rest = next;

        if value.eq_ignore_ascii_case("nonce") {
            digest.nonce = Some(content);
        } else if value.eq_ignore_ascii_case("stale") {
            if content.eq_ignore_ascii_case("true") {
                digest.stale = true;
                digest.nc = 1; // we make a new nonce now
            }
        } else if value.eq_ignore_ascii_case("realm") {
            digest.realm = Some(content);
        } else if value.eq_ignore_ascii_case("opaque") {
            digest.opaque = Some(content);
        } else if value.eq_ignore_ascii_case("qop") {
            // Select only auth or auth-int; otherwise ignore.
            if let Some(qop) = select_http_qop(&content) {
                digest.qop = Some(qop);
            }
        } else if value.eq_ignore_ascii_case("algorithm") {
            // Store the raw token (case preserved) before mapping, matching C
            // which strdup()s the algorithm even when the mapping then fails.
            let mapped = match_algorithm(&content);
            digest.algorithm = Some(content);
            digest.algo = mapped.ok_or_else(|| {
                Error::bad_content_encoding("Digest: unrecognized algorithm in challenge")
            })?;
        } else if value.eq_ignore_ascii_case("userhash") {
            if content.eq_ignore_ascii_case("true") {
                digest.userhash = true;
            }
        } else {
            // Unknown specifier, ignore it!
        }

        // Pass all additional spaces, then allow a comma-separated list.
        rest = skip_blanks(rest);
        if let Some(stripped) = rest.strip_prefix(',') {
            rest = stripped;
        }
    }

    // We had a nonce since before, and we got another one now without
    // 'stale=true'. This means we provided bad credentials previously.
    if before && !digest.stale {
        return Err(Error::bad_content_encoding(
            "Digest: repeated challenge without stale=true",
        ));
    }

    // We got this header without a nonce: a bad Digest line!
    if digest.nonce.is_none() {
        return Err(Error::bad_content_encoding(
            "Digest: challenge without a nonce",
        ));
    }

    // "<algo>-sess" protocol versions require "auth" or "auth-int" qop.
    if digest.qop.is_none() && digest.algo.is_sess() {
        return Err(Error::bad_content_encoding(
            "Digest: -sess algorithm requires a qop",
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Phase E — create an HTTP Digest response value (← digest.c L677-1015)
// ---------------------------------------------------------------------------

/// Build the RFC 2617 / RFC 7616 Digest response value for the current
/// challenge.
///
/// This fuses `auth_create_digest_http_message` and its public dispatcher
/// `Curl_auth_create_digest_http_message` (`lib/vauth/digest.c` L677-1015). The
/// hash algorithm is chosen from `digest.algo` ([`DigestAlgo::hash_kind`]). The
/// returned string is the value that follows the scheme word — i.e. **without**
/// the leading `Authorization: Digest ` (the HTTP glue in [`output_digest`] adds
/// that).
///
/// `uri` is the request target to hash and echo; the caller ([`output_digest`])
/// is responsible for the IE-style truncation before calling this.
///
/// # Determinism / test seam
///
/// A client nonce is generated (12 random bytes, standard-base64 → 16 chars,
/// exactly as curl 8.19.0-DEV) **only when `digest.cnonce` is `None`**, matching
/// the C `if(!digest->cnonce)` guard. Tests obtain byte-for-byte determinism by
/// pre-setting `digest.cnonce` to a fixed value.
///
/// # Errors
///
/// Currently infallible for well-formed state, but returns
/// [`crate::error::Result`] to mirror the C `CURLcode` contract and to remain
/// forward-compatible.
pub fn create_digest_http_message(
    user: &str,
    passwd: &str,
    method: &str,
    uri: &str,
    digest: &mut DigestData,
) -> Result<String> {
    let kind = digest.algo.hash_kind();

    // nc defaults to 1 (C: `if(!digest->nc) digest->nc = 1;`).
    if digest.nc == 0 {
        digest.nc = 1;
    }

    // Generate a client nonce if we do not already have one. curl uses 12 random
    // bytes, standard-base64 encoded (16 characters) — see digest.c L710-725.
    // Only generated when absent, so callers/tests can inject a fixed cnonce.
    if digest.cnonce.is_none() {
        let mut buf = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut buf);
        digest.cnonce = Some(BASE64_STANDARD.encode(buf));
    }

    // A missing realm hashes/serializes as an empty string (digest.c L753-754,
    // L866-872). nonce is guaranteed present (decode requires it).
    let realm = digest.realm.as_deref().unwrap_or("");
    let nonce = digest.nonce.as_deref().unwrap_or("");
    let cnonce = digest.cnonce.as_deref().unwrap_or("");

    // RFC 7616 §3.4.4 username hashing: the username field carries
    // H(unq(username) ":" unq(realm)) (digest.c L727-740).
    let userh = if digest.userhash {
        hash_hex(kind, format!("{user}:{realm}").as_bytes())
    } else {
        String::new()
    };

    // ---- A1 (digest.c L742-779) ----
    // Base A1 = username ":" realm ":" password; HA1 = H(A1).
    let mut ha1 = hash_hex(kind, format!("{user}:{realm}:{passwd}").as_bytes());
    if digest.algo.is_sess() {
        // For a "-sess" algorithm the nonce and cnonce are folded in OUTSIDE the
        // first hash: HA1 = H(HA1 ":" nonce ":" cnonce).
        ha1 = hash_hex(kind, format!("{ha1}:{nonce}:{cnonce}").as_bytes());
    }

    // ---- A2 (digest.c L781-829) ----
    // A2 = Method ":" digest-uri-value, hashing the RAW uri (the wire field is
    // quoted separately below).
    let mut a2 = format!("{method}:{uri}");
    if digest.qop.as_deref() == Some(DIGEST_QOP_VALUE_STRING_AUTH_INT) {
        // curl does NOT support auth-int for PUT/POST: it hashes an EMPTY body.
        // This limitation is preserved verbatim (Minimal Change Mandate).
        let empty_body = hash_hex(kind, b"");
        a2 = format!("{a2}:{empty_body}");
    }
    let ha2 = hash_hex(kind, a2.as_bytes());

    // ---- response hash (digest.c L831-846) ----
    let nc = digest.nc;
    let nc_hex = format!("{nc:08x}");
    let request_digest = if let Some(qop) = digest.qop.as_deref() {
        hash_hex(
            kind,
            format!("{ha1}:{nonce}:{nc_hex}:{cnonce}:{qop}:{ha2}").as_bytes(),
        )
    } else {
        // Legacy RFC 2069 (no qop).
        hash_hex(kind, format!("{ha1}:{nonce}:{ha2}").as_bytes())
    };

    // ---- assemble the response header value (digest.c L861-946) ----
    let username_field = string_quoted(if digest.userhash { &userh } else { user });
    let realm_q = string_quoted(realm);
    let nonce_q = string_quoted(nonce);
    let uri_q = string_quoted(uri);

    let mut response = if let Some(qop) = digest.qop.as_deref() {
        let s = format!(
            "username=\"{username_field}\", realm=\"{realm_q}\", nonce=\"{nonce_q}\", uri=\"{uri_q}\", cnonce=\"{cnonce}\", nc={nc_hex}, qop={qop}, response=\"{request_digest}\""
        );
        // Increment the nonce-count for the next request (digest.c L903).
        digest.nc += 1;
        s
    } else {
        format!(
            "username=\"{username_field}\", realm=\"{realm_q}\", nonce=\"{nonce_q}\", uri=\"{uri_q}\", response=\"{request_digest}\""
        )
    };

    // Optional fields, appended in curl's exact order (digest.c L920-946).
    if let Some(opaque) = digest.opaque.as_deref() {
        let opaque_q = string_quoted(opaque);
        response.push_str(&format!(", opaque=\"{opaque_q}\""));
    }
    if let Some(algorithm) = digest.algorithm.as_deref() {
        // The raw algorithm token is echoed unquoted.
        response.push_str(&format!(", algorithm={algorithm}"));
    }
    if digest.userhash {
        response.push_str(", userhash=true");
    }

    Ok(response)
}

// ---------------------------------------------------------------------------
// Phase F — HTTP input/output glue (← http_digest.c)
// ---------------------------------------------------------------------------

/// Consume a `WWW-Authenticate` / `Proxy-Authenticate` Digest header value and
/// decode it into `digest`.
///
/// Port of `Curl_input_digest` (`lib/http_digest.c` L41-63). `header` is the
/// text after the header name, beginning with the `Digest` scheme word. The
/// header must start with `Digest` (matched case-insensitively, like curl's
/// `checkprefix`) followed by a blank (space or tab); the scheme word and the
/// following blanks are then stripped and the remainder is handed to
/// [`decode_digest_http_message`].
///
/// The `proxy` flag mirrors curl's host-vs-proxy `digestdata` selection; because
/// the caller here passes the already-selected `digest`, the flag carries no
/// behavioral effect and is accepted only for signature parity with
/// `Curl_input_digest`.
///
/// # Errors
///
/// Returns [`Error::BadContentEncoding`] (curl's `CURLE_BAD_CONTENT_ENCODING`)
/// if the `Digest` prefix or the following blank is missing, or if
/// [`decode_digest_http_message`] rejects the challenge.
pub fn input_digest(proxy: bool, header: &str, digest: &mut DigestData) -> Result<()> {
    // Silence the intentionally-unused parity parameter without altering the
    // public signature.
    let _ = proxy;

    // C: `if(!checkprefix("Digest", header) || !ISBLANK(header[6]))` -> error.
    let has_prefix = header
        .get(..6)
        .is_some_and(|p| p.eq_ignore_ascii_case("Digest"));
    let blank_after = header
        .as_bytes()
        .get(6)
        .is_some_and(|&b| b == b' ' || b == b'\t');
    if !has_prefix || !blank_after {
        return Err(Error::bad_content_encoding(
            "Digest: WWW-Authenticate header is not a Digest challenge",
        ));
    }

    // Advance past "Digest" and skip the blanks, then decode.
    let rest = skip_blanks(header.get(6..).unwrap_or(""));
    decode_digest_http_message(rest, digest)
}

/// Produce the complete `Authorization: Digest ...\r\n` request-header line
/// (`Proxy-Authorization` when `proxy` is set), or `None` when there is nothing
/// to send yet.
///
/// Port of `Curl_output_digest` (`lib/http_digest.c` L65-170).
///
/// * When no challenge has been decoded (`digest.nonce` is `None`), returns
///   `Ok(None)`: the authentication phase is not complete and no header is
///   emitted (curl sets `authp->done = FALSE` and returns `CURLE_OK`).
/// * When `iestyle` is set, `uripath` is truncated at the first `?` before the
///   digest is computed. This reproduces the IE < v7 behavior that some (IIS)
///   servers expect; note it deliberately yields a different MD5 than the RFC
///   path.
///
/// `request` is the HTTP method (e.g. `GET`). The returned line ends with the
/// canonical CRLF, exactly as curl's `curl_maprintf("%sAuthorization: Digest
/// %s\r\n", ...)`.
///
/// # Errors
///
/// Propagates any error returned by [`create_digest_http_message`].
pub fn output_digest(
    proxy: bool,
    request: &str,
    uripath: &str,
    iestyle: bool,
    user: &str,
    passwd: &str,
    digest: &mut DigestData,
) -> Result<Option<String>> {
    // "have challenge" — C `have_chlg = !!digest->nonce` (non-SSPI, L120).
    if !digest.have_challenge() {
        // The auth phase is not done; nothing to send yet.
        return Ok(None);
    }

    // IE-style: cut the uri at the query part before computing the digest.
    let path: &str = if iestyle {
        match uripath.find('?') {
            Some(idx) => &uripath[..idx],
            None => uripath,
        }
    } else {
        uripath
    };

    let response = create_digest_http_message(user, passwd, request, path, digest)?;

    let prefix = if proxy { "Proxy-" } else { "" };
    Ok(Some(format!(
        "{prefix}Authorization: Digest {response}\r\n"
    )))
}

// ---------------------------------------------------------------------------
// Phase G — SASL DIGEST-MD5 (RFC 2831) (← digest.c L176-493)
// ---------------------------------------------------------------------------

/// Extract the (backslash-unescaped) value for `key` from a SASL DIGEST-MD5
/// challenge.
///
/// Faithful port of `auth_digest_get_key_value` (`lib/vauth/digest.c`
/// L176-230). The challenge is a comma-separated list of `keyword=value` pairs
/// whose values may or may not be quoted. This differs from the HTTP
/// [`get_pair`] parser in several load-bearing ways, all preserved here:
///
/// * The key name is matched **case-sensitively** (`curlx_str_cmp`), unlike the
///   HTTP decoder's case-insensitive keys.
/// * The name is read until `=` and is capped at 64 bytes; the value is read as
///   a quoted word (with `\`-escapes) or, if unquoted, up to the next `,`, and
///   is capped at 256 bytes. Exceeding either cap, or an empty name/value, makes
///   the whole lookup fail (returns `None`).
/// * When the matching key is found, its **raw** (still-escaped) length must be
///   strictly less than `buflen` — mirroring the C `if(len >= buflen) return
///   FALSE;` fixed-buffer guard (`nonce`/`algorithm`/`qop` use 64, `realm` 128).
/// * A non-matching pair must be followed by a `,` to continue scanning;
///   otherwise the lookup fails.
///
/// Returns `Some(value)` with backslash-escapes removed (`\x` → `x`), or `None`
/// if the key is absent or any of the above structural rules are violated.
fn sasl_get_key_value(chlg: &[u8], key: &str, buflen: usize) -> Option<String> {
    let key_bytes = key.as_bytes();
    let mut pos = 0usize;

    loop {
        // curlx_str_passblanks: skip leading spaces/tabs.
        while pos < chlg.len() && (chlg[pos] == b' ' || chlg[pos] == b'\t') {
            pos += 1;
        }

        // curlx_str_until(name, 64, '='): read the key name.
        let name_start = pos;
        while pos < chlg.len() && chlg[pos] != b'=' {
            pos += 1;
        }
        let name = &chlg[name_start..pos];
        // STRE_SHORT (empty) or STRE_BIG (> 64) => C `else`/odd-syntax => break.
        if name.is_empty() || name.len() > 64 {
            return None;
        }
        // curlx_str_single('='): the name must be terminated by '='.
        if pos >= chlg.len() || chlg[pos] != b'=' {
            return None;
        }
        pos += 1; // consume '='

        // Read the value: a quoted word, or (if it does not begin with a quote)
        // an unquoted run up to the next comma.
        let value_raw: &[u8];
        if pos < chlg.len() && chlg[pos] == b'"' {
            // curlx_str_quotedword: escaped quotes/backslashes are supported;
            // the raw span (backslashes included) is captured, and both the
            // backslash and the escaped byte count toward the 256 cap.
            pos += 1; // skip opening quote
            let vstart = pos;
            loop {
                if pos >= chlg.len() {
                    // End of input before a closing quote => STRE_ENDQUOTE.
                    return None;
                }
                let c = chlg[pos];
                if c == b'"' {
                    break;
                }
                if c == b'\\' && pos + 1 < chlg.len() {
                    pos += 1; // the escaped byte is part of the value span
                }
                pos += 1;
            }
            value_raw = &chlg[vstart..pos];
            pos += 1; // skip closing quote
            if value_raw.len() > 256 {
                return None; // STRE_BIG
            }
        } else {
            // STRE_BEGQUOTE => unquoted value read until ',' (max 256).
            let vstart = pos;
            while pos < chlg.len() && chlg[pos] != b',' {
                pos += 1;
            }
            value_raw = &chlg[vstart..pos];
            if value_raw.is_empty() || value_raw.len() > 256 {
                return None; // STRE_SHORT / STRE_BIG
            }
        }

        if name == key_bytes {
            // Matching key: enforce the fixed-buffer fit on the RAW length.
            if value_raw.len() >= buflen {
                return None;
            }
            // Un-escape: `\x` collapses to `x`; a trailing lone `\` is literal.
            let mut out = Vec::with_capacity(value_raw.len());
            let mut i = 0;
            while i < value_raw.len() {
                if value_raw[i] == b'\\' && i + 1 < value_raw.len() {
                    i += 1; // skip the backslash
                }
                out.push(value_raw[i]);
                i += 1;
            }
            return Some(String::from_utf8_lossy(&out).into_owned());
        }

        // Non-matching pair: a comma must separate it from the next pair.
        if pos >= chlg.len() || chlg[pos] != b',' {
            return None;
        }
        pos += 1; // consume ','
    }
}

/// Parse a DIGEST-MD5 `qop-options` string into the [`DIGEST_QOP_VALUE_AUTH`] /
/// [`DIGEST_QOP_VALUE_AUTH_INT`] / [`DIGEST_QOP_VALUE_AUTH_CONF`] bitmask.
///
/// Port of `auth_digest_get_qop_values` (`lib/vauth/digest.c` L232-249): the
/// options are split on `,`, each token (capped at 32 bytes) is compared
/// case-insensitively for an exact match against the three known qop tokens, and
/// the corresponding bit is OR-ed in. An oversized or empty token stops the
/// scan, exactly as curl's `curlx_str_until` short-circuits the loop.
fn parse_qop_values(options: &[u8]) -> u32 {
    let mut pos = 0usize;
    let mut value = 0u32;

    loop {
        // curlx_str_until(out, 32, ',')
        let start = pos;
        while pos < options.len() && options[pos] != b',' {
            pos += 1;
        }
        let token = &options[start..pos];
        // STRE_SHORT (empty) or STRE_BIG (> 32) => stop scanning.
        if token.is_empty() || token.len() > 32 {
            break;
        }
        // curlx_str_casecompare: exact-length, case-insensitive match.
        if token.eq_ignore_ascii_case(DIGEST_QOP_VALUE_STRING_AUTH.as_bytes()) {
            value |= DIGEST_QOP_VALUE_AUTH;
        } else if token.eq_ignore_ascii_case(DIGEST_QOP_VALUE_STRING_AUTH_INT.as_bytes()) {
            value |= DIGEST_QOP_VALUE_AUTH_INT;
        } else if token.eq_ignore_ascii_case(DIGEST_QOP_VALUE_STRING_AUTH_CONF.as_bytes()) {
            value |= DIGEST_QOP_VALUE_AUTH_CONF;
        }
        // curlx_str_single(','): stop if the next byte is not a comma.
        if pos >= options.len() || options[pos] != b',' {
            break;
        }
        pos += 1;
    }

    value
}

/// Generate a 32-hex-character client nonce (16 random bytes → hex), matching
/// curl's `Curl_rand_hex(data, cnonce, sizeof(cnonce))` where `cnonce` is a
/// `char[33]` (32 hex chars + NUL) — see digest.c L384-385.
fn generate_sasl_cnonce() -> String {
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    hex_encode(&buf)
}

/// Create a SASL DIGEST-MD5 (RFC 2831) response for the given challenge.
///
/// Port of `Curl_auth_create_digest_md5_message` (`lib/vauth/digest.c`
/// L334-493). The returned bytes are the **raw** (un-encoded) response string;
/// the SASL engine base64-encodes them before transmission, so this returns
/// `Vec<u8>` rather than a header line.
///
/// A fresh 32-hex-character client nonce is generated on every call
/// ([`generate_sasl_cnonce`]); [`sasl_digest_md5_response`] is the deterministic
/// core that accepts an explicit `cnonce` and is exercised directly by the
/// RFC 2831 test vector.
///
/// # Parameters
///
/// * `chlg` — the raw DIGEST-MD5 challenge bytes (as received, before base64
///   decoding is already done by the caller).
/// * `userp` / `passwdp` — the credentials.
/// * `service` — the service token (`imap`, `smtp`, `pop`, ...).
/// * `host` — the host name, combined with `service` into the digest-uri SPN via
///   [`crate::auth::build_spn`].
///
/// # Errors
///
/// Returns [`Error::BadContentEncoding`] when the challenge is empty, is missing
/// a required `nonce`/`algorithm`/`qop`, advertises an algorithm other than
/// `md5-sess`, or does not offer the `auth` quality of protection.
pub fn create_digest_md5_message(
    chlg: &[u8],
    userp: &str,
    passwdp: &str,
    service: &str,
    host: &str,
) -> Result<Vec<u8>> {
    let cnonce = generate_sasl_cnonce();
    sasl_digest_md5_response(chlg, userp, passwdp, service, host, &cnonce)
}

/// Deterministic core of [`create_digest_md5_message`] taking an explicit client
/// nonce, so wire-parity tests can pin `cnonce` and assert an exact response.
fn sasl_digest_md5_response(
    chlg: &[u8],
    userp: &str,
    passwdp: &str,
    service: &str,
    host: &str,
    cnonce: &str,
) -> Result<Vec<u8>> {
    // C `auth_decode_digest_md5_message`: an empty challenge is invalid.
    if chlg.is_empty() {
        return Err(Error::bad_content_encoding(
            "DIGEST-MD5: empty challenge message",
        ));
    }

    // Retrieve the nonce (required), realm (optional → empty per RFC 2831),
    // algorithm (required) and qop-options (required). Buffer caps mirror the
    // C fixed buffers: nonce/algorithm/qop = 64, realm = 128.
    let nonce = sasl_get_key_value(chlg, "nonce", 64)
        .ok_or_else(|| Error::bad_content_encoding("DIGEST-MD5: missing nonce"))?;
    let realm = sasl_get_key_value(chlg, "realm", 128).unwrap_or_default();
    let algorithm = sasl_get_key_value(chlg, "algorithm", 64)
        .ok_or_else(|| Error::bad_content_encoding("DIGEST-MD5: missing algorithm"))?;
    let qop_options = sasl_get_key_value(chlg, "qop", 64)
        .ok_or_else(|| Error::bad_content_encoding("DIGEST-MD5: missing qop"))?;

    // We only support md5 sessions (C: `strcmp(algorithm, "md5-sess")`,
    // case-sensitive).
    if algorithm != "md5-sess" {
        return Err(Error::bad_content_encoding(
            "DIGEST-MD5: unsupported algorithm (only md5-sess)",
        ));
    }

    // The server must advertise the "auth" quality of protection.
    let qop_values = parse_qop_values(qop_options.as_bytes());
    if qop_values & DIGEST_QOP_VALUE_AUTH == 0 {
        return Err(Error::bad_content_encoding(
            "DIGEST-MD5: server does not support auth qop",
        ));
    }

    // ---- A1 / H(A1) per RFC 2831 §3.4.2 ----
    // First: MD5(user ":" realm ":" passwd) → 16 RAW octets.
    let mut a1a = Md5::new();
    a1a.update(userp.as_bytes());
    a1a.update(b":");
    a1a.update(realm.as_bytes());
    a1a.update(b":");
    a1a.update(passwdp.as_bytes());
    let a1a_digest = a1a.finalize();

    // Second: MD5(<16 raw octets> ":" nonce ":" cnonce) → HA1; hex-encode.
    // The RAW octets are fed in (NOT their hex form) — this is load-bearing.
    let mut a1b = Md5::new();
    a1b.update(a1a_digest.as_slice());
    a1b.update(b":");
    a1b.update(nonce.as_bytes());
    a1b.update(b":");
    a1b.update(cnonce.as_bytes());
    let ha1_hex = hex_encode(a1b.finalize().as_slice());

    // ---- SPN / digest-uri ----
    // build_spn(service, Some(host), None) yields "service/host".
    let spn = build_spn(service, Some(host), None);

    // ---- A2 / H(A2): MD5("AUTHENTICATE" ":" spn) → HA2; hex-encode. ----
    let mut a2 = Md5::new();
    a2.update(b"AUTHENTICATE");
    a2.update(b":");
    a2.update(spn.as_bytes());
    let ha2_hex = hex_encode(a2.finalize().as_slice());

    // ---- response = MD5(HA1 ":" nonce ":" nc ":" cnonce ":" qop ":" HA2) ----
    // nc is fixed at "00000001" and qop at "auth" for the SASL exchange.
    let nonce_count = "00000001";
    let qop = DIGEST_QOP_VALUE_STRING_AUTH;
    let mut resp = Md5::new();
    resp.update(ha1_hex.as_bytes());
    resp.update(b":");
    resp.update(nonce.as_bytes());
    resp.update(b":");
    resp.update(nonce_count.as_bytes());
    resp.update(b":");
    resp.update(cnonce.as_bytes());
    resp.update(b":");
    resp.update(qop.as_bytes());
    resp.update(b":");
    resp.update(ha2_hex.as_bytes());
    let resp_hash_hex = hex_encode(resp.finalize().as_slice());

    // ---- assemble the response (digest.c L472-482) ----
    // NOTE: no spaces after the commas (unlike the HTTP Digest header). realm
    // and nonce are quote-escaped; username, cnonce and digest-uri are emitted
    // raw exactly as curl does; response and qop are unquoted.
    let qrealm = string_quoted(&realm);
    let qnonce = string_quoted(&nonce);
    let response = format!(
        "username=\"{userp}\",realm=\"{qrealm}\",nonce=\"{qnonce}\",cnonce=\"{cnonce}\",nc=\"{nonce_count}\",digest-uri=\"{spn}\",response={resp_hash_hex},qop={qop}"
    );

    Ok(response.into_bytes())
}

// ---------------------------------------------------------------------------
// Phase H — tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Phase A: constants & algorithm identity -----------------------------

    #[test]
    fn algo_numeric_identity_matches_c() {
        // The discriminants must reproduce the C `ALGO_*` #defines exactly, and
        // the low bit must flag the "-sess" variants.
        assert_eq!(DigestAlgo::Md5 as u8, 0);
        assert_eq!(DigestAlgo::Md5Sess as u8, 1);
        assert_eq!(DigestAlgo::Sha256 as u8, 2);
        assert_eq!(DigestAlgo::Sha256Sess as u8, 3);
        assert_eq!(DigestAlgo::Sha512_256 as u8, 4);
        assert_eq!(DigestAlgo::Sha512_256Sess as u8, 5);
        assert_eq!(SESSION_ALGO, 1);
    }

    #[test]
    fn algo_is_sess() {
        assert!(!DigestAlgo::Md5.is_sess());
        assert!(DigestAlgo::Md5Sess.is_sess());
        assert!(!DigestAlgo::Sha256.is_sess());
        assert!(DigestAlgo::Sha256Sess.is_sess());
        assert!(!DigestAlgo::Sha512_256.is_sess());
        assert!(DigestAlgo::Sha512_256Sess.is_sess());
        assert_eq!(DigestAlgo::default(), DigestAlgo::Md5);
    }

    #[test]
    fn qop_bit_and_string_constants() {
        assert_eq!(DIGEST_QOP_VALUE_AUTH, 1);
        assert_eq!(DIGEST_QOP_VALUE_AUTH_INT, 2);
        assert_eq!(DIGEST_QOP_VALUE_AUTH_CONF, 4);
        assert_eq!(DIGEST_QOP_VALUE_STRING_AUTH, "auth");
        assert_eq!(DIGEST_QOP_VALUE_STRING_AUTH_INT, "auth-int");
        assert_eq!(DIGEST_QOP_VALUE_STRING_AUTH_CONF, "auth-conf");
        assert_eq!(DIGEST_MAX_VALUE_LENGTH, 256);
        assert_eq!(DIGEST_MAX_CONTENT_LENGTH, 1024);
    }

    // -- Hashing / quoting helpers -------------------------------------------

    #[test]
    fn hex_encode_is_lowercase() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn hash_hex_known_vectors() {
        // MD5("abc"), SHA-256("abc"), SHA-512/256("abc").
        assert_eq!(
            hash_hex(HashKind::Md5, b"abc"),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hash_hex(HashKind::Sha256, b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hash_hex(HashKind::Sha512_256, b"abc"),
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
        );
    }

    #[test]
    fn string_quoted_escapes_quote_and_backslash() {
        assert_eq!(string_quoted("plain"), "plain");
        assert_eq!(string_quoted("a\"b"), "a\\\"b");
        assert_eq!(string_quoted("a\\b"), "a\\\\b");
        assert_eq!(string_quoted(""), "");
        // Combined: a backslash then a quote.
        assert_eq!(string_quoted("\\\""), "\\\\\\\"");
    }

    // -- Phase B: DigestData state -------------------------------------------

    #[test]
    fn digestdata_default_and_reset() {
        let mut d = DigestData::default();
        assert!(!d.have_challenge());
        d.nonce = Some("abc".into());
        d.nc = 5;
        d.stale = true;
        assert!(d.have_challenge());
        d.reset();
        assert!(!d.have_challenge());
        assert_eq!(d.nc, 0);
        assert!(!d.stale);
        assert_eq!(d.algo, DigestAlgo::Md5);
    }

    // -- Phase C: get_pair quirks --------------------------------------------

    #[test]
    fn get_pair_simple_quoted() {
        let (k, v, rest) = get_pair("realm=\"testrealm\"").unwrap();
        assert_eq!(k, "realm");
        assert_eq!(v, "testrealm");
        assert_eq!(rest, "");
    }

    #[test]
    fn get_pair_unquoted_sloppy_comma_terminates_and_is_consumed() {
        // Unquoted value ends at the comma; the comma is consumed, so `rest`
        // points *past* it.
        let (k, v, rest) = get_pair("qop=auth,").unwrap();
        assert_eq!(k, "qop");
        assert_eq!(v, "auth");
        assert_eq!(rest, "");

        let (k, v, rest) = get_pair("nonce=abc,algorithm=MD5").unwrap();
        assert_eq!(k, "nonce");
        assert_eq!(v, "abc");
        assert_eq!(rest, "algorithm=MD5");
    }

    #[test]
    fn get_pair_quoted_rest_points_at_trailing_comma() {
        // A quoted value stops at the closing quote; `rest` points *at* the
        // following comma (the decode loop then skips it).
        let (k, v, rest) = get_pair("realm=\"foo\",nonce=\"bar\"").unwrap();
        assert_eq!(k, "realm");
        assert_eq!(v, "foo");
        assert_eq!(rest, ",nonce=\"bar\"");
    }

    #[test]
    fn get_pair_escaped_quote_inside_quoted_value() {
        // realm="test\"realm"  ->  content is  test"realm
        let (k, v, rest) = get_pair("realm=\"test\\\"realm\"").unwrap();
        assert_eq!(k, "realm");
        assert_eq!(v, "test\"realm");
        assert_eq!(rest, "");
    }

    #[test]
    fn get_pair_escaped_backslash_inside_quoted_value() {
        // realm="a\\b" -> a\b
        let (k, v, _rest) = get_pair("realm=\"a\\\\b\"").unwrap();
        assert_eq!(k, "realm");
        assert_eq!(v, "a\\b");
    }

    #[test]
    fn get_pair_no_equals_is_none() {
        assert!(get_pair("realm").is_none());
        assert!(get_pair("").is_none());
    }

    #[test]
    fn get_pair_unterminated_quote_with_newline_is_none() {
        // A quoted value that meets CR/LF before its closing quote fails.
        assert!(get_pair("realm=\"unterminated\r\n").is_none());
        assert!(get_pair("realm=\"unterminated\n").is_none());
    }

    #[test]
    fn get_pair_quote_ending_at_input_boundary_is_ok() {
        // Unlike the CR/LF case, simply running out of input keeps whatever was
        // read (curl returns TRUE and sets endptr to the end).
        let (k, v, rest) = get_pair("realm=\"unterminated").unwrap();
        assert_eq!(k, "realm");
        assert_eq!(v, "unterminated");
        assert_eq!(rest, "");
    }

    #[test]
    fn get_pair_bare_quote_in_unquoted_value_is_none() {
        // A `"` inside an unquoted value is rejected.
        assert!(get_pair("realm=te\"st").is_none());
    }

    #[test]
    fn get_pair_trailing_backslash_is_none() {
        // An escape with no following character inside a quoted value.
        assert!(get_pair("realm=\"abc\\").is_none());
    }

    // -- Phase D: decode HTTP Digest challenge -------------------------------

    #[test]
    fn decode_full_challenge() {
        let chlg = "realm=\"testrealm@host.com\", \
                    qop=\"auth,auth-int\", \
                    nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
                    opaque=\"5ccc069c403ebaf9f0171e9517f40e41\", \
                    algorithm=MD5";
        let mut d = DigestData::default();
        decode_digest_http_message(chlg, &mut d).unwrap();
        assert_eq!(d.realm.as_deref(), Some("testrealm@host.com"));
        assert_eq!(
            d.nonce.as_deref(),
            Some("dcd98b7102dd2f0e8b11d0f600bfb0c093")
        );
        assert_eq!(
            d.opaque.as_deref(),
            Some("5ccc069c403ebaf9f0171e9517f40e41")
        );
        // qop prefers "auth" over "auth-int".
        assert_eq!(d.qop.as_deref(), Some("auth"));
        assert_eq!(d.algorithm.as_deref(), Some("MD5"));
        assert_eq!(d.algo, DigestAlgo::Md5);
    }

    #[test]
    fn decode_algorithm_mapping_case_insensitive() {
        let cases = [
            ("MD5", DigestAlgo::Md5),
            ("md5", DigestAlgo::Md5),
            ("MD5-sess", DigestAlgo::Md5Sess),
            ("SHA-256", DigestAlgo::Sha256),
            ("sha-256-sess", DigestAlgo::Sha256Sess),
            ("SHA-512-256", DigestAlgo::Sha512_256),
            ("SHA-512-256-SESS", DigestAlgo::Sha512_256Sess),
        ];
        for (algo_str, expected) in cases {
            // -sess variants need a qop, so always advertise one.
            let chlg = format!("nonce=\"n\", qop=\"auth\", algorithm={algo_str}");
            let mut d = DigestData::default();
            decode_digest_http_message(&chlg, &mut d).unwrap();
            assert_eq!(d.algo, expected, "algorithm={algo_str}");
            assert_eq!(d.algorithm.as_deref(), Some(algo_str));
        }
    }

    #[test]
    fn decode_unknown_algorithm_is_error() {
        let mut d = DigestData::default();
        let err = decode_digest_http_message("nonce=\"n\", algorithm=whirlpool", &mut d);
        assert!(err.is_err());
    }

    #[test]
    fn decode_missing_nonce_is_error() {
        let mut d = DigestData::default();
        assert!(decode_digest_http_message("realm=\"r\"", &mut d).is_err());
    }

    #[test]
    fn decode_sess_without_qop_is_error() {
        // A "-sess" algorithm mandates a qop (parity with digest.c L650).
        let mut d = DigestData::default();
        assert!(decode_digest_http_message("nonce=\"n\", algorithm=MD5-sess", &mut d).is_err());
    }

    #[test]
    fn decode_repeated_challenge_without_stale_is_error() {
        let mut d = DigestData::default();
        decode_digest_http_message("nonce=\"first\"", &mut d).unwrap();
        // A second challenge without stale=true means the credentials were bad.
        let err = decode_digest_http_message("nonce=\"second\"", &mut d);
        assert!(err.is_err());
    }

    #[test]
    fn decode_stale_true_resets_and_allows_repeat() {
        let mut d = DigestData::default();
        decode_digest_http_message("nonce=\"first\"", &mut d).unwrap();
        d.nc = 7;
        decode_digest_http_message("nonce=\"second\", stale=true", &mut d).unwrap();
        assert!(d.stale);
        assert_eq!(d.nonce.as_deref(), Some("second"));
        assert_eq!(d.nc, 1); // reset on stale
    }

    #[test]
    fn decode_userhash_true() {
        let mut d = DigestData::default();
        decode_digest_http_message("nonce=\"n\", userhash=TRUE", &mut d).unwrap();
        assert!(d.userhash);
        let mut d2 = DigestData::default();
        decode_digest_http_message("nonce=\"n\", userhash=false", &mut d2).unwrap();
        assert!(!d2.userhash);
    }

    // -- Phase E: create HTTP Digest response --------------------------------

    fn rfc2617_digest(qop: Option<&str>, algo: DigestAlgo) -> DigestData {
        DigestData {
            nonce: Some("dcd98b7102dd2f0e8b11d0f600bfb0c093".into()),
            realm: Some("testrealm@host.com".into()),
            qop: qop.map(str::to_string),
            cnonce: Some("0a4f113b".into()),
            algo,
            ..Default::default()
        }
    }

    #[test]
    fn create_rfc2617_md5_auth_exact_string() {
        let mut d = rfc2617_digest(Some("auth"), DigestAlgo::Md5);
        let resp = create_digest_http_message(
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            &mut d,
        )
        .unwrap();
        assert_eq!(
            resp,
            "username=\"Mufasa\", realm=\"testrealm@host.com\", \
             nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", \
             cnonce=\"0a4f113b\", nc=00000001, qop=auth, \
             response=\"6629fae49393a05397450978507c4ef1\""
        );
        // nonce-count advanced for the next request.
        assert_eq!(d.nc, 2);
    }

    #[test]
    fn create_rfc2069_no_qop_exact_string() {
        let mut d = rfc2617_digest(None, DigestAlgo::Md5);
        let resp = create_digest_http_message(
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            &mut d,
        )
        .unwrap();
        assert_eq!(
            resp,
            "username=\"Mufasa\", realm=\"testrealm@host.com\", \
             nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", \
             response=\"670fd8c2df070c60b045671b8b24ff02\""
        );
        // No qop => nc is not incremented.
        assert_eq!(d.nc, 1);
    }

    fn response_field(header_value: &str) -> &str {
        // Extract the value inside `response="..."`.
        let marker = "response=\"";
        let start = header_value.find(marker).unwrap() + marker.len();
        let tail = &header_value[start..];
        let end = tail.find('"').unwrap();
        &tail[..end]
    }

    #[test]
    fn create_sha256_response() {
        let mut d = rfc2617_digest(Some("auth"), DigestAlgo::Sha256);
        let resp = create_digest_http_message(
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            &mut d,
        )
        .unwrap();
        assert_eq!(
            response_field(&resp),
            "5abdd07184ba512a22c53f41470e5eea7dcaa3a93a59b630c13dfe0a5dc6e38b"
        );
    }

    #[test]
    fn create_sha512_256_response() {
        let mut d = rfc2617_digest(Some("auth"), DigestAlgo::Sha512_256);
        let resp = create_digest_http_message(
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            &mut d,
        )
        .unwrap();
        assert_eq!(
            response_field(&resp),
            "f23c08ec7334a881f8286e68450ddbd9f0cd91c41481f0e1433604da8113c6dc"
        );
    }

    #[test]
    fn create_md5_sess_response() {
        let mut d = rfc2617_digest(Some("auth"), DigestAlgo::Md5Sess);
        let resp = create_digest_http_message(
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            &mut d,
        )
        .unwrap();
        assert_eq!(response_field(&resp), "8e3825c57e897f5a0dec6c2d4e5059d0");
    }

    #[test]
    fn create_auth_int_response_uses_empty_body_hash() {
        // curl does not support auth-int for PUT/POST: it hashes an empty body.
        let mut d = rfc2617_digest(Some("auth-int"), DigestAlgo::Md5);
        let resp = create_digest_http_message(
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            &mut d,
        )
        .unwrap();
        assert_eq!(response_field(&resp), "5e6610ecf9ba3017a4870ad48e3ad30b");
        assert!(resp.contains("qop=auth-int"));
    }

    #[test]
    fn create_userhash_uses_hashed_username_field() {
        let mut d = rfc2617_digest(Some("auth"), DigestAlgo::Md5);
        d.userhash = true;
        let resp = create_digest_http_message(
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            &mut d,
        )
        .unwrap();
        // Username field carries H(user:realm), and userhash=true is appended.
        assert!(resp.starts_with("username=\"74f54fe2c8045a5ffda7d02fd97f1716\", "));
        assert!(resp.ends_with(", userhash=true"));
        // The response digest is unchanged by userhash.
        assert_eq!(response_field(&resp), "6629fae49393a05397450978507c4ef1");
    }

    #[test]
    fn create_appends_opaque_and_algorithm() {
        let mut d = rfc2617_digest(Some("auth"), DigestAlgo::Md5);
        d.opaque = Some("op-aque".into());
        d.algorithm = Some("MD5".into());
        let resp = create_digest_http_message(
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            &mut d,
        )
        .unwrap();
        // Optional fields appear in curl's order: opaque (quoted), algorithm
        // (unquoted).
        assert!(resp.contains(", opaque=\"op-aque\", algorithm=MD5"));
    }

    #[test]
    fn create_cnonce_generated_when_absent() {
        // With no injected cnonce, one is generated (16 base64 chars from 12
        // random bytes) and reused on the next call.
        let mut d = rfc2617_digest(Some("auth"), DigestAlgo::Md5);
        d.cnonce = None;
        let _ = create_digest_http_message("u", "p", "GET", "/", &mut d).unwrap();
        let generated = d.cnonce.clone().expect("cnonce generated");
        assert_eq!(generated.len(), 16, "12 bytes -> 16 base64 chars");
        // Second call reuses the same cnonce.
        let _ = create_digest_http_message("u", "p", "GET", "/", &mut d).unwrap();
        assert_eq!(d.cnonce.as_deref(), Some(generated.as_str()));
    }

    // -- Phase F: HTTP input/output glue -------------------------------------

    #[test]
    fn input_digest_valid_challenge() {
        let mut d = DigestData::default();
        input_digest(false, "Digest realm=\"r\", nonce=\"abc\"", &mut d).unwrap();
        assert_eq!(d.realm.as_deref(), Some("r"));
        assert_eq!(d.nonce.as_deref(), Some("abc"));
    }

    #[test]
    fn input_digest_prefix_is_case_insensitive() {
        let mut d = DigestData::default();
        input_digest(false, "digest nonce=\"abc\"", &mut d).unwrap();
        assert_eq!(d.nonce.as_deref(), Some("abc"));
    }

    #[test]
    fn input_digest_tab_after_scheme_is_accepted() {
        let mut d = DigestData::default();
        input_digest(false, "Digest\tnonce=\"abc\"", &mut d).unwrap();
        assert_eq!(d.nonce.as_deref(), Some("abc"));
    }

    #[test]
    fn input_digest_rejects_wrong_scheme() {
        let mut d = DigestData::default();
        assert!(input_digest(false, "Basic realm=\"r\"", &mut d).is_err());
    }

    #[test]
    fn input_digest_rejects_missing_blank() {
        // "Digest" with no following blank (too short) must fail.
        let mut d = DigestData::default();
        assert!(input_digest(false, "Digest", &mut d).is_err());
        // "DigestX" — 7th char is not a blank.
        let mut d2 = DigestData::default();
        assert!(input_digest(false, "DigestX nonce=\"a\"", &mut d2).is_err());
    }

    #[test]
    fn output_digest_no_challenge_returns_none() {
        let mut d = DigestData::default();
        let out = output_digest(false, "GET", "/", false, "u", "p", &mut d).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn output_digest_builds_full_line() {
        let mut d = DigestData::default();
        input_digest(false, "Digest realm=\"testrealm@host.com\", qop=\"auth\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"", &mut d).unwrap();
        d.cnonce = Some("0a4f113b".into());
        let line = output_digest(
            false,
            "GET",
            "/dir/index.html",
            false,
            "Mufasa",
            "Circle Of Life",
            &mut d,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            line,
            "Authorization: Digest username=\"Mufasa\", realm=\"testrealm@host.com\", \
             nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", \
             cnonce=\"0a4f113b\", nc=00000001, qop=auth, \
             response=\"6629fae49393a05397450978507c4ef1\"\r\n"
        );
    }

    #[test]
    fn output_digest_proxy_prefix() {
        let mut d = DigestData::default();
        input_digest(true, "Digest nonce=\"n\"", &mut d).unwrap();
        d.cnonce = Some("cn".into());
        let line = output_digest(true, "GET", "/", false, "u", "p", &mut d)
            .unwrap()
            .unwrap();
        assert!(line.starts_with("Proxy-Authorization: Digest "));
        assert!(line.ends_with("\r\n"));
    }

    #[test]
    fn output_digest_iestyle_truncates_uri_at_query() {
        let build = |iestyle: bool| {
            let mut d = DigestData::default();
            input_digest(false, "Digest nonce=\"n\", qop=\"auth\"", &mut d).unwrap();
            d.cnonce = Some("cn".into());
            output_digest(false, "GET", "/path?a=1&b=2", iestyle, "u", "p", &mut d)
                .unwrap()
                .unwrap()
        };
        let ie = build(true);
        let full = build(false);
        // IE-style truncates the uri field at '?' and yields a different digest.
        assert!(ie.contains("uri=\"/path\""));
        assert!(full.contains("uri=\"/path?a=1&b=2\""));
        assert_ne!(ie, full);
    }

    // -- Phase G: SASL DIGEST-MD5 --------------------------------------------

    const RFC2831_CHLG: &[u8] = b"realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",qop=\"auth\",algorithm=md5-sess,charset=utf-8";

    #[test]
    fn sasl_get_key_value_basics() {
        assert_eq!(
            sasl_get_key_value(RFC2831_CHLG, "nonce", 64).as_deref(),
            Some("OA6MG9tEQGm2hh")
        );
        assert_eq!(
            sasl_get_key_value(RFC2831_CHLG, "realm", 128).as_deref(),
            Some("elwood.innosoft.com")
        );
        assert_eq!(
            sasl_get_key_value(RFC2831_CHLG, "algorithm", 64).as_deref(),
            Some("md5-sess")
        );
        assert_eq!(
            sasl_get_key_value(RFC2831_CHLG, "qop", 64).as_deref(),
            Some("auth")
        );
        // Absent key.
        assert!(sasl_get_key_value(RFC2831_CHLG, "missing", 64).is_none());
    }

    #[test]
    fn sasl_get_key_value_is_case_sensitive() {
        // curlx_str_cmp is case-sensitive: "Nonce" != "nonce".
        assert!(sasl_get_key_value(RFC2831_CHLG, "Nonce", 64).is_none());
    }

    #[test]
    fn sasl_get_key_value_unescapes_backslashes() {
        let chlg = b"realm=\"a\\\"b\",nonce=\"n\"";
        assert_eq!(
            sasl_get_key_value(chlg, "realm", 128).as_deref(),
            Some("a\"b")
        );
    }

    #[test]
    fn sasl_get_key_value_respects_buffer_cap() {
        // Value length must be strictly less than buflen (C fixed-buffer guard).
        let chlg = b"nonce=abcdefghij"; // 10-char value
        assert_eq!(
            sasl_get_key_value(chlg, "nonce", 11).as_deref(),
            Some("abcdefghij")
        );
        assert!(sasl_get_key_value(chlg, "nonce", 10).is_none());
    }

    #[test]
    fn parse_qop_values_bits() {
        assert_eq!(parse_qop_values(b"auth"), DIGEST_QOP_VALUE_AUTH);
        assert_eq!(parse_qop_values(b"auth-int"), DIGEST_QOP_VALUE_AUTH_INT);
        assert_eq!(parse_qop_values(b"auth-conf"), DIGEST_QOP_VALUE_AUTH_CONF);
        assert_eq!(
            parse_qop_values(b"auth,auth-int"),
            DIGEST_QOP_VALUE_AUTH | DIGEST_QOP_VALUE_AUTH_INT
        );
        // Case-insensitive.
        assert_eq!(parse_qop_values(b"AUTH"), DIGEST_QOP_VALUE_AUTH);
        // Unknown token ignored.
        assert_eq!(parse_qop_values(b"bogus"), 0);
    }

    #[test]
    fn sasl_rfc2831_exact_response() {
        // RFC 2831 §4 worked example (with the RFC's own cnonce), asserting the
        // exact raw response bytes.
        let out = sasl_digest_md5_response(
            RFC2831_CHLG,
            "chris",
            "secret",
            "imap",
            "elwood.innosoft.com",
            "OA6MHXh6VqTrRk",
        )
        .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert_eq!(
            out,
            "username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",\
             cnonce=\"OA6MHXh6VqTrRk\",nc=\"00000001\",digest-uri=\"imap/elwood.innosoft.com\",\
             response=d388dad90d4bbd760a152321f2143af7,qop=auth"
        );
    }

    #[test]
    fn sasl_public_wrapper_generates_hex_cnonce() {
        let out = create_digest_md5_message(
            RFC2831_CHLG,
            "chris",
            "secret",
            "imap",
            "elwood.innosoft.com",
        )
        .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.starts_with("username=\"chris\",realm=\"elwood.innosoft.com\","));
        assert!(out.contains("digest-uri=\"imap/elwood.innosoft.com\""));
        assert!(out.ends_with(",qop=auth"));
        // Extract the generated cnonce and confirm it is 32 lowercase-hex chars.
        let marker = "cnonce=\"";
        let start = out.find(marker).unwrap() + marker.len();
        let tail = &out[start..];
        let cnonce = &tail[..tail.find('"').unwrap()];
        assert_eq!(cnonce.len(), 32);
        assert!(cnonce.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn sasl_generate_cnonce_is_32_hex() {
        let c = generate_sasl_cnonce();
        assert_eq!(c.len(), 32);
        assert!(c.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn sasl_rejects_non_md5_sess_algorithm() {
        let chlg = b"realm=\"r\",nonce=\"n\",qop=\"auth\",algorithm=md5";
        assert!(sasl_digest_md5_response(chlg, "u", "p", "imap", "host", "cn").is_err());
    }

    #[test]
    fn sasl_rejects_missing_auth_qop() {
        let chlg = b"realm=\"r\",nonce=\"n\",qop=\"auth-int\",algorithm=md5-sess";
        assert!(sasl_digest_md5_response(chlg, "u", "p", "imap", "host", "cn").is_err());
    }

    #[test]
    fn sasl_rejects_missing_nonce_and_algorithm() {
        // Missing nonce.
        let chlg = b"realm=\"r\",qop=\"auth\",algorithm=md5-sess";
        assert!(sasl_digest_md5_response(chlg, "u", "p", "imap", "host", "cn").is_err());
        // Missing algorithm.
        let chlg2 = b"realm=\"r\",nonce=\"n\",qop=\"auth\"";
        assert!(sasl_digest_md5_response(chlg2, "u", "p", "imap", "host", "cn").is_err());
    }

    #[test]
    fn sasl_rejects_empty_challenge() {
        assert!(sasl_digest_md5_response(b"", "u", "p", "imap", "host", "cn").is_err());
        assert!(create_digest_md5_message(b"", "u", "p", "imap", "host").is_err());
    }

    #[test]
    fn sasl_realm_absent_defaults_empty() {
        // No realm in the challenge -> realm defaults to "" (RFC 2831).
        let chlg = b"nonce=\"n\",qop=\"auth\",algorithm=md5-sess";
        let out = sasl_digest_md5_response(chlg, "u", "p", "imap", "host", "cn").unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("realm=\"\""));
    }
}
