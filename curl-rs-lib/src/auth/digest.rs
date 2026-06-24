//! HTTP Digest authentication and SASL `DIGEST-MD5`, reproduced byte-for-byte.
//!
//! This module is the memory-safe Rust reimplementation of curl's
//! `lib/vauth/digest.c` (+ `digest.h`) and the HTTP glue in `lib/http_digest.c`.
//! It is the **most byte-exact** of the auth modules: the generated
//! `Authorization: Digest` header — every field, every `", "` separator, every
//! quote and `%08x` nonce-count — must match curl 8.x exactly so that the
//! upstream regression suite (whose digest tests compare the full header line)
//! passes unmodified.
//!
//! # Two distinct wire formats
//!
//! HTTP Digest (RFC 7616 / RFC 2617) and SASL `DIGEST-MD5` (RFC 2831) share the
//! hashing math but use **different** serializations, so they have two separate
//! formatters that must never be merged:
//!
//! * **HTTP Digest** — `field="value", field=value, …` with a space after every
//!   comma; the `response` is quoted.
//! * **SASL `DIGEST-MD5`** — `field="value",field=value,…` with **no** spaces;
//!   the `response` is **unquoted**.
//!
//! # Algorithms
//!
//! `MD5`, `MD5-sess`, `SHA-256`, `SHA-256-sess`, `SHA-512-256` and
//! `SHA-512-256-sess` (RFC 7616) are all fully supported via the pure-Rust
//! [`crate::util::md5`] / [`crate::util::sha256`] primitives (the last two use
//! [`crate::util::sha256::sha512_256it`]). SHA-512/256 is gated behind
//! [`HAVE_SHA512_256`], which is `true` in this build — exactly like a stock curl
//! build that defines `CURL_HAVE_SHA512_256` — and is kept in lockstep with
//! `version.rs`, which reports the `sha512-256` capability.
//!
//! # The cnonce and deterministic tests
//!
//! The client nonce (`cnonce`) is the only nondeterministic input. For HTTP
//! Digest it is 12 OS-random bytes, base64-encoded; for SASL it is 32 random
//! lowercase-hex characters. Reproducibility for the regression suite comes
//! entirely from the `CURL_ENTROPY` debug hook honored by [`crate::util::rand`].
//! Callers (and tests) that need a fixed cnonce can pre-set
//! [`DigestData::cnonce`] for HTTP Digest (the generator is skipped when it is
//! already set, exactly as in curl).
//!
//! # Memory safety
//!
//! This module contains **zero `unsafe`** and compiles under the crate-wide
//! `#![forbid(unsafe_code)]` (declared below as well, matching the sibling
//! modules). All crypto is pure Rust via [`crate::util`]; there is no C crypto
//! linkage, no raw pointers, and no manual allocation.

#![forbid(unsafe_code)]

use crate::error::{CurlError, Result};
use crate::util::base64::base64_encode;
use crate::util::dynbuf::DynBuf;
use crate::util::md5::md5it;
use crate::util::rand::{rand_bytes, rand_hex};
use crate::util::sha256::{sha256it, sha512_256it};
use crate::util::strparse::{curlx_str_casecompare, curlx_str_cmp, strcasecompare, Str, StrError};

// ===========================================================================
// Phase A — Constants & types
// ===========================================================================

/// Maximum length of a challenge pair's *key* (curl `DIGEST_MAX_VALUE_LENGTH`).
///
/// Mirrors `lib/vauth/digest.h`. The key (e.g. `realm`, `nonce`) is captured up
/// to this many bytes; anything longer is truncated exactly as curl truncates.
pub const DIGEST_MAX_VALUE_LENGTH: usize = 256;

/// Maximum length of a challenge pair's *value/content* (curl
/// `DIGEST_MAX_CONTENT_LENGTH`).
///
/// Mirrors `lib/vauth/digest.h`. Content longer than this is truncated, matching
/// curl's fixed-size on-stack buffer.
pub const DIGEST_MAX_CONTENT_LENGTH: usize = 1024;

/// Lowercase hexadecimal digit table, matching curl's hex conversion in
/// `auth_digest_md5_to_ascii` / `auth_digest_sha256_to_ascii` (`%02x`).
const LDIGITS: &[u8; 16] = b"0123456789abcdef";

/// `qop` token bit: `auth` (curl `DIGEST_QOP_VALUE_AUTH`).
const DIGEST_QOP_VALUE_AUTH: u8 = 1 << 0;
/// `qop` token bit: `auth-int` (curl `DIGEST_QOP_VALUE_AUTH_INT`).
const DIGEST_QOP_VALUE_AUTH_INT: u8 = 1 << 1;
/// `qop` token bit: `auth-conf` (curl `DIGEST_QOP_VALUE_AUTH_CONF`).
const DIGEST_QOP_VALUE_AUTH_CONF: u8 = 1 << 2;

/// `qop` token string `"auth"` (curl `DIGEST_QOP_VALUE_STRING_AUTH`).
const DIGEST_QOP_VALUE_STRING_AUTH: &str = "auth";
/// `qop` token string `"auth-int"` (curl `DIGEST_QOP_VALUE_STRING_AUTH_INT`).
const DIGEST_QOP_VALUE_STRING_AUTH_INT: &str = "auth-int";
/// `qop` token string `"auth-conf"` (curl `DIGEST_QOP_VALUE_STRING_AUTH_CONF`).
const DIGEST_QOP_VALUE_STRING_AUTH_CONF: &str = "auth-conf";

/// SASL `DIGEST-MD5` method string (curl's `char method[] = "AUTHENTICATE"`),
/// hashed into HA2.
const SASL_DIGEST_METHOD: &[u8] = b"AUTHENTICATE";
/// SASL `DIGEST-MD5` nonce-count (curl's `char nonceCount[] = "00000001"`),
/// emitted in the `nc="…"` field and hashed into the response.
const SASL_DIGEST_NONCE_COUNT: &[u8] = b"00000001";

/// Whether this build provides SHA-512/256 (curl's `CURL_HAVE_SHA512_256`).
///
/// `true` in this build: `crate::util::sha256::sha512_256it` implements the
/// SHA-512/256 truncation via the pure-Rust RustCrypto `sha2` crate, and
/// `version.rs` reports the `sha512-256` capability. This exactly matches a stock
/// curl build that defines `CURL_HAVE_SHA512_256` — the default for the
/// OpenSSL/rustls/wolfSSL/mbedTLS crypto backends. With it `true`, the
/// `SHA-512-256` and `SHA-512-256-SESS` algorithms (RFC 7616) are accepted by the
/// decoder ([`decode_digest_http_message`]) and hashed by [`digest_hash`], just as
/// curl computes them with `Curl_sha512_256it` paired with
/// `auth_digest_sha256_to_ascii` in `lib/vauth/digest.c`.
pub const HAVE_SHA512_256: bool = true;

/// The Digest algorithm, with the curl numeric values preserved exactly.
///
/// The low bit (`& 1`) is curl's `SESSION_ALGO` flag, so every `*-sess` variant
/// is the corresponding base algorithm `| 1`. Preserving the integer values
/// lets the hashing dispatch use the same `algo <= ALGO_*SESS` range checks as
/// curl's `Curl_auth_create_digest_http_message`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Algorithm {
    /// `MD5` — curl `ALGO_MD5` (0). The default algorithm.
    #[default]
    Md5 = 0,
    /// `MD5-sess` — curl `ALGO_MD5SESS` (1).
    Md5Sess = 1,
    /// `SHA-256` — curl `ALGO_SHA256` (2).
    Sha256 = 2,
    /// `SHA-256-SESS` — curl `ALGO_SHA256SESS` (3).
    Sha256Sess = 3,
    /// `SHA-512-256` — curl `ALGO_SHA512_256` (4). Gated by [`HAVE_SHA512_256`].
    Sha512_256 = 4,
    /// `SHA-512-256-SESS` — curl `ALGO_SHA512_256SESS` (5). Gated by
    /// [`HAVE_SHA512_256`].
    Sha512_256Sess = 5,
}

impl Algorithm {
    /// The raw curl numeric value (`ALGO_*`), used for the `<=` range dispatch.
    #[must_use]
    pub const fn raw(self) -> u8 {
        self as u8
    }

    /// Whether this is a session (`*-sess`) algorithm — curl's `algo &
    /// SESSION_ALGO`.
    ///
    /// Session variants fold the `nonce` and `cnonce` into `HA1`, and require a
    /// `qop` to be present in the challenge.
    #[must_use]
    pub const fn is_session(self) -> bool {
        (self as u8) & 1 == 1
    }
}

/// Per-handle Digest state (curl's `struct digestdata`).
///
/// A host instance and a proxy instance live on the easy handle in curl; here
/// the caller owns one [`DigestData`] per authentication target. All string
/// fields are owned [`String`]s (curl's heap `char *`), stored **de-escaped**
/// (the challenge parser removes backslash escapes), and re-escaped on output.
///
/// [`Default`] produces the cleaned-up state curl resets to in
/// `Curl_auth_digest_cleanup`: all strings cleared, `nc = 0`, `algo = MD5`,
/// `stale = false`, `userhash = false`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DigestData {
    /// The server nonce from the challenge (`nonce="…"`).
    pub nonce: Option<String>,
    /// The client nonce. Generated on first use for HTTP Digest unless already
    /// set; pre-set it to force a deterministic value (e.g. in tests).
    pub cnonce: Option<String>,
    /// The authentication realm (`realm="…"`), de-escaped.
    pub realm: Option<String>,
    /// The opaque value (`opaque="…"`) echoed back verbatim (re-escaped).
    pub opaque: Option<String>,
    /// The selected quality-of-protection token (`"auth"` or `"auth-int"`).
    pub qop: Option<String>,
    /// The raw algorithm string from the challenge (e.g. `"MD5-sess"`), emitted
    /// verbatim and **unquoted** in the response's `algorithm=` field.
    pub algorithm: Option<String>,
    /// The nonce count; incremented after each `qop`-bearing response.
    pub nc: u32,
    /// The parsed algorithm enum used to select the hash.
    pub algo: Algorithm,
    /// Whether the challenge carried `stale=true` (re-auth with a new nonce).
    pub stale: bool,
    /// Whether the challenge requested `userhash=true` (RFC 7616 §3.4.4).
    pub userhash: bool,
}

impl DigestData {
    /// Create a fresh, empty [`DigestData`] (equivalent to [`Default`]).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset to the default state — curl's `Curl_auth_digest_cleanup`.
    ///
    /// Clears every string field, sets `nc = 0`, `algo = MD5`, `stale = false`
    /// and `userhash = false`.
    pub fn cleanup(&mut self) {
        *self = Self::default();
    }
}

/// `true` — Digest is supported by this build (curl's
/// `Curl_auth_is_digest_supported`).
#[must_use]
pub fn is_digest_supported() -> bool {
    true
}

/// ASCII blank test — curl's `ISBLANK` (a space or a horizontal tab).
#[inline]
const fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

// ===========================================================================
// Phase B — Challenge pair parser (curl `Curl_auth_digest_get_pair`)
// ===========================================================================

/// One parsed `key=value` pair extracted from a Digest challenge.
///
/// `content` is already **de-escaped** — backslash escapes inside a quoted value
/// have been removed — exactly as curl's `Curl_auth_digest_get_pair` returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestPair {
    /// The pair's key (e.g. `realm`, `nonce`), captured up to
    /// [`DIGEST_MAX_VALUE_LENGTH`] − 1 bytes.
    pub key: Vec<u8>,
    /// The pair's de-escaped value, captured up to
    /// [`DIGEST_MAX_CONTENT_LENGTH`] − 1 bytes.
    pub content: Vec<u8>,
    /// The number of bytes of `input` consumed (the C `endptr` offset). The
    /// unparsed remainder is `&input[consumed..]`.
    pub consumed: usize,
}

/// Extract a single `key=value` pair from a challenge string, reproducing
/// curl's `Curl_auth_digest_get_pair` byte-for-byte.
///
/// Parsing rules (identical to curl):
///
/// * The **key** is read until `=` (or end of input), capped at
///   [`DIGEST_MAX_VALUE_LENGTH`] − 1 bytes. A missing `=` is a hard failure.
/// * If the value begins with `"` it is a quoted string: backslash escapes
///   (`\x`) are removed (de-escaped), the closing `"` ends the value, and a
///   `CR`/`LF` encountered before the closing quote is a failure (unclosed
///   quote). Reaching the end of input without a closing quote is **not** a
///   failure — the captured content is returned (curl's sloppy behavior).
/// * If the value is unquoted, a bare `,` ends it (and is consumed), a `CR`/`LF`
///   ends it (and is consumed), and a bare `"` is a failure.
/// * A trailing backslash with no following byte (a dangling escape) is a
///   failure.
/// * The value is capped at [`DIGEST_MAX_CONTENT_LENGTH`] − 1 bytes.
///
/// Returns [`None`] on any of the failures above (curl's `FALSE`).
#[must_use]
pub fn digest_get_pair(input: &[u8]) -> Option<DigestPair> {
    let n = input.len();
    let mut i = 0usize;

    // --- Key: read until '=' or end, capped at DIGEST_MAX_VALUE_LENGTH - 1. ---
    // C: `for(c = MAX-1; (*str && (*str != '=') && c--);) *value++ = *str++;`
    let mut key = Vec::new();
    let mut budget = DIGEST_MAX_VALUE_LENGTH - 1;
    while i < n && input[i] != b'=' && budget > 0 {
        key.push(input[i]);
        i += 1;
        budget -= 1;
    }

    // C: `if('=' != *str++) return FALSE;` — require '=', then step past it.
    if i >= n || input[i] != b'=' {
        return None;
    }
    i += 1; // consume '='

    // Optional leading quote.
    let mut starts_with_quote = false;
    if i < n && input[i] == b'"' {
        starts_with_quote = true;
        i += 1;
    }

    // --- Content: capped at DIGEST_MAX_CONTENT_LENGTH - 1 bytes. ---
    let mut content = Vec::new();
    let mut budget = DIGEST_MAX_CONTENT_LENGTH - 1;
    let mut escape = false;
    while i < n && budget > 0 {
        let ch = input[i];
        if !escape {
            match ch {
                b'\\' => {
                    if starts_with_quote {
                        // Start of an escaped sequence: drop the backslash and
                        // mark the next byte as escaped. (C: `escape = TRUE;
                        // continue;` — the `continue` still advances `str` and
                        // decrements the budget.)
                        escape = true;
                        i += 1;
                        budget -= 1;
                        continue;
                    }
                    // Unquoted: a backslash is an ordinary byte; fall through.
                }
                b',' => {
                    if !starts_with_quote {
                        // Unquoted comma terminates the content and is consumed.
                        i += 1;
                        break;
                    }
                    // Quoted: a comma is ordinary; fall through.
                }
                b'\r' | b'\n' => {
                    if starts_with_quote {
                        // Newline inside a quote == unclosed quote == failure.
                        return None;
                    }
                    // Unquoted: the newline terminates the content and is
                    // consumed.
                    i += 1;
                    break;
                }
                b'"' => {
                    if starts_with_quote {
                        // Closing quote terminates the content and is consumed.
                        i += 1;
                        break;
                    }
                    // A bare quote in unquoted content is a failure.
                    return None;
                }
                _ => {}
            }
        }

        // Ordinary byte (or the byte following an escape): copy it.
        escape = false;
        content.push(ch);
        i += 1;
        budget -= 1;
    }

    // C: `if(escape) return FALSE;` — a dangling trailing backslash.
    if escape {
        return None;
    }

    Some(DigestPair {
        key,
        content,
        consumed: i,
    })
}

// ===========================================================================
// Phase C — HTTP Digest challenge decode
// (curl `Curl_auth_decode_digest_http_message`)
// ===========================================================================

/// Decode an HTTP Digest challenge into `digest`, reproducing curl's
/// `Curl_auth_decode_digest_http_message`.
///
/// `chlg` is the challenge text **after** the `Digest` scheme token (see
/// [`input_digest`]). The function first records whether a `nonce` was already
/// present, then resets `digest` (curl cleans up before parsing) and walks the
/// comma-separated `key=value` list, populating the recognized fields:
///
/// * `nonce`, `realm`, `opaque` — stored de-escaped.
/// * `stale=true` — sets [`DigestData::stale`] and `nc = 1` (a fresh nonce).
/// * `qop` — tokenized on `,`; `auth` is preferred, else `auth-int`.
/// * `algorithm` — mapped to [`Algorithm`]; `SHA-512-256[-SESS]` is accepted
///   while [`HAVE_SHA512_256`] is `true` (this build), else returns
///   [`CurlError::NotBuiltIn`]; an unrecognized value returns
///   [`CurlError::BadContentEncoding`].
/// * `userhash=true` — sets [`DigestData::userhash`].
///
/// # Errors
///
/// Returns [`CurlError::BadContentEncoding`] if a nonce was already present and
/// the new challenge is not `stale` (bad credentials, no retry), if no `nonce`
/// is supplied at all, or if a session algorithm is offered without a `qop`.
pub fn decode_digest_http_message(chlg: &[u8], digest: &mut DigestData) -> Result<()> {
    // Remember whether we had a nonce before resetting (C: `before`).
    let before = digest.nonce.is_some();

    // Clean up former leftovers and initialise to defaults.
    digest.cleanup();

    let mut rest = chlg;
    loop {
        // Pass all additional leading spaces/tabs.
        rest = skip_blanks(rest);

        let Some(pair) = digest_get_pair(rest) else {
            break; // We are done here.
        };
        rest = &rest[pair.consumed..];

        let key = pair.key.as_slice();
        let content = pair.content.as_slice();

        if strcasecompare(key, b"nonce") {
            digest.nonce = Some(bytes_to_string(content));
        } else if strcasecompare(key, b"stale") {
            if strcasecompare(content, b"true") {
                digest.stale = true;
                digest.nc = 1; // we make a new nonce now
            }
        } else if strcasecompare(key, b"realm") {
            digest.realm = Some(bytes_to_string(content));
        } else if strcasecompare(key, b"opaque") {
            digest.opaque = Some(bytes_to_string(content));
        } else if strcasecompare(key, b"qop") {
            if let Some(qop) = select_qop(content) {
                digest.qop = Some(qop.to_string());
            }
        } else if strcasecompare(key, b"algorithm") {
            digest.algorithm = Some(bytes_to_string(content));
            digest.algo = map_algorithm(content)?;
        } else if strcasecompare(key, b"userhash") {
            if strcasecompare(content, b"true") {
                digest.userhash = true;
            }
        } else {
            // Unknown specifier, ignore it!
        }

        // Pass all additional spaces, then allow a single comma separator.
        rest = skip_blanks(rest);
        if let Some((&b',', tail)) = rest.split_first() {
            rest = tail;
        }
    }

    // We had a nonce since before, and got another now without 'stale=true':
    // this means we provided bad credentials in the previous request.
    if before && !digest.stale {
        return Err(CurlError::BadContentEncoding);
    }

    // A challenge without a nonce is a bad Digest line.
    if digest.nonce.is_none() {
        return Err(CurlError::BadContentEncoding);
    }

    // "<algo>-sess" versions require "auth" or "auth-int" qop.
    if digest.qop.is_none() && digest.algo.is_session() {
        return Err(CurlError::BadContentEncoding);
    }

    Ok(())
}

/// Skip leading ASCII blanks (spaces/tabs), returning the remaining slice.
fn skip_blanks(mut s: &[u8]) -> &[u8] {
    while let Some((&b, tail)) = s.split_first() {
        if is_blank(b) {
            s = tail;
        } else {
            break;
        }
    }
    s
}

/// Tokenize a `qop` challenge value and select the preferred token.
///
/// Mirrors the `qop` branch of `Curl_auth_decode_digest_http_message`: the
/// content is split on commas (each token capped at 32 bytes), and `auth` is
/// chosen if present, otherwise `auth-int`. Any other tokens are ignored, and a
/// value with neither returns [`None`].
fn select_qop(content: &[u8]) -> Option<&'static str> {
    let mut cur = Str::from_bytes(content);
    let mut found_auth = false;
    let mut found_auth_int = false;

    // Pass leading blanks (C: `while(*token && ISBLANK(*token)) token++;`).
    cur.curlx_str_passblanks();

    let mut token = Str::default();
    while cur.curlx_str_until(&mut token, 32, b',').is_ok() {
        if curlx_str_casecompare(&token, DIGEST_QOP_VALUE_STRING_AUTH) {
            found_auth = true;
        } else if curlx_str_casecompare(&token, DIGEST_QOP_VALUE_STRING_AUTH_INT) {
            found_auth_int = true;
        }
        if cur.curlx_str_single(b',').is_err() {
            break;
        }
        cur.curlx_str_passblanks();
    }

    if found_auth {
        Some(DIGEST_QOP_VALUE_STRING_AUTH)
    } else if found_auth_int {
        Some(DIGEST_QOP_VALUE_STRING_AUTH_INT)
    } else {
        None
    }
}

/// Map a challenge `algorithm` string to an [`Algorithm`], reproducing curl's
/// case-insensitive comparison and SHA-512/256 gating.
///
/// # Errors
///
/// Returns [`CurlError::NotBuiltIn`] for `SHA-512-256`/`SHA-512-256-SESS` while
/// [`HAVE_SHA512_256`] is `false`, and [`CurlError::BadContentEncoding`] for an
/// unrecognized algorithm.
fn map_algorithm(content: &[u8]) -> Result<Algorithm> {
    if strcasecompare(content, b"MD5-sess") {
        Ok(Algorithm::Md5Sess)
    } else if strcasecompare(content, b"MD5") {
        Ok(Algorithm::Md5)
    } else if strcasecompare(content, b"SHA-256") {
        Ok(Algorithm::Sha256)
    } else if strcasecompare(content, b"SHA-256-SESS") {
        Ok(Algorithm::Sha256Sess)
    } else if strcasecompare(content, b"SHA-512-256") {
        if HAVE_SHA512_256 {
            Ok(Algorithm::Sha512_256)
        } else {
            // Matches curl built without CURL_HAVE_SHA512_256.
            Err(CurlError::NotBuiltIn)
        }
    } else if strcasecompare(content, b"SHA-512-256-SESS") {
        if HAVE_SHA512_256 {
            Ok(Algorithm::Sha512_256Sess)
        } else {
            Err(CurlError::NotBuiltIn)
        }
    } else {
        Err(CurlError::BadContentEncoding)
    }
}

/// Convert challenge bytes to an owned [`String`].
///
/// Digest challenge tokens are ASCII/UTF-8 in practice; any invalid UTF-8 byte
/// is replaced with U+FFFD (valid UTF-8 sequences are preserved exactly).
fn bytes_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

// ===========================================================================
// Phase E — Hash dispatch and ASCII conversion
// (curl `auth_digest_md5_to_ascii` / `auth_digest_sha256_to_ascii` plus the
//  algorithm-keyed dispatch in `Curl_auth_create_digest_http_message`)
// ===========================================================================

/// Lowercase-hex–encode `source`, producing exactly `2 * source.len()` ASCII
/// bytes (curl's `%02x` per byte).
fn hex_encode_lower(source: &[u8]) -> Vec<u8> {
    let mut dest = Vec::with_capacity(source.len() * 2);
    for &b in source {
        dest.push(LDIGITS[usize::from(b >> 4)]);
        dest.push(LDIGITS[usize::from(b & 0x0f)]);
    }
    dest
}

/// Convert a 16-byte MD5 digest to its 32-character lowercase-hex form.
///
/// Mirrors curl's `auth_digest_md5_to_ascii` (RFC 2617 §3.1.3).
fn md5_to_ascii(source: &[u8; 16]) -> Vec<u8> {
    hex_encode_lower(source)
}

/// Convert a 32-byte SHA-256 digest to its 64-character lowercase-hex form.
///
/// Mirrors curl's `auth_digest_sha256_to_ascii` (RFC 7616).
fn sha256_to_ascii(source: &[u8; 32]) -> Vec<u8> {
    hex_encode_lower(source)
}

/// Hash `input` with the algorithm selected by `algo`, returning the digest's
/// **lowercase-hex ASCII** form — the representation curl feeds back into the
/// next hash and emits verbatim in the header.
///
/// This fuses curl's `hash` + `convert_to_ascii` function-pointer pair, which
/// `Curl_auth_create_digest_http_message` always selects together:
///
/// * `algo <= ALGO_MD5SESS` → MD5 → 32 hex chars.
/// * `algo <= ALGO_SHA256SESS` → SHA-256 → 64 hex chars.
/// * `algo <= ALGO_SHA512_256SESS` → SHA-512/256, gated by [`HAVE_SHA512_256`].
///
/// # Errors
///
/// Infallible in this build: `MD5`/`SHA-256`/`SHA-512-256` are all wired, so the
/// `Result` is always `Ok`. It would only return [`CurlError::NotBuiltIn`] for
/// the SHA-512/256 algorithms if [`HAVE_SHA512_256`] were `false` (matching a
/// curl build without `CURL_HAVE_SHA512_256`), but the decoder rejects those
/// up front in that case, so this signature stays fallible only to mirror curl's
/// `#ifdef`-gated dispatch.
fn digest_hash(algo: Algorithm, input: &[u8]) -> Result<Vec<u8>> {
    let raw = algo.raw();
    if raw <= Algorithm::Md5Sess.raw() {
        Ok(md5_to_ascii(&md5it(input)))
    } else if raw <= Algorithm::Sha256Sess.raw() {
        Ok(sha256_to_ascii(&sha256it(input)))
    } else {
        // ALGO_SHA512_256 / ALGO_SHA512_256SESS. SHA-512/256 produces a 256-bit
        // (32-byte) digest, so it reuses the SHA-256 hex serialization
        // (`auth_digest_sha256_to_ascii` in curl). This mirrors curl's
        // `Curl_auth_create_digest_http_message`, which dispatches the
        // `algo <= ALGO_SHA512_256SESS` range to `auth_digest_sha256_to_ascii`
        // paired with `Curl_sha512_256it` (lib/vauth/digest.c). Gated on
        // [`HAVE_SHA512_256`], which is `true` in this build.
        Ok(sha256_to_ascii(&sha512_256it(input)))
    }
}

// ===========================================================================
// Phase D — HTTP Digest response output (BYTE-EXACT)
// (curl `auth_create_digest_http_message` + `auth_digest_string_quoted`)
// ===========================================================================

/// Quoted-string escaping for Digest header values — curl's
/// `auth_digest_string_quoted` (RFC 2616 + errata).
///
/// A `"` or `\` byte is prefixed with a backslash; every other byte is copied
/// verbatim. Empty input yields an empty vector, which the caller wraps in
/// quotes to produce e.g. `realm=""`. The returned bytes do **not** include the
/// surrounding quotes.
fn auth_digest_string_quoted(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for &c in s {
        if c == b'"' || c == b'\\' {
            out.push(b'\\');
        }
        out.push(c);
    }
    out
}

/// Append a quoted field `name="value"` to `out`. `value` is emitted verbatim
/// between the quotes (the caller has already escaped it where required).
fn push_quoted_field(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.extend_from_slice(name);
    out.extend_from_slice(b"=\"");
    out.extend_from_slice(value);
    out.push(b'"');
}

/// Append a raw (unquoted) field `name=value` to `out`.
fn push_raw_field(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.extend_from_slice(name);
    out.push(b'=');
    out.extend_from_slice(value);
}

/// Generate an HTTP Digest response value — everything that follows `Digest ` in
/// the `Authorization` / `Proxy-Authorization` header — reproducing curl's
/// `Curl_auth_create_digest_http_message` (via `auth_create_digest_http_message`)
/// **byte-for-byte**.
///
/// The hashing math (RFC 7616 / RFC 2617):
///
/// * `HA1 = H(user ":" realm ":" passwd)`; for a session algorithm (`*-sess`)
///   `HA1 = H(HA1 ":" nonce ":" cnonce)`.
/// * `HA2 = H(request ":" uripath)`; for `qop=auth-int` an empty-entity hash is
///   appended: `HA2 = H(request ":" uripath ":" H(""))`.
/// * `response = H(HA1 ":" nonce ":" nc ":" cnonce ":" qop ":" HA2)` when a `qop`
///   is in effect, otherwise `response = H(HA1 ":" nonce ":" HA2)`.
///
/// The serialization is parity-critical. With a `qop` the fields are, in order
/// and separated by `", "` (comma **and** space):
///
/// ```text
/// username="…", realm="…", nonce="…", uri="…", cnonce="…", nc=XXXXXXXX, qop=…, response="…"
/// ```
///
/// Without a `qop` the `cnonce`, `nc` and `qop` fields are omitted. Then, in this
/// exact order, the optional fields are appended (each prefixed by `", "`):
/// `opaque="…"` (quoted), `algorithm=…` (raw), `userhash=true`.
///
/// `username`, `realm`, `nonce`, `uri` and `opaque` are quoted-string–escaped;
/// `cnonce`, `nc` (`%08x`), `qop`, `response` and `algorithm` are emitted raw.
/// When a `qop` is present the handle's nonce-count is incremented for the next
/// request, exactly as curl does.
///
/// The client nonce is generated on first use (12 OS-random bytes, base64) and
/// stored on `digest`; a pre-set [`DigestData::cnonce`] is reused unchanged,
/// which is how deterministic tests fix the value.
///
/// # Errors
///
/// * [`CurlError::NotBuiltIn`] — the SHA-512/256 algorithm is requested while
///   unsupported; never returned in this build, where [`HAVE_SHA512_256`] is
///   `true` (see [`HAVE_SHA512_256`]).
/// * [`CurlError::TooLarge`] — the assembled header exceeds curl's 4096-byte cap.
/// * [`CurlError::BadFunctionArgument`] — no `nonce` is present (the challenge
///   must be decoded first via [`decode_digest_http_message`]).
/// * Any error propagated from random-byte or base64 generation of the cnonce.
pub fn create_digest_http_message(
    digest: &mut DigestData,
    user: &[u8],
    passwd: &[u8],
    request: &[u8],
    uripath: &[u8],
) -> Result<Vec<u8>> {
    // nc defaults to 1 (C: `if(!digest->nc) digest->nc = 1;`).
    if digest.nc == 0 {
        digest.nc = 1;
    }

    // Generate the client nonce on first use: 12 OS-random bytes, base64-encoded
    // (C: Curl_rand_bytes + curlx_base64_encode). A pre-set cnonce is kept as-is,
    // which is how deterministic tests fix the value. `rand_bytes` honors the
    // `CURL_ENTROPY` debug hook for reproducibility.
    if digest.cnonce.is_none() {
        let mut cnoncebuf = [0u8; 12];
        rand_bytes(&mut cnoncebuf)?;
        let encoded = base64_encode(&cnoncebuf)?;
        // base64 output is pure ASCII, so this conversion is exact (never lossy).
        digest.cnonce = Some(bytes_to_string(&encoded));
    }

    // Snapshot the fields we read as owned values so that incrementing
    // `digest.nc` below cannot conflict with outstanding borrows. `realm`
    // defaults to "" when absent (C: `digest->realm ? digest->realm : ""`),
    // which is used both in the hashes and in the emitted `realm=""` field.
    let algo = digest.algo;
    let realm = digest.realm.clone().unwrap_or_default();
    let nonce = digest.nonce.clone().ok_or(CurlError::BadFunctionArgument)?;
    let cnonce = digest
        .cnonce
        .clone()
        .ok_or(CurlError::BadFunctionArgument)?;
    let qop = digest.qop.clone();
    let algorithm = digest.algorithm.clone();
    let opaque = digest.opaque.clone();
    let userhash = digest.userhash;
    let nc = digest.nc;

    // userhash: userh = H(user ":" realm) in ASCII hex, used in place of the
    // username (RFC 7616 §3.4.4).
    let user_field: Vec<u8> = if userhash {
        let mut h = Vec::with_capacity(user.len() + 1 + realm.len());
        h.extend_from_slice(user);
        h.push(b':');
        h.extend_from_slice(realm.as_bytes());
        digest_hash(algo, &h)?
    } else {
        user.to_vec()
    };

    // HA1 = H(user ":" realm ":" passwd); for *-sess fold in nonce + cnonce.
    let mut ha1 = {
        let mut h = Vec::with_capacity(user.len() + realm.len() + passwd.len() + 2);
        h.extend_from_slice(user);
        h.push(b':');
        h.extend_from_slice(realm.as_bytes());
        h.push(b':');
        h.extend_from_slice(passwd);
        digest_hash(algo, &h)?
    };
    if algo.is_session() {
        // nonce and cnonce are OUTSIDE the inner hash.
        let mut h = Vec::with_capacity(ha1.len() + nonce.len() + cnonce.len() + 2);
        h.extend_from_slice(&ha1);
        h.push(b':');
        h.extend_from_slice(nonce.as_bytes());
        h.push(b':');
        h.extend_from_slice(cnonce.as_bytes());
        ha1 = digest_hash(algo, &h)?;
    }

    // HA2 = H(request ":" uripath [":" H("")]); the trailing empty-entity hash
    // is appended only for qop=auth-int.
    let ha2 = {
        let mut h = Vec::with_capacity(request.len() + uripath.len() + 1);
        h.extend_from_slice(request);
        h.push(b':');
        h.extend_from_slice(uripath);
        if qop.as_deref() == Some(DIGEST_QOP_VALUE_STRING_AUTH_INT) {
            // We do not support auth-int for PUT or POST: hash an empty body.
            let entity = digest_hash(algo, b"")?;
            h.push(b':');
            h.extend_from_slice(&entity);
        }
        digest_hash(algo, &h)?
    };

    // response: with qop  H(HA1:nonce:nc:cnonce:qop:HA2)
    //           without   H(HA1:nonce:HA2).
    let nc_hex = format!("{nc:08x}");
    let request_digest = if let Some(qop) = qop.as_deref() {
        let mut h = Vec::new();
        h.extend_from_slice(&ha1);
        h.push(b':');
        h.extend_from_slice(nonce.as_bytes());
        h.push(b':');
        h.extend_from_slice(nc_hex.as_bytes());
        h.push(b':');
        h.extend_from_slice(cnonce.as_bytes());
        h.push(b':');
        h.extend_from_slice(qop.as_bytes());
        h.push(b':');
        h.extend_from_slice(&ha2);
        digest_hash(algo, &h)?
    } else {
        let mut h = Vec::new();
        h.extend_from_slice(&ha1);
        h.push(b':');
        h.extend_from_slice(nonce.as_bytes());
        h.push(b':');
        h.extend_from_slice(&ha2);
        digest_hash(algo, &h)?
    };

    // Assemble the header value with byte-exact field order, `", "` separators
    // and quoting. Quoted: username, realm, nonce, uri, opaque. Raw: cnonce, nc,
    // qop, response, algorithm.
    let userp_quoted = auth_digest_string_quoted(&user_field);
    let realm_quoted = auth_digest_string_quoted(realm.as_bytes());
    let nonce_quoted = auth_digest_string_quoted(nonce.as_bytes());
    let uri_quoted = auth_digest_string_quoted(uripath);

    let mut out: Vec<u8> = Vec::new();
    push_quoted_field(&mut out, b"username", &userp_quoted);
    out.extend_from_slice(b", ");
    push_quoted_field(&mut out, b"realm", &realm_quoted);
    out.extend_from_slice(b", ");
    push_quoted_field(&mut out, b"nonce", &nonce_quoted);
    out.extend_from_slice(b", ");
    push_quoted_field(&mut out, b"uri", &uri_quoted);

    if let Some(qop) = qop.as_deref() {
        out.extend_from_slice(b", ");
        push_quoted_field(&mut out, b"cnonce", cnonce.as_bytes());
        out.extend_from_slice(b", ");
        push_raw_field(&mut out, b"nc", nc_hex.as_bytes());
        out.extend_from_slice(b", ");
        push_raw_field(&mut out, b"qop", qop.as_bytes());
        out.extend_from_slice(b", ");
        push_quoted_field(&mut out, b"response", &request_digest);

        // Increment the nonce-count to use a fresh nc for the next request.
        digest.nc = digest.nc.wrapping_add(1);
    } else {
        out.extend_from_slice(b", ");
        push_quoted_field(&mut out, b"response", &request_digest);
    }

    // Optional fields, in curl's exact order.
    if let Some(opaque) = opaque.as_deref() {
        out.extend_from_slice(b", ");
        let opaque_quoted = auth_digest_string_quoted(opaque.as_bytes());
        push_quoted_field(&mut out, b"opaque", &opaque_quoted);
    }
    if let Some(algorithm) = algorithm.as_deref() {
        out.extend_from_slice(b", ");
        push_raw_field(&mut out, b"algorithm", algorithm.as_bytes());
    }
    if userhash {
        out.extend_from_slice(b", userhash=true");
    }

    // Final assembly through DynBuf to enforce curl's 4096-byte response cap
    // (C: `curlx_dyn_init(&response, 4096)`); over-long output → CURLE_TOO_LARGE.
    let mut response = DynBuf::new(4096);
    response.curlx_dyn_addn(&out)?;
    Ok(response.curlx_dyn_take())
}

// ===========================================================================
// Phase G — SASL DIGEST-MD5 (curl `Curl_auth_create_digest_md5_message`)
// ===========================================================================
//
// The SASL `DIGEST-MD5` wire format (RFC 2831) DIFFERS from HTTP Digest: the
// fields are joined with bare commas (NO space), the `response` is emitted
// UNQUOTED, and the username is emitted RAW (not quoted-string–escaped). It also
// uses a different challenge parser (`auth_digest_get_key_value`) and a binary
// (raw-bytes) inner MD5 in HA1. These two formatters must never be merged.

/// Build a SASL/GSSAPI service principal name, mirroring curl's generic
/// (non-SSPI) `Curl_auth_build_spn` (`lib/vauth/vauth.c`):
///
/// * `service/host@realm` when both `host` and `realm` are given,
/// * `service/host` with a host only,
/// * `service@realm` with a realm only,
/// * `None` when neither is given.
///
/// `crate::auth::build_spn` is pipeline-pending and is not a dependency of this
/// file, so the generic helper is reproduced locally. SASL `DIGEST-MD5` calls it
/// as `build_spn(service, Some(host), None)`, yielding `service/host` — the
/// RFC 2831 `digest-uri`.
fn build_spn(service: &[u8], host: Option<&[u8]>, realm: Option<&[u8]>) -> Option<Vec<u8>> {
    let mut spn = Vec::new();
    match (host, realm) {
        (Some(h), Some(r)) => {
            spn.extend_from_slice(service);
            spn.push(b'/');
            spn.extend_from_slice(h);
            spn.push(b'@');
            spn.extend_from_slice(r);
        }
        (Some(h), None) => {
            spn.extend_from_slice(service);
            spn.push(b'/');
            spn.extend_from_slice(h);
        }
        (None, Some(r)) => {
            spn.extend_from_slice(service);
            spn.push(b'@');
            spn.extend_from_slice(r);
        }
        (None, None) => return None,
    }
    Some(spn)
}

/// Retrieve the (de-escaped) value for `key` from a SASL `DIGEST-MD5` challenge,
/// reproducing curl's `auth_digest_get_key_value`.
///
/// The challenge is `keyword=[value],keyword2=[value]`, where values may be
/// quoted or not. For each pair the key is read up to `=` (max 64), the value is
/// read as a quoted word (max 256) or, failing the opening quote, up to the next
/// comma. A pair whose key matches `key` (case-**sensitive**, like curl's
/// `curlx_str_cmp`) has its value de-escaped (a `\` before another byte is
/// dropped) and returned. `buflen` mirrors curl's fixed destination buffer: a
/// raw value of length `>= buflen` yields [`None`] (does not fit).
///
/// Returns [`None`] if the key is absent, if a value does not fit, or on the
/// "weird"/"odd syntax" parse failures curl reports as `FALSE`.
fn sasl_digest_get_key_value(chlg: &[u8], key: &str, buflen: usize) -> Option<Vec<u8>> {
    let mut cur = Str::from_bytes(chlg);

    loop {
        let mut name = Str::default();
        let mut data = Str::default();

        cur.curlx_str_passblanks();

        // Read `name=` — both the name (up to '=') and the '=' must be present.
        if cur.curlx_str_until(&mut name, 64, b'=').is_ok() && cur.curlx_str_single(b'=').is_ok() {
            // Read the value: a quoted word, or (no opening quote) up to a comma.
            let mut rc = cur.curlx_str_quotedword(&mut data, 256);
            if matches!(rc, Err(StrError::BegQuote)) {
                rc = cur.curlx_str_until(&mut data, 256, b',');
            }
            if rc.is_err() {
                return None; // weird
            }

            if curlx_str_cmp(&name, key) {
                let src = data.curlx_str();
                let len = src.len();
                // C: `if(len >= buflen) return FALSE;` — does not fit.
                if len >= buflen {
                    return None;
                }
                // De-escape: a backslash before another byte is dropped.
                let mut out = Vec::with_capacity(len);
                let mut i = 0;
                while i < len {
                    if src[i] == b'\\' && i + 1 < len {
                        i += 1; // skip backslash
                    }
                    out.push(src[i]);
                    i += 1;
                }
                return Some(out);
            }

            // Not our key: a comma must separate it from the next pair.
            if cur.curlx_str_single(b',').is_err() {
                return None;
            }
        } else {
            break; // odd syntax
        }
    }

    None
}

/// Parse a SASL `qop-options` string into the [`DIGEST_QOP_VALUE_AUTH`] /
/// [`DIGEST_QOP_VALUE_AUTH_INT`] / [`DIGEST_QOP_VALUE_AUTH_CONF`] bit set,
/// reproducing curl's `auth_digest_get_qop_values`.
///
/// Tokens are split strictly on commas (each capped at 32 bytes) with **no**
/// blank-skipping (unlike the HTTP [`select_qop`] path); unrecognized tokens are
/// ignored.
fn sasl_qop_values(options: &[u8]) -> u8 {
    let mut cur = Str::from_bytes(options);
    let mut value = 0u8;
    let mut out = Str::default();

    while cur.curlx_str_until(&mut out, 32, b',').is_ok() {
        if curlx_str_casecompare(&out, DIGEST_QOP_VALUE_STRING_AUTH) {
            value |= DIGEST_QOP_VALUE_AUTH;
        } else if curlx_str_casecompare(&out, DIGEST_QOP_VALUE_STRING_AUTH_INT) {
            value |= DIGEST_QOP_VALUE_AUTH_INT;
        } else if curlx_str_casecompare(&out, DIGEST_QOP_VALUE_STRING_AUTH_CONF) {
            value |= DIGEST_QOP_VALUE_AUTH_CONF;
        }
        if cur.curlx_str_single(b',').is_err() {
            break;
        }
    }

    value
}

/// The decoded fields of a SASL `DIGEST-MD5` challenge, in order:
/// `(nonce, realm, algorithm, qop-options)`. A named alias keeps the decoder's
/// signature readable (and satisfies `clippy::type_complexity`).
type Md5ChallengeFields = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Decode a SASL `DIGEST-MD5` challenge into `(nonce, realm, algorithm, qop)`,
/// reproducing curl's `auth_decode_digest_md5_message`.
///
/// The `nonce`, `algorithm` and `qop` keys are required; a missing `realm`
/// yields an empty realm (RFC 2831). The buffer caps mirror curl's fixed
/// buffers: `nonce` 64, `realm` 128, `algorithm` 64, `qop` 64.
///
/// # Errors
///
/// Returns [`CurlError::BadContentEncoding`] for an empty challenge or a missing
/// required key (or a value that does not fit its buffer).
fn auth_decode_digest_md5_message(chlg: &[u8]) -> Result<Md5ChallengeFields> {
    // Ensure we have a valid (non-empty) challenge message.
    if chlg.is_empty() {
        return Err(CurlError::BadContentEncoding);
    }

    let nonce =
        sasl_digest_get_key_value(chlg, "nonce", 64).ok_or(CurlError::BadContentEncoding)?;
    // A missing realm is allowed and becomes the empty string (RFC 2831 p.6).
    let realm = sasl_digest_get_key_value(chlg, "realm", 128).unwrap_or_default();
    let algorithm =
        sasl_digest_get_key_value(chlg, "algorithm", 64).ok_or(CurlError::BadContentEncoding)?;
    let qop = sasl_digest_get_key_value(chlg, "qop", 64).ok_or(CurlError::BadContentEncoding)?;

    Ok((nonce, realm, algorithm, qop))
}

/// Generate a SASL `DIGEST-MD5` response message (RFC 2831) ready for sending,
/// reproducing curl's `Curl_auth_create_digest_md5_message` **byte-for-byte**.
///
/// `challenge` is the decoded server challenge; `user`/`passwd` are the
/// credentials; `service` (e.g. `imap`, `smtp`) and `host` form the
/// `digest-uri` SPN as `service/host`.
///
/// Only the `md5-sess` algorithm and the `auth` quality-of-protection are
/// supported, matching curl. The client nonce is 32 random lowercase-hex
/// characters (honoring the `CURL_ENTROPY` debug hook for reproducibility).
///
/// # Errors
///
/// * [`CurlError::BadContentEncoding`] — malformed challenge, an algorithm other
///   than `md5-sess`, or a `qop` lacking `auth`.
/// * Any error propagated from random cnonce generation.
pub fn create_digest_md5_message(
    challenge: &[u8],
    user: &[u8],
    passwd: &[u8],
    service: &[u8],
    host: &[u8],
) -> Result<Vec<u8>> {
    // Generate 32 random hex chars (a 33-byte buffer incl. the NUL, like curl's
    // `char cnonce[33]`); `rand_hex` honors the CURL_ENTROPY debug hook.
    let mut cnoncebuf = [0u8; 33];
    rand_hex(&mut cnoncebuf, 33)?;
    create_digest_md5_message_with_cnonce(challenge, user, passwd, service, host, &cnoncebuf[..32])
}

/// SASL `DIGEST-MD5` response generation with a caller-supplied `cnonce`.
///
/// This is the deterministic core of [`create_digest_md5_message`]; the public
/// wrapper only generates the random `cnonce`. Tests pass a fixed `cnonce` here
/// to reproduce a known-answer response byte-for-byte.
fn create_digest_md5_message_with_cnonce(
    challenge: &[u8],
    user: &[u8],
    passwd: &[u8],
    service: &[u8],
    host: &[u8],
    cnonce: &[u8],
) -> Result<Vec<u8>> {
    // Decode the challenge message.
    let (nonce, realm, algorithm, qop_options) = auth_decode_digest_md5_message(challenge)?;

    // We only support md5 sessions (C uses a case-sensitive `strcmp`).
    if algorithm.as_slice() != b"md5-sess" {
        return Err(CurlError::BadContentEncoding);
    }

    // We only support the "auth" quality-of-protection.
    let qop_values = sasl_qop_values(&qop_options);
    if qop_values & DIGEST_QOP_VALUE_AUTH == 0 {
        return Err(CurlError::BadContentEncoding);
    }

    // HA1 (RFC 2831): first MD5(user ":" realm ":" passwd) as RAW 16 bytes, then
    // MD5(those 16 raw bytes ":" nonce ":" cnonce), rendered as 32 hex chars.
    let mut a1 = Vec::with_capacity(user.len() + realm.len() + passwd.len() + 2);
    a1.extend_from_slice(user);
    a1.push(b':');
    a1.extend_from_slice(&realm);
    a1.push(b':');
    a1.extend_from_slice(passwd);
    let inner = md5it(&a1); // 16 RAW bytes — fed into the next hash verbatim

    let mut a1b = Vec::with_capacity(inner.len() + nonce.len() + cnonce.len() + 2);
    a1b.extend_from_slice(&inner);
    a1b.push(b':');
    a1b.extend_from_slice(&nonce);
    a1b.push(b':');
    a1b.extend_from_slice(cnonce);
    let ha1_hex = md5_to_ascii(&md5it(&a1b)); // 32 hex chars

    // SPN / digest-uri = service/host.
    let spn = build_spn(service, Some(host), None).ok_or(CurlError::OutOfMemory)?;

    // HA2 = MD5("AUTHENTICATE" ":" spn) → 32 hex chars.
    let mut a2 = Vec::with_capacity(SASL_DIGEST_METHOD.len() + spn.len() + 1);
    a2.extend_from_slice(SASL_DIGEST_METHOD);
    a2.push(b':');
    a2.extend_from_slice(&spn);
    let ha2_hex = md5_to_ascii(&md5it(&a2));

    // response = MD5(HA1 ":" nonce ":" nc ":" cnonce ":" qop ":" HA2) → 32 hex.
    let mut resp = Vec::new();
    resp.extend_from_slice(&ha1_hex);
    resp.push(b':');
    resp.extend_from_slice(&nonce);
    resp.push(b':');
    resp.extend_from_slice(SASL_DIGEST_NONCE_COUNT);
    resp.push(b':');
    resp.extend_from_slice(cnonce);
    resp.push(b':');
    resp.extend_from_slice(DIGEST_QOP_VALUE_STRING_AUTH.as_bytes());
    resp.push(b':');
    resp.extend_from_slice(&ha2_hex);
    let resp_hash_hex = md5_to_ascii(&md5it(&resp));

    // Assemble the response. NOTE the SASL format: bare commas (NO spaces),
    // the `response` value is UNQUOTED, and the username is emitted RAW (only
    // `realm` and `nonce` are quoted-string–escaped).
    let qrealm = auth_digest_string_quoted(&realm);
    let qnonce = auth_digest_string_quoted(&nonce);

    let mut out = Vec::new();
    out.extend_from_slice(b"username=\"");
    out.extend_from_slice(user);
    out.extend_from_slice(b"\",realm=\"");
    out.extend_from_slice(&qrealm);
    out.extend_from_slice(b"\",nonce=\"");
    out.extend_from_slice(&qnonce);
    out.extend_from_slice(b"\",cnonce=\"");
    out.extend_from_slice(cnonce);
    out.extend_from_slice(b"\",nc=\"");
    out.extend_from_slice(SASL_DIGEST_NONCE_COUNT);
    out.extend_from_slice(b"\",digest-uri=\"");
    out.extend_from_slice(&spn);
    out.extend_from_slice(b"\",response=");
    out.extend_from_slice(&resp_hash_hex);
    out.extend_from_slice(b",qop=");
    out.extend_from_slice(DIGEST_QOP_VALUE_STRING_AUTH.as_bytes());

    Ok(out)
}

// ===========================================================================
// Phase H — HTTP glue (curl `lib/http_digest.c`)
// ===========================================================================

/// The result of [`output_digest`]: the header line to send (if a challenge was
/// available) and the authentication `done` flag for the caller's auth state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestOutput {
    /// The full `"[Proxy-]Authorization: Digest …\r\n"` header line, or [`None`]
    /// when there is no challenge yet (the caller should await the 401/407).
    pub header: Option<String>,
    /// Whether authentication is complete for this phase (curl's `authp->done`).
    /// `false` while awaiting the challenge; `true` once a response was emitted.
    pub done: bool,
}

/// Case-insensitive `Digest` scheme-token prefix check — curl's
/// `checkprefix("Digest", header)`.
fn checkprefix_digest(header: &[u8]) -> bool {
    header.len() >= 6 && strcasecompare(&header[..6], b"Digest")
}

/// Feed an HTTP `WWW-Authenticate` / `Proxy-Authenticate` Digest challenge into
/// `digest`, reproducing curl's `Curl_input_digest`.
///
/// `header` is the value following `WWW-Authenticate:` (or `Proxy-Authenticate:`)
/// — it must begin with the `Digest` scheme token (case-insensitive) followed by
/// an ASCII blank. The scheme token and surrounding blanks are stripped and the
/// remainder is decoded via [`decode_digest_http_message`]. The caller selects
/// the host or proxy [`DigestData`].
///
/// # Errors
///
/// Returns [`CurlError::BadContentEncoding`] if the `Digest` prefix or its
/// trailing blank is missing, or as propagated from the challenge decode.
pub fn input_digest(digest: &mut DigestData, header: &[u8]) -> Result<()> {
    // Require "Digest" followed by a blank (C: `!checkprefix(...) ||
    // !ISBLANK(header[6])`). The length guard replaces C's reliance on the
    // NUL terminator at `header[6]`.
    if !checkprefix_digest(header) || header.len() <= 6 || !is_blank(header[6]) {
        return Err(CurlError::BadContentEncoding);
    }

    // Skip "Digest" and any following blanks, then decode.
    let rest = skip_blanks(&header[6..]);
    decode_digest_http_message(rest, digest)
}

/// Produce an HTTP Digest `Authorization` header line, reproducing curl's
/// `Curl_output_digest`.
///
/// If no challenge has been received yet (`digest.nonce` is `None`), this returns
/// `done = false` with no header — the caller should wait for the server's 401
/// (or 407) challenge. Otherwise the Digest response is generated and wrapped as
/// `"[Proxy-]Authorization: Digest <response>\r\n"` (`Proxy-` when `proxy` is
/// set) and `done = true`.
///
/// When `iestyle` is set (curl's `CURLAUTH_DIGEST_IE`), the URI is truncated at
/// the first `?` before hashing — IE < v7 computed the Digest over the path
/// without the query, and some servers expect that. `request` is the HTTP method
/// and `uripath` the request target; empty `user`/`passwd` are valid.
///
/// # Errors
///
/// Propagates any error from [`create_digest_http_message`] (e.g.
/// [`CurlError::NotBuiltIn`], [`CurlError::TooLarge`]).
pub fn output_digest(
    digest: &mut DigestData,
    proxy: bool,
    iestyle: bool,
    request: &[u8],
    uripath: &[u8],
    user: &[u8],
    passwd: &[u8],
) -> Result<DigestOutput> {
    // Without a challenge we cannot answer yet: not done, await the 401/407.
    let have_chlg = digest.nonce.is_some();
    if !have_chlg {
        return Ok(DigestOutput {
            header: None,
            done: false,
        });
    }

    // IE-style: cut the URI at the query separator '?' (different MD5 input).
    let path: Vec<u8> = if iestyle {
        match uripath.iter().position(|&b| b == b'?') {
            Some(pos) => uripath[..pos].to_vec(),
            None => uripath.to_vec(),
        }
    } else {
        uripath.to_vec()
    };

    let response = create_digest_http_message(digest, user, passwd, request, &path)?;

    // "%sAuthorization: Digest %s\r\n", with the "Proxy-" prefix for proxies.
    let mut header = Vec::new();
    if proxy {
        header.extend_from_slice(b"Proxy-");
    }
    header.extend_from_slice(b"Authorization: Digest ");
    header.extend_from_slice(&response);
    header.extend_from_slice(b"\r\n");

    Ok(DigestOutput {
        header: Some(bytes_to_string(&header)),
        done: true,
    })
}

// ===========================================================================
// Tests (Phase I) — byte-exact parity against curl's known-answer vectors.
//
// Determinism: the client nonce (cnonce) is the only nondeterministic input.
// These tests fix it directly — pre-setting `DigestData::cnonce` for HTTP Digest
// (curl skips generation when it is already set) and passing a fixed cnonce to
// the SASL `_with_cnonce` core — which is the curl-faithful way to reproduce a
// known-answer header without depending on the process-global `CURL_ENTROPY`
// counter.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    // RFC 2617 §3.5 base parameters, shared by the HTTP Digest vectors.
    const USER: &[u8] = b"Mufasa";
    const PASSWD: &[u8] = b"Circle Of Life";
    const REALM: &str = "testrealm@host.com";
    const NONCE: &str = "dcd98b7102dd2f0e8b11d0f600bfb0c093";
    const CNONCE: &str = "0a4f113b";
    const REQUEST: &[u8] = b"GET";
    const URI: &[u8] = b"/dir/index.html";

    /// A `DigestData` pre-loaded with the RFC 2617 challenge and a fixed cnonce.
    fn base_http() -> DigestData {
        let mut d = DigestData::new();
        d.nonce = Some(NONCE.to_string());
        d.cnonce = Some(CNONCE.to_string());
        d.realm = Some(REALM.to_string());
        d.qop = Some("auth".to_string());
        d.algo = Algorithm::Md5;
        d.nc = 1;
        d
    }

    fn http(d: &mut DigestData) -> String {
        let out = create_digest_http_message(d, USER, PASSWD, REQUEST, URI).expect("http message");
        String::from_utf8(out).expect("utf8")
    }

    #[test]
    fn md5_qop_auth_byte_exact() {
        let mut d = base_http();
        let got = http(&mut d);
        assert_eq!(
            got,
            "username=\"Mufasa\", realm=\"testrealm@host.com\", \
nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", \
cnonce=\"0a4f113b\", nc=00000001, qop=auth, \
response=\"6629fae49393a05397450978507c4ef1\""
        );
        assert_eq!(d.nc, 2, "nc incremented after a qop response");
    }

    #[test]
    fn md5_no_qop_byte_exact() {
        let mut d = base_http();
        d.qop = None;
        let got = http(&mut d);
        assert_eq!(
            got,
            "username=\"Mufasa\", realm=\"testrealm@host.com\", \
nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", \
response=\"670fd8c2df070c60b045671b8b24ff02\""
        );
        assert_eq!(d.nc, 1, "nc NOT incremented without qop");
    }

    #[test]
    fn md5_auth_int_byte_exact() {
        let mut d = base_http();
        d.qop = Some("auth-int".to_string());
        let got = http(&mut d);
        assert_eq!(
            got,
            "username=\"Mufasa\", realm=\"testrealm@host.com\", \
nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", \
cnonce=\"0a4f113b\", nc=00000001, qop=auth-int, \
response=\"5e6610ecf9ba3017a4870ad48e3ad30b\""
        );
    }

    #[test]
    fn md5_sess_byte_exact() {
        let mut d = base_http();
        d.algo = Algorithm::Md5Sess;
        let got = http(&mut d);
        assert_eq!(
            got,
            "username=\"Mufasa\", realm=\"testrealm@host.com\", \
nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", \
cnonce=\"0a4f113b\", nc=00000001, qop=auth, \
response=\"8e3825c57e897f5a0dec6c2d4e5059d0\""
        );
    }

    #[test]
    fn sha256_qop_auth_byte_exact() {
        let mut d = base_http();
        d.algo = Algorithm::Sha256;
        let got = http(&mut d);
        assert_eq!(
            got,
            "username=\"Mufasa\", realm=\"testrealm@host.com\", \
nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", \
cnonce=\"0a4f113b\", nc=00000001, qop=auth, \
response=\"5abdd07184ba512a22c53f41470e5eea7dcaa3a93a59b630c13dfe0a5dc6e38b\""
        );
    }

    #[test]
    fn optional_fields_opaque_then_algorithm_order() {
        // opaque (quoted) must precede algorithm (raw), both after response.
        let mut d = base_http();
        d.opaque = Some("5ccc069c403ebaf9f0171e9517f40e41".to_string());
        d.algorithm = Some("MD5".to_string());
        let got = http(&mut d);
        assert_eq!(
            got,
            "username=\"Mufasa\", realm=\"testrealm@host.com\", \
nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", \
cnonce=\"0a4f113b\", nc=00000001, qop=auth, \
response=\"6629fae49393a05397450978507c4ef1\", \
opaque=\"5ccc069c403ebaf9f0171e9517f40e41\", algorithm=MD5"
        );
    }

    #[test]
    fn userhash_replaces_username_and_appends_flag() {
        // userhash hashes the username field (H(user:realm)) but does NOT change
        // the response hash; `userhash=true` is appended last.
        let mut d = base_http();
        d.userhash = true;
        let got = http(&mut d);
        assert_eq!(
            got,
            "username=\"74f54fe2c8045a5ffda7d02fd97f1716\", realm=\"testrealm@host.com\", \
nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", \
cnonce=\"0a4f113b\", nc=00000001, qop=auth, \
response=\"6629fae49393a05397450978507c4ef1\", userhash=true"
        );
    }

    #[test]
    fn empty_realm_emits_empty_quotes() {
        let mut d = base_http();
        d.realm = None;
        let got = http(&mut d);
        assert!(
            got.contains("realm=\"\", "),
            "empty realm → realm=\"\": {got}"
        );
    }

    #[test]
    fn string_quoted_escapes_quote_and_backslash() {
        assert_eq!(auth_digest_string_quoted(b""), b"");
        assert_eq!(auth_digest_string_quoted(b"plain"), b"plain");
        // a"b\c  →  a\"b\\c
        assert_eq!(auth_digest_string_quoted(b"a\"b\\c"), b"a\\\"b\\\\c");
    }

    #[test]
    fn sasl_digest_md5_byte_exact() {
        // RFC 2831 §4 known-answer vector (fixed cnonce via the private core).
        let challenge =
            b"realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",qop=\"auth\",algorithm=md5-sess";
        let out = create_digest_md5_message_with_cnonce(
            challenge,
            b"chris",
            b"secret",
            b"imap",
            b"elwood.innosoft.com",
            b"OA6MHXh6VqTrRk",
        )
        .expect("sasl message");
        let got = String::from_utf8(out).unwrap();
        assert_eq!(
            got,
            "username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",\
cnonce=\"OA6MHXh6VqTrRk\",nc=\"00000001\",digest-uri=\"imap/elwood.innosoft.com\",\
response=d388dad90d4bbd760a152321f2143af7,qop=auth"
        );
    }

    #[test]
    fn sasl_rejects_non_md5_sess_algorithm() {
        let challenge = b"realm=\"r\",nonce=\"n\",qop=\"auth\",algorithm=md5";
        let err = create_digest_md5_message_with_cnonce(
            challenge,
            b"u",
            b"p",
            b"imap",
            b"host",
            b"deadbeefdeadbeefdeadbeefdeadbeef",
        )
        .unwrap_err();
        assert_eq!(err, CurlError::BadContentEncoding);
    }

    #[test]
    fn sasl_requires_auth_qop() {
        let challenge = b"realm=\"r\",nonce=\"n\",qop=\"auth-int\",algorithm=md5-sess";
        let err = create_digest_md5_message_with_cnonce(
            challenge,
            b"u",
            b"p",
            b"imap",
            b"host",
            b"deadbeefdeadbeefdeadbeefdeadbeef",
        )
        .unwrap_err();
        assert_eq!(err, CurlError::BadContentEncoding);
    }

    #[test]
    fn sha512_256_is_accepted_and_selected() {
        // HAVE_SHA512_256 is true (crate::util::sha256::sha512_256it is wired), so
        // decoding a SHA-512-256 challenge succeeds and selects the algorithm,
        // exactly like a curl build with CURL_HAVE_SHA512_256.
        let mut d = DigestData::new();
        decode_digest_http_message(
            b"realm=\"r\", nonce=\"n\", qop=\"auth\", algorithm=SHA-512-256",
            &mut d,
        )
        .unwrap();
        assert_eq!(d.algo, Algorithm::Sha512_256);

        let mut d2 = DigestData::new();
        decode_digest_http_message(
            b"realm=\"r\", nonce=\"n\", qop=\"auth\", algorithm=SHA-512-256-SESS",
            &mut d2,
        )
        .unwrap();
        assert_eq!(d2.algo, Algorithm::Sha512_256Sess);
    }

    #[test]
    fn decode_populates_fields() {
        let mut d = DigestData::new();
        decode_digest_http_message(
            b"realm=\"testrealm\", nonce=\"abc123\", qop=\"auth,auth-int\", \
opaque=\"op\", algorithm=MD5-sess, userhash=true",
            &mut d,
        )
        .unwrap();
        assert_eq!(d.realm.as_deref(), Some("testrealm"));
        assert_eq!(d.nonce.as_deref(), Some("abc123"));
        assert_eq!(d.qop.as_deref(), Some("auth")); // auth preferred over auth-int
        assert_eq!(d.opaque.as_deref(), Some("op"));
        assert_eq!(d.algo, Algorithm::Md5Sess);
        assert!(d.userhash);
    }

    #[test]
    fn decode_stale_sets_flag_and_nc() {
        let mut d = DigestData::new();
        decode_digest_http_message(b"realm=\"r\", nonce=\"n\", stale=true", &mut d).unwrap();
        assert!(d.stale);
        assert_eq!(d.nc, 1);
    }

    #[test]
    fn decode_repeat_nonce_without_stale_fails() {
        let mut d = DigestData::new();
        decode_digest_http_message(b"realm=\"r\", nonce=\"n1\"", &mut d).unwrap();
        // A second challenge with a nonce but no stale=true → bad credentials.
        let err = decode_digest_http_message(b"realm=\"r\", nonce=\"n2\"", &mut d).unwrap_err();
        assert_eq!(err, CurlError::BadContentEncoding);
    }

    #[test]
    fn decode_missing_nonce_fails() {
        let mut d = DigestData::new();
        let err = decode_digest_http_message(b"realm=\"r\", qop=\"auth\"", &mut d).unwrap_err();
        assert_eq!(err, CurlError::BadContentEncoding);
    }

    #[test]
    fn decode_session_without_qop_fails() {
        let mut d = DigestData::new();
        let err =
            decode_digest_http_message(b"realm=\"r\", nonce=\"n\", algorithm=MD5-sess", &mut d)
                .unwrap_err();
        assert_eq!(err, CurlError::BadContentEncoding);
    }

    #[test]
    fn pair_parser_quoted_unquoted_and_escapes() {
        let p = digest_get_pair(b"realm=\"test\"").unwrap();
        assert_eq!(p.key, b"realm");
        assert_eq!(p.content, b"test");
        assert_eq!(p.consumed, 12);

        // Unquoted, comma-terminated (comma is consumed).
        let p = digest_get_pair(b"nc=00000001,rest").unwrap();
        assert_eq!(p.key, b"nc");
        assert_eq!(p.content, b"00000001");
        assert_eq!(&b"nc=00000001,rest"[p.consumed..], b"rest");

        // Backslash escapes inside quotes are de-escaped.
        let p = digest_get_pair(b"k=\"a\\\"b\"").unwrap();
        assert_eq!(p.content, b"a\"b");

        // An unclosed quote (newline before closing) fails.
        assert!(digest_get_pair(b"k=\"abc\r\n").is_none());
        // A missing '=' fails.
        assert!(digest_get_pair(b"noequals").is_none());
    }

    #[test]
    fn input_digest_prefix_handling() {
        // Valid: case-insensitive "Digest" + blank, then decodes.
        let mut d = DigestData::new();
        input_digest(&mut d, b"Digest realm=\"r\", nonce=\"n\"").unwrap();
        assert_eq!(d.nonce.as_deref(), Some("n"));

        let mut d2 = DigestData::new();
        input_digest(&mut d2, b"DIGEST\trealm=\"r\", nonce=\"n\"").unwrap();
        assert_eq!(d2.nonce.as_deref(), Some("n"));

        // Wrong scheme, missing blank, and bare token all fail.
        let mut d3 = DigestData::new();
        assert_eq!(
            input_digest(&mut d3, b"Basic abc").unwrap_err(),
            CurlError::BadContentEncoding
        );
        assert_eq!(
            input_digest(&mut d3, b"Digestx realm=\"r\"").unwrap_err(),
            CurlError::BadContentEncoding
        );
        assert_eq!(
            input_digest(&mut d3, b"Digest").unwrap_err(),
            CurlError::BadContentEncoding
        );
    }

    #[test]
    fn output_digest_without_challenge_is_not_done() {
        let mut d = DigestData::new(); // no nonce
        let out = output_digest(&mut d, false, false, REQUEST, URI, USER, PASSWD).unwrap();
        assert!(out.header.is_none());
        assert!(!out.done);
    }

    #[test]
    fn output_digest_with_challenge_builds_header() {
        let mut d = base_http();
        let out = output_digest(&mut d, false, false, REQUEST, URI, USER, PASSWD).unwrap();
        assert!(out.done);
        let header = out.header.unwrap();
        assert!(header.starts_with("Authorization: Digest "));
        assert!(header.ends_with("\r\n"));
        assert!(header.contains("response=\"6629fae49393a05397450978507c4ef1\""));
    }

    #[test]
    fn output_digest_proxy_uses_proxy_prefix() {
        let mut d = base_http();
        let out = output_digest(&mut d, true, false, REQUEST, URI, USER, PASSWD).unwrap();
        let header = out.header.unwrap();
        assert!(header.starts_with("Proxy-Authorization: Digest "));
    }

    #[test]
    fn output_digest_iestyle_cuts_query() {
        let mut d = base_http();
        let out = output_digest(
            &mut d,
            false,
            true, // IE-style
            REQUEST,
            b"/dir/index.html?name=value",
            USER,
            PASSWD,
        )
        .unwrap();
        let header = out.header.unwrap();
        // The URI is truncated at '?' before quoting and hashing.
        assert!(header.contains("uri=\"/dir/index.html\""));
        assert!(!header.contains('?'));
        // With the query stripped the hash matches the canonical vector.
        assert!(header.contains("response=\"6629fae49393a05397450978507c4ef1\""));
    }

    #[test]
    fn build_spn_formats() {
        assert_eq!(
            build_spn(b"imap", Some(b"host"), None).unwrap(),
            b"imap/host"
        );
        assert_eq!(
            build_spn(b"http", Some(b"h"), Some(b"r")).unwrap(),
            b"http/h@r"
        );
        assert_eq!(build_spn(b"smtp", None, Some(b"r")).unwrap(), b"smtp@r");
        assert!(build_spn(b"x", None, None).is_none());
    }

    #[test]
    fn hash_dispatch_lengths() {
        // MD5 → 32 hex chars; SHA-256 → 64 hex chars.
        assert_eq!(digest_hash(Algorithm::Md5, b"").unwrap().len(), 32);
        assert_eq!(digest_hash(Algorithm::Md5Sess, b"").unwrap().len(), 32);
        assert_eq!(digest_hash(Algorithm::Sha256, b"").unwrap().len(), 64);
        assert_eq!(digest_hash(Algorithm::Sha256Sess, b"").unwrap().len(), 64);
        // SHA-512/256 → 64 hex chars (a 32-byte digest, like SHA-256).
        assert_eq!(digest_hash(Algorithm::Sha512_256, b"").unwrap().len(), 64);
        assert_eq!(
            digest_hash(Algorithm::Sha512_256Sess, b"").unwrap().len(),
            64
        );
        // Known FIPS 180-4 vector for SHA-512/256("abc"), hex-encoded, confirms the
        // hashing branch routes to the SHA-512/256 primitive (not SHA-256).
        assert_eq!(
            digest_hash(Algorithm::Sha512_256, b"abc").unwrap(),
            b"53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23".to_vec()
        );
    }
}
