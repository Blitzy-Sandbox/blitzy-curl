// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! AWS Signature Version 4 request signing (← `lib/http_aws_sigv4.c`).
//!
//! This module computes the `Authorization: AWS4-HMAC-SHA256 …` header for the
//! `CURLAUTH_AWS_SIGV4` mechanism (the CLI `--aws-sigv4` option). It is the
//! highest-precedence host authentication scheme in [`super`]'s output-auth
//! ordering (see [`super::output_auth_headers`] and
//! [`super::PickedAuth::AwsSigV4`]) and is never used for proxy authentication.
//!
//! # Parity contract
//!
//! The signature output is **byte-for-byte identical** to curl 8.x for
//! identical inputs — this is the binary success condition and is verified by
//! the curl test corpus (`tests/data/test439`, `test472`, `test1955`, …). Every
//! canonicalization rule, whitespace byte, casing decision, separator, and
//! ordering is reproduced exactly from `Curl_output_aws_sigv4` and its helpers.
//! The [`tests`] module pins the known-answer vectors from curl's own test
//! suite (`test439`/`test472`, signed with `CURL_FORCETIME` ⇒ clock `0`) and
//! the canonical AWS SigV4 test-suite examples.
//!
//! # Memory safety
//!
//! This module contains **zero** `unsafe`: the crate root's
//! [`forbid(unsafe_code)`](crate) makes any `unsafe` token a hard compile error.
//! All cryptography is pure-Rust (`sha2` + `hmac`); there is no OpenSSL / C
//! crypto linkage.
//!
//! # Logging of signing material
//!
//! SigV4 signing produces several values that constitute request-authorization
//! material: the **canonical request** (embeds the signed headers and payload
//! hash), the **string-to-sign** (embeds the credential scope and the
//! canonical-request hash), and — most sensitive of all — the final request
//! **signature**. curl's C implementation emits all three verbatim via `infof`
//! under `-v` (`lib/http_aws_sigv4.c`), i.e. at its default informational
//! verbosity. This module deliberately deviates for security:
//!
//! * The canonical request and string-to-sign are recorded at
//!   [`tracing::trace!`] rather than `info!`, so they surface only under an
//!   explicit deepest-verbosity (`--trace`-level) subscriber and never at the
//!   default level.
//! * The signature is **never** written to any log at any verbosity; only a
//!   fixed, value-free completion marker is emitted (also at `trace!`).
//!
//! This is the single intentional observability divergence from curl in this
//! module; every wire byte and header value the peer receives is unchanged.
//!
//! # Structural mapping (C → Rust)
//!
//! | C (`lib/http_aws_sigv4.c`)        | Rust (this module)                    |
//! |-----------------------------------|---------------------------------------|
//! | `Curl_output_aws_sigv4`           | [`output_aws_sigv4`] + `compute_signature` |
//! | `sha256_to_hex` / `Curl_hexencode`| [`sha256_to_hex`]                     |
//! | `HMAC_SHA256` macro               | [`hmac_sha256`]                       |
//! | `is_reserved_char`                | [`is_reserved_char`]                  |
//! | `uri_encode_path` / `canon_path`  | [`canon_path`]                        |
//! | `normalize_query` / `canon_query` | [`normalize_query`] / [`canon_query`] |
//! | `should_urlencode`                | [`should_urlencode`]                  |
//! | `make_headers` / `trim_headers`   | [`make_headers`] / [`trim_header`]    |
//! | `parse_content_sha_hdr`           | [`parse_content_sha_hdr`]             |
//! | `calc_payload_hash`               | [`calc_payload_hash`]                 |
//! | `calc_s3_payload_hash`            | [`calc_s3_payload_hash`]              |
//! | `curlx_str_until` / `_single`     | [`StrParser`]                         |

use crate::error::{Error, Result};
use crate::protocols::http::HttpReq;

use hmac::{Hmac, Mac};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

// ===========================================================================
// PHASE 1 — Constants (mirrors the `#define`s in `lib/http_aws_sigv4.c`).
// ===========================================================================

/// Size of the `YYYYMMDDThhmmssZ` timestamp buffer including the trailing NUL
/// (← `#define TIMESTAMP_SIZE 17`). The printable timestamp is 16 bytes; the
/// signing `date` is its first 8 bytes (`YYYYMMDD`).
const TIMESTAMP_SIZE: usize = 17;

/// Length of a hex-encoded SHA-256 digest including the trailing NUL
/// (← `#define SHA256_HEX_LENGTH (2 * CURL_SHA256_DIGEST_LENGTH + 1)` = 65).
/// Retained as an exact parity constant; the Rust hex encoder produces the
/// 64 printable characters directly.
#[allow(dead_code)]
const SHA256_HEX_LENGTH: usize = 2 * 32 + 1;

/// Maximum number of `&`-separated query components that will be canonicalized
/// (← `#define MAX_QUERY_COMPONENTS 128`). Exceeding it is [`Error::TooLarge`]
/// (← `CURLE_TOO_LARGE`), matching `split_to_dyn_array`.
const MAX_QUERY_COMPONENTS: usize = 128;

/// Maximum length, in non-`:` bytes, of each `--aws-sigv4` token
/// (`provider0`, `provider1`, `region`, `service`) (← `#define MAX_SIGV4_LEN 64`).
const MAX_SIGV4_LEN: usize = 64;

/// The S3 sentinel payload hash used when the request body is not available for
/// hashing (← `#define S3_UNSIGNED_PAYLOAD "UNSIGNED-PAYLOAD"`).
const S3_UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// The default provider specification when `--aws-sigv4` is empty
/// (← `line = "aws:amz"` in `Curl_output_aws_sigv4`).
const DEFAULT_PROVIDER: &str = "aws:amz";

// ===========================================================================
// PHASE 1 — Cryptographic and hex helpers.
// ===========================================================================

/// Type alias for the HMAC-SHA256 construction used throughout the signing
/// chain (matches the `Hmac<Sha256>` usage in `crate::auth::scram`).
type HmacSha256 = Hmac<Sha256>;

/// Lowercase-hex encode a byte slice (← `sha256_to_hex` / `Curl_hexencode`,
/// which documents "converts binary input to **lowercase** hex-encoded ASCII").
///
/// The workspace intentionally carries no `hex` crate, so the encoding is done
/// by hand from a nibble table — the same approach as
/// `crate::auth::digest::hex_encode`.
fn sha256_to_hex(sha: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(sha.len() * 2);
    for &b in sha {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Compute `HMAC-SHA256(key, data)` returning the raw 32-byte tag
/// (← the `HMAC_SHA256(k, kl, d, dl, o)` macro that wraps `Curl_hmacit`).
///
/// HMAC accepts a key of any length, so `new_from_slice` is infallible here;
/// the `expect` documents that invariant (mirrors `crate::auth::scram`).
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

// ===========================================================================
// PHASE 1 — Percent-encoding primitives.
// ===========================================================================

/// Whether `c` is an "unreserved" byte that AWS canonicalization leaves intact
/// (← `is_reserved_char` = `ISALNUM(c) || ISURLPUNTCS(c)`), i.e. an ASCII
/// alphanumeric or one of the RFC 3986 unreserved punctuation marks
/// `-` `.` `_` `~`.
fn is_reserved_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~')
}

/// The set of bytes that [`canon_path`]'s URI-encoder leaves **unescaped**
/// (← the `is_reserved_char(c) || c == '/'` test in `uri_encode_path`): ASCII
/// alphanumerics, the unreserved punctuation `-._~`, and the path separator
/// `/`. Every other byte becomes an uppercase `%XX` escape, which is exactly
/// what [`percent_encoding`] emits.
const URI_PATH_ALLOWED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'/');

/// Append a single byte as an uppercase `%XX` escape
/// (← the `curlx_dyn_addf(db, "%%%02X", c)` calls, which use **uppercase** hex).
fn push_pct_upper(out: &mut String, b: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.push('%');
    out.push(HEX[(b >> 4) as usize] as char);
    out.push(HEX[(b & 0x0f) as usize] as char);
}

/// Decode a single ASCII hex digit to its 0–15 value (← `curlx_hexval`). The
/// caller guarantees the byte is a hex digit; any other byte maps to `0`,
/// matching the "only valid input" contract of `curlx_hexval`.
fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

// ===========================================================================
// PHASE 1 — Canonical URI (path) encoding.
// ===========================================================================

/// Whether the canonical path for `service` must be percent-encoded
/// (← `should_urlencode`).
///
/// AWS S3 receives the path verbatim (S3 keys are already
/// percent-encoded by the caller and must **not** be double-encoded); every
/// other service double-encodes. The comparison is **case-sensitive**
/// (← `curlx_str_cmp`, an exact byte compare) against the three S3 service
/// spellings — this is deliberately distinct from the case-**insensitive**
/// `sign_as_s3` test used to select the payload-hash strategy.
fn should_urlencode(service: &str) -> bool {
    !(service == "s3" || service == "s3-express" || service == "s3-outposts")
}

/// Produce the canonical URI (← `canon_path` + `uri_encode_path`).
///
/// When `do_uri_encode` is set, every byte that is neither
/// [`is_reserved_char`] nor `/` is rewritten as an uppercase `%XX` escape (via
/// the [`URI_PATH_ALLOWED`] set); otherwise the path is copied verbatim
/// (S3). An empty result becomes `"/"` (← `if(!curlx_dyn_len(new_path))
/// result = curlx_dyn_addn(new_path, "/", 1)`).
fn canon_path(path: &str, do_uri_encode: bool) -> String {
    let mut out = if do_uri_encode {
        utf8_percent_encode(path, URI_PATH_ALLOWED).to_string()
    } else {
        path.to_string()
    };
    if out.is_empty() {
        out.push('/');
    }
    out
}

// ===========================================================================
// PHASE 1 — Canonical query string.
// ===========================================================================

/// Normalize one query-string component in place (← `normalize_query`).
///
/// Walk the bytes left to right. A valid `%XX` triple (at least three bytes
/// remaining, both trailing bytes hex) is decoded to a single byte; anything
/// else is taken literally. Then:
///
/// * a decoded `+` is emitted as the literal escape `"%2B"` (so a
///   pre-encoded plus is preserved, never folded to a space);
/// * a [`is_reserved_char`] byte is emitted verbatim;
/// * a literal `+` is emitted as `"%20"` (form-encoding's space);
/// * every other byte is emitted as an uppercase `%XX` escape.
fn normalize_query(input: &[u8], out: &mut String) {
    let n = input.len();
    let mut i = 0;
    while i < n {
        let cur = input[i];
        let decoded;
        // A `%XX` escape needs strictly more than two bytes remaining
        // (← the `len > 2` guard) plus two hex digits.
        if cur == b'%'
            && (n - i) > 2
            && input[i + 1].is_ascii_hexdigit()
            && input[i + 2].is_ascii_hexdigit()
        {
            decoded = (hex_val(input[i + 1]) << 4) | hex_val(input[i + 2]);
            i += 3;
            if decoded == b'+' {
                // A pre-encoded plus stays encoded (as uppercase `%2B`).
                out.push_str("%2B");
                continue;
            }
        } else {
            decoded = cur;
            i += 1;
        }

        if is_reserved_char(decoded) {
            out.push(decoded as char);
        } else if decoded == b'+' {
            out.push_str("%20");
        } else {
            push_pct_upper(out, decoded);
        }
    }
}

/// Split a raw query string on `&`, dropping empty components and enforcing the
/// [`MAX_QUERY_COMPONENTS`] ceiling (← `split_to_dyn_array`).
///
/// Returns [`Error::TooLarge`] (← `CURLE_TOO_LARGE`) once the component count
/// reaches [`MAX_QUERY_COMPONENTS`], matching the `if(count == MAX_...) return
/// CURLE_TOO_LARGE` check performed as each component is appended.
fn split_query(source: &[u8]) -> Result<Vec<&[u8]>> {
    let mut parts: Vec<&[u8]> = Vec::new();
    let n = source.len();
    let mut start = 0usize;
    let mut seg_len = 0usize;
    let mut pos = 0usize;

    while pos < n {
        if source[pos] == b'&' {
            if seg_len != 0 {
                parts.push(&source[start..start + seg_len]);
                seg_len = 0;
                if parts.len() == MAX_QUERY_COMPONENTS {
                    return Err(Error::TooLarge);
                }
            }
            start = pos + 1;
        } else {
            seg_len += 1;
        }
        pos += 1;
    }
    if seg_len != 0 {
        parts.push(&source[start..start + seg_len]);
        if parts.len() == MAX_QUERY_COMPONENTS {
            return Err(Error::TooLarge);
        }
    }
    Ok(parts)
}

/// Build the canonical query string (← `canon_query`).
///
/// Each `&`-separated component is split into `key=value` at its **first** `=`
/// (a component with no `=`, or one whose only `=` is the final byte, has an
/// empty value). Key and value are independently [`normalize_query`]-encoded,
/// the components are sorted bytewise by `(key, value)`, and finally joined
/// with `&` as `key=value` (the `=` is always emitted, even for an empty
/// value). An absent query yields the empty string.
fn canon_query(query: Option<&str>) -> Result<String> {
    let Some(query) = query else {
        return Ok(String::new());
    };
    let parts = split_query(query.as_bytes())?;

    let mut pairs: Vec<(String, String)> = Vec::with_capacity(parts.len());
    for part in parts {
        let eq = part.iter().position(|&b| b == b'=');
        let (key_bytes, value): (&[u8], String) = match eq {
            None => (part, String::new()),
            Some(idx) if idx == part.len() - 1 => (&part[..idx], String::new()),
            Some(idx) => {
                let mut v = String::new();
                normalize_query(&part[idx + 1..], &mut v);
                (&part[..idx], v)
            }
        };
        let mut key = String::new();
        normalize_query(key_bytes, &mut key);
        pairs.push((key, value));
    }

    // Stable bytewise ordering by key, then value (← `compare_func`, a pair of
    // `strcmp`s; an empty field sorts before any non-empty field).
    pairs.sort_by(|a, b| {
        a.0.as_bytes()
            .cmp(b.0.as_bytes())
            .then_with(|| a.1.as_bytes().cmp(b.1.as_bytes()))
    });

    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(k);
        out.push('=');
        out.push_str(v);
    }
    Ok(out)
}

// ===========================================================================
// PHASE 1 — `curlx_str_*` token scanner (used for `--aws-sigv4` parsing and
// hostname service/region inference).
// ===========================================================================

/// A tiny forward cursor over a `&str`, reproducing the two `curlx_str_*`
/// primitives the C entry point relies on for splitting the provider spec and
/// the hostname.
struct StrParser<'a> {
    rest: &'a str,
}

impl<'a> StrParser<'a> {
    fn new(s: &'a str) -> Self {
        Self { rest: s }
    }

    /// Consume a token up to (but not including) `delim` or end of input,
    /// advancing the cursor past it (← `curlx_str_until`).
    ///
    /// Returns `None` — leaving the cursor unchanged — when the token would be
    /// empty (← `STRE_SHORT`) or would exceed `max` bytes (← `STRE_BIG`). The
    /// `max` bound counts **bytes**, exactly as the C length check does.
    fn until(&mut self, max: usize, delim: u8) -> Option<&'a str> {
        let bytes = self.rest.as_bytes();
        let mut len = 0usize;
        while len < bytes.len() && bytes[len] != delim {
            len += 1;
            if len > max {
                return None; // STRE_BIG
            }
        }
        if len == 0 {
            return None; // STRE_SHORT
        }
        // `delim` is always ASCII (`:` or `.`) and multi-byte UTF-8 continuation
        // bytes are never ASCII, so `len` always lands on a char boundary.
        let tok = &self.rest[..len];
        self.rest = &self.rest[len..];
        Some(tok)
    }

    /// Consume exactly one leading byte equal to `ch`, returning whether it was
    /// present (← `curlx_str_single`, which returns `STRE_OK`/`STRE_BYTE`).
    fn single(&mut self, ch: u8) -> bool {
        if self.rest.as_bytes().first() == Some(&ch) {
            self.rest = &self.rest[1..];
            true
        } else {
            false
        }
    }
}

// ===========================================================================
// PHASE 1 — Header canonicalization.
// ===========================================================================

/// Find the first header line whose name matches `name` case-insensitively,
/// terminated by `:` or `;` (← `Curl_checkheaders`). Returns the whole line.
///
/// This re-implements the private `find_header` in [`super`]; it is duplicated
/// here (rather than imported) because that helper is not part of the module's
/// public surface.
fn check_header<'a>(headers: &'a [String], name: &str) -> Option<&'a str> {
    let nlen = name.len();
    let want = name.as_bytes();
    headers.iter().map(String::as_str).find(|line| {
        let b = line.as_bytes();
        b.len() > nlen
            && b[..nlen].eq_ignore_ascii_case(want)
            && (b[nlen] == b':' || b[nlen] == b';')
    })
}

/// The header name of a `"name:value"` line, i.e. everything before the first
/// `:` (or the whole line when there is none). Used for sorting, duplicate
/// merging, and building the `SignedHeaders` list.
fn header_name(line: &str) -> &str {
    match line.find(':') {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Canonicalize one `"Name: Value"` header into the AWS form `"name:value"`
/// (← `trim_headers`).
///
/// The name (everything up to the first `:`) is lowercased. The value has its
/// leading and trailing blanks stripped and every internal run of spaces/tabs
/// collapsed to a single space. A line without a `:` is lowercased whole and
/// returned unchanged otherwise.
fn trim_header(line: &str) -> String {
    let Some(colon) = line.find(':') else {
        return line.to_ascii_lowercase();
    };
    let name = line[..colon].to_ascii_lowercase();
    let value = &line[colon + 1..];

    let mut trimmed = String::with_capacity(value.len());
    let mut pending_space = false; // a run of blanks is waiting to be emitted
    let mut seen_nonblank = false;
    for &b in value.as_bytes() {
        if b == b' ' || b == b'\t' {
            // Collapse; only emit once we know a non-blank follows.
            if seen_nonblank {
                pending_space = true;
            }
        } else {
            if pending_space {
                trimmed.push(' ');
                pending_space = false;
            }
            trimmed.push(b as char);
            seen_nonblank = true;
        }
    }

    let mut out = String::with_capacity(name.len() + 1 + trimmed.len());
    out.push_str(&name);
    out.push(':');
    out.push_str(&trimmed);
    out
}

/// Lowercase `s` then uppercase its first byte (ASCII only), reproducing the
/// `X-<Provider>-Date` header-name casing built by `make_headers`
/// (`curl_msnprintf` + `Curl_strntolower` + `Curl_raw_toupper(provider[0])`).
fn ucfirst(s: &str) -> String {
    let mut bytes = s.to_ascii_lowercase().into_bytes();
    if let Some(first) = bytes.first_mut() {
        first.make_ascii_uppercase();
    }
    // `to_ascii_lowercase` preserves UTF-8 validity and only ASCII bytes were
    // touched, so the buffer is still valid UTF-8.
    String::from_utf8(bytes).unwrap_or_else(|_| s.to_string())
}

/// The outcome of [`make_headers`]: the canonical header block, the
/// `;`-joined signed-header names, and the date header to install in the
/// request output (`None` when the caller supplied their own date header).
struct MadeHeaders {
    /// `name:value\n` for every signed header, in sorted order — used verbatim
    /// as the fourth line group of the canonical request.
    canonical_headers: String,
    /// The sorted header names joined by `;` (the `SignedHeaders` value).
    signed_headers: String,
    /// The `"X-<Provider>-Date: <ts>\r\n"` line to add to the request, or
    /// `None` when a user-supplied date header is already present.
    date_header: Option<String>,
}

/// Build the canonical/signed header sets and decide the date header
/// (← `make_headers`).
///
/// `timestamp` is the clock-derived `YYYYMMDDThhmmssZ` string; it is
/// **overwritten** with the user's value when a date header is already present
/// (so the rest of the signing uses the caller's timestamp), exactly as the C
/// code rewrites its `timestamp` buffer.
fn make_headers(
    user_headers: &[String],
    host_header: Option<&str>,
    hostname: &str,
    timestamp: &mut String,
    provider1: &str,
    content_sha256_header: Option<&str>,
) -> Result<MadeHeaders> {
    // "X-<Ucfirst(provider1)>-Date" — the header name we look for / install.
    let date_hdr_key = format!("X-{}-Date", ucfirst(provider1));
    // "x-<lower(provider1)>-date:<ts>" — the canonical date header (built from
    // the clock timestamp; only used when the caller supplied none).
    let date_full_hdr = format!("x-{}-date:{}", provider1.to_ascii_lowercase(), timestamp);

    let mut head: Vec<String> = Vec::new();

    // Host — from the pre-formatted `Host:` line if present (truncated at the
    // first CR/LF), otherwise synthesized from the bare hostname. Skipped
    // entirely when the user already set a `Host` header (it is copied below).
    if check_header(user_headers, "Host").is_none() {
        let fullhost = match host_header {
            Some(h) => {
                let end = h.find(['\r', '\n']).unwrap_or(h.len());
                h[..end].to_string()
            }
            None => format!("host:{hostname}"),
        };
        head.push(fullhost);
    }

    // The S3 `x-<provider1>-content-sha256` header participates in signing.
    if let Some(csh) = content_sha256_header {
        head.push(csh.to_string());
    }

    // Copy every user header that carries a value, normalizing its separator to
    // `:` (← the `strchr`/`strdup` loop). Skip: no separator; a bare `name:`
    // with nothing after; and whitespace-only values.
    for line in user_headers {
        let bytes = line.as_bytes();
        let colon = bytes.iter().position(|&b| b == b':');
        let sep = colon.or_else(|| bytes.iter().position(|&b| b == b';'));
        let Some(sep) = sep else {
            continue; // no `:` or `;`
        };
        let sep_ch = bytes[sep];
        let after = &line[sep + 1..];
        if sep_ch == b':' && after.is_empty() {
            continue; // bare "name:"
        }
        let value = after.trim_start_matches([' ', '\t']);
        if value.is_empty() && !after.is_empty() {
            continue; // whitespace-only value
        }
        let mut dup = line.clone().into_bytes();
        dup[sep] = b':';
        head.push(String::from_utf8(dup).unwrap_or_else(|_| line.clone()));
    }

    // Canonicalize (lowercase name, squeeze value) everything gathered so far.
    let mut head: Vec<String> = head.iter().map(|h| trim_header(h)).collect();

    // Date header: honor a caller-supplied `X-<Provider>-Date` (or `Date`),
    // otherwise inject our clock-derived one and report it back for output.
    let date_header = match find_date_hdr(user_headers, &date_hdr_key) {
        None => {
            head.push(date_full_hdr);
            Some(format!("{date_hdr_key}: {timestamp}\r\n"))
        }
        Some(dh) => {
            // Extract the value after `:`; a header with no `:` is a hard error
            // in the C path (`goto fail` with `CURLE_OUT_OF_MEMORY`).
            let colon = dh.find(':').ok_or(Error::OutOfMemory)?;
            let val = dh[colon + 1..].trim_start_matches([' ', '\t']);
            let alnum = val.bytes().take_while(u8::is_ascii_alphanumeric).count();
            if alnum == TIMESTAMP_SIZE - 1 {
                *timestamp = val[..alnum].to_string();
            } else {
                // A malformed length yields an empty timestamp (the C code
                // leaves its buffer's first byte as NUL).
                timestamp.clear();
            }
            None
        }
    };

    // Stable sort by header name (← the stable bubble sort in `make_headers`).
    head.sort_by(|a, b| header_name(a).as_bytes().cmp(header_name(b).as_bytes()));

    // Merge duplicate header names, comma-joining their values in order
    // (← `merge_duplicate_headers`).
    let mut merged: Vec<String> = Vec::with_capacity(head.len());
    for h in head {
        if let Some(last) = merged.last_mut() {
            if header_name(last) == header_name(&h) {
                let hv = match h.find(':') {
                    Some(i) => &h[i + 1..],
                    None => "",
                };
                last.push(',');
                last.push_str(hv);
                continue;
            }
        }
        merged.push(h);
    }

    // Emit the canonical block (`name:value\n` each) and the `;`-joined signed
    // header names.
    let mut canonical_headers = String::new();
    let mut signed_headers = String::new();
    for (i, h) in merged.iter().enumerate() {
        canonical_headers.push_str(h);
        canonical_headers.push('\n');
        if i > 0 {
            signed_headers.push(';');
        }
        signed_headers.push_str(header_name(h));
    }

    Ok(MadeHeaders {
        canonical_headers,
        signed_headers,
        date_header,
    })
}

/// Locate the caller-supplied date header: prefer `X-<Provider>-Date`, falling
/// back to a bare `Date` (← the two `Curl_checkheaders` calls in
/// `make_headers`).
fn find_date_hdr<'a>(user_headers: &'a [String], date_hdr_key: &str) -> Option<&'a str> {
    check_header(user_headers, date_hdr_key).or_else(|| check_header(user_headers, "Date"))
}

// ===========================================================================
// PHASE 1 — Payload hashing.
// ===========================================================================

/// The lowercase-hex SHA-256 of the request body (← `calc_payload_hash`). An
/// absent body hashes the empty input, yielding the well-known
/// `e3b0c442…b855` digest.
fn calc_payload_hash(body: &[u8]) -> String {
    sha256_to_hex(Sha256::digest(body).as_slice())
}

/// Extract a caller-supplied `x-<provider1>-content-sha256` header value
/// (← `parse_content_sha_hdr`).
///
/// Returns the trimmed value (blanks stripped from both ends) when the header
/// is present and contains a `:`, else `None`.
fn parse_content_sha_hdr(headers: &[String], provider1: &str) -> Option<String> {
    let key = format!("x-{provider1}-content-sha256");
    let line = check_header(headers, &key)?;
    let colon = line.find(':')?;
    Some(line[colon + 1..].trim_matches([' ', '\t']).to_string())
}

/// Compute the S3 payload hash and the `x-<provider1>-content-sha256` header
/// to install (← `calc_s3_payload_hash`).
///
/// A real SHA-256 is used when the payload is known to be empty (`GET`/`HEAD`,
/// or an explicit zero-length upload) or is an in-memory `POST` body;
/// otherwise the [`S3_UNSIGNED_PAYLOAD`] sentinel is used because the body is
/// streamed and not available for hashing. The returned header preserves
/// `provider1`'s original casing (canonicalization lowercases it later; the
/// verbatim form is what gets written to the wire).
fn calc_s3_payload_hash(
    httpreq: HttpReq,
    filesize: i64,
    body: Option<&[u8]>,
    provider1: &str,
) -> (String, String) {
    let empty_method = matches!(httpreq, HttpReq::Get | HttpReq::Head);
    let empty_payload = empty_method || filesize == 0;
    let post_payload = httpreq == HttpReq::Post && body.is_some();

    let sha_hex = if empty_payload || post_payload {
        calc_payload_hash(body.unwrap_or(&[]))
    } else {
        S3_UNSIGNED_PAYLOAD.to_string()
    };
    let header = format!("x-{provider1}-content-sha256: {sha_hex}");
    (sha_hex, header)
}

// ===========================================================================
// PHASE 1 — `--aws-sigv4` provider spec parsing.
// ===========================================================================

/// The parsed four-part provider specification.
struct Providers {
    /// `provider0` — the credential-scope / algorithm prefix (e.g. `aws`).
    provider0: String,
    /// `provider1` — the header-namespace prefix (e.g. `amz`); defaults to
    /// `provider0` when the second token is absent.
    provider1: String,
    /// The explicit region, if the spec supplied one.
    region: Option<String>,
    /// The explicit service, if the spec supplied one.
    service: Option<String>,
}

/// Parse `provider0[:provider1[:region[:service]]]` (← the `curlx_str_until` /
/// `curlx_str_single` cascade at the top of `Curl_output_aws_sigv4`).
///
/// An empty `provider0` is [`Error::BadFunctionArgument`]. A missing
/// `provider1` mirrors `provider0`. `region`/`service` are only parsed when a
/// well-formed `provider1` was found, short-circuiting exactly like the C
/// `||` chain.
fn parse_providers(line: &str) -> Result<Providers> {
    let mut p = StrParser::new(line);

    let provider0 = match p.until(MAX_SIGV4_LEN, b':') {
        Some(t) => t.to_string(),
        None => {
            return Err(Error::bad_argument(
                "first aws-sigv4 provider cannot be empty",
            ));
        }
    };

    // provider1: only if we can consume ':' AND read a token; otherwise mirror
    // provider0 and stop (no region/service).
    let consumed = p.single(b':');
    let prov1 = if consumed {
        p.until(MAX_SIGV4_LEN, b':')
    } else {
        None
    };

    let (provider1, region, service) = match prov1 {
        None => (provider0.clone(), None, None),
        Some(tok) => {
            let provider1 = tok.to_string();
            // region := next token, then service := the token after it — each
            // parsed only if the preceding ':' and token both succeed.
            let mut region = None;
            let mut service = None;
            if p.single(b':') {
                if let Some(r) = p.until(MAX_SIGV4_LEN, b':') {
                    region = Some(r.to_string());
                    if p.single(b':') {
                        if let Some(s) = p.until(MAX_SIGV4_LEN, b':') {
                            service = Some(s.to_string());
                        }
                    }
                }
            }
            (provider1, region, service)
        }
    };

    Ok(Providers {
        provider0,
        provider1,
        region,
        service,
    })
}

// ===========================================================================
// PHASE 2 — Timestamp handling.
// ===========================================================================

/// The current wall-clock time as a Unix timestamp (seconds).
///
/// In debug/test builds the `CURL_FORCETIME` environment variable pins the
/// clock to epoch `0` (`19700101T000000Z`), reproducing the `DEBUGBUILD`
/// `CURL_FORCETIME` override that makes curl's own signing tests deterministic.
fn current_clock() -> i64 {
    #[cfg(debug_assertions)]
    {
        if std::env::var_os("CURL_FORCETIME").is_some() {
            return 0;
        }
    }
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// Format a Unix timestamp as `YYYYMMDDThhmmssZ`
/// (← `strftime("%Y%m%dT%H%M%SZ", gmtime(&clock))`).
///
/// A timestamp outside the representable range yields
/// [`Error::BadFunctionArgument`], matching the C guard that fails when
/// `gmtime`/`strftime` cannot produce the buffer.
fn format_timestamp(clock: i64) -> Result<String> {
    use chrono::{DateTime, Utc};
    let dt = DateTime::<Utc>::from_timestamp(clock, 0)
        .ok_or_else(|| Error::bad_argument("aws-sigv4: invalid timestamp"))?;
    Ok(dt.format("%Y%m%dT%H%M%SZ").to_string())
}

// ===========================================================================
// PHASE 2 — Public entry point.
// ===========================================================================

/// The request state required to compute an AWS SigV4 `Authorization` header.
///
/// This mirrors the fields `Curl_output_aws_sigv4` reads out of `struct
/// Curl_easy`, decoupled from the transfer machinery so the signer is a pure
/// function of its inputs (and therefore trivially testable against
/// known-answer vectors). The caller is responsible for resolving curl's
/// `postfields`/`postfieldsize` semantics into a concrete [`Self::body`] slice.
pub struct SigV4Input<'a> {
    /// Whether `--path-as-is` is in effect. SigV4 is incompatible with it
    /// (← the early `CURLE_BAD_FUNCTION_ARGUMENT`).
    pub path_as_is: bool,
    /// The raw `--aws-sigv4` parameter (`CURLOPT_AWS_SIGV4`); `None`/empty ⇒
    /// the [`DEFAULT_PROVIDER`] `"aws:amz"`.
    pub sigv4_param: Option<&'a str>,
    /// The request hostname (no port), used for service/region inference and as
    /// the `Host` fallback.
    pub hostname: &'a str,
    /// The HTTP method token (e.g. `"GET"`), as resolved by
    /// [`super::http_method`].
    pub method: &'a str,
    /// The resolved request kind, used by the S3 payload-hash strategy.
    pub httpreq: HttpReq,
    /// The access key id (curl's `user`); empty when unset.
    pub access_key_id: &'a str,
    /// The secret access key (curl's `passwd`); `None` ⇒ empty.
    pub secret_key: Option<&'a str>,
    /// The user-supplied request headers (`name: value`, no CRLF), as an
    /// already-materialized list.
    pub headers: &'a [String],
    /// The pre-formatted `Host:` request line (curl's `aptr.host`,
    /// `"Host: …\r\n"`), if available. Preferred over synthesizing from
    /// [`Self::hostname`] because it carries the port.
    pub host_header: Option<&'a str>,
    /// The canonical request path (`state.up.path`).
    pub url_path: &'a str,
    /// The raw query string (`state.up.query`, without a leading `?`), if any.
    pub url_query: Option<&'a str>,
    /// The in-memory request body, if available for hashing.
    pub body: Option<&'a [u8]>,
    /// The declared upload size: `-1` when unknown, `0` for an explicit
    /// empty upload (drives the S3 `UNSIGNED-PAYLOAD` decision).
    pub filesize: i64,
}

impl Default for SigV4Input<'_> {
    fn default() -> Self {
        Self {
            path_as_is: false,
            sigv4_param: None,
            hostname: "",
            method: "GET",
            httpreq: HttpReq::Get,
            access_key_id: "",
            secret_key: None,
            headers: &[],
            host_header: None,
            url_path: "/",
            url_query: None,
            body: None,
            filesize: -1,
        }
    }
}

/// Compute the AWS SigV4 header block for `input`, signing against `clock`
/// (a Unix timestamp in seconds).
///
/// Returns:
/// * `Ok(None)` when the caller already supplied an `Authorization` header
///   (SigV4 defers, exactly as the C code returns `CURLE_OK` without acting);
/// * `Ok(Some(block))` — the header lines to install, each terminated by
///   `\r\n`: the `Authorization` line, then (for S3) the
///   `x-<provider1>-content-sha256` line, then (unless the caller supplied one)
///   the `X-<Provider>-Date` line;
/// * `Err(_)` for the parameter / hostname / path-as-is error cases.
///
/// Splitting the clock out of [`output_aws_sigv4`] makes the whole computation
/// deterministic for the known-answer tests.
fn compute_signature(input: &SigV4Input<'_>, clock: i64) -> Result<Option<String>> {
    // (1) SigV4 cannot coexist with `--path-as-is`.
    if input.path_as_is {
        return Err(Error::bad_argument(
            "Cannot use sigv4 authentication with path-as-is flag",
        ));
    }

    // (2) If the caller already set Authorization, do nothing.
    if check_header(input.headers, "Authorization").is_some() {
        return Ok(None);
    }

    // (3) Parse `provider0[:provider1[:region[:service]]]`.
    let line = input
        .sigv4_param
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_PROVIDER);
    let Providers {
        provider0,
        provider1,
        mut region,
        mut service,
    } = parse_providers(line)?;

    // (4) Infer service (and, only then, region) from the hostname labels when
    // the service was not given explicitly.
    if service.is_none() {
        let mut hp = StrParser::new(input.hostname);
        let Some(svc) = hp.until(MAX_SIGV4_LEN, b'.') else {
            return Err(Error::url(
                "aws-sigv4: service missing in parameters and hostname",
            ));
        };
        if !hp.single(b'.') {
            return Err(Error::url(
                "aws-sigv4: service missing in parameters and hostname",
            ));
        }
        tracing::info!("aws_sigv4: picked service {} from host", svc);
        service = Some(svc.to_string());

        if region.is_none() {
            let Some(reg) = hp.until(MAX_SIGV4_LEN, b'.') else {
                return Err(Error::url(
                    "aws-sigv4: region missing in parameters and hostname",
                ));
            };
            if !hp.single(b'.') {
                return Err(Error::url(
                    "aws-sigv4: region missing in parameters and hostname",
                ));
            }
            tracing::info!("aws_sigv4: picked region {} from host", reg);
            region = Some(reg.to_string());
        }
    }
    let region = region.unwrap_or_default();
    let service = service.unwrap_or_default();

    // (6) Determine the payload hash and (for S3) the content-sha256 header.
    let mut content_sha256_hdr: Option<String> = None;
    let payload_hash = if let Some(v) = parse_content_sha_hdr(input.headers, &provider1) {
        v
    } else {
        let sign_as_s3 =
            provider0.eq_ignore_ascii_case("aws") && service.eq_ignore_ascii_case("s3");
        if sign_as_s3 {
            let (hash, header) =
                calc_s3_payload_hash(input.httpreq, input.filesize, input.body, &provider1);
            content_sha256_hdr = Some(header);
            hash
        } else {
            calc_payload_hash(input.body.unwrap_or(&[]))
        }
    };

    // (7) Timestamp (may be overwritten by a user-supplied date header in step 8).
    let mut timestamp = format_timestamp(clock)?;

    // (8) Canonical + signed headers, plus the date header to install.
    let made = make_headers(
        input.headers,
        input.host_header,
        input.hostname,
        &mut timestamp,
        &provider1,
        content_sha256_hdr.as_deref(),
    )?;

    // The signing `date` is the first 8 chars (`YYYYMMDD`) of the timestamp.
    let date = timestamp.get(..8).unwrap_or(timestamp.as_str()).to_string();

    // (9)/(7-path) Canonical query and (10) canonical path.
    let canonical_query = canon_query(input.url_query)?;
    let canonical_path = canon_path(input.url_path, should_urlencode(&service));

    // (11) Assemble the canonical request.
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        input.method,
        canonical_path,
        canonical_query,
        made.canonical_headers,
        made.signed_headers,
        payload_hash
    );
    // The canonical request is authorization-derived material: it embeds the
    // signed headers and the payload hash used to compute the request
    // signature. curl emits it via `infof` under `-v`, but signing material must
    // never surface by default. It is therefore recorded at `trace!` (the
    // deepest verbosity — only reachable under an explicit `--trace`-level
    // subscriber, never at the default level), not `info!`. See the module note
    // and the `string_to_sign` / signature sites below.
    tracing::trace!(
        "aws_sigv4: Canonical request (enclosed in []) - [{}]",
        canonical_request
    );

    // (12/13) request_type + credential scope, provider-cased.
    let provider0_upper = provider0.to_ascii_uppercase();
    let request_type = format!("{}4_request", provider0.to_ascii_lowercase());
    let credential_scope = format!("{date}/{region}/{service}/{request_type}");

    // (13) String to sign (`<P0UPPER>4-HMAC-SHA256`).
    let algo = format!("{provider0_upper}4-HMAC-SHA256");
    let cr_hash = sha256_to_hex(Sha256::digest(canonical_request.as_bytes()).as_slice());
    let string_to_sign = format!("{algo}\n{timestamp}\n{credential_scope}\n{cr_hash}");
    // The string-to-sign is likewise signing material (it carries the credential
    // scope and the canonical-request hash). Recorded at `trace!` for the same
    // reason as the canonical request above: available for deep `--trace`
    // debugging, but never emitted at the default verbosity.
    tracing::trace!(
        "aws_sigv4: String to sign (enclosed in []) - [{}]",
        string_to_sign
    );

    // (14) Derive the signing key and sign: AWS4+secret → date → region →
    // service → request_type, then HMAC the string-to-sign.
    let secret = format!("{}4{}", provider0_upper, input.secret_key.unwrap_or(""));
    let k_date = hmac_sha256(secret.as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, request_type.as_bytes());
    let signature = sha256_to_hex(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));
    // The final request signature is the single most sensitive value produced
    // here: an attacker who observes it can replay the signed request until it
    // expires. curl logs it verbatim under `-v`, but we deliberately deviate —
    // the value is REDACTED and never written to any log at any verbosity. Only
    // a fixed, value-free completion marker is emitted, and only at `trace!`.
    tracing::trace!("aws_sigv4: request signed (signature redacted)");

    // (15/16) Build the output header block: Authorization, then (S3)
    // content-sha256, then (if we generated it) the date header.
    let mut out = format!(
        "Authorization: {} Credential={}/{}, SignedHeaders={}, Signature={}\r\n",
        algo, input.access_key_id, credential_scope, made.signed_headers, signature
    );
    if let Some(csh) = &content_sha256_hdr {
        out.push_str(csh);
        out.push_str("\r\n");
    }
    if let Some(dh) = &made.date_header {
        out.push_str(dh);
    }

    Ok(Some(out))
}

/// Compute the AWS SigV4 `Authorization` header block for `input`, using the
/// current wall-clock time (← `Curl_output_aws_sigv4`).
///
/// This is the module's public entry point. See [`compute_signature`] for the
/// return-value contract; the only difference is that the signing clock is
/// obtained from [`current_clock`] rather than supplied by the caller.
pub fn output_aws_sigv4(input: &SigV4Input<'_>) -> Result<Option<String>> {
    compute_signature(input, current_clock())
}

// ===========================================================================
// Tests — known-answer vectors against curl 8.x (`tests/data/test439`,
// `test472`) and the canonical AWS SigV4 test-suite examples. Every vector was
// cross-checked against a reference implementation of curl's exact algorithm.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The well-known SHA-256 of the empty input.
    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// Sign `input` with a fixed `clock`, asserting success and that a header
    /// block was produced.
    fn sign(input: &SigV4Input<'_>, clock: i64) -> String {
        compute_signature(input, clock)
            .expect("signing should succeed")
            .expect("an Authorization block should be produced")
    }

    /// Extract the value following `key` (e.g. `"Signature="`) up to the next
    /// `,` or `\r` in the produced header block.
    fn field<'a>(block: &'a str, key: &str) -> &'a str {
        let start = block.find(key).expect("key must be present") + key.len();
        let rest = &block[start..];
        let end = rest.find([',', '\r']).unwrap_or(rest.len());
        &rest[..end]
    }

    // --- constants -------------------------------------------------------

    #[test]
    fn constants_match_curl() {
        assert_eq!(TIMESTAMP_SIZE, 17);
        assert_eq!(SHA256_HEX_LENGTH, 65);
        assert_eq!(MAX_QUERY_COMPONENTS, 128);
        assert_eq!(MAX_SIGV4_LEN, 64);
        assert_eq!(S3_UNSIGNED_PAYLOAD, "UNSIGNED-PAYLOAD");
        assert_eq!(DEFAULT_PROVIDER, "aws:amz");
    }

    // --- crypto / hex helpers -------------------------------------------

    #[test]
    fn sha256_to_hex_is_lowercase() {
        assert_eq!(sha256_to_hex(Sha256::digest(b"").as_slice()), SHA256_EMPTY);
        assert_eq!(sha256_to_hex(&[0x00, 0xab, 0xff, 0x0f]), "00abff0f");
    }

    #[test]
    fn hmac_sha256_rfc4231_case1() {
        // RFC 4231 test case 1: key = 0x0b × 20, data = "Hi There".
        let out = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            sha256_to_hex(&out),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    // --- character classes / path encoding ------------------------------

    #[test]
    fn reserved_char_set_matches_c() {
        for c in b'a'..=b'z' {
            assert!(is_reserved_char(c));
        }
        for c in b'A'..=b'Z' {
            assert!(is_reserved_char(c));
        }
        for c in b'0'..=b'9' {
            assert!(is_reserved_char(c));
        }
        for &c in b"-._~" {
            assert!(is_reserved_char(c));
        }
        for &c in b" /?#[]@!$&'()*+,;=%\"" {
            assert!(!is_reserved_char(c));
        }
        assert!(!is_reserved_char(0x80));
    }

    #[test]
    fn should_urlencode_is_case_sensitive() {
        assert!(!should_urlencode("s3"));
        assert!(!should_urlencode("s3-express"));
        assert!(!should_urlencode("s3-outposts"));
        // Case-sensitive: an uppercase spelling IS encoded.
        assert!(should_urlencode("S3"));
        assert!(should_urlencode("es"));
        assert!(should_urlencode("execute-api"));
        assert!(should_urlencode("s3-other"));
    }

    #[test]
    fn canon_path_non_s3_double_encodes() {
        // test472 UTF-8 path.
        assert_eq!(
            canon_path("/472/a=%E3%81%82", true),
            "/472/a%3D%25E3%2581%2582"
        );
        assert_eq!(canon_path("/", true), "/");
        assert_eq!(canon_path("", true), "/"); // empty → "/"
        assert_eq!(canon_path("/path/to/thing", true), "/path/to/thing");
        assert_eq!(canon_path("/a b", true), "/a%20b");
        assert_eq!(
            canon_path("/tilde~dash-dot.und_er", true),
            "/tilde~dash-dot.und_er"
        );
    }

    #[test]
    fn canon_path_s3_is_verbatim() {
        // S3 (should_urlencode == false) does NOT double-encode.
        assert_eq!(
            canon_path("/mybucket/my%20file.txt", false),
            "/mybucket/my%20file.txt"
        );
        assert_eq!(canon_path("", false), "/");
    }

    // --- query canonicalization -----------------------------------------

    #[test]
    fn normalize_query_rules() {
        let mut o = String::new();
        normalize_query(b"b%aad", &mut o);
        assert_eq!(o, "b%AAd"); // decoded non-reserved byte re-encoded uppercase

        o.clear();
        normalize_query(b"*.//-", &mut o);
        assert_eq!(o, "%2A.%2F%2F-");

        o.clear();
        normalize_query(b"a+b", &mut o);
        assert_eq!(o, "a%20b"); // literal '+' → "%20"

        o.clear();
        normalize_query(b"%2B", &mut o);
        assert_eq!(o, "%2B"); // pre-encoded '+' stays "%2B"

        o.clear();
        normalize_query(b"plain", &mut o);
        assert_eq!(o, "plain");

        o.clear();
        normalize_query(b"%", &mut o);
        assert_eq!(o, "%25"); // lone '%' (too short to decode)

        o.clear();
        normalize_query(b"%2", &mut o);
        assert_eq!(o, "%252"); // incomplete escape
    }

    #[test]
    fn canon_query_test439_and_edges() {
        assert_eq!(
            canon_query(Some("name=me&noval&aim=b%aad&&&weirdo=*.//-")).unwrap(),
            "aim=b%AAd&name=me&noval=&weirdo=%2A.%2F%2F-"
        );
        assert_eq!(canon_query(None).unwrap(), "");
        assert_eq!(canon_query(Some("")).unwrap(), "");
        assert_eq!(canon_query(Some("=value")).unwrap(), "=value"); // empty key
        assert_eq!(canon_query(Some("key=")).unwrap(), "key="); // trailing '='
        assert_eq!(canon_query(Some("b=2&a=1")).unwrap(), "a=1&b=2"); // sorted
    }

    #[test]
    fn split_query_enforces_max_components() {
        let q127 = vec!["a=1"; 127].join("&");
        assert_eq!(split_query(q127.as_bytes()).unwrap().len(), 127);

        let q128 = vec!["a=1"; 128].join("&");
        assert!(matches!(split_query(q128.as_bytes()), Err(Error::TooLarge)));
    }

    // --- header canonicalization ----------------------------------------

    #[test]
    fn trim_header_canonicalizes() {
        assert_eq!(trim_header("Host: Example.com"), "host:Example.com");
        assert_eq!(
            trim_header("X-Amz-Date:  20150830T123600Z  "),
            "x-amz-date:20150830T123600Z"
        );
        assert_eq!(trim_header("My-Header: a   b\tc"), "my-header:a b c");
        assert_eq!(trim_header("Empty:"), "empty:");
        assert_eq!(trim_header("NoColon"), "nocolon");
    }

    #[test]
    fn ucfirst_lowercases_then_caps_first() {
        assert_eq!(ucfirst("amz"), "Amz");
        assert_eq!(ucfirst("COS"), "Cos");
        assert_eq!(ucfirst("x"), "X");
        assert_eq!(ucfirst(""), "");
    }

    #[test]
    fn make_headers_basic_host_and_date() {
        let mut ts = "20150830T123600Z".to_string();
        let made = make_headers(&[], None, "example.amazonaws.com", &mut ts, "amz", None).unwrap();
        assert_eq!(
            made.canonical_headers,
            "host:example.amazonaws.com\nx-amz-date:20150830T123600Z\n"
        );
        assert_eq!(made.signed_headers, "host;x-amz-date");
        assert_eq!(
            made.date_header.as_deref(),
            Some("X-Amz-Date: 20150830T123600Z\r\n")
        );
        assert_eq!(ts, "20150830T123600Z"); // untouched (no user date header)
    }

    #[test]
    fn make_headers_uses_host_line_with_port() {
        let mut ts = "19700101T000000Z".to_string();
        let made = make_headers(
            &[],
            Some("Host: fake.fake.fake:8000\r\n"),
            "fake.fake.fake",
            &mut ts,
            "amz",
            None,
        )
        .unwrap();
        assert!(made
            .canonical_headers
            .starts_with("host:fake.fake.fake:8000\n"));
    }

    #[test]
    fn make_headers_user_host_skips_synthetic() {
        let headers = vec!["Host: user.example.com".to_string()];
        let mut ts = "20150830T123600Z".to_string();
        let made = make_headers(
            &headers,
            Some("Host: ignored:1\r\n"),
            "ignored",
            &mut ts,
            "amz",
            None,
        )
        .unwrap();
        assert!(made.canonical_headers.contains("host:user.example.com\n"));
        assert!(!made.canonical_headers.contains("ignored"));
        assert_eq!(made.signed_headers, "host;x-amz-date");
    }

    #[test]
    fn make_headers_merges_duplicates_and_sorts() {
        let headers = vec![
            "X-Amz-Meta: b".to_string(),
            "X-Amz-Meta: a".to_string(),
            "Zed: last".to_string(),
        ];
        let mut ts = "20150830T123600Z".to_string();
        let made = make_headers(&headers, None, "h.example.com", &mut ts, "amz", None).unwrap();
        // Duplicates merge comma-joined in original order.
        assert!(made.canonical_headers.contains("x-amz-meta:b,a\n"));
        // Overall sorted by name.
        assert_eq!(made.signed_headers, "host;x-amz-date;x-amz-meta;zed");
    }

    #[test]
    fn make_headers_user_date_overwrites_timestamp() {
        let headers = vec!["x-amz-date: 20200101T000000Z".to_string()];
        let mut ts = "20150830T123600Z".to_string();
        let made = make_headers(&headers, None, "h.example.com", &mut ts, "amz", None).unwrap();
        assert_eq!(ts, "20200101T000000Z"); // overwritten from user header
        assert_eq!(made.date_header, None); // we did not synthesize one
        assert!(made
            .canonical_headers
            .contains("x-amz-date:20200101T000000Z\n"));
    }

    #[test]
    fn make_headers_bad_user_date_length_clears_timestamp() {
        // A user date whose value is not exactly 16 alphanumerics ⇒ empty ts.
        let headers = vec!["x-amz-date: short".to_string()];
        let mut ts = "20150830T123600Z".to_string();
        let _ = make_headers(&headers, None, "h.example.com", &mut ts, "amz", None).unwrap();
        assert_eq!(ts, "");
    }

    // --- payload hashing -------------------------------------------------

    #[test]
    fn parse_content_sha_hdr_reads_trimmed_value() {
        let headers = vec!["x-amz-content-sha256:   ABCDEF  ".to_string()];
        assert_eq!(
            parse_content_sha_hdr(&headers, "amz").as_deref(),
            Some("ABCDEF")
        );
        assert_eq!(parse_content_sha_hdr(&[], "amz"), None);
    }

    #[test]
    fn calc_s3_payload_hash_variants() {
        // GET ⇒ empty method ⇒ real (empty) hash + header.
        let (h, hdr) = calc_s3_payload_hash(HttpReq::Get, -1, None, "amz");
        assert_eq!(h, SHA256_EMPTY);
        assert_eq!(hdr, format!("x-amz-content-sha256: {SHA256_EMPTY}"));

        // PUT, unknown size ⇒ UNSIGNED-PAYLOAD.
        let (h, _) = calc_s3_payload_hash(HttpReq::Put, -1, None, "amz");
        assert_eq!(h, "UNSIGNED-PAYLOAD");

        // PUT, explicit zero-length ⇒ real empty hash.
        let (h, _) = calc_s3_payload_hash(HttpReq::Put, 0, None, "amz");
        assert_eq!(h, SHA256_EMPTY);

        // POST with an in-memory body ⇒ hash of that body.
        let (h, _) = calc_s3_payload_hash(HttpReq::Post, -1, Some(b"hello"), "amz");
        assert_eq!(h, sha256_to_hex(Sha256::digest(b"hello").as_slice()));
    }

    // --- provider spec parsing ------------------------------------------

    #[test]
    fn parse_providers_forms() {
        let p = parse_providers("aws:amz").unwrap();
        assert_eq!((p.provider0.as_str(), p.provider1.as_str()), ("aws", "amz"));
        assert!(p.region.is_none() && p.service.is_none());

        // Missing provider1 mirrors provider0.
        let p = parse_providers("aws").unwrap();
        assert_eq!((p.provider0.as_str(), p.provider1.as_str()), ("aws", "aws"));

        let p = parse_providers("aws:amz:us-east-1:s3").unwrap();
        assert_eq!(p.region.as_deref(), Some("us-east-1"));
        assert_eq!(p.service.as_deref(), Some("s3"));

        let p = parse_providers("oss:cos:cn-hangzhou:svc").unwrap();
        assert_eq!((p.provider0.as_str(), p.provider1.as_str()), ("oss", "cos"));
        assert_eq!(p.region.as_deref(), Some("cn-hangzhou"));
        assert_eq!(p.service.as_deref(), Some("svc"));
    }

    #[test]
    fn parse_providers_empty_first_is_error() {
        assert!(matches!(
            parse_providers(":amz"),
            Err(Error::BadFunctionArgument(_))
        ));
    }

    #[test]
    fn parse_providers_token_length_bounds() {
        let too_long = "x".repeat(MAX_SIGV4_LEN + 1);
        assert!(matches!(
            parse_providers(&too_long),
            Err(Error::BadFunctionArgument(_))
        ));
        let exactly_max = "x".repeat(MAX_SIGV4_LEN);
        assert_eq!(
            parse_providers(&exactly_max).unwrap().provider0.len(),
            MAX_SIGV4_LEN
        );
    }

    // --- hostname service/region inference ------------------------------

    #[test]
    fn infers_service_and_region_from_host() {
        let input = SigV4Input {
            sigv4_param: Some("aws:amz"),
            hostname: "es.us-east-2.amazonaws.com",
            access_key_id: "user",
            secret_key: Some("secret"),
            ..Default::default()
        };
        let block = sign(&input, 0);
        assert!(field(&block, "Credential=").ends_with("/us-east-2/es/aws4_request"));
    }

    #[test]
    fn missing_service_in_host_errors() {
        let input = SigV4Input {
            sigv4_param: Some("aws:amz"),
            hostname: "singlelabel",
            ..Default::default()
        };
        assert!(matches!(compute_signature(&input, 0), Err(Error::Url(_))));
    }

    #[test]
    fn missing_region_in_host_errors() {
        let input = SigV4Input {
            sigv4_param: Some("aws:amz"),
            hostname: "es.",
            ..Default::default()
        };
        assert!(matches!(compute_signature(&input, 0), Err(Error::Url(_))));
    }

    // --- entry-point guard rails ----------------------------------------

    #[test]
    fn path_as_is_is_rejected() {
        let input = SigV4Input {
            path_as_is: true,
            ..Default::default()
        };
        assert!(matches!(
            compute_signature(&input, 0),
            Err(Error::BadFunctionArgument(_))
        ));
    }

    #[test]
    fn existing_authorization_defers() {
        let headers = vec!["Authorization: something".to_string()];
        let input = SigV4Input {
            sigv4_param: Some("aws:amz:us-east-1:service"),
            hostname: "example.amazonaws.com",
            headers: &headers,
            ..Default::default()
        };
        assert_eq!(compute_signature(&input, 0).unwrap(), None);
    }

    // --- timestamp ------------------------------------------------------

    #[test]
    fn format_timestamp_values() {
        assert_eq!(format_timestamp(0).unwrap(), "19700101T000000Z");
        assert_eq!(format_timestamp(1_440_938_160).unwrap(), "20150830T123600Z");
    }

    // --- known-answer signature vectors ---------------------------------

    #[test]
    fn kat_test472_utf8_path() {
        let input = SigV4Input {
            sigv4_param: Some("aws:amz:us-east-2:es"),
            hostname: "fake.fake.fake",
            host_header: Some("Host: fake.fake.fake:8000\r\n"),
            method: "GET",
            httpreq: HttpReq::Get,
            access_key_id: "user",
            secret_key: Some("secret"),
            url_path: "/472/a=%E3%81%82",
            ..Default::default()
        };
        let block = sign(&input, 0);
        assert_eq!(
            field(&block, "Signature="),
            "b8783c8387a5249b084642126fe1f8e07e12a2847820fd5b6cd64b2047149da4"
        );
    }

    #[test]
    fn kat_test439_query_edges() {
        let input = SigV4Input {
            sigv4_param: Some("aws:amz:us-east-2:es"),
            hostname: "fake.fake.fake",
            host_header: Some("Host: fake.fake.fake:8000\r\n"),
            method: "GET",
            httpreq: HttpReq::Get,
            access_key_id: "user",
            secret_key: Some("secret"),
            url_path: "/439/",
            url_query: Some("name=me&noval&aim=b%aad&&&weirdo=*.//-"),
            ..Default::default()
        };
        let block = sign(&input, 0);
        assert_eq!(
            field(&block, "Signature="),
            "9dd8592929306832a6673d10063491391e486e5f50de4647ea7c2c797277e0a6"
        );
    }

    #[test]
    fn kat_aws_get_vanilla() {
        let input = SigV4Input {
            sigv4_param: Some("aws:amz:us-east-1:service"),
            hostname: "example.amazonaws.com",
            method: "GET",
            httpreq: HttpReq::Get,
            access_key_id: "AKIDEXAMPLE",
            secret_key: Some("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
            url_path: "/",
            ..Default::default()
        };
        let block = sign(&input, 1_440_938_160);
        assert_eq!(
            field(&block, "Signature="),
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
        assert_eq!(field(&block, "SignedHeaders="), "host;x-amz-date");
        assert_eq!(
            field(&block, "Credential="),
            "AKIDEXAMPLE/20150830/us-east-1/service/aws4_request"
        );
        assert!(block.starts_with("Authorization: AWS4-HMAC-SHA256 "));
        assert!(block.contains("\r\nX-Amz-Date: 20150830T123600Z\r\n"));
    }

    #[test]
    fn kat_s3_get_adds_content_sha256_header() {
        let input = SigV4Input {
            sigv4_param: Some("aws:amz:us-east-1:s3"),
            hostname: "s3.amazonaws.com",
            method: "GET",
            httpreq: HttpReq::Get,
            access_key_id: "AKIDEXAMPLE",
            secret_key: Some("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
            url_path: "/mybucket/myfile.txt",
            ..Default::default()
        };
        let block = sign(&input, 1_440_938_160);
        assert_eq!(
            field(&block, "Signature="),
            "355927535aae33b7b96283a228fe734581389f934947bc45a0f7d6b4dd7344d5"
        );
        assert_eq!(
            field(&block, "SignedHeaders="),
            "host;x-amz-content-sha256;x-amz-date"
        );
        assert!(block.contains(&format!("\r\nx-amz-content-sha256: {SHA256_EMPTY}\r\n")));
    }

    #[test]
    fn kat_s3_put_unsigned_payload() {
        let input = SigV4Input {
            sigv4_param: Some("aws:amz:us-east-1:s3"),
            hostname: "s3.amazonaws.com",
            method: "PUT",
            httpreq: HttpReq::Put,
            access_key_id: "AKIDEXAMPLE",
            secret_key: Some("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
            url_path: "/mybucket/upload.bin",
            filesize: -1,
            ..Default::default()
        };
        let block = sign(&input, 1_440_938_160);
        assert_eq!(
            field(&block, "Signature="),
            "4ff20abf14d2f4c168f6c95ff1266629b75217e2cd29a003ef8fe7f08be1321b"
        );
        assert!(block.contains("x-amz-content-sha256: UNSIGNED-PAYLOAD\r\n"));
    }

    #[test]
    fn kat_custom_provider_casing() {
        let input = SigV4Input {
            sigv4_param: Some("oss:cos:cn-hangzhou:svc"),
            hostname: "host.example.com",
            method: "GET",
            httpreq: HttpReq::Get,
            access_key_id: "AK",
            secret_key: Some("SK"),
            url_path: "/",
            ..Default::default()
        };
        let block = sign(&input, 1_440_938_160);
        assert_eq!(
            field(&block, "Signature="),
            "0e700201f4fab5d1e33260c69e435635e7baa1958b40a2273ed75b2ba70b0b7c"
        );
        assert!(block.starts_with("Authorization: OSS4-HMAC-SHA256 "));
        assert_eq!(field(&block, "SignedHeaders="), "host;x-cos-date");
        assert_eq!(
            field(&block, "Credential="),
            "AK/20150830/cn-hangzhou/svc/oss4_request"
        );
        // The date header name uses the ucfirst provider: "X-Cos-Date".
        assert!(block.contains("\r\nX-Cos-Date: 20150830T123600Z\r\n"));
    }

    #[test]
    fn kat_post_with_body() {
        let body = br#"{"hello":"world"}"#;
        let input = SigV4Input {
            sigv4_param: Some("aws:amz:us-east-2:es"),
            hostname: "api.example.com",
            method: "POST",
            httpreq: HttpReq::Post,
            access_key_id: "user",
            secret_key: Some("secret"),
            url_path: "/path/",
            body: Some(body),
            ..Default::default()
        };
        let block = sign(&input, 0);
        assert_eq!(
            field(&block, "Signature="),
            "89b29a1e76ed1291b743b62015ced0eff3f55aa4c212a0390dc91b9e0b467f4d"
        );
    }

    #[test]
    fn canonical_request_and_string_to_sign_get_vanilla() {
        // Rebuild the canonical request from the same helpers `compute_signature`
        // uses and confirm it matches the AWS-documented get-vanilla example.
        let mut ts = "20150830T123600Z".to_string();
        let made = make_headers(&[], None, "example.amazonaws.com", &mut ts, "amz", None).unwrap();
        let cp = canon_path("/", true);
        let cq = canon_query(None).unwrap();
        let payload = sha256_to_hex(Sha256::digest(b"").as_slice());
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            "GET", cp, cq, made.canonical_headers, made.signed_headers, payload
        );
        assert_eq!(
            canonical_request,
            "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\n\
             host;x-amz-date\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let cr_hash = sha256_to_hex(Sha256::digest(canonical_request.as_bytes()).as_slice());
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            "20150830T123600Z", "20150830/us-east-1/service/aws4_request", cr_hash
        );
        assert_eq!(
            string_to_sign,
            "AWS4-HMAC-SHA256\n20150830T123600Z\n\
             20150830/us-east-1/service/aws4_request\n\
             bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
        );
    }

    // --- public entry point smoke test ----------------------------------

    #[test]
    fn output_aws_sigv4_produces_wellformed_block() {
        // Uses the real clock, so the signature is not asserted — only the
        // structural invariants that hold regardless of the timestamp.
        let input = SigV4Input {
            sigv4_param: Some("aws:amz:us-east-1:service"),
            hostname: "example.amazonaws.com",
            access_key_id: "AKIDEXAMPLE",
            secret_key: Some("secret"),
            url_path: "/",
            ..Default::default()
        };
        let block = output_aws_sigv4(&input).unwrap().unwrap();
        assert!(block.starts_with("Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"));
        assert!(block.contains("SignedHeaders=host;x-amz-date"));
        assert!(block.contains("Signature="));
        assert!(block.ends_with("\r\n"));
    }
}
