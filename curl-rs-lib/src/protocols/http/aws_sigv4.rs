//! AWS Signature Version 4 request signing (`CURLAUTH_AWS_SIGV4`).
//!
//! This module is the memory-safe Rust reimplementation of curl's
//! `lib/http_aws_sigv4.c` (entry point `Curl_output_aws_sigv4`). Its behavioral
//! and ABI oracle is that C translation unit, read in full and reproduced
//! **byte-for-byte**: the canonical request, the string-to-sign, the
//! signing-key HMAC chain, and the final `Authorization: AWS4-HMAC-SHA256 …`
//! header value are all generated identically to curl 8.x so that the upstream
//! regression suite (the `--aws-sigv4` tests — `tests/data/test1955`–`test1980`,
//! `test472`, the `lib19xx` ABI drivers) passes unmodified. Every quirk of the
//! C implementation is preserved deliberately (the default `aws:amz` provider,
//! the S3 `UNSIGNED-PAYLOAD` special-casing, the `%2B`-stays-encoded query
//! normalization, the case-sensitive header sort).
//!
//! # Where this fits
//!
//! SigV4 is a **host-only** signer (`lib/http.c` `output_auth_headers`: "this
//! method is never for proxy"); the request builder calls it exactly when the
//! picked *host* authentication is `CURLAUTH_AWS_SIGV4`. Although the C dispatch
//! lives in `http.c`, the entire algorithm lives in `http_aws_sigv4.c`, so this
//! module is self-contained and **independent of `crate::auth`**.
//!
//! # Integration contract
//!
//! In the C tree the signer reads a large amount of state directly from the
//! `Curl_easy`/`connectdata` handles (`data->set.*`, `data->state.aptr.*`,
//! `data->state.up.*`, `conn->host.name`). Those engine structs are authored by
//! sibling migration steps; to stay decoupled from their in-flight shape, this
//! module defines a small, explicit **input contract** — [`HttpRequestCtx`] —
//! that the HTTP/1 request builder (`h1.rs`) populates from its parsed URL
//! ([`crate::url::ParsedUrl`]), its request-header set, and the easy-handle
//! options. The signer is a pure function of that context: it returns the
//! headers to add ([`Sigv4Headers`]) rather than mutating engine state, which
//! keeps it trivially testable against the published AWS test vectors.
//!
//! Two modeling choices are deliberate and documented here so they are not
//! mistaken for omissions:
//!
//! * **Request headers are carried as raw `Vec<String>` lines** (mirroring
//!   curl's `data->set.headers` `curl_slist`) rather than as a
//!   [`crate::headers::DynHds`]. Byte-for-byte parity requires the *raw* user
//!   header lines, because curl's canonicalization depends on the original
//!   `name;` vs `name:` form (a trailing `;` signals "send an empty header" and
//!   is rewritten to `:`; a bare `name:` signals "remove" and is dropped) — a
//!   distinction a split name/value container cannot represent.
//! * **The request path and query are carried as owned strings** taken from the
//!   already-parsed URL, rather than borrowing a [`crate::url::CurlUrl`]. This
//!   decouples the signer from the URL engine and matches curl, which reads the
//!   *post-parse* `data->state.up.path` / `.query`.
//!
//! # Memory safety
//!
//! Pure safe Rust: zero `unsafe`. The crate root and `protocols/mod.rs` already
//! carry `#![forbid(unsafe_code)]`, so it is intentionally **not** re-declared
//! here.

use crate::error::{CurlError, Result};
use crate::util::hmac::hmac_sha256;
use crate::util::sha256::{sha256it, CURL_SHA256_DIGEST_LENGTH};
use crate::util::strparse::{curlx_hexval, curlx_str_casecompare, curlx_str_cmp, Str};

use chrono::{DateTime, Utc};

// ===========================================================================
// Constants — exact mirrors of the `#define`s in `lib/http_aws_sigv4.c`.
// ===========================================================================

/// Maximum length, in non-`:` bytes, of each `aws-sigv4` parameter
/// (`provider0`, `provider1`, `region`, `service`). C: `MAX_SIGV4_LEN`.
const MAX_SIGV4_LEN: usize = 64;

/// Maximum number of `&`-separated query components curl will canonicalize
/// before failing with [`CurlError::TooLarge`]. C: `MAX_QUERY_COMPONENTS`.
const MAX_QUERY_COMPONENTS: usize = 128;

/// Length of the `YYYYMMDDTHHMMSSZ` timestamp **without** the C string's NUL
/// terminator (C `TIMESTAMP_SIZE` is `17`, i.e. these 16 bytes plus `\0`).
const TIMESTAMP_LEN: usize = 16;

/// Length of the short `YYYYMMDD` credential-scope date.
const SHORT_DATE_LEN: usize = 8;

/// The S3 sentinel payload hash used when the request body is not available for
/// hashing. C: `S3_UNSIGNED_PAYLOAD`.
const S3_UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// Lowercase SHA-256 of the empty input — the canonical payload hash for a
/// request with no body. The signer always *computes* this via
/// [`sha256_hex`]`(&sha256it(b""))` (mirroring curl, which never special-cases
/// it); this pinned copy exists only so the unit tests can assert the computed
/// value against the well-known constant, hence `#[cfg(test)]`.
#[cfg(test)]
const EMPTY_SHA256_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// ===========================================================================
// Public input/output contract
// ===========================================================================

/// HTTP request method classification, mirroring curl's `Curl_HttpReq`
/// (`lib/http.h`) including its exact discriminant order. SigV4 only needs to
/// distinguish the body-bearing kinds for the S3 payload-hash decision, but the
/// full set is modeled so the mapping from the engine is lossless.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpReq {
    /// `HTTPREQ_GET`.
    Get,
    /// `HTTPREQ_POST` — an in-memory `CURLOPT_POSTFIELDS` body.
    Post,
    /// `HTTPREQ_POST_FORM` — a legacy `curl_formadd` multipart body.
    PostForm,
    /// `HTTPREQ_POST_MIME` — a `curl_mime` multipart body.
    PostMime,
    /// `HTTPREQ_PUT`.
    Put,
    /// `HTTPREQ_HEAD`.
    Head,
}

impl HttpReq {
    /// True for the request kinds curl treats as having no request payload by
    /// method alone (`GET`/`HEAD`). C: `empty_method` in `calc_s3_payload_hash`.
    #[must_use]
    pub const fn is_get_or_head(self) -> bool {
        matches!(self, HttpReq::Get | HttpReq::Head)
    }

    /// True for a plain `POST` (the only kind whose in-memory `postfields` curl
    /// hashes on the S3 path). C: `httpreq == HTTPREQ_POST`.
    #[must_use]
    pub const fn is_post(self) -> bool {
        matches!(self, HttpReq::Post)
    }
}

/// The complete set of request inputs the SigV4 signer reads.
///
/// Each field documents the `Curl_easy`/`connectdata` member it stands in for,
/// so the request builder can populate it mechanically. The signer never
/// mutates this context.
#[derive(Debug, Clone)]
pub struct HttpRequestCtx {
    /// Wire request method string, e.g. `"GET"`/`"POST"` (C: the `method`
    /// out-param of `Curl_http_method`). Used verbatim as the first line of the
    /// canonical request.
    pub method: String,
    /// Request-method classification (C: the `httpreq` out-param of
    /// `Curl_http_method`). Drives the S3 payload-hash decision only.
    pub httpreq: HttpReq,
    /// Target host without scheme or path (C: `conn->host.name`). Used to derive
    /// the default `host:` canonical header and, when `region`/`service` are not
    /// given in the provider spec, the credential scope.
    pub hostname: String,
    /// Post-parse request path, always at least `"/"` (C: `data->state.up.path`).
    pub path: String,
    /// Post-parse query string without the leading `?` (C:
    /// `data->state.up.query`); `None` when the URL has no query.
    pub query: Option<String>,
    /// The user-supplied request headers as **raw** `"Name: Value"` lines, in
    /// the order set (C: `data->set.headers`, the `CURLOPT_HTTPHEADER`
    /// `curl_slist`). See the module docs for why the raw form is required.
    pub headers: Vec<String>,
    /// The already-formatted `Host` header line curl would send, e.g.
    /// `"Host: example.com\r\n"` (C: `data->state.aptr.host`). When present and
    /// the user set no explicit `Host` header, it is the source of the canonical
    /// `host:` line; `None` falls back to `host:{hostname}`.
    pub aptr_host: Option<String>,
    /// The access-key id (C: `data->state.aptr.user`); `None`/empty becomes the
    /// empty `Credential=` user component.
    pub user: Option<String>,
    /// The secret access key (C: `data->state.aptr.passwd`); `None`/empty signs
    /// with an empty secret tail (`"AWS4"`).
    pub passwd: Option<String>,
    /// The raw `CURLOPT_AWS_SIGV4` provider spec
    /// `provider0[:provider1[:region[:service]]]` (C:
    /// `data->set.str[STRING_AWS_SIGV4]`); `None`/empty defaults to `"aws:amz"`.
    pub sigv4: Option<String>,
    /// `CURLOPT_PATH_AS_IS` (C: `data->set.path_as_is`). SigV4 is incompatible
    /// with it and rejects the request when set.
    pub path_as_is: bool,
    /// The in-memory request body, if any (C: `data->set.postfields`). Hashed
    /// for the payload hash on non-S3 requests and on the S3 POST path.
    pub postfields: Option<Vec<u8>>,
    /// The configured `postfields` length (C: `data->set.postfieldsize`); a
    /// negative value means "NUL-terminated, use the byte length", matching
    /// curl's `< 0 ⇒ strlen` convention.
    pub postfieldsize: i64,
    /// The configured upload size (C: `data->set.filesize`); `0` marks an
    /// explicitly empty payload on the S3 path.
    pub filesize: i64,
    /// Test/replay hook mirroring curl's debug-build `CURL_FORCETIME`: when
    /// `Some(epoch_seconds)` and no request date header is present, the signing
    /// timestamp is taken from this instant instead of the wall clock. `None`
    /// uses [`Utc::now`]. (curl forces epoch `0`, i.e. `19700101T000000Z`.)
    pub force_epoch: Option<i64>,
}

impl HttpRequestCtx {
    /// Creates a context for `method`/`hostname`/`path` with every other field
    /// at its inert default (no headers, no credentials, default provider, live
    /// clock). Convenience for callers and tests that set only what they need.
    #[must_use]
    pub fn new(
        method: impl Into<String>,
        hostname: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        HttpRequestCtx {
            method: method.into(),
            httpreq: HttpReq::Get,
            hostname: hostname.into(),
            path: path.into(),
            query: None,
            headers: Vec::new(),
            aptr_host: None,
            user: None,
            passwd: None,
            sigv4: None,
            path_as_is: false,
            postfields: None,
            postfieldsize: -1,
            filesize: -1,
            force_epoch: None,
        }
    }
}

/// The headers the signer produces for a request.
///
/// `h1.rs` applies these to the outgoing request: it adds an `Authorization`
/// header whose value is [`Self::authorization`], then adds each
/// [`Self::extra_headers`] entry. The extra headers are exactly the ones curl
/// *generates* (and therefore must inject) — the `x-{provider1}-date` header
/// when the caller supplied none, and the S3 `x-{provider1}-content-sha256`
/// header. Headers the caller already supplied are **not** echoed here because
/// they are already on the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sigv4Headers {
    /// The `Authorization` header **value** (without the `"Authorization: "`
    /// name prefix and without a trailing CRLF), e.g.
    /// `"AWS4-HMAC-SHA256 Credential=…/…, SignedHeaders=…, Signature=…"`.
    pub authorization: String,
    /// `(name, value)` pairs curl generated and that must be added to the
    /// request, in curl's emission order (date header first, then the S3
    /// content hash header). Each `name` is already in the exact case curl
    /// sends (`X-Amz-Date`, `x-amz-content-sha256`).
    pub extra_headers: Vec<(String, String)>,
}

// ===========================================================================
// Low-level encoding helpers
// ===========================================================================

/// Lowercase hex digit table (curl uses a lowercase table for digest output).
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
/// Uppercase hex digit table (curl percent-encodes with uppercase nibbles).
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Lowercase hex-encodes `bytes`, matching curl's `Curl_hexencode` lowercase
/// digit table. Used to render SHA-256 digests and HMAC signatures.
fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_LOWER[(b >> 4) as usize] as char);
        out.push(HEX_LOWER[(b & 0x0f) as usize] as char);
    }
    out
}

/// Hex-encodes a 32-byte SHA-256 digest to a 64-character lowercase string.
///
/// Mirrors the C `sha256_to_hex` helper, which renders the digest produced by
/// `Curl_sha256it` into the lowercase hex form AWS requires for the payload
/// hash, the hashed canonical request, and the empty-payload sentinel.
fn sha256_hex(digest: &[u8; CURL_SHA256_DIGEST_LENGTH]) -> String {
    hex_lower(digest)
}

/// Appends the uppercase two-digit hex encoding of `b` to `out` (no `%` prefix).
fn push_hex_upper(out: &mut String, b: u8) {
    out.push(HEX_UPPER[(b >> 4) as usize] as char);
    out.push(HEX_UPPER[(b & 0x0f) as usize] as char);
}

/// RFC 3986 *unreserved* test.
///
/// This reproduces curl's `is_reserved_char` predicate — whose name is a
/// misnomer: it actually returns true for characters that must **not** be
/// percent-encoded, namely ASCII alphanumerics plus `-`, `.`, `_` and `~`
/// (the C expression `ISALNUM(c) || ISURLPUNTCS(c)`).
fn is_unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~')
}

// ===========================================================================
// Canonical URI path  (C: uri_encode_path / canon_path)
// ===========================================================================

/// Percent-encodes a path per curl's `uri_encode_path`.
///
/// Every unreserved byte and the path separator `/` pass through literally;
/// every other byte is emitted as an uppercase `%XX` escape. AWS SigV4 requires
/// the canonical URI to be the *encoded* path (with `/` left intact), so this is
/// distinct from generic component encoding.
fn uri_encode_path(path: &[u8]) -> String {
    let mut out = String::with_capacity(path.len());
    for &c in path {
        if is_unreserved(c) || c == b'/' {
            out.push(c as char);
        } else {
            out.push('%');
            push_hex_upper(&mut out, c);
        }
    }
    out
}

/// Builds the canonical URI path (C: `canon_path`).
///
/// When `do_uri_encode` is set (every service except S3 and its variants) the
/// path is percent-encoded via [`uri_encode_path`]; otherwise the already-stored
/// path is taken verbatim (S3 signs the literal, un-normalized path). An empty
/// path canonicalizes to `"/"`, exactly as curl does.
fn canon_path(path: &str, do_uri_encode: bool) -> String {
    let mut out = if do_uri_encode {
        uri_encode_path(path.as_bytes())
    } else {
        path.to_string()
    };
    if out.is_empty() {
        out.push('/');
    }
    out
}

// ===========================================================================
// Canonical query string  (C: normalize_query / canon_query)
// ===========================================================================

/// Normalizes one query key or value per curl's `normalize_query`.
///
/// The input is first percent-*decoded* (only well-formed `%XX` escapes, where
/// both following bytes are hex digits, are treated as escapes) and then
/// re-encoded per the AWS canonicalization rules, with two crucial special
/// cases that curl implements and that must be preserved byte-for-byte:
///
/// * An encoded `%2B` (which decodes to `+`) is **kept verbatim** as `%2B`. It
///   is never decoded to `+` and then re-encoded — doing so would corrupt the
///   signature for any value legitimately containing a `+`.
/// * A *literal* `+` is encoded to `%20`, because AWS treats a literal `+` in a
///   query string as an encoded space.
///
/// All other bytes are passed through if unreserved, or emitted as uppercase
/// `%XX` otherwise. A lone or truncated `%` (not followed by two hex digits) is
/// itself encoded as `%25`.
fn normalize_query(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    let len = input.len();
    while i < len {
        // Attempt to decode a `%XX` escape at the current position. curl's guard
        // is `(remaining > 2) && ISXDIGIT(s[1]) && ISXDIGIT(s[2])`.
        let decoded = if input[i] == b'%' && (len - i) > 2 {
            match (curlx_hexval(input[i + 1]), curlx_hexval(input[i + 2])) {
                (Some(hi), Some(lo)) => Some((hi << 4) | lo),
                _ => None,
            }
        } else {
            None
        };

        let byte = if let Some(b) = decoded {
            i += 3;
            if b == b'+' {
                // Decoded to '+': preserve the encoded form, do not re-encode.
                out.push_str("%2B");
                continue;
            }
            b
        } else {
            let b = input[i];
            i += 1;
            b
        };

        if is_unreserved(byte) {
            out.push(byte as char);
        } else if byte == b'+' {
            // A literal '+' represents a space in a query component.
            out.push_str("%20");
        } else {
            out.push('%');
            push_hex_upper(&mut out, byte);
        }
    }
    out
}

/// Builds the canonical query string (C: `canon_query` + `split_to_dyn_array`).
///
/// The raw query (everything after `?`, already stripped of the leading `?` by
/// the URL parser) is split on `&`; empty segments are dropped. Each segment is
/// split into a key and value on the first `=` (a trailing `=` or a missing `=`
/// yields an empty value). Key and value are individually normalized via
/// [`normalize_query`], the resulting pairs are sorted by encoded key and then
/// encoded value, and finally re-joined as `key=value` pairs with `&`.
///
/// curl caps the number of components at [`MAX_QUERY_COMPONENTS`]; exceeding the
/// cap yields [`CurlError::TooLarge`] (`CURLE_TOO_LARGE`), preserving error
/// parity with the C implementation.
fn canon_query(query: Option<&str>) -> Result<String> {
    let query = match query {
        Some(q) => q,
        None => return Ok(String::new()),
    };

    let mut components: Vec<(String, String)> = Vec::new();
    for segment in query.as_bytes().split(|&b| b == b'&') {
        if segment.is_empty() {
            // curl's splitter skips empty fields produced by `&&` or a leading
            // / trailing `&`.
            continue;
        }

        // Split key/value on the first '='. A '=' that is the final byte of the
        // segment denotes an explicit empty value, identical to no '=' at all.
        let (key_bytes, value_bytes): (&[u8], &[u8]) = match segment.iter().position(|&b| b == b'=')
        {
            Some(eq) if eq + 1 < segment.len() => (&segment[..eq], &segment[eq + 1..]),
            Some(eq) => (&segment[..eq], &[][..]),
            None => (segment, &[][..]),
        };

        let key = normalize_query(key_bytes);
        let value = normalize_query(value_bytes);
        components.push((key, value));

        // curl errors once the component count reaches the cap.
        if components.len() == MAX_QUERY_COMPONENTS {
            return Err(CurlError::TooLarge);
        }
    }

    // Sort by (encoded key, encoded value). Standard tuple ordering reproduces
    // curl's `compare_func`, where an empty key or value sorts first.
    components.sort();

    let mut out = String::new();
    for (idx, (key, value)) in components.iter().enumerate() {
        if idx > 0 {
            out.push('&');
        }
        out.push_str(key);
        out.push('=');
        out.push_str(value);
    }
    Ok(out)
}

// ===========================================================================
// Request-header inspection  (C: Curl_checkheaders / find_date_hdr)
// ===========================================================================

/// Returns the name portion of a `"Name:Value"` header line (the bytes before
/// the first `:`), or the whole line if there is no `:`. Used for the
/// case-sensitive canonical sort and duplicate-merge, which operate on already
/// lowercased names that always carry a `:` at this stage.
fn header_name_bytes(line: &str) -> &[u8] {
    let bytes = line.as_bytes();
    let end = bytes.iter().position(|&b| b == b':').unwrap_or(bytes.len());
    &bytes[..end]
}

/// True when `line`'s header name equals `name` case-insensitively, with the
/// name terminated by a `:` or `;` separator.
///
/// Mirrors curl's `Curl_checkheaders` matching rule: the leading
/// `strlen(name)` bytes match case-insensitively *and* the following byte is a
/// header separator (`Curl_headersep` ⇒ `:` or `;`). A line equal to `name`
/// with no separator does not match.
fn header_name_matches(line: &str, name: &str) -> bool {
    let bytes = line.as_bytes();
    let nlen = name.len();
    if bytes.len() <= nlen {
        return false;
    }
    if !bytes[..nlen].eq_ignore_ascii_case(name.as_bytes()) {
        return false;
    }
    matches!(bytes[nlen], b':' | b';')
}

/// Returns the first user header line whose name matches `name`
/// (case-insensitively, separator-terminated), or `None`.
///
/// Direct analogue of C's `Curl_checkheaders(data, name, len)` restricted to the
/// `data->set.headers` list (SigV4 only ever inspects user-supplied headers).
fn checkheaders<'a>(headers: &'a [String], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .map(String::as_str)
        .find(|line| header_name_matches(line, name))
}

/// Finds the request date header: the provider-specific `X-<Provider1>-Date`
/// header if present, otherwise a plain `Date` header. C: `find_date_hdr`.
fn find_date_hdr<'a>(headers: &'a [String], sig_hdr: &str) -> Option<&'a str> {
    checkheaders(headers, sig_hdr).or_else(|| checkheaders(headers, "Date"))
}

/// Extracts the `YYYYMMDDTHHMMSSZ` timestamp embedded in a user-supplied date
/// header value (C: the `else` branch of the date handling in `make_headers`).
///
/// The value after the `:` is read past leading blanks, then the run of
/// alphanumeric bytes is taken; if that run is exactly [`TIMESTAMP_LEN`] (16)
/// bytes it is the timestamp, otherwise the timestamp is treated as empty
/// (curl's "bad timestamp length" path). Returns `None` only when there is no
/// `:` at all, which curl treats as a hard error.
fn extract_timestamp(date_header: &str) -> Option<String> {
    let bytes = date_header.as_bytes();
    let colon = bytes.iter().position(|&b| b == b':')?;
    let mut i = colon + 1;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
        i += 1;
    }
    let start = i;
    while i < bytes.len() && bytes[i].is_ascii_alphanumeric() {
        i += 1;
    }
    if i - start == TIMESTAMP_LEN {
        Some(date_header[start..i].to_string())
    } else {
        Some(String::new())
    }
}

// ===========================================================================
// Header canonicalization  (C: trim_headers / compare_header_names /
//                              merge_duplicate_headers / make_headers)
// ===========================================================================

/// Canonicalizes a single header line in the manner of curl's `trim_headers`:
///
/// * the header **name** (up to the first `:`) is lowercased;
/// * the **value** has leading and trailing ASCII blanks removed and every
///   internal run of blanks collapsed to a single space;
/// * the case of the value is otherwise preserved.
///
/// A line with no `:` is returned fully lowercased with no value processing,
/// matching the C edge case (though every line reaching this point has a `:`).
fn trim_header_line(line: &str) -> String {
    let bytes = line.as_bytes();
    let colon = bytes.iter().position(|&b| b == b':').unwrap_or(bytes.len());

    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    for &b in &bytes[..colon] {
        out.push(b.to_ascii_lowercase());
    }
    if colon == bytes.len() {
        // No separator: whole line is the (lowercased) name, no value to trim.
        return String::from_utf8(out).unwrap_or_default();
    }
    out.push(b':');

    let value = &bytes[colon + 1..];
    let is_blank = |c: u8| c == b' ' || c == b'\t';

    // Skip leading blanks.
    let mut i = 0;
    while i < value.len() && is_blank(value[i]) {
        i += 1;
    }
    while i < value.len() {
        if is_blank(value[i]) {
            // Collapse a run of blanks; emit a single space only if more
            // non-blank content follows (i.e. never a trailing space).
            let mut j = i;
            while j < value.len() && is_blank(value[j]) {
                j += 1;
            }
            if j < value.len() {
                out.push(b' ');
            }
            i = j;
        } else {
            out.push(value[i]);
            i += 1;
        }
    }
    // Only ASCII blanks were dropped and only ASCII letters lowercased, so the
    // bytes remain valid UTF-8.
    String::from_utf8(out).unwrap_or_default()
}

/// Merges adjacent headers that share a name by comma-joining their values, in
/// place, expecting the list to already be name-sorted. C:
/// `merge_duplicate_headers`.
fn merge_duplicate_headers(head: &mut Vec<String>) {
    let mut i = 0;
    while i < head.len() {
        if i + 1 < head.len() && header_name_bytes(&head[i]) == header_name_bytes(&head[i + 1]) {
            // Remove the successor and append its value (everything after its
            // ':') onto the current header, comma-separated.
            let next = head.remove(i + 1);
            let val_next = match next.as_bytes().iter().position(|&b| b == b':') {
                Some(c) => &next[c + 1..],
                None => "",
            };
            head[i].push(',');
            head[i].push_str(val_next);
            // Do not advance: re-check the merged header against the new
            // successor, exactly as the C loop does.
        } else {
            i += 1;
        }
    }
}

/// Lowercases every byte of `provider1` (C: `provider1` is used verbatim for the
/// lowercase `x-…-date`/`x-…-content-sha256` keys).
fn provider_lower(provider1: &[u8]) -> Vec<u8> {
    provider1.iter().map(u8::to_ascii_lowercase).collect()
}

/// Builds the `X-<Provider1>-Date` header *key* with the provider segment in
/// `Ucfirst` form (C: `date_hdr_key`, built by lowercasing the provider then
/// uppercasing its first byte).
fn date_header_key(provider1: &[u8]) -> String {
    let mut key: Vec<u8> = Vec::with_capacity(provider1.len() + 7);
    key.extend_from_slice(b"X-");
    for (idx, &b) in provider1.iter().enumerate() {
        let lb = b.to_ascii_lowercase();
        key.push(if idx == 0 {
            lb.to_ascii_uppercase()
        } else {
            lb
        });
    }
    key.extend_from_slice(b"-Date");
    String::from_utf8(key).unwrap_or_default()
}

/// Result of header canonicalization: the assembled canonical-headers block and
/// signed-headers list, the (possibly header-overridden) timestamp, and the
/// date header to *emit* when curl synthesizes one.
struct MadeHeaders {
    canonical_headers: String,
    signed_headers: String,
    timestamp: String,
    date_emit: Option<(String, String)>,
}

/// Reproduces curl's `make_headers`: assembles the host header, any
/// S3 content-sha256 header, and the filtered/canonicalized user headers into
/// the sorted, duplicate-merged canonical-headers block and the matching
/// signed-headers list. May override `timestamp` from a user date header and,
/// when none is supplied, schedules emission of the synthesized date header.
fn make_headers(
    ctx: &HttpRequestCtx,
    hostname: &str,
    mut timestamp: String,
    provider1: &[u8],
    content_sha256_header: Option<&str>,
) -> Result<MadeHeaders> {
    let date_hdr_key = date_header_key(provider1);

    // date_full_hdr = "x-<provider1-lower>-date:<timestamp>" (already canonical).
    let date_full_hdr = {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(b"x-");
        v.extend_from_slice(&provider_lower(provider1));
        v.extend_from_slice(b"-date:");
        v.extend_from_slice(timestamp.as_bytes());
        String::from_utf8(v).unwrap_or_default()
    };

    let mut head: Vec<String> = Vec::new();

    // Auto Host header, unless the user supplied one.
    if checkheaders(&ctx.headers, "Host").is_none() {
        let host_line = if let Some(aptr) = &ctx.aptr_host {
            // Use the already-formatted "Host: …" line, truncated at the first
            // CR/LF (the canonical-request separator must be a bare '\n').
            let abytes = aptr.as_bytes();
            let end = abytes
                .iter()
                .position(|&b| b == b'\r' || b == b'\n')
                .unwrap_or(abytes.len());
            aptr[..end].to_string()
        } else {
            format!("host:{hostname}")
        };
        head.push(host_line);
    }

    // S3-synthesized content hash header (added before user headers, as in C).
    if let Some(cs) = content_sha256_header {
        head.push(cs.to_string());
    }

    // Copy user headers, applying curl's filtering rules (http.c-derived):
    //   * a line with neither ':' nor ';' is skipped;
    //   * "name:" with an empty value (header removal) is skipped;
    //   * a value of only whitespace is skipped;
    //   * "name;" (send empty header) is kept, the ';' rewritten to ':'.
    for line in &ctx.headers {
        let bytes = line.as_bytes();
        let sep_pos = match bytes.iter().position(|&b| b == b':') {
            Some(p) => p,
            None => match bytes.iter().position(|&b| b == b';') {
                Some(p) => p,
                None => continue, // no separator at all
            },
        };
        let sep_is_colon = bytes[sep_pos] == b':';

        // "name:" with nothing after the colon → removal signal, skip.
        if sep_is_colon && sep_pos + 1 >= bytes.len() {
            continue;
        }

        // Whitespace-only value → skip (but "name;" with an empty tail is kept).
        let rest = &bytes[sep_pos + 1..];
        let first_nonblank = rest.iter().position(|&b| b != b' ' && b != b'\t');
        if first_nonblank.is_none() && !rest.is_empty() {
            continue;
        }

        // Duplicate the line, rewriting a ';' separator to ':'.
        let dup = if sep_is_colon {
            line.clone()
        } else {
            let mut s = String::with_capacity(line.len());
            s.push_str(&line[..sep_pos]);
            s.push(':');
            s.push_str(&line[sep_pos + 1..]);
            s
        };
        head.push(dup);
    }

    // Trim/lowercase every collected header line.
    for line in &mut head {
        *line = trim_header_line(line);
    }

    // Date header: extract its timestamp if the user supplied one, else
    // synthesize the canonical date header and schedule emission.
    let date_emit = match find_date_hdr(&ctx.headers, &date_hdr_key) {
        Some(user_line) => {
            match extract_timestamp(user_line) {
                Some(ts) => timestamp = ts,
                None => return Err(CurlError::OutOfMemory),
            }
            None
        }
        None => {
            head.push(date_full_hdr);
            Some((date_hdr_key, timestamp.clone()))
        }
    };

    // Case-sensitive alphabetical sort by header name (names are lowercased, so
    // this equals a case-insensitive sort of the originals). Rust's sort is
    // stable, preserving insertion order among equal names for the merge step —
    // exactly as curl's stable bubble sort does.
    head.sort_by(|a, b| header_name_bytes(a).cmp(header_name_bytes(b)));

    merge_duplicate_headers(&mut head);

    // Build the canonical-headers block ("name:value\n" per line) and the
    // signed-headers list (";"-joined names).
    let mut canonical_headers = String::new();
    let mut signed_headers = String::new();
    for (idx, line) in head.iter().enumerate() {
        canonical_headers.push_str(line);
        canonical_headers.push('\n');
        if idx > 0 {
            signed_headers.push(';');
        }
        // Names are lowercase ASCII at this point.
        signed_headers.push_str(core::str::from_utf8(header_name_bytes(line)).unwrap_or(""));
    }

    Ok(MadeHeaders {
        canonical_headers,
        signed_headers,
        timestamp,
        date_emit,
    })
}

// ===========================================================================
// Payload hashing  (C: parse_content_sha_hdr / calc_payload_hash /
//                      calc_s3_payload_hash)
// ===========================================================================

/// Reads a caller-supplied `x-<provider1>-content-sha256` header value, if any
/// (C: `parse_content_sha_hdr`). The returned slice is the value with leading
/// and trailing blanks removed.
fn parse_content_sha_hdr<'a>(headers: &'a [String], provider1: &[u8]) -> Option<&'a str> {
    let mut key = String::from("x-");
    key.push_str(core::str::from_utf8(provider1).unwrap_or(""));
    key.push_str("-content-sha256");

    let line = checkheaders(headers, &key)?;
    let bytes = line.as_bytes();
    let colon = bytes.iter().position(|&b| b == b':')?;
    let mut start = colon + 1;
    while start < bytes.len() && matches!(bytes[start], b' ' | b'\t') {
        start += 1;
    }
    let mut end = bytes.len();
    while end > start && matches!(bytes[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    Some(&line[start..end])
}

/// Returns the in-memory request body curl would hash: `postfields` truncated to
/// `postfieldsize` when that is non-negative, the whole NUL-terminated buffer
/// when it is negative, or empty when there are no `postfields`.
fn payload_bytes(ctx: &HttpRequestCtx) -> &[u8] {
    match &ctx.postfields {
        Some(pf) => {
            if ctx.postfieldsize < 0 {
                pf.as_slice()
            } else {
                let n = ctx.postfieldsize as usize;
                &pf[..n.min(pf.len())]
            }
        }
        None => &[],
    }
}

/// Computes the lowercase hex SHA-256 of the request payload (C:
/// `calc_payload_hash`). An absent body hashes the empty input.
fn calc_payload_hash(ctx: &HttpRequestCtx) -> String {
    sha256_hex(&sha256it(payload_bytes(ctx)))
}

/// Computes the S3 payload hash (C: `calc_s3_payload_hash`): a real SHA-256 when
/// the body is known to be empty or is an in-memory POST, otherwise the
/// `UNSIGNED-PAYLOAD` sentinel.
fn calc_s3_payload_hash(ctx: &HttpRequestCtx) -> String {
    let empty_method = ctx.httpreq.is_get_or_head();
    // The request method or an explicit zero filesize indicates no payload.
    let empty_payload = empty_method || ctx.filesize == 0;
    // A POST with in-memory postfields has a hashable payload.
    let post_payload = ctx.httpreq.is_post() && ctx.postfields.is_some();

    if empty_payload || post_payload {
        calc_payload_hash(ctx)
    } else {
        S3_UNSIGNED_PAYLOAD.to_string()
    }
}

/// Decides whether the canonical URI path must be percent-encoded (C:
/// `should_urlencode`). S3 and its variants sign the path verbatim; every other
/// service requires encoding. The comparison is case-sensitive, matching curl.
fn should_urlencode(service: &Str) -> bool {
    !(curlx_str_cmp(service, "s3")
        || curlx_str_cmp(service, "s3-express")
        || curlx_str_cmp(service, "s3-outposts"))
}

// ===========================================================================
// Entry point  (C: Curl_output_aws_sigv4)
// ===========================================================================

/// Produces the AWS SigV4 `Authorization` header (and any headers curl must add
/// alongside it) for a request, or `None` when signing is a no-op.
///
/// This is the Rust port of `Curl_output_aws_sigv4`. It is a pure function of
/// [`HttpRequestCtx`]: it reads the request method, URL path/query, headers and
/// credentials from `ctx` and returns the [`Sigv4Headers`] the request builder
/// must apply. It never mutates `ctx` or any engine state.
///
/// # Returns
///
/// * `Ok(Some(headers))` — the request must be signed; apply `headers`.
/// * `Ok(None)` — signing is a no-op because the caller already supplied an
///   `Authorization` header (curl's "Authorization already present, bailing
///   out" path).
///
/// # Errors
///
/// * [`CurlError::BadFunctionArgument`] — SigV4 was requested together with
///   `CURLOPT_PATH_AS_IS`, or the provider spec's first field is empty.
/// * [`CurlError::UrlMalformat`] — neither the provider spec nor the hostname
///   yields a service (and, when needed, a region).
/// * [`CurlError::TooLarge`] — the query string has too many components
///   (≥ [`MAX_QUERY_COMPONENTS`]).
/// * [`CurlError::OutOfMemory`] — a supplied date header is malformed (parity
///   with curl's corresponding failure).
pub fn output_aws_sigv4(ctx: &HttpRequestCtx) -> Result<Option<Sigv4Headers>> {
    // SigV4 is incompatible with path-as-is (curl rejects the combination).
    if ctx.path_as_is {
        return Err(CurlError::BadFunctionArgument);
    }

    // If the caller already provided an Authorization header, do nothing.
    if checkheaders(&ctx.headers, "Authorization").is_some() {
        return Ok(None);
    }

    // --- Provider spec parsing: provider0[:provider1[:region[:service]]] ------
    // Default is "aws:amz" because most non-Amazon providers reuse it.
    let line: &str = match ctx.sigv4.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => "aws:amz",
    };
    let mut cursor = Str::new(line);
    let mut provider0 = Str::default();
    let mut provider1 = Str::default();
    let mut region = Str::default();
    let mut service = Str::default();

    if cursor
        .curlx_str_until(&mut provider0, MAX_SIGV4_LEN, b':')
        .is_err()
    {
        // First provider field cannot be empty.
        return Err(CurlError::BadFunctionArgument);
    }
    if cursor.curlx_str_single(b':').is_err()
        || cursor
            .curlx_str_until(&mut provider1, MAX_SIGV4_LEN, b':')
            .is_err()
    {
        // No provider1 given: it defaults to provider0.
        provider1 = provider0;
    } else if cursor.curlx_str_single(b':').is_err()
        || cursor
            .curlx_str_until(&mut region, MAX_SIGV4_LEN, b':')
            .is_err()
        || cursor.curlx_str_single(b':').is_err()
        || cursor
            .curlx_str_until(&mut service, MAX_SIGV4_LEN, b':')
            .is_err()
    {
        // Region/service are optional; whatever was captured stands.
    }

    // If no service was given, derive service (and, if needed, region) from the
    // leading labels of the hostname.
    if service.curlx_strlen() == 0 {
        let mut hp = Str::new(ctx.hostname.as_str());
        if hp
            .curlx_str_until(&mut service, MAX_SIGV4_LEN, b'.')
            .is_err()
            || hp.curlx_str_single(b'.').is_err()
        {
            return Err(CurlError::UrlMalformat);
        }
        // Region derivation only runs when the spec gave no region. The `&&`
        // short-circuit reproduces the C nesting: when a region is already set
        // the hostname is not consumed for one.
        if region.curlx_strlen() == 0
            && (hp
                .curlx_str_until(&mut region, MAX_SIGV4_LEN, b'.')
                .is_err()
                || hp.curlx_str_single(b'.').is_err())
        {
            return Err(CurlError::UrlMalformat);
        }
    }

    let provider0_bytes = provider0.curlx_str();
    let provider1_bytes = provider1.curlx_str();
    let provider0_str = core::str::from_utf8(provider0_bytes).unwrap_or("");
    let provider1_str = core::str::from_utf8(provider1_bytes).unwrap_or("");
    let region_str = core::str::from_utf8(region.curlx_str()).unwrap_or("");
    let service_str = core::str::from_utf8(service.curlx_str()).unwrap_or("");

    // --- Payload hash --------------------------------------------------------
    // Prefer a caller-supplied content-sha256 header; otherwise compute it
    // (S3 gets the special-cased UNSIGNED-PAYLOAD treatment and an emitted
    // header, everything else a plain body hash).
    let (payload_hash, content_sha256_line, content_sha256_emit): (
        String,
        Option<String>,
        Option<(String, String)>,
    ) = match parse_content_sha_hdr(&ctx.headers, provider1_bytes) {
        Some(v) => (v.to_string(), None, None),
        None => {
            let sign_as_s3 =
                curlx_str_casecompare(&provider0, "aws") && curlx_str_casecompare(&service, "s3");
            if sign_as_s3 {
                let hex = calc_s3_payload_hash(ctx);
                let name = format!("x-{provider1_str}-content-sha256");
                let line = format!("{name}: {hex}");
                let emit = (name, hex.clone());
                (hex, Some(line), Some(emit))
            } else {
                (calc_payload_hash(ctx), None, None)
            }
        }
    };

    // --- Timestamp -----------------------------------------------------------
    // curl uses the wall clock (or a forced epoch under CURL_FORCETIME); a user
    // date header overrides this inside make_headers.
    let initial_timestamp = {
        let dt: DateTime<Utc> = match ctx.force_epoch {
            Some(e) => DateTime::from_timestamp(e, 0).ok_or(CurlError::OutOfMemory)?,
            None => Utc::now(),
        };
        dt.format("%Y%m%dT%H%M%SZ").to_string()
    };

    // --- Canonical headers ---------------------------------------------------
    let made = make_headers(
        ctx,
        &ctx.hostname,
        initial_timestamp,
        provider1_bytes,
        content_sha256_line.as_deref(),
    )?;
    let MadeHeaders {
        canonical_headers,
        signed_headers,
        timestamp,
        date_emit,
    } = made;

    // Short date for the credential scope (first 8 bytes of the timestamp).
    let date = if timestamp.len() >= SHORT_DATE_LEN {
        &timestamp[..SHORT_DATE_LEN]
    } else {
        ""
    };

    // --- Canonical query and path -------------------------------------------
    let canonical_query = canon_query(ctx.query.as_deref())?;
    let canonical_path = canon_path(&ctx.path, should_urlencode(&service));

    // --- Canonical request ---------------------------------------------------
    // canonical_headers already ends each line with '\n'; the literal '\n' after
    // it yields the blank line AWS requires before the signed-headers list.
    let canonical_request = format!(
        "{method}\n{canonical_path}\n{canonical_query}\n{canonical_headers}\n\
         {signed_headers}\n{payload_hash}",
        method = ctx.method,
    );

    // --- String to sign ------------------------------------------------------
    let request_type = format!("{}4_request", provider0_str.to_ascii_lowercase());
    let credential_scope = format!("{date}/{region_str}/{service_str}/{request_type}");
    let hashed_canonical_request = sha256_hex(&sha256it(canonical_request.as_bytes()));

    let provider0_upper = provider0_str.to_ascii_uppercase();
    let string_to_sign = format!(
        "{provider0_upper}4-HMAC-SHA256\n{timestamp}\n{credential_scope}\n\
         {hashed_canonical_request}"
    );

    // --- Signing key derivation and signature --------------------------------
    let passwd = ctx.passwd.as_deref().unwrap_or("");
    let secret = format!("{provider0_upper}4{passwd}");

    let sign0 = hmac_sha256(secret.as_bytes(), date.as_bytes());
    let sign1 = hmac_sha256(&sign0, region_str.as_bytes());
    let sign0 = hmac_sha256(&sign1, service_str.as_bytes());
    let sign1 = hmac_sha256(&sign0, request_type.as_bytes());
    let sign0 = hmac_sha256(&sign1, string_to_sign.as_bytes());
    let signature = sha256_hex(&sign0);

    // --- Authorization header assembly ---------------------------------------
    let user = ctx.user.as_deref().unwrap_or("");
    let authorization = format!(
        "{provider0_upper}4-HMAC-SHA256 \
         Credential={user}/{credential_scope}, \
         SignedHeaders={signed_headers}, \
         Signature={signature}"
    );

    let mut extra_headers: Vec<(String, String)> = Vec::new();
    if let Some(de) = date_emit {
        extra_headers.push(de);
    }
    if let Some(ce) = content_sha256_emit {
        extra_headers.push(ce);
    }

    Ok(Some(Sigv4Headers {
        authorization,
        extra_headers,
    }))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The published AWS SigV4 secret used by the upstream test suite (and AWS's
    /// own documentation). It is a well-known *example* credential, not a live
    /// secret.
    const AWS_EXAMPLE_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    /// The doubled SHA-256 value test1959 supplies for `X-Xxx-Content-Sha256`.
    const TEST1959_DOUBLED_SHA: &str = concat!(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    // ---- Low-level encoding helpers ----------------------------------------

    #[test]
    fn empty_payload_sha256_matches_well_known_constant() {
        // curl computes the empty-body payload hash; it must equal the
        // documented empty-string SHA-256.
        assert_eq!(sha256_hex(&sha256it(b"")), EMPTY_SHA256_HEX);
    }

    #[test]
    fn hex_lower_encodes_lowercase() {
        assert_eq!(hex_lower(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        assert_eq!(hex_lower(&[]), "");
    }

    #[test]
    fn is_unreserved_matches_rfc3986() {
        for c in b'a'..=b'z' {
            assert!(is_unreserved(c));
        }
        for c in b'A'..=b'Z' {
            assert!(is_unreserved(c));
        }
        for c in b'0'..=b'9' {
            assert!(is_unreserved(c));
        }
        for &c in b"-._~" {
            assert!(is_unreserved(c));
        }
        for &c in b" /+%&=?#@:".iter() {
            assert!(!is_unreserved(c));
        }
    }

    // ---- Canonical path -----------------------------------------------------

    #[test]
    fn canon_path_percent_encodes_when_required() {
        assert_eq!(canon_path("/a b/c.d~e", true), "/a%20b/c.d~e");
        // A literal '+' in a path is encoded (it is not a path special char).
        assert_eq!(canon_path("/docs/+name", true), "/docs/%2Bname");
        // Slash and unreserved chars stay literal.
        assert_eq!(canon_path("/A/b-c_d.e~f", true), "/A/b-c_d.e~f");
    }

    #[test]
    fn canon_path_verbatim_for_s3() {
        // S3 (do_uri_encode = false) signs the path as-is.
        assert_eq!(canon_path("/mybucket/+x", false), "/mybucket/+x");
        assert_eq!(canon_path("/a b", false), "/a b");
    }

    #[test]
    fn canon_path_empty_becomes_root() {
        assert_eq!(canon_path("", true), "/");
        assert_eq!(canon_path("", false), "/");
    }

    // ---- Canonical query ----------------------------------------------------

    #[test]
    fn canon_query_sorts_and_preserves_encoded_plus() {
        // %2B stays encoded; components sort by (key, value).
        assert_eq!(canon_query(Some("a=%2B&b=2&a=1")).unwrap(), "a=%2B&a=1&b=2");
    }

    #[test]
    fn canon_query_sorts_by_key() {
        assert_eq!(
            canon_query(Some("Param2=value2&Param1=value1")).unwrap(),
            "Param1=value1&Param2=value2"
        );
    }

    #[test]
    fn canon_query_literal_plus_becomes_space() {
        // A literal '+' becomes %20; an encoded %2B is preserved.
        assert_eq!(canon_query(Some("a%2Bb=c+d")).unwrap(), "a%2Bb=c%20d");
    }

    #[test]
    fn canon_query_none_is_empty() {
        assert_eq!(canon_query(None).unwrap(), "");
        assert_eq!(canon_query(Some("")).unwrap(), "");
    }

    #[test]
    fn canon_query_empty_value_and_no_value() {
        // "key" (no '='), "key=" (trailing '='): both canonicalize to "key=".
        assert_eq!(canon_query(Some("key")).unwrap(), "key=");
        assert_eq!(canon_query(Some("key=")).unwrap(), "key=");
    }

    #[test]
    fn canon_query_too_many_components_errors() {
        let q127 = (0..127)
            .map(|i| format!("k{i}=v"))
            .collect::<Vec<_>>()
            .join("&");
        assert!(canon_query(Some(&q127)).is_ok());

        let q128 = (0..128)
            .map(|i| format!("k{i}=v"))
            .collect::<Vec<_>>()
            .join("&");
        assert!(matches!(canon_query(Some(&q128)), Err(CurlError::TooLarge)));
    }

    // ---- Header canonicalization -------------------------------------------

    #[test]
    fn trim_header_line_lowercases_name_and_collapses_value() {
        assert_eq!(trim_header_line("X-Test:   a   b   "), "x-test:a b");
        assert_eq!(trim_header_line("Host: example.com"), "host:example.com");
        // Tabs are blanks too; value case is preserved.
        assert_eq!(trim_header_line("A:\t Mixed\tCase \t"), "a:Mixed Case");
        // Empty value stays empty.
        assert_eq!(trim_header_line("X-Empty:"), "x-empty:");
    }

    #[test]
    fn merge_duplicate_headers_comma_joins() {
        let mut head = vec!["a:1".to_string(), "a:2".to_string(), "b:3".to_string()];
        merge_duplicate_headers(&mut head);
        assert_eq!(head, vec!["a:1,2".to_string(), "b:3".to_string()]);
    }

    // ---- Published golden vectors -------------------------------------------

    #[test]
    fn aws_get_vanilla_published_vector() {
        // The canonical AWS SigV4 test-suite "get-vanilla" case.
        let mut ctx = HttpRequestCtx::new("GET", "example.amazonaws.com", "/");
        ctx.sigv4 = Some("aws:amz:us-east-1:service".to_string());
        ctx.user = Some("AKIDEXAMPLE".to_string());
        ctx.passwd = Some(AWS_EXAMPLE_KEY.to_string());
        ctx.headers = vec!["X-Amz-Date:20150830T123600Z".to_string()];

        let out = output_aws_sigv4(&ctx).unwrap().unwrap();
        assert_eq!(
            out.authorization,
            "AWS4-HMAC-SHA256 \
             Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
        // The user supplied the date header and it is non-S3, so nothing extra
        // is emitted.
        assert!(out.extra_headers.is_empty());
    }

    #[test]
    fn curl_test1959_vector() {
        // Reproduces curl's own tests/data/test1959 (long content-sha256 value,
        // service/region derived from the host, forced epoch timestamp).
        let mut ctx = HttpRequestCtx::new("GET", "exam.ple.com", "/aws_sigv4/testapi/test");
        ctx.sigv4 = Some("xxx".to_string());
        ctx.user = Some("xxx".to_string());
        ctx.passwd = None; // USERPWD "xxx" ⇒ empty password
        ctx.aptr_host = Some("Host: exam.ple.com:9000\r\n".to_string());
        ctx.force_epoch = Some(0);
        ctx.headers = vec![
            "Content-Type: application/json".to_string(),
            format!("X-Xxx-Content-Sha256: {TEST1959_DOUBLED_SHA}"),
        ];

        let out = output_aws_sigv4(&ctx).unwrap().unwrap();
        assert_eq!(
            out.authorization,
            "XXX4-HMAC-SHA256 \
             Credential=xxx/19700101/ple/exam/xxx4_request, \
             SignedHeaders=content-type;host;x-xxx-content-sha256;x-xxx-date, \
             Signature=7b343a4aa55d73ffc05005d84480bc705a3367373ed8cae1a1c0fbd2b3aa0483"
        );
        // The date header is synthesized (no user date header); the content
        // hash header was user-supplied, so it is not re-emitted.
        assert_eq!(
            out.extra_headers,
            vec![("X-Xxx-Date".to_string(), "19700101T000000Z".to_string())]
        );
    }

    #[test]
    fn s3_get_emits_real_empty_payload_hash() {
        // S3 GET ⇒ empty payload ⇒ real SHA-256 of "", plus an emitted
        // x-amz-content-sha256 header.
        let mut ctx = HttpRequestCtx::new("GET", "s3.amazonaws.com", "/mybucket/key.txt");
        ctx.sigv4 = Some("aws:amz:us-east-1:s3".to_string());
        ctx.user = Some("AKIDEXAMPLE".to_string());
        ctx.passwd = Some(AWS_EXAMPLE_KEY.to_string());
        ctx.aptr_host = Some("Host: s3.amazonaws.com\r\n".to_string());
        ctx.force_epoch = Some(0);

        let out = output_aws_sigv4(&ctx).unwrap().unwrap();
        assert_eq!(
            out.authorization,
            "AWS4-HMAC-SHA256 \
             Credential=AKIDEXAMPLE/19700101/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=62e5ed020c89c66528c1a87df32d2b2faff25ab69c4bd1d445219d35e24fceef"
        );
        assert_eq!(
            out.extra_headers,
            vec![
                ("X-Amz-Date".to_string(), "19700101T000000Z".to_string()),
                (
                    "x-amz-content-sha256".to_string(),
                    EMPTY_SHA256_HEX.to_string()
                ),
            ]
        );
    }

    #[test]
    fn s3_put_uses_unsigned_payload() {
        // S3 PUT with an unknown body ⇒ UNSIGNED-PAYLOAD sentinel.
        let mut ctx = HttpRequestCtx::new("PUT", "s3.amazonaws.com", "/mybucket/key.txt");
        ctx.httpreq = HttpReq::Put;
        ctx.sigv4 = Some("aws:amz:us-east-1:s3".to_string());
        ctx.user = Some("AKIDEXAMPLE".to_string());
        ctx.passwd = Some(AWS_EXAMPLE_KEY.to_string());
        ctx.aptr_host = Some("Host: s3.amazonaws.com\r\n".to_string());
        ctx.force_epoch = Some(0);

        let out = output_aws_sigv4(&ctx).unwrap().unwrap();
        assert_eq!(
            out.authorization,
            "AWS4-HMAC-SHA256 \
             Credential=AKIDEXAMPLE/19700101/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=580b29150c01b40bd3cd419c53d4fddf7553b7c08644490bf8ff35ef18e102c6"
        );
        assert_eq!(
            out.extra_headers,
            vec![
                ("X-Amz-Date".to_string(), "19700101T000000Z".to_string()),
                (
                    "x-amz-content-sha256".to_string(),
                    "UNSIGNED-PAYLOAD".to_string()
                ),
            ]
        );
    }

    // ---- Provider parsing & host derivation --------------------------------

    #[test]
    fn provider_defaults_to_aws_amz_and_derives_from_host() {
        // sigv4 unset ⇒ default "aws:amz"; service/region from the host labels.
        let mut ctx = HttpRequestCtx::new("GET", "service1.region1.example.com", "/");
        ctx.user = Some("AKID".to_string());
        ctx.force_epoch = Some(0);

        let out = output_aws_sigv4(&ctx).unwrap().unwrap();
        assert!(out.authorization.starts_with("AWS4-HMAC-SHA256 "));
        assert!(out.authorization.contains("/region1/service1/aws4_request"));
        // provider1 defaults to "amz" ⇒ the synthesized date key is X-Amz-Date.
        assert_eq!(
            out.extra_headers,
            vec![("X-Amz-Date".to_string(), "19700101T000000Z".to_string())]
        );
    }

    #[test]
    fn missing_service_and_unsplittable_host_errors() {
        // No service in the spec and a single-label host ⇒ URL malformat.
        let mut ctx = HttpRequestCtx::new("GET", "localhost", "/");
        ctx.sigv4 = Some("aws:amz".to_string());
        assert!(matches!(
            output_aws_sigv4(&ctx),
            Err(CurlError::UrlMalformat)
        ));
    }

    #[test]
    fn empty_first_provider_errors() {
        let mut ctx = HttpRequestCtx::new("GET", "a.b.c", "/");
        ctx.sigv4 = Some(":amz:r:s".to_string());
        assert!(matches!(
            output_aws_sigv4(&ctx),
            Err(CurlError::BadFunctionArgument)
        ));
    }

    // ---- Header-filtering rules --------------------------------------------

    #[test]
    fn user_header_filtering_rules() {
        // "name:" ⇒ removal (skipped); whitespace-only ⇒ skipped;
        // "name;" ⇒ kept as empty "name:"; normal ⇒ kept.
        let mut ctx = HttpRequestCtx::new("GET", "example.amazonaws.com", "/");
        ctx.sigv4 = Some("aws:amz:us-east-1:service".to_string());
        ctx.user = Some("AKID".to_string());
        ctx.force_epoch = Some(0);
        ctx.headers = vec![
            "X-Remove:".to_string(),
            "X-Blank:    ".to_string(),
            "X-Send;".to_string(),
            "X-Keep: val".to_string(),
        ];

        let out = output_aws_sigv4(&ctx).unwrap().unwrap();
        assert!(out
            .authorization
            .contains("SignedHeaders=host;x-amz-date;x-keep;x-send,"));
    }

    // ---- Bail-out / error paths --------------------------------------------

    #[test]
    fn authorization_already_present_is_noop() {
        let mut ctx = HttpRequestCtx::new("GET", "example.amazonaws.com", "/");
        ctx.sigv4 = Some("aws:amz:us-east-1:service".to_string());
        ctx.headers = vec!["Authorization: already-here".to_string()];
        assert_eq!(output_aws_sigv4(&ctx).unwrap(), None);
    }

    #[test]
    fn path_as_is_is_rejected() {
        let mut ctx = HttpRequestCtx::new("GET", "example.amazonaws.com", "/");
        ctx.sigv4 = Some("aws:amz:us-east-1:service".to_string());
        ctx.path_as_is = true;
        assert!(matches!(
            output_aws_sigv4(&ctx),
            Err(CurlError::BadFunctionArgument)
        ));
    }

    #[test]
    fn user_supplied_host_suppresses_auto_host() {
        // A user Host header is used verbatim (canonicalized); no auto host is
        // added, and the signature still resolves deterministically.
        let mut ctx = HttpRequestCtx::new("GET", "ignored.example.com", "/");
        ctx.sigv4 = Some("aws:amz:us-east-1:service".to_string());
        ctx.user = Some("AKIDEXAMPLE".to_string());
        ctx.passwd = Some(AWS_EXAMPLE_KEY.to_string());
        ctx.force_epoch = Some(0);
        ctx.headers = vec![
            "Host: example.amazonaws.com".to_string(),
            "X-Amz-Date: 20150830T123600Z".to_string(),
        ];

        let out = output_aws_sigv4(&ctx).unwrap().unwrap();
        // Same signed set as get-vanilla (host;x-amz-date), date user-supplied.
        assert!(out.authorization.contains("SignedHeaders=host;x-amz-date,"));
        assert!(out.extra_headers.is_empty());
    }
}
