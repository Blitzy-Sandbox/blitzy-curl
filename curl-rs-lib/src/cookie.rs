//! HTTP cookie engine and jar — RFC 6265 (and the 6265bis draft refinements).
//!
//! This is the idiomatic, memory-safe Rust reimplementation of libcurl's cookie
//! subsystem (`lib/cookie.c` / `lib/cookie.h`). It owns four responsibilities
//! that together let the transfer engine persist and exchange cookies with a
//! server in a way that is byte-for-byte compatible with curl 8.x:
//!
//! 1. **Parsing** — [`CookieJar::add_from_set_cookie`] consumes a `Set-Cookie:`
//!    response-header value, honoring the `Domain`, `Path`, `Expires`,
//!    `Max-Age`, `Secure`, `HttpOnly` and `SameSite` attributes plus the
//!    `__Secure-` / `__Host-` name prefixes. Mirrors C's `Curl_cookie_add` (the
//!    `parse_cookie_header` path).
//! 2. **Matching** — [`CookieJar::get_list`] / [`CookieJar::match_for`] select
//!    the cookies that apply to an outgoing request (domain / path / secure /
//!    expiry matching) and order them exactly as curl does (longest path first,
//!    then domain length, name length, and creation time). Mirrors
//!    `Curl_cookie_getlist` and the `http_cookies` header builder in `lib/http.c`.
//! 3. **Persistence** — [`CookieJar::load_file`] / [`CookieJar::save`] read and
//!    write the Netscape/Mozilla `cookies.txt` format (the
//!    `# Netscape HTTP Cookie File` tab-separated layout, including the
//!    `#HttpOnly_` line prefix) **byte-for-byte** so the regression suite's
//!    cookie-jar dump comparisons pass unchanged. Mirrors `cookie_load` and
//!    `cookie_output` / `Curl_flush_cookies`.
//! 4. **List commands** — [`CookieJar::cookie_list_command`] implements the
//!    `CURLOPT_COOKIELIST` verbs (`ALL`, `SESS`, `FLUSH`, `RELOAD`, and adding a
//!    single Set-Cookie / Netscape line) and [`CookieJar::export_list`] backs
//!    `CURLINFO_COOKIELIST`. Mirrors `lib/setopt.c`'s `cookielist()` and
//!    `Curl_cookie_list`.
//!
//! The C sources are consulted strictly as a **behavioral and file-format
//! oracle** (AAP §0.8.2): the parsing rules, domain/path matching, secure /
//! httponly / prefix handling, expiry clamping, the public-suffix domain check,
//! the cookie ordering, and the persisted layout are reproduced exactly, but the
//! code is expressed with safe Rust collections (`Vec`, owned `String`s) rather
//! than the hand-rolled linked-list-of-hash-buckets used in C.
//!
//! # Storage model
//!
//! curl hashes every cookie into one of [`COOKIE_HASH_SIZE`] buckets keyed by
//! the *top* (registrable, last-two-label) portion of its domain, and an
//! outgoing-request lookup scans only the single bucket the request host hashes
//! to. We replicate that bucketing exactly ([`cookiehash`]), because it is what
//! makes the [`MAX_COOKIE_SEND_AMOUNT`] cap and the iteration order
//! deterministic and therefore wire-observable. Within a bucket, cookies are
//! stored in insertion order, matching curl's `Curl_llist_append`.
//!
//! # Time handling
//!
//! Unlike the C code — which reads the wall clock internally via `time(NULL)` —
//! every time-sensitive entry point here takes an explicit `now` (a Unix
//! timestamp in seconds, UTC). This keeps the module free of ambient global
//! state and makes expiry deterministically testable. [`now_unix`] is provided
//! for callers that simply want the system clock. The "never expires" /
//! "uninitialized next-expiration" sentinel is [`i64::MAX`], matching curl's
//! `CURL_OFF_T_MAX` on the 64-bit `curl_off_t` model used by every target
//! platform (AAP §0.8.1).
//!
//! # Feature gating
//!
//! The whole module is gated behind the `cookies` Cargo feature (default on),
//! matching curl's `CURL_DISABLE_COOKIES` build gate. When the feature is off
//! the module compiles to nothing; `crate::version` then omits the cookie
//! capability and the relevant `setopt` calls return `CURLE_NOT_BUILT_IN`
//! (both handled in their own modules, in lockstep with this feature).
//!
//! # Public-suffix protection
//!
//! Rejecting a `Domain=` that is "too broad" (for example `Domain=.co.uk`) is
//! delegated to [`crate::psl::Psl::is_cookie_domain_acceptable`], which itself
//! reproduces both curl's `USE_LIBPSL` path (the real Public Suffix List) and
//! its no-`libpsl` fallback (`bad_domain`). This module simply applies that
//! decision at the exact point curl calls `is_public_suffix`.
//!
//! # Memory safety
//!
//! Per the project mandate (AAP §0.7.1) this module contains **zero `unsafe`**
//! and is compiled under `#![forbid(unsafe_code)]`. All comparisons that curl
//! performs with `curl_strnequal` / `strncmp` operate here on raw bytes with
//! ASCII-only case folding, so they never panic on non-UTF-8 input or char
//! boundaries.

#![cfg(feature = "cookies")]
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{CurlError, Result};
use crate::url::CurlUrl;

// ----------------------------------------------------------------------------
// Constants — mirroring the `#define`s in `lib/cookie.h` and `lib/cookie.c`.
// These values are part of the externally observable contract (they bound what
// the parser accepts and what the request builder emits) and MUST match curl
// exactly (AAP §0.8.2 / agent task "enforce limits exactly").
// ----------------------------------------------------------------------------

/// Number of hash buckets the jar is split into (`COOKIE_HASH_SIZE` in
/// `lib/cookie.h`). Cookies are distributed across these buckets by the
/// top-level portion of their domain; see [`cookiehash`].
pub const COOKIE_HASH_SIZE: usize = 63;

/// The longest line (in bytes) accepted when reading a cookie from an HTTP
/// header or from a cookie jar (`MAX_COOKIE_LINE` in `lib/cookie.h`). Longer
/// header lines are discarded outright.
pub const MAX_COOKIE_LINE: usize = 5000;

/// Maximum length of an incoming cookie name or value, and the cap on their
/// combined length (`MAX_NAME` in `lib/cookie.h`). Longer cookies are ignored.
pub const MAX_NAME: usize = 4096;

/// Maximum number of `Set-Cookie:` header lines honored within a single
/// response (`MAX_SET_COOKIE_AMOUNT` in `lib/cookie.h`). Further lines are
/// silently ignored.
///
/// This cap is **request-scoped** in curl (`data->req.setcookies`), not a
/// property of the jar, so it is enforced by the transfer/response layer that
/// owns the per-request counter; [`CookieJar`] exposes the constant but does
/// not itself track the per-response count.
pub const MAX_SET_COOKIE_AMOUNT: u8 = 50;

/// Maximum size of the outgoing `Cookie:` request header libcurl will build
/// (`MAX_COOKIE_HEADER_LEN` in `lib/cookie.h`). Once a request would exceed
/// this, the remaining matched cookies are dropped from that request.
pub const MAX_COOKIE_HEADER_LEN: usize = 8190;

/// Maximum number of cookies libcurl will send in a single request even when
/// more match (`MAX_COOKIE_SEND_AMOUNT` in `lib/cookie.h`).
pub const MAX_COOKIE_SEND_AMOUNT: usize = 150;

/// Number of seconds in 400 days — the upper bound RFC 6265bis places on a
/// cookie's lifetime (`COOKIES_MAXAGE` in `lib/cookie.c`).
pub const COOKIES_MAXAGE: i64 = 400 * 24 * 3600;

/// The longest string accepted for the `Expires=` attribute value
/// (`MAX_DATE_LENGTH` in `lib/cookie.c`); longer values are ignored, leaving
/// the cookie as a session cookie.
pub const MAX_DATE_LENGTH: usize = 80;

/// Upper bound on the length of a single `CURLOPT_COOKIELIST` input line
/// (`CURL_MAX_INPUT_LENGTH` in `lib/urldata.h`); a longer line is rejected with
/// [`CurlError::BadFunctionArgument`].
const CURL_MAX_INPUT_LENGTH: usize = 8_000_000;

/// The sentinel curl uses for "no expiration recorded yet" and "never expires"
/// (`CURL_OFF_T_MAX` on the 64-bit `curl_off_t` model). Equal to [`i64::MAX`].
const EXPIRE_NEVER: i64 = i64::MAX;

// ----------------------------------------------------------------------------
// The Cookie record (`struct Cookie` in `lib/cookie.h`).
// ----------------------------------------------------------------------------

/// A single stored cookie.
///
/// This is the Rust image of C's `struct Cookie`. The two `Curl_llist_node`
/// link fields the C struct carries (`node` / `getnode`) have no analog here —
/// list membership and the transient "matched for this request" set are managed
/// by [`CookieJar`] using owned [`Vec`]s — but every *data* field is preserved
/// with the same meaning so that parsing, matching, and the Netscape dump are
/// byte-for-byte faithful.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie {
    /// The cookie name (the `<this>=value` left-hand side). Always non-empty for
    /// a stored cookie.
    pub name: String,
    /// The cookie value (the `name=<this>` right-hand side). May be empty.
    pub value: String,
    /// The canonical path the cookie applies to (curl's sanitized path). `None`
    /// means "no path constraint" (matches any path), mirroring a `NULL`
    /// `co->path` in C.
    pub path: Option<String>,
    /// The domain the cookie applies to. `None` mirrors a `NULL` `co->domain`.
    pub domain: Option<String>,
    /// Absolute expiry as a Unix timestamp in seconds, or `0` for a session
    /// cookie (`co->expires`, a `curl_off_t`).
    pub expires: i64,
    /// A per-jar monotonically increasing creation index used as the final
    /// tie-breaker when ordering cookies (`co->creationtime`). Unique per cookie
    /// within a jar.
    pub creationtime: u32,
    /// Whether the domain is tail-matched (the `Domain=` attribute was given, or
    /// the Netscape file flag was `TRUE`), so subdomains also match
    /// (`co->tailmatch`).
    pub tailmatch: bool,
    /// Whether the `Secure` attribute was set (`co->secure`).
    pub secure: bool,
    /// Whether this cookie was set from a live server response rather than read
    /// from a file (`co->livecookie`); live cookies take precedence over
    /// file-loaded ones when replacing.
    pub livecookie: bool,
    /// Whether the `HttpOnly` attribute was set (`co->httponly`).
    pub httponly: bool,
    /// Whether the cookie name carried the `__Secure-` prefix
    /// (`co->prefix_secure`).
    pub prefix_secure: bool,
    /// Whether the cookie name carried the `__Host-` prefix (`co->prefix_host`).
    pub prefix_host: bool,
}

impl Cookie {
    /// Returns `true` if this is a session cookie (no persistent expiry), i.e.
    /// `expires == 0` — the same test curl uses in `Curl_cookie_clearsess`.
    #[must_use]
    pub fn is_session(&self) -> bool {
        self.expires == 0
    }

    /// Formats this cookie as a single Netscape/Mozilla `cookies.txt` line
    /// (without the trailing newline), byte-for-byte identical to curl's
    /// `get_netscape_format`.
    ///
    /// The layout is, tab-separated:
    ///
    /// ```text
    /// [#HttpOnly_][.]domain<TAB>TRUE|FALSE<TAB>path<TAB>TRUE|FALSE<TAB>expires<TAB>name<TAB>value
    /// ```
    ///
    /// Mozilla-style, a leading `.` is prepended to the domain when the cookie
    /// tail-matches and the stored domain does not already start with `.`; a
    /// missing domain renders as `unknown`, a missing path as `/`, and a missing
    /// value as the empty string.
    #[must_use]
    pub fn to_netscape_line(&self) -> String {
        let httponly = if self.httponly { "#HttpOnly_" } else { "" };
        let domain = self.domain.as_deref().unwrap_or("unknown");
        // Prefix a dot for tail-matching domains that do not already have one,
        // matching curl's Mozilla-compatible output.
        let dot = if self.tailmatch && self.domain.is_some() && !domain.starts_with('.') {
            "."
        } else {
            ""
        };
        let tailmatch = if self.tailmatch { "TRUE" } else { "FALSE" };
        let path = self.path.as_deref().unwrap_or("/");
        let secure = if self.secure { "TRUE" } else { "FALSE" };
        format!(
            "{httponly}{dot}{domain}\t{tailmatch}\t{path}\t{secure}\t{expires}\t{name}\t{value}",
            expires = self.expires,
            name = self.name,
            value = self.value,
        )
    }
}

// ----------------------------------------------------------------------------
// Free helper functions — direct, behavior-preserving ports of the static
// helpers in `lib/cookie.c`. They operate on `&str`/`&[u8]` and allocate only
// owned `String`s, so the whole module stays inside `#![forbid(unsafe_code)]`.
// ----------------------------------------------------------------------------

/// ASCII upper-casing identical to curl's `Curl_raw_toupper` (only `a`–`z` are
/// folded; every other byte is returned unchanged).
#[inline]
fn raw_toupper(b: u8) -> u8 {
    b.to_ascii_uppercase()
}

/// Returns `true` if `host` is a numeric IP literal (IPv4 or IPv6).
///
/// Mirrors curl's `Curl_host_is_ipnum`, which probes the string with
/// `inet_pton` for both `AF_INET` and `AF_INET6`. Cookies are never tail-matched
/// against an IP host, and an IP "domain" is never treated as a public suffix.
fn is_ip_literal(host: &str) -> bool {
    host.parse::<Ipv4Addr>().is_ok() || host.parse::<Ipv6Addr>().is_ok()
}

/// Returns the top-level (registrable, last-two-label) portion of a domain, used
/// purely to bucket cookies for hashing. Mirrors curl's `get_top_domain`.
///
/// For `www.example.com` this returns `example.com`; for `example.com` it
/// returns the whole string; for a single label (or empty) it returns the input
/// unchanged.
fn get_top_domain(domain: &str) -> &str {
    let bytes = domain.as_bytes();
    if let Some(last) = bytes.iter().rposition(|&b| b == b'.') {
        if let Some(first) = bytes[..last].iter().rposition(|&b| b == b'.') {
            // Start just after the second-to-last dot.
            return &domain[first + 1..];
        }
    }
    domain
}

/// Case-insensitive hash of a cookie domain, mirroring curl's
/// `cookie_hash_domain` (a djb2 variant over the ASCII-upper-cased bytes). The
/// arithmetic deliberately wraps modulo 2^64 exactly as the C `size_t` math
/// does, then is reduced modulo [`COOKIE_HASH_SIZE`].
fn cookie_hash_domain(domain: &str) -> usize {
    let mut h: u64 = 5381;
    for &b in domain.as_bytes() {
        let j = u64::from(raw_toupper(b));
        h = h.wrapping_add(h.wrapping_shl(5));
        h ^= j;
    }
    (h % COOKIE_HASH_SIZE as u64) as usize
}

/// Maps a domain to its hash bucket, mirroring curl's `cookiehash`.
///
/// A missing domain, or one that is a numeric IP literal, always maps to bucket
/// `0` (exactly as curl returns `0` for `!domain || Curl_host_is_ipnum(domain)`).
fn cookiehash(domain: Option<&str>) -> usize {
    match domain {
        Some(d) if !is_ip_literal(d) => cookie_hash_domain(get_top_domain(d)),
        _ => 0,
    }
}

/// RFC 6265 §4.1.2.3 domain tail-matching, mirroring curl's `cookie_tailmatch`.
///
/// Returns `true` when `cookie_domain` is a case-insensitive suffix of
/// `hostname` at a label boundary: either the two are equal, or the byte of
/// `hostname` immediately preceding the matched suffix is a `.`.
fn cookie_tailmatch(cookie_domain: &str, hostname: &str) -> bool {
    let cd = cookie_domain.as_bytes();
    let host = hostname.as_bytes();
    let (cd_len, host_len) = (cd.len(), host.len());

    if host_len < cd_len {
        return false;
    }
    let tail = &host[host_len - cd_len..];
    if !tail.eq_ignore_ascii_case(cd) {
        return false;
    }
    if host_len == cd_len {
        return true;
    }
    host[host_len - cd_len - 1] == b'.'
}

/// RFC 6265 §5.1.4 path matching, mirroring curl's `pathmatch`.
///
/// The comparison is **case-sensitive** (unlike domain matching). An empty or
/// non-absolute `uri_path` is treated as `/`. A cookie path of `/` matches
/// everything; otherwise the cookie path must be a prefix of the URI path and
/// either equal to it or followed by a `/` in the URI path.
fn pathmatch(cookie_path: &str, uri_path: &str) -> bool {
    let cp = cookie_path.as_bytes();
    let cp_len = cp.len();

    // A cookie path of exactly "/" matches any URI path.
    if cp_len == 1 {
        return true;
    }

    // `#`-fragments are already cut off by the URL layer.
    let uri = if uri_path.is_empty() || uri_path.as_bytes()[0] != b'/' {
        "/"
    } else {
        uri_path
    };
    let up = uri.as_bytes();
    let up_len = up.len();

    if up_len < cp_len {
        return false;
    }
    // Case-sensitive prefix comparison (curl uses strncmp, not checkprefix).
    if up[..cp_len] != *cp {
        return false;
    }
    if cp_len == up_len {
        return true;
    }
    up[cp_len] == b'/'
}

/// Sanitizes a cookie path, mirroring curl's `sanitize_cookie_path`.
///
/// Surrounding double-quotes are stripped; an empty or non-absolute path becomes
/// the default `/`; and a single trailing `/` is removed from a longer path
/// (`/hoge/` becomes `/hoge`). Operates on raw bytes (the source is a slice of a
/// header or file line) and returns an owned `String`.
fn sanitize_cookie_path(input: &[u8]) -> String {
    let mut bytes = input;

    // Some sites wrap the path attribute in double-quotes.
    if bytes.first() == Some(&b'"') {
        bytes = &bytes[1..];
        if bytes.last() == Some(&b'"') {
            bytes = &bytes[..bytes.len() - 1];
        }
    }

    // RFC 6265 §5.2.4: a path that is empty or does not start with '/' uses the
    // default path of "/".
    if bytes.is_empty() || bytes[0] != b'/' {
        return "/".to_string();
    }

    // Remove a single trailing slash from a non-trivial path.
    if bytes.len() > 1 && bytes[bytes.len() - 1] == b'/' {
        bytes = &bytes[..bytes.len() - 1];
    }

    // Path bytes originate from a header/file slice; preserve them verbatim. Any
    // non-UTF-8 bytes are carried through losslessly via `from_utf8_lossy` only
    // as a safety net — cookie paths are ASCII in every conformant input.
    String::from_utf8_lossy(bytes).into_owned()
}

/// Returns `true` for the blank bytes curl's `str_trimblanks` recognizes
/// (space and TAB).
#[inline]
fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Trims leading and trailing blanks (space / TAB) from a byte slice, mirroring
/// `curlx_str_trimblanks` applied to a captured token.
fn trim_blanks(mut s: &[u8]) -> &[u8] {
    while let Some(&first) = s.first() {
        if is_blank(first) {
            s = &s[1..];
        } else {
            break;
        }
    }
    while let Some(&last) = s.last() {
        if is_blank(last) {
            s = &s[..s.len() - 1];
        } else {
            break;
        }
    }
    s
}

/// A minimal byte cursor reproducing the three `curlx_str_*` primitives the
/// cookie header tokenizer relies on (`str_cspn`, `str_single`), without taking
/// a dependency on `crate::util::strparse` (outside this file's allowed import
/// set). It borrows the input line and never allocates.
struct ByteCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Mirrors `curlx_str_cspn`: returns the run of leading bytes that are NOT
    /// in `reject`, advancing past them. Returns `None` (leaving the cursor
    /// unchanged) when that run would be empty — exactly the C `STRE_SHORT`
    /// failure the caller tests with `!curlx_str_cspn(...)`.
    fn cspn(&mut self, reject: &[u8]) -> Option<&'a [u8]> {
        let start = self.pos;
        while self.pos < self.bytes.len() && !reject.contains(&self.bytes[self.pos]) {
            self.pos += 1;
        }
        if self.pos > start {
            Some(&self.bytes[start..self.pos])
        } else {
            None
        }
    }

    /// Mirrors `curlx_str_single`: consumes exactly `byte` if it is next,
    /// returning whether it did.
    fn single(&mut self, byte: u8) -> bool {
        if self.pos < self.bytes.len() && self.bytes[self.pos] == byte {
            self.pos += 1;
            true
        } else {
            false
        }
    }
}

/// ASCII case-insensitive equality between a captured token and a literal,
/// mirroring curl's `curlx_str_casecompare`.
#[inline]
fn token_eq_ci(token: &[u8], literal: &str) -> bool {
    token.eq_ignore_ascii_case(literal.as_bytes())
}

/// Parses an HTTP `Set-Cookie:` header value into a [`Cookie`], mirroring the
/// `parse_cookie_header` path of curl's `Curl_cookie_add`.
///
/// `default_domain` / `default_path` are the request's host and path, used when
/// the header omits an explicit `Domain` / `Path`. `secure` indicates the
/// request was made over a secure origin, and `running` is the jar's running
/// state (a non-running jar — i.e. one loading from a file — accepts `secure`
/// cookies unconditionally). `now` is the current Unix time, used for `Max-Age`
/// / `Expires` arithmetic and the 400-day cap.
///
/// Returns `Some(cookie)` when a well-formed cookie was parsed, or `None` when
/// the line is to be ignored (curl's `CURLE_OK` with `okay == FALSE`): an
/// over-long line, a missing `name=value` separator, invalid control octets, an
/// over-sized name/value, a TAB inside the value, or a `Domain` that does not
/// tail-match the request host.
fn parse_cookie_header(
    line: &str,
    default_domain: Option<&str>,
    default_path: Option<&str>,
    secure: bool,
    running: bool,
    now: i64,
) -> Option<Cookie> {
    // Discard overly long lines at once (curl checks before any parsing).
    if line.len() > MAX_COOKIE_LINE {
        return None;
    }

    let mut cur = ByteCursor::new(line.as_bytes());

    // First name=value pair (the cookie itself) plus the optional Path override.
    let mut name: Option<&[u8]> = None;
    let mut value: &[u8] = b"";
    let mut path_attr: Option<&[u8]> = None;
    let mut domain_override: Option<String> = None;
    let mut tailmatch = false;
    let mut co_secure = false;
    let mut httponly = false;
    let mut expires: i64 = 0;
    let mut prefix_secure = false;
    let mut prefix_host = false;

    loop {
        if let Some(name_tok) = cur.cspn(b";\t\r\n=") {
            let name_tok = trim_blanks(name_tok);
            let sep;
            let val_tok: &[u8] = if cur.single(b'=') {
                sep = true;
                match cur.cspn(b";\r\n") {
                    Some(v) => trim_blanks(v),
                    None => b"",
                }
            } else {
                sep = false;
                b""
            };

            if name.is_none() {
                // The first pair is the actual cookie name/value.
                if !sep
                    || invalid_octets(name_tok)
                    || invalid_octets(val_tok)
                    || name_tok.is_empty()
                {
                    // Bad name/value pair → drop the whole cookie.
                    return None;
                }
                // Reject too-long individual name/value or an over-sized combo
                // (Chrome/Firefox support a ~4096-byte name+value combination).
                if name_tok.len() >= (MAX_NAME - 1)
                    || val_tok.len() >= (MAX_NAME - 1)
                    || (name_tok.len() + val_tok.len()) > MAX_NAME
                {
                    return None;
                }
                // Reject a TAB inside the value.
                if val_tok.contains(&b'\t') {
                    return None;
                }
                // Reserved name prefixes (case-sensitive), RFC 6265bis.
                if name_tok.starts_with(b"__Secure-") {
                    prefix_secure = true;
                } else if name_tok.starts_with(b"__Host-") {
                    prefix_host = true;
                }
                name = Some(name_tok);
                value = val_tok;
            } else if !sep {
                // A stand-alone word: `secure` or `httponly`.
                if token_eq_ci(name_tok, "secure") {
                    // Secure cookies are only accepted over a secure origin, or
                    // when reading from a file (the jar is not running).
                    if secure || !running {
                        co_secure = true;
                    } else {
                        return None;
                    }
                } else if token_eq_ci(name_tok, "httponly") {
                    httponly = true;
                }
            } else if token_eq_ci(name_tok, "path") {
                path_attr = Some(val_tok);
            } else if token_eq_ci(name_tok, "domain") && !val_tok.is_empty() {
                // Strip a single leading dot from the domain value.
                let v = if val_tok.first() == Some(&b'.') {
                    &val_tok[1..]
                } else {
                    val_tok
                };
                let v_str = String::from_utf8_lossy(v).into_owned();

                // `is_ip` reflects the request host (falling back to the cookie
                // domain when there is no request host), matching curl.
                let is_ip = is_ip_literal(default_domain.unwrap_or(&v_str));

                let accept = match default_domain {
                    None => true,
                    Some(dom) if is_ip => v_str == dom,
                    Some(dom) => cookie_tailmatch(&v_str, dom),
                };
                if accept {
                    if !is_ip {
                        tailmatch = true;
                    }
                    domain_override = Some(v_str);
                } else {
                    // Bad tail-match: the cookie's domain is not one this host
                    // may set → drop.
                    return None;
                }
            } else if token_eq_ci(name_tok, "max-age") && !val_tok.is_empty() {
                // RFC 2109 Max-Age (seconds). Takes priority over Expires.
                let mut maxage = val_tok;
                if maxage.first() == Some(&b'"') {
                    maxage = &maxage[1..];
                }
                let maxage_str = String::from_utf8_lossy(maxage);
                expires = match parse_leading_number(&maxage_str) {
                    NumParse::Overflow => EXPIRE_NEVER,
                    NumParse::Bad => 1,   // negative / unparsable → expire now
                    NumParse::Ok(0) => 1, // zero → expire now
                    NumParse::Ok(secs) => {
                        if EXPIRE_NEVER - now < secs {
                            EXPIRE_NEVER
                        } else {
                            now + secs
                        }
                    }
                };
                expires = cap_expires(now, expires);
            } else if token_eq_ci(name_tok, "expires")
                && !val_tok.is_empty()
                && expires == 0
                && val_tok.len() < MAX_DATE_LENGTH
            {
                // Max-Age has priority (guarded by `expires == 0`). A date that
                // cannot be parsed leaves the cookie as a session cookie.
                let date_str = String::from_utf8_lossy(val_tok);
                expires = match crate::util::parsedate::getdate_capped(&date_str) {
                    Some(date) => {
                        if date == 0 {
                            1
                        } else {
                            date
                        }
                    }
                    None => 0,
                };
                expires = cap_expires(now, expires);
            }
        }

        // Consume the next ';' separator and continue; stop otherwise (a TAB,
        // CR, LF, end-of-line, or a leading '=' all terminate the parse).
        if !cur.single(b';') {
            break;
        }
    }

    // A cookie is only valid if a name was found.
    let name = name?;

    // storecookie: assemble the final owned record, applying default path and
    // default domain where the header did not specify them.
    let path = if let Some(p) = path_attr {
        if p.is_empty() {
            // An empty Path= attribute falls through to the default below.
            default_path_value(default_path)
        } else {
            Some(sanitize_cookie_path(p))
        }
    } else {
        default_path_value(default_path)
    };

    let domain = domain_override.or_else(|| default_domain.map(str::to_string));

    Some(Cookie {
        name: String::from_utf8_lossy(name).into_owned(),
        value: String::from_utf8_lossy(value).into_owned(),
        path,
        domain,
        expires,
        creationtime: 0, // assigned by the jar on insertion
        tailmatch,
        secure: co_secure,
        livecookie: false, // set by the jar based on running state
        httponly,
        prefix_secure,
        prefix_host,
    })
}

/// Computes the default cookie path from the request path, mirroring the
/// `else if(path)` branch of curl's `storecookie`: everything up to and
/// including the last `/` (or the whole path when it has no `/`), then
/// sanitized. Returns `None` when there is no request path.
fn default_path_value(default_path: Option<&str>) -> Option<String> {
    let dp = default_path?;
    let dpb = dp.as_bytes();
    let plen = match dpb.iter().rposition(|&b| b == b'/') {
        Some(idx) => idx + 1, // include the slash
        None => dpb.len(),
    };
    Some(sanitize_cookie_path(&dpb[..plen]))
}

/// Case-sensitive `strncmp(lit, field, field.len()) == 0` — i.e. `field` is a
/// case-sensitive prefix of `lit`. Used for the Netscape path/boolean
/// disambiguation (curl uses `strncmp` there).
fn strncmp_prefix(lit: &str, field: &[u8]) -> bool {
    let lit = lit.as_bytes();
    field.len() <= lit.len() && lit[..field.len()] == *field
}

/// Case-insensitive `curl_strnequal(field, lit, field.len())` — i.e. `field` is
/// a case-insensitive prefix of `lit`. Used for the Netscape tailmatch / secure
/// flags and the name-prefix detection (curl uses `curl_strnequal` there).
fn strnequal_prefix(lit: &str, field: &[u8]) -> bool {
    let lit = lit.as_bytes();
    field.len() <= lit.len() && lit[..field.len()].eq_ignore_ascii_case(field)
}

/// Parses a Netscape/Mozilla `cookies.txt` line into a [`Cookie`], mirroring
/// curl's `parse_netscape`.
///
/// The `#HttpOnly_` line prefix sets [`Cookie::httponly`] and is then stripped;
/// any other `#`-prefixed line is a comment and yields `None`. The remaining
/// TAB-separated fields are, in order: domain, tail-match flag, path, secure
/// flag, expiry, name, and value. curl's quirk of detecting a missing path
/// field (when field 2 is a boolean) and a missing value field is reproduced
/// exactly, so both 6-field shapes load identically to curl.
///
/// `secure` / `running` gate acceptance of a `secure` flag exactly as in the
/// header parser. Returns `None` for a comment, a malformed expiry, a `secure`
/// flag that cannot be honored, or a line without the required seven fields.
fn parse_netscape(line: &str, secure: bool, running: bool) -> Option<Cookie> {
    let mut bytes = line.as_bytes();
    let mut httponly = false;

    // `#HttpOnly_` prefix (Firefox-style) marks an HTTP-only cookie.
    if bytes.starts_with(b"#HttpOnly_") {
        bytes = &bytes[10..];
        httponly = true;
    }
    // Any remaining leading '#' is a comment.
    if bytes.first() == Some(&b'#') {
        return None;
    }

    let mut domain: Option<String> = None;
    let mut tailmatch = false;
    let mut path: Option<String> = None;
    let mut co_secure = false;
    let mut expires: i64 = 0;
    let mut name: Option<String> = None;
    let mut value: Option<String> = None;
    let mut prefix_secure = false;
    let mut prefix_host = false;

    let mut fields: usize = 0;
    let mut pos = 0usize;
    loop {
        let start = pos;
        while pos < bytes.len() && bytes[pos] != b'\t' && bytes[pos] != b'\r' && bytes[pos] != b'\n'
        {
            pos += 1;
        }
        let field = &bytes[start..pos];
        let has_tab = pos < bytes.len() && bytes[pos] == b'\t';

        match fields {
            0 => {
                // Domain — skip a single preceding dot.
                let d = if field.first() == Some(&b'.') {
                    &field[1..]
                } else {
                    field
                };
                domain = Some(String::from_utf8_lossy(d).into_owned());
            }
            1 => {
                // Tail-match flag (case-insensitive "TRUE").
                tailmatch = strnequal_prefix("TRUE", field);
            }
            2 => {
                // Path — unless the field is actually a boolean, in which case
                // the path field was omitted: default to "/" and reprocess this
                // field as the secure flag (curl's `fields++; FALLTHROUGH`).
                if strncmp_prefix("TRUE", field) || strncmp_prefix("FALSE", field) {
                    path = Some("/".to_string());
                    // Fall through to the secure-flag handling for this field.
                    if strnequal_prefix("TRUE", field) {
                        if secure || running {
                            co_secure = true;
                        } else {
                            return None;
                        }
                    }
                    fields += 1; // extra increment before the fallthrough
                } else {
                    path = Some(sanitize_cookie_path(field));
                }
            }
            3 => {
                // Secure flag.
                if strnequal_prefix("TRUE", field) {
                    if secure || running {
                        co_secure = true;
                    } else {
                        return None;
                    }
                }
            }
            4 => {
                // Expiry — a malformed number drops the cookie.
                match parse_leading_number(&String::from_utf8_lossy(field)) {
                    NumParse::Ok(v) => expires = v,
                    NumParse::Overflow | NumParse::Bad => return None,
                }
            }
            5 => {
                let n = String::from_utf8_lossy(field).into_owned();
                // Name-prefix detection (case-insensitive for the file format).
                if strnequal_prefix_full(&n, "__Secure-", 9) {
                    prefix_secure = true;
                } else if strnequal_prefix_full(&n, "__Host-", 7) {
                    prefix_host = true;
                }
                name = Some(n);
            }
            6 => {
                value = Some(String::from_utf8_lossy(field).into_owned());
            }
            _ => {}
        }

        fields += 1;
        if has_tab {
            pos += 1; // step past the TAB to the next field
        } else {
            break;
        }
    }

    // A line with six fields and no value gets a blank value (curl's fixup).
    if fields == 6 {
        value = Some(String::new());
        fields += 1;
    }
    // Without the full seven fields the line is not a valid cookie.
    if fields != 7 {
        return None;
    }

    Some(Cookie {
        name: name?,
        value: value.unwrap_or_default(),
        path,
        domain,
        expires,
        creationtime: 0, // assigned by the jar on insertion
        tailmatch,
        secure: co_secure,
        livecookie: false, // set by the jar based on running state
        httponly,
        prefix_secure,
        prefix_host,
    })
}

/// Case-insensitive check that `name` begins with the `n`-byte literal `lit`,
/// mirroring `curl_strnequal(lit, name, n)` used for the Netscape name-prefix
/// detection. Requires `name` to be at least `n` bytes long.
fn strnequal_prefix_full(name: &str, lit: &str, n: usize) -> bool {
    let name = name.as_bytes();
    let lit = lit.as_bytes();
    debug_assert_eq!(lit.len(), n);
    name.len() >= n && name[..n].eq_ignore_ascii_case(lit)
}

/// Case-insensitive comparison of the first `n` bytes of `a` and `b`, faithfully
/// mirroring C's `curl_strnequal(a, b, n)` (a length-bounded `strncasecmp`)
/// including its NUL-terminator semantics: if either string is shorter than `n`,
/// the comparison stops at that string's end and equality additionally requires
/// the other string to end at the very same position.
///
/// Used only by [`CookieJar::try_replace`] for the non-secure-overlay guard,
/// where `a` (the existing cookie's path) is always at least `n` bytes long.
fn strnequal_n(a: &str, b: &str, n: usize) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let m = n.min(a.len()).min(b.len());
    if !a[..m].eq_ignore_ascii_case(&b[..m]) {
        return false;
    }
    if m < n {
        // One (or both) of the strings ran out before `n` bytes; `strncasecmp`
        // would have compared the NUL terminator next, so the strings are equal
        // for `n` bytes only when they end at exactly the same length.
        return a.len() == b.len();
    }
    true
}

/// Returns whether `line` begins with a case-insensitive `Set-Cookie:` prefix,
/// the equivalent of curl's `checkprefix("Set-Cookie:", line)`.
fn has_setcookie_prefix(line: &str) -> bool {
    let bytes = line.as_bytes();
    bytes.len() >= 11 && bytes[..11].eq_ignore_ascii_case(b"Set-Cookie:")
}

/// Skips leading blanks (space and TAB), mirroring curl's
/// `curlx_str_passblanks` used after the `Set-Cookie:` prefix on a file line.
fn passblanks(s: &str) -> &str {
    s.trim_start_matches([' ', '\t'])
}

/// Strips a single surrounding pair of `[` `]` brackets from an IPv6 host
/// literal, yielding the bare address curl stores in `conn->host.name`. Used by
/// the URL-driven convenience methods so that IPv6 matching and
/// [`CookieJar::secure_context`] see `::1` rather than `[::1]`.
fn strip_host_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// Rejects control octets in a cookie name or value, mirroring curl's
/// `invalid_octets`: bytes `0x01`–`0x1f` (except TAB, `0x09`) and `0x7f` are
/// invalid. Parsing also stops at a NUL, matching the C `while(len && *p)` loop.
fn invalid_octets(s: &[u8]) -> bool {
    for &p in s {
        if p == 0 {
            break;
        }
        if (p != 9 && p < 0x20) || p == 0x7f {
            return true;
        }
    }
    false
}

/// Clamps a cookie's expiry to at most 400 days into the future, aligned to a
/// 60-second boundary, mirroring curl's `cap_expires`.
///
/// A `0` (session) expiry is left untouched, and the clamp is skipped near the
/// representable maximum exactly as the C guard `(TIME_T_MAX - COOKIES_MAXAGE -
/// 30) > now` does.
fn cap_expires(now: i64, expires: i64) -> i64 {
    if expires != 0 && (EXPIRE_NEVER - COOKIES_MAXAGE - 30) > now {
        let cap = now + COOKIES_MAXAGE;
        if expires > cap {
            let cap = cap + 30;
            return (cap / 60) * 60;
        }
    }
    expires
}

/// Outcome of parsing a leading non-negative decimal integer, mirroring the
/// three relevant return states of curl's `curlx_str_number`.
enum NumParse {
    /// A value was parsed successfully (clamped to `<= i64::MAX`).
    Ok(i64),
    /// The digits represent a value larger than `i64::MAX` (`STRE_OVERFLOW`).
    Overflow,
    /// No leading decimal digit was present (a parse failure).
    Bad,
}

/// Parses the leading run of ASCII decimal digits of `s` into an [`i64`],
/// mirroring `curlx_str_number(&p, &num, CURL_OFF_T_MAX)`.
///
/// Parsing stops at the first non-digit (trailing characters are ignored, as in
/// curl). A leading non-digit yields [`NumParse::Bad`]; a value exceeding
/// [`i64::MAX`] yields [`NumParse::Overflow`].
fn parse_leading_number(s: &str) -> NumParse {
    let mut seen = false;
    let mut acc: i64 = 0;
    for &b in s.as_bytes() {
        if !b.is_ascii_digit() {
            break;
        }
        seen = true;
        let digit = i64::from(b - b'0');
        acc = match acc.checked_mul(10).and_then(|v| v.checked_add(digit)) {
            Some(v) => v,
            None => return NumParse::Overflow,
        };
    }
    if seen {
        NumParse::Ok(acc)
    } else {
        NumParse::Bad
    }
}

/// Returns the current wall-clock time as a Unix timestamp in seconds (UTC).
///
/// This is the convenience curl gets from `time(NULL)`; callers that need
/// deterministic behavior (tests, replay) should pass their own `now` to the
/// time-sensitive [`CookieJar`] methods instead. Before the Unix epoch the
/// result saturates to `0`.
#[must_use]
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ----------------------------------------------------------------------------
// The cookie jar (`struct CookieInfo` in `lib/cookie.h`).
// ----------------------------------------------------------------------------

/// The action a [`CookieJar::cookie_list_command`] call resolved to.
///
/// `CURLOPT_COOKIELIST`'s `ALL`, `SESS`, and "add a line" verbs are performed
/// in place and reported as [`Self::ClearedAll`], [`Self::ClearedSession`], and
/// [`Self::Added`]. `FLUSH` and `RELOAD` cannot be carried out by the jar alone
/// — they need the cookie-jar filename and the list of cookie files, which live
/// on the easy handle — so they are reported back to the caller as
/// [`Self::Flush`] / [`Self::Reload`] for it to act on (calling
/// [`CookieJar::save`] or [`CookieJar::load_file`] respectively). This mirrors
/// how `lib/setopt.c`'s `cookielist()` dispatches to `Curl_flush_cookies` /
/// `Curl_cookie_loadfiles`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieListAction {
    /// `ALL` — every cookie was cleared.
    ClearedAll,
    /// `SESS` — session cookies were cleared.
    ClearedSession,
    /// `FLUSH` — the caller should persist the jar to its configured file.
    Flush,
    /// `RELOAD` — the caller should reload the jar from its cookie files.
    Reload,
    /// A single cookie line was processed; the payload is `true` when a cookie
    /// was actually stored (or replaced) and `false` when it was ignored.
    Added(bool),
}

/// An in-memory cookie store: parses, holds, matches and persists cookies.
///
/// This is the Rust image of C's `struct CookieInfo`. Cookies are kept in
/// [`COOKIE_HASH_SIZE`] insertion-ordered buckets keyed by [`cookiehash`] so
/// that outgoing-request lookups, the send cap, and the dump order all match
/// curl exactly.
///
/// # Thread-safe sharing
///
/// A `CookieJar` is plain owned data (`Send + Sync`), so the shared-handle layer
/// (`crate::share`) can wrap it in an `Arc<Mutex<CookieJar>>` to back a
/// `CURLSH` with `CURL_LOCK_DATA_COOKIE`; this type intentionally does **not**
/// embed its own lock, leaving the locking policy to the owner exactly as curl
/// does (the C `CookieInfo` carries no mutex either).
#[derive(Debug, Clone)]
pub struct CookieJar {
    /// The hash buckets; always exactly [`COOKIE_HASH_SIZE`] long.
    buckets: Vec<Vec<Cookie>>,
    /// The earliest future expiry currently known, used to skip full expiry
    /// scans (`next_expiration`). Initialized to [`EXPIRE_NEVER`].
    next_expiration: i64,
    /// Total number of cookies stored (`numcookies`).
    numcookies: u32,
    /// The last creation index handed out (`lastct`); pre-incremented per add.
    lastct: u32,
    /// Whether the jar is "running" — i.e. processing live server cookies rather
    /// than loading from a file (`running`). Controls secure-cookie acceptance
    /// and whether `save` persists.
    running: bool,
    /// Whether a new session was requested, so session cookies are discarded on
    /// load (`newsession`).
    newsession: bool,
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::new()
    }
}

impl CookieJar {
    /// Creates an empty jar — the equivalent of `Curl_cookie_init()`.
    ///
    /// The `next_expiration` tracker starts at [`EXPIRE_NEVER`] to signal "not
    /// enough information yet", exactly as curl does.
    #[must_use]
    pub fn new() -> Self {
        let mut buckets = Vec::with_capacity(COOKIE_HASH_SIZE);
        buckets.resize_with(COOKIE_HASH_SIZE, Vec::new);
        Self {
            buckets,
            next_expiration: EXPIRE_NEVER,
            numcookies: 0,
            lastct: 0,
            running: false,
            newsession: false,
        }
    }

    /// Creates a jar and immediately loads cookies from `file` — the combined
    /// effect of `Curl_cookie_init()` followed by `cookie_load()`.
    ///
    /// `file` may be `"-"` to read from standard input. When `newsession` is
    /// `true`, session cookies present in the file are discarded on load.
    ///
    /// # Errors
    ///
    /// Returns an error only on an I/O failure reading standard input; a missing
    /// or unreadable on-disk file is treated as "no cookies" (a warning in
    /// curl), matching `cookie_load`'s tolerance.
    pub fn init_from_file(file: &str, newsession: bool, now: i64) -> Result<Self> {
        let mut jar = Self::new();
        jar.load_file(file, newsession, now)?;
        Ok(jar)
    }

    /// Marks the jar as running (processing live cookies) — the equivalent of
    /// `Curl_cookie_run()`. While running, secure cookies are accepted only over
    /// a secure origin and [`save`](Self::save) is permitted.
    pub fn set_running(&mut self, running: bool) {
        self.running = running;
    }

    /// Returns whether the jar is currently running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Sets whether a new session is in effect (discard session cookies on the
    /// next file load), mirroring `data->set.cookiesession`.
    pub fn set_newsession(&mut self, newsession: bool) {
        self.newsession = newsession;
    }

    /// Returns the number of cookies currently stored (`numcookies`).
    #[must_use]
    pub fn num_cookies(&self) -> u32 {
        self.numcookies
    }

    /// Returns `true` if the jar holds no cookies.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.numcookies == 0
    }

    // ------------------------------------------------------------------------
    // Expiry / clearing (`remove_expired`, `Curl_cookie_clearall`,
    // `Curl_cookie_clearsess`).
    // ------------------------------------------------------------------------

    /// Drops every cookie whose persistent expiry is in the past, mirroring
    /// curl's `remove_expired`.
    ///
    /// As an optimization (preserved from curl) the full scan is skipped when
    /// the earliest recorded future expiry is still ahead of `now`; otherwise
    /// the tracker is recomputed during the scan. Session cookies (`expires ==
    /// 0`) are never removed here.
    pub fn remove_expired(&mut self, now: i64) {
        // Nothing to do when the earliest known future expiry is still ahead of
        // `now`, or when the jar is empty (`Curl_cookie_add` lowers
        // `next_expiration` to a just-added cookie's expiry — even one already
        // in the past — so this guard never hides an expired cookie).
        if self.next_expiration > now || self.numcookies == 0 {
            return;
        }
        let mut next_exp = EXPIRE_NEVER;
        let mut removed: u32 = 0;
        for bucket in &mut self.buckets {
            let mut i = 0;
            while i < bucket.len() {
                let exp = bucket[i].expires;
                if exp != 0 {
                    if exp < now {
                        bucket.remove(i);
                        removed += 1;
                        continue; // the next element has shifted into index `i`
                    } else if exp < next_exp {
                        next_exp = exp;
                    }
                }
                i += 1;
            }
        }
        self.next_expiration = next_exp;
        self.numcookies = self.numcookies.saturating_sub(removed);
    }

    /// Removes all cookies and resets the count, mirroring
    /// `Curl_cookie_clearall`. The creation-index counter is intentionally left
    /// untouched, exactly as in C.
    pub fn clear_all(&mut self) {
        for bucket in &mut self.buckets {
            bucket.clear();
        }
        self.numcookies = 0;
    }

    /// Removes all session cookies (those with `expires == 0`), mirroring
    /// `Curl_cookie_clearsess`.
    pub fn clear_session(&mut self) {
        let mut removed: u32 = 0;
        for bucket in &mut self.buckets {
            let before = bucket.len();
            bucket.retain(|c| c.expires != 0);
            removed += (before - bucket.len()) as u32;
        }
        self.numcookies = self.numcookies.saturating_sub(removed);
    }

    // ------------------------------------------------------------------------
    // File loading (`cookie_load`).
    // ------------------------------------------------------------------------

    /// Loads cookies from `file`, mirroring curl's `cookie_load`.
    ///
    /// `file` may be `"-"` to read from standard input; an empty string is a
    /// no-op. Each line is dispatched to the `Set-Cookie:`-header parser (when it
    /// carries that case-insensitive prefix, after which leading blanks are
    /// skipped) or otherwise to the Netscape parser, both with the file-load
    /// settings `no_expire = true` and `secure = true`. The jar is marked
    /// not-running for the duration of the load (so session cookies and secure
    /// cookies are accepted from the file), expired cookies are pruned once after
    /// the whole file is read, and the jar is left running on return.
    ///
    /// # Errors
    ///
    /// Propagates an I/O error only when reading standard input fails; a file
    /// that cannot be opened is tolerated (a warning in curl), leaving the jar
    /// unchanged for that file.
    pub fn load_file(&mut self, file: &str, newsession: bool, now: i64) -> Result<()> {
        self.newsession = newsession;
        self.running = false;

        // Acquire the file contents. Standard input read failures propagate;
        // a missing/unreadable named file is tolerated, exactly as curl warns
        // and carries on.
        let content: Option<String> = if file.is_empty() {
            None
        } else if file == "-" {
            let mut s = String::new();
            std::io::stdin().lock().read_to_string(&mut s)?;
            Some(s)
        } else {
            match std::fs::read(file) {
                Ok(bytes) => Some(String::from_utf8_lossy(&bytes).into_owned()),
                Err(_) => None, // WARNING: failed to open cookie file — tolerated
            }
        };

        if let Some(text) = content {
            for line in text.lines() {
                if has_setcookie_prefix(line) {
                    let header = passblanks(&line[11..]);
                    // File reading cookie failures are not propagated, matching
                    // curl (there is no way to report them per line).
                    let _ = self.add(header, true, true, None, None, true, now);
                } else {
                    let _ = self.add(line, false, true, None, None, true, now);
                }
            }
            // Prune expired cookies once, after the whole file is read.
            self.remove_expired(now);
        }

        self.running = true;
        Ok(())
    }

    // ------------------------------------------------------------------------
    // Public-suffix / secure-origin checks.
    // ------------------------------------------------------------------------

    /// Returns whether `co`'s domain must be rejected as a public suffix,
    /// mirroring curl's `is_public_suffix`.
    ///
    /// The check is performed only when there is a request domain, the cookie
    /// carries an explicit domain, and that domain is not a numeric IP literal —
    /// exactly curl's guard. The decision is delegated to
    /// [`crate::psl::Psl::is_cookie_domain_acceptable`], which reproduces
    /// `libpsl`'s `psl_is_cookie_domain_acceptable` when the `psl` feature is on
    /// and curl's conservative `host_within_domain && !bad_domain` fallback when
    /// it is off; an unacceptable domain means "drop the cookie".
    fn is_public_suffix(&self, co: &Cookie, default_domain: Option<&str>) -> bool {
        if let (Some(domain), Some(cookie_domain)) = (default_domain, co.domain.as_deref()) {
            if is_ip_literal(cookie_domain) {
                return false;
            }
            let psl = crate::psl::Psl::global();
            if !psl.is_cookie_domain_acceptable(domain, cookie_domain) {
                return true;
            }
        }
        false
    }

    /// Returns whether the `(scheme, host)` pair denotes a "secure context" for
    /// cookie purposes, mirroring curl's `Curl_secure_context`.
    ///
    /// A context is secure over HTTPS or WSS, or when the host is the loopback
    /// `localhost` / `127.0.0.1` / `::1`. The scheme comparison is
    /// case-insensitive; the loopback literals match curl's exact spellings.
    #[must_use]
    pub fn secure_context(scheme: &str, host: &str) -> bool {
        scheme.eq_ignore_ascii_case("https")
            || scheme.eq_ignore_ascii_case("wss")
            || host.eq_ignore_ascii_case("localhost")
            || host == "127.0.0.1"
            || host == "::1"
    }

    // ------------------------------------------------------------------------
    // Storing cookies (`replace_existing`, `Curl_cookie_add`).
    // ------------------------------------------------------------------------

    /// Resolves whether a freshly-parsed cookie should be stored, removing any
    /// cookie it supersedes, mirroring curl's `replace_existing`.
    ///
    /// Returns `None` when the new cookie must be dropped — either because it
    /// would let a non-secure cookie overlay an existing secure cookie sharing
    /// the same name, domain and (segment-prefixed) path over an insecure
    /// connection, or because an equivalent **live** (header-sourced) cookie
    /// already exists and the new one is not live. Otherwise returns
    /// `Some(replaced)`, having unlinked the superseded cookie (if any) and
    /// copied its `creationtime` onto `co` so the replacement keeps the original
    /// ordering.
    fn try_replace(&mut self, co: &mut Cookie, secure: bool) -> Option<bool> {
        let myhash = cookiehash(co.domain.as_deref());
        let mut replace_idx: Option<usize> = None;

        {
            let bucket = &self.buckets[myhash];
            for (idx, clist) in bucket.iter().enumerate() {
                if clist.name == co.name {
                    // Do the names' domains match (both equal, or both absent)?
                    let matching_domains = match (clist.domain.as_deref(), co.domain.as_deref()) {
                        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                        (None, None) => true,
                        _ => false,
                    };

                    // A non-secure cookie may not overlay an existing secure one.
                    if matching_domains
                        && clist.path.is_some()
                        && co.path.is_some()
                        && clist.secure
                        && !co.secure
                        && !secure
                    {
                        let cp = clist.path.as_deref().unwrap();
                        // cllen spans up to (not including) the first '/' after
                        // index 0, else the whole path (`sep - clist->path`).
                        let cllen = match cp.as_bytes()[1..].iter().position(|&b| b == b'/') {
                            Some(rel) => 1 + rel,
                            None => cp.len(),
                        };
                        if strnequal_n(cp, co.path.as_deref().unwrap(), cllen) {
                            return None; // would overlay an existing secure cookie
                        }
                    }
                }

                // Identify the (first) cookie this one replaces.
                if replace_idx.is_none() && clist.name == co.name {
                    let mut replace_old = match (clist.domain.as_deref(), co.domain.as_deref()) {
                        (Some(a), Some(b)) => {
                            a.eq_ignore_ascii_case(b) && clist.tailmatch == co.tailmatch
                        }
                        (None, None) => true,
                        _ => false,
                    };
                    if replace_old {
                        // Paths must be identical, or both absent.
                        match (clist.path.as_deref(), co.path.as_deref()) {
                            (Some(a), Some(b)) if !a.eq_ignore_ascii_case(b) => {
                                replace_old = false;
                            }
                            (Some(_), None) | (None, Some(_)) => replace_old = false,
                            _ => {}
                        }
                    }
                    // A live (header) cookie is preferred over a file-loaded one.
                    if replace_old && !co.livecookie && clist.livecookie {
                        return None;
                    }
                    if replace_old {
                        replace_idx = Some(idx);
                    }
                }
            }
        }

        if let Some(idx) = replace_idx {
            // Keep the superseded cookie's creation time, then unlink it.
            co.creationtime = self.buckets[myhash][idx].creationtime;
            self.buckets[myhash].remove(idx);
            Some(true)
        } else {
            Some(false)
        }
    }

    /// Adds a single cookie line to the jar, mirroring curl's `Curl_cookie_add`.
    ///
    /// `line` is parsed as an HTTP `Set-Cookie:` value when `http_header` is
    /// `true`, otherwise as a Netscape file line. `default_domain` /
    /// `default_path` supply the request host and path used to default a cookie
    /// that omits `Domain`/`Path` (both `None` when loading from a file).
    /// `secure` reflects whether the origin is secure. When `no_expire` is
    /// `false` the jar's expired cookies are pruned as part of the add (curl
    /// skips this while bulk-loading a file).
    ///
    /// Returns `Ok(true)` when a cookie was stored (or replaced) and `Ok(false)`
    /// when the line was ignored (malformed, a rejected prefix/public-suffix
    /// domain, a discarded session cookie, or a dropped overlay).
    ///
    /// Note: curl's per-response `MAX_SET_COOKIE_AMOUNT` cap is a request-scoped
    /// concern owned by the HTTP layer feeding this method, not jar state, and so
    /// is intentionally not enforced here.
    #[allow(clippy::too_many_arguments)]
    pub fn add(
        &mut self,
        line: &str,
        http_header: bool,
        no_expire: bool,
        default_domain: Option<&str>,
        default_path: Option<&str>,
        secure: bool,
        now: i64,
    ) -> Result<bool> {
        // Parse the incoming line into a candidate cookie.
        let mut co = if http_header {
            match parse_cookie_header(
                line,
                default_domain,
                default_path,
                secure,
                self.running,
                now,
            ) {
                Some(c) => c,
                None => return Ok(false),
            }
        } else {
            match parse_netscape(line, secure, self.running) {
                Some(c) => c,
                None => return Ok(false),
            }
        };

        // The __Secure- prefix requires the cookie to be secure.
        if co.prefix_secure && !co.secure {
            return Ok(false);
        }
        // The __Host- prefix requires secure, a "/" path and no explicit domain
        // (encoded by the absence of a tail-match).
        if co.prefix_host && !(co.secure && co.path.as_deref() == Some("/") && !co.tailmatch) {
            return Ok(false);
        }

        // When loading a file for a fresh session, discard session cookies.
        if !self.running && self.newsession && co.is_session() {
            return Ok(false);
        }

        co.livecookie = self.running;
        self.lastct = self.lastct.wrapping_add(1);
        co.creationtime = self.lastct;

        if !no_expire {
            self.remove_expired(now);
        }

        // Reject cookies set on a public suffix / otherwise-protected domain.
        if self.is_public_suffix(&co, default_domain) {
            return Ok(false);
        }

        // Supersede any matching cookie, or drop the new one if disallowed.
        let replaced = match self.try_replace(&mut co, secure) {
            Some(r) => r,
            None => return Ok(false),
        };

        // Store the cookie in its domain's bucket.
        let myhash = cookiehash(co.domain.as_deref());
        let co_expires = co.expires;
        self.buckets[myhash].push(co);

        if !replaced {
            self.numcookies += 1;
        }
        // Track the earliest future expiry for the `remove_expired` fast-path.
        if co_expires != 0 && co_expires < self.next_expiration {
            self.next_expiration = co_expires;
        }

        Ok(true)
    }

    /// Stores a `Set-Cookie:` header value received for the request URL `url`,
    /// the common live-processing entry point (`Curl_cookie_add` with the
    /// request's domain/path and secure context).
    ///
    /// `header` is the value **after** the `Set-Cookie:` label. The request
    /// host (with any IPv6 brackets removed) and path become the cookie's
    /// defaults, and the secure context is derived from the URL's scheme/host.
    /// The caller is expected to have marked the jar running (see
    /// [`set_running`](Self::set_running)).
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::UrlMalformat`] when `url` cannot yield request parts.
    pub fn store_response_url(&mut self, header: &str, url: &CurlUrl, now: i64) -> Result<bool> {
        let parts = url
            .to_request_parts()
            .map_err(|_| CurlError::UrlMalformat)?;
        let host = strip_host_brackets(&parts.host);
        let secure = Self::secure_context(&parts.scheme, host);
        self.add(
            header,
            true,
            false,
            Some(host),
            Some(&parts.path),
            secure,
            now,
        )
    }

    /// Convenience alias for [`store_response_url`](Self::store_response_url)
    /// using the wording from the task's public-API description: parse and store
    /// a `Set-Cookie:` value (the part after the label) against `request_url`.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::UrlMalformat`] when `request_url` cannot yield
    /// request parts.
    pub fn add_from_set_cookie(
        &mut self,
        header: &str,
        request_url: &CurlUrl,
        now: i64,
    ) -> Result<bool> {
        self.store_response_url(header, request_url, now)
    }

    // ------------------------------------------------------------------------
    // Matching cookies to a request (`Curl_cookie_getlist`, `cookie_sort`).
    // ------------------------------------------------------------------------

    /// Returns the cookies that should be sent to `host`/`path`, in the exact
    /// order curl emits them, mirroring `Curl_cookie_getlist`.
    ///
    /// `secure` indicates whether the connection is secure (secure-only cookies
    /// are withheld otherwise). Expired cookies are pruned first. Selection
    /// applies curl's domain rule (no domain, a tail-match for tail-matching
    /// non-IP cookies, or an exact host match otherwise) and path rule
    /// ([`pathmatch`]), capping the result at [`MAX_COOKIE_SEND_AMOUNT`]. The
    /// returned clones are sorted by descending path length, then descending
    /// domain length, then descending name length, with the unique creation time
    /// as the final (newest-first) tiebreaker — the order required for
    /// byte-for-byte `Cookie:` header parity.
    pub fn get_list(&mut self, host: &str, path: &str, secure: bool, now: i64) -> Vec<Cookie> {
        let myhash = cookiehash(Some(host));

        // Nothing to do without a populated bucket for this host.
        if self.buckets[myhash].is_empty() {
            return Vec::new();
        }

        // Remove expired cookies before matching.
        self.remove_expired(now);

        let is_ip = is_ip_literal(host);
        let mut matches: Vec<Cookie> = Vec::new();

        for co in &self.buckets[myhash] {
            // Secure-only cookies require a secure connection.
            if co.secure && !secure {
                continue;
            }
            // Domain rule.
            let domain_ok = match co.domain.as_deref() {
                None => true,
                Some(d) => {
                    if co.tailmatch && !is_ip {
                        cookie_tailmatch(d, host)
                    } else {
                        host.eq_ignore_ascii_case(d)
                    }
                }
            };
            if !domain_ok {
                continue;
            }
            // Path rule.
            let path_ok = match co.path.as_deref() {
                None => true,
                Some(p) => pathmatch(p, path),
            };
            if !path_ok {
                continue;
            }

            matches.push(co.clone());
            if matches.len() >= MAX_COOKIE_SEND_AMOUNT {
                break;
            }
        }

        if matches.len() > 1 {
            // Longest path first, then longest domain, then longest name, then
            // newest creation time (`cookie_sort`).
            matches.sort_by(|c1, c2| {
                let l1 = c1.path.as_deref().map_or(0, str::len);
                let l2 = c2.path.as_deref().map_or(0, str::len);
                if l1 != l2 {
                    return l2.cmp(&l1);
                }
                let l1 = c1.domain.as_deref().map_or(0, str::len);
                let l2 = c2.domain.as_deref().map_or(0, str::len);
                if l1 != l2 {
                    return l2.cmp(&l1);
                }
                if c1.name.len() != c2.name.len() {
                    return c2.name.len().cmp(&c1.name.len());
                }
                c2.creationtime.cmp(&c1.creationtime)
            });
        }

        matches
    }

    /// Builds the `Cookie:` request-header **value** for `host`/`path`,
    /// reproducing the formatting and size cap of curl's HTTP request builder
    /// (`http_cookies` in `lib/http.c`).
    ///
    /// The cookies are gathered and ordered by [`get_list`](Self::get_list) and
    /// joined as `name=value` pairs separated by `"; "`. The cumulative length is
    /// tracked exactly as curl does — seeded at the 8 bytes of the `"Cookie: "`
    /// label so that the [`MAX_COOKIE_HEADER_LEN`] cut-off matches — and emission
    /// stops before the first cookie that would breach the limit. The returned
    /// string carries neither the `Cookie: ` prefix nor a trailing CRLF; the
    /// caller adds those. An empty string means no cookie matched.
    pub fn match_for(&mut self, host: &str, path: &str, secure: bool, now: i64) -> String {
        let cookies = self.get_list(host, path, secure, now);
        let mut out = String::new();
        let mut clen: usize = 8; // tracks the eventual "Cookie: " + content length

        // `count` is the loop index; because emission stops at the first cookie
        // that would breach the cap (a `break`), it equals the number of cookies
        // already emitted, so `count > 0` correctly gates the "; " separator and
        // its two-byte contribution to `clen`, exactly as `lib/http.c` does.
        for (count, co) in cookies.iter().enumerate() {
            let add = co.name.len() + co.value.len() + 1;
            if clen + add >= MAX_COOKIE_HEADER_LEN {
                // Adding this cookie would exceed the header-size limit.
                break;
            }
            if count > 0 {
                out.push_str("; ");
            }
            out.push_str(&co.name);
            out.push('=');
            out.push_str(&co.value);
            clen += add + if count > 0 { 2 } else { 0 };
        }

        out
    }

    /// Builds the `Cookie:` header value for the request URL `url`, deriving the
    /// host (IPv6 brackets stripped), path and secure context from it before
    /// delegating to [`match_for`](Self::match_for).
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::UrlMalformat`] when `url` cannot yield request parts.
    pub fn match_for_url(&mut self, url: &CurlUrl, now: i64) -> Result<String> {
        let parts = url
            .to_request_parts()
            .map_err(|_| CurlError::UrlMalformat)?;
        let host = strip_host_brackets(&parts.host);
        let secure = Self::secure_context(&parts.scheme, host);
        Ok(self.match_for(host, &parts.path, secure, now))
    }

    // ------------------------------------------------------------------------
    // Netscape file output (`cookie_output`, `cookie_list`).
    // ------------------------------------------------------------------------

    /// Renders the entire jar in the Netscape/Mozilla `cookies.txt` format,
    /// mirroring curl's `cookie_output` (minus the file handling).
    ///
    /// Expired cookies are pruned first. The fixed three-line banner is emitted,
    /// then every cookie that carries a domain, in descending creation-time order
    /// (`cookie_sort_ct` — newest first), each as one [`Cookie::to_netscape_line`]
    /// terminated by `\n`. The result is byte-format compatible with curl so that
    /// cookie-jar dumps compare equal.
    pub fn write_to_string(&mut self, now: i64) -> String {
        self.remove_expired(now);

        let mut out = String::new();
        out.push_str("# Netscape HTTP Cookie File\n");
        out.push_str("# https://curl.se/docs/http-cookies.html\n");
        out.push_str("# This file was generated by libcurl! Edit at your own risk.\n\n");

        if self.numcookies > 0 {
            // Collect only cookies that carry a domain, then order newest-first.
            let mut array: Vec<&Cookie> = Vec::new();
            for bucket in &self.buckets {
                for co in bucket {
                    if co.domain.is_some() {
                        array.push(co);
                    }
                }
            }
            array.sort_by_key(|c| std::cmp::Reverse(c.creationtime));
            for co in array {
                out.push_str(&co.to_netscape_line());
                out.push('\n');
            }
        }

        out
    }

    /// Writes the jar to `file` in Netscape format, mirroring `cookie_output`.
    ///
    /// `file` may be `"-"` to write to standard output. For a named file the
    /// write is atomic: the content is built in memory, written to a sibling
    /// temporary file, and renamed over the target (the temporary file is removed
    /// on failure), matching curl's `Curl_fopen` + rename strategy.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::WriteError`] on any I/O failure writing standard
    /// output, the temporary file, or performing the rename.
    pub fn save(&mut self, file: &str, now: i64) -> Result<()> {
        let content = self.write_to_string(now);

        if file == "-" {
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            lock.write_all(content.as_bytes())
                .map_err(|_| CurlError::WriteError)?;
            lock.flush().map_err(|_| CurlError::WriteError)?;
            return Ok(());
        }

        // Atomic replace: write a sibling temp file, then rename over the target.
        let tmp = format!("{file}.tmp.{}", std::process::id());
        if std::fs::write(&tmp, content.as_bytes()).is_err() {
            let _ = std::fs::remove_file(&tmp);
            return Err(CurlError::WriteError);
        }
        if std::fs::rename(&tmp, file).is_err() {
            let _ = std::fs::remove_file(&tmp);
            return Err(CurlError::WriteError);
        }
        Ok(())
    }

    /// Exports the jar as a list of Netscape-format lines, mirroring curl's
    /// `cookie_list` (the backing of `CURLINFO_COOKIELIST`).
    ///
    /// Expired cookies are pruned first. Every cookie that carries a domain is
    /// emitted as one [`Cookie::to_netscape_line`], in hash-bucket then insertion
    /// order (curl applies **no** sort here — unlike the file dump). An empty
    /// vector is returned when the jar holds no cookies.
    pub fn export_list(&mut self, now: i64) -> Vec<String> {
        if self.numcookies == 0 {
            return Vec::new();
        }
        self.remove_expired(now);

        let mut out = Vec::new();
        for bucket in &self.buckets {
            for co in bucket {
                if co.domain.is_some() {
                    out.push(co.to_netscape_line());
                }
            }
        }
        out
    }

    // ------------------------------------------------------------------------
    // CURLOPT_COOKIELIST command dispatch (`cookielist` in `lib/setopt.c`).
    // ------------------------------------------------------------------------

    /// Interprets a `CURLOPT_COOKIELIST` string, mirroring `lib/setopt.c`'s
    /// `cookielist`.
    ///
    /// The case-insensitive verbs `ALL` and `SESS` clear all / session cookies
    /// in place; `FLUSH` and `RELOAD` cannot be completed by the jar alone and
    /// are reported back via [`CookieListAction`] for the owning handle to act
    /// on. Any other value is treated as a cookie line — parsed as a
    /// `Set-Cookie:` header when it carries that prefix (skipping the label),
    /// otherwise as a Netscape line — and stored with live settings
    /// (`no_expire = false`, `secure = true`).
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::BadFunctionArgument`] when a cookie line exceeds
    /// [`CURL_MAX_INPUT_LENGTH`], matching curl's abuse guard.
    pub fn cookie_list_command(&mut self, ptr: &str, now: i64) -> Result<CookieListAction> {
        if ptr.eq_ignore_ascii_case("ALL") {
            self.clear_all();
            return Ok(CookieListAction::ClearedAll);
        }
        if ptr.eq_ignore_ascii_case("SESS") {
            self.clear_session();
            return Ok(CookieListAction::ClearedSession);
        }
        if ptr.eq_ignore_ascii_case("FLUSH") {
            return Ok(CookieListAction::Flush);
        }
        if ptr.eq_ignore_ascii_case("RELOAD") {
            return Ok(CookieListAction::Reload);
        }

        // General protection against mistakes and abuse.
        if ptr.len() > CURL_MAX_INPUT_LENGTH {
            return Err(CurlError::BadFunctionArgument);
        }

        let stored = if has_setcookie_prefix(ptr) {
            self.add(&ptr[11..], true, false, None, None, true, now)?
        } else {
            self.add(ptr, false, false, None, None, true, now)?
        };
        Ok(CookieListAction::Added(stored))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed "now" (2001-09-09T01:46:40Z) used by every time-sensitive test so
    /// expiry math is deterministic and well clear of any clamping edge.
    const NOW: i64 = 1_000_000_000;

    // ---- stateless helpers ------------------------------------------------

    #[test]
    fn raw_toupper_folds_only_ascii_lowercase() {
        assert_eq!(raw_toupper(b'a'), b'A');
        assert_eq!(raw_toupper(b'z'), b'Z');
        assert_eq!(raw_toupper(b'A'), b'A');
        assert_eq!(raw_toupper(b'0'), b'0');
        assert_eq!(raw_toupper(b'.'), b'.');
    }

    #[test]
    fn ip_literal_detection() {
        assert!(is_ip_literal("127.0.0.1"));
        assert!(is_ip_literal("::1"));
        assert!(is_ip_literal("2001:db8::1"));
        assert!(!is_ip_literal("example.com"));
        assert!(!is_ip_literal("localhost"));
        // Bracketed IPv6 is not a bare literal (curl stores the bare form).
        assert!(!is_ip_literal("[::1]"));
    }

    #[test]
    fn top_domain_takes_last_two_labels() {
        assert_eq!(get_top_domain("www.example.com"), "example.com");
        assert_eq!(get_top_domain("a.b.c.example.com"), "example.com");
        assert_eq!(get_top_domain("example.com"), "example.com");
        assert_eq!(get_top_domain("com"), "com");
        assert_eq!(get_top_domain(""), "");
    }

    #[test]
    fn cookiehash_buckets_share_by_top_domain() {
        // No domain / IP host hash to bucket 0.
        assert_eq!(cookiehash(None), 0);
        assert_eq!(cookiehash(Some("127.0.0.1")), 0);
        assert_eq!(cookiehash(Some("::1")), 0);
        // Sub-domains of the same registrable domain share a bucket.
        assert_eq!(
            cookiehash(Some("www.example.com")),
            cookiehash(Some("mail.example.com"))
        );
        assert_eq!(
            cookiehash(Some("example.com")),
            cookiehash(Some("a.b.example.com"))
        );
        // The bucket index is always within range.
        assert!(cookiehash(Some("example.com")) < COOKIE_HASH_SIZE);
    }

    #[test]
    fn tailmatch_respects_label_boundaries() {
        assert!(cookie_tailmatch("example.com", "www.example.com"));
        assert!(cookie_tailmatch("example.com", "example.com"));
        // Not a boundary match.
        assert!(!cookie_tailmatch("ample.com", "example.com"));
        // Host shorter than the cookie domain never matches.
        assert!(!cookie_tailmatch("www.example.com", "example.com"));
        // Case-insensitive.
        assert!(cookie_tailmatch("Example.COM", "WWW.example.com"));
    }

    #[test]
    fn pathmatch_prefix_rules() {
        assert!(pathmatch("/", "/anything/here"));
        assert!(pathmatch("/foo", "/foo"));
        assert!(pathmatch("/foo", "/foo/bar"));
        assert!(!pathmatch("/foo", "/foobar"));
        assert!(!pathmatch("/foo", "/fo"));
        // An empty / relative request path is treated as "/".
        assert!(pathmatch("/", ""));
        assert!(!pathmatch("/foo", ""));
        // Path comparison is case-sensitive.
        assert!(!pathmatch("/Foo", "/foo"));
    }

    #[test]
    fn sanitize_cookie_path_rules() {
        assert_eq!(sanitize_cookie_path(b"/foo/"), "/foo");
        assert_eq!(sanitize_cookie_path(b"\"/foo\""), "/foo");
        assert_eq!(sanitize_cookie_path(b""), "/");
        assert_eq!(sanitize_cookie_path(b"foo"), "/"); // no leading slash
        assert_eq!(sanitize_cookie_path(b"/"), "/");
        assert_eq!(sanitize_cookie_path(b"/a/b"), "/a/b");
        // Only a single trailing slash is stripped, and never the root.
        assert_eq!(sanitize_cookie_path(b"/a//"), "/a/");
    }

    #[test]
    fn invalid_octets_rejects_controls() {
        assert!(!invalid_octets(b"normal-value"));
        assert!(!invalid_octets(b"with\ttab")); // TAB is allowed here
        assert!(invalid_octets(b"with\x01ctrl"));
        assert!(invalid_octets(b"with\x7fdel"));
        assert!(!invalid_octets(b"")); // empty stops immediately
    }

    #[test]
    fn cap_expires_clamps_far_future() {
        // A modest Max-Age is left untouched.
        assert_eq!(cap_expires(NOW, NOW + 3600), NOW + 3600);
        // A far-future expiry is capped to roughly now + COOKIES_MAXAGE.
        let capped = cap_expires(NOW, EXPIRE_NEVER);
        assert!(capped <= NOW + COOKIES_MAXAGE + 30);
        assert!(capped >= NOW + COOKIES_MAXAGE);
        assert_eq!(capped % 60, 0); // rounded down to the minute
                                    // Session cookies (0) are never modified.
        assert_eq!(cap_expires(NOW, 0), 0);
    }

    // ---- Set-Cookie parsing & storing ------------------------------------

    #[cfg_attr(miri, ignore)]
    #[test]
    fn add_basic_cookie_and_match() {
        let mut jar = CookieJar::new();
        assert!(jar
            .add(
                "foo=bar",
                true,
                false,
                Some("example.com"),
                Some("/"),
                false,
                NOW
            )
            .unwrap());
        assert_eq!(jar.num_cookies(), 1);
        assert_eq!(jar.match_for("example.com", "/", false, NOW), "foo=bar");
        // A different host in the same registrable domain without a Domain=
        // attribute must NOT receive the cookie (exact host match required).
        assert_eq!(jar.match_for("www.example.com", "/", false, NOW), "");
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn domain_attribute_enables_tailmatch() {
        let mut jar = CookieJar::new();
        assert!(jar
            .add(
                "foo=bar; Domain=example.com",
                true,
                false,
                Some("www.example.com"),
                Some("/"),
                false,
                NOW,
            )
            .unwrap());
        assert_eq!(jar.match_for("www.example.com", "/", false, NOW), "foo=bar");
        assert_eq!(jar.match_for("example.com", "/", false, NOW), "foo=bar");
        assert_eq!(jar.match_for("other.com", "/", false, NOW), "");
    }

    #[test]
    fn bad_tailmatch_domain_is_dropped() {
        let mut jar = CookieJar::new();
        // Domain=other.com does not tail-match the request host -> dropped.
        assert!(!jar
            .add(
                "foo=bar; Domain=other.com",
                true,
                false,
                Some("www.example.com"),
                Some("/"),
                false,
                NOW,
            )
            .unwrap());
        assert_eq!(jar.num_cookies(), 0);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn secure_cookie_withheld_over_insecure() {
        let mut jar = CookieJar::new();
        jar.set_running(true);
        // Accepted because the origin is secure.
        assert!(jar
            .add(
                "s=1; Secure",
                true,
                false,
                Some("example.com"),
                Some("/"),
                true,
                NOW
            )
            .unwrap());
        // Withheld on an insecure request, sent on a secure one.
        assert_eq!(jar.match_for("example.com", "/", false, NOW), "");
        assert_eq!(jar.match_for("example.com", "/", true, NOW), "s=1");
    }

    #[test]
    fn secure_attribute_rejected_when_running_and_insecure() {
        let mut jar = CookieJar::new();
        jar.set_running(true);
        // running && !secure -> a Secure cookie cannot be set.
        assert!(!jar
            .add(
                "s=1; Secure",
                true,
                false,
                Some("example.com"),
                Some("/"),
                false,
                NOW
            )
            .unwrap());
        assert_eq!(jar.num_cookies(), 0);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn max_age_zero_expires_immediately() {
        let mut jar = CookieJar::new();
        // Max-Age=0 -> expire now (stored, then pruned on the next lookup).
        assert!(jar
            .add(
                "foo=bar; Max-Age=0",
                true,
                false,
                Some("example.com"),
                Some("/"),
                false,
                NOW
            )
            .unwrap());
        assert_eq!(jar.match_for("example.com", "/", false, NOW), "");
        assert_eq!(jar.num_cookies(), 0);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn max_age_persistent_cookie() {
        let mut jar = CookieJar::new();
        assert!(jar
            .add(
                "foo=bar; Max-Age=3600",
                true,
                false,
                Some("example.com"),
                Some("/"),
                false,
                NOW,
            )
            .unwrap());
        // Still valid an hour minus a second from now; gone an hour and one later.
        assert_eq!(
            jar.match_for("example.com", "/", false, NOW + 3599),
            "foo=bar"
        );
        assert_eq!(jar.match_for("example.com", "/", false, NOW + 3601), "");
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn expires_in_the_past_is_pruned() {
        let mut jar = CookieJar::new();
        assert!(jar
            .add(
                "foo=bar; Expires=Mon, 01 Jan 1990 00:00:00 GMT",
                true,
                false,
                Some("example.com"),
                Some("/"),
                false,
                NOW,
            )
            .unwrap());
        // Parsed as a persistent (non-session) cookie that is already expired.
        assert_eq!(jar.match_for("example.com", "/", false, NOW), "");
        assert_eq!(jar.num_cookies(), 0);
    }

    #[test]
    fn overlong_line_and_name_are_rejected() {
        let mut jar = CookieJar::new();
        // Line longer than MAX_COOKIE_LINE.
        let huge = format!("foo={}", "v".repeat(MAX_COOKIE_LINE + 10));
        assert!(!jar
            .add(
                &huge,
                true,
                false,
                Some("example.com"),
                Some("/"),
                false,
                NOW
            )
            .unwrap());
        // Name at/over the MAX_NAME-1 limit.
        let bigname = format!("{}=v", "n".repeat(MAX_NAME - 1));
        assert!(!jar
            .add(
                &bigname,
                true,
                false,
                Some("example.com"),
                Some("/"),
                false,
                NOW
            )
            .unwrap());
        assert_eq!(jar.num_cookies(), 0);
    }

    #[test]
    fn malformed_pairs_are_rejected() {
        let mut jar = CookieJar::new();
        // No '=' separator.
        assert!(!jar
            .add(
                "justname",
                true,
                false,
                Some("example.com"),
                Some("/"),
                false,
                NOW
            )
            .unwrap());
        // Empty name.
        assert!(!jar
            .add(
                "=value",
                true,
                false,
                Some("example.com"),
                Some("/"),
                false,
                NOW
            )
            .unwrap());
        assert_eq!(jar.num_cookies(), 0);
    }

    // ---- prefixes ---------------------------------------------------------

    #[cfg_attr(miri, ignore)]
    #[test]
    fn secure_prefix_requires_secure_flag() {
        let mut jar = CookieJar::new();
        jar.set_running(true);
        assert!(jar
            .add(
                "__Secure-x=1; Secure",
                true,
                false,
                Some("example.com"),
                Some("/"),
                true,
                NOW
            )
            .unwrap());
        // Missing Secure -> dropped.
        assert!(!jar
            .add(
                "__Secure-y=1",
                true,
                false,
                Some("example.com"),
                Some("/"),
                true,
                NOW
            )
            .unwrap());
        assert_eq!(jar.num_cookies(), 1);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn host_prefix_requires_secure_root_path_no_domain() {
        let mut jar = CookieJar::new();
        jar.set_running(true);
        // Valid __Host- cookie.
        assert!(jar
            .add(
                "__Host-ok=1; Secure; Path=/",
                true,
                false,
                Some("example.com"),
                Some("/"),
                true,
                NOW
            )
            .unwrap());
        // Has a Domain -> dropped.
        assert!(!jar
            .add(
                "__Host-bad1=1; Secure; Path=/; Domain=example.com",
                true,
                false,
                Some("example.com"),
                Some("/"),
                true,
                NOW,
            )
            .unwrap());
        // Non-root path -> dropped.
        assert!(!jar
            .add(
                "__Host-bad2=1; Secure",
                true,
                false,
                Some("example.com"),
                Some("/sub/dir"),
                true,
                NOW,
            )
            .unwrap());
        assert_eq!(jar.num_cookies(), 1);
    }

    // ---- matching order & limits -----------------------------------------

    #[cfg_attr(miri, ignore)]
    #[test]
    fn longest_path_is_sent_first() {
        let mut jar = CookieJar::new();
        jar.add(
            "a=1; Path=/",
            true,
            false,
            Some("example.com"),
            Some("/"),
            false,
            NOW,
        )
        .unwrap();
        jar.add(
            "a=2; Path=/foo",
            true,
            false,
            Some("example.com"),
            Some("/"),
            false,
            NOW,
        )
        .unwrap();
        // Both have the name "a" but distinct paths, so both are kept and the
        // longer path is emitted first.
        assert_eq!(jar.num_cookies(), 2);
        assert_eq!(jar.match_for("example.com", "/foo", false, NOW), "a=2; a=1");
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn send_amount_is_capped() {
        let mut jar = CookieJar::new();
        for i in 0..(MAX_COOKIE_SEND_AMOUNT + 10) {
            let line = format!("c{i}=v");
            jar.add(
                &line,
                true,
                false,
                Some("example.com"),
                Some("/"),
                false,
                NOW,
            )
            .unwrap();
        }
        let list = jar.get_list("example.com", "/", false, NOW);
        assert_eq!(list.len(), MAX_COOKIE_SEND_AMOUNT);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn header_length_is_capped() {
        let mut jar = CookieJar::new();
        let big = "v".repeat(4000);
        for i in 0..3 {
            let line = format!("c{i}={big}");
            jar.add(
                &line,
                true,
                false,
                Some("example.com"),
                Some("/"),
                false,
                NOW,
            )
            .unwrap();
        }
        // All three match, but only two fit under MAX_COOKIE_HEADER_LEN.
        assert_eq!(jar.get_list("example.com", "/", false, NOW).len(), 3);
        let header = jar.match_for("example.com", "/", false, NOW);
        assert_eq!(header.matches('=').count(), 2);
    }

    // ---- replacement ------------------------------------------------------

    #[cfg_attr(miri, ignore)]
    #[test]
    fn identical_cookie_replaces_in_place() {
        let mut jar = CookieJar::new();
        jar.add(
            "a=1; Path=/",
            true,
            false,
            Some("example.com"),
            Some("/"),
            false,
            NOW,
        )
        .unwrap();
        jar.add(
            "a=2; Path=/",
            true,
            false,
            Some("example.com"),
            Some("/"),
            false,
            NOW,
        )
        .unwrap();
        assert_eq!(jar.num_cookies(), 1);
        assert_eq!(jar.match_for("example.com", "/", false, NOW), "a=2");
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn live_cookie_not_overwritten_by_file_cookie() {
        let mut jar = CookieJar::new();
        // A live (header) cookie.
        jar.set_running(true);
        jar.add(
            "a=live",
            true,
            false,
            Some("example.com"),
            Some("/"),
            false,
            NOW,
        )
        .unwrap();
        // A non-live (file-loaded) cookie with the same identity is rejected.
        jar.set_running(false);
        assert!(!jar
            .add(
                "a=file",
                true,
                false,
                Some("example.com"),
                Some("/"),
                false,
                NOW
            )
            .unwrap());
        jar.set_running(true);
        assert_eq!(jar.match_for("example.com", "/", false, NOW), "a=live");
    }

    // ---- public suffix ----------------------------------------------------

    #[cfg_attr(miri, ignore)]
    #[test]
    fn public_suffix_tld_is_rejected_in_all_builds() {
        let mut jar = CookieJar::new();
        // Domain=com is a public suffix (PSL build) and a dot-less "bad domain"
        // (non-PSL build): rejected either way.
        assert!(!jar
            .add(
                "foo=bar; Domain=com",
                true,
                false,
                Some("example.com"),
                Some("/"),
                false,
                NOW,
            )
            .unwrap());
        assert_eq!(jar.num_cookies(), 0);
    }

    #[cfg(feature = "psl")]
    #[cfg_attr(miri, ignore)]
    #[test]
    fn multi_label_public_suffix_is_rejected_with_psl() {
        let mut jar = CookieJar::new();
        // co.uk is only known to be a public suffix via the real PSL.
        assert!(!jar
            .add(
                "foo=bar; Domain=co.uk",
                true,
                false,
                Some("example.co.uk"),
                Some("/"),
                false,
                NOW,
            )
            .unwrap());
        // example.co.uk is registrable -> accepted.
        assert!(jar
            .add(
                "foo=bar; Domain=example.co.uk",
                true,
                false,
                Some("www.example.co.uk"),
                Some("/"),
                false,
                NOW,
            )
            .unwrap());
    }

    // ---- Netscape format --------------------------------------------------

    #[test]
    fn netscape_line_formatting() {
        let co = Cookie {
            name: "foo".into(),
            value: "bar".into(),
            path: Some("/".into()),
            domain: Some("example.com".into()),
            expires: 0,
            creationtime: 1,
            tailmatch: true,
            secure: false,
            livecookie: false,
            httponly: false,
            prefix_secure: false,
            prefix_host: false,
        };
        assert_eq!(
            co.to_netscape_line(),
            ".example.com\tTRUE\t/\tFALSE\t0\tfoo\tbar"
        );

        let httponly = Cookie {
            httponly: true,
            tailmatch: false,
            ..co.clone()
        };
        assert_eq!(
            httponly.to_netscape_line(),
            "#HttpOnly_example.com\tFALSE\t/\tFALSE\t0\tfoo\tbar"
        );
    }

    #[test]
    fn netscape_parse_roundtrip() {
        let line = ".example.com\tTRUE\t/\tFALSE\t0\tfoo\tbar";
        let co = parse_netscape(line, true, false).expect("parse");
        assert_eq!(co.domain.as_deref(), Some("example.com")); // dot stripped
        assert!(co.tailmatch);
        assert_eq!(co.path.as_deref(), Some("/"));
        assert!(!co.secure);
        assert_eq!(co.expires, 0);
        assert_eq!(co.name, "foo");
        assert_eq!(co.value, "bar");
        assert_eq!(co.to_netscape_line(), line);
    }

    #[test]
    fn netscape_httponly_prefix_parsed() {
        let line = "#HttpOnly_example.com\tFALSE\t/\tFALSE\t0\tfoo\tbar";
        let co = parse_netscape(line, true, false).expect("parse");
        assert!(co.httponly);
        assert!(!co.tailmatch);
        assert_eq!(co.domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn netscape_comment_is_skipped() {
        assert!(parse_netscape("# a comment", true, false).is_none());
        // Too few fields.
        assert!(parse_netscape("example.com\tTRUE", true, false).is_none());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn write_to_string_has_banner_and_newest_first() {
        let mut jar = CookieJar::new();
        jar.add("a=1", true, false, Some("aaa.com"), Some("/"), false, NOW)
            .unwrap();
        jar.add("b=2", true, false, Some("bbb.com"), Some("/"), false, NOW)
            .unwrap();
        let dump = jar.write_to_string(NOW);
        assert!(dump.starts_with("# Netscape HTTP Cookie File\n"));
        assert!(dump.contains("# https://curl.se/docs/http-cookies.html\n"));
        // Newest cookie (b, created last) is dumped before the older one (a).
        let pos_b = dump.find("\tb\t2").expect("b present");
        let pos_a = dump.find("\ta\t1").expect("a present");
        assert!(pos_b < pos_a);
    }

    #[test]
    fn load_file_then_dump_orders_newest_first() {
        use std::io::Write as _;
        let dir = std::env::temp_dir();
        let path = dir.join(format!("blitzy_adhoc_cookie_{}.txt", std::process::id()));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            // Three cookies; loaded top-to-bottom so the last gets the newest ct.
            writeln!(f, "# Netscape HTTP Cookie File").unwrap();
            writeln!(f, "aaa.com\tFALSE\t/\tFALSE\t0\tone\t1").unwrap();
            writeln!(f, "bbb.com\tFALSE\t/\tFALSE\t0\ttwo\t2").unwrap();
            writeln!(f, "ccc.com\tFALSE\t/\tFALSE\t0\tthree\t3").unwrap();
        }
        let jar = CookieJar::init_from_file(path.to_str().unwrap(), false, NOW).unwrap();
        assert_eq!(jar.num_cookies(), 3);
        assert!(jar.is_running());

        let mut jar2 = jar;
        let dump = jar2.write_to_string(NOW);
        let p_one = dump.find("\tone\t1").unwrap();
        let p_two = dump.find("\ttwo\t2").unwrap();
        let p_three = dump.find("\tthree\t3").unwrap();
        // Reverse of file order (newest creation time first).
        assert!(p_three < p_two && p_two < p_one);

        let _ = std::fs::remove_file(&path);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn save_writes_atomically_and_reloads() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "blitzy_adhoc_cookie_save_{}.txt",
            std::process::id()
        ));

        let mut jar = CookieJar::new();
        jar.set_running(true);
        jar.add(
            "foo=bar; Domain=example.com",
            true,
            false,
            Some("www.example.com"),
            Some("/"),
            false,
            NOW,
        )
        .unwrap();
        jar.save(path.to_str().unwrap(), NOW).unwrap();

        let reloaded = CookieJar::init_from_file(path.to_str().unwrap(), false, NOW).unwrap();
        assert_eq!(reloaded.num_cookies(), 1);
        let mut reloaded = reloaded;
        assert_eq!(
            reloaded.match_for("www.example.com", "/", false, NOW),
            "foo=bar"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn export_list_emits_lines_with_domain() {
        let mut jar = CookieJar::new();
        jar.add(
            "foo=bar; Domain=example.com",
            true,
            false,
            Some("www.example.com"),
            Some("/"),
            false,
            NOW,
        )
        .unwrap();
        let lines = jar.export_list(NOW);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("\tfoo\tbar"));
        assert!(lines[0].starts_with(".example.com\t"));
    }

    // ---- CURLOPT_COOKIELIST verbs ----------------------------------------

    #[cfg_attr(miri, ignore)]
    #[test]
    fn cookie_list_command_verbs() {
        let mut jar = CookieJar::new();
        jar.add(
            "foo=bar; Max-Age=3600",
            true,
            false,
            Some("example.com"),
            Some("/"),
            false,
            NOW,
        )
        .unwrap();
        jar.add(
            "sess=1",
            true,
            false,
            Some("example.com"),
            Some("/"),
            false,
            NOW,
        )
        .unwrap();
        assert_eq!(jar.num_cookies(), 2);

        assert_eq!(
            jar.cookie_list_command("SESS", NOW).unwrap(),
            CookieListAction::ClearedSession
        );
        assert_eq!(jar.num_cookies(), 1); // only the session cookie removed

        assert_eq!(
            jar.cookie_list_command("FLUSH", NOW).unwrap(),
            CookieListAction::Flush
        );
        assert_eq!(
            jar.cookie_list_command("RELOAD", NOW).unwrap(),
            CookieListAction::Reload
        );

        assert_eq!(
            jar.cookie_list_command("ALL", NOW).unwrap(),
            CookieListAction::ClearedAll
        );
        assert_eq!(jar.num_cookies(), 0);
    }

    #[test]
    fn cookie_list_command_adds_lines() {
        let mut jar = CookieJar::new();
        // Header-format line.
        assert_eq!(
            jar.cookie_list_command("Set-Cookie: x=1; domain=example.com", NOW)
                .unwrap(),
            CookieListAction::Added(true)
        );
        // Netscape-format line.
        assert_eq!(
            jar.cookie_list_command("ample.org\tFALSE\t/\tFALSE\t0\ty\t2", NOW)
                .unwrap(),
            CookieListAction::Added(true)
        );
        assert_eq!(jar.num_cookies(), 2);
    }

    #[test]
    fn cookie_list_command_rejects_overlong_input() {
        let mut jar = CookieJar::new();
        let huge = "x".repeat(CURL_MAX_INPUT_LENGTH + 1);
        assert!(matches!(
            jar.cookie_list_command(&huge, NOW),
            Err(CurlError::BadFunctionArgument)
        ));
    }

    // ---- secure context & URL helpers ------------------------------------

    #[test]
    fn secure_context_rules() {
        assert!(CookieJar::secure_context("https", "example.com"));
        assert!(CookieJar::secure_context("HTTPS", "example.com"));
        assert!(CookieJar::secure_context("wss", "example.com"));
        assert!(!CookieJar::secure_context("http", "example.com"));
        assert!(CookieJar::secure_context("http", "localhost"));
        assert!(CookieJar::secure_context("http", "127.0.0.1"));
        assert!(CookieJar::secure_context("ws", "::1"));
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn url_convenience_store_and_match() {
        use crate::url::{CurlUPart, CurlUrl};
        let mut url = CurlUrl::new();
        url.set(CurlUPart::Url, Some("https://www.example.com/path"), 0)
            .unwrap();

        let mut jar = CookieJar::new();
        jar.set_running(true);
        assert!(jar.store_response_url("foo=bar", &url, NOW).unwrap());
        assert_eq!(jar.match_for_url(&url, NOW).unwrap(), "foo=bar");
    }
}
