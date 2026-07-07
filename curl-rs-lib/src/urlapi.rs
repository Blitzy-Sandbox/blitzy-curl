// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! RFC 3986 URL parser and the standalone `CURLU` URL API — a memory-safe Rust
//! rewrite of curl's `lib/urlapi.c`.
//!
//! This module implements curl's public URL API: the [`Url`] handle (curl's
//! `CURLU`) together with the operations that back the six `curl_url_*` FFI
//! symbols:
//!
//! | curl C function     | this module            |
//! |---------------------|------------------------|
//! | `curl_url()`        | [`Url::new`]           |
//! | `curl_url_cleanup()`| [`Drop`] (automatic)   |
//! | `curl_url_dup()`    | [`Url::dup`] / [`Clone`] |
//! | `curl_url_get()`    | [`Url::get`]           |
//! | `curl_url_set()`    | [`Url::set`]           |
//! | `curl_url_strerror()` | [`CurlUCode::message`] (from [`crate::error`]) |
//!
//! [`Url::parse`] is a convenience that mirrors `curl_url()` immediately
//! followed by `curl_url_set(CURLUPART_URL, ...)`.
//!
//! # Parity philosophy
//!
//! This is a *faithful port* of curl's parser, not a generic RFC 3986 or WHATWG
//! parser. curl's URL API has a large number of curl-specific behaviors that
//! downstream code (and the curl test corpus, notably `tests/libtest/lib1560.c`)
//! depends on:
//!
//! * curl-style scheme guessing from the hostname (`ftp.` ⇒ `ftp`, `www.` ⇒
//!   `http`, …) driven by [`GUESS_SCHEME`].
//! * the `CURLU_*` flag matrix ([`DEFAULT_PORT`], [`URLENCODE`], [`PATH_AS_IS`],
//!   …).
//! * partial-URL handling and relative-URL resolution for `Location:` redirects
//!   (curl's `redirect_url`).
//! * IPv6 zone-id parsing, curl's specific host-character reject set, and curl's
//!   numeric-IPv4 normalization.
//! * the frozen [`CurlUCode`] integer error space.
//!
//! Because the WHATWG URL Standard (as implemented by the `url` crate)
//! deliberately diverges from curl on several of these points — the curl test
//! suite even documents cases where "WHATWG disagrees" — this module implements
//! curl's behavior directly rather than delegating parsing to `url`. It uses
//! [`crate::escape`] for percent-encoding/decoding and [`crate::idn`] for host
//! IDN/Punycode conversion, and [`std::net`] for IP-literal normalization (the
//! equivalent of curl's `inet_pton`/`inet_ntop`).
//!
//! # Dropped schemes
//!
//! The RTMP family (`rtmp`, `rtmpt`, `rtmpe`, `rtmpte`, `rtmps`, `rtmpts`) is
//! **not** part of the supported scheme set: there is no pure-Rust `librtmp`
//! equivalent, so those protocols were removed from the workspace (AAP §0.2.2 /
//! §1.3.2.5). Consequently they are rejected by the supported-scheme gate
//! exactly as any other unknown scheme is (i.e. accepted only with
//! [`NON_SUPPORT_SCHEME`]).
//!
//! # Memory-safety guarantee
//!
//! This module is written entirely in safe Rust. It performs no raw-pointer or
//! FFI work — curl's manual `malloc`/`free`/`strdup` bookkeeping is replaced by
//! owned [`String`] values inside [`Url`], so `curl_url_cleanup` becomes an
//! automatic [`Drop`] and `curl_url_dup` becomes a derived [`Clone`]. The
//! keyword that opts out of the compiler's safety checks is intentionally
//! absent from this file so that the crate-wide `grep` audit of
//! `curl-rs-lib/src/` stays green.

use crate::error::CurlUCode;
use crate::{escape, idn};

use std::net::Ipv6Addr;

/// Re-export of the frozen URL-API error code enum.
///
/// The integer values are a frozen ABI transcribed from
/// `include/curl/urlapi.h`; they live in [`crate::error`] so the FFI layer and
/// the rest of the library share a single definition.
pub use crate::error::CurlUCode as UrlCode;

/// The result type used throughout the URL API: `Result<T, CurlUCode>`.
///
/// This mirrors curl's `CURLUcode` return convention directly — every URL-API
/// entry point yields either a value or one of the frozen [`CurlUCode`] error
/// codes.
pub type UResult<T> = core::result::Result<T, CurlUCode>;

// ===========================================================================
// CURLU_* flags — transcribed verbatim from include/curl/urlapi.h.
// ===========================================================================
//
// These are the bit flags accepted by [`Url::get`], [`Url::set`], and
// [`Url::parse`]. The numeric values are part of the frozen public ABI and MUST
// match the `#define CURLU_*` values in `include/curl/urlapi.h` exactly.

/// `CURLU_DEFAULT_PORT` — return the default port number for the scheme when no
/// port is stored (on get).
pub const DEFAULT_PORT: u32 = 1 << 0;
/// `CURLU_NO_DEFAULT_PORT` — on get, act as if no port was set when the stored
/// port matches the scheme's default.
pub const NO_DEFAULT_PORT: u32 = 1 << 1;
/// `CURLU_DEFAULT_SCHEME` — treat a scheme-less URL as using the default scheme
/// (`https`) instead of failing.
pub const DEFAULT_SCHEME: u32 = 1 << 2;
/// `CURLU_NON_SUPPORT_SCHEME` — accept a scheme that curl does not have a
/// built-in handler for.
pub const NON_SUPPORT_SCHEME: u32 = 1 << 3;
/// `CURLU_PATH_AS_IS` — do not apply RFC 3986 dot-segment removal to the path.
pub const PATH_AS_IS: u32 = 1 << 4;
/// `CURLU_DISALLOW_USER` — reject a URL that carries user/password credentials.
pub const DISALLOW_USER: u32 = 1 << 5;
/// `CURLU_URLDECODE` — URL-decode the component on get.
pub const URLDECODE: u32 = 1 << 6;
/// `CURLU_URLENCODE` — URL-encode the component on set (and on some gets).
pub const URLENCODE: u32 = 1 << 7;
/// `CURLU_APPENDQUERY` — append (rather than replace) when setting the query.
pub const APPENDQUERY: u32 = 1 << 8;
/// `CURLU_GUESS_SCHEME` — enable curl's legacy hostname-based scheme guessing.
pub const GUESS_SCHEME: u32 = 1 << 9;
/// `CURLU_NO_AUTHORITY` — allow an empty authority when the scheme is unknown.
pub const NO_AUTHORITY: u32 = 1 << 10;
/// `CURLU_ALLOW_SPACE` — allow (unencoded) space characters in the URL.
pub const ALLOW_SPACE: u32 = 1 << 11;
/// `CURLU_PUNYCODE` — return the hostname in its ACE/Punycode form on get.
pub const PUNYCODE: u32 = 1 << 12;
/// `CURLU_PUNY2IDN` — convert a Punycode hostname back to its IDN/Unicode form
/// on get.
pub const PUNY2IDN: u32 = 1 << 13;
/// `CURLU_GET_EMPTY` — return empty query/fragment components (and emit them in
/// the full URL) instead of omitting them.
pub const GET_EMPTY: u32 = 1 << 14;
/// `CURLU_NO_GUESS_SCHEME` — on get, do not return a scheme that was guessed.
pub const NO_GUESS_SCHEME: u32 = 1 << 15;

/// The default scheme used when a scheme-less URL is parsed with
/// [`DEFAULT_SCHEME`] (curl's `DEFAULT_SCHEME` macro).
const DEFAULT_SCHEME_NAME: &str = "https";

/// The longest scheme name curl accepts, from `MAX_SCHEME_LEN` in
/// `lib/urlapi.c`. Schemes longer than this are rejected by [`Url::set`] with
/// [`CurlUCode::BadScheme`].
const MAX_SCHEME_LEN: usize = 40;

/// The maximum accepted input length, from `CURL_MAX_INPUT_LENGTH` in
/// `lib/urldata.h`. Inputs longer than this are rejected with
/// [`CurlUCode::MalformedInput`] (for URLs) or [`CurlUCode::MalformedInput`]
/// (for oversized `set` values).
const CURL_MAX_INPUT_LENGTH: usize = 8_000_000;

// ===========================================================================
// CURLUPart — transcribed verbatim from include/curl/urlapi.h.
// ===========================================================================

/// The individual URL components addressable by [`Url::get`] and [`Url::set`].
///
/// The discriminant values match the `CURLUPart` enum in
/// `include/curl/urlapi.h` exactly (`CURLUPART_URL == 0`, …,
/// `CURLUPART_ZONEID == 10`) so the FFI layer can transmute the C integer
/// directly.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurlUPart {
    /// The complete URL (`CURLUPART_URL`).
    Url = 0,
    /// The scheme, e.g. `https` (`CURLUPART_SCHEME`).
    Scheme = 1,
    /// The user name (`CURLUPART_USER`).
    User = 2,
    /// The password (`CURLUPART_PASSWORD`).
    Password = 3,
    /// The options field (IMAP/POP3/SMTP only) (`CURLUPART_OPTIONS`).
    Options = 4,
    /// The host name or IP literal (`CURLUPART_HOST`).
    Host = 5,
    /// The port number (`CURLUPART_PORT`).
    Port = 6,
    /// The path (`CURLUPART_PATH`).
    Path = 7,
    /// The query string, without the leading `?` (`CURLUPART_QUERY`).
    Query = 8,
    /// The fragment, without the leading `#` (`CURLUPART_FRAGMENT`).
    Fragment = 9,
    /// The IPv6 zone id (`CURLUPART_ZONEID`, added in curl 7.65.0).
    ZoneId = 10,
}

// ===========================================================================
// Scheme table.
// ===========================================================================

/// A single row of curl's built-in scheme table.
///
/// This is the subset of `struct Curl_scheme` (`lib/urldata.h`) that the URL
/// API actually consults: the lowercase scheme name, its default port, and
/// whether the scheme permits an `;options` field in the userinfo portion of
/// the authority (curl's `PROTOPT_URLOPTIONS`).
#[derive(Debug, Clone, Copy)]
struct SchemeInfo {
    /// The scheme name in lowercase (as compared case-insensitively).
    name: &'static str,
    /// The default TCP/UDP port for the scheme (curl's `defport`).
    defport: u16,
    /// Whether the scheme allows an `;options` field in the userinfo
    /// (`PROTOPT_URLOPTIONS`). True only for IMAP/POP3/SMTP and their TLS
    /// variants.
    url_options: bool,
}

/// curl's built-in scheme table, with the RTMP family deliberately omitted.
///
/// Default ports come from the `PORT_*` macros in `lib/urldata.h`; the
/// `url_options` column reflects which schemes carry `PROTOPT_URLOPTIONS` in
/// their `Curl_scheme_*` definition. The RTMP schemes (`rtmp`, `rtmpt`,
/// `rtmpe`, `rtmpte`, `rtmps`, `rtmpts`) present in curl 8.x are **not** listed
/// here because the protocol was dropped from this rewrite (AAP §0.2.2); they
/// are therefore treated as unsupported schemes.
const SCHEMES: &[SchemeInfo] = &[
    SchemeInfo {
        name: "http",
        defport: 80,
        url_options: false,
    },
    SchemeInfo {
        name: "https",
        defport: 443,
        url_options: false,
    },
    SchemeInfo {
        name: "ftp",
        defport: 21,
        url_options: false,
    },
    SchemeInfo {
        name: "ftps",
        defport: 990,
        url_options: false,
    },
    SchemeInfo {
        name: "sftp",
        defport: 22,
        url_options: false,
    },
    SchemeInfo {
        name: "scp",
        defport: 22,
        url_options: false,
    },
    SchemeInfo {
        name: "telnet",
        defport: 23,
        url_options: false,
    },
    SchemeInfo {
        name: "dict",
        defport: 2628,
        url_options: false,
    },
    SchemeInfo {
        name: "ldap",
        defport: 389,
        url_options: false,
    },
    SchemeInfo {
        name: "ldaps",
        defport: 636,
        url_options: false,
    },
    SchemeInfo {
        name: "imap",
        defport: 143,
        url_options: true,
    },
    SchemeInfo {
        name: "imaps",
        defport: 993,
        url_options: true,
    },
    SchemeInfo {
        name: "pop3",
        defport: 110,
        url_options: true,
    },
    SchemeInfo {
        name: "pop3s",
        defport: 995,
        url_options: true,
    },
    SchemeInfo {
        name: "smtp",
        defport: 25,
        url_options: true,
    },
    SchemeInfo {
        name: "smtps",
        defport: 465,
        url_options: true,
    },
    SchemeInfo {
        name: "smb",
        defport: 445,
        url_options: false,
    },
    SchemeInfo {
        name: "smbs",
        defport: 445,
        url_options: false,
    },
    SchemeInfo {
        name: "rtsp",
        defport: 554,
        url_options: false,
    },
    SchemeInfo {
        name: "gopher",
        defport: 70,
        url_options: false,
    },
    SchemeInfo {
        name: "gophers",
        defport: 70,
        url_options: false,
    },
    SchemeInfo {
        name: "tftp",
        defport: 69,
        url_options: false,
    },
    SchemeInfo {
        name: "mqtt",
        defport: 1883,
        url_options: false,
    },
    SchemeInfo {
        name: "mqtts",
        defport: 8883,
        url_options: false,
    },
    SchemeInfo {
        name: "ws",
        defport: 80,
        url_options: false,
    },
    SchemeInfo {
        name: "wss",
        defport: 443,
        url_options: false,
    },
];

/// Looks up a scheme by name, case-insensitively.
///
/// This reproduces the behavior of curl's `Curl_getn_scheme`: the comparison is
/// case-insensitive (curl lowercases via `Curl_raw_tolower` and compares with
/// `curl_strnequal`), and only names of length `1..=7` can match (curl's table
/// is gated on `len && (len <= 7)`). Every curl scheme name fits in 7 bytes, so
/// the length cap never rejects a legitimate scheme; it simply lets us bail out
/// quickly for over-long candidates. Returns [`None`] for unknown schemes,
/// including the deliberately dropped RTMP family.
fn get_scheme(scheme: &str) -> Option<&'static SchemeInfo> {
    let len = scheme.len();
    if len == 0 || len > 7 {
        return None;
    }
    SCHEMES.iter().find(|s| s.name.eq_ignore_ascii_case(scheme))
}

// ===========================================================================
// Low-level byte helpers.
//
// curl's parser works over NUL-terminated C strings with pointer arithmetic.
// These helpers let the Rust port work over byte slices while preserving the
// exact byte-level behavior, including curl's reliance on a terminating NUL
// (modeled here by treating out-of-range indices as the byte 0).
// ===========================================================================

/// Returns the byte at `i`, or `0` if `i` is out of range.
///
/// This models C's NUL-terminated-string convention: reading at or past the end
/// of a curl string yields the terminating `\0`. Porting curl's `p[i]`-style
/// lookahead with this helper keeps the control flow identical without risking a
/// Rust panic on an out-of-range index.
#[inline]
fn at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

/// The uppercase hexadecimal digits curl uses for percent-encoding
/// (`Curl_udigits`).
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Appends `%XX` (uppercase hex) for `b`, mirroring curl's `Curl_hexbyte`.
#[inline]
fn push_hex_upper(out: &mut Vec<u8>, b: u8) {
    out.push(b'%');
    out.push(HEX_UPPER[(b >> 4) as usize]);
    out.push(HEX_UPPER[(b & 0x0f) as usize]);
}

/// Reports whether `b` is an RFC 3986 *unreserved* byte, mirroring curl's
/// `ISUNRESERVED` macro (`ISALNUM(x) || ISURLPUNTCS(x)` from
/// `lib/curl_ctype.h`).
#[inline]
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// Finds the separator at the end of the hostname, mirroring curl's
/// `find_host_sep`.
///
/// It locates the `//` that introduces the authority (if any), then scans
/// forward to the first `/` or `?`. The returned value is the byte offset of
/// that separator (or the end of the slice). When there is no `//`, scanning
/// begins at the start of the slice, exactly as curl's `sep = url` fallback.
fn find_host_sep(url: &[u8]) -> usize {
    let mut i = url
        .windows(2)
        .position(|w| w == b"//")
        .map_or(0, |pos| pos + 2);
    while i < url.len() && url[i] != b'/' && url[i] != b'?' {
        i += 1;
    }
    i
}

/// Scans the URL for illegal control bytes and returns its length.
///
/// This is curl's `Curl_junkscan`: it rejects any byte `<= 0x1f` when spaces are
/// allowed, or `<= 0x20` (thus also rejecting the space itself) otherwise, and
/// always rejects `0x7f` (DEL). Inputs longer than [`CURL_MAX_INPUT_LENGTH`] are
/// rejected outright.
///
/// # Errors
///
/// Returns [`CurlUCode::MalformedInput`] if the input is too long or contains a
/// forbidden control byte.
fn junkscan(url: &[u8], allowspace: bool) -> UResult<usize> {
    let n = url.len();
    if n > CURL_MAX_INPUT_LENGTH {
        return Err(CurlUCode::MalformedInput);
    }
    let control: u8 = if allowspace { 0x1f } else { 0x20 };
    for &b in url {
        if b <= control || b == 127 {
            return Err(CurlUCode::MalformedInput);
        }
    }
    Ok(n)
}

/// Determines whether `url` begins with a scheme, mirroring curl's
/// `Curl_is_absolute_url`.
///
/// A URL is "absolute" when it starts with `ALPHA *( ALPHA / DIGIT / "+" / "-" /
/// "." )` followed by `:` — and, in `guess_scheme` mode, the `:` must be
/// followed by `/` (so that a scheme-less `data:1234`-style host:port is not
/// mistaken for a scheme). On success it returns the scheme length together with
/// the lowercased scheme name (curl writes the lowercased scheme into the
/// caller's buffer); on failure it returns [`None`].
fn is_absolute_url(url: &[u8], guess_scheme: bool) -> Option<(usize, String)> {
    let mut i = 0usize;
    if at(url, 0).is_ascii_alphabetic() {
        i = 1;
        while i < MAX_SCHEME_LEN {
            let s = at(url, i);
            if s != 0 && (s.is_ascii_alphanumeric() || s == b'+' || s == b'-' || s == b'.') {
                i += 1;
            } else {
                break;
            }
        }
    }
    if i != 0 && at(url, i) == b':' && (at(url, i + 1) == b'/' || !guess_scheme) {
        // Scheme bytes are all ASCII (verified above), so lowercasing and the
        // `char` conversion are lossless.
        let scheme: String = url[..i]
            .iter()
            .map(|b| b.to_ascii_lowercase() as char)
            .collect();
        return Some((i, scheme));
    }
    None
}

/// URL-encodes the space characters (and control/high bytes) of a URL fragment,
/// mirroring curl's `urlencode_str`.
///
/// This is *not* a general percent-encoder: it only rewrites bytes that must be
/// escaped for the URL to remain well-formed while leaving reserved characters
/// untouched, exactly as curl does when assembling a URL. A literal space
/// becomes `%20` in the "left" part (before any `?`) and `+` once inside the
/// query portion; bytes below `0x20` or at/above `0x7f` become `%XX`
/// (uppercase). When `relative` is `false`, the portion up to the host separator
/// (see [`find_host_sep`]) is copied verbatim so that host bytes are not
/// space-encoded (which would break IDN resolution).
///
/// The C function can only fail on allocation error; because Rust's `Vec`
/// aborts on allocation failure rather than returning, this port is infallible.
fn urlencode_str(out: &mut Vec<u8>, url: &[u8], relative: bool, query: bool) {
    // `left` tracks whether we are still before the query delimiter: spaces are
    // `%20` on the left and `+` inside the query.
    let mut left = !query;
    let mut start = 0usize;

    if !relative {
        let sep = find_host_sep(url);
        out.extend_from_slice(&url[..sep]);
        start = sep;
    }

    for &c in &url[start..] {
        if c == b' ' {
            if left {
                out.extend_from_slice(b"%20");
            } else {
                out.push(b'+');
            }
        } else if !(b' '..0x7f).contains(&c) {
            push_hex_upper(out, c);
        } else {
            out.push(c);
            if c == b'?' {
                left = false;
            }
        }
    }
}

// ===========================================================================
// Url — the CURLU handle.
// ===========================================================================

/// A parsed URL handle — the Rust equivalent of curl's opaque `CURLU`.
///
/// Every component is stored as an owned, already-percent-encoded [`String`]
/// (mirroring curl's `struct Curl_URL`, whose members "point to URL-encoded
/// strings"). A [`None`] component is curl's `NULL` pointer; a `Some("")` is an
/// explicitly empty component. Ownership means `curl_url_cleanup` is handled by
/// [`Drop`] and `curl_url_dup` by a derived [`Clone`] — there is no manual
/// memory management.
///
/// Construct an empty handle with [`Url::new`], parse a URL with [`Url::parse`],
/// and read/modify components with [`Url::get`] / [`Url::set`].
#[derive(Debug, Clone, Default)]
pub struct Url {
    /// The scheme, lowercased, without the trailing `:` (curl `u->scheme`).
    scheme: Option<String>,
    /// The user name (curl `u->user`).
    user: Option<String>,
    /// The password (curl `u->password`).
    password: Option<String>,
    /// The options field, IMAP/POP3/SMTP only (curl `u->options`).
    options: Option<String>,
    /// The host, percent-encoded; IPv6 literals keep their `[` `]` brackets
    /// (curl `u->host`).
    host: Option<String>,
    /// The IPv6 zone id, stored separately from the bracketed host
    /// (curl `u->zoneid`).
    zoneid: Option<String>,
    /// The port as a decimal string with leading zeroes stripped
    /// (curl `u->port`).
    port: Option<String>,
    /// The path, always beginning with `/` when present (curl `u->path`).
    path: Option<String>,
    /// The query, without the leading `?` (curl `u->query`).
    query: Option<String>,
    /// The fragment, without the leading `#` (curl `u->fragment`).
    fragment: Option<String>,
    /// The numeric port, valid only when [`port`](Self::port) is `Some`
    /// (curl `u->portnum`).
    portnum: u16,
    /// Whether a query delimiter (`?`) was present, so a blank query can be
    /// distinguished from a missing one (curl `u->query_present`).
    query_present: bool,
    /// Whether a fragment delimiter (`#`) was present (curl
    /// `u->fragment_present`).
    fragment_present: bool,
    /// Whether the scheme was guessed rather than given (curl
    /// `u->guessed_scheme`).
    guessed_scheme: bool,
}

impl Url {
    /// Creates a new, empty URL handle — the equivalent of curl's `curl_url()`.
    ///
    /// All components start unset. Populate the handle with [`Url::set`] using
    /// [`CurlUPart::Url`] (or use the [`Url::parse`] convenience).
    #[must_use]
    pub fn new() -> Url {
        Url::default()
    }
}

/// Converts owned bytes to an owned [`String`].
///
/// On the parse path the input is always a UTF-8 [`str`] split on ASCII
/// delimiters, so the bytes are guaranteed to be valid UTF-8 and this is
/// lossless. The [`String::from_utf8_lossy`] fallback exists only so the
/// function is total; it is unreachable for parser-produced byte runs and is
/// never used to smuggle invalid UTF-8 into a component (host decoding, which
/// can produce arbitrary bytes, is validated separately and rejected with
/// [`CurlUCode::BadHostname`]).
fn vec_to_string(v: Vec<u8>) -> String {
    match String::from_utf8(v) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}

/// Parses a bare decimal number that must consume the entire slice.
///
/// This combines curl's `curlx_str_number(&p, &n, max)` with the subsequent
/// `|| *p` "fully consumed" check used for port parsing: it requires at least
/// one digit, accepts leading zeroes, forbids a sign or any trailing byte, and
/// rejects values above `max` (or that overflow). Returns [`None`] on any
/// violation.
fn parse_decimal_all(bytes: &[u8], max: u64) -> Option<u64> {
    if bytes.is_empty() || !bytes[0].is_ascii_digit() {
        return None;
    }
    let mut num: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        num = num.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
        if num > max {
            return None;
        }
    }
    Some(num)
}

/// Splits a userinfo run into user, password, and (optionally) options.
///
/// This is a faithful port of curl's `Curl_parse_login_details`. It accepts the
/// forms `user`, `user:password`, `user:password;options`, `user;options`,
/// `:password`, `;options`, and their permutations, splitting on the first `:`
/// (password) and — when `parse_options` is set — the first `;` (options). The
/// user portion is always returned (possibly empty); the password is returned
/// only when a `:` is present; options are returned only when `parse_options`
/// is set and the options run is non-empty (matching curl, where an empty
/// options run yields a `NULL` options pointer).
fn parse_login_details(
    login: &[u8],
    parse_options: bool,
) -> (Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>) {
    let len = login.len();
    let psep = login.iter().position(|&b| b == b':');
    let osep = if parse_options {
        login.iter().position(|&b| b == b';')
    } else {
        None
    };

    // Length of the user portion (curl's `ulen`).
    let ulen = match psep {
        Some(p) => match osep {
            Some(o) if p > o => o,
            _ => p,
        },
        None => osep.unwrap_or(len),
    };

    // Length of the password portion (curl's `plen`).
    let plen = match psep {
        Some(p) => {
            let end = match osep {
                Some(o) if o > p => o,
                _ => len,
            };
            end - p - 1
        }
        None => 0,
    };

    // Length of the options portion (curl's `olen`).
    let olen = match osep {
        Some(o) => {
            let end = match psep {
                Some(p) if p > o => p,
                _ => len,
            };
            end - o - 1
        }
        None => 0,
    };

    let user = login[..ulen].to_vec();
    let password = psep.map(|p| login[p + 1..p + 1 + plen].to_vec());
    let options = match osep {
        Some(o) if olen > 0 => Some(login[o + 1..o + 1 + olen].to_vec()),
        _ => None,
    };

    (user, password, options)
}

impl Url {
    /// Extracts the `user[:password][;options]@` login prefix from an authority,
    /// mirroring curl's `parse_hostname_login`.
    ///
    /// The authority is split on the first `@`; if none is present there is no
    /// login and the hostname begins at offset `0`. Otherwise the userinfo run
    /// before the `@` is decomposed by [`parse_login_details`] (options only
    /// when the scheme carries `PROTOPT_URLOPTIONS`). When [`DISALLOW_USER`] is
    /// set and the URL carries any credentials, this fails with
    /// [`CurlUCode::UserNotAllowed`]. Returns the byte offset at which the
    /// hostname starts.
    fn parse_hostname_login(&mut self, login: &[u8], flags: u32) -> UResult<usize> {
        let at_pos = match login.iter().position(|&b| b == b'@') {
            None => return Ok(0),
            Some(p) => p,
        };

        // Options are parsed only for schemes that declare PROTOPT_URLOPTIONS.
        let options_allowed = self
            .scheme
            .as_deref()
            .and_then(get_scheme)
            .is_some_and(|h| h.url_options);

        let (user, password, options) = parse_login_details(&login[..at_pos], options_allowed);

        // curl always allocates the user (even when empty), so the presence of
        // an `@` alone means credentials are present for DISALLOW_USER purposes.
        if flags & DISALLOW_USER != 0 {
            return Err(CurlUCode::UserNotAllowed);
        }

        self.user = Some(vec_to_string(user));
        if let Some(pw) = password {
            self.password = Some(vec_to_string(pw));
        }
        if let Some(op) = options {
            self.options = Some(vec_to_string(op));
        }

        Ok(at_pos + 1)
    }

    /// Splits an optional `:port` off the end of the host buffer, mirroring
    /// curl's `Curl_parse_port`.
    ///
    /// For a bracketed IPv6 literal the port follows the closing `]`; otherwise
    /// it follows the first `:`. A colon with nothing after it is tolerated only
    /// when the URL has a scheme (Firefox/Chrome/Safari behavior: the empty port
    /// is ignored and the default is used), matching curl. A present port must
    /// be a decimal number in `0..=65535` with no trailing bytes. On success the
    /// host buffer is truncated to just the host and the numeric/string port is
    /// stored (with leading zeroes stripped).
    ///
    /// # Errors
    ///
    /// [`CurlUCode::BadIpv6`] for a bracketed host with no closing `]`;
    /// [`CurlUCode::BadPortNumber`] for a malformed or out-of-range port.
    fn parse_port(&mut self, host: &mut Vec<u8>, has_scheme: bool) -> UResult<()> {
        let colon_idx: Option<usize> = if at(host, 0) == b'[' {
            match host.iter().position(|&b| b == b']') {
                None => return Err(CurlUCode::BadIpv6),
                Some(close) => match host.get(close + 1) {
                    None => None,
                    Some(&b':') => Some(close + 1),
                    Some(_) => return Err(CurlUCode::BadPortNumber),
                },
            }
        } else {
            host.iter().position(|&b| b == b':')
        };

        if let Some(ci) = colon_idx {
            let port_bytes = host[ci + 1..].to_vec();
            host.truncate(ci);

            if port_bytes.is_empty() {
                return if has_scheme {
                    Ok(())
                } else {
                    Err(CurlUCode::BadPortNumber)
                };
            }

            let port = parse_decimal_all(&port_bytes, 0xffff).ok_or(CurlUCode::BadPortNumber)?;
            self.portnum = port as u16;
            // to_string() strips leading zeroes, matching curl's re-formatting
            // through `curl_maprintf("%ld", port)`.
            self.port = Some(port.to_string());
        }

        Ok(())
    }

    /// Validates and normalizes a bracketed IPv6 literal, mirroring curl's
    /// `ipv6_parse`.
    ///
    /// It strips the `[` `]` brackets, isolates the address text, and extracts a
    /// trailing `%zone-id` if present (skipping a URL-encoded `%25` prefix). The
    /// address is parsed and canonicalized through [`Ipv6Addr`] (the Rust
    /// equivalent of curl's `inet_pton`/`inet_ntop` round-trip). On success the
    /// host buffer is rewritten as `[canonical-address]` and the zone id (if
    /// any) is stored separately.
    ///
    /// # Errors
    ///
    /// [`CurlUCode::BadIpv6`] if the literal is too short, has trailing junk
    /// that is not a valid zone id, or is not a parseable IPv6 address.
    fn ipv6_parse(&mut self, host: &mut Vec<u8>) -> UResult<()> {
        let hlen = host.len();
        if hlen < 4 {
            // "[::]" is the shortest possible valid literal.
            return Err(CurlUCode::BadIpv6);
        }

        // Content length between the brackets (curl's `hlen -= 2`).
        let content_len = hlen - 2;

        // Count the leading run of valid IPv6 address characters, starting just
        // after the '['. Scanning stops at the first non-address byte (a '%'
        // introducing a zone id, or the closing ']').
        let is_v6 = |b: u8| b.is_ascii_hexdigit() || b == b':' || b == b'.';
        let mut len = 0usize;
        while 1 + len < host.len() && is_v6(host[1 + len]) {
            len += 1;
        }

        if content_len != len {
            // There is a trailing segment; it must be a '%zone-id'.
            if at(host, 1 + len) != b'%' {
                return Err(CurlUCode::BadIpv6);
            }
            // Zone id content begins after the '%'.
            let mut h = 1 + len + 1;
            // Skip a URL-encoded "25" (the percent sign) if it is followed by a
            // real zone-id character (not the closing ']').
            if at(host, h) == b'2'
                && at(host, h + 1) == b'5'
                && at(host, h + 2) != 0
                && at(host, h + 2) != b']'
            {
                h += 2;
            }
            let mut zone = Vec::new();
            while zone.len() < 15 {
                let c = at(host, h);
                if c == 0 || c == b']' {
                    break;
                }
                zone.push(c);
                h += 1;
            }
            if zone.is_empty() || at(host, h) != b']' {
                return Err(CurlUCode::BadIpv6);
            }
            self.zoneid = Some(vec_to_string(zone));
        }

        // Normalize the address text (host[1..1+len]) through the standard
        // library, which produces the same canonical form as inet_ntop.
        let addr = core::str::from_utf8(&host[1..1 + len]).map_err(|_| CurlUCode::BadIpv6)?;
        let ip: Ipv6Addr = addr.parse().map_err(|_| CurlUCode::BadIpv6)?;
        let canonical = ip.to_string();

        host.clear();
        host.push(b'[');
        host.extend_from_slice(canonical.as_bytes());
        host.push(b']');
        Ok(())
    }

    /// Validates a hostname, mirroring curl's `hostname_check`.
    ///
    /// An empty host is [`CurlUCode::NoHost`]; a bracketed host is handed to
    /// [`Url::ipv6_parse`]; any other host is rejected with
    /// [`CurlUCode::BadHostname`] if it contains a byte from curl's forbidden
    /// set (whitespace and a fixed list of delimiters/specials). Bytes `>= 0x80`
    /// are permitted, exactly as curl's `strcspn` check allows.
    fn hostname_check(&mut self, host: &mut Vec<u8>) -> UResult<()> {
        if host.is_empty() {
            return Err(CurlUCode::NoHost);
        }
        if host[0] == b'[' {
            return self.ipv6_parse(host);
        }
        // curl's reject set for a plain hostname.
        const REJECT: &[u8] = b" \r\n\t/:#?!@{}[]\\$'\"^`*<>=;,+&()%";
        if host.iter().any(|b| REJECT.contains(b)) {
            return Err(CurlUCode::BadHostname);
        }
        Ok(())
    }
}

/// The classification returned by [`ipv4_normalize`].
///
/// curl's `HOST_ERROR` (an out-of-memory result from the dynamic buffer) has no
/// analogue here: Rust aborts rather than returning on allocation failure, so
/// only the three success-path outcomes are represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostType {
    /// A regular host name (or an address form curl leaves untouched).
    Name,
    /// A numeric IPv4 address that was normalized into dotted-quad form.
    Ipv4,
    /// A bracketed IPv6 literal, to be handled by [`Url::ipv6_parse`].
    Ipv6,
}

/// Parses a single component of a numeric IPv4 address in curl's accepted
/// bases.
///
/// A leading `0x`/`0X` selects hexadecimal, a leading `0` selects octal, and
/// anything else is decimal — matching the `curlx_str_hex`/`curlx_str_octal`/
/// `curlx_str_number` dispatch in curl's `ipv4_normalize`. Returns the parsed
/// value (capped at `UINT_MAX`) and the number of bytes consumed, or [`None`]
/// if there is no valid digit or the value overflows.
fn parse_ipv4_part(s: &[u8]) -> Option<(u64, usize)> {
    const MAXV: u64 = u32::MAX as u64;
    if at(s, 0) == b'0' {
        if at(s, 1) == b'x' {
            parse_radix(&s[2..], 16, MAXV).map(|(v, c)| (v, c + 2))
        } else {
            parse_radix(s, 8, MAXV)
        }
    } else {
        parse_radix(s, 10, MAXV)
    }
}

/// Parses a run of digits in the given radix (8, 10, or 16), mirroring curl's
/// `str_num_base`.
///
/// Requires at least one valid digit, stops at the first non-digit, and rejects
/// values exceeding `max`. Returns the value and the number of bytes consumed,
/// or [`None`] on "no digits" / overflow.
fn parse_radix(s: &[u8], radix: u64, max: u64) -> Option<(u64, usize)> {
    let digit = |b: u8| -> Option<u64> {
        let v = match b {
            b'0'..=b'9' => u64::from(b - b'0'),
            b'a'..=b'f' => u64::from(b - b'a') + 10,
            b'A'..=b'F' => u64::from(b - b'A') + 10,
            _ => return None,
        };
        if v < radix {
            Some(v)
        } else {
            None
        }
    };

    // Require at least one valid digit (curl's STRE_NO_NUM guard).
    let mut num = digit(at(s, 0))?;
    let mut i = 1;
    while let Some(v) = digit(at(s, i)) {
        num = num.checked_mul(radix)?.checked_add(v)?;
        if num > max {
            return None;
        }
        i += 1;
    }
    Some((num, i))
}

/// Normalizes partial and multi-base numeric IPv4 addresses, mirroring curl's
/// `ipv4_normalize`.
///
/// It accepts the historical dotted forms `a`, `a.b`, `a.b.c`, and `a.b.c.d`
/// (each component in decimal, octal, or hex) and rewrites the host buffer into
/// canonical dotted-quad decimal. A bracketed host short-circuits to
/// [`HostType::Ipv6`]; anything that is not a well-formed numeric address (bad
/// syntax, too many parts, or a component out of range for its position)
/// returns [`HostType::Name`] so it is treated as a regular hostname.
fn ipv4_normalize(host: &mut Vec<u8>) -> HostType {
    if at(host, 0) == b'[' {
        return HostType::Ipv6;
    }

    let s = host.clone();
    let mut idx = 0usize;
    let mut parts = [0u64; 4];
    let mut n = 0usize;

    loop {
        let (val, consumed) = match parse_ipv4_part(&s[idx..]) {
            Some(x) => x,
            None => return HostType::Name,
        };
        parts[n] = val;
        idx += consumed;

        match at(&s, idx) {
            b'.' => {
                if n == 3 {
                    return HostType::Name;
                }
                n += 1;
                idx += 1;
            }
            0 => break,
            _ => return HostType::Name,
        }
    }

    let (a, b, c, d) = match n {
        0 => {
            let v = parts[0];
            (
                (v >> 24) & 0xff,
                (v >> 16) & 0xff,
                (v >> 8) & 0xff,
                v & 0xff,
            )
        }
        1 => {
            if parts[0] > 0xff || parts[1] > 0x00ff_ffff {
                return HostType::Name;
            }
            (
                parts[0],
                (parts[1] >> 16) & 0xff,
                (parts[1] >> 8) & 0xff,
                parts[1] & 0xff,
            )
        }
        2 => {
            if parts[0] > 0xff || parts[1] > 0xff || parts[2] > 0xffff {
                return HostType::Name;
            }
            (parts[0], parts[1], (parts[2] >> 8) & 0xff, parts[2] & 0xff)
        }
        3 => {
            if parts[0] > 0xff || parts[1] > 0xff || parts[2] > 0xff || parts[3] > 0xff {
                return HostType::Name;
            }
            (parts[0], parts[1], parts[2], parts[3])
        }
        _ => unreachable!("n is bounded to 0..=3 by the parsing loop"),
    };

    host.clear();
    // Components are each masked to a single octet, so the result is always a
    // valid dotted-quad.
    let dotted = format!("{a}.{b}.{c}.{d}");
    host.extend_from_slice(dotted.as_bytes());
    HostType::Ipv4
}

impl Url {
    /// URL-decodes the host in place when it contains a `%`, mirroring curl's
    /// `urldecode_host`.
    ///
    /// Decoding uses curl's `REJECT_CTRL` mode (control bytes in the decoded
    /// output are rejected). Hosts without a `%` are left untouched.
    ///
    /// # Errors
    ///
    /// [`CurlUCode::BadHostname`] if decoding fails (a decoded control byte).
    fn urldecode_host(host: &mut Vec<u8>) -> UResult<()> {
        if !host.contains(&b'%') {
            return Ok(());
        }
        let decoded = escape::unescape(host, true).map_err(|_| CurlUCode::BadHostname)?;
        *host = decoded;
        Ok(())
    }

    /// Parses the authority (`[userinfo@]host[:port]`) of a URL, mirroring
    /// curl's `parse_authority`.
    ///
    /// It strips and stores the login details, appends the remaining hostname to
    /// `host`, splits off the port, and then classifies the host via
    /// [`ipv4_normalize`], dispatching to IPv6 parsing, IPv4 normalization, or
    /// hostname validation (with host URL-decoding) as appropriate.
    ///
    /// # Errors
    ///
    /// Propagates the component-specific [`CurlUCode`] (e.g.
    /// [`CurlUCode::NoHost`], [`CurlUCode::BadHostname`],
    /// [`CurlUCode::BadPortNumber`], [`CurlUCode::UserNotAllowed`]).
    fn parse_authority(
        &mut self,
        auth: &[u8],
        flags: u32,
        host: &mut Vec<u8>,
        has_scheme: bool,
    ) -> UResult<()> {
        let offset = self.parse_hostname_login(auth, flags)?;
        host.extend_from_slice(&auth[offset..]);

        self.parse_port(host, has_scheme)?;

        if host.is_empty() {
            return Err(CurlUCode::NoHost);
        }

        match ipv4_normalize(host) {
            HostType::Ipv4 => Ok(()),
            HostType::Ipv6 => self.ipv6_parse(host),
            HostType::Name => {
                Url::urldecode_host(host)?;
                self.hostname_check(host)
            }
        }
    }

    /// Sets the authority (host, and optionally userinfo/port) from a raw
    /// authority string — curl's `Curl_url_set_authority`, used for HTTP/2
    /// server push.
    ///
    /// Credentials are rejected ([`DISALLOW_USER`] semantics). On success the
    /// host component is replaced.
    ///
    /// # Errors
    ///
    /// Propagates any [`CurlUCode`] from authority parsing, or
    /// [`CurlUCode::BadHostname`] if the parsed host is not valid UTF-8.
    pub fn set_authority(&mut self, authority: &str) -> UResult<()> {
        let mut host = Vec::new();
        let has_scheme = self.scheme.is_some();
        self.parse_authority(authority.as_bytes(), DISALLOW_USER, &mut host, has_scheme)?;
        self.host = Some(String::from_utf8(host).map_err(|_| CurlUCode::BadHostname)?);
        Ok(())
    }
}

// ===========================================================================
// Scheme guessing, file: URLs, and path normalization helpers.
// ===========================================================================

/// Case-insensitive ASCII prefix test, mirroring curl's `checkprefix`.
///
/// `needle_lower` is compared case-insensitively against the start of
/// `haystack` (curl's `checkprefix` is case-insensitive on both operands).
fn starts_with_ci(haystack: &[u8], needle_lower: &[u8]) -> bool {
    haystack.len() >= needle_lower.len()
        && haystack[..needle_lower.len()].eq_ignore_ascii_case(needle_lower)
}

/// Reports whether `s` begins with a Windows-style URL drive prefix, mirroring
/// curl's `STARTS_WITH_URL_DRIVE_PREFIX`.
///
/// The pattern is `<letter>` followed by `:` or `|` and then `/`, `\`, or end
/// of string. On the non-Windows target this is used only to *reject* such
/// `file:` URLs.
fn starts_with_url_drive_prefix(s: &[u8]) -> bool {
    at(s, 0).is_ascii_alphabetic()
        && (at(s, 1) == b':' || at(s, 1) == b'|')
        && (at(s, 2) == b'/' || at(s, 2) == b'\\' || at(s, 2) == 0)
}

/// Detects a "dot" path segment at the start of `s`, mirroring curl's `is_dot`.
///
/// Returns the number of bytes the dot occupies — `1` for a literal `.`, or `3`
/// for a percent-encoded `%2e`/`%2E` — or [`None`] if `s` does not begin with a
/// dot segment.
fn is_dot(s: &[u8]) -> Option<usize> {
    if at(s, 0) == b'.' {
        Some(1)
    } else if s.len() >= 3 && s[0] == b'%' && s[1] == b'2' && (s[2] | 0x20) == b'e' {
        Some(3)
    } else {
        None
    }
}

/// Removes `.` and `..` path segments per RFC 3986 §5.2.4, mirroring curl's
/// `dedotdotify` (curl unit test 1395).
///
/// The input is a path (it must not contain the query or fragment). Percent-
/// encoded dots (`%2e`) are treated as dots, matching curl. A path shorter than
/// two bytes is returned unchanged (curl leaves `u->path` untouched in that
/// case). The result may legitimately be empty (e.g. for an input of `.` or
/// `..`).
fn dedotdotify(input: &[u8]) -> Vec<u8> {
    // The path always starts with a slash, and a slash has no dot; a length
    // below two cannot contain a dot segment.
    if input.len() < 2 {
        return input.to_vec();
    }

    let mut out: Vec<u8> = Vec::with_capacity(input.len() + 1);
    let mut cur: &[u8] = input;

    // Step A/D: strip a leading "./", ".", "../", or ".." prefix.
    if let Some(adv1) = is_dot(cur) {
        let after1 = &cur[adv1..];
        cur = after1;
        if after1.is_empty() {
            // "." at end.
            return out;
        } else if after1[0] == b'/' {
            // "./"
            cur = &after1[1..];
        } else if let Some(adv2) = is_dot(after1) {
            let after2 = &after1[adv2..];
            if after2.is_empty() {
                // ".." at end.
                return out;
            } else if after2[0] == b'/' {
                // "../"
                cur = &after2[1..];
            }
            // Otherwise ("..x"), fall through with `cur` after the first dot.
        }
        // Otherwise (".x"), fall through with `cur` after the first dot.
    }

    while !cur.is_empty() {
        if cur[0] == b'/' {
            let after_slash = &cur[1..];
            if let Some(adv) = is_dot(after_slash) {
                let p1 = &after_slash[adv..];
                if p1.is_empty() {
                    // "/." at the end: replace with a trailing slash.
                    out.push(b'/');
                    break;
                } else if p1[0] == b'/' {
                    // "/./" -> collapse to "/" and continue from that slash.
                    cur = p1;
                    continue;
                } else if let Some(adv2) = is_dot(p1) {
                    let p2 = &p1[adv2..];
                    if p2.is_empty() || p2[0] == b'/' {
                        // "/../" or "/..": remove the last output segment.
                        if let Some(last) = out.iter().rposition(|&b| b == b'/') {
                            out.truncate(last);
                        }
                        if !p2.is_empty() {
                            // "/../"
                            cur = p2;
                            continue;
                        }
                        // "/.." at the end.
                        out.push(b'/');
                        break;
                    }
                    // "/..x" -> a real segment; fall through to step E.
                }
                // "/.x" -> a real segment; fall through to step E.
            }
        }

        // Step E: move one byte from input to output.
        out.push(cur[0]);
        cur = &cur[1..];
    }

    out
}

impl Url {
    /// Parses a `file:` URL, mirroring curl's `parse_file`.
    ///
    /// Sets the scheme to `file` and returns the byte offset and length of the
    /// path portion within `url`. Per RFC 8089 the authority may be omitted
    /// (`file:/path`); when present it must be empty, `localhost`, or
    /// `127.0.0.1` (UNC hosts and drive letters are Windows-only and rejected
    /// on this target). No host component is produced for `file:` URLs.
    ///
    /// # Errors
    ///
    /// [`CurlUCode::BadFileUrl`] for a too-short URL, a non-local authority, or
    /// a drive-letter path.
    fn parse_file(&mut self, url: &[u8], urllen: usize) -> UResult<(usize, usize)> {
        if urllen <= 6 {
            // "file:/" is not enough to be a complete file: URL.
            return Err(CurlUCode::BadFileUrl);
        }

        // The path begins right after "file:".
        let mut path_start = 5usize;
        self.scheme = Some("file".to_string());

        // Handle the "file://" authority form.
        if at(url, path_start) == b'/' && at(url, path_start + 1) == b'/' {
            // Skip the two slashes.
            let mut ptr = path_start + 2;
            if at(url, ptr) != b'/' && !starts_with_url_drive_prefix(&url[ptr..]) {
                // A hostname is present; only "localhost" or "127.0.0.1" are
                // accepted as local (anything else would be a UNC host, which
                // this target does not support).
                if starts_with_ci(&url[ptr..], b"localhost/")
                    || starts_with_ci(&url[ptr..], b"127.0.0.1/")
                {
                    // Advance to the slash after the host (keep it as path).
                    ptr += 9;
                } else {
                    return Err(CurlUCode::BadFileUrl);
                }
            }
            path_start = ptr;
        }

        // Reject Windows drive letters (both "file:/c:" and "file:c:" forms),
        // which are only valid on MS-DOS/Windows.
        if (at(url, path_start) == b'/' && starts_with_url_drive_prefix(&url[path_start + 1..]))
            || starts_with_url_drive_prefix(&url[path_start..])
        {
            return Err(CurlUCode::BadFileUrl);
        }

        let pathlen = urllen - path_start;
        Ok((path_start, pathlen))
    }

    /// Parses the scheme and validates the slash count, mirroring curl's
    /// `parse_scheme`.
    ///
    /// When a scheme is present, the run of slashes after `scheme:` must number
    /// one to three, and an unknown scheme is rejected unless
    /// [`NON_SUPPORT_SCHEME`] is set. When no scheme is present, either
    /// [`DEFAULT_SCHEME`] (applies `https`) or [`GUESS_SCHEME`] (defers to
    /// [`Url::guess_scheme`]) must be set. Returns the byte offset at which the
    /// hostname begins.
    ///
    /// # Errors
    ///
    /// [`CurlUCode::UnsupportedScheme`], [`CurlUCode::BadSlashes`], or
    /// [`CurlUCode::BadScheme`].
    fn parse_scheme(
        &mut self,
        url: &[u8],
        schemebuf: Option<&str>,
        schemelen: usize,
        flags: u32,
    ) -> UResult<usize> {
        if schemelen > 0 {
            let scheme = schemebuf.unwrap_or_default();

            // Count the slashes that follow the "scheme:".
            let mut i = 0;
            let mut p = schemelen + 1;
            while at(url, p) == b'/' && i < 4 {
                p += 1;
                i += 1;
            }

            // Reject an unknown scheme unless the caller explicitly allows it.
            if get_scheme(scheme).is_none() && flags & NON_SUPPORT_SCHEME == 0 {
                return Err(CurlUCode::UnsupportedScheme);
            }

            if !(1..=3).contains(&i) {
                // Fewer than one or more than three slashes.
                return Err(CurlUCode::BadSlashes);
            }

            self.scheme = Some(scheme.to_string());
            Ok(p)
        } else {
            // No scheme present.
            if flags & (DEFAULT_SCHEME | GUESS_SCHEME) == 0 {
                return Err(CurlUCode::BadScheme);
            }
            if flags & DEFAULT_SCHEME != 0 {
                self.scheme = Some(DEFAULT_SCHEME_NAME.to_string());
            }
            // The hostname starts at the beginning of the (scheme-less) URL.
            Ok(0)
        }
    }

    /// Applies curl's legacy hostname-based scheme guessing, mirroring
    /// `guess_scheme`.
    ///
    /// A host beginning with `ftp.`, `dict.`, `ldap.`, `imap.`, `smtp.`, or
    /// `pop3.` selects the matching scheme; anything else defaults to `http`.
    /// The [`Url::guessed_scheme`] flag is set so `--trace` output and
    /// [`NO_GUESS_SCHEME`] behave identically to curl.
    fn guess_scheme(&mut self, host: &[u8]) {
        let scheme = if starts_with_ci(host, b"ftp.") {
            "ftp"
        } else if starts_with_ci(host, b"dict.") {
            "dict"
        } else if starts_with_ci(host, b"ldap.") {
            "ldap"
        } else if starts_with_ci(host, b"imap.") {
            "imap"
        } else if starts_with_ci(host, b"smtp.") {
            "smtp"
        } else if starts_with_ci(host, b"pop3.") {
            "pop3"
        } else {
            "http"
        };
        self.scheme = Some(scheme.to_string());
        self.guessed_scheme = true;
    }

    /// Stores the fragment component, mirroring curl's `handle_fragment`.
    ///
    /// `fragment` includes the leading `#`. The presence flag is always set; a
    /// non-empty body (more than just `#`) is stored, URL-encoded when
    /// [`URLENCODE`] is set. A bare `#` records presence with no stored value.
    fn handle_fragment(&mut self, fragment: &[u8], fraglen: usize, flags: u32) {
        self.fragment_present = true;
        if fraglen > 1 {
            let body = &fragment[1..fraglen];
            if flags & URLENCODE != 0 {
                let mut enc = Vec::new();
                urlencode_str(&mut enc, body, true, false);
                self.fragment = Some(vec_to_string(enc));
            } else {
                self.fragment = Some(vec_to_string(body.to_vec()));
            }
        }
    }

    /// Stores the query component, mirroring curl's `handle_query`.
    ///
    /// `query` includes the leading `?`. The presence flag is always set. A
    /// non-empty body is stored (URL-encoded, with `+` for spaces, when
    /// [`URLENCODE`] is set); a bare `?` stores an empty string (matching
    /// curl's "single byte query" branch).
    fn handle_query(&mut self, query: &[u8], qlen: usize, flags: u32) {
        self.query_present = true;
        if qlen > 1 {
            let body = &query[1..qlen];
            if flags & URLENCODE != 0 {
                let mut enc = Vec::new();
                urlencode_str(&mut enc, body, true, true);
                self.query = Some(vec_to_string(enc));
            } else {
                self.query = Some(vec_to_string(body.to_vec()));
            }
        } else {
            // Single-byte query ("?"): store an empty string.
            self.query = Some(String::new());
        }
    }

    /// Stores (and normalizes) the path component, mirroring curl's
    /// `handle_path`.
    ///
    /// The path is URL-encoded first when [`URLENCODE`] is set. A path that is
    /// empty or just `/` is left unset (curl's `pathlen <= 1` branch). Otherwise
    /// the path is stored and, unless [`PATH_AS_IS`] is set, run through
    /// [`dedotdotify`] to remove `.`/`..` segments per RFC 3986.
    fn handle_path(&mut self, path: &[u8], flags: u32) {
        let mut path_buf: Vec<u8>;
        let mut pathlen = path.len();

        if pathlen > 0 && flags & URLENCODE != 0 {
            let mut enc = Vec::new();
            urlencode_str(&mut enc, path, true, false);
            pathlen = enc.len();
            path_buf = enc;
        } else {
            path_buf = path.to_vec();
        }

        if pathlen <= 1 {
            // No path left, or just the slash: leave unset (None).
            return;
        }

        if flags & PATH_AS_IS == 0 {
            path_buf = dedotdotify(&path_buf);
        }
        self.path = Some(vec_to_string(path_buf));
    }

    /// Parses a complete (absolute) URL into `self`, mirroring curl's
    /// `parseurl`.
    ///
    /// `self` is expected to be empty; on success every component is populated.
    /// The steps are: junk scan, absolute-scheme detection, `file:` handling or
    /// scheme+authority parsing (with optional scheme guessing), then splitting
    /// the fragment, query, and path off the tail. On failure `self` may hold
    /// partial state and must be discarded by the caller (see
    /// [`Url::parseurl_and_replace`]).
    ///
    /// # Errors
    ///
    /// Any component-specific [`CurlUCode`].
    fn parseurl(&mut self, url: &str, flags: u32) -> UResult<()> {
        let ub = url.as_bytes();
        let urllen = junkscan(ub, flags & ALLOW_SPACE != 0)?;

        // In guessing/default mode the scheme's colon must be followed by a
        // slash for the URL to be treated as absolute.
        let guess = flags & (GUESS_SCHEME | DEFAULT_SCHEME) != 0;
        let abs = is_absolute_url(ub, guess);
        let schemelen = abs.as_ref().map_or(0, |(l, _)| *l);
        let is_file = schemelen > 0 && abs.as_ref().map(|(_, s)| s.as_str()) == Some("file");

        let mut host: Vec<u8> = Vec::new();
        let mut host_present = false;
        let path_start: usize;
        let mut pathlen: usize;

        if is_file {
            let (ps, pl) = self.parse_file(ub, urllen)?;
            path_start = ps;
            pathlen = pl;
            // file: URLs carry no host on this target.
        } else {
            let schemebuf = abs.as_ref().map(|(_, s)| s.as_str());
            let hostp_start = self.parse_scheme(ub, schemebuf, schemelen, flags)?;

            // The hostname runs until the first '/', '?', or '#'.
            let hostp = &ub[hostp_start..];
            let hostlen = hostp
                .iter()
                .position(|&b| b == b'/' || b == b'?' || b == b'#')
                .unwrap_or(hostp.len());
            path_start = hostp_start + hostlen;
            pathlen = urllen - path_start;

            if hostlen > 0 {
                let has_scheme = self.scheme.is_some();
                self.parse_authority(
                    &ub[hostp_start..hostp_start + hostlen],
                    flags,
                    &mut host,
                    has_scheme,
                )?;
                if flags & GUESS_SCHEME != 0 && self.scheme.is_none() {
                    self.guess_scheme(&host);
                }
                host_present = true;
            } else if flags & NO_AUTHORITY != 0 {
                // Allowed to be empty.
                host_present = true;
            } else {
                return Err(CurlUCode::NoHost);
            }
        }

        // The fragment is found first, by scanning the whole remaining tail, so
        // that a '?' inside a fragment is not mistaken for a query delimiter.
        {
            let tail = &ub[path_start..path_start + pathlen];
            if let Some(fpos) = tail.iter().position(|&b| b == b'#') {
                let fraglen = pathlen - fpos;
                self.handle_fragment(&ub[path_start + fpos..path_start + pathlen], fraglen, flags);
                pathlen -= fraglen;
            }
        }

        // The query is then found within the fragment-stripped path.
        {
            let tail = &ub[path_start..path_start + pathlen];
            if let Some(qpos) = tail.iter().position(|&b| b == b'?') {
                let qlen = pathlen - qpos;
                self.handle_query(&ub[path_start + qpos..path_start + pathlen], qlen, flags);
                pathlen -= qlen;
            }
        }

        // Whatever remains is the path.
        self.handle_path(&ub[path_start..path_start + pathlen], flags);

        if host_present {
            self.host = Some(String::from_utf8(host).map_err(|_| CurlUCode::BadHostname)?);
        }
        Ok(())
    }

    /// Parses `url` and, on success, replaces every component of `self`,
    /// mirroring curl's `parseurl_and_replace`.
    ///
    /// Parsing happens into a fresh temporary handle so that `self` is left
    /// untouched if parsing fails.
    ///
    /// # Errors
    ///
    /// Any [`CurlUCode`] produced by [`Url::parseurl`].
    fn parseurl_and_replace(&mut self, url: &str, flags: u32) -> UResult<()> {
        let mut tmp = Url::default();
        tmp.parseurl(url, flags)?;
        *self = tmp;
        Ok(())
    }

    /// Resolves a relative URL against the current handle, mirroring curl's
    /// `redirect_url`.
    ///
    /// `base` is the fully-serialized current URL and `relurl` the relative
    /// reference (e.g. a `Location:` header value). The four relative forms are
    /// handled exactly as curl does:
    ///
    /// * `//host/path` — protocol-relative: keep the scheme, replace the host.
    /// * `/path` — absolute path: keep `scheme://host`, replace the path.
    /// * `#frag` — fragment-only change.
    /// * anything else — a path or query-relative reference, spliced in after
    ///   the last slash (dropping any existing query/fragment as curl does).
    ///
    /// The assembled URL is then re-parsed (with [`PATH_AS_IS`] cleared so
    /// `.`/`..` are resolved), replacing `self`.
    ///
    /// # Errors
    ///
    /// Any [`CurlUCode`] produced while re-parsing the combined URL.
    fn redirect_url(&mut self, base: &str, relurl: &str, flags: u32) -> UResult<()> {
        let base_b = base.as_bytes();
        let rel = relurl.as_bytes();

        // `protsep` points at the hostname, just past "scheme://". It is clamped
        // to the length of `base` purely as a panic-safety guard; for any URL
        // produced by this module it lands within bounds.
        let scheme_len = self.scheme.as_deref().map_or(0, str::len);
        let protsep = (scheme_len + 3).min(base_b.len());

        let mut host_changed = false;
        let mut useurl_start = 0usize;
        let mut cutoff: Option<usize> = None;

        // strchr starting at `from`, returning an absolute index into `base`.
        let strchr_from = |from: usize, ch: u8| -> Option<usize> {
            base_b[from..]
                .iter()
                .position(|&b| b == ch)
                .map(|p| from + p)
        };

        match at(rel, 0) {
            b'/' => {
                if at(rel, 1) == b'/' {
                    // Protocol-relative URL: "//example.com/path".
                    cutoff = Some(protsep);
                    useurl_start = 2;
                    host_changed = true;
                } else {
                    // Absolute path: "/path".
                    cutoff = strchr_from(protsep, b'/');
                }
            }
            b'#' => {
                // Fragment-only change.
                if self.fragment.is_some() {
                    cutoff = strchr_from(protsep, b'#');
                }
            }
            _ => {
                // Path or query-relative change.
                if self.query.as_deref().is_some_and(|q| !q.is_empty()) {
                    // Remove the existing query.
                    cutoff = strchr_from(protsep, b'?');
                } else if self.fragment.as_deref().is_some_and(|f| !f.is_empty()) {
                    // Remove the existing fragment.
                    cutoff = strchr_from(protsep, b'#');
                }

                if at(rel, 0) != b'?' {
                    // Append a relative path after the last slash of the region.
                    let end = cutoff.unwrap_or(base_b.len());
                    cutoff = base_b[protsep..end]
                        .iter()
                        .rposition(|&b| b == b'/')
                        .map(|p| protsep + p + 1);
                }
            }
        }

        let prelen = cutoff.unwrap_or(base_b.len());

        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&base_b[..prelen]);
        // When the host changed (protocol-relative), the appended part carries
        // its own host, so it is encoded as a non-relative fragment (its host
        // bytes are preserved); otherwise it is encoded as a relative fragment.
        urlencode_str(&mut buf, &rel[useurl_start..], !host_changed, false);

        let newurl = vec_to_string(buf);
        self.parseurl_and_replace(&newurl, flags & !PATH_AS_IS)
    }
}

// ===========================================================================
// Component readback — curl_url_get.
// ===========================================================================

impl Url {
    /// Applies the requested transforms to a single component string, mirroring
    /// curl's `urlget_format`.
    ///
    /// In order: `+`→space decoding (query only), URL-decoding
    /// ([`URLDECODE`], control bytes rejected), then exactly one of
    /// URL-encoding ([`URLENCODE`]), IDN→Punycode ([`PUNYCODE`], host only), or
    /// Punycode→IDN ([`PUNY2IDN`], host only).
    ///
    /// # Errors
    ///
    /// [`CurlUCode::Urldecode`] if decoding hits a control byte;
    /// [`CurlUCode::BadHostname`] if IDN conversion fails.
    fn urlget_format(
        &self,
        what: CurlUPart,
        ptr: &str,
        plusdecode: bool,
        flags: u32,
    ) -> UResult<String> {
        let urldecode = flags & URLDECODE != 0;
        let urlencode = flags & URLENCODE != 0;
        let punycode = flags & PUNYCODE != 0 && what == CurlUPart::Host;
        let depunyfy = flags & PUNY2IDN != 0 && what == CurlUPart::Host;

        let mut part: Vec<u8> = ptr.as_bytes().to_vec();

        if plusdecode {
            // Convert '+' to space.
            for b in &mut part {
                if *b == b'+' {
                    *b = b' ';
                }
            }
        }

        if urldecode {
            // Control bytes are unconditionally rejected (documented behavior).
            part = escape::unescape(&part, true).map_err(|_| CurlUCode::Urldecode)?;
        }

        if urlencode {
            let mut enc = Vec::new();
            urlencode_str(&mut enc, &part, true, what == CurlUPart::Query);
            part = enc;
        } else if punycode {
            // Deliver the ACE/Punycode form of a non-ASCII host.
            let host = self.host.as_deref().unwrap_or_default();
            if !idn::is_ascii_name(host) {
                let s = core::str::from_utf8(&part).map_err(|_| CurlUCode::BadHostname)?;
                part = idn::to_ascii(s)
                    .map_err(|_| CurlUCode::BadHostname)?
                    .into_bytes();
            }
        } else if depunyfy {
            // Deliver the Unicode form of an ASCII (possibly ACE) host.
            let host = self.host.as_deref().unwrap_or_default();
            if idn::is_ascii_name(host) {
                let s = core::str::from_utf8(&part).map_err(|_| CurlUCode::BadHostname)?;
                part = idn::from_ascii(s)
                    .map_err(|_| CurlUCode::BadHostname)?
                    .into_bytes();
            }
        }

        Ok(vec_to_string(part))
    }

    /// Serializes the whole handle back into a URL string, mirroring curl's
    /// `urlget_url`.
    ///
    /// Honors [`GET_EMPTY`] (emit empty but present query/fragment),
    /// [`DEFAULT_SCHEME`]/[`DEFAULT_PORT`] (supply scheme/port defaults),
    /// [`NO_DEFAULT_PORT`] (drop a port equal to the scheme default),
    /// [`NO_GUESS_SCHEME`] (omit a guessed `scheme://`), [`URLENCODE`]
    /// (percent-encode the host), and [`PUNYCODE`]/[`PUNY2IDN`] (host IDN form).
    /// A zone id is rendered as `[host%25zone]`.
    ///
    /// # Errors
    ///
    /// [`CurlUCode::NoHost`] if there is no host (non-`file:`),
    /// [`CurlUCode::NoScheme`] if no scheme can be determined, or
    /// [`CurlUCode::BadHostname`] on IDN conversion failure.
    fn urlget_url(&self, flags: u32) -> UResult<String> {
        let show_fragment =
            self.fragment.is_some() || (self.fragment_present && flags & GET_EMPTY != 0);
        let show_query = self.query.as_deref().is_some_and(|q| !q.is_empty())
            || (self.query_present && flags & GET_EMPTY != 0);
        let punycode = flags & PUNYCODE != 0;
        let depunyfy = flags & PUNY2IDN != 0;
        let urlencode = flags & URLENCODE != 0;

        // The file: scheme has no authority; assemble it directly.
        if self.scheme.as_deref() == Some("file") {
            let mut url = String::from("file://");
            url.push_str(self.path.as_deref().unwrap_or_default());
            if show_query {
                url.push('?');
            }
            if let Some(q) = &self.query {
                url.push_str(q);
            }
            if show_fragment {
                url.push('#');
            }
            if let Some(f) = &self.fragment {
                url.push_str(f);
            }
            return Ok(url);
        }

        let host = self.host.as_deref().ok_or(CurlUCode::NoHost)?;

        // Resolve the scheme (stored, defaulted, or error).
        let scheme: &str = if let Some(s) = self.scheme.as_deref() {
            s
        } else if flags & DEFAULT_SCHEME != 0 {
            DEFAULT_SCHEME_NAME
        } else {
            return Err(CurlUCode::NoScheme);
        };
        let h = get_scheme(scheme);

        // Supply or inhibit the port per the flags.
        let mut port: Option<String> = self.port.clone();
        if self.port.is_none() && flags & DEFAULT_PORT != 0 {
            if let Some(hi) = h {
                port = Some(hi.defport.to_string());
            }
        } else if self.port.is_some() {
            if let Some(hi) = h {
                if hi.defport == self.portnum && flags & NO_DEFAULT_PORT != 0 {
                    port = None;
                }
            }
        }

        // Options are only meaningful for schemes that carry them.
        let mut options = self.options.as_deref();
        if let Some(hi) = h {
            if !hi.url_options {
                options = None;
            }
        }

        // Format the host (zone id, URL-encoding, or IDN forms).
        let allochost: Option<String> = if host.as_bytes().first() == Some(&b'[') {
            self.zoneid.as_ref().map(|zone| {
                // "[ host %25 zoneid ]": host without its trailing ']'.
                let trimmed = &host[..host.len().saturating_sub(1)];
                format!("{trimmed}%25{zone}]")
            })
        } else if urlencode {
            Some(escape::escape(host.as_bytes()))
        } else if punycode {
            if idn::is_ascii_name(host) {
                None
            } else {
                Some(idn::to_ascii(host).map_err(|_| CurlUCode::BadHostname)?)
            }
        } else if depunyfy {
            if idn::is_ascii_name(host) {
                Some(idn::from_ascii(host).map_err(|_| CurlUCode::BadHostname)?)
            } else {
                None
            }
        } else {
            None
        };
        let effective_host = allochost.as_deref().unwrap_or(host);

        let mut url = String::new();

        // Omit "scheme://" only when asked to and the scheme was guessed.
        if flags & NO_GUESS_SCHEME == 0 || !self.guessed_scheme {
            url.push_str(scheme);
            url.push_str("://");
        }

        // Userinfo: user[:password][;options]@ (only if any are present).
        if let Some(u) = &self.user {
            url.push_str(u);
        }
        if let Some(pw) = &self.password {
            url.push(':');
            url.push_str(pw);
        }
        if let Some(op) = options {
            url.push(';');
            url.push_str(op);
        }
        if self.user.is_some() || self.password.is_some() || options.is_some() {
            url.push('@');
        }

        url.push_str(effective_host);

        if let Some(p) = &port {
            url.push(':');
            url.push_str(p);
        }

        // Path defaults to "/" when unset.
        url.push_str(self.path.as_deref().unwrap_or("/"));

        if show_query {
            url.push('?');
        }
        if let Some(q) = &self.query {
            url.push_str(q);
        }
        if show_fragment {
            url.push('#');
        }
        if let Some(f) = &self.fragment {
            url.push_str(f);
        }

        Ok(url)
    }

    /// Reads a component out of the handle — the Rust form of `curl_url_get`.
    ///
    /// Returns the requested [`CurlUPart`] as an owned [`String`] with the
    /// transforms selected by `flags` applied (see [`Url::urlget_format`] and
    /// [`Url::urlget_url`]). A component that is not present yields the part's
    /// "no such part" [`CurlUCode`] (e.g. [`CurlUCode::NoHost`]) — except
    /// [`CurlUPart::Path`], which defaults to `/`, and [`CurlUPart::Url`], which
    /// assembles the full URL.
    ///
    /// # Errors
    ///
    /// The part-specific missing-component code, or a transform error from the
    /// helpers above.
    pub fn get(&self, what: CurlUPart, flags: u32) -> UResult<String> {
        let mut flags = flags;
        let ifmissing: CurlUCode;
        let mut plusdecode = false;
        let ptr: Option<String>;

        match what {
            CurlUPart::Scheme => {
                ifmissing = CurlUCode::NoScheme;
                flags &= !URLDECODE; // never for schemes
                if flags & NO_GUESS_SCHEME != 0 && self.guessed_scheme {
                    return Err(CurlUCode::NoScheme);
                }
                ptr = self.scheme.clone();
            }
            CurlUPart::User => {
                ifmissing = CurlUCode::NoUser;
                ptr = self.user.clone();
            }
            CurlUPart::Password => {
                ifmissing = CurlUCode::NoPassword;
                ptr = self.password.clone();
            }
            CurlUPart::Options => {
                ifmissing = CurlUCode::NoOptions;
                ptr = self.options.clone();
            }
            CurlUPart::Host => {
                ifmissing = CurlUCode::NoHost;
                ptr = self.host.clone();
            }
            CurlUPart::ZoneId => {
                ifmissing = CurlUCode::NoZoneid;
                ptr = self.zoneid.clone();
            }
            CurlUPart::Port => {
                ifmissing = CurlUCode::NoPort;
                flags &= !URLDECODE; // never for port
                if self.port.is_none() && flags & DEFAULT_PORT != 0 && self.scheme.is_some() {
                    // No stored port, but a default was requested.
                    let h = self.scheme.as_deref().and_then(get_scheme);
                    ptr = h.map(|hi| hi.defport.to_string());
                } else if self.port.is_some() && self.scheme.is_some() {
                    // A stored port that may be inhibited if it is the default.
                    let h = self.scheme.as_deref().and_then(get_scheme);
                    if h.is_some_and(|hi| hi.defport == self.portnum)
                        && flags & NO_DEFAULT_PORT != 0
                    {
                        ptr = None;
                    } else {
                        ptr = self.port.clone();
                    }
                } else {
                    ptr = self.port.clone();
                }
            }
            CurlUPart::Path => {
                ifmissing = CurlUCode::UnknownPart; // path is never "missing"
                ptr = Some(self.path.clone().unwrap_or_else(|| "/".to_string()));
            }
            CurlUPart::Query => {
                ifmissing = CurlUCode::NoQuery;
                plusdecode = flags & URLDECODE != 0;
                ptr = match &self.query {
                    // A blank query is withheld unless GET_EMPTY was requested.
                    Some(q) if q.is_empty() && flags & GET_EMPTY == 0 => None,
                    other => other.clone(),
                };
            }
            CurlUPart::Fragment => {
                ifmissing = CurlUCode::NoFragment;
                if self.fragment.is_none() && self.fragment_present && flags & GET_EMPTY != 0 {
                    // A blank fragment is delivered when explicitly requested.
                    ptr = Some(String::new());
                } else {
                    ptr = self.fragment.clone();
                }
            }
            CurlUPart::Url => {
                return self.urlget_url(flags);
            }
        }

        match ptr {
            Some(s) => self.urlget_format(what, &s, plusdecode, flags),
            None => Err(ifmissing),
        }
    }
}

// ===========================================================================
// Component mutation — curl_url_set.
// ===========================================================================

/// Reports whether `x` is a sub-delim / path character that curl leaves
/// unescaped inside a path, mirroring curl's `allowed_in_path`.
fn allowed_in_path(x: u8) -> bool {
    matches!(
        x,
        b'!' | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'{'
            | b'}'
            | b'['
            | b']'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'='
            | b':'
            | b'@'
            | b'/'
    )
}

/// Identifies which component a `set` call targets, chosen before the value is
/// encoded and stored (curl uses a `char **storep` for the same purpose).
#[derive(Debug, Clone, Copy)]
enum StorePart {
    Scheme,
    User,
    Password,
    Options,
    Host,
    ZoneId,
    Path,
    Query,
    Fragment,
}

impl Url {
    /// Validates a scheme being set, mirroring curl's `set_url_scheme`.
    ///
    /// The scheme must be 1..=[`MAX_SCHEME_LEN`] bytes. A scheme unknown to curl
    /// is rejected unless [`NON_SUPPORT_SCHEME`] is set, in which case it must
    /// still be syntactically valid (`ALPHA *( ALNUM / "+" / "-" / "." )`).
    /// Clears the guessed-scheme flag. The scheme string itself is stored by the
    /// caller.
    ///
    /// # Errors
    ///
    /// [`CurlUCode::BadScheme`] or [`CurlUCode::UnsupportedScheme`].
    fn set_url_scheme(&mut self, scheme: &str, flags: u32) -> UResult<()> {
        let plen = scheme.len();
        if !(1..=MAX_SCHEME_LEN).contains(&plen) {
            return Err(CurlUCode::BadScheme);
        }
        let known = get_scheme(scheme);
        if flags & NON_SUPPORT_SCHEME == 0 && known.is_none() {
            return Err(CurlUCode::UnsupportedScheme);
        }
        if known.is_none() {
            let b = scheme.as_bytes();
            if !b[0].is_ascii_alphabetic() {
                return Err(CurlUCode::BadScheme);
            }
            // curl validates every byte except the last (its loop runs
            // `plen - 1` times over the string starting at index 0).
            for &c in &b[..plen - 1] {
                if !(c.is_ascii_alphanumeric() || c == b'+' || c == b'-' || c == b'.') {
                    return Err(CurlUCode::BadScheme);
                }
            }
        }
        self.guessed_scheme = false;
        Ok(())
    }

    /// Sets the port from a decimal string, mirroring curl's `set_url_port`.
    ///
    /// The value must begin with a digit and be a decimal number in
    /// `0..=65535` with no trailing bytes. The stored string is re-formatted
    /// (leading zeroes stripped) and the numeric port is recorded.
    ///
    /// # Errors
    ///
    /// [`CurlUCode::BadPortNumber`].
    fn set_url_port(&mut self, provided: &str) -> UResult<()> {
        let b = provided.as_bytes();
        if !at(b, 0).is_ascii_digit() {
            return Err(CurlUCode::BadPortNumber);
        }
        let port = parse_decimal_all(b, 0xffff).ok_or(CurlUCode::BadPortNumber)?;
        self.port = Some(port.to_string());
        self.portnum = port as u16;
        Ok(())
    }

    /// Clears a component (or the whole handle), mirroring curl's
    /// `urlset_clear` — invoked when `set` is called with a `None` value.
    fn urlset_clear(&mut self, what: CurlUPart) {
        match what {
            CurlUPart::Url => *self = Url::default(),
            CurlUPart::Scheme => {
                self.scheme = None;
                self.guessed_scheme = false;
            }
            CurlUPart::User => self.user = None,
            CurlUPart::Password => self.password = None,
            CurlUPart::Options => self.options = None,
            CurlUPart::Host => self.host = None,
            CurlUPart::ZoneId => self.zoneid = None,
            CurlUPart::Port => {
                self.portnum = 0;
                self.port = None;
            }
            CurlUPart::Path => self.path = None,
            CurlUPart::Query => {
                self.query = None;
                self.query_present = false;
            }
            CurlUPart::Fragment => {
                self.fragment = None;
                self.fragment_present = false;
            }
        }
    }

    /// Replaces the handle's URL from an absolute or relative reference,
    /// mirroring curl's `set_url`.
    ///
    /// An empty value is a no-op when the handle already holds a complete URL
    /// (the redirect base case); an absolute value replaces everything; a
    /// relative value is resolved against the current URL via
    /// [`Url::redirect_url`] (or replaces outright if the current URL is
    /// incomplete).
    ///
    /// # Errors
    ///
    /// [`CurlUCode::MalformedInput`] for an empty value with no existing URL, or
    /// any parse/resolution [`CurlUCode`].
    fn set_url(&mut self, url: &str, part_size: usize, flags: u32) -> UResult<()> {
        if part_size == 0 {
            // A blank URL is valid only if we already have a complete one and
            // this is effectively a redirect that changes nothing.
            return match self.get(CurlUPart::Url, flags) {
                Ok(_) => Ok(()),
                Err(CurlUCode::OutOfMemory) => Err(CurlUCode::OutOfMemory),
                Err(_) => Err(CurlUCode::MalformedInput),
            };
        }

        // An absolute URL replaces the existing contents outright.
        let guess = flags & (GUESS_SCHEME | DEFAULT_SCHEME) != 0;
        if is_absolute_url(url.as_bytes(), guess).is_some() {
            return self.parseurl_and_replace(url, flags);
        }

        // Otherwise, apply the relative reference to the current URL. If the
        // current URL is incomplete, replace it with the new value instead.
        match self.get(CurlUPart::Url, flags) {
            Err(CurlUCode::OutOfMemory) => Err(CurlUCode::OutOfMemory),
            Err(_) => self.parseurl_and_replace(url, flags),
            Ok(oldurl) => self.redirect_url(&oldurl, url, flags),
        }
    }

    /// Sets or clears a component — the Rust form of `curl_url_set`.
    ///
    /// A `None` value clears the component (see [`Url::urlset_clear`]). A
    /// `Some` value is validated and, when [`URLENCODE`] is set, percent-encoded
    /// according to per-part rules (spaces become `+` in queries, path
    /// sub-delims are preserved, only the first `=` survives an appended query).
    /// [`CurlUPart::Path`] gains a leading `/`; [`CurlUPart::Host`] is validated
    /// (and clears the zone id first); [`CurlUPart::Query`] with [`APPENDQUERY`]
    /// appends to any existing query; [`CurlUPart::Scheme`], [`CurlUPart::Port`],
    /// and [`CurlUPart::Url`] have dedicated handling.
    ///
    /// # Errors
    ///
    /// The component-specific [`CurlUCode`] (`BadScheme`, `BadPortNumber`,
    /// `BadHostname`, `MalformedInput`, etc.).
    pub fn set(&mut self, what: CurlUPart, part: Option<&str>, flags: u32) -> UResult<()> {
        let part = match part {
            // Setting a part to nothing clears it.
            None => {
                self.urlset_clear(what);
                return Ok(());
            }
            Some(p) => p,
        };

        let nalloc = part.len();
        if nalloc > CURL_MAX_INPUT_LENGTH {
            return Err(CurlUCode::MalformedInput);
        }

        let mut urlencode = flags & URLENCODE != 0;
        let mut plusencode = false;
        let mut pathmode = false;
        let mut leadingslash = false;
        let mut appendquery = false;
        let mut equalsencode = false;
        let store: StorePart;

        match what {
            CurlUPart::Scheme => {
                self.set_url_scheme(part, flags)?;
                store = StorePart::Scheme;
                urlencode = false; // never for schemes
            }
            CurlUPart::User => store = StorePart::User,
            CurlUPart::Password => store = StorePart::Password,
            CurlUPart::Options => store = StorePart::Options,
            CurlUPart::Host => {
                store = StorePart::Host;
                self.zoneid = None;
            }
            CurlUPart::ZoneId => store = StorePart::ZoneId,
            CurlUPart::Port => return self.set_url_port(part),
            CurlUPart::Path => {
                pathmode = true;
                leadingslash = true; // enforce a leading slash
                store = StorePart::Path;
            }
            CurlUPart::Query => {
                plusencode = urlencode;
                appendquery = flags & APPENDQUERY != 0;
                equalsencode = appendquery;
                store = StorePart::Query;
                self.query_present = true;
            }
            CurlUPart::Fragment => {
                store = StorePart::Fragment;
                self.fragment_present = true;
            }
            CurlUPart::Url => return self.set_url(part, nalloc, flags),
        }

        // Build the (possibly encoded) value.
        let pbytes = part.as_bytes();
        let mut enc: Vec<u8> = Vec::new();

        if leadingslash && at(pbytes, 0) != b'/' {
            enc.push(b'/');
        }

        if urlencode {
            for &i in pbytes {
                if i == b' ' && plusencode {
                    enc.push(b'+');
                } else if is_unreserved(i)
                    || (pathmode && allowed_in_path(i))
                    || (i == b'=' && equalsencode)
                {
                    if i == b'=' && equalsencode {
                        // Only the first equals sign is kept literally.
                        equalsencode = false;
                    }
                    enc.push(i);
                } else {
                    push_hex_upper(&mut enc, i);
                }
            }
        } else {
            enc.extend_from_slice(pbytes);
            // Normalize any percent-encoded triplets to lowercase hex.
            let mut j = 0;
            while j < enc.len() {
                if enc[j] == b'%'
                    && j + 2 < enc.len()
                    && enc[j + 1].is_ascii_hexdigit()
                    && enc[j + 2].is_ascii_hexdigit()
                    && (enc[j + 1].is_ascii_uppercase() || enc[j + 2].is_ascii_uppercase())
                {
                    enc[j + 1] = enc[j + 1].to_ascii_lowercase();
                    enc[j + 2] = enc[j + 2].to_ascii_lowercase();
                    j += 3;
                } else {
                    j += 1;
                }
            }
        }

        // curl treats a URL-encoded value that produced no bytes as a NULL
        // pointer (the dynamic buffer was never allocated); a non-encoded empty
        // value is a real empty string.
        let newp_is_null = urlencode && enc.is_empty();

        if appendquery && !newp_is_null {
            // Append onto any existing query, inserting '&' if needed.
            let querylen = self.query.as_deref().map_or(0, str::len);
            if querylen > 0 {
                let existing = self.query.as_deref().unwrap_or_default();
                let mut q = existing.as_bytes().to_vec();
                if !existing.ends_with('&') {
                    q.push(b'&');
                }
                q.extend_from_slice(&enc);
                self.query = Some(vec_to_string(q));
                return Ok(());
            }
            // With no existing query, fall through to a plain store.
        } else if matches!(store, StorePart::Host) {
            // Validate the hostname before storing it.
            let n = enc.len();
            if n == 0 && flags & NO_AUTHORITY != 0 {
                // Empty hostname explicitly allowed; skip the check.
            } else {
                let bad = if n == 0 {
                    true
                } else if !urlencode {
                    // The value was set already-encoded, so decode a copy to
                    // validate it (any zone-id side effect is preserved).
                    match escape::unescape(&enc, true) {
                        Ok(mut decoded) => self.hostname_check(&mut decoded).is_err(),
                        Err(_) => true,
                    }
                } else {
                    let mut tmp = enc.clone();
                    self.hostname_check(&mut tmp).is_err()
                };
                if bad {
                    return Err(CurlUCode::BadHostname);
                }
            }
        }

        let value: Option<String> = if newp_is_null {
            None
        } else {
            Some(vec_to_string(enc))
        };

        match store {
            StorePart::Scheme => self.scheme = value,
            StorePart::User => self.user = value,
            StorePart::Password => self.password = value,
            StorePart::Options => self.options = value,
            StorePart::Host => self.host = value,
            StorePart::ZoneId => self.zoneid = value,
            StorePart::Path => self.path = value,
            StorePart::Query => self.query = value,
            StorePart::Fragment => self.fragment = value,
        }
        Ok(())
    }
}

// ===========================================================================
// Convenience constructors and public API.
// ===========================================================================

impl Url {
    /// Parses a URL string into a new handle — the idiomatic Rust form of
    /// `curl_url()` followed by `curl_url_set(CURLUPART_URL, url, flags)`.
    ///
    /// # Errors
    ///
    /// Any parse [`CurlUCode`] (e.g. [`CurlUCode::BadScheme`],
    /// [`CurlUCode::NoHost`], [`CurlUCode::MalformedInput`]).
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::urlapi::{Url, CurlUPart};
    ///
    /// let u = Url::parse("http://user:pass@host:8080/p?q#f", 0).unwrap();
    /// assert_eq!(u.get(CurlUPart::Scheme, 0).unwrap(), "http");
    /// assert_eq!(u.get(CurlUPart::Host, 0).unwrap(), "host");
    /// assert_eq!(u.get(CurlUPart::Port, 0).unwrap(), "8080");
    /// assert_eq!(u.get(CurlUPart::Path, 0).unwrap(), "/p");
    /// ```
    pub fn parse(url: &str, flags: u32) -> UResult<Url> {
        let mut u = Url::new();
        u.set(CurlUPart::Url, Some(url), flags)?;
        Ok(u)
    }

    /// Returns a deep clone of this handle — the Rust form of `curl_url_dup`.
    ///
    /// Every owned component is duplicated; there is no shared state between the
    /// original and the copy. (Cleanup is automatic via [`Drop`], so there is no
    /// `curl_url_cleanup` to call.)
    #[must_use]
    pub fn dup(&self) -> Url {
        self.clone()
    }
}

/// Returns the human-readable message for a [`CurlUCode`], mirroring
/// `curl_url_strerror`.
///
/// This simply forwards to the canonical table in [`crate::error`], keeping the
/// URL-API error strings identical to curl 8.x.
#[must_use]
pub fn strerror(code: CurlUCode) -> &'static str {
    crate::error::url_strerror(code)
}

// ===========================================================================
// Unit tests.
//
// These transcribe representative cases from curl's own URL-API regression
// tests (`tests/unit/unit1560.c` a.k.a. `lib1560`, and the `Curl_parse_port`
// coverage in `unit1653.c`). They exercise: full-URL parsing and per-part
// extraction, the frozen `CURLUcode` integer ABI, scheme guessing and the
// supported-scheme gate (including the RTMP/RTMPS rejection mandated by the
// Agent Action Plan), per-component get/set round-trips, the `CURLU_*` flag
// behaviors, IPv6 + zone-id parsing, port validation, and `dup`.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CurlUCode;

    /// Renders the nine principal components exactly like lib1560's
    /// `checkparts`: `scheme | user | password | options | host | port |
    /// path | query | fragment`, substituting `[N]` (the integer `CURLUcode`)
    /// for any component that is reported missing.
    fn checkparts(u: &Url, flags: u32) -> String {
        const PARTS: [CurlUPart; 9] = [
            CurlUPart::Scheme,
            CurlUPart::User,
            CurlUPart::Password,
            CurlUPart::Options,
            CurlUPart::Host,
            CurlUPart::Port,
            CurlUPart::Path,
            CurlUPart::Query,
            CurlUPart::Fragment,
        ];
        PARTS
            .iter()
            .map(|&p| match u.get(p, flags) {
                Ok(s) => s,
                Err(e) => format!("[{}]", e as i32),
            })
            .collect::<Vec<_>>()
            .join(" | ")
    }

    /// The `CURLUcode` integers are a frozen ABI transcribed verbatim from
    /// `include/curl/urlapi.h`. A consumer hard-coding, e.g.,
    /// `CURLUE_NO_HOST == 14` must keep working.
    #[test]
    fn curlucode_integer_values_are_frozen_abi() {
        assert_eq!(CurlUCode::Ok as i32, 0);
        assert_eq!(CurlUCode::BadHandle as i32, 1);
        assert_eq!(CurlUCode::BadPartpointer as i32, 2);
        assert_eq!(CurlUCode::MalformedInput as i32, 3);
        assert_eq!(CurlUCode::BadPortNumber as i32, 4);
        assert_eq!(CurlUCode::UnsupportedScheme as i32, 5);
        assert_eq!(CurlUCode::Urldecode as i32, 6);
        assert_eq!(CurlUCode::OutOfMemory as i32, 7);
        assert_eq!(CurlUCode::UserNotAllowed as i32, 8);
        assert_eq!(CurlUCode::UnknownPart as i32, 9);
        assert_eq!(CurlUCode::NoScheme as i32, 10);
        assert_eq!(CurlUCode::NoUser as i32, 11);
        assert_eq!(CurlUCode::NoPassword as i32, 12);
        assert_eq!(CurlUCode::NoOptions as i32, 13);
        assert_eq!(CurlUCode::NoHost as i32, 14);
        assert_eq!(CurlUCode::NoPort as i32, 15);
        assert_eq!(CurlUCode::NoQuery as i32, 16);
        assert_eq!(CurlUCode::NoFragment as i32, 17);
        assert_eq!(CurlUCode::NoZoneid as i32, 18);
        assert_eq!(CurlUCode::BadFileUrl as i32, 19);
        assert_eq!(CurlUCode::BadFragment as i32, 20);
        assert_eq!(CurlUCode::BadHostname as i32, 21);
        assert_eq!(CurlUCode::BadIpv6 as i32, 22);
        assert_eq!(CurlUCode::BadLogin as i32, 23);
        assert_eq!(CurlUCode::BadPassword as i32, 24);
        assert_eq!(CurlUCode::BadPath as i32, 25);
        assert_eq!(CurlUCode::BadQuery as i32, 26);
        assert_eq!(CurlUCode::BadScheme as i32, 27);
        assert_eq!(CurlUCode::BadSlashes as i32, 28);
        assert_eq!(CurlUCode::BadUser as i32, 29);
        assert_eq!(CurlUCode::LacksIdn as i32, 30);
        assert_eq!(CurlUCode::TooLarge as i32, 31);
    }

    /// Parse a fully-populated URL and read every component back, then confirm
    /// the URL re-serializes byte-for-byte.
    #[test]
    fn parse_full_url_and_extract_every_part() {
        let u = Url::parse("http://user:pass@host:8080/p?q#f", 0).expect("parse");
        assert_eq!(u.get(CurlUPart::Scheme, 0).unwrap(), "http");
        assert_eq!(u.get(CurlUPart::User, 0).unwrap(), "user");
        assert_eq!(u.get(CurlUPart::Password, 0).unwrap(), "pass");
        assert_eq!(u.get(CurlUPart::Host, 0).unwrap(), "host");
        assert_eq!(u.get(CurlUPart::Port, 0).unwrap(), "8080");
        assert_eq!(u.get(CurlUPart::Path, 0).unwrap(), "/p");
        assert_eq!(u.get(CurlUPart::Query, 0).unwrap(), "q");
        assert_eq!(u.get(CurlUPart::Fragment, 0).unwrap(), "f");
        assert_eq!(
            u.get(CurlUPart::Url, 0).unwrap(),
            "http://user:pass@host:8080/p?q#f"
        );
    }

    /// Components that are genuinely absent report their specific "no-part"
    /// code; `path` is never missing (it defaults to `/`).
    #[test]
    fn missing_components_report_specific_codes() {
        let u = Url::parse("http://curl.se/", 0).expect("parse");
        assert_eq!(u.get(CurlUPart::User, 0).unwrap_err(), CurlUCode::NoUser);
        assert_eq!(
            u.get(CurlUPart::Password, 0).unwrap_err(),
            CurlUCode::NoPassword
        );
        assert_eq!(
            u.get(CurlUPart::Options, 0).unwrap_err(),
            CurlUCode::NoOptions
        );
        assert_eq!(u.get(CurlUPart::Port, 0).unwrap_err(), CurlUCode::NoPort);
        assert_eq!(u.get(CurlUPart::Query, 0).unwrap_err(), CurlUCode::NoQuery);
        assert_eq!(
            u.get(CurlUPart::Fragment, 0).unwrap_err(),
            CurlUCode::NoFragment
        );
        // Path always resolves, defaulting to "/".
        assert_eq!(u.get(CurlUPart::Path, 0).unwrap(), "/");
    }

    /// Scheme guessing (`CURLU_GUESS_SCHEME`) and the lib1560 rule that a
    /// *guessed* scheme is withheld when read back with
    /// `CURLU_NO_GUESS_SCHEME` (yielding `CURLUE_NO_SCHEME`, i.e. `[10]`).
    #[test]
    fn guessed_scheme_is_hidden_under_no_guess_flag() {
        let u = Url::parse("curl.se", GUESS_SCHEME).expect("guess parse");
        // Without the flag the guessed scheme is visible.
        assert_eq!(u.get(CurlUPart::Scheme, 0).unwrap(), "http");
        assert_eq!(u.get(CurlUPart::Host, 0).unwrap(), "curl.se");
        // With NO_GUESS_SCHEME the guessed scheme is suppressed.
        assert_eq!(
            checkparts(&u, NO_GUESS_SCHEME),
            "[10] | [11] | [12] | [13] | curl.se | [15] | / | [16] | [17]"
        );
    }

    /// Scheme guessing from a recognizable host prefix (`ftp.` -> `ftp`).
    #[test]
    fn guess_scheme_from_host_prefix() {
        let u = Url::parse("ftp.example.com/dir/", GUESS_SCHEME).expect("guess ftp");
        assert_eq!(u.get(CurlUPart::Scheme, 0).unwrap(), "ftp");
        assert_eq!(u.get(CurlUPart::Host, 0).unwrap(), "ftp.example.com");
    }

    /// The Agent Action Plan mandates that RTMP/RTMPS are dropped: they must
    /// not be accepted as supported schemes. Every RTMP variant is rejected
    /// with `CURLUE_UNSUPPORTED_SCHEME`, while a supported scheme (`http`)
    /// parses cleanly.
    #[test]
    fn rtmp_family_schemes_are_rejected() {
        for s in [
            "rtmp://example.com/live",
            "rtmpe://example.com/live",
            "rtmpt://example.com/live",
            "rtmpte://example.com/live",
            "rtmps://example.com/live",
            "rtmpts://example.com/live",
        ] {
            assert_eq!(
                Url::parse(s, 0).unwrap_err(),
                CurlUCode::UnsupportedScheme,
                "RTMP variant must be rejected: {s}"
            );
        }
        // Control: a supported scheme still works.
        assert!(Url::parse("http://example.com/", 0).is_ok());
    }

    /// With `CURLU_NON_SUPPORT_SCHEME` an otherwise-unknown but syntactically
    /// valid scheme (including `rtmp`) is accepted verbatim — this proves the
    /// rejection above is exactly the supported-scheme gate, matching curl.
    #[test]
    fn non_support_scheme_flag_allows_unknown_schemes() {
        let u = Url::parse("rtmp://example.com/live", NON_SUPPORT_SCHEME).expect("non-support");
        assert_eq!(u.get(CurlUPart::Scheme, 0).unwrap(), "rtmp");
        assert_eq!(u.get(CurlUPart::Host, 0).unwrap(), "example.com");
    }

    /// Build a URL from scratch with per-component `set` and confirm it
    /// serializes correctly.
    #[test]
    fn set_components_and_serialize() {
        let mut u = Url::new();
        u.set(CurlUPart::Scheme, Some("http"), 0).unwrap();
        u.set(CurlUPart::Host, Some("example.com"), 0).unwrap();
        u.set(CurlUPart::Path, Some("/a/b"), 0).unwrap();
        assert_eq!(u.get(CurlUPart::Scheme, 0).unwrap(), "http");
        assert_eq!(u.get(CurlUPart::Host, 0).unwrap(), "example.com");
        assert_eq!(u.get(CurlUPart::Path, 0).unwrap(), "/a/b");
        assert_eq!(u.get(CurlUPart::Url, 0).unwrap(), "http://example.com/a/b");
    }

    /// `CURLU_APPENDQUERY` concatenates onto an existing query with a `&`.
    #[test]
    fn append_query_joins_with_ampersand() {
        let mut u = Url::parse("http://example.com/?a=1", 0).expect("parse");
        u.set(CurlUPart::Query, Some("b=2"), APPENDQUERY).unwrap();
        assert_eq!(u.get(CurlUPart::Query, 0).unwrap(), "a=1&b=2");
    }

    /// `CURLU_URLENCODE` on the query encodes spaces as `+` (curl's query
    /// convention), while on the path it encodes spaces as `%20`.
    #[test]
    fn urlencode_flag_encodes_query_and_path_differently() {
        let mut q = Url::new();
        q.set(CurlUPart::Scheme, Some("http"), 0).unwrap();
        q.set(CurlUPart::Host, Some("example.com"), 0).unwrap();
        q.set(CurlUPart::Query, Some("hello world"), URLENCODE)
            .unwrap();
        assert_eq!(q.get(CurlUPart::Query, 0).unwrap(), "hello+world");

        let mut p = Url::new();
        p.set(CurlUPart::Scheme, Some("http"), 0).unwrap();
        p.set(CurlUPart::Host, Some("example.com"), 0).unwrap();
        p.set(CurlUPart::Path, Some("/a b/c"), URLENCODE).unwrap();
        assert_eq!(p.get(CurlUPart::Path, 0).unwrap(), "/a%20b/c");
    }

    /// `CURLU_URLDECODE` decodes percent-escapes when reading a component.
    #[test]
    fn urldecode_flag_decodes_on_get() {
        let u = Url::parse("http://example.com/a%20b?x%3Dy", 0).expect("parse");
        assert_eq!(u.get(CurlUPart::Path, URLDECODE).unwrap(), "/a b");
        assert_eq!(u.get(CurlUPart::Query, URLDECODE).unwrap(), "x=y");
        // Without the flag the escapes are preserved verbatim.
        assert_eq!(u.get(CurlUPart::Path, 0).unwrap(), "/a%20b");
    }

    /// `CURLU_DISALLOW_USER` rejects a URL that carries userinfo.
    #[test]
    fn disallow_user_rejects_userinfo() {
        assert_eq!(
            Url::parse("http://user@example.com/", DISALLOW_USER).unwrap_err(),
            CurlUCode::UserNotAllowed
        );
    }

    /// A `file:` URL has no host component (lib1560: `file:/hello.html` yields
    /// `[14]` for the host) and preserves the path.
    #[test]
    fn file_url_has_no_host() {
        let u = Url::parse("file:/hello.html", 0).expect("parse file");
        assert_eq!(u.get(CurlUPart::Path, 0).unwrap(), "/hello.html");
        assert_eq!(u.get(CurlUPart::Host, 0).unwrap_err(), CurlUCode::NoHost);
    }

    /// Port 0 is a legal port; the parser accepts it and echoes it back.
    #[test]
    fn port_zero_is_accepted() {
        let u = Url::parse("http://host:0/", 0).expect("parse");
        assert_eq!(u.get(CurlUPart::Port, 0).unwrap(), "0");
    }

    /// `Curl_parse_port` coverage (unit1653): the boundary value 65535 is
    /// accepted while 65536 and non-numeric input are rejected with
    /// `CURLUE_BAD_PORT_NUMBER`.
    #[test]
    fn set_port_validates_range() {
        let mut u = Url::new();
        u.set(CurlUPart::Scheme, Some("http"), 0).unwrap();
        u.set(CurlUPart::Host, Some("example.com"), 0).unwrap();

        u.set(CurlUPart::Port, Some("0"), 0).expect("0 ok");
        u.set(CurlUPart::Port, Some("65535"), 0).expect("65535 ok");
        assert_eq!(u.get(CurlUPart::Port, 0).unwrap(), "65535");

        assert_eq!(
            u.set(CurlUPart::Port, Some("65536"), 0).unwrap_err(),
            CurlUCode::BadPortNumber
        );
        assert_eq!(
            u.set(CurlUPart::Port, Some("12x"), 0).unwrap_err(),
            CurlUCode::BadPortNumber
        );
    }

    /// IPv6 literal with a URL-encoded zone id (`%25` -> `%`): the address is
    /// canonicalized and bracketed, the zone id is captured separately, and
    /// the explicit port is retained.
    #[test]
    fn ipv6_literal_with_zone_id_and_port() {
        let u = Url::parse("http://[fe80::1%25eth0]:8080/path", 0).expect("parse v6");
        assert_eq!(u.get(CurlUPart::Host, 0).unwrap(), "[fe80::1]");
        assert_eq!(u.get(CurlUPart::ZoneId, 0).unwrap(), "eth0");
        assert_eq!(u.get(CurlUPart::Port, 0).unwrap(), "8080");
    }

    /// A malformed IPv6 literal is rejected with `CURLUE_BAD_IPV6`.
    #[test]
    fn malformed_ipv6_is_rejected() {
        assert_eq!(
            Url::parse("http://[fe80::1::2]/", 0).unwrap_err(),
            CurlUCode::BadIpv6
        );
    }

    /// A scheme beginning with a digit is not a valid absolute URL; with
    /// `CURLU_NON_SUPPORT_SCHEME` (so the unsupported-scheme gate is bypassed)
    /// it is reported as `CURLUE_BAD_SCHEME` (lib1560).
    #[test]
    fn scheme_with_leading_digit_is_bad_scheme() {
        assert_eq!(
            Url::parse("1h://example.net", NON_SUPPORT_SCHEME).unwrap_err(),
            CurlUCode::BadScheme
        );
    }

    /// Empty or whitespace-only input is malformed.
    #[test]
    fn empty_or_space_input_is_malformed() {
        assert_eq!(Url::parse("", 0).unwrap_err(), CurlUCode::MalformedInput);
        assert_eq!(Url::parse(" ", 0).unwrap_err(), CurlUCode::MalformedInput);
    }

    /// `dup` produces an independent deep copy: mutating the clone leaves the
    /// original untouched.
    #[test]
    fn dup_is_an_independent_deep_copy() {
        let original = Url::parse("http://user@host:9000/p?q#f", 0).expect("parse");
        let mut clone = original.dup();
        assert_eq!(
            clone.get(CurlUPart::Url, 0).unwrap(),
            original.get(CurlUPart::Url, 0).unwrap()
        );
        // Mutate the clone; the original must be unaffected.
        clone.set(CurlUPart::Fragment, Some("changed"), 0).unwrap();
        assert_eq!(clone.get(CurlUPart::Fragment, 0).unwrap(), "changed");
        assert_eq!(original.get(CurlUPart::Fragment, 0).unwrap(), "f");
    }

    /// `strerror` returns a non-empty, stable message for each code.
    #[test]
    fn strerror_returns_messages() {
        assert!(!strerror(CurlUCode::Ok).is_empty());
        assert!(!strerror(CurlUCode::NoHost).is_empty());
        assert!(!strerror(CurlUCode::BadPortNumber).is_empty());
    }

    /// imap parses `;option` in the login as options; a plain http login does
    /// not treat `;option` specially (it becomes part of the password).
    #[test]
    fn login_options_are_scheme_specific() {
        let imap =
            Url::parse("imap://user:pass;cram-md5@mail.example.com/INBOX", 0).expect("imap parse");
        assert_eq!(imap.get(CurlUPart::User, 0).unwrap(), "user");
        assert_eq!(imap.get(CurlUPart::Password, 0).unwrap(), "pass");
        assert_eq!(imap.get(CurlUPart::Options, 0).unwrap(), "cram-md5");

        let http = Url::parse("http://user:pass;cram-md5@www.example.com/", 0).expect("http parse");
        assert_eq!(http.get(CurlUPart::User, 0).unwrap(), "user");
        assert_eq!(http.get(CurlUPart::Password, 0).unwrap(), "pass;cram-md5");
        assert_eq!(
            http.get(CurlUPart::Options, 0).unwrap_err(),
            CurlUCode::NoOptions
        );
    }
}
