//! URL parsing, building, normalization, and the URL-API handle (`CURLU`).
//!
//! This module is the memory-safe Rust reimplementation of libcurl's URL
//! handling. Its behavioral/ABI oracle is `lib/urlapi.c` (the public URL-API)
//! together with the URL-parsing and scheme/default-port tables of `lib/url.c`
//! and the internal struct shape in `lib/urlapi-int.h`. It owns two concerns:
//!
//! 1. **The public URL-API** — [`CurlUrl`], a handle that maps 1:1 onto curl's
//!    opaque `CURLU`. The six public entry points
//!    (`curl_url`, `curl_url_set`, `curl_url_get`, `curl_url_dup`,
//!    `curl_url_cleanup`, `curl_url_strerror`) are surfaced here as
//!    [`CurlUrl::new`], [`CurlUrl::set`], [`CurlUrl::get`], [`Clone`]/
//!    [`CurlUrl::dup`], [`Drop`], and [`CurlUrl::strerror`]. The
//!    `curl-rs-ffi` crate boxes a [`CurlUrl`] behind a raw `CURLU*` and routes
//!    the C symbols to these methods.
//! 2. **Internal normalization for the engine** — [`CurlUrl::to_request_parts`]
//!    yields a [`ParsedUrl`] (scheme/host/port/path/...) ready for `crate::conn`
//!    and `crate::protocols` to consume, and [`CurlUrl::resolve`] performs the
//!    relative→absolute redirect resolution used by `crate::transfer` /
//!    `crate::protocols::http`.
//!
//! Connection bring-up and connection-cache lookup (the `Curl_connect` side of
//! `lib/url.c`) deliberately live in `crate::conn`; this module stops at
//! producing a fully parsed, normalized URL.
//!
//! # Parity: curl's bespoke parser vs. the WHATWG `url` crate
//!
//! URL parsing is one of the most heavily test-covered areas of curl, and the
//! externally observable result **must match curl's own parser byte-for-byte**
//! — *not* the WHATWG URL Standard implemented by the `url` crate. curl's
//! parser predates and intentionally diverges from WHATWG in many places.
//! Because every divergence must resolve in curl's favor, this module ports
//! curl's algorithm directly and uses the workspace's encoding/IDN substrate as
//! building blocks rather than delegating parsing to `url::Url`:
//!
//! * **Percent-encoding/decoding** is delegated to [`crate::escape`] (which
//!   wraps the `percent-encoding` crate) so the unreserved set and uppercase
//!   `%XX` output match curl's `lib/escape.c` exactly.
//! * **IDN/Punycode** is delegated to [`crate::idn`] (which wraps the `idna`
//!   crate) for the `CURLU_PUNYCODE` / `CURLU_PUNY2IDN` get flags and for
//!   producing a wire-ready host in [`CurlUrl::to_request_parts`].
//! * **IP-literal normalization** uses [`std::net::Ipv4Addr`] /
//!   [`std::net::Ipv6Addr`] (the equivalent of curl's `inet_pton`/`inet_ntop`).
//!
//! The concrete curl-vs-WHATWG divergences reproduced here (curl wins each):
//!
//! | Behavior | curl (reproduced here) | WHATWG `url` crate |
//! |----------|------------------------|--------------------|
//! | Host case | preserved verbatim | lowercased |
//! | Scheme set | curl scheme list + default-port table; `https` is the default scheme | special-scheme set |
//! | Unknown scheme | rejected unless `CURLU_NON_SUPPORT_SCHEME` | accepted as opaque |
//! | Missing scheme | error unless `CURLU_DEFAULT_SCHEME`/`CURLU_GUESS_SCHEME` | requires a base |
//! | Legacy guessing | `ftp.`/`imap.`/… host prefixes pick a scheme | none |
//! | Slashes after scheme | 1–3 accepted (`http:/x`), else `CURLU_BAD_SLASHES` | exactly `//` |
//! | `%2e`/`%2E` in path | treated as a dot segment by remove-dot-segments | left encoded |
//! | `+` on decode | left as `+` (only `application/x-www-form-urlencoded` query get maps it) | left as `+` |
//! | IPv4 shorthand | `0x7f`, `0177`, `1.2`, `16843009` normalized to dotted quad | rejected/different |
//! | `file:` host | only empty/`localhost`/`127.0.0.1` allowed (non-Windows) | broader |
//! | Empty authority | allowed only with `CURLU_NO_AUTHORITY` for unknown schemes | scheme-dependent |
//!
//! One pragmatic, documented divergence from the C oracle itself: curl stores
//! components as raw `char*` byte strings, whereas this module stores them as
//! owned [`String`]s (per the workspace's typed model). A percent-encoded host
//! that decodes to a non-UTF-8 byte sequence — which is never resolvable and
//! which curl would reject downstream anyway — is rejected here at parse time
//! with [`CurlUError::BadHostname`] instead of being stored as raw bytes.
//!
//! # Memory safety
//!
//! This module contains **zero** `unsafe` and compiles cleanly under its own
//! `#![forbid(unsafe_code)]` (and the crate-root forbid). All allocation,
//! growth, and teardown is handled by [`String`]/[`Vec`] and deterministic
//! [`Drop`]; the `Box`↔`CURLU*` raw-pointer conversion happens only in
//! `curl-rs-ffi`.

#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{CurlError, CurlUError};
use crate::escape::{self, UrlReject};
use crate::idn;

/// Result alias for the URL API: success or a [`CurlUError`] (`CURLUcode`).
type UResult<T> = core::result::Result<T, CurlUError>;

/// Maximum accepted input length, mirroring curl's `CURL_MAX_INPUT_LENGTH`
/// (`lib/urldata.h`). Inputs longer than this are rejected as malformed.
const CURL_MAX_INPUT_LENGTH: usize = 8_000_000;

/// Longest libcurl-supported scheme name, mirroring curl's `MAX_SCHEME_LEN`
/// (`lib/urlapi.c`). A scheme may be at most this many bytes.
const MAX_SCHEME_LEN: usize = 40;

/// The scheme curl falls back to for [`CURLU_DEFAULT_SCHEME`], mirroring curl's
/// `DEFAULT_SCHEME` (`lib/urlapi.c`).
const DEFAULT_SCHEME: &str = "https";

// ============================================================================
// CURLU_* flags — bit flags shared by `set` and `get`
// (mirrors the `#define CURLU_*` values in include/curl/urlapi.h)
// ============================================================================

/// Return the default port number for the scheme if none is set.
pub const CURLU_DEFAULT_PORT: u32 = 1 << 0;
/// Act as if no port number was set when it matches the scheme default.
pub const CURLU_NO_DEFAULT_PORT: u32 = 1 << 1;
/// Return (or assume) the default scheme (`https`) when the scheme is missing.
pub const CURLU_DEFAULT_SCHEME: u32 = 1 << 2;
/// Allow a non-supported scheme.
pub const CURLU_NON_SUPPORT_SCHEME: u32 = 1 << 3;
/// Leave `.`/`..` dot sequences in the path untouched.
pub const CURLU_PATH_AS_IS: u32 = 1 << 4;
/// Disallow user+password in the URL.
pub const CURLU_DISALLOW_USER: u32 = 1 << 5;
/// URL-decode the component when getting it.
pub const CURLU_URLDECODE: u32 = 1 << 6;
/// URL-encode the component when setting (or getting) it.
pub const CURLU_URLENCODE: u32 = 1 << 7;
/// Append a form-style part to the existing query (`set(QUERY, …)`).
pub const CURLU_APPENDQUERY: u32 = 1 << 8;
/// Legacy curl-style scheme guessing from the hostname prefix.
pub const CURLU_GUESS_SCHEME: u32 = 1 << 9;
/// Allow an empty authority when the scheme is unknown.
pub const CURLU_NO_AUTHORITY: u32 = 1 << 10;
/// Allow spaces in the URL.
pub const CURLU_ALLOW_SPACE: u32 = 1 << 11;
/// Get the hostname in Punycode (ACE) form.
pub const CURLU_PUNYCODE: u32 = 1 << 12;
/// Convert a Punycode hostname back to its IDN (Unicode) form on get.
pub const CURLU_PUNY2IDN: u32 = 1 << 13;
/// Allow empty queries and fragments when extracting the URL or components.
pub const CURLU_GET_EMPTY: u32 = 1 << 14;
/// For get, do not accept a guessed scheme.
pub const CURLU_NO_GUESS_SCHEME: u32 = 1 << 15;

/// A component (`CURLUPart`) of a URL, addressable through
/// [`CurlUrl::get`]/[`CurlUrl::set`].
///
/// Discriminants follow `include/curl/urlapi.h`'s `CURLUPart` enumeration so
/// the FFI crate can map the C integer 1:1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurlUPart {
    /// The whole URL (`CURLUPART_URL`).
    Url = 0,
    /// The scheme (`CURLUPART_SCHEME`).
    Scheme = 1,
    /// The user name (`CURLUPART_USER`).
    User = 2,
    /// The password (`CURLUPART_PASSWORD`).
    Password = 3,
    /// The options (`CURLUPART_OPTIONS`, used by IMAP/POP3/SMTP).
    Options = 4,
    /// The host (`CURLUPART_HOST`).
    Host = 5,
    /// The port (`CURLUPART_PORT`).
    Port = 6,
    /// The path (`CURLUPART_PATH`).
    Path = 7,
    /// The query (`CURLUPART_QUERY`).
    Query = 8,
    /// The fragment (`CURLUPART_FRAGMENT`).
    Fragment = 9,
    /// The IPv6 zone id (`CURLUPART_ZONEID`).
    ZoneId = 10,
}

// ============================================================================
// Scheme table — name → default port (+ whether the scheme carries URL options)
// (mirrors the `Curl_scheme_*` handler structs and `Curl_get_scheme` in
//  lib/url.c / the per-protocol .c files, restricted to the in-scope default
//  build; the out-of-scope RTMP family is intentionally omitted, so an
//  `rtmp*` scheme is treated as unsupported unless CURLU_NON_SUPPORT_SCHEME.)
// ============================================================================

/// Static metadata for a known URL scheme.
struct SchemeInfo {
    /// Lowercase scheme name.
    name: &'static str,
    /// Default port for the scheme (`0` for schemes without a network port,
    /// e.g. `file`).
    defport: u16,
    /// Whether the scheme accepts URL `;options` (curl's `PROTOPT_URLOPTIONS`,
    /// set only on the IMAP/POP3/SMTP families).
    urloptions: bool,
}

/// The known-scheme table. Mirrors curl's default build: every scheme here has
/// a working handler (curl's `h->run != NULL`), so it is accepted by
/// `set(SCHEME, …)` without `CURLU_NON_SUPPORT_SCHEME`.
///
/// `#[rustfmt::skip]` keeps this an aligned, one-row-per-scheme lookup table
/// (the natural shape for a port/flag map); the rest of the module is plain
/// `rustfmt`-clean.
#[rustfmt::skip]
const SCHEMES: &[SchemeInfo] = &[
    SchemeInfo { name: "http", defport: 80, urloptions: false },
    SchemeInfo { name: "https", defport: 443, urloptions: false },
    SchemeInfo { name: "ftp", defport: 21, urloptions: false },
    SchemeInfo { name: "ftps", defport: 990, urloptions: false },
    SchemeInfo { name: "sftp", defport: 22, urloptions: false },
    SchemeInfo { name: "scp", defport: 22, urloptions: false },
    SchemeInfo { name: "imap", defport: 143, urloptions: true },
    SchemeInfo { name: "imaps", defport: 993, urloptions: true },
    SchemeInfo { name: "pop3", defport: 110, urloptions: true },
    SchemeInfo { name: "pop3s", defport: 995, urloptions: true },
    SchemeInfo { name: "smtp", defport: 25, urloptions: true },
    SchemeInfo { name: "smtps", defport: 465, urloptions: true },
    SchemeInfo { name: "telnet", defport: 23, urloptions: false },
    SchemeInfo { name: "tftp", defport: 69, urloptions: false },
    SchemeInfo { name: "dict", defport: 2628, urloptions: false },
    SchemeInfo { name: "ldap", defport: 389, urloptions: false },
    SchemeInfo { name: "ldaps", defport: 636, urloptions: false },
    SchemeInfo { name: "gopher", defport: 70, urloptions: false },
    SchemeInfo { name: "gophers", defport: 70, urloptions: false },
    SchemeInfo { name: "smb", defport: 445, urloptions: false },
    SchemeInfo { name: "smbs", defport: 445, urloptions: false },
    SchemeInfo { name: "rtsp", defport: 554, urloptions: false },
    SchemeInfo { name: "mqtt", defport: 1883, urloptions: false },
    SchemeInfo { name: "mqtts", defport: 8883, urloptions: false },
    SchemeInfo { name: "ws", defport: 80, urloptions: false },
    SchemeInfo { name: "wss", defport: 443, urloptions: false },
    SchemeInfo { name: "file", defport: 0, urloptions: false },
];

/// Looks up a scheme by name, case-insensitively (curl scheme names are stored
/// lowercase and compared with `curl_strnequal`). Returns `None` for an unknown
/// scheme. This is the equivalent of curl's `Curl_get_scheme`.
fn get_scheme(scheme: &str) -> Option<&'static SchemeInfo> {
    SCHEMES.iter().find(|s| scheme.eq_ignore_ascii_case(s.name))
}

// ============================================================================
// CurlUrl — the URL-API handle (CURLU)
// ============================================================================

/// A parsed URL handle, the memory-safe equivalent of curl's opaque `CURLU`
/// (`struct Curl_URL` in `lib/urlapi.c`).
///
/// Each component is stored in its **URL-encoded** form (matching the C
/// struct's "Point to URL-encoded strings" contract), except the host which is
/// stored decoded — exactly as curl's `parse_authority` leaves it. `None` means
/// the component is absent; the `*_present` flags distinguish an absent query
/// or fragment from a present-but-empty one (`?`/`#` with nothing after).
///
/// Construct one with [`CurlUrl::new`], populate it with [`CurlUrl::set`], and
/// read components back with [`CurlUrl::get`]. The handle is freely
/// [`Clone`]able ([`CurlUrl::dup`] is the `curl_url_dup` alias) and is cleaned
/// up by ordinary [`Drop`] (the `curl_url_cleanup` equivalent).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CurlUrl {
    /// Scheme, lowercased (e.g. `"https"`). `None` if unset.
    scheme: Option<String>,
    /// User name (URL-encoded). `None` if unset.
    user: Option<String>,
    /// Password (URL-encoded). `None` if unset.
    password: Option<String>,
    /// URL `;options` (IMAP/POP3/SMTP). `None` if unset.
    options: Option<String>,
    /// Host, decoded; IPv6 literals keep their surrounding brackets. `None` if
    /// unset.
    host: Option<String>,
    /// IPv6 zone id (the part after `%`). `None` if unset.
    zoneid: Option<String>,
    /// Port as a normalized decimal string (leading zeros stripped). `None` if
    /// unset.
    port: Option<String>,
    /// Path (URL-encoded). `None` means "no path", which renders as `/`.
    path: Option<String>,
    /// Query (URL-encoded), without the leading `?`. `None` if unset; see
    /// [`CurlUrl::query_present`].
    query: Option<String>,
    /// Fragment (URL-encoded), without the leading `#`. `None` if unset; see
    /// [`CurlUrl::fragment_present`].
    fragment: Option<String>,
    /// Numeric form of [`Self::port`] (`0` when no port is set).
    portnum: u16,
    /// Whether a query was present in the input (supports a blank `?`).
    query_present: bool,
    /// Whether a fragment was present in the input (supports a blank `#`).
    fragment_present: bool,
    /// Whether the scheme was guessed (no scheme in the input).
    guessed_scheme: bool,
}

/// The normalized request components consumed by the connection and protocol
/// layers (`crate::conn`, `crate::protocols`).
///
/// Produced by [`CurlUrl::to_request_parts`]. The host is wire-ready (IDN names
/// have been converted to ACE), the port is resolved to the scheme default when
/// the URL carried no explicit port, and the path is never empty (defaulting to
/// `"/"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUrl {
    /// Lowercase scheme (e.g. `"https"`).
    pub scheme: String,
    /// Wire-ready host (ASCII/ACE for IDN names); IPv6 literals keep brackets.
    pub host: String,
    /// Resolved port (explicit value, or the scheme default).
    pub port: u16,
    /// User name, if any (still URL-encoded as stored).
    pub user: Option<String>,
    /// Password, if any (still URL-encoded as stored).
    pub password: Option<String>,
    /// URL `;options`, if any.
    pub options: Option<String>,
    /// IPv6 zone id, if any.
    pub zoneid: Option<String>,
    /// Path, always at least `"/"` (URL-encoded as stored).
    pub path: String,
    /// Query without the leading `?`, if present.
    pub query: Option<String>,
    /// Fragment without the leading `#`, if present.
    pub fragment: Option<String>,
}

impl CurlUrl {
    /// Creates a new, empty URL handle — the equivalent of `curl_url()`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Duplicates the handle — the equivalent of `curl_url_dup()`.
    ///
    /// A deep copy of every owned component plus `portnum` and the
    /// query/fragment "present" bits.
    ///
    /// Faithful-parity note: curl's `curl_url_dup` copies all of the above but
    /// **not** the `guessed_scheme` bit, so a duplicated handle renders its
    /// `scheme://` prefix even under `CURLU_NO_GUESS_SCHEME` where the original
    /// would have suppressed it. We reproduce that exactly here. (The derived
    /// [`Clone`] performs an exact field-for-field copy and is used internally;
    /// the public `curl_url_dup` semantics live here in [`dup`](Self::dup).)
    #[must_use]
    pub fn dup(&self) -> Self {
        let mut u = self.clone();
        u.guessed_scheme = false;
        u
    }

    /// Returns the human-readable description for a [`CurlUError`] — the
    /// equivalent of `curl_url_strerror()`.
    ///
    /// The text is owned by [`crate::error`] and matches curl's
    /// `lib/strerror.c` strings verbatim.
    #[must_use]
    pub fn strerror(code: CurlUError) -> &'static str {
        code.description()
    }
}

// ============================================================================
// Parsing helpers — direct ports of the static functions in lib/urlapi.c.
// These operate on `&str`/`&[u8]` and never allocate raw pointers, so the whole
// module stays inside `#![forbid(unsafe_code)]`.
// ============================================================================

/// Uppercase hex digits, mirroring curl's `Curl_udigits` used by
/// `Curl_hexbyte` (curl emits **uppercase** `%XX`).
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Classification of a host literal, mirroring curl's `ipv4_normalize` return
/// codes (`HOST_NAME` / `HOST_IPV4` / `HOST_IPV6`). The out-of-memory
/// `HOST_ERROR` case cannot occur in safe Rust and is therefore omitted.
enum HostKind {
    /// A regular registered name (DNS host); left for `hostname_check`.
    Name,
    /// A normalized IPv4 dotted quad (e.g. `0x7f000001` → `127.0.0.1`).
    Ipv4(String),
    /// An IPv6 literal (`[...]`); normalized by [`ipv6_parse`].
    Ipv6,
}

/// Rejects control bytes and over-long input, returning the input length on
/// success. The equivalent of curl's `Curl_junkscan`.
///
/// curl rejects any byte `<= 0x1f` (or `<= 0x20` when `CURLU_ALLOW_SPACE` is
/// not set) and the DEL byte `0x7f`, plus inputs longer than
/// `CURL_MAX_INPUT_LENGTH`. High bytes (`>= 0x80`) are allowed so IDN names
/// survive to the host-parsing stage.
fn junkscan(url: &str, allow_space: bool) -> UResult<usize> {
    let len = url.len();
    if len > CURL_MAX_INPUT_LENGTH {
        return Err(CurlUError::MalformedInput);
    }
    let ceiling: u8 = if allow_space { 0x1f } else { 0x20 };
    if url.bytes().any(|c| c <= ceiling || c == 0x7f) {
        return Err(CurlUError::MalformedInput);
    }
    Ok(len)
}

/// Detects an absolute-URL scheme prefix, returning `(scheme_len, lowercased
/// scheme)`. A `scheme_len` of `0` means the input is not absolute. The
/// equivalent of curl's `Curl_is_absolute_url`.
///
/// A scheme is `ALPHA *( ALNUM / "+" / "-" / "." )` followed by `:`. In
/// guess/default mode curl additionally requires the `:` to be followed by `/`
/// (otherwise a bare `host:port` would be misread as `scheme:opaque`).
pub(crate) fn is_absolute_url(url: &str, guessing: bool) -> (usize, Option<String>) {
    let b = url.as_bytes();
    let mut i = 0usize;
    if b.first().is_some_and(u8::is_ascii_alphabetic) {
        i = 1;
        while i < MAX_SCHEME_LEN {
            match b.get(i) {
                Some(&c) if c.is_ascii_alphanumeric() || c == b'+' || c == b'-' || c == b'.' => {
                    i += 1;
                }
                _ => break,
            }
        }
    }
    let at_colon = b.get(i) == Some(&b':');
    let next_slash = b.get(i + 1) == Some(&b'/');
    if i != 0 && at_colon && (next_slash || !guessing) {
        (i, Some(url[..i].to_ascii_lowercase()))
    } else {
        (0, None)
    }
}

/// Finds the byte offset at which the path/query begins, skipping the
/// `//`-introduced authority. The equivalent of curl's `find_host_sep`, used
/// only by [`urlencode_str`] in non-relative (redirect) mode.
fn find_host_sep(url: &str) -> usize {
    let bytes = url.as_bytes();
    let mut sep = match url.find("//") {
        Some(p) => p + 2,
        None => 0,
    };
    while sep < bytes.len() && bytes[sep] != b'/' && bytes[sep] != b'?' {
        sep += 1;
    }
    sep
}

/// URL-encodes a fragment of a URL exactly as curl's `urlencode_str` does:
/// only spaces, control bytes (`< 0x20`), and high bytes (`>= 0x7f`) are
/// percent-encoded (uppercase `%XX`); a space becomes `+` once a query context
/// is in effect and `%20` otherwise. Every other byte is passed through
/// verbatim — curl does **not** encode general reserved punctuation here.
///
/// When `relative` is false (the protocol-relative redirect case) the leading
/// authority is emitted unchanged and only the path/query tail is encoded,
/// matching curl's `find_host_sep` handling.
fn urlencode_str(input: &str, relative: bool, query: bool) -> String {
    if relative {
        return urlencode_bytes(input.as_bytes(), query);
    }
    // Non-relative (protocol-relative redirect): emit the authority as-is and
    // encode only the path/query tail. The leading bytes do not affect the
    // space-mapping state, so the tail can be encoded independently with the
    // same initial `query` context.
    let host_sep = find_host_sep(input);
    let mut out = String::with_capacity(input.len() + 8);
    out.push_str(&input[..host_sep]);
    out.push_str(&urlencode_bytes(&input.as_bytes()[host_sep..], query));
    out
}

/// The byte-oriented core of [`urlencode_str`] for the relative case (no
/// authority skipping). Spaces become `+` once a query context is active, else
/// `%20`; control and high bytes become uppercase `%XX`; everything else passes
/// through. Encountering `?` switches the space mapping to `+` (curl's
/// behavior when a path and query are encoded together).
fn urlencode_bytes(input: &[u8], query: bool) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    let mut left = !query;
    for &b in input {
        if b == b' ' {
            out.push_str(if left { "%20" } else { "+" });
        } else if !(0x20..0x7f).contains(&b) {
            // Control bytes (< 0x20) and high/DEL bytes (>= 0x7f) are escaped.
            out.push('%');
            out.push(char::from(HEX_UPPER[(b >> 4) as usize]));
            out.push(char::from(HEX_UPPER[(b & 0x0f) as usize]));
        } else {
            out.push(char::from(b));
            if b == b'?' {
                left = false;
            }
        }
    }
    out
}

/// Splits a `user:password;options` login string into its parts. The
/// equivalent of curl's `Curl_parse_login_details`.
///
/// `options` are only recognized when `parse_options` is true (curl only does
/// so for schemes carrying `PROTOPT_URLOPTIONS`: IMAP/POP3/SMTP). The user part
/// is always returned (possibly empty), matching curl's always-non-NULL `ubuf`.
fn parse_login_details(
    login: &str,
    parse_options: bool,
) -> (Option<String>, Option<String>, Option<String>) {
    let bytes = login.as_bytes();
    let len = bytes.len();
    let psep = bytes.iter().position(|&b| b == b':');
    let osep = if parse_options {
        bytes.iter().position(|&b| b == b';')
    } else {
        None
    };

    // User length runs to the first separator that actually precedes it.
    let ulen = match (psep, osep) {
        (Some(p), Some(o)) => p.min(o),
        (Some(p), None) => p,
        (None, Some(o)) => o,
        (None, None) => len,
    };
    let user = Some(login[..ulen].to_string());

    let password = psep.map(|p| {
        let end = match osep {
            Some(o) if o > p => o,
            _ => len,
        };
        login[p + 1..end].to_string()
    });

    let options = osep.and_then(|o| {
        let end = match psep {
            Some(p) if p > o => p,
            _ => len,
        };
        let opt = &login[o + 1..end];
        if opt.is_empty() {
            None
        } else {
            Some(opt.to_string())
        }
    });

    (user, password, options)
}

/// Parses a decimal port string into a `u16`, mirroring curl's
/// `curlx_str_number` constraints used by `Curl_parse_port`: ASCII digits only,
/// value `0..=65535`. Leading zeros are accepted (and stripped by rendering the
/// parsed value back to decimal). Returns `None` on malformed/out-of-range
/// input.
fn parse_port_number(s: &str) -> Option<u16> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    match s.parse::<u64>() {
        Ok(n) if n <= u64::from(u16::MAX) => Some(n as u16),
        _ => None,
    }
}

/// Splits a `host[:port]` authority, returning the bare host plus the optional
/// `(rendered_port, port_number)`. The equivalent of curl's `Curl_parse_port`.
///
/// For an IPv6 literal (`[...]`) the closing bracket is located first and only
/// a trailing `:port` is honored. An empty port (`host:`) is accepted only when
/// a scheme is present; otherwise it is `CURLUE_BAD_PORT_NUMBER` (curl's
/// browser-compatible "colon with no digits" behavior).
fn parse_port(host: &str, has_scheme: bool) -> UResult<(String, Option<(String, u16)>)> {
    let bytes = host.as_bytes();
    let colon = if bytes.first() == Some(&b'[') {
        let close = host.find(']').ok_or(CurlUError::BadIpv6)?;
        match bytes.get(close + 1) {
            None => None,
            Some(&b':') => Some(close + 1),
            Some(_) => return Err(CurlUError::BadPortNumber),
        }
    } else {
        host.find(':')
    };

    match colon {
        None => Ok((host.to_string(), None)),
        Some(idx) => {
            let bare = host[..idx].to_string();
            let port_str = &host[idx + 1..];
            if port_str.is_empty() {
                return if has_scheme {
                    Ok((bare, None))
                } else {
                    Err(CurlUError::BadPortNumber)
                };
            }
            match parse_port_number(port_str) {
                Some(num) => Ok((bare, Some((num.to_string(), num)))),
                None => Err(CurlUError::BadPortNumber),
            }
        }
    }
}

/// Parses one IPv4 address part, honoring curl's `0x`-hex, leading-`0`-octal,
/// and decimal forms (a single part may carry up to 32 bits). Returns `None`
/// for anything that is not a valid number in its detected base. The `+`/`-`
/// signs that `u64::from_str_radix` would otherwise accept are rejected, since
/// curl's number parser never accepts them.
fn parse_ipv4_part(seg: &str) -> Option<u32> {
    if seg.is_empty() {
        return None;
    }
    let b = seg.as_bytes();
    let (radix, digits): (u32, &str) = if b[0] == b'0' {
        if b.len() >= 2 && (b[1] == b'x' || b[1] == b'X') {
            (16, &seg[2..])
        } else {
            (8, seg)
        }
    } else {
        (10, seg)
    };
    if digits.is_empty() {
        return None;
    }
    let valid = match radix {
        8 => digits.bytes().all(|c| matches!(c, b'0'..=b'7')),
        16 => digits.bytes().all(|c| c.is_ascii_hexdigit()),
        _ => digits.bytes().all(|c| c.is_ascii_digit()),
    };
    if !valid {
        return None;
    }
    u64::from_str_radix(digits, radix)
        .ok()
        .filter(|&v| v <= u64::from(u32::MAX))
        .map(|v| v as u32)
}

/// Normalizes a host into a dotted-quad IPv4 string when it parses as one of
/// curl's accepted IPv4 forms (1–4 parts, each in hex/octal/decimal, with
/// curl's per-part range rules). The equivalent of curl's `ipv4_normalize`;
/// returns [`HostKind::Name`] for non-IPv4 names and [`HostKind::Ipv6`] for
/// `[...]` literals.
fn ipv4_normalize(host: &str) -> HostKind {
    if host.as_bytes().first() == Some(&b'[') {
        return HostKind::Ipv6;
    }
    let segments: Vec<&str> = host.split('.').collect();
    if segments.len() > 4 {
        return HostKind::Name;
    }
    let mut parts = [0u32; 4];
    for (idx, seg) in segments.iter().enumerate() {
        match parse_ipv4_part(seg) {
            Some(v) => parts[idx] = v,
            None => return HostKind::Name,
        }
    }
    // The packed 32-bit address depends on how many dotted parts were given.
    let address = match segments.len() {
        1 => parts[0],
        2 => {
            if parts[0] > 0xff || parts[1] > 0x00ff_ffff {
                return HostKind::Name;
            }
            (parts[0] << 24) | (parts[1] & 0x00ff_ffff)
        }
        3 => {
            if parts[0] > 0xff || parts[1] > 0xff || parts[2] > 0xffff {
                return HostKind::Name;
            }
            (parts[0] << 24) | (parts[1] << 16) | (parts[2] & 0xffff)
        }
        _ => {
            if parts.iter().any(|&p| p > 0xff) {
                return HostKind::Name;
            }
            (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
        }
    };
    HostKind::Ipv4(Ipv4Addr::from(address).to_string())
}

/// Parses and normalizes an IPv6 literal (`[addr]` or `[addr%zoneid]`),
/// returning `(normalized_bracketed_host, zoneid)`. The equivalent of curl's
/// `ipv6_parse` (using `inet_pton`/`inet_ntop`, here [`Ipv6Addr`], which yields
/// the same RFC 5952 lowercase compressed form). The zone id is at most 15
/// bytes and is **not** part of the normalized address.
fn ipv6_parse(host: &str) -> UResult<(String, Option<String>)> {
    let b = host.as_bytes();
    // "[::]" is the shortest valid literal; brackets are required at both ends.
    if b.len() < 4 || b.first() != Some(&b'[') || b.last() != Some(&b']') {
        return Err(CurlUError::BadIpv6);
    }
    let inner = &host[1..host.len() - 1];
    let ib = inner.as_bytes();
    let span = ib
        .iter()
        .take_while(|&&c| c.is_ascii_hexdigit() || c == b':' || c == b'.')
        .count();

    let mut zoneid: Option<String> = None;
    if span != ib.len() {
        // The only legal trailing content is a "%zoneid".
        if ib.get(span) != Some(&b'%') {
            return Err(CurlUError::BadIpv6);
        }
        let mut zstart = span + 1;
        // A URL-encoded '%' renders as "%25"; skip the "25" when there is real
        // zone text after it, so the zone id is the remaining bytes (curl's
        // special case).
        if zstart + 2 < inner.len() && &ib[zstart..zstart + 2] == b"25" {
            zstart += 2;
        }
        let zone = &inner[zstart..];
        if zone.is_empty() || zone.len() > 15 {
            return Err(CurlUError::BadIpv6);
        }
        zoneid = Some(zone.to_string());
    }

    let addr: Ipv6Addr = inner[..span].parse().map_err(|_| CurlUError::BadIpv6)?;
    Ok((format!("[{addr}]"), zoneid))
}

/// Validates a host, returning `Some((normalized_host, zoneid))` when the host
/// is an IPv6 literal (which [`ipv6_parse`] normalizes) and `None` for a plain
/// registered name that is left unchanged. The equivalent of curl's
/// `hostname_check`.
fn hostname_check(host: &str) -> UResult<Option<(String, Option<String>)>> {
    if host.is_empty() {
        return Err(CurlUError::NoHost);
    }
    if host.as_bytes()[0] == b'[' {
        return ipv6_parse(host).map(Some);
    }
    // Bytes that may never appear unescaped in a registered name.
    const REJECT: &[u8] = b" \r\n\t/:#?!@{}[]\\$'\"^`*<>=;,+&()%";
    if host.bytes().any(|c| REJECT.contains(&c)) {
        return Err(CurlUError::BadHostname);
    }
    Ok(None)
}

/// URL-decodes a host, but only when it actually contains a `%`; control bytes
/// are rejected. The equivalent of curl's `urldecode_host`.
///
/// Documented divergence from the C oracle: curl stores hosts as raw `char*`
/// bytes, whereas this module stores `String`s, so a host that decodes to a
/// non-UTF-8 byte sequence (never resolvable, and rejected by curl downstream
/// anyway) is rejected here with [`CurlUError::BadHostname`].
fn urldecode_host(host: &str) -> UResult<String> {
    if !host.contains('%') {
        return Ok(host.to_string());
    }
    let decoded =
        escape::urldecode(host.as_bytes(), UrlReject::Ctrl).map_err(|_| CurlUError::BadHostname)?;
    String::from_utf8(decoded).map_err(|_| CurlUError::BadHostname)
}

/// Returns the byte length of a leading "dot" at the start of `rest` — `1` for
/// `.` or `3` for the URL-encoded `%2e`/`%2E` — or `None`. The equivalent of
/// curl's `is_dot`.
fn is_dot(rest: &[u8]) -> Option<usize> {
    match rest.first() {
        Some(&b'.') => Some(1),
        Some(&b'%') if rest.len() >= 3 && rest[1] == b'2' && (rest[2] | 0x20) == b'e' => Some(3),
        _ => None,
    }
}

/// Converts the dedot output buffer back into a `String`. The buffer is always
/// valid UTF-8 (a reordering of the input's bytes plus ASCII `/`); the lossy
/// fallback exists only to keep the function total and panic-free.
fn finish_dedot(out: Vec<u8>) -> String {
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(&e.into_bytes()).into_owned())
}

/// Removes `.`/`..` dot segments from a path per RFC 3986 §5.2.4, treating
/// `%2e`/`%2E` as a literal dot (curl's behavior). The equivalent of curl's
/// `dedotdotify` (curl unit test 1395). The input always begins with `/` for
/// real URL paths; inputs shorter than 2 bytes are returned unchanged.
fn dedotdotify(input_str: &str) -> String {
    let input = input_str.as_bytes();
    let len = input.len();
    if len < 2 {
        return input_str.to_string();
    }
    let mut out: Vec<u8> = Vec::with_capacity(len + 1);
    let mut i = 0usize;

    // Step A: strip a leading "./" or "../" (or a bare "."/".." ) prefix.
    //
    // Unlike the main loop (steps B–E), which *preserves* the leading slash of a
    // "/./" or "/../" segment, Step A discards the matched prefix entirely and
    // resumes scanning *past* the trailing slash (curl: `input = p + 1`). This
    // is why `dedotdotify("./")` yields `""` (not `"/"`) — exactly the behavior
    // libtest 1560 asserts for `file:./` → `file://`.
    if let Some(d) = is_dot(&input[i..]) {
        let after = i + d;
        if after >= len {
            // bare "." / "%2e" at the very end → nothing to emit
            return finish_dedot(out);
        } else if input[after] == b'/' {
            // "./" → drop the dot AND its slash, resume after the slash
            i = after + 1;
        } else if let Some(d2) = is_dot(&input[after..]) {
            let after2 = after + d2;
            if after2 >= len {
                // bare ".." at the very end → nothing to emit
                return finish_dedot(out);
            } else if input[after2] == b'/' {
                // "../" → drop the dots AND the slash, resume after the slash
                i = after2 + 1;
            }
            // else: not a dot-segment (e.g. "..x"); fall through unchanged
        }
        // else: not a dot-segment (e.g. ".x"); fall through unchanged
    }

    // Main loop (RFC steps B–E).
    while i < len {
        if input[i] == b'/' {
            let p = i + 1;
            if let Some(d) = is_dot(&input[p..]) {
                let p1 = p + d;
                if p1 >= len {
                    // "/." at end → emit a single trailing slash
                    out.push(b'/');
                    break;
                } else if input[p1] == b'/' {
                    // "/./" → skip the "." and continue at the slash
                    i = p1;
                    continue;
                } else if let Some(d2) = is_dot(&input[p1..]) {
                    let p2 = p1 + d2;
                    if p2 >= len || input[p2] == b'/' {
                        // "/../" or "/.." at end → remove the last output
                        // segment, but only if a slash is present (curl leaves
                        // the buffer untouched when none is found).
                        if let Some(pos) = out.iter().rposition(|&c| c == b'/') {
                            out.truncate(pos);
                        }
                        if p2 >= len {
                            out.push(b'/');
                            break;
                        }
                        i = p2;
                        continue;
                    }
                    // "/..x" → not a dot-segment; fall through to copy
                }
                // "/.x" → not a dot-segment; fall through to copy
            }
        }
        out.push(input[i]);
        i += 1;
    }

    finish_dedot(out)
}

/// Detects a Windows drive-letter prefix (`c:` / `c|`, optionally followed by a
/// separator or end-of-string). The equivalent of curl's
/// `STARTS_WITH_URL_DRIVE_PREFIX`. Such prefixes are rejected for `file:` URLs
/// on non-Windows targets.
fn starts_with_url_drive_prefix(s: &[u8]) -> bool {
    if s.len() < 2 || !s[0].is_ascii_alphabetic() || (s[1] != b':' && s[1] != b'|') {
        return false;
    }
    // A drive prefix may be followed by a path separator or end the string.
    match s.get(2) {
        None => true,
        Some(&c) => c == b'/' || c == b'\\',
    }
}

/// Case-insensitive ASCII prefix test, the equivalent of curl's `checkprefix`
/// (`curl_strnequal`) with the prefix given first.
fn checkprefix_ci(haystack: &str, prefix: &str) -> bool {
    let hb = haystack.as_bytes();
    let pb = prefix.as_bytes();
    hb.len() >= pb.len() && hb[..pb.len()].eq_ignore_ascii_case(pb)
}

/// Parses a `file:` URL into `(scheme, host, path_tail)` where `path_tail` is
/// the path-plus-query-plus-fragment remainder still to be split. The
/// equivalent of curl's `parse_file`, restricted to non-Windows semantics
/// (UNC paths and drive letters are rejected, and the host is always empty).
fn parse_file(url: &str, urllen: usize) -> UResult<(String, Option<String>, String)> {
    if urllen <= 6 {
        // "file:/" is not enough to be a complete file: URL.
        return Err(CurlUError::BadFileUrl);
    }
    let ub = url.as_bytes();
    // The path begins right after "file:".
    let mut path_start = 5usize;

    if ub.get(5) == Some(&b'/') && ub.get(6) == Some(&b'/') {
        // file:// — swallow the two slashes and inspect the authority.
        let mut ptr = 7usize;
        let ptr0 = ub.get(ptr).copied().unwrap_or(0);
        if ptr0 != b'/' && !starts_with_url_drive_prefix(&ub[ptr.min(ub.len())..]) {
            // A hostname is present; only localhost/127.0.0.1 are accepted.
            let rest = &url[ptr..];
            if checkprefix_ci(rest, "localhost/") || checkprefix_ci(rest, "127.0.0.1/") {
                ptr += 9; // now points at the slash after the host
            } else {
                return Err(CurlUError::BadFileUrl);
            }
        }
        path_start = ptr;
    }

    // Reject Windows drive letters on non-Windows ("file:/c:" and "file:c:").
    let pb = &ub[path_start.min(ub.len())..];
    let after_slash = pb.get(1..).unwrap_or(&[]);
    if (pb.first() == Some(&b'/') && starts_with_url_drive_prefix(after_slash))
        || starts_with_url_drive_prefix(pb)
    {
        return Err(CurlUError::BadFileUrl);
    }

    Ok(("file".to_string(), None, url[path_start..].to_string()))
}

/// Legacy curl-style scheme guessing from a hostname prefix, the equivalent of
/// curl's `guess_scheme`. Anything unrecognized defaults to `http`.
fn guess_scheme_from_host(host: &str) -> &'static str {
    if checkprefix_ci(host, "ftp.") {
        "ftp"
    } else if checkprefix_ci(host, "dict.") {
        "dict"
    } else if checkprefix_ci(host, "ldap.") {
        "ldap"
    } else if checkprefix_ci(host, "imap.") {
        "imap"
    } else if checkprefix_ci(host, "smtp.") {
        "smtp"
    } else if checkprefix_ci(host, "pop3.") {
        "pop3"
    } else {
        "http"
    }
}

// ============================================================================
// CurlUrl — the parse engine (private methods used by `set`)
// ============================================================================

impl CurlUrl {
    /// Parses a complete URL into a fresh handle. The equivalent of curl's
    /// `parseurl`. Errors leave nothing partially populated (the caller builds
    /// a brand-new handle and only commits it on success).
    fn parse_url(url: &str, flags: u32) -> UResult<Self> {
        let mut u = Self::default();
        let urllen = junkscan(url, flags & CURLU_ALLOW_SPACE != 0)?;
        let guessing = flags & (CURLU_GUESS_SCHEME | CURLU_DEFAULT_SCHEME) != 0;
        let (schemelen, scheme_lower) = is_absolute_url(url, guessing);

        // `path_tail` is the path + query + fragment remainder common to both
        // the file and authority branches.
        let path_tail: String;

        if schemelen != 0 && scheme_lower.as_deref() == Some("file") {
            let (scheme, host, tail) = parse_file(url, urllen)?;
            u.scheme = Some(scheme);
            u.host = host;
            path_tail = tail;
        } else {
            let host_start = u.parse_scheme(url, schemelen, scheme_lower.as_deref(), flags)?;
            let hostp = &url[host_start..];
            let hostlen = hostp.find(['/', '?', '#']).unwrap_or(hostp.len());
            path_tail = hostp[hostlen..].to_string();

            if hostlen != 0 {
                let has_scheme = u.scheme.is_some();
                u.parse_authority(&hostp[..hostlen], flags, has_scheme)?;
                if flags & CURLU_GUESS_SCHEME != 0 && u.scheme.is_none() {
                    let guessed = guess_scheme_from_host(u.host.as_deref().unwrap_or(""));
                    u.scheme = Some(guessed.to_string());
                    u.guessed_scheme = true;
                }
            } else if flags & CURLU_NO_AUTHORITY != 0 {
                // An empty authority is allowed; the host is the empty string.
                u.host = Some(String::new());
            } else {
                return Err(CurlUError::NoHost);
            }
        }

        // Split off the fragment, then the query, then handle the path. The
        // query is searched only within the pre-fragment portion (matching
        // curl's `memchr(path, '?', pathlen)` after the fragment is trimmed).
        let (before_frag, fragment) = match path_tail.find('#') {
            Some(pos) => (&path_tail[..pos], Some(&path_tail[pos..])),
            None => (path_tail.as_str(), None),
        };
        if let Some(frag) = fragment {
            u.handle_fragment(frag, flags);
        }
        let (path_only, query) = match before_frag.find('?') {
            Some(pos) => (&before_frag[..pos], Some(&before_frag[pos..])),
            None => (before_frag, None),
        };
        if let Some(q) = query {
            u.handle_query(q, flags);
        }
        u.handle_path(path_only, flags);

        Ok(u)
    }

    /// Handles the scheme of a non-`file` URL, returning the byte offset at
    /// which the hostname begins. The equivalent of curl's `parse_scheme`.
    fn parse_scheme(
        &mut self,
        url: &str,
        schemelen: usize,
        scheme_lower: Option<&str>,
        flags: u32,
    ) -> UResult<usize> {
        if schemelen != 0 {
            let bytes = url.as_bytes();
            // Count the slashes after "scheme:" (1–3 are valid).
            let mut p = schemelen + 1;
            let mut slashes = 0;
            while slashes < 4 && bytes.get(p) == Some(&b'/') {
                p += 1;
                slashes += 1;
            }
            if let Some(s) = scheme_lower {
                if get_scheme(s).is_none() && flags & CURLU_NON_SUPPORT_SCHEME == 0 {
                    return Err(CurlUError::UnsupportedScheme);
                }
            }
            if !(1..=3).contains(&slashes) {
                return Err(CurlUError::BadSlashes);
            }
            self.scheme = scheme_lower.map(str::to_string);
            Ok(p)
        } else {
            if flags & (CURLU_DEFAULT_SCHEME | CURLU_GUESS_SCHEME) == 0 {
                return Err(CurlUError::BadScheme);
            }
            if flags & CURLU_DEFAULT_SCHEME != 0 {
                self.scheme = Some(DEFAULT_SCHEME.to_string());
            }
            Ok(0)
        }
    }

    /// Parses the authority (`[user[:password][;options]@]host[:port]`) into the
    /// handle. The equivalent of curl's `parse_authority`.
    fn parse_authority(&mut self, auth: &str, flags: u32, has_scheme: bool) -> UResult<()> {
        let host_offset = self.parse_hostname_login(auth, flags)?;
        let raw_host = &auth[host_offset..];

        let (bare_host, port) = parse_port(raw_host, has_scheme)?;
        if let Some((port_str, port_num)) = port {
            self.port = Some(port_str);
            self.portnum = port_num;
        }
        if bare_host.is_empty() {
            return Err(CurlUError::NoHost);
        }

        match ipv4_normalize(&bare_host) {
            HostKind::Ipv4(normalized) => self.host = Some(normalized),
            HostKind::Ipv6 => {
                let (normalized, zoneid) = ipv6_parse(&bare_host)?;
                self.host = Some(normalized);
                self.zoneid = zoneid;
            }
            HostKind::Name => {
                let decoded = urldecode_host(&bare_host)?;
                // Usually a plain name, but a percent-encoded IPv6 literal
                // (e.g. `%5B::1%5D`) only reveals its brackets after decoding;
                // curl re-runs the full `hostname_check`, which normalizes such
                // a literal in place and extracts its zone id. Mirror that: use
                // the normalized form when one is produced.
                match hostname_check(&decoded)? {
                    Some((normalized, zoneid)) => {
                        self.host = Some(normalized);
                        self.zoneid = zoneid;
                    }
                    None => self.host = Some(decoded),
                }
            }
        }
        Ok(())
    }

    /// Extracts `user:password;options` from the authority, returning the
    /// offset at which the hostname begins. The equivalent of curl's
    /// `parse_hostname_login`.
    fn parse_hostname_login(&mut self, login: &str, flags: u32) -> UResult<usize> {
        let Some(at) = login.find('@') else {
            return Ok(0);
        };
        // Options are only parsed for schemes that carry URL options.
        let parse_options = self
            .scheme
            .as_deref()
            .and_then(get_scheme)
            .is_some_and(|h| h.urloptions);
        let (user, password, options) = parse_login_details(&login[..at], parse_options);

        if user.is_some() {
            if flags & CURLU_DISALLOW_USER != 0 {
                return Err(CurlUError::UserNotAllowed);
            }
            self.user = user;
        }
        if password.is_some() {
            self.password = password;
        }
        if options.is_some() {
            self.options = options;
        }
        Ok(at + 1)
    }

    /// Stores the fragment (the `#…` tail, leading `#` included on input). The
    /// equivalent of curl's `handle_fragment`.
    fn handle_fragment(&mut self, fragment: &str, flags: u32) {
        self.fragment_present = true;
        if fragment.len() > 1 {
            let content = &fragment[1..];
            self.fragment = Some(if flags & CURLU_URLENCODE != 0 {
                urlencode_str(content, true, false)
            } else {
                content.to_string()
            });
        }
    }

    /// Stores the query (the `?…` tail, leading `?` included on input); a lone
    /// `?` stores an empty string. The equivalent of curl's `handle_query`.
    fn handle_query(&mut self, query: &str, flags: u32) {
        self.query_present = true;
        if query.len() > 1 {
            let content = &query[1..];
            self.query = Some(if flags & CURLU_URLENCODE != 0 {
                urlencode_str(content, true, true)
            } else {
                content.to_string()
            });
        } else {
            self.query = Some(String::new());
        }
    }

    /// Stores the path, applying URL-encoding and/or dot-segment removal per the
    /// flags. The equivalent of curl's `handle_path`. A path of `"/"` or shorter
    /// is left unset (it renders as `/`).
    fn handle_path(&mut self, path: &str, flags: u32) {
        let encoded;
        let path_ref: &str = if !path.is_empty() && flags & CURLU_URLENCODE != 0 {
            encoded = urlencode_str(path, true, false);
            &encoded
        } else {
            path
        };

        if path_ref.len() <= 1 {
            // No path, or just the slash: leave it unset (renders as "/").
            self.path = None;
        } else if flags & CURLU_PATH_AS_IS != 0 {
            self.path = Some(path_ref.to_string());
        } else {
            self.path = Some(dedotdotify(path_ref));
        }
    }
}

/// Maps a [`CurlError`] from the IDN layer onto the URL-API result, matching
/// curl's `host_decode`/`host_encode` translation (and the no-IDN build's
/// `CURLUE_LACKS_IDN`).
fn map_idn_err(e: CurlError) -> CurlUError {
    match e {
        CurlError::OutOfMemory => CurlUError::OutOfMemory,
        CurlError::NotBuiltIn => CurlUError::LacksIdn,
        _ => CurlUError::BadHostname,
    }
}

// ============================================================================
// CurlUrl::get — read a component (the `curl_url_get` family)
// ============================================================================

impl CurlUrl {
    /// Returns the requested component, applying the decode/encode flags. The
    /// equivalent of `curl_url_get` / `curl_url_set`'s read side.
    ///
    /// Absent components yield the matching `CURLUE_NO_*` error; an out-of-range
    /// or malformed request yields the exact `CURLUcode`.
    ///
    /// # Errors
    ///
    /// Returns a [`CurlUError`] when the component is missing
    /// (`CURLUE_NO_SCHEME`, `CURLUE_NO_HOST`, …) or when a flag transform fails
    /// (`CURLUE_URLDECODE`, `CURLUE_BAD_HOSTNAME`, `CURLUE_LACKS_IDN`).
    pub fn get(&self, what: CurlUPart, flags: u32) -> UResult<String> {
        if what == CurlUPart::Url {
            return self.urlget_url(flags);
        }

        // Precompute the scheme's default port string when PORT is requested and
        // a default is asked for; it must outlive the match so `ptr` can borrow
        // it (the C code holds it in `portbuf` on the stack for the same reason).
        let default_port: Option<String> =
            if what == CurlUPart::Port && self.port.is_none() && flags & CURLU_DEFAULT_PORT != 0 {
                self.scheme
                    .as_deref()
                    .and_then(get_scheme)
                    .map(|h| h.defport.to_string())
            } else {
                None
            };

        // Resolve the stored value (`ptr`), the "missing" error, and whether a
        // '+'→space decode applies, following `curl_url_get`'s per-part switch.
        let mut plusdecode = false;
        let (ptr, ifmissing): (Option<&str>, CurlUError) = match what {
            CurlUPart::Scheme => {
                if flags & CURLU_NO_GUESS_SCHEME != 0 && self.guessed_scheme {
                    return Err(CurlUError::NoScheme);
                }
                (self.scheme.as_deref(), CurlUError::NoScheme)
            }
            CurlUPart::User => (self.user.as_deref(), CurlUError::NoUser),
            CurlUPart::Password => (self.password.as_deref(), CurlUError::NoPassword),
            CurlUPart::Options => (self.options.as_deref(), CurlUError::NoOptions),
            CurlUPart::Host => (self.host.as_deref(), CurlUError::NoHost),
            CurlUPart::ZoneId => (self.zoneid.as_deref(), CurlUError::NoZoneid),
            CurlUPart::Port => {
                let mut p = self.port.as_deref();
                if p.is_none() {
                    // No stored port: deliver the scheme default if one was
                    // precomputed (i.e. CURLU_DEFAULT_PORT was set and the
                    // scheme is known); otherwise stays absent → CURLUE_NO_PORT.
                    p = default_port.as_deref();
                } else if let Some(h) = self.scheme.as_deref().and_then(get_scheme) {
                    // A stored port matching the scheme default is hidden when
                    // the caller asked to inhibit defaults.
                    if h.defport == self.portnum && flags & CURLU_NO_DEFAULT_PORT != 0 {
                        p = None;
                    }
                }
                (p, CurlUError::NoPort)
            }
            // Path always resolves (defaulting to "/"), so its "missing" code
            // is never reached; curl uses the generic UNKNOWN_PART there.
            CurlUPart::Path => (
                Some(self.path.as_deref().unwrap_or("/")),
                CurlUError::UnknownPart,
            ),
            CurlUPart::Query => {
                plusdecode = flags & CURLU_URLDECODE != 0;
                let mut p = self.query.as_deref();
                if let Some(q) = p {
                    if q.is_empty() && flags & CURLU_GET_EMPTY == 0 {
                        p = None;
                    }
                }
                (p, CurlUError::NoQuery)
            }
            CurlUPart::Fragment => {
                let mut p = self.fragment.as_deref();
                if p.is_none() && self.fragment_present && flags & CURLU_GET_EMPTY != 0 {
                    p = Some("");
                }
                (p, CurlUError::NoFragment)
            }
            CurlUPart::Url => unreachable!("URL handled above"),
        };

        // SCHEME and PORT never URL-decode (curl strips the flag).
        let eff_flags = if matches!(what, CurlUPart::Scheme | CurlUPart::Port) {
            flags & !CURLU_URLDECODE
        } else {
            flags
        };

        match ptr {
            Some(value) => self.urlget_format(what, value, plusdecode, eff_flags),
            None => Err(ifmissing),
        }
    }

    /// Applies the decode/encode/punycode flags to a single component value.
    /// The equivalent of curl's `urlget_format`.
    fn urlget_format(
        &self,
        what: CurlUPart,
        ptr: &str,
        plusdecode: bool,
        flags: u32,
    ) -> UResult<String> {
        let urldecode = flags & CURLU_URLDECODE != 0;
        let urlencode = flags & CURLU_URLENCODE != 0;
        let punycode = flags & CURLU_PUNYCODE != 0 && what == CurlUPart::Host;
        let depunyfy = flags & CURLU_PUNY2IDN != 0 && what == CurlUPart::Host;

        // Working byte copy, with the optional '+'→space conversion.
        let mut bytes: Vec<u8> = ptr.as_bytes().to_vec();
        if plusdecode {
            for b in &mut bytes {
                if *b == b'+' {
                    *b = b' ';
                }
            }
        }

        if urldecode {
            bytes =
                escape::urldecode(&bytes, UrlReject::Ctrl).map_err(|_| CurlUError::Urldecode)?;
        }

        if urlencode {
            return Ok(urlencode_bytes(&bytes, what == CurlUPart::Query));
        }

        // The remaining transforms operate on text. The stored value is valid
        // UTF-8; a decode above could in theory produce non-UTF-8 bytes, which
        // cannot be meaningfully punycoded, so fall back to lossy text.
        let text = String::from_utf8(bytes)
            .unwrap_or_else(|e| String::from_utf8_lossy(&e.into_bytes()).into_owned());

        if punycode {
            if let Some(host) = self.host.as_deref() {
                if !host.is_ascii() {
                    return idn::to_ascii(&text).map_err(map_idn_err);
                }
            }
        } else if depunyfy {
            if let Some(host) = self.host.as_deref() {
                if host.is_ascii() {
                    return idn::from_ascii(&text).map_err(map_idn_err);
                }
            }
        }
        Ok(text)
    }

    /// Reassembles the full URL string. The equivalent of curl's `urlget_url`.
    fn urlget_url(&self, flags: u32) -> UResult<String> {
        let show_fragment =
            self.fragment.is_some() || (self.fragment_present && flags & CURLU_GET_EMPTY != 0);
        let show_query = self.query.as_deref().is_some_and(|q| !q.is_empty())
            || (self.query_present && flags & CURLU_GET_EMPTY != 0);
        let query = self.query.as_deref().unwrap_or("");
        let fragment = self.fragment.as_deref().unwrap_or("");

        // file: URLs render path/query/fragment only (no authority).
        //
        // Faithful-parity note: curl's `urlget_url` passes `u->path` straight to
        // `curl_maprintf("file://%s…")` *without* the `u->path ? u->path : "/"`
        // guard it uses for the network-scheme branch. curl's `maprintf` renders
        // a NULL `%s` as the literal `(nil)`, so a `file:` URL whose path
        // collapsed to nothing (`file:///`, path stored as `None`) round-trips
        // to `file://(nil)`. An *empty* (present) path (`file:./`, stored as
        // `Some("")`) renders as `file://`. We reproduce both exactly.
        if self.scheme.as_deref() == Some("file") {
            let path = self.path.as_deref().unwrap_or("(nil)");
            return Ok(format!(
                "file://{}{}{}{}{}",
                path,
                if show_query { "?" } else { "" },
                query,
                if show_fragment { "#" } else { "" },
                fragment,
            ));
        }

        let Some(host) = self.host.as_deref() else {
            return Err(CurlUError::NoHost);
        };

        // Resolve the scheme to render.
        let scheme = match self.scheme.as_deref() {
            Some(s) => s,
            None if flags & CURLU_DEFAULT_SCHEME != 0 => DEFAULT_SCHEME,
            None => return Err(CurlUError::NoScheme),
        };
        let scheme_info = get_scheme(scheme);

        // Port: deliver a default if asked, or inhibit a default if asked.
        let mut port = self.port.clone();
        if port.is_none() && flags & CURLU_DEFAULT_PORT != 0 {
            if let Some(h) = scheme_info {
                port = Some(h.defport.to_string());
            }
        } else if port.is_some() {
            if let Some(h) = scheme_info {
                if h.defport == self.portnum && flags & CURLU_NO_DEFAULT_PORT != 0 {
                    port = None;
                }
            }
        }

        // Options are only emitted for schemes that carry URL options.
        let options = match scheme_info {
            Some(h) if !h.urloptions => None,
            _ => self.options.as_deref(),
        };

        // Host rendering: IPv6+zone, URL-encoded, or punycode/depunyfy.
        let host_rendered: String = if host.as_bytes().first() == Some(&b'[') {
            if let Some(zone) = self.zoneid.as_deref() {
                // "[addr%25zoneid]" — splice the zone before the closing ']'.
                format!("{}%25{}]", &host[..host.len() - 1], zone)
            } else {
                host.to_string()
            }
        } else if flags & CURLU_URLENCODE != 0 {
            escape::escape(host.as_bytes())
        } else if flags & CURLU_PUNYCODE != 0 {
            if host.is_ascii() {
                host.to_string()
            } else {
                idn::to_ascii(host).map_err(map_idn_err)?
            }
        } else if flags & CURLU_PUNY2IDN != 0 {
            if host.is_ascii() {
                idn::from_ascii(host).map_err(map_idn_err)?
            } else {
                host.to_string()
            }
        } else {
            host.to_string()
        };

        // The "scheme://" prefix is hidden for a guessed scheme when the caller
        // asked to suppress guessing.
        let scheme_prefix = if flags & CURLU_NO_GUESS_SCHEME == 0 || !self.guessed_scheme {
            format!("{scheme}://")
        } else {
            String::new()
        };

        let user = self.user.as_deref().unwrap_or("");
        let password = self.password.as_deref().unwrap_or("");
        let has_userinfo = self.user.is_some() || self.password.is_some() || options.is_some();
        let path = self.path.as_deref().unwrap_or("/");

        let mut url = String::with_capacity(scheme_prefix.len() + host_rendered.len() + 16);
        url.push_str(&scheme_prefix);
        url.push_str(user);
        if self.password.is_some() {
            url.push(':');
            url.push_str(password);
        }
        if let Some(opt) = options {
            url.push(';');
            url.push_str(opt);
        }
        if has_userinfo {
            url.push('@');
        }
        url.push_str(&host_rendered);
        if let Some(p) = port.as_deref() {
            url.push(':');
            url.push_str(p);
        }
        url.push_str(path);
        if show_query {
            url.push('?');
            url.push_str(query);
        }
        if show_fragment {
            url.push('#');
            url.push_str(fragment);
        }
        Ok(url)
    }
}

// ============================================================================
// Setter helpers — direct ports of the static functions backing `curl_url_set`
// ============================================================================

/// Returns whether a byte is RFC 3986 "unreserved" (curl's `ISUNRESERVED`):
/// ALPHA / DIGIT / `-` / `.` / `_` / `~`.
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// Returns whether a byte may appear unescaped in a path when `set` is given a
/// path in path-mode. The equivalent of curl's `allowed_in_path`.
fn allowed_in_path(b: u8) -> bool {
    matches!(
        b,
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

/// Validates a scheme being set, the equivalent of curl's `set_url_scheme`
/// (minus the in-place store and the `guessed_scheme` reset, which the caller
/// performs). A known scheme is always accepted; an unknown scheme requires
/// `CURLU_NON_SUPPORT_SCHEME` and must still be syntactically valid.
fn set_url_scheme(scheme: &str, flags: u32) -> UResult<()> {
    let plen = scheme.len();
    if !(1..=MAX_SCHEME_LEN).contains(&plen) {
        return Err(CurlUError::BadScheme);
    }
    let known = get_scheme(scheme).is_some();
    if flags & CURLU_NON_SUPPORT_SCHEME == 0 && !known {
        return Err(CurlUError::UnsupportedScheme);
    }
    if !known {
        // ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
        let b = scheme.as_bytes();
        if !b[0].is_ascii_alphabetic() {
            return Err(CurlUError::BadScheme);
        }
        for &c in &b[1..] {
            if !(c.is_ascii_alphanumeric() || c == b'+' || c == b'-' || c == b'.') {
                return Err(CurlUError::BadScheme);
            }
        }
    }
    Ok(())
}

/// Validates and renders a port being set, the equivalent of curl's
/// `set_url_port`. The first byte must be a digit, the whole string must be
/// decimal, and the value must fit `0..=65535`; the value is re-rendered to
/// strip leading zeros.
fn set_url_port(value: &str) -> UResult<(String, u16)> {
    match value.as_bytes().first() {
        Some(c) if c.is_ascii_digit() => {}
        _ => return Err(CurlUError::BadPortNumber),
    }
    if !value.bytes().all(|c| c.is_ascii_digit()) {
        return Err(CurlUError::BadPortNumber);
    }
    match value.parse::<u64>() {
        Ok(n) if n <= u64::from(u16::MAX) => Ok((n.to_string(), n as u16)),
        _ => Err(CurlUError::BadPortNumber),
    }
}

/// Builds the stored value for a `set` operation, the equivalent of the
/// dynbuf-building block in curl's `curl_url_set`.
///
/// * A leading `/` is enforced for path-mode when the value lacks one.
/// * With `urlencode`, bytes are percent-encoded (uppercase) except the
///   unreserved set, the path-allowed set (in path-mode), the first `=` (when
///   `equalsencode`), and spaces become `+` when `plusencode`.
/// * Without `urlencode`, the value is stored verbatim except that any
///   uppercase `%XX` escape is lowercased.
fn encode_set_value(
    part: &str,
    urlencode: bool,
    plusencode: bool,
    pathmode: bool,
    leadingslash: bool,
    mut equalsencode: bool,
) -> String {
    let bytes = part.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(part.len() * 3 + 2);
    if leadingslash && bytes.first() != Some(&b'/') {
        out.push(b'/');
    }
    if urlencode {
        for &b in bytes {
            if b == b' ' && plusencode {
                out.push(b'+');
            } else if is_unreserved(b)
                || (pathmode && allowed_in_path(b))
                || (b == b'=' && equalsencode)
            {
                // Only the first '=' is preserved when equalsencode is set.
                if b == b'=' && equalsencode {
                    equalsencode = false;
                }
                out.push(b);
            } else {
                out.push(b'%');
                out.push(HEX_UPPER[(b >> 4) as usize]);
                out.push(HEX_UPPER[(b & 0x0f) as usize]);
            }
        }
    } else {
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if b == b'%'
                && i + 2 < bytes.len()
                && bytes[i + 1].is_ascii_hexdigit()
                && bytes[i + 2].is_ascii_hexdigit()
                && (bytes[i + 1].is_ascii_uppercase() || bytes[i + 2].is_ascii_uppercase())
            {
                out.push(b'%');
                out.push(bytes[i + 1].to_ascii_lowercase());
                out.push(bytes[i + 2].to_ascii_lowercase());
                i += 3;
            } else {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(&e.into_bytes()).into_owned())
}

/// Finds the first occurrence of `needle` in `s` at or after byte offset
/// `start`, returning its absolute offset. The equivalent of curl's
/// `strchr(s + start, needle)` (returns `None` when `start` is past the end or
/// the byte is absent).
fn strchr_from(s: &str, start: usize, needle: u8) -> Option<usize> {
    if start >= s.len() {
        return None;
    }
    s.as_bytes()[start..]
        .iter()
        .position(|&b| b == needle)
        .map(|p| p + start)
}

// ============================================================================
// CurlUrl::set — write a component (the `curl_url_set` family)
// ============================================================================

impl CurlUrl {
    /// Sets a numeric port, the equivalent of the `CURLUPART_PORT` arm of
    /// `curl_url_set` (which delegates to `set_url_port`). The value is never
    /// URL-encoded.
    fn set_port(&mut self, value: &str) -> UResult<()> {
        let (rendered, num) = set_url_port(value)?;
        self.port = Some(rendered);
        self.portnum = num;
        Ok(())
    }

    /// Validates a host being set and, for an IPv6 literal, extracts its zone id
    /// as a side effect — the equivalent of curl's `hostname_check` as called
    /// from the `CURLUPART_HOST` arm of `curl_url_set`.
    ///
    /// Faithful-parity note: in the *set* path (unlike parsing) curl validates
    /// the host but stores the caller-provided value verbatim; `ipv6_parse`
    /// normalizes only a throwaway local buffer, so the **un-normalized** host
    /// is what ends up stored. Only the extracted `zoneid` persists on the
    /// handle. Any IPv6 parse failure here is reported as `CURLUE_BAD_HOSTNAME`
    /// (curl folds every `hostname_check`/`ipv6_parse` error into `bad = TRUE`).
    fn check_host_set(&mut self, host: &str) -> UResult<()> {
        match hostname_check(host) {
            // IPv6 literal: keep the extracted zone id as a side effect; the
            // normalized address is intentionally discarded (the caller stores
            // the original `newp`).
            Ok(Some((_normalized, zoneid))) => {
                self.zoneid = zoneid;
                Ok(())
            }
            // A plain registered name passed validation.
            Ok(None) => Ok(()),
            // curl folds every validation failure here into CURLUE_BAD_HOSTNAME.
            Err(_) => Err(CurlUError::BadHostname),
        }
    }

    /// Clears a single component (or the whole handle for `Url`). The equivalent
    /// of curl's `urlset_clear`, called when `curl_url_set` is given a NULL
    /// value. Because [`CurlUPart`] is exhaustive this can never fail (curl's
    /// `default: CURLUE_UNKNOWN_PART` is unreachable).
    fn urlset_clear(&mut self, what: CurlUPart) {
        match what {
            CurlUPart::Url => *self = Self::default(),
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

    /// Concatenates a relative URL onto the (already-rendered) base URL, making
    /// it absolute, and returns the string to be re-parsed. The equivalent of
    /// curl's `redirect_url` up to (but not including) the `parseurl_and_replace`
    /// call, which the caller performs.
    ///
    /// `base` is the current handle's `get(URL)` output; `relurl` is the new
    /// relative reference. `protsep` (the host offset) is computed as
    /// `scheme.len() + 3` — exactly curl's `base + strlen(u->scheme) + 3` —
    /// which assumes `base` carries the `scheme://` prefix (always true for a
    /// successfully-rendered absolute URL).
    fn build_redirect(&self, base: &str, relurl: &str) -> String {
        let scheme_len = self.scheme.as_deref().map_or(0, str::len);
        let protsep = (scheme_len + 3).min(base.len());
        let rbytes = relurl.as_bytes();

        let mut host_changed = false;
        let mut useurl_off = 0usize;
        let mut cutoff: Option<usize> = None;

        match rbytes.first().copied() {
            Some(b'/') => {
                if rbytes.get(1) == Some(&b'/') {
                    // protocol-relative URL: "//example.com/path"
                    cutoff = Some(protsep);
                    useurl_off = 2;
                    host_changed = true;
                } else {
                    // absolute path "/path": cut at the first '/' of the host tail
                    cutoff = strchr_from(base, protsep, b'/');
                }
            }
            Some(b'#') => {
                // fragment-only change: replace any existing fragment
                if self.fragment.is_some() {
                    cutoff = strchr_from(base, protsep, b'#');
                }
            }
            _ => {
                // path- or query-only change
                if self.query.as_deref().is_some_and(|q| !q.is_empty()) {
                    cutoff = strchr_from(base, protsep, b'?');
                } else if self.fragment.as_deref().is_some_and(|f| !f.is_empty()) {
                    cutoff = strchr_from(base, protsep, b'#');
                }
                if rbytes.first() != Some(&b'?') {
                    // append after the last slash: memrchr('/') within the
                    // region [protsep, cutoff|end), then advance past it.
                    let region_end = cutoff.unwrap_or(base.len()).min(base.len());
                    let lo = protsep.min(region_end);
                    cutoff = base.as_bytes()[lo..region_end]
                        .iter()
                        .rposition(|&b| b == b'/')
                        .map(|p| lo + p + 1);
                }
            }
        }

        let prelen = cutoff.unwrap_or(base.len()).min(base.len());
        let useurl = &relurl[useurl_off.min(relurl.len())..];
        let mut out = String::with_capacity(prelen + useurl.len() + 8);
        out.push_str(&base[..prelen]);
        out.push_str(&urlencode_str(useurl, !host_changed, false));
        out
    }

    /// Replaces the handle from a new URL value (absolute) or resolves a
    /// relative reference against the current contents (redirect). The
    /// equivalent of curl's `set_url`.
    fn set_url(&mut self, url: &str, flags: u32) -> UResult<()> {
        if url.is_empty() {
            // A blank URL is only valid if we already hold a complete one (a
            // redirect to ""); nothing changes in that case.
            return match self.get(CurlUPart::Url, flags) {
                Ok(_) => Ok(()),
                Err(CurlUError::OutOfMemory) => Err(CurlUError::OutOfMemory),
                Err(_) => Err(CurlUError::MalformedInput),
            };
        }

        let guessing = flags & (CURLU_GUESS_SCHEME | CURLU_DEFAULT_SCHEME) != 0;
        if is_absolute_url(url, guessing).0 != 0 {
            // Absolute URL: replace wholesale.
            *self = Self::parse_url(url, flags)?;
            return Ok(());
        }

        // Relative reference: we need a complete base URL to resolve against.
        match self.get(CurlUPart::Url, flags) {
            Ok(oldurl) => {
                let built = self.build_redirect(&oldurl, url);
                *self = Self::parse_url(&built, flags & !CURLU_PATH_AS_IS)?;
                Ok(())
            }
            Err(CurlUError::OutOfMemory) => Err(CurlUError::OutOfMemory),
            // Base is incomplete (no absolute URL available): treat the new
            // value as the replacement, exactly as curl does.
            Err(_) => {
                *self = Self::parse_url(url, flags)?;
                Ok(())
            }
        }
    }
}

impl CurlUrl {
    /// Sets (or, with a `None` value, clears) a URL component. The equivalent of
    /// `curl_url_set`.
    ///
    /// A `None` value clears the component (curl's NULL → `urlset_clear`). For a
    /// `Some` value the byte length must not exceed `CURL_MAX_INPUT_LENGTH`. The
    /// per-part behavior mirrors `curl_url_set` exactly:
    ///
    /// * `Scheme` — validated (known, or syntactically valid with
    ///   `CURLU_NON_SUPPORT_SCHEME`); never URL-encoded; clears `guessed_scheme`.
    /// * `User`/`Password`/`Options`/`Fragment` — stored (optionally encoded).
    /// * `Host` — clears any zone id, validates the host (extracting an IPv6
    ///   zone id as a side effect), and rejects an empty host unless
    ///   `CURLU_NO_AUTHORITY`.
    /// * `Port` — validated as a decimal `0..=65535` and re-rendered.
    /// * `Path` — a leading `/` is enforced; path-reserved characters survive
    ///   URL-encoding.
    /// * `Query` — with `CURLU_APPENDQUERY` the value is appended to any
    ///   existing query (joined with `&`), and under URL-encoding the first `=`
    ///   is preserved while spaces become `+`.
    /// * `Url` — parsed as an absolute URL (replacing the handle) or resolved as
    ///   a relative reference (redirect) against the current contents.
    ///
    /// # Errors
    ///
    /// Returns the exact `CURLUcode` curl would: `CURLUE_MALFORMED_INPUT`
    /// (over-long input or an unparseable blank-redirect base),
    /// `CURLUE_BAD_SCHEME` / `CURLUE_UNSUPPORTED_SCHEME`,
    /// `CURLUE_BAD_PORT_NUMBER`, `CURLUE_BAD_HOSTNAME`, or any code surfaced by
    /// parsing a `Url` value.
    pub fn set(&mut self, what: CurlUPart, part: Option<&str>, flags: u32) -> UResult<()> {
        // A NULL value clears the component.
        let Some(part) = part else {
            self.urlset_clear(what);
            return Ok(());
        };

        if part.len() > CURL_MAX_INPUT_LENGTH {
            return Err(CurlUError::MalformedInput);
        }

        // Per-part flags controlling the shared encoder, mirroring the locals in
        // `curl_url_set`.
        let mut urlencode = flags & CURLU_URLENCODE != 0;
        let mut plusencode = false;
        let mut pathmode = false;
        let mut leadingslash = false;
        let mut appendquery = false;
        let mut equalsencode = false;

        match what {
            CurlUPart::Scheme => {
                // Validate before touching any state; on success the scheme is
                // no longer "guessed". The scheme is never URL-encoded.
                set_url_scheme(part, flags)?;
                self.guessed_scheme = false;
                urlencode = false;
            }
            CurlUPart::User | CurlUPart::Password | CurlUPart::Options => {}
            CurlUPart::Host => {
                // Setting the host always drops any previous zone id.
                self.zoneid = None;
            }
            CurlUPart::ZoneId => {}
            CurlUPart::Port => return self.set_port(part),
            CurlUPart::Path => {
                pathmode = true;
                leadingslash = true;
            }
            CurlUPart::Query => {
                plusencode = urlencode;
                appendquery = flags & CURLU_APPENDQUERY != 0;
                equalsencode = appendquery;
                self.query_present = true;
            }
            CurlUPart::Fragment => {
                self.fragment_present = true;
            }
            CurlUPart::Url => return self.set_url(part, flags),
        }

        // Build the stored (encoded) representation of the value.
        let newp = encode_set_value(
            part,
            urlencode,
            plusencode,
            pathmode,
            leadingslash,
            equalsencode,
        );

        // Faithful-parity note: curl builds `newp` with a `dynbuf`, and
        // `curlx_dyn_ptr` returns a NULL pointer for an *empty* buffer (see
        // `lib/curlx/dynbuf.c`). That NULL-ness drives two behaviors:
        //   1. the append-query block is entered only `if(appendquery && newp)`,
        //      so an empty appended value never splices onto the old query; and
        //   2. the final `*storep = newp` then stores NULL, i.e. clears the
        //      component.
        // We model curl's NULL with an empty encoded string here.
        let newp_is_null = newp.is_empty();

        // Append-to-query: splice onto the existing query with a '&' separator
        // (only when a non-empty value is appended AND a non-empty query already
        // exists; otherwise fall through to a plain store, exactly like curl).
        if appendquery && !newp_is_null {
            let querylen = self.query.as_deref().map_or(0, str::len);
            if querylen > 0 {
                let existing = self.query.as_deref().unwrap_or("");
                let add_amp = !existing.ends_with('&');
                let mut combined = String::with_capacity(querylen + 1 + newp.len());
                combined.push_str(existing);
                if add_amp {
                    combined.push('&');
                }
                combined.push_str(&newp);
                self.query = Some(combined);
                return Ok(());
            }
            // querylen == 0 → store `newp` directly below.
        } else if what == CurlUPart::Host {
            // Host validation (and IPv6 zone-id extraction side effect).
            let n = newp.len();
            if n == 0 && flags & CURLU_NO_AUTHORITY != 0 {
                // An empty host is explicitly allowed (it is cleared to None
                // below, matching curl's `*storep = NULL`).
            } else if n == 0 {
                return Err(CurlUError::BadHostname);
            } else if !urlencode {
                // The value was supplied already-encoded; decode to validate.
                let decoded = escape::urldecode(newp.as_bytes(), UrlReject::Ctrl)
                    .map_err(|_| CurlUError::BadHostname)?;
                let decoded_str =
                    String::from_utf8(decoded).map_err(|_| CurlUError::BadHostname)?;
                self.check_host_set(&decoded_str)?;
            } else {
                self.check_host_set(&newp)?;
            }
        }

        // Commit the value to the addressed field. An empty encoded value
        // clears the field (curl stores NULL); otherwise the encoded string is
        // stored.
        let stored = if newp_is_null { None } else { Some(newp) };
        match what {
            CurlUPart::Scheme => self.scheme = stored,
            CurlUPart::User => self.user = stored,
            CurlUPart::Password => self.password = stored,
            CurlUPart::Options => self.options = stored,
            CurlUPart::Host => self.host = stored,
            CurlUPart::ZoneId => self.zoneid = stored,
            CurlUPart::Path => self.path = stored,
            CurlUPart::Query => self.query = stored,
            CurlUPart::Fragment => self.fragment = stored,
            // Port and Url returned early above.
            CurlUPart::Port | CurlUPart::Url => unreachable!("Port/Url handled above"),
        }
        Ok(())
    }
}

// ============================================================================
// CurlUrl — internal normalization API consumed by `crate::conn` /
// `crate::protocols` / `crate::transfer`.
// ============================================================================

impl CurlUrl {
    /// Produces the normalized [`ParsedUrl`] the connection and protocol layers
    /// consume.
    ///
    /// This is the bridge between the URL-API handle and the transfer engine
    /// (curl resolves these same fields out of `struct Curl_URL` during
    /// connection setup in `lib/url.c`):
    ///
    /// * **scheme** — the stored scheme, or [`DEFAULT_SCHEME`] (`https`) when
    ///   none was set.
    /// * **host** — wire-ready and connectable: IPv6 literals have their
    ///   surrounding `[`/`]` stripped (the bare address the resolver/socket
    ///   needs; the zone id is delivered separately in
    ///   [`ParsedUrl::zoneid`]), and an IDN name is converted to its ACE
    ///   (`xn--`) form via [`crate::idn::to_ascii`]. An ASCII name (including an
    ///   IPv4 literal) is passed through unchanged.
    /// * **port** — the explicit port when one was set, otherwise the scheme's
    ///   default port from the scheme table (`0` for an unknown scheme).
    /// * **path** — never empty; defaults to `"/"`.
    /// * user/password/options/query/fragment — as stored (still URL-encoded).
    ///
    /// # Errors
    ///
    /// Returns [`CurlUError::NoHost`] when no host is set, or the mapped IDN
    /// error ([`CurlUError::LacksIdn`] / [`CurlUError::BadHostname`] /
    /// [`CurlUError::OutOfMemory`]) when an IDN name cannot be converted.
    pub fn to_request_parts(&self) -> UResult<ParsedUrl> {
        let scheme = self
            .scheme
            .clone()
            .unwrap_or_else(|| DEFAULT_SCHEME.to_string());
        let scheme_info = get_scheme(&scheme);

        let stored_host = self.host.as_deref().ok_or(CurlUError::NoHost)?;
        let host = if stored_host.as_bytes().first() == Some(&b'[') {
            // IPv6 literal: hand the resolver the bare address (no brackets).
            stored_host
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or(stored_host)
                .to_string()
        } else {
            // Registered name: convert IDN → ACE for the wire (ASCII/IPv4 names
            // pass straight through).
            idn::to_ascii(stored_host).map_err(map_idn_err)?
        };

        // An explicitly set port (even a non-default one) wins; otherwise fall
        // back to the scheme's default port. `port.is_some()` (not `portnum`) is
        // the discriminator so a literal `:0` is honored as port 0.
        let port = if self.port.is_some() {
            self.portnum
        } else {
            scheme_info.map_or(0, |h| h.defport)
        };

        let path = self.path.clone().unwrap_or_else(|| "/".to_string());

        Ok(ParsedUrl {
            scheme,
            host,
            port,
            user: self.user.clone(),
            password: self.password.clone(),
            options: self.options.clone(),
            zoneid: self.zoneid.clone(),
            path,
            query: self.query.clone(),
            fragment: self.fragment.clone(),
        })
    }

    /// Resolves a `Location:` redirect target against this URL, returning the
    /// new absolute URL handle. The equivalent of how curl applies a redirect
    /// (`curl_url_set(CURLUPART_URL, location, …)` on a duplicate of the current
    /// handle, in `lib/transfer.c`).
    ///
    /// `location` may be absolute (replacing the URL outright) or relative
    /// (resolved against this URL exactly as a browser/`libcurl` would). The
    /// receiver is left untouched; the resolved URL is returned in a fresh
    /// handle.
    ///
    /// # Errors
    ///
    /// Returns whatever [`set`](Self::set) would for the `Url` part — e.g.
    /// `CURLUE_MALFORMED_INPUT` for an unparseable target.
    pub fn resolve(&self, location: &str, flags: u32) -> UResult<Self> {
        let mut next = self.clone();
        next.set(CurlUPart::Url, Some(location), flags)?;
        Ok(next)
    }
}

// ============================================================================
// Tests
//
// The authoritative oracle for these vectors is curl 8.x's
// `tests/libtest/lib1560.c`. Wherever a vector is taken verbatim from that file
// it is noted, so the parity intent is auditable. The pipe-format helper
// [`dump`] reproduces lib1560's `checkparts` output
// (`scheme | user | password | options | host | port | path | query |
// fragment`), where a missing component renders as `[N]` with `N` being the
// exact `CURLUE_NO_*` integer — which equals the corresponding [`CurlUError`]
// discriminant (NoScheme=10 … NoFragment=17).
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    // -- helpers --------------------------------------------------------------

    /// Parses a full URL into a fresh handle (the equivalent of lib1560 calling
    /// `curl_url_set(u, CURLUPART_URL, url, flags)`).
    fn parse(url: &str, flags: u32) -> UResult<CurlUrl> {
        let mut u = CurlUrl::new();
        u.set(CurlUPart::Url, Some(url), flags)?;
        Ok(u)
    }

    /// Renders every component in lib1560's pipe order, mapping a missing
    /// component to `[<code>]` exactly like `checkparts`.
    fn dump(u: &CurlUrl, getflags: u32) -> String {
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
            .map(|&p| match u.get(p, getflags) {
                Ok(s) => s,
                Err(e) => format!("[{}]", e as i32),
            })
            .collect::<Vec<_>>()
            .join(" | ")
    }

    /// Parse + compare all parts (lib1560 `get_parts`).
    fn check_parts(url: &str, expected: &str, setflags: u32, getflags: u32) {
        let u = parse(url, setflags).unwrap_or_else(|e| panic!("parse {url:?} failed: {e:?}"));
        assert_eq!(dump(&u, getflags), expected, "parts mismatch for {url:?}");
    }

    /// Parse + compare the reassembled URL (lib1560 `get_url`).
    fn check_url(url: &str, expected: &str, setflags: u32, getflags: u32) {
        let u = parse(url, setflags).unwrap_or_else(|e| panic!("parse {url:?} failed: {e:?}"));
        let got = u
            .get(CurlUPart::Url, getflags)
            .unwrap_or_else(|e| panic!("get(URL) {url:?} failed: {e:?}"));
        assert_eq!(got, expected, "url mismatch for {url:?}");
    }

    /// Parse is expected to fail with an exact `CURLUcode`.
    fn check_parse_err(url: &str, setflags: u32, expected: CurlUError) {
        let mut u = CurlUrl::new();
        assert_eq!(
            u.set(CurlUPart::Url, Some(url), setflags),
            Err(expected),
            "expected {expected:?} parsing {url:?}"
        );
    }

    /// Resolve a (relative or absolute) redirect target against a base URL and
    /// compare the reassembled result (lib1560 `set_url`).
    fn check_redirect(base: &str, location: &str, expected: &str) {
        let u = parse(base, 0).unwrap_or_else(|e| panic!("parse base {base:?} failed: {e:?}"));
        let next = u
            .resolve(location, 0)
            .unwrap_or_else(|e| panic!("resolve {location:?} on {base:?} failed: {e:?}"));
        assert_eq!(
            next.get(CurlUPart::Url, 0).unwrap(),
            expected,
            "redirect {base:?} + {location:?}"
        );
    }

    /// Append a query part and compare the reassembled URL (lib1560 `append`).
    fn check_append(base: &str, q: &str, expected: &str, qflags: u32) {
        let mut u = parse(base, 0).unwrap_or_else(|e| panic!("parse {base:?} failed: {e:?}"));
        u.set(CurlUPart::Query, Some(q), qflags | CURLU_APPENDQUERY)
            .unwrap_or_else(|e| panic!("append {q:?} failed: {e:?}"));
        assert_eq!(
            u.get(CurlUPart::Url, 0).unwrap(),
            expected,
            "append {base:?} + {q:?}"
        );
    }

    // -- basic round-trips ----------------------------------------------------

    #[test]
    fn parse_basic_roundtrip() {
        check_url("http://example.com/", "http://example.com/", 0, 0);
        check_url(
            "https://user:pass@example.com:8080/path?a=b#frag",
            "https://user:pass@example.com:8080/path?a=b#frag",
            0,
            0,
        );
        // A scheme-only URL with no path still renders a "/" path.
        check_url("http://example.com", "http://example.com/", 0, 0);
        // The scheme is lowercased on parse.
        check_url("HTTP://Example.COM/Path", "http://Example.COM/Path", 0, 0);
    }

    #[test]
    fn get_parts_pipe_format() {
        // Vectors transcribed from lib1560.c get_parts_list.
        check_parts(
            "http://example.com",
            "http | [11] | [12] | [13] | example.com | [15] | / | [16] | [17]",
            CURLU_DEFAULT_SCHEME,
            0,
        );
        check_parts(
            "http://example.com/path/html?query=name#anchor",
            "http | [11] | [12] | [13] | example.com | [15] | /path/html | query=name | anchor",
            CURLU_DEFAULT_SCHEME,
            0,
        );
        check_parts(
            "http://user:password@example.com:1234/path/html?query=name#anchor",
            "http | user | password | [13] | example.com | 1234 | /path/html | query=name | anchor",
            CURLU_DEFAULT_SCHEME,
            0,
        );
        // IMAP carries URL ;options; HTTP does not (the `;option` stays in the
        // password for http).
        check_parts(
            "imap://user:pass;option@server/path",
            "imap | user | pass | option | server | [15] | /path | [16] | [17]",
            0,
            0,
        );
        check_parts(
            "http://user:pass;option@server/path",
            "http | user | pass;option | [13] | server | [15] | /path | [16] | [17]",
            0,
            0,
        );
        // Fragment containing '?' and '#' is captured whole.
        check_parts(
            "https://example.com/color/#green?no-red",
            "https | [11] | [12] | [13] | example.com | [15] | /color/ | [16] | green?no-red",
            CURLU_DEFAULT_SCHEME,
            0,
        );
        check_parts(
            "https://example.com/color/?green#no-red",
            "https | [11] | [12] | [13] | example.com | [15] | /color/ | green | no-red",
            CURLU_DEFAULT_SCHEME,
            0,
        );
    }

    // -- scheme guessing / default / errors -----------------------------------

    #[test]
    fn scheme_guessing() {
        // Legacy hostname-prefix guessing (lib1560 + guess_scheme).
        for (host, scheme) in [
            ("ftp.example.com", "ftp"),
            ("dict.example.com", "dict"),
            ("ldap.example.com", "ldap"),
            ("imap.example.com", "imap"),
            ("smtp.example.com", "smtp"),
            ("pop3.example.com", "pop3"),
            ("www.example.com", "http"),
            ("example.com", "http"),
        ] {
            let u = parse(host, CURLU_GUESS_SCHEME).unwrap();
            assert_eq!(
                u.get(CurlUPart::Scheme, 0).unwrap(),
                scheme,
                "host {host:?}"
            );
            assert_eq!(u.get(CurlUPart::Host, 0).unwrap(), host);
        }
        // boing:80 with DEFAULT|GUESS is host:port, not scheme:path (the colon
        // is not followed by "//", and guessing is on).
        check_parts(
            "boing:80",
            "https | [11] | [12] | [13] | boing | 80 | / | [16] | [17]",
            CURLU_DEFAULT_SCHEME | CURLU_GUESS_SCHEME,
            0,
        );
    }

    #[test]
    fn default_scheme_not_guessed() {
        // DEFAULT_SCHEME supplies "https" but does NOT mark the scheme guessed,
        // so NO_GUESS_SCHEME on get still shows it.
        let u = parse("example.com", CURLU_DEFAULT_SCHEME).unwrap();
        assert_eq!(u.get(CurlUPart::Scheme, 0).unwrap(), "https");
        assert_eq!(
            u.get(CurlUPart::Scheme, CURLU_NO_GUESS_SCHEME).unwrap(),
            "https"
        );
        // about:80 with DEFAULT_SCHEME → host "about", port 80.
        check_url("about:80", "https://about:80/", CURLU_DEFAULT_SCHEME, 0);
    }

    #[test]
    fn no_guess_scheme_suppresses_prefix() {
        // lib1560: "example.com" GUESS_SCHEME, get with NO_GUESS_SCHEME →
        // "example.com/" (the guessed scheme:// prefix is hidden).
        check_url(
            "example.com",
            "example.com/",
            CURLU_GUESS_SCHEME,
            CURLU_NO_GUESS_SCHEME,
        );
        // get(SCHEME) under NO_GUESS_SCHEME on a guessed scheme → NO_SCHEME.
        let u = parse("example.com", CURLU_GUESS_SCHEME).unwrap();
        assert_eq!(
            u.get(CurlUPart::Scheme, CURLU_NO_GUESS_SCHEME),
            Err(CurlUError::NoScheme)
        );
    }

    #[test]
    fn no_scheme_without_flags_is_error() {
        check_parse_err("example.com", 0, CurlUError::BadScheme);
    }

    #[test]
    fn unsupported_schemes() {
        for url in [
            "data:text/html;charset=utf-8;base64,PCFE",
            "d:anything-really",
            "about:config",
            "example://foo",
            "mailto:infobot@example.com?body=send",
        ] {
            check_parse_err(url, 0, CurlUError::UnsupportedScheme);
        }
        // ...but allowed with NON_SUPPORT_SCHEME and a syntactically valid
        // scheme.
        let u = parse("example://foo/bar", CURLU_NON_SUPPORT_SCHEME).unwrap();
        assert_eq!(u.get(CurlUPart::Scheme, 0).unwrap(), "example");
        assert_eq!(u.get(CurlUPart::Host, 0).unwrap(), "foo");
    }

    #[test]
    fn bad_slashes() {
        // Four slashes after the scheme → CURLUE_BAD_SLASHES (lib1560).
        check_parse_err(
            "http:////user:password@example.com:1234/path",
            CURLU_DEFAULT_SCHEME,
            CurlUError::BadSlashes,
        );
    }

    // -- ports ----------------------------------------------------------------

    #[test]
    fn port_parsing_and_validation() {
        // lib1560 vectors.
        check_parse_err(
            "https://example.com:65536",
            CURLU_DEFAULT_SCHEME,
            CurlUError::BadPortNumber,
        );
        check_parse_err(
            "https://example.com:-1#moo",
            CURLU_DEFAULT_SCHEME,
            CurlUError::BadPortNumber,
        );
        // :0 is a valid port.
        check_parts(
            "https://example.com:0#moo",
            "https | [11] | [12] | [13] | example.com | 0 | / | [16] | moo",
            CURLU_DEFAULT_SCHEME,
            0,
        );
        // Leading zeros are stripped on parse.
        check_parts(
            "https://example.com:01#moo",
            "https | [11] | [12] | [13] | example.com | 1 | / | [16] | moo",
            CURLU_DEFAULT_SCHEME,
            0,
        );
        // Very long zero-padded port that still fits.
        check_url(
            "https://example.com:000000000000000000000443/foo",
            "https://example.com/foo",
            0,
            CURLU_NO_DEFAULT_PORT,
        );
        check_url(
            "https://example.com:000000000000000000000/foo",
            "https://example.com:0/foo",
            0,
            CURLU_NO_DEFAULT_PORT,
        );
    }

    #[test]
    fn default_port_get_flags() {
        // No explicit port → NO_PORT, unless DEFAULT_PORT is asked for.
        let u = parse("https://127.0.0.1", 0).unwrap();
        assert_eq!(u.get(CurlUPart::Port, 0), Err(CurlUError::NoPort));
        assert_eq!(u.get(CurlUPart::Port, CURLU_DEFAULT_PORT).unwrap(), "443");
        // An explicit port equal to the default is hidden under NO_DEFAULT_PORT.
        let u = parse("https://127.0.0.1:443", 0).unwrap();
        assert_eq!(
            u.get(CurlUPart::Port, CURLU_NO_DEFAULT_PORT),
            Err(CurlUError::NoPort)
        );
        // A non-default explicit port is always shown.
        let u = parse("https://127.0.0.1:8443", 0).unwrap();
        assert_eq!(
            u.get(CurlUPart::Port, CURLU_NO_DEFAULT_PORT).unwrap(),
            "8443"
        );
    }

    #[test]
    fn set_port_validation() {
        let mut u = parse("https://example.com/", 0).unwrap();
        u.set(CurlUPart::Port, Some("8080"), 0).unwrap();
        assert_eq!(u.get(CurlUPart::Port, 0).unwrap(), "8080");
        // Leading zeros stripped on set.
        u.set(CurlUPart::Port, Some("080"), 0).unwrap();
        assert_eq!(u.get(CurlUPart::Port, 0).unwrap(), "80");
        // Out of range / non-numeric.
        assert_eq!(
            u.set(CurlUPart::Port, Some("99999"), 0),
            Err(CurlUError::BadPortNumber)
        );
        assert_eq!(
            u.set(CurlUPart::Port, Some("abc"), 0),
            Err(CurlUError::BadPortNumber)
        );
        assert_eq!(
            u.set(CurlUPart::Port, Some("12ab"), 0),
            Err(CurlUError::BadPortNumber)
        );
    }

    // -- IPv4 normalization ---------------------------------------------------

    #[test]
    fn ipv4_normalization() {
        // lib1560 "IPv4 trickeries" — octal, hex, dotted and single-number
        // forms. Anything that is not a strictly valid IPv4 literal stays a
        // registered name.
        let cases = [
            ("0", "http://0.0.0.0/"),
            ("01", "http://0.0.0.1/"),
            ("07", "http://0.0.0.7/"),
            ("07.1", "http://7.0.0.1/"),
            ("7.1", "http://7.0.0.1/"),
            ("0x7.1", "http://7.0.0.1/"),
            ("0xa", "http://0.0.0.10/"),
            ("0xf", "http://0.0.0.15/"),
            // Invalid octal/hex or too-many-parts → kept as a name.
            ("0x", "http://0x/"),
            ("0xg", "http://0xg/"),
            ("08", "http://08/"),
            ("018.0.0.0", "http://018.0.0.0/"),
        ];
        for (host, expected) in cases {
            check_url(host, expected, CURLU_GUESS_SCHEME, 0);
        }
        // With an explicit scheme (lib1560 get_url_list).
        check_url("https://16843009", "https://1.1.1.1/", 0, 0);
        check_url("https://0xffffffff", "https://255.255.255.255/", 0, 0);
        check_url("https://0177.1", "https://127.0.0.1/", 0, 0);
        check_url("https://0111.02.0x3", "https://73.2.0.3/", 0, 0);
        check_url("https://192.0x0000A80001", "https://192.168.0.1/", 0, 0);
        check_url("https://0x7f.1", "https://127.0.0.1/", 0, 0);
        // Not valid IPv4 → unchanged names.
        check_url("https://1.0x1000000", "https://1.0x1000000/", 0, 0);
        check_url("https://1.2.3.256.com", "https://1.2.3.256.com/", 0, 0);
        check_url("https://10.com", "https://10.com/", 0, 0);
        check_url("https://1.2.com.99", "https://1.2.com.99/", 0, 0);
    }

    // -- IPv6 + zoneid --------------------------------------------------------

    #[test]
    fn ipv6_normalization_and_zoneid() {
        // Zero-run collapsing and lowercase (lib1560).
        check_url(
            "https://[fe80::0000:20c:29ff:fe9c:409b]:80/moo",
            "https://[fe80::20c:29ff:fe9c:409b]:80/moo",
            0,
            0,
        );
        check_url(
            "https://[fe80:0000:0000:0000:020c:29ff:fe9c:409b]:80/moo",
            "https://[fe80::20c:29ff:fe9c:409b]:80/moo",
            0,
            0,
        );
        check_url(
            "https://[FE80:0:A:0:409B:0:0:0]:80/moo",
            "https://[fe80:0:a:0:409b::]:80/moo",
            0,
            0,
        );
        // Zone id: "%25" in the URL decodes to the "%" separator; host keeps the
        // bare address and the zone id is captured separately.
        let u = parse("https://[fe80::1%25eth0]:1234/", 0).unwrap();
        assert_eq!(u.get(CurlUPart::Host, 0).unwrap(), "[fe80::1]");
        assert_eq!(u.get(CurlUPart::ZoneId, 0).unwrap(), "eth0");
        assert_eq!(u.get(CurlUPart::Port, 0).unwrap(), "1234");
        // Round-trips back to the "%25"-escaped form.
        assert_eq!(
            u.get(CurlUPart::Url, 0).unwrap(),
            "https://[fe80::1%25eth0]:1234/"
        );
        // "bad" (unescaped) zone id is still accepted (lib1560).
        let u = parse("https://[fe80::20c:29ff:fe9c:409b%eth0]:1234", 0).unwrap();
        assert_eq!(
            u.get(CurlUPart::Host, 0).unwrap(),
            "[fe80::20c:29ff:fe9c:409b]"
        );
        assert_eq!(u.get(CurlUPart::ZoneId, 0).unwrap(), "eth0");
        // "%252" → "%2" → zone id "2".
        let u = parse("https://[::1%252]:1234", 0).unwrap();
        assert_eq!(u.get(CurlUPart::Host, 0).unwrap(), "[::1]");
        assert_eq!(u.get(CurlUPart::ZoneId, 0).unwrap(), "2");
    }

    #[test]
    fn ipv6_errors() {
        check_parse_err(
            "http://[ab.be:1]/x",
            CURLU_DEFAULT_SCHEME,
            CurlUError::BadIpv6,
        );
        check_parse_err(
            "http://[ab.be]/x",
            CURLU_DEFAULT_SCHEME,
            CurlUError::BadIpv6,
        );
        // A bad "port" delimiter after the bracket.
        check_parse_err(
            "https://[fe80::20c:29ff:fe9c:409b]-80/moo",
            0,
            CurlUError::BadPortNumber,
        );
        check_parse_err("https://[::%25fakeit];80/moo", 0, CurlUError::BadPortNumber);
    }

    // -- file URLs ------------------------------------------------------------

    #[test]
    fn file_urls() {
        // lib1560 file vectors.
        check_parts(
            "file:/hello.html",
            "file | [11] | [12] | [13] | [14] | [15] | /hello.html | [16] | [17]",
            0,
            0,
        );
        check_parts(
            "file:/h",
            "file | [11] | [12] | [13] | [14] | [15] | /h | [16] | [17]",
            0,
            0,
        );
        check_parts(
            "file://127.0.0.1/hello.html",
            "file | [11] | [12] | [13] | [14] | [15] | /hello.html | [16] | [17]",
            0,
            0,
        );
        check_parts(
            "file:////hello.html",
            "file | [11] | [12] | [13] | [14] | [15] | //hello.html | [16] | [17]",
            0,
            0,
        );
        check_parts(
            "file:///hello.html",
            "file | [11] | [12] | [13] | [14] | [15] | /hello.html | [16] | [17]",
            0,
            0,
        );
        // Errors.
        check_parse_err("file://hello.html", 0, CurlUError::BadFileUrl);
        check_parse_err("file:/", 0, CurlUError::BadFileUrl);
        // get(URL) round-trips.
        check_url("file:///file.txt", "file:///file.txt", 0, 0);
        check_url("file:////file.txt", "file:////file.txt", 0, 0);
        check_url("file:///file.txt#moo", "file:///file.txt#moo", 0, 0);
    }

    #[test]
    fn file_url_dedotdotify_step_a() {
        // The dedotdotify Step-A fix: "./" collapses to "" (advancing PAST the
        // trailing slash), so "file:./" reassembles to "file://".
        check_url("file:./", "file://", 0, 0);
    }

    #[test]
    fn file_url_nil_path() {
        // Faithful-parity quirk: a file URL whose path collapses to nothing
        // (path stored as None, e.g. "file:///") renders with curl's maprintf
        // NULL-`%s` placeholder "(nil)".
        let u = parse("file:///", 0).unwrap();
        assert_eq!(u.get(CurlUPart::Url, 0).unwrap(), "file://(nil)");
    }

    // -- path normalization (dedotdotify) / path-as-is ------------------------

    #[test]
    fn path_dot_segment_removal() {
        check_url("http://example.com/./a", "http://example.com/a", 0, 0);
        check_url("http://example.com/a/./b", "http://example.com/a/b", 0, 0);
        check_url("http://example.com/a/../b", "http://example.com/b", 0, 0);
        check_url(
            "http://example.com/a/b/../../c",
            "http://example.com/c",
            0,
            0,
        );
        // Leading "../" cannot escape the root.
        check_url("http://example.com/../a", "http://example.com/a", 0, 0);
    }

    #[test]
    fn path_as_is_preserves_dots() {
        check_url(
            "http://example.com/../a",
            "http://example.com/../a",
            CURLU_PATH_AS_IS,
            0,
        );
        check_url(
            "http://example.com/a/./b/../c",
            "http://example.com/a/./b/../c",
            CURLU_PATH_AS_IS,
            0,
        );
    }

    // -- redirect resolution --------------------------------------------------

    #[test]
    fn redirect_relative_and_absolute() {
        // lib1560 set_url_list.
        check_redirect("https://example.com", "", "https://example.com/");
        check_redirect(
            "http://firstplace.example.com/want/1314",
            "//somewhere.example.com/reply/1314",
            "http://somewhere.example.com/reply/1314",
        );
        check_redirect(
            "http://example.org#without/ash",
            "/moo#frag",
            "http://example.org/moo#frag",
        );
        check_redirect(
            "http://example.org/foo?bar",
            "moo?hey#weird",
            "http://example.org/moo?hey#weird",
        );
        // Query-only and fragment-only redirects.
        check_redirect(
            "http://example.org/foo?bar",
            "?weird",
            "http://example.org/foo?weird",
        );
        check_redirect("http://example.org", "?weird", "http://example.org/?weird");
        check_redirect(
            "http://example.org/foo?bar",
            "#weird",
            "http://example.org/foo?bar#weird",
        );
        check_redirect("file:///basic#", "#yay", "file:///basic#yay");
        check_redirect("file:///basic?", "?yay", "file:///basic?yay");
    }

    #[test]
    fn redirect_dot_segments() {
        check_redirect(
            "http://example.org/",
            "../path/././../././../moo",
            "http://example.org/moo",
        );
        // Percent-encoded dots are recognized as dot segments.
        check_redirect(
            "http://example.org/",
            ".%2e/path/././../%2E/./../moo",
            "http://example.org/moo",
        );
        check_redirect(
            "http://example.org/",
            ".%2e/path/./%2e/.%2E/%2E/./%2e%2E/moo",
            "http://example.org/moo",
        );
    }

    // -- query append ---------------------------------------------------------

    #[test]
    fn append_query() {
        // lib1560 append_list.
        check_append(
            "HTTP://test/?s",
            "name=joe\u{02}",
            "http://test/?s&name=joe%02",
            CURLU_URLENCODE,
        );
        check_append(
            "HTTP://test/?size=2#f",
            "name=joe=",
            "http://test/?size=2&name=joe%3D#f",
            CURLU_URLENCODE,
        );
        check_append(
            "HTTP://test/?size=2#f",
            "name=joe doe",
            "http://test/?size=2&name=joe+doe#f",
            CURLU_URLENCODE,
        );
        // Appending to an empty existing query just stores the value.
        check_append("http://test/", "a=b", "http://test/?a=b", 0);
        // Appending without urlencode keeps the value verbatim and adds '&'.
        check_append("http://test/?a=b", "c=d", "http://test/?a=b&c=d", 0);
    }

    // -- set parts ------------------------------------------------------------

    #[test]
    fn set_path_urlencode() {
        // lib1560 set_parts_list: allowed-in-path bytes are kept; space and '%'
        // are encoded.
        let mut u = parse("https://example.com/", 0).unwrap();
        u.set(
            CurlUPart::Path,
            Some("one /$!$&'()*+;=:@{}[]%"),
            CURLU_URLENCODE,
        )
        .unwrap();
        assert_eq!(
            u.get(CurlUPart::Url, 0).unwrap(),
            "https://example.com/one%20/$!$&'()*+;=:@{}[]%25"
        );
    }

    #[test]
    fn set_scheme_validation() {
        let mut u = parse("https://example.com/", 0).unwrap();
        // A syntactically valid custom scheme requires NON_SUPPORT_SCHEME.
        u.set(
            CurlUPart::Scheme,
            Some("ftp+-.123"),
            CURLU_NON_SUPPORT_SCHEME,
        )
        .unwrap();
        assert_eq!(
            u.get(CurlUPart::Url, 0).unwrap(),
            "ftp+-.123://example.com/"
        );
        // Schemes must start with a letter.
        assert_eq!(
            u.set(CurlUPart::Scheme, Some("1234"), CURLU_NON_SUPPORT_SCHEME),
            Err(CurlUError::BadScheme)
        );
        assert_eq!(
            u.set(CurlUPart::Scheme, Some("1http"), CURLU_NON_SUPPORT_SCHEME),
            Err(CurlUError::BadScheme)
        );
        // set(SCHEME) does NOT lowercase (unlike parse).
        let mut u = parse("https://example.com/", 0).unwrap();
        u.set(CurlUPart::Scheme, Some("HTTP"), 0).unwrap();
        assert_eq!(u.get(CurlUPart::Scheme, 0).unwrap(), "HTTP");
    }

    #[test]
    fn set_host_keeps_encoded_value() {
        // The HOST-set asymmetry: the value is decoded only to VALIDATE; the
        // original (encoded) form is what gets stored (lib1560).
        let mut u = parse("https://example.com/", 0).unwrap();
        u.set(CurlUPart::Host, Some("%43url.se"), 0).unwrap();
        assert_eq!(u.get(CurlUPart::Url, 0).unwrap(), "https://%43url.se/");
        // A value that decodes to an invalid host is rejected.
        assert_eq!(
            u.set(CurlUPart::Host, Some("%25url.se"), 0),
            Err(CurlUError::BadHostname)
        );
        // Empty host is rejected unless NO_AUTHORITY.
        assert_eq!(
            u.set(CurlUPart::Host, Some(""), 0),
            Err(CurlUError::BadHostname)
        );
    }

    #[test]
    fn set_query_empty_clears() {
        // Setting an empty query with APPENDQUERY|URLENCODE drops the query.
        let mut u = parse("https://example.com/?param=value", 0).unwrap();
        u.set(
            CurlUPart::Query,
            Some(""),
            CURLU_APPENDQUERY | CURLU_URLENCODE,
        )
        .unwrap();
        assert_eq!(u.get(CurlUPart::Url, 0).unwrap(), "https://example.com/");
    }

    // -- percent-encoded hostnames -------------------------------------------

    #[test]
    fn percent_host_decoding() {
        // %41 → 'A' (host is decoded at parse).
        check_url("https://%41", "https://A/", 0, 0);
        check_parts(
            "http://HO0_-st%41/",
            "http | [11] | [12] | [13] | HO0_-stA | [15] | / | [16] | [17]",
            0,
            0,
        );
        // Decoded separators/controls in a host are rejected.
        for bad in [
            "http://example.com%40127.0.0.1/", // '@'
            "http://example.com%3f127.0.0.1/", // '?'
            "http://example.com%23127.0.0.1/", // '#'
            "http://example.com%3a127.0.0.1/", // ':'
            "http://example.com%2F127.0.0.1/", // '/'
            "http://example.com%09127.0.0.1/", // TAB (control)
            "https://%20",                     // space
            "https://%25",                     // '%'
            "https://%41%0D",                  // CR (control)
        ] {
            check_parse_err(bad, 0, CurlUError::BadHostname);
        }
    }

    #[test]
    fn non_utf8_host_is_rejected_documented_divergence() {
        // DOCUMENTED DIVERGENCE from curl: curl stores hosts as raw bytes, so
        // "https://_%c0_" keeps the literal 0xC0 byte and round-trips. This
        // module stores hosts as Rust `String`s (UTF-8), so a host that decodes
        // to an invalid UTF-8 byte sequence — which is never resolvable and is
        // rejected by curl downstream regardless — is rejected here at parse
        // time with CURLUE_BAD_HOSTNAME (see `urldecode_host`).
        check_parse_err("https://_%c0_", 0, CurlUError::BadHostname);
    }

    // -- decode/encode get flags ---------------------------------------------

    #[test]
    fn urldecode_get_flag() {
        // lib1560: the big decode vector. Query plus-decodes (space), the
        // fragment does not, and an invalid "%g7" escape is preserved.
        check_parts(
            "http://%3a:%3a@ex4mple/%3f+?+%3f+%23#+%23%3f%g7",
            "http | : | : | [13] | ex4mple | [15] | /?+ |  ? # | +#?%g7",
            0,
            CURLU_URLDECODE,
        );
        // Without URLDECODE the stored (encoded) forms come back as-is.
        check_parts(
            "http://%3a:%3a@ex4mple/%3f?%3f%35#%35%3f%g7",
            "http | %3a | %3a | [13] | ex4mple | [15] | /%3f | %3f%35 | %35%3f%g7",
            0,
            0,
        );
    }

    #[test]
    fn urlencode_get_flag_query() {
        // A query stored verbatim re-encodes on get under URLENCODE; a space in
        // a query becomes '+' (not %20).
        let mut u = parse("https://example.com/", 0).unwrap();
        u.set(CurlUPart::Query, Some("x y&z"), 0).unwrap();
        assert_eq!(u.get(CurlUPart::Query, 0).unwrap(), "x y&z");
        assert_eq!(u.get(CurlUPart::Query, CURLU_URLENCODE).unwrap(), "x+y&z");
        // A space in the PATH re-encodes to %20 (paths are not query context).
        let mut u = parse("https://example.com/", 0).unwrap();
        u.set(CurlUPart::Path, Some("/a b"), 0).unwrap();
        assert_eq!(u.get(CurlUPart::Path, CURLU_URLENCODE).unwrap(), "/a%20b");
    }

    #[test]
    fn set_empty_clears_component() {
        // Setting a component to an empty string clears it (curl's `newp` is
        // NULL for an empty encoded value → `*storep = NULL`).
        let mut u = parse("https://user:pass@example.com/p?q#f", 0).unwrap();
        u.set(CurlUPart::User, Some(""), 0).unwrap();
        assert_eq!(u.get(CurlUPart::User, 0), Err(CurlUError::NoUser));
        u.set(CurlUPart::Fragment, Some(""), 0).unwrap();
        assert_eq!(u.get(CurlUPart::Fragment, 0), Err(CurlUError::NoFragment));
        // Appending an empty value to an existing query clears the query
        // (lib1560: query="" with APPENDQUERY|URLENCODE).
        let mut u = parse("https://example.com/?param=value", 0).unwrap();
        u.set(
            CurlUPart::Query,
            Some(""),
            CURLU_APPENDQUERY | CURLU_URLENCODE,
        )
        .unwrap();
        assert_eq!(u.get(CurlUPart::Url, 0).unwrap(), "https://example.com/");
    }

    #[test]
    fn get_empty_flag() {
        // lib1560: empty user/query/fragment surface only with GET_EMPTY.
        check_url(
            "http://user@example.com?#",
            "http://user@example.com/?#",
            0,
            CURLU_GET_EMPTY,
        );
        // Without GET_EMPTY the empty query/fragment are omitted.
        let u = parse("http://user@example.com?#", 0).unwrap();
        assert_eq!(
            u.get(CurlUPart::Url, 0).unwrap(),
            "http://user@example.com/"
        );
    }

    // -- dup / clear / strerror ----------------------------------------------

    #[test]
    fn dup_clears_guessed_scheme() {
        // curl_url_dup copies every field EXCEPT guessed_scheme, so a duplicate
        // renders its scheme even under NO_GUESS_SCHEME where the original would
        // have suppressed it.
        let u = parse("example.com", CURLU_GUESS_SCHEME).unwrap();
        assert_eq!(
            u.get(CurlUPart::Url, CURLU_NO_GUESS_SCHEME).unwrap(),
            "example.com/"
        );
        let d = u.dup();
        assert_eq!(
            d.get(CurlUPart::Url, CURLU_NO_GUESS_SCHEME).unwrap(),
            "http://example.com/"
        );
        // The full value round-trips identically.
        assert_eq!(
            d.get(CurlUPart::Url, 0).unwrap(),
            u.get(CurlUPart::Url, 0).unwrap()
        );
    }

    #[test]
    fn clear_parts() {
        let mut u = parse("https://user:pass@example.com:8080/p?q#f", 0).unwrap();
        u.set(CurlUPart::Port, None, 0).unwrap();
        assert_eq!(u.get(CurlUPart::Port, 0), Err(CurlUError::NoPort));
        u.set(CurlUPart::Query, None, 0).unwrap();
        assert_eq!(u.get(CurlUPart::Query, 0), Err(CurlUError::NoQuery));
        u.set(CurlUPart::Fragment, None, 0).unwrap();
        assert_eq!(u.get(CurlUPart::Fragment, 0), Err(CurlUError::NoFragment));
        u.set(CurlUPart::User, None, 0).unwrap();
        assert_eq!(u.get(CurlUPart::User, 0), Err(CurlUError::NoUser));
        // Clearing the whole URL resets to empty.
        u.set(CurlUPart::Url, None, 0).unwrap();
        assert_eq!(u.get(CurlUPart::Host, 0), Err(CurlUError::NoHost));
        assert_eq!(u.get(CurlUPart::Scheme, 0), Err(CurlUError::NoScheme));
    }

    #[test]
    fn strerror_text() {
        // Delegates to crate::error; just confirm a couple are non-empty and
        // distinct.
        assert!(!CurlUrl::strerror(CurlUError::Ok).is_empty());
        assert!(!CurlUrl::strerror(CurlUError::BadPortNumber).is_empty());
        assert_ne!(
            CurlUrl::strerror(CurlUError::NoHost),
            CurlUrl::strerror(CurlUError::BadHostname)
        );
    }

    // -- internal request parts ----------------------------------------------

    #[test]
    fn to_request_parts_defaults() {
        let u = parse("https://example.com/path?q#f", 0).unwrap();
        let p = u.to_request_parts().unwrap();
        assert_eq!(p.scheme, "https");
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port, 443); // scheme default
        assert_eq!(p.path, "/path");
        assert_eq!(p.query.as_deref(), Some("q"));
        assert_eq!(p.fragment.as_deref(), Some("f"));

        // No path → "/".
        let u = parse("http://example.com", 0).unwrap();
        let p = u.to_request_parts().unwrap();
        assert_eq!(p.path, "/");
        assert_eq!(p.port, 80);

        // Explicit port wins.
        let u = parse("https://example.com:8443/", 0).unwrap();
        assert_eq!(u.to_request_parts().unwrap().port, 8443);

        // IPv6 brackets are stripped for the wire; the zone id travels alongside.
        let u = parse("https://[fe80::1%25eth0]/", 0).unwrap();
        let p = u.to_request_parts().unwrap();
        assert_eq!(p.host, "fe80::1");
        assert_eq!(p.zoneid.as_deref(), Some("eth0"));

        // No host → error.
        let u = parse("file:///x", 0).unwrap();
        assert_eq!(u.to_request_parts(), Err(CurlUError::NoHost));
    }

    // -- IDN ------------------------------------------------------------------

    #[test]
    fn idn_punycode_behavior() {
        // This test deliberately avoids any `#[cfg(feature = "idn")]` gate so it
        // is self-contained and correct whether or not the optional `idn`
        // backend is compiled in; it branches on the observed result instead.

        // An already-ASCII / ACE (`xn--`) host always passes through unchanged,
        // regardless of the IDN backend (curl never runs ASCII names through
        // libidn2).
        let u = parse("https://xn--rksmrgs-5wao1o.se/path?q#frag", 0).unwrap();
        assert_eq!(
            u.get(CurlUPart::Host, CURLU_PUNYCODE).unwrap(),
            "xn--rksmrgs-5wao1o.se"
        );
        assert_eq!(u.to_request_parts().unwrap().host, "xn--rksmrgs-5wao1o.se");
        // PUNY2IDN (ToUnicode) is best-effort and has no wire-parity constraint:
        // with the IDN backend it decodes the ACE host back to Unicode; without
        // it the (ASCII) host is returned unchanged for display. Both are valid.
        match u.get(CurlUPart::Host, CURLU_PUNY2IDN) {
            Ok(h) => assert!(
                h == "r\u{e4}ksm\u{f6}rg\u{e5}s.se" || h == "xn--rksmrgs-5wao1o.se",
                "unexpected PUNY2IDN result: {h:?}"
            ),
            Err(e) => assert_eq!(e, CurlUError::LacksIdn),
        }

        // A non-ASCII (Unicode) host either converts to ACE (idn feature on) or
        // reports LACKS_IDN (idn feature off) — both are exact curl parity for
        // the respective build.
        let u = parse("https://r\u{e4}ksm\u{f6}rg\u{e5}s.se/", 0).unwrap();
        match u.get(CurlUPart::Host, CURLU_PUNYCODE) {
            Ok(h) => assert_eq!(h, "xn--rksmrgs-5wao1o.se"),
            Err(e) => assert_eq!(e, CurlUError::LacksIdn),
        }
        match u.to_request_parts() {
            Ok(p) => assert_eq!(p.host, "xn--rksmrgs-5wao1o.se"),
            Err(e) => assert_eq!(e, CurlUError::LacksIdn),
        }
    }

    // -- malformed input ------------------------------------------------------

    #[test]
    fn malformed_spaces() {
        // Spaces in the authority are rejected unless ALLOW_SPACE.
        check_parse_err(
            "https:// example.com?check",
            CURLU_DEFAULT_SCHEME,
            CurlUError::MalformedInput,
        );
        check_parse_err(
            "https://e x a m p l e.com?check",
            CURLU_DEFAULT_SCHEME,
            CurlUError::MalformedInput,
        );
    }

    #[test]
    fn no_host_authority() {
        check_parse_err("http://a:b@/x", CURLU_DEFAULT_SCHEME, CurlUError::NoHost);
    }

    #[test]
    fn input_too_long() {
        // A value longer than CURL_MAX_INPUT_LENGTH is rejected by set().
        let mut u = CurlUrl::new();
        let huge = "a".repeat(CURL_MAX_INPUT_LENGTH + 1);
        assert_eq!(
            u.set(CurlUPart::Url, Some(&huge), 0),
            Err(CurlUError::MalformedInput)
        );
    }
}
