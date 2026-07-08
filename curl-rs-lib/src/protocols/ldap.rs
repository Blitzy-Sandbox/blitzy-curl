// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-FileCopyrightText: Howard Chu, <hyc@openldap.org>

//! LDAP / LDAPS protocol handler — the memory-safe Rust port of curl's LDAP
//! support for the byte-for-byte functional-parity rewrite of curl / libcurl
//! **8.19.0-DEV**.
//!
//! # ⚠️ DEP GAP — no pure-Rust LDAP client is wired into the workspace
//!
//! curl implements LDAP by **linking the C libraries `libldap` + `liblber`**
//! (`#include <ldap.h>`, `ldap_init_fd`, `ldap_url_parse`, `ldap_sasl_bind`,
//! `ldap_search_ext`, the `ber_*` family, and the OpenLDAP sockbuf shim
//! `ldapsb_tls_*`). The rewrite's core mandate is **no C-library linkage**
//! (the sole retained C dependency is optional OS GSSAPI/Kerberos for
//! Negotiate — AAP §0.5.2), and the dependency inventory (AAP §0.5.1) lists
//! **no pure-Rust LDAP crate**. This is therefore a genuine, unresolved
//! dependency gap — flagged here exactly as [`crate::auth::scram`] flagged its
//! missing crypto crate. See the `DEP NOTE` block immediately below.
//!
//! Until a pure-Rust LDAP client is approved and wired into
//! `curl-rs-lib/Cargo.toml` by the workspace owner, this module compiles the
//! parts that need **no** external LDAP dependency — the LDAP-URL parser
//! (Phase 1) and the LDIF result formatter (Phase 3), both of which are the
//! wire-observable surfaces the curl test corpus exercises — and provides the
//! scheme + [`Protocol`] scaffolding (Phase 4). The network bind/search steps
//! (Phase 2) that genuinely require the backend crate are marked with a clear
//! `// TODO(dep):` and, at runtime, return [`CurlCode::NotBuiltIn`] rather than
//! silently succeeding. **No C FFI is introduced anywhere**, and the module
//! contains **zero** `unsafe` (the crate root sets `#![forbid(unsafe_code)]`).
//!
//! # Provenance (source-of-truth C references — read, never modified)
//!
//! * **`lib/openldap.c` (PRIMARY)** — the modern OpenLDAP-backed implementation.
//!   Source-of-truth for the connect/bind state machine (`oldap_connect` /
//!   `oldap_connecting`), the search dispatch (`oldap_do`), the teardown
//!   (`oldap_done` / `oldap_disconnect`), and — most importantly — the
//!   **LDIF result formatting** in `oldap_recv` / its `client_write` helper,
//!   which this module reproduces byte-for-byte.
//! * **`lib/ldap.c`** — the generic/legacy implementation. Source-of-truth for
//!   the canonical **LDAP-URL parser** (`ldap_url_parse2_low` + `str2scope`)
//!   and the scheme registration (`Curl_scheme_ldap` / `Curl_scheme_ldaps`).
//! * **`lib/curl_ldap.h`** — the handler/scheme declarations.
//!
//! # What is faithful vs. gated
//!
//! * [`LdapUrl::parse`] reproduces curl's exact URL decomposition, defaulting,
//!   and percent-unescaping (Phase 1) — fully implemented and unit-tested.
//! * [`LdapEntry::write_ldif`] reproduces `oldap_recv`'s exact LDIF byte stream,
//!   including the base64 double-colon (`attr:: <b64>`) for binary /
//!   non-printable values and the blank-line framing (Phase 3) — fully
//!   implemented and unit-tested.
//! * [`HANDLER`] wires the [`Protocol`] trait (Phase 4). The bind + search
//!   (Phase 2) is the only part blocked on the missing crate; when wired it
//!   will drive the socket through [`crate::conn::Connection`] and layer TLS
//!   for `ldaps` (implicit) / STARTTLS (`ldap` upgrade) through
//!   [`crate::tls`] (`crate::tls::TlsConnector` over a
//!   `crate::tls::TlsConfig`), exactly as `oldap_ssl_connect` /
//!   `oldap_perform_starttls` do in `openldap.c`.

// DEP NOTE: curl's LDAP handler links the C libraries `libldap` + `liblber`.
// The AAP §0.5.1 dependency inventory lists NO pure-Rust LDAP crate, and the
// rewrite forbids C-library linkage (§0.7.2). This is an unresolved dependency
// gap. RESOLUTION for the `curl-rs-lib/Cargo.toml` owner (do NOT hard-code a
// version here — flag only, matching how `auth/scram.rs` flagged `sha1`):
//
//   * Add a pure-Rust LDAP client behind the existing (currently empty) `ldap`
//     Cargo feature. The candidate is the `ldap3` crate — a pure-Rust LDAPv3
//     client that binds/searches asynchronously over Tokio (it speaks the
//     `bind` -> `search` -> streamed results flow this module is shaped around)
//     and, being pure Rust, honours the no-C-linkage mandate. Wire it as
//     `ldap = ["dep:ldap3"]` (version owned by `[workspace.dependencies]`).
//   * ALTERNATIVELY, leave `ldap` default-off (its current state) so the
//     `ldap`/`ldaps` schemes are simply not registered, exactly as a stock curl
//     built with `CURL_DISABLE_LDAP` — `scheme_handler("ldap")` returns `None`.
//
// Until then the network bind/search below is marked `// TODO(dep):` and the
// DO phase returns `CURLE_NOT_BUILT_IN`. The URL parser and the LDIF formatter
// need no external crate and are implemented + tested in full.
//
// DEP NOTE (SASL): `openldap.c` also supports SASL binds (`oldap_perform_sasl`
// via `Curl_sasl_*`). Which SASL mechanisms are reachable depends entirely on
// the approved LDAP crate's bind API; `ldap3`, for instance, exposes SASL
// EXTERNAL and GSSAPI but not the full curl mechanism set. Any shortfall versus
// curl's SASL coverage is a follow-up for whoever wires the crate.

use crate::error::{CurlCode, Error, Result};
use crate::protocols::{ProtoFuture, Protocol, TransferCtx};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

// ===========================================================================
// LDAP search scope (← the `LDAP_SCOPE_*` constants used by `ldap.c`'s
// `str2scope` and consumed by `ldap_search_ext`).
//
// The integer values are the OpenLDAP/RFC 4511 wire values and are frozen: a
// future backend crate maps directly onto them, and `--trace` output names the
// scope the same way curl does.
// ===========================================================================

/// `LDAP_SCOPE_BASE` — search only the base object itself.
pub const LDAP_SCOPE_BASE: i32 = 0;
/// `LDAP_SCOPE_ONELEVEL` — search the immediate children of the base object.
pub const LDAP_SCOPE_ONELEVEL: i32 = 1;
/// `LDAP_SCOPE_SUBTREE` — search the base object and its whole subtree.
pub const LDAP_SCOPE_SUBTREE: i32 = 2;

/// The scope of an LDAP search (← `ludp->lud_scope`).
///
/// Reproduces curl's `str2scope` mapping (`lib/ldap.c`): the URL scope tokens
/// `base`, `one`/`onetree`, and `sub`/`subtree` map to [`Base`](LdapScope::Base),
/// [`OneLevel`](LdapScope::OneLevel), and [`Subtree`](LdapScope::Subtree)
/// respectively; any other token is rejected as a malformed URL. The default
/// when the URL omits the scope field is [`Base`](LdapScope::Base), exactly as
/// `ldap_url_parse2_low` initializes `lud_scope = LDAP_SCOPE_BASE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LdapScope {
    /// Base-object search (`LDAP_SCOPE_BASE`).
    Base = LDAP_SCOPE_BASE as isize,
    /// One-level search (`LDAP_SCOPE_ONELEVEL`).
    OneLevel = LDAP_SCOPE_ONELEVEL as isize,
    /// Subtree search (`LDAP_SCOPE_SUBTREE`).
    Subtree = LDAP_SCOPE_SUBTREE as isize,
}

impl LdapScope {
    /// Parse an LDAP-URL scope token into an [`LdapScope`], reproducing curl's
    /// `str2scope` (`lib/ldap.c`) exactly — including its case-insensitive
    /// matching (curl uses `curl_strequal`) and its acceptance of both the
    /// short (`one`, `sub`) and long (`onetree`, `subtree`) spellings.
    ///
    /// Returns `None` for any unrecognized token, which the URL parser turns
    /// into a `CURLE_URL_MALFORMAT` (curl's `LDAP_INVALID_SYNTAX`).
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        if token.eq_ignore_ascii_case("one") || token.eq_ignore_ascii_case("onetree") {
            Some(LdapScope::OneLevel)
        } else if token.eq_ignore_ascii_case("base") {
            Some(LdapScope::Base)
        } else if token.eq_ignore_ascii_case("sub") || token.eq_ignore_ascii_case("subtree") {
            Some(LdapScope::Subtree)
        } else {
            None
        }
    }

    /// The frozen integer scope value (`LDAP_SCOPE_*`) passed to the search.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl Default for LdapScope {
    /// The default scope is [`Base`](LdapScope::Base) — the value
    /// `ldap_url_parse2_low` assigns before parsing the (optional) scope field.
    fn default() -> Self {
        LdapScope::Base
    }
}

// ===========================================================================
// LDAP scheme defaults (← `ldap.c` `PORT_LDAP` / `PORT_LDAPS` and the RFC 4516
// default filter).
// ===========================================================================

/// Default TCP port for `ldap://` (`PORT_LDAP`).
pub const PORT_LDAP: u16 = 389;
/// Default TCP port for `ldaps://` (`PORT_LDAPS`).
pub const PORT_LDAPS: u16 = 636;

/// The default search filter used when the URL omits the filter field.
///
/// RFC 4516 §3 defines the default `<filter>` as `(objectClass=*)`, and curl's
/// search passes a NULL filter (`ludp->lud_filter`) to the LDAP library, which
/// substitutes exactly this value. It is materialized here so [`LdapUrl`] always
/// carries a concrete filter to hand to the (future) backend.
pub const DEFAULT_FILTER: &str = "(objectClass=*)";

/// The maximum length curl accepts for a single attribute token in the URL
/// (`curlx_str_until(&atp, &out, 1024, ',')` in `ldap_url_parse2_low`). A token
/// longer than this stops attribute parsing, exactly as the C loop `break`s.
const MAX_ATTR_LEN: usize = 1024;

// ===========================================================================
// LdapUrl — the decomposed LDAP URL (← `LDAPURLDesc` / `ldap_url_parse2_low`).
// ===========================================================================

/// A parsed LDAP URL, decomposed exactly as curl's `ldap_url_parse2_low`
/// (`lib/ldap.c`) decomposes `ldap://host:port/dn?attrs?scope?filter?exts`.
///
/// Field defaulting mirrors curl precisely:
///
/// * [`dn`](LdapUrl::dn) is `""` when the path is empty.
/// * [`attributes`](LdapUrl::attributes) is empty when the attribute field is
///   absent — meaning "return all attributes".
/// * [`scope`](LdapUrl::scope) defaults to [`LdapScope::Base`].
/// * [`filter`](LdapUrl::filter) defaults to [`DEFAULT_FILTER`].
///
/// The DN, attribute, and filter fields are percent-unescaped with curl's
/// `REJECT_ZERO` policy (an unescaped NUL byte is rejected as a malformed URL).
/// Because RFC 4514/4516 define those fields as UTF-8, the unescaped bytes are
/// additionally required to be valid UTF-8; a non-UTF-8 result is reported as
/// `CURLE_URL_MALFORMAT` (curl keeps raw `char*` bytes, but every real-world
/// LDAP URL decodes to UTF-8, and this crate's `unsafe`-free string model makes
/// UTF-8 the natural representation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LdapUrl {
    /// `true` for the `ldaps://` scheme (implicit TLS), `false` for `ldap://`.
    pub secure: bool,
    /// The host component (may be empty, e.g. `ldap:///dc=example` — curl reads
    /// the host from the connection in that case).
    pub host: String,
    /// The explicit port, or `None` to use [`PORT_LDAP`] / [`PORT_LDAPS`].
    pub port: Option<u16>,
    /// The base distinguished name to search from (← `lud_dn`).
    pub dn: String,
    /// The requested attribute list (← `lud_attrs`); empty means all attributes.
    pub attributes: Vec<String>,
    /// The search scope (← `lud_scope`).
    pub scope: LdapScope,
    /// The search filter (← `lud_filter`); [`DEFAULT_FILTER`] when omitted.
    pub filter: String,
    /// The (unparsed) URL extensions field, split on `,` (← `lud_exts`). curl's
    /// fallback parser ignores the extension *values* but rejects a present-yet-
    /// empty extensions field; both behaviors are reproduced.
    pub extensions: Vec<String>,
}

impl LdapUrl {
    /// The effective port: the explicit [`port`](LdapUrl::port) if present, else
    /// the scheme default ([`PORT_LDAPS`] for `ldaps`, [`PORT_LDAP`] otherwise).
    #[must_use]
    pub fn effective_port(&self) -> u16 {
        self.port
            .unwrap_or(if self.secure { PORT_LDAPS } else { PORT_LDAP })
    }

    /// Parse a full `ldap://` or `ldaps://` URL, reproducing curl's
    /// decomposition, defaulting, and percent-unescaping (`lib/ldap.c`
    /// `ldap_url_parse2_low` + `str2scope`; `lib/openldap.c` `oldap_url_parse`
    /// wraps the OpenLDAP parser over the same RFC 4516 grammar).
    ///
    /// # Errors
    ///
    /// Returns [`Error::url`] (`CURLE_URL_MALFORMAT`) for a non-LDAP scheme, a
    /// malformed authority/port, an unrecognized scope token, an unescaped NUL
    /// byte, a non-UTF-8 unescaped component, or a present-but-empty extensions
    /// field — the cases curl reports as `LDAP_INVALID_SYNTAX` /
    /// `CURLE_URL_MALFORMAT`.
    pub fn parse(url: &str) -> Result<Self> {
        // --- Scheme (case-insensitive, as curl's scheme match) ---------------
        let (secure, rest) = if let Some(r) = strip_prefix_ci(url, "ldaps://") {
            (true, r)
        } else if let Some(r) = strip_prefix_ci(url, "ldap://") {
            (false, r)
        } else {
            return Err(Error::url("LDAP: URL scheme is not ldap:// or ldaps://"));
        };

        // --- Authority vs. path+query: authority ends at the first '/' or '?'.
        let auth_end = rest.find(['/', '?']).unwrap_or(rest.len());
        let authority = &rest[..auth_end];
        let remainder = &rest[auth_end..];

        let (host, port) = parse_authority(authority)?;

        // --- Split off the DN (path) from the query --------------------------
        // Drop a single leading '/', then the DN runs up to the first '?'.
        let after_slash = remainder.strip_prefix('/').unwrap_or(remainder);
        let (dn_raw, query) = match after_slash.find('?') {
            Some(i) => (&after_slash[..i], Some(&after_slash[i + 1..])),
            None => (after_slash, None),
        };

        // curl unescapes the DN only when it is non-empty (`if(*p)`).
        let dn = if dn_raw.is_empty() {
            String::new()
        } else {
            percent_decode_utf8(dn_raw)?
        };

        let mut out = LdapUrl {
            secure,
            host,
            port,
            dn,
            attributes: Vec::new(),
            scope: LdapScope::Base,
            filter: DEFAULT_FILTER.to_string(),
            extensions: Vec::new(),
        };

        if let Some(query) = query {
            out.parse_query(query)?;
        }

        Ok(out)
    }

    /// Parse the `attrs?scope?filter?exts` query tail, consuming one `?`
    /// delimiter at a time exactly as `ldap_url_parse2_low` does.
    fn parse_query(&mut self, query: &str) -> Result<()> {
        // Attributes (comma-separated, each token capped at MAX_ATTR_LEN).
        let (attrs_seg, rest) = split_once_q(query);
        if !attrs_seg.is_empty() {
            for token in attrs_seg.split(',') {
                // curl's `curlx_str_until(.., MAX_ATTR_LEN, ',')` stops the loop
                // when a token exceeds the cap.
                if token.len() > MAX_ATTR_LEN {
                    break;
                }
                self.attributes.push(percent_decode_utf8(token)?);
            }
        }
        let Some(rest) = rest else { return Ok(()) };

        // Scope.
        let (scope_seg, rest) = split_once_q(rest);
        if !scope_seg.is_empty() {
            self.scope = LdapScope::from_token(scope_seg)
                .ok_or_else(|| Error::url("LDAP: bad search scope in URL"))?;
        }
        let Some(rest) = rest else { return Ok(()) };

        // Filter.
        let (filter_seg, rest) = split_once_q(rest);
        if !filter_seg.is_empty() {
            self.filter = percent_decode_utf8(filter_seg)?;
        }

        // Extensions: curl does not parse the values but rejects a delimiter
        // that introduces an empty extensions field (`if(p && !*p)`).
        if let Some(ext) = rest {
            if ext.is_empty() {
                return Err(Error::url("LDAP: empty extensions field in URL"));
            }
            self.extensions = ext.split(',').map(str::to_string).collect();
        }

        Ok(())
    }
}

/// Case-insensitively strip `prefix` from the front of `s`, returning the
/// remainder. Used for the scheme match (curl uses `curl_strnequal`).
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Split `s` at the first `?`, returning `(before, Some(after))`, or
/// `(s, None)` when there is no `?`. Mirrors curl's `strchr(p, '?')` +
/// `*q++ = '\0'` one-delimiter-at-a-time consumption.
fn split_once_q(s: &str) -> (&str, Option<&str>) {
    match s.find('?') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    }
}

/// Parse an LDAP-URL authority into `(host, Option<port>)`, handling bracketed
/// IPv6 literals (`[::1]:389`). An empty authority yields an empty host and no
/// port (curl then falls back to the connection's host/port).
fn parse_authority(authority: &str) -> Result<(String, Option<u16>)> {
    if authority.is_empty() {
        return Ok((String::new(), None));
    }

    if let Some(after_bracket) = authority.strip_prefix('[') {
        // IPv6 literal: host is inside the brackets.
        let Some(close) = after_bracket.find(']') else {
            return Err(Error::url("LDAP: unterminated IPv6 literal in URL host"));
        };
        let host = after_bracket[..close].to_string();
        let tail = &after_bracket[close + 1..];
        let port = match tail.strip_prefix(':') {
            Some(p) => Some(parse_port(p)?),
            None if tail.is_empty() => None,
            None => return Err(Error::url("LDAP: malformed IPv6 authority in URL")),
        };
        return Ok((host, port));
    }

    // host[:port] — a hostname never contains ':', so split on the first one.
    match authority.split_once(':') {
        Some((host, port)) => Ok((host.to_string(), Some(parse_port(port)?))),
        None => Ok((authority.to_string(), None)),
    }
}

/// Parse a decimal port (1..=65535) from a URL, rejecting empty/non-numeric/
/// out-of-range values as `CURLE_URL_MALFORMAT`.
fn parse_port(port: &str) -> Result<u16> {
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::url("LDAP: malformed port in URL"));
    }
    port.parse::<u16>()
        .ok()
        .filter(|&p| p != 0)
        .ok_or_else(|| Error::url("LDAP: port out of range in URL"))
}

/// Percent-decode `s` with curl's `REJECT_ZERO` policy and return the result as
/// a UTF-8 [`String`].
///
/// Reproduces `Curl_urldecode(..., REJECT_ZERO)` from `lib/escape.c`: a `%`
/// followed by two hex digits decodes to that byte; any other `%` (or a `%` too
/// near the end) is kept literally; and any resulting NUL byte (`0x00`) — from a
/// `%00` escape or a literal NUL — is rejected. `+` is **not** turned into a
/// space (curl does no form-decoding here).
fn percent_decode_utf8(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let byte = if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            // Safe unwraps by construction: both nibbles are ASCII hex digits.
            let hi = hex_value(bytes[i + 1]);
            let lo = hex_value(bytes[i + 2]);
            i += 3;
            (hi << 4) | lo
        } else {
            let b = bytes[i];
            i += 1;
            b
        };

        // REJECT_ZERO: an unescaped or decoded NUL is a malformed URL.
        if byte == 0 {
            return Err(Error::url("LDAP: URL component contains a NUL byte"));
        }
        out.push(byte);
    }

    String::from_utf8(out)
        .map_err(|_| Error::url("LDAP: URL component is not valid UTF-8 after unescaping"))
}

/// Decode a single ASCII hex digit to its 0..=15 value. The caller guarantees
/// `b.is_ascii_hexdigit()`, so the `else` arm is unreachable in practice and
/// returns `0` defensively (no panic, per the crate's no-`unwrap` policy).
fn hex_value(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

// ===========================================================================
// LDIF output (← `openldap.c` `oldap_recv` + its `client_write` helper).
//
// This is the single most wire-observable surface of the LDAP handler: the
// bytes a search entry turns into are compared verbatim by the curl test
// corpus. The formatting is reproduced byte-for-byte, including the LDIF
// base64 double-colon (`attr:: <b64>`) for binary / non-printable values and
// the exact blank-line framing.
// ===========================================================================

/// `true` for the LDIF "blank" bytes curl's `ISBLANK` recognizes — an ASCII
/// space (`0x20`) or horizontal tab (`0x09`). A value whose first or last byte
/// is blank must be base64-encoded (LDIF "safe string" rule).
fn is_ldif_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// `true` for the printable bytes curl's `ISPRINT` recognizes — the ASCII
/// range `0x20..=0x7e`. Control bytes, `0x7f`, and every byte `>= 0x80` are
/// non-printable and force base64 encoding.
fn is_ldif_print(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

/// The exact analogue of `openldap.c`'s `client_write(data, prefix, plen,
/// value, len, suffix, slen)`.
///
/// Writes `prefix`, then `value` (when present), then `suffix` into `out`. The
/// one non-obvious rule is reproduced verbatim: **if the value is empty and the
/// prefix ends with a space separator, that trailing space is dropped** — this
/// is what turns an empty DN into `DN:` (not `DN: `) and an empty printable
/// value into a bare newline. `value == None` models curl's NULL `value`
/// pointer (used by the blank-line writes); a `Some(&[])` empty slice behaves
/// identically to a NULL pointer here because both have length zero.
fn client_write(out: &mut Vec<u8>, prefix: &[u8], value: Option<&[u8]>, suffix: &[u8]) {
    let value_len = value.map_or(0, |v| v.len());
    let mut plen = prefix.len();
    if value_len == 0 && plen > 0 && prefix[plen - 1] == b' ' {
        plen -= 1;
    }
    out.extend_from_slice(&prefix[..plen]);
    if let Some(v) = value {
        out.extend_from_slice(v);
    }
    out.extend_from_slice(suffix);
}

/// A single attribute of an [`LdapEntry`] (← one `ldap_get_attribute_ber`
/// iteration in `oldap_recv`).
///
/// The distinction curl draws between "the attribute has no value structure"
/// (`bvals == NULL`) and "the attribute has a (possibly empty) list of values"
/// is preserved by [`values`](LdapAttribute::values):
///
/// * [`None`] reproduces the `!bvals` branch — the attribute is emitted as
///   `\t<name>:\n` with **no** trailing blank line.
/// * [`Some`] reproduces the value loop — each value is emitted, then a single
///   trailing blank line.
///
/// The attribute name is matched case-insensitively against the `;binary`
/// suffix exactly as curl does (`curl_strnequal(.. , ";binary", 7)` when the
/// name is longer than seven bytes) to decide whether every value is forced to
/// base64.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LdapAttribute {
    /// The attribute description (e.g. `cn`, `jpegPhoto;binary`).
    pub name: String,
    /// The attribute's values as raw bytes, or [`None`] when the entry carried
    /// no value structure for this attribute.
    pub values: Option<Vec<Vec<u8>>>,
}

impl LdapAttribute {
    /// An attribute with an explicit (possibly empty) list of raw-byte values.
    pub fn with_values(name: impl Into<String>, values: Vec<Vec<u8>>) -> Self {
        LdapAttribute {
            name: name.into(),
            values: Some(values),
        }
    }

    /// An attribute that carried no value structure (curl's `bvals == NULL`),
    /// emitted as `\t<name>:\n`.
    pub fn no_values(name: impl Into<String>) -> Self {
        LdapAttribute {
            name: name.into(),
            values: None,
        }
    }

    /// Whether every value of this attribute is forced to base64 because the
    /// name ends (case-insensitively) with `;binary` and is longer than the
    /// suffix itself (← the `binary` flag in `oldap_recv`).
    #[must_use]
    pub fn is_binary(&self) -> bool {
        let name = self.name.as_bytes();
        name.len() > 7 && name[name.len() - 7..].eq_ignore_ascii_case(b";binary")
    }
}

/// One LDAP search-result entry (← a `LDAP_RES_SEARCH_ENTRY` message in
/// `oldap_recv`): a distinguished name plus its attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LdapEntry {
    /// The entry's distinguished name (← `ldap_get_dn_ber`).
    pub dn: String,
    /// The entry's attributes, in the order the server returned them.
    pub attributes: Vec<LdapAttribute>,
}

impl LdapEntry {
    /// Create an entry from a DN and its attributes.
    pub fn new(dn: impl Into<String>, attributes: Vec<LdapAttribute>) -> Self {
        LdapEntry {
            dn: dn.into(),
            attributes,
        }
    }

    /// Append this entry's LDIF byte stream to `out`, byte-for-byte identical to
    /// what `openldap.c`'s `oldap_recv` writes to the client for a
    /// `LDAP_RES_SEARCH_ENTRY`:
    ///
    /// * `DN: <dn>\n` (an empty DN collapses the separator to `DN:\n`);
    /// * for each attribute: either `\t<name>:\n` (no value structure) or, per
    ///   value, `\t<name>: <value>\n` for a printable value or
    ///   `\t<name>:: <base64>\n` for a `;binary` / non-printable / whitespace-
    ///   edged value, followed by a single blank line;
    /// * a final blank line terminating the entry.
    pub fn write_ldif(&self, out: &mut Vec<u8>) {
        // DN line (← client_write(STRCONST("DN: "), dn, STRCONST("\n"))).
        client_write(out, b"DN: ", Some(self.dn.as_bytes()), b"\n");

        for attr in &self.attributes {
            let name = attr.name.as_bytes();

            let Some(values) = &attr.values else {
                // No value structure: "\t<name>:\n", and NO trailing blank line
                // (curl `continue`s past the per-attribute blank write).
                client_write(out, b"\t", Some(name), b":\n");
                continue;
            };

            let binary = attr.is_binary();

            for value in values {
                // "\t<name>:" — the attribute name plus its single colon.
                client_write(out, b"\t", Some(name), b":");

                let binval = if binary {
                    false // already forced to base64 below
                } else if !value.is_empty()
                    && (is_ldif_blank(value[0]) || is_ldif_blank(value[value.len() - 1]))
                {
                    // Leading or trailing whitespace forces base64.
                    true
                } else {
                    // Any non-printable byte forces base64.
                    value.iter().any(|&b| !is_ldif_print(b))
                };

                if binary || binval {
                    // Base64 branch -> the LDIF double-colon: "\t<name>:: <b64>\n".
                    // curl only base64-encodes a non-empty value; an empty value
                    // collapses ": " to ":" giving "\t<name>::\n".
                    if value.is_empty() {
                        client_write(out, b": ", None, b"\n");
                    } else {
                        let encoded = BASE64.encode(value);
                        client_write(out, b": ", Some(encoded.as_bytes()), b"\n");
                    }
                } else {
                    // Printable branch: "\t<name>: <value>\n"; an empty value
                    // drops the space separator giving "\t<name>:\n".
                    client_write(out, b" ", Some(value), b"\n");
                }
            }

            // Blank line after this attribute's values.
            client_write(out, b"\n", None, b"");
        }

        // Blank line terminating the entry.
        client_write(out, b"\n", None, b"");
    }

    /// Return this entry's LDIF byte stream as a freshly allocated buffer.
    #[must_use]
    pub fn to_ldif(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_ldif(&mut out);
        out
    }
}

// ===========================================================================
// Protocol handler (← `Curl_protocol_ldap` in `openldap.c`).
//
// `mod.rs` registers both `SCHEME_LDAP` (PROTOPT_SSL_REUSE, port 389) and
// `SCHEME_LDAPS` (PROTOPT_SSL, port 636) against `&ldap::HANDLER`, so this
// module must expose exactly one `HANDLER` singleton that implements
// [`Protocol`]. The lifecycle methods map 1:1 onto curl's `oldap_*` vtable
// entries; the network bind/search is the sole part blocked on the missing
// pure-Rust LDAP crate (see the module `DEP NOTE`) and is marked `TODO(dep)`.
// ===========================================================================

/// The message surfaced (as `CURLE_NOT_BUILT_IN`) when an LDAP transfer is
/// actually attempted in a build where no pure-Rust LDAP backend is wired. It
/// is kept descriptive so the stderr text points a diagnosing user straight at
/// the dependency gap.
const LDAP_BACKEND_UNAVAILABLE: &str = "LDAP: no pure-Rust LDAP client backend is compiled in \
     (see DEP GAP in curl-rs-lib/src/protocols/ldap.rs); the `ldap` feature registers the \
     ldap/ldaps schemes but the bind/search backend crate is not yet wired";

/// The LDAP / LDAPS protocol handler (← `Curl_protocol_ldap`, `openldap.c`).
///
/// A zero-sized handler singleton, shared as `&'static dyn Protocol` by both the
/// `ldap` and `ldaps` scheme records in [`crate::protocols`]. All wire-observable
/// pure logic it relies on — [`LdapUrl::parse`] and [`LdapEntry::write_ldif`] —
/// is implemented and tested above; the connect/bind/search steps that require
/// the (missing) backend crate are documented against their `oldap_*` originals
/// and marked `TODO(dep)`.
#[derive(Debug, Default, Clone, Copy)]
pub struct LdapHandler;

/// The shared LDAP/LDAPS handler singleton referenced by `SCHEME_LDAP` and
/// `SCHEME_LDAPS` in [`crate::protocols`].
pub static HANDLER: LdapHandler = LdapHandler;

impl Protocol for LdapHandler {
    /// Establish the LDAP session (← `oldap_connect`).
    ///
    /// In curl this allocates the OpenLDAP handle over the already-connected
    /// socket (`ldap_init_fd`), pins protocol version 3, disables referral
    /// chasing, and then — depending on the scheme and options — begins the
    /// implicit-TLS handshake (`ldaps`), the STARTTLS upgrade (`ldap` +
    /// `--ssl`), a SASL-mechanism probe, or a simple bind, returning through the
    /// [`connecting`](Protocol::connecting) state machine.
    fn connect<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        // TODO(dep): requires an approved pure-Rust LDAP crate to allocate the
        // LDAP handle over the connected socket and start the bind. TODO(wiring):
        // requires TransferCtx to expose the owning `crate::conn::Connection`
        // (for the socket) and, for `ldaps`/STARTTLS, a `crate::tls::TlsConnector`
        // built from the transfer's `crate::tls::TlsConfig`. Until then the
        // protocol-connect is reported complete and the DO phase surfaces the gap.
        Box::pin(async { Ok(true) })
    }

    /// Drive the LDAP connect state machine (← `oldap_connecting`).
    ///
    /// In curl this pumps `ldap_result` and advances the `OLDAP_*` states
    /// (SSL → STARTTLS → TLS → MECHS → SASL → BIND/BINDV2), including the
    /// automatic fallback from protocol version 3 to version 2 on
    /// `LDAP_PROTOCOL_ERROR`, and installs the search receive path once bound.
    fn connecting<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        // TODO(dep): requires the LDAP crate to advance the bind/TLS handshake.
        Box::pin(async { Ok(true) })
    }

    /// Issue the search (← `oldap_do`).
    ///
    /// In curl this re-parses the URL, then calls `ldap_search_ext` with the
    /// base DN, [`scope`](LdapScope), filter, and requested attributes from
    /// [`LdapUrl`], streaming each result entry to the client as LDIF via
    /// `oldap_recv` (reproduced by [`LdapEntry::write_ldif`]). A search failure
    /// maps to `CURLE_LDAP_SEARCH_FAILED`.
    ///
    /// Because no pure-Rust LDAP backend is wired (module `DEP NOTE`), an
    /// attempted transfer cannot bind or search; this reports
    /// [`CurlCode::NotBuiltIn`] rather than silently producing empty output.
    fn do_it<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        // TODO(dep): requires an approved pure-Rust LDAP crate. When wired, this
        // parses the transfer URL via `LdapUrl::parse`, runs `bind` then `search`
        // (base/scope/filter/attributes), and streams each `LdapEntry` through
        // `LdapEntry::write_ldif` to the download callback — mapping a bind error
        // to CURLE_LDAP_CANNOT_BIND and a search error to CURLE_LDAP_SEARCH_FAILED.
        Box::pin(async {
            Err(Error::with_context(
                CurlCode::NotBuiltIn,
                LDAP_BACKEND_UNAVAILABLE,
            ))
        })
    }

    /// Tear down a completed or aborted search (← `oldap_done`).
    ///
    /// In curl this abandons any still-in-flight search message
    /// (`ldap_abandon_ext`) and drops the per-request state; it always returns
    /// success.
    fn done<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        status: Result<()>,
        premature: bool,
    ) -> ProtoFuture<'a, ()> {
        let _ = (ctx, status, premature);
        // TODO(dep): requires the LDAP crate to abandon an in-progress search.
        Box::pin(async { Ok(()) })
    }

    /// Disconnect the LDAP session (← `oldap_disconnect`).
    ///
    /// In curl this unbinds and frees the OpenLDAP handle (`ldap_unbind_ext`).
    fn disconnect<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        dead_connection: bool,
    ) -> ProtoFuture<'a, ()> {
        let _ = (ctx, dead_connection);
        // TODO(dep): requires the LDAP crate to unbind the session handle.
        Box::pin(async { Ok(()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;

    /// Minimal executor for the trivially-ready futures the handler returns
    /// (mirrors the `block_on` helper in `protocols/mod.rs`'s tests). No Tokio
    /// runtime is needed because none of these futures actually await I/O.
    fn block_on<F: Future>(fut: F) -> F::Output {
        use std::sync::Arc;
        use std::task::{Context, Poll, Wake, Waker};

        struct NoopWake;
        impl Wake for NoopWake {
            fn wake(self: Arc<Self>) {}
        }

        let waker = Waker::from(Arc::new(NoopWake));
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(fut);
        loop {
            if let Poll::Ready(value) = fut.as_mut().poll(&mut cx) {
                return value;
            }
        }
    }

    // ---- Scope ------------------------------------------------------------

    #[test]
    fn scope_integer_values_are_frozen() {
        assert_eq!(LDAP_SCOPE_BASE, 0);
        assert_eq!(LDAP_SCOPE_ONELEVEL, 1);
        assert_eq!(LDAP_SCOPE_SUBTREE, 2);
        assert_eq!(LdapScope::Base.as_i32(), 0);
        assert_eq!(LdapScope::OneLevel.as_i32(), 1);
        assert_eq!(LdapScope::Subtree.as_i32(), 2);
        assert_eq!(LdapScope::default(), LdapScope::Base);
    }

    #[test]
    fn scope_from_token_matches_str2scope() {
        // Short and long spellings, case-insensitive (curl's `str2scope`).
        assert_eq!(LdapScope::from_token("base"), Some(LdapScope::Base));
        assert_eq!(LdapScope::from_token("BASE"), Some(LdapScope::Base));
        assert_eq!(LdapScope::from_token("one"), Some(LdapScope::OneLevel));
        assert_eq!(LdapScope::from_token("onetree"), Some(LdapScope::OneLevel));
        assert_eq!(LdapScope::from_token("sub"), Some(LdapScope::Subtree));
        assert_eq!(LdapScope::from_token("subtree"), Some(LdapScope::Subtree));
        assert_eq!(LdapScope::from_token("SubTree"), Some(LdapScope::Subtree));
        // Anything else is rejected.
        assert_eq!(LdapScope::from_token("children"), None);
        assert_eq!(LdapScope::from_token(""), None);
    }

    // ---- URL parsing ------------------------------------------------------

    #[test]
    fn parse_full_url_all_components() {
        let u =
            LdapUrl::parse("ldap://ldap.example.com:389/dc=example,dc=com?cn,sn?sub?(uid=jdoe)")
                .expect("valid URL");
        assert!(!u.secure);
        assert_eq!(u.host, "ldap.example.com");
        assert_eq!(u.port, Some(389));
        assert_eq!(u.effective_port(), 389);
        assert_eq!(u.dn, "dc=example,dc=com");
        assert_eq!(u.attributes, vec!["cn".to_string(), "sn".to_string()]);
        assert_eq!(u.scope, LdapScope::Subtree);
        assert_eq!(u.filter, "(uid=jdoe)");
        assert!(u.extensions.is_empty());
    }

    #[test]
    fn parse_applies_curl_defaults() {
        // No path, no query: empty DN, all-attributes, base scope, default filter.
        let u = LdapUrl::parse("ldap://localhost/").expect("valid");
        assert_eq!(u.host, "localhost");
        assert_eq!(u.port, None);
        assert_eq!(u.effective_port(), PORT_LDAP);
        assert_eq!(u.dn, "");
        assert!(u.attributes.is_empty());
        assert_eq!(u.scope, LdapScope::Base);
        assert_eq!(u.filter, DEFAULT_FILTER);
        assert_eq!(u.filter, "(objectClass=*)");
    }

    #[test]
    fn parse_ldaps_uses_636_default_port() {
        let u = LdapUrl::parse("ldaps://secure.example.org/dc=x").expect("valid");
        assert!(u.secure);
        assert_eq!(u.port, None);
        assert_eq!(u.effective_port(), PORT_LDAPS);
        assert_eq!(u.dn, "dc=x");
    }

    #[test]
    fn parse_scheme_is_case_insensitive() {
        assert!(LdapUrl::parse("LDAP://h/").is_ok());
        assert!(LdapUrl::parse("LdApS://h/").expect("valid").secure);
    }

    #[test]
    fn parse_rejects_non_ldap_scheme() {
        let err = LdapUrl::parse("http://h/").unwrap_err();
        assert_eq!(err.code(), CurlCode::UrlMalformat);
    }

    #[test]
    fn parse_unescapes_dn_attrs_filter() {
        // %3D -> '=', %2A -> '*'. Empty DN preceding the query is allowed.
        let u = LdapUrl::parse("ldap://h/dc%3Dexample?cn?base?(cn=%2A)").expect("valid");
        assert_eq!(u.dn, "dc=example");
        assert_eq!(u.attributes, vec!["cn".to_string()]);
        assert_eq!(u.scope, LdapScope::Base);
        assert_eq!(u.filter, "(cn=*)");
    }

    #[test]
    fn parse_empty_dn_with_query() {
        let u = LdapUrl::parse("ldap://h/?mail?one?(uid=a)").expect("valid");
        assert_eq!(u.dn, "");
        assert_eq!(u.attributes, vec!["mail".to_string()]);
        assert_eq!(u.scope, LdapScope::OneLevel);
        assert_eq!(u.filter, "(uid=a)");
    }

    #[test]
    fn parse_percent_literal_when_not_two_hex() {
        // A '%' not followed by two hex digits is kept literally (curl behavior).
        assert_eq!(LdapUrl::parse("ldap://h/x%zz").expect("valid").dn, "x%zz");
        assert_eq!(LdapUrl::parse("ldap://h/50%").expect("valid").dn, "50%");
    }

    #[test]
    fn parse_does_not_form_decode_plus() {
        // '+' is NOT turned into a space (LDAP URLs are not form-encoded).
        assert_eq!(LdapUrl::parse("ldap://h/a+b").expect("valid").dn, "a+b");
    }

    #[test]
    fn parse_rejects_nul_byte_reject_zero() {
        let err = LdapUrl::parse("ldap://h/dc=%00").unwrap_err();
        assert_eq!(err.code(), CurlCode::UrlMalformat);
    }

    #[test]
    fn parse_rejects_non_utf8_component() {
        let err = LdapUrl::parse("ldap://h/%ff%fe").unwrap_err();
        assert_eq!(err.code(), CurlCode::UrlMalformat);
    }

    #[test]
    fn parse_rejects_bad_scope() {
        let err = LdapUrl::parse("ldap://h/dc=x?cn?bogus").unwrap_err();
        assert_eq!(err.code(), CurlCode::UrlMalformat);
    }

    #[test]
    fn parse_rejects_trailing_empty_extensions() {
        // A '?' that introduces an empty extensions field is malformed (curl's
        // `if(p && !*p)`).
        let err = LdapUrl::parse("ldap://h/dc=x?cn?sub?(f=1)?").unwrap_err();
        assert_eq!(err.code(), CurlCode::UrlMalformat);
    }

    #[test]
    fn parse_keeps_nonempty_extensions() {
        let u = LdapUrl::parse("ldap://h/dc=x?cn?sub?(f=1)?!ext=v").expect("valid");
        assert_eq!(u.extensions, vec!["!ext=v".to_string()]);
        assert_eq!(u.filter, "(f=1)");
    }

    #[test]
    fn parse_ipv6_host_with_and_without_port() {
        let u = LdapUrl::parse("ldap://[2001:db8::1]:389/dc=x").expect("valid");
        assert_eq!(u.host, "2001:db8::1");
        assert_eq!(u.port, Some(389));

        let u = LdapUrl::parse("ldaps://[::1]/dc=x").expect("valid");
        assert_eq!(u.host, "::1");
        assert_eq!(u.port, None);
        assert_eq!(u.effective_port(), PORT_LDAPS);
    }

    #[test]
    fn parse_empty_host_allowed() {
        let u = LdapUrl::parse("ldap:///dc=example").expect("valid");
        assert_eq!(u.host, "");
        assert_eq!(u.dn, "dc=example");
    }

    #[test]
    fn parse_rejects_bad_port() {
        assert_eq!(
            LdapUrl::parse("ldap://h:0/").unwrap_err().code(),
            CurlCode::UrlMalformat
        );
        assert_eq!(
            LdapUrl::parse("ldap://h:notaport/").unwrap_err().code(),
            CurlCode::UrlMalformat
        );
        assert_eq!(
            LdapUrl::parse("ldap://h:99999/").unwrap_err().code(),
            CurlCode::UrlMalformat
        );
    }

    #[test]
    fn parse_attribute_length_cap_stops_parsing() {
        // A token longer than MAX_ATTR_LEN stops attribute parsing (curl's
        // `curlx_str_until(.., 1024, ',')` break), keeping earlier attributes.
        let long = "a".repeat(MAX_ATTR_LEN + 1);
        let url = format!("ldap://h/dc=x?short,{long}");
        let u = LdapUrl::parse(&url).expect("valid");
        assert_eq!(u.attributes, vec!["short".to_string()]);
    }

    // ---- LDIF formatting --------------------------------------------------

    #[test]
    fn ldif_simple_printable_entry() {
        let entry = LdapEntry::new(
            "cn=John Doe,dc=example,dc=com",
            vec![
                LdapAttribute::with_values("cn", vec![b"John Doe".to_vec()]),
                LdapAttribute::with_values("sn", vec![b"Doe".to_vec()]),
            ],
        );
        let ldif = entry.to_ldif();
        assert_eq!(
            ldif,
            b"DN: cn=John Doe,dc=example,dc=com\n\tcn: John Doe\n\n\tsn: Doe\n\n\n".to_vec()
        );
    }

    #[test]
    fn ldif_empty_dn_collapses_separator() {
        let entry = LdapEntry::new("", vec![]);
        assert_eq!(entry.to_ldif(), b"DN:\n\n".to_vec());
    }

    #[test]
    fn ldif_binary_suffix_forces_base64_double_colon() {
        let entry = LdapEntry::new(
            "dc=x",
            vec![LdapAttribute::with_values(
                "photo;binary",
                vec![vec![0x01, 0x02, 0x03]],
            )],
        );
        // base64([1,2,3]) == "AQID"; the double colon comes from ":" + ": ".
        assert_eq!(
            entry.to_ldif(),
            b"DN: dc=x\n\tphoto;binary:: AQID\n\n\n".to_vec()
        );
    }

    #[test]
    fn ldif_nonprintable_value_forces_base64() {
        let entry = LdapEntry::new(
            "dc=x",
            vec![LdapAttribute::with_values("desc", vec![vec![0xFF]])],
        );
        // base64([0xFF]) == "/w==".
        assert_eq!(entry.to_ldif(), b"DN: dc=x\n\tdesc:: /w==\n\n\n".to_vec());
    }

    #[test]
    fn ldif_whitespace_edges_force_base64() {
        // Leading space.
        let e1 = LdapEntry::new(
            "",
            vec![LdapAttribute::with_values("cn", vec![b" hi".to_vec()])],
        );
        assert_eq!(e1.to_ldif(), b"DN:\n\tcn:: IGhp\n\n\n".to_vec());
        // Trailing space.
        let e2 = LdapEntry::new(
            "",
            vec![LdapAttribute::with_values("cn", vec![b"hi ".to_vec()])],
        );
        assert_eq!(e2.to_ldif(), b"DN:\n\tcn:: aGkg\n\n\n".to_vec());
        // Interior space is fine (stays printable).
        let e3 = LdapEntry::new(
            "",
            vec![LdapAttribute::with_values("cn", vec![b"h i".to_vec()])],
        );
        assert_eq!(e3.to_ldif(), b"DN:\n\tcn: h i\n\n\n".to_vec());
    }

    #[test]
    fn ldif_empty_printable_value() {
        let entry = LdapEntry::new("", vec![LdapAttribute::with_values("cn", vec![Vec::new()])]);
        assert_eq!(entry.to_ldif(), b"DN:\n\tcn:\n\n\n".to_vec());
    }

    #[test]
    fn ldif_empty_binary_value() {
        let entry = LdapEntry::new(
            "",
            vec![LdapAttribute::with_values("x;binary", vec![Vec::new()])],
        );
        assert_eq!(entry.to_ldif(), b"DN:\n\tx;binary::\n\n\n".to_vec());
    }

    #[test]
    fn ldif_attribute_without_value_structure() {
        // `no_values` reproduces curl's `bvals == NULL` branch: "\t<name>:\n"
        // with NO trailing per-attribute blank line.
        let entry = LdapEntry::new("", vec![LdapAttribute::no_values("cn")]);
        assert_eq!(entry.to_ldif(), b"DN:\n\tcn:\n\n".to_vec());
    }

    #[test]
    fn ldif_multiple_values_one_attribute() {
        let entry = LdapEntry::new(
            "",
            vec![LdapAttribute::with_values(
                "mail",
                vec![b"a@x".to_vec(), b"b@x".to_vec()],
            )],
        );
        assert_eq!(
            entry.to_ldif(),
            b"DN:\n\tmail: a@x\n\tmail: b@x\n\n\n".to_vec()
        );
    }

    #[test]
    fn ldif_is_binary_detection() {
        assert!(LdapAttribute::with_values("jpegPhoto;binary", vec![]).is_binary());
        assert!(LdapAttribute::with_values("X;BINARY", vec![]).is_binary());
        // Exactly ";binary" (length 7) is NOT treated as binary (curl uses `> 7`).
        assert!(!LdapAttribute::with_values(";binary", vec![]).is_binary());
        assert!(!LdapAttribute::with_values("cn", vec![]).is_binary());
    }

    // ---- Protocol handler -------------------------------------------------

    #[test]
    fn handler_is_object_safe_and_defaults_ok() {
        let handler: &dyn Protocol = &HANDLER;
        let mut ctx = TransferCtx::new();
        assert!(block_on(handler.connect(&mut ctx)).expect("connect ok"));
        assert!(block_on(handler.connecting(&mut ctx)).expect("connecting ok"));
        block_on(handler.done(&mut ctx, Ok(()), false)).expect("done ok");
        block_on(handler.disconnect(&mut ctx, false)).expect("disconnect ok");
    }

    #[test]
    fn do_it_reports_backend_dependency_gap() {
        let mut ctx = TransferCtx::new();
        let err = block_on(HANDLER.do_it(&mut ctx)).expect_err("must report the gap");
        // Honest "not compiled in" until a pure-Rust LDAP backend is wired.
        assert_eq!(err.code(), CurlCode::NotBuiltIn);
    }
}
