// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-FileCopyrightText: Howard Chu, <hyc@openldap.org>

//! LDAP / LDAPS protocol handler — the memory-safe Rust port of curl's LDAP
//! support for the byte-for-byte functional-parity rewrite of curl / libcurl
//! **8.19.0-DEV**.
//!
//! # A self-contained, pure-Rust LDAPv3 client (no `libldap` / `liblber`)
//!
//! curl implements LDAP by **linking the C libraries `libldap` + `liblber`**
//! (`ldap_init_fd`, `ldap_url_parse`, `ldap_sasl_bind`, `ldap_search_ext`, the
//! `ber_*` family). The rewrite forbids C-library linkage (AAP §0.7.2), so this
//! module speaks LDAPv3 (RFC 4511) **directly on the wire**: it hand-rolls the
//! small definite-length BER/DER subset LDAP uses — exactly as the SMB, TFTP,
//! and TELNET handlers hand-roll their own wire framing — encoding the
//! `bindRequest` / `searchRequest` / `unbindRequest` PDUs and decoding the
//! `bindResponse` / `searchResultEntry` / `searchResultDone` replies. No C FFI
//! is introduced anywhere, no external ASN.1 crate is added, and the module
//! contains **zero** memory-unchecked code (the crate root sets the
//! `#![forbid(...)]` safe-code lint); every BER read is bounds-checked and a
//! truncated or malformed frame yields `CURLE_WEIRD_SERVER_REPLY`, never a
//! panic.
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
//! # Flow
//!
//! * [`LdapUrl::parse`] reproduces curl's exact URL decomposition, defaulting,
//!   and percent-unescaping (`ldap_url_parse2_low`). The DN, attribute, and
//!   filter components are decoded to **raw bytes** (`REJECT_ZERO` only, no
//!   UTF-8 coercion) so byte-exact LDAP syntax survives the round-trip to the
//!   wire, exactly as curl keeps them as `char*`.
//! * [`LdapHandler::do_it`](Protocol::do_it) drives the whole exchange over the
//!   live [`TransferCtx::io`] stream — a simple `bind`, then a `search` whose
//!   [`filter`](LdapUrl::filter) is compiled from its RFC 4515 string into a BER
//!   `Filter`, then each returned entry is streamed to the client sink as LDIF,
//!   then an `unbind` — collapsing curl's `oldap_connect` / `oldap_do` /
//!   `oldap_recv` sequence into one async future (the same collapsed-lifecycle
//!   shape the crate's other stream handlers use).
//! * [`LdapEntry::write_ldif`] reproduces `oldap_recv`'s exact LDIF byte stream,
//!   including the base64 double-colon (`attr:: <b64>`) for binary /
//!   non-printable values and the blank-line framing.
//!
//! # Transport, TLS and authentication scope
//!
//! * **`ldaps://` (implicit TLS)** is handled transparently: the connection
//!   filter chain (AAP §0.3.2) TLS-wraps [`TransferCtx::io`] before the handler
//!   runs — plain TCP for `ldap`, a `rustls` stream for `ldaps` — so this module
//!   speaks identical LDAP bytes over either, with no `crate::tls` coupling.
//! * **Simple bind** (name + password, anonymous when no username is set) is
//!   curl's default bind and the one `oldap_do` issues unless a SASL mechanism
//!   is explicitly requested; it is implemented in full here. SASL-mechanism
//!   binds and the in-band STARTTLS upgrade (`ldap://` + `--ssl`) depend on the
//!   cross-cutting `crate::auth` SASL machinery and a mid-stream socket TLS
//!   upgrade owned by the connection-filter layer respectively, neither of which
//!   this self-contained protocol module owns; the default simple-bind flow that
//!   the curl LDAP test corpus exercises is complete.

use crate::error::{CurlCode, Error, Result};
use crate::protocols::{ProtoFuture, Protocol, TransferCtx};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
/// `REJECT_ZERO` policy (an unescaped NUL byte is rejected as a malformed URL)
/// and are kept as **raw decoded bytes** — curl passes them to the LDAP library
/// as `char*` byte strings subject to LDAP syntax, *not* validated as UTF-8, so
/// a valid input carrying raw (e.g. Latin-1 or otherwise non-UTF-8) bytes is
/// preserved rather than rejected. Conversion to text happens only at the
/// backend boundary where the protocol genuinely requires it (e.g. an attribute
/// name emitted into LDIF), never at parse time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LdapUrl {
    /// `true` for the `ldaps://` scheme (implicit TLS), `false` for `ldap://`.
    pub secure: bool,
    /// The host component (may be empty, e.g. `ldap:///dc=example` — curl reads
    /// the host from the connection in that case).
    pub host: String,
    /// The explicit port, or `None` to use [`PORT_LDAP`] / [`PORT_LDAPS`].
    pub port: Option<u16>,
    /// The base distinguished name to search from (← `lud_dn`), as raw decoded
    /// bytes (not coerced to UTF-8).
    pub dn: Vec<u8>,
    /// The requested attribute list (← `lud_attrs`), each as raw decoded bytes;
    /// empty means all attributes.
    pub attributes: Vec<Vec<u8>>,
    /// The search scope (← `lud_scope`).
    pub scope: LdapScope,
    /// The search filter (← `lud_filter`) as raw decoded bytes;
    /// [`DEFAULT_FILTER`] when omitted.
    pub filter: Vec<u8>,
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
            Vec::new()
        } else {
            percent_decode_bytes(dn_raw)?
        };

        let mut out = LdapUrl {
            secure,
            host,
            port,
            dn,
            attributes: Vec::new(),
            scope: LdapScope::Base,
            filter: DEFAULT_FILTER.as_bytes().to_vec(),
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
                self.attributes.push(percent_decode_bytes(token)?);
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
            self.filter = percent_decode_bytes(filter_seg)?;
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

/// Percent-decode `s` with curl's `REJECT_ZERO` policy and return the **raw
/// decoded bytes**.
///
/// Reproduces `Curl_urldecode(..., REJECT_ZERO)` from `lib/escape.c`: a `%`
/// followed by two hex digits decodes to that byte; any other `%` (or a `%` too
/// near the end) is kept literally; and any resulting NUL byte (`0x00`) — from a
/// `%00` escape or a literal NUL — is rejected. `+` is **not** turned into a
/// space (curl does no form-decoding here).
///
/// The bytes are returned verbatim — **not** validated as UTF-8 — because curl
/// hands the decoded DN / attribute / filter to the LDAP library as a `char*`
/// byte string subject to LDAP syntax, not as a UTF-8-validated string. Keeping
/// the raw bytes means a valid input carrying non-UTF-8 bytes is preserved
/// rather than rejected (see [`LdapUrl`]).
fn percent_decode_bytes(s: &str) -> Result<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let byte = if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            // Both nibbles are ASCII hex digits by the guard above.
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

    Ok(out)
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
// BER / DER wire codec (← the `ber_*` family curl reaches through `liblber`).
//
// LDAPv3 (RFC 4511) frames every PDU as definite-length BER. This is the small,
// self-contained subset needed to encode the bind/search/unbind requests and
// decode the bind/search responses — hand-rolled exactly as the SMB, TFTP, and
// TELNET handlers hand-roll their wire framing, so no C `liblber` and no
// external ASN.1 crate is pulled in. Every decode is bounds-checked: a
// truncated or malformed element yields `CURLE_WEIRD_SERVER_REPLY`, never a
// panic.
// ===========================================================================

// Universal tags.
const BER_BOOLEAN: u8 = 0x01;
const BER_INTEGER: u8 = 0x02;
const BER_OCTET_STRING: u8 = 0x04;
const BER_ENUMERATED: u8 = 0x0a;
const BER_SEQUENCE: u8 = 0x30; // constructed
const BER_SET: u8 = 0x31; // constructed

// LDAP protocol-op tags (application class).
const LDAP_REQ_BIND: u8 = 0x60; // [APPLICATION 0] constructed
const LDAP_RES_BIND: u8 = 0x61; // [APPLICATION 1] constructed
const LDAP_REQ_UNBIND: u8 = 0x42; // [APPLICATION 2] primitive (NULL)
const LDAP_REQ_SEARCH: u8 = 0x63; // [APPLICATION 3] constructed
const LDAP_RES_SEARCH_ENTRY: u8 = 0x64; // [APPLICATION 4] constructed
const LDAP_RES_SEARCH_DONE: u8 = 0x65; // [APPLICATION 5] constructed
const LDAP_RES_SEARCH_REFERENCE: u8 = 0x73; // [APPLICATION 19] constructed

// Authentication choice: [CONTEXT 0] primitive — simple (password) bind.
const LDAP_AUTH_SIMPLE: u8 = 0x80;

// Filter choice tags (RFC 4511 §4.5.1), context class.
const FILTER_AND: u8 = 0xa0; // [0] constructed
const FILTER_OR: u8 = 0xa1; // [1] constructed
const FILTER_NOT: u8 = 0xa2; // [2] constructed
const FILTER_EQUALITY: u8 = 0xa3; // [3] constructed
const FILTER_SUBSTRINGS: u8 = 0xa4; // [4] constructed
const FILTER_GREATER_OR_EQUAL: u8 = 0xa5; // [5] constructed
const FILTER_LESS_OR_EQUAL: u8 = 0xa6; // [6] constructed
const FILTER_PRESENT: u8 = 0x87; // [7] primitive
const FILTER_APPROX_MATCH: u8 = 0xa8; // [8] constructed

// Substring choice tags (context class, primitive).
const SUBSTR_INITIAL: u8 = 0x80; // [0]
const SUBSTR_ANY: u8 = 0x81; // [1]
const SUBSTR_FINAL: u8 = 0x82; // [2]

// A hard cap on a single inbound PDU so a hostile length prefix cannot force an
// unbounded allocation (curl bounds `liblber` similarly via `ber_get_next`).
const MAX_LDAP_PDU: usize = 8 * 1024 * 1024;

/// The error a malformed / truncated BER element maps to (curl surfaces a bad
/// server frame as `CURLE_WEIRD_SERVER_REPLY`).
fn ber_err() -> Error {
    Error::with_context(
        CurlCode::WeirdServerReply,
        "LDAP: malformed BER in server response",
    )
}

/// Append the BER definite-length encoding of `len` to `out`.
fn ber_push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    // Long form: `0x80 | number-of-length-bytes`, then the big-endian length
    // with leading zero bytes stripped.
    let bytes = len.to_be_bytes();
    let first = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = &bytes[first..];
    out.push(0x80 | significant.len() as u8);
    out.extend_from_slice(significant);
}

/// Append a full tag-length-value element with the given `tag` and `contents`.
fn ber_tlv(out: &mut Vec<u8>, tag: u8, contents: &[u8]) {
    out.push(tag);
    ber_push_len(out, contents.len());
    out.extend_from_slice(contents);
}

/// The minimal two's-complement content bytes of a (non-negative, small) LDAP
/// integer — version, message id, scope, `derefAliases`, size/time limits.
fn ber_int_contents(mut value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    let mut buf = Vec::new();
    while value != 0 {
        buf.push((value & 0xff) as u8);
        value >>= 8;
    }
    // If the most-significant retained byte has its sign bit set, prepend a
    // `0x00` so a positive value is not misread as negative.
    if buf.last().is_some_and(|&b| b & 0x80 != 0) {
        buf.push(0);
    }
    buf.reverse();
    buf
}

/// Append an INTEGER (`BER_INTEGER`) or ENUMERATED (`BER_ENUMERATED`).
fn ber_int(out: &mut Vec<u8>, tag: u8, value: i64) {
    let contents = ber_int_contents(value);
    ber_tlv(out, tag, &contents);
}

/// Append a BOOLEAN.
fn ber_bool(out: &mut Vec<u8>, value: bool) {
    ber_tlv(out, BER_BOOLEAN, &[if value { 0xff } else { 0x00 }]);
}

/// A bounds-checked cursor over a BER buffer — the LDAP decode counterpart to
/// the SMB frame parser's checked slice readers.
struct BerReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> BerReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        BerReader { buf, pos: 0 }
    }

    /// `true` once the whole buffer has been consumed.
    fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Read one element, returning `(tag, contents)` and advancing past it.
    fn read_tlv(&mut self) -> Result<(u8, &'a [u8])> {
        let tag = *self.buf.get(self.pos).ok_or_else(ber_err)?;
        self.pos += 1;
        let first = *self.buf.get(self.pos).ok_or_else(ber_err)?;
        self.pos += 1;
        let len = if first < 0x80 {
            first as usize
        } else {
            let n = (first & 0x7f) as usize;
            // Reject the indefinite form (`n == 0`) and absurd lengths; LDAP
            // uses definite lengths that comfortably fit in four bytes.
            if n == 0 || n > 4 {
                return Err(ber_err());
            }
            let mut value = 0usize;
            for _ in 0..n {
                let b = *self.buf.get(self.pos).ok_or_else(ber_err)?;
                self.pos += 1;
                value = (value << 8) | b as usize;
            }
            value
        };
        let end = self.pos.checked_add(len).ok_or_else(ber_err)?;
        let contents = self.buf.get(self.pos..end).ok_or_else(ber_err)?;
        self.pos = end;
        Ok((tag, contents))
    }

    /// Read one element and require it to carry the expected `tag`.
    fn read_expect(&mut self, tag: u8) -> Result<&'a [u8]> {
        let (got, contents) = self.read_tlv()?;
        if got != tag {
            return Err(ber_err());
        }
        Ok(contents)
    }

    /// Read an INTEGER / ENUMERATED as an `i64`.
    fn read_int(&mut self) -> Result<i64> {
        let (tag, contents) = self.read_tlv()?;
        if (tag != BER_INTEGER && tag != BER_ENUMERATED)
            || contents.is_empty()
            || contents.len() > 8
        {
            return Err(ber_err());
        }
        // Sign-extend from the leading byte.
        let mut value: i64 = if contents[0] & 0x80 != 0 { -1 } else { 0 };
        for &b in contents {
            value = (value << 8) | i64::from(b);
        }
        Ok(value)
    }
}

// ===========================================================================
// RFC 4515 filter string -> BER `Filter` (← what `ldap_search_ext` compiles the
// `lud_filter` string into internally before putting it on the wire).
// ===========================================================================

/// The error a malformed filter string maps to.
fn filter_err() -> Error {
    Error::with_context(CurlCode::LdapSearchFailed, "LDAP: malformed search filter")
}

/// Compile an RFC 4515 filter string (raw bytes) into its BER `Filter` encoding.
fn encode_filter(filter: &[u8]) -> Result<Vec<u8>> {
    let mut parser = FilterParser {
        buf: filter,
        pos: 0,
    };
    let out = parser.parse_filter()?;
    // A single top-level filter must consume the whole string.
    if parser.pos != filter.len() {
        return Err(filter_err());
    }
    Ok(out)
}

struct FilterParser<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl FilterParser<'_> {
    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    /// `filter = "(" filtercomp ")"`.
    fn parse_filter(&mut self) -> Result<Vec<u8>> {
        if self.bump() != Some(b'(') {
            return Err(filter_err());
        }
        let out = self.parse_comp()?;
        if self.bump() != Some(b')') {
            return Err(filter_err());
        }
        Ok(out)
    }

    /// `filtercomp = and / or / not / item`.
    fn parse_comp(&mut self) -> Result<Vec<u8>> {
        match self.peek() {
            Some(b'&') => {
                self.pos += 1;
                self.parse_set(FILTER_AND)
            }
            Some(b'|') => {
                self.pos += 1;
                self.parse_set(FILTER_OR)
            }
            Some(b'!') => {
                self.pos += 1;
                let inner = self.parse_filter()?;
                let mut out = Vec::new();
                ber_tlv(&mut out, FILTER_NOT, &inner);
                Ok(out)
            }
            _ => self.parse_item(),
        }
    }

    /// `and / or = tag SET OF filter` — one or more nested `(...)` filters.
    fn parse_set(&mut self, tag: u8) -> Result<Vec<u8>> {
        if self.peek() != Some(b'(') {
            return Err(filter_err());
        }
        let mut inner = Vec::new();
        while self.peek() == Some(b'(') {
            inner.extend_from_slice(&self.parse_filter()?);
        }
        let mut out = Vec::new();
        ber_tlv(&mut out, tag, &inner);
        Ok(out)
    }

    /// `item = attr OP value` — an equality / present / substring / relational
    /// assertion.
    fn parse_item(&mut self) -> Result<Vec<u8>> {
        // Attribute description: up to the first operator or paren.
        let start = self.pos;
        while let Some(c) = self.peek() {
            if matches!(c, b'=' | b'<' | b'>' | b'~' | b'(' | b')') {
                break;
            }
            self.pos += 1;
        }
        let attr = &self.buf[start..self.pos];
        if attr.is_empty() {
            return Err(filter_err());
        }

        let op = self.bump().ok_or_else(filter_err)?;
        // The three two-character operators consume their trailing '='.
        let tag = match op {
            b'=' => FILTER_EQUALITY, // may be reclassified as present/substrings
            b'<' => {
                if self.bump() != Some(b'=') {
                    return Err(filter_err());
                }
                FILTER_LESS_OR_EQUAL
            }
            b'>' => {
                if self.bump() != Some(b'=') {
                    return Err(filter_err());
                }
                FILTER_GREATER_OR_EQUAL
            }
            b'~' => {
                if self.bump() != Some(b'=') {
                    return Err(filter_err());
                }
                FILTER_APPROX_MATCH
            }
            _ => return Err(filter_err()),
        };

        // Assertion value: up to the closing ')'.
        let vstart = self.pos;
        while let Some(c) = self.peek() {
            if c == b')' {
                break;
            }
            self.pos += 1;
        }
        let raw = &self.buf[vstart..self.pos];

        if tag == FILTER_EQUALITY {
            // "(attr=*)" is a presence test, not equality with a literal '*'.
            if raw == b"*" {
                let mut out = Vec::new();
                ber_tlv(&mut out, FILTER_PRESENT, attr);
                return Ok(out);
            }
            // An unescaped '*' anywhere else marks a substring filter.
            if raw.contains(&b'*') {
                return encode_substrings(attr, raw);
            }
        }

        let value = unescape_filter_value(raw)?;
        Ok(encode_ava(tag, attr, &value))
    }
}

/// Encode an `AttributeValueAssertion` filter (`equality`, `>=`, `<=`, `~=`).
fn encode_ava(tag: u8, attr: &[u8], value: &[u8]) -> Vec<u8> {
    let mut ava = Vec::new();
    ber_tlv(&mut ava, BER_OCTET_STRING, attr);
    ber_tlv(&mut ava, BER_OCTET_STRING, value);
    let mut out = Vec::new();
    ber_tlv(&mut out, tag, &ava);
    out
}

/// Encode a `substrings` filter from a value containing one or more `*` marks.
fn encode_substrings(attr: &[u8], raw: &[u8]) -> Result<Vec<u8>> {
    let segments = split_unescaped_star(raw);
    let last = segments.len() - 1;
    let mut subs = Vec::new();
    for (i, seg) in segments.iter().enumerate() {
        if seg.is_empty() {
            continue; // a wildcard at this position — no substring component
        }
        let choice = if i == 0 {
            SUBSTR_INITIAL
        } else if i == last {
            SUBSTR_FINAL
        } else {
            SUBSTR_ANY
        };
        let value = unescape_filter_value(seg)?;
        ber_tlv(&mut subs, choice, &value);
    }
    // SubstringFilter ::= SEQUENCE { type OCTET STRING, substrings SEQUENCE OF }
    let mut sf = Vec::new();
    ber_tlv(&mut sf, BER_OCTET_STRING, attr);
    ber_tlv(&mut sf, BER_SEQUENCE, &subs);
    let mut out = Vec::new();
    ber_tlv(&mut out, FILTER_SUBSTRINGS, &sf);
    Ok(out)
}

/// Split a filter value on each **unescaped** `*`, returning the `N+1` segments
/// around the `N` wildcards (empty segments mark a leading / trailing / adjacent
/// `*`).
fn split_unescaped_star(raw: &[u8]) -> Vec<&[u8]> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'\\' => {
                // Skip the backslash and the byte it escapes so an escaped '*'
                // is never treated as a wildcard.
                i += 2;
            }
            b'*' => {
                parts.push(&raw[start..i]);
                start = i + 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    parts.push(&raw[start..]);
    parts
}

/// Decode RFC 4515 `\XX` escapes in a filter assertion value to raw bytes.
fn unescape_filter_value(raw: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\\' {
            let hi = *raw.get(i + 1).ok_or_else(filter_err)?;
            let lo = *raw.get(i + 2).ok_or_else(filter_err)?;
            if !hi.is_ascii_hexdigit() || !lo.is_ascii_hexdigit() {
                return Err(filter_err());
            }
            out.push((hex_value(hi) << 4) | hex_value(lo));
            i += 3;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    Ok(out)
}

// ===========================================================================
// LDAP PDU builders + response decoders (RFC 4511 §4).
// ===========================================================================

/// Wrap a protocol op in an `LDAPMessage` SEQUENCE with its message id.
fn encode_message(msgid: i64, op_tag: u8, op_contents: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    ber_int(&mut inner, BER_INTEGER, msgid);
    ber_tlv(&mut inner, op_tag, op_contents);
    let mut out = Vec::new();
    ber_tlv(&mut out, BER_SEQUENCE, &inner);
    out
}

/// Build a simple `bindRequest` (LDAPv3, name + password authentication).
fn build_bind_request(msgid: i64, name: &[u8], password: &[u8]) -> Vec<u8> {
    let mut op = Vec::new();
    ber_int(&mut op, BER_INTEGER, 3); // version = 3
    ber_tlv(&mut op, BER_OCTET_STRING, name); // bind DN
    ber_tlv(&mut op, LDAP_AUTH_SIMPLE, password); // [0] simple
    encode_message(msgid, LDAP_REQ_BIND, &op)
}

/// Build a `searchRequest` from a parsed [`LdapUrl`] and compiled filter.
fn build_search_request(
    msgid: i64,
    base: &[u8],
    scope: i64,
    filter_ber: &[u8],
    attributes: &[Vec<u8>],
) -> Vec<u8> {
    let mut op = Vec::new();
    ber_tlv(&mut op, BER_OCTET_STRING, base); // baseObject
    ber_int(&mut op, BER_ENUMERATED, scope); // scope
    ber_int(&mut op, BER_ENUMERATED, 0); // derefAliases = neverDerefAliases
    ber_int(&mut op, BER_INTEGER, 0); // sizeLimit = 0 (no limit)
    ber_int(&mut op, BER_INTEGER, 0); // timeLimit = 0 (no limit)
    ber_bool(&mut op, false); // typesOnly = FALSE
    op.extend_from_slice(filter_ber); // filter
                                      // AttributeSelection ::= SEQUENCE OF LDAPString.
    let mut attrsel = Vec::new();
    for attr in attributes {
        ber_tlv(&mut attrsel, BER_OCTET_STRING, attr);
    }
    ber_tlv(&mut op, BER_SEQUENCE, &attrsel);
    encode_message(msgid, LDAP_REQ_SEARCH, &op)
}

/// Build an `unbindRequest` (`[APPLICATION 2] NULL`).
fn build_unbind_request(msgid: i64) -> Vec<u8> {
    encode_message(msgid, LDAP_REQ_UNBIND, &[])
}

/// Decode an `LDAPMessage` body into `(message_id, protocol_op_tag, op_body)`.
fn parse_message(pdu: &[u8]) -> Result<(i64, u8, &[u8])> {
    let mut reader = BerReader::new(pdu);
    let msgid = reader.read_int()?;
    let (tag, body) = reader.read_tlv()?;
    Ok((msgid, tag, body))
}

/// Read the `resultCode` from an `LDAPResult`-shaped op body — the shared prefix
/// of `bindResponse` and `searchResultDone`.
fn parse_result_code(op: &[u8]) -> Result<i64> {
    BerReader::new(op).read_int()
}

/// Decode a `searchResultEntry` into an [`LdapEntry`]. The DN and attribute
/// names are converted to text **here, at the backend boundary** (curl uses the
/// DN and attribute description as C strings when formatting LDIF); attribute
/// *values* stay raw bytes.
fn parse_search_entry(op: &[u8]) -> Result<LdapEntry> {
    let mut reader = BerReader::new(op);
    let dn = reader.read_expect(BER_OCTET_STRING)?; // objectName LDAPDN
    let attr_list = reader.read_expect(BER_SEQUENCE)?; // PartialAttributeList

    let mut attributes = Vec::new();
    let mut attrs = BerReader::new(attr_list);
    while !attrs.at_end() {
        let one = attrs.read_expect(BER_SEQUENCE)?; // PartialAttribute
        let mut field = BerReader::new(one);
        let name = field.read_expect(BER_OCTET_STRING)?; // type
        let vals = field.read_expect(BER_SET)?; // vals SET OF value

        let mut values = Vec::new();
        let mut value_reader = BerReader::new(vals);
        while !value_reader.at_end() {
            let value = value_reader.read_expect(BER_OCTET_STRING)?;
            values.push(value.to_vec());
        }
        attributes.push(LdapAttribute::with_values(
            String::from_utf8_lossy(name).into_owned(),
            values,
        ));
    }

    Ok(LdapEntry::new(
        String::from_utf8_lossy(dn).into_owned(),
        attributes,
    ))
}

// ===========================================================================
// Async transport (← `oldap_connect` / `oldap_do` / `oldap_recv`, collapsed
// into one future because a Rust future can `.await` the socket directly).
// ===========================================================================

/// Send a whole PDU and flush it.
async fn send_pdu<S: AsyncWrite + Unpin + ?Sized>(stream: &mut S, pdu: &[u8]) -> Result<()> {
    stream
        .write_all(pdu)
        .await
        .map_err(|_| Error::with_context(CurlCode::SendError, "LDAP: sending request"))?;
    stream
        .flush()
        .await
        .map_err(|_| Error::with_context(CurlCode::SendError, "LDAP: flushing request"))?;
    Ok(())
}

/// Read exactly one `LDAPMessage` from `stream`, returning the SEQUENCE contents
/// (message id + protocol op) — the slice [`parse_message`] expects.
async fn read_pdu<S: AsyncRead + Unpin + ?Sized>(stream: &mut S) -> Result<Vec<u8>> {
    let recv_err = || Error::with_context(CurlCode::RecvError, "LDAP: reading server response");

    // Outer SEQUENCE tag.
    let mut tag = [0u8; 1];
    stream.read_exact(&mut tag).await.map_err(|_| recv_err())?;
    if tag[0] != BER_SEQUENCE {
        return Err(ber_err());
    }

    // Definite length.
    let mut first = [0u8; 1];
    stream
        .read_exact(&mut first)
        .await
        .map_err(|_| recv_err())?;
    let len = if first[0] < 0x80 {
        first[0] as usize
    } else {
        let n = (first[0] & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err(ber_err());
        }
        let mut raw = [0u8; 4];
        stream
            .read_exact(&mut raw[..n])
            .await
            .map_err(|_| recv_err())?;
        let mut value = 0usize;
        for &b in &raw[..n] {
            value = (value << 8) | b as usize;
        }
        value
    };
    if len > MAX_LDAP_PDU {
        return Err(Error::with_context(
            CurlCode::TooLarge,
            "LDAP: server response frame too large",
        ));
    }

    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.map_err(|_| recv_err())?;
    Ok(body)
}

/// Drive a complete LDAP transfer over `stream`: simple `bind`, `search`, stream
/// every result entry to `write_body` as LDIF, then `unbind`. This is the async,
/// pure-Rust equivalent of `oldap_connect` + `oldap_do` + `oldap_recv`.
async fn run_ldap<S, WB>(
    stream: &mut S,
    url: &LdapUrl,
    bind_dn: &[u8],
    password: &[u8],
    mut write_body: WB,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
    WB: FnMut(&[u8]) -> Result<()>,
{
    // --- Simple bind (message id 1) ---
    send_pdu(stream, &build_bind_request(1, bind_dn, password)).await?;
    let response = read_pdu(stream).await?;
    let (_, tag, op) = parse_message(&response)?;
    if tag != LDAP_RES_BIND {
        return Err(Error::with_context(
            CurlCode::LdapCannotBind,
            "LDAP: unexpected response to bind",
        ));
    }
    if parse_result_code(op)? != 0 {
        return Err(Error::with_context(
            CurlCode::LdapCannotBind,
            "LDAP: bind failed",
        ));
    }

    // --- Search (message id 2) ---
    let filter_ber = encode_filter(&url.filter)?;
    let search = build_search_request(
        2,
        &url.dn,
        i64::from(url.scope.as_i32()),
        &filter_ber,
        &url.attributes,
    );
    send_pdu(stream, &search).await?;

    // Stream each returned entry as LDIF until searchResultDone.
    loop {
        let pdu = read_pdu(stream).await?;
        let (_, tag, op) = parse_message(&pdu)?;
        match tag {
            LDAP_RES_SEARCH_ENTRY => {
                let entry = parse_search_entry(op)?;
                let mut ldif = Vec::new();
                entry.write_ldif(&mut ldif);
                write_body(&ldif)?;
            }
            // A continuation reference is not emitted as LDIF by curl; skip it.
            LDAP_RES_SEARCH_REFERENCE => {}
            LDAP_RES_SEARCH_DONE => {
                if parse_result_code(op)? != 0 {
                    return Err(Error::with_context(
                        CurlCode::LdapSearchFailed,
                        "LDAP: search failed",
                    ));
                }
                break;
            }
            // Any other/unsolicited message is ignored while draining results.
            _ => {}
        }
    }

    // --- Unbind (message id 3), best-effort. The server closes the connection
    // on receipt and never replies, so a write error during teardown must not
    // fail the (already complete) transfer. ---
    let _ = send_pdu(stream, &build_unbind_request(3)).await;

    Ok(())
}

// ===========================================================================
// Protocol handler (← `Curl_protocol_ldap` in `openldap.c`).
//
// `mod.rs` registers both `SCHEME_LDAP` (PROTOPT_SSL_REUSE, port 389) and
// `SCHEME_LDAPS` (PROTOPT_SSL, port 636) against `&ldap::HANDLER`, so this
// module exposes exactly one `HANDLER` singleton implementing [`Protocol`].
// curl spreads LDAP across `oldap_connect` (bind), `oldap_do` (search), and
// `oldap_recv` (stream results); because a Rust future can `.await` the socket
// directly, `do_it` drives that whole sequence to completion over the live
// `TransferCtx::io` stream — the same collapsed-lifecycle shape the crate's
// other stream handlers use.
// ===========================================================================

/// The LDAP / LDAPS protocol handler (← `Curl_protocol_ldap`, `openldap.c`).
///
/// A zero-sized handler singleton, shared as `&'static dyn Protocol` by both the
/// `ldap` and `ldaps` scheme records in [`crate::protocols`]. Its
/// [`do_it`](Protocol::do_it) parses the transfer URL via [`LdapUrl::parse`],
/// runs a simple `bind` then a `search` (compiling the RFC 4515 filter to BER),
/// and streams each returned entry to the client sink as LDIF via
/// [`LdapEntry::write_ldif`] — a fully self-contained, pure-Rust LDAPv3 client
/// with no `libldap` linkage.
#[derive(Debug, Default, Clone, Copy)]
pub struct LdapHandler;

/// The shared LDAP/LDAPS handler singleton referenced by `SCHEME_LDAP` and
/// `SCHEME_LDAPS` in [`crate::protocols`].
pub static HANDLER: LdapHandler = LdapHandler;

impl Protocol for LdapHandler {
    /// **Required "DO" phase** — the full LDAP exchange (← `oldap_connect` +
    /// `oldap_do` + `oldap_recv`, collapsed into one async run).
    ///
    /// It parses the transfer URL ([`LdapUrl::parse`]), issues a simple `bind`
    /// with the transfer's username/password (an absent username binds
    /// anonymously, exactly as curl does when no `CURLOPT_USERNAME` is set),
    /// then a `search` over the URL's base DN / [`scope`](LdapScope) / filter /
    /// attributes, streaming every returned entry to [`TransferCtx::sink`] as
    /// LDIF ([`LdapEntry::write_ldif`]), and finally an `unbind`. It returns
    /// `Ok(true)` ("DO phase complete").
    ///
    /// The live transport is taken from [`TransferCtx::io`] — plain TCP for
    /// `ldap`, a `rustls` stream (installed by the connection filter chain) for
    /// `ldaps`, so the same LDAP bytes flow over either.
    ///
    /// # Errors
    ///
    /// `CURLE_URL_MALFORMAT` (bad URL), `CURLE_COULDNT_CONNECT` (no transport
    /// installed), `CURLE_LDAP_CANNOT_BIND` (bind rejected),
    /// `CURLE_LDAP_SEARCH_FAILED` (search rejected or a malformed filter), or
    /// the transport's mapped `CURLE_SEND_ERROR` / `CURLE_RECV_ERROR` /
    /// `CURLE_WEIRD_SERVER_REPLY`.
    fn do_it<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        Box::pin(async move {
            // oldap_url_parse: decompose the transfer URL into base DN, scope,
            // filter, and attributes (percent-decoded to raw bytes, REJECT_ZERO).
            let url = LdapUrl::parse(&ctx.request.url)?;

            // Credentials for the simple bind (owned copies, so no borrow of
            // `ctx.request` outlives the mutable `ctx.io` / `ctx.sink` borrows
            // taken below).
            let bind_dn = ctx
                .request
                .user
                .as_ref()
                .map(|u| u.as_bytes().to_vec())
                .unwrap_or_default();
            let password = ctx
                .request
                .password
                .clone()
                .unwrap_or_default()
                .into_bytes();

            // The live transport off `ctx.io` (installed by the connection
            // filter chain — plain TCP for `ldap`, TLS-wrapped for `ldaps`). Its
            // borrow is disjoint from `ctx.sink` below.
            let stream = ctx.io.as_deref_mut().ok_or_else(|| {
                Error::with_context(CurlCode::CouldntConnect, "no transport for LDAP")
            })?;

            // Stream each decoded entry's LDIF to the client sink (← oldap_recv
            // → Curl_client_write). A transfer with no sink installed discards
            // the body, exactly as a null write target does in curl.
            let sink_slot = &mut ctx.sink;
            let mut write_body = |data: &[u8]| -> Result<()> {
                match sink_slot.as_deref_mut() {
                    Some(s) => s.write(data),
                    None => Ok(()),
                }
            };

            run_ldap(stream, &url, &bind_dn, &password, &mut write_body).await?;
            Ok(true)
        })
    }

    /// Per-request teardown (← `oldap_done`). curl abandons any still-in-flight
    /// search here, but this handler's [`do_it`](Protocol::do_it) fully drains
    /// the search (through `searchResultDone`) and unbinds before it returns, so
    /// nothing remains in flight. No-op.
    fn done<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        status: Result<()>,
        premature: bool,
    ) -> ProtoFuture<'a, ()> {
        let _ = (ctx, status, premature);
        Box::pin(async { Ok(()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::TransferSink;
    use std::sync::{Arc, Mutex};
    use tokio::io::{duplex, DuplexStream};

    /// A [`TransferSink`] that records everything a wired handler streams to the
    /// client, so a handler test can assert the exact LDIF bytes produced.
    struct RecordingSink(Arc<Mutex<Vec<u8>>>);
    impl TransferSink for RecordingSink {
        fn write(&mut self, data: &[u8]) -> Result<()> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(())
        }
    }

    /// Read exactly one `LDAPMessage` from the mock-server side of a duplex pair,
    /// returning the SEQUENCE *contents* (message id + protocol op) — the mirror
    /// of the production [`read_pdu`].
    async fn recv_pdu(stream: &mut DuplexStream) -> Vec<u8> {
        let mut tag = [0u8; 1];
        stream.read_exact(&mut tag).await.expect("pdu tag");
        assert_eq!(tag[0], BER_SEQUENCE, "client PDUs are SEQUENCE-framed");
        let mut first = [0u8; 1];
        stream.read_exact(&mut first).await.expect("pdu length");
        let len = if first[0] < 0x80 {
            first[0] as usize
        } else {
            let n = (first[0] & 0x7f) as usize;
            let mut raw = [0u8; 4];
            stream
                .read_exact(&mut raw[..n])
                .await
                .expect("pdu long length");
            raw[..n]
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | b as usize)
        };
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await.expect("pdu body");
        body
    }

    /// A minimal `LDAPResult`-shaped op body carrying just `result_code`
    /// (empty matchedDN + diagnosticMessage) — used for `bindResponse` and
    /// `searchResultDone`.
    fn result_op(result_code: i64) -> Vec<u8> {
        let mut op = Vec::new();
        ber_int(&mut op, BER_ENUMERATED, result_code); // resultCode
        ber_tlv(&mut op, BER_OCTET_STRING, b""); // matchedDN
        ber_tlv(&mut op, BER_OCTET_STRING, b""); // diagnosticMessage
        op
    }

    /// A `searchResultEntry` op body for `dn` with the given `(name, values)`
    /// attribute list.
    fn entry_op(dn: &[u8], attrs: &[(&[u8], &[&[u8]])]) -> Vec<u8> {
        let mut list = Vec::new();
        for (name, values) in attrs {
            let mut vals = Vec::new();
            for v in *values {
                ber_tlv(&mut vals, BER_OCTET_STRING, v);
            }
            let mut one = Vec::new();
            ber_tlv(&mut one, BER_OCTET_STRING, name);
            ber_tlv(&mut one, BER_SET, &vals);
            ber_tlv(&mut list, BER_SEQUENCE, &one);
        }
        let mut op = Vec::new();
        ber_tlv(&mut op, BER_OCTET_STRING, dn);
        ber_tlv(&mut op, BER_SEQUENCE, &list);
        op
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
        assert_eq!(u.dn, b"dc=example,dc=com".to_vec());
        assert_eq!(u.attributes, vec![b"cn".to_vec(), b"sn".to_vec()]);
        assert_eq!(u.scope, LdapScope::Subtree);
        assert_eq!(u.filter, b"(uid=jdoe)".to_vec());
        assert!(u.extensions.is_empty());
    }

    #[test]
    fn parse_applies_curl_defaults() {
        // No path, no query: empty DN, all-attributes, base scope, default filter.
        let u = LdapUrl::parse("ldap://localhost/").expect("valid");
        assert_eq!(u.host, "localhost");
        assert_eq!(u.port, None);
        assert_eq!(u.effective_port(), PORT_LDAP);
        assert!(u.dn.is_empty());
        assert!(u.attributes.is_empty());
        assert_eq!(u.scope, LdapScope::Base);
        assert_eq!(u.filter, DEFAULT_FILTER.as_bytes().to_vec());
        assert_eq!(u.filter, b"(objectClass=*)".to_vec());
    }

    #[test]
    fn parse_ldaps_uses_636_default_port() {
        let u = LdapUrl::parse("ldaps://secure.example.org/dc=x").expect("valid");
        assert!(u.secure);
        assert_eq!(u.port, None);
        assert_eq!(u.effective_port(), PORT_LDAPS);
        assert_eq!(u.dn, b"dc=x".to_vec());
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
        assert_eq!(u.dn, b"dc=example".to_vec());
        assert_eq!(u.attributes, vec![b"cn".to_vec()]);
        assert_eq!(u.scope, LdapScope::Base);
        assert_eq!(u.filter, b"(cn=*)".to_vec());
    }

    #[test]
    fn parse_empty_dn_with_query() {
        let u = LdapUrl::parse("ldap://h/?mail?one?(uid=a)").expect("valid");
        assert!(u.dn.is_empty());
        assert_eq!(u.attributes, vec![b"mail".to_vec()]);
        assert_eq!(u.scope, LdapScope::OneLevel);
        assert_eq!(u.filter, b"(uid=a)".to_vec());
    }

    #[test]
    fn parse_percent_literal_when_not_two_hex() {
        // A '%' not followed by two hex digits is kept literally (curl behavior).
        assert_eq!(
            LdapUrl::parse("ldap://h/x%zz").expect("valid").dn,
            b"x%zz".to_vec()
        );
        assert_eq!(
            LdapUrl::parse("ldap://h/50%").expect("valid").dn,
            b"50%".to_vec()
        );
    }

    #[test]
    fn parse_does_not_form_decode_plus() {
        // '+' is NOT turned into a space (LDAP URLs are not form-encoded).
        assert_eq!(
            LdapUrl::parse("ldap://h/a+b").expect("valid").dn,
            b"a+b".to_vec()
        );
    }

    #[test]
    fn parse_rejects_nul_byte_reject_zero() {
        let err = LdapUrl::parse("ldap://h/dc=%00").unwrap_err();
        assert_eq!(err.code(), CurlCode::UrlMalformat);
    }

    #[test]
    fn parse_preserves_non_utf8_component() {
        // curl keeps the decoded DN as raw `char*` bytes, NOT UTF-8-validated,
        // so non-UTF-8 bytes must survive rather than be rejected (unlike a
        // NUL byte, which `REJECT_ZERO` still rejects — see the test above).
        let u = LdapUrl::parse("ldap://h/%ff%fe").expect("valid: raw bytes preserved");
        assert_eq!(u.dn, vec![0xff, 0xfe]);
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
        assert_eq!(u.filter, b"(f=1)".to_vec());
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
        assert_eq!(u.dn, b"dc=example".to_vec());
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
        assert_eq!(u.attributes, vec![b"short".to_vec()]);
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

    // ---- BER / DER codec --------------------------------------------------

    #[test]
    fn ber_int_contents_minimal_two_complement() {
        // Zero is the single byte 0x00.
        assert_eq!(ber_int_contents(0), vec![0x00]);
        // 127 fits in one byte with the sign bit clear.
        assert_eq!(ber_int_contents(127), vec![0x7f]);
        // 128 would set the sign bit, so a 0x00 pad byte is prepended.
        assert_eq!(ber_int_contents(128), vec![0x00, 0x80]);
        // 255 likewise needs the pad; 256 spans two bytes cleanly.
        assert_eq!(ber_int_contents(255), vec![0x00, 0xff]);
        assert_eq!(ber_int_contents(256), vec![0x01, 0x00]);
    }

    #[test]
    fn ber_reader_round_trips_a_sequence() {
        // Encode { INTEGER 3, OCTET "cn" } and read it back element by element.
        let mut inner = Vec::new();
        ber_int(&mut inner, BER_INTEGER, 3);
        ber_tlv(&mut inner, BER_OCTET_STRING, b"cn");
        let mut seq = Vec::new();
        ber_tlv(&mut seq, BER_SEQUENCE, &inner);

        let mut outer = BerReader::new(&seq);
        let contents = outer.read_expect(BER_SEQUENCE).expect("sequence");
        let mut reader = BerReader::new(contents);
        assert_eq!(reader.read_int().expect("int"), 3);
        assert_eq!(reader.read_expect(BER_OCTET_STRING).expect("octet"), b"cn");
        assert!(reader.at_end());
    }

    #[test]
    fn ber_reader_rejects_truncated_and_indefinite_length() {
        // A tag that promises two content bytes but supplies none.
        assert!(BerReader::new(&[BER_OCTET_STRING, 0x02])
            .read_tlv()
            .is_err());
        // The indefinite form (0x80) is rejected — LDAP is definite-length only.
        assert!(BerReader::new(&[BER_OCTET_STRING, 0x80])
            .read_tlv()
            .is_err());
        // A 5-byte long-form length is beyond the 4-byte cap.
        assert!(BerReader::new(&[BER_OCTET_STRING, 0x85, 0, 0, 0, 0, 0])
            .read_tlv()
            .is_err());
    }

    // ---- RFC 4515 filter compiler ----------------------------------------

    #[test]
    fn encode_filter_present() {
        // "(objectClass=*)" is a presence assertion: [7] "objectClass".
        let mut expected = Vec::new();
        ber_tlv(&mut expected, FILTER_PRESENT, b"objectClass");
        assert_eq!(encode_filter(b"(objectClass=*)").expect("filter"), expected);
    }

    #[test]
    fn encode_filter_equality() {
        // "(cn=alice)" → [3] { "cn", "alice" }.
        let mut ava = Vec::new();
        ber_tlv(&mut ava, BER_OCTET_STRING, b"cn");
        ber_tlv(&mut ava, BER_OCTET_STRING, b"alice");
        let mut expected = Vec::new();
        ber_tlv(&mut expected, FILTER_EQUALITY, &ava);
        assert_eq!(encode_filter(b"(cn=alice)").expect("filter"), expected);
    }

    #[test]
    fn encode_filter_substrings_initial_any_final() {
        // "(cn=a*b*c)" → [4] { "cn", { [0]"a", [1]"b", [2]"c" } }.
        let mut subs = Vec::new();
        ber_tlv(&mut subs, SUBSTR_INITIAL, b"a");
        ber_tlv(&mut subs, SUBSTR_ANY, b"b");
        ber_tlv(&mut subs, SUBSTR_FINAL, b"c");
        let mut sf = Vec::new();
        ber_tlv(&mut sf, BER_OCTET_STRING, b"cn");
        ber_tlv(&mut sf, BER_SEQUENCE, &subs);
        let mut expected = Vec::new();
        ber_tlv(&mut expected, FILTER_SUBSTRINGS, &sf);
        assert_eq!(encode_filter(b"(cn=a*b*c)").expect("filter"), expected);
    }

    #[test]
    fn encode_filter_and_of_two_equalities() {
        // "(&(a=b)(c=d))" → [0] SET OF { [3]{a,b}, [3]{c,d} }.
        let mut eq1 = Vec::new();
        ber_tlv(&mut eq1, BER_OCTET_STRING, b"a");
        ber_tlv(&mut eq1, BER_OCTET_STRING, b"b");
        let mut eq2 = Vec::new();
        ber_tlv(&mut eq2, BER_OCTET_STRING, b"c");
        ber_tlv(&mut eq2, BER_OCTET_STRING, b"d");
        let mut set = Vec::new();
        ber_tlv(&mut set, FILTER_EQUALITY, &eq1);
        ber_tlv(&mut set, FILTER_EQUALITY, &eq2);
        let mut expected = Vec::new();
        ber_tlv(&mut expected, FILTER_AND, &set);
        assert_eq!(encode_filter(b"(&(a=b)(c=d))").expect("filter"), expected);
    }

    #[test]
    fn encode_filter_rejects_malformed() {
        // Missing parentheses, trailing garbage, and an empty attribute all fail
        // with the LDAP "malformed filter" code rather than panicking.
        for bad in [&b"cn=x"[..], &b"(cn=x)extra"[..], &b"(=x)"[..], &b"("[..]] {
            let err = encode_filter(bad).expect_err("must reject");
            assert_eq!(err.code(), CurlCode::LdapSearchFailed);
        }
    }

    #[test]
    fn parse_message_and_search_entry_round_trip() {
        // Build a searchResultEntry on the wire, then decode it back through the
        // same path `run_ldap` uses (`read_pdu` → `parse_message` →
        // `parse_search_entry`) and assert the reconstructed LDIF.
        let op = entry_op(
            b"uid=jdoe",
            &[(b"cn", &[b"John"]), (b"mail", &[b"a@x", b"b@x"])],
        );
        let full = encode_message(4, LDAP_RES_SEARCH_ENTRY, &op);

        let mut outer = BerReader::new(&full);
        let contents = outer.read_expect(BER_SEQUENCE).expect("outer sequence");
        let (msgid, tag, body) = parse_message(contents).expect("message");
        assert_eq!(msgid, 4);
        assert_eq!(tag, LDAP_RES_SEARCH_ENTRY);

        let entry = parse_search_entry(body).expect("entry");
        assert_eq!(entry.dn, "uid=jdoe");
        assert_eq!(
            entry.to_ldif(),
            b"DN: uid=jdoe\n\tcn: John\n\n\tmail: a@x\n\tmail: b@x\n\n\n".to_vec()
        );
    }

    // ---- Protocol handler (full duplex exchange) --------------------------

    #[tokio::test]
    async fn handler_do_it_binds_searches_and_streams_ldif() {
        // Drive the whole LDAP exchange through `do_it` over one in-memory
        // stream: bind → search → one searchResultEntry → searchResultDone →
        // unbind, and assert the sink received exactly that entry's LDIF.
        let (client, mut server) = duplex(64 * 1024);

        let server_task = tokio::spawn(async move {
            // 1. bindRequest (message id 1, [APPLICATION 0]).
            let bind = recv_pdu(&mut server).await;
            let (id, tag, _) = parse_message(&bind).expect("bind message");
            assert_eq!((id, tag), (1, LDAP_REQ_BIND));
            server
                .write_all(&encode_message(1, LDAP_RES_BIND, &result_op(0)))
                .await
                .expect("write bindResponse");

            // 2. searchRequest (message id 2, [APPLICATION 3]).
            let search = recv_pdu(&mut server).await;
            let (id, tag, _) = parse_message(&search).expect("search message");
            assert_eq!((id, tag), (2, LDAP_REQ_SEARCH));
            server
                .write_all(&encode_message(
                    2,
                    LDAP_RES_SEARCH_ENTRY,
                    &entry_op(b"cn=alice,dc=example,dc=com", &[(b"cn", &[b"alice"])]),
                ))
                .await
                .expect("write searchResultEntry");
            server
                .write_all(&encode_message(2, LDAP_RES_SEARCH_DONE, &result_op(0)))
                .await
                .expect("write searchResultDone");

            // 3. unbindRequest (message id 3, [APPLICATION 2]).
            let unbind = recv_pdu(&mut server).await;
            let (id, tag, _) = parse_message(&unbind).expect("unbind message");
            assert_eq!((id, tag), (3, LDAP_REQ_UNBIND));
        });

        let received = Arc::new(Mutex::new(Vec::new()));
        let mut ctx = TransferCtx::new();
        ctx.request.url = "ldap://dir.example.com/dc=example,dc=com?cn,mail?sub?(cn=alice)".into();
        ctx.io = Some(Box::new(client));
        ctx.sink = Some(Box::new(RecordingSink(received.clone())));

        let done = HANDLER
            .do_it(&mut ctx)
            .await
            .expect("do_it drives to completion");
        assert!(done);
        assert_eq!(
            *received.lock().unwrap(),
            b"DN: cn=alice,dc=example,dc=com\n\tcn: alice\n\n\n".to_vec()
        );
        server_task.await.expect("server task");
    }

    #[tokio::test]
    async fn handler_do_it_streams_multiple_entries_and_skips_reference() {
        // Two entries plus an interleaved searchResultReference: the reference is
        // silently skipped (curl does not emit it as LDIF) and both entries are
        // concatenated into the sink in arrival order.
        let (client, mut server) = duplex(64 * 1024);

        let server_task = tokio::spawn(async move {
            recv_pdu(&mut server).await; // bindRequest
            server
                .write_all(&encode_message(1, LDAP_RES_BIND, &result_op(0)))
                .await
                .expect("bindResponse");
            recv_pdu(&mut server).await; // searchRequest
            server
                .write_all(&encode_message(
                    2,
                    LDAP_RES_SEARCH_ENTRY,
                    &entry_op(b"cn=alice", &[(b"cn", &[b"alice"])]),
                ))
                .await
                .expect("entry 1");
            // A continuation reference — decoded, recognised, and ignored.
            server
                .write_all(&encode_message(2, LDAP_RES_SEARCH_REFERENCE, b""))
                .await
                .expect("reference");
            server
                .write_all(&encode_message(
                    2,
                    LDAP_RES_SEARCH_ENTRY,
                    &entry_op(b"cn=bob", &[(b"cn", &[b"bob"]), (b"mail", &[b"bob@x"])]),
                ))
                .await
                .expect("entry 2");
            server
                .write_all(&encode_message(2, LDAP_RES_SEARCH_DONE, &result_op(0)))
                .await
                .expect("searchResultDone");
            recv_pdu(&mut server).await; // unbindRequest
        });

        let received = Arc::new(Mutex::new(Vec::new()));
        let mut ctx = TransferCtx::new();
        ctx.request.url = "ldap://h/dc=x?cn?sub?(objectClass=*)".into();
        ctx.io = Some(Box::new(client));
        ctx.sink = Some(Box::new(RecordingSink(received.clone())));

        assert!(HANDLER.do_it(&mut ctx).await.expect("do_it"));
        let mut expected = b"DN: cn=alice\n\tcn: alice\n\n\n".to_vec();
        expected.extend_from_slice(b"DN: cn=bob\n\tcn: bob\n\n\tmail: bob@x\n\n\n");
        assert_eq!(*received.lock().unwrap(), expected);
        server_task.await.expect("server task");
    }

    #[tokio::test]
    async fn handler_do_it_reports_bind_failure() {
        // A non-zero bind resultCode (49 = invalidCredentials) surfaces as
        // CURLE_LDAP_CANNOT_BIND and the search is never issued.
        let (client, mut server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            recv_pdu(&mut server).await; // bindRequest
            server
                .write_all(&encode_message(1, LDAP_RES_BIND, &result_op(49)))
                .await
                .expect("bindResponse");
        });

        let mut ctx = TransferCtx::new();
        ctx.request.url = "ldap://h/dc=x".into();
        ctx.io = Some(Box::new(client));
        ctx.sink = Some(Box::new(RecordingSink(Arc::new(Mutex::new(Vec::new())))));

        let err = HANDLER.do_it(&mut ctx).await.expect_err("bind must fail");
        assert_eq!(err.code(), CurlCode::LdapCannotBind);
        server_task.await.expect("server task");
    }

    #[tokio::test]
    async fn handler_do_it_reports_search_failure() {
        // Bind succeeds, but searchResultDone carries a non-zero resultCode
        // (32 = noSuchObject) → CURLE_LDAP_SEARCH_FAILED.
        let (client, mut server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            recv_pdu(&mut server).await; // bindRequest
            server
                .write_all(&encode_message(1, LDAP_RES_BIND, &result_op(0)))
                .await
                .expect("bindResponse");
            recv_pdu(&mut server).await; // searchRequest
            server
                .write_all(&encode_message(2, LDAP_RES_SEARCH_DONE, &result_op(32)))
                .await
                .expect("searchResultDone");
        });

        let mut ctx = TransferCtx::new();
        ctx.request.url = "ldap://h/dc=x?cn?sub?(cn=missing)".into();
        ctx.io = Some(Box::new(client));
        ctx.sink = Some(Box::new(RecordingSink(Arc::new(Mutex::new(Vec::new())))));

        let err = HANDLER.do_it(&mut ctx).await.expect_err("search must fail");
        assert_eq!(err.code(), CurlCode::LdapSearchFailed);
        server_task.await.expect("server task");
    }

    #[tokio::test]
    async fn handler_do_it_without_transport_reports_couldnt_connect() {
        // The URL parses cleanly, but no transport was installed on the context
        // (the connection filter chain never ran), so `do_it` reports
        // CURLE_COULDNT_CONNECT rather than dereferencing a missing stream.
        let mut ctx = TransferCtx::new();
        ctx.request.url = "ldap://h/dc=x".into();
        let err = HANDLER.do_it(&mut ctx).await.expect_err("no transport");
        assert_eq!(err.code(), CurlCode::CouldntConnect);
    }

    #[tokio::test]
    async fn handler_do_it_rejects_non_ldap_scheme() {
        // A non-ldap:// URL is rejected at parse time before any I/O.
        let mut ctx = TransferCtx::new();
        ctx.request.url = "http://h/".into();
        assert!(HANDLER.do_it(&mut ctx).await.is_err());
    }

    #[tokio::test]
    async fn handler_done_is_noop() {
        // `done` performs no teardown of its own (the connection filter chain
        // owns socket lifetime) and reports success.
        let mut ctx = TransferCtx::new();
        HANDLER
            .done(&mut ctx, Ok(()), false)
            .await
            .expect("done ok");
    }
}
