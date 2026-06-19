//! LDAP / LDAPS protocol engine (`ldap://`, `ldaps://`).
//!
//! This is the Rust analog of curl's two C LDAP translation units — `lib/ldap.c`
//! (the generic / Windows-WLDAP path) and `lib/openldap.c` (the OpenLDAP path) —
//! consumed strictly as a **behavioral oracle**. The C code binds an external
//! `libldap` / WLDAP library, which is explicitly out of scope for
//! transliteration (AAP §0.3.2: "SSH/LDAP/etc. C backends bind external
//! libraries"). Instead, this module reproduces the **observable** LDAP behavior
//! in pure, memory-safe Rust:
//!
//! * **LDAP URL parsing** per RFC 4516 §2
//!   (`ldap://host:port/dn?attributes?scope?filter?extensions`), matching
//!   `ldap.c`'s `ldap_url_parse2()` byte-for-byte (DN/attribute/filter
//!   percent-decoding, the `base`/`one`/`sub` scope keywords, and the
//!   trailing-delimiter syntax error).
//! * A minimal but real **LDAPv3 client**: BER/DER encoding of a `bindRequest`
//!   (anonymous or simple bind) and a `searchRequest` (RFC 4511 §4.2 / §4.5.1),
//!   plus decoding of `bindResponse`, `searchResEntry`, and `searchResDone`
//!   (RFC 4511 §4.1.1).
//! * **LDIF-style result formatting** reproducing `openldap.c`'s `oldap_recv()`
//!   output exactly — `DN: <dn>`, a tab-indented `attr: value` per value, the
//!   `attr:: <base64>` double-colon convention for binary / non-printable
//!   values, the empty-value rendering, and the blank-line separators.
//! * **Result-code mapping** from LDAP result codes to [`CurlError`] mirroring
//!   `openldap.c`'s `oldap_map_error()` and `ldap.c`'s bind/search failure
//!   handling.
//!
//! # Scheme registration
//!
//! Two scheme descriptors are served by a single [`LdapHandler`] type:
//!
//! * `ldap://` — [`SCHEME_LDAP`], default port 389, `PROTOPT_SSL_REUSE`
//!   (plaintext, may upgrade with STARTTLS).
//! * `ldaps://` — [`SCHEME_LDAPS`], default port 636, `PROTOPT_SSL` (TLS from the
//!   first byte). The TLS layer is supplied transparently by the connection
//!   filter chain ([`crate::conn`]); this module sends and receives plaintext
//!   LDAP messages and the chain encrypts them, so no direct TLS handling is
//!   needed here.
//!
//! # Test-parity scope
//!
//! curl's own regression suite exercises LDAP only at the *recognition* and
//! *URL-parsing* level — no test harness ships a live LDAP server — so this
//! module is "at minimum stub-handled" per AAP §0.1.1: the schemes are
//! registered correctly, the URL parser and LDIF formatter are complete and
//! exhaustively unit-tested, and [`LdapHandler::do_it`] performs a faithful
//! bind + search exchange over the connection. Where the surrounding
//! transfer-engine seam is not yet wired (it is wired for no protocol at this
//! checkpoint), the gap is called out with `// PARITY:` comments.
//!
//! # Memory safety
//!
//! This subtree inherits `#![forbid(unsafe_code)]` from [`crate::protocols`]; it
//! is intentionally **not** re-declared here. All parsing operates on owned
//! `Vec<u8>` / `&[u8]` slices with checked indexing, so the BER decoder cannot
//! over-read.

use crate::conn::{BoxFuture, Connection, Curl_conn_recv, Curl_conn_send, FIRSTSOCKET};
use crate::easy::Easy;
use crate::error::{CurlError, Result};
use crate::protocols::{
    Protocol, ProtocolTransfer, Scheme, TransferDirection, SCHEME_LDAP, SCHEME_LDAPS,
};
use crate::url::{
    CurlUPart, CurlUrl, CURLU_GUESS_SCHEME, CURLU_NON_SUPPORT_SCHEME, CURLU_URLDECODE,
};
use crate::util::sendf::{failf, infof};

// ===========================================================================
// LDAP protocol constants (RFC 4511 / RFC 4516).
// ===========================================================================

/// LDAP protocol version sent in the `bindRequest` — LDAPv3 (RFC 4511 §4.2).
const LDAP_VERSION3: u8 = 3;

// --- Search scope (RFC 4511 §4.5.1.2 `SearchRequest.scope`) -----------------

/// `baseObject` — search only the base entry (the default when the URL omits a
/// scope, RFC 4516 §4). C `LDAP_SCOPE_BASE`.
const LDAP_SCOPE_BASE: u8 = 0;
/// `singleLevel` — search the base entry's immediate children. C
/// `LDAP_SCOPE_ONELEVEL`.
const LDAP_SCOPE_ONELEVEL: u8 = 1;
/// `wholeSubtree` — search the base entry and all descendants. C
/// `LDAP_SCOPE_SUBTREE`.
const LDAP_SCOPE_SUBTREE: u8 = 2;

// --- deref-aliases (RFC 4511 §4.5.1.3) -------------------------------------

/// `neverDerefAliases` — the conservative default used for URL-driven searches.
const LDAP_DEREF_NEVER: u8 = 0;

// --- LDAP result codes (RFC 4511 §4.1.9, the subset curl maps) --------------

/// `success` (0).
const LDAP_SUCCESS: i64 = 0;
/// `protocolError` (2).
const LDAP_PROTOCOL_ERROR: i64 = 2;
/// `sizeLimitExceeded` (4) — partial results were returned; curl treats this as
/// a (warned) success.
const LDAP_SIZELIMIT_EXCEEDED: i64 = 4;
/// `invalidCredentials` (49).
const LDAP_INVALID_CREDENTIALS: i64 = 49;
/// `insufficientAccessRights` (50).
const LDAP_INSUFFICIENT_ACCESS: i64 = 50;

// ===========================================================================
// BER / DER identifier octets (RFC 4511 uses BER with definite lengths).
// ===========================================================================

/// Universal `BOOLEAN` (primitive).
const BER_BOOLEAN: u8 = 0x01;
/// Universal `INTEGER` (primitive).
const BER_INTEGER: u8 = 0x02;
/// Universal `OCTET STRING` (primitive).
const BER_OCTET_STRING: u8 = 0x04;
/// Universal `ENUMERATED` (primitive).
const BER_ENUMERATED: u8 = 0x0a;
/// Universal `SEQUENCE` / `SEQUENCE OF` (constructed).
const BER_SEQUENCE: u8 = 0x30;
/// Universal `SET` / `SET OF` (constructed).
const BER_SET: u8 = 0x31;

/// `[APPLICATION 0]` constructed — `bindRequest` (RFC 4511 §4.2).
const LDAP_REQ_BIND: u8 = 0x60;
/// `[APPLICATION 1]` constructed — `bindResponse`.
const LDAP_RES_BIND: u8 = 0x61;
/// `[APPLICATION 2]` primitive — `unbindRequest` (a NULL).
const LDAP_REQ_UNBIND: u8 = 0x42;
/// `[APPLICATION 3]` constructed — `searchRequest` (RFC 4511 §4.5.1).
const LDAP_REQ_SEARCH: u8 = 0x63;
/// `[APPLICATION 4]` constructed — `searchResultEntry` (RFC 4511 §4.5.2).
const LDAP_RES_SEARCH_ENTRY: u8 = 0x64;
/// `[APPLICATION 5]` constructed — `searchResultDone`.
const LDAP_RES_SEARCH_RESULT: u8 = 0x65;
/// `[APPLICATION 19]` constructed — `searchResultReference` (skipped on read).
const LDAP_RES_SEARCH_REFERENCE: u8 = 0x73;

/// `[0]` context primitive — the `simple` authentication choice inside a
/// `bindRequest` (RFC 4511 §4.2).
const LDAP_AUTH_SIMPLE: u8 = 0x80;

// --- Filter CHOICE tags (RFC 4511 §4.5.1, context class) -------------------

/// `and [0]` (constructed).
const FILTER_AND: u8 = 0xa0;
/// `or [1]` (constructed).
const FILTER_OR: u8 = 0xa1;
/// `not [2]` (constructed).
const FILTER_NOT: u8 = 0xa2;
/// `equalityMatch [3]` (constructed).
const FILTER_EQUALITY: u8 = 0xa3;
/// `substrings [4]` (constructed).
const FILTER_SUBSTRINGS: u8 = 0xa4;
/// `greaterOrEqual [5]` (constructed).
const FILTER_GE: u8 = 0xa5;
/// `lessOrEqual [6]` (constructed).
const FILTER_LE: u8 = 0xa6;
/// `present [7]` (primitive).
const FILTER_PRESENT: u8 = 0x87;
/// `approxMatch [8]` (constructed).
const FILTER_APPROX: u8 = 0xa8;

/// `substring initial [0]` (primitive).
const SUBSTR_INITIAL: u8 = 0x80;
/// `substring any [1]` (primitive).
const SUBSTR_ANY: u8 = 0x81;
/// `substring final [2]` (primitive).
const SUBSTR_FINAL: u8 = 0x82;

/// The default LDAP search filter applied when the URL omits one
/// (`(objectclass=*)`, RFC 4516 §4). Curl/libldap use the same default.
const DEFAULT_FILTER: &str = "(objectclass=*)";

// ===========================================================================
// Search scope — the safe analog of the C `lud_scope` int.
// ===========================================================================

/// An LDAP search scope, parsed from the `?scope?` URL field (RFC 4516 §2).
///
/// The wire value (`u8`) is what goes into the `searchRequest.scope`
/// `ENUMERATED` (RFC 4511 §4.5.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// `base` — the base object only (the URL default).
    Base,
    /// `one` / `onetree` — one level below the base object.
    OneLevel,
    /// `sub` / `subtree` — the whole subtree.
    Subtree,
}

impl Scope {
    /// The BER `ENUMERATED` wire value for `searchRequest.scope`.
    #[must_use]
    pub const fn wire_value(self) -> u8 {
        match self {
            Scope::Base => LDAP_SCOPE_BASE,
            Scope::OneLevel => LDAP_SCOPE_ONELEVEL,
            Scope::Subtree => LDAP_SCOPE_SUBTREE,
        }
    }
}

/// Map a URL `?scope?` keyword to a [`Scope`], the analog of `ldap.c`'s
/// `str2scope()`.
///
/// Recognizes `base`, `one`, `onetree`, `sub`, and `subtree` case-insensitively
/// (exactly the keyword set `ldap.c` accepts); any other token yields `None`,
/// which the URL parser turns into [`CurlError::UrlMalformat`] (`ldap.c` returns
/// `LDAP_INVALID_SYNTAX`).
#[must_use]
pub fn str2scope(s: &str) -> Option<Scope> {
    if s.eq_ignore_ascii_case("base") {
        Some(Scope::Base)
    } else if s.eq_ignore_ascii_case("one") || s.eq_ignore_ascii_case("onetree") {
        Some(Scope::OneLevel)
    } else if s.eq_ignore_ascii_case("sub") || s.eq_ignore_ascii_case("subtree") {
        Some(Scope::Subtree)
    } else {
        None
    }
}

// ===========================================================================
// Local primitives — percent-decoding and base64.
//
// curl's LDAP code uses `Curl_urldecode(..., REJECT_ZERO)` and
// `curlx_base64_encode`. Those live in `crate::escape` / `crate::util::base64`,
// which are NOT in this file's dependency whitelist (AAP §0.6.2 import rules), so
// the two small, self-contained behaviors are reproduced locally rather than
// pulling in non-whitelisted modules. Both match curl's semantics exactly and
// are covered by this module's unit tests.
// ===========================================================================

/// Convert one ASCII hex digit to its value, or `None` if not `[0-9A-Fa-f]`.
const fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode `input`, rejecting a decoded NUL byte — the local analog of
/// curl's `Curl_urldecode(data, input, 0, &out, NULL, REJECT_ZERO)`.
///
/// A `%XX` escape is decoded only when both following characters are hex digits
/// (matching curl, which keeps a malformed `%` literally); any other byte passes
/// through unchanged. A decoded NUL (`0x00`) yields [`CurlError::UrlMalformat`],
/// since an embedded NUL cannot appear in an LDAP DN / attribute / filter and
/// curl's `REJECT_ZERO` rejects it.
fn percent_decode(input: &[u8]) -> Result<Vec<u8>> {
    let len = input.len();
    let mut out = Vec::with_capacity(len);
    let mut i = 0;
    while i < len {
        let cur = input[i];
        let decoded = if cur == b'%' && (len - i) > 2 {
            match (hex_value(input[i + 1]), hex_value(input[i + 2])) {
                (Some(hi), Some(lo)) => {
                    i += 3;
                    (hi << 4) | lo
                }
                // Not a valid escape: keep the literal '%'.
                _ => {
                    i += 1;
                    cur
                }
            }
        } else {
            i += 1;
            cur
        };
        if decoded == 0 {
            return Err(CurlError::UrlMalformat);
        }
        out.push(decoded);
    }
    Ok(out)
}

/// The standard base64 alphabet (RFC 4648 §4), as used by `curlx_base64_encode`.
const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode `input` as standard, `=`-padded base64 with no line wrapping — the
/// local analog of `curlx_base64_encode`.
///
/// Returns the ASCII base64 text. Empty input yields empty output (curl returns
/// `CURLE_OK` with a zero-length result), which is why the LDIF formatter never
/// base64-encodes an empty value.
fn base64_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied();
        let b2 = chunk.get(2).copied();

        let n0 = b0 >> 2;
        let n1 = ((b0 & 0x03) << 4) | (b1.unwrap_or(0) >> 4);
        out.push(B64_ALPHABET[n0 as usize]);
        out.push(B64_ALPHABET[n1 as usize]);

        match (b1, b2) {
            (Some(c1), Some(c2)) => {
                let n2 = ((c1 & 0x0f) << 2) | (c2 >> 6);
                let n3 = c2 & 0x3f;
                out.push(B64_ALPHABET[n2 as usize]);
                out.push(B64_ALPHABET[n3 as usize]);
            }
            (Some(c1), None) => {
                let n2 = (c1 & 0x0f) << 2;
                out.push(B64_ALPHABET[n2 as usize]);
                out.push(b'=');
            }
            _ => {
                out.push(b'=');
                out.push(b'=');
            }
        }
    }
    out
}

// ===========================================================================
// LDAP URL — RFC 4516 §2 parsing (oracle: `ldap.c` `ldap_url_parse2()`).
// ===========================================================================

/// The decoded pieces of an LDAP URL, the Rust analog of the C `LDAPURLDesc`
/// fields that curl actually consumes (`lud_dn`, `lud_attrs`, `lud_scope`,
/// `lud_filter`). Host and port are carried by the connection, not here, exactly
/// as `ldap_url_parse2()` takes them from `conn->host.name` / `conn->remote_port`
/// rather than the path/query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapUrl {
    /// The base distinguished name (percent-decoded). Empty string when the URL
    /// path is just `/` (RFC 4516: an absent DN means the empty DN).
    pub dn: String,
    /// The requested attribute descriptions (each percent-decoded). Empty means
    /// "all user attributes" (the LDAP default).
    pub attributes: Vec<String>,
    /// The search scope (defaults to [`Scope::Base`] when the URL omits it).
    pub scope: Scope,
    /// The search filter (percent-decoded) if the URL supplies one; `None`
    /// selects the [`DEFAULT_FILTER`] at search time.
    pub filter: Option<String>,
}

impl LdapUrl {
    /// Parse the LDAP-specific portion of a URL — its `path` and `query` — per
    /// RFC 4516 §2, reproducing `ldap.c`'s `ldap_url_parse2()`.
    ///
    /// `path` is the URL path **including** its leading `/` (curl's
    /// `data->state.up.path`, which always begins with `/`); the DN is everything
    /// after that slash. `query` is the raw query string **without** the leading
    /// `?` (curl's `data->state.up.query`), split into
    /// `attributes ? scope ? filter ? extensions`. Every field is optional.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::UrlMalformat`] when:
    /// * `path` does not start with `/` (curl's `LDAP_INVALID_SYNTAX`),
    /// * a percent-escape decodes to NUL (curl's `REJECT_ZERO`),
    /// * the `?scope?` field is a keyword [`str2scope`] does not recognize, or
    /// * the query ends with a dangling `?` that opens an empty extensions field
    ///   (curl's trailing-`if(p && !*p)` syntax check).
    pub fn parse(path: &str, query: Option<&str>) -> Result<Self> {
        // The path must be absolute; curl rejects anything else up front.
        let rest = path.strip_prefix('/').ok_or(CurlError::UrlMalformat)?;

        // The DN is the (percent-decoded) path remainder; "/" alone => empty DN.
        let dn = if rest.is_empty() {
            String::new()
        } else {
            decode_utf8(rest)?
        };

        let mut ldap = LdapUrl {
            dn,
            attributes: Vec::new(),
            scope: Scope::Base,
            filter: None,
        };

        let query = match query {
            Some(q) if !q.is_empty() => q,
            // No query (or an empty one) => just the DN, default scope/filter.
            _ => return Ok(ldap),
        };

        // Split into at most four fields; the 4th captures any trailing
        // extensions (which may itself contain '?'), mirroring the C parser that
        // stops attending to the URL after the filter.
        let mut fields = query.splitn(4, '?');
        let attrs = fields.next().unwrap_or("");
        let scope = fields.next();
        let filter = fields.next();
        let extensions = fields.next();

        // Attributes: a comma-separated list, each entry percent-decoded. An
        // empty field leaves the list empty ("all attributes").
        if !attrs.is_empty() {
            for attr in attrs.split(',') {
                ldap.attributes.push(decode_utf8(attr)?);
            }
        }

        // Scope: an unrecognized keyword is a hard syntax error; an empty field
        // keeps the default (base).
        if let Some(scope) = scope {
            if !scope.is_empty() {
                ldap.scope = str2scope(scope).ok_or(CurlError::UrlMalformat)?;
            }
        }

        // Filter: percent-decoded when present and non-empty.
        if let Some(filter) = filter {
            if !filter.is_empty() {
                ldap.filter = Some(decode_utf8(filter)?);
            }
        }

        // A dangling trailing '?' that opens an *empty* extensions field is the
        // C `if(p && !*p) rc = LDAP_INVALID_SYNTAX` case (e.g. "a?s?f?"). A
        // non-empty extensions field is accepted and ignored.
        if let Some(extensions) = extensions {
            if extensions.is_empty() {
                return Err(CurlError::UrlMalformat);
            }
        }

        Ok(ldap)
    }
}

/// Percent-decode `s` and interpret the bytes as UTF-8 (lossily, like curl which
/// passes raw bytes straight through to libldap). Used for DN / attribute /
/// filter fields.
fn decode_utf8(s: &str) -> Result<String> {
    let bytes = percent_decode(s.as_bytes())?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

// ===========================================================================
// BER / DER codec — definite-length TLV encoding/decoding (RFC 4511 wire).
//
// LDAP-over-the-wire is BER with definite lengths; the encoder always emits the
// minimal (DER) length form, which every LDAP server accepts. Only single-byte
// identifier octets are produced/consumed (tag number < 31), which covers every
// tag in RFC 4511's protocol grammar.
// ===========================================================================

mod ber {
    use super::CurlError;
    use crate::error::Result;

    /// Append a definite-length octet sequence for `len` (X.690 §8.1.3): the
    /// short form (`0x00..=0x7f`) for lengths below 128, else the long form
    /// (`0x80 | n` followed by `n` big-endian length octets).
    pub(super) fn encode_length(out: &mut Vec<u8>, len: usize) {
        if len < 0x80 {
            out.push(len as u8);
            return;
        }
        // Long form: emit the minimal big-endian byte count.
        let bytes = (len as u64).to_be_bytes();
        let first = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        let significant = &bytes[first..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }

    /// Append a complete TLV: the `tag` identifier octet, the encoded length of
    /// `value`, then `value` itself.
    pub(super) fn encode_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
        out.push(tag);
        encode_length(out, value.len());
        out.extend_from_slice(value);
    }

    /// Append a minimally-encoded two's-complement `INTEGER`/`ENUMERATED` value
    /// under the given `tag` (X.690 §8.3): redundant leading `0x00` / `0xff`
    /// octets are stripped while preserving the sign bit.
    pub(super) fn encode_int(out: &mut Vec<u8>, tag: u8, value: i64) {
        let be = value.to_be_bytes();
        // Strip leading bytes that are redundant given the next byte's sign bit.
        let mut start = 0;
        while start < be.len() - 1 {
            let b = be[start];
            let next = be[start + 1];
            let redundant_zero = b == 0x00 && (next & 0x80) == 0;
            let redundant_ones = b == 0xff && (next & 0x80) != 0;
            if redundant_zero || redundant_ones {
                start += 1;
            } else {
                break;
            }
        }
        encode_tlv(out, tag, &be[start..]);
    }

    /// Append a `BOOLEAN` TLV (`0xff` for true, `0x00` for false; X.690 §8.2).
    pub(super) fn encode_bool(out: &mut Vec<u8>, tag: u8, value: bool) {
        encode_tlv(out, tag, &[if value { 0xff } else { 0x00 }]);
    }

    /// A decoded TLV: its identifier octet and a borrow of its content octets.
    #[derive(Debug, Clone, Copy)]
    pub(super) struct Tlv<'a> {
        /// The identifier (tag) octet.
        pub tag: u8,
        /// The content octets (the `V` of the TLV), length-delimited.
        pub value: &'a [u8],
    }

    /// A cursor over a BER byte stream that yields successive TLVs.
    ///
    /// Every read is bounds-checked; a truncated length or content yields
    /// [`CurlError::WeirdServerReply`] rather than panicking, so a malformed or
    /// hostile server response can never over-read.
    pub(super) struct Reader<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> Reader<'a> {
        /// Create a reader over `buf`, positioned at its start.
        pub(super) fn new(buf: &'a [u8]) -> Self {
            Reader { buf, pos: 0 }
        }

        /// Whether all octets have been consumed.
        pub(super) fn is_empty(&self) -> bool {
            self.pos >= self.buf.len()
        }

        /// Read the next TLV, advancing past it.
        ///
        /// # Errors
        ///
        /// [`CurlError::WeirdServerReply`] on truncation or an unsupported
        /// high-tag-number / indefinite-length form.
        pub(super) fn read(&mut self) -> Result<Tlv<'a>> {
            let tag = *self.byte(self.pos)?;
            // High-tag-number form (tag bits all set) is not used by LDAP.
            if tag & 0x1f == 0x1f {
                return Err(CurlError::WeirdServerReply);
            }
            let mut idx = self.pos + 1;
            let first = *self.byte(idx)?;
            idx += 1;
            let len = if first < 0x80 {
                first as usize
            } else {
                let num = (first & 0x7f) as usize;
                // Indefinite length (0x80) is forbidden for LDAP messages.
                if num == 0 || num > 8 {
                    return Err(CurlError::WeirdServerReply);
                }
                let mut acc: usize = 0;
                for _ in 0..num {
                    let b = *self.byte(idx)?;
                    idx += 1;
                    acc = acc
                        .checked_shl(8)
                        .and_then(|v| v.checked_add(b as usize))
                        .ok_or(CurlError::WeirdServerReply)?;
                }
                acc
            };
            let end = idx.checked_add(len).ok_or(CurlError::WeirdServerReply)?;
            if end > self.buf.len() {
                return Err(CurlError::WeirdServerReply);
            }
            self.pos = end;
            Ok(Tlv {
                tag,
                value: &self.buf[idx..end],
            })
        }

        /// Bounds-checked single-byte access.
        fn byte(&self, idx: usize) -> Result<&u8> {
            self.buf.get(idx).ok_or(CurlError::WeirdServerReply)
        }
    }

    /// Decode the content of an `INTEGER`/`ENUMERATED` (already stripped to its
    /// content octets) as a signed two's-complement [`i64`].
    ///
    /// # Errors
    ///
    /// [`CurlError::WeirdServerReply`] for an empty or over-9-byte content run.
    pub(super) fn decode_int(value: &[u8]) -> Result<i64> {
        if value.is_empty() || value.len() > 8 {
            return Err(CurlError::WeirdServerReply);
        }
        // Sign-extend from the leading byte.
        let mut acc: i64 = if value[0] & 0x80 != 0 { -1 } else { 0 };
        for &b in value {
            acc = (acc << 8) | i64::from(b);
        }
        Ok(acc)
    }

    /// Determine the **total** encoded length (identifier + length octets +
    /// content) of the first TLV at the front of `buf`, given a possibly
    /// incomplete prefix — the framing primitive the streaming receiver uses to
    /// know when a whole `LDAPMessage` has arrived.
    ///
    /// Returns `Ok(None)` when more bytes are needed to even determine the
    /// length (the identifier/length octets are not all present yet), `Ok(Some(
    /// total))` once the framing is known (the caller then waits until
    /// `buf.len() >= total`), or [`CurlError::WeirdServerReply`] for malformed
    /// framing (high-tag-number form, indefinite length, or an unreasonably
    /// large length field).
    pub(super) fn try_total_len(buf: &[u8]) -> Result<Option<usize>> {
        if buf.len() < 2 {
            return Ok(None);
        }
        // High-tag-number form (low 5 bits all set) is unused by LDAP.
        if buf[0] & 0x1f == 0x1f {
            return Err(CurlError::WeirdServerReply);
        }
        let first = buf[1];
        if first & 0x80 == 0 {
            // Short form: the length is this byte.
            return Ok(Some(2 + first as usize));
        }
        // Long form: low 7 bits give the count of subsequent length octets.
        let count = (first & 0x7f) as usize;
        if count == 0 {
            // Indefinite length is forbidden in DER / LDAP BER.
            return Err(CurlError::WeirdServerReply);
        }
        if count > 4 {
            // A length needing >4 octets is far larger than any sane LDAP PDU.
            return Err(CurlError::WeirdServerReply);
        }
        if buf.len() < 2 + count {
            // Need more bytes to read the full length field.
            return Ok(None);
        }
        let mut content = 0usize;
        for &b in &buf[2..2 + count] {
            content = (content << 8) | b as usize;
        }
        Ok(Some(2 + count + content))
    }
}

// ===========================================================================
// LDAP request builders (RFC 4511 §4.1.1 envelope + §4.2 / §4.5.1 ops).
// ===========================================================================

/// Wrap a protocol operation in an `LDAPMessage` envelope (RFC 4511 §4.1.1):
/// `SEQUENCE { messageID INTEGER, protocolOp }`. `op_tag`/`op_body` are the
/// already-built protocol operation's identifier octet and content.
fn wrap_message(message_id: i64, op_tag: u8, op_body: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    ber::encode_int(&mut inner, BER_INTEGER, message_id);
    ber::encode_tlv(&mut inner, op_tag, op_body);

    let mut msg = Vec::new();
    ber::encode_tlv(&mut msg, BER_SEQUENCE, &inner);
    msg
}

/// Build a `bindRequest` (RFC 4511 §4.2): LDAPv3, the given `name` (bind DN, or
/// empty for an anonymous bind), and `simple` authentication carrying
/// `password` (empty for anonymous). Returns the full `LDAPMessage` bytes.
fn build_bind_request(message_id: i64, name: &str, password: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    ber::encode_int(&mut body, BER_INTEGER, i64::from(LDAP_VERSION3));
    ber::encode_tlv(&mut body, BER_OCTET_STRING, name.as_bytes());
    // simple [0] OCTET STRING — context primitive, so the password bytes are the
    // raw content under the [0] tag.
    ber::encode_tlv(&mut body, LDAP_AUTH_SIMPLE, password);
    wrap_message(message_id, LDAP_REQ_BIND, &body)
}

/// Build an `unbindRequest` (RFC 4511 §4.3): `[APPLICATION 2]` NULL, sent to
/// gracefully close the LDAP session before the transport is torn down.
fn build_unbind_request(message_id: i64) -> Vec<u8> {
    wrap_message(message_id, LDAP_REQ_UNBIND, &[])
}

/// Build a `searchRequest` (RFC 4511 §4.5.1): the base DN, scope, never-deref,
/// no size/time limit, attributes-and-values (not types-only), the compiled
/// `filter`, and the requested `attributes` selection.
///
/// # Errors
///
/// [`CurlError::UrlMalformat`] if `filter` is not a well-formed RFC 4515 filter.
fn build_search_request(
    message_id: i64,
    base_dn: &str,
    scope: Scope,
    filter: &str,
    attributes: &[String],
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    ber::encode_tlv(&mut body, BER_OCTET_STRING, base_dn.as_bytes());
    ber::encode_int(&mut body, BER_ENUMERATED, i64::from(scope.wire_value()));
    ber::encode_int(&mut body, BER_ENUMERATED, i64::from(LDAP_DEREF_NEVER));
    ber::encode_int(&mut body, BER_INTEGER, 0); // sizeLimit: no limit
    ber::encode_int(&mut body, BER_INTEGER, 0); // timeLimit: no limit
    ber::encode_bool(&mut body, BER_BOOLEAN, false); // typesOnly: false

    encode_filter(&mut body, filter)?;

    // AttributeSelection ::= SEQUENCE OF LDAPString. An empty sequence requests
    // all user attributes (the LDAP default).
    let mut attrs = Vec::new();
    for attr in attributes {
        ber::encode_tlv(&mut attrs, BER_OCTET_STRING, attr.as_bytes());
    }
    ber::encode_tlv(&mut body, BER_SEQUENCE, &attrs);

    Ok(wrap_message(message_id, LDAP_REQ_SEARCH, &body))
}

// ===========================================================================
// RFC 4515 search-filter compiler → BER Filter (RFC 4511 §4.5.1).
//
// Supports the full string-filter grammar except `extensibleMatch` (the `:=`
// form), which curl/libldap accept but which no curl test exercises.
// ===========================================================================

/// Compile an RFC 4515 string filter into its BER `Filter` encoding, appending
/// to `out`. Accepts either a parenthesized filter (`(objectclass=*)`) or a bare
/// item (`objectclass=*`).
///
/// # Errors
///
/// [`CurlError::UrlMalformat`] for any malformed filter (unbalanced parentheses,
/// empty attribute, or trailing junk) — the analog of libldap rejecting the
/// filter string.
fn encode_filter(out: &mut Vec<u8>, filter: &str) -> Result<()> {
    let bytes = filter.as_bytes();
    let mut pos = 0;
    skip_ws(bytes, &mut pos);
    if pos < bytes.len() && bytes[pos] == b'(' {
        parse_paren_filter(bytes, &mut pos, out)?;
    } else {
        parse_item(bytes, &mut pos, bytes.len(), out)?;
    }
    skip_ws(bytes, &mut pos);
    if pos != bytes.len() {
        return Err(CurlError::UrlMalformat);
    }
    Ok(())
}

/// Skip ASCII spaces at `*pos`.
fn skip_ws(bytes: &[u8], pos: &mut usize) {
    while *pos < bytes.len() && bytes[*pos] == b' ' {
        *pos += 1;
    }
}

/// Parse a parenthesized filter `( filtercomp )` at `*pos`, dispatching on the
/// leading `&` / `|` / `!` to the set operators or otherwise to an item.
fn parse_paren_filter(bytes: &[u8], pos: &mut usize, out: &mut Vec<u8>) -> Result<()> {
    if *pos >= bytes.len() || bytes[*pos] != b'(' {
        return Err(CurlError::UrlMalformat);
    }
    *pos += 1; // consume '('
    skip_ws(bytes, pos);
    let kind = *bytes.get(*pos).ok_or(CurlError::UrlMalformat)?;
    match kind {
        b'&' | b'|' => {
            *pos += 1;
            let mut children = Vec::new();
            // 1*filter
            let mut count = 0;
            loop {
                skip_ws(bytes, pos);
                match bytes.get(*pos) {
                    Some(b'(') => {
                        parse_paren_filter(bytes, pos, &mut children)?;
                        count += 1;
                    }
                    Some(b')') => break,
                    _ => return Err(CurlError::UrlMalformat),
                }
            }
            if count == 0 {
                return Err(CurlError::UrlMalformat);
            }
            let tag = if kind == b'&' { FILTER_AND } else { FILTER_OR };
            ber::encode_tlv(out, tag, &children);
        }
        b'!' => {
            *pos += 1;
            skip_ws(bytes, pos);
            let mut child = Vec::new();
            parse_paren_filter(bytes, pos, &mut child)?;
            ber::encode_tlv(out, FILTER_NOT, &child);
        }
        _ => {
            // Find the matching ')': an item runs to the next ')'.
            let end = find_close(bytes, *pos)?;
            parse_item(bytes, pos, end, out)?;
            *pos = end; // position at ')'
        }
    }
    // consume the closing ')'
    skip_ws(bytes, pos);
    if bytes.get(*pos) != Some(&b')') {
        return Err(CurlError::UrlMalformat);
    }
    *pos += 1;
    Ok(())
}

/// Index of the next `)` at or after `start`, error if none.
fn find_close(bytes: &[u8], start: usize) -> Result<usize> {
    bytes[start..]
        .iter()
        .position(|&b| b == b')')
        .map(|off| start + off)
        .ok_or(CurlError::UrlMalformat)
}

/// Parse a single filter `item` (simple / present / substring) spanning
/// `bytes[*pos..end]`, appending its BER encoding to `out` and leaving `*pos` at
/// `end`.
fn parse_item(bytes: &[u8], pos: &mut usize, end: usize, out: &mut Vec<u8>) -> Result<()> {
    // Attribute description: up to the filter-type operator.
    let attr_start = *pos;
    while *pos < end && !matches!(bytes[*pos], b'=' | b'~' | b'<' | b'>') {
        *pos += 1;
    }
    let attr = &bytes[attr_start..*pos];
    if attr.is_empty() || *pos >= end {
        return Err(CurlError::UrlMalformat);
    }

    // Determine the filter type and advance past its operator.
    let op = bytes[*pos];
    let tag = match op {
        b'=' => {
            *pos += 1;
            FILTER_EQUALITY // refined below to present/substrings
        }
        b'~' => {
            expect_eq(bytes, pos)?;
            FILTER_APPROX
        }
        b'>' => {
            expect_eq(bytes, pos)?;
            FILTER_GE
        }
        b'<' => {
            expect_eq(bytes, pos)?;
            FILTER_LE
        }
        _ => return Err(CurlError::UrlMalformat),
    };

    let raw_value = &bytes[*pos..end];
    *pos = end;

    // present: "attr=*"
    if tag == FILTER_EQUALITY && raw_value == b"*" {
        ber::encode_tlv(out, FILTER_PRESENT, attr);
        return Ok(());
    }

    // substrings: an "=" value containing an unescaped '*'.
    if tag == FILTER_EQUALITY && raw_value.contains(&b'*') {
        encode_substrings(out, attr, raw_value)?;
        return Ok(());
    }

    // Otherwise an AttributeValueAssertion: SEQUENCE { attr, value }.
    let value = unescape_filter_value(raw_value)?;
    let mut ava = Vec::new();
    ber::encode_tlv(&mut ava, BER_OCTET_STRING, attr);
    ber::encode_tlv(&mut ava, BER_OCTET_STRING, &value);
    ber::encode_tlv(out, tag, &ava);
    Ok(())
}

/// Consume a `=` that must follow a `~` / `<` / `>` operator lead-in.
fn expect_eq(bytes: &[u8], pos: &mut usize) -> Result<()> {
    *pos += 1; // consume the lead-in char
    if bytes.get(*pos) != Some(&b'=') {
        return Err(CurlError::UrlMalformat);
    }
    *pos += 1;
    Ok(())
}

/// Encode a `substrings [4]` filter from an `=`-value containing `*` separators
/// (RFC 4511 §4.5.1): leading text → `initial [0]`, trailing text → `final [2]`,
/// each interior segment → `any [1]`.
fn encode_substrings(out: &mut Vec<u8>, attr: &[u8], raw_value: &[u8]) -> Result<()> {
    let segments: Vec<&[u8]> = raw_value.split(|&b| b == b'*').collect();
    let last = segments.len() - 1;

    let mut subs = Vec::new();
    for (i, seg) in segments.iter().enumerate() {
        if seg.is_empty() {
            continue;
        }
        let value = unescape_filter_value(seg)?;
        let tag = if i == 0 {
            SUBSTR_INITIAL
        } else if i == last {
            SUBSTR_FINAL
        } else {
            SUBSTR_ANY
        };
        ber::encode_tlv(&mut subs, tag, &value);
    }
    if subs.is_empty() {
        return Err(CurlError::UrlMalformat);
    }

    // SubstringFilter ::= SEQUENCE { type, substrings SEQUENCE OF ... }
    let mut body = Vec::new();
    ber::encode_tlv(&mut body, BER_OCTET_STRING, attr);
    ber::encode_tlv(&mut body, BER_SEQUENCE, &subs);
    ber::encode_tlv(out, FILTER_SUBSTRINGS, &body);
    Ok(())
}

/// Decode RFC 4515 §3 value escaping: `\XX` (two hex digits) → the byte. A lone
/// `\` or a non-hex escape is a malformed filter.
fn unescape_filter_value(value: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(value.len());
    let mut i = 0;
    while i < value.len() {
        if value[i] == b'\\' {
            let hi = value.get(i + 1).copied().and_then(hex_value);
            let lo = value.get(i + 2).copied().and_then(hex_value);
            match (hi, lo) {
                (Some(hi), Some(lo)) => {
                    out.push((hi << 4) | lo);
                    i += 3;
                }
                _ => return Err(CurlError::UrlMalformat),
            }
        } else {
            out.push(value[i]);
            i += 1;
        }
    }
    Ok(out)
}

// ===========================================================================
// LDAP response decoding (RFC 4511 §4.1.1 envelope + §4.5.2 entry).
// ===========================================================================

/// A decoded `searchResultEntry` (RFC 4511 §4.5.2). Raw bytes are retained for
/// the DN, attribute names, and values because LDAP carries arbitrary octet
/// strings (the LDIF formatter base64-encodes any non-printable value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapEntry {
    /// `objectName` — the entry's distinguished name (raw octets).
    pub dn: Vec<u8>,
    /// `PartialAttributeList` — `(type, [value, ...])` pairs in wire order. An
    /// attribute with an empty value list is preserved (rendered `attr:`).
    pub attributes: Vec<(Vec<u8>, Vec<Vec<u8>>)>,
}

/// The protocol operation carried by a decoded `LDAPMessage`, limited to the
/// operations this client issues or observes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LdapResponse {
    /// `bindResponse` carrying its `resultCode`.
    Bind(i64),
    /// `searchResultEntry`.
    Entry(LdapEntry),
    /// `searchResultDone` carrying its `resultCode`.
    Done(i64),
    /// `searchResultReference` — a continuation reference, skipped by curl.
    Reference,
    /// Any other protocol-op tag (ignored).
    Other(u8),
}

/// Decode one `LDAPMessage` (RFC 4511 §4.1.1) into its message id and operation.
///
/// # Errors
///
/// [`CurlError::WeirdServerReply`] for any structural violation (wrong outer
/// tag, missing message id, truncated TLV).
fn parse_message(bytes: &[u8]) -> Result<(i64, LdapResponse)> {
    let mut top = ber::Reader::new(bytes);
    let envelope = top.read()?;
    if envelope.tag != BER_SEQUENCE {
        return Err(CurlError::WeirdServerReply);
    }
    let mut inner = ber::Reader::new(envelope.value);

    let id_tlv = inner.read()?;
    if id_tlv.tag != BER_INTEGER {
        return Err(CurlError::WeirdServerReply);
    }
    let message_id = ber::decode_int(id_tlv.value)?;

    let op = inner.read()?;
    let response = match op.tag {
        LDAP_RES_BIND => LdapResponse::Bind(parse_ldap_result(op.value)?),
        LDAP_RES_SEARCH_ENTRY => LdapResponse::Entry(parse_search_entry(op.value)?),
        LDAP_RES_SEARCH_RESULT => LdapResponse::Done(parse_ldap_result(op.value)?),
        LDAP_RES_SEARCH_REFERENCE => LdapResponse::Reference,
        other => LdapResponse::Other(other),
    };
    Ok((message_id, response))
}

/// Decode the `resultCode` from an `LDAPResult` body (RFC 4511 §4.1.9), whose
/// first element is the result `ENUMERATED`.
fn parse_ldap_result(value: &[u8]) -> Result<i64> {
    let mut r = ber::Reader::new(value);
    let code = r.read()?;
    if code.tag != BER_ENUMERATED {
        return Err(CurlError::WeirdServerReply);
    }
    ber::decode_int(code.value)
}

/// Decode a `searchResultEntry` body (RFC 4511 §4.5.2):
/// `SEQUENCE { objectName, attributes SEQUENCE OF SEQUENCE { type, vals SET } }`.
fn parse_search_entry(value: &[u8]) -> Result<LdapEntry> {
    let mut r = ber::Reader::new(value);
    let dn = r.read()?.value.to_vec();

    let attrs_seq = r.read()?;
    if attrs_seq.tag != BER_SEQUENCE {
        return Err(CurlError::WeirdServerReply);
    }

    let mut attributes = Vec::new();
    let mut ar = ber::Reader::new(attrs_seq.value);
    while !ar.is_empty() {
        let partial = ar.read()?;
        if partial.tag != BER_SEQUENCE {
            return Err(CurlError::WeirdServerReply);
        }
        let mut pr = ber::Reader::new(partial.value);
        let name = pr.read()?.value.to_vec();

        let vals = pr.read()?;
        if vals.tag != BER_SET {
            return Err(CurlError::WeirdServerReply);
        }
        let mut values = Vec::new();
        let mut vr = ber::Reader::new(vals.value);
        while !vr.is_empty() {
            values.push(vr.read()?.value.to_vec());
        }
        attributes.push((name, values));
    }

    Ok(LdapEntry { dn, attributes })
}

// ===========================================================================
// LDIF formatting (oracle: `openldap.c` `oldap_recv` + `client_write`).
// ===========================================================================

/// curl's `ISBLANK` — an ASCII space or tab.
const fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// curl's `ISPRINT` — a printable ASCII character (`0x20..=0x7e`). Bytes `>=
/// 0x80` are treated as non-printable, exactly as curl's ASCII `ctype` table
/// does, which is why UTF-8 / binary values get base64-encoded.
const fn is_print(b: u8) -> bool {
    b >= 0x20 && b <= 0x7e
}

/// Append one `client_write(prefix, value, suffix)` unit, reproducing
/// `openldap.c`'s `client_write()` — including its rule that a trailing space in
/// `prefix` is dropped when `value` is empty (so an empty value renders without
/// a dangling separator). An empty `prefix`/`value`/`suffix` is the analog of
/// the C `NULL` argument (nothing written).
fn ldif_write(out: &mut Vec<u8>, prefix: &[u8], value: &[u8], suffix: &[u8]) {
    if !prefix.is_empty() {
        let last = prefix[prefix.len() - 1];
        let p = if value.is_empty() && last == b' ' {
            &prefix[..prefix.len() - 1]
        } else {
            prefix
        };
        out.extend_from_slice(p);
    }
    out.extend_from_slice(value);
    out.extend_from_slice(suffix);
}

/// Format one [`LdapEntry`] as LDIF, appending to `out` — a byte-for-byte
/// reproduction of `openldap.c`'s `LDAP_RES_SEARCH_ENTRY` branch:
///
/// * `DN: <dn>\n`
/// * per attribute with no values: `\t<attr>:\n`
/// * per value: `\t<attr>: <value>\n`, or `\t<attr>:: <base64>\n` when the
///   attribute name ends in `;binary` or the value contains a leading/trailing
///   blank or any non-printable byte (the LDIF base64 `::` convention)
/// * a blank line after each attribute, and a final blank line after the entry.
pub fn format_entry(out: &mut Vec<u8>, entry: &LdapEntry) {
    ldif_write(out, b"DN: ", &entry.dn, b"\n");

    for (name, values) in &entry.attributes {
        if values.is_empty() {
            // Attribute present with no values: "\t<attr>:\n", and (matching
            // `openldap.c`'s `if(!bvals) { …; continue; }`) NO trailing blank
            // line for this attribute.
            //
            // PARITY: on the wire a `PartialAttribute` always carries a `SET OF`
            // (possibly empty); libldap collapses an empty set to a NULL `bvals`
            // (this branch) on every version curl's tests touch, so the readable
            // `"\t<attr>:\n"` form is reproduced here.
            ldif_write(out, b"\t", name, b":\n");
            continue;
        }

        // ";binary" attribute option forces base64 (case-insensitive, 7 bytes).
        let binary = name.len() > 7 && name[name.len() - 7..].eq_ignore_ascii_case(b";binary");

        for value in values {
            ldif_write(out, b"\t", name, b":");

            // base64 (the `::` form) is required when the attribute carries the
            // ";binary" option, when the value has a leading/trailing blank, or
            // when it contains any non-printable byte — `openldap.c`'s `binval`
            // logic. `||` short-circuits, so the scan runs only when needed.
            let has_edge_blank =
                !value.is_empty() && (is_blank(value[0]) || is_blank(value[value.len() - 1]));
            let binval = binary || has_edge_blank || value.iter().any(|&b| !is_print(b));

            if binval {
                let encoded = base64_encode(value);
                ldif_write(out, b": ", &encoded, b"\n");
            } else {
                ldif_write(out, b" ", value, b"\n");
            }
        }

        // Blank line after each attribute's values.
        ldif_write(out, b"\n", b"", b"");
    }

    // Blank line terminating the entry.
    ldif_write(out, b"\n", b"", b"");
}

// ===========================================================================
// Result-code mapping (oracle: `openldap.c` `oldap_map_error` + `ldap.c`).
// ===========================================================================

/// Map an LDAP `resultCode` to a [`CurlError`], reproducing `openldap.c`'s
/// `oldap_map_error()`: a recognized server condition maps to its specific
/// `CURLcode`, otherwise `default_error` (the operation's generic failure) is
/// used.
fn map_result_to_error(code: i64, default_error: CurlError) -> CurlError {
    match code {
        LDAP_INVALID_CREDENTIALS => CurlError::LoginDenied,
        LDAP_PROTOCOL_ERROR => CurlError::UnsupportedProtocol,
        LDAP_INSUFFICIENT_ACCESS => CurlError::RemoteAccessDenied,
        _ => default_error,
    }
}

/// Translate a `bindResponse` result code into a [`Result`]: `success` is `Ok`,
/// any other code is an error (`ldap.c` reports a bind failure as
/// [`CurlError::LdapCannotBind`], refined by [`map_result_to_error`]).
fn bind_result(code: i64) -> Result<()> {
    if code == LDAP_SUCCESS {
        Ok(())
    } else {
        Err(map_result_to_error(code, CurlError::LdapCannotBind))
    }
}

/// Translate a `searchResultDone` result code into a [`Result`]: `success` and
/// `sizeLimitExceeded` are treated as success (the latter only warns, per
/// `openldap.c`), any other code is [`CurlError::LdapSearchFailed`] (refined by
/// [`map_result_to_error`]).
fn search_done_result(code: i64) -> Result<()> {
    if code == LDAP_SUCCESS || code == LDAP_SIZELIMIT_EXCEEDED {
        Ok(())
    } else {
        Err(map_result_to_error(code, CurlError::LdapSearchFailed))
    }
}

// ===========================================================================
// Connection I/O helpers — drive the `crate::conn` filter chain to completion.
//
// `ldaps` TLS and any `ldap` STARTTLS upgrade are handled transparently by the
// filter chain (PROTOPT_SSL / PROTOPT_SSL_REUSE), so these helpers only ever
// move *plaintext* LDAP messages; the chain encrypts/decrypts as configured.
// ===========================================================================

/// The receive chunk size for a single [`Curl_conn_recv`] call. LDAP PDUs in
/// curl's tests are small; a 4 KiB scratch buffer drains a typical response in
/// one or two reads while the streaming framer ([`ber::try_total_len`]) handles
/// PDUs split across reads or coalesced into one.
const RECV_CHUNK: usize = 4096;

/// Send the whole of `buf` through the connection's first socket, looping until
/// every byte is accepted (the filter chain may accept a partial write) and
/// transparently retrying on the non-blocking [`CurlError::Again`] signal.
///
/// # Errors
///
/// [`CurlError::SendError`] if the peer accepts zero bytes (a closed write
/// side), or any transport error surfaced by [`Curl_conn_send`].
async fn send_all(conn: &mut Connection, buf: &[u8]) -> Result<()> {
    let mut sent = 0usize;
    while sent < buf.len() {
        match Curl_conn_send(conn, FIRSTSOCKET, &buf[sent..], false).await {
            Ok(0) => return Err(CurlError::SendError),
            Ok(n) => sent += n,
            // PARITY: curl's nonblocking sockets surface EAGAIN as CURLE_AGAIN
            // and the multi loop re-polls; under Tokio the await already parks
            // until writable, so re-issuing the send is the faithful analog.
            Err(CurlError::Again) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Read and decode exactly one [`LDAPMessage`](parse_message) from the
/// connection, buffering across [`Curl_conn_recv`] calls. `rxbuf` carries any
/// bytes left over from a previous message (LDAP responses are commonly
/// pipelined), so it MUST be the same buffer across successive calls within one
/// exchange.
///
/// # Errors
///
/// [`CurlError::WeirdServerReply`] if the connection closes before a full
/// message arrives or the framing is malformed, or any transport error from
/// [`Curl_conn_recv`].
async fn next_message(conn: &mut Connection, rxbuf: &mut Vec<u8>) -> Result<(i64, LdapResponse)> {
    loop {
        // If a complete PDU is already buffered, decode and drain it.
        if let Some(total) = ber::try_total_len(rxbuf)? {
            if rxbuf.len() >= total {
                let parsed = parse_message(&rxbuf[..total])?;
                rxbuf.drain(..total);
                return Ok(parsed);
            }
        }

        let mut tmp = [0u8; RECV_CHUNK];
        let n = match Curl_conn_recv(conn, FIRSTSOCKET, &mut tmp).await {
            Ok(n) => n,
            // PARITY: as in `send_all`, re-await on the nonblocking signal.
            Err(CurlError::Again) => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            // EOF before a full PDU — the server hung up mid-message.
            return Err(CurlError::WeirdServerReply);
        }
        rxbuf.extend_from_slice(&tmp[..n]);
    }
}

// ===========================================================================
// `LdapHandler` — the `Protocol` implementation for `ldap` and `ldaps`.
// ===========================================================================

/// The protocol handler serving both `ldap://` and `ldaps://`.
///
/// A single stateless handler type backs both schemes — exactly as curl's C
/// code shares `Curl_handler_ldap` / `Curl_handler_ldaps` over the same
/// `openldap.c` implementation — distinguished only by the [`Scheme`] descriptor
/// it carries (which differs in default port and the `PROTOPT_SSL` vs
/// `PROTOPT_SSL_REUSE` flag). All per-transfer state lives on the [`Easy`]
/// handle and the [`Connection`]; the handler holds only the static descriptor,
/// so one instance can serve every transfer of its scheme.
pub struct LdapHandler {
    /// The static scheme descriptor ([`SCHEME_LDAP`] or [`SCHEME_LDAPS`]).
    scheme: &'static Scheme,
}

impl LdapHandler {
    /// Construct a handler bound to a specific scheme descriptor — used by the
    /// registry, which already holds the `&'static` descriptor from the scheme
    /// table.
    #[must_use]
    pub const fn new(scheme: &'static Scheme) -> Self {
        Self { scheme }
    }

    /// Construct the `ldap://` handler ([`SCHEME_LDAP`], port 389).
    #[must_use]
    pub const fn ldap() -> Self {
        Self::new(&SCHEME_LDAP)
    }

    /// Construct the `ldaps://` handler ([`SCHEME_LDAPS`], port 636).
    #[must_use]
    pub const fn ldaps() -> Self {
        Self::new(&SCHEME_LDAPS)
    }
}

impl Protocol for LdapHandler {
    fn scheme(&self) -> &'static Scheme {
        self.scheme
    }

    /// Perform the LDAP query: parse the LDAP URL, bind (anonymous or simple),
    /// issue the search, collect `searchResEntry` records into an LDIF body, and
    /// confirm the `searchResDone` status — the fused analog of curl's
    /// `ldap_do()` / `oldap_do()` + the `doing` loop.
    ///
    /// Errors are mapped exactly as the C oracle does: a malformed LDAP URL is
    /// [`CurlError::UrlMalformat`] (`ldap.c`), a bind failure is
    /// [`CurlError::LdapCannotBind`] (refined by [`map_result_to_error`]), and a
    /// search failure is [`CurlError::LdapSearchFailed`].
    fn do_it<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<ProtocolTransfer>> {
        Box::pin(async move {
            let verbose = data.set.verbose;
            // `failf` writes to the transfer's error buffer in curl; the Easy
            // handle exposes no error-buffer slot at this checkpoint, so a local
            // buffer captures the message (still emitted via tracing, exactly as
            // curl's `failf` always logs) while the typed error is returned.
            let mut errbuf: Option<String> = None;

            // --- 1. Resolve and parse the LDAP URL (RFC 4516). ---------------
            let Some(url_str) = data.url().map(str::to_string) else {
                failf(&mut errbuf, "LDAP local: no URL set");
                return Err(CurlError::UrlMalformat);
            };

            let mut handle = CurlUrl::new();
            if handle
                .set(
                    CurlUPart::Url,
                    Some(&url_str),
                    CURLU_GUESS_SCHEME | CURLU_NON_SUPPORT_SCHEME,
                )
                .is_err()
            {
                failf(&mut errbuf, "LDAP local: bad LDAP URL");
                return Err(CurlError::UrlMalformat);
            }

            // Path (DN) and query (attributes/scope/filter) are taken without
            // URL-decoding; `LdapUrl::parse` performs the RFC 4516 decoding.
            let path = handle.get(CurlUPart::Path, 0).unwrap_or_default();
            let query = handle.get(CurlUPart::Query, 0).ok();
            // Bind credentials come from the URL userinfo, URL-decoded.
            let user = handle.get(CurlUPart::User, CURLU_URLDECODE).ok();
            let password = handle.get(CurlUPart::Password, CURLU_URLDECODE).ok();

            let ldap_url = match LdapUrl::parse(&path, query.as_deref()) {
                Ok(parsed) => parsed,
                Err(e) => {
                    failf(&mut errbuf, "LDAP local: bad LDAP URL");
                    return Err(e);
                }
            };

            infof(
                verbose,
                &format!(
                    "LDAP local: trying to bind, DN \"{}\", scope {}",
                    if user.as_deref().unwrap_or("").is_empty() {
                        "(anonymous)"
                    } else {
                        user.as_deref().unwrap_or("")
                    },
                    ldap_url.scope.wire_value()
                ),
            );

            // --- 2. Bind (message id 1). ------------------------------------
            let bind_dn = user.as_deref().unwrap_or("");
            let bind_pw = password.as_deref().unwrap_or("");
            let bind = build_bind_request(1, bind_dn, bind_pw.as_bytes());
            send_all(conn, &bind).await?;

            let mut rxbuf: Vec<u8> = Vec::new();
            match next_message(conn, &mut rxbuf).await? {
                (_, LdapResponse::Bind(code)) => {
                    if let Err(e) = bind_result(code) {
                        failf(
                            &mut errbuf,
                            &format!("LDAP local: bind failed (result code {code})"),
                        );
                        return Err(e);
                    }
                }
                _ => {
                    failf(&mut errbuf, "LDAP local: unexpected response to bind");
                    return Err(CurlError::LdapCannotBind);
                }
            }
            infof(verbose, "LDAP local: bind success");

            // --- 3. Search (message id 2). ----------------------------------
            let filter = ldap_url.filter.as_deref().unwrap_or(DEFAULT_FILTER);
            let search = match build_search_request(
                2,
                &ldap_url.dn,
                ldap_url.scope,
                filter,
                &ldap_url.attributes,
            ) {
                Ok(bytes) => bytes,
                Err(e) => {
                    failf(&mut errbuf, "LDAP local: bad search filter");
                    return Err(e);
                }
            };
            send_all(conn, &search).await?;

            // --- 4. Collect entries until searchResultDone. -----------------
            let mut body: Vec<u8> = Vec::new();
            let mut entries: u64 = 0;
            loop {
                match next_message(conn, &mut rxbuf).await? {
                    (_, LdapResponse::Entry(entry)) => {
                        format_entry(&mut body, &entry);
                        entries += 1;
                    }
                    // Continuation references are not followed (parity with
                    // curl's default, which ignores them for output).
                    (_, LdapResponse::Reference) => {}
                    (_, LdapResponse::Done(code)) => {
                        if code == LDAP_SIZELIMIT_EXCEEDED {
                            infof(verbose, &format!("There are more than {entries} entries"));
                        }
                        if let Err(e) = search_done_result(code) {
                            failf(&mut errbuf, "LDAP remote: search failed");
                            return Err(e);
                        }
                        break;
                    }
                    // A stray bindResponse or any other op is ignored, matching
                    // curl's tolerance of unexpected intermediate messages.
                    (_, LdapResponse::Bind(_) | LdapResponse::Other(_)) => {}
                }
            }
            infof(
                verbose,
                &format!("LDAP local: search complete, {entries} entries"),
            );

            // --- 5. Unbind (message id 3, best effort). ---------------------
            let unbind = build_unbind_request(3);
            let _ = send_all(conn, &unbind).await;

            // PARITY: the assembled LDIF `body` is delivered to the client
            // writer here once the transfer engine's protocol-drive seam is
            // wired (no protocol delivers a body to the writer at this
            // checkpoint — `do_it` is not yet invoked by the engine for any
            // scheme). The transfer descriptor reports the body's size so the
            // engine can account for it; the byte handoff lands with the seam.
            Ok(ProtocolTransfer::new(TransferDirection::Download).with_size(body.len() as u64))
        })
    }
}

// ===========================================================================
// Unit tests — URL parsing, BER round-trips, request builders, the RFC 4515
// filter compiler, response decoding, LDIF formatting, and result mapping.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ----- Test helpers -----------------------------------------------------

    /// Decode a single TLV at the front of `buf`, returning `(tag, value)`.
    fn one_tlv(buf: &[u8]) -> (u8, Vec<u8>) {
        let mut r = ber::Reader::new(buf);
        let tlv = r.read().expect("valid TLV");
        (tlv.tag, tlv.value.to_vec())
    }

    /// Build a `searchResultEntry` `LDAPMessage` from a DN and `(attr, [values])`
    /// pairs, used to exercise the parser + LDIF formatter end to end.
    fn build_entry_msg(message_id: i64, dn: &[u8], attrs: &[(&[u8], &[&[u8]])]) -> Vec<u8> {
        let mut entry = Vec::new();
        ber::encode_tlv(&mut entry, BER_OCTET_STRING, dn);
        let mut attrs_seq = Vec::new();
        for (name, vals) in attrs {
            let mut partial = Vec::new();
            ber::encode_tlv(&mut partial, BER_OCTET_STRING, name);
            let mut set = Vec::new();
            for v in *vals {
                ber::encode_tlv(&mut set, BER_OCTET_STRING, v);
            }
            ber::encode_tlv(&mut partial, BER_SET, &set);
            ber::encode_tlv(&mut attrs_seq, BER_SEQUENCE, &partial);
        }
        ber::encode_tlv(&mut entry, BER_SEQUENCE, &attrs_seq);
        wrap_message(message_id, LDAP_RES_SEARCH_ENTRY, &entry)
    }

    /// Build an `LDAPResult`-bearing message (bindResponse / searchResultDone)
    /// with a given `resultCode`.
    fn build_result_msg(message_id: i64, op_tag: u8, code: i64) -> Vec<u8> {
        let mut body = Vec::new();
        ber::encode_int(&mut body, BER_ENUMERATED, code);
        ber::encode_tlv(&mut body, BER_OCTET_STRING, b""); // matchedDN
        ber::encode_tlv(&mut body, BER_OCTET_STRING, b""); // diagnosticMessage
        wrap_message(message_id, op_tag, &body)
    }

    // ----- Scope keyword mapping -------------------------------------------

    #[test]
    fn scope_keywords_match_oracle() {
        assert_eq!(str2scope("base"), Some(Scope::Base));
        assert_eq!(str2scope("BASE"), Some(Scope::Base)); // case-insensitive
        assert_eq!(str2scope("one"), Some(Scope::OneLevel));
        assert_eq!(str2scope("onetree"), Some(Scope::OneLevel));
        assert_eq!(str2scope("sub"), Some(Scope::Subtree));
        assert_eq!(str2scope("subtree"), Some(Scope::Subtree));
        assert_eq!(str2scope("bogus"), None);
        assert_eq!(str2scope(""), None);
    }

    #[test]
    fn scope_wire_values() {
        assert_eq!(Scope::Base.wire_value(), 0);
        assert_eq!(Scope::OneLevel.wire_value(), 1);
        assert_eq!(Scope::Subtree.wire_value(), 2);
    }

    // ----- RFC 4516 URL parsing --------------------------------------------

    #[test]
    fn url_dn_only() {
        let u = LdapUrl::parse("/dc=example,dc=com", None).unwrap();
        assert_eq!(u.dn, "dc=example,dc=com");
        assert!(u.attributes.is_empty());
        assert_eq!(u.scope, Scope::Base);
        assert_eq!(u.filter, None);
    }

    #[test]
    fn url_empty_dn() {
        let u = LdapUrl::parse("/", None).unwrap();
        assert_eq!(u.dn, "");
        assert!(u.attributes.is_empty());
        assert_eq!(u.scope, Scope::Base);
    }

    #[test]
    fn url_dn_percent_decoded() {
        let u = LdapUrl::parse("/o=University%20of%20Michigan,c=US", None).unwrap();
        assert_eq!(u.dn, "o=University of Michigan,c=US");
    }

    #[test]
    fn url_attributes_split_before_decode() {
        // Attributes split on a *literal* comma, then each is percent-decoded —
        // so "%2C" (encoded comma) stays inside a single attribute name.
        let u = LdapUrl::parse("/dc=x", Some("cn,mail,a%20b")).unwrap();
        assert_eq!(u.attributes, vec!["cn", "mail", "a b"]);

        let u2 = LdapUrl::parse("/dc=x", Some("cn%2Cmail")).unwrap();
        assert_eq!(u2.attributes, vec!["cn,mail"]);
    }

    #[test]
    fn url_full_attrs_scope_filter() {
        let u = LdapUrl::parse("/dc=example,dc=com", Some("cn,sn?sub?(objectClass=*)")).unwrap();
        assert_eq!(u.dn, "dc=example,dc=com");
        assert_eq!(u.attributes, vec!["cn", "sn"]);
        assert_eq!(u.scope, Scope::Subtree);
        assert_eq!(u.filter.as_deref(), Some("(objectClass=*)"));
    }

    #[test]
    fn url_scope_keywords() {
        assert_eq!(
            LdapUrl::parse("/d", Some("?one?")).unwrap().scope,
            Scope::OneLevel
        );
        assert_eq!(
            LdapUrl::parse("/d", Some("?onetree")).unwrap().scope,
            Scope::OneLevel
        );
        assert_eq!(
            LdapUrl::parse("/d", Some("?base")).unwrap().scope,
            Scope::Base
        );
        // An empty scope field keeps the base default.
        assert_eq!(
            LdapUrl::parse("/d", Some("cn??(cn=x)")).unwrap().scope,
            Scope::Base
        );
    }

    #[test]
    fn url_filter_percent_decoded() {
        let u = LdapUrl::parse("/d", Some("?sub?(o=University%20of%20Michigan)")).unwrap();
        assert_eq!(u.filter.as_deref(), Some("(o=University of Michigan)"));
    }

    #[test]
    fn url_errors() {
        // Path must be absolute.
        assert!(matches!(
            LdapUrl::parse("dc=x", None),
            Err(CurlError::UrlMalformat)
        ));
        // Unrecognized scope keyword.
        assert!(matches!(
            LdapUrl::parse("/d", Some("?bogus")),
            Err(CurlError::UrlMalformat)
        ));
        // Dangling trailing '?' opening an empty extensions field.
        assert!(matches!(
            LdapUrl::parse("/d", Some("cn?sub?(cn=*)?")),
            Err(CurlError::UrlMalformat)
        ));
        // A NUL-decoding escape in the DN is rejected (REJECT_ZERO).
        assert!(matches!(
            LdapUrl::parse("/dc=%00", None),
            Err(CurlError::UrlMalformat)
        ));
    }

    #[test]
    fn url_nonempty_extensions_accepted() {
        // A non-empty extensions field is accepted and ignored.
        let u = LdapUrl::parse("/d", Some("cn?sub?(cn=*)?!x-ext=1")).unwrap();
        assert_eq!(u.scope, Scope::Subtree);
        assert_eq!(u.filter.as_deref(), Some("(cn=*)"));
    }

    // ----- BER / DER codec --------------------------------------------------

    #[test]
    fn ber_int_roundtrip() {
        for v in [
            0i64, 1, 127, 128, 255, 256, -1, -128, 32767, -32768, 12_345_678,
        ] {
            let mut buf = Vec::new();
            ber::encode_int(&mut buf, BER_INTEGER, v);
            let (tag, value) = one_tlv(&buf);
            assert_eq!(tag, BER_INTEGER);
            assert_eq!(ber::decode_int(&value).unwrap(), v, "roundtrip {v}");
        }
    }

    #[test]
    fn ber_int_minimal_encoding() {
        // 127 fits in one octet; 128 needs a leading 0x00 to keep the sign bit 0.
        let mut a = Vec::new();
        ber::encode_int(&mut a, BER_INTEGER, 127);
        assert_eq!(a, vec![0x02, 0x01, 0x7f]);
        let mut b = Vec::new();
        ber::encode_int(&mut b, BER_INTEGER, 128);
        assert_eq!(b, vec![0x02, 0x02, 0x00, 0x80]);
        let mut c = Vec::new();
        ber::encode_int(&mut c, BER_INTEGER, -1);
        assert_eq!(c, vec![0x02, 0x01, 0xff]);
    }

    #[test]
    fn ber_long_length_roundtrip() {
        let payload = vec![0xABu8; 200];
        let mut buf = Vec::new();
        ber::encode_tlv(&mut buf, BER_OCTET_STRING, &payload);
        // 200 >= 128 => long form: 0x81 0xc8.
        assert_eq!(&buf[..3], &[0x04, 0x81, 0xc8]);
        let (tag, value) = one_tlv(&buf);
        assert_eq!(tag, BER_OCTET_STRING);
        assert_eq!(value, payload);
    }

    #[test]
    fn ber_reader_rejects_truncation() {
        // Claims 5 content bytes but supplies only 2.
        let mut r = ber::Reader::new(&[0x04, 0x05, 0x01, 0x02]);
        assert!(matches!(r.read(), Err(CurlError::WeirdServerReply)));
    }

    #[test]
    fn ber_try_total_len() {
        // Short form: total = 2 + content.
        assert_eq!(ber::try_total_len(&[0x30, 0x0c]).unwrap(), Some(14));
        // Incomplete header.
        assert_eq!(ber::try_total_len(&[0x30]).unwrap(), None);
        // Long form needing one length octet, not yet present.
        assert_eq!(ber::try_total_len(&[0x04, 0x81]).unwrap(), None);
        // Long form complete: 0x81 0xc8 => 200 content => 203 total.
        assert_eq!(ber::try_total_len(&[0x04, 0x81, 0xc8]).unwrap(), Some(203));
        // Indefinite length is rejected.
        assert!(matches!(
            ber::try_total_len(&[0x30, 0x80]),
            Err(CurlError::WeirdServerReply)
        ));
    }

    // ----- Request builders -------------------------------------------------

    #[test]
    fn bind_request_anonymous_golden() {
        // Anonymous simple bind, message id 1.
        let msg = build_bind_request(1, "", b"");
        assert_eq!(
            msg,
            vec![
                0x30, 0x0c, // LDAPMessage SEQUENCE, len 12
                0x02, 0x01, 0x01, // messageID 1
                0x60, 0x07, // bindRequest [APPLICATION 0], len 7
                0x02, 0x01, 0x03, // version 3
                0x04, 0x00, // name ""
                0x80, 0x00, // simple [0] ""
            ]
        );
    }

    #[test]
    fn unbind_request_golden() {
        let msg = build_unbind_request(3);
        assert_eq!(msg, vec![0x30, 0x05, 0x02, 0x01, 0x03, 0x42, 0x00]);
    }

    #[test]
    fn bind_request_simple_credentials() {
        let msg = build_bind_request(1, "cn=admin", b"secret");
        // Decode the envelope and confirm the bind body's pieces.
        let (tag, body) = one_tlv(&msg);
        assert_eq!(tag, BER_SEQUENCE);
        let mut r = ber::Reader::new(&body);
        assert_eq!(r.read().unwrap().tag, BER_INTEGER); // messageID
        let op = r.read().unwrap();
        assert_eq!(op.tag, LDAP_REQ_BIND);
        let mut br = ber::Reader::new(op.value);
        assert_eq!(ber::decode_int(br.read().unwrap().value).unwrap(), 3); // version
        assert_eq!(br.read().unwrap().value, b"cn=admin"); // name
        let pw = br.read().unwrap();
        assert_eq!(pw.tag, LDAP_AUTH_SIMPLE);
        assert_eq!(pw.value, b"secret");
    }

    #[test]
    fn search_request_structure() {
        let attrs = vec!["cn".to_string(), "mail".to_string()];
        let msg =
            build_search_request(2, "dc=x", Scope::Subtree, "(objectclass=*)", &attrs).unwrap();
        let (_, body) = one_tlv(&msg);
        let mut r = ber::Reader::new(&body);
        assert_eq!(ber::decode_int(r.read().unwrap().value).unwrap(), 2); // messageID
        let op = r.read().unwrap();
        assert_eq!(op.tag, LDAP_REQ_SEARCH);
        let mut sr = ber::Reader::new(op.value);
        assert_eq!(sr.read().unwrap().value, b"dc=x"); // baseObject
        assert_eq!(ber::decode_int(sr.read().unwrap().value).unwrap(), 2); // scope=sub
        assert_eq!(ber::decode_int(sr.read().unwrap().value).unwrap(), 0); // derefAliases
        assert_eq!(ber::decode_int(sr.read().unwrap().value).unwrap(), 0); // sizeLimit
        assert_eq!(ber::decode_int(sr.read().unwrap().value).unwrap(), 0); // timeLimit
        assert_eq!(sr.read().unwrap().value, &[0x00]); // typesOnly = false
                                                       // filter "(objectclass=*)" => present filter [7].
        let filt = sr.read().unwrap();
        assert_eq!(filt.tag, FILTER_PRESENT);
        assert_eq!(filt.value, b"objectclass");
        // attribute selection SEQUENCE OF.
        let sel = sr.read().unwrap();
        assert_eq!(sel.tag, BER_SEQUENCE);
        let mut selr = ber::Reader::new(sel.value);
        assert_eq!(selr.read().unwrap().value, b"cn");
        assert_eq!(selr.read().unwrap().value, b"mail");
        assert!(selr.is_empty());
    }

    // ----- RFC 4515 filter compiler ----------------------------------------

    #[test]
    fn filter_present() {
        let mut out = Vec::new();
        encode_filter(&mut out, "(objectClass=*)").unwrap();
        let (tag, value) = one_tlv(&out);
        assert_eq!(tag, FILTER_PRESENT);
        assert_eq!(value, b"objectClass");
    }

    #[test]
    fn filter_equality() {
        let mut out = Vec::new();
        encode_filter(&mut out, "(cn=babs)").unwrap();
        let (tag, body) = one_tlv(&out);
        assert_eq!(tag, FILTER_EQUALITY);
        let mut r = ber::Reader::new(&body);
        assert_eq!(r.read().unwrap().value, b"cn");
        assert_eq!(r.read().unwrap().value, b"babs");
    }

    #[test]
    fn filter_bare_item_accepted() {
        // encode_filter accepts an unparenthesized item too.
        let mut out = Vec::new();
        encode_filter(&mut out, "cn=babs").unwrap();
        assert_eq!(one_tlv(&out).0, FILTER_EQUALITY);
    }

    #[test]
    fn filter_substrings() {
        let mut out = Vec::new();
        encode_filter(&mut out, "(cn=ab*cd*ef)").unwrap();
        let (tag, body) = one_tlv(&out);
        assert_eq!(tag, FILTER_SUBSTRINGS);
        let mut r = ber::Reader::new(&body);
        assert_eq!(r.read().unwrap().value, b"cn");
        let subs = r.read().unwrap();
        assert_eq!(subs.tag, BER_SEQUENCE);
        let mut sr = ber::Reader::new(subs.value);
        let initial = sr.read().unwrap();
        assert_eq!(initial.tag, SUBSTR_INITIAL);
        assert_eq!(initial.value, b"ab");
        let any = sr.read().unwrap();
        assert_eq!(any.tag, SUBSTR_ANY);
        assert_eq!(any.value, b"cd");
        let fin = sr.read().unwrap();
        assert_eq!(fin.tag, SUBSTR_FINAL);
        assert_eq!(fin.value, b"ef");
    }

    #[test]
    fn filter_ge_le_approx() {
        for (s, want) in [
            ("(age>=18)", FILTER_GE),
            ("(age<=65)", FILTER_LE),
            ("(cn~=jon)", FILTER_APPROX),
        ] {
            let mut out = Vec::new();
            encode_filter(&mut out, s).unwrap();
            assert_eq!(one_tlv(&out).0, want, "filter {s}");
        }
    }

    #[test]
    fn filter_and_or_not() {
        let mut out = Vec::new();
        encode_filter(&mut out, "(&(a=1)(b=2))").unwrap();
        let (tag, body) = one_tlv(&out);
        assert_eq!(tag, FILTER_AND);
        let mut r = ber::Reader::new(&body);
        assert_eq!(r.read().unwrap().tag, FILTER_EQUALITY);
        assert_eq!(r.read().unwrap().tag, FILTER_EQUALITY);
        assert!(r.is_empty());

        let mut o2 = Vec::new();
        encode_filter(&mut o2, "(|(a=1)(b=2)(c=3))").unwrap();
        assert_eq!(one_tlv(&o2).0, FILTER_OR);

        let mut o3 = Vec::new();
        encode_filter(&mut o3, "(!(a=1))").unwrap();
        let (tag, body) = one_tlv(&o3);
        assert_eq!(tag, FILTER_NOT);
        assert_eq!(one_tlv(&body).0, FILTER_EQUALITY);
    }

    #[test]
    fn filter_value_escapes() {
        // RFC 4515 \XX hex escapes decode to raw bytes.
        let mut out = Vec::new();
        encode_filter(&mut out, "(cn=a\\2ab)").unwrap(); // \2a == '*'
        let (_, body) = one_tlv(&out);
        let mut r = ber::Reader::new(&body);
        assert_eq!(r.read().unwrap().value, b"cn");
        assert_eq!(r.read().unwrap().value, b"a*b");
    }

    #[test]
    fn filter_errors() {
        for bad in [
            "(cn=babs",
            "()",
            "(=x)",
            "(cn)",
            "(cn~x)",
            "cn=a\\2",
            "(cn=a) junk",
        ] {
            let mut out = Vec::new();
            assert!(
                matches!(encode_filter(&mut out, bad), Err(CurlError::UrlMalformat)),
                "expected error for {bad:?}"
            );
        }
    }

    // ----- Response decoding ------------------------------------------------

    #[test]
    fn parse_bind_and_done_results() {
        let bind = build_result_msg(1, LDAP_RES_BIND, 0);
        assert_eq!(parse_message(&bind).unwrap(), (1, LdapResponse::Bind(0)));

        let done = build_result_msg(2, LDAP_RES_SEARCH_RESULT, 4);
        assert_eq!(parse_message(&done).unwrap(), (2, LdapResponse::Done(4)));
    }

    #[test]
    fn parse_search_entry_roundtrip() {
        let msg = build_entry_msg(
            2,
            b"cn=Babs,dc=example,dc=com",
            &[
                (b"cn".as_slice(), &[b"Babs Jensen".as_slice()]),
                (
                    b"objectClass".as_slice(),
                    &[b"person".as_slice(), b"top".as_slice()],
                ),
            ],
        );
        let (id, resp) = parse_message(&msg).unwrap();
        assert_eq!(id, 2);
        let LdapResponse::Entry(entry) = resp else {
            panic!("expected Entry, got {resp:?}");
        };
        assert_eq!(entry.dn, b"cn=Babs,dc=example,dc=com");
        assert_eq!(entry.attributes.len(), 2);
        assert_eq!(entry.attributes[0].0, b"cn");
        assert_eq!(entry.attributes[0].1, vec![b"Babs Jensen".to_vec()]);
        assert_eq!(entry.attributes[1].0, b"objectClass");
        assert_eq!(
            entry.attributes[1].1,
            vec![b"person".to_vec(), b"top".to_vec()]
        );
    }

    #[test]
    fn parse_rejects_bad_envelope() {
        // Not a SEQUENCE at the top.
        assert!(matches!(
            parse_message(&[0x04, 0x01, 0x00]),
            Err(CurlError::WeirdServerReply)
        ));
    }

    // ----- LDIF formatting --------------------------------------------------

    fn format_one(dn: &[u8], attrs: &[(&[u8], &[&[u8]])]) -> Vec<u8> {
        let entry = LdapEntry {
            dn: dn.to_vec(),
            attributes: attrs
                .iter()
                .map(|(n, vs)| (n.to_vec(), vs.iter().map(|v| v.to_vec()).collect()))
                .collect(),
        };
        let mut out = Vec::new();
        format_entry(&mut out, &entry);
        out
    }

    #[test]
    fn ldif_basic_entry() {
        let out = format_one(
            b"dc=example,dc=com",
            &[
                (b"cn".as_slice(), &[b"Babs Jensen".as_slice()]),
                (
                    b"objectClass".as_slice(),
                    &[b"person".as_slice(), b"top".as_slice()],
                ),
            ],
        );
        let expected = b"DN: dc=example,dc=com\n\
                         \tcn: Babs Jensen\n\
                         \n\
                         \tobjectClass: person\n\
                         \tobjectClass: top\n\
                         \n\
                         \n";
        assert_eq!(out, expected);
    }

    #[test]
    fn ldif_binary_attribute_base64() {
        // A ";binary" attribute is always base64-encoded (the "::" form).
        let out = format_one(
            b"x",
            &[(b"cert;binary".as_slice(), &[&[0x00u8, 0x01, 0x02][..]])],
        );
        // base64([0,1,2]) == "AAEC"
        let expected = b"DN: x\n\tcert;binary:: AAEC\n\n\n";
        assert_eq!(out, expected);
    }

    #[test]
    fn ldif_binval_leading_space_base64() {
        // A value with a leading blank triggers base64 (binval).
        let out = format_one(b"x", &[(b"desc".as_slice(), &[b" hi".as_slice()])]);
        // base64(" hi") == "IGhp"
        let expected = b"DN: x\n\tdesc:: IGhp\n\n\n";
        assert_eq!(out, expected);
    }

    #[test]
    fn ldif_nonprintable_base64() {
        // A high byte (>= 0x80) is non-printable => base64.
        let out = format_one(b"x", &[(b"v".as_slice(), &[&[0xc3u8, 0xa9][..]])]);
        // base64([0xc3,0xa9]) == "w6k="
        let expected = b"DN: x\n\tv:: w6k=\n\n\n";
        assert_eq!(out, expected);
    }

    #[test]
    fn ldif_empty_value() {
        // An empty *normal* value renders "\tattr:\n" (the trailing space in the
        // " " prefix is dropped).
        let out = format_one(b"x", &[(b"mail".as_slice(), &[b"".as_slice()])]);
        let expected = b"DN: x\n\tmail:\n\n\n";
        assert_eq!(out, expected);
    }

    #[test]
    fn ldif_attribute_without_values() {
        // An attribute with no values: "\tattr:\n" and no per-attribute blank
        // line (only the final entry blank line follows).
        let out = format_one(b"x", &[(b"member".as_slice(), &[][..])]);
        let expected = b"DN: x\n\tmember:\n\n";
        assert_eq!(out, expected);
    }

    #[test]
    fn ldif_end_to_end_from_wire() {
        // Decode a wire entry then format it, exercising the full pipeline.
        let msg = build_entry_msg(2, b"o=Test", &[(b"cn".as_slice(), &[b"Jon".as_slice()])]);
        let (_, resp) = parse_message(&msg).unwrap();
        let LdapResponse::Entry(entry) = resp else {
            panic!("expected entry");
        };
        let mut out = Vec::new();
        format_entry(&mut out, &entry);
        assert_eq!(out, b"DN: o=Test\n\tcn: Jon\n\n\n");
    }

    // ----- Result-code mapping ---------------------------------------------

    #[test]
    fn bind_result_mapping() {
        assert!(bind_result(LDAP_SUCCESS).is_ok());
        assert!(matches!(bind_result(49), Err(CurlError::LoginDenied)));
        assert!(matches!(
            bind_result(2),
            Err(CurlError::UnsupportedProtocol)
        ));
        assert!(matches!(
            bind_result(50),
            Err(CurlError::RemoteAccessDenied)
        ));
        // An unrecognized failure falls back to the generic bind error.
        assert!(matches!(bind_result(53), Err(CurlError::LdapCannotBind)));
    }

    #[test]
    fn search_done_mapping() {
        assert!(search_done_result(LDAP_SUCCESS).is_ok());
        // sizeLimitExceeded is treated as success (only warns).
        assert!(search_done_result(LDAP_SIZELIMIT_EXCEEDED).is_ok());
        assert!(matches!(
            search_done_result(49),
            Err(CurlError::LoginDenied)
        ));
        // noSuchObject (32) has no specific mapping => generic search failure.
        assert!(matches!(
            search_done_result(32),
            Err(CurlError::LdapSearchFailed)
        ));
    }

    // ----- Scheme descriptors ----------------------------------------------

    #[test]
    fn scheme_descriptors() {
        let ldap = LdapHandler::ldap();
        assert_eq!(ldap.scheme().name, "ldap");
        assert_eq!(ldap.scheme().default_port, 389);

        let ldaps = LdapHandler::ldaps();
        assert_eq!(ldaps.scheme().name, "ldaps");
        assert_eq!(ldaps.scheme().default_port, 636);

        // `new` binds to whatever descriptor it is handed.
        assert_eq!(LdapHandler::new(&SCHEME_LDAP).scheme().name, "ldap");
    }
}
