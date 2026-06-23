//! Forward (non-tunneling) HTTP-proxy request rewriting.
//!
//! This module owns the narrow, surgical piece of curl's HTTP engine that turns
//! an *origin-form* request-target (`/path?query`) into the *absolute-URI form*
//! (`http://host/path?query`) that a **forward** (non-tunneling) HTTP proxy
//! requires, plus the forward-proxy custom-header selection rules. It is the
//! Rust port of curl's `http_target()` (`lib/http.c`, the **primary** oracle)
//! together with the forward-proxy slice of `dynhds_add_custom()`
//! (`lib/http_proxy.c`, the **secondary** oracle).
//!
//! # Scope boundary — this module does NOT do CONNECT tunneling
//!
//! In this curl revision `lib/http_proxy.c` is, almost in its entirety, the
//! `CONNECT`-tunnel connection filter (`Curl_cft_http_proxy`,
//! `http_proxy_cf_connect`, `Curl_http_proxy_create_CONNECT`,
//! `Curl_http_proxy_get_destination`). **None of that lives here.** The tunnel
//! machinery is owned by other modules:
//!
//! * [`crate::conn::h1_proxy`] / [`crate::conn::h2_proxy`] — the `CONNECT`-tunnel
//!   sub-filters.
//! * [`crate::proxy`] — proxy *configuration* (`CurlProxyType`, `Proxy`,
//!   [`crate::proxy::is_https_proxy`]) and the `CONNECT` request build.
//!
//! This file is the thin **request-rewriting + proxy-header-selection** layer
//! only. The distinction between the absolute-URI form and the origin form
//! hinges on `conn.bits.httpproxy && !conn.bits.tunnel_proxy`: an HTTPS target
//! through *any* proxy is always tunneled (`CONNECT`), so it takes the
//! origin-form branch — the absolute form is produced only for cleartext
//! `http`/`ftp` through a forward proxy.
//!
//! # Memory safety
//!
//! This subtree inherits `#![forbid(unsafe_code)]` from [`crate::protocols`]; it
//! is intentionally **not** re-declared here. The module is pure,
//! allocation-safe Rust (`String`/`&str` manipulation plus calls into the
//! safe URL and header APIs), so it carries no `unsafe` and no raw-pointer work.

use crate::conn::Connection;
use crate::error::{CurlError, Result};
use crate::headers::DynHds;
use crate::url::{CurlUPart, CurlUrl, CURLU_NO_DEFAULT_PORT};

// ===========================================================================
// Phase A — request-target rewriting (port of `http_target`, lib/http.c).
// ===========================================================================

/// Builds the HTTP request-target string for a request.
///
/// This is the faithful port of curl's `http_target()` (`lib/http.c`
/// L2080-L2185). It returns the exact bytes that belong on the HTTP/1.x request
/// line after the method (and that the HTTP/2/3 engines use to derive the
/// `:path` pseudo-header in the non-proxy case):
///
/// * **Direct or tunneled** request (the common case, including any HTTPS-via-
///   `CONNECT` request): the *origin form* — the URL path, with `?query`
///   appended when a query is present (e.g. `/index.html?a=1`).
/// * **Forward HTTP proxy** request (`conn.bits.httpproxy && !conn.bits
///   .tunnel_proxy`): the *absolute-URI form* — the full URL the proxy must
///   fetch on the client's behalf (e.g. `http://example.com/index.html?a=1`),
///   reconstructed from a duplicate of `url` with the IDN-encoded host, no
///   fragment, and (for `http`) no userinfo.
///
/// # Parameters
///
/// * `url` — the request URL handle (curl's `data->state.uh`; the analog of the
///   crate-root [`crate::Url`] alias). Read-only: the proxy branch operates on a
///   private duplicate so the caller's handle is never mutated.
/// * `conn` — the connection the request runs over. Only `conn.bits.httpproxy`,
///   `conn.bits.tunnel_proxy` and `conn.remote_host` (curl's `conn->host.name`,
///   the wire/ACE host) are consulted; nothing protocol-specific is touched, so
///   no `conn` → `protocols` dependency cycle is introduced.
/// * `request_target_override` — `CURLOPT_REQUEST_TARGET` (curl's
///   `data->set.str[STRING_TARGET]`). When `Some`, it is used verbatim as the
///   request-target and the URL query is dropped, exactly as curl does. `Some("")`
///   models a non-NULL empty option (curl treats it as set); `None` means unset.
/// * `proxy_transfer_mode` — `CURLOPT_PROXY_TRANSFER_MODE`
///   (`data->set.proxy_transfer_mode`). Only meaningful for `ftp` URLs through a
///   forward proxy: when `true`, a `;type=<a|i>` suffix is appended if absent.
/// * `prefer_ascii` — curl's `data->state.prefer_ascii`. Selects the FTP type
///   letter for the `;type=` suffix above (`a` for ASCII, `i` for binary).
///
/// # Faithfulness notes
///
/// * Splitting curl's single `data->set.proxy_transfer_mode` /
///   `data->state.prefer_ascii` pair into the two explicit `proxy_transfer_mode`
///   and `prefer_ascii` parameters preserves byte-exact FTP-over-proxy behavior;
///   collapsing them would lose the "append only when transfer-mode is on"
///   gate.
/// * The IDN host replacement reproduces curl's `conn->host.dispname !=
///   conn->host.name` guard. That pointer inequality is true exactly when the
///   host was IDN/ACE-encoded, which happens only for **non-ASCII** hostnames
///   (ASCII names, including IPv6 literals, pass through `Curl_idnconvert_hostname`
///   unchanged). We therefore replace the duplicate's host with the connection's
///   encoded `remote_host` precisely when the URL's host is non-ASCII — which is
///   both faithful and immune to IPv6-bracket differences.
///
/// # Errors
///
/// Returns [`CurlError::OutOfMemory`] if any of the URL-handle operations in the
/// forward-proxy branch fail. This mirrors `http_target`, which maps every
/// `CURLUcode` from the duplicate/set/get calls to `CURLE_OUT_OF_MEMORY`
/// (those operations only fail under memory pressure for already-validated
/// inputs). The direct/tunneled branch never fails.
pub fn request_target(
    url: &CurlUrl,
    conn: &Connection,
    request_target_override: Option<&str>,
    proxy_transfer_mode: bool,
    prefer_ascii: bool,
) -> Result<String> {
    // C: `const char *path = data->state.up.path;`
    //    `const char *query = data->state.up.query;`
    // then, when `STRING_TARGET` is set: `path = STRING_TARGET; query = NULL;`.
    //
    // `path` is reused below both as the origin-form body (direct branch) and as
    // the source for the FTP `;type=` detection (proxy branch), so it is bound
    // once here exactly as curl binds it once at the top of `http_target`.
    let (path, query): (String, Option<String>) = match request_target_override {
        Some(target) => (target.to_string(), None),
        None => {
            // `CURLUPART_PATH` always resolves (curl defaults it to "/"), so the
            // error arm is unreachable for a real handle; default defensively.
            let path = url
                .get(CurlUPart::Path, 0)
                .unwrap_or_else(|_| "/".to_string());
            // `CURLUPART_QUERY` with no flags yields the query or a "no query"
            // error for an absent/empty query — exactly how `data->state.up.query`
            // ends up NULL in that case. `.ok()` collapses that to `None`.
            let query = url.get(CurlUPart::Query, 0).ok();
            (path, query)
        }
    };

    // C: `#ifndef CURL_DISABLE_PROXY if(conn->bits.httpproxy &&
    //     !conn->bits.tunnel_proxy)` — using a proxy but not tunneling through
    // it, i.e. a forward HTTP proxy. The request-target is the *entire* URL.
    if conn.bits.httpproxy && !conn.bits.tunnel_proxy {
        // C: `CURLU *h = curl_url_dup(data->state.uh);` — operate on a private
        // copy so the caller's handle is untouched.
        let mut h = url.dup();

        // C: `if(conn->host.dispname != conn->host.name) curl_url_set(h,
        //     CURLUPART_HOST, conn->host.name, 0);`
        //
        // The pointer inequality is true exactly when the host was IDN/ACE
        // encoded — only non-ASCII hostnames are converted, so an ASCII host
        // (including an IPv6 literal) is never rewritten. We force the wire host
        // (`conn.remote_host`, curl's already-encoded `conn->host.name`) only in
        // that case; the `!is_empty` guard avoids ever producing a host-less URL.
        if let Ok(disphost) = url.get(CurlUPart::Host, 0) {
            if !disphost.is_ascii() && !conn.remote_host.is_empty() {
                h.set(CurlUPart::Host, Some(&conn.remote_host), 0)
                    .map_err(|_| CurlError::OutOfMemory)?;
            }
        }

        // C: `curl_url_set(h, CURLUPART_FRAGMENT, NULL, 0);` — a fragment is
        // meaningless to a proxy, so strip it (NULL value clears the part).
        h.set(CurlUPart::Fragment, None, 0)
            .map_err(|_| CurlError::OutOfMemory)?;

        // The scheme drives the `http`/`ftp` special-cases below. curl reads
        // `data->state.up.scheme` (the original URL's scheme); we read it from
        // `url` for the same reason. An absent scheme matches neither branch.
        let scheme = url.get(CurlUPart::Scheme, 0).unwrap_or_default();

        // C: `if(curl_strequal("http", data->state.up.scheme)) { curl_url_set(h,
        //     CURLUPART_USER, NULL, 0); curl_url_set(h, CURLUPART_PASSWORD,
        //     NULL, 0); }` — never leak userinfo to the proxy for plain HTTP.
        if scheme.eq_ignore_ascii_case("http") {
            h.set(CurlUPart::User, None, 0)
                .map_err(|_| CurlError::OutOfMemory)?;
            h.set(CurlUPart::Password, None, 0)
                .map_err(|_| CurlError::OutOfMemory)?;
        }

        // C: `curl_url_get(h, CURLUPART_URL, &url, CURLU_NO_DEFAULT_PORT);` —
        // the absolute request-target. `CURLU_NO_DEFAULT_PORT` omits the port
        // when it equals the scheme default (so `:80`/`:21` are not emitted).
        let absolute = h
            .get(CurlUPart::Url, CURLU_NO_DEFAULT_PORT)
            .map_err(|_| CurlError::OutOfMemory)?;

        // C: `result = curlx_dyn_add(r, STRING_TARGET ? STRING_TARGET : url);` —
        // an explicit request-target wins verbatim over the rebuilt URL.
        let mut result = match request_target_override {
            Some(target) => target.to_string(),
            None => absolute,
        };

        // C: `if(curl_strequal("ftp", data->state.up.scheme) &&
        //     data->set.proxy_transfer_mode) { ... append ;type=<a|i> ... }`
        //
        // The detection runs on `path` (the original path or the override), and
        // the suffix is appended to the already-built target.
        if scheme.eq_ignore_ascii_case("ftp") && proxy_transfer_mode && !has_type_suffix(&path) {
            // C: `curlx_dyn_addf(r, ";type=%c", prefer_ascii ? 'a' : 'i');`
            result.push_str(if prefer_ascii { ";type=a" } else { ";type=i" });
        }

        Ok(result)
    } else {
        // C (the `#else`/non-proxy arm): `curlx_dyn_add(r, path); if(query)
        //   curlx_dyn_addf(r, "?%s", query);` — the origin form.
        let mut result = path;
        if let Some(q) = query {
            result.push('?');
            result.push_str(&q);
        }
        Ok(result)
    }
}

/// The origin-form request target (`path[?query]`) used as the **Digest URI**,
/// independent of any proxy.
///
/// curl computes the Digest `uri=` field (and the `HA2 = MD5(method:uri)` hash)
/// from `data->state.up.path` plus the query — the ORIGIN form — even when a
/// forward HTTP proxy makes the request *line* carry the absolute URL
/// (`GET http://host/path HTTP/1.1`). So a Digest auth through a forward proxy
/// still hashes over `/path`, not `http://host/path`. Both the host (`401`,
/// `WWW-Authenticate`) and the proxy (`407`, `Proxy-Authenticate`) Digest
/// challenges use this same origin-form URI (tests 167, 168).
///
/// An explicit `--request-target` (`CURLOPT_REQUEST_TARGET` / `STRING_TARGET`)
/// wins verbatim, exactly as in [`request_target`] (curl sets `path =
/// STRING_TARGET; query = NULL`). This mirrors the non-proxy (`#else`) arm of
/// `http_target`, which is what curl's auth code effectively reads.
pub fn auth_uri_target(url: &CurlUrl, request_target_override: Option<&str>) -> Result<String> {
    // An explicit request-target is the verbatim URI (curl: `path =
    // STRING_TARGET; query = NULL`).
    if let Some(target) = request_target_override {
        return Ok(target.to_string());
    }
    // C: `path = data->state.up.path` (defaults to "/") and the optional query.
    let path = url
        .get(CurlUPart::Path, 0)
        .unwrap_or_else(|_| "/".to_string());
    let query = url.get(CurlUPart::Query, 0).ok();
    let mut result = path;
    if let Some(q) = query {
        result.push('?');
        result.push_str(&q);
    }
    Ok(result)
}

/// Returns `true` when `path` already ends with a `;type=<X>` FTP type suffix
/// whose letter `X` (case-insensitively) is `A`, `D`, or `I`.
///
/// This is the exact port of the detection in `http_target` (`lib/http.c`
/// L2155-L2165): `(len >= 7) && !memcmp(&path[len - 7], ";type=", 6)` followed
/// by `Curl_raw_toupper(path[len - 1])` matching `'A' | 'D' | 'I'`. The literal
/// `";type="` is six bytes, leaving the seventh-from-last byte as the type
/// letter. Operates on raw bytes so it is encoding-agnostic, exactly like the C.
fn has_type_suffix(path: &str) -> bool {
    let bytes = path.as_bytes();
    let len = bytes.len();
    // Need at least `;type=` (6 bytes) plus the one-byte type letter.
    if len >= 7 && &bytes[len - 7..len - 1] == b";type=" {
        matches!(bytes[len - 1].to_ascii_uppercase(), b'A' | b'D' | b'I')
    } else {
        false
    }
}

// ===========================================================================
// Phase B — forward-proxy custom-header selection (port of the forward slice of
// `dynhds_add_custom`, lib/http_proxy.c L40-L163).
// ===========================================================================

/// The disposition of a single custom-header line after curl's two
/// custom-header quirks are applied (the heart of `dynhds_add_custom`,
/// `lib/http_proxy.c` L85-L121).
///
/// curl supports two deliberate quirks on a custom header line `name<sep>value`:
///
/// 1. `"Name:"` — a name with a `:` and **no** value: *suppress* the header
///    (do not send it at all).
/// 2. `"Name;"` — a name with a trailing `;` and nothing after: send the header
///    with an **empty** value (`Name:`).
///
/// Any other shape (no name, a name with neither `:` nor `;`, or `"Name;extra"`)
/// is silently ignored. All of these "do not emit" outcomes collapse to
/// [`Skip`](CustomHeader::Skip), since curl handles each with `continue`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomHeader<'a> {
    /// Emit this header. `value` is borrowed from the input line and may be
    /// empty (the `"Name;"` quirk).
    Add {
        /// The header name (the bytes before the first `:`/`;`, untrimmed —
        /// matching curl's `curlx_str_cspn` span).
        name: &'a str,
        /// The header value (leading blanks stripped, trailing bytes kept), or
        /// `""` for the empty-header quirk.
        value: &'a str,
    },
    /// Do not emit this line (the `"Name:"` suppression quirk, or a malformed /
    /// value-less line that curl ignores).
    Skip,
}

/// Parses one custom-header line exactly as `dynhds_add_custom` does, applying
/// the two quirks documented on [`CustomHeader`].
///
/// The parse mirrors curl's `curlx_str_*` walk byte-for-byte
/// (`lib/curlx/strparse.c`):
///
/// * The name is the maximal prefix containing neither `:` nor `;`
///   (`curlx_str_cspn(line, ";:")`); an empty name ⇒ [`CustomHeader::Skip`].
/// * If a `:` follows the name, blanks (space/tab, curl's `ISBLANK`) after it
///   are skipped; a non-empty remainder is the value, an empty remainder is the
///   suppress quirk ⇒ [`CustomHeader::Skip`].
/// * Else if a `;` follows the name, blanks after it are skipped; an empty
///   remainder is the empty-value quirk (`value == ""`), a non-empty remainder
///   is ignored ⇒ [`CustomHeader::Skip`].
/// * Else (no `:`/`;` at all) ⇒ [`CustomHeader::Skip`].
///
/// The returned `name`/`value` borrow from `line`, so no allocation occurs.
#[must_use]
pub fn parse_custom_header_line(line: &str) -> CustomHeader<'_> {
    let bytes = line.as_bytes();
    // C: `curlx_str_cspn(&ptr, &name, ";:")` — span up to the first ';' or ':'.
    // A zero-length span (STR_E_SHORT) means "no name" ⇒ ignore.
    let sep = bytes
        .iter()
        .position(|&b| b == b':' || b == b';')
        .unwrap_or(bytes.len());
    if sep == 0 {
        return CustomHeader::Skip;
    }
    let name = &line[..sep];
    // `rest` begins at the delimiter (or the end of the line when none exists).
    let rest = &bytes[sep..];

    match rest.first() {
        // C: `if(!curlx_str_single(&ptr, ':'))` — a ':' delimiter.
        Some(&b':') => {
            // C: `curlx_str_passblanks(&ptr);` then test `if(*ptr)`.
            let value = skip_blanks(&line[sep + 1..]);
            if value.is_empty() {
                // Quirk #1: `"Name:"` with no value ⇒ suppress.
                CustomHeader::Skip
            } else {
                CustomHeader::Add { name, value }
            }
        }
        // C: `else if(!curlx_str_single(&ptr, ';'))` — a ';' delimiter.
        Some(&b';') => {
            // Quirk #2: a "blank header" (`-H "Name;"`) sends `Name:` with an
            // empty value. The C oracle (`Curl_add_custom_headers`, lib/http.c)
            // recognizes this *only* when the semicolon is immediately followed
            // by the end of the string — the test chain is
            // `curlx_str_single(&p, ';')` then `curlx_str_single(&p, '\0')`,
            // i.e. NO trailing blanks are tolerated. So `"Name;"` is a blank
            // header, but `"Name;  "` (semicolon + blanks) and `"Name;extra"`
            // are NOT — they have no colon either, so curl skips them entirely.
            if line[sep + 1..].is_empty() {
                CustomHeader::Add { name, value: "" }
            } else {
                // `"Name; …"` / `"Name;extra"` — semicolon not at end-of-string
                // and no colon present ⇒ curl ignores the line.
                CustomHeader::Skip
            }
        }
        // No delimiter at all (the name ran to end of line) ⇒ ignore.
        _ => CustomHeader::Skip,
    }
}

/// Strips leading curl-`ISBLANK` bytes (ASCII space and horizontal tab) from
/// `s`, returning the remaining slice. The equivalent of
/// `curlx_str_passblanks`. Only **leading** blanks are removed (curl never
/// trims the trailing end of a header value).
fn skip_blanks(s: &str) -> &str {
    s.trim_start_matches([' ', '\t'])
}

/// The request-state flags that gate which custom headers may be emitted —
/// the Rust face of the `data->state` / `data->req` bits that
/// `dynhds_add_custom` consults (`lib/http_proxy.c` L124-L151).
///
/// Each field corresponds to one of curl's skip conditions; see
/// [`add_custom_headers`] for how they are applied. Bundling them keeps the
/// helper's signature legible and lets a caller (e.g. the HTTP/1.x engine)
/// compute them once.
#[derive(Debug, Clone, Copy, Default)]
pub struct CustomHeaderContext {
    /// A `Host:` header has already been generated (curl's
    /// `data->state.aptr.host`); a custom `Host:` is then dropped to avoid
    /// sending two.
    pub host_header_present: bool,
    /// The request body is `multipart/form-data` (`HTTPREQ_POST_FORM`); the
    /// `Content-Type` is emitted later by the form encoder, so a custom one is
    /// dropped here.
    pub is_post_form: bool,
    /// The request body is a MIME structure (`HTTPREQ_POST_MIME`); as with
    /// forms, the `Content-Type` is emitted later.
    pub is_post_mime: bool,
    /// An authentication negotiation round is in progress (`data->req.authneg`);
    /// the body length is forced to zero, so a custom `Content-Length` is
    /// dropped.
    pub authneg: bool,
    /// The negotiated HTTP version times ten (curl's convention: `20` ⇒
    /// HTTP/2, `30` ⇒ HTTP/3). At `>= 20`, chunked requests are unsupported, so
    /// a custom `Transfer-Encoding` is dropped.
    pub httpversion: i32,
    /// Whether sensitive headers may be sent to the current host (curl's
    /// `Curl_auth_allowed_to_host(data)`). When `false`, custom `Authorization`
    /// and `Cookie` headers are dropped so they are not leaked across a
    /// redirect to another host. Passed in by the caller because the auth
    /// policy lives outside this module's dependency set.
    pub allowed_to_host: bool,
}

impl CustomHeaderContext {
    /// Returns `true` when a custom header named `name` must be **dropped**
    /// under the current request state, reproducing the `else if(... )` skip
    /// ladder of `dynhds_add_custom` (`lib/http_proxy.c` L124-L151). Name
    /// matching is exact-length and case-insensitive (curl's
    /// `curlx_str_casecompare`).
    #[must_use]
    fn suppresses(&self, name: &str) -> bool {
        if name.eq_ignore_ascii_case("Host") {
            // A Host: header was sent already — do not pass a custom one.
            self.host_header_present
        } else if name.eq_ignore_ascii_case("Content-Type") {
            // Form/MIME Content-Type is added later by the body encoder.
            self.is_post_form || self.is_post_mime
        } else if name.eq_ignore_ascii_case("Content-Length") {
            // During auth negotiation the length is forced to zero.
            self.authneg
        } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
            // HTTP/2 and HTTP/3 do not support chunked requests.
            self.httpversion >= 20
        } else if name.eq_ignore_ascii_case("Authorization") || name.eq_ignore_ascii_case("Cookie")
        {
            // Be careful sending these potentially sensitive headers onward.
            !self.allowed_to_host
        } else {
            false
        }
    }
}

/// Adds the applicable custom request headers to `hds` for a forward (non-
/// `CONNECT`) request, reproducing `dynhds_add_custom` with `is_connect ==
/// false` (`lib/http_proxy.c` L40-L163).
///
/// # List selection (curl's `HEADER_PROXY` / `HEADER_SERVER`)
///
/// curl picks the header list(s) by the request's relationship to the proxy:
///
/// * If the request goes through a **forward** HTTP proxy
///   (`conn.bits.httpproxy && !conn.bits.tunnel_proxy`, curl's `HEADER_PROXY`):
///   the normal `headers` list is walked, and — only when `sep_headers`
///   (`CURLOPT_PROXYHEADER` with `CURLHEADER_SEPARATE`) is set — the
///   `proxy_headers` list is walked too.
/// * Otherwise (a direct or tunneled request, curl's `HEADER_SERVER`): only the
///   `headers` list is walked. (`HEADER_CONNECT`, the third C case, is for
///   `CONNECT` tunnels and is intentionally **out of scope** for this module.)
///
/// Each line is parsed by [`parse_custom_header_line`] (the two quirks) and then
/// filtered by [`CustomHeaderContext`] (the Host/Content-Type/Content-Length/
/// Transfer-Encoding/Authorization/Cookie skip rules) before being appended.
///
/// `headers` and `proxy_headers` are slices of header lines (each a
/// `name: value` / `name:` / `name;` string), the analog of curl's
/// `data->set.headers` and `data->set.proxyheaders` slists. A single element
/// type is used for both so an empty `proxy_headers` slice (`&[]`) infers its
/// type from `headers`.
///
/// # Errors
///
/// Propagates [`CurlError::OutOfMemory`] from [`DynHds::add`] if a header would
/// exceed the destination set's caps — exactly as curl surfaces a
/// `Curl_dynhds_add` failure.
pub fn add_custom_headers<S: AsRef<str>>(
    hds: &mut DynHds,
    conn: &Connection,
    headers: &[S],
    proxy_headers: &[S],
    sep_headers: bool,
    ctx: &CustomHeaderContext,
) -> Result<()> {
    // C: `proxy = conn->bits.httpproxy && !conn->bits.tunnel_proxy ?
    //     HEADER_PROXY : HEADER_SERVER;` (is_connect is always false here).
    let header_proxy = conn.bits.httpproxy && !conn.bits.tunnel_proxy;

    // C: `h[0] = data->set.headers;` — always walked first.
    for line in headers {
        add_one_custom_header(hds, line.as_ref(), ctx)?;
    }

    // C: `if(data->set.sep_headers) { h[1] = data->set.proxyheaders;
    //     numlists++; }` — the proxy list is walked only for HEADER_PROXY with
    // separate proxy headers.
    if header_proxy && sep_headers {
        for line in proxy_headers {
            add_one_custom_header(hds, line.as_ref(), ctx)?;
        }
    }

    Ok(())
}

/// Parses one custom-header `line`, applies the [`CustomHeaderContext`] skip
/// rules, and appends the survivor to `hds`. The per-line body of the
/// `dynhds_add_custom` loop.
fn add_one_custom_header(hds: &mut DynHds, line: &str, ctx: &CustomHeaderContext) -> Result<()> {
    let CustomHeader::Add { name, value } = parse_custom_header_line(line) else {
        // Quirk #1 / malformed line ⇒ nothing to add.
        return Ok(());
    };
    if ctx.suppresses(name) {
        // A state-gated header (Host/Content-Type/…) ⇒ dropped.
        return Ok(());
    }
    // C: `Curl_dynhds_add(hds, name, namelen, value, valuelen);`
    hds.add(name, value)
}

// ===========================================================================
// Tests — exercise the `http_target` port (Phase A) and the forward-proxy
// custom-header selection (Phase B) against the exact byte-for-byte behavior of
// the C oracles. Expected strings are anchored to curl's documented round-trip
// behavior (see `lib/http.c` `http_target` and the `urlapi.c` reassembly).
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{SchemeDescriptor, TRNSPRT_TCP};

    // ---- construction helpers ---------------------------------------------

    /// Builds a [`Connection`] with the proxy bits and encoded host set, leaving
    /// every other field at its default. `scheme_name` only feeds the
    /// descriptor; `request_target` never reads it (it reads the *URL* scheme).
    fn make_conn(httpproxy: bool, tunnel_proxy: bool, remote_host: &str) -> Connection {
        let mut conn = Connection::new(
            "test-destination",
            TRNSPRT_TCP,
            SchemeDescriptor::new("http", 80, 0, 0),
        );
        conn.bits.httpproxy = httpproxy;
        conn.bits.tunnel_proxy = tunnel_proxy;
        conn.remote_host = remote_host.to_string();
        conn
    }

    /// A direct (no-proxy) connection.
    fn direct_conn() -> Connection {
        make_conn(false, false, "")
    }

    /// A forward HTTP-proxy connection (`httpproxy && !tunnel_proxy`).
    fn forward_proxy_conn() -> Connection {
        make_conn(true, false, "")
    }

    /// A tunneling-proxy connection (`httpproxy && tunnel_proxy`, i.e. CONNECT —
    /// always used for HTTPS through a proxy).
    fn tunnel_proxy_conn() -> Connection {
        make_conn(true, true, "")
    }

    /// Parses a full URL string into a handle, exactly as the engine populates
    /// `data->state.uh`.
    fn parse_url(s: &str) -> CurlUrl {
        let mut u = CurlUrl::new();
        u.set(CurlUPart::Url, Some(s), 0)
            .unwrap_or_else(|e| panic!("parse {s:?} failed: {e:?}"));
        u
    }

    // ---- Phase A: request_target ------------------------------------------

    // (a) Direct request → origin-form `/path?query`.
    #[test]
    fn direct_request_is_origin_form_with_query() {
        let url = parse_url("http://example.com/path/html?query=name");
        let conn = direct_conn();
        let got = request_target(&url, &conn, None, false, false).unwrap();
        assert_eq!(got, "/path/html?query=name");
    }

    // (a, cont.) Direct request with no query → bare path, no trailing '?'.
    #[test]
    fn direct_request_without_query_has_no_question_mark() {
        let url = parse_url("http://example.com/just/a/path");
        let conn = direct_conn();
        let got = request_target(&url, &conn, None, false, false).unwrap();
        assert_eq!(got, "/just/a/path");
    }

    // (a, cont.) Direct request to a root path defaults to "/".
    #[test]
    fn direct_request_root_path_defaults_to_slash() {
        let url = parse_url("http://example.com");
        let conn = direct_conn();
        let got = request_target(&url, &conn, None, false, false).unwrap();
        assert_eq!(got, "/");
    }

    // (b) Forward HTTP proxy → absolute-URI form `http://host/path?query`.
    #[test]
    fn forward_proxy_request_is_absolute_form() {
        let url = parse_url("http://example.com/path/html?query=name");
        let conn = forward_proxy_conn();
        let got = request_target(&url, &conn, None, false, false).unwrap();
        assert_eq!(got, "http://example.com/path/html?query=name");
    }

    // (b, cont.) Forward proxy preserves a non-default explicit port.
    #[test]
    fn forward_proxy_keeps_explicit_nondefault_port() {
        let url = parse_url("http://example.com:8080/path");
        let conn = forward_proxy_conn();
        let got = request_target(&url, &conn, None, false, false).unwrap();
        assert_eq!(got, "http://example.com:8080/path");
    }

    // (b, cont.) Forward proxy omits the scheme-default port (CURLU_NO_DEFAULT_PORT).
    #[test]
    fn forward_proxy_omits_default_port() {
        let url = parse_url("http://example.com:80/path");
        let conn = forward_proxy_conn();
        let got = request_target(&url, &conn, None, false, false).unwrap();
        assert_eq!(got, "http://example.com/path");
    }

    // (c) Userinfo stripped for an `http` forward-proxy request.
    #[test]
    fn forward_proxy_http_strips_userinfo() {
        let url = parse_url("http://user:password@example.com/path/html");
        let conn = forward_proxy_conn();
        let got = request_target(&url, &conn, None, false, false).unwrap();
        assert_eq!(got, "http://example.com/path/html");
        assert!(!got.contains("user"), "userinfo leaked: {got}");
        assert!(!got.contains("password"), "userinfo leaked: {got}");
        assert!(!got.contains('@'), "userinfo separator leaked: {got}");
    }

    // (c, cont.) For a non-`http` scheme (ftp) the userinfo is NOT stripped —
    // curl only clears it for the literal "http" scheme.
    #[test]
    fn forward_proxy_ftp_keeps_userinfo() {
        let url = parse_url("ftp://user:password@example.com/file.txt");
        let conn = forward_proxy_conn();
        let got = request_target(&url, &conn, None, false, false).unwrap();
        assert_eq!(got, "ftp://user:password@example.com/file.txt");
    }

    // (d) Fragment removed from the forward-proxy absolute target.
    #[test]
    fn forward_proxy_removes_fragment() {
        let url = parse_url("http://example.com/path?q=1#section");
        let conn = forward_proxy_conn();
        let got = request_target(&url, &conn, None, false, false).unwrap();
        assert_eq!(got, "http://example.com/path?q=1");
        assert!(!got.contains('#'), "fragment leaked: {got}");
        assert!(!got.contains("section"), "fragment leaked: {got}");
    }

    // (e) CURLOPT_REQUEST_TARGET override is honored verbatim in the direct
    // branch and drops the URL query.
    #[test]
    fn request_target_override_direct_is_verbatim() {
        let url = parse_url("http://example.com/realpath?realquery");
        let conn = direct_conn();
        let got = request_target(&url, &conn, Some("*"), false, false).unwrap();
        // The "*" target (e.g. `OPTIONS *`) is used as-is; the query is dropped.
        assert_eq!(got, "*");
    }

    // (e, cont.) The override wins over the rebuilt absolute URL in the
    // forward-proxy branch too (C: `STRING_TARGET ? STRING_TARGET : url`).
    #[test]
    fn request_target_override_forward_proxy_is_verbatim() {
        let url = parse_url("http://example.com/realpath?realquery");
        let conn = forward_proxy_conn();
        let got = request_target(&url, &conn, Some("/custom-target"), false, false).unwrap();
        assert_eq!(got, "/custom-target");
    }

    // (e, cont.) A non-NULL but empty override (`Some("")`) is treated as set —
    // curl tests the pointer, not the contents — yielding an empty target.
    #[test]
    fn request_target_empty_override_is_treated_as_set() {
        let url = parse_url("http://example.com/realpath?realquery");
        let conn = direct_conn();
        let got = request_target(&url, &conn, Some(""), false, false).unwrap();
        assert_eq!(got, "");
    }

    // (f) FTP-over-proxy appends `;type=i` (binary) when transfer-mode is on.
    #[test]
    fn forward_proxy_ftp_appends_type_binary() {
        let url = parse_url("ftp://example.com/file.txt");
        let conn = forward_proxy_conn();
        let got = request_target(&url, &conn, None, true, false).unwrap();
        assert_eq!(got, "ftp://example.com/file.txt;type=i");
    }

    // (f, cont.) FTP-over-proxy appends `;type=a` (ASCII) when prefer_ascii.
    #[test]
    fn forward_proxy_ftp_appends_type_ascii() {
        let url = parse_url("ftp://example.com/file.txt");
        let conn = forward_proxy_conn();
        let got = request_target(&url, &conn, None, true, true).unwrap();
        assert_eq!(got, "ftp://example.com/file.txt;type=a");
    }

    // (f, cont.) An already-present `;type=` suffix is not duplicated.
    #[test]
    fn forward_proxy_ftp_keeps_existing_type_suffix() {
        let url = parse_url("ftp://example.com/file.txt;type=a");
        let conn = forward_proxy_conn();
        // prefer_ascii=false would normally pick 'i', but the existing 'a' wins.
        let got = request_target(&url, &conn, None, true, false).unwrap();
        assert_eq!(got, "ftp://example.com/file.txt;type=a");
    }

    // (f, cont.) Without proxy_transfer_mode, no `;type=` suffix is added.
    #[test]
    fn forward_proxy_ftp_no_suffix_without_transfer_mode() {
        let url = parse_url("ftp://example.com/file.txt");
        let conn = forward_proxy_conn();
        let got = request_target(&url, &conn, None, false, false).unwrap();
        assert_eq!(got, "ftp://example.com/file.txt");
    }

    // (g) An IDN (non-ASCII) host is replaced by the connection's encoded host.
    #[test]
    fn forward_proxy_idn_host_uses_encoded_host() {
        // Build piece-by-piece: a full-URL parse of a non-ASCII host is not
        // needed, and this directly stores the UTF-8 display host.
        let mut url = CurlUrl::new();
        url.set(CurlUPart::Scheme, Some("http"), 0).unwrap();
        url.set(CurlUPart::Host, Some("münchen.example"), 0).unwrap();
        url.set(CurlUPart::Path, Some("/path"), 0).unwrap();
        // The connection carries the already-encoded (ACE) host name.
        let conn = make_conn(true, false, "xn--mnchen-3ya.example");
        let got = request_target(&url, &conn, None, false, false).unwrap();
        assert_eq!(got, "http://xn--mnchen-3ya.example/path");
    }

    // (g, cont.) An ASCII host is NOT replaced even if the connection carries a
    // different encoded host (the C `dispname != name` guard is false here).
    #[test]
    fn forward_proxy_ascii_host_not_replaced() {
        let url = parse_url("http://example.com/path");
        // Even though remote_host differs, the URL host is ASCII so the guard
        // (true only for IDN-encoded hosts) does not fire.
        let conn = make_conn(true, false, "different.example");
        let got = request_target(&url, &conn, None, false, false).unwrap();
        assert_eq!(got, "http://example.com/path");
    }

    // IPv6-literal safety: an IPv6 host is ASCII, so it is never substituted and
    // its brackets are preserved in the absolute target.
    #[test]
    fn forward_proxy_ipv6_literal_is_preserved() {
        let url = parse_url("http://[::1]/path");
        let conn = make_conn(true, false, "::1");
        let got = request_target(&url, &conn, None, false, false).unwrap();
        assert_eq!(got, "http://[::1]/path");
    }

    // An HTTPS target through a proxy is always tunneled (CONNECT), so it takes
    // the origin-form branch — never the absolute form.
    #[test]
    fn https_through_proxy_is_tunneled_origin_form() {
        let url = parse_url("https://example.com/secure?x=1");
        let conn = tunnel_proxy_conn();
        let got = request_target(&url, &conn, None, false, false).unwrap();
        assert_eq!(got, "/secure?x=1");
    }

    // ---- has_type_suffix bytes-level detection ----------------------------

    #[test]
    fn type_suffix_detection() {
        assert!(has_type_suffix("/f;type=a"));
        assert!(has_type_suffix("/f;type=A"));
        assert!(has_type_suffix("/f;type=i"));
        assert!(has_type_suffix("/f;type=I"));
        assert!(has_type_suffix("/f;type=d"));
        assert!(has_type_suffix("/f;type=D"));
        // Wrong/absent letter or marker.
        assert!(!has_type_suffix("/f;type=x"));
        assert!(!has_type_suffix("/file.txt"));
        assert!(!has_type_suffix(""));
        assert!(!has_type_suffix(";type=")); // only 6 bytes — no letter
        // Must be the trailing suffix, not in the middle.
        assert!(!has_type_suffix("/f;type=a/more"));
    }

    // ---- Phase B: parse_custom_header_line --------------------------------

    #[test]
    fn parse_header_name_colon_value() {
        assert_eq!(
            parse_custom_header_line("X-Foo: bar"),
            CustomHeader::Add {
                name: "X-Foo",
                value: "bar"
            }
        );
    }

    #[test]
    fn parse_header_no_space_after_colon() {
        assert_eq!(
            parse_custom_header_line("X-Foo:bar"),
            CustomHeader::Add {
                name: "X-Foo",
                value: "bar"
            }
        );
    }

    #[test]
    fn parse_header_strips_leading_blanks_only() {
        // Leading spaces/tabs are skipped; the trailing space is preserved and
        // internal spaces are untouched (curl never trims the tail).
        assert_eq!(
            parse_custom_header_line("X-Foo:  \tbar baz "),
            CustomHeader::Add {
                name: "X-Foo",
                value: "bar baz "
            }
        );
    }

    #[test]
    fn parse_header_colon_no_value_is_suppressed() {
        // Quirk #1: "Name:" with no value suppresses the header entirely.
        assert_eq!(parse_custom_header_line("X-Foo:"), CustomHeader::Skip);
        // Trailing blanks after the colon still count as "no value".
        assert_eq!(parse_custom_header_line("X-Foo:   "), CustomHeader::Skip);
    }

    #[test]
    fn parse_header_semicolon_sends_empty_value() {
        // Quirk #2: "Name;" sends the header with an empty value.
        assert_eq!(
            parse_custom_header_line("X-Foo;"),
            CustomHeader::Add {
                name: "X-Foo",
                value: ""
            }
        );
    }

    #[test]
    fn parse_header_semicolon_with_trailing_blanks_is_ignored() {
        // The blank-header form is recognized ONLY when the ';' is immediately
        // at end-of-string (C: `curlx_str_single(&p, ';')` then
        // `curlx_str_single(&p, '\0')` — no trailing blanks tolerated). So
        // `"X-Foo;   "` is NOT a blank header; with no colon present curl skips
        // the line entirely. This is exactly `tests/data/test4`'s `X-Test4;  `
        // case, whose expected `<protocol>` emits no `X-Test4` line at all.
        assert_eq!(parse_custom_header_line("X-Foo;   "), CustomHeader::Skip);
    }

    #[test]
    fn parse_header_semicolon_with_extra_is_ignored() {
        // "Name;extra" is reserved and currently ignored by curl.
        assert_eq!(parse_custom_header_line("X-Foo;extra"), CustomHeader::Skip);
    }

    #[test]
    fn parse_header_without_delimiter_is_ignored() {
        assert_eq!(parse_custom_header_line("X-Foo"), CustomHeader::Skip);
    }

    #[test]
    fn parse_header_empty_or_no_name_is_ignored() {
        assert_eq!(parse_custom_header_line(""), CustomHeader::Skip);
        assert_eq!(parse_custom_header_line(":bar"), CustomHeader::Skip);
        assert_eq!(parse_custom_header_line(";bar"), CustomHeader::Skip);
    }

    // ---- Phase B: add_custom_headers list selection -----------------------

    #[test]
    fn add_custom_headers_forward_proxy_walks_both_lists() {
        let conn = forward_proxy_conn();
        let mut hds = DynHds::with_request_limits();
        let headers = ["X-Custom: v1", "X-Drop:", "X-Empty;"];
        let proxy_headers = ["X-Proxy: p1"];
        let ctx = CustomHeaderContext::default();
        add_custom_headers(&mut hds, &conn, &headers, &proxy_headers, true, &ctx).unwrap();

        // "X-Drop:" suppressed (quirk #1); "X-Empty;" added with empty value;
        // proxy list walked because HEADER_PROXY && sep_headers.
        assert_eq!(hds.count(), 3);
        assert_eq!(hds.get("X-Custom").unwrap().value(), "v1");
        assert_eq!(hds.get("X-Empty").unwrap().value(), "");
        assert_eq!(hds.get("X-Proxy").unwrap().value(), "p1");
        assert!(!hds.contains("X-Drop"));
    }

    #[test]
    fn add_custom_headers_forward_proxy_ignores_proxy_list_without_sep() {
        let conn = forward_proxy_conn();
        let mut hds = DynHds::with_request_limits();
        let headers = ["X-A: 1"];
        let proxy_headers = ["X-P: 2"];
        let ctx = CustomHeaderContext::default();
        // sep_headers=false → proxy list is not consulted.
        add_custom_headers(&mut hds, &conn, &headers, &proxy_headers, false, &ctx).unwrap();
        assert_eq!(hds.count(), 1);
        assert!(hds.contains("X-A"));
        assert!(!hds.contains("X-P"));
    }

    #[test]
    fn add_custom_headers_server_ignores_proxy_list() {
        // A direct request is HEADER_SERVER: only the normal list is walked,
        // even with sep_headers set.
        let conn = direct_conn();
        let mut hds = DynHds::with_request_limits();
        let headers = ["X-A: 1"];
        let proxy_headers = ["X-P: 2"];
        let ctx = CustomHeaderContext::default();
        add_custom_headers(&mut hds, &conn, &headers, &proxy_headers, true, &ctx).unwrap();
        assert_eq!(hds.count(), 1);
        assert!(hds.contains("X-A"));
        assert!(!hds.contains("X-P"));
    }

    #[test]
    fn add_custom_headers_empty_proxy_slice_infers_type() {
        // An empty `&[]` proxy slice must infer its element type from `headers`.
        let conn = direct_conn();
        let mut hds = DynHds::with_request_limits();
        let headers = ["X-A: 1"];
        let ctx = CustomHeaderContext::default();
        add_custom_headers(&mut hds, &conn, &headers, &[], false, &ctx).unwrap();
        assert_eq!(hds.count(), 1);
    }

    // ---- Phase B: state-gated skip conditions -----------------------------

    #[test]
    fn skip_host_header_when_already_present() {
        let conn = direct_conn();
        let mut hds = DynHds::with_request_limits();
        let ctx = CustomHeaderContext {
            host_header_present: true,
            ..Default::default()
        };
        add_custom_headers(&mut hds, &conn, &["Host: evil.example"], &[], false, &ctx).unwrap();
        assert!(!hds.contains("Host"));
        // When no Host has been generated yet, a custom Host IS passed through.
        let mut hds2 = DynHds::with_request_limits();
        let ctx2 = CustomHeaderContext::default();
        add_custom_headers(&mut hds2, &conn, &["Host: custom.example"], &[], false, &ctx2).unwrap();
        assert_eq!(hds2.get("Host").unwrap().value(), "custom.example");
    }

    #[test]
    fn skip_content_type_for_form_and_mime() {
        let conn = direct_conn();
        for ctx in [
            CustomHeaderContext {
                is_post_form: true,
                ..Default::default()
            },
            CustomHeaderContext {
                is_post_mime: true,
                ..Default::default()
            },
        ] {
            let mut hds = DynHds::with_request_limits();
            add_custom_headers(&mut hds, &conn, &["Content-Type: text/plain"], &[], false, &ctx)
                .unwrap();
            assert!(!hds.contains("Content-Type"));
        }
        // Outside form/mime, a custom Content-Type is allowed.
        let mut hds = DynHds::with_request_limits();
        let ctx = CustomHeaderContext::default();
        add_custom_headers(&mut hds, &conn, &["Content-Type: text/plain"], &[], false, &ctx)
            .unwrap();
        assert!(hds.contains("Content-Type"));
    }

    #[test]
    fn skip_content_length_during_authneg() {
        let conn = direct_conn();
        let mut hds = DynHds::with_request_limits();
        let ctx = CustomHeaderContext {
            authneg: true,
            ..Default::default()
        };
        add_custom_headers(&mut hds, &conn, &["Content-Length: 100"], &[], false, &ctx).unwrap();
        assert!(!hds.contains("Content-Length"));
    }

    #[test]
    fn skip_transfer_encoding_for_http2_plus() {
        let conn = direct_conn();
        // HTTP/2 (>= 20): Transfer-Encoding is dropped.
        let mut hds = DynHds::with_request_limits();
        let ctx = CustomHeaderContext {
            httpversion: 20,
            ..Default::default()
        };
        add_custom_headers(&mut hds, &conn, &["Transfer-Encoding: chunked"], &[], false, &ctx)
            .unwrap();
        assert!(!hds.contains("Transfer-Encoding"));
        // HTTP/1.1 (< 20): allowed.
        let mut hds11 = DynHds::with_request_limits();
        let ctx11 = CustomHeaderContext {
            httpversion: 11,
            ..Default::default()
        };
        add_custom_headers(
            &mut hds11,
            &conn,
            &["Transfer-Encoding: chunked"],
            &[],
            false,
            &ctx11,
        )
        .unwrap();
        assert!(hds11.contains("Transfer-Encoding"));
    }

    #[test]
    fn skip_authorization_and_cookie_when_not_allowed_to_host() {
        let conn = direct_conn();
        // Not allowed → both dropped.
        let mut hds = DynHds::with_request_limits();
        let ctx = CustomHeaderContext {
            allowed_to_host: false,
            ..Default::default()
        };
        add_custom_headers(
            &mut hds,
            &conn,
            &["Authorization: Bearer x", "Cookie: a=1"],
            &[],
            false,
            &ctx,
        )
        .unwrap();
        assert!(!hds.contains("Authorization"));
        assert!(!hds.contains("Cookie"));

        // Allowed → both kept.
        let mut hds_ok = DynHds::with_request_limits();
        let ctx_ok = CustomHeaderContext {
            allowed_to_host: true,
            ..Default::default()
        };
        add_custom_headers(
            &mut hds_ok,
            &conn,
            &["Authorization: Bearer x", "Cookie: a=1"],
            &[],
            false,
            &ctx_ok,
        )
        .unwrap();
        assert_eq!(hds_ok.get("Authorization").unwrap().value(), "Bearer x");
        assert_eq!(hds_ok.get("Cookie").unwrap().value(), "a=1");
    }

    #[test]
    fn skip_conditions_are_case_insensitive() {
        let conn = direct_conn();
        let mut hds = DynHds::with_request_limits();
        let ctx = CustomHeaderContext {
            host_header_present: true,
            authneg: true,
            httpversion: 30,
            allowed_to_host: false,
            ..Default::default()
        };
        // Mixed-case names must still match the skip ladder.
        add_custom_headers(
            &mut hds,
            &conn,
            &[
                "hOsT: x",
                "content-LENGTH: 9",
                "transfer-encoding: chunked",
                "AUTHORIZATION: y",
                "cookie: z=1",
            ],
            &[],
            false,
            &ctx,
        )
        .unwrap();
        assert_eq!(hds.count(), 0, "all should be suppressed regardless of case");
    }
}

