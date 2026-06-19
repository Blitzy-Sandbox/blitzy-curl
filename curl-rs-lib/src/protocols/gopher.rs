//! Gopher / Gophers protocol engine — the Rust analog of `lib/gopher.c`.
//!
//! Gopher (RFC 1436) is a deliberately minimal request/response protocol: the
//! client opens a TCP connection, sends a single *selector* line terminated by
//! `CRLF`, and the server streams the response body back until it closes the
//! connection. There are no request or response headers, no status line, and no
//! framing — the body is exactly the bytes the server sends. `gophers` is the
//! same protocol carried over TLS.
//!
//! This module is consumed by the engine through the [`Protocol`] trait. It is
//! the safe, asynchronous reimplementation of curl's `gopher_do`
//! (`lib/gopher.c`), which is used unmodified by the curl 8.x regression suite;
//! the C file is treated strictly as a **behavioral / ABI oracle**, not
//! transliterated line by line.
//!
//! # Selector construction (wire-parity critical)
//!
//! curl builds the selector from the parsed URL exactly as follows (the bytes
//! put on the wire are observable and exercised by `tests/data`, so they are
//! reproduced byte-for-byte — AAP §0.8.2):
//!
//! 1. `gopherpath` is the URL path, with `"?" + query` appended when the URL
//!    carries a query (curl's `curl_maprintf("%s?%s", path, query)`).
//! 2. The *degenerate* paths `"/"` and `"/1"` (anything whose byte length is
//!    `<= 2`) collapse to the empty (root) selector.
//! 3. Otherwise curl drops the leading `"/"` **and** the one-byte Gopher item
//!    type that follows it (`newp = gopherpath + 2`) and percent-decodes the
//!    remainder with `REJECT_ZERO` (a decoded NUL is rejected as
//!    [`CurlError::UrlMalformat`]). A URL query therefore becomes part of the
//!    decoded selector after the `?`, which is how Gopher search / Gopher+
//!    requests are expressed.
//!
//! All of this works on **bytes** (matching curl's `strlen`/pointer arithmetic),
//! so the two-byte strip never falls on a UTF-8 char boundary and never panics.
//! See [`build_selector`].
//!
//! # How the transfer runs (engine-driven body)
//!
//! curl's `gopher_do` sends the request and then calls `Curl_xfer_setup_recv`,
//! handing the *body receive* to the transfer engine — it does not read the
//! response itself. The Rust [`Protocol`] contract mirrors this precisely:
//! [`Protocol::do_it`] issues the request and returns a [`ProtocolTransfer`]
//! that tells the engine to stream a [`TransferDirection::Download`] body to the
//! client until the server closes the connection. The handler thus writes the
//! request with [`Curl_conn_send`] and leaves the response read loop (over the
//! same connection-filter chain, via `Curl_conn_recv`) to the engine.
//!
//! # `gophers` and TLS
//!
//! The `gophers` scheme carries [`PROTOPT_SSL`](super::PROTOPT_SSL), so TLS is
//! established entirely by the connection-filter chain (`crate::conn`'s cf-ssl
//! filter) before [`Protocol::do_it`] runs — exactly as the engine drives
//! curl's `gopher_connecting`/`Curl_conn_connect`. There is therefore **no**
//! TLS code in this module; `Gopher` and `Gophers` share the identical request
//! logic and differ only in their [`Scheme`] descriptor, mirroring the two
//! `Curl_protocol` vtables in the C oracle that both point at `gopher_do`.
//!
//! # Memory safety
//!
//! This subtree inherits `#![forbid(unsafe_code)]` from [`crate::protocols`]; it
//! is intentionally **not** re-declared here. The module is pure, allocation-safe
//! Rust with no raw pointers.

use super::{Protocol, ProtocolTransfer, Scheme, TransferDirection, SCHEME_GOPHER, SCHEME_GOPHERS};
use crate::conn::{BoxFuture, Connection, Curl_conn_send, FIRSTSOCKET};
use crate::easy::Easy;
use crate::error::{CurlError, Result};
use crate::transfer::uc_to_curlcode;
use crate::url::{CurlUPart, CurlUrl, CURLU_GUESS_SCHEME};
use crate::util::sendf::failf;

// ===========================================================================
// Percent-decoding (curl's `Curl_urldecode` with `REJECT_ZERO`)
// ===========================================================================

/// Convert one ASCII hex digit to its `0..=15` value, or `None` for a non-hex
/// byte — the total, panic-free equivalent of curl's `ISXDIGIT` + `curlx_hexval`
/// (accepts `0-9`, `a-f`, `A-F`).
#[inline]
fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode `input`, rejecting a decoded NUL byte — the Rust counterpart
/// of the `Curl_urldecode(..., REJECT_ZERO)` call curl's `gopher_do` makes on
/// the selector.
///
/// A `%` is decoded only when it is followed by two valid hex digits **and**
/// there are at least two more bytes available (curl's `alloc > 2` guard,
/// expressed here as `(len - i) > 2`); otherwise the `%` is preserved literally,
/// so malformed sequences such as `"%"`, `"%2"`, and `"%zz"` decode to
/// themselves. A `+` is left untouched (curl's URL decoder never maps `+` to a
/// space).
///
/// # Errors
///
/// Returns [`CurlError::UrlMalformat`] (curl's `CURLE_URL_MALFORMAT`) if any
/// decoded byte is NUL, matching `REJECT_ZERO`.
fn urldecode_reject_nul(input: &[u8]) -> Result<Vec<u8>> {
    let len = input.len();
    let mut out = Vec::with_capacity(len);
    let mut i = 0;

    while i < len {
        let cur = input[i];
        // Decode `%XX` only when a full, well-formed escape is present. The
        // `(len - i) > 2` test (curl's `alloc > 2`) guarantees `i + 1` and
        // `i + 2` are valid indices, keeping the lookahead in bounds.
        let decoded = if cur == b'%' && (len - i) > 2 {
            match (hex_val(input[i + 1]), hex_val(input[i + 2])) {
                (Some(hi), Some(lo)) => {
                    i += 3;
                    (hi << 4) | lo
                }
                // Not two hex digits: keep the '%' literally.
                _ => {
                    i += 1;
                    cur
                }
            }
        } else {
            i += 1;
            cur
        };

        // REJECT_ZERO: a decoded NUL byte is rejected.
        if decoded == 0 {
            return Err(CurlError::UrlMalformat);
        }
        out.push(decoded);
    }

    Ok(out)
}

// ===========================================================================
// Selector construction (curl's `gopher_do` selector logic)
// ===========================================================================

/// Build the Gopher selector from the URL `path` and optional `query`, exactly
/// as curl's `gopher_do` does.
///
/// `gopherpath` is `path` with `"?" + query` appended when a query is present.
/// The degenerate paths `"/"` and `"/1"` (any `gopherpath` whose **byte** length
/// is `<= 2`) yield the empty (root) selector. Otherwise the leading `"/"` and
/// the one-byte item type are dropped (`gopherpath[2..]`) and the remainder is
/// percent-decoded with [`urldecode_reject_nul`].
///
/// The work is byte-based (mirroring curl's `strlen` and `newp = gopherpath + 2`
/// pointer arithmetic), so the two-byte strip is always in bounds and never
/// crosses a UTF-8 char boundary.
///
/// # Errors
///
/// Propagates [`CurlError::UrlMalformat`] from [`urldecode_reject_nul`] when the
/// selector contains a percent-encoded NUL.
fn build_selector(path: &str, query: Option<&str>) -> Result<Vec<u8>> {
    // gopherpath = path (+ "?" + query). Built as bytes so the length test and
    // the two-byte strip use byte offsets exactly like the C oracle.
    let mut gopherpath: Vec<u8> = Vec::with_capacity(path.len() + query.map_or(0, |q| q.len() + 1));
    gopherpath.extend_from_slice(path.as_bytes());
    if let Some(q) = query {
        gopherpath.push(b'?');
        gopherpath.extend_from_slice(q.as_bytes());
    }

    // Degenerate cases "/" and "/1" (length <= 2) collapse to the empty (root)
    // selector — curl's `if(strlen(gopherpath) <= 2)`.
    if gopherpath.len() <= 2 {
        return Ok(Vec::new());
    }

    // Drop the leading "/" and the one-byte item type, then percent-decode the
    // remainder (rejecting a decoded NUL, curl's REJECT_ZERO).
    urldecode_reject_nul(&gopherpath[2..])
}

// ===========================================================================
// Request transmission
// ===========================================================================

/// Resolve the request URL for this transfer, mirroring the preflight in
/// [`Easy::perform`](crate::easy::Easy) (`Curl_easy`'s `state.up`): prefer an
/// explicitly-set `CURLOPT_CURLU` handle, otherwise parse the `CURLOPT_URL`
/// string (guessing the scheme for schemeless inputs, as curl does).
///
/// # Errors
///
/// [`CurlError::UrlMalformat`] when no URL is configured, or the parse error
/// mapped through [`uc_to_curlcode`] when the URL string is invalid.
fn resolve_request_url(data: &Easy) -> Result<CurlUrl> {
    if let Some(uh) = data.set.uh.as_ref() {
        Ok(uh.clone())
    } else if let Some(url_str) = data.url() {
        let mut url = CurlUrl::new();
        url.set(CurlUPart::Url, Some(url_str), CURLU_GUESS_SCHEME)
            .map_err(uc_to_curlcode)?;
        Ok(url)
    } else {
        Err(CurlError::UrlMalformat)
    }
}

/// Send the complete request buffer over the primary connection-filter chain,
/// looping until every byte is accepted.
///
/// curl's `gopher_do` sends the request in a partial-write loop because its
/// hand-rolled `select`/`poll` core can only move whatever the socket accepts
/// right now; under Tokio the awaited [`Curl_conn_send`] naturally handles
/// readiness, so this is a straightforward "write the rest" loop. The send uses
/// `eos = false`: the connection stays open to stream the response body
/// afterwards.
///
/// # Errors
///
/// Propagates any non-transient [`CurlError`] from [`Curl_conn_send`]. A write
/// that accepts zero bytes (the chain can make no progress) is reported as
/// [`CurlError::SendError`] (curl's `CURLE_SEND_ERROR`); the transient
/// [`CurlError::Again`] is retried.
async fn send_request(conn: &mut Connection, mut buf: &[u8]) -> Result<()> {
    while !buf.is_empty() {
        match Curl_conn_send(conn, FIRSTSOCKET, buf, false).await {
            // No progress possible on a non-empty buffer: a failed send.
            Ok(0) => return Err(CurlError::SendError),
            // `n` is the count accepted; clamp defensively (curl's
            // `if(nwritten > buf_len) DEBUGASSERT(0)`) before advancing.
            Ok(n) => buf = &buf[n.min(buf.len())..],
            // Transient would-block: the awaited send will make progress next.
            Err(CurlError::Again) => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// Issue the Gopher request and describe the transfer — the shared body of both
/// scheme handlers, the Rust analog of curl's `gopher_do`.
///
/// It resolves the URL, builds the selector from the path/query, sends
/// `<selector>\r\n` over the (already-connected, TLS-terminated for `gophers`)
/// filter chain, and returns a [`TransferDirection::Download`] descriptor so the
/// engine streams the response body to the client until the server closes the
/// connection (curl's `Curl_xfer_setup_recv(data, FIRSTSOCKET, -1)`). Gopher
/// responses carry no protocol headers, so `has_response_headers` stays `false`.
///
/// # Errors
///
/// * [`CurlError::UrlMalformat`] for a missing/invalid URL or a NUL-bearing
///   percent-encoded selector.
/// * The send error from [`send_request`] (after recording the
///   `"Failed sending Gopher request"` diagnostic, exactly as curl's `failf`).
async fn gopher_do(data: &mut Easy, conn: &mut Connection) -> Result<ProtocolTransfer> {
    // Resolve the URL and pull its (still percent-encoded) path and query, the
    // analog of curl reading `data->state.up.path` / `data->state.up.query`.
    let url = resolve_request_url(data)?;
    let path = url.get(CurlUPart::Path, 0).map_err(uc_to_curlcode)?;
    let query = url.get(CurlUPart::Query, 0).ok();

    // Build the decoded selector and frame the request as `<selector>\r\n`.
    let mut request = build_selector(&path, query.as_deref())?;
    request.extend_from_slice(b"\r\n");

    // Send the whole request; on failure record curl's diagnostic and surface
    // the error (curl writes this regardless of which send leg failed).
    if let Err(err) = send_request(conn, &request).await {
        failf(
            &mut conn.filter_data.error_buffer,
            "Failed sending Gopher request",
        );
        return Err(err);
    }

    // The engine streams the body (download) until the server closes; Gopher has
    // no response headers.
    Ok(ProtocolTransfer::new(TransferDirection::Download))
}

// ===========================================================================
// `Protocol` handlers
// ===========================================================================

/// The `gopher://` scheme handler (the Rust analog of C
/// `Curl_protocol_gopher`).
///
/// A zero-sized, stateless singleton: all per-transfer state lives on the
/// [`Easy`] handle and the [`Connection`], so one value can serve every
/// `gopher` transfer.
#[derive(Debug, Clone, Copy, Default)]
pub struct Gopher;

/// The `gophers://` (Gopher-over-TLS) scheme handler (the Rust analog of C
/// `Curl_protocol_gophers`).
///
/// Identical request logic to [`Gopher`]; the only difference is the [`Scheme`]
/// descriptor it advertises ([`PROTOPT_SSL`](super::PROTOPT_SSL)). TLS is
/// provided by the connection-filter chain, so there is no TLS code here.
#[derive(Debug, Clone, Copy, Default)]
pub struct Gophers;

impl Protocol for Gopher {
    fn scheme(&self) -> &'static Scheme {
        &SCHEME_GOPHER
    }

    fn do_it<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<ProtocolTransfer>> {
        Box::pin(gopher_do(data, conn))
    }
}

impl Protocol for Gophers {
    fn scheme(&self) -> &'static Scheme {
        &SCHEME_GOPHERS
    }

    fn do_it<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<ProtocolTransfer>> {
        Box::pin(gopher_do(data, conn))
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::{CURLPROTO_GOPHER, CURLPROTO_GOPHERS};

    // -----------------------------------------------------------------------
    // `urldecode_reject_nul` — must match curl's `Curl_urldecode(REJECT_ZERO)`
    // byte-for-byte (it drives the wire selector).
    // -----------------------------------------------------------------------

    #[test]
    fn urldecode_basic_escape() {
        assert_eq!(urldecode_reject_nul(b"a%20b").unwrap(), b"a b");
    }

    #[test]
    fn urldecode_accepts_both_hex_cases() {
        // Upper- and lowercase hex both decode (curl accepts `%2F` and `%2f`).
        assert_eq!(urldecode_reject_nul(b"%2F").unwrap(), b"/");
        assert_eq!(urldecode_reject_nul(b"%2f").unwrap(), b"/");
    }

    #[test]
    fn urldecode_preserves_malformed_escapes() {
        // A lone '%', a too-short escape, and non-hex digits are all kept
        // literally (curl's `alloc > 2` / `ISXDIGIT` guards).
        assert_eq!(urldecode_reject_nul(b"%").unwrap(), b"%");
        assert_eq!(urldecode_reject_nul(b"%2").unwrap(), b"%2");
        assert_eq!(urldecode_reject_nul(b"%zz").unwrap(), b"%zz");
    }

    #[test]
    fn urldecode_leaves_plus_untouched() {
        // curl's URL decoder never maps '+' to space.
        assert_eq!(urldecode_reject_nul(b"a+b").unwrap(), b"a+b");
    }

    #[test]
    fn urldecode_empty_is_empty() {
        assert_eq!(urldecode_reject_nul(b"").unwrap(), b"");
    }

    #[test]
    fn urldecode_rejects_encoded_nul() {
        // REJECT_ZERO: a decoded NUL byte fails with CURLE_URL_MALFORMAT.
        assert_eq!(urldecode_reject_nul(b"%00"), Err(CurlError::UrlMalformat));
        assert_eq!(urldecode_reject_nul(b"a%00b"), Err(CurlError::UrlMalformat));
    }

    // -----------------------------------------------------------------------
    // `build_selector` — the `gopher_do` selector logic (wire parity).
    // -----------------------------------------------------------------------

    #[test]
    fn selector_strips_slash_and_item_type() {
        // `gopher://host/1/path`: path "/1/path" -> drop "/1" -> "/path".
        assert_eq!(build_selector("/1/path", None).unwrap(), b"/path");
    }

    #[test]
    fn selector_root_is_empty() {
        // Degenerate paths "/" and "/1" (length <= 2) collapse to "" (root).
        assert_eq!(build_selector("/", None).unwrap(), b"");
        assert_eq!(build_selector("/1", None).unwrap(), b"");
    }

    #[test]
    fn selector_is_percent_decoded() {
        // `%20` -> space; decoding happens after the two-byte strip.
        assert_eq!(build_selector("/1/foo%20bar", None).unwrap(), b"/foo bar");
    }

    #[test]
    fn selector_strip_precedes_decode() {
        // Parity guard: curl strips the first two BYTES of the *encoded* path
        // and only then decodes. For "/%31/foo" that drops "/%", leaving
        // "31/foo" (decode-first would instead yield "/foo").
        assert_eq!(build_selector("/%31/foo", None).unwrap(), b"31/foo");
    }

    #[test]
    fn selector_appends_query() {
        // A query becomes part of the selector after '?', the Gopher search /
        // Gopher+ form (`curl_maprintf("%s?%s", path, query)`).
        assert_eq!(
            build_selector("/7/search", Some("term")).unwrap(),
            b"/search?term"
        );
    }

    #[test]
    fn selector_query_short_path_keeps_question_mark_offset() {
        // "/" + "?x" -> gopherpath "/?x" (len 3 > 2) -> drop "/?" -> "x".
        assert_eq!(build_selector("/", Some("x")).unwrap(), b"x");
    }

    #[test]
    fn selector_preserves_malformed_escape() {
        // A malformed trailing escape survives decoding verbatim. Path "/1/a%2"
        // drops "/1" -> "/a%2"; the too-short "%2" is kept literally (the
        // leading '/' is the selector's own path separator, like "/1/path").
        assert_eq!(build_selector("/1/a%2", None).unwrap(), b"/a%2");
    }

    #[test]
    fn selector_rejects_encoded_nul() {
        assert_eq!(
            build_selector("/1/x%00y", None),
            Err(CurlError::UrlMalformat)
        );
    }

    // -----------------------------------------------------------------------
    // Request framing — every request ends with CRLF (curl always sends the
    // trailing "\r\n", even for the empty root selector).
    // -----------------------------------------------------------------------

    #[test]
    fn request_is_crlf_terminated() {
        let mut request = build_selector("/1/path", None).unwrap();
        request.extend_from_slice(b"\r\n");
        assert_eq!(request, b"/path\r\n");
        assert!(request.ends_with(b"\r\n"));

        // A root request is exactly "\r\n".
        let mut root = build_selector("/", None).unwrap();
        root.extend_from_slice(b"\r\n");
        assert_eq!(root, b"\r\n");
    }

    // -----------------------------------------------------------------------
    // End-to-end selector extraction from a parsed URL (mirrors `gopher_do`'s
    // path/query retrieval through the URL API).
    // -----------------------------------------------------------------------

    fn selector_from_url(url_str: &str) -> Result<Vec<u8>> {
        let mut url = CurlUrl::new();
        url.set(CurlUPart::Url, Some(url_str), CURLU_GUESS_SCHEME)
            .map_err(uc_to_curlcode)?;
        let path = url.get(CurlUPart::Path, 0).map_err(uc_to_curlcode)?;
        let query = url.get(CurlUPart::Query, 0).ok();
        build_selector(&path, query.as_deref())
    }

    #[test]
    fn selector_from_full_gopher_url() {
        assert_eq!(selector_from_url("gopher://host/1/path").unwrap(), b"/path");
    }

    #[test]
    fn selector_from_url_root() {
        // No path component -> path defaults to "/" -> empty selector.
        assert_eq!(selector_from_url("gopher://host/").unwrap(), b"");
        assert_eq!(selector_from_url("gopher://host").unwrap(), b"");
    }

    #[test]
    fn selector_from_url_decodes_escape() {
        assert_eq!(
            selector_from_url("gopher://host/1/foo%20bar").unwrap(),
            b"/foo bar"
        );
    }

    #[test]
    fn selector_from_gophers_url() {
        assert_eq!(
            selector_from_url("gophers://host/1/secure").unwrap(),
            b"/secure"
        );
    }

    // -----------------------------------------------------------------------
    // `Protocol` handler descriptors and object safety.
    // -----------------------------------------------------------------------

    #[test]
    fn gopher_scheme_descriptor_matches_oracle() {
        let scheme = Gopher.scheme();
        assert_eq!(scheme.name, "gopher");
        assert_eq!(scheme.protocol, CURLPROTO_GOPHER);
        assert_eq!(scheme.family, CURLPROTO_GOPHER);
        assert_eq!(scheme.default_port, 70);
        assert!(!scheme.is_ssl());
    }

    #[test]
    fn gophers_scheme_descriptor_matches_oracle() {
        let scheme = Gophers.scheme();
        assert_eq!(scheme.name, "gophers");
        assert_eq!(scheme.protocol, CURLPROTO_GOPHERS);
        // The TLS variant's family is the plaintext protocol (CURLPROTO_GOPHER).
        assert_eq!(scheme.family, CURLPROTO_GOPHER);
        assert_eq!(scheme.default_port, 70);
        assert!(scheme.is_ssl());
    }

    #[test]
    fn handlers_are_object_safe_and_thread_safe() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Gopher>();
        assert_send_sync::<Gophers>();

        // Both must be usable as boxed trait objects (the engine dispatches
        // through `Box<dyn Protocol>`).
        let _gopher: Box<dyn Protocol> = Box::new(Gopher);
        let _gophers: Box<dyn Protocol> = Box::new(Gophers);
    }
}
