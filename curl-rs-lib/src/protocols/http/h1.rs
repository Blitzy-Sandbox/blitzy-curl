// SPDX-License-Identifier: curl
//
// HTTP/1.1 request-line / head parsing and request/response transfer.
//
// This module is the Rust port of curl 8.19.0-DEV `lib/http1.c` + `lib/http1.h`.
// It has two responsibilities that mirror the C original exactly:
//
//   * **Phase 1 — `H1ReqParser`** (port of `struct h1_req_parser`): an
//     incremental parser for an HTTP/1.x *request* head. curl uses it when it
//     needs to read a request line itself — CONNECT tunnels and forward-proxy
//     handling — and the same code is reused by the RTSP and WebSocket layers.
//     The parser recognises origin-form, absolute-form, authority-form
//     (CONNECT) and asterisk-form request targets and honours the STRICT vs.
//     lenient CRLF/whitespace rules byte-for-byte with the C code.
//
//   * **Phase 2 — the HTTP/1.1 transfer engine** ([`perform`]): drives a single
//     request/response exchange over a [`crate::conn::Connection`]'s filter
//     chain using the `hyper` HTTP/1 client. curl's original hand-rolled
//     `http1.c` serialisation (`Curl_h1_req_write_head`) is preserved as
//     [`req_write_head`] for wire-parity checks and for the head bytes emitted
//     on CONNECT/proxy tunnels; the actual client transfer is delegated to
//     `hyper` so that framing, chunked decoding and keep-alive match a
//     well-tested implementation while keeping curl's observable behaviour.
//
// # Memory safety
//
// This module is written entirely in safe Rust, satisfying the workspace CI
// gate that forbids the memory-safety escape hatch anywhere in the safe core
// (AAP §0.6.2 / §0.7.2). The `hyper` byte stream is bridged to the
// [`crate::conn::filters::FilterChain`] (which only exposes `async` `send`/`recv`
// on `&mut self`) through an in-memory `tokio::io::duplex` pipe plus a pump
// loop, avoiding any self-referential-future / raw-pointer trickery.
//
// All third-party dependencies are consumed via the workspace (`workspace =
// true`); no versions are hard-coded here.

use std::fmt::Write as _;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http::{HeaderName, HeaderValue, Method, Request, Uri, Version};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt as _;
use hyper::client::conn::http1;
use hyper::rt::{Read as HyperRead, Write as HyperWrite};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::conn::filters::FilterChain;
use crate::conn::{Connection, FIRSTSOCKET};
use crate::error::{CurlCode, Error, Result};
use crate::protocols::http::{
    HttpReqData, HttpResp, MAX_HTTP_RESP_HEADER_COUNT, MAX_HTTP_RESP_HEADER_SIZE,
};

// ===========================================================================
// Constants (mirroring `lib/http1.h`)
// ===========================================================================

/// No parse options (`H1_PARSE_OPT_NONE` in `http1.h`).
pub const H1_PARSE_OPT_NONE: u32 = 0;

/// Enforce strict RFC 9112 request-line syntax (`H1_PARSE_OPT_STRICT`).
///
/// When set, request lines must be terminated by a full `CRLF`, must not be
/// empty, and an unparsable absolute-form target is rejected rather than being
/// treated leniently as a path.
pub const H1_PARSE_OPT_STRICT: u32 = 1 << 0;

/// Maximum length curl accepts for an absolute-form request target
/// (`H1_MAX_URL_LEN` in `http1.h`, `8 * 1024`).
pub const H1_MAX_URL_LEN: usize = 8 * 1024;

/// Default maximum length of a single request-head line.
///
/// Matches `H1_PARSE_DEFAULT_MAX_LINE_LEN`, which in curl is defined as
/// `DYN_HTTP_REQUEST` (`1024 * 1024`) in `lib/curlx/dynbuf.h`.
pub const H1_PARSE_DEFAULT_MAX_LINE_LEN: usize = 1024 * 1024;

// ===========================================================================
// Phase 1 — H1ReqParser (port of `struct h1_req_parser`)
// ===========================================================================

/// Incremental parser for an HTTP/1.x request head.
///
/// This is the direct port of curl's `struct h1_req_parser`. Bytes are fed via
/// [`parse_read`](H1ReqParser::parse_read); the parser accumulates partial
/// lines in an internal scratch buffer across calls and reports completion via
/// [`done`](H1ReqParser::done). Once complete, the assembled request is
/// available through [`req`](H1ReqParser::req) / [`take_req`](H1ReqParser::take_req).
///
/// The C field `scratch_skip` — which is present in the C struct but never read
/// by `http1.c` — is repurposed here to expose the number of bytes currently
/// buffered for an in-progress line via [`scratch_len`](H1ReqParser::scratch_len);
/// its value has no effect on parsing, matching the C behaviour.
///
/// The C struct's `line` field (a `const char *` pointing transiently into
/// either the caller's buffer or `scratch` during a single parse iteration) has
/// no persistent-state role and cannot be expressed as a stored borrow without
/// self-referential-lifetime tricks. It is therefore modelled as an owned line
/// slice threaded through the internal helpers rather than a struct field — a
/// behaviour-preserving, memory-safe translation.
pub struct H1ReqParser {
    /// The request being assembled; `None` until the request line is parsed.
    req: Option<HttpReqData>,
    /// Scratch buffer holding the bytes of a not-yet-complete line.
    scratch: BytesMut,
    /// Number of bytes currently buffered in `scratch` (mirrors C `scratch_skip`).
    scratch_skip: usize,
    /// Maximum accepted length of a single line (excluding the terminator).
    max_line_len: usize,
    /// Length of the most recently completed line (terminator stripped).
    line_len: usize,
    /// Whether the terminating empty line has been seen.
    done: bool,
}

impl H1ReqParser {
    /// Create a new parser (`Curl_h1_req_parse_init`).
    ///
    /// `max_line_len` bounds the length of any single request-head line; callers
    /// typically pass [`H1_PARSE_DEFAULT_MAX_LINE_LEN`].
    #[must_use]
    pub fn new(max_line_len: usize) -> Self {
        Self {
            req: None,
            scratch: BytesMut::new(),
            scratch_skip: 0,
            max_line_len,
            line_len: 0,
            done: false,
        }
    }

    /// Whether the request head has been fully parsed (terminating empty line
    /// consumed).
    #[must_use]
    pub fn done(&self) -> bool {
        self.done
    }

    /// Length of the most recently completed line (terminator excluded).
    #[must_use]
    pub fn line_len(&self) -> usize {
        self.line_len
    }

    /// Number of bytes currently buffered for an in-progress (incomplete) line.
    #[must_use]
    pub fn scratch_len(&self) -> usize {
        self.scratch_skip
    }

    /// Borrow the parsed request, if the request line has been seen.
    #[must_use]
    pub fn req(&self) -> Option<&HttpReqData> {
        self.req.as_ref()
    }

    /// Take ownership of the parsed request, leaving the parser empty.
    pub fn take_req(&mut self) -> Option<HttpReqData> {
        self.req.take()
    }

    /// Trim the trailing line terminator from `line`, returning the length of
    /// the line content (terminator excluded).
    ///
    /// Ported from `trim_line`: strips a trailing `\n`, then a trailing `\r`.
    /// Under [`H1_PARSE_OPT_STRICT`] a missing `CRLF` or an empty line is a
    /// malformat error. A line whose content exceeds `max_line_len` is always
    /// rejected.
    fn trim_line(&self, line: &[u8], options: u32) -> Result<usize> {
        let strict = options & H1_PARSE_OPT_STRICT != 0;
        let mut len = line.len();

        if len > 0 && line[len - 1] == b'\n' {
            len -= 1;
            if len > 0 && line[len - 1] == b'\r' {
                len -= 1;
            } else if strict {
                // Bare LF without a preceding CR is rejected in strict mode.
                return Err(Error::url("h1: request line not CRLF terminated"));
            }
        } else if strict {
            // No line terminator at all (or empty) is rejected in strict mode.
            return Err(Error::url("h1: request line not CRLF terminated"));
        }

        if len > self.max_line_len {
            return Err(Error::url("h1: request head line exceeds maximum length"));
        }
        Ok(len)
    }

    /// Extract the next complete line from `buf`.
    ///
    /// Ported from `detect_line` + `next_line`. Returns `(Some(line), consumed)`
    /// where `line` is the trimmed line content (terminator stripped) when a
    /// full line is available, or `(None, consumed)` when more input is required
    /// (`CURLE_AGAIN` in the C code) — in which case all remaining bytes are
    /// buffered in `scratch`. `consumed` is the number of bytes taken from
    /// `buf`.
    fn next_line(&mut self, buf: &[u8], options: u32) -> Result<(Option<Vec<u8>>, usize)> {
        match buf.iter().position(|&b| b == b'\n') {
            Some(nl) => {
                // Bytes up to and including the LF form the tail of this line.
                let consumed = nl + 1;
                let piece = &buf[..consumed];

                let full: Vec<u8> = if self.scratch.is_empty() {
                    piece.to_vec()
                } else {
                    let mut v = Vec::with_capacity(self.scratch.len() + piece.len());
                    v.extend_from_slice(&self.scratch);
                    v.extend_from_slice(piece);
                    self.scratch.clear();
                    self.scratch_skip = 0;
                    v
                };

                let trimmed = self.trim_line(&full, options)?;
                let mut line = full;
                line.truncate(trimmed);
                self.line_len = trimmed;
                Ok((Some(line), consumed))
            }
            None => {
                // No terminator yet: buffer everything and ask for more input.
                let newlen = self.scratch.len() + buf.len();
                if newlen > self.max_line_len {
                    return Err(Error::url("h1: request head line exceeds maximum length"));
                }
                self.scratch.extend_from_slice(buf);
                self.scratch_skip = self.scratch.len();
                Ok((None, buf.len()))
            }
        }
    }

    /// Parse the request line (`start_req`).
    ///
    /// `line` is the trimmed request line (`METHOD SP target SP HTTP/x.y`). The
    /// method, request target and HTTP version are split exactly as the C code
    /// does — the method ends at `custom_method`'s length when it matches,
    /// otherwise at the first space; the version begins after the *last* space,
    /// so a lenient target may itself contain spaces. The target is then
    /// classified into asterisk-, authority- (CONNECT), origin- or absolute-form
    /// and the resulting [`HttpReqData`] is stored, applying `scheme_default`
    /// when the target carries no scheme of its own.
    fn start_req(
        &mut self,
        line: &[u8],
        scheme_default: Option<&str>,
        custom_method: Option<&str>,
        options: u32,
    ) -> Result<()> {
        let strict = options & H1_PARSE_OPT_STRICT != 0;
        let malformat = || Error::url("h1: malformed request line");

        // --- method -------------------------------------------------------
        let m_end = match custom_method.filter(|c| !c.is_empty()) {
            Some(cm) if line.starts_with(cm.as_bytes()) => cm.len(),
            _ => {
                let sp = line.iter().position(|&b| b == b' ').ok_or_else(malformat)?;
                if sp == 0 {
                    return Err(malformat());
                }
                sp
            }
        };
        if m_end >= line.len() {
            return Err(malformat());
        }
        let method = &line[..m_end];
        let target_start = m_end + 1;

        // --- version (after the LAST space) ------------------------------
        let last_sp = line[target_start..]
            .iter()
            .rposition(|&b| b == b' ')
            .map(|p| p + target_start);
        let sp2 = match last_sp {
            Some(i) if i > m_end => i,
            _ => return Err(malformat()),
        };
        let target = &line[target_start..sp2];
        let version = &line[sp2 + 1..];
        if target.is_empty() || version.is_empty() {
            return Err(malformat());
        }

        let method_str = std::str::from_utf8(method).map_err(|_| malformat())?;
        let target_str = std::str::from_utf8(target).map_err(|_| malformat())?;

        // --- classify the request target ---------------------------------
        let (scheme, authority, path): (Option<String>, Option<String>, Option<String>) =
            if target == b"*" {
                // asterisk-form (e.g. `OPTIONS * HTTP/1.1`)
                (None, None, Some("*".to_string()))
            } else if method.eq_ignore_ascii_case(b"CONNECT") {
                // authority-form (`CONNECT host:port`)
                (None, Some(target_str.to_string()), None)
            } else if target.first() == Some(&b'/') {
                // origin-form (`/path?query`)
                (None, None, Some(target_str.to_string()))
            } else {
                // absolute-form or a lenient path.
                if target.len() >= H1_MAX_URL_LEN {
                    return Err(malformat());
                }
                match parse_absolute_target(target_str) {
                    Some((sc, au, pa)) => (Some(sc), au, pa),
                    None if strict => return Err(malformat()),
                    None => (None, None, Some(target_str.to_string())),
                }
            };

        // Apply the default scheme when the target itself carried none.
        let scheme =
            scheme.or_else(|| scheme_default.filter(|s| !s.is_empty()).map(str::to_string));

        self.req = Some(HttpReqData::make(
            method_str,
            scheme.as_deref(),
            authority.as_deref(),
            path.as_deref(),
        ));
        Ok(())
    }

    /// Add a header line to the in-progress request (`Curl_dynhds_h1_add_line`).
    ///
    /// The name is the text up to the first `:`; the value is the remainder with
    /// leading blanks (space/tab) skipped and any trailing `CR`/`LF` removed. A
    /// line without a colon is a `CURLE_BAD_FUNCTION_ARGUMENT` error.
    fn add_header_line(&mut self, line: &[u8]) -> Result<()> {
        if line.is_empty() {
            return Ok(());
        }
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or_else(|| Error::bad_argument("h1: header line without colon"))?;

        let name = &line[..colon];
        let mut i = colon + 1;
        while i < line.len() && (line[i] == b' ' || line[i] == b'\t') {
            i += 1;
        }
        let mut value = &line[i..];
        if let Some(end) = value.iter().position(|&b| b == b'\r' || b == b'\n') {
            value = &value[..end];
        }

        let name = String::from_utf8_lossy(name).into_owned();
        let value = String::from_utf8_lossy(value).into_owned();

        let req = self.req.as_mut().ok_or_else(|| {
            Error::with_context(CurlCode::UrlMalformat, "h1: header before request line")
        })?;
        req.headers.add(name, value);
        Ok(())
    }

    /// Feed `buf` to the parser (`Curl_h1_req_parse_read`).
    ///
    /// Returns the number of bytes consumed from `buf`. Parsing may complete
    /// within this call (check [`done`](H1ReqParser::done)) or require further
    /// input, in which case any trailing partial line is retained internally.
    ///
    /// * `scheme_default` — scheme applied to component-form targets that lack
    ///   one (e.g. the connection's scheme).
    /// * `custom_method` — a non-standard method whose spelling may itself
    ///   contain no trailing space; when it prefixes the line it delimits the
    ///   method exactly.
    /// * `options` — [`H1_PARSE_OPT_NONE`] or [`H1_PARSE_OPT_STRICT`].
    pub fn parse_read(
        &mut self,
        mut buf: &[u8],
        scheme_default: Option<&str>,
        custom_method: Option<&str>,
        options: u32,
    ) -> Result<usize> {
        let mut pnread = 0usize;
        while !self.done {
            let (line_opt, nread) = self.next_line(buf, options)?;
            pnread += nread;
            buf = &buf[nread..];

            match line_opt {
                None => {
                    // Buffered a partial line; nothing more we can do until the
                    // caller supplies additional bytes.
                    break;
                }
                Some(line) => {
                    if self.req.is_none() {
                        self.start_req(&line, scheme_default, custom_method, options)?;
                    } else if line.is_empty() {
                        // Empty line: end of the request head.
                        self.done = true;
                        self.scratch.clear();
                        self.scratch_skip = 0;
                    } else {
                        self.add_header_line(&line)?;
                    }
                }
            }

            if buf.is_empty() {
                break;
            }
        }
        Ok(pnread)
    }
}

/// Detect and split an absolute-form request target.
///
/// Returns `Some((scheme, authority, path))` when `target` is an absolute URL
/// (`scheme://authority/path?query`), or `None` when it is not — in which case
/// the caller treats it as a lenient path (or rejects it under STRICT). This
/// mirrors curl's `Curl_is_absolute_url` + `curl_url_set(URLPART_URL, ...)`
/// path; the requirement for `"://"` matches curl's absolute-URL detection for
/// the request-line use case.
fn parse_absolute_target(target: &str) -> Option<(String, Option<String>, Option<String>)> {
    if !target.contains("://") {
        return None;
    }
    let u = url::Url::parse(target).ok()?;
    if u.scheme().is_empty() {
        return None;
    }
    let scheme = u.scheme().to_string();
    let authority = u.host_str().map(|h| match u.port() {
        Some(p) => format!("{h}:{p}"),
        None => h.to_string(),
    });
    let mut path = u.path().to_string();
    if let Some(q) = u.query() {
        path.push('?');
        path.push_str(q);
    }
    let path = if path.is_empty() { None } else { Some(path) };
    Some((scheme, authority, path))
}

// ===========================================================================
// Request-head serialisation (byte-exact with `Curl_h1_req_write_head`)
// ===========================================================================

/// Serialise a request head to bytes (`Curl_h1_req_write_head`).
///
/// Produces, byte-for-byte with the C implementation:
///
/// ```text
/// METHOD SP <scheme><://><authority><path> SP HTTP/1.<minor> CRLF
/// Header-Name: value CRLF
/// ...
/// CRLF
/// ```
///
/// The scheme/`://`/authority prefix is only emitted for absolute-form targets
/// (i.e. when `scheme` is present); origin-form requests serialise just the
/// path. Headers are emitted in insertion (wire) order.
pub fn req_write_head(req: &HttpReqData, http_minor: i32) -> Result<Vec<u8>> {
    let mut out = String::new();

    let scheme = req.scheme.as_deref().unwrap_or("");
    let sep = if req.scheme.is_some() { "://" } else { "" };
    let authority = req.authority.as_deref().unwrap_or("");
    let path = req.path.as_deref().unwrap_or("");

    // `"%s %s%s%s%s HTTP/1.%d\r\n"` — method, scheme, "://", authority, path.
    write!(
        out,
        "{} {}{}{}{} HTTP/1.{}\r\n",
        req.method, scheme, sep, authority, path, http_minor
    )
    .map_err(|_| Error::OutOfMemory)?;

    for (name, value) in req.headers.iter() {
        write!(out, "{name}: {value}\r\n").map_err(|_| Error::OutOfMemory)?;
    }
    out.push_str("\r\n");

    Ok(out.into_bytes())
}

/// Debug/trace serialisation of a request head (`Curl_h1_req_dprint`).
///
/// `Curl_h1_req_dprint` is declared in `http1.h` but has no implementation in
/// the curl 8.x tree; this provides the natural head serialisation (as
/// HTTP/1.1) for `--trace`/diagnostic output.
pub fn req_dprint(req: &HttpReqData) -> Result<String> {
    let bytes = req_write_head(req, 1)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

// ===========================================================================
// Phase 2 — HTTP/1.1 transfer engine over `hyper`
// ===========================================================================

/// Size of the in-memory duplex pipe bridging `hyper`/`h2` and the filter
/// chain. `pub(crate)` so the sibling [`crate::protocols::http::h2`] engine
/// bridges its connection to the filter chain with the identical geometry.
pub(crate) const DUPLEX_BUF_LEN: usize = 64 * 1024;

/// Size of the scratch buffers used by the byte pump.
const PUMP_BUF_LEN: usize = 64 * 1024;

/// A request body supplied to [`perform`].
///
/// The variant selects the framing used on the wire, matching curl's choice
/// between `Content-Length` and `Transfer-Encoding: chunked`:
///
/// * [`RequestBody::Empty`] — no body (`Content-Length: 0`).
/// * [`RequestBody::Sized`] — body of known length (`Content-Length`).
/// * [`RequestBody::Chunked`] — body of unknown length (`chunked`).
#[derive(Clone, Debug)]
pub enum RequestBody {
    /// No request body.
    Empty,
    /// A complete body of known length, sent with `Content-Length`.
    Sized(Vec<u8>),
    /// A complete body sent with `Transfer-Encoding: chunked` framing.
    Chunked(Vec<u8>),
}

/// Framing mode of a [`ReqBody`].
#[derive(Clone, Copy)]
enum BodyMode {
    Empty,
    Sized,
    Chunked,
}

/// [`http_body::Body`] adaptor for a [`RequestBody`].
///
/// The body is delivered as at most one data frame. [`BodyMode`] drives
/// [`Body::size_hint`] so `hyper` selects `Content-Length` (exact size) or
/// chunked framing (unknown size), preserving curl's on-the-wire choice.
struct ReqBody {
    data: Option<Bytes>,
    mode: BodyMode,
}

impl RequestBody {
    fn into_req_body(self) -> ReqBody {
        match self {
            RequestBody::Empty => ReqBody {
                data: None,
                mode: BodyMode::Empty,
            },
            RequestBody::Sized(v) => ReqBody {
                data: Some(Bytes::from(v)),
                mode: BodyMode::Sized,
            },
            RequestBody::Chunked(v) => ReqBody {
                data: Some(Bytes::from(v)),
                mode: BodyMode::Chunked,
            },
        }
    }
}

impl Body for ReqBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        // `ReqBody` is `Unpin` (all fields are `Unpin`), so `get_mut` needs no
        // pin projection and no memory-safety escape hatch.
        let this = self.get_mut();
        match this.data.take() {
            Some(b) if !b.is_empty() => Poll::Ready(Some(Ok(Frame::data(b)))),
            _ => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        match self.mode {
            BodyMode::Empty => SizeHint::with_exact(0),
            BodyMode::Sized => {
                SizeHint::with_exact(self.data.as_ref().map_or(0, Bytes::len) as u64)
            }
            // Unknown length -> `hyper` uses chunked transfer encoding.
            BodyMode::Chunked => SizeHint::new(),
        }
    }
}

/// Which phase of the exchange an error occurred in (affects code mapping).
#[derive(Clone, Copy)]
enum Phase {
    /// Before/while obtaining the response head.
    Head,
    /// While streaming the response body.
    Body,
}

/// Map a `hyper` error to the frozen curl error code appropriate for `phase`.
///
/// * parse / bad status line -> `CURLE_WEIRD_SERVER_REPLY` (8)
/// * incomplete message in the head -> `CURLE_GOT_NOTHING` (52)
/// * incomplete message in the body -> `CURLE_PARTIAL_FILE` (18)
/// * aborted request-body write -> `CURLE_SEND_ERROR` (55)
/// * connection closed/cancelled before a head -> `CURLE_GOT_NOTHING` (52)
/// * anything else -> `CURLE_RECV_ERROR` (56)
fn classify_hyper(e: &hyper::Error, phase: Phase) -> Error {
    // A `Parse::TooLarge` while obtaining the response head means hyper hit one
    // of its configured ceilings. Because `max_buf_size` is sized to curl's
    // absolute header-byte ceiling (see the builder in `h1_exchange`), a byte
    // overflow is caught first by `record_response`/`bump_headersize`
    // (-> `CURLE_RECV_ERROR` 56). The remaining head `TooLarge` is therefore a
    // *header-count* overflow past `max_headers` (httparse `TooManyHeaders`
    // -> `Parse::TooLarge`), which curl reports as `CURLE_TOO_LARGE` (100) with
    // the exact "Too many response headers, N is max" text (← the header-store
    // `failf` in `lib/headers.c`).
    //
    // hyper exposes the precise `Error::is_parse_too_large()` predicate only
    // under `feature = "server"`; as an HTTP client we cannot call it. We
    // instead recognise the variant by its stable public `Display` text
    // ("message head is too large" — the sole `Parse` description containing
    // "too large"; `UriTooLong` renders "URI too long"), double-guarded by
    // `is_parse()` so a non-parse error whose message coincidentally contained
    // the phrase could never match. This arm MUST precede the generic
    // `is_parse()` arm below, which would otherwise claim the error first and
    // misclassify count overflow as `CURLE_WEIRD_SERVER_REPLY` (8).
    if matches!(phase, Phase::Head) && e.is_parse() && e.to_string().contains("too large") {
        return Error::with_context(
            CurlCode::TooLarge,
            format!("Too many response headers, {MAX_HTTP_RESP_HEADER_COUNT} is max"),
        );
    }
    if e.is_parse() || e.is_parse_status() {
        return Error::with_context(
            CurlCode::WeirdServerReply,
            format!("h1: bad server reply: {e}"),
        );
    }
    if e.is_incomplete_message() {
        return match phase {
            Phase::Head => Error::GotNothing,
            Phase::Body => Error::PartialFile,
        };
    }
    if e.is_body_write_aborted() {
        return Error::Send;
    }
    match phase {
        Phase::Head if e.is_closed() || e.is_canceled() => Error::GotNothing,
        Phase::Head | Phase::Body => Error::Recv,
    }
}

/// Compute the request-target string for the request line.
///
/// Uses origin-form (path only, default `/`) for ordinary requests so that
/// `hyper` does not synthesise a `Host` header from a URI authority — curl
/// controls the `Host` header explicitly. CONNECT uses authority-form and
/// `OPTIONS *` uses asterisk-form.
fn request_target(req: &HttpReqData) -> String {
    if req.path.as_deref() == Some("*") {
        return "*".to_string();
    }
    if req.method.eq_ignore_ascii_case("CONNECT") {
        if let Some(auth) = req.authority.as_deref() {
            return auth.to_string();
        }
    }
    match req.path.as_deref() {
        Some(p) if !p.is_empty() => p.to_string(),
        _ => "/".to_string(),
    }
}

/// Build the `hyper` request from a [`HttpReqData`].
///
/// Headers are emitted in curl's insertion (wire) order. A `Host` header is
/// synthesised from the authority only when the caller did not already supply
/// one. A `Connection` header reflecting keep-alive/close is added only when the
/// caller did not set one, matching curl's HTTP/1.0-vs-1.1 defaults.
fn build_request(
    req: &HttpReqData,
    http_minor: i32,
    body: RequestBody,
    req_keepalive: bool,
) -> Result<Request<ReqBody>> {
    let method =
        Method::from_bytes(req.method.as_bytes()).map_err(|_| Error::url("h1: invalid method"))?;

    let uri: Uri = request_target(req)
        .parse()
        .map_err(|_| Error::url("h1: invalid request target"))?;

    let version = if http_minor == 0 {
        Version::HTTP_10
    } else {
        Version::HTTP_11
    };

    let mut builder = Request::builder().method(method).uri(uri).version(version);

    // `Host` from authority, unless the caller already provided one.
    if !req.headers.contains("Host") {
        if let Some(authority) = req.authority.as_deref() {
            builder = builder.header(http::header::HOST, authority);
        }
    }

    // Request headers, preserving order and duplicates.
    for (name, value) in req.headers.iter() {
        let hname = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| Error::url("h1: invalid header name"))?;
        let hvalue =
            HeaderValue::from_str(value).map_err(|_| Error::url("h1: invalid header value"))?;
        builder = builder.header(hname, hvalue);
    }

    // Keep-alive / close, only when not explicitly set by the caller.
    if !req.headers.contains("Connection") {
        if http_minor >= 1 && !req_keepalive {
            builder = builder.header(http::header::CONNECTION, "close");
        } else if http_minor == 0 && req_keepalive {
            builder = builder.header(http::header::CONNECTION, "keep-alive");
        }
    }

    builder
        .body(body.into_req_body())
        .map_err(|e| Error::url(format!("h1: invalid request: {e}")))
}

/// Convert `hyper`'s response head into curl's [`HttpResp`].
///
/// `hyper` does not surface the server's original reason phrase, so the
/// canonical text for the status code is used. Headers are copied in receive
/// order, preserving visibility for `--trace`.
fn map_response(parts: &http::response::Parts) -> HttpResp {
    let status = i32::from(parts.status.as_u16());
    let mut resp = HttpResp::make(status, parts.status.canonical_reason());
    for (name, value) in parts.headers.iter() {
        resp.headers.add(
            name.as_str(),
            String::from_utf8_lossy(value.as_bytes()).into_owned(),
        );
    }
    resp
}

/// Decide whether the connection may be reused after this exchange.
///
/// Mirrors curl's keep-alive logic: HTTP/1.1 defaults to reuse unless the
/// response carries `Connection: close`; HTTP/1.0 defaults to close unless the
/// response carries `Connection: keep-alive`. A request that opted out of
/// keep-alive is never reused.
fn response_keep_alive(http_minor: i32, headers: &http::HeaderMap, req_keepalive: bool) -> bool {
    if !req_keepalive {
        return false;
    }
    let (mut has_close, mut has_keep) = (false, false);
    for value in headers.get_all(http::header::CONNECTION).iter() {
        if let Ok(s) = value.to_str() {
            for token in s.split(',') {
                let t = token.trim();
                if t.eq_ignore_ascii_case("close") {
                    has_close = true;
                } else if t.eq_ignore_ascii_case("keep-alive") {
                    has_keep = true;
                }
            }
        }
    }
    if http_minor >= 1 {
        !has_close
    } else {
        has_keep
    }
}

/// Shuttle bytes between an in-memory duplex endpoint and the connection's
/// filter chain until either side closes.
///
/// This is the fully safe-Rust bridge that lets `hyper`/`h2` (which need an
/// `AsyncRead + AsyncWrite`) drive a [`FilterChain`] (which only exposes async
/// `send`/`recv` on `&mut self`). The two in-flight futures inside the
/// `select!` borrow disjoint objects — the duplex read half vs. the chain — and
/// the loser is dropped before its handler re-borrows the chain, so there is no
/// aliasing. `TcpStream::read`/filter `recv` are cancel-safe, so dropping a
/// pending branch loses no bytes.
///
/// Returns `Ok(())` on a clean peer EOF (`recv` returned 0); on return the
/// duplex write half is dropped, signalling EOF to `hyper`/`h2` so a buffered
/// response can drain.
///
/// `pub(crate)` so the sibling [`crate::protocols::http::h2`] engine reuses the
/// identical, audited bridge rather than duplicating it (a single point of
/// cancel-safety review for both HTTP/1 and HTTP/2 over a filter chain).
pub(crate) async fn pump_bridge(
    chain: &mut FilterChain,
    bridge: tokio::io::DuplexStream,
) -> Result<()> {
    let (mut bridge_r, mut bridge_w) = tokio::io::split(bridge);
    let mut out_buf = vec![0u8; PUMP_BUF_LEN];
    let mut in_buf = vec![0u8; PUMP_BUF_LEN];
    // Once `hyper` closes its write side we stop reading from the bridge, but we
    // keep receiving from the chain so the response can still be delivered.
    let mut send_open = true;

    loop {
        tokio::select! {
            read = bridge_r.read(&mut out_buf), if send_open => {
                match read {
                    Ok(0) => {
                        // `hyper` finished writing the request.
                        send_open = false;
                    }
                    Ok(n) => {
                        let mut off = 0;
                        while off < n {
                            let w = chain.send(&out_buf[off..n], false).await?;
                            if w == 0 {
                                return Err(Error::Send);
                            }
                            off += w;
                        }
                    }
                    Err(_) => return Err(Error::Send),
                }
            }
            recvd = chain.recv(&mut in_buf) => {
                match recvd {
                    Ok(0) => return Ok(()),          // peer EOF
                    Ok(n) => {
                        bridge_w
                            .write_all(&in_buf[..n])
                            .await
                            .map_err(|_| Error::Recv)?;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }
}

/// Drive a single HTTP/1 request/response exchange over the byte stream `io`.
///
/// `io` is a `hyper` I/O endpoint (in production, the duplex half bridged to the
/// filter chain; in tests, a `TokioIo<TcpStream>`). Returns the mapped
/// [`HttpResp`] together with whether the connection may be reused.
///
/// The `hyper` `Connection` future must be polled concurrently with the request
/// futures; a `biased` `select!` prioritises the request/response result so the
/// response head is preferred over connection completion. If the connection
/// completes before the head is available the exchange fails immediately
/// (avoiding a spin); during body streaming a clean connection completion is
/// recorded and the remaining buffered frames are drained.
async fn h1_exchange<S, W>(
    io: S,
    req: &HttpReqData,
    http_minor: i32,
    body: RequestBody,
    req_keepalive: bool,
    fail_on_error: bool,
    mut write_body: W,
) -> Result<(HttpResp, bool)>
where
    S: HyperRead + HyperWrite + Unpin,
    W: FnMut(&[u8]) -> Result<()>,
{
    // Build the request first so malformed input fails before any I/O.
    let hyper_req = build_request(req, http_minor, body, req_keepalive)?;

    // Raise hyper's response-header parse ceiling from its default of 100 to
    // curl's `MAX_HTTP_RESP_HEADER_COUNT` (5000). Without this, a perfectly
    // ordinary response bearing more than 100 header lines would be rejected by
    // the parser — far below curl 8.x's documented limit. `max_headers` sizes an
    // in-parser buffer of `val` slots per response, so we cap it at exactly one
    // above the curl limit: this lets the parser hand the boundary case (the
    // 5001st header) up to `record_response`, which maps the overflow to
    // `CURLE_TOO_LARGE`, matching curl's "accept 5000, reject the 5001st" rule
    // (← `MAX_HTTP_RESP_HEADER_COUNT`, `lib/http.h`; the header-store guard in
    // `lib/headers.c`). Kept modest to bound per-response allocation.
    let mut builder = http1::Builder::new();
    builder.max_headers(MAX_HTTP_RESP_HEADER_COUNT + 1);
    // Raise hyper's head-buffer ceiling to curl's absolute response-header byte
    // limit (`MAX_HTTP_RESP_HEADER_SIZE * 20`, i.e. 6,144,000 bytes — the same
    // `max * 20` bound enforced by `bump_headersize`). hyper's default
    // (`DEFAULT_MAX_BUFFER_SIZE`, ~408 KiB) is *below* curl's per-transfer
    // ceiling, so without this a head between ~408 KiB and 6 MB would be
    // rejected by the parser (`Parse::TooLarge`) before `record_response` could
    // apply curl's real size rule. By admitting any head curl itself would
    // accept, we make `record_response`/`bump_headersize` the authoritative
    // *size* gate (overflow -> `CURLE_RECV_ERROR` 56 with the exact "Too large
    // response headers" text), leaving `max_headers` as the sole *count* gate
    // (overflow -> `CURLE_TOO_LARGE` 100, mapped in `classify_hyper`). This is
    // parity-consistent: curl buffers the same ceiling, so no new exposure is
    // introduced (← `MAX_HTTP_RESP_HEADER_SIZE`, `lib/http.h`).
    builder.max_buf_size(MAX_HTTP_RESP_HEADER_SIZE.saturating_mul(20));
    let (mut sender, conn) = builder
        .handshake(io)
        .await
        .map_err(|e| classify_hyper(&e, Phase::Head))?;
    tokio::pin!(conn);

    // The hyper `Connection` future performs the actual socket I/O and must be
    // polled concurrently with the request/response futures. Its *completion*
    // is informational — the response may already have been handed off to
    // `send_request` when the connection then closes — so we record it via
    // `conn_done` and only treat a connection **error** as fatal. The guard
    // also prevents polling the future after it has resolved.
    let mut conn_done = false;

    // Phase A: wait until the sender can accept a request, driving `conn`.
    loop {
        tokio::select! {
            biased;
            r = sender.ready() => {
                r.map_err(|e| classify_hyper(&e, Phase::Head))?;
                break;
            }
            c = &mut conn, if !conn_done => {
                conn_done = true;
                if let Err(e) = c {
                    return Err(classify_hyper(&e, Phase::Head));
                }
            }
        }
    }

    // Phase B: send the request and obtain the response head, driving `conn`.
    // If `conn` completes in the same cycle the response arrives, the next
    // iteration extracts it from `send_fut` (which is polled first).
    let send_fut = sender.send_request(hyper_req);
    tokio::pin!(send_fut);
    let response = loop {
        tokio::select! {
            biased;
            r = &mut send_fut => break r.map_err(|e| classify_hyper(&e, Phase::Head))?,
            c = &mut conn, if !conn_done => {
                conn_done = true;
                if let Err(e) = c {
                    return Err(classify_hyper(&e, Phase::Head));
                }
            }
        }
    };

    let (parts, mut resp_body) = response.into_parts();
    let reusable = response_keep_alive(http_minor, &parts.headers, req_keepalive);
    let mut resp = map_response(&parts);

    // `CURLOPT_FAILONERROR` (`-f`/`--fail`): once the status line reports an HTTP
    // error (>= 400), curl stops handing the response body to the client
    // (`k->ignorebody`), which is why `curl -f` on a `404` prints nothing. The
    // status is known here — before the first body frame is read — so the
    // write-out is gated from the outset. The body is still drained from the
    // socket below (so keep-alive accounting is unaffected); only its delivery
    // to `write_body` is suppressed.
    let suppress_body = fail_on_error && resp.status >= 400;

    // Phase C: stream the body, recording trailers, draining until EOF.
    loop {
        tokio::select! {
            biased;
            frame = resp_body.frame() => {
                match frame {
                    Some(Ok(fr)) => {
                        if fr.is_data() {
                            if let Ok(data) = fr.into_data() {
                                if !suppress_body {
                                    write_body(data.as_ref())?;
                                }
                            }
                        } else if let Ok(trailers) = fr.into_trailers() {
                            for (name, value) in trailers.iter() {
                                resp.trailers.add(
                                    name.as_str(),
                                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                                );
                            }
                        }
                    }
                    Some(Err(e)) => return Err(classify_hyper(&e, Phase::Body)),
                    None => break,
                }
            }
            c = &mut conn, if !conn_done => {
                conn_done = true;
                if let Err(e) = c {
                    return Err(classify_hyper(&e, Phase::Body));
                }
                // Clean connection completion (e.g. `Connection: close`): keep
                // draining buffered frames until `frame()` yields `None`.
            }
        }
    }

    Ok((resp, reusable))
}

/// Perform one HTTP/1.1 request/response exchange over a connection.
///
/// This is the entry point invoked by the HTTP version dispatch in
/// [`crate::protocols::http`]. The request is driven over the connection's
/// primary [`FilterChain`] (raw TCP or TLS), with `hyper` handling HTTP/1
/// framing, chunked transfer decoding and keep-alive.
///
/// * `req` — the fully-populated request description (method, target, headers).
/// * `http_minor` — `0` for HTTP/1.0, `1` for HTTP/1.1 (governs keep-alive
///   defaults and the request-line version).
/// * `body` — the request body and its framing ([`RequestBody`]).
/// * `write_body` — sink invoked with each chunk of decoded response body; its
///   error is mapped to `CURLE_WRITE_ERROR` (23).
///
/// `Expect: 100-continue` handling is intentionally *not* reimplemented here —
/// it is delegated to the caller in [`crate::protocols::http`] per the design.
///
/// On completion the connection's keep-alive disposition is updated: reusable
/// connections have their `lastused` timestamp refreshed (for a future
/// `ConnCache` to reclaim), while non-reusable connections are closed.
///
/// # Errors
///
/// Returns a [`crate::error::Error`] whose code follows curl's conventions:
/// send failure -> `CURLE_SEND_ERROR` (55), receive failure ->
/// `CURLE_RECV_ERROR` (56), a bad status line -> `CURLE_WEIRD_SERVER_REPLY`
/// (8), no reply -> `CURLE_GOT_NOTHING` (52), body write-out failure ->
/// `CURLE_WRITE_ERROR` (23), truncated body -> `CURLE_PARTIAL_FILE` (18).
pub async fn perform<W>(
    conn: &mut Connection,
    req: HttpReqData,
    http_minor: i32,
    body: RequestBody,
    fail_on_error: bool,
    write_body: W,
) -> Result<HttpResp>
where
    W: FnMut(&[u8]) -> Result<()>,
{
    // HTTP/1.1 defaults to keep-alive; HTTP/1.0 defaults to close. An explicit
    // caller-supplied `Connection` header is honoured verbatim in
    // `build_request`.
    let req_keepalive = http_minor >= 1;

    // Ensure the primary filter chain exists and is connected.
    {
        let chain = conn.cfilter[FIRSTSOCKET].as_mut().ok_or_else(|| {
            Error::with_context(CurlCode::SendError, "h1: connection has no filter chain")
        })?;
        if !chain.is_connected() {
            chain.connect(true).await?;
        }
    }

    let (resp, reusable) = {
        // Borrow the chain only for the duration of the exchange so that the
        // keep-alive disposition below can re-borrow `conn`.
        let chain = conn.cfilter[FIRSTSOCKET].as_mut().ok_or_else(|| {
            Error::with_context(CurlCode::SendError, "h1: connection has no filter chain")
        })?;

        // Fully safe-Rust bridge: `hyper` drives one end of an in-memory duplex
        // pipe; `pump_bridge` shuttles bytes between the other end and the
        // filter chain.
        let (hyper_side, bridge_side) = tokio::io::duplex(DUPLEX_BUF_LEN);
        let io = TokioIo::new(hyper_side);

        let exchange = h1_exchange(
            io,
            &req,
            http_minor,
            body,
            req_keepalive,
            fail_on_error,
            write_body,
        );
        let pump = pump_bridge(chain, bridge_side);
        tokio::pin!(exchange);
        tokio::pin!(pump);

        let mut pump_done = false;
        loop {
            tokio::select! {
                biased;
                r = &mut exchange => break r?,
                p = &mut pump, if !pump_done => {
                    pump_done = true;
                    // Surface socket errors; on a clean EOF keep looping so the
                    // exchange can drain any buffered response body. The pump's
                    // duplex write half is dropped on return, signalling EOF to
                    // `hyper`.
                    p?;
                }
            }
        }
    };

    // Keep-alive disposition. There is no connection-pool type yet; reflect the
    // decision on the connection so the (future) transfer driver / `ConnCache`
    // can reuse or discard it, mirroring curl's `Curl_conncache` handling.
    if reusable {
        conn.lastused = std::time::Instant::now();
    } else {
        conn.close(FIRSTSOCKET);
    }

    Ok(resp)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use crate::conn::filters::{CfFuture, FilterCtx};
    use crate::conn::{CfType, Connection, ConnectionFilter, Scheme};

    /// A leaf [`ConnectionFilter`] wrapping a pre-connected `TcpStream`.
    ///
    /// This lets `perform` drive a *real* [`FilterChain`] end-to-end while using
    /// only whitelisted `conn` / `conn::filters` types (no dependency on the
    /// production socket filter). The stream is connected before construction,
    /// so `connect` merely reports success.
    struct MockTcpFilter {
        stream: Option<TcpStream>,
    }

    impl ConnectionFilter for MockTcpFilter {
        fn name(&self) -> &'static str {
            "MOCK-TCP"
        }

        fn cf_type(&self) -> CfType {
            CfType::IP_CONNECT
        }

        fn connect<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            _blocking: bool,
        ) -> CfFuture<'a, Result<bool>> {
            Box::pin(async move { Ok(self.stream.is_some()) })
        }

        fn send<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            buf: &'a [u8],
            _eos: bool,
        ) -> CfFuture<'a, Result<usize>> {
            Box::pin(async move {
                let s = self.stream.as_mut().ok_or(Error::Send)?;
                s.write_all(buf).await.map_err(|_| Error::Send)?;
                Ok(buf.len())
            })
        }

        fn recv<'a>(
            &'a mut self,
            _cx: &'a mut FilterCtx<'_>,
            buf: &'a mut [u8],
        ) -> CfFuture<'a, Result<usize>> {
            Box::pin(async move {
                let s = self.stream.as_mut().ok_or(Error::Recv)?;
                s.read(buf).await.map_err(|_| Error::Recv)
            })
        }
    }

    // ---- helpers ---------------------------------------------------------

    /// Find the first occurrence of `needle` within `haystack`.
    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || haystack.len() < needle.len() {
            return None;
        }
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    /// Read a complete HTTP/1 request (head + body) from a mock-server socket.
    ///
    /// Reads until the `CRLFCRLF` head terminator, then reads the declared
    /// `Content-Length` bytes or, for a chunked body, until the `0\r\n\r\n`
    /// terminator.
    async fn read_request(sock: &mut TcpStream) -> Vec<u8> {
        let mut data = Vec::new();
        let mut buf = [0u8; 4096];

        let head_end = loop {
            if let Some(pos) = find_subslice(&data, b"\r\n\r\n") {
                break pos + 4;
            }
            let n = sock.read(&mut buf).await.unwrap();
            if n == 0 {
                return data;
            }
            data.extend_from_slice(&buf[..n]);
        };

        let head = String::from_utf8_lossy(&data[..head_end]).to_ascii_lowercase();
        let chunked = head.contains("transfer-encoding:") && head.contains("chunked");
        let clen: usize = head
            .lines()
            .find_map(|l| {
                l.strip_prefix("content-length:")
                    .map(|v| v.trim().parse().unwrap_or(0))
            })
            .unwrap_or(0);

        if chunked {
            while find_subslice(&data[head_end..], b"0\r\n\r\n").is_none() {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
            }
        } else {
            while data.len() < head_end + clen {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
            }
        }
        data
    }

    /// Lowercased position of `needle` (already lowercase) within `haystack`.
    fn ci_pos(haystack: &[u8], needle: &str) -> Option<usize> {
        let lower = String::from_utf8_lossy(haystack).to_ascii_lowercase();
        lower.find(needle)
    }

    // ---- Phase 1: constants & serialisation ------------------------------

    #[test]
    fn parser_constants_exact() {
        assert_eq!(H1_PARSE_OPT_NONE, 0);
        assert_eq!(H1_PARSE_OPT_STRICT, 1);
        assert_eq!(H1_MAX_URL_LEN, 8192);
        assert_eq!(H1_PARSE_DEFAULT_MAX_LINE_LEN, 1024 * 1024);
    }

    #[test]
    fn req_write_head_byte_exact_origin_form() {
        // Origin-form: no scheme, no authority (Host travels as a header) — the
        // request target is just the path, byte-for-byte with C's format.
        let mut req = HttpReqData::make("GET", None, None, Some("/index.html"));
        req.headers.add("Host", "example.com");
        req.headers.add("Accept", "*/*");

        let head = req_write_head(&req, 1).unwrap();
        assert_eq!(
            head,
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n".to_vec()
        );
    }

    #[test]
    fn req_write_head_absolute_form_and_http10() {
        // Absolute-form (proxy) target: scheme + "://" + authority + path.
        let req = HttpReqData::make("GET", Some("http"), Some("proxy.test:8080"), Some("/p"));
        let head = req_write_head(&req, 0).unwrap();
        assert_eq!(
            head,
            b"GET http://proxy.test:8080/p HTTP/1.0\r\n\r\n".to_vec()
        );
    }

    #[test]
    fn req_write_head_connect_emits_authority() {
        // CONNECT authority-form: C emits the authority (no scheme, no path),
        // exercising the `req->authority ? ... : ""` branch of the C format.
        let req = HttpReqData::make("CONNECT", None, Some("tunnel.test:443"), None);
        let head = req_write_head(&req, 1).unwrap();
        assert_eq!(head, b"CONNECT tunnel.test:443 HTTP/1.1\r\n\r\n".to_vec());
    }

    #[test]
    fn req_dprint_serialises_head() {
        let req = HttpReqData::make("HEAD", None, None, Some("/"));
        let s = req_dprint(&req).unwrap();
        assert!(s.starts_with("HEAD / HTTP/1.1\r\n"), "got: {s:?}");
        assert!(s.ends_with("\r\n\r\n"));
    }

    // ---- Phase 1: parse_read --------------------------------------------

    #[test]
    fn parse_read_origin_form() {
        let mut p = H1ReqParser::new(H1_PARSE_DEFAULT_MAX_LINE_LEN);
        let input = b"GET /path?q=1 HTTP/1.1\r\nHost: h.test\r\nX-A: 1\r\n\r\n";
        let n = p.parse_read(input, None, None, H1_PARSE_OPT_NONE).unwrap();
        assert_eq!(n, input.len());
        assert!(p.done());
        let req = p.req().unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path.as_deref(), Some("/path?q=1"));
        assert_eq!(req.scheme, None);
        assert_eq!(req.headers.get("Host"), Some("h.test"));
        assert_eq!(req.headers.get("X-A"), Some("1"));
    }

    #[test]
    fn parse_read_absolute_form() {
        let mut p = H1ReqParser::new(H1_PARSE_DEFAULT_MAX_LINE_LEN);
        let input = b"GET http://host.test/p?q=1 HTTP/1.1\r\n\r\n";
        p.parse_read(input, None, None, H1_PARSE_OPT_NONE).unwrap();
        assert!(p.done());
        let req = p.req().unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.scheme.as_deref(), Some("http"));
        assert_eq!(req.authority.as_deref(), Some("host.test"));
        assert_eq!(req.path.as_deref(), Some("/p?q=1"));
    }

    #[test]
    fn parse_read_connect_authority_form() {
        let mut p = H1ReqParser::new(H1_PARSE_DEFAULT_MAX_LINE_LEN);
        let input = b"CONNECT host.test:443 HTTP/1.1\r\n\r\n";
        p.parse_read(input, None, None, H1_PARSE_OPT_NONE).unwrap();
        assert!(p.done());
        let req = p.req().unwrap();
        assert_eq!(req.method, "CONNECT");
        assert_eq!(req.authority.as_deref(), Some("host.test:443"));
        assert_eq!(req.path, None);
        assert_eq!(req.scheme, None);
    }

    #[test]
    fn parse_read_asterisk_form() {
        let mut p = H1ReqParser::new(H1_PARSE_DEFAULT_MAX_LINE_LEN);
        let input = b"OPTIONS * HTTP/1.1\r\n\r\n";
        p.parse_read(input, None, None, H1_PARSE_OPT_NONE).unwrap();
        assert!(p.done());
        let req = p.req().unwrap();
        assert_eq!(req.method, "OPTIONS");
        assert_eq!(req.path.as_deref(), Some("*"));
    }

    #[test]
    fn parse_read_scheme_default_applied() {
        let mut p = H1ReqParser::new(H1_PARSE_DEFAULT_MAX_LINE_LEN);
        let input = b"GET /x HTTP/1.1\r\n\r\n";
        p.parse_read(input, Some("https"), None, H1_PARSE_OPT_NONE)
            .unwrap();
        let req = p.req().unwrap();
        // Origin-form target has no scheme, so the default is applied.
        assert_eq!(req.scheme.as_deref(), Some("https"));
    }

    #[test]
    fn parse_read_strict_requires_crlf() {
        let mut p = H1ReqParser::new(H1_PARSE_DEFAULT_MAX_LINE_LEN);
        // Bare LF (no CR) under STRICT is rejected.
        let input = b"GET /x HTTP/1.1\n";
        let err = p
            .parse_read(input, None, None, H1_PARSE_OPT_STRICT)
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::UrlMalformat);
    }

    #[test]
    fn parse_read_lenient_accepts_bare_lf() {
        let mut p = H1ReqParser::new(H1_PARSE_DEFAULT_MAX_LINE_LEN);
        // Lenient mode tolerates bare-LF line endings.
        let input = b"GET /x HTTP/1.1\nHost: h\n\n";
        p.parse_read(input, None, None, H1_PARSE_OPT_NONE).unwrap();
        assert!(p.done());
        assert_eq!(p.req().unwrap().path.as_deref(), Some("/x"));
        assert_eq!(p.req().unwrap().headers.get("Host"), Some("h"));
    }

    #[test]
    fn parse_read_multi_buffer_across_line_boundary() {
        let mut p = H1ReqParser::new(H1_PARSE_DEFAULT_MAX_LINE_LEN);
        // Feed the request split in the middle of the request line.
        let n1 = p
            .parse_read(b"GET /spl", None, None, H1_PARSE_OPT_NONE)
            .unwrap();
        assert_eq!(n1, 8);
        assert!(!p.done());
        assert_eq!(p.scratch_len(), 8); // buffered partial line
        let rest = b"it HTTP/1.1\r\nHost: h\r\n\r\n";
        let n2 = p.parse_read(rest, None, None, H1_PARSE_OPT_NONE).unwrap();
        assert_eq!(n2, rest.len());
        assert!(p.done());
        let req = p.req().unwrap();
        assert_eq!(req.path.as_deref(), Some("/split"));
        assert_eq!(req.headers.get("Host"), Some("h"));
    }

    #[test]
    fn parse_read_custom_method() {
        let mut p = H1ReqParser::new(H1_PARSE_DEFAULT_MAX_LINE_LEN);
        // A custom method whose name is matched as a prefix.
        let input = b"PROPFIND /dav HTTP/1.1\r\n\r\n";
        p.parse_read(input, None, Some("PROPFIND"), H1_PARSE_OPT_NONE)
            .unwrap();
        assert_eq!(p.req().unwrap().method, "PROPFIND");
        assert_eq!(p.req().unwrap().path.as_deref(), Some("/dav"));
    }

    #[test]
    fn parse_read_missing_colon_header_is_error() {
        let mut p = H1ReqParser::new(H1_PARSE_DEFAULT_MAX_LINE_LEN);
        let input = b"GET / HTTP/1.1\r\nBadHeaderNoColon\r\n\r\n";
        let err = p
            .parse_read(input, None, None, H1_PARSE_OPT_NONE)
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
    }

    // ---- Phase 2: keep-alive decision -----------------------------------

    #[test]
    fn keepalive_decision_matches_curl() {
        let empty = http::HeaderMap::new();
        // HTTP/1.1 defaults to reuse when the request allowed it.
        assert!(response_keep_alive(1, &empty, true));
        assert!(!response_keep_alive(1, &empty, false));

        let mut closed = http::HeaderMap::new();
        closed.insert(http::header::CONNECTION, "close".parse().unwrap());
        assert!(!response_keep_alive(1, &closed, true));

        // HTTP/1.0 defaults to close unless keep-alive is explicit.
        let empty10 = http::HeaderMap::new();
        assert!(!response_keep_alive(0, &empty10, true));
        let mut keep10 = http::HeaderMap::new();
        keep10.insert(http::header::CONNECTION, "keep-alive".parse().unwrap());
        assert!(response_keep_alive(0, &keep10, true));
    }

    #[test]
    fn request_target_forms() {
        let opt = HttpReqData::make("OPTIONS", None, None, Some("*"));
        assert_eq!(request_target(&opt), "*");

        let connect = HttpReqData::make("CONNECT", None, Some("h:443"), None);
        assert_eq!(request_target(&connect), "h:443");

        let origin = HttpReqData::make("GET", None, Some("h"), Some("/a?b=1"));
        assert_eq!(request_target(&origin), "/a?b=1");

        let no_path = HttpReqData::make("GET", None, Some("h"), None);
        assert_eq!(request_target(&no_path), "/");
    }

    // ---- Phase 2: hyper transfer engine ---------------------------------

    #[tokio::test]
    async fn h1_get_simple() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let req = read_request(&mut sock).await;
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Srv: yes\r\n\r\nhello")
                .await
                .unwrap();
            req
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let reqdata = HttpReqData::make("GET", None, Some("host.test"), Some("/path"));
        let mut body: Vec<u8> = Vec::new();
        let (resp, reusable) = h1_exchange(
            TokioIo::new(stream),
            &reqdata,
            1,
            RequestBody::Empty,
            true,
            false,
            |d: &[u8]| -> Result<()> {
                body.extend_from_slice(d);
                Ok(())
            },
        )
        .await
        .unwrap();

        let captured = srv.await.unwrap();
        assert!(
            captured.starts_with(b"GET /path HTTP/1.1\r\n"),
            "request line: {:?}",
            String::from_utf8_lossy(&captured)
        );
        assert!(ci_pos(&captured, "host: host.test").is_some());
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.get("x-srv"), Some("yes"));
        assert_eq!(body, b"hello");
        assert!(reusable); // no Connection: close on an HTTP/1.1 response
    }

    #[tokio::test]
    async fn h1_post_content_length() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let req = read_request(&mut sock).await;
            sock.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nOK")
                .await
                .unwrap();
            req
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let reqdata = HttpReqData::make("POST", None, Some("host.test"), Some("/submit"));
        let mut body: Vec<u8> = Vec::new();
        let (resp, _) = h1_exchange(
            TokioIo::new(stream),
            &reqdata,
            1,
            RequestBody::Sized(b"payload!".to_vec()),
            true,
            false,
            |d: &[u8]| -> Result<()> {
                body.extend_from_slice(d);
                Ok(())
            },
        )
        .await
        .unwrap();

        let captured = srv.await.unwrap();
        assert!(captured.starts_with(b"POST /submit HTTP/1.1\r\n"));
        // hyper sets Content-Length from the sized body's exact size hint.
        assert!(ci_pos(&captured, "content-length: 8").is_some());
        assert!(captured.ends_with(b"payload!"));
        assert_eq!(resp.status, 201);
        assert_eq!(body, b"OK");
    }

    #[tokio::test]
    async fn h1_chunked_response_decoded() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _ = read_request(&mut sock).await;
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                  5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
            )
            .await
            .unwrap();
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let reqdata = HttpReqData::make("GET", None, Some("host.test"), Some("/stream"));
        let mut body: Vec<u8> = Vec::new();
        let (resp, _) = h1_exchange(
            TokioIo::new(stream),
            &reqdata,
            1,
            RequestBody::Empty,
            true,
            false,
            |d: &[u8]| -> Result<()> {
                body.extend_from_slice(d);
                Ok(())
            },
        )
        .await
        .unwrap();

        srv.await.unwrap();
        assert_eq!(resp.status, 200);
        // hyper decodes the chunked framing transparently.
        assert_eq!(body, b"hello world");
    }

    #[tokio::test]
    async fn h1_header_order_preserved() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let req = read_request(&mut sock).await;
            sock.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            req
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut reqdata = HttpReqData::make("GET", None, Some("host.test"), Some("/h"));
        reqdata.headers.add("X-Alpha", "1");
        reqdata.headers.add("X-Bravo", "2");
        reqdata.headers.add("X-Charlie", "3");
        let mut body: Vec<u8> = Vec::new();
        let (resp, _) = h1_exchange(
            TokioIo::new(stream),
            &reqdata,
            1,
            RequestBody::Empty,
            true,
            false,
            |d: &[u8]| -> Result<()> {
                body.extend_from_slice(d);
                Ok(())
            },
        )
        .await
        .unwrap();

        let captured = srv.await.unwrap();
        let a = ci_pos(&captured, "x-alpha").expect("x-alpha present");
        let b = ci_pos(&captured, "x-bravo").expect("x-bravo present");
        let c = ci_pos(&captured, "x-charlie").expect("x-charlie present");
        assert!(a < b && b < c, "header order not preserved: {a} {b} {c}");
        assert_eq!(resp.status, 204);
    }

    #[tokio::test]
    async fn h1_accepts_response_headers_above_hyper_default() {
        // Regression for the response-header COUNT ceiling (QA F3-H1-001).
        // hyper's parser defaults to 100 headers; curl accepts up to
        // MAX_HTTP_RESP_HEADER_COUNT (5000). A response with 200 header lines —
        // ordinary yet above hyper's default — must be parsed successfully,
        // proving `h1_exchange` raised the ceiling. Before the fix this response
        // was rejected outright.
        const N: usize = 200;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _ = read_request(&mut sock).await;
            let mut resp = String::from("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n");
            for i in 0..N {
                resp.push_str(&format!("X-H-{i:04}: v\r\n"));
            }
            resp.push_str("\r\nOK");
            sock.write_all(resp.as_bytes()).await.unwrap();
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let reqdata = HttpReqData::make("GET", None, Some("host.test"), Some("/many"));
        let mut body: Vec<u8> = Vec::new();
        let (resp, _) = h1_exchange(
            TokioIo::new(stream),
            &reqdata,
            1,
            RequestBody::Empty,
            true,
            false,
            |d: &[u8]| -> Result<()> {
                body.extend_from_slice(d);
                Ok(())
            },
        )
        .await
        .unwrap();

        srv.await.unwrap();
        assert_eq!(resp.status, 200);
        // The last custom header (well past the old 100 limit) was retained.
        assert_eq!(resp.headers.get("x-h-0199"), Some("v"));
        assert_eq!(body, b"OK");
    }

    // ---- Phase 2: perform() end-to-end over a real FilterChain ----------

    #[tokio::test]
    async fn perform_end_to_end_get_over_filter_chain() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let req = read_request(&mut sock).await;
            sock.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let _ = sock.shutdown().await;
            req
        });

        // Connect the client socket, then wrap it in a mock leaf filter so that
        // `perform` drives a real `FilterChain` (built from whitelisted types).
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut chain = FilterChain::new(FIRSTSOCKET);
        chain.add(Box::new(MockTcpFilter {
            stream: Some(stream),
        }));
        let mut conn = Connection::new(Scheme::new("http", 80), "127.0.0.1", addr.port());
        conn.cfilter[FIRSTSOCKET] = Some(chain);

        let reqdata = HttpReqData::make("GET", None, Some("127.0.0.1"), Some("/e2e"));
        let mut body: Vec<u8> = Vec::new();
        let resp = perform(
            &mut conn,
            reqdata,
            1,
            RequestBody::Empty,
            false,
            |d: &[u8]| -> Result<()> {
                body.extend_from_slice(d);
                Ok(())
            },
        )
        .await
        .unwrap();

        let captured = srv.await.unwrap();
        assert!(captured.starts_with(b"GET /e2e HTTP/1.1\r\n"));
        assert_eq!(resp.status, 204);
        assert!(body.is_empty());
        // `Connection: close` => not reusable => the chain is closed.
        assert!(
            conn.cfilter[FIRSTSOCKET]
                .as_ref()
                .is_some_and(|c| !c.is_connected()),
            "chain should be closed after a Connection: close response"
        );
    }
}
