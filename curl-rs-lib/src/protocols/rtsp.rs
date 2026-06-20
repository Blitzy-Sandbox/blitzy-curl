//! RTSP (Real Time Streaming Protocol, RFC 2326) scheme handler — the
//! idiomatic-Rust analog of curl's `lib/rtsp.c`.
//!
//! RTSP is an "HTTP-shaped" text protocol: requests look like
//! `METHOD <uri> RTSP/1.0\r\n<headers>\r\n[body]` and responses look like
//! `RTSP/1.0 <code> <reason>\r\n<headers>\r\n[body]`, so the request/response
//! machinery deliberately mirrors HTTP. The distinctive parts this module
//! owns are:
//!
//! * the mandatory monotonic **`CSeq`** sequence number, auto-incremented per
//!   request and validated against the response (a mismatch is
//!   [`CurlError::RtspCseqError`]);
//! * the **`Session`** header (learned from the first response, then enforced)
//!   and the **`Transport`** header (required for `SETUP`);
//! * **interleaved binary RTP** framing on the control connection — frames of
//!   the form `'$' <channel:u8> <length:u16 big-endian> <payload>` are
//!   demultiplexed out of the byte stream and routed to the interleave sink,
//!   exactly as curl's `rtsp_filter_rtp` does.
//!
//! The control connection is reused across method requests
//! ([`crate::conn::PROTOPT_NONE`]-style reuse via `PROTOPT_CONN_REUSE` on the
//! [`SCHEME_RTSP`] descriptor).
//!
//! C ORACLE (read-only reference, never modified): `lib/rtsp.c`.
//!
//! This module contains **zero `unsafe`**; the crate root applies
//! `#![forbid(unsafe_code)]` and it is *not* re-declared here (it is inherited).

use std::ffi::CStr;
use std::sync::Mutex;

use crate::conn::{
    BoxFuture, Connection, Curl_conn_is_alive, Curl_conn_recv, Curl_conn_send, FIRSTSOCKET,
};
use crate::easy::Easy;
use crate::error::{CurlError, Result};
use crate::protocols::{
    connect_network_scheme, Protocol, ProtocolTransfer, Scheme, TransferDirection, SCHEME_RTSP,
};
use crate::transfer::{
    ClientWriteType, ClientWriter, ReadCallback, ReadStep, UploadReader, WriteCallbacks,
};
// Dependency justification: `StrId` lives in `crate::setopt`, which is outside
// this file's `depends_on_files` whitelist. Reading the RTSP string options
// (`CURLOPT_RTSP_STREAM_URI` / `_SESSION_ID` / `_TRANSPORT`, and the shared
// `CURLOPT_RANGE` / `_REFERER` / `_USERAGENT` / `_ACCEPT_ENCODING`) is only
// possible through the public getter `UserDefined::str(StrId)` — the matching
// setter is private and neither `Easy` nor `easy.rs` re-exports `StrId`. This is
// the minimal, unavoidable cross-module name needed to reproduce the C behavior.
use crate::setopt::StrId;
use crate::util::dynbuf::{DynBuf, DYN_RTSP_REQ_HEADER};
use crate::util::sendf::{failf, infof};

// ===========================================================================
// Request-method constants (C `Curl_RtspReq`, lib/urldata.h / include/curl/curl.h)
//
// These are kept as raw `u8` values rather than a fielded enum *on purpose*:
// `lib/rtsp.c` performs two parity-critical bitwise tests that treat the request
// id as a bit pattern (see `session_id_required` and `range_applies` below), and
// reproducing them faithfully requires the exact integer values.
// ===========================================================================

/// `RTSPREQ_NONE` — no request configured (invalid for `do_it`).
const RTSPREQ_NONE: u8 = 0;
/// `RTSPREQ_OPTIONS` — `OPTIONS`.
const RTSPREQ_OPTIONS: u8 = 1;
/// `RTSPREQ_DESCRIBE` — `DESCRIBE` (carries a response body).
const RTSPREQ_DESCRIBE: u8 = 2;
/// `RTSPREQ_ANNOUNCE` — `ANNOUNCE` (carries a request body).
const RTSPREQ_ANNOUNCE: u8 = 3;
/// `RTSPREQ_SETUP` — `SETUP` (requires a `Transport` header).
const RTSPREQ_SETUP: u8 = 4;
/// `RTSPREQ_PLAY` — `PLAY`.
const RTSPREQ_PLAY: u8 = 5;
/// `RTSPREQ_PAUSE` — `PAUSE`.
const RTSPREQ_PAUSE: u8 = 6;
/// `RTSPREQ_TEARDOWN` — `TEARDOWN`.
const RTSPREQ_TEARDOWN: u8 = 7;
/// `RTSPREQ_GET_PARAMETER` — `GET_PARAMETER` (empty form is a heartbeat).
const RTSPREQ_GET_PARAMETER: u8 = 8;
/// `RTSPREQ_SET_PARAMETER` — `SET_PARAMETER` (carries a request body).
const RTSPREQ_SET_PARAMETER: u8 = 9;
/// `RTSPREQ_RECORD` — `RECORD`.
const RTSPREQ_RECORD: u8 = 10;
/// `RTSPREQ_RECEIVE` — pseudo-request: read interleaved RTP, send nothing.
const RTSPREQ_RECEIVE: u8 = 11;
/// `RTSPREQ_LAST` — one past the last valid request id (invalid sentinel).
const RTSPREQ_LAST: u8 = 12;

// ===========================================================================
// Connection-check / connection-result bitsets (C lib/urldata.h, L560-565).
// Not defined elsewhere in the Rust tree yet, so declared locally.
// ===========================================================================

/// `CONNCHECK_ISDEAD` — caller requests a liveness probe of the connection.
const CONNCHECK_ISDEAD: u32 = 1 << 0;
/// `CONNRESULT_DEAD` — the connection was found dead.
const CONNRESULT_DEAD: u32 = 1 << 0;

// ===========================================================================
// RTP interleave framing constants (C lib/rtsp.c).
// ===========================================================================

/// Length of the interleave frame header: `'$'` + channel + 2-byte length.
const RTP_HEADER_LEN: usize = 4;
/// Number of bytes in the 256-bit interleaved-channel bitmask (`256 / 8`).
const CHANNEL_MASK_LEN: usize = 32;
/// Upper bound on a buffered RTP message (C `MAX_RTP_BUFFERSIZE`). A 2-byte
/// length field caps a real frame at `65535 + 4`, well under this ceiling; it is
/// retained for parity and asserted against while accumulating.
const MAX_RTP_BUFFERSIZE: usize = 1_000_000;
/// Size of the per-call network read buffer used in `RECEIVE` mode.
const RTP_RECV_CHUNK: usize = 16 * 1024;
/// The interleave magic byte that introduces an RTP frame.
const RTP_MAGIC: u8 = b'$';

/// Extract the 2-byte big-endian payload length from a buffered frame header.
///
/// Mirrors curl's `RTP_PKT_LENGTH(p)` = `(p[2] << 8) | p[3]`, where `p` points
/// at the buffered frame (`p[0]` = `'$'`, `p[1]` = channel, `p[2..4]` = length).
#[inline]
fn rtp_pkt_length(hdr: &[u8]) -> usize {
    ((hdr[2] as usize) << 8) | (hdr[3] as usize)
}

// ===========================================================================
// RTP demux state machine types.
// ===========================================================================

/// The interleaved-RTP parser state (C `enum rtp_parse_st`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum RtpParseState {
    /// Scanning for the next `'$'`; intervening bytes are body/junk.
    #[default]
    Skip,
    /// Read the 1-byte channel that follows `'$'`.
    Channel,
    /// Read the 2 big-endian length bytes.
    Len,
    /// Accumulate the payload until the full frame is buffered.
    Data,
}

/// One unit of output produced by [`filter_rtp`]: either body bytes destined for
/// the client writer, or a complete interleaved RTP frame.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RtpOutput {
    /// Junk/body bytes that appeared outside any RTP frame.
    Body(Vec<u8>),
    /// A complete interleaved frame, including its 4-byte `'$' chan len` header
    /// (curl writes the whole buffered frame to the interleave callback).
    Interleaved {
        /// The interleave channel number (`hdr[1]`).
        channel: u8,
        /// The full frame bytes (`RTP_HEADER_LEN + payload`).
        frame: Vec<u8>,
    },
}

/// Per-connection RTP demux state (C `struct rtsp_conn`).
#[derive(Debug)]
struct RtspConn {
    /// Accumulator for a partially-received interleaved frame (C `rtspc->buf`,
    /// capped at [`MAX_RTP_BUFFERSIZE`]).
    buf: Vec<u8>,
    /// Last validated channel number, or `-1` when none is in progress.
    rtp_channel: i32,
    /// Expected total length of the in-progress frame once the header is known.
    rtp_len: usize,
    /// Current parser state.
    state: RtpParseState,
    /// Whether response *header* parsing is currently in progress (RTP demux is
    /// suspended while headers are being read).
    in_header: bool,
}

impl Default for RtspConn {
    fn default() -> Self {
        Self {
            buf: Vec::new(),
            // C `rtsp_connect` initializes rtp_channel to -1.
            rtp_channel: -1,
            rtp_len: 0,
            state: RtpParseState::Skip,
            in_header: false,
        }
    }
}

/// Per-transfer CSeq bookkeeping (C `struct RTSP`).
#[derive(Debug, Clone, Copy, Default)]
struct RtspState {
    /// The `CSeq` value sent on the current request.
    cseq_sent: u32,
    /// The `CSeq` value parsed from the response.
    cseq_recv: u32,
}

/// All mutable RTSP session state, guarded by a single mutex on
/// [`RtspProtocol`]. Bundling it keeps the lock scope obvious: lock briefly to
/// read/update, then drop the guard before any `.await`.
#[derive(Debug, Default)]
struct RtspSession {
    /// CSeq send/receive tracking.
    state: RtspState,
    /// RTP demux state.
    conn: RtspConn,
    /// Bitmask of valid interleaved channels (bit `c` set ⇒ channel `c` valid).
    channel_mask: [u8; CHANNEL_MASK_LEN],
    /// The learned/active RTSP session id (from the first `Session:` response).
    session_id: Option<String>,
    /// Demuxed body bytes awaiting delivery to the client writer.
    pending_body: Vec<u8>,
    /// Demuxed interleaved frames awaiting delivery: `(channel, full frame)`.
    pending_rtp: Vec<(u8, Vec<u8>)>,
}

// ===========================================================================
// Diagnostic context + request parameters.
// ===========================================================================

/// The safe stand-in for curl's `struct Curl_easy *data` at `infof`/`failf`
/// call sites: just the verbose flag and the first-write-wins error-buffer slot.
///
/// curl threads `data` everywhere partly to reach these two diagnostic
/// channels; isolating them keeps the pure request/response logic free of the
/// full handle while still emitting faithful messages.
struct RtspDiag<'a> {
    /// Whether informational (`infof`) messages should be surfaced.
    verbose: bool,
    /// The error-message sink (`failf`), first write wins.
    errbuf: &'a mut Option<String>,
}

/// All the resolved inputs needed to format an RTSP request, gathered from the
/// easy handle's options by the caller. Passed as one struct so the assembler
/// stays a single, directly-testable function.
struct RtspReqParams<'a> {
    /// The request method id (`RTSPREQ_*`).
    rtspreq: u8,
    /// The Request-URI (already defaulted to `"*"` when unset).
    stream_uri: &'a str,
    /// The `CSeq` value for this request.
    cseq: u32,
    /// The active session id, if any.
    session_id: Option<&'a str>,
    /// The `CURLOPT_RTSP_TRANSPORT` value (emitted as a `Transport:` line for
    /// `SETUP` when no custom `Transport` header is present).
    transport: Option<&'a str>,
    /// `CURLOPT_ACCEPT_ENCODING` value (only used for `DESCRIBE`).
    accept_encoding: Option<&'a str>,
    /// `CURLOPT_RANGE` value (only supplied when `use_range` is set).
    range: Option<&'a str>,
    /// `CURLOPT_REFERER` value.
    referer: Option<&'a str>,
    /// `CURLOPT_USERAGENT` value.
    user_agent: Option<&'a str>,
    /// User-supplied custom request headers (`CURLOPT_HTTPHEADER`).
    custom_headers: &'a [&'a CStr],
    /// Request body length, if the method carries a body.
    body_len: Option<u64>,
}

// ===========================================================================
// Pure request-method helpers.
// ===========================================================================

/// Map a request id to its on-the-wire method name, or `None` for an invalid id.
///
/// `RECEIVE` maps to the empty string: it sends no request and only reads
/// interleaved RTP (the caller short-circuits before formatting), mirroring
/// curl's `p_request = ""`.
fn rtsp_method_name(rtspreq: u8) -> Option<&'static str> {
    Some(match rtspreq {
        RTSPREQ_NONE => return None,
        RTSPREQ_OPTIONS => "OPTIONS",
        RTSPREQ_DESCRIBE => "DESCRIBE",
        RTSPREQ_ANNOUNCE => "ANNOUNCE",
        RTSPREQ_SETUP => "SETUP",
        RTSPREQ_PLAY => "PLAY",
        RTSPREQ_PAUSE => "PAUSE",
        RTSPREQ_TEARDOWN => "TEARDOWN",
        RTSPREQ_GET_PARAMETER => "GET_PARAMETER",
        RTSPREQ_SET_PARAMETER => "SET_PARAMETER",
        RTSPREQ_RECORD => "RECORD",
        RTSPREQ_RECEIVE => "",
        RTSPREQ_LAST => return None,
        _ => return None,
    })
}

/// Whether the method's default form carries a body (request or response) — the
/// set for which curl clears `no_body` in the `do` switch
/// (`DESCRIBE`/`GET_PARAMETER`/`RECEIVE`).
fn rtsp_req_has_body(rtspreq: u8) -> bool {
    matches!(
        rtspreq,
        RTSPREQ_DESCRIBE | RTSPREQ_GET_PARAMETER | RTSPREQ_RECEIVE
    )
}

/// Whether a session id is required for this request.
///
/// PARITY-CRITICAL bitwise test (C `rtsp.c`): curl computes
/// `rtspreq & ~(RTSPREQ_OPTIONS | RTSPREQ_DESCRIBE | RTSPREQ_SETUP)`, i.e.
/// `rtspreq & ~0x07`, treating the request ids as a bit pattern. The net effect
/// is that a session id is required only when a bit outside the low three is set
/// — `GET_PARAMETER`(8), `SET_PARAMETER`(9), `RECORD`(10) (and the
/// already-handled `RECEIVE`) — and NOT for
/// `OPTIONS`/`DESCRIBE`/`ANNOUNCE`/`SETUP`/`PLAY`/`PAUSE`/`TEARDOWN`. Reproduced
/// exactly rather than as a clean per-method table.
fn session_id_required(rtspreq: u8) -> bool {
    (rtspreq & !(RTSPREQ_OPTIONS | RTSPREQ_DESCRIBE | RTSPREQ_SETUP)) != 0
}

/// Whether the `Range` header applies to this request.
///
/// PARITY-CRITICAL bitwise test (C `rtsp.c`): curl computes
/// `rtspreq & (RTSPREQ_PLAY | RTSPREQ_PAUSE | RTSPREQ_RECORD)` = `rtspreq & 0x0F`
/// (because `5 | 6 | 10 == 15`). Although the source comment says "only PLAY,
/// PAUSE, RECORD", the actual mask `0x0F` matches every valid request id, so the
/// genuine limiter is whether `CURLOPT_RANGE` (`use_range`) was set. Reproduced
/// exactly for byte-for-byte parity.
fn range_applies(rtspreq: u8) -> bool {
    (rtspreq & (RTSPREQ_PLAY | RTSPREQ_PAUSE | RTSPREQ_RECORD)) != 0
}

/// Case-insensitive `"<name>:"`-prefix match against a single custom header
/// (curl's `Curl_checkheaders` predicate), after skipping leading blanks.
fn header_matches(header: &CStr, name: &str) -> bool {
    let Ok(s) = header.to_str() else {
        return false;
    };
    let s = s.trim_start_matches([' ', '\t']);
    s.as_bytes().get(name.len()) == Some(&b':')
        && s.get(..name.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(name))
}

/// Whether any custom header matches `name` (curl's `Curl_checkheaders`).
fn has_custom_header(headers: &[&CStr], name: &str) -> bool {
    headers.iter().any(|h| header_matches(h, name))
}

// ===========================================================================
// Request assembly (C `rtsp_do` + `rtsp_setup_body`).
// ===========================================================================

/// Format a complete RTSP request header block into a freshly-allocated buffer,
/// reproducing curl's `rtsp_do` assembly order and `rtsp_setup_body` content
/// headers.
///
/// The buffer is capped at [`DYN_RTSP_REQ_HEADER`] (64 KiB), so a pathologically
/// large header set fails with [`CurlError::TooLarge`], exactly as curl's
/// `curlx_dyn_*` would. Returns the assembled bytes (request line through the
/// terminating blank line); the body itself is streamed separately by the
/// caller.
fn build_rtsp_request(p: &RtspReqParams, diag: &mut RtspDiag) -> Result<Vec<u8>> {
    // Resolve the method name; an unknown id is a usage error.
    let method = match rtsp_method_name(p.rtspreq) {
        Some(m) => m,
        None => {
            failf(diag.errbuf, "Got invalid RTSP request");
            return Err(CurlError::BadFunctionArgument);
        }
    };

    // A session id is mandatory for some methods (parity-critical bitwise test).
    if p.session_id.is_none() && session_id_required(p.rtspreq) {
        failf(
            diag.errbuf,
            &format!("Refusing to issue an RTSP request [{method}] without a session ID."),
        );
        return Err(CurlError::BadFunctionArgument);
    }

    // SETUP must carry a Transport (custom header or CURLOPT_RTSP_TRANSPORT).
    let custom_transport = has_custom_header(p.custom_headers, "Transport");
    if p.rtspreq == RTSPREQ_SETUP && !custom_transport && p.transport.is_none() {
        failf(
            diag.errbuf,
            "Refusing to issue an RTSP SETUP without a Transport: header.",
        );
        return Err(CurlError::BadFunctionArgument);
    }

    // CSeq and Session are owned by this layer and cannot be set as custom headers.
    if has_custom_header(p.custom_headers, "CSeq") {
        failf(diag.errbuf, "CSeq cannot be set as a custom header.");
        return Err(CurlError::RtspCseqError);
    }
    if has_custom_header(p.custom_headers, "Session") {
        failf(diag.errbuf, "Session ID cannot be set as a custom header.");
        return Err(CurlError::BadFunctionArgument);
    }

    let mut req = DynBuf::new(DYN_RTSP_REQ_HEADER);

    // Request line + mandatory CSeq.
    let uri = p.stream_uri;
    let cseq = p.cseq;
    req.curlx_dyn_add(&format!("{method} {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n"))?;

    // Session header (kept unformatted to make response comparison trivial).
    if let Some(sid) = p.session_id {
        req.curlx_dyn_add(&format!("Session: {sid}\r\n"))?;
    }

    // Transport (SETUP, option-derived only — a custom Transport flows through
    // the custom-header append below, so this never double-emits).
    if p.rtspreq == RTSPREQ_SETUP && !custom_transport {
        if let Some(t) = p.transport {
            req.curlx_dyn_add(&format!("Transport: {t}\r\n"))?;
        }
    }

    // Accept / Accept-Encoding for DESCRIBE.
    if p.rtspreq == RTSPREQ_DESCRIBE {
        if !has_custom_header(p.custom_headers, "Accept") {
            req.curlx_dyn_add("Accept: application/sdp\r\n")?;
        }
        if let Some(enc) = p.accept_encoding {
            if !has_custom_header(p.custom_headers, "Accept-Encoding") {
                req.curlx_dyn_add(&format!("Accept-Encoding: {enc}\r\n"))?;
            }
        }
    }

    // Range — gated by the (parity-critical) bitwise method test and the absence
    // of a custom Range header. The caller only supplies `range` when
    // CURLOPT_RANGE (curl's `use_range`) was set.
    if let Some(r) = p.range {
        if range_applies(p.rtspreq) && !has_custom_header(p.custom_headers, "Range") {
            req.curlx_dyn_add(&format!("Range: {r}\r\n"))?;
        }
    }

    // Referer / User-Agent (shared HTTP-like options).
    if let Some(rf) = p.referer {
        if !has_custom_header(p.custom_headers, "Referer") {
            req.curlx_dyn_add(&format!("Referer: {rf}\r\n"))?;
        }
    }
    if let Some(ua) = p.user_agent {
        if !has_custom_header(p.custom_headers, "User-Agent") {
            req.curlx_dyn_add(&format!("User-Agent: {ua}\r\n"))?;
        }
    }

    // Custom request headers (curl's `Curl_add_custom_headers`). CSeq/Session
    // were already rejected; everything else is appended verbatim with CRLF.
    for h in p.custom_headers {
        if let Ok(line) = h.to_str() {
            let line = line.trim_end_matches(['\r', '\n']);
            if !line.is_empty() {
                req.curlx_dyn_add(line)?;
                req.curlx_dyn_add("\r\n")?;
            }
        }
    }

    // Body content headers (C `rtsp_setup_body`): only for body-bearing methods
    // with non-empty content.
    if let Some(clen) = p.body_len.filter(|&c| c > 0) {
        if !has_custom_header(p.custom_headers, "Content-Length") {
            req.curlx_dyn_add(&format!("Content-Length: {clen}\r\n"))?;
        }
        if !has_custom_header(p.custom_headers, "Content-Type") {
            match p.rtspreq {
                RTSPREQ_SET_PARAMETER | RTSPREQ_GET_PARAMETER => {
                    req.curlx_dyn_add("Content-Type: text/parameters\r\n")?;
                }
                RTSPREQ_ANNOUNCE => {
                    req.curlx_dyn_add("Content-Type: application/sdp\r\n")?;
                }
                _ => {}
            }
        }
    }

    // Terminating blank line.
    req.curlx_dyn_add("\r\n")?;

    Ok(req.curlx_dyn_take())
}

// ===========================================================================
// Response / header parsing (C `Curl_rtsp_parseheader` + `rtsp_parse_transport`).
// ===========================================================================

/// A parsed RTSP status line (`RTSP/<major>.<minor> <code> [reason]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtspStatus {
    /// The major protocol version (`1` for `RTSP/1.0`).
    pub http_major: u8,
    /// The minor protocol version (`0` for `RTSP/1.0`).
    pub http_minor: u8,
    /// The numeric status code (e.g. `200`).
    pub status_code: u16,
}

/// Parse an RTSP status line, returning `None` if it is not a well-formed
/// `RTSP/<major>.<minor> <code> …` line.
///
/// RTSP status lines are HTTP-shaped; this is the RTSP analog of curl's status
/// parsing and is exposed as a utility for response handling and tests.
#[must_use]
pub fn parse_status_line(line: &str) -> Option<RtspStatus> {
    let line = line.trim();
    let mut it = line.strip_prefix("RTSP/")?.split_whitespace();
    let ver = it.next()?;
    let code_str = it.next()?;
    let (maj, min) = ver.split_once('.')?;
    Some(RtspStatus {
        http_major: maj.parse().ok()?,
        http_minor: min.parse().ok()?,
        status_code: code_str.parse().ok()?,
    })
}

/// The outcome of parsing a `Session:` response header.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SessionOutcome {
    /// The received id matched the configured/learned id.
    Matched,
    /// No id was configured yet; this one is now learned.
    Learned(String),
}

/// Case-insensitive `"<name>:"`-prefix value extractor for a response header
/// line (curl's `checkprefix` then skip the name). `name` is given without the
/// colon; returns the remainder after the colon, or `None` on no match.
fn header_value<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let head = line.get(..name.len())?;
    if !head.eq_ignore_ascii_case(name) {
        return None;
    }
    line[name.len()..].strip_prefix(':')
}

/// Parse a `CSeq` header value (C: `curlx_str_number(.., UINT_MAX)`), reading the
/// leading run of digits. Returns [`CurlError::RtspCseqError`] when no number is
/// present or it does not fit `u32` (curl's `UINT_MAX` cap).
fn parse_cseq_value(value: &str) -> Result<u32> {
    let v = value.trim_start_matches([' ', '\t']);
    let digits: String = v.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return Err(CurlError::RtspCseqError);
    }
    digits.parse::<u32>().map_err(|_| CurlError::RtspCseqError)
}

/// Parse a `Session` header value (C `Curl_rtsp_parseheader` Session branch).
///
/// The id runs from the first non-blank character to the next whitespace/control
/// character or `';'`. A blank value is [`CurlError::RtspSessionError`]; when an
/// id is already configured/learned a mismatch is also
/// [`CurlError::RtspSessionError`]; otherwise the id is learned.
fn parse_session_value(value: &str, configured: Option<&str>) -> Result<SessionOutcome> {
    let start = value.trim_start_matches([' ', '\t']);
    if start.is_empty() {
        return Err(CurlError::RtspSessionError);
    }
    // End at the first whitespace/control char or ';' (curl: `*end > ' ' && != ';'`).
    let end = start
        .find(|c: char| c <= ' ' || c == ';')
        .unwrap_or(start.len());
    let id = &start[..end];
    match configured {
        Some(want) => {
            if want == id {
                Ok(SessionOutcome::Matched)
            } else {
                Err(CurlError::RtspSessionError)
            }
        }
        None => Ok(SessionOutcome::Learned(id.to_owned())),
    }
}

/// Parse a single channel number (0..=255) from the leading digits of `s`
/// (curl caps at 255). Returns `None` when absent or out of range.
fn parse_channel(s: &str) -> Option<u16> {
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    match digits.parse::<u32>() {
        Ok(v) if v <= 255 => Some(v as u16),
        _ => None,
    }
}

/// Apply one `interleaved=chan1[-chan2]` specifier to the channel mask (the
/// inner part of C `rtsp_parse_transport`).
fn parse_interleaved_spec(
    spec: &str,
    transport: &str,
    mask: &mut [u8; CHANNEL_MASK_LEN],
    diag: &mut RtspDiag,
) {
    let (c1s, c2s) = match spec.split_once('-') {
        Some((a, b)) => (a, Some(b)),
        None => (spec, None),
    };
    let Some(chan1) = parse_channel(c1s) else {
        infof(
            diag.verbose,
            &format!(
                "Unable to read the interleaved parameter from Transport header: [{transport}]"
            ),
        );
        return;
    };
    let chan2 = match c2s {
        // A second value that fails to parse falls back to chan1 (curl logs and
        // keeps chan2 = chan1).
        Some(b) => parse_channel(b).unwrap_or_else(|| {
            infof(
                diag.verbose,
                &format!(
                    "Unable to read the interleaved parameter from Transport header: [{transport}]"
                ),
            );
            chan1
        }),
        None => chan1,
    };
    for chan in chan1..=chan2 {
        let idx = (chan / 8) as usize;
        let off = u32::from(chan % 8);
        if let Some(byte) = mask.get_mut(idx) {
            *byte |= 1u8 << off;
        }
    }
}

/// Parse a `Transport` response header for `interleaved=` channels and record
/// them in the validity mask (C `rtsp_parse_transport`). Multiple `Transport`
/// headers accumulate into the same mask. Only the first `interleaved=`
/// parameter is processed (curl `break`s after it).
fn parse_transport_interleaved(
    transport: &str,
    mask: &mut [u8; CHANNEL_MASK_LEN],
    diag: &mut RtspDiag,
) {
    let mut rest = transport;
    loop {
        let start = rest.trim_start_matches([' ', '\t']);
        let (param, next) = match start.find(';') {
            Some(i) => (&start[..i], Some(&start[i + 1..])),
            None => (start, None),
        };
        if let Some(spec) = strip_prefix_ci(param, "interleaved=") {
            parse_interleaved_spec(spec, transport, mask, diag);
            break;
        }
        match next {
            Some(n) => rest = n,
            None => break,
        }
    }
}

/// Case-insensitive [`str::strip_prefix`] (curl's `checkprefix`).
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// The mutable targets a parsed response header updates.
struct RtspHeaderSink<'a> {
    /// CSeq tracking (the `Session`/`Transport` branches leave it untouched).
    state: &'a mut RtspState,
    /// The interleaved-channel validity mask.
    channel_mask: &'a mut [u8; CHANNEL_MASK_LEN],
    /// The learned session id (set on the first `Session:` response).
    session_id: &'a mut Option<String>,
}

/// Parse one RTSP response header line and fold it into `sink`
/// (C `Curl_rtsp_parseheader`). `configured` is the user-set
/// `CURLOPT_RTSP_SESSION_ID`, if any. Non-RTSP headers are ignored (the generic
/// header path stores them).
fn parse_rtsp_header(
    header: &str,
    sink: &mut RtspHeaderSink,
    configured: Option<&str>,
    diag: &mut RtspDiag,
) -> Result<()> {
    let trimmed = header.trim_end_matches(['\r', '\n']);

    if let Some(v) = header_value(trimmed, "CSeq") {
        let cseq = match parse_cseq_value(v) {
            Ok(c) => c,
            Err(e) => {
                failf(
                    diag.errbuf,
                    &format!("Unable to read the CSeq header: [{trimmed}]"),
                );
                return Err(e);
            }
        };
        sink.state.cseq_recv = cseq;
    } else if let Some(v) = header_value(trimmed, "Session") {
        // Compare against the user-configured id first, then any learned id.
        let want = configured.or(sink.session_id.as_deref());
        match parse_session_value(v, want) {
            Ok(SessionOutcome::Matched) => {}
            Ok(SessionOutcome::Learned(id)) => *sink.session_id = Some(id),
            Err(e) => {
                if v.trim().is_empty() {
                    failf(diag.errbuf, "Got a blank Session ID");
                } else {
                    failf(
                        diag.errbuf,
                        &format!(
                            "Got RTSP Session ID Line [{got}], but wanted ID [{want}]",
                            got = v.trim_start(),
                            want = want.unwrap_or(""),
                        ),
                    );
                }
                return Err(e);
            }
        }
    } else if let Some(v) = header_value(trimmed, "Transport") {
        parse_transport_interleaved(v, sink.channel_mask, diag);
    }

    Ok(())
}

/// Validate the response `CSeq` against the request `CSeq` (C `rtsp_done`).
///
/// Returns [`CurlError::RtspCseqError`] on a mismatch, except for `RECEIVE`
/// (which sends no request and therefore has nothing to match).
fn check_cseq(rtspreq: u8, sent: u32, recv: u32) -> Result<()> {
    if rtspreq != RTSPREQ_RECEIVE && sent != recv {
        Err(CurlError::RtspCseqError)
    } else {
        Ok(())
    }
}

// ===========================================================================
// Interleaved RTP demux (C `rtsp_filter_rtp`).
// ===========================================================================

/// Demultiplex interleaved RTP frames out of a control-connection byte stream.
///
/// This is a faithful port of curl's `rtsp_filter_rtp`. It is a resumable state
/// machine: partial frames persist in `rtspc.buf` across calls, so a frame split
/// over several network reads is reassembled correctly. Frame format on the wire
/// is `'$' <channel:u8> <length:u16 big-endian> <payload[length]>`; the total
/// buffered frame is therefore `length + RTP_HEADER_LEN` bytes.
///
/// Returns the ordered outputs ([`RtpOutput::Body`] for junk/body bytes that
/// appear between frames, [`RtpOutput::Interleaved`] for each complete frame —
/// including its 4-byte header, exactly as curl writes it) together with the
/// number of bytes consumed from `buf`. When fewer than `buf.len()` bytes are
/// consumed, the remainder is the start of the next RTSP response's headers
/// (curl's `RTSP/` look-ahead), and the caller should hand it to the header
/// parser.
///
/// * `in_body` mirrors curl's `in_body` (we are inside a known response body, so
///   the `RTSP/` next-response look-ahead is suppressed).
/// * `is_receive` is `true` for the `RECEIVE` pseudo-request (also suppresses
///   the `RTSP/` look-ahead).
fn filter_rtp(
    rtspc: &mut RtspConn,
    mask: &[u8; CHANNEL_MASK_LEN],
    buf: &[u8],
    in_body: bool,
    is_receive: bool,
) -> Result<(Vec<RtpOutput>, usize)> {
    let mut outputs: Vec<RtpOutput> = Vec::new();
    let mut consumed = 0usize;
    // Number of consecutive junk/body bytes ending just before `i`, pending flush.
    let mut skip_len = 0usize;
    let mut i = 0usize;

    'outer: while i < buf.len() {
        match rtspc.state {
            RtpParseState::Skip => {
                // Consume bytes until the next interleave marker '$'.
                while i < buf.len() && buf[i] != RTP_MAGIC {
                    if !in_body && buf[i] == b'R' && !is_receive {
                        // Could this be the start of the next RTSP response?
                        // Compare against "RTSP/" over the bytes we have (a
                        // partial prefix at a chunk boundary also matches, so we
                        // stop and wait for more data — curl's strncmp(min(blen,5))).
                        let end = core::cmp::min(buf.len(), i + 5);
                        let probe = &buf[i..end];
                        if b"RTSP/".starts_with(probe) {
                            if skip_len > 0 {
                                outputs.push(RtpOutput::Body(buf[i - skip_len..i].to_vec()));
                                skip_len = 0;
                            }
                            // Do not consume this byte; it belongs to the headers.
                            rtspc.state = RtpParseState::Skip;
                            rtspc.in_header = true;
                            break 'outer;
                        }
                    }
                    // Junk/body byte: consume without buffering.
                    consumed += 1;
                    i += 1;
                    skip_len += 1;
                }
                if i < buf.len() && buf[i] == RTP_MAGIC {
                    // Flush any junk/body that preceded this frame.
                    if skip_len > 0 {
                        outputs.push(RtpOutput::Body(buf[i - skip_len..i].to_vec()));
                        skip_len = 0;
                    }
                    rtspc.buf.push(RTP_MAGIC);
                    consumed += 1;
                    i += 1;
                    rtspc.state = RtpParseState::Channel;
                }
            }

            RtpParseState::Channel => {
                let ch = buf[i];
                let idx = (ch as usize) / 8;
                let off = u32::from(ch % 8);
                let valid = mask.get(idx).is_some_and(|b| (b & (1u8 << off)) != 0);
                if valid {
                    rtspc.rtp_channel = i32::from(ch);
                    rtspc.buf.push(ch);
                    consumed += 1;
                    i += 1;
                    rtspc.state = RtpParseState::Len;
                } else {
                    // Invalid channel: the byte is BODY data, not consumed here.
                    rtspc.state = RtpParseState::Skip;
                    if consumed == 0 {
                        // The '$' was buffered by an earlier call and cannot be
                        // un-consumed; write it directly as BODY.
                        outputs.push(RtpOutput::Body(rtspc.buf.clone()));
                    } else {
                        // Count the buffered '$' as skip and continue scanning.
                        skip_len = 1;
                    }
                    rtspc.buf.clear();
                }
            }

            RtpParseState::Len => {
                // `cur` is the buffered length BEFORE adding this byte (2 then 3).
                let cur = rtspc.buf.len();
                rtspc.buf.push(buf[i]);
                consumed += 1;
                i += 1;
                if cur != 2 {
                    // We just appended the low length byte; the header is now
                    // complete (['$', chan, hi, lo]).
                    let total = rtp_pkt_length(&rtspc.buf) + RTP_HEADER_LEN;
                    debug_assert!(
                        total <= MAX_RTP_BUFFERSIZE,
                        "RTP frame exceeds MAX_RTP_BUFFERSIZE"
                    );
                    rtspc.rtp_len = total;
                    rtspc.state = RtpParseState::Data;
                }
            }

            RtpParseState::Data => {
                let cur = rtspc.buf.len();
                let needed = rtspc.rtp_len - cur;
                let avail = buf.len() - i;
                if needed <= avail {
                    rtspc.buf.extend_from_slice(&buf[i..i + needed]);
                    consumed += needed;
                    i += needed;
                    // Parity with curl's rtp_client_write 0-length guard. The
                    // framing guarantees rtp_len >= RTP_HEADER_LEN, so this is
                    // structurally unreachable, but kept to mirror the contract.
                    if rtspc.rtp_len == 0 {
                        return Err(CurlError::WriteError);
                    }
                    let channel = rtspc.rtp_channel as u8;
                    let frame = std::mem::take(&mut rtspc.buf);
                    outputs.push(RtpOutput::Interleaved { channel, frame });
                    rtspc.state = RtpParseState::Skip;
                } else {
                    // Partial payload: buffer everything and wait for more.
                    rtspc.buf.extend_from_slice(&buf[i..]);
                    consumed += avail;
                    i += avail;
                }
            }
        }
    }

    // Flush any trailing junk/body bytes (curl's `out:` epilogue).
    if skip_len > 0 {
        outputs.push(RtpOutput::Body(buf[i - skip_len..i].to_vec()));
    }

    Ok((outputs, consumed))
}

// ===========================================================================
// The RTSP protocol handler (C `Curl_protocol_rtsp` + `Curl_scheme_rtsp`).
// ===========================================================================

/// Fold a batch of demux outputs into the session's pending buffers.
fn push_outputs(sess: &mut RtspSession, outs: Vec<RtpOutput>) {
    for o in outs {
        match o {
            RtpOutput::Body(b) => sess.pending_body.extend_from_slice(&b),
            RtpOutput::Interleaved { channel, frame } => sess.pending_rtp.push((channel, frame)),
        }
    }
}

/// Compute the request-body length for body-bearing methods, mirroring curl's
/// `rtsp_setup_body` content-length resolution (post-fields, then infile size).
/// Returns `None` for methods that never carry a body or when the body is empty.
fn rtsp_request_body_len(data: &Easy, rtspreq: u8) -> Option<u64> {
    if !matches!(
        rtspreq,
        RTSPREQ_ANNOUNCE | RTSPREQ_SET_PARAMETER | RTSPREQ_GET_PARAMETER
    ) {
        return None;
    }
    let len: u64 = if let Some(cp) = data.set.copypostfields.as_ref() {
        if data.set.postfieldsize >= 0 {
            u64::try_from(data.set.postfieldsize).unwrap_or(0)
        } else {
            cp.len() as u64
        }
    } else if data.set.postfields.is_some() && data.set.postfieldsize >= 0 {
        u64::try_from(data.set.postfieldsize).unwrap_or(0)
    } else if data.set.filesize >= 0 {
        u64::try_from(data.set.filesize).unwrap_or(0)
    } else {
        0
    };
    (len > 0).then_some(len)
}

/// The RTSP [`Protocol`] handler — the idiomatic analog of curl's
/// `Curl_protocol_rtsp` vtable bound to the `Curl_scheme_rtsp` descriptor.
///
/// All mutable session state lives behind a single [`Mutex`] so the trait's
/// `&self` methods can mutate it. The lock is only ever held for brief,
/// non-`async` critical sections — never across an `.await` — so it cannot stall
/// the async runtime.
#[derive(Debug)]
pub struct RtspProtocol {
    /// The guarded RTSP session state.
    session: Mutex<RtspSession>,
}

impl Default for RtspProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl RtspProtocol {
    /// Create a fresh RTSP handler with empty session state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            session: Mutex::new(RtspSession::default()),
        }
    }

    /// Lock the session, recovering the guard even if a previous holder panicked
    /// (no critical section here panics, so this is a belt-and-suspenders).
    fn lock(&self) -> std::sync::MutexGuard<'_, RtspSession> {
        self.session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Take the demuxed body bytes accumulated from response/interleave
    /// processing, clearing the internal buffer.
    #[must_use]
    pub fn take_pending_body(&self) -> Vec<u8> {
        std::mem::take(&mut self.lock().pending_body)
    }

    /// Take the demuxed interleaved RTP frames `(channel, frame)` accumulated so
    /// far, clearing the internal buffer. Each `frame` includes its 4-byte
    /// `'$' chan len` header, exactly as curl delivers it.
    #[must_use]
    pub fn take_pending_rtp(&self) -> Vec<(u8, Vec<u8>)> {
        std::mem::take(&mut self.lock().pending_rtp)
    }
}

impl Protocol for RtspProtocol {
    fn scheme(&self) -> &'static Scheme {
        &SCHEME_RTSP
    }

    fn setup_connection<'a>(
        &'a self,
        _data: &'a mut Easy,
        _conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // C `rtsp_setup_connection`: establish fresh per-connection RTP demux
            // state (the cross-request session id / channel mask are preserved).
            let mut sess = self.lock();
            sess.conn = RtspConn::default();
            Ok(())
        })
    }

    fn connect<'a>(
        &'a self,
        data: &'a mut Easy,
        _conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // C `rtsp_connect`: initialize the CSeq counters to 1 when unset and
            // reset the demux channel to "none".
            if data.set.rtsp_next_client_cseq == 0 {
                data.set.rtsp_next_client_cseq = 1;
            }
            if data.set.rtsp_next_server_cseq == 0 {
                data.set.rtsp_next_server_cseq = 1;
            }
            let mut sess = self.lock();
            sess.conn.rtp_channel = -1;
            Ok(())
        })
    }

    fn do_it<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<ProtocolTransfer>> {
        Box::pin(async move {
            let rtspreq = data.set.rtspreq;

            // RECEIVE: send nothing; read one chunk of interleaved data, demux it,
            // and stash the results. (C `rtsp_do` RECEIVE short-circuit.)
            if rtspreq == RTSPREQ_RECEIVE {
                let mut net = vec![0u8; RTP_RECV_CHUNK];
                let n = Curl_conn_recv(conn, FIRSTSOCKET, &mut net).await?;
                let mut sess = self.lock();
                let mask = sess.channel_mask;
                let (outs, _consumed) = filter_rtp(&mut sess.conn, &mask, &net[..n], false, true)?;
                push_outputs(&mut sess, outs);
                return Ok(ProtocolTransfer::new(TransferDirection::Download));
            }

            // Resolve the request body length (C `rtsp_setup_body`).
            let body_len = rtsp_request_body_len(data, rtspreq);

            // Snapshot/advance CSeq under a brief lock; release before building.
            let cseq = {
                let mut sess = self.lock();
                sess.state.cseq_sent = data.set.rtsp_next_client_cseq;
                sess.state.cseq_recv = 0;
                sess.state.cseq_sent
            };
            // Any session id learned from an earlier response on this connection.
            let learned = self.lock().session_id.clone();

            // Gather custom headers and option strings (immutable borrows of data).
            let custom: Vec<&CStr> = data
                .set
                .headers
                .as_ref()
                .map(|h| h.iter().collect())
                .unwrap_or_default();
            let stream_uri = data.set.str(StrId::RtspStreamUri).unwrap_or("*");
            let session_id = data.set.str(StrId::RtspSessionId).or(learned.as_deref());
            let transport = data.set.str(StrId::RtspTransport);
            let accept_encoding = data.set.str(StrId::Encoding);
            let range = data.set.str(StrId::SetRange);
            let referer = data.set.str(StrId::SetReferer);
            let user_agent = data.set.str(StrId::Useragent);

            let verbose = data.set.verbose;
            let mut errbuf: Option<String> = None;
            let mut diag = RtspDiag {
                verbose,
                errbuf: &mut errbuf,
            };
            let params = RtspReqParams {
                rtspreq,
                stream_uri,
                cseq,
                session_id,
                transport,
                accept_encoding,
                range,
                referer,
                user_agent,
                custom_headers: &custom,
                body_len,
            };
            // After this call, all immutable borrows of `data`/`learned`/`custom`
            // end (NLL), freeing `data` for the mutable CSeq bump below.
            let request = build_rtsp_request(&params, &mut diag)?;

            Curl_conn_send(conn, FIRSTSOCKET, &request, false).await?;

            // Increment the client CSeq on a successful send (C `rtsp_do`).
            data.set.rtsp_next_client_cseq = data.set.rtsp_next_client_cseq.wrapping_add(1);

            // Describe the transfer shape for the engine. A response body is
            // expected for the methods where curl clears `no_body`
            // (DESCRIBE/GET_PARAMETER), with the empty-GET_PARAMETER heartbeat
            // (no request body) reverting to no body.
            let has_req_body = body_len.is_some();
            let expects_resp_body =
                (has_req_body || rtspreq != RTSPREQ_GET_PARAMETER) && rtsp_req_has_body(rtspreq);
            let direction = match (has_req_body, expects_resp_body) {
                (true, true) => TransferDirection::Bidirectional,
                (true, false) => TransferDirection::Upload,
                (false, true) => TransferDirection::Download,
                (false, false) => TransferDirection::None,
            };
            let mut xfer = ProtocolTransfer::new(direction).with_response_headers(true);
            if let Some(len) = body_len {
                xfer = xfer.with_size(len);
            }
            Ok(xfer)
        })
    }

    fn done<'a>(
        &'a self,
        data: &'a mut Easy,
        _conn: &'a mut Connection,
        status: Result<()>,
        _premature: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Propagate a transfer-phase error rather than swallowing it. C
            // `rtsp_done` returns `httpStatus = Curl_http_done(data, status, …)`,
            // which carries `status` when the transfer failed, and only runs the
            // `CSeq` check under `if(!status && !httpStatus)`. Mirroring that, an
            // error `status` (e.g. `CURLE_GOT_NOTHING` from an empty reply) is
            // returned unchanged so the final exit code matches curl.
            status?;

            // Transfer succeeded: validate the response sequence numbers.
            let rtspreq = data.set.rtspreq;
            let (sent, recv, channel) = {
                let sess = self.lock();
                (
                    sess.state.cseq_sent,
                    sess.state.cseq_recv,
                    sess.conn.rtp_channel,
                )
            };
            if rtspreq == RTSPREQ_RECEIVE && channel == -1 {
                infof(
                    data.set.verbose,
                    &format!("Got an RTP Receive with a CSeq of {recv}"),
                );
            }
            if let Err(e) = check_cseq(rtspreq, sent, recv) {
                let mut errbuf: Option<String> = None;
                failf(
                    &mut errbuf,
                    &format!(
                        "The CSeq of this request {sent} did not match the response {recv}"
                    ),
                );
                return Err(e);
            }
            Ok(())
        })
    }

    fn write_resp(&self, data: &mut Easy, buf: &[u8], _is_eos: bool) -> Result<bool> {
        let is_receive = data.set.rtspreq == RTSPREQ_RECEIVE;
        let mut sess = self.lock();
        let mask = sess.channel_mask;
        let (outs, _consumed) = filter_rtp(&mut sess.conn, &mask, buf, false, is_receive)?;
        push_outputs(&mut sess, outs);
        // We fully handle the body bytes (demuxing body vs interleaved RTP).
        Ok(true)
    }

    fn write_resp_hd(&self, data: &mut Easy, hd: &[u8], _is_eos: bool) -> Result<bool> {
        // Non-UTF-8 header lines are left to the generic header path.
        let Ok(line) = std::str::from_utf8(hd) else {
            return Ok(false);
        };
        let configured = data.set.str(StrId::RtspSessionId).map(str::to_owned);
        let verbose = data.set.verbose;
        let mut errbuf: Option<String> = None;

        let (recv_cseq, sess_id) = {
            let mut sess = self.lock();
            {
                let RtspSession {
                    state,
                    channel_mask,
                    session_id,
                    ..
                } = &mut *sess;
                let mut sink = RtspHeaderSink {
                    state,
                    channel_mask,
                    session_id,
                };
                let mut diag = RtspDiag {
                    verbose,
                    errbuf: &mut errbuf,
                };
                parse_rtsp_header(line, &mut sink, configured.as_deref(), &mut diag)?;
            }
            (sess.state.cseq_recv, sess.session_id.clone())
        };

        // Surface received values via getinfo (C `data->state.rtsp_CSeq_recv`,
        // `STRING_RTSP_SESSION_ID`).
        data.info.rtsp_cseq_recv = i64::from(recv_cseq);
        if let Some(id) = sess_id {
            data.info.rtsp_session_id = std::ffi::CString::new(id).ok();
        }
        // Return Ok(false) so the generic header path also stores the header.
        Ok(false)
    }

    fn connection_check(&self, _data: &mut Easy, conn: &mut Connection, checks: u32) -> u32 {
        let mut result = 0u32;
        if checks & CONNCHECK_ISDEAD != 0 {
            let (alive, _input_pending) = Curl_conn_is_alive(conn);
            if !alive {
                result |= CONNRESULT_DEAD;
            }
        }
        result
    }
}

// ===========================================================================
// Transfer-engine driver (C `Curl_do` → `Curl_done` for an `rtsp://` transfer).
// ===========================================================================

/// Find the first occurrence of `needle` in `haystack` (a tiny `memmem` — the
/// header block is small, so the naive window scan is more than adequate).
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Parse a `Content-Length:` value from a single CRLF-terminated header line,
/// case-insensitively on the field name (C reads it via `Curl_compareheader`).
/// Returns `None` for any other header or an unparseable value.
fn rtsp_content_length(line: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(line).ok()?;
    let (name, value) = s.split_once(':')?;
    if !name.trim().eq_ignore_ascii_case("Content-Length") {
        return None;
    }
    value.trim().parse::<u64>().ok()
}

/// Buffer the entire RTSP request body from the upload read callback (`-T`),
/// the analog of SMTP's `read_upload_to_end`: loop until the source yields no
/// more data. Used for body-bearing methods when no in-memory `-d`
/// (`copypostfields`) buffer is set.
fn read_rtsp_upload(source: &mut dyn ReadCallback) -> Result<Vec<u8>> {
    let mut reader = UploadReader::new(None, false);
    let mut body = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    while let ReadStep::Data(n) = reader.read(&mut buf, source)? {
        body.extend_from_slice(&buf[..n]);
    }
    Ok(body)
}

/// Read and dispatch one RTSP response off `conn`, mirroring curl's split of
/// `Curl_http_readwrite_headers` (header lines) and `rtsp_rtp_write_resp`
/// (body + interleaved RTP). The RTSP response is HTTP-shaped
/// (`RTSP/1.0 <code> <reason>\r\n<headers>\r\n\r\n[body]`):
///
/// 1. Read until the blank-line header terminator (`\r\n\r\n`) or peer close.
/// 2. Feed every CRLF-delimited line — including the status line, which curl
///    also writes as a header — to [`RtspProtocol::write_resp_hd`], which tracks
///    `CSeq`/`Session` (consumed by the `done`-phase `CSeq` check) and returns
///    `Ok(false)` so the line is also written to the client header stream.
///    `Content-Length` is parsed here to bound the body.
/// 3. Feed the body bytes (those already read past the header terminator, plus
///    any remainder read from the socket, bounded by `Content-Length`) to
///    [`RtspProtocol::write_resp`], which demuxes interleaved RTP and
///    accumulates the demuxed body.
/// 4. Deliver the accumulated body to the client `sink` with an end-of-stream.
///
/// # Errors
///
/// Any transport error from [`Curl_conn_recv`], a header-parse error surfaced by
/// the handler, or a client write error.
async fn read_rtsp_response(
    data: &mut Easy,
    conn: &mut Connection,
    handler: &RtspProtocol,
    sink: &mut dyn WriteCallbacks,
) -> Result<()> {
    let mut writer = ClientWriter::with_options(data.set.include_header, false);
    let mut acc: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; RTP_RECV_CHUNK];

    // (1) Read until the end of the header block (CRLF CRLF) or peer close.
    let header_end = loop {
        if let Some(pos) = find_subsequence(&acc, b"\r\n\r\n") {
            break Some(pos + 4);
        }
        match Curl_conn_recv(conn, FIRSTSOCKET, &mut buf).await {
            Ok(0) => break None, // peer closed before a complete header block
            Ok(n) => acc.extend_from_slice(&buf[..n]),
            Err(CurlError::Again) => continue,
            Err(e) => return Err(e),
        }
    };

    let Some(header_end) = header_end else {
        // The peer closed before a complete header block.
        if acc.is_empty() {
            // Nothing at all was received: curl's transfer loop reports
            // `CURLE_GOT_NOTHING` ("Empty reply from server", exit 52) for this
            // case — the same code system curl returns against a server that
            // accepts the connection and closes without replying. Surface it so
            // the exit code matches (G6 behavioral parity).
            return Err(CurlError::GotNothing);
        }
        // Some bytes arrived but never completed the header block (a truncated
        // response). Flush a zero-length body end-of-stream so the writer
        // finalizes; the `done`-phase `CSeq` check then surfaces the protocol
        // error (`recv` stays 0), exactly as curl reports a truncated RTSP
        // response.
        writer.write(ClientWriteType::BODY.union(ClientWriteType::EOS), &[], sink)?;
        return Ok(());
    };

    // (2) Dispatch each header line (status line included), retaining its CRLF
    //     so the bytes match what curl hands the header writer.
    let mut content_length: Option<u64> = None;
    let mut start = 0usize;
    while start < header_end {
        let Some(rel) = find_subsequence(&acc[start..header_end], b"\r\n") else {
            break;
        };
        let line_end = start + rel + 2; // include the CRLF
        let line = acc[start..line_end].to_vec();
        let is_terminator = line.as_slice() == b"\r\n";
        if !is_terminator {
            if let Some(v) = rtsp_content_length(&line) {
                content_length = Some(v);
            }
        }
        let handled = handler.write_resp_hd(data, &line, is_terminator)?;
        if !handled && writer.write(ClientWriteType::HEADER, &line, sink).is_err() {
            return Err(CurlError::WriteError);
        }
        start = line_end;
        if is_terminator {
            break;
        }
    }

    // (3) Body: the bytes after the header terminator, bounded by
    //     `Content-Length` (RTSP requires it for a body; its absence means no
    //     body). Feed to the protocol's demux (`write_resp`).
    let body_target = content_length.unwrap_or(0);
    let mut body_seen: u64 = 0;
    let leading = acc.split_off(header_end); // bytes already read past the headers
    if body_target > 0 && !leading.is_empty() {
        let take = ((body_target - body_seen) as usize).min(leading.len());
        handler.write_resp(data, &leading[..take], false)?;
        body_seen += take as u64;
    }
    while body_seen < body_target {
        let want = ((body_target - body_seen) as usize).min(buf.len());
        match Curl_conn_recv(conn, FIRSTSOCKET, &mut buf[..want]).await {
            Ok(0) => break, // peer closed before the full body arrived
            Ok(n) => {
                handler.write_resp(data, &buf[..n], false)?;
                body_seen += n as u64;
            }
            Err(CurlError::Again) => continue,
            Err(e) => return Err(e),
        }
    }
    // Signal end-of-body to the demux filter (no-op on an empty buffer).
    handler.write_resp(data, &[], true)?;

    // (4) Deliver the demuxed body to the client.
    let body = handler.take_pending_body();
    writer.write(
        ClientWriteType::BODY.union(ClientWriteType::EOS),
        &body,
        sink,
    )?;
    data.info.size_download = body.len() as i64;
    Ok(())
}

/// Drive an `rtsp://` transfer end-to-end, the RTSP analog of
/// [`pop3::perform_pop3`](crate::protocols::pop3::perform_pop3) and the seam
/// [`perform_transfer`](crate::protocols::perform_transfer) dispatches every
/// `rtsp` scheme to:
///
/// 1. Open the plain-TCP connection-filter chain with [`connect_network_scheme`]
///    (RTSP has a single scheme; RTSP-over-TLS exists only via an explicit
///    proxy tunnel, out of scope here).
/// 2. [`connect`](Protocol::connect) initializes the client/server `CSeq`
///    counters (C `rtsp_connect`).
/// 3. [`do_it`](Protocol::do_it) sends the request line + headers (e.g.
///    `OPTIONS`/`DESCRIBE`/`SETUP`/`PLAY`) and reports the transfer shape. For a
///    body-bearing method (`ANNOUNCE`/`SET_PARAMETER`/`GET_PARAMETER` with
///    content) the request body is sent here — from the in-memory `-d`
///    (`copypostfields`) buffer or the `-T` upload read callback — immediately
///    after the headers. The response (status line + headers + optional
///    `Content-Length` body, with interleaved-RTP demux) is then read by
///    [`read_rtsp_response`]; the `RECEIVE` pseudo-request instead delivers the
///    single chunk `do_it` already demuxed.
/// 4. [`done`](Protocol::done) validates the response `CSeq` (C `rtsp_done`) and
///    [`disconnect`](Protocol::disconnect) tears down.
///
/// This is the wiring whose absence produced QA finding **F5-CRIT-10** (every
/// `rtsp://` transfer returned `UnsupportedProtocol` before a socket opened).
///
/// # Errors
///
/// Propagates any connection-setup, request-send, response-read, `CSeq`
/// validation, or client write error as the corresponding [`CurlError`].
pub(crate) async fn perform_rtsp(
    data: &mut Easy,
    sink: &mut dyn WriteCallbacks,
    source: &mut dyn ReadCallback,
) -> Result<()> {
    // RTSP has a single scheme descriptor (default port 554).
    let scheme: &'static Scheme = &SCHEME_RTSP;

    // (1) Establish the plain-TCP connection.
    let mut conn = connect_network_scheme(data, scheme).await?;

    // (2) Connect phase: initialize the CSeq counters (C `rtsp_connect`).
    let handler = RtspProtocol::new();
    handler.connect(data, &mut conn).await?;

    // (3) DO phase: send the request, optionally send the request body, then
    //     read the response. Fenced so a failure still runs `done`.
    let result: Result<()> = async {
        let xfer = handler.do_it(data, &mut conn).await?;
        let rtspreq = data.set.rtspreq;

        // (3a) Body-bearing methods: `do_it` sent the headers (incl.
        //      `Content-Length`); the body follows on the same connection.
        if matches!(
            xfer.direction,
            TransferDirection::Upload | TransferDirection::Bidirectional
        ) {
            if let Some(len) = xfer.expected_size {
                let mut body = if let Some(cp) = data.set.copypostfields.clone() {
                    cp
                } else {
                    read_rtsp_upload(source)?
                };
                body.truncate(len as usize);
                if !body.is_empty() {
                    Curl_conn_send(&mut conn, FIRSTSOCKET, &body, false).await?;
                }
            }
        }

        // (3b) Read the response. RTSP always returns a status line + headers
        //      (`has_response_headers` is always set), except the `RECEIVE`
        //      pseudo-request, which `do_it` already serviced by demuxing one
        //      interleaved chunk.
        if rtspreq == RTSPREQ_RECEIVE {
            let body = handler.take_pending_body();
            let mut writer = ClientWriter::with_options(data.set.include_header, false);
            writer.write(
                ClientWriteType::BODY.union(ClientWriteType::EOS),
                &body,
                sink,
            )?;
            data.info.size_download = body.len() as i64;
        } else if xfer.has_response_headers {
            read_rtsp_response(data, &mut conn, &handler, sink).await?;
        }
        Ok(())
    }
    .await;

    // (4) Finalize (validates the response CSeq) then best-effort tear-down.
    let premature = result.is_err();
    let done = handler.done(data, &mut conn, result, premature).await;
    let _ = handler.disconnect(data, &mut conn, done.is_err()).await;
    done
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    // --- helpers ----------------------------------------------------------

    fn cstr(s: &str) -> CString {
        CString::new(s).expect("test header has no interior NUL")
    }

    fn build_with(
        rtspreq: u8,
        cseq: u32,
        session_id: Option<&str>,
        transport: Option<&str>,
        custom: &[&CStr],
        body_len: Option<u64>,
    ) -> Result<String> {
        let p = RtspReqParams {
            rtspreq,
            stream_uri: "rtsp://h/s",
            cseq,
            session_id,
            transport,
            accept_encoding: None,
            range: None,
            referer: None,
            user_agent: None,
            custom_headers: custom,
            body_len,
        };
        let mut eb: Option<String> = None;
        let mut diag = RtspDiag {
            verbose: false,
            errbuf: &mut eb,
        };
        build_rtsp_request(&p, &mut diag).map(|v| String::from_utf8(v).expect("ascii request"))
    }

    fn parse_header(
        line: &str,
        state: &mut RtspState,
        mask: &mut [u8; CHANNEL_MASK_LEN],
        sid: &mut Option<String>,
        configured: Option<&str>,
    ) -> Result<()> {
        let mut eb: Option<String> = None;
        let mut diag = RtspDiag {
            verbose: false,
            errbuf: &mut eb,
        };
        let mut sink = RtspHeaderSink {
            state,
            channel_mask: mask,
            session_id: sid,
        };
        parse_rtsp_header(line, &mut sink, configured, &mut diag)
    }

    fn set_channel(mask: &mut [u8; CHANNEL_MASK_LEN], ch: u8) {
        mask[(ch / 8) as usize] |= 1u8 << (ch % 8);
    }

    fn channel_set(mask: &[u8; CHANNEL_MASK_LEN], ch: u8) -> bool {
        (mask[(ch / 8) as usize] & (1u8 << (ch % 8))) != 0
    }

    // --- method helpers ---------------------------------------------------

    #[test]
    fn method_names_match_curl() {
        assert_eq!(rtsp_method_name(RTSPREQ_OPTIONS), Some("OPTIONS"));
        assert_eq!(rtsp_method_name(RTSPREQ_DESCRIBE), Some("DESCRIBE"));
        assert_eq!(rtsp_method_name(RTSPREQ_ANNOUNCE), Some("ANNOUNCE"));
        assert_eq!(rtsp_method_name(RTSPREQ_SETUP), Some("SETUP"));
        assert_eq!(rtsp_method_name(RTSPREQ_PLAY), Some("PLAY"));
        assert_eq!(rtsp_method_name(RTSPREQ_PAUSE), Some("PAUSE"));
        assert_eq!(rtsp_method_name(RTSPREQ_TEARDOWN), Some("TEARDOWN"));
        assert_eq!(
            rtsp_method_name(RTSPREQ_GET_PARAMETER),
            Some("GET_PARAMETER")
        );
        assert_eq!(
            rtsp_method_name(RTSPREQ_SET_PARAMETER),
            Some("SET_PARAMETER")
        );
        assert_eq!(rtsp_method_name(RTSPREQ_RECORD), Some("RECORD"));
        assert_eq!(rtsp_method_name(RTSPREQ_RECEIVE), Some(""));
        assert_eq!(rtsp_method_name(RTSPREQ_NONE), None);
        assert_eq!(rtsp_method_name(RTSPREQ_LAST), None);
        assert_eq!(rtsp_method_name(200), None);
    }

    #[test]
    fn body_methods_match_curl() {
        assert!(rtsp_req_has_body(RTSPREQ_DESCRIBE));
        assert!(rtsp_req_has_body(RTSPREQ_GET_PARAMETER));
        assert!(rtsp_req_has_body(RTSPREQ_RECEIVE));
        assert!(!rtsp_req_has_body(RTSPREQ_OPTIONS));
        assert!(!rtsp_req_has_body(RTSPREQ_PLAY));
    }

    /// PARITY: session id required exactly for GET_PARAMETER / SET_PARAMETER /
    /// RECORD / RECEIVE per the `rtspreq & ~0x07` bitwise test.
    #[test]
    fn session_id_requirement_is_bitwise() {
        for req in [
            RTSPREQ_OPTIONS,
            RTSPREQ_DESCRIBE,
            RTSPREQ_ANNOUNCE,
            RTSPREQ_SETUP,
            RTSPREQ_PLAY,
            RTSPREQ_PAUSE,
            RTSPREQ_TEARDOWN,
        ] {
            assert!(
                !session_id_required(req),
                "req {req} must NOT need a session"
            );
        }
        for req in [
            RTSPREQ_GET_PARAMETER,
            RTSPREQ_SET_PARAMETER,
            RTSPREQ_RECORD,
            RTSPREQ_RECEIVE,
        ] {
            assert!(session_id_required(req), "req {req} MUST need a session");
        }
    }

    /// PARITY: the range mask is `5 | 6 | 10 == 0x0F`, so it matches every valid
    /// request id (the real limiter is whether CURLOPT_RANGE was set).
    #[test]
    fn range_mask_matches_all_valid_requests() {
        for req in RTSPREQ_OPTIONS..=RTSPREQ_RECEIVE {
            assert!(range_applies(req), "req {req} should pass the 0x0F mask");
        }
    }

    // --- request building -------------------------------------------------

    #[test]
    fn build_options_minimal() {
        let req = build_with(RTSPREQ_OPTIONS, 1, None, None, &[], None).unwrap();
        assert_eq!(req, "OPTIONS rtsp://h/s RTSP/1.0\r\nCSeq: 1\r\n\r\n");
    }

    #[test]
    fn build_describe_adds_accept_sdp() {
        let req = build_with(RTSPREQ_DESCRIBE, 2, None, None, &[], None).unwrap();
        assert_eq!(
            req,
            "DESCRIBE rtsp://h/s RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n"
        );
    }

    #[test]
    fn build_setup_orders_headers_and_includes_transport() {
        let req = build_with(
            RTSPREQ_SETUP,
            3,
            Some("S1"),
            Some("RTP/AVP/TCP;interleaved=0-1"),
            &[],
            None,
        )
        .unwrap();
        assert_eq!(
            req,
            "SETUP rtsp://h/s RTSP/1.0\r\nCSeq: 3\r\nSession: S1\r\n\
             Transport: RTP/AVP/TCP;interleaved=0-1\r\n\r\n"
        );
    }

    #[test]
    fn build_setup_without_transport_is_error() {
        let err = build_with(RTSPREQ_SETUP, 3, None, None, &[], None).unwrap_err();
        assert_eq!(err, CurlError::BadFunctionArgument);
    }

    #[test]
    fn build_setup_with_custom_transport_header_is_ok() {
        let h = [cstr("Transport: RTP/AVP/TCP;interleaved=2-3")];
        let refs: Vec<&CStr> = h.iter().map(CString::as_c_str).collect();
        let req = build_with(RTSPREQ_SETUP, 3, None, None, &refs, None).unwrap();
        assert!(req.contains("Transport: RTP/AVP/TCP;interleaved=2-3\r\n"));
    }

    #[test]
    fn build_play_emits_session() {
        let req = build_with(RTSPREQ_PLAY, 4, Some("12345678"), None, &[], None).unwrap();
        assert!(req.starts_with("PLAY rtsp://h/s RTSP/1.0\r\nCSeq: 4\r\nSession: 12345678\r\n"));
    }

    #[test]
    fn build_get_parameter_requires_session() {
        let err = build_with(RTSPREQ_GET_PARAMETER, 5, None, None, &[], None).unwrap_err();
        assert_eq!(err, CurlError::BadFunctionArgument);
        // With a session it succeeds.
        let req = build_with(RTSPREQ_GET_PARAMETER, 5, Some("s"), None, &[], None).unwrap();
        assert!(req.contains("Session: s\r\n"));
    }

    #[test]
    fn build_rejects_custom_cseq_and_session() {
        let h1 = [cstr("CSeq: 99")];
        let r1: Vec<&CStr> = h1.iter().map(CString::as_c_str).collect();
        assert_eq!(
            build_with(RTSPREQ_OPTIONS, 1, None, None, &r1, None).unwrap_err(),
            CurlError::RtspCseqError
        );

        let h2 = [cstr("Session: x")];
        let r2: Vec<&CStr> = h2.iter().map(CString::as_c_str).collect();
        assert_eq!(
            build_with(RTSPREQ_OPTIONS, 1, None, None, &r2, None).unwrap_err(),
            CurlError::BadFunctionArgument
        );
    }

    #[test]
    fn build_appends_custom_headers() {
        let h = [cstr("X-Foo: bar"), cstr("X-Baz: qux")];
        let refs: Vec<&CStr> = h.iter().map(CString::as_c_str).collect();
        let req = build_with(RTSPREQ_OPTIONS, 1, None, None, &refs, None).unwrap();
        assert!(req.contains("X-Foo: bar\r\n"));
        assert!(req.contains("X-Baz: qux\r\n"));
    }

    #[test]
    fn build_announce_body_headers() {
        let req = build_with(RTSPREQ_ANNOUNCE, 6, Some("s"), None, &[], Some(42)).unwrap();
        assert!(req.contains("Content-Length: 42\r\n"));
        assert!(req.contains("Content-Type: application/sdp\r\n"));
    }

    #[test]
    fn build_set_parameter_body_content_type() {
        let req = build_with(RTSPREQ_SET_PARAMETER, 7, Some("s"), None, &[], Some(10)).unwrap();
        assert!(req.contains("Content-Length: 10\r\n"));
        assert!(req.contains("Content-Type: text/parameters\r\n"));
    }

    #[test]
    fn build_invalid_request_is_error() {
        assert_eq!(
            build_with(RTSPREQ_NONE, 1, None, None, &[], None).unwrap_err(),
            CurlError::BadFunctionArgument
        );
    }

    #[test]
    fn build_header_overflow_is_too_large() {
        // A single custom header larger than the 64 KiB cap must overflow.
        let big = format!("X-Big: {}", "a".repeat(DYN_RTSP_REQ_HEADER + 16));
        let h = [cstr(&big)];
        let refs: Vec<&CStr> = h.iter().map(CString::as_c_str).collect();
        assert_eq!(
            build_with(RTSPREQ_OPTIONS, 1, None, None, &refs, None).unwrap_err(),
            CurlError::TooLarge
        );
    }

    // --- status / header parsing -----------------------------------------

    #[test]
    fn status_line_parsing() {
        assert_eq!(
            parse_status_line("RTSP/1.0 200 OK\r\n"),
            Some(RtspStatus {
                http_major: 1,
                http_minor: 0,
                status_code: 200,
            })
        );
        assert_eq!(
            parse_status_line("RTSP/1.0 454 Session Not Found").map(|s| s.status_code),
            Some(454)
        );
        assert_eq!(parse_status_line("HTTP/1.1 200 OK"), None);
        assert_eq!(parse_status_line("garbage"), None);
        assert_eq!(parse_status_line("RTSP/1.0"), None);
    }

    #[test]
    fn cseq_value_parsing() {
        assert_eq!(parse_cseq_value("  5"), Ok(5));
        assert_eq!(parse_cseq_value("4294967295"), Ok(u32::MAX));
        assert_eq!(parse_cseq_value(""), Err(CurlError::RtspCseqError));
        assert_eq!(parse_cseq_value("abc"), Err(CurlError::RtspCseqError));
        assert_eq!(
            parse_cseq_value("4294967296"),
            Err(CurlError::RtspCseqError)
        );
    }

    #[test]
    fn session_value_learn_match_mismatch_blank() {
        assert_eq!(
            parse_session_value("  ABC123 ;foo", None),
            Ok(SessionOutcome::Learned("ABC123".to_owned()))
        );
        assert_eq!(
            parse_session_value(" ABC", Some("ABC")),
            Ok(SessionOutcome::Matched)
        );
        assert_eq!(
            parse_session_value(" XYZ", Some("ABC")),
            Err(CurlError::RtspSessionError)
        );
        assert_eq!(
            parse_session_value("    ", None),
            Err(CurlError::RtspSessionError)
        );
    }

    #[test]
    fn parse_header_cseq() {
        let mut state = RtspState::default();
        let mut mask = [0u8; CHANNEL_MASK_LEN];
        let mut sid = None;
        parse_header("CSeq: 7\r\n", &mut state, &mut mask, &mut sid, None).unwrap();
        assert_eq!(state.cseq_recv, 7);

        let bad = parse_header("CSeq: nope", &mut state, &mut mask, &mut sid, None);
        assert_eq!(bad, Err(CurlError::RtspCseqError));
    }

    #[test]
    fn parse_header_session_learn_then_enforce() {
        let mut state = RtspState::default();
        let mut mask = [0u8; CHANNEL_MASK_LEN];
        let mut sid = None;

        // First response learns the id.
        parse_header("Session: ABC\r\n", &mut state, &mut mask, &mut sid, None).unwrap();
        assert_eq!(sid.as_deref(), Some("ABC"));

        // A matching id on a later response is fine.
        parse_header("Session: ABC\r\n", &mut state, &mut mask, &mut sid, None).unwrap();

        // A different id is now rejected.
        let err = parse_header("Session: XYZ\r\n", &mut state, &mut mask, &mut sid, None);
        assert_eq!(err, Err(CurlError::RtspSessionError));
    }

    #[test]
    fn parse_header_session_blank_is_error() {
        let mut state = RtspState::default();
        let mut mask = [0u8; CHANNEL_MASK_LEN];
        let mut sid = None;
        let err = parse_header("Session:   \r\n", &mut state, &mut mask, &mut sid, None);
        assert_eq!(err, Err(CurlError::RtspSessionError));
    }

    #[test]
    fn parse_header_session_against_configured() {
        let mut state = RtspState::default();
        let mut mask = [0u8; CHANNEL_MASK_LEN];
        let mut sid = None;
        let err = parse_header(
            "Session: got\r\n",
            &mut state,
            &mut mask,
            &mut sid,
            Some("want"),
        );
        assert_eq!(err, Err(CurlError::RtspSessionError));
    }

    #[test]
    fn parse_header_transport_sets_channels() {
        let mut state = RtspState::default();
        let mut mask = [0u8; CHANNEL_MASK_LEN];
        let mut sid = None;
        parse_header(
            "Transport: RTP/AVP/TCP;unicast;interleaved=5-6\r\n",
            &mut state,
            &mut mask,
            &mut sid,
            None,
        )
        .unwrap();
        assert!(channel_set(&mask, 5));
        assert!(channel_set(&mask, 6));
        assert!(!channel_set(&mask, 4));
        assert!(!channel_set(&mask, 7));
    }

    #[test]
    fn parse_header_non_rtsp_is_ignored() {
        let mut state = RtspState::default();
        let mut mask = [0u8; CHANNEL_MASK_LEN];
        let mut sid = None;
        parse_header("Content-Type: x\r\n", &mut state, &mut mask, &mut sid, None).unwrap();
        assert_eq!(state.cseq_recv, 0);
        assert!(sid.is_none());
    }

    #[test]
    fn transport_interleaved_single_and_range() {
        let mut eb: Option<String> = None;
        let mut diag = RtspDiag {
            verbose: false,
            errbuf: &mut eb,
        };

        let mut m1 = [0u8; CHANNEL_MASK_LEN];
        parse_transport_interleaved("RTP/AVP/TCP;unicast;interleaved=0-1", &mut m1, &mut diag);
        assert!(channel_set(&m1, 0));
        assert!(channel_set(&m1, 1));

        let mut m2 = [0u8; CHANNEL_MASK_LEN];
        parse_transport_interleaved("interleaved=10", &mut m2, &mut diag);
        assert!(channel_set(&m2, 10));
        assert!(!channel_set(&m2, 9));

        let mut m3 = [0u8; CHANNEL_MASK_LEN];
        parse_transport_interleaved("RTP/AVP;unicast;client_port=8000", &mut m3, &mut diag);
        assert_eq!(m3, [0u8; CHANNEL_MASK_LEN]);
    }

    // --- CSeq validation --------------------------------------------------

    #[test]
    fn check_cseq_match_mismatch_receive() {
        assert_eq!(check_cseq(RTSPREQ_PLAY, 5, 5), Ok(()));
        assert_eq!(
            check_cseq(RTSPREQ_PLAY, 5, 6),
            Err(CurlError::RtspCseqError)
        );
        // RECEIVE bypasses the check.
        assert_eq!(check_cseq(RTSPREQ_RECEIVE, 5, 6), Ok(()));
    }

    // --- RTP demux --------------------------------------------------------

    fn demux(
        conn: &mut RtspConn,
        mask: &[u8; CHANNEL_MASK_LEN],
        buf: &[u8],
    ) -> (Vec<RtpOutput>, usize) {
        filter_rtp(conn, mask, buf, false, false).expect("demux ok")
    }

    #[test]
    fn demux_single_frame() {
        let mut mask = [0u8; CHANNEL_MASK_LEN];
        set_channel(&mut mask, 0);
        let mut conn = RtspConn::default();
        let buf = [RTP_MAGIC, 0, 0, 2, 0xAA, 0xBB];
        let (out, consumed) = demux(&mut conn, &mask, &buf);
        assert_eq!(consumed, 6);
        assert_eq!(
            out,
            vec![RtpOutput::Interleaved {
                channel: 0,
                frame: vec![RTP_MAGIC, 0, 0, 2, 0xAA, 0xBB],
            }]
        );
        assert_eq!(conn.state, RtpParseState::Skip);
    }

    #[test]
    fn demux_body_then_frame() {
        let mut mask = [0u8; CHANNEL_MASK_LEN];
        set_channel(&mut mask, 0);
        let mut conn = RtspConn::default();
        let mut buf = b"hi".to_vec();
        buf.extend_from_slice(&[RTP_MAGIC, 0, 0, 1, 0xCC]);
        let (out, consumed) = demux(&mut conn, &mask, &buf);
        assert_eq!(consumed, buf.len());
        assert_eq!(
            out,
            vec![
                RtpOutput::Body(b"hi".to_vec()),
                RtpOutput::Interleaved {
                    channel: 0,
                    frame: vec![RTP_MAGIC, 0, 0, 1, 0xCC],
                },
            ]
        );
    }

    #[test]
    fn demux_frame_split_across_reads() {
        let mut mask = [0u8; CHANNEL_MASK_LEN];
        set_channel(&mut mask, 0);
        let mut conn = RtspConn::default();

        // First read: '$', channel, high length byte.
        let (out1, c1) = demux(&mut conn, &mask, &[RTP_MAGIC, 0, 0]);
        assert!(out1.is_empty());
        assert_eq!(c1, 3);
        assert_eq!(conn.state, RtpParseState::Len);

        // Second read: low length byte + 2-byte payload.
        let (out2, c2) = demux(&mut conn, &mask, &[2, 0xAA, 0xBB]);
        assert_eq!(c2, 3);
        assert_eq!(
            out2,
            vec![RtpOutput::Interleaved {
                channel: 0,
                frame: vec![RTP_MAGIC, 0, 0, 2, 0xAA, 0xBB],
            }]
        );
        assert_eq!(conn.state, RtpParseState::Skip);
    }

    #[test]
    fn demux_invalid_channel_becomes_body() {
        // Only channel 0 is valid; a '$' followed by channel 5 is body data.
        let mut mask = [0u8; CHANNEL_MASK_LEN];
        set_channel(&mut mask, 0);
        let mut conn = RtspConn::default();
        let buf = [RTP_MAGIC, 5, 0, 2];
        let (out, consumed) = demux(&mut conn, &mask, &buf);
        assert_eq!(consumed, 4);
        assert_eq!(out, vec![RtpOutput::Body(vec![RTP_MAGIC, 5, 0, 2])]);
        assert_eq!(conn.state, RtpParseState::Skip);
    }

    #[test]
    fn demux_rtsp_prefix_stops_consumption() {
        // Junk then the start of the next response — "RTSP/" must NOT be consumed.
        let mut mask = [0u8; CHANNEL_MASK_LEN];
        set_channel(&mut mask, 0);
        let mut conn = RtspConn::default();
        let buf = b"jkRTSP/";
        let (out, consumed) = demux(&mut conn, &mask, buf);
        assert_eq!(consumed, 2, "only the junk 'jk' is consumed");
        assert_eq!(out, vec![RtpOutput::Body(b"jk".to_vec())]);
        assert!(
            conn.in_header,
            "header parsing flagged for the next response"
        );
    }

    #[test]
    fn demux_rtsp_partial_prefix_waits() {
        // A partial "RT" at a chunk boundary should stop and consume nothing.
        let mut mask = [0u8; CHANNEL_MASK_LEN];
        set_channel(&mut mask, 0);
        let mut conn = RtspConn::default();
        let (out, consumed) = demux(&mut conn, &mask, b"RT");
        assert_eq!(consumed, 0);
        assert!(out.is_empty());
        assert!(conn.in_header);
    }

    #[test]
    fn demux_in_body_does_not_trigger_rtsp_lookahead() {
        // With in_body = true, an 'R' run is plain body data.
        let mut mask = [0u8; CHANNEL_MASK_LEN];
        set_channel(&mut mask, 0);
        let mut conn = RtspConn::default();
        let (out, consumed) =
            filter_rtp(&mut conn, &mask, b"RTSP/", true, false).expect("demux ok");
        assert_eq!(consumed, 5);
        assert_eq!(out, vec![RtpOutput::Body(b"RTSP/".to_vec())]);
    }

    #[test]
    fn demux_multiple_frames() {
        let mut mask = [0u8; CHANNEL_MASK_LEN];
        set_channel(&mut mask, 0);
        let mut conn = RtspConn::default();
        let buf = [
            RTP_MAGIC, 0, 0, 1, 0xAA, // frame 1
            RTP_MAGIC, 0, 0, 1, 0xBB, // frame 2
        ];
        let (out, consumed) = demux(&mut conn, &mask, &buf);
        assert_eq!(consumed, 10);
        assert_eq!(
            out,
            vec![
                RtpOutput::Interleaved {
                    channel: 0,
                    frame: vec![RTP_MAGIC, 0, 0, 1, 0xAA],
                },
                RtpOutput::Interleaved {
                    channel: 0,
                    frame: vec![RTP_MAGIC, 0, 0, 1, 0xBB],
                },
            ]
        );
    }

    #[test]
    fn push_outputs_routes_body_and_rtp() {
        let mut sess = RtspSession::default();
        push_outputs(
            &mut sess,
            vec![
                RtpOutput::Body(b"abc".to_vec()),
                RtpOutput::Interleaved {
                    channel: 3,
                    frame: vec![RTP_MAGIC, 3, 0, 0],
                },
            ],
        );
        assert_eq!(sess.pending_body, b"abc");
        assert_eq!(sess.pending_rtp, vec![(3u8, vec![RTP_MAGIC, 3, 0, 0])]);
    }

    // --- handler ----------------------------------------------------------

    #[test]
    fn handler_exposes_rtsp_scheme() {
        let h = RtspProtocol::new();
        let scheme = h.scheme();
        assert_eq!(scheme.name, "rtsp");
        assert_eq!(scheme.default_port, 554);
        assert_eq!(scheme.flags, SCHEME_RTSP.flags);
    }

    #[test]
    fn handler_take_pending_drains() {
        let h = RtspProtocol::new();
        {
            let mut sess = h.lock();
            sess.pending_body.extend_from_slice(b"xyz");
            sess.pending_rtp.push((7, vec![1, 2, 3]));
        }
        assert_eq!(h.take_pending_body(), b"xyz");
        assert_eq!(h.take_pending_rtp(), vec![(7u8, vec![1, 2, 3])]);
        // Second take is empty.
        assert!(h.take_pending_body().is_empty());
        assert!(h.take_pending_rtp().is_empty());
    }
}
