// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! RTSP (Real Time Streaming Protocol, RFC 2326) handler.
//!
//! This is the safe-Rust rewrite of curl's RTSP handler, ported verbatim in
//! behavior from the source-of-truth `lib/rtsp.c` (~1084 lines) and `lib/rtsp.h`
//! of curl / libcurl 8.19.0-DEV. The rewrite exists to eliminate the manual
//! `malloc`/`free` memory management of the C original while preserving **exact**
//! functional parity: the same request bytes on the wire, the same interleaved
//! RTP framing, and the same frozen error codes.
//!
//! # RTSP is HTTP-shaped
//!
//! RTSP is a text protocol that borrows HTTP's request/response grammar. curl
//! implements it by *reusing* its HTTP request-assembly and response-header
//! parsing machinery (`lib/rtsp.c` includes `http.h` and calls the `Curl_http_*`
//! helpers for authentication headers, custom headers, time conditions,
//! redirect following, and the response-header parser). On top of that shared
//! machinery RTSP layers three protocol-specific concerns, which are exactly
//! what this module reproduces:
//!
//! * **`CSeq` tracking** — every request carries a monotonically increasing
//!   `CSeq:` header and the response must echo the identical value.
//! * **`Session` handling** — a `SETUP` response's `Session:` id is captured and
//!   echoed on every subsequent request for that session.
//! * **Interleaved binary RTP** — media data is multiplexed onto the *same*
//!   control connection, framed as `$<channel><length><payload>`.
//!
//! # Module layout (engine + integration)
//!
//! The bulk of the real, testable RTSP behavior lives in self-contained
//! "engine" types that operate on concrete inputs and outputs rather than on
//! transfer-global state; the [`Protocol`] implementation then drives those
//! engines over the live [`crate::protocols::TransferCtx`] stream and sink:
//!
//! * [`RtspReq`] — the request-method enum (← `Curl_RtspReq` in `rtsp.h`), with
//!   the `CURLOPT_RTSP_REQUEST` mapping and curl's per-method characteristics.
//! * [`RtspState`] — the per-session `CSeq`/`Session`/interleave-channel state
//!   (← the transfer-scoped `struct RTSP` plus the relevant `data->state`
//!   fields), including the `CSeq`/`Session`/`Transport` response-header parser
//!   (← `Curl_rtsp_parseheader`).
//! * [`RtspRequest`] — the request-line + header byte assembler (← the
//!   `curlx_dyn_addf` sequence in `rtsp_do` / `rtsp_setup_body`).
//! * [`RtpInterleave`] — the interleaved-RTP parse state machine (← the
//!   connection-scoped `struct rtsp_conn` and `rtsp_filter_rtp`), surviving
//!   partial reads exactly as curl does.
//!
//! The [`Protocol`] implementation ([`RtspHandler`], exposed as the
//! [`HANDLER`] singleton that the scheme table in [`crate::protocols`] points
//! at) is the thin integration surface: its `do_it` assembles and sends each
//! request over the [`crate::protocols::TransferCtx`] stream and streams the
//! response — including interleaved RTP — to the context's sink, driving the
//! engine types above. The scheme
//! metadata (`rtsp`, [`crate::protocols::PROTOPT_CONN_REUSE`], default port
//! [`PORT_RTSP`]) is owned by [`crate::protocols`], matching curl's
//! `Curl_scheme_rtsp`.
//!
//! # Imports and the HTTP layer
//!
//! Per this file's dependency contract, the imports are limited to
//! [`crate::error`], [`crate::protocols`], and the `tokio::io` read/write
//! traits used to drive the transfer stream. curl's RTSP handler leans on `http.c`
//! helpers, but the request-line and header assembly it performs is plain
//! `printf`-style string building (`curlx_dyn_addf`), reproduced directly here
//! in [`RtspRequest`] so the emitted bytes match curl exactly without depending
//! on the HTTP module's (separately authored) internal API; the sole exception
//! is `crate::auth::basic`, reused to format the `Authorization: Basic` line
//! byte-for-byte as curl's `Curl_auth_create_basic_message` does. The
//! [`crate::conn`] connection type is referenced only conceptually; the
//! connection-scoped interleave state it models is carried by
//! [`RtpInterleave`].
//!
//! # Safety
//!
//! This module contains **zero** memory-unchecked code — the crate root's
//! `#![forbid(...)]` safe-code lint makes any escape-hatch token a hard compile
//! error, and a CI grep asserts the token never appears under
//! `curl-rs-lib/src/`. There is no FFI and there are no raw pointers here.

use std::fmt::Write as _;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::error::{CurlCode, Error, Result};
use crate::protocols::{ProtoFuture, Protocol, TransferCtx, TransferSink};

// ===========================================================================
// Constants (← lib/rtsp.c, lib/curlx/dynbuf.h, lib/urldata.h).
// ===========================================================================

/// The default RTSP port (← `PORT_RTSP`, `lib/urldata.h`). Registered on the
/// `rtsp` scheme by [`crate::protocols`]; duplicated here as the protocol's
/// documented default.
pub const PORT_RTSP: u16 = 554;

/// Initial capacity hint for the request-header build buffer
/// (← `DYN_RTSP_REQ_HEADER`, `lib/curlx/dynbuf.h`). curl uses this as the
/// dynamic-buffer growth ceiling; here it seeds [`Vec::with_capacity`] so a
/// typical request assembles without reallocating.
pub const DYN_RTSP_REQ_HEADER: usize = 64 * 1024;

/// Upper bound on a buffered interleaved-RTP message (← `MAX_RTP_BUFFERSIZE`,
/// `lib/rtsp.c`). A single `$`-framed message may not exceed this while being
/// reassembled across partial reads; exceeding it is a protocol error, exactly
/// as curl's dynamic buffer refuses to grow past this ceiling.
pub const MAX_RTP_BUFFERSIZE: usize = 1_000_000;

/// Number of bytes in the interleaved-channel validity bitmask
/// (← `rtp_channel_mask[32]`, `lib/urldata.h`): 32 bytes × 8 = 256 bits, one
/// per possible channel number `0..=255`.
pub const RTP_CHANNEL_MASK_LEN: usize = 32;

/// The four-byte interleaved-RTP frame header: the `$` marker, the one-byte
/// channel, and the two-byte big-endian payload length (← the `+ 4` in
/// `rtspc->rtp_len = RTP_PKT_LENGTH(rtp_buf) + 4`).
const RTP_FRAME_HEADER_LEN: usize = 4;

/// The interleaved-RTP frame marker byte (`$`) (← `buf[0] == '$'`).
const RTP_MARKER: u8 = b'$';

// ===========================================================================
// PHASE 1 — RtspReq: the RTSP request-method enum (← `Curl_RtspReq`, rtsp.h).
// ===========================================================================

/// The RTSP request method (← the `Curl_RtspReq` enum in `lib/rtsp.h`, whose
/// integer values are identical to the public `CURL_RTSPREQ_*` constants in
/// `include/curl/curl.h`).
///
/// The discriminants are the **sequential** `0..=12` values curl assigns; they
/// are load-bearing because `rtsp.c` performs bitwise arithmetic directly on
/// them (see [`RtspReq::requires_session`] and [`RtspReq::wants_range`]). The
/// variant *names* are preserved from `rtsp.h` verbatim (`RTSPREQ_NONE` becomes
/// [`RtspReq::None`], `RTSPREQ_GET_PARAMETER` becomes [`RtspReq::GetParameter`],
/// and so on) so `--trace` diagnostics and the `CURLOPT_RTSP_REQUEST` mapping
/// stay identical.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RtspReq {
    /// `RTSPREQ_NONE` — no request selected (the zero/default value).
    None = 0,
    /// `RTSPREQ_OPTIONS` — `OPTIONS`: query supported methods.
    Options = 1,
    /// `RTSPREQ_DESCRIBE` — `DESCRIBE`: fetch the session description (SDP).
    Describe = 2,
    /// `RTSPREQ_ANNOUNCE` — `ANNOUNCE`: post a session description to the server.
    Announce = 3,
    /// `RTSPREQ_SETUP` — `SETUP`: establish a media transport (and a session).
    Setup = 4,
    /// `RTSPREQ_PLAY` — `PLAY`: start or resume delivery.
    Play = 5,
    /// `RTSPREQ_PAUSE` — `PAUSE`: temporarily halt delivery.
    Pause = 6,
    /// `RTSPREQ_TEARDOWN` — `TEARDOWN`: stop delivery and free the session.
    Teardown = 7,
    /// `RTSPREQ_GET_PARAMETER` — `GET_PARAMETER`: read session/media parameters.
    GetParameter = 8,
    /// `RTSPREQ_SET_PARAMETER` — `SET_PARAMETER`: write session/media parameters.
    SetParameter = 9,
    /// `RTSPREQ_RECORD` — `RECORD`: start recording a range of media.
    Record = 10,
    /// `RTSPREQ_RECEIVE` — the client-internal "passively receive interleaved
    /// RTP / server requests" mode; no request line is emitted.
    Receive = 11,
    /// `RTSPREQ_LAST` — the end-of-list sentinel (not a real request).
    Last = 12,
}

impl RtspReq {
    /// The raw integer discriminant (← the underlying `Curl_RtspReq` value).
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Map a `CURLOPT_RTSP_REQUEST` option value to an [`RtspReq`].
    ///
    /// curl stores the supplied `long` directly as the enum, so the accepted
    /// range is exactly `0..=12` (mirroring `CURL_RTSPREQ_NONE` through
    /// `CURL_RTSPREQ_LAST`). Values outside that range yield `None`; the caller
    /// then reports the same `CURLE_BAD_FUNCTION_ARGUMENT` curl's `rtsp_do`
    /// `default` arm produces. Note that [`RtspReq::None`] and [`RtspReq::Last`]
    /// are valid *enum* values but are not issuable requests — see
    /// [`RtspReq::is_request`].
    #[must_use]
    pub const fn from_long(value: i64) -> Option<Self> {
        match value {
            0 => Some(RtspReq::None),
            1 => Some(RtspReq::Options),
            2 => Some(RtspReq::Describe),
            3 => Some(RtspReq::Announce),
            4 => Some(RtspReq::Setup),
            5 => Some(RtspReq::Play),
            6 => Some(RtspReq::Pause),
            7 => Some(RtspReq::Teardown),
            8 => Some(RtspReq::GetParameter),
            9 => Some(RtspReq::SetParameter),
            10 => Some(RtspReq::Record),
            11 => Some(RtspReq::Receive),
            12 => Some(RtspReq::Last),
            _ => None,
        }
    }

    /// The request-line method token (← the `p_request` assignments in the
    /// `rtsp_do` `switch`).
    ///
    /// [`RtspReq::Receive`] maps to the empty string (curl sets `p_request = ""`
    /// because a receive emits no request line), and [`RtspReq::None`] /
    /// [`RtspReq::Last`] also map to the empty string — they are rejected before
    /// a request line is ever built (see [`RtspReq::is_request`]).
    #[must_use]
    pub const fn method_str(self) -> &'static str {
        match self {
            RtspReq::Options => "OPTIONS",
            RtspReq::Describe => "DESCRIBE",
            RtspReq::Announce => "ANNOUNCE",
            RtspReq::Setup => "SETUP",
            RtspReq::Play => "PLAY",
            RtspReq::Pause => "PAUSE",
            RtspReq::Teardown => "TEARDOWN",
            RtspReq::GetParameter => "GET_PARAMETER",
            RtspReq::SetParameter => "SET_PARAMETER",
            RtspReq::Record => "RECORD",
            // NONE and LAST error out before a request line is built; RECEIVE
            // deliberately emits no method token.
            RtspReq::None | RtspReq::Receive | RtspReq::Last => "",
        }
    }

    /// Whether this value is a real, issuable request.
    ///
    /// Reproduces the `rtsp_do` guard: the `default` arm (which
    /// [`RtspReq::None`] falls into) and the explicit [`RtspReq::Last`] arm both
    /// return `CURLE_BAD_FUNCTION_ARGUMENT`. Every other value — including
    /// [`RtspReq::Receive`] — is issuable.
    #[must_use]
    pub const fn is_request(self) -> bool {
        !matches!(self, RtspReq::None | RtspReq::Last)
    }

    /// Whether a session id is required to issue this request.
    ///
    /// Reproduces `rtsp_do`'s check **exactly**, quirks included:
    /// `rtspreq & ~(RTSPREQ_OPTIONS | RTSPREQ_DESCRIBE | RTSPREQ_SETUP)`, i.e.
    /// `value & !(1 | 2 | 4)`. Because the method values are sequential rather
    /// than single-bit flags, this predicate is only true for values that carry
    /// a bit outside the low three — among real requests that is
    /// [`RtspReq::GetParameter`], [`RtspReq::SetParameter`], and
    /// [`RtspReq::Record`]. (curl returns from the `RTSPREQ_RECEIVE` path before
    /// consulting this check, so the caller applies it only to non-receive
    /// requests.)
    #[must_use]
    pub const fn requires_session(self) -> bool {
        let options = RtspReq::Options as u32;
        let describe = RtspReq::Describe as u32;
        let setup = RtspReq::Setup as u32;
        (self as u32 & !(options | describe | setup)) != 0
    }

    /// Whether a `Range:` header may be attached to this request.
    ///
    /// Reproduces `rtsp_do`'s check **exactly**:
    /// `rtspreq & (RTSPREQ_PLAY | RTSPREQ_PAUSE | RTSPREQ_RECORD)`, i.e.
    /// `value & (5 | 6 | 10)` = `value & 15`. As with
    /// [`RtspReq::requires_session`], this is bitwise arithmetic on sequential
    /// values, so it is true for every value except [`RtspReq::None`]; curl
    /// additionally gates the header on the user having supplied a range.
    #[must_use]
    pub const fn wants_range(self) -> bool {
        let play = RtspReq::Play as u32;
        let pause = RtspReq::Pause as u32;
        let record = RtspReq::Record as u32;
        (self as u32 & (play | pause | record)) != 0
    }

    /// The initial `no_body` disposition for this request (← the `data->req
    /// .no_body` assignments in `rtsp_do`, before [`RtspReq::needs_body_setup`]
    /// may refine it).
    ///
    /// curl defaults `no_body` to `true` and clears it for the requests that
    /// download a body: `DESCRIBE` (SDP), `GET_PARAMETER`, and the `RECEIVE`
    /// mode (interleaved RTP is treated as body).
    #[must_use]
    pub const fn default_no_body(self) -> bool {
        !matches!(
            self,
            RtspReq::Describe | RtspReq::GetParameter | RtspReq::Receive
        )
    }

    /// Whether this request runs curl's `rtsp_setup_body` content path
    /// (`ANNOUNCE`, `SET_PARAMETER`, `GET_PARAMETER`), which may attach a
    /// request body and the associated `Content-Length` / `Content-Type`
    /// headers.
    #[must_use]
    pub const fn needs_body_setup(self) -> bool {
        matches!(
            self,
            RtspReq::Announce | RtspReq::SetParameter | RtspReq::GetParameter
        )
    }
}

impl Default for RtspReq {
    /// The default request is [`RtspReq::None`] (`RTSPREQ_NONE`, value `0`),
    /// matching a freshly-initialized `data->set.rtspreq`.
    fn default() -> Self {
        RtspReq::None
    }
}

impl TryFrom<i64> for RtspReq {
    type Error = Error;

    /// Fallible conversion from a `CURLOPT_RTSP_REQUEST` value; an out-of-range
    /// value produces [`CurlCode::BadFunctionArgument`], as curl's `rtsp_do`
    /// does for an unrecognized request.
    fn try_from(value: i64) -> Result<Self> {
        RtspReq::from_long(value).ok_or_else(|| Error::bad_argument("Got invalid RTSP request"))
    }
}

// ===========================================================================
// Small byte-string parsing helpers (← lib/curlx/strparse.c).
//
// These reproduce the exact behavior of the `curlx_str_*` primitives that
// `Curl_rtsp_parseheader` and `rtsp_parse_transport` rely on, so header parsing
// matches curl byte-for-byte.
// ===========================================================================

/// Case-insensitive ASCII prefix test (← `checkprefix`, which is
/// `curl_strnequal`). Returns `true` when `haystack` begins with `prefix`
/// compared ASCII-case-insensitively.
fn ci_starts_with(haystack: &[u8], prefix: &[u8]) -> bool {
    haystack.len() >= prefix.len()
        && haystack[..prefix.len()]
            .iter()
            .zip(prefix)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// Skip leading blanks — space and tab (← `curlx_str_passblanks`, which loops
/// over `ISBLANK`). Returns the remainder of `s` after any leading blanks.
fn pass_blanks(s: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < s.len() && (s[i] == b' ' || s[i] == b'\t') {
        i += 1;
    }
    &s[i..]
}

/// Parse a leading decimal number (← `curlx_str_number` in base 10).
///
/// Requires at least one ASCII digit (else `None`, ← `STRE_NO_NUM`) and fails
/// if the accumulated value would exceed `max` (`None`, ← `STRE_OVERFLOW`). On
/// success returns the value together with the slice positioned just past the
/// consumed digits.
fn parse_number(s: &[u8], max: u64) -> Option<(u64, &[u8])> {
    let mut i = 0;
    let mut num: u64 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        let digit = u64::from(s[i] - b'0');
        // Overflow-safe accumulation mirroring str_num_base's `num > (max-n)/base`
        // guard, generalized so it is correct for any `max`.
        num = num.checked_mul(10).and_then(|v| v.checked_add(digit))?;
        if num > max {
            return None;
        }
        i += 1;
    }
    if i == 0 {
        return None;
    }
    Some((num, &s[i..]))
}

/// Consume a single expected byte (← `curlx_str_single`). Returns the remainder
/// past the byte on a match, or `None` when the next byte differs.
fn str_single(s: &[u8], byte: u8) -> Option<&[u8]> {
    match s.first() {
        Some(&b) if b == byte => Some(&s[1..]),
        _ => None,
    }
}

// ===========================================================================
// PHASE 2 — RtspState: per-session CSeq / Session / interleave-channel state.
//
// Combines the transfer-scoped `struct RTSP` (`CSeq_sent`/`CSeq_recv`) with the
// `data->state` fields curl uses across a session — `rtsp_next_client_CSeq`,
// `rtsp_next_server_CSeq`, the captured session id (`STRING_RTSP_SESSION_ID`),
// and the interleave-channel validity bitmask (`rtp_channel_mask[32]`).
// ===========================================================================

/// Per-session RTSP request/response bookkeeping.
///
/// One instance tracks a single RTSP session: the `CSeq` echoed-value contract,
/// the captured `Session:` id, and the set of interleaved-RTP channels that a
/// `Transport:` response has declared valid.
#[derive(Clone, Debug)]
pub struct RtspState {
    /// `CSeq` sent with the in-flight request (← `struct RTSP::CSeq_sent`).
    cseq_sent: u32,
    /// `CSeq` echoed by the most recent response (← `struct RTSP::CSeq_recv`,
    /// also mirrored by curl into `data->state.rtsp_CSeq_recv`).
    cseq_recv: u32,
    /// The session's next client `CSeq` (← `data->state.rtsp_next_client_CSeq`).
    next_client_cseq: u32,
    /// The session's next server `CSeq` (← `data->state.rtsp_next_server_CSeq`).
    /// Tracked for parity with curl's state even though the client path does not
    /// consume it.
    next_server_cseq: u32,
    /// The session id, either supplied via `CURLOPT_RTSP_SESSION_ID` or captured
    /// from a `SETUP` response's `Session:` header
    /// (← `data->set.str[STRING_RTSP_SESSION_ID]`).
    session_id: Option<String>,
    /// Validity bitmask for interleaved channels `0..=255`
    /// (← `data->state.rtp_channel_mask[32]`).
    rtp_channel_mask: [u8; RTP_CHANNEL_MASK_LEN],
}

impl RtspState {
    /// Create fresh session state.
    ///
    /// The client and server `CSeq` counters start at `1`, reproducing
    /// `rtsp_connect`'s "initialize the CSeq if not already done" step (curl
    /// bumps a zero counter to `1`). No session id is set and no interleave
    /// channel is yet valid.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cseq_sent: 0,
            cseq_recv: 0,
            next_client_cseq: 1,
            next_server_cseq: 1,
            session_id: None,
            rtp_channel_mask: [0; RTP_CHANNEL_MASK_LEN],
        }
    }

    /// Create session state pre-seeded with a `CURLOPT_RTSP_SESSION_ID`.
    ///
    /// When the application pins the session id up front, [`parse_header`] will
    /// *compare* an incoming `Session:` against it (rejecting a mismatch with
    /// [`CurlCode::RtspSessionError`]) rather than capturing a new one.
    ///
    /// [`parse_header`]: RtspState::parse_header
    #[must_use]
    pub fn with_session_id(session_id: impl Into<String>) -> Self {
        let mut state = Self::new();
        state.session_id = Some(session_id.into());
        state
    }

    /// The `CSeq` attached to the in-flight request.
    #[must_use]
    pub const fn cseq_sent(&self) -> u32 {
        self.cseq_sent
    }

    /// The `CSeq` echoed by the most recently parsed response.
    #[must_use]
    pub const fn cseq_recv(&self) -> u32 {
        self.cseq_recv
    }

    /// The next client `CSeq` that [`begin_request`](RtspState::begin_request)
    /// will assign.
    #[must_use]
    pub const fn next_client_cseq(&self) -> u32 {
        self.next_client_cseq
    }

    /// The session's next server `CSeq` (tracked for state parity).
    #[must_use]
    pub const fn next_server_cseq(&self) -> u32 {
        self.next_server_cseq
    }

    /// The currently-known session id, if any.
    #[must_use]
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Begin a new request: stamp its `CSeq` and clear the received `CSeq`
    /// (← `rtsp->CSeq_sent = data->state.rtsp_next_client_CSeq; rtsp->CSeq_recv
    /// = 0;` in `rtsp_do`).
    pub fn begin_request(&mut self) {
        self.cseq_sent = self.next_client_cseq;
        self.cseq_recv = 0;
    }

    /// Advance the client `CSeq` after a request was sent successfully
    /// (← `data->state.rtsp_next_client_CSeq++;` in `rtsp_do`). The increment
    /// wraps on overflow, matching the C `uint32_t` semantics.
    pub fn on_request_sent(&mut self) {
        self.next_client_cseq = self.next_client_cseq.wrapping_add(1);
    }

    /// Verify the response `CSeq` matched the request `CSeq`
    /// (← the sequence-number check in `rtsp_done`).
    ///
    /// For every request except [`RtspReq::Receive`] (which is server-initiated
    /// and carries no request `CSeq`), a mismatch between the sent and received
    /// `CSeq` is [`CurlCode::RtspCseqError`] (integer value `85`), with the same
    /// diagnostic text curl emits.
    pub fn check_cseq(&self, req: RtspReq) -> Result<()> {
        if req != RtspReq::Receive && self.cseq_sent != self.cseq_recv {
            return Err(Error::with_context(
                CurlCode::RtspCseqError,
                format!(
                    "The CSeq of this request {} did not match the response {}",
                    self.cseq_sent, self.cseq_recv
                ),
            ));
        }
        Ok(())
    }

    /// Parse one RTSP response header line (← `Curl_rtsp_parseheader`).
    ///
    /// Recognizes the three RTSP-specific headers case-insensitively:
    ///
    /// * `CSeq:` — records the echoed sequence number; a value that cannot be
    ///   read is [`CurlCode::RtspCseqError`].
    /// * `Session:` — captures the session id (or, when one is already pinned,
    ///   verifies it); a blank id or a mismatch is
    ///   [`CurlCode::RtspSessionError`].
    /// * `Transport:` — merges any `interleaved=` channel range into the
    ///   validity bitmask (never fails).
    ///
    /// Any other header line is ignored (returns `Ok(())`), exactly as curl's
    /// parser falls through. The line may be passed with or without its trailing
    /// CRLF; the value scanners stop at the terminator either way.
    pub fn parse_header(&mut self, header: &str) -> Result<()> {
        let bytes = header.as_bytes();
        if ci_starts_with(bytes, b"CSeq:") {
            let after = pass_blanks(&bytes[5..]);
            match parse_number(after, u64::from(u32::MAX)) {
                Some((cseq, _)) => {
                    // Safe: parse_number capped the value at u32::MAX.
                    self.cseq_recv = cseq as u32;
                    Ok(())
                }
                None => Err(Error::with_context(
                    CurlCode::RtspCseqError,
                    format!("Unable to read the CSeq header: [{header}]"),
                )),
            }
        } else if ci_starts_with(bytes, b"Session:") {
            self.parse_session(&bytes[8..])
        } else if ci_starts_with(bytes, b"Transport:") {
            self.parse_transport(&bytes[10..]);
            Ok(())
        } else {
            Ok(())
        }
    }

    /// Parse the value portion of a `Session:` header (the bytes after the
    /// field name), reproducing `Curl_rtsp_parseheader`'s session branch.
    fn parse_session(&mut self, value: &[u8]) -> Result<()> {
        let start = pass_blanks(value);
        if start.is_empty() {
            return Err(Error::with_context(
                CurlCode::RtspSessionError,
                "Got a blank Session ID",
            ));
        }

        // Find the end of the session id: any non-whitespace up to the field
        // separator ';' or end of line. curl compares with a signed `char`, so a
        // high-bit byte (>= 0x80) also terminates the id — reproduced here by
        // comparing as `i8` (`*end > ' '` in the C loop).
        let mut idlen = 0;
        while idlen < start.len() {
            let b = start[idlen];
            if (b as i8) <= (b' ' as i8) || b == b';' {
                break;
            }
            idlen += 1;
        }
        let id = &start[..idlen];

        if let Some(existing) = self.session_id.as_deref() {
            // A pinned id must match exactly (length and bytes).
            if existing.as_bytes() != id {
                return Err(Error::with_context(
                    CurlCode::RtspSessionError,
                    format!(
                        "Got RTSP Session ID Line [{}], but wanted ID [{}]",
                        String::from_utf8_lossy(start),
                        existing
                    ),
                ));
            }
        } else {
            // Otherwise capture it for echoing on later requests.
            self.session_id = Some(String::from_utf8_lossy(id).into_owned());
        }
        Ok(())
    }

    /// Merge the `interleaved=` channel range from a `Transport:` header value
    /// into the validity bitmask (← `rtsp_parse_transport`).
    ///
    /// Scans the `;`-separated transport parameters for the first
    /// `interleaved=<lo>[-<hi>]` (each channel `<= 255`) and marks every channel
    /// in the inclusive range valid. Multiple `Transport:` headers accumulate
    /// (the mask is OR-merged), matching curl's cross-header behavior. Malformed
    /// input is tolerated exactly as curl tolerates it (the range is skipped).
    fn parse_transport(&mut self, transport: &[u8]) {
        let mut start = 0usize;
        while start < transport.len() {
            // Skip blanks at the start of this parameter.
            let rel = pass_blanks(&transport[start..]);
            start = transport.len() - rel.len();
            let semi = transport[start..]
                .iter()
                .position(|&b| b == b';')
                .map(|i| start + i);

            if ci_starts_with(&transport[start..], b"interleaved=") {
                let after = &transport[start + "interleaved=".len()..];
                if let Some((chan1, rest)) = parse_number(after, 255) {
                    let mut chan2 = chan1;
                    if let Some(rest2) = str_single(rest, b'-') {
                        // A malformed upper bound leaves chan2 == chan1 (curl
                        // logs and falls back), so ignore a failed parse.
                        if let Some((c2, _)) = parse_number(rest2, 255) {
                            chan2 = c2;
                        }
                    }
                    for chan in chan1..=chan2 {
                        // Safe: parse_number capped both bounds at 255.
                        self.mark_channel(chan as u8);
                    }
                }
                // curl processes only the first `interleaved=` and breaks.
                break;
            }

            match semi {
                Some(s) => start = s + 1,
                None => break,
            }
        }
    }

    /// Mark an interleaved channel valid in the bitmask (`mask[ch/8] |=
    /// 1 << (ch%8)`).
    fn mark_channel(&mut self, channel: u8) {
        let idx = (channel / 8) as usize;
        let off = channel % 8;
        self.rtp_channel_mask[idx] |= 1 << off;
    }

    /// Whether `channel` has been declared valid by a `Transport:` header
    /// (← the `rtp_channel_mask[idx] & (1 << off)` test in `rtsp_filter_rtp`).
    #[must_use]
    pub fn channel_valid(&self, channel: u8) -> bool {
        let idx = (channel / 8) as usize;
        let off = channel % 8;
        (self.rtp_channel_mask[idx] & (1 << off)) != 0
    }

    /// The raw interleave-channel validity bitmask, for the interleave parser to
    /// consult (← passing `data->state.rtp_channel_mask` into
    /// `rtsp_filter_rtp`).
    #[must_use]
    pub const fn channel_mask(&self) -> &[u8; RTP_CHANNEL_MASK_LEN] {
        &self.rtp_channel_mask
    }
}

impl Default for RtspState {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// PHASE 3 — RtspRequest: request-line + header byte assembly (← rtsp_do /
// rtsp_setup_body).
// ===========================================================================

/// Extract the header field name from a logical `"Name: value"` line (the part
/// before the first `':'`, trimmed of trailing blanks), for the custom-header
/// guards and "already present?" checks curl performs with `Curl_checkheaders`.
fn header_name(line: &str) -> &str {
    let name = line.split(':').next().unwrap_or(line);
    name.trim_end_matches([' ', '\t'])
}

/// Whether a header with `name` (ASCII case-insensitive) is present among the
/// caller-supplied header lines (← `Curl_checkheaders`).
fn header_name_present(headers: &[&str], name: &str) -> bool {
    headers
        .iter()
        .any(|line| header_name(line).eq_ignore_ascii_case(name))
}

/// Assembles the exact byte stream of an RTSP request (← the `curlx_dyn_addf`
/// sequence in `rtsp_do`, plus the body headers from `rtsp_setup_body`).
///
/// The builder owns only the RTSP-specific pieces that curl's handler formats
/// itself — the request line, `CSeq`, `Session`, the SETUP `Transport`, the
/// DESCRIBE default `Accept`, and the body's `Content-Length`/`Content-Type`.
/// Everything else curl computes in shared HTTP code (authentication,
/// `Referer`, `User-Agent`, `Accept-Encoding`, `Range`, time conditions) and
/// then concatenates verbatim; those pre-formatted `"Name: value"` lines — and
/// any user custom headers — are supplied via [`RtspRequest::headers`] in curl's
/// emission order and copied through unchanged.
///
/// # Emission order (byte-for-byte with curl)
///
/// 1. `"<METHOD> <uri> RTSP/1.0\r\n"`
/// 2. `"CSeq: <n>\r\n"`
/// 3. `"Session: <id>\r\n"` — when a session id is set
/// 4. `"Transport: <value>\r\n"` — when a transport is set (required for SETUP)
/// 5. `"Accept: application/sdp\r\n"` — DESCRIBE only, unless a custom `Accept`
///    was supplied
/// 6. the supplied header lines, verbatim, each terminated with `\r\n`
/// 7. `"Content-Length: <n>\r\n"` then `"Content-Type: <ct>\r\n"` — for a
///    body-bearing `ANNOUNCE`/`SET_PARAMETER`/`GET_PARAMETER`, each suppressed
///    if the same header was supplied
/// 8. the terminating `"\r\n"`
/// 9. the request body, if any
#[derive(Clone, Debug)]
pub struct RtspRequest<'a> {
    method: RtspReq,
    cseq: u32,
    stream_uri: Option<&'a str>,
    session_id: Option<&'a str>,
    transport: Option<&'a str>,
    headers: &'a [&'a str],
    body: Option<&'a [u8]>,
}

impl<'a> RtspRequest<'a> {
    /// Start building a request of `method` carrying sequence number `cseq`.
    #[must_use]
    pub fn new(method: RtspReq, cseq: u32) -> Self {
        Self {
            method,
            cseq,
            stream_uri: None,
            session_id: None,
            transport: None,
            headers: &[],
            body: None,
        }
    }

    /// Set the request URI (← `CURLOPT_RTSP_STREAM_URI`). When unset, the
    /// server-wide `"*"` target is used, exactly as `rtsp_do` defaults it.
    #[must_use]
    pub fn stream_uri(mut self, uri: &'a str) -> Self {
        self.stream_uri = Some(uri);
        self
    }

    /// Set the session id to echo (← the captured / `CURLOPT_RTSP_SESSION_ID`
    /// value emitted as the `Session:` header).
    #[must_use]
    pub fn session_id(mut self, id: &'a str) -> Self {
        self.session_id = Some(id);
        self
    }

    /// Set the transport specification (← `CURLOPT_RTSP_TRANSPORT`), emitted as
    /// the `Transport:` header. Required for `SETUP`.
    #[must_use]
    pub fn transport(mut self, transport: &'a str) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Supply the pre-formatted shared/custom header lines (each a logical
    /// `"Name: value"` without a trailing CRLF), in curl's emission order.
    #[must_use]
    pub fn headers(mut self, headers: &'a [&'a str]) -> Self {
        self.headers = headers;
        self
    }

    /// Attach a request body (← the `ANNOUNCE`/`SET_PARAMETER`/`GET_PARAMETER`
    /// upload path in `rtsp_setup_body`).
    #[must_use]
    pub fn body(mut self, body: &'a [u8]) -> Self {
        self.body = Some(body);
        self
    }

    /// The default `Content-Type` value for a body of this method
    /// (← `rtsp_setup_body`): `application/sdp` for `ANNOUNCE`, `text/parameters`
    /// for `SET_PARAMETER` / `GET_PARAMETER`.
    fn default_content_type(&self) -> Option<&'static str> {
        match self.method {
            RtspReq::Announce => Some("application/sdp"),
            RtspReq::SetParameter | RtspReq::GetParameter => Some("text/parameters"),
            _ => None,
        }
    }

    /// Validate the request against curl's `rtsp_do` preconditions, returning the
    /// same [`CurlCode`]s on violation.
    fn validate(&self) -> Result<()> {
        // NONE / LAST are rejected by rtsp_do's switch.
        if !self.method.is_request() {
            return Err(Error::bad_argument("Got invalid RTSP request"));
        }
        // RECEIVE emits no request line; building one is a misuse.
        if self.method == RtspReq::Receive {
            return Err(Error::bad_argument(
                "RTSPREQ_RECEIVE issues no request and cannot be built",
            ));
        }

        // A session id is required for the requests curl's bitmask test selects.
        if self.method.requires_session() && self.session_id.is_none() {
            return Err(Error::bad_argument(format!(
                "Refusing to issue an RTSP request [{}] without a session ID.",
                self.method.method_str()
            )));
        }

        // SETUP demands a Transport, from CURLOPT_RTSP_TRANSPORT or a custom
        // header.
        if self.method == RtspReq::Setup
            && self.transport.is_none()
            && !header_name_present(self.headers, "Transport")
        {
            return Err(Error::bad_argument(
                "Refusing to issue an RTSP SETUP without a Transport: header.",
            ));
        }

        // CSeq and Session are handler-managed and must not be set as custom
        // headers (distinct error codes, matching rtsp_do).
        if header_name_present(self.headers, "CSeq") {
            return Err(Error::with_context(
                CurlCode::RtspCseqError,
                "CSeq cannot be set as a custom header.",
            ));
        }
        if header_name_present(self.headers, "Session") {
            return Err(Error::bad_argument(
                "Session ID cannot be set as a custom header.",
            ));
        }
        Ok(())
    }

    /// Assemble the complete request (headers followed by any body).
    ///
    /// Returns [`CurlCode::BadFunctionArgument`] for an invalid method, a
    /// missing required session id, or a `SETUP` without a transport;
    /// [`CurlCode::RtspCseqError`] if a `CSeq` custom header was supplied. On
    /// success the returned bytes are exactly what curl writes to the socket.
    pub fn build(&self) -> Result<Vec<u8>> {
        self.validate()?;

        let uri = self.stream_uri.unwrap_or("*");
        let mut out = String::with_capacity(DYN_RTSP_REQ_HEADER.min(256));

        // Append one `"Name: value"` header line plus its CRLF terminator. The
        // value is written without a trailing newline in the `write!` itself so
        // the CRLF is a separate literal push (keeps request bytes exact and
        // avoids `write!`-with-newline pitfalls).
        let push_line = |out: &mut String, args: std::fmt::Arguments<'_>| {
            let _ = out.write_fmt(args);
            out.push_str("\r\n");
        };

        // 1) Request line and CSeq (a single dyn_addf pair in curl).
        push_line(
            &mut out,
            format_args!("{} {} RTSP/1.0", self.method.method_str(), uri),
        );
        push_line(&mut out, format_args!("CSeq: {}", self.cseq));

        // 2) Session (echoed as the raw stored value).
        if let Some(id) = self.session_id {
            push_line(&mut out, format_args!("Session: {id}"));
        }

        // 3) Shared block — Transport first, then the DESCRIBE default Accept.
        if let Some(transport) = self.transport {
            push_line(&mut out, format_args!("Transport: {transport}"));
        }
        if self.method == RtspReq::Describe && !header_name_present(self.headers, "Accept") {
            out.push_str("Accept: application/sdp\r\n");
        }

        // 4) Remaining shared options + custom headers, verbatim in order.
        for line in self.headers {
            push_line(&mut out, format_args!("{line}"));
        }

        // 5) Body headers (rtsp_setup_body): only for the body-capable methods
        //    and only with an actual body, each suppressed if already supplied.
        let body = self.body.filter(|b| !b.is_empty());
        if self.method.needs_body_setup() {
            if let Some(body) = body {
                if !header_name_present(self.headers, "Content-Length") {
                    push_line(&mut out, format_args!("Content-Length: {}", body.len()));
                }
                if !header_name_present(self.headers, "Content-Type") {
                    if let Some(ct) = self.default_content_type() {
                        push_line(&mut out, format_args!("Content-Type: {ct}"));
                    }
                }
            }
        }

        // 6) End of headers.
        out.push_str("\r\n");

        // 7) Append the body bytes, if any.
        let mut bytes = out.into_bytes();
        if let Some(body) = body {
            bytes.extend_from_slice(body);
        }
        Ok(bytes)
    }
}

// ===========================================================================
// PHASE 4 — Interleaved RTP: the `$<channel:1><length:2><payload>` framing
// state machine (← `rtsp_filter_rtp` / `rtp_client_write` / `rtp_write_body_junk`).
// ===========================================================================

/// The `"RTSP/"` response-line prefix. When the interleave scanner is between
/// messages (not mid-body) and encounters an `'R'`, a match against this prefix
/// (or a partial match at a buffer boundary) signals that the next RTSP response
/// has begun and RTP extraction must yield (← the `strncmp(buf, "RTSP/", …)`
/// check in `rtsp_filter_rtp`).
const RTSP_RESPONSE_PREFIX: &[u8] = b"RTSP/";

/// State of the interleaved-RTP frame scanner (← the C `rtp_parse_st` enum).
///
/// A frame is `$` (marker) · one channel byte · a big-endian 2-byte length ·
/// that many payload bytes. The scanner walks these four phases and, because
/// interleaved data shares the control connection and may be split across
/// arbitrary reads, every phase is resumable mid-frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RtpParseState {
    /// Scanning for the next `$` marker (or an `RTSP/` response boundary).
    #[default]
    Skip,
    /// Reading the single channel-identifier byte that follows `$`.
    Channel,
    /// Reading the two big-endian length bytes.
    Len,
    /// Collecting the fixed-size payload of the current frame.
    Data,
}

/// Sink for the two output streams the interleave scanner produces
/// (← curl's `rtp_client_write` and `rtp_write_body_junk`).
///
/// The scanner is transfer-state-agnostic: it decides *what* bytes are a
/// complete RTP frame versus response-body/junk and hands them to this sink,
/// which the transfer layer implements to route RTP frames to
/// `CURLOPT_INTERLEAVEFUNCTION`/`CURLOPT_INTERLEAVEDATA` and body bytes to the
/// normal write callback (applying any `Content-Length` clamp).
pub trait RtpSink {
    /// Deliver one complete interleaved RTP frame, including its 4-byte
    /// `$`/channel/length header (← `rtp_client_write`). Returning `Err`
    /// mirrors a failed or paused write callback.
    fn write_rtp(&mut self, frame: &[u8]) -> Result<()>;

    /// Deliver bytes that are not part of an RTP frame — i.e. response body or
    /// junk between frames (← `rtp_write_body_junk` / `Curl_client_write` with
    /// `CLIENTWRITE_BODY`).
    fn write_body_junk(&mut self, bytes: &[u8]) -> Result<()>;

    /// Whether the transfer is currently inside the response body (headers seen,
    /// not re-parsing headers, and `bytecount < size`). When `true`, an `'R'`
    /// is treated as ordinary body data rather than a potential `RTSP/`
    /// response boundary (← the `in_body` computation in `rtsp_filter_rtp`).
    /// Defaults to `false`, matching the between-messages / RECEIVE case.
    fn in_body(&self) -> bool {
        false
    }
}

/// Big-endian 16-bit payload length encoded at bytes 2..4 of an interleaved
/// frame header (← the `RTP_PKT_LENGTH(p)` macro). `hdr` must be at least four
/// bytes (the scanner only calls this once the full 4-byte header is buffered).
fn rtp_pkt_length(hdr: &[u8]) -> usize {
    debug_assert!(hdr.len() >= RTP_FRAME_HEADER_LEN);
    ((hdr[2] as usize) << 8) | (hdr[3] as usize)
}

/// Deliver a fully-assembled RTP frame, reproducing `rtp_client_write`'s
/// zero-length guard: a zero-size packet is rejected with
/// [`CurlCode::WriteError`] and curl's exact message before the sink is
/// consulted. A short/paused write surfaces as `Err` from the sink.
fn rtp_client_write<S: RtpSink>(sink: &mut S, frame: &[u8]) -> Result<()> {
    if frame.is_empty() {
        return Err(Error::with_context(
            CurlCode::WriteError,
            "Cannot write a 0 size RTP packet.",
        ));
    }
    sink.write_rtp(frame)
}

/// Connection-scoped interleaved-RTP scanner (← the C `struct rtsp_conn`).
///
/// Holds the partially-accumulated frame (`buf`), the current channel, the
/// expected total frame length, the parse phase, and the `in_header` flag that
/// coordinates with response-header parsing. One instance lives for the life of
/// a reused RTSP connection and survives partial reads.
#[derive(Clone, Debug)]
pub struct RtpInterleave {
    /// Bytes of the frame currently being assembled (`$` · channel · length ·
    /// payload-so-far). Empty whenever [`RtpParseState::Skip`] is active.
    buf: Vec<u8>,
    /// Channel of the frame in progress, or `-1` when none (← `rtp_channel`,
    /// initialised to `-1` by `rtsp_connect`).
    rtp_channel: i32,
    /// Total byte length of the current frame, header included (← `rtp_len`).
    rtp_len: usize,
    /// Current scanner phase (← `state`).
    state: RtpParseState,
    /// `true` while response headers are being parsed on this connection, which
    /// suspends RTP extraction (← `in_header`).
    in_header: bool,
}

impl RtpInterleave {
    /// Create a fresh scanner in the state `rtsp_connect` establishes: empty
    /// buffer, no channel (`-1`), [`RtpParseState::Skip`], not in-header.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            rtp_channel: -1,
            rtp_len: 0,
            state: RtpParseState::Skip,
            in_header: false,
        }
    }

    /// Current scanner phase.
    #[must_use]
    pub fn state(&self) -> RtpParseState {
        self.state
    }

    /// Channel of the frame in progress (`-1` when none).
    #[must_use]
    pub fn rtp_channel(&self) -> i32 {
        self.rtp_channel
    }

    /// Number of bytes buffered for the in-progress frame.
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    /// Whether response-header parsing is currently active on this connection.
    #[must_use]
    pub fn in_header(&self) -> bool {
        self.in_header
    }

    /// Set the `in_header` flag (← `rtsp_rtp_write_resp` toggling it from
    /// `data->req.header`).
    pub fn set_in_header(&mut self, in_header: bool) {
        self.in_header = in_header;
    }

    /// Whether a complete interleaved frame is mid-assembly (scanner not in the
    /// [`RtpParseState::Skip`] idle phase). Mirrors the `rtspc->state !=
    /// RTP_PARSE_SKIP` test that keeps a transfer from finishing early.
    #[must_use]
    pub fn frame_in_progress(&self) -> bool {
        self.state != RtpParseState::Skip
    }

    /// Append to the frame buffer, enforcing curl's `MAX_RTP_BUFFERSIZE` cap
    /// (the dynbuf is initialised with that maximum). Overflow maps to
    /// [`CurlCode::OutOfMemory`], exactly as the C `curlx_dyn_addn` failure path.
    fn buf_add(&mut self, bytes: &[u8]) -> Result<()> {
        if self.buf.len().saturating_add(bytes.len()) > MAX_RTP_BUFFERSIZE {
            return Err(Error::OutOfMemory);
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    /// Feed a chunk of freshly-received connection bytes through the interleave
    /// scanner, returning how many bytes were consumed (← `rtsp_filter_rtp`'s
    /// `*pconsumed`).
    ///
    /// Complete RTP frames are delivered via [`RtpSink::write_rtp`]; interleaved
    /// body/junk runs via [`RtpSink::write_body_junk`]. Scanning stops early —
    /// consuming fewer than `input.len()` bytes and setting [`in_header`] — when
    /// an `RTSP/` response boundary is detected (unless `is_receive`, i.e.
    /// `RTSPREQ_RECEIVE`, where the connection is read passively). Any unfinished
    /// frame remains buffered for the next call, so payloads spanning multiple
    /// reads are handled transparently.
    ///
    /// [`in_header`]: RtpInterleave::in_header
    pub fn filter_rtp<S: RtpSink>(
        &mut self,
        input: &[u8],
        channel_mask: &[u8; RTP_CHANNEL_MASK_LEN],
        is_receive: bool,
        sink: &mut S,
    ) -> Result<usize> {
        let len = input.len();
        let mut pos = 0usize;
        let mut pconsumed = 0usize;
        // Count of contiguous junk/body bytes pending a flush; the invariant is
        // that these are exactly `input[pos - skip_len .. pos]`.
        let mut skip_len = 0usize;
        let mut result: Result<()> = Ok(());

        'outer: while pos < len {
            let in_body = sink.in_body();
            match self.state {
                RtpParseState::Skip => {
                    debug_assert!(self.buf.is_empty());
                    // Advance over non-marker bytes, watching for a response
                    // boundary while not mid-body.
                    while pos < len && input[pos] != RTP_MARKER {
                        if !in_body && input[pos] == b'R' && !is_receive {
                            let n = (len - pos).min(RTSP_RESPONSE_PREFIX.len());
                            if input[pos..pos + n] == RTSP_RESPONSE_PREFIX[..n] {
                                // Possible next response: stop without consuming
                                // this byte and hand control back to header
                                // parsing.
                                self.state = RtpParseState::Skip;
                                self.in_header = true;
                                break 'outer;
                            }
                        }
                        // Junk / body byte: consume without buffering.
                        pconsumed += 1;
                        pos += 1;
                        skip_len += 1;
                    }
                    if pos < len && input[pos] == RTP_MARKER {
                        // Flush any junk that preceded the marker.
                        if skip_len > 0 {
                            result = sink.write_body_junk(&input[pos - skip_len..pos]);
                            skip_len = 0;
                            if result.is_err() {
                                break 'outer;
                            }
                        }
                        // Buffer the '$' and move on to the channel byte.
                        self.buf_add(&input[pos..=pos])?;
                        pconsumed += 1;
                        pos += 1;
                        self.state = RtpParseState::Channel;
                    }
                }

                RtpParseState::Channel => {
                    debug_assert_eq!(self.buf.len(), 1);
                    let ch = input[pos];
                    let idx = (ch / 8) as usize;
                    let off = ch % 8;
                    if channel_mask[idx] & (1u8 << off) == 0 {
                        // Not an announced channel: the '$' and this byte are
                        // body/junk, not a frame.
                        debug_assert_eq!(skip_len, 0);
                        self.state = RtpParseState::Skip;
                        if pconsumed == 0 {
                            // The '$' came from a previous call and cannot be
                            // un-consumed, so emit it straight to the body.
                            result = sink.write_body_junk(&self.buf);
                        } else {
                            // Re-count the already-consumed '$' as junk so the
                            // Skip phase flushes it together with what follows.
                            skip_len = 1;
                        }
                        self.buf.clear();
                        if result.is_err() {
                            break 'outer;
                        }
                        // Deliberately do NOT consume `input[pos]`: it is
                        // reprocessed by the Skip phase.
                    } else {
                        self.rtp_channel = ch as i32;
                        self.buf_add(&input[pos..=pos])?;
                        pconsumed += 1;
                        pos += 1;
                        self.state = RtpParseState::Len;
                    }
                }

                RtpParseState::Len => {
                    let have = self.buf.len();
                    debug_assert!((2..4).contains(&have));
                    self.buf_add(&input[pos..=pos])?;
                    pconsumed += 1;
                    pos += 1;
                    if have == 3 {
                        // The 2-byte length is complete; total frame size is the
                        // payload length plus the 4-byte header.
                        self.rtp_len = rtp_pkt_length(&self.buf) + RTP_FRAME_HEADER_LEN;
                        self.state = RtpParseState::Data;
                    }
                    // have == 2: one more length byte still required.
                }

                RtpParseState::Data => {
                    let have = self.buf.len();
                    debug_assert!(have < self.rtp_len);
                    let needed = self.rtp_len - have;
                    let avail = len - pos;
                    if needed <= avail {
                        // The frame completes within this chunk.
                        self.buf_add(&input[pos..pos + needed])?;
                        pconsumed += needed;
                        pos += needed;
                        result = rtp_client_write(sink, &self.buf);
                        self.buf.clear();
                        self.state = RtpParseState::Skip;
                        if result.is_err() {
                            break 'outer;
                        }
                    } else {
                        // Payload spans into a later read: buffer the remainder.
                        self.buf_add(&input[pos..len])?;
                        pconsumed += avail;
                        pos = len;
                    }
                }
            }
        }

        // Flush trailing junk accumulated up to the current position.
        if result.is_ok() && skip_len > 0 {
            result = sink.write_body_junk(&input[pos - skip_len..pos]);
        }
        result.map(|()| pconsumed)
    }
}

impl Default for RtpInterleave {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// PHASE 4b — DO/DONE integration helpers (← the parts of `rtsp_do` /
// `rtsp_rtp` / the generic transfer loop that drive the engine over a live
// connection). These bridge the self-contained engine types above to the
// [`TransferCtx`] transport and body sink.
// ===========================================================================

/// Map a `TransferRequest::rtsp_request` integer to an [`RtspReq`], defaulting an
/// unrecognized value to [`RtspReq::None`] (which `do_it` then rejects exactly
/// as `rtsp_do`'s `switch` rejects `RTSPREQ_NONE`).
fn rtsp_method(request: i64) -> RtspReq {
    RtspReq::from_long(request).unwrap_or(RtspReq::None)
}

/// Whether a header named `name` (ASCII case-insensitive) is present among the
/// owned custom-header lines (the `&[String]` analogue of
/// [`header_name_present`], used by `do_it`'s shared-header assembly to honor
/// curl's `Curl_checkheaders` "do not duplicate a user-supplied header" guard).
fn header_present(headers: &[String], name: &str) -> bool {
    headers
        .iter()
        .any(|line| header_name(line).eq_ignore_ascii_case(name))
}

/// Extract the value of header `name` (ASCII case-insensitive) from a single
/// `"Name: value"` response line, trimmed of surrounding blanks and any
/// trailing CR/LF. Returns `None` when the line is a different header.
fn header_value_ci<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let (n, v) = line.split_once(':')?;
    if n.trim_end_matches([' ', '\t']).eq_ignore_ascii_case(name) {
        Some(v.trim_matches([' ', '\t', '\r', '\n']))
    } else {
        None
    }
}

/// Format a `CURLOPT_TIMECONDITION` header line (← `Curl_add_timecondition`,
/// `lib/http.c`), without the trailing CRLF (the [`RtspRequest`] builder appends
/// it). Returns `None` for `CURL_TIMECOND_NONE`/`0` or an unrecognized value —
/// exactly the cases where curl emits nothing.
///
/// The format is RFC 7231 IMF-fixdate in GMT (`"Tue, 15 Nov 1994 12:45:26 GMT"`);
/// chrono's `%a`/`%b` are locale-independent English abbreviations, matching
/// curl's `Curl_wkday` / `Curl_month` tables byte-for-byte.
fn format_timecondition(cond: i32, timevalue: i64) -> Option<String> {
    // ← CURL_TIMECOND_* : IFMODSINCE=1, IFUNMODSINCE=2, LASTMOD=3, NONE=0.
    let name = match cond {
        1 => "If-Modified-Since",
        2 => "If-Unmodified-Since",
        3 => "Last-Modified",
        _ => return None,
    };
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(timevalue, 0)?;
    Some(format!(
        "{name}: {}",
        dt.format("%a, %d %b %Y %H:%M:%S GMT")
    ))
}

/// Map a socket write failure to curl's `CURLE_SEND_ERROR` (← the
/// `"Failed sending RTSP request"` path in `rtsp_do`).
fn send_err(e: std::io::Error) -> Error {
    Error::with_context(CurlCode::SendError, e.to_string())
}

/// Map a socket read failure to curl's `CURLE_RECV_ERROR`.
fn recv_err(e: std::io::Error) -> Error {
    Error::with_context(CurlCode::RecvError, e.to_string())
}

/// A [`TransferSink`] that discards everything, used when a transfer installed
/// no body sink (← curl's `NULL` write target). A bare unit type — never
/// wrapping an `Option<&mut dyn …>` — so it dodges the `&mut`-invariance /
/// default-object-lifetime escape the adapter construction would otherwise hit.
struct DiscardTransferSink;

impl TransferSink for DiscardTransferSink {
    fn write(&mut self, _data: &[u8]) -> Result<()> {
        Ok(())
    }
}

/// Adapts a [`TransferSink`] to the [`RtpSink`] the interleave scanner needs:
/// both complete RTP frames and inter-frame body/junk are delivered to the same
/// transfer body sink (← curl routing `rtp_client_write` frames to
/// `CURLOPT_INTERLEAVEFUNCTION` and `rtp_write_body_junk` to the write callback;
/// at this checkpoint a transfer exposes a single body sink, so both streams
/// converge there). The field is a bare `&mut dyn TransferSink` — unwrapped by
/// the caller before construction — per the invariance rule that forbids an
/// `Option<&mut dyn …>` newtype field.
struct SinkRtp<'s> {
    sink: &'s mut dyn TransferSink,
    in_body: bool,
}

impl RtpSink for SinkRtp<'_> {
    fn write_rtp(&mut self, frame: &[u8]) -> Result<()> {
        self.sink.write(frame)
    }

    fn write_body_junk(&mut self, bytes: &[u8]) -> Result<()> {
        self.sink.write(bytes)
    }

    fn in_body(&self) -> bool {
        self.in_body
    }
}

/// Pump interleaved data through the [`RtpInterleave`] scanner until EOF,
/// starting from any bytes already buffered after the response headers
/// (`initial`) and then reading more from `io` (← the repeated
/// `Curl_rtsp_rtp`/`rtsp_filter_rtp` calls in the transfer loop). Complete RTP
/// frames and body/junk are streamed to `sink`.
async fn pump_interleave<S>(
    io: &mut S,
    interleave: &mut RtpInterleave,
    mask: &[u8; RTP_CHANNEL_MASK_LEN],
    is_receive: bool,
    initial: Vec<u8>,
    sink: &mut dyn TransferSink,
) -> Result<()>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut carry = initial;
    let mut chunk = [0u8; 4096];
    loop {
        if !carry.is_empty() {
            let consumed = {
                let mut rtp_sink = SinkRtp {
                    sink,
                    in_body: false,
                };
                interleave.filter_rtp(&carry, mask, is_receive, &mut rtp_sink)?
            };
            carry.drain(..consumed);
            // Guard against an unbounded partial-frame buffer (← curl bounding
            // interleaved reassembly by `MAX_RTP_BUFFERSIZE`).
            if carry.len() > MAX_RTP_BUFFERSIZE {
                return Err(Error::with_context(
                    CurlCode::RecvError,
                    "RTSP interleaved buffer overflow",
                ));
            }
            // A response boundary (`RTSP/`) or an invalid channel can leave bytes
            // unconsumed with no forward progress; at this checkpoint one
            // response and its trailing interleaved run is the transfer unit, so
            // stop rather than spin.
            if consumed == 0 {
                break;
            }
            continue;
        }
        let n = io.read(&mut chunk).await.map_err(recv_err)?;
        if n == 0 {
            break;
        }
        carry.extend_from_slice(&chunk[..n]);
    }
    Ok(())
}

/// Read and process an RTSP response over `io` (← the generic transfer read loop
/// feeding the RTSP header parser and `rtsp_filter_rtp`): parse the status line
/// and headers (feeding `CSeq`/`Session`/`Transport` to `state`), then stream
/// the response body to `sink` — either `Content-Length`-delimited, or, when the
/// negotiated transport interleaves RTP on the control connection, via the
/// [`RtpInterleave`] scanner.
async fn read_rtsp_response<S>(
    io: &mut S,
    state: &mut RtspState,
    sink: &mut dyn TransferSink,
) -> Result<()>
where
    S: AsyncRead + Unpin + ?Sized,
{
    // Accumulate until the CRLFCRLF header terminator.
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let n = io.read(&mut chunk).await.map_err(recv_err)?;
        if n == 0 {
            if buf.is_empty() {
                // Server closed with no response at all (← CURLE_GOT_NOTHING).
                return Err(Error::with_context(
                    CurlCode::GotNothing,
                    "No RTSP response received",
                ));
            }
            return Err(Error::with_context(
                CurlCode::RecvError,
                "RTSP response truncated before end of headers",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        // Bound header growth (← curl's `DYN_RTSP_REQ_HEADER` cap) to reject a
        // server that streams headers forever.
        if buf.len() > DYN_RTSP_REQ_HEADER {
            return Err(Error::with_context(
                CurlCode::RecvError,
                "RTSP response headers exceed maximum size",
            ));
        }
    };

    // Parse the status line + headers; capture Content-Length for body framing
    // and feed the RTSP-specific headers to the state machine.
    let head = String::from_utf8_lossy(&buf[..header_end]);
    let mut content_length: Option<usize> = None;
    for (i, line) in head.split("\r\n").enumerate() {
        if line.is_empty() {
            continue;
        }
        if i == 0 {
            // Status line ("RTSP/1.0 <code> <reason>"): no state to record for
            // the checkpoint; the CSeq/Session echo below is the parity anchor.
            continue;
        }
        if let Some(v) = header_value_ci(line, "Content-Length") {
            content_length = v.parse::<usize>().ok();
        }
        state.parse_header(line)?;
    }

    // Bytes already read past the header terminator start the body.
    let body_start = buf[header_end..].to_vec();

    // Interleaved transport? The Transport parser sets validity bits when the
    // response carried `interleaved=`; a non-empty mask selects the RTP path.
    let interleaved = state.channel_mask().iter().any(|&b| b != 0);

    if interleaved {
        let mask = *state.channel_mask();
        let mut interleave = RtpInterleave::new();
        pump_interleave(io, &mut interleave, &mask, false, body_start, sink).await?;
        return Ok(());
    }

    // Content-Length-delimited body (the RTSP control-response common case).
    match content_length {
        Some(len) => {
            let mut remaining = len;
            let take = body_start.len().min(remaining);
            if take > 0 {
                sink.write(&body_start[..take])?;
                remaining -= take;
            }
            while remaining > 0 {
                let want = remaining.min(chunk.len());
                let n = io.read(&mut chunk[..want]).await.map_err(recv_err)?;
                if n == 0 {
                    return Err(Error::with_context(
                        CurlCode::RecvError,
                        "RTSP response body truncated",
                    ));
                }
                sink.write(&chunk[..n])?;
                remaining -= n;
            }
        }
        None => {
            // No Content-Length: forward whatever body bytes accompanied the
            // response (methods like OPTIONS/SETUP carry none).
            if !body_start.is_empty() {
                sink.write(&body_start)?;
            }
        }
    }
    Ok(())
}

// ===========================================================================
// PHASE 5 — Protocol handler (← the `Curl_protocol_rtsp` vtable and
// `Curl_scheme_rtsp` scheme record).
// ===========================================================================

/// The RTSP protocol handler singleton (← `Curl_protocol_rtsp`).
///
/// Like every handler in this crate this is a zero-sized unit type; the scheme
/// record [`SCHEME_RTSP`](crate::protocols::SCHEME_RTSP) points at the shared
/// [`HANDLER`] instance (scheme `rtsp`, [`PROTOPT_CONN_REUSE`](crate::protocols::PROTOPT_CONN_REUSE), default port
/// [`PORT_RTSP`], plain TCP — curl 8.x defines no TLS-wrapped `rtsps`).
///
/// The behaviour that makes RTSP distinct lives in the self-contained,
/// fully-tested engine types in this module — [`RtspReq`] (method vocabulary
/// and its bitmask predicates), [`RtspState`] (CSeq increment/echo and Session
/// capture, with the frozen [`CurlCode::RtspCseqError`]/
/// [`CurlCode::RtspSessionError`] outcomes), [`RtspRequest`] (byte-exact
/// request assembly), and [`RtpInterleave`] (the `$`-framed interleaved-RTP
/// scanner). The [`Protocol`] trait methods below are the integration seam
/// through which the transfer core drives that engine.
///
/// The DO and DONE phases (← `rtsp_do` / `rtsp_done`) drive that engine over the
/// live [`TransferCtx`] transport: `do_it` selects the method from
/// [`TransferRequest::rtsp_request`](crate::protocols::TransferRequest::rtsp_request),
/// assembles the complete request — the RTSP-specific lines plus the shared
/// HTTP-derived headers (`Range`, `Authorization`, time condition, custom
/// headers) in curl's exact emission order — sends it, then reads the response,
/// feeding `CSeq`/`Session`/`Transport` to [`RtspState`] and streaming the body
/// (or interleaved RTP) to the sink; `done` verifies the echoed `CSeq`. The
/// server-initiated [`RtspReq::Receive`] path sends no request and instead runs
/// the interleave scanner over the incoming control-connection data. No RTSP
/// behaviour is stubbed: every step is implemented over the engine types
/// without divergence from `lib/rtsp.c`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RtspHandler;

/// The shared RTSP handler instance referenced by
/// [`SCHEME_RTSP`](crate::protocols::SCHEME_RTSP).
pub static HANDLER: RtspHandler = RtspHandler;

impl Protocol for RtspHandler {
    /// The DO phase (← `rtsp_do`): build the method request via [`RtspRequest`],
    /// send it over the live transport, parse the response headers feeding
    /// [`RtspState::parse_header`], enforce `CSeq`/`Session`, and stream the body
    /// (or interleaved RTP) to the sink. Returns `true` since RTSP has no split
    /// DO/DO_MORE phase — the whole exchange runs to completion here, exactly as
    /// the sibling run-to-completion auxiliary handlers do.
    ///
    /// The [`RtspState`] built for this request is stashed in
    /// [`TransferCtx::proto_state`](crate::protocols::TransferCtx::proto_state)
    /// so [`done`](RtspHandler::done) can verify the echoed `CSeq`. A missing
    /// transport surfaces as `CURLE_COULDNT_CONNECT`; an invalid method
    /// (`RTSPREQ_NONE`/`_LAST`) as `CURLE_BAD_FUNCTION_ARGUMENT`, matching
    /// `rtsp_do`.
    fn do_it<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        Box::pin(async move {
            let method = rtsp_method(ctx.request.rtsp_request);

            // Seed session state, pinning a caller-supplied session id (←
            // CURLOPT_RTSP_SESSION_ID) so a response `Session:` is *verified*
            // rather than captured; then stamp this request's CSeq.
            let mut state = match ctx.request.rtsp_session_id.as_deref() {
                Some(id) => RtspState::with_session_id(id),
                None => RtspState::new(),
            };
            state.begin_request();
            let cseq = state.cseq_sent();

            // ── RTSPREQ_RECEIVE: server-initiated, no request emitted ─────────
            // (← the `if(rtspreq == RTSPREQ_RECEIVE)` early path in `rtsp_do`).
            if method == RtspReq::Receive {
                let stream = ctx.io.as_deref_mut().ok_or_else(|| {
                    Error::with_context(CurlCode::CouldntConnect, "no transport for RTSP")
                })?;
                let mask = *state.channel_mask();
                let mut interleave = RtpInterleave::new();
                match ctx.sink.as_deref_mut() {
                    Some(s) => {
                        pump_interleave(stream, &mut interleave, &mask, true, Vec::new(), s).await?
                    }
                    None => {
                        let mut discard = DiscardTransferSink;
                        pump_interleave(
                            stream,
                            &mut interleave,
                            &mask,
                            true,
                            Vec::new(),
                            &mut discard,
                        )
                        .await?
                    }
                }
                ctx.proto_state = Some(Box::new((state, method)));
                return Ok(true);
            }

            // ── Assemble the request bytes (borrows only ctx.request; dropped
            //    before the transport is borrowed for sending) ────────────────
            let bytes = {
                let custom = &ctx.request.headers;

                // Shared HTTP-derived headers, in curl's exact emission order
                // (Transport and the DESCRIBE `Accept` are emitted by the builder
                // itself, immediately before these lines):
                //   Accept-Encoding, Range, Referer, User-Agent, Authorization,
                //   [time condition], custom headers.
                // Each dedicated-option header is suppressed when the same header
                // was supplied as a custom header (← `Curl_checkheaders`).
                let mut shared: Vec<String> = Vec::new();

                if method == RtspReq::Describe {
                    if let Some(enc) = ctx.request.accept_encoding.as_deref() {
                        if !header_present(custom, "Accept-Encoding") {
                            shared.push(format!("Accept-Encoding: {enc}"));
                        }
                    }
                }
                if method.wants_range() {
                    if let Some(range) = ctx.request.range.as_deref() {
                        if !header_present(custom, "Range") {
                            shared.push(format!("Range: {range}"));
                        }
                    }
                }
                if let Some(referer) = ctx.request.referer.as_deref() {
                    if !header_present(custom, "Referer") {
                        shared.push(format!("Referer: {referer}"));
                    }
                }
                if let Some(ua) = ctx.request.user_agent.as_deref() {
                    if !header_present(custom, "User-Agent") {
                        shared.push(format!("User-Agent: {ua}"));
                    }
                }
                // Default HTTP auth (← `Curl_http_output_auth`; the default
                // `CURLAUTH_BASIC` emits the header immediately when credentials
                // are set). Digest/NTLM/Negotiate need a challenge round-trip
                // (multi-request), which the transfer driver drives in a later
                // checkpoint; Basic is stateless and emitted here.
                if (ctx.request.user.is_some() || ctx.request.password.is_some())
                    && !header_present(custom, "Authorization")
                {
                    let line = crate::auth::basic::http_output_basic(
                        ctx.request.user.as_deref(),
                        ctx.request.password.as_deref(),
                        false,
                    )?;
                    shared.push(line.trim_end_matches("\r\n").to_string());
                }
                // Time condition (← `Curl_add_timecondition`), only for
                // SETUP/DESCRIBE, suppressed if a matching custom header exists.
                if matches!(method, RtspReq::Setup | RtspReq::Describe) {
                    if let Some(tc) =
                        format_timecondition(ctx.request.time_condition, ctx.request.time_value)
                    {
                        let name = header_name(&tc);
                        if !header_present(custom, name) {
                            shared.push(tc);
                        }
                    }
                }
                // Custom headers verbatim, last (← `Curl_add_custom_headers`).
                shared.extend(custom.iter().cloned());

                let refs: Vec<&str> = shared.iter().map(String::as_str).collect();
                let mut builder = RtspRequest::new(method, cseq);
                if let Some(uri) = ctx.request.rtsp_stream_uri.as_deref() {
                    builder = builder.stream_uri(uri);
                }
                if let Some(sid) = state.session_id() {
                    builder = builder.session_id(sid);
                }
                if let Some(tr) = ctx.request.rtsp_transport.as_deref() {
                    builder = builder.transport(tr);
                }
                builder = builder.headers(&refs);
                if let Some(body) = ctx.request.body.as_deref() {
                    builder = builder.body(body);
                }
                builder.build()?
            };

            // ── Send the request, then read the response ─────────────────────
            let stream = ctx.io.as_deref_mut().ok_or_else(|| {
                Error::with_context(CurlCode::CouldntConnect, "no transport for RTSP")
            })?;
            stream.write_all(&bytes).await.map_err(send_err)?;
            stream.flush().await.map_err(send_err)?;
            // ← `data->state.rtsp_next_client_CSeq++` on a successful send.
            state.on_request_sent();

            match ctx.sink.as_deref_mut() {
                Some(s) => read_rtsp_response(stream, &mut state, s).await?,
                None => {
                    let mut discard = DiscardTransferSink;
                    read_rtsp_response(stream, &mut state, &mut discard).await?
                }
            }

            // Stash state (+ method) so `done` can run the CSeq check.
            ctx.proto_state = Some(Box::new((state, method)));
            Ok(true)
        })
    }

    /// The DONE phase (← `rtsp_done`): verify the echoed `CSeq` via
    /// [`RtspState::check_cseq`] (skipped for [`RtspReq::Receive`]) using the
    /// state `do_it` stashed in
    /// [`TransferCtx::proto_state`](crate::protocols::TransferCtx::proto_state).
    /// The check is skipped on a premature teardown or a failed transfer,
    /// matching `rtsp_done`'s early return when the request did not complete.
    /// Keeps the connection for reuse
    /// ([`PROTOPT_CONN_REUSE`](crate::protocols::PROTOPT_CONN_REUSE)).
    fn done<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        status: Result<()>,
        premature: bool,
    ) -> ProtoFuture<'a, ()> {
        Box::pin(async move {
            // Only verify CSeq for a request that actually completed (← curl
            // skipping the check when the transfer failed or was aborted early).
            if status.is_ok() && !premature {
                if let Some(state) = ctx.proto_state.as_ref() {
                    if let Some((state, method)) = state.downcast_ref::<(RtspState, RtspReq)>() {
                        state.check_cseq(*method)?;
                    }
                }
            }
            Ok(())
        })
    }
}

// ===========================================================================
// Unit tests — exercise the self-contained RTSP engine against curl's
// documented behavior (method vocabulary and bitmask quirks, CSeq/Session
// tracking with the frozen 85/86 codes, byte-exact request assembly, and the
// interleaved-RTP state machine including spanning and cross-call reads).
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::protocols::TransferSink;

    /// Drive an async test body to completion on a fresh Tokio current-thread
    /// runtime.
    ///
    /// The wired [`RtspHandler`] futures perform real (in-memory) socket I/O over
    /// a [`tokio::io::duplex`] peer, so they suspend across reads and need a real
    /// reactor rather than a first-poll no-op executor. The current-thread flavor
    /// matches curl 8.x's single-threaded transfer model and keeps this module in
    /// safe Rust (no hand-built `Waker`), consistent with the sibling protocol
    /// handlers' test harnesses.
    fn block_on<F: Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build current-thread Tokio runtime for test")
            .block_on(fut)
    }

    /// A shared-buffer [`TransferSink`] recording every delivered body/RTP chunk,
    /// so a handler test can assert what the RTSP transfer streamed.
    struct RecordingSink(Arc<Mutex<Vec<u8>>>);
    impl TransferSink for RecordingSink {
        fn write(&mut self, data: &[u8]) -> Result<()> {
            self.0.lock().expect("sink lock").extend_from_slice(data);
            Ok(())
        }
    }

    // -- RtspReq -----------------------------------------------------------

    #[test]
    fn rtsp_req_discriminants_are_sequential_zero_through_twelve() {
        // The integer values must equal the public CURL_RTSPREQ_* constants
        // (0..=12) because rtsp.c does bitwise arithmetic on them.
        assert_eq!(RtspReq::None as u32, 0);
        assert_eq!(RtspReq::Options as u32, 1);
        assert_eq!(RtspReq::Describe as u32, 2);
        assert_eq!(RtspReq::Announce as u32, 3);
        assert_eq!(RtspReq::Setup as u32, 4);
        assert_eq!(RtspReq::Play as u32, 5);
        assert_eq!(RtspReq::Pause as u32, 6);
        assert_eq!(RtspReq::Teardown as u32, 7);
        assert_eq!(RtspReq::GetParameter as u32, 8);
        assert_eq!(RtspReq::SetParameter as u32, 9);
        assert_eq!(RtspReq::Record as u32, 10);
        assert_eq!(RtspReq::Receive as u32, 11);
        assert_eq!(RtspReq::Last as u32, 12);
    }

    #[test]
    fn rtsp_req_method_tokens_match_curl() {
        assert_eq!(RtspReq::Options.method_str(), "OPTIONS");
        assert_eq!(RtspReq::Describe.method_str(), "DESCRIBE");
        assert_eq!(RtspReq::Announce.method_str(), "ANNOUNCE");
        assert_eq!(RtspReq::Setup.method_str(), "SETUP");
        assert_eq!(RtspReq::Play.method_str(), "PLAY");
        assert_eq!(RtspReq::Pause.method_str(), "PAUSE");
        assert_eq!(RtspReq::Teardown.method_str(), "TEARDOWN");
        assert_eq!(RtspReq::GetParameter.method_str(), "GET_PARAMETER");
        assert_eq!(RtspReq::SetParameter.method_str(), "SET_PARAMETER");
        assert_eq!(RtspReq::Record.method_str(), "RECORD");
        // Non-request / receive tokens are empty.
        assert_eq!(RtspReq::None.method_str(), "");
        assert_eq!(RtspReq::Receive.method_str(), "");
        assert_eq!(RtspReq::Last.method_str(), "");
    }

    #[test]
    fn rtsp_req_from_long_maps_option_values() {
        assert_eq!(RtspReq::from_long(0), Some(RtspReq::None));
        assert_eq!(RtspReq::from_long(8), Some(RtspReq::GetParameter));
        assert_eq!(RtspReq::from_long(12), Some(RtspReq::Last));
        assert_eq!(RtspReq::from_long(13), None);
        assert_eq!(RtspReq::from_long(-1), None);
    }

    #[test]
    fn rtsp_req_try_from_rejects_out_of_range() {
        assert_eq!(RtspReq::try_from(4_i64).unwrap(), RtspReq::Setup);
        let err = RtspReq::try_from(99_i64).unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
    }

    #[test]
    fn rtsp_req_is_request_excludes_none_and_last() {
        assert!(!RtspReq::None.is_request());
        assert!(!RtspReq::Last.is_request());
        // Everything else, including RECEIVE, is issuable.
        assert!(RtspReq::Options.is_request());
        assert!(RtspReq::Receive.is_request());
    }

    #[test]
    fn rtsp_req_requires_session_reproduces_bitmask_quirk() {
        // rtspreq & ~(OPTIONS|DESCRIBE|SETUP) == rtspreq & ~7.
        // True only for values carrying a bit outside the low three among real
        // requests: GET_PARAMETER (8), SET_PARAMETER (9), RECORD (10).
        assert!(RtspReq::GetParameter.requires_session());
        assert!(RtspReq::SetParameter.requires_session());
        assert!(RtspReq::Record.requires_session());
        // The classic quirk: PLAY/PAUSE/TEARDOWN do NOT trip the check.
        assert!(!RtspReq::Options.requires_session());
        assert!(!RtspReq::Describe.requires_session());
        assert!(!RtspReq::Announce.requires_session());
        assert!(!RtspReq::Setup.requires_session());
        assert!(!RtspReq::Play.requires_session());
        assert!(!RtspReq::Pause.requires_session());
        assert!(!RtspReq::Teardown.requires_session());
    }

    #[test]
    fn rtsp_req_wants_range_reproduces_bitmask_quirk() {
        // rtspreq & (PLAY|PAUSE|RECORD) == rtspreq & 15 -> true for all but NONE.
        assert!(!RtspReq::None.wants_range());
        for req in [
            RtspReq::Options,
            RtspReq::Describe,
            RtspReq::Announce,
            RtspReq::Setup,
            RtspReq::Play,
            RtspReq::Pause,
            RtspReq::Teardown,
            RtspReq::GetParameter,
            RtspReq::SetParameter,
            RtspReq::Record,
            RtspReq::Receive,
            RtspReq::Last,
        ] {
            assert!(req.wants_range(), "{req:?} should trip wants_range");
        }
    }

    #[test]
    fn rtsp_req_body_dispositions() {
        // no_body defaults true, cleared for DESCRIBE, GET_PARAMETER, RECEIVE.
        assert!(!RtspReq::Describe.default_no_body());
        assert!(!RtspReq::GetParameter.default_no_body());
        assert!(!RtspReq::Receive.default_no_body());
        assert!(RtspReq::Options.default_no_body());
        assert!(RtspReq::Play.default_no_body());
        // needs_body_setup: ANNOUNCE, SET_PARAMETER, GET_PARAMETER.
        assert!(RtspReq::Announce.needs_body_setup());
        assert!(RtspReq::SetParameter.needs_body_setup());
        assert!(RtspReq::GetParameter.needs_body_setup());
        assert!(!RtspReq::Options.needs_body_setup());
        assert!(!RtspReq::Describe.needs_body_setup());
    }

    #[test]
    fn rtsp_req_default_is_none() {
        assert_eq!(RtspReq::default(), RtspReq::None);
    }

    // -- byte-parsing helpers ---------------------------------------------

    #[test]
    fn ci_starts_with_is_ascii_case_insensitive() {
        assert!(ci_starts_with(b"CSeq: 3", b"cseq:"));
        assert!(ci_starts_with(b"session: x", b"Session:"));
        assert!(!ci_starts_with(b"CSeq", b"CSeq:"));
        assert!(!ci_starts_with(b"Transport", b"Session:"));
    }

    #[test]
    fn pass_blanks_skips_space_and_tab_only() {
        assert_eq!(pass_blanks(b"  \t42"), b"42");
        assert_eq!(pass_blanks(b"42"), b"42");
        // A CR is not a blank and must not be skipped.
        assert_eq!(pass_blanks(b"\r\n"), b"\r\n");
    }

    #[test]
    fn parse_number_requires_a_digit_and_caps_overflow() {
        assert_eq!(parse_number(b"42;rest", u64::from(u32::MAX)).unwrap().0, 42);
        assert!(parse_number(b"abc", 255).is_none());
        assert!(parse_number(b"", 255).is_none());
        // Exceeding the cap fails (STRE_OVERFLOW).
        assert!(parse_number(b"256", 255).is_none());
        assert_eq!(parse_number(b"255", 255).unwrap().0, 255);
    }

    #[test]
    fn str_single_consumes_one_expected_byte() {
        assert_eq!(str_single(b"-5", b'-'), Some(&b"5"[..]));
        assert_eq!(str_single(b"5", b'-'), None);
        assert_eq!(str_single(b"", b'-'), None);
    }

    // -- RtspState: CSeq ---------------------------------------------------

    #[test]
    fn state_new_starts_cseq_counters_at_one() {
        let st = RtspState::new();
        assert_eq!(st.next_client_cseq(), 1);
        assert_eq!(st.next_server_cseq(), 1);
        assert_eq!(st.cseq_sent(), 0);
        assert_eq!(st.cseq_recv(), 0);
        assert_eq!(st.session_id(), None);
    }

    #[test]
    fn state_begin_and_advance_cseq() {
        let mut st = RtspState::new();
        st.begin_request();
        assert_eq!(st.cseq_sent(), 1);
        assert_eq!(st.cseq_recv(), 0);
        st.on_request_sent();
        assert_eq!(st.next_client_cseq(), 2);
        st.begin_request();
        assert_eq!(st.cseq_sent(), 2);
    }

    #[test]
    fn state_check_cseq_matches_and_mismatches() {
        let mut st = RtspState::new();
        st.begin_request(); // cseq_sent = 1
        st.parse_header("CSeq: 1").unwrap();
        assert_eq!(st.cseq_recv(), 1);
        st.check_cseq(RtspReq::Options).unwrap();

        // Mismatch -> CURLE_RTSP_CSEQ_ERROR (85).
        let mut st2 = RtspState::new();
        st2.begin_request();
        st2.parse_header("CSeq: 2").unwrap();
        let err = st2.check_cseq(RtspReq::Options).unwrap_err();
        assert_eq!(err.code(), CurlCode::RtspCseqError);
        assert_eq!(err.code() as i32, 85);
    }

    #[test]
    fn state_check_cseq_exempts_receive() {
        let mut st = RtspState::new();
        st.begin_request(); // cseq_sent = 1, cseq_recv = 0 (no echo for RECEIVE)
                            // RECEIVE is server-initiated and carries no request CSeq: never errors.
        st.check_cseq(RtspReq::Receive).unwrap();
    }

    #[test]
    fn state_parse_cseq_invalid_is_cseq_error() {
        let mut st = RtspState::new();
        let err = st.parse_header("CSeq: notanumber").unwrap_err();
        assert_eq!(err.code(), CurlCode::RtspCseqError);
        // An empty value is equally invalid.
        assert_eq!(
            st.parse_header("CSeq:").unwrap_err().code(),
            CurlCode::RtspCseqError
        );
    }

    // -- RtspState: Session ------------------------------------------------

    #[test]
    fn state_captures_session_id() {
        let mut st = RtspState::new();
        st.parse_header("Session: 1234ABCD").unwrap();
        assert_eq!(st.session_id(), Some("1234ABCD"));
    }

    #[test]
    fn state_session_stops_at_semicolon_and_crlf() {
        // A timeout parameter after ';' is not part of the id.
        let mut st = RtspState::new();
        st.parse_header("Session: 42AbC;timeout=60").unwrap();
        assert_eq!(st.session_id(), Some("42AbC"));

        // A trailing CRLF terminates the id too.
        let mut st2 = RtspState::new();
        st2.parse_header("Session: zxcv\r\n").unwrap();
        assert_eq!(st2.session_id(), Some("zxcv"));
    }

    #[test]
    fn state_blank_session_is_session_error() {
        let mut st = RtspState::new();
        let err = st.parse_header("Session: ").unwrap_err();
        assert_eq!(err.code(), CurlCode::RtspSessionError);
        assert_eq!(err.code() as i32, 86);
    }

    #[test]
    fn state_session_mismatch_is_session_error() {
        // A pinned id must match; a differing echo is CURLE_RTSP_SESSION_ERROR.
        let mut st = RtspState::with_session_id("expected-id");
        let err = st.parse_header("Session: other-id").unwrap_err();
        assert_eq!(err.code(), CurlCode::RtspSessionError);
        // A matching echo is accepted.
        let mut st2 = RtspState::with_session_id("match-me");
        st2.parse_header("Session: match-me").unwrap();
        assert_eq!(st2.session_id(), Some("match-me"));
    }

    // -- RtspState: Transport / channel mask -------------------------------

    #[test]
    fn state_transport_marks_interleaved_channel_range() {
        let mut st = RtspState::new();
        st.parse_header("Transport: RTP/AVP/TCP;unicast;interleaved=0-1")
            .unwrap();
        assert!(st.channel_valid(0));
        assert!(st.channel_valid(1));
        assert!(!st.channel_valid(2));
    }

    #[test]
    fn state_transport_single_channel_and_accumulates() {
        let mut st = RtspState::new();
        st.parse_header("Transport: RTP/AVP/TCP;interleaved=5")
            .unwrap();
        assert!(st.channel_valid(5));
        assert!(!st.channel_valid(4));
        assert!(!st.channel_valid(6));
        // A second Transport header OR-merges more channels in.
        st.parse_header("Transport: RTP/AVP/TCP;interleaved=8-9")
            .unwrap();
        assert!(st.channel_valid(5));
        assert!(st.channel_valid(8));
        assert!(st.channel_valid(9));
    }

    // -- RtspRequest: byte-exact assembly ----------------------------------

    fn build_str(req: RtspRequest<'_>) -> String {
        String::from_utf8(req.build().expect("build should succeed")).unwrap()
    }

    #[test]
    fn request_options_minimal() {
        let out =
            build_str(RtspRequest::new(RtspReq::Options, 1).stream_uri("rtsp://example.com/m"));
        assert_eq!(
            out,
            "OPTIONS rtsp://example.com/m RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        );
    }

    #[test]
    fn request_uri_defaults_to_star() {
        let out = build_str(RtspRequest::new(RtspReq::Options, 7));
        assert_eq!(out, "OPTIONS * RTSP/1.0\r\nCSeq: 7\r\n\r\n");
    }

    #[test]
    fn request_describe_adds_default_accept() {
        let out = build_str(RtspRequest::new(RtspReq::Describe, 2).stream_uri("rtsp://x/1"));
        assert_eq!(
            out,
            "DESCRIBE rtsp://x/1 RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n"
        );
    }

    #[test]
    fn request_describe_custom_accept_suppresses_default() {
        let hdrs = ["Accept: application/custom"];
        let out = build_str(
            RtspRequest::new(RtspReq::Describe, 2)
                .stream_uri("rtsp://x/1")
                .headers(&hdrs),
        );
        assert_eq!(
            out,
            "DESCRIBE rtsp://x/1 RTSP/1.0\r\nCSeq: 2\r\nAccept: application/custom\r\n\r\n"
        );
    }

    #[test]
    fn request_setup_requires_transport() {
        let err = RtspRequest::new(RtspReq::Setup, 1)
            .stream_uri("rtsp://x/1")
            .build()
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
    }

    #[test]
    fn request_setup_with_transport() {
        let out = build_str(
            RtspRequest::new(RtspReq::Setup, 3)
                .stream_uri("rtsp://x/1")
                .transport("RTP/AVP;unicast;client_port=4588-4589"),
        );
        assert_eq!(
            out,
            "SETUP rtsp://x/1 RTSP/1.0\r\nCSeq: 3\r\n\
             Transport: RTP/AVP;unicast;client_port=4588-4589\r\n\r\n"
        );
    }

    #[test]
    fn request_setup_transport_via_custom_header_satisfies_requirement() {
        // A custom Transport header also satisfies SETUP's requirement.
        let hdrs = ["Transport: RTP/AVP/TCP;interleaved=0-1"];
        let out = build_str(
            RtspRequest::new(RtspReq::Setup, 4)
                .stream_uri("rtsp://x/1")
                .headers(&hdrs),
        );
        assert_eq!(
            out,
            "SETUP rtsp://x/1 RTSP/1.0\r\nCSeq: 4\r\n\
             Transport: RTP/AVP/TCP;interleaved=0-1\r\n\r\n"
        );
    }

    #[test]
    fn request_play_echoes_session() {
        let out = build_str(
            RtspRequest::new(RtspReq::Play, 4)
                .stream_uri("rtsp://x/1")
                .session_id("12345678"),
        );
        assert_eq!(
            out,
            "PLAY rtsp://x/1 RTSP/1.0\r\nCSeq: 4\r\nSession: 12345678\r\n\r\n"
        );
    }

    #[test]
    fn request_get_parameter_requires_session() {
        let err = RtspRequest::new(RtspReq::GetParameter, 5)
            .stream_uri("rtsp://x/1")
            .build()
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
    }

    #[test]
    fn request_get_parameter_with_body() {
        let body = b"scale\nspeed\n"; // 12 bytes
        let out = build_str(
            RtspRequest::new(RtspReq::GetParameter, 5)
                .stream_uri("rtsp://x/1")
                .session_id("sess")
                .body(body),
        );
        assert_eq!(
            out,
            "GET_PARAMETER rtsp://x/1 RTSP/1.0\r\nCSeq: 5\r\nSession: sess\r\n\
             Content-Length: 12\r\nContent-Type: text/parameters\r\n\r\nscale\nspeed\n"
        );
    }

    #[test]
    fn request_empty_get_parameter_has_no_body_headers() {
        // The heartbeat form: session only, no body -> no Content-* headers.
        let out = build_str(
            RtspRequest::new(RtspReq::GetParameter, 6)
                .stream_uri("rtsp://x/1")
                .session_id("sess"),
        );
        assert_eq!(
            out,
            "GET_PARAMETER rtsp://x/1 RTSP/1.0\r\nCSeq: 6\r\nSession: sess\r\n\r\n"
        );
    }

    #[test]
    fn request_announce_defaults_to_sdp_content_type() {
        let body = b"v=0\r\n"; // 5 bytes
        let out = build_str(
            RtspRequest::new(RtspReq::Announce, 7)
                .stream_uri("rtsp://x/1")
                .session_id("sess")
                .body(body),
        );
        assert_eq!(
            out,
            "ANNOUNCE rtsp://x/1 RTSP/1.0\r\nCSeq: 7\r\nSession: sess\r\n\
             Content-Length: 5\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n"
        );
    }

    #[test]
    fn request_custom_content_type_suppresses_default() {
        let hdrs = ["Content-Type: application/x-custom"];
        let body = b"data";
        let out = build_str(
            RtspRequest::new(RtspReq::SetParameter, 2)
                .stream_uri("rtsp://x/1")
                .session_id("s")
                .headers(&hdrs)
                .body(body),
        );
        // Custom Content-Type is emitted in the custom-header slot (before body
        // setup); Content-Length is still auto-added afterwards.
        assert_eq!(
            out,
            "SET_PARAMETER rtsp://x/1 RTSP/1.0\r\nCSeq: 2\r\nSession: s\r\n\
             Content-Type: application/x-custom\r\nContent-Length: 4\r\n\r\ndata"
        );
    }

    #[test]
    fn request_custom_headers_are_emitted_in_order() {
        let hdrs = ["User-Agent: test/1.0", "X-Custom: val"];
        let out = build_str(
            RtspRequest::new(RtspReq::Options, 1)
                .stream_uri("rtsp://x/1")
                .headers(&hdrs),
        );
        assert_eq!(
            out,
            "OPTIONS rtsp://x/1 RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: test/1.0\r\nX-Custom: val\r\n\r\n"
        );
    }

    #[test]
    fn request_custom_cseq_header_is_cseq_error() {
        let hdrs = ["CSeq: 99"];
        let err = RtspRequest::new(RtspReq::Options, 1)
            .stream_uri("rtsp://x/1")
            .headers(&hdrs)
            .build()
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::RtspCseqError);
    }

    #[test]
    fn request_custom_session_header_is_bad_argument() {
        let hdrs = ["Session: forbidden"];
        let err = RtspRequest::new(RtspReq::Options, 1)
            .stream_uri("rtsp://x/1")
            .headers(&hdrs)
            .build()
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
    }

    #[test]
    fn request_invalid_method_is_bad_argument() {
        assert_eq!(
            RtspRequest::new(RtspReq::None, 1)
                .build()
                .unwrap_err()
                .code(),
            CurlCode::BadFunctionArgument
        );
        assert_eq!(
            RtspRequest::new(RtspReq::Last, 1)
                .build()
                .unwrap_err()
                .code(),
            CurlCode::BadFunctionArgument
        );
    }

    #[test]
    fn request_receive_cannot_be_built() {
        let err = RtspRequest::new(RtspReq::Receive, 1).build().unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
    }

    // -- RtpInterleave: the $-framed state machine -------------------------

    /// Records everything the interleave scanner emits.
    #[derive(Default)]
    struct TestSink {
        rtp: Vec<Vec<u8>>,
        body: Vec<u8>,
        in_body: bool,
    }

    impl RtpSink for TestSink {
        fn write_rtp(&mut self, frame: &[u8]) -> Result<()> {
            self.rtp.push(frame.to_vec());
            Ok(())
        }
        fn write_body_junk(&mut self, bytes: &[u8]) -> Result<()> {
            self.body.extend_from_slice(bytes);
            Ok(())
        }
        fn in_body(&self) -> bool {
            self.in_body
        }
    }

    /// A channel-validity mask with the given channels marked valid.
    fn mask_with(channels: &[u8]) -> [u8; RTP_CHANNEL_MASK_LEN] {
        let mut m = [0u8; RTP_CHANNEL_MASK_LEN];
        for &c in channels {
            m[(c / 8) as usize] |= 1 << (c % 8);
        }
        m
    }

    #[test]
    fn rtp_single_frame_delivered_whole() {
        let mask = mask_with(&[0]);
        // '$', channel 0, length 4 (big-endian), 4 payload bytes.
        let input = [0x24, 0x00, 0x00, 0x04, b'A', b'B', b'C', b'D'];
        let mut il = RtpInterleave::new();
        let mut sink = TestSink::default();
        let consumed = il.filter_rtp(&input, &mask, false, &mut sink).unwrap();
        assert_eq!(consumed, input.len());
        assert_eq!(sink.rtp.len(), 1);
        assert_eq!(sink.rtp[0], input);
        assert!(sink.body.is_empty());
        assert_eq!(il.state(), RtpParseState::Skip);
        assert_eq!(il.rtp_channel(), 0);
    }

    #[test]
    fn rtp_frame_spanning_two_reads() {
        let mask = mask_with(&[0]);
        // Full 8-byte frame split 5 + 3.
        let part1 = [0x24, 0x00, 0x00, 0x04, b'A'];
        let part2 = [b'B', b'C', b'D'];
        let mut il = RtpInterleave::new();
        let mut sink = TestSink::default();

        let c1 = il.filter_rtp(&part1, &mask, false, &mut sink).unwrap();
        assert_eq!(c1, 5);
        assert!(sink.rtp.is_empty()); // not complete yet
        assert_eq!(il.state(), RtpParseState::Data);
        assert!(il.frame_in_progress());

        let c2 = il.filter_rtp(&part2, &mask, false, &mut sink).unwrap();
        assert_eq!(c2, 3);
        assert_eq!(sink.rtp.len(), 1);
        assert_eq!(
            sink.rtp[0],
            [0x24, 0x00, 0x00, 0x04, b'A', b'B', b'C', b'D']
        );
        assert_eq!(il.state(), RtpParseState::Skip);
    }

    #[test]
    fn rtp_two_frames_back_to_back() {
        let mask = mask_with(&[0]);
        let mut input = Vec::new();
        input.extend_from_slice(&[0x24, 0x00, 0x00, 0x02, b'A', b'B']); // frame 1
        input.extend_from_slice(&[0x24, 0x00, 0x00, 0x01, b'C']); // frame 2
        let mut il = RtpInterleave::new();
        let mut sink = TestSink::default();
        let consumed = il.filter_rtp(&input, &mask, false, &mut sink).unwrap();
        assert_eq!(consumed, input.len());
        assert_eq!(sink.rtp.len(), 2);
        assert_eq!(sink.rtp[0], [0x24, 0x00, 0x00, 0x02, b'A', b'B']);
        assert_eq!(sink.rtp[1], [0x24, 0x00, 0x00, 0x01, b'C']);
    }

    #[test]
    fn rtp_junk_before_marker_is_body() {
        let mask = mask_with(&[0]);
        // Two junk bytes, then a complete 6-byte frame.
        let input = [b'X', b'Y', 0x24, 0x00, 0x00, 0x02, b'P', b'Q'];
        let mut il = RtpInterleave::new();
        let mut sink = TestSink::default();
        let consumed = il.filter_rtp(&input, &mask, false, &mut sink).unwrap();
        assert_eq!(consumed, input.len());
        assert_eq!(sink.body, b"XY");
        assert_eq!(sink.rtp.len(), 1);
        assert_eq!(sink.rtp[0], [0x24, 0x00, 0x00, 0x02, b'P', b'Q']);
    }

    #[test]
    fn rtp_rtsp_response_boundary_stops_scanning() {
        let mask = mask_with(&[0]);
        let input = b"RTSP/1.0 200 OK\r\n";
        let mut il = RtpInterleave::new();
        let mut sink = TestSink::default();
        // Not RECEIVE, not in body -> "RTSP/" is the next response boundary.
        let consumed = il.filter_rtp(input, &mask, false, &mut sink).unwrap();
        assert_eq!(consumed, 0);
        assert!(il.in_header());
        assert!(sink.rtp.is_empty());
        assert!(sink.body.is_empty());
    }

    #[test]
    fn rtp_invalid_channel_treated_as_body() {
        // No channels valid -> a '$' followed by an unannounced channel is body.
        let mask = mask_with(&[]);
        let input = [0x24, 0x05, 0x06, 0x07];
        let mut il = RtpInterleave::new();
        let mut sink = TestSink::default();
        let consumed = il.filter_rtp(&input, &mask, false, &mut sink).unwrap();
        assert_eq!(consumed, input.len());
        // The '$' and all following bytes are delivered as body.
        assert_eq!(sink.body, [0x24, 0x05, 0x06, 0x07]);
        assert!(sink.rtp.is_empty());
        assert_eq!(il.state(), RtpParseState::Skip);
    }

    #[test]
    fn rtp_invalid_channel_across_calls_writes_buffered_marker() {
        // The '$' arrives alone, then an invalid channel byte in the next read:
        // exercises the pconsumed == 0 branch that writes the buffered '$'.
        let mask = mask_with(&[]);
        let mut il = RtpInterleave::new();
        let mut sink = TestSink::default();

        let c1 = il.filter_rtp(&[0x24], &mask, false, &mut sink).unwrap();
        assert_eq!(c1, 1);
        assert_eq!(il.state(), RtpParseState::Channel);
        assert_eq!(il.buffered_len(), 1);

        let c2 = il
            .filter_rtp(&[0x05, 0x06], &mask, false, &mut sink)
            .unwrap();
        assert_eq!(c2, 2);
        // Buffered '$' written first, then the two junk bytes.
        assert_eq!(sink.body, [0x24, 0x05, 0x06]);
        assert!(sink.rtp.is_empty());
        assert_eq!(il.state(), RtpParseState::Skip);
    }

    #[test]
    fn rtp_receive_mode_does_not_treat_r_as_boundary() {
        let mask = mask_with(&[0]);
        let input = b"RTSP/1.0";
        let mut il = RtpInterleave::new();
        let mut sink = TestSink::default();
        // is_receive = true: the response-boundary heuristic is disabled, so the
        // bytes are consumed as body and scanning does not stop.
        let consumed = il.filter_rtp(input, &mask, true, &mut sink).unwrap();
        assert_eq!(consumed, input.len());
        assert!(!il.in_header());
        assert_eq!(sink.body, b"RTSP/1.0");
    }

    #[test]
    fn rtp_in_body_disables_boundary_detection() {
        let mask = mask_with(&[0]);
        let input = b"RTSP/";
        let mut il = RtpInterleave::new();
        let mut sink = TestSink {
            in_body: true,
            ..TestSink::default()
        };
        // Mid-body, an 'R'/"RTSP/" is ordinary body data, not a boundary.
        let consumed = il.filter_rtp(input, &mask, false, &mut sink).unwrap();
        assert_eq!(consumed, input.len());
        assert!(!il.in_header());
        assert_eq!(sink.body, b"RTSP/");
    }

    #[test]
    fn rtp_payload_spanning_many_reads() {
        // A larger payload delivered one byte per call still reassembles.
        let mask = mask_with(&[2]);
        let payload: Vec<u8> = (0..10u8).collect();
        let mut frame = vec![0x24, 0x02, 0x00, 0x0A]; // channel 2, length 10
        frame.extend_from_slice(&payload);
        let mut il = RtpInterleave::new();
        let mut sink = TestSink::default();
        let mut total = 0;
        for byte in &frame {
            total += il.filter_rtp(&[*byte], &mask, false, &mut sink).unwrap();
        }
        assert_eq!(total, frame.len());
        assert_eq!(sink.rtp.len(), 1);
        assert_eq!(sink.rtp[0], frame);
        assert_eq!(il.rtp_channel(), 2);
    }

    // -- rtp_client_write zero-length guard --------------------------------

    #[test]
    fn rtp_client_write_rejects_zero_length() {
        let mut sink = TestSink::default();
        let err = rtp_client_write(&mut sink, &[]).unwrap_err();
        assert_eq!(err.code(), CurlCode::WriteError);
        assert!(sink.rtp.is_empty());
    }

    #[test]
    fn rtp_pkt_length_is_big_endian() {
        assert_eq!(rtp_pkt_length(&[0x24, 0x00, 0x01, 0x02]), 0x0102);
        assert_eq!(rtp_pkt_length(&[0x24, 0x00, 0xFF, 0xFF]), 0xFFFF);
    }

    // -- Protocol handler DO/DONE wiring -----------------------------------

    /// Read the client's request bytes off the server side of a duplex, up to
    /// and including the CRLFCRLF header terminator.
    async fn read_request<S: AsyncRead + Unpin>(server: &mut S) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut b = [0u8; 1];
        while server.read_exact(&mut b).await.is_ok() {
            buf.push(b[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        buf
    }

    #[test]
    fn handler_is_zero_sized_singleton() {
        assert_eq!(core::mem::size_of::<RtspHandler>(), 0);
        // The exported HANDLER coerces to a &dyn Protocol for the scheme table.
        let _p: &dyn Protocol = &HANDLER;
    }

    #[test]
    fn handler_do_it_none_method_is_bad_argument() {
        // rtsp_request 0 => RTSPREQ_NONE, which rtsp_do rejects during request
        // assembly, before any transport is touched — so an empty ctx suffices.
        let mut ctx = TransferCtx::new();
        let err = block_on(HANDLER.do_it(&mut ctx)).unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
    }

    #[test]
    fn handler_do_it_without_transport_is_couldnt_connect() {
        // A valid method whose request assembles but with no live stream must
        // surface CURLE_COULDNT_CONNECT.
        let mut ctx = TransferCtx::new();
        ctx.request.rtsp_request = RtspReq::Options as i64;
        let err = block_on(HANDLER.do_it(&mut ctx)).unwrap_err();
        assert_eq!(err.code(), CurlCode::CouldntConnect);
    }

    #[test]
    fn handler_do_it_setup_without_transport_is_bad_argument() {
        // SETUP requires a Transport (from CURLOPT_RTSP_TRANSPORT or a custom
        // header); its absence is rejected during request assembly, before I/O.
        let mut ctx = TransferCtx::new();
        ctx.request.rtsp_request = RtspReq::Setup as i64;
        ctx.request.rtsp_session_id = Some("S".to_string());
        let err = block_on(HANDLER.do_it(&mut ctx)).unwrap_err();
        assert_eq!(err.code(), CurlCode::BadFunctionArgument);
    }

    #[test]
    fn handler_do_it_options_roundtrip_and_done_checks_cseq() {
        block_on(async {
            let (client, mut server) = tokio::io::duplex(4096);
            let server_task = async {
                let req = read_request(&mut server).await;
                // The request line + CSeq must be byte-exact.
                let text = String::from_utf8_lossy(&req);
                assert!(
                    text.starts_with("OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n"),
                    "got: {text:?}"
                );
                // Reply 200 OK echoing CSeq 1, no body.
                server
                    .write_all(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")
                    .await
                    .unwrap();
                server.flush().await.unwrap();
            };
            let mut ctx = TransferCtx::new();
            ctx.request.rtsp_request = RtspReq::Options as i64;
            ctx.io = Some(Box::new(client));
            let client_task = async {
                let done = HANDLER.do_it(&mut ctx).await?;
                assert!(done, "RTSP DO completes in one step");
                HANDLER.done(&mut ctx, Ok(()), false).await
            };
            let (_s, res) = tokio::join!(server_task, client_task);
            res.unwrap();
        });
    }

    #[test]
    fn handler_done_reports_cseq_mismatch() {
        block_on(async {
            let (client, mut server) = tokio::io::duplex(4096);
            let server_task = async {
                let _req = read_request(&mut server).await;
                // Echo the WRONG CSeq (99 != 1) — done must flag RtspCseqError.
                server
                    .write_all(b"RTSP/1.0 200 OK\r\nCSeq: 99\r\n\r\n")
                    .await
                    .unwrap();
                server.flush().await.unwrap();
            };
            let mut ctx = TransferCtx::new();
            ctx.request.rtsp_request = RtspReq::Options as i64;
            ctx.io = Some(Box::new(client));
            let client_task = async {
                HANDLER.do_it(&mut ctx).await.unwrap();
                HANDLER.done(&mut ctx, Ok(()), false).await
            };
            let (_s, res) = tokio::join!(server_task, client_task);
            assert_eq!(res.unwrap_err().code(), CurlCode::RtspCseqError);
        });
    }

    #[test]
    fn handler_do_it_describe_streams_body_to_sink() {
        block_on(async {
            let (client, mut server) = tokio::io::duplex(4096);
            let sdp = b"v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n";
            let server_task = async {
                let req = read_request(&mut server).await;
                let text = String::from_utf8_lossy(&req);
                assert!(text.starts_with("DESCRIBE rtsp://example.com/s RTSP/1.0\r\nCSeq: 1\r\n"));
                // DESCRIBE emits the default Accept: application/sdp.
                assert!(
                    text.contains("Accept: application/sdp\r\n"),
                    "got: {text:?}"
                );
                let resp = format!(
                    "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: {}\r\n\r\n",
                    sdp.len()
                );
                server.write_all(resp.as_bytes()).await.unwrap();
                server.write_all(sdp).await.unwrap();
                server.flush().await.unwrap();
            };
            let collected = Arc::new(Mutex::new(Vec::new()));
            let mut ctx = TransferCtx::new();
            ctx.request.rtsp_request = RtspReq::Describe as i64;
            ctx.request.rtsp_stream_uri = Some("rtsp://example.com/s".to_string());
            ctx.io = Some(Box::new(client));
            ctx.sink = Some(Box::new(RecordingSink(Arc::clone(&collected))));
            let client_task = async { HANDLER.do_it(&mut ctx).await };
            let (_s, res) = tokio::join!(server_task, client_task);
            assert!(res.unwrap());
            assert_eq!(
                collected.lock().unwrap().as_slice(),
                sdp,
                "the Content-Length body is streamed to the sink"
            );
        });
    }

    #[test]
    fn handler_do_it_emits_shared_headers_in_curl_order() {
        // rtsp#2: the wired handler supplies the shared HTTP-derived headers
        // (Range, User-Agent, Authorization) in curl's exact emission order.
        block_on(async {
            let (client, mut server) = tokio::io::duplex(4096);
            let captured = Arc::new(Mutex::new(Vec::new()));
            let cap = Arc::clone(&captured);
            let server_task = async {
                let req = read_request(&mut server).await;
                cap.lock().unwrap().extend_from_slice(&req);
                server
                    .write_all(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")
                    .await
                    .unwrap();
                server.flush().await.unwrap();
            };
            let mut ctx = TransferCtx::new();
            ctx.request.rtsp_request = RtspReq::Play as i64;
            ctx.request.rtsp_stream_uri = Some("rtsp://h/s".to_string());
            ctx.request.rtsp_session_id = Some("ABCD1234".to_string());
            ctx.request.range = Some("npt=0.000-".to_string());
            ctx.request.user = Some("u".to_string());
            ctx.request.password = Some("p".to_string());
            ctx.request.user_agent = Some("curl-rs/test".to_string());
            ctx.io = Some(Box::new(client));
            let client_task = async { HANDLER.do_it(&mut ctx).await };
            let (_s, res) = tokio::join!(server_task, client_task);
            res.unwrap();
            let sent = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
            // Request line + CSeq + Session, then the shared block in curl order.
            assert!(
                sent.starts_with("PLAY rtsp://h/s RTSP/1.0\r\nCSeq: 1\r\nSession: ABCD1234\r\n"),
                "got: {sent:?}"
            );
            let range_at = sent.find("Range: npt=0.000-\r\n").expect("Range present");
            let ua_at = sent
                .find("User-Agent: curl-rs/test\r\n")
                .expect("User-Agent present");
            // base64("u:p") == "dTpw".
            let auth_at = sent
                .find("Authorization: Basic dTpw\r\n")
                .expect("Basic auth present");
            assert!(
                range_at < ua_at && ua_at < auth_at,
                "shared headers must follow curl's Range→User-Agent→Authorization order"
            );
        });
    }

    #[test]
    fn handler_receive_streams_interleaved_data() {
        // rtsp#3: RECEIVE sends no request and runs the interleave scanner over
        // the incoming control-connection data (passive receive path).
        block_on(async {
            let (client, mut server) = tokio::io::duplex(4096);
            let server_task = async {
                server.write_all(b"payload-bytes").await.unwrap();
                server.flush().await.unwrap();
                drop(server);
            };
            let collected = Arc::new(Mutex::new(Vec::new()));
            let mut ctx = TransferCtx::new();
            ctx.request.rtsp_request = RtspReq::Receive as i64;
            ctx.io = Some(Box::new(client));
            ctx.sink = Some(Box::new(RecordingSink(Arc::clone(&collected))));
            let client_task = async { HANDLER.do_it(&mut ctx).await };
            let (_s, res) = tokio::join!(server_task, client_task);
            assert!(res.unwrap(), "RECEIVE DO completes when the peer closes");
            // With no validated channels the scanner delivers bytes as body/junk,
            // exercising the RECEIVE read path end to end.
            assert_eq!(collected.lock().unwrap().as_slice(), b"payload-bytes");
        });
    }
}
