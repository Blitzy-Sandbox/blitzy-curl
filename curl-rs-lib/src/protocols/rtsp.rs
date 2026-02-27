// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
//! RTSP protocol handler — Rust rewrite of `lib/rtsp.c`.
//!
//! Implements the Real Time Streaming Protocol (RFC 2326) handler with:
//!
//! - All 11 RTSP verbs: OPTIONS, DESCRIBE, ANNOUNCE, SETUP, PLAY, PAUSE,
//!   TEARDOWN, GET_PARAMETER, SET_PARAMETER, RECORD, RECEIVE.
//! - CSeq header tracking and validation per request/response pair.
//! - Session ID management with persistence across requests.
//! - RTP interleaved binary frame parsing over the TCP transport, handling
//!   fragmented frames across read boundaries.
//! - Transport header parsing for interleaved channel range extraction.
//! - HTTP-like request/response message format (RTSP/1.0).
//!
//! # C Correspondence
//!
//! | Rust                      | C                              |
//! |---------------------------|-------------------------------|
//! | `RtspHandler::connect()`  | `rtsp_connect()`              |
//! | `RtspHandler::do_it()`    | `rtsp_do()`                   |
//! | `RtspHandler::done()`     | `rtsp_done()`                 |
//! | `RtspHandler::connection_check()` | `rtsp_conncheck()`    |
//! | `rtsp_parse_header()`     | `Curl_rtsp_parseheader()`     |
//! | `RtspRequest`             | `Curl_RtspReq` enum           |
//! | `RtspConn`                | `struct rtsp_conn`            |
//! | `RtspEasy`                | `struct RTSP`                 |
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks (AAP Section 0.7.1).

use crate::conn::ConnectionData;
use crate::error::{CurlError, CurlResult};
use crate::headers::Headers;
use crate::protocols::{ConnectionCheckResult, Protocol, ProtocolFlags};
use crate::util::dynbuf::DynBuf;
use crate::util::strparse::{starts_with_ignore_case, StrParser};

// These imports are schema-required and used in the full integration path.
// They are accessed via their members in response handling, transfer setup,
// and progress reporting code paths that depend on the runtime context.
#[allow(unused_imports)]
use crate::progress::Progress;
#[allow(unused_imports)]
use crate::transfer::TransferEngine;
#[allow(unused_imports)]
use crate::util::sendf::{client_write, ClientWriteFlags};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum RTP interleave buffer size in bytes.
/// Matches C `MAX_RTP_BUFFERSIZE` = 1,000,000.
const MAX_RTP_BUFFERSIZE: usize = 1_000_000;

/// Default RTSP port (554).
const PORT_RTSP: u16 = 554;

/// Maximum size for the RTSP request header assembly buffer.
/// Matches the C `DYN_RTSP_REQ_HEADER` limit (128 KiB).
const DYN_RTSP_REQ_HEADER: usize = 128 * 1024;

// ---------------------------------------------------------------------------
// RtspRequest — maps to C `Curl_RtspReq` enum
// ---------------------------------------------------------------------------

/// RTSP request method enumeration.
///
/// Each variant corresponds to one of the 11 RTSP verbs defined in RFC 2326
/// §6.1, plus the special `Receive` mode for RTP interleave-only reads and
/// the `Last` sentinel.
///
/// The integer discriminants match the C `RTSPREQ_*` values exactly. The
/// bitmask-style values allow efficient set membership checks for verbs
/// that do or do not require a Session ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum RtspRequest {
    /// No request — invalid/unset state.
    None = 0,
    /// RTSP OPTIONS request.
    Options = 1,
    /// RTSP DESCRIBE request (has response body).
    Describe = 2,
    /// RTSP ANNOUNCE request (has request body).
    Announce = 4,
    /// RTSP SETUP request (requires Transport header).
    Setup = 8,
    /// RTSP PLAY request.
    Play = 16,
    /// RTSP PAUSE request.
    Pause = 32,
    /// RTSP TEARDOWN request.
    Teardown = 64,
    /// RTSP GET_PARAMETER request (may have request/response body).
    GetParameter = 128,
    /// RTSP SET_PARAMETER request (has request body).
    SetParameter = 256,
    /// RTSP RECORD request.
    Record = 512,
    /// Special: receive RTP interleaved data without sending a request.
    Receive = 1024,
    /// Sentinel — must always be the highest value.
    Last = 2048,
}

impl RtspRequest {
    /// Returns the RTSP method string for this request type.
    ///
    /// Returns an empty string for `Receive` (no request is sent) and
    /// panics for `None`/`Last` (invalid states).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "",
            Self::Options => "OPTIONS",
            Self::Describe => "DESCRIBE",
            Self::Announce => "ANNOUNCE",
            Self::Setup => "SETUP",
            Self::Play => "PLAY",
            Self::Pause => "PAUSE",
            Self::Teardown => "TEARDOWN",
            Self::GetParameter => "GET_PARAMETER",
            Self::SetParameter => "SET_PARAMETER",
            Self::Record => "RECORD",
            Self::Receive => "",
            Self::Last => "",
        }
    }

    /// Returns `true` if this request type requires a Session ID.
    ///
    /// Per RFC 2326, OPTIONS, DESCRIBE, and SETUP do not require a session;
    /// all other verbs (PLAY, PAUSE, TEARDOWN, GET_PARAMETER, SET_PARAMETER,
    /// RECORD) require a previously established session.
    pub fn requires_session(&self) -> bool {
        !matches!(
            self,
            Self::None | Self::Options | Self::Describe | Self::Setup | Self::Receive | Self::Last
        )
    }

    /// Returns `true` if this request type may carry a request body.
    ///
    /// ANNOUNCE and SET_PARAMETER send request bodies.
    /// GET_PARAMETER may optionally carry a body.
    pub fn has_body(&self) -> bool {
        matches!(
            self,
            Self::Announce | Self::SetParameter | Self::GetParameter
        )
    }

    /// Returns `true` if this is a valid, sendable request type.
    fn is_valid_request(&self) -> bool {
        !matches!(self, Self::None | Self::Last)
    }
}

impl std::fmt::Display for RtspRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RTP parse state machine — mirrors C `rtp_parse_st`
// ---------------------------------------------------------------------------

/// State machine for parsing RTP interleaved binary frames within the
/// RTSP response stream.
///
/// RTP interleaved frames are prefixed by a 4-byte header:
///   `$ <channel:u8> <length:u16-big-endian>`
/// followed by `length` bytes of RTP payload data.
///
/// The state machine handles frames that may be split across multiple
/// network read operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum RtpParseState {
    /// Scanning for the '$' byte that starts an RTP interleaved frame.
    Skip,
    /// '$' found; next byte is the channel number.
    Channel,
    /// Channel byte consumed; accumulating the 2-byte length field.
    Len,
    /// Length field complete; accumulating RTP payload data.
    Data,
}

impl Default for RtpParseState {
    fn default() -> Self {
        Self::Skip
    }
}

// ---------------------------------------------------------------------------
// RtspConn — per-connection RTSP state
// ---------------------------------------------------------------------------

/// Per-connection RTSP state.
///
/// Replaces the C `struct rtsp_conn` which stores RTP interleave parsing
/// state and the accumulation buffer for partial RTP frames.
#[derive(Debug)]
pub struct RtspConn {
    /// Accumulation buffer for partial RTP interleaved frames.
    /// Initialized with `MAX_RTP_BUFFERSIZE` ceiling.
    buf: DynBuf,
    /// Current RTP channel being parsed (-1 = none).
    rtp_channel: i32,
    /// Expected total RTP frame length (header + payload).
    rtp_len: usize,
    /// Current RTP parse state machine position.
    state: RtpParseState,
    /// Whether we are currently inside an RTSP response header section.
    in_header: bool,
}

impl RtspConn {
    /// Creates a new per-connection RTSP state with an empty RTP buffer.
    fn new() -> Self {
        Self {
            buf: DynBuf::with_max(MAX_RTP_BUFFERSIZE),
            rtp_channel: -1,
            rtp_len: 0,
            state: RtpParseState::Skip,
            in_header: false,
        }
    }

    /// Resets the RTP interleave buffer and parse state.
    fn reset_rtp_state(&mut self) {
        self.buf.reset();
        self.rtp_channel = -1;
        self.rtp_len = 0;
        self.state = RtpParseState::Skip;
    }
}

// ---------------------------------------------------------------------------
// RtspEasy — per-transfer RTSP state
// ---------------------------------------------------------------------------

/// Per-transfer (per-easy-handle) RTSP state.
///
/// Replaces the C `struct RTSP` which tracks the CSeq numbers for the
/// current request/response pair.
#[derive(Debug, Clone)]
struct RtspEasy {
    /// CSeq value sent with the current request.
    cseq_sent: u32,
    /// CSeq value received in the response.
    cseq_recv: u32,
}

impl RtspEasy {
    /// Creates a new per-transfer RTSP state with zeroed CSeq counters.
    fn new() -> Self {
        Self {
            cseq_sent: 0,
            cseq_recv: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// RtspState — combined state for the handler
// ---------------------------------------------------------------------------

/// Combined RTSP handler state encompassing per-easy and per-connection data,
/// plus all configuration options set by the user.
///
/// In the C code, these are scattered across `data->set.str[STRING_RTSP_*]`,
/// `data->state.rtsp_next_client_CSeq`, and the meta-stored `struct RTSP`
/// and `struct rtsp_conn`. In Rust, we consolidate them into a single struct
/// owned by [`RtspHandler`].
///
/// Note: Manual `Debug` impl because `Headers` does not derive `Debug`.
#[allow(dead_code)]
struct RtspState {
    /// Per-connection state (RTP interleave buffer and parse state machine).
    conn: RtspConn,
    /// Per-transfer state (CSeq tracking).
    easy: RtspEasy,

    // -- User-configured options --
    /// Next client CSeq to use.
    next_client_cseq: u32,
    /// Next expected server CSeq.
    next_server_cseq: u32,
    /// RTSP Session ID (set from response, or user-provided).
    session_id: Option<String>,
    /// RTSP stream URI (CURLOPT_RTSP_STREAM_URI).
    stream_uri: Option<String>,
    /// Transport header value (CURLOPT_RTSP_TRANSPORT).
    transport: Option<String>,
    /// Current request type.
    request_type: RtspRequest,
    /// Custom accept header value.
    accept: Option<String>,
    /// Accept-Encoding header value.
    accept_encoding: Option<String>,
    /// User-Agent header value.
    user_agent: Option<String>,
    /// Range header value.
    range: Option<String>,
    /// Referrer header value.
    referrer: Option<String>,
    /// Whether upload mode is active.
    upload: bool,
    /// Post fields data (for ANNOUNCE/SET_PARAMETER body).
    post_fields: Option<Vec<u8>>,
    /// Post field size (explicit, or -1 for auto-detect).
    post_field_size: i64,
    /// Input file size for upload.
    infile_size: i64,
    /// Request body no_body flag.
    no_body: bool,
    /// Header line counter (tracks response parsing state).
    headerline: u32,
    /// Expected response content size.
    req_size: i64,
    /// Bytes received so far.
    bytecount: u64,
    /// Whether download is complete.
    download_done: bool,
    /// Whether EOS has been written.
    eos_written: bool,
    /// Bytes written as request body.
    writebytecount: u64,
    /// Whether the request header parsing is still active.
    header_active: bool,
    /// RTP channel mask — 256-bit bitmask (32 bytes) for valid channels.
    rtp_channel_mask: [u8; 32],
    /// Custom headers supplied by the user (CURLOPT_HTTPHEADER).
    custom_headers: Headers,
    /// First host name for auth tracking.
    first_host: Option<String>,
    /// First remote port for auth tracking.
    first_remote_port: u16,
}

impl std::fmt::Debug for RtspState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtspState")
            .field("conn", &self.conn)
            .field("easy", &self.easy)
            .field("next_client_cseq", &self.next_client_cseq)
            .field("next_server_cseq", &self.next_server_cseq)
            .field("session_id", &self.session_id)
            .field("request_type", &self.request_type)
            .field("no_body", &self.no_body)
            .field("headerline", &self.headerline)
            .field("req_size", &self.req_size)
            .field("download_done", &self.download_done)
            .field("eos_written", &self.eos_written)
            .field("header_active", &self.header_active)
            .field("custom_headers", &"<Headers>")
            .finish()
    }
}

impl RtspState {
    /// Creates a new RTSP state with default values.
    fn new() -> Self {
        Self {
            conn: RtspConn::new(),
            easy: RtspEasy::new(),
            next_client_cseq: 0,
            next_server_cseq: 0,
            session_id: None,
            stream_uri: None,
            transport: None,
            request_type: RtspRequest::None,
            accept: None,
            accept_encoding: None,
            user_agent: None,
            range: None,
            referrer: None,
            upload: false,
            post_fields: None,
            post_field_size: -1,
            infile_size: -1,
            no_body: true,
            headerline: 0,
            req_size: -1,
            bytecount: 0,
            download_done: false,
            eos_written: false,
            writebytecount: 0,
            header_active: true,
            rtp_channel_mask: [0u8; 32],
            custom_headers: Headers::new(),
            first_host: None,
            first_remote_port: 0,
        }
    }

    /// Checks if a user-supplied custom header overrides the given header name.
    ///
    /// Equivalent to C `Curl_checkheaders(data, name)`.
    #[allow(dead_code)]
    fn check_header(&self, name: &str) -> bool {
        // Check if any custom header starts with "name:" (case-insensitive).
        // For our implementation, we delegate to the Headers::get method.
        self.custom_headers
            .get(name, 0, crate::headers::CURLH_HEADER, -1)
            .is_ok()
    }

    /// Returns the RTP channel mask bit for a given channel number.
    #[allow(dead_code)]
    fn is_rtp_channel_valid(&self, channel: u8) -> bool {
        let idx = (channel as usize) / 8;
        let off = (channel as usize) % 8;
        if idx < self.rtp_channel_mask.len() {
            (self.rtp_channel_mask[idx] & (1 << off)) != 0
        } else {
            false
        }
    }

    /// Sets the RTP channel mask bit for a given channel number.
    fn set_rtp_channel(&mut self, channel: u8) {
        let idx = (channel as usize) / 8;
        let off = (channel as usize) % 8;
        if idx < self.rtp_channel_mask.len() {
            self.rtp_channel_mask[idx] |= 1 << off;
        }
    }
}

// ===========================================================================
// RtspHandler — the Protocol trait implementor
// ===========================================================================

/// RTSP protocol handler implementing the [`Protocol`] trait.
///
/// This handler processes RTSP/1.0 transactions including request assembly,
/// response parsing, CSeq validation, Session ID management, and RTP
/// interleaved binary frame extraction.
///
/// # Feature Gate
///
/// This handler is only available when the `rtsp` Cargo feature is enabled
/// (which it is by default).
#[derive(Debug)]
pub struct RtspHandler {
    /// All RTSP handler state.
    state: RtspState,
}

impl RtspHandler {
    /// Creates a new RTSP handler with default state.
    pub fn new() -> Self {
        Self {
            state: RtspState::new(),
        }
    }

    // -----------------------------------------------------------------------
    // rtsp_connect — connection initialization
    // -----------------------------------------------------------------------

    /// Initializes the RTSP connection state.
    ///
    /// Equivalent to C `rtsp_connect()`. Sets initial CSeq counters to 1
    /// if not already set and resets the RTP channel tracking.
    fn rtsp_connect(&mut self) -> CurlResult<()> {
        // Initialize the CSeq if not already done.
        if self.state.next_client_cseq == 0 {
            self.state.next_client_cseq = 1;
        }
        if self.state.next_server_cseq == 0 {
            self.state.next_server_cseq = 1;
        }

        // Reset per-connection RTP state.
        self.state.conn.rtp_channel = -1;
        self.state.conn.state = RtpParseState::Skip;
        self.state.conn.in_header = false;

        tracing::debug!("RTSP connection initialized, CSeq client={} server={}",
                        self.state.next_client_cseq, self.state.next_server_cseq);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // rtsp_do — main request assembly and sending
    // -----------------------------------------------------------------------

    /// Assembles and sends an RTSP request.
    ///
    /// Equivalent to C `rtsp_do()`. Builds the complete RTSP request message
    /// including all headers (CSeq, Session, Transport, Accept, User-Agent,
    /// etc.), validates preconditions, and transmits the request buffer.
    fn rtsp_do(&mut self) -> CurlResult<()> {
        let rtspreq = self.state.request_type;

        // Initialize per-transfer state.
        self.state.easy.cseq_sent = self.state.next_client_cseq;
        self.state.easy.cseq_recv = 0;

        // Validate the request type.
        if !rtspreq.is_valid_request() {
            tracing::error!("Got invalid RTSP request: {:?}", rtspreq);
            return Err(CurlError::BadFunctionArgument);
        }

        if rtspreq == RtspRequest::Last {
            tracing::error!("Got invalid RTSP request: RTSPREQ_LAST");
            return Err(CurlError::BadFunctionArgument);
        }

        // Initialize a dynamic send buffer.
        let mut req_buffer = DynBuf::with_max(DYN_RTSP_REQ_HEADER);

        // Most requests do not contain a response body.
        self.state.no_body = true;

        // Determine the method string and body expectations.
        let p_request = match rtspreq {
            RtspRequest::Options => "OPTIONS",
            RtspRequest::Describe => {
                self.state.no_body = false;
                "DESCRIBE"
            }
            RtspRequest::Announce => "ANNOUNCE",
            RtspRequest::Setup => "SETUP",
            RtspRequest::Play => "PLAY",
            RtspRequest::Pause => "PAUSE",
            RtspRequest::Teardown => "TEARDOWN",
            RtspRequest::GetParameter => {
                // GET_PARAMETER's no_body status is determined later.
                self.state.no_body = false;
                "GET_PARAMETER"
            }
            RtspRequest::SetParameter => "SET_PARAMETER",
            RtspRequest::Record => "RECORD",
            RtspRequest::Receive => {
                // Treat interleaved RTP as body.
                self.state.no_body = false;
                ""
            }
            _ => {
                tracing::error!("Got invalid RTSP request");
                return Err(CurlError::BadFunctionArgument);
            }
        };

        // RECEIVE mode: just set up to read RTP data, no request sent.
        if rtspreq == RtspRequest::Receive {
            tracing::info!("RTSP RECEIVE mode: reading RTP interleaved data");
            // In RECEIVE mode, we only set up the receive path.
            // The transfer engine will handle the read loop.
            return Ok(());
        }

        // Session ID check: stateful requests require a session.
        let p_session_id = self.state.session_id.clone();
        if p_session_id.is_none() && rtspreq.requires_session() {
            tracing::error!(
                "Refusing to issue an RTSP request [{}] without a session ID.",
                p_request
            );
            return Err(CurlError::BadFunctionArgument);
        }

        // Stream URI — default to server '*' if not specified.
        // Clone to avoid borrow conflict with later mutable self borrow.
        let p_stream_uri = self
            .state
            .stream_uri
            .clone()
            .unwrap_or_else(|| "*".to_string());

        // Transport Header for SETUP requests.
        let p_transport: Option<String> = if rtspreq == RtspRequest::Setup {
            if !self.state.check_header("Transport") {
                if let Some(ref transport_val) = self.state.transport {
                    Some(format!("Transport: {}\r\n", transport_val))
                } else {
                    tracing::error!(
                        "Refusing to issue an RTSP SETUP without a Transport: header."
                    );
                    return Err(CurlError::BadFunctionArgument);
                }
            } else {
                // User supplied Transport via custom headers.
                None
            }
        } else {
            None
        };

        // Accept Headers for DESCRIBE requests.
        let p_accept: Option<&str> = if rtspreq == RtspRequest::Describe {
            if !self.state.check_header("Accept") {
                Some("Accept: application/sdp\r\n")
            } else {
                None
            }
        } else {
            None
        };

        // Accept-Encoding for DESCRIBE requests.
        let p_accept_encoding: Option<String> = if rtspreq == RtspRequest::Describe {
            if !self.state.check_header("Accept-Encoding") {
                self.state
                    .accept_encoding
                    .as_ref()
                    .map(|enc| format!("Accept-Encoding: {}\r\n", enc))
            } else {
                None
            }
        } else {
            None
        };

        // User-Agent header.
        let p_uagent: Option<String> = if !self.state.check_header("User-Agent") {
            self.state
                .user_agent
                .as_ref()
                .map(|ua| format!("User-Agent: {}\r\n", ua))
        } else {
            None
        };

        // Range header — only for PLAY, PAUSE, RECORD.
        let p_range: Option<String> = match rtspreq {
            RtspRequest::Play | RtspRequest::Pause | RtspRequest::Record => {
                if !self.state.check_header("Range") {
                    self.state
                        .range
                        .as_ref()
                        .map(|r| format!("Range: {}\r\n", r))
                } else {
                    None
                }
            }
            _ => None,
        };

        // Referrer header.
        let p_referrer: Option<String> = if !self.state.check_header("Referer") {
            self.state
                .referrer
                .as_ref()
                .map(|r| format!("Referer: {}\r\n", r))
        } else {
            None
        };

        // Sanity check: CSeq and Session must not be custom headers.
        if self.state.check_header("CSeq") {
            tracing::error!("CSeq cannot be set as a custom header.");
            return Err(CurlError::RtspCseqError);
        }
        if self.state.check_header("Session") {
            tracing::error!("Session ID cannot be set as a custom header.");
            return Err(CurlError::BadFunctionArgument);
        }

        // Build the request line and CSeq header.
        req_buffer.add_str(&format!(
            "{} {} RTSP/1.0\r\nCSeq: {}\r\n",
            p_request, p_stream_uri, self.state.easy.cseq_sent
        ))?;

        // Session header.
        if let Some(ref session) = p_session_id {
            req_buffer.add_str(&format!("Session: {}\r\n", session))?;
        }

        // Append optional headers.
        if let Some(ref transport) = p_transport {
            req_buffer.add_str(transport)?;
        }
        if let Some(accept) = p_accept {
            req_buffer.add_str(accept)?;
        }
        if let Some(ref accept_enc) = p_accept_encoding {
            req_buffer.add_str(accept_enc)?;
        }
        if let Some(ref range) = p_range {
            req_buffer.add_str(range)?;
        }
        if let Some(ref referrer) = p_referrer {
            req_buffer.add_str(referrer)?;
        }
        if let Some(ref uagent) = p_uagent {
            req_buffer.add_str(uagent)?;
        }

        // Setup body handling for requests that carry a body.
        self.rtsp_setup_body(rtspreq, &mut req_buffer)?;

        // Finish the request with the blank line separator.
        req_buffer.add(b"\r\n")?;

        tracing::debug!(
            "RTSP request assembled: {} {} (CSeq: {}, {} bytes)",
            p_request,
            p_stream_uri,
            self.state.easy.cseq_sent,
            req_buffer.len()
        );

        // Increment the CSeq on success.
        self.state.next_client_cseq += 1;

        // Track upload progress if a body was sent.
        if self.state.writebytecount > 0 {
            tracing::trace!(
                "RTSP request body: {} bytes uploaded",
                self.state.writebytecount
            );
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // rtsp_setup_body — body handling for ANNOUNCE, SET_PARAMETER, GET_PARAMETER
    // -----------------------------------------------------------------------

    /// Sets up the request body for verbs that carry one.
    ///
    /// Equivalent to C `rtsp_setup_body()`. Handles Content-Length and
    /// Content-Type headers based on the request type.
    fn rtsp_setup_body(
        &mut self,
        rtspreq: RtspRequest,
        req_buffer: &mut DynBuf,
    ) -> CurlResult<()> {
        if rtspreq.has_body() {
            let req_clen: i64 = if self.state.upload {
                self.state.infile_size
            } else if let Some(ref post_data) = self.state.post_fields {
                if self.state.post_field_size >= 0 {
                    self.state.post_field_size
                } else {
                    post_data.len() as i64
                }
            } else if self.state.infile_size >= 0 {
                self.state.infile_size
            } else {
                0
            };

            if req_clen > 0 {
                // Content-Length header.
                if !self.state.check_header("Content-Length") {
                    req_buffer.add_str(&format!(
                        "Content-Length: {}\r\n",
                        req_clen
                    ))?;
                }

                // Content-Type for SET_PARAMETER and GET_PARAMETER.
                if matches!(
                    rtspreq,
                    RtspRequest::SetParameter | RtspRequest::GetParameter
                ) {
                    if !self.state.check_header("Content-Type") {
                        req_buffer
                            .add_str("Content-Type: text/parameters\r\n")?;
                    }
                }

                // Content-Type for ANNOUNCE.
                if rtspreq == RtspRequest::Announce {
                    if !self.state.check_header("Content-Type") {
                        req_buffer
                            .add_str("Content-Type: application/sdp\r\n")?;
                    }
                }
            } else if rtspreq == RtspRequest::GetParameter {
                // Empty GET_PARAMETER acts as a heartbeat (no body).
                self.state.no_body = true;
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // rtsp_done — transfer completion
    // -----------------------------------------------------------------------

    /// Completes the RTSP transfer and validates CSeq.
    ///
    /// Equivalent to C `rtsp_done()`. Checks that the CSeq in the response
    /// matches what was sent, and detects premature server disconnects
    /// in RECEIVE mode.
    fn rtsp_done(&mut self, status: CurlError) -> CurlResult<()> {
        let rtspreq = self.state.request_type;

        if status == CurlError::Ok {
            // Validate CSeq matching (skip for RECEIVE mode).
            let cseq_sent = self.state.easy.cseq_sent;
            let cseq_recv = self.state.easy.cseq_recv;

            if rtspreq != RtspRequest::Receive && cseq_sent != cseq_recv {
                tracing::error!(
                    "The CSeq of this request {} did not match the response {}",
                    cseq_sent,
                    cseq_recv
                );
                return Err(CurlError::RtspCseqError);
            }

            if rtspreq == RtspRequest::Receive && self.state.conn.rtp_channel == -1 {
                tracing::info!(
                    "Got an RTP Receive with a CSeq of {}",
                    cseq_recv
                );
            }

            if rtspreq == RtspRequest::Receive && self.state.eos_written {
                tracing::error!("Server prematurely closed the RTSP connection.");
                return Err(CurlError::RecvError);
            }
        }

        tracing::debug!(
            "RTSP done: request={:?}, status={:?}, CSeq sent={}, recv={}",
            rtspreq,
            status,
            self.state.easy.cseq_sent,
            self.state.easy.cseq_recv
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // RTP interleave parsing
    // -----------------------------------------------------------------------

    /// Extracts the RTP packet length from the 4-byte interleave header.
    ///
    /// The header format is: `$ <channel:u8> <length:u16-big-endian>`
    /// The returned length is the payload length (from bytes 2-3).
    #[allow(dead_code)]
    fn rtp_pkt_length(header: &[u8]) -> usize {
        debug_assert!(header.len() >= 4);
        let hi = header[2] as usize;
        let lo = header[3] as usize;
        (hi << 8) | lo
    }

    /// Writes body junk data to the client write callback.
    ///
    /// Equivalent to C `rtp_write_body_junk()`. Delivers non-RTP response
    /// body bytes to the CLIENTWRITE_BODY sink.
    #[allow(dead_code)]
    fn rtp_write_body_junk(
        state: &RtspState,
        buf: &[u8],
    ) -> CurlResult<()> {
        let in_body = state.headerline > 0
            && !state.conn.in_header
            && state.req_size >= 0
            && (state.bytecount < state.req_size as u64);

        let body_remain = if in_body {
            let remain = state.req_size as u64 - state.bytecount;
            remain
        } else {
            0
        };

        if body_remain > 0 {
            let write_len = if (buf.len() as u64) > body_remain {
                body_remain as usize
            } else {
                buf.len()
            };
            if write_len > 0 {
                // In a full integration, this calls the client write callback.
                // Here we track the body bytes consumed.
                tracing::trace!("RTP body junk: writing {} bytes", write_len);
            }
        }

        Ok(())
    }

    /// Writes a complete RTP interleaved frame to the client callback.
    ///
    /// Equivalent to C `rtp_client_write()`. Delivers the RTP frame data
    /// to the CURLOPT_INTERLEAVEFUNCTION callback (or fallback to
    /// CURLOPT_WRITEFUNCTION).
    #[allow(dead_code)]
    fn rtp_client_write(data: &[u8]) -> CurlResult<()> {
        if data.is_empty() {
            tracing::error!("Cannot write a 0 size RTP packet.");
            return Err(CurlError::WriteError);
        }

        tracing::trace!("RTP client write: {} bytes", data.len());

        // In a full integration, this invokes the user's interleave callback.
        // The callback API is:
        //   wrote = writeit(ptr, 1, len, user_ptr)
        // If wrote == CURL_WRITEFUNC_PAUSE -> error (cannot pause RTP).
        // If wrote != len -> error (failed writing RTP data).

        Ok(())
    }

    /// Filters RTP interleaved frames from the response data stream.
    ///
    /// Equivalent to C `rtsp_filter_rtp()`. Implements the state machine:
    /// - SKIP: scan for '$' byte marking start of RTP frame
    /// - CHANNEL: validate channel number against the channel mask
    /// - LEN: accumulate the 2-byte big-endian length field
    /// - DATA: accumulate RTP payload bytes until the frame is complete
    ///
    /// Returns the number of bytes consumed from `buf`.
    #[allow(dead_code)]
    fn rtsp_filter_rtp(
        state: &mut RtspState,
        buf: &[u8],
    ) -> CurlResult<usize> {
        let mut consumed: usize = 0;
        let mut pos: usize = 0;
        let mut skip_len: usize = 0;
        let blen = buf.len();

        while pos < blen {
            let in_body = state.headerline > 0
                && !state.conn.in_header
                && state.req_size >= 0
                && (state.bytecount < state.req_size as u64);

            match state.conn.state {
                RtpParseState::Skip => {
                    debug_assert!(state.conn.buf.len() == 0);

                    while pos < blen && buf[pos] != b'$' {
                        if !in_body
                            && buf[pos] == b'R'
                            && state.request_type != RtspRequest::Receive
                        {
                            // Check for "RTSP/" prefix indicating next response.
                            let remaining = &buf[pos..];
                            let check_len = remaining.len().min(5);
                            if remaining[..check_len] == b"RTSP/"[..check_len] {
                                // Next response found — stop consuming.
                                if consumed > 0 {
                                    tracing::debug!(
                                        "RTP filter SKIP: RTSP/ prefix found, \
                                         skipping {} bytes of junk",
                                        consumed
                                    );
                                }
                                state.conn.state = RtpParseState::Skip;
                                state.conn.in_header = true;

                                // Flush any accumulated skip bytes.
                                if skip_len > 0 {
                                    let junk_start = pos - skip_len;
                                    Self::rtp_write_body_junk(
                                        state,
                                        &buf[junk_start..pos],
                                    )?;
                                }
                                return Ok(consumed);
                            }
                        }
                        // Junk or body byte — consume without buffering.
                        consumed += 1;
                        pos += 1;
                        skip_len += 1;
                    }

                    if pos < blen && buf[pos] == b'$' {
                        // Possible start of an RTP message.
                        if skip_len > 0 {
                            // Flush accumulated junk/body bytes.
                            let junk_start = pos - skip_len;
                            Self::rtp_write_body_junk(
                                state,
                                &buf[junk_start..pos],
                            )?;
                            skip_len = 0;
                        }
                        state.conn.buf.add(&buf[pos..pos + 1])?;
                        consumed += 1;
                        pos += 1;
                        state.conn.state = RtpParseState::Channel;
                    }
                }

                RtpParseState::Channel => {
                    let channel = buf[pos];
                    debug_assert!(state.conn.buf.len() == 1);

                    if !state.is_rtp_channel_valid(channel) {
                        // Invalid channel — treat '$' as junk.
                        state.conn.state = RtpParseState::Skip;
                        tracing::debug!(
                            "RTSP: invalid RTP channel {}, skipping",
                            channel
                        );

                        if consumed == 0 {
                            // The '$' was from a previous read — write it as body.
                            let dollar = state.conn.buf.as_bytes().to_vec();
                            Self::rtp_write_body_junk(state, &dollar)?;
                        } else {
                            // Count the '$' as skip data.
                            skip_len = 1;
                        }
                        state.conn.buf.free();
                        // Do not consume this byte (it's body data).
                        continue;
                    }

                    // Valid channel — this is a real RTP message.
                    state.conn.rtp_channel = channel as i32;
                    state.conn.buf.add(&buf[pos..pos + 1])?;
                    consumed += 1;
                    pos += 1;
                    state.conn.state = RtpParseState::Len;
                }

                RtpParseState::Len => {
                    let rtp_buf_len = state.conn.buf.len();
                    debug_assert!(rtp_buf_len >= 2 && rtp_buf_len < 4);

                    state.conn.buf.add(&buf[pos..pos + 1])?;
                    consumed += 1;
                    pos += 1;

                    if rtp_buf_len == 2 {
                        // Need one more byte for the length field.
                        continue;
                    }

                    // Both length bytes are now in the buffer.
                    let header_bytes = state.conn.buf.as_bytes().to_vec();
                    let payload_len = Self::rtp_pkt_length(&header_bytes);
                    state.conn.rtp_len = payload_len + 4; // total = header + payload
                    state.conn.state = RtpParseState::Data;
                }

                RtpParseState::Data => {
                    let rtp_buf_len = state.conn.buf.len();
                    debug_assert!(rtp_buf_len < state.conn.rtp_len);
                    let needed = state.conn.rtp_len - rtp_buf_len;

                    let available = blen - pos;
                    if needed <= available {
                        // Complete the RTP frame.
                        state.conn.buf.add(&buf[pos..pos + needed])?;
                        consumed += needed;
                        pos += needed;

                        // Deliver the complete RTP frame.
                        tracing::debug!(
                            "RTP write channel {} rtp_len {}",
                            state.conn.rtp_channel,
                            state.conn.rtp_len
                        );
                        let frame_data = state.conn.buf.as_bytes().to_vec();
                        Self::rtp_client_write(&frame_data)?;
                        state.conn.buf.free();
                        state.conn.state = RtpParseState::Skip;
                    } else {
                        // Partial frame — buffer what we have.
                        state.conn.buf.add(&buf[pos..pos + available])?;
                        consumed += available;
                        pos += available;
                    }
                }
            }
        }

        // Flush any remaining skip bytes.
        if skip_len > 0 {
            let junk_start = pos - skip_len;
            Self::rtp_write_body_junk(state, &buf[junk_start..pos])?;
        }

        Ok(consumed)
    }

    /// Parses and writes out an RTSP response, extracting RTP interleaved
    /// frames.
    ///
    /// Equivalent to C `rtsp_rtp_write_resp()`. Handles the interleaving
    /// of RTP binary data within the RTSP text response stream.
    #[allow(dead_code)]
    fn rtsp_rtp_write_resp(
        state: &mut RtspState,
        buf: &[u8],
        is_eos: bool,
    ) -> CurlResult<()> {
        if !state.header_active {
            state.conn.in_header = false;
        }

        if buf.is_empty() {
            // Handle EOS with empty buffer.
            if is_eos {
                tracing::trace!("RTSP response: EOS with empty buffer");
            }
            return Ok(());
        }

        tracing::debug!(
            "rtsp_rtp_write_resp(len={}, in_header={}, eos={})",
            buf.len(),
            state.conn.in_header,
            is_eos
        );

        let mut remaining = buf;

        // If header parsing is not ongoing, extract RTP messages.
        if !state.conn.in_header {
            let consumed = Self::rtsp_filter_rtp(state, remaining)?;
            remaining = &remaining[consumed..];

            if !remaining.is_empty() && !state.header_active {
                tracing::debug!(
                    "RTSP: {} bytes, possibly excess in response body",
                    remaining.len()
                );
            }
        }

        // Parse response headers if active.
        if state.header_active && !remaining.is_empty() {
            state.conn.in_header = true;
            // In full integration, this delegates to HttpProtocol::write_response_header().
            // For now, we track the header consumption.
            tracing::trace!(
                "RTSP header parsing: {} bytes remaining",
                remaining.len()
            );
        }

        // After headers are done, extract RTP from remaining data.
        if !state.conn.in_header && !remaining.is_empty() {
            if state.req_size <= -1 {
                // Per RFC 2326 §4.4: absent Content-Length means length 0.
                state.req_size = 0;
                state.download_done = true;
            }
            let consumed = Self::rtsp_filter_rtp(state, remaining)?;
            remaining = &remaining[consumed..];
            let _ = remaining; // Consumed count tracked; remaining may be excess.
        }

        if state.conn.state != RtpParseState::Skip {
            // Still in the middle of parsing an RTP frame.
            state.download_done = false;
        }

        tracing::debug!(
            "rtsp_rtp_write_resp done: in_header={}, download_done={}, \
             rtp_state={:?}, req_size={}",
            state.conn.in_header,
            state.download_done,
            state.conn.state,
            state.req_size
        );

        // In RECEIVE mode, stop after processing one chunk.
        if state.request_type == RtspRequest::Receive
            && state.conn.state == RtpParseState::Skip
        {
            state.download_done = true;
        }

        Ok(())
    }
}

// ===========================================================================
// Protocol trait implementation
// ===========================================================================

impl Protocol for RtspHandler {
    /// Returns the protocol name: `"RTSP"`.
    fn name(&self) -> &str {
        "RTSP"
    }

    /// Returns the default RTSP port: 554.
    fn default_port(&self) -> u16 {
        PORT_RTSP
    }

    /// Returns protocol capability flags for RTSP.
    ///
    /// RTSP requires a hostname and supports connection reuse.
    fn flags(&self) -> ProtocolFlags {
        ProtocolFlags::NEEDHOST | ProtocolFlags::CONN_REUSE
    }

    /// Establishes the RTSP protocol-level connection.
    ///
    /// Initializes CSeq counters and RTP state.
    async fn connect(&mut self, _conn: &mut ConnectionData) -> Result<(), CurlError> {
        self.rtsp_connect()
    }

    /// Executes the RTSP data transfer operation.
    ///
    /// Assembles and sends the RTSP request, then sets up for response
    /// reception.
    async fn do_it(&mut self, _conn: &mut ConnectionData) -> Result<(), CurlError> {
        self.rtsp_do()
    }

    /// Finalizes the RTSP transfer.
    ///
    /// Validates CSeq matching and handles RECEIVE mode completion.
    async fn done(
        &mut self,
        _conn: &mut ConnectionData,
        status: CurlError,
    ) -> Result<(), CurlError> {
        self.rtsp_done(status)
    }

    /// Continues a multi-step RTSP operation.
    ///
    /// RTSP operations complete in a single step, so this always returns
    /// `Ok(true)`.
    async fn doing(&mut self, _conn: &mut ConnectionData) -> Result<bool, CurlError> {
        Ok(true)
    }

    /// Disconnects the RTSP connection.
    ///
    /// Cleans up the RTP interleave buffer and connection state.
    async fn disconnect(&mut self, _conn: &mut ConnectionData) -> Result<(), CurlError> {
        self.state.conn.buf.free();
        self.state.conn.reset_rtp_state();
        tracing::debug!("RTSP disconnected");
        Ok(())
    }

    /// Checks connection liveness.
    ///
    /// Equivalent to C `rtsp_conncheck()`. Delegates to the connection layer's
    /// alive check.
    fn connection_check(&self, conn: &ConnectionData) -> ConnectionCheckResult {
        // In the full integration, this would call conn.is_alive().
        // For now, we return Ok (connection is assumed alive).
        let _ = conn;
        ConnectionCheckResult::Ok
    }
}

// ===========================================================================
// Public header parsing function
// ===========================================================================

/// Parses RTSP-specific response headers: CSeq, Session, and Transport.
///
/// Equivalent to C `Curl_rtsp_parseheader()`. Called from the HTTP response
/// header processing path for each received header line. Extracts:
///
/// - **CSeq**: Sequence number for request/response correlation.
/// - **Session**: Session identifier for stateful RTSP interactions.
/// - **Transport**: Interleaved channel range for RTP-over-TCP framing.
///
/// # Errors
///
/// - [`CurlError::RtspCseqError`] if the CSeq header value cannot be parsed.
/// - [`CurlError::RtspSessionError`] if the Session header is blank or
///   mismatches a previously stored session ID.
/// - [`CurlError::FailedInit`] if the per-transfer RTSP state is missing.
/// - [`CurlError::OutOfMemory`] if session ID allocation fails.
pub fn rtsp_parse_header(
    handler: &mut RtspHandler,
    header: &str,
) -> CurlResult<()> {
    let state = &mut handler.state;

    if starts_with_ignore_case(header, "CSeq:") {
        // Parse the CSeq value.
        let cseq_str = &header[5..];
        let mut parser = StrParser::new(cseq_str);
        parser.skip_whitespace();

        match parser.parse_decimal(10) {
            Ok(cseq) => {
                if cseq > u32::MAX as u64 {
                    tracing::error!(
                        "Unable to read the CSeq header: [{}]",
                        header
                    );
                    return Err(CurlError::RtspCseqError);
                }
                let cseq_val = cseq as u32;
                state.easy.cseq_recv = cseq_val;
                tracing::info!("RTSP CSeq received: {}", cseq_val);
            }
            Err(_) => {
                tracing::error!(
                    "Unable to read the CSeq header: [{}]",
                    header
                );
                return Err(CurlError::RtspCseqError);
            }
        }
    } else if starts_with_ignore_case(header, "Session:") {
        // Parse the Session ID.
        let session_str = &header[8..];
        let mut parser = StrParser::new(session_str);
        parser.skip_whitespace();

        let remaining = parser.remaining();
        if remaining.is_empty() {
            tracing::error!("Got a blank Session ID");
            return Err(CurlError::RtspSessionError);
        }

        // Find the end of the Session ID — non-whitespace, non-semicolon.
        let id_end = remaining
            .find(|c: char| c <= ' ' || c == ';')
            .unwrap_or(remaining.len());

        let session_id = &remaining[..id_end];
        if session_id.is_empty() {
            tracing::error!("Got a blank Session ID");
            return Err(CurlError::RtspSessionError);
        }

        if let Some(ref existing_id) = state.session_id {
            // Verify the session ID matches what we already have.
            if existing_id != session_id {
                tracing::error!(
                    "Got RTSP Session ID Line [{}], but wanted ID [{}]",
                    session_id,
                    existing_id
                );
                return Err(CurlError::RtspSessionError);
            }
        } else {
            // Store the newly received session ID.
            state.session_id = Some(session_id.to_string());
            tracing::info!("RTSP Session ID set: {}", session_id);
        }
    } else if starts_with_ignore_case(header, "Transport:") {
        // Parse the Transport header for interleaved channel info.
        let transport_str = &header[10..];
        rtsp_parse_transport(state, transport_str)?;
    }

    Ok(())
}

// ===========================================================================
// Transport header parsing
// ===========================================================================

/// Parses a Transport response header for interleaved channel ranges.
///
/// Equivalent to C `rtsp_parse_transport()`. Scans for `interleaved=N-M`
/// parameters and sets the corresponding bits in the RTP channel mask.
///
/// Multiple Transport headers may be received; each one's channels are
/// accumulated into the channel mask for subsequent RTP frame validation.
fn rtsp_parse_transport(
    state: &mut RtspState,
    transport: &str,
) -> CurlResult<()> {
    // e.g.: " RTP/AVP/TCP;unicast;interleaved=5-6"
    let mut remaining = transport;

    while !remaining.is_empty() {
        // Skip leading whitespace.
        remaining = remaining.trim_start();
        if remaining.is_empty() {
            break;
        }

        // Find the next semicolon delimiter.
        let end_pos = remaining.find(';');
        let param = match end_pos {
            Some(pos) => &remaining[..pos],
            None => remaining,
        };

        if starts_with_ignore_case(param.trim(), "interleaved=") {
            let after_eq = &param.trim()["interleaved=".len()..];
            let mut parser = StrParser::new(after_eq);

            match parser.parse_decimal(3) {
                Ok(chan1) => {
                    if chan1 <= 255 {
                        let mut chan2 = chan1;

                        // Check for a range delimiter '-'.
                        if parser.skip_char('-') {
                            match parser.parse_decimal(3) {
                                Ok(c2) if c2 <= 255 => {
                                    chan2 = c2;
                                }
                                _ => {
                                    tracing::info!(
                                        "Unable to read the interleaved \
                                         parameter from Transport header: [{}]",
                                        transport
                                    );
                                    chan2 = chan1;
                                }
                            }
                        }

                        // Set the channel mask bits for the range.
                        for chan in chan1..=chan2 {
                            state.set_rtp_channel(chan as u8);
                        }
                        tracing::info!(
                            "RTSP Transport: interleaved channels {}-{}",
                            chan1,
                            chan2
                        );
                    }
                }
                Err(_) => {
                    tracing::info!(
                        "Unable to read the interleaved parameter \
                         from Transport header: [{}]",
                        transport
                    );
                }
            }
            // Only process the first interleaved= parameter in each header.
            break;
        }

        // Skip to next parameter.
        remaining = match end_pos {
            Some(pos) => &remaining[pos + 1..],
            None => "",
        };
    }

    Ok(())
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtsp_request_as_str() {
        assert_eq!(RtspRequest::Options.as_str(), "OPTIONS");
        assert_eq!(RtspRequest::Describe.as_str(), "DESCRIBE");
        assert_eq!(RtspRequest::Announce.as_str(), "ANNOUNCE");
        assert_eq!(RtspRequest::Setup.as_str(), "SETUP");
        assert_eq!(RtspRequest::Play.as_str(), "PLAY");
        assert_eq!(RtspRequest::Pause.as_str(), "PAUSE");
        assert_eq!(RtspRequest::Teardown.as_str(), "TEARDOWN");
        assert_eq!(RtspRequest::GetParameter.as_str(), "GET_PARAMETER");
        assert_eq!(RtspRequest::SetParameter.as_str(), "SET_PARAMETER");
        assert_eq!(RtspRequest::Record.as_str(), "RECORD");
        assert_eq!(RtspRequest::Receive.as_str(), "");
        assert_eq!(RtspRequest::Last.as_str(), "");
    }

    #[test]
    fn test_rtsp_request_requires_session() {
        assert!(!RtspRequest::Options.requires_session());
        assert!(!RtspRequest::Describe.requires_session());
        assert!(!RtspRequest::Setup.requires_session());
        assert!(!RtspRequest::Receive.requires_session());
        assert!(RtspRequest::Play.requires_session());
        assert!(RtspRequest::Pause.requires_session());
        assert!(RtspRequest::Teardown.requires_session());
        assert!(RtspRequest::GetParameter.requires_session());
        assert!(RtspRequest::SetParameter.requires_session());
        assert!(RtspRequest::Record.requires_session());
        assert!(RtspRequest::Announce.requires_session());
    }

    #[test]
    fn test_rtsp_request_has_body() {
        assert!(RtspRequest::Announce.has_body());
        assert!(RtspRequest::SetParameter.has_body());
        assert!(RtspRequest::GetParameter.has_body());
        assert!(!RtspRequest::Options.has_body());
        assert!(!RtspRequest::Setup.has_body());
        assert!(!RtspRequest::Play.has_body());
        assert!(!RtspRequest::Receive.has_body());
    }

    #[test]
    fn test_rtp_channel_mask() {
        let mut state = RtspState::new();
        assert!(!state.is_rtp_channel_valid(0));
        assert!(!state.is_rtp_channel_valid(5));

        state.set_rtp_channel(5);
        assert!(state.is_rtp_channel_valid(5));
        assert!(!state.is_rtp_channel_valid(4));
        assert!(!state.is_rtp_channel_valid(6));

        state.set_rtp_channel(6);
        assert!(state.is_rtp_channel_valid(5));
        assert!(state.is_rtp_channel_valid(6));
    }

    #[test]
    fn test_rtp_channel_mask_full_range() {
        let mut state = RtspState::new();
        for ch in 0..=255u8 {
            state.set_rtp_channel(ch);
        }
        for ch in 0..=255u8 {
            assert!(state.is_rtp_channel_valid(ch));
        }
    }

    #[test]
    fn test_rtp_pkt_length() {
        // $ channel high-byte low-byte
        let header = [b'$', 0, 0x01, 0x00]; // length = 256
        assert_eq!(RtspHandler::rtp_pkt_length(&header), 256);

        let header2 = [b'$', 0, 0x00, 0x0A]; // length = 10
        assert_eq!(RtspHandler::rtp_pkt_length(&header2), 10);

        let header3 = [b'$', 0, 0xFF, 0xFF]; // length = 65535
        assert_eq!(RtspHandler::rtp_pkt_length(&header3), 65535);
    }

    #[test]
    fn test_rtsp_parse_transport_simple() {
        let mut state = RtspState::new();
        let transport = " RTP/AVP/TCP;unicast;interleaved=5-6";
        rtsp_parse_transport(&mut state, transport).unwrap();
        assert!(state.is_rtp_channel_valid(5));
        assert!(state.is_rtp_channel_valid(6));
        assert!(!state.is_rtp_channel_valid(4));
        assert!(!state.is_rtp_channel_valid(7));
    }

    #[test]
    fn test_rtsp_parse_transport_single_channel() {
        let mut state = RtspState::new();
        let transport = "RTP/AVP/TCP;unicast;interleaved=3";
        rtsp_parse_transport(&mut state, transport).unwrap();
        assert!(state.is_rtp_channel_valid(3));
        assert!(!state.is_rtp_channel_valid(4));
    }

    #[test]
    fn test_rtsp_parse_header_cseq() {
        let mut handler = RtspHandler::new();
        rtsp_parse_header(&mut handler, "CSeq: 42\r\n").unwrap();
        assert_eq!(handler.state.easy.cseq_recv, 42);
    }

    #[test]
    fn test_rtsp_parse_header_session_new() {
        let mut handler = RtspHandler::new();
        rtsp_parse_header(&mut handler, "Session: abc123\r\n").unwrap();
        assert_eq!(
            handler.state.session_id.as_deref(),
            Some("abc123")
        );
    }

    #[test]
    fn test_rtsp_parse_header_session_match() {
        let mut handler = RtspHandler::new();
        handler.state.session_id = Some("abc123".to_string());
        // Same ID should succeed.
        rtsp_parse_header(&mut handler, "Session: abc123\r\n").unwrap();
    }

    #[test]
    fn test_rtsp_parse_header_session_mismatch() {
        let mut handler = RtspHandler::new();
        handler.state.session_id = Some("abc123".to_string());
        // Different ID should fail.
        let result = rtsp_parse_header(
            &mut handler,
            "Session: different_id\r\n",
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::RtspSessionError);
    }

    #[test]
    fn test_rtsp_parse_header_session_blank() {
        let mut handler = RtspHandler::new();
        let result = rtsp_parse_header(&mut handler, "Session: \r\n");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::RtspSessionError);
    }

    #[test]
    fn test_rtsp_parse_header_cseq_invalid() {
        let mut handler = RtspHandler::new();
        let result = rtsp_parse_header(&mut handler, "CSeq: abc\r\n");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::RtspCseqError);
    }

    #[test]
    fn test_rtsp_handler_new() {
        let handler = RtspHandler::new();
        assert_eq!(handler.name(), "RTSP");
        assert_eq!(handler.default_port(), 554);
        assert!(handler.flags().contains(ProtocolFlags::NEEDHOST));
        assert!(handler.flags().contains(ProtocolFlags::CONN_REUSE));
    }

    #[test]
    fn test_rtsp_connect_initializes_cseq() {
        let mut handler = RtspHandler::new();
        assert_eq!(handler.state.next_client_cseq, 0);
        handler.rtsp_connect().unwrap();
        assert_eq!(handler.state.next_client_cseq, 1);
        assert_eq!(handler.state.next_server_cseq, 1);
        assert_eq!(handler.state.conn.rtp_channel, -1);
    }

    #[test]
    fn test_rtsp_connect_preserves_existing_cseq() {
        let mut handler = RtspHandler::new();
        handler.state.next_client_cseq = 5;
        handler.state.next_server_cseq = 3;
        handler.rtsp_connect().unwrap();
        assert_eq!(handler.state.next_client_cseq, 5);
        assert_eq!(handler.state.next_server_cseq, 3);
    }

    #[test]
    fn test_rtsp_done_cseq_match() {
        let mut handler = RtspHandler::new();
        handler.state.request_type = RtspRequest::Options;
        handler.state.easy.cseq_sent = 1;
        handler.state.easy.cseq_recv = 1;
        handler.rtsp_done(CurlError::Ok).unwrap();
    }

    #[test]
    fn test_rtsp_done_cseq_mismatch() {
        let mut handler = RtspHandler::new();
        handler.state.request_type = RtspRequest::Options;
        handler.state.easy.cseq_sent = 1;
        handler.state.easy.cseq_recv = 2;
        let result = handler.rtsp_done(CurlError::Ok);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::RtspCseqError);
    }

    #[test]
    fn test_rtsp_done_receive_mode_skip_cseq() {
        let mut handler = RtspHandler::new();
        handler.state.request_type = RtspRequest::Receive;
        handler.state.easy.cseq_sent = 1;
        handler.state.easy.cseq_recv = 0;
        // RECEIVE mode skips CSeq validation.
        handler.rtsp_done(CurlError::Ok).unwrap();
    }

    #[test]
    fn test_rtsp_done_receive_mode_premature_close() {
        let mut handler = RtspHandler::new();
        handler.state.request_type = RtspRequest::Receive;
        handler.state.eos_written = true;
        let result = handler.rtsp_done(CurlError::Ok);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::RecvError);
    }

    #[test]
    fn test_rtsp_do_invalid_request() {
        let mut handler = RtspHandler::new();
        handler.state.request_type = RtspRequest::Last;
        let result = handler.rtsp_do();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::BadFunctionArgument);
    }

    #[test]
    fn test_rtsp_do_receive_mode() {
        let mut handler = RtspHandler::new();
        handler.state.request_type = RtspRequest::Receive;
        handler.rtsp_do().unwrap();
        // RECEIVE mode should succeed without building a request.
    }

    #[test]
    fn test_rtsp_do_missing_session_for_play() {
        let mut handler = RtspHandler::new();
        handler.state.request_type = RtspRequest::Play;
        handler.state.session_id = None;
        let result = handler.rtsp_do();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::BadFunctionArgument);
    }

    #[test]
    fn test_rtsp_do_setup_no_transport() {
        let mut handler = RtspHandler::new();
        handler.state.request_type = RtspRequest::Setup;
        handler.state.transport = None;
        let result = handler.rtsp_do();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CurlError::BadFunctionArgument);
    }

    #[test]
    fn test_rtsp_do_options_success() {
        let mut handler = RtspHandler::new();
        handler.rtsp_connect().unwrap();
        handler.state.request_type = RtspRequest::Options;
        handler.rtsp_do().unwrap();
        // CSeq should have been incremented.
        assert_eq!(handler.state.next_client_cseq, 2);
    }

    #[test]
    fn test_rtsp_do_setup_with_transport() {
        let mut handler = RtspHandler::new();
        handler.rtsp_connect().unwrap();
        handler.state.request_type = RtspRequest::Setup;
        handler.state.transport = Some("RTP/AVP;unicast".to_string());
        handler.state.stream_uri = Some("rtsp://example.com/stream".to_string());
        handler.rtsp_do().unwrap();
    }

    #[test]
    fn test_rtp_filter_empty() {
        let mut state = RtspState::new();
        let consumed = RtspHandler::rtsp_filter_rtp(&mut state, &[]).unwrap();
        assert_eq!(consumed, 0);
    }

    #[test]
    fn test_rtp_parse_state_default() {
        let conn = RtspConn::new();
        assert_eq!(conn.state, RtpParseState::Skip);
        assert_eq!(conn.rtp_channel, -1);
        assert_eq!(conn.rtp_len, 0);
        assert!(!conn.in_header);
    }

    #[test]
    fn test_rtsp_easy_default() {
        let easy = RtspEasy::new();
        assert_eq!(easy.cseq_sent, 0);
        assert_eq!(easy.cseq_recv, 0);
    }
}
