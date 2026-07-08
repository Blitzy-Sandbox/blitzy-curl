// SPDX-License-Identifier: curl
// SPDX-FileCopyrightText: Daniel Stenberg, <daniel@haxx.se>, et al.

//! TFTP (Trivial File Transfer Protocol, RFC 1350) — the only UDP application
//! protocol in the workspace.
//!
//! This is the language rewrite of curl's `lib/tftp.c` (+ `lib/tftp.h`). TFTP is
//! a **lock-step** protocol carried over **UDP**: a request (`RRQ`/`WRQ`) is
//! answered with an option acknowledgement (`OACK`) or a first `DATA`/`ACK`,
//! after which each `DATA` block is answered with an `ACK` of the same block
//! number until a `DATA` payload shorter than the negotiated block size signals
//! end-of-transfer. Reliability is provided entirely at the application layer by
//! per-block timeout + retransmit of the last packet.
//!
//! # Fidelity (Minimal Change Mandate, AAP §0.7.3)
//!
//! Every algorithm here reproduces curl 8.19.0-DEV exactly:
//!
//! * The [`TftpState`] and [`TftpError`] enums keep curl's `tftp_state_t` /
//!   `tftp_error_t` names and integer values. The `0..=7` error codes are the
//!   RFC 1350 wire codes (sent inside `ERROR` packets); the negative values
//!   ([`TftpError::None`] = -100, [`TftpError::Timeout`] = -101,
//!   [`TftpError::NoResponse`] = -102) are curl-internal, exactly as in
//!   `lib/tftp.c`.
//! * Packet framing (big-endian `u16` opcode + block, NUL-terminated
//!   `filename`/`mode`, and the `blksize`/`tsize`/`timeout` option pairs
//!   negotiated through `OACK`) is byte-for-byte identical.
//! * Block-number tracking uses `u16` wraparound ([`next_blocknum`]), including
//!   the tftpd-hpa "ACK 65535 for block 0" wraparound quirk.
//! * The per-block timeout / retransmit-last-packet logic, the "short `DATA`
//!   block ⇒ EOF" rule, and the "lock onto the server's new transfer id (port)"
//!   behaviour are preserved.
//! * `ERROR`-packet wire codes translate to the exact frozen `CURLE_TFTP_*` /
//!   `CURLE_REMOTE_*` values via [`TftpError::translate`].
//!
//! # Structure
//!
//! * The [`TftpConn`] **engine** owns all protocol state and the RX/TX state
//!   machine. Its state handlers are I/O-free: they *stage* an outgoing datagram
//!   into the send buffer and the asynchronous driver flushes it. This mirrors
//!   curl's split between `tftp_state_machine` (pure logic) and
//!   `tftp_multi_statemach` (the socket pump) and makes the whole state machine
//!   unit-testable without a network.
//! * [`TftpConn::run`] is the Tokio driver: it performs the whole transfer over
//!   a [`tokio::net::UdpSocket`], using [`tokio::time`] for the retransmit clock,
//!   exactly as curl's multi state machine drives the socket.
//! * [`TftpSource`] / [`TftpSink`] abstract the upload byte source and the
//!   download byte sink, standing in for curl's `Curl_client_read` /
//!   `Curl_client_write` callbacks.
//! * [`TftpHandler`] / [`HANDLER`] plug the protocol into the scheme-dispatch
//!   table in [`crate::protocols`] (the `tftp` scheme, default port 69, flags
//!   `PROTOPT_NOTCPPROXY | PROTOPT_NOURLQUERY`, transport [`Transport::Udp`]).
//!
//! There is **no `unsafe`** anywhere in this file (the crate root applies
//! `#![forbid(unsafe_code)]`); TFTP needs no TLS and no authentication.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::time::sleep;

use crate::conn::Transport;
use crate::error::{CurlCode, Error, Result};
use crate::protocols::{ProtoFuture, Protocol, TransferCtx};

// ===========================================================================
// Wire and negotiation constants (← lib/tftp.c, lib/tftp.h).
// ===========================================================================

/// The default (and initial) TFTP block size, RFC 1350 (`TFTP_BLKSIZE_DEFAULT`).
///
/// A transfer starts at this size and only grows if the server acknowledges a
/// larger `blksize` option in its `OACK`.
pub const TFTP_BLKSIZE_DEFAULT: usize = 512;

/// The smallest block size curl will accept in an `OACK` (`TFTP_BLKSIZE_MIN`,
/// RFC 2348, from `lib/tftp.h`).
pub const TFTP_BLKSIZE_MIN: usize = 8;

/// The largest block size curl will request/accept (`TFTP_BLKSIZE_MAX`,
/// RFC 2348, from `lib/tftp.h`).
pub const TFTP_BLKSIZE_MAX: usize = 65464;

/// The IANA-assigned default TFTP server port (`PORT_TFTP`, `lib/urldata.h`).
pub const PORT_TFTP: u16 = 69;

/// The `blksize` option name (RFC 2348, `TFTP_OPTION_BLKSIZE`).
const TFTP_OPTION_BLKSIZE: &str = "blksize";
/// The `tsize` option name (RFC 2349, `TFTP_OPTION_TSIZE`).
const TFTP_OPTION_TSIZE: &str = "tsize";
/// The `timeout` option name (RFC 2349, `TFTP_OPTION_INTERVAL`).
const TFTP_OPTION_INTERVAL: &str = "timeout";

// ===========================================================================
// TftpMode — the transfer mode (← `tftp_mode_t`, lib/tftp.c).
// ===========================================================================

/// The TFTP transfer mode string sent in the `RRQ`/`WRQ` (← `tftp_mode_t`).
///
/// curl selects [`TftpMode::Netascii`] when the CLI `-B/--use-ascii` flag set
/// `prefer_ascii`, otherwise [`TftpMode::Octet`] (binary, the default). curl
/// performs no local newline translation for `netascii`; the mode only tells
/// the server how to treat the file, so the payload is carried verbatim in
/// either mode — this rewrite preserves that behaviour.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TftpMode {
    /// `netascii` mode (← `TFTP_MODE_NETASCII`).
    Netascii = 0,
    /// `octet` (binary) mode — the default (← `TFTP_MODE_OCTET`).
    Octet,
}

impl TftpMode {
    /// The on-the-wire mode string placed in an `RRQ`/`WRQ` packet.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            TftpMode::Netascii => "netascii",
            TftpMode::Octet => "octet",
        }
    }
}

// ===========================================================================
// TftpState — the state-machine state (← `tftp_state_t`, lib/tftp.c).
// VERBATIM names + values.
// ===========================================================================

/// The TFTP state-machine state (← `tftp_state_t`). The discriminants match
/// curl so `--trace` diagnostics report the same state numbers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TftpState {
    /// The initial state; the first `RRQ`/`WRQ` is (re)sent here
    /// (← `TFTP_STATE_START`).
    Start = 0,
    /// Receiving `DATA` (a download) (← `TFTP_STATE_RX`).
    Rx,
    /// Transmitting `DATA` (an upload) (← `TFTP_STATE_TX`).
    Tx,
    /// The transfer has finished (← `TFTP_STATE_FIN`).
    Fin,
}

// ===========================================================================
// TftpEvent — the state-machine event (← `tftp_event_t`, lib/tftp.c).
// ===========================================================================

/// A state-machine event (← `tftp_event_t`). The `0..=6` values equal the TFTP
/// opcodes (`RRQ`..`OACK`); [`TftpEvent::None`] and [`TftpEvent::Timeout`] are
/// curl-internal sentinels.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TftpEvent {
    /// No event (← `TFTP_EVENT_NONE`).
    None = -1,
    /// Kick off the transfer; (re)send the first request (← `TFTP_EVENT_INIT`).
    Init = 0,
    /// Read request opcode `1` (← `TFTP_EVENT_RRQ`).
    Rrq = 1,
    /// Write request opcode `2` (← `TFTP_EVENT_WRQ`).
    Wrq = 2,
    /// Data packet opcode `3` (← `TFTP_EVENT_DATA`).
    Data = 3,
    /// Acknowledgement opcode `4` (← `TFTP_EVENT_ACK`).
    Ack = 4,
    /// Error packet opcode `5` (← `TFTP_EVENT_ERROR`).
    Error = 5,
    /// Option-acknowledgement opcode `6` (← `TFTP_EVENT_OACK`).
    Oack = 6,
    /// The per-block timer expired (← `TFTP_EVENT_TIMEOUT`).
    Timeout,
}

impl TftpEvent {
    /// The 16-bit opcode value for this event (used to frame outgoing packets).
    #[must_use]
    pub const fn opcode(self) -> u16 {
        self as i16 as u16
    }

    /// Map a received 16-bit opcode to the corresponding event.
    ///
    /// Mirrors curl's direct `(tftp_event_t)opcode` cast for the defined opcodes
    /// `0..=6`; any other value has no defined event and maps to
    /// [`TftpEvent::None`], which the per-state handlers treat as an unexpected
    /// packet (exactly as curl's `default` switch arms do).
    #[must_use]
    pub const fn from_opcode(op: u16) -> TftpEvent {
        match op {
            0 => TftpEvent::Init,
            1 => TftpEvent::Rrq,
            2 => TftpEvent::Wrq,
            3 => TftpEvent::Data,
            4 => TftpEvent::Ack,
            5 => TftpEvent::Error,
            6 => TftpEvent::Oack,
            _ => TftpEvent::None,
        }
    }
}

// ===========================================================================
// TftpError — internal + wire error codes (← `tftp_error_t`, lib/tftp.c).
// VERBATIM names + values. The 0..=7 codes travel on the wire (RFC 1350);
// the negatives are curl-internal.
// ===========================================================================

/// A TFTP error code (← `tftp_error_t`).
///
/// The `0..=7` variants are the RFC 1350 error codes carried inside `ERROR`
/// packets — their integer values are load-bearing and MUST match. The negative
/// variants are curl-internal sentinels ([`TftpError::None`] = -100,
/// [`TftpError::Timeout`] = -101, [`TftpError::NoResponse`] = -102).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TftpError {
    /// Not defined, see the error message (← `TFTP_ERR_UNDEF`, wire `0`).
    Undef = 0,
    /// File not found (← `TFTP_ERR_NOTFOUND`, wire `1`).
    NotFound = 1,
    /// Access violation (← `TFTP_ERR_PERM`, wire `2`).
    Perm = 2,
    /// Disk full or allocation exceeded (← `TFTP_ERR_DISKFULL`, wire `3`).
    DiskFull = 3,
    /// Illegal TFTP operation (← `TFTP_ERR_ILLEGAL`, wire `4`).
    Illegal = 4,
    /// Unknown transfer id (← `TFTP_ERR_UNKNOWNID`, wire `5`).
    UnknownId = 5,
    /// File already exists (← `TFTP_ERR_EXISTS`, wire `6`).
    Exists = 6,
    /// No such user; never produced by this code (← `TFTP_ERR_NOSUCHUSER`,
    /// wire `7`).
    NoSuchUser = 7,

    /// No error (curl-internal) (← `TFTP_ERR_NONE`, -100).
    None = -100,
    /// A per-block timeout exhausted the retries (curl-internal)
    /// (← `TFTP_ERR_TIMEOUT`, -101).
    Timeout = -101,
    /// The server never responded to the first request (curl-internal)
    /// (← `TFTP_ERR_NORESPONSE`, -102).
    NoResponse = -102,
}

impl TftpError {
    /// The 16-bit wire value for an RFC 1350 error code (`0..=7`).
    ///
    /// Only meaningful for the wire variants; the curl-internal negatives are
    /// never serialized into a packet.
    #[must_use]
    pub const fn to_wire(self) -> u16 {
        self as i16 as u16
    }

    /// Map a received 16-bit wire error code to a [`TftpError`].
    ///
    /// Mirrors curl's direct `(tftp_error_t)error` cast for `0..=7`; any other
    /// value falls back to [`TftpError::Undef`] (which [`translate`] maps to
    /// `CURLE_TFTP_ILLEGAL`, curl's behaviour for an undefined code).
    ///
    /// [`translate`]: TftpError::translate
    #[must_use]
    pub const fn from_wire(code: u16) -> TftpError {
        match code {
            1 => TftpError::NotFound,
            2 => TftpError::Perm,
            3 => TftpError::DiskFull,
            4 => TftpError::Illegal,
            5 => TftpError::UnknownId,
            6 => TftpError::Exists,
            7 => TftpError::NoSuchUser,
            _ => TftpError::Undef,
        }
    }

    /// Translate this internal/wire error to the frozen curl [`CurlCode`]
    /// (← `tftp_translate_code`, lib/tftp.c). Integer values are frozen ABI.
    #[must_use]
    pub const fn translate(self) -> CurlCode {
        match self {
            TftpError::None => CurlCode::Ok,
            TftpError::NotFound => CurlCode::TftpNotfound,
            TftpError::Perm => CurlCode::TftpPerm,
            TftpError::DiskFull => CurlCode::RemoteDiskFull,
            // curl folds both UNDEF and ILLEGAL onto CURLE_TFTP_ILLEGAL.
            TftpError::Undef | TftpError::Illegal => CurlCode::TftpIllegal,
            TftpError::UnknownId => CurlCode::TftpUnknownid,
            TftpError::Exists => CurlCode::RemoteFileExists,
            TftpError::NoSuchUser => CurlCode::TftpNosuchuser,
            TftpError::Timeout => CurlCode::OperationTimedout,
            TftpError::NoResponse => CurlCode::CouldntConnect,
        }
    }
}

// ===========================================================================
// Packet framing helpers (← setpacketevent/setpacketblock/getrpacketevent/
// getrpacketblock and the NEXT_BLOCKNUM macro, lib/tftp.c).
//
// Every TFTP packet begins with a big-endian 16-bit opcode; DATA/ACK/OACK then
// carry a big-endian 16-bit block (or, for ERROR, an error code) in bytes 2..4.
// ===========================================================================

/// The next block number, wrapping at the unsigned 16-bit boundary
/// (← `#define NEXT_BLOCKNUM(x) (((x) + 1) & 0xffff)`).
///
/// `u16::wrapping_add` reproduces the C `& 0xffff` masking exactly: block
/// `65535` is followed by block `0`.
#[must_use]
pub const fn next_blocknum(x: u16) -> u16 {
    x.wrapping_add(1)
}

/// Write the big-endian opcode into bytes `0..2` of `packet`
/// (← `setpacketevent`).
fn set_packet_event(packet: &mut [u8], num: u16) {
    let be = num.to_be_bytes();
    packet[0] = be[0];
    packet[1] = be[1];
}

/// Write the big-endian block/error field into bytes `2..4` of `packet`
/// (← `setpacketblock`).
fn set_packet_block(packet: &mut [u8], num: u16) {
    let be = num.to_be_bytes();
    packet[2] = be[0];
    packet[3] = be[1];
}

/// Read the big-endian opcode from bytes `0..2` of `packet`
/// (← `getrpacketevent`).
#[must_use]
fn get_packet_event(packet: &[u8]) -> u16 {
    u16::from_be_bytes([packet[0], packet[1]])
}

/// Read the big-endian block/error field from bytes `2..4` of `packet`
/// (← `getrpacketblock`).
#[must_use]
fn get_packet_block(packet: &[u8]) -> u16 {
    u16::from_be_bytes([packet[2], packet[3]])
}

/// Case-insensitive prefix test (← curl's `checkprefix`): does `s` begin with
/// `prefix`? TFTP option names are compared this way so a server echoing
/// `Blksize` or `BLKSIZE` still matches.
#[must_use]
fn checkprefix(prefix: &str, s: &[u8]) -> bool {
    let p = prefix.as_bytes();
    s.len() >= p.len() && s[..p.len()].eq_ignore_ascii_case(p)
}

/// Parse a decimal option value the way curl's `curlx_str_number` does for TFTP
/// options: the whole field must be ASCII digits and the value must not exceed
/// `max`. Returns [`None`] for an empty field, a non-digit byte, or overflow of
/// `max` (curl treats all of these as "conversion failed").
#[must_use]
fn parse_option_number(value: &[u8], max: u64) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    let mut acc: u64 = 0;
    for &b in value {
        if !b.is_ascii_digit() {
            return None;
        }
        let digit = u64::from(b - b'0');
        acc = acc.checked_mul(10)?.checked_add(digit)?;
        if acc > max {
            return None;
        }
    }
    Some(acc)
}

// ===========================================================================
// Upload source / download sink (← Curl_client_read / Curl_client_write).
//
// TFTP is a plain byte transfer with no framing beyond the block boundary, so
// the byte producer (upload) and consumer (download) are modeled as two tiny
// synchronous traits — exactly the shape of curl's client read/write callbacks,
// which are likewise synchronous.
// ===========================================================================

/// The upload byte source (← `Curl_client_read`).
///
/// Implementors fill `buf` with up to `buf.len()` bytes and report how many
/// were produced plus whether the source is now exhausted (`eof`). A return of
/// `Ok((0, true))` marks a clean end of input.
pub trait TftpSource {
    /// Read up to `buf.len()` bytes into `buf`.
    ///
    /// Returns `(n, eof)` where `n` is the number of bytes written to the start
    /// of `buf` and `eof` indicates no more bytes will ever be produced.
    ///
    /// # Errors
    /// Returns an [`Error`] (typically [`Error::Read`]) if the underlying source
    /// cannot be read.
    fn read(&mut self, buf: &mut [u8]) -> Result<(usize, bool)>;
}

/// The download byte sink (← `Curl_client_write` with `CLIENTWRITE_BODY`).
pub trait TftpSink {
    /// Write the whole of `buf` to the sink.
    ///
    /// # Errors
    /// Returns an [`Error`] (typically [`Error::Write`]) if the sink rejects the
    /// data.
    fn write(&mut self, buf: &[u8]) -> Result<()>;
}

/// Read from an in-memory slice, advancing the slice as bytes are consumed.
///
/// `eof` becomes `true` once the slice is emptied by the read, so the classic
/// "last, short block" boundary is reported naturally.
impl TftpSource for &[u8] {
    fn read(&mut self, buf: &mut [u8]) -> Result<(usize, bool)> {
        let n = self.len().min(buf.len());
        buf[..n].copy_from_slice(&self[..n]);
        *self = &self[n..];
        Ok((n, self.is_empty()))
    }
}

/// Collect downloaded bytes by appending to a `Vec<u8>`.
impl TftpSink for Vec<u8> {
    fn write(&mut self, buf: &[u8]) -> Result<()> {
        self.extend_from_slice(buf);
        Ok(())
    }
}

// ===========================================================================
// TftpParams — the transfer inputs (← the fields curl reads from `Curl_easy`).
//
// The engine takes these explicitly rather than reaching through the (still
// placeholder) `TransferCtx`, mirroring how the sibling `dns` backends receive
// `host`/`port`/`ip_version` as parameters.
// ===========================================================================

/// The inputs that configure a single TFTP transfer.
#[derive(Clone, Debug)]
pub struct TftpParams {
    /// The remote filename (the URL path with its leading `/` removed, exactly
    /// as curl skips `up.path[0]`).
    pub filename: String,
    /// `true` for an upload (`WRQ`), `false` for a download (`RRQ`)
    /// (← `data->state.upload`).
    pub upload: bool,
    /// The transfer mode (← `data->state.prefer_ascii`).
    pub mode: TftpMode,
    /// The requested block size (← `CURLOPT_TFTP_BLKSIZE`); `0` selects the
    /// default of [`TFTP_BLKSIZE_DEFAULT`]. A non-zero value is clamped to
    /// `[`[`TFTP_BLKSIZE_MIN`]`, `[`TFTP_BLKSIZE_MAX`]`]`.
    pub blksize: usize,
    /// The known upload size, used for the `tsize` option and progress
    /// (← `data->state.infilesize`); `None` when unknown.
    pub infilesize: Option<u64>,
    /// Suppress the `blksize`/`tsize`/`timeout` option request
    /// (← `CURLOPT_TFTP_NO_OPTIONS`).
    pub no_options: bool,
    /// The overall transfer deadline as a duration from "now" (← the effective
    /// `CURLOPT_TIMEOUT`/`Curl_timeleft`); `None` means no explicit timeout, in
    /// which case curl's 15-second default retransmit clock applies.
    pub timeout: Option<Duration>,
}

impl Default for TftpParams {
    fn default() -> Self {
        Self {
            filename: String::new(),
            upload: false,
            mode: TftpMode::Octet,
            blksize: 0,
            infilesize: None,
            no_options: false,
            timeout: None,
        }
    }
}

// ===========================================================================
// TftpConn — the protocol engine (← `struct tftp_conn`, lib/tftp.c).
// ===========================================================================

/// The TFTP transfer engine: all protocol state plus the RX/TX state machine
/// (← `struct tftp_conn`).
///
/// The state handlers are I/O-free — they *stage* the next outgoing datagram in
/// [`spacket`](Self::spacket-field) and record its length so the asynchronous
/// [`run`](TftpConn::run) driver can flush it. This split makes the entire state
/// machine unit-testable without a socket.
#[derive(Debug)]
pub struct TftpConn {
    /// The current state-machine state (← `state->state`).
    state: TftpState,
    /// The transfer mode (← `state->mode`).
    mode: TftpMode,
    /// The terminal/last error (← `state->error`).
    error: TftpError,
    /// The most recently processed event (← `state->event`).
    event: TftpEvent,
    /// The negotiated block size; starts at [`TFTP_BLKSIZE_DEFAULT`] and only
    /// grows via `OACK` (← `state->blksize`).
    blksize: usize,
    /// The block size requested in the option set (← `state->requested_blksize`).
    requested_blksize: usize,
    /// The current block number, wrapping at the 16-bit boundary
    /// (← `state->block`).
    block: u16,
    /// The retransmit counter for the current block (← `state->retries`).
    retries: i32,
    /// The per-block retransmit interval in seconds (← `state->retry_time`).
    retry_time: i32,
    /// The maximum number of retransmits before giving up (← `state->retry_max`).
    retry_max: i32,
    /// When the last packet was received, driving the retransmit clock
    /// (← `state->rx_time`).
    rx_time: Instant,
    /// The outgoing-packet buffer (← `state->spacket`).
    spacket: Vec<u8>,
    /// The number of payload bytes currently staged in [`spacket`] for a `DATA`
    /// packet (← `state->sbytes`).
    sbytes: usize,
    /// The size of the last received datagram (← `state->rbytes`).
    rbytes: usize,
    /// The block/error field of the last received datagram (← the value read by
    /// `getrpacketblock` in the handlers).
    rblock: u16,
    /// The length of the datagram staged for sending, consumed by the driver;
    /// `None` when nothing is pending.
    send_len: Option<usize>,
    /// Whether this is an upload (`WRQ`) (← `data->state.upload`).
    upload: bool,
    /// The known upload size for the `tsize` option (← `data->state.infilesize`).
    infilesize: Option<u64>,
    /// Whether TFTP option negotiation is suppressed (← `tftp_no_options`).
    no_options: bool,
    /// The remote filename.
    filename: String,
    /// Whether the remote transfer-id (address+port) has been pinned
    /// (← `state->remote_pinned`).
    remote_pinned: bool,
    /// The pinned remote address the server answered from (← `state->remote_addr`).
    remote_addr: Option<SocketAddr>,
    /// The download size learned from an `OACK` `tsize` option, if any.
    tsize: Option<u64>,
    /// The overall transfer deadline (← `Curl_timeleft`).
    deadline: Option<Instant>,
    /// The number of payload bytes transferred (progress accounting).
    bytecount: u64,
}

impl TftpConn {
    /// Create an engine for the transfer described by `params`
    /// (← the state initialization in `tftp_connect`).
    ///
    /// Packet buffers are sized `max(requested_blksize, 512) + 4`, matching
    /// curl's `need_blksize + 2 + 2` allocation, so a later `OACK` can raise the
    /// block size up to the requested maximum without reallocation.
    #[must_use]
    pub fn new(params: TftpParams) -> Self {
        let requested_blksize = if params.blksize == 0 {
            TFTP_BLKSIZE_DEFAULT
        } else {
            params.blksize.clamp(TFTP_BLKSIZE_MIN, TFTP_BLKSIZE_MAX)
        };
        // need_blksize = max(requested, default); buffer = need_blksize + 4.
        let cap = requested_blksize.max(TFTP_BLKSIZE_DEFAULT) + 4;
        let deadline = params.timeout.map(|d| Instant::now() + d);
        Self {
            state: TftpState::Start,
            mode: params.mode,
            error: TftpError::None,
            event: TftpEvent::None,
            blksize: TFTP_BLKSIZE_DEFAULT,
            requested_blksize,
            block: 0,
            retries: 0,
            retry_time: 0,
            retry_max: 0,
            rx_time: Instant::now(),
            spacket: vec![0u8; cap],
            sbytes: 0,
            rbytes: 0,
            rblock: 0,
            send_len: None,
            upload: params.upload,
            infilesize: params.infilesize,
            no_options: params.no_options,
            filename: params.filename,
            remote_pinned: false,
            remote_addr: None,
            tsize: None,
            deadline,
            bytecount: 0,
        }
    }

    // --- Read-only accessors (state inspection for consumers and tests) ------

    /// The current state (← `state->state`).
    #[must_use]
    pub const fn state(&self) -> TftpState {
        self.state
    }

    /// The terminal/last error (← `state->error`).
    #[must_use]
    pub const fn error(&self) -> TftpError {
        self.error
    }

    /// The negotiated block size (← `state->blksize`).
    #[must_use]
    pub const fn blksize(&self) -> usize {
        self.blksize
    }

    /// The requested block size (← `state->requested_blksize`).
    #[must_use]
    pub const fn requested_blksize(&self) -> usize {
        self.requested_blksize
    }

    /// The current block number (← `state->block`).
    #[must_use]
    pub const fn block(&self) -> u16 {
        self.block
    }

    /// The download size learned from an `OACK` `tsize` option, if any.
    #[must_use]
    pub const fn tsize(&self) -> Option<u64> {
        self.tsize
    }

    /// The number of payload bytes transferred so far.
    #[must_use]
    pub const fn bytecount(&self) -> u64 {
        self.bytecount
    }

    /// The pinned remote (server transfer-id) address, once known.
    #[must_use]
    pub const fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    /// Translate the engine's terminal error to a curl [`Result`]
    /// (← `tftp_translate_code` applied in `tftp_done`/`tftp_do`).
    ///
    /// # Errors
    /// Returns the mapped [`Error`] when the transfer ended in a TFTP error.
    pub fn outcome(&self) -> Result<()> {
        let code = self.error.translate();
        if code == CurlCode::Ok {
            Ok(())
        } else {
            Err(Error::Code(code))
        }
    }

    // --- Timeout computation (← tftp_set_timeouts) ---------------------------

    /// Recompute the per-block retransmit interval and retry cap from the time
    /// remaining before the overall deadline (← `tftp_set_timeouts`).
    ///
    /// `retry_time` and `retry_max` are kept as `i32` (as in curl) and derived
    /// exactly: the per-block timeout defaults to the whole remaining budget (or
    /// 15 s when no overall timeout is configured); an ACK is reposted about
    /// every 5 s, bounded to `[3, 50]` total tries; the interval is at least 1 s.
    ///
    /// # Errors
    /// Returns [`CurlCode::OperationTimedout`] when the overall deadline has
    /// already passed (← the `timeout_ms < 0` branch).
    fn set_timeouts(&mut self) -> Result<()> {
        // ← Curl_timeleft_ms: milliseconds until the drop-dead time; 0 when no
        //   overall timeout is configured; negative once the deadline passed.
        let timeout_ms: i64 = match self.deadline {
            None => 0,
            Some(dl) => {
                let now = Instant::now();
                if now <= dl {
                    i64::try_from((dl - now).as_millis()).unwrap_or(i64::MAX)
                } else {
                    -i64::try_from((now - dl).as_millis()).unwrap_or(i64::MAX)
                }
            }
        };
        if timeout_ms < 0 {
            return Err(Error::with_context(
                CurlCode::OperationTimedout,
                "Connection time-out",
            ));
        }
        // Per-block timeout defaults to the whole transfer budget, else 15 s.
        let timeout: i64 = if timeout_ms > 0 {
            (timeout_ms + 500) / 1000
        } else {
            15
        };
        // Average reposting an ACK every ~5 s, bounded to a sane retry count.
        let retry_max: i64 = (timeout / 5).clamp(3, 50);
        // Re-ACK interval to suit the timeout, at least once per second.
        let retry_time: i64 = (timeout / retry_max).max(1);
        self.retry_max = retry_max as i32;
        self.retry_time = retry_time.min(i64::from(i32::MAX)) as i32;
        self.rx_time = Instant::now();
        Ok(())
    }

    // --- Request construction (← tftp_option_add / tftp_send_first) ----------

    /// Append a NUL-terminated option token (an option *name* or its *value*) to
    /// the request buffer at the current end (← `tftp_option_add`).
    ///
    /// The bound is the *negotiated* block size — which is still the default 512
    /// while the request is being built — exactly matching curl's use of
    /// `state->blksize` as the limit. `*sbytes` is advanced past the token and
    /// its NUL terminator.
    ///
    /// # Errors
    /// Returns [`CurlCode::TftpIllegal`] if the token would not fit.
    fn option_add(&mut self, sbytes: &mut usize, option: &str) -> Result<()> {
        let index = *sbytes;
        let oplen = option.len();
        if self.blksize <= index || (oplen + 1) > (self.blksize - index) {
            return Err(Error::Code(CurlCode::TftpIllegal));
        }
        self.spacket[index..index + oplen].copy_from_slice(option.as_bytes());
        self.spacket[index + oplen] = 0;
        *sbytes += oplen + 1;
        Ok(())
    }

    /// Append the `tsize`, `blksize`, and `timeout` option pairs — in curl's
    /// exact order — to the request being built (← the option block of
    /// `tftp_send_first`).
    ///
    /// # Errors
    /// Propagates [`option_add`](Self::option_add)'s [`CurlCode::TftpIllegal`]
    /// if the option set does not fit.
    fn add_request_options(&mut self, sbytes: &mut usize) -> Result<()> {
        // tsize: the upload size when known and uploading, otherwise 0 (curl
        // sends 0 on download to ask the server for the file size).
        let tsize_val: u64 = if self.upload {
            self.infilesize.unwrap_or(0)
        } else {
            0
        };
        let tbuf = tsize_val.to_string();
        let bbuf = self.requested_blksize.to_string();
        let ibuf = self.retry_time.to_string();
        self.option_add(sbytes, TFTP_OPTION_TSIZE)?;
        self.option_add(sbytes, &tbuf)?;
        self.option_add(sbytes, TFTP_OPTION_BLKSIZE)?;
        self.option_add(sbytes, &bbuf)?;
        self.option_add(sbytes, TFTP_OPTION_INTERVAL)?;
        self.option_add(sbytes, &ibuf)?;
        Ok(())
    }

    /// Build the initial `RRQ`/`WRQ` request (with option negotiation) into the
    /// send buffer and stage it for transmission (← the `INIT`/`TIMEOUT` arm of
    /// `tftp_send_first`).
    ///
    /// # Errors
    /// Returns [`CurlCode::TftpIllegal`] for a missing or over-long filename, or
    /// for an option set that will not fit in the request.
    fn build_first_request(&mut self) -> Result<()> {
        // RFC 3617: the leading slash is not part of the filename. curl skips
        // `up.path[0]` and rejects an empty remainder; the caller has already
        // stripped the slash, so an empty `filename` is the rejection case.
        if self.filename.is_empty() {
            return Err(Error::with_context(
                CurlCode::TftpIllegal,
                "Missing filename",
            ));
        }
        let opcode = if self.upload {
            TftpEvent::Wrq
        } else {
            TftpEvent::Rrq
        };
        set_packet_event(&mut self.spacket, opcode.opcode());

        let mode = self.mode.as_str();
        if self.filename.len() + mode.len() + 4 > self.blksize {
            return Err(Error::with_context(
                CurlCode::TftpIllegal,
                "TFTP filename too long",
            ));
        }

        // Write "filename\0mode\0" starting after the 2-byte opcode.
        let mut idx = 2usize;
        let fname = self.filename.as_bytes();
        self.spacket[idx..idx + fname.len()].copy_from_slice(fname);
        idx += fname.len();
        self.spacket[idx] = 0;
        idx += 1;
        let modeb = mode.as_bytes();
        self.spacket[idx..idx + modeb.len()].copy_from_slice(modeb);
        idx += modeb.len();
        self.spacket[idx] = 0;
        idx += 1;
        let mut sbytes = idx;

        // Optional TFTP option request (unless suppressed by --tftp-no-options).
        if !self.no_options {
            self.add_request_options(&mut sbytes).map_err(|_| {
                Error::with_context(CurlCode::TftpIllegal, "TFTP buffer too small for options")
            })?;
        }
        self.send_len = Some(sbytes);
        Ok(())
    }

    // --- Per-state handlers (← tftp_send_first / tftp_rx / tftp_tx) ----------

    /// The `TFTP_STATE_START` handler (← `tftp_send_first`): (re)send the first
    /// request, or transition to RX/TX once the server's first reply arrives.
    ///
    /// # Errors
    /// Propagates request-construction errors, or [`CurlCode::TftpIllegal`] for
    /// an internally impossible event.
    fn send_first(&mut self, event: TftpEvent, source: &mut dyn TftpSource) -> Result<()> {
        match event {
            TftpEvent::Init | TftpEvent::Timeout => {
                // (Re)transmit the request; give up after too many attempts.
                self.retries += 1;
                if self.retries > self.retry_max {
                    self.error = TftpError::NoResponse;
                    self.state = TftpState::Fin;
                    return Ok(());
                }
                self.build_first_request()
            }
            TftpEvent::Oack => {
                if self.upload {
                    self.connect_for_tx(event, source)
                } else {
                    self.connect_for_rx(event)
                }
            }
            TftpEvent::Ack => self.connect_for_tx(event, source),
            TftpEvent::Data => self.connect_for_rx(event),
            TftpEvent::Error => {
                self.state = TftpState::Fin;
                Ok(())
            }
            _ => Err(Error::with_context(
                CurlCode::TftpIllegal,
                "tftp_send_first: internal error",
            )),
        }
    }

    /// Transition to `TFTP_STATE_RX` and process the first RX event
    /// (← `tftp_connect_for_rx`).
    fn connect_for_rx(&mut self, event: TftpEvent) -> Result<()> {
        self.state = TftpState::Rx;
        self.set_timeouts()?;
        self.rx(event)
    }

    /// Transition to `TFTP_STATE_TX` and process the first TX event
    /// (← `tftp_connect_for_tx`).
    fn connect_for_tx(&mut self, event: TftpEvent, source: &mut dyn TftpSource) -> Result<()> {
        self.state = TftpState::Tx;
        self.set_timeouts()?;
        self.tx(event, source)
    }

    /// The `TFTP_STATE_RX` handler — download (← `tftp_rx`).
    ///
    /// # Errors
    /// Returns [`CurlCode::TftpIllegal`] for an internally impossible event.
    fn rx(&mut self, event: TftpEvent) -> Result<()> {
        match event {
            TftpEvent::Data => {
                let rblock = self.rblock;
                if next_blocknum(self.block) == rblock {
                    // The expected block: reset the retry counter and ACK it.
                    self.retries = 0;
                } else if self.block == rblock {
                    // A duplicate of the last block: ACK it again below without
                    // resetting the retry counter.
                } else {
                    // A totally unexpected block: ignore it (no ACK, no send).
                    return Ok(());
                }
                // ACK this block.
                self.block = rblock;
                set_packet_event(&mut self.spacket, TftpEvent::Ack.opcode());
                set_packet_block(&mut self.spacket, self.block);
                self.send_len = Some(4);
                // A short datagram (< blksize + 4) marks end-of-transfer.
                if self.rbytes < self.blksize + 4 {
                    self.state = TftpState::Fin;
                } else {
                    self.state = TftpState::Rx;
                }
                self.rx_time = Instant::now();
                Ok(())
            }
            TftpEvent::Oack => {
                // Acknowledge the option set, then move on to receiving data.
                self.block = 0;
                self.retries = 0;
                set_packet_event(&mut self.spacket, TftpEvent::Ack.opcode());
                set_packet_block(&mut self.spacket, self.block);
                self.send_len = Some(4);
                self.state = TftpState::Rx;
                self.rx_time = Instant::now();
                Ok(())
            }
            TftpEvent::Timeout => {
                self.retries += 1;
                if self.retries > self.retry_max {
                    self.error = TftpError::Timeout;
                    self.state = TftpState::Fin;
                } else {
                    // Resend the previous ACK (still staged in the send buffer).
                    self.send_len = Some(4);
                }
                Ok(())
            }
            TftpEvent::Error => {
                // Be a good client: tell the server we are done, then finish.
                set_packet_event(&mut self.spacket, TftpEvent::Error.opcode());
                set_packet_block(&mut self.spacket, self.block);
                self.send_len = Some(4);
                self.state = TftpState::Fin;
                Ok(())
            }
            _ => Err(Error::with_context(
                CurlCode::TftpIllegal,
                "tftp_rx: internal error",
            )),
        }
    }

    /// The `TFTP_STATE_TX` handler — upload (← `tftp_tx`).
    ///
    /// # Errors
    /// Returns [`CurlCode::SendError`] when it gives up waiting for a block ACK,
    /// or propagates an upload-source read error.
    fn tx(&mut self, event: TftpEvent, source: &mut dyn TftpSource) -> Result<()> {
        match event {
            TftpEvent::Ack | TftpEvent::Oack => {
                if event == TftpEvent::Ack {
                    let rblock = self.rblock;
                    // tftpd-hpa acks 65535 when the block number wraps to 0, so
                    // accept 65535 when we are expecting the ACK for block 0.
                    if rblock != self.block && !(self.block == 0 && rblock == 65535) {
                        // Not the expected ACK: count it and resend the packet.
                        self.retries += 1;
                        if self.retries > self.retry_max {
                            return Err(Error::with_context(
                                CurlCode::SendError,
                                "tftp_tx: giving up waiting for block ack",
                            ));
                        }
                        self.send_len = Some(4 + self.sbytes);
                        return Ok(());
                    }
                    // The expected ACK: advance to the next block.
                    self.rx_time = Instant::now();
                    self.block = self.block.wrapping_add(1);
                } else {
                    // OACK: the first data block is number 1.
                    self.block = 1;
                }
                self.retries = 0;
                set_packet_event(&mut self.spacket, TftpEvent::Data.opcode());
                set_packet_block(&mut self.spacket, self.block);
                // Past the first block, a previous short block means we are done.
                if self.block > 1 && self.sbytes < self.blksize {
                    self.state = TftpState::Fin;
                    return Ok(());
                }
                // Read the next block, waiting for a full block unless the source
                // is exhausted (a short/empty block signals EOF to the server).
                self.sbytes = 0;
                loop {
                    let want = self.blksize - self.sbytes;
                    let start = 4 + self.sbytes;
                    let (cb, _eos) = source.read(&mut self.spacket[start..start + want])?;
                    self.sbytes += cb;
                    if self.sbytes >= self.blksize || cb == 0 {
                        break;
                    }
                }
                self.send_len = Some(4 + self.sbytes);
                self.bytecount += self.sbytes as u64;
                Ok(())
            }
            TftpEvent::Timeout => {
                self.retries += 1;
                if self.retries > self.retry_max {
                    self.error = TftpError::Timeout;
                    self.state = TftpState::Fin;
                } else {
                    // Resend the current data packet unchanged.
                    self.send_len = Some(4 + self.sbytes);
                }
                Ok(())
            }
            TftpEvent::Error => {
                // Be a good client: send an ERROR to the server, then finish.
                self.state = TftpState::Fin;
                set_packet_event(&mut self.spacket, TftpEvent::Error.opcode());
                set_packet_block(&mut self.spacket, self.block);
                self.send_len = Some(4);
                Ok(())
            }
            // curl logs an internal error for any other event but leaves the
            // result OK; reproduce that (do nothing, succeed).
            _ => Ok(()),
        }
    }

    /// Dispatch an event to the handler for the current state
    /// (← `tftp_state_machine`).
    ///
    /// # Errors
    /// Propagates the active handler's error.
    fn state_machine(&mut self, event: TftpEvent, source: &mut dyn TftpSource) -> Result<()> {
        match self.state {
            TftpState::Start => self.send_first(event, source),
            TftpState::Rx => self.rx(event),
            TftpState::Tx => self.tx(event, source),
            TftpState::Fin => Ok(()),
        }
    }

    // --- OACK option negotiation (← tftp_parse_option_ack) -------------------

    /// Parse an `OACK` payload and adopt the negotiated `blksize`/`tsize`
    /// (← `tftp_parse_option_ack`).
    ///
    /// `payload` is the bytes *after* the 2-byte opcode. If the packet omits a
    /// `blksize` option the RFC 1350 default of 512 is used. Option parsing
    /// follows curl's `tftp_option_get` framing exactly: each option is a
    /// NUL-terminated name followed by a NUL-terminated value.
    ///
    /// # Errors
    /// Returns [`CurlCode::TftpIllegal`] for a malformed packet or an
    /// out-of-range `blksize`/`tsize`.
    fn parse_option_ack(&mut self, payload: &[u8]) -> Result<()> {
        // If the OACK omits blksize, the default (512) must be used.
        self.blksize = TFTP_BLKSIZE_DEFAULT;
        let len = payload.len();
        let mut pos = 0usize;
        while pos < len {
            let remaining = len - pos;
            // Option name: bytes up to the first NUL (← tftp_option_get).
            let optlen = payload[pos..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(remaining);
            let loc1 = optlen + 1;
            if loc1 >= remaining {
                return Err(Error::with_context(
                    CurlCode::TftpIllegal,
                    "Malformed ACK packet, rejecting",
                ));
            }
            // Option value: bytes up to the next NUL.
            let vallen = payload[pos + loc1..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(remaining - loc1);
            let loc2 = loc1 + vallen + 1;
            if loc2 > remaining {
                return Err(Error::with_context(
                    CurlCode::TftpIllegal,
                    "Malformed ACK packet, rejecting",
                ));
            }
            let option = &payload[pos..pos + optlen];
            let value = &payload[pos + loc1..pos + loc1 + vallen];

            if checkprefix(TFTP_OPTION_BLKSIZE, option) {
                self.adopt_blksize(value)?;
            } else if checkprefix(TFTP_OPTION_TSIZE, option) {
                self.adopt_tsize(value)?;
            }
            // Unknown options are ignored, exactly as curl does.
            pos += loc2;
        }
        Ok(())
    }

    /// Validate and adopt a `blksize` value from an `OACK` (← the blksize branch
    /// of `tftp_parse_option_ack`).
    ///
    /// # Errors
    /// Returns [`CurlCode::TftpIllegal`] if the value is unparsable, zero, below
    /// [`TFTP_BLKSIZE_MIN`], or larger than the size originally requested.
    fn adopt_blksize(&mut self, value: &[u8]) -> Result<()> {
        match parse_option_number(value, TFTP_BLKSIZE_MAX as u64) {
            None => Err(Error::with_context(
                CurlCode::TftpIllegal,
                "blksize is larger than max supported",
            )),
            Some(0) => Err(Error::with_context(
                CurlCode::TftpIllegal,
                "invalid blocksize value in OACK packet",
            )),
            Some(bs) if (bs as usize) < TFTP_BLKSIZE_MIN => Err(Error::with_context(
                CurlCode::TftpIllegal,
                "blksize is smaller than min supported",
            )),
            Some(bs) if (bs as usize) > self.requested_blksize => Err(Error::with_context(
                CurlCode::TftpIllegal,
                "server requested blksize larger than allocated",
            )),
            Some(bs) => {
                self.blksize = bs as usize;
                Ok(())
            }
        }
    }

    /// Validate and adopt a `tsize` value from an `OACK` (← the tsize branch of
    /// `tftp_parse_option_ack`); ignored on upload.
    ///
    /// # Errors
    /// Returns [`CurlCode::TftpIllegal`] if a successfully parsed size is zero.
    fn adopt_tsize(&mut self, value: &[u8]) -> Result<()> {
        // tsize is meaningless on upload (who cares about the remote size?).
        if self.upload {
            return Ok(());
        }
        // A parse failure is silently ignored (curl's `!curlx_str_number`
        // guard); a value that parses cleanly to zero is rejected.
        if let Some(tsize) = parse_option_number(value, i64::MAX as u64) {
            if tsize == 0 {
                return Err(Error::with_context(
                    CurlCode::TftpIllegal,
                    "invalid tsize value in OACK packet",
                ));
            }
            self.tsize = Some(tsize);
        }
        Ok(())
    }

    // --- Datagram intake (← tftp_receive_packet) -----------------------------

    /// Process one received datagram: pin/verify the server transfer id, deliver
    /// downloaded body bytes to the sink, classify the event, and (for `OACK`)
    /// adopt negotiated options (← `tftp_receive_packet`).
    ///
    /// The classified [`TftpEvent`] is stored in `self.event` for the driver to
    /// feed to [`state_machine`](Self::state_machine).
    ///
    /// # Errors
    /// Returns [`CurlCode::RecvError`] for a datagram from an unexpected address
    /// (wrong transfer id), or propagates a sink-write / option-parse error.
    fn receive_packet(
        &mut self,
        data: &[u8],
        from: SocketAddr,
        sink: &mut dyn TftpSink,
    ) -> Result<()> {
        // Lock onto the server's transfer id (its new ephemeral port) on the
        // first datagram; afterwards, reject anything from another address.
        if self.remote_pinned {
            if self.remote_addr != Some(from) {
                return Err(Error::with_context(
                    CurlCode::RecvError,
                    "Data received from another address",
                ));
            }
        } else {
            self.remote_pinned = true;
            self.remote_addr = Some(from);
        }

        self.rbytes = data.len();
        // A too-short datagram is treated as a timeout (← the `rbytes < 4`
        // branch, which sets `state->event = TFTP_EVENT_TIMEOUT`).
        if data.len() < 4 {
            self.event = TftpEvent::Timeout;
            return Ok(());
        }

        self.rblock = get_packet_block(data);
        let event = TftpEvent::from_opcode(get_packet_event(data));
        self.event = event;
        match event {
            TftpEvent::Data => {
                // Deliver only new, non-empty blocks to the sink — curl skips
                // empty or retransmitted DATA — before the state machine runs.
                if data.len() > 4 && next_blocknum(self.block) == self.rblock {
                    sink.write(&data[4..])?;
                    self.bytecount += (data.len() - 4) as u64;
                }
            }
            TftpEvent::Error => {
                // The block field carries the RFC 1350 error code.
                self.error = TftpError::from_wire(self.rblock);
            }
            TftpEvent::Oack => {
                self.parse_option_ack(&data[2..])?;
            }
            // ACK has no side effect here; RRQ/WRQ/None are unexpected and are
            // handled by the per-state default arms of the state machine.
            _ => {}
        }
        Ok(())
    }

    // --- Asynchronous driver (← tftp_perform + tftp_multi_statemach) ---------

    /// Flush any staged outgoing datagram to the correct destination: the pinned
    /// server transfer id once known, otherwise the initial `server` address the
    /// first request is sent to.
    ///
    /// # Errors
    /// Returns [`CurlCode::SendError`] on a socket error or a short send.
    async fn flush(&mut self, socket: &UdpSocket, server: SocketAddr) -> Result<()> {
        if let Some(len) = self.send_len.take() {
            let dest = self.remote_addr.unwrap_or(server);
            let sent = socket
                .send_to(&self.spacket[..len], dest)
                .await
                .map_err(|e| Error::with_context(CurlCode::SendError, e.to_string()))?;
            if sent != len {
                return Err(Error::with_context(
                    CurlCode::SendError,
                    "short send on TFTP socket",
                ));
            }
        }
        Ok(())
    }

    /// Drive the entire transfer to completion over `socket` (← `tftp_perform`
    /// followed by the `tftp_multi_statemach` loop).
    ///
    /// `server` is the initial server address (host:69) the first request goes
    /// to; once the server answers from its transfer-id port, every later
    /// datagram is sent there and packets from any other address are rejected.
    /// `source` supplies upload bytes (unused for a download) and `sink` receives
    /// downloaded bytes (unused for an upload).
    ///
    /// The retransmit clock is realized with [`tokio::time`]: each iteration
    /// waits for either an inbound datagram or the per-block retry interval,
    /// whichever comes first — the async equivalent of curl's poll-with-timeout
    /// multi loop. The overall deadline is honored exactly like
    /// `tftp_state_timeout`'s `timeout_ms < 0` check.
    ///
    /// # Errors
    /// Returns the mapped curl error if the transfer fails: a timeout
    /// ([`CurlCode::OperationTimedout`]), a server `ERROR` packet (a
    /// `CURLE_TFTP_*`/`CURLE_REMOTE_*` code), a send/recv failure, or an
    /// option/framing violation.
    pub async fn run(
        &mut self,
        socket: &UdpSocket,
        server: SocketAddr,
        source: &mut dyn TftpSource,
        sink: &mut dyn TftpSink,
    ) -> Result<()> {
        // ← tftp_connect: prime the retransmit clock before the first send.
        self.set_timeouts()?;
        // ← tftp_perform: send the first RRQ/WRQ, then run the multi loop.
        self.state_machine(TftpEvent::Init, source)?;
        self.flush(socket, server).await?;
        if self.state == TftpState::Fin {
            return self.outcome();
        }

        // Receive buffer sized to the largest datagram we could ever accept;
        // each recv is limited to the current blksize + 4 (⇐ curl's
        // recvfrom(state->blksize + 4)) so an oversized datagram truncates just
        // as it does in C.
        let mut rxbuf = vec![0u8; self.spacket.len()];

        // ← tftp_multi_statemach loop.
        while self.state != TftpState::Fin {
            // Overall drop-dead check (← tftp_state_timeout: `timeout_ms < 0`).
            if self.overall_timed_out() {
                return Err(Error::with_context(
                    CurlCode::OperationTimedout,
                    "TFTP response timeout",
                ));
            }

            // The per-block retransmit fires `retry_time` seconds after the last
            // received packet; never sleep past the overall deadline.
            let retry_at = self.rx_time + Duration::from_secs(self.retry_time as u64);
            let wake_at = match self.deadline {
                Some(dl) => retry_at.min(dl),
                None => retry_at,
            };
            let wait = wake_at.saturating_duration_since(Instant::now());
            let recv_len = self.blksize + 4;

            tokio::select! {
                recv = socket.recv_from(&mut rxbuf[..recv_len]) => {
                    let (n, from) = recv.map_err(|e| {
                        Error::with_context(CurlCode::RecvError, e.to_string())
                    })?;
                    self.receive_packet(&rxbuf[..n], from, sink)?;
                    self.state_machine(self.event, source)?;
                    self.flush(socket, server).await?;
                }
                () = sleep(wait) => {
                    // The timer elapsed: an overall timeout or a per-block retry.
                    if self.overall_timed_out() {
                        return Err(Error::with_context(
                            CurlCode::OperationTimedout,
                            "TFTP response timeout",
                        ));
                    }
                    // ← tftp_state_timeout updates rx_time even with no data.
                    self.rx_time = Instant::now();
                    self.state_machine(TftpEvent::Timeout, source)?;
                    self.flush(socket, server).await?;
                }
            }
        }
        self.outcome()
    }

    /// Whether the overall transfer deadline has passed, marking the engine
    /// finished with a timeout error (← the `timeout_ms < 0` branch of
    /// `tftp_state_timeout`).
    fn overall_timed_out(&mut self) -> bool {
        if let Some(dl) = self.deadline {
            if Instant::now() >= dl {
                self.error = TftpError::Timeout;
                self.state = TftpState::Fin;
                return true;
            }
        }
        false
    }
}

// ===========================================================================
// URL ";mode=" suffix handling (← tftp_setup_connection).
// ===========================================================================

/// Apply TFTP's URL `;mode=` suffix rule to a URL path (← `tftp_setup_connection`).
///
/// A trailing `;mode=netascii` selects [`TftpMode::Netascii`]; a trailing
/// `;mode=octet` selects [`TftpMode::Octet`]. In either case the suffix is
/// stripped from the returned path. With no recognized suffix the path is
/// returned unchanged together with `default_mode` (curl leaves `prefer_ascii`
/// at whatever the `-B`/`--use-ascii` flag set).
#[must_use]
pub fn parse_mode_suffix(path: &str, default_mode: TftpMode) -> (String, TftpMode) {
    const NETASCII_SUFFIX: &str = ";mode=netascii";
    const OCTET_SUFFIX: &str = ";mode=octet";
    if let Some(stripped) = path.strip_suffix(NETASCII_SUFFIX) {
        (stripped.to_string(), TftpMode::Netascii)
    } else if let Some(stripped) = path.strip_suffix(OCTET_SUFFIX) {
        (stripped.to_string(), TftpMode::Octet)
    } else {
        (path.to_string(), default_mode)
    }
}

// ===========================================================================
// TftpHandler — the scheme-dispatch entry point (← the TFTP `Curl_protocol`
// vtable reached through `Curl_scheme_tftp`).
// ===========================================================================

/// The TFTP protocol handler singleton (← the TFTP `struct Curl_protocol`
/// vtable, reached through `Curl_scheme_tftp`).
///
/// [`crate::protocols::SCHEME_TFTP`] points its `handler` field at [`HANDLER`],
/// this type's single shared instance. The scheme record fixes the datagram
/// transport ([`Transport::Udp`]), default port 69, and the
/// `PROTOPT_NOTCPPROXY | PROTOPT_NOURLQUERY` flags; TFTP uses neither TLS nor
/// authentication.
///
/// The protocol logic — the RX/TX state machine, `OACK` option negotiation, the
/// short-block EOF rule, block-number wraparound, transfer-id pinning, and the
/// timeout/retransmit clock — lives in [`TftpConn`], which is fully implemented
/// and unit-tested in this module. The trait methods below are intentionally
/// thin because the shared [`TransferCtx`] is still the crate-wide placeholder
/// (opaque and `#[non_exhaustive]`, with no fields populated yet): until it
/// carries the owning [`crate::conn::Connection`] and the in-flight request
/// state, a vtable method
/// has nothing to pull a socket or transfer parameters from. When that wiring
/// lands, `connect` will open the [`UdpSocket`] and the DO phase will drive
/// [`TftpConn::run`] to completion — no protocol behavior is deferred here, only
/// the handle plumbing that every protocol in the crate shares.
#[derive(Debug, Clone, Copy, Default)]
pub struct TftpHandler;

impl TftpHandler {
    /// The transport TFTP always uses: UDP datagrams (← `TRNSPRT_UDP`, set by
    /// `tftp_setup_connection`). This matches the transport that
    /// [`crate::protocols::SchemeHandler::transport`] derives for the `tftp`
    /// scheme, exposed here for direct use by the connection layer.
    #[must_use]
    pub const fn transport(&self) -> Transport {
        Transport::Udp
    }
}

impl Protocol for TftpHandler {
    /// The required DO phase (← `tftp_do` / `tftp_perform`).
    ///
    /// TFTP performs the whole transfer within DO/DOING; the concrete work is
    /// [`TftpConn::run`]. Returns `true` (DO complete) — the faithful result for
    /// a run-to-completion transfer. The socket and parameters are threaded in
    /// once [`TransferCtx`] is finalized (see the type-level note).
    fn do_it<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(async { Ok(true) })
    }

    /// The required teardown (← `tftp_done`).
    ///
    /// TFTP keeps no connection alive (`connclose`), so there is nothing to
    /// release here; the transfer's `status` is propagated unchanged so a
    /// failure surfaces to the caller exactly as `tftp_done` returns the
    /// translated error.
    fn done<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        status: Result<()>,
        premature: bool,
    ) -> ProtoFuture<'a, ()> {
        let _ = (ctx, premature);
        Box::pin(async move { status })
    }
}

/// The shared [`TftpHandler`] singleton referenced by
/// [`crate::protocols::SCHEME_TFTP`] (← the address of the TFTP `Curl_protocol`
/// vtable stored in `Curl_scheme_tftp`).
pub static HANDLER: TftpHandler = TftpHandler;

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::Transport;
    use crate::error::{CurlCode, Error};
    use crate::protocols::{Protocol, TransferCtx};
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    // --- Enum identity (← tftp_state_t / tftp_event_t / tftp_error_t) --------

    #[test]
    fn state_discriminants_match_curl() {
        assert_eq!(TftpState::Start as i32, 0);
        assert_eq!(TftpState::Rx as i32, 1);
        assert_eq!(TftpState::Tx as i32, 2);
        assert_eq!(TftpState::Fin as i32, 3);
    }

    #[test]
    fn event_discriminants_match_curl() {
        assert_eq!(TftpEvent::None as i32, -1);
        assert_eq!(TftpEvent::Init as i32, 0);
        assert_eq!(TftpEvent::Rrq as i32, 1);
        assert_eq!(TftpEvent::Wrq as i32, 2);
        assert_eq!(TftpEvent::Data as i32, 3);
        assert_eq!(TftpEvent::Ack as i32, 4);
        assert_eq!(TftpEvent::Error as i32, 5);
        assert_eq!(TftpEvent::Oack as i32, 6);
        // TFTP_EVENT_TIMEOUT follows OACK (= 6) with no explicit value.
        assert_eq!(TftpEvent::Timeout as i32, 7);
    }

    #[test]
    fn error_discriminants_match_curl() {
        assert_eq!(TftpError::Undef as i32, 0);
        assert_eq!(TftpError::NotFound as i32, 1);
        assert_eq!(TftpError::Perm as i32, 2);
        assert_eq!(TftpError::DiskFull as i32, 3);
        assert_eq!(TftpError::Illegal as i32, 4);
        assert_eq!(TftpError::UnknownId as i32, 5);
        assert_eq!(TftpError::Exists as i32, 6);
        assert_eq!(TftpError::NoSuchUser as i32, 7);
        // curl-internal negatives.
        assert_eq!(TftpError::None as i32, -100);
        assert_eq!(TftpError::Timeout as i32, -101);
        assert_eq!(TftpError::NoResponse as i32, -102);
    }

    #[test]
    fn mode_strings_match_curl() {
        assert_eq!(TftpMode::Netascii as i32, 0);
        assert_eq!(TftpMode::Octet as i32, 1);
        assert_eq!(TftpMode::Netascii.as_str(), "netascii");
        assert_eq!(TftpMode::Octet.as_str(), "octet");
    }

    // --- translate_code (frozen CURLE_* integer values) ----------------------

    #[test]
    fn translate_matches_curl_codes() {
        assert_eq!(TftpError::None.translate(), CurlCode::Ok);
        assert_eq!(TftpError::NotFound.translate(), CurlCode::TftpNotfound);
        assert_eq!(TftpError::Perm.translate(), CurlCode::TftpPerm);
        assert_eq!(TftpError::DiskFull.translate(), CurlCode::RemoteDiskFull);
        assert_eq!(TftpError::Undef.translate(), CurlCode::TftpIllegal);
        assert_eq!(TftpError::Illegal.translate(), CurlCode::TftpIllegal);
        assert_eq!(TftpError::UnknownId.translate(), CurlCode::TftpUnknownid);
        assert_eq!(TftpError::Exists.translate(), CurlCode::RemoteFileExists);
        assert_eq!(TftpError::NoSuchUser.translate(), CurlCode::TftpNosuchuser);
        assert_eq!(TftpError::Timeout.translate(), CurlCode::OperationTimedout);
        assert_eq!(TftpError::NoResponse.translate(), CurlCode::CouldntConnect);
        // The frozen integer values themselves.
        assert_eq!(i32::from(CurlCode::TftpNotfound), 68);
        assert_eq!(i32::from(CurlCode::RemoteDiskFull), 70);
        assert_eq!(i32::from(CurlCode::TftpNosuchuser), 74);
    }

    #[test]
    fn error_wire_round_trip() {
        assert_eq!(TftpError::NotFound.to_wire(), 1);
        assert_eq!(TftpError::NoSuchUser.to_wire(), 7);
        assert_eq!(TftpError::from_wire(0), TftpError::Undef);
        assert_eq!(TftpError::from_wire(3), TftpError::DiskFull);
        assert_eq!(TftpError::from_wire(7), TftpError::NoSuchUser);
        // Unknown wire codes fall back to Undef (→ CURLE_TFTP_ILLEGAL).
        assert_eq!(TftpError::from_wire(99), TftpError::Undef);
    }

    #[test]
    fn event_opcode_round_trip() {
        assert_eq!(TftpEvent::Rrq.opcode(), 1);
        assert_eq!(TftpEvent::Data.opcode(), 3);
        assert_eq!(TftpEvent::Oack.opcode(), 6);
        assert_eq!(TftpEvent::from_opcode(1), TftpEvent::Rrq);
        assert_eq!(TftpEvent::from_opcode(3), TftpEvent::Data);
        assert_eq!(TftpEvent::from_opcode(6), TftpEvent::Oack);
        assert_eq!(TftpEvent::from_opcode(99), TftpEvent::None);
    }

    // --- Framing helpers (← setpacket*/getrpacket*/NEXT_BLOCKNUM) ------------

    #[test]
    fn next_blocknum_wraps_at_16_bits() {
        assert_eq!(next_blocknum(0), 1);
        assert_eq!(next_blocknum(1), 2);
        assert_eq!(next_blocknum(65534), 65535);
        assert_eq!(next_blocknum(65535), 0);
    }

    #[test]
    fn packet_fields_are_big_endian() {
        let mut buf = [0u8; 8];
        set_packet_event(&mut buf, 3);
        set_packet_block(&mut buf, 0x1234);
        assert_eq!(buf[0], 0x00);
        assert_eq!(buf[1], 0x03);
        assert_eq!(buf[2], 0x12);
        assert_eq!(buf[3], 0x34);
        assert_eq!(get_packet_event(&buf), 3);
        assert_eq!(get_packet_block(&buf), 0x1234);
    }

    #[test]
    fn checkprefix_is_case_insensitive() {
        assert!(checkprefix("blksize", b"blksize"));
        assert!(checkprefix("blksize", b"BLKSIZE"));
        assert!(checkprefix("blksize", b"BlkSize"));
        assert!(checkprefix("tsize", b"tsizeextra"));
        assert!(!checkprefix("blksize", b"tsize"));
        assert!(!checkprefix("blksize", b"blk"));
    }

    #[test]
    fn parse_option_number_matches_curl_str_number() {
        assert_eq!(parse_option_number(b"512", 65464), Some(512));
        assert_eq!(parse_option_number(b"0", 65464), Some(0));
        assert_eq!(parse_option_number(b"", 65464), None);
        assert_eq!(parse_option_number(b"12a", 65464), None);
        // Overflow of the max is a conversion failure (like curl).
        assert_eq!(parse_option_number(b"70000", 65464), None);
    }

    #[test]
    fn parse_mode_suffix_strips_and_selects() {
        let (p, m) = parse_mode_suffix("/file;mode=netascii", TftpMode::Octet);
        assert_eq!(p, "/file");
        assert_eq!(m, TftpMode::Netascii);
        let (p, m) = parse_mode_suffix("/file;mode=octet", TftpMode::Netascii);
        assert_eq!(p, "/file");
        assert_eq!(m, TftpMode::Octet);
        let (p, m) = parse_mode_suffix("/plain", TftpMode::Octet);
        assert_eq!(p, "/plain");
        assert_eq!(m, TftpMode::Octet);
    }

    // --- Construction / buffer sizing (← tftp_connect) -----------------------

    #[test]
    fn new_sizes_buffers_and_clamps_blksize() {
        let c = TftpConn::new(TftpParams {
            filename: "f".into(),
            blksize: 1024,
            ..Default::default()
        });
        assert_eq!(c.requested_blksize(), 1024);
        // The negotiated size starts at the default until an OACK grows it.
        assert_eq!(c.blksize(), TFTP_BLKSIZE_DEFAULT);
        assert_eq!(c.spacket.len(), 1024 + 4);

        // A small blksize still allocates at least the 512-byte fallback.
        let c2 = TftpConn::new(TftpParams {
            blksize: 8,
            ..Default::default()
        });
        assert_eq!(c2.requested_blksize(), 8);
        assert_eq!(c2.spacket.len(), 512 + 4);

        // Zero requests the default; oversize is clamped to the maximum.
        let c3 = TftpConn::new(TftpParams::default());
        assert_eq!(c3.requested_blksize(), TFTP_BLKSIZE_DEFAULT);
        let c4 = TftpConn::new(TftpParams {
            blksize: 999_999,
            ..Default::default()
        });
        assert_eq!(c4.requested_blksize(), TFTP_BLKSIZE_MAX);
    }

    #[test]
    fn set_timeouts_defaults_without_deadline() {
        let mut c = TftpConn::new(TftpParams::default());
        c.set_timeouts().unwrap();
        // timeout = 15 → retry_max = clamp(15/5,3,50) = 3, retry_time = max(15/3,1) = 5.
        assert_eq!(c.retry_max, 3);
        assert_eq!(c.retry_time, 5);
    }

    // --- Request construction (← tftp_send_first / tftp_option_add) ----------

    #[test]
    fn build_rrq_frames_filename_mode_and_options() {
        let mut c = TftpConn::new(TftpParams {
            filename: "foo".into(),
            blksize: 512,
            ..Default::default()
        });
        c.set_timeouts().unwrap();
        c.build_first_request().unwrap();
        let len = c.send_len.unwrap();
        let pkt = &c.spacket[..len];
        // RRQ opcode.
        assert_eq!(&pkt[0..2], &[0u8, 1][..]);
        // filename\0mode\0
        assert_eq!(&pkt[2..12], b"foo\0octet\0");
        // Options, in curl's order: tsize (0 on download), blksize, timeout.
        assert_eq!(
            &pkt[12..],
            b"tsize\x000\x00blksize\x00512\x00timeout\x005\x00"
        );
    }

    #[test]
    fn build_wrq_uses_infilesize_for_tsize() {
        let mut c = TftpConn::new(TftpParams {
            filename: "up".into(),
            upload: true,
            infilesize: Some(9),
            blksize: 512,
            ..Default::default()
        });
        c.set_timeouts().unwrap();
        c.build_first_request().unwrap();
        let len = c.send_len.unwrap();
        let pkt = &c.spacket[..len];
        // WRQ opcode.
        assert_eq!(&pkt[0..2], &[0u8, 2][..]);
        assert_eq!(&pkt[2..11], b"up\0octet\0");
        // tsize carries the known upload size.
        assert_eq!(
            &pkt[11..],
            b"tsize\x009\x00blksize\x00512\x00timeout\x005\x00"
        );
    }

    #[test]
    fn build_request_without_options() {
        let mut c = TftpConn::new(TftpParams {
            filename: "f".into(),
            no_options: true,
            ..Default::default()
        });
        c.set_timeouts().unwrap();
        c.build_first_request().unwrap();
        let len = c.send_len.unwrap();
        assert_eq!(&c.spacket[..len], b"\x00\x01f\x00octet\x00");
    }

    #[test]
    fn build_request_rejects_empty_and_overlong_filename() {
        let mut c = TftpConn::new(TftpParams {
            filename: String::new(),
            ..Default::default()
        });
        c.set_timeouts().unwrap();
        assert_eq!(
            c.build_first_request().unwrap_err().code(),
            CurlCode::TftpIllegal
        );

        let mut c2 = TftpConn::new(TftpParams {
            filename: "x".repeat(600),
            ..Default::default()
        });
        c2.set_timeouts().unwrap();
        assert_eq!(
            c2.build_first_request().unwrap_err().code(),
            CurlCode::TftpIllegal
        );
    }

    // --- OACK negotiation (← tftp_parse_option_ack) --------------------------

    #[test]
    fn parse_oack_adopts_blksize_and_tsize() {
        let mut c = TftpConn::new(TftpParams {
            filename: "f".into(),
            blksize: 1024,
            ..Default::default()
        });
        let mut payload = Vec::new();
        payload.extend_from_slice(b"blksize\x00512\0");
        payload.extend_from_slice(b"tsize\x004096\0");
        c.parse_option_ack(&payload).unwrap();
        assert_eq!(c.blksize(), 512);
        assert_eq!(c.tsize(), Some(4096));
    }

    #[test]
    fn parse_oack_defaults_blksize_when_absent() {
        let mut c = TftpConn::new(TftpParams {
            filename: "f".into(),
            blksize: 1024,
            ..Default::default()
        });
        // Pretend a prior negotiation had grown the block size.
        c.blksize = 1024;
        c.parse_option_ack(b"tsize\x00100\0").unwrap();
        assert_eq!(c.blksize(), TFTP_BLKSIZE_DEFAULT);
    }

    #[test]
    fn parse_oack_rejects_bad_blksize() {
        // Larger than requested.
        let mut c = TftpConn::new(TftpParams {
            filename: "f".into(),
            blksize: 512,
            ..Default::default()
        });
        assert_eq!(
            c.parse_option_ack(b"blksize\x001024\0").unwrap_err().code(),
            CurlCode::TftpIllegal
        );
        // Below the minimum.
        let mut c2 = TftpConn::new(TftpParams {
            filename: "f".into(),
            blksize: 512,
            ..Default::default()
        });
        assert_eq!(
            c2.parse_option_ack(b"blksize\x004\0").unwrap_err().code(),
            CurlCode::TftpIllegal
        );
        // Zero.
        let mut c3 = TftpConn::new(TftpParams {
            filename: "f".into(),
            blksize: 512,
            ..Default::default()
        });
        assert_eq!(
            c3.parse_option_ack(b"blksize\x000\0").unwrap_err().code(),
            CurlCode::TftpIllegal
        );
    }

    #[test]
    fn parse_oack_rejects_malformed() {
        let mut c = TftpConn::new(TftpParams {
            filename: "f".into(),
            ..Default::default()
        });
        // An option name with no NUL/value is malformed.
        assert_eq!(
            c.parse_option_ack(b"blksize").unwrap_err().code(),
            CurlCode::TftpIllegal
        );
    }

    // --- rx handler (← tftp_rx) ---------------------------------------------

    #[test]
    fn rx_acks_expected_block_and_detects_eof() {
        let mut c = TftpConn::new(TftpParams {
            filename: "f".into(),
            blksize: 8,
            ..Default::default()
        });
        c.state = TftpState::Rx;
        c.blksize = 8;
        c.block = 0;
        c.rblock = 1;
        c.rbytes = 4 + 8; // a full block → not EOF
        c.rx(TftpEvent::Data).unwrap();
        assert_eq!(c.block, 1);
        assert_eq!(c.state, TftpState::Rx);
        assert_eq!(c.send_len, Some(4));
        assert_eq!(&c.spacket[0..4], &[0u8, 4, 0, 1][..]); // ACK block 1

        // A short block ends the transfer.
        c.rblock = 2;
        c.rbytes = 4 + 3;
        c.rx(TftpEvent::Data).unwrap();
        assert_eq!(c.block, 2);
        assert_eq!(c.state, TftpState::Fin);
    }

    #[test]
    fn rx_reacks_duplicate_without_resetting_retries() {
        let mut c = TftpConn::new(TftpParams {
            filename: "f".into(),
            blksize: 8,
            ..Default::default()
        });
        c.state = TftpState::Rx;
        c.blksize = 8;
        c.block = 5;
        c.retries = 2;
        c.rblock = 5; // duplicate of the last received block
        c.rbytes = 4 + 8;
        c.rx(TftpEvent::Data).unwrap();
        assert_eq!(c.block, 5);
        assert_eq!(c.retries, 2); // NOT reset for a duplicate
        assert_eq!(c.send_len, Some(4));
        assert_eq!(&c.spacket[0..4], &[0u8, 4, 0, 5][..]);
    }

    #[test]
    fn rx_ignores_unexpected_block() {
        let mut c = TftpConn::new(TftpParams {
            filename: "f".into(),
            blksize: 8,
            ..Default::default()
        });
        c.state = TftpState::Rx;
        c.blksize = 8;
        c.block = 5;
        c.send_len = None;
        c.rblock = 9; // neither next (6) nor duplicate (5)
        c.rbytes = 4 + 8;
        c.rx(TftpEvent::Data).unwrap();
        assert_eq!(c.block, 5); // unchanged
        assert_eq!(c.send_len, None); // no ACK sent
        assert_eq!(c.state, TftpState::Rx);
    }

    #[test]
    fn rx_oack_acks_block_zero() {
        let mut c = TftpConn::new(TftpParams {
            filename: "f".into(),
            ..Default::default()
        });
        c.state = TftpState::Rx;
        c.block = 99;
        c.rx(TftpEvent::Oack).unwrap();
        assert_eq!(c.block, 0);
        assert_eq!(c.send_len, Some(4));
        assert_eq!(&c.spacket[0..4], &[0u8, 4, 0, 0][..]);
        assert_eq!(c.state, TftpState::Rx);
    }

    #[test]
    fn rx_timeout_retransmits_then_gives_up() {
        let mut c = TftpConn::new(TftpParams {
            filename: "f".into(),
            ..Default::default()
        });
        c.state = TftpState::Rx;
        c.retry_max = 3;
        c.retries = 0;
        c.send_len = None;
        c.rx(TftpEvent::Timeout).unwrap();
        assert_eq!(c.retries, 1);
        assert_eq!(c.send_len, Some(4)); // resent previous ACK

        c.retries = 3;
        c.rx(TftpEvent::Timeout).unwrap();
        assert_eq!(c.error, TftpError::Timeout);
        assert_eq!(c.state, TftpState::Fin);
    }

    // --- tx handler (← tftp_tx) ---------------------------------------------

    #[test]
    fn tx_oack_sends_first_data_block() {
        let mut c = TftpConn::new(TftpParams {
            upload: true,
            no_options: true,
            ..Default::default()
        });
        c.state = TftpState::Tx;
        c.blksize = 512;
        let mut src: &[u8] = b"abcdef";
        c.tx(TftpEvent::Oack, &mut src).unwrap();
        assert_eq!(c.block, 1); // first data block is 1 after OACK
        assert_eq!(&c.spacket[0..4], &[0u8, 3, 0, 1][..]); // DATA block 1
        assert_eq!(c.send_len, Some(4 + 6));
        assert_eq!(&c.spacket[4..10], b"abcdef");
    }

    #[test]
    fn tx_expected_ack_advances_block() {
        let mut c = TftpConn::new(TftpParams {
            upload: true,
            no_options: true,
            ..Default::default()
        });
        c.state = TftpState::Tx;
        c.blksize = 512;
        c.block = 0;
        c.rblock = 0; // ACK for block 0 (the WRQ ACK)
        let mut src: &[u8] = b"payload";
        c.tx(TftpEvent::Ack, &mut src).unwrap();
        assert_eq!(c.block, 1);
        assert_eq!(c.send_len, Some(4 + 7));
    }

    #[test]
    fn tx_accepts_65535_ack_when_expecting_zero() {
        // tftpd-hpa wraparound quirk: expecting block 0, server acks 65535.
        let mut c = TftpConn::new(TftpParams {
            upload: true,
            no_options: true,
            ..Default::default()
        });
        c.state = TftpState::Tx;
        c.blksize = 512;
        c.block = 0;
        c.sbytes = 10;
        c.rblock = 65535;
        let mut src: &[u8] = b"more-data";
        c.tx(TftpEvent::Ack, &mut src).unwrap();
        // Treated as the expected ACK → advance from 0 to 1.
        assert_eq!(c.block, 1);
        assert!(c.send_len.is_some());
    }

    #[test]
    fn tx_wrong_ack_resends_then_gives_up() {
        let mut c = TftpConn::new(TftpParams {
            upload: true,
            no_options: true,
            ..Default::default()
        });
        c.state = TftpState::Tx;
        c.blksize = 512;
        c.block = 5;
        c.sbytes = 100;
        c.retry_max = 3;
        c.retries = 0;
        c.rblock = 3; // wrong ACK
        let mut src: &[u8] = b"unused";
        c.tx(TftpEvent::Ack, &mut src).unwrap();
        assert_eq!(c.block, 5); // unchanged
        assert_eq!(c.retries, 1);
        assert_eq!(c.send_len, Some(4 + 100)); // resent the data packet

        // Exhaust the retries → give up with a send error.
        c.retries = 3;
        assert_eq!(
            c.tx(TftpEvent::Ack, &mut src).unwrap_err().code(),
            CurlCode::SendError
        );
    }

    #[test]
    fn tx_finishes_after_short_block() {
        let mut c = TftpConn::new(TftpParams {
            upload: true,
            no_options: true,
            ..Default::default()
        });
        c.state = TftpState::Tx;
        c.blksize = 512;
        c.block = 1;
        c.sbytes = 100; // the previous block was short (< 512)
        c.rblock = 1;
        let mut src: &[u8] = b"";
        c.tx(TftpEvent::Ack, &mut src).unwrap();
        assert_eq!(c.block, 2);
        assert_eq!(c.state, TftpState::Fin);
    }

    // --- receive_packet: transfer-id pinning (← tftp_receive_packet) ---------

    #[test]
    fn receive_packet_pins_tid_and_rejects_others() {
        let mut c = TftpConn::new(TftpParams {
            filename: "f".into(),
            ..Default::default()
        });
        let addr_a: SocketAddr = "127.0.0.1:5001".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:5002".parse().unwrap();
        let mut sink: Vec<u8> = Vec::new();

        // First DATA block 1 pins addr_a and is delivered (next of 0 is 1).
        let mut data = Vec::new();
        data.extend_from_slice(&3u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(b"hello");
        c.receive_packet(&data, addr_a, &mut sink).unwrap();
        assert_eq!(c.remote_addr(), Some(addr_a));
        assert_eq!(c.event, TftpEvent::Data);
        assert_eq!(sink, b"hello");

        // A datagram from another address is rejected with CURLE_RECV_ERROR.
        assert_eq!(
            c.receive_packet(&data, addr_b, &mut sink)
                .unwrap_err()
                .code(),
            CurlCode::RecvError
        );
    }

    #[test]
    fn receive_packet_short_datagram_is_timeout() {
        let mut c = TftpConn::new(TftpParams {
            filename: "f".into(),
            ..Default::default()
        });
        let addr: SocketAddr = "127.0.0.1:5003".parse().unwrap();
        let mut sink: Vec<u8> = Vec::new();
        c.receive_packet(&[0u8, 3, 0], addr, &mut sink).unwrap();
        assert_eq!(c.event, TftpEvent::Timeout);
    }

    #[test]
    fn receive_packet_error_sets_error() {
        let mut c = TftpConn::new(TftpParams {
            filename: "f".into(),
            ..Default::default()
        });
        let addr: SocketAddr = "127.0.0.1:5004".parse().unwrap();
        let mut sink: Vec<u8> = Vec::new();
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&5u16.to_be_bytes()); // ERROR
        pkt.extend_from_slice(&2u16.to_be_bytes()); // PERM
        pkt.extend_from_slice(b"denied\0");
        c.receive_packet(&pkt, addr, &mut sink).unwrap();
        assert_eq!(c.error, TftpError::Perm);
        assert_eq!(c.event, TftpEvent::Error);
    }

    // --- Handler contract (← Curl_scheme_tftp / Curl_protocol vtable) --------

    #[test]
    fn handler_reports_udp_transport() {
        assert_eq!(HANDLER.transport(), Transport::Udp);
    }

    #[tokio::test]
    async fn handler_is_object_safe_and_do_it_done_behave() {
        // Exercised through &dyn Protocol, exactly as SCHEME_TFTP stores it.
        let handler: &dyn Protocol = &HANDLER;
        let mut ctx = TransferCtx::new();
        assert!(handler.do_it(&mut ctx).await.unwrap());
        // A successful status passes through.
        handler.done(&mut ctx, Ok(()), false).await.unwrap();
        // A failing status is propagated unchanged.
        let err = handler
            .done(&mut ctx, Err(Error::Code(CurlCode::TftpNotfound)), true)
            .await
            .unwrap_err();
        assert_eq!(err.code(), CurlCode::TftpNotfound);
    }

    // --- End-to-end transfers over a real UDP loopback socket ----------------
    //
    // Each in-process server binds a fresh socket for its replies (a new
    // transfer id), so these tests also exercise the client's TID-locking.

    /// Serve a download: parse the RRQ, optionally OACK-negotiate `blksize`,
    /// then stream DATA blocks and read each ACK, from a *new* socket.
    async fn serve_download(main: UdpSocket, file: Vec<u8>, use_oack: bool, blksize: usize) {
        let mut buf = vec![0u8; 4096];
        let (_n, client) = main.recv_from(&mut buf).await.unwrap(); // RRQ
        let data_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap(); // new TID
        if use_oack {
            let mut oack = Vec::new();
            oack.extend_from_slice(&6u16.to_be_bytes());
            oack.extend_from_slice(b"blksize\0");
            oack.extend_from_slice(blksize.to_string().as_bytes());
            oack.push(0);
            oack.extend_from_slice(b"tsize\0");
            oack.extend_from_slice(file.len().to_string().as_bytes());
            oack.push(0);
            data_sock.send_to(&oack, client).await.unwrap();
            let _ = data_sock.recv_from(&mut buf).await.unwrap(); // ACK(0)
        }
        let mut block: u16 = 1;
        let mut offset = 0usize;
        loop {
            let end = (offset + blksize).min(file.len());
            let chunk = &file[offset..end];
            let mut data = Vec::new();
            data.extend_from_slice(&3u16.to_be_bytes());
            data.extend_from_slice(&block.to_be_bytes());
            data.extend_from_slice(chunk);
            data_sock.send_to(&data, client).await.unwrap();
            let _ = data_sock.recv_from(&mut buf).await.unwrap(); // ACK(block)
            let short = chunk.len() < blksize;
            offset = end;
            block = block.wrapping_add(1);
            if short {
                break;
            }
        }
    }

    /// Serve an upload: parse the WRQ, ACK block 0, then read DATA blocks and
    /// ACK each, from a *new* socket. Returns the reassembled payload.
    async fn serve_upload(main: UdpSocket, blksize: usize) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        let (_n, client) = main.recv_from(&mut buf).await.unwrap(); // WRQ
        let data_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut ack0 = Vec::new();
        ack0.extend_from_slice(&4u16.to_be_bytes());
        ack0.extend_from_slice(&0u16.to_be_bytes());
        data_sock.send_to(&ack0, client).await.unwrap();
        let mut received = Vec::new();
        loop {
            let (n, _) = data_sock.recv_from(&mut buf).await.unwrap();
            let block = u16::from_be_bytes([buf[2], buf[3]]);
            let payload = &buf[4..n];
            received.extend_from_slice(payload);
            let mut ack = Vec::new();
            ack.extend_from_slice(&4u16.to_be_bytes());
            ack.extend_from_slice(&block.to_be_bytes());
            data_sock.send_to(&ack, client).await.unwrap();
            if payload.len() < blksize {
                break;
            }
        }
        received
    }

    /// Serve an ERROR packet in response to the first request, from a new socket.
    async fn serve_error(main: UdpSocket, code: u16, msg: &str) {
        let mut buf = vec![0u8; 4096];
        let (_n, client) = main.recv_from(&mut buf).await.unwrap();
        let data_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&5u16.to_be_bytes());
        pkt.extend_from_slice(&code.to_be_bytes());
        pkt.extend_from_slice(msg.as_bytes());
        pkt.push(0);
        data_sock.send_to(&pkt, client).await.unwrap();
    }

    #[tokio::test]
    async fn e2e_download_with_oack_multiblock() {
        let file: Vec<u8> = (0u8..37).collect(); // 37 bytes / blksize 8 → 5 blocks
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = serve_download(server_sock, file.clone(), true, 8);

        let mut conn = TftpConn::new(TftpParams {
            filename: "data.bin".into(),
            blksize: 8,
            ..Default::default()
        });
        let mut src: &[u8] = &[];
        let mut sink: Vec<u8> = Vec::new();
        let client = conn.run(&client_sock, server_addr, &mut src, &mut sink);

        let (_srv, cres) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(server, client)
        })
        .await
        .expect("test timed out");
        cres.expect("client download failed");
        assert_eq!(sink, file);
        assert_eq!(conn.blksize(), 8); // negotiated
        assert_eq!(conn.tsize(), Some(37)); // negotiated download size
    }

    #[tokio::test]
    async fn e2e_download_without_oack_single_block() {
        let file: Vec<u8> = b"hello world".to_vec();
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = serve_download(server_sock, file.clone(), false, 512);

        let mut conn = TftpConn::new(TftpParams {
            filename: "h.txt".into(),
            ..Default::default()
        });
        let mut src: &[u8] = &[];
        let mut sink: Vec<u8> = Vec::new();
        let client = conn.run(&client_sock, server_addr, &mut src, &mut sink);

        let (_srv, cres) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(server, client)
        })
        .await
        .expect("test timed out");
        cres.expect("client download failed");
        assert_eq!(sink, file);
        assert_eq!(conn.blksize(), TFTP_BLKSIZE_DEFAULT); // no negotiation
    }

    #[tokio::test]
    async fn e2e_upload_multiblock() {
        let payload: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = serve_upload(server_sock, 512);

        let mut conn = TftpConn::new(TftpParams {
            filename: "up.bin".into(),
            upload: true,
            no_options: true,
            infilesize: Some(1000),
            ..Default::default()
        });
        let src_data = payload.clone();
        let mut src: &[u8] = &src_data;
        let mut sink: Vec<u8> = Vec::new();
        let client = conn.run(&client_sock, server_addr, &mut src, &mut sink);

        let (received, cres) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(server, client)
        })
        .await
        .expect("test timed out");
        cres.expect("client upload failed");
        assert_eq!(received, payload);
        assert_eq!(conn.bytecount(), 1000);
    }

    #[tokio::test]
    async fn e2e_server_error_maps_to_curl_code() {
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = serve_error(server_sock, 1, "File not found"); // wire 1 = NOTFOUND

        let mut conn = TftpConn::new(TftpParams {
            filename: "missing".into(),
            ..Default::default()
        });
        let mut src: &[u8] = &[];
        let mut sink: Vec<u8> = Vec::new();
        let client = conn.run(&client_sock, server_addr, &mut src, &mut sink);

        let (_srv, cres) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(server, client)
        })
        .await
        .expect("test timed out");
        let err = cres.expect_err("expected a TFTP error");
        assert_eq!(err.code(), CurlCode::TftpNotfound);
    }
}
