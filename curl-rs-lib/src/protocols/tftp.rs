//! TFTP — the Trivial File Transfer Protocol (`tftp://`).
//!
//! This is the idiomatic-async-Rust port of curl's `lib/tftp.c`. TFTP is the
//! one protocol in the workspace that runs over **UDP datagrams**
//! ([`TRNSPRT_UDP`]) rather than a reliable byte stream, so it implements its
//! own reliability on top of unreliable datagrams: a strictly *lock-step*
//! request/acknowledgement exchange (RFC 1350) optionally extended with the
//! `blksize`, `tsize`, and `timeout` options (RFC 2347/2348/2349).
//!
//! # Wire model
//!
//! Every TFTP packet begins with a two-byte big-endian *opcode*:
//!
//! | Opcode | Name  | Layout                                   |
//! |-------:|-------|------------------------------------------|
//! | 1      | RRQ   | `opcode \| filename\0 \| mode\0 \| opts` |
//! | 2      | WRQ   | `opcode \| filename\0 \| mode\0 \| opts` |
//! | 3      | DATA  | `opcode \| block# \| payload`            |
//! | 4      | ACK   | `opcode \| block#`                       |
//! | 5      | ERROR | `opcode \| errcode \| message\0`         |
//! | 6      | OACK  | `opcode \| (option\0 value\0)...`        |
//!
//! A download is driven by `RRQ`: for every `DATA(n)` the client writes the
//! payload to the body sink and replies `ACK(n)`; a DATA packet shorter than
//! the negotiated block size terminates the transfer. An upload is driven by
//! `WRQ`: after the server acknowledges with `ACK(0)` (or `OACK`), the client
//! sends `DATA(n)` and awaits `ACK(n)`; the final, short DATA block ends it.
//!
//! # Reliability
//!
//! Because UDP provides no delivery guarantees, the engine owns a per-block
//! retransmission timer (`retry_time` seconds) and a retry cap (`retry_max`),
//! computed from the transfer's remaining time exactly as `tftp.c` does. The
//! server replies from a freshly chosen ephemeral port (its *transfer ID*);
//! after the first response the engine *pins* that peer address and rejects
//! datagrams from any other source ([`CurlError::RecvError`]), mirroring the
//! C `tftp_receive_packet` "Data received from another address" guard.
//!
//! # Layering
//!
//! The pure protocol logic — the packet codec, the [`TftpConn`] state machine,
//! and option negotiation — is fully synchronous and unit-testable in
//! isolation. Datagram transport is abstracted behind the [`TftpIo`] trait, of
//! which [`UdpTftpIo`] is the production implementation over
//! [`tokio::net::UdpSocket`]. The body sink and upload source are abstracted
//! behind [`TftpDataSink`] / [`TftpDataSource`], and [`run_transfer`] ties the
//! three together into the lock-step drive loop. This crate forbids `unsafe`
//! at its root; this module adds none.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::conn::{BoxFuture, Connection, TRNSPRT_UDP};
use crate::easy::Easy;
use crate::error::{CurlError, Result};
use crate::protocols::{Protocol, ProtocolTransfer, Scheme, TransferDirection, SCHEME_TFTP};
use crate::setopt::HttpReq;
use crate::transfer::{
    uc_to_curlcode, ClientWriteType, ClientWriter, ReadCallback, ReadStep, UploadReader,
    WriteCallbacks,
};
use crate::url::{CurlUPart, CurlUrl, CURLU_DEFAULT_PORT, CURLU_GUESS_SCHEME, CURLU_URLDECODE};
use crate::util::sendf::{failf, infof};
use crate::util::timediff::ms_to_duration;
use crate::util::timeval::{curlx_now, curlx_timediff, CurlTime};

// =============================================================================
// Constants (mirroring `lib/tftp.c`)
// =============================================================================

/// Default TFTP transfer block size in bytes (`TFTP_BLKSIZE_DEFAULT`). This is
/// the only value the base RFC 1350 protocol uses and the value assumed when
/// the server's `OACK` omits a `blksize` option.
pub const TFTP_BLKSIZE_DEFAULT: u16 = 512;

/// Smallest block size curl will accept from a server (`TFTP_BLKSIZE_MIN`,
/// `lib/tftp.h`). A negotiated `blksize` below this is rejected as illegal.
pub const TFTP_BLKSIZE_MIN: u16 = 8;

/// Largest block size curl will request or accept (`TFTP_BLKSIZE_MAX`,
/// `lib/tftp.h`). Chosen so a full datagram (`blksize + 4` header bytes) fits
/// comfortably below the IPv4 minimum-MTU reassembly limit.
pub const TFTP_BLKSIZE_MAX: u16 = 65464;

/// RFC 2348 block-size option name.
pub const TFTP_OPTION_BLKSIZE: &str = "blksize";
/// RFC 2349 transfer-size option name.
pub const TFTP_OPTION_TSIZE: &str = "tsize";
/// RFC 2349 timeout-interval option name.
pub const TFTP_OPTION_INTERVAL: &str = "timeout";

/// Read request opcode.
pub const TFTP_OPCODE_RRQ: u16 = 1;
/// Write request opcode.
pub const TFTP_OPCODE_WRQ: u16 = 2;
/// Data packet opcode.
pub const TFTP_OPCODE_DATA: u16 = 3;
/// Acknowledgement opcode.
pub const TFTP_OPCODE_ACK: u16 = 4;
/// Error packet opcode.
pub const TFTP_OPCODE_ERROR: u16 = 5;
/// Option-acknowledgement opcode (RFC 2347).
pub const TFTP_OPCODE_OACK: u16 = 6;

// =============================================================================
// Enumerations (mirroring `tftp_mode_t`, `tftp_state_t`, `tftp_event_t`,
// `tftp_error_t`)
// =============================================================================

/// Transfer mode carried in the `RRQ`/`WRQ` packet (`tftp_mode_t`).
///
/// curl only ever uses `octet` (binary) unless the user explicitly requests
/// text transfers or the URL carries a `;mode=netascii` suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TftpMode {
    /// `netascii` — line-ending-translated text mode.
    Netascii,
    /// `octet` — raw binary mode (curl's default).
    Octet,
}

impl TftpMode {
    /// The on-the-wire mode string (`"netascii"` or `"octet"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            TftpMode::Netascii => "netascii",
            TftpMode::Octet => "octet",
        }
    }
}

/// The lock-step state-machine states (`tftp_state_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TftpState {
    /// Initial state: the request (`RRQ`/`WRQ`) has not yet been answered.
    Start,
    /// Receiving (download): awaiting `DATA`, replying `ACK`.
    Rx,
    /// Transmitting (upload): sending `DATA`, awaiting `ACK`.
    Tx,
    /// Terminal state: the transfer has finished (successfully or in error).
    Fin,
}

/// Events that drive the state machine (`tftp_event_t`).
///
/// The numeric discriminants match the C enumeration: the packet opcodes map
/// onto [`TftpEvent::Rrq`]`..=`[`TftpEvent::Oack`], with [`TftpEvent::None`]
/// (`-1`), [`TftpEvent::Init`] (`0`) and [`TftpEvent::Timeout`] (`7`) as the
/// internal, non-wire events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum TftpEvent {
    /// No event (sentinel, `TFTP_EVENT_NONE`).
    None = -1,
    /// Begin the transfer (`TFTP_EVENT_INIT`): send the first `RRQ`/`WRQ`.
    Init = 0,
    /// A read request was received (unused by the client; `TFTP_EVENT_RRQ`).
    Rrq = 1,
    /// A write request was received (unused by the client; `TFTP_EVENT_WRQ`).
    Wrq = 2,
    /// A `DATA` packet arrived.
    Data = 3,
    /// An `ACK` packet arrived.
    Ack = 4,
    /// An `ERROR` packet arrived.
    Error = 5,
    /// An `OACK` (option acknowledgement) arrived.
    Oack = 6,
    /// The retransmission timer fired (`TFTP_EVENT_TIMEOUT`).
    Timeout = 7,
}

impl TftpEvent {
    /// Map a wire opcode onto the corresponding event. Unknown opcodes yield
    /// [`TftpEvent::None`].
    #[must_use]
    pub fn from_opcode(opcode: u16) -> TftpEvent {
        match opcode {
            TFTP_OPCODE_RRQ => TftpEvent::Rrq,
            TFTP_OPCODE_WRQ => TftpEvent::Wrq,
            TFTP_OPCODE_DATA => TftpEvent::Data,
            TFTP_OPCODE_ACK => TftpEvent::Ack,
            TFTP_OPCODE_ERROR => TftpEvent::Error,
            TFTP_OPCODE_OACK => TftpEvent::Oack,
            _ => TftpEvent::None,
        }
    }
}

/// TFTP error conditions (`tftp_error_t`).
///
/// Variants [`TftpError::Undef`]`..=`[`TftpError::Nosuchuser`] are the RFC 1350
/// wire error codes (0..=7). The remaining variants are curl-internal pseudo
/// errors used by the state machine to record *why* a transfer ended:
/// [`TftpError::None`] (no error), [`TftpError::Timeout`] (the retry cap was
/// exhausted mid-transfer) and [`TftpError::Noresponse`] (the server never
/// answered the initial request). [`TftpError::Other`] preserves any
/// out-of-range wire code so it can still be reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TftpError {
    /// No error recorded (curl-internal `TFTP_ERR_NONE`).
    None,
    /// Not defined, see the error message (wire code 0).
    Undef,
    /// File not found (wire code 1).
    Notfound,
    /// Access violation (wire code 2).
    Perm,
    /// Disk full or allocation exceeded (wire code 3).
    Diskfull,
    /// Illegal TFTP operation (wire code 4).
    Illegal,
    /// Unknown transfer ID (wire code 5).
    Unknownid,
    /// File already exists (wire code 6).
    Exists,
    /// No such user (wire code 7).
    Nosuchuser,
    /// curl-internal: the retry cap was reached mid-transfer (`TFTP_ERR_TIMEOUT`).
    Timeout,
    /// curl-internal: no response to the initial request (`TFTP_ERR_NORESPONSE`).
    Noresponse,
    /// An out-of-range wire error code that has no named variant.
    Other(u16),
}

impl TftpError {
    /// Map a wire error code (the `errcode` field of an `ERROR` packet) onto a
    /// [`TftpError`]. Codes outside `0..=7` are preserved via
    /// [`TftpError::Other`].
    #[must_use]
    pub fn from_code(code: u16) -> TftpError {
        match code {
            0 => TftpError::Undef,
            1 => TftpError::Notfound,
            2 => TftpError::Perm,
            3 => TftpError::Diskfull,
            4 => TftpError::Illegal,
            5 => TftpError::Unknownid,
            6 => TftpError::Exists,
            7 => TftpError::Nosuchuser,
            other => TftpError::Other(other),
        }
    }

    /// Translate the recorded error into the public [`CurlError`], mirroring
    /// `tftp.c`'s `tftp_translate_code`. [`TftpError::None`] maps to `Ok(())`.
    pub fn translate(self) -> Result<()> {
        match self {
            TftpError::None => Ok(()),
            TftpError::Notfound => Err(CurlError::TftpNotfound),
            TftpError::Perm => Err(CurlError::TftpPerm),
            TftpError::Diskfull => Err(CurlError::RemoteDiskFull),
            // Both "not defined" and "illegal operation" surface as the generic
            // illegal-operation code, exactly as the C switch does.
            TftpError::Undef | TftpError::Illegal => Err(CurlError::TftpIllegal),
            TftpError::Unknownid => Err(CurlError::TftpUnknownid),
            TftpError::Exists => Err(CurlError::RemoteFileExists),
            TftpError::Nosuchuser => Err(CurlError::TftpNosuchuser),
            TftpError::Timeout => Err(CurlError::OperationTimedout),
            TftpError::Noresponse => Err(CurlError::CouldntConnect),
            // Any unknown wire code is reported the same way the C `default:`
            // arm does — as an aborted callback.
            TftpError::Other(_) => Err(CurlError::AbortedByCallback),
        }
    }
}

// =============================================================================
// Packet codec (pure, synchronous, fully unit-tested)
// =============================================================================

/// Read the two-byte big-endian opcode from the front of a packet. Returns `0`
/// (an invalid opcode) for packets too short to contain one, so callers never
/// index out of bounds.
fn opcode_of(pkt: &[u8]) -> u16 {
    if pkt.len() < 2 {
        return 0;
    }
    u16::from_be_bytes([pkt[0], pkt[1]])
}

/// Read the two-byte big-endian block number (bytes 2..4) of a `DATA`/`ACK`
/// packet. Returns `0` for packets too short to contain one.
fn block_of(pkt: &[u8]) -> u16 {
    if pkt.len() < 4 {
        return 0;
    }
    u16::from_be_bytes([pkt[2], pkt[3]])
}

/// The next block number with 16-bit wraparound, mirroring the C
/// `NEXT_BLOCKNUM(x) == (((x) + 1) & 0xffff)` macro.
#[must_use]
fn next_blocknum(block: u16) -> u16 {
    block.wrapping_add(1)
}

/// Encode an `RRQ` (opcode 1) or `WRQ` (opcode 2) request:
/// `opcode | filename\0 | mode\0 | (option\0 value\0)...`.
fn encode_request(
    opcode: u16,
    filename: &str,
    mode: &str,
    options: &[(String, String)],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + filename.len() + mode.len() + 2 + 32);
    buf.extend_from_slice(&opcode.to_be_bytes());
    buf.extend_from_slice(filename.as_bytes());
    buf.push(0);
    buf.extend_from_slice(mode.as_bytes());
    buf.push(0);
    for (name, value) in options {
        buf.extend_from_slice(name.as_bytes());
        buf.push(0);
        buf.extend_from_slice(value.as_bytes());
        buf.push(0);
    }
    buf
}

/// Encode a `DATA` packet: `opcode(3) | block# | payload`.
fn encode_data(block: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&TFTP_OPCODE_DATA.to_be_bytes());
    buf.extend_from_slice(&block.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Encode an `ACK` packet: `opcode(4) | block#`.
fn encode_ack(block: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4);
    buf.extend_from_slice(&TFTP_OPCODE_ACK.to_be_bytes());
    buf.extend_from_slice(&block.to_be_bytes());
    buf
}

/// Encode the four-byte `ERROR` reply curl emits from the `RX`/`TX` states.
///
/// Faithful to `tftp.c`: when curl aborts a transfer it sends only the
/// opcode plus the *current block number* in the error-code field (it never
/// originates a textual error message), so this is `opcode(5) | block#`.
fn encode_error_reply(block: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4);
    buf.extend_from_slice(&TFTP_OPCODE_ERROR.to_be_bytes());
    buf.extend_from_slice(&block.to_be_bytes());
    buf
}

/// Decode a received `ERROR` packet into its `(errcode, message)` pair.
///
/// The message is the NUL-terminated string following the two-byte error code;
/// any bytes after the first NUL (or the absence of one) are tolerated, and the
/// text is decoded lossily so malformed UTF-8 cannot fail the parse.
fn decode_error(pkt: &[u8]) -> (u16, String) {
    let code = block_of(pkt); // the errcode occupies the same 2..4 slot as a block#
    let msg = if pkt.len() > 4 {
        let tail = &pkt[4..];
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        String::from_utf8_lossy(&tail[..end]).into_owned()
    } else {
        String::new()
    };
    (code, msg)
}

/// Parse the option/value pairs of an `OACK` body (the bytes *after* the
/// opcode). Returns [`None`] if the buffer is malformed — i.e. an option name
/// or value is not NUL-terminated within the buffer — which the caller maps to
/// [`CurlError::TftpIllegal`], mirroring the C "Malformed ACK packet" guard.
fn parse_oack_options(mut data: &[u8]) -> Option<Vec<(String, String)>> {
    let mut options = Vec::new();
    while !data.is_empty() {
        let name_end = data.iter().position(|&b| b == 0)?;
        let name = &data[..name_end];
        data = &data[name_end + 1..];

        let value_end = data.iter().position(|&b| b == 0)?;
        let value = &data[..value_end];
        data = &data[value_end + 1..];

        options.push((
            String::from_utf8_lossy(name).into_owned(),
            String::from_utf8_lossy(value).into_owned(),
        ));
    }
    Some(options)
}

/// Case-insensitive ASCII prefix test, the equivalent of curl's `checkprefix`.
/// Returns `true` when `s` begins with `prefix` ignoring ASCII case.
fn checkprefix(prefix: &str, s: &str) -> bool {
    let p = prefix.as_bytes();
    let b = s.as_bytes();
    b.len() >= p.len() && b[..p.len()].eq_ignore_ascii_case(p)
}

/// Strip a trailing `;mode=netascii` / `;mode=octet` suffix from a URL path and
/// determine the transfer mode, faithful to `tftp.c`'s `tftp_setup_connection`
/// (which compares the fixed-length suffix, not an embedded substring).
///
/// When no suffix is present, `prefer_ascii` (set by `CURLOPT_TRANSFERTEXT` /
/// `-B`) selects the mode. Returns the mode and the path with any suffix
/// removed.
fn parse_mode(path: &str, prefer_ascii: bool) -> (TftpMode, String) {
    if let Some(stripped) = path.strip_suffix(";mode=netascii") {
        (TftpMode::Netascii, stripped.to_string())
    } else if let Some(stripped) = path.strip_suffix(";mode=octet") {
        (TftpMode::Octet, stripped.to_string())
    } else if prefer_ascii {
        (TftpMode::Netascii, path.to_string())
    } else {
        (TftpMode::Octet, path.to_string())
    }
}

/// Derive the retransmission parameters from the transfer's remaining time,
/// mirroring `tftp.c`'s `tftp_set_timeouts`.
///
/// Returns `(retry_max, retry_time_seconds)`. A negative `timeleft_ms`
/// (the overall transfer deadline already elapsed) yields
/// [`CurlError::OperationTimedout`]. With no deadline (`timeleft_ms == 0`) the
/// C default of a 15-second budget is used. `retry_max` is clamped to
/// `3..=50` and `retry_time` to a one-second minimum.
fn compute_timeouts(timeleft_ms: i64) -> Result<(i32, i32)> {
    if timeleft_ms < 0 {
        return Err(CurlError::OperationTimedout);
    }
    // Whole-second budget: round to the nearest second when a deadline exists,
    // else fall back to curl's hard-coded 15s.
    let timeout: i64 = if timeleft_ms > 0 {
        timeleft_ms.saturating_add(500) / 1000
    } else {
        15
    };
    let retry_max = (timeout / 5).clamp(3, 50) as i32;
    let retry_time = (timeout / i64::from(retry_max)).clamp(1, i64::from(i32::MAX)) as i32;
    Ok((retry_max, retry_time))
}

/// Enforce the server transfer-ID (TID) lock. The first datagram pins the peer
/// address; every later datagram must come from that same address or it is
/// rejected with [`CurlError::RecvError`], mirroring the C
/// "Data received from another address" check in `tftp_receive_packet`.
fn check_peer(pinned: &mut Option<SocketAddr>, from: SocketAddr) -> Result<()> {
    match *pinned {
        Some(addr) if addr != from => Err(CurlError::RecvError),
        Some(_) => Ok(()),
        None => {
            *pinned = Some(from);
            Ok(())
        }
    }
}

// =============================================================================
// Request configuration
// =============================================================================

/// The immutable parameters of a single TFTP transfer, distilled from the URL
/// and the easy-handle options before the state machine starts.
#[derive(Debug, Clone)]
pub struct TftpRequest {
    /// The remote file name (the URL path with its leading `/` and any
    /// `;mode=` suffix removed, URL-decoded).
    pub filename: String,
    /// The transfer mode advertised in the `RRQ`/`WRQ`.
    pub mode: TftpMode,
    /// `true` for an upload (`WRQ`), `false` for a download (`RRQ`).
    pub upload: bool,
    /// The block size to request via the `blksize` option. `0` means "use the
    /// default 512 and request no custom block size".
    pub requested_blksize: u16,
    /// When `true`, suppress all TFTP options (no `blksize`/`tsize`/`timeout`),
    /// matching `CURLOPT_TFTP_NO_OPTIONS`.
    pub no_options: bool,
    /// The known upload size in bytes, or `-1` if unknown
    /// (`CURLOPT_INFILESIZE`). Used only to populate the `tsize` option.
    pub infilesize: i64,
}

impl TftpRequest {
    /// Build a request from a `tftp://` URL and the relevant easy-handle
    /// options.
    ///
    /// The URL is parsed with the workspace URL engine; the path is URL-decoded
    /// and stripped of a leading `/` and any `;mode=` suffix to yield the
    /// remote file name. An empty file name (e.g. `tftp://host/`) is rejected
    /// with [`CurlError::TftpIllegal`], matching the C "Missing filename" path.
    ///
    /// # Errors
    ///
    /// Returns a [`CurlError`] if the URL cannot be parsed or carries no file
    /// name.
    pub fn from_url(
        url: &str,
        requested_blksize: u16,
        no_options: bool,
        prefer_ascii: bool,
        infilesize: i64,
        upload: bool,
    ) -> Result<TftpRequest> {
        let mut parsed = CurlUrl::new();
        parsed
            .set(CurlUPart::Url, Some(url), CURLU_GUESS_SCHEME)
            .map_err(uc_to_curlcode)?;
        // The `tftp` scheme has `urloptions: false`, so the `;mode=` suffix is
        // preserved in the path here for us to interpret ourselves.
        let path = parsed
            .get(CurlUPart::Path, CURLU_URLDECODE)
            .map_err(uc_to_curlcode)?;

        let (mode, stripped) = parse_mode(&path, prefer_ascii);
        let filename = stripped.strip_prefix('/').unwrap_or(&stripped).to_string();
        if filename.is_empty() {
            return Err(CurlError::TftpIllegal);
        }

        Ok(TftpRequest {
            filename,
            mode,
            upload,
            requested_blksize,
            no_options,
            infilesize,
        })
    }
}

/// The result of feeding one event to the [`TftpConn`] state machine: an
/// optional datagram to transmit, and whether the transfer has finished.
#[derive(Debug, Default)]
pub struct StepOutcome {
    /// A datagram to send to the server, if the step produced one.
    pub send: Option<Vec<u8>>,
    /// `true` once the machine has reached [`TftpState::Fin`].
    pub done: bool,
}

// =============================================================================
// State machine engine
// =============================================================================

/// The TFTP lock-step state machine — the synchronous heart of the protocol,
/// independent of any particular I/O or runtime.
///
/// [`run_transfer`] owns one of these, feeding it received packets and timer
/// events via [`TftpConn::on_receive`] and [`TftpConn::step`] and transmitting
/// whatever datagrams the steps produce. Every method is synchronous and
/// testable without a socket.
pub struct TftpConn {
    /// Current state.
    state: TftpState,
    /// Transfer mode (`octet`/`netascii`).
    mode: TftpMode,
    /// The terminal error condition, recorded as the machine runs and mapped to
    /// a [`CurlError`] by [`TftpConn::translate`] when the transfer ends.
    error: TftpError,
    /// `true` for uploads.
    upload: bool,
    /// Whether to suppress TFTP options in the request.
    no_options: bool,
    /// Known upload size, or `-1`.
    infilesize: i64,
    /// Remote file name.
    filename: String,
    /// Verbose-logging flag (drives [`infof`]).
    verbose: bool,

    /// Negotiated block size: 512 until an `OACK` raises it.
    blksize: usize,
    /// The block size advertised in our request.
    requested_blksize: usize,
    /// `max(requested_blksize, 512)` — the receive-buffer sizing basis.
    need_blksize: usize,

    /// The current block number (the block we last sent or acknowledged).
    block: u16,
    /// Consecutive retransmissions of the current packet.
    retries: i32,
    /// The retry cap; exceeding it ends the transfer with a timeout.
    retry_max: i32,
    /// The per-block retransmission interval, in seconds.
    retry_time: i32,

    /// Payload byte count of the last `DATA` packet we built (upload).
    sbytes: usize,
    /// Byte count of the most recently received packet.
    rbytes: usize,
    /// Buffer holding the most recently received packet (`rbytes` long).
    rpacket: Vec<u8>,
    /// The last datagram we sent, retained for retransmission on timeout.
    spacket: Vec<u8>,

    /// Absolute deadline for the whole transfer (monotonic).
    deadline: CurlTime,
    /// Download size advertised by the server's `tsize` option, if any.
    download_size: Option<u64>,
}

impl TftpConn {
    /// Create a fresh state machine for the given request. The receive buffer
    /// is sized for `max(requested_blksize, 512) + 4` bytes so it can hold any
    /// DATA packet the server may send within the negotiated range.
    #[must_use]
    pub fn new(req: TftpRequest) -> Self {
        let requested = if req.requested_blksize == 0 {
            TFTP_BLKSIZE_DEFAULT as usize
        } else {
            req.requested_blksize as usize
        };
        let need = requested.max(TFTP_BLKSIZE_DEFAULT as usize);
        TftpConn {
            state: TftpState::Start,
            mode: req.mode,
            error: TftpError::None,
            upload: req.upload,
            no_options: req.no_options,
            infilesize: req.infilesize,
            filename: req.filename,
            verbose: false,
            blksize: TFTP_BLKSIZE_DEFAULT as usize,
            requested_blksize: requested,
            need_blksize: need,
            block: 0,
            retries: 0,
            retry_max: 0,
            retry_time: 0,
            sbytes: 0,
            rbytes: 0,
            rpacket: vec![0u8; need + 4],
            spacket: Vec::new(),
            deadline: CurlTime::zero(),
            download_size: None,
        }
    }

    /// The current state (chiefly for tests and the drive loop).
    #[must_use]
    pub fn state(&self) -> TftpState {
        self.state
    }

    /// The negotiated block size in bytes.
    #[must_use]
    pub fn blksize(&self) -> usize {
        self.blksize
    }

    /// The server-advertised download size, if a `tsize` option was received.
    #[must_use]
    pub fn download_size(&self) -> Option<u64> {
        self.download_size
    }

    /// The size of the buffer [`run_transfer`] should provide to
    /// [`TftpIo::recv_packet`].
    #[must_use]
    pub fn recv_buf_size(&self) -> usize {
        self.need_blksize + 4
    }

    /// Set the absolute transfer deadline `timeleft_ms` milliseconds from now.
    pub fn set_deadline_ms(&mut self, timeleft_ms: i64) {
        let now = curlx_now();
        let deadline = now.as_duration() + ms_to_duration(timeleft_ms.max(0));
        self.deadline = CurlTime::from_duration(deadline);
    }

    /// Milliseconds remaining until the transfer deadline (negative once it has
    /// elapsed).
    #[must_use]
    pub fn timeleft_ms(&self) -> i64 {
        curlx_timediff(self.deadline, curlx_now())
    }

    /// Recompute `retry_max`/`retry_time` from the time remaining, mirroring the
    /// C `tftp_set_timeouts` called on each state transition.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::OperationTimedout`] if the deadline has elapsed.
    fn refresh_timeouts(&mut self, errbuf: &mut Option<String>) -> Result<()> {
        let timeleft = self.timeleft_ms();
        let (retry_max, retry_time) = compute_timeouts(timeleft).map_err(|e| {
            failf(errbuf, "TFTP: Connection time-out");
            e
        })?;
        self.retry_max = retry_max;
        self.retry_time = retry_time;
        infof(
            self.verbose,
            &format!(
                "set timeouts for state {:?}; total {} ms, retry {} secs, max {} tries",
                self.state, timeleft, self.retry_time, self.retry_max
            ),
        );
        Ok(())
    }

    /// Store a freshly received datagram for the next [`TftpConn::on_receive`].
    pub fn set_received(&mut self, pkt: &[u8]) {
        let n = pkt.len();
        if self.rpacket.len() < n {
            self.rpacket.resize(n, 0);
        }
        self.rpacket[..n].copy_from_slice(pkt);
        self.rbytes = n;
    }

    /// Parse an `OACK` body and negotiate options, mirroring
    /// `tftp_parse_option_ack`.
    ///
    /// The block size is reset to the 512 default first, so an `OACK` lacking a
    /// `blksize` option correctly falls back. A `blksize` that is zero, below
    /// [`TFTP_BLKSIZE_MIN`], above [`TFTP_BLKSIZE_MAX`], or larger than what we
    /// requested is rejected with [`CurlError::TftpIllegal`]. A `tsize` option
    /// is honored only for downloads.
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::TftpIllegal`] for a malformed packet or an
    /// out-of-range option value.
    fn parse_option_ack(&mut self, data: &[u8], errbuf: &mut Option<String>) -> Result<()> {
        // Default if the OACK omits blksize (faithful to the C comment).
        self.blksize = TFTP_BLKSIZE_DEFAULT as usize;

        let options = match parse_oack_options(data) {
            Some(o) => o,
            None => {
                failf(errbuf, "Malformed ACK packet, rejecting");
                return Err(CurlError::TftpIllegal);
            }
        };

        for (option, value) in options {
            infof(
                self.verbose,
                &format!("got option=({option}) value=({value})"),
            );
            if checkprefix(TFTP_OPTION_BLKSIZE, &option) {
                let blksize = match value.trim().parse::<i64>() {
                    Ok(n) if n <= i64::from(TFTP_BLKSIZE_MAX) => n,
                    _ => {
                        failf(
                            errbuf,
                            &format!("blksize is larger than max supported ({TFTP_BLKSIZE_MAX})"),
                        );
                        return Err(CurlError::TftpIllegal);
                    }
                };
                if blksize == 0 {
                    failf(errbuf, "invalid blocksize value in OACK packet");
                    return Err(CurlError::TftpIllegal);
                } else if blksize < i64::from(TFTP_BLKSIZE_MIN) {
                    failf(
                        errbuf,
                        &format!("blksize is smaller than min supported ({TFTP_BLKSIZE_MIN})"),
                    );
                    return Err(CurlError::TftpIllegal);
                } else if blksize > self.requested_blksize as i64 {
                    failf(
                        errbuf,
                        &format!("server requested blksize larger than allocated ({blksize})"),
                    );
                    return Err(CurlError::TftpIllegal);
                }
                self.blksize = blksize as usize;
                infof(
                    self.verbose,
                    &format!(
                        "blksize parsed from OACK ({}) requested ({})",
                        self.blksize, self.requested_blksize
                    ),
                );
            } else if checkprefix(TFTP_OPTION_TSIZE, &option) && !self.upload {
                if let Ok(tsize) = value.trim().parse::<i64>() {
                    if tsize == 0 {
                        failf(errbuf, "invalid tsize value in OACK packet");
                        return Err(CurlError::TftpIllegal);
                    }
                    infof(self.verbose, &format!("tsize parsed from OACK ({tsize})"));
                    self.download_size = Some(tsize as u64);
                }
            }
        }
        Ok(())
    }
}

impl TftpConn {
    /// Interpret the stored received packet (see [`TftpConn::set_received`]),
    /// performing the side effects the C `tftp_receive_packet` performs before
    /// dispatch: writing fresh `DATA` payload to `sink`, recording the error
    /// code of an `ERROR` packet, and negotiating an `OACK`'s options. Returns
    /// the [`TftpEvent`] the packet represents for the subsequent
    /// [`TftpConn::step`].
    ///
    /// A packet shorter than four bytes is treated as a [`TftpEvent::Timeout`]
    /// ("Received too short packet"), exactly as in C.
    ///
    /// # Errors
    ///
    /// Propagates [`CurlError::TftpIllegal`] from a malformed `OACK`.
    pub fn on_receive(
        &mut self,
        sink: &mut dyn TftpDataSink,
        errbuf: &mut Option<String>,
    ) -> Result<TftpEvent> {
        if self.rbytes < 4 {
            infof(self.verbose, "Received too short packet");
            return Ok(TftpEvent::Timeout);
        }
        let event = TftpEvent::from_opcode(opcode_of(&self.rpacket));
        match event {
            TftpEvent::Data => {
                // Only fresh, non-empty DATA is written; a retransmitted or
                // empty block is acknowledged but not duplicated into the body.
                if self.rbytes > 4 && next_blocknum(self.block) == block_of(&self.rpacket) {
                    sink.write(&self.rpacket[4..self.rbytes])?;
                }
            }
            TftpEvent::Error => {
                let (code, msg) = decode_error(&self.rpacket[..self.rbytes]);
                self.error = TftpError::from_code(code);
                infof(self.verbose, &format!("got TFTP error code {code}: {msg}"));
            }
            TftpEvent::Oack => {
                // Copy the OACK body out first to avoid borrowing `self.rpacket`
                // while taking `&mut self` for the option parser.
                let body = self.rpacket[2..self.rbytes].to_vec();
                self.parse_option_ack(&body, errbuf)?;
            }
            TftpEvent::Ack => {}
            _ => {
                infof(self.verbose, "Received unexpected TFTP packet");
            }
        }
        Ok(event)
    }

    /// Advance the state machine by one event, returning any datagram to send
    /// and whether the transfer has finished. This is the dispatch hub
    /// corresponding to `tftp_state_machine` in the C source.
    ///
    /// # Errors
    ///
    /// Propagates protocol errors raised by the per-state handlers.
    pub fn step(
        &mut self,
        event: TftpEvent,
        source: &mut dyn TftpDataSource,
        errbuf: &mut Option<String>,
    ) -> Result<StepOutcome> {
        match self.state {
            TftpState::Start => self.send_first(event, source, errbuf),
            TftpState::Rx => self.rx(event, errbuf),
            TftpState::Tx => self.tx(event, source, errbuf),
            TftpState::Fin => Ok(StepOutcome {
                send: None,
                done: true,
            }),
        }
    }

    /// Map the recorded terminal error to a [`CurlError`] result.
    ///
    /// # Errors
    ///
    /// Returns the translated [`CurlError`] when the transfer ended in error.
    pub fn translate(&self) -> Result<()> {
        self.error.translate()
    }

    /// Enter the `TX` (upload) state, recompute timeouts, and dispatch the
    /// triggering event to the transmit handler.
    fn connect_for_tx(
        &mut self,
        event: TftpEvent,
        source: &mut dyn TftpDataSource,
        errbuf: &mut Option<String>,
    ) -> Result<StepOutcome> {
        infof(self.verbose, "TFTP: connected for transmit");
        self.state = TftpState::Tx;
        self.refresh_timeouts(errbuf)?;
        self.tx(event, source, errbuf)
    }

    /// Enter the `RX` (download) state, recompute timeouts, and dispatch the
    /// triggering event to the receive handler.
    fn connect_for_rx(
        &mut self,
        event: TftpEvent,
        errbuf: &mut Option<String>,
    ) -> Result<StepOutcome> {
        infof(self.verbose, "TFTP: connected for receive");
        self.state = TftpState::Rx;
        self.refresh_timeouts(errbuf)?;
        self.rx(event, errbuf)
    }

    /// The `START`-state handler (`tftp_send_first`): send the initial
    /// `RRQ`/`WRQ`, and on the first server response transition into `RX`/`TX`.
    fn send_first(
        &mut self,
        event: TftpEvent,
        source: &mut dyn TftpDataSource,
        errbuf: &mut Option<String>,
    ) -> Result<StepOutcome> {
        match event {
            TftpEvent::Init | TftpEvent::Timeout => {
                self.retries += 1;
                if self.retries > self.retry_max {
                    self.error = TftpError::Noresponse;
                    self.state = TftpState::Fin;
                    return Ok(StepOutcome {
                        send: None,
                        done: true,
                    });
                }

                if self.filename.is_empty() {
                    failf(errbuf, "TFTP: Missing filename");
                    return Err(CurlError::TftpIllegal);
                }

                let mode = self.mode.as_str();
                // The base request (opcode + filename\0 + mode\0) must fit in a
                // single block; the C code applies the same guard.
                if self.filename.len() + mode.len() + 4 > self.blksize {
                    failf(errbuf, "TFTP file name too long");
                    return Err(CurlError::TftpIllegal);
                }

                let opcode = if self.upload {
                    TFTP_OPCODE_WRQ
                } else {
                    TFTP_OPCODE_RRQ
                };

                let mut options: Vec<(String, String)> = Vec::new();
                if !self.no_options {
                    // tsize: the upload size when known, else 0 (the server fills
                    // it in for a download).
                    let tsize = if self.upload && self.infilesize != -1 {
                        self.infilesize
                    } else {
                        0
                    };
                    options.push((TFTP_OPTION_TSIZE.to_string(), tsize.to_string()));
                    options.push((
                        TFTP_OPTION_BLKSIZE.to_string(),
                        self.requested_blksize.to_string(),
                    ));
                    options.push((
                        TFTP_OPTION_INTERVAL.to_string(),
                        self.retry_time.to_string(),
                    ));
                }

                let packet = encode_request(opcode, &self.filename, mode, &options);
                if packet.len() > self.blksize {
                    failf(errbuf, "TFTP buffer too small for options");
                    return Err(CurlError::TftpIllegal);
                }
                self.spacket = packet.clone();
                Ok(StepOutcome {
                    send: Some(packet),
                    done: false,
                })
            }
            TftpEvent::Oack => {
                if self.upload {
                    self.connect_for_tx(event, source, errbuf)
                } else {
                    self.connect_for_rx(event, errbuf)
                }
            }
            TftpEvent::Ack => self.connect_for_tx(event, source, errbuf),
            TftpEvent::Data => self.connect_for_rx(event, errbuf),
            TftpEvent::Error => {
                self.state = TftpState::Fin;
                Ok(StepOutcome {
                    send: None,
                    done: true,
                })
            }
            _ => {
                failf(errbuf, "TFTP: internal error in START state");
                Err(CurlError::TftpIllegal)
            }
        }
    }

    /// The `RX`-state handler (`tftp_rx`): acknowledge received `DATA`, resend
    /// the previous `ACK` on timeout, and end on a short final block.
    fn rx(&mut self, event: TftpEvent, errbuf: &mut Option<String>) -> Result<StepOutcome> {
        match event {
            TftpEvent::Data => {
                let rblock = block_of(&self.rpacket);
                if next_blocknum(self.block) == rblock {
                    // Expected next block.
                    self.retries = 0;
                } else if self.block == rblock {
                    // The last block again — re-acknowledge it.
                    infof(
                        self.verbose,
                        &format!("Received last DATA packet block {rblock} again"),
                    );
                } else {
                    // Out of order: ignore and keep waiting for the right block.
                    infof(
                        self.verbose,
                        &format!(
                            "Received unexpected DATA packet block {rblock}, expecting block {}",
                            next_blocknum(self.block)
                        ),
                    );
                    return Ok(StepOutcome {
                        send: None,
                        done: false,
                    });
                }

                self.block = rblock;
                let ack = encode_ack(self.block);
                self.spacket = ack.clone();
                // A short datagram (less than a full block plus header) is the
                // last one.
                self.state = if self.rbytes < self.blksize + 4 {
                    TftpState::Fin
                } else {
                    TftpState::Rx
                };
                let done = self.state == TftpState::Fin;
                Ok(StepOutcome {
                    send: Some(ack),
                    done,
                })
            }
            TftpEvent::Oack => {
                // OACK before any DATA: acknowledge block 0 to start the flow.
                self.block = 0;
                self.retries = 0;
                let ack = encode_ack(self.block);
                self.spacket = ack.clone();
                self.state = TftpState::Rx;
                Ok(StepOutcome {
                    send: Some(ack),
                    done: false,
                })
            }
            TftpEvent::Timeout => {
                self.retries += 1;
                infof(
                    self.verbose,
                    &format!(
                        "Timeout waiting for block {} ACK; retry {}",
                        next_blocknum(self.block),
                        self.retries
                    ),
                );
                if self.retries > self.retry_max {
                    self.error = TftpError::Timeout;
                    self.state = TftpState::Fin;
                    Ok(StepOutcome {
                        send: None,
                        done: true,
                    })
                } else {
                    Ok(StepOutcome {
                        send: Some(self.spacket.clone()),
                        done: false,
                    })
                }
            }
            TftpEvent::Error => {
                self.state = TftpState::Fin;
                Ok(StepOutcome {
                    send: Some(encode_error_reply(self.block)),
                    done: true,
                })
            }
            _ => {
                failf(errbuf, "TFTP: illegal event in RX state");
                Err(CurlError::TftpIllegal)
            }
        }
    }

    /// The `TX`-state handler (`tftp_tx`): on each `ACK` advance the block and
    /// send the next `DATA`, resend on a mismatched `ACK` or timeout, and end
    /// after the final short block is acknowledged.
    fn tx(
        &mut self,
        event: TftpEvent,
        source: &mut dyn TftpDataSource,
        errbuf: &mut Option<String>,
    ) -> Result<StepOutcome> {
        match event {
            TftpEvent::Ack | TftpEvent::Oack => {
                if event == TftpEvent::Ack {
                    let rblock = block_of(&self.rpacket);
                    // Accept the ACK for the block we just sent. The
                    // `block == 0 && rblock == 65535` case tolerates the
                    // tftpd-hpa wraparound bug for the very first ACK.
                    if rblock != self.block && !(self.block == 0 && rblock == 0xffff) {
                        infof(
                            self.verbose,
                            &format!("Received ACK for block {rblock}, expecting {}", self.block),
                        );
                        self.retries += 1;
                        if self.retries > self.retry_max {
                            failf(
                                errbuf,
                                &format!("tftp_tx: giving up waiting for block {} ACK", self.block),
                            );
                            return Err(CurlError::SendError);
                        }
                        // Resend the current DATA packet.
                        return Ok(StepOutcome {
                            send: Some(self.spacket.clone()),
                            done: false,
                        });
                    }
                    self.block = self.block.wrapping_add(1);
                } else {
                    // First DATA block after an OACK is block 1.
                    self.block = 1;
                }

                self.retries = 0;

                // After the first block, a previous short send signals EOF.
                if self.block > 1 && self.sbytes < self.blksize {
                    self.state = TftpState::Fin;
                    return Ok(StepOutcome {
                        send: None,
                        done: true,
                    });
                }

                // Fill one block from the upload source.
                let mut payload = vec![0u8; self.blksize];
                let mut total = 0usize;
                loop {
                    let got = source.read(&mut payload[total..])?;
                    total += got;
                    if total >= self.blksize || got == 0 {
                        break;
                    }
                }
                payload.truncate(total);
                self.sbytes = total;

                let packet = encode_data(self.block, &payload);
                self.spacket = packet.clone();
                Ok(StepOutcome {
                    send: Some(packet),
                    done: false,
                })
            }
            TftpEvent::Timeout => {
                self.retries += 1;
                infof(
                    self.verbose,
                    &format!(
                        "Timeout waiting for block {} ACK; retry {}",
                        self.block, self.retries
                    ),
                );
                if self.retries > self.retry_max {
                    self.error = TftpError::Timeout;
                    self.state = TftpState::Fin;
                    Ok(StepOutcome {
                        send: None,
                        done: true,
                    })
                } else {
                    Ok(StepOutcome {
                        send: Some(self.spacket.clone()),
                        done: false,
                    })
                }
            }
            TftpEvent::Error => {
                self.state = TftpState::Fin;
                Ok(StepOutcome {
                    send: Some(encode_error_reply(self.block)),
                    done: true,
                })
            }
            _ => {
                failf(
                    errbuf,
                    &format!("tftp_tx: internal error, event {}", event as i32),
                );
                Ok(StepOutcome {
                    send: None,
                    done: false,
                })
            }
        }
    }
}

// =============================================================================
// Datagram transport abstraction
// =============================================================================

/// The datagram transport the TFTP engine drives.
///
/// Abstracting the socket behind this trait keeps [`run_transfer`] independent
/// of Tokio so the full lock-step protocol can be exercised against an
/// in-memory mock. [`UdpTftpIo`] is the production implementation.
pub trait TftpIo: Send {
    /// Send one datagram to the server (or the pinned transfer-ID peer).
    fn send_packet<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<()>>;

    /// Wait up to `timeout` for the next datagram, copying it into `buf`.
    ///
    /// Resolves to `Ok(Some(n))` for a datagram of `n` bytes, `Ok(None)` if the
    /// timeout elapsed first (which the engine treats as a retransmission
    /// trigger), or `Err` on a transport error or transfer-ID violation.
    fn recv_packet<'a>(
        &'a mut self,
        buf: &'a mut [u8],
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Option<usize>>>;
}

/// Production [`TftpIo`] over an unconnected [`tokio::net::UdpSocket`].
///
/// The socket is bound to an ephemeral local port and is *not* `connect`ed, so
/// it can send to the server's well-known port for the initial request and then
/// receive the reply from — and pin onto — the server's freshly chosen transfer
/// ID port.
pub struct UdpTftpIo {
    socket: UdpSocket,
    server: SocketAddr,
    peer: Option<SocketAddr>,
}

impl UdpTftpIo {
    /// Bind a local ephemeral UDP socket suitable for talking to `server`.
    ///
    /// The bind address family matches the server's so IPv4 and IPv6 targets
    /// both work. The socket is intentionally left unconnected (see the struct
    /// docs).
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::CouldntConnect`] if the socket cannot be bound.
    pub async fn connect(server: SocketAddr) -> Result<Self> {
        let bind = if server.is_ipv6() {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|_| CurlError::CouldntConnect)?;
        Ok(UdpTftpIo {
            socket,
            server,
            peer: None,
        })
    }

    /// The currently pinned peer (the server's transfer-ID port), once known.
    #[must_use]
    pub fn peer(&self) -> Option<SocketAddr> {
        self.peer
    }
}

impl TftpIo for UdpTftpIo {
    fn send_packet<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Once the server's TID is known, address replies to it; before
            // that, the initial request goes to the well-known server port.
            let dst = self.peer.unwrap_or(self.server);
            let sent = self
                .socket
                .send_to(buf, dst)
                .await
                .map_err(|_| CurlError::SendError)?;
            if sent != buf.len() {
                return Err(CurlError::SendError);
            }
            Ok(())
        })
    }

    fn recv_packet<'a>(
        &'a mut self,
        buf: &'a mut [u8],
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Option<usize>>> {
        Box::pin(async move {
            match tokio::time::timeout(timeout, self.socket.recv_from(buf)).await {
                // Timer elapsed: signal a retransmission opportunity.
                Err(_elapsed) => Ok(None),
                Ok(Err(_io)) => Err(CurlError::RecvError),
                Ok(Ok((n, from))) => {
                    check_peer(&mut self.peer, from)?;
                    Ok(Some(n))
                }
            }
        })
    }
}

/// The destination for downloaded body bytes (the engine's `DATA` payload
/// writer). In production this bridges to curl's write callback; in tests it is
/// a simple buffer.
pub trait TftpDataSink: Send {
    /// Append `buf` to the download body.
    ///
    /// # Errors
    ///
    /// Returns a [`CurlError`] if the consumer rejects the data (e.g. a write
    /// callback abort).
    fn write(&mut self, buf: &[u8]) -> Result<()>;
}

/// The source of upload body bytes (the engine's `DATA` payload reader). In
/// production this bridges to curl's read callback; in tests it is a buffer.
pub trait TftpDataSource: Send {
    /// Read up to `buf.len()` bytes into `buf`, returning the number read (`0`
    /// at end of input).
    ///
    /// # Errors
    ///
    /// Returns a [`CurlError`] if the producer fails (e.g. a read callback
    /// abort).
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
}

// =============================================================================
// Drive loop
// =============================================================================

/// Drive a TFTP transfer to completion over the supplied transport.
///
/// This is the async counterpart of `tftp.c`'s `tftp_multi_statemach` loop. It
/// constructs a [`TftpConn`], sends the initial request, then alternately waits
/// for a datagram (up to the per-block retransmission interval) and feeds the
/// resulting event — a received packet or a [`TftpEvent::Timeout`] — to the
/// state machine, transmitting whatever the step yields. The loop ends when the
/// machine reaches [`TftpState::Fin`] or the overall deadline elapses, and the
/// recorded protocol error is translated into the returned [`Result`].
///
/// # Errors
///
/// Returns a [`CurlError`] for any protocol failure, transport error, or
/// timeout, exactly as curl's TFTP handler would.
pub async fn run_transfer(
    req: TftpRequest,
    io: &mut dyn TftpIo,
    sink: &mut dyn TftpDataSink,
    source: &mut dyn TftpDataSource,
    timeleft_ms: i64,
    verbose: bool,
    errbuf: &mut Option<String>,
) -> Result<()> {
    let mut conn = TftpConn::new(req);
    conn.verbose = verbose;
    conn.set_deadline_ms(timeleft_ms);
    // Initial timeout parameters (the C `tftp_connect` calls set_timeouts once).
    conn.refresh_timeouts(errbuf)?;

    // INIT: send the first RRQ/WRQ.
    let first = conn.step(TftpEvent::Init, source, errbuf)?;
    if let Some(packet) = first.send {
        io.send_packet(&packet).await?;
    }
    if conn.state() == TftpState::Fin {
        return conn.translate();
    }

    let mut recv_buf = vec![0u8; conn.recv_buf_size()];
    loop {
        // Honor the overall transfer deadline before each wait.
        let timeleft = conn.timeleft_ms();
        if timeleft < 0 {
            conn.error = TftpError::Timeout;
            failf(errbuf, "TFTP response timeout");
            return Err(CurlError::OperationTimedout);
        }

        // The per-block retransmission interval (seconds → Duration), at least
        // one millisecond so the timer always makes progress.
        let interval = ms_to_duration(i64::from(conn.retry_time).saturating_mul(1000).max(1));

        let event = match io.recv_packet(&mut recv_buf, interval).await? {
            Some(n) => {
                conn.set_received(&recv_buf[..n]);
                conn.on_receive(sink, errbuf)?
            }
            None => TftpEvent::Timeout,
        };

        let outcome = conn.step(event, source, errbuf)?;
        if let Some(packet) = outcome.send {
            io.send_packet(&packet).await?;
        }
        if conn.state() == TftpState::Fin {
            break;
        }
    }

    conn.translate()
}

// =============================================================================
// Protocol handler
// =============================================================================

/// The `tftp://` [`Protocol`] handler.
///
/// It advertises the [`SCHEME_TFTP`] descriptor, requests a UDP transport
/// during connection setup ([`TRNSPRT_UDP`]), and validates the request URL.
/// The lock-step datagram engine itself lives in [`run_transfer`] and the
/// [`TftpConn`] state machine; this handler is the boundary the transfer
/// engine drives.
#[derive(Debug, Clone, Copy, Default)]
pub struct TftpHandler;

impl TftpHandler {
    /// Construct a new TFTP handler.
    #[must_use]
    pub fn new() -> Self {
        TftpHandler
    }
}

impl Protocol for TftpHandler {
    fn scheme(&self) -> &'static Scheme {
        &SCHEME_TFTP
    }

    fn setup_connection<'a>(
        &'a self,
        _data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // TFTP is the one UDP protocol: request a datagram transport rather
            // than the default TCP path. (`tftp_setup_connection` sets
            // `conn->transport = TRNSPRT_UDP`.)
            conn.transport_wanted = TRNSPRT_UDP;
            Ok(())
        })
    }

    fn do_it<'a>(
        &'a self,
        data: &'a mut Easy,
        _conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<ProtocolTransfer>> {
        Box::pin(async move {
            let url = data.url().ok_or(CurlError::UrlMalformat)?.to_string();
            let blksize = data.set.tftp_blksize;
            let no_options = data.set.tftp_no_options;
            let prefer_ascii = data.set.prefer_ascii;
            let infilesize = data.set.filesize;

            // Validate the URL and file name up front (the C handler rejects a
            // missing file name and a malformed URL before any I/O). The
            // resulting request shape is what the transfer engine consumes when
            // it drives `run_transfer`. Upload-versus-download is selected by
            // the engine wiring; the descriptor below reports the download
            // direction, which the engine refines from the easy-handle state.
            let _request =
                TftpRequest::from_url(&url, blksize, no_options, prefer_ascii, infilesize, false)?;

            Ok(ProtocolTransfer::new(TransferDirection::Download))
        })
    }
}

// =============================================================================
// Client bridge: adapt the engine's data traits to curl's read/write callbacks
// =============================================================================

/// Bridges the engine's [`TftpDataSink`] to the client write stack on the `RRQ`
/// (download) path.
///
/// Each `DATA` block is delivered as a body write through a [`ClientWriter`],
/// which honors `CURLOPT_HEADER` (a no-op for TFTP — the protocol carries no
/// headers) and content decoding, exactly as `tftp.c` delivers received data
/// via `Curl_client_write(data, CLIENTWRITE_BODY, …)`.
struct ClientTftpSink<'a> {
    writer: ClientWriter,
    sink: &'a mut dyn WriteCallbacks,
}

impl TftpDataSink for ClientTftpSink<'_> {
    fn write(&mut self, buf: &[u8]) -> Result<()> {
        self.writer.write(ClientWriteType::BODY, buf, self.sink)
    }
}

impl ClientTftpSink<'_> {
    /// Flush a zero-length end-of-stream so the body writer finalizes any
    /// content decoder, mirroring the final client write curl performs at the
    /// end of a transfer. `self.writer` and `self.sink` are disjoint fields, so
    /// borrowing both here is sound.
    fn finish(&mut self) -> Result<()> {
        self.writer.write(
            ClientWriteType::BODY.union(ClientWriteType::EOS),
            &[],
            self.sink,
        )
    }
}

/// Bridges the engine's [`TftpDataSource`] to the client read callback on the
/// `WRQ` (upload) path.
///
/// Each block is filled from an [`UploadReader`] over the client read callback —
/// the analog of `tftp.c` pulling the next `DATA` block from the read callback.
/// TFTP's lock-step engine has no notion of pausing, so a paused or exhausted
/// source both report end-of-input (`Ok(0)`), which the engine treats as the
/// final (possibly short) block.
struct ClientTftpSource<'a> {
    reader: UploadReader,
    source: &'a mut dyn ReadCallback,
}

impl TftpDataSource for ClientTftpSource<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.reader.read(buf, self.source)? {
            ReadStep::Data(n) => Ok(n),
            ReadStep::Eof | ReadStep::Paused => Ok(0),
        }
    }
}

/// Drive a `tftp://` transfer end-to-end over UDP — [F5-CRIT-7].
///
/// TFTP is curl's one datagram protocol, so — unlike every other network
/// scheme — it does *not* use the TCP connection-filter seam
/// ([`connect_network_scheme`](super::connect_network_scheme)). It resolves the
/// server endpoint, binds an ephemeral UDP socket via [`UdpTftpIo::connect`],
/// and drives the lock-step [`run_transfer`] state machine directly: the async
/// analog of `tftp.c`'s `tftp_connect` + `tftp_multi_statemach`. Before this
/// driver existed the recognized `tftp` scheme fell through to
/// `CURLE_UNSUPPORTED_PROTOCOL` in [`perform_transfer`](super::perform_transfer),
/// so no datagram was ever sent.
///
/// Downloads (`RRQ`) stream each `DATA` block to the client write stack;
/// uploads (`WRQ`, selected by `CURLOPT_UPLOAD`) pull each block from the client
/// read callback. Both adapters are always constructed; the unused side of a
/// given direction is simply never exercised by the engine.
///
/// # Errors
///
/// A malformed URL or empty file name ([`CurlError::UrlMalformat`] /
/// [`CurlError::TftpIllegal`]), a resolve failure
/// ([`CurlError::CouldntResolveHost`]), a socket bind failure
/// ([`CurlError::CouldntConnect`]), or any transport/protocol error surfaced by
/// [`run_transfer`].
pub(crate) async fn perform_tftp(
    data: &mut Easy,
    scheme: &'static Scheme,
    sink: &mut dyn WriteCallbacks,
    source: &mut dyn ReadCallback,
) -> Result<()> {
    use crate::dns::{self, DnsCache, IpVersion, ResolveParams};

    let verbose = data.set.verbose;
    // `-T`/`CURLOPT_UPLOAD` selects the `WRQ` path (setopt maps both UPLOAD and
    // PUT to `HttpReq::Put`), matching how the SMB and mail drivers detect an
    // upload.
    let upload = data.set.method == HttpReq::Put;

    // (1) Resolve the request URL into host + port. The scheme's well-known
    //     port (69) is the default when the URL omits one.
    let url_str = data.url().ok_or(CurlError::UrlMalformat)?.to_string();
    let mut url = CurlUrl::new();
    url.set(
        CurlUPart::Url,
        Some(&url_str),
        CURLU_GUESS_SCHEME | CURLU_DEFAULT_PORT,
    )
    .map_err(|_| CurlError::UrlMalformat)?;
    let host_bracketed = url.get(CurlUPart::Host, CURLU_URLDECODE).unwrap_or_default();
    if host_bracketed.is_empty() {
        return Err(CurlError::UrlMalformat);
    }
    let host = host_bracketed
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(&host_bracketed)
        .to_string();
    let port = url
        .get(CurlUPart::Port, 0)
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(scheme.default_port);

    // (2) Resolve the endpoint with the system resolver, honoring `-4`/`-6`.
    //     The first resolved address is the initial RRQ/WRQ destination; the
    //     server's reply pins the transfer-ID peer inside `UdpTftpIo`.
    let ipver = IpVersion::from_raw(i64::from(data.set.ipver));
    let server: SocketAddr = {
        let mut cache = DnsCache::new();
        let mut errbuf: Option<String> = None;
        let mut params = ResolveParams::new(&host, port);
        params.ip_version = ipver;
        params.verbose = verbose;
        let entry = dns::resolve(&mut cache, &params, &mut errbuf).await?;
        entry
            .addrs
            .addrs
            .first()
            .copied()
            .ok_or(CurlError::CouldntResolveHost)?
    };

    // (3) Build the immutable request from the URL + options. `from_url` strips
    //     the leading `/` and any `;mode=` suffix, URL-decodes the file name,
    //     and rejects an empty name. (`do_it` validated the download shape; the
    //     real upload flag is supplied here.)
    let blksize = data.set.tftp_blksize;
    let no_options = data.set.tftp_no_options;
    let prefer_ascii = data.set.prefer_ascii;
    let infilesize = data.set.filesize;
    let req =
        TftpRequest::from_url(&url_str, blksize, no_options, prefer_ascii, infilesize, upload)?;

    // (4) Bind the ephemeral UDP socket for the server's address family.
    let mut io = UdpTftpIo::connect(server).await?;

    // (5) Overall transfer deadline. curl's `tftp_set_timeouts` derives both the
    //     retransmission budget and the drop-dead time from `Curl_timeleft_ms`:
    //     a set `CURLOPT_TIMEOUT` bounds the whole transfer, while *no* timeout
    //     uses the hard-coded 15-second budget (`retry_max` 3, `retry_time` 5 s
    //     — the wire-visible retransmission cadence). `run_transfer` folds the
    //     overall deadline and the retry budget into one `timeleft_ms` (a `0`
    //     would set a deadline of "now" and time out immediately), so mirror the
    //     C logic exactly: the user timeout when set (`data.set.timeout` is in
    //     ms), else 15 000 ms — which yields the same `retry_max` 3 / `retry_time`
    //     5 s and a sane upper bound.
    let timeleft_ms = if data.set.timeout > 0 {
        data.set.timeout
    } else {
        15_000
    };

    // (6) Build the client-bridging sink/source and drive the state machine.
    let total_len = if infilesize >= 0 {
        Some(infilesize as u64)
    } else {
        None
    };
    let mut tftp_sink = ClientTftpSink {
        writer: ClientWriter::new(),
        sink,
    };
    let mut tftp_source = ClientTftpSource {
        reader: UploadReader::new(total_len, false),
        source,
    };
    let mut errbuf: Option<String> = None;

    let result = run_transfer(
        req,
        &mut io,
        &mut tftp_sink,
        &mut tftp_source,
        timeleft_ms,
        verbose,
        &mut errbuf,
    )
    .await;

    // On a successful download, flush the end-of-stream marker so the body
    // writer finalizes any content decoder (the analog of curl's final client
    // write). The upload path writes nothing to the sink.
    if result.is_ok() && !upload {
        tftp_sink.finish()?;
    }

    // Surface any engine failure message in verbose mode. (The bridge to the
    // C `CURLOPT_ERRORBUFFER` slot belongs to the FFI layer.)
    if result.is_err() {
        if let Some(msg) = &errbuf {
            infof(verbose, msg);
        }
    }

    result
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    // ---- Test doubles --------------------------------------------------------

    /// A scripted [`TftpIo`] that returns queued datagrams (or simulated
    /// timeouts) and records everything sent.
    struct MockIo {
        responses: VecDeque<Option<Vec<u8>>>,
        sent: Vec<Vec<u8>>,
    }

    impl MockIo {
        fn new(responses: Vec<Option<Vec<u8>>>) -> Self {
            MockIo {
                responses: responses.into_iter().collect(),
                sent: Vec::new(),
            }
        }
    }

    impl TftpIo for MockIo {
        fn send_packet<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                self.sent.push(buf.to_vec());
                Ok(())
            })
        }

        fn recv_packet<'a>(
            &'a mut self,
            buf: &'a mut [u8],
            _timeout: Duration,
        ) -> BoxFuture<'a, Result<Option<usize>>> {
            Box::pin(async move {
                // An explicit `None` entry and an exhausted queue both model a
                // receive timeout.
                match self.responses.pop_front().flatten() {
                    Some(pkt) => {
                        let n = pkt.len().min(buf.len());
                        buf[..n].copy_from_slice(&pkt[..n]);
                        Ok(Some(n))
                    }
                    None => Ok(None),
                }
            })
        }
    }

    #[derive(Default)]
    struct VecSink {
        data: Vec<u8>,
    }
    impl TftpDataSink for VecSink {
        fn write(&mut self, buf: &[u8]) -> Result<()> {
            self.data.extend_from_slice(buf);
            Ok(())
        }
    }

    struct VecSource {
        data: Vec<u8>,
        pos: usize,
    }
    impl VecSource {
        fn new(data: Vec<u8>) -> Self {
            VecSource { data, pos: 0 }
        }
    }
    impl TftpDataSource for VecSource {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            let remaining = self.data.len().saturating_sub(self.pos);
            let n = remaining.min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    struct EmptySource;
    impl TftpDataSource for EmptySource {
        fn read(&mut self, _buf: &mut [u8]) -> Result<usize> {
            Ok(0)
        }
    }

    #[derive(Default)]
    struct NullSink;
    impl TftpDataSink for NullSink {
        fn write(&mut self, _buf: &[u8]) -> Result<()> {
            Ok(())
        }
    }

    // ---- Packet builders for tests ------------------------------------------

    fn make_oack(opts: &[(&str, &str)]) -> Vec<u8> {
        let mut v = TFTP_OPCODE_OACK.to_be_bytes().to_vec();
        for (k, value) in opts {
            v.extend_from_slice(k.as_bytes());
            v.push(0);
            v.extend_from_slice(value.as_bytes());
            v.push(0);
        }
        v
    }

    fn make_error(code: u16, msg: &str) -> Vec<u8> {
        let mut v = TFTP_OPCODE_ERROR.to_be_bytes().to_vec();
        v.extend_from_slice(&code.to_be_bytes());
        v.extend_from_slice(msg.as_bytes());
        v.push(0);
        v
    }

    fn dl_conn(requested: u16) -> TftpConn {
        TftpConn::new(TftpRequest {
            filename: "f".to_string(),
            mode: TftpMode::Octet,
            upload: false,
            requested_blksize: requested,
            no_options: false,
            infilesize: -1,
        })
    }

    // ---- Codec & helpers -----------------------------------------------------

    #[test]
    fn next_blocknum_wraps_at_16_bits() {
        assert_eq!(next_blocknum(0), 1);
        assert_eq!(next_blocknum(41), 42);
        assert_eq!(next_blocknum(0xffff), 0);
    }

    #[test]
    fn opcode_and_block_decoders_are_big_endian_and_guarded() {
        let data = encode_data(0x0102, &[9, 9]);
        assert_eq!(opcode_of(&data), TFTP_OPCODE_DATA);
        assert_eq!(block_of(&data), 0x0102);
        // Short packets never panic.
        assert_eq!(opcode_of(&[]), 0);
        assert_eq!(opcode_of(&[0x00]), 0);
        assert_eq!(block_of(&[0, 3, 1]), 0);
    }

    #[test]
    fn encode_request_lays_out_rrq_with_options() {
        let opts = vec![
            ("blksize".to_string(), "512".to_string()),
            ("tsize".to_string(), "0".to_string()),
        ];
        let pkt = encode_request(TFTP_OPCODE_RRQ, "myfile", "octet", &opts);
        let expected = b"\x00\x01myfile\x00octet\x00blksize\x00512\x00tsize\x000\x00";
        assert_eq!(pkt, expected);
    }

    #[test]
    fn encode_request_lays_out_wrq_without_options() {
        let pkt = encode_request(TFTP_OPCODE_WRQ, "up", "netascii", &[]);
        assert_eq!(pkt, b"\x00\x02up\x00netascii\x00");
    }

    #[test]
    fn encode_data_ack_error_layouts() {
        assert_eq!(encode_data(7, &[0xaa, 0xbb]), vec![0, 3, 0, 7, 0xaa, 0xbb]);
        assert_eq!(encode_ack(0x1234), vec![0, 4, 0x12, 0x34]);
        // The RX/TX error reply carries the block number in the code slot and
        // no message.
        assert_eq!(encode_error_reply(5), vec![0, 5, 0, 5]);
    }

    #[test]
    fn decode_error_extracts_code_and_message() {
        let pkt = make_error(1, "File not found");
        let (code, msg) = decode_error(&pkt);
        assert_eq!(code, 1);
        assert_eq!(msg, "File not found");
        // No message body still decodes.
        let (code, msg) = decode_error(&[0, 5, 0, 3]);
        assert_eq!(code, 3);
        assert_eq!(msg, "");
    }

    #[test]
    fn parse_oack_options_wellformed_and_malformed() {
        let ok = parse_oack_options(b"blksize\x00512\x00timeout\x005\x00").unwrap();
        assert_eq!(
            ok,
            vec![
                ("blksize".to_string(), "512".to_string()),
                ("timeout".to_string(), "5".to_string()),
            ]
        );
        // Empty body → no options.
        assert_eq!(parse_oack_options(b""), Some(vec![]));
        // Option with no terminating NUL for its value → malformed.
        assert_eq!(parse_oack_options(b"blksize\x00512"), None);
        // Dangling option name without a value → malformed.
        assert_eq!(parse_oack_options(b"blksize"), None);
    }

    #[test]
    fn checkprefix_is_case_insensitive() {
        assert!(checkprefix("blksize", "BLKSIZE"));
        assert!(checkprefix("tsize", "tsize"));
        assert!(checkprefix("timeout", "Timeout"));
        assert!(!checkprefix("blksize", "blk"));
        assert!(!checkprefix("tsize", "size"));
    }

    #[test]
    fn parse_mode_handles_suffix_and_prefer_ascii() {
        assert_eq!(
            parse_mode("/file;mode=netascii", false),
            (TftpMode::Netascii, "/file".to_string())
        );
        assert_eq!(
            parse_mode("/file;mode=octet", true),
            (TftpMode::Octet, "/file".to_string())
        );
        assert_eq!(
            parse_mode("/file", false),
            (TftpMode::Octet, "/file".to_string())
        );
        assert_eq!(
            parse_mode("/file", true),
            (TftpMode::Netascii, "/file".to_string())
        );
    }

    #[test]
    fn compute_timeouts_clamps_and_rejects_elapsed() {
        // Large budget → retry_max clamped to 50.
        assert_eq!(compute_timeouts(1_000_000).unwrap(), (50, 20));
        // Tiny budget → retry_max floored to 3, retry_time floored to 1.
        assert_eq!(compute_timeouts(1000).unwrap(), (3, 1));
        // No deadline → C default 15s budget.
        assert_eq!(compute_timeouts(0).unwrap(), (3, 5));
        // Already elapsed → timed out.
        assert!(matches!(
            compute_timeouts(-1),
            Err(CurlError::OperationTimedout)
        ));
    }

    #[test]
    fn event_from_opcode_maps_all() {
        assert_eq!(TftpEvent::from_opcode(1), TftpEvent::Rrq);
        assert_eq!(TftpEvent::from_opcode(2), TftpEvent::Wrq);
        assert_eq!(TftpEvent::from_opcode(3), TftpEvent::Data);
        assert_eq!(TftpEvent::from_opcode(4), TftpEvent::Ack);
        assert_eq!(TftpEvent::from_opcode(5), TftpEvent::Error);
        assert_eq!(TftpEvent::from_opcode(6), TftpEvent::Oack);
        assert_eq!(TftpEvent::from_opcode(99), TftpEvent::None);
    }

    #[test]
    fn error_from_code_and_translate_cover_all() {
        // Wire codes → CURLcode mapping (tftp_translate_code).
        assert_eq!(TftpError::from_code(0), TftpError::Undef);
        assert!(matches!(
            TftpError::from_code(0).translate(),
            Err(CurlError::TftpIllegal)
        ));
        assert!(matches!(
            TftpError::Notfound.translate(),
            Err(CurlError::TftpNotfound)
        ));
        assert!(matches!(
            TftpError::Perm.translate(),
            Err(CurlError::TftpPerm)
        ));
        assert!(matches!(
            TftpError::Diskfull.translate(),
            Err(CurlError::RemoteDiskFull)
        ));
        assert!(matches!(
            TftpError::Illegal.translate(),
            Err(CurlError::TftpIllegal)
        ));
        assert!(matches!(
            TftpError::Unknownid.translate(),
            Err(CurlError::TftpUnknownid)
        ));
        assert!(matches!(
            TftpError::Exists.translate(),
            Err(CurlError::RemoteFileExists)
        ));
        assert!(matches!(
            TftpError::Nosuchuser.translate(),
            Err(CurlError::TftpNosuchuser)
        ));
        assert!(matches!(
            TftpError::Timeout.translate(),
            Err(CurlError::OperationTimedout)
        ));
        assert!(matches!(
            TftpError::Noresponse.translate(),
            Err(CurlError::CouldntConnect)
        ));
        assert!(matches!(
            TftpError::Other(42).translate(),
            Err(CurlError::AbortedByCallback)
        ));
        assert!(TftpError::None.translate().is_ok());
        // Out-of-range wire code is preserved.
        assert_eq!(TftpError::from_code(250), TftpError::Other(250));
    }

    // ---- Request parsing -----------------------------------------------------

    #[test]
    fn request_from_url_basic() {
        let r = TftpRequest::from_url("tftp://host/myfile", 0, false, false, -1, false).unwrap();
        assert_eq!(r.filename, "myfile");
        assert_eq!(r.mode, TftpMode::Octet);
        assert!(!r.upload);
    }

    #[test]
    fn request_from_url_netascii_suffix() {
        let r = TftpRequest::from_url(
            "tftp://host/myfile;mode=netascii",
            0,
            false,
            false,
            -1,
            false,
        )
        .unwrap();
        assert_eq!(r.filename, "myfile");
        assert_eq!(r.mode, TftpMode::Netascii);
    }

    #[test]
    fn request_from_url_missing_filename_is_illegal() {
        let r = TftpRequest::from_url("tftp://host/", 0, false, false, -1, false);
        assert!(matches!(r, Err(CurlError::TftpIllegal)));
    }

    // ---- Option negotiation --------------------------------------------------

    #[test]
    fn blksize_negotiation_via_oack() {
        let mut eb = None;
        // OACK with blksize within range → accepted.
        let mut c = dl_conn(1024);
        c.parse_option_ack(b"blksize\x00512\x00", &mut eb).unwrap();
        assert_eq!(c.blksize(), 512);

        // A subsequent OACK lacking blksize falls back to the 512 default and
        // records the download size from tsize.
        c.parse_option_ack(b"tsize\x001000\x00", &mut eb).unwrap();
        assert_eq!(c.blksize(), 512);
        assert_eq!(c.download_size(), Some(1000));

        // blksize larger than requested → rejected.
        assert!(matches!(
            dl_conn(512).parse_option_ack(b"blksize\x001024\x00", &mut eb),
            Err(CurlError::TftpIllegal)
        ));
        // blksize below the minimum → rejected.
        assert!(matches!(
            dl_conn(512).parse_option_ack(b"blksize\x004\x00", &mut eb),
            Err(CurlError::TftpIllegal)
        ));
        // blksize above the maximum → rejected.
        assert!(matches!(
            dl_conn(512).parse_option_ack(b"blksize\x0070000\x00", &mut eb),
            Err(CurlError::TftpIllegal)
        ));
        // Malformed OACK → rejected.
        assert!(matches!(
            dl_conn(512).parse_option_ack(b"blksize", &mut eb),
            Err(CurlError::TftpIllegal)
        ));
    }

    #[test]
    fn tsize_is_ignored_on_upload() {
        let mut eb = None;
        let mut cu = TftpConn::new(TftpRequest {
            filename: "f".to_string(),
            mode: TftpMode::Octet,
            upload: true,
            requested_blksize: 512,
            no_options: false,
            infilesize: 1000,
        });
        cu.parse_option_ack(b"tsize\x005000\x00", &mut eb).unwrap();
        assert_eq!(cu.download_size(), None);
    }

    // ---- TID pinning ---------------------------------------------------------

    #[test]
    fn check_peer_pins_first_and_rejects_mismatch() {
        let a: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:6000".parse().unwrap();
        let mut peer = None;
        assert!(check_peer(&mut peer, a).is_ok());
        assert_eq!(peer, Some(a));
        // Same peer continues to be accepted.
        assert!(check_peer(&mut peer, a).is_ok());
        // A different peer is rejected.
        assert!(matches!(
            check_peer(&mut peer, b),
            Err(CurlError::RecvError)
        ));
    }

    // ---- End-to-end drive loop ----------------------------------------------

    #[tokio::test]
    async fn download_with_oack_then_short_block_ends() {
        let req = TftpRequest {
            filename: "file".to_string(),
            mode: TftpMode::Octet,
            upload: false,
            requested_blksize: 512,
            no_options: false,
            infilesize: -1,
        };
        let mut io = MockIo::new(vec![
            Some(make_oack(&[("blksize", "512")])),
            Some(encode_data(1, &[b'A'; 512])),
            Some(encode_data(2, &[b'B'; 10])),
        ]);
        let mut sink = VecSink::default();
        let mut src = EmptySource;
        let mut eb = None;

        run_transfer(req, &mut io, &mut sink, &mut src, 60_000, false, &mut eb)
            .await
            .unwrap();

        assert_eq!(sink.data.len(), 522);
        assert!(sink.data[..512].iter().all(|&b| b == b'A'));
        assert!(sink.data[512..].iter().all(|&b| b == b'B'));
        // RRQ, ACK(0), ACK(1), ACK(2).
        assert_eq!(io.sent.len(), 4);
        assert_eq!(opcode_of(&io.sent[0]), TFTP_OPCODE_RRQ);
        assert_eq!(io.sent[1], encode_ack(0));
        assert_eq!(io.sent[2], encode_ack(1));
        assert_eq!(io.sent[3], encode_ack(2));
    }

    #[tokio::test]
    async fn download_without_oack_uses_default_blksize() {
        let req = TftpRequest {
            filename: "file".to_string(),
            mode: TftpMode::Octet,
            upload: false,
            requested_blksize: 512,
            no_options: true,
            infilesize: -1,
        };
        let mut io = MockIo::new(vec![
            Some(encode_data(1, &[b'A'; 512])),
            Some(encode_data(2, &[b'C'; 5])),
        ]);
        let mut sink = VecSink::default();
        let mut src = EmptySource;
        let mut eb = None;

        run_transfer(req, &mut io, &mut sink, &mut src, 60_000, false, &mut eb)
            .await
            .unwrap();

        assert_eq!(sink.data.len(), 517);
        // RRQ, ACK(1), ACK(2).
        assert_eq!(io.sent.len(), 3);
        assert_eq!(opcode_of(&io.sent[0]), TFTP_OPCODE_RRQ);
        assert_eq!(io.sent[1], encode_ack(1));
        assert_eq!(io.sent[2], encode_ack(2));
    }

    #[tokio::test]
    async fn upload_with_short_final_block() {
        let payload: Vec<u8> = (0..1034u32).map(|i| (i % 256) as u8).collect();
        let req = TftpRequest {
            filename: "up".to_string(),
            mode: TftpMode::Octet,
            upload: true,
            requested_blksize: 512,
            no_options: true,
            infilesize: payload.len() as i64,
        };
        let mut io = MockIo::new(vec![
            Some(encode_ack(0)),
            Some(encode_ack(1)),
            Some(encode_ack(2)),
            Some(encode_ack(3)),
        ]);
        let mut sink = NullSink;
        let mut src = VecSource::new(payload.clone());
        let mut eb = None;

        run_transfer(req, &mut io, &mut sink, &mut src, 60_000, false, &mut eb)
            .await
            .unwrap();

        // WRQ + three DATA packets (512, 512, 10).
        assert_eq!(io.sent.len(), 4);
        assert_eq!(opcode_of(&io.sent[0]), TFTP_OPCODE_WRQ);
        let mut uploaded = Vec::new();
        for pkt in &io.sent[1..] {
            assert_eq!(opcode_of(pkt), TFTP_OPCODE_DATA);
            uploaded.extend_from_slice(&pkt[4..]);
        }
        assert_eq!(uploaded, payload);
        assert_eq!(io.sent[3].len(), 4 + 10);
    }

    #[tokio::test]
    async fn upload_exact_multiple_sends_empty_final_block() {
        let payload: Vec<u8> = vec![0x55; 1024];
        let req = TftpRequest {
            filename: "up".to_string(),
            mode: TftpMode::Octet,
            upload: true,
            requested_blksize: 512,
            no_options: true,
            infilesize: payload.len() as i64,
        };
        let mut io = MockIo::new(vec![
            Some(encode_ack(0)),
            Some(encode_ack(1)),
            Some(encode_ack(2)),
            Some(encode_ack(3)),
        ]);
        let mut sink = NullSink;
        let mut src = VecSource::new(payload.clone());
        let mut eb = None;

        run_transfer(req, &mut io, &mut sink, &mut src, 60_000, false, &mut eb)
            .await
            .unwrap();

        // WRQ + DATA(512) + DATA(512) + DATA(empty).
        assert_eq!(io.sent.len(), 4);
        let mut uploaded = Vec::new();
        for pkt in &io.sent[1..] {
            uploaded.extend_from_slice(&pkt[4..]);
        }
        assert_eq!(uploaded, payload);
        // The terminating block is empty (header only).
        assert_eq!(io.sent[3].len(), 4);
    }

    #[tokio::test]
    async fn error_packet_maps_to_curlcode() {
        let req = TftpRequest {
            filename: "missing".to_string(),
            mode: TftpMode::Octet,
            upload: false,
            requested_blksize: 512,
            no_options: true,
            infilesize: -1,
        };
        let mut io = MockIo::new(vec![Some(make_error(1, "File not found"))]);
        let mut sink = VecSink::default();
        let mut src = EmptySource;
        let mut eb = None;

        let result = run_transfer(req, &mut io, &mut sink, &mut src, 60_000, false, &mut eb).await;
        assert!(matches!(result, Err(CurlError::TftpNotfound)));
    }

    #[tokio::test]
    async fn no_response_exhausts_retries_to_couldnt_connect() {
        let req = TftpRequest {
            filename: "file".to_string(),
            mode: TftpMode::Octet,
            upload: false,
            requested_blksize: 512,
            no_options: true,
            infilesize: -1,
        };
        // An empty response queue → every receive times out, so the initial
        // request is retransmitted up to the cap and then gives up.
        let mut io = MockIo::new(vec![]);
        let mut sink = VecSink::default();
        let mut src = EmptySource;
        let mut eb = None;

        // 15s budget → retry_max == 3, so the request is sent then retried.
        let result = run_transfer(req, &mut io, &mut sink, &mut src, 15_000, false, &mut eb).await;
        assert!(matches!(result, Err(CurlError::CouldntConnect)));
        // The initial RRQ plus retransmissions were all sent.
        assert!(io.sent.len() >= 2);
        assert!(io.sent.iter().all(|p| opcode_of(p) == TFTP_OPCODE_RRQ));
    }

    // ---- Transport (real loopback sockets) ----------------------------------

    #[cfg_attr(miri, ignore)]
    #[tokio::test]
    async fn udp_io_roundtrip_and_tid_pin() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let mut io = UdpTftpIo::connect(server_addr).await.unwrap();
        io.send_packet(b"hello").await.unwrap();

        // The server learns the client's address and replies; that reply pins
        // the transfer ID.
        let mut sbuf = [0u8; 16];
        let (n, client_addr) = server.recv_from(&mut sbuf).await.unwrap();
        assert_eq!(&sbuf[..n], b"hello");
        server.send_to(b"world", client_addr).await.unwrap();

        let mut rbuf = vec![0u8; 16];
        let got = io
            .recv_packet(&mut rbuf, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(got, Some(5));
        assert_eq!(&rbuf[..5], b"world");
        assert_eq!(io.peer(), Some(server_addr));

        // A datagram from any other address must be rejected (wrong TID).
        let intruder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        intruder.send_to(b"evil!", client_addr).await.unwrap();
        let rejected = io.recv_packet(&mut rbuf, Duration::from_secs(2)).await;
        assert!(matches!(rejected, Err(CurlError::RecvError)));
    }

    // ---- Protocol handler ----------------------------------------------------

    #[test]
    fn handler_reports_tftp_scheme() {
        let h = TftpHandler::new();
        assert_eq!(h.scheme().name, "tftp");
        assert_eq!(h.scheme().default_port, 69);
    }

    #[tokio::test]
    async fn setup_connection_requests_udp_transport() {
        use crate::conn::{SchemeDescriptor, TRNSPRT_TCP};

        let mut data = Easy::new();
        let scheme = SchemeDescriptor::new("tftp", 69, 0, 0);
        let mut conn = Connection::new("host", TRNSPRT_TCP, scheme);
        assert_eq!(conn.transport_wanted, TRNSPRT_TCP);

        let handler = TftpHandler::new();
        handler
            .setup_connection(&mut data, &mut conn)
            .await
            .unwrap();
        assert_eq!(conn.transport_wanted, TRNSPRT_UDP);
    }
}
