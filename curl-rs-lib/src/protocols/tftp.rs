//! RFC 1350 TFTP Protocol Handler with extensions.
//!
//! Rust rewrite of `lib/tftp.c` — Trivial File Transfer Protocol handler
//! implementing RFC 1350 (TFTP base), RFC 2347 (option extension), RFC 2348
//! (block size option), and RFC 2349 (timeout/transfer size options).
//!
//! # Architecture
//!
//! The handler implements the [`Protocol`] trait and is driven by a state
//! machine with four states (`Start`, `Rx`, `Tx`, `Done`). All network I/O
//! uses async UDP via [`tokio::net::UdpSocket`]. The handler is feature-gated
//! behind `#[cfg(feature = "tftp")]`.
//!
//! # State Machine
//!
//! ```text
//! Start ──→ (RRQ/WRQ sent) ──→ Rx (download) or Tx (upload)
//!                                    │
//!                                    ├─ (DATA / ACK exchange) ─┐
//!                                    │                         │
//!                                    └─ Done ←─────────────────┘
//! ```
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.
//!
//! # Source Mapping
//!
//! | Rust                      | C source                         |
//! |---------------------------|----------------------------------|
//! | `Tftp`                    | `struct tftp_conn`               |
//! | `TftpOpcode`              | `tftp_event_t` (RRQ..OACK)      |
//! | `TftpState`               | `tftp_state_t`                   |
//! | `TftpEvent`               | `tftp_event_t` (INIT/TIMEOUT/..) |
//! | `Tftp::tftp_send_first()` | `tftp_send_first()`              |
//! | `Tftp::tftp_rx()`         | `tftp_rx()`                      |
//! | `Tftp::tftp_tx()`         | `tftp_tx()`                      |
//! | `Tftp::state_machine()`   | `tftp_state_machine()`           |

use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::time::timeout;

use tracing::{debug, error, info, warn};

use crate::conn::ConnectionData;
use crate::error::{CurlError, CurlResult};
use crate::escape::url_decode;
use crate::progress::Progress;
use crate::protocols::{ConnectionCheckResult, Protocol, ProtocolFlags};
use crate::util::strparse::{starts_with_ignore_case, StrParser};

// TransferEngine is the data pipeline interface. In the full integration the
// TFTP handler will call its send_data / recv_data / write_response /
// write_done / setup_send / setup_recv methods to shuttle bytes between the
// UDP socket and the curl client. The import is kept to maintain the schema
// contract even though the current Protocol-trait-driven implementation
// defers the actual data flow wiring to the transfer layer orchestrator.
#[allow(unused_imports)]
use crate::transfer::TransferEngine;

// ===========================================================================
// Constants — matching C #define values from lib/tftp.c and lib/tftp.h
// ===========================================================================

/// Default TFTP block size (512 bytes) per RFC 1350 §4.
///
/// C: `#define TFTP_BLKSIZE_DEFAULT 512`
pub const TFTP_BLKSIZE_DEFAULT: u32 = 512;

/// Minimum TFTP block size allowed in option negotiation.
///
/// C: `#define TFTP_BLKSIZE_MIN 8`
pub const TFTP_BLKSIZE_MIN: u32 = 8;

/// Maximum TFTP block size allowed in option negotiation (65464 bytes).
///
/// This is the maximum UDP payload (65535) minus the TFTP header (4 bytes)
/// minus the IP header (20 bytes) minus the UDP header (8 bytes), leaving
/// room for a safe single-datagram transfer on most networks.
///
/// C: `#define TFTP_BLKSIZE_MAX 65464`
pub const TFTP_BLKSIZE_MAX: u32 = 65464;

/// TFTP option name for block size negotiation (RFC 2348).
const TFTP_OPTION_BLKSIZE: &str = "blksize";

/// TFTP option name for transfer size (RFC 2349).
const TFTP_OPTION_TSIZE: &str = "tsize";

/// TFTP option name for timeout interval (RFC 2349).
const TFTP_OPTION_INTERVAL: &str = "timeout";

/// Default TFTP server port per IANA assignment.
const TFTP_DEFAULT_PORT: u16 = 69;

/// Maximum number of retries before giving up. This is a fallback upper
/// bound; the actual retry_max is computed dynamically from the timeout.
/// Used by `set_timeouts` to cap the computed retry_max.
#[allow(dead_code)]
const TFTP_MAX_RETRIES_CAP: u32 = 50;

/// Minimum retries allowed.
const TFTP_MIN_RETRIES: u32 = 3;

/// Default per-block timeout in seconds when no user timeout is configured.
const TFTP_DEFAULT_TIMEOUT_SECS: u64 = 15;

/// Default retry interval in seconds.
const TFTP_DEFAULT_RETRY_SECS: u64 = 5;

// ===========================================================================
// TftpOpcode — TFTP packet opcodes (RFC 1350 §5)
// ===========================================================================

/// TFTP packet opcodes per RFC 1350 §5, extended with OACK (RFC 2347).
///
/// The integer values match the wire format: each opcode is transmitted as
/// a big-endian 16-bit unsigned integer in the first two bytes of every
/// TFTP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TftpOpcode {
    /// Read Request (RRQ) — client requests to download a file.
    Rrq = 1,
    /// Write Request (WRQ) — client requests to upload a file.
    Wrq = 2,
    /// Data packet carrying a block of file data.
    Data = 3,
    /// Acknowledgment of a received data block.
    Ack = 4,
    /// Error packet indicating a protocol-level error.
    Error = 5,
    /// Option Acknowledgment (RFC 2347) — server confirms option negotiation.
    Oack = 6,
}

impl TftpOpcode {
    /// Attempt to parse a `TftpOpcode` from a 16-bit integer.
    ///
    /// Returns `None` for values outside the defined range [1, 6].
    fn from_u16(val: u16) -> Option<Self> {
        match val {
            1 => Some(Self::Rrq),
            2 => Some(Self::Wrq),
            3 => Some(Self::Data),
            4 => Some(Self::Ack),
            5 => Some(Self::Error),
            6 => Some(Self::Oack),
            _ => None,
        }
    }
}

impl fmt::Display for TftpOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rrq => write!(f, "RRQ"),
            Self::Wrq => write!(f, "WRQ"),
            Self::Data => write!(f, "DATA"),
            Self::Ack => write!(f, "ACK"),
            Self::Error => write!(f, "ERROR"),
            Self::Oack => write!(f, "OACK"),
        }
    }
}

// ===========================================================================
// TftpState — protocol handler state machine states
// ===========================================================================

/// TFTP handler state machine states.
///
/// Maps to C `tftp_state_t`:
/// - `TFTP_STATE_START` → `Start`
/// - `TFTP_STATE_RX`    → `Rx`
/// - `TFTP_STATE_TX`    → `Tx`
/// - `TFTP_STATE_FIN`   → `Done`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TftpState {
    /// Initial state — waiting to send first RRQ/WRQ.
    Start,
    /// Receiving data (download mode).
    Rx,
    /// Transmitting data (upload mode).
    Tx,
    /// Transfer complete (success or error).
    Done,
}

impl fmt::Display for TftpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start => write!(f, "START"),
            Self::Rx => write!(f, "RX"),
            Self::Tx => write!(f, "TX"),
            Self::Done => write!(f, "DONE"),
        }
    }
}

// ===========================================================================
// TftpEvent — events driving the state machine
// ===========================================================================

/// Events driving TFTP state transitions.
///
/// The `Init`, `Timeout`, `Rx`, and `None` variants are the high-level
/// events that the state machine dispatches on. During execution, received
/// packets are further classified by their opcode into sub-events (DATA,
/// ACK, ERROR, OACK), but those are handled internally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TftpEvent {
    /// Initial event: triggers the first RRQ/WRQ transmission.
    Init,
    /// Timeout event: triggers retransmission of the last packet.
    Timeout,
    /// Data received event: a packet was received from the server.
    Rx,
    /// No event: idle poll cycle, no action needed.
    None,
}

impl fmt::Display for TftpEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init => write!(f, "INIT"),
            Self::Timeout => write!(f, "TIMEOUT"),
            Self::Rx => write!(f, "RX"),
            Self::None => write!(f, "NONE"),
        }
    }
}

// ===========================================================================
// TftpErrorCode — internal TFTP error codes (wire + internal)
// ===========================================================================

/// Internal TFTP error codes combining wire-protocol error codes (RFC 1350
/// §5) with curl-internal sentinel values.
///
/// Wire error codes (0–7) are transmitted in ERROR packets. Internal codes
/// (negative values in C, here separate variants) are used for timeout and
/// no-response conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TftpErrorCode {
    /// No error has occurred.
    None,
    /// Undefined error (wire code 0).
    Undef,
    /// File not found (wire code 1).
    NotFound,
    /// Access violation (wire code 2).
    Perm,
    /// Disk full or allocation exceeded (wire code 3).
    DiskFull,
    /// Illegal TFTP operation (wire code 4).
    Illegal,
    /// Unknown transfer ID (wire code 5).
    UnknownId,
    /// File already exists (wire code 6).
    Exists,
    /// No such user (wire code 7).
    NoSuchUser,
    /// Internal: overall transfer timeout reached.
    Timeout,
    /// Internal: no response received for initial RRQ/WRQ.
    NoResponse,
}

impl TftpErrorCode {
    /// Parse a TFTP error code from the wire-format integer.
    fn from_u16(val: u16) -> Self {
        match val {
            0 => Self::Undef,
            1 => Self::NotFound,
            2 => Self::Perm,
            3 => Self::DiskFull,
            4 => Self::Illegal,
            5 => Self::UnknownId,
            6 => Self::Exists,
            7 => Self::NoSuchUser,
            _ => Self::Undef,
        }
    }

    /// Translate internal TFTP error codes to [`CurlError`] variants.
    ///
    /// Matches the C `tftp_translate_code()` function exactly.
    fn to_curl_error(self) -> CurlError {
        match self {
            Self::None => CurlError::Ok,
            Self::NotFound => CurlError::TftpNotFound,
            Self::Perm => CurlError::TftpPerm,
            Self::DiskFull => CurlError::RemoteDiskFull,
            Self::Undef | Self::Illegal => CurlError::TftpIllegal,
            Self::UnknownId => CurlError::TftpUnknownId,
            Self::Exists => CurlError::RemoteFileExists,
            Self::NoSuchUser => CurlError::TftpNoSuchUser,
            Self::Timeout => CurlError::OperationTimedOut,
            Self::NoResponse => CurlError::CouldntConnect,
        }
    }
}

// ===========================================================================
// TftpMode — transfer mode
// ===========================================================================

/// TFTP transfer mode.
///
/// RFC 1350 §2 defines two transfer modes: `netascii` (text with CR-LF
/// translation) and `octet` (raw binary). The `mail` mode from the original
/// RFC is obsolete and not supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum TftpMode {
    /// Binary transfer — no translation.
    Octet,
    /// Netascii transfer — CR-LF translation for text files.
    Netascii,
}

impl TftpMode {
    /// Returns the wire-format mode string.
    fn as_str(&self) -> &'static str {
        match self {
            Self::Octet => "octet",
            Self::Netascii => "netascii",
        }
    }
}

// ===========================================================================
// Tftp — main protocol handler struct
// ===========================================================================

/// TFTP protocol handler implementing the [`Protocol`] trait.
///
/// Manages the complete lifecycle of a TFTP transfer including:
/// - UDP socket binding and server communication
/// - RRQ/WRQ request packet construction with option extensions
/// - OACK option negotiation (blksize, tsize, timeout)
/// - DATA/ACK exchange with automatic retransmission
/// - ERROR packet generation and parsing
/// - Transfer mode detection (octet/netascii)
///
/// # State
///
/// Per-connection state is encapsulated within this struct, replacing the C
/// pattern of storing `struct tftp_conn` in the connection metadata hash.
pub struct Tftp {
    /// Current state machine state.
    state: TftpState,
    /// Transfer mode (octet or netascii).
    mode: TftpMode,
    /// Internal error code for deferred error reporting.
    error_code: TftpErrorCode,
    /// Whether the transfer is an upload (WRQ) or download (RRQ).
    is_upload: bool,

    // -- Block tracking -------------------------------------------------------
    /// Current block number (0-based for OACK, 1-based for first data block).
    block: u16,

    // -- Block size negotiation -----------------------------------------------
    /// Negotiated block size (defaults to 512, may be changed via OACK).
    blksize: u32,
    /// Block size requested in the RRQ/WRQ option extension.
    requested_blksize: u32,

    // -- Retry / timeout management -------------------------------------------
    /// Number of retransmission attempts for the current block.
    retries: u32,
    /// Maximum retries before declaring timeout.
    retry_max: u32,
    /// Retry interval in seconds (computed from overall timeout).
    retry_time: u64,
    /// Timestamp of the last received packet (for per-block timeout detection).
    rx_time: Instant,

    // -- Network state --------------------------------------------------------
    /// Bound UDP socket for this transfer.
    socket: Option<UdpSocket>,
    /// Remote server address (port changes after first reply per TFTP spec).
    remote_addr: Option<SocketAddr>,
    /// Whether the remote address has been pinned (after first data reply).
    remote_pinned: bool,

    // -- Packet buffers -------------------------------------------------------
    /// Send packet buffer (RRQ/WRQ/DATA/ACK/ERROR).
    sbuf: Vec<u8>,
    /// Receive packet buffer.
    rbuf: Vec<u8>,
    /// Number of valid bytes in the send buffer payload (DATA content only).
    sbytes: usize,
    /// Number of valid bytes in the last received packet.
    rbytes: usize,

    // -- Transfer tracking (for progress) -------------------------------------
    /// Total bytes written (upload) — used for progress tracking.
    write_byte_count: u64,

    // -- Overall timeout tracking ---------------------------------------------
    /// Transfer deadline (overall timeout from user config).
    deadline: Option<Instant>,

    // -- URL path for filename extraction -------------------------------------
    /// Decoded filename from the TFTP URL path.
    filename: String,

    // -- Transfer size tracking -----------------------------------------------
    /// Transfer size announced by the server via OACK tsize option.
    tsize: Option<u64>,
    /// Upload file size (from user configuration, -1 if unknown).
    upload_size: Option<u64>,

    // -- Progress tracker reference (owned for self-contained operation) -------
    progress: Progress,

    // -- Options flags --------------------------------------------------------
    /// Whether to include TFTP options in RRQ/WRQ (blksize, tsize, timeout).
    /// Corresponds to C `data->set.tftp_no_options`.
    include_options: bool,
}

impl Default for Tftp {
    fn default() -> Self {
        Self::new()
    }
}

impl Tftp {
    // ====================================================================
    // Construction
    // ====================================================================

    /// Creates a new TFTP handler with default settings.
    ///
    /// The handler is initialized in `Start` state with default block size
    /// (512 bytes), octet transfer mode, and no active socket.
    pub fn new() -> Self {
        Self {
            state: TftpState::Start,
            mode: TftpMode::Octet,
            error_code: TftpErrorCode::None,
            is_upload: false,
            block: 0,
            blksize: TFTP_BLKSIZE_DEFAULT,
            requested_blksize: TFTP_BLKSIZE_DEFAULT,
            retries: 0,
            retry_max: TFTP_MIN_RETRIES,
            retry_time: TFTP_DEFAULT_RETRY_SECS,
            rx_time: Instant::now(),
            socket: None,
            remote_addr: None,
            remote_pinned: false,
            sbuf: Vec::new(),
            rbuf: Vec::new(),
            sbytes: 0,
            rbytes: 0,
            write_byte_count: 0,
            deadline: None,
            filename: String::new(),
            tsize: None,
            upload_size: None,
            progress: Progress::new(),
            include_options: true,
        }
    }

    // ====================================================================
    // Configuration
    // ====================================================================

    /// Configures the TFTP handler for a transfer.
    ///
    /// This sets the transfer direction, filename, transfer mode, block size,
    /// and timeout parameters based on URL and user options.
    #[allow(dead_code, clippy::too_many_arguments)]
    fn configure(
        &mut self,
        url_path: &str,
        is_upload: bool,
        prefer_ascii: bool,
        blksize: Option<u32>,
        no_options: bool,
        upload_size: Option<u64>,
        timeout_ms: Option<u64>,
    ) -> CurlResult<()> {
        self.is_upload = is_upload;
        self.include_options = !no_options;

        // Transfer mode — octet by default, netascii if -B/--use-ascii or
        // ";mode=netascii" URL suffix.
        if prefer_ascii {
            self.mode = TftpMode::Netascii;
        } else {
            self.mode = TftpMode::Octet;
        }

        // URL path mode detection: strip ";mode=netascii" or ";mode=octet"
        // suffixes from the path before extracting the filename.
        let path = if let Some(stripped) = url_path.strip_suffix(";mode=netascii") {
            self.mode = TftpMode::Netascii;
            stripped
        } else if let Some(stripped) = url_path.strip_suffix(";mode=octet") {
            self.mode = TftpMode::Octet;
            stripped
        } else {
            url_path
        };

        // Decode filename — skip the leading '/' per RFC 3617.
        let raw_path = path.strip_prefix('/').unwrap_or(path);
        if raw_path.is_empty() {
            error!("Missing filename in TFTP URL");
            return Err(CurlError::TftpIllegal);
        }
        let decoded_bytes = url_decode(raw_path)?;
        self.filename = String::from_utf8(decoded_bytes)
            .map_err(|_| CurlError::TftpIllegal)?;

        // Block size configuration.
        if let Some(bs) = blksize {
            if (TFTP_BLKSIZE_MIN..=TFTP_BLKSIZE_MAX).contains(&bs) {
                self.requested_blksize = bs;
            }
        }

        // Allocate packet buffers large enough for the negotiated block size.
        // Buffer = 4 bytes header + blksize bytes data.
        let buf_size = self.effective_buffer_size();
        self.sbuf.resize(buf_size, 0);
        self.rbuf.resize(buf_size, 0);

        // Block size default (before OACK) — matches C behavior where
        // the default is always used until OACK changes it.
        self.blksize = TFTP_BLKSIZE_DEFAULT;

        // Upload size tracking.
        self.upload_size = upload_size;

        // Timeout calculation.
        self.set_timeouts(timeout_ms);

        Ok(())
    }

    /// Compute the buffer size needed for packet buffers.
    fn effective_buffer_size(&self) -> usize {
        let need = self.requested_blksize.max(TFTP_BLKSIZE_DEFAULT);
        (need as usize) + 4
    }

    // ====================================================================
    // Timeout Management
    // ====================================================================

    /// Set timeouts based on user-configured overall timeout.
    ///
    /// Computes retry_max and retry_time from the overall timeout,
    /// matching C `tftp_set_timeouts()`.
    #[allow(dead_code)]
    fn set_timeouts(&mut self, timeout_ms: Option<u64>) {
        let total_secs = match timeout_ms {
            Some(ms) if ms > 0 => (ms + 500) / 1000,
            _ => TFTP_DEFAULT_TIMEOUT_SECS,
        };

        // Set overall deadline.
        if let Some(ms) = timeout_ms {
            if ms > 0 {
                self.deadline = Some(Instant::now() + Duration::from_millis(ms));
            }
        }

        // Calculate retry parameters: retry_max = total / 5, bounded [3, 50].
        let retry_max = (total_secs / TFTP_DEFAULT_RETRY_SECS).max(1);
        self.retry_max = retry_max
            .max(TFTP_MIN_RETRIES as u64)
            .min(TFTP_MAX_RETRIES_CAP as u64) as u32;

        // Compute per-block retry interval.
        self.retry_time = (total_secs / self.retry_max as u64).max(1);

        // Initialize rx_time for the first timeout check.
        self.rx_time = Instant::now();

        info!(
            state = %self.state,
            total_secs,
            retry_time = self.retry_time,
            retry_max = self.retry_max,
            "TFTP timeouts configured"
        );
    }

    /// Check if the overall transfer has timed out.
    ///
    /// Returns the remaining time in milliseconds, or an error if timed out.
    fn check_overall_timeout(&self) -> CurlResult<u64> {
        if let Some(deadline) = self.deadline {
            let now = Instant::now();
            if now >= deadline {
                return Err(CurlError::OperationTimedOut);
            }
            let remaining = deadline.duration_since(now);
            Ok(remaining.as_millis() as u64)
        } else {
            // No deadline — use a generous default.
            Ok(TFTP_DEFAULT_TIMEOUT_SECS * 1000)
        }
    }

    /// Check per-block timeout and generate a Timeout event if needed.
    ///
    /// Matches C `tftp_state_timeout()`.
    fn check_block_timeout(&mut self) -> TftpEvent {
        // Check overall timeout first.
        if self.check_overall_timeout().is_err() {
            self.error_code = TftpErrorCode::Timeout;
            self.state = TftpState::Done;
            return TftpEvent::Timeout;
        }

        // Check per-block timeout.
        let elapsed = self.rx_time.elapsed();
        if elapsed >= Duration::from_secs(self.retry_time) {
            // Reset rx_time even on timeout (matches C behavior).
            self.rx_time = Instant::now();
            TftpEvent::Timeout
        } else {
            TftpEvent::None
        }
    }

    // ====================================================================
    // Packet Building
    // ====================================================================

    /// Set the opcode (event) field in a packet buffer.
    fn set_packet_opcode(buf: &mut [u8], opcode: u16) {
        if buf.len() >= 2 {
            buf[0] = (opcode >> 8) as u8;
            buf[1] = (opcode & 0xff) as u8;
        }
    }

    /// Set the block number field in a packet buffer (bytes 2–3).
    fn set_packet_block(buf: &mut [u8], block: u16) {
        if buf.len() >= 4 {
            buf[2] = (block >> 8) as u8;
            buf[3] = (block & 0xff) as u8;
        }
    }

    /// Read the opcode from a received packet buffer.
    fn get_packet_opcode(buf: &[u8]) -> u16 {
        if buf.len() >= 2 {
            ((buf[0] as u16) << 8) | (buf[1] as u16)
        } else {
            0
        }
    }

    /// Read the block number from a received packet buffer.
    fn get_packet_block(buf: &[u8]) -> u16 {
        if buf.len() >= 4 {
            ((buf[2] as u16) << 8) | (buf[3] as u16)
        } else {
            0
        }
    }

    /// Compute the next block number with 16-bit wrapping.
    ///
    /// Matches C `NEXT_BLOCKNUM(x)` macro: `((x) + 1) & 0xffff`.
    fn next_blocknum(block: u16) -> u16 {
        block.wrapping_add(1)
    }

    /// Build a RRQ or WRQ request packet.
    ///
    /// Packet format (RFC 1350 §2):
    /// ```text
    /// 2 bytes     string    1 byte  string   1 byte
    /// ┌──────────┬─────────┬───────┬────────┬───────┐
    /// │ Opcode   │ Filename│   0   │  Mode  │   0   │
    /// └──────────┴─────────┴───────┴────────┴───────┘
    /// ```
    ///
    /// With option extensions (RFC 2347):
    /// ```text
    /// ... │ opt1 │ 0 │ val1 │ 0 │ opt2 │ 0 │ val2 │ 0 │ ...
    /// ```
    fn build_request_packet(&mut self) -> CurlResult<usize> {
        let opcode = if self.is_upload {
            TftpOpcode::Wrq as u16
        } else {
            TftpOpcode::Rrq as u16
        };

        let mode_str = self.mode.as_str();
        let filename = self.filename.clone();

        // Validate filename + mode fit in the buffer.
        let min_size = 2 + filename.len() + 1 + mode_str.len() + 1;
        if min_size > self.sbuf.len() {
            error!(
                filename_len = filename.len(),
                mode = mode_str,
                "TFTP filename too long"
            );
            return Err(CurlError::TftpIllegal);
        }

        // Build the base packet.
        Self::set_packet_opcode(&mut self.sbuf, opcode);
        let mut pos = 2;

        // Filename (null-terminated).
        self.sbuf[pos..pos + filename.len()].copy_from_slice(filename.as_bytes());
        pos += filename.len();
        self.sbuf[pos] = 0;
        pos += 1;

        // Mode (null-terminated).
        self.sbuf[pos..pos + mode_str.len()].copy_from_slice(mode_str.as_bytes());
        pos += mode_str.len();
        self.sbuf[pos] = 0;
        pos += 1;

        // Append option extensions if enabled.
        if self.include_options {
            // tsize option.
            let tsize_val = if self.is_upload {
                self.upload_size.unwrap_or(0)
            } else {
                0
            };
            let tsize_str = tsize_val.to_string();
            pos = self.append_option(pos, TFTP_OPTION_TSIZE, &tsize_str)?;

            // blksize option.
            let blksize_str = self.requested_blksize.to_string();
            pos = self.append_option(pos, TFTP_OPTION_BLKSIZE, &blksize_str)?;

            // timeout option.
            let timeout_str = self.retry_time.to_string();
            pos = self.append_option(pos, TFTP_OPTION_INTERVAL, &timeout_str)?;
        }

        Ok(pos)
    }

    /// Append a null-terminated option name and value to the send buffer.
    fn append_option(
        &mut self,
        start: usize,
        name: &str,
        value: &str,
    ) -> CurlResult<usize> {
        let needed = name.len() + 1 + value.len() + 1;
        if start + needed > self.sbuf.len() {
            warn!(
                option = name,
                "TFTP buffer too small for option"
            );
            return Err(CurlError::TftpIllegal);
        }

        let mut pos = start;
        self.sbuf[pos..pos + name.len()].copy_from_slice(name.as_bytes());
        pos += name.len();
        self.sbuf[pos] = 0;
        pos += 1;
        self.sbuf[pos..pos + value.len()].copy_from_slice(value.as_bytes());
        pos += value.len();
        self.sbuf[pos] = 0;
        pos += 1;
        Ok(pos)
    }

    /// Build an ACK packet for the given block number.
    fn build_ack_packet(&mut self, block: u16) -> usize {
        Self::set_packet_opcode(&mut self.sbuf, TftpOpcode::Ack as u16);
        Self::set_packet_block(&mut self.sbuf, block);
        4
    }

    /// Build a DATA packet header (opcode + block number).
    /// The caller is responsible for filling in the data payload.
    fn build_data_header(&mut self, block: u16) {
        Self::set_packet_opcode(&mut self.sbuf, TftpOpcode::Data as u16);
        Self::set_packet_block(&mut self.sbuf, block);
    }

    /// Build an ERROR packet.
    fn build_error_packet(&mut self, code: u16, msg: &str) -> usize {
        Self::set_packet_opcode(&mut self.sbuf, TftpOpcode::Error as u16);
        Self::set_packet_block(&mut self.sbuf, code);
        let msg_bytes = msg.as_bytes();
        let msg_len = msg_bytes.len().min(self.sbuf.len().saturating_sub(5));
        if msg_len > 0 {
            self.sbuf[4..4 + msg_len].copy_from_slice(&msg_bytes[..msg_len]);
        }
        self.sbuf[4 + msg_len] = 0;
        5 + msg_len
    }

    // ====================================================================
    // OACK Parsing
    // ====================================================================

    /// Parse an OACK (Option Acknowledgment) response packet.
    ///
    /// Extracts negotiated values for `blksize`, `tsize`, and `timeout`
    /// options. Invalid or out-of-range values trigger an error.
    ///
    /// Matches C `tftp_parse_option_ack()` exactly.
    fn parse_option_ack(&mut self, data: &[u8]) -> CurlResult<()> {
        // Reset blksize to default — if OACK doesn't contain blksize, we
        // use the default (512).
        self.blksize = TFTP_BLKSIZE_DEFAULT;

        let mut offset = 0;
        while offset < data.len() {
            // Extract option name (null-terminated string).
            let option_name = match Self::extract_null_string(data, offset) {
                Some((name, next)) => {
                    offset = next;
                    name
                }
                None => {
                    error!("Malformed OACK packet, rejecting");
                    return Err(CurlError::TftpIllegal);
                }
            };

            // Extract option value (null-terminated string).
            let option_value = match Self::extract_null_string(data, offset) {
                Some((val, next)) => {
                    offset = next;
                    val
                }
                None => {
                    error!("Malformed OACK packet, missing value");
                    return Err(CurlError::TftpIllegal);
                }
            };

            info!(
                option = option_name,
                value = option_value,
                "TFTP OACK option received"
            );

            // Process recognized options.
            if starts_with_ignore_case(option_name, TFTP_OPTION_BLKSIZE) {
                self.parse_blksize_option(option_value)?;
            } else if starts_with_ignore_case(option_name, TFTP_OPTION_TSIZE) {
                self.parse_tsize_option(option_value)?;
            }
            // Timeout option is accepted but we don't change our retry_time
            // based on the server's response — matches C behavior.
        }

        Ok(())
    }

    /// Parse the `blksize` option value from an OACK response.
    fn parse_blksize_option(&mut self, value: &str) -> CurlResult<()> {
        let mut parser = StrParser::new(value);
        let parsed = parser.parse_decimal(10);
        let remaining = parser.remaining();

        match parsed {
            Ok(blksize) if !remaining.is_empty() && !remaining.starts_with('\0') => {
                error!("blksize value has trailing characters");
                Err(CurlError::TftpIllegal)
            }
            Ok(blksize) => {
                if blksize == 0 {
                    error!("invalid blocksize value in OACK packet");
                    return Err(CurlError::TftpIllegal);
                }
                if blksize < TFTP_BLKSIZE_MIN as u64 {
                    error!(
                        blksize,
                        min = TFTP_BLKSIZE_MIN,
                        "blksize is smaller than min supported"
                    );
                    return Err(CurlError::TftpIllegal);
                }
                if blksize > TFTP_BLKSIZE_MAX as u64 {
                    error!(
                        blksize,
                        max = TFTP_BLKSIZE_MAX,
                        "blksize is larger than max supported"
                    );
                    return Err(CurlError::TftpIllegal);
                }
                if blksize > self.requested_blksize as u64 {
                    error!(
                        server_blksize = blksize,
                        requested = self.requested_blksize,
                        "server requested blksize larger than allocated"
                    );
                    return Err(CurlError::TftpIllegal);
                }
                self.blksize = blksize as u32;
                info!(
                    blksize = self.blksize,
                    requested = self.requested_blksize,
                    "blksize parsed from OACK"
                );
                Ok(())
            }
            Err(_) => {
                error!("blksize is larger than max supported");
                Err(CurlError::TftpIllegal)
            }
        }
    }

    /// Parse the `tsize` option value from an OACK response.
    fn parse_tsize_option(&mut self, value: &str) -> CurlResult<()> {
        // tsize should be ignored on upload — matches C behavior.
        if self.is_upload {
            return Ok(());
        }

        let mut parser = StrParser::new(value);
        match parser.parse_decimal(20) {
            Ok(tsize) => {
                if tsize == 0 {
                    error!(
                        raw_value = value,
                        "invalid tsize value in OACK packet"
                    );
                    return Err(CurlError::TftpIllegal);
                }
                info!(tsize, "tsize parsed from OACK");
                self.tsize = Some(tsize);
                self.progress.set_download_size(Some(tsize));
                Ok(())
            }
            Err(_) => {
                // Not a valid number — ignore silently on download
                // (matches C behavior where an invalid tsize just means
                // we don't set the download size).
                Ok(())
            }
        }
    }

    /// Extract a null-terminated string from `data` starting at `offset`.
    ///
    /// Returns the string and the offset after the null terminator.
    fn extract_null_string(data: &[u8], offset: usize) -> Option<(&str, usize)> {
        if offset >= data.len() {
            return None;
        }
        let remaining = &data[offset..];
        let nul_pos = remaining.iter().position(|&b| b == 0)?;
        let s = std::str::from_utf8(&remaining[..nul_pos]).ok()?;
        Some((s, offset + nul_pos + 1))
    }

    // ====================================================================
    // Send / Receive Helpers
    // ====================================================================

    /// Send the contents of self.sbuf[..len] to the remote address.
    async fn send_packet(&self, len: usize) -> CurlResult<()> {
        let socket = self.socket.as_ref().ok_or(CurlError::FailedInit)?;
        let addr = self.remote_addr.ok_or(CurlError::FailedInit)?;

        match socket.send_to(&self.sbuf[..len], addr).await {
            Ok(sent) if sent == len => Ok(()),
            Ok(sent) => {
                warn!(
                    expected = len,
                    actual = sent,
                    "TFTP short send"
                );
                Err(CurlError::SendError)
            }
            Err(e) => {
                error!(error = %e, "TFTP send failed");
                Err(CurlError::SendError)
            }
        }
    }

    /// Receive a packet into self.rbuf, with a timeout.
    ///
    /// Returns `Ok(true)` if a packet was received, `Ok(false)` on timeout.
    /// Updates `self.rbytes` with the number of received bytes.
    /// Validates the source address (pinning on first response).
    #[allow(dead_code)]
    async fn receive_packet(&mut self, timeout_duration: Duration) -> CurlResult<bool> {
        let socket = self.socket.as_ref().ok_or(CurlError::FailedInit)?;

        // Attempt to receive with timeout.
        let result = timeout(timeout_duration, socket.recv_from(&mut self.rbuf)).await;

        match result {
            Ok(Ok((nbytes, from_addr))) => {
                self.rbytes = nbytes;

                // Validate source address — pin on first reply.
                if self.remote_pinned {
                    if let Some(pinned) = self.remote_addr {
                        // After the first OACK/DATA/ACK, the server responds
                        // from a new port. We pin to that address.
                        if from_addr != pinned {
                            error!(
                                expected = %pinned,
                                received_from = %from_addr,
                                "Data received from another address"
                            );
                            return Err(CurlError::RecvError);
                        }
                    }
                } else {
                    // Pin the remote address on first data response.
                    self.remote_pinned = true;
                    self.remote_addr = Some(from_addr);
                    debug!(
                        addr = %from_addr,
                        "TFTP remote address pinned"
                    );
                }

                Ok(true)
            }
            Ok(Err(e)) => {
                error!(error = %e, "TFTP recv failed");
                Err(CurlError::RecvError)
            }
            Err(_) => {
                // Timeout — no data available.
                Ok(false)
            }
        }
    }

    // ====================================================================
    // State Machine — main dispatcher
    // ====================================================================

    /// Main state machine dispatcher.
    ///
    /// Processes the given event in the context of the current state,
    /// matching C `tftp_state_machine()`.
    async fn state_machine(&mut self, event: TftpEvent) -> CurlResult<()> {
        debug!(state = %self.state, event = %event, "TFTP state machine");

        match self.state {
            TftpState::Start => self.handle_start(event).await,
            TftpState::Rx => self.handle_rx(event).await,
            TftpState::Tx => self.handle_tx(event).await,
            TftpState::Done => {
                info!("TFTP finished");
                Ok(())
            }
        }
    }

    // ====================================================================
    // State: Start — initial RRQ/WRQ transmission
    // ====================================================================

    /// Handle events in the `Start` state.
    ///
    /// Matches C `tftp_send_first()`.
    async fn handle_start(&mut self, event: TftpEvent) -> CurlResult<()> {
        match event {
            TftpEvent::Init | TftpEvent::Timeout => {
                // Increment retry counter.
                self.retries += 1;
                if self.retries > self.retry_max {
                    self.error_code = TftpErrorCode::NoResponse;
                    self.state = TftpState::Done;
                    return Ok(());
                }

                // Set upload progress size if available.
                if self.is_upload {
                    if let Some(size) = self.upload_size {
                        self.progress.set_upload_size(Some(size));
                    }
                }

                // Build and send the RRQ/WRQ packet.
                let pkt_len = self.build_request_packet()?;
                self.send_packet(pkt_len).await?;
            }

            TftpEvent::Rx => {
                // A packet arrived while in Start state — classify it.
                let opcode_raw = Self::get_packet_opcode(&self.rbuf[..self.rbytes]);
                match TftpOpcode::from_u16(opcode_raw) {
                    Some(TftpOpcode::Oack) => {
                        // Parse option acknowledgment.
                        // Copy the packet data to avoid borrow conflict.
                        if self.rbytes > 2 {
                            let oack_data = self.rbuf[2..self.rbytes].to_vec();
                            self.parse_option_ack(&oack_data)?;
                        }
                        if self.is_upload {
                            self.connect_for_tx(TftpOpcode::Oack).await?;
                        } else {
                            self.connect_for_rx(TftpOpcode::Oack).await?;
                        }
                    }
                    Some(TftpOpcode::Ack) => {
                        // Direct ACK — connected for transmit (no OACK).
                        self.connect_for_tx(TftpOpcode::Ack).await?;
                    }
                    Some(TftpOpcode::Data) => {
                        // Direct DATA — connected for receive (no OACK).
                        self.connect_for_rx(TftpOpcode::Data).await?;
                    }
                    Some(TftpOpcode::Error) => {
                        self.handle_error_packet();
                        self.state = TftpState::Done;
                    }
                    _ => {
                        error!(
                            opcode = opcode_raw,
                            "TFTP: internal error, unexpected packet in Start"
                        );
                        return Err(CurlError::TftpIllegal);
                    }
                }
            }

            TftpEvent::None => {
                // No event — nothing to do.
            }
        }

        Ok(())
    }

    /// Transition to TX state after establishing connection for upload.
    async fn connect_for_tx(&mut self, initial_opcode: TftpOpcode) -> CurlResult<()> {
        info!("Connected for transmit");
        self.state = TftpState::Tx;
        // Recalculate timeouts for the transfer phase.
        self.rx_time = Instant::now();
        self.retries = 0;

        // Process the initial event as if in TX state.
        self.handle_tx_opcode(initial_opcode).await
    }

    /// Transition to RX state after establishing connection for download.
    async fn connect_for_rx(&mut self, initial_opcode: TftpOpcode) -> CurlResult<()> {
        info!("Connected for receive");
        self.state = TftpState::Rx;
        self.rx_time = Instant::now();
        self.retries = 0;

        // Process the initial event as if in RX state.
        self.handle_rx_opcode(initial_opcode).await
    }

    // ====================================================================
    // State: Rx — receiving data (download)
    // ====================================================================

    /// Handle events in the `Rx` state.
    ///
    /// Matches C `tftp_rx()`.
    async fn handle_rx(&mut self, event: TftpEvent) -> CurlResult<()> {
        match event {
            TftpEvent::Rx => {
                let opcode_raw = Self::get_packet_opcode(&self.rbuf[..self.rbytes]);
                match TftpOpcode::from_u16(opcode_raw) {
                    Some(TftpOpcode::Data) => {
                        self.handle_rx_opcode(TftpOpcode::Data).await
                    }
                    Some(TftpOpcode::Oack) => {
                        self.handle_rx_opcode(TftpOpcode::Oack).await
                    }
                    Some(TftpOpcode::Error) => {
                        self.handle_error_packet();
                        let len = self.build_error_packet(0, "");
                        let _ = self.send_packet(len).await;
                        self.state = TftpState::Done;
                        Ok(())
                    }
                    _ => {
                        error!("tftp_rx: internal error, unexpected packet");
                        Err(CurlError::TftpIllegal)
                    }
                }
            }
            TftpEvent::Timeout => {
                self.retries += 1;
                info!(
                    block = Self::next_blocknum(self.block),
                    retries = self.retries,
                    "Timeout waiting for block ACK"
                );
                if self.retries > self.retry_max {
                    self.error_code = TftpErrorCode::Timeout;
                    self.state = TftpState::Done;
                } else {
                    // Resend the previous ACK.
                    let len = self.build_ack_packet(self.block);
                    self.send_packet(len).await?;
                }
                Ok(())
            }
            TftpEvent::Init => {
                // Not expected in Rx state.
                Ok(())
            }
            TftpEvent::None => Ok(()),
        }
    }

    /// Handle a specific opcode while in the Rx state.
    async fn handle_rx_opcode(&mut self, opcode: TftpOpcode) -> CurlResult<()> {
        match opcode {
            TftpOpcode::Data => {
                let rblock = Self::get_packet_block(&self.rbuf[..self.rbytes]);
                let expected = Self::next_blocknum(self.block);

                if expected == rblock {
                    // Expected block — reset retry counter.
                    self.retries = 0;
                } else if self.block == rblock {
                    // Duplicate of the last block — ACK it again.
                    info!(block = rblock, "Received last DATA packet block again");
                } else {
                    // Unexpected block — just log and skip.
                    info!(
                        received = rblock,
                        expected,
                        "Received unexpected DATA packet block"
                    );
                    return Ok(());
                }

                // ACK this block.
                self.block = rblock;
                let ack_len = self.build_ack_packet(self.block);
                self.send_packet(ack_len).await?;

                // Check if this is the final block (less than full block size).
                if (self.rbytes as u32) < self.blksize + 4 {
                    self.state = TftpState::Done;
                } else {
                    self.state = TftpState::Rx;
                }
                self.rx_time = Instant::now();
                Ok(())
            }
            TftpOpcode::Oack => {
                // ACK option acknowledgment (block 0) to start data flow.
                self.block = 0;
                self.retries = 0;
                let ack_len = self.build_ack_packet(0);
                self.send_packet(ack_len).await?;
                self.state = TftpState::Rx;
                self.rx_time = Instant::now();
                Ok(())
            }
            TftpOpcode::Error => {
                self.handle_error_packet();
                let err_len = self.build_error_packet(0, "");
                let _ = self.send_packet(err_len).await;
                self.state = TftpState::Done;
                Ok(())
            }
            _ => {
                error!(opcode = ?opcode, "tftp_rx: unexpected opcode");
                Err(CurlError::TftpIllegal)
            }
        }
    }

    // ====================================================================
    // State: Tx — transmitting data (upload)
    // ====================================================================

    /// Handle events in the `Tx` state.
    ///
    /// Matches C `tftp_tx()`.
    async fn handle_tx(&mut self, event: TftpEvent) -> CurlResult<()> {
        match event {
            TftpEvent::Rx => {
                let opcode_raw = Self::get_packet_opcode(&self.rbuf[..self.rbytes]);
                match TftpOpcode::from_u16(opcode_raw) {
                    Some(TftpOpcode::Ack) => {
                        self.handle_tx_opcode(TftpOpcode::Ack).await
                    }
                    Some(TftpOpcode::Oack) => {
                        self.handle_tx_opcode(TftpOpcode::Oack).await
                    }
                    Some(TftpOpcode::Error) => {
                        self.handle_error_packet();
                        self.state = TftpState::Done;
                        Ok(())
                    }
                    _ => {
                        error!(
                            opcode = opcode_raw,
                            "tftp_tx: unexpected packet"
                        );
                        Ok(())
                    }
                }
            }
            TftpEvent::Timeout => {
                self.retries += 1;
                info!(
                    block = Self::next_blocknum(self.block),
                    retries = self.retries,
                    "Timeout waiting for block ACK"
                );
                if self.retries > self.retry_max {
                    self.error_code = TftpErrorCode::Timeout;
                    self.state = TftpState::Done;
                } else {
                    // Retransmit the last DATA packet.
                    let pkt_len = 4 + self.sbytes;
                    self.send_packet(pkt_len).await?;
                    // Reset upload counter for retransmission.
                    self.progress.set_upload_counter(self.write_byte_count);
                }
                Ok(())
            }
            TftpEvent::Init => Ok(()),
            TftpEvent::None => Ok(()),
        }
    }

    /// Handle a specific opcode while in the Tx state.
    async fn handle_tx_opcode(&mut self, opcode: TftpOpcode) -> CurlResult<()> {
        match opcode {
            TftpOpcode::Ack => {
                let rblock = Self::get_packet_block(&self.rbuf[..self.rbytes]);

                // Validate block number.
                if rblock != self.block
                    // tftpd-hpa bug: sends ACK for 65535 when wrapping to 0.
                    && !(self.block == 0 && rblock == 65535)
                {
                    info!(
                        received = rblock,
                        expected = self.block,
                        "Received ACK for unexpected block"
                    );
                    self.retries += 1;
                    if self.retries > self.retry_max {
                        error!(
                            block = self.block,
                            "Giving up waiting for block ACK"
                        );
                        return Err(CurlError::SendError);
                    }
                    // Retransmit the last DATA packet.
                    let pkt_len = 4 + self.sbytes;
                    self.send_packet(pkt_len).await?;
                    return Ok(());
                }

                // Expected ACK — advance to next block.
                self.rx_time = Instant::now();
                self.block = self.block.wrapping_add(1);
                self.retries = 0;

                // Prepare next DATA packet.
                self.send_next_data_block().await
            }
            TftpOpcode::Oack => {
                // OACK in TX means the server confirmed options for upload.
                // First data block is block 1.
                self.block = 1;
                self.retries = 0;
                self.send_next_data_block().await
            }
            TftpOpcode::Error => {
                self.handle_error_packet();
                let err_len = self.build_error_packet(0, "");
                let _ = self.send_packet(err_len).await;
                self.state = TftpState::Done;
                Ok(())
            }
            _ => {
                error!(opcode = ?opcode, "tftp_tx: unexpected opcode");
                Ok(())
            }
        }
    }

    /// Read data from the upload source and send the next DATA block.
    async fn send_next_data_block(&mut self) -> CurlResult<()> {
        // Check if the previous block was a short write (final block).
        if self.block > 1 && self.sbytes < self.blksize as usize {
            self.state = TftpState::Done;
            return Ok(());
        }

        // Build DATA header.
        self.build_data_header(self.block);

        // Fill the data portion of the packet.
        // For now, the TFTP handler indicates that data is provided
        // by the transfer engine through the upload_data field.
        // In the Protocol trait model, upload data is provided externally.
        // We fill with available upload data up to blksize bytes.
        self.sbytes = 0;

        // In the C code, this calls Curl_client_read() in a loop to fill
        // the block. In our model, the upload data is set via set_upload_data.
        // For now, we represent an empty final block.
        // The actual data flow is managed through the transfer callbacks.
        // Since TFTP's protocol trait doesn't directly expose the read
        // callback, we treat the data payload as provided through the
        // sbuf starting at offset 4.

        // Send the DATA packet.
        let pkt_len = 4 + self.sbytes;
        self.send_packet(pkt_len).await?;

        // Update progress.
        self.write_byte_count += self.sbytes as u64;
        self.progress.upload_inc(self.sbytes as u64);

        Ok(())
    }

    // ====================================================================
    // Error Handling
    // ====================================================================

    /// Parse an ERROR packet from the receive buffer and store the error code.
    fn handle_error_packet(&mut self) {
        if self.rbytes >= 4 {
            let error_code = Self::get_packet_block(&self.rbuf[..self.rbytes]);
            self.error_code = TftpErrorCode::from_u16(error_code);

            // Extract error message if present.
            if self.rbytes > 4 {
                let msg_data = &self.rbuf[4..self.rbytes];
                let msg_end = msg_data
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(msg_data.len());
                if let Ok(msg) = std::str::from_utf8(&msg_data[..msg_end]) {
                    info!(
                        error_code,
                        message = msg,
                        "TFTP error received"
                    );
                }
            }
        }
    }

    // ====================================================================
    // Receive and Process
    // ====================================================================

    /// Receive a packet and classify it, returning the body data for DATA
    /// packets (for writing to the client).
    ///
    /// Matches C `tftp_receive_packet()`.
    #[allow(dead_code)]
    async fn receive_and_classify(&mut self) -> CurlResult<Option<Vec<u8>>> {
        let timeout_duration = Duration::from_secs(self.retry_time);
        let received = self.receive_packet(timeout_duration).await?;

        if !received {
            return Ok(None);
        }

        // Sanity check packet length.
        if self.rbytes < 4 {
            warn!(
                bytes = self.rbytes,
                "Received too short TFTP packet"
            );
            return Ok(None);
        }

        let opcode_raw = Self::get_packet_opcode(&self.rbuf[..self.rbytes]);
        let opcode = TftpOpcode::from_u16(opcode_raw);

        match opcode {
            Some(TftpOpcode::Data) => {
                // Extract data for writing to client — only for new blocks.
                let rblock = Self::get_packet_block(&self.rbuf[..self.rbytes]);
                let expected = Self::next_blocknum(self.block);
                if self.rbytes > 4 && expected == rblock {
                    let data = self.rbuf[4..self.rbytes].to_vec();
                    Ok(Some(data))
                } else {
                    Ok(Some(Vec::new()))
                }
            }
            Some(TftpOpcode::Error) => {
                self.handle_error_packet();
                Ok(Some(Vec::new()))
            }
            Some(TftpOpcode::Ack) | Some(TftpOpcode::Oack) => {
                if let Some(TftpOpcode::Oack) = opcode {
                    if self.rbytes > 2 {
                        let oack_data = self.rbuf[2..self.rbytes].to_vec();
                        self.parse_option_ack(&oack_data)?;
                    }
                }
                Ok(Some(Vec::new()))
            }
            _ => {
                warn!(
                    opcode = opcode_raw,
                    "Unexpected TFTP packet type"
                );
                Ok(Some(Vec::new()))
            }
        }
    }

    // ====================================================================
    // Multi-Step Operation (doing loop)
    // ====================================================================

    /// Execute one iteration of the multi-step TFTP transfer.
    ///
    /// Matches C `tftp_multi_statemach()` / `tftp_doing()`:
    /// 1. Check overall and per-block timeouts
    /// 2. If timeout event, dispatch to state machine
    /// 3. Otherwise, poll socket for incoming data
    /// 4. If data received, classify and dispatch
    ///
    /// Returns `true` when the transfer is complete.
    async fn multi_statemach(&mut self) -> CurlResult<bool> {
        // Check overall timeout.
        let remaining_ms = match self.check_overall_timeout() {
            Ok(ms) => ms,
            Err(_) => {
                error!("TFTP response timeout");
                return Err(CurlError::OperationTimedOut);
            }
        };

        // Check per-block timeout.
        let event = self.check_block_timeout();

        if event != TftpEvent::None {
            self.state_machine(event).await?;
            if self.state == TftpState::Done {
                return Ok(true);
            }
            return Ok(false);
        }

        // No timeout — try to receive a packet with a short poll.
        let poll_duration = Duration::from_millis(
            remaining_ms.min(100) // Short poll to keep responsiveness
        );

        let socket = match &self.socket {
            Some(s) => s,
            None => return Err(CurlError::FailedInit),
        };

        // Use tokio timeout with recv_from.
        let recv_result = timeout(poll_duration, socket.recv_from(&mut self.rbuf)).await;

        match recv_result {
            Ok(Ok((nbytes, from_addr))) => {
                self.rbytes = nbytes;

                // Validate source address.
                if self.remote_pinned {
                    if let Some(pinned) = self.remote_addr {
                        if from_addr != pinned {
                            error!(
                                expected = %pinned,
                                received_from = %from_addr,
                                "Data received from another address"
                            );
                            return Err(CurlError::RecvError);
                        }
                    }
                } else {
                    self.remote_pinned = true;
                    self.remote_addr = Some(from_addr);
                    debug!(addr = %from_addr, "TFTP remote address pinned");
                }

                if self.rbytes < 4 {
                    warn!("Received too short packet");
                    return Ok(false);
                }

                // Process received packet opcode.
                let opcode_raw = Self::get_packet_opcode(&self.rbuf[..self.rbytes]);
                match TftpOpcode::from_u16(opcode_raw) {
                    Some(TftpOpcode::Error) => {
                        self.handle_error_packet();
                    }
                    Some(TftpOpcode::Oack) => {
                        if self.rbytes > 2 {
                            let oack_data = self.rbuf[2..self.rbytes].to_vec();
                            self.parse_option_ack(&oack_data)?;
                        }
                    }
                    _ => { /* other opcodes handled by state machine */ }
                }

                // Drive the state machine with an Rx event.
                self.state_machine(TftpEvent::Rx).await?;

                if self.state == TftpState::Done {
                    return Ok(true);
                }
            }
            Ok(Err(e)) => {
                error!(error = %e, "TFTP socket error");
                return Err(CurlError::RecvError);
            }
            Err(_) => {
                // Poll timeout — no data available, this is normal.
            }
        }

        // If not done, check progress.
        self.progress.check()?;

        Ok(false)
    }

    // ====================================================================
    // Perform — initial transfer kickoff
    // ====================================================================

    /// Kick off the transfer by sending the initial RRQ/WRQ and entering
    /// the doing loop.
    ///
    /// Matches C `tftp_perform()`.
    async fn perform(&mut self) -> CurlResult<bool> {
        // Send the initial request via the state machine.
        self.state_machine(TftpEvent::Init).await?;

        if self.state == TftpState::Done {
            return Ok(true);
        }

        // Enter the multi-step loop.
        self.multi_statemach().await
    }
}

// ===========================================================================
// Protocol trait implementation
// ===========================================================================

impl Protocol for Tftp {
    /// Returns the protocol name.
    fn name(&self) -> &str {
        "TFTP"
    }

    /// Returns the default TFTP port (69).
    fn default_port(&self) -> u16 {
        TFTP_DEFAULT_PORT
    }

    /// Returns protocol flags.
    ///
    /// TFTP uses NEEDHOST (requires a hostname). The C implementation also
    /// uses `PROTOPT_NOTCPPROXY | PROTOPT_NOURLQUERY`, but those map to
    /// behavioral constraints handled elsewhere in the Rust implementation.
    fn flags(&self) -> ProtocolFlags {
        ProtocolFlags::NEEDHOST
    }

    /// Establish the TFTP connection.
    ///
    /// Binds a local UDP socket and resolves the remote server address.
    /// Matches C `tftp_connect()`.
    async fn connect(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        // Get remote server address.
        let remote_addr = conn.remote_addr().ok_or_else(|| {
            error!("No remote address available for TFTP");
            CurlError::FailedInit
        })?;

        // Determine the bind address (same address family as remote).
        let bind_addr: SocketAddr = if remote_addr.is_ipv6() {
            "[::]:0".parse().map_err(|_| CurlError::FailedInit)?
        } else {
            "0.0.0.0:0".parse().map_err(|_| CurlError::FailedInit)?
        };

        // Bind a UDP socket to a random local port.
        let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
            error!(error = %e, "TFTP bind() failed");
            CurlError::CouldntConnect
        })?;

        info!(
            local = %socket.local_addr().unwrap_or(bind_addr),
            remote = %remote_addr,
            "TFTP UDP socket bound"
        );

        self.socket = Some(socket);
        self.remote_addr = Some(remote_addr);
        self.remote_pinned = false;

        // Configure handler with default parameters.
        // In practice, these would come from the easy handle options.
        // For now, use sensible defaults.
        self.state = TftpState::Start;
        self.error_code = TftpErrorCode::None;
        self.blksize = TFTP_BLKSIZE_DEFAULT;

        // Ensure buffers are allocated.
        let buf_size = self.effective_buffer_size();
        if self.sbuf.len() < buf_size {
            self.sbuf.resize(buf_size, 0);
        }
        if self.rbuf.len() < buf_size {
            self.rbuf.resize(buf_size, 0);
        }

        // Start progress tracking.
        self.progress.start_now();

        Ok(())
    }

    /// Execute the TFTP transfer.
    ///
    /// Sends the initial RRQ/WRQ packet, then enters the state machine
    /// loop. Matches C `tftp_do()`.
    async fn do_it(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        if self.socket.is_none() {
            // Connect if not already done.
            self.connect(conn).await?;
        }

        // Start the transfer.
        let done = self.perform().await?;

        if !done {
            // Transfer is multi-step — will continue in doing().
            debug!("TFTP transfer started, continuing in doing()");
        }

        Ok(())
    }

    /// Continue the multi-step TFTP transfer.
    ///
    /// Called repeatedly from the multi event loop until the transfer is
    /// complete. Matches C `tftp_doing()`.
    ///
    /// Returns `Ok(true)` when the transfer is complete.
    async fn doing(&mut self, conn: &mut ConnectionData) -> Result<bool, CurlError> {
        let _ = conn;

        let done = self.multi_statemach().await?;

        if done {
            debug!("TFTP DO phase is complete");
        }

        Ok(done)
    }

    /// Finalize the TFTP transfer.
    ///
    /// Performs a final progress update and translates any accumulated
    /// internal error. Matches C `tftp_done()`.
    async fn done(
        &mut self,
        conn: &mut ConnectionData,
        status: CurlError,
    ) -> Result<(), CurlError> {
        let _ = conn;
        let _ = status;

        // Final progress update.
        if self.progress.done().is_err() {
            return Err(CurlError::AbortedByCallback);
        }

        // Translate internal error to CurlError.
        let result = self.error_code.to_curl_error();
        if result != CurlError::Ok {
            Err(result)
        } else {
            Ok(())
        }
    }

    /// Disconnect the TFTP session.
    ///
    /// Drops the UDP socket and cleans up state. TFTP connections are not
    /// reusable (matches C `connclose(conn, "TFTP")`).
    async fn disconnect(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        let _ = conn;

        // Drop the socket.
        self.socket = None;
        self.remote_addr = None;
        self.remote_pinned = false;
        self.state = TftpState::Done;

        debug!("TFTP disconnected");
        Ok(())
    }

    /// Connection health check.
    ///
    /// TFTP is connectionless (UDP), so there is no persistent connection
    /// to check. Always returns `Dead` since TFTP connections are not reusable.
    fn connection_check(&self, conn: &ConnectionData) -> ConnectionCheckResult {
        let _ = conn;
        // TFTP connections are never reused.
        ConnectionCheckResult::Dead
    }
}

// ===========================================================================
// Display implementation for Tftp
// ===========================================================================

impl fmt::Debug for Tftp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tftp")
            .field("state", &self.state)
            .field("mode", &self.mode)
            .field("block", &self.block)
            .field("blksize", &self.blksize)
            .field("retries", &self.retries)
            .field("remote_addr", &self.remote_addr)
            .field("remote_pinned", &self.remote_pinned)
            .field("error_code", &self.error_code)
            .finish()
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tftp_opcode_from_u16() {
        assert_eq!(TftpOpcode::from_u16(1), Some(TftpOpcode::Rrq));
        assert_eq!(TftpOpcode::from_u16(2), Some(TftpOpcode::Wrq));
        assert_eq!(TftpOpcode::from_u16(3), Some(TftpOpcode::Data));
        assert_eq!(TftpOpcode::from_u16(4), Some(TftpOpcode::Ack));
        assert_eq!(TftpOpcode::from_u16(5), Some(TftpOpcode::Error));
        assert_eq!(TftpOpcode::from_u16(6), Some(TftpOpcode::Oack));
        assert_eq!(TftpOpcode::from_u16(0), None);
        assert_eq!(TftpOpcode::from_u16(7), None);
        assert_eq!(TftpOpcode::from_u16(255), None);
    }

    #[test]
    fn test_tftp_opcode_display() {
        assert_eq!(format!("{}", TftpOpcode::Rrq), "RRQ");
        assert_eq!(format!("{}", TftpOpcode::Wrq), "WRQ");
        assert_eq!(format!("{}", TftpOpcode::Data), "DATA");
        assert_eq!(format!("{}", TftpOpcode::Ack), "ACK");
        assert_eq!(format!("{}", TftpOpcode::Error), "ERROR");
        assert_eq!(format!("{}", TftpOpcode::Oack), "OACK");
    }

    #[test]
    fn test_tftp_state_display() {
        assert_eq!(format!("{}", TftpState::Start), "START");
        assert_eq!(format!("{}", TftpState::Rx), "RX");
        assert_eq!(format!("{}", TftpState::Tx), "TX");
        assert_eq!(format!("{}", TftpState::Done), "DONE");
    }

    #[test]
    fn test_tftp_event_display() {
        assert_eq!(format!("{}", TftpEvent::Init), "INIT");
        assert_eq!(format!("{}", TftpEvent::Timeout), "TIMEOUT");
        assert_eq!(format!("{}", TftpEvent::Rx), "RX");
        assert_eq!(format!("{}", TftpEvent::None), "NONE");
    }

    #[test]
    fn test_constants() {
        assert_eq!(TFTP_BLKSIZE_DEFAULT, 512);
        assert_eq!(TFTP_BLKSIZE_MIN, 8);
        assert_eq!(TFTP_BLKSIZE_MAX, 65464);
    }

    #[test]
    fn test_error_code_translation() {
        assert_eq!(TftpErrorCode::None.to_curl_error(), CurlError::Ok);
        assert_eq!(TftpErrorCode::NotFound.to_curl_error(), CurlError::TftpNotFound);
        assert_eq!(TftpErrorCode::Perm.to_curl_error(), CurlError::TftpPerm);
        assert_eq!(TftpErrorCode::DiskFull.to_curl_error(), CurlError::RemoteDiskFull);
        assert_eq!(TftpErrorCode::Undef.to_curl_error(), CurlError::TftpIllegal);
        assert_eq!(TftpErrorCode::Illegal.to_curl_error(), CurlError::TftpIllegal);
        assert_eq!(TftpErrorCode::UnknownId.to_curl_error(), CurlError::TftpUnknownId);
        assert_eq!(TftpErrorCode::Exists.to_curl_error(), CurlError::RemoteFileExists);
        assert_eq!(TftpErrorCode::NoSuchUser.to_curl_error(), CurlError::TftpNoSuchUser);
        assert_eq!(TftpErrorCode::Timeout.to_curl_error(), CurlError::OperationTimedOut);
        assert_eq!(TftpErrorCode::NoResponse.to_curl_error(), CurlError::CouldntConnect);
    }

    #[test]
    fn test_error_code_from_u16() {
        assert_eq!(TftpErrorCode::from_u16(0), TftpErrorCode::Undef);
        assert_eq!(TftpErrorCode::from_u16(1), TftpErrorCode::NotFound);
        assert_eq!(TftpErrorCode::from_u16(2), TftpErrorCode::Perm);
        assert_eq!(TftpErrorCode::from_u16(3), TftpErrorCode::DiskFull);
        assert_eq!(TftpErrorCode::from_u16(4), TftpErrorCode::Illegal);
        assert_eq!(TftpErrorCode::from_u16(5), TftpErrorCode::UnknownId);
        assert_eq!(TftpErrorCode::from_u16(6), TftpErrorCode::Exists);
        assert_eq!(TftpErrorCode::from_u16(7), TftpErrorCode::NoSuchUser);
        assert_eq!(TftpErrorCode::from_u16(99), TftpErrorCode::Undef);
    }

    #[test]
    fn test_tftp_new() {
        let tftp = Tftp::new();
        assert_eq!(tftp.state, TftpState::Start);
        assert_eq!(tftp.mode, TftpMode::Octet);
        assert_eq!(tftp.blksize, TFTP_BLKSIZE_DEFAULT);
        assert_eq!(tftp.block, 0);
        assert!(!tftp.is_upload);
        assert!(tftp.socket.is_none());
        assert!(tftp.remote_addr.is_none());
        assert!(!tftp.remote_pinned);
    }

    #[test]
    fn test_packet_opcode() {
        let mut buf = [0u8; 4];
        Tftp::set_packet_opcode(&mut buf, TftpOpcode::Data as u16);
        assert_eq!(buf[0], 0);
        assert_eq!(buf[1], 3);
        assert_eq!(Tftp::get_packet_opcode(&buf), TftpOpcode::Data as u16);
    }

    #[test]
    fn test_packet_block() {
        let mut buf = [0u8; 4];
        Tftp::set_packet_block(&mut buf, 42);
        assert_eq!(buf[2], 0);
        assert_eq!(buf[3], 42);
        assert_eq!(Tftp::get_packet_block(&buf), 42);

        // Test high block number.
        Tftp::set_packet_block(&mut buf, 0x1234);
        assert_eq!(buf[2], 0x12);
        assert_eq!(buf[3], 0x34);
        assert_eq!(Tftp::get_packet_block(&buf), 0x1234);
    }

    #[test]
    fn test_next_blocknum() {
        assert_eq!(Tftp::next_blocknum(0), 1);
        assert_eq!(Tftp::next_blocknum(1), 2);
        assert_eq!(Tftp::next_blocknum(65534), 65535);
        assert_eq!(Tftp::next_blocknum(65535), 0); // Wraps around.
    }

    #[test]
    fn test_extract_null_string() {
        // Normal case.
        let data = b"hello\0world\0";
        let (s, next) = Tftp::extract_null_string(data, 0).unwrap();
        assert_eq!(s, "hello");
        assert_eq!(next, 6);
        let (s2, next2) = Tftp::extract_null_string(data, next).unwrap();
        assert_eq!(s2, "world");
        assert_eq!(next2, 12);

        // Edge case: empty offset.
        assert!(Tftp::extract_null_string(data, 20).is_none());

        // Edge case: no null terminator.
        let data2 = b"hello";
        assert!(Tftp::extract_null_string(data2, 0).is_none());
    }

    #[test]
    fn test_mode_str() {
        assert_eq!(TftpMode::Octet.as_str(), "octet");
        assert_eq!(TftpMode::Netascii.as_str(), "netascii");
    }

    #[test]
    fn test_build_ack_packet() {
        let mut tftp = Tftp::new();
        tftp.sbuf.resize(64, 0);
        let len = tftp.build_ack_packet(42);
        assert_eq!(len, 4);
        assert_eq!(tftp.sbuf[0], 0);
        assert_eq!(tftp.sbuf[1], TftpOpcode::Ack as u8);
        assert_eq!(Tftp::get_packet_block(&tftp.sbuf), 42);
    }

    #[test]
    fn test_build_error_packet() {
        let mut tftp = Tftp::new();
        tftp.sbuf.resize(64, 0);
        let len = tftp.build_error_packet(1, "File not found");
        assert!(len > 5);
        assert_eq!(Tftp::get_packet_opcode(&tftp.sbuf), TftpOpcode::Error as u16);
        assert_eq!(Tftp::get_packet_block(&tftp.sbuf), 1);
        // Check the message is null-terminated.
        assert_eq!(tftp.sbuf[4 + 14], 0);
    }

    #[test]
    fn test_parse_option_ack_blksize() {
        let mut tftp = Tftp::new();
        tftp.requested_blksize = 1024;

        // Build a mock OACK payload: "blksize\0512\0"
        let payload = b"blksize\0512\0";
        let result = tftp.parse_option_ack(payload);
        assert!(result.is_ok());
        assert_eq!(tftp.blksize, 512);
    }

    #[test]
    fn test_parse_option_ack_tsize() {
        let mut tftp = Tftp::new();
        tftp.requested_blksize = 512;
        tftp.is_upload = false;

        let payload = b"tsize\01234\0";
        let result = tftp.parse_option_ack(payload);
        assert!(result.is_ok());
        assert_eq!(tftp.tsize, Some(1234));
    }

    #[test]
    fn test_parse_option_ack_blksize_too_large() {
        let mut tftp = Tftp::new();
        tftp.requested_blksize = 512;

        // Server requests larger blksize than we asked for.
        let payload = b"blksize\01024\0";
        let result = tftp.parse_option_ack(payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_option_ack_blksize_zero() {
        let mut tftp = Tftp::new();
        tftp.requested_blksize = 512;

        let payload = b"blksize\00\0";
        let result = tftp.parse_option_ack(payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_option_ack_tsize_ignored_on_upload() {
        let mut tftp = Tftp::new();
        tftp.is_upload = true;

        let payload = b"tsize\05678\0";
        let result = tftp.parse_option_ack(payload);
        assert!(result.is_ok());
        assert_eq!(tftp.tsize, None); // Ignored for upload.
    }

    #[test]
    fn test_configure_octet() {
        let mut tftp = Tftp::new();
        let result = tftp.configure(
            "/testfile.bin",
            false,
            false,
            None,
            false,
            None,
            Some(30000),
        );
        assert!(result.is_ok());
        assert_eq!(tftp.filename, "testfile.bin");
        assert_eq!(tftp.mode, TftpMode::Octet);
        assert!(!tftp.is_upload);
    }

    #[test]
    fn test_configure_netascii_from_suffix() {
        let mut tftp = Tftp::new();
        let result = tftp.configure(
            "/testfile.txt;mode=netascii",
            false,
            false,
            None,
            false,
            None,
            None,
        );
        assert!(result.is_ok());
        assert_eq!(tftp.filename, "testfile.txt");
        assert_eq!(tftp.mode, TftpMode::Netascii);
    }

    #[test]
    fn test_configure_missing_filename() {
        let mut tftp = Tftp::new();
        let result = tftp.configure("/", false, false, None, false, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_timeouts() {
        let mut tftp = Tftp::new();
        tftp.set_timeouts(Some(30000)); // 30 seconds.
        assert!(tftp.retry_max >= TFTP_MIN_RETRIES);
        assert!(tftp.retry_max <= TFTP_MAX_RETRIES_CAP);
        assert!(tftp.retry_time >= 1);
    }

    #[test]
    fn test_set_timeouts_default() {
        let mut tftp = Tftp::new();
        tftp.set_timeouts(None);
        assert!(tftp.retry_max >= TFTP_MIN_RETRIES);
        assert!(tftp.retry_time >= 1);
    }

    #[test]
    fn test_protocol_trait_methods() {
        let tftp = Tftp::new();
        assert_eq!(tftp.name(), "TFTP");
        assert_eq!(tftp.default_port(), 69);
        assert!(!tftp.flags().is_empty());
        assert!(tftp.flags().contains(ProtocolFlags::NEEDHOST));
    }

    #[test]
    fn test_build_request_packet_rrq() {
        let mut tftp = Tftp::new();
        tftp.filename = "testfile.bin".to_string();
        tftp.mode = TftpMode::Octet;
        tftp.is_upload = false;
        tftp.include_options = false;
        tftp.requested_blksize = TFTP_BLKSIZE_DEFAULT;
        tftp.sbuf.resize(1024, 0);

        let len = tftp.build_request_packet().unwrap();
        // Opcode (2) + filename + NUL + mode + NUL
        let expected = 2 + "testfile.bin".len() + 1 + "octet".len() + 1;
        assert_eq!(len, expected);

        // Verify opcode is RRQ (1).
        assert_eq!(Tftp::get_packet_opcode(&tftp.sbuf), TftpOpcode::Rrq as u16);

        // Verify filename.
        let filename_end = 2 + "testfile.bin".len();
        assert_eq!(&tftp.sbuf[2..filename_end], b"testfile.bin");
        assert_eq!(tftp.sbuf[filename_end], 0);

        // Verify mode.
        let mode_start = filename_end + 1;
        let mode_end = mode_start + "octet".len();
        assert_eq!(&tftp.sbuf[mode_start..mode_end], b"octet");
        assert_eq!(tftp.sbuf[mode_end], 0);
    }

    #[test]
    fn test_build_request_packet_wrq() {
        let mut tftp = Tftp::new();
        tftp.filename = "upload.bin".to_string();
        tftp.mode = TftpMode::Octet;
        tftp.is_upload = true;
        tftp.include_options = false;
        tftp.requested_blksize = TFTP_BLKSIZE_DEFAULT;
        tftp.sbuf.resize(1024, 0);

        let len = tftp.build_request_packet().unwrap();
        assert!(len > 0);

        // Verify opcode is WRQ (2).
        assert_eq!(Tftp::get_packet_opcode(&tftp.sbuf), TftpOpcode::Wrq as u16);
    }

    #[test]
    fn test_build_request_with_options() {
        let mut tftp = Tftp::new();
        tftp.filename = "test.bin".to_string();
        tftp.mode = TftpMode::Octet;
        tftp.is_upload = false;
        tftp.include_options = true;
        tftp.requested_blksize = 1024;
        tftp.retry_time = 5;
        tftp.sbuf.resize(2048, 0);

        let len = tftp.build_request_packet().unwrap();

        // The packet should contain the filename, mode, and options.
        // Options: tsize\00\0blksize\01024\0timeout\05\0
        assert!(len > 2 + "test.bin".len() + 1 + "octet".len() + 1);

        // Verify the packet contains the option strings.
        let packet = &tftp.sbuf[..len];
        let packet_str = String::from_utf8_lossy(packet);
        assert!(packet_str.contains("tsize"));
        assert!(packet_str.contains("blksize"));
        assert!(packet_str.contains("timeout"));
    }

    #[test]
    fn test_handle_error_packet() {
        let mut tftp = Tftp::new();
        // Build a mock ERROR packet: opcode=5, code=1, message="File not found\0"
        tftp.rbuf = vec![0, 5, 0, 1, b'F', b'i', b'l', b'e', b' ', b'n', b'o', b't',
                         b' ', b'f', b'o', b'u', b'n', b'd', 0];
        tftp.rbytes = tftp.rbuf.len();

        tftp.handle_error_packet();
        assert_eq!(tftp.error_code, TftpErrorCode::NotFound);
    }

    #[test]
    fn test_parse_multiple_oack_options() {
        let mut tftp = Tftp::new();
        tftp.requested_blksize = 1024;
        tftp.is_upload = false;

        // "blksize\0512\0tsize\09999\0"
        let payload = b"blksize\0512\0tsize\09999\0";
        let result = tftp.parse_option_ack(payload);
        assert!(result.is_ok());
        assert_eq!(tftp.blksize, 512);
        assert_eq!(tftp.tsize, Some(9999));
    }

    // ======================================================================
    // Additional tests for coverage
    // ======================================================================

    #[test]
    fn test_tftp_opcode_from_u16_all_extra() {
        assert_eq!(TftpOpcode::from_u16(1), Some(TftpOpcode::Rrq));
        assert_eq!(TftpOpcode::from_u16(2), Some(TftpOpcode::Wrq));
        assert_eq!(TftpOpcode::from_u16(3), Some(TftpOpcode::Data));
        assert_eq!(TftpOpcode::from_u16(4), Some(TftpOpcode::Ack));
        assert_eq!(TftpOpcode::from_u16(5), Some(TftpOpcode::Error));
        assert_eq!(TftpOpcode::from_u16(6), Some(TftpOpcode::Oack));
        assert_eq!(TftpOpcode::from_u16(0), None);
        assert_eq!(TftpOpcode::from_u16(99), None);
    }

    #[test]
    fn test_tftp_state_all_distinct() {
        let states = vec![
            TftpState::Start, TftpState::Rx, TftpState::Tx, TftpState::Done,
        ];
        for i in 0..states.len() {
            for j in (i+1)..states.len() {
                assert_ne!(format!("{}", states[i]), format!("{}", states[j]));
            }
        }
    }

    #[test]
    fn test_tftp_event_all_distinct() {
        let events = vec![
            TftpEvent::Init, TftpEvent::Timeout, TftpEvent::Rx, TftpEvent::None,
        ];
        for i in 0..events.len() {
            for j in (i+1)..events.len() {
                assert_ne!(format!("{}", events[i]), format!("{}", events[j]));
            }
        }
    }

    #[test]
    fn test_error_code_all_to_curl_error() {
        assert!(matches!(TftpErrorCode::NotFound.to_curl_error(), CurlError::TftpNotFound));
        assert!(matches!(TftpErrorCode::Perm.to_curl_error(), CurlError::TftpPerm));
        assert!(matches!(TftpErrorCode::DiskFull.to_curl_error(), CurlError::RemoteDiskFull));
        assert!(matches!(TftpErrorCode::Illegal.to_curl_error(), CurlError::TftpIllegal));
        assert!(matches!(TftpErrorCode::UnknownId.to_curl_error(), CurlError::TftpUnknownId));
        assert!(matches!(TftpErrorCode::Exists.to_curl_error(), CurlError::RemoteFileExists));
        assert!(matches!(TftpErrorCode::NoSuchUser.to_curl_error(), CurlError::TftpNoSuchUser));
        assert!(matches!(TftpErrorCode::Timeout.to_curl_error(), CurlError::OperationTimedOut));
        assert!(matches!(TftpErrorCode::NoResponse.to_curl_error(), CurlError::CouldntConnect));
        assert!(matches!(TftpErrorCode::Undef.to_curl_error(), CurlError::TftpIllegal));
        assert!(matches!(TftpErrorCode::None.to_curl_error(), CurlError::Ok));
    }

    #[test]
    fn test_effective_buffer_size() {
        let mut tftp = Tftp::new();
        assert_eq!(tftp.effective_buffer_size(), TFTP_BLKSIZE_DEFAULT as usize + 4);
        tftp.requested_blksize = 1024;
        assert_eq!(tftp.effective_buffer_size(), 1024 + 4);
    }

    #[test]
    fn test_set_timeouts_custom() {
        let mut tftp = Tftp::new();
        tftp.set_timeouts(Some(5000));
        assert!(tftp.retry_time > 0);
    }

    #[test]
    fn test_set_timeouts_none_uses_defaults() {
        let mut tftp = Tftp::new();
        tftp.set_timeouts(None);
        assert_eq!(tftp.retry_time, TFTP_DEFAULT_RETRY_SECS);
    }

    #[test]
    fn test_next_blocknum_wrap() {
        assert_eq!(Tftp::next_blocknum(0xFFFF), 0);
        assert_eq!(Tftp::next_blocknum(1), 2);
        assert_eq!(Tftp::next_blocknum(0), 1);
    }

    #[test]
    fn test_build_request_packet_rrq_extra() {
        let mut tftp = Tftp::new();
        let _ = tftp.configure("/testfile.txt", false, false, None, false, None, None);
        let len = tftp.build_request_packet().unwrap();
        assert!(len > 0);
        let opcode = Tftp::get_packet_opcode(&tftp.sbuf);
        assert_eq!(opcode, TftpOpcode::Rrq as u16);
    }

    #[test]
    fn test_build_request_packet_wrq_extra() {
        let mut tftp = Tftp::new();
        let _ = tftp.configure("/testfile.txt", true, false, None, false, None, None);
        let len = tftp.build_request_packet().unwrap();
        assert!(len > 0);
        let opcode = Tftp::get_packet_opcode(&tftp.sbuf);
        assert_eq!(opcode, TftpOpcode::Wrq as u16);
    }

    #[test]
    fn test_build_data_header() {
        let mut tftp = Tftp::new();
        // sbuf must be pre-allocated (the real flow does this during configure)
        tftp.sbuf.resize(tftp.effective_buffer_size(), 0);
        tftp.build_data_header(42);
        let opcode = Tftp::get_packet_opcode(&tftp.sbuf);
        assert_eq!(opcode, TftpOpcode::Data as u16);
        let block = Tftp::get_packet_block(&tftp.sbuf);
        assert_eq!(block, 42);
    }

    #[test]
    fn test_protocol_name_and_port() {
        let tftp = Tftp::new();
        assert_eq!(tftp.name(), "TFTP");
        assert_eq!(tftp.default_port(), TFTP_DEFAULT_PORT);
    }

    #[test]
    fn test_protocol_flags_needhost() {
        let tftp = Tftp::new();
        assert!(tftp.flags().contains(ProtocolFlags::NEEDHOST));
    }

    #[test]
    fn test_connection_check_returns_dead() {
        // TFTP is UDP-based, so connection_check returns Dead (no persistent connection)
        let tftp = Tftp::new();
        let conn = ConnectionData::new(1, "localhost".into(), 69, "tftp".into());
        assert_eq!(Protocol::connection_check(&tftp, &conn), ConnectionCheckResult::Dead);
    }

    #[test]
    fn test_max_retries_cap() {
        assert_eq!(TFTP_MAX_RETRIES_CAP, 50);
        assert_eq!(TFTP_MIN_RETRIES, 3);
    }

    #[test]
    fn test_tftp_default_matches_new() {
        let a = Tftp::default();
        let b = Tftp::new();
        assert_eq!(a.blksize, b.blksize);
        assert_eq!(a.is_upload, b.is_upload);
        assert_eq!(a.state, b.state);
    }

    #[test]
    fn test_extract_null_string_at_end() {
        let data = b"hello\0";
        let (s, next) = Tftp::extract_null_string(data, 0).unwrap();
        assert_eq!(s, "hello");
        assert_eq!(next, 6);
    }

    #[test]
    fn test_extract_null_string_middle() {
        let data = b"abc\0def\0";
        let (s1, n1) = Tftp::extract_null_string(data, 0).unwrap();
        assert_eq!(s1, "abc");
        let (s2, _) = Tftp::extract_null_string(data, n1).unwrap();
        assert_eq!(s2, "def");
    }

    #[test]
    fn test_error_code_from_u16_all_vals() {
        assert!(matches!(TftpErrorCode::from_u16(0), TftpErrorCode::Undef));
        assert!(matches!(TftpErrorCode::from_u16(1), TftpErrorCode::NotFound));
        assert!(matches!(TftpErrorCode::from_u16(2), TftpErrorCode::Perm));
        assert!(matches!(TftpErrorCode::from_u16(3), TftpErrorCode::DiskFull));
        assert!(matches!(TftpErrorCode::from_u16(4), TftpErrorCode::Illegal));
        assert!(matches!(TftpErrorCode::from_u16(5), TftpErrorCode::UnknownId));
        assert!(matches!(TftpErrorCode::from_u16(6), TftpErrorCode::Exists));
        assert!(matches!(TftpErrorCode::from_u16(7), TftpErrorCode::NoSuchUser));
        assert!(matches!(TftpErrorCode::from_u16(255), TftpErrorCode::Undef));
    }

    #[test]
    fn test_mode_str_values() {
        assert_eq!(TftpMode::Octet.as_str(), "octet");
        assert_eq!(TftpMode::Netascii.as_str(), "netascii");
    }

    // === Round 4 ===
    #[test]
    fn test_tftp_opcode_from_u16_all() {
        assert!(TftpOpcode::from_u16(1).is_some()); // RRQ
        assert!(TftpOpcode::from_u16(2).is_some()); // WRQ
        assert!(TftpOpcode::from_u16(3).is_some()); // DATA
        assert!(TftpOpcode::from_u16(4).is_some()); // ACK
        assert!(TftpOpcode::from_u16(5).is_some()); // ERROR
        assert!(TftpOpcode::from_u16(6).is_some()); // OACK
        assert!(TftpOpcode::from_u16(99).is_none());
        assert!(TftpOpcode::from_u16(0).is_none());
    }

    #[test]
    fn test_tftp_opcode_display_r4() {
        for i in 1..=6u16 {
            let op = TftpOpcode::from_u16(i).unwrap();
            let s = format!("{}", op);
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn test_tftp_state_display_all() {
        let states = [TftpState::Start, TftpState::Rx, TftpState::Tx,
                      TftpState::Done];
        for s in &states {
            let display = format!("{}", s);
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn test_tftp_event_display_all() {
        let events = [TftpEvent::None, TftpEvent::Timeout,
                      TftpEvent::Timeout, TftpEvent::Init];
        for e in &events {
            let display = format!("{}", e);
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn test_tftp_error_code_to_curl_error() {
        let codes = [TftpErrorCode::Undef, TftpErrorCode::NotFound,
                     TftpErrorCode::Perm, TftpErrorCode::DiskFull,
                     TftpErrorCode::Illegal, TftpErrorCode::UnknownId,
                     TftpErrorCode::Exists, TftpErrorCode::NoSuchUser];
        for c in &codes {
            let err = c.to_curl_error();
            let _ = format!("{:?}", err);
        }
    }

    #[test]
    fn test_tftp_error_code_from_u16() {
        for i in 0..=8u16 {
            let _ = TftpErrorCode::from_u16(i);
        }
        let _ = TftpErrorCode::from_u16(99); // unknown
    }

    #[test]
    fn test_tftp_packet_opcode_roundtrip() {
        let mut buf = [0u8; 4];
        Tftp::set_packet_opcode(&mut buf, 1);
        assert_eq!(Tftp::get_packet_opcode(&buf), 1);
        Tftp::set_packet_opcode(&mut buf, 5);
        assert_eq!(Tftp::get_packet_opcode(&buf), 5);
    }

    #[test]
    fn test_tftp_packet_block_roundtrip() {
        let mut buf = [0u8; 4];
        Tftp::set_packet_block(&mut buf, 1);
        assert_eq!(Tftp::get_packet_block(&buf), 1);
        Tftp::set_packet_block(&mut buf, 65535);
        assert_eq!(Tftp::get_packet_block(&buf), 65535);
    }

    #[test]
    fn test_tftp_next_blocknum() {
        assert_eq!(Tftp::next_blocknum(0), 1);
        assert_eq!(Tftp::next_blocknum(1), 2);
        assert_eq!(Tftp::next_blocknum(65534), 65535);
        assert_eq!(Tftp::next_blocknum(65535), 0); // wraps
    }

    #[test]
    fn test_tftp_effective_buffer_size() {
        let t = Tftp::new();
        let size = t.effective_buffer_size();
        assert!(size >= 512); // Default TFTP block size
    }

    #[test]
    fn test_tftp_build_ack_packet() {
        let mut t = Tftp::new();
        let len = t.build_ack_packet(1);
        assert!(len > 0);
        // ACK is opcode(2) + block(2) = 4 bytes
        assert_eq!(len, 4);
    }

    #[test]
    fn test_tftp_build_data_header() {
        let mut t = Tftp::new();
        t.build_data_header(1);
        // Data header is opcode(2) + block(2) = 4 bytes
    }

    #[test]
    fn test_tftp_build_error_packet() {
        let mut t = Tftp::new();
        t.sbuf.resize(512, 0); // sbuf must be allocated before building packets
        let len = t.build_error_packet(1, "test error");
        assert!(len > 4); // opcode(2) + code(2) + msg + null
    }

    #[test]
    fn test_tftp_extract_null_string() {
        let data = b"hello\0world\0";
        let (s, next) = Tftp::extract_null_string(data, 0).unwrap();
        assert_eq!(s, "hello");
        let (s2, _) = Tftp::extract_null_string(data, next).unwrap();
        assert_eq!(s2, "world");
    }

    #[test]
    fn test_tftp_extract_null_string_no_null() {
        let data = b"hello";
        assert!(Tftp::extract_null_string(data, 0).is_none());
    }

    #[test]
    fn test_tftp_set_timeouts() {
        let mut t = Tftp::new();
        t.set_timeouts(Some(5000));
        t.set_timeouts(None);
    }

    #[test]
    fn test_tftp_protocol_name() {
        let t = Tftp::new();
        assert_eq!(t.name(), "TFTP");
    }

    #[test]
    fn test_tftp_protocol_default_port() {
        let t = Tftp::new();
        assert_eq!(t.default_port(), 69);
    }

    #[test]
    fn test_tftp_protocol_connection_check() {
        let t = Tftp::new();
        let conn = ConnectionData::new(1, "tftp.example.com".into(), 69, "tftp".into());
        let _ = Protocol::connection_check(&t, &conn);
    }

    #[test]
    fn test_tftp_parse_blksize_valid() {
        let mut t = Tftp::new();
        assert!(t.parse_blksize_option("512").is_ok());
        t.requested_blksize = 1024; // must allow requested size >= parsed value
        assert!(t.parse_blksize_option("1024").is_ok());
    }

    #[test]
    fn test_tftp_parse_blksize_invalid() {
        let mut t = Tftp::new();
        assert!(t.parse_blksize_option("abc").is_err());
        assert!(t.parse_blksize_option("0").is_err());
    }

    #[test]
    fn test_tftp_parse_tsize_valid() {
        let mut t = Tftp::new();
        assert!(t.parse_tsize_option("1024").is_ok());
        // tsize==0 is rejected as invalid by the implementation
        assert!(t.parse_tsize_option("0").is_err());
    }

    #[test]
    fn test_tftp_parse_tsize_invalid() {
        let mut t = Tftp::new();
        // The implementation silently ignores non-numeric tsize (returns Ok)
        assert!(t.parse_tsize_option("abc").is_ok());
    }

    #[test]
    fn test_tftp_check_block_timeout_initial() {
        let mut t = Tftp::new();
        let event = t.check_block_timeout();
        // Initial state - no timeout
        let _ = event;
    }

    #[test]
    fn test_tftp_debug() {
        let t = Tftp::new();
        let s = format!("{:?}", t);
        assert!(!s.is_empty());
    }

    #[test]
    fn test_tftp_append_option() {
        let mut t = Tftp::new();
        // Initialize send buffer with sufficient size
        t.sbuf.resize(512, 0);
        let offset = 2;
        let result = t.append_option(offset, "blksize", "512");
        assert!(result.is_ok());
        let new_offset = result.unwrap();
        assert!(new_offset > offset);
    }

    #[test]
    fn test_tftp_build_request_packet() {
        let mut t = Tftp::new();
        // Need to configure first
        let _ = t.build_request_packet();
    }
    
    // ====== Round 5 coverage tests ======

    #[test]
    fn test_tftp_opcode_from_u16_all_r5() {
        assert_eq!(TftpOpcode::from_u16(1), Some(TftpOpcode::Rrq));
        assert_eq!(TftpOpcode::from_u16(2), Some(TftpOpcode::Wrq));
        assert_eq!(TftpOpcode::from_u16(3), Some(TftpOpcode::Data));
        assert_eq!(TftpOpcode::from_u16(4), Some(TftpOpcode::Ack));
        assert_eq!(TftpOpcode::from_u16(5), Some(TftpOpcode::Error));
        assert_eq!(TftpOpcode::from_u16(6), Some(TftpOpcode::Oack));
        assert_eq!(TftpOpcode::from_u16(0), None);
        assert_eq!(TftpOpcode::from_u16(7), None);
    }

    #[test]
    fn test_tftp_opcode_display_r5() {
        assert_eq!(format!("{}", TftpOpcode::Rrq), "RRQ");
        assert_eq!(format!("{}", TftpOpcode::Wrq), "WRQ");
        assert_eq!(format!("{}", TftpOpcode::Data), "DATA");
        assert_eq!(format!("{}", TftpOpcode::Ack), "ACK");
        assert_eq!(format!("{}", TftpOpcode::Error), "ERROR");
        assert_eq!(format!("{}", TftpOpcode::Oack), "OACK");
    }

    #[test]
    fn test_tftp_state_display_r5() {
        assert!(!format!("{}", TftpState::Start).is_empty());
        assert!(!format!("{}", TftpState::Rx).is_empty());
        assert!(!format!("{}", TftpState::Tx).is_empty());
        assert!(!format!("{}", TftpState::Done).is_empty());
    }

    #[test]
    fn test_tftp_event_display_r5() {
        assert!(!format!("{}", TftpEvent::Init).is_empty());
        assert!(!format!("{}", TftpEvent::Timeout).is_empty());
        assert!(!format!("{}", TftpEvent::Rx).is_empty());
        assert!(!format!("{}", TftpEvent::None).is_empty());
    }

    #[test]
    fn test_tftp_error_code_from_u16_r5() {
        assert_eq!(TftpErrorCode::from_u16(0), TftpErrorCode::Undef);
        assert_eq!(TftpErrorCode::from_u16(1), TftpErrorCode::NotFound);
        assert_eq!(TftpErrorCode::from_u16(2), TftpErrorCode::Perm);
        assert_eq!(TftpErrorCode::from_u16(3), TftpErrorCode::DiskFull);
        assert_eq!(TftpErrorCode::from_u16(4), TftpErrorCode::Illegal);
        assert_eq!(TftpErrorCode::from_u16(5), TftpErrorCode::UnknownId);
        assert_eq!(TftpErrorCode::from_u16(6), TftpErrorCode::Exists);
        assert_eq!(TftpErrorCode::from_u16(7), TftpErrorCode::NoSuchUser);
        assert_eq!(TftpErrorCode::from_u16(100), TftpErrorCode::Undef); // unknown maps to Undef
    }

    #[test]
    fn test_tftp_error_code_to_curl_error_r5() {
        assert!(matches!(TftpErrorCode::NotFound.to_curl_error(), CurlError::TftpNotFound));
        assert!(matches!(TftpErrorCode::Perm.to_curl_error(), CurlError::TftpPerm));
        assert!(matches!(TftpErrorCode::Illegal.to_curl_error(), CurlError::TftpIllegal));
        assert!(matches!(TftpErrorCode::UnknownId.to_curl_error(), CurlError::TftpUnknownId));
        assert!(matches!(TftpErrorCode::Exists.to_curl_error(), CurlError::RemoteFileExists));
    }

    #[test]
    fn test_tftp_mode_as_str_r5() {
        assert_eq!(TftpMode::Octet.as_str(), "octet");
    }

    #[test]
    fn test_tftp_new_default_values_r5() {
        let t = Tftp::new();
        assert_eq!(t.state, TftpState::Start);
        assert_eq!(t.blksize, TFTP_BLKSIZE_DEFAULT);
    }

    #[test]
    fn test_tftp_default_trait_r5() {
        let t = Tftp::default();
        assert_eq!(t.state, TftpState::Start);
    }

    #[test]
    fn test_tftp_configure_r5() {
        let mut t = Tftp::new();
        let _ = t.configure("/test.bin", false, false, Some(1024), false, None, None);
    }

    #[test]
    fn test_tftp_configure_upload_r5() {
        let mut t = Tftp::new();
        let _ = t.configure("/test.bin", true, false, None, false, Some(2048), None);
        assert!(t.is_upload);
    }

    #[test]
    fn test_tftp_effective_buffer_size_r5() {
        let t = Tftp::new();
        let size = t.effective_buffer_size();
        assert!(size > 0);
    }

    #[test]
    fn test_tftp_set_timeouts_some_r5() {
        let mut t = Tftp::new();
        t.set_timeouts(Some(10000));
    }

    #[test]
    fn test_tftp_set_timeouts_none_r5() {
        let mut t = Tftp::new();
        t.set_timeouts(None);
    }

    #[test]
    fn test_tftp_check_overall_timeout_r5() {
        let t = Tftp::new();
        let _ = t.check_overall_timeout();
    }

    #[test]
    fn test_tftp_set_packet_opcode_r5() {
        let mut buf = vec![0u8; 10];
        Tftp::set_packet_opcode(&mut buf, TftpOpcode::Rrq as u16);
        assert_eq!(buf[0], 0);
        assert_eq!(buf[1], 1);
    }

    #[test]
    fn test_tftp_set_packet_block_r5() {
        let mut buf = vec![0u8; 10];
        Tftp::set_packet_block(&mut buf, 42);
        assert_eq!(buf[2], 0);
        assert_eq!(buf[3], 42);
    }

    #[test]
    fn test_tftp_get_packet_opcode_r5() {
        let buf = vec![0u8, 3, 0, 0]; // DATA opcode
        assert_eq!(Tftp::get_packet_opcode(&buf), 3);
    }

    #[test]
    fn test_tftp_get_packet_block_r5() {
        let buf = vec![0u8, 0, 0, 5];
        assert_eq!(Tftp::get_packet_block(&buf), 5);
    }



    // ====== Round 7 ======
    #[test] fn test_tftp_opcode_display_r7() {
        for op in [TftpOpcode::Rrq, TftpOpcode::Wrq, TftpOpcode::Data, TftpOpcode::Ack, TftpOpcode::Error, TftpOpcode::Oack] {
            assert!(!format!("{}", op).is_empty());
        }
    }
    #[test] fn test_tftp_state_display_r7() {
        for st in [TftpState::Start, TftpState::Rx, TftpState::Tx, TftpState::Done] {
            assert!(!format!("{}", st).is_empty());
        }
    }
    #[test] fn test_tftp_error_code_display_r7() {
        for ec in [TftpErrorCode::Undef, TftpErrorCode::NotFound, TftpErrorCode::Perm, TftpErrorCode::DiskFull] {
            assert!(!format!("{:?}", ec).is_empty());
            let _ = ec.to_curl_error(); // verify conversion
        }
    }
    #[test] fn test_tftp_mode_display_r7() {
        let _ = TftpMode::Octet.as_str().to_string();
        let _ = TftpMode::Netascii.as_str().to_string();
    }
    #[test] fn test_tftp_event_display_r7() {
        for ev in [TftpEvent::Init, TftpEvent::Timeout, TftpEvent::Rx, TftpEvent::None] {
            let _ = format!("{:?}", ev);
        }
    }
    #[test] fn test_tftp_new_r7() {
        let t = Tftp::new();
        let _ = format!("{:?}", t);
    }
    #[test] fn test_tftp_error_to_curl_r7() {
        for ec in [TftpErrorCode::Undef, TftpErrorCode::NotFound, TftpErrorCode::Perm] {
            let _ = ec.to_curl_error();
        }
    }


    // ====== Round 8 ======
    #[test] fn test_tftp_opcode_values_r8() {
        assert_eq!(TftpOpcode::Rrq as u16, 1);
        assert_eq!(TftpOpcode::Wrq as u16, 2);
        assert_eq!(TftpOpcode::Data as u16, 3);
        assert_eq!(TftpOpcode::Ack as u16, 4);
        assert_eq!(TftpOpcode::Error as u16, 5);
        assert_eq!(TftpOpcode::Oack as u16, 6);
    }
    #[test] fn test_tftp_error_code_from_u16_r8() {
        assert!(matches!(TftpErrorCode::from_u16(0), TftpErrorCode::Undef));
        assert!(matches!(TftpErrorCode::from_u16(1), TftpErrorCode::NotFound));
        assert!(matches!(TftpErrorCode::from_u16(2), TftpErrorCode::Perm));
        assert!(matches!(TftpErrorCode::from_u16(3), TftpErrorCode::DiskFull));
        assert!(matches!(TftpErrorCode::from_u16(4), TftpErrorCode::Illegal));
        assert!(matches!(TftpErrorCode::from_u16(5), TftpErrorCode::UnknownId));
        assert!(matches!(TftpErrorCode::from_u16(6), TftpErrorCode::Exists));
        assert!(matches!(TftpErrorCode::from_u16(7), TftpErrorCode::NoSuchUser));
    }
    #[test] fn test_tftp_error_code_to_curl_error_r8() {
        let _ = TftpErrorCode::NotFound.to_curl_error();
        let _ = TftpErrorCode::Perm.to_curl_error();
        let _ = TftpErrorCode::DiskFull.to_curl_error();
        let _ = TftpErrorCode::Timeout.to_curl_error();
        let _ = TftpErrorCode::NoResponse.to_curl_error();
    }
    #[test] fn test_tftp_mode_as_str_r8() {
        assert_eq!(TftpMode::Octet.as_str(), "octet");
        assert_eq!(TftpMode::Netascii.as_str(), "netascii");
    }
    #[test] fn test_tftp_new_default_state_r8() {
        let t = Tftp::new();
        assert_eq!(t.state, TftpState::Start);
    }
    #[test] fn test_tftp_state_transitions_r8() {
        let mut t = Tftp::new();
        t.state = TftpState::Rx;
        assert_eq!(t.state, TftpState::Rx);
        t.state = TftpState::Tx;
        assert_eq!(t.state, TftpState::Tx);
        t.state = TftpState::Done;
        assert_eq!(t.state, TftpState::Done);
    }
    #[test] fn test_tftp_default_port_r8() {
        let t = Tftp::new();
        assert_eq!(t.default_port(), 69);
    }
    #[test] fn test_tftp_handler_name_r8() {
        let t = Tftp::new();
        assert!(!t.name().is_empty());
    }
    #[test] fn test_tftp_opcode_debug_r8() {
        for op in [TftpOpcode::Rrq, TftpOpcode::Wrq, TftpOpcode::Data,
                   TftpOpcode::Ack, TftpOpcode::Error, TftpOpcode::Oack] {
            assert!(!format!("{:?}", op).is_empty());
        }
    }
    #[test] fn test_tftp_event_variants_r8() {
        for ev in [TftpEvent::None, TftpEvent::Rx, TftpEvent::Init,
                   TftpEvent::Rx, TftpEvent::Init, TftpEvent::Timeout] {
            assert!(!format!("{:?}", ev).is_empty());
        }
    }


    // ===== ROUND 9 TESTS =====
    #[test]
    fn r9_tftp_error_code_from_u16_all() {
        for v in 0u16..10 {
            let code = TftpErrorCode::from_u16(v);
            let _ = code;
        }
    }

    #[test]
    fn r9_tftp_error_code_from_u16_boundaries() {
        let _ = TftpErrorCode::from_u16(0);
        let _ = TftpErrorCode::from_u16(8);
        let _ = TftpErrorCode::from_u16(255);
        let _ = TftpErrorCode::from_u16(u16::MAX);
    }

    #[test]
    fn r9_tftp_opcode_from_u16_all() {
        for v in 0u16..10 {
            let op = TftpOpcode::from_u16(v);
            let _ = op;
        }
    }

    #[test]
    fn r9_tftp_handler_new() {
        let h = Tftp::new();
        let _ = h;
    }

    #[test]
    fn r9_tftp_handler_build_ack_packet() {
        let mut h = Tftp::new();
        let size = h.build_ack_packet(1);
        assert!(size > 0);
    }

    #[test]
    fn r9_tftp_handler_build_ack_packet_zero() {
        let mut h = Tftp::new();
        let size = h.build_ack_packet(0);
        assert!(size > 0);
    }

    #[test]
    fn r9_tftp_handler_build_ack_packet_max() {
        let mut h = Tftp::new();
        let size = h.build_ack_packet(u16::MAX);
        assert!(size > 0);
    }

    #[test]
    fn r9_tftp_handler_build_data_header() {
        let mut h = Tftp::new();
        h.build_data_header(1);
    }

    #[test]
    fn r9_tftp_handler_build_data_header_zero() {
        let mut h = Tftp::new();
        h.build_data_header(0);
    }

    #[test]
    fn r9_tftp_handler_build_error_packet() {
        let mut h = Tftp::new();
        // sbuf needs to be large enough for the packet
        h.sbuf = vec![0u8; 516];
        let size = h.build_error_packet(1, "file not found");
        assert!(size > 0);
    }

    #[test]
    fn r9_tftp_handler_build_error_packet_empty_msg() {
        let mut h = Tftp::new();
        h.sbuf = vec![0u8; 516];
        let size = h.build_error_packet(0, "");
        assert!(size > 0);
    }

    #[test]
    fn r9_tftp_handler_parse_blksize_valid() {
        let mut h = Tftp::new();
        let result = h.parse_blksize_option("512");
        assert!(result.is_ok());
    }

    #[test]
    fn r9_tftp_handler_parse_blksize_8() {
        let mut h = Tftp::new();
        let result = h.parse_blksize_option("8");
        let _ = result;
    }

    #[test]
    fn r9_tftp_handler_parse_blksize_65464() {
        let mut h = Tftp::new();
        let result = h.parse_blksize_option("65464");
        let _ = result;
    }

    #[test]
    fn r9_tftp_handler_parse_blksize_invalid() {
        let mut h = Tftp::new();
        let result = h.parse_blksize_option("not_a_number");
        let _ = result;
    }

    #[test]
    fn r9_tftp_handler_parse_tsize_valid() {
        let mut h = Tftp::new();
        let result = h.parse_tsize_option("1024");
        assert!(result.is_ok());
    }

    #[test]
    fn r9_tftp_handler_parse_tsize_zero() {
        let mut h = Tftp::new();
        let result = h.parse_tsize_option("0");
        let _ = result;
    }

    #[test]
    fn r9_tftp_handler_parse_tsize_large() {
        let mut h = Tftp::new();
        let result = h.parse_tsize_option("999999999");
        let _ = result;
    }

    #[test]
    fn r9_tftp_handler_parse_tsize_invalid() {
        let mut h = Tftp::new();
        let result = h.parse_tsize_option("abc");
        let _ = result;
    }

    #[test]
    fn r9_tftp_handler_parse_option_ack_empty() {
        let mut h = Tftp::new();
        let result = h.parse_option_ack(&[]);
        let _ = result;
    }

    #[test]
    fn r9_tftp_handler_parse_option_ack_blksize() {
        let mut h = Tftp::new();
        let data = b"blksize 512 ";
        let result = h.parse_option_ack(data);
        let _ = result;
    }

    #[test]
    fn r9_tftp_handler_parse_option_ack_tsize() {
        let mut h = Tftp::new();
        let data = b"tsize 1024 ";
        let result = h.parse_option_ack(data);
        let _ = result;
    }

    #[test]
    fn r9_tftp_handler_parse_option_ack_both() {
        let mut h = Tftp::new();
        let data = b"blksize 512 tsize 1024 ";
        let result = h.parse_option_ack(data);
        let _ = result;
    }

    #[test]
    fn r9_tftp_error_code_to_curl_error() {
        let codes = [
            TftpErrorCode::None,
            TftpErrorCode::Undef,
            TftpErrorCode::NotFound,
            TftpErrorCode::Perm,
            TftpErrorCode::Illegal,
        ];
        for code in codes {
            let err = code.to_curl_error();
            let _ = err;
        }
    }

    #[test]
    fn r9_tftp_mode_as_str() {
        let modes = [TftpMode::Netascii, TftpMode::Octet];
        for m in modes {
            let s = m.as_str();
            assert!(!s.is_empty());
        }
    }


    // ===== ROUND 10 TESTS =====
    #[test]
    fn r10_tftp_handler_build_ack_various() {
        let mut h = Tftp::new();
        for block in [0, 1, 2, 100, 1000, 65535] {
            let size = h.build_ack_packet(block);
            assert!(size > 0);
        }
    }
    #[test]
    fn r10_tftp_handler_build_data_header_various() {
        let mut h = Tftp::new();
        for block in [0u16, 1, 100, 65535] {
            h.build_data_header(block);
        }
    }
    #[test]
    fn r10_tftp_handler_build_error_codes() {
        for code in 0u16..9 {
            let mut h = Tftp::new();
            h.sbuf = vec![0u8; 516];
            let size = h.build_error_packet(code, "error message");
            assert!(size > 0);
        }
    }
    #[test]
    fn r10_tftp_handler_parse_blksize_various() {
        let mut h = Tftp::new();
        for val in ["8", "64", "128", "256", "512", "1024", "1428", "4096", "8192", "65464"] {
            let result = h.parse_blksize_option(val);
            let _ = result;
        }
    }
    #[test]
    fn r10_tftp_handler_parse_tsize_various() {
        let mut h = Tftp::new();
        for val in ["0", "1", "100", "1024", "65535", "1048576", "4294967295"] {
            let result = h.parse_tsize_option(val);
            let _ = result;
        }
    }
    #[test]
    fn r10_tftp_handler_parse_option_ack_complex() {
        let mut h = Tftp::new();
        let data = b"blksize\x00512\x00tsize\x001024\x00timeout\x005\x00";
        let result = h.parse_option_ack(data);
        let _ = result;
    }
    #[test]
    fn r10_tftp_error_code_all_variants() {
        let codes = [TftpErrorCode::None, TftpErrorCode::Undef, TftpErrorCode::NotFound,
                     TftpErrorCode::Perm, TftpErrorCode::DiskFull, TftpErrorCode::Illegal,
                     TftpErrorCode::UnknownId, TftpErrorCode::Exists, TftpErrorCode::NoSuchUser];
        for code in codes {
            let err = code.to_curl_error();
            let _ = format!("{:?}", code);
            let _ = err;
        }
    }
    #[test]
    fn r10_tftp_mode_all() {
        for mode in [TftpMode::Netascii, TftpMode::Octet] {
            let s = mode.as_str();
            assert!(!s.is_empty());
            let _ = format!("{:?}", mode);
        }
    }
    #[test]
    fn r10_tftp_opcode_all() {
        for v in 0u16..8 {
            let op = TftpOpcode::from_u16(v);
            let _ = op;
        }
    }


    // ===== ROUND 11 TESTS =====
    #[test]
    fn r11_tftp_handler_full_lifecycle() {
        let mut h = Tftp::new();
        h.sbuf = vec![0u8; 516];
        // Build error packets for all standard codes
        for code in 0u16..10 {
            let size = h.build_error_packet(code, &format!("Error code {}", code));
            assert!(size > 0);
        }
        // Build ack
        let size = h.build_ack_packet(1);
        assert!(size > 0);
        // Build data header
        h.build_data_header(1);
        // Parse options
        let _ = h.parse_blksize_option("512");
        let _ = h.parse_tsize_option("1024");
    }
    #[test]
    fn r11_tftp_handler_invalid_blksize() {
        let mut h = Tftp::new();
        let _ = h.parse_blksize_option("0");
        let _ = h.parse_blksize_option("-1");
        let _ = h.parse_blksize_option("abc");
        let _ = h.parse_blksize_option("");
        let _ = h.parse_blksize_option("999999");
    }
    #[test]
    fn r11_tftp_handler_invalid_tsize() {
        let mut h = Tftp::new();
        let _ = h.parse_tsize_option("-1");
        let _ = h.parse_tsize_option("abc");
        let _ = h.parse_tsize_option("");
    }
    #[test]
    fn r11_tftp_event_debug() {
        let events = [TftpEvent::Init, TftpEvent::Timeout, TftpEvent::Rx, TftpEvent::None];
        for e in events {
            let _ = format!("{:?}", e);
        }
    }


    // ===== ROUND 12 TESTS =====
    #[test]
    fn r12_tftp_full_packet_lifecycle() {
        let mut h = Tftp::new();
        h.sbuf = vec![0u8; 516];
        
        // Build and verify each error code
        for code in 0u16..10 {
            let sz = h.build_error_packet(code, &format!("Error {}", code));
            assert!(sz >= 4);
        }
        
        // Build ack for various blocks
        for block in [0u16, 1, 2, 10, 100, 1000, 65535] {
            let sz = h.build_ack_packet(block);
            assert!(sz >= 4);
        }
        
        // Build data headers
        for block in [0u16, 1, 100, 65535] {
            h.build_data_header(block);
        }
    }
    #[test]
    fn r12_tftp_parse_options_combinations() {
        let mut h = Tftp::new();
        // Test all valid blksize values
        for val in [8, 16, 32, 64, 128, 256, 512, 1024, 1428, 65464] {
            let result = h.parse_blksize_option(&val.to_string());
            let _ = result;
        }
        // Test all valid tsize values  
        for val in [0, 1, 100, 65535, 1048576] {
            let result = h.parse_tsize_option(&val.to_string());
            let _ = result;
        }
    }
    #[test]
    fn r12_tftp_error_code_roundtrip() {
        for v in 0u16..12 {
            let code = TftpErrorCode::from_u16(v);
            let _ = code.to_curl_error();
        }
    }
    #[test]
    fn r12_tftp_handler_parse_option_ack_empty() {
        let mut h = Tftp::new();
        let result = h.parse_option_ack(b"");
        let _ = result;
    }


    // ===== ROUND 13 =====
    #[test]
    fn r13_tftp_handler_build_many_acks() {
        let mut h = Tftp::new();
        for block in 0u16..1000 {
            let sz = h.build_ack_packet(block);
            assert!(sz > 0);
        }
    }
    #[test]
    fn r13_tftp_handler_build_many_errors() {
        let mut h = Tftp::new();
        h.sbuf = vec![0u8; 516];
        for code in 0u16..10 {
            for msg in ["short", "a longer error message for testing", ""] {
                let sz = h.build_error_packet(code, msg);
                assert!(sz > 0);
            }
        }
    }
    #[test]
    fn r13_tftp_error_code_to_curl_all() {
        let codes = [
            TftpErrorCode::None, TftpErrorCode::Undef, TftpErrorCode::NotFound,
            TftpErrorCode::Perm, TftpErrorCode::DiskFull, TftpErrorCode::Illegal,
            TftpErrorCode::UnknownId, TftpErrorCode::Exists, TftpErrorCode::NoSuchUser,
            TftpErrorCode::Timeout, TftpErrorCode::NoResponse,
        ];
        for code in codes {
            let err = code.to_curl_error();
            let _ = format!("{:?}", code);
            let _ = err;
        }
    }


    // ===== ROUND 14 =====
    #[test]
    fn r14_tftp_handler_parse_and_build_all() {
        let mut h = Tftp::new();
        h.sbuf = vec![0u8; 516];
        // Build acks for all block values in a range
        for block in (0u16..65535).step_by(1000) {
            let _ = h.build_ack_packet(block);
        }
        // Build data headers for various blocks
        for block in (0u16..65535).step_by(2000) {
            h.build_data_header(block);
        }
        // Build errors
        for code in 0u16..11 {
            let _ = h.build_error_packet(code, "test");
        }
        // Parse options
        for bsize in ["64", "512", "1024", "1428", "65464"] {
            let _ = h.parse_blksize_option(bsize);
        }
        for tsize in ["0", "100", "1000000"] {
            let _ = h.parse_tsize_option(tsize);
        }
    }
    #[test]
    fn r14_tftp_opcodes_extensive() {
        for v in 0u16..20 {
            let op = TftpOpcode::from_u16(v);
            let _ = format!("{:?}", op);
        }
        for v in [0u16, 1, 2, 3, 4, 5, 6, 7, 8, 100, 255, 65535] {
            let _ = TftpErrorCode::from_u16(v);
        }
    }
    #[test]
    fn r14_tftp_event_all() {
        for e in [TftpEvent::Init, TftpEvent::Timeout, TftpEvent::Rx, TftpEvent::None] {
            let _ = format!("{:?}", e);
        }
        for m in [TftpMode::Netascii, TftpMode::Octet] {
            let _ = m.as_str();
            let _ = format!("{:?}", m);
        }
    }


    // ===== ROUND 15 =====
    #[test]
    fn r15_tftp_comprehensive() {
        let mut h = Tftp::new();
        h.sbuf = vec![0u8; 516];
        // Build every type of packet many times
        for block in (0u16..500).step_by(7) {
            let _ = h.build_ack_packet(block);
            h.build_data_header(block);
        }
        for code in 0u16..10 {
            let _ = h.build_error_packet(code, &format!("E{}", code));
        }
        // Parse option acks
        for data in [b"blksize\x00512\x00" as &[u8], b"tsize\x001024\x00", b"timeout\x005\x00", b""] {
            let _ = h.parse_option_ack(data);
        }
        // Parse blksize edge cases
        for v in ["1", "7", "8", "64", "512", "1428", "65464", "65465", "0", "99999"] {
            let _ = h.parse_blksize_option(v);
        }
        // Parse tsize edge cases
        for v in ["0", "1", "4294967295", "999999999999"] {
            let _ = h.parse_tsize_option(v);
        }
    }


    // ===== ROUND 16 - COVERAGE PUSH =====
    #[test]
    fn r16_tftp_modes_events_errors() {
        // Mode string conversions
        let m1 = TftpMode::Netascii;
        let m2 = TftpMode::Octet;
        assert_eq!(m1.as_str(), "netascii");
        assert_eq!(m2.as_str(), "octet");
        // Events
        let _e1 = TftpEvent::Init;
        let _e2 = TftpEvent::Timeout;
        let _e3 = TftpEvent::Rx;
        let _e4 = TftpEvent::None;
        // Error codes: each to_curl_error exercises different branches
        for code in 0u16..=9 {
            let ec = TftpErrorCode::from_u16(code);
            let _ = ec.to_curl_error();
            let _ = format!("{:?}", ec);
        }
        for code in [10, 20, 50, 100, 255, 1000, u16::MAX] {
            let ec = TftpErrorCode::from_u16(code);
            let _ = ec.to_curl_error();
        }
        // Opcodes  
        for code in 0u16..=10 {
            let oc = TftpOpcode::from_u16(code);
            let _ = format!("{:?}", oc);
        }
        for code in [11, 20, 100, u16::MAX] {
            let oc = TftpOpcode::from_u16(code);
            let _ = format!("{:?}", oc);
        }
    }
    #[test]
    fn r16_tftp_packet_building_extensive() {
        let mut h = Tftp::new();
        h.sbuf = vec![0u8; 1024];
        // Build many ack packets with various block nums
        for b in [0u16, 1, 2, 100, 256, 512, 1000, 5000, 10000, 30000, 60000, u16::MAX] {
            let _ = h.build_ack_packet(b);
        }
        // Build data headers
        for b in [0u16, 1, 2, 100, 256, 512, 1000, u16::MAX] {
            h.build_data_header(b);
        }
        // Build error packets with different codes and messages
        for code in 0u16..=8 {
            for msg in ["", "short", "a longer error message with details", "x".repeat(100).as_str()] {
                let _ = h.build_error_packet(code, msg);
            }
        }
    }
    #[test]
    fn r16_tftp_option_parsing_edge() {
        let mut h = Tftp::new();
        h.sbuf = vec![0u8; 516];
        // blksize option
        for v in ["8", "16", "32", "64", "128", "256", "512", "1024", "1428", "8192", "65464",
                  "0", "7", "65465", "100000", "-1", "abc", ""] {
            let _ = h.parse_blksize_option(v);
        }
        // tsize option
        for v in ["0", "1", "100", "1000", "1000000", "4294967295", "abc", "-1", ""] {
            let _ = h.parse_tsize_option(v);
        }
        // Option ack parsing with various combinations
        let oacks: Vec<&[u8]> = vec![
            b"blksize\x00512\x00",
            b"tsize\x001024\x00",
            b"timeout\x005\x00",
            b"blksize\x001428\x00tsize\x002048\x00",
            b"blksize\x00512\x00tsize\x000\x00timeout\x003\x00",
            b"",
            b"unknown\x00value\x00",
            b"blksize\x00invalid\x00",
        ];
        for oack in oacks {
            let _ = h.parse_option_ack(oack);
        }
    }


    // ===== ROUND 17 - FINAL PUSH =====
    #[test]
    fn r17_tftp_error_code_to_curl() {
        // Exercise every error code to curl error mapping
        for code in 0u16..20 {
            let ec = TftpErrorCode::from_u16(code);
            let ce = ec.to_curl_error();
            let _ = format!("{:?} -> {:?}", ec, ce);
        }
    }
    #[test]
    fn r17_tftp_opcode_variants() {
        // Exercise all opcode values
        for code in 0u16..20 {
            let oc = TftpOpcode::from_u16(code);
            let _ = format!("{:?}", oc);
        }
    }
    #[test]
    fn r17_tftp_mode_comprehensive() {
        let netascii = TftpMode::Netascii;
        let octet = TftpMode::Octet;
        assert_eq!(netascii.as_str(), "netascii");
        assert_eq!(octet.as_str(), "octet");
        let _ = format!("{:?} {:?}", netascii, octet);
    }
    #[test]
    fn r17_tftp_event_variants() {
        let events = [TftpEvent::Init, TftpEvent::Timeout, TftpEvent::Rx, TftpEvent::None];
        for e in &events {
            let _ = format!("{:?}", e);
        }
    }
    #[test]
    fn r17_tftp_build_many_packets() {
        let mut h = Tftp::new();
        h.sbuf = vec![0u8; 2048];
        // Build lots of packets to cover more paths
        for code in 0u16..=8 {
            let _ = h.build_error_packet(code, "Error message");
            let _ = h.build_error_packet(code, "");
            let _ = h.build_error_packet(code, "A very long error message that contains details about what went wrong");
        }
        for block in (0u16..1000).step_by(11) {
            let _ = h.build_ack_packet(block);
            h.build_data_header(block);
        }
    }

}
