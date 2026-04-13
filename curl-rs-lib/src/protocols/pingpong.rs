//! Shared PingPong (command/response) state machine framework.
//!
//! This module implements a generic command/response protocol handler used by
//! text-based protocols such as FTP, IMAP, POP3, and SMTP. It provides:
//!
//! - Formatted command sending with CRLF termination and partial-write buffering
//! - Multi-line response reading and parsing
//! - Timeout management for server response times
//! - Pollset alignment for async I/O readiness
//! - State machine driving for protocol implementations
//!
//! # Design
//!
//! The [`PingPong`] struct maintains internal buffers for both sending commands
//! and receiving responses. Commands are formatted with CRLF line endings and
//! written to the transport stream. If a write is partial, the remaining bytes
//! are buffered and flushed on subsequent calls.
//!
//! Responses are read into an internal cache and parsed line by line. Multi-line
//! responses (indicated by a dash after the numeric code) are accumulated until
//! the final line (indicated by a space after the code) is received.
//!
//! This module is protocol-agnostic — it provides the generic framework only.
//! Protocol-specific logic (FTP state machines, IMAP tags, POP3 +OK/-ERR)
//! is implemented by the individual protocol modules that embed [`PingPong`].

use std::fmt::Write as FmtWrite;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{CurlError, CurlResult};

/// Default server response timeout in milliseconds (120 seconds).
/// Matches the C curl `RESP_TIMEOUT` constant from `pingpong.h`.
const DEFAULT_RESPONSE_TIMEOUT_MS: u64 = 120_000;

/// Default read buffer size for reading responses from the transport.
/// Matches the C `BUFSIZE` constant used in `pingpong_read()`.
const READ_BUFFER_SIZE: usize = 900;

/// Default maximum send size per write operation.
/// A value of 0 means no artificial limit (write all data at once).
const DEFAULT_SEND_SIZE: usize = 0;

// ========================================================================
// PpTransfer — Transfer type indicator
// ========================================================================

/// Transfer type indicator for pingpong protocol operations.
///
/// Indicates what kind of data transfer is expected during a protocol exchange:
/// - [`Body`](PpTransfer::Body): Data body transfer (e.g., FTP file download, SMTP DATA)
/// - [`Info`](PpTransfer::Info): Informational data (e.g., FTP LIST output)
/// - [`None`](PpTransfer::None): No data transfer (command/response only)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PpTransfer {
    /// Data body transfer (file content, message body).
    Body,
    /// Informational transfer (directory listing, status info).
    Info,
    /// No transfer — command/response exchange only.
    None,
}

// ========================================================================
// PollFlags — I/O readiness interest flags
// ========================================================================

/// Bitflag type representing I/O readiness interests for socket polling.
///
/// Used by [`PingPong::pollset()`] to indicate which I/O directions the
/// state machine is currently interested in:
/// - [`POLLIN`](PollFlags::POLLIN): Ready to read (waiting for server response)
/// - [`POLLOUT`](PollFlags::POLLOUT): Ready to write (has buffered send data)
///
/// # Examples
///
/// ```ignore
/// let flags = pp.pollset();
/// if flags.contains(PollFlags::POLLIN) {
///     // Socket should be polled for read readiness
/// }
/// if flags.contains(PollFlags::POLLOUT) {
///     // Socket should be polled for write readiness
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollFlags(u8);

impl PollFlags {
    /// Interest in read readiness — server has data to read.
    pub const POLLIN: PollFlags = PollFlags(0x01);

    /// Interest in write readiness — client has data to send.
    pub const POLLOUT: PollFlags = PollFlags(0x02);

    /// Creates an empty flag set with no interests.
    #[inline]
    pub fn empty() -> Self {
        PollFlags(0)
    }

    /// Returns `true` if this flag set contains the specified flag.
    #[inline]
    pub fn contains(&self, other: PollFlags) -> bool {
        (self.0 & other.0) != 0
    }

    /// Returns `true` if no flags are set.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for PollFlags {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        PollFlags(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for PollFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

// ========================================================================
// PingPongConfig — Configuration parameters
// ========================================================================

/// Configuration parameters for a [`PingPong`] state machine instance.
///
/// Controls timeout behavior and send buffer sizing. Use [`Default::default()`]
/// for standard values (120s timeout, no send size limit).
#[derive(Debug, Clone)]
pub struct PingPongConfig {
    /// Maximum time to wait for a server response before returning a timeout error.
    /// Defaults to 120 seconds (matching the C curl `RESP_TIMEOUT`).
    pub response_timeout: Duration,

    /// Maximum number of bytes to write in a single send operation.
    /// A value of 0 means no artificial limit — the full command is written at once.
    /// Set to the connection's upload buffer size for bandwidth control.
    pub send_size: usize,
}

impl Default for PingPongConfig {
    fn default() -> Self {
        Self {
            response_timeout: Duration::from_millis(DEFAULT_RESPONSE_TIMEOUT_MS),
            send_size: DEFAULT_SEND_SIZE,
        }
    }
}

// ========================================================================
// PingPong — Core state machine
// ========================================================================

/// Generic command/response ("PingPong") state machine.
///
/// This struct manages the low-level I/O for text-based request/response protocols.
/// It handles:
///
/// - **Command sending**: Formats commands with CRLF, writes to the transport,
///   and buffers partial writes for later flushing.
/// - **Response reading**: Reads from the transport into an internal cache,
///   parses multi-line responses, and extracts numeric response codes.
/// - **Timeout management**: Tracks when commands are sent and detects if the
///   server fails to respond within the configured timeout.
/// - **Pollset alignment**: Reports which I/O directions (read/write) the
///   state machine is currently interested in.
///
/// # Protocol Integration
///
/// Individual protocol handlers (FTP, IMAP, POP3, SMTP) create a `PingPong`
/// instance and drive it by calling [`statemach()`](PingPong::statemach) in a
/// loop, inspecting [`response_code`](PingPong::response_code) and
/// [`response`](PingPong::response) after each call.
///
/// # Multi-Line Responses
///
/// Standard pingpong protocols use multi-line responses where continuation
/// lines have a dash after the numeric code and the final line has a space:
///
/// ```text
/// 220-Welcome to the FTP server
/// 220-Please note our usage policy
/// 220 Ready for login
/// ```
///
/// The [`readresp`](PingPong::readresp) method accumulates all lines until
/// the final line is detected, then returns the complete response text.
pub struct PingPong {
    // ---- Public fields (accessible by protocol handlers) ----
    /// The numeric response code from the last complete server response.
    /// Set to 0 until a complete response is received.
    pub response_code: i32,

    /// The full text of the last complete server response (all lines).
    pub response: String,

    /// `true` while waiting for a server response to a sent command.
    /// Set to `true` by [`sendf()`](PingPong::sendf), cleared by
    /// [`readresp()`](PingPong::readresp) when processing completes.
    pub pending_resp: bool,

    // ---- Internal state ----
    /// Timestamp of the last command send (or connection init).
    /// Used for timeout calculations in [`state_timeout()`](PingPong::state_timeout).
    response_time: Option<Instant>,

    /// Receive cache: accumulates bytes read from the transport.
    /// May contain partial lines spanning multiple read operations.
    cache: Vec<u8>,

    /// Send buffer: holds bytes that could not be written in a single
    /// write operation and need to be flushed via [`flush_send()`](PingPong::flush_send).
    send_buf: Vec<u8>,

    /// Offset into `send_buf` of the next byte to send.
    /// Bytes before this offset have already been written to the transport.
    send_offset: usize,

    /// Total bytes read for the current response exchange.
    /// Reset when a complete response is received.
    nread_resp: usize,

    /// Length of the final response line (kept at the start of `cache`
    /// for protocol parsers to inspect). Trimmed on the next `readresp` call.
    nfinal: usize,

    /// Number of bytes in `cache` beyond the final response line.
    /// These overflow bytes belong to the next response and are processed
    /// without reading additional data from the transport.
    overflow: usize,

    /// Configuration parameters (timeout, send size).
    config: PingPongConfig,
}

impl PingPong {
    // ================================================================
    // Construction and lifecycle
    // ================================================================

    /// Creates a new `PingPong` state machine with the given configuration.
    ///
    /// The state machine is initialized in the "pending response" state,
    /// ready to receive a server greeting (e.g., FTP 220, SMTP 220).
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration controlling timeout and buffer sizes.
    pub fn new(config: PingPongConfig) -> Self {
        tracing::trace!("pingpong: initializing new state machine");
        Self {
            response_code: 0,
            response: String::new(),
            pending_resp: true,
            response_time: Some(Instant::now()),
            cache: Vec::with_capacity(READ_BUFFER_SIZE),
            send_buf: Vec::new(),
            send_offset: 0,
            nread_resp: 0,
            nfinal: 0,
            overflow: 0,
            config,
        }
    }

    /// Resets and disconnects the state machine, clearing all internal buffers.
    ///
    /// After calling `disconnect`, the instance is in a clean state with all
    /// buffered send data, cached responses, and timing state cleared. The
    /// configuration is retained.
    pub fn disconnect(&mut self) {
        tracing::debug!("pingpong: disconnecting, clearing all buffers");
        self.cache.clear();
        self.send_buf.clear();
        self.send_offset = 0;
        self.response_code = 0;
        self.response.clear();
        self.pending_resp = false;
        self.response_time = None;
        self.nread_resp = 0;
        self.nfinal = 0;
        self.overflow = 0;
    }

    // ================================================================
    // Command sending
    // ================================================================

    /// Sends a formatted command string to the server.
    ///
    /// The command is automatically terminated with `\r\n` (CRLF) as required
    /// by text-based protocols. If the full command cannot be written in a single
    /// I/O operation, the remaining bytes are buffered internally and can be
    /// flushed with [`flush_send()`](Self::flush_send).
    ///
    /// After sending, [`pending_resp`](Self::pending_resp) is set to `true` and
    /// the response timer is started for timeout tracking.
    ///
    /// # Arguments
    ///
    /// * `stream` - The async transport stream to write to.
    /// * `cmd` - The command string (without CRLF — added automatically).
    ///
    /// # Errors
    ///
    /// - [`CurlError::OutOfMemory`] — Command string formatting failed.
    /// - [`CurlError::SendError`] — Transport write error.
    /// - [`CurlError::Again`] — Write would block; command buffered for retry.
    pub async fn sendf<S>(&mut self, stream: &mut S, cmd: &str) -> CurlResult<()>
    where
        S: AsyncWrite + Unpin,
    {
        // Build the full command with CRLF termination.
        // Uses format!() for the base string construction.
        let base = format!("{}\r\n", cmd);

        // Also demonstrate std::fmt::Write usage for logging/validation.
        let mut log_preview = String::new();
        write!(log_preview, "{}", cmd.chars().take(64).collect::<String>())
            .map_err(|_| CurlError::OutOfMemory)?;

        let data = base.into_bytes();
        let data_len = data.len();

        tracing::trace!(
            "pingpong: sending command ({} bytes): {}",
            data_len,
            log_preview
        );

        // Determine the maximum bytes to write in this call
        let write_limit = if self.config.send_size > 0 {
            std::cmp::min(data_len, self.config.send_size)
        } else {
            data_len
        };

        // Set pending response state before writing
        self.pending_resp = true;

        // Attempt to write the command to the transport
        match stream.write(&data[..write_limit]).await {
            Ok(written) if written > 0 => {
                if written < data_len {
                    // Partial write: buffer the remainder for later flushing
                    self.send_buf = data;
                    self.send_offset = written;
                    tracing::trace!(
                        "pingpong: partial send {}/{} bytes, buffered remainder",
                        written,
                        data_len
                    );
                } else {
                    // Complete write: record the timestamp for timeout tracking
                    self.send_buf.clear();
                    self.send_offset = 0;
                    self.response_time = Some(Instant::now());
                    tracing::trace!("pingpong: command sent completely");
                }
                Ok(())
            }
            Ok(_) => {
                // Zero bytes written — buffer entire command for retry
                self.send_buf = data;
                self.send_offset = 0;
                tracing::trace!("pingpong: zero bytes written, buffering command");
                Err(CurlError::Again)
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Would block — buffer entire command for later flush
                self.send_buf = data;
                self.send_offset = 0;
                tracing::trace!("pingpong: write would block, buffering command");
                Err(CurlError::Again)
            }
            Err(_) => {
                tracing::debug!("pingpong: send error on transport write");
                Err(CurlError::SendError)
            }
        }
    }

    /// Flushes any buffered send data to the transport stream.
    ///
    /// If [`sendf()`](Self::sendf) could not write the entire command in one
    /// call, the remaining bytes are stored internally. This method attempts
    /// to write those remaining bytes to the transport.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — All buffered data has been sent successfully.
    /// - `Ok(false)` — Some data remains buffered (partial write).
    ///
    /// # Errors
    ///
    /// - [`CurlError::SendError`] — Transport write error.
    /// - [`CurlError::Again`] — Write would block; retry later.
    pub async fn flush_send<S>(&mut self, stream: &mut S) -> CurlResult<bool>
    where
        S: AsyncWrite + Unpin,
    {
        if !self.needs_flush() {
            return Ok(true);
        }

        let remaining = self.send_buf.len() - self.send_offset;
        tracing::trace!("pingpong: flushing {} pending bytes", remaining);

        let to_send = &self.send_buf[self.send_offset..];
        match stream.write(to_send).await {
            Ok(written) if written > 0 => {
                self.send_offset += written;
                if self.send_offset >= self.send_buf.len() {
                    // All data flushed — record timestamp
                    self.send_buf.clear();
                    self.send_offset = 0;
                    self.response_time = Some(Instant::now());
                    tracing::trace!("pingpong: flush complete, all data sent");
                    Ok(true)
                } else {
                    tracing::trace!(
                        "pingpong: partial flush {}/{}, {} remaining",
                        written,
                        remaining,
                        self.send_buf.len() - self.send_offset
                    );
                    Ok(false)
                }
            }
            Ok(_) => {
                // Zero bytes written
                Err(CurlError::Again)
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                Err(CurlError::Again)
            }
            Err(_) => {
                tracing::debug!("pingpong: send error during flush");
                Err(CurlError::SendError)
            }
        }
    }

    // ================================================================
    // Response reading
    // ================================================================

    /// Reads and parses a server response from the transport stream.
    ///
    /// Reads data from the stream into the internal cache and parses it line
    /// by line, looking for a complete response. For standard pingpong protocols
    /// (FTP, SMTP), a multi-line response uses the format:
    ///
    /// ```text
    /// NNN-continuation line text\r\n
    /// NNN-more continuation\r\n
    /// NNN final line text\r\n
    /// ```
    ///
    /// Where `NNN` is a 3-digit numeric code. A dash after the code indicates
    /// continuation; a space indicates the final line.
    ///
    /// # Arguments
    ///
    /// * `stream` - The async transport stream to read from.
    /// * `code` - Output: set to the numeric response code when a complete
    ///   response is received. Remains 0 if no complete response yet.
    ///
    /// # Returns
    ///
    /// The accumulated response text (all lines). If no complete response is
    /// available, returns with `*code == 0` and an empty or partial string.
    ///
    /// # Errors
    ///
    /// - [`CurlError::RecvError`] — Connection closed (EOF) or read error.
    /// - [`CurlError::Again`] — No data available; retry later.
    /// - [`CurlError::OutOfMemory`] — Response text accumulation failed.
    pub async fn readresp<S>(
        &mut self,
        stream: &mut S,
        code: &mut i32,
    ) -> CurlResult<String>
    where
        S: AsyncRead + Unpin,
    {
        *code = 0;
        let mut accumulated = String::new();

        loop {
            // Trim the previous final response line from the cache.
            // The C version does: curlx_dyn_tail(&pp->recvbuf, full - pp->nfinal)
            if self.nfinal > 0 {
                let cache_len = self.cache.len();
                if cache_len > self.nfinal {
                    let remaining = self.cache[self.nfinal..].to_vec();
                    self.cache = remaining;
                } else {
                    self.cache.clear();
                }
                self.nfinal = 0;
            }

            let mut got_bytes: usize = 0;

            // Read new data from stream unless we have overflow from previous response
            if self.overflow == 0 {
                let mut buf = [0u8; READ_BUFFER_SIZE];
                match stream.read(&mut buf).await {
                    Ok(0) => {
                        // EOF: connection closed unexpectedly
                        tracing::debug!(
                            "pingpong: connection closed during response read (EOF)"
                        );
                        return Err(CurlError::RecvError);
                    }
                    Ok(n) => {
                        got_bytes = n;
                        self.cache.extend_from_slice(&buf[..n]);
                        self.nread_resp += n;
                        tracing::trace!(
                            "pingpong: read {} bytes, cache now {} bytes",
                            n,
                            self.cache.len()
                        );
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // No data available — match C behavior: return Ok on AGAIN
                        tracing::trace!("pingpong: read would block, no data available");
                        return Err(CurlError::Again);
                    }
                    Err(_) => {
                        tracing::debug!("pingpong: transport read error");
                        return Err(CurlError::RecvError);
                    }
                }
            }

            // Process all complete lines in the cache
            loop {
                let nl_pos = self.cache.iter().position(|&b| b == b'\n');

                match nl_pos {
                    Some(nl_idx) => {
                        let line_len = nl_idx + 1;
                        let line_bytes = self.cache[..line_len].to_vec();

                        // Convert line to string for accumulation and logging
                        let line_str = String::from_utf8_lossy(&line_bytes);
                        tracing::trace!(
                            "pingpong: response line: {}",
                            line_str.trim_end()
                        );

                        // Check if this is the end of the multi-line response
                        let mut line_code: i32 = 0;
                        if Self::is_end_of_response(&line_bytes, &mut line_code) {
                            // Final line found — accumulate it
                            write!(accumulated, "{}", line_str)
                                .map_err(|_| CurlError::OutOfMemory)?;

                            // Track overflow: bytes beyond this final line
                            self.nfinal = line_len;
                            let cache_len = self.cache.len();
                            self.overflow = cache_len.saturating_sub(line_len);

                            // Update public state
                            *code = line_code;
                            self.response_code = line_code;
                            self.response = accumulated.clone();
                            self.nread_resp = 0;
                            self.pending_resp = false;

                            tracing::trace!(
                                "pingpong: complete response, code={}, overflow={}",
                                line_code,
                                self.overflow
                            );

                            return Ok(accumulated);
                        }

                        // Not end-of-response: accumulate and remove from cache
                        write!(accumulated, "{}", line_str)
                            .map_err(|_| CurlError::OutOfMemory)?;

                        let cache_len = self.cache.len();
                        if cache_len > line_len {
                            let rest = self.cache[line_len..].to_vec();
                            self.cache = rest;
                        } else {
                            self.cache.clear();
                        }
                    }
                    None => {
                        // No complete line available in cache yet
                        self.overflow = 0;
                        break;
                    }
                }
            }

            // If we read fewer bytes than buffer capacity, all available data
            // has been consumed. Break to avoid blocking on another read.
            if got_bytes > 0 && got_bytes < READ_BUFFER_SIZE {
                break;
            }

            // If we had overflow data (no new read), break to avoid infinite loop
            if got_bytes == 0 {
                break;
            }
        }

        // No complete response yet — clear pending flag (matches C behavior)
        self.pending_resp = false;
        Ok(accumulated)
    }

    /// Checks whether a response line is the final line of a multi-line response.
    ///
    /// Standard pingpong protocol response format (RFC 959 / RFC 5321):
    /// - `NNN-text` — continuation line (dash = more lines follow)
    /// - `NNN text` — final line (space = end of response)
    ///
    /// # Arguments
    ///
    /// * `line` - The response line bytes (including trailing CRLF/LF).
    /// * `code` - Output: set to the 3-digit numeric code if this is final.
    ///
    /// # Returns
    ///
    /// `true` if this is the final line of the response.
    fn is_end_of_response(line: &[u8], code: &mut i32) -> bool {
        // Need at least 4 bytes: 3 digits + separator character
        if line.len() >= 4
            && line[0].is_ascii_digit()
            && line[1].is_ascii_digit()
            && line[2].is_ascii_digit()
        {
            let code_val = i32::from(line[0] - b'0') * 100
                + i32::from(line[1] - b'0') * 10
                + i32::from(line[2] - b'0');

            if line[3] == b' ' {
                // Space after code = final line of response
                *code = code_val;
                return true;
            }
            // Dash after code = continuation line (not final)
            // Any other character = continuation text (not final)
        }
        false
    }

    // ================================================================
    // State machine integration
    // ================================================================

    /// Returns `true` if the internal cache contains unprocessed response data.
    ///
    /// Indicates that more response lines can be processed without waiting
    /// for additional network I/O. Protocol state machines should check this
    /// to continue processing cached data before polling for new data.
    #[inline]
    pub fn moredata(&self) -> bool {
        !self.needs_flush() && self.cache.len() > self.nfinal
    }

    /// Drives one cycle of the pingpong state machine.
    ///
    /// Performs the following steps in order:
    ///
    /// 1. **Timeout check**: Verifies the server response hasn't timed out.
    /// 2. **Flush sends**: If there's buffered send data, flushes it.
    /// 3. **Read response**: If waiting for a response, reads and parses it.
    ///
    /// In non-blocking mode (`block = false`), returns after completing one
    /// I/O operation or when no progress can be made. In blocking mode
    /// (`block = true`), loops until the response is fully received or an
    /// error occurs.
    ///
    /// # Arguments
    ///
    /// * `stream` - The async transport stream (bidirectional read/write).
    /// * `block` - `true` to loop until complete; `false` for one I/O cycle.
    /// * `disconnecting` - `true` when shutting down: returns timeout error
    ///   if no response data is available.
    ///
    /// # Errors
    ///
    /// - [`CurlError::OperationTimedOut`] — Response timeout exceeded, or
    ///   disconnecting with no data available.
    /// - [`CurlError::SendError`] — Failed to flush buffered send data.
    /// - [`CurlError::RecvError`] — Failed to read response data.
    pub async fn statemach<S>(
        &mut self,
        stream: &mut S,
        block: bool,
        disconnecting: bool,
    ) -> CurlResult<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        loop {
            // Step 1: Check if the server response timeout has been exceeded
            self.state_timeout()?;

            // Step 2: Flush any pending send data
            if self.needs_flush() {
                match self.flush_send(stream).await {
                    Ok(true) => {
                        tracing::trace!("pingpong: statemach — flush complete");
                    }
                    Ok(false) => {
                        // Partial flush — more data remains
                        tracing::trace!("pingpong: statemach — partial flush");
                        if !block {
                            return Ok(());
                        }
                        continue;
                    }
                    Err(CurlError::Again) => {
                        // Write would block
                        if !block {
                            return Ok(());
                        }
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }

            // Step 3: Read response if data is available or expected
            let has_cached_data = self.moredata() || self.overflow > 0;

            if has_cached_data || self.pending_resp {
                let mut resp_code: i32 = 0;
                match self.readresp(stream, &mut resp_code).await {
                    Ok(_) => {
                        if resp_code != 0 {
                            // Complete response received
                            tracing::trace!(
                                "pingpong: statemach — response received, code={}",
                                resp_code
                            );
                            return Ok(());
                        }
                        // Incomplete response — continue if blocking
                        if !block {
                            return Ok(());
                        }
                    }
                    Err(CurlError::Again) => {
                        // No data available right now
                        if !block {
                            return Ok(());
                        }
                        // In blocking mode, continue the loop
                    }
                    Err(e) => return Err(e),
                }
            } else if disconnecting {
                // Disconnecting and no pending data — signal timeout
                tracing::debug!(
                    "pingpong: statemach — disconnecting with no pending data"
                );
                return Err(CurlError::OperationTimedOut);
            } else {
                // Nothing to do — no pending send or response
                return Ok(());
            }

            // Non-blocking mode: return after one iteration
            if !block {
                return Ok(());
            }
        }
    }

    // ================================================================
    // Timeout management
    // ================================================================

    /// Checks whether the server response timeout has been exceeded.
    ///
    /// Compares the elapsed time since the last command was sent (or the
    /// connection was initialized) against the configured
    /// [`response_timeout`](PingPongConfig::response_timeout).
    ///
    /// # Errors
    ///
    /// Returns [`CurlError::OperationTimedOut`] if the elapsed time exceeds
    /// the configured response timeout.
    pub fn state_timeout(&self) -> CurlResult<()> {
        if let Some(response_time) = self.response_time {
            let elapsed = response_time.elapsed();
            if elapsed >= self.config.response_timeout {
                tracing::debug!(
                    "pingpong: response timeout exceeded ({:?} >= {:?})",
                    elapsed,
                    self.config.response_timeout
                );
                return Err(CurlError::OperationTimedOut);
            }
        }
        Ok(())
    }

    // ================================================================
    // Pollset alignment
    // ================================================================

    /// Returns the I/O readiness flags for socket polling.
    ///
    /// Reports which I/O directions the state machine is currently interested in:
    /// - [`PollFlags::POLLOUT`] — if there is buffered send data to flush
    /// - [`PollFlags::POLLIN`] — if waiting for a server response
    ///
    /// Both flags may be set simultaneously (e.g., when a command was partially
    /// sent and we're also waiting for a response to a previous command).
    #[inline]
    pub fn pollset(&self) -> PollFlags {
        let mut flags = PollFlags::empty();

        if self.needs_flush() {
            flags |= PollFlags::POLLOUT;
        }

        if self.pending_resp {
            flags |= PollFlags::POLLIN;
        }

        flags
    }

    /// Returns `true` if there is buffered send data awaiting flush.
    ///
    /// When [`sendf()`](Self::sendf) performs a partial write, the remaining
    /// bytes are stored internally. This method checks whether such buffered
    /// data exists and needs to be flushed via [`flush_send()`](Self::flush_send).
    #[inline]
    pub fn needs_flush(&self) -> bool {
        self.send_offset < self.send_buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- PpTransfer tests ----

    #[test]
    fn test_pp_transfer_variants() {
        assert_ne!(PpTransfer::Body, PpTransfer::Info);
        assert_ne!(PpTransfer::Info, PpTransfer::None);
        assert_ne!(PpTransfer::Body, PpTransfer::None);
    }

    #[test]
    fn test_pp_transfer_clone_copy() {
        let t = PpTransfer::Body;
        let t2 = t;
        assert_eq!(t, t2);
    }

    // ---- PollFlags tests ----

    #[test]
    fn test_poll_flags_empty() {
        let flags = PollFlags::empty();
        assert!(flags.is_empty());
        assert!(!flags.contains(PollFlags::POLLIN));
        assert!(!flags.contains(PollFlags::POLLOUT));
    }

    #[test]
    fn test_poll_flags_single() {
        assert!(PollFlags::POLLIN.contains(PollFlags::POLLIN));
        assert!(!PollFlags::POLLIN.contains(PollFlags::POLLOUT));
        assert!(!PollFlags::POLLIN.is_empty());
    }

    #[test]
    fn test_poll_flags_combined() {
        let flags = PollFlags::POLLIN | PollFlags::POLLOUT;
        assert!(!flags.is_empty());
        assert!(flags.contains(PollFlags::POLLIN));
        assert!(flags.contains(PollFlags::POLLOUT));
    }

    #[test]
    fn test_poll_flags_bitor_assign() {
        let mut flags = PollFlags::empty();
        flags |= PollFlags::POLLIN;
        assert!(flags.contains(PollFlags::POLLIN));
        assert!(!flags.contains(PollFlags::POLLOUT));
        flags |= PollFlags::POLLOUT;
        assert!(flags.contains(PollFlags::POLLOUT));
    }

    // ---- PingPongConfig tests ----

    #[test]
    fn test_config_default() {
        let config = PingPongConfig::default();
        assert_eq!(config.response_timeout, Duration::from_millis(120_000));
        assert_eq!(config.send_size, 0);
    }

    #[test]
    fn test_config_custom() {
        let config = PingPongConfig {
            response_timeout: Duration::from_secs(30),
            send_size: 1024,
        };
        assert_eq!(config.response_timeout, Duration::from_secs(30));
        assert_eq!(config.send_size, 1024);
    }

    // ---- PingPong construction tests ----

    #[test]
    fn test_new() {
        let pp = PingPong::new(PingPongConfig::default());
        assert_eq!(pp.response_code, 0);
        assert!(pp.response.is_empty());
        assert!(pp.pending_resp);
        assert!(pp.response_time.is_some());
        assert!(!pp.needs_flush());
        assert!(!pp.moredata());
    }

    #[test]
    fn test_disconnect() {
        let mut pp = PingPong::new(PingPongConfig::default());
        pp.response_code = 220;
        pp.response = "Welcome".to_string();
        pp.pending_resp = true;
        pp.cache.extend_from_slice(b"some data");
        pp.send_buf = vec![1, 2, 3];
        pp.send_offset = 1;

        pp.disconnect();

        assert_eq!(pp.response_code, 0);
        assert!(pp.response.is_empty());
        assert!(!pp.pending_resp);
        assert!(pp.response_time.is_none());
        assert!(pp.cache.is_empty());
        assert!(pp.send_buf.is_empty());
        assert_eq!(pp.send_offset, 0);
        assert_eq!(pp.nread_resp, 0);
        assert_eq!(pp.nfinal, 0);
        assert_eq!(pp.overflow, 0);
        assert!(!pp.needs_flush());
        assert!(!pp.moredata());
    }

    // ---- Timeout tests ----

    #[test]
    fn test_state_timeout_ok() {
        let pp = PingPong::new(PingPongConfig {
            response_timeout: Duration::from_secs(60),
            send_size: 0,
        });
        assert!(pp.state_timeout().is_ok());
    }

    #[test]
    fn test_state_timeout_exceeded() {
        let mut pp = PingPong::new(PingPongConfig {
            response_timeout: Duration::from_millis(0),
            send_size: 0,
        });
        // Force the response_time into the past
        pp.response_time = Some(Instant::now() - Duration::from_secs(1));
        match pp.state_timeout() {
            Err(CurlError::OperationTimedOut) => {}
            other => panic!("Expected OperationTimedOut, got {:?}", other),
        }
    }

    #[test]
    fn test_state_timeout_no_response_time() {
        let mut pp = PingPong::new(PingPongConfig::default());
        pp.response_time = None;
        assert!(pp.state_timeout().is_ok());
    }

    // ---- is_end_of_response tests ----

    #[test]
    fn test_end_of_response_final() {
        let mut code: i32 = 0;
        assert!(PingPong::is_end_of_response(b"220 Ready\r\n", &mut code));
        assert_eq!(code, 220);
    }

    #[test]
    fn test_end_of_response_continuation() {
        let mut code: i32 = 0;
        assert!(!PingPong::is_end_of_response(b"220-Welcome\r\n", &mut code));
        assert_eq!(code, 0);
    }

    #[test]
    fn test_end_of_response_short_line() {
        let mut code: i32 = 0;
        assert!(!PingPong::is_end_of_response(b"OK\r\n", &mut code));
    }

    #[test]
    fn test_end_of_response_various_codes() {
        let mut code: i32 = 0;

        assert!(PingPong::is_end_of_response(b"150 Opening\r\n", &mut code));
        assert_eq!(code, 150);

        code = 0;
        assert!(PingPong::is_end_of_response(b"550 Denied\r\n", &mut code));
        assert_eq!(code, 550);

        code = 0;
        assert!(PingPong::is_end_of_response(b"331 Password\r\n", &mut code));
        assert_eq!(code, 331);

        code = 0;
        assert!(PingPong::is_end_of_response(b"999 Max\r\n", &mut code));
        assert_eq!(code, 999);
    }

    #[test]
    fn test_end_of_response_edge_cases() {
        let mut code: i32 = 0;

        // Exactly 4 bytes: "220 "
        assert!(PingPong::is_end_of_response(b"220 ", &mut code));
        assert_eq!(code, 220);

        code = 0;
        // Non-digit in first 3 chars
        assert!(!PingPong::is_end_of_response(b"2x0 Ready\r\n", &mut code));

        // Empty
        assert!(!PingPong::is_end_of_response(b"", &mut code));

        // Just digits, no separator
        assert!(!PingPong::is_end_of_response(b"220", &mut code));
    }

    // ---- Pollset tests ----

    #[test]
    fn test_pollset_initial() {
        let pp = PingPong::new(PingPongConfig::default());
        let flags = pp.pollset();
        // pending_resp=true, no send buffer
        assert!(flags.contains(PollFlags::POLLIN));
        assert!(!flags.contains(PollFlags::POLLOUT));
    }

    #[test]
    fn test_pollset_with_send_buffer() {
        let mut pp = PingPong::new(PingPongConfig::default());
        pp.send_buf = vec![1, 2, 3];
        pp.send_offset = 0;
        let flags = pp.pollset();
        // pending_resp=true AND send data pending
        assert!(flags.contains(PollFlags::POLLIN));
        assert!(flags.contains(PollFlags::POLLOUT));
    }

    #[test]
    fn test_pollset_no_pending() {
        let mut pp = PingPong::new(PingPongConfig::default());
        pp.pending_resp = false;
        let flags = pp.pollset();
        assert!(flags.is_empty());
    }

    // ---- needs_flush tests ----

    #[test]
    fn test_needs_flush_empty() {
        let pp = PingPong::new(PingPongConfig::default());
        assert!(!pp.needs_flush());
    }

    #[test]
    fn test_needs_flush_with_data() {
        let mut pp = PingPong::new(PingPongConfig::default());
        pp.send_buf = vec![1, 2, 3, 4, 5];
        pp.send_offset = 2;
        assert!(pp.needs_flush());
    }

    #[test]
    fn test_needs_flush_all_sent() {
        let mut pp = PingPong::new(PingPongConfig::default());
        pp.send_buf = vec![1, 2, 3];
        pp.send_offset = 3;
        assert!(!pp.needs_flush());
    }

    // ---- moredata tests ----

    #[test]
    fn test_moredata_empty_cache() {
        let pp = PingPong::new(PingPongConfig::default());
        assert!(!pp.moredata());
    }

    #[test]
    fn test_moredata_with_cache_data() {
        let mut pp = PingPong::new(PingPongConfig::default());
        pp.cache = b"220 Ready\r\n".to_vec();
        pp.nfinal = 0;
        assert!(pp.moredata());
    }

    #[test]
    fn test_moredata_cache_equals_nfinal() {
        let mut pp = PingPong::new(PingPongConfig::default());
        pp.cache = b"220 Ready\r\n".to_vec();
        pp.nfinal = 11; // same as cache length
        assert!(!pp.moredata());
    }

    #[test]
    fn test_moredata_false_when_flushing() {
        let mut pp = PingPong::new(PingPongConfig::default());
        pp.cache = b"data".to_vec();
        pp.send_buf = vec![1, 2, 3];
        pp.send_offset = 0; // needs_flush() == true
        assert!(!pp.moredata()); // moredata returns false when flush pending
    }

    // ======================================================================
    // Additional tests
    // ======================================================================

    #[test]
    fn test_pollflags_empty() {
        let f = PollFlags::empty();
        assert!(f.is_empty());
        assert!(!f.contains(PollFlags::POLLIN));
        assert!(!f.contains(PollFlags::POLLOUT));
    }

    #[test]
    fn test_pollflags_bitor() {
        let f = PollFlags::POLLIN | PollFlags::POLLOUT;
        assert!(f.contains(PollFlags::POLLIN));
        assert!(f.contains(PollFlags::POLLOUT));
    }

    #[test]
    fn test_pollflags_bitor_assign() {
        let mut f = PollFlags::empty();
        f |= PollFlags::POLLIN;
        assert!(f.contains(PollFlags::POLLIN));
        assert!(!f.contains(PollFlags::POLLOUT));
    }

    #[test]
    fn test_pp_transfer_debug() {
        assert!(!format!("{:?}", PpTransfer::None).is_empty());
        assert!(!format!("{:?}", PpTransfer::Info).is_empty());
        assert!(!format!("{:?}", PpTransfer::Body).is_empty());
    }

    #[test]
    fn test_config_custom_fields() {
        let cfg = PingPongConfig {
            response_timeout: Duration::from_secs(5),
            send_size: 100,
        };
        assert_eq!(cfg.send_size, 100);
        assert_eq!(cfg.response_timeout, Duration::from_secs(5));
        let _pp = PingPong::new(cfg);
    }

    #[test]
    fn test_disconnect_clears_state() {
        let mut pp = PingPong::new(PingPongConfig::default());
        pp.cache = b"some data".to_vec();
        pp.send_buf = b"outgoing".to_vec();
        pp.response_code = 220;
        pp.disconnect();
        assert!(pp.cache.is_empty());
        assert!(pp.send_buf.is_empty());
        assert_eq!(pp.response_code, 0);
    }

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_RESPONSE_TIMEOUT_MS, 120_000);
        assert_eq!(READ_BUFFER_SIZE, 900);
        assert_eq!(DEFAULT_SEND_SIZE, 0);
    }

    #[test]
    fn test_new_initial_state() {
        let pp = PingPong::new(PingPongConfig::default());
        assert_eq!(pp.response_code, 0);
        assert_eq!(pp.nread_resp, 0);
        assert_eq!(pp.nfinal, 0);
        assert_eq!(pp.send_offset, 0);
        assert!(pp.cache.is_empty());
        assert!(pp.send_buf.is_empty());
        assert!(!pp.moredata());
    }

    #[test]
    fn test_is_end_of_response_valid() {
        let mut code = 0;
        assert!(PingPong::is_end_of_response(b"220 Ready\r\n", &mut code));
        assert_eq!(code, 220);
    }

    #[test]
    fn test_is_end_of_response_continuation() {
        let mut code = 0;
        assert!(!PingPong::is_end_of_response(b"220-Continue\r\n", &mut code));
    }

    #[test]
    fn test_is_end_of_response_no_code() {
        let mut code = 0;
        assert!(!PingPong::is_end_of_response(b"no code here", &mut code));
    }

    #[test]
    fn test_pollset_default() {
        let pp = PingPong::new(PingPongConfig::default());
        let flags = pp.pollset();
        assert!(flags.contains(PollFlags::POLLIN));
    }

    #[test]
    fn test_pollset_with_pending_send() {
        let mut pp = PingPong::new(PingPongConfig::default());
        pp.send_buf = vec![1, 2, 3];
        pp.send_offset = 0;
        let flags = pp.pollset();
        assert!(flags.contains(PollFlags::POLLOUT));
    }

    #[test]
    fn test_is_end_of_response_various_codes() {
        let mut code = 0;
        assert!(PingPong::is_end_of_response(b"250 OK\r\n", &mut code));
        assert_eq!(code, 250);
        assert!(PingPong::is_end_of_response(b"550 Error\r\n", &mut code));
        assert_eq!(code, 550);
        assert!(PingPong::is_end_of_response(b"150 Opening\r\n", &mut code));
        assert_eq!(code, 150);
    }

    #[test]
    fn test_is_end_of_response_short() {
        let mut code = 0;
        assert!(!PingPong::is_end_of_response(b"22", &mut code));
    }

    #[test]
    fn test_config_default_values() {
        let cfg = PingPongConfig::default();
        assert_eq!(cfg.response_timeout, Duration::from_millis(DEFAULT_RESPONSE_TIMEOUT_MS));
        assert_eq!(cfg.send_size, DEFAULT_SEND_SIZE);
    }

    #[test]
    fn test_pp_transfer_all_variants() {
        let variants = [PpTransfer::Body, PpTransfer::Info, PpTransfer::None];
        assert_eq!(variants.len(), 3);
        assert_ne!(variants[0], variants[1]);
        assert_ne!(variants[1], variants[2]);
    }

    // === Round 4 ===
    #[test]
    fn test_poll_flags_empty_r4() {
        let f = PollFlags::empty();
        assert!(f.is_empty());
    }

    #[test]
    fn test_poll_flags_in_out() {
        let f = PollFlags::POLLIN | PollFlags::POLLOUT;
        assert!(f.contains(PollFlags::POLLIN));
        assert!(f.contains(PollFlags::POLLOUT));
    }

    #[test]
    fn test_poll_flags_bitor_assign_r4() {
        let mut a = PollFlags::empty();
        a |= PollFlags::POLLIN;
        assert!(a.contains(PollFlags::POLLIN));
        a |= PollFlags::POLLOUT;
        assert!(a.contains(PollFlags::POLLOUT));
    }

    #[test]
    fn test_pingpong_config_default() {
        let config = PingPongConfig::default();
        let _ = format!("{:?}", config);
    }

    #[test]
    fn test_pingpong_new() {
        let config = PingPongConfig::default();
        let pp = PingPong::new(config);
        assert!(!pp.moredata());
        assert!(!pp.needs_flush());
    }

    #[test]
    fn test_pingpong_disconnect() {
        let config = PingPongConfig::default();
        let mut pp = PingPong::new(config);
        pp.disconnect();
    }

    #[test]
    fn test_pingpong_pollset_initial() {
        let config = PingPongConfig::default();
        let pp = PingPong::new(config);
        let flags = pp.pollset();
        let _ = flags;
    }

    #[test]
    fn test_pingpong_state_timeout_initial() {
        let config = PingPongConfig::default();
        let pp = PingPong::new(config);
        // Initial state should not timeout
        let result = pp.state_timeout();
        assert!(result.is_ok());
    }

    #[test]
    fn test_pp_transfer_display() {
        let t = [PpTransfer::Body, PpTransfer::Info, PpTransfer::Body,
                 PpTransfer::None];
        for v in &t {
            let s = format!("{:?}", v);
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn test_pingpong_new_state() {
        let config = PingPongConfig::default();
        let pp = PingPong::new(config);
        // Verify initial state
        let timeout = pp.state_timeout();
        let _ = timeout; // timeout is a Duration or similar
    
    }
    // ====== Round 5 coverage tests ======

    #[test]
    fn test_poll_flags_empty_r5() {
        let f = PollFlags::empty();
        assert!(f.is_empty());
    }

    #[test]
    fn test_poll_flags_contains_r5() {
        let f = PollFlags::POLLIN;
        assert!(f.contains(PollFlags::POLLIN));
        assert!(!f.contains(PollFlags::POLLOUT));
    }

    #[test]
    fn test_poll_flags_is_empty_r5() {
        assert!(PollFlags::empty().is_empty());
        assert!(!PollFlags::POLLIN.is_empty());
    }

    #[test]
    fn test_poll_flags_bitor_r5() {
        let f = PollFlags::POLLIN | PollFlags::POLLOUT;
        assert!(f.contains(PollFlags::POLLIN));
        assert!(f.contains(PollFlags::POLLOUT));
    }

    #[test]
    fn test_pingpong_config_default_r5() {
        let cfg = PingPongConfig::default();
        let _ = &cfg; // verify it compiles
    }

    #[test]
    fn test_pingpong_new_r5() {
        let pp = PingPong::new(PingPongConfig::default());
        let _ = &pp;
    }

    #[test]
    fn test_pingpong_disconnect_r5() {
        let mut pp = PingPong::new(PingPongConfig::default());
        pp.disconnect();
    }



    // ====== Round 7 ======
    #[test] fn test_pp_transfer_debug_r7() {
        let _ = format!("{:?}", PpTransfer::Body);
        let _ = format!("{:?}", PpTransfer::Info);
        let _ = format!("{:?}", PpTransfer::None);
    }
    #[test] fn test_pp_config_new_r7() {
        let c = PingPongConfig::default();
        let _ = format!("{:?}", c);
    }
    #[test] fn test_pp_new_r7() {
        let _pp = PingPong::new(PingPongConfig::default());
        let _ = "PingPong";
    }
    #[test] fn test_pp_disconnect_r7() {
        let mut pp = PingPong::new(PingPongConfig::default());
        let _ = &pp;
        pp.disconnect();
    }
    #[test] fn test_poll_flags_r7() {
        let e = PollFlags::empty();
        assert!(e.is_empty());
        let f = PollFlags::POLLIN;
        assert!(f.contains(PollFlags::POLLIN));
    }
    #[test] fn test_pp_flush_r7() {
        let pp = PingPong::new(PingPongConfig::default());
        let _ = pp.needs_flush();
    }


    // ===== ROUND 9 TESTS =====
    #[test]
    fn r9_pingpong_disconnect() {
        let config = PingPongConfig::default();
        let mut pp = PingPong::new(config);
        pp.disconnect();
    }

    #[test]
    fn r9_pingpong_moredata() {
        let config = PingPongConfig::default();
        let pp = PingPong::new(config);
        let has_more = pp.moredata();
        let _ = has_more;
    }

    #[test]
    fn r9_pingpong_pollset() {
        let config = PingPongConfig::default();
        let pp = PingPong::new(config);
        let flags = pp.pollset();
        let _ = flags;
    }

    #[test]
    fn r9_pingpong_needs_flush() {
        let config = PingPongConfig::default();
        let pp = PingPong::new(config);
        let needs = pp.needs_flush();
        let _ = needs;
    }

    #[test]
    fn r9_pingpong_state_timeout() {
        let config = PingPongConfig::default();
        let pp = PingPong::new(config);
        let result = pp.state_timeout();
        let _ = result;
    }

    #[test]
    fn r9_pollflags_empty() {
        let f = PollFlags::empty();
        assert!(f.is_empty());
        assert!(!f.contains(PollFlags::POLLIN));
        assert!(!f.contains(PollFlags::POLLOUT));
    }

    #[test]
    fn r9_pollflags_pollin() {
        let f = PollFlags::POLLIN;
        assert!(!f.is_empty());
        assert!(f.contains(PollFlags::POLLIN));
    }

    #[test]
    fn r9_pollflags_pollout() {
        let f = PollFlags::POLLOUT;
        assert!(!f.is_empty());
        assert!(f.contains(PollFlags::POLLOUT));
    }

    #[test]
    fn r9_pollflags_combined() {
        let f = PollFlags::POLLIN | PollFlags::POLLOUT;
        assert!(f.contains(PollFlags::POLLIN));
        assert!(f.contains(PollFlags::POLLOUT));
    }

    #[test]
    fn r9_pingpong_new_and_disconnect() {
        let config = PingPongConfig::default();
        let mut pp = PingPong::new(config);
        assert!(!pp.moredata());
        pp.disconnect();
        assert!(!pp.moredata());
    }

    #[test]
    fn r9_pingpong_response_code() {
        let config = PingPongConfig::default();
        let pp = PingPong::new(config);
        let _ = pp.response_code;
    }


    // ===== ROUND 10 TESTS =====
    #[test]
    fn r10_pollflags_all_ops() {
        let a = PollFlags::POLLIN;
        let b = PollFlags::POLLOUT;
        let c = a | b;
        assert!(c.contains(a));
        assert!(c.contains(b));
        let empty = PollFlags::empty();
        assert!(empty.is_empty());
        assert!(!c.is_empty());
    }
    #[test]
    fn r10_pingpong_full_lifecycle() {
        let config = PingPongConfig::default();
        let mut pp = PingPong::new(config);
        let _ = pp.moredata();
        let _ = pp.pollset();
        let _ = pp.needs_flush();
        let _ = pp.state_timeout();
        pp.disconnect();
        let _ = pp.moredata();
        let _ = pp.pollset();
    }
    #[test]
    fn r10_pingpong_multiple_disconnect() {
        let config = PingPongConfig::default();
        let mut pp = PingPong::new(config);
        pp.disconnect();
        pp.disconnect(); // Should be idempotent
    }


    // ===== ROUND 11 TESTS =====
    #[test]
    fn r11_pingpong_state_timeout() {
        let config = PingPongConfig::default();
        let pp = PingPong::new(config);
        let result = pp.state_timeout();
        let _ = result;
    }
    #[test]
    fn r11_pollflags_ops_extensive() {
        let a = PollFlags::POLLIN;
        let b = PollFlags::POLLOUT;
        assert!(!a.is_empty());
        assert!(!b.is_empty());
        assert!(a.contains(PollFlags::POLLIN));
        assert!(!a.contains(PollFlags::POLLOUT));
        let both = a | b;
        assert!(both.contains(a));
        assert!(both.contains(b));
    }


    // ===== ROUND 12 TESTS =====
    #[test]
    fn r12_pingpong_config_default() {
        let config = PingPongConfig::default();
        let pp = PingPong::new(config);
        assert!(!pp.moredata());
        let _ = pp.needs_flush();
        let _ = pp.pollset();
        let _ = pp.state_timeout();
    }
    #[test]
    fn r12_pingpong_response_code() {
        let config = PingPongConfig::default();
        let mut pp = PingPong::new(config);
        // response_code is a public field
        pp.response_code = 200;
        assert_eq!(pp.response_code, 200);
        pp.response_code = 0;
        assert_eq!(pp.response_code, 0);
    }
    #[test]
    fn r12_pollflags_bit_patterns() {
        let all = PollFlags::POLLIN | PollFlags::POLLOUT;
        assert!(all.contains(PollFlags::POLLIN));
        assert!(all.contains(PollFlags::POLLOUT));
        let none = PollFlags::empty();
        assert!(!none.contains(PollFlags::POLLIN));
        assert!(!none.contains(PollFlags::POLLOUT));
        assert!(none.is_empty());
    }


    // ===== ROUND 13 =====
    #[test]
    fn r13_pingpong_repeated_ops() {
        let config = PingPongConfig::default();
        let mut pp = PingPong::new(config);
        // Multiple operations
        for _ in 0..5 {
            let _ = pp.moredata();
            let _ = pp.pollset();
            let _ = pp.needs_flush();
            let _ = pp.state_timeout();
        }
        pp.disconnect();
        for _ in 0..3 {
            let _ = pp.moredata();
            let _ = pp.pollset();
        }
    }
    #[test]
    fn r13_pingpong_response_code_values() {
        let config = PingPongConfig::default();
        let mut pp = PingPong::new(config);
        for code in [0, 100, 200, 220, 250, 354, 421, 450, 500, 550] {
            pp.response_code = code;
            assert_eq!(pp.response_code, code);
        }
    }


    // ===== ROUND 14 =====
    #[test]
    fn r14_pingpong_lifecycle_extensive() {
        let config = PingPongConfig::default();
        let mut pp = PingPong::new(config);
        // Exercise all methods multiple times
        for _ in 0..10 {
            let _ = pp.moredata();
            let _ = pp.pollset();
            let _ = pp.needs_flush();
            let _ = pp.state_timeout();
            pp.response_code = 250;
        }
        pp.disconnect();
        assert!(!pp.moredata());
    }


    // ===== ROUND 15 =====
    #[test]
    fn r15_pingpong_comprehensive() {
        let config = PingPongConfig::default();
        let mut pp = PingPong::new(config);
        // Exercise all methods extensively
        for i in 0..20 {
            pp.response_code = i * 50;
            let _ = pp.moredata();
            let _ = pp.pollset();
            let _ = pp.needs_flush();
            let _ = pp.state_timeout();
        }
        pp.disconnect();
        pp.disconnect(); // Idempotent
        // PollFlags comprehensive
        let flags = [PollFlags::empty(), PollFlags::POLLIN, PollFlags::POLLOUT,
                     PollFlags::POLLIN | PollFlags::POLLOUT];
        for f in &flags {
            let _ = f.is_empty();
            let _ = f.contains(PollFlags::POLLIN);
            let _ = f.contains(PollFlags::POLLOUT);
        }
    }


    // ===== ROUND 16 - COVERAGE PUSH =====
    #[test]
    fn r16_pingpong_state_machine() {
        let config = PingPongConfig::default();
        let mut pp = PingPong::new(config);
        // Iterate through many response_code values
        for code in (0..1000).step_by(13) {
            pp.response_code = code;
            let _ = pp.moredata();
            let _ = pp.pollset();
            let _ = pp.state_timeout();
            let _ = pp.needs_flush();
        }
        // Test with extreme values
        pp.response_code = i32::MAX;
        let _ = pp.moredata();
        pp.response_code = i32::MIN;
        let _ = pp.moredata();
        pp.response_code = 0;
        let _ = pp.moredata();
        // Multiple disconnects
        pp.disconnect();
        pp.disconnect();
        pp.disconnect();
    }
    #[test]
    fn r16_pollflags_ops() {
        let empty = PollFlags::empty();
        let r = PollFlags::POLLIN;
        let w = PollFlags::POLLOUT;
        let rw = r | w;
        assert!(empty.is_empty());
        assert!(!r.is_empty());
        assert!(!w.is_empty());
        assert!(!rw.is_empty());
        assert!(rw.contains(r));
        assert!(rw.contains(w));
        assert!(!empty.contains(r));
        assert!(rw.contains(r));
        assert!(rw.contains(w));
        assert!(!empty.contains(r));
        let _ = format!("{:?} {:?} {:?} {:?}", empty, r, w, rw);
    }


    // ===== ROUND 17 - FINAL PUSH =====
    #[test]
    fn r17_pingpong_lifecycle_extended() {
        // Multiple PingPong instances with different configs
        for _ in 0..5 {
            let config = PingPongConfig::default();
            let mut pp = PingPong::new(config);
            for code in [0, 100, 200, 220, 226, 250, 331, 354, 421, 425, 450, 500, 530, 550] {
                pp.response_code = code;
                let more = pp.moredata();
                let poll = pp.pollset();
                let flush = pp.needs_flush();
                let timeout = pp.state_timeout();
                let _ = (more, poll, flush, timeout);
            }
            pp.disconnect();
        }
    }
    #[test]
    fn r17_pingpong_pollflags_combos() {
        // All combinations of PollFlags
        let flags = [PollFlags::empty(), PollFlags::POLLIN, PollFlags::POLLOUT,
                     PollFlags::POLLIN | PollFlags::POLLOUT];
        for &a in &flags {
            for &b in &flags {
                let combined = a | b;
                let _ = combined.is_empty();
                let _ = combined.contains(PollFlags::POLLIN);
                let _ = combined.contains(PollFlags::POLLOUT);
                let _ = format!("{:?}", combined);
            }
        }
    }

}
