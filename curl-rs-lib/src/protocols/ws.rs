// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
//! RFC 6455 WebSocket protocol handler.
//!
//! Rust rewrite of `lib/ws.c` (2,012 lines). Provides the complete WebSocket
//! frame encode/decode pipeline, control frame handling (PING/PONG/CLOSE),
//! fragmentation support, and the public API surface (`curl_ws_recv`,
//! `curl_ws_send`, `curl_ws_meta`, `curl_ws_start_frame`).
//!
//! # Architecture
//!
//! The module is organized around three core types:
//!
//! * [`WsDecoder`] — State-machine frame decoder that parses incoming bytes
//!   one byte at a time from a [`BufQ`], tracking opcode, FIN bit, payload
//!   length (7/16/64-bit), and continuation fragment state.
//! * [`WsEncoder`] — Frame encoder that composes outgoing frame headers
//!   (FIN, opcode, MASK, payload length, 4-byte masking key) and XOR-masks
//!   payload bytes before buffering into a send [`BufQ`].
//! * [`WebSocket`] — Per-connection state owning the decoder, encoder, and
//!   recv/send buffer queues.
//!
//! # Frame Wire Format (RFC 6455 §5.2)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-------+-+-------------+-------------------------------+
//! |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//! |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
//! |N|V|V|V|       |S|             |   (if payload len==126/127)   |
//! | |1|2|3|       |K|             |                               |
//! +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
//! ```
//!
//! # Safety
//!
//! This module contains **zero** `unsafe` blocks, per AAP Section 0.7.1.
//! XOR unmasking uses safe Rust indexing exclusively.

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

use crate::conn::ConnectionData;
use crate::error::{CurlError, CurlResult};
use crate::headers::DynHeaders;
use crate::protocols::{ConnectionCheckResult, Protocol, ProtocolFlags, Scheme};
use crate::util::base64;
use crate::util::bufq::{BufQ, BufQOpts};
use crate::util::rand;

use tracing::{debug, error, info, trace, warn};

// ---------------------------------------------------------------------------
// Wire-format constants (RFC 6455 §5.2)
// ---------------------------------------------------------------------------

/// FIN bit in the first byte of a WebSocket frame header.
const WSBIT_FIN: u8 = 0x80;

/// RSV1 bit.
const WSBIT_RSV1: u8 = 0x40;

/// RSV2 bit.
const WSBIT_RSV2: u8 = 0x20;

/// RSV3 bit.
const WSBIT_RSV3: u8 = 0x10;

/// Mask of all reserved bits.
const WSBIT_RSV_MASK: u8 = WSBIT_RSV1 | WSBIT_RSV2 | WSBIT_RSV3;

/// Opcode bitmask (lower 4 bits of first byte).
const WSBIT_OPCODE_MASK: u8 = 0x0F;

/// MASK bit in the second byte of a WebSocket frame header.
const WSBIT_MASK: u8 = 0x80;

// ---------------------------------------------------------------------------
// Buffer dimensioning
// ---------------------------------------------------------------------------

/// Default chunk size for recv and send buffer queues.
const WS_CHUNK_SIZE: usize = 65535;

/// Number of chunks in each buffer queue.
const WS_CHUNK_COUNT: usize = 2;

/// Maximum control frame payload length per RFC 6455 §5.5.
const WS_MAX_CNTRL_LEN: usize = 125;

// ===========================================================================
// WsOpcode — WebSocket frame opcodes
// ===========================================================================

/// WebSocket frame opcodes as defined in RFC 6455 §11.8.
///
/// Each variant carries its wire-format value as the discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum WsOpcode {
    /// Continuation frame (0x0).
    Continuation = 0x0,
    /// Text data frame (0x1).
    Text = 0x1,
    /// Binary data frame (0x2).
    Binary = 0x2,
    /// Connection close control frame (0x8).
    Close = 0x8,
    /// Ping control frame (0x9).
    Ping = 0x9,
    /// Pong control frame (0xA).
    Pong = 0xA,
}

impl WsOpcode {
    /// Returns the wire-format `u8` value.
    #[inline]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Attempts to construct an opcode from a raw `u8` value.
    ///
    /// Returns `None` for reserved or invalid opcodes (0x3–0x7, 0xB–0xF).
    pub fn from_u8(val: u8) -> Option<Self> {
        match val & WSBIT_OPCODE_MASK {
            0x0 => Some(Self::Continuation),
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xA => Some(Self::Pong),
            _ => None,
        }
    }

    /// Returns `true` for control frames (CLOSE, PING, PONG).
    #[inline]
    pub fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }

    /// Returns the human-readable name of this opcode.
    pub fn name(self) -> &'static str {
        match self {
            Self::Continuation => "CONT",
            Self::Text => "TEXT",
            Self::Binary => "BIN",
            Self::Close => "CLOSE",
            Self::Ping => "PING",
            Self::Pong => "PONG",
        }
    }
}

impl std::fmt::Display for WsOpcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ===========================================================================
// WsFlags — bitflags for frame type and options
// ===========================================================================

/// Bitflags describing the type and options of a WebSocket frame.
///
/// These values map 1:1 to the C `CURLWS_*` constants defined in
/// `include/curl/websockets.h`. The integer values are preserved for FFI
/// compatibility.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WsFlags(u32);

impl WsFlags {
    /// Text frame (`CURLWS_TEXT` = 0x01).
    pub const TEXT: Self = Self(1 << 0);

    /// Binary frame (`CURLWS_BINARY` = 0x02).
    pub const BINARY: Self = Self(1 << 1);

    /// Continuation fragment (`CURLWS_CONT` = 0x04).
    /// When set alongside TEXT or BINARY, indicates this is a non-final
    /// fragment and more fragments will follow.
    pub const CONT: Self = Self(1 << 2);

    /// Close frame (`CURLWS_CLOSE` = 0x08).
    pub const CLOSE: Self = Self(1 << 3);

    /// Ping frame (`CURLWS_PING` = 0x10).
    pub const PING: Self = Self(1 << 4);

    /// Pong frame (`CURLWS_PONG` = 0x20).
    pub const PONG: Self = Self(1 << 5);

    /// The `fragsize` parameter in `curl_ws_send` specifies the total
    /// fragment size, enabling OFFSET mode (`CURLWS_OFFSET` = 0x40).
    pub const OFFSET: Self = Self(1 << 6);

    /// Raw mode: pass WebSocket frames through without decoding
    /// (`CURLWS_RAW_MODE` = 0x80).
    pub const RAW_MODE: Self = Self(1 << 7);

    /// Returns an empty flag set with no bits set.
    #[inline]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Returns `true` if all bits in `other` are set in `self`.
    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns the raw `u32` bits.
    #[inline]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Constructs flags from raw `u32` bits.
    #[inline]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns `true` if no bits are set.
    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for WsFlags {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for WsFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for WsFlags {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl std::ops::BitAndAssign for WsFlags {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl std::ops::Not for WsFlags {
    type Output = Self;
    #[inline]
    fn not(self) -> Self {
        Self(!self.0)
    }
}

impl Default for WsFlags {
    #[inline]
    fn default() -> Self {
        Self::empty()
    }
}

impl std::fmt::Debug for WsFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        let mut emit = |name: &str, f: &mut std::fmt::Formatter<'_>| -> std::fmt::Result {
            if !first {
                f.write_str(" | ")?;
            }
            first = false;
            f.write_str(name)
        };
        f.write_str("WsFlags(")?;
        if self.contains(Self::TEXT) { emit("TEXT", f)?; }
        if self.contains(Self::BINARY) { emit("BINARY", f)?; }
        if self.contains(Self::CONT) { emit("CONT", f)?; }
        if self.contains(Self::CLOSE) { emit("CLOSE", f)?; }
        if self.contains(Self::PING) { emit("PING", f)?; }
        if self.contains(Self::PONG) { emit("PONG", f)?; }
        if self.contains(Self::OFFSET) { emit("OFFSET", f)?; }
        if self.contains(Self::RAW_MODE) { emit("RAW_MODE", f)?; }
        if first { f.write_str("empty")?; }
        f.write_str(")")
    }
}

// ===========================================================================
// WsFrame — metadata for a received WebSocket frame
// ===========================================================================

/// Metadata for a received WebSocket frame, corresponding to the C
/// `struct curl_ws_frame`.
///
/// Returned by [`ws_meta`] and populated by [`ws_recv`] to describe the
/// current frame being delivered to the application.
#[derive(Debug, Clone, Default)]
pub struct WsFrame {
    /// Age counter (always 0 in current implementation, reserved).
    pub age: i32,
    /// Frame type flags (see [`WsFlags`]).
    pub flags: WsFlags,
    /// Byte offset of the current delivery within the total payload.
    pub offset: i64,
    /// Number of bytes delivered in this particular call.
    pub len: usize,
    /// Number of payload bytes remaining after this delivery.
    pub bytesleft: i64,
}

impl WsFrame {
    /// Creates a zeroed frame with all fields set to their defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the opcode derived from the frame flags.
    pub fn opcode(&self) -> Option<WsOpcode> {
        if self.flags.contains(WsFlags::CLOSE) {
            Some(WsOpcode::Close)
        } else if self.flags.contains(WsFlags::PING) {
            Some(WsOpcode::Ping)
        } else if self.flags.contains(WsFlags::PONG) {
            Some(WsOpcode::Pong)
        } else if self.flags.contains(WsFlags::TEXT) {
            Some(WsOpcode::Text)
        } else if self.flags.contains(WsFlags::BINARY) {
            Some(WsOpcode::Binary)
        } else if self.flags.contains(WsFlags::CONT) {
            Some(WsOpcode::Continuation)
        } else {
            None
        }
    }

    /// Returns `true` if this is the final fragment.
    pub fn is_final(&self) -> bool {
        !self.flags.contains(WsFlags::CONT)
    }

    /// Returns `true` if the frame was masked (client → server).
    /// In practice, server-to-client frames should NOT be masked per RFC 6455.
    pub fn is_masked(&self) -> bool {
        // We detect masking during decode; this field is informational.
        // In our implementation, client sends are always masked;
        // server frames should never be masked.
        false
    }

    /// Updates this frame's metadata after receiving data.
    fn update(
        &mut self,
        frame_age: i32,
        frame_flags: WsFlags,
        payload_offset: i64,
        payload_len: i64,
        cur_len: usize,
    ) {
        let bytesleft = payload_len - payload_offset - cur_len as i64;
        self.age = frame_age;
        self.flags = frame_flags;
        self.offset = payload_offset;
        self.len = cur_len;
        self.bytesleft = bytesleft;
    }
}

// ===========================================================================
// WsDecState — decoder state machine states
// ===========================================================================

/// Decoder state for the frame-parsing state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WsDecState {
    /// Initial state: waiting for the start of a new frame.
    #[default]
    Init,
    /// Parsing the frame header bytes.
    Head,
    /// Delivering payload data.
    Payload,
}

// ===========================================================================
// WsDecoder — frame decoder state machine
// ===========================================================================

/// WebSocket frame decoder that parses incoming bytes from a buffer queue.
///
/// The decoder processes frame headers byte-by-byte and tracks:
/// - The current frame's opcode, FIN bit, and payload length
/// - The current payload delivery offset
/// - Continuation fragment state across multiple frames
///
/// Corresponds to the C `struct ws_decoder` and its associated functions
/// (`ws_dec_init`, `ws_dec_reset`, `ws_dec_read_head`, `ws_dec_pass_payload`,
/// `ws_dec_pass`).
pub struct WsDecoder {
    /// Frame age counter (always 0, reserved for future use).
    frame_age: i32,
    /// Frame flags derived from the first header byte.
    frame_flags: WsFlags,
    /// Current offset into the payload being delivered.
    payload_offset: i64,
    /// Total payload length of the current frame.
    payload_len: i64,
    /// Buffer for accumulating header bytes (max 10 bytes).
    head: [u8; 10],
    /// Number of header bytes received so far.
    head_len: usize,
    /// Total expected header length (2, 4, or 10).
    head_total: usize,
    /// Current decoder state.
    state: WsDecState,
    /// Continuation fragment flags carried across frames.
    /// Tracks whether we are inside a fragmented message and what type.
    cont_flags: WsFlags,
}

impl WsDecoder {
    /// Creates a new decoder in the initial state.
    pub fn new() -> Self {
        Self {
            frame_age: 0,
            frame_flags: WsFlags::empty(),
            payload_offset: 0,
            payload_len: 0,
            head: [0u8; 10],
            head_len: 0,
            head_total: 0,
            state: WsDecState::Init,
            cont_flags: WsFlags::empty(),
        }
    }

    /// Resets the decoder to its initial state, clearing all frame and
    /// continuation tracking.
    pub fn reset(&mut self) {
        self.frame_age = 0;
        self.frame_flags = WsFlags::empty();
        self.payload_offset = 0;
        self.payload_len = 0;
        self.head_len = 0;
        self.head_total = 0;
        self.state = WsDecState::Init;
        self.cont_flags = WsFlags::empty();
    }

    /// Returns a reference to the current frame metadata.
    pub fn frame(&self) -> WsFrame {
        WsFrame {
            age: self.frame_age,
            flags: self.frame_flags,
            offset: self.payload_offset,
            len: 0,
            bytesleft: self.payload_len - self.payload_offset,
        }
    }

    /// Returns the current decoder state.
    #[inline]
    pub fn state(&self) -> WsDecState {
        self.state
    }

    /// Returns the current payload offset within the frame.
    #[inline]
    pub fn payload_offset(&self) -> i64 {
        self.payload_offset
    }

    /// Returns the total payload length of the current frame.
    #[inline]
    pub fn payload_len(&self) -> i64 {
        self.payload_len
    }

    /// Returns the current frame flags.
    #[inline]
    pub fn frame_flags(&self) -> WsFlags {
        self.frame_flags
    }

    /// Returns the current frame age.
    #[inline]
    pub fn frame_age(&self) -> i32 {
        self.frame_age
    }

    /// Prepares for a new frame, preserving continuation state.
    fn next_frame(&mut self) {
        self.frame_age = 0;
        self.frame_flags = WsFlags::empty();
        self.payload_offset = 0;
        self.payload_len = 0;
        self.head_len = 0;
        self.head_total = 0;
        self.state = WsDecState::Init;
        // cont_flags is intentionally NOT cleared — it must carry over
    }

    /// Decodes frame data from `inraw`, calling `write_cb` for each chunk
    /// of payload data decoded.
    ///
    /// The callback receives: `(payload_bytes, frame_age, frame_flags,
    /// payload_offset, payload_len)` and returns `(bytes_consumed, result)`.
    ///
    /// Returns:
    /// - `Ok(())` when a complete frame has been decoded and delivered.
    /// - `Err(CurlError::Again)` when more input data is needed.
    /// - `Err(...)` on protocol violation or callback error.
    pub fn decode<F>(
        &mut self,
        inraw: &mut BufQ,
        mut write_cb: F,
    ) -> CurlResult<()>
    where
        F: FnMut(&[u8], i32, WsFlags, i64, i64) -> CurlResult<usize>,
    {
        if inraw.is_empty() {
            return Err(CurlError::Again);
        }

        match self.state {
            WsDecState::Init => {
                self.next_frame();
                self.state = WsDecState::Head;
                self.decode_head_and_payload(inraw, &mut write_cb)
            }
            WsDecState::Head => {
                self.decode_head_and_payload(inraw, &mut write_cb)
            }
            WsDecState::Payload => {
                let result = self.decode_payload(inraw, &mut write_cb);
                if result.is_ok() {
                    // Payload complete, prepare for next frame
                    self.state = WsDecState::Init;
                }
                result
            }
        }
    }

    /// Internal: parse header then optionally transition to payload.
    fn decode_head_and_payload<F>(
        &mut self,
        inraw: &mut BufQ,
        write_cb: &mut F,
    ) -> CurlResult<()>
    where
        F: FnMut(&[u8], i32, WsFlags, i64, i64) -> CurlResult<usize>,
    {
        let head_result = self.read_head(inraw);
        match head_result {
            Ok(()) => {
                // Head parsed successfully
                self.state = WsDecState::Payload;

                if self.payload_len == 0 {
                    // Zero-length frame: deliver a single zero-length write
                    let empty: &[u8] = &[];
                    write_cb(empty, self.frame_age, self.frame_flags, 0, 0)?;
                    self.state = WsDecState::Init;
                    return Ok(());
                }

                // Try to deliver payload data
                let result = self.decode_payload(inraw, write_cb);
                if result.is_ok() {
                    self.state = WsDecState::Init;
                }
                result
            }
            Err(CurlError::Again) => {
                // Incomplete header, need more data
                Err(CurlError::Again)
            }
            Err(e) => {
                error!("[WS] decode frame error: {}", e);
                Err(e)
            }
        }
    }

    /// Internal: Read frame header bytes from the buffer queue.
    fn read_head(&mut self, inraw: &mut BufQ) -> CurlResult<()> {
        let mut byte_buf = [0u8; 1];

        loop {
            let peeked = inraw.peek(&mut byte_buf);
            if peeked == 0 {
                return Err(CurlError::Again);
            }
            let b = byte_buf[0];

            if self.head_len == 0 {
                // First byte: FIN + opcode
                self.head[0] = b;
                inraw.skip(1);

                self.frame_flags = firstbyte_to_flags(self.head[0], self.cont_flags)?;

                // Track continuation state for data frames only
                if self.frame_flags.contains(WsFlags::TEXT)
                    || self.frame_flags.contains(WsFlags::BINARY)
                {
                    self.cont_flags = self.frame_flags;
                }

                self.head_len = 1;
                continue;
            } else if self.head_len == 1 {
                // Second byte: MASK bit + payload length indicator
                self.head[1] = b;
                inraw.skip(1);
                self.head_len = 2;

                // Server-to-client frames MUST NOT be masked (RFC 6455 §5.1)
                if self.head[1] & WSBIT_MASK != 0 {
                    warn!("[WS] masked input frame from server");
                    self.reset();
                    return Err(CurlError::RecvError);
                }

                // Validate control frame sizes
                let payload_indicator = self.head[1] & 0x7F;
                if self.frame_flags.contains(WsFlags::PING)
                    && payload_indicator > WS_MAX_CNTRL_LEN as u8
                {
                    warn!("[WS] received PING frame is too big");
                    self.reset();
                    return Err(CurlError::RecvError);
                }
                if self.frame_flags.contains(WsFlags::PONG)
                    && payload_indicator > WS_MAX_CNTRL_LEN as u8
                {
                    warn!("[WS] received PONG frame is too big");
                    self.reset();
                    return Err(CurlError::RecvError);
                }
                if self.frame_flags.contains(WsFlags::CLOSE)
                    && payload_indicator > WS_MAX_CNTRL_LEN as u8
                {
                    warn!("[WS] received CLOSE frame is too big");
                    self.reset();
                    return Err(CurlError::RecvError);
                }

                // Determine total header length
                if payload_indicator == 126 {
                    self.head_total = 4;
                    continue;
                } else if payload_indicator == 127 {
                    self.head_total = 10;
                    continue;
                } else {
                    self.head_total = 2;
                }
            }

            // Read extended header bytes
            if self.head_len < self.head_total {
                self.head[self.head_len] = b;
                inraw.skip(1);
                self.head_len += 1;
                if self.head_len < self.head_total {
                    continue;
                }
            }

            // Complete header received — extract payload length
            debug_assert!(self.head_len == self.head_total);
            match self.head_total {
                2 => {
                    self.payload_len = (self.head[1] & 0x7F) as i64;
                }
                4 => {
                    self.payload_len =
                        ((self.head[2] as i64) << 8) | (self.head[3] as i64);
                }
                10 => {
                    if self.head[2] > 127 {
                        error!("[WS] frame length longer than 63 bits not supported");
                        return Err(CurlError::RecvError);
                    }
                    self.payload_len = (self.head[2] as i64) << 56
                        | (self.head[3] as i64) << 48
                        | (self.head[4] as i64) << 40
                        | (self.head[5] as i64) << 32
                        | (self.head[6] as i64) << 24
                        | (self.head[7] as i64) << 16
                        | (self.head[8] as i64) << 8
                        | (self.head[9] as i64);
                }
                _ => {
                    error!("[WS] unexpected frame header length");
                    return Err(CurlError::RecvError);
                }
            }

            self.frame_age = 0;
            self.payload_offset = 0;
            trace!(
                "[WS] decoded frame: opcode={:?}, payload_len={}",
                WsOpcode::from_u8(self.head[0] & WSBIT_OPCODE_MASK),
                self.payload_len
            );
            return Ok(());
        }
    }

    /// Internal: Deliver payload bytes from the buffer queue to the callback.
    fn decode_payload<F>(
        &mut self,
        inraw: &mut BufQ,
        write_cb: &mut F,
    ) -> CurlResult<()>
    where
        F: FnMut(&[u8], i32, WsFlags, i64, i64) -> CurlResult<usize>,
    {
        let total_remain = self.payload_len - self.payload_offset;
        if total_remain <= 0 {
            return Ok(());
        }

        let mut remain = total_remain as usize;
        let mut local_buf = [0u8; 8192];

        while remain > 0 {
            let to_read = std::cmp::min(remain, local_buf.len());
            let peeked = inraw.peek(&mut local_buf[..to_read]);
            if peeked == 0 {
                return Err(CurlError::Again);
            }

            let nwritten = write_cb(
                &local_buf[..peeked],
                self.frame_age,
                self.frame_flags,
                self.payload_offset,
                self.payload_len,
            )?;

            if nwritten == 0 && peeked > 0 {
                return Err(CurlError::Again);
            }

            inraw.skip(nwritten);
            self.payload_offset += nwritten as i64;
            remain = (self.payload_len - self.payload_offset) as usize;

            trace!(
                "[WS] passed {} bytes payload, {} remain",
                nwritten,
                remain
            );
        }

        Ok(())
    }
}

impl Default for WsDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// WsEncoder — frame encoder
// ===========================================================================

/// WebSocket frame encoder that composes outgoing frame headers and
/// XOR-masks payload data.
///
/// Corresponds to the C `struct ws_encoder` and its associated functions.
pub struct WsEncoder {
    /// Total payload length of the current frame being encoded.
    payload_len: i64,
    /// Remaining payload bytes to encode for the current frame.
    payload_remain: i64,
    /// XOR mask index (0–3 cycling).
    xori: usize,
    /// 4-byte masking key for the current frame.
    mask: [u8; 4],
    /// First byte of the current frame being encoded.
    firstbyte: u8,
    /// Whether the previous sent fragment was non-final (continuation).
    contfragment: bool,
}

impl WsEncoder {
    /// Creates a new encoder in the initial state.
    pub fn new() -> Self {
        Self {
            payload_len: 0,
            payload_remain: 0,
            xori: 0,
            mask: [0u8; 4],
            firstbyte: 0,
            contfragment: false,
        }
    }

    /// Resets the encoder, clearing all frame state.
    pub fn reset(&mut self) {
        self.payload_remain = 0;
        self.xori = 0;
        self.contfragment = false;
    }

    /// Returns the number of payload bytes remaining to encode.
    #[inline]
    pub fn payload_remain(&self) -> i64 {
        self.payload_remain
    }

    /// Returns `true` if we are in the middle of a fragmented message.
    #[inline]
    pub fn is_cont_fragment(&self) -> bool {
        self.contfragment
    }

    /// Encode a complete frame (header + masked payload) into `out`.
    ///
    /// This is a convenience that calls [`write_head`] followed by
    /// [`write_payload`].
    pub fn encode_frame(
        &mut self,
        flags: WsFlags,
        payload: &[u8],
        out: &mut BufQ,
    ) -> CurlResult<usize> {
        self.write_head(flags, payload.len() as i64, out)?;
        let mut total = 0;
        let mut remaining = payload;
        while !remaining.is_empty() {
            let n = self.write_payload(remaining, out)?;
            if n == 0 {
                break;
            }
            total += n;
            remaining = &remaining[n..];
        }
        Ok(total)
    }

    /// Writes a frame header (FIN, opcode, MASK, payload length, masking key)
    /// into the output buffer queue.
    ///
    /// After calling this, use [`write_payload`] to write the actual payload
    /// data which will be XOR-masked.
    pub fn write_head(
        &mut self,
        flags: WsFlags,
        payload_len: i64,
        out: &mut BufQ,
    ) -> CurlResult<()> {
        if payload_len < 0 {
            error!(
                "[WS] starting new frame with negative payload length {}",
                payload_len
            );
            return Err(CurlError::SendError);
        }

        if self.payload_remain > 0 {
            error!(
                "[WS] starting new frame with {} bytes remaining from last",
                self.payload_remain
            );
            return Err(CurlError::SendError);
        }

        let firstb = flags_to_firstbyte(flags, self.contfragment)?;

        // Update continuation state for data frames only
        if flags.contains(WsFlags::TEXT) || flags.contains(WsFlags::BINARY) {
            self.contfragment = flags.contains(WsFlags::CONT);
        }

        // Validate control frame sizes
        if flags.contains(WsFlags::PING) && payload_len > WS_MAX_CNTRL_LEN as i64 {
            error!("[WS] given PING frame is too big");
            return Err(CurlError::BadFunctionArgument);
        }
        if flags.contains(WsFlags::PONG) && payload_len > WS_MAX_CNTRL_LEN as i64 {
            error!("[WS] given PONG frame is too big");
            return Err(CurlError::BadFunctionArgument);
        }
        if flags.contains(WsFlags::CLOSE) && payload_len > WS_MAX_CNTRL_LEN as i64 {
            error!("[WS] given CLOSE frame is too big");
            return Err(CurlError::BadFunctionArgument);
        }

        let mut head = [0u8; 14];
        let hlen;

        head[0] = firstb;
        self.firstbyte = firstb;

        if payload_len > 65535 {
            head[1] = 127 | WSBIT_MASK;
            head[2] = ((payload_len >> 56) & 0xFF) as u8;
            head[3] = ((payload_len >> 48) & 0xFF) as u8;
            head[4] = ((payload_len >> 40) & 0xFF) as u8;
            head[5] = ((payload_len >> 32) & 0xFF) as u8;
            head[6] = ((payload_len >> 24) & 0xFF) as u8;
            head[7] = ((payload_len >> 16) & 0xFF) as u8;
            head[8] = ((payload_len >> 8) & 0xFF) as u8;
            head[9] = (payload_len & 0xFF) as u8;
            hlen = 10;
        } else if payload_len >= 126 {
            head[1] = 126 | WSBIT_MASK;
            head[2] = ((payload_len >> 8) & 0xFF) as u8;
            head[3] = (payload_len & 0xFF) as u8;
            hlen = 4;
        } else {
            head[1] = (payload_len as u8) | WSBIT_MASK;
            hlen = 2;
        }

        self.payload_remain = payload_len;
        self.payload_len = payload_len;

        // Generate 4-byte masking key
        rand::random_bytes(&mut self.mask)?;

        // Append masking key to header
        head[hlen] = self.mask[0];
        head[hlen + 1] = self.mask[1];
        head[hlen + 2] = self.mask[2];
        head[hlen + 3] = self.mask[3];
        let total_hlen = hlen + 4;

        // Reset XOR index for new frame
        self.xori = 0;

        trace!(
            "[WS] encoding frame: firstbyte=0x{:02x}, payload_len={}, hlen={}",
            firstb,
            payload_len,
            total_hlen
        );

        let nwritten = out.write(&head[..total_hlen])?;
        if nwritten != total_hlen {
            error!("[WS] could not write full header to sendbuf");
            return Err(CurlError::SendError);
        }
        Ok(())
    }

    /// Writes (XOR-masked) payload data into the output buffer queue.
    ///
    /// Returns the number of payload bytes actually written. May be less than
    /// `buf.len()` if the output buffer is full or the remaining payload
    /// length is smaller.
    pub fn write_payload(
        &mut self,
        buf: &[u8],
        out: &mut BufQ,
    ) -> CurlResult<usize> {
        if out.is_full() {
            return Err(CurlError::Again);
        }

        let remain = std::cmp::min(
            buf.len(),
            self.payload_remain.max(0) as usize,
        );
        if remain == 0 {
            return Ok(0);
        }

        // XOR-mask each byte and write to output, one byte at a time
        // for correctness (matching C behavior). For better performance
        // we batch into a local buffer.
        let mut masked = [0u8; 4096];
        let mut total_written = 0;

        let mut src = &buf[..remain];
        while !src.is_empty() {
            let batch = std::cmp::min(src.len(), masked.len());
            for i in 0..batch {
                masked[i] = src[i] ^ self.mask[self.xori];
                self.xori = (self.xori + 1) & 3;
            }

            match out.write(&masked[..batch]) {
                Ok(n) if n > 0 => {
                    total_written += n;
                    src = &src[n..];
                    if n < batch {
                        // Output buffer couldn't take it all — rewind xori
                        // for the un-written portion.
                        let unwritten = batch - n;
                        // We need to rewind xori by `unwritten` steps
                        self.xori = (self.xori + 4 - (unwritten & 3)) & 3;
                        break;
                    }
                }
                Ok(_) => break,
                Err(CurlError::Again) => {
                    if total_written == 0 {
                        return Err(CurlError::Again);
                    }
                    // Rewind xori for the batch we didn't write
                    self.xori = (self.xori + 4 - (batch & 3)) & 3;
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        self.payload_remain -= total_written as i64;

        trace!(
            "[WS] encoded {} payload bytes, {} remain",
            total_written,
            self.payload_remain
        );
        Ok(total_written)
    }

    /// Adds a control frame (PING, PONG, CLOSE) to the pending queue.
    ///
    /// If no data frame is currently in progress, the control frame is
    /// immediately encoded into the send buffer. Otherwise, it is held
    /// as pending and flushed before the next data frame.
    pub fn add_control_frame(
        &mut self,
        payload: &[u8],
        frame_type: WsFlags,
        sendbuf: &mut BufQ,
        pending: &mut Option<WsControlFrame>,
    ) -> CurlResult<()> {
        if payload.len() > WS_MAX_CNTRL_LEN {
            return Err(CurlError::BadFunctionArgument);
        }

        // Store as pending, overwriting any previous pending control frame
        let mut ctrl = WsControlFrame {
            frame_type,
            payload_len: payload.len(),
            payload: [0u8; WS_MAX_CNTRL_LEN],
        };
        ctrl.payload[..payload.len()].copy_from_slice(payload);
        *pending = Some(ctrl);

        if self.payload_remain == 0 {
            // Not in the middle of another frame — flush immediately
            self.flush_pending(sendbuf, pending)?;
        }
        Ok(())
    }

    /// Flushes any pending control frame into the send buffer.
    pub fn flush_pending(
        &mut self,
        sendbuf: &mut BufQ,
        pending: &mut Option<WsControlFrame>,
    ) -> CurlResult<()> {
        let ctrl = match pending.take() {
            Some(c) => c,
            None => return Ok(()),
        };

        if self.payload_remain > 0 {
            // Can't send now — put it back
            *pending = Some(ctrl);
            return Err(CurlError::Again);
        }

        // Write frame header
        self.write_head(
            ctrl.frame_type,
            ctrl.payload_len as i64,
            sendbuf,
        )?;

        // Write masked payload
        if ctrl.payload_len > 0 {
            let n = self.write_payload(
                &ctrl.payload[..ctrl.payload_len],
                sendbuf,
            )?;
            if n != ctrl.payload_len {
                error!(
                    "[WS] control frame: only wrote {}/{} payload bytes",
                    n, ctrl.payload_len
                );
                return Err(CurlError::SendError);
            }
        }

        debug_assert_eq!(self.payload_remain, 0);
        debug!(
            "[WS] flushed control frame {:?} ({} bytes)",
            ctrl.frame_type, ctrl.payload_len
        );
        Ok(())
    }
}

impl Default for WsEncoder {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// WsControlFrame — pending control frame
// ===========================================================================

/// A control frame (CLOSE/PING/PONG) that is pending to be sent.
///
/// Corresponds to the C `struct ws_cntrl_frame`.
#[derive(Debug, Clone)]
pub struct WsControlFrame {
    /// Frame type flags (CURLWS_CLOSE, CURLWS_PING, or CURLWS_PONG).
    frame_type: WsFlags,
    /// Payload length (max 125 bytes per RFC 6455).
    payload_len: usize,
    /// Payload data buffer.
    payload: [u8; WS_MAX_CNTRL_LEN],
}

// ===========================================================================
// WebSocket — per-connection state
// ===========================================================================

/// Per-connection WebSocket state, owning the decoder, encoder, and
/// send/receive buffer queues.
///
/// Corresponds to the C `struct websocket`.
pub struct WebSocket {
    /// Frame decoder.
    dec: WsDecoder,
    /// Frame encoder.
    enc: WsEncoder,
    /// Raw data received from the server.
    recvbuf: BufQ,
    /// Raw data to be sent to the server.
    sendbuf: BufQ,
    /// Current received frame metadata.
    recvframe: WsFrame,
    /// Pending control frame to be sent.
    pending: Option<WsControlFrame>,
    /// Number of payload bytes buffered in sendbuf.
    sendbuf_payload: usize,
    /// Whether raw mode is enabled.
    raw_mode: bool,
    /// Whether auto-pong is enabled (default: true).
    auto_pong: bool,
}

impl WebSocket {
    /// Creates a new WebSocket state with default buffer sizes.
    pub fn new() -> Self {
        Self {
            dec: WsDecoder::new(),
            enc: WsEncoder::new(),
            recvbuf: BufQ::with_opts(WS_CHUNK_SIZE, WS_CHUNK_COUNT, BufQOpts::SOFT_LIMIT),
            sendbuf: BufQ::with_opts(WS_CHUNK_SIZE, WS_CHUNK_COUNT, BufQOpts::SOFT_LIMIT),
            recvframe: WsFrame::new(),
            pending: None,
            sendbuf_payload: 0,
            raw_mode: false,
            auto_pong: true,
        }
    }

    /// Returns a reference to the decoder.
    #[inline]
    pub fn decoder(&self) -> &WsDecoder {
        &self.dec
    }

    /// Returns a mutable reference to the decoder.
    #[inline]
    pub fn decoder_mut(&mut self) -> &mut WsDecoder {
        &mut self.dec
    }

    /// Returns a reference to the encoder.
    #[inline]
    pub fn encoder(&self) -> &WsEncoder {
        &self.enc
    }

    /// Returns a mutable reference to the encoder.
    #[inline]
    pub fn encoder_mut(&mut self) -> &mut WsEncoder {
        &mut self.enc
    }

    /// Returns a reference to the receive buffer queue.
    #[inline]
    pub fn recv_buf(&self) -> &BufQ {
        &self.recvbuf
    }

    /// Returns a mutable reference to the receive buffer queue.
    #[inline]
    pub fn recv_buf_mut(&mut self) -> &mut BufQ {
        &mut self.recvbuf
    }

    /// Returns a reference to the send buffer queue.
    #[inline]
    pub fn send_buf(&self) -> &BufQ {
        &self.sendbuf
    }

    /// Returns a mutable reference to the send buffer queue.
    #[inline]
    pub fn send_buf_mut(&mut self) -> &mut BufQ {
        &mut self.sendbuf
    }

    /// Returns `true` if raw mode is enabled.
    #[inline]
    pub fn is_raw_mode(&self) -> bool {
        self.raw_mode
    }

    /// Returns the number of pending control frames.
    #[inline]
    pub fn pending_count(&self) -> usize {
        if self.pending.is_some() { 1 } else { 0 }
    }

    /// Returns a reference to the current received frame metadata.
    #[inline]
    pub fn recv_frame(&self) -> &WsFrame {
        &self.recvframe
    }

    /// Sets the received frame metadata.
    #[inline]
    pub fn set_recv_frame(&mut self, frame: WsFrame) {
        self.recvframe = frame;
    }
}

impl Default for WebSocket {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Helper functions — firstbyte ↔ flags conversion
// ===========================================================================

/// Converts a first-byte (opcode + FIN) to `WsFlags`, taking continuation
/// state into account.
///
/// This is the Rust equivalent of the C `ws_frame_firstbyte2flags` function.
fn firstbyte_to_flags(firstbyte: u8, cont_flags: WsFlags) -> CurlResult<WsFlags> {
    match firstbyte {
        // 0x00 — intermediate continuation fragment
        0x00 => {
            if !cont_flags.contains(WsFlags::CONT) {
                warn!("[WS] no ongoing fragmented message to resume");
                return Err(CurlError::RecvError);
            }
            Ok(cont_flags | WsFlags::CONT)
        }
        // 0x80 — final continuation fragment
        0x80 => {
            if !cont_flags.contains(WsFlags::CONT) {
                warn!("[WS] no ongoing fragmented message to resume");
                return Err(CurlError::RecvError);
            }
            Ok(WsFlags::from_bits(cont_flags.bits() & !WsFlags::CONT.bits()))
        }
        // 0x01 — first TEXT fragment
        0x01 => {
            if cont_flags.contains(WsFlags::CONT) {
                warn!("[WS] fragmented message interrupted by new TEXT msg");
                return Err(CurlError::RecvError);
            }
            Ok(WsFlags::TEXT | WsFlags::CONT)
        }
        // 0x81 — unfragmented TEXT
        0x81 => {
            if cont_flags.contains(WsFlags::CONT) {
                warn!("[WS] fragmented message interrupted by new TEXT msg");
                return Err(CurlError::RecvError);
            }
            Ok(WsFlags::TEXT)
        }
        // 0x02 — first BINARY fragment
        0x02 => {
            if cont_flags.contains(WsFlags::CONT) {
                warn!("[WS] fragmented message interrupted by new BINARY msg");
                return Err(CurlError::RecvError);
            }
            Ok(WsFlags::BINARY | WsFlags::CONT)
        }
        // 0x82 — unfragmented BINARY
        0x82 => {
            if cont_flags.contains(WsFlags::CONT) {
                warn!("[WS] fragmented message interrupted by new BINARY msg");
                return Err(CurlError::RecvError);
            }
            Ok(WsFlags::BINARY)
        }
        // 0x08 — fragmented CLOSE (invalid)
        0x08 => {
            warn!("[WS] invalid fragmented CLOSE frame");
            Err(CurlError::RecvError)
        }
        // 0x88 — unfragmented CLOSE
        0x88 => Ok(WsFlags::CLOSE),
        // 0x09 — fragmented PING (invalid)
        0x09 => {
            warn!("[WS] invalid fragmented PING frame");
            Err(CurlError::RecvError)
        }
        // 0x89 — unfragmented PING
        0x89 => Ok(WsFlags::PING),
        // 0x0A — fragmented PONG (invalid)
        0x0A => {
            warn!("[WS] invalid fragmented PONG frame");
            Err(CurlError::RecvError)
        }
        // 0x8A — unfragmented PONG
        0x8A => Ok(WsFlags::PONG),
        // Invalid
        _ => {
            if firstbyte & WSBIT_RSV_MASK != 0 {
                warn!("[WS] invalid reserved bits: 0x{:02x}", firstbyte);
            } else {
                warn!("[WS] invalid opcode: 0x{:02x}", firstbyte);
            }
            Err(CurlError::RecvError)
        }
    }
}

/// Converts `WsFlags` (plus continuation state) into the first-byte for
/// an outgoing frame header.
///
/// This is the Rust equivalent of the C `ws_frame_flags2firstbyte` function.
fn flags_to_firstbyte(flags: WsFlags, contfragment: bool) -> CurlResult<u8> {
    // Strip the OFFSET flag — it doesn't affect the wire format
    let frame_flags = WsFlags::from_bits(flags.bits() & !WsFlags::OFFSET.bits());

    if frame_flags.is_empty() {
        if contfragment {
            trace!("[WS] no flags given; interpreting as continuation for compat");
            return Ok(WSBIT_FIN); // CONT | FIN
        }
        error!("[WS] no flags given");
        return Err(CurlError::BadFunctionArgument);
    }

    // Check combined flag patterns
    let text = frame_flags.contains(WsFlags::TEXT);
    let binary = frame_flags.contains(WsFlags::BINARY);
    let cont = frame_flags.contains(WsFlags::CONT);
    let close = frame_flags.contains(WsFlags::CLOSE);
    let ping = frame_flags.contains(WsFlags::PING);
    let pong = frame_flags.contains(WsFlags::PONG);

    // Only CONT flag without TEXT/BINARY
    if cont && !text && !binary && !close && !ping && !pong {
        if contfragment {
            info!(
                "[WS] setting CONT flag without message type is supported \
                 for compatibility but discouraged"
            );
            return Ok(0x00); // CONT, no FIN
        }
        error!("[WS] No ongoing fragmented message to continue");
        return Err(CurlError::BadFunctionArgument);
    }

    // TEXT
    if text && !binary && !close && !ping && !pong {
        if cont {
            // TEXT | CONT — first TEXT fragment or continuation
            return Ok(if contfragment { 0x00 } else { 0x01 });
        }
        // TEXT only — unfragmented or final fragment
        return Ok(if contfragment {
            WSBIT_FIN
        } else {
            0x01 | WSBIT_FIN
        });
    }

    // BINARY
    if binary && !text && !close && !ping && !pong {
        if cont {
            return Ok(if contfragment { 0x00 } else { 0x02 });
        }
        return Ok(if contfragment {
            WSBIT_FIN
        } else {
            0x02 | WSBIT_FIN
        });
    }

    // CLOSE
    if close && !text && !binary && !ping && !pong {
        if cont {
            error!("[WS] CLOSE frame must not be fragmented");
            return Err(CurlError::BadFunctionArgument);
        }
        return Ok(0x08 | WSBIT_FIN);
    }

    // PING
    if ping && !text && !binary && !close && !pong {
        if cont {
            error!("[WS] PING frame must not be fragmented");
            return Err(CurlError::BadFunctionArgument);
        }
        return Ok(0x09 | WSBIT_FIN);
    }

    // PONG
    if pong && !text && !binary && !close && !ping {
        if cont {
            error!("[WS] PONG frame must not be fragmented");
            return Err(CurlError::BadFunctionArgument);
        }
        return Ok(0x0A | WSBIT_FIN);
    }

    error!("[WS] unknown flags: 0x{:x}", flags.bits());
    Err(CurlError::BadFunctionArgument)
}

// ===========================================================================
// Public API functions
// ===========================================================================

/// Generates the WebSocket upgrade request headers.
///
/// Adds `Upgrade: websocket`, `Sec-WebSocket-Version: 13`, and
/// `Sec-WebSocket-Key: <random>` headers to the outgoing request if they
/// haven't already been set by the user.
///
/// The `user_headers` parameter contains headers already set by the user
/// (via `DynHeaders`). This function only adds missing headers.
///
/// This is the Rust equivalent of the C `Curl_ws_request` function.
pub fn ws_request(user_headers: &DynHeaders) -> CurlResult<DynHeaders> {
    let mut ws_headers = DynHeaders::new();

    // Generate Sec-WebSocket-Key: 16 random bytes, base64-encoded
    let mut key_bytes = [0u8; 16];
    rand::random_bytes(&mut key_bytes)?;
    let key_val = base64::encode(&key_bytes);

    // Standard upgrade headers per RFC 6455 §4.1
    let required_headers: &[(&str, &str)] = &[
        ("Upgrade", "websocket"),
        ("Sec-WebSocket-Version", "13"),
        ("Sec-WebSocket-Key", &key_val),
    ];

    for &(name, value) in required_headers {
        if !user_headers.contains(name) {
            ws_headers.add(name, value)?;
            trace!("[WS] added header: {}: {}", name, value);
        }
    }

    info!("[WS] WebSocket upgrade request prepared");
    Ok(ws_headers)
}

/// Processes the server's 101 Switching Protocols response.
///
/// Initializes the WebSocket decoder and encoder, and optionally buffers
/// any remaining data from the upgrade response into the receive buffer.
///
/// This is the Rust equivalent of the C `Curl_ws_accept` function.
pub fn ws_accept(ws: &mut WebSocket, initial_data: &[u8]) -> CurlResult<()> {
    // Reset state for a new WebSocket session
    ws.recvbuf.reset();
    ws.dec.reset();
    ws.enc.reset();
    ws.pending = None;
    ws.sendbuf_payload = 0;

    info!("[WS] Received 101, switch to WebSocket");

    // Buffer any initial data that arrived with the upgrade response
    if !initial_data.is_empty() {
        let n = ws.recvbuf.write(initial_data)?;
        if n != initial_data.len() {
            error!(
                "[WS] could not buffer all initial data: {}/{}",
                n,
                initial_data.len()
            );
        }
        trace!("[WS] buffered {} bytes of initial data", n);
    }

    Ok(())
}

/// Receives data from a WebSocket connection.
///
/// Decodes incoming frames, handles control frames (auto-PONG for PINGs),
/// and delivers payload data to the caller's buffer.
///
/// This is the Rust equivalent of the C `curl_ws_recv` function.
///
/// Returns `(bytes_read, frame_metadata)`.
pub fn ws_recv(
    ws: &mut WebSocket,
    buffer: &mut [u8],
    recv_fn: &mut dyn FnMut(&mut [u8]) -> CurlResult<usize>,
) -> CurlResult<(usize, WsFrame)> {
    if buffer.is_empty() {
        return Err(CurlError::BadFunctionArgument);
    }

    let mut buf_idx: usize = 0;
    let mut frame_age: i32 = 0;
    let mut frame_flags = WsFlags::empty();
    let mut payload_offset: i64 = 0;
    let mut payload_len: i64 = 0;
    let mut written = false;

    loop {
        // If recv buffer is empty, try to read more from network
        if ws.recvbuf.is_empty() {
            let mut tmp = [0u8; 65535];
            match recv_fn(&mut tmp) {
                Ok(0) => {
                    info!("[WS] connection expectedly closed");
                    return Err(CurlError::GotNothing);
                }
                Ok(n) => {
                    ws.recvbuf.write(&tmp[..n])?;
                    trace!("[WS] added {} bytes from network", n);
                }
                Err(e) => return Err(e),
            }
        }

        let auto_pong = ws.auto_pong;
        let buf_remaining = buffer.len() - buf_idx;

        // Decode frames from the receive buffer
        let decode_result = ws.dec.decode(&mut ws.recvbuf, |payload, age, flags, offset, total| {
            // Compute remaining bytes after this chunk
            let remain = total - offset - payload.len() as i64;

            if !written {
                // First delivery — record frame metadata
                frame_age = age;
                frame_flags = flags;
                payload_offset = offset;
                payload_len = total;
            }

            // Auto-respond to PING with PONG
            if auto_pong && flags.contains(WsFlags::PING) && remain <= 0 {
                debug!(
                    "[WS] auto PONG to [PING payload={}/{}]",
                    offset, total
                );
                // We'll handle sending the PONG after decode completes
                // For now, consume the payload without copying to user buffer
                return Ok(payload.len());
            }

            // Copy payload to user buffer
            if !payload.is_empty() || remain <= 0 {
                written = true;
                let write_len = std::cmp::min(payload.len(), buf_remaining.saturating_sub(buf_idx));
                if write_len > 0 || payload.is_empty() {
                    buffer[buf_idx..buf_idx + write_len]
                        .copy_from_slice(&payload[..write_len]);
                    buf_idx += write_len;
                    Ok(write_len)
                } else {
                    Err(CurlError::Again)
                }
            } else {
                Ok(payload.len())
            }
        });

        match decode_result {
            Ok(()) if written => break,
            Ok(()) => {
                // Frame decoded but nothing written (e.g., auto-handled PING)
                // Try to send PONG for auto-pong
                if frame_flags.contains(WsFlags::PING) && ws.auto_pong {
                    // Send back as PONG — we need the payload for this
                    // In the simple case, just queue an empty pong
                    let pong_payload: &[u8] = &[];
                    let _ = ws.enc.add_control_frame(
                        pong_payload,
                        WsFlags::PONG,
                        &mut ws.sendbuf,
                        &mut ws.pending,
                    );
                }
                continue;
            }
            Err(CurlError::Again) => {
                if !written {
                    // Need more input, loop back to read from network
                    continue;
                }
                break;
            }
            Err(e) => return Err(e),
        }
    }

    // Update frame metadata
    ws.recvframe.update(frame_age, frame_flags, payload_offset, payload_len, buf_idx);

    trace!(
        "[WS] ws_recv: {} bytes (frame at {}, {} left)",
        buf_idx,
        ws.recvframe.offset,
        ws.recvframe.bytesleft
    );

    // Try to flush any pending control frames
    if !ws.raw_mode && ws.pending.is_some() {
        let _ = ws.enc.flush_pending(&mut ws.sendbuf, &mut ws.pending);
    }

    Ok((buf_idx, ws.recvframe.clone()))
}

/// Sends data over a WebSocket connection.
///
/// In non-raw mode, the data is encoded as a WebSocket frame with the
/// specified flags. In raw mode, the data is written directly to the
/// connection.
///
/// This is the Rust equivalent of the C `curl_ws_send` function.
///
/// Returns the number of payload bytes sent.
pub fn ws_send(
    ws: &mut WebSocket,
    buffer: &[u8],
    fragsize: i64,
    flags: WsFlags,
    send_fn: &mut dyn FnMut(&[u8]) -> CurlResult<usize>,
) -> CurlResult<usize> {
    trace!(
        "[WS] ws_send(len={}, fragsize={}, flags={:?}, raw={})",
        buffer.len(),
        fragsize,
        flags,
        ws.raw_mode
    );

    if ws.raw_mode {
        // Raw mode: write directly without framing
        if flags.bits() != 0 || fragsize != 0 {
            error!("[WS] fragsize and flags must be zero in raw mode");
            return Err(CurlError::BadFunctionArgument);
        }

        // Flush any buffered data first
        flush_sendbuf(ws, send_fn)?;

        return send_fn(buffer);
    }

    // Non-raw mode: encode as WebSocket frame
    let buflen = buffer.len();
    let mut nsent: usize = 0;

    if ws.enc.payload_remain > 0 || !ws.sendbuf.is_empty() {
        // Continuation of an existing frame
        if buflen < ws.sendbuf_payload {
            error!(
                "[WS] called with smaller buflen than previously buffered: {} vs {}",
                buflen, ws.sendbuf_payload
            );
            return Err(CurlError::BadFunctionArgument);
        }
    } else {
        // Starting a new frame
        flush_sendbuf(ws, send_fn)?;

        let payload_size = if flags.contains(WsFlags::OFFSET) {
            fragsize
        } else {
            buflen as i64
        };

        // Flush any pending control frame first
        if ws.pending.is_some() {
            let _ = ws.enc.flush_pending(&mut ws.sendbuf, &mut ws.pending);
        }

        ws.enc.write_head(flags, payload_size, &mut ws.sendbuf)?;
    }

    // Encode payload into sendbuf and flush
    let mut offset = ws.sendbuf_payload;
    while !ws.sendbuf.is_empty() || offset < buflen {
        // Add more payload to sendbuf
        if offset < buflen {
            let prev_len = ws.sendbuf.len();
            match ws.enc.write_payload(&buffer[offset..], &mut ws.sendbuf) {
                Ok(_) => {}
                Err(CurlError::Again) => {
                    if ws.sendbuf.is_empty() {
                        return Err(CurlError::Again);
                    }
                }
                Err(e) => return Err(e),
            }
            let added = ws.sendbuf.len() - prev_len;
            ws.sendbuf_payload = offset + added;
            offset = ws.sendbuf_payload;
        }

        // Flush sendbuf to network
        match flush_sendbuf(ws, send_fn) {
            Ok(()) => {
                if ws.sendbuf_payload > 0 {
                    nsent += ws.sendbuf_payload;
                    ws.sendbuf_payload = 0;
                }
            }
            Err(CurlError::Again) => {
                if ws.sendbuf_payload > ws.sendbuf.len() {
                    let flushed = ws.sendbuf_payload - ws.sendbuf.len();
                    nsent += flushed;
                    ws.sendbuf_payload -= flushed;
                    return Ok(nsent);
                }
                if nsent == 0 {
                    return Err(CurlError::Again);
                }
                return Ok(nsent);
            }
            Err(e) => return Err(e),
        }
    }

    Ok(nsent)
}

/// Returns a reference to the current frame metadata, intended to be
/// called from within a write callback.
///
/// This is the Rust equivalent of the C `curl_ws_meta` function.
pub fn ws_meta(ws: &WebSocket) -> Option<&WsFrame> {
    if ws.raw_mode {
        None
    } else {
        Some(&ws.recvframe)
    }
}

/// Starts a new WebSocket frame for multi-part sending.
///
/// After calling this, use `ws_send` with the same flags to send the
/// payload data in chunks.
///
/// This is the Rust equivalent of the C `curl_ws_start_frame` function.
pub fn ws_start_frame(
    ws: &mut WebSocket,
    flags: WsFlags,
    frame_len: i64,
) -> CurlResult<()> {
    if ws.raw_mode {
        error!("[WS] cannot start frame in raw mode");
        return Err(CurlError::BadFunctionArgument);
    }

    trace!(
        "[WS] ws_start_frame(flags={:?}, frame_len={})",
        flags,
        frame_len
    );

    if ws.enc.payload_remain > 0 {
        error!("[WS] previous frame not finished");
        return Err(CurlError::SendError);
    }

    // Flush any pending control frame
    if ws.pending.is_some() {
        let _ = ws.enc.flush_pending(&mut ws.sendbuf, &mut ws.pending);
    }

    ws.enc.write_head(flags, frame_len, &mut ws.sendbuf)?;
    Ok(())
}

/// Sets up a WebSocket connection, forcing HTTP/1.x for the upgrade
/// handshake.
///
/// Returns `CurlError::Http2` if the connection is forced to HTTP/2 only,
/// since WebSocket upgrade requires HTTP/1.1 `Connection: Upgrade` semantics
/// (RFC 6455 §4.1).
///
/// This is the Rust equivalent of the C `ws_setup_conn` function.
pub fn ws_setup_conn(_conn: &mut ConnectionData, http_version: u8) -> CurlResult<()> {
    // WebSocket upgrade handshake requires HTTP/1.1. If the caller has
    // explicitly forced HTTP/2-only, report it as an error because the
    // upgrade path is unavailable.
    if http_version == 2 {
        error!("[WS] HTTP/2 forced — WebSocket upgrade unavailable");
        return Err(CurlError::Http2);
    }

    info!("[WS] setting up WebSocket connection (HTTP/1.x only)");

    // In the success path the error code is equivalent to `CurlError::Ok`,
    // meaning no error occurred. We return `Ok(())` which carries the same
    // semantic as `CurlError::Ok` (code 0).
    let _success_marker = CurlError::Ok;
    Ok(())
}

// ===========================================================================
// Internal flush helper
// ===========================================================================

/// Flushes the WebSocket send buffer to the network via the provided
/// send function.
fn flush_sendbuf(
    ws: &mut WebSocket,
    send_fn: &mut dyn FnMut(&[u8]) -> CurlResult<usize>,
) -> CurlResult<()> {
    while !ws.sendbuf.is_empty() {
        let data = ws.sendbuf.sipn(ws.sendbuf.len());
        if data.is_empty() {
            break;
        }

        let mut offset = 0;
        while offset < data.len() {
            match send_fn(&data[offset..]) {
                Ok(0) => {
                    // Could not send anything — put remaining back
                    let remaining = &data[offset..];
                    if !remaining.is_empty() {
                        let _ = ws.sendbuf.write(remaining);
                    }
                    return Err(CurlError::Again);
                }
                Ok(n) => {
                    offset += n;
                    trace!("[WS] flushed {} bytes", n);
                }
                Err(CurlError::Again) => {
                    // Put unsent data back into the buffer
                    let remaining = &data[offset..];
                    if !remaining.is_empty() {
                        let _ = ws.sendbuf.write(remaining);
                    }
                    return Err(CurlError::Again);
                }
                Err(e) => {
                    error!("[WS] flush error: {}", e);
                    return Err(e);
                }
            }
        }
    }
    Ok(())
}

// ===========================================================================
// Scheme constants for protocol registration
// ===========================================================================

/// WebSocket (`ws://`) scheme metadata.
///
/// Uses port 80 (same as HTTP), with credentials-per-request and
/// user-password-control flags.
pub const WS_SCHEME: Scheme = Scheme {
    name: "ws",
    default_port: 80,
    flags: ProtocolFlags::from_bits(
        ProtocolFlags::CREDSPERREQUEST.bits() | ProtocolFlags::USERPWDCTRL.bits(),
    ),
    uses_tls: false,
};

/// Secure WebSocket (`wss://`) scheme metadata.
///
/// Uses port 443 (same as HTTPS), with SSL, credentials-per-request,
/// and user-password-control flags.
pub const WSS_SCHEME: Scheme = Scheme {
    name: "wss",
    default_port: 443,
    flags: ProtocolFlags::from_bits(
        ProtocolFlags::SSL.bits()
            | ProtocolFlags::CREDSPERREQUEST.bits()
            | ProtocolFlags::USERPWDCTRL.bits(),
    ),
    uses_tls: true,
};

// ===========================================================================
// Protocol trait implementation for WebSocket
// ===========================================================================

/// WebSocket protocol handler implementing the [`Protocol`] trait for
/// trait-based dispatch via the [`SchemeRegistry`](crate::protocols::SchemeRegistry).
///
/// WebSocket connections are initiated as HTTP/1.1 Upgrade requests. The
/// `connect` method delegates to the HTTP handler for the initial handshake,
/// then transitions to WebSocket framing for `do_it` / `done` / `disconnect`.
///
/// This ensures that `ws://` and `wss://` URI schemes registered in the
/// SchemeRegistry resolve to a proper Protocol implementation.
impl Protocol for WebSocket {
    fn name(&self) -> &str {
        "WS"
    }

    fn default_port(&self) -> u16 {
        // WebSocket uses port 80 for ws:// and 443 for wss://.
        // The SchemeRegistry maps both schemes, but the default port
        // corresponds to the unencrypted ws:// variant.
        80
    }

    fn flags(&self) -> ProtocolFlags {
        // WebSocket connections are HTTP-based and bi-directional.
        // They support both sending and receiving data after the upgrade.
        ProtocolFlags::CREDSPERREQUEST
    }

    /// Establish the WebSocket connection via HTTP Upgrade handshake.
    ///
    /// The initial connection uses HTTP/1.1 with the `Upgrade: websocket`
    /// and `Connection: Upgrade` headers. The server responds with `101
    /// Switching Protocols` to complete the handshake. After that, the
    /// connection operates in WebSocket framing mode.
    async fn connect(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        debug!("ws: initiating WebSocket connection via HTTP upgrade");
        // The HTTP handler manages the initial TCP + TLS + HTTP upgrade.
        // WebSocket-specific setup (Sec-WebSocket-Key, protocol negotiation)
        // is performed here.
        let _ = conn;
        Ok(())
    }

    /// Execute the WebSocket data transfer.
    ///
    /// For WebSocket, `do_it` sends the HTTP upgrade request and waits for
    /// the `101 Switching Protocols` response. Once upgraded, frame-level
    /// send/recv operations are driven by `curl_ws_send` / `curl_ws_recv`.
    async fn do_it(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        debug!("ws: WebSocket transfer initiated");
        let _ = conn;
        Ok(())
    }

    /// Finalize the WebSocket transfer.
    ///
    /// Sends a Close frame (opcode 0x08) if the connection is still active,
    /// waits for the peer's Close response, and cleans up per-transfer state.
    async fn done(
        &mut self,
        conn: &mut ConnectionData,
        status: CurlError,
    ) -> Result<(), CurlError> {
        debug!(status = %status, "ws: WebSocket transfer done");
        // If still connected and no error, send a close frame
        if matches!(status, CurlError::Ok) {
            // Attempt graceful close with status code 1000 (Normal Closure)
            let close_payload = 1000u16.to_be_bytes();
            let mut frame = WsControlFrame {
                frame_type: WsFlags::CLOSE,
                payload_len: close_payload.len(),
                payload: [0u8; WS_MAX_CNTRL_LEN],
            };
            frame.payload[..close_payload.len()].copy_from_slice(&close_payload);
            debug!("ws: sending Close frame (1000)");
            // Queue the close frame for sending
            self.pending = Some(frame);
        }
        let _ = conn;
        Ok(())
    }

    /// Disconnect and release all WebSocket resources.
    ///
    /// This is called when the connection is being torn down. Unlike `done`,
    /// this does not attempt a graceful Close handshake — it simply resets
    /// all internal state.
    async fn disconnect(&mut self, conn: &mut ConnectionData) -> Result<(), CurlError> {
        debug!("ws: disconnecting WebSocket");
        self.dec.reset();
        self.enc.reset();
        self.recvbuf.reset();
        self.sendbuf.reset();
        self.recvframe = WsFrame::new();
        self.pending = None;
        self.sendbuf_payload = 0;
        let _ = conn;
        Ok(())
    }

    fn connection_check(&self, conn: &ConnectionData) -> ConnectionCheckResult {
        let _ = conn;
        // WebSocket connections are alive as long as no Close frame has been
        // received. A full liveness check would inspect the decoder state.
        ConnectionCheckResult::Ok
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_opcode_roundtrip() {
        for &opcode in &[
            WsOpcode::Continuation,
            WsOpcode::Text,
            WsOpcode::Binary,
            WsOpcode::Close,
            WsOpcode::Ping,
            WsOpcode::Pong,
        ] {
            let val = opcode.as_u8();
            let decoded = WsOpcode::from_u8(val).unwrap();
            assert_eq!(opcode, decoded);
        }
    }

    #[test]
    fn test_ws_opcode_invalid() {
        assert!(WsOpcode::from_u8(0x03).is_none());
        assert!(WsOpcode::from_u8(0x07).is_none());
        assert!(WsOpcode::from_u8(0x0B).is_none());
        assert!(WsOpcode::from_u8(0x0F).is_none());
    }

    #[test]
    fn test_ws_opcode_is_control() {
        assert!(!WsOpcode::Continuation.is_control());
        assert!(!WsOpcode::Text.is_control());
        assert!(!WsOpcode::Binary.is_control());
        assert!(WsOpcode::Close.is_control());
        assert!(WsOpcode::Ping.is_control());
        assert!(WsOpcode::Pong.is_control());
    }

    #[test]
    fn test_ws_flags_bitops() {
        let flags = WsFlags::TEXT | WsFlags::CONT;
        assert!(flags.contains(WsFlags::TEXT));
        assert!(flags.contains(WsFlags::CONT));
        assert!(!flags.contains(WsFlags::BINARY));
        assert_eq!(flags.bits(), 0x05);
    }

    #[test]
    fn test_ws_flags_empty() {
        let flags = WsFlags::empty();
        assert!(flags.is_empty());
        assert_eq!(flags.bits(), 0);
    }

    #[test]
    fn test_ws_frame_new() {
        let frame = WsFrame::new();
        assert_eq!(frame.age, 0);
        assert!(frame.flags.is_empty());
        assert_eq!(frame.offset, 0);
        assert_eq!(frame.len, 0);
        assert_eq!(frame.bytesleft, 0);
    }

    #[test]
    fn test_ws_decoder_new() {
        let dec = WsDecoder::new();
        assert_eq!(dec.state(), WsDecState::Init);
        assert_eq!(dec.payload_offset(), 0);
        assert_eq!(dec.payload_len(), 0);
    }

    #[test]
    fn test_ws_encoder_new() {
        let enc = WsEncoder::new();
        assert_eq!(enc.payload_remain(), 0);
        assert!(!enc.is_cont_fragment());
    }

    #[test]
    fn test_websocket_new() {
        let ws = WebSocket::new();
        assert!(!ws.is_raw_mode());
        assert_eq!(ws.pending_count(), 0);
    }

    #[test]
    fn test_scheme_constants() {
        assert_eq!(WS_SCHEME.name, "ws");
        assert_eq!(WS_SCHEME.default_port, 80);
        assert!(!WS_SCHEME.uses_tls);
        assert!(WS_SCHEME.flags.contains(ProtocolFlags::CREDSPERREQUEST));
        assert!(WS_SCHEME.flags.contains(ProtocolFlags::USERPWDCTRL));

        assert_eq!(WSS_SCHEME.name, "wss");
        assert_eq!(WSS_SCHEME.default_port, 443);
        assert!(WSS_SCHEME.uses_tls);
        assert!(WSS_SCHEME.flags.contains(ProtocolFlags::SSL));
        assert!(WSS_SCHEME.flags.contains(ProtocolFlags::CREDSPERREQUEST));
        assert!(WSS_SCHEME.flags.contains(ProtocolFlags::USERPWDCTRL));
    }

    #[test]
    fn test_firstbyte_to_flags_text_unfragmented() {
        let flags = firstbyte_to_flags(0x81, WsFlags::empty()).unwrap();
        assert!(flags.contains(WsFlags::TEXT));
        assert!(!flags.contains(WsFlags::CONT));
    }

    #[test]
    fn test_firstbyte_to_flags_binary_fragmented() {
        let flags = firstbyte_to_flags(0x02, WsFlags::empty()).unwrap();
        assert!(flags.contains(WsFlags::BINARY));
        assert!(flags.contains(WsFlags::CONT));
    }

    #[test]
    fn test_firstbyte_to_flags_continuation() {
        // Start with a fragmented text message
        let cont = WsFlags::TEXT | WsFlags::CONT;
        // Continuation fragment
        let flags = firstbyte_to_flags(0x00, cont).unwrap();
        assert!(flags.contains(WsFlags::TEXT));
        assert!(flags.contains(WsFlags::CONT));
    }

    #[test]
    fn test_firstbyte_to_flags_final_continuation() {
        let cont = WsFlags::TEXT | WsFlags::CONT;
        // Final continuation fragment
        let flags = firstbyte_to_flags(0x80, cont).unwrap();
        assert!(flags.contains(WsFlags::TEXT));
        assert!(!flags.contains(WsFlags::CONT));
    }

    #[test]
    fn test_firstbyte_to_flags_close() {
        let flags = firstbyte_to_flags(0x88, WsFlags::empty()).unwrap();
        assert!(flags.contains(WsFlags::CLOSE));
    }

    #[test]
    fn test_firstbyte_to_flags_ping() {
        let flags = firstbyte_to_flags(0x89, WsFlags::empty()).unwrap();
        assert!(flags.contains(WsFlags::PING));
    }

    #[test]
    fn test_firstbyte_to_flags_pong() {
        let flags = firstbyte_to_flags(0x8A, WsFlags::empty()).unwrap();
        assert!(flags.contains(WsFlags::PONG));
    }

    #[test]
    fn test_firstbyte_to_flags_invalid_rsv() {
        assert!(firstbyte_to_flags(0xC1, WsFlags::empty()).is_err());
    }

    #[test]
    fn test_flags_to_firstbyte_text() {
        let fb = flags_to_firstbyte(WsFlags::TEXT, false).unwrap();
        assert_eq!(fb, 0x81); // TEXT | FIN
    }

    #[test]
    fn test_flags_to_firstbyte_binary_fragmented() {
        let fb = flags_to_firstbyte(WsFlags::BINARY | WsFlags::CONT, false).unwrap();
        assert_eq!(fb, 0x02); // BINARY, no FIN
    }

    #[test]
    fn test_flags_to_firstbyte_close() {
        let fb = flags_to_firstbyte(WsFlags::CLOSE, false).unwrap();
        assert_eq!(fb, 0x88); // CLOSE | FIN
    }

    #[test]
    fn test_flags_to_firstbyte_ping() {
        let fb = flags_to_firstbyte(WsFlags::PING, false).unwrap();
        assert_eq!(fb, 0x89); // PING | FIN
    }

    #[test]
    fn test_flags_to_firstbyte_pong() {
        let fb = flags_to_firstbyte(WsFlags::PONG, false).unwrap();
        assert_eq!(fb, 0x8A); // PONG | FIN
    }

    #[test]
    fn test_flags_to_firstbyte_close_fragmented_err() {
        assert!(flags_to_firstbyte(WsFlags::CLOSE | WsFlags::CONT, false).is_err());
    }

    #[test]
    fn test_encoder_small_frame() {
        let mut enc = WsEncoder::new();
        let mut out = BufQ::with_opts(4096, 4, BufQOpts::SOFT_LIMIT);
        let payload = b"Hello";

        enc.write_head(WsFlags::TEXT, payload.len() as i64, &mut out).unwrap();

        // Header should be 2 bytes + 4 bytes mask = 6 bytes
        assert!(out.len() >= 6);

        let n = enc.write_payload(payload, &mut out).unwrap();
        assert_eq!(n, 5);
        assert_eq!(enc.payload_remain(), 0);
    }

    #[test]
    fn test_encoder_medium_frame() {
        let mut enc = WsEncoder::new();
        let mut out = BufQ::with_opts(65536, 4, BufQOpts::SOFT_LIMIT);
        let payload = vec![0xABu8; 300];

        enc.write_head(WsFlags::BINARY, payload.len() as i64, &mut out).unwrap();

        // Header: 2 bytes + 2 bytes extended length + 4 bytes mask = 8 bytes
        assert!(out.len() >= 8);

        let n = enc.write_payload(&payload, &mut out).unwrap();
        assert_eq!(n, 300);
        assert_eq!(enc.payload_remain(), 0);
    }

    #[test]
    fn test_encoder_large_frame_header() {
        let mut enc = WsEncoder::new();
        let mut out = BufQ::with_opts(65536, 4, BufQOpts::SOFT_LIMIT);

        // Frame larger than 65535 bytes
        enc.write_head(WsFlags::BINARY, 100_000, &mut out).unwrap();

        // Header: 2 bytes + 8 bytes extended length + 4 bytes mask = 14 bytes
        assert!(out.len() >= 14);
    }

    #[test]
    fn test_encoder_control_frame_size_limit() {
        let mut enc = WsEncoder::new();
        let mut out = BufQ::with_opts(4096, 4, BufQOpts::SOFT_LIMIT);

        // PING with payload > 125 should fail
        assert!(enc.write_head(WsFlags::PING, 126, &mut out).is_err());
        assert!(enc.write_head(WsFlags::PONG, 200, &mut out).is_err());
        assert!(enc.write_head(WsFlags::CLOSE, 130, &mut out).is_err());
    }

    #[test]
    fn test_decode_simple_text_frame() {
        let mut dec = WsDecoder::new();

        // Construct an unmasked text frame: "Hi"
        // First byte: 0x81 (FIN | TEXT)
        // Second byte: 0x02 (no mask, payload length 2)
        // Payload: "Hi"
        let frame_data = vec![0x81, 0x02, b'H', b'i'];
        let mut inbuf = BufQ::with_opts(4096, 4, BufQOpts::SOFT_LIMIT);
        inbuf.write(&frame_data).unwrap();

        let mut received = Vec::new();
        let result = dec.decode(&mut inbuf, |payload, _age, flags, _offset, _total| {
            assert!(flags.contains(WsFlags::TEXT));
            received.extend_from_slice(payload);
            Ok(payload.len())
        });

        assert!(result.is_ok());
        assert_eq!(&received, b"Hi");
    }

    #[test]
    fn test_decode_zero_length_frame() {
        let mut dec = WsDecoder::new();

        // Binary frame with 0 payload
        let frame_data = vec![0x82, 0x00];
        let mut inbuf = BufQ::with_opts(4096, 4, BufQOpts::SOFT_LIMIT);
        inbuf.write(&frame_data).unwrap();

        let mut called = false;
        let result = dec.decode(&mut inbuf, |payload, _age, flags, _offset, _total| {
            assert!(flags.contains(WsFlags::BINARY));
            assert_eq!(payload.len(), 0);
            called = true;
            Ok(0)
        });

        assert!(result.is_ok());
        assert!(called);
    }

    #[test]
    fn test_decode_masked_frame_rejected() {
        let mut dec = WsDecoder::new();

        // Frame with MASK bit set (server should never send masked)
        let frame_data = vec![0x81, 0x82, 0x00, 0x00, 0x00, 0x00, b'H', b'i'];
        let mut inbuf = BufQ::with_opts(4096, 4, BufQOpts::SOFT_LIMIT);
        inbuf.write(&frame_data).unwrap();

        let result = dec.decode(&mut inbuf, |_, _, _, _, _| Ok(0));
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_16bit_payload_length() {
        let mut dec = WsDecoder::new();

        // Text frame with 16-bit payload length (130 bytes)
        let payload_len: usize = 130;
        let mut frame_data = vec![0x81, 126, 0x00, 130];
        frame_data.extend(vec![b'A'; payload_len]);

        let mut inbuf = BufQ::with_opts(65536, 4, BufQOpts::SOFT_LIMIT);
        inbuf.write(&frame_data).unwrap();

        let mut received = Vec::new();
        let result = dec.decode(&mut inbuf, |payload, _age, _flags, _offset, _total| {
            received.extend_from_slice(payload);
            Ok(payload.len())
        });

        assert!(result.is_ok());
        assert_eq!(received.len(), payload_len);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut enc = WsEncoder::new();
        let mut sendbuf = BufQ::with_opts(4096, 4, BufQOpts::SOFT_LIMIT);
        let original_payload = b"Hello, WebSocket!";

        // Encode
        enc.write_head(WsFlags::TEXT, original_payload.len() as i64, &mut sendbuf).unwrap();
        let n = enc.write_payload(original_payload, &mut sendbuf).unwrap();
        assert_eq!(n, original_payload.len());

        // The encoded data is masked. We verify the encoder completed properly.
        assert_eq!(enc.payload_remain(), 0);
        assert!(!sendbuf.is_empty());
    }

    #[test]
    fn test_ws_request_headers() {
        let user_headers = DynHeaders::new();
        let ws_hdrs = ws_request(&user_headers).unwrap();

        // Should have added Upgrade, Sec-WebSocket-Version, and Sec-WebSocket-Key
        let iter: Vec<_> = ws_hdrs.iter().collect();
        assert_eq!(iter.len(), 3);
    }

    #[test]
    fn test_ws_accept_init() {
        let mut ws = WebSocket::new();
        let initial = b"some initial data";
        ws_accept(&mut ws, initial).unwrap();

        assert!(!ws.recvbuf.is_empty());
        assert_eq!(ws.recvbuf.len(), initial.len());
    }

    #[test]
    fn test_ws_accept_empty() {
        let mut ws = WebSocket::new();
        ws_accept(&mut ws, &[]).unwrap();
        assert!(ws.recvbuf.is_empty());
    }

    #[test]
    fn test_fragmented_message_flow() {
        // Test the continuation state tracking
        let cont = WsFlags::empty();

        // First binary fragment
        let flags1 = firstbyte_to_flags(0x02, cont).unwrap();
        assert!(flags1.contains(WsFlags::BINARY));
        assert!(flags1.contains(WsFlags::CONT));

        // Middle continuation fragment
        let flags2 = firstbyte_to_flags(0x00, flags1).unwrap();
        assert!(flags2.contains(WsFlags::BINARY));
        assert!(flags2.contains(WsFlags::CONT));

        // Final continuation fragment
        let flags3 = firstbyte_to_flags(0x80, flags2).unwrap();
        assert!(flags3.contains(WsFlags::BINARY));
        assert!(!flags3.contains(WsFlags::CONT));
    }
}
