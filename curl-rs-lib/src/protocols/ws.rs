//! WebSocket (`ws://` / `wss://`) protocol handler — the memory-safe Rust port
//! of curl's `lib/ws.c` (and `lib/ws.h`) for the byte-for-byte functional-parity
//! rewrite of curl / libcurl **8.19.0-DEV**.
//!
//! # What this module is
//!
//! curl implements [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455) WebSockets
//! *on top of* an ordinary HTTP/1.1 `Upgrade` handshake: the request is issued
//! through the HTTP handler, the server answers `101 Switching Protocols`, and
//! from that point the connection carries length-delimited, (client→server)
//! masked WebSocket **frames** instead of an HTTP body. This module reproduces
//! exactly that design:
//!
//! * **Handshake** — [`Websocket::request_headers`] generates the three RFC 6455
//!   client headers (`Upgrade`, `Sec-WebSocket-Version: 13`, and a fresh
//!   base64-encoded 16-byte `Sec-WebSocket-Key`), byte-identical to curl's
//!   `Curl_ws_request`. [`Websocket::accept`] validates the `101` status and the
//!   `Sec-WebSocket-Accept` value (← curl's `Curl_ws_accept`), then installs the
//!   frame decoder and buffers any payload bytes that arrived with the response.
//! * **Framing** — [`WsDecoder`] and [`WsEncoder`] are faithful reimplementations
//!   of curl's `ws_dec_*` / `ws_enc_*` state machines: the decoder is *resumable*
//!   across arbitrary socket-read boundaries (that is the entire purpose of
//!   [`WsDecState`]), and the encoder masks every client frame with a fresh
//!   32-bit key, exactly as RFC 6455 §5.3 requires.
//! * **Engine** — [`Websocket`] owns the per-connection receive/transmit buffers
//!   and the `curl_ws_recv` / `curl_ws_send` / `curl_ws_start_frame` /
//!   `curl_ws_meta` semantics that the FFI layer (`curl-rs-ffi/src/ws.rs`) routes
//!   its C-ABI trampolines to.
//!
//! # Transport independence
//!
//! Like curl's `ws.c` — whose codec operates purely on `bufq` byte buffers while
//! the socket I/O is delegated to the connection layer (`nw_in_recv`,
//! `ws_flush`) — this engine is transport-agnostic. All network I/O is driven
//! through the [`WsIo`] abstraction, whose production implementor is the
//! connection filter chain ([`crate::conn::FilterChain`]). For a `wss://`
//! transfer that chain simply includes the TLS (`rustls`) filter, so the very
//! same framing code runs unchanged over plaintext and TLS — mirroring curl,
//! where `ws.c` never mentions TLS and the `PROTOPT_SSL` flag on the `wss` scheme
//! is what layers it in. Because WebSocket is HTTP/1.1-only (curl's
//! `ws_setup_conn` pins the version), the `wss` TLS layer advertises the
//! [`crate::tls::ALPN_HTTP_1_1`] ALPN protocol.
//!
//! # Safety
//!
//! This module is written entirely in **safe Rust** — it contains no
//! escape-hatch blocks, no raw pointers, and no FFI. Manual `malloc`/`free` of curl's
//! `struct websocket` and its `bufq`s is replaced by ownership; masking, length
//! decoding, and buffering are all bounds-checked by construction. Every
//! fallible step returns an [`Error`] carrying the exact curl [`CurlCode`].

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use bytes::{Buf, BytesMut};
use rand::RngCore as _;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use std::os::fd::RawFd;

use crate::conn::FilterChain;
use crate::error::{CurlCode, Error, Result};
use crate::protocols::{
    Pollset, ProtoFuture, Protocol, TransferCtx, TransferRequest, TransferStream,
};
use crate::tls;

// ===========================================================================
// RFC 6455 §5.2 frame-header bits (← `lib/ws.c`, reproduced value-for-value).
//
//   0 1 2 3 4 5 6 7
//  +-+-+-+-+-------+
//  |F|R|R|R| opcode|
//  |I|S|S|S|  (4)  |
//  |N|V|V|V|       |
//  | |1|2|3|       |
// ===========================================================================

/// First-byte `FIN` bit — set on the final fragment of a message (`WSBIT_FIN`).
const WSBIT_FIN: u8 = 0x80;
/// Reserved bit 1 (`WSBIT_RSV1`); must be zero for the base protocol.
const WSBIT_RSV1: u8 = 0x40;
/// Reserved bit 2 (`WSBIT_RSV2`); must be zero for the base protocol.
const WSBIT_RSV2: u8 = 0x20;
/// Reserved bit 3 (`WSBIT_RSV3`); must be zero for the base protocol.
const WSBIT_RSV3: u8 = 0x10;
/// Mask of all three reserved bits (`WSBIT_RSV_MASK`); any set → protocol error.
const WSBIT_RSV_MASK: u8 = WSBIT_RSV1 | WSBIT_RSV2 | WSBIT_RSV3;

/// Continuation-frame opcode `0x0` (`WSBIT_OPCODE_CONT`).
const WSBIT_OPCODE_CONT: u8 = 0x0;
/// Text-frame opcode `0x1` (`WSBIT_OPCODE_TEXT`).
const WSBIT_OPCODE_TEXT: u8 = 0x1;
/// Binary-frame opcode `0x2` (`WSBIT_OPCODE_BIN`).
const WSBIT_OPCODE_BIN: u8 = 0x2;
/// Close control-frame opcode `0x8` (`WSBIT_OPCODE_CLOSE`).
const WSBIT_OPCODE_CLOSE: u8 = 0x8;
/// Ping control-frame opcode `0x9` (`WSBIT_OPCODE_PING`).
const WSBIT_OPCODE_PING: u8 = 0x9;
/// Pong control-frame opcode `0xa` (`WSBIT_OPCODE_PONG`).
const WSBIT_OPCODE_PONG: u8 = 0xa;
/// Mask selecting the 4-bit opcode field of the first byte (`WSBIT_OPCODE_MASK`).
const WSBIT_OPCODE_MASK: u8 = 0x0f;

/// Second-byte `MASK` bit (`WSBIT_MASK`). A client MUST set it on every frame it
/// sends; a server MUST NOT set it on any frame it sends.
const WSBIT_MASK: u8 = 0x80;

// ===========================================================================
// Public `CURLWS_*` flag bits (← `include/curl/websockets.h`).
//
// These values are a FROZEN ABI contract: they populate `struct curl_ws_frame`'s
// `flags` field and the `flags` argument of `curl_ws_send`, and are re-declared
// verbatim by the FFI crate (`curl-rs-ffi/src/ws.rs`). They are `pub` so the
// engine and any in-crate caller share exactly one definition.
// ===========================================================================

/// `CURLWS_TEXT` — the frame carries UTF-8 text payload (`1 << 0`).
pub const CURLWS_TEXT: u32 = 1 << 0;
/// `CURLWS_BINARY` — the frame carries binary payload (`1 << 1`).
pub const CURLWS_BINARY: u32 = 1 << 1;
/// `CURLWS_CONT` — this chunk is part of a fragmented message not yet complete
/// (`1 << 2`).
pub const CURLWS_CONT: u32 = 1 << 2;
/// `CURLWS_CLOSE` — a CLOSE control frame (`1 << 3`).
pub const CURLWS_CLOSE: u32 = 1 << 3;
/// `CURLWS_PING` — a PING control frame (`1 << 4`).
pub const CURLWS_PING: u32 = 1 << 4;
/// `CURLWS_OFFSET` — the send uses an explicit fragment size; `fragsize`/offset
/// apply (`1 << 5`).
pub const CURLWS_OFFSET: u32 = 1 << 5;
/// `CURLWS_PONG` — a PONG control frame (`1 << 6`).
pub const CURLWS_PONG: u32 = 1 << 6;

/// `CURLWS_RAW_MODE` — a `CURLOPT_WS_OPTIONS` bit requesting raw passthrough of
/// WebSocket bytes without libcurl's automatic framing/decoding (`1 << 0`).
///
/// Note this shares the numeric value of [`CURLWS_TEXT`] because curl declares it
/// in a *different* namespace (the `CURLOPT_WS_OPTIONS` bitmask, not the
/// frame-flag set); the two are never combined.
pub const CURLWS_RAW_MODE: u32 = 1 << 0;
/// `CURLWS_NOAUTOPONG` — a `CURLOPT_WS_OPTIONS` bit suppressing libcurl's
/// automatic PONG reply to PING frames (`1 << 1`).
pub const CURLWS_NOAUTOPONG: u32 = 1 << 1;

// ===========================================================================
// Buffer dimensioning and limits (← `lib/ws.c`).
// ===========================================================================

/// Default receive/transmit working-buffer chunk size (`WS_CHUNK_SIZE`), also the
/// number of network bytes pulled per [`Websocket::recv`] top-up.
const WS_CHUNK_SIZE: usize = 65535;

/// Maximum control-frame (CLOSE/PING/PONG) payload length, RFC 6455 §5.5
/// (`WS_MAX_CNTRL_LEN`). Auto-ponging an over-long PING would mean transmitting
/// an equally over-long PONG, so over-long control frames are rejected.
const WS_MAX_CNTRL_LEN: usize = 125;

/// The RFC 6455 §1.3 "magic" GUID appended to the client key before hashing to
/// derive `Sec-WebSocket-Accept`.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// `tracing` target for the WebSocket frame diagnostics (← curl's `CURL_TRC_WS`
/// verbose channel). Emitting under a stable target keeps the `--trace`
/// vocabulary (`CONT`/`TEXT`/`BIN`/`CLOSE`/`PING`/`PONG`, `NON-FINAL`) identical
/// to curl 8.x for downstream log parity.
const WS_TRACE_TARGET: &str = "curl::ws";

// ===========================================================================
// Small error constructors mirroring curl's `failf(...) + return CURLE_*`.
//
// Keeping the exact "[WS] " message prefix preserves the stderr / `--trace`
// text that downstream log scrapers rely on (a preservation contract of the
// rewrite), while the [`CurlCode`] fixes the integer error-code parity.
// ===========================================================================

/// Build a `CURLE_RECV_ERROR` (56) — used for every decode-side protocol
/// violation, exactly as curl's `ws_dec_read_head` / `ws_frame_firstbyte2flags`
/// map their `failf` sites.
fn recv_err(msg: impl Into<String>) -> Error {
    Error::with_context(CurlCode::RecvError, msg)
}

/// Build a `CURLE_SEND_ERROR` (55) — used for encode-side framing faults, as in
/// curl's `ws_enc_add_frame`.
fn send_err(msg: impl Into<String>) -> Error {
    Error::with_context(CurlCode::SendError, msg)
}

/// Build a `CURLE_BAD_FUNCTION_ARGUMENT` (43) — used for API-misuse conditions,
/// matching curl's `curl_ws_send` / `ws_frame_flags2firstbyte` argument checks.
fn arg_err(msg: impl Into<String>) -> Error {
    Error::with_context(CurlCode::BadFunctionArgument, msg)
}

// ===========================================================================
// Decoder / encoder state — VERBATIM structural port of `lib/ws.c`.
//
// The field names, roles, and the state-machine shape are preserved so that
// `--trace` output and reasoning about the code line up 1:1 with curl.
// ===========================================================================

/// Frame-decoder state machine (← curl `enum ws_dec_state`).
///
/// * [`WsDecState::Init`]   ≡ `WS_DEC_INIT`   — between frames; the next
///   [`WsDecoder::pass`] begins a fresh frame.
/// * [`WsDecState::Head`]   ≡ `WS_DEC_HEAD`   — accumulating the 2/4/10-byte
///   frame header (resumable across reads).
/// * [`WsDecState::Payload`] ≡ `WS_DEC_PAYLOAD` — streaming payload bytes to the
///   caller (also resumable — the header is fully parsed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WsDecState {
    Init,
    Head,
    Payload,
}

/// Client-side frame decoder (← curl `struct ws_decoder`).
///
/// Parses frame headers and payloads while tracking the current position, so a
/// single logical frame can be delivered across an arbitrary number of socket
/// reads. This is the resumable core; `state` records where parsing paused.
#[derive(Debug, Clone)]
struct WsDecoder {
    /// `frame_age` — always zero (reserved for future ABI use, as in curl).
    frame_age: i32,
    /// `frame_flags` — the `CURLWS_*` flags of the frame currently being decoded.
    frame_flags: u32,
    /// `payload_offset` — how far into the current frame's payload parsing is.
    payload_offset: i64,
    /// `payload_len` — the total payload length of the current frame.
    payload_len: i64,
    /// `head` — raw frame-header bytes accumulated so far (max 10: 2 base + up to
    /// 8 extended-length bytes; server frames are never masked, so no mask key).
    head: [u8; 10],
    /// `head_len` — number of header bytes accumulated.
    head_len: usize,
    /// `head_total` — total header length once the base byte reveals it (2/4/10).
    head_total: usize,
    /// `state` — resumable decoder state.
    state: WsDecState,
    /// `cont_flags` — the flags of an in-progress fragmented message, carried
    /// across `CONT` frames (preserved by `next_frame`, cleared by `reset`).
    cont_flags: u32,
}

/// Client-side frame encoder (← curl `struct ws_encoder`).
///
/// Generates frame headers and masks payloads, tracking how much of the current
/// frame remains to be emitted.
#[derive(Debug, Clone)]
struct WsEncoder {
    /// `payload_len` — payload length of the frame currently being encoded.
    payload_len: i64,
    /// `payload_remain` — payload bytes of the current frame not yet encoded.
    payload_remain: i64,
    /// `xori` — rotating index (0..=3) into `mask` for the XOR masking stream.
    xori: u32,
    /// `mask` — the 32-bit masking key for the current frame (RFC 6455 §5.3).
    mask: [u8; 4],
    /// `firstbyte` — the first byte (FIN|opcode) of the frame being encoded.
    firstbyte: u8,
    /// `contfragment` — true if the previous fragment sent was not final, so the
    /// next data frame must continue it.
    contfragment: bool,
}

/// A pending control frame awaiting transmission (← curl `struct ws_cntrl_frame`).
///
/// curl keeps at most one; a newer control frame overwrites an unsent older one.
#[derive(Debug, Clone)]
struct WsCntrlFrame {
    /// `type` (renamed — `type` is a Rust keyword): the `CURLWS_*` frame type,
    /// or `0` when no control frame is pending.
    frame_type: u32,
    /// `payload_len` — number of valid bytes in `payload`.
    payload_len: usize,
    /// `payload` — the control-frame body (≤ 125 bytes, RFC 6455 §5.5).
    payload: [u8; WS_MAX_CNTRL_LEN],
}

impl Default for WsCntrlFrame {
    fn default() -> Self {
        WsCntrlFrame {
            frame_type: 0,
            payload_len: 0,
            payload: [0u8; WS_MAX_CNTRL_LEN],
        }
    }
}

/// Metadata describing the WebSocket frame chunk most recently handed to the
/// caller — the safe-Rust mirror of the public ABI `struct curl_ws_frame`.
///
/// The FFI crate (`curl-rs-ffi`) owns the `#[repr(C)]` definition that crosses
/// the C boundary; this in-crate copy carries the identical fields (with
/// idiomatic Rust types) and is what the engine populates via [`update_meta`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CurlWsFrame {
    /// `age` — reserved, always zero.
    pub age: i32,
    /// `flags` — a bitmask of the `CURLWS_*` flag constants.
    pub flags: u32,
    /// `offset` — the offset of this chunk into the overall frame payload.
    pub offset: i64,
    /// `bytesleft` — payload bytes still pending after this chunk.
    pub bytesleft: i64,
    /// `len` — size of the current data chunk.
    pub len: usize,
}

// ===========================================================================
// First-byte ⇔ CURLWS_* flag translation (← `ws_frame_firstbyte2flags` /
// `ws_frame_flags2firstbyte`). Pure, total functions — exhaustively unit-tested.
// ===========================================================================

/// Translate a received frame's first byte into the `CURLWS_*` flag set
/// (← curl `ws_frame_firstbyte2flags`). `cont_flags` carries the flags of an
/// in-progress fragmented message.
///
/// Returns `Err(CURLE_RECV_ERROR)` for every protocol violation, reproducing
/// curl's exact `failf` message text (curl returns `0`, which its caller maps to
/// `CURLE_RECV_ERROR`).
fn frame_firstbyte2flags(firstbyte: u8, cont_flags: u32) -> Result<u32> {
    // Combined first-byte labels (opcode | FIN). Declared as `const` so they are
    // matched as constant patterns (NOT bitwise-or, which a bare `A | B` pattern
    // would mean) — mirroring curl's `switch` case labels exactly.
    const CONT: u8 = WSBIT_OPCODE_CONT; // 0x00
    const CONT_FIN: u8 = WSBIT_OPCODE_CONT | WSBIT_FIN; // 0x80
    const TEXT: u8 = WSBIT_OPCODE_TEXT; // 0x01
    const TEXT_FIN: u8 = WSBIT_OPCODE_TEXT | WSBIT_FIN; // 0x81
    const BIN: u8 = WSBIT_OPCODE_BIN; // 0x02
    const BIN_FIN: u8 = WSBIT_OPCODE_BIN | WSBIT_FIN; // 0x82
    const CLOSE: u8 = WSBIT_OPCODE_CLOSE; // 0x08
    const CLOSE_FIN: u8 = WSBIT_OPCODE_CLOSE | WSBIT_FIN; // 0x88
    const PING: u8 = WSBIT_OPCODE_PING; // 0x09
    const PING_FIN: u8 = WSBIT_OPCODE_PING | WSBIT_FIN; // 0x89
    const PONG: u8 = WSBIT_OPCODE_PONG; // 0x0a
    const PONG_FIN: u8 = WSBIT_OPCODE_PONG | WSBIT_FIN; // 0x8a

    match firstbyte {
        // 0x00 - intermediate TEXT/BINARY fragment
        CONT => {
            if cont_flags & CURLWS_CONT == 0 {
                return Err(recv_err("[WS] no ongoing fragmented message to resume"));
            }
            Ok(cont_flags | CURLWS_CONT)
        }
        // 0x80 - final TEXT/BIN fragment
        CONT_FIN => {
            if cont_flags & CURLWS_CONT == 0 {
                return Err(recv_err("[WS] no ongoing fragmented message to resume"));
            }
            Ok(cont_flags & !CURLWS_CONT)
        }
        // 0x01 - first TEXT fragment
        TEXT => {
            if cont_flags & CURLWS_CONT != 0 {
                return Err(recv_err(
                    "[WS] fragmented message interrupted by new TEXT msg",
                ));
            }
            Ok(CURLWS_TEXT | CURLWS_CONT)
        }
        // 0x81 - unfragmented TEXT msg
        TEXT_FIN => {
            if cont_flags & CURLWS_CONT != 0 {
                return Err(recv_err(
                    "[WS] fragmented message interrupted by new TEXT msg",
                ));
            }
            Ok(CURLWS_TEXT)
        }
        // 0x02 - first BINARY fragment
        BIN => {
            if cont_flags & CURLWS_CONT != 0 {
                return Err(recv_err(
                    "[WS] fragmented message interrupted by new BINARY msg",
                ));
            }
            Ok(CURLWS_BINARY | CURLWS_CONT)
        }
        // 0x82 - unfragmented BINARY msg
        BIN_FIN => {
            if cont_flags & CURLWS_CONT != 0 {
                return Err(recv_err(
                    "[WS] fragmented message interrupted by new BINARY msg",
                ));
            }
            Ok(CURLWS_BINARY)
        }
        // 0x08 - first CLOSE fragment (control frames must not be fragmented)
        CLOSE => Err(recv_err("[WS] invalid fragmented CLOSE frame")),
        // 0x88 - unfragmented CLOSE
        CLOSE_FIN => Ok(CURLWS_CLOSE),
        // 0x09 - first PING fragment
        PING => Err(recv_err("[WS] invalid fragmented PING frame")),
        // 0x89 - unfragmented PING
        PING_FIN => Ok(CURLWS_PING),
        // 0x0a - first PONG fragment
        PONG => Err(recv_err("[WS] invalid fragmented PONG frame")),
        // 0x8a - unfragmented PONG
        PONG_FIN => Ok(CURLWS_PONG),
        // invalid first byte
        _ => {
            if firstbyte & WSBIT_RSV_MASK != 0 {
                // any of the reserved bits 0x40/0x20/0x10 are set
                Err(recv_err(format!(
                    "[WS] invalid reserved bits: {firstbyte:02x}"
                )))
            } else {
                // a reserved opcode 0x3-0x7 or 0xb-0xf is used
                Err(recv_err(format!("[WS] invalid opcode: {firstbyte:02x}")))
            }
        }
    }
}

/// Translate an application-supplied `CURLWS_*` flag set into the frame's first
/// byte (← curl `ws_frame_flags2firstbyte`). `contfragment` is true when the
/// previous data frame left a fragment open.
///
/// Returns `Err(CURLE_BAD_FUNCTION_ARGUMENT)` for illegal combinations, with
/// curl's exact message text.
fn frame_flags2firstbyte(flags: u32, contfragment: bool) -> Result<u8> {
    match flags & !CURLWS_OFFSET {
        0 => {
            if contfragment {
                // curl: "no flags given; interpreting as continuation fragment
                // for compatibility" (trace-level informational only).
                Ok(WSBIT_OPCODE_CONT | WSBIT_FIN)
            } else {
                Err(arg_err("[WS] no flags given"))
            }
        }
        CURLWS_CONT => {
            if contfragment {
                // curl emits an informational "supported for compatibility but
                // highly discouraged" note here; behavior is the bare CONT byte.
                Ok(WSBIT_OPCODE_CONT)
            } else {
                Err(arg_err("[WS] No ongoing fragmented message to continue"))
            }
        }
        CURLWS_TEXT => Ok(if contfragment {
            WSBIT_OPCODE_CONT | WSBIT_FIN
        } else {
            WSBIT_OPCODE_TEXT | WSBIT_FIN
        }),
        x if x == CURLWS_TEXT | CURLWS_CONT => Ok(if contfragment {
            WSBIT_OPCODE_CONT
        } else {
            WSBIT_OPCODE_TEXT
        }),
        CURLWS_BINARY => Ok(if contfragment {
            WSBIT_OPCODE_CONT | WSBIT_FIN
        } else {
            WSBIT_OPCODE_BIN | WSBIT_FIN
        }),
        x if x == CURLWS_BINARY | CURLWS_CONT => Ok(if contfragment {
            WSBIT_OPCODE_CONT
        } else {
            WSBIT_OPCODE_BIN
        }),
        CURLWS_CLOSE => Ok(WSBIT_OPCODE_CLOSE | WSBIT_FIN),
        x if x == CURLWS_CLOSE | CURLWS_CONT => {
            Err(arg_err("[WS] CLOSE frame must not be fragmented"))
        }
        CURLWS_PING => Ok(WSBIT_OPCODE_PING | WSBIT_FIN),
        x if x == CURLWS_PING | CURLWS_CONT => {
            Err(arg_err("[WS] PING frame must not be fragmented"))
        }
        CURLWS_PONG => Ok(WSBIT_OPCODE_PONG | WSBIT_FIN),
        x if x == CURLWS_PONG | CURLWS_CONT => {
            Err(arg_err("[WS] PONG frame must not be fragmented"))
        }
        other => Err(arg_err(format!("[WS] unknown flags: {other:x}"))),
    }
}

/// Human-readable name of the opcode carried in a frame's first byte
/// (← curl `ws_frame_name_of_op`, gated behind `CURLVERBOSE`).
///
/// The opcode occupies the low nibble ([`WSBIT_OPCODE_MASK`]); the returned
/// name feeds the `--trace` diagnostics emitted by [`WsDecoder::dec_info`], so
/// the vocabulary must match curl 8.x verbatim (`"???"` for reserved opcodes).
fn frame_name_of_op(firstbyte: u8) -> &'static str {
    match firstbyte & WSBIT_OPCODE_MASK {
        WSBIT_OPCODE_CONT => "CONT",
        WSBIT_OPCODE_TEXT => "TEXT",
        WSBIT_OPCODE_BIN => "BIN",
        WSBIT_OPCODE_CLOSE => "CLOSE",
        WSBIT_OPCODE_PING => "PING",
        WSBIT_OPCODE_PONG => "PONG",
        _ => "???",
    }
}

/// The resumable "need more input" signal (← curl's `CURLE_AGAIN`). The decoder
/// returns this to mean "pause here and call me again with more bytes".
fn again_err() -> Error {
    Error::Again
}

/// Clamp a signed `curl_off_t` value into `[0, usize::MAX]` (← curl
/// `curlx_sotouz_range(v, 0, SIZE_MAX)`): negatives saturate to `0`, and values
/// exceeding the platform `usize` saturate to `usize::MAX`.
fn clamp_off_to_usize(v: i64) -> usize {
    if v <= 0 {
        0
    } else {
        usize::try_from(v).unwrap_or(usize::MAX)
    }
}

/// Widen a `usize` byte count into `curl_off_t` (← curl `curlx_uztoso`),
/// saturating at `i64::MAX` (unreachable for real WebSocket buffers).
fn usize_to_off(v: usize) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Compute the payload remaining after `payload_buffered` bytes of the current
/// frame chunk are accounted for (← curl `ws_payload_remain`). Returns `-1` on
/// any inconsistency, exactly as curl does.
fn ws_payload_remain(payload_total: i64, payload_offset: i64, payload_buffered: usize) -> i64 {
    let remain = payload_total - payload_offset;
    if payload_total < 0 || payload_offset < 0 || remain < 0 {
        return -1;
    }
    let buffered = usize_to_off(payload_buffered);
    if remain < buffered {
        return -1;
    }
    remain - buffered
}

/// Populate the caller-visible frame metadata (← curl `update_meta`).
fn update_meta(
    frame: &mut CurlWsFrame,
    frame_age: i32,
    frame_flags: u32,
    payload_offset: i64,
    payload_len: i64,
    cur_len: usize,
) {
    let cur = usize_to_off(cur_len);
    frame.age = frame_age;
    frame.flags = frame_flags;
    frame.offset = payload_offset;
    frame.len = cur_len;
    frame.bytesleft = payload_len - payload_offset - cur;
}

/// Signature of the decode payload sink (← curl's `ws_write_payload` typedef).
///
/// Invoked with the freshly decoded chunk plus the frame metadata; returns the
/// number of bytes consumed. Returning [`Error::Again`] means "no room, resume
/// later" — any other `Err` is a hard failure.
///
/// Parameters: `(payload_chunk, frame_age, frame_flags, payload_offset,
/// payload_len)`.
type WsWriteCb<'c> = dyn FnMut(&[u8], i32, u32, i64, i64) -> Result<usize> + 'c;

impl WsDecoder {
    /// Construct a fresh decoder in the [`WsDecState::Init`] state (≡ curl
    /// `ws_dec_init`, which is a `ws_dec_reset` over zeroed memory).
    fn new() -> Self {
        WsDecoder {
            frame_age: 0,
            frame_flags: 0,
            payload_offset: 0,
            payload_len: 0,
            head: [0u8; 10],
            head_len: 0,
            head_total: 0,
            state: WsDecState::Init,
            cont_flags: 0,
        }
    }

    /// Prepare for the next frame while preserving `cont_flags` (← curl
    /// `ws_dec_next_frame`) — fragmentation continuity spans frames.
    fn next_frame(&mut self) {
        self.frame_age = 0;
        self.frame_flags = 0;
        self.payload_offset = 0;
        self.payload_len = 0;
        self.head_len = 0;
        self.head_total = 0;
        self.state = WsDecState::Init;
        // dec->cont_flags is intentionally carried over to the next frame.
    }

    /// Full reset including fragmentation continuity (← curl `ws_dec_reset`,
    /// which `ws_dec_init` also calls).
    fn reset(&mut self) {
        self.next_frame();
        self.cont_flags = 0;
    }

    /// Emit a `--trace`-level diagnostic about the current header progress
    /// (← curl `ws_dec_info` + its `CURL_TRC_WS` output).
    ///
    /// The message shape mirrors curl exactly: the opcode name (via
    /// [`frame_name_of_op`]), a `NON-FINAL` marker when the FIN bit is clear,
    /// and either the head accumulation ratio (while the header is still being
    /// read) or the payload progress (once the header is complete).
    fn dec_info(&self, msg: &str) {
        let name = frame_name_of_op(self.head[0]);
        let fin = if self.head[0] & WSBIT_FIN != 0 {
            ""
        } else {
            " NON-FINAL"
        };
        match self.head_len {
            0 => {}
            1 => tracing::trace!(target: WS_TRACE_TARGET, "decoded {msg} [{name}{fin}]"),
            _ if self.head_len < self.head_total => {
                let (have, total) = (self.head_len, self.head_total);
                tracing::trace!(
                    target: WS_TRACE_TARGET,
                    "decoded {msg} [{name}{fin}]({have}/{total})"
                );
            }
            _ => {
                let (off, len) = (self.payload_offset, self.payload_len);
                tracing::trace!(
                    target: WS_TRACE_TARGET,
                    "decoded {msg} [{name}{fin} payload={off}/{len}]"
                );
            }
        }
    }

    /// Parse the frame header from `inraw`, consuming bytes as it goes
    /// (← curl `ws_dec_read_head`).
    ///
    /// Resumable: partial headers leave `head`/`head_len` populated so a later
    /// call finishes the job. Returns `Ok(())` once the complete header is
    /// parsed (with `payload_len` set), [`Error::Again`] when more input is
    /// needed, or a hard `CURLE_RECV_ERROR` on a protocol violation.
    fn read_head(&mut self, inraw: &mut BytesMut) -> Result<()> {
        while !inraw.is_empty() {
            if self.head_len == 0 {
                self.head[0] = inraw[0];
                inraw.advance(1);

                self.frame_flags = match frame_firstbyte2flags(self.head[0], self.cont_flags) {
                    Ok(f) => f,
                    Err(e) => {
                        self.reset();
                        return Err(e);
                    }
                };

                // Fragmentation only applies to data frames (text/binary);
                // control frames (close/ping/pong) do not affect CONT status.
                if self.frame_flags & (CURLWS_TEXT | CURLWS_BINARY) != 0 {
                    self.cont_flags = self.frame_flags;
                }

                self.head_len = 1;
                continue;
            } else if self.head_len == 1 {
                self.head[1] = inraw[0];
                inraw.advance(1);
                self.head_len = 2;

                if self.head[1] & WSBIT_MASK != 0 {
                    // A client MUST close the connection on a masked frame.
                    self.reset();
                    return Err(recv_err("[WS] masked input frame"));
                }
                let len_byte = usize::from(self.head[1]);
                if self.frame_flags & CURLWS_PING != 0 && len_byte > WS_MAX_CNTRL_LEN {
                    // Accepting an over-long PING would force an over-long PONG.
                    self.reset();
                    return Err(recv_err("[WS] received PING frame is too big"));
                }
                if self.frame_flags & CURLWS_PONG != 0 && len_byte > WS_MAX_CNTRL_LEN {
                    self.reset();
                    return Err(recv_err("[WS] received PONG frame is too big"));
                }
                if self.frame_flags & CURLWS_CLOSE != 0 && len_byte > WS_MAX_CNTRL_LEN {
                    self.reset();
                    return Err(recv_err("[WS] received CLOSE frame is too big"));
                }

                // How long is the frame head?
                if self.head[1] == 126 {
                    self.head_total = 4;
                    continue;
                } else if self.head[1] == 127 {
                    self.head_total = 10;
                    continue;
                } else {
                    self.head_total = 2;
                }
            }

            if self.head_len < self.head_total {
                self.head[self.head_len] = inraw[0];
                inraw.advance(1);
                self.head_len += 1;
                if self.head_len < self.head_total {
                    continue;
                }
            }

            // Got the complete frame head — decode the payload length.
            debug_assert_eq!(self.head_len, self.head_total);
            match self.head_total {
                2 => {
                    self.payload_len = i64::from(self.head[1]);
                }
                4 => {
                    self.payload_len = (i64::from(self.head[2]) << 8) | i64::from(self.head[3]);
                }
                10 => {
                    if self.head[2] > 127 {
                        return Err(recv_err(
                            "[WS] frame length longer than 63 bits not supported",
                        ));
                    }
                    self.payload_len = (i64::from(self.head[2]) << 56)
                        | (i64::from(self.head[3]) << 48)
                        | (i64::from(self.head[4]) << 40)
                        | (i64::from(self.head[5]) << 32)
                        | (i64::from(self.head[6]) << 24)
                        | (i64::from(self.head[7]) << 16)
                        | (i64::from(self.head[8]) << 8)
                        | i64::from(self.head[9]);
                }
                _ => {
                    // Unreachable: head_total is only ever set to 2, 4, or 10.
                    return Err(recv_err("[WS] unexpected frame header length"));
                }
            }

            self.frame_age = 0;
            self.payload_offset = 0;
            self.dec_info("decoded"); // ← curl ws_dec_info(dec, data, "decoded")
            return Ok(());
        }
        // Ran out of input before the header completed.
        self.dec_info("decoding head"); // ← curl ws_dec_info(dec, data, "decoding head")
        Err(again_err())
    }

    /// Stream payload bytes from `inraw` to `write_cb` (← curl
    /// `ws_dec_pass_payload`). Resumable across reads via `payload_offset`.
    fn pass_payload(&mut self, inraw: &mut BytesMut, write_cb: &mut WsWriteCb<'_>) -> Result<()> {
        self.dec_info("passing"); // ← curl ws_dec_info(dec, data, "passing")
        let mut remain = clamp_off_to_usize(self.payload_len - self.payload_offset);

        while remain > 0 && !inraw.is_empty() {
            let inlen = inraw.len().min(remain);
            let nwritten = write_cb(
                &inraw[..inlen],
                self.frame_age,
                self.frame_flags,
                self.payload_offset,
                self.payload_len,
            )?;
            inraw.advance(nwritten);
            self.payload_offset += usize_to_off(nwritten);
            remain = clamp_off_to_usize(self.payload_len - self.payload_offset);
            if nwritten == 0 {
                // Defensive: a sink that accepts nothing cannot make progress —
                // pause rather than spin. (curl's collector never does this for
                // a non-empty chunk; it returns CURLE_AGAIN instead.)
                break;
            }
        }

        if remain > 0 {
            Err(again_err())
        } else {
            Ok(())
        }
    }

    /// Drive the decoder state machine over `inraw`, delivering at most one
    /// frame's worth of decoded payload to `write_cb` (← curl `ws_dec_pass`).
    ///
    /// Returns `Ok(())` when a frame (or a resumable slice of one) has been
    /// fully passed, [`Error::Again`] when more network input is required (state
    /// is preserved for the next call), or a hard error on a protocol fault.
    fn pass<F>(&mut self, inraw: &mut BytesMut, mut write_cb: F) -> Result<()>
    where
        F: FnMut(&[u8], i32, u32, i64, i64) -> Result<usize>,
    {
        if inraw.is_empty() {
            return Err(again_err());
        }

        loop {
            match self.state {
                WsDecState::Init => {
                    self.next_frame();
                    self.state = WsDecState::Head;
                    // Fall through to header parsing in the next loop turn.
                }
                WsDecState::Head => {
                    self.read_head(inraw)?; // Again / hard error propagate as-is.
                    self.state = WsDecState::Payload;
                    if self.payload_len == 0 {
                        // Zero-length frame: the sink is invoked exactly once.
                        write_cb(&[], self.frame_age, self.frame_flags, 0, 0)?;
                        self.state = WsDecState::Init;
                        return Ok(());
                    }
                    // Fall through to payload streaming in the next loop turn.
                }
                WsDecState::Payload => {
                    self.pass_payload(inraw, &mut write_cb)?;
                    self.state = WsDecState::Init;
                    return Ok(());
                }
            }
        }
    }
}

/// Fill `mask` with four fresh random bytes for a new outgoing frame (← curl's
/// `Curl_rand` call in `ws_enc_add_frame`).
///
/// In debug builds only — mirroring curl's `DEBUGBUILD` gating — the
/// `CURL_WS_FORCE_ZERO_MASK` environment variable forces an all-zero mask, which
/// curl's test suite relies on to make outgoing frames byte-deterministic. In
/// release builds the override is compiled out and the mask is always random.
fn fill_mask(mask: &mut [u8; 4]) {
    #[cfg(debug_assertions)]
    {
        if std::env::var_os("CURL_WS_FORCE_ZERO_MASK").is_some() {
            *mask = [0u8; 4];
            return;
        }
    }
    rand::thread_rng().fill_bytes(mask.as_mut_slice());
}

impl WsEncoder {
    /// Construct a fresh encoder (≡ curl `ws_enc_init` over zeroed memory).
    fn new() -> Self {
        WsEncoder {
            payload_len: 0,
            payload_remain: 0,
            xori: 0,
            mask: [0u8; 4],
            firstbyte: 0,
            contfragment: false,
        }
    }

    /// Reset the encoder between transfers (← curl `ws_enc_reset`). The mask is
    /// left as-is (it is regenerated for every frame in [`WsEncoder::add_frame`]).
    fn reset(&mut self) {
        self.payload_remain = 0;
        self.xori = 0;
        self.contfragment = false;
    }

    /// Emit a frame header for a new frame of `payload_len` bytes into `out`,
    /// generating a fresh mask (← curl `ws_enc_add_frame`).
    ///
    /// Fails with `CURLE_SEND_ERROR` on a negative length or when a previous
    /// frame is still unfinished, and `CURLE_TOO_LARGE` for oversized control
    /// frames — matching curl's checks and message text exactly.
    fn add_frame(&mut self, flags: u32, payload_len: i64, out: &mut BytesMut) -> Result<()> {
        if payload_len < 0 {
            return Err(send_err(format!(
                "[WS] starting new frame with negative payload length {payload_len}"
            )));
        }

        if self.payload_remain > 0 {
            // Trying to write a new frame before the previous one is finished.
            return Err(send_err(format!(
                "[WS] starting new frame with {} bytes from last one remaining to be sent",
                self.payload_remain
            )));
        }

        let firstb = frame_flags2firstbyte(flags, self.contfragment)?;

        // Fragmentation only applies to data frames (text/binary); control
        // frames (close/ping/pong) do not affect the CONT status.
        if flags & (CURLWS_TEXT | CURLWS_BINARY) != 0 {
            self.contfragment = flags & CURLWS_CONT != 0;
        }

        let max_cntrl = WS_MAX_CNTRL_LEN as i64;
        if flags & CURLWS_PING != 0 && payload_len > max_cntrl {
            return Err(Error::with_context(
                CurlCode::TooLarge,
                "[WS] given PING frame is too big",
            ));
        }
        if flags & CURLWS_PONG != 0 && payload_len > max_cntrl {
            return Err(Error::with_context(
                CurlCode::TooLarge,
                "[WS] given PONG frame is too big",
            ));
        }
        if flags & CURLWS_CLOSE != 0 && payload_len > max_cntrl {
            return Err(Error::with_context(
                CurlCode::TooLarge,
                "[WS] given CLOSE frame is too big",
            ));
        }

        let mut head = [0u8; 14];
        self.firstbyte = firstb;
        head[0] = firstb;
        let hlen: usize;
        if payload_len > 65535 {
            head[1] = 127 | WSBIT_MASK;
            head[2] = ((payload_len >> 56) & 0xff) as u8;
            head[3] = ((payload_len >> 48) & 0xff) as u8;
            head[4] = ((payload_len >> 40) & 0xff) as u8;
            head[5] = ((payload_len >> 32) & 0xff) as u8;
            head[6] = ((payload_len >> 24) & 0xff) as u8;
            head[7] = ((payload_len >> 16) & 0xff) as u8;
            head[8] = ((payload_len >> 8) & 0xff) as u8;
            head[9] = (payload_len & 0xff) as u8;
            hlen = 10;
        } else if payload_len >= 126 {
            head[1] = 126 | WSBIT_MASK;
            head[2] = ((payload_len >> 8) & 0xff) as u8;
            head[3] = (payload_len & 0xff) as u8;
            hlen = 4;
        } else {
            head[1] = (payload_len as u8) | WSBIT_MASK;
            hlen = 2;
        }

        self.payload_remain = payload_len;
        self.payload_len = payload_len;

        // 4 bytes random mask (client→server frames MUST be masked).
        fill_mask(&mut self.mask);
        head[hlen..hlen + 4].copy_from_slice(&self.mask);
        let total = hlen + 4;
        // reset for the payload to come
        self.xori = 0;

        out.extend_from_slice(&head[..total]);
        Ok(())
    }

    /// Mask and buffer up to one [`WS_CHUNK_SIZE`] chunk of `buf`'s payload into
    /// `out`, advancing the rolling XOR index (← curl `ws_enc_write_payload`).
    ///
    /// Returns the number of payload bytes consumed. curl streams a frame's
    /// payload through a **bounded** `bufq` (`WS_CHUNK_SIZE` bytes per chunk),
    /// so a single call never materialises more than one chunk;
    /// [`Websocket::enc_send`] flushes `out` to the transport between calls and
    /// re-enters here for the next chunk. Bounding each call this way keeps the
    /// send buffer size independent of the (possibly huge) frame size — the
    /// growable `out` never balloons to hold the whole payload — while the
    /// flush-between-chunks loop supplies the `CURLE_AGAIN` backpressure that
    /// curl's bufq soft-limit provides once the transport stops draining. The
    /// bytes are masked straight into `out` (a single reserve, with no throwaway
    /// intermediate buffer doubling the copy and the allocation).
    fn write_payload(&mut self, buf: &[u8], out: &mut BytesMut) -> Result<usize> {
        let remain = clamp_off_to_usize(self.payload_remain);
        // Bound the amount encoded per call to one transmit chunk so a large
        // frame is streamed in `WS_CHUNK_SIZE` pieces rather than buffered whole.
        let len = buf.len().min(remain).min(WS_CHUNK_SIZE);

        let start = self.xori as usize;
        // Mask directly into `out`: reserve once, then append the XOR-masked
        // bytes via the byte iterator (no temporary `Vec`).
        out.reserve(len);
        out.extend(
            buf[..len]
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ self.mask[(start + i) & 3]),
        );

        self.xori = ((start + len) & 3) as u32;
        self.payload_remain -= usize_to_off(len);
        Ok(len)
    }
}

// ===========================================================================
// The per-connection WebSocket engine (← curl `struct websocket` + the
// `Curl_ws_*` / `curl_ws_*` functions).
// ===========================================================================

/// A live WebSocket connection: the frame decoder/encoder plus the receive and
/// transmit buffers and the per-transfer flags (← curl `struct websocket`).
///
/// This is the object the FFI layer's `curl_ws_send` / `curl_ws_recv` /
/// `curl_ws_start_frame` / `curl_ws_meta` trampolines drive: they call
/// [`Websocket::send`], [`Websocket::recv`], [`Websocket::start_frame`], and
/// [`Websocket::meta`] respectively.
pub struct Websocket {
    /// Frame decoder (server→client) — `struct websocket.dec`.
    dec: WsDecoder,
    /// Frame encoder (client→server) — `struct websocket.enc`.
    enc: WsEncoder,
    /// Raw bytes received from the server awaiting decode — `websocket.recvbuf`.
    recvbuf: BytesMut,
    /// Raw bytes encoded and awaiting transmission — `websocket.sendbuf`.
    sendbuf: BytesMut,
    /// Metadata for the frame chunk most recently returned — `websocket.recvframe`.
    recvframe: CurlWsFrame,
    /// A single pending control frame to be sent — `websocket.pending`.
    pending: WsCntrlFrame,
    /// Count of payload bytes currently buffered in `sendbuf` for the frame in
    /// progress — `websocket.sendbuf_payload`.
    sendbuf_payload: usize,
    /// `CURLWS_RAW_MODE` — passthrough without libcurl framing (`data->set.ws_raw_mode`).
    raw_mode: bool,
    /// `CURLWS_NOAUTOPONG` — suppress automatic PONG replies (`data->set.ws_no_auto_pong`).
    no_auto_pong: bool,
    /// Whether the transfer is in `CURLOPT_CONNECT_ONLY` mode.
    connect_only: bool,
    /// The `Sec-WebSocket-Key` this side sent, retained to validate the server's
    /// `Sec-WebSocket-Accept` reply.
    sec_key: String,
}

impl Default for Websocket {
    fn default() -> Self {
        Self::new()
    }
}

impl Websocket {
    /// Create a fresh, unconnected engine (buffers empty, decoder/encoder in
    /// their initial states).
    #[must_use]
    pub fn new() -> Self {
        Websocket {
            dec: WsDecoder::new(),
            enc: WsEncoder::new(),
            recvbuf: BytesMut::new(),
            sendbuf: BytesMut::new(),
            recvframe: CurlWsFrame::default(),
            pending: WsCntrlFrame::default(),
            sendbuf_payload: 0,
            raw_mode: false,
            no_auto_pong: false,
            connect_only: false,
            sec_key: String::new(),
        }
    }

    /// Apply the `CURLOPT_WS_OPTIONS` bits (raw mode / auto-pong suppression) and
    /// the connect-only flag before the handshake.
    pub fn configure(&mut self, raw_mode: bool, no_auto_pong: bool, connect_only: bool) {
        self.raw_mode = raw_mode;
        self.no_auto_pong = no_auto_pong;
        self.connect_only = connect_only;
    }

    /// Whether raw (unframed) mode is active.
    #[must_use]
    pub fn is_raw_mode(&self) -> bool {
        self.raw_mode
    }

    // -- Handshake --------------------------------------------------------

    /// Generate a fresh `Sec-WebSocket-Key`: a base64-encoded 16-byte nonce
    /// (RFC 6455 §4.1, ← curl's `Curl_rand` + `curlx_base64_encode`).
    #[must_use]
    fn sec_websocket_key() -> String {
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        BASE64_STANDARD.encode(nonce)
    }

    /// Compute the expected `Sec-WebSocket-Accept` value for a given client key:
    /// `base64(SHA-1(key ++ WS_GUID))` (RFC 6455 §4.2.2).
    #[must_use]
    fn sec_websocket_accept(key: &str) -> String {
        let mut hasher = Sha1::new();
        hasher.update(key.as_bytes());
        hasher.update(WS_GUID.as_bytes());
        let digest = hasher.finalize();
        BASE64_STANDARD.encode(digest)
    }

    /// Produce the WebSocket-specific handshake header lines (← curl
    /// `Curl_ws_request`): `Upgrade`, `Sec-WebSocket-Version`, and a freshly
    /// generated `Sec-WebSocket-Key` (which is retained for accept validation).
    ///
    /// Each header is emitted as `"{name}: {value}\r\n"`, and — exactly like curl
    /// — any header already supplied by the application (named in `existing`,
    /// matched case-insensitively) is skipped so it is not duplicated.
    ///
    /// In the integrated transfer these lines are appended to the HTTP/1.1
    /// request the HTTP handler builds; [`Websocket::build_upgrade_request`]
    /// assembles a complete request for the connect-only path and for testing.
    pub fn ws_request_headers(&mut self, existing: &[&str]) -> Vec<u8> {
        self.sec_key = Self::sec_websocket_key();
        let heads: [(&str, &str); 3] = [
            ("Upgrade", "websocket"),
            ("Sec-WebSocket-Version", "13"),
            ("Sec-WebSocket-Key", self.sec_key.as_str()),
        ];
        let mut out = Vec::new();
        for (name, val) in heads {
            if !existing.iter().any(|h| h.eq_ignore_ascii_case(name)) {
                out.extend_from_slice(format!("{name}: {val}\r\n").as_bytes());
            }
        }
        out
    }

    /// Assemble a complete HTTP/1.1 WebSocket upgrade request for `path` on
    /// `host`, including the mandatory `Connection: Upgrade` and the WS headers
    /// from [`Websocket::ws_request_headers`], followed by any `extra` header
    /// lines (each without a trailing CRLF) and the terminating blank line.
    ///
    /// This mirrors the request curl transmits: in the fully integrated build
    /// the HTTP handler owns the request line / `Host` / default headers and the
    /// WS handler contributes the upgrade headers; this helper is the
    /// self-contained equivalent used on the connect-only path and in tests.
    pub fn build_upgrade_request(&mut self, path: &str, host: &str, extra: &[&str]) -> Vec<u8> {
        let mut req = Vec::new();
        req.extend_from_slice(format!("GET {path} HTTP/1.1\r\n").as_bytes());
        req.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
        req.extend_from_slice(b"Connection: Upgrade\r\n");
        // Existing header names so ws_request_headers does not duplicate them.
        req.extend_from_slice(&self.ws_request_headers(&["Connection"]));
        for line in extra {
            req.extend_from_slice(line.as_bytes());
            req.extend_from_slice(b"\r\n");
        }
        req.extend_from_slice(b"\r\n");
        req
    }

    /// Parse the server handshake response, returning
    /// `(status_code, sec_websocket_accept, body_offset)`.
    ///
    /// `body_offset` is the index of the first byte after the `\r\n\r\n` header
    /// terminator. Returns [`Error::Again`] if the header block is not yet
    /// complete, and `CURLE_WEIRD_SERVER_REPLY` if the status line is malformed.
    fn parse_status_and_accept(response: &[u8]) -> Result<(u16, Option<String>, usize)> {
        let sep = b"\r\n\r\n";
        let term = response
            .windows(sep.len())
            .position(|w| w == sep)
            .ok_or_else(again_err)?;
        let body_offset = term + sep.len();

        let head = std::str::from_utf8(&response[..term])
            .map_err(|_| recv_err_weird("[WS] non-ASCII bytes in server handshake response"))?;

        let mut lines = head.split("\r\n");
        let status_line = lines
            .next()
            .ok_or_else(|| recv_err_weird("[WS] empty server handshake response"))?;

        // "HTTP/1.1 101 Switching Protocols" -> the second whitespace token.
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|tok| tok.parse::<u16>().ok())
            .ok_or_else(|| recv_err_weird("[WS] malformed status line in handshake response"))?;

        let mut accept_val: Option<String> = None;
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                if name.trim().eq_ignore_ascii_case("Sec-WebSocket-Accept") {
                    accept_val = Some(value.trim().to_string());
                    break;
                }
            }
        }

        Ok((status_code, accept_val, body_offset))
    }

    /// Complete the WebSocket handshake from the raw server `response` bytes
    /// (← curl `Curl_ws_accept`, plus the RFC 6455 §4.2.2 `Sec-WebSocket-Accept`
    /// validation that the AAP mandates — curl 8.19 only comments on this step).
    ///
    /// On success the decoder/encoder and buffers are (re)initialised and any
    /// payload bytes that arrived after the response headers are buffered for
    /// [`Websocket::recv`]; the number of such leftover bytes is returned.
    ///
    /// Errors: a non-`101` status yields `CURLE_HTTP_RETURNED_ERROR`; a missing
    /// or mismatched `Sec-WebSocket-Accept` yields `CURLE_WEIRD_SERVER_REPLY`.
    pub fn accept(&mut self, response: &[u8]) -> Result<usize> {
        let (status, accept_val, body_offset) = Self::parse_status_and_accept(response)?;

        if status != 101 {
            return Err(Error::HttpReturnedError(u32::from(status)));
        }

        let expected = Self::sec_websocket_accept(&self.sec_key);
        match accept_val {
            Some(ref v) if v == &expected => {}
            Some(_) => {
                return Err(recv_err_weird(
                    "[WS] server reply Sec-WebSocket-Accept mismatch",
                ));
            }
            None => {
                return Err(recv_err_weird(
                    "[WS] server reply missing Sec-WebSocket-Accept",
                ));
            }
        }

        // Handshake accepted: (re)initialise state (← Curl_ws_accept setup).
        self.dec.reset();
        self.enc.reset();
        self.recvbuf.clear();
        self.pending = WsCntrlFrame::default();
        self.sendbuf_payload = 0;

        let leftover = &response[body_offset..];
        self.recvbuf.extend_from_slice(leftover);
        Ok(leftover.len())
    }
}

/// Build a `CURLE_WEIRD_SERVER_REPLY` (8) — the handshake-validation failure
/// code the AAP requires for a bad `Sec-WebSocket-Accept`.
fn recv_err_weird(msg: impl Into<String>) -> Error {
    Error::with_context(CurlCode::WeirdServerReply, msg)
}

// ===========================================================================
// Transport abstraction (← curl's `nw_in_recv` / `Curl_xfer_send` seams).
// ===========================================================================

/// Byte-stream transport the WebSocket engine reads frames from and writes
/// frames to.
///
/// The production implementor is [`crate::conn::FilterChain`]: its filter stack
/// already terminates TLS for `wss://` (an SSL filter in the chain), so the
/// exact same framing code runs unchanged over plaintext and TLS — mirroring
/// curl, where `ws.c` performs no TLS work of its own. Tests provide an
/// in-memory implementor.
///
/// This models curl's `nw_in_recv` (which wraps `curl_easy_recv` /
/// `Curl_conn_recv`) and the `Curl_xfer_send` / `Curl_senddata` calls inside
/// `ws_flush`.
#[allow(async_fn_in_trait)] // Used only via static dispatch within this crate.
pub trait WsIo {
    /// Read up to `buf.len()` bytes from the transport. `Ok(0)` signals the peer
    /// closed the connection.
    async fn ws_recv(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Write bytes to the transport, returning how many were accepted (a partial
    /// write is permitted; `Ok(0)` is treated as "would block").
    async fn ws_send(&mut self, buf: &[u8]) -> Result<usize>;
}

impl WsIo for FilterChain {
    async fn ws_recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        // Delegates through the filter chain (TCP → [TLS] → ...), exactly as
        // curl's WS recv path bottoms out in the connection filters.
        self.recv(buf).await
    }

    async fn ws_send(&mut self, buf: &[u8]) -> Result<usize> {
        // `eos = false`: WebSocket frames never mark end-of-stream at this layer.
        self.send(buf, false).await
    }
}

impl Websocket {
    // -- Encoder-side control-frame helpers -------------------------------

    /// Begin a new outgoing frame, first materialising any pending control frame
    /// as part of the flush (← curl `ws_enc_write_head`).
    fn enc_write_head(&mut self, flags: u32, payload_len: i64) -> Result<()> {
        if self.pending.frame_type != 0 {
            self.enc_add_pending()?;
        }
        // Disjoint field borrows (`enc` + `sendbuf`) — permitted in one call.
        self.enc.add_frame(flags, payload_len, &mut self.sendbuf)
    }

    /// Encode the pending control frame into `sendbuf` if one is queued and no
    /// data frame is mid-flight (← curl `ws_enc_add_pending`).
    ///
    /// Together with the inline PONG-queueing in [`Websocket::recv_one`] this
    /// reproduces curl's `ws_enc_add_cntrl`: `recv_one` stores the control frame
    /// into `pending` (curl's `ws->enc.pending`) and this method materialises it
    /// into `sendbuf` once the encoder is idle. Splitting the queue step from the
    /// encode step is what lets the receive path answer a PING without the
    /// decoder/encoder borrow conflict a single combined call would create.
    ///
    /// Returns [`Error::Again`] when a data frame is still in progress (the
    /// control frame stays queued for later), matching curl.
    fn enc_add_pending(&mut self) -> Result<()> {
        if self.pending.frame_type == 0 {
            return Ok(()); // no pending frame
        }
        if self.enc.payload_remain != 0 {
            return Err(again_err()); // in the middle of another frame
        }

        let ptype = self.pending.frame_type;
        let plen = self.pending.payload_len;

        // `enc` (mut, receiver) + `sendbuf` (mut) are disjoint fields → OK.
        self.enc
            .add_frame(ptype, usize_to_off(plen), &mut self.sendbuf)?;
        // `enc` (mut) + `pending.payload` (shared) + `sendbuf` (mut) — all
        // disjoint fields of `self`, so this single call type-checks.
        let n = self
            .enc
            .write_payload(&self.pending.payload[..plen], &mut self.sendbuf)?;
        if n != plen {
            return Err(send_err(format!(
                "[WS] control frame buffered only {n}/{plen} payload bytes"
            )));
        }
        debug_assert_eq!(self.enc.payload_remain, 0);
        self.pending = WsCntrlFrame::default();
        Ok(())
    }

    // -- Transmit-buffer flush --------------------------------------------

    /// Push the buffered `sendbuf` bytes to the transport until empty (← curl
    /// `ws_flush`).
    ///
    /// Returns [`Error::Again`] if the transport accepts nothing while bytes
    /// remain (a would-block), leaving the unsent remainder in `sendbuf` for a
    /// later retry — exactly as curl's `ws_flush` returns `CURLE_AGAIN` with the
    /// remainder still queued.
    async fn flush<T: WsIo>(&mut self, io: &mut T) -> Result<()> {
        while !self.sendbuf.is_empty() {
            let n = io.ws_send(&self.sendbuf).await?;
            if n == 0 {
                return Err(again_err());
            }
            self.sendbuf.advance(n);
        }
        Ok(())
    }

    // -- Receive path (← ws_client_collect / curl_ws_recv) ----------------

    /// Decode at most one frame chunk out of the already-buffered `recvbuf` into
    /// `out` (← curl `ws_dec_pass` + `ws_client_collect`, minus the network
    /// slurp which the async driver owns).
    ///
    /// A PING whose full payload is present is auto-answered by queueing a PONG
    /// (into `pending`) rather than delivering it — matching curl — unless
    /// `no_auto_pong` is set. Any other frame chunk is copied into `out` and
    /// reported via [`RecvStep::Delivered`]; when nothing is delivered (an
    /// auto-ponged PING, or a header/​payload split across reads) the result is
    /// [`RecvStep::NeedMore`].
    fn recv_one(&mut self, out: &mut [u8]) -> Result<RecvStep> {
        // Split `self` into disjoint field borrows so the decoder (`dec` +
        // `recvbuf`) and the collector closure (`pending`, `recvframe`, `out`)
        // can be borrowed simultaneously without conflict.
        let Websocket {
            dec,
            recvbuf,
            pending,
            recvframe,
            no_auto_pong,
            ..
        } = self;
        let no_auto_pong = *no_auto_pong;
        let out_cap = out.len();

        let mut bufidx = 0usize;
        let mut written = false;
        let mut f_age = 0i32;
        let mut f_flags = 0u32;
        let mut f_off = 0i64;
        let mut f_len = 0i64;

        let pass_result = dec.pass(
            recvbuf,
            |buf, frame_age, frame_flags, payload_offset, payload_len| {
                let remain = ws_payload_remain(payload_len, payload_offset, buf.len());
                if remain < 0 {
                    return Err(arg_err("[WS] payload length parameter mismatch"));
                }

                if bufidx == 0 {
                    // First write of this frame — capture the frame metadata.
                    f_age = frame_age;
                    f_flags = frame_flags;
                    f_off = payload_offset;
                    f_len = payload_len;
                }

                if !no_auto_pong && (frame_flags & CURLWS_PING != 0) && remain == 0 {
                    // Auto-respond to a fully-received PING: queue a PONG echoing
                    // the exact payload. Encoded/flushed by the driver afterwards
                    // (curl encodes it inline; deferring is observably identical
                    // and avoids a decoder/encoder borrow conflict). Not delivered.
                    let plen = buf.len().min(WS_MAX_CNTRL_LEN);
                    pending.frame_type = CURLWS_PONG;
                    pending.payload_len = plen;
                    pending.payload[..plen].copy_from_slice(&buf[..plen]);
                    Ok(buf.len())
                } else {
                    written = true;
                    let write_len = buf.len().min(out_cap - bufidx);
                    if write_len == 0 {
                        if buf.is_empty() {
                            // 0-length frame: accepted, delivered as an empty chunk.
                            return Ok(0);
                        }
                        // No space left in the caller's buffer — resume later.
                        return Err(again_err());
                    }
                    out[bufidx..bufidx + write_len].copy_from_slice(&buf[..write_len]);
                    bufidx += write_len;
                    Ok(write_len)
                }
            },
        );

        match pass_result {
            Ok(()) => {
                if written {
                    update_meta(recvframe, f_age, f_flags, f_off, f_len, bufidx);
                    Ok(RecvStep::Delivered(bufidx))
                } else {
                    // A PING was auto-ponged (nothing to hand back) — try again.
                    Ok(RecvStep::NeedMore)
                }
            }
            Err(e) if e.code() == CurlCode::Again => {
                if written {
                    // The caller's buffer filled mid-frame; hand back what we have
                    // (the frame resumes on the next call).
                    update_meta(recvframe, f_age, f_flags, f_off, f_len, bufidx);
                    Ok(RecvStep::Delivered(bufidx))
                } else {
                    Ok(RecvStep::NeedMore)
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Encode-and-flush any queued control frame on a best-effort basis (← the
    /// `ws_enc_add_pending` + `ws_flush` tail of `curl_ws_recv`, and the inline
    /// auto-PONG of `ws_client_collect`).
    ///
    /// A would-block during the flush leaves the remainder queued without
    /// failing the receive, exactly as curl casts that `ws_flush` to `void`.
    async fn send_pending_control<T: WsIo>(&mut self, io: &mut T) -> Result<()> {
        if self.raw_mode || self.pending.frame_type == 0 {
            return Ok(());
        }
        match self.enc_add_pending() {
            Ok(()) => {}
            Err(e) if e.code() == CurlCode::Again => return Ok(()),
            Err(e) => return Err(e),
        }
        // Best-effort: curl ignores this flush's result here.
        let _ = self.flush(io).await;
        Ok(())
    }

    /// Receive one WebSocket frame's worth of data into `out` (← curl
    /// `curl_ws_recv`).
    ///
    /// Tops up `recvbuf` from the transport when empty, drives the resumable
    /// decoder, auto-answers PINGs, and returns `(bytes_written, frame_meta)`.
    /// A large frame is delivered across successive calls, each reporting the
    /// running `offset` / `bytesleft` in the returned [`CurlWsFrame`].
    ///
    /// Returns `CURLE_GOT_NOTHING` if the peer closes with the buffer empty.
    pub async fn recv<T: WsIo>(
        &mut self,
        io: &mut T,
        out: &mut [u8],
    ) -> Result<(usize, CurlWsFrame)> {
        loop {
            if self.recvbuf.is_empty() {
                let mut tmp = vec![0u8; WS_CHUNK_SIZE];
                let n = io.ws_recv(&mut tmp).await?;
                if n == 0 {
                    // Connection closed.
                    return Err(Error::with_context(
                        CurlCode::GotNothing,
                        "[WS] connection expectedly closed?",
                    ));
                }
                self.recvbuf.extend_from_slice(&tmp[..n]);
            }

            match self.recv_one(out)? {
                RecvStep::Delivered(n) => {
                    self.send_pending_control(io).await?;
                    return Ok((n, self.recvframe));
                }
                RecvStep::NeedMore => {
                    // Flush any auto-PONG queued during the pass, then retry
                    // (decoding more of `recvbuf`, or slurping when it drains).
                    self.send_pending_control(io).await?;
                }
            }
        }
    }

    // -- Send path (← curl_ws_send / ws_enc_send / ws_send_raw) ------------

    /// Send `buffer` as WebSocket payload with the given `flags`
    /// (← curl `curl_ws_send`).
    ///
    /// In raw mode (`CURLWS_RAW_MODE`) `fragsize` and `flags` must both be zero
    /// and the bytes are written through untouched after flushing any backlog;
    /// otherwise the bytes are framed and masked. Returns the number of *payload*
    /// bytes accepted.
    pub async fn send<T: WsIo>(
        &mut self,
        io: &mut T,
        buffer: &[u8],
        fragsize: i64,
        flags: u32,
    ) -> Result<usize> {
        if self.raw_mode {
            // Flush any content still waiting, then write directly.
            self.flush(io).await?;
            if fragsize != 0 || flags != 0 {
                return Err(arg_err("[WS] fragsize and flags must be zero in raw mode"));
            }
            if buffer.is_empty() {
                return Ok(0);
            }
            return io.ws_send(buffer).await;
        }
        self.enc_send(io, buffer, fragsize, flags).await
    }

    /// The framed-send engine with curl's exact partial-send accounting
    /// (← curl `ws_enc_send`).
    async fn enc_send<T: WsIo>(
        &mut self,
        io: &mut T,
        buffer: &[u8],
        fragsize: i64,
        flags: u32,
    ) -> Result<usize> {
        let mut buffer = buffer;
        let mut pnsent = 0usize;

        if self.enc.payload_remain != 0 || !self.sendbuf.is_empty() {
            // A frame is ongoing with payload buffered, or more payload remains
            // to be encoded into the buffer.
            if buffer.len() < self.sendbuf_payload {
                return Err(arg_err(format!(
                    "[WS] curl_ws_send() called with smaller 'buflen' than bytes already \
                     buffered in previous call, {} vs {}",
                    buffer.len(),
                    self.sendbuf_payload
                )));
            }
            if usize_to_off(buffer.len())
                > self.enc.payload_remain + usize_to_off(self.sendbuf_payload)
            {
                return Err(arg_err(format!(
                    "[WS] unaligned frame size (sending {} instead of {})",
                    buffer.len(),
                    self.enc.payload_remain + usize_to_off(self.sendbuf_payload)
                )));
            }
        } else {
            self.flush(io).await?;
            let plen = if flags & CURLWS_OFFSET != 0 {
                fragsize
            } else {
                usize_to_off(buffer.len())
            };
            self.enc_write_head(flags, plen)?;
        }

        // While there is either sendbuf to flush OR more payload to encode...
        while !self.sendbuf.is_empty() || buffer.len() > self.sendbuf_payload {
            if buffer.len() > self.sendbuf_payload {
                let prev_len = self.sendbuf.len();
                // `buffer` is a local slice (not a field), so borrowing it while
                // mutably borrowing `enc` + `sendbuf` is fine.
                self.enc
                    .write_payload(&buffer[self.sendbuf_payload..], &mut self.sendbuf)?;
                self.sendbuf_payload += self.sendbuf.len() - prev_len;
                if self.sendbuf_payload == 0 {
                    return Err(again_err());
                }
            }

            match self.flush(io).await {
                Ok(()) => {
                    if self.sendbuf_payload > 0 {
                        pnsent += self.sendbuf_payload;
                        buffer = &buffer[self.sendbuf_payload..];
                        self.sendbuf_payload = 0;
                    }
                }
                Err(e) if e.code() == CurlCode::Again => {
                    let remaining = self.sendbuf.len();
                    if self.sendbuf_payload > remaining {
                        // Header (and some payload) flushed — report the payload
                        // bytes that made it out and succeed.
                        let flushed = self.sendbuf_payload - remaining;
                        pnsent += flushed;
                        self.sendbuf_payload -= flushed;
                        return Ok(pnsent);
                    }
                    // Blocked before any payload byte left the buffer.
                    return Err(again_err());
                }
                Err(e) => return Err(e),
            }
        }

        Ok(pnsent)
    }

    // -- Frame start / metadata (← curl_ws_start_frame / curl_ws_meta) ----

    /// Begin an explicit outgoing frame of `frame_len` payload bytes
    /// (← curl `curl_ws_start_frame`), to be followed by `send` calls that
    /// stream the payload. Illegal in raw mode or while a frame is unfinished.
    pub fn start_frame(&mut self, flags: u32, frame_len: i64) -> Result<()> {
        if self.raw_mode {
            return Err(Error::with_context(
                CurlCode::FailedInit,
                "cannot curl_ws_start_frame() with CURLWS_RAW_MODE enabled",
            ));
        }
        if self.enc.payload_remain != 0 {
            return Err(send_err("[WS] previous frame not finished"));
        }
        self.enc_write_head(flags, frame_len)
    }

    /// The metadata of the most recently received frame chunk
    /// (← curl `curl_ws_meta`), or `None` in raw mode.
    #[must_use]
    pub fn meta(&self) -> Option<&CurlWsFrame> {
        if self.raw_mode {
            None
        } else {
            Some(&self.recvframe)
        }
    }
}

/// Outcome of a single [`Websocket::recv_one`] decode step.
enum RecvStep {
    /// A frame chunk of the given byte length was written into the caller buffer.
    Delivered(usize),
    /// Nothing was delivered (auto-ponged PING, or a partial header/payload);
    /// the driver should feed more input and retry.
    NeedMore,
}

// ===========================================================================
// TLS integration for `wss://` and connection pollset contribution.
// ===========================================================================

/// The ALPN protocol list a `wss://` TLS handshake advertises.
///
/// curl's `ws_setup_conn` pins the connection to HTTP/1.1 (`CURL_HTTP_V1x`), so
/// the TLS layer offers exactly [`crate::tls::ALPN_HTTP_1_1`] and nothing else.
/// The TLS handshake itself is performed by the SSL filter inside the connection
/// filter chain (see [`WsIo`]); this list is what that filter is configured with
/// for a WebSocket-over-TLS connection.
#[must_use]
pub fn wss_alpn() -> [&'static [u8]; 1] {
    [tls::ALPN_HTTP_1_1]
}

impl Websocket {
    /// Contribute the sockets this WebSocket transfer wants watched (← the
    /// intent of curl's WS `perform_pollset`, delegated from `Curl_http`).
    ///
    /// A WebSocket is always interested in *readable* (incoming frames may
    /// arrive at any time) and additionally in *writable* whenever there are
    /// buffered outbound bytes still to flush.
    pub fn adjust_pollset(&self, sock: RawFd, ps: &mut Pollset) {
        ps.add_in(sock);
        if !self.sendbuf.is_empty() {
            ps.add_out(sock);
        }
    }
}

// ===========================================================================
// Protocol handler singleton (← `struct Curl_protocol Curl_protocol_ws` and the
// `Curl_scheme_ws` / `Curl_scheme_wss` scheme records in `lib/ws.c`).
// ===========================================================================

/// The WebSocket protocol handler (← curl `Curl_protocol_ws`).
///
/// A zero-sized singleton shared as `&'static dyn Protocol` by both the `ws` and
/// `wss` scheme records ([`crate::protocols::SCHEME_WS`] /
/// [`crate::protocols::SCHEME_WSS`]) — exactly as curl points both
/// `Curl_scheme_ws` and `Curl_scheme_wss` at the same `Curl_protocol_ws` vtable,
/// with the `wss` scheme's `PROTOPT_SSL` flag layering TLS via the filter chain.
///
/// In curl, `Curl_protocol_ws` delegates its request/response phases to the HTTP
/// handler (`do_it = Curl_http`, `write_resp = Curl_http_write_resp`, …) while a
/// dedicated client writer decodes the WebSocket frames out of the response
/// body. The heavy lifting of this port — the RFC 6455 frame codec, the
/// handshake, and the `curl_ws_*` engine — lives on [`Websocket`]; this handler
/// is the thin vtable that the transfer core dispatches through.
pub struct WsHandler;

/// The shared WebSocket handler singleton referenced by the `ws`/`wss` scheme
/// records (`handler: &ws::HANDLER`).
pub static HANDLER: WsHandler = WsHandler;

/// Adapts the transfer's boxed byte transport ([`TransferCtx::io`], a
/// `&mut dyn `[`TransferStream`]) to the [`WsIo`] seam the [`Websocket`] engine
/// drives, so the exact same framing code runs over the production
/// [`FilterChain`] and over an in-memory test pipe alike.
///
/// This mirrors curl, where the WebSocket engine's `nw_in_recv` / `ws_flush`
/// bottom out in `Curl_conn_recv` / `Curl_xfer_send` regardless of whether the
/// underlying connection filter is plaintext TCP or a TLS filter (for `wss`).
struct AsyncIoWs<'a> {
    stream: &'a mut dyn TransferStream,
}

impl WsIo for AsyncIoWs<'_> {
    async fn ws_recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        // `&mut dyn TransferStream` is `AsyncRead + Unpin`, so `read` applies.
        self.stream.read(buf).await.map_err(|e| io_err_to_curl(&e, false))
    }

    async fn ws_send(&mut self, buf: &[u8]) -> Result<usize> {
        // A single `write` may accept fewer bytes than offered; the engine's
        // flush / partial-send accounting already tolerates a short count.
        self.stream.write(buf).await.map_err(|e| io_err_to_curl(&e, true))
    }
}

/// Map a transport [`std::io::Error`] to the curl error the WebSocket engine
/// expects, preserving the `WouldBlock`/`Interrupted` → `CURLE_AGAIN` mapping
/// the non-blocking send/receive loops rely on (← curl's `Curl_xfer_send` /
/// `nw_in_recv` error sites). `dir_send` selects the directional fallback:
/// `CURLE_SEND_ERROR` for the write path, `CURLE_RECV_ERROR` for the read path.
fn io_err_to_curl(e: &std::io::Error, dir_send: bool) -> Error {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::WouldBlock | ErrorKind::Interrupted => again_err(),
        _ if dir_send => send_err(format!("[WS] transport send failed: {e}")),
        _ => recv_err(format!("[WS] transport recv failed: {e}")),
    }
}

/// Ensure the transfer's [`TransferCtx::proto_state`] holds a [`Websocket`]
/// engine, creating and configuring one from the request options if absent
/// (← curl allocating the `struct websocket` in `ws_setup_conn` /
/// `Curl_ws_accept`). Idempotent: a handshake already in progress keeps its
/// existing engine and buffers untouched.
fn ensure_ws_installed(ctx: &mut TransferCtx) {
    let present = matches!(&ctx.proto_state, Some(b) if b.is::<Websocket>());
    if !present {
        let mut ws = Websocket::new();
        let opts = ctx.request.ws_options;
        ws.configure(
            opts & CURLWS_RAW_MODE != 0,
            opts & CURLWS_NOAUTOPONG != 0,
            ctx.request.connect_only,
        );
        ctx.proto_state = Some(Box::new(ws));
    }
}

/// Build the `Host` request-header value: bare `host` when the port is the
/// scheme default (`80` for `ws`, `443` for `wss`) or unset, else `host:port`
/// (← the Host emission of curl's HTTP request builder that WebSocket reuses).
fn ws_host_header(req: &TransferRequest) -> String {
    let default_port: u16 = if req.scheme.eq_ignore_ascii_case("wss") {
        443
    } else {
        80
    };
    if req.port == 0 || req.port == default_port {
        req.host.clone()
    } else {
        format!("{}:{}", req.host, req.port)
    }
}

/// The upper bound on the accumulated handshake-response header block do_it will
/// buffer before giving up (← the bounded read curl performs while parsing the
/// `101` response). Prevents an unbounded read from a hostile or broken server.
const WS_MAX_HANDSHAKE: usize = 128 * 1024;

impl Protocol for WsHandler {
    /// Prepare the connection for a WebSocket transfer (← curl `ws_setup_conn`).
    ///
    /// curl pins the negotiation to HTTP/1.1 (WebSocket runs over an HTTP/1.1
    /// Upgrade) and allocates the per-transfer WebSocket state. The HTTP/1.1 pin
    /// is expressed by [`wss_alpn`] — the `wss` TLS filter offers only
    /// HTTP/1.1 — because this port layers HTTP/TLS through the connection
    /// filter chain rather than carrying a mutable http-version enum in
    /// [`TransferCtx`]; here we perform the state allocation, configuring the
    /// [`Websocket`] engine from the request's `CURLOPT_WS_OPTIONS` bits so it is
    /// ready to mint the handshake in [`do_it`](WsHandler::do_it).
    fn setup_connection<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, ()> {
        ensure_ws_installed(ctx);
        Box::pin(async { Ok(()) })
    }

    /// The DO phase (← curl's `do_it = Curl_http`): drive the HTTP/1.1 Upgrade
    /// request, then hand the connection over to WebSocket framing.
    ///
    /// Issues the upgrade request built by [`Websocket::build_upgrade_request`],
    /// then reads and validates the `101` response via [`Websocket::accept`]
    /// (status `101` + `Sec-WebSocket-Accept`). For `CURLOPT_CONNECT_ONLY == 2`
    /// the application drives `curl_ws_send`/`curl_ws_recv` afterwards; otherwise
    /// the transfer's PERFORM phase feeds received body bytes to
    /// [`write_resp`](WsHandler::write_resp), which decodes frames into the
    /// client sink. Either way the DO phase itself is finished, so this returns
    /// `true` (as curl's HTTP `do_it` does once the upgrade response is in).
    fn do_it<'a>(&'a self, ctx: &'a mut TransferCtx) -> ProtoFuture<'a, bool> {
        Box::pin(async move {
            // The engine is normally installed by setup_connection; create it
            // here too so do_it is self-sufficient (e.g. when tested directly).
            ensure_ws_installed(ctx);

            // Build the Upgrade request. `path`/`host`/`extra` immutably borrow
            // `ctx.request` while the engine mutably borrows `ctx.proto_state`
            // (disjoint fields), and the engine mints a fresh `Sec-WebSocket-Key`.
            let request_bytes = {
                let path = if ctx.request.path.is_empty() {
                    "/"
                } else {
                    ctx.request.path.as_str()
                };
                let host_hdr = ws_host_header(&ctx.request);
                let extra: Vec<&str> =
                    ctx.request.headers.iter().map(String::as_str).collect();
                let engine = match ctx
                    .proto_state
                    .as_mut()
                    .and_then(|b| b.downcast_mut::<Websocket>())
                {
                    Some(ws) => ws,
                    None => {
                        return Err(Error::with_context(
                            CurlCode::FailedInit,
                            "[WS] WebSocket engine state missing",
                        ))
                    }
                };
                engine.build_upgrade_request(path, &host_hdr, &extra)
            };

            // Send the whole handshake request (tolerating short writes). Scoped
            // so the transport borrow ends before the accept loop reborrows it.
            {
                let stream = ctx.io.as_deref_mut().ok_or_else(|| {
                    Error::with_context(
                        CurlCode::CouldntConnect,
                        "[WS] no transport for handshake",
                    )
                })?;
                let mut io = AsyncIoWs { stream };
                let mut off = 0usize;
                while off < request_bytes.len() {
                    let n = io.ws_send(&request_bytes[off..]).await?;
                    if n == 0 {
                        return Err(send_err(
                            "[WS] connection closed during handshake send",
                        ));
                    }
                    off += n;
                }
            }

            // Read the server handshake until complete, then validate `101` +
            // `Sec-WebSocket-Accept`. `accept` does not touch engine state until
            // the header block parses, so repeated calls on a growing buffer are
            // safe; on success it buffers any trailing body bytes for `recv`.
            let mut resp = BytesMut::new();
            let mut tmp = vec![0u8; WS_CHUNK_SIZE];
            loop {
                let accept_res = match ctx
                    .proto_state
                    .as_mut()
                    .and_then(|b| b.downcast_mut::<Websocket>())
                {
                    Some(ws) => ws.accept(&resp),
                    None => {
                        return Err(Error::with_context(
                            CurlCode::FailedInit,
                            "[WS] WebSocket engine state missing",
                        ))
                    }
                };
                match accept_res {
                    Ok(_leftover) => break,
                    Err(e) if e.code() == CurlCode::Again => {
                        if resp.len() >= WS_MAX_HANDSHAKE {
                            return Err(recv_err_weird(
                                "[WS] server handshake response exceeded the size limit",
                            ));
                        }
                        let n = {
                            let stream = ctx.io.as_deref_mut().ok_or_else(|| {
                                Error::with_context(
                                    CurlCode::CouldntConnect,
                                    "[WS] no transport for handshake",
                                )
                            })?;
                            let mut io = AsyncIoWs { stream };
                            io.ws_recv(&mut tmp).await?
                        };
                        if n == 0 {
                            return Err(Error::with_context(
                                CurlCode::GotNothing,
                                "[WS] connection closed during handshake",
                            ));
                        }
                        resp.extend_from_slice(&tmp[..n]);
                    }
                    Err(e) => return Err(e),
                }
            }

            Ok(true)
        })
    }

    /// Feed a chunk of response *body* bytes into the WebSocket decoder
    /// (← the `ws_cw_decode` client writer curl installs in `Curl_ws_accept`).
    ///
    /// Appends `buf` to the per-connection [`Websocket`] engine's receive buffer
    /// and decodes every complete frame out of it, delivering each frame's
    /// payload to the client [`sink`](TransferCtx::sink) and flushing any
    /// auto-PONG queued in response to a PING. A partial frame is left buffered
    /// for the next call. `_is_eos` is unused: the WebSocket frame protocol is
    /// self-delimiting, so end-of-stream needs no extra decode step here.
    fn write_resp<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        buf: &'a [u8],
        _is_eos: bool,
    ) -> ProtoFuture<'a, ()> {
        Box::pin(async move {
            // Disjoint field borrows: the engine (`proto_state`), the transport
            // (`io`, for flushing auto-PONGs), and the client sink.
            let engine = match ctx
                .proto_state
                .as_mut()
                .and_then(|b| b.downcast_mut::<Websocket>())
            {
                Some(ws) => ws,
                None => {
                    return Err(Error::with_context(
                        CurlCode::FailedInit,
                        "[WS] response bytes arrived before the WebSocket handshake",
                    ))
                }
            };
            let mut io = ctx.io.as_deref_mut().map(|stream| AsyncIoWs { stream });
            let mut sink = ctx.sink.as_deref_mut();

            engine.recvbuf.extend_from_slice(buf);
            let mut out = vec![0u8; WS_CHUNK_SIZE];
            loop {
                match engine.recv_one(&mut out)? {
                    RecvStep::Delivered(n) => {
                        if let Some(io) = io.as_mut() {
                            engine.send_pending_control(io).await?;
                        }
                        if let Some(sink) = sink.as_deref_mut() {
                            sink.write(&out[..n])?;
                        }
                    }
                    RecvStep::NeedMore => {
                        if let Some(io) = io.as_mut() {
                            engine.send_pending_control(io).await?;
                        }
                        break;
                    }
                }
            }
            Ok(())
        })
    }

    /// Tear down a WebSocket transfer (← curl `Curl_http_done` path).
    ///
    /// A cleanly-finished (`status` ok, not `premature`), non-raw, non-`CONNECT_
    /// ONLY` transfer that still has a live transport is closed gracefully with
    /// a CLOSE control frame before its state is released; an aborted or dead
    /// connection skips the close chatter, and a `CONNECT_ONLY` WebSocket is
    /// left for the application to close. The CLOSE is best-effort — a failed
    /// close never overrides the transfer's outcome — after which the per-
    /// transfer engine state is dropped (← freeing `req.p.ws`).
    fn done<'a>(
        &'a self,
        ctx: &'a mut TransferCtx,
        status: Result<()>,
        premature: bool,
    ) -> ProtoFuture<'a, ()> {
        Box::pin(async move {
            let graceful = !premature && status.is_ok();
            if graceful {
                let want_close = matches!(
                    ctx.proto_state
                        .as_ref()
                        .and_then(|b| b.downcast_ref::<Websocket>()),
                    Some(ws) if !ws.is_raw_mode() && !ws.connect_only
                );
                if want_close {
                    if let Some(engine) = ctx
                        .proto_state
                        .as_mut()
                        .and_then(|b| b.downcast_mut::<Websocket>())
                    {
                        if let Some(stream) = ctx.io.as_deref_mut() {
                            let mut io = AsyncIoWs { stream };
                            // Empty-payload CLOSE frame; ignore any send error.
                            let _ = engine.send(&mut io, &[], 0, CURLWS_CLOSE).await;
                        }
                    }
                }
            }
            // Release the per-transfer WebSocket state.
            ctx.proto_state = None;
            Ok(())
        })
    }

    /// Contribute desired sockets during the transfer (← curl's WS
    /// `perform_pollset`, which delegates to `Curl_http_perform_pollset`).
    ///
    /// Delegates the concrete want-read/want-write decision to
    /// [`Websocket::adjust_pollset`] (always readable; writable while outbound
    /// bytes remain buffered), given the installed engine and the transfer's
    /// concrete socket handle [`socket_fd`](TransferCtx::socket_fd).
    fn perform_pollset(&self, ctx: &mut TransferCtx, ps: &mut Pollset) {
        if let (Some(engine), Some(fd)) = (
            ctx.proto_state
                .as_ref()
                .and_then(|b| b.downcast_ref::<Websocket>()),
            ctx.socket_fd,
        ) {
            engine.adjust_pollset(fd, ps);
        }
    }
}

// ===========================================================================
// Unit tests. These exercise the pure codec + handshake logic directly and the
// async engine over an in-memory transport, with no external daemons.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::TransferSink;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Wake, Waker};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    // -- A minimal, fully safe executor ----------------------------------
    //
    // The engine's async methods only ever await the in-memory `MockTransport`
    // below, whose futures are always immediately ready, so a single poll with a
    // no-op waker suffices. `std::task::Wake` gives us a `Waker` without any
    // escape-hatch code, respecting the crate-wide `#![forbid(...)]` safe-code lint.

    struct NoopWake;
    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    fn block_on<F: Future>(fut: F) -> F::Output {
        let waker: Waker = Arc::new(NoopWake).into();
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(fut);
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    // -- In-memory transport --------------------------------------------

    struct MockTransport {
        to_recv: Vec<u8>,
        pos: usize,
        chunk: usize,
        sent: Vec<u8>,
    }

    impl MockTransport {
        fn new(to_recv: Vec<u8>, chunk: usize) -> Self {
            MockTransport {
                to_recv,
                pos: 0,
                chunk: chunk.max(1),
                sent: Vec::new(),
            }
        }
    }

    impl WsIo for MockTransport {
        async fn ws_recv(&mut self, buf: &mut [u8]) -> Result<usize> {
            let avail = self.to_recv.len() - self.pos;
            let n = avail.min(self.chunk).min(buf.len());
            buf[..n].copy_from_slice(&self.to_recv[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }

        async fn ws_send(&mut self, buf: &[u8]) -> Result<usize> {
            self.sent.extend_from_slice(buf);
            Ok(buf.len())
        }
    }

    /// Decode every frame present in `frame`, collecting payload + last flags.
    fn decode_frame(frame: &[u8]) -> Result<(Vec<u8>, u32)> {
        let mut dec = WsDecoder::new();
        let mut buf = BytesMut::from(frame);
        let mut out = Vec::new();
        let mut flags = 0u32;
        loop {
            let r = dec.pass(&mut buf, |b, _age, f, _off, _len| {
                out.extend_from_slice(b);
                flags = f;
                Ok(b.len())
            });
            match r {
                Ok(()) => {
                    if buf.is_empty() {
                        break;
                    }
                }
                Err(e) if e.code() == CurlCode::Again => break,
                Err(e) => return Err(e),
            }
        }
        Ok((out, flags))
    }

    // -- Constant parity (← include/curl/websockets.h) -------------------

    #[test]
    fn curlws_flag_values_are_frozen() {
        assert_eq!(CURLWS_TEXT, 1 << 0);
        assert_eq!(CURLWS_BINARY, 1 << 1);
        assert_eq!(CURLWS_CONT, 1 << 2);
        assert_eq!(CURLWS_CLOSE, 1 << 3);
        assert_eq!(CURLWS_PING, 1 << 4);
        assert_eq!(CURLWS_OFFSET, 1 << 5);
        assert_eq!(CURLWS_PONG, 1 << 6);
        assert_eq!(CURLWS_RAW_MODE, 1 << 0);
        assert_eq!(CURLWS_NOAUTOPONG, 1 << 1);
    }

    #[test]
    fn frame_bit_constants_are_frozen() {
        assert_eq!(WSBIT_FIN, 0x80);
        assert_eq!(WSBIT_RSV_MASK, 0x70);
        assert_eq!(WSBIT_OPCODE_MASK, 0x0f);
        assert_eq!(WSBIT_MASK, 0x80);
        assert_eq!(WSBIT_OPCODE_CONT, 0x0);
        assert_eq!(WSBIT_OPCODE_TEXT, 0x1);
        assert_eq!(WSBIT_OPCODE_BIN, 0x2);
        assert_eq!(WSBIT_OPCODE_CLOSE, 0x8);
        assert_eq!(WSBIT_OPCODE_PING, 0x9);
        assert_eq!(WSBIT_OPCODE_PONG, 0xa);
    }

    // -- firstbyte <-> flags (← ws_frame_firstbyte2flags/…2firstbyte) ----

    #[test]
    fn firstbyte2flags_data_and_control() {
        // Unfragmented data frames.
        assert_eq!(frame_firstbyte2flags(0x81, 0).unwrap(), CURLWS_TEXT);
        assert_eq!(frame_firstbyte2flags(0x82, 0).unwrap(), CURLWS_BINARY);
        // First fragment of a message: adds CONT.
        assert_eq!(
            frame_firstbyte2flags(0x01, 0).unwrap(),
            CURLWS_TEXT | CURLWS_CONT
        );
        assert_eq!(
            frame_firstbyte2flags(0x02, 0).unwrap(),
            CURLWS_BINARY | CURLWS_CONT
        );
        // Control frames.
        assert_eq!(frame_firstbyte2flags(0x88, 0).unwrap(), CURLWS_CLOSE);
        assert_eq!(frame_firstbyte2flags(0x89, 0).unwrap(), CURLWS_PING);
        assert_eq!(frame_firstbyte2flags(0x8a, 0).unwrap(), CURLWS_PONG);
    }

    #[test]
    fn firstbyte2flags_continuation() {
        // Intermediate continuation requires an ongoing message.
        let cont = CURLWS_TEXT | CURLWS_CONT;
        assert_eq!(
            frame_firstbyte2flags(0x00, cont).unwrap(),
            CURLWS_TEXT | CURLWS_CONT
        );
        // Final continuation drops CONT.
        assert_eq!(frame_firstbyte2flags(0x80, cont).unwrap(), CURLWS_TEXT);
        // Continuation with no ongoing message is an error.
        assert_eq!(
            frame_firstbyte2flags(0x00, 0).unwrap_err().code(),
            CurlCode::RecvError
        );
    }

    #[test]
    fn firstbyte2flags_rejects_bad_bytes() {
        // Reserved bits set.
        assert_eq!(
            frame_firstbyte2flags(0xC1, 0).unwrap_err().code(),
            CurlCode::RecvError
        );
        // Reserved opcode 0x3.
        assert_eq!(
            frame_firstbyte2flags(0x83, 0).unwrap_err().code(),
            CurlCode::RecvError
        );
        // Fragmented control frames are illegal.
        assert!(frame_firstbyte2flags(0x08, 0).is_err()); // CLOSE without FIN
        assert!(frame_firstbyte2flags(0x09, 0).is_err()); // PING without FIN
        assert!(frame_firstbyte2flags(0x0a, 0).is_err()); // PONG without FIN
    }

    #[test]
    fn flags2firstbyte_roundtrip() {
        assert_eq!(
            frame_flags2firstbyte(CURLWS_TEXT, false).unwrap(),
            WSBIT_OPCODE_TEXT | WSBIT_FIN
        );
        assert_eq!(
            frame_flags2firstbyte(CURLWS_BINARY, false).unwrap(),
            WSBIT_OPCODE_BIN | WSBIT_FIN
        );
        assert_eq!(
            frame_flags2firstbyte(CURLWS_TEXT | CURLWS_CONT, false).unwrap(),
            WSBIT_OPCODE_TEXT
        );
        // A continuation fragment emits the CONT opcode.
        assert_eq!(
            frame_flags2firstbyte(CURLWS_TEXT | CURLWS_CONT, true).unwrap(),
            WSBIT_OPCODE_CONT
        );
        assert_eq!(
            frame_flags2firstbyte(CURLWS_CLOSE, false).unwrap(),
            WSBIT_OPCODE_CLOSE | WSBIT_FIN
        );
        // Fragmented control frames are rejected.
        assert_eq!(
            frame_flags2firstbyte(CURLWS_CLOSE | CURLWS_CONT, false)
                .unwrap_err()
                .code(),
            CurlCode::BadFunctionArgument
        );
        // No flags without an open fragment is an error.
        assert_eq!(
            frame_flags2firstbyte(0, false).unwrap_err().code(),
            CurlCode::BadFunctionArgument
        );
    }

    // -- Accept-key (RFC 6455 §1.3 worked example) -----------------------

    #[test]
    fn sec_websocket_accept_matches_rfc_example() {
        let accept = Websocket::sec_websocket_accept("dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn sec_websocket_key_is_base64_of_16_bytes() {
        let key = Websocket::sec_websocket_key();
        let decoded = BASE64_STANDARD.decode(key.as_bytes()).unwrap();
        assert_eq!(decoded.len(), 16);
    }

    // -- Handshake request + accept validation ---------------------------

    #[test]
    fn request_headers_contain_mandatory_fields() {
        let mut ws = Websocket::new();
        let bytes = ws.ws_request_headers(&[]);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("Upgrade: websocket\r\n"));
        assert!(text.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(text.contains("Sec-WebSocket-Key: "));
        // A caller-supplied header is not duplicated.
        let mut ws2 = Websocket::new();
        let bytes2 = ws2.ws_request_headers(&["upgrade"]);
        let text2 = String::from_utf8(bytes2).unwrap();
        assert!(!text2.contains("Upgrade: websocket"));
    }

    #[test]
    fn accept_validates_101_and_accept_key() {
        let mut ws = Websocket::new();
        let _ = ws.ws_request_headers(&[]);
        let accept = Websocket::sec_websocket_accept(&ws.sec_key);
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\nLEFTOVER"
        );
        let leftover = ws.accept(response.as_bytes()).unwrap();
        assert_eq!(leftover, b"LEFTOVER".len());
        assert_eq!(&ws.recvbuf[..], b"LEFTOVER");
    }

    #[test]
    fn accept_rejects_bad_accept_key() {
        let mut ws = Websocket::new();
        let _ = ws.ws_request_headers(&[]);
        let response = "HTTP/1.1 101 Switching Protocols\r\n\
                        Sec-WebSocket-Accept: totally-wrong\r\n\r\n";
        assert_eq!(
            ws.accept(response.as_bytes()).unwrap_err().code(),
            CurlCode::WeirdServerReply
        );
    }

    #[test]
    fn accept_rejects_missing_accept_key_and_non_101() {
        let mut ws = Websocket::new();
        let _ = ws.ws_request_headers(&[]);
        let missing = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";
        assert_eq!(
            ws.accept(missing.as_bytes()).unwrap_err().code(),
            CurlCode::WeirdServerReply
        );

        let mut ws2 = Websocket::new();
        let _ = ws2.ws_request_headers(&[]);
        let non101 = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            ws2.accept(non101.as_bytes()).unwrap_err().code(),
            CurlCode::HttpReturnedError
        );
    }

    // -- Decode (server -> client, unmasked) -----------------------------

    #[test]
    fn decode_unmasked_text_frame() {
        // 0x81 = TEXT|FIN, 0x05 = len 5 (mask bit clear), payload "hello".
        let frame = [0x81, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let (payload, flags) = decode_frame(&frame).unwrap();
        assert_eq!(payload, b"hello");
        assert_eq!(flags, CURLWS_TEXT);
    }

    #[test]
    fn decode_rejects_masked_input() {
        // Server frames must be unmasked; the mask bit (0x80) in byte 1 is fatal.
        let frame = [0x81, 0x85, 0, 0, 0, 0, b'h'];
        assert_eq!(
            decode_frame(&frame).unwrap_err().code(),
            CurlCode::RecvError
        );
    }

    #[test]
    fn decode_extended_lengths() {
        // 16-bit length: 0x82 (BIN|FIN), 126, 0x01 0x00 => 256.
        let mut dec = WsDecoder::new();
        let mut buf = BytesMut::from(&[0x82u8, 126, 0x01, 0x00][..]);
        dec.read_head(&mut buf).unwrap();
        assert_eq!(dec.payload_len, 256);

        // 64-bit length: 0x82, 127, then 8 big-endian bytes => 256.
        let mut dec2 = WsDecoder::new();
        let mut buf2 = BytesMut::from(&[0x82u8, 127, 0, 0, 0, 0, 0, 0, 0x01, 0x00][..]);
        dec2.read_head(&mut buf2).unwrap();
        assert_eq!(dec2.payload_len, 256);

        // 64-bit with the top bit set is rejected (> 63-bit lengths unsupported).
        let mut dec3 = WsDecoder::new();
        let mut buf3 = BytesMut::from(&[0x82u8, 127, 0x80, 0, 0, 0, 0, 0, 0, 0][..]);
        assert_eq!(
            dec3.read_head(&mut buf3).unwrap_err().code(),
            CurlCode::RecvError
        );
    }

    #[test]
    fn decode_rejects_overlong_control_frame() {
        // A PING whose length byte is 126 exceeds the 125-byte control limit.
        let mut dec = WsDecoder::new();
        let mut buf = BytesMut::from(&[0x89u8, 126][..]);
        assert_eq!(
            dec.read_head(&mut buf).unwrap_err().code(),
            CurlCode::RecvError
        );
    }

    // -- Encode (client -> server, masked) -------------------------------

    #[test]
    fn encode_masks_client_frame() {
        let mut enc = WsEncoder::new();
        let mut out = BytesMut::new();
        enc.add_frame(CURLWS_TEXT, 5, &mut out).unwrap();
        let mask = enc.mask;
        let n = enc.write_payload(b"hello", &mut out).unwrap();
        assert_eq!(n, 5);

        assert_eq!(out[0], WSBIT_OPCODE_TEXT | WSBIT_FIN); // 0x81
        assert_eq!(out[1], 5 | WSBIT_MASK); // len 5, masked
        assert_eq!(&out[2..6], &mask[..]);
        let expected: Vec<u8> = b"hello"
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ mask[i % 4])
            .collect();
        assert_eq!(&out[6..11], &expected[..]);
        assert_eq!(enc.payload_remain, 0);
    }

    #[test]
    fn encode_rejects_oversized_control_frame() {
        let mut enc = WsEncoder::new();
        let mut out = BytesMut::new();
        assert_eq!(
            enc.add_frame(CURLWS_PING, 126, &mut out)
                .unwrap_err()
                .code(),
            CurlCode::TooLarge
        );
    }

    // -- Resumable / partial decode via the async engine -----------------

    #[test]
    fn recv_reassembles_frame_split_across_reads() {
        // Server TEXT "hello", but the transport yields only 3 bytes per read,
        // so the frame header and payload straddle several socket reads.
        //
        // Matching curl's `curl_ws_recv` loop, each read that produces payload
        // is handed back immediately (collector `written` + `CURLE_AGAIN` =>
        // break) with the running `offset`/`bytesleft`, so a caller reassembles
        // the frame across successive calls until `bytesleft == 0`. This is the
        // resumable cross-read decode property `ws_dec_state` exists for.
        let frame = vec![0x81, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let mut mock = MockTransport::new(frame, 3);
        let mut ws = Websocket::new();
        let mut out = [0u8; 32];

        let mut acc = Vec::new();
        let mut last_offset = -1i64;
        loop {
            let (n, meta) = block_on(ws.recv(&mut mock, &mut out)).unwrap();
            assert_eq!(meta.flags, CURLWS_TEXT);
            // `len` is the bytes delivered THIS call (curl's `cur_len`); `offset`
            // is where this chunk began; the three always sum to the total.
            assert_eq!(meta.len, n);
            assert_eq!(meta.offset, i64::try_from(acc.len()).unwrap());
            assert_eq!(meta.offset + i64::try_from(n).unwrap() + meta.bytesleft, 5);
            assert!(meta.offset > last_offset); // strictly progressing
            last_offset = meta.offset;
            acc.extend_from_slice(&out[..n]);
            if meta.bytesleft == 0 {
                break;
            }
        }
        assert_eq!(acc, b"hello");
    }

    #[test]
    fn recv_delivers_large_frame_across_calls() {
        // A single TEXT frame larger than the caller's buffer is delivered in
        // successive calls with a running offset / bytesleft.
        let frame = vec![0x81, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let mut mock = MockTransport::new(frame, 64);
        let mut ws = Websocket::new();

        let mut out = [0u8; 3];
        let (n1, m1) = block_on(ws.recv(&mut mock, &mut out)).unwrap();
        assert_eq!(&out[..n1], b"hel");
        assert_eq!(m1.offset, 0);
        assert_eq!(m1.len, 3);
        assert_eq!(m1.bytesleft, 2);

        let (n2, m2) = block_on(ws.recv(&mut mock, &mut out)).unwrap();
        assert_eq!(&out[..n2], b"lo");
        assert_eq!(m2.offset, 3);
        assert_eq!(m2.len, 2);
        assert_eq!(m2.bytesleft, 0);
    }

    // -- Control frames --------------------------------------------------

    #[test]
    fn recv_auto_ponds_ping_then_delivers_next_frame() {
        // Server sends PING "hi" (unmasked) then TEXT "ok" (unmasked).
        let mut frame = vec![0x89, 0x02, b'h', b'i']; // PING|FIN, len 2
        frame.extend_from_slice(&[0x81, 0x02, b'o', b'k']); // TEXT|FIN, len 2
        let mut mock = MockTransport::new(frame, 64);
        let mut ws = Websocket::new();
        let mut out = [0u8; 16];

        let (n, meta) = block_on(ws.recv(&mut mock, &mut out)).unwrap();
        // The PING is not delivered; the following TEXT is.
        assert_eq!(&out[..n], b"ok");
        assert_eq!(meta.flags, CURLWS_TEXT);

        // A masked PONG echoing "hi" was transmitted.
        assert!(mock.sent.len() >= 8);
        assert_eq!(mock.sent[0], WSBIT_OPCODE_PONG | WSBIT_FIN); // 0x8a
        assert_eq!(mock.sent[1], 2 | WSBIT_MASK); // len 2, masked
        let mask = [mock.sent[2], mock.sent[3], mock.sent[4], mock.sent[5]];
        let unmasked: Vec<u8> = mock.sent[6..8]
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ mask[i % 4])
            .collect();
        assert_eq!(&unmasked, b"hi");
    }

    #[test]
    fn recv_delivers_close_frame() {
        // Empty CLOSE frame (unmasked).
        let frame = vec![0x88, 0x00];
        let mut mock = MockTransport::new(frame, 64);
        let mut ws = Websocket::new();
        let mut out = [0u8; 16];
        let (n, meta) = block_on(ws.recv(&mut mock, &mut out)).unwrap();
        assert_eq!(n, 0);
        assert_eq!(meta.flags, CURLWS_CLOSE);
    }

    #[test]
    fn recv_reports_got_nothing_on_close() {
        let mut mock = MockTransport::new(Vec::new(), 64);
        let mut ws = Websocket::new();
        let mut out = [0u8; 16];
        assert_eq!(
            block_on(ws.recv(&mut mock, &mut out)).unwrap_err().code(),
            CurlCode::GotNothing
        );
    }

    // -- Send path -------------------------------------------------------

    #[test]
    fn send_frames_and_masks_text() {
        let mut mock = MockTransport::new(Vec::new(), 64);
        let mut ws = Websocket::new();
        let n = block_on(ws.send(&mut mock, b"hello", 0, CURLWS_TEXT)).unwrap();
        assert_eq!(n, 5);

        assert_eq!(mock.sent[0], WSBIT_OPCODE_TEXT | WSBIT_FIN);
        assert_eq!(mock.sent[1], 5 | WSBIT_MASK);
        let mask = [mock.sent[2], mock.sent[3], mock.sent[4], mock.sent[5]];
        let unmasked: Vec<u8> = mock.sent[6..11]
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ mask[i % 4])
            .collect();
        assert_eq!(&unmasked, b"hello");
    }

    #[test]
    fn raw_mode_rejects_nonzero_flags() {
        let mut mock = MockTransport::new(Vec::new(), 64);
        let mut ws = Websocket::new();
        ws.configure(true, false, true);
        assert!(ws.is_raw_mode());
        assert_eq!(
            block_on(ws.send(&mut mock, b"x", 0, CURLWS_TEXT))
                .unwrap_err()
                .code(),
            CurlCode::BadFunctionArgument
        );
    }

    #[test]
    fn raw_mode_writes_through_unframed() {
        let mut mock = MockTransport::new(Vec::new(), 64);
        let mut ws = Websocket::new();
        ws.configure(true, false, true);
        let n = block_on(ws.send(&mut mock, b"raw", 0, 0)).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&mock.sent, b"raw");
    }

    // -- Handler / scheme surface ---------------------------------------

    #[test]
    fn handler_is_object_safe() {
        // Coercing the singleton to a trait object confirms `WsHandler`
        // implements `Protocol` and that the vtable is well-formed.
        let h: &dyn Protocol = &HANDLER;
        let _ = h;
    }

    #[test]
    fn wss_alpn_is_http_1_1_only() {
        assert_eq!(wss_alpn(), [b"http/1.1".as_slice()]);
    }

    // -- Handler lifecycle over an in-memory transport ------------------
    //
    // These exercise the `WsHandler` `Protocol` vtable — the DO-phase
    // handshake, the PERFORM-phase frame decode, and the DONE-phase graceful
    // CLOSE — end to end, with no external daemons.

    /// A client body sink that captures every delivered chunk for assertion.
    struct VecSink(Arc<Mutex<Vec<u8>>>);
    impl TransferSink for VecSink {
        fn write(&mut self, data: &[u8]) -> Result<()> {
            self.0.lock().expect("sink lock").extend_from_slice(data);
            Ok(())
        }
    }

    /// An in-memory [`TransferStream`]: `poll_read` hands back preloaded server
    /// bytes (0 bytes = EOF) and `poll_write` captures everything the handler
    /// sends into a shared buffer. Every op is immediately ready, so it drives
    /// under the crate's tiny [`block_on`] executor without a Tokio runtime.
    struct MockStream {
        to_recv: Vec<u8>,
        pos: usize,
        sent: Arc<Mutex<Vec<u8>>>,
    }
    impl MockStream {
        fn new(to_recv: Vec<u8>) -> (Self, Arc<Mutex<Vec<u8>>>) {
            let sent = Arc::new(Mutex::new(Vec::new()));
            (
                MockStream {
                    to_recv,
                    pos: 0,
                    sent: Arc::clone(&sent),
                },
                sent,
            )
        }
    }
    impl AsyncRead for MockStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            let n = (this.to_recv.len() - this.pos).min(buf.remaining());
            if n > 0 {
                buf.put_slice(&this.to_recv[this.pos..this.pos + n]);
                this.pos += n;
            }
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncWrite for MockStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.get_mut()
                .sent
                .lock()
                .expect("sent lock")
                .extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Build a [`Websocket`] already in the post-handshake ("accepted") state for
    /// a known key, so `write_resp`/`done` can be exercised without running the
    /// (random-key) DO handshake first.
    fn accepted_engine(sec_key: &str) -> Websocket {
        let mut ws = Websocket::new();
        ws.sec_key = sec_key.to_string();
        let accept = Websocket::sec_websocket_accept(sec_key);
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        ws.accept(resp.as_bytes()).expect("engine reaches accepted state");
        ws
    }

    /// Full happy path over a live `tokio::io::duplex` pipe with a concurrent
    /// server that computes the correct `Sec-WebSocket-Accept` from the client's
    /// *random* key: DO handshake, PERFORM decode into the sink, DONE CLOSE.
    #[tokio::test]
    async fn handler_performs_handshake_decodes_and_closes_over_a_live_pipe() {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);

        let server = tokio::spawn(async move {
            // Read the client's Upgrade request up to the header terminator.
            let mut req = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                let n = server_io.read(&mut buf).await.expect("server read req");
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            // Echo back the RFC 6455 accept token for the offered key.
            let text = String::from_utf8_lossy(&req);
            let key = text
                .lines()
                .find_map(|l| {
                    l.split_once(':').and_then(|(n, v)| {
                        n.trim()
                            .eq_ignore_ascii_case("Sec-WebSocket-Key")
                            .then(|| v.trim().to_string())
                    })
                })
                .expect("client offered a Sec-WebSocket-Key");
            let accept = Websocket::sec_websocket_accept(&key);
            // 101 response immediately followed by an unmasked server TEXT frame
            // ("hi"), written together so the client buffers the frame while
            // completing the handshake.
            let mut resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            .into_bytes();
            resp.extend_from_slice(&[0x81, 0x02, b'h', b'i']);
            server_io.write_all(&resp).await.expect("server write 101+frame");
            server_io.flush().await.expect("server flush");
            // Observe the client's CLOSE frame from DONE.
            let mut close = Vec::new();
            if let Ok(n) = server_io.read(&mut buf).await {
                close.extend_from_slice(&buf[..n]);
            }
            close
        });

        let mut ctx = TransferCtx::new();
        ctx.io = Some(Box::new(client_io));
        ctx.request.scheme = "ws".to_string();
        ctx.request.host = "example.test".to_string();
        ctx.request.port = 80;
        ctx.request.path = "/chat".to_string();
        let sink_data = Arc::new(Mutex::new(Vec::new()));
        ctx.sink = Some(Box::new(VecSink(Arc::clone(&sink_data))));

        HANDLER.setup_connection(&mut ctx).await.expect("setup_connection ok");
        let done = HANDLER.do_it(&mut ctx).await.expect("do_it handshake ok");
        assert!(done, "WS do_it reports the DO phase complete after the 101");

        // The transfer driver feeds received body bytes to write_resp; the
        // server frame was buffered by `accept`, so an empty feed decodes it.
        HANDLER
            .write_resp(&mut ctx, &[], false)
            .await
            .expect("write_resp decodes the buffered frame");
        assert_eq!(
            sink_data.lock().expect("sink").as_slice(),
            b"hi",
            "the server TEXT frame is decoded into the client sink"
        );

        HANDLER.done(&mut ctx, Ok(()), false).await.expect("done ok");
        assert!(
            ctx.proto_state.is_none(),
            "done releases the per-transfer WebSocket engine state"
        );

        let close = server.await.expect("server task joins");
        assert!(!close.is_empty(), "server observed a client CLOSE frame");
        assert_eq!(
            close[0], 0x88,
            "the CLOSE frame carries the FIN + CLOSE opcode (0x88)"
        );
        assert_ne!(close[1] & 0x80, 0, "the client CLOSE frame is masked");
    }

    /// do_it maps a non-`101` handshake response to `CURLE_HTTP_RETURNED_ERROR`.
    #[test]
    fn handler_do_it_rejects_non_101() {
        let (io, _sent) = MockStream::new(
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".to_vec(),
        );
        let mut ctx = TransferCtx::new();
        ctx.io = Some(Box::new(io));
        ctx.request.host = "h".to_string();
        let err = block_on(HANDLER.do_it(&mut ctx)).expect_err("non-101 must fail");
        assert_eq!(err.code(), CurlCode::HttpReturnedError);
    }

    /// do_it rejects a `101` whose `Sec-WebSocket-Accept` does not match the key.
    #[test]
    fn handler_do_it_rejects_bad_accept_key() {
        let (io, _sent) = MockStream::new(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
              Sec-WebSocket-Accept: wrong-value\r\n\r\n"
                .to_vec(),
        );
        let mut ctx = TransferCtx::new();
        ctx.io = Some(Box::new(io));
        ctx.request.host = "h".to_string();
        let err = block_on(HANDLER.do_it(&mut ctx)).expect_err("bad accept must fail");
        assert_eq!(err.code(), CurlCode::WeirdServerReply);
    }

    /// write_resp before the handshake (no engine installed) is a hard error,
    /// never a silent no-op.
    #[test]
    fn handler_write_resp_without_handshake_errors() {
        let mut ctx = TransferCtx::new();
        let err = block_on(HANDLER.write_resp(&mut ctx, b"\x81\x01A", false))
            .expect_err("body before handshake must fail");
        assert_eq!(err.code(), CurlCode::FailedInit);
    }

    /// write_resp feeds body bytes into the decoder and delivers the decoded
    /// frame payload to the client sink.
    #[test]
    fn handler_write_resp_decodes_frame_into_sink() {
        let mut ctx = TransferCtx::new();
        ctx.proto_state = Some(Box::new(accepted_engine("dGhlIHNhbXBsZSBub25jZQ==")));
        let (io, _sent) = MockStream::new(Vec::new());
        ctx.io = Some(Box::new(io));
        let sink_data = Arc::new(Mutex::new(Vec::new()));
        ctx.sink = Some(Box::new(VecSink(Arc::clone(&sink_data))));

        // An unmasked server TEXT frame carrying "ok".
        block_on(HANDLER.write_resp(&mut ctx, &[0x81, 0x02, b'o', b'k'], false))
            .expect("decode ok");
        assert_eq!(sink_data.lock().expect("sink").as_slice(), b"ok");
    }

    /// done gracefully sends a masked, empty CLOSE frame and releases the engine
    /// state for a cleanly-finished transfer.
    #[test]
    fn handler_done_sends_close_and_releases_state() {
        let mut ctx = TransferCtx::new();
        ctx.proto_state = Some(Box::new(accepted_engine("dGhlIHNhbXBsZSBub25jZQ==")));
        let (io, sent) = MockStream::new(Vec::new());
        ctx.io = Some(Box::new(io));

        block_on(HANDLER.done(&mut ctx, Ok(()), false)).expect("done ok");
        let sent = sent.lock().expect("sent");
        assert_eq!(sent.len(), 6, "empty CLOSE = 2 header + 4 mask bytes");
        assert_eq!(sent[0], 0x88, "FIN + CLOSE opcode");
        assert_eq!(sent[1], 0x80, "MASK bit set, zero payload length");
        assert!(ctx.proto_state.is_none(), "engine state released");
    }

    /// done on an aborted (`premature`) transfer skips the CLOSE chatter but
    /// still releases the engine state.
    #[test]
    fn handler_done_skips_close_when_premature() {
        let mut ctx = TransferCtx::new();
        ctx.proto_state = Some(Box::new(accepted_engine("dGhlIHNhbXBsZSBub25jZQ==")));
        let (io, sent) = MockStream::new(Vec::new());
        ctx.io = Some(Box::new(io));

        block_on(HANDLER.done(&mut ctx, Ok(()), true)).expect("done ok");
        assert!(
            sent.lock().expect("sent").is_empty(),
            "no CLOSE frame is sent on a premature teardown"
        );
        assert!(ctx.proto_state.is_none(), "engine state still released");
    }

    /// The bounded encoder never materialises more than one `WS_CHUNK_SIZE`
    /// chunk of payload per `write_payload` call, masking straight into `out`
    /// (← finding: the old path buffered the whole frame via a throwaway `Vec`).
    #[test]
    fn encode_write_payload_is_bounded_to_one_chunk() {
        let mut enc = WsEncoder::new();
        let big = vec![0xAAu8; WS_CHUNK_SIZE + 100];
        let mut out = BytesMut::new();
        enc.add_frame(CURLWS_BINARY, (WS_CHUNK_SIZE + 100) as i64, &mut out)
            .expect("add_frame ok");
        let head_len = out.len();
        let mask0 = enc.mask[0];

        let n1 = enc.write_payload(&big, &mut out).expect("chunk 1");
        assert_eq!(n1, WS_CHUNK_SIZE, "a single call is capped at one chunk");
        assert_eq!(
            out.len(),
            head_len + WS_CHUNK_SIZE,
            "out grows by exactly one chunk, not the whole payload"
        );
        assert_eq!(out[head_len], 0xAA ^ mask0, "payload is masked into out");

        let n2 = enc.write_payload(&big[n1..], &mut out).expect("chunk 2");
        assert_eq!(n2, 100, "the remainder is consumed on the next call");
        assert_eq!(out.len(), head_len + WS_CHUNK_SIZE + 100);
    }
}
