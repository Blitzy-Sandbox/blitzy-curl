//! WebSocket (`ws` / `wss`) protocol engine — the Rust analog of curl's
//! `lib/ws.c` (+ `lib/ws.h`).
//!
//! This module implements the RFC 6455 WebSocket client engine that backs the
//! public `curl_ws_*` C API (`curl_ws_recv`, `curl_ws_send`,
//! `curl_ws_start_frame`, `curl_ws_meta`). WebSockets bootstrap over an
//! HTTP/1.1 `Upgrade` handshake, so this module depends on the
//! [`crate::protocols::http`] subtree: the handshake reuses the HTTP/1.1 client
//! rather than re-implementing HTTP parsing, exactly as curl's
//! `Curl_protocol_ws` reuses `Curl_http` for its `do_it`/`done` slots.
//!
//! # Architecture
//!
//! The C source is consumed as a **behavioral oracle**, not transliterated
//! line-by-line. The translation maps curl's constructs onto idiomatic Rust:
//!
//! * curl's `struct ws_decoder` / `struct ws_encoder` become [`WsDecoder`] /
//!   [`WsEncoder`]: small state machines that turn a byte stream into RFC 6455
//!   frames and back. They are **pure** (no I/O), which makes the parity-
//!   critical codec fully unit-testable.
//! * curl's `struct websocket` (the per-connection en/decoder + raw buffers +
//!   the current frame meta) becomes [`WsConnState`], stored on the
//!   [`Connection`]'s protocol-state slot — the Rust analog of curl's
//!   `Curl_conn_meta_set(CURL_META_PROTO_WS_CONN, …)`.
//! * the public `curl_ws_*` entrypoints become **safe** async/sync engine
//!   methods on [`WsConnState`] ([`WsConnState::ws_recv`],
//!   [`WsConnState::ws_send`], [`WsConnState::ws_start_frame`],
//!   [`WsConnState::meta`]). The raw-pointer marshaling for the `extern "C"`
//!   shims lives in `curl-rs-ffi`, **not** here.
//! * curl's `const struct Curl_scheme Curl_scheme_ws/wss` are already modeled by
//!   [`crate::protocols::SCHEME_WS`] / [`crate::protocols::SCHEME_WSS`]; this
//!   module supplies the [`Protocol`] handler ([`WsHandler`]) those schemes
//!   dispatch to.
//!
//! # The accept-hash: SHA-1, implemented inline
//!
//! The WebSocket opening handshake validates the server's
//! `Sec-WebSocket-Accept` header as `base64(SHA-1(key + GUID))` where the GUID
//! is the fixed RFC 6455 magic string. This is **SHA-1**, distinct from the
//! SHA-256 (`crate::util::sha256`) and MD5 (`crate::util::md5`) primitives the
//! rest of the crate uses.
//!
//! A standalone `sha1` crate is **not** added: the workspace's RustCrypto
//! digests are pinned on the `digest 0.10` line (`sha2 0.10`, `md-5 0.10`,
//! `hmac 0.12`), whereas the only `sha1` release resolvable in the locked graph
//! requires the incompatible `digest 0.11` — the exact obstacle already
//! documented in [`crate::auth::scram`], which dropped SCRAM-SHA-1 for the same
//! reason. Adding `sha1` as a direct dependency would also force a `Cargo.lock`
//! change, breaking the committed `--locked` build. Because the WebSocket
//! accept value is a **non-secret, fixed transformation** mandated by the
//! protocol (it is an anti-caching/anti-proxy sanity check, not a security
//! primitive), a small, self-contained, audited SHA-1 ([`sha1`]) is the correct
//! engineering choice. It is validated against the RFC 6455 known-answer vector
//! in the unit tests.
//!
//! # Memory safety
//!
//! This file contains **zero** `unsafe`. The crate root applies
//! `#![forbid(unsafe_code)]`, which this module inherits (it deliberately does
//! **not** re-declare it). All raw-pointer / `va_list` handling for the
//! `curl_ws_*` symbols is confined to `curl-rs-ffi`.

use crate::conn::{BoxFuture, Connection, Curl_conn_recv, Curl_conn_send, FIRSTSOCKET};
use crate::easy::Easy;
use crate::error::{CurlError, Result};
use crate::protocols::http::HttpProtocol;
use crate::protocols::{Protocol, ProtocolTransfer, Scheme};
use crate::util::base64::base64_encode;
use crate::util::rand::rand_bytes;
use crate::util::sendf;

// ===========================================================================
// RFC 6455 frame header bits (oracle: `lib/ws.c` L52-L75).
// ===========================================================================

/// FIN bit — set on the final fragment of a message (`WSBIT_FIN`).
const WSBIT_FIN: u8 = 0x80;
/// Reserved bit 1 (`WSBIT_RSV1`); must be zero without a negotiated extension.
const WSBIT_RSV1: u8 = 0x40;
/// Reserved bit 2 (`WSBIT_RSV2`).
const WSBIT_RSV2: u8 = 0x20;
/// Reserved bit 3 (`WSBIT_RSV3`).
const WSBIT_RSV3: u8 = 0x10;
/// Mask of all three reserved bits (`WSBIT_RSV_MASK`).
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
/// Mask selecting the 4-bit opcode field (`WSBIT_OPCODE_MASK`).
const WSBIT_OPCODE_MASK: u8 = 0x0f;
/// The MASK bit in the second header byte (`WSBIT_MASK`). Client→server frames
/// MUST set it; server→client frames MUST NOT.
const WSBIT_MASK: u8 = 0x80;

/// Maximum payload length of a control frame (RFC 6455 §5.5): 125 bytes
/// (`WS_MAX_CNTRL_LEN`).
const WS_MAX_CNTRL_LEN: usize = 125;

/// The network receive chunk size used when slurping bytes from the connection
/// (curl's `WS_CHUNK_SIZE`).
const WS_CHUNK_SIZE: usize = 65535;

/// The RFC 6455 §1.3 magic GUID appended to the client key before hashing to
/// produce the `Sec-WebSocket-Accept` value.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// ===========================================================================
// Public `CURLWS_*` flags — the PUBLIC ABI (oracle: `include/curl/websockets.h`
// L40-L46, L60). These values are part of the stable libcurl ABI and are
// re-exposed by `curl-rs-ffi`; they MUST match curl 8.x exactly.
// ===========================================================================

/// `CURLWS_TEXT` — a text-data frame/message.
pub const CURLWS_TEXT: u32 = 1 << 0;
/// `CURLWS_BINARY` — a binary-data frame/message.
pub const CURLWS_BINARY: u32 = 1 << 1;
/// `CURLWS_CONT` — this is **not** the final fragment; more will follow (the
/// message continues).
pub const CURLWS_CONT: u32 = 1 << 2;
/// `CURLWS_CLOSE` — a close control frame.
pub const CURLWS_CLOSE: u32 = 1 << 3;
/// `CURLWS_PING` — a ping control frame.
pub const CURLWS_PING: u32 = 1 << 4;
/// `CURLWS_OFFSET` — on send, the call provides a fragment of a larger frame
/// whose total length was given to [`WsConnState::ws_start_frame`]; on the meta
/// it indicates partial-frame delivery.
pub const CURLWS_OFFSET: u32 = 1 << 5;
/// `CURLWS_PONG` — a pong control frame.
pub const CURLWS_PONG: u32 = 1 << 6;

// ---------------------------------------------------------------------------
// Bits for the `CURLOPT_WS_OPTIONS` bitmask (oracle: `include/curl/websockets.h`
// L88-L89). These overlap the `CURLWS_TEXT`/`CURLWS_BINARY` bit positions on
// purpose — they are interpreted in a different context (the option bitmask,
// not a frame's flags), exactly as in curl.
// ---------------------------------------------------------------------------

/// `CURLWS_RAW_MODE` — the application sends/receives raw frame bytes; the
/// engine performs no RFC 6455 framing.
pub const CURLWS_RAW_MODE: u32 = 1 << 0;
/// `CURLWS_NOAUTOPONG` — disable the engine's automatic PONG reply to received
/// PINGs.
pub const CURLWS_NOAUTOPONG: u32 = 1 << 1;

// ===========================================================================
// `WsFrameMeta` — the engine-side mirror of the PUBLIC `struct curl_ws_frame`
// (oracle: `include/curl/websockets.h` L31-L37).
// ===========================================================================

/// Metadata describing the WebSocket frame (or frame fragment) most recently
/// received — the safe-Rust mirror of the public C `struct curl_ws_frame`.
///
/// ```c
/// struct curl_ws_frame {
///   int age;              /* zero */
///   int flags;            /* the CURLWS_* bits */
///   curl_off_t offset;    /* offset of this data into the frame */
///   curl_off_t bytesleft; /* pending bytes left of the payload */
///   size_t len;           /* size of the current data chunk */
/// };
/// ```
///
/// The FFI crate converts this into the `#[repr(C)] curl_ws_frame` it hands back
/// to C callers through `curl_ws_recv` / `curl_ws_meta`; keeping a plain owned
/// Rust struct here (with `i32`/`i64`/`usize` standing in for
/// `int`/`curl_off_t`/`size_t`) lets the safe engine stay free of any `#[repr(C)]`
/// or pointer concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WsFrameMeta {
    /// Always `0` in curl 8.x (reserved; curl's `frame_age`).
    pub age: i32,
    /// The `CURLWS_*` flag bits describing this frame (curl's `frame_flags`).
    pub flags: i32,
    /// The byte offset of this chunk within the overall frame payload (curl's
    /// `recvframe.offset`). Non-zero only when a large frame is delivered
    /// piecewise.
    pub offset: i64,
    /// The number of payload bytes still pending after this chunk (curl's
    /// `recvframe.bytesleft`).
    pub bytesleft: i64,
    /// The size of this chunk of payload data (curl's `recvframe.len`).
    pub len: usize,
}

impl WsFrameMeta {
    /// Update the meta from a decoded chunk, computing `bytesleft` exactly as
    /// curl's `update_meta()` (`lib/ws.c` L573): `payload_len - payload_offset -
    /// cur_len`.
    fn update(
        &mut self,
        frame_age: i32,
        frame_flags: i32,
        payload_offset: i64,
        payload_len: i64,
        cur_len: usize,
    ) {
        self.age = frame_age;
        self.flags = frame_flags;
        self.offset = payload_offset;
        self.len = cur_len;
        self.bytesleft = payload_len - payload_offset - cur_len as i64;
    }
}

// ===========================================================================
// SHA-1 (FIPS 180-1 / RFC 3174) — implemented inline.
//
// See the module-level "The accept-hash" note for why this is hand-rolled
// rather than pulled from a crate. This is a faithful, constant-space
// implementation of the standard algorithm; it produces the canonical SHA-1
// digest (verified against the RFC 6455 known-answer vector in the tests).
// It contains no `unsafe` and performs no allocation beyond the single padded
// message buffer.
// ===========================================================================

/// The five SHA-1 initialization constants (FIPS 180-1 §5).
const SHA1_H: [u32; 5] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];

/// Compute the 20-byte SHA-1 digest of `data`.
///
/// This is the standard Merkle–Damgård construction: the message is padded with
/// a `0x80` byte, zero bytes to a 56 mod 64 boundary, and the 64-bit big-endian
/// bit length, then processed in 64-byte blocks through the four-round
/// compression function.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = SHA1_H;
    let bit_len: u64 = (data.len() as u64).wrapping_mul(8);

    // Build the padded message: data ++ 0x80 ++ 0x00* ++ be64(bit_len).
    let mut msg = Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 80];
    for block in msg.chunks_exact(64) {
        // Load the 16 big-endian words of this block.
        for (word, src) in w.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
        }
        // Extend to 80 words via the message schedule (indices reference earlier
        // entries, so an index loop is the clearest expression here).
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (word, dst) in h.iter().zip(out.chunks_exact_mut(4)) {
        dst.copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Compute the `Sec-WebSocket-Accept` value the server is expected to return for
/// a given client `Sec-WebSocket-Key`.
///
/// Defined by RFC 6455 §4.2.2 as `base64(SHA-1(key + WS_GUID))`. The `key` is
/// the exact (base64) value sent in the client's `Sec-WebSocket-Key` request
/// header.
///
/// This is provided for completeness and conformance testing. It is **not**
/// used to validate the server's response at runtime: curl 8.x performs no such
/// check, and the regression suite depends on that (see [`WsHandler`]). Keeping
/// the function `pub` makes it reachable for the FFI crate and tests.
pub fn sec_websocket_accept(key: &str) -> Result<String> {
    let mut input = String::with_capacity(key.len() + WS_GUID.len());
    input.push_str(key);
    input.push_str(WS_GUID);
    let digest = sha1(input.as_bytes());
    let encoded = base64_encode(&digest)?;
    // Base64 output is always ASCII, so this conversion never fails; map any
    // theoretical error to a clean init failure rather than panicking.
    String::from_utf8(encoded).map_err(|_| CurlError::FailedInit)
}

/// Generate a fresh `Sec-WebSocket-Key`: a base64-encoded 16-byte random nonce
/// (oracle: `Curl_ws_request`, `lib/ws.c` L1276-L1289). RFC 6455 §4.1 requires
/// the nonce to be selected randomly for each connection.
fn generate_sec_websocket_key() -> Result<String> {
    let mut nonce = [0u8; 16];
    rand_bytes(&mut nonce)?;
    let encoded = base64_encode(&nonce)?;
    String::from_utf8(encoded).map_err(|_| CurlError::FailedInit)
}

// ===========================================================================
// Frame-flag mapping — pure functions translating between the on-wire first
// byte (opcode + FIN) and curl's `CURLWS_*` flag set, in both directions.
//
// These mirror curl's `ws_frame_firstbyte2flags` / `ws_frame_flags2firstbyte`
// (`lib/ws.c`). They are deliberately pure so the parity-critical mapping is
// fully unit-testable; the engine layer threads any error message to the
// connection's error buffer and returns the carried `CURLcode`.
// ===========================================================================

/// A codec-layer error: the [`CurlError`] code curl would return paired with the
/// human-readable diagnostic curl emits via `failf()`.
///
/// Returned by the pure codec routines so they stay free of connection /
/// error-buffer coupling. The networked engine methods convert it by logging the
/// message to the connection's error buffer (`sendf::failf`) and returning the
/// code.
type WsCodecResult<T> = core::result::Result<T, (CurlError, String)>;

/// Translate a received frame's first header byte (opcode + FIN) into the
/// `CURLWS_*` flag set curl surfaces, validating RFC 6455 fragmentation rules.
///
/// Oracle: `ws_frame_firstbyte2flags` (`lib/ws.c`). `cont_flags` is the decoder's
/// running flag set for an in-progress fragmented message — it carries
/// `CURLWS_CONT` together with the originating `CURLWS_TEXT` / `CURLWS_BINARY`
/// type bit. The byte is decomposed into opcode + FIN (rather than matched as a
/// single value) purely for readability; an explicit reserved-bit check up front
/// reproduces curl's `default:` arm, which rejects any first byte that does not
/// match a known opcode pattern (a byte with RSV bits set can never match a
/// valid pattern, so it would otherwise fall through to that arm). On a protocol
/// violation the function returns `(CURLE_RECV_ERROR, diagnostic)`.
fn firstbyte_to_flags(firstbyte: u8, cont_flags: i32) -> WsCodecResult<i32> {
    // Reserved bits must be clear (no extension is negotiated).
    if firstbyte & WSBIT_RSV_MASK != 0 {
        return Err((
            CurlError::RecvError,
            format!("[WS] invalid reserved bits: {firstbyte:02x}"),
        ));
    }

    let cont = CURLWS_CONT as i32;
    let fin = firstbyte & WSBIT_FIN != 0;
    let opcode = firstbyte & WSBIT_OPCODE_MASK;
    let in_fragment = cont_flags & cont != 0;

    match opcode {
        // Continuation frame: only valid while a fragmented message is open. A
        // non-final continuation keeps CURLWS_CONT set; the final continuation
        // clears it, closing the message — while preserving the TEXT/BINARY type
        // bit carried in `cont_flags`.
        WSBIT_OPCODE_CONT => {
            if !in_fragment {
                return Err((
                    CurlError::RecvError,
                    "[WS] no ongoing fragmented message to continue".into(),
                ));
            }
            Ok(if fin {
                cont_flags & !cont
            } else {
                cont_flags | cont
            })
        }
        // Text frame: a fresh message. A non-final first fragment also sets
        // CURLWS_CONT. Starting a new data message mid-fragment is illegal.
        WSBIT_OPCODE_TEXT => {
            if in_fragment {
                return Err((
                    CurlError::RecvError,
                    "[WS] fragmented message interrupted by new TEXT message".into(),
                ));
            }
            let text = CURLWS_TEXT as i32;
            Ok(if fin { text } else { text | cont })
        }
        // Binary frame: analogous to TEXT.
        WSBIT_OPCODE_BIN => {
            if in_fragment {
                return Err((
                    CurlError::RecvError,
                    "[WS] fragmented message interrupted by new BINARY message".into(),
                ));
            }
            let bin = CURLWS_BINARY as i32;
            Ok(if fin { bin } else { bin | cont })
        }
        // Control frames MUST NOT be fragmented (RFC 6455 §5.5): the FIN bit is
        // mandatory.
        WSBIT_OPCODE_CLOSE | WSBIT_OPCODE_PING | WSBIT_OPCODE_PONG => {
            if !fin {
                let name = match opcode {
                    WSBIT_OPCODE_CLOSE => "CLOSE",
                    WSBIT_OPCODE_PING => "PING",
                    _ => "PONG",
                };
                return Err((
                    CurlError::RecvError,
                    format!("[WS] invalid fragmented {name} frame"),
                ));
            }
            Ok(match opcode {
                WSBIT_OPCODE_CLOSE => CURLWS_CLOSE as i32,
                WSBIT_OPCODE_PING => CURLWS_PING as i32,
                _ => CURLWS_PONG as i32,
            })
        }
        other => Err((
            CurlError::RecvError,
            format!("[WS] invalid opcode: {other:02x}"),
        )),
    }
}

/// Translate a `CURLWS_*` flag set (as passed to `ws_send`) into the on-wire
/// first header byte (opcode + FIN), honoring an in-progress fragmented message.
///
/// Oracle: `ws_frame_flags2firstbyte` (`lib/ws.c`). `contfragment` records
/// whether the encoder is mid-message: when set, a data send is emitted as a
/// continuation opcode rather than a fresh TEXT/BINARY opcode. The `CURLWS_OFFSET`
/// bit is a send-side delivery modifier and is masked off before the decision.
/// On an invalid flag combination it returns `(CURLE_BAD_FUNCTION_ARGUMENT,
/// diagnostic)`.
fn flags_to_firstbyte(flags: u32, contfragment: bool) -> WsCodecResult<u8> {
    // OFFSET selects piecewise delivery of a pre-announced frame; it is not part
    // of the opcode decision.
    let sel = flags & !CURLWS_OFFSET;
    let fin = WSBIT_FIN;
    match sel {
        // No data-type flag: only valid as the final continuation closing an
        // in-progress fragmented message (CONT | FIN); otherwise a usage error.
        0 => {
            if contfragment {
                Ok(WSBIT_OPCODE_CONT | fin)
            } else {
                Err((
                    CurlError::BadFunctionArgument,
                    "[WS] no flags given to ws_send".into(),
                ))
            }
        }
        // Bare CONT: a non-final continuation; requires an open message.
        f if f == CURLWS_CONT => {
            if contfragment {
                Ok(WSBIT_OPCODE_CONT)
            } else {
                Err((
                    CurlError::BadFunctionArgument,
                    "[WS] no ongoing fragmented message to continue".into(),
                ))
            }
        }
        // TEXT (final): a fresh single-frame text message, or — if mid-fragment —
        // the final continuation of the open message.
        f if f == CURLWS_TEXT => Ok(if contfragment {
            WSBIT_OPCODE_CONT | fin
        } else {
            WSBIT_OPCODE_TEXT | fin
        }),
        // TEXT | CONT (non-final): the first fragment of a new text message, or a
        // continuation of the open one.
        f if f == (CURLWS_TEXT | CURLWS_CONT) => Ok(if contfragment {
            WSBIT_OPCODE_CONT
        } else {
            WSBIT_OPCODE_TEXT
        }),
        // BINARY (final): analogous to TEXT (final).
        f if f == CURLWS_BINARY => Ok(if contfragment {
            WSBIT_OPCODE_CONT | fin
        } else {
            WSBIT_OPCODE_BIN | fin
        }),
        // BINARY | CONT (non-final): analogous to TEXT | CONT.
        f if f == (CURLWS_BINARY | CURLWS_CONT) => Ok(if contfragment {
            WSBIT_OPCODE_CONT
        } else {
            WSBIT_OPCODE_BIN
        }),
        // Control frames: always final, never fragmented.
        f if f == CURLWS_CLOSE => Ok(WSBIT_OPCODE_CLOSE | fin),
        f if f == CURLWS_PING => Ok(WSBIT_OPCODE_PING | fin),
        f if f == CURLWS_PONG => Ok(WSBIT_OPCODE_PONG | fin),
        f if f == (CURLWS_CLOSE | CURLWS_CONT) => Err((
            CurlError::BadFunctionArgument,
            "[WS] CLOSE frame must not be fragmented".into(),
        )),
        f if f == (CURLWS_PING | CURLWS_CONT) => Err((
            CurlError::BadFunctionArgument,
            "[WS] PING frame must not be fragmented".into(),
        )),
        f if f == (CURLWS_PONG | CURLWS_CONT) => Err((
            CurlError::BadFunctionArgument,
            "[WS] PONG frame must not be fragmented".into(),
        )),
        other => Err((
            CurlError::BadFunctionArgument,
            format!("[WS] unknown flags: {other:#x}"),
        )),
    }
}

/// Saturating `i64`→`usize` conversion: negative values clamp to `0` and values
/// exceeding `usize` (only reachable on 32-bit targets) clamp to `usize::MAX`.
/// WebSocket frame lengths are non-negative by construction; this keeps the
/// length arithmetic total and panic-free.
fn clamp_i64_to_usize(v: i64) -> usize {
    if v <= 0 {
        0
    } else {
        usize::try_from(v).unwrap_or(usize::MAX)
    }
}

// ===========================================================================
// `WsEncoder` — the RFC 6455 frame encoder (oracle: `struct ws_encoder` +
// `ws_enc_add_frame` / `ws_enc_write_payload`, `lib/ws.c`).
//
// Pure by design: the caller supplies the already-validated first byte and the
// masking key, so the encoder is deterministic and unit-testable. Randomness
// (the masking key) and flag→opcode validation live in the engine layer.
// ===========================================================================

/// The WebSocket frame encoder state — the Rust analog of curl's
/// `struct ws_encoder`.
#[derive(Debug, Default)]
struct WsEncoder {
    /// Payload bytes still to be written for the frame in progress (curl's
    /// `enc->payload_remain`). Zero when no frame is open.
    payload_remain: i64,
    /// Rolling index `0..4` into [`Self::mask`] for the next payload byte (curl's
    /// `enc->xori`).
    xori: usize,
    /// The 4-byte masking key for the frame in progress (curl's `enc->mask`).
    mask: [u8; 4],
    /// Whether a fragmented (continuation) message is open, so the next
    /// `flags→firstbyte` mapping emits continuation opcodes (curl's
    /// `enc->contfragment`).
    contfragment: bool,
}

impl WsEncoder {
    /// Begin a new frame: validate, then append the framed header — first byte,
    /// MASK-flagged length field, and 4-byte masking key — to `out`. Mirrors the
    /// header-writing portion of `ws_enc_add_frame` (`lib/ws.c`).
    ///
    /// * `firstbyte` — the already-computed opcode+FIN byte (see
    ///   [`flags_to_firstbyte`]).
    /// * `payload_len` — the total payload length of this frame.
    /// * `mask` — the masking key (a fresh random key in production; a fixed key
    ///   in tests).
    ///
    /// Client→server frames are **always** masked, so the MASK bit is set in the
    /// length byte unconditionally. Returns `(CURLE_*, diagnostic)` on a usage or
    /// protocol error (negative length, a frame already in progress, or an
    /// over-long control frame).
    fn add_frame_head(
        &mut self,
        firstbyte: u8,
        payload_len: i64,
        mask: [u8; 4],
        out: &mut Vec<u8>,
    ) -> WsCodecResult<()> {
        if payload_len < 0 {
            return Err((
                CurlError::SendError,
                format!("[WS] starting new frame with negative payload length {payload_len}"),
            ));
        }
        if self.payload_remain > 0 {
            return Err((
                CurlError::SendError,
                format!(
                    "[WS] starting new frame with {} bytes from the previous one still unsent",
                    self.payload_remain
                ),
            ));
        }

        // Control frames (CLOSE/PING/PONG) carry at most 125 payload bytes
        // (RFC 6455 §5.5); curl returns CURLE_TOO_LARGE otherwise.
        let opcode = firstbyte & WSBIT_OPCODE_MASK;
        if matches!(
            opcode,
            WSBIT_OPCODE_CLOSE | WSBIT_OPCODE_PING | WSBIT_OPCODE_PONG
        ) && payload_len > WS_MAX_CNTRL_LEN as i64
        {
            let name = match opcode {
                WSBIT_OPCODE_PING => "PING",
                WSBIT_OPCODE_PONG => "PONG",
                _ => "CLOSE",
            };
            return Err((
                CurlError::TooLarge,
                format!("[WS] given {name} frame is too big"),
            ));
        }

        out.push(firstbyte);

        // Length field, with the MASK bit set in the second byte. Lengths up to
        // 125 are inline; 126..=65535 use a 16-bit extension; larger lengths use
        // a 64-bit extension.
        if payload_len > 65535 {
            out.push(127 | WSBIT_MASK);
            out.extend_from_slice(&(payload_len as u64).to_be_bytes());
        } else if payload_len >= 126 {
            out.push(126 | WSBIT_MASK);
            out.extend_from_slice(&(payload_len as u16).to_be_bytes());
        } else {
            out.push(payload_len as u8 | WSBIT_MASK);
        }

        // The 4-byte masking key follows the length field.
        out.extend_from_slice(&mask);

        self.mask = mask;
        self.xori = 0;
        self.payload_remain = payload_len;
        Ok(())
    }

    /// Mask and append up to `payload_remain` bytes of `buf` to `out`, advancing
    /// the rolling mask index, and return the number of payload bytes consumed
    /// (`≤ buf.len()` and `≤ payload_remain`). Mirrors `ws_enc_write_payload`
    /// (`lib/ws.c`): each byte is XORed with `mask[xori]`, and `xori` cycles
    /// `0→1→2→3→0`.
    fn encode_payload(&mut self, buf: &[u8], out: &mut Vec<u8>) -> usize {
        let remain = clamp_i64_to_usize(self.payload_remain);
        let len = buf.len().min(remain);
        for &byte in &buf[..len] {
            out.push(byte ^ self.mask[self.xori]);
            self.xori = (self.xori + 1) & 3;
        }
        self.payload_remain -= len as i64;
        len
    }

    /// Whether the frame in progress has had its entire payload written.
    fn frame_complete(&self) -> bool {
        self.payload_remain == 0
    }
}

// ===========================================================================
// `RecvBuf` — the inbound raw-byte buffer (oracle: curl's `inraw` bufq).
//
// A simple cursor over a `Vec<u8>`: bytes are appended at the back (from the
// network) and consumed from the front (by the decoder). Keeping a single
// contiguous backing store lets the decoder hand the payload pass a real slice,
// which a `VecDeque` could split. The read cursor is compacted lazily so the
// backing `Vec` does not grow without bound across many frames.
// ===========================================================================

/// A front-to-back byte cursor used as the decoder's input buffer.
#[derive(Debug, Default)]
struct RecvBuf {
    /// The backing bytes; valid unread data is `data[pos..]`.
    data: Vec<u8>,
    /// Read cursor: the index of the next unread byte.
    pos: usize,
}

impl RecvBuf {
    /// Create an empty buffer.
    fn new() -> Self {
        Self::default()
    }

    /// The unread bytes (`data[pos..]`).
    fn available(&self) -> &[u8] {
        &self.data[self.pos..]
    }

    /// The number of unread bytes.
    fn len(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Whether there are no unread bytes.
    fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Append freshly received bytes at the back, compacting consumed bytes
    /// first so the buffer reclaims space.
    fn extend(&mut self, bytes: &[u8]) {
        if self.pos > 0 {
            self.data.drain(..self.pos);
            self.pos = 0;
        }
        self.data.extend_from_slice(bytes);
    }

    /// Advance the read cursor by `n` bytes (clamped to what remains); fully
    /// drained buffers reset to empty so the backing `Vec` can be reused.
    fn skip(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.data.len());
        if self.pos >= self.data.len() {
            self.data.clear();
            self.pos = 0;
        }
    }
}

// ===========================================================================
// `WsDecoder` — the RFC 6455 frame decoder (oracle: `struct ws_decoder` +
// `ws_dec_read_head` / `ws_dec_pass*`, `lib/ws.c`).
//
// A re-entrant state machine: a frame head may arrive split across several
// network reads, and a payload is streamed out in chunks. All state needed to
// resume mid-frame lives in the struct.
// ===========================================================================

/// Decoder state (curl's `enum ws_dec_state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WsDecState {
    /// Between frames: the next pass starts a fresh frame.
    Init,
    /// Parsing the frame head (first byte, length, extended length).
    Head,
    /// Streaming the frame payload to the caller.
    Payload,
}

/// The result of attempting to parse a frame head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeadStatus {
    /// A complete head was parsed; `payload_len`/`frame_flags` are now set.
    Done,
    /// The input ran out mid-head; more network bytes are needed (curl's
    /// `CURLE_AGAIN`).
    NeedMore,
}

/// The WebSocket frame decoder — the Rust analog of curl's `struct ws_decoder`.
#[derive(Debug)]
struct WsDecoder {
    /// `frame_age` carried on the decoded meta (always `0` in curl 8.x).
    frame_age: i32,
    /// The `CURLWS_*` flag set of the frame currently being decoded.
    frame_flags: i32,
    /// How many payload bytes of the current frame have already been delivered.
    payload_offset: i64,
    /// The total payload length of the current frame.
    payload_len: i64,
    /// The raw frame-head bytes accumulated so far (max 10: 2 base + 8 extended).
    head: [u8; 10],
    /// Number of head bytes accumulated.
    head_len: usize,
    /// Total head length expected (2, 4, or 10), known once the second byte is in.
    head_total: usize,
    /// The decoder state.
    state: WsDecState,
    /// The running flag set of an in-progress fragmented message — carries
    /// `CURLWS_CONT` plus the originating `CURLWS_TEXT`/`CURLWS_BINARY` type bit.
    /// Carried across frames (only reset by [`Self::reset`]).
    cont_flags: i32,
}

impl Default for WsDecoder {
    fn default() -> Self {
        Self {
            frame_age: 0,
            frame_flags: 0,
            payload_offset: 0,
            payload_len: 0,
            head: [0; 10],
            head_len: 0,
            head_total: 0,
            state: WsDecState::Init,
            cont_flags: 0,
        }
    }
}

impl WsDecoder {
    /// Create a fresh decoder (curl's `ws_dec_init`).
    fn new() -> Self {
        Self::default()
    }

    /// Reset for the next frame, **carrying** `cont_flags` (curl's
    /// `ws_dec_next_frame`).
    fn next_frame(&mut self) {
        self.frame_age = 0;
        self.frame_flags = 0;
        self.payload_offset = 0;
        self.payload_len = 0;
        self.head_len = 0;
        self.head_total = 0;
        self.state = WsDecState::Init;
        // cont_flags is intentionally preserved across frames.
    }

    /// Full reset, **clearing** `cont_flags` too (curl's `ws_dec_reset`). Used on
    /// a decode error to abandon any in-progress fragmented message.
    fn reset(&mut self) {
        self.next_frame();
        self.cont_flags = 0;
    }

    /// Parse the frame head from `inbuf`, consuming bytes as they are read.
    ///
    /// Faithful port of `ws_dec_read_head` (`lib/ws.c`): returns
    /// [`HeadStatus::Done`] once the full head is parsed (with `payload_len`,
    /// `frame_flags`, `payload_offset` set), [`HeadStatus::NeedMore`] when the
    /// input is exhausted mid-head, or `(CURLE_RECV_ERROR, diagnostic)` on a
    /// protocol violation (masked server frame, over-long control frame,
    /// invalid opcode/reserved bits, or a length wider than 63 bits). On error
    /// the decoder is reset (curl calls `ws_dec_reset`).
    fn read_head(&mut self, inbuf: &mut RecvBuf) -> WsCodecResult<HeadStatus> {
        while !inbuf.is_empty() {
            if self.head_len == 0 {
                // First byte: opcode + FIN. Map to flags and validate.
                let b0 = inbuf.available()[0];
                inbuf.skip(1);
                self.head[0] = b0;
                match firstbyte_to_flags(b0, self.cont_flags) {
                    Ok(flags) => self.frame_flags = flags,
                    Err(e) => {
                        self.reset();
                        return Err(e);
                    }
                }
                // Fragmentation tracking applies only to data frames; control
                // frames (close/ping/pong) leave the CONT status untouched.
                if self.frame_flags & ((CURLWS_TEXT | CURLWS_BINARY) as i32) != 0 {
                    self.cont_flags = self.frame_flags;
                }
                self.head_len = 1;
                continue;
            } else if self.head_len == 1 {
                // Second byte: MASK bit + 7-bit length (or 126/127 marker).
                let b1 = inbuf.available()[0];
                inbuf.skip(1);
                self.head[1] = b1;
                self.head_len = 2;

                // A client MUST fail the connection on a masked server frame.
                if b1 & WSBIT_MASK != 0 {
                    self.reset();
                    return Err((CurlError::RecvError, "[WS] masked input frame".into()));
                }

                // Control frames are limited to 125 payload bytes; a 126/127
                // length marker on a control frame is therefore invalid.
                let ctrl_len = b1 as usize;
                if self.frame_flags & (CURLWS_PING as i32) != 0 && ctrl_len > WS_MAX_CNTRL_LEN {
                    self.reset();
                    return Err((
                        CurlError::RecvError,
                        "[WS] received PING frame is too big".into(),
                    ));
                }
                if self.frame_flags & (CURLWS_PONG as i32) != 0 && ctrl_len > WS_MAX_CNTRL_LEN {
                    self.reset();
                    return Err((
                        CurlError::RecvError,
                        "[WS] received PONG frame is too big".into(),
                    ));
                }
                if self.frame_flags & (CURLWS_CLOSE as i32) != 0 && ctrl_len > WS_MAX_CNTRL_LEN {
                    self.reset();
                    return Err((
                        CurlError::RecvError,
                        "[WS] received CLOSE frame is too big".into(),
                    ));
                }

                // Determine the total head length from the length marker.
                if b1 == 126 {
                    self.head_total = 4;
                    continue;
                } else if b1 == 127 {
                    self.head_total = 10;
                    continue;
                }
                // 7-bit length: head_total stays 2 and we fall through to finish.
                self.head_total = 2;
            }

            // Accumulate any remaining extended-length bytes.
            if self.head_len < self.head_total {
                self.head[self.head_len] = inbuf.available()[0];
                inbuf.skip(1);
                self.head_len += 1;
                if self.head_len < self.head_total {
                    continue;
                }
            }

            // The complete head is in hand; compute the payload length.
            match self.head_total {
                2 => self.payload_len = i64::from(self.head[1]),
                4 => {
                    self.payload_len = (i64::from(self.head[2]) << 8) | i64::from(self.head[3]);
                }
                10 => {
                    if self.head[2] > 127 {
                        self.reset();
                        return Err((
                            CurlError::RecvError,
                            "[WS] frame length longer than 63 bits not supported".into(),
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
                    self.reset();
                    return Err((
                        CurlError::RecvError,
                        "[WS] unexpected frame header length".into(),
                    ));
                }
            }

            self.frame_age = 0;
            self.payload_offset = 0;
            return Ok(HeadStatus::Done);
        }

        // Ran out of input before the head was complete.
        Ok(HeadStatus::NeedMore)
    }
}

// ===========================================================================
// Encoder-send helpers (oracle: `ws_enc_add_frame`/`ws_enc_write_head`/
// `ws_enc_add_pending`/`ws_enc_add_cntrl`, `lib/ws.c`).
//
// These are free functions taking the encoder, the outbound buffer, and the
// pending-control slot by explicit `&mut` so that callers can invoke them while
// holding disjoint borrows of other [`WsConnState`] fields (e.g. the decoder
// during auto-PONG). They generate the random masking key the pure
// [`WsEncoder::add_frame_head`] requires.
// ===========================================================================

/// A control frame queued for sending (oracle: curl's `ws->pending`). curl keeps
/// at most one; a newer control frame overwrites an older unsent one.
#[derive(Debug, Clone)]
struct PendingControl {
    /// The `CURLWS_*` frame type (`CURLWS_CLOSE`/`CURLWS_PING`/`CURLWS_PONG`).
    frame_type: u32,
    /// The control payload (≤ [`WS_MAX_CNTRL_LEN`] bytes).
    payload: Vec<u8>,
}

/// Generate a fresh 4-byte masking key. Honors the `CURL_WS_FORCE_ZERO_MASK`
/// environment variable (the regression suite sets it to make the masked wire
/// output deterministic), matching curl's `DEBUGBUILD` behavior.
fn generate_mask() -> Result<[u8; 4]> {
    let mut mask = [0u8; 4];
    rand_bytes(&mut mask)?;
    if std::env::var_os("CURL_WS_FORCE_ZERO_MASK").is_some() {
        mask = [0; 4];
    }
    Ok(mask)
}

/// Map `flags`→firstbyte, update the encoder's continuation state, generate a
/// masking key, and write the frame head into `out`. The engine wrapper around
/// the pure [`WsEncoder::add_frame_head`] (oracle: the tail of `ws_enc_add_frame`).
fn enc_add_frame_random(
    enc: &mut WsEncoder,
    out: &mut Vec<u8>,
    flags: u32,
    payload_len: i64,
) -> WsCodecResult<()> {
    let firstbyte = flags_to_firstbyte(flags, enc.contfragment)?;
    // Continuation tracking applies only to data frames (text/binary); control
    // frames never change the CONT status.
    if flags & (CURLWS_TEXT | CURLWS_BINARY) != 0 {
        enc.contfragment = flags & CURLWS_CONT != 0;
    }
    let mask =
        generate_mask().map_err(|e| (e, "[WS] failed to generate masking key".to_string()))?;
    enc.add_frame_head(firstbyte, payload_len, mask, out)
}

/// Encode a queued pending control frame (head + masked payload) into `out`, if
/// one is queued and the encoder is not mid-frame (oracle: `ws_enc_add_pending`).
/// A no-op when nothing is pending or the encoder is busy (the frame stays
/// queued for the next opportunity, matching curl's `CURLE_AGAIN` deferral).
fn enc_add_pending(
    enc: &mut WsEncoder,
    out: &mut Vec<u8>,
    pending: &mut Option<PendingControl>,
) -> WsCodecResult<()> {
    let (frame_type, payload) = match pending.take() {
        Some(p) => (p.frame_type, p.payload),
        None => return Ok(()),
    };
    if enc.payload_remain > 0 {
        // In the middle of another frame; cannot add now — re-queue it.
        *pending = Some(PendingControl {
            frame_type,
            payload,
        });
        return Ok(());
    }
    enc_add_frame_random(enc, out, frame_type, payload.len() as i64)?;
    let n = enc.encode_payload(&payload, out);
    debug_assert_eq!(n, payload.len(), "control payload must fit in one frame");
    Ok(())
}

/// Queue a control frame (overwriting any prior pending one) and encode it
/// immediately when the encoder is idle (oracle: `ws_enc_add_cntrl`). The actual
/// network flush is performed by the caller.
fn enc_add_cntrl(
    enc: &mut WsEncoder,
    out: &mut Vec<u8>,
    pending: &mut Option<PendingControl>,
    frame_type: u32,
    payload: &[u8],
) -> WsCodecResult<()> {
    if payload.len() > WS_MAX_CNTRL_LEN {
        return Err((
            CurlError::BadFunctionArgument,
            "[WS] control frame payload exceeds 125 bytes".into(),
        ));
    }
    *pending = Some(PendingControl {
        frame_type,
        payload: payload.to_vec(),
    });
    // If no frame is currently open, the control frame can be emitted right
    // away; otherwise it stays queued until the open frame's payload finishes
    // (oracle: `if(!enc->payload_remain) ws_enc_add_pending(...)`).
    if enc.frame_complete() {
        enc_add_pending(enc, out, pending)?;
    }
    Ok(())
}

/// Flush any pending control frame, then write a new frame head (oracle:
/// `ws_enc_write_head`).
fn enc_write_head(
    enc: &mut WsEncoder,
    out: &mut Vec<u8>,
    pending: &mut Option<PendingControl>,
    flags: u32,
    payload_len: i64,
) -> WsCodecResult<()> {
    if pending.is_some() {
        enc_add_pending(enc, out, pending)?;
    }
    enc_add_frame_random(enc, out, flags, payload_len)
}

// ===========================================================================
// `WsConnState` — the per-connection WebSocket engine state (oracle: curl's
// `struct websocket`, stored in `conn` meta under `CURL_META_PROTO_WS_CONN`).
//
// This is the object the FFI crate stores on the connection and drives through
// the safe methods below. The FFI marshals raw C pointers/buffers into the
// `&mut [u8]` / `&[u8]` shapes used here; it also temporarily takes this state
// out of the [`Connection`]'s protocol-state slot around each call so that the
// engine can borrow both `self` and the `&mut Connection` without aliasing.
// ===========================================================================

/// Per-connection WebSocket state: the frame decoder/encoder, the inbound and
/// outbound byte buffers, the most-recent received-frame meta, and the queued
/// control frame. Engine methods on this type back the public `curl_ws_*` API.
pub struct WsConnState {
    /// Inbound frame decoder (curl's `ws->dec`).
    dec: WsDecoder,
    /// Outbound frame encoder (curl's `ws->enc`).
    enc: WsEncoder,
    /// Raw bytes received from the network awaiting decode (curl's `ws->recvbuf`).
    recvbuf: RecvBuf,
    /// Encoded bytes awaiting transmission (curl's `ws->sendbuf`).
    sendbuf: Vec<u8>,
    /// Count of payload bytes currently buffered in `sendbuf` but not yet
    /// credited to a `ws_send` caller (curl's `ws->sendbuf_payload`).
    sendbuf_payload: usize,
    /// Metadata of the most recently received frame/chunk (curl's `ws->recvframe`),
    /// returned by [`Self::meta`] and the `curl_ws_recv` out-parameter.
    recvframe: WsFrameMeta,
    /// A single queued control frame awaiting transmission (curl's `ws->pending`).
    pending: Option<PendingControl>,
    /// `CURLWS_RAW_MODE`: the application supplies/consumes raw frame bytes and
    /// the engine performs no RFC 6455 framing (curl's `data->set.ws_raw_mode`).
    raw_mode: bool,
    /// `CURLWS_NOAUTOPONG`: disable the automatic PONG reply to PINGs (curl's
    /// `data->set.ws_no_auto_pong`).
    no_auto_pong: bool,
}

/// The transient per-`ws_recv` collection context (oracle: `struct ws_collect`).
#[derive(Default)]
struct Collect {
    /// Bytes written into the caller's buffer so far.
    bufidx: usize,
    /// Recorded frame meta (captured on the first chunk).
    frame_age: i32,
    frame_flags: i32,
    payload_offset: i64,
    payload_len: i64,
    /// Whether a (non-auto-PONG) frame was delivered to the caller.
    written: bool,
}

/// The outcome of decoding one pass (oracle: the `CURLE_OK`/`CURLE_AGAIN` return
/// of `ws_dec_pass`).
enum PassResult {
    /// A frame (or 0-length frame, or auto-PONG'd control) was fully processed.
    Done,
    /// More network input is required to make progress.
    Again,
}

/// The outcome of collecting one payload chunk (oracle: the write-callback
/// `CURLcode`/`*pnwritten` contract).
enum CollectOutcome {
    /// `n` bytes were consumed from the inbound buffer.
    Consumed(usize),
    /// The caller's buffer is full; retry once it has been drained (no bytes
    /// consumed).
    Again,
}

impl WsConnState {
    /// Create fresh per-connection WebSocket state with the given option flags.
    #[must_use]
    pub fn new(raw_mode: bool, no_auto_pong: bool) -> Self {
        Self {
            dec: WsDecoder::new(),
            enc: WsEncoder::default(),
            recvbuf: RecvBuf::new(),
            sendbuf: Vec::new(),
            sendbuf_payload: 0,
            recvframe: WsFrameMeta::default(),
            pending: None,
            raw_mode,
            no_auto_pong,
        }
    }

    /// Seed the inbound buffer with bytes already read off the socket during the
    /// HTTP upgrade (oracle: the `connect_only` path in `Curl_ws_accept` that
    /// writes the leftover `mem` into `ws->recvbuf`).
    pub fn buffer_received(&mut self, bytes: &[u8]) {
        self.recvbuf.extend(bytes);
    }

    /// The metadata of the most recently received frame (backs `curl_ws_meta`).
    #[must_use]
    pub fn meta(&self) -> WsFrameMeta {
        self.recvframe
    }

    // ----- send path -------------------------------------------------------

    /// Send a WebSocket message (backs `curl_ws_send`).
    ///
    /// In raw mode the bytes are transmitted verbatim (and `flags`/`fragsize`
    /// must be `0`); otherwise the payload is framed per RFC 6455 — opcode/FIN
    /// chosen from `flags`, masked with a fresh random key, and transmitted.
    /// With `CURLWS_OFFSET`, `fragsize` gives the total frame length and the call
    /// supplies one chunk of it (subsequent calls supply the rest). Returns the
    /// number of **payload** bytes accepted from `payload` (framing overhead is
    /// not counted), matching curl's `*sent` contract.
    pub async fn ws_send(
        &mut self,
        conn: &mut Connection,
        payload: &[u8],
        flags: u32,
        fragsize: i64,
    ) -> Result<usize> {
        if self.raw_mode {
            return self.ws_send_raw(conn, payload, flags, fragsize).await;
        }
        self.ws_enc_send(conn, payload, flags, fragsize).await
    }

    /// Start a frame for piecewise (`CURLWS_OFFSET`) delivery without sending
    /// payload yet (backs `curl_ws_start_frame`). The frame head is buffered; the
    /// following [`Self::ws_send`] calls supply the payload. `err_buf` receives
    /// any diagnostic (the FFI passes the easy handle's error buffer).
    pub fn ws_start_frame(
        &mut self,
        err_buf: &mut Option<String>,
        flags: u32,
        frame_len: i64,
    ) -> Result<()> {
        if self.raw_mode {
            // curl returns CURLE_FAILED_INIT for start_frame under raw mode.
            sendf::failf(
                err_buf,
                "cannot curl_ws_start_frame() with CURLWS_RAW_MODE enabled",
            );
            return Err(CurlError::FailedInit);
        }
        if self.enc.payload_remain > 0 {
            sendf::failf(err_buf, "[WS] previous frame not finished");
            return Err(CurlError::SendError);
        }
        enc_write_head(
            &mut self.enc,
            &mut self.sendbuf,
            &mut self.pending,
            flags,
            frame_len,
        )
        .map_err(|(code, msg)| {
            sendf::failf(err_buf, &msg);
            code
        })
    }

    /// Raw-mode send: flush any buffered bytes, then transmit `payload` verbatim
    /// (oracle: `ws_send_raw`). `flags` and `fragsize` MUST be zero.
    async fn ws_send_raw(
        &mut self,
        conn: &mut Connection,
        payload: &[u8],
        flags: u32,
        fragsize: i64,
    ) -> Result<usize> {
        if fragsize != 0 || flags != 0 {
            sendf::failf(
                &mut conn.filter_data.error_buffer,
                "[WS] fragsize and flags must be zero in raw mode",
            );
            return Err(CurlError::BadFunctionArgument);
        }
        self.flush(conn).await?;
        if payload.is_empty() {
            return Ok(0);
        }
        let mut sent = 0usize;
        while sent < payload.len() {
            let n = Curl_conn_send(conn, FIRSTSOCKET, &payload[sent..], false).await?;
            if n == 0 {
                return Err(CurlError::SendError);
            }
            sent += n;
        }
        Ok(sent)
    }

    /// Framed (non-raw) send (oracle: `ws_enc_send`). Drives one `ws_send` call:
    /// writes the frame head if starting fresh, encodes this call's payload
    /// chunk, and flushes the buffer to the network.
    async fn ws_enc_send(
        &mut self,
        conn: &mut Connection,
        buffer: &[u8],
        flags: u32,
        fragsize: i64,
    ) -> Result<usize> {
        let buflen = buffer.len();
        let ongoing = self.enc.payload_remain > 0 || !self.sendbuf.is_empty();

        if ongoing {
            // Continuing an in-flight frame: the new chunk must not overflow the
            // remaining declared payload (curl's "unaligned frame size" guard).
            let capacity = self.enc.payload_remain + self.sendbuf_payload as i64;
            if (buflen as i64) > capacity {
                sendf::failf(
                    &mut conn.filter_data.error_buffer,
                    &format!("[WS] unaligned frame size (sending {buflen} instead of {capacity})"),
                );
                return Err(CurlError::BadFunctionArgument);
            }
        } else {
            // Fresh frame: flush leftovers, then write the head. With OFFSET the
            // declared frame length is `fragsize`; otherwise it is this buffer.
            self.flush(conn).await?;
            let payload_len = if flags & CURLWS_OFFSET != 0 {
                fragsize
            } else {
                buflen as i64
            };
            if let Err((code, msg)) = enc_write_head(
                &mut self.enc,
                &mut self.sendbuf,
                &mut self.pending,
                flags,
                payload_len,
            ) {
                sendf::failf(&mut conn.filter_data.error_buffer, &msg);
                return Err(code);
            }
        }

        // Encode this call's payload (after any bytes already buffered) and flush.
        let start = self.sendbuf_payload.min(buflen);
        let added = self.enc.encode_payload(&buffer[start..], &mut self.sendbuf);
        self.sendbuf_payload += added;

        self.flush(conn).await?;
        let sent = self.sendbuf_payload;
        self.sendbuf_payload = 0;
        Ok(sent)
    }

    /// Transmit the entire `sendbuf` to the network, awaiting writability
    /// (oracle: `ws_flush`, blocking variant — the FFI's `block_on` drives this
    /// to completion, matching curl's in-callback blocking flush).
    async fn flush(&mut self, conn: &mut Connection) -> Result<()> {
        while !self.sendbuf.is_empty() {
            let n = Curl_conn_send(conn, FIRSTSOCKET, &self.sendbuf, false).await?;
            if n == 0 {
                return Err(CurlError::SendError);
            }
            self.sendbuf.drain(..n);
        }
        Ok(())
    }

    // ----- receive path ----------------------------------------------------

    /// Receive and decode the next WebSocket frame (or the next chunk of a large
    /// frame) into `out` (backs `curl_ws_recv`).
    ///
    /// Network bytes are slurped into the inbound buffer as needed and decoded;
    /// control PINGs are auto-answered with a PONG (unless `CURLWS_NOAUTOPONG`)
    /// and not surfaced to the caller. Returns the number of payload bytes
    /// written to `out` together with the frame metadata. A clean connection
    /// close with no data yields [`CurlError::GotNothing`].
    pub async fn ws_recv(
        &mut self,
        conn: &mut Connection,
        out: &mut [u8],
    ) -> Result<(usize, WsFrameMeta)> {
        let mut ctx = Collect::default();

        loop {
            if self.recvbuf.is_empty() {
                let mut tmp = vec![0u8; WS_CHUNK_SIZE];
                let n = Curl_conn_recv(conn, FIRSTSOCKET, &mut tmp).await?;
                if n == 0 {
                    sendf::infof(
                        conn.filter_data.verbose,
                        "[WS] connection expectedly closed?",
                    );
                    return Err(CurlError::GotNothing);
                }
                self.recvbuf.extend(&tmp[..n]);
            }

            let res = match self.pump_decode(out, &mut ctx) {
                Ok(r) => r,
                Err((code, msg)) => {
                    sendf::failf(&mut conn.filter_data.error_buffer, &msg);
                    return Err(code);
                }
            };

            match res {
                PassResult::Again => {
                    if ctx.written {
                        break;
                    }
                    // Nothing delivered yet: read more input.
                    continue;
                }
                PassResult::Done => {
                    if ctx.written {
                        break;
                    }
                    // A control frame (e.g. PING) was auto-handled and not
                    // delivered; decode the next frame.
                    continue;
                }
            }
        }

        self.recvframe.update(
            ctx.frame_age,
            ctx.frame_flags,
            ctx.payload_offset,
            ctx.payload_len,
            ctx.bufidx,
        );
        let nread = self.recvframe.len;

        // Send any control frame queued during decode (the auto-PONG), so the
        // peer sees it promptly. Best-effort, exactly like curl's `(void)`-cast
        // flush at the tail of `curl_ws_recv`.
        if !self.raw_mode && self.pending.is_some() {
            let _ = enc_add_pending(&mut self.enc, &mut self.sendbuf, &mut self.pending);
            let _ = self.flush(conn).await;
        }

        Ok((nread, self.recvframe))
    }

    /// Drive the decoder one pass over the inbound buffer, collecting payload
    /// into `out` and auto-answering control PINGs (oracle: `ws_dec_pass` +
    /// `ws_client_collect`).
    fn pump_decode(&mut self, out: &mut [u8], ctx: &mut Collect) -> WsCodecResult<PassResult> {
        if self.recvbuf.is_empty() {
            return Ok(PassResult::Again);
        }

        // WS_DEC_INIT → start a fresh frame, then parse its head.
        if self.dec.state == WsDecState::Init {
            self.dec.next_frame();
            self.dec.state = WsDecState::Head;
        }

        // WS_DEC_HEAD → parse the frame head.
        if self.dec.state == WsDecState::Head {
            match self.dec.read_head(&mut self.recvbuf)? {
                HeadStatus::NeedMore => return Ok(PassResult::Again),
                HeadStatus::Done => {
                    self.dec.state = WsDecState::Payload;
                    if self.dec.payload_len == 0 {
                        // A 0-length frame still triggers exactly one delivery.
                        let _ = self.collect_chunk(out, ctx, 0)?;
                        self.dec.state = WsDecState::Init;
                        return Ok(PassResult::Done);
                    }
                }
            }
        }

        // WS_DEC_PAYLOAD → stream the payload out, chunk by chunk.
        if self.dec.state == WsDecState::Payload {
            loop {
                let remain = self.dec.payload_len - self.dec.payload_offset;
                if remain <= 0 {
                    break;
                }
                if self.recvbuf.is_empty() {
                    return Ok(PassResult::Again);
                }
                let inlen = clamp_i64_to_usize(remain).min(self.recvbuf.len());
                match self.collect_chunk(out, ctx, inlen)? {
                    CollectOutcome::Again => return Ok(PassResult::Again),
                    CollectOutcome::Consumed(n) => {
                        self.recvbuf.skip(n);
                        self.dec.payload_offset += n as i64;
                    }
                }
            }
            self.dec.state = WsDecState::Init;
            return Ok(PassResult::Done);
        }

        Ok(PassResult::Done)
    }

    /// Collect one payload chunk of `inlen` bytes from the front of the inbound
    /// buffer (oracle: `ws_client_collect`). Either copies the bytes into the
    /// caller's buffer, or — for an auto-answered PING — queues a PONG and
    /// consumes the bytes without delivering them.
    fn collect_chunk(
        &mut self,
        out: &mut [u8],
        ctx: &mut Collect,
        inlen: usize,
    ) -> WsCodecResult<CollectOutcome> {
        let flags = self.dec.frame_flags;
        let payload_offset = self.dec.payload_offset;
        let payload_len = self.dec.payload_len;
        let auto_pong = !self.no_auto_pong;

        // Bytes of payload that will still be pending after this chunk.
        let remain_after = payload_len - payload_offset - inlen as i64;
        if remain_after < 0 {
            return Err((
                CurlError::BadFunctionArgument,
                "[WS] payload parameter mismatch".into(),
            ));
        }

        // Record the frame meta on the first chunk of the frame.
        if ctx.bufidx == 0 {
            ctx.frame_age = self.dec.frame_age;
            ctx.frame_flags = flags;
            ctx.payload_offset = payload_offset;
            ctx.payload_len = payload_len;
        }

        if auto_pong && (flags & CURLWS_PING as i32) != 0 && remain_after == 0 {
            // Auto-respond to a (single-chunk) PING with the identical payload as
            // a PONG; the PING itself is consumed but not delivered to the caller.
            enc_add_cntrl(
                &mut self.enc,
                &mut self.sendbuf,
                &mut self.pending,
                CURLWS_PONG,
                &self.recvbuf.available()[..inlen],
            )?;
            Ok(CollectOutcome::Consumed(inlen))
        } else {
            ctx.written = true;
            let space = out.len() - ctx.bufidx;
            let write_len = inlen.min(space);
            if write_len == 0 {
                if inlen == 0 {
                    // A genuine 0-length frame is accepted as one empty delivery.
                    return Ok(CollectOutcome::Consumed(0));
                }
                // No room in the caller's buffer; deliver the rest next call.
                return Ok(CollectOutcome::Again);
            }
            out[ctx.bufidx..ctx.bufidx + write_len]
                .copy_from_slice(&self.recvbuf.available()[..write_len]);
            ctx.bufidx += write_len;
            Ok(CollectOutcome::Consumed(write_len))
        }
    }
}

// ===========================================================================
// Handshake request/response helpers (oracle: `Curl_ws_request` +
// `Curl_ws_accept`, `lib/ws.c`).
// ===========================================================================

/// Whether a header line (`b"Name: value"`) has the field name `name`
/// (case-insensitive), the Rust analog of curl's `Curl_checkheaders` match used
/// to avoid duplicating a user-supplied handshake header.
fn header_line_has_name(line: &[u8], name: &str) -> bool {
    let nb = name.as_bytes();
    if line.len() < nb.len() || !line[..nb.len()].eq_ignore_ascii_case(nb) {
        return false;
    }
    // The field name must be followed (after optional spaces) by a colon.
    let rest = &line[nb.len()..];
    let mut i = 0;
    while i < rest.len() && rest[i] == b' ' {
        i += 1;
    }
    i < rest.len() && rest[i] == b':'
}

/// Build the three WebSocket Upgrade request header `(name, value)` pairs for
/// the given `Sec-WebSocket-Key` value (oracle: `Curl_ws_request`):
/// `Upgrade: websocket`, `Sec-WebSocket-Version: 13`, and
/// `Sec-WebSocket-Key: <key>`. Pure and deterministic so the handshake-header
/// construction is unit-testable independently of the random key generator.
fn ws_request_headers(key: &str) -> [(&'static str, String); 3] {
    [
        ("Upgrade", "websocket".to_string()),
        ("Sec-WebSocket-Version", "13".to_string()),
        ("Sec-WebSocket-Key", key.to_string()),
    ]
}

/// Inject the WebSocket Upgrade request headers onto the easy handle's custom
/// header list (oracle: `Curl_ws_request`). Adds `Upgrade: websocket`,
/// `Sec-WebSocket-Version: 13`, and a fresh random `Sec-WebSocket-Key`, each only
/// if the user has not already supplied that header (curl's `Curl_checkheaders`
/// guard). The HTTP/1.1 engine emits the custom header list verbatim, so these
/// ride out on the upgrade `GET`.
pub(crate) fn ws_inject_request_headers(data: &mut Easy) -> Result<()> {
    let key = generate_sec_websocket_key()?;
    let list = data.set.headers.get_or_insert_with(Default::default);
    for (name, value) in ws_request_headers(&key) {
        let present = list
            .as_slice()
            .iter()
            .any(|entry| header_line_has_name(entry.to_bytes(), name));
        if !present {
            list.append(&format!("{name}: {value}"))?;
        }
    }
    Ok(())
}

// ===========================================================================
// `WsHandler` — the `ws`/`wss` `Protocol` implementation (oracle:
// `Curl_protocol_ws` + `Curl_scheme_ws`/`Curl_scheme_wss`, `lib/ws.c`).
// ===========================================================================

/// The WebSocket protocol handler for the `ws` and `wss` schemes.
///
/// One instance is created per scheme by the scheme registry (mirroring curl's
/// single `Curl_protocol_ws` vtable shared by `Curl_scheme_ws` and
/// `Curl_scheme_wss`). The carried [`Scheme`] descriptor distinguishes the two.
///
/// # Lifecycle mapping to `Curl_protocol_ws`
///
/// * `setup_connection`, `connect`, and `disconnect` use the trait defaults —
///   curl's `Curl_protocol_ws` wires `setup_connection` to `ws_setup_conn` (which
///   only pins HTTP/1.1) and leaves `connect_it`/`disconnect` as `ZERO_NULL`. A
///   CLOSE frame is **not** sent on disconnect (curl leaves that to the
///   application via `curl_ws_send(CURLWS_CLOSE)`), so emitting one here would be
///   a non-parity behavior change.
/// * [`do_it`](WsHandler::do_it) builds the Upgrade request and delegates the
///   actual exchange to the HTTP/1.1 engine — exactly as `Curl_protocol_ws.do_it
///   == Curl_http`.
/// * [`done`](WsHandler::done) installs the [`WsConnState`] engine on the
///   connection for the subsequent `curl_ws_*` calls — the Rust analog of
///   `Curl_ws_accept` storing the websocket state in the connection meta. Note
///   that curl 8.x's `Curl_ws_accept` does **not** validate
///   `Sec-WebSocket-Accept` (its `ws.c` computes no SHA-1), and the regression
///   suite relies on that: `tests/data/test2301` deliberately returns a
///   non-matching accept value. Rejecting a mismatch here would break
///   test-suite parity, so the engine matches curl and accepts the upgrade as
///   the server presented it. The RFC 6455 §4.2.2 accept hash is still provided
///   by [`sec_websocket_accept`] for completeness and conformance testing.
pub struct WsHandler {
    /// The static scheme descriptor served (`ws` or `wss`).
    scheme: &'static Scheme,
}

impl WsHandler {
    /// Construct the handler for a specific WebSocket scheme descriptor
    /// ([`crate::protocols::SCHEME_WS`] or [`crate::protocols::SCHEME_WSS`]).
    #[must_use]
    pub fn new(scheme: &'static Scheme) -> Self {
        Self { scheme }
    }
}

impl Protocol for WsHandler {
    fn scheme(&self) -> &'static Scheme {
        self.scheme
    }

    fn do_it<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
    ) -> BoxFuture<'a, Result<ProtocolTransfer>> {
        Box::pin(async move {
            // Curl_ws_request: add the Upgrade/Version/Key handshake headers.
            ws_inject_request_headers(data)?;

            // The opening handshake is an ordinary HTTP/1.1 GET Upgrade; reuse
            // the HTTP engine wholesale (curl's `Curl_protocol_ws.do_it ==
            // Curl_http`). The HTTP `is_websocket` plumbing forces the GET verb.
            let http = HttpProtocol::new(self.scheme);
            let transfer = http.do_it(data, conn).await?;
            Ok(transfer)
        })
    }

    fn done<'a>(
        &'a self,
        data: &'a mut Easy,
        conn: &'a mut Connection,
        status: Result<()>,
        premature: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Release the HTTP version state recorded by the delegated `do_it`
            // (the teardown half of `Curl_http_done`).
            let _ = conn.take_proto_state();

            // On a successful, non-premature upgrade, hand the connection to the
            // WebSocket engine — the Rust analog of `Curl_ws_accept` attaching
            // the websocket state to the connection. The subsequent `curl_ws_*`
            // FFI shims locate this state via `conn` to frame/deframe the wire.
            //
            // curl 8.x does not validate `Sec-WebSocket-Accept` here (and the
            // response-header value is not retained past the client-write
            // callbacks anyway), so no accept check is performed: see the type
            // doc and `sec_websocket_accept` for the parity rationale.
            if status.is_ok() && !premature {
                if data.set.verbose {
                    sendf::infof(true, "[WS] connection upgraded to WebSocket");
                }
                conn.set_proto_state(Box::new(WsConnState::new(
                    data.set.ws_raw_mode,
                    data.set.ws_no_auto_pong,
                )));
            }
            Ok(())
        })
    }
}

// ===========================================================================
// Unit tests — the RFC 6455 codec and handshake helpers are pure and fully
// exercised here. Network-dependent paths (`ws_send`/`ws_recv` over a live
// `Connection`, `wss://` over TLS) are covered by the integration suite in a
// later phase; the synchronous decode pump (`pump_decode`) is driven directly
// over a pre-seeded buffer so the framing logic is testable without a socket.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    // ----- test helpers ----------------------------------------------------

    /// Hex-encode a byte slice for readable known-answer assertions.
    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// Build an **unmasked** server→client frame (the only direction a curl
    /// client decodes): first byte, plain length field (no MASK bit), payload.
    fn server_frame(firstbyte: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![firstbyte];
        let n = payload.len();
        if n > 65535 {
            v.push(127);
            v.extend_from_slice(&(n as u64).to_be_bytes());
        } else if n >= 126 {
            v.push(126);
            v.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            v.push(n as u8);
        }
        v.extend_from_slice(payload);
        v
    }

    /// Parse a masked client→server frame (as produced by [`WsEncoder`]) and
    /// return `(firstbyte, unmasked_payload)`. Unmasks with the key embedded in
    /// the frame, so it is robust to whatever random mask the encoder chose.
    fn parse_client_frame(bytes: &[u8]) -> (u8, Vec<u8>) {
        let firstbyte = bytes[0];
        let b1 = bytes[1];
        assert_ne!(b1 & WSBIT_MASK, 0, "client frames must set the MASK bit");
        let len7 = (b1 & 0x7f) as usize;
        let (payload_len, mut idx) = match len7 {
            127 => (
                u64::from_be_bytes(bytes[2..10].try_into().unwrap()) as usize,
                10,
            ),
            126 => (
                u16::from_be_bytes(bytes[2..4].try_into().unwrap()) as usize,
                4,
            ),
            n => (n, 2),
        };
        let mask = [bytes[idx], bytes[idx + 1], bytes[idx + 2], bytes[idx + 3]];
        idx += 4;
        let payload: Vec<u8> = bytes[idx..idx + payload_len]
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ mask[i & 3])
            .collect();
        (firstbyte, payload)
    }

    /// Synchronous analog of [`WsConnState::ws_recv`] for tests: drive
    /// [`WsConnState::pump_decode`] over the already-buffered input (no socket
    /// slurp), returning `(nread, meta)` for the next delivered frame/chunk.
    fn decode_one(state: &mut WsConnState, out: &mut [u8]) -> Result<(usize, WsFrameMeta)> {
        let mut ctx = Collect::default();
        loop {
            if state.recvbuf.is_empty() {
                break;
            }
            match state.pump_decode(out, &mut ctx).map_err(|(code, _)| code)? {
                // `Again` here means either the caller buffer filled (with bytes
                // already written) or more network input is needed; with no
                // socket in tests, stop in both cases.
                PassResult::Again => break,
                PassResult::Done => {
                    if ctx.written {
                        break;
                    }
                    // A control frame was auto-handled (not delivered); keep
                    // decoding the next frame.
                    continue;
                }
            }
        }
        state.recvframe.update(
            ctx.frame_age,
            ctx.frame_flags,
            ctx.payload_offset,
            ctx.payload_len,
            ctx.bufidx,
        );
        Ok((state.recvframe.len, state.recvframe))
    }

    // ----- SHA-1 + Sec-WebSocket-Accept ------------------------------------

    #[test]
    fn sha1_matches_fips_180_vectors() {
        // FIPS 180-1 / RFC 3174 published test vectors.
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn sec_websocket_accept_rfc6455_known_answer() {
        // RFC 6455 §1.3 worked example.
        let accept = sec_websocket_accept("dGhlIHNhbXBsZSBub25jZQ==").unwrap();
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn generate_key_is_16_random_bytes_base64() {
        let a = generate_sec_websocket_key().unwrap();
        let b = generate_sec_websocket_key().unwrap();
        // base64 of 16 bytes is always 24 chars ending in a single pad group.
        assert_eq!(a.len(), 24, "key must be base64 of 16 bytes");
        assert!(a.ends_with("=="), "16-byte nonce ends with one pad group");
        // Overwhelmingly likely to differ; guards against a constant nonce.
        assert_ne!(a, b, "successive nonces must be randomized");
    }

    // ----- handshake request headers ---------------------------------------

    #[test]
    fn ws_request_headers_are_exact() {
        let h = ws_request_headers("KEYVALUE==");
        assert_eq!(h[0], ("Upgrade", "websocket".to_string()));
        assert_eq!(h[1], ("Sec-WebSocket-Version", "13".to_string()));
        assert_eq!(h[2], ("Sec-WebSocket-Key", "KEYVALUE==".to_string()));
    }

    #[test]
    fn header_line_has_name_is_case_insensitive_and_exact() {
        assert!(header_line_has_name(b"Upgrade: websocket", "upgrade"));
        assert!(header_line_has_name(b"Upgrade: websocket", "Upgrade"));
        assert!(header_line_has_name(
            b"Sec-WebSocket-Key: x",
            "sec-websocket-key"
        ));
        // A space before the colon is tolerated (curl trims around it).
        assert!(header_line_has_name(b"Upgrade : websocket", "Upgrade"));
        // A longer field name that merely starts with the target is not a match.
        assert!(!header_line_has_name(b"Upgrade-Foo: y", "Upgrade"));
        // A prefix that differs is not a match.
        assert!(!header_line_has_name(b"X-Upgrade: y", "Upgrade"));
        // No colon at all is not a header line.
        assert!(!header_line_has_name(b"Upgrade", "Upgrade"));
    }

    // ----- flag <-> first-byte mapping --------------------------------------

    #[test]
    fn firstbyte_to_flags_maps_every_opcode() {
        let t = CURLWS_TEXT as i32;
        let b = CURLWS_BINARY as i32;
        let cont = CURLWS_CONT as i32;
        assert_eq!(
            firstbyte_to_flags(WSBIT_FIN | WSBIT_OPCODE_TEXT, 0).unwrap(),
            t
        );
        assert_eq!(
            firstbyte_to_flags(WSBIT_FIN | WSBIT_OPCODE_BIN, 0).unwrap(),
            b
        );
        assert_eq!(
            firstbyte_to_flags(WSBIT_FIN | WSBIT_OPCODE_CLOSE, 0).unwrap(),
            CURLWS_CLOSE as i32
        );
        assert_eq!(
            firstbyte_to_flags(WSBIT_FIN | WSBIT_OPCODE_PING, 0).unwrap(),
            CURLWS_PING as i32
        );
        assert_eq!(
            firstbyte_to_flags(WSBIT_FIN | WSBIT_OPCODE_PONG, 0).unwrap(),
            CURLWS_PONG as i32
        );
        // Non-final first text fragment carries CONT.
        assert_eq!(firstbyte_to_flags(WSBIT_OPCODE_TEXT, 0).unwrap(), t | cont);
        // Final continuation of a text message clears CONT, keeps TEXT.
        assert_eq!(
            firstbyte_to_flags(WSBIT_FIN | WSBIT_OPCODE_CONT, t | cont).unwrap(),
            t
        );
    }

    #[test]
    fn firstbyte_to_flags_rejects_protocol_violations() {
        // Reserved bit set.
        assert!(firstbyte_to_flags(WSBIT_FIN | WSBIT_RSV1 | WSBIT_OPCODE_TEXT, 0).is_err());
        // Continuation with no open message.
        assert!(firstbyte_to_flags(WSBIT_FIN | WSBIT_OPCODE_CONT, 0).is_err());
        // Fragmented control frame (no FIN).
        assert!(firstbyte_to_flags(WSBIT_OPCODE_PING, 0).is_err());
        // New TEXT while a fragmented message is open.
        assert!(firstbyte_to_flags(
            WSBIT_FIN | WSBIT_OPCODE_TEXT,
            CURLWS_TEXT as i32 | CURLWS_CONT as i32
        )
        .is_err());
    }

    #[test]
    fn flags_to_firstbyte_maps_every_flag() {
        assert_eq!(
            flags_to_firstbyte(CURLWS_TEXT, false).unwrap(),
            WSBIT_FIN | WSBIT_OPCODE_TEXT
        );
        assert_eq!(
            flags_to_firstbyte(CURLWS_BINARY, false).unwrap(),
            WSBIT_FIN | WSBIT_OPCODE_BIN
        );
        assert_eq!(
            flags_to_firstbyte(CURLWS_CLOSE, false).unwrap(),
            WSBIT_FIN | WSBIT_OPCODE_CLOSE
        );
        assert_eq!(
            flags_to_firstbyte(CURLWS_PING, false).unwrap(),
            WSBIT_FIN | WSBIT_OPCODE_PING
        );
        assert_eq!(
            flags_to_firstbyte(CURLWS_PONG, false).unwrap(),
            WSBIT_FIN | WSBIT_OPCODE_PONG
        );
        // First fragment of a new text message (non-final, no contfragment).
        assert_eq!(
            flags_to_firstbyte(CURLWS_TEXT | CURLWS_CONT, false).unwrap(),
            WSBIT_OPCODE_TEXT
        );
        // Final continuation closing an open message (contfragment set, no type).
        assert_eq!(
            flags_to_firstbyte(0, true).unwrap(),
            WSBIT_FIN | WSBIT_OPCODE_CONT
        );
        // OFFSET is masked off and does not affect the opcode decision.
        assert_eq!(
            flags_to_firstbyte(CURLWS_TEXT | CURLWS_OFFSET, false).unwrap(),
            WSBIT_FIN | WSBIT_OPCODE_TEXT
        );
        // Fragmented control frame is rejected.
        assert!(flags_to_firstbyte(CURLWS_PING | CURLWS_CONT, false).is_err());
        // No flags and no open message is a usage error.
        assert!(flags_to_firstbyte(0, false).is_err());
    }

    // ----- encoder: masking + length encodings ------------------------------

    #[test]
    fn encoder_masks_per_rfc6455_5_7_example() {
        // RFC 6455 §5.7: "Hello" masked with key 0x37fa213d.
        let mut enc = WsEncoder::default();
        let mut out = Vec::new();
        let mask = [0x37, 0xfa, 0x21, 0x3d];
        enc.add_frame_head(WSBIT_FIN | WSBIT_OPCODE_TEXT, 5, mask, &mut out)
            .unwrap();
        let consumed = enc.encode_payload(b"Hello", &mut out);
        assert_eq!(consumed, 5);
        assert!(enc.frame_complete());
        assert_eq!(
            out,
            vec![0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]
        );
        // And it round-trips back to the plaintext via the embedded mask.
        let (fb, payload) = parse_client_frame(&out);
        assert_eq!(fb, 0x81);
        assert_eq!(payload, b"Hello");
    }

    #[test]
    fn encoder_zero_mask_is_identity_payload() {
        let mut enc = WsEncoder::default();
        let mut out = Vec::new();
        enc.add_frame_head(WSBIT_FIN | WSBIT_OPCODE_BIN, 4, [0, 0, 0, 0], &mut out)
            .unwrap();
        enc.encode_payload(&[1, 2, 3, 4], &mut out);
        // firstbyte, len|MASK, 4 zero mask bytes, then the unchanged payload.
        assert_eq!(out[0], WSBIT_FIN | WSBIT_OPCODE_BIN);
        assert_eq!(out[1], 4 | WSBIT_MASK);
        assert_eq!(&out[6..10], &[1, 2, 3, 4]);
    }

    #[test]
    fn encoder_extended_length_fields() {
        // 16-bit extended length (126..=65535).
        let mut enc = WsEncoder::default();
        let mut out = Vec::new();
        enc.add_frame_head(WSBIT_FIN | WSBIT_OPCODE_TEXT, 200, [1, 2, 3, 4], &mut out)
            .unwrap();
        assert_eq!(out[1], 126 | WSBIT_MASK);
        assert_eq!(&out[2..4], &200u16.to_be_bytes());

        // 64-bit extended length (> 65535). Only the head is built (no payload).
        let mut enc = WsEncoder::default();
        let mut out = Vec::new();
        enc.add_frame_head(WSBIT_FIN | WSBIT_OPCODE_BIN, 70_000, [1, 2, 3, 4], &mut out)
            .unwrap();
        assert_eq!(out[1], 127 | WSBIT_MASK);
        assert_eq!(&out[2..10], &70_000u64.to_be_bytes());
    }

    #[test]
    fn encoder_rejects_oversized_control_frame() {
        let mut enc = WsEncoder::default();
        let mut out = Vec::new();
        // A control frame may carry at most 125 payload bytes.
        let err = enc
            .add_frame_head(WSBIT_FIN | WSBIT_OPCODE_PING, 126, [0; 4], &mut out)
            .unwrap_err();
        assert_eq!(err.0, CurlError::TooLarge);
    }

    #[test]
    fn encoder_rejects_overlapping_frames() {
        let mut enc = WsEncoder::default();
        let mut out = Vec::new();
        enc.add_frame_head(WSBIT_FIN | WSBIT_OPCODE_TEXT, 10, [0; 4], &mut out)
            .unwrap();
        // A second head before the first frame's payload is finished is illegal.
        let err = enc
            .add_frame_head(WSBIT_FIN | WSBIT_OPCODE_TEXT, 5, [0; 4], &mut out)
            .unwrap_err();
        assert_eq!(err.0, CurlError::SendError);
    }

    // ----- decoder: per-opcode round-trips ----------------------------------

    #[test]
    fn decode_text_frame() {
        let mut state = WsConnState::new(false, false);
        state.buffer_received(&server_frame(WSBIT_FIN | WSBIT_OPCODE_TEXT, b"hello"));
        let mut out = [0u8; 64];
        let (n, meta) = decode_one(&mut state, &mut out).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&out[..5], b"hello");
        assert_eq!(meta.flags, CURLWS_TEXT as i32);
        assert_eq!(meta.offset, 0);
        assert_eq!(meta.bytesleft, 0);
        assert_eq!(meta.len, 5);
    }

    #[test]
    fn decode_binary_frame() {
        let mut state = WsConnState::new(false, false);
        state.buffer_received(&server_frame(WSBIT_FIN | WSBIT_OPCODE_BIN, &[9, 8, 7]));
        let mut out = [0u8; 16];
        let (n, meta) = decode_one(&mut state, &mut out).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&out[..3], &[9, 8, 7]);
        assert_eq!(meta.flags, CURLWS_BINARY as i32);
    }

    #[test]
    fn decode_close_and_pong_frames() {
        // Empty CLOSE: a zero-length frame still yields exactly one delivery.
        let mut state = WsConnState::new(false, false);
        state.buffer_received(&server_frame(WSBIT_FIN | WSBIT_OPCODE_CLOSE, b""));
        let mut out = [0u8; 16];
        let (n, meta) = decode_one(&mut state, &mut out).unwrap();
        assert_eq!(n, 0);
        assert_eq!(meta.flags, CURLWS_CLOSE as i32);

        // A server PONG is delivered to the caller (it is not auto-answered).
        let mut state = WsConnState::new(false, false);
        state.buffer_received(&server_frame(WSBIT_FIN | WSBIT_OPCODE_PONG, b"pong"));
        let (n, meta) = decode_one(&mut state, &mut out).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&out[..4], b"pong");
        assert_eq!(meta.flags, CURLWS_PONG as i32);
    }

    #[test]
    fn decoder_rejects_masked_server_frame() {
        // A server frame must not set the MASK bit (RFC 6455 §5.1).
        let mut state = WsConnState::new(false, false);
        // 0x81 TEXT|FIN, 0x85 = len 5 | MASK, mask, then 5 (masked) bytes.
        let framed = vec![
            0x81, 0x85, 0x01, 0x02, 0x03, 0x04, b'h', b'e', b'l', b'l', b'o',
        ];
        state.buffer_received(&framed);
        let mut out = [0u8; 16];
        let err = decode_one(&mut state, &mut out).unwrap_err();
        assert_eq!(err, CurlError::RecvError);
    }

    // ----- fragmentation reassembly -----------------------------------------

    #[test]
    fn decode_fragmented_text_message() {
        let mut state = WsConnState::new(false, false);
        // Fragment 1: TEXT, no FIN. Fragment 2: CONT, FIN.
        state.buffer_received(&server_frame(WSBIT_OPCODE_TEXT, b"Hel"));
        state.buffer_received(&server_frame(WSBIT_FIN | WSBIT_OPCODE_CONT, b"lo"));
        let mut out = [0u8; 64];

        let (n1, meta1) = decode_one(&mut state, &mut out).unwrap();
        assert_eq!(&out[..n1], b"Hel");
        // The opening fragment of a text message carries TEXT | CONT.
        assert_eq!(meta1.flags, (CURLWS_TEXT | CURLWS_CONT) as i32);

        let (n2, meta2) = decode_one(&mut state, &mut out).unwrap();
        assert_eq!(&out[..n2], b"lo");
        // The closing continuation clears CONT and reports the message type.
        assert_eq!(meta2.flags, CURLWS_TEXT as i32);

        assert_eq!(n1 + n2, 5);
    }

    // ----- large-frame CURLWS_OFFSET piecewise delivery ---------------------

    #[test]
    fn decode_large_frame_in_pieces() {
        let payload: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        let mut state = WsConnState::new(false, false);
        state.buffer_received(&server_frame(WSBIT_FIN | WSBIT_OPCODE_BIN, &payload));

        // Deliver in 100-byte windows; the engine streams the frame piecewise,
        // tracking offset/bytesleft exactly like curl's CURLWS_OFFSET.
        let mut reassembled = Vec::new();
        let mut out = [0u8; 100];
        let mut expected_offset = 0i64;
        loop {
            let (n, meta) = decode_one(&mut state, &mut out).unwrap();
            if n == 0 {
                break;
            }
            reassembled.extend_from_slice(&out[..n]);
            assert_eq!(meta.offset, expected_offset);
            assert_eq!(meta.len, n);
            assert_eq!(meta.bytesleft, 300 - expected_offset - n as i64);
            expected_offset += n as i64;
            if meta.bytesleft == 0 {
                break;
            }
        }
        assert_eq!(reassembled, payload);
        assert_eq!(expected_offset, 300);
    }

    #[test]
    fn decode_64bit_length_frame() {
        // A payload larger than 65535 bytes uses the 64-bit (127) length marker;
        // the decoder must parse the 10-byte head and stream the full payload.
        let payload: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
        let mut state = WsConnState::new(false, false);
        state.buffer_received(&server_frame(WSBIT_FIN | WSBIT_OPCODE_BIN, &payload));

        let mut reassembled = Vec::new();
        let mut out = [0u8; 4096];
        loop {
            let (n, meta) = decode_one(&mut state, &mut out).unwrap();
            if n == 0 {
                break;
            }
            reassembled.extend_from_slice(&out[..n]);
            if meta.bytesleft == 0 {
                break;
            }
        }
        assert_eq!(reassembled.len(), 70_000, "64-bit-framed payload truncated");
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn decode_rejects_oversized_control_frames() {
        // A control frame (PING/PONG/CLOSE) may carry at most 125 payload bytes
        // (RFC 6455 §5.5). A 126-byte control payload forces the 126 length
        // marker, which the decoder must reject as a protocol violation — one
        // dedicated guard per control opcode.
        for opcode in [
            WSBIT_OPCODE_PING,
            WSBIT_OPCODE_PONG,
            WSBIT_OPCODE_CLOSE,
        ] {
            let frame = server_frame(WSBIT_FIN | opcode, &[0u8; 126]);
            let mut state = WsConnState::new(false, false);
            state.buffer_received(&frame);
            let mut out = [0u8; 256];
            let err = decode_one(&mut state, &mut out).unwrap_err();
            assert_eq!(
                err,
                CurlError::RecvError,
                "oversized control frame (opcode {opcode:#x}) must be rejected"
            );
        }
    }

    #[test]
    fn decode_rejects_length_longer_than_63_bits() {
        // A 64-bit length whose top bit is set (head[2] > 127) exceeds the 63-bit
        // limit curl supports and must be rejected rather than mis-parsed.
        let raw: &[u8] = &[
            WSBIT_FIN | WSBIT_OPCODE_BIN,
            127,
            0x80, // high bit set → length > 2^63
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let mut state = WsConnState::new(false, false);
        state.buffer_received(raw);
        let mut out = [0u8; 64];
        let err = decode_one(&mut state, &mut out).unwrap_err();
        assert_eq!(err, CurlError::RecvError, "63-bit overflow must be rejected");
    }


    // ----- auto-PONG behavior -----------------------------------------------

    #[test]
    fn ping_is_auto_ponged_and_not_delivered() {
        let mut state = WsConnState::new(false, false); // auto-pong on
        state.buffer_received(&server_frame(WSBIT_FIN | WSBIT_OPCODE_PING, b"hi"));
        let mut out = [0u8; 16];
        let (n, _meta) = decode_one(&mut state, &mut out).unwrap();
        // The PING payload is consumed, not delivered to the caller.
        assert_eq!(n, 0);
        // A PONG carrying the same payload was queued/encoded for transmission.
        assert!(!state.sendbuf.is_empty(), "a PONG must be queued");
        let (fb, payload) = parse_client_frame(&state.sendbuf);
        assert_eq!(fb, WSBIT_FIN | WSBIT_OPCODE_PONG);
        assert_eq!(payload, b"hi");
    }

    #[test]
    fn ping_is_delivered_when_noautopong() {
        let mut state = WsConnState::new(false, true); // NOAUTOPONG
        state.buffer_received(&server_frame(WSBIT_FIN | WSBIT_OPCODE_PING, b"hi"));
        let mut out = [0u8; 16];
        let (n, meta) = decode_one(&mut state, &mut out).unwrap();
        // With auto-PONG disabled the PING is delivered verbatim to the caller.
        assert_eq!(n, 2);
        assert_eq!(&out[..2], b"hi");
        assert_eq!(meta.flags, CURLWS_PING as i32);
        // No automatic PONG was queued.
        assert!(state.sendbuf.is_empty(), "no PONG must be queued");
    }

    // ----- handler scheme wiring --------------------------------------------

    #[test]
    fn ws_handler_reports_its_scheme() {
        use crate::protocols::{SCHEME_WS, SCHEME_WSS};
        let ws = WsHandler::new(&SCHEME_WS);
        let wss = WsHandler::new(&SCHEME_WSS);
        assert_eq!(ws.scheme().name, "ws");
        assert_eq!(wss.scheme().name, "wss");
    }

    // ===================================================================
    // Pure frame-codec coverage: `firstbyte_to_flags`, `flags_to_firstbyte`,
    // `WsEncoder::add_frame_head`/`encode_payload`, `WsDecoder::read_head`, and
    // the RFC 6455 `Sec-WebSocket-Accept` SHA-1/base64 path. These exercise the
    // deterministic codec branches (oracle: RFC 6455 + `lib/ws.c`).
    // ===================================================================

    #[test]
    fn firstbyte_to_flags_data_frames_fin_and_fragmented() {
        let text = CURLWS_TEXT as i32;
        let bin = CURLWS_BINARY as i32;
        let cont = CURLWS_CONT as i32;
        // Final single-frame TEXT/BINARY messages.
        assert_eq!(firstbyte_to_flags(WSBIT_FIN | WSBIT_OPCODE_TEXT, 0).unwrap(), text);
        assert_eq!(firstbyte_to_flags(WSBIT_FIN | WSBIT_OPCODE_BIN, 0).unwrap(), bin);
        // Non-final first fragments additionally carry CURLWS_CONT.
        assert_eq!(firstbyte_to_flags(WSBIT_OPCODE_TEXT, 0).unwrap(), text | cont);
        assert_eq!(firstbyte_to_flags(WSBIT_OPCODE_BIN, 0).unwrap(), bin | cont);
    }

    #[test]
    fn firstbyte_to_flags_continuation_open_and_close() {
        let cont = CURLWS_CONT as i32;
        let open = (CURLWS_TEXT as i32) | cont;
        // A non-final continuation keeps the running flag set unchanged.
        assert_eq!(firstbyte_to_flags(WSBIT_OPCODE_CONT, open).unwrap(), open);
        // The final continuation clears CURLWS_CONT, preserving the TEXT type bit.
        assert_eq!(
            firstbyte_to_flags(WSBIT_FIN | WSBIT_OPCODE_CONT, open).unwrap(),
            CURLWS_TEXT as i32
        );
    }

    #[test]
    fn firstbyte_to_flags_rejects_invalid_fragmentation() {
        // Continuation with no open message.
        assert!(firstbyte_to_flags(WSBIT_OPCODE_CONT, 0).is_err());
        // New data frame interrupting an open fragmented message.
        let open = (CURLWS_TEXT as i32) | (CURLWS_CONT as i32);
        let e = firstbyte_to_flags(WSBIT_FIN | WSBIT_OPCODE_TEXT, open).unwrap_err();
        assert_eq!(e.0, CurlError::RecvError);
        assert!(firstbyte_to_flags(WSBIT_FIN | WSBIT_OPCODE_BIN, open).is_err());
    }

    #[test]
    fn firstbyte_to_flags_control_frames_and_errors() {
        assert_eq!(
            firstbyte_to_flags(WSBIT_FIN | WSBIT_OPCODE_CLOSE, 0).unwrap(),
            CURLWS_CLOSE as i32
        );
        assert_eq!(
            firstbyte_to_flags(WSBIT_FIN | WSBIT_OPCODE_PING, 0).unwrap(),
            CURLWS_PING as i32
        );
        assert_eq!(
            firstbyte_to_flags(WSBIT_FIN | WSBIT_OPCODE_PONG, 0).unwrap(),
            CURLWS_PONG as i32
        );
        // Control frames must not be fragmented (FIN required).
        assert!(firstbyte_to_flags(WSBIT_OPCODE_CLOSE, 0).is_err());
        assert!(firstbyte_to_flags(WSBIT_OPCODE_PING, 0).is_err());
        assert!(firstbyte_to_flags(WSBIT_OPCODE_PONG, 0).is_err());
        // Reserved bits set and an unassigned opcode are both rejected.
        assert!(firstbyte_to_flags(WSBIT_FIN | WSBIT_RSV1 | WSBIT_OPCODE_TEXT, 0).is_err());
        assert!(firstbyte_to_flags(WSBIT_FIN | 0x03, 0).is_err());
    }

    #[test]
    fn flags_to_firstbyte_data_and_offset_mask() {
        // Final single-frame messages.
        assert_eq!(flags_to_firstbyte(CURLWS_TEXT, false).unwrap(), WSBIT_FIN | WSBIT_OPCODE_TEXT);
        assert_eq!(flags_to_firstbyte(CURLWS_BINARY, false).unwrap(), WSBIT_FIN | WSBIT_OPCODE_BIN);
        // OFFSET is a delivery modifier and must not change the opcode decision.
        assert_eq!(
            flags_to_firstbyte(CURLWS_TEXT | CURLWS_OFFSET, false).unwrap(),
            WSBIT_FIN | WSBIT_OPCODE_TEXT
        );
        // Non-final first fragments use the data opcode without FIN.
        assert_eq!(flags_to_firstbyte(CURLWS_TEXT | CURLWS_CONT, false).unwrap(), WSBIT_OPCODE_TEXT);
        assert_eq!(flags_to_firstbyte(CURLWS_BINARY | CURLWS_CONT, false).unwrap(), WSBIT_OPCODE_BIN);
    }

    #[test]
    fn flags_to_firstbyte_continuation_state() {
        // Mid-message, a final data flag becomes the closing continuation.
        assert_eq!(flags_to_firstbyte(CURLWS_TEXT, true).unwrap(), WSBIT_FIN | WSBIT_OPCODE_CONT);
        assert_eq!(flags_to_firstbyte(CURLWS_BINARY, true).unwrap(), WSBIT_FIN | WSBIT_OPCODE_CONT);
        // Mid-message, a non-final data flag becomes a bare continuation.
        assert_eq!(flags_to_firstbyte(CURLWS_TEXT | CURLWS_CONT, true).unwrap(), WSBIT_OPCODE_CONT);
        // Empty flags close the open message; bare CONT continues it.
        assert_eq!(flags_to_firstbyte(0, true).unwrap(), WSBIT_FIN | WSBIT_OPCODE_CONT);
        assert_eq!(flags_to_firstbyte(CURLWS_CONT, true).unwrap(), WSBIT_OPCODE_CONT);
    }

    #[test]
    fn flags_to_firstbyte_control_and_errors() {
        assert_eq!(flags_to_firstbyte(CURLWS_CLOSE, false).unwrap(), WSBIT_FIN | WSBIT_OPCODE_CLOSE);
        assert_eq!(flags_to_firstbyte(CURLWS_PING, false).unwrap(), WSBIT_FIN | WSBIT_OPCODE_PING);
        assert_eq!(flags_to_firstbyte(CURLWS_PONG, false).unwrap(), WSBIT_FIN | WSBIT_OPCODE_PONG);
        // No flags / bare CONT outside a fragmented message are usage errors.
        assert_eq!(flags_to_firstbyte(0, false).unwrap_err().0, CurlError::BadFunctionArgument);
        assert!(flags_to_firstbyte(CURLWS_CONT, false).is_err());
        // Fragmented control frames are illegal.
        assert!(flags_to_firstbyte(CURLWS_CLOSE | CURLWS_CONT, false).is_err());
        assert!(flags_to_firstbyte(CURLWS_PING | CURLWS_CONT, false).is_err());
        assert!(flags_to_firstbyte(CURLWS_PONG | CURLWS_CONT, false).is_err());
        // An unknown flag combination is rejected.
        assert!(flags_to_firstbyte(0x100, false).is_err());
    }

    #[test]
    fn sec_websocket_accept_matches_rfc6455_example() {
        // RFC 6455 §1.3 worked example.
        let accept = sec_websocket_accept("dGhlIHNhbXBsZSBub25jZQ==").unwrap();
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn sha1_known_answer_vectors() {
        // FIPS 180-1 classic vectors, surfaced through the public accept path is
        // awkward, so assert the raw digest directly.
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn encoder_add_frame_head_length_tiers_set_mask_bit() {
        let mask = [0xAA, 0xBB, 0xCC, 0xDD];
        // Inline 7-bit length.
        let mut enc = WsEncoder::default();
        let mut out = Vec::new();
        enc.add_frame_head(WSBIT_FIN | WSBIT_OPCODE_TEXT, 5, mask, &mut out).unwrap();
        assert_eq!(out, vec![0x81, 5 | WSBIT_MASK, 0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(enc.payload_remain, 5);

        // 16-bit extended length (126 marker).
        let mut enc = WsEncoder::default();
        let mut out = Vec::new();
        enc.add_frame_head(WSBIT_FIN | WSBIT_OPCODE_BIN, 200, mask, &mut out).unwrap();
        assert_eq!(&out[..4], &[0x82, 126 | WSBIT_MASK, 0x00, 0xC8]);

        // 64-bit extended length (127 marker).
        let mut enc = WsEncoder::default();
        let mut out = Vec::new();
        enc.add_frame_head(WSBIT_FIN | WSBIT_OPCODE_BIN, 70000, mask, &mut out).unwrap();
        assert_eq!(out[0], 0x82);
        assert_eq!(out[1], 127 | WSBIT_MASK);
        assert_eq!(&out[2..10], &70000u64.to_be_bytes());
    }

    #[test]
    fn encoder_add_frame_head_rejects_bad_frames() {
        let mask = [1, 2, 3, 4];
        // Negative payload length.
        let mut enc = WsEncoder::default();
        assert_eq!(
            enc.add_frame_head(WSBIT_FIN | WSBIT_OPCODE_TEXT, -1, mask, &mut Vec::new()).unwrap_err().0,
            CurlError::SendError
        );
        // A new frame while the previous payload is unsent.
        let mut enc = WsEncoder::default();
        enc.payload_remain = 3;
        assert_eq!(
            enc.add_frame_head(WSBIT_FIN | WSBIT_OPCODE_TEXT, 1, mask, &mut Vec::new()).unwrap_err().0,
            CurlError::SendError
        );
        // An over-long control frame.
        let mut enc = WsEncoder::default();
        assert_eq!(
            enc.add_frame_head(WSBIT_FIN | WSBIT_OPCODE_PING, 126, mask, &mut Vec::new()).unwrap_err().0,
            CurlError::TooLarge
        );
    }

    #[test]
    fn encoder_encode_payload_masks_and_advances() {
        let mask = [1, 2, 3, 4];
        let mut enc = WsEncoder::default();
        let mut out = Vec::new();
        enc.add_frame_head(WSBIT_FIN | WSBIT_OPCODE_BIN, 5, mask, &mut out).unwrap();
        out.clear(); // isolate the payload bytes
        let n = enc.encode_payload(&[0x10, 0x20, 0x30, 0x40, 0x50], &mut out);
        assert_eq!(n, 5);
        // Each byte XORed with mask[i % 4].
        assert_eq!(out, vec![0x10 ^ 1, 0x20 ^ 2, 0x30 ^ 3, 0x40 ^ 4, 0x50 ^ 1]);
        assert_eq!(enc.payload_remain, 0);
    }

    #[test]
    fn decoder_read_head_parses_length_tiers() {
        // 7-bit inline length.
        let mut dec = WsDecoder::new();
        let mut buf = RecvBuf::new();
        buf.extend(&[WSBIT_FIN | WSBIT_OPCODE_TEXT, 5]);
        assert_eq!(dec.read_head(&mut buf).unwrap(), HeadStatus::Done);
        assert_eq!(dec.payload_len, 5);
        assert_eq!(dec.frame_flags, CURLWS_TEXT as i32);

        // 16-bit extended length.
        let mut dec = WsDecoder::new();
        let mut buf = RecvBuf::new();
        buf.extend(&[WSBIT_FIN | WSBIT_OPCODE_BIN, 126, 0x01, 0x00]);
        assert_eq!(dec.read_head(&mut buf).unwrap(), HeadStatus::Done);
        assert_eq!(dec.payload_len, 256);

        // 64-bit extended length.
        let mut dec = WsDecoder::new();
        let mut buf = RecvBuf::new();
        let mut bytes = vec![WSBIT_FIN | WSBIT_OPCODE_BIN, 127];
        bytes.extend_from_slice(&70000u64.to_be_bytes());
        buf.extend(&bytes);
        assert_eq!(dec.read_head(&mut buf).unwrap(), HeadStatus::Done);
        assert_eq!(dec.payload_len, 70000);
    }

    #[test]
    fn decoder_read_head_needs_more_when_split() {
        let mut dec = WsDecoder::new();
        let mut buf = RecvBuf::new();
        // Only the first byte arrives.
        buf.extend(&[WSBIT_FIN | WSBIT_OPCODE_TEXT]);
        assert_eq!(dec.read_head(&mut buf).unwrap(), HeadStatus::NeedMore);
        // The length byte arrives in a later read; the head completes.
        buf.extend(&[7]);
        assert_eq!(dec.read_head(&mut buf).unwrap(), HeadStatus::Done);
        assert_eq!(dec.payload_len, 7);
    }

    #[test]
    fn decoder_read_head_rejects_protocol_violations() {
        // A masked server→client frame is illegal.
        let mut dec = WsDecoder::new();
        let mut buf = RecvBuf::new();
        buf.extend(&[WSBIT_FIN | WSBIT_OPCODE_TEXT, WSBIT_MASK | 1]);
        assert_eq!(dec.read_head(&mut buf).unwrap_err().0, CurlError::RecvError);

        // An over-long control frame (PING with a 126 length marker).
        let mut dec = WsDecoder::new();
        let mut buf = RecvBuf::new();
        buf.extend(&[WSBIT_FIN | WSBIT_OPCODE_PING, 126]);
        assert_eq!(dec.read_head(&mut buf).unwrap_err().0, CurlError::RecvError);

        // A 64-bit length with the top bit set (>63 bits) is unsupported.
        let mut dec = WsDecoder::new();
        let mut buf = RecvBuf::new();
        let mut bytes = vec![WSBIT_FIN | WSBIT_OPCODE_BIN, 127];
        bytes.extend_from_slice(&[0x80, 0, 0, 0, 0, 0, 0, 0]);
        buf.extend(&bytes);
        assert_eq!(dec.read_head(&mut buf).unwrap_err().0, CurlError::RecvError);

        // Reserved bits set in the first byte.
        let mut dec = WsDecoder::new();
        let mut buf = RecvBuf::new();
        buf.extend(&[WSBIT_FIN | WSBIT_RSV1 | WSBIT_OPCODE_TEXT, 1]);
        assert!(dec.read_head(&mut buf).is_err());
    }

}
